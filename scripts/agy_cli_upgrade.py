#!/usr/bin/env python3
"""Controlled Antigravity CLI (`agy`) version check, backup, upgrade, and rollback tool.

Design guarantees:
- Zero hardcoded user home paths (derives defaults from `Path.home()` or CLI/env overrides).
- Fail-closed preflight & backup before invoking `agy update`.
- Removes `AGY_CLI_DISABLE_AUTO_UPDATE` ONLY in the `agy update` subprocess env copy
  (never mutates parent `os.environ`, never uses `shell=True`).
- Enforces `AGY_CLI_DISABLE_AUTO_UPDATE=1` during pre/post `agy --version` and `verify_gate.py`.
- Enforces HTTPS-only manifest URLs with explicit timeout.
- Enforces backup directory permissions (`0700`), `.sha256` permissions (`0600`), strict
  path/symlink/SHA256 verification on rollback, and same-directory atomic replacement
  (`flush` + `os.fsync` + `chmod 0o755` + `os.replace` + `finally` cleanup).
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse
import urllib.request

DEFAULT_MANIFEST_BASE = "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests"
DEFAULT_HTTP_TIMEOUT = 10.0
DEFAULT_VERSION_TIMEOUT = 15.0
DEFAULT_UPDATE_TIMEOUT = 300.0
DEFAULT_VERIFY_TIMEOUT = 300.0
MAX_MANIFEST_BYTES = 1024 * 1024  # 1 MiB

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_VER_RE = re.compile(r"[^A-Za-z0-9._-]+")
_SEMVER_RE = re.compile(r"\b(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?)\b")


def default_agy_bin() -> Path:
    raw = (os.environ.get("AGY_TG_AGY_BIN") or os.environ.get("AGY_BIN") or "").strip()
    if raw:
        return Path(os.path.expandvars(os.path.expanduser(raw)))
    return Path.home() / ".local" / "bin" / "agy"


def default_backup_dir() -> Path:
    raw = (os.environ.get("AGY_CLI_BACKUP_DIR") or "").strip()
    if raw:
        return Path(os.path.expandvars(os.path.expanduser(raw)))
    return Path.home() / ".local" / "share" / "agy-cli-backups"


def default_verify_gate_script() -> Path:
    return Path(__file__).resolve().parent / "verify_gate.py"


def resolve_platform_key(system: Optional[str] = None, machine: Optional[str] = None) -> str:
    """Map OS/arch to official Antigravity CLI manifest platform key."""
    sys_name = (system if system is not None else platform.system()).strip().lower()
    arch_name = (machine if machine is not None else platform.machine()).strip().lower()

    os_map = {
        "linux": "linux",
        "darwin": "darwin",
    }
    arch_map = {
        "arm64": "arm64",
        "aarch64": "arm64",
        "amd64": "amd64",
        "x86_64": "amd64",
        "x64": "amd64",
    }
    if sys_name not in os_map:
        raise ValueError(f"Unsupported operating system for manifest lookup: {sys_name!r}")
    if arch_name not in arch_map:
        raise ValueError(f"Unsupported CPU architecture for manifest lookup: {arch_name!r}")
    return f"{os_map[sys_name]}_{arch_map[arch_name]}"


def default_manifest_url(system: Optional[str] = None, machine: Optional[str] = None) -> str:
    return f"{DEFAULT_MANIFEST_BASE}/{resolve_platform_key(system=system, machine=machine)}.json"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail-closed redirect handler that forbids all HTTP 3xx redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if fp is not None:
            try:
                fp.close()
            except Exception:
                pass
        raise ValueError("Manifest URL HTTP redirects are forbidden")


def _validate_positive_timeout(value: float, label: str = "HTTP timeout") -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{label} must be a finite positive number, got: {value!r}")
    return float(value)


def _parse_positive_timeout_arg(raw: str) -> float:
    try:
        val = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid timeout value: {raw!r}") from exc
    if not math.isfinite(val) or val <= 0:
        raise argparse.ArgumentTypeError(f"Timeout must be a finite positive number, got: {raw!r}")
    return val


def validate_manifest_url(url: str) -> str:
    """Fail-closed validation allowing ONLY `https://` URLs without credentials, whitespace, or control chars."""
    cleaned = url or ""
    if not cleaned:
        raise ValueError("Manifest URL must not be empty")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        raise ValueError("Manifest URL must not contain whitespace or control characters")
    parsed = urlparse(cleaned)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"Manifest URL must use https:// scheme, got: {parsed.scheme or '<none>'!r}")
    if not parsed.hostname:
        raise ValueError("Manifest URL must contain a valid hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Manifest URL must not contain embedded credentials")
    return cleaned


def sanitize_version_token(version: str) -> str:
    cleaned = _SAFE_VER_RE.sub("_", (version or "").strip()).strip("._-")
    return cleaned[:48] if cleaned else "unknown"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_version_output(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    m = _SEMVER_RE.search(text)
    if m:
        return m.group(1)
    first_line = text.splitlines()[0].strip()
    return first_line


def _validate_regular_source_binary(agy_bin: Path) -> None:
    if agy_bin.is_symlink():
        raise ValueError(f"Refusing symlink binary source: {agy_bin}")
    if not agy_bin.exists():
        raise FileNotFoundError(f"Antigravity CLI binary not found: {agy_bin}")
    st = agy_bin.lstat()
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"Antigravity CLI path is not a regular file: {agy_bin}")
    if not os.access(agy_bin, os.R_OK):
        raise PermissionError(f"Antigravity CLI binary is not readable: {agy_bin}")


def _validate_backup_dir_for_write(backup_dir: Path) -> Path:
    if backup_dir.is_symlink():
        raise ValueError(f"Refusing symlink backup directory: {backup_dir}")
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if backup_dir.is_symlink() or not backup_dir.is_dir():
        raise ValueError(f"Backup path is not a directory: {backup_dir}")
    os.chmod(backup_dir, 0o700)
    return backup_dir


def _atomic_write_bytes(target: Path, data: bytes, mode: int) -> None:
    tmp_path: Optional[Path] = None
    replaced = False
    tmp_f = tempfile.NamedTemporaryFile(
        dir=str(target.parent),
        prefix=f".{target.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        tmp_path = Path(tmp_f.name)
        tmp_f.write(data)
        tmp_f.flush()
        os.fsync(tmp_f.fileno())
        tmp_f.close()
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, target)
        replaced = True
    finally:
        try:
            if not tmp_f.closed:
                tmp_f.close()
        except Exception:
            pass
        if not replaced and tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


def _atomic_copy_file(
    src: Path,
    dst: Path,
    mode: int,
    *,
    prefix: str = ".agy-copy-",
    expected_sha256: Optional[str] = None,
) -> str:
    tmp_path: Optional[Path] = None
    replaced = False
    hasher = hashlib.sha256()
    tmp_f = tempfile.NamedTemporaryFile(
        dir=str(dst.parent),
        prefix=prefix,
        suffix=".tmp",
        delete=False,
    )
    try:
        tmp_path = Path(tmp_f.name)
        with open(src, "rb") as src_fh:
            for chunk in iter(lambda: src_fh.read(65536), b""):
                hasher.update(chunk)
                tmp_f.write(chunk)
        tmp_f.flush()
        os.fsync(tmp_f.fileno())
        tmp_f.close()
        computed = hasher.hexdigest().lower()
        if expected_sha256 is not None and not hmac.compare_digest(computed, expected_sha256.lower()):
            raise ValueError(
                f"SHA256 mismatch during atomic copy of {src.name}: "
                f"expected {expected_sha256[:12]}..., got {computed[:12]}..."
            )
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, dst)
        replaced = True
        return computed
    finally:
        try:
            if not tmp_f.closed:
                tmp_f.close()
        except Exception:
            pass
        if not replaced and tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


def get_local_version(agy_bin: Path, *, timeout: float = DEFAULT_VERSION_TIMEOUT) -> str:
    """Query local `agy --version` with `AGY_CLI_DISABLE_AUTO_UPDATE=1` on child env copy."""
    _validate_regular_source_binary(agy_bin)
    child_env = os.environ.copy()
    child_env["AGY_CLI_DISABLE_AUTO_UPDATE"] = "1"
    proc = subprocess.run(
        [str(agy_bin), "--version"],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=child_env,
        shell=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
        raise RuntimeError(f"`{agy_bin} --version` failed (rc={proc.returncode}): {detail[:240]}")
    ver = _parse_version_output(proc.stdout or proc.stderr)
    if not ver:
        raise RuntimeError(f"`{agy_bin} --version` returned empty output")
    return ver


def fetch_remote_manifest(
    manifest_url: str,
    *,
    timeout: float = DEFAULT_HTTP_TIMEOUT,
) -> Dict[str, Any]:
    """Fetch official remote manifest JSON over HTTPS with explicit finite timeout and no redirects."""
    safe_timeout = _validate_positive_timeout(timeout, "HTTP timeout")
    safe_url = validate_manifest_url(manifest_url)
    req = urllib.request.Request(
        safe_url,
        headers={
            "User-Agent": "agy-cli-upgrade/1.0",
            "Accept": "application/json",
        },
        method="GET",
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    with opener.open(req, timeout=safe_timeout) as resp:
        raw = resp.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError(f"Manifest response exceeds {MAX_MANIFEST_BYTES} bytes limit")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("version"), str) or not data["version"].strip():
        raise ValueError("Remote manifest JSON missing valid string 'version' field")
    return data


def create_backup(
    agy_bin: Path,
    backup_dir: Path,
    *,
    version: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a timestamped backup binary + companion `.sha256` inside `backup_dir` (0700)."""
    _validate_regular_source_binary(agy_bin)
    bdir = _validate_backup_dir_for_write(backup_dir)

    ver_str = version
    if ver_str is None:
        try:
            ver_str = get_local_version(agy_bin)
        except Exception:
            ver_str = "unknown"
    ver_tok = sanitize_version_token(ver_str)
    utc_now = datetime.now(timezone.utc)
    ts = utc_now.strftime("%Y%m%dT%H%M%SZ")

    base_name = f"agy-{ver_tok}-{ts}"
    backup_path = bdir / base_name
    suffix = 1
    while backup_path.exists() or Path(f"{backup_path}.sha256").exists():
        backup_path = bdir / f"{base_name}-{suffix}"
        suffix += 1

    _atomic_copy_file(agy_bin, backup_path, mode=0o600, prefix=".agy-backup-")
    digest = sha256_file(backup_path)
    sha_path = Path(f"{backup_path}.sha256")
    _atomic_write_bytes(sha_path, f"{digest}  {backup_path.name}\n".encode("utf-8"), mode=0o600)

    return {
        "backup_name": backup_path.name,
        "backup_path": str(backup_path),
        "sha256_path": str(sha_path),
        "sha256": digest,
        "version": ver_str,
        "size_bytes": backup_path.stat().st_size,
        "created_at_utc": utc_now.isoformat(),
    }


def _read_expected_sha256(sha_path: Path, resolved_backup_dir: Path) -> str:
    if sha_path.is_symlink():
        raise ValueError(f"Refusing symlink SHA256 sidecar: {sha_path}")
    if not sha_path.exists():
        raise FileNotFoundError(f"Missing required SHA256 checksum file: {sha_path}")
    resolved_sha = sha_path.resolve(strict=True)
    if not resolved_sha.is_relative_to(resolved_backup_dir):
        raise ValueError(f"SHA256 checksum path escapes backup directory: {sha_path}")
    if not stat.S_ISREG(sha_path.lstat().st_mode):
        raise ValueError(f"SHA256 checksum path is not a regular file: {sha_path}")
    content = resolved_sha.read_text(encoding="utf-8").strip()
    if not content:
        raise ValueError(f"SHA256 checksum file is empty: {sha_path}")
    first_token = content.split()[0]
    if not _HEX64_RE.fullmatch(first_token):
        raise ValueError(f"Invalid SHA256 digest format in {sha_path}")
    return first_token.lower()


def _resolve_verified_backup(backup_arg: str, backup_dir: Path) -> tuple[Path, str]:
    raw_arg = (backup_arg or "").strip()
    if not raw_arg:
        raise ValueError("Backup name or path must not be empty")
    if backup_dir.is_symlink():
        raise ValueError(f"Refusing symlink backup directory: {backup_dir}")
    if not backup_dir.is_dir():
        raise FileNotFoundError(f"Backup directory does not exist: {backup_dir}")

    resolved_dir = backup_dir.resolve(strict=True)
    abs_backup_dir = Path(os.path.abspath(str(backup_dir)))
    arg_path = Path(raw_arg)
    if ".." in arg_path.parts:
        raise ValueError(f"Path traversal ('..') rejected in backup reference: {backup_arg!r}")

    if arg_path.is_absolute():
        if arg_path.is_relative_to(abs_backup_dir):
            base_dir = abs_backup_dir
            rel_path = arg_path.relative_to(abs_backup_dir)
        elif arg_path.is_relative_to(resolved_dir):
            base_dir = resolved_dir
            rel_path = arg_path.relative_to(resolved_dir)
        else:
            raise ValueError(f"Backup path escapes backup directory {resolved_dir}: {arg_path}")
        if not rel_path.parts:
            raise ValueError(f"Backup path must reference a file inside {resolved_dir}: {arg_path}")
        candidate = base_dir / rel_path
    else:
        base_dir = backup_dir
        rel_path = arg_path
        if not rel_path.parts:
            raise ValueError("Backup name or path must not be empty")
        candidate = backup_dir / rel_path

    # Reject if any intermediate segment or final target under backup_dir is a symlink.
    cur = base_dir
    for part in rel_path.parts:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError(f"Refusing symlink component in backup path: {cur}")

    if candidate.is_symlink():
        raise ValueError(f"Refusing symlink backup file: {candidate}")
    if not candidate.exists():
        raise FileNotFoundError(f"Backup file not found: {candidate}")
    if not stat.S_ISREG(candidate.lstat().st_mode):
        raise ValueError(f"Backup target is not a regular file: {candidate}")

    resolved_candidate = candidate.resolve(strict=True)
    if resolved_candidate == resolved_dir or not resolved_candidate.is_relative_to(resolved_dir):
        raise ValueError(f"Backup path escapes backup directory {resolved_dir}: {candidate}")

    sha_path = Path(f"{candidate}.sha256")
    expected = _read_expected_sha256(sha_path, resolved_dir)
    actual = sha256_file(resolved_candidate).lower()
    if not hmac.compare_digest(actual, expected):
        raise ValueError(
            f"SHA256 verification failed for {resolved_candidate.name}: "
            f"expected {expected[:12]}..., got {actual[:12]}..."
        )
    return resolved_candidate, actual


def list_backups(backup_dir: Path) -> List[Dict[str, Any]]:
    if backup_dir.is_symlink():
        raise ValueError(f"Refusing symlink backup directory: {backup_dir}")
    if not backup_dir.exists():
        return []
    if not backup_dir.is_dir():
        raise ValueError(f"Backup path is not a directory: {backup_dir}")

    resolved_dir = backup_dir.resolve(strict=True)
    items: List[Dict[str, Any]] = []
    for entry in sorted(backup_dir.iterdir(), key=lambda p: p.name, reverse=True):
        if entry.name.startswith(".") or entry.name.endswith((".sha256", ".tmp")):
            continue
        if entry.is_symlink() or not stat.S_ISREG(entry.lstat().st_mode):
            continue
        sha_path = Path(f"{entry}.sha256")
        sha_status = "ok"
        digest = ""
        try:
            expected = _read_expected_sha256(sha_path, resolved_dir)
            actual = sha256_file(entry).lower()
            if hmac.compare_digest(actual, expected):
                digest = actual
            else:
                sha_status = "mismatch"
        except FileNotFoundError:
            sha_status = "missing_sha256"
        except Exception:
            sha_status = "invalid_sha256"
        st = entry.stat()
        items.append(
            {
                "name": entry.name,
                "path": str(entry),
                "size_bytes": st.st_size,
                "sha256_status": sha_status,
                "sha256": digest,
            }
        )
    return items


def rollback_binary(
    backup_arg: str,
    *,
    agy_bin: Path,
    backup_dir: Path,
) -> Dict[str, Any]:
    """Verify backup path & SHA256, then atomically replace `agy_bin` via same-dir temp file."""
    verified_backup, digest = _resolve_verified_backup(backup_arg, backup_dir)

    if agy_bin.is_symlink():
        raise ValueError(f"Refusing to overwrite symlink target binary: {agy_bin}")
    if not agy_bin.parent.is_dir():
        raise FileNotFoundError(f"Target parent directory does not exist: {agy_bin.parent}")
    if agy_bin.exists() and not stat.S_ISREG(agy_bin.lstat().st_mode):
        raise ValueError(f"Target path is not a regular file: {agy_bin}")

    _atomic_copy_file(
        verified_backup,
        agy_bin,
        mode=0o755,
        prefix=".agy-rollback-",
        expected_sha256=digest,
    )
    return {
        "status": "ok",
        "restored_from": str(verified_backup),
        "backup_name": verified_backup.name,
        "target": str(agy_bin),
        "sha256": digest,
        "mode": "0755",
    }


def _format_rollback_hint(backup_name: str, agy_bin: Path, backup_dir: Path) -> str:
    return (
        f"python3 scripts/agy_cli_upgrade.py --rollback {shlex.quote(backup_name)} "
        f"--agy-bin {shlex.quote(str(agy_bin))} --backup-dir {shlex.quote(str(backup_dir))}"
    )


def run_check(
    *,
    agy_bin: Path,
    manifest_url: Optional[str] = None,
    timeout: float = DEFAULT_HTTP_TIMEOUT,
) -> Dict[str, Any]:
    safe_timeout = _validate_positive_timeout(timeout, "HTTP timeout")
    url = validate_manifest_url(manifest_url) if manifest_url else validate_manifest_url(default_manifest_url())
    local_version = get_local_version(agy_bin)
    manifest = fetch_remote_manifest(url, timeout=safe_timeout)
    remote_version = str(manifest["version"]).strip()
    return {
        "status": "ok",
        "agy_bin": str(agy_bin),
        "local_version": local_version,
        "remote_version": remote_version,
        "up_to_date": local_version == remote_version,
        "manifest_url": url,
    }


def run_upgrade(
    *,
    agy_bin: Path,
    backup_dir: Path,
    skip_verify: bool = False,
    verify_gate_script: Optional[Path] = None,
    update_timeout: float = DEFAULT_UPDATE_TIMEOUT,
    verify_timeout: float = DEFAULT_VERIFY_TIMEOUT,
) -> tuple[int, Dict[str, Any]]:
    """Fail-closed upgrade: preflight -> backup -> scoped `agy update` -> post-verify."""
    # 1. Fail-closed preflight & backup before ever touching `agy update`
    try:
        _validate_regular_source_binary(agy_bin)
        if not os.access(agy_bin.parent, os.W_OK | os.X_OK):
            raise PermissionError(f"Target binary directory is not writable: {agy_bin.parent}")
        before_version = get_local_version(agy_bin)
        backup_info = create_backup(agy_bin, backup_dir, version=before_version)
    except Exception as exc:
        return 1, {
            "status": "error",
            "stage": "preflight_backup",
            "error": str(exc),
            "update_invoked": False,
        }

    backup_name = backup_info["backup_name"]
    rollback_cmd = _format_rollback_hint(backup_name, agy_bin, backup_dir)

    # 2. Run `agy update` with AGY_CLI_DISABLE_AUTO_UPDATE popped ONLY in child env copy
    update_env = os.environ.copy()
    update_env.pop("AGY_CLI_DISABLE_AUTO_UPDATE", None)
    try:
        upd = subprocess.run(
            [str(agy_bin), "update"],
            capture_output=True,
            text=True,
            timeout=update_timeout,
            env=update_env,
            shell=False,
        )
    except Exception as exc:
        return 1, {
            "status": "error",
            "stage": "agy_update",
            "error": str(exc),
            "before_version": before_version,
            "backup": backup_info,
            "rollback_command": rollback_cmd,
            "update_invoked": True,
        }

    if upd.returncode != 0:
        detail = (upd.stderr or upd.stdout or f"exit {upd.returncode}").strip()
        return 1, {
            "status": "error",
            "stage": "agy_update",
            "exit_code": upd.returncode,
            "error": detail[:400],
            "before_version": before_version,
            "backup": backup_info,
            "rollback_command": rollback_cmd,
            "update_invoked": True,
        }

    # 3. Verify updated `agy --version` (with AGY_CLI_DISABLE_AUTO_UPDATE=1 enforced)
    try:
        after_version = get_local_version(agy_bin)
    except Exception as exc:
        return 1, {
            "status": "error",
            "stage": "post_version_check",
            "error": str(exc),
            "before_version": before_version,
            "backup": backup_info,
            "rollback_command": rollback_cmd,
            "update_invoked": True,
        }

    # 4. Run `verify_gate.py --scope bridge --with-hooks-canary --agy-bin <agy_bin>` unless --skip-verify
    verify_result: Dict[str, Any] = {"skipped": bool(skip_verify)}
    if not skip_verify:
        gate_script = verify_gate_script or default_verify_gate_script()
        verify_env = os.environ.copy()
        verify_env["AGY_CLI_DISABLE_AUTO_UPDATE"] = "1"
        verify_env["AGY_TG_AGY_BIN"] = str(agy_bin)
        verify_env["AGY_BIN"] = str(agy_bin)
        verify_env.pop("AGY_VERIFY_GATE_NESTED", None)
        try:
            vres = subprocess.run(
                [
                    sys.executable,
                    str(gate_script),
                    "--scope",
                    "bridge",
                    "--with-hooks-canary",
                    "--agy-bin",
                    str(agy_bin),
                ],
                capture_output=True,
                text=True,
                timeout=verify_timeout,
                env=verify_env,
                shell=False,
            )
        except Exception as exc:
            return 1, {
                "status": "error",
                "stage": "verify_gate",
                "error": str(exc),
                "before_version": before_version,
                "after_version": after_version,
                "backup": backup_info,
                "rollback_command": rollback_cmd,
                "update_invoked": True,
            }
        verify_result = {
            "skipped": False,
            "exit_code": vres.returncode,
            "passed": vres.returncode == 0,
            "agy_bin": str(agy_bin),
            "with_hooks_canary": True,
        }
        if vres.returncode != 0:
            detail = (vres.stderr or vres.stdout or f"exit {vres.returncode}").strip()
            return 1, {
                "status": "error",
                "stage": "verify_gate",
                "exit_code": vres.returncode,
                "error": detail[-400:],
                "before_version": before_version,
                "after_version": after_version,
                "backup": backup_info,
                "verify_gate": verify_result,
                "rollback_command": rollback_cmd,
                "update_invoked": True,
            }

    return 0, {
        "status": "ok",
        "before_version": before_version,
        "after_version": after_version,
        "backup": backup_info,
        "verify_gate": verify_result,
        "rollback_command": rollback_cmd,
        "update_invoked": True,
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agy_cli_upgrade.py",
        description="Controlled Antigravity CLI (`agy`) version check, backup, upgrade, and rollback tool.",
    )
    action = p.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true", help="Read-only check of local vs remote manifest version")
    action.add_argument("--backup-only", action="store_true", help="Backup current `agy` binary + SHA256 sidecar only")
    action.add_argument("--list-backups", action="store_true", help="List available backups in backup directory")
    action.add_argument("--upgrade", action="store_true", help="Backup current binary, run scoped `agy update`, and verify")
    action.add_argument(
        "--rollback",
        metavar="BACKUP",
        help="Verify SHA256 and atomically restore a backup by name or path inside backup directory",
    )

    p.add_argument("--agy-bin", type=Path, default=None, help="Path to `agy` binary (default: ~/.local/bin/agy)")
    p.add_argument(
        "--backup-dir",
        type=Path,
        default=None,
        help="Backup directory (default: ~/.local/share/agy-cli-backups)",
    )
    p.add_argument("--manifest-url", default=None, help="Override remote manifest HTTPS URL for --check")
    p.add_argument(
        "--timeout",
        type=_parse_positive_timeout_arg,
        default=DEFAULT_HTTP_TIMEOUT,
        help="HTTP timeout in seconds for --check (finite positive number)",
    )
    p.add_argument("--skip-verify", action="store_true", help="Skip `verify_gate.py --scope bridge` after --upgrade")
    p.add_argument("--json", action="store_true", dest="as_json", help="Emit machine-readable JSON output")
    return p


def _emit(payload: Dict[str, Any], as_json: bool, text_lines: Sequence[str], *, error: bool = False) -> None:
    stream = sys.stderr if (error and not as_json) else sys.stdout
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for ln in text_lines:
            print(ln, file=stream)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not any([args.check, args.backup_only, args.list_backups, args.upgrade, args.rollback]):
        parser.print_help()
        return 0

    agy_bin = args.agy_bin if args.agy_bin is not None else default_agy_bin()
    backup_dir = args.backup_dir if args.backup_dir is not None else default_backup_dir()

    if args.check:
        try:
            res = run_check(agy_bin=agy_bin, manifest_url=args.manifest_url, timeout=args.timeout)
        except Exception as exc:
            _emit(
                {"status": "error", "error": str(exc)},
                args.as_json,
                [f"[ERROR] Check failed: {exc}"],
                error=True,
            )
            return 1
        state = "up-to-date" if res["up_to_date"] else "update-available"
        _emit(
            res,
            args.as_json,
            [
                f"Local version : {res['local_version']}",
                f"Remote version: {res['remote_version']} ({state})",
                f"Manifest URL  : {res['manifest_url']}",
            ],
        )
        return 0

    if args.backup_only:
        try:
            info = create_backup(agy_bin, backup_dir)
            res = {"status": "ok", "backup": info}
        except Exception as exc:
            _emit(
                {"status": "error", "error": str(exc)},
                args.as_json,
                [f"[ERROR] Backup failed: {exc}"],
                error=True,
            )
            return 1
        _emit(
            res,
            args.as_json,
            [
                f"[OK] Backup created: {info['backup_path']}",
                f"     SHA256: {info['sha256']} ({info['sha256_path']})",
            ],
        )
        return 0

    if args.list_backups:
        try:
            backups = list_backups(backup_dir)
            res = {"status": "ok", "backup_dir": str(backup_dir), "backups": backups}
        except Exception as exc:
            _emit(
                {"status": "error", "error": str(exc)},
                args.as_json,
                [f"[ERROR] List backups failed: {exc}"],
                error=True,
            )
            return 1
        lines = [f"Backup directory: {backup_dir} ({len(backups)} backup(s))"]
        for b in backups:
            lines.append(f"  - {b['name']}  ({b['size_bytes']} bytes, sha256={b['sha256_status']})")
        _emit(res, args.as_json, lines)
        return 0

    if args.upgrade:
        rc, res = run_upgrade(
            agy_bin=agy_bin,
            backup_dir=backup_dir,
            skip_verify=args.skip_verify,
        )
        if rc != 0:
            lines = [f"[ERROR] Upgrade failed at stage '{res.get('stage')}': {res.get('error')}"]
            if res.get("rollback_command"):
                lines.append(f"[HINT] Rollback command: {res['rollback_command']}")
            _emit(res, args.as_json, lines, error=True)
            return rc
        _emit(
            res,
            args.as_json,
            [
                f"[OK] Upgrade complete: {res['before_version']} -> {res['after_version']}",
                f"     Backup: {res['backup']['backup_path']}",
                f"     Rollback: {res['rollback_command']}",
            ],
        )
        return 0

    if args.rollback:
        try:
            res = rollback_binary(args.rollback, agy_bin=agy_bin, backup_dir=backup_dir)
        except Exception as exc:
            _emit(
                {"status": "error", "error": str(exc)},
                args.as_json,
                [f"[ERROR] Rollback failed: {exc}"],
                error=True,
            )
            return 1
        _emit(
            res,
            args.as_json,
            [
                f"[OK] Rolled back {res['target']} from {res['backup_name']}",
                f"     Verified SHA256: {res['sha256']}",
            ],
        )
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
