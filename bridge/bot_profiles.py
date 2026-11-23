#!/usr/bin/env python3
"""Per-Bot Independent Profile, Rules, Soul, Memory, Skills & Instincts Storage Engine.

Provides strict repository-external per-bot storage under `AGY_BOT_PROFILES_DIR`
(default `~/.config/agy-tg-bridge/bots/<handle>/`) with:
- Mandatory directory (`0700`) and file (`0600`) permissions
- Strict doc allowlist (`SOUL.md`, `RULES.md`, `MEMORY.md`, case-sensitive)
- Strict skill slug validation (`^[a-z0-9][a-z0-9_-]{0,63}$`, rejecting `.`/`..`/`__proto__`)
- UTF-8 24 KiB per-document size cap, NUL-byte rejection, recursive forbidden-key scanning
- Optimistic concurrency locking (`expected_rev` -> 409 Conflict with zero disk mutation)
- Per-bot `fcntl.flock`, `lstat`/`O_NOFOLLOW` + `resolve().relative_to()` symlink defense,
  and atomic `tmp + fsync + chmod 0600 + os.replace` writes
- Non-git sentinel directory `<profiles_dir>/<handle>/.mem-cwd/bot-<handle>` for native
  `claude-mem` per-bot project derivation (`bot-<handle>`)
- Effective skills resolution (Worker isolated vs. Coordinator full-team aggregation)
- Atomic `BUS_DIR/cid_owners.json` conversation ownership registry
- Compact `[ACB_BOT_PROFILE rev=<n> handle=<h> role=<r>]` prompt renderer
- Atomic `~/.gemini/config/mcp_config.json` updater for wrapping `claude-mem`
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import sys
import time
from typing import Any, Iterator, Sequence

ALLOWED_DOCS: frozenset[str] = frozenset({"SOUL.md", "RULES.md", "MEMORY.md"})
MAX_DOC_BYTES: int = 24 * 1024
MAX_SPECIALTY_CHARS: int = 160
MAX_SKILL_CATALOG_ITEMS: int = 200

HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
SKILL_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
FORBIDDEN_SLUGS: frozenset[str] = frozenset(
    {".", "..", "__proto__", "constructor", "prototype"}
)
VALID_SKILL_POLICY_MODES: frozenset[str] = frozenset({"allowlist", "all"})
VALID_MEMORY_SCOPES: frozenset[str] = frozenset({"isolated", "coordinator_all"})

FORBIDDEN_PROFILE_KEYS: frozenset[str] = frozenset(
    {
        "workdir",
        "default_workdir",
        "ipc_sock",
        "role",
        "path",
        "reload_file",
        "env",
        "headers",
        "command",
        "cmd",
        "args",
        "url",
        "shell",
        "script",
        "token",
        "secret",
        "password",
        "pid",
        "allowed_chats",
        "mirror_chat_id",
        "mirror_thread_id",
        "chat_id",
        "thread_id",
    }
)

_CTRL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_SENSITIVE_HOST_PATH_RE = re.compile(
    r"(?:/home/[^/\s\"'<>]+|/root|/Users/[^/\s\"'<>]+|/etc/[^\s\"'<>]+)"
)
_FRONTMATTER_RE = re.compile(r"^---\s*\n([\s\S]*?)\n---\s*(?:\n|$)")
_YAML_NAME_RE = re.compile(r"^\s*name\s*:\s*(.+?)\s*$", re.MULTILINE)
_YAML_DESC_RE = re.compile(r"^\s*description\s*:\s*(.+?)\s*$", re.MULTILINE)
_MCP_CONFIG_LOCK_PATH = "/tmp/agy_mcp_config.lock"


def resolve_profiles_dir(profiles_dir: str | Path | None = None) -> Path:
    """Resolve the canonical per-bot profile root directory (strictly outside Git repos)."""
    if profiles_dir is not None and str(profiles_dir).strip():
        return Path(str(profiles_dir)).expanduser()
    env_val = os.environ.get("AGY_BOT_PROFILES_DIR", "").strip()
    if env_val:
        return Path(env_val).expanduser()
    return Path.home() / ".config" / "agy-tg-bridge" / "bots"


def resolve_bus_dir(bus_dir: str | Path | None = None) -> Path:
    if bus_dir is not None and str(bus_dir).strip():
        return Path(str(bus_dir)).expanduser()
    env_val = os.environ.get("AGY_BOT_BUS_DIR", "").strip()
    if env_val:
        return Path(env_val).expanduser()
    return Path.home() / ".config" / "agy-tg-bridge" / "bus"


def resolve_claude_mem_db(db_path: str | Path | None = None) -> Path:
    if db_path is not None and str(db_path).strip():
        return Path(str(db_path)).expanduser()
    env_val = os.environ.get("CLAUDE_MEM_DB_PATH", "").strip()
    if env_val:
        return Path(env_val).expanduser()
    return Path.home() / ".claude-mem" / "claude-mem.db"


def normalize_bot_handle(raw: Any) -> str | None:
    """Strictly validate and normalize a bot handle (no traversal/slashes/NUL)."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if s.startswith("@"):
        s = s[1:]
    s = s.lower()
    if not s or "/" in s or "\\" in s or ".." in s or "%" in s or "\x00" in s:
        return None
    if s in FORBIDDEN_SLUGS or not HANDLE_RE.fullmatch(s):
        return None
    return s


def is_valid_skill_slug(raw: Any) -> bool:
    if not isinstance(raw, str):
        return False
    if raw in FORBIDDEN_SLUGS or ".." in raw or "/" in raw or "\\" in raw or "\x00" in raw:
        return False
    return bool(SKILL_SLUG_RE.fullmatch(raw))


def is_valid_doc_name(raw: Any) -> bool:
    return isinstance(raw, str) and raw in ALLOWED_DOCS


def parse_strict_rev(raw: Any) -> int | None:
    """Parse a non-negative integer optimistic-lock revision (rejects bool/float/str)."""
    if isinstance(raw, bool) or not isinstance(raw, int):
        return None
    return raw if raw >= 0 else None


def find_forbidden_key(
    obj: Any,
    forbidden: frozenset[str] = FORBIDDEN_PROFILE_KEYS,
    *,
    depth: int = 0,
) -> str | None:
    """Recursively scan dicts/lists for forbidden privilege/path/secret keys."""
    if depth > 16:
        return "max_depth_exceeded"
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).strip().lower()
            if kl in forbidden:
                return kl
            hit = find_forbidden_key(v, forbidden, depth=depth + 1)
            if hit:
                return hit
    elif isinstance(obj, list):
        for item in obj:
            hit = find_forbidden_key(item, forbidden, depth=depth + 1)
            if hit:
                return hit
    return None


def validate_markdown_content(
    raw: Any,
    *,
    max_bytes: int = MAX_DOC_BYTES,
) -> tuple[bool, str, int, int]:
    """Validate UTF-8 Markdown document content.

    Returns `(ok, error_message, http_status, byte_len)`.
    """
    if not isinstance(raw, str):
        return False, "文档内容必须为字符串", 400, 0
    if "\x00" in raw:
        return False, "文档内容禁止包含 NUL 空字节", 400, 0
    b_len = len(raw.encode("utf-8"))
    if b_len > max_bytes:
        return False, f"文档大小超过上限（{b_len} > {max_bytes} 字节）", 413, b_len
    return True, "", 200, b_len


def memory_project_for_handle(handle: str) -> str:
    norm = normalize_bot_handle(handle)
    if not norm:
        raise ValueError(f"Invalid bot handle: {handle!r}")
    return f"bot-{norm}"


def memory_scope_for_role(role: str | None) -> str:
    r = str(role or "worker").strip().lower()
    return "coordinator_all" if r == "coordinator" else "isolated"


def _sanitize_summary_text(raw: Any, max_len: int = 160) -> str:
    s = str(raw or "")
    s = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", s)
    s = " ".join(s.split())
    if max_len > 0 and len(s) > max_len:
        return s[: max_len - 1].rstrip() + "…"
    return s


def _parse_skill_md_meta(md_text: str, fallback_slug: str) -> tuple[str, str]:
    name = fallback_slug
    desc = ""
    m = _FRONTMATTER_RE.match(md_text.lstrip("\ufeff"))
    if m:
        fm = m.group(1)
        nm = _YAML_NAME_RE.search(fm)
        if nm:
            val = nm.group(1).strip().strip("\"'")
            if val:
                name = val[:64]
        dm = _YAML_DESC_RE.search(fm)
        if dm:
            val = dm.group(1).strip()
            if val in (">-", "|", ">", "|-"):
                lines = fm.splitlines()
                for idx, ln in enumerate(lines):
                    if re.match(r"^\s*description\s*:", ln):
                        collected = []
                        for nxt in lines[idx + 1 :]:
                            if nxt.startswith((" ", "\t")):
                                collected.append(nxt.strip())
                            else:
                                break
                        val = " ".join(collected)
                        break
            else:
                val = val.strip("\"'")
            desc = val
    if not desc:
        for line in md_text.splitlines():
            st = line.strip()
            if not st or st == "---" or st.startswith("#"):
                continue
            desc = st
            break
    return name[:64], _sanitize_summary_text(desc, max_len=160)


# ---------------------------------------------------------------------------
# Symlink-resistant, permission-hardened filesystem helpers
# ---------------------------------------------------------------------------


def _assert_not_symlink(path: Path) -> None:
    try:
        st = os.lstat(str(path))
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"Refusing symlink path: {path.name}")


def _assert_safe_under_base(base_dir: Path, target: Path) -> None:
    """Verify no path segment from `base_dir` to `target` is a symlink and `target` stays inside `base_dir`."""
    _assert_not_symlink(base_dir)
    base_res = base_dir.resolve(strict=False)
    target_res = target.resolve(strict=False)
    try:
        target_res.relative_to(base_res)
    except ValueError as exc:
        raise PermissionError("Path escapes bot profile directory boundary") from exc

    rel = target_res.relative_to(base_res)
    cur = base_res
    for part in rel.parts:
        cur = cur / part
        _assert_not_symlink(cur)


def _ensure_dir_0700(path: Path, *, base_dir: Path | None = None) -> Path:
    if base_dir is not None:
        _assert_safe_under_base(base_dir, path)
    else:
        _assert_not_symlink(path)
    path.mkdir(parents=True, exist_ok=True)
    _assert_not_symlink(path)
    os.chmod(path, 0o700)
    return path


def _read_text_nofollow(path: Path, *, base_dir: Path, max_bytes: int = 256 * 1024) -> str:
    _assert_safe_under_base(base_dir, path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        return ""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError("Target is not a regular file")
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    if len(data) > max_bytes:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace")


def _write_bytes_atomic_0600(path: Path, data: bytes, *, base_dir: Path) -> None:
    _ensure_dir_0700(path.parent, base_dir=base_dir)
    _assert_safe_under_base(base_dir, path)
    tmp_path = path.parent / f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_path), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def get_bot_dir(handle: str, *, profiles_dir: str | Path | None = None) -> Path:
    norm = normalize_bot_handle(handle)
    if not norm:
        raise ValueError(f"Invalid bot handle: {handle!r}")
    root = resolve_profiles_dir(profiles_dir)
    return root / norm


def _has_git_ancestor(path: Path) -> bool:
    cur = path.resolve(strict=False)
    for anc in (cur, *cur.parents):
        if (anc / ".git").exists():
            return True
    return False


def ensure_mem_cwd_sentinel(
    handle: str,
    *,
    profiles_dir: str | Path | None = None,
) -> Path:
    """Ensure non-git sentinel cwd `<profiles_dir>/<handle>/.mem-cwd/bot-<handle>` exists (`0700`)."""
    norm = normalize_bot_handle(handle)
    if not norm:
        raise ValueError(f"Invalid bot handle: {handle!r}")
    root = _ensure_dir_0700(resolve_profiles_dir(profiles_dir))
    bot_dir = _ensure_dir_0700(root / norm, base_dir=root)
    sentinel = _ensure_dir_0700(bot_dir / ".mem-cwd" / f"bot-{norm}", base_dir=bot_dir)
    if _has_git_ancestor(sentinel):
        raise RuntimeError(
            f"claude-mem sentinel directory must not be inside a git repository: {sentinel}"
        )
    return sentinel


@contextmanager
def bot_profile_lock(
    handle: str,
    *,
    profiles_dir: str | Path | None = None,
    shared: bool = False,
) -> Iterator[Path]:
    """Per-bot advisory `fcntl.flock` protecting profile metadata, docs, and skills."""
    norm = normalize_bot_handle(handle)
    if not norm:
        raise ValueError(f"Invalid bot handle: {handle!r}")
    root = _ensure_dir_0700(resolve_profiles_dir(profiles_dir))
    bot_dir = _ensure_dir_0700(root / norm, base_dir=root)
    lock_path = bot_dir / ".profile.lock"
    _assert_safe_under_base(bot_dir, lock_path)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(lock_path), flags, 0o600)
    try:
        os.chmod(lock_path, 0o600)
    except OSError:
        pass
    lock_op = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
    try:
        fcntl.flock(fd, lock_op)
        try:
            yield bot_dir
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Profile Initialization & Metadata Helpers
# ---------------------------------------------------------------------------


def _default_profile_meta(
    handle: str,
    *,
    role: str = "worker",
    specialty: str = "",
) -> dict[str, Any]:
    norm_role = str(role or "worker").strip().lower()
    return {
        "version": 1,
        "handle": handle,
        "rev": 1,
        "memory_project": f"bot-{handle}",
        "memory_scope": memory_scope_for_role(norm_role),
        "skills_policy": {
            "mode": "all" if norm_role == "coordinator" else "allowlist",
            "enabled_catalog_skills": [],
        },
        "specialty": _sanitize_summary_text(specialty, max_len=MAX_SPECIALTY_CHARS),
        "updated_at": int(time.time()),
        "updated_by": "system",
    }


def _normalize_skills_policy(raw: Any, *, default_mode: str = "allowlist") -> dict[str, Any]:
    mode = default_mode
    enabled: list[str] = []
    if isinstance(raw, dict):
        m = str(raw.get("mode") or default_mode).strip().lower()
        if m in VALID_SKILL_POLICY_MODES:
            mode = m
        raw_list = raw.get("enabled_catalog_skills")
        if isinstance(raw_list, list):
            seen: set[str] = set()
            for item in raw_list[:MAX_SKILL_CATALOG_ITEMS]:
                if isinstance(item, str) and is_valid_skill_slug(item) and item not in seen:
                    seen.add(item)
                    enabled.append(item)
    return {"mode": mode, "enabled_catalog_skills": sorted(enabled)}


def _read_profile_meta_unlocked(
    bot_dir: Path,
    handle: str,
    *,
    role: str = "worker",
    specialty: str = "",
) -> dict[str, Any]:
    meta_path = bot_dir / "profile.json"
    default_mode = "all" if str(role or "").strip().lower() == "coordinator" else "allowlist"
    base = _default_profile_meta(handle, role=role, specialty=specialty)
    if not meta_path.exists():
        return base
    try:
        raw_txt = _read_text_nofollow(meta_path, base_dir=bot_dir, max_bytes=64 * 1024)
        loaded = json.loads(raw_txt) if raw_txt.strip() else {}
    except Exception:
        loaded = {}
    if not isinstance(loaded, dict):
        return base

    rev = parse_strict_rev(loaded.get("rev"))
    base["rev"] = rev if (rev is not None and rev >= 1) else 1
    base["memory_project"] = f"bot-{handle}"
    base["memory_scope"] = memory_scope_for_role(role)
    base["skills_policy"] = _normalize_skills_policy(
        loaded.get("skills_policy"), default_mode=default_mode
    )
    if isinstance(loaded.get("specialty"), str):
        base["specialty"] = _sanitize_summary_text(
            loaded["specialty"], max_len=MAX_SPECIALTY_CHARS
        )
    if isinstance(loaded.get("updated_at"), (int, float)) and not isinstance(
        loaded.get("updated_at"), bool
    ):
        base["updated_at"] = int(loaded["updated_at"])
    if isinstance(loaded.get("updated_by"), str):
        base["updated_by"] = _CTRL_CHARS_RE.sub("", loaded["updated_by"])[:64]
    return base


def _write_profile_meta_unlocked(bot_dir: Path, meta: dict[str, Any]) -> None:
    payload = (json.dumps(meta, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _write_bytes_atomic_0600(bot_dir / "profile.json", payload, base_dir=bot_dir)


def ensure_bot_profile(
    handle: str,
    *,
    role: str = "worker",
    profiles_dir: str | Path | None = None,
    specialty: str = "",
) -> dict[str, Any]:
    """Idempotently initialize `<profiles_dir>/<handle>/` without overwriting existing docs."""
    norm = normalize_bot_handle(handle)
    if not norm:
        raise ValueError(f"Invalid bot handle: {handle!r}")
    with bot_profile_lock(norm, profiles_dir=profiles_dir) as bot_dir:
        _ensure_dir_0700(bot_dir / "skills", base_dir=bot_dir)
        _ensure_dir_0700(bot_dir / "instincts", base_dir=bot_dir)
        _ensure_dir_0700(bot_dir / "instincts" / "personal", base_dir=bot_dir)
        _ensure_dir_0700(bot_dir / "instincts" / "archived", base_dir=bot_dir)
        _ensure_dir_0700(bot_dir / ".mem-cwd" / f"bot-{norm}", base_dir=bot_dir)

        meta_path = bot_dir / "profile.json"
        if meta_path.exists():
            meta = _read_profile_meta_unlocked(bot_dir, norm, role=role, specialty=specialty)
        else:
            meta = _default_profile_meta(norm, role=role, specialty=specialty)
            _write_profile_meta_unlocked(bot_dir, meta)

        for doc_name in sorted(ALLOWED_DOCS):
            doc_path = bot_dir / doc_name
            if not doc_path.exists():
                _write_bytes_atomic_0600(doc_path, b"", base_dir=bot_dir)
        return meta


def get_profile_rev(
    handle: str,
    *,
    role: str = "worker",
    profiles_dir: str | Path | None = None,
) -> int:
    norm = normalize_bot_handle(handle)
    if not norm:
        return 0
    bot_dir = get_bot_dir(norm, profiles_dir=profiles_dir)
    if not bot_dir.is_dir():
        return 0
    try:
        with bot_profile_lock(norm, profiles_dir=profiles_dir, shared=True) as bd:
            meta = _read_profile_meta_unlocked(bd, norm, role=role)
            return int(meta.get("rev") or 1)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Skills Resolution (Isolated Worker vs. Coordinator Full-Team Aggregation)
# ---------------------------------------------------------------------------


def _scan_skills_dir(
    root_dir: Path,
    *,
    scope: str,
    owner: str | None = None,
    include_paths: bool = False,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not root_dir.is_dir() or root_dir.is_symlink():
        return out
    try:
        entries = sorted(os.scandir(root_dir), key=lambda e: e.name)
    except OSError:
        return out
    for ent in entries:
        if not ent.is_dir(follow_symlinks=False):
            continue
        slug = ent.name
        if not is_valid_skill_slug(slug):
            continue
        md_path = Path(ent.path) / "SKILL.md"
        if md_path.is_symlink() or not md_path.is_file():
            continue
        try:
            st = md_path.stat()
            md_text = md_path.read_text(encoding="utf-8", errors="replace")[: MAX_DOC_BYTES + 2048]
        except OSError:
            continue
        name, desc = _parse_skill_md_meta(md_text, slug)
        item: dict[str, Any] = {
            "slug": slug,
            "name": name,
            "scope": scope,
            "description": desc,
            "size_bytes": int(st.st_size),
            "updated_at": int(st.st_mtime),
        }
        if owner is not None:
            item["owner"] = owner
        if include_paths:
            item["skill_md_path"] = str(md_path)
        out.append(item)
        if len(out) >= MAX_SKILL_CATALOG_ITEMS:
            break
    return out


def default_catalog_dirs(workspace_dir: str | Path | None = None) -> list[Path]:
    ws = (
        Path(str(workspace_dir)).expanduser()
        if workspace_dir is not None and str(workspace_dir).strip()
        else Path(
            os.environ.get("AGY_WORKSPACE_DIR", str(Path.home() / "agy-workspace"))
        ).expanduser()
    )
    return [ws / ".agents" / "skills"]


def list_profile_handles(*, profiles_dir: str | Path | None = None) -> list[str]:
    root = resolve_profiles_dir(profiles_dir)
    if not root.is_dir() or root.is_symlink():
        return []
    handles: list[str] = []
    try:
        for ent in sorted(os.scandir(root), key=lambda e: e.name):
            if not ent.is_dir(follow_symlinks=False):
                continue
            h = normalize_bot_handle(ent.name)
            if h and h == ent.name:
                handles.append(h)
    except OSError:
        return []
    return handles


def resolve_effective_skills(
    handle: str,
    *,
    role: str = "worker",
    profiles_dir: str | Path | None = None,
    catalog_dirs: Sequence[str | Path] | None = None,
    include_paths: bool = False,
) -> dict[str, Any]:
    """Resolve own skills, catalog skills, effective skills, and (for coordinator) team skills."""
    norm = normalize_bot_handle(handle)
    if not norm:
        raise ValueError(f"Invalid bot handle: {handle!r}")
    norm_role = str(role or "worker").strip().lower()
    root = resolve_profiles_dir(profiles_dir)
    bot_dir = root / norm

    default_mode = "all" if norm_role == "coordinator" else "allowlist"
    meta = (
        _read_profile_meta_unlocked(bot_dir, norm, role=norm_role)
        if bot_dir.is_dir()
        else _default_profile_meta(norm, role=norm_role)
    )
    policy = _normalize_skills_policy(meta.get("skills_policy"), default_mode=default_mode)
    enabled_set = set(policy["enabled_catalog_skills"])

    own_skills = _scan_skills_dir(
        bot_dir / "skills", scope="bot", owner=norm, include_paths=include_paths
    )

    cat_roots = (
        [Path(str(d)).expanduser() for d in catalog_dirs]
        if catalog_dirs is not None
        else default_catalog_dirs()
    )
    catalog_skills: list[dict[str, Any]] = []
    seen_cat: set[str] = set()
    for cdir in cat_roots:
        for item in _scan_skills_dir(cdir, scope="catalog", include_paths=include_paths):
            slug = item["slug"]
            if slug in seen_cat:
                continue
            seen_cat.add(slug)
            is_enabled = (norm_role == "coordinator") or (policy["mode"] == "all") or (slug in enabled_set)
            item_copy = dict(item)
            item_copy["enabled"] = is_enabled
            catalog_skills.append(item_copy)

    team_skills: list[dict[str, Any]] = []
    if norm_role == "coordinator":
        for sibling in list_profile_handles(profiles_dir=root):
            if sibling == norm:
                continue
            sib_skills = _scan_skills_dir(
                root / sibling / "skills",
                scope="team_bot",
                owner=sibling,
                include_paths=include_paths,
            )
            team_skills.extend(sib_skills)

    effective: list[dict[str, Any]] = []
    seen_eff: set[tuple[str, str]] = set()
    for item in own_skills:
        key = ("bot", item["slug"])
        if key not in seen_eff:
            seen_eff.add(key)
            effective.append(dict(item))
    for item in team_skills:
        key = (f"bot:{item.get('owner', '')}", item["slug"])
        if key not in seen_eff:
            seen_eff.add(key)
            effective.append(dict(item))
    for item in catalog_skills:
        if not item.get("enabled"):
            continue
        key = ("catalog", item["slug"])
        if key not in seen_eff:
            seen_eff.add(key)
            effective.append(dict(item))

    return {
        "skills_policy": policy,
        "own_skills": own_skills,
        "catalog_skills": catalog_skills,
        "team_skills": team_skills,
        "effective_skills": effective,
    }


def get_worker_allowed_catalog_slugs(
    handle: str,
    *,
    profiles_dir: str | Path | None = None,
) -> tuple[str, set[str]]:
    """Return `(policy_mode, allowed_catalog_slugs)` for a worker bot (fail-closed default allowlist)."""
    norm = normalize_bot_handle(handle)
    if not norm:
        return "allowlist", set()
    bot_dir = get_bot_dir(norm, profiles_dir=profiles_dir)
    if not bot_dir.is_dir():
        return "allowlist", set()
    meta = _read_profile_meta_unlocked(bot_dir, norm, role="worker")
    policy = _normalize_skills_policy(meta.get("skills_policy"), default_mode="allowlist")
    return str(policy["mode"]), set(policy["enabled_catalog_skills"])


# ---------------------------------------------------------------------------
# Read-only Memory Statistics (SQLite RO + Per-Bot Instincts)
# ---------------------------------------------------------------------------


def _count_bot_instincts(bot_dir: Path) -> tuple[int, str]:
    personal_dir = bot_dir / "instincts" / "personal"
    count = 0
    if personal_dir.is_dir() and not personal_dir.is_symlink():
        try:
            count = sum(
                1
                for p in personal_dir.iterdir()
                if p.is_file() and not p.is_symlink() and p.suffix == ".yaml"
            )
        except OSError:
            count = 0
    active_md = ""
    active_path = bot_dir / "instincts" / "active-instincts.md"
    if active_path.is_file() and not active_path.is_symlink():
        try:
            active_md = _read_text_nofollow(active_path, base_dir=bot_dir, max_bytes=16 * 1024)
        except Exception:
            active_md = ""
    return count, active_md


def _query_claude_mem_counts(
    db_path: Path,
) -> dict[str, dict[str, int]]:
    """Read-only per-project counts of observations and session_summaries from claude-mem.db."""
    counts: dict[str, dict[str, int]] = {}
    if not db_path.is_file():
        return counts
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2.0)
        try:
            for tbl, key in (("observations", "observations"), ("session_summaries", "summaries")):
                try:
                    rows = conn.execute(
                        f"SELECT project, COUNT(*) FROM {tbl} GROUP BY project"
                    ).fetchall()
                except sqlite3.Error:
                    continue
                for proj, cnt in rows:
                    p = str(proj or "").strip()
                    if not p:
                        continue
                    bucket = counts.setdefault(p, {"observations": 0, "summaries": 0})
                    bucket[key] = int(cnt or 0)
        finally:
            conn.close()
    except Exception:
        return {}
    return counts


def get_bot_memory_stats(
    handle: str,
    *,
    role: str = "worker",
    profiles_dir: str | Path | None = None,
    claude_mem_db: str | Path | None = None,
) -> dict[str, Any]:
    norm = normalize_bot_handle(handle)
    if not norm:
        raise ValueError(f"Invalid bot handle: {handle!r}")
    norm_role = str(role or "worker").strip().lower()
    root = resolve_profiles_dir(profiles_dir)
    bot_dir = root / norm
    proj_name = f"bot-{norm}"
    db_counts = _query_claude_mem_counts(resolve_claude_mem_db(claude_mem_db))
    own_db = db_counts.get(proj_name, {"observations": 0, "summaries": 0})
    inst_cnt, active_md = _count_bot_instincts(bot_dir) if bot_dir.is_dir() else (0, "")

    result: dict[str, Any] = {
        "memory_project": proj_name,
        "memory_scope": memory_scope_for_role(norm_role),
        "observations_count": int(own_db.get("observations") or 0),
        "summaries_count": int(own_db.get("summaries") or 0),
        "instincts_count": inst_cnt,
        "active_instincts_preview": active_md[:2000],
    }
    if norm_role == "coordinator":
        team_rows: list[dict[str, Any]] = []
        seen_projs: set[str] = set()
        for h in list_profile_handles(profiles_dir=root):
            p = f"bot-{h}"
            seen_projs.add(p)
            c = db_counts.get(p, {"observations": 0, "summaries": 0})
            h_inst, _ = _count_bot_instincts(root / h)
            team_rows.append(
                {
                    "handle": h,
                    "project": p,
                    "observations_count": int(c.get("observations") or 0),
                    "summaries_count": int(c.get("summaries") or 0),
                    "instincts_count": h_inst,
                }
            )
        for p, c in sorted(db_counts.items()):
            if p in seen_projs:
                continue
            team_rows.append(
                {
                    "handle": p[4:] if p.startswith("bot-") else "",
                    "project": p,
                    "observations_count": int(c.get("observations") or 0),
                    "summaries_count": int(c.get("summaries") or 0),
                    "instincts_count": 0,
                }
            )
        result["team_memory"] = team_rows
        result["total_observations"] = sum(r["observations_count"] for r in team_rows)
        result["total_summaries"] = sum(r["summaries_count"] for r in team_rows)
        result["total_instincts"] = sum(r["instincts_count"] for r in team_rows)
    return result


# ---------------------------------------------------------------------------
# Full Profile Bundle & Optimistic-Locked Mutations
# ---------------------------------------------------------------------------


def get_bot_profile_bundle(
    handle: str,
    *,
    role: str = "worker",
    specialty: str = "",
    profiles_dir: str | Path | None = None,
    catalog_dirs: Sequence[str | Path] | None = None,
    claude_mem_db: str | Path | None = None,
) -> dict[str, Any]:
    """Return a strictly sanitized (zero host paths / zero secrets) profile bundle for IPC/Studio."""
    norm = normalize_bot_handle(handle)
    if not norm:
        raise ValueError(f"Invalid bot handle: {handle!r}")
    norm_role = str(role or "worker").strip().lower()
    ensure_bot_profile(norm, role=norm_role, profiles_dir=profiles_dir, specialty=specialty)

    with bot_profile_lock(norm, profiles_dir=profiles_dir, shared=True) as bot_dir:
        meta = _read_profile_meta_unlocked(bot_dir, norm, role=norm_role, specialty=specialty)
        docs: dict[str, str] = {}
        doc_bytes: dict[str, int] = {}
        for doc_name in sorted(ALLOWED_DOCS):
            txt = _read_text_nofollow(bot_dir / doc_name, base_dir=bot_dir, max_bytes=MAX_DOC_BYTES + 1024)
            docs[doc_name] = txt
            doc_bytes[doc_name] = len(txt.encode("utf-8"))

    skills_info = resolve_effective_skills(
        norm,
        role=norm_role,
        profiles_dir=profiles_dir,
        catalog_dirs=catalog_dirs,
        include_paths=False,
    )
    mem_stats = get_bot_memory_stats(
        norm,
        role=norm_role,
        profiles_dir=profiles_dir,
        claude_mem_db=claude_mem_db,
    )

    return {
        "ok": True,
        "handle": norm,
        "role": norm_role,
        "rev": int(meta["rev"]),
        "max_doc_bytes": MAX_DOC_BYTES,
        "specialty": meta.get("specialty") or "",
        "memory_project": meta["memory_project"],
        "memory_scope": meta["memory_scope"],
        "updated_at": int(meta.get("updated_at") or 0),
        "updated_by": str(meta.get("updated_by") or ""),
        "docs": docs,
        "doc_bytes": doc_bytes,
        "skills_policy": skills_info["skills_policy"],
        "own_skills": skills_info["own_skills"],
        "catalog_skills": skills_info["catalog_skills"],
        "team_skills": skills_info["team_skills"],
        "effective_skills": skills_info["effective_skills"],
        "memory_stats": mem_stats,
    }


def update_bot_profile(
    handle: str,
    *,
    expected_rev: Any,
    doc: str | None = None,
    content: str | None = None,
    docs: dict[str, Any] | None = None,
    skills_policy: dict[str, Any] | None = None,
    specialty: str | None = None,
    updated_by: str = "",
    role: str = "worker",
    profiles_dir: str | Path | None = None,
    catalog_dirs: Sequence[str | Path] | None = None,
    claude_mem_db: str | Path | None = None,
) -> tuple[int, dict[str, Any]]:
    """Atomically update a bot's SOUL.md / RULES.md / MEMORY.md / skills_policy / specialty with `expected_rev`."""
    norm = normalize_bot_handle(handle)
    if not norm:
        return 400, {"ok": False, "error": "非法的 Bot handle 格式"}

    exp_rev = parse_strict_rev(expected_rev)
    if exp_rev is None:
        return 400, {"ok": False, "error": "缺少有效的整数 expected_rev 乐观锁版本号"}

    pending_docs: dict[str, bytes] = {}
    if doc is not None or content is not None:
        if not is_valid_doc_name(doc):
            return 400, {"ok": False, "error": "doc 仅允许 SOUL.md / RULES.md / MEMORY.md（严格大小写匹配）"}
        ok_c, err_c, sc_c, _bl = validate_markdown_content(content)
        if not ok_c:
            return sc_c, {"ok": False, "error": err_c}
        assert doc is not None and content is not None
        pending_docs[doc] = content.encode("utf-8")

    if docs is not None:
        if not isinstance(docs, dict):
            return 400, {"ok": False, "error": "docs 必须为对象映射"}
        for k, v in docs.items():
            if not is_valid_doc_name(k):
                return 400, {"ok": False, "error": f"非法的文档名称: {k}"}
            ok_c, err_c, sc_c, _bl = validate_markdown_content(v)
            if not ok_c:
                return sc_c, {"ok": False, "error": err_c}
            pending_docs[k] = str(v).encode("utf-8")

    new_policy: dict[str, Any] | None = None
    if skills_policy is not None:
        if not isinstance(skills_policy, dict):
            return 400, {"ok": False, "error": "skills_policy 必须为对象"}
        bad_k = find_forbidden_key(skills_policy)
        if bad_k:
            return 400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"}
        extra_pk = set(skills_policy.keys()) - {"mode", "enabled_catalog_skills"}
        if extra_pk:
            return 400, {"ok": False, "error": f"skills_policy 包含未允许字段: {sorted(extra_pk)[0]}"}
        raw_mode = skills_policy.get("mode")
        if raw_mode is not None:
            if not isinstance(raw_mode, str) or raw_mode.strip().lower() not in VALID_SKILL_POLICY_MODES:
                return 400, {"ok": False, "error": "skills_policy.mode 仅允许 allowlist 或 all"}
        raw_en = skills_policy.get("enabled_catalog_skills")
        if raw_en is not None:
            if not isinstance(raw_en, list) or len(raw_en) > MAX_SKILL_CATALOG_ITEMS:
                return 400, {"ok": False, "error": "enabled_catalog_skills 必须为有效 slug 数组"}
            for sl in raw_en:
                if not is_valid_skill_slug(sl):
                    return 400, {"ok": False, "error": f"非法的 skill slug: {sl}"}
        new_policy = _normalize_skills_policy(skills_policy)

    new_specialty: str | None = None
    if specialty is not None:
        if not isinstance(specialty, str):
            return 400, {"ok": False, "error": "specialty 必须为字符串"}
        if "\x00" in specialty:
            return 400, {"ok": False, "error": "specialty 禁止包含 NUL 字节"}
        if len(specialty.encode("utf-8")) > 1024:
            return 413, {"ok": False, "error": "specialty 长度超过上限"}
        new_specialty = _sanitize_summary_text(specialty, max_len=MAX_SPECIALTY_CHARS)

    if not pending_docs and new_policy is None and new_specialty is None:
        return 400, {"ok": False, "error": "至少需要提供一个可更新字段（doc / docs / skills_policy / specialty）"}

    ensure_bot_profile(norm, role=role, profiles_dir=profiles_dir)
    norm_role = str(role or "worker").strip().lower()
    actor = _CTRL_CHARS_RE.sub("", str(updated_by or "")).strip()[:64] or "admin"

    try:
        with bot_profile_lock(norm, profiles_dir=profiles_dir) as bot_dir:
            meta = _read_profile_meta_unlocked(bot_dir, norm, role=norm_role)
            cur_rev = int(meta["rev"])
            if exp_rev != cur_rev:
                return 409, {
                    "ok": False,
                    "code": "rev_conflict",
                    "current_rev": cur_rev,
                    "error": f"版本冲突：当前 rev={cur_rev}，提交的 expected_rev={exp_rev}，请刷新后重试",
                }
            for doc_name, raw_bytes in pending_docs.items():
                _write_bytes_atomic_0600(bot_dir / doc_name, raw_bytes, base_dir=bot_dir)
            if new_policy is not None:
                meta["skills_policy"] = new_policy
            if new_specialty is not None:
                meta["specialty"] = new_specialty
            meta["rev"] = cur_rev + 1
            meta["updated_at"] = int(time.time())
            meta["updated_by"] = actor
            _write_profile_meta_unlocked(bot_dir, meta)
    except PermissionError as exc:
        return 403, {"ok": False, "code": "unsafe_path", "error": f"安全拦截：{exc}"}

    bundle = get_bot_profile_bundle(
        norm,
        role=norm_role,
        profiles_dir=profiles_dir,
        catalog_dirs=catalog_dirs,
        claude_mem_db=claude_mem_db,
    )
    return 200, bundle


def get_bot_skill(
    handle: str,
    slug: str,
    *,
    role: str = "worker",
    profiles_dir: str | Path | None = None,
) -> tuple[int, dict[str, Any]]:
    norm = normalize_bot_handle(handle)
    if not norm:
        return 400, {"ok": False, "error": "非法的 Bot handle 格式"}
    if not is_valid_skill_slug(slug):
        return 400, {"ok": False, "error": "非法的 skill slug 格式"}

    ensure_bot_profile(norm, role=role, profiles_dir=profiles_dir)
    try:
        with bot_profile_lock(norm, profiles_dir=profiles_dir, shared=True) as bot_dir:
            meta = _read_profile_meta_unlocked(bot_dir, norm, role=role)
            skill_md = bot_dir / "skills" / slug / "SKILL.md"
            _assert_safe_under_base(bot_dir, skill_md)
            if not skill_md.exists():
                return 404, {"ok": False, "error": f"未找到 Bot 自有 Skill: {slug}"}
            text = _read_text_nofollow(skill_md, base_dir=bot_dir, max_bytes=MAX_DOC_BYTES + 1024)
            name, desc = _parse_skill_md_meta(text, slug)
            return 200, {
                "ok": True,
                "handle": norm,
                "slug": slug,
                "rev": int(meta["rev"]),
                "name": name,
                "description": desc,
                "content": text,
                "size_bytes": len(text.encode("utf-8")),
                "max_doc_bytes": MAX_DOC_BYTES,
            }
    except PermissionError as exc:
        return 403, {"ok": False, "code": "unsafe_path", "error": f"安全拦截：{exc}"}


def put_bot_skill(
    handle: str,
    slug: str,
    *,
    content: Any,
    expected_rev: Any,
    updated_by: str = "",
    role: str = "worker",
    profiles_dir: str | Path | None = None,
) -> tuple[int, dict[str, Any]]:
    norm = normalize_bot_handle(handle)
    if not norm:
        return 400, {"ok": False, "error": "非法的 Bot handle 格式"}
    if not is_valid_skill_slug(slug):
        return 400, {"ok": False, "error": "非法的 skill slug 格式（仅允许 ^[a-z0-9][a-z0-9_-]{0,63}$）"}
    exp_rev = parse_strict_rev(expected_rev)
    if exp_rev is None:
        return 400, {"ok": False, "error": "缺少有效的整数 expected_rev 乐观锁版本号"}
    ok_c, err_c, sc_c, b_len = validate_markdown_content(content)
    if not ok_c:
        return sc_c, {"ok": False, "error": err_c}

    ensure_bot_profile(norm, role=role, profiles_dir=profiles_dir)
    actor = _CTRL_CHARS_RE.sub("", str(updated_by or "")).strip()[:64] or "admin"
    assert isinstance(content, str)

    try:
        with bot_profile_lock(norm, profiles_dir=profiles_dir) as bot_dir:
            meta = _read_profile_meta_unlocked(bot_dir, norm, role=role)
            cur_rev = int(meta["rev"])
            if exp_rev != cur_rev:
                return 409, {
                    "ok": False,
                    "code": "rev_conflict",
                    "current_rev": cur_rev,
                    "error": f"版本冲突：当前 rev={cur_rev}，提交的 expected_rev={exp_rev}",
                }
            skill_dir = _ensure_dir_0700(bot_dir / "skills" / slug, base_dir=bot_dir)
            skill_md = skill_dir / "SKILL.md"
            _write_bytes_atomic_0600(skill_md, content.encode("utf-8"), base_dir=bot_dir)
            meta["rev"] = cur_rev + 1
            meta["updated_at"] = int(time.time())
            meta["updated_by"] = actor
            _write_profile_meta_unlocked(bot_dir, meta)
            name, desc = _parse_skill_md_meta(content, slug)
            return 200, {
                "ok": True,
                "handle": norm,
                "slug": slug,
                "rev": int(meta["rev"]),
                "name": name,
                "description": desc,
                "content": content,
                "size_bytes": b_len,
                "max_doc_bytes": MAX_DOC_BYTES,
            }
    except PermissionError as exc:
        return 403, {"ok": False, "code": "unsafe_path", "error": f"安全拦截：{exc}"}


def delete_bot_skill(
    handle: str,
    slug: str,
    *,
    expected_rev: Any,
    updated_by: str = "",
    role: str = "worker",
    profiles_dir: str | Path | None = None,
) -> tuple[int, dict[str, Any]]:
    norm = normalize_bot_handle(handle)
    if not norm:
        return 400, {"ok": False, "error": "非法的 Bot handle 格式"}
    if not is_valid_skill_slug(slug):
        return 400, {"ok": False, "error": "非法的 skill slug 格式"}
    exp_rev = parse_strict_rev(expected_rev)
    if exp_rev is None:
        return 400, {"ok": False, "error": "缺少有效的整数 expected_rev 乐观锁版本号"}

    ensure_bot_profile(norm, role=role, profiles_dir=profiles_dir)
    actor = _CTRL_CHARS_RE.sub("", str(updated_by or "")).strip()[:64] or "admin"

    try:
        with bot_profile_lock(norm, profiles_dir=profiles_dir) as bot_dir:
            meta = _read_profile_meta_unlocked(bot_dir, norm, role=role)
            cur_rev = int(meta["rev"])
            if exp_rev != cur_rev:
                return 409, {
                    "ok": False,
                    "code": "rev_conflict",
                    "current_rev": cur_rev,
                    "error": f"版本冲突：当前 rev={cur_rev}，提交的 expected_rev={exp_rev}",
                }
            skills_root = bot_dir / "skills"
            skill_dir = skills_root / slug
            _assert_safe_under_base(skills_root, skill_dir)
            if not skill_dir.exists():
                return 404, {"ok": False, "error": f"未找到 Bot 自有 Skill: {slug}"}
            shutil.rmtree(skill_dir)
            meta["rev"] = cur_rev + 1
            meta["updated_at"] = int(time.time())
            meta["updated_by"] = actor
            _write_profile_meta_unlocked(bot_dir, meta)
            return 200, {
                "ok": True,
                "deleted": True,
                "handle": norm,
                "slug": slug,
                "rev": int(meta["rev"]),
            }
    except PermissionError as exc:
        return 403, {"ok": False, "code": "unsafe_path", "error": f"安全拦截：{exc}"}


# ---------------------------------------------------------------------------
# Atomic CID Ownership Registry (`BUS_DIR/cid_owners.json`)
# ---------------------------------------------------------------------------


def cid_owners_path(bus_dir: str | Path | None = None) -> Path:
    return resolve_bus_dir(bus_dir) / "cid_owners.json"


def _read_cid_owners_unlocked(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"version": 1, "owners": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if isinstance(data, dict) and isinstance(data.get("owners"), dict):
            return {"version": 1, "owners": dict(data["owners"])}
    except Exception:
        pass
    return {"version": 1, "owners": {}}


def register_cid_owner(
    cid: str,
    handle: str,
    *,
    bus_dir: str | Path | None = None,
    max_entries: int = 5000,
) -> bool:
    """Atomically record `cid -> handle` ownership in `BUS_DIR/cid_owners.json`."""
    clean_cid = str(cid or "").strip()
    norm = normalize_bot_handle(handle)
    if not clean_cid or not norm:
        return False
    bdir = resolve_bus_dir(bus_dir)
    bdir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(bdir, 0o700)
    except OSError:
        pass
    target = bdir / "cid_owners.json"
    lock_p = bdir / ".cid_owners.json.lock"
    fd = os.open(str(lock_p), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        with os.fdopen(fd, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                data = _read_cid_owners_unlocked(target)
                owners: dict[str, Any] = data["owners"]
                now = int(time.time())
                prev = owners.get(clean_cid)
                if isinstance(prev, dict) and prev.get("handle") == norm:
                    prev["updated_at"] = now
                else:
                    owners[clean_cid] = {"handle": norm, "updated_at": now}
                if len(owners) > max_entries:
                    ordered = sorted(
                        owners.items(),
                        key=lambda kv: int((kv[1] or {}).get("updated_at") or 0)
                        if isinstance(kv[1], dict)
                        else 0,
                    )
                    for drop_k, _ in ordered[: len(owners) - max_entries]:
                        owners.pop(drop_k, None)
                tmp = bdir / f".cid_owners.json.tmp.{os.getpid()}.{secrets.token_hex(6)}"
                tfd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(tfd, "w", encoding="utf-8") as wf:
                        json.dump(data, wf, indent=2, ensure_ascii=False)
                        wf.flush()
                        os.fsync(wf.fileno())
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, target)
                    os.chmod(target, 0o600)
                except Exception:
                    tmp.unlink(missing_ok=True)
                    raise
                return True
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception:
        return False


def lookup_cid_owner(
    cid: str,
    *,
    bus_dir: str | Path | None = None,
) -> str | None:
    clean_cid = str(cid or "").strip()
    if not clean_cid:
        return None
    owners = list_cid_owners(bus_dir=bus_dir)
    return owners.get(clean_cid)


def list_cid_owners(*, bus_dir: str | Path | None = None) -> dict[str, str]:
    target = cid_owners_path(bus_dir)
    if not target.is_file():
        return {}
    lock_p = target.parent / ".cid_owners.json.lock"
    try:
        fd = os.open(str(lock_p), os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_SH)
            try:
                data = _read_cid_owners_unlocked(target)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception:
        data = _read_cid_owners_unlocked(target)

    out: dict[str, str] = {}
    for k, v in (data.get("owners") or {}).items():
        if isinstance(v, dict):
            h = normalize_bot_handle(v.get("handle"))
        else:
            h = normalize_bot_handle(v)
        if h:
            out[str(k)] = h
    return out


# ---------------------------------------------------------------------------
# Compact Prompt Renderer (`[ACB_BOT_PROFILE rev=<n> handle=<h> role=<r>]`)
# ---------------------------------------------------------------------------


def _clip_section(text: str, limit: int) -> str:
    s = (text or "").strip()
    if not s:
        return ""
    if len(s) <= limit:
        return s
    return s[: max(64, limit - 40)].rstrip() + "\n...[truncated]"


def render_bot_profile_prompt(
    handle: str,
    *,
    role: str = "worker",
    profiles_dir: str | Path | None = None,
    catalog_dirs: Sequence[str | Path] | None = None,
    max_section_chars: int = 4000,
) -> tuple[int, str]:
    """Render a compact `[ACB_BOT_PROFILE ...]` block for first-turn / rev-change / post-compact injection."""
    norm = normalize_bot_handle(handle)
    if not norm:
        return 0, ""
    norm_role = str(role or "worker").strip().lower()
    root = resolve_profiles_dir(profiles_dir)
    bot_dir = root / norm
    if not bot_dir.is_dir():
        return 0, ""

    with bot_profile_lock(norm, profiles_dir=root, shared=True) as bd:
        meta = _read_profile_meta_unlocked(bd, norm, role=norm_role)
        rev = int(meta.get("rev") or 1)
        soul = _clip_section(
            _read_text_nofollow(bd / "SOUL.md", base_dir=bd, max_bytes=MAX_DOC_BYTES + 512),
            max_section_chars,
        )
        rules = _clip_section(
            _read_text_nofollow(bd / "RULES.md", base_dir=bd, max_bytes=MAX_DOC_BYTES + 512),
            max_section_chars,
        )
        memory_md = _clip_section(
            _read_text_nofollow(bd / "MEMORY.md", base_dir=bd, max_bytes=MAX_DOC_BYTES + 512),
            max_section_chars,
        )
        instincts_md = _clip_section(
            _read_text_nofollow(
                bd / "instincts" / "active-instincts.md", base_dir=bd, max_bytes=16 * 1024
            ),
            min(2500, max_section_chars),
        )

    skills_info = resolve_effective_skills(
        norm,
        role=norm_role,
        profiles_dir=root,
        catalog_dirs=catalog_dirs,
        include_paths=True,
    )
    own_skills = skills_info["own_skills"]
    team_skills = skills_info["team_skills"]
    enabled_catalog = [s for s in skills_info["catalog_skills"] if s.get("enabled")]

    lines: list[str] = [
        f"[ACB_BOT_PROFILE rev={rev} handle={norm} role={norm_role} memory_project=bot-{norm} memory_scope={memory_scope_for_role(norm_role)}]"
    ]
    if soul:
        lines.append("## SOUL\n" + soul)
    if rules:
        lines.append("## RULES\n" + rules)
    if memory_md:
        lines.append("## CURATED MEMORY\n" + memory_md)
    if instincts_md:
        lines.append("## ACTIVE INSTINCTS\n" + instincts_md)

    skill_lines: list[str] = []
    for sk in own_skills:
        skill_lines.append(
            f"- [own] `{sk['slug']}`: {sk.get('description') or sk['name']} (`{sk.get('skill_md_path', '')}`)"
        )
    for sk in enabled_catalog:
        skill_lines.append(
            f"- [catalog] `{sk['slug']}`: {sk.get('description') or sk['name']} (`{sk.get('skill_md_path', '')}`)"
        )
    if skill_lines:
        lines.append("## EFFECTIVE SKILLS\n" + "\n".join(skill_lines[:80]))

    if norm_role == "coordinator":
        if team_skills:
            ts_lines = [
                f"- [owner=@{sk.get('owner', '')}] `{sk['slug']}`: {sk.get('description') or sk['name']} (`{sk.get('skill_md_path', '')}`)"
                for sk in team_skills[:80]
            ]
            lines.append("## TEAM AGGREGATED SKILLS (COORDINATOR)\n" + "\n".join(ts_lines))
        lines.append(
            "## COORDINATOR MEMORY AGGREGATION\n"
            "- You hold full read visibility across all bots' memories (`bot-*`) and team skills. "
            "New memories you write default to `bot-" + norm + "`."
        )

    lines.append("[/ACB_BOT_PROFILE]")
    return rev, "\n\n".join(lines)


# ---------------------------------------------------------------------------
# Atomic `mcp_config.json` updater for wrapping `claude-mem` with proxy
# ---------------------------------------------------------------------------


def ensure_claude_mem_proxy_configured(
    *,
    mcp_config_path: str | Path | None = None,
    proxy_script: str | Path | None = None,
    python_exe: str | None = None,
    lock_path: str | Path = _MCP_CONFIG_LOCK_PATH,
) -> bool:
    """Wrap `claude-mem` in `mcp_config.json` with `claude_mem_mcp_proxy.py` atomically without altering other keys."""
    cfg_path = (
        Path(str(mcp_config_path)).expanduser()
        if mcp_config_path is not None
        else Path.home() / ".gemini" / "config" / "mcp_config.json"
    )
    script_path = (
        Path(str(proxy_script)).expanduser()
        if proxy_script is not None
        else Path(__file__).resolve().parent / "claude_mem_mcp_proxy.py"
    )
    if not script_path.is_file():
        return False

    py_bin = str(python_exe or sys.executable)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    lock_p = Path(str(lock_path))
    lock_p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_p), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        with os.fdopen(fd, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                cfg: dict[str, Any] = {}
                if cfg_path.is_file():
                    try:
                        loaded = json.loads(cfg_path.read_text(encoding="utf-8"))
                        if isinstance(loaded, dict):
                            cfg = loaded
                    except Exception:
                        cfg = {}
                servers = cfg.setdefault("mcpServers", {})
                if not isinstance(servers, dict):
                    servers = {}
                    cfg["mcpServers"] = servers

                existing = servers.get("claude-mem")
                desired: dict[str, Any] = {
                    "command": py_bin,
                    "args": [str(script_path)],
                }
                # Preserve any custom env on existing claude-mem entry if present
                if isinstance(existing, dict) and isinstance(existing.get("env"), dict) and existing["env"]:
                    desired["env"] = dict(existing["env"])

                if existing == desired:
                    return False

                servers["claude-mem"] = desired
                tmp = cfg_path.parent / f".{cfg_path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}"
                tfd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(tfd, "w", encoding="utf-8") as wf:
                        json.dump(cfg, wf, indent=2, ensure_ascii=False)
                        wf.write("\n")
                        wf.flush()
                        os.fsync(wf.fileno())
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, cfg_path)
                except Exception:
                    tmp.unlink(missing_ok=True)
                    raise
                return True
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception:
        return False
