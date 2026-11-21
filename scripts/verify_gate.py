#!/usr/bin/env python3
"""Scoped one-command verification gate for `agy-cli-bot`.

Runs atomic, zero-pollution verification checks for a requested scope:
  1. `py_compile`               - compiles scoped `.py` files into a TemporaryDirectory
                                  (dual Python with `~/camoufox-env/bin/python3` when applicable)
  2. `ruff_lint`                - auto-detected `ruff check --select F401,F821`
  3. `webui_build`              - offline `tsc --noEmit && npm run build` for `studio`/`all`
  4. `unittest`                 - scoped unit tests with `NoRealBrowser` import hook
  5. `audit_secrets`            - `scripts/sync_live.py audit-secrets --json` (exit 0 & 0 findings)
  6. `git_hygiene_and_protected`- `git diff --check` + protected-file modification guard

Usage:
  python3 scripts/verify_gate.py --scope studio --no-build --json
  python3 scripts/verify_gate.py --scope security --json
  python3 scripts/verify_gate.py --scope all --tier prod
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.abc
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

VALID_SCOPES: Tuple[str, ...] = ("studio", "browser", "bridge", "security", "all")
VALID_TIERS: Tuple[str, ...] = ("mvp", "prod")

DUAL_PYTHON_SCOPES = frozenset({"studio", "browser", "all"})
WEBUI_SCOPES = frozenset({"studio", "all"})

PROTECTED_FILES: Tuple[str, ...] = (
    ".agents/skills/google-profile/scripts/google_browser.py",
    ".agents/skills/live-browser/scripts/static/index.html",
)

BRIDGE_TEST_FILES: Tuple[str, ...] = (
    "tests/test_access_control.py",
    "tests/test_agy_auto_update_guard.py",
    "tests/test_bridge_core.py",
    "tests/test_bridge_p0.py",
    "tests/test_bot_bus.py",
    "tests/test_group_chat_bus.py",
    "tests/test_model_failover.py",
    "tests/test_queue_persistence_and_rollback.py",
    "tests/test_scheduler.py",
    "tests/test_memory_guard_and_dream.py",
)

SECURITY_TEST_FILES: Tuple[str, ...] = (
    "tests/test_security_audit_webui.py",
    "tests/test_verify_gate.py",
)

SKIP_WALK_DIRS = frozenset(
    {
        ".git",
        ".worktrees",
        "__pycache__",
        "node_modules",
        "venv",
        ".venv",
        ".ruff_cache",
        ".pytest_cache",
    }
)

BLOCKED_BROWSER_ROOTS: Tuple[str, ...] = ("camoufox", "playwright")


class NoRealBrowserFinder(importlib.abc.MetaPathFinder):
    """`sys.meta_path` hook that blocks importing real browser automation libraries."""

    blocked_roots: Tuple[str, ...] = BLOCKED_BROWSER_ROOTS

    def find_spec(self, fullname: str, path: Any, target: Any = None) -> Any:
        root_pkg = fullname.split(".", 1)[0]
        if root_pkg in self.blocked_roots:
            raise ImportError(
                f"Real browser import blocked by verify_gate NoRealBrowser hook: {fullname}"
            )
        return None


# Public alias matching the spec terminology.
NoRealBrowser = NoRealBrowserFinder


def install_no_real_browser_hook() -> NoRealBrowserFinder:
    """Install `NoRealBrowserFinder` at the front of `sys.meta_path` (idempotent)."""
    for existing in sys.meta_path:
        if isinstance(existing, NoRealBrowserFinder):
            return existing
    finder = NoRealBrowserFinder()
    sys.meta_path.insert(0, finder)
    return finder


@dataclasses.dataclass
class StepResult:
    name: str
    status: str  # "pass" | "fail" | "skip"
    duration_s: float
    exit_code: int
    summary: str
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "name": self.name,
            "status": self.status,
            "duration_s": round(self.duration_s, 3),
            "exit_code": self.exit_code,
            "summary": self.summary,
        }
        if self.details:
            data["details"] = self.details
        return data


def default_repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def find_camoufox_python() -> Optional[str]:
    """Return path to `~/camoufox-env/bin/python3` (or `AGY_CAMOUFOX_PYTHON`) without resolving symlinks."""
    override = os.environ.get("AGY_CAMOUFOX_PYTHON", "").strip()
    if override:
        candidate = Path(override).expanduser()
        return str(candidate) if candidate.exists() else None
    candidate = Path.home() / "camoufox-env" / "bin" / "python3"
    return str(candidate) if candidate.exists() else None


def find_system_python(camoufox_py: Optional[str] = None) -> str:
    """Return the system Python executable path."""
    current = sys.executable
    if camoufox_py and os.path.abspath(current) == os.path.abspath(camoufox_py):
        sys_py = Path("/usr/bin/python3")
        if sys_py.exists():
            return str(sys_py)
    return current


def _child_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Clone current environment faithfully (never unsets or mutates `AGY_MEMORY_READONLY`)."""
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra:
        for k, v in extra.items():
            if k == "AGY_MEMORY_READONLY":
                continue
            env[k] = v
    return env


def _iter_py_under(root: Path, rel_dir: str) -> List[str]:
    base = root / rel_dir
    if not base.is_dir():
        return []
    found: List[str] = []
    for cur, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_WALK_DIRS)
        cur_p = Path(cur)
        for fn in sorted(files):
            if fn.endswith(".py"):
                rel = (cur_p / fn).relative_to(root).as_posix()
                found.append(rel)
    return found


def _glob_existing_tests(root: Path, pattern: str) -> List[str]:
    tests_dir = root / "tests"
    if not tests_dir.is_dir():
        return []
    return sorted(
        p.relative_to(root).as_posix()
        for p in tests_dir.glob(pattern)
        if p.is_file()
    )


def _existing_rel_files(root: Path, rel_paths: Sequence[str]) -> List[str]:
    out: List[str] = []
    for rel in rel_paths:
        if (root / rel).is_file():
            out.append(rel)
    return out


def collect_scope_py_files(root: Path, scope: str) -> List[str]:
    """Collect sorted, deduplicated relative `.py` file paths for a gate scope."""
    if scope not in VALID_SCOPES:
        raise ValueError(f"Unsupported scope: {scope!r}")

    if scope == "all":
        merged: List[str] = []
        seen = set()
        for sub in ("studio", "browser", "bridge", "security"):
            for item in collect_scope_py_files(root, sub):
                if item not in seen:
                    seen.add(item)
                    merged.append(item)
        return sorted(merged)

    files: List[str] = []
    if scope == "studio":
        files.extend(_iter_py_under(root, "studio"))
        files.extend(_glob_existing_tests(root, "test_studio*.py"))
        files.extend(_existing_rel_files(root, ["tests/test_security_audit_webui.py"]))
    elif scope == "browser":
        files.extend(_iter_py_under(root, ".agents/skills/live-browser/scripts"))
        files.extend(_iter_py_under(root, ".agents/skills/google-profile/scripts"))
        files.extend(_glob_existing_tests(root, "test_live_browser*.py"))
        files.extend(_existing_rel_files(root, ["tests/test_browser_panel.py"]))
    elif scope == "bridge":
        files.extend(_iter_py_under(root, "bridge"))
        files.extend(_existing_rel_files(root, ["scripts/agy_cli_upgrade.py"]))
        files.extend(_existing_rel_files(root, BRIDGE_TEST_FILES))
    elif scope == "security":
        files.extend(
            _existing_rel_files(
                root,
                [
                    "scripts/security_audit.py",
                    "scripts/verify_gate.py",
                    "scripts/sync_live.py",
                ],
            )
        )
        files.extend(_existing_rel_files(root, SECURITY_TEST_FILES))

    return sorted(set(files))


def collect_scope_unittest_plan(
    root: Path,
    scope: str,
    *,
    system_py: Optional[str] = None,
    camoufox_py: Optional[str] = None,
) -> List[Tuple[str, str]]:
    """Build ordered, deduplicated `(python_executable, test_rel_path)` pairs for a scope."""
    if scope not in VALID_SCOPES:
        raise ValueError(f"Unsupported scope: {scope!r}")

    cf_py = camoufox_py if camoufox_py is not None else find_camoufox_python()
    sys_py = system_py if system_py is not None else find_system_python(cf_py)

    plan: List[Tuple[str, str]] = []
    seen: set[Tuple[str, str]] = set()

    def _add(py_exe: str, test_rel: str) -> None:
        key = (py_exe, test_rel)
        if key not in seen:
            seen.add(key)
            plan.append(key)

    scopes = ("studio", "browser", "bridge", "security") if scope == "all" else (scope,)
    for sc in scopes:
        if sc == "studio":
            studio_py = cf_py or sys_py
            for tf in _glob_existing_tests(root, "test_studio*.py"):
                _add(studio_py, tf)
            for tf in _existing_rel_files(root, ["tests/test_security_audit_webui.py"]):
                _add(sys_py, tf)
        elif sc == "browser":
            browser_tests = sorted(
                set(
                    _glob_existing_tests(root, "test_live_browser*.py")
                    + _existing_rel_files(root, ["tests/test_browser_panel.py"])
                )
            )
            interpreters = [sys_py]
            if cf_py and os.path.abspath(cf_py) != os.path.abspath(sys_py):
                interpreters.append(cf_py)
            for interp in interpreters:
                for tf in browser_tests:
                    _add(interp, tf)
        elif sc == "bridge":
            for tf in _existing_rel_files(root, BRIDGE_TEST_FILES):
                _add(sys_py, tf)
        elif sc == "security":
            for tf in _existing_rel_files(root, SECURITY_TEST_FILES):
                _add(sys_py, tf)

    return plan


def _tail_text(text: str, max_lines: int = 8, max_chars: int = 600) -> str:
    lines = [ln.rstrip() for ln in text.strip().splitlines() if ln.strip()]
    snippet = "\n".join(lines[-max_lines:])
    if len(snippet) > max_chars:
        snippet = "..." + snippet[-max_chars:]
    return snippet


_PY_COMPILE_RUNNER = r"""
import os, py_compile, sys
out_dir = sys.argv[1]
files = sys.argv[2:]
errors = []
for idx, src in enumerate(files):
    cfile = os.path.join(out_dir, f"m_{idx}.pyc")
    try:
        py_compile.compile(src, cfile=cfile, doraise=True)
    except Exception as exc:
        errors.append(f"{src}: {exc}")
if errors:
    sys.stderr.write("\n".join(errors) + "\n")
    sys.exit(1)
"""


def step_py_compile(
    root: Path,
    scope: str,
    *,
    system_py: str,
    camoufox_py: Optional[str],
) -> StepResult:
    t0 = time.monotonic()
    py_files = collect_scope_py_files(root, scope)
    if not py_files:
        return StepResult(
            name="py_compile",
            status="skip",
            duration_s=time.monotonic() - t0,
            exit_code=0,
            summary=f"No Python files matched scope '{scope}'",
        )

    interpreters = [system_py]
    if (
        scope in DUAL_PYTHON_SCOPES
        and camoufox_py
        and os.path.abspath(camoufox_py) != os.path.abspath(system_py)
    ):
        interpreters.append(camoufox_py)

    abs_files = [str(root / rel) for rel in py_files]
    failures: List[Dict[str, Any]] = []
    ran_interpreters: List[str] = []

    with tempfile.TemporaryDirectory(prefix="agy_verify_pyc_") as tmpdir:
        for idx, py_exe in enumerate(interpreters):
            out_dir = Path(tmpdir) / f"py_{idx}"
            out_dir.mkdir(parents=True, exist_ok=True)
            ran_interpreters.append(py_exe)
            proc = subprocess.run(
                [py_exe, "-c", _PY_COMPILE_RUNNER, str(out_dir), *abs_files],
                cwd=str(root),
                env=_child_env(),
                capture_output=True,
                text=True,
            )
            if proc.returncode != 0:
                failures.append(
                    {
                        "python": py_exe,
                        "exit_code": proc.returncode,
                        "error": _tail_text(proc.stderr or proc.stdout),
                    }
                )

    dur = time.monotonic() - t0
    if failures:
        first_err = failures[0]["error"]
        return StepResult(
            name="py_compile",
            status="fail",
            duration_s=dur,
            exit_code=failures[0]["exit_code"] or 1,
            summary=f"Compile failed on {len(failures)}/{len(interpreters)} interpreter(s): {first_err}",
            details={"files_count": len(py_files), "interpreters": ran_interpreters, "failures": failures},
        )

    return StepResult(
        name="py_compile",
        status="pass",
        duration_s=dur,
        exit_code=0,
        summary=f"Compiled {len(py_files)} file(s) across {len(interpreters)} interpreter(s) into TemporaryDirectory",
        details={"files_count": len(py_files), "interpreters": ran_interpreters},
    )


def step_ruff_lint(root: Path, scope: str) -> StepResult:
    t0 = time.monotonic()
    ruff_bin = shutil.which("ruff")
    if not ruff_bin:
        return StepResult(
            name="ruff_lint",
            status="skip",
            duration_s=time.monotonic() - t0,
            exit_code=0,
            summary="ruff not installed; skipped",
        )

    py_files = collect_scope_py_files(root, scope)
    if not py_files:
        return StepResult(
            name="ruff_lint",
            status="skip",
            duration_s=time.monotonic() - t0,
            exit_code=0,
            summary=f"No Python files matched scope '{scope}'",
        )

    with tempfile.TemporaryDirectory(prefix="agy_verify_ruff_") as tmpdir:
        proc = subprocess.run(
            [ruff_bin, "check", "--select", "F401,F821", *py_files],
            cwd=str(root),
            env=_child_env({"RUFF_CACHE_DIR": tmpdir}),
            capture_output=True,
            text=True,
        )

    dur = time.monotonic() - t0
    if proc.returncode != 0:
        snippet = _tail_text(proc.stdout or proc.stderr)
        return StepResult(
            name="ruff_lint",
            status="fail",
            duration_s=dur,
            exit_code=proc.returncode,
            summary=f"ruff F401/F821 check failed: {snippet}",
            details={"files_count": len(py_files)},
        )

    return StepResult(
        name="ruff_lint",
        status="pass",
        duration_s=dur,
        exit_code=0,
        summary=f"ruff F401/F821 clean across {len(py_files)} file(s)",
        details={"files_count": len(py_files)},
    )


def _is_git_repo(root: Path) -> bool:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return False
    if proc.returncode != 0:
        return False
    toplevel = proc.stdout.strip()
    if not toplevel:
        return False
    try:
        return Path(toplevel).resolve() == root.resolve()
    except OSError:
        return False


def _webui_has_local_changes(root: Path) -> bool:
    if not _is_git_repo(root):
        return True
    proc = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--", "webui"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return True
    return bool(proc.stdout.strip())


def step_webui_build(
    root: Path,
    scope: str,
    *,
    tier: str,
    no_build: bool,
) -> StepResult:
    t0 = time.monotonic()
    if scope not in WEBUI_SCOPES:
        return StepResult(
            name="webui_build",
            status="skip",
            duration_s=time.monotonic() - t0,
            exit_code=0,
            summary=f"Not applicable for scope '{scope}'",
        )
    if no_build:
        return StepResult(
            name="webui_build",
            status="skip",
            duration_s=time.monotonic() - t0,
            exit_code=0,
            summary="Skipped via --no-build",
        )

    webui_dir = root / "webui"
    if not (webui_dir / "package.json").is_file():
        return StepResult(
            name="webui_build",
            status="skip",
            duration_s=time.monotonic() - t0,
            exit_code=0,
            summary="webui/package.json not found; skipped",
        )

    if tier == "mvp" and not _webui_has_local_changes(root):
        return StepResult(
            name="webui_build",
            status="skip",
            duration_s=time.monotonic() - t0,
            exit_code=0,
            summary="No local changes under webui/ in mvp tier; skipped",
        )

    build_env = _child_env({"npm_config_offline": "true"})
    cmds = [
        (["npx", "--no-install", "tsc", "--noEmit"], "tsc --noEmit"),
        (["npm", "run", "build"], "npm run build"),
    ]
    for cmd, label in cmds:
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(webui_dir),
                env=build_env,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            return StepResult(
                name="webui_build",
                status="fail",
                duration_s=time.monotonic() - t0,
                exit_code=127,
                summary=f"{label} failed to start: {exc}",
            )
        if proc.returncode != 0:
            snippet = _tail_text(proc.stderr or proc.stdout)
            return StepResult(
                name="webui_build",
                status="fail",
                duration_s=time.monotonic() - t0,
                exit_code=proc.returncode,
                summary=f"{label} failed (exit {proc.returncode}): {snippet}",
            )

    return StepResult(
        name="webui_build",
        status="pass",
        duration_s=time.monotonic() - t0,
        exit_code=0,
        summary="Offline tsc --noEmit and npm run build succeeded",
    )


_UNITTEST_NO_REAL_BROWSER_RUNNER = r"""
import importlib.abc, sys, unittest

class NoRealBrowserFinder(importlib.abc.MetaPathFinder):
    BLOCKED = ("camoufox", "playwright")
    def find_spec(self, fullname, path, target=None):
        if fullname.split(".", 1)[0] in self.BLOCKED:
            raise ImportError(
                f"Real browser import blocked by verify_gate NoRealBrowser hook: {fullname}"
            )
        return None

sys.meta_path.insert(0, NoRealBrowserFinder())
if "" not in sys.path:
    sys.path.insert(0, "")

unittest.main(module=None, argv=["unittest", *sys.argv[1:]])
"""


def step_unittest(
    root: Path,
    scope: str,
    *,
    system_py: str,
    camoufox_py: Optional[str],
) -> StepResult:
    t0 = time.monotonic()
    plan = collect_scope_unittest_plan(
        root,
        scope,
        system_py=system_py,
        camoufox_py=camoufox_py,
    )
    if not plan:
        return StepResult(
            name="unittest",
            status="skip",
            duration_s=time.monotonic() - t0,
            exit_code=0,
            summary=f"No test files matched scope '{scope}'",
        )

    runs: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    run_env = _child_env({"AGY_VERIFY_GATE_NESTED": "1"})

    for py_exe, test_rel in plan:
        item_t0 = time.monotonic()
        proc = subprocess.run(
            [py_exe, "-c", _UNITTEST_NO_REAL_BROWSER_RUNNER, test_rel],
            cwd=str(root),
            env=run_env,
            capture_output=True,
            text=True,
        )
        item_dur = round(time.monotonic() - item_t0, 3)
        entry: Dict[str, Any] = {
            "python": py_exe,
            "test": test_rel,
            "exit_code": proc.returncode,
            "duration_s": item_dur,
        }
        if proc.returncode != 0:
            entry["error"] = _tail_text(proc.stderr or proc.stdout)
            failures.append(entry)
        runs.append(entry)

    dur = time.monotonic() - t0
    if failures:
        first = failures[0]
        return StepResult(
            name="unittest",
            status="fail",
            duration_s=dur,
            exit_code=first["exit_code"] or 1,
            summary=(
                f"{len(failures)}/{len(runs)} test run(s) failed "
                f"(first: {first['test']} via {Path(first['python']).name})"
            ),
            details={"runs": runs, "failures": failures},
        )

    return StepResult(
        name="unittest",
        status="pass",
        duration_s=dur,
        exit_code=0,
        summary=f"All {len(runs)} scoped test run(s) passed with NoRealBrowser hook",
        details={"runs": runs},
    )


def step_audit_secrets(root: Path, *, system_py: str) -> StepResult:
    t0 = time.monotonic()
    sync_script = root / "scripts" / "sync_live.py"
    audit_script = root / "scripts" / "security_audit.py"
    if sync_script.is_file():
        cmd = [system_py, str(sync_script), "audit-secrets", "--json"]
    elif audit_script.is_file():
        cmd = [
            system_py,
            str(audit_script),
            "--mode",
            "public-release",
            "--root",
            str(root),
            "--json",
        ]
    else:
        return StepResult(
            name="audit_secrets",
            status="skip",
            duration_s=time.monotonic() - t0,
            exit_code=0,
            summary="Neither scripts/sync_live.py nor scripts/security_audit.py found; skipped",
        )

    proc = subprocess.run(
        cmd,
        cwd=str(root),
        env=_child_env(),
        capture_output=True,
        text=True,
    )
    dur = time.monotonic() - t0

    try:
        payload = json.loads(proc.stdout)
    except Exception as exc:
        return StepResult(
            name="audit_secrets",
            status="fail",
            duration_s=dur,
            exit_code=proc.returncode or 1,
            summary=f"Failed to parse audit-secrets JSON output: {exc}",
            details={"stderr": _tail_text(proc.stderr), "stdout": _tail_text(proc.stdout)},
        )

    findings = payload.get("findings") if isinstance(payload, dict) else None
    history_findings = payload.get("history_findings", []) if isinstance(payload, dict) else []
    if proc.returncode != 0 or not isinstance(findings, list) or len(findings) > 0 or len(history_findings) > 0:
        f_count = len(findings) if isinstance(findings, list) else -1
        return StepResult(
            name="audit_secrets",
            status="fail",
            duration_s=dur,
            exit_code=proc.returncode or 1,
            summary=f"audit-secrets failed (exit={proc.returncode}, findings={f_count})",
            details={
                "findings_count": f_count,
                "history_findings_count": len(history_findings),
                "sample_findings": findings[:5] if isinstance(findings, list) else [],
            },
        )

    scanned = payload.get("scanned_files", "?")
    return StepResult(
        name="audit_secrets",
        status="pass",
        duration_s=dur,
        exit_code=0,
        summary=f"0 findings across {scanned} scanned file(s)",
        details={"scanned_files": scanned, "findings_count": 0},
    )


def step_git_hygiene_and_protected(root: Path, *, allow_protected: bool) -> StepResult:
    t0 = time.monotonic()
    if not _is_git_repo(root):
        return StepResult(
            name="git_hygiene_and_protected",
            status="skip",
            duration_s=time.monotonic() - t0,
            exit_code=0,
            summary="Not a git repository; skipped",
        )

    diff_check = subprocess.run(
        ["git", "-C", str(root), "diff", "--check"],
        capture_output=True,
        text=True,
    )
    cached_check = subprocess.run(
        ["git", "-C", str(root), "diff", "--cached", "--check"],
        capture_output=True,
        text=True,
    )
    hygiene_errors: List[str] = []
    if diff_check.returncode != 0:
        hygiene_errors.append(_tail_text(diff_check.stdout or diff_check.stderr))
    if cached_check.returncode != 0:
        hygiene_errors.append(_tail_text(cached_check.stdout or cached_check.stderr))

    has_head = (
        subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            text=True,
        ).returncode
        == 0
    )

    touched_protected: List[str] = []
    if has_head:
        p_diff = subprocess.run(
            ["git", "-C", str(root), "diff", "--name-only", "HEAD", "--", *PROTECTED_FILES],
            capture_output=True,
            text=True,
        )
        for line in p_diff.stdout.splitlines():
            norm = line.strip().replace("\\", "/")
            if norm and norm not in touched_protected:
                touched_protected.append(norm)

    p_status = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain", "--", *PROTECTED_FILES],
        capture_output=True,
        text=True,
    )
    for line in p_status.stdout.splitlines():
        if len(line) >= 4:
            rel = line[3:].strip()
            if " -> " in rel:
                rel = rel.split(" -> ", 1)[1].strip()
            rel = rel.strip('"').replace("\\", "/")
            if rel in PROTECTED_FILES and rel not in touched_protected:
                touched_protected.append(rel)

    dur = time.monotonic() - t0
    if hygiene_errors:
        return StepResult(
            name="git_hygiene_and_protected",
            status="fail",
            duration_s=dur,
            exit_code=diff_check.returncode or cached_check.returncode or 1,
            summary=f"git diff --check failed: {hygiene_errors[0]}",
            details={"hygiene_errors": hygiene_errors, "touched_protected": touched_protected},
        )

    if touched_protected and not allow_protected:
        return StepResult(
            name="git_hygiene_and_protected",
            status="fail",
            duration_s=dur,
            exit_code=1,
            summary=(
                "Protected file(s) modified relative to HEAD "
                f"(pass --allow-protected to override): {', '.join(touched_protected)}"
            ),
            details={"touched_protected": touched_protected, "allow_protected": False},
        )

    if touched_protected and allow_protected:
        return StepResult(
            name="git_hygiene_and_protected",
            status="pass",
            duration_s=dur,
            exit_code=0,
            summary=(
                "git diff --check clean; protected file modification(s) allowed via --allow-protected: "
                + ", ".join(touched_protected)
            ),
            details={"touched_protected": touched_protected, "allow_protected": True},
        )

    return StepResult(
        name="git_hygiene_and_protected",
        status="pass",
        duration_s=dur,
        exit_code=0,
        summary="git diff --check clean and 0 protected files modified",
        details={"touched_protected": [], "allow_protected": allow_protected},
    )


def run_gate(
    *,
    root: Path,
    scope: str = "all",
    tier: str = "mvp",
    no_build: bool = False,
    allow_protected: bool = False,
    system_py: Optional[str] = None,
    camoufox_py: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute all 6 atomic gate steps and return a structured report dict."""
    t0 = time.monotonic()
    resolved_root = root.resolve()
    cf_py = camoufox_py if camoufox_py is not None else find_camoufox_python()
    sys_py = system_py if system_py is not None else find_system_python(cf_py)

    steps: List[StepResult] = [
        step_py_compile(resolved_root, scope, system_py=sys_py, camoufox_py=cf_py),
        step_ruff_lint(resolved_root, scope),
        step_webui_build(resolved_root, scope, tier=tier, no_build=no_build),
        step_unittest(resolved_root, scope, system_py=sys_py, camoufox_py=cf_py),
        step_audit_secrets(resolved_root, system_py=sys_py),
        step_git_hygiene_and_protected(resolved_root, allow_protected=allow_protected),
    ]

    counts = {"pass": 0, "fail": 0, "skip": 0}
    for s in steps:
        counts[s.status] = counts.get(s.status, 0) + 1

    ok = counts["fail"] == 0
    return {
        "ok": ok,
        "scope": scope,
        "tier": tier,
        "root": str(resolved_root),
        "total_duration_s": round(time.monotonic() - t0, 3),
        "summary": counts,
        "steps": [s.to_dict() for s in steps],
    }


def format_human_table(report: Dict[str, Any]) -> str:
    lines = [
        f"AGY Verify Gate | scope={report['scope']} | tier={report['tier']} | root={report['root']}",
        "-" * 100,
        f"{'STEP':<28} {'STATUS':<8} {'EXIT':<6} {'TIME':<8} SUMMARY",
        "-" * 100,
    ]
    for st in report["steps"]:
        status_label = st["status"].upper()
        dur_str = f"{st['duration_s']:.3f}s"
        lines.append(
            f"{st['name']:<28} {status_label:<8} {st['exit_code']:<6} {dur_str:<8} {st['summary']}"
        )
    lines.append("-" * 100)
    s = report["summary"]
    verdict = "PASS" if report["ok"] else "FAIL"
    lines.append(
        f"RESULT: {verdict} (pass={s['pass']}, fail={s['fail']}, skip={s['skip']}, "
        f"total={report['total_duration_s']:.3f}s)"
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scoped verification gate for agy-cli-bot (compile, lint, build, unittest, secrets, git hygiene)."
    )
    parser.add_argument(
        "--scope",
        choices=VALID_SCOPES,
        default="all",
        help="Verification scope (default: all)",
    )
    parser.add_argument(
        "--tier",
        choices=VALID_TIERS,
        default="mvp",
        help="Verification tier: mvp skips unchanged webui build; prod forces webui build (default: mvp)",
    )
    parser.add_argument(
        "--no-build",
        action="store_true",
        help="Skip webui TypeScript/Vite build step",
    )
    parser.add_argument(
        "--allow-protected",
        action="store_true",
        help="Explicitly allow modifications to protected files relative to HEAD",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit strictly valid JSON receipt to stdout",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=default_repo_root(),
        help="Repository root directory override (default: repository root)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    report = run_gate(
        root=args.root,
        scope=args.scope,
        tier=args.tier,
        no_build=args.no_build,
        allow_protected=args.allow_protected,
    )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(format_human_table(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
