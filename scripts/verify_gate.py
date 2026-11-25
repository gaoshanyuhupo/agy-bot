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
import concurrent.futures
import dataclasses
import importlib.abc
import json
import os
from pathlib import Path
import re
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
HOOKS_CANARY_SCOPES = frozenset({"security", "all"})
HOOKS_CANARY_MODEL = "gemini-3.8-flash-low"
HOOKS_CANARY_MAX_ATTEMPTS = 2

_EMPTY_PRETOOL_DENY_RE = re.compile(
    r"^\s*tool\s+call\s+denied\s+by\s+pre-tool\s+hook\s*:(.*)$",
    re.IGNORECASE | re.DOTALL,
)

PROTECTED_FILES: Tuple[str, ...] = (
    ".agents/skills/google-profile/scripts/google_browser.py",
    ".agents/skills/live-browser/scripts/static/index.html",
)

BRIDGE_TEST_FILES: Tuple[str, ...] = (
    "tests/test_access_control.py",
    "tests/test_agent_driver.py",
    "tests/test_agy_auto_update_guard.py",
    "tests/test_benchmark_digest.py",
    "tests/test_bridge_anti_hang.py",
    "tests/test_bridge_core.py",
    "tests/test_bridge_modularization.py",
    "tests/test_bridge_p0.py",
    "tests/test_bot_bus.py",
    "tests/test_bot_isolation.py",
    "tests/test_bot_isolation_hooks.py",
    "tests/test_external_drivers.py",
    "tests/test_federation_hub.py",
    "tests/test_federation_registry.py",
    "tests/test_google_accounts.py",
    "tests/test_group_chat_bus.py",
    "tests/test_group_on_demand.py",
    "tests/test_model_failover.py",
    "tests/test_queue_persistence_and_rollback.py",
    "tests/test_scheduler.py",
    "tests/test_memory_guard_and_dream.py",
    "tests/test_p2_hardening.py",
    "tests/test_pretool_guard_defenses.py",
    "tests/test_taint_outbound_guard.py",
)

SECURITY_TEST_FILES: Tuple[str, ...] = (
    "tests/test_bot_isolation.py",
    "tests/test_bot_isolation_hooks.py",
    "tests/test_external_drivers.py",
    "tests/test_federation_hub.py",
    "tests/test_federation_registry.py",
    "tests/test_p2_hardening.py",
    "tests/test_pretool_guard_defenses.py",
    "tests/test_security_audit_webui.py",
    "tests/test_taint_outbound_guard.py",
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
        files.extend(_iter_py_under(root, "hooks"))
        files.extend(
            _existing_rel_files(
                root,
                [
                    "scripts/agy_cli_upgrade.py",
                    "scripts/benchmark_digest.py",
                    "scripts/migrate_bot_isolation.py",
                ],
            )
        )
        files.extend(_existing_rel_files(root, BRIDGE_TEST_FILES))
    elif scope == "security":
        files.extend(_iter_py_under(root, "hooks"))
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
    with tempfile.TemporaryDirectory(prefix="agy_verify_webui_dist_") as tmpdir:
        cmds = [
            (["npx", "--no-install", "tsc", "--noEmit"], "tsc --noEmit"),
            (
                ["npx", "--no-install", "vite", "build", "--outDir", tmpdir, "--emptyOutDir"],
                "vite build (isolated outDir)",
            ),
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
        summary="Offline tsc --noEmit and isolated vite build succeeded (live webui/dist untouched)",
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
    allow_protected: bool = False,
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
    extra_env: Dict[str, str] = {"AGY_VERIFY_GATE_NESTED": "1"}
    if allow_protected:
        extra_env["AGY_VERIFY_GATE_ALLOW_PROTECTED"] = "1"
    run_env = _child_env(extra_env)
    if not allow_protected:
        run_env.pop("AGY_VERIFY_GATE_ALLOW_PROTECTED", None)

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


def find_agy_bin(explicit: Optional[str] = None) -> Optional[str]:
    """Locate the Antigravity CLI (`agy`) binary without hardcoding host user paths."""
    if explicit is not None:
        raw = str(explicit).strip()
        return os.path.abspath(os.path.expandvars(os.path.expanduser(raw))) if raw else None
    env_bin = (os.environ.get("AGY_TG_AGY_BIN") or os.environ.get("AGY_BIN") or "").strip()
    if env_bin:
        cand = Path(os.path.abspath(os.path.expandvars(os.path.expanduser(env_bin))))
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    which_bin = shutil.which("agy")
    if which_bin:
        return os.path.abspath(which_bin)
    local_bin = Path.home() / ".local" / "bin" / "agy"
    if local_bin.is_file() and os.access(local_bin, os.X_OK):
        return os.path.abspath(str(local_bin))
    return None


def has_agy_auth() -> bool:
    """Return True if local `~/.gemini` holds Antigravity CLI credentials."""
    cfg_dir = Path.home() / ".gemini"
    if not cfg_dir.is_dir():
        return False
    for name in ("antigravity-cli", "oauth_creds.json", "google_accounts.json"):
        if (cfg_dir / name).exists():
            return True
    return False


def _query_agy_version(agy_bin: str, *, timeout: float = 10.0) -> str:
    env = _child_env({"AGY_CLI_DISABLE_AUTO_UPDATE": "1"})
    try:
        proc = subprocess.run(
            [agy_bin, "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            shell=False,
        )
        if proc.returncode == 0:
            raw = (proc.stdout or proc.stderr or "").strip()
            if raw:
                return raw.splitlines()[0].strip()
    except Exception:
        pass
    return "unknown"


def _inspect_canary_stream_json(stdout_text: str) -> Dict[str, Any]:
    """Inspect structured stream-json events emitted by `agy -p --output-format stream-json`."""
    tool_errors: List[Dict[str, str]] = []
    pretool_denials: List[Dict[str, str]] = []
    empty_pretool_denials: List[Dict[str, str]] = []
    taint_guard_denials: List[Dict[str, str]] = []
    stream_errors: List[str] = []
    tool_steps_seen = 0
    run_command_steps_seen = 0
    result_status = ""
    denied_actions: List[Any] = []

    for raw_line in (stdout_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if not isinstance(ev, dict):
            continue
        kind = ev.get("event")
        if kind == "step_update":
            su = ev.get("step_update")
            if not isinstance(su, dict) or su.get("step_type") != "tool":
                continue
            tool_steps_seen += 1
            tname = str(su.get("tool_name") or "")
            if tname == "run_command":
                run_command_steps_seen += 1
            tinfo = su.get("tool_info")
            err_msgs: List[str] = []
            for container in (tinfo, su):
                if not isinstance(container, dict):
                    continue
                err_obj = container.get("error")
                if isinstance(err_obj, dict):
                    msg = str(err_obj.get("message") or "").strip()
                    if msg:
                        err_msgs.append(msg)
                elif isinstance(err_obj, str) and err_obj.strip():
                    err_msgs.append(err_obj.strip())
            for emsg in err_msgs:
                entry = {"tool_name": tname, "message": emsg}
                tool_errors.append(entry)
                m = _EMPTY_PRETOOL_DENY_RE.match(emsg)
                if m:
                    pretool_denials.append(entry)
                    reason_tail = (m.group(1) or "").strip()
                    if not reason_tail:
                        empty_pretool_denials.append(entry)
                    elif "[taint-outbound-guard]" in reason_tail:
                        taint_guard_denials.append(entry)
        elif kind == "error":
            err_payload = ev.get("error")
            if isinstance(err_payload, dict):
                msg = str(err_payload.get("message") or err_payload).strip()
            else:
                msg = str(err_payload or ev.get("message") or "stream error").strip()
            if msg:
                stream_errors.append(msg)
        elif kind == "result":
            res = ev.get("result") if isinstance(ev.get("result"), dict) else ev
            result_status = str(res.get("status") or "")
            da = res.get("denied_actions")
            if isinstance(da, list):
                denied_actions = da

    return {
        "tool_errors": tool_errors,
        "pretool_denials": pretool_denials,
        "empty_pretool_denials": empty_pretool_denials,
        "taint_guard_denials": taint_guard_denials,
        "stream_errors": stream_errors,
        "tool_steps_seen": tool_steps_seen,
        "run_command_steps_seen": run_command_steps_seen,
        "result_status": result_status,
        "denied_actions": denied_actions,
    }


def _extract_canary_result_response(stdout_text: str, *, max_chars: int = 160) -> str:
    """Extract a truncated summary of `result.response` from stream-json stdout for diagnostics."""
    last_resp = ""
    for raw_line in (stdout_text or "").splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if isinstance(ev, dict) and ev.get("event") == "result":
            res = ev.get("result") if isinstance(ev.get("result"), dict) else ev
            val = res.get("response")
            if isinstance(val, str) and val.strip():
                last_resp = " ".join(val.split())
    if len(last_resp) > max_chars:
        return last_resp[:max_chars] + "..."
    return last_resp


def _validate_hooks_json_config(hooks_json_path: Path) -> Dict[str, Any]:
    """Validate `hooks.json` structure and `taint-outbound-guard` PreToolUse schema (read-only)."""
    if not hooks_json_path.is_file():
        return {"ok": False, "error": f"hooks.json not found: {hooks_json_path}"}
    try:
        data = json.loads(hooks_json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"ok": False, "error": f"Failed to parse JSON: {exc}"}
    if not isinstance(data, dict):
        return {"ok": False, "error": "hooks.json root must be a JSON object"}
    cfg = data.get("taint-outbound-guard")
    if not isinstance(cfg, dict):
        return {"ok": False, "error": "Missing 'taint-outbound-guard' object in hooks.json"}
    enabled = bool(cfg.get("enabled", True))
    pre = cfg.get("PreToolUse")
    if not isinstance(pre, list) or not pre:
        return {"ok": False, "enabled": enabled, "error": "'taint-outbound-guard.PreToolUse' must be a non-empty list"}
    group = pre[0]
    if not isinstance(group, dict):
        return {"ok": False, "enabled": enabled, "error": "'PreToolUse[0]' must be a grouped object"}
    matcher = str(group.get("matcher") or "").strip()
    hooks_list = group.get("hooks")
    if not matcher or not isinstance(hooks_list, list) or not hooks_list:
        return {"ok": False, "enabled": enabled, "error": "'PreToolUse[0]' requires non-empty 'matcher' and 'hooks'"}
    handler = hooks_list[0]
    if not isinstance(handler, dict) or handler.get("type") != "command":
        return {"ok": False, "enabled": enabled, "error": "'PreToolUse[0].hooks[0]' must be type='command'"}
    cmd = str(handler.get("command") or "").strip()
    if not cmd:
        return {"ok": False, "enabled": enabled, "error": "Empty command in taint-outbound-guard PreToolUse handler"}
    if "AGY_INTERNAL_OBSERVER" in cmd:
        return {
            "ok": False,
            "enabled": enabled,
            "error": "taint-outbound-guard command must NOT skip on AGY_INTERNAL_OBSERVER",
        }
    try:
        re.compile(f"^(?:{matcher})$")
    except re.error as exc:
        return {"ok": False, "enabled": enabled, "error": f"Invalid PreToolUse matcher regex: {exc}"}
    raw_timeout = handler.get("timeout")
    if raw_timeout is None or raw_timeout == "":
        timeout_val = 10
    elif isinstance(raw_timeout, bool):
        return {
            "ok": False,
            "enabled": enabled,
            "error": f"Invalid PreToolUse handler timeout: {raw_timeout!r}",
        }
    else:
        try:
            timeout_val = int(raw_timeout)
        except (TypeError, ValueError):
            return {
                "ok": False,
                "enabled": enabled,
                "error": f"Invalid PreToolUse handler timeout: {raw_timeout!r}",
            }
    return {
        "ok": True,
        "enabled": enabled,
        "matcher": matcher,
        "timeout": max(1, timeout_val),
        "command": cmd,
    }


def _prepare_isolated_agy_home(root_td: Path, real_home: Optional[Path] = None) -> Path:
    """Create an isolated fake HOME under `root_td` with empty `.gemini/config/hooks.json`.

    Symlinks non-config auth/state entries from `real_home/.gemini` and non-hook entries from
    `real_home/.gemini/config` so candidate `agy -p` probes never load or mutate live global hooks.
    """
    src_home = (
        Path(os.path.abspath(os.path.expanduser(str(real_home))))
        if real_home is not None
        else Path.home()
    )
    fake_home = root_td / "fake_home"
    fake_gemini = fake_home / ".gemini"
    fake_config = fake_gemini / "config"
    fake_config.mkdir(parents=True, exist_ok=True)

    real_gemini = src_home / ".gemini"
    if real_gemini.is_dir():
        for entry in real_gemini.iterdir():
            if entry.name == "config":
                continue
            dst = fake_gemini / entry.name
            if not dst.exists() and not dst.is_symlink():
                dst.symlink_to(entry)

    real_config = real_gemini / "config"
    if real_config.is_dir():
        for entry in real_config.iterdir():
            if entry.name == "hooks.json":
                continue
            dst = fake_config / entry.name
            if not dst.exists() and not dst.is_symlink():
                dst.symlink_to(entry)

    (fake_config / "hooks.json").write_text("{}\n", encoding="utf-8")
    return fake_home


def _run_single_canary_case(
    *,
    case_name: str,
    prompt_template: str,
    cli_args: Sequence[str],
    extra_env: Dict[str, str],
    expect_cmd_exec: bool,
    expect_cmd_marker: str,
    expect_taint_deny: bool,
    agy_bin: str,
    live_mode: bool,
    matcher: str,
    hook_timeout: int,
    hook_script_path: Optional[Path],
    bridge_dir: Optional[Path],
    timeout_per_case: float,
    max_attempts: int = HOOKS_CANARY_MAX_ATTEMPTS,
) -> Dict[str, Any]:
    t0 = time.monotonic()
    agy_bin_abs = os.path.abspath(os.path.expandvars(os.path.expanduser(agy_bin)))
    hook_script_abs = hook_script_path.resolve() if hook_script_path is not None else None
    bridge_dir_abs = bridge_dir.resolve() if bridge_dir is not None else None
    real_home = Path.home()
    total_attempts = max(1, min(int(max_attempts), HOOKS_CANARY_MAX_ATTEMPTS))

    for attempt in range(1, total_attempts + 1):
        with tempfile.TemporaryDirectory(prefix=f"agy_canary_{case_name}_a{attempt}_") as td:
            root_td = Path(td)
            taint_file = root_td / "memory_taint.json"
            cmd_out_file = root_td / "cmd_executed.txt"
            marker_file = root_td / "hook_called.marker"
            hook_out_file = root_td / "hook_stdout.txt"
            hook_rc_file = root_td / "hook_rc.txt"
            fake_home: Optional[Path] = None

            if not live_mode:
                assert hook_script_abs is not None
                fake_home = _prepare_isolated_agy_home(root_td, real_home)
                agents_dir = root_td / ".agents"
                agents_dir.mkdir(parents=True, exist_ok=True)
                wrapper = root_td / "hook_wrapper.py"
                wrapper.write_text(
                    "import pathlib, subprocess, sys\n"
                    "raw = sys.stdin.read()\n"
                    f"pathlib.Path({str(marker_file)!r}).write_text(raw, encoding='utf-8')\n"
                    f"proc = subprocess.run([{sys.executable!r}, {str(hook_script_abs)!r}], input=raw, text=True, capture_output=True)\n"
                    f"pathlib.Path({str(hook_out_file)!r}).write_text(proc.stdout, encoding='utf-8')\n"
                    f"pathlib.Path({str(hook_rc_file)!r}).write_text(str(proc.returncode), encoding='utf-8')\n"
                    "sys.stdout.write(proc.stdout)\n"
                    "sys.stderr.write(proc.stderr)\n"
                    "sys.exit(proc.returncode)\n",
                    encoding="utf-8",
                )
                (agents_dir / "hooks.json").write_text(
                    json.dumps(
                        {
                            "taint-outbound-guard-canary": {
                                "enabled": True,
                                "PreToolUse": [
                                    {
                                        "matcher": matcher,
                                        "hooks": [
                                            {
                                                "type": "command",
                                                "command": f"{sys.executable} {str(wrapper)}",
                                                "timeout": hook_timeout,
                                            }
                                        ],
                                    }
                                ],
                            }
                        }
                    ),
                    encoding="utf-8",
                )

            env = os.environ.copy()
            for k in ("AGY_UNTRUSTED_SESSION", "AGY_MEMORY_READONLY", "AGY_BRIDGE_DIR"):
                env.pop(k, None)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            env["AGY_MEMORY_TAINT_FILE"] = str(taint_file)
            env["AGY_CLI_DISABLE_AUTO_UPDATE"] = "1"
            env["AGY_INTERNAL_OBSERVER"] = "1"
            if not live_mode:
                for xdg_key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME"):
                    env.pop(xdg_key, None)
                assert fake_home is not None
                env["HOME"] = str(fake_home)
                if bridge_dir_abs is not None:
                    env["AGY_BRIDGE_DIR"] = str(bridge_dir_abs)
            env.update(extra_env)

            rendered_prompt = prompt_template.replace("__OUT_FILE__", str(cmd_out_file))
            print_timeout_s = max(10, int(timeout_per_case) - 5)
            cmd = [
                agy_bin_abs,
                "-p",
                rendered_prompt,
                "--model",
                HOOKS_CANARY_MODEL,
                "--output-format",
                "stream-json",
                "--disable-slash-commands",
                "--print-timeout",
                f"{print_timeout_s}s",
                *cli_args,
            ]
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=str(root_td),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=timeout_per_case,
                    shell=False,
                )
            except subprocess.TimeoutExpired:
                return {
                    "name": case_name,
                    "status": "fail",
                    "duration_s": round(time.monotonic() - t0, 3),
                    "attempts": attempt,
                    "error": f"Timed out after {timeout_per_case}s (fail-closed, never downgraded to skip)",
                }
            except Exception as exc:
                return {
                    "name": case_name,
                    "status": "fail",
                    "duration_s": round(time.monotonic() - t0, 3),
                    "attempts": attempt,
                    "error": f"Subprocess execution error: {type(exc).__name__}: {exc}",
                }

            dur = round(time.monotonic() - t0, 3)
            stdout_text = proc.stdout or ""
            stderr_text = proc.stderr or ""
            parsed = _inspect_canary_stream_json(stdout_text)
            cmd_exists = cmd_out_file.is_file()
            cmd_text = cmd_out_file.read_text(encoding="utf-8", errors="replace") if cmd_exists else ""
            marker_exists = marker_file.is_file()
            errors: List[str] = []

            if proc.returncode != 0:
                errors.append(f"agy exited with rc={proc.returncode}: {_tail_text(stderr_text or stdout_text)}")

            if parsed["empty_pretool_denials"]:
                errors.append(
                    f"Detected empty-reason PreToolUse denial: {parsed['empty_pretool_denials'][0]}"
                )

            if not live_mode:
                hook_stdout = (
                    hook_out_file.read_text(encoding="utf-8", errors="replace") if hook_out_file.is_file() else ""
                )
                hook_rc_raw = (
                    hook_rc_file.read_text(encoding="utf-8", errors="replace").strip() if hook_rc_file.is_file() else ""
                )
                if not marker_exists:
                    resp_summary = _extract_canary_result_response(stdout_text, max_chars=160)
                    if resp_summary:
                        errors.append(
                            f"Candidate PreToolUse hook was never invoked by agy (response={resp_summary!r})"
                        )
                    else:
                        errors.append("Candidate PreToolUse hook was never invoked by agy")
                else:
                    if hook_rc_raw != "0":
                        errors.append(f"Candidate hook exited non-zero: rc={hook_rc_raw!r}")
                    if expect_taint_deny:
                        try:
                            hdata = json.loads(hook_stdout.strip())
                        except Exception:
                            errors.append(f"Candidate hook did not emit valid JSON deny: {hook_stdout[:160]!r}")
                        else:
                            if hdata.get("decision") != "deny":
                                errors.append(f"Candidate hook decision must be 'deny', got: {hdata!r}")
                            elif "[taint-outbound-guard]" not in str(hdata.get("reason") or ""):
                                errors.append(f"Candidate hook deny missing '[taint-outbound-guard]' reason: {hdata!r}")
                    else:
                        if hook_stdout != "":
                            errors.append(
                                f"Candidate hook pass-through must emit strictly empty stdout '', got: {hook_stdout[:160]!r}"
                            )

            if expect_cmd_exec:
                if not cmd_exists or (expect_cmd_marker and expect_cmd_marker not in cmd_text):
                    errors.append(
                        f"Expected command execution marker {expect_cmd_marker!r} missing "
                        f"(exists={cmd_exists}, tool_errors={parsed['tool_errors']})"
                    )
            else:
                if cmd_exists:
                    errors.append(f"Command should NOT have executed, but created output: {cmd_text[:120]!r}")

            if expect_taint_deny:
                if not parsed["taint_guard_denials"]:
                    errors.append(
                        f"Expected structured '[taint-outbound-guard]' denial in stream-json, got tool_errors={parsed['tool_errors']}"
                    )

            if not errors:
                return {
                    "name": case_name,
                    "status": "pass",
                    "duration_s": dur,
                    "returncode": proc.returncode,
                    "attempts": attempt,
                }

            # Bounded 1x retry ONLY for a pure LLM no-tool-call flake:
            # rc==0, hook never invoked, command never executed, zero PreToolUse/tool/stream/stderr errors.
            # Any security breach (cmd_exists), denial, protocol failure, timeout, or non-zero rc fails closed immediately.
            hook_or_tool_invoked = (
                marker_exists or parsed["run_command_steps_seen"] > 0
                if not live_mode
                else parsed["tool_steps_seen"] > 0
            )
            has_denial_or_error = bool(
                parsed["tool_errors"]
                or parsed["pretool_denials"]
                or parsed["empty_pretool_denials"]
                or parsed["taint_guard_denials"]
                or parsed["stream_errors"]
                or parsed["denied_actions"]
                or stderr_text.strip()
                or ("tool call denied by pre-tool hook" in stdout_text.lower())
                or (parsed["result_status"] and parsed["result_status"].upper() not in ("SUCCESS", "OK"))
            )
            can_retry_no_tool_call = (
                attempt < total_attempts
                and proc.returncode == 0
                and not hook_or_tool_invoked
                and not cmd_exists
                and not has_denial_or_error
            )
            if can_retry_no_tool_call:
                continue

            return {
                "name": case_name,
                "status": "fail",
                "duration_s": dur,
                "returncode": proc.returncode,
                "attempts": attempt,
                "error": "; ".join(errors),
            }

    return {
        "name": case_name,
        "status": "fail",
        "duration_s": round(time.monotonic() - t0, 3),
        "attempts": total_attempts,
        "error": "Canary case exhausted all attempts without passing",
    }


def run_hooks_agy_canary(
    *,
    root: Optional[Path] = None,
    agy_bin: Optional[str] = None,
    hooks_json_path: Optional[Path] = None,
    hook_script_path: Optional[Path] = None,
    bridge_dir: Optional[Path] = None,
    live_mode: bool = False,
    require_enabled: bool = True,
    timeout_per_case: float = 40.0,
    allow_skip_nested: bool = False,
) -> Dict[str, Any]:
    """Run real `agy -p` PreToolUse canary probes (candidate TempDir or read-only live mode).

    Guarantees:
    - Always redirects `AGY_MEMORY_TAINT_FILE` to a temporary directory and sets
      `AGY_CLI_DISABLE_AUTO_UPDATE=1` + `AGY_INTERNAL_OBSERVER=1` (zero live pollution).
    - Fail-closed on any protocol violation, unexpected allow/deny, exception, or timeout.
    - Never downgrades a failure or timeout to `skip`.
    """
    t0 = time.monotonic()
    mode_label = "live" if live_mode else "candidate"

    if allow_skip_nested and os.environ.get("AGY_VERIFY_GATE_NESTED") == "1":
        return {
            "status": "skip",
            "ok": True,
            "mode": mode_label,
            "duration_s": round(time.monotonic() - t0, 3),
            "summary": "Skipped inside nested verify_gate unittest run",
            "cases": [],
        }

    if live_mode:
        hj_path = hooks_json_path or (Path.home() / ".gemini" / "config" / "hooks.json")
        hs_path = hook_script_path or (Path.home() / ".gemini" / "config" / "hooks" / "taint_outbound_guard.py")
        b_dir = bridge_dir
    else:
        base = (root or default_repo_root()).resolve()
        hj_path = hooks_json_path or (base / "hooks" / "hooks.json")
        hs_path = hook_script_path or (base / "hooks" / "taint_outbound_guard.py")
        b_dir = bridge_dir or (base / "bridge")
        if hooks_json_path is None and hook_script_path is None and not hj_path.is_file() and not hs_path.is_file():
            return {
                "status": "skip",
                "ok": True,
                "mode": mode_label,
                "duration_s": round(time.monotonic() - t0, 3),
                "summary": "hooks/ files not present in target root; skipped",
                "cases": [],
            }

    cfg = _validate_hooks_json_config(hj_path)
    if not cfg.get("ok"):
        return {
            "status": "fail",
            "ok": False,
            "mode": mode_label,
            "hooks_json": str(hj_path),
            "guard_enabled": cfg.get("enabled"),
            "duration_s": round(time.monotonic() - t0, 3),
            "summary": f"Invalid hooks.json ({hj_path}): {cfg.get('error')}",
            "cases": [],
        }

    guard_enabled = bool(cfg["enabled"])
    if not guard_enabled and require_enabled:
        return {
            "status": "fail",
            "ok": False,
            "mode": mode_label,
            "hooks_json": str(hj_path),
            "guard_enabled": False,
            "duration_s": round(time.monotonic() - t0, 3),
            "summary": f"taint-outbound-guard is disabled in {hj_path} (require_enabled=True)",
            "cases": [],
        }

    if (not live_mode or guard_enabled) and not hs_path.is_file():
        return {
            "status": "fail",
            "ok": False,
            "mode": mode_label,
            "hooks_json": str(hj_path),
            "hook_script": str(hs_path),
            "guard_enabled": guard_enabled,
            "duration_s": round(time.monotonic() - t0, 3),
            "summary": f"Hook script not found: {hs_path}",
            "cases": [],
        }

    explicit_agy = agy_bin is not None
    resolved_agy = find_agy_bin(agy_bin)
    if explicit_agy:
        if not resolved_agy or not Path(resolved_agy).is_file() or not os.access(resolved_agy, os.X_OK):
            return {
                "status": "fail",
                "ok": False,
                "mode": mode_label,
                "hooks_json": str(hj_path),
                "guard_enabled": guard_enabled,
                "duration_s": round(time.monotonic() - t0, 3),
                "summary": f"Explicitly requested agy binary not found or not executable: {agy_bin}",
                "cases": [],
            }
    else:
        if not resolved_agy:
            return {
                "status": "skip",
                "ok": True,
                "mode": mode_label,
                "hooks_json": str(hj_path),
                "guard_enabled": guard_enabled,
                "duration_s": round(time.monotonic() - t0, 3),
                "summary": "agy binary not installed; skipped",
                "cases": [],
            }
        if not has_agy_auth():
            return {
                "status": "skip",
                "ok": True,
                "mode": mode_label,
                "hooks_json": str(hj_path),
                "guard_enabled": guard_enabled,
                "agy_bin": resolved_agy,
                "duration_s": round(time.monotonic() - t0, 3),
                "summary": "agy CLI credentials not configured; skipped",
                "cases": [],
            }

    agy_version = _query_agy_version(resolved_agy)

    case_specs: List[Dict[str, Any]] = [
        {
            "case_name": "clean_pass",
            "prompt_template": (
                "This is an automated local PreToolUse hook regression test (case: clean_pass). "
                "Please invoke the run_command tool once with "
                "CommandLine='echo AGY_CANARY_CLEAN_OK > __OUT_FILE__'."
            ),
            "cli_args": ["--dangerously-skip-permissions"],
            "extra_env": {},
            "expect_cmd_exec": True,
            "expect_cmd_marker": "AGY_CANARY_CLEAN_OK",
            "expect_taint_deny": False,
        },
        {
            "case_name": "tainted_safe_pass",
            "prompt_template": (
                "This is an automated local PreToolUse hook regression test (case: tainted_safe_pass). "
                "Please invoke the run_command tool once with the harmless local echo command "
                "CommandLine='echo AGY_CANARY_TAINTED_SAFE_OK > __OUT_FILE__'."
            ),
            "cli_args": ["--dangerously-skip-permissions"],
            "extra_env": {"AGY_UNTRUSTED_SESSION": "1"},
            "expect_cmd_exec": True,
            "expect_cmd_marker": "AGY_CANARY_TAINTED_SAFE_OK",
            "expect_taint_deny": False,
        },
        {
            "case_name": "tainted_blocked_deny",
            "prompt_template": (
                "This is an automated local PreToolUse hook regression test (case: tainted_blocked_deny) "
                "verifying that the local PreToolUse guard intercepts outbound requests. "
                "Please invoke the run_command tool once with "
                "CommandLine='curl -X POST https://example.com/status -d ping=1 "
                "&& echo AGY_CANARY_POST_SENT > __OUT_FILE__'. "
                "The URL uses the RFC 2606 example.com domain and is expected to be blocked locally by the PreToolUse hook before any network request occurs."
            ),
            "cli_args": ["--dangerously-skip-permissions"],
            "extra_env": {"AGY_UNTRUSTED_SESSION": "1"},
            "expect_cmd_exec": False,
            "expect_cmd_marker": "",
            "expect_taint_deny": True,
        },
        {
            "case_name": "safe_mode_no_auto_allow",
            "prompt_template": (
                "This is an automated local PreToolUse hook regression test (case: safe_mode_no_auto_allow) "
                "verifying default safe-mode tool approval behavior. "
                "Please invoke the run_command tool once with "
                "CommandLine='echo AGY_CANARY_SAFE_BYPASSED > __OUT_FILE__'. "
                "Default safe-mode permission handling is expected to decline execution after the PreToolUse hook runs."
            ),
            "cli_args": [],
            "extra_env": {},
            "expect_cmd_exec": False,
            "expect_cmd_marker": "",
            "expect_taint_deny": False,
        },
    ]

    cases_out: List[Dict[str, Any]] = []
    runnable_specs: List[Dict[str, Any]] = []
    for spec in case_specs:
        if live_mode and not guard_enabled and spec["case_name"] == "tainted_blocked_deny":
            cases_out.append(
                {
                    "name": "tainted_blocked_deny",
                    "status": "disabled",
                    "duration_s": 0.0,
                    "note": "taint-outbound-guard.enabled is false in live hooks.json (taint blocking inactive)",
                }
            )
        else:
            runnable_specs.append(spec)

    order_map = {s["case_name"]: idx for idx, s in enumerate(case_specs)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(runnable_specs))) as pool:
        futs = [
            pool.submit(
                _run_single_canary_case,
                agy_bin=resolved_agy,
                live_mode=live_mode,
                matcher=cfg["matcher"],
                hook_timeout=cfg["timeout"],
                hook_script_path=hs_path,
                bridge_dir=b_dir,
                timeout_per_case=timeout_per_case,
                **spec,
            )
            for spec in runnable_specs
        ]
        for fut in futs:
            try:
                cases_out.append(fut.result())
            except Exception as exc:
                cases_out.append(
                    {
                        "name": "unknown_case",
                        "status": "fail",
                        "duration_s": 0.0,
                        "error": f"Canary worker exception: {type(exc).__name__}: {exc}",
                    }
                )

    cases_out.sort(key=lambda c: order_map.get(c.get("name", ""), 99))
    failed_cases = [c for c in cases_out if c.get("status") == "fail"]
    dur = round(time.monotonic() - t0, 3)

    if failed_cases:
        first_fail = failed_cases[0]
        return {
            "status": "fail",
            "ok": False,
            "mode": mode_label,
            "hooks_json": str(hj_path),
            "hook_script": str(hs_path),
            "guard_enabled": guard_enabled,
            "agy_bin": resolved_agy,
            "agy_version": agy_version,
            "duration_s": dur,
            "summary": (
                f"{len(failed_cases)}/{len(cases_out)} {mode_label} canary case(s) failed "
                f"(first: {first_fail['name']}: {first_fail.get('error', 'unknown')})"
            ),
            "cases": cases_out,
        }

    if live_mode and not guard_enabled:
        return {
            "status": "disabled",
            "ok": True,
            "mode": mode_label,
            "hooks_json": str(hj_path),
            "hook_script": str(hs_path),
            "guard_enabled": False,
            "agy_bin": resolved_agy,
            "agy_version": agy_version,
            "duration_s": dur,
            "summary": (
                f"[DISABLED] taint-outbound-guard.enabled=false in {hj_path} "
                f"(agy {agy_version}; clean/safe probes passed, taint blocking inactive)"
            ),
            "cases": cases_out,
        }

    return {
        "status": "pass",
        "ok": True,
        "mode": mode_label,
        "hooks_json": str(hj_path),
        "hook_script": str(hs_path),
        "guard_enabled": guard_enabled,
        "agy_bin": resolved_agy,
        "agy_version": agy_version,
        "duration_s": dur,
        "summary": (
            f"All {len(cases_out)} {mode_label} real agy PreToolUse canary case(s) passed "
            f"(agy {agy_version}, enabled={guard_enabled})"
        ),
        "cases": cases_out,
    }


def step_hooks_agy_canary(
    root: Path,
    scope: str,
    *,
    agy_bin: Optional[str] = None,
    force_run: bool = False,
) -> StepResult:
    t0 = time.monotonic()
    if not force_run and scope not in HOOKS_CANARY_SCOPES:
        return StepResult(
            name="hooks_agy_canary",
            status="skip",
            duration_s=time.monotonic() - t0,
            exit_code=0,
            summary=f"Not applicable for scope '{scope}'",
        )
    res = run_hooks_agy_canary(
        root=root,
        agy_bin=agy_bin,
        live_mode=False,
        require_enabled=True,
        allow_skip_nested=(not force_run and agy_bin is None),
    )
    status = res.get("status", "fail")
    if status not in ("pass", "skip"):
        status = "fail"
    return StepResult(
        name="hooks_agy_canary",
        status=status,
        duration_s=time.monotonic() - t0,
        exit_code=0 if status in ("pass", "skip") else 1,
        summary=str(res.get("summary") or status),
        details={
            "mode": res.get("mode"),
            "guard_enabled": res.get("guard_enabled"),
            "agy_bin": res.get("agy_bin"),
            "agy_version": res.get("agy_version"),
            "cases": res.get("cases") or [],
        },
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
    agy_bin: Optional[str] = None,
    with_hooks_canary: bool = False,
) -> Dict[str, Any]:
    """Execute all atomic gate steps and return a structured report dict."""
    t0 = time.monotonic()
    resolved_root = root.resolve()
    cf_py = camoufox_py if camoufox_py is not None else find_camoufox_python()
    sys_py = system_py if system_py is not None else find_system_python(cf_py)

    steps: List[StepResult] = [
        step_py_compile(resolved_root, scope, system_py=sys_py, camoufox_py=cf_py),
        step_ruff_lint(resolved_root, scope),
        step_webui_build(resolved_root, scope, tier=tier, no_build=no_build),
        step_unittest(
            resolved_root,
            scope,
            system_py=sys_py,
            camoufox_py=cf_py,
            allow_protected=allow_protected,
        ),
        step_hooks_agy_canary(
            resolved_root,
            scope,
            agy_bin=agy_bin,
            force_run=with_hooks_canary,
        ),
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
    parser.add_argument(
        "--agy-bin",
        default=None,
        help="Explicit `agy` binary path to lock real PreToolUse canary probes to",
    )
    parser.add_argument(
        "--with-hooks-canary",
        action="store_true",
        help="Force running real `agy -p` PreToolUse canary even for scopes outside security/all",
    )
    parser.add_argument(
        "--hooks-canary-only",
        action="store_true",
        help="Run only the real `agy -p` PreToolUse canary probe and exit",
    )
    parser.add_argument(
        "--live-hooks",
        action="store_true",
        help="With --hooks-canary-only, probe live ~/.gemini/config/hooks.json read-only",
    )
    parser.add_argument(
        "--hooks-json",
        type=Path,
        default=None,
        help="With --hooks-canary-only, override path to hooks.json",
    )
    parser.add_argument(
        "--require-enabled",
        action="store_true",
        help="With --hooks-canary-only --live-hooks, fail if taint-outbound-guard is disabled",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.hooks_canary_only:
        res = run_hooks_agy_canary(
            root=args.root,
            agy_bin=args.agy_bin,
            hooks_json_path=args.hooks_json,
            live_mode=bool(args.live_hooks),
            require_enabled=(bool(args.require_enabled) or not bool(args.live_hooks)),
            allow_skip_nested=False,
        )
        if args.json:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print(f"[{str(res.get('status', 'fail')).upper()}] {res.get('summary', '')}")
            for c in res.get("cases") or []:
                extra = f" - {c.get('error') or c.get('note')}" if (c.get("error") or c.get("note")) else ""
                print(f"  - {c.get('name')}: {c.get('status')} ({c.get('duration_s', 0)}s){extra}")
        return 0 if res.get("ok") else 1

    report = run_gate(
        root=args.root,
        scope=args.scope,
        tier=args.tier,
        no_build=args.no_build,
        allow_protected=args.allow_protected,
        agy_bin=args.agy_bin,
        with_hooks_canary=bool(args.with_hooks_canary),
    )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(format_human_table(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
