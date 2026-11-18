#!/usr/bin/env python3
"""Setup & Environment Diagnostics CLI (`agy-bot setup` / `agy-bot doctor`).

Zero-side-effect module: does NOT import `bridge.bridge` or create runtime directories
on import, keeping `python3 bridge/bridge.py` standalone execution 100% compatible.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

BRIDGE_PKG_DIR = Path(__file__).resolve().parent
RUNTIME_BRIDGE_FILES: Tuple[str, ...] = (
    "bridge.py",
    "formatting.py",
    "access_control.py",
    "model_failover.py",
    "cost_usage.py",
    "scheduler.py",
    "bot_bus.py",
    "bot_bus_mcp.py",
    "github_webhook.py",
)

_PLACEHOLDER_MARKERS: Tuple[str, ...] = (
    "REPLACE_WITH",
    "YOUR_",
    "YOUR-",
    "EXAMPLE",
    "PLACEHOLDER",
    "DUMMY",
    "MOCK_",
    "CHANGEME",
    "CHANGE_ME",
    "INSERT_",
    "<RETRIEVE",
    "REDACTED",
)

_BOT_TOKEN_RE = re.compile(r"^\d{6,15}:[A-Za-z0-9_-]{20,}$")

_FALLBACK_ENV_TEMPLATE = """# Antigravity CLI Telegram Bridge v3 Configuration
# Copy to $HOME/agy-tg-bridge/.env (chmod 0600) — NEVER commit real tokens.

AGY_TG_BOT_TOKEN=1234567890:REPLACE_WITH_TELEGRAM_BOT_TOKEN
AGY_TG_ALLOWED_CHATS=123456789
AGY_TG_WORKDIR=$HOME/agy-workspace
AGY_TG_AGY_BIN=$HOME/.local/bin/agy
AGY_TG_STATE_FILE=$HOME/.agy-tg-bridge-state.json
AGY_TG_RELOAD_FILE=/tmp/agy_bridge_reload
AGY_TG_PRINT_TIMEOUT=30m
AGY_TG_IDLE_TTL=2700
AGY_TG_AUTO_COMPACT_TOKENS=180000
"""


@dataclasses.dataclass(frozen=True)
class CheckResult:
    """Single diagnostic check outcome for `agy-bot doctor`."""

    name: str
    status: str  # "PASS" | "WARN" | "FAIL"
    message: str
    hint: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "hint": self.hint,
        }


def _expand_path(raw: str) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(raw.strip()))
    return Path(expanded)


def _parse_env_file(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        values[k.strip()] = v.strip().strip("'\"")
    return values


def _resolve_env_file(explicit_env_file: Optional[Path]) -> Path:
    if explicit_env_file is not None:
        return _expand_path(str(explicit_env_file))
    from_env = os.environ.get("AGY_TG_ENV_FILE", "").strip()
    if from_env:
        return _expand_path(from_env)
    candidates = (
        Path.home() / "agy-tg-bridge" / ".env",
        Path.cwd() / ".env",
        BRIDGE_PKG_DIR / ".env",
    )
    for cand in candidates:
        if cand.is_file():
            return cand
    return candidates[0]


def _is_placeholder_value(val: str) -> bool:
    s = (val or "").strip()
    if not s:
        return True
    upper = s.upper()
    if any(marker in upper for marker in _PLACEHOLDER_MARKERS):
        return True
    if s.startswith(("1234567890:REPLACE", "123456789:EXAMPLE", "000000000:")):
        return True
    return False


def _dir_writable_readonly(target_dir: Path) -> Tuple[bool, Path, str]:
    """Check whether `target_dir` (or its nearest existing ancestor) is writable without mutating disk."""
    probe = target_dir
    while not probe.exists():
        parent = probe.parent
        if parent == probe:
            return False, probe, "filesystem root unreachable"
        probe = parent
    if not probe.is_dir():
        return False, probe, f"expected directory, found non-directory: {probe}"
    if not os.access(probe, os.W_OK | os.X_OK):
        return False, probe, f"missing write/execute permission on {probe}"
    return True, probe, "writable"


def _check_python_version() -> CheckResult:
    ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 11):
        return CheckResult("python_version", "PASS", f"Python {ver} (>= 3.11)")
    return CheckResult(
        "python_version",
        "FAIL",
        f"Python {ver} is older than required >= 3.11",
        "Upgrade to Python 3.11+ before running agy-bot.",
    )


def _check_dependencies() -> CheckResult:
    required = ("requests", "fcntl", "sqlite3", "zoneinfo")
    missing: List[str] = []
    for mod in required:
        try:
            importlib.import_module(mod)
        except Exception:
            missing.append(mod)
    if missing:
        return CheckResult(
            "dependencies",
            "FAIL",
            f"Missing required Python module(s): {', '.join(missing)}",
            "Install dependencies via: pip install -r bridge/requirements.txt (or pip install .)",
        )
    return CheckResult("dependencies", "PASS", "Required modules importable (requests, fcntl, sqlite3, zoneinfo)")


def _check_agy_cli(cfg: Dict[str, str]) -> CheckResult:
    raw_bin = (cfg.get("AGY_TG_AGY_BIN") or os.environ.get("AGY_TG_AGY_BIN") or "").strip()
    if raw_bin:
        candidate = _expand_path(raw_bin)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return CheckResult("agy_cli", "PASS", f"Found configured AGY_TG_AGY_BIN: {candidate}")
    found_path = shutil.which("agy")
    if found_path:
        return CheckResult("agy_cli", "PASS", f"Found `agy` CLI in $PATH: {found_path}")
    if not raw_bin:
        standard_paths = (
            Path.home() / ".local" / "bin" / "agy",
            Path.home() / "bin" / "agy",
            Path("/usr/local/bin/agy"),
            Path("/usr/bin/agy"),
        )
        for std_bin in standard_paths:
            if std_bin.is_file() and os.access(std_bin, os.X_OK):
                return CheckResult("agy_cli", "PASS", f"Found `agy` CLI at standard path: {std_bin}")
    if raw_bin:
        return CheckResult(
            "agy_cli",
            "WARN",
            f"Configured AGY_TG_AGY_BIN not executable ({raw_bin}) and `agy` not in $PATH",
            "Install Google Antigravity CLI (`agy`) or set AGY_TG_AGY_BIN to a valid binary path.",
        )
    return CheckResult(
        "agy_cli",
        "WARN",
        "`agy` CLI not found in $PATH and AGY_TG_AGY_BIN not configured",
        "Install Google Antigravity CLI (`agy`) or set AGY_TG_AGY_BIN in your .env file.",
    )


def _check_env_file(env_path: Path, fix: bool = False) -> Tuple[CheckResult, Dict[str, str]]:
    if not env_path.is_file():
        return (
            CheckResult(
                "env_file",
                "FAIL",
                f"Environment file not found: {env_path}",
                "Run `agy-bot setup` or pass `--env-file /path/to/.env`.",
            ),
            {},
        )
    try:
        cfg = _parse_env_file(env_path)
    except OSError as exc:
        return (
            CheckResult(
                "env_file",
                "FAIL",
                f"Cannot read environment file {env_path}: {exc}",
                "Check file ownership and read permissions.",
            ),
            {},
        )
    mode = stat.S_IMODE(env_path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        if fix:
            try:
                os.chmod(env_path, 0o600)
                new_mode = stat.S_IMODE(env_path.stat().st_mode)
                if not (new_mode & (stat.S_IRWXG | stat.S_IRWXO)):
                    return (
                        CheckResult(
                            "env_file",
                            "PASS",
                            f"Readable .env at {env_path} (auto-fixed permission -> 0o600, was {oct(mode)})",
                        ),
                        cfg,
                    )
                mode = new_mode
            except OSError as exc:
                return (
                    CheckResult(
                        "env_file",
                        "WARN",
                        f"Found {env_path} with permissions {oct(mode)}, auto-fix chmod 0o600 failed: {exc}",
                        f"Restrict permissions with: chmod 600 {env_path}",
                    ),
                    cfg,
                )
        return (
            CheckResult(
                "env_file",
                "WARN",
                f"Found {env_path}, but permissions {oct(mode)} are group/world accessible",
                f"Restrict permissions with: chmod 600 {env_path}",
            ),
            cfg,
        )
    return CheckResult("env_file", "PASS", f"Readable .env at {env_path} (mode {oct(mode)})"), cfg


def _check_bot_token(cfg: Dict[str, str], env_present: bool) -> Tuple[CheckResult, str]:
    token = (cfg.get("AGY_TG_BOT_TOKEN") or os.environ.get("AGY_TG_BOT_TOKEN") or "").strip()
    if not token:
        return (
            CheckResult(
                "bot_token",
                "FAIL",
                "AGY_TG_BOT_TOKEN is empty or missing",
                "Set AGY_TG_BOT_TOKEN from Telegram BotFather in your .env file.",
            ),
            "",
        )
    if _is_placeholder_value(token):
        return (
            CheckResult(
                "bot_token",
                "FAIL",
                "AGY_TG_BOT_TOKEN is still a placeholder value",
                "Replace AGY_TG_BOT_TOKEN with a real Telegram bot token from Telegram BotFather.",
            ),
            "",
        )
    if not _BOT_TOKEN_RE.match(token):
        return (
            CheckResult(
                "bot_token",
                "FAIL",
                f"AGY_TG_BOT_TOKEN format looks invalid (len={len(token)})",
                "Expected BotFather format `<digits>:<secret>`.",
            ),
            "",
        )
    src = "env-file" if env_present and cfg.get("AGY_TG_BOT_TOKEN") else "environment"
    return CheckResult("bot_token", "PASS", f"AGY_TG_BOT_TOKEN configured via {src} (len={len(token)})"), token


def _check_allowed_chats(cfg: Dict[str, str]) -> CheckResult:
    raw = (cfg.get("AGY_TG_ALLOWED_CHATS") or os.environ.get("AGY_TG_ALLOWED_CHATS") or "").strip()
    if not raw:
        return CheckResult(
            "allowed_chats",
            "FAIL",
            "AGY_TG_ALLOWED_CHATS is empty (fail-closed auth would reject all chats)",
            "Set AGY_TG_ALLOWED_CHATS to one or more comma-separated Telegram chat/user IDs.",
        )
    items = [part.strip() for part in raw.split(",") if part.strip()]
    if not items:
        return CheckResult(
            "allowed_chats",
            "FAIL",
            "AGY_TG_ALLOWED_CHATS contains no valid entries",
            "Provide comma-separated integer Telegram chat IDs.",
        )
    parsed: List[int] = []
    for item in items:
        try:
            parsed.append(int(item))
        except ValueError:
            return CheckResult(
                "allowed_chats",
                "FAIL",
                f"AGY_TG_ALLOWED_CHATS contains non-integer value: {item!r}",
                "Use numeric Telegram chat/user IDs (e.g. -1001234567890 or 123456789).",
            )
    if parsed == [123456789]:
        return CheckResult(
            "allowed_chats",
            "WARN",
            "AGY_TG_ALLOWED_CHATS is still set to template example ID `123456789`",
            "Update AGY_TG_ALLOWED_CHATS with your real Telegram user or group chat ID.",
        )
    return CheckResult("allowed_chats", "PASS", f"AGY_TG_ALLOWED_CHATS configured ({len(parsed)} chat ID(s))")


def _check_dir_permissions(cfg: Dict[str, str], fix: bool = False) -> CheckResult:
    raw_workdir = (cfg.get("AGY_TG_WORKDIR") or os.environ.get("AGY_TG_WORKDIR") or "$HOME/agy-workspace").strip()
    raw_state = (
        cfg.get("AGY_TG_STATE_FILE") or os.environ.get("AGY_TG_STATE_FILE") or "$HOME/.agy-tg-bridge-state.json"
    ).strip()
    raw_lock = (cfg.get("AGY_TG_LOCK_DIR") or os.environ.get("AGY_TG_LOCK_DIR") or tempfile.gettempdir()).strip()

    targets = (
        ("workdir", _expand_path(raw_workdir)),
        ("state_dir", _expand_path(raw_state).parent),
        ("lock_dir", _expand_path(raw_lock)),
    )
    failures: List[str] = []
    checked: List[str] = []
    created: List[str] = []
    for label, path in targets:
        ok, _probe, reason = _dir_writable_readonly(path)
        if ok and fix and not path.exists():
            try:
                path.mkdir(parents=True, exist_ok=True)
                ok, _probe, reason = _dir_writable_readonly(path)
                if ok:
                    created.append(f"{label}={path}")
            except OSError as exc:
                ok = False
                reason = f"auto-create failed: {exc}"
        if not ok:
            failures.append(f"{label}={path} ({reason})")
        else:
            checked.append(f"{label}={path}")
    if failures:
        return CheckResult(
            "dir_permissions",
            "FAIL",
            f"Directory permission check failed: {'; '.join(failures)}",
            "Ensure target directories (or their parent directories) exist and are writable.",
        )
    if created:
        return CheckResult(
            "dir_permissions",
            "PASS",
            f"Writable runtime paths verified ({', '.join(checked)}; auto-created {', '.join(created)})",
        )
    return CheckResult("dir_permissions", "PASS", f"Writable runtime paths verified ({', '.join(checked)})")


def _check_telegram_online(
    token: str,
    http_get: Optional[Callable[..., Any]] = None,
) -> CheckResult:
    if not token:
        return CheckResult(
            "telegram_online",
            "FAIL",
            "Skipped Telegram getMe check because AGY_TG_BOT_TOKEN is missing or invalid",
            "Configure a valid AGY_TG_BOT_TOKEN first.",
        )
    try:
        getter = http_get
        if getter is None:
            import requests

            getter = requests.get
        resp = getter(f"https://api.telegram.org/bot{token}/getMe", timeout=8)
        status_code = getattr(resp, "status_code", 0)
        payload = resp.json() if hasattr(resp, "json") else {}
        if status_code == 200 and isinstance(payload, dict) and payload.get("ok"):
            bot_info = payload.get("result") or {}
            username = bot_info.get("username") or "unknown"
            bot_id = bot_info.get("id") or "?"
            return CheckResult(
                "telegram_online",
                "PASS",
                f"Telegram getMe succeeded: @{username} (id={bot_id})",
            )
        desc = payload.get("description") if isinstance(payload, dict) else ""
        return CheckResult(
            "telegram_online",
            "FAIL",
            f"Telegram getMe failed (HTTP {status_code}{': ' + desc if desc else ''})",
            "Verify AGY_TG_BOT_TOKEN and outbound HTTPS connectivity to api.telegram.org.",
        )
    except Exception as exc:
        # Never embed URL (which contains token) in error message
        return CheckResult(
            "telegram_online",
            "FAIL",
            f"Telegram getMe request error: {type(exc).__name__}",
            "Verify network connectivity to api.telegram.org.",
        )


def run_doctor(
    *,
    env_file: Optional[Path] = None,
    online: bool = False,
    fix: bool = False,
    http_get: Optional[Callable[..., Any]] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Run all diagnostic checks and return `(exit_code, report_dict)`."""
    resolved_env = _resolve_env_file(env_file)
    checks: List[CheckResult] = [
        _check_python_version(),
        _check_dependencies(),
    ]
    env_res, cfg = _check_env_file(resolved_env, fix=fix)
    checks.append(env_res)
    checks.append(_check_agy_cli(cfg))
    tok_res, valid_token = _check_bot_token(cfg, env_present=resolved_env.is_file())
    checks.append(tok_res)
    checks.append(_check_allowed_chats(cfg))
    checks.append(_check_dir_permissions(cfg, fix=fix))
    if online:
        checks.append(_check_telegram_online(valid_token, http_get=http_get))

    pass_cnt = sum(1 for c in checks if c.status == "PASS")
    warn_cnt = sum(1 for c in checks if c.status == "WARN")
    fail_cnt = sum(1 for c in checks if c.status == "FAIL")
    overall = "fail" if fail_cnt > 0 else ("warn" if warn_cnt > 0 else "ok")
    report: Dict[str, Any] = {
        "status": overall,
        "env_file": str(resolved_env),
        "online_checked": bool(online),
        "fix_mode": bool(fix),
        "summary": {
            "pass": pass_cnt,
            "warn": warn_cnt,
            "fail": fail_cnt,
            "total": len(checks),
        },
        "checks": [c.to_dict() for c in checks],
    }
    return (1 if fail_cnt > 0 else 0), report


def _render_doctor_text(report: Dict[str, Any]) -> str:
    lines = [
        f"agy-bot doctor (env: {report['env_file']}, online: {'yes' if report['online_checked'] else 'no'})",
        "-" * 60,
    ]
    for chk in report["checks"]:
        lines.append(f"[{chk['status']}] {chk['name']}: {chk['message']}")
        if chk["hint"] and chk["status"] != "PASS":
            lines.append(f"       hint: {chk['hint']}")
    s = report["summary"]
    lines.append("-" * 60)
    lines.append(f"Summary: {s['pass']} PASS, {s['warn']} WARN, {s['fail']} FAIL (overall={report['status']})")
    return "\n".join(lines)


def _load_env_template() -> str:
    tmpl_path = BRIDGE_PKG_DIR / ".env.example"
    if tmpl_path.is_file():
        return tmpl_path.read_text(encoding="utf-8")
    return _FALLBACK_ENV_TEMPLATE


def _render_env_content(
    template: str,
    *,
    bot_token: Optional[str] = None,
    allowed_chats: Optional[str] = None,
    workdir: Optional[str] = None,
    extra_overrides: Optional[Dict[str, str]] = None,
) -> str:
    overrides: Dict[str, str] = {}
    if bot_token is not None and bot_token.strip():
        overrides["AGY_TG_BOT_TOKEN"] = bot_token.strip()
    if allowed_chats is not None and allowed_chats.strip():
        overrides["AGY_TG_ALLOWED_CHATS"] = allowed_chats.strip()
    if workdir is not None and workdir.strip():
        overrides["AGY_TG_WORKDIR"] = workdir.strip()
    if extra_overrides:
        for k, v in extra_overrides.items():
            if v is not None and str(v).strip():
                overrides[k] = str(v).strip()

    if not overrides:
        return template

    lines = template.splitlines()
    seen: set[str] = set()
    out_lines: List[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in overrides:
                out_lines.append(f"{key}={overrides[key]}")
                seen.add(key)
                continue
        out_lines.append(line)
    for key, val in overrides.items():
        if key not in seen:
            out_lines.append(f"{key}={val}")
    return "\n".join(out_lines) + "\n"


_BOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
_VALID_BOT_ROLES = ("coordinator", "worker", "peer")


def _parse_bot_team_spec(
    *,
    bots: Optional[str],
    team: bool,
    roles: Optional[str],
) -> Tuple[bool, List[Tuple[str, str]], Optional[str]]:
    """Parse `--bots` / `--team` / `--roles` into `(is_team, [(name, role), ...], err)`."""
    raw_bots = (bots or "").strip()
    is_team = bool(raw_bots or team)
    if not is_team:
        if roles and roles.strip():
            role_val = roles.strip().lower()
            if role_val not in _VALID_BOT_ROLES:
                return False, [], f"Invalid role {role_val!r}; expected one of {', '.join(_VALID_BOT_ROLES)}"
            return False, [("main", role_val)], None
        return False, [("main", "")], None

    names = [part.strip() for part in raw_bots.split(",") if part.strip()] if raw_bots else ["main", "dev", "qa"]
    if not names:
        return True, [], "Bot list in --bots must not be empty"

    seen_names: set[str] = set()
    for n in names:
        if not _BOT_NAME_RE.match(n):
            return True, [], f"Invalid bot name {n!r}; use 1-32 chars of [A-Za-z0-9_-]"
        low = n.lower()
        if low in seen_names:
            return True, [], f"Duplicate bot name {n!r} in --bots"
        seen_names.add(low)

    parsed_roles: List[str] = []
    if roles and roles.strip():
        parsed_roles = [r.strip().lower() for r in roles.split(",") if r.strip()]
        for r in parsed_roles:
            if r not in _VALID_BOT_ROLES:
                return True, [], f"Invalid role {r!r}; expected one of {', '.join(_VALID_BOT_ROLES)}"
        if len(parsed_roles) not in (1, len(names)):
            return True, [], f"--roles count ({len(parsed_roles)}) must be 1 or match --bots count ({len(names)})"

    specs: List[Tuple[str, str]] = []
    for idx, n in enumerate(names):
        if parsed_roles:
            role_val = parsed_roles[0] if len(parsed_roles) == 1 else parsed_roles[idx]
        else:
            role_val = "coordinator" if idx == 0 else "worker"
        specs.append((n, role_val))
    return True, specs, None


def _render_systemd_unit(
    *,
    unit_desc: str,
    dest_dir: Path,
    env_path: Path,
    python_bin: Path,
) -> str:
    bridge_script = dest_dir / "bridge.py"
    return (
        "[Unit]\n"
        f"Description=Antigravity CLI Telegram Bridge ({unit_desc})\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"Environment=AGY_TG_ENV_FILE={env_path}\n"
        f"EnvironmentFile={env_path}\n"
        f"WorkingDirectory={dest_dir}\n"
        f"ExecStart={python_bin} {bridge_script}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "KillMode=mixed\n"
        "TimeoutStopSec=90\n"
        "NoNewPrivileges=true\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def _copy_if_needed(src: Path, dst: Path) -> str:
    if src.resolve() == dst.resolve():
        return "skipped_same"
    existed = dst.is_file()
    shutil.copy2(src, dst)
    if src.stat().st_mode & stat.S_IXUSR:
        dst.chmod(dst.stat().st_mode | stat.S_IXUSR)
    return "updated" if existed else "copied"


def run_setup(
    *,
    target_dir: Optional[Path] = None,
    non_interactive: bool = False,
    force: bool = False,
    check_only: bool = False,
    bot_token: Optional[str] = None,
    allowed_chats: Optional[str] = None,
    workdir: Optional[str] = None,
    bots: Optional[str] = None,
    team: bool = False,
    roles: Optional[str] = None,
    fallback_models: Optional[str] = None,
    bus_dir: Optional[str] = None,
    systemd_out: Optional[Path] = None,
    input_fn: Callable[[str], str] = input,
) -> Tuple[int, Dict[str, Any]]:
    """Bootstrap runtime directory with `bridge/*.py`, single/multi-bot `.env*`, and optional systemd units."""
    dest_dir = _expand_path(str(target_dir)) if target_dir is not None else (Path.home() / "agy-tg-bridge")

    is_team, bot_specs, spec_err = _parse_bot_team_spec(bots=bots, team=team, roles=roles)
    if spec_err:
        return 1, {
            "status": "error",
            "target_dir": str(dest_dir),
            "error": spec_err,
        }

    missing_sources = [name for name in RUNTIME_BRIDGE_FILES if not (BRIDGE_PKG_DIR / name).is_file()]
    if missing_sources:
        return 1, {
            "status": "error",
            "target_dir": str(dest_dir),
            "error": f"Missing source bridge file(s) in {BRIDGE_PKG_DIR}: {', '.join(missing_sources)}",
        }

    primary_is_default_env = (not is_team) or (bot_specs[0][0].lower() == "main")
    primary_env_name = ".env" if primary_is_default_env else f".env.{bot_specs[0][0]}"
    primary_env_path = dest_dir / primary_env_name
    primary_env_exists = primary_env_path.is_file()
    will_write_primary = (not primary_env_exists) or force

    if will_write_primary and not non_interactive and not check_only and sys.stdin.isatty():
        if not bot_token:
            entered = input_fn("Telegram BOT_TOKEN (leave blank to keep placeholder): ").strip()
            if entered:
                bot_token = entered
        if not allowed_chats:
            entered = input_fn("Allowed Telegram chat IDs (comma-separated, blank for placeholder): ").strip()
            if entered:
                allowed_chats = entered
        if not workdir:
            entered = input_fn("Workspace directory [default: $HOME/agy-workspace]: ").strip()
            if entered:
                workdir = entered

    resolved_bus_dir = (bus_dir or "").strip() or (
        "$HOME/.gemini/antigravity-cli/bot-bus" if is_team else ""
    )
    resolved_fb = (fallback_models or "").strip()
    systemd_dir = _expand_path(str(systemd_out)) if systemd_out is not None else None
    python_bin = dest_dir / "venv" / "bin" / "python"

    # Build per-bot target plan
    bot_plan: List[Dict[str, Any]] = []
    for idx, (bname, brole) in enumerate(bot_specs):
        use_root_env = (idx == 0 and primary_is_default_env)
        env_filename = ".env" if use_root_env else f".env.{bname}"
        epath = dest_dir / env_filename
        unit_name = "agy-tg-bridge.service" if use_root_env else f"agy-tg-bridge-{bname}.service"
        upath = (systemd_dir / unit_name) if systemd_dir is not None else None

        overrides: Dict[str, str] = {}
        if is_team or brole:
            overrides["AGY_TG_BOT_ROLE"] = brole or "coordinator"
            overrides["AGY_TG_BOT_HANDLE"] = f"@{bname}_bot"
        if is_team:
            overrides["AGY_TG_STATE_FILE"] = (
                "$HOME/.agy-tg-bridge-state.json"
                if use_root_env
                else f"$HOME/.agy-tg-bridge-{bname}-state.json"
            )
            overrides["AGY_TG_RELOAD_FILE"] = (
                "/tmp/agy_bridge_reload" if use_root_env else f"/tmp/agy_bridge_{bname}_reload"
            )
        if resolved_bus_dir:
            overrides["AGY_BOT_BUS_DIR"] = resolved_bus_dir
        if resolved_fb:
            overrides["AGY_TG_FALLBACK_MODELS"] = resolved_fb

        tok_for_bot = (
            bot_token
            if idx == 0
            else f"1234567890:REPLACE_WITH_{bname.upper()}_BOT_TOKEN"
        )
        bot_plan.append(
            {
                "name": bname,
                "role": brole or "standalone",
                "env_path": epath,
                "unit_path": upath,
                "token": tok_for_bot,
                "overrides": overrides,
            }
        )

    file_actions: Dict[str, str] = {}
    if check_only:
        for fname in RUNTIME_BRIDGE_FILES:
            dst = dest_dir / fname
            file_actions[fname] = "would_update" if dst.exists() else "would_copy"

        env_actions: Dict[str, str] = {}
        for item in bot_plan:
            ep = item["env_path"]
            existed = ep.is_file()
            env_actions[str(ep)] = (
                "would_overwrite" if (existed and force) else ("would_preserve" if existed else "would_create")
            )

        systemd_actions: Dict[str, str] = {}
        for item in bot_plan:
            up = item["unit_path"]
            if up is not None:
                existed = up.is_file()
                systemd_actions[str(up)] = (
                    "would_overwrite" if (existed and force) else ("would_preserve" if existed else "would_create")
                )

        res_payload: Dict[str, Any] = {
            "status": "check_only",
            "target_dir": str(dest_dir),
            "env_file": str(primary_env_path),
            "env_action": env_actions[str(primary_env_path)],
            "env_files": env_actions,
            "files": file_actions,
            "team_mode": is_team,
        }
        if systemd_actions:
            res_payload["systemd_files"] = systemd_actions
        return 0, res_payload

    dest_dir.mkdir(parents=True, exist_ok=True)
    for fname in RUNTIME_BRIDGE_FILES:
        file_actions[fname] = _copy_if_needed(BRIDGE_PKG_DIR / fname, dest_dir / fname)

    template = _load_env_template()
    env_actions = {}
    for item in bot_plan:
        ep: Path = item["env_path"]
        existed = ep.is_file()
        if (not existed) or force:
            content = _render_env_content(
                template,
                bot_token=item["token"],
                allowed_chats=allowed_chats,
                workdir=workdir,
                extra_overrides=item["overrides"],
            )
            ep.write_text(content, encoding="utf-8")
            os.chmod(ep, 0o600)
            env_actions[str(ep)] = "overwritten" if existed else "created"
        else:
            env_actions[str(ep)] = "preserved"
            try:
                if stat.S_IMODE(ep.stat().st_mode) & (stat.S_IRWXG | stat.S_IRWXO):
                    os.chmod(ep, 0o600)
            except OSError:
                pass

    systemd_actions = {}
    if systemd_dir is not None:
        systemd_dir.mkdir(parents=True, exist_ok=True)
        for item in bot_plan:
            up: Optional[Path] = item["unit_path"]
            if up is None:
                continue
            existed = up.is_file()
            if (not existed) or force:
                desc = f"{item['name']} · {item['role']}" if is_team else item["name"]
                unit_txt = _render_systemd_unit(
                    unit_desc=desc,
                    dest_dir=dest_dir,
                    env_path=item["env_path"],
                    python_bin=python_bin,
                )
                up.write_text(unit_txt, encoding="utf-8")
                systemd_actions[str(up)] = "overwritten" if existed else "created"
            else:
                systemd_actions[str(up)] = "preserved"

    res_out: Dict[str, Any] = {
        "status": "ok",
        "target_dir": str(dest_dir),
        "env_file": str(primary_env_path),
        "env_action": env_actions[str(primary_env_path)],
        "env_files": env_actions,
        "files": file_actions,
        "team_mode": is_team,
    }
    if systemd_actions:
        res_out["systemd_files"] = systemd_actions
    return 0, res_out


def _render_setup_text(result: Dict[str, Any]) -> str:
    if result.get("status") == "error":
        return f"[FAIL] setup error: {result.get('error')}"
    prefix = "[CHECK-ONLY] " if result.get("status") == "check_only" else "[OK] "
    lines = [
        f"{prefix}agy-bot setup -> {result['target_dir']}",
    ]
    env_files = result.get("env_files") or {result["env_file"]: result["env_action"]}
    for epath, act in env_files.items():
        lines.append(f"  .env ({epath}): {act}")
    for upath, act in (result.get("systemd_files") or {}).items():
        lines.append(f"  systemd ({upath}): {act}")
    for fname, act in result["files"].items():
        lines.append(f"  {fname}: {act}")
    if result.get("status") == "ok":
        lines.append(f"\nNext: agy-bot doctor --env-file {result['env_file']}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agy-bot",
        description="Setup and environment diagnostics CLI for agy-bot Telegram bridge",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    doc_p = sub.add_parser("doctor", help="Run read-only environment & configuration health checks")
    doc_p.add_argument("--env-file", type=Path, default=None, help="Path to .env configuration file")
    doc_p.add_argument("--json", action="store_true", help="Print diagnostic report as JSON")
    doc_p.add_argument(
        "--online",
        action="store_true",
        help="Also verify Telegram BOT_TOKEN connectivity via getMe (disabled by default)",
    )
    doc_p.add_argument(
        "--fix",
        action="store_true",
        help="Auto-fix safe local issues (tighten .env permissions to 0600, create missing writable dirs)",
    )

    set_p = sub.add_parser("setup", help="Initialize runtime bridge directory and .env template")
    set_p.add_argument(
        "--target-dir",
        type=Path,
        default=None,
        help="Target bridge runtime directory (default: $HOME/agy-tg-bridge)",
    )
    set_p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Do not prompt on stdin; use flags or template defaults",
    )
    set_p.add_argument("--force", action="store_true", help="Overwrite an existing .env file")
    set_p.add_argument("--check-only", action="store_true", help="Preview setup actions without writing files")
    set_p.add_argument("--bot-token", default=None, help="Optional AGY_TG_BOT_TOKEN value")
    set_p.add_argument("--allowed-chats", default=None, help="Optional AGY_TG_ALLOWED_CHATS value")
    set_p.add_argument("--workdir", default=None, help="Optional AGY_TG_WORKDIR value")
    set_p.add_argument(
        "--bots",
        default=None,
        help="Comma-separated bot names for multi-bot team setup (e.g. main,dev,qa)",
    )
    set_p.add_argument(
        "--team",
        action="store_true",
        help="Enable multi-bot team setup (defaults to main,dev,qa if --bots omitted)",
    )
    set_p.add_argument(
        "--roles",
        default=None,
        help="Comma-separated roles matching --bots (coordinator,worker,peer)",
    )
    set_p.add_argument(
        "--fallback-models",
        default=None,
        help="Optional AGY_TG_FALLBACK_MODELS value (comma-separated model slugs)",
    )
    set_p.add_argument(
        "--bus-dir",
        default=None,
        help="Optional shared AGY_BOT_BUS_DIR path for multi-bot team coordination",
    )
    set_p.add_argument(
        "--systemd-out",
        type=Path,
        default=None,
        help="Optional directory to render systemd .service unit file(s)",
    )
    return parser


def _normalize_cli_argv(argv: Sequence[str]) -> list[str]:
    """Bind negative Telegram chat IDs (e.g. ``-100...``) to ``--allowed-chats=`` for Python <3.14 argparse."""
    items = list(argv)
    out: list[str] = []
    i = 0
    while i < len(items):
        tok = items[i]
        if tok == "--allowed-chats" and i + 1 < len(items) and items[i + 1].startswith("-"):
            out.append(f"{tok}={items[i + 1]}")
            i += 2
            continue
        out.append(tok)
        i += 1
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    raw_argv = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(_normalize_cli_argv(raw_argv))
    if args.command == "doctor":
        rc, report = run_doctor(env_file=args.env_file, online=args.online, fix=args.fix)
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print(_render_doctor_text(report))
        return rc
    if args.command == "setup":
        rc, res = run_setup(
            target_dir=args.target_dir,
            non_interactive=args.non_interactive,
            force=args.force,
            check_only=args.check_only,
            bot_token=args.bot_token,
            allowed_chats=args.allowed_chats,
            workdir=args.workdir,
            bots=args.bots,
            team=args.team,
            roles=args.roles,
            fallback_models=args.fallback_models,
            bus_dir=args.bus_dir,
            systemd_out=args.systemd_out,
        )
        print(_render_setup_text(res), file=sys.stderr if rc != 0 else sys.stdout)
        return rc
    return 2


if __name__ == "__main__":
    sys.exit(main())
