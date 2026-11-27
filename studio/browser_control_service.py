#!/usr/bin/env python3
"""AGY Studio — Dual-Engine Browser Control, Profile Isolation & Unrestricted AI Binding Service.

Provides:
- Unified dual-engine abstraction across:
  1. `camoufox` (`live-browser` Hub HTTP internal API)
  2. `external_chromium` (pluggable external Chromium wrapper via `AGY_BROWSER_EXTERNAL_CLI`
     & `AGY_BROWSER_EXTERNAL_LABEL`, degrading cleanly to `available: false` when unconfigured)
- Strict Profile & Google Isolation Guards (BM2):
  - Primary pinned profile (`default` / `pinned=True`) is immutable, direct-only, non-deletable
  - Active/running profile cannot be modified or deleted (`409`)
  - Secondary dedicated Google profile (`allow_google=True`) modifications require strict boolean
    `confirm_google_profile_change: true` and never allow mutating security boundary keys
  - Zero plaintext proxy credentials (`user:pass@` rejected on profile APIs; Vault ref required)
- Unrestricted Full Bot Roster Selection & Atomic Hot-Rebind (BM5):
  - `GET /api/browser/bots` exposes ALL configured bots without hardcoded exclusions
  - `POST /api/browser/owner-bot` presets (idle) or atomically hot-rebinds (running/takeover)
    without restarting the browser
- Manual Launch & Managed `--watch` Process-Group Lifecycle (BM4, BM6, BM7):
  - Launches `camoufox` (`manual_launch=True`) or `external_chromium` (`live --watch`, never
    `--wait-human`) in an isolated process group (`start_new_session=True`), waits for Hub
    attachment, binds `owner_bot`, and enters human takeover (`manual_launch`) to wake the AI
  - `POST /api/browser/takeover` supports optional sanitized `instruction`/`handback_note`
  - `close_all()` reaps all managed process groups on `app.on_cleanup` (0 orphan/zombie procs)
- Four-layer Studio write gate + `0600` anti-symlink JSONL audit log on every write route (BM1).
"""

from __future__ import annotations

import asyncio
from collections import deque
import datetime
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import signal
import time
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web

from .auth import StudioAuthManager, studio_auth_error
from .browser_proxy import HTTP_SESSION_KEY
from .chat_service import (
    MAX_PROMPT_BODY_BYTES,
    _extract_media_type,
    _read_bounded_json_body,
)
from .control_plane import _find_forbidden_key_recursive
from .data_sources import StudioDataSources, _sanitize_slug
from .egress_pool_service import (
    StudioEgressPoolService,
    _is_forbidden_agy_binary,
    _scrub_egress_text,
    _validate_host,
    _validate_port,
    is_forbidden_proxy_target,
)

log = logging.getLogger("agy-studio.browser_control")

DEFAULT_EXTERNAL_LABEL = "External Chromium"

_VALID_ENGINES = frozenset({"camoufox", "external_chromium"})
_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_BOT_FLAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$")
_TZ_RE = re.compile(r"^[A-Za-z0-9_/+.-]{1,64}$")
_LANG_RE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}$")
_WINDOW_RE = re.compile(r"^[1-9][0-9]{2,3}[xX,][1-9][0-9]{2,3}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_HANDBACK_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HANDBACK_TAG_BREAK_RE = re.compile(
    r"<\s*/?\s*(?:untrusted_webpage_content|system|assistant|user|developer|tool_call|tool_response)\b[^>]*>",
    re.IGNORECASE,
)
_HANDBACK_ACB_MARKER_RE = re.compile(r"\[\s*/?\s*ACB_[A-Z0-9_]+[^\]]*\]", re.IGNORECASE)
_ALLOWED_PROXY_SCHEMES = frozenset({"socks5", "socks5h", "http", "https"})

_DEDICATED_GOOGLE_BOUNDARY_KEYS = frozenset(
    {
        "user_data_dir",
        "persistent",
        "persistent_context",
        "ephemeral",
        "pinned",
        "allow_google",
        "account",
        "headless",
    }
)
_FORBIDDEN_WRITE_KEYS = frozenset(
    {
        "role",
        "user_id",
        "cmd",
        "command",
        "shell",
        "script",
        "cli",
        "cli_path",
        "password",
        "passwd",
        "secret",
        "token",
    }
)
_ALLOWED_PROFILE_WRITE_KEYS = frozenset(
    {
        "engine",
        "name",
        "overwrite",
        "confirm_google_profile_change",
        "os",
        "locale",
        "lang",
        "tz",
        "window",
        "mobile",
        "webgl_config",
        "block_webrtc",
        "geoip",
        "persistent",
        "ephemeral",
        "allow_google",
        "account",
        "proxy",
        "proxy_bao_ref",
        "egress_ref",
        "egress_node",
        "pinned",
        "user_data_dir",
        "persistent_context",
        "headless",
    }
)
_ALLOWED_DELETE_KEYS = frozenset({"purge_data"})
_ALLOWED_OWNER_BOT_KEYS = frozenset({"owner_bot", "expected_session_gen"})
_ALLOWED_LAUNCH_KEYS = frozenset(
    {
        "engine",
        "profile",
        "url",
        "owner_bot",
        "manual_launch",
        "restart",
        "allow_override",
        "confirm_google_profile_change",
        "notify",
        "proxy",
        "proxy_bao_ref",
        "egress_ref",
        "egress_node",
        "os",
        "locale",
        "window",
        "mobile",
    }
)
_ALLOWED_STOP_KEYS = frozenset({"force", "expected_session_gen"})
_ALLOWED_TAKEOVER_KEYS = frozenset(
    {
        "active",
        "reason",
        "instruction",
        "handback_note",
        "expected_session_gen",
        "expected_takeover_gen",
    }
)

_MAX_HANDBACK_LEN = 2000
_HUB_HTTP_TIMEOUT_SEC = 12.0
_EXT_CLI_TIMEOUT_SEC = 25.0
_EXT_ATTACH_TIMEOUT_SEC = 30.0
_EXT_WATCH_STOP_GRACE_SEC = 6.0
_EXT_STDERR_MAX_LINES = 40


def _parse_external_status_output(status_text: str) -> dict[str, bool]:
    """Parse `external_chromium --profile <p> status` output for live view & CDP state."""
    live_active = False
    live_inactive = False
    container_running = False
    cdp_disabled = False
    for raw_line in (status_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("live view:"):
            val = low.split(":", 1)[1].strip()
            if val == "inactive" or val.startswith(("inactive ", "inactive(")):
                live_inactive = True
            elif val == "active" or val.startswith(("active ", "active(")):
                live_active = True
        elif low.startswith("container:"):
            val = low.split(":", 1)[1].strip()
            if "(running" in val or " running," in val or " running)" in val:
                container_running = True
            if "cdp=disabled" in val:
                cdp_disabled = True
    return {
        "live_active": live_active,
        "live_inactive": live_inactive,
        "container_running": container_running,
        "cdp_disabled": cdp_disabled,
    }


def _utc_iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _actor_label(sess: dict[str, Any] | None) -> str:
    if not sess:
        return "anonymous"
    uname = str(sess.get("username") or "").strip()
    if uname:
        return _sanitize_slug(uname, max_len=64) or "user"
    bot = _sanitize_slug(sess.get("bot") or "studio", max_len=32) or "studio"
    uid = int(sess.get("user_id") or 0)
    return f"{bot}:#{uid}"


def _ensure_secure_dir(path: Path) -> None:
    if path.is_symlink():
        raise PermissionError("Refusing symlink directory")
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


class _BrowserControlAuditLogger:
    """Anti-symlink `0600` append-only JSONL audit logger for browser control mutations."""

    def __init__(self, audit_path: Path) -> None:
        self.audit_path = Path(audit_path)

    def record(
        self,
        *,
        action: str,
        ok: bool,
        sess: dict[str, Any] | None = None,
        engine: str = "",
        profile: str = "",
        owner_bot: str = "",
        error: str = "",
    ) -> None:
        rec = {
            "ts": _utc_iso_now(),
            "actor": _actor_label(sess),
            "role": str((sess or {}).get("role") or "anonymous"),
            "action": str(action)[:64],
            "engine": _sanitize_slug(engine, max_len=32) if engine else "",
            "profile": _sanitize_slug(profile, max_len=64) if profile else "",
            "owner_bot": _sanitize_slug(owner_bot, max_len=64) if owner_bot else "",
            "ok": bool(ok),
            "error": _scrub_egress_text(error) if error else "",
        }
        line = (json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            _ensure_secure_dir(self.audit_path.parent)
            if self.audit_path.is_symlink():
                raise PermissionError("Refusing to append audit log to symlink")
            flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(self.audit_path), flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    os.write(fd, line)
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        except Exception as exc:
            log.warning("Browser control audit write failed: %s", type(exc).__name__)


def _validate_strict_bool(raw: Any, field: str) -> bool:
    if not isinstance(raw, bool):
        raise ValueError(f"字段 '{field}' 必须为严格布尔值（true/false）")
    return raw


def _parse_positive_bot_id(raw: Any) -> int | None:
    """Normalize a positive integer or ASCII digit string bot_id; reject bool/non-positive/malformed."""
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw > 0 else None
    if isinstance(raw, str):
        if not raw or any(ch.isspace() for ch in raw):
            return None
        if not raw.isascii() or not raw.isdigit():
            return None
        if len(raw) > 1 and raw.startswith("0"):
            return None
        val = int(raw)
        return val if val > 0 else None
    return None


def _validate_profile_name(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ValueError("Profile 名称必须为字符串")
    name = raw.strip()
    if not name or ".." in name or not _PROFILE_NAME_RE.fullmatch(name):
        raise ValueError("Profile 名称非法，仅允许字母数字开头及 . _ -（1-64 字符）")
    return name


def _validate_engine(raw: Any, *, default: str = "camoufox") -> str:
    if raw is None or raw == "":
        return default
    if not isinstance(raw, str):
        raise ValueError("engine 必须为字符串")
    val = raw.strip().lower()
    if val not in _VALID_ENGINES:
        raise ValueError(f"不支持的浏览器引擎 {val!r}，仅允许: camoufox, external_chromium")
    return val


def _validate_credential_free_proxy(raw: Any) -> str | None:
    """Validate optional bare proxy URL, strictly rejecting embedded `user:pass@` credentials and SSRF targets."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, dict):
        if raw.get("username") or raw.get("password"):
            raise ValueError("禁止在 Profile 配置中直接传入含账密的代理，请先通过出口池安全存入 OpenBao 再引用")
        raw_s = str(raw.get("server") or "").strip()
        if not raw_s:
            return None
        raw = raw_s
    if not isinstance(raw, str):
        raise ValueError("proxy 必须为字符串")
    s = raw.strip()
    if not s:
        return None
    if len(s) > 512 or _CTRL_RE.search(s) or any(ch.isspace() for ch in s):
        raise ValueError("proxy URL 包含非法字符")
    if "://" not in s:
        raise ValueError("proxy URL 必须包含协议头（如 socks5h://host:1080）")
    sp = urlsplit(s)
    if (sp.scheme or "").lower() not in _ALLOWED_PROXY_SCHEMES:
        raise ValueError("不支持的 proxy 协议")
    if sp.username is not None or sp.password is not None or "@" in (sp.netloc or ""):
        raise ValueError("禁止直接传入含 user:pass@ 的裸代理 URL，请先通过出口池安全存入 OpenBao 再引用")
    if sp.path not in ("", "/") or sp.query or sp.fragment:
        raise ValueError("proxy URL 不允许包含路径、查询参数或锚点")
    clean_host = _validate_host(sp.hostname or "")
    try:
        parsed_port = sp.port
    except ValueError as exc:
        raise ValueError("proxy 端口无效") from exc
    if parsed_port is None:
        raise ValueError("proxy URL 必须包含有效主机名与端口")
    clean_port = _validate_port(parsed_port)
    forb, forb_reason = is_forbidden_proxy_target(clean_host, clean_port)
    if forb:
        raise ValueError(forb_reason)
    host_fmt = f"[{clean_host}]" if ":" in clean_host else clean_host
    return f"{sp.scheme.lower()}://{host_fmt}:{clean_port}"


def _validate_window_spec(raw: Any) -> str:
    """Validate window dimension string (`WxH`) or strict non-bool 2-int sequence `[W, H]`."""
    if isinstance(raw, (list, tuple)):
        if len(raw) != 2:
            raise ValueError("window 数组必须包含恰好 2 个整数 [width, height]")
        w_raw, h_raw = raw[0], raw[1]
        if (
            isinstance(w_raw, bool)
            or isinstance(h_raw, bool)
            or not isinstance(w_raw, int)
            or not isinstance(h_raw, int)
        ):
            raise ValueError("window 数组元素必须为严格整数（不能为布尔值、字符串或空值）")
        win_val = f"{w_raw}x{h_raw}"
    elif isinstance(raw, str):
        win_val = raw.strip()
    else:
        raise ValueError("window 必须为 'WxH' 字符串或 [W, H] 整数数组")
    if not _WINDOW_RE.fullmatch(win_val):
        raise ValueError("window 格式非法，应为 WxH（如 1280x800）")
    return win_val


def _validate_vault_ref(raw: Any) -> str | None:
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise ValueError("proxy_bao_ref 必须为字符串")
    s = raw.strip()
    if not s:
        return None
    if len(s) > 160 or _CTRL_RE.search(s) or any(ch.isspace() for ch in s) or ".." in s or s.startswith(("-", "/")):
        raise ValueError("proxy_bao_ref 格式非法")
    if "://" in s or "@" in s:
        raise ValueError("proxy_bao_ref 不允许包含 URL 协议或账密")
    return s


def _validate_launch_url(raw: Any) -> str | None:
    if raw is None or raw == "":
        return None
    if not isinstance(raw, str):
        raise ValueError("url 必须为字符串")
    s = raw.strip()
    if not s:
        return None
    if len(s) > 2048 or _CTRL_RE.search(s) or any(ch.isspace() for ch in s):
        raise ValueError("url 包含非法空白或控制字符")
    if s.startswith("-"):
        raise ValueError("url 不能以 '-' 开头")
    if s.lower() == "about:blank":
        return s
    sp = urlsplit(s)
    if (sp.scheme or "").lower() not in ("http", "https"):
        raise ValueError("仅允许 http://、https:// 或 about:blank 地址")
    if not sp.hostname:
        raise ValueError("url 缺少有效主机名")
    return s


def _sanitize_handback_note(raw: Any, max_len: int = _MAX_HANDBACK_LEN) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise ValueError("交还附言必须为字符串")
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    text = _HANDBACK_CTRL_RE.sub("", text)
    text = _HANDBACK_TAG_BREAK_RE.sub("[tag-neutralized]", text)
    text = _HANDBACK_ACB_MARKER_RE.sub("[marker-neutralized]", text)
    text = re.sub(r"<\s*/\s*untrusted", "&lt;/untrusted", text, flags=re.IGNORECASE)
    text = text.strip()
    if len(text) > max_len:
        text = text[:max_len].rstrip()
    return text


def _sanitize_profile_item(engine: str, raw: dict[str, Any], *, active_engine: str, active_profile: str) -> dict[str, Any]:
    name = _sanitize_slug(raw.get("name") or "", max_len=64)
    is_pinned = bool(raw.get("pinned", False)) or (engine == "external_chromium" and name == "default")
    is_persistent = raw.get("persistent") is True if "persistent" in raw else True
    allow_google = bool(is_pinned or (raw.get("allow_google") is True and is_persistent))
    egress = _scrub_egress_text(raw.get("egress") or raw.get("egress_display") or "direct", max_len=128) or "direct"
    out: dict[str, Any] = {
        "engine": engine,
        "name": name,
        "pinned": is_pinned,
        "persistent": is_persistent,
        "allow_google": allow_google,
        "egress": egress,
        "proxy_bao_ref": raw.get("proxy_bao_ref") or raw.get("bao_ref") or None,
        "os": _sanitize_slug(raw.get("os") or "", max_len=32),
        "active": bool(active_profile and name == active_profile and (not active_engine or active_engine == engine)),
        "editable": not is_pinned,
        "deletable": not is_pinned,
    }
    for key in ("locale", "lang", "tz", "window", "mobile", "account", "source"):
        if key in raw and raw[key] is not None:
            val = raw[key]
            out[key] = _scrub_egress_text(val, max_len=128) if isinstance(val, str) else val
    return out


class StudioBrowserControlService:
    """Studio backend orchestrator & REST handlers for dual-engine browser control."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        data_sources: StudioDataSources,
        egress_pool: StudioEgressPoolService | None = None,
        *,
        audit_log_path: str | Path | None = None,
        external_cli_path: str | None = None,
        external_label: str | None = None,
        subprocess_exec: Callable[..., Awaitable[Any]] | None = None,
        external_attach_timeout: float = _EXT_ATTACH_TIMEOUT_SEC,
        external_attach_poll_interval: float = 0.2,
        external_watch_stop_grace: float = _EXT_WATCH_STOP_GRACE_SEC,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.egress_pool = egress_pool
        self._external_cli_override = external_cli_path
        self._external_label_override = external_label
        self._subprocess_exec = subprocess_exec or asyncio.create_subprocess_exec
        self._external_attach_timeout = float(external_attach_timeout)
        self._external_attach_poll_interval = max(0.02, float(external_attach_poll_interval))
        self._external_watch_stop_grace = max(0.01, float(external_watch_stop_grace))

        default_audit = Path(
            os.environ.get(
                "AGY_STUDIO_BROWSER_AUDIT_LOG",
                str(self.auth_mgr.config_dir / "browser_control_audit.jsonl"),
            )
        )
        self.audit = _BrowserControlAuditLogger(Path(audit_log_path) if audit_log_path is not None else default_audit)

        # Preferred/default owner bot for idle launches
        self._default_owner_bot: str | None = None
        self._default_owner_bot_id: int | None = None

        # Managed external_chromium `--watch` process group & transient CLI subprocesses
        self._ext_lock = asyncio.Lock()
        self._ext_watch_proc: Any | None = None
        self._ext_watch_meta: dict[str, Any] = {}
        self._ext_watch_stderr_buf: deque[str] = deque(maxlen=_EXT_STDERR_MAX_LINES)
        self._ext_watch_stderr_task: asyncio.Task[None] | None = None
        self._transient_procs: set[Any] = set()

        if self.egress_pool is not None:
            self.egress_pool.set_in_use_checker(self.is_egress_in_use)

    # ------------------------------------------------------------------ External CLI Discovery
    def _resolve_external_cli(self) -> str | None:
        raw = (
            self._external_cli_override
            if self._external_cli_override is not None
            else os.environ.get("AGY_BROWSER_EXTERNAL_CLI", "")
        ).strip()
        if not raw:
            return None
        cand = Path(raw).expanduser()
        if _is_forbidden_agy_binary(cand):
            return None
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
        return None

    def external_label(self) -> str:
        raw = (
            self._external_label_override
            if self._external_label_override is not None
            else os.environ.get("AGY_BROWSER_EXTERNAL_LABEL", "")
        ).strip()
        return _scrub_egress_text(raw, max_len=64) if raw else DEFAULT_EXTERNAL_LABEL

    def external_available(self) -> bool:
        return self._resolve_external_cli() is not None

    # ------------------------------------------------------------------ Process-Group Management
    @staticmethod
    async def _terminate_proc_group(proc: Any, *, grace_sec: float = _EXT_WATCH_STOP_GRACE_SEC) -> None:
        if proc is None or getattr(proc, "returncode", None) is not None:
            return
        # Send single-PID SIGTERM first (NEVER os.killpg(..., SIGTERM)) so child drivers
        # such as Playwright's internal Node driver stay alive while the wrapper/bridge
        # flushes /internal/sync/stop cleanly.
        try:
            proc.terminate()
        except ProcessLookupError:
            return
        except Exception:
            pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=grace_sec)
            return
        except Exception:
            pass
        pid = getattr(proc, "pid", None)
        if isinstance(pid, int) and pid > 0:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        else:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        except Exception:
            pass

    @staticmethod
    async def _drain_stream_lines(stream: Any, buf: deque[str]) -> None:
        """Continuously drain merged child stdout/stderr into a bounded ring buffer without blocking PIPE."""
        if stream is None:
            return
        read_fn = getattr(stream, "read", None)
        if not callable(read_fn):
            return
        pending = ""
        try:
            while True:
                chunk = await read_fn(4096)
                if not chunk:
                    break
                if isinstance(chunk, (bytes, bytearray)):
                    text = chunk.decode("utf-8", errors="ignore")
                else:
                    text = str(chunk)
                combined = pending + text
                if "\n" in combined or "\r" in combined:
                    parts = re.split(r"[\r\n]+", combined)
                    pending = parts.pop()
                    for part in parts:
                        line = part.strip()
                        if line:
                            buf.append(line[:512])
                else:
                    pending = combined[-1024:]
            tail = pending.strip()
            if tail:
                buf.append(tail[:512])
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    @staticmethod
    def _extract_json_error(lines: list[str]) -> str | None:
        """Extract non-empty string `error` field if merged watch output contains a JSON dict."""
        for line in reversed(lines):
            if line.startswith("{") and line.endswith("}"):
                try:
                    parsed = json.loads(line)
                except Exception:
                    parsed = None
                if isinstance(parsed, dict):
                    err_val = parsed.get("error")
                    if isinstance(err_val, str) and err_val.strip():
                        return err_val.strip()
        joined = "\n".join(lines)
        end = joined.rfind("}")
        end_attempts = 0
        while end != -1 and end_attempts < 4:
            end_attempts += 1
            pos = joined.rfind("{", 0, end)
            start_attempts = 0
            while pos != -1 and start_attempts < 16:
                start_attempts += 1
                try:
                    parsed = json.loads(joined[pos : end + 1])
                except Exception:
                    parsed = None
                if isinstance(parsed, dict):
                    err_val = parsed.get("error")
                    if isinstance(err_val, str) and err_val.strip():
                        return err_val.strip()
                pos = joined.rfind("{", 0, pos)
            end = joined.rfind("}", 0, end)
        return None

    @classmethod
    def _format_stderr_tail(cls, buf: deque[str], *, max_lines: int = 3, max_len: int = 240) -> str:
        lines = [line for line in list(buf) if line]
        if not lines:
            return ""
        json_err = cls._extract_json_error(lines)
        if json_err:
            scrubbed = _scrub_egress_text(json_err, max_len=max_len)
            if scrubbed:
                return scrubbed
        tail = lines[-max_lines:]
        return _scrub_egress_text(" | ".join(tail), max_len=max_len)

    def _is_external_watch_active(self, profile: str | None = None) -> bool:
        proc = self._ext_watch_proc
        if proc is None or getattr(proc, "returncode", None) is not None:
            return False
        if profile is None:
            return True
        return str(self._ext_watch_meta.get("profile") or "") == profile

    async def _stop_external_watch(
        self,
        *,
        stop_external_profile: bool = False,
        expected_proc: Any | None = None,
    ) -> bool:
        async with self._ext_lock:
            if expected_proc is not None and self._ext_watch_proc is not expected_proc:
                stale_proc = expected_proc
                proc = None
                meta: dict[str, Any] = {}
                stderr_task = None
            else:
                stale_proc = None
                proc = self._ext_watch_proc
                meta = dict(self._ext_watch_meta)
                stderr_task = self._ext_watch_stderr_task
                self._ext_watch_proc = None
                self._ext_watch_meta = {}
                self._ext_watch_stderr_task = None
                self._ext_watch_stderr_buf.clear()
        if stale_proc is not None:
            await self._terminate_proc_group(stale_proc, grace_sec=self._external_watch_stop_grace)
            return False
        if proc is not None:
            await self._terminate_proc_group(proc, grace_sec=self._external_watch_stop_grace)
        if stderr_task is not None:
            if not stderr_task.done():
                stderr_task.cancel()
            try:
                await asyncio.wait_for(stderr_task, timeout=1.0)
            except (asyncio.CancelledError, Exception):
                pass
        if proc is None:
            return False
        if stop_external_profile:
            prof = str(meta.get("profile") or "").strip()
            if prof and self.external_available():
                try:
                    await self._run_external_cli(["--profile", prof, "stop"], timeout_sec=10.0)
                except Exception as exc:
                    log.warning("Best-effort external chromium stop failed for %s: %s", prof, type(exc).__name__)
        return True

    async def close_all(self) -> None:
        """Terminate and reap managed `--watch` and transient external CLI process groups."""
        await self._stop_external_watch()
        for proc in list(self._transient_procs):
            await self._terminate_proc_group(proc)
        self._transient_procs.clear()

    async def _run_external_cli(self, args: list[str], *, timeout_sec: float = _EXT_CLI_TIMEOUT_SEC) -> tuple[int, str, str]:
        cli = self._resolve_external_cli()
        if not cli:
            raise RuntimeError("外部 Chromium 适配器未配置（AGY_BROWSER_EXTERNAL_CLI）")
        proc = await self._subprocess_exec(
            cli,
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        self._transient_procs.add(proc)
        try:
            out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            rc = int(proc.returncode if proc.returncode is not None else 0)
            return (
                rc,
                out_b.decode("utf-8", errors="ignore"),
                _scrub_egress_text(err_b.decode("utf-8", errors="ignore"), max_len=400),
            )
        except asyncio.TimeoutError:
            await self._terminate_proc_group(proc)
            raise TimeoutError(f"外部浏览器 CLI 超时（>{timeout_sec:.0f}s）")
        except asyncio.CancelledError:
            await self._terminate_proc_group(proc)
            raise
        finally:
            self._transient_procs.discard(proc)

    # ------------------------------------------------------------------ Hub Internal HTTP Helpers
    async def _hub_request(
        self,
        http_session: aiohttp.ClientSession,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        timeout_sec: float = _HUB_HTTP_TIMEOUT_SEC,
    ) -> tuple[int, dict[str, Any]]:
        token = self.data_sources.read_live_browser_token()
        if not token:
            return 503, {"ok": False, "source": "upstream", "error": "Live-Browser 本地令牌不可读或服务未初始化"}
        url = f"{self.data_sources.live_browser_url}{path}"
        headers = {"X-Live-Token": token}
        try:
            async with http_session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=aiohttp.ClientTimeout(total=timeout_sec),
            ) as resp:
                raw_txt = await resp.text()
                try:
                    data = json.loads(raw_txt) if raw_txt else {}
                except Exception:
                    data = {"ok": False, "error": _scrub_egress_text(raw_txt, max_len=200) or f"HTTP {resp.status}"}
                if not isinstance(data, dict):
                    data = {"ok": False, "error": f"HTTP {resp.status}"}
                return resp.status, data
        except Exception as exc:
            log.warning("Hub HTTP %s %s failed: %s", method, path, type(exc).__name__)
            return 502, {"ok": False, "source": "upstream", "error": "Live-Browser 服务暂不可达"}

    async def _fetch_hub_status(
        self,
        http_session: aiohttp.ClientSession,
        sess: dict[str, Any],
    ) -> dict[str, Any]:
        sc, data = await self._hub_request(
            http_session,
            "GET",
            "/internal/status",
            params={
                "source": "tg_cmd",
                "chat_scope": "private",
                "bot": str(sess["bot"]),
                "user_id": str(sess["user_id"]),
            },
            timeout_sec=3.5,
        )
        if sc >= 400 or not isinstance(data, dict):
            return {"reachable": False, "running": False, "engine_mode": "offline"}
        data["reachable"] = True
        return data

    async def is_egress_in_use(self, slug: str, ref: str) -> bool:
        """Check whether an egress node slug/ref is actively used by the current browser session."""
        if self._ext_watch_proc is not None and getattr(self._ext_watch_proc, "returncode", None) is None:
            meta_ref = str(self._ext_watch_meta.get("egress_ref") or "")
            if meta_ref and (meta_ref == ref or meta_ref.rsplit("/", 1)[-1] == slug):
                return True
        token = self.data_sources.read_live_browser_token()
        if not token:
            return False
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2.5)) as cli:
                async with cli.get(
                    f"{self.data_sources.live_browser_url}/internal/status",
                    headers={"X-Live-Token": token},
                ) as resp:
                    if resp.status != 200:
                        return False
                    st = await resp.json()
                    if not isinstance(st, dict) or not st.get("running"):
                        return False
                    active_prof = str(st.get("profile") or "")
                    for p in st.get("profiles") or []:
                        if isinstance(p, dict) and str(p.get("name") or "") == active_prof:
                            p_ref = str(p.get("proxy_bao_ref") or p.get("bao_ref") or "")
                            if p_ref and (p_ref == ref or p_ref.rsplit("/", 1)[-1] == slug):
                                return True
                    active_egress = str(st.get("egress") or "")
                    if active_egress and (ref in active_egress or slug in active_egress):
                        return True
        except Exception:
            return False
        return False

    # ------------------------------------------------------------------ Four-Layer Write Gate (BM1)
    async def _enforce_write_gate(
        self,
        request: web.Request,
        *,
        action: str,
        engine: str = "",
        profile: str = "",
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        ok_orig, err_orig = self.auth_mgr.check_same_origin(request, require_origin=True)
        if not ok_orig:
            self.audit.record(action=action, ok=False, engine=engine, profile=profile, error="denied_origin")
            return False, None, studio_auth_error(err_orig, status=403)

        sfs = (request.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sfs and sfs not in ("same-origin", "none"):
            self.audit.record(action=action, ok=False, engine=engine, profile=profile, error="denied_sec_fetch_site")
            return False, None, studio_auth_error("Sec-Fetch-Site 跨站写请求已拦截", status=403)

        if _extract_media_type(request) != "application/json":
            self.audit.record(action=action, ok=False, engine=engine, profile=profile, error="denied_content_type")
            return False, None, studio_auth_error("写接口仅接受 Content-Type: application/json", status=415)

        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            self.audit.record(action=action, ok=False, engine=engine, profile=profile, error=f"denied_auth:{status_code}")
            return False, None, studio_auth_error(err_auth, status=status_code)

        ok_csrf, err_csrf = self.auth_mgr.check_csrf(request, sess)
        if not ok_csrf:
            self.audit.record(action=action, ok=False, sess=sess, engine=engine, profile=profile, error="denied_csrf")
            return False, None, studio_auth_error(err_csrf, status=403)

        if sess.get("role") != "admin":
            self.audit.record(action=action, ok=False, sess=sess, engine=engine, profile=profile, error="denied_rbac")
            return False, None, studio_auth_error("只读权限（readonly）禁止执行写操作", status=403)

        return True, sess, None

    async def _parse_write_body(
        self,
        request: web.Request,
        *,
        sess: dict[str, Any],
        action: str,
        allowed_keys: frozenset[str],
        allow_empty: bool,
        engine: str = "",
        profile: str = "",
        extra_forbidden: frozenset[str] = frozenset(),
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request,
            max_bytes=MAX_PROMPT_BODY_BYTES,
            allow_empty=allow_empty,
        )
        if not ok_body or body is None:
            self.audit.record(action=action, ok=False, sess=sess, engine=engine, profile=profile, error=body_outcome)
            return False, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        forbidden_set = _FORBIDDEN_WRITE_KEYS | extra_forbidden if extra_forbidden else _FORBIDDEN_WRITE_KEYS
        bad_forb = _find_forbidden_key_recursive(body, forbidden_set)
        if bad_forb is not None:
            self.audit.record(
                action=action,
                ok=False,
                sess=sess,
                engine=engine,
                profile=profile,
                error=f"denied_forbidden_field:{bad_forb}",
            )
            return False, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止传入受限字段: {bad_forb}"},
                status=400,
            )

        unknown = set(body.keys()) - allowed_keys
        if unknown:
            self.audit.record(
                action=action,
                ok=False,
                sess=sess,
                engine=engine,
                profile=profile,
                error="denied_unknown_field",
            )
            return False, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": f"存在未允许的字段: {sorted(unknown)[0]}"},
                status=400,
            )

        return True, body, None

    # ------------------------------------------------------------------ Roster & Profile Helpers
    def _lookup_roster_bot(self, raw_handle: Any) -> dict[str, Any] | None:
        if not isinstance(raw_handle, str):
            return None
        target = raw_handle.strip().lstrip("@").lower()
        if not target:
            return None
        bots_data = self.data_sources.get_browser_bots()
        for item in bots_data.get("bots") or []:
            if str(item.get("handle") or "").strip().lower() == target:
                return item
        return None

    async def _list_external_profiles_raw(self) -> list[dict[str, Any]]:
        if not self.external_available():
            return []
        rc, out_txt, err_txt = await self._run_external_cli(["profile", "list", "--json"])
        if rc != 0:
            log.warning("External chromium profile list failed (rc=%d): %s", rc, err_txt)
            return []
        try:
            parsed = json.loads(out_txt)
        except Exception:
            return []
        if isinstance(parsed, dict) and isinstance(parsed.get("profiles"), list):
            return [p for p in parsed["profiles"] if isinstance(p, dict)]
        if isinstance(parsed, list):
            return [p for p in parsed if isinstance(p, dict)]
        return []

    async def _show_external_profile_raw(self, name: str) -> dict[str, Any] | None:
        if not self.external_available():
            return None
        rc, out_txt, _err_txt = await self._run_external_cli(["profile", "show", name, "--json"])
        if rc != 0:
            return None
        try:
            parsed = json.loads(out_txt)
        except Exception:
            return None
        if isinstance(parsed, dict):
            if isinstance(parsed.get("profile"), dict):
                return parsed["profile"]
            return parsed
        return None

    # ------------------------------------------------------------------ GET Endpoints
    async def handle_get_engines(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        hub_st = await self._fetch_hub_status(request.app[HTTP_SESSION_KEY], sess)
        restricted = bool(hub_st.get("session_restricted"))
        return web.json_response(
            {
                "ok": True,
                "can_edit": sess.get("role") == "admin",
                "engines": [
                    {
                        "id": "camoufox",
                        "label": "Camoufox",
                        "available": bool(hub_st.get("reachable")),
                    },
                    {
                        "id": "external_chromium",
                        "label": self.external_label(),
                        "available": self.external_available(),
                    },
                ],
                "active_session": {
                    "running": bool(hub_st.get("running")) and not restricted,
                    "engine_mode": _sanitize_slug(hub_st.get("engine_mode") or "idle", max_len=32),
                    "engine": "" if restricted else _sanitize_slug(hub_st.get("engine") or "", max_len=32),
                    "profile": None if restricted else (hub_st.get("profile") or None),
                    "egress": "" if restricted else _scrub_egress_text(hub_st.get("egress") or "direct", max_len=128),
                    "takeover": False if restricted else bool(hub_st.get("takeover")),
                    "manual_launch": False if restricted else bool(hub_st.get("manual_launch")),
                    "owner_bot": None if restricted else (hub_st.get("owner_bot") or self._default_owner_bot),
                    "owner_bot_id": None if restricted else (hub_st.get("owner_bot_id") or self._default_owner_bot_id),
                },
            }
        )

    async def handle_get_bots(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        roster_data = self.data_sources.get_browser_bots()
        hub_st = await self._fetch_hub_status(request.app[HTTP_SESSION_KEY], sess)
        restricted = bool(hub_st.get("session_restricted"))
        active_owner_bot = None if restricted else (hub_st.get("owner_bot") or None)
        active_owner_bot_id = None if restricted else (hub_st.get("owner_bot_id") or None)
        return web.json_response(
            {
                "ok": True,
                "can_edit": sess.get("role") == "admin",
                "total": roster_data["total"],
                "bots": roster_data["bots"],
                "active_owner_bot": active_owner_bot,
                "active_owner_bot_id": active_owner_bot_id,
                "default_owner_bot": self._default_owner_bot,
                "default_owner_bot_id": self._default_owner_bot_id,
            }
        )

    async def handle_list_profiles(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        if sess.get("role") != "admin":
            return web.json_response(
                {
                    "ok": True,
                    "can_edit": False,
                    "camoufox_available": False,
                    "external_chromium_available": self.external_available(),
                    "external_chromium_label": self.external_label(),
                    "profiles": [],
                    "by_engine": {"camoufox": [], "external_chromium": []},
                }
            )

        engine_filter = str(request.query.get("engine") or "all").strip().lower()
        if engine_filter not in ("all", "camoufox", "external_chromium"):
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "engine 参数仅允许 all、camoufox 或 external_chromium"},
                status=400,
            )

        http_session = request.app[HTTP_SESSION_KEY]
        hub_st = await self._fetch_hub_status(http_session, sess)
        active_profile = str(hub_st.get("profile") or "") if hub_st.get("running") else ""
        active_engine = str(hub_st.get("engine") or "") if hub_st.get("running") else ""

        cf_items: list[dict[str, Any]] = []
        cf_available = bool(hub_st.get("reachable"))
        if engine_filter in ("all", "camoufox") and cf_available:
            sc_p, p_data = await self._hub_request(
                http_session,
                "GET",
                "/internal/profiles",
                params={
                    "source": "tg_cmd",
                    "chat_scope": "private",
                    "bot": str(sess["bot"]),
                    "user_id": str(sess["user_id"]),
                },
            )
            if sc_p == 200 and isinstance(p_data.get("profiles"), list):
                for raw_p in p_data["profiles"]:
                    if isinstance(raw_p, dict):
                        cf_items.append(
                            _sanitize_profile_item(
                                "camoufox",
                                raw_p,
                                active_engine=active_engine,
                                active_profile=active_profile,
                            )
                        )

        ext_items: list[dict[str, Any]] = []
        ext_available = self.external_available()
        if engine_filter in ("all", "external_chromium") and ext_available:
            raw_ext = await self._list_external_profiles_raw()
            for raw_p in raw_ext:
                ext_items.append(
                    _sanitize_profile_item(
                        "external_chromium",
                        raw_p,
                        active_engine=active_engine,
                        active_profile=active_profile,
                    )
                )

        merged = [*cf_items, *ext_items]
        return web.json_response(
            {
                "ok": True,
                "can_edit": True,
                "camoufox_available": cf_available,
                "external_chromium_available": ext_available,
                "external_chromium_label": self.external_label(),
                "active_profile": active_profile or None,
                "active_engine": active_engine or None,
                "profiles": merged,
                "by_engine": {
                    "camoufox": cf_items,
                    "external_chromium": ext_items,
                },
            }
        )

    # ------------------------------------------------------------------ POST / PUT / DELETE Profiles (BM2)
    async def handle_upsert_profile(self, request: web.Request) -> web.Response:
        route_engine = request.match_info.get("engine")
        route_name = request.match_info.get("name")
        is_put = request.method == "PUT"

        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request,
            action="profile_update" if is_put else "profile_upsert",
            engine=str(route_engine or ""),
            profile=str(route_name or ""),
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="profile_update" if is_put else "profile_upsert",
            allowed_keys=_ALLOWED_PROFILE_WRITE_KEYS,
            allow_empty=False,
            engine=str(route_engine or ""),
            profile=str(route_name or ""),
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        try:
            engine = _validate_engine(route_engine if route_engine is not None else body.get("engine"))
            name = _validate_profile_name(route_name if route_name is not None else body.get("name"))
            overwrite = True if is_put else (
                _validate_strict_bool(body["overwrite"], "overwrite")
                if body.get("overwrite") is not None
                else False
            )
            confirm_google = (
                _validate_strict_bool(body["confirm_google_profile_change"], "confirm_google_profile_change")
                if "confirm_google_profile_change" in body and body["confirm_google_profile_change"] is not None
                else False
            )
            if "pinned" in body and body["pinned"] is not None:
                if _validate_strict_bool(body["pinned"], "pinned"):
                    raise ValueError("禁止设置 pinned=true；主 Profile 身份由宿主安全策略派生且不可修改")
            bare_proxy = _validate_credential_free_proxy(body.get("proxy"))
            raw_ref = (
                body.get("proxy_bao_ref")
                if body.get("proxy_bao_ref") is not None
                else (body.get("egress_ref") if body.get("egress_ref") is not None else body.get("egress_node"))
            )
            vault_ref = _validate_vault_ref(raw_ref)
            if bare_proxy and vault_ref:
                raise ValueError("不能同时指定 proxy 与 proxy_bao_ref/egress_ref")
            if body.get("window") is not None:
                _validate_window_spec(body["window"])
        except ValueError as exc:
            err_msg = _scrub_egress_text(exc)
            self.audit.record(action="profile_upsert", ok=False, sess=sess, error=err_msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": err_msg}, status=400)

        # Resolve Vault ref against egress pool when provided
        if vault_ref and self.egress_pool is not None and self.egress_pool.vault.is_ready():
            resolved_ref = await self.egress_pool.resolve_node_ref(vault_ref)
            if resolved_ref is None:
                self.audit.record(action="profile_upsert", ok=False, sess=sess, engine=engine, profile=name, error="egress_not_found")
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"出口节点 {vault_ref!r} 不存在或已作废"},
                    status=400,
                )
            vault_ref = resolved_ref[1]

        # Primary default/pinned profile hard guard
        if name == "default":
            self.audit.record(action="profile_upsert", ok=False, sess=sess, engine=engine, profile=name, error="pinned_immutable")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "主默认/Pinned Profile 不可修改、不可绑定代理或覆盖"},
                status=403,
            )

        http_session = request.app[HTTP_SESSION_KEY]
        hub_st = await self._fetch_hub_status(http_session, sess)
        active_profile = str(hub_st.get("profile") or "") if hub_st.get("running") else ""
        active_engine = str(hub_st.get("engine") or "") if hub_st.get("running") else ""

        is_running_hub = active_profile == name and (not active_engine or active_engine == engine)
        is_running_local_ext = engine == "external_chromium" and self._is_external_watch_active(name)
        if is_running_hub or is_running_local_ext:
            self.audit.record(action="profile_upsert", ok=False, sess=sess, engine=engine, profile=name, error="profile_running")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"Profile '{name}' 正在运行中，请先停止浏览器后再修改"},
                status=409,
            )

        if engine == "camoufox":
            return await self._upsert_camoufox_profile(
                http_session=http_session,
                sess=sess,
                name=name,
                body=body,
                overwrite=overwrite,
                confirm_google=confirm_google,
                bare_proxy=bare_proxy,
                vault_ref=vault_ref,
            )
        return await self._upsert_external_profile(
            sess=sess,
            name=name,
            body=body,
            overwrite=overwrite,
            confirm_google=confirm_google,
            bare_proxy=bare_proxy,
            vault_ref=vault_ref,
        )

    def _check_dedicated_google_boundary_keys(
        self,
        *,
        body: dict[str, Any],
        existing: dict[str, Any],
        sess: dict[str, Any],
        engine: str,
        name: str,
    ) -> web.Response | None:
        """Enforce immutable security boundary keys on existing dedicated Google profiles across both engines."""
        existing_acct = str(existing.get("account") or "").strip()
        for bkey in _DEDICATED_GOOGLE_BOUNDARY_KEYS:
            if bkey not in body or body[bkey] is None:
                continue
            if bkey == "allow_google" and body[bkey] is True:
                continue
            if bkey == "persistent" and body[bkey] is True:
                continue
            if bkey == "ephemeral" and body[bkey] is False:
                continue
            if bkey == "account":
                if isinstance(body[bkey], str) and existing_acct and body[bkey].strip() == existing_acct:
                    continue
            self.audit.record(
                action="profile_upsert",
                ok=False,
                sess=sess,
                engine=engine,
                profile=name,
                error=f"immutable:{bkey}",
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"专用 Google Profile 禁止修改安全边界字段: {bkey}"},
                status=400,
            )
        return None

    async def _upsert_camoufox_profile(
        self,
        *,
        http_session: aiohttp.ClientSession,
        sess: dict[str, Any],
        name: str,
        body: dict[str, Any],
        overwrite: bool,
        confirm_google: bool,
        bare_proxy: str | None,
        vault_ref: str | None,
    ) -> web.Response:
        sc_list, list_data = await self._hub_request(
            http_session,
            "GET",
            "/internal/profiles",
            params={
                "source": "tg_cmd",
                "chat_scope": "private",
                "bot": str(sess["bot"]),
                "user_id": str(sess["user_id"]),
            },
        )
        if sc_list >= 400:
            return web.json_response(list_data, status=sc_list)

        existing: dict[str, Any] | None = None
        for item in list_data.get("profiles") or []:
            if isinstance(item, dict) and str(item.get("name") or "") == name:
                existing = item
                break

        if existing is not None:
            if existing.get("pinned"):
                self.audit.record(action="profile_upsert", ok=False, sess=sess, engine="camoufox", profile=name, error="pinned_immutable")
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "主 Pinned Profile 不可修改、不可绑定代理或覆盖"},
                    status=403,
                )
            if not overwrite:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"Profile '{name}' 已存在，如需更新请传入 overwrite=true"},
                    status=409,
                )
            if existing.get("allow_google") is True:
                if not confirm_google:
                    self.audit.record(action="profile_upsert", ok=False, sess=sess, engine="camoufox", profile=name, error="missing_google_confirm")
                    return web.json_response(
                        {
                            "ok": False,
                            "source": "studio_api",
                            "error": "修改专用 Google Profile 必须显式传入严格布尔值 confirm_google_profile_change=true",
                        },
                        status=400,
                    )
                boundary_err = self._check_dedicated_google_boundary_keys(
                    body=body,
                    existing=existing,
                    sess=sess,
                    engine="camoufox",
                    name=name,
                )
                if boundary_err is not None:
                    return boundary_err

        payload: dict[str, Any] = {
            "name": name,
            "overwrite": overwrite,
            "source": "tg_cmd",
            "chat_scope": "private",
            "bot": str(sess["bot"]),
            "user_id": int(sess["user_id"]),
        }
        # Preserve existing fields when updating dedicated Google profile
        if existing is not None and overwrite:
            for keep in ("os", "locale", "window", "mobile", "webgl_config", "block_webrtc", "geoip", "persistent", "allow_google", "account"):
                if keep in existing and existing[keep] is not None:
                    payload[keep] = existing[keep]

        for field in ("os", "locale", "window", "mobile", "webgl_config", "block_webrtc", "geoip", "persistent", "ephemeral", "allow_google", "account"):
            if field in body and body[field] is not None:
                payload[field] = body[field]
        if "lang" in body and body["lang"] is not None and "locale" not in body:
            payload["locale"] = body["lang"]
        if bare_proxy is not None:
            payload["proxy"] = bare_proxy
            payload.pop("proxy_bao_ref", None)
        elif vault_ref is not None:
            payload["proxy_bao_ref"] = vault_ref
            payload.pop("proxy", None)

        sc_res, res_data = await self._hub_request(
            http_session,
            "POST",
            "/internal/profiles",
            json_body=payload,
        )
        if sc_res >= 400:
            err_msg = _scrub_egress_text(res_data.get("error") or f"HTTP {sc_res}")
            self.audit.record(action="profile_upsert", ok=False, sess=sess, engine="camoufox", profile=name, error=err_msg)
            return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=sc_res)

        prof_out = _sanitize_profile_item(
            "camoufox",
            res_data.get("profile") or {"name": name},
            active_engine="",
            active_profile="",
        )
        self.audit.record(action="profile_upsert", ok=True, sess=sess, engine="camoufox", profile=name)
        return web.json_response({"ok": True, "profile": prof_out}, status=200 if overwrite else 201)

    async def _upsert_external_profile(
        self,
        *,
        sess: dict[str, Any],
        name: str,
        body: dict[str, Any],
        overwrite: bool,
        confirm_google: bool,
        bare_proxy: str | None,
        vault_ref: str | None,
    ) -> web.Response:
        if not self.external_available():
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "外部 Chromium 适配器未配置（AGY_BROWSER_EXTERNAL_CLI）"},
                status=503,
            )

        existing = await self._show_external_profile_raw(name)
        if existing is not None:
            if existing.get("pinned") or name == "default":
                self.audit.record(action="profile_upsert", ok=False, sess=sess, engine="external_chromium", profile=name, error="pinned_immutable")
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "主 Pinned Profile 不可修改或覆盖"},
                    status=403,
                )
            if not overwrite:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"Profile '{name}' 已存在，如需更新请传入 overwrite=true"},
                    status=409,
                )
            if existing.get("allow_google") is True or existing.get("account"):
                if not confirm_google:
                    self.audit.record(action="profile_upsert", ok=False, sess=sess, engine="external_chromium", profile=name, error="missing_google_confirm")
                    return web.json_response(
                        {
                            "ok": False,
                            "source": "studio_api",
                            "error": "修改专用 Google Profile 必须显式传入严格布尔值 confirm_google_profile_change=true",
                        },
                        status=400,
                    )
                boundary_err = self._check_dedicated_google_boundary_keys(
                    body=body,
                    existing=existing,
                    sess=sess,
                    engine="external_chromium",
                    name=name,
                )
                if boundary_err is not None:
                    return boundary_err

        args = ["profile", "create", name]
        if overwrite:
            args.append("--overwrite")
        if bare_proxy:
            args.extend(["--proxy", bare_proxy])
        elif vault_ref:
            args.extend(["--proxy-bao", vault_ref])
        if body.get("tz") is not None:
            tz_val = str(body["tz"]).strip()
            if not _TZ_RE.fullmatch(tz_val) or tz_val.startswith("-"):
                return web.json_response({"ok": False, "source": "studio_api", "error": "tz 格式非法"}, status=400)
            args.extend(["--tz", tz_val])
        raw_lang = body.get("lang") if body.get("lang") is not None else body.get("locale")
        if raw_lang is not None:
            lang_val = str(raw_lang).strip()
            if not _LANG_RE.fullmatch(lang_val):
                return web.json_response({"ok": False, "source": "studio_api", "error": "lang/locale 格式非法"}, status=400)
            args.extend(["--lang", lang_val])
        if body.get("window") is not None:
            try:
                win_val = _validate_window_spec(body["window"])
            except ValueError as exc:
                return web.json_response({"ok": False, "source": "studio_api", "error": str(exc)}, status=400)
            args.extend(["--window", win_val])
        if body.get("account") is not None:
            acct_val = str(body["account"]).strip()
            if acct_val:
                if len(acct_val) > 128 or _CTRL_RE.search(acct_val) or any(ch.isspace() for ch in acct_val) or acct_val.startswith("-"):
                    return web.json_response({"ok": False, "source": "studio_api", "error": "account 标签非法"}, status=400)
                args.extend(["--account", acct_val])

        try:
            rc, out_txt, err_txt = await self._run_external_cli(args)
        except Exception as exc:
            err_msg = _scrub_egress_text(exc)
            self.audit.record(action="profile_upsert", ok=False, sess=sess, engine="external_chromium", profile=name, error=err_msg)
            return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=502)

        if rc != 0:
            err_msg = err_txt or _scrub_egress_text(out_txt, max_len=240) or f"CLI exited {rc}"
            self.audit.record(action="profile_upsert", ok=False, sess=sess, engine="external_chromium", profile=name, error=err_msg)
            return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=400)

        refreshed = await self._show_external_profile_raw(name) or {"name": name, "proxy_bao_ref": vault_ref}
        prof_out = _sanitize_profile_item("external_chromium", refreshed, active_engine="", active_profile="")
        self.audit.record(action="profile_upsert", ok=True, sess=sess, engine="external_chromium", profile=name)
        return web.json_response({"ok": True, "profile": prof_out}, status=200 if overwrite else 201)

    async def handle_delete_profile(self, request: web.Request) -> web.Response:
        raw_engine = request.match_info.get("engine") or ""
        raw_name = request.match_info.get("name") or ""
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="profile_delete", engine=raw_engine, profile=raw_name
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="profile_delete",
            allowed_keys=_ALLOWED_DELETE_KEYS,
            allow_empty=True,
            engine=raw_engine,
            profile=raw_name,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        try:
            engine = _validate_engine(raw_engine)
            name = _validate_profile_name(raw_name)
        except ValueError as exc:
            return web.json_response({"ok": False, "source": "studio_api", "error": str(exc)}, status=400)

        if name == "default":
            self.audit.record(action="profile_delete", ok=False, sess=sess, engine=engine, profile=name, error="pinned_immutable")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "主默认/Pinned Profile 禁止删除"},
                status=403,
            )

        http_session = request.app[HTTP_SESSION_KEY]
        hub_st = await self._fetch_hub_status(http_session, sess)
        active_profile = str(hub_st.get("profile") or "") if hub_st.get("running") else ""
        active_engine = str(hub_st.get("engine") or "") if hub_st.get("running") else ""
        is_running_hub = active_profile == name and (not active_engine or active_engine == engine)
        is_running_local_ext = engine == "external_chromium" and self._is_external_watch_active(name)
        if is_running_hub or is_running_local_ext:
            self.audit.record(action="profile_delete", ok=False, sess=sess, engine=engine, profile=name, error="profile_running")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"Profile '{name}' 正在运行中，请先停止浏览器后再删除"},
                status=409,
            )

        if engine == "camoufox":
            sc, data = await self._hub_request(
                http_session,
                "DELETE",
                f"/internal/profiles/{name}",
                params={
                    "source": "tg_cmd",
                    "chat_scope": "private",
                    "bot": str(sess["bot"]),
                    "user_id": str(sess["user_id"]),
                },
            )
            if sc >= 400:
                err_msg = _scrub_egress_text(data.get("error") or f"HTTP {sc}")
                self.audit.record(action="profile_delete", ok=False, sess=sess, engine=engine, profile=name, error=err_msg)
                return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=sc)
            self.audit.record(action="profile_delete", ok=True, sess=sess, engine=engine, profile=name)
            return web.json_response({"ok": True, "engine": engine, "deleted": name})

        # external_chromium
        if not self.external_available():
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "外部 Chromium 适配器未配置"},
                status=503,
            )
        existing = await self._show_external_profile_raw(name)
        if existing is None:
            return web.json_response({"ok": False, "source": "studio_api", "error": f"Profile '{name}' 不存在"}, status=404)
        if existing.get("pinned"):
            self.audit.record(action="profile_delete", ok=False, sess=sess, engine=engine, profile=name, error="pinned_immutable")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "主 Pinned Profile 禁止删除"},
                status=403,
            )
        args = ["profile", "delete", name]
        if body.get("purge_data") is True:
            args.append("--purge-data")
        rc, out_txt, err_txt = await self._run_external_cli(args)
        if rc != 0:
            err_msg = err_txt or _scrub_egress_text(out_txt, max_len=240) or f"CLI exited {rc}"
            self.audit.record(action="profile_delete", ok=False, sess=sess, engine=engine, profile=name, error=err_msg)
            return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=400)
        self.audit.record(action="profile_delete", ok=True, sess=sess, engine=engine, profile=name)
        return web.json_response({"ok": True, "engine": engine, "deleted": name})

    # ------------------------------------------------------------------ POST /api/browser/owner-bot (BM5)
    async def handle_set_owner_bot(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="set_owner_bot")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="set_owner_bot",
            allowed_keys=_ALLOWED_OWNER_BOT_KEYS,
            allow_empty=False,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        raw_bot = body.get("owner_bot")
        roster_entry = self._lookup_roster_bot(raw_bot)
        if roster_entry is None:
            self.audit.record(action="set_owner_bot", ok=False, sess=sess, owner_bot=str(raw_bot or ""), error="bot_not_in_roster")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "目标 AI 不在当前团队 Bot Roster 中，无法绑定"},
                status=400,
            )

        norm_handle = str(roster_entry["handle"])
        bot_id = _parse_positive_bot_id(roster_entry.get("bot_id"))
        hub_payload: dict[str, Any] = {
            "owner_bot": norm_handle,
            "source": "tg_cmd",
            "chat_scope": "private",
            "bot": str(sess["bot"]),
            "user_id": int(sess["user_id"]),
        }
        if bot_id is not None:
            hub_payload["owner_bot_id"] = bot_id
        if body.get("expected_session_gen") is not None:
            hub_payload["expected_session_gen"] = body["expected_session_gen"]

        sc, data = await self._hub_request(
            request.app[HTTP_SESSION_KEY],
            "POST",
            "/internal/owner-bot",
            json_body=hub_payload,
        )
        if sc >= 400:
            err_msg = _scrub_egress_text(data.get("error") or f"HTTP {sc}")
            self.audit.record(action="set_owner_bot", ok=False, sess=sess, owner_bot=norm_handle, error=err_msg)
            return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=sc)

        self._default_owner_bot = norm_handle
        self._default_owner_bot_id = bot_id
        if self._ext_watch_meta:
            self._ext_watch_meta["owner_bot"] = norm_handle
            self._ext_watch_meta["owner_bot_id"] = self._default_owner_bot_id

        self.audit.record(action="set_owner_bot", ok=True, sess=sess, owner_bot=norm_handle)
        return web.json_response(
            {
                "ok": True,
                "owner_bot": norm_handle,
                "owner_bot_id": self._default_owner_bot_id,
                "running": bool(data.get("running")),
                "session_gen": data.get("session_gen"),
                "takeover_gen": data.get("takeover_gen"),
                "engine": data.get("engine") or "",
            }
        )

    # ------------------------------------------------------------------ POST /api/browser/launch (BM6)
    async def handle_launch(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="browser_launch")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="browser_launch",
            allowed_keys=_ALLOWED_LAUNCH_KEYS,
            allow_empty=True,
            extra_forbidden=_DEDICATED_GOOGLE_BOUNDARY_KEYS,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        try:
            engine = _validate_engine(body.get("engine"), default="camoufox")
            raw_profile = body.get("profile")
            profile = _validate_profile_name(raw_profile) if (raw_profile is not None and str(raw_profile).strip()) else "default"
            launch_url = _validate_launch_url(body.get("url"))
            manual_launch = (
                _validate_strict_bool(body["manual_launch"], "manual_launch")
                if "manual_launch" in body and body["manual_launch"] is not None
                else True
            )
            restart = (
                _validate_strict_bool(body["restart"], "restart")
                if "restart" in body and body["restart"] is not None
                else False
            )
            allow_override = (
                _validate_strict_bool(body["allow_override"], "allow_override")
                if "allow_override" in body and body["allow_override"] is not None
                else False
            )
            confirm_google = (
                _validate_strict_bool(body["confirm_google_profile_change"], "confirm_google_profile_change")
                if "confirm_google_profile_change" in body and body["confirm_google_profile_change"] is not None
                else False
            )
            bare_proxy = _validate_credential_free_proxy(body.get("proxy"))
            raw_ref = (
                body.get("proxy_bao_ref")
                if body.get("proxy_bao_ref") is not None
                else (body.get("egress_ref") if body.get("egress_ref") is not None else body.get("egress_node"))
            )
            vault_ref = _validate_vault_ref(raw_ref)
            if bare_proxy and vault_ref:
                raise ValueError("不能同时指定 proxy 与 proxy_bao_ref/egress_ref")
            if body.get("window") is not None:
                _validate_window_spec(body["window"])
        except ValueError as exc:
            err_msg = _scrub_egress_text(exc)
            self.audit.record(action="browser_launch", ok=False, sess=sess, error=err_msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": err_msg}, status=400)

        if vault_ref and self.egress_pool is not None and self.egress_pool.vault.is_ready():
            resolved_ref = await self.egress_pool.resolve_node_ref(vault_ref)
            if resolved_ref is None:
                self.audit.record(
                    action="browser_launch",
                    ok=False,
                    sess=sess,
                    engine=engine,
                    profile=profile,
                    error="egress_not_found",
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"出口节点 {vault_ref!r} 不存在或已作废"},
                    status=400,
                )
            vault_ref = resolved_ref[1]

        owner_bot: str | None = self._default_owner_bot
        owner_bot_id: int | None = _parse_positive_bot_id(self._default_owner_bot_id)
        if body.get("owner_bot") is not None and str(body.get("owner_bot")).strip():
            roster_entry = self._lookup_roster_bot(body.get("owner_bot"))
            if roster_entry is None:
                self.audit.record(action="browser_launch", ok=False, sess=sess, engine=engine, profile=profile, error="bot_not_in_roster")
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "指定的 owner_bot 不在团队 Roster 中"},
                    status=400,
                )
            owner_bot = str(roster_entry["handle"])
            owner_bot_id = _parse_positive_bot_id(roster_entry.get("bot_id"))
            self._default_owner_bot = owner_bot
            self._default_owner_bot_id = owner_bot_id
        elif owner_bot and owner_bot_id is None:
            roster_entry = self._lookup_roster_bot(owner_bot)
            if roster_entry is not None:
                owner_bot_id = _parse_positive_bot_id(roster_entry.get("bot_id"))
                self._default_owner_bot_id = owner_bot_id

        http_session = request.app[HTTP_SESSION_KEY]

        if engine == "camoufox":
            if self._ext_watch_proc is not None and getattr(self._ext_watch_proc, "returncode", None) is None:
                if not restart:
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "外部 Chromium 会话正在运行，请先停止或传入 restart=true"},
                        status=409,
                    )
                await self._stop_external_watch(stop_external_profile=True)

            hub_payload: dict[str, Any] = {
                "profile": profile,
                "restart": restart,
                "manual_launch": manual_launch,
                "engine": "camoufox",
                "notify": bool(body.get("notify", False)),
                "source": "tg_cmd",
                "chat_scope": "private",
                "bot": str(sess["bot"]),
                "user_id": int(sess["user_id"]),
            }
            if launch_url:
                hub_payload["url"] = launch_url
            if owner_bot:
                hub_payload["owner_bot"] = owner_bot
            if owner_bot_id:
                hub_payload["owner_bot_id"] = owner_bot_id
            if allow_override:
                hub_payload["allow_override"] = True
            if bare_proxy is not None:
                hub_payload["proxy"] = bare_proxy
            if vault_ref is not None:
                hub_payload["proxy_bao_ref"] = vault_ref
            for ov_k in ("os", "locale", "window", "mobile"):
                if ov_k in body and body[ov_k] is not None:
                    hub_payload[ov_k] = body[ov_k]

            has_drift_override = any(
                k in hub_payload for k in ("proxy", "proxy_bao_ref", "os", "locale", "window", "mobile")
            )
            if has_drift_override and allow_override and not confirm_google:
                # Check if target profile is a dedicated Google profile
                sc_p, p_data = await self._hub_request(
                    http_session,
                    "GET",
                    "/internal/profiles",
                    params={
                        "source": "tg_cmd",
                        "chat_scope": "private",
                        "bot": str(sess["bot"]),
                        "user_id": str(sess["user_id"]),
                    },
                )
                if sc_p == 200:
                    for item in p_data.get("profiles") or []:
                        if isinstance(item, dict) and item.get("name") == profile and item.get("allow_google") and not item.get("pinned"):
                            return web.json_response(
                                {
                                    "ok": False,
                                    "source": "studio_api",
                                    "error": "覆盖专用 Google Profile 参数必须同时传入严格布尔值 confirm_google_profile_change=true",
                                },
                                status=400,
                            )

            sc, data = await self._hub_request(
                http_session,
                "POST",
                "/internal/start",
                json_body=hub_payload,
                timeout_sec=30.0,
            )
            if sc >= 400:
                err_msg = _scrub_egress_text(data.get("error") or f"HTTP {sc}")
                self.audit.record(action="browser_launch", ok=False, sess=sess, engine=engine, profile=profile, owner_bot=owner_bot or "", error=err_msg)
                return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=sc)
            self.audit.record(action="browser_launch", ok=True, sess=sess, engine=engine, profile=profile, owner_bot=owner_bot or "")
            return web.json_response({"ok": True, "engine": "camoufox", "state": data})

        # Engine 2: external_chromium
        return await self._launch_external_chromium(
            http_session=http_session,
            sess=sess,
            profile=profile,
            launch_url=launch_url,
            owner_bot=owner_bot,
            owner_bot_id=owner_bot_id,
            manual_launch=manual_launch,
            restart=restart,
            notify=bool(body.get("notify", False)),
        )

    async def _launch_external_chromium(
        self,
        *,
        http_session: aiohttp.ClientSession,
        sess: dict[str, Any],
        profile: str,
        launch_url: str | None,
        owner_bot: str | None,
        owner_bot_id: int | None,
        manual_launch: bool,
        restart: bool,
        notify: bool = False,
    ) -> web.Response:
        cli = self._resolve_external_cli()
        if not cli:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "外部 Chromium 适配器未配置（AGY_BROWSER_EXTERNAL_CLI）"},
                status=503,
            )

        hub_st = await self._fetch_hub_status(http_session, sess)
        local_watch_active = self._is_external_watch_active()
        if hub_st.get("running") or local_watch_active:
            if not restart:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "已有活跃浏览器会话，请先停止或传入 restart=true"},
                    status=409,
                )
            await self._stop_external_watch()
            if hub_st.get("running") and hub_st.get("engine_mode") == "async_hosted":
                await self._hub_request(
                    http_session,
                    "POST",
                    "/internal/stop",
                    json_body={
                        "source": "tg_cmd",
                        "chat_scope": "private",
                        "bot": str(sess["bot"]),
                        "user_id": int(sess["user_id"]),
                    },
                )

        prof_info = await self._show_external_profile_raw(profile) if profile != "default" else {"name": "default", "pinned": True}
        if prof_info is None:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"外部 Chromium Profile '{profile}' 不存在"},
                status=404,
            )

        # 1. Inspect external profile status: reject active external live bridge (409),
        #    and safely self-heal idle containers started without a loopback CDP port.
        try:
            rc_st, out_st, _err_st = await self._run_external_cli(
                ["--profile", profile, "status"],
                timeout_sec=15.0,
            )
        except Exception as exc:
            log.warning("External chromium status probe failed for %s: %s", profile, type(exc).__name__)
            rc_st, out_st = -1, ""

        container_preexisted = False
        if rc_st == 0:
            st_flags = _parse_external_status_output(out_st)
            container_preexisted = bool(
                st_flags["container_running"]
                and not (st_flags["cdp_disabled"] and st_flags["live_inactive"])
            )
            if st_flags["live_active"]:
                err_msg = f"外部 Chromium Profile '{profile}' 已有活跃的 Live 直播桥在运行，请先停止后再试"
                self.audit.record(
                    action="browser_launch",
                    ok=False,
                    sess=sess,
                    engine="external_chromium",
                    profile=profile,
                    owner_bot=owner_bot or "",
                    error="external_live_active",
                )
                return web.json_response({"ok": False, "source": "studio_api", "error": err_msg}, status=409)
            if st_flags["container_running"] and st_flags["cdp_disabled"] and st_flags["live_inactive"]:
                try:
                    rc_stop, out_stop, err_stop = await self._run_external_cli(
                        ["--profile", profile, "stop"],
                        timeout_sec=20.0,
                    )
                except Exception as exc:
                    err_msg = f"回收无 CDP 闲置容器失败: {_scrub_egress_text(exc)}"
                    self.audit.record(
                        action="browser_launch",
                        ok=False,
                        sess=sess,
                        engine="external_chromium",
                        profile=profile,
                        owner_bot=owner_bot or "",
                        error=err_msg,
                    )
                    return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=500)
                if rc_stop != 0:
                    detail = err_stop or _scrub_egress_text(out_stop, max_len=240) or f"stop exited {rc_stop}"
                    err_msg = f"回收无 CDP 闲置容器失败: {detail}"
                    self.audit.record(
                        action="browser_launch",
                        ok=False,
                        sess=sess,
                        engine="external_chromium",
                        profile=profile,
                        owner_bot=owner_bot or "",
                        error=err_msg,
                    )
                    return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=500)

        # 2. Spawn managed `live --watch` bridge directly in an isolated process group (NEVER `--wait-human`!)
        await self._stop_external_watch()
        watch_cmd: list[str] = [cli, "--profile", profile, "live", "--watch"]
        if launch_url and launch_url.lower() != "about:blank":
            watch_cmd.extend(["--url", launch_url])
        sess_bot = str(sess.get("bot") or "").strip()
        if _BOT_FLAG_RE.fullmatch(sess_bot):
            watch_cmd.extend(["--bot", sess_bot])
        sess_uid = sess.get("user_id")
        if isinstance(sess_uid, int) and not isinstance(sess_uid, bool) and sess_uid > 0:
            watch_cmd.extend(["--user-id", str(sess_uid)])
        if not notify:
            watch_cmd.append("--no-notify")

        try:
            watch_proc = await self._subprocess_exec(
                *watch_cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
        except Exception as exc:
            err_msg = _scrub_egress_text(exc)
            self.audit.record(
                action="browser_launch",
                ok=False,
                sess=sess,
                engine="external_chromium",
                profile=profile,
                owner_bot=owner_bot or "",
                error=err_msg,
            )
            return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=500)

        stderr_buf: deque[str] = deque(maxlen=_EXT_STDERR_MAX_LINES)
        stderr_task: asyncio.Task[None] | None = None
        proc_stream = getattr(watch_proc, "stdout", None) or getattr(watch_proc, "stderr", None)
        if proc_stream is not None and callable(getattr(proc_stream, "read", None)):
            stderr_task = asyncio.create_task(self._drain_stream_lines(proc_stream, stderr_buf))

        egress_ref = str(prof_info.get("proxy_bao_ref") or prof_info.get("bao_ref") or "")
        egress_display = _scrub_egress_text(prof_info.get("egress") or prof_info.get("egress_display") or "direct", max_len=128)
        async with self._ext_lock:
            self._ext_watch_proc = watch_proc
            self._ext_watch_stderr_buf = stderr_buf
            self._ext_watch_stderr_task = stderr_task
            self._ext_watch_meta = {
                "profile": profile,
                "owner_bot": owner_bot,
                "owner_bot_id": owner_bot_id,
                "egress_ref": egress_ref,
                "egress": egress_display,
                "started_at": time.monotonic(),
            }

        # 3. Wait for Hub sync_external attachment (skipping transient `/internal/sync/start` placeholder state)
        deadline = time.monotonic() + self._external_attach_timeout
        attached = False
        latest_st: dict[str, Any] = {}
        while time.monotonic() < deadline:
            if getattr(watch_proc, "returncode", None) is not None:
                if stderr_task is not None and not stderr_task.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(stderr_task), timeout=0.3)
                    except Exception:
                        pass
                diag = self._format_stderr_tail(stderr_buf)
                exit_rc = watch_proc.returncode
                await self._stop_external_watch(
                    stop_external_profile=not container_preexisted,
                    expected_proc=watch_proc,
                )
                audit_err = f"watch_exited_early:{diag}" if diag else "watch_exited_early"
                self.audit.record(
                    action="browser_launch",
                    ok=False,
                    sess=sess,
                    engine="external_chromium",
                    profile=profile,
                    owner_bot=owner_bot or "",
                    error=audit_err,
                )
                err_msg = (
                    f"外部 Chromium live --watch 提前退出（code={exit_rc}）: {diag}"
                    if diag
                    else f"外部 Chromium live --watch 提前退出（code={exit_rc}）"
                )
                return web.json_response(
                    {"ok": False, "source": "upstream", "error": err_msg},
                    status=500,
                )
            latest_st = await self._fetch_hub_status(http_session, sess)
            if latest_st.get("running") and latest_st.get("engine_mode") == "sync_external":
                ai_st = latest_st.get("ai_status")
                has_frame = bool(latest_st.get("has_frame"))
                has_url = bool(str(latest_st.get("url") or "").strip())
                if ai_st == "已启动同步浏览器会话" and not has_frame and not has_url:
                    await asyncio.sleep(self._external_attach_poll_interval)
                    continue
                attached = True
                break
            await asyncio.sleep(self._external_attach_poll_interval)

        if not attached:
            diag = self._format_stderr_tail(stderr_buf)
            await self._stop_external_watch(
                stop_external_profile=not container_preexisted,
                expected_proc=watch_proc,
            )
            audit_err = f"attach_timeout:{diag}" if diag else "attach_timeout"
            self.audit.record(
                action="browser_launch",
                ok=False,
                sess=sess,
                engine="external_chromium",
                profile=profile,
                owner_bot=owner_bot or "",
                error=audit_err,
            )
            err_msg = (
                f"等待外部 Chromium 附着 Live-Browser Hub 超时: {diag}"
                if diag
                else "等待外部 Chromium 附着 Live-Browser Hub 超时"
            )
            return web.json_response(
                {"ok": False, "source": "upstream", "error": err_msg},
                status=500,
            )

        # 4. Atomically sync engine/egress metadata (and optional owner_bot) on Hub even when owner_bot is None
        ob_payload: dict[str, Any] = {
            "engine": "external_chromium",
            "egress": egress_display or "direct",
            "source": "tg_cmd",
            "chat_scope": "private",
            "bot": str(sess["bot"]),
            "user_id": int(sess["user_id"]),
        }
        if owner_bot:
            ob_payload["owner_bot"] = owner_bot
            if owner_bot_id:
                ob_payload["owner_bot_id"] = owner_bot_id
        sc_ob, ob_data = await self._hub_request(http_session, "POST", "/internal/owner-bot", json_body=ob_payload)
        if sc_ob == 200 and isinstance(ob_data, dict):
            latest_st = ob_data

        # 5. Manual launch -> trigger human takeover wakeup immediately!
        if manual_launch:
            sc_tk, tk_data = await self._hub_request(
                http_session,
                "POST",
                "/internal/takeover",
                json_body={
                    "active": True,
                    "reason": "manual_launch",
                    "manual_launch": True,
                    "source": "tg_cmd",
                    "chat_scope": "private",
                    "bot": str(sess["bot"]),
                    "user_id": int(sess["user_id"]),
                },
            )
            if sc_tk == 200 and isinstance(tk_data, dict):
                latest_st = tk_data

        # 6. Post-handover liveness re-check: prevent fake HTTP 200 if watch exited or Hub dropped back to idle
        post_rc = getattr(watch_proc, "returncode", None)
        post_st = await self._fetch_hub_status(http_session, sess)
        hub_still_running = bool(post_st.get("running") and post_st.get("engine_mode") == "sync_external")
        if post_rc is not None or not hub_still_running:
            if stderr_task is not None and not stderr_task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(stderr_task), timeout=0.3)
                except Exception:
                    pass
            diag = self._format_stderr_tail(stderr_buf)
            await self._stop_external_watch(
                stop_external_profile=not container_preexisted,
                expected_proc=watch_proc,
            )
            if post_rc is not None:
                audit_err = f"watch_exited_after_attach:{diag}" if diag else "watch_exited_after_attach"
                err_msg = (
                    f"外部 Chromium 直播桥启动后意外退出（code={post_rc}）: {diag}"
                    if diag
                    else f"外部 Chromium 直播桥启动后意外退出（code={post_rc}）"
                )
            else:
                audit_err = f"hub_not_running_after_attach:{diag}" if diag else "hub_not_running_after_attach"
                err_msg = (
                    f"外部 Chromium 未能保持连接（Hub 已回到待机）: {diag}"
                    if diag
                    else "外部 Chromium 未能保持连接（Hub 已回到待机）"
                )
            self.audit.record(
                action="browser_launch",
                ok=False,
                sess=sess,
                engine="external_chromium",
                profile=profile,
                owner_bot=owner_bot or "",
                error=audit_err,
            )
            return web.json_response(
                {"ok": False, "source": "upstream", "error": err_msg},
                status=500,
            )

        self.audit.record(
            action="browser_launch",
            ok=True,
            sess=sess,
            engine="external_chromium",
            profile=profile,
            owner_bot=owner_bot or "",
        )
        return web.json_response({"ok": True, "engine": "external_chromium", "state": latest_st})

    # ------------------------------------------------------------------ POST /api/browser/stop
    async def handle_stop(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="browser_stop")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="browser_stop",
            allowed_keys=_ALLOWED_STOP_KEYS,
            allow_empty=True,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        http_session = request.app[HTTP_SESSION_KEY]
        stopped_watch = await self._stop_external_watch(stop_external_profile=True)
        if stopped_watch:
            self.audit.record(action="browser_stop", ok=True, sess=sess, engine="external_chromium")
            return web.json_response({"ok": True, "engine": "external_chromium", "stopped": True})

        hub_payload: dict[str, Any] = {
            "source": "tg_cmd",
            "chat_scope": "private",
            "bot": str(sess["bot"]),
            "user_id": int(sess["user_id"]),
            "force": bool(body.get("force") is True),
        }
        if body.get("expected_session_gen") is not None:
            hub_payload["expected_session_gen"] = body["expected_session_gen"]

        sc, data = await self._hub_request(http_session, "POST", "/internal/stop", json_body=hub_payload)
        if sc >= 400:
            err_msg = _scrub_egress_text(data.get("error") or f"HTTP {sc}")
            self.audit.record(action="browser_stop", ok=False, sess=sess, error=err_msg)
            return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=sc)
        self.audit.record(action="browser_stop", ok=True, sess=sess, engine="camoufox")
        return web.json_response({"ok": True, "stopped": True, "state": data})

    # ------------------------------------------------------------------ POST /api/browser/takeover (BM7)
    async def handle_takeover(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="browser_takeover")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="browser_takeover",
            allowed_keys=_ALLOWED_TAKEOVER_KEYS,
            allow_empty=False,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        try:
            active = _validate_strict_bool(body.get("active"), "active")
            reason = _scrub_egress_text(body.get("reason") or "", max_len=200)
            raw_note = body.get("instruction") if body.get("instruction") is not None else body.get("handback_note")
            clean_note = _sanitize_handback_note(raw_note) if (not active and raw_note is not None) else ""
        except ValueError as exc:
            return web.json_response({"ok": False, "source": "studio_api", "error": str(exc)}, status=400)

        hub_payload: dict[str, Any] = {
            "active": active,
            "reason": reason,
            "source": "tg_cmd",
            "chat_scope": "private",
            "bot": str(sess["bot"]),
            "user_id": int(sess["user_id"]),
        }
        if clean_note:
            hub_payload["instruction"] = clean_note
            hub_payload["handback_note"] = clean_note
        if body.get("expected_session_gen") is not None:
            hub_payload["expected_session_gen"] = body["expected_session_gen"]
        if body.get("expected_takeover_gen") is not None:
            hub_payload["expected_takeover_gen"] = body["expected_takeover_gen"]

        sc, data = await self._hub_request(
            request.app[HTTP_SESSION_KEY],
            "POST",
            "/internal/takeover",
            json_body=hub_payload,
        )
        if sc >= 400:
            err_msg = _scrub_egress_text(data.get("error") or f"HTTP {sc}")
            self.audit.record(action="browser_takeover", ok=False, sess=sess, error=err_msg)
            return web.json_response({"ok": False, "source": "upstream", "error": err_msg}, status=sc)
        self.audit.record(action="browser_takeover", ok=True, sess=sess)
        return web.json_response({"ok": True, "state": data})
