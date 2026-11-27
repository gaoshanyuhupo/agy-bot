#!/usr/bin/env python3
"""Generic loopback-only CDP -> Live Browser SyncLiveBridge adapter.

Bridges an external local Chromium/CDP browser instance (strictly on 127.0.0.1 or [::1])
into the existing `agy-live-browser.service` Telegram Live Card & Mini App panel for
real-time visibility and visible Human-in-the-Loop remote takeover.

Security invariants:
- Strictly loopback-only literal hosts (`127.0.0.1` or `[::1]`), unprivileged ports
  (`1024..65535`), `/devtools/` WS path prefix, no credentials, no `..`, no control chars.
- `/json/version` discovery disables proxies (`trust_env=False`, explicit `proxies=None`),
  disables HTTP redirects (`allow_redirects=False`), caps response size (64 KiB), and
  re-verifies that `webSocketDebuggerUrl` shares the exact same loopback host & port.
- Never imports `playwright` or `camoufox` at module import time (100% compatible with
  `verify_gate.NoRealBrowserFinder`).
- Non-destructive detach on exit: releases held mouse buttons, returns self-held takeover
  with dual `(expected_session_gen, expected_takeover_gen)` CAS, calls `SyncLiveBridge.close()`,
  and disconnects CDP client (`browser.close()` + `pw.stop()`) without closing remote
  pages or contexts.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import threading
import time
from typing import Any, Callable, Mapping
import urllib.parse

import requests

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import live_browser_ctl as ctl  # noqa: E402

SYNC_LEASE_TIMEOUT_SECONDS = 120.0
DEFAULT_WAIT_TIMEOUT_SECONDS = 600.0
ACTIVE_TAKEOVER_TICK_SECONDS = 0.09
WATCH_IDLE_TICK_SECONDS = 0.35
MAX_HEARTBEAT_INTERVAL_SECONDS = 15.0
MAX_VERSION_RESPONSE_BYTES = 65536
CDP_VERSION_TIMEOUT_SECONDS = 5.0
MIN_CDP_PORT = 1024
MAX_CDP_PORT = 65535
MAX_CONSECUTIVE_SCREENSHOT_ERRORS = 3

REEXEC_SENTINEL_ENV = "_AGY_LIVE_BROWSER_REEXEC"
PYTHON_OVERRIDE_ENV = "AGY_LIVE_BROWSER_PYTHON"

_LOOPBACK_NETLOC_RE = re.compile(r"^(?:(127\.0\.0\.1)|\[(::1)\]):([1-9][0-9]{3,4})$")
_WS_DEVTOOLS_PATH_RE = re.compile(r"^/devtools/[A-Za-z0-9._/-]+$")
_HTTP_ALLOWED_PATHS = frozenset({"", "/", "/json/version"})
_FALLBACK_GOOGLE_HOST_RE = re.compile(
    r"^(?:[a-z0-9-]+\.)*(?:"
    r"google\.[a-z]{2,3}(?:\.[a-z]{2})?|"
    r"gmail\.com|googlemail\.com|"
    r"youtube\.com|youtu\.be|"
    r"googleapis\.com|googleusercontent\.com|gstatic\.com|googlevideo\.com|withgoogle\.com|"
    r"g\.co|goo\.gl"
    r")$"
)


def _is_google_destination_url_fallback(url: str | None) -> bool:
    """Fail-closed Google destination check when live_browser_server cannot be imported."""
    raw = str(url or "").strip()
    if not raw:
        return False
    if "://" not in raw and not raw.lower().startswith(("about:", "data:", "javascript:", "blob:")):
        raw = "https://" + raw
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception:
        return True
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return False
    return bool(_FALLBACK_GOOGLE_HOST_RE.match(host))

_FATAL_CDP_ERROR_PATTERNS = (
    "targetclosederror",
    "target closed",
    "target page, context or browser has been closed",
    "browser has been closed",
    "context has been closed",
    "page has been closed",
    "connection closed",
    "cdp session closed",
    "session closed",
    "pipe closed",
    "browser disconnected",
    "websocket closed",
)


def _has_control_or_whitespace(text: str) -> bool:
    return any(ord(ch) <= 32 or ord(ch) == 127 for ch in text)


def parse_loopback_cdp_url(
    raw_url: Any,
    *,
    allow_http: bool = True,
) -> tuple[str, str, int, str]:
    """Strictly validate a loopback-only CDP URL and return `(scheme, host, port, normalized_url)`.

    Only accepts literal `127.0.0.1` or `[::1]` on ports `1024..65535`.
    Rejects DNS hostnames (`localhost`), wildcards (`0.0.0.0`, `[::]`), non-canonical
    loopback addresses (`127.0.0.2`, `[::ffff:127.0.0.1]`), credentials, control chars,
    queries/fragments, backslashes, path traversal (`..`), and non-`/devtools/` WS paths.
    """
    if not isinstance(raw_url, str) or not raw_url:
        raise ValueError("CDP URL must be a non-empty string")
    if _has_control_or_whitespace(raw_url):
        raise ValueError("CDP URL must not contain whitespace or control characters")
    if "\\" in raw_url or "?" in raw_url or "#" in raw_url:
        raise ValueError("CDP URL must not contain backslashes, query strings, or fragments")

    parsed = urllib.parse.urlsplit(raw_url)
    scheme = (parsed.scheme or "").lower()
    allowed_schemes = ("ws", "http") if allow_http else ("ws",)
    if scheme not in allowed_schemes:
        raise ValueError(f"Unsupported CDP URL scheme {scheme!r}; allowed: {', '.join(allowed_schemes)}")

    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise ValueError("CDP URL must not contain credentials")

    match = _LOOPBACK_NETLOC_RE.fullmatch(parsed.netloc)
    if not match:
        raise ValueError(
            "CDP URL host must be literal 127.0.0.1 or [::1] with an explicit unprivileged port"
        )
    host = match.group(1) or match.group(2)
    port = int(match.group(3))
    if port < MIN_CDP_PORT or port > MAX_CDP_PORT:
        raise ValueError(f"CDP port must be within {MIN_CDP_PORT}..{MAX_CDP_PORT}, got {port}")

    path = parsed.path or ""
    unquoted_path = urllib.parse.unquote(path)
    if (
        _has_control_or_whitespace(unquoted_path)
        or "\\" in unquoted_path
        or "//" in path
        or "//" in unquoted_path
    ):
        raise ValueError("CDP URL path contains forbidden characters")

    segments = path.split("/")
    unquoted_segments = unquoted_path.split("/")
    if any(seg in (".", "..") for seg in segments) or any(seg in (".", "..") for seg in unquoted_segments):
        raise ValueError("CDP URL path must not contain relative path segments")

    host_netloc = f"[{host}]" if host == "::1" else host
    if scheme == "ws":
        if not _WS_DEVTOOLS_PATH_RE.fullmatch(path) or path.endswith("/"):
            raise ValueError("CDP WebSocket URL path must start with '/devtools/' and contain safe characters")
        normalized = f"ws://{host_netloc}:{port}{path}"
    else:
        if path not in _HTTP_ALLOWED_PATHS:
            raise ValueError("CDP HTTP discovery URL path must be empty, '/', or '/json/version'")
        normalized = f"http://{host_netloc}:{port}/json/version"

    return scheme, host, port, normalized


def validate_loopback_cdp_url(raw_url: Any, *, allow_http: bool = True) -> str:
    """Validate a loopback CDP URL and return its normalized string form."""
    _, _, _, normalized = parse_loopback_cdp_url(raw_url, allow_http=allow_http)
    return normalized


def validate_navigation_url(raw_url: Any) -> str:
    """Validate an optional initial navigation URL (strictly http:// or https://)."""
    if not isinstance(raw_url, str) or not raw_url:
        raise ValueError("Navigation URL must be a non-empty string")
    if raw_url.startswith("-"):
        raise ValueError("Navigation URL must not start with '-'")
    if _has_control_or_whitespace(raw_url):
        raise ValueError("Navigation URL must not contain whitespace or control characters")
    parsed = urllib.parse.urlsplit(raw_url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"Navigation URL scheme must be http or https, got {scheme!r}")
    if not parsed.hostname:
        raise ValueError("Navigation URL must include a valid host")
    return raw_url


def validate_timeout(raw_timeout: Any, default: float = DEFAULT_WAIT_TIMEOUT_SECONDS) -> float:
    """Validate timeout is a strict positive finite float (rejects bool, <=0, NaN, inf)."""
    return ctl._validate_positive_timeout(raw_timeout, default=default)


def resolve_cdp_ws_url(
    raw_url: str,
    *,
    session: requests.Session | None = None,
    timeout: float = CDP_VERSION_TIMEOUT_SECONDS,
) -> str:
    """Resolve a loopback `ws://` or `http://` CDP endpoint to a verified loopback `ws://` URL.

    For `http://127.0.0.1:<port>`, probes `/json/version` with proxies and redirects strictly
    disabled, enforces a 64 KiB response cap, and re-verifies that `webSocketDebuggerUrl`
    matches the exact same loopback host, port, and `/devtools/` path prefix.
    """
    scheme, host, port, normalized = parse_loopback_cdp_url(raw_url, allow_http=True)
    if scheme == "ws":
        return normalized

    timeout_s = validate_timeout(timeout, default=CDP_VERSION_TIMEOUT_SECONDS)
    own_session = session is None
    sess = requests.Session() if own_session else session
    assert sess is not None
    if hasattr(sess, "trust_env"):
        sess.trust_env = False

    resp: Any = None
    try:
        resp = sess.get(
            normalized,
            timeout=timeout_s,
            allow_redirects=False,
            proxies={"http": None, "https": None},
            stream=True,
        )
        status = getattr(resp, "status_code", 0)
        if status != 200:
            raise ValueError(f"CDP /json/version probe rejected with HTTP {status}")

        headers = getattr(resp, "headers", None) or {}
        raw_cl = headers.get("Content-Length") or headers.get("content-length")
        if raw_cl is not None:
            try:
                if int(str(raw_cl).strip()) > MAX_VERSION_RESPONSE_BYTES:
                    raise ValueError("CDP /json/version response exceeds maximum allowed size")
            except ValueError as exc:
                if "maximum allowed size" in str(exc):
                    raise
                raise ValueError("CDP /json/version returned invalid Content-Length header") from exc

        chunks: list[bytes] = []
        total_bytes = 0
        iter_content = getattr(resp, "iter_content", None)
        if callable(iter_content):
            for chunk in iter_content(chunk_size=8192):
                if not chunk:
                    continue
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                total_bytes += len(chunk)
                if total_bytes > MAX_VERSION_RESPONSE_BYTES:
                    raise ValueError("CDP /json/version response exceeds maximum allowed size")
                chunks.append(chunk)
            raw_bytes = b"".join(chunks)
        else:
            raw_content = getattr(resp, "content", b"")
            if isinstance(raw_content, str):
                raw_bytes = raw_content.encode("utf-8")
            else:
                raw_bytes = bytes(raw_content or b"")
            if len(raw_bytes) > MAX_VERSION_RESPONSE_BYTES:
                raise ValueError("CDP /json/version response exceeds maximum allowed size")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to probe CDP /json/version: {exc}") from exc
    finally:
        if resp is not None:
            close_resp = getattr(resp, "close", None)
            if callable(close_resp):
                try:
                    close_resp()
                except Exception:
                    pass
        if own_session:
            try:
                sess.close()
            except Exception:
                pass

    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError("CDP /json/version returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("CDP /json/version payload must be a JSON object")

    raw_ws = payload.get("webSocketDebuggerUrl")
    if not isinstance(raw_ws, str) or not raw_ws:
        raise ValueError("CDP /json/version missing webSocketDebuggerUrl")

    ws_scheme, ws_host, ws_port, ws_normalized = parse_loopback_cdp_url(raw_ws, allow_http=False)
    if ws_scheme != "ws" or ws_host != host or ws_port != port:
        raise ValueError(
            f"CDP /json/version webSocketDebuggerUrl host/port mismatch "
            f"(expected {host}:{port}, got {ws_host}:{ws_port})"
        )
    return ws_normalized


def _is_world_writable_dir(dir_path: str) -> bool:
    try:
        st = os.stat(dir_path)
    except OSError:
        return True
    if not stat.S_ISDIR(st.st_mode):
        return True
    return bool(st.st_mode & stat.S_IWOTH)


def validate_reexec_python(raw_path: Any) -> str:
    """Validate a candidate Python interpreter path for safe `os.execv` forwarding.

    Checks `realpath()` for regular file, executability, and non-world-writable permissions,
    while returning the UNRESOLVED path so virtualenv symlinks retain their `pyvenv.cfg`.
    """
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError("Python interpreter path must be a non-empty string")
    if _has_control_or_whitespace(raw_path):
        raise ValueError("Python interpreter path must not contain whitespace or control characters")
    if not raw_path.startswith("/"):
        raise ValueError("Python interpreter path must be an absolute path")
    if raw_path.endswith("/"):
        raise ValueError("Python interpreter path must reference a file, not a directory")
    if ".." in raw_path.split("/"):
        raise ValueError("Python interpreter path must not contain '..' segments")

    if not os.path.lexists(raw_path):
        raise ValueError(f"Python interpreter path does not exist: {raw_path}")

    parent_raw = os.path.dirname(raw_path) or "/"
    if _is_world_writable_dir(parent_raw):
        raise ValueError("Python interpreter resides in a world-writable directory")

    resolved = os.path.realpath(raw_path)
    try:
        st = os.stat(resolved)
    except OSError as exc:
        raise ValueError(f"Python interpreter target is inaccessible: {exc}") from exc

    if not stat.S_ISREG(st.st_mode):
        raise ValueError("Python interpreter target must be a regular file")
    if not os.access(resolved, os.X_OK):
        raise ValueError("Python interpreter target is not executable")
    if st.st_mode & stat.S_IWOTH:
        raise ValueError("Python interpreter target must not be world-writable")

    parent_resolved = os.path.dirname(resolved) or "/"
    if _is_world_writable_dir(parent_resolved):
        raise ValueError("Python interpreter target resides in a world-writable directory")

    # Return unresolved path so venv symlinks keep `pyvenv.cfg` resolution intact.
    return raw_path


def _has_playwright_module(
    find_spec_fn: Callable[[str], Any] = importlib.util.find_spec,
) -> bool:
    try:
        return find_spec_fn("playwright") is not None
    except ImportError:
        return False


def default_playwright_python() -> str:
    return str(Path.home() / "camoufox-env" / "bin" / "python3")


def maybe_reexec_into_playwright_python(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    execv_fn: Callable[[str, list[str]], Any] = os.execv,
    find_spec_fn: Callable[[str], Any] = importlib.util.find_spec,
    default_python: str | None = None,
    current_executable: str | None = None,
) -> bool:
    """Re-exec into a validated Playwright-capable Python interpreter if `playwright` is absent.

    Returns False if `playwright` is already available (no re-exec needed).
    Raises `ValueError` on invalid `AGY_LIVE_BROWSER_PYTHON` override or `RuntimeError`
    if re-exec was already attempted (`_AGY_LIVE_BROWSER_REEXEC=1`) to prevent recursion.
    """
    if _has_playwright_module(find_spec_fn):
        return False

    target_env = os.environ if env is None else env
    if str(target_env.get(REEXEC_SENTINEL_ENV) or "").strip() == "1":
        raise RuntimeError(
            "playwright is unavailable after interpreter forwarding "
            f"({REEXEC_SENTINEL_ENV}=1); aborting to prevent recursive re-exec"
        )

    override = target_env.get(PYTHON_OVERRIDE_ENV)
    if override is not None and override != "":
        candidate = override
    else:
        candidate = default_python if default_python is not None else default_playwright_python()

    target_py = validate_reexec_python(candidate)
    cur_exe = sys.executable if current_executable is None else current_executable
    if os.path.abspath(target_py) == os.path.abspath(cur_exe):
        raise RuntimeError(
            f"Target Python interpreter {target_py!r} matches current executable without playwright"
        )

    target_env[REEXEC_SENTINEL_ENV] = "1"
    execv_fn(target_py, [target_py, *argv])
    return True


def _default_connect_over_cdp(ws_url: str, timeout_ms: int) -> tuple[Any, Any]:
    """Lazily import Playwright sync API and attach to a verified loopback CDP endpoint."""
    from playwright.sync_api import sync_playwright  # noqa: PLC0415

    pw = sync_playwright().start()
    try:
        browser = pw.chromium.connect_over_cdp(ws_url, timeout=timeout_ms)
    except Exception:
        try:
            pw.stop()
        except Exception:
            pass
        raise
    return pw, browser


def _is_page_closed(page: Any) -> bool:
    fn = getattr(page, "is_closed", None)
    if callable(fn):
        try:
            return bool(fn())
        except Exception:
            return True
    return bool(fn) if fn is not None else False


def _open_pages(ctx: Any) -> list[Any]:
    try:
        pages = list(getattr(ctx, "pages", None) or [])
    except Exception:
        return []
    return [p for p in pages if not _is_page_closed(p)]


def _is_browser_connected(browser: Any) -> bool:
    fn = getattr(browser, "is_connected", None)
    if callable(fn):
        try:
            return bool(fn())
        except Exception:
            return False
    return True


def _is_fatal_cdp_error(exc_type: str | None, err_msg: str | None) -> bool:
    combined = f"{exc_type or ''} {err_msg or ''}".lower()
    if not combined.strip():
        return False
    return any(pat in combined for pat in _FATAL_CDP_ERROR_PATTERNS)


def _select_context_and_page(browser: Any) -> tuple[Any | None, Any | None, str | None]:
    if not _is_browser_connected(browser):
        return None, None, "cdp_disconnected"
    try:
        contexts = list(getattr(browser, "contexts", None) or [])
    except Exception:
        return None, None, "cdp_disconnected"
    if not contexts:
        return None, None, "no_browser_context"
    for ctx in contexts:
        pages = _open_pages(ctx)
        if pages:
            return ctx, pages[0], None
    return contexts[0], None, "no_open_page"


def _sync_active_idx_to_open_page(bridge: Any, ctx: Any) -> bool:
    try:
        all_pages = list(getattr(ctx, "pages", None) or [])
    except Exception:
        return False
    if not all_pages:
        return False
    idx = getattr(bridge, "active_idx", 0)
    if isinstance(idx, int) and 0 <= idx < len(all_pages) and not _is_page_closed(all_pages[idx]):
        return True
    for i, p in enumerate(all_pages):
        if not _is_page_closed(p):
            bridge.active_idx = i
            return True
    return False


def _read_page_snapshot(ctx: Any, active_idx: int) -> tuple[str, str]:
    try:
        pages = list(getattr(ctx, "pages", None) or [])
    except Exception:
        return "", ""
    if not pages:
        return "", ""
    idx = active_idx if 0 <= active_idx < len(pages) else 0
    page = pages[idx]
    if _is_page_closed(page):
        return "", ""
    url = ""
    title = ""
    try:
        url = str(getattr(page, "url", "") or "")
    except Exception:
        url = ""
    try:
        title_fn = getattr(page, "title", None)
        title = str(title_fn() if callable(title_fn) else "")
    except Exception:
        title = ""
    return url, title


def run_cdp_live_bridge(
    cdp_url: str,
    *,
    mode: str = "wait_human",
    reason: str = "请在实时面板完成操作后点击【▶️ 交还给 AI】",
    timeout: float | None = None,
    url: str | None = None,
    bot: str | None = None,
    user_id: int | str | None = None,
    notify: bool | None = None,
    profile: str | None = None,
    profile_dir: str | Path | None = None,
    allow_google: bool = False,
    connect_timeout_ms: int = 15000,
    active_tick_seconds: float = ACTIVE_TAKEOVER_TICK_SECONDS,
    watch_idle_tick_seconds: float = WATCH_IDLE_TICK_SECONDS,
    http_session: requests.Session | None = None,
    connect_fn: Callable[[str, int], tuple[Any, Any]] | None = None,
    bridge_factory: Callable[..., Any] | None = None,
    clock_fn: Callable[[], float] | None = None,
    sleep_fn: Callable[[float], None] | None = None,
    install_signals: bool = True,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Attach a loopback CDP browser to Live Browser Hub and drive frame sync + human takeover.

    Raises `ValueError` immediately (0 HTTP / 0 CDP calls) for invalid loopback URLs,
    invalid timeouts, invalid navigation URLs, invalid explicit user IDs, or cross-bot
    overrides inside an active Telegram bridge turn.
    """
    if mode not in ("wait_human", "watch"):
        raise ValueError(f"Unsupported mode {mode!r}; expected 'wait_human' or 'watch'")
    if not isinstance(allow_google, bool):
        raise ValueError("allow_google must be a boolean")

    timeout_s: float | None
    if mode == "wait_human":
        timeout_s = validate_timeout(
            DEFAULT_WAIT_TIMEOUT_SECONDS if timeout is None else timeout,
            default=DEFAULT_WAIT_TIMEOUT_SECONDS,
        )
    else:
        timeout_s = validate_timeout(timeout) if timeout is not None else None

    # Pure local pre-flight validations BEFORE any network, Hub HTTP, or CDP calls.
    parse_loopback_cdp_url(cdp_url, allow_http=True)
    nav_url = validate_navigation_url(url) if url is not None else None
    resolved_bot = ctl.resolve_bot_target(bot, env=env)
    if user_id is not None:
        ctl.resolve_tg_identity(explicit_user_id=user_id, env=env)

    active_tick = validate_timeout(active_tick_seconds, default=ACTIVE_TAKEOVER_TICK_SECONDS)
    watch_tick = min(
        validate_timeout(watch_idle_tick_seconds, default=WATCH_IDLE_TICK_SECONDS),
        MAX_HEARTBEAT_INTERVAL_SECONDS,
    )
    active_tick = min(active_tick, MAX_HEARTBEAT_INTERVAL_SECONDS)

    # Resolve loopback CDP ws:// endpoint (no proxy, no redirect, same host+port re-check).
    ws_url = resolve_cdp_ws_url(cdp_url, session=http_session)

    clock = time.monotonic if clock_fn is None else clock_fn
    sleeper = time.sleep if sleep_fn is None else sleep_fn

    stop_state: dict[str, Any] = {"signal": None}
    prev_handlers: dict[int, Any] = {}
    can_install_sig = install_signals and threading.current_thread() is threading.main_thread()

    def _on_signal(signum: int, _frame: Any) -> None:
        stop_state["signal"] = signum

    if can_install_sig:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                prev_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, _on_signal)
            except Exception:
                pass

    pw_obj: Any = None
    browser: Any = None
    bridge: Any = None
    ctx: Any = None
    self_held_takeover: tuple[int, int] | None = None
    remote_dead = False
    skip_final_checkpoint = False
    exit_reason = "completed"
    frames_pushed = 0
    consecutive_shot_errors = 0

    try:
        connector = _default_connect_over_cdp if connect_fn is None else connect_fn
        pw_obj, browser = connector(ws_url, connect_timeout_ms)

        ctx, first_page, err_code = _select_context_and_page(browser)
        if err_code is not None or ctx is None or first_page is None:
            remote_dead = True
            exit_reason = err_code or "no_open_page"
            return {
                "ok": False,
                "mode": mode,
                "reason": exit_reason,
                "frames_pushed": 0,
                "error": f"Remote CDP browser unavailable ({exit_reason})",
            }

        factory = ctl.SyncLiveBridge if bridge_factory is None else bridge_factory
        bridge = factory(
            ctx,
            bot_hint=resolved_bot,
            notify=notify,
            user_id=user_id,
            profile_dir=profile_dir,
            pinned_launch=False,
            allow_google=bool(allow_google),
            profile_name=profile,
        )

        if not getattr(bridge, "enabled", False):
            skip_final_checkpoint = True
            exit_reason = "sync_start_rejected"
            return {
                "ok": False,
                "mode": mode,
                "reason": exit_reason,
                "status_code": getattr(bridge, "last_status_code", None),
                "frames_pushed": 0,
                "error": getattr(bridge, "last_error", None) or "Live Browser sync session rejected",
            }

        if nav_url is not None:
            is_google_blocked = getattr(bridge, "_is_sync_google_nav_blocked", None)
            blocked_by_bridge = bool(callable(is_google_blocked) and is_google_blocked(nav_url))
            if not blocked_by_bridge and allow_google and not getattr(bridge, "_allow_google_verified", False):
                # Explicit --allow-google was NOT verified by Hub: fail closed for Google destinations even if
                # client process does not carry server-side pinned env switches.
                try:
                    srv_mod = ctl._import_server_module()
                    blocked_by_bridge = bool(srv_mod.is_google_destination_url(nav_url))
                except Exception:
                    blocked_by_bridge = _is_google_destination_url_fallback(nav_url)
            if blocked_by_bridge:
                skip_final_checkpoint = True
                exit_reason = "google_nav_blocked"
                return {
                    "ok": False,
                    "mode": mode,
                    "reason": exit_reason,
                    "frames_pushed": 0,
                    "error": "外部 CDP 会话未获 Google 域白名单授权，已拒绝打开目标 Google 页面",
                }
            try:
                first_page.goto(nav_url, wait_until="domcontentloaded", timeout=45000)
            except Exception as exc:
                skip_final_checkpoint = True
                if _is_fatal_cdp_error(type(exc).__name__, str(exc)):
                    remote_dead = True
                exit_reason = "navigation_failed"
                return {
                    "ok": False,
                    "mode": mode,
                    "reason": exit_reason,
                    "frames_pushed": 0,
                    "error": f"打开初始页面失败: {exc}",
                }

        # Push initial frame before requesting takeover / entering watch loop.
        init_status = reason if mode == "wait_human" else "已接入外部 CDP 实时镜像"
        bridge.sync_checkpoint(ai_status=init_status, allow_takeover_loop=False)
        if getattr(bridge, "last_push_ok", False) is True and getattr(bridge, "last_error", None) is None:
            frames_pushed += 1

        if not getattr(bridge, "enabled", False):
            exit_reason = "lease_lost"
            return {
                "ok": False,
                "mode": mode,
                "reason": exit_reason,
                "status_code": getattr(bridge, "last_status_code", None),
                "frames_pushed": frames_pushed,
                "error": getattr(bridge, "last_error", None) or "Sync lease rejected or expired",
            }

        shot_err = getattr(bridge, "last_screenshot_error", None)
        shot_exc = getattr(bridge, "last_screenshot_exc_type", None)
        if shot_err:
            consecutive_shot_errors += 1
            if _is_fatal_cdp_error(shot_exc, shot_err):
                remote_dead = True
                exit_reason = "cdp_target_closed"
                return {
                    "ok": False,
                    "mode": mode,
                    "reason": exit_reason,
                    "frames_pushed": frames_pushed,
                    "error": shot_err,
                }

        if not _is_browser_connected(browser) or not _sync_active_idx_to_open_page(bridge, ctx):
            remote_dead = True
            exit_reason = "cdp_disconnected" if not _is_browser_connected(browser) else "no_open_page"
            return {
                "ok": False,
                "mode": mode,
                "reason": exit_reason,
                "frames_pushed": frames_pushed,
                "error": f"Remote CDP target lost ({exit_reason})",
            }

        if mode == "wait_human":
            cfg_kwargs: dict[str, Any] = {
                "takeover": True,
                "reason": reason,
                "ensure_card": bool(getattr(bridge, "notify", True)),
            }
            sync_sgen = getattr(bridge, "_sync_session_gen", None)
            if sync_sgen is not None:
                cfg_kwargs["expected_session_gen"] = sync_sgen
            try:
                cfg_res = bridge.client.update_config(**cfg_kwargs)
            except Exception as exc:
                exit_reason = "takeover_start_failed"
                return {
                    "ok": False,
                    "mode": mode,
                    "reason": exit_reason,
                    "frames_pushed": frames_pushed,
                    "error": f"Failed to activate human takeover: {exc}",
                }

            cfg_ok = isinstance(cfg_res, dict) and bool(cfg_res.get("ok"))
            card_sent_val = cfg_res.get("card_sent") if isinstance(cfg_res, dict) else None
            need_card = bool(getattr(bridge, "notify", True))
            if not cfg_ok or (need_card and card_sent_val is False):
                tk_sgen = ctl._parse_strict_int_no_ws((cfg_res or {}).get("session_gen"))
                if tk_sgen is None:
                    tk_sgen = ctl._parse_strict_int_no_ws(sync_sgen)
                tk_tgen = ctl._parse_strict_int_no_ws((cfg_res or {}).get("takeover_gen"))
                if (
                    isinstance(cfg_res, dict)
                    and cfg_res.get("takeover")
                    and tk_sgen is not None
                    and tk_tgen is not None
                ):
                    self_held_takeover = (tk_sgen, tk_tgen)
                err_text = (
                    (cfg_res or {}).get("error")
                    or (cfg_res or {}).get("card_error")
                    or "Failed to activate human takeover or deliver Live Card"
                )
                exit_reason = "card_send_failed" if card_sent_val is False else "takeover_start_failed"
                return {
                    "ok": False,
                    "mode": mode,
                    "reason": exit_reason,
                    "card_sent": False if card_sent_val is False else card_sent_val,
                    "frames_pushed": frames_pushed,
                    "error": str(err_text),
                }

            tk_sgen = ctl._parse_strict_int_no_ws(cfg_res.get("session_gen"))
            if tk_sgen is None:
                tk_sgen = ctl._parse_strict_int_no_ws(sync_sgen)
            tk_tgen = ctl._parse_strict_int_no_ws(cfg_res.get("takeover_gen"))
            if tk_tgen is None:
                tk_tgen = getattr(bridge, "last_takeover_gen", None)
            if tk_sgen is not None and tk_tgen is not None:
                self_held_takeover = (tk_sgen, tk_tgen)

        assert timeout_s is not None or mode == "watch"
        deadline = (clock() + timeout_s) if timeout_s is not None else None

        while True:
            if stop_state["signal"] is not None:
                exit_reason = "signal"
                final_url, final_title = _read_page_snapshot(ctx, getattr(bridge, "active_idx", 0))
                return {
                    "ok": mode == "watch",
                    "mode": mode,
                    "reason": exit_reason,
                    "signal": stop_state["signal"],
                    "frames_pushed": frames_pushed,
                    "url": final_url,
                    "title": final_title,
                    **({} if mode == "watch" else {"error": f"Interrupted by signal {stop_state['signal']}"}),
                }

            if deadline is not None and clock() >= deadline:
                exit_reason = "timeout"
                final_url, final_title = _read_page_snapshot(ctx, getattr(bridge, "active_idx", 0))
                return {
                    "ok": mode == "watch",
                    "mode": mode,
                    "reason": exit_reason,
                    "frames_pushed": frames_pushed,
                    "url": final_url,
                    "title": final_title,
                    **(
                        {}
                        if mode == "watch"
                        else {"error": f"Timed out waiting for human handback after {timeout_s:g}s"}
                    ),
                }

            if not _is_browser_connected(browser):
                remote_dead = True
                exit_reason = "cdp_disconnected"
                return {
                    "ok": False,
                    "mode": mode,
                    "reason": exit_reason,
                    "frames_pushed": frames_pushed,
                    "error": "Remote CDP browser disconnected",
                }

            if not _sync_active_idx_to_open_page(bridge, ctx):
                remote_dead = True
                exit_reason = "no_open_page"
                return {
                    "ok": False,
                    "mode": mode,
                    "reason": exit_reason,
                    "frames_pushed": frames_pushed,
                    "error": "All remote CDP browser pages were closed",
                }

            tick_status = (
                reason
                if (mode == "wait_human" or getattr(bridge, "last_takeover", False))
                else "外部 CDP 实时镜像中（可随时点击【一键接管】）"
            )
            bridge.sync_checkpoint(ai_status=tick_status, allow_takeover_loop=False)
            push_ok = (
                getattr(bridge, "last_push_ok", False) is True
                and getattr(bridge, "last_error", None) is None
            )
            if push_ok:
                frames_pushed += 1

            if not getattr(bridge, "enabled", False):
                exit_reason = "lease_lost"
                return {
                    "ok": False,
                    "mode": mode,
                    "reason": exit_reason,
                    "status_code": getattr(bridge, "last_status_code", None),
                    "frames_pushed": frames_pushed,
                    "error": getattr(bridge, "last_error", None) or "Sync lease rejected or expired",
                }

            shot_err = getattr(bridge, "last_screenshot_error", None)
            shot_exc = getattr(bridge, "last_screenshot_exc_type", None)
            if shot_err:
                consecutive_shot_errors += 1
                if (
                    _is_fatal_cdp_error(shot_exc, shot_err)
                    or consecutive_shot_errors >= MAX_CONSECUTIVE_SCREENSHOT_ERRORS
                ):
                    remote_dead = True
                    exit_reason = "cdp_target_closed"
                    return {
                        "ok": False,
                        "mode": mode,
                        "reason": exit_reason,
                        "frames_pushed": frames_pushed,
                        "error": shot_err,
                    }
            else:
                consecutive_shot_errors = 0

            if (
                mode == "wait_human"
                and push_ok
                and not getattr(bridge, "last_takeover", False)
            ):
                self_held_takeover = None
                exit_reason = "handback"
                final_url, final_title = _read_page_snapshot(ctx, getattr(bridge, "active_idx", 0))
                return {
                    "ok": True,
                    "mode": mode,
                    "reason": exit_reason,
                    "resumed": True,
                    "frames_pushed": frames_pushed,
                    "session_gen": getattr(bridge, "_sync_session_gen", None),
                    "takeover_gen": getattr(bridge, "last_takeover_gen", None),
                    "url": final_url,
                    "title": final_title,
                }

            if stop_state["signal"] is not None:
                continue

            step_delay = (
                active_tick
                if (mode == "wait_human" or getattr(bridge, "last_takeover", False))
                else watch_tick
            )
            if deadline is not None:
                remaining = deadline - clock()
                if remaining <= 0:
                    continue
                sleeper(min(step_delay, remaining))
            else:
                sleeper(step_delay)

    finally:
        # Strict CB3 teardown order:
        # 1. Release all held mouse buttons on their originating pages.
        if bridge is not None:
            rel_fn = getattr(bridge, "_release_held_buttons_sync", None)
            if callable(rel_fn):
                try:
                    rel_fn()
                except Exception:
                    pass

        # 2. Return self-held takeover using dual (expected_session_gen, expected_takeover_gen) CAS.
        if bridge is not None and getattr(bridge, "enabled", False) and self_held_takeover is not None:
            rel_sgen, rel_tgen = self_held_takeover
            try:
                bridge.client.update_config(
                    takeover=False,
                    reason=f"CDP 桥接退出（{exit_reason}），已自动清理接管状态",
                    expected_session_gen=rel_sgen,
                    expected_takeover_gen=rel_tgen,
                )
            except Exception:
                pass

        # 3. Close SyncLiveBridge (/internal/sync/stop with X-Sync-Lease-Id -> retire card & idle).
        if bridge is not None:
            try:
                bridge.close(skip_final_checkpoint=(remote_dead or skip_final_checkpoint))
            except TypeError:
                try:
                    bridge.close()
                except Exception:
                    pass
            except Exception:
                pass

        # 4. Non-destructive CDP client detach ONLY (NEVER call page.close() or context.close()).
        if browser is not None:
            close_browser = getattr(browser, "close", None)
            if callable(close_browser):
                try:
                    close_browser()
                except Exception:
                    pass
        if pw_obj is not None:
            stop_pw = getattr(pw_obj, "stop", None)
            if callable(stop_pw):
                try:
                    stop_pw()
                except Exception:
                    pass

        for sig, prev in prev_handlers.items():
            try:
                signal.signal(sig, prev)
            except Exception:
                pass
