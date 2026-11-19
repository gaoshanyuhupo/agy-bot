#!/usr/bin/env python3
"""AGY Live Browser Hub & Async Camoufox Daemon (Telegram Mini App + Live Card).

Provides:
1. Authenticated Telegram Mini App WebSocket server (8-12 FPS binary JPEG stream +
   bi-directional mouse/touch/keyboard/tab control + 3-state AI/Human takeover lock).
2. Hosted persistent AsyncCamoufox engine locked to the pinned browser profile
   (preserving all mandatory invariants: flock, os='windows', headless='virtual',
   humanize=True, direct egress network.proxy.type=0).
3. Localhost Cooperative Sync Provider bridge so legacy `with open_google_browser():`
   scripts also stream live to Telegram and support interactive human takeover.
4. Automatic in-chat Telegram Live Photo Card (`sendPhoto` + `editMessageMedia`) with
   an embedded Inline Keyboard `web_app` button.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import hmac
import html
import importlib.util
import inspect
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable
import urllib.parse

try:
    from aiohttp import FormData, MultipartReader, WSMsgType, web
except ImportError:
    FormData = None  # type: ignore[assignment]
    MultipartReader = None  # type: ignore[assignment]
    WSMsgType = None  # type: ignore[assignment]
    web = None  # type: ignore[assignment]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("live-browser")

CONFIG_DIR = Path(os.environ.get("AGY_LIVE_BROWSER_CONFIG_DIR", str(Path.home() / ".config/agy-live-browser")))
CONFIG_FILE = CONFIG_DIR / "config.json"
PROFILES_FILE = CONFIG_DIR / "profiles.json"
LOCAL_TOKEN_FILE = CONFIG_DIR / "local.token"
PROFILES_DATA_DIR = Path(
    os.environ.get("AGY_LIVE_BROWSER_PROFILES_DIR", str(Path.home() / ".local/share/camoufox-profiles"))
)
STATIC_DIR = Path(__file__).resolve().parent / "static"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18795
IDLE_AUTOCLOSE_SECONDS = 900.0  # Auto-release profile lock after 15m idle

PINNED_FINGERPRINT_DEFAULTS: dict[str, Any] = {
    "headless": "virtual",
    "os": "windows",
    "humanize": True,
    "i_know_what_im_doing": True,
}
ALLOWED_OS_VALUES = ("windows", "macos", "linux")
ALLOWED_PROXY_SCHEMES = ("http", "https", "socks4", "socks5", "socks5h")
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PROXY_ENV_KEYS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
    "SOCKS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "ftp_proxy",
    "socks_proxy",
    "no_proxy",
)
PINNED_FORBIDDEN_OVERRIDES = frozenset(
    {
        "proxy",
        "proxy_bao_ref",
        "os",
        "locale",
        "window",
        "mobile",
        "webgl_config",
        "block_webrtc",
        "geoip",
        "headless",
        "user_data_dir",
        "persistent_context",
        "persistent",
        "ephemeral",
    }
)

MOBILE_WINDOW_PRESET: list[int] = [430, 932]
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MiB max total file payload per upload
MAX_UPLOAD_META_BYTES = 64 * 1024  # 64 KiB max non-file multipart overhead
MAX_UPLOAD_TOTAL_BYTES = MAX_UPLOAD_BYTES + MAX_UPLOAD_META_BYTES
MAX_UPLOAD_TOTAL_REQUEST_BYTES = MAX_UPLOAD_TOTAL_BYTES  # Decoded HTTP multipart request body byte budget (25 MiB files + 64 KiB overhead, drained to EOF)
MAX_UPLOAD_NONFILE_FIELD_BYTES = 8 * 1024  # 8 KiB per non-file multipart field
MAX_UPLOAD_NONFILE_TOTAL_BYTES = 32 * 1024  # 32 KiB combined non-file fields budget
MAX_UPLOAD_FILES = 10
MAX_UPLOAD_PARTS = 16
MAX_UPLOAD_CONCURRENCY = 2
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MiB max cached download size
MAX_TG_DOWNLOAD_BYTES = 20 * 1024 * 1024  # 20 MiB auto-push to TG DM
TRANSFER_TTL_SECONDS = 1800.0  # 30 minutes temp file retention
DIALOG_TIMEOUT_SECONDS = 120.0
SYNC_CMD_QUEUE_MAX = 200
SYNC_LEASE_TIMEOUT_SECONDS = 120.0
WS_CLOSE_AUTH_FORBIDDEN = 4003
_SYNC_EXTRACT_ALLOWED_MODES = frozenset({"point", "page", "url", "selection", "range", "range_preview"})

_GOOGLE_HOST_RE = re.compile(
    r"^(?:[a-z0-9-]+\.)*(?:"
    r"google\.[a-z]{2,3}(?:\.[a-z]{2})?|"
    r"gmail\.com|googlemail\.com|"
    r"youtube\.com|youtu\.be|"
    r"googleapis\.com|googleusercontent\.com|gstatic\.com|googlevideo\.com|withgoogle\.com|"
    r"g\.co|goo\.gl"
    r")$"
)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

QUALITY_PRESETS: dict[str, dict[str, Any]] = {
    "smooth": {
        "stream_quality": 46,
        "hd_quality": 76,
        "active_interval": 0.07,
        "idle_intervals": (0.22, 0.40, 0.55),
    },
    "balanced": {
        "stream_quality": 58,
        "hd_quality": 84,
        "active_interval": 0.085,
        "idle_intervals": (0.25, 0.42, 0.55),
    },
    "hd": {
        "stream_quality": 74,
        "hd_quality": 92,
        "active_interval": 0.10,
        "idle_intervals": (0.28, 0.45, 0.60),
    },
}

_BRIDGE_DIR = Path(os.environ.get("AGY_TG_BRIDGE_DIR", str(Path.home() / "agy-tg-bridge")))
_IGNORED_ENV_SUFFIXES = (
    ".bak",
    ".tmp",
    ".example",
    ".sample",
    ".orig",
    ".old",
    ".swp",
    ".dist",
    ".disabled",
)
_IGNORED_ENV_KEYS = frozenset(s.lstrip(".") for s in _IGNORED_ENV_SUFFIXES)
_ENV_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
BRIDGE_ENV_FILES = {
    "main": _BRIDGE_DIR / ".env",
    "sg": _BRIDGE_DIR / ".env.sg",
}


def discover_bridge_env_files(bridge_dir: Path | None = None) -> dict[str, Path]:
    """Discover `.env` (`main`) and all runtime `.env.<name>` files under bridge directory."""
    target_dir = bridge_dir or _BRIDGE_DIR
    found: dict[str, Path] = {}
    if not target_dir.is_dir():
        return found

    main_env = target_dir / ".env"
    if main_env.is_file():
        found["main"] = main_env

    try:
        entries = sorted(target_dir.iterdir(), key=lambda p: p.name)
    except OSError:
        return found

    for entry in entries:
        if not entry.is_file():
            continue
        name = entry.name
        if not name.startswith(".env.") or name == ".env":
            continue
        low = name.lower()
        if any(low.endswith(sfx) for sfx in _IGNORED_ENV_SUFFIXES):
            continue
        key = name[5:]
        if not key or "." in key or key.lower() in _IGNORED_ENV_KEYS:
            continue
        if not _ENV_KEY_RE.match(key):
            continue
        found[key] = entry
    return found


def _parse_env_bool(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in ("1", "true", "yes", "on")


def _get_google_skill_scripts_dir() -> Path:
    raw = os.environ.get("AGY_GOOGLE_SKILL_SCRIPTS")
    if raw is not None:
        return Path(raw) if raw.strip() else Path("/nonexistent-google-skill-dir")
    return Path.home() / "agy-workspace/.agents/skills/google-profile/scripts"


def _is_pinned_host_required() -> tuple[bool, Path | None]:
    """Return `(required, scripts_dir)` determining if host pinned profile must fail closed."""
    explicit_require = _parse_env_bool(os.environ.get("AGY_LIVE_BROWSER_REQUIRE_PINNED"))
    raw = os.environ.get("AGY_GOOGLE_SKILL_SCRIPTS")
    if raw is not None:
        stripped = raw.strip()
        if not stripped:
            if explicit_require:
                return True, Path("/nonexistent-google-skill-dir")
            return False, None
        scripts_dir = Path(stripped)
        skill_root_present = scripts_dir.is_dir() or (
            scripts_dir.parent.name == "google-profile" and scripts_dir.parent.is_dir()
        )
        return (explicit_require or skill_root_present), scripts_dir

    scripts_dir = Path.home() / "agy-workspace/.agents/skills/google-profile/scripts"
    skill_root_present = scripts_dir.is_dir() or scripts_dir.parent.is_dir()
    return (explicit_require or skill_root_present), scripts_dir


def _import_google_browser() -> Any | None:
    """Load host-specific `google_browser` module; fail closed on private hosts if broken/missing."""
    required, scripts_dir = _is_pinned_host_required()
    if scripts_dir is None:
        return None
    mod_path = scripts_dir / "google_browser.py"
    if not mod_path.is_file():
        if required:
            raise RuntimeError(
                f"Host requires pinned google-profile module, but {mod_path} is missing (fail-closed)."
            )
        return None
    existing = sys.modules.get("google_browser")
    if existing is not None:
        existing_file = getattr(existing, "__file__", None)
        if existing_file and Path(existing_file).resolve() == mod_path.resolve():
            return existing
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    spec = importlib.util.spec_from_file_location("google_browser", mod_path)
    if spec is None or spec.loader is None:
        if required:
            raise RuntimeError(f"Failed to construct module spec for pinned {mod_path} (fail-closed).")
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        if required:
            raise RuntimeError(f"Failed importing pinned google_browser module {mod_path}: {exc}") from exc
        return None
    return mod


def discover_pinned_host_profile() -> dict[str, Any] | None:
    """Discover a host-pinned persistent profile if `google_browser` is installed (fail-closed on private hosts)."""
    required, _ = _is_pinned_host_required()
    gb = _import_google_browser()
    if gb is None:
        if required:
            raise RuntimeError("Pinned google-profile module is required on this host but unavailable (fail-closed).")
        return None
    profile_dir = getattr(gb, "PROFILE_DIR", None)
    lock_path = getattr(gb, "LOCK_PATH", None)
    if not profile_dir or not lock_path:
        if required:
            raise RuntimeError("Pinned google_browser module missing PROFILE_DIR or LOCK_PATH (fail-closed).")
        return None
    p_dir = Path(profile_dir)
    fp = dict(getattr(gb, "PINNED_FINGERPRINT", PINNED_FINGERPRINT_DEFAULTS))
    return {
        "name": p_dir.name,
        "profile_dir": p_dir,
        "lock_path": Path(lock_path),
        "pinned": True,
        "fingerprint": fp,
        "direct_env_fn": getattr(gb, "_direct_env", None),
    }


def is_google_destination_url(url: str | None) -> bool:
    """Return True if URL targets a Google / Gmail / YouTube domain."""
    raw = str(url or "").strip()
    if not raw:
        return False
    if "://" not in raw and not raw.lower().startswith(("about:", "data:", "javascript:", "blob:")):
        raw = "https://" + raw
    try:
        parsed = urllib.parse.urlparse(raw)
    except Exception:
        return False
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return False
    return bool(_GOOGLE_HOST_RE.match(host))


def enforce_google_profile_policy(
    url: str | None,
    *,
    is_pinned: bool,
    profile_dir: Path | None = None,
    host_has_pinned: bool | None = None,
) -> None:
    """Fail-closed guard: disallow non-pinned (or unverified pinned) profiles from Google domains on pinned hosts.

    Never trusts a bare `is_pinned=True` boolean without a matching canonical host pinned directory.
    """
    if not url:
        return
    host_pinned = discover_pinned_host_profile()
    has_pinned = (host_pinned is not None) if host_has_pinned is None else bool(host_has_pinned)
    if not has_pinned:
        return
    effective_pinned = False
    if is_pinned and profile_dir is not None and host_pinned is not None:
        try:
            p_resolved = Path(profile_dir).resolve()
            h_resolved = Path(host_pinned["profile_dir"]).resolve()
            effective_pinned = (p_resolved == h_resolved) and p_resolved.is_dir()
        except OSError:
            effective_pinned = False
    if not effective_pinned and is_google_destination_url(url):
        raise ValueError(
            "安全策略拦截：此主机已锁定 Pinned Google Profile，禁止非 Pinned Profile 访问 Google/Gmail/YouTube 域。"
        )


def _sanitize_filename(raw_name: str | None, fallback: str = "file.bin") -> str:
    """Sanitize a filename while preserving readable Unicode characters and blocking path/control injection."""
    base = Path(str(raw_name or "")).name
    cleaned = _CONTROL_CHAR_RE.sub("", base).replace("/", "_").replace("\\", "_").strip()
    if not cleaned or cleaned in (".", ".."):
        return fallback
    return cleaned[:180]


def _format_content_disposition(filename: str) -> str:
    """Build RFC 5987 safe attachment Content-Disposition header stripping control characters."""
    clean = _sanitize_filename(filename, fallback="download.bin")
    ascii_chars = [
        ch if (32 <= ord(ch) < 127 and ch not in ('"', "\\", ";")) else "_"
        for ch in clean
    ]
    ascii_fallback = "".join(ascii_chars).strip(" .") or "download.bin"
    utf8_encoded = urllib.parse.quote(clean, safe="")
    return f'attachment; filename="{ascii_fallback}"; filename*=UTF-8\'\'{utf8_encoded}'


def _clean_proxy_env(base_env: dict[str, str] | None = None, *, direct: bool = True) -> dict[str, str]:
    """Return an environment dict stripped of proxy variables (enforcing direct egress when direct=True)."""
    cleaned = dict(os.environ if base_env is None else base_env)
    for key in PROXY_ENV_KEYS:
        cleaned.pop(key, None)
    if direct:
        cleaned["NO_PROXY"] = "*"
        cleaned["no_proxy"] = "*"
    return cleaned


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _clean_stale_firefox_locks(profile_dir: Path) -> None:
    """Remove stale Firefox lock symlinks inside `profile_dir` after external flock is held."""
    lock_link = profile_dir / "lock"
    if lock_link.is_symlink():
        try:
            target = os.readlink(lock_link)
        except OSError:
            return
        pid_part = target.rsplit("+", 1)[-1] if "+" in target else ""
        if pid_part.isdigit() and not _pid_alive(int(pid_part)):
            lock_link.unlink(missing_ok=True)
            (profile_dir / ".parentlock").unlink(missing_ok=True)


def validate_profile_name(name: str) -> str:
    """Validate named profile identifier (blocks traversal, slashes, whitespace, '..')."""
    if not isinstance(name, str):
        raise ValueError("Profile name must be a string")
    if not name or ".." in name or not PROFILE_NAME_RE.match(name):
        raise ValueError(
            f"Invalid profile name {name!r}: must match ^[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}$ without '..'"
        )
    return name


def parse_proxy_url(raw_url: str) -> dict[str, str]:
    """Parse a proxy URL into Playwright proxy dict `{server, username?, password?}`."""
    text = str(raw_url or "").strip()
    if "://" not in text:
        raise ValueError("Proxy URL must include scheme (e.g. socks5://proxy.example.com:1080)")
    parsed = urllib.parse.urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_PROXY_SCHEMES:
        raise ValueError(f"Unsupported proxy scheme {scheme!r}; allowed: {', '.join(ALLOWED_PROXY_SCHEMES)}")
    if not parsed.hostname:
        raise ValueError("Proxy URL missing hostname")
    host_part = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    port_part = f":{parsed.port}" if parsed.port else ""
    out: dict[str, str] = {"server": f"{scheme}://{host_part}{port_part}"}
    if parsed.username is not None:
        out["username"] = urllib.parse.unquote(parsed.username)
    if parsed.password is not None:
        out["password"] = urllib.parse.unquote(parsed.password)
    return out


def normalize_proxy_config(proxy: dict[str, Any] | str | None) -> dict[str, str] | None:
    """Normalize proxy string or dict into `{server, username?, password?}`."""
    if proxy is None or proxy == "" or proxy == {}:
        return None
    if isinstance(proxy, str):
        return parse_proxy_url(proxy)
    if isinstance(proxy, dict):
        raw_server = str(proxy.get("server") or "").strip()
        if not raw_server:
            raise ValueError("Proxy config dict must contain non-empty 'server'")
        out = parse_proxy_url(raw_server)
        if proxy.get("username") is not None and str(proxy["username"]) != "":
            out["username"] = str(proxy["username"])
        if proxy.get("password") is not None and str(proxy["password"]) != "":
            out["password"] = str(proxy["password"])
        return out
    raise ValueError("Proxy config must be a URL string or dict")


def mask_proxy_display(proxy: dict[str, Any] | str | None, *, bao_ref: str | None = None) -> str:
    """Return a credential-free display string for proxy egress (e.g. `socks5://***@example.com:1080`)."""
    if proxy is None or proxy == "" or proxy == {}:
        return f"bao:{bao_ref}" if bao_ref else "direct"
    try:
        norm = normalize_proxy_config(proxy)
    except Exception:
        return "proxy:invalid"
    if not norm:
        return f"bao:{bao_ref}" if bao_ref else "direct"
    parsed = urllib.parse.urlparse(norm["server"])
    host_part = f"[{parsed.hostname}]" if parsed.hostname and ":" in parsed.hostname else (parsed.hostname or "")
    port_part = f":{parsed.port}" if parsed.port else ""
    has_auth = bool(norm.get("username") or norm.get("password"))
    if has_auth:
        return f"{parsed.scheme}://***@{host_part}{port_part}"
    return f"{parsed.scheme}://{host_part}{port_part}"


def resolve_proxy_bao_ref(bao_ref: str) -> dict[str, str]:
    """Fetch proxy config in memory from OpenBao (`path` or `path#field`) without persisting secrets."""
    ref = str(bao_ref or "").strip()
    if not ref or any(ch.isspace() for ch in ref):
        raise ValueError(f"Invalid proxy_bao_ref: {bao_ref!r}")
    if "#" in ref:
        secret_path, field = ref.split("#", 1)
        secret_path = secret_path.strip()
        field = field.strip()
        if not secret_path or not field:
            raise ValueError(f"Invalid proxy_bao_ref syntax: {bao_ref!r}")
    else:
        secret_path, field = ref, None

    bao_bin = shutil.which("bao")
    if not bao_bin:
        candidate = Path.home() / ".local/bin/bao"
        bao_bin = str(candidate) if candidate.is_file() else "bao"

    cmd = [bao_bin, "get", secret_path]
    if field:
        cmd.extend(["--field", field])

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"Failed to resolve proxy secret from OpenBao ref '{ref}' (exit {proc.returncode})")

    raw = (proc.stdout or "").strip()
    if not raw:
        raise RuntimeError(f"OpenBao ref '{ref}' returned empty proxy value")

    if raw.startswith("{"):
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError(f"OpenBao ref '{ref}' JSON payload must be an object")
        if "server" in payload:
            res = normalize_proxy_config(payload)
        elif "url" in payload:
            res = normalize_proxy_config(str(payload["url"]))
        elif "proxy" in payload:
            res = normalize_proxy_config(payload["proxy"])
        else:
            raise ValueError(f"OpenBao ref '{ref}' JSON missing 'server'/'url'/'proxy'")
        if not res:
            raise ValueError(f"OpenBao ref '{ref}' resolved to empty proxy")
        return res

    return parse_proxy_url(raw)


def _normalize_window(val: Any) -> list[int]:
    if isinstance(val, str):
        parts = re.split(r"[xX,]", val.strip())
    elif isinstance(val, (list, tuple)):
        parts = list(val)
    else:
        raise ValueError("window must be [width, height] or 'WxH'")
    if len(parts) != 2:
        raise ValueError("window must contain exactly width and height")
    try:
        w, h = int(parts[0]), int(parts[1])
    except (TypeError, ValueError) as exc:
        raise ValueError("window dimensions must be integers") from exc
    if not (320 <= w <= 7680 and 240 <= h <= 4320):
        raise ValueError(f"window dimensions out of range: {w}x{h}")
    return [w, h]


def _normalize_webgl(val: Any) -> list[str]:
    if isinstance(val, str):
        parts = [p.strip() for p in val.split(",", 1)]
    elif isinstance(val, (list, tuple)):
        parts = [str(p).strip() for p in val]
    else:
        raise ValueError("webgl_config must be [vendor, renderer] or 'VENDOR,RENDERER'")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("webgl_config must contain non-empty vendor and renderer")
    return parts


def _normalize_geoip(val: Any) -> bool | str:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        s = val.strip()
        low = s.lower()
        if low in ("true", "1", "yes"):
            return True
        if low in ("false", "0", "no"):
            return False
        if s:
            return s
    raise ValueError("geoip must be a boolean or IP string")


def validate_profile_payload(data: dict[str, Any], *, allow_pinned: bool = False) -> dict[str, Any]:
    """Validate and normalize a profile configuration dictionary."""
    if not isinstance(data, dict):
        raise ValueError("Profile config must be a JSON object")

    pinned = bool(data.get("pinned", False))
    if pinned and not allow_pinned:
        raise ValueError(
            "Cannot set pinned=True on a user-configured profile; pinned identity is strictly derived from host google-profile."
        )
    os_val = data.get("os")
    if os_val is not None:
        os_val = str(os_val).strip().lower()
        if os_val not in ALLOWED_OS_VALUES:
            raise ValueError(f"Unsupported os {os_val!r}; allowed: {', '.join(ALLOWED_OS_VALUES)}")

    locale_val = data.get("locale")
    if locale_val is not None:
        locale_val = str(locale_val).strip()
        if not locale_val:
            locale_val = None

    window_val = _normalize_window(data["window"]) if data.get("window") is not None else None
    mobile_val = bool(data.get("mobile", False))
    webgl_val = _normalize_webgl(data["webgl_config"]) if data.get("webgl_config") is not None else None
    block_webrtc_val = bool(data["block_webrtc"]) if data.get("block_webrtc") is not None else None
    geoip_val = _normalize_geoip(data["geoip"]) if data.get("geoip") is not None else None

    persistent_val = True if data.get("persistent") is None else bool(data["persistent"])
    if data.get("ephemeral"):
        persistent_val = False

    proxy_val = normalize_proxy_config(data.get("proxy")) if data.get("proxy") is not None else None
    bao_ref_raw = data.get("proxy_bao_ref")
    bao_ref_val = str(bao_ref_raw).strip() if bao_ref_raw is not None and str(bao_ref_raw).strip() else None
    if bao_ref_val and any(ch.isspace() for ch in bao_ref_val):
        raise ValueError("proxy_bao_ref must not contain whitespace")
    if proxy_val and bao_ref_val:
        raise ValueError("Cannot specify both 'proxy' and 'proxy_bao_ref' on the same profile")

    if pinned:
        if proxy_val or bao_ref_val:
            raise ValueError("Pinned profile cannot configure proxy or proxy_bao_ref")
        if mobile_val or window_val is not None:
            raise ValueError("Pinned profile cannot configure mobile or custom window viewport")
        if not persistent_val:
            raise ValueError("Pinned profile must have persistent=True")
        if os_val is not None and os_val != "windows":
            raise ValueError("Pinned profile must use os='windows'")
        os_val = "windows"
    elif mobile_val and window_val is None:
        window_val = list(MOBILE_WINDOW_PRESET)

    out: dict[str, Any] = {
        "pinned": pinned,
        "os": os_val or "windows",
        "persistent": persistent_val,
    }
    if locale_val is not None:
        out["locale"] = locale_val
    if window_val is not None:
        out["window"] = window_val
    if mobile_val:
        out["mobile"] = True
    if webgl_val is not None:
        out["webgl_config"] = webgl_val
    if block_webrtc_val is not None:
        out["block_webrtc"] = block_webrtc_val
    if geoip_val is not None:
        out["geoip"] = geoip_val
    if proxy_val is not None:
        out["proxy"] = proxy_val
    if bao_ref_val is not None:
        out["proxy_bao_ref"] = bao_ref_val
    return out


def sanitize_profile_for_output(name: str, entry: dict[str, Any], *, active: bool = False, source: str = "configured") -> dict[str, Any]:
    """Return a safe public representation of a profile with proxy credentials masked."""
    proxy_raw = entry.get("proxy")
    bao_ref = entry.get("proxy_bao_ref")
    egress = mask_proxy_display(proxy_raw, bao_ref=bao_ref)
    out: dict[str, Any] = {
        "name": name,
        "pinned": bool(entry.get("pinned", False)),
        "os": entry.get("os") or "windows",
        "persistent": bool(entry.get("persistent", True)),
        "egress": egress,
        "egress_display": egress,
        "has_proxy": bool(proxy_raw or bao_ref),
        "bao_ref": bao_ref or None,
        "active": active,
        "source": source,
    }
    for key in ("locale", "window", "mobile", "webgl_config", "block_webrtc", "geoip", "proxy_bao_ref"):
        if key in entry and entry[key] is not None:
            out[key] = entry[key]
    if proxy_raw is not None:
        out["proxy_masked"] = egress
    return out


def load_profiles(profiles_file: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load named profile definitions from `profiles.json`."""
    target = profiles_file or PROFILES_FILE
    if not target.is_file():
        return {}
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Failed reading %s: %s", target, exc)
        return {}
    if not isinstance(raw, dict):
        return {}
    if isinstance(raw.get("profiles"), dict):
        return dict(raw["profiles"])
    return {k: v for k, v in raw.items() if isinstance(v, dict)}


def save_profiles(profiles: dict[str, dict[str, Any]], profiles_file: Path | None = None) -> None:
    """Persist named profiles to `profiles.json` atomically with 0600 permissions."""
    target = profiles_file or PROFILES_FILE
    target.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(target.parent, 0o700)
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps({"profiles": profiles}, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(target)


def list_profiles(
    *,
    active_profile: str = "",
    profiles_file: Path | None = None,
) -> list[dict[str, Any]]:
    """List host-pinned (if present) and configured profiles with masked proxy credentials."""
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    host_pinned = discover_pinned_host_profile()
    if host_pinned is not None:
        p_name = host_pinned["name"]
        items.append(
            sanitize_profile_for_output(
                p_name,
                {"pinned": True, "os": "windows", "persistent": True},
                active=(active_profile == p_name),
                source="host_pinned",
            )
        )
        seen.add(p_name)

    configured = load_profiles(profiles_file=profiles_file)
    for name in sorted(configured.keys()):
        if name in seen or (host_pinned is not None and name == "default"):
            continue
        # Never allow user-configured entries in profiles.json to impersonate host-pinned identity
        sanitized_entry = dict(configured[name])
        sanitized_entry["pinned"] = False
        items.append(
            sanitize_profile_for_output(
                name,
                sanitized_entry,
                active=(active_profile == name),
                source="configured",
            )
        )
        seen.add(name)

    if host_pinned is None and "default" not in seen:
        items.insert(
            0,
            sanitize_profile_for_output(
                "default",
                {"pinned": False, "os": "windows", "persistent": True},
                active=(active_profile == "default"),
                source="builtin_default",
            ),
        )
    return items


def create_profile(
    name: str,
    config: dict[str, Any],
    *,
    overwrite: bool = False,
    profiles_file: Path | None = None,
) -> dict[str, Any]:
    """Create (or optionally update) a named browser profile in `profiles.json`."""
    clean_name = validate_profile_name(name)
    host_pinned = discover_pinned_host_profile()
    if host_pinned is not None and clean_name in ("default", host_pinned["name"]):
        raise ValueError(f"Cannot create or overwrite host-pinned profile '{clean_name}'")

    profiles = load_profiles(profiles_file=profiles_file)
    if clean_name in profiles and not overwrite:
        raise ValueError(f"Profile '{clean_name}' already exists")

    validated = validate_profile_payload(config)
    profiles[clean_name] = validated
    save_profiles(profiles, profiles_file=profiles_file)
    return sanitize_profile_for_output(clean_name, validated, active=False, source="configured")


def delete_profile(
    name: str,
    *,
    active_profile: str = "",
    profiles_file: Path | None = None,
) -> dict[str, Any]:
    """Delete a non-pinned, non-running named profile from `profiles.json`."""
    clean_name = validate_profile_name(name)
    host_pinned = discover_pinned_host_profile()
    if host_pinned is not None and clean_name in ("default", host_pinned["name"]):
        raise ValueError(f"Cannot delete host-pinned profile '{clean_name}'")

    profiles = load_profiles(profiles_file=profiles_file)
    if clean_name not in profiles:
        raise KeyError(f"Profile '{clean_name}' not found")
    if profiles[clean_name].get("pinned"):
        raise ValueError(f"Cannot delete pinned profile '{clean_name}'")
    if active_profile and active_profile == clean_name:
        raise RuntimeError(f"Cannot delete running profile '{clean_name}'; stop browser first")

    del profiles[clean_name]
    save_profiles(profiles, profiles_file=profiles_file)
    return {"ok": True, "deleted": clean_name}


def _check_pinned_overrides(profile_name: str, overrides: dict[str, Any] | None) -> None:
    if not overrides:
        return
    bad: list[str] = []
    for key in PINNED_FORBIDDEN_OVERRIDES:
        if key not in overrides:
            continue
        val = overrides[key]
        if key in ("ephemeral", "mobile"):
            if val:
                bad.append(key)
        elif key == "persistent":
            if val is not None:
                bad.append(key)
        elif val is not None:
            bad.append(key)
    custom_env = overrides.get("env")
    if isinstance(custom_env, dict):
        for env_key in PROXY_ENV_KEYS:
            if env_key in custom_env:
                if env_key.lower() == "no_proxy" and custom_env[env_key] == "*":
                    continue
                if custom_env[env_key]:
                    bad.append(f"env:{env_key}")
    custom_prefs = overrides.get("firefox_user_prefs")
    if isinstance(custom_prefs, dict) and "network.proxy.type" in custom_prefs:
        if custom_prefs["network.proxy.type"] != 0:
            bad.append("firefox_user_prefs:network.proxy.type")
    if bad:
        raise ValueError(
            f"Pinned profile '{profile_name}' forbids overrides: {', '.join(sorted(set(bad)))}"
        )


def resolve_launch_spec(
    profile_name: str | None = None,
    overrides: dict[str, Any] | None = None,
    *,
    profiles_file: Path | None = None,
    profiles_data_dir: Path | None = None,
) -> dict[str, Any]:
    """Resolve a profile name + optional overrides into a validated launch specification."""
    req_name = (profile_name or "").strip()
    data_dir = profiles_data_dir or PROFILES_DATA_DIR
    host_pinned = discover_pinned_host_profile()

    if host_pinned is not None and (not req_name or req_name in ("default", host_pinned["name"])):
        p_name = host_pinned["name"]
        _check_pinned_overrides(p_name, overrides)
        return {
            "name": p_name,
            "pinned": True,
            "pinned_verified": True,
            "persistent": True,
            "profile_dir": Path(host_pinned["profile_dir"]),
            "lock_path": Path(host_pinned["lock_path"]),
            "os": str(host_pinned["fingerprint"].get("os", "windows")),
            "fingerprint": dict(host_pinned["fingerprint"]),
            "direct_env_fn": host_pinned.get("direct_env_fn"),
            "proxy": None,
            "proxy_bao_ref": None,
            "locale": None,
            "window": None,
            "webgl_config": None,
            "block_webrtc": None,
            "geoip": None,
        }

    target_name = validate_profile_name(req_name or "default")
    configured = load_profiles(profiles_file=profiles_file)
    if target_name in configured:
        entry = dict(configured[target_name])
    elif target_name == "default":
        entry = {"pinned": False, "os": "windows", "persistent": True}
    else:
        raise KeyError(
            f"Profile '{target_name}' not found. Create it with `live-browser profile create {target_name}`."
        )

    # Strip any forged `pinned: true` from user-configured profiles.json entries
    if entry.get("pinned"):
        log.warning("Stripping forged pinned=True on configured profile '%s'", target_name)
        entry["pinned"] = False

    ov = overrides or {}
    merged: dict[str, Any] = dict(entry)
    merged["pinned"] = False
    for field in ("os", "locale", "window", "webgl_config", "block_webrtc", "geoip", "persistent"):
        if ov.get(field) is not None:
            merged[field] = ov[field]
    if ov.get("mobile"):
        merged["mobile"] = True
        if ov.get("window") is None and not merged.get("window"):
            merged["window"] = list(MOBILE_WINDOW_PRESET)
    if ov.get("ephemeral"):
        merged["persistent"] = False

    if ov.get("proxy") is not None:
        merged["proxy"] = ov["proxy"]
        merged.pop("proxy_bao_ref", None)
    elif ov.get("proxy_bao_ref") is not None and str(ov["proxy_bao_ref"]).strip():
        merged["proxy_bao_ref"] = str(ov["proxy_bao_ref"]).strip()
        merged.pop("proxy", None)

    validated = validate_profile_payload(merged, allow_pinned=False)
    return {
        "name": target_name,
        "pinned": False,
        "pinned_verified": False,
        "persistent": bool(validated["persistent"]),
        "profile_dir": data_dir / target_name,
        "lock_path": data_dir / f"{target_name}.lock",
        "os": validated["os"],
        "fingerprint": {
            "headless": "virtual",
            "os": validated["os"],
            "humanize": True,
            "i_know_what_im_doing": True,
        },
        "direct_env_fn": None,
        "proxy": validated.get("proxy"),
        "proxy_bao_ref": validated.get("proxy_bao_ref"),
        "locale": validated.get("locale"),
        "window": validated.get("window"),
        "mobile": bool(validated.get("mobile", False)),
        "webgl_config": validated.get("webgl_config"),
        "block_webrtc": validated.get("block_webrtc"),
        "geoip": validated.get("geoip"),
    }


def build_camoufox_kwargs(spec: dict[str, Any], user_data_dir: Path) -> tuple[dict[str, Any], str]:
    """Build `AsyncCamoufox` launch kwargs and masked egress summary from a launch spec."""
    if spec.get("pinned"):
        direct_fn = spec.get("direct_env_fn")
        env = direct_fn() if callable(direct_fn) else _clean_proxy_env(direct=True)
        kwargs: dict[str, Any] = {
            **PINNED_FINGERPRINT_DEFAULTS,
            **dict(spec.get("fingerprint") or {}),
            "headless": "virtual",
            "os": "windows",
            "humanize": True,
            "i_know_what_im_doing": True,
            "persistent_context": True,
            "user_data_dir": str(user_data_dir),
            "env": env,
            "firefox_user_prefs": {"network.proxy.type": 0},
        }
        return kwargs, "direct"

    proxy_dict: dict[str, str] | None = None
    bao_ref = spec.get("proxy_bao_ref")
    if spec.get("proxy") is not None:
        proxy_dict = normalize_proxy_config(spec["proxy"])
    elif bao_ref:
        proxy_dict = resolve_proxy_bao_ref(str(bao_ref))

    kwargs = {
        "headless": "virtual",
        "os": spec.get("os") or "windows",
        "humanize": True,
        "i_know_what_im_doing": True,
        "persistent_context": True,
        "user_data_dir": str(user_data_dir),
    }
    if spec.get("locale"):
        kwargs["locale"] = spec["locale"]
    if spec.get("window"):
        w, h = spec["window"]
        kwargs["window"] = (int(w), int(h))
    if spec.get("webgl_config"):
        vendor, renderer = spec["webgl_config"]
        kwargs["webgl_config"] = (str(vendor), str(renderer))
    if spec.get("block_webrtc") is not None:
        kwargs["block_webrtc"] = bool(spec["block_webrtc"])
    if spec.get("geoip") is not None:
        kwargs["geoip"] = spec["geoip"]

    if proxy_dict:
        kwargs["proxy"] = proxy_dict
        kwargs["env"] = _clean_proxy_env(direct=False)
        egress_summary = mask_proxy_display(proxy_dict)
    else:
        kwargs["env"] = _clean_proxy_env(direct=True)
        kwargs["firefox_user_prefs"] = {"network.proxy.type": 0}
        egress_summary = "direct"

    return kwargs, egress_summary


def ensure_local_config() -> tuple[dict[str, Any], str]:
    """Ensure local config directory and 0600 IPC token exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, 0o700)

    if not LOCAL_TOKEN_FILE.is_file():
        tok = secrets.token_hex(24)
        LOCAL_TOKEN_FILE.write_text(tok, encoding="utf-8")
        os.chmod(LOCAL_TOKEN_FILE, 0o600)
    else:
        tok = LOCAL_TOKEN_FILE.read_text(encoding="utf-8").strip()

    cfg: dict[str, Any] = {"host": DEFAULT_HOST, "port": DEFAULT_PORT, "public_url": ""}
    if CONFIG_FILE.is_file():
        try:
            loaded = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cfg.update(loaded)
        except Exception as exc:
            log.warning("Failed reading %s: %s", CONFIG_FILE, exc)
    else:
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        os.chmod(CONFIG_FILE, 0o600)
    return cfg, tok


def save_local_config(cfg: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(CONFIG_FILE)


_LAST_ALLOWED_BY_BOT: dict[str, set[int]] = {}
_LAST_BOT_ROLES: dict[str, dict[int, str]] = {}


def _parse_uid_set(raw: str | None) -> set[int]:
    out: set[int] = set()
    if not raw:
        return out
    for tok in str(raw).replace(" ", ",").split(","):
        tok = tok.strip()
        if tok and tok.lstrip("-").isdigit():
            try:
                out.add(int(tok))
            except ValueError:
                continue
    return out


def _parse_user_roles_map(raw: str | None) -> dict[int, str]:
    """Parse `AGY_TG_USER_ROLES` (`111:admin,222:readonly` or JSON object) into `{uid: role}`."""
    out: dict[int, str] = {}
    if not raw:
        return out
    text = str(raw).strip()
    if not text:
        return out
    if text.startswith("{"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if str(k).strip().lstrip("-").isdigit():
                        role = str(v or "").strip().lower()
                        if role in ("admin", "readonly", "denied"):
                            out[int(str(k).strip())] = role
                return out
        except Exception:
            pass
    for item in text.replace(" ", ",").split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        uid_s, role_s = item.split(":", 1)
        uid_s = uid_s.strip()
        role_s = role_s.strip().lower()
        if uid_s.lstrip("-").isdigit() and role_s in ("admin", "readonly", "denied"):
            out[int(uid_s)] = role_s
    return out


def _resolve_bot_roles_from_env(env_map: dict[str, str], bot_allowed: set[int]) -> dict[int, str]:
    """Resolve per-user RBAC role (`admin` / `readonly` / `denied`) matching `bridge/access_control.py`."""
    allowed_users = _parse_uid_set(env_map.get("AGY_TG_ALLOWED_USERS"))
    admin_users = _parse_uid_set(env_map.get("AGY_TG_ADMIN_USERS"))
    readonly_users = _parse_uid_set(env_map.get("AGY_TG_READONLY_USERS"))
    explicit_roles = _parse_user_roles_map(env_map.get("AGY_TG_USER_ROLES"))

    for uid, role in explicit_roles.items():
        if role == "admin":
            admin_users.add(uid)
            readonly_users.discard(uid)
        elif role == "readonly":
            readonly_users.add(uid)
            admin_users.discard(uid)
            allowed_users.discard(uid)

    effective_admins = admin_users if admin_users else allowed_users
    roles: dict[int, str] = {}
    for cid in bot_allowed:
        if cid <= 0:
            continue
        if explicit_roles.get(cid) == "denied":
            roles[cid] = "denied"
            continue
        if effective_admins:
            if cid in effective_admins:
                roles[cid] = "admin"
            elif cid in readonly_users:
                roles[cid] = "readonly"
            elif admin_users and allowed_users and cid in allowed_users:
                roles[cid] = "readonly"
            else:
                roles[cid] = "denied"
        else:
            if cid in readonly_users:
                roles[cid] = "readonly"
            else:
                roles[cid] = "admin"
    return roles


def load_bot_credentials_with_rbac(
    bridge_dir: Path | None = None,
) -> tuple[dict[str, str], dict[str, str], set[int], dict[str, set[int]], dict[str, dict[int, str]]]:
    """Load bot tokens, bot ID map, allowed chats, per-bot allowed chats, and per-bot RBAC roles.

    Files without a valid `AGY_TG_BOT_TOKEN` are completely ignored and never contribute UIDs.
    """
    bots_by_key: dict[str, str] = {}
    bot_id_to_key: dict[str, str] = {}
    allowed_chats: set[int] = set()
    allowed_by_bot: dict[str, set[int]] = {}
    bot_roles: dict[str, dict[int, str]] = {}

    env_files = discover_bridge_env_files(bridge_dir=bridge_dir)
    if not env_files and bridge_dir is None:
        env_files = {k: p for k, p in BRIDGE_ENV_FILES.items() if p.is_file()}

    for key, path in env_files.items():
        if not path.is_file():
            continue
        env_map: dict[str, str] = {}
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env_map[k.strip()] = v.strip().strip("'\"")
        token = env_map.get("AGY_TG_BOT_TOKEN", "")
        if not (token and ":" in token):
            # Strictly ignore token-less env files so they never pollute any whitelist
            continue
        bot_allowed = _parse_uid_set(env_map.get("AGY_TG_ALLOWED_CHATS"))
        bots_by_key[key] = token
        bot_id_to_key[token.split(":", 1)[0]] = key
        allowed_by_bot[key] = bot_allowed
        allowed_chats.update(bot_allowed)
        bot_roles[key] = _resolve_bot_roles_from_env(env_map, bot_allowed)

    _LAST_ALLOWED_BY_BOT.clear()
    _LAST_ALLOWED_BY_BOT.update(allowed_by_bot)
    _LAST_BOT_ROLES.clear()
    _LAST_BOT_ROLES.update(bot_roles)
    return bots_by_key, bot_id_to_key, allowed_chats, allowed_by_bot, bot_roles


def load_bot_credentials_detailed(
    bridge_dir: Path | None = None,
) -> tuple[dict[str, str], dict[str, str], set[int], dict[str, set[int]]]:
    """Load bot tokens, bot ID map, global allowed chats, and per-bot allowed chats without logging secrets."""
    bots_by_key, bot_id_to_key, allowed_chats, allowed_by_bot, _bot_roles = load_bot_credentials_with_rbac(
        bridge_dir=bridge_dir
    )
    return bots_by_key, bot_id_to_key, allowed_chats, allowed_by_bot


def load_bot_credentials() -> tuple[dict[str, str], dict[str, str], set[int]]:
    """Load bot tokens and allowed chat IDs from agy-tg-bridge .env* files without logging secrets."""
    bots_by_key, bot_id_to_key, allowed_chats, _allowed_by_bot = load_bot_credentials_detailed()
    return bots_by_key, bot_id_to_key, allowed_chats


_DEFAULT_LOAD_BOT_CREDENTIALS = load_bot_credentials


def _load_auth_context() -> tuple[
    dict[str, str], dict[str, str], set[int], dict[str, set[int]], dict[str, dict[int, str]]
]:
    """Load authoritative per-bot auth & RBAC context (honoring test monkeypatches of `load_bot_credentials`)."""
    if load_bot_credentials is _DEFAULT_LOAD_BOT_CREDENTIALS:
        return load_bot_credentials_with_rbac()
    bots, id_map, allowed = load_bot_credentials()
    allowed_set = set(allowed or ())
    if len(bots) == 1:
        only_key = next(iter(bots.keys()))
        by_bot = {only_key: set(allowed_set)}
        roles = {only_key: {cid: "admin" for cid in allowed_set if cid > 0}}
    else:
        by_bot = {k: set(allowed_set) for k in bots}
        roles = {k: {cid: "admin" for cid in allowed_set if cid > 0} for k in bots}
    return bots, id_map, allowed_set, by_bot, roles


def _resolve_private_chat_id(
    allowed_or_bot_key: Iterable[int] | str | None,
    preferred_user_id: int | None = None,
    bot_allowed: Iterable[int] | None = None,
) -> int | None:
    """Resolve a strictly positive, unambiguous Telegram private DM chat ID within the target bot's whitelist.

    Rules (fail-closed):
    - Never returns negative group IDs.
    - When `bot_allowed` is supplied, ONLY `bot_allowed` is consulted (never falls back to global union).
    - When `preferred_user_id` is supplied, it MUST be positive and present in the target bot's whitelist
      (returns None otherwise — never falls back to another user).
    - When `preferred_user_id` is None, returns a chat ID ONLY if the target bot has EXACTLY ONE positive
      private chat ID (returns None for 0 or >=2 positive IDs to prevent misrouting).
    """
    if bot_allowed is not None:
        source_iter: Iterable[int] = bot_allowed
    elif isinstance(allowed_or_bot_key, str):
        _, _, _, by_bot, _ = _load_auth_context()
        source_iter = by_bot.get(allowed_or_bot_key, set())
    else:
        source_iter = allowed_or_bot_key or ()

    pos_set: set[int] = set()
    for cid in source_iter:
        try:
            ic = int(cid)
        except (TypeError, ValueError):
            continue
        if ic > 0:
            pos_set.add(ic)

    if preferred_user_id is not None:
        try:
            pref = int(preferred_user_id)
        except (TypeError, ValueError):
            return None
        return pref if (pref > 0 and pref in pos_set) else None

    if len(pos_set) == 1:
        return next(iter(pos_set))
    return None


def verify_telegram_init_data(
    init_data: str,
    bots_by_key: dict[str, str],
    allowed_chats: set[int] | None = None,
    max_age_sec: int = 86400,
    *,
    allowed_by_bot: dict[str, set[int]] | None = None,
    bot_roles: dict[str, dict[int, str]] | None = None,
) -> tuple[bool, dict[str, Any] | None, str]:
    """Validate Telegram Mini App initData via HMAC-SHA256 + signing bot's own whitelist & RBAC role."""
    if not init_data:
        return False, None, "缺少 Telegram Mini App 身份签名，请从授权 TG 机器人对话按钮打开。"

    try:
        pairs = urllib.parse.parse_qsl(init_data, keep_blank_values=True)
    except Exception:
        return False, None, "initData 格式无效。"

    params = dict(pairs)
    received_hash = params.get("hash", "")
    auth_date_str = params.get("auth_date", "0")
    if not received_hash or not auth_date_str.isdigit():
        return False, None, "缺少签名哈希或时间戳。"

    auth_date = int(auth_date_str)
    if abs(time.time() - auth_date) > max_age_sec:
        return False, None, "Telegram 会话签名已过期，请关闭面板后重新从聊天按钮打开。"

    data_check_string = "\n".join(
        f"{k}={v}" for k, v in sorted((k, v) for k, v in pairs if k != "hash")
    )

    matched_bot: str | None = None
    for bot_key, token in bots_by_key.items():
        secret_key = hmac.new(b"WebAppData", token.encode("utf-8"), hashlib.sha256).digest()
        expected = hmac.new(
            secret_key, data_check_string.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if hmac.compare_digest(expected, received_hash):
            matched_bot = bot_key
            break

    if not matched_bot:
        return False, None, "Telegram 机器人签名校验不通过。"

    try:
        user = json.loads(params.get("user", "{}"))
        uid = int(user.get("id", 0))
    except Exception:
        return False, None, "无法解析 Telegram 用户身份。"

    if uid <= 0:
        return False, None, "无效的 Telegram 用户 ID。"

    if allowed_by_bot is not None:
        target_allowed = allowed_by_bot.get(matched_bot, set())
    else:
        target_allowed = allowed_chats or set()

    if uid not in target_allowed:
        return False, None, f"账号 {uid} 不在机器人 {matched_bot} 的授权白名单中。"

    role = "admin"
    if bot_roles is not None:
        roles_for_bot = bot_roles.get(matched_bot)
        if roles_for_bot is not None:
            role = roles_for_bot.get(uid, "denied")
        else:
            role = "denied"
    if role not in ("admin", "readonly"):
        return False, None, f"账号 {uid} 在机器人 {matched_bot} 上无有效访问角色。"

    return True, {"user": user, "user_id": uid, "bot": matched_bot, "role": role}, ""


def _authenticate_init_data(init_data: str) -> tuple[bool, dict[str, Any] | None, str]:
    """Authenticate Telegram initData against fresh per-bot tokens, whitelists, and RBAC roles."""
    bots, _, allowed, allowed_by_bot, bot_roles = _load_auth_context()
    return verify_telegram_init_data(
        init_data,
        bots,
        allowed,
        allowed_by_bot=allowed_by_bot,
        bot_roles=bot_roles,
    )


def _check_live_user_role_from_ctx(
    bot_key: str,
    user_id: int,
    auth_ctx: tuple[dict[str, str], dict[str, str], set[int], dict[str, set[int]], dict[str, dict[int, str]]],
) -> str:
    """Evaluate live role for `(bot_key, user_id)` against a freshly loaded auth context snapshot."""
    bots, _, _, allowed_by_bot, bot_roles = auth_ctx
    if not bot_key or bot_key not in bots:
        return "denied"
    if user_id <= 0 or user_id not in allowed_by_bot.get(bot_key, set()):
        return "denied"
    roles_for_bot = bot_roles.get(bot_key)
    if roles_for_bot is None:
        return "denied"
    return roles_for_bot.get(user_id, "denied")


def _check_live_user_role(bot_key: str, user_id: int) -> str:
    """Re-verify live role for `(bot_key, user_id)` against current `.env*` credentials (handles revocation)."""
    return _check_live_user_role_from_ctx(bot_key, user_id, _load_auth_context())


XCLIP_BIN = shutil.which("xclip") or "/usr/bin/xclip"


def resolve_camoufox_display(ctx: Any, profile_dir: Path | None = None) -> str | None:
    """Discover the Xvfb DISPLAY string (e.g. ':1') attached to Camoufox without touching browser prefs."""
    if ctx is not None:
        close_fn = getattr(ctx, "close", None)
        closure = getattr(close_fn, "__closure__", None) or ()
        for cell in closure:
            try:
                val = cell.cell_contents
            except ValueError:
                continue
            disp_num = getattr(val, "_display", None)
            if isinstance(disp_num, int):
                return f":{disp_num}"

    # Fallback: scan /proc for camoufox-bin running against active profile_dir
    prof_bytes = str(profile_dir).encode("utf-8") if profile_dir is not None else b""
    proc_root = Path("/proc")
    if proc_root.is_dir():
        for entry in proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cmd = (entry / "cmdline").read_bytes()
                if b"camoufox-bin" not in cmd:
                    continue
                if prof_bytes and prof_bytes not in cmd:
                    continue
                env_raw = (entry / "environ").read_bytes()
                for item in env_raw.split(b"\x00"):
                    if item.startswith(b"DISPLAY="):
                        disp = item.split(b"=", 1)[1].decode("ascii", errors="ignore").strip()
                        if disp.startswith(":"):
                            return disp
            except Exception:
                continue
    return None


async def read_x11_clipboard_async(display: str | None) -> str:
    """Read X11 CLIPBOARD selection externally from Xvfb without injecting any page JS."""
    if not display or not os.path.isfile(XCLIP_BIN):
        return ""
    env = {"DISPLAY": display, "PATH": "/usr/bin:/bin"}
    for target in ("UTF8_STRING", "STRING"):
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                XCLIP_BIN,
                "-o",
                "-selection",
                "clipboard",
                "-t",
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=0.45)
            if proc.returncode == 0:
                return out.decode("utf-8", errors="replace")[:25000]
            err_txt = err.decode("utf-8", errors="ignore")
            if "UTF8_STRING" not in err_txt:
                break
        except Exception:
            if proc and proc.returncode is None:
                try:
                    proc.kill()
                except Exception:
                    pass
            break
    return ""


class TelegramLiveCardPublisher:
    """Manages the in-chat live-updating photo card (`sendPhoto` + `editMessageMedia`)."""

    def __init__(self, hub: "LiveBrowserHub") -> None:
        self.hub = hub
        self.http: Any = None
        # Active card state keyed by `(bot_key, chat_id)` with `session_gen` binding
        self.cards: dict[tuple[str, int], dict[str, Any]] = {}
        # Stale / retiring card records isolated by `(bot_key, chat_id, message_id)` so fast
        # same-owner rollovers, `force_new` replacements, and rejected stale-card callbacks never
        # overwrite or drop bounded retirement retries (`retire_attempts` capped at 3).
        self.pending_retire_cards: dict[tuple[str, int, int], dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    def _stage_card_for_retire(
        self,
        card: dict[str, Any] | None,
        *,
        card_key: tuple[str, int] | None = None,
    ) -> tuple[tuple[str, int, int], dict[str, Any]] | None:
        """Move a stale/superseded card into `pending_retire_cards[(bot_key, chat_id, message_id)]`
        preserving any existing `retire_attempts`. Only removes `card_key` from `self.cards` when
        it still refers to the same card/message_id.
        """
        if not isinstance(card, dict):
            if card_key is not None:
                self.cards.pop(card_key, None)
            return None
        bot_key = str(card.get("bot_key") or (card_key[0] if card_key else ""))
        chat_id = int(card.get("chat_id") or (card_key[1] if card_key else 0))
        mid = int(card.get("message_id") or 0)
        if card_key is not None:
            cur = self.cards.get(card_key)
            if cur is card or (cur is not None and int(cur.get("message_id") or 0) == mid):
                self.cards.pop(card_key, None)
        if not bot_key or chat_id <= 0 or mid <= 0:
            return None
        retire_key = (bot_key, chat_id, mid)
        existing = self.pending_retire_cards.get(retire_key)
        if existing is not None:
            existing["retire_attempts"] = max(
                int(existing.get("retire_attempts") or 0),
                int(card.get("retire_attempts") or 0),
            )
            return retire_key, existing
        card["bot_key"] = bot_key
        card["chat_id"] = chat_id
        card["message_id"] = mid
        self.pending_retire_cards[retire_key] = card
        return retire_key, card

    def _drop_revoked_cards(self, bot_key: str, chat_id: int) -> None:
        """Drop active & pending-retire cards for a revoked `(bot_key, chat_id)` without calling Telegram."""
        self.cards.pop((bot_key, chat_id), None)
        for rk in [k for k in self.pending_retire_cards if k[0] == bot_key and k[1] == chat_id]:
            self.pending_retire_cards.pop(rk, None)

    def _recheck_auth_or_drop_locked(self, bot_key: str, chat_id: int) -> str | None:
        """Re-check live admin RBAC while holding `self._lock`; drop all active & pending cards if revoked."""
        bots, _, _, allowed_by_bot, bot_roles = _load_auth_context()
        live_token = self._is_card_currently_authorized(
            bot_key, chat_id, bots, allowed_by_bot, bot_roles
        )
        if not live_token:
            self._drop_revoked_cards(bot_key, chat_id)
            return None
        return live_token

    async def start(self) -> None:
        from aiohttp import ClientSession, ClientTimeout
        self.http = ClientSession(timeout=ClientTimeout(total=15), trust_env=True)

    async def close(self) -> None:
        if self.http:
            await self.http.close()
            self.http = None

    def _resolve_bot_token_and_chat(
        self,
        bot_key: str,
        preferred_user_id: int | None = None,
        *,
        require_admin: bool = True,
    ) -> tuple[str | None, int | None]:
        bots, _, _, allowed_by_bot, bot_roles = _load_auth_context()
        token = bots.get(bot_key)
        if not token:
            return None, None
        bot_allowed = allowed_by_bot.get(bot_key, set())
        chat_id = _resolve_private_chat_id(
            None, preferred_user_id=preferred_user_id, bot_allowed=bot_allowed
        )
        if chat_id is None or chat_id <= 0:
            return token, None
        roles_for_bot = bot_roles.get(bot_key)
        if roles_for_bot is not None:
            role = roles_for_bot.get(chat_id, "denied")
            if require_admin and role != "admin":
                return token, None
            if role not in ("admin", "readonly"):
                return token, None
        return token, chat_id

    def _is_card_currently_authorized(
        self,
        bot_key: str,
        chat_id: int,
        bots: dict[str, str],
        allowed_by_bot: dict[str, set[int]],
        bot_roles: dict[str, dict[int, str]],
    ) -> str | None:
        """Verify live authorization for `(bot_key, chat_id)` and return token if valid admin."""
        token = bots.get(bot_key)
        if not token or chat_id <= 0:
            return None
        if chat_id not in allowed_by_bot.get(bot_key, set()):
            return None
        roles_for_bot = bot_roles.get(bot_key)
        if roles_for_bot is not None and roles_for_bot.get(chat_id) != "admin":
            return None
        return token

    def _matches_session_owner(self, bot_key: str, chat_id: int) -> bool:
        """Bind Telegram live cards strictly to an explicit verified `(bot_key, user_id)` session owner."""
        if not self.hub._has_verified_session_owner():
            return False
        assert self.hub.session_owner is not None
        s_bot, s_uid = self.hub.session_owner
        if not bot_key or bot_key != s_bot:
            return False
        return s_uid is not None and int(chat_id) == int(s_uid)

    def verify_card_control(
        self,
        bot_key: str | None,
        chat_id: int,
        *,
        message_id: int | None = None,
        require_card: bool = True,
        require_running: bool = True,
        expected_session_gen: int | None = None,
    ) -> tuple[bool, str, str | None]:
        """Pre-flight & in-lock verification for any Telegram card callback BEFORE side effects."""
        if not bot_key:
            return False, "缺少或无法识别的 Bot 身份", None
        if require_running and self.hub.engine_mode == "idle":
            return False, "当前没有运行中的浏览器会话", None
        if expected_session_gen is not None and self.hub.session_gen != expected_session_gen:
            return False, "当前浏览器会话代次已变更", None
        if not self.hub._has_verified_session_owner():
            return False, "当前浏览器会话未绑定私聊归属者，仅限本机 CLI 控制", None
        bots, _, _, allowed_by_bot, bot_roles = _load_auth_context()
        token = self._is_card_currently_authorized(bot_key, chat_id, bots, allowed_by_bot, bot_roles)
        if not token:
            self._drop_revoked_cards(bot_key, chat_id)
            return False, "当前私聊卡片未授权或权限已撤销", None
        if not self._matches_session_owner(bot_key, chat_id):
            return False, "该实况卡片不属于当前浏览器会话归属者", None
        if require_card:
            if (
                message_id is None
                or isinstance(message_id, bool)
                or not isinstance(message_id, int)
                or message_id <= 0
            ):
                return False, "缺少有效的实况卡片 message_id", None
            card_key = (bot_key, chat_id)
            card = self.cards.get(card_key)
            if not card or card.get("session_gen") != self.hub.session_gen:
                if card is not None:
                    # Reject stale callback without dropping retirement retry tracking
                    self._stage_card_for_retire(card, card_key=card_key)
                return False, "该实况卡片已过期或不属于当前浏览器会话", None
            if int(card.get("message_id", -1)) != int(message_id):
                return False, "该实况卡片已不是最新卡片", None
        return True, "ok", token

    def has_card_for_bot(self, bot_key: str) -> bool:
        return any(
            k[0] == bot_key and c.get("session_gen") == self.hub.session_gen
            for k, c in self.cards.items()
        )

    @staticmethod
    def _build_finished_caption() -> str:
        """Strictly stateless retired-card caption: NEVER reads live hub title/url/profile/egress."""
        ts_str = time.strftime("%H:%M:%S", time.localtime())
        return (
            f"🔴 <b>远端浏览器会话已结束</b> · <code>{ts_str}</code>\n"
            "✅ 会话已安全关闭（历史画面仅供留档）"
        )

    def _build_markup(self, bot_key: str, finished: bool = False) -> str | None:
        if finished:
            # Stateless empty keyboard so retired cards never reflect a newer session's takeover state
            return json.dumps({"inline_keyboard": []}, ensure_ascii=False)
        pub = (self.hub.config.get("public_url") or "").strip().rstrip("/")
        rows: list[list[dict[str, Any]]] = []
        if pub.startswith("https://"):
            btn_text = (
                "🟠 人工接管中 · 点此操作浏览器"
                if self.hub.takeover
                else "🖥 打开实时画面 / 人工接管"
            )
            rows.append([{"text": btn_text, "web_app": {"url": f"{pub}/?bot={bot_key}"}}])
        takeover_btn = (
            {"text": "▶️ 交还 AI", "callback_data": "browser:takeover_off"}
            if self.hub.takeover
            else {"text": "🖐 接管", "callback_data": "browser:takeover_on"}
        )
        rows.append(
            [
                takeover_btn,
                {"text": "📸 刷新", "callback_data": "browser:card_refresh"},
                {"text": "⏹ 关闭", "callback_data": "browser:card_stop"},
            ]
        )
        if not rows:
            return None
        return json.dumps({"inline_keyboard": rows}, ensure_ascii=False)

    def _build_caption(self, finished: bool = False) -> str:
        if finished:
            return self._build_finished_caption()
        ts_str = time.strftime("%H:%M:%S", time.localtime())
        title = html.escape((self.hub.title or "加载中...")[:70])
        url = html.escape((self.hub.url or "about:blank")[:120])
        if self.hub.takeover:
            header = "🟠 <b>LIVE 浏览器实况</b> · <code>🖐 人工接管中</code>"
            reason = html.escape(self.hub.takeover_reason or "AI 已暂停，等待你在面板操作完成后交还")
            status_line = f"🖐 <b>状态</b>：{reason}"
        else:
            header = f"🔴 <b>LIVE 浏览器实况</b> · <code>👀 实时同步 ({ts_str})</code>"
            ai_st = html.escape(self.hub.ai_status or "浏览器运行中")
            status_line = f"🤖 <b>动作</b>：{ai_st}"

        lines = [
            header,
            f"📄 <b>页面</b>：{title}",
            f"🔗 <code>{url}</code>",
            status_line,
        ]
        if self.hub.active_profile:
            lock_badge = "🔒 " if self.hub.active_pinned else ""
            os_part = self.hub.active_os or "windows"
            egress_part = self.hub.active_egress or "direct"
            lines.append(
                f"🎭 <b>环境</b>：{lock_badge}<code>{html.escape(self.hub.active_profile)}</code>"
                f" · <code>{html.escape(os_part)}</code> · <code>{html.escape(egress_part)}</code>"
            )
        if not (self.hub.config.get("public_url") or "").startswith("https://"):
            lines.append("💡 <i>绑定 HTTPS 隧道域名后将自动显示【实时画面/人工接管】按钮</i>")
        return "\n".join(lines)

    _CARD_RETIRE_MAX_ATTEMPTS = 3
    _PERMANENT_TG_RETIRE_ERRORS = (
        "message is not modified",
        "message to edit not found",
        "chat not found",
        "message_id_invalid",
        "message can't be edited",
        "bot was blocked by the user",
        "user is deactivated",
    )

    @classmethod
    def _is_tg_retire_terminal_response(cls, status: Any, data: Any) -> bool:
        """Return True iff Telegram HTTP status + JSON body confirm retirement or a permanent terminal error.

        Returns False on transient errors (HTTP 429/5xx, non-dict body, API error_code 429/5xx, or other
        non-ok transient failures) so callers retain the card record for bounded retry.
        """
        if isinstance(status, int) and (status == 429 or status >= 500):
            return False
        if not isinstance(data, dict):
            return False
        if data.get("ok"):
            return True
        err_code = data.get("error_code")
        desc = str(data.get("description") or "").lower()
        if any(marker in desc for marker in cls._PERMANENT_TG_RETIRE_ERRORS):
            return True
        if err_code == 429 or (isinstance(err_code, int) and err_code >= 500):
            return False
        if err_code == 400 and ("not found" in desc or "not modified" in desc or "invalid" in desc):
            return True
        return False

    async def _retire_orphan_card_message(self, token: str, chat_id: int, message_id: int) -> bool:
        """Silently retire an orphaned Telegram card using strictly stateless fixed copy (zero hub reads).

        Returns True when Telegram confirms `ok=true` or returns a permanent terminal error
        (e.g., message already gone / not modified / chat not found). Returns False on transient
        network/HTTP 5xx/429/unexpected failures so callers can retain the record and retry.
        """
        if not token or chat_id <= 0 or message_id <= 0:
            return True
        if not self.http:
            return False
        try:
            finished_caption = self._build_finished_caption()
            async with self.http.post(
                f"https://api.telegram.org/bot{token}/editMessageCaption",
                json={
                    "chat_id": chat_id,
                    "message_id": message_id,
                    "caption": finished_caption,
                    "parse_mode": "HTML",
                    "reply_markup": {"inline_keyboard": []},
                },
            ) as resp:
                status = getattr(resp, "status", 200)
                if isinstance(status, int) and (status == 429 or status >= 500):
                    log.debug(
                        "Orphan card retire transient HTTP %s (chat_id=%s mid=%s)",
                        status,
                        chat_id,
                        message_id,
                    )
                    return False
                data = await resp.json()
                if self._is_tg_retire_terminal_response(status, data):
                    return True
                log.debug("Orphan card retire non-ok response (chat_id=%s mid=%s): %s", chat_id, message_id, data)
                return False
        except Exception as exc:
            log.debug("Orphan card retire transient error (chat_id=%s mid=%s): %s", chat_id, message_id, exc)
            return False

    async def _retire_card_record_locked(
        self,
        retire_key: tuple[str, int, int],
        token: str | None = None,
        *,
        jpeg_override: bytes | None = None,
    ) -> bool:
        """Retire a staged stale card record in `pending_retire_cards`; pop only on confirmed retire,
        live RBAC revocation (which drops all active & pending cards for that `(bot_key, chat_id)`),
        or bounded retry cap.

        Shared by explicit `retire_cards()` (both caption-only and final-JPEG `editMessageMedia` paths),
        orphan card cleanup in `ensure_card()`, and periodic `tick_updates()` / `_update_card_locked()`
        retirement paths so all observe per-request live RBAC verification, the same Telegram response
        verification, and shared per-card `retire_attempts` counter (capped at 3).
        """
        card = self.pending_retire_cards.get(retire_key)
        if card is None:
            return False
        bot_key, chat_id, mid = retire_key
        if mid <= 0:
            self.pending_retire_cards.pop(retire_key, None)
            return True
        # Re-check live RBAC inside lock right before EVERY outbound retire request.
        bots, _, _, allowed_by_bot, bot_roles = _load_auth_context()
        live_token = self._is_card_currently_authorized(
            bot_key, chat_id, bots, allowed_by_bot, bot_roles
        )
        if not live_token:
            log.info(
                "Dropping revoked cards bot=%s chat_id=%s mid=%s before retire request",
                bot_key,
                chat_id,
                mid,
            )
            self._drop_revoked_cards(bot_key, chat_id)
            return False
        if not self.http:
            return False
        try:
            if jpeg_override:
                retired_ok = await self._update_card_locked(
                    (bot_key, chat_id),
                    live_token,
                    finished=True,
                    force=True,
                    allow_stale_gen=True,
                    jpeg_override=jpeg_override,
                    card_override=card,
                )
                if retire_key not in self.pending_retire_cards:
                    return retired_ok
            else:
                retired_ok = await self._retire_orphan_card_message(live_token, chat_id, mid)
        except BaseException:
            self._recheck_auth_or_drop_locked(bot_key, chat_id)
            raise
        if retired_ok:
            self.pending_retire_cards.pop(retire_key, None)
            if (bot_key, chat_id) in self.cards or any(
                k[0] == bot_key and k[1] == chat_id for k in self.pending_retire_cards
            ):
                if not self._recheck_auth_or_drop_locked(bot_key, chat_id):
                    log.info(
                        "Dropping remaining revoked cards bot=%s chat_id=%s after retire request",
                        bot_key,
                        chat_id,
                    )
            return True
        # Re-check live RBAC after failed outbound request: if revoked mid-flight, drop all
        # active & pending cards for `(bot_key, chat_id)` immediately rather than retaining for retry.
        if not self._recheck_auth_or_drop_locked(bot_key, chat_id):
            log.info(
                "Dropping revoked cards bot=%s chat_id=%s mid=%s after failed retire request",
                bot_key,
                chat_id,
                mid,
            )
            return False
        attempts = int(card.get("retire_attempts") or 0) + 1
        card["retire_attempts"] = attempts
        if attempts >= self._CARD_RETIRE_MAX_ATTEMPTS:
            log.warning(
                "Dropping stale card record bot=%s chat_id=%s mid=%s after %d failed retire attempts",
                bot_key,
                chat_id,
                mid,
                attempts,
            )
            self.pending_retire_cards.pop(retire_key, None)
            return False
        return False

    async def ensure_card(
        self,
        bot_key: str,
        force_new: bool = False,
        preferred_user_id: int | None = None,
    ) -> dict[str, Any] | None:
        """Create or update the live browser card in the session owner's verified private DM chat."""
        if not bot_key or self.hub.engine_mode == "idle":
            return None
        if not self.hub._has_verified_session_owner():
            log.warning(
                "Skipping live card send for bot=%s: session has no explicit verified (bot_key, user_id) owner",
                bot_key,
            )
            return None
        card_gen = self.hub.session_gen
        card_owner = self.hub.session_owner
        token, chat_id = self._resolve_bot_token_and_chat(
            bot_key, preferred_user_id=preferred_user_id, require_admin=True
        )
        if not token or not chat_id or chat_id <= 0:
            if token:
                log.warning(
                    "Skipping live card send for bot=%s: no unambiguous authorized private chat_id",
                    bot_key,
                )
            return None
        if not self._matches_session_owner(bot_key, chat_id):
            log.warning(
                "Blocking live card send for bot=%s chat_id=%s: session owned by %s",
                bot_key,
                chat_id,
                self.hub.session_owner,
            )
            return None

        # Wait briefly if first frame is still arriving
        for _ in range(15):
            if (
                self.hub.session_gen != card_gen
                or self.hub.session_owner != card_owner
                or self.hub.engine_mode == "idle"
            ):
                return None
            if self.hub.latest_jpeg:
                break
            await asyncio.sleep(0.15)
        if (
            self.hub.session_gen != card_gen
            or self.hub.session_owner != card_owner
            or self.hub.engine_mode == "idle"
            or not self.hub.latest_jpeg
            or not self.http
            or not self._matches_session_owner(bot_key, chat_id)
        ):
            return None

        card_key = (bot_key, chat_id)
        async with self._lock:
            if (
                self.hub.session_gen != card_gen
                or self.hub.session_owner != card_owner
                or self.hub.engine_mode == "idle"
                or not self.hub.latest_jpeg
                or not self._matches_session_owner(bot_key, chat_id)
            ):
                return None
            # Re-check live authorization right before calling Telegram API!
            bots, _, _, allowed_by_bot, bot_roles = _load_auth_context()
            live_token = self._is_card_currently_authorized(bot_key, chat_id, bots, allowed_by_bot, bot_roles)
            if not live_token:
                self._drop_revoked_cards(bot_key, chat_id)
                return None

            existing = self.cards.get(card_key)
            if existing and not force_new and existing.get("session_gen") == card_gen:
                await self._update_card_locked(card_key, live_token, finished=False, force=True)
                return self.cards.get(card_key)
            if existing and existing.get("session_gen") != card_gen:
                # Preserve stale card's retirement retry tracking before sending a new card
                self._stage_card_for_retire(existing, card_key=card_key)

            snap_jpeg = self.hub.latest_jpeg
            caption = self._build_caption(finished=False)
            markup = self._build_markup(bot_key, finished=False)
            form = FormData()
            form.add_field("chat_id", str(chat_id))
            form.add_field("caption", caption)
            form.add_field("parse_mode", "HTML")
            if markup:
                form.add_field("reply_markup", markup)
            form.add_field(
                "photo",
                snap_jpeg,
                filename="live_browser.jpg",
                content_type="image/jpeg",
            )

            send_ok = False
            mid = 0
            try:
                parsed_mid = 0
                io_send_ok = False
                async with self.http.post(
                    f"https://api.telegram.org/bot{live_token}/sendPhoto", data=form
                ) as resp:
                    status = getattr(resp, "status", 200)
                    if isinstance(status, int) and status >= 400:
                        try:
                            err_data = await resp.json()
                        except Exception:
                            err_data = None
                        desc = (
                            err_data.get("description")
                            if isinstance(err_data, dict)
                            else f"HTTP {status}"
                        )
                        log.warning("sendPhoto failed (%s, HTTP %s): %s", bot_key, status, desc)
                    else:
                        data = await resp.json()
                        if (
                            isinstance(data, dict)
                            and data.get("ok")
                            and isinstance(data.get("result"), dict)
                        ):
                            raw_mid = data["result"].get("message_id")
                            if isinstance(raw_mid, bool) or isinstance(raw_mid, float):
                                raise ValueError(f"invalid message_id: {raw_mid!r}")
                            parsed_mid = int(raw_mid)
                            if parsed_mid <= 0:
                                raise ValueError(f"non-positive message_id: {parsed_mid}")
                            io_send_ok = True
                        else:
                            desc = data.get("description") if isinstance(data, dict) else data
                            log.warning("sendPhoto failed (%s): %s", bot_key, desc)
                # Commit success only after async with __aexit__ exits cleanly
                if io_send_ok:
                    mid = parsed_mid
                    send_ok = True
            except Exception as exc:
                send_ok = False
                mid = 0
                log.warning("sendPhoto error (%s): %s", bot_key, exc)
            except BaseException:
                self._recheck_auth_or_drop_locked(bot_key, chat_id)
                raise

            # Re-check live admin RBAC inside lock after EVERY sendPhoto I/O exit
            # (200 ok, non-200 / ok=false, missing/malformed message_id, or transport/JSON exception).
            still_token = self._recheck_auth_or_drop_locked(bot_key, chat_id)
            if not still_token:
                log.info(
                    "Discarding live cards bot=%s chat_id=%s mid=%s: authorization revoked in-flight during sendPhoto",
                    bot_key,
                    chat_id,
                    mid,
                )
                return None
            if not send_ok:
                return None

            if (
                self.hub.engine_mode == "idle"
                or self.hub.session_gen != card_gen
                or self.hub.session_owner != card_owner
                or not self._matches_session_owner(bot_key, chat_id)
            ):
                log.info(
                    "Discarding & retiring orphan live card bot=%s chat_id=%s mid=%s (card_gen=%d cur_gen=%d)",
                    bot_key,
                    chat_id,
                    mid,
                    card_gen,
                    self.hub.session_gen,
                )
                staged = self._stage_card_for_retire(
                    {
                        "bot_key": bot_key,
                        "chat_id": chat_id,
                        "message_id": mid,
                        "session_gen": card_gen,
                        "owner": card_owner,
                    }
                )
                if staged is not None:
                    await self._retire_card_record_locked(staged[0], still_token)
                return None
            prev = self.cards.get(card_key)
            if prev is not None and int(prev.get("message_id") or 0) != mid:
                self._stage_card_for_retire(prev, card_key=card_key)
            sha = hashlib.sha1(snap_jpeg).hexdigest()
            self.cards[card_key] = {
                "bot_key": bot_key,
                "chat_id": chat_id,
                "message_id": mid,
                "session_gen": card_gen,
                "owner": card_owner,
                "last_sha1": sha,
                "last_caption": caption,
                "last_markup": markup,
                "last_ts": time.monotonic(),
            }
            log.info(
                "Created Telegram live card bot=%s chat_id=%s message_id=%s gen=%d",
                bot_key,
                chat_id,
                mid,
                card_gen,
            )
            return self.cards[card_key]

    async def retire_cards(
        self,
        *,
        session_gen: int | None = None,
        mark_finished: bool = True,
        final_jpeg: bytes | None = None,
    ) -> int:
        """Retire active & pending-retire cards (optionally matching `session_gen`) using strictly
        stateless finished copy.

        Stages matching active cards into `pending_retire_cards[(bot_key, chat_id, message_id)]`
        and shares the same Telegram confirmation/permanent-error verification and bounded 3-attempt
        retry state machine (`_retire_card_record_locked`) as periodic `tick_updates()` across both
        caption-only (`editMessageCaption`) and final-JPEG (`editMessageMedia`) paths.
        """
        if not self.cards and not self.pending_retire_cards:
            return 0
        retired = 0
        async with self._lock:
            staged_from_active: dict[tuple[str, int, int], bytes | None] = {}
            for card_key in list(self.cards.keys()):
                card = self.cards.get(card_key)
                if not card:
                    continue
                if session_gen is not None and card.get("session_gen") != session_gen:
                    continue
                if not mark_finished:
                    self.cards.pop(card_key, None)
                    retired += 1
                    continue
                same_gen_jpeg = (
                    self.hub.latest_jpeg
                    if card.get("session_gen") == self.hub.session_gen
                    else None
                )
                jpeg_for_finish = final_jpeg if final_jpeg is not None else same_gen_jpeg
                staged = self._stage_card_for_retire(card, card_key=card_key)
                if staged is None:
                    retired += 1
                    continue
                staged_from_active[staged[0]] = jpeg_for_finish

            for retire_key in list(self.pending_retire_cards.keys()):
                card = self.pending_retire_cards.get(retire_key)
                if not card:
                    continue
                if session_gen is not None and card.get("session_gen") != session_gen:
                    continue
                if not mark_finished:
                    self.pending_retire_cards.pop(retire_key, None)
                    retired += 1
                    continue
                bot_key, chat_id, _mid = retire_key
                # Re-check live RBAC inside lock before EVERY outbound retire request
                # (never reuse a cached auth snapshot across network awaits!).
                bots, _, _, allowed_by_bot, bot_roles = _load_auth_context()
                token = self._is_card_currently_authorized(
                    bot_key, chat_id, bots, allowed_by_bot, bot_roles
                )
                if not token:
                    log.info(
                        "Dropping revoked cards bot=%s chat_id=%s during retire_cards",
                        bot_key,
                        chat_id,
                    )
                    self._drop_revoked_cards(bot_key, chat_id)
                    retired += 1
                    continue
                if not self.http:
                    self.pending_retire_cards.pop(retire_key, None)
                    retired += 1
                    continue
                jpeg_for_finish = (
                    staged_from_active[retire_key]
                    if retire_key in staged_from_active
                    else (final_jpeg if final_jpeg is not None else None)
                )
                if await self._retire_card_record_locked(
                    retire_key, token, jpeg_override=jpeg_for_finish
                ):
                    retired += 1
        return retired

    async def _refresh_single_card_with_status(
        self,
        bot_key: str,
        chat_id: int,
        *,
        message_id: int | None = None,
        expected_session_gen: int | None = None,
    ) -> tuple[bool, str, int]:
        """Strictly refresh only the single card matching `(bot_key, chat_id, message_id, session_gen)`.

        Returns `(ok, message, http_status)`:
        - `403` when unauthorized, card missing/stale/retired, or session stopped/switched
        - `502` when authorized and card remains active, but Telegram `editMessageMedia` was not confirmed
        - `200` when Telegram confirmed the update (or confirmed `message is not modified`)
        """
        if not self.hub.latest_jpeg or self.hub.engine_mode == "idle":
            return False, "当前没有运行中的浏览器画面", 403
        ok_v, msg_v, token = self.verify_card_control(
            bot_key,
            chat_id,
            message_id=message_id,
            require_card=True,
            require_running=True,
            expected_session_gen=expected_session_gen,
        )
        if not ok_v or not token:
            return False, msg_v, 403
        card_key = (bot_key, chat_id)
        async with self._lock:
            ok_v2, msg_v2, live_token = self.verify_card_control(
                bot_key,
                chat_id,
                message_id=message_id,
                require_card=True,
                require_running=True,
                expected_session_gen=expected_session_gen,
            )
            if not ok_v2 or not live_token:
                return False, msg_v2, 403
            updated = await self._update_card_locked(
                card_key, live_token, finished=False, force=True
            )
            if card_key not in self.cards:
                return False, "当前私聊卡片未授权或权限已撤销", 403
            if not updated:
                return False, "Telegram 实况卡片刷新失败，请稍后重试", 502
            return True, "ok", 200

    async def refresh_single_card(
        self,
        bot_key: str,
        chat_id: int,
        *,
        message_id: int | None = None,
        expected_session_gen: int | None = None,
    ) -> tuple[bool, str]:
        """Strictly refresh only the single card matching `(bot_key, chat_id, message_id, session_gen)`."""
        ok, msg, _status = await self._refresh_single_card_with_status(
            bot_key,
            chat_id,
            message_id=message_id,
            expected_session_gen=expected_session_gen,
        )
        return ok, msg

    async def tick_updates(
        self, finished: bool = False, force: bool = False, *, bot_filter: str | None = None
    ) -> None:
        if not self.cards and not self.pending_retire_cards:
            return
        if finished:
            await self.retire_cards(mark_finished=True)
            return
        if not self.http:
            return
        async with self._lock:
            attempted_retire_keys: set[tuple[str, int, int]] = set()
            for card_key in list(self.cards.keys()):
                bot_key, chat_id = card_key
                if bot_filter is not None and bot_key != bot_filter:
                    continue
                card = self.cards.get(card_key)
                if not card:
                    continue
                bots, _, _, allowed_by_bot, bot_roles = _load_auth_context()
                token = self._is_card_currently_authorized(
                    bot_key, chat_id, bots, allowed_by_bot, bot_roles
                )
                if not token:
                    log.info("Retiring live card bot=%s chat_id=%s: authorization revoked", bot_key, chat_id)
                    self._drop_revoked_cards(bot_key, chat_id)
                    continue
                if (
                    self.hub.engine_mode == "idle"
                    or card.get("session_gen") != self.hub.session_gen
                    or not self._matches_session_owner(bot_key, chat_id)
                ):
                    # Stage stale card into `pending_retire_cards` so the retirement pass below
                    # retries it (stateless finished caption + empty keyboard) up to the shared cap.
                    self._stage_card_for_retire(card, card_key=card_key)
                    continue
                if not self.hub.latest_jpeg:
                    continue
                await self._update_card_locked(
                    card_key,
                    token,
                    finished=False,
                    force=force,
                    attempted_retire_keys=attempted_retire_keys,
                )

            # Independently drain `pending_retire_cards` regardless of idle/no-frame or whether a
            # newer active card exists for the same `(bot_key, chat_id)`.
            for retire_key in list(self.pending_retire_cards.keys()):
                bot_key, chat_id, mid = retire_key
                if bot_filter is not None and bot_key != bot_filter:
                    continue
                if retire_key in attempted_retire_keys or retire_key not in self.pending_retire_cards:
                    continue
                bots, _, _, allowed_by_bot, bot_roles = _load_auth_context()
                token = self._is_card_currently_authorized(
                    bot_key, chat_id, bots, allowed_by_bot, bot_roles
                )
                if not token:
                    log.info(
                        "Dropping pending-retire card bot=%s chat_id=%s mid=%s: authorization revoked",
                        bot_key,
                        chat_id,
                        mid,
                    )
                    self._drop_revoked_cards(bot_key, chat_id)
                    continue
                await self._retire_card_record_locked(retire_key, token)

    async def _update_card_locked(
        self,
        card_key: tuple[str, int],
        token: str,
        finished: bool = False,
        force: bool = False,
        allow_stale_gen: bool = False,
        jpeg_override: bytes | None = None,
        card_override: dict[str, Any] | None = None,
        attempted_retire_keys: set[tuple[str, int, int]] | None = None,
    ) -> bool:
        card = card_override if card_override is not None else self.cards.get(card_key)
        bot_key, chat_id = card_key
        if not card or not self.http:
            return False
        # Always re-verify live RBAC inside lock right before invoking Telegram API
        # (covers BOTH live updates and finished/allow_stale_gen retirement updates!).
        bots, _, _, allowed_by_bot, bot_roles = _load_auth_context()
        live_token = self._is_card_currently_authorized(
            bot_key, chat_id, bots, allowed_by_bot, bot_roles
        )
        if not live_token:
            self._drop_revoked_cards(bot_key, chat_id)
            return False
        token = live_token
        if not finished and not allow_stale_gen:
            # Capture coherent same-generation snapshot and re-verify owner & session_gen
            # right before invoking Telegram API!
            snap_gen = self.hub.session_gen
            snap_owner = self.hub.session_owner
            if (
                self.hub.engine_mode == "idle"
                or card.get("session_gen") != snap_gen
                or self.hub.session_gen != snap_gen
                or self.hub.session_owner != snap_owner
                or not self._matches_session_owner(bot_key, chat_id)
            ):
                staged = self._stage_card_for_retire(card, card_key=card_key)
                if staged is not None:
                    if attempted_retire_keys is not None:
                        attempted_retire_keys.add(staged[0])
                    await self._retire_card_record_locked(staged[0], live_token)
                return False
            jpeg_bytes = jpeg_override if jpeg_override is not None else self.hub.latest_jpeg
        else:
            jpeg_bytes = jpeg_override
        if not jpeg_bytes:
            return False
        now = time.monotonic()
        if not force and not finished and (now - card["last_ts"]) < 3.0:
            return False

        sha = hashlib.sha1(jpeg_bytes).hexdigest()
        caption = self._build_finished_caption() if finished else self._build_caption(finished=False)
        markup = self._build_markup(bot_key, finished=finished)

        if (
            not force
            and not finished
            and sha == card["last_sha1"]
            and caption == card["last_caption"]
            and markup == card.get("last_markup")
        ):
            return False

        media_obj = {
            "type": "photo",
            "media": "attach://frame",
            "caption": caption,
            "parse_mode": "HTML",
        }
        form = FormData()
        form.add_field("chat_id", str(card["chat_id"]))
        form.add_field("message_id", str(card["message_id"]))
        form.add_field("media", json.dumps(media_obj, ensure_ascii=False))
        if markup:
            form.add_field("reply_markup", markup)
        form.add_field(
            "frame",
            jpeg_bytes,
            filename="live_browser.jpg",
            content_type="image/jpeg",
        )

        result = False
        try:
            io_result = False
            io_media_ok = False
            io_retry_after: float | None = None
            async with self.http.post(
                f"https://api.telegram.org/bot{token}/editMessageMedia", data=form
            ) as resp:
                status = getattr(resp, "status", 200)
                if isinstance(status, int) and (status == 429 or status >= 500):
                    log.debug("editMessageMedia transient HTTP %s (%s)", status, bot_key)
                else:
                    data = await resp.json()
                    if (
                        isinstance(data, dict)
                        and data.get("ok")
                        and not (isinstance(status, int) and status >= 400)
                    ):
                        io_media_ok = True
                        io_result = True
                    else:
                        if isinstance(data, dict):
                            desc = str(data.get("description", ""))
                            retry = (data.get("parameters") or {}).get("retry_after")
                            if retry:
                                io_retry_after = float(retry)
                            elif (
                                not finished
                                and not data.get("ok")
                                and (not isinstance(status, int) or status in (200, 400))
                                and data.get("error_code") in (None, 400)
                                and "message is not modified" in desc.lower()
                            ):
                                io_media_ok = True
                                io_result = True
                            elif "message is not modified" not in desc.lower():
                                log.debug("editMessageMedia (%s): %s", bot_key, desc)
                        if finished:
                            io_result = self._is_tg_retire_terminal_response(status, data)
            # Commit card state & success only after async with __aexit__ exits cleanly
            if io_media_ok:
                card["last_sha1"] = sha
                card["last_caption"] = caption
                card["last_markup"] = markup
                card["last_ts"] = time.monotonic()
            elif io_retry_after is not None:
                card["last_ts"] = time.monotonic() + io_retry_after
            result = io_result
        except Exception as exc:
            result = False
            log.debug("editMessageMedia error (%s): %s", bot_key, exc)
        except BaseException:
            self._recheck_auth_or_drop_locked(bot_key, chat_id)
            raise

        # Re-check live admin RBAC inside lock after EVERY editMessageMedia I/O exit
        # (200 ok, 429/5xx, non-200 / ok=false, malformed response, or transport/JSON exception).
        if not self._recheck_auth_or_drop_locked(bot_key, chat_id):
            log.info(
                "Dropping revoked live cards bot=%s chat_id=%s after editMessageMedia I/O",
                bot_key,
                chat_id,
            )
            return result if finished else False
        return result

    async def send_clip_message(
        self, bot_key: str, text: str, preferred_user_id: int | None = None
    ) -> bool:
        """Send an explicit user-requested clipboard snippet to the authorized private Telegram DM."""
        cleaned = (text or "").strip()
        if not cleaned or not self.http:
            return False
        token, chat_id = self._resolve_bot_token_and_chat(bot_key, preferred_user_id=preferred_user_id)
        if not token or not chat_id or chat_id <= 0:
            return False
        snippet = html.escape(cleaned[:3800])
        msg_html = f"📋 <b>从浏览器提取的内容</b>\n<pre><code>{snippet}</code></pre>"
        try:
            async with self.http.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": msg_html,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
            ) as resp:
                data = await resp.json()
                return bool(data.get("ok"))
        except Exception as exc:
            log.warning("send_clip_message error (%s): %s", bot_key, exc)
            return False

    async def send_photo_bytes(
        self,
        bot_key: str,
        jpeg_bytes: bytes,
        caption: str = "",
        preferred_user_id: int | None = None,
    ) -> bool:
        """Send a high-definition screenshot directly to the authorized private Telegram DM."""
        if not jpeg_bytes or not self.http:
            return False
        token, chat_id = self._resolve_bot_token_and_chat(bot_key, preferred_user_id=preferred_user_id)
        if not token or not chat_id or chat_id <= 0:
            return False
        form = FormData()
        form.add_field("chat_id", str(chat_id))
        if caption:
            form.add_field("caption", caption[:1000])
            form.add_field("parse_mode", "HTML")
        form.add_field(
            "photo",
            jpeg_bytes,
            filename="live_browser_hd.jpg",
            content_type="image/jpeg",
        )
        try:
            async with self.http.post(
                f"https://api.telegram.org/bot{token}/sendPhoto", data=form
            ) as resp:
                data = await resp.json()
                return bool(data.get("ok"))
        except Exception as exc:
            log.warning("send_photo_bytes error (%s): %s", bot_key, exc)
            return False

    async def send_document_file(
        self,
        bot_key: str,
        file_path: Path,
        filename: str,
        caption: str = "",
        preferred_user_id: int | None = None,
    ) -> bool:
        """Send a downloaded file (<= MAX_TG_DOWNLOAD_BYTES) to the authorized private Telegram DM."""
        if not self.http or not file_path.is_file():
            return False
        try:
            size = file_path.stat().st_size
        except OSError:
            return False
        if size <= 0 or size > MAX_TG_DOWNLOAD_BYTES:
            return False
        token, chat_id = self._resolve_bot_token_and_chat(bot_key, preferred_user_id=preferred_user_id)
        if not token or not chat_id or chat_id <= 0:
            return False
        safe_name = Path(filename or file_path.name).name or "download.bin"
        form = FormData()
        form.add_field("chat_id", str(chat_id))
        if caption:
            form.add_field("caption", caption[:1000])
            form.add_field("parse_mode", "HTML")
        try:
            raw_bytes = file_path.read_bytes()
        except OSError:
            return False
        form.add_field(
            "document",
            raw_bytes,
            filename=safe_name,
            content_type="application/octet-stream",
        )
        try:
            async with self.http.post(
                f"https://api.telegram.org/bot{token}/sendDocument", data=form
            ) as resp:
                data = await resp.json()
                return bool(data.get("ok"))
        except Exception as exc:
            log.warning("send_document_file error (%s): %s", bot_key, exc)
            return False


class LiveBrowserHub:
    """Central coordinator for AsyncCamoufox, SyncExternal provider, WebSockets, and Takeover Lock."""

    def __init__(self, config: dict[str, Any], local_token: str) -> None:
        self.config = config
        self.local_token = local_token

        # Engine state & session generation / ownership isolation
        self.engine_mode: str = "idle"  # 'idle' | 'async_hosted' | 'sync_external'
        self.session_gen: int = 0
        self.session_owner: tuple[str, int | None] | None = None
        self.camoufox_cm: Any = None
        self.ctx: Any = None
        self.lock_fd: int | None = None
        self.active_tab_index: int = 0
        self.ai_busy_count: int = 0
        self.last_activity_ts: float = time.monotonic()
        self._sync_last_push_ts: float | None = None
        self._sync_lease_id: str | None = None

        # Active profile & egress state (never stores plaintext proxy credentials)
        self.active_profile: str = ""
        self.active_profile_dir: Path | None = None
        self._ephemeral_dir: Path | None = None
        self.active_pinned: bool = False
        self.active_pinned_verified: bool = False
        self.active_egress: str = "direct"
        self.active_os: str = ""
        self.active_fingerprint: dict[str, Any] = {}

        # Shared display state
        self.latest_jpeg: bytes | None = None
        self.url: str = ""
        self.title: str = ""
        self.vw: int = 1280
        self.vh: int = 800
        self.tabs: list[dict[str, Any]] = []
        self.ai_status: str = ""
        self.cursor: dict[str, Any] = {}
        self.x11_display: str | None = None
        self._last_x11_clip: str = ""
        self.latest_clip: dict[str, Any] = {}

        # Adaptive streaming, quality preset & decoupled metadata state
        self.quality_preset: str = "balanced"
        self._tabs_dirty: bool = True
        self._tab_select_rev: int = 0
        self._last_tabs_refresh: float = 0.0
        self._last_normal_sig: tuple[int, bytes] | None = None
        self._hd_settled: bool = False
        self._unchanged_frames: int = 0
        self._last_active_ts: float = time.monotonic()
        self._hd_pending: bool = False
        self._meta_changed_pending: bool = False
        self._meta_task: asyncio.Task[None] | None = None

        # Native Playwright page event state (zero page JS injection)
        self._attached_pages: set[int] = set()
        self._closing_unguarded_pages: set[int] = set()
        self._unguarded_close_tasks: dict[int, asyncio.Task[Any]] = {}
        self._startup_guard_failed_ctx: set[int] = set()
        self._explicit_new_tab_in_flight: int = 0
        self._explicit_close_tab_in_flight: int = 0
        self._recent_response_cl: dict[str, int] = {}
        self.pending_dialogs: dict[str, dict[str, Any]] = {}
        self.pending_filechoosers: dict[str, dict[str, Any]] = {}
        self.downloads: dict[str, dict[str, Any]] = {}
        self._transfer_dir: Path | None = None
        self._bg_tasks: set[asyncio.Task[Any]] = set()
        self._upload_sem = asyncio.Semaphore(MAX_UPLOAD_CONCURRENCY)

        # 3-State Control Arbitration + Input Barrier
        self.takeover: bool = False
        self.takeover_reason: str = ""
        self.takeover_gen: int = 0
        self.takeover_owner: tuple[str, int | None] | None = None
        self._mouse_buttons_down: set[str] = set()
        self._sync_buttons_down: set[str] = set()
        self._takeover_lock = asyncio.Lock()
        self._exec_lock = asyncio.Lock()
        self.ai_allowed_event = asyncio.Event()
        self.ai_allowed_event.set()

        # Queues & Clients
        self.viewers: set[web.WebSocketResponse] = set()
        self.viewer_meta: dict[Any, dict[str, Any]] = {}
        self.input_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=250)
        self.sync_cmd_queue: list[dict[str, Any]] = []
        self._pending_sync_extracts: dict[str, dict[str, Any]] = {}
        self._engine_lock = asyncio.Lock()

        # Background tasks
        self._capture_task: asyncio.Task[None] | None = None
        self._input_task: asyncio.Task[None] | None = None
        self._tg_loop_task: asyncio.Task[None] | None = None
        self.tg = TelegramLiveCardPublisher(self)

    def _track_bg_task(self, task: asyncio.Task[Any]) -> asyncio.Task[Any]:
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)
        return task

    async def _cancel_and_await_bg_tasks(self, timeout: float = 2.0) -> None:
        try:
            cur_task = asyncio.current_task()
        except RuntimeError:
            cur_task = None
        tasks = [t for t in list(self._bg_tasks) if not t.done() and t is not cur_task]
        if self._meta_task and not self._meta_task.done() and self._meta_task is not cur_task:
            tasks.append(self._meta_task)
        self._meta_task = None
        for t in tasks:
            t.cancel()
        if tasks:
            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=timeout)
            except Exception:
                pass
        if cur_task is not None and cur_task in self._bg_tasks:
            self._bg_tasks.clear()
            self._bg_tasks.add(cur_task)
        else:
            self._bg_tasks.clear()

    async def startup(self) -> None:
        await self.tg.start()
        self._capture_task = asyncio.create_task(self._capture_loop())
        self._input_task = asyncio.create_task(self._input_loop())
        self._tg_loop_task = asyncio.create_task(self._tg_maintenance_loop())

    async def shutdown(self) -> None:
        for t in (self._capture_task, self._input_task, self._tg_loop_task):
            if t:
                t.cancel()
        try:
            await asyncio.wait_for(self.stop_hosted(notify_finished=False), timeout=3.5)
        except Exception:
            pass
        await self._cancel_and_await_bg_tasks()
        await self._cleanup_pending_dialogs()
        await self._cleanup_pending_filechoosers_async()
        self._cleanup_transfer_dir(force_all=True)
        for ws in list(self.viewers):
            await ws.close()
        self.viewer_meta.clear()
        await self.tg.close()

    def mark_active(self, *, mark_tabs_dirty: bool = False) -> None:
        now = time.monotonic()
        self.last_activity_ts = now
        self._last_active_ts = now
        self._unchanged_frames = 0
        self._hd_pending = True
        self._hd_settled = False
        if mark_tabs_dirty:
            self._tabs_dirty = True

    async def set_quality_preset(self, preset: str) -> str:
        clean = str(preset or "").strip().lower()
        if clean not in QUALITY_PRESETS:
            clean = "balanced"
        self.quality_preset = clean
        self._last_normal_sig = None
        self._hd_settled = False
        self.mark_active()
        await self.broadcast_state()
        return clean

    def _ensure_transfer_dir(self) -> Path:
        if self._transfer_dir is None or not self._transfer_dir.is_dir():
            d = Path(tempfile.mkdtemp(prefix="agy-live-xfer-"))
            os.chmod(d, 0o700)
            self._transfer_dir = d
        return self._transfer_dir

    def _cleanup_transfer_dir(self, *, force_all: bool = False) -> None:
        now = time.monotonic()
        if force_all:
            self.downloads.clear()
            if self._transfer_dir is not None and self._transfer_dir.exists():
                shutil.rmtree(self._transfer_dir, ignore_errors=True)
            self._transfer_dir = None
            return
        expired_ids = [
            did
            for did, info in list(self.downloads.items())
            if (now - float(info.get("created_ts", 0.0))) > TRANSFER_TTL_SECONDS
        ]
        for did in expired_ids:
            info = self.downloads.pop(did, None)
            if info and info.get("path"):
                try:
                    p = Path(info["path"])
                    p.unlink(missing_ok=True)
                    if p.parent != self._transfer_dir and p.parent.is_dir():
                        shutil.rmtree(p.parent, ignore_errors=True)
                except OSError:
                    pass
        if self._transfer_dir and self._transfer_dir.is_dir():
            try:
                for p in self._transfer_dir.iterdir():
                    try:
                        if (time.time() - p.stat().st_mtime) > TRANSFER_TTL_SECONDS:
                            if p.is_dir():
                                shutil.rmtree(p, ignore_errors=True)
                            else:
                                p.unlink(missing_ok=True)
                    except OSError:
                        pass
            except OSError:
                pass

    # ---------------- Ownership, RBAC & Scoped Broadcast Helpers ----------------

    def _has_verified_session_owner(self) -> bool:
        """Return True ONLY when session_owner is an explicit `(bot_key: str, user_id: int > 0)`."""
        if self.session_owner is None:
            return False
        s_bot, s_uid = self.session_owner
        return bool(s_bot) and isinstance(s_uid, int) and not isinstance(s_uid, bool) and s_uid > 0

    def _effective_resource_owner(self) -> tuple[str | None, int | None]:
        """Return authoritative `(owner_bot, owner_uid)` for newly created dialogs/choosers/downloads."""
        if self.takeover and self.takeover_owner is not None:
            t_bot, t_uid = self.takeover_owner
            if t_bot and isinstance(t_uid, int) and not isinstance(t_uid, bool) and t_uid > 0:
                return t_bot, t_uid
        if self._has_verified_session_owner():
            assert self.session_owner is not None
            return self.session_owner[0], int(self.session_owner[1])  # type: ignore[arg-type]
        return None, None

    def _viewer_can_mutate(self, bot_key: str, user_id: int, role: str) -> bool:
        """Check whether `(bot_key, user_id, role)` may mutate or control the active browser session.

        Active sessions without a verified `(bot_key, user_id)` owner are strictly localhost CLI only.
        """
        if role != "admin":
            return False
        if self.engine_mode != "idle":
            if not self._has_verified_session_owner():
                return False
            assert self.session_owner is not None
            s_bot, s_uid = self.session_owner
            if bot_key != s_bot or int(user_id) != int(s_uid):  # type: ignore[arg-type]
                return False
        return True

    def _viewer_can_control_takeover(self, bot_key: str, user_id: int, role: str) -> bool:
        if not self._viewer_can_mutate(bot_key, user_id, role):
            return False
        if self.takeover:
            if self.takeover_owner is None:
                return False
            t_bot, t_uid = self.takeover_owner
            if not t_bot or t_uid is None or isinstance(t_uid, bool) or int(t_uid) <= 0:
                return False
            if bot_key != t_bot or int(user_id) != int(t_uid):
                return False
        return True

    def _can_access_resource(
        self,
        rec: dict[str, Any],
        bot_key: str,
        user_id: int,
        role: str,
        *,
        require_admin: bool = True,
    ) -> bool:
        if require_admin and role != "admin":
            return False
        if rec.get("session_gen") != self.session_gen:
            return False
        o_bot = rec.get("owner_bot")
        o_uid = rec.get("owner_uid")
        if not o_bot or o_uid is None or isinstance(o_uid, bool) or int(o_uid) <= 0:
            return False
        if bot_key != o_bot:
            return False
        return int(user_id) == int(o_uid)

    def _viewer_can_read_session(self, bot_key: str, user_id: int, role: str) -> bool:
        """Strictly isolate active session frames/URL/title/tabs/clipboard to the verified session owner.

        Active sessions without an explicit `(bot_key, user_id)` owner are NEVER exposed to remote WS viewers.
        """
        if role not in ("admin", "readonly"):
            return False
        if self.engine_mode == "idle":
            return True
        if not self._has_verified_session_owner():
            return False
        assert self.session_owner is not None
        s_bot, s_uid = self.session_owner
        return bot_key == s_bot and int(user_id) == int(s_uid)  # type: ignore[arg-type]

    async def _evict_revoked_viewer(
        self, ws: Any, reason: str = "访问权限已被撤销"
    ) -> None:
        """Immediately send auth_error, close WS with code 4003, and drop from viewers."""
        self.viewers.discard(ws)
        self.viewer_meta.pop(ws, None)
        if not getattr(ws, "closed", False):
            try:
                await ws.send_str(json.dumps({"type": "auth_error", "error": reason}, ensure_ascii=False))
            except Exception:
                pass
            try:
                await ws.close(code=WS_CLOSE_AUTH_FORBIDDEN, message=b"Forbidden")
            except TypeError:
                try:
                    await ws.close()
                except Exception:
                    pass
            except Exception:
                pass

    def _has_eligible_admin_viewer(
        self, owner_bot: str | None, owner_uid: int | None
    ) -> bool:
        if not owner_bot or owner_uid is None or isinstance(owner_uid, bool) or int(owner_uid) <= 0:
            return False
        auth_ctx = _load_auth_context()
        for ws in list(self.viewers):
            if getattr(ws, "closed", False):
                continue
            meta = self.viewer_meta.get(ws) or {}
            bkey = str(meta.get("bot_key") or "")
            uid = int(meta.get("user_id") or 0)
            live_role = _check_live_user_role_from_ctx(bkey, uid, auth_ctx)
            if live_role != "admin":
                continue
            if bkey != owner_bot or uid != int(owner_uid):
                continue
            return True
        return False

    def resolve_bot_key(self, hint: str | None) -> str | None:
        """Resolve a bot key fail-closed (never silently fall back across bots in multi-bot setups)."""
        bots, id_map, _, _, _ = _load_auth_context()
        clean_hint = str(hint or "").strip()
        if clean_hint:
            if clean_hint in bots:
                return clean_hint
            if clean_hint in id_map:
                return id_map[clean_hint]
            return None
        if len(bots) == 1:
            return next(iter(bots.keys()))
        return None

    def _is_active_pinned_verified(self) -> bool:
        """Verify active profile matches the real host canonical pinned directory (rejects forged pinned)."""
        if not (self.active_pinned and self.active_pinned_verified):
            return False
        if self.active_profile_dir is None:
            return False
        try:
            host_pinned = discover_pinned_host_profile()
        except Exception:
            return False
        if host_pinned is None:
            return False
        try:
            return Path(self.active_profile_dir).resolve() == Path(host_pinned["profile_dir"]).resolve()
        except OSError:
            return False

    def state_dict(self) -> dict[str, Any]:
        return {
            "type": "state",
            "running": self.engine_mode != "idle",
            "engine_mode": self.engine_mode,
            "session_gen": self.session_gen,
            "takeover_gen": self.takeover_gen,
            "profile": self.active_profile or None,
            "pinned": self.active_pinned,
            "egress": self.active_egress or "direct",
            "os": self.active_os or "",
            "fingerprint": dict(self.active_fingerprint),
            "takeover": self.takeover,
            "takeover_reason": self.takeover_reason,
            "ai_status": self.ai_status,
            "ai_busy": self.ai_busy_count > 0,
            "url": self.url,
            "title": self.title,
            "vw": self.vw,
            "vh": self.vh,
            "tabs": self.tabs,
            "cursor": self.cursor,
            "quality_preset": self.quality_preset,
            "public_url": self.config.get("public_url") or "",
            "direct_app_url": self.config.get("direct_app_url") or "",
            "viewers": len(self.viewers),
            "profiles": list_profiles(active_profile=self.active_profile),
        }

    def _redacted_state_dict(self) -> dict[str, Any]:
        return {
            "type": "state",
            "running": False,
            "session_restricted": True,
            "restricted_reason": "当前浏览器由其他授权会话占用或仅限本机控制，画面与内容已隔离",
            "engine_mode": "idle",
            "session_gen": self.session_gen,
            "takeover_gen": 0,
            "profile": None,
            "pinned": False,
            "egress": "",
            "os": "",
            "fingerprint": {},
            "takeover": False,
            "takeover_reason": "",
            "ai_status": "🔒 当前浏览器由其他授权会话占用",
            "ai_busy": False,
            "url": "",
            "title": "",
            "vw": 1280,
            "vh": 800,
            "tabs": [],
            "cursor": {},
            "quality_preset": self.quality_preset,
            "public_url": self.config.get("public_url") or "",
            "direct_app_url": self.config.get("direct_app_url") or "",
            "viewers": len(self.viewers),
            "profiles": [],
        }

    def state_dict_for_viewer(self, bot_key: str, user_id: int, role: str) -> dict[str, Any]:
        """Return full state for authorized session readers, or redacted placeholder for isolated viewers."""
        if self.engine_mode == "idle" or self._viewer_can_read_session(bot_key, user_id, role):
            return self.state_dict()
        return self._redacted_state_dict()

    async def broadcast_json(self, obj: dict[str, Any]) -> None:
        if not self.viewers:
            return
        # Capture coherent generation/owner snapshot synchronously BEFORE any await
        snap_gen = self.session_gen
        snap_owner = self.session_owner
        snap_mode = self.engine_mode
        payload = json.dumps(obj, ensure_ascii=False)
        stale: list[web.WebSocketResponse] = []
        for ws in list(self.viewers):
            if self.session_gen != snap_gen or self.session_owner != snap_owner or self.engine_mode != snap_mode:
                break
            if ws.closed:
                stale.append(ws)
                continue
            meta = self.viewer_meta.get(ws)
            if not meta:
                await self._evict_revoked_viewer(ws)
                continue
            bkey = str(meta.get("bot_key") or "")
            uid = int(meta.get("user_id") or 0)
            live_role = _check_live_user_role(bkey, uid)
            if live_role == "denied":
                await self._evict_revoked_viewer(ws)
                continue
            meta["role"] = live_role
            if self.session_gen != snap_gen or self.session_owner != snap_owner or self.engine_mode != snap_mode:
                break
            if not self._viewer_can_read_session(bkey, uid, live_role):
                continue
            try:
                await ws.send_str(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.viewers.discard(ws)
            self.viewer_meta.pop(ws, None)

    async def broadcast_json_to_owners(
        self,
        obj: dict[str, Any],
        *,
        owner_bot: str | None,
        owner_uid: int | None,
        require_admin: bool = True,
        expected_session_gen: int | None = None,
    ) -> None:
        """Broadcast sensitive resource notifications ONLY to live-authorized explicit `(owner_bot, owner_uid)` viewers."""
        if (
            not self.viewers
            or not owner_bot
            or owner_uid is None
            or isinstance(owner_uid, bool)
            or int(owner_uid) <= 0
        ):
            return
        snap_gen = self.session_gen if expected_session_gen is None else expected_session_gen
        if self.session_gen != snap_gen:
            return
        snap_owner = self.session_owner
        payload = json.dumps(obj, ensure_ascii=False)
        stale: list[web.WebSocketResponse] = []
        for ws in list(self.viewers):
            if self.session_gen != snap_gen or self.session_owner != snap_owner:
                break
            if ws.closed:
                stale.append(ws)
                continue
            meta = self.viewer_meta.get(ws)
            if not meta:
                await self._evict_revoked_viewer(ws)
                continue
            bkey = str(meta.get("bot_key") or "")
            uid = int(meta.get("user_id") or 0)
            live_role = _check_live_user_role(bkey, uid)
            if live_role == "denied":
                await self._evict_revoked_viewer(ws)
                continue
            meta["role"] = live_role
            if self.session_gen != snap_gen or self.session_owner != snap_owner:
                break
            if require_admin and live_role != "admin":
                continue
            if bkey != owner_bot or uid != int(owner_uid):
                continue
            try:
                await ws.send_str(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.viewers.discard(ws)
            self.viewer_meta.pop(ws, None)

    async def broadcast_state(self) -> None:
        if not self.viewers:
            return
        # Pack coherent payloads for this exact `(session_gen, session_owner, engine_mode)` synchronously
        snap_gen = self.session_gen
        snap_owner = self.session_owner
        snap_mode = self.engine_mode
        full_payload = json.dumps(self.state_dict(), ensure_ascii=False)
        redacted_payload = json.dumps(self._redacted_state_dict(), ensure_ascii=False)
        stale: list[web.WebSocketResponse] = []
        for ws in list(self.viewers):
            if self.session_gen != snap_gen or self.session_owner != snap_owner or self.engine_mode != snap_mode:
                break
            if ws.closed:
                stale.append(ws)
                continue
            meta = self.viewer_meta.get(ws)
            if not meta:
                await self._evict_revoked_viewer(ws)
                continue
            bkey = str(meta.get("bot_key") or "")
            uid = int(meta.get("user_id") or 0)
            live_role = _check_live_user_role(bkey, uid)
            if live_role == "denied":
                await self._evict_revoked_viewer(ws)
                continue
            meta["role"] = live_role
            if self.session_gen != snap_gen or self.session_owner != snap_owner or self.engine_mode != snap_mode:
                break
            if snap_mode == "idle" or self._viewer_can_read_session(bkey, uid, live_role):
                out_str = full_payload
            else:
                out_str = redacted_payload
            try:
                await ws.send_str(out_str)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.viewers.discard(ws)
            self.viewer_meta.pop(ws, None)

    async def broadcast_frame(self, jpeg_bytes: bytes) -> None:
        if self.engine_mode == "idle":
            return
        snap_gen = self.session_gen
        snap_owner = self.session_owner
        snap_mode = self.engine_mode
        self.latest_jpeg = jpeg_bytes
        if not self.viewers:
            return
        stale: list[web.WebSocketResponse] = []
        for ws in list(self.viewers):
            if self.session_gen != snap_gen or self.session_owner != snap_owner or self.engine_mode != snap_mode:
                break
            if ws.closed:
                stale.append(ws)
                continue
            meta = self.viewer_meta.get(ws)
            if not meta:
                await self._evict_revoked_viewer(ws)
                continue
            bkey = str(meta.get("bot_key") or "")
            uid = int(meta.get("user_id") or 0)
            live_role = _check_live_user_role(bkey, uid)
            if live_role == "denied":
                await self._evict_revoked_viewer(ws)
                continue
            meta["role"] = live_role
            if self.session_gen != snap_gen or self.session_owner != snap_owner or self.engine_mode != snap_mode:
                break
            if not self._viewer_can_read_session(bkey, uid, live_role):
                continue
            # Drop frame for slow client if transport buffer > 512 KiB to prevent latency buildup
            transport = getattr(ws, "_writer", None)
            if transport and getattr(transport, "transport", None):
                buf_size = transport.transport.get_write_buffer_size()
                if buf_size > 524288:
                    continue
            try:
                await ws.send_bytes(jpeg_bytes)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.viewers.discard(ws)
            self.viewer_meta.pop(ws, None)

    def _drain_input_queue(self) -> int:
        dropped = 0
        while not self.input_queue.empty():
            try:
                self.input_queue.get_nowait()
                dropped += 1
            except asyncio.QueueEmpty:
                break
        return dropped

    def _enqueue_sync_cmd(self, cmd: dict[str, Any]) -> None:
        """Append command to bounded `sync_cmd_queue`, dropping oldest move/wheel first when full."""
        act = cmd.get("action")
        if act == "mousedown":
            btn = str(cmd.get("button") or "left")
            self._sync_buttons_down.add(btn if btn in ("left", "right", "middle") else "left")
        elif act == "mouseup":
            btn = str(cmd.get("button") or "left")
            self._sync_buttons_down.discard(btn if btn in ("left", "right", "middle") else "left")

        if len(self.sync_cmd_queue) >= SYNC_CMD_QUEUE_MAX:
            drop_idx: int | None = None
            for i, existing in enumerate(self.sync_cmd_queue):
                if existing.get("action") in ("move", "wheel"):
                    drop_idx = i
                    break
            if drop_idx is None:
                for i, existing in enumerate(self.sync_cmd_queue):
                    if existing.get("action") != "mouseup":
                        drop_idx = i
                        break
            if drop_idx is not None:
                self.sync_cmd_queue.pop(drop_idx)
            else:
                self.sync_cmd_queue.pop(0)
        self.sync_cmd_queue.append(cmd)

    async def _release_held_mouse_buttons_locked(self) -> list[str]:
        """Server-side fallback releasing any held mouse buttons (caller MUST hold `self._exec_lock`)."""
        released: list[str] = []
        buttons = list(self._mouse_buttons_down)
        self._mouse_buttons_down.clear()
        if buttons and self.engine_mode == "async_hosted":
            page = self._current_page()
            if page is not None:
                for btn in buttons:
                    try:
                        await asyncio.wait_for(page.mouse.up(button=btn), timeout=1.5)
                        released.append(btn)
                    except Exception as exc:
                        log.debug("Fallback mouse.up(%s) error: %s", btn, exc)
        return released

    async def set_takeover(
        self,
        active: bool,
        reason: str = "",
        *,
        owner: tuple[str, int | None] | None = None,
        expected_session_gen: int | None = None,
        expected_takeover_gen: int | None = None,
        actor: tuple[str, int] | None = None,
        card_message_id: int | None = None,
        require_card: bool = False,
    ) -> tuple[bool, str, int, int]:
        want_active = bool(active)
        async with self._takeover_lock:
            if expected_session_gen is not None and self.session_gen != expected_session_gen:
                return False, "会话代次已变更，已拒绝过期接管/交还请求", self.session_gen, self.takeover_gen
            if expected_takeover_gen is not None and self.takeover_gen != expected_takeover_gen:
                return False, "接管代次已变更，已拒绝过期接管/交还请求", self.session_gen, self.takeover_gen
            if want_active and self.engine_mode == "idle" and (actor is not None or require_card):
                return False, "当前浏览器未运行", self.session_gen, self.takeover_gen
            if actor is not None:
                a_bot, a_uid = actor
                if require_card:
                    ok_v, msg_v, _ = self.tg.verify_card_control(
                        a_bot,
                        a_uid,
                        message_id=card_message_id,
                        require_card=True,
                        require_running=True,
                        expected_session_gen=expected_session_gen,
                    )
                    if not ok_v:
                        return False, msg_v, self.session_gen, self.takeover_gen
                else:
                    live_role = _check_live_user_role(a_bot, a_uid)
                    if live_role != "admin":
                        return False, "当前用户未授权或权限已撤销", self.session_gen, self.takeover_gen
                    if not self._viewer_can_control_takeover(a_bot, a_uid, live_role):
                        return False, "🔒 当前浏览器会话由其他 Bot/用户持有，无权接管或释放", self.session_gen, self.takeover_gen

            self.mark_active()
            if want_active:
                self.takeover_gen += 1
                self.takeover = True
                self.takeover_owner = owner if owner is not None else self.session_owner
                self.takeover_reason = reason or "人工接管中（AI 已挂起等待）"
                self.ai_allowed_event.clear()
                # Barrier: wait for any in-flight AI action under `_exec_lock` to complete
                async with self._exec_lock:
                    pass
                log.info("Takeover ENABLED (gen=%d owner=%s): %s", self.takeover_gen, self.takeover_owner, self.takeover_reason)
            else:
                # 1. Advance takeover generation & disallow new human inputs immediately
                self.takeover_gen += 1
                self.takeover = False
                self.takeover_owner = None
                self.takeover_reason = ""
                # 2. Drain queued stale human inputs
                self._drain_input_queue()
                # 3. Acquire execution barrier so in-flight human cmd finishes, then release held mouse buttons
                async with self._exec_lock:
                    await self._release_held_mouse_buttons_locked()
                    if self.engine_mode == "sync_external":
                        self.sync_cmd_queue.clear()
                        for btn in list(self._sync_buttons_down):
                            self.sync_cmd_queue.append(
                                {
                                    "action": "mouseup",
                                    "button": btn,
                                    "x": 0,
                                    "y": 0,
                                    "session_gen": self.session_gen,
                                    "takeover_gen": self.takeover_gen,
                                    "cleanup": True,
                                    "_server_internal": True,
                                }
                            )
                        self._sync_buttons_down.clear()
                log.info("Takeover RELEASED (gen=%d) -> AI resumed", self.takeover_gen)
            # Atomic invariant enforcement before releasing `_takeover_lock`
            if self.takeover:
                self.ai_allowed_event.clear()
            else:
                self.ai_allowed_event.set()
            res_sgen = self.session_gen
            res_tgen = self.takeover_gen
        await self.broadcast_state()
        asyncio.create_task(self.tg.tick_updates(force=True))
        return True, "ok", res_sgen, res_tgen

    async def wait_until_ai_allowed(self, timeout: float = 900.0) -> None:
        if self.takeover:
            await asyncio.wait_for(self.ai_allowed_event.wait(), timeout=timeout)

    # ---------------- Native Page Listeners (Dialog / FileChooser / Download) ----------------

    def _schedule_google_block_toast(
        self,
        blocked_url: str,
        *,
        origin_session_gen: int | None = None,
        owner_bot: str | None = None,
        owner_uid: int | None = None,
    ) -> None:
        msg = (
            "安全策略拦截：此主机已锁定 Pinned Google Profile，禁止非 Pinned Profile 访问 Google/Gmail/YouTube 域。"
        )
        try:
            loop = asyncio.get_running_loop()
            if owner_bot is None and owner_uid is None:
                owner_bot, owner_uid = self._effective_resource_owner()
            gen = self.session_gen if origin_session_gen is None else origin_session_gen
            if owner_bot is not None and owner_uid is not None:
                self._track_bg_task(
                    loop.create_task(
                        self.broadcast_json_to_owners(
                            {"type": "toast", "message": msg},
                            owner_bot=owner_bot,
                            owner_uid=owner_uid,
                            require_admin=False,
                            expected_session_gen=gen,
                        )
                    )
                )
        except RuntimeError:
            pass

    async def _enforce_non_pinned_blank(
        self,
        page: Any,
        blocked_url: str,
        *,
        origin_session_gen: int | None = None,
        owner_bot: str | None = None,
        owner_uid: int | None = None,
    ) -> None:
        gen = self.session_gen if origin_session_gen is None else origin_session_gen
        if gen != self.session_gen:
            return
        self._schedule_google_block_toast(
            blocked_url,
            origin_session_gen=gen,
            owner_bot=owner_bot,
            owner_uid=owner_uid,
        )
        try:
            is_closed_fn = getattr(page, "is_closed", None)
            if callable(is_closed_fn) and is_closed_fn():
                return
            await page.goto("about:blank", wait_until="domcontentloaded", timeout=10000)
        except Exception as exc:
            log.debug("Failed redirecting blocked non-pinned Google page to about:blank: %s", exc)

    async def _install_non_pinned_google_guard(
        self,
        ctx: Any,
        *,
        is_pinned_verified: bool | None = None,
    ) -> None:
        """Install context-level Playwright route interceptor blocking Google navigations on non-pinned contexts.

        Fail-closed: raises RuntimeError if host has a pinned profile and context route interception cannot be installed.
        """
        pinned_ok = self._is_active_pinned_verified() if is_pinned_verified is None else bool(is_pinned_verified)
        if pinned_ok:
            return
        try:
            has_pinned = discover_pinned_host_profile() is not None
        except Exception:
            has_pinned = True  # fail-closed
        if not has_pinned:
            return
        route_fn = getattr(ctx, "route", None)
        if not callable(route_fn):
            raise RuntimeError("非 Pinned 浏览器上下文不支持 ctx.route 导航拦截，已拒绝启动（fail-closed）")

        async def _route_google_guard(route: Any, request: Any | None = None) -> None:
            origin_gen = self.session_gen
            origin_owner_bot, origin_owner_uid = self._effective_resource_owner()
            req = request if request is not None else getattr(route, "request", None)
            url = str(getattr(req, "url", "") or "")
            is_nav_attr = getattr(req, "is_navigation_request", None)
            is_nav = bool(is_nav_attr()) if callable(is_nav_attr) else bool(is_nav_attr)
            res_type = str(getattr(req, "resource_type", "") or "").lower()
            if (is_nav or res_type == "document") and is_google_destination_url(url):
                log.warning("Blocked non-pinned navigation via ctx.route to Google domain: %s", url[:120])
                try:
                    await route.abort("blockedbyclient")
                except TypeError:
                    await route.abort()
                self._schedule_google_block_toast(
                    url,
                    origin_session_gen=origin_gen,
                    owner_bot=origin_owner_bot,
                    owner_uid=origin_owner_uid,
                )
                return
            await route.continue_()

        try:
            await route_fn("**/*", _route_google_guard)
        except Exception as exc:
            raise RuntimeError(f"非 Pinned 导航防护安装失败，已中止启动（fail-closed）: {exc}") from exc

    def _attach_page_listeners(self, page: Any, *, require_nav_guard: bool = False) -> None:
        """Attach native Playwright listeners for metadata dirtying, Google guard, dialog, filechooser & download."""
        pid = id(page)
        if pid in self._attached_pages:
            return
        strict_guard = bool(require_nav_guard)
        if not strict_guard and self.engine_mode == "async_hosted" and not self._is_active_pinned_verified():
            try:
                strict_guard = discover_pinned_host_profile() is not None
            except Exception:
                strict_guard = True  # fail-closed

        on_fn = getattr(page, "on", None)
        if not callable(on_fn):
            if strict_guard:
                raise RuntimeError("非 Pinned 浏览器页面不支持 page.on('framenavigated') 监听，已拒绝启动（fail-closed）")
            return
        self._attached_pages.add(pid)

        def _mark_dirty(*_args: Any) -> None:
            self._tab_select_rev += 1
            self.mark_active(mark_tabs_dirty=True)

        def _on_framenavigated(frame: Any = None, *_args: Any) -> None:
            origin_gen = self.session_gen
            origin_owner_bot, origin_owner_uid = self._effective_resource_owner()
            self._tab_select_rev += 1
            self.mark_active(mark_tabs_dirty=True)
            if self._is_active_pinned_verified():
                return
            frame_url = str(getattr(frame, "url", None) or getattr(page, "url", "") or "")
            if frame_url and is_google_destination_url(frame_url):
                try:
                    has_pinned = discover_pinned_host_profile() is not None
                except Exception:
                    has_pinned = True  # fail-closed
                if has_pinned:
                    log.warning("Fallback framenavigated blocked non-pinned Google URL: %s", frame_url[:120])
                    try:
                        loop = asyncio.get_running_loop()
                        self._track_bg_task(
                            loop.create_task(
                                self._enforce_non_pinned_blank(
                                    page,
                                    frame_url,
                                    origin_session_gen=origin_gen,
                                    owner_bot=origin_owner_bot,
                                    owner_uid=origin_owner_uid,
                                )
                            )
                        )
                    except RuntimeError:
                        pass

        def _on_close(*_args: Any) -> None:
            self._attached_pages.discard(pid)
            was_quarantined = pid in self._closing_unguarded_pages
            if not was_quarantined and self._explicit_close_tab_in_flight <= 0:
                self._tab_select_rev += 1
            self._tabs_dirty = True
            try:
                loop = asyncio.get_running_loop()
                self._track_bg_task(loop.create_task(self._cleanup_pending_filechoosers_async(page_id=pid)))
                self._track_bg_task(loop.create_task(self._cleanup_pending_dialogs(page_id=pid)))
            except RuntimeError:
                self._cleanup_pending_filechoosers(page_id=pid)

        def _on_dialog(dialog: Any) -> None:
            origin_gen = self.session_gen
            origin_owner_bot, origin_owner_uid = self._effective_resource_owner()
            try:
                loop = asyncio.get_running_loop()
                self._track_bg_task(
                    loop.create_task(
                        self._handle_page_dialog(
                            dialog,
                            page,
                            origin_session_gen=origin_gen,
                            owner_bot=origin_owner_bot,
                            owner_uid=origin_owner_uid,
                        )
                    )
                )
            except RuntimeError:
                pass

        def _on_filechooser(chooser: Any) -> None:
            origin_gen = self.session_gen
            origin_owner_bot, origin_owner_uid = self._effective_resource_owner()
            try:
                loop = asyncio.get_running_loop()
                self._track_bg_task(
                    loop.create_task(
                        self._handle_page_filechooser(
                            chooser,
                            page,
                            origin_session_gen=origin_gen,
                            owner_bot=origin_owner_bot,
                            owner_uid=origin_owner_uid,
                        )
                    )
                )
            except RuntimeError:
                pass

        def _on_download(download: Any) -> None:
            gen = self.session_gen
            owner_bot, owner_uid = self._effective_resource_owner()
            try:
                loop = asyncio.get_running_loop()
                self._track_bg_task(
                    loop.create_task(
                        self._handle_page_download(
                            download,
                            page,
                            session_gen=gen,
                            owner_bot=owner_bot,
                            owner_uid=owner_uid,
                        )
                    )
                )
            except RuntimeError:
                pass

        def _on_response(response: Any) -> None:
            try:
                r_url = str(getattr(response, "url", "") or "")
                hdrs = getattr(response, "headers", None)
                if r_url and isinstance(hdrs, dict):
                    raw_cl = hdrs.get("content-length") or hdrs.get("Content-Length") or ""
                    if str(raw_cl).strip().isdigit():
                        if len(self._recent_response_cl) >= 256:
                            self._recent_response_cl.clear()
                        self._recent_response_cl[r_url] = int(str(raw_cl).strip())
            except Exception:
                pass

        try:
            on_fn("framenavigated", _on_framenavigated)
        except Exception as exc:
            self._attached_pages.discard(pid)
            if strict_guard:
                raise RuntimeError(f"非 Pinned 导航监听 framenavigated 注册失败（fail-closed）: {exc}") from exc
            log.debug("Failed attaching framenavigated listener: %s", exc)
            return

        for ev_name, handler in (
            ("load", _mark_dirty),
            ("close", _on_close),
            ("dialog", _on_dialog),
            ("filechooser", _on_filechooser),
            ("download", _on_download),
            ("response", _on_response),
        ):
            try:
                on_fn(ev_name, handler)
            except Exception as exc:
                log.debug("Failed attaching secondary page listener %s: %s", ev_name, exc)

    def _schedule_fail_closed_close_unguarded_page(
        self,
        new_page: Any,
        *,
        expected_ctx: Any = None,
        startup_ctx_id: int | None = None,
        bump_tab_rev: bool = True,
    ) -> asyncio.Task[Any] | None:
        """Synchronously quarantine `new_page` and deduplicate fail-closed close into a single task per page id.

        Never acquires `_engine_lock` synchronously or inside `_exec_lock`.
        """
        pid = id(new_page)
        self._closing_unguarded_pages.add(pid)
        existing = self._unguarded_close_tasks.get(pid)
        if existing is not None and not existing.done():
            return existing
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            close_fn = getattr(new_page, "close", None)
            close_ok = self._is_page_closed(new_page)
            if not close_ok and callable(close_fn):
                try:
                    res = close_fn()
                    if inspect.isawaitable(res):
                        res.close()
                    else:
                        close_ok = True
                except Exception:
                    close_ok = False
            if not close_ok and startup_ctx_id is not None:
                self._startup_guard_failed_ctx.add(startup_ctx_id)
            return None

        task = self._track_bg_task(
            loop.create_task(
                self._fail_closed_close_unguarded_page(
                    new_page,
                    expected_ctx=expected_ctx,
                    startup_ctx_id=startup_ctx_id,
                    bump_tab_rev=bump_tab_rev,
                )
            )
        )
        self._unguarded_close_tasks[pid] = task
        task.add_done_callback(lambda _t, _pid=pid: self._unguarded_close_tasks.pop(_pid, None))
        return task

    async def _fail_closed_close_unguarded_page(
        self,
        new_page: Any,
        *,
        expected_ctx: Any = None,
        startup_ctx_id: int | None = None,
        bump_tab_rev: bool = True,
    ) -> None:
        """Fail-closed cleanup when a page cannot install its navigation guard or is revoked during new_tab.

        Closes the quarantined page immediately; if closing fails, marks any unpublished startup ctx
        synchronously and aborts a published hosted session under `_engine_lock` (never called while
        holding `_exec_lock`).
        """
        pid = id(new_page)
        self._closing_unguarded_pages.add(pid)
        close_ok = False
        try:
            if self._is_page_closed(new_page):
                close_ok = True
            else:
                close_fn = getattr(new_page, "close", None)
                if callable(close_fn):
                    res = close_fn()
                    if inspect.isawaitable(res):
                        await asyncio.wait_for(res, timeout=5.0)
                    close_ok = True
        except Exception as close_exc:
            log.error("Fail-closed close of quarantined page failed: %s", close_exc)
        if not close_ok:
            if startup_ctx_id is not None:
                self._startup_guard_failed_ctx.add(startup_ctx_id)
            # If the context has not been published yet (`self.ctx is not expected_ctx`),
            # `start_hosted()` will abort directly inside its own `_engine_lock` via `_startup_guard_failed_ctx`.
            if expected_ctx is not None and self.ctx is not expected_ctx:
                log.error(
                    "Marked unpublished startup context fail-closed after quarantined page could not be closed"
                )
                return
            log.error("Aborting hosted session fail-closed after quarantined page could not be closed")
            try:
                async with self._engine_lock:
                    if expected_ctx is None or self.ctx is expected_ctx:
                        await self._stop_hosted_locked(notify_finished=True)
            except Exception as stop_exc:
                log.error("Fail-closed hosted session abort error: %s", stop_exc)
            return
        if bump_tab_rev:
            self._tab_select_rev += 1
        self.mark_active(mark_tabs_dirty=True)

    async def _handle_page_dialog(
        self,
        dialog: Any,
        page: Any | None = None,
        *,
        origin_session_gen: int | None = None,
        owner_bot: str | None = None,
        owner_uid: int | None = None,
    ) -> None:
        dlg_gen = self.session_gen if origin_session_gen is None else origin_session_gen
        dtype = str(getattr(dialog, "type", "alert") or "alert")
        message = str(getattr(dialog, "message", "") or "")
        default_val = str(getattr(dialog, "default_value", "") or "")
        if owner_bot is None and owner_uid is None:
            owner_bot, owner_uid = self._effective_resource_owner()

        if dlg_gen != self.session_gen or (
            not self._has_eligible_admin_viewer(owner_bot, owner_uid) and not self.takeover
        ):
            log.info("Auto-dismissing dialog (%s) with stale gen or no eligible admin viewers/takeover", dtype)
            try:
                await dialog.dismiss()
            except Exception as exc:
                log.debug("Auto-dismiss dialog error: %s", exc)
            return

        dialog_id = secrets.token_hex(8)
        entry: dict[str, Any] = {
            "id": dialog_id,
            "dialog": dialog,
            "page_id": id(page) if page is not None else None,
            "dialog_type": dtype,
            "message": message[:2000],
            "default_value": default_val[:500],
            "created_ts": time.monotonic(),
            "session_gen": dlg_gen,
            "owner_bot": owner_bot,
            "owner_uid": owner_uid,
            "resolved": False,
        }
        self.pending_dialogs[dialog_id] = entry
        self.mark_active()

        # Register timeout guard BEFORE broadcasting so broadcast failure can never leave an unguarded dialog
        async def _timeout_guard() -> None:
            await asyncio.sleep(DIALOG_TIMEOUT_SECONDS)
            if dialog_id in self.pending_dialogs:
                log.info("Dialog %s timed out; auto-dismissing", dialog_id)
                await self.resolve_dialog(dialog_id, accept=False)

        try:
            entry["timeout_task"] = asyncio.create_task(_timeout_guard())
        except RuntimeError:
            pass

        payload = {
            "type": "dialog_open",
            "dialog_id": dialog_id,
            "dialog_type": dtype,
            "message": entry["message"],
            "default_value": entry["default_value"],
        }
        if owner_bot is not None and owner_uid is not None:
            await self.broadcast_json_to_owners(
                payload,
                owner_bot=owner_bot,
                owner_uid=owner_uid,
                require_admin=True,
                expected_session_gen=entry.get("session_gen"),
            )

    async def resolve_dialog(
        self, dialog_id: str, accept: bool, prompt_text: str | None = None
    ) -> bool:
        entry = self.pending_dialogs.pop(dialog_id, None)
        if not entry or entry.get("resolved"):
            return False
        entry["resolved"] = True
        tt = entry.get("timeout_task")
        cur_task: asyncio.Task[Any] | None = None
        try:
            cur_task = asyncio.current_task()
        except RuntimeError:
            cur_task = None
        if tt and not tt.done() and tt is not cur_task:
            tt.cancel()
        dialog = entry["dialog"]
        try:
            if accept:
                if entry.get("dialog_type") == "prompt":
                    await dialog.accept(str(prompt_text or ""))
                else:
                    await dialog.accept()
            else:
                await dialog.dismiss()
        except Exception as exc:
            log.debug("resolve_dialog (%s) error: %s", dialog_id, exc)
        finally:
            closed_msg = {"type": "dialog_closed", "dialog_id": dialog_id}
            if entry.get("owner_bot") is not None and entry.get("owner_uid") is not None:
                await self.broadcast_json_to_owners(
                    closed_msg,
                    owner_bot=entry.get("owner_bot"),
                    owner_uid=entry.get("owner_uid"),
                    require_admin=True,
                    expected_session_gen=entry.get("session_gen"),
                )
        self.mark_active(mark_tabs_dirty=True)
        if self.engine_mode == "async_hosted":
            await self._capture_once(force_broadcast=True)
            await self.broadcast_state()
        return True

    async def _cleanup_pending_dialogs(self, *, page_id: int | None = None) -> None:
        to_remove = [
            did
            for did, info in list(self.pending_dialogs.items())
            if page_id is None or info.get("page_id") == page_id
        ]
        cur_task: asyncio.Task[Any] | None = None
        try:
            cur_task = asyncio.current_task()
        except RuntimeError:
            cur_task = None
        for did in to_remove:
            entry = self.pending_dialogs.pop(did, None)
            if not entry or entry.get("resolved"):
                continue
            entry["resolved"] = True
            tt = entry.get("timeout_task")
            if tt and not tt.done() and tt is not cur_task:
                tt.cancel()
            try:
                await entry["dialog"].dismiss()
            except Exception:
                pass
            closed_msg = {"type": "dialog_closed", "dialog_id": did}
            if entry.get("owner_bot") is not None and entry.get("owner_uid") is not None:
                await self.broadcast_json_to_owners(
                    closed_msg,
                    owner_bot=entry.get("owner_bot"),
                    owner_uid=entry.get("owner_uid"),
                    require_admin=True,
                    expected_session_gen=entry.get("session_gen"),
                )

    async def _dismiss_orphaned_dialogs_on_disconnect(self) -> None:
        """Auto-dismiss any pending dialog that no longer has an eligible connected admin viewer."""
        for did, info in list(self.pending_dialogs.items()):
            if not self._has_eligible_admin_viewer(info.get("owner_bot"), info.get("owner_uid")):
                log.info("Auto-dismissing orphaned dialog %s after eligible admin disconnect", did)
                await self.resolve_dialog(did, accept=False)

    async def _handle_page_filechooser(
        self,
        chooser: Any,
        page: Any | None = None,
        *,
        origin_session_gen: int | None = None,
        owner_bot: str | None = None,
        owner_uid: int | None = None,
    ) -> None:
        fc_gen = self.session_gen if origin_session_gen is None else origin_session_gen
        if fc_gen != self.session_gen:
            return
        chooser_id = secrets.token_hex(8)
        multiple = False
        try:
            is_mult = getattr(chooser, "is_multiple", None)
            multiple = bool(is_mult() if callable(is_mult) else is_mult)
        except Exception:
            multiple = False
        if owner_bot is None and owner_uid is None:
            owner_bot, owner_uid = self._effective_resource_owner()
        self.pending_filechoosers[chooser_id] = {
            "id": chooser_id,
            "chooser": chooser,
            "page_id": id(page) if page is not None else None,
            "multiple": multiple,
            "created_ts": time.monotonic(),
            "session_gen": fc_gen,
            "owner_bot": owner_bot,
            "owner_uid": owner_uid,
        }
        self.mark_active()
        if owner_bot is not None:
            await self.broadcast_json_to_owners(
                {
                    "type": "filechooser_open",
                    "chooser_id": chooser_id,
                    "multiple": multiple,
                },
                owner_bot=owner_bot,
                owner_uid=owner_uid,
                require_admin=True,
                expected_session_gen=fc_gen,
            )

    def _cleanup_pending_filechoosers(self, *, page_id: int | None = None) -> list[dict[str, Any]]:
        now = time.monotonic()
        removed: list[dict[str, Any]] = []
        for cid, info in list(self.pending_filechoosers.items()):
            expired = (now - float(info.get("created_ts", 0.0))) > TRANSFER_TTL_SECONDS
            stale_gen = info.get("session_gen") != self.session_gen
            if page_id is None or info.get("page_id") == page_id or expired or stale_gen:
                popped = self.pending_filechoosers.pop(cid, None)
                if popped:
                    removed.append(popped)
        return removed

    async def _cleanup_pending_filechoosers_async(self, *, page_id: int | None = None) -> None:
        removed = self._cleanup_pending_filechoosers(page_id=page_id)
        for info in removed:
            msg = {"type": "filechooser_closed", "chooser_id": info["id"]}
            if info.get("owner_bot") is not None:
                await self.broadcast_json_to_owners(
                    msg,
                    owner_bot=info.get("owner_bot"),
                    owner_uid=info.get("owner_uid"),
                    require_admin=True,
                    expected_session_gen=info.get("session_gen"),
                )

    async def _handle_page_download(
        self,
        download: Any,
        _page: Any | None = None,
        *,
        session_gen: int | None = None,
        owner_bot: str | None = None,
        owner_uid: int | None = None,
    ) -> None:
        gen = self.session_gen if session_gen is None else session_gen
        if owner_bot is None and owner_uid is None:
            owner_bot, owner_uid = self._effective_resource_owner()
        if gen != self.session_gen:
            return

        download_id = secrets.token_hex(8)
        raw_name = str(getattr(download, "suggested_filename", "") or "download.bin")
        safe_name = _sanitize_filename(raw_name, fallback="download.bin")
        xfer_dir = self._ensure_transfer_dir()
        dl_subdir = xfer_dir / f"dl-{download_id}"
        dl_subdir.mkdir(parents=True, exist_ok=True)
        os.chmod(dl_subdir, 0o700)
        tmp_part = dl_subdir / ".downloading.part"
        dest_path = dl_subdir / safe_name

        async def _abort_download_artifact() -> None:
            for meth_name in ("cancel", "delete"):
                fn = getattr(download, meth_name, None)
                if callable(fn):
                    try:
                        await asyncio.wait_for(fn(), timeout=1.0)
                    except Exception:
                        pass

        oversized = False
        size = 0
        # Early Content-Length pre-check: cancel immediately before save_as if known size exceeds server cache cap
        declared_cl: int | None = None
        raw_dl_cl = getattr(download, "content_length", None)
        if raw_dl_cl is not None and str(raw_dl_cl).strip().isdigit():
            declared_cl = int(str(raw_dl_cl).strip())
        if declared_cl is None:
            dl_hdrs = getattr(download, "headers", None)
            if isinstance(dl_hdrs, dict):
                hv = dl_hdrs.get("content-length") or dl_hdrs.get("Content-Length") or ""
                if str(hv).strip().isdigit():
                    declared_cl = int(str(hv).strip())
        if declared_cl is None:
            dl_url = str(getattr(download, "url", "") or "")
            if dl_url and dl_url in self._recent_response_cl:
                declared_cl = self._recent_response_cl.get(dl_url)
        if declared_cl is not None and declared_cl > MAX_DOWNLOAD_BYTES:
            oversized = True
            size = declared_cl
            await _abort_download_artifact()

        try:
            if oversized:
                pass
            else:
                # Prefer bounded streaming copy if download exposes an async chunk stream; otherwise watch save_as live
                stream_fn = getattr(download, "read_chunks", None)
                if callable(stream_fn):
                    with open(tmp_part, "wb") as fh:
                        async for chunk in stream_fn():
                            if not chunk:
                                continue
                            size += len(chunk)
                            if size > MAX_DOWNLOAD_BYTES:
                                oversized = True
                                break
                            fh.write(chunk)
                    if oversized:
                        await _abort_download_artifact()
                else:
                    save_task = asyncio.create_task(download.save_as(str(tmp_part)))

                    async def _watch_part_size() -> None:
                        nonlocal oversized
                        while not save_task.done():
                            try:
                                if tmp_part.is_file() and tmp_part.stat().st_size > MAX_DOWNLOAD_BYTES:
                                    oversized = True
                                    await _abort_download_artifact()
                                    save_task.cancel()
                                    tmp_part.unlink(missing_ok=True)
                                    return
                            except OSError:
                                pass
                            await asyncio.sleep(0.015)

                    watcher = asyncio.create_task(_watch_part_size())
                    try:
                        await save_task
                    except asyncio.CancelledError:
                        if not oversized:
                            watcher.cancel()
                            await _abort_download_artifact()
                            shutil.rmtree(dl_subdir, ignore_errors=True)
                            raise
                    finally:
                        if not watcher.done():
                            watcher.cancel()
                            try:
                                await watcher
                            except (asyncio.CancelledError, Exception):
                                pass

                    if not oversized and tmp_part.is_file():
                        size = tmp_part.stat().st_size
                        if size > MAX_DOWNLOAD_BYTES:
                            oversized = True
                            await _abort_download_artifact()
        except asyncio.CancelledError:
            shutil.rmtree(dl_subdir, ignore_errors=True)
            raise
        except Exception as exc:
            log.warning("Download save_as failed (%s): %s", safe_name, exc)
            await _abort_download_artifact()
            shutil.rmtree(dl_subdir, ignore_errors=True)
            if owner_bot is not None:
                await self.broadcast_json_to_owners(
                    {"type": "toast", "message": f"❌ 下载失败: {safe_name}"},
                    owner_bot=owner_bot,
                    owner_uid=owner_uid,
                    require_admin=True,
                    expected_session_gen=gen,
                )
            return

        if oversized or size > MAX_DOWNLOAD_BYTES:
            log.warning(
                "Download %s exceeded MAX_DOWNLOAD_BYTES (%d > %d); aborted and purged",
                safe_name,
                size,
                MAX_DOWNLOAD_BYTES,
            )
            shutil.rmtree(dl_subdir, ignore_errors=True)
            if owner_bot is not None:
                await self.broadcast_json_to_owners(
                    {
                        "type": "toast",
                        "message": f"❌ 下载文件超过 {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MiB 服务端单文件上限，已中止并清理: {safe_name}",
                    },
                    owner_bot=owner_bot,
                    owner_uid=owner_uid,
                    require_admin=True,
                    expected_session_gen=gen,
                )
            return

        # Re-check session generation after async save_as (prevent stale session write)
        if gen != self.session_gen or not tmp_part.is_file():
            shutil.rmtree(dl_subdir, ignore_errors=True)
            return

        try:
            os.chmod(tmp_part, 0o600)
            tmp_part.replace(dest_path)
        except OSError:
            shutil.rmtree(dl_subdir, ignore_errors=True)
            return

        info = {
            "id": download_id,
            "filename": safe_name,
            "path": dest_path,
            "size": size,
            "created_ts": time.monotonic(),
            "session_gen": gen,
            "owner_bot": owner_bot,
            "owner_uid": owner_uid,
            "auto_sent": False,
        }
        self.downloads[download_id] = info
        self.mark_active()

        auto_sent = False
        if 0 < size <= MAX_TG_DOWNLOAD_BYTES and owner_bot is not None:
            caption = f"📥 <b>浏览器下载文件</b>\n<code>{html.escape(safe_name)}</code> ({size:,} B)"
            auto_sent = await self.tg.send_document_file(
                owner_bot, dest_path, safe_name, caption=caption, preferred_user_id=owner_uid
            )
            info["auto_sent"] = auto_sent

        if owner_bot is not None:
            await self.broadcast_json_to_owners(
                {
                    "type": "download_ready",
                    "download_id": download_id,
                    "filename": safe_name,
                    "size": size,
                    "auto_sent": auto_sent,
                },
                owner_bot=owner_bot,
                owner_uid=owner_uid,
                require_admin=True,
                expected_session_gen=gen,
            )

    async def send_download_to_tg(
        self,
        download_id: str,
        bot_key: str,
        preferred_user_id: int | None = None,
        *,
        role: str = "admin",
    ) -> tuple[bool, str]:
        info = self.downloads.get(download_id)
        if not info:
            return False, "下载文件已过期或不存在"
        uid = int(preferred_user_id or 0)
        if not self._can_access_resource(info, bot_key, uid, role, require_admin=True):
            return False, "🔒 无权操作该下载文件或会话已过期"
        path = Path(info["path"])
        if not path.is_file():
            self.downloads.pop(download_id, None)
            return False, "下载文件已被清理"
        size = int(info.get("size") or path.stat().st_size)
        if size > MAX_TG_DOWNLOAD_BYTES:
            return False, f"文件超过 {MAX_TG_DOWNLOAD_BYTES // (1024 * 1024)} MiB 限制，请直接从面板下载"
        fname = str(info["filename"])
        ok = await self.tg.send_document_file(
            bot_key,
            path,
            fname,
            caption=f"📥 <b>浏览器下载文件</b>\n<code>{html.escape(fname)}</code> ({size:,} B)",
            preferred_user_id=preferred_user_id,
        )
        return (True, "✅ 已发送到私聊 Telegram") if ok else (False, "发送文件到 Telegram 失败")

    # ---------------- Hosted AsyncCamoufox Lifecycle ----------------

    def _clear_session_caches(self) -> None:
        """Clear all frame/URL/title/clipboard/cursor/tab caches so stale data never leaks across sessions."""
        self.latest_jpeg = None
        self.latest_clip = {}
        self._last_x11_clip = ""
        self.url = ""
        self.title = ""
        self.tabs = []
        self.cursor = {}
        self.ai_status = ""
        self.x11_display = None
        self.active_profile = ""
        self.active_profile_dir = None
        self.active_pinned = False
        self.active_pinned_verified = False
        self.active_egress = "direct"
        self.active_os = ""
        self.active_fingerprint = {}
        self._attached_pages.clear()
        self._closing_unguarded_pages.clear()
        self._unguarded_close_tasks.clear()
        self._startup_guard_failed_ctx.clear()
        self._explicit_new_tab_in_flight = 0
        self._explicit_close_tab_in_flight = 0
        self._recent_response_cl.clear()
        self._tabs_dirty = True
        self._tab_select_rev += 1
        self._last_normal_sig = None
        self._hd_settled = False
        self._unchanged_frames = 0
        self._hd_pending = False
        self._meta_changed_pending = False
        self.session_owner = None
        self.takeover_owner = None
        self.takeover = False
        self.takeover_reason = ""
        self._sync_lease_id = None
        self._mouse_buttons_down.clear()
        self._sync_buttons_down.clear()
        self._pending_sync_extracts.clear()

    async def _stop_hosted_locked(self, *, notify_finished: bool = True) -> None:
        if self.engine_mode != "async_hosted":
            return
        # 1. Capture coherent handles & final JPEG synchronously, then IMMEDIATELY advance generations,
        #    flip mode to `idle`, clear owner/takeover/queues/caches BEFORE ANY await!
        old_gen = self.session_gen
        final_jpeg = self.latest_jpeg
        old_page = self._current_page()
        cm = self.camoufox_cm
        fd = self.lock_fd
        ephemeral_dir = self._ephemeral_dir
        held_buttons = list(self._mouse_buttons_down)

        self.session_gen += 1
        self.takeover_gen += 1
        self.engine_mode = "idle"
        self.camoufox_cm = None
        self.ctx = None
        self.lock_fd = None
        self._ephemeral_dir = None
        self._drain_input_queue()
        self._clear_session_caches()
        self.ai_allowed_event.set()

        # 2. Release any held mouse buttons on the detached page under a bounded execution barrier
        if held_buttons and old_page is not None:
            async def _release_held_buttons() -> None:
                async with self._exec_lock:
                    for btn in held_buttons:
                        try:
                            await asyncio.wait_for(old_page.mouse.up(button=btn), timeout=1.5)
                        except Exception as exc:
                            log.debug("Stop fallback mouse.up(%s) error: %s", btn, exc)

            try:
                await asyncio.wait_for(_release_held_buttons(), timeout=2.5)
            except Exception as exc:
                log.warning("Bounded stop mouse.up release timed out/failed: %s", exc)

        # 3. Retire all cards for `old_gen` with strictly stateless finished copy
        await self.tg.retire_cards(session_gen=old_gen, mark_finished=notify_finished, final_jpeg=final_jpeg)

        # 4. Clean pending dialogs/choosers & cancel/await background tasks (e.g. in-flight save_as)
        await self._cleanup_pending_dialogs()
        await self._cleanup_pending_filechoosers_async()
        await self._cancel_and_await_bg_tasks(timeout=2.0)
        self._cleanup_transfer_dir(force_all=True)

        if cm is not None:
            try:
                await cm.__aexit__(None, None, None)
            except Exception as exc:
                log.warning("Error closing AsyncCamoufox: %s", exc)
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        if ephemeral_dir is not None and ephemeral_dir.exists():
            shutil.rmtree(ephemeral_dir, ignore_errors=True)
        log.info("Stopped hosted AsyncCamoufox and released profile lock (gen=%d)", self.session_gen)

    async def start_hosted(
        self,
        initial_url: str | None = None,
        bot_hint: str | None = None,
        notify_tg: bool = True,
        lock_timeout: float = 45.0,
        profile: str | None = None,
        overrides: dict[str, Any] | None = None,
        restart: bool = False,
        preferred_user_id: int | None = None,
        *,
        actor: tuple[str, int] | None = None,
        source: str = "cli",
        expected_session_gen: int | None = None,
    ) -> dict[str, Any]:
        async with self._engine_lock:
            is_remote_actor = (source != "cli") or (actor is not None)
            if is_remote_actor:
                if (
                    actor is None
                    or not actor[0]
                    or not isinstance(actor[1], int)
                    or isinstance(actor[1], bool)
                    or actor[1] <= 0
                ):
                    raise PermissionError("缺少有效的 Bot 或私聊用户身份")
                a_bot, a_uid = str(actor[0]), int(actor[1])
                live_role = _check_live_user_role(a_bot, a_uid)
                if live_role != "admin":
                    raise PermissionError("当前用户未授权或不是管理员")
                if expected_session_gen is not None and self.session_gen != expected_session_gen:
                    raise PermissionError("会话代次已变更，已拒绝过期启动/切换请求")
                if self.engine_mode != "idle":
                    if not self._viewer_can_mutate(a_bot, a_uid, live_role):
                        raise PermissionError("🔒 当前浏览器会话由其他 Bot/用户或本机 CLI 持有，无权复用、导航或切换")
                    if source == "ws" and not restart:
                        raise RuntimeError("浏览器已在运行中")
                bot_hint = a_bot
                preferred_user_id = a_uid

            self.mark_active(mark_tabs_dirty=True)
            if self.engine_mode == "sync_external":
                raise RuntimeError("当前已有外部同步脚本持有浏览器会话。")

            spec = resolve_launch_spec(profile_name=profile, overrides=overrides)
            # Fail-closed Google destination enforcement BEFORE launching or switching
            enforce_google_profile_policy(
                initial_url,
                is_pinned=bool(spec.get("pinned_verified")),
                profile_dir=Path(spec["profile_dir"]) if spec.get("profile_dir") else None,
            )

            has_explicit_overrides = bool(
                overrides
                and any(
                    v is not None and not (k in ("ephemeral", "mobile") and v is False)
                    for k, v in overrides.items()
                )
            )
            if self.engine_mode == "async_hosted":
                wants_switch = (spec["name"] != self.active_profile) or has_explicit_overrides
                if wants_switch:
                    if not restart:
                        raise RuntimeError(
                            f"当前正在运行 Profile '{self.active_profile}'，请先执行 `live-browser stop` 或传入 `--restart` 切换至 '{spec['name']}'。"
                        )
                    if self.takeover or self.ai_busy_count > 0:
                        raise RuntimeError(
                            "当前浏览器处于人工接管或任务执行中，暂不允许自动重启切换，请先结束接管/等待任务完成后再切换。"
                        )
                    await self._stop_hosted_locked(notify_finished=True)

            newly_started = False
            if self.engine_mode != "async_hosted":
                pre_launch_gen = self.session_gen
                pre_launch_owner = (
                    (self.resolve_bot_key(bot_hint), preferred_user_id) if is_remote_actor else None
                )
                ephemeral_dir: Path | None = None
                if spec["persistent"]:
                    user_data_dir = Path(spec["profile_dir"])
                    if spec["pinned"]:
                        if not user_data_dir.is_dir():
                            raise FileNotFoundError(f"Pinned profile missing: {user_data_dir}")
                    else:
                        user_data_dir.mkdir(parents=True, exist_ok=True)
                        os.chmod(user_data_dir, 0o700)
                else:
                    ephemeral_dir = Path(tempfile.mkdtemp(prefix=f"agy-live-{spec['name']}-"))
                    os.chmod(ephemeral_dir, 0o700)
                    user_data_dir = ephemeral_dir

                lock_path = Path(spec["lock_path"])
                lock_path.parent.mkdir(parents=True, exist_ok=True)
                os.chmod(lock_path.parent, 0o700)
                fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
                deadline = time.monotonic() + lock_timeout
                cm: Any = None
                cm_entered = False
                ctx: Any = None
                published = False
                startup_guard_failed = False
                pinned_verified_flag = bool(spec.get("pinned_verified"))
                try:
                    host_has_pinned = discover_pinned_host_profile() is not None
                except Exception:
                    host_has_pinned = True  # fail-closed
                require_non_pinned_guard = (not pinned_verified_flag) and host_has_pinned

                def _on_new_page(new_page: Any) -> None:
                    nonlocal startup_guard_failed
                    try:
                        self._attach_page_listeners(new_page, require_nav_guard=require_non_pinned_guard)
                    except Exception as exc:
                        if require_non_pinned_guard:
                            log.error("Non-pinned new page guard attachment failed (fail-closed): %s", exc)
                            if not published:
                                startup_guard_failed = True
                            self._schedule_fail_closed_close_unguarded_page(
                                new_page,
                                expected_ctx=ctx,
                                startup_ctx_id=(id(ctx) if (ctx is not None and not published) else None),
                            )
                        return
                    # Do NOT preemptively switch active_tab_index while an explicit human `new_tab`
                    # command is awaiting post-await authorization/guard verification!
                    if self._explicit_new_tab_in_flight > 0:
                        return
                    try:
                        if self.ctx is not None:
                            pages = self._visible_pages(self.ctx)
                            if new_page in pages:
                                self.active_tab_index = pages.index(new_page)
                                self._tab_select_rev += 1
                        self.mark_active(mark_tabs_dirty=True)
                    except Exception:
                        pass

                try:
                    while True:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError(f"等待 {spec['name']} 浏览器锁超时。")
                            await asyncio.sleep(0.25)
                    _clean_stale_firefox_locks(user_data_dir)

                    if is_remote_actor:
                        if _check_live_user_role(a_bot, a_uid) != "admin":
                            raise PermissionError("启动准备期间管理员权限已撤销，已中止启动（fail-closed）")

                    kwargs, egress_summary = build_camoufox_kwargs(spec, user_data_dir)

                    from camoufox.async_api import AsyncCamoufox

                    cm = AsyncCamoufox(**kwargs)
                    ctx = await cm.__aenter__()
                    cm_entered = True

                    # Fail-closed: install non-pinned Google navigation guard + page listeners BEFORE
                    # activating the session or navigating any page!
                    await self._install_non_pinned_google_guard(
                        ctx, is_pinned_verified=pinned_verified_flag
                    )
                    ctx_on = getattr(ctx, "on", None)
                    if callable(ctx_on):
                        ctx_on("page", _on_new_page)
                    elif require_non_pinned_guard:
                        raise RuntimeError("非 Pinned 浏览器上下文不支持 ctx.on('page') 监听，已拒绝启动（fail-closed）")

                    for existing_page in list(ctx.pages):
                        self._attach_page_listeners(existing_page, require_nav_guard=require_non_pinned_guard)
                    if not ctx.pages:
                        created_page = await ctx.new_page()
                        self._attach_page_listeners(created_page, require_nav_guard=require_non_pinned_guard)

                    resolved_display = resolve_camoufox_display(ctx, user_data_dir)
                    initial_x11_clip = await read_x11_clipboard_async(resolved_display)

                    # Pre-publish startup guard gate: if any popup/new page failed guard installation
                    # during startup, abort directly inside the current `_engine_lock` without re-entering!
                    if startup_guard_failed or (ctx is not None and id(ctx) in self._startup_guard_failed_ctx):
                        raise RuntimeError("启动期间弹出页面导航守卫安装失败，已中止发布（fail-closed）")

                    # Final pre-commit RBAC, idle, generation & owner re-verification AFTER all async
                    # launch awaits and BEFORE publishing the new session (fail-closed: closes unpublished CM!).
                    if is_remote_actor:
                        resolved_owner_check = (self.resolve_bot_key(bot_hint), preferred_user_id)
                        if (
                            _check_live_user_role(a_bot, a_uid) != "admin"
                            or self.engine_mode != "idle"
                            or self.session_gen != pre_launch_gen
                            or (expected_session_gen is not None and not restart and self.session_gen != expected_session_gen)
                            or resolved_owner_check != pre_launch_owner
                            or resolved_owner_check != (a_bot, a_uid)
                        ):
                            raise PermissionError("会话发布前管理员权限已撤销或状态/代次/归属已变更，已中止启动（fail-closed）")
                except Exception:
                    if ctx is not None:
                        self._startup_guard_failed_ctx.discard(id(ctx))
                    if cm_entered and cm is not None:
                        try:
                            await cm.__aexit__(None, None, None)
                        except Exception as close_exc:
                            log.warning("Error closing AsyncCamoufox after guard/start failure: %s", close_exc)
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except Exception:
                        pass
                    os.close(fd)
                    if ephemeral_dir is not None and ephemeral_dir.exists():
                        shutil.rmtree(ephemeral_dir, ignore_errors=True)
                    raise

                published = True
                self._startup_guard_failed_ctx.discard(id(ctx))
                self.session_gen += 1
                resolved_owner_bot = self.resolve_bot_key(bot_hint)
                self.session_owner = (
                    (resolved_owner_bot, preferred_user_id) if resolved_owner_bot is not None else None
                )
                self.lock_fd = fd
                self.camoufox_cm = cm
                self.ctx = ctx
                self.engine_mode = "async_hosted"
                self.active_profile = spec["name"]
                self.active_profile_dir = user_data_dir
                self._ephemeral_dir = ephemeral_dir
                self.active_pinned = pinned_verified_flag
                self.active_pinned_verified = pinned_verified_flag
                self.active_egress = egress_summary
                self.active_os = str(spec.get("os") or "windows")
                fp_summary: dict[str, Any] = {"os": self.active_os, "persistent": bool(spec["persistent"])}
                for fp_key in ("locale", "window", "mobile", "webgl_config", "block_webrtc", "geoip"):
                    if spec.get(fp_key) is not None and spec.get(fp_key) is not False:
                        fp_summary[fp_key] = spec[fp_key]
                self.active_fingerprint = fp_summary

                self.ai_status = "已启动安全浏览器"
                self.x11_display = resolved_display
                self._last_x11_clip = initial_x11_clip
                log.info("Resolved Camoufox X11 display=%s", self.x11_display)

                self.active_tab_index = max(0, len(self._visible_pages(ctx)) - 1)
                self._tab_select_rev += 1
                self._tabs_dirty = True
                self._last_normal_sig = None
                self._hd_settled = False
                newly_started = True
                log.info(
                    "Started hosted AsyncCamoufox gen=%d profile=%s pinned=%s os=%s egress=%s owner=%s",
                    self.session_gen,
                    self.active_profile,
                    self.active_pinned,
                    self.active_os,
                    self.active_egress,
                    self.session_owner,
                )

            commit_gen = self.session_gen
            page = self._current_page()
            if initial_url and page:
                if is_remote_actor:
                    live_role_pre_nav = _check_live_user_role(a_bot, a_uid)
                    if (
                        live_role_pre_nav != "admin"
                        or self.engine_mode != "async_hosted"
                        or self.session_gen != commit_gen
                        or not self._viewer_can_mutate(a_bot, a_uid, live_role_pre_nav)
                    ):
                        if newly_started:
                            await self._stop_hosted_locked(notify_finished=False)
                        raise PermissionError("导航前管理员权限已撤销或会话已变更，已中止导航（fail-closed）")
                self.ai_status = f"正在打开 {initial_url}"
                await self.broadcast_state()
                # Re-verify live admin RBAC, ownership & session_gen AFTER `await broadcast_state()`
                # and strictly BEFORE invoking `page.goto(initial_url)`!
                if is_remote_actor:
                    live_role_nav = _check_live_user_role(a_bot, a_uid)
                    if (
                        live_role_nav != "admin"
                        or self.engine_mode != "async_hosted"
                        or self.session_gen != commit_gen
                        or not self._viewer_can_mutate(a_bot, a_uid, live_role_nav)
                    ):
                        if newly_started:
                            await self._stop_hosted_locked(notify_finished=False)
                        raise PermissionError("导航前管理员权限已撤销或会话已变更，已中止导航（fail-closed）")
                await page.goto(initial_url, wait_until="domcontentloaded", timeout=45000)
                self.ai_status = f"已打开 {initial_url}"
                self.mark_active(mark_tabs_dirty=True)

            await self._capture_once(force_broadcast=True)
            await self.broadcast_state()
            result_state = self.state_dict()

        if notify_tg:
            if not is_remote_actor or _check_live_user_role(a_bot, a_uid) == "admin":
                bot_key = self.resolve_bot_key(bot_hint)
                if bot_key is not None:
                    asyncio.create_task(self.tg.ensure_card(bot_key, preferred_user_id=preferred_user_id))

        return result_state

    async def stop_hosted(
        self,
        notify_finished: bool = True,
        *,
        pre_stop_verify: Any | None = None,
        actor: tuple[str, int] | None = None,
        source: str = "cli",
        expected_session_gen: int | None = None,
        card_message_id: int | None = None,
        require_card: bool = False,
        force: bool = False,
    ) -> tuple[bool, str]:
        async with self._engine_lock:
            if callable(pre_stop_verify):
                ok_v, msg_v = pre_stop_verify()
                if not ok_v:
                    return False, str(msg_v)
            if source != "cli" or actor is not None:
                if (
                    actor is None
                    or not actor[0]
                    or not isinstance(actor[1], int)
                    or isinstance(actor[1], bool)
                    or actor[1] <= 0
                ):
                    return False, "缺少有效的 Bot 或私聊用户身份"
                a_bot, a_uid = str(actor[0]), int(actor[1])
                if require_card:
                    ok_cv, msg_cv, _ = self.tg.verify_card_control(
                        a_bot,
                        a_uid,
                        message_id=card_message_id,
                        require_card=True,
                        require_running=False,
                        expected_session_gen=expected_session_gen,
                    )
                    if not ok_cv:
                        return False, msg_cv
                else:
                    if expected_session_gen is not None and self.session_gen != expected_session_gen:
                        return False, "会话代次已变更，已拒绝过期停止请求"
                    live_role = _check_live_user_role(a_bot, a_uid)
                    if live_role != "admin":
                        return False, "当前用户未授权或不是管理员"
                    if self.engine_mode != "idle" and not self._viewer_can_mutate(a_bot, a_uid, live_role):
                        return False, "🔒 无权关闭其他 Bot/用户或本机 CLI 持有的浏览器会话"
                if self.engine_mode == "sync_external":
                    return False, "当前为外部脚本联动会话，无法直接关闭"
                if self.ai_busy_count > 0 and not force:
                    return False, "AI 正在执行浏览器操作，请稍候再关闭"
            if self.engine_mode != "async_hosted":
                return True, "ok"
            await self._stop_hosted_locked(notify_finished=notify_finished)
        await self.broadcast_state()
        return True, "ok"

    def _visible_pages(self, ctx: Any | None = None) -> list[Any]:
        """Return the unified list of open, non-quarantined pages for tab indexing & selection."""
        target_ctx = self.ctx if ctx is None else ctx
        if not target_ctx:
            return []
        raw_pages = getattr(target_ctx, "pages", None)
        if not raw_pages:
            return []
        return [
            p
            for p in list(raw_pages)
            if not self._is_page_closed(p) and id(p) not in self._closing_unguarded_pages
        ]

    def _current_page(self) -> Any | None:
        pages = self._visible_pages()
        if not pages:
            return None
        if self.active_tab_index >= len(pages):
            self.active_tab_index = len(pages) - 1
        if self.active_tab_index < 0:
            self.active_tab_index = 0
        return pages[self.active_tab_index]

    @staticmethod
    def _is_page_closed(page: Any) -> bool:
        fn = getattr(page, "is_closed", None)
        if callable(fn):
            try:
                return bool(fn())
            except Exception:
                return False
        return bool(fn) if fn is not None else False

    async def _refresh_tabs_metadata(self, *, force: bool = False) -> bool:
        """Refresh tab list, URL, title & viewport atomically after all awaits, never overwriting newer selections.

        Returns True when any observable metadata (tabs, url, title, vw, vh) changed.
        """
        if self.engine_mode != "async_hosted" or not self.ctx:
            return False
        snap_ctx = self.ctx
        snap_gen = self.session_gen
        snap_rev = self._tab_select_rev
        raw_pages = list(snap_ctx.pages)
        pages = self._visible_pages(snap_ctx)
        if not pages:
            return False
        active_idx = max(0, min(self.active_tab_index, len(pages) - 1))
        target_active_page = pages[active_idx]
        now = time.monotonic()
        needs = (
            force
            or self._tabs_dirty
            or len(pages) != len(self.tabs)
            or (now - self._last_tabs_refresh) >= 1.2
            or target_active_page.url != self.url
        )
        if not needs:
            return False

        prev_state = (self.url, self.title, self.tabs, self.vw, self.vh)
        closed_during_snap = len(pages) != len(raw_pages)
        collected: list[tuple[Any, str, str]] = []
        for p in pages:
            self._attach_page_listeners(p)
            try:
                t_title = await asyncio.wait_for(p.title(), timeout=0.45)
            except Exception:
                t_title = ""
            if (
                self.engine_mode != "async_hosted"
                or self.session_gen != snap_gen
                or self.ctx is not snap_ctx
            ):
                return False
            if self._tab_select_rev != snap_rev:
                self._tabs_dirty = True
                return False
            cur_live = self._visible_pages(snap_ctx)
            if p not in cur_live:
                closed_during_snap = True
                continue
            collected.append((p, t_title, p.url))

        if (
            self.engine_mode != "async_hosted"
            or self.session_gen != snap_gen
            or self.ctx is not snap_ctx
        ):
            return False
        if self._tab_select_rev != snap_rev:
            self._tabs_dirty = True
            return False

        # Second pass against current visible pages to drop any page closed/quarantined while awaiting titles
        final_live = self._visible_pages(snap_ctx)
        kept: list[tuple[Any, str, str]] = []
        for p, t_title, p_url in collected:
            if p in final_live:
                kept.append((p, t_title, p_url))
            else:
                closed_during_snap = True

        if not kept:
            if self._tab_select_rev != snap_rev:
                self._tabs_dirty = True
                return False
            self.tabs = []
            self.active_tab_index = 0
            self._tabs_dirty = True
            return True

        kept_pages = [item[0] for item in kept]
        if target_active_page in kept_pages:
            safe_idx = kept_pages.index(target_active_page)
        else:
            closed_during_snap = True
            safe_idx = max(0, min(active_idx, len(kept_pages) - 1))

        tabs_info: list[dict[str, Any]] = []
        for idx, (_p, t_title, p_url) in enumerate(kept):
            tabs_info.append(
                {
                    "index": idx,
                    "title": t_title or p_url or f"Tab {idx + 1}",
                    "url": p_url,
                    "active": idx == safe_idx,
                }
            )

        active_page = kept_pages[safe_idx]
        new_url = active_page.url
        new_title = tabs_info[safe_idx]["title"]
        new_vw = self.vw
        new_vh = self.vh

        vp = active_page.viewport_size
        if vp and vp.get("width") and vp.get("height"):
            new_vw = int(vp["width"])
            new_vh = int(vp["height"])
        else:
            try:
                dims = await asyncio.wait_for(
                    active_page.evaluate("() => ({w: window.innerWidth, h: window.innerHeight})"),
                    timeout=0.6,
                )
                if dims and dims.get("w") and dims.get("h"):
                    new_vw = int(dims["w"])
                    new_vh = int(dims["h"])
            except Exception:
                pass

        # Final atomic commit gate AFTER the very last await: verify ctx, session_gen, _tab_select_rev & live pages
        if (
            self.engine_mode != "async_hosted"
            or self.session_gen != snap_gen
            or self.ctx is not snap_ctx
        ):
            return False
        if self._tab_select_rev != snap_rev:
            self._tabs_dirty = True
            return False
        live_after_all = self._visible_pages(snap_ctx)
        if live_after_all != kept_pages:
            # Tab set mutated during viewport await: discard stale snapshot & keep dirty
            self._tabs_dirty = True
            return False

        # Commit all hub metadata fields in one synchronous block
        self.active_tab_index = safe_idx
        self.tabs = tabs_info
        self.url = new_url
        self.title = new_title
        self.vw = new_vw
        self.vh = new_vh

        if closed_during_snap or len(kept_pages) != len(final_live):
            self._tabs_dirty = True
        else:
            self._tabs_dirty = False
        self._last_tabs_refresh = time.monotonic()
        meta_changed = (self.url, self.title, self.tabs, self.vw, self.vh) != prev_state
        if meta_changed:
            self._meta_changed_pending = True
        return meta_changed

    def _schedule_metadata_refresh(self) -> None:
        """Run non-blocking bounded metadata refresh so slow `page.title()` never stalls frame capture."""
        if self._meta_task and not self._meta_task.done():
            return

        async def _runner() -> None:
            try:
                changed = await self._refresh_tabs_metadata(force=False)
                if changed:
                    self._meta_changed_pending = False
                    await self.broadcast_state()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.debug("Background metadata refresh skipped: %s", exc)

        try:
            self._meta_task = asyncio.create_task(_runner())
        except RuntimeError:
            pass

    async def _capture_once(
        self,
        *,
        force_broadcast: bool = False,
        hd: bool = False,
        nonblocking_meta: bool = False,
    ) -> bool:
        if self.engine_mode != "async_hosted" or self.ctx is None:
            return False
        page = self._current_page()
        if not page:
            return False
        cap_gen = self.session_gen
        try:
            preset_cfg = QUALITY_PRESETS.get(self.quality_preset, QUALITY_PRESETS["balanced"])
            quality = int(preset_cfg["hd_quality"] if hd else preset_cfg["stream_quality"])
            jpeg = await asyncio.wait_for(
                page.screenshot(type="jpeg", quality=quality, animations="allow"),
                timeout=3.0,
            )
            # Guard against late screenshot completing after stop/switch/generation advance
            if self.engine_mode != "async_hosted" or self.session_gen != cap_gen or self.ctx is None:
                return False

            if nonblocking_meta and not force_broadcast:
                self._schedule_metadata_refresh()
            else:
                meta_changed = await self._refresh_tabs_metadata(force=force_broadcast)
                if meta_changed:
                    self._meta_changed_pending = True

            if self.engine_mode != "async_hosted" or self.session_gen != cap_gen or self.ctx is None:
                return False

            sig = (len(jpeg), hashlib.blake2b(jpeg, digest_size=16).digest())
            if hd:
                # Still-frame HD upgrade MUST NOT overwrite `_last_normal_sig` so subsequent
                # normal-quality captures on a static screen stay deduplicated and back off!
                self._hd_pending = False
                self._hd_settled = True
                await self.broadcast_frame(jpeg)
                if self._meta_changed_pending:
                    self._meta_changed_pending = False
                    await self.broadcast_state()
                return True

            if not force_broadcast and sig == self._last_normal_sig:
                self._unchanged_frames += 1
                if not self._hd_settled:
                    self.latest_jpeg = jpeg
                if self._meta_changed_pending:
                    self._meta_changed_pending = False
                    await self.broadcast_state()
                return False

            self._last_normal_sig = sig
            self._unchanged_frames = 0
            self._hd_pending = True
            self._hd_settled = False

            await self.broadcast_frame(jpeg)
            if self._meta_changed_pending:
                self._meta_changed_pending = False
                await self.broadcast_state()
            return True
        except Exception as exc:
            log.debug("Frame capture skipped: %s", exc)
            return False

    async def _poll_clipboard_once(self) -> None:
        if self.engine_mode != "async_hosted" or self.ctx is None:
            return
        cap_gen = self.session_gen
        if not self.x11_display:
            self.x11_display = resolve_camoufox_display(self.ctx, self.active_profile_dir)
            if self.x11_display:
                init_clip = await read_x11_clipboard_async(self.x11_display)
                if self.engine_mode == "async_hosted" and self.session_gen == cap_gen:
                    self._last_x11_clip = init_clip
                return
        if not self.x11_display:
            return
        clip = await read_x11_clipboard_async(self.x11_display)
        if self.engine_mode != "async_hosted" or self.session_gen != cap_gen or self.ctx is None:
            return
        if clip and clip != self._last_x11_clip:
            self._last_x11_clip = clip
            self.latest_clip = {
                "text": clip,
                "source": "网页复制按钮 / Ctrl+C",
                "url": self.url,
                "ts": time.time(),
            }
            log.info("Detected X11 clipboard update (%d chars)", len(clip))
            await self.broadcast_json({"type": "clipboard", **self.latest_clip})

    async def extract_content_async(
        self,
        req: dict[str, Any],
        *,
        expected_session_gen: int | None = None,
        expected_takeover_gen: int | None = None,
        expected_owner: tuple[str, int | None] | None = None,
        check_owner: bool = False,
    ) -> dict[str, Any] | None:
        """Read-only DOM extraction for mobile/desktop cross-system copy without altering page prototypes."""
        page = self._current_page()
        if not page:
            return None
        cap_gen = self.session_gen if expected_session_gen is None else expected_session_gen
        cap_tgen = self.takeover_gen if expected_takeover_gen is None else expected_takeover_gen
        cap_owner = expected_owner if check_owner else self.session_owner

        def _still_coherent() -> bool:
            return (
                self.engine_mode == "async_hosted"
                and self.session_gen == cap_gen
                and self.takeover_gen == cap_tgen
                and self.session_owner == cap_owner
            )

        if not _still_coherent():
            return None
        mode = str(req.get("mode") or "point")
        try:
            if mode == "url":
                if not self.url:
                    return None
                return {
                    "text": self.url,
                    "blockText": f"{self.title}\n{self.url}".strip() if self.title else "",
                    "href": self.url,
                    "source": "当前网页网址",
                    "url": self.url,
                    "ts": time.time(),
                }

            if mode == "page":
                body_txt = await asyncio.wait_for(
                    page.evaluate("() => (document.body && document.body.innerText || '').trim().slice(0, 25000)"),
                    timeout=1.8,
                )
                if not body_txt or not _still_coherent():
                    return None
                return {
                    "text": body_txt,
                    "source": "整页可见文字",
                    "url": page.url,
                    "ts": time.time(),
                }

            if mode in ("range", "range_preview"):
                x1 = float(req.get("x1", 0))
                y1 = float(req.get("y1", 0))
                x2 = float(req.get("x2", 0))
                y2 = float(req.get("y2", 0))
                sel_res = await asyncio.wait_for(
                    page.evaluate(
                        """({x1, y1, x2, y2}) => {
                            function isSensitiveEl(el) {
                                if (!el || el.nodeType !== 1) return false;
                                const tag = (el.tagName || '').toUpperCase();
                                if (tag !== 'INPUT' && tag !== 'TEXTAREA') return false;
                                const tp = (el.type || 'text').toLowerCase();
                                const ac = ((el.getAttribute && el.getAttribute('autocomplete')) || '').toLowerCase();
                                const nm = ((el.name || '') + ' ' + (el.id || '')).toLowerCase();
                                return tp === 'password' || ac.includes('password') || ac.includes('cc-') || ac.includes('one-time-code') || /\\b(otp|cvv|cvc|passcode|pin|card[-_]?num)\\b/.test(nm);
                            }
                            const el1 = document.elementFromPoint(x1, y1);
                            const el2 = document.elementFromPoint(x2, y2);
                            if (isSensitiveEl(el1) || isSensitiveEl(el2)) return '';
                            function getCaret(x, y) {
                                if (document.caretPositionFromPoint) {
                                    const p = document.caretPositionFromPoint(x, y);
                                    if (p && p.offsetNode) return { node: p.offsetNode, offset: p.offset };
                                }
                                if (document.caretRangeFromPoint) {
                                    const r = document.caretRangeFromPoint(x, y);
                                    if (r && r.startContainer) return { node: r.startContainer, offset: r.startOffset };
                                }
                                return null;
                            }
                            const c1 = getCaret(x1, y1);
                            const c2 = getCaret(x2, y2);
                            if (!c1 || !c2) return null;
                            const range = document.createRange();
                            let forward = true;
                            if (c1.node === c2.node) {
                                forward = c1.offset <= c2.offset;
                            } else {
                                const cmp = c1.node.compareDocumentPosition(c2.node);
                                forward = !!(cmp & Node.DOCUMENT_POSITION_FOLLOWING);
                            }
                            try {
                                if (forward) {
                                    range.setStart(c1.node, c1.offset);
                                    range.setEnd(c2.node, c2.offset);
                                } else {
                                    range.setStart(c2.node, c2.offset);
                                    range.setEnd(c1.node, c1.offset);
                                }
                                const sel = window.getSelection();
                                sel.removeAllRanges();
                                sel.addRange(range);
                                return (sel.toString() || '').slice(0, 20000);
                            } catch (_) {
                                return null;
                            }
                        }""",
                        {"x1": x1, "y1": y1, "x2": x2, "y2": y2},
                    ),
                    timeout=0.9,
                )
                if not _still_coherent():
                    return None
                if mode == "range_preview":
                    return {"preview": True, "text": (sel_res or "").strip()}
                cleaned_sel = (sel_res or "").strip()
                if not cleaned_sel:
                    return None
                await self._capture_once()
                if not _still_coherent():
                    return None
                out_range = {
                    "text": cleaned_sel,
                    "source": f"涂抹选定 ({len(cleaned_sel)}字)",
                    "url": page.url,
                    "ts": time.time(),
                }
                self.latest_clip = out_range
                return out_range

            if mode == "selection":
                sel_txt = await asyncio.wait_for(
                    page.evaluate(
                        """() => {
                            const ae = document.activeElement;
                            if (ae && ae.nodeType === 1) {
                                const tag = (ae.tagName || '').toUpperCase();
                                if (tag === 'INPUT' || tag === 'TEXTAREA') {
                                    const tp = (ae.type || 'text').toLowerCase();
                                    const ac = ((ae.getAttribute && ae.getAttribute('autocomplete')) || '').toLowerCase();
                                    const nm = ((ae.name || '') + ' ' + (ae.id || '')).toLowerCase();
                                    if (tp === 'password' || ac.includes('password') || ac.includes('cc-') || ac.includes('one-time-code') || /\\b(otp|cvv|cvc|passcode|pin|card[-_]?num)\\b/.test(nm)) {
                                        return '';
                                    }
                                }
                            }
                            return (window.getSelection && window.getSelection().toString() || '').trim().slice(0, 25000);
                        }"""
                    ),
                    timeout=0.8,
                )
                if not _still_coherent():
                    return None
                if sel_txt:
                    return {
                        "text": sel_txt,
                        "href": page.url,
                        "source": f"网页已选中文字 ({len(sel_txt)}字)",
                        "url": page.url,
                        "ts": time.time(),
                    }
                if self.latest_clip and self.latest_clip.get("text"):
                    return {**self.latest_clip, "ts": time.time()}
                return {
                    "text": "",
                    "href": page.url,
                    "source": "请点【🖊 拖选文字】在画面涂抹选定，或点【📄 整页文字】后在框内自由划词",
                    "url": page.url,
                    "ts": time.time(),
                }

            # Default: mode == 'point' (single tap on a paragraph/word without grabbing giant container!)
            x = float(req.get("x", 0))
            y = float(req.get("y", 0))
            extracted = await asyncio.wait_for(
                page.evaluate(
                    """({x, y}) => {
                        let el = document.elementFromPoint(x, y);
                        if (!el) return null;
                        const tag = (el.tagName || '').toUpperCase();
                        if (tag === 'INPUT' || tag === 'TEXTAREA') {
                            const tp = (el.type || 'text').toLowerCase();
                            const ac = ((el.getAttribute && el.getAttribute('autocomplete')) || '').toLowerCase();
                            const nm = ((el.name || '') + ' ' + (el.id || '')).toLowerCase();
                            const isSensitive = tp === 'password' || ac.includes('password') || ac.includes('cc-') || ac.includes('one-time-code') || /\\b(otp|cvv|cvc|passcode|pin|card[-_]?num)\\b/.test(nm);
                            const val = isSensitive ? '' : String(el.value || el.placeholder || '').trim();
                            if (val) {
                                return { text: val.slice(0, 20000), blockText: '', href: '', label: '输入框内容' };
                            }
                            return null;
                        }
                        const linkEl = el.closest('a[href]');
                        const href = linkEl ? String(linkEl.href || '') : '';
                        const codeEl = el.closest('code, pre, samp, kbd');
                        if (codeEl && (codeEl.innerText || '').trim()) {
                            try {
                                const r = document.createRange();
                                r.selectNodeContents(codeEl);
                                const s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
                            } catch (_) {}
                            return {
                                text: codeEl.innerText.trim().slice(0, 20000),
                                blockText: '',
                                href: href.slice(0, 4000),
                                label: `<${codeEl.tagName.toLowerCase()}> 代码块`
                            };
                        }
                        // If user tapped whitespace margin of a huge container (<div>/<main>/<body>), pick nearest child paragraph/leaf!
                        if (el.children && el.children.length > 0 && ((el.innerText || '').trim().length > 220)) {
                            const candidates = el.querySelectorAll('p, li, td, th, h1, h2, h3, h4, h5, h6, blockquote, code, pre, a, span');
                            let nearest = null;
                            let bestDist = 999999;
                            for (const c of candidates) {
                                const ct = (c.innerText || '').trim();
                                if (!ct || ct.length > 1500) continue;
                                const rect = c.getBoundingClientRect();
                                if (!rect.width || !rect.height) continue;
                                const dx = x < rect.left ? (rect.left - x) : (x > rect.right ? x - rect.right : 0);
                                const dy = y < rect.top ? (rect.top - y) : (y > rect.bottom ? y - rect.bottom : 0);
                                const d = Math.hypot(dx, dy);
                                if (d < bestDist && d <= 60) {
                                    bestDist = d;
                                    nearest = c;
                                }
                            }
                            if (nearest) el = nearest;
                        }
                        let cur = el;
                        let targetNode = el;
                        let bestText = '';
                        let bestTag = (el.tagName || '').toLowerCase();
                        while (cur && cur !== document.body && cur !== document.documentElement) {
                            const t = (cur.innerText || cur.textContent || '').trim();
                            if (t) {
                                bestText = t;
                                targetNode = cur;
                                bestTag = (cur.tagName || '').toLowerCase();
                                if (t.length >= 2) break;
                            }
                            cur = cur.parentElement;
                        }
                        if (!bestText || bestText.length > 4000) return null;
                        try {
                            const r = document.createRange();
                            r.selectNodeContents(targetNode);
                            const s = window.getSelection();
                            s.removeAllRanges();
                            s.addRange(r);
                        } catch (_) {}
                        let blockText = '';
                        const blockEl = targetNode.closest('p, li, td, th, blockquote, h1, h2, h3, h4');
                        if (blockEl && blockEl !== targetNode) {
                            const bt = (blockEl.innerText || '').trim();
                            if (bt && bt !== bestText && bt.length <= 4000) blockText = bt;
                        }
                        return {
                            text: bestText.slice(0, 20000),
                            blockText: blockText.slice(0, 20000),
                            href: href.slice(0, 4000),
                            label: `点选段落 <${bestTag}>`
                        };
                    }""",
                    {"x": x, "y": y},
                ),
                timeout=1.2,
            )
            if not extracted or not extracted.get("text"):
                return None
            if not _still_coherent():
                return None
            await self._capture_once()
            if not _still_coherent():
                return None
            out = {
                "text": extracted["text"],
                "blockText": extracted.get("blockText") or "",
                "href": extracted.get("href") or "",
                "source": extracted.get("label") or "点字提取",
                "url": page.url,
                "ts": time.time(),
            }
            self.latest_clip = out
            return out
        except Exception as exc:
            log.debug("extract_content_async error: %s", exc)
            return None

    def _compute_capture_sleep(self, has_viewers: bool, changed: bool, now: float) -> float:
        if not has_viewers:
            return 2.2
        preset_cfg = QUALITY_PRESETS.get(self.quality_preset, QUALITY_PRESETS["balanced"])
        active_iv = float(preset_cfg["active_interval"])
        idle_ivs = preset_cfg["idle_intervals"]
        idle_since_active = now - self._last_active_ts
        if changed or idle_since_active < 0.35:
            return active_iv
        if self._unchanged_frames < 3:
            return float(idle_ivs[0])
        if self._unchanged_frames < 8:
            return float(idle_ivs[1])
        return float(idle_ivs[2])

    def _invalidate_sync_session_sync(self) -> tuple[int, bytes | None]:
        """Synchronously invalidate the active sync lease, mode, generations & caches BEFORE any async cleanup."""
        old_gen = self.session_gen
        final_jpeg = self.latest_jpeg
        self._sync_lease_id = None
        self._sync_last_push_ts = None
        self.engine_mode = "idle"
        self.session_gen += 1
        self.takeover_gen += 1
        self.sync_cmd_queue.clear()
        self._clear_session_caches()
        self.ai_allowed_event.set()
        return old_gen, final_jpeg

    async def _expire_sync_session_if_stale(self) -> bool:
        """Auto-reset `sync_external` back to `idle` if external script stops pushing beyond lease TTL.

        Invalidates lease, mode, generations & caches synchronously FIRST, then retires cards & broadcasts state.
        """
        if self.engine_mode != "sync_external":
            return False
        if self._sync_last_push_ts is None:
            return False
        if (time.monotonic() - self._sync_last_push_ts) <= SYNC_LEASE_TIMEOUT_SECONDS:
            return False
        log.warning("Sync external session lease expired (>%.0fs without push); resetting to idle", SYNC_LEASE_TIMEOUT_SECONDS)
        old_gen, final_jpeg = self._invalidate_sync_session_sync()
        await self.tg.retire_cards(session_gen=old_gen, mark_finished=True, final_jpeg=final_jpeg)
        await self.broadcast_state()
        return True

    async def _capture_loop(self) -> None:
        last_state_push = 0.0
        last_clip_poll = 0.0
        while True:
            try:
                if self.engine_mode == "async_hosted":
                    has_viewers = len(self.viewers) > 0
                    has_cards = len(self.tg.cards) > 0
                    changed = False
                    now = time.monotonic()
                    if has_viewers or has_cards:
                        idle_since_active = now - self._last_active_ts
                        need_hd = (
                            has_viewers
                            and self._hd_pending
                            and not self._hd_settled
                            and idle_since_active >= 0.32
                        )
                        changed = await self._capture_once(hd=need_hd, nonblocking_meta=True)
                        now = time.monotonic()
                        if (changed or self._tabs_dirty or self._meta_changed_pending) and (now - last_state_push >= 0.6):
                            last_state_push = now
                            self._meta_changed_pending = False
                            await self.broadcast_state()
                        if has_viewers and (now - last_clip_poll >= 0.45):
                            last_clip_poll = now
                            await self._poll_clipboard_once()
                    # Idle auto-release so profile lock is not held forever
                    if (
                        not has_viewers
                        and not self.takeover
                        and self.ai_busy_count == 0
                        and (time.monotonic() - self.last_activity_ts) > IDLE_AUTOCLOSE_SECONDS
                    ):
                        log.info("Idle timeout reached, releasing hosted browser")
                        await self.stop_hosted(notify_finished=True)
                    await asyncio.sleep(self._compute_capture_sleep(has_viewers, changed, time.monotonic()))
                else:
                    await asyncio.sleep(0.4)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.warning("Capture loop error: %s", exc)
                await asyncio.sleep(0.5)

    async def _tg_maintenance_loop(self) -> None:
        last_cleanup = 0.0
        while True:
            try:
                await self._expire_sync_session_if_stale()
                if self.tg.cards or self.tg.pending_retire_cards:
                    await self.tg.tick_updates(finished=False, force=False)
                now = time.monotonic()
                if (now - last_cleanup) >= 60.0:
                    last_cleanup = now
                    self._cleanup_transfer_dir(force_all=False)
                    await self._cleanup_pending_filechoosers_async(page_id=-1)
                await asyncio.sleep(1.2)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.debug("TG maintenance loop error: %s", exc)
                await asyncio.sleep(2.0)

    @staticmethod
    def _cmd_meta_key(cmd: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
        return (
            cmd.get("_session_gen"),
            cmd.get("_takeover_gen"),
            cmd.get("_bot_key"),
            cmd.get("_user_id"),
        )

    def _coalesce_queued_input(self, cmd: dict[str, Any]) -> dict[str, Any]:
        """Coalesce consecutive wheel or mouse move events sharing the same generation/owner metadata."""
        act = cmd.get("action")
        meta_key = self._cmd_meta_key(cmd)
        if act == "wheel":
            dx = float(cmd.get("dx", 0))
            dy = float(cmd.get("dy", 0))
            while not self.input_queue.empty():
                nxt = self.input_queue._queue[0]  # peek
                if nxt.get("action") == "wheel" and self._cmd_meta_key(nxt) == meta_key:
                    self.input_queue.get_nowait()
                    dx += float(nxt.get("dx", 0))
                    dy += float(nxt.get("dy", 0))
                else:
                    break
            out = {"action": "wheel", "dx": dx, "dy": dy}
            for mk in ("_session_gen", "_takeover_gen", "_bot_key", "_user_id"):
                if mk in cmd:
                    out[mk] = cmd[mk]
            return out
        if act == "move":
            latest = cmd
            while not self.input_queue.empty():
                nxt = self.input_queue._queue[0]  # peek
                if nxt.get("action") == "move" and self._cmd_meta_key(nxt) == meta_key:
                    latest = self.input_queue.get_nowait()
                else:
                    break
            return latest
        return cmd

    def _is_human_cmd_still_valid(self, cmd: dict[str, Any], *, check_live_rbac: bool = True) -> bool:
        """Re-verify session/takeover generation, owner & live admin RBAC before executing any dequeued human input."""
        if "_session_gen" in cmd and cmd["_session_gen"] != self.session_gen:
            return False
        if "_takeover_gen" in cmd:
            if not self.takeover or cmd["_takeover_gen"] != self.takeover_gen:
                return False
        if "_bot_key" in cmd:
            bkey = str(cmd.get("_bot_key") or "")
            uid = int(cmd.get("_user_id") or 0)
            if self.takeover_owner is not None:
                t_bot, t_uid = self.takeover_owner
                if bkey != t_bot:
                    return False
                if t_uid is None or uid != int(t_uid):
                    return False
            if self.session_owner is not None:
                s_bot, s_uid = self.session_owner
                if bkey != s_bot:
                    return False
                if s_uid is None or uid != int(s_uid):
                    return False
            if check_live_rbac:
                live_role = _check_live_user_role(bkey, uid)
                if live_role != "admin":
                    return False
        return True

    async def _revoke_actor_on_exec_boundary(self, bkey: str, uid: int, live_role: str) -> None:
        """On live RBAC revocation or downgrade at execution boundary, release takeover/buttons & evict WS."""
        if live_role == "denied":
            for ws in list(self.viewers):
                meta = self.viewer_meta.get(ws) or {}
                if str(meta.get("bot_key") or "") == bkey and int(meta.get("user_id") or 0) == uid:
                    await self._evict_revoked_viewer(ws, reason="访问权限已被撤销")
        else:
            for ws in list(self.viewers):
                meta = self.viewer_meta.get(ws) or {}
                if str(meta.get("bot_key") or "") == bkey and int(meta.get("user_id") or 0) == uid:
                    meta["role"] = live_role
        if self.takeover and self.takeover_owner is not None:
            t_bot, t_uid = self.takeover_owner
            if t_bot == bkey and (t_uid is None or int(t_uid) == uid):
                self.takeover_gen += 1
                self.takeover = False
                self.takeover_owner = None
                self.takeover_reason = ""
                self._drain_input_queue()
                self.ai_allowed_event.set()
                try:
                    asyncio.get_running_loop().create_task(self.broadcast_state())
                except RuntimeError:
                    pass

    async def _enforce_human_cmd_live_auth_locked(self, cmd: dict[str, Any]) -> bool:
        """Execution-boundary check (caller holds `_exec_lock` or outside lock) with revocation cleanup."""
        if not self._is_human_cmd_still_valid(cmd, check_live_rbac=False):
            return False
        if "_bot_key" in cmd:
            bkey = str(cmd.get("_bot_key") or "")
            uid = int(cmd.get("_user_id") or 0)
            live_role = _check_live_user_role(bkey, uid)
            if live_role != "admin":
                if self._exec_lock.locked():
                    await self._release_held_mouse_buttons_locked()
                else:
                    async with self._exec_lock:
                        await self._release_held_mouse_buttons_locked()
                await self._revoke_actor_on_exec_boundary(bkey, uid, live_role)
                return False
        return True

    def pop_sync_cmds(self) -> list[dict[str, Any]]:
        """Drain sync_cmd_queue while filtering by current `(session_gen, takeover_gen, takeover)` and live RBAC."""
        raw_cmds = list(self.sync_cmd_queue)
        self.sync_cmd_queue.clear()
        valid: list[dict[str, Any]] = []
        for cmd in raw_cmds:
            c_sgen = cmd.get("session_gen")
            if c_sgen is not None and int(c_sgen) != self.session_gen:
                continue
            act = cmd.get("action")
            # ONLY trust server-generated internal cleanup markers (NEVER client-supplied flags!)
            is_cleanup_up = act == "mouseup" and bool(cmd.get("_server_internal"))
            if is_cleanup_up:
                out_clean = {k: v for k, v in cmd.items() if not str(k).startswith("_")}
                out_clean["cleanup"] = True
                valid.append(out_clean)
                continue
            actor_bot = cmd.get("_bot_key")
            actor_uid = cmd.get("_user_id")
            if actor_bot is not None:
                live_role = _check_live_user_role(str(actor_bot), int(actor_uid or 0))
                if act == "extract":
                    if live_role not in ("admin", "readonly"):
                        continue
                    if not self._viewer_can_read_session(str(actor_bot), int(actor_uid or 0), live_role):
                        continue
                else:
                    if live_role != "admin":
                        continue
            if act == "extract":
                c_tgen = _parse_strict_int(cmd.get("takeover_gen"))
                if c_tgen is None or c_tgen != self.takeover_gen:
                    continue
                valid.append({k: v for k, v in cmd.items() if k != "cleanup" and not str(k).startswith("_")})
                continue
            if not self.takeover:
                continue
            c_tgen = cmd.get("takeover_gen")
            if c_tgen is not None and int(c_tgen) != self.takeover_gen:
                continue
            valid.append({k: v for k, v in cmd.items() if k != "cleanup" and not str(k).startswith("_")})
        return valid

    async def _input_loop(self) -> None:
        while True:
            try:
                cmd = await self.input_queue.get()
                cmd = self._coalesce_queued_input(cmd)
                if not await self._enforce_human_cmd_live_auth_locked(cmd):
                    continue
                self.mark_active()

                if self.engine_mode == "sync_external":
                    clean_cmd = {
                        k: v for k, v in cmd.items() if k != "cleanup" and not str(k).startswith("_")
                    }
                    if "_session_gen" in cmd:
                        clean_cmd["session_gen"] = cmd["_session_gen"]
                    if "_takeover_gen" in cmd:
                        clean_cmd["takeover_gen"] = cmd["_takeover_gen"]
                    if "_bot_key" in cmd:
                        clean_cmd["_bot_key"] = cmd["_bot_key"]
                        clean_cmd["_user_id"] = cmd.get("_user_id")
                    self._enqueue_sync_cmd(clean_cmd)
                    continue

                if self.engine_mode != "async_hosted":
                    continue

                await self._execute_human_cmd_async(cmd)
            except asyncio.CancelledError:
                cur_task = asyncio.current_task()
                cancelling_fn = getattr(cur_task, "cancelling", None)
                if cur_task is None or (cancelling_fn() > 0 if callable(cancelling_fn) else True):
                    break
                log.debug("Swallowed non-self CancelledError inside _input_loop")
                continue
            except Exception as exc:
                log.warning("Human input execution error: %s", exc)

    async def _execute_human_cmd_async(self, cmd: dict[str, Any]) -> None:
        post_exec_cleanup_task: asyncio.Task[Any] | None = None
        async with self._exec_lock:
            if not await self._enforce_human_cmd_live_auth_locked(cmd):
                return
            page = self._current_page()
            if not page:
                return
            act = cmd.get("action")
            self.mark_active(
                mark_tabs_dirty=(act in ("goto", "back", "forward", "reload", "switch_tab", "new_tab", "close_tab"))
            )

            if act == "move":
                x = float(cmd.get("x", 0))
                y = float(cmd.get("y", 0))
                self.cursor = {"x": x, "y": y, "actor": "human", "kind": "move", "ts": time.time()}
                await page.mouse.move(x, y)
                return

            if act == "mousedown":
                x = float(cmd.get("x", 0))
                y = float(cmd.get("y", 0))
                button = str(cmd.get("button") or "left")
                if button not in ("left", "right", "middle"):
                    button = "left"
                self.cursor = {"x": x, "y": y, "actor": "human", "kind": "down", "ts": time.time()}
                await page.mouse.move(x, y)
                # Re-verify takeover/session generation & live RBAC after async mouse.move before pressing down
                if not await self._enforce_human_cmd_live_auth_locked(cmd):
                    return
                pressed = False
                try:
                    self._mouse_buttons_down.add(button)
                    await page.mouse.down(button=button)
                    pressed = True
                finally:
                    if pressed and not self._is_human_cmd_still_valid(cmd, check_live_rbac=True):
                        self._mouse_buttons_down.discard(button)
                        try:
                            await asyncio.wait_for(page.mouse.up(button=button), timeout=1.5)
                        except Exception as exc:
                            log.debug("Post-mousedown fallback mouse.up(%s) error: %s", button, exc)
                if self._is_human_cmd_still_valid(cmd, check_live_rbac=True):
                    await self._capture_once()
                return

            if act == "mouseup":
                x = float(cmd.get("x", 0))
                y = float(cmd.get("y", 0))
                button = str(cmd.get("button") or "left")
                if button not in ("left", "right", "middle"):
                    button = "left"
                self.cursor = {"x": x, "y": y, "actor": "human", "kind": "up", "ts": time.time()}
                await page.mouse.move(x, y)
                was_held = button in self._mouse_buttons_down
                if not was_held and not await self._enforce_human_cmd_live_auth_locked(cmd):
                    return
                self._mouse_buttons_down.discard(button)
                await page.mouse.up(button=button)
                if self._is_human_cmd_still_valid(cmd, check_live_rbac=True):
                    await self._capture_once()
                    if self._is_human_cmd_still_valid(cmd, check_live_rbac=True):
                        await self.broadcast_state()
                return

            if act == "rightclick":
                x = float(cmd.get("x", 0))
                y = float(cmd.get("y", 0))
                self.cursor = {"x": x, "y": y, "actor": "human", "kind": "rightclick", "ts": time.time()}
                await page.mouse.click(x, y, button="right")
                if self._is_human_cmd_still_valid(cmd, check_live_rbac=True):
                    await self._capture_once()
                    if self._is_human_cmd_still_valid(cmd, check_live_rbac=True):
                        await self.broadcast_state()
                return

            if act in ("click", "dblclick"):
                x = float(cmd.get("x", 0))
                y = float(cmd.get("y", 0))
                self.cursor = {"x": x, "y": y, "actor": "human", "kind": act, "ts": time.time()}
                if act == "dblclick":
                    await page.mouse.dblclick(x, y)
                else:
                    try:
                        click_count = int(cmd.get("click_count") or 1)
                    except (TypeError, ValueError):
                        click_count = 1
                    click_count = max(1, min(3, click_count))
                    button = str(cmd.get("button") or "left")
                    if button not in ("left", "right", "middle"):
                        button = "left"
                    if click_count == 1 and button == "left":
                        await page.mouse.click(x, y)
                    else:
                        await page.mouse.click(x, y, button=button, click_count=click_count)
                # Re-verify live RBAC & generations before querying focused DOM element!
                if not await self._enforce_human_cmd_live_auth_locked(cmd):
                    return
                # Detect if the user just clicked an editable input/textarea/contenteditable on the page
                try:
                    focus_info = await asyncio.wait_for(
                        page.evaluate(
                            """() => {
                                const el = document.activeElement;
                                if (!el) return null;
                                const tag = (el.tagName || '').toUpperCase();
                                const tp = (el.type || 'text').toLowerCase();
                                const nonText = ['button','submit','reset','checkbox','radio','file','range','color','hidden','image'];
                                const editable = el.isContentEditable || tag === 'TEXTAREA' || (tag === 'INPUT' && !nonText.includes(tp));
                                if (!editable) return null;
                                return {
                                    label: el.placeholder || el.getAttribute('aria-label') || el.name || tag,
                                    value: tp === 'password' ? '' : String(el.value ?? '').slice(0, 300),
                                    isPassword: tp === 'password'
                                };
                            }"""
                        ),
                        timeout=0.6,
                    )
                    if focus_info and await self._enforce_human_cmd_live_auth_locked(cmd):
                        owner_bot, owner_uid = self._effective_resource_owner()
                        if owner_bot is not None and owner_uid is not None:
                            await self.broadcast_json_to_owners(
                                {"type": "input_focused", **focus_info},
                                owner_bot=owner_bot,
                                owner_uid=owner_uid,
                                require_admin=True,
                                expected_session_gen=cmd.get("_session_gen"),
                            )
                except Exception:
                    pass
            elif act == "wheel":
                await page.mouse.wheel(float(cmd.get("dx", 0)), float(cmd.get("dy", 0)))
            elif act == "type":
                text = str(cmd.get("text", ""))
                if cmd.get("replace"):
                    await page.keyboard.press("Control+A")
                    if not await self._enforce_human_cmd_live_auth_locked(cmd):
                        return
                    await page.keyboard.press("Backspace")
                    if not await self._enforce_human_cmd_live_auth_locked(cmd):
                        return
                if text:
                    if text.isascii() and len(text) <= 64:
                        await page.keyboard.type(text, delay=15)
                    else:
                        await page.keyboard.insert_text(text)
                if cmd.get("submit"):
                    if not await self._enforce_human_cmd_live_auth_locked(cmd):
                        return
                    await page.keyboard.press("Enter")
            elif act == "press":
                key = str(cmd.get("key", ""))
                if key:
                    await page.keyboard.press(key)
            elif act == "clear_field":
                await page.keyboard.press("Control+A")
                if not await self._enforce_human_cmd_live_auth_locked(cmd):
                    return
                await page.keyboard.press("Backspace")
            elif act == "goto":
                url = str(cmd.get("url", "")).strip()
                if url:
                    try:
                        enforce_google_profile_policy(
                            url,
                            is_pinned=self._is_active_pinned_verified(),
                            profile_dir=self.active_profile_dir,
                        )
                    except ValueError as exc:
                        owner_bot, owner_uid = self._effective_resource_owner()
                        if owner_bot is not None and owner_uid is not None:
                            await self.broadcast_json_to_owners(
                                {"type": "toast", "message": str(exc)},
                                owner_bot=owner_bot,
                                owner_uid=owner_uid,
                                require_admin=False,
                                expected_session_gen=cmd.get("_session_gen"),
                            )
                        return
                    await page.goto(url, wait_until="domcontentloaded", timeout=45000)
            elif act == "back":
                await page.go_back(wait_until="domcontentloaded", timeout=15000)
            elif act == "forward":
                await page.go_forward(wait_until="domcontentloaded", timeout=15000)
            elif act == "reload":
                await page.reload(wait_until="domcontentloaded", timeout=30000)
            elif act == "switch_tab":
                idx = int(cmd.get("index", 0))
                pages_vis = self._visible_pages()
                if 0 <= idx < len(pages_vis):
                    target_page = pages_vis[idx]
                    self.active_tab_index = idx
                    self._tab_select_rev += 1
                    await target_page.bring_to_front()
            elif act == "new_tab":
                if self.ctx:
                    cur_ctx = self.ctx
                    self._explicit_new_tab_in_flight += 1
                    try:
                        np = await cur_ctx.new_page()
                    finally:
                        self._explicit_new_tab_in_flight = max(0, self._explicit_new_tab_in_flight - 1)
                    # Re-verify (session_gen, takeover_gen, owner, live admin RBAC) AFTER `await new_page()`
                    # BEFORE updating tab selection or navigating; quarantine & fail-closed close outside `_exec_lock` if revoked!
                    if not await self._enforce_human_cmd_live_auth_locked(cmd) or self.ctx is not cur_ctx:
                        post_exec_cleanup_task = self._schedule_fail_closed_close_unguarded_page(
                            np, expected_ctx=cur_ctx, bump_tab_rev=False
                        )
                    elif id(np) in self._closing_unguarded_pages:
                        # Callback `ctx.on('page')` already caught a guard failure during `new_page()`:
                        # merge onto the same deduplicated cleanup task and release `_exec_lock` before awaiting!
                        post_exec_cleanup_task = self._schedule_fail_closed_close_unguarded_page(
                            np, expected_ctx=cur_ctx
                        )
                    else:
                        try:
                            self._attach_page_listeners(np)
                        except Exception as guard_exc:
                            log.error("new_tab listener attachment failed (fail-closed): %s", guard_exc)
                            post_exec_cleanup_task = self._schedule_fail_closed_close_unguarded_page(
                                np, expected_ctx=cur_ctx
                            )
                        else:
                            pages_now = self._visible_pages(cur_ctx)
                            if np in pages_now:
                                self.active_tab_index = pages_now.index(np)
                                self._tab_select_rev += 1
                            new_tab_url = (
                                "https://www.google.com" if self._is_active_pinned_verified() else "about:blank"
                            )
                            await np.goto(new_tab_url, wait_until="domcontentloaded", timeout=30000)
            elif act == "close_tab":
                idx = int(cmd.get("index", -1))
                pages_vis = self._visible_pages()
                if self.ctx and len(pages_vis) > 1 and 0 <= idx < len(pages_vis):
                    cur_ctx = self.ctx
                    target_page = pages_vis[idx]
                    self._explicit_close_tab_in_flight += 1
                    try:
                        await target_page.close()
                    finally:
                        self._explicit_close_tab_in_flight = max(0, self._explicit_close_tab_in_flight - 1)
                    # Re-verify (session_gen, takeover_gen, owner, live admin RBAC) AFTER `await close()`
                    # BEFORE updating selected tab index!
                    if not await self._enforce_human_cmd_live_auth_locked(cmd) or self.ctx is not cur_ctx:
                        return
                    rem_pages = self._visible_pages(cur_ctx)
                    self.active_tab_index = max(0, min(self.active_tab_index, len(rem_pages) - 1)) if rem_pages else 0
                    self._tab_select_rev += 1

            if post_exec_cleanup_task is None and self._is_human_cmd_still_valid(cmd, check_live_rbac=True):
                await self._capture_once()
                if self._is_human_cmd_still_valid(cmd, check_live_rbac=True):
                    await self.broadcast_state()

        # Await deduplicated fail-closed close/teardown strictly AFTER releasing `_exec_lock`
        # so `_stop_hosted_locked()` can acquire `_exec_lock` to release held mouse buttons with zero deadlock!
        # Distinguish child-task cancellation (from concurrent `stop_hosted()` -> `_cancel_and_await_bg_tasks()`)
        # from cancellation of the service-level `_input_loop` task itself so stopping one hosted session
        # NEVER terminates `_input_loop`!
        if post_exec_cleanup_task is not None:
            try:
                await post_exec_cleanup_task
            except asyncio.CancelledError:
                cur_task = asyncio.current_task()
                cancelling_fn = getattr(cur_task, "cancelling", None)
                if cur_task is not None and (cancelling_fn() > 0 if callable(cancelling_fn) else True):
                    raise
                log.debug(
                    "Post-exec unguarded page cleanup task cancelled concurrently; keeping _input_loop alive"
                )

    # ---------------- AI Agent Action RPC ----------------

    async def execute_ai_action(self, payload: dict[str, Any]) -> dict[str, Any]:
        action = str(payload.get("action", "")).strip()
        bot_hint = payload.get("bot")
        raw_uid = payload.get("user_id")
        pref_uid = int(raw_uid) if raw_uid is not None and str(raw_uid).isdigit() and int(raw_uid) > 0 else None
        notify = bool(payload.get("notify", True))
        self.mark_active(mark_tabs_dirty=True)

        if action == "wait_human":
            reason = str(payload.get("reason") or "请点击下方按钮打开面板完成手动操作，完成后点【▶️ 交还给 AI】")
            timeout = float(payload.get("timeout", 600.0))
            if self.engine_mode == "idle":
                await self.start_hosted(bot_hint=bot_hint, notify_tg=notify, preferred_user_id=pref_uid)
            elif notify:
                bot_key = self.resolve_bot_key(bot_hint)
                if bot_key is not None:
                    await self.tg.ensure_card(bot_key, preferred_user_id=pref_uid)
            await self.set_takeover(True, reason=reason, owner=self.session_owner)
            await asyncio.wait_for(self.ai_allowed_event.wait(), timeout=timeout)
            await self._capture_once()
            return {"ok": True, "resumed": True, **self.state_dict()}

        if self.engine_mode == "idle":
            await self.start_hosted(bot_hint=bot_hint, notify_tg=notify, preferred_user_id=pref_uid)
        elif notify and bot_hint:
            bot_key = self.resolve_bot_key(bot_hint)
            if bot_key is not None and not self.tg.has_card_for_bot(bot_key):
                asyncio.create_task(self.tg.ensure_card(bot_key, preferred_user_id=pref_uid))

        self.ai_busy_count += 1
        result_data: dict[str, Any] = {}
        try:
            # Handle pure sleep wait outside `_exec_lock` while still respecting takeover
            if action == "wait" and str(payload["target"]).isdigit():
                await self.wait_until_ai_allowed()
                ms = int(str(payload["target"]))
                self.ai_status = f"等待 {ms}ms..."
                await asyncio.sleep(ms / 1000.0)
                self.ai_status = "等待完成"
            else:
                # Acquire `_exec_lock` while verifying takeover is not active (prevents AI/human collision)
                while True:
                    await self.wait_until_ai_allowed()
                    async with self._exec_lock:
                        if self.takeover:
                            continue
                        page = self._current_page()
                        if not page:
                            raise RuntimeError("没有可用的浏览器标签页。")

                        if action == "goto":
                            url = str(payload["url"])
                            enforce_google_profile_policy(
                                url,
                                is_pinned=self._is_active_pinned_verified(),
                                profile_dir=self.active_profile_dir,
                            )
                            self.ai_status = f"正在打开: {url[:60]}"
                            await self.broadcast_state()
                            await page.goto(
                                url,
                                wait_until=str(payload.get("wait_until", "domcontentloaded")),
                                timeout=int(payload.get("timeout", 45000)),
                            )
                            self.ai_status = f"已打开: {page.url[:60]}"

                        elif action == "click":
                            target = str(payload["target"])
                            self.ai_status = f"正在点击: {target[:50]}"
                            await self.broadcast_state()
                            if "," in target and all(
                                p.strip().replace(".", "", 1).isdigit() for p in target.split(",", 1)
                            ):
                                xs, ys = target.split(",", 1)
                                x, y = float(xs.strip()), float(ys.strip())
                                self.cursor = {"x": x, "y": y, "actor": "ai", "ts": time.time()}
                                await page.mouse.click(x, y)
                            else:
                                loc = page.locator(target).first
                                box = await loc.bounding_box(timeout=int(payload.get("timeout", 15000)))
                                if box:
                                    cx = round(box["x"] + box["width"] / 2, 1)
                                    cy = round(box["y"] + box["height"] / 2, 1)
                                    self.cursor = {"x": cx, "y": cy, "actor": "ai", "ts": time.time()}
                                await loc.click(timeout=int(payload.get("timeout", 15000)))
                            self.ai_status = f"已点击: {target[:50]}"

                        elif action == "fill":
                            selector = str(payload["selector"])
                            text = str(payload["text"])
                            self.ai_status = f"正在填写: {selector[:40]}"
                            await self.broadcast_state()
                            await page.locator(selector).first.fill(
                                text, timeout=int(payload.get("timeout", 15000))
                            )
                            if payload.get("submit"):
                                await page.keyboard.press("Enter")
                            self.ai_status = f"已填写: {selector[:40]}"

                        elif action == "type":
                            text = str(payload["text"])
                            self.ai_status = "正在输入文字..."
                            await self.broadcast_state()
                            await page.keyboard.type(text, delay=int(payload.get("delay", 20)))
                            if payload.get("submit"):
                                await page.keyboard.press("Enter")
                            self.ai_status = "已完成文字输入"

                        elif action == "press":
                            key = str(payload["key"])
                            self.ai_status = f"按键: {key}"
                            await page.keyboard.press(key)

                        elif action == "wait":
                            target = str(payload["target"])
                            self.ai_status = f"等待元素: {target[:45]}"
                            await page.locator(target).first.wait_for(
                                state="visible", timeout=int(payload.get("timeout", 30000))
                            )
                            self.ai_status = "等待完成"

                        elif action == "text":
                            selector = str(payload.get("selector") or "body")
                            txt = await page.locator(selector).first.inner_text(
                                timeout=int(payload.get("timeout", 10000))
                            )
                            result_data["text"] = txt

                        elif action == "eval":
                            expr = str(payload["expression"])
                            val = await page.evaluate(expr)
                            result_data["value"] = val

                        elif action == "screenshot":
                            out = Path(str(payload["path"])).expanduser().resolve()
                            out.parent.mkdir(parents=True, exist_ok=True)
                            await page.screenshot(path=str(out), full_page=bool(payload.get("full_page", False)))
                            result_data["screenshot"] = str(out)

                        else:
                            raise ValueError(f"Unknown AI action: {action}")
                        break

            await self._capture_once()
        finally:
            # Decrement ai_busy_count BEFORE broadcasting final state so clients see `ai_busy=False`
            self.ai_busy_count = max(0, self.ai_busy_count - 1)
            await self.broadcast_state()
        asyncio.create_task(self.tg.tick_updates(force=False))
        return {"ok": True, **result_data, "url": self.url, "title": self.title}


# ---------------- HTTP & WebSocket Route Handlers ----------------


def check_local_auth(request: web.Request, hub: LiveBrowserHub) -> None:
    peer = request.remote or ""
    if peer not in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        raise web.HTTPForbidden(text="Localhost only")
    tok = request.headers.get("X-Live-Token", "")
    if not hmac.compare_digest(tok, hub.local_token):
        raise web.HTTPForbidden(text="Invalid local token")


async def handle_index(_request: web.Request) -> web.FileResponse:
    # Serves ONLY the zero-data static UI shell; all state/frames require WS HMAC auth.
    return web.FileResponse(
        STATIC_DIR / "index.html",
        headers={"Cache-Control": "no-store, max-age=0"},
    )


async def handle_healthz(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    return web.json_response({"ok": True, "running": hub.engine_mode != "idle"})


async def _ws_send_json(ws: web.WebSocketResponse, payload: dict[str, Any]) -> None:
    if not ws.closed:
        await ws.send_str(json.dumps(payload, ensure_ascii=False))


async def _ws_launch_or_switch(
    ws: web.WebSocketResponse,
    hub: LiveBrowserHub,
    *,
    profile: str | None,
    initial_url: str | None,
    bot_key: str,
    restart: bool,
    takeover: bool,
    takeover_reason: str,
    preferred_user_id: int | None = None,
    expected_session_gen: int | None = None,
) -> None:
    try:
        actor = (bot_key, int(preferred_user_id)) if preferred_user_id is not None and int(preferred_user_id) > 0 else None
        st = await hub.start_hosted(
            initial_url=initial_url,
            bot_hint=bot_key,
            notify_tg=True,
            profile=profile,
            restart=restart,
            preferred_user_id=preferred_user_id,
            actor=actor,
            source="ws",
            expected_session_gen=expected_session_gen,
        )
        started_sgen = _parse_strict_int(st.get("session_gen"))
        started_tgen = _parse_strict_int(st.get("takeover_gen"))
        if takeover and not hub.takeover:
            await hub.set_takeover(
                True,
                takeover_reason,
                owner=(bot_key, preferred_user_id),
                expected_session_gen=started_sgen,
                expected_takeover_gen=started_tgen,
                actor=actor,
            )
    except (PermissionError, ValueError, KeyError, FileNotFoundError, RuntimeError, TimeoutError) as exc:
        await _ws_send_json(ws, {"type": "toast", "message": str(exc)})
        await hub.broadcast_state()
    except Exception as exc:
        log.warning("WS launch/switch failed: %s", exc)
        await _ws_send_json(ws, {"type": "toast", "message": f"浏览器操作失败: {exc}"})
        await hub.broadcast_state()


def _parse_strict_int(raw: Any) -> int | None:
    """Parse an integer strictly (rejecting None, bool, floats, and non-ASCII/non-numeric strings)."""
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return None
        digits = s[1:] if s.startswith("-") else s
        if not digits or not digits.isascii() or not digits.isdigit():
            return None
        try:
            return int(s)
        except (TypeError, ValueError):
            return None
    return None


async def handle_ws(request: web.Request) -> web.WebSocketResponse:
    hub: LiveBrowserHub = request.app["hub"]
    ws = web.WebSocketResponse(heartbeat=25.0, max_msg_size=2 * 1024 * 1024)
    await ws.prepare(request)

    authenticated = False
    bot_key = ""
    user_id = 0
    role = "denied"
    try:
        # First message within 8s MUST be valid Telegram initData auth
        first_msg = await asyncio.wait_for(ws.receive(), timeout=8.0)
        if first_msg.type != WSMsgType.TEXT:
            await ws.close(code=WS_CLOSE_AUTH_FORBIDDEN, message=b"Forbidden")
            return ws

        auth_payload = json.loads(first_msg.data)
        if auth_payload.get("type") != "auth":
            await ws.send_str(json.dumps({"type": "auth_error", "error": "未提供身份认证帧"}))
            await ws.close(code=WS_CLOSE_AUTH_FORBIDDEN, message=b"Forbidden")
            return ws

        ok, info, err = _authenticate_init_data(str(auth_payload.get("initData", "")))
        if not ok or not info:
            log.warning("Rejected Mini App WS auth from %s: %s", request.remote, err)
            await ws.send_str(json.dumps({"type": "auth_error", "error": err}))
            await ws.close(code=WS_CLOSE_AUTH_FORBIDDEN, message=b"Forbidden")
            return ws

        authenticated = True
        bot_key = str(info["bot"])
        user_id = int(info["user_id"])
        role = str(info.get("role") or "admin")
        hub.viewers.add(ws)
        hub.viewer_meta[ws] = {"user_id": user_id, "bot_key": bot_key, "role": role}
        hub.mark_active()
        log.info(
            "Mini App viewer connected (user=%s, bot=%s, role=%s, total=%d)",
            user_id,
            bot_key,
            role,
            len(hub.viewers),
        )

        async def _require_live_auth() -> bool:
            nonlocal role
            live_role = _check_live_user_role(bot_key, user_id)
            if live_role == "denied":
                await hub._evict_revoked_viewer(ws, reason="访问权限已被撤销")
                return False
            role = live_role
            if ws in hub.viewer_meta:
                hub.viewer_meta[ws]["role"] = role
            return True

        async def _require_live_reader(action_label: str) -> bool:
            if not await _require_live_auth():
                return False
            if not hub._viewer_can_read_session(bot_key, user_id, role):
                await _ws_send_json(
                    ws,
                    {"type": "toast", "message": f"🔒 当前浏览器由其他授权会话占用，不可{action_label}"},
                )
                return False
            return True

        async def _require_live_admin(action_label: str) -> bool:
            if not await _require_live_auth():
                return False
            if role != "admin":
                await _ws_send_json(
                    ws,
                    {"type": "toast", "message": f"🔒 只读权限（readonly）不可执行：{action_label}"},
                )
                return False
            return True

        # Clean expired choosers synchronously before capturing coherent initial replay snapshot
        expired_choosers = hub._cleanup_pending_filechoosers(page_id=-1)
        for exp_c in expired_choosers:
            if exp_c.get("owner_bot") is not None and exp_c.get("owner_uid") is not None:
                try:
                    asyncio.get_running_loop().create_task(
                        hub.broadcast_json_to_owners(
                            {"type": "filechooser_closed", "chooser_id": exp_c["id"]},
                            owner_bot=exp_c.get("owner_bot"),
                            owner_uid=exp_c.get("owner_uid"),
                            require_admin=True,
                            expected_session_gen=exp_c.get("session_gen"),
                        )
                    )
                except RuntimeError:
                    pass

        # Synchronous critical section: capture coherent `(snap_gen, snap_owner, snap_mode)` snapshot!
        snap_gen = hub.session_gen
        snap_owner = hub.session_owner
        snap_mode = hub.engine_mode
        snap_state_full = json.dumps(hub.state_dict(), ensure_ascii=False)
        snap_state_redacted = json.dumps(hub._redacted_state_dict(), ensure_ascii=False)
        snap_jpeg = hub.latest_jpeg
        snap_dialogs = [
            dict(p)
            for p in hub.pending_dialogs.values()
            if p.get("session_gen") == snap_gen
        ]
        now_mono = time.monotonic()
        snap_choosers = [
            dict(c)
            for c in hub.pending_filechoosers.values()
            if c.get("session_gen") == snap_gen
            and (now_mono - float(c.get("created_ts", 0.0))) <= TRANSFER_TTL_SECONDS
        ]

        await ws.send_str(json.dumps({"type": "auth_ok", **info}))

        # Re-verify live auth, role, owner & session_gen BEFORE EVERY SINGLE replay send!
        def _snap_still_current() -> bool:
            return (
                hub.session_gen == snap_gen
                and hub.session_owner == snap_owner
                and hub.engine_mode == snap_mode
            )

        if not await _require_live_auth():
            return ws
        if _snap_still_current():
            can_read_snap = (snap_mode == "idle") or hub._viewer_can_read_session(bot_key, user_id, role)
            await ws.send_str(snap_state_full if can_read_snap else snap_state_redacted)
        else:
            # Session transitioned during auth_ok send; send fresh state bound to live auth/owner
            if not await _require_live_auth():
                return ws
            await ws.send_str(json.dumps(hub.state_dict_for_viewer(bot_key, user_id, role), ensure_ascii=False))

        if snap_jpeg and snap_mode != "idle":
            if not await _require_live_auth():
                return ws
            if _snap_still_current() and hub._viewer_can_read_session(bot_key, user_id, role):
                await ws.send_bytes(snap_jpeg)

        for pending in snap_dialogs:
            if not await _require_live_auth():
                return ws
            if not _snap_still_current():
                break
            if pending["id"] not in hub.pending_dialogs:
                continue
            if hub._can_access_resource(pending, bot_key, user_id, role, require_admin=True):
                await _ws_send_json(
                    ws,
                    {
                        "type": "dialog_open",
                        "dialog_id": pending["id"],
                        "dialog_type": pending["dialog_type"],
                        "message": pending["message"],
                        "default_value": pending["default_value"],
                    },
                )

        for chooser_entry in snap_choosers:
            if not await _require_live_auth():
                return ws
            if not _snap_still_current():
                break
            live_entry = hub.pending_filechoosers.get(chooser_entry["id"])
            if not live_entry:
                continue
            if (time.monotonic() - float(live_entry.get("created_ts", 0.0))) > TRANSFER_TTL_SECONDS:
                continue
            if hub._can_access_resource(live_entry, bot_key, user_id, role, require_admin=True):
                await _ws_send_json(
                    ws,
                    {
                        "type": "filechooser_open",
                        "chooser_id": chooser_entry["id"],
                        "multiple": bool(chooser_entry.get("multiple")),
                    },
                )

        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                continue
            data = json.loads(msg.data)
            mtype = data.get("type")
            if mtype == "ping":
                if not await _require_live_auth():
                    break
                await ws.send_str(json.dumps({"type": "pong", "t": data.get("t", 0)}))
            elif mtype == "list_profiles":
                if not await _require_live_auth():
                    break
                can_read = hub._viewer_can_read_session(bot_key, user_id, role)
                try:
                    prof_list = list_profiles(active_profile=(hub.active_profile if can_read else ""))
                except RuntimeError as exc:
                    await _ws_send_json(ws, {"type": "toast", "message": f"❌ {exc}"})
                    continue
                await _ws_send_json(
                    ws,
                    {
                        "type": "profiles_list",
                        "active_profile": (hub.active_profile or None) if can_read else None,
                        "pinned": hub.active_pinned if can_read else False,
                        "running": (hub.engine_mode != "idle") if can_read else False,
                        "ai_busy": (hub.ai_busy_count > 0) if can_read else False,
                        "takeover": hub.takeover if can_read else False,
                        "profiles": prof_list,
                    },
                )
            elif mtype == "set_takeover":
                req_id = data.get("req_id")
                if not await _require_live_admin("接管控制"):
                    if ws.closed:
                        break
                    if req_id is not None:
                        await _ws_send_json(
                            ws,
                            {
                                "type": "takeover_ack",
                                "req_id": str(req_id),
                                "ok": False,
                                "takeover": False,
                                "session_gen": hub.session_gen,
                                "takeover_gen": hub.takeover_gen,
                                "error": "只读权限不可接管",
                            },
                        )
                    continue
                # Require explicit integer BOTH `session_gen` AND `takeover_gen` — NEVER auto-fill!
                cli_sgen = _parse_strict_int(data.get("session_gen"))
                cli_tgen = _parse_strict_int(data.get("takeover_gen"))
                if (
                    cli_sgen is None
                    or cli_sgen != hub.session_gen
                    or cli_tgen is None
                    or cli_tgen != hub.takeover_gen
                ):
                    err_msg = "缺少或过期的 session_gen/takeover_gen，已拒绝接管请求"
                    if req_id is not None:
                        await _ws_send_json(
                            ws,
                            {
                                "type": "takeover_ack",
                                "req_id": str(req_id),
                                "ok": False,
                                "takeover": False,
                                "session_gen": hub.session_gen,
                                "takeover_gen": hub.takeover_gen,
                                "error": err_msg,
                            },
                        )
                    continue
                if not hub._viewer_can_control_takeover(bot_key, user_id, role):
                    err_msg = "🔒 当前浏览器会话由其他 Bot/用户持有，无权接管或释放"
                    await _ws_send_json(ws, {"type": "toast", "message": err_msg})
                    if req_id is not None:
                        await _ws_send_json(
                            ws,
                            {
                                "type": "takeover_ack",
                                "req_id": str(req_id),
                                "ok": False,
                                "takeover": False,
                                "session_gen": hub.session_gen,
                                "takeover_gen": hub.takeover_gen,
                                "error": err_msg,
                            },
                        )
                    continue
                want = bool(data.get("active"))
                if want and hub.engine_mode == "idle":
                    err_msg = "当前浏览器未运行"
                    await _ws_send_json(ws, {"type": "toast", "message": err_msg})
                    if req_id is not None:
                        await _ws_send_json(
                            ws,
                            {
                                "type": "takeover_ack",
                                "req_id": str(req_id),
                                "ok": False,
                                "takeover": False,
                                "session_gen": hub.session_gen,
                                "takeover_gen": hub.takeover_gen,
                                "error": err_msg,
                            },
                        )
                    continue
                ok_tk, err_tk, ack_sgen, ack_tgen = await hub.set_takeover(
                    want,
                    str(data.get("reason", "")),
                    owner=(bot_key, user_id) if want else None,
                    expected_session_gen=cli_sgen,
                    expected_takeover_gen=cli_tgen,
                    actor=(bot_key, user_id),
                )
                if not ok_tk and not req_id:
                    await _ws_send_json(ws, {"type": "toast", "message": err_tk})
                if req_id is not None:
                    # Bind ACK strictly to the locked `(ack_sgen, ack_tgen, want)` snapshot (never post-await hub.takeover!)
                    await _ws_send_json(
                        ws,
                        {
                            "type": "takeover_ack",
                            "req_id": str(req_id),
                            "ok": bool(ok_tk),
                            "takeover": bool(want) if ok_tk else False,
                            "session_gen": ack_sgen,
                            "takeover_gen": ack_tgen,
                            "owner_bot": bot_key,
                            "owner_uid": user_id,
                            **({} if ok_tk else {"error": err_tk}),
                        },
                    )
            elif mtype == "set_quality":
                if not await _require_live_admin("切换画质"):
                    continue
                if not hub._viewer_can_mutate(bot_key, user_id, role):
                    await _ws_send_json(ws, {"type": "toast", "message": "🔒 无权修改当前会话画质"})
                    continue
                chosen = await hub.set_quality_preset(str(data.get("preset") or "balanced"))
                label_map = {"smooth": "流畅", "balanced": "均衡", "hd": "高清"}
                await _ws_send_json(
                    ws, {"type": "toast", "message": f"🎬 画质已切换为：{label_map.get(chosen, chosen)}"}
                )
            elif mtype == "dialog_response":
                if not await _require_live_admin("处理网页弹窗"):
                    continue
                did = str(data.get("dialog_id") or "")
                entry = hub.pending_dialogs.get(did)
                if not entry:
                    continue
                if not hub._can_access_resource(entry, bot_key, user_id, role, require_admin=True):
                    await _ws_send_json(ws, {"type": "toast", "message": "🔒 无权操作该网页弹窗"})
                    continue
                accept = bool(data.get("accept"))
                prompt_text = data.get("prompt_text")
                await hub.resolve_dialog(did, accept=accept, prompt_text=prompt_text)
            elif mtype == "filechooser_cancel":
                if not await _require_live_admin("取消文件上传"):
                    continue
                cid = str(data.get("chooser_id") or "")
                entry = hub.pending_filechoosers.get(cid)
                if not entry:
                    continue
                if not hub._can_access_resource(entry, bot_key, user_id, role, require_admin=True):
                    await _ws_send_json(ws, {"type": "toast", "message": "🔒 无权取消该文件选择会话"})
                    continue
                hub.pending_filechoosers.pop(cid, None)
                await hub.broadcast_json_to_owners(
                    {"type": "filechooser_closed", "chooser_id": cid},
                    owner_bot=entry.get("owner_bot"),
                    owner_uid=entry.get("owner_uid"),
                    require_admin=True,
                    expected_session_gen=entry.get("session_gen"),
                )
            elif mtype == "send_download_to_tg":
                if not await _require_live_admin("发送下载文件到 TG"):
                    continue
                did = str(data.get("download_id") or "")
                ok_dl, msg_dl = await hub.send_download_to_tg(
                    did, bot_key, preferred_user_id=user_id, role=role
                )
                await _ws_send_json(ws, {"type": "toast", "message": msg_dl})
            elif mtype == "send_hd_screenshot":
                if not await _require_live_admin("发送高清截图"):
                    continue
                if hub.engine_mode == "idle":
                    await _ws_send_json(ws, {"type": "toast", "message": "当前浏览器未运行，暂无可发送的画面"})
                    continue
                if not hub._viewer_can_mutate(bot_key, user_id, role):
                    await _ws_send_json(ws, {"type": "toast", "message": "🔒 无权导出当前会话高清截图"})
                    continue
                shot_bytes: bytes | None = None
                cap_gen = hub.session_gen
                if hub.engine_mode == "async_hosted":
                    page = hub._current_page()
                    if page:
                        try:
                            raw_shot = await asyncio.wait_for(
                                page.screenshot(type="jpeg", quality=92, animations="allow"),
                                timeout=4.0,
                            )
                            if hub.engine_mode == "async_hosted" and hub.session_gen == cap_gen:
                                shot_bytes = raw_shot
                        except Exception:
                            if hub.session_gen == cap_gen:
                                shot_bytes = hub.latest_jpeg
                elif hub.session_gen == cap_gen:
                    shot_bytes = hub.latest_jpeg
                if not shot_bytes:
                    await _ws_send_json(ws, {"type": "toast", "message": "当前暂无可发送的画面"})
                else:
                    cap = (
                        f"📸 <b>浏览器高清截图</b>\n"
                        f"📄 {html.escape((hub.title or '无标题')[:80])}\n"
                        f"🔗 <code>{html.escape((hub.url or '')[:140])}</code>"
                    )
                    sent_ok = await hub.tg.send_photo_bytes(
                        bot_key, shot_bytes, caption=cap, preferred_user_id=user_id
                    )
                    await _ws_send_json(
                        ws,
                        {
                            "type": "toast",
                            "message": "✅ 高清截图已发送到私聊 TG" if sent_ok else "发送高清截图失败",
                        },
                    )
            elif mtype == "start_browser":
                if not await _require_live_admin("启动浏览器"):
                    continue
                # Strict integer session_gen required — NEVER auto-fill missing/invalid values!
                ws_sgen = _parse_strict_int(data.get("session_gen"))
                if ws_sgen is None or ws_sgen != hub.session_gen:
                    await _ws_send_json(ws, {"type": "toast", "message": "会话代次缺失或已变更，已拒绝启动请求"})
                    await hub.broadcast_state()
                    continue
                if hub.engine_mode == "idle":
                    req_profile = str(data.get("profile") or "").strip() or None
                    raw_url = str(data.get("url") or "").strip()
                    try:
                        spec = resolve_launch_spec(profile_name=req_profile)
                        req_url = raw_url or ("https://www.google.com" if spec.get("pinned_verified") else "about:blank")
                        enforce_google_profile_policy(
                            req_url,
                            is_pinned=bool(spec.get("pinned_verified")),
                            profile_dir=Path(spec["profile_dir"]) if spec.get("profile_dir") else None,
                        )
                    except (ValueError, KeyError, FileNotFoundError, RuntimeError) as exc:
                        await _ws_send_json(ws, {"type": "toast", "message": f"❌ {exc}"})
                        await hub.broadcast_state()
                        continue
                    asyncio.create_task(
                        _ws_launch_or_switch(
                            ws,
                            hub,
                            profile=req_profile,
                            initial_url=req_url,
                            bot_key=bot_key,
                            restart=False,
                            takeover=bool(data.get("takeover")),
                            takeover_reason="手动启动浏览器接管模式",
                            preferred_user_id=user_id,
                            expected_session_gen=ws_sgen,
                        )
                    )
                else:
                    await _ws_send_json(ws, {"type": "toast", "message": "浏览器已在运行中"})
                    await hub.broadcast_state()
            elif mtype == "switch_profile":
                if not await _require_live_admin("切换浏览器指纹"):
                    continue
                ws_sgen = _parse_strict_int(data.get("session_gen"))
                if ws_sgen is None or ws_sgen != hub.session_gen:
                    await _ws_send_json(ws, {"type": "toast", "message": "会话代次缺失或已变更，已拒绝切换请求"})
                    await hub.broadcast_state()
                    continue
                if hub.engine_mode != "idle" and not hub._viewer_can_mutate(bot_key, user_id, role):
                    await _ws_send_json(ws, {"type": "toast", "message": "🔒 无权切换其他 Bot/用户持有的浏览器会话"})
                    continue
                target_profile = str(data.get("profile") or "").strip()
                raw_url = str(data.get("url") or "").strip() or None
                if not target_profile:
                    await _ws_send_json(ws, {"type": "toast", "message": "❌ 请指定要切换的 Profile 名称"})
                    await hub.broadcast_state()
                    continue
                try:
                    spec = resolve_launch_spec(profile_name=target_profile)
                    req_url = raw_url
                    if not req_url:
                        req_url = "https://www.google.com" if spec.get("pinned_verified") else "about:blank"
                    enforce_google_profile_policy(
                        req_url,
                        is_pinned=bool(spec.get("pinned_verified")),
                        profile_dir=Path(spec["profile_dir"]) if spec.get("profile_dir") else None,
                    )
                except (ValueError, KeyError, FileNotFoundError, RuntimeError) as exc:
                    await _ws_send_json(ws, {"type": "toast", "message": f"❌ Profile 无效: {exc}"})
                    await hub.broadcast_state()
                    continue
                asyncio.create_task(
                    _ws_launch_or_switch(
                        ws,
                        hub,
                        profile=target_profile,
                        initial_url=req_url,
                        bot_key=bot_key,
                        restart=True,
                        takeover=bool(data.get("takeover")),
                        takeover_reason=f"切换指纹 {target_profile} 并接管",
                        preferred_user_id=user_id,
                        expected_session_gen=ws_sgen,
                    )
                )
            elif mtype == "stop_browser":
                if not await _require_live_admin("关闭浏览器"):
                    continue
                ws_sgen = _parse_strict_int(data.get("session_gen"))
                if ws_sgen is None or ws_sgen != hub.session_gen:
                    await _ws_send_json(ws, {"type": "toast", "message": "会话代次缺失或已变更，已拒绝关闭请求"})
                    await hub.broadcast_state()
                    continue
                if hub.engine_mode == "sync_external":
                    await _ws_send_json(ws, {"type": "toast", "message": "当前为外部脚本联动会话，无法从面板直接关闭"})
                    await hub.broadcast_state()
                elif hub.engine_mode == "async_hosted":
                    if not hub._viewer_can_mutate(bot_key, user_id, role):
                        await _ws_send_json(ws, {"type": "toast", "message": "🔒 无权关闭其他 Bot/用户持有的浏览器会话"})
                        continue
                    if hub.ai_busy_count > 0:
                        await _ws_send_json(ws, {"type": "toast", "message": "AI 正在执行浏览器操作，请稍候再关闭"})
                        await hub.broadcast_state()
                    else:
                        ok_st_ws, err_st_ws = await hub.stop_hosted(
                            notify_finished=True,
                            actor=(bot_key, user_id),
                            source="ws",
                            expected_session_gen=ws_sgen,
                        )
                        if not ok_st_ws:
                            await _ws_send_json(ws, {"type": "toast", "message": err_st_ws})
                else:
                    await hub.broadcast_state()
            elif mtype == "extract":
                if not await _require_live_reader("提取页面内容"):
                    if ws.closed:
                        break
                    continue
                # Require explicit integer BOTH `session_gen` AND `takeover_gen` — NEVER auto-fill!
                cli_sgen = _parse_strict_int(data.get("session_gen"))
                cli_tgen = _parse_strict_int(data.get("takeover_gen"))
                if (
                    cli_sgen is None
                    or cli_sgen != hub.session_gen
                    or cli_tgen is None
                    or cli_tgen != hub.takeover_gen
                ):
                    continue
                req_gen = hub.session_gen
                req_tgen = hub.takeover_gen
                req_owner = hub.session_owner
                hub.mark_active()
                if hub.engine_mode == "async_hosted":
                    clip_res = await hub.extract_content_async(
                        data,
                        expected_session_gen=req_gen,
                        expected_takeover_gen=req_tgen,
                        expected_owner=req_owner,
                        check_owner=True,
                    )
                    # Post-await live auth, owner & BOTH generations re-verification before sending extract result!
                    if not await _require_live_auth():
                        break
                    if (
                        hub.engine_mode != "async_hosted"
                        or hub.session_gen != req_gen
                        or hub.takeover_gen != req_tgen
                        or hub.session_owner != req_owner
                        or not hub._viewer_can_read_session(bot_key, user_id, role)
                    ):
                        continue
                    if clip_res and clip_res.get("preview"):
                        preview_payload: dict[str, Any] = {
                            "type": "selection_preview",
                            "text": clip_res.get("text", ""),
                        }
                        if "extract_gen" in data:
                            preview_payload["extract_gen"] = data["extract_gen"]
                        await ws.send_str(json.dumps(preview_payload, ensure_ascii=False))
                    elif clip_res:
                        await ws.send_str(json.dumps({"type": "clipboard", **clip_res}, ensure_ascii=False))
                    elif data.get("mode") != "range_preview":
                        await ws.send_str(json.dumps({"type": "toast", "message": "未选中文字，请直接在文字上拖动涂抹或轻点段落"}))
                elif hub.engine_mode == "sync_external":
                    # Strict field whitelist before forwarding read-only extract command to Sync producer
                    mode = str(data.get("mode") or "point").strip()
                    if mode not in _SYNC_EXTRACT_ALLOWED_MODES:
                        await _ws_send_json(ws, {"type": "toast", "message": "不支持的提取模式"})
                        continue
                    ext_req_id = secrets.token_hex(8)
                    safe_extract: dict[str, Any] = {
                        "action": "extract",
                        "mode": mode,
                        "req_id": ext_req_id,
                        "session_gen": req_gen,
                        "takeover_gen": req_tgen,
                        "_bot_key": bot_key,
                        "_user_id": user_id,
                    }
                    try:
                        if mode == "point":
                            x_val = float(data.get("x", 0))
                            y_val = float(data.get("y", 0))
                            if not (-100000.0 <= x_val <= 100000.0 and -100000.0 <= y_val <= 100000.0):
                                continue
                            safe_extract["x"] = x_val
                            safe_extract["y"] = y_val
                        elif mode in ("range", "range_preview"):
                            for coord_k in ("x1", "y1", "x2", "y2"):
                                c_val = float(data.get(coord_k, 0))
                                if not (-100000.0 <= c_val <= 100000.0):
                                    raise ValueError("coord out of range")
                                safe_extract[coord_k] = c_val
                            if mode == "range_preview" and "extract_gen" in data:
                                eg = _parse_strict_int(data.get("extract_gen"))
                                if eg is not None:
                                    safe_extract["extract_gen"] = eg
                    except (TypeError, ValueError):
                        continue
                    now_ext = time.monotonic()
                    if len(hub._pending_sync_extracts) >= 128:
                        for old_k, old_v in list(hub._pending_sync_extracts.items()):
                            if (now_ext - float(old_v.get("created_ts", 0.0))) > 60.0 or len(hub._pending_sync_extracts) >= 128:
                                hub._pending_sync_extracts.pop(old_k, None)
                    hub._pending_sync_extracts[ext_req_id] = {
                        "bot_key": bot_key,
                        "user_id": user_id,
                        "session_gen": req_gen,
                        "takeover_gen": req_tgen,
                        "owner": req_owner,
                        "ws": ws,
                        "created_ts": now_ext,
                    }
                    hub._enqueue_sync_cmd(safe_extract)
                else:
                    await ws.send_str(json.dumps({"type": "toast", "message": "当前浏览器未运行"}))
            elif mtype == "read_clipboard":
                if not await _require_live_reader("读取剪贴板"):
                    if ws.closed:
                        break
                    continue
                req_gen = hub.session_gen
                req_tgen = hub.takeover_gen
                req_owner = hub.session_owner
                hub.mark_active()
                if hub.engine_mode == "idle":
                    await ws.send_str(json.dumps({"type": "toast", "message": "当前浏览器未运行"}))
                elif hub.engine_mode == "async_hosted":
                    clip_res = await hub.extract_content_async(
                        {"mode": "selection"},
                        expected_session_gen=req_gen,
                        expected_takeover_gen=req_tgen,
                        expected_owner=req_owner,
                        check_owner=True,
                    )
                    if not await _require_live_auth():
                        break
                    if (
                        hub.engine_mode != "async_hosted"
                        or hub.session_gen != req_gen
                        or hub.takeover_gen != req_tgen
                        or hub.session_owner != req_owner
                        or not hub._viewer_can_read_session(bot_key, user_id, role)
                    ):
                        continue
                    if clip_res:
                        await ws.send_str(json.dumps({"type": "clipboard", **clip_res}, ensure_ascii=False))
                elif hub.latest_clip:
                    await ws.send_str(json.dumps({"type": "clipboard", **hub.latest_clip}, ensure_ascii=False))
                else:
                    await ws.send_str(
                        json.dumps(
                            {
                                "type": "clipboard",
                                "text": hub.url or "",
                                "source": "剪贴板为空（可点【👆 点画面文字提取】）",
                                "url": hub.url or "",
                                "ts": time.time(),
                            },
                            ensure_ascii=False,
                        )
                    )
            elif mtype == "send_to_tg":
                if not await _require_live_admin("发送文本到 TG"):
                    if ws.closed:
                        break
                    continue
                txt = str(data.get("text") or "").strip()
                if txt:
                    sent = await hub.tg.send_clip_message(bot_key, txt, preferred_user_id=user_id)
                    await ws.send_str(
                        json.dumps(
                            {
                                "type": "toast",
                                "message": "✅ 已发送到私聊 TG 聊天框" if sent else "发送 TG 消息失败",
                            },
                            ensure_ascii=False,
                        )
                    )
            elif mtype == "input":
                if not await _require_live_admin("操作浏览器"):
                    if ws.closed:
                        break
                    continue
                if not hub.takeover:
                    await ws.send_str(
                        json.dumps({"type": "toast", "message": "请先点击右上角【🖐 一键接管】"})
                    )
                    continue
                if not hub._viewer_can_control_takeover(bot_key, user_id, role):
                    await _ws_send_json(ws, {"type": "toast", "message": "🔒 当前接管控制权属于其他 Bot/用户"})
                    continue
                # STRICT generation requirement: missing or stale `session_gen` / `takeover_gen` MUST be dropped, NEVER auto-filled!
                cli_sgen = _parse_strict_int(data.get("session_gen"))
                cli_tgen = _parse_strict_int(data.get("takeover_gen"))
                if cli_sgen is None or cli_sgen != hub.session_gen:
                    continue
                if cli_tgen is None or cli_tgen != hub.takeover_gen:
                    continue

                clean_payload = {
                    k: v
                    for k, v in data.items()
                    if k not in ("session_gen", "takeover_gen", "cleanup") and not str(k).startswith("_")
                }
                enriched = {
                    **clean_payload,
                    "_session_gen": cli_sgen,
                    "_takeover_gen": cli_tgen,
                    "_bot_key": bot_key,
                    "_user_id": user_id,
                }
                if hub.input_queue.full():
                    # Never silently drop mouseup on overflow: make room or force fallback release
                    if enriched.get("action") == "mouseup":
                        hub._drain_input_queue()
                        await hub.input_queue.put(enriched)
                    elif enriched.get("action") not in ("move", "wheel"):
                        try:
                            hub.input_queue.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                        await hub.input_queue.put(enriched)
                else:
                    await hub.input_queue.put(enriched)
    except asyncio.TimeoutError:
        log.debug("WS auth timeout from %s", request.remote)
    except Exception as exc:
        log.debug("WS closed (%s): %s", request.remote, exc)
    finally:
        if authenticated:
            hub.viewers.discard(ws)
            hub.viewer_meta.pop(ws, None)
            log.info("Mini App viewer disconnected (user=%s, bot=%s, remaining=%d)", user_id, bot_key, len(hub.viewers))
            # Check if disconnecting viewer held takeover control and no other WS for that owner remains
            is_takeover_holder = hub.takeover and (
                hub.takeover_owner is None
                or (
                    hub.takeover_owner[0] == bot_key
                    and (hub.takeover_owner[1] is None or hub.takeover_owner[1] == user_id)
                )
            )
            still_has_owner_ws = any(
                not getattr(other_ws, "closed", False)
                and (hub.viewer_meta.get(other_ws) or {}).get("bot_key") == bot_key
                and (hub.viewer_meta.get(other_ws) or {}).get("user_id") == user_id
                for other_ws in list(hub.viewers)
            )
            if is_takeover_holder and not still_has_owner_ws:
                # Immediately bump takeover_gen BEFORE acquiring _exec_lock so any suspended
                # in-flight `mousedown` (e.g. awaiting `mouse.move`) sees stale gen and skips `mouse.down`!
                hub.takeover_gen += 1
                hub._drain_input_queue()
                async with hub._exec_lock:
                    await hub._release_held_mouse_buttons_locked()
                    if hub.engine_mode == "sync_external" and hub._sync_buttons_down:
                        for btn in list(hub._sync_buttons_down):
                            hub.sync_cmd_queue.append(
                                {
                                    "action": "mouseup",
                                    "button": btn,
                                    "x": 0,
                                    "y": 0,
                                    "session_gen": hub.session_gen,
                                    "takeover_gen": hub.takeover_gen,
                                    "cleanup": True,
                                    "_server_internal": True,
                                }
                            )
                        hub._sync_buttons_down.clear()
            elif hub._mouse_buttons_down and (
                hub.takeover_owner is None
                or (
                    hub.takeover_owner[0] == bot_key
                    and (hub.takeover_owner[1] is None or hub.takeover_owner[1] == user_id)
                )
            ):
                async with hub._exec_lock:
                    await hub._release_held_mouse_buttons_locked()
            # Auto-dismiss any pending dialogs with no eligible admin viewer left
            if hub.pending_dialogs:
                await hub._dismiss_orphaned_dialogs_on_disconnect()
    return ws


class _UploadPayloadTooLargeError(Exception):
    """Raised immediately when decoded HTTP multipart request body exceeds MAX_UPLOAD_TOTAL_REQUEST_BYTES."""


class _CountingStreamReader:
    """Byte-counting wrapper around aiohttp StreamReader enforcing decoded HTTP multipart request body byte limits."""

    def __init__(self, inner: Any, max_bytes: int) -> None:
        self._inner = inner
        self.max_bytes = int(max_bytes)
        self.bytes_read = 0
        self._unread_credit = 0

    def _account(self, data: bytes) -> bytes:
        n = len(data)
        if n <= 0:
            return data
        if self._unread_credit > 0:
            used = min(self._unread_credit, n)
            self._unread_credit -= used
            n -= used
        self.bytes_read += n
        if self.bytes_read > self.max_bytes:
            raise _UploadPayloadTooLargeError(
                f"decoded HTTP multipart request body exceeded {self.max_bytes} bytes"
            )
        return data

    def unread_data(self, data: bytes) -> None:
        if data:
            self._unread_credit += len(data)
        return self._inner.unread_data(data)

    async def read(self, *args: Any, **kwargs: Any) -> bytes:
        return self._account(await self._inner.read(*args, **kwargs))

    async def readany(self, *args: Any, **kwargs: Any) -> bytes:
        return self._account(await self._inner.readany(*args, **kwargs))

    async def readexactly(self, *args: Any, **kwargs: Any) -> bytes:
        return self._account(await self._inner.readexactly(*args, **kwargs))

    async def readline(self, *args: Any, **kwargs: Any) -> bytes:
        return self._account(await self._inner.readline(*args, **kwargs))

    async def readchunk(self, *args: Any, **kwargs: Any) -> tuple[bytes, bool]:
        chunk, end_of_http_chunk = await self._inner.readchunk(*args, **kwargs)
        return self._account(chunk), end_of_http_chunk

    def at_eof(self) -> bool:
        return bool(self._inner.at_eof())

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


async def handle_api_upload(request: web.Request) -> web.Response:
    """Authenticated multipart upload handler backing Playwright `filechooser` with pre-disk validation."""
    hub: LiveBrowserHub = request.app["hub"]
    init_data = request.headers.get("X-TG-Init-Data", "")
    ok, info, err = _authenticate_init_data(init_data)
    if not ok or not info:
        return web.json_response({"ok": False, "error": err or "Forbidden"}, status=403)
    bot_key = str(info["bot"])
    user_id = int(info["user_id"])
    role = str(info.get("role") or "denied")
    if role != "admin":
        return web.json_response({"ok": False, "error": "只读权限（readonly）禁止上传文件"}, status=403)

    # Pre-disk chooser validation (header or query MUST identify a valid, owned, current-gen chooser!)
    query = getattr(request, "query", {}) or {}
    chooser_id = str(request.headers.get("X-Chooser-Id") or query.get("chooser_id") or "").strip()
    if not chooser_id:
        return web.json_response({"ok": False, "error": "缺少 X-Chooser-Id 或 chooser_id 参数"}, status=400)

    await hub._cleanup_pending_filechoosers_async(page_id=-1)
    entry_preview = hub.pending_filechoosers.get(chooser_id)
    if not entry_preview:
        return web.json_response({"ok": False, "error": "文件选择会话已过期或不存在"}, status=404)
    if entry_preview.get("session_gen") != hub.session_gen:
        popped_stale = hub.pending_filechoosers.pop(chooser_id, None)
        if popped_stale and popped_stale.get("owner_bot") is not None and popped_stale.get("owner_uid") is not None:
            await hub.broadcast_json_to_owners(
                {"type": "filechooser_closed", "chooser_id": chooser_id},
                owner_bot=popped_stale.get("owner_bot"),
                owner_uid=popped_stale.get("owner_uid"),
                require_admin=True,
                expected_session_gen=popped_stale.get("session_gen"),
            )
        return web.json_response({"ok": False, "error": "文件选择会话已过期"}, status=404)
    if not hub._can_access_resource(entry_preview, bot_key, user_id, role, require_admin=True):
        return web.json_response({"ok": False, "error": "无权操作该文件选择会话"}, status=403)

    max_req_bytes = min(MAX_UPLOAD_TOTAL_BYTES, MAX_UPLOAD_TOTAL_REQUEST_BYTES)

    # Reject declared oversized requests before reading body
    raw_cl = request.headers.get("Content-Length", "")
    parsed_cl = _parse_strict_int(raw_cl)
    if parsed_cl is not None and parsed_cl > max_req_bytes:
        return web.json_response(
            {
                "ok": False,
                "error": (
                    f"上传请求体总大小超过 {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB 文件"
                    f" + {MAX_UPLOAD_META_BYTES // 1024} KiB multipart 开销限制"
                ),
            },
            status=413,
        )

    try:
        await asyncio.wait_for(hub._upload_sem.acquire(), timeout=0.5)
    except asyncio.TimeoutError:
        return web.json_response({"ok": False, "error": "当前上传并发已满，请稍后重试"}, status=429)

    multiple = bool(entry_preview.get("multiple"))
    upload_subdir: Path | None = None
    saved_paths: list[Path] = []
    saved_names: list[str] = []
    used_names: set[str] = set()
    total_file_bytes = 0
    total_nonfile_bytes = 0
    total_req_bytes = 0
    part_count = 0
    file_count = 0
    committed = False
    counting_stream: _CountingStreamReader | None = None

    try:
        xfer_dir = hub._ensure_transfer_dir()
        upload_subdir = xfer_dir / f"up-{secrets.token_hex(8)}"
        upload_subdir.mkdir(parents=True, exist_ok=True)
        os.chmod(upload_subdir, 0o700)

        # Wrap decoded HTTP request body stream (`request.content` drained to EOF) BEFORE multipart parsing
        # to enforce the full decoded request body byte budget (including headers, boundaries, and epilogue)
        raw_content = getattr(request, "content", None)
        if (
            MultipartReader is not None
            and raw_content is not None
            and callable(getattr(raw_content, "read", None))
            and callable(getattr(raw_content, "readline", None))
        ):
            counting_stream = _CountingStreamReader(raw_content, max_req_bytes)
            reader = MultipartReader(request.headers, counting_stream)
        else:
            reader = await request.multipart()

        while True:
            part = await reader.next()
            if part is None:
                break
            part_count += 1
            if part_count > MAX_UPLOAD_PARTS:
                return web.json_response({"ok": False, "error": f"表单字段数量超过上限 ({MAX_UPLOAD_PARTS})"}, status=400)

            # Fallback framing accounting when using mock readers without raw StreamReader
            if counting_stream is None:
                part_headers = getattr(part, "headers", None)
                framing_bytes = 64
                if part_headers:
                    try:
                        framing_bytes += sum(len(str(k)) + len(str(v)) + 4 for k, v in part_headers.items())
                    except Exception:
                        framing_bytes += len(str(part_headers))
                else:
                    framing_bytes += (
                        len(str(getattr(part, "name", "") or ""))
                        + len(str(getattr(part, "filename", "") or ""))
                        + 40
                    )
                total_req_bytes += framing_bytes
                if total_req_bytes > max_req_bytes:
                    return web.json_response({"ok": False, "error": "上传总请求体积超出上限"}, status=413)

            # Strict file part classification: ONLY parts with a non-empty `filename` are treated as files;
            # parts without a filename (even if named "files") strictly count against non-file field budgets!
            raw_part_fn = getattr(part, "filename", None)
            has_filename = isinstance(raw_part_fn, str) and bool(raw_part_fn.strip())
            if not has_filename:
                field_buf = bytearray()
                while True:
                    chunk = await part.read_chunk(4096)
                    if not chunk:
                        break
                    total_nonfile_bytes += len(chunk)
                    if counting_stream is None:
                        total_req_bytes += len(chunk)
                    if len(field_buf) + len(chunk) > MAX_UPLOAD_NONFILE_FIELD_BYTES:
                        return web.json_response({"ok": False, "error": "非文件表单字段过大"}, status=413)
                    if total_nonfile_bytes > MAX_UPLOAD_NONFILE_TOTAL_BYTES:
                        return web.json_response({"ok": False, "error": "非文件表单字段总大小超出上限"}, status=413)
                    if counting_stream is None and total_req_bytes > max_req_bytes:
                        return web.json_response({"ok": False, "error": "上传总请求体积超出上限"}, status=413)
                    field_buf.extend(chunk)
                if part.name == "chooser_id":
                    body_cid = field_buf.decode("utf-8", errors="replace").strip()
                    if body_cid and body_cid != chooser_id:
                        return web.json_response({"ok": False, "error": "chooser_id 不一致"}, status=400)
                continue

            file_count += 1
            if not multiple and file_count > 1:
                return web.json_response({"ok": False, "error": "单文件选择器不支持上传多个文件"}, status=400)
            if file_count > MAX_UPLOAD_FILES:
                return web.json_response({"ok": False, "error": f"单次最多上传 {MAX_UPLOAD_FILES} 个文件"}, status=400)

            raw_fn = str(raw_part_fn)
            safe_fn = _sanitize_filename(raw_fn, fallback=f"upload-{file_count}.bin")
            # Preserve exact sanitized original filename inside isolated 0700 subdir
            unique_fn = safe_fn
            if unique_fn in used_names:
                stem = Path(safe_fn).stem or "upload"
                sfx = Path(safe_fn).suffix
                n = 2
                while f"{stem}-{n}{sfx}" in used_names:
                    n += 1
                unique_fn = f"{stem}-{n}{sfx}"
            used_names.add(unique_fn)
            dest = upload_subdir / unique_fn

            with open(dest, "wb") as fh:
                while True:
                    chunk = await part.read_chunk(65536)
                    if not chunk:
                        break
                    total_file_bytes += len(chunk)
                    if counting_stream is None:
                        total_req_bytes += len(chunk)
                    if total_file_bytes > MAX_UPLOAD_BYTES or (
                        counting_stream is None and total_req_bytes > max_req_bytes
                    ):
                        return web.json_response(
                            {
                                "ok": False,
                                "error": f"上传文件总大小超过 {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB 限制",
                            },
                            status=413,
                        )
                    fh.write(chunk)
            os.chmod(dest, 0o600)
            saved_paths.append(dest)
            saved_names.append(unique_fn)

        # Drain the underlying aiohttp decoded request body stream to true EOF through the SAME
        # byte-counting wrapper BEFORE calling `set_files()` (accounts for any trailing/epilogue bytes!)
        if counting_stream is not None:
            while not counting_stream.at_eof():
                trailing = await counting_stream.read(65536)
                if not trailing:
                    break

        if not saved_paths:
            return web.json_response({"ok": False, "error": "未选择任何文件"}, status=400)

        # Re-verify live role, chooser TTL, session_gen & ownership atomically before popping & handing off to Playwright
        live_role = _check_live_user_role(bot_key, user_id)
        if live_role != "admin":
            return web.json_response({"ok": False, "error": "用户权限已变更或撤销，禁止提交上传"}, status=403)
        entry = hub.pending_filechoosers.get(chooser_id)
        if not entry or entry.get("session_gen") != hub.session_gen:
            return web.json_response({"ok": False, "error": "文件选择会话已过期或不存在"}, status=404)
        if (time.monotonic() - float(entry.get("created_ts", 0.0))) > TRANSFER_TTL_SECONDS:
            popped_exp = hub.pending_filechoosers.pop(chooser_id, None)
            if popped_exp and popped_exp.get("owner_bot") is not None and popped_exp.get("owner_uid") is not None:
                await hub.broadcast_json_to_owners(
                    {"type": "filechooser_closed", "chooser_id": chooser_id},
                    owner_bot=popped_exp.get("owner_bot"),
                    owner_uid=popped_exp.get("owner_uid"),
                    require_admin=True,
                    expected_session_gen=popped_exp.get("session_gen"),
                )
            return web.json_response({"ok": False, "error": "文件选择会话在上传期间已超时过期"}, status=404)
        if not hub._can_access_resource(entry, bot_key, user_id, live_role, require_admin=True):
            return web.json_response({"ok": False, "error": "无权操作该文件选择会话"}, status=403)
        hub.pending_filechoosers.pop(chooser_id, None)

        chooser = entry["chooser"]
        entry_sgen = entry.get("session_gen")
        closed_payload = {"type": "filechooser_closed", "chooser_id": chooser_id}
        closed_notified = False
        try:
            target_arg: Any = [str(p) for p in saved_paths] if multiple else str(saved_paths[0])
            await chooser.set_files(target_arg)
            committed = True
        except asyncio.CancelledError:
            # Cancellation-safe notification bound strictly to `entry["session_gen"]`
            if entry.get("owner_bot") is not None and entry.get("owner_uid") is not None:
                try:
                    asyncio.get_running_loop().create_task(
                        hub.broadcast_json_to_owners(
                            closed_payload,
                            owner_bot=entry.get("owner_bot"),
                            owner_uid=entry.get("owner_uid"),
                            require_admin=True,
                            expected_session_gen=entry_sgen,
                        )
                    )
                    closed_notified = True
                except RuntimeError:
                    pass
            raise
        except Exception as exc:
            await hub.broadcast_json_to_owners(
                closed_payload,
                owner_bot=entry.get("owner_bot"),
                owner_uid=entry.get("owner_uid"),
                require_admin=True,
                expected_session_gen=entry_sgen,
            )
            closed_notified = True
            return web.json_response({"ok": False, "error": f"写入网页文件选择器失败: {exc}"}, status=500)
        finally:
            if not closed_notified and entry.get("owner_bot") is not None and entry.get("owner_uid") is not None:
                try:
                    asyncio.get_running_loop().create_task(
                        hub.broadcast_json_to_owners(
                            closed_payload,
                            owner_bot=entry.get("owner_bot"),
                            owner_uid=entry.get("owner_uid"),
                            require_admin=True,
                            expected_session_gen=entry_sgen,
                        )
                    )
                except RuntimeError:
                    pass

        hub.mark_active()
        if hub.engine_mode == "async_hosted":
            await hub._capture_once(force_broadcast=True)
            await hub.broadcast_state()
        return web.json_response({"ok": True, "files": saved_names, "total_bytes": total_file_bytes})
    except _UploadPayloadTooLargeError:
        return web.json_response(
            {
                "ok": False,
                "error": (
                    f"上传请求体总大小超过 {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB 文件"
                    f" + {MAX_UPLOAD_META_BYTES // 1024} KiB multipart 开销限制"
                ),
            },
            status=413,
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return web.json_response({"ok": False, "error": f"读取上传数据失败: {exc}"}, status=400)
    finally:
        hub._upload_sem.release()
        if not committed and upload_subdir is not None:
            shutil.rmtree(upload_subdir, ignore_errors=True)


async def handle_api_download(request: web.Request) -> web.StreamResponse:
    """Authenticated download endpoint enforcing per-bot/owner/role/session_gen isolation & safe headers."""
    hub: LiveBrowserHub = request.app["hub"]
    init_data = request.headers.get("X-TG-Init-Data", "")
    ok, info, err = _authenticate_init_data(init_data)
    if not ok or not info:
        return web.json_response({"ok": False, "error": err or "Forbidden"}, status=403)
    bot_key = str(info["bot"])
    user_id = int(info["user_id"])
    role = str(info.get("role") or "denied")
    if role != "admin":
        return web.json_response({"ok": False, "error": "只读权限（readonly）禁止下载他人会话文件"}, status=403)

    did = str(request.match_info.get("download_id") or "").strip()
    info_rec = hub.downloads.get(did)
    if not info_rec:
        return web.json_response({"ok": False, "error": "下载文件已过期或不存在"}, status=404)
    if info_rec.get("session_gen") != hub.session_gen:
        return web.json_response({"ok": False, "error": "下载文件所属会话已过期"}, status=404)
    if not hub._can_access_resource(info_rec, bot_key, user_id, role, require_admin=True):
        return web.json_response({"ok": False, "error": "无权访问该下载文件"}, status=403)

    path = Path(info_rec["path"])
    if not path.is_file():
        hub.downloads.pop(did, None)
        return web.json_response({"ok": False, "error": "下载文件已被清理"}, status=404)

    safe_name = str(info_rec.get("filename") or path.name)
    return web.FileResponse(
        path,
        headers={
            "Content-Type": "application/octet-stream",
            "Content-Disposition": _format_content_disposition(safe_name),
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store, max-age=0",
        },
    )


# ---------------- Localhost Internal IPC Endpoints ----------------


def _resolve_internal_tg_reader(
    hub: LiveBrowserHub, query: Any
) -> tuple[bool, bool]:
    """Inspect internal GET query params for Telegram caller context & delivery scope.

    Returns `(is_tg_caller, can_read_active_session)`.
    Localhost CLI queries without `source=tg_*`, `chat_scope`, or `user_id`/`chat_id` return `(False, True)`.
    Group/shared chat deliveries (`chat_scope=group` or non-positive `chat_id`) ALWAYS return `(True, False)`
    while a session is active, even if the triggering `user_id` is the session owner.
    """
    raw_source = str(query.get("source") or "").strip().lower()
    raw_scope = str(query.get("chat_scope") or "").strip().lower()
    raw_bot = query.get("bot") or query.get("bot_key")
    raw_uid = query.get("user_id")
    raw_cid = query.get("chat_id")
    is_tg = (
        raw_source in ("tg_cmd", "tg_card", "tg")
        or bool(raw_scope)
        or raw_uid is not None
        or raw_cid is not None
    )
    if not is_tg:
        return False, True
    if hub.engine_mode == "idle":
        return True, True
    # Group / non-private delivery scope MUST ALWAYS be redacted regardless of triggering user!
    if raw_scope in ("group", "supergroup", "channel"):
        return True, False
    if raw_cid is not None:
        cid_val = _parse_positive_int(raw_cid)
        if cid_val is None:
            return True, False
    else:
        cid_val = None
    # Fail-closed: Telegram status queries require explicit resolvable bot + positive user_id
    if raw_bot is None or not str(raw_bot).strip():
        return True, False
    target_bot = hub.resolve_bot_key(str(raw_bot))
    uid_val = _parse_positive_int(raw_uid if raw_uid is not None else raw_cid)
    if not target_bot or not uid_val:
        return True, False
    if cid_val is not None and cid_val != uid_val:
        return True, False
    live_role = _check_live_user_role(target_bot, uid_val)
    if live_role not in ("admin", "readonly"):
        return True, False
    return True, hub._viewer_can_read_session(target_bot, uid_val, live_role)


def _is_group_internal_scope(mapping: Any) -> bool:
    """Return True when an internal query/body indicates a Telegram group/non-private chat delivery scope."""
    if not mapping or not hasattr(mapping, "get"):
        return False
    raw_scope = str(mapping.get("chat_scope") or "").strip().lower()
    if raw_scope in ("group", "supergroup", "channel"):
        return True
    raw_cid = mapping.get("chat_id")
    if raw_cid is not None and _parse_positive_int(raw_cid) is None:
        return True
    return False


async def internal_status(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    query = getattr(request, "query", {}) or {}
    is_tg, can_read = _resolve_internal_tg_reader(hub, query)
    if is_tg and not can_read:
        return web.json_response({"ok": True, **hub._redacted_state_dict()})
    state = hub.state_dict()
    if _is_group_internal_scope(query):
        state = {**state, "profiles": []}
    return web.json_response({"ok": True, **state})


def _parse_positive_int(raw: Any) -> int | None:
    val = _parse_strict_int(raw)
    return val if (val is not None and val > 0) else None


def _verify_internal_caller_control(
    hub: LiveBrowserHub,
    body: dict[str, Any],
    *,
    require_running: bool = True,
) -> tuple[bool, str, tuple[str, int | None] | None, dict[str, Any]]:
    """Verify bot/user/card ownership on internal control endpoints when Telegram user/card context is supplied.

    Returns `(ok, err, owner_tuple, auth_ctx)` where `auth_ctx` can be re-verified inside execution locks.
    """
    raw_bot = body.get("bot")
    raw_uid = body.get("user_id")
    raw_cid = body.get("chat_id")
    raw_mid = body.get("message_id")
    raw_source = str(body.get("source") or "").strip().lower()
    from_card = (
        raw_source == "tg_card"
        or _parse_bool_flag(body.get("from_card"))
        or (raw_mid is not None)
    )

    uid_val = _parse_positive_int(raw_uid if raw_uid is not None else raw_cid)
    cid_val = _parse_positive_int(raw_cid if raw_cid is not None else raw_uid)
    mid_val = _parse_positive_int(raw_mid)

    has_tg_identity = (
        from_card
        or raw_source in ("tg_cmd", "tg_card", "tg")
        or (raw_uid is not None)
        or (raw_cid is not None)
    )
    if not has_tg_identity:
        if raw_bot is not None and str(raw_bot).strip():
            bkey = hub.resolve_bot_key(str(raw_bot))
            if bkey is None:
                return False, "无法识别目标 Bot 身份", None, {}
            return True, "ok", (bkey, None), {"is_tg": False}
        return True, "ok", None, {"is_tg": False}

    # Strictly require explicit `bot` for Telegram callers — NEVER fall back to single-bot auto-resolution!
    if raw_bot is None or not str(raw_bot).strip():
        return False, "缺少必填的 bot 身份参数", None, {}
    target_bot = hub.resolve_bot_key(str(raw_bot))
    if not target_bot or not cid_val:
        return False, "缺少有效的 Bot 或私聊用户身份", None, {}

    expected_gen = hub.session_gen
    if from_card:
        if mid_val is None or mid_val <= 0:
            return False, "Telegram 卡片回调缺少有效的正整数 message_id", None, {}
        ok_v, msg_v, _ = hub.tg.verify_card_control(
            target_bot,
            cid_val,
            message_id=mid_val,
            require_card=True,
            require_running=require_running,
            expected_session_gen=expected_gen,
        )
        if not ok_v:
            return False, msg_v, None, {}
        return (
            True,
            "ok",
            (target_bot, cid_val),
            {
                "is_tg": True,
                "from_card": True,
                "source": "tg_card",
                "bot_key": target_bot,
                "chat_id": cid_val,
                "message_id": mid_val,
                "expected_gen": expected_gen,
            },
        )

    # Non-card Telegram command/callback with explicit bot + user_id: verify live admin & session owner
    live_role = _check_live_user_role(target_bot, cid_val)
    if live_role != "admin":
        return False, "当前用户未授权或不是管理员", None, {}
    if hub.engine_mode != "idle" and not hub._viewer_can_mutate(target_bot, cid_val, live_role):
        return False, "无权操作其他 Bot/用户或本机 CLI 持有的浏览器会话", None, {}
    return (
        True,
        "ok",
        (target_bot, uid_val),
        {
            "is_tg": True,
            "from_card": False,
            "source": raw_source or "tg_cmd",
            "bot_key": target_bot,
            "chat_id": cid_val,
            "message_id": None,
            "expected_gen": expected_gen,
        },
    )


async def internal_takeover(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        return web.json_response({"ok": False, "error": "Request body must be a JSON object"}, status=400)
    ok_ctrl, err_ctrl, owner, auth_ctx = _verify_internal_caller_control(hub, body, require_running=True)
    if not ok_ctrl:
        return web.json_response({"ok": False, "error": err_ctrl}, status=403)
    active = _parse_bool_flag(body.get("active", True))
    reason = str(body.get("reason") or "")
    actor_arg = (auth_ctx["bot_key"], auth_ctx["chat_id"]) if auth_ctx.get("is_tg") else None
    exp_gen = auth_ctx.get("expected_gen") if auth_ctx.get("is_tg") else None
    ok_tk, err_tk, _, _ = await hub.set_takeover(
        active,
        reason=reason,
        owner=(owner if active else None),
        expected_session_gen=exp_gen,
        actor=actor_arg,
        card_message_id=auth_ctx.get("message_id"),
        require_card=bool(auth_ctx.get("from_card")),
    )
    if not ok_tk:
        return web.json_response({"ok": False, "error": err_tk}, status=403)
    return web.json_response({"ok": True, **hub.state_dict()})


async def internal_start(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        return web.json_response({"ok": False, "error": "Request body must be a JSON object"}, status=400)
    ok_ctrl, err_ctrl, _, auth_ctx = _verify_internal_caller_control(hub, body, require_running=False)
    if not ok_ctrl:
        return web.json_response({"ok": False, "error": err_ctrl}, status=403)
    overrides: dict[str, Any] = {}
    for key in (
        "os",
        "locale",
        "window",
        "mobile",
        "webgl_config",
        "block_webrtc",
        "geoip",
        "proxy",
        "proxy_bao_ref",
        "ephemeral",
        "persistent",
        "headless",
        "user_data_dir",
        "persistent_context",
    ):
        if key in body and body[key] is not None:
            overrides[key] = body[key]
    pref_uid = _parse_positive_int(body.get("user_id"))
    actor_arg = (auth_ctx["bot_key"], auth_ctx["chat_id"]) if auth_ctx.get("is_tg") else None
    source_arg = str(auth_ctx.get("source") or "tg_cmd") if auth_ctx.get("is_tg") else "cli"
    exp_gen = auth_ctx.get("expected_gen") if auth_ctx.get("is_tg") else None
    is_group_scope = _is_group_internal_scope(body)
    try:
        st = await hub.start_hosted(
            initial_url=body.get("url"),
            bot_hint=body.get("bot"),
            notify_tg=bool(body.get("notify", True)),
            profile=body.get("profile"),
            overrides=overrides or None,
            restart=bool(body.get("restart", False)),
            preferred_user_id=pref_uid,
            actor=actor_arg,
            source=source_arg,
            expected_session_gen=exp_gen,
        )
        return web.json_response({"ok": True, **st})
    except PermissionError as exc:
        err_msg = "当前操作未获授权，请前往私聊查看与操作" if is_group_scope else str(exc)
        return web.json_response({"ok": False, "error": err_msg}, status=403)
    except ValueError as exc:
        err_msg = "请求参数无效，请前往私聊检查" if is_group_scope else str(exc)
        return web.json_response({"ok": False, "error": err_msg}, status=400)
    except (KeyError, FileNotFoundError) as exc:
        err_msg = "请求的浏览器配置不可用，请前往私聊检查" if is_group_scope else str(exc)
        return web.json_response({"ok": False, "error": err_msg}, status=404)
    except RuntimeError as exc:
        err_msg = "当前浏览器会话冲突或正忙，请前往私聊查看与操作" if is_group_scope else str(exc)
        return web.json_response({"ok": False, "error": err_msg}, status=409)
    except Exception as exc:
        err_msg = "浏览器服务暂不可用，请前往私聊重试" if is_group_scope else str(exc)
        return web.json_response({"ok": False, "error": err_msg}, status=500)


async def internal_profiles_list(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    query = getattr(request, "query", {}) or {}
    is_tg, can_read = _resolve_internal_tg_reader(hub, query)
    if (is_tg and not can_read) or _is_group_internal_scope(query):
        return web.json_response(
            {
                "ok": True,
                "active_profile": None,
                "profiles": [],
            }
        )
    visible_active = hub.active_profile
    try:
        profs = list_profiles(active_profile=visible_active)
    except RuntimeError as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=500)
    return web.json_response(
        {
            "ok": True,
            "active_profile": visible_active or None,
            "profiles": profs,
        }
    )


async def internal_profiles_create(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    body = await request.json()
    name = body.get("name", "")
    overwrite = bool(body.get("overwrite", False))
    cfg = {k: v for k, v in body.items() if k not in ("name", "overwrite")}
    try:
        prof = create_profile(name, cfg, overwrite=overwrite)
        return web.json_response({"ok": True, "profile": prof})
    except ValueError as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=400)
    except Exception as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=500)


async def internal_profiles_delete(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    name = request.match_info.get("name", "")
    try:
        res = delete_profile(name, active_profile=hub.active_profile)
        return web.json_response(res)
    except KeyError as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=404)
    except ValueError as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=400)
    except RuntimeError as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=409)
    except Exception as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=500)


async def internal_profiles_switch(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        return web.json_response({"ok": False, "error": "Request body must be a JSON object"}, status=400)
    target_profile = str(body.get("profile") or "").strip()
    if not target_profile:
        return web.json_response({"ok": False, "error": "Missing required 'profile' field"}, status=400)
    ok_ctrl, err_ctrl, _, auth_ctx = _verify_internal_caller_control(hub, body, require_running=False)
    if not ok_ctrl:
        return web.json_response({"ok": False, "error": err_ctrl}, status=403)
    pref_uid = _parse_positive_int(body.get("user_id"))
    actor_arg = (auth_ctx["bot_key"], auth_ctx["chat_id"]) if auth_ctx.get("is_tg") else None
    source_arg = str(auth_ctx.get("source") or "tg_cmd") if auth_ctx.get("is_tg") else "cli"
    exp_gen = auth_ctx.get("expected_gen") if auth_ctx.get("is_tg") else None
    is_group_scope = _is_group_internal_scope(body)
    try:
        st = await hub.start_hosted(
            initial_url=body.get("url") or None,
            bot_hint=body.get("bot"),
            notify_tg=bool(body.get("notify", True)),
            profile=target_profile,
            restart=bool(body.get("restart", True)),
            preferred_user_id=pref_uid,
            actor=actor_arg,
            source=source_arg,
            expected_session_gen=exp_gen,
        )
        return web.json_response({"ok": True, **st})
    except PermissionError as exc:
        err_msg = "当前操作未获授权，请前往私聊查看与操作" if is_group_scope else str(exc)
        return web.json_response({"ok": False, "error": err_msg}, status=403)
    except ValueError as exc:
        err_msg = "请求参数无效，请前往私聊检查" if is_group_scope else str(exc)
        return web.json_response({"ok": False, "error": err_msg}, status=400)
    except (KeyError, FileNotFoundError) as exc:
        err_msg = "请求的浏览器配置不可用，请前往私聊检查" if is_group_scope else str(exc)
        return web.json_response({"ok": False, "error": err_msg}, status=404)
    except RuntimeError as exc:
        err_msg = "当前浏览器会话冲突或正忙，请前往私聊查看与操作" if is_group_scope else str(exc)
        return web.json_response({"ok": False, "error": err_msg}, status=409)
    except Exception as exc:
        err_msg = "浏览器服务暂不可用，请前往私聊重试" if is_group_scope else str(exc)
        return web.json_response({"ok": False, "error": err_msg}, status=500)


def _parse_bool_flag(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    return str(raw or "").strip().lower() in ("1", "true", "yes")


async def internal_stop(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)

    body: dict[str, Any] = {}
    if hasattr(request, "read"):
        try:
            raw = await request.read()
        except Exception:
            raw = b""
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except Exception:
                return web.json_response({"ok": False, "error": "Invalid JSON body"}, status=400)
            if not isinstance(parsed, dict):
                return web.json_response({"ok": False, "error": "Request body must be a JSON object"}, status=400)
            body = parsed
    elif hasattr(request, "json"):
        try:
            parsed = await request.json()
            if isinstance(parsed, dict):
                body = parsed
        except Exception:
            body = {}

    query = getattr(request, "query", {}) or {}
    force = _parse_bool_flag(body.get("force")) or _parse_bool_flag(query.get("force"))

    ok_ctrl, err_ctrl, _, auth_ctx = _verify_internal_caller_control(hub, body, require_running=False)
    if not ok_ctrl:
        return web.json_response({"ok": False, "error": err_ctrl}, status=403)

    if hub.engine_mode == "sync_external":
        return web.json_response(
            {"ok": False, "error": "Cannot stop external sync browser session"},
            status=409,
        )
    if hub.ai_busy_count > 0 and not force:
        return web.json_response(
            {"ok": False, "error": "Browser is busy with an AI action; pass force=true to override"},
            status=409,
        )

    if auth_ctx.get("is_tg"):
        stop_res = await hub.stop_hosted(
            notify_finished=True,
            actor=(auth_ctx["bot_key"], auth_ctx["chat_id"]),
            source=str(auth_ctx.get("source") or "tg_cmd"),
            expected_session_gen=auth_ctx.get("expected_gen"),
            card_message_id=auth_ctx.get("message_id"),
            require_card=bool(auth_ctx.get("from_card")),
            force=force,
        )
    else:
        stop_res = await hub.stop_hosted(notify_finished=True)
    if isinstance(stop_res, tuple) and len(stop_res) == 2:
        ok_stop, err_stop = stop_res
        if not ok_stop:
            status_code = 409 if ("外部脚本" in err_stop or "AI 正在执行" in err_stop) else 403
            return web.json_response({"ok": False, "error": err_stop}, status=status_code)
    return web.json_response({"ok": True, **hub.state_dict()})


async def internal_action(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    body = await request.json()
    try:
        res = await hub.execute_ai_action(body)
        return web.json_response(res)
    except ValueError as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=400)
    except RuntimeError as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=409)
    except Exception as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=500)


async def internal_config(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    body = await request.json()
    if "public_url" in body:
        hub.config["public_url"] = str(body["public_url"]).strip().rstrip("/")
        save_local_config(hub.config)
        await hub.broadcast_state()
        asyncio.create_task(hub.tg.tick_updates(force=True))
    if "direct_app_url" in body:
        hub.config["direct_app_url"] = str(body["direct_app_url"]).strip().rstrip("/")
        save_local_config(hub.config)
        await hub.broadcast_state()
    if "takeover" in body:
        await hub.set_takeover(bool(body["takeover"]), str(body.get("reason", "")))
    if body.get("refresh_card"):
        raw_cid = body.get("chat_id")
        raw_bot = body.get("bot")
        raw_mid = body.get("message_id")
        is_tg_card = (
            raw_cid is not None
            or str(body.get("source") or "").strip().lower() == "tg_card"
            or _parse_bool_flag(body.get("from_card"))
            or raw_mid is not None
        )
        if is_tg_card:
            target_cid = _parse_positive_int(raw_cid)
            if not target_cid:
                return web.json_response({"ok": False, "error": "Invalid chat_id"}, status=400)
            if raw_bot is None or not str(raw_bot).strip():
                return web.json_response({"ok": False, "error": "Telegram 卡片刷新缺少必填的 bot 身份参数"}, status=403)
            target_bot = hub.resolve_bot_key(str(raw_bot))
            mid_val = _parse_positive_int(raw_mid)
            if mid_val is None or mid_val <= 0:
                return web.json_response({"ok": False, "error": "Telegram 卡片刷新缺少有效的正整数 message_id"}, status=403)
            pre_gen = hub.session_gen
            # Verify card, ownership, live admin role & positive message_id BEFORE triggering any HD capture!
            ok_pre, msg_pre, _ = hub.tg.verify_card_control(
                target_bot,
                target_cid,
                message_id=mid_val,
                require_card=True,
                require_running=True,
                expected_session_gen=pre_gen,
            )
            if not ok_pre or not target_bot:
                return web.json_response({"ok": False, "error": msg_pre}, status=403)
            if hub.engine_mode == "async_hosted":
                await hub._capture_once(force_broadcast=True, hd=True)
            ok_rf, msg_rf, status_rf = await hub.tg._refresh_single_card_with_status(
                target_bot, target_cid, message_id=mid_val, expected_session_gen=pre_gen
            )
            if not ok_rf:
                return web.json_response({"ok": False, "error": msg_rf}, status=status_rf)
        else:
            bot_filter = hub.resolve_bot_key(str(raw_bot)) if raw_bot else None
            if raw_bot and bot_filter is None:
                return web.json_response({"ok": False, "error": "无法识别目标 Bot 身份"}, status=403)
            if hub.engine_mode == "async_hosted":
                await hub._capture_once(force_broadcast=True, hd=True)
            await hub.tg.tick_updates(force=True, bot_filter=bot_filter)
    if body.get("ensure_card"):
        bot_key = hub.resolve_bot_key(body.get("bot"))
        pref_uid = _parse_positive_int(body.get("user_id"))
        if bot_key is not None:
            await hub.tg.ensure_card(
                bot_key, force_new=bool(body.get("force_new", False)), preferred_user_id=pref_uid
            )
    return web.json_response(
        {
            "ok": True,
            "config": hub.config,
            "cards": [f"{bk}:{cid}" for (bk, cid) in hub.tg.cards.keys()],
        }
    )


async def internal_yield_lock(request: web.Request) -> web.Response:
    """Allow legacy `with open_google_browser():` to reclaim the profile lock cleanly when idle."""
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    if hub.engine_mode == "async_hosted":
        if hub.takeover or hub.ai_busy_count > 0:
            return web.json_response(
                {"ok": False, "busy": True, "reason": "Hosted browser busy or in human takeover"}
            )
        await hub.stop_hosted(notify_finished=False)
    return web.json_response({"ok": True, "yielded": True})


async def internal_sync_start(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    body = await request.json()
    prev_sync_retire: tuple[int, bytes | None] | None = None

    async with hub._engine_lock:
        if hub.engine_mode == "async_hosted":
            await hub._stop_hosted_locked(notify_finished=False)
        elif hub.engine_mode == "sync_external":
            prev_sync_retire = hub._invalidate_sync_session_sync()
        hub.session_gen += 1
        hub.takeover_gen += 1
        hub._clear_session_caches()
        lease_id = secrets.token_hex(12)
        hub.engine_mode = "sync_external"
        hub._sync_lease_id = lease_id
        bot_key = hub.resolve_bot_key(body.get("bot"))
        pref_uid = _parse_positive_int(body.get("user_id"))
        hub.session_owner = (bot_key, pref_uid) if bot_key is not None else None

        # Never infer producer `pinned=True` from host discovery alone!
        # Only verify pinned when the Sync launch explicitly passes a matching canonical pinned `profile_dir`.
        raw_pdir = str(body.get("profile_dir") or "").strip()
        pinned_claim = body.get("pinned_launch") is True
        pinned_verified = False
        host_pinned = None
        if raw_pdir and pinned_claim:
            try:
                host_pinned = discover_pinned_host_profile()
            except Exception:
                host_pinned = None
            if host_pinned is not None:
                try:
                    p_res = Path(raw_pdir).resolve()
                    h_res = Path(host_pinned["profile_dir"]).resolve()
                    if p_res == h_res and p_res.is_dir():
                        pinned_verified = True
                except OSError:
                    pinned_verified = False

        if pinned_verified and host_pinned is not None:
            hub.active_profile = host_pinned["name"]
            hub.active_profile_dir = Path(host_pinned["profile_dir"])
            hub.active_pinned = True
            hub.active_pinned_verified = True
            hub.active_egress = "direct"
            hub.active_os = str(host_pinned["fingerprint"].get("os", "windows"))
            hub.active_fingerprint = {"os": hub.active_os, "persistent": True}
        else:
            hub.active_profile = str(body.get("profile") or "").strip()
            hub.active_profile_dir = None
            hub.active_pinned = False
            hub.active_pinned_verified = False
            hub.active_egress = "direct"
            hub.active_os = str(body.get("os") or "")
            hub.active_fingerprint = {}

        hub.sync_cmd_queue.clear()
        hub.ai_status = str(body.get("ai_status") or "外部脚本运行中")
        now = time.monotonic()
        hub.last_activity_ts = now
        hub._sync_last_push_ts = now

        # Capture atomic locked snapshot for response (NEVER read mutable hub fields after awaits!)
        resp_payload = {
            "ok": True,
            "bot_key": bot_key,
            "session_gen": hub.session_gen,
            "takeover_gen": hub.takeover_gen,
            "sync_lease_id": lease_id,
            "pinned": hub.active_pinned,
            "pinned_verified": hub.active_pinned_verified,
        }

    if prev_sync_retire is not None:
        old_gen, final_jpeg = prev_sync_retire
        await hub.tg.retire_cards(session_gen=old_gen, mark_finished=True, final_jpeg=final_jpeg)
    await hub.broadcast_state()
    return web.json_response(resp_payload)


def _check_sync_lease_active(
    hub: LiveBrowserHub,
    req_lease: str,
    *,
    expected_gen: int | None = None,
) -> tuple[bool, int, str]:
    """Verify active sync_external lease + built-in TTL expiration + optional expected session_gen synchronously."""
    if hub.engine_mode == "async_hosted" or hub.ctx is not None:
        return False, 409, "Active hosted browser session cannot be mutated by sync producer"
    if hub.engine_mode != "sync_external" or not hub._sync_lease_id:
        return False, 410, "Sync session is idle or lease expired; call /internal/sync/start first"
    # Built-in TTL check: immediately revoke an expired lease even if maintenance tick hasn't run yet!
    if (
        hub._sync_last_push_ts is not None
        and (time.monotonic() - hub._sync_last_push_ts) > SYNC_LEASE_TIMEOUT_SECONDS
    ):
        log.warning(
            "Sync external session lease expired on validator check (>%.0fs without push); revoking immediately",
            SYNC_LEASE_TIMEOUT_SECONDS,
        )
        old_gen, final_jpeg = hub._invalidate_sync_session_sync()
        try:
            loop = asyncio.get_running_loop()
            hub._track_bg_task(
                loop.create_task(
                    hub.tg.retire_cards(session_gen=old_gen, mark_finished=True, final_jpeg=final_jpeg)
                )
            )
            hub._track_bg_task(loop.create_task(hub.broadcast_state()))
        except RuntimeError:
            pass
        return False, 410, "Sync session lease expired; call /internal/sync/start first"
    if not req_lease or not hmac.compare_digest(req_lease, hub._sync_lease_id):
        return False, 409, "Invalid or stale sync_lease_id"
    if expected_gen is not None and hub.session_gen != expected_gen:
        return False, 409, "Stale sync session_gen"
    return True, 200, "ok"


async def internal_sync_push(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    q = getattr(request, "query", {}) or {}
    req_lease = str(q.get("lease_id") or request.headers.get("X-Sync-Lease-Id") or "").strip()
    req_sgen = _parse_strict_int(q.get("session_gen")) if q.get("session_gen") is not None else None

    # 1. Pre-read validation BEFORE reading body
    ok_pre, st_pre, err_pre = _check_sync_lease_active(hub, req_lease, expected_gen=req_sgen)
    if not ok_pre:
        return web.json_response({"ok": False, "error": err_pre}, status=st_pre)
    start_gen = hub.session_gen

    jpeg = await request.read()

    # 2. Post-read validation AFTER reading body — BEFORE writing ANY frame/metadata/cache!
    ok_post, st_post, err_post = _check_sync_lease_active(hub, req_lease, expected_gen=start_gen)
    if not ok_post:
        return web.json_response({"ok": False, "error": err_post}, status=st_post)

    now = time.monotonic()
    hub.last_activity_ts = now
    hub._sync_last_push_ts = now
    if "url" in q:
        hub.url = q["url"]
    if "title" in q:
        hub.title = q["title"]
    if q.get("vw", "").isdigit():
        hub.vw = int(q["vw"])
    if q.get("vh", "").isdigit():
        hub.vh = int(q["vh"])
    if "ai_status" in q and q["ai_status"]:
        hub.ai_status = q["ai_status"]
    if "tabs" in q:
        try:
            hub.tabs = json.loads(q["tabs"])
        except Exception:
            pass
    if q.get("cx") and q.get("cy"):
        try:
            hub.cursor = {
                "x": float(q["cx"]),
                "y": float(q["cy"]),
                "actor": q.get("actor", "ai"),
                "ts": time.time(),
            }
        except Exception:
            pass

    if jpeg:
        await hub.broadcast_frame(jpeg)
    await hub.broadcast_state()

    # 3. Final validation AFTER broadcast awaits — BEFORE dequeuing sync commands or auto-creating cards!
    ok_fin, st_fin, err_fin = _check_sync_lease_active(hub, req_lease, expected_gen=start_gen)
    if not ok_fin:
        return web.json_response({"ok": False, "error": err_fin}, status=st_fin)

    # Auto-create card ONLY bound to authoritative verified (owner_bot, owner_uid)
    bot_hint = q.get("bot")
    if bot_hint and jpeg and hub._has_verified_session_owner():
        assert hub.session_owner is not None
        o_bot, o_uid = hub.session_owner
        resolved_hint = hub.resolve_bot_key(bot_hint)
        if resolved_hint == o_bot and not hub.tg.has_card_for_bot(o_bot):
            asyncio.create_task(hub.tg.ensure_card(o_bot, preferred_user_id=o_uid))

    cmds = hub.pop_sync_cmds()
    return web.json_response(
        {
            "ok": True,
            "session_gen": hub.session_gen,
            "sync_lease_id": hub._sync_lease_id,
            "takeover": hub.takeover,
            "takeover_gen": hub.takeover_gen,
            "takeover_reason": hub.takeover_reason,
            "commands": cmds,
        }
    )


async def internal_sync_clipboard(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    q = getattr(request, "query", {}) or {}
    hdr_lease = str(request.headers.get("X-Sync-Lease-Id") or q.get("lease_id") or "").strip()
    hdr_sgen = _parse_strict_int(q.get("session_gen") or request.headers.get("X-Sync-Session-Gen"))

    # 1. Mandatory pre-read lease validation BEFORE reading request body!
    if not hdr_lease:
        return web.json_response({"ok": False, "error": "Missing required X-Sync-Lease-Id header or lease_id query"}, status=409)
    ok_pre, st_pre, err_pre = _check_sync_lease_active(hub, hdr_lease, expected_gen=hdr_sgen)
    if not ok_pre:
        return web.json_response({"ok": False, "error": err_pre}, status=st_pre)
    start_gen = hub.session_gen

    body = await request.json()
    body_lease = str(body.get("lease_id") or "").strip()
    if body_lease and not hmac.compare_digest(body_lease, hdr_lease):
        return web.json_response({"ok": False, "error": "Mismatched sync_lease_id"}, status=409)
    raw_sgen_body = body.get("session_gen")
    req_sgen = _parse_strict_int(raw_sgen_body)
    if raw_sgen_body is not None and req_sgen is None:
        return web.json_response({"ok": False, "error": "Invalid sync session_gen"}, status=400)

    # 2. Post-read validation BEFORE writing clipboard or sending to viewer!
    if req_sgen is not None and req_sgen != start_gen:
        return web.json_response({"ok": False, "error": "Stale sync session_gen"}, status=409)
    ok_post, st_post, err_post = _check_sync_lease_active(hub, hdr_lease, expected_gen=start_gen)
    if not ok_post:
        return web.json_response({"ok": False, "error": err_post}, status=st_post)

    raw_tgen_body = body.get("takeover_gen")
    req_tgen_body = _parse_strict_int(raw_tgen_body)
    if raw_tgen_body is not None and req_tgen_body is None:
        return web.json_response({"ok": False, "error": "Invalid sync takeover_gen"}, status=400)

    req_id_str = str(body.get("req_id") or "").strip()
    if req_id_str and (req_sgen is None or req_tgen_body is None):
        return web.json_response(
            {"ok": False, "error": "Targeted extract reply requires valid integer session_gen and takeover_gen"},
            status=400,
        )

    def _validate_targeted_extract_reply(req_id_val: str) -> Any | None:
        """Strictly validate a pending Sync extract `req_id` against BOTH mandatory body generations, owner, live RBAC, and live WS.

        Returns the originating `target_ws` ONLY when all checks pass AND `target_ws` is still live & open.
        Returns `None` (drop without writing `latest_clip` or broadcasting) on any mismatch or if `target_ws` closed.
        """
        if req_sgen is None or req_tgen_body is None:
            return None
        pending = hub._pending_sync_extracts.pop(req_id_val, None)
        if not pending:
            return None
        if pending.get("session_gen") != start_gen or hub.session_gen != start_gen or req_sgen != start_gen:
            return None
        p_tgen = pending.get("takeover_gen")
        if p_tgen is None or p_tgen != hub.takeover_gen or req_tgen_body != p_tgen:
            return None
        if pending.get("owner") != hub.session_owner:
            return None
        p_bot = str(pending.get("bot_key") or "")
        p_uid = int(pending.get("user_id") or 0)
        live_role = _check_live_user_role(p_bot, p_uid)
        if live_role not in ("admin", "readonly") or not hub._viewer_can_read_session(p_bot, p_uid, live_role):
            return None
        target_ws = pending.get("ws")
        if target_ws is None or target_ws not in hub.viewers or getattr(target_ws, "closed", False):
            # Originating viewer disconnected/closed: drop strictly, NEVER fall back to broadcasting!
            return None
        return target_ws

    if body.get("preview"):
        preview_payload: dict[str, Any] = {
            "type": "selection_preview",
            "text": str(body.get("text") or "")[:5000],
        }
        if "extract_gen" in body:
            eg = _parse_strict_int(body.get("extract_gen"))
            if eg is not None:
                preview_payload["extract_gen"] = eg
        if req_id_str:
            target_ws = _validate_targeted_extract_reply(req_id_str)
            if target_ws is not None:
                await _ws_send_json(target_ws, preview_payload)
        else:
            owner_bot, owner_uid = hub._effective_resource_owner()
            if owner_bot is not None and owner_uid is not None:
                await hub.broadcast_json_to_owners(
                    preview_payload,
                    owner_bot=owner_bot,
                    owner_uid=owner_uid,
                    require_admin=False,
                    expected_session_gen=start_gen,
                )
        return web.json_response({"ok": True})

    text = str(body.get("text") or "")
    if text:
        clip_obj = {
            "text": text[:25000],
            "blockText": str(body.get("blockText") or "")[:20000],
            "href": str(body.get("href") or "")[:4000],
            "source": str(body.get("source") or "网页复制"),
            "url": hub.url,
            "ts": time.time(),
        }
        clip_msg = {"type": "clipboard", **clip_obj}
        if req_id_str:
            # Validate req_id + (session_gen, takeover_gen, owner, live RBAC, live target_ws) BEFORE writing latest_clip!
            target_ws = _validate_targeted_extract_reply(req_id_str)
            if target_ws is not None:
                hub.latest_clip = clip_obj
                await _ws_send_json(target_ws, clip_msg)
        else:
            hub.latest_clip = clip_obj
            owner_bot, owner_uid = hub._effective_resource_owner()
            if owner_bot is not None and owner_uid is not None:
                await hub.broadcast_json_to_owners(
                    clip_msg,
                    owner_bot=owner_bot,
                    owner_uid=owner_uid,
                    require_admin=False,
                    expected_session_gen=start_gen,
                )
    return web.json_response({"ok": True})


async def internal_sync_stop(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    q = getattr(request, "query", {}) or {}
    hdr_lease = str(request.headers.get("X-Sync-Lease-Id") or q.get("lease_id") or "").strip()
    hdr_sgen = _parse_strict_int(q.get("session_gen") or request.headers.get("X-Sync-Session-Gen"))

    # 1. Mandatory pre-read lease validation BEFORE reading request body!
    if not hdr_lease:
        return web.json_response({"ok": False, "error": "Missing required X-Sync-Lease-Id header or lease_id query"}, status=409)
    ok_pre, st_pre, err_pre = _check_sync_lease_active(hub, hdr_lease, expected_gen=hdr_sgen)
    if not ok_pre:
        return web.json_response({"ok": False, "error": err_pre}, status=st_pre)
    start_gen = hub.session_gen

    body: dict[str, Any] = {}
    if hasattr(request, "read"):
        try:
            raw = await request.read()
        except Exception:
            raw = b""
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
                if isinstance(parsed, dict):
                    body = parsed
            except Exception:
                return web.json_response({"ok": False, "error": "Invalid JSON body"}, status=400)
    elif hasattr(request, "json"):
        try:
            parsed = await request.json()
            if isinstance(parsed, dict):
                body = parsed
        except Exception:
            body = {}

    body_lease = str(body.get("lease_id") or "").strip()
    if body_lease and not hmac.compare_digest(body_lease, hdr_lease):
        return web.json_response({"ok": False, "error": "Mismatched sync_lease_id"}, status=409)
    req_sgen = _parse_strict_int(body.get("session_gen")) if body.get("session_gen") is not None else None
    if req_sgen is not None and req_sgen != start_gen:
        return web.json_response({"ok": False, "error": "Stale sync session_gen"}, status=409)

    # 2. Post-read validation + synchronous invalidation INSIDE `_engine_lock`!
    async with hub._engine_lock:
        ok_post, st_post, err_post = _check_sync_lease_active(hub, hdr_lease, expected_gen=start_gen)
        if not ok_post:
            return web.json_response({"ok": False, "error": err_post}, status=st_post)
        old_gen, final_jpeg = hub._invalidate_sync_session_sync()

    await hub.tg.retire_cards(session_gen=old_gen, mark_finished=True, final_jpeg=final_jpeg)
    await hub.broadcast_state()
    return web.json_response({"ok": True})


def create_app() -> web.Application:
    if web is None:
        raise RuntimeError("aiohttp is required to run the Live Browser Hub server")
    cfg, local_token = ensure_local_config()
    hub = LiveBrowserHub(cfg, local_token)
    app = web.Application(client_max_size=MAX_UPLOAD_TOTAL_BYTES)
    app["hub"] = hub

    async def _on_startup(_app: web.Application) -> None:
        await hub.startup()

    async def _on_cleanup(_app: web.Application) -> None:
        await hub.shutdown()

    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)

    app.router.add_get("/", handle_index)
    app.router.add_get("/healthz", handle_healthz)
    app.router.add_get("/ws", handle_ws)
    app.router.add_post("/api/upload", handle_api_upload)
    app.router.add_get("/api/download/{download_id}", handle_api_download)

    app.router.add_get("/internal/status", internal_status)
    app.router.add_post("/internal/takeover", internal_takeover)
    app.router.add_post("/internal/start", internal_start)
    app.router.add_post("/internal/stop", internal_stop)
    app.router.add_post("/internal/action", internal_action)
    app.router.add_post("/internal/config", internal_config)
    app.router.add_post("/internal/yield-lock", internal_yield_lock)
    app.router.add_get("/internal/profiles", internal_profiles_list)
    app.router.add_post("/internal/profiles", internal_profiles_create)
    app.router.add_post("/internal/profiles/switch", internal_profiles_switch)
    app.router.add_delete("/internal/profiles/{name}", internal_profiles_delete)
    app.router.add_post("/internal/sync/start", internal_sync_start)
    app.router.add_post("/internal/sync/push", internal_sync_push)
    app.router.add_post("/internal/sync/clipboard", internal_sync_clipboard)
    app.router.add_post("/internal/sync/stop", internal_sync_stop)
    return app


def main() -> None:
    cfg, _ = ensure_local_config()
    host = str(cfg.get("host") or DEFAULT_HOST)
    port = int(cfg.get("port") or DEFAULT_PORT)
    app = create_app()
    log.info("Starting AGY Live Browser Hub on http://%s:%d", host, port)
    web.run_app(app, host=host, port=port, print=None)


if __name__ == "__main__":
    main()
