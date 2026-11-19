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
    from aiohttp import FormData, WSMsgType, web
except ImportError:
    FormData = None  # type: ignore[assignment]
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
MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25 MB per upload
MAX_TG_DOWNLOAD_BYTES = 20 * 1024 * 1024  # 20 MB auto-push to TG DM
TRANSFER_TTL_SECONDS = 1800.0  # 30 minutes temp file retention
DIALOG_TIMEOUT_SECONDS = 120.0

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


def _get_google_skill_scripts_dir() -> Path:
    raw = os.environ.get("AGY_GOOGLE_SKILL_SCRIPTS")
    if raw is not None:
        return Path(raw) if raw.strip() else Path("/nonexistent-google-skill-dir")
    return Path.home() / "agy-workspace/.agents/skills/google-profile/scripts"


def _import_google_browser() -> Any | None:
    """Optionally load host-specific `google_browser` module when present."""
    scripts_dir = _get_google_skill_scripts_dir()
    mod_path = scripts_dir / "google_browser.py"
    if not mod_path.is_file():
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
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def discover_pinned_host_profile() -> dict[str, Any] | None:
    """Discover a host-pinned persistent profile if `google_browser` is installed."""
    gb = _import_google_browser()
    if gb is None:
        return None
    profile_dir = getattr(gb, "PROFILE_DIR", None)
    lock_path = getattr(gb, "LOCK_PATH", None)
    if not profile_dir or not lock_path:
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


def validate_profile_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a profile configuration dictionary."""
    if not isinstance(data, dict):
        raise ValueError("Profile config must be a JSON object")

    pinned = bool(data.get("pinned", False))
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
        items.append(
            sanitize_profile_for_output(
                name,
                configured[name],
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

    is_pinned = bool(entry.get("pinned", False))
    if is_pinned:
        _check_pinned_overrides(target_name, overrides)
        if entry.get("proxy") or entry.get("proxy_bao_ref") or entry.get("persistent") is False:
            raise ValueError(f"Pinned profile '{target_name}' cannot have proxy or ephemeral config")
        return {
            "name": target_name,
            "pinned": True,
            "persistent": True,
            "profile_dir": data_dir / target_name,
            "lock_path": data_dir / f"{target_name}.lock",
            "os": "windows",
            "fingerprint": dict(PINNED_FINGERPRINT_DEFAULTS),
            "direct_env_fn": None,
            "proxy": None,
            "proxy_bao_ref": None,
            "locale": None,
            "window": None,
            "webgl_config": None,
            "block_webrtc": None,
            "geoip": None,
        }

    ov = overrides or {}
    merged: dict[str, Any] = dict(entry)
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

    validated = validate_profile_payload(merged)
    return {
        "name": target_name,
        "pinned": False,
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


def load_bot_credentials_detailed(
    bridge_dir: Path | None = None,
) -> tuple[dict[str, str], dict[str, str], set[int], dict[str, set[int]]]:
    """Load bot tokens, bot ID map, global allowed chats, and per-bot allowed chats without logging secrets."""
    bots_by_key: dict[str, str] = {}
    bot_id_to_key: dict[str, str] = {}
    allowed_chats: set[int] = set()
    allowed_by_bot: dict[str, set[int]] = {}

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
        bot_allowed: set[int] = set()
        for chat_str in env_map.get("AGY_TG_ALLOWED_CHATS", "").split(","):
            chat_str = chat_str.strip()
            if chat_str and chat_str.lstrip("-").isdigit():
                cid = int(chat_str)
                allowed_chats.add(cid)
                bot_allowed.add(cid)
        if token and ":" in token:
            bots_by_key[key] = token
            bot_id_to_key[token.split(":", 1)[0]] = key
            allowed_by_bot[key] = bot_allowed

    return bots_by_key, bot_id_to_key, allowed_chats, allowed_by_bot


def load_bot_credentials() -> tuple[dict[str, str], dict[str, str], set[int]]:
    """Load bot tokens and allowed chat IDs from agy-tg-bridge .env* files without logging secrets."""
    bots_by_key, bot_id_to_key, allowed_chats, allowed_by_bot = load_bot_credentials_detailed()
    _LAST_ALLOWED_BY_BOT.clear()
    _LAST_ALLOWED_BY_BOT.update(allowed_by_bot)
    return bots_by_key, bot_id_to_key, allowed_chats


_DEFAULT_LOAD_BOT_CREDENTIALS = load_bot_credentials


def _resolve_private_chat_id(
    allowed: Iterable[int] | None,
    preferred_user_id: int | None = None,
    bot_allowed: Iterable[int] | None = None,
) -> int | None:
    """Resolve a strictly positive Telegram private DM chat ID; never returns negative group IDs."""
    allowed_set: set[int] = set()
    for cid in allowed or ():
        try:
            allowed_set.add(int(cid))
        except (TypeError, ValueError):
            continue

    bot_set: set[int] = set()
    for cid in bot_allowed or ():
        try:
            bot_set.add(int(cid))
        except (TypeError, ValueError):
            continue

    if preferred_user_id is not None:
        try:
            pref = int(preferred_user_id)
        except (TypeError, ValueError):
            pref = 0
        if pref > 0 and (pref in allowed_set or pref in bot_set):
            return pref

    bot_pos = sorted(c for c in bot_set if c > 0)
    if bot_pos:
        return bot_pos[0]

    global_pos = sorted(c for c in allowed_set if c > 0)
    if global_pos:
        return global_pos[0]

    return None


def verify_telegram_init_data(
    init_data: str,
    bots_by_key: dict[str, str],
    allowed_chats: set[int],
    max_age_sec: int = 86400,
) -> tuple[bool, dict[str, Any] | None, str]:
    """Validate Telegram Mini App initData via HMAC-SHA256 + allowed user whitelist."""
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

    if uid not in allowed_chats:
        return False, None, f"账号 {uid} 不在授权白名单中。"

    return True, {"user": user, "bot": matched_bot}, ""


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
        # Per-bot active card state: {bot_key: {"chat_id": int, "message_id": int, "last_sha1": str, "last_caption": str, "last_ts": float}}
        self.cards: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        from aiohttp import ClientSession, ClientTimeout
        self.http = ClientSession(timeout=ClientTimeout(total=15), trust_env=True)

    async def close(self) -> None:
        if self.http:
            await self.http.close()
            self.http = None

    def _resolve_bot_token_and_chat(
        self, bot_key: str, preferred_user_id: int | None = None
    ) -> tuple[str | None, int | None]:
        bots, _, allowed = load_bot_credentials()
        token = bots.get(bot_key)
        if not token:
            return None, None
        bot_allowed = (
            _LAST_ALLOWED_BY_BOT.get(bot_key)
            if load_bot_credentials is _DEFAULT_LOAD_BOT_CREDENTIALS
            else None
        )
        chat_id = _resolve_private_chat_id(
            allowed, preferred_user_id=preferred_user_id, bot_allowed=bot_allowed
        )
        return token, chat_id

    def _build_markup(self, bot_key: str, finished: bool = False) -> str | None:
        pub = (self.hub.config.get("public_url") or "").strip().rstrip("/")
        rows: list[list[dict[str, Any]]] = []
        if pub.startswith("https://"):
            btn_text = (
                "🟠 人工接管中 · 点此操作浏览器"
                if self.hub.takeover
                else "🖥 打开实时画面 / 人工接管"
            )
            rows.append([{"text": btn_text, "web_app": {"url": f"{pub}/?bot={bot_key}"}}])
        if not finished:
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
        ts_str = time.strftime("%H:%M:%S", time.localtime())
        title = html.escape((self.hub.title or "加载中...")[:70])
        url = html.escape((self.hub.url or "about:blank")[:120])
        if finished:
            header = f"⏹ <b>浏览器实况已结束</b> · <code>{ts_str}</code>"
            status_line = "✅ 会话已安全关闭（保留最终画面）"
        elif self.hub.takeover:
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

    async def ensure_card(
        self,
        bot_key: str,
        force_new: bool = False,
        preferred_user_id: int | None = None,
    ) -> dict[str, Any] | None:
        """Create or update the live browser card in the target bot's primary private DM chat."""
        token, chat_id = self._resolve_bot_token_and_chat(bot_key, preferred_user_id=preferred_user_id)
        if not token or not chat_id or chat_id <= 0:
            if token:
                log.warning("Skipping live card send for bot=%s: no positive private chat_id in allowed chats", bot_key)
            return None

        # Wait briefly if first frame is still arriving
        for _ in range(15):
            if self.hub.latest_jpeg:
                break
            await asyncio.sleep(0.15)
        if not self.hub.latest_jpeg:
            return None

        async with self._lock:
            existing = self.cards.get(bot_key)
            if existing and not force_new:
                await self._update_card_locked(bot_key, token, finished=False, force=True)
                return self.cards.get(bot_key)

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
                self.hub.latest_jpeg,
                filename="live_browser.jpg",
                content_type="image/jpeg",
            )

            try:
                async with self.http.post(
                    f"https://api.telegram.org/bot{token}/sendPhoto", data=form
                ) as resp:
                    data = await resp.json()
                    if data.get("ok") and data.get("result"):
                        mid = data["result"]["message_id"]
                        sha = hashlib.sha1(self.hub.latest_jpeg).hexdigest()
                        self.cards[bot_key] = {
                            "chat_id": chat_id,
                            "message_id": mid,
                            "last_sha1": sha,
                            "last_caption": caption,
                            "last_markup": markup,
                            "last_ts": time.monotonic(),
                        }
                        log.info("Created Telegram live card bot=%s chat_id=%s message_id=%s", bot_key, chat_id, mid)
                        return self.cards[bot_key]
                    log.warning("sendPhoto failed (%s): %s", bot_key, data.get("description"))
            except Exception as exc:
                log.warning("sendPhoto error (%s): %s", bot_key, exc)
            return None

    async def tick_updates(self, finished: bool = False, force: bool = False) -> None:
        if not self.cards or not self.hub.latest_jpeg:
            return
        bots, _, _ = load_bot_credentials()
        async with self._lock:
            for bot_key in list(self.cards.keys()):
                token = bots.get(bot_key)
                if not token:
                    continue
                await self._update_card_locked(bot_key, token, finished=finished, force=force)
                if finished:
                    self.cards.pop(bot_key, None)

    async def _update_card_locked(
        self, bot_key: str, token: str, finished: bool = False, force: bool = False
    ) -> None:
        card = self.cards.get(bot_key)
        if not card or not self.hub.latest_jpeg:
            return
        now = time.monotonic()
        if not force and not finished and (now - card["last_ts"]) < 3.0:
            return

        sha = hashlib.sha1(self.hub.latest_jpeg).hexdigest()
        caption = self._build_caption(finished=finished)
        markup = self._build_markup(bot_key, finished=finished)

        if (
            not force
            and not finished
            and sha == card["last_sha1"]
            and caption == card["last_caption"]
            and markup == card.get("last_markup")
        ):
            return

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
            self.hub.latest_jpeg,
            filename="live_browser.jpg",
            content_type="image/jpeg",
        )

        try:
            async with self.http.post(
                f"https://api.telegram.org/bot{token}/editMessageMedia", data=form
            ) as resp:
                data = await resp.json()
                if data.get("ok"):
                    card["last_sha1"] = sha
                    card["last_caption"] = caption
                    card["last_markup"] = markup
                    card["last_ts"] = time.monotonic()
                else:
                    desc = str(data.get("description", ""))
                    retry = (data.get("parameters") or {}).get("retry_after")
                    if retry:
                        card["last_ts"] = time.monotonic() + float(retry)
                    elif "message is not modified" not in desc.lower():
                        log.debug("editMessageMedia (%s): %s", bot_key, desc)
        except Exception as exc:
            log.debug("editMessageMedia error (%s): %s", bot_key, exc)

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

        # Engine state
        self.engine_mode: str = "idle"  # 'idle' | 'async_hosted' | 'sync_external'
        self.camoufox_cm: Any = None
        self.ctx: Any = None
        self.lock_fd: int | None = None
        self.active_tab_index: int = 0
        self.ai_busy_count: int = 0
        self.last_activity_ts: float = time.monotonic()

        # Active profile & egress state (never stores plaintext proxy credentials)
        self.active_profile: str = ""
        self.active_profile_dir: Path | None = None
        self._ephemeral_dir: Path | None = None
        self.active_pinned: bool = False
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
        self._last_tabs_refresh: float = 0.0
        self._last_frame_sig: tuple[int, bytes] | None = None
        self._last_frame_is_hd: bool = False
        self._unchanged_frames: int = 0
        self._last_active_ts: float = time.monotonic()
        self._hd_pending: bool = False

        # Native Playwright page event state (zero page JS injection)
        self._attached_pages: set[int] = set()
        self.pending_dialogs: dict[str, dict[str, Any]] = {}
        self.pending_filechoosers: dict[str, dict[str, Any]] = {}
        self.downloads: dict[str, dict[str, Any]] = {}
        self._transfer_dir: Path | None = None

        # 3-State Control Arbitration
        self.takeover: bool = False
        self.takeover_reason: str = ""
        self.ai_allowed_event = asyncio.Event()
        self.ai_allowed_event.set()

        # Queues & Clients
        self.viewers: set[web.WebSocketResponse] = set()
        self.viewer_meta: dict[Any, dict[str, Any]] = {}
        self.input_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=250)
        self.sync_cmd_queue: list[dict[str, Any]] = []
        self._engine_lock = asyncio.Lock()

        # Background tasks
        self._capture_task: asyncio.Task[None] | None = None
        self._input_task: asyncio.Task[None] | None = None
        self._tg_loop_task: asyncio.Task[None] | None = None
        self.tg = TelegramLiveCardPublisher(self)

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
        await self._cleanup_pending_dialogs()
        self._cleanup_pending_filechoosers()
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
        self._last_frame_is_hd = False
        if mark_tabs_dirty:
            self._tabs_dirty = True

    async def set_quality_preset(self, preset: str) -> str:
        clean = str(preset or "").strip().lower()
        if clean not in QUALITY_PRESETS:
            clean = "balanced"
        self.quality_preset = clean
        self._last_frame_sig = None
        self._last_frame_is_hd = False
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
                    Path(info["path"]).unlink(missing_ok=True)
                except OSError:
                    pass
        if self._transfer_dir and self._transfer_dir.is_dir():
            try:
                for p in self._transfer_dir.iterdir():
                    try:
                        if (time.time() - p.stat().st_mtime) > TRANSFER_TTL_SECONDS:
                            p.unlink(missing_ok=True)
                    except OSError:
                        pass
            except OSError:
                pass

    def _preferred_viewer_target(self) -> tuple[str, int | None]:
        for ws in list(self.viewers):
            meta = self.viewer_meta.get(ws)
            if meta and meta.get("bot_key"):
                return str(meta["bot_key"]), meta.get("user_id")
        return self.resolve_bot_key(None), None

    def resolve_bot_key(self, hint: str | None) -> str:
        bots, id_map, _ = load_bot_credentials()
        if hint:
            if hint in bots:
                return hint
            if hint in id_map:
                return id_map[hint]
        if "sg" in bots:
            return "sg"
        return next(iter(bots.keys()), "main")

    def state_dict(self) -> dict[str, Any]:
        return {
            "type": "state",
            "running": self.engine_mode != "idle",
            "engine_mode": self.engine_mode,
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

    async def broadcast_json(self, obj: dict[str, Any]) -> None:
        if not self.viewers:
            return
        payload = json.dumps(obj, ensure_ascii=False)
        stale: list[web.WebSocketResponse] = []
        for ws in list(self.viewers):
            if ws.closed:
                stale.append(ws)
                continue
            try:
                await ws.send_str(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.viewers.discard(ws)

    async def broadcast_state(self) -> None:
        await self.broadcast_json(self.state_dict())

    async def broadcast_frame(self, jpeg_bytes: bytes) -> None:
        self.latest_jpeg = jpeg_bytes
        if not self.viewers:
            return
        stale: list[web.WebSocketResponse] = []
        for ws in list(self.viewers):
            if ws.closed:
                stale.append(ws)
                continue
            # Drop frame for slow client if transport buffer > 512KB to prevent latency buildup
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

    async def set_takeover(self, active: bool, reason: str = "") -> None:
        self.takeover = bool(active)
        self.mark_active()
        if self.takeover:
            self.ai_allowed_event.clear()
            self.takeover_reason = reason or "人工接管中（AI 已挂起等待）"
            log.info("Takeover ENABLED: %s", self.takeover_reason)
        else:
            self.takeover_reason = ""
            self.ai_allowed_event.set()
            log.info("Takeover RELEASED -> AI resumed")
        await self.broadcast_state()
        asyncio.create_task(self.tg.tick_updates(force=True))

    async def wait_until_ai_allowed(self, timeout: float = 900.0) -> None:
        if self.takeover:
            await asyncio.wait_for(self.ai_allowed_event.wait(), timeout=timeout)

    # ---------------- Native Page Listeners (Dialog / FileChooser / Download) ----------------

    def _attach_page_listeners(self, page: Any) -> None:
        """Attach native Playwright listeners for metadata dirtying, dialog, filechooser & download."""
        pid = id(page)
        if pid in self._attached_pages:
            return
        on_fn = getattr(page, "on", None)
        if not callable(on_fn):
            return
        self._attached_pages.add(pid)

        def _mark_dirty(*_args: Any) -> None:
            self.mark_active(mark_tabs_dirty=True)

        def _on_close(*_args: Any) -> None:
            self._attached_pages.discard(pid)
            self._tabs_dirty = True
            self._cleanup_pending_filechoosers(page_id=pid)
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._cleanup_pending_dialogs(page_id=pid))
            except RuntimeError:
                pass

        def _on_dialog(dialog: Any) -> None:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._handle_page_dialog(dialog, page))
            except RuntimeError:
                pass

        def _on_filechooser(chooser: Any) -> None:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._handle_page_filechooser(chooser, page))
            except RuntimeError:
                pass

        def _on_download(download: Any) -> None:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._handle_page_download(download, page))
            except RuntimeError:
                pass

        try:
            on_fn("framenavigated", _mark_dirty)
            on_fn("load", _mark_dirty)
            on_fn("close", _on_close)
            on_fn("dialog", _on_dialog)
            on_fn("filechooser", _on_filechooser)
            on_fn("download", _on_download)
        except Exception as exc:
            log.debug("Failed attaching page listeners: %s", exc)

    async def _handle_page_dialog(self, dialog: Any, page: Any | None = None) -> None:
        dtype = str(getattr(dialog, "type", "alert") or "alert")
        message = str(getattr(dialog, "message", "") or "")
        default_val = str(getattr(dialog, "default_value", "") or "")

        if not self.viewers and not self.takeover:
            log.info("Auto-dismissing dialog (%s) with no active viewers/takeover", dtype)
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
            "resolved": False,
        }
        self.pending_dialogs[dialog_id] = entry
        self.mark_active()
        await self.broadcast_json(
            {
                "type": "dialog_open",
                "dialog_id": dialog_id,
                "dialog_type": dtype,
                "message": entry["message"],
                "default_value": entry["default_value"],
            }
        )

        async def _timeout_guard() -> None:
            await asyncio.sleep(DIALOG_TIMEOUT_SECONDS)
            if dialog_id in self.pending_dialogs:
                log.info("Dialog %s timed out; auto-dismissing", dialog_id)
                await self.resolve_dialog(dialog_id, accept=False)

        try:
            entry["timeout_task"] = asyncio.create_task(_timeout_guard())
        except RuntimeError:
            pass

    async def resolve_dialog(
        self, dialog_id: str, accept: bool, prompt_text: str | None = None
    ) -> bool:
        entry = self.pending_dialogs.pop(dialog_id, None)
        if not entry or entry.get("resolved"):
            return False
        entry["resolved"] = True
        tt = entry.get("timeout_task")
        if tt and not tt.done():
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
        await self.broadcast_json({"type": "dialog_closed", "dialog_id": dialog_id})
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
        for did in to_remove:
            entry = self.pending_dialogs.pop(did, None)
            if not entry or entry.get("resolved"):
                continue
            entry["resolved"] = True
            tt = entry.get("timeout_task")
            if tt and not tt.done():
                tt.cancel()
            try:
                await entry["dialog"].dismiss()
            except Exception:
                pass
            await self.broadcast_json({"type": "dialog_closed", "dialog_id": did})

    async def _handle_page_filechooser(self, chooser: Any, page: Any | None = None) -> None:
        chooser_id = secrets.token_hex(8)
        multiple = False
        try:
            is_mult = getattr(chooser, "is_multiple", None)
            multiple = bool(is_mult() if callable(is_mult) else is_mult)
        except Exception:
            multiple = False
        self.pending_filechoosers[chooser_id] = {
            "id": chooser_id,
            "chooser": chooser,
            "page_id": id(page) if page is not None else None,
            "multiple": multiple,
            "created_ts": time.monotonic(),
        }
        self.mark_active()
        await self.broadcast_json(
            {
                "type": "filechooser_open",
                "chooser_id": chooser_id,
                "multiple": multiple,
            }
        )

    def _cleanup_pending_filechoosers(self, *, page_id: int | None = None) -> None:
        now = time.monotonic()
        for cid, info in list(self.pending_filechoosers.items()):
            expired = (now - float(info.get("created_ts", 0.0))) > TRANSFER_TTL_SECONDS
            if page_id is None or info.get("page_id") == page_id or expired:
                self.pending_filechoosers.pop(cid, None)

    async def _handle_page_download(self, download: Any, _page: Any | None = None) -> None:
        download_id = secrets.token_hex(8)
        raw_name = str(getattr(download, "suggested_filename", "") or "download.bin")
        safe_name = Path(raw_name).name or "download.bin"
        xfer_dir = self._ensure_transfer_dir()
        dest_path = xfer_dir / f"dl-{download_id}-{safe_name}"
        try:
            await download.save_as(str(dest_path))
            os.chmod(dest_path, 0o600)
            size = dest_path.stat().st_size
        except Exception as exc:
            log.warning("Download save_as failed (%s): %s", safe_name, exc)
            dest_path.unlink(missing_ok=True)
            await self.broadcast_json({"type": "toast", "message": f"❌ 下载失败: {safe_name}"})
            return

        info = {
            "id": download_id,
            "filename": safe_name,
            "path": dest_path,
            "size": size,
            "created_ts": time.monotonic(),
            "auto_sent": False,
        }
        self.downloads[download_id] = info
        self.mark_active()

        auto_sent = False
        if 0 < size <= MAX_TG_DOWNLOAD_BYTES:
            bot_key, pref_uid = self._preferred_viewer_target()
            caption = f"📥 <b>浏览器下载文件</b>\n<code>{html.escape(safe_name)}</code> ({size:,} B)"
            auto_sent = await self.tg.send_document_file(
                bot_key, dest_path, safe_name, caption=caption, preferred_user_id=pref_uid
            )
            info["auto_sent"] = auto_sent

        await self.broadcast_json(
            {
                "type": "download_ready",
                "download_id": download_id,
                "filename": safe_name,
                "size": size,
                "auto_sent": auto_sent,
            }
        )

    async def send_download_to_tg(
        self, download_id: str, bot_key: str, preferred_user_id: int | None = None
    ) -> tuple[bool, str]:
        info = self.downloads.get(download_id)
        if not info:
            return False, "下载文件已过期或不存在"
        path = Path(info["path"])
        if not path.is_file():
            self.downloads.pop(download_id, None)
            return False, "下载文件已被清理"
        size = int(info.get("size") or path.stat().st_size)
        if size > MAX_TG_DOWNLOAD_BYTES:
            return False, f"文件超过 {MAX_TG_DOWNLOAD_BYTES // (1024 * 1024)}MB 限制，请直接从面板下载"
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

    async def _stop_hosted_locked(self) -> None:
        if self.engine_mode != "async_hosted":
            return
        await self._cleanup_pending_dialogs()
        self._cleanup_pending_filechoosers()
        await self._capture_once(force_broadcast=True)
        cm = self.camoufox_cm
        fd = self.lock_fd
        ephemeral_dir = self._ephemeral_dir
        self.camoufox_cm = None
        self.ctx = None
        self.lock_fd = None
        self._ephemeral_dir = None
        self.engine_mode = "idle"
        self.x11_display = None
        self._last_x11_clip = ""
        self.tabs = []
        self.ai_status = ""
        self.takeover = False
        self.takeover_reason = ""
        self.active_profile = ""
        self.active_profile_dir = None
        self.active_pinned = False
        self.active_egress = "direct"
        self.active_os = ""
        self.active_fingerprint = {}
        self._attached_pages.clear()
        self._tabs_dirty = True
        self._last_frame_sig = None
        self._last_frame_is_hd = False
        self._unchanged_frames = 0
        self._hd_pending = False
        self.ai_allowed_event.set()
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
        log.info("Stopped hosted AsyncCamoufox and released profile lock")

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
    ) -> dict[str, Any]:
        async with self._engine_lock:
            self.mark_active(mark_tabs_dirty=True)
            if self.engine_mode == "sync_external":
                raise RuntimeError("当前已有外部同步脚本持有浏览器会话。")

            spec = resolve_launch_spec(profile_name=profile, overrides=overrides)
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
                    await self._stop_hosted_locked()

            if self.engine_mode != "async_hosted":
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

                    kwargs, egress_summary = build_camoufox_kwargs(spec, user_data_dir)

                    from camoufox.async_api import AsyncCamoufox

                    cm = AsyncCamoufox(**kwargs)
                    ctx = await cm.__aenter__()
                except Exception:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except Exception:
                        pass
                    os.close(fd)
                    if ephemeral_dir is not None and ephemeral_dir.exists():
                        shutil.rmtree(ephemeral_dir, ignore_errors=True)
                    raise

                self.lock_fd = fd
                self.camoufox_cm = cm
                self.ctx = ctx
                self.engine_mode = "async_hosted"
                self.active_profile = spec["name"]
                self.active_profile_dir = user_data_dir
                self._ephemeral_dir = ephemeral_dir
                self.active_pinned = bool(spec["pinned"])
                self.active_egress = egress_summary
                self.active_os = str(spec.get("os") or "windows")
                fp_summary: dict[str, Any] = {"os": self.active_os, "persistent": bool(spec["persistent"])}
                for fp_key in ("locale", "window", "mobile", "webgl_config", "block_webrtc", "geoip"):
                    if spec.get(fp_key) is not None and spec.get(fp_key) is not False:
                        fp_summary[fp_key] = spec[fp_key]
                self.active_fingerprint = fp_summary

                self.ai_status = "已启动安全浏览器"
                self.x11_display = resolve_camoufox_display(ctx, self.active_profile_dir)
                self._last_x11_clip = await read_x11_clipboard_async(self.x11_display)
                log.info("Resolved Camoufox X11 display=%s", self.x11_display)

                def _on_new_page(new_page: Any) -> None:
                    try:
                        self._attach_page_listeners(new_page)
                        pages = list(self.ctx.pages)
                        if new_page in pages:
                            self.active_tab_index = pages.index(new_page)
                        self.mark_active(mark_tabs_dirty=True)
                    except Exception:
                        pass

                ctx.on("page", _on_new_page)
                if not ctx.pages:
                    await ctx.new_page()
                for existing_page in list(ctx.pages):
                    self._attach_page_listeners(existing_page)
                self.active_tab_index = max(0, len(ctx.pages) - 1)
                self._tabs_dirty = True
                self._last_frame_sig = None
                log.info(
                    "Started hosted AsyncCamoufox profile=%s pinned=%s os=%s egress=%s",
                    self.active_profile,
                    self.active_pinned,
                    self.active_os,
                    self.active_egress,
                )

            page = self._current_page()
            if initial_url and page:
                self.ai_status = f"正在打开 {initial_url}"
                await self.broadcast_state()
                await page.goto(initial_url, wait_until="domcontentloaded", timeout=45000)
                self.ai_status = f"已打开 {initial_url}"
                self.mark_active(mark_tabs_dirty=True)

            await self._capture_once(force_broadcast=True)
            await self.broadcast_state()

        if notify_tg:
            bot_key = self.resolve_bot_key(bot_hint)
            asyncio.create_task(self.tg.ensure_card(bot_key, preferred_user_id=preferred_user_id))

        return self.state_dict()

    async def stop_hosted(self, notify_finished: bool = True) -> None:
        async with self._engine_lock:
            if self.engine_mode != "async_hosted":
                return
            await self._stop_hosted_locked()

        if notify_finished:
            await self.tg.tick_updates(finished=True, force=True)
        await self.broadcast_state()

    def _current_page(self) -> Any | None:
        if not self.ctx or not self.ctx.pages:
            return None
        pages = list(self.ctx.pages)
        if self.active_tab_index >= len(pages):
            self.active_tab_index = len(pages) - 1
        if self.active_tab_index < 0:
            self.active_tab_index = 0
        return pages[self.active_tab_index]

    async def _refresh_tabs_metadata(self, *, force: bool = False) -> bool:
        """Refresh tab list, URL, title & viewport outside the hot screenshot path."""
        if self.engine_mode != "async_hosted" or not self.ctx:
            return False
        page = self._current_page()
        if not page:
            return False
        now = time.monotonic()
        pages = list(self.ctx.pages)
        needs = (
            force
            or self._tabs_dirty
            or len(pages) != len(self.tabs)
            or (now - self._last_tabs_refresh) >= 1.2
            or page.url != self.url
        )
        if not needs:
            return False

        tabs_info: list[dict[str, Any]] = []
        for idx, p in enumerate(pages):
            self._attach_page_listeners(p)
            try:
                t_title = await asyncio.wait_for(p.title(), timeout=0.6)
            except Exception:
                t_title = ""
            tabs_info.append(
                {
                    "index": idx,
                    "title": t_title or p.url or f"Tab {idx + 1}",
                    "url": p.url,
                    "active": idx == self.active_tab_index,
                }
            )
        self.tabs = tabs_info
        self.url = page.url
        self.title = tabs_info[self.active_tab_index]["title"] if tabs_info else ""

        vp = page.viewport_size
        if vp and vp.get("width") and vp.get("height"):
            self.vw = int(vp["width"])
            self.vh = int(vp["height"])
        else:
            try:
                dims = await asyncio.wait_for(
                    page.evaluate("() => ({w: window.innerWidth, h: window.innerHeight})"),
                    timeout=0.8,
                )
                if dims and dims.get("w") and dims.get("h"):
                    self.vw = int(dims["w"])
                    self.vh = int(dims["h"])
            except Exception:
                pass

        self._tabs_dirty = False
        self._last_tabs_refresh = now
        return True

    async def _capture_once(self, *, force_broadcast: bool = False, hd: bool = False) -> bool:
        if self.engine_mode != "async_hosted":
            return False
        page = self._current_page()
        if not page:
            return False
        try:
            preset_cfg = QUALITY_PRESETS.get(self.quality_preset, QUALITY_PRESETS["balanced"])
            quality = int(preset_cfg["hd_quality"] if hd else preset_cfg["stream_quality"])
            jpeg = await asyncio.wait_for(
                page.screenshot(type="jpeg", quality=quality, animations="allow"),
                timeout=3.0,
            )
            await self._refresh_tabs_metadata(force=force_broadcast)

            sig = (len(jpeg), hashlib.blake2b(jpeg, digest_size=16).digest())
            if not force_broadcast and not hd and sig == self._last_frame_sig:
                self._unchanged_frames += 1
                self.latest_jpeg = jpeg
                return False

            self._last_frame_sig = sig
            self._last_frame_is_hd = hd
            if hd:
                self._hd_pending = False
            else:
                self._unchanged_frames = 0
                self._hd_pending = True

            await self.broadcast_frame(jpeg)
            return True
        except Exception as exc:
            log.debug("Frame capture skipped: %s", exc)
            return False

    async def _poll_clipboard_once(self) -> None:
        if self.engine_mode != "async_hosted":
            return
        if not self.x11_display:
            self.x11_display = resolve_camoufox_display(self.ctx, self.active_profile_dir)
            if self.x11_display:
                self._last_x11_clip = await read_x11_clipboard_async(self.x11_display)
                return
        if not self.x11_display:
            return
        clip = await read_x11_clipboard_async(self.x11_display)
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

    async def extract_content_async(self, req: dict[str, Any]) -> dict[str, Any] | None:
        """Read-only DOM extraction for mobile/desktop cross-system copy without altering page prototypes."""
        page = self._current_page()
        if not page:
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
                if not body_txt:
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
                if mode == "range_preview":
                    return {"preview": True, "text": (sel_res or "").strip()}
                cleaned_sel = (sel_res or "").strip()
                if not cleaned_sel:
                    return None
                await self._capture_once()
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
                    page.evaluate("() => (window.getSelection && window.getSelection().toString() || '').trim().slice(0, 25000)"),
                    timeout=0.8,
                )
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
                            const val = tp === 'password' ? '' : String(el.value || el.placeholder || '').trim();
                            if (val) {
                                return { text: val.slice(0, 20000), blockText: '', href: '', label: '输入框内容' };
                            }
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
            await self._capture_once()
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
                            and not self._last_frame_is_hd
                            and idle_since_active >= 0.32
                        )
                        changed = await self._capture_once(hd=need_hd)
                        now = time.monotonic()
                        if (changed or self._tabs_dirty) and (now - last_state_push >= 0.6):
                            last_state_push = now
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
                if self.engine_mode != "idle" and self.tg.cards:
                    await self.tg.tick_updates(finished=False, force=False)
                now = time.monotonic()
                if (now - last_cleanup) >= 60.0:
                    last_cleanup = now
                    self._cleanup_transfer_dir(force_all=False)
                    self._cleanup_pending_filechoosers(page_id=-1)
                await asyncio.sleep(1.2)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.debug("TG maintenance loop error: %s", exc)
                await asyncio.sleep(2.0)

    def _coalesce_queued_input(self, cmd: dict[str, Any]) -> dict[str, Any]:
        """Coalesce consecutive wheel or mouse move events from input_queue."""
        act = cmd.get("action")
        if act == "wheel":
            dx = float(cmd.get("dx", 0))
            dy = float(cmd.get("dy", 0))
            while not self.input_queue.empty():
                nxt = self.input_queue._queue[0]  # peek
                if nxt.get("action") == "wheel":
                    self.input_queue.get_nowait()
                    dx += float(nxt.get("dx", 0))
                    dy += float(nxt.get("dy", 0))
                else:
                    break
            return {"action": "wheel", "dx": dx, "dy": dy}
        if act == "move":
            latest = cmd
            while not self.input_queue.empty():
                nxt = self.input_queue._queue[0]  # peek
                if nxt.get("action") == "move":
                    latest = self.input_queue.get_nowait()
                else:
                    break
            return latest
        return cmd

    async def _input_loop(self) -> None:
        while True:
            try:
                cmd = await self.input_queue.get()
                self.mark_active()
                cmd = self._coalesce_queued_input(cmd)

                if self.engine_mode == "sync_external":
                    self.sync_cmd_queue.append(cmd)
                    continue

                if self.engine_mode != "async_hosted":
                    continue

                await self._execute_human_cmd_async(cmd)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.warning("Human input execution error: %s", exc)

    async def _execute_human_cmd_async(self, cmd: dict[str, Any]) -> None:
        page = self._current_page()
        if not page:
            return
        act = cmd.get("action")
        self.mark_active(mark_tabs_dirty=(act in ("goto", "back", "forward", "reload", "switch_tab", "new_tab", "close_tab")))

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
            await page.mouse.down(button=button)
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
            await page.mouse.up(button=button)
            await self._capture_once()
            await self.broadcast_state()
            return

        if act == "rightclick":
            x = float(cmd.get("x", 0))
            y = float(cmd.get("y", 0))
            self.cursor = {"x": x, "y": y, "actor": "human", "kind": "rightclick", "ts": time.time()}
            await page.mouse.click(x, y, button="right")
            await self._capture_once()
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
                if focus_info:
                    await self.broadcast_json({"type": "input_focused", **focus_info})
            except Exception:
                pass
        elif act == "wheel":
            await page.mouse.wheel(float(cmd.get("dx", 0)), float(cmd.get("dy", 0)))
        elif act == "type":
            text = str(cmd.get("text", ""))
            if cmd.get("replace"):
                await page.keyboard.press("Control+A")
                await page.keyboard.press("Backspace")
            if text:
                if text.isascii() and len(text) <= 64:
                    await page.keyboard.type(text, delay=15)
                else:
                    await page.keyboard.insert_text(text)
            if cmd.get("submit"):
                await page.keyboard.press("Enter")
        elif act == "press":
            key = str(cmd.get("key", ""))
            if key:
                await page.keyboard.press(key)
        elif act == "clear_field":
            await page.keyboard.press("Control+A")
            await page.keyboard.press("Backspace")
        elif act == "goto":
            url = str(cmd.get("url", "")).strip()
            if url:
                await page.goto(url, wait_until="domcontentloaded", timeout=45000)
        elif act == "back":
            await page.go_back(wait_until="domcontentloaded", timeout=15000)
        elif act == "forward":
            await page.go_forward(wait_until="domcontentloaded", timeout=15000)
        elif act == "reload":
            await page.reload(wait_until="domcontentloaded", timeout=30000)
        elif act == "switch_tab":
            idx = int(cmd.get("index", 0))
            if self.ctx and 0 <= idx < len(self.ctx.pages):
                self.active_tab_index = idx
                await self.ctx.pages[idx].bring_to_front()
        elif act == "new_tab":
            if self.ctx:
                np = await self.ctx.new_page()
                self._attach_page_listeners(np)
                self.active_tab_index = list(self.ctx.pages).index(np)
                await np.goto("https://www.google.com", wait_until="domcontentloaded", timeout=30000)
        elif act == "close_tab":
            idx = int(cmd.get("index", -1))
            if self.ctx and len(self.ctx.pages) > 1 and 0 <= idx < len(self.ctx.pages):
                await self.ctx.pages[idx].close()
                self.active_tab_index = max(0, min(self.active_tab_index, len(self.ctx.pages) - 1))

        await self._capture_once()
        await self.broadcast_state()

    # ---------------- AI Agent Action RPC ----------------

    async def execute_ai_action(self, payload: dict[str, Any]) -> dict[str, Any]:
        action = str(payload.get("action", "")).strip()
        bot_hint = payload.get("bot")
        notify = bool(payload.get("notify", True))
        self.mark_active(mark_tabs_dirty=True)

        if action == "wait_human":
            reason = str(payload.get("reason") or "请点击下方按钮打开面板完成手动操作，完成后点【▶️ 交还给 AI】")
            timeout = float(payload.get("timeout", 600.0))
            if self.engine_mode == "idle":
                await self.start_hosted(bot_hint=bot_hint, notify_tg=notify)
            elif notify:
                await self.tg.ensure_card(self.resolve_bot_key(bot_hint))
            await self.set_takeover(True, reason=reason)
            await asyncio.wait_for(self.ai_allowed_event.wait(), timeout=timeout)
            await self._capture_once()
            return {"ok": True, "resumed": True, **self.state_dict()}

        if self.engine_mode == "idle":
            await self.start_hosted(bot_hint=bot_hint, notify_tg=notify)
        elif notify and bot_hint:
            bot_key = self.resolve_bot_key(bot_hint)
            if bot_key not in self.tg.cards:
                asyncio.create_task(self.tg.ensure_card(bot_key))

        self.ai_busy_count += 1
        try:
            await self.wait_until_ai_allowed()
            page = self._current_page()
            if not page:
                raise RuntimeError("没有可用的浏览器标签页。")

            result_data: dict[str, Any] = {}

            if action == "goto":
                url = str(payload["url"])
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
                if target.isdigit():
                    ms = int(target)
                    self.ai_status = f"等待 {ms}ms..."
                    await asyncio.sleep(ms / 1000.0)
                else:
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

            await self._capture_once()
            await self.broadcast_state()
            asyncio.create_task(self.tg.tick_updates(force=False))
            return {"ok": True, **result_data, "url": self.url, "title": self.title}
        finally:
            self.ai_busy_count = max(0, self.ai_busy_count - 1)


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
) -> None:
    try:
        await hub.start_hosted(
            initial_url=initial_url,
            bot_hint=bot_key,
            notify_tg=True,
            profile=profile,
            restart=restart,
            preferred_user_id=preferred_user_id,
        )
        if takeover and not hub.takeover:
            await hub.set_takeover(True, takeover_reason)
    except (ValueError, KeyError, FileNotFoundError, RuntimeError, TimeoutError) as exc:
        await _ws_send_json(ws, {"type": "toast", "message": str(exc)})
        await hub.broadcast_state()
    except Exception as exc:
        log.warning("WS launch/switch failed: %s", exc)
        await _ws_send_json(ws, {"type": "toast", "message": f"浏览器操作失败: {exc}"})
        await hub.broadcast_state()


async def handle_ws(request: web.Request) -> web.WebSocketResponse:
    hub: LiveBrowserHub = request.app["hub"]
    ws = web.WebSocketResponse(heartbeat=25.0, max_msg_size=2 * 1024 * 1024)
    await ws.prepare(request)

    authenticated = False
    try:
        # First message within 8s MUST be valid Telegram initData auth
        first_msg = await asyncio.wait_for(ws.receive(), timeout=8.0)
        if first_msg.type != WSMsgType.TEXT:
            await ws.close()
            return ws

        auth_payload = json.loads(first_msg.data)
        if auth_payload.get("type") != "auth":
            await ws.send_str(json.dumps({"type": "auth_error", "error": "未提供身份认证帧"}))
            await ws.close()
            return ws

        bots, _, allowed = load_bot_credentials()
        ok, info, err = verify_telegram_init_data(
            str(auth_payload.get("initData", "")), bots, allowed
        )
        if not ok or not info:
            log.warning("Rejected Mini App WS auth from %s: %s", request.remote, err)
            await ws.send_str(json.dumps({"type": "auth_error", "error": err}))
            await ws.close()
            return ws

        authenticated = True
        bot_key = info["bot"]
        user_id = int(info["user"]["id"])
        hub.viewers.add(ws)
        hub.viewer_meta[ws] = {"user_id": user_id, "bot_key": bot_key}
        hub.mark_active()
        log.info("Mini App viewer connected (user=%s, bot=%s, total=%d)", user_id, bot_key, len(hub.viewers))

        await ws.send_str(json.dumps({"type": "auth_ok", **info}))
        await ws.send_str(json.dumps(hub.state_dict(), ensure_ascii=False))
        if hub.latest_jpeg and hub.engine_mode != "idle":
            await ws.send_bytes(hub.latest_jpeg)
        for pending in list(hub.pending_dialogs.values()):
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

        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                continue
            data = json.loads(msg.data)
            mtype = data.get("type")
            if mtype == "ping":
                await ws.send_str(json.dumps({"type": "pong", "t": data.get("t", 0)}))
            elif mtype == "list_profiles":
                await _ws_send_json(
                    ws,
                    {
                        "type": "profiles_list",
                        "active_profile": hub.active_profile or None,
                        "pinned": hub.active_pinned,
                        "running": hub.engine_mode != "idle",
                        "ai_busy": hub.ai_busy_count > 0,
                        "takeover": hub.takeover,
                        "profiles": list_profiles(active_profile=hub.active_profile),
                    },
                )
            elif mtype == "set_takeover":
                await hub.set_takeover(bool(data.get("active")), str(data.get("reason", "")))
            elif mtype == "set_quality":
                chosen = await hub.set_quality_preset(str(data.get("preset") or "balanced"))
                label_map = {"smooth": "流畅", "balanced": "均衡", "hd": "高清"}
                await _ws_send_json(
                    ws, {"type": "toast", "message": f"🎬 画质已切换为：{label_map.get(chosen, chosen)}"}
                )
            elif mtype == "dialog_response":
                did = str(data.get("dialog_id") or "")
                accept = bool(data.get("accept"))
                prompt_text = data.get("prompt_text")
                await hub.resolve_dialog(did, accept=accept, prompt_text=prompt_text)
            elif mtype == "filechooser_cancel":
                cid = str(data.get("chooser_id") or "")
                if cid:
                    hub.pending_filechoosers.pop(cid, None)
                    await hub.broadcast_json({"type": "filechooser_closed", "chooser_id": cid})
            elif mtype == "send_download_to_tg":
                did = str(data.get("download_id") or "")
                ok_dl, msg_dl = await hub.send_download_to_tg(did, bot_key, preferred_user_id=user_id)
                await _ws_send_json(ws, {"type": "toast", "message": msg_dl})
            elif mtype == "send_hd_screenshot":
                shot_bytes: bytes | None = None
                if hub.engine_mode == "async_hosted":
                    page = hub._current_page()
                    if page:
                        try:
                            shot_bytes = await asyncio.wait_for(
                                page.screenshot(type="jpeg", quality=92, animations="allow"),
                                timeout=4.0,
                            )
                        except Exception:
                            shot_bytes = hub.latest_jpeg
                else:
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
                if hub.engine_mode == "idle":
                    req_profile = str(data.get("profile") or "").strip() or None
                    req_url = str(data.get("url") or "https://www.google.com")
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
                        )
                    )
                else:
                    await _ws_send_json(ws, {"type": "toast", "message": "浏览器已在运行中"})
                    await hub.broadcast_state()
            elif mtype == "switch_profile":
                target_profile = str(data.get("profile") or "").strip()
                req_url = str(data.get("url") or "").strip() or None
                try:
                    # Validate target profile existence & pinned invariants upfront
                    resolve_launch_spec(profile_name=target_profile or None)
                except (ValueError, KeyError, FileNotFoundError) as exc:
                    await _ws_send_json(ws, {"type": "toast", "message": f"❌ Profile 无效: {exc}"})
                    await hub.broadcast_state()
                    continue
                if not target_profile:
                    await _ws_send_json(ws, {"type": "toast", "message": "❌ 请指定要切换的 Profile 名称"})
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
                    )
                )
            elif mtype == "stop_browser":
                if hub.engine_mode == "sync_external":
                    await _ws_send_json(ws, {"type": "toast", "message": "当前为外部脚本联动会话，无法从面板直接关闭"})
                    await hub.broadcast_state()
                elif hub.engine_mode == "async_hosted":
                    if hub.ai_busy_count > 0:
                        await _ws_send_json(ws, {"type": "toast", "message": "AI 正在执行浏览器操作，请稍候再关闭"})
                        await hub.broadcast_state()
                    else:
                        await hub.stop_hosted(notify_finished=True)
                else:
                    await hub.broadcast_state()
            elif mtype == "extract":
                hub.mark_active()
                if hub.engine_mode == "async_hosted":
                    clip_res = await hub.extract_content_async(data)
                    if clip_res and clip_res.get("preview"):
                        await ws.send_str(
                            json.dumps({"type": "selection_preview", "text": clip_res.get("text", "")}, ensure_ascii=False)
                        )
                    elif clip_res:
                        await ws.send_str(json.dumps({"type": "clipboard", **clip_res}, ensure_ascii=False))
                    elif data.get("mode") != "range_preview":
                        await ws.send_str(json.dumps({"type": "toast", "message": "未选中文字，请直接在文字上拖动涂抹或轻点段落"}))
                elif hub.engine_mode == "sync_external":
                    hub.sync_cmd_queue.append({"action": "extract", **data})
                else:
                    await ws.send_str(json.dumps({"type": "toast", "message": "当前浏览器未运行"}))
            elif mtype == "read_clipboard":
                hub.mark_active()
                if hub.engine_mode == "async_hosted":
                    clip_res = await hub.extract_content_async({"mode": "selection"})
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
                if not hub.takeover:
                    await ws.send_str(
                        json.dumps({"type": "toast", "message": "请先点击右上角【🖐 一键接管】"})
                    )
                    continue
                if not hub.input_queue.full():
                    await hub.input_queue.put(data)
    except asyncio.TimeoutError:
        log.debug("WS auth timeout from %s", request.remote)
    except Exception as exc:
        log.debug("WS closed (%s): %s", request.remote, exc)
    finally:
        if authenticated:
            hub.viewers.discard(ws)
            hub.viewer_meta.pop(ws, None)
            log.info("Mini App viewer disconnected (remaining=%d)", len(hub.viewers))
    return ws


async def handle_api_upload(request: web.Request) -> web.Response:
    """Authenticated multipart upload handler backing Playwright `filechooser`."""
    hub: LiveBrowserHub = request.app["hub"]
    init_data = request.headers.get("X-TG-Init-Data", "")
    bots, _, allowed = load_bot_credentials()
    ok, _info, err = verify_telegram_init_data(init_data, bots, allowed)
    if not ok:
        return web.json_response({"ok": False, "error": err or "Forbidden"}, status=403)

    query = getattr(request, "query", {}) or {}
    chooser_id = str(query.get("chooser_id") or request.headers.get("X-Chooser-Id") or "").strip()

    reader = await request.multipart()
    saved_paths: list[Path] = []
    saved_names: list[str] = []
    total_bytes = 0
    xfer_dir = hub._ensure_transfer_dir()

    try:
        while True:
            part = await reader.next()
            if part is None:
                break
            if part.name == "chooser_id":
                val = (await part.text()).strip()
                if val:
                    chooser_id = val
                continue
            if part.name != "files" and not part.filename:
                continue
            raw_fn = str(part.filename or f"upload-{len(saved_paths) + 1}.bin")
            safe_fn = Path(raw_fn).name or f"upload-{len(saved_paths) + 1}.bin"
            dest = xfer_dir / f"up-{secrets.token_hex(6)}-{safe_fn}"
            with open(dest, "wb") as fh:
                while True:
                    chunk = await part.read_chunk(65536)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > MAX_UPLOAD_BYTES:
                        fh.close()
                        dest.unlink(missing_ok=True)
                        for prev in saved_paths:
                            prev.unlink(missing_ok=True)
                        return web.json_response(
                            {
                                "ok": False,
                                "error": f"上传文件总大小超过 {MAX_UPLOAD_BYTES // (1024 * 1024)}MB 限制",
                            },
                            status=413,
                        )
                    fh.write(chunk)
            os.chmod(dest, 0o600)
            saved_paths.append(dest)
            saved_names.append(safe_fn)
    except Exception as exc:
        for prev in saved_paths:
            prev.unlink(missing_ok=True)
        return web.json_response({"ok": False, "error": f"读取上传数据失败: {exc}"}, status=400)

    if not chooser_id or chooser_id not in hub.pending_filechoosers:
        for prev in saved_paths:
            prev.unlink(missing_ok=True)
        return web.json_response({"ok": False, "error": "文件选择会话已过期或不存在"}, status=404)

    if not saved_paths:
        return web.json_response({"ok": False, "error": "未选择任何文件"}, status=400)

    entry = hub.pending_filechoosers.pop(chooser_id)
    chooser = entry["chooser"]
    multiple = bool(entry.get("multiple"))
    try:
        target_arg: Any = [str(p) for p in saved_paths] if multiple else str(saved_paths[0])
        await chooser.set_files(target_arg)
    except Exception as exc:
        for prev in saved_paths:
            prev.unlink(missing_ok=True)
        await hub.broadcast_json({"type": "filechooser_closed", "chooser_id": chooser_id})
        return web.json_response({"ok": False, "error": f"写入网页文件选择器失败: {exc}"}, status=500)

    await hub.broadcast_json({"type": "filechooser_closed", "chooser_id": chooser_id})
    hub.mark_active()
    if hub.engine_mode == "async_hosted":
        await hub._capture_once(force_broadcast=True)
        await hub.broadcast_state()
    return web.json_response({"ok": True, "files": saved_names, "total_bytes": total_bytes})


async def handle_api_download(request: web.Request) -> web.StreamResponse:
    """Authenticated download endpoint for files captured by Playwright `download` events."""
    hub: LiveBrowserHub = request.app["hub"]
    init_data = request.headers.get("X-TG-Init-Data", "")
    bots, _, allowed = load_bot_credentials()
    ok, _info, err = verify_telegram_init_data(init_data, bots, allowed)
    if not ok:
        return web.json_response({"ok": False, "error": err or "Forbidden"}, status=403)

    did = str(request.match_info.get("download_id") or "").strip()
    info = hub.downloads.get(did)
    if not info:
        return web.json_response({"ok": False, "error": "下载文件已过期或不存在"}, status=404)
    path = Path(info["path"])
    if not path.is_file():
        hub.downloads.pop(did, None)
        return web.json_response({"ok": False, "error": "下载文件已被清理"}, status=404)
    safe_name = str(info.get("filename") or path.name).replace('"', "_")
    return web.FileResponse(
        path,
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "Cache-Control": "no-store, max-age=0",
        },
    )


# ---------------- Localhost Internal IPC Endpoints ----------------


async def internal_status(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    return web.json_response({"ok": True, **hub.state_dict()})


async def internal_takeover(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        return web.json_response({"ok": False, "error": "Request body must be a JSON object"}, status=400)
    active = _parse_bool_flag(body.get("active", True))
    reason = str(body.get("reason") or "")
    await hub.set_takeover(active, reason=reason)
    return web.json_response({"ok": True, **hub.state_dict()})


async def internal_start(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    body = await request.json()
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
    try:
        st = await hub.start_hosted(
            initial_url=body.get("url"),
            bot_hint=body.get("bot"),
            notify_tg=bool(body.get("notify", True)),
            profile=body.get("profile"),
            overrides=overrides or None,
            restart=bool(body.get("restart", False)),
        )
        return web.json_response({"ok": True, **st})
    except ValueError as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=400)
    except (KeyError, FileNotFoundError) as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=404)
    except RuntimeError as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=409)
    except Exception as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=500)


async def internal_profiles_list(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    return web.json_response(
        {
            "ok": True,
            "active_profile": hub.active_profile or None,
            "profiles": list_profiles(active_profile=hub.active_profile),
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
    try:
        st = await hub.start_hosted(
            initial_url=body.get("url") or None,
            bot_hint=body.get("bot"),
            notify_tg=bool(body.get("notify", True)),
            profile=target_profile,
            restart=bool(body.get("restart", True)),
        )
        return web.json_response({"ok": True, **st})
    except ValueError as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=400)
    except (KeyError, FileNotFoundError) as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=404)
    except RuntimeError as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=409)
    except Exception as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=500)


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

    await hub.stop_hosted(notify_finished=True)
    return web.json_response({"ok": True, **hub.state_dict()})


async def internal_action(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    body = await request.json()
    try:
        res = await hub.execute_ai_action(body)
        return web.json_response(res)
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
        if hub.engine_mode == "async_hosted":
            await hub._capture_once(force_broadcast=True, hd=True)
        await hub.tg.tick_updates(force=True)
    if body.get("ensure_card"):
        bot_key = hub.resolve_bot_key(body.get("bot"))
        await hub.tg.ensure_card(bot_key, force_new=bool(body.get("force_new", False)))
    return web.json_response({"ok": True, "config": hub.config, "cards": list(hub.tg.cards.keys())})


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
    if hub.engine_mode == "async_hosted":
        await hub.stop_hosted(notify_finished=False)
    hub.engine_mode = "sync_external"
    host_pinned = discover_pinned_host_profile()
    if host_pinned is not None:
        hub.active_profile = host_pinned["name"]
        hub.active_profile_dir = Path(host_pinned["profile_dir"])
        hub.active_pinned = True
        hub.active_egress = "direct"
        hub.active_os = str(host_pinned["fingerprint"].get("os", "windows"))
        hub.active_fingerprint = {"os": hub.active_os, "persistent": True}
    hub.sync_cmd_queue.clear()
    hub.ai_status = str(body.get("ai_status") or "外部脚本运行中")
    hub.last_activity_ts = time.monotonic()
    await hub.broadcast_state()
    return web.json_response({"ok": True, "bot_key": hub.resolve_bot_key(body.get("bot"))})


async def internal_sync_push(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    jpeg = await request.read()
    q = request.query
    hub.engine_mode = "sync_external"
    hub.last_activity_ts = time.monotonic()
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

    bot_hint = q.get("bot")
    if bot_hint:
        bot_key = hub.resolve_bot_key(bot_hint)
        if bot_key not in hub.tg.cards and jpeg:
            asyncio.create_task(hub.tg.ensure_card(bot_key))

    cmds = list(hub.sync_cmd_queue)
    hub.sync_cmd_queue.clear()
    return web.json_response(
        {
            "ok": True,
            "takeover": hub.takeover,
            "takeover_reason": hub.takeover_reason,
            "commands": cmds,
        }
    )


async def internal_sync_clipboard(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    body = await request.json()
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
        hub.latest_clip = clip_obj
        await hub.broadcast_json({"type": "clipboard", **clip_obj})
    return web.json_response({"ok": True})


async def internal_sync_stop(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    if hub.engine_mode == "sync_external":
        hub.engine_mode = "idle"
        hub.takeover = False
        hub.takeover_reason = ""
        hub.active_profile = ""
        hub.active_profile_dir = None
        hub.active_pinned = False
        hub.active_egress = "direct"
        hub.active_os = ""
        hub.active_fingerprint = {}
        hub.ai_allowed_event.set()
        hub.sync_cmd_queue.clear()
        await hub.tg.tick_updates(finished=True, force=True)
        await hub.broadcast_state()
    return web.json_response({"ok": True})


def create_app() -> web.Application:
    if web is None:
        raise RuntimeError("aiohttp is required to run the Live Browser Hub server")
    cfg, local_token = ensure_local_config()
    hub = LiveBrowserHub(cfg, local_token)
    app = web.Application(client_max_size=30 * 1024 * 1024)
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
