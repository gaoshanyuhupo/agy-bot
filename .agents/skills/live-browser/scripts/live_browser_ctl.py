#!/usr/bin/env python3
"""CLI & Python SDK for AGY Live Browser Hub + SyncLiveBridge for open_google_browser()."""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Mapping
import urllib.parse

import requests


def _import_server_module() -> Any:
    scripts_dir = str(Path(__file__).resolve().parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    import live_browser_server

    return live_browser_server

CONFIG_DIR = Path(os.environ.get("AGY_LIVE_BROWSER_CONFIG_DIR", str(Path.home() / ".config/agy-live-browser")))
CONFIG_FILE = CONFIG_DIR / "config.json"
LOCAL_TOKEN_FILE = CONFIG_DIR / "local.token"
DEFAULT_BASE_URL = "http://127.0.0.1:18795"
_TAB_CMD_ID_RE = re.compile(r"^[A-Za-z0-9_:-]{1,48}$")


def _sanitize_tab_cmd_id(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    val = raw.strip()
    if not val or not _TAB_CMD_ID_RE.match(val):
        return None
    return val


def _parse_strict_int_no_ws(raw: Any) -> int | None:
    """Parse a strict ASCII integer rejecting bools, floats, leading zeros, and any whitespace."""
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        if not raw or any(ch.isspace() for ch in raw):
            return None
        digits = raw[1:] if raw.startswith("-") else raw
        if not digits or not digits.isascii() or not digits.isdigit():
            return None
        if len(digits) > 1 and digits.startswith("0"):
            return None
        try:
            return int(raw)
        except (TypeError, ValueError):
            return None
    return None


def _parse_strict_positive_int(raw: Any) -> int | None:
    """Return a strict positive integer (> 0, not bool, no whitespace) or None."""
    val = _parse_strict_int_no_ws(raw)
    return val if (val is not None and val > 0) else None


def _validate_positive_timeout(raw: Any, default: float = 600.0) -> float:
    """Validate timeout is a positive finite number (rejects bool, <=0, NaN, inf)."""
    val = default if raw is None else raw
    if isinstance(val, bool):
        raise ValueError("timeout must be a positive finite number, not bool")
    try:
        num = float(val)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid timeout: {raw!r}") from exc
    if not math.isfinite(num) or num <= 0:
        raise ValueError(f"timeout must be a positive finite number, got {raw!r}")
    return num


def resolve_tg_identity(
    *,
    explicit_user_id: Any = None,
    explicit_chat_id: Any = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Resolve Telegram caller identity for internal Live Browser requests.

    Priority: explicit args > AGY_LIVE_USER_ID > AGY_BOT_CHAT_ID.
    - Pure local CLI (no explicit args and neither env var set/non-empty) returns {}.
    - Only a strict positive integer private DM ID binds `user_id` + `chat_id` + `source="tg_cmd"`.
    - Negative group IDs (`-100...`), `"0"`, `"abc"`, whitespace, or invalid env strings NEVER
      infer a positive `user_id`; they carry `source="tg_cmd"` + raw/negative `chat_id` (or
      invalid `user_id`) so the server fails closed with HTTP 403 and never sends cards to groups.
    """
    if explicit_user_id is not None:
        uid = _parse_strict_positive_int(explicit_user_id)
        if uid is None:
            raise ValueError("user_id must be a strict positive integer")
        if explicit_chat_id is not None:
            if isinstance(explicit_chat_id, bool):
                raise ValueError("chat_id must not be a boolean")
            cid_int = _parse_strict_int_no_ws(explicit_chat_id)
            if cid_int is None:
                raise ValueError("chat_id must be a strict integer")
            return {"source": "tg_cmd", "user_id": uid, "chat_id": cid_int}
        return {"source": "tg_cmd", "user_id": uid, "chat_id": uid}

    if explicit_chat_id is not None:
        if isinstance(explicit_chat_id, bool):
            raise ValueError("chat_id must not be a boolean")
        cid_int = _parse_strict_int_no_ws(explicit_chat_id)
        if cid_int is not None and cid_int > 0:
            return {"source": "tg_cmd", "user_id": cid_int, "chat_id": cid_int}
        return {
            "source": "tg_cmd",
            "chat_id": cid_int if cid_int is not None else str(explicit_chat_id),
        }

    e = os.environ if env is None else env
    raw_env_uid = e.get("AGY_LIVE_USER_ID")
    raw_env_cid = e.get("AGY_BOT_CHAT_ID")
    has_env_uid = raw_env_uid is not None and raw_env_uid != ""
    has_env_cid = raw_env_cid is not None and raw_env_cid != ""
    if not has_env_uid and not has_env_cid:
        return {}

    if has_env_uid:
        uid = _parse_strict_positive_int(raw_env_uid)
        if uid is None:
            bad_uid = _parse_strict_int_no_ws(raw_env_uid)
            out: dict[str, Any] = {
                "source": "tg_cmd",
                "user_id": bad_uid if bad_uid is not None else str(raw_env_uid),
            }
            if has_env_cid:
                cid_parsed = _parse_strict_int_no_ws(raw_env_cid)
                out["chat_id"] = cid_parsed if cid_parsed is not None else str(raw_env_cid)
            return out
        if has_env_cid:
            cid_parsed = _parse_strict_int_no_ws(raw_env_cid)
            if cid_parsed is None or cid_parsed <= 0:
                return {
                    "source": "tg_cmd",
                    "user_id": uid,
                    "chat_id": cid_parsed if cid_parsed is not None else str(raw_env_cid),
                }
            return {"source": "tg_cmd", "user_id": uid, "chat_id": cid_parsed}
        return {"source": "tg_cmd", "user_id": uid, "chat_id": uid}

    cid_int = _parse_strict_int_no_ws(raw_env_cid)
    if cid_int is not None and cid_int > 0:
        return {"source": "tg_cmd", "user_id": cid_int, "chat_id": cid_int}
    return {
        "source": "tg_cmd",
        "chat_id": cid_int if cid_int is not None else str(raw_env_cid),
    }


_IGNORED_BOT_ENV_KEYS = frozenset(
    {"bak", "tmp", "example", "sample", "orig", "old", "swp", "dist", "disabled"}
)
_BOT_ENV_KEY_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")


def _parse_env_file_bot_key(raw_env_file: Any) -> str | None:
    """Extract canonical bridge bot key from `AGY_TG_ENV_FILE` (`.env` -> `main`, `.env.<k>` -> `<k>`)."""
    if raw_env_file is None:
        return None
    raw = str(raw_env_file)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return None
    val = raw.strip()
    if not val or val.endswith("/") or val.endswith("\\"):
        return None
    p = Path(val)
    if ".." in p.parts or any(seg == ".." for seg in re.split(r"[/\\]", val)):
        return None
    name = p.name
    if name == ".env":
        return "main"
    if name.startswith(".env.") and len(name) > 5:
        key = name[5:]
        if (
            "." not in key
            and key.lower() not in _IGNORED_BOT_ENV_KEYS
            and _BOT_ENV_KEY_RE.fullmatch(key)
        ):
            return key
    return None


def _detect_ambient_bot_identity(env: Mapping[str, str] | None = None) -> tuple[str | None, str | None]:
    """Return `(bot_key, bot_id)` of the spawning Telegram bridge process without exposing tokens."""
    e = os.environ if env is None else env
    bot_key = _parse_env_file_bot_key(e.get("AGY_TG_ENV_FILE"))
    bot_id: str | None = None
    tok = str(e.get("AGY_TG_BOT_TOKEN") or "").strip()
    if ":" in tok:
        prefix = tok.split(":", 1)[0].strip()
        if prefix.isascii() and prefix.isdigit():
            bot_id = prefix
    return bot_key, bot_id


def _detect_current_bot_hint(env: Mapping[str, str] | None = None) -> str:
    """Detect which Telegram bot spawned the current agent process without exposing tokens."""
    bot_key, bot_id = _detect_ambient_bot_identity(env=env)
    if bot_key:
        return bot_key
    if bot_id:
        return bot_id
    return "sg"


def resolve_bot_target(
    explicit_bot: Any = None,
    *,
    env: Mapping[str, str] | None = None,
) -> str:
    """Resolve target bot key/ID and fail closed on cross-bot overrides inside a Telegram bridge turn.

    - None / "" / "auto": auto-detects the spawning bot (`AGY_TG_ENV_FILE` > `AGY_TG_BOT_TOKEN` > `"sg"`).
    - Inside an active Telegram bridge turn (`AGY_BOT_CHAT_ID` or `AGY_BOT_HANDLE` set alongside
      `AGY_TG_ENV_FILE` / `AGY_TG_BOT_TOKEN`), refuses explicit `--bot <other>` overrides targeting
      a different bot so one bot can never misroute Live Cards or sessions into another bot's DM.
    - Outside Telegram bridge turns (standalone CLI/cron), explicit `--bot <key>` remains permitted.
    """
    e = os.environ if env is None else env
    env_key, env_id = _detect_ambient_bot_identity(env=e)
    req = "" if explicit_bot is None else str(explicit_bot).strip()
    if not req or req.lower() == "auto":
        return _detect_current_bot_hint(env=e)

    in_tg_turn = bool(env_key or env_id) and bool(
        str(e.get("AGY_BOT_CHAT_ID") or "").strip()
        or str(e.get("AGY_BOT_HANDLE") or "").strip()
    )
    if in_tg_turn:
        allowed_aliases = {a.lower() for a in (env_key, env_id) if a}
        req_low = req.lower()
        if req_low not in allowed_aliases:
            owner_desc = f"机器人 '{env_key}'" if env_key is not None else f"机器人 ID '{env_id}'"
            raise ValueError(
                f"安全隔离拦截：当前 Telegram 会话归属{owner_desc}，"
                f"禁止通过 --bot '{req}' 跨机器人拉起或操控浏览器；请省略 --bot（默认 auto 自动绑定当前机器人）。"
            )
    return req


def _load_hub_conn() -> tuple[str, str]:
    base = DEFAULT_BASE_URL
    if CONFIG_FILE.is_file():
        try:
            cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            host = cfg.get("host", "127.0.0.1")
            port = cfg.get("port", 18795)
            base = f"http://{host}:{port}"
        except Exception:
            pass
    tok = LOCAL_TOKEN_FILE.read_text(encoding="utf-8").strip() if LOCAL_TOKEN_FILE.is_file() else ""
    return base, tok


class LiveBrowserClient:
    """Client for controlling the persistent AsyncCamoufox Live Browser Hub."""

    def __init__(
        self,
        bot: str | None = None,
        *,
        user_id: int | str | None = None,
        chat_id: int | str | None = None,
    ) -> None:
        self.base_url, self.token = _load_hub_conn()
        self.bot = resolve_bot_target(bot)
        self._explicit_user_id: Any = None
        self._explicit_chat_id: Any = None
        if user_id is not None or chat_id is not None:
            # Validate explicit arguments immediately at construction time
            resolve_tg_identity(explicit_user_id=user_id, explicit_chat_id=chat_id)
            self._explicit_user_id = user_id
            self._explicit_chat_id = chat_id
        self.session = requests.Session()
        self.session.trust_env = False  # Always direct to 127.0.0.1

    def _identity_payload(
        self,
        *,
        user_id: Any = None,
        chat_id: Any = None,
    ) -> dict[str, Any]:
        eff_uid = user_id if user_id is not None else self._explicit_user_id
        eff_cid = chat_id if chat_id is not None else self._explicit_chat_id
        return resolve_tg_identity(explicit_user_id=eff_uid, explicit_chat_id=eff_cid)

    @property
    def user_id(self) -> int | None:
        ident = self._identity_payload()
        return _parse_strict_positive_int(ident.get("user_id"))

    @property
    def chat_id(self) -> int | str | None:
        ident = self._identity_payload()
        return ident.get("chat_id")

    def _headers(self) -> dict[str, str]:
        return {"X-Live-Token": self.token}

    def is_alive(self) -> bool:
        try:
            r = self.session.get(f"{self.base_url}/healthz", timeout=1.5)
            return r.status_code == 200
        except Exception:
            return False

    def yield_lock_if_idle(self) -> bool:
        if not self.token:
            return False
        try:
            r = self.session.post(
                f"{self.base_url}/internal/yield-lock",
                headers=self._headers(),
                timeout=8.0,
            )
            return r.status_code == 200 and bool(r.json().get("ok"))
        except Exception:
            return False

    def status(self, *, user_id: Any = None, chat_id: Any = None) -> dict[str, Any]:
        ident = self._identity_payload(user_id=user_id, chat_id=chat_id)
        kwargs: dict[str, Any] = {"headers": self._headers(), "timeout": 5.0}
        if ident:
            kwargs["params"] = {"bot": self.bot, **ident}
        r = self.session.get(f"{self.base_url}/internal/status", **kwargs)
        r.raise_for_status()
        return r.json()

    def start(
        self,
        url: str | None = None,
        notify: bool = True,
        *,
        profile: str | None = None,
        os_name: str | None = None,
        locale: str | None = None,
        window: list[int] | str | None = None,
        mobile: bool = False,
        webgl_config: list[str] | str | None = None,
        block_webrtc: bool | None = None,
        geoip: bool | str | None = None,
        proxy: str | dict[str, str] | None = None,
        proxy_bao_ref: str | None = None,
        ephemeral: bool = False,
        restart: bool = False,
        allow_override: Any = False,
        user_id: Any = None,
        chat_id: Any = None,
        expected_session_gen: int | None = None,
    ) -> dict[str, Any]:
        ident = self._identity_payload(user_id=user_id, chat_id=chat_id)
        payload: dict[str, Any] = {"url": url, "bot": self.bot, "notify": notify, **ident}
        if expected_session_gen is not None:
            payload["expected_session_gen"] = expected_session_gen
        if profile is not None:
            payload["profile"] = profile
        if os_name is not None:
            payload["os"] = os_name
        if locale is not None:
            payload["locale"] = locale
        if window is not None:
            payload["window"] = window
        if mobile:
            payload["mobile"] = True
        if webgl_config is not None:
            payload["webgl_config"] = webgl_config
        if block_webrtc is not None:
            payload["block_webrtc"] = block_webrtc
        if geoip is not None:
            payload["geoip"] = geoip
        if proxy is not None:
            payload["proxy"] = proxy
        if proxy_bao_ref is not None:
            payload["proxy_bao_ref"] = proxy_bao_ref
        if ephemeral:
            payload["ephemeral"] = True
        if restart:
            payload["restart"] = True
        if allow_override is not False:
            payload["allow_override"] = allow_override
        r = self.session.post(
            f"{self.base_url}/internal/start",
            headers=self._headers(),
            json=payload,
            timeout=65.0,
        )
        return r.json()

    def list_profiles(self) -> dict[str, Any]:
        ident = self._identity_payload()
        if self.is_alive() and self.token:
            kwargs: dict[str, Any] = {"headers": self._headers(), "timeout": 5.0}
            if ident:
                kwargs["params"] = {"bot": self.bot, **ident}
            r = self.session.get(f"{self.base_url}/internal/profiles", **kwargs)
            return r.json()
        raw_env_scope = (
            str(os.environ.get("AGY_BOT_CHAT_SCOPE") or os.environ.get("AGY_CHAT_SCOPE") or "").strip().lower()
        )
        raw_ident_scope = str(ident.get("chat_scope") or "").strip().lower()
        raw_env_cid = os.environ.get("AGY_BOT_CHAT_ID")
        has_env_non_dm_cid = (
            raw_env_cid is not None
            and raw_env_cid != ""
            and _parse_strict_positive_int(raw_env_cid) is None
        )
        is_group_or_non_dm = (
            raw_env_scope in ("group", "supergroup", "channel")
            or raw_ident_scope in ("group", "supergroup", "channel")
            or has_env_non_dm_cid
            or (
                bool(ident)
                and (
                    _parse_strict_positive_int(ident.get("user_id")) is None
                    or (
                        ident.get("chat_id") is not None
                        and _parse_strict_positive_int(ident.get("chat_id")) is None
                    )
                )
            )
        )
        if is_group_or_non_dm:
            return {"ok": True, "active_profile": None, "profiles": []}
        srv = _import_server_module()

        return {"ok": True, "active_profile": None, "profiles": srv.list_profiles()}

    def create_profile(self, name: str, overwrite: bool = False, **kwargs: Any) -> dict[str, Any]:
        payload = {"name": name, "overwrite": overwrite, **{k: v for k, v in kwargs.items() if v is not None}}
        if self.is_alive() and self.token:
            r = self.session.post(
                f"{self.base_url}/internal/profiles",
                headers=self._headers(),
                json=payload,
                timeout=10.0,
            )
            return r.json()
        srv = _import_server_module()

        prof = srv.create_profile(name, kwargs, overwrite=overwrite)
        return {"ok": True, "profile": prof}

    def delete_profile(self, name: str) -> dict[str, Any]:
        if self.is_alive() and self.token:
            safe_name = urllib.parse.quote(name, safe="")
            r = self.session.delete(
                f"{self.base_url}/internal/profiles/{safe_name}",
                headers=self._headers(),
                timeout=10.0,
            )
            return r.json()
        srv = _import_server_module()

        return srv.delete_profile(name)

    def stop(
        self,
        *,
        force: bool = False,
        user_id: Any = None,
        chat_id: Any = None,
        expected_session_gen: int | None = None,
    ) -> dict[str, Any]:
        ident = self._identity_payload(user_id=user_id, chat_id=chat_id)
        req_kwargs: dict[str, Any] = {"headers": self._headers(), "timeout": 20.0}
        if ident or force or expected_session_gen is not None:
            body: dict[str, Any] = {"bot": self.bot, **ident}
            if force:
                body["force"] = True
            if expected_session_gen is not None:
                body["expected_session_gen"] = expected_session_gen
            req_kwargs["json"] = body
        r = self.session.post(f"{self.base_url}/internal/stop", **req_kwargs)
        return r.json()

    def action(
        self,
        action: str,
        timeout_http: float = 120.0,
        *,
        expected_session_gen: int | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        call_uid = kwargs.pop("user_id", None)
        call_cid = kwargs.pop("chat_id", None)
        ident = self._identity_payload(user_id=call_uid, chat_id=call_cid)
        payload: dict[str, Any] = {"action": action, "bot": self.bot, **ident, **kwargs}
        if expected_session_gen is not None:
            payload["expected_session_gen"] = expected_session_gen
        if action == "wait_human" and "timeout" in payload and payload["timeout"] is not None:
            payload["timeout"] = _validate_positive_timeout(payload["timeout"])
        r = self.session.post(
            f"{self.base_url}/internal/action",
            headers=self._headers(),
            json=payload,
            timeout=timeout_http,
        )
        return r.json()

    def update_config(self, **kwargs: Any) -> dict[str, Any]:
        call_uid = kwargs.pop("user_id", None)
        call_cid = kwargs.pop("chat_id", None)
        ident = self._identity_payload(user_id=call_uid, chat_id=call_cid)
        payload: dict[str, Any] = {"bot": self.bot, **ident, **kwargs}
        r = self.session.post(
            f"{self.base_url}/internal/config",
            headers=self._headers(),
            json=payload,
            timeout=15.0,
        )
        return r.json()


# ---------------- Cooperative Sync Bridge for `open_google_browser()` ----------------


class SyncLiveBridge:
    """Wraps a sync Playwright BrowserContext to stream frames & honor human takeover."""

    def __init__(
        self,
        raw_ctx: Any,
        bot_hint: str | None = None,
        notify: bool | None = None,
        user_id: int | None = None,
        profile_dir: str | Path | None = None,
        pinned_launch: bool = False,
        chat_id: int | None = None,
        allow_google: bool = False,
        profile_name: str | None = None,
    ) -> None:
        self.raw_ctx = raw_ctx
        self.client = LiveBrowserClient(bot=bot_hint, user_id=user_id, chat_id=chat_id)
        self.notify = (os.environ.get("AGY_LIVE_NOTIFY", "1") != "0") if notify is None else notify
        self.enabled = self.client.is_alive() and bool(self.client.token)
        self.active_idx = 0
        self._in_checkpoint = False
        self._held_buttons: dict[str, Any] = {}
        self._acked_tab_cmds: list[str] = []
        self._rejected_tab_cmds: list[str] = []
        self._pinned_verified: bool = False
        self._allow_google_verified: bool = False
        self._profile_name: str | None = str(profile_name).strip() if profile_name else None
        self._profile_dir: Path | None = Path(profile_dir) if profile_dir is not None else None
        self._sync_lease_id: str | None = None
        self._sync_session_gen: int | None = None
        self._x11_display: str | None = self._resolve_display()
        self._last_clip: str = self._read_x11_clip()
        if self.enabled:
            try:
                ident = self.client._identity_payload()
                start_body: dict[str, Any] = {
                    "bot": self.client.bot,
                    "ai_status": "已启动同步浏览器会话",
                    **ident,
                }
                if ident and _parse_strict_positive_int(ident.get("user_id")) is None:
                    # Group / non-private / invalid TG identity: never send live cards
                    self.notify = False
                if profile_dir is not None:
                    start_body["profile_dir"] = str(profile_dir)
                if self._profile_name:
                    start_body["profile"] = self._profile_name
                if pinned_launch:
                    start_body["pinned_launch"] = True
                if allow_google is True:
                    start_body["allow_google"] = True
                resp = self.client.session.post(
                    f"{self.client.base_url}/internal/sync/start",
                    headers=self.client._headers(),
                    json=start_body,
                    timeout=3.0,
                )
                status_code = getattr(resp, "status_code", 200)
                start_data = resp.json() if hasattr(resp, "json") else {}
                if status_code >= 400 or (isinstance(start_data, dict) and start_data.get("ok") is False):
                    self.enabled = False
                elif isinstance(start_data, dict):
                    self._sync_lease_id = start_data.get("sync_lease_id")
                    self._sync_session_gen = start_data.get("session_gen")
                    self._pinned_verified = bool(start_data.get("pinned_verified"))
                    self._allow_google_verified = bool(start_data.get("allow_google_verified"))
            except Exception:
                self.enabled = False

    def _sync_headers(self) -> dict[str, str]:
        hdrs = dict(self.client._headers())
        lease_id = getattr(self, "_sync_lease_id", None)
        if lease_id:
            hdrs["X-Sync-Lease-Id"] = str(lease_id)
        return hdrs

    def close(self) -> None:
        self._release_held_buttons_sync()
        if not self.enabled:
            return
        try:
            self.sync_checkpoint(ai_status="会话即将完成", allow_takeover_loop=False)
            self._release_held_buttons_sync()
            stop_body: dict[str, Any] = {}
            if self._sync_lease_id:
                stop_body["lease_id"] = self._sync_lease_id
            if self._sync_session_gen is not None:
                stop_body["session_gen"] = self._sync_session_gen
            self.client.session.post(
                f"{self.client.base_url}/internal/sync/stop",
                headers=self._sync_headers(),
                json=stop_body,
                timeout=5.0,
            )
        except Exception:
            pass
        finally:
            self._release_held_buttons_sync()
            self._clear_acked_tab_cmds()
            self.enabled = False

    def _record_acked_tab_cmd(self, raw_cmd_id: Any) -> None:
        clean = _sanitize_tab_cmd_id(raw_cmd_id)
        if not clean:
            return
        acked = getattr(self, "_acked_tab_cmds", None)
        if acked is None:
            acked = []
            self._acked_tab_cmds = acked
        if clean not in acked:
            acked.append(clean)
            if len(acked) > 32:
                del acked[:-32]

    def _record_rejected_tab_cmd(self, raw_cmd_id: Any) -> None:
        clean = _sanitize_tab_cmd_id(raw_cmd_id)
        if not clean:
            return
        acked = getattr(self, "_acked_tab_cmds", None)
        if isinstance(acked, list):
            try:
                acked.remove(clean)
            except ValueError:
                pass
        rejected = getattr(self, "_rejected_tab_cmds", None)
        if rejected is None:
            rejected = []
            self._rejected_tab_cmds = rejected
        if clean not in rejected:
            rejected.append(clean)
            if len(rejected) > 32:
                del rejected[:-32]

    def _clear_acked_tab_cmds(self) -> None:
        acked = getattr(self, "_acked_tab_cmds", None)
        if isinstance(acked, list):
            acked.clear()
        rejected = getattr(self, "_rejected_tab_cmds", None)
        if isinstance(rejected, list):
            rejected.clear()

    def _active_raw_page(self) -> Any | None:
        pages = list(self.raw_ctx.pages)
        if not pages:
            return None
        if self.active_idx >= len(pages):
            self.active_idx = len(pages) - 1
        if self.active_idx < 0:
            self.active_idx = 0
        return pages[self.active_idx]

    def _resolve_display(self) -> str | None:
        close_fn = getattr(self.raw_ctx, "close", None)
        for cell in getattr(close_fn, "__closure__", None) or ():
            try:
                val = cell.cell_contents
            except ValueError:
                continue
            disp_num = getattr(val, "_display", None)
            if isinstance(disp_num, int):
                return f":{disp_num}"
        return None

    def _read_x11_clip(self) -> str:
        xclip = shutil.which("xclip") or "/usr/bin/xclip"
        if not self._x11_display or not os.path.isfile(xclip):
            return ""
        try:
            r = subprocess.run(
                [xclip, "-o", "-selection", "clipboard", "-t", "UTF8_STRING"],
                env={"DISPLAY": self._x11_display, "PATH": "/usr/bin:/bin"},
                capture_output=True,
                timeout=0.4,
            )
            if r.returncode == 0:
                return r.stdout.decode("utf-8", errors="replace")[:25000]
        except Exception:
            pass
        return ""

    def _push_clip(self, payload: dict[str, Any]) -> None:
        if not self.enabled or (not payload.get("text") and not payload.get("preview")):
            return
        try:
            body = dict(payload)
            lease_id = getattr(self, "_sync_lease_id", None)
            if lease_id:
                body["lease_id"] = lease_id
            sync_sgen = getattr(self, "_sync_session_gen", None)
            if sync_sgen is not None:
                body["session_gen"] = sync_sgen
            resp = self.client.session.post(
                f"{self.client.base_url}/internal/sync/clipboard",
                headers=self._sync_headers(),
                json=body,
                timeout=2.5,
            )
            if getattr(resp, "status_code", 200) in (409, 410):
                self._release_held_buttons_sync()
                self.enabled = False
        except Exception:
            pass

    def sync_checkpoint(
        self,
        ai_status: str = "",
        cursor: tuple[float, float, str] | None = None,
        allow_takeover_loop: bool = True,
        takeover_timeout: float | None = None,
    ) -> bool:
        """Push current frame & process human commands. Returns True iff exited due to takeover_timeout."""
        validated_timeout: float | None = None
        if takeover_timeout is not None:
            validated_timeout = _validate_positive_timeout(takeover_timeout)
        if not self.enabled or self._in_checkpoint:
            return False
        deadline = (time.monotonic() + validated_timeout) if validated_timeout is not None else None
        timed_out = False
        self._in_checkpoint = True
        try:
            while True:
                page = self._active_raw_page()
                if not page:
                    break
                try:
                    jpeg = page.screenshot(type="jpeg", quality=56, animations="allow", timeout=2500)
                except Exception:
                    jpeg = b""

                pages = list(self.raw_ctx.pages)
                tabs = []
                for i, p in enumerate(pages):
                    try:
                        t = p.title()
                    except Exception:
                        t = ""
                    tabs.append(
                        {"index": i, "title": t or p.url or f"Tab {i + 1}", "url": p.url, "active": i == self.active_idx}
                    )

                vw, vh = 1280, 800
                vp = page.viewport_size
                if vp and vp.get("width") and vp.get("height"):
                    vw, vh = int(vp["width"]), int(vp["height"])
                else:
                    try:
                        dims = page.evaluate("() => ({w: window.innerWidth, h: window.innerHeight})")
                        if dims and dims.get("w") and dims.get("h"):
                            vw, vh = int(dims["w"]), int(dims["h"])
                    except Exception:
                        pass

                params: dict[str, str] = {
                    "bot": self.client.bot if self.notify else "",
                    "url": page.url,
                    "title": tabs[self.active_idx]["title"] if tabs else "",
                    "vw": str(vw),
                    "vh": str(vh),
                    "ai_status": ai_status,
                    "tabs": json.dumps(tabs, ensure_ascii=False),
                }
                lease_id = getattr(self, "_sync_lease_id", None)
                if lease_id:
                    params["lease_id"] = str(lease_id)
                sync_sgen = getattr(self, "_sync_session_gen", None)
                if sync_sgen is not None:
                    params["session_gen"] = str(sync_sgen)
                if cursor:
                    params["cx"] = str(cursor[0])
                    params["cy"] = str(cursor[1])
                    params["actor"] = cursor[2]
                acked_snap = list(getattr(self, "_acked_tab_cmds", None) or []) if jpeg else []
                if acked_snap:
                    params["ack_tab_cmds"] = ",".join(acked_snap)
                rejected_snap = list(getattr(self, "_rejected_tab_cmds", None) or [])
                if rejected_snap:
                    params["reject_tab_cmds"] = ",".join(rejected_snap)

                qs = urllib.parse.urlencode(params)
                resp = self.client.session.post(
                    f"{self.client.base_url}/internal/sync/push?{qs}",
                    headers={**self._sync_headers(), "Content-Type": "image/jpeg"},
                    data=jpeg,
                    timeout=4.0,
                )
                status_code = getattr(resp, "status_code", 200)
                if status_code in (409, 410):
                    self._release_held_buttons_sync()
                    self._clear_acked_tab_cmds()
                    self.enabled = False
                    break
                data = resp.json()
                if isinstance(data, dict) and data.get("ok") is False:
                    self._release_held_buttons_sync()
                    self._clear_acked_tab_cmds()
                    self.enabled = False
                    break
                if acked_snap:
                    cur_acked = getattr(self, "_acked_tab_cmds", None)
                    if isinstance(cur_acked, list):
                        for cid in acked_snap:
                            try:
                                cur_acked.remove(cid)
                            except ValueError:
                                pass
                if rejected_snap:
                    cur_rejected = getattr(self, "_rejected_tab_cmds", None)
                    if isinstance(cur_rejected, list):
                        for cid in rejected_snap:
                            try:
                                cur_rejected.remove(cid)
                            except ValueError:
                                pass
                cur_clip = self._read_x11_clip()
                if cur_clip and cur_clip != self._last_clip:
                    self._last_clip = cur_clip
                    self._push_clip({"text": cur_clip, "source": "网页复制按钮 / Ctrl+C"})
                resp_lease = data.get("sync_lease_id")
                if lease_id and resp_lease is not None and str(resp_lease) != str(lease_id):
                    self._release_held_buttons_sync()
                    self.enabled = False
                    break
                is_takeover = bool(data.get("takeover"))
                resp_sgen = data.get("session_gen")
                resp_tgen = data.get("takeover_gen")
                if sync_sgen is not None and resp_sgen is not None:
                    try:
                        if int(resp_sgen) != int(sync_sgen):
                            self._release_held_buttons_sync()
                            self.enabled = False
                            break
                    except (TypeError, ValueError):
                        self._release_held_buttons_sync()
                        self.enabled = False
                        break
                cmds = data.get("commands") or []
                for cmd in cmds:
                    if not self.enabled:
                        self._release_held_buttons_sync()
                        break
                    act = cmd.get("action")
                    cmd_sgen = cmd.get("session_gen")
                    cmd_tgen = cmd.get("takeover_gen")
                    if resp_sgen is not None:
                        if cmd_sgen is None or isinstance(cmd_sgen, bool):
                            continue
                        try:
                            if int(cmd_sgen) != int(resp_sgen):
                                continue
                        except (TypeError, ValueError):
                            continue
                    # Strictly honor takeover barrier & generation binding:
                    # once takeover is released or takeover_gen changed, only run cleanup `mouseup`
                    # or read-only `extract`; discard stale/unstamped mutating commands.
                    is_cleanup_up = act == "mouseup" and (bool(cmd.get("cleanup")) or not is_takeover)
                    if act not in ("mouseup", "extract"):
                        if not is_takeover:
                            continue
                        if resp_tgen is not None:
                            if cmd_tgen is None or isinstance(cmd_tgen, bool):
                                continue
                            try:
                                if int(cmd_tgen) != int(resp_tgen):
                                    continue
                            except (TypeError, ValueError):
                                continue
                    elif act == "mouseup" and not is_cleanup_up:
                        if resp_tgen is not None:
                            if cmd_tgen is None or isinstance(cmd_tgen, bool):
                                continue
                            try:
                                if int(cmd_tgen) != int(resp_tgen):
                                    continue
                            except (TypeError, ValueError):
                                continue
                    cursor = self._exec_human_sync(cmd)
                if not is_takeover or not self.enabled:
                    self._release_held_buttons_sync()
                if not allow_takeover_loop or not is_takeover or not self.enabled:
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    timed_out = True
                    self._release_held_buttons_sync()
                    break
                ai_status = "人工接管中（脚本已挂起等待）"
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        self._release_held_buttons_sync()
                        break
                    time.sleep(min(0.09, remaining))
                else:
                    time.sleep(0.09)
        except Exception:
            if not self.enabled:
                self._release_held_buttons_sync()
        finally:
            if not self.enabled:
                self._release_held_buttons_sync()
            self._in_checkpoint = False
        return timed_out

    @staticmethod
    def _is_raw_page_closed(page: Any) -> bool:
        fn = getattr(page, "is_closed", None)
        if callable(fn):
            try:
                return bool(fn())
            except Exception:
                return False
        return bool(fn) if fn is not None else False

    def _is_sync_google_nav_blocked(self, url: str) -> bool:
        """Enforce non-pinned / unauthorized Google domain navigation block matching hosted policy."""
        if getattr(self, "_pinned_verified", False):
            return False
        try:
            script_dir = str(Path(__file__).resolve().parent)
            if script_dir not in sys.path:
                sys.path.insert(0, script_dir)
            import live_browser_server as _srv  # type: ignore[import-not-found]

            try:
                _srv.enforce_google_profile_policy(
                    url,
                    is_pinned=False,
                    allow_google=bool(getattr(self, "_allow_google_verified", False)),
                    profile_name=getattr(self, "_profile_name", None),
                    profile_dir=getattr(self, "_profile_dir", None),
                )
                return False
            except ValueError:
                return True
        except Exception:
            # Fail-closed regex fallback matching live_browser_server._GOOGLE_HOST_RE
            import re as _re

            host = (urllib.parse.urlparse(url).hostname or "").lower()
            is_g = bool(
                _re.match(
                    r"^(?:[a-z0-9-]+\.)*(?:"
                    r"google\.[a-z]{2,3}(?:\.[a-z]{2})?|"
                    r"gmail\.com|googlemail\.com|"
                    r"youtube\.com|youtu\.be|"
                    r"googleapis\.com|googleusercontent\.com|gstatic\.com|googlevideo\.com|withgoogle\.com|"
                    r"g\.co|goo\.gl"
                    r")$",
                    host,
                )
            )
            return is_g and (os.environ.get("AGY_LIVE_BROWSER_REQUIRE_PINNED", "").strip() == "1")

    def _release_held_buttons_sync(self) -> None:
        held = getattr(self, "_held_buttons", None)
        if not held:
            return
        if isinstance(held, dict):
            entries = list(held.items())
            held.clear()
        else:
            fallback_page = self._active_raw_page()
            entries = [(btn, fallback_page) for btn in list(held)]
            held.clear()
        for btn, orig_page in entries:
            target_page = orig_page if orig_page is not None else self._active_raw_page()
            if target_page is None or self._is_raw_page_closed(target_page):
                continue
            try:
                target_page.mouse.up(button=btn)
            except Exception:
                pass

    def _exec_human_sync(self, cmd: dict[str, Any]) -> tuple[float, float, str] | None:
        page = self._active_raw_page()
        if not page:
            if cmd.get("action") in ("switch_tab", "new_tab", "close_tab"):
                self._record_rejected_tab_cmd(cmd.get("cmd_id"))
            return None
        held = getattr(self, "_held_buttons", None)
        if held is None:
            held = {}
            self._held_buttons = held
        act = cmd.get("action")
        orig_page = page
        cursor_out: tuple[float, float, str] | None = None
        try:
            if act == "move":
                x, y = float(cmd.get("x", 0)), float(cmd.get("y", 0))
                cursor_out = (x, y, "human")
                page.mouse.move(x, y)
            elif act == "mousedown":
                x, y = float(cmd.get("x", 0)), float(cmd.get("y", 0))
                btn = str(cmd.get("button") or "left")
                if btn not in ("left", "right", "middle"):
                    btn = "left"
                cursor_out = (x, y, "human")
                # If this same button is already recorded as held on another page, release that
                # original page first (if still open) so overwriting `held[btn]` never strands it!
                if isinstance(held, dict):
                    prev_page = held.get(btn)
                    if prev_page is not None and prev_page is not page:
                        held.pop(btn, None)
                        if not self._is_raw_page_closed(prev_page):
                            try:
                                prev_page.mouse.up(button=btn)
                            except Exception:
                                pass
                page.mouse.move(x, y)
                if isinstance(held, dict):
                    held[btn] = page
                else:
                    held.add(btn)
                page.mouse.down(button=btn)
            elif act == "mouseup":
                x, y = float(cmd.get("x", 0)), float(cmd.get("y", 0))
                btn = str(cmd.get("button") or "left")
                if btn not in ("left", "right", "middle"):
                    btn = "left"
                cursor_out = (x, y, "human")
                orig_page = held.pop(btn, None) if isinstance(held, dict) else None
                if not isinstance(held, dict):
                    held.discard(btn)
                if orig_page is not None and orig_page is not page:
                    # Button was originally pressed on another page: release ONLY on that page if
                    # still open; if the original page is already closed, drop the stale record and
                    # NEVER fall back to sending mouse.up to an unrelated current page!
                    if not self._is_raw_page_closed(orig_page):
                        orig_page.mouse.up(button=btn)
                elif orig_page is None and cmd.get("cleanup"):
                    # Server-internal cleanup for a button not currently held: no-op
                    pass
                else:
                    page.mouse.move(x, y)
                    page.mouse.up(button=btn)
            elif act == "rightclick":
                x, y = float(cmd.get("x", 0)), float(cmd.get("y", 0))
                cursor_out = (x, y, "human")
                page.mouse.click(x, y, button="right")
            elif act in ("click", "dblclick"):
                x, y = float(cmd.get("x", 0)), float(cmd.get("y", 0))
                cursor_out = (x, y, "human")
                if act == "dblclick":
                    page.mouse.dblclick(x, y)
                else:
                    try:
                        click_count = max(1, min(3, int(cmd.get("click_count") or 1)))
                    except (TypeError, ValueError):
                        click_count = 1
                    btn = str(cmd.get("button") or "left")
                    if btn not in ("left", "right", "middle"):
                        btn = "left"
                    if click_count == 1 and btn == "left":
                        page.mouse.click(x, y)
                    else:
                        page.mouse.click(x, y, button=btn, click_count=click_count)
            elif act == "wheel":
                page.mouse.wheel(float(cmd.get("dx", 0)), float(cmd.get("dy", 0)))
            elif act == "type":
                txt = str(cmd.get("text", ""))
                if cmd.get("replace"):
                    page.keyboard.press("Control+A")
                    page.keyboard.press("Backspace")
                if txt:
                    if txt.isascii() and len(txt) <= 64:
                        page.keyboard.type(txt, delay=15)
                    else:
                        page.keyboard.insert_text(txt)
                if cmd.get("submit"):
                    page.keyboard.press("Enter")
            elif act == "press":
                k = str(cmd.get("key", ""))
                if k:
                    page.keyboard.press(k)
            elif act == "clear_field":
                page.keyboard.press("Control+A")
                page.keyboard.press("Backspace")
            elif act == "goto":
                u = str(cmd.get("url", "")).strip()
                if u and not self._is_sync_google_nav_blocked(u):
                    page.goto(u, wait_until="domcontentloaded", timeout=45000)
            elif act == "back":
                page.go_back(wait_until="domcontentloaded", timeout=15000)
            elif act == "forward":
                page.go_forward(wait_until="domcontentloaded", timeout=15000)
            elif act == "reload":
                page.reload(wait_until="domcontentloaded", timeout=30000)
            elif act == "switch_tab":
                idx = int(cmd.get("index", 0))
                pages_now = list(self.raw_ctx.pages)
                if 0 <= idx < len(pages_now):
                    target_page = pages_now[idx]
                    if target_page is not page:
                        self._release_held_buttons_sync()
                    try:
                        target_page.bring_to_front()
                    except Exception:
                        pages_fb = list(self.raw_ctx.pages)
                        if orig_page in pages_fb:
                            self.active_idx = pages_fb.index(orig_page)
                        raise
                    pages_after = list(self.raw_ctx.pages)
                    if target_page in pages_after:
                        self.active_idx = pages_after.index(target_page)
                        self._record_acked_tab_cmd(cmd.get("cmd_id"))
                    else:
                        if orig_page in pages_after:
                            self.active_idx = pages_after.index(orig_page)
                        self._record_rejected_tab_cmd(cmd.get("cmd_id"))
                else:
                    self._record_acked_tab_cmd(cmd.get("cmd_id"))
            elif act == "new_tab":
                self._release_held_buttons_sync()
                np = self.raw_ctx.new_page()
                try:
                    np.goto("about:blank", wait_until="domcontentloaded", timeout=30000)
                except Exception:
                    pages_fb = list(self.raw_ctx.pages)
                    if orig_page in pages_fb:
                        self.active_idx = pages_fb.index(orig_page)
                    raise
                pages_after = list(self.raw_ctx.pages)
                if np in pages_after:
                    self.active_idx = pages_after.index(np)
                    self._record_acked_tab_cmd(cmd.get("cmd_id"))
                else:
                    if orig_page in pages_after:
                        self.active_idx = pages_after.index(orig_page)
                    self._record_rejected_tab_cmd(cmd.get("cmd_id"))
            elif act == "close_tab":
                idx = int(cmd.get("index", -1))
                pages_now = list(self.raw_ctx.pages)
                if len(pages_now) > 1 and 0 <= idx < len(pages_now):
                    self._release_held_buttons_sync()
                    pages_now[idx].close()
                    self.active_idx = max(0, min(self.active_idx, len(self.raw_ctx.pages) - 1))
                self._record_acked_tab_cmd(cmd.get("cmd_id"))
            elif act == "extract":
                mode = str(cmd.get("mode") or "point")
                req_id = cmd.get("req_id")
                cmd_sgen = cmd.get("session_gen")
                cmd_tgen = cmd.get("takeover_gen")

                def _emit_extract(payload_dict: dict[str, Any]) -> None:
                    out_p = dict(payload_dict)
                    if req_id:
                        out_p["req_id"] = str(req_id)
                    if cmd_sgen is not None:
                        out_p["session_gen"] = cmd_sgen
                    if cmd_tgen is not None:
                        out_p["takeover_gen"] = cmd_tgen
                    self._push_clip(out_p)

                if mode == "page":
                    txt = page.evaluate("() => (document.body && document.body.innerText || '').trim().slice(0, 25000)")
                    if txt:
                        _emit_extract({"text": txt, "source": "整页可见文字"})
                elif mode == "url":
                    _emit_extract({"text": page.url, "href": page.url, "source": "当前网页网址"})
                elif mode == "selection":
                    sel_txt = page.evaluate(
                        """() => {
                            const ae = document.activeElement;
                            if (ae && ae.nodeType === 1) {
                                const tag = (ae.tagName || '').toUpperCase();
                                if (tag === 'INPUT' || tag === 'TEXTAREA') {
                                    const tp = (ae.type || 'text').toLowerCase();
                                    const ac = ((ae.getAttribute && ae.getAttribute('autocomplete')) || '').toLowerCase();
                                    const nm = ((ae.name || '') + ' ' + (ae.id || '')).toLowerCase();
                                    const isSensitive = tp === 'password' || ac.includes('password') || ac.includes('cc-') || ac.includes('one-time-code') || /\\b(otp|cvv|cvc|passcode|pin|card[-_]?num)\\b/.test(nm);
                                    if (isSensitive) return '';
                                }
                            }
                            return (window.getSelection && window.getSelection().toString() || '').trim().slice(0, 25000);
                        }"""
                    )
                    if sel_txt:
                        _emit_extract(
                            {
                                "text": sel_txt,
                                "href": page.url,
                                "source": f"网页已选中文字 ({len(sel_txt)}字)",
                            }
                        )
                elif mode in ("range", "range_preview"):
                    x1, y1 = float(cmd.get("x1", 0)), float(cmd.get("y1", 0))
                    x2, y2 = float(cmd.get("x2", 0)), float(cmd.get("y2", 0))
                    range_txt = page.evaluate(
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
                            if (isSensitiveEl(document.elementFromPoint(x1, y1)) || isSensitiveEl(document.elementFromPoint(x2, y2))) {
                                return '';
                            }
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
                            if (!c1 || !c2) return '';
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
                                return (sel.toString() || '').trim().slice(0, 20000);
                            } catch (_) {
                                return '';
                            }
                        }""",
                        {"x1": x1, "y1": y1, "x2": x2, "y2": y2},
                    )
                    cleaned_rt = str(range_txt or "").strip()
                    if mode == "range_preview":
                        prev_body: dict[str, Any] = {"preview": True, "text": cleaned_rt}
                        if "extract_gen" in cmd:
                            prev_body["extract_gen"] = cmd["extract_gen"]
                        _emit_extract(prev_body)
                    elif cleaned_rt:
                        _emit_extract(
                            {
                                "text": cleaned_rt,
                                "source": f"涂抹选定 ({len(cleaned_rt)}字)",
                            }
                        )
                else:
                    x, y = float(cmd.get("x", 0)), float(cmd.get("y", 0))
                    ext = page.evaluate(
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
                                return val ? { text: val.slice(0, 20000), blockText: '', href: '', source: '输入框内容' } : null;
                            }
                            const linkEl = el.closest('a[href]');
                            const href = linkEl ? String(linkEl.href || '') : '';
                            const codeEl = el.closest('code, pre, samp, kbd');
                            if (codeEl && (codeEl.innerText || '').trim()) {
                                return {
                                    text: codeEl.innerText.trim().slice(0, 20000),
                                    blockText: '',
                                    href: href.slice(0, 4000),
                                    source: `<${codeEl.tagName.toLowerCase()}> 代码块`
                                };
                            }
                            // Container-margin guard (parity with hosted extract_content_async): avoid grabbing huge wrapper containers!
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
                                source: `点选段落 <${bestTag}>`
                            };
                        }""",
                        {"x": x, "y": y},
                    )
                    if ext:
                        _emit_extract(ext)
        except Exception:
            if act in ("switch_tab", "new_tab", "close_tab"):
                cur_page = self._active_raw_page()
                if cur_page is orig_page and not self._is_raw_page_closed(orig_page):
                    self._record_rejected_tab_cmd(cmd.get("cmd_id"))
                elif cur_page is not None:
                    self._record_acked_tab_cmd(cmd.get("cmd_id"))
        return cursor_out


class WrappedSyncLocator:
    _HOOKED = {"click", "dblclick", "fill", "type", "press", "check", "uncheck", "select_option", "tap"}

    def __init__(self, raw_loc: Any, bridge: SyncLiveBridge) -> None:
        self._raw = raw_loc
        self._bridge = bridge
        if hasattr(raw_loc, "_impl_obj"):
            self._impl_obj = raw_loc._impl_obj

    @property
    def first(self) -> "WrappedSyncLocator":
        return WrappedSyncLocator(self._raw.first, self._bridge)

    @property
    def last(self) -> "WrappedSyncLocator":
        return WrappedSyncLocator(self._raw.last, self._bridge)

    def nth(self, index: int) -> "WrappedSyncLocator":
        return WrappedSyncLocator(self._raw.nth(index), self._bridge)

    def locator(self, *args: Any, **kwargs: Any) -> "WrappedSyncLocator":
        return WrappedSyncLocator(self._raw.locator(*args, **kwargs), self._bridge)

    def filter(self, *args: Any, **kwargs: Any) -> "WrappedSyncLocator":
        return WrappedSyncLocator(self._raw.filter(*args, **kwargs), self._bridge)

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._raw, name)
        if name in self._HOOKED and callable(attr):
            def _wrapped(*args: Any, **kwargs: Any) -> Any:
                self._bridge.sync_checkpoint(ai_status=f"准备执行: {name}")
                res = attr(*args, **kwargs)
                self._bridge.sync_checkpoint(ai_status=f"已执行: {name}")
                return res
            return _wrapped
        return attr


class WrappedSyncPage:
    _HOOKED = {"goto", "click", "dblclick", "fill", "type", "press", "check", "uncheck", "select_option", "reload", "go_back", "go_forward"}

    def __init__(self, raw_page: Any, bridge: SyncLiveBridge) -> None:
        self._raw = raw_page
        self._bridge = bridge
        if hasattr(raw_page, "_impl_obj"):
            self._impl_obj = raw_page._impl_obj

    def locator(self, *args: Any, **kwargs: Any) -> WrappedSyncLocator:
        return WrappedSyncLocator(self._raw.locator(*args, **kwargs), self._bridge)

    def get_by_role(self, *args: Any, **kwargs: Any) -> WrappedSyncLocator:
        return WrappedSyncLocator(self._raw.get_by_role(*args, **kwargs), self._bridge)

    def get_by_text(self, *args: Any, **kwargs: Any) -> WrappedSyncLocator:
        return WrappedSyncLocator(self._raw.get_by_text(*args, **kwargs), self._bridge)

    def get_by_label(self, *args: Any, **kwargs: Any) -> WrappedSyncLocator:
        return WrappedSyncLocator(self._raw.get_by_label(*args, **kwargs), self._bridge)

    def get_by_placeholder(self, *args: Any, **kwargs: Any) -> WrappedSyncLocator:
        return WrappedSyncLocator(self._raw.get_by_placeholder(*args, **kwargs), self._bridge)

    def wait_for_timeout(self, timeout: float) -> None:
        end = time.monotonic() + (timeout / 1000.0)
        while time.monotonic() < end:
            step_ms = min(250.0, max(10.0, (end - time.monotonic()) * 1000.0))
            self._raw.wait_for_timeout(step_ms)
            self._bridge.sync_checkpoint(ai_status="等待页面响应...")

    def wait_for_human(
        self,
        reason: str = "请完成手动确认后点击【交还给 AI】",
        timeout: float = 600.0,
    ) -> None:
        """Explicitly pause sync script and pump live takeover loop until user resumes AI or timeout."""
        timeout_s = _validate_positive_timeout(timeout)
        if not self._bridge.enabled:
            raise RuntimeError("Live Browser 同步会话未启用，无法发起人工接管")
        cfg_kwargs: dict[str, Any] = {
            "takeover": True,
            "reason": reason,
            "ensure_card": bool(self._bridge.notify),
        }
        if self._bridge._sync_session_gen is not None:
            cfg_kwargs["expected_session_gen"] = self._bridge._sync_session_gen
        cfg_res = self._bridge.client.update_config(**cfg_kwargs)
        if not isinstance(cfg_res, dict) or not cfg_res.get("ok"):
            err = (
                (cfg_res or {}).get("error")
                or (cfg_res or {}).get("card_error")
                or "无法启用人工接管或发送私聊卡片"
            )
            tk_sgen = _parse_strict_int_no_ws((cfg_res or {}).get("session_gen"))
            tk_tgen = _parse_strict_int_no_ws((cfg_res or {}).get("takeover_gen"))
            if isinstance(cfg_res, dict) and cfg_res.get("takeover") and tk_sgen is not None and tk_tgen is not None:
                try:
                    self._bridge.client.update_config(
                        takeover=False,
                        reason="发卡失败，自动清理接管状态",
                        expected_session_gen=tk_sgen,
                        expected_takeover_gen=tk_tgen,
                    )
                except Exception:
                    pass
            raise RuntimeError(str(err))
        tk_sgen = _parse_strict_int_no_ws(cfg_res.get("session_gen"))
        if tk_sgen is None:
            tk_sgen = self._bridge._sync_session_gen
        tk_tgen = _parse_strict_int_no_ws(cfg_res.get("takeover_gen"))
        timed_out = self._bridge.sync_checkpoint(
            ai_status=reason,
            allow_takeover_loop=True,
            takeover_timeout=timeout_s,
        )
        if timed_out:
            release_kwargs: dict[str, Any] = {
                "takeover": False,
                "reason": f"等待人工交还超时（{timeout_s:g}s），已自动清理接管状态",
            }
            if tk_sgen is not None:
                release_kwargs["expected_session_gen"] = tk_sgen
            if tk_tgen is not None:
                release_kwargs["expected_takeover_gen"] = tk_tgen
            try:
                self._bridge.client.update_config(**release_kwargs)
            except Exception:
                pass
            self._bridge._release_held_buttons_sync()
            raise TimeoutError(f"wait_for_human timed out after {timeout_s:g}s")

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._raw, name)
        if name in self._HOOKED and callable(attr):
            def _wrapped(*args: Any, **kwargs: Any) -> Any:
                label = f"{name}({str(args[0])[:45]})" if args else name
                self._bridge.sync_checkpoint(ai_status=f"正在执行: {label}")
                res = attr(*args, **kwargs)
                self._bridge.sync_checkpoint(ai_status=f"已完成: {label}")
                return res
            return _wrapped
        return attr


class WrappedSyncContext:
    def __init__(self, raw_ctx: Any, bridge: SyncLiveBridge) -> None:
        self._raw = raw_ctx
        self._bridge = bridge
        if hasattr(raw_ctx, "_impl_obj"):
            self._impl_obj = raw_ctx._impl_obj

    @property
    def pages(self) -> list[WrappedSyncPage]:
        return [WrappedSyncPage(p, self._bridge) for p in self._raw.pages]

    def new_page(self, *args: Any, **kwargs: Any) -> WrappedSyncPage:
        p = self._raw.new_page(*args, **kwargs)
        self._bridge.active_idx = max(0, len(self._raw.pages) - 1)
        self._bridge.sync_checkpoint(ai_status="新建标签页")
        return WrappedSyncPage(p, self._bridge)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._raw, name)


# ---------------- CLI Entrypoint ----------------


def _parse_geoip_arg(raw: Any) -> bool | str | None:
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    txt = str(raw).strip()
    low = txt.lower()
    if low in ("true", "1", "yes"):
        return True
    if low in ("false", "0", "no"):
        return False
    return txt


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Control AGY Live Browser (Telegram Mini App real-time view + human takeover)."
    )
    p.add_argument(
        "--bot",
        default="auto",
        help="Bot target: auto (default; automatically binds to the spawning bridge bot from AGY_TG_ENV_FILE/AGY_TG_BOT_TOKEN; omit inside Telegram turns) or any bridge .env.<key> name for standalone CLI.",
    )
    p.add_argument("--user-id", default=None, help="Explicit positive Telegram admin user ID for private DM ownership.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Inspect Live Browser Hub status and public Mini App URL.")

    p_start = sub.add_parser("start", help="Start hosted Camoufox session (pinned default or named profile).")
    p_start.add_argument("--url", help="Optional initial URL to open.")
    p_start.add_argument("--no-notify", action="store_true", help="Skip sending Telegram live card.")
    p_start.add_argument("--profile", help="Profile name (defaults to host-pinned profile or 'default').")
    p_start.add_argument("--os", dest="os_name", choices=["windows", "macos", "linux"], help="Override OS fingerprint.")
    p_start.add_argument("--locale", help="Override browser locale (e.g. en-US, zh-CN, ja-JP).")
    p_start.add_argument("--window", help="Override window size WxH (e.g. 1440x900).")
    p_start.add_argument("--mobile", action="store_true", help="Use mobile portrait viewport preset (430x932, non-pinned profiles only).")
    p_start.add_argument("--webgl", dest="webgl_config", help="Override WebGL VENDOR,RENDERER.")
    p_start.add_argument("--block-webrtc", action="store_true", default=None, help="Block WebRTC leaks.")
    p_start.add_argument("--geoip", nargs="?", const="true", default=None, help="Enable Camoufox GeoIP (true or IP).")
    p_start.add_argument("--proxy", help="Egress proxy URL (e.g. socks5://proxy.example.com:1080).")
    p_start.add_argument("--proxy-bao", dest="proxy_bao_ref", help="OpenBao secret ref for proxy (e.g. kv/proxies/us-west).")
    p_start.add_argument("--ephemeral", action="store_true", help="Use temporary profile directory cleaned up on stop.")
    p_start.add_argument("--restart", action="store_true", help="Safely restart & switch profile if idle.")
    p_start.add_argument(
        "--confirm-override",
        action="store_true",
        help="Explicitly confirm overriding fingerprint/egress on a dedicated Google profile for this launch (requires user consent; does not mutate profiles.json).",
    )

    p_prof = sub.add_parser("profile", help="Manage named browser profiles, fingerprints, and proxy egress.")
    prof_sub = p_prof.add_subparsers(dest="profile_cmd", required=True)

    prof_sub.add_parser("list", help="List configured and host-pinned browser profiles.")

    p_prof_create = prof_sub.add_parser("create", help="Create a named browser profile.")
    p_prof_create.add_argument("name", help="Profile name (alphanumeric, '.', '_', '-').")
    p_prof_create.add_argument("--os", dest="os_name", choices=["windows", "macos", "linux"], default="windows")
    p_prof_create.add_argument("--locale", help="Browser locale (e.g. en-US, ja-JP).")
    p_prof_create.add_argument("--window", help="Window size WxH (e.g. 1440x900).")
    p_prof_create.add_argument("--mobile", action="store_true", help="Use mobile portrait viewport preset (430x932).")
    p_prof_create.add_argument("--webgl", dest="webgl_config", help="WebGL VENDOR,RENDERER.")
    p_prof_create.add_argument("--block-webrtc", action="store_true", default=None, help="Block WebRTC leaks.")
    p_prof_create.add_argument("--geoip", nargs="?", const="true", default=None, help="Enable Camoufox GeoIP (true or IP).")
    p_prof_create.add_argument("--proxy", help="Proxy URL (e.g. socks5://proxy.example.com:1080).")
    p_prof_create.add_argument("--proxy-bao", dest="proxy_bao_ref", help="OpenBao secret ref for proxy (e.g. kv/proxies/us-west).")
    p_prof_create.add_argument("--ephemeral", action="store_true", help="Mark profile ephemeral (non-persistent).")
    p_prof_create.add_argument(
        "--allow-google",
        action="store_true",
        help="Mark persistent profile as a dedicated Google-capable profile (requires AGY_LIVE_BROWSER_ALLOW_DEDICATED_GOOGLE_PROFILES=1).",
    )
    p_prof_create.add_argument(
        "--account",
        default=None,
        help="Optional account label/identifier (1..128 chars, no whitespace/control chars; never store passwords).",
    )
    p_prof_create.add_argument("--overwrite", action="store_true", help="Overwrite existing profile config (while idle).")

    p_prof_del = prof_sub.add_parser("delete", help="Delete a non-pinned, stopped named profile.")
    p_prof_del.add_argument("name", help="Profile name to delete.")

    sub.add_parser("stop", help="Stop hosted browser session and release profile lock.")

    p_open = sub.add_parser("open", help="Navigate active tab to URL (auto-starts if idle).")
    p_open.add_argument("url", help="Target URL.")

    p_click = sub.add_parser("click", help="Click CSS/Playwright selector or 'x,y' coordinates.")
    p_click.add_argument("target", help="Selector or 'x,y'.")

    p_fill = sub.add_parser("fill", help="Fill input selector with text.")
    p_fill.add_argument("selector")
    p_fill.add_argument("text")
    p_fill.add_argument("--submit", action="store_true", help="Press Enter after filling.")

    p_type = sub.add_parser("type", help="Type text into current focused element.")
    p_type.add_argument("text")
    p_type.add_argument("--submit", action="store_true", help="Press Enter after typing.")

    p_press = sub.add_parser("press", help="Press keyboard key (e.g. Enter, Tab, Escape).")
    p_press.add_argument("key")

    p_wait = sub.add_parser("wait", help="Wait milliseconds (e.g. 2000) or until selector visible.")
    p_wait.add_argument("target")

    p_text = sub.add_parser("text", help="Read visible innerText of selector (default: body).")
    p_text.add_argument("selector", nargs="?", default="body")

    p_eval = sub.add_parser("eval", help="Evaluate JavaScript expression on active page.")
    p_eval.add_argument("expression")

    p_shot = sub.add_parser("screenshot", help="Save screenshot to path.")
    p_shot.add_argument("path")
    p_shot.add_argument("--full-page", action="store_true")

    p_human = sub.add_parser(
        "wait-human",
        help="Switch to Human Takeover mode and wait until user clicks [交还给 AI] in Telegram.",
    )
    p_human.add_argument("--reason", default="请在实时面板完成操作后点击【▶️ 交还给 AI】")
    p_human.add_argument("--timeout", type=float, default=600.0)

    p_pub = sub.add_parser("set-public-url", help="Set public HTTPS Mini App URL (e.g. Cloudflare Tunnel).")
    p_pub.add_argument("url", help="HTTPS URL (or empty string to clear).")

    p_card = sub.add_parser("notify", help="Force send/refresh Telegram Live Browser card.")
    p_card.add_argument("--new", action="store_true", help="Send a fresh card message.")

    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        cli = LiveBrowserClient(bot=args.bot, user_id=args.user_id)
        if args.cmd == "status":
            out = cli.status()
        elif args.cmd == "start":
            out = cli.start(
                url=args.url,
                notify=not args.no_notify,
                profile=args.profile,
                os_name=args.os_name,
                locale=args.locale,
                window=args.window,
                mobile=args.mobile,
                webgl_config=args.webgl_config,
                block_webrtc=args.block_webrtc,
                geoip=_parse_geoip_arg(args.geoip),
                proxy=args.proxy,
                proxy_bao_ref=args.proxy_bao_ref,
                ephemeral=args.ephemeral,
                restart=args.restart,
                allow_override=args.confirm_override,
            )
        elif args.cmd == "profile":
            if args.profile_cmd == "list":
                out = cli.list_profiles()
            elif args.profile_cmd == "create":
                out = cli.create_profile(
                    args.name,
                    overwrite=args.overwrite,
                    os=args.os_name,
                    locale=args.locale,
                    window=args.window,
                    mobile=True if args.mobile else None,
                    webgl_config=args.webgl_config,
                    block_webrtc=args.block_webrtc,
                    geoip=_parse_geoip_arg(args.geoip),
                    proxy=args.proxy,
                    proxy_bao_ref=args.proxy_bao_ref,
                    persistent=False if args.ephemeral else True,
                    allow_google=bool(args.allow_google),
                    account=args.account,
                )
            elif args.profile_cmd == "delete":
                out = cli.delete_profile(args.name)
            else:
                raise SystemExit(f"Unknown profile command: {args.profile_cmd}")
        elif args.cmd == "stop":
            out = cli.stop()
        elif args.cmd == "open":
            out = cli.action("goto", url=args.url)
        elif args.cmd == "click":
            out = cli.action("click", target=args.target)
        elif args.cmd == "fill":
            out = cli.action("fill", selector=args.selector, text=args.text, submit=args.submit)
        elif args.cmd == "type":
            out = cli.action("type", text=args.text, submit=args.submit)
        elif args.cmd == "press":
            out = cli.action("press", key=args.key)
        elif args.cmd == "wait":
            out = cli.action("wait", target=args.target)
        elif args.cmd == "text":
            out = cli.action("text", selector=args.selector)
        elif args.cmd == "eval":
            out = cli.action("eval", expression=args.expression)
        elif args.cmd == "screenshot":
            out = cli.action("screenshot", path=args.path, full_page=args.full_page)
        elif args.cmd == "wait-human":
            timeout_s = _validate_positive_timeout(args.timeout)
            out = cli.action(
                "wait_human",
                reason=args.reason,
                timeout=timeout_s,
                timeout_http=timeout_s + 15.0,
            )
        elif args.cmd == "set-public-url":
            out = cli.update_config(public_url=args.url)
        elif args.cmd == "notify":
            out = cli.update_config(ensure_card=True, force_new=args.new)
        else:
            raise SystemExit(f"Unknown command: {args.cmd}")
    except (ValueError, KeyError, RuntimeError, TimeoutError) as exc:
        out = {"ok": False, "error": str(exc)}

    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
