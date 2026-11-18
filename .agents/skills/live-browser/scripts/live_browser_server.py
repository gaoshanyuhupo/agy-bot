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
import json
import logging
import os
from pathlib import Path
import secrets
import shutil
import sys
import time
from typing import Any
import urllib.parse

from aiohttp import FormData, WSMsgType, web

# Import canonical profile constants & helpers from google-profile skill
GOOGLE_SKILL_SCRIPTS = Path(
    os.environ.get(
        "AGY_GOOGLE_SKILL_SCRIPTS",
        str(Path.home() / "agy-workspace/.agents/skills/google-profile/scripts"),
    )
)
if str(GOOGLE_SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(GOOGLE_SKILL_SCRIPTS))

from google_browser import (  # noqa: E402
    LOCK_PATH,
    PINNED_FINGERPRINT,
    PROFILE_DIR,
    _clean_stale_firefox_locks,
    _direct_env,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("live-browser")

CONFIG_DIR = Path(os.environ.get("AGY_LIVE_BROWSER_CONFIG_DIR", str(Path.home() / ".config/agy-live-browser")))
CONFIG_FILE = CONFIG_DIR / "config.json"
LOCAL_TOKEN_FILE = CONFIG_DIR / "local.token"
STATIC_DIR = Path(__file__).resolve().parent / "static"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 18795
IDLE_AUTOCLOSE_SECONDS = 900.0  # Auto-release profile lock after 15m idle

_BRIDGE_DIR = Path(os.environ.get("AGY_TG_BRIDGE_DIR", str(Path.home() / "agy-tg-bridge")))
BRIDGE_ENV_FILES = {
    "main": _BRIDGE_DIR / ".env",
    "sg": _BRIDGE_DIR / ".env.sg",
}


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


def load_bot_credentials() -> tuple[dict[str, str], dict[str, str], set[int]]:
    """Load bot tokens and allowed chat IDs from agy-tg-bridge .env files without logging secrets."""
    bots_by_key: dict[str, str] = {}
    bot_id_to_key: dict[str, str] = {}
    allowed_chats: set[int] = set()

    for key, path in BRIDGE_ENV_FILES.items():
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
        if token and ":" in token:
            bots_by_key[key] = token
            bot_id_to_key[token.split(":", 1)[0]] = key
        for chat_str in env_map.get("AGY_TG_ALLOWED_CHATS", "").split(","):
            chat_str = chat_str.strip()
            if chat_str.lstrip("-").isdigit():
                allowed_chats.add(int(chat_str))

    return bots_by_key, bot_id_to_key, allowed_chats


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


def resolve_camoufox_display(ctx: Any) -> str | None:
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

    # Fallback: scan /proc for camoufox-bin running against PROFILE_DIR
    prof_bytes = str(PROFILE_DIR).encode("utf-8")
    proc_root = Path("/proc")
    if proc_root.is_dir():
        for entry in proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cmd = (entry / "cmdline").read_bytes()
                if b"camoufox-bin" not in cmd or prof_bytes not in cmd:
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

    def _build_markup(self, bot_key: str) -> str | None:
        pub = (self.hub.config.get("public_url") or "").strip().rstrip("/")
        if not pub.startswith("https://"):
            return None
        btn_text = (
            "🟠 人工接管中 · 点此操作浏览器"
            if self.hub.takeover
            else "🖥 打开实时画面 / 人工接管"
        )
        markup = {
            "inline_keyboard": [
                [{"text": btn_text, "web_app": {"url": f"{pub}/?bot={bot_key}"}}]
            ]
        }
        return json.dumps(markup, ensure_ascii=False)

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
        if not (self.hub.config.get("public_url") or "").startswith("https://"):
            lines.append("💡 <i>绑定 HTTPS 隧道域名后将自动显示【实时画面/人工接管】按钮</i>")
        return "\n".join(lines)

    async def ensure_card(self, bot_key: str, force_new: bool = False) -> dict[str, Any] | None:
        """Create or update the live browser card in the target bot's primary allowed chat."""
        bots, _, allowed = load_bot_credentials()
        token = bots.get(bot_key)
        if not token or not allowed:
            return None
        chat_id = sorted(allowed)[0]

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
            markup = self._build_markup(bot_key)
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
                        log.info("Created Telegram live card bot=%s message_id=%s", bot_key, mid)
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
        markup = self._build_markup(bot_key)

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

    async def send_clip_message(self, bot_key: str, text: str) -> bool:
        """Send an explicit user-requested clipboard snippet to the authorized Telegram chat."""
        cleaned = (text or "").strip()
        if not cleaned or not self.http:
            return False
        bots, _, allowed = load_bot_credentials()
        token = bots.get(bot_key)
        if not token or not allowed:
            return False
        chat_id = sorted(allowed)[0]
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

        # 3-State Control Arbitration
        self.takeover: bool = False
        self.takeover_reason: str = ""
        self.ai_allowed_event = asyncio.Event()
        self.ai_allowed_event.set()

        # Queues & Clients
        self.viewers: set[web.WebSocketResponse] = set()
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
        for ws in list(self.viewers):
            await ws.close()
        await self.tg.close()

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
            "takeover": self.takeover,
            "takeover_reason": self.takeover_reason,
            "ai_status": self.ai_status,
            "url": self.url,
            "title": self.title,
            "vw": self.vw,
            "vh": self.vh,
            "tabs": self.tabs,
            "cursor": self.cursor,
            "public_url": self.config.get("public_url") or "",
            "viewers": len(self.viewers),
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
        self.last_activity_ts = time.monotonic()
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

    # ---------------- Hosted AsyncCamoufox Lifecycle ----------------

    async def start_hosted(
        self,
        initial_url: str | None = None,
        bot_hint: str | None = None,
        notify_tg: bool = True,
        lock_timeout: float = 45.0,
    ) -> dict[str, Any]:
        async with self._engine_lock:
            self.last_activity_ts = time.monotonic()
            if self.engine_mode == "sync_external":
                raise RuntimeError("当前已有外部同步脚本持有浏览器会话。")

            if self.engine_mode != "async_hosted":
                if not PROFILE_DIR.is_dir():
                    raise FileNotFoundError(f"Pinned Google profile missing: {PROFILE_DIR}")

                PROFILE_DIR.parent.mkdir(parents=True, exist_ok=True)
                os.chmod(PROFILE_DIR.parent, 0o700)
                fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
                deadline = time.monotonic() + lock_timeout
                try:
                    while True:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if time.monotonic() >= deadline:
                                raise TimeoutError(f"等待 {PROFILE_DIR.name} 浏览器锁超时。")
                            await asyncio.sleep(0.25)
                    _clean_stale_firefox_locks()

                    from camoufox.async_api import AsyncCamoufox

                    kwargs = {
                        **PINNED_FINGERPRINT,
                        "persistent_context": True,
                        "user_data_dir": str(PROFILE_DIR),
                        "env": _direct_env(),
                        "firefox_user_prefs": {"network.proxy.type": 0},
                    }
                    cm = AsyncCamoufox(**kwargs)
                    ctx = await cm.__aenter__()
                except Exception:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except Exception:
                        pass
                    os.close(fd)
                    raise

                self.lock_fd = fd
                self.camoufox_cm = cm
                self.ctx = ctx
                self.engine_mode = "async_hosted"
                self.ai_status = "已启动安全浏览器"
                self.x11_display = resolve_camoufox_display(ctx)
                self._last_x11_clip = await read_x11_clipboard_async(self.x11_display)
                log.info("Resolved Camoufox X11 display=%s", self.x11_display)

                def _on_new_page(new_page: Any) -> None:
                    try:
                        pages = list(self.ctx.pages)
                        if new_page in pages:
                            self.active_tab_index = pages.index(new_page)
                    except Exception:
                        pass

                ctx.on("page", _on_new_page)
                if not ctx.pages:
                    await ctx.new_page()
                self.active_tab_index = max(0, len(ctx.pages) - 1)
                log.info("Started hosted AsyncCamoufox on profile %s", PROFILE_DIR)

            page = self._current_page()
            if initial_url and page:
                self.ai_status = f"正在打开 {initial_url}"
                await self.broadcast_state()
                await page.goto(initial_url, wait_until="domcontentloaded", timeout=45000)
                self.ai_status = f"已打开 {initial_url}"

            await self._capture_once()
            await self.broadcast_state()

        if notify_tg:
            bot_key = self.resolve_bot_key(bot_hint)
            asyncio.create_task(self.tg.ensure_card(bot_key))

        return self.state_dict()

    async def stop_hosted(self, notify_finished: bool = True) -> None:
        async with self._engine_lock:
            if self.engine_mode != "async_hosted":
                return
            await self._capture_once()
            cm = self.camoufox_cm
            fd = self.lock_fd
            self.camoufox_cm = None
            self.ctx = None
            self.lock_fd = None
            self.engine_mode = "idle"
            self.x11_display = None
            self._last_x11_clip = ""
            self.tabs = []
            self.ai_status = ""
            self.takeover = False
            self.takeover_reason = ""
            self.ai_allowed_event.set()

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
            log.info("Stopped hosted AsyncCamoufox and released profile lock")

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

    async def _capture_once(self) -> bool:
        if self.engine_mode != "async_hosted":
            return False
        page = self._current_page()
        if not page:
            return False
        try:
            jpeg = await asyncio.wait_for(
                page.screenshot(type="jpeg", quality=58, animations="allow"),
                timeout=3.0,
            )
            pages = list(self.ctx.pages)
            tabs_info: list[dict[str, Any]] = []
            for idx, p in enumerate(pages):
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
                dims = await asyncio.wait_for(
                    page.evaluate("() => ({w: window.innerWidth, h: window.innerHeight})"),
                    timeout=0.8,
                )
                if dims and dims.get("w") and dims.get("h"):
                    self.vw = int(dims["w"])
                    self.vh = int(dims["h"])

            await self.broadcast_frame(jpeg)
            return True
        except Exception as exc:
            log.debug("Frame capture skipped: %s", exc)
            return False

    async def _poll_clipboard_once(self) -> None:
        if self.engine_mode != "async_hosted":
            return
        if not self.x11_display:
            self.x11_display = resolve_camoufox_display(self.ctx)
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

    async def _capture_loop(self) -> None:
        last_state_push = 0.0
        last_clip_poll = 0.0
        while True:
            try:
                if self.engine_mode == "async_hosted":
                    has_viewers = len(self.viewers) > 0
                    has_cards = len(self.tg.cards) > 0
                    if has_viewers or has_cards:
                        ok = await self._capture_once()
                        now = time.monotonic()
                        if ok and (now - last_state_push >= 0.6):
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
                    await asyncio.sleep(0.10 if has_viewers else 2.2)
                else:
                    await asyncio.sleep(0.4)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.warning("Capture loop error: %s", exc)
                await asyncio.sleep(0.5)

    async def _tg_maintenance_loop(self) -> None:
        while True:
            try:
                if self.engine_mode != "idle" and self.tg.cards:
                    await self.tg.tick_updates(finished=False, force=False)
                await asyncio.sleep(1.2)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.debug("TG maintenance loop error: %s", exc)
                await asyncio.sleep(2.0)

    async def _input_loop(self) -> None:
        while True:
            try:
                cmd = await self.input_queue.get()
                self.last_activity_ts = time.monotonic()

                # Coalesce consecutive wheel events for smooth touch scrolling
                if cmd.get("action") == "wheel":
                    dx = float(cmd.get("dx", 0))
                    dy = float(cmd.get("dy", 0))
                    while not self.input_queue.empty():
                        nxt = self.input_queue. _queue[0]  # peek
                        if nxt.get("action") == "wheel":
                            self.input_queue.get_nowait()
                            dx += float(nxt.get("dx", 0))
                            dy += float(nxt.get("dy", 0))
                        else:
                            break
                    cmd = {"action": "wheel", "dx": dx, "dy": dy}

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
        if act in ("click", "dblclick"):
            x = float(cmd.get("x", 0))
            y = float(cmd.get("y", 0))
            self.cursor = {"x": x, "y": y, "actor": "human", "ts": time.time()}
            if act == "dblclick":
                await page.mouse.dblclick(x, y)
            else:
                await page.mouse.click(x, y)
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
        self.last_activity_ts = time.monotonic()

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
        hub.viewers.add(ws)
        hub.last_activity_ts = time.monotonic()
        log.info("Mini App viewer connected (user=%s, bot=%s, total=%d)", info["user"].get("id"), bot_key, len(hub.viewers))

        await ws.send_str(json.dumps({"type": "auth_ok", **info}))
        await ws.send_str(json.dumps(hub.state_dict(), ensure_ascii=False))
        if hub.latest_jpeg and hub.engine_mode != "idle":
            await ws.send_bytes(hub.latest_jpeg)

        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                continue
            data = json.loads(msg.data)
            mtype = data.get("type")
            if mtype == "ping":
                await ws.send_str(json.dumps({"type": "pong", "t": data.get("t", 0)}))
            elif mtype == "set_takeover":
                await hub.set_takeover(bool(data.get("active")), str(data.get("reason", "")))
            elif mtype == "start_browser":
                if hub.engine_mode == "idle":
                    asyncio.create_task(
                        hub.start_hosted(
                            initial_url=str(data.get("url") or "https://www.google.com"),
                            bot_hint=bot_key,
                            notify_tg=True,
                        )
                    )
                    if data.get("takeover"):
                        await hub.set_takeover(True, "手动启动浏览器接管模式")
            elif mtype == "extract":
                hub.last_activity_ts = time.monotonic()
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
                hub.last_activity_ts = time.monotonic()
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
                    sent = await hub.tg.send_clip_message(bot_key, txt)
                    await ws.send_str(
                        json.dumps(
                            {
                                "type": "toast",
                                "message": "✅ 已发送到当前 TG 聊天框" if sent else "发送 TG 消息失败",
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
            log.info("Mini App viewer disconnected (remaining=%d)", len(hub.viewers))
    return ws


# ---------------- Localhost Internal IPC Endpoints ----------------


async def internal_status(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    return web.json_response({"ok": True, **hub.state_dict()})


async def internal_start(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
    body = await request.json()
    try:
        st = await hub.start_hosted(
            initial_url=body.get("url"),
            bot_hint=body.get("bot"),
            notify_tg=bool(body.get("notify", True)),
        )
        return web.json_response({"ok": True, **st})
    except Exception as exc:
        return web.json_response({"ok": False, "error": str(exc)}, status=500)


async def internal_stop(request: web.Request) -> web.Response:
    hub: LiveBrowserHub = request.app["hub"]
    check_local_auth(request, hub)
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
    if "takeover" in body:
        await hub.set_takeover(bool(body["takeover"]), str(body.get("reason", "")))
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
        hub.ai_allowed_event.set()
        hub.sync_cmd_queue.clear()
        await hub.tg.tick_updates(finished=True, force=True)
        await hub.broadcast_state()
    return web.json_response({"ok": True})


def create_app() -> web.Application:
    cfg, local_token = ensure_local_config()
    hub = LiveBrowserHub(cfg, local_token)
    app = web.Application(client_max_size=12 * 1024 * 1024)
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

    app.router.add_get("/internal/status", internal_status)
    app.router.add_post("/internal/start", internal_start)
    app.router.add_post("/internal/stop", internal_stop)
    app.router.add_post("/internal/action", internal_action)
    app.router.add_post("/internal/config", internal_config)
    app.router.add_post("/internal/yield-lock", internal_yield_lock)
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
