#!/usr/bin/env python3
"""CLI & Python SDK for AGY Live Browser Hub + SyncLiveBridge for open_google_browser()."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any
import urllib.parse

import requests

CONFIG_DIR = Path(os.environ.get("AGY_LIVE_BROWSER_CONFIG_DIR", str(Path.home() / ".config/agy-live-browser")))
CONFIG_FILE = CONFIG_DIR / "config.json"
LOCAL_TOKEN_FILE = CONFIG_DIR / "local.token"
DEFAULT_BASE_URL = "http://127.0.0.1:18795"


def _detect_current_bot_hint() -> str:
    """Detect which Telegram bot spawned the current agent process without exposing tokens."""
    tok = os.environ.get("AGY_TG_BOT_TOKEN", "")
    if ":" in tok:
        return tok.split(":", 1)[0]
    env_file = os.environ.get("AGY_TG_ENV_FILE", "")
    if env_file.endswith(".env.sg"):
        return "sg"
    if env_file.endswith(".env"):
        return "main"
    return "sg"


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

    def __init__(self, bot: str | None = None) -> None:
        self.base_url, self.token = _load_hub_conn()
        self.bot = bot if (bot and bot != "auto") else _detect_current_bot_hint()
        self.session = requests.Session()
        self.session.trust_env = False  # Always direct to 127.0.0.1

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

    def status(self) -> dict[str, Any]:
        r = self.session.get(
            f"{self.base_url}/internal/status", headers=self._headers(), timeout=5.0
        )
        r.raise_for_status()
        return r.json()

    def start(self, url: str | None = None, notify: bool = True) -> dict[str, Any]:
        r = self.session.post(
            f"{self.base_url}/internal/start",
            headers=self._headers(),
            json={"url": url, "bot": self.bot, "notify": notify},
            timeout=65.0,
        )
        return r.json()

    def stop(self) -> dict[str, Any]:
        r = self.session.post(
            f"{self.base_url}/internal/stop", headers=self._headers(), timeout=20.0
        )
        return r.json()

    def action(self, action: str, timeout_http: float = 120.0, **kwargs: Any) -> dict[str, Any]:
        payload = {"action": action, "bot": self.bot, **kwargs}
        r = self.session.post(
            f"{self.base_url}/internal/action",
            headers=self._headers(),
            json=payload,
            timeout=timeout_http,
        )
        return r.json()

    def update_config(self, **kwargs: Any) -> dict[str, Any]:
        payload = {"bot": self.bot, **kwargs}
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

    def __init__(self, raw_ctx: Any, bot_hint: str | None = None, notify: bool | None = None) -> None:
        self.raw_ctx = raw_ctx
        self.client = LiveBrowserClient(bot=bot_hint)
        self.notify = (os.environ.get("AGY_LIVE_NOTIFY", "1") != "0") if notify is None else notify
        self.enabled = self.client.is_alive() and bool(self.client.token)
        self.active_idx = 0
        self._in_checkpoint = False
        self._x11_display: str | None = self._resolve_display()
        self._last_clip: str = self._read_x11_clip()
        if self.enabled:
            try:
                self.client.session.post(
                    f"{self.client.base_url}/internal/sync/start",
                    headers=self.client._headers(),
                    json={"bot": self.client.bot, "ai_status": "已启动同步浏览器会话"},
                    timeout=3.0,
                )
            except Exception:
                self.enabled = False

    def close(self) -> None:
        if not self.enabled:
            return
        try:
            self.sync_checkpoint(ai_status="会话即将完成", allow_takeover_loop=False)
            self.client.session.post(
                f"{self.client.base_url}/internal/sync/stop",
                headers=self.client._headers(),
                timeout=5.0,
            )
        except Exception:
            pass

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
        if not self.enabled or not payload.get("text"):
            return
        try:
            self.client.session.post(
                f"{self.client.base_url}/internal/sync/clipboard",
                headers=self.client._headers(),
                json=payload,
                timeout=2.5,
            )
        except Exception:
            pass

    def sync_checkpoint(
        self,
        ai_status: str = "",
        cursor: tuple[float, float, str] | None = None,
        allow_takeover_loop: bool = True,
    ) -> None:
        if not self.enabled or self._in_checkpoint:
            return
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
                if cursor:
                    params["cx"] = str(cursor[0])
                    params["cy"] = str(cursor[1])
                    params["actor"] = cursor[2]

                qs = urllib.parse.urlencode(params)
                resp = self.client.session.post(
                    f"{self.client.base_url}/internal/sync/push?{qs}",
                    headers={**self.client._headers(), "Content-Type": "image/jpeg"},
                    data=jpeg,
                    timeout=4.0,
                )
                data = resp.json()
                cur_clip = self._read_x11_clip()
                if cur_clip and cur_clip != self._last_clip:
                    self._last_clip = cur_clip
                    self._push_clip({"text": cur_clip, "source": "网页复制按钮 / Ctrl+C"})
                for cmd in data.get("commands") or []:
                    cursor = self._exec_human_sync(cmd)
                if not allow_takeover_loop or not data.get("takeover"):
                    break
                ai_status = "人工接管中（脚本已挂起等待）"
                time.sleep(0.09)
        except Exception:
            pass
        finally:
            self._in_checkpoint = False

    def _exec_human_sync(self, cmd: dict[str, Any]) -> tuple[float, float, str] | None:
        page = self._active_raw_page()
        if not page:
            return None
        act = cmd.get("action")
        cursor_out: tuple[float, float, str] | None = None
        try:
            if act in ("click", "dblclick"):
                x, y = float(cmd.get("x", 0)), float(cmd.get("y", 0))
                cursor_out = (x, y, "human")
                if act == "dblclick":
                    page.mouse.dblclick(x, y)
                else:
                    page.mouse.click(x, y)
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
                if u:
                    page.goto(u, wait_until="domcontentloaded", timeout=45000)
            elif act == "back":
                page.go_back(wait_until="domcontentloaded", timeout=15000)
            elif act == "forward":
                page.go_forward(wait_until="domcontentloaded", timeout=15000)
            elif act == "reload":
                page.reload(wait_until="domcontentloaded", timeout=30000)
            elif act == "switch_tab":
                idx = int(cmd.get("index", 0))
                if 0 <= idx < len(self.raw_ctx.pages):
                    self.active_idx = idx
                    self.raw_ctx.pages[idx].bring_to_front()
            elif act == "new_tab":
                np = self.raw_ctx.new_page()
                self.active_idx = list(self.raw_ctx.pages).index(np)
                np.goto("https://www.google.com", wait_until="domcontentloaded", timeout=30000)
            elif act == "close_tab":
                idx = int(cmd.get("index", -1))
                if len(self.raw_ctx.pages) > 1 and 0 <= idx < len(self.raw_ctx.pages):
                    self.raw_ctx.pages[idx].close()
                    self.active_idx = max(0, min(self.active_idx, len(self.raw_ctx.pages) - 1))
            elif act == "extract":
                mode = str(cmd.get("mode") or "point")
                if mode == "page":
                    txt = page.evaluate("() => (document.body && document.body.innerText || '').trim().slice(0, 25000)")
                    if txt:
                        self._push_clip({"text": txt, "source": "整页可见文字"})
                elif mode == "url":
                    self._push_clip({"text": page.url, "href": page.url, "source": "当前网页网址"})
                else:
                    x, y = float(cmd.get("x", 0)), float(cmd.get("y", 0))
                    ext = page.evaluate(
                        """({x, y}) => {
                            const el = document.elementFromPoint(x, y);
                            if (!el) return null;
                            const link = el.closest('a[href]');
                            const txt = (el.value || el.innerText || el.textContent || '').trim();
                            return txt ? { text: txt.slice(0, 20000), href: link ? link.href : '', source: '点字提取' } : null;
                        }""",
                        {"x": x, "y": y},
                    )
                    if ext:
                        self._push_clip(ext)
        except Exception:
            pass
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

    def wait_for_human(self, reason: str = "请完成手动确认后点击【交还给 AI】") -> None:
        """Explicitly pause sync script and pump live 11 FPS takeover loop until user resumes AI."""
        if not self._bridge.enabled:
            return
        self._bridge.client.update_config(takeover=True, reason=reason, ensure_card=True)
        self._bridge.sync_checkpoint(ai_status=reason, allow_takeover_loop=True)

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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Control AGY Live Browser (Telegram Mini App real-time view + human takeover)."
    )
    p.add_argument("--bot", default="auto", help="Bot target: auto | sg | main")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Inspect Live Browser Hub status and public Mini App URL.")

    p_start = sub.add_parser("start", help="Start hosted persistent Google Camoufox session.")
    p_start.add_argument("--url", help="Optional initial URL to open.")
    p_start.add_argument("--no-notify", action="store_true", help="Skip sending Telegram live card.")

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
    cli = LiveBrowserClient(bot=args.bot)

    if args.cmd == "status":
        out = cli.status()
    elif args.cmd == "start":
        out = cli.start(url=args.url, notify=not args.no_notify)
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
        out = cli.action(
            "wait_human",
            reason=args.reason,
            timeout=args.timeout,
            timeout_http=args.timeout + 15.0,
        )
    elif args.cmd == "set-public-url":
        out = cli.update_config(public_url=args.url)
    elif args.cmd == "notify":
        out = cli.update_config(ensure_card=True, force_new=args.new)
    else:
        raise SystemExit(f"Unknown command: {args.cmd}")

    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
