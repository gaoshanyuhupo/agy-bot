#!/usr/bin/env python3
"""CLI & Python SDK for AGY Live Browser Hub + SyncLiveBridge for open_google_browser()."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any
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


def _detect_current_bot_hint() -> str:
    """Detect which Telegram bot spawned the current agent process without exposing tokens."""
    tok = os.environ.get("AGY_TG_BOT_TOKEN", "")
    if ":" in tok:
        return tok.split(":", 1)[0]
    env_file = os.environ.get("AGY_TG_ENV_FILE", "")
    if env_file:
        name = Path(env_file).name
        if name == ".env":
            return "main"
        if name.startswith(".env.") and len(name) > 5:
            return name[5:]
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
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"url": url, "bot": self.bot, "notify": notify}
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
        r = self.session.post(
            f"{self.base_url}/internal/start",
            headers=self._headers(),
            json=payload,
            timeout=65.0,
        )
        return r.json()

    def list_profiles(self) -> dict[str, Any]:
        if self.is_alive() and self.token:
            r = self.session.get(
                f"{self.base_url}/internal/profiles", headers=self._headers(), timeout=5.0
            )
            return r.json()
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

    def __init__(
        self,
        raw_ctx: Any,
        bot_hint: str | None = None,
        notify: bool | None = None,
        user_id: int | None = None,
        profile_dir: str | Path | None = None,
        pinned_launch: bool = False,
    ) -> None:
        self.raw_ctx = raw_ctx
        self.client = LiveBrowserClient(bot=bot_hint)
        self.notify = (os.environ.get("AGY_LIVE_NOTIFY", "1") != "0") if notify is None else notify
        self.enabled = self.client.is_alive() and bool(self.client.token)
        self.active_idx = 0
        self._in_checkpoint = False
        self._held_buttons: set[str] = set()
        self._sync_lease_id: str | None = None
        self._sync_session_gen: int | None = None
        self._x11_display: str | None = self._resolve_display()
        self._last_clip: str = self._read_x11_clip()
        if self.enabled:
            try:
                start_body: dict[str, Any] = {
                    "bot": self.client.bot,
                    "ai_status": "已启动同步浏览器会话",
                }
                if profile_dir is not None:
                    start_body["profile_dir"] = str(profile_dir)
                if pinned_launch:
                    start_body["pinned_launch"] = True
                raw_uid = user_id if user_id is not None else os.environ.get("AGY_LIVE_USER_ID")
                if raw_uid is not None and str(raw_uid).strip().isdigit() and int(str(raw_uid).strip()) > 0:
                    start_body["user_id"] = int(str(raw_uid).strip())
                resp = self.client.session.post(
                    f"{self.client.base_url}/internal/sync/start",
                    headers=self.client._headers(),
                    json=start_body,
                    timeout=3.0,
                )
                start_data = resp.json() if hasattr(resp, "json") else {}
                if isinstance(start_data, dict):
                    self._sync_lease_id = start_data.get("sync_lease_id")
                    self._sync_session_gen = start_data.get("session_gen")
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
            self.enabled = False

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
                    self.enabled = False
                    break
                data = resp.json()
                if isinstance(data, dict) and data.get("ok") is False:
                    self._release_held_buttons_sync()
                    self.enabled = False
                    break
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
                ai_status = "人工接管中（脚本已挂起等待）"
                time.sleep(0.09)
        except Exception:
            if not self.enabled:
                self._release_held_buttons_sync()
        finally:
            if not self.enabled:
                self._release_held_buttons_sync()
            self._in_checkpoint = False

    def _release_held_buttons_sync(self) -> None:
        held = getattr(self, "_held_buttons", None)
        if not held:
            return
        page = self._active_raw_page()
        buttons = list(held)
        held.clear()
        if page is not None:
            for btn in buttons:
                try:
                    page.mouse.up(button=btn)
                except Exception:
                    pass

    def _exec_human_sync(self, cmd: dict[str, Any]) -> tuple[float, float, str] | None:
        page = self._active_raw_page()
        if not page:
            return None
        held = getattr(self, "_held_buttons", None)
        if held is None:
            held = set()
            self._held_buttons = held
        act = cmd.get("action")
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
                page.mouse.move(x, y)
                held.add(btn)
                page.mouse.down(button=btn)
            elif act == "mouseup":
                x, y = float(cmd.get("x", 0)), float(cmd.get("y", 0))
                btn = str(cmd.get("button") or "left")
                if btn not in ("left", "right", "middle"):
                    btn = "left"
                cursor_out = (x, y, "human")
                page.mouse.move(x, y)
                held.discard(btn)
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
                        self._push_clip(
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
                        self._push_clip(prev_body)
                    elif cleaned_rt:
                        self._push_clip(
                            {
                                "text": cleaned_rt,
                                "source": f"涂抹选定 ({len(cleaned_rt)}字)",
                            }
                        )
                else:
                    x, y = float(cmd.get("x", 0)), float(cmd.get("y", 0))
                    ext = page.evaluate(
                        """({x, y}) => {
                            const el = document.elementFromPoint(x, y);
                            if (!el) return null;
                            const tag = (el.tagName || '').toUpperCase();
                            if (tag === 'INPUT' || tag === 'TEXTAREA') {
                                const tp = (el.type || 'text').toLowerCase();
                                const ac = ((el.getAttribute && el.getAttribute('autocomplete')) || '').toLowerCase();
                                const nm = ((el.name || '') + ' ' + (el.id || '')).toLowerCase();
                                const isSensitive = tp === 'password' || ac.includes('password') || ac.includes('cc-') || ac.includes('one-time-code') || /\\b(otp|cvv|cvc|passcode|pin|card[-_]?num)\\b/.test(nm);
                                const val = isSensitive ? '' : String(el.value || el.placeholder || '').trim();
                                return val ? { text: val.slice(0, 20000), href: '', source: '输入框内容' } : null;
                            }
                            const link = el.closest('a[href]');
                            const txt = (el.innerText || el.textContent || '').trim();
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
    p.add_argument("--bot", default="auto", help="Bot target: auto | sg | main")
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
    p_prof_create.add_argument("--overwrite", action="store_true", help="Overwrite existing profile config.")

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
    cli = LiveBrowserClient(bot=args.bot)

    try:
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
    except (ValueError, KeyError, RuntimeError) as exc:
        out = {"ok": False, "error": str(exc)}

    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
