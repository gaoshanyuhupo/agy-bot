#!/usr/bin/env python3
"""Same-origin authenticated HTTP & WebSocket reverse proxy to local `live-browser`.

Security guarantees:
- Enforces strict same-origin (`Origin` required & matched) on `/ws/browser` (anti-CSWSH)
  and mutating upload proxy endpoints.
- Verifies HttpOnly session cookie & fresh `.env*` RBAC BEFORE connecting upstream.
- Authenticates upstream via loopback-only `internal_auth` + `X-Internal-Token` (never
  forges Telegram `initData`, never forwards `X-Forwarded-For` / `CF-Connecting-IP`, never
  asserts `role` to upstream).
- Re-checks live RBAC on every client message and on a periodic watchdog timer; revocation
  immediately closes both client and upstream WebSockets.
- Defense-in-depth blocks mutating WS commands for `readonly` sessions at the proxy layer
  in addition to upstream enforcement.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import aiohttp
from aiohttp import WSMsgType, web

from .auth import StudioAuthManager, studio_auth_error, upstream_error
from .data_sources import StudioDataSources

log = logging.getLogger("agy-studio.proxy")

HTTP_SESSION_KEY: web.AppKey[aiohttp.ClientSession] = web.AppKey("http_session", aiohttp.ClientSession)
WS_CLOSE_AUTH_FORBIDDEN = 4003
WS_CLOSE_ROLE_CHANGED = 4008

_MUTATING_WS_TYPES = frozenset({
    "set_takeover",
    "rebind_owner_bot",
    "input",
    "start_browser",
    "stop_browser",
    "switch_profile",
    "set_quality",
    "dialog_response",
    "filechooser_cancel",
    "send_to_tg",
    "send_download_to_tg",
    "send_hd_screenshot",
})

_BLOCKED_CLIENT_WS_TYPES = frozenset({"auth", "internal_auth"})


def _parse_positive_bot_id(raw: Any) -> int | None:
    """Normalize a positive integer or ASCII digit string bot_id; reject bool/leading-zero/malformed."""
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


def _http_to_ws_url(base_http_url: str, path: str) -> str:
    clean = base_http_url.strip().rstrip("/")
    if clean.startswith("https://"):
        return "wss://" + clean[len("https://"):] + path
    if clean.startswith("http://"):
        return "ws://" + clean[len("http://"):] + path
    return "ws://" + clean + path


class BrowserProxy:
    """Manages authenticated same-origin WS/HTTP proxying to local `live-browser`."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        data_sources: StudioDataSources,
        *,
        revocation_check_interval: float = 1.5,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.revocation_check_interval = max(0.05, float(revocation_check_interval))
        self._active_sockets: dict[int, dict[str, Any]] = {}
        self._session_ws_owners: dict[str, int] = {}
        self.auth_mgr.add_revoke_listener(self._on_auth_revoked)

    @staticmethod
    async def _close_upstream(uws: aiohttp.ClientWebSocketResponse | None, timeout_sec: float = 1.0) -> None:
        if uws is None or uws.closed:
            return
        try:
            await asyncio.wait_for(uws.close(), timeout=timeout_sec)
        except Exception:
            pass

    @staticmethod
    async def _close_downstream_bounded(
        entry: dict[str, Any],
        *,
        timeout_sec: float = 0.8,
    ) -> None:
        if entry.get("downstream_closing"):
            return
        entry["downstream_closing"] = True
        cws: web.WebSocketResponse | None = entry.get("client_ws")
        if cws is None or cws.closed:
            return
        payload = entry.get("close_payload")
        close_code = int(entry.get("close_code") or WS_CLOSE_AUTH_FORBIDDEN)
        close_message = bytes(entry.get("close_message") or b"Revoked")
        if payload is not None:
            try:
                await asyncio.wait_for(
                    cws.send_str(json.dumps(payload, ensure_ascii=False)),
                    timeout=min(0.4, timeout_sec),
                )
            except Exception:
                pass
        try:
            await asyncio.wait_for(
                cws.close(code=close_code, message=close_message),
                timeout=timeout_sec,
            )
        except Exception:
            # Client stalled close handshake: abort underlying transport so resources are freed promptly
            try:
                req = getattr(cws, "_req", None)
                transport = getattr(req, "transport", None) if req is not None else None
                if transport is not None and not transport.is_closing():
                    transport.close()
            except Exception:
                pass

    async def _close_entry(
        self,
        entry: dict[str, Any],
        *,
        reason: str = "访问权限已被撤销",
        close_code: int = WS_CLOSE_AUTH_FORBIDDEN,
        close_message: bytes = b"Revoked",
        event_payload: dict[str, Any] | None = None,
        await_downstream: bool = True,
    ) -> None:
        if entry.get("closing"):
            return
        # 1. Synchronously block all further forwarding in both directions & record close metadata
        entry["closing"] = True
        entry["close_code"] = close_code
        entry["close_message"] = close_message
        entry["close_payload"] = event_payload or {
            "type": "auth_error",
            "source": "studio_auth",
            "error": reason,
        }
        uws: aiohttp.ClientWebSocketResponse | None = entry.get("upstream_ws")
        # 2. Close upstream FIRST immediately (never wait on downstream client close confirmation!)
        await self._close_upstream(uws, timeout_sec=1.0)
        # 3. Independently notify & close downstream with a strict short timeout (<= 0.8s)
        cws: web.WebSocketResponse | None = entry.get("client_ws")
        if cws is not None and not cws.closed:
            coro = self._close_downstream_bounded(entry, timeout_sec=0.8)
            if await_downstream:
                await coro
            else:
                asyncio.create_task(coro)

    async def _on_auth_revoked(
        self,
        session_hash: str | None,
        bot: str | None,
        user_id: int | None,
        *,
        username_key: str | None = None,
        exclude_session_hash: str | None = None,
    ) -> None:
        if username_key:
            # Account-scoped revocation (password rotation / disable / delete): close all sockets
            # for this username_key (optionally excluding a newly rotated session_hash)
            targets = [
                entry
                for entry in list(self._active_sockets.values())
                if entry.get("username_key") == username_key
                and entry.get("session_hash") != exclude_session_hash
                and not entry.get("closing")
            ]
        elif session_hash:
            # Session-scoped revocation (logout or single-session expiry): ONLY close matching session_hash
            targets = [
                entry
                for entry in list(self._active_sockets.values())
                if entry.get("session_hash") == session_hash and not entry.get("closing")
            ]
        elif bot and user_id is not None:
            # Identity-scoped RBAC revocation: close ALL sockets for `(bot, user_id)`
            targets = [
                entry
                for entry in list(self._active_sockets.values())
                if entry.get("bot") == bot and entry.get("user_id") == user_id and not entry.get("closing")
            ]
        else:
            targets = []

        if not targets:
            return

        payload = {
            "type": "auth_error",
            "source": "studio_auth",
            "error": "访问权限已被撤销",
        }
        # 1. Synchronously mark ALL matching sockets as closing before any await
        for entry in targets:
            entry["closing"] = True
            entry["close_code"] = WS_CLOSE_AUTH_FORBIDDEN
            entry["close_message"] = b"Revoked"
            entry["close_payload"] = payload

        # 2. Close ALL upstream connections FIRST in parallel (zero wait for client ACK)
        await asyncio.gather(
            *(self._close_upstream(entry.get("upstream_ws"), timeout_sec=1.0) for entry in targets),
            return_exceptions=True,
        )

        # 3. Independently notify & close downstream clients in bounded background tasks
        for entry in targets:
            cws = entry.get("client_ws")
            if cws is not None and not cws.closed and not entry.get("downstream_closing"):
                asyncio.create_task(self._close_downstream_bounded(entry, timeout_sec=0.8))

    async def close_all(self) -> None:
        entries = list(self._active_sockets.values())
        payload = {"type": "auth_error", "source": "studio_auth", "error": "服务正在关闭"}
        for entry in entries:
            entry["closing"] = True
            entry.setdefault("close_code", WS_CLOSE_AUTH_FORBIDDEN)
            entry.setdefault("close_message", b"Shutdown")
            entry.setdefault("close_payload", payload)
        await asyncio.gather(
            *(self._close_upstream(entry.get("upstream_ws"), timeout_sec=1.0) for entry in entries),
            return_exceptions=True,
        )
        await asyncio.gather(
            *(self._close_downstream_bounded(entry, timeout_sec=0.8) for entry in entries),
            return_exceptions=True,
        )
        self._active_sockets.clear()
        self._session_ws_owners.clear()

    async def handle_ws_browser(self, request: web.Request) -> web.StreamResponse:
        # 1. Strict Origin check (anti-CSWSH: rejects missing or cross-site Origin)
        ok_orig, err_orig = self.auth_mgr.check_same_origin(request, require_origin=True)
        if not ok_orig:
            return studio_auth_error(err_orig, status=403)

        # 2. Authenticate HttpOnly session cookie + fresh live RBAC
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            return studio_auth_error(err_auth, status=status_code)

        # 2b. Zero-TOCTOU synchronous single-session single-instance reservation BEFORE any await
        session_hash = str(sess["session_hash"])
        if session_hash in self._session_ws_owners:
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "browser_ws_conflict",
                    "error": "当前会话已有活跃的实时浏览器连接（单实例互斥），请先关闭其他分栏或标签页中的浏览器视图",
                },
                status=409,
            )

        entry: dict[str, Any] = {
            "client_ws": None,
            "upstream_ws": None,
            "session_hash": session_hash,
            "username_key": sess.get("username_key"),
            "bot": sess["bot"],
            "user_id": int(sess["user_id"]),
            "role": str(sess["role"]),
            "up_role": "readonly",
            "closing": False,
        }
        entry_key = id(entry)
        self._session_ws_owners[session_hash] = entry_key
        self._active_sockets[entry_key] = entry

        upstream_ws: aiohttp.ClientWebSocketResponse | None = None
        client_ws: web.WebSocketResponse | None = None
        try:
            # 3. Read live-browser local token
            live_token = self.data_sources.read_live_browser_token()
            if not live_token:
                return upstream_error("Live-Browser 本地令牌不可读或服务未初始化", status=503)

            http_session = request.app[HTTP_SESSION_KEY]
            upstream_ws_url = _http_to_ws_url(self.data_sources.live_browser_url, "/ws")
            try:
                upstream_ws = await http_session.ws_connect(
                    upstream_ws_url,
                    headers={"X-Internal-Token": live_token},
                    heartbeat=25.0,
                    max_msg_size=4 * 1024 * 1024,
                    timeout=aiohttp.ClientWSTimeout(ws_close=6.0),
                )
            except Exception as exc:
                log.warning("Upstream live-browser WS connect failed: %s", exc)
                return upstream_error("Live-Browser 实时流服务暂不可达", status=502)

            entry["upstream_ws"] = upstream_ws
            if entry.get("closing"):
                return studio_auth_error("访问权限已被撤销", status=403)

            # 4. Perform loopback delegated handshake with upstream (never send role!)
            try:
                await upstream_ws.send_str(
                    json.dumps(
                        {
                            "type": "internal_auth",
                            "bot": sess["bot"],
                            "user_id": int(sess["user_id"]),
                        }
                    )
                )
                first = await asyncio.wait_for(upstream_ws.receive(), timeout=5.0)
            except Exception:
                return upstream_error("Live-Browser 上游鉴权握手超时", status=502)

            if entry.get("closing"):
                return studio_auth_error("访问权限已被撤销", status=403)

            if first.type != WSMsgType.TEXT:
                return upstream_error("Live-Browser 上游拒绝连接", status=403)

            try:
                up_auth = json.loads(first.data)
            except Exception:
                return upstream_error("Live-Browser 上游返回无效鉴权响应", status=502)

            if up_auth.get("type") != "auth_ok":
                err_msg = str(up_auth.get("error") or "Live-Browser 上游鉴权未通过")
                return upstream_error(err_msg, status=403)

            # Enforce least-privilege role between Studio & upstream
            up_role = str(up_auth.get("role") or "readonly")
            eff_role = "admin" if (sess["role"] == "admin" and up_role == "admin") else "readonly"
            entry["role"] = eff_role
            entry["up_role"] = up_role

            # Re-verify live auth right before upgrading downstream WS
            ok_pre, live_pre, err_pre, _sc_pre = await self.auth_mgr.authenticate_session_hash(session_hash)
            if entry.get("closing") or not ok_pre or not live_pre:
                reason = "password_change_required" if err_pre == "password_change_required" else "访问权限已被撤销"
                return studio_auth_error(reason, status=403)

            client_ws = web.WebSocketResponse(heartbeat=25.0, max_msg_size=4 * 1024 * 1024)
            await client_ws.prepare(request)
            entry["client_ws"] = client_ws

            if entry.get("closing"):
                await self._close_downstream_bounded(entry, timeout_sec=0.8)
                return client_ws

            await client_ws.send_str(
                json.dumps(
                    {
                        "type": "auth_ok",
                        "bot": sess["bot"],
                        "user_id": int(sess["user_id"]),
                        "role": eff_role,
                        "user": sess.get("user") or {"id": int(sess["user_id"])},
                        "auth_track": sess["auth_track"],
                    },
                    ensure_ascii=False,
                )
            )

            async def _reverify_live() -> tuple[str, str]:
                """Re-verify session & live RBAC; returns `(status, eff_live_role)`.

                `status` is `'ok'`, `'downgraded'`, or `'revoked'`.
                """
                if entry.get("closing"):
                    return "revoked", "denied"
                ok_live, live_sess, err_live, _sc = await self.auth_mgr.authenticate_session_hash(
                    sess["session_hash"]
                )
                if not ok_live or not live_sess:
                    if err_live == "password_change_required":
                        await self._close_entry(
                            entry,
                            reason="password_change_required",
                            close_code=WS_CLOSE_AUTH_FORBIDDEN,
                            close_message=b"Password change required",
                        )
                    else:
                        await self._close_entry(entry, reason="访问权限已被撤销")
                    return "revoked", "denied"
                live_role = str(live_sess["role"])
                eff_live = "admin" if (live_role == "admin" and up_role == "admin") else "readonly"
                if entry["role"] == "admin" and eff_live != "admin":
                    entry["role"] = eff_live
                    await self._close_entry(
                        entry,
                        reason="权限已降级为只读（readonly），请重新连接",
                        close_code=WS_CLOSE_ROLE_CHANGED,
                        close_message=b"Role downgraded",
                        event_payload={
                            "type": "role_changed",
                            "source": "studio_auth",
                            "role": eff_live,
                            "previous_role": "admin",
                            "message": "权限已降级为只读（readonly），正在重新鉴权连接",
                        },
                    )
                    return "downgraded", eff_live
                return "ok", eff_live

            async def _pump_client_to_upstream() -> None:
                assert client_ws is not None and upstream_ws is not None
                async for msg in client_ws:
                    if msg.type in (WSMsgType.TEXT, WSMsgType.BINARY):
                        st_live, eff_live = await _reverify_live()
                        if st_live != "ok":
                            return
                        if msg.type == WSMsgType.BINARY:
                            # Live-Browser client protocol is JSON text only; ignore binary after auth check
                            continue
                        try:
                            payload = json.loads(msg.data)
                        except Exception:
                            continue
                        if not isinstance(payload, dict):
                            continue
                        mtype = str(payload.get("type") or "")
                        if mtype in _BLOCKED_CLIENT_WS_TYPES:
                            continue
                        if eff_live != "admin" and mtype in _MUTATING_WS_TYPES:
                            await client_ws.send_str(
                                json.dumps(
                                    {
                                        "type": "toast",
                                        "source": "studio_auth",
                                        "message": "🔒 只读权限（readonly）不可执行控制或接管操作",
                                    },
                                    ensure_ascii=False,
                                )
                            )
                            if mtype == "set_takeover" and payload.get("req_id") is not None:
                                await client_ws.send_str(
                                    json.dumps(
                                        {
                                            "type": "takeover_ack",
                                            "req_id": str(payload.get("req_id")),
                                            "ok": False,
                                            "takeover": False,
                                            "source": "studio_auth",
                                            "error": "只读权限不可接管",
                                        },
                                        ensure_ascii=False,
                                    )
                                )
                            elif mtype == "rebind_owner_bot" and payload.get("req_id") is not None:
                                await client_ws.send_str(
                                    json.dumps(
                                        {
                                            "type": "owner_bot_ack",
                                            "req_id": str(payload.get("req_id")),
                                            "ok": False,
                                            "source": "studio_auth",
                                            "error": "只读权限不可切换绑定 AI",
                                        },
                                        ensure_ascii=False,
                                    )
                                )
                            continue
                        # Strip any client-forged `role` key before forwarding upstream;
                        # normalize/fill `owner_bot_id` on `rebind_owner_bot` from Studio roster.
                        mutated_payload = False
                        if "role" in payload:
                            payload.pop("role", None)
                            mutated_payload = True
                        if mtype == "rebind_owner_bot":
                            raw_owner_bot = payload.get("owner_bot")
                            target_handle = (
                                raw_owner_bot.strip().lstrip("@").lower()
                                if isinstance(raw_owner_bot, str)
                                else ""
                            )
                            roster_bots: list[dict[str, Any]] | None = None
                            try:
                                bots_data = self.data_sources.get_browser_bots()
                                raw_list = bots_data.get("bots") if isinstance(bots_data, dict) else None
                                if isinstance(raw_list, list):
                                    roster_bots = [item for item in raw_list if isinstance(item, dict)]
                            except Exception:
                                roster_bots = None

                            roster_match: dict[str, Any] | None = None
                            if target_handle and roster_bots:
                                for item in roster_bots:
                                    if str(item.get("handle") or "").strip().lower() == target_handle:
                                        roster_match = item
                                        break

                            had_owner_bot_id = "owner_bot_id" in payload
                            if roster_match is not None:
                                roster_bid = _parse_positive_bot_id(roster_match.get("bot_id"))
                                if roster_bid is not None:
                                    cur_bid = payload.get("owner_bot_id")
                                    if isinstance(cur_bid, bool) or cur_bid != roster_bid or type(cur_bid) is not int:
                                        payload["owner_bot_id"] = roster_bid
                                        mutated_payload = True
                                elif had_owner_bot_id:
                                    payload.pop("owner_bot_id", None)
                                    mutated_payload = True
                            elif roster_bots:
                                # Roster is configured and target owner_bot is absent/unlisted:
                                # strip any client-supplied owner_bot_id to align with HTTP /api/browser/owner-bot.
                                if had_owner_bot_id:
                                    payload.pop("owner_bot_id", None)
                                    mutated_payload = True
                            else:
                                client_bid = _parse_positive_bot_id(payload.get("owner_bot_id"))
                                if client_bid is not None:
                                    cur_bid = payload.get("owner_bot_id")
                                    if isinstance(cur_bid, bool) or cur_bid != client_bid or type(cur_bid) is not int:
                                        payload["owner_bot_id"] = client_bid
                                        mutated_payload = True
                                elif had_owner_bot_id:
                                    payload.pop("owner_bot_id", None)
                                    mutated_payload = True
                        forward_str = json.dumps(payload, ensure_ascii=False) if mutated_payload else msg.data
                        if not upstream_ws.closed and not entry.get("closing"):
                            await upstream_ws.send_str(forward_str)
                    elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR):
                        break

            async def _pump_upstream_to_client() -> None:
                assert client_ws is not None and upstream_ws is not None
                async for msg in upstream_ws:
                    if client_ws.closed or entry.get("closing"):
                        return
                    if msg.type == WSMsgType.BINARY:
                        st_live, _eff_live = await _reverify_live()
                        if st_live != "ok" or client_ws.closed or entry.get("closing"):
                            return
                        await client_ws.send_bytes(msg.data)
                    elif msg.type == WSMsgType.TEXT:
                        st_live, _eff_live = await _reverify_live()
                        if st_live != "ok" or client_ws.closed or entry.get("closing"):
                            return
                        await client_ws.send_str(msg.data)
                    elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR):
                        break

            async def _revocation_watchdog() -> None:
                assert client_ws is not None and upstream_ws is not None
                while not client_ws.closed and not upstream_ws.closed and not entry.get("closing"):
                    await asyncio.sleep(self.revocation_check_interval)
                    st_live, _eff_live = await _reverify_live()
                    if st_live != "ok":
                        return

            tasks = [
                asyncio.create_task(_pump_client_to_upstream()),
                asyncio.create_task(_pump_upstream_to_client()),
                asyncio.create_task(_revocation_watchdog()),
            ]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for t in done:
                try:
                    t.result()
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass
            return client_ws
        finally:
            self._active_sockets.pop(entry_key, None)
            if self._session_ws_owners.get(session_hash) == entry_key:
                self._session_ws_owners.pop(session_hash, None)
            entry["closing"] = True
            if upstream_ws is not None:
                await self._close_upstream(upstream_ws, timeout_sec=1.0)
            if client_ws is not None and not client_ws.closed:
                if entry.get("close_code") is not None:
                    await self._close_downstream_bounded(entry, timeout_sec=0.8)
                else:
                    try:
                        await asyncio.wait_for(client_ws.close(), timeout=0.8)
                    except Exception:
                        pass

    async def handle_upload(self, request: web.Request) -> web.Response:
        ok_orig, err_orig = self.auth_mgr.check_same_origin(request, require_origin=True)
        if not ok_orig:
            return studio_auth_error(err_orig, status=403)
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            return studio_auth_error(err_auth, status=status_code)
        ok_csrf, err_csrf = self.auth_mgr.check_csrf(request, sess)
        if not ok_csrf:
            return studio_auth_error(err_csrf, status=403)
        if sess["role"] != "admin":
            return studio_auth_error("只读权限（readonly）禁止上传文件", status=403)

        live_token = self.data_sources.read_live_browser_token()
        if not live_token:
            return upstream_error("Live-Browser 本地令牌不可读", status=503)

        headers = {
            "X-Internal-Token": live_token,
            "X-Studio-Bot": str(sess["bot"]),
            "X-Studio-User-Id": str(sess["user_id"]),
        }
        if "Content-Type" in request.headers:
            headers["Content-Type"] = request.headers["Content-Type"]
        if "X-Chooser-Id" in request.headers:
            headers["X-Chooser-Id"] = request.headers["X-Chooser-Id"]
        params = {}
        if request.query.get("chooser_id"):
            params["chooser_id"] = request.query["chooser_id"]

        http_session = request.app[HTTP_SESSION_KEY]
        body = await request.read()
        try:
            async with http_session.post(
                f"{self.data_sources.live_browser_url}/api/upload",
                headers=headers,
                params=params,
                data=body,
                timeout=aiohttp.ClientTimeout(total=30.0),
            ) as resp:
                raw_text = await resp.text()
                try:
                    payload = json.loads(raw_text)
                except Exception:
                    payload = {"ok": False, "error": raw_text[:200] or f"HTTP {resp.status}"}
                if resp.status >= 400 and isinstance(payload, dict):
                    payload.setdefault("source", "upstream")
                return web.json_response(payload, status=resp.status)
        except Exception:
            return upstream_error("上传转发至 Live-Browser 失败", status=502)

    async def handle_download(self, request: web.Request) -> web.StreamResponse:
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            return studio_auth_error(err_auth, status=status_code)
        if sess["role"] != "admin":
            return studio_auth_error("只读权限（readonly）禁止下载浏览器会话文件", status=403)

        live_token = self.data_sources.read_live_browser_token()
        if not live_token:
            return upstream_error("Live-Browser 本地令牌不可读", status=503)

        did = str(request.match_info.get("download_id") or "").strip()
        if not did or "/" in did or ".." in did:
            return studio_auth_error("无效的下载标识", status=400)

        headers = {
            "X-Internal-Token": live_token,
            "X-Studio-Bot": str(sess["bot"]),
            "X-Studio-User-Id": str(sess["user_id"]),
        }
        http_session = request.app[HTTP_SESSION_KEY]
        try:
            async with http_session.get(
                f"{self.data_sources.live_browser_url}/api/download/{did}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30.0),
            ) as resp:
                if resp.status >= 400:
                    try:
                        payload = await resp.json()
                    except Exception:
                        payload = {"ok": False, "error": f"HTTP {resp.status}"}
                    if isinstance(payload, dict):
                        payload.setdefault("source", "upstream")
                    return web.json_response(payload, status=resp.status)

                out_headers = {
                    "Content-Type": resp.headers.get("Content-Type", "application/octet-stream"),
                    "X-Content-Type-Options": "nosniff",
                    "Cache-Control": "no-store, max-age=0",
                }
                if "Content-Disposition" in resp.headers:
                    out_headers["Content-Disposition"] = resp.headers["Content-Disposition"]
                body = await resp.read()
                return web.Response(body=body, status=resp.status, headers=out_headers)
        except Exception:
            return upstream_error("下载代理请求 Live-Browser 失败", status=502)
