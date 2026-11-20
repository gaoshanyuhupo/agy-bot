#!/usr/bin/env python3
"""AGY Studio Phase A M2 — Global Real-Time Event Hub (`GET /api/events`).

Provides zero-TOCTOU concurrency-capped, revocation-safe Server-Sent Events (SSE)
for real-time updates across Bots, Jobs, and Schedules:
- Auth: any authenticated user (`admin` or `readonly`, `must_change_password=False`)
- Concurrency caps: <= 4 per session, <= 32 global (synchronous placeholder registered
  BEFORE any `await` including `sse_resp.prepare()`, released in `try/finally`)
- Real-time revocation: `auth_mgr.add_revoke_listener` + live RBAC watchdog + pre-write
  `authenticate_session_hash()` verification; logout / password rotation / disable / role
  downgrade immediately stops pushes, emits terminal `auth_error`, and closes within <= 0.8s
  with 0 post-revocation data frames leaked
- Bounded 256-event ring buffer with monotonic `seq`, `Last-Event-ID` / `after_seq` replay,
  overflow `resync_required`, <= 16 KiB per-frame hard cap, and deep payload redaction
- Lightweight background file-change watcher (runs only while subscribers exist; cleanly
  cancelled in `close_all()` during `app.on_cleanup`)
"""

from __future__ import annotations

import asyncio
from collections import deque
import json
import logging
import os
import time
from typing import Any

from aiohttp import web

from .auth import StudioAuthManager, studio_auth_error
from .data_sources import (
    StudioDataSources,
    _SENSITIVE_HOST_PATH_RE,
    redact_secrets_only,
    truncate_utf8_bytes,
)

log = logging.getLogger("agy-studio.events")

DEFAULT_MAX_EVENTS = 256
MAX_SSE_EVENT_BYTES = 16 * 1024
MAX_STREAMS_PER_SESSION = 4
MAX_STREAMS_GLOBAL = 32
DEFAULT_KEEPALIVE_SEC = 15.0
DEFAULT_WATCHER_INTERVAL_SEC = 2.0

_FORBIDDEN_EVENT_KEYS = frozenset({
    "ipc_sock",
    "workdir",
    "script",
    "command",
    "cmd",
    "shell",
    "precheck_cmd",
    "target_chat_id",
    "chat_id",
    "thread_id",
    "target_thread_id",
    "origin_chat_id",
    "origin_thread_id",
    "origin_msg_id",
    "password",
    "password_hash",
    "csrf_token",
    "cookie",
    "token",
    "secret",
    "api_key",
    "authorization",
})


def _sanitize_event_value(val: Any, *, depth: int = 0) -> Any:
    if depth > 6:
        return None
    if val is None or isinstance(val, (bool, int, float)):
        return val
    if isinstance(val, str):
        red = redact_secrets_only(val)
        if red:
            red = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", red)
        return red
    if isinstance(val, dict):
        out: dict[str, Any] = {}
        for k, v in val.items():
            ks = str(k)
            if ks.strip().lower() in _FORBIDDEN_EVENT_KEYS:
                continue
            out[ks] = _sanitize_event_value(v, depth=depth + 1)
        return out
    if isinstance(val, (list, tuple)):
        return [_sanitize_event_value(item, depth=depth + 1) for item in val[:64]]
    red = redact_secrets_only(str(val))
    return _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", red) if red else ""


class StudioEventHub:
    """In-memory bounded ring-buffer SSE hub with real-time revocation & state watcher."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        data_sources: StudioDataSources,
        *,
        max_events: int = DEFAULT_MAX_EVENTS,
        revocation_check_interval: float = 1.5,
        keepalive_interval: float = DEFAULT_KEEPALIVE_SEC,
        watcher_interval: float = DEFAULT_WATCHER_INTERVAL_SEC,
        max_streams_per_session: int = MAX_STREAMS_PER_SESSION,
        max_streams_global: int = MAX_STREAMS_GLOBAL,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.max_events = max(1, int(max_events))
        self.revocation_check_interval = max(0.05, float(revocation_check_interval))
        self.keepalive_interval = max(0.5, float(keepalive_interval))
        self.watcher_interval = float(watcher_interval)
        self.max_streams_per_session = max(1, int(max_streams_per_session))
        self.max_streams_global = max(1, int(max_streams_global))

        self._events: deque[tuple[int, str, dict[str, Any]]] = deque()
        self._next_seq: int = 1
        self._dropped_before_seq: int = 0
        self._active_streams: dict[int, dict[str, Any]] = {}
        self._watcher_task: asyncio.Task[Any] | None = None
        self._stopped: bool = False
        self._last_fp: tuple[Any, Any, Any] | None = None

        self.auth_mgr.add_revoke_listener(self._on_auth_revoked)

    # ------------------------------------------------------------------ Lifecycle & Watcher
    def start_watcher(self) -> None:
        if self._stopped or self.watcher_interval <= 0:
            return
        if self._watcher_task is None or self._watcher_task.done():
            self._watcher_task = asyncio.create_task(self._watch_state_loop())

    def _compute_fingerprints(self) -> tuple[Any, Any, Any]:
        bus_dir = self.data_sources.bus_dir
        bots_fp: list[tuple[str, int, int]] = []
        for fn in ("roster.json", "team_config.json"):
            p = bus_dir / fn
            try:
                st = p.stat()
                bots_fp.append((fn, st.st_mtime_ns, st.st_size))
            except OSError:
                bots_fp.append((fn, 0, 0))

        jobs_dir = bus_dir / "jobs"
        jobs_count = 0
        jobs_max_mt = 0
        jobs_sum_sz = 0
        try:
            if jobs_dir.is_dir():
                for ent in os.scandir(jobs_dir):
                    if ent.name.endswith(".json") and not ent.name.endswith(".tmp"):
                        try:
                            st = ent.stat()
                            jobs_count += 1
                            if st.st_mtime_ns > jobs_max_mt:
                                jobs_max_mt = st.st_mtime_ns
                            jobs_sum_sz += st.st_size
                        except OSError:
                            continue
        except OSError:
            pass
        jobs_fp = (jobs_count, jobs_max_mt, jobs_sum_sz)

        sched_p = self.data_sources.schedules_file
        try:
            st = sched_p.stat()
            sched_fp = (st.st_mtime_ns, st.st_size)
        except OSError:
            sched_fp = (0, 0)

        return (tuple(bots_fp), jobs_fp, sched_fp)

    async def _watch_state_loop(self) -> None:
        last_warn_ts = 0.0

        def _warn_throttled(stage: str, exc: Exception) -> None:
            nonlocal last_warn_ts
            now_m = time.monotonic()
            if last_warn_ts == 0.0 or (now_m - last_warn_ts) >= 30.0:
                log.warning(
                    "EventHub watcher %s error (continuing): %s",
                    stage,
                    type(exc).__name__,
                )
                last_warn_ts = now_m

        try:
            while not self._stopped:
                await asyncio.sleep(self.watcher_interval)
                if self._stopped or not self._active_streams:
                    continue
                try:
                    fp = self._compute_fingerprints()
                    if self._last_fp is None:
                        self._last_fp = fp
                        continue
                    prev_bots, prev_jobs, prev_sched = self._last_fp
                    cur_bots, cur_jobs, cur_sched = fp
                    self._last_fp = fp

                    if cur_bots != prev_bots:
                        try:
                            binfo = self.data_sources.get_bots()
                            self.publish(
                                "bots_updated",
                                {
                                    "total": int(binfo.get("total") or 0),
                                    "online": int(binfo.get("online") or 0),
                                    "busy": int(binfo.get("busy") or 0),
                                    "source": "watcher",
                                },
                            )
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            _warn_throttled("bots", exc)
                    if cur_jobs != prev_jobs:
                        try:
                            jinfo = self.data_sources.get_jobs(limit=1)
                            self.publish(
                                "job_updated",
                                {
                                    "total": int(jinfo.get("total") or 0),
                                    "counts": dict(jinfo.get("counts") or {}),
                                    "source": "watcher",
                                },
                            )
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            _warn_throttled("jobs", exc)
                    if cur_sched != prev_sched:
                        try:
                            sinfo = self.data_sources.get_schedules()
                            self.publish(
                                "schedule_updated",
                                {
                                    "total": int(sinfo.get("total") or 0),
                                    "active": int(sinfo.get("active") or 0),
                                    "paused": int(sinfo.get("paused") or 0),
                                    "source": "watcher",
                                },
                            )
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            _warn_throttled("schedules", exc)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    _warn_throttled("loop", exc)
        except asyncio.CancelledError:
            return

    # ------------------------------------------------------------------ Publishing & Framing
    @staticmethod
    def _format_sse_frame(event_name: str, data: dict[str, Any], seq: int | None = None) -> bytes:
        raw_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        encoded_json = raw_json.encode("utf-8")
        if len(encoded_json) > MAX_SSE_EVENT_BYTES - 128:
            compact: dict[str, Any] = {"truncated": True}
            for k in (
                "action",
                "job_id",
                "group_id",
                "schedule_id",
                "status",
                "count",
                "total",
                "online",
                "busy",
                "active",
                "paused",
                "reason",
                "code",
                "source",
            ):
                if k in data:
                    compact[k] = data[k]
            for text_k in ("message", "error", "label", "summary"):
                if text_k in data and isinstance(data[text_k], str):
                    clipped, _ = truncate_utf8_bytes(data[text_k], MAX_SSE_EVENT_BYTES - 512)
                    compact[text_k] = clipped
            raw_json = json.dumps(compact, ensure_ascii=False, separators=(",", ":"))
            if len(raw_json.encode("utf-8")) > MAX_SSE_EVENT_BYTES - 128:
                raw_json = json.dumps(
                    {"truncated": True, "event": str(event_name)[:48]},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )

        lines: list[str] = []
        if seq is not None and seq > 0:
            lines.append(f"id: {seq}")
        lines.append(f"event: {event_name}")
        lines.append(f"data: {raw_json}")
        return ("\n".join(lines) + "\n\n").encode("utf-8")

    def publish(self, event_type: str, payload: dict[str, Any] | None = None) -> int:
        """Sanitize, bound, append to ring buffer, and wake all active subscribers."""
        clean_type = str(event_type or "message").strip()[:64] or "message"
        sanitized = _sanitize_event_value(payload if isinstance(payload, dict) else {})
        if not isinstance(sanitized, dict):
            sanitized = {}
        sanitized.setdefault("ts", int(time.time()))

        seq = self._next_seq
        self._next_seq += 1
        self._events.append((seq, clean_type, sanitized))
        while len(self._events) > self.max_events:
            old_seq, _old_type, _old_data = self._events.popleft()
            self._dropped_before_seq = max(self._dropped_before_seq, old_seq)

        for entry in list(self._active_streams.values()):
            if not entry.get("closing"):
                ev = entry.get("wakeup")
                if isinstance(ev, asyncio.Event):
                    ev.set()
        return seq

    # ------------------------------------------------------------------ Revocation & Teardown
    @staticmethod
    async def _close_downstream_sse_bounded(
        entry: dict[str, Any],
        *,
        error_reason: str | None = None,
        error_code: str | None = None,
        extra_role: str | None = None,
        timeout_sec: float = 0.8,
    ) -> None:
        resp: web.StreamResponse | None = entry.get("stream_resp")
        if resp is None:
            return
        if entry.get("downstream_closing"):
            return
        entry["downstream_closing"] = True
        if error_reason:
            err_body: dict[str, Any] = {"source": "studio_auth", "error": error_reason}
            if error_code:
                err_body["code"] = error_code
            if extra_role:
                err_body["role"] = extra_role
            frame = (
                "event: auth_error\n"
                f"data: {json.dumps(err_body, ensure_ascii=False, separators=(',', ':'))}\n\n"
            ).encode("utf-8")
            try:
                await asyncio.wait_for(resp.write(frame), timeout=min(0.35, timeout_sec))
            except Exception:
                pass
        try:
            await asyncio.wait_for(resp.write_eof(), timeout=min(0.45, timeout_sec))
        except Exception:
            try:
                req = entry.get("request")
                transport = getattr(req, "transport", None) if req is not None else None
                if transport is not None and not transport.is_closing():
                    transport.close()
            except Exception:
                pass

    async def _terminate_stream_entry(
        self,
        entry: dict[str, Any],
        *,
        error_reason: str = "访问权限已被撤销",
        error_code: str | None = None,
        extra_role: str | None = None,
        await_downstream: bool = True,
    ) -> None:
        if entry.get("closing"):
            return
        entry["closing"] = True
        entry["close_reason"] = error_reason
        entry["close_code"] = error_code
        entry["close_role"] = extra_role
        ev = entry.get("wakeup")
        if isinstance(ev, asyncio.Event):
            ev.set()
        coro = self._close_downstream_sse_bounded(
            entry,
            error_reason=error_reason,
            error_code=error_code,
            extra_role=extra_role,
            timeout_sec=0.8,
        )
        if await_downstream:
            await coro
        else:
            entry["close_task"] = asyncio.create_task(coro)

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
            targets = [
                e for e in list(self._active_streams.values())
                if e.get("username_key") == username_key
                and e.get("session_hash") != exclude_session_hash
                and not e.get("closing")
            ]
        elif session_hash:
            targets = [
                e for e in list(self._active_streams.values())
                if e.get("session_hash") == session_hash and not e.get("closing")
            ]
        elif bot and user_id is not None:
            targets = [
                e for e in list(self._active_streams.values())
                if e.get("bot") == bot and e.get("user_id") == user_id and not e.get("closing")
            ]
        else:
            targets = []

        if not targets:
            return

        for e in targets:
            e["closing"] = True
            e["close_reason"] = "访问权限已被撤销"
            ev = e.get("wakeup")
            if isinstance(ev, asyncio.Event):
                ev.set()

        for e in targets:
            if not e.get("downstream_closing") and e.get("close_task") is None:
                e["close_task"] = asyncio.create_task(
                    self._close_downstream_sse_bounded(
                        e, error_reason="访问权限已被撤销", timeout_sec=0.8
                    )
                )

    async def close_all(self) -> None:
        self._stopped = True
        wt = self._watcher_task
        self._watcher_task = None
        if wt is not None and not wt.done():
            wt.cancel()
            try:
                await asyncio.wait_for(wt, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass

        entries = list(self._active_streams.values())
        for e in entries:
            e["closing"] = True
            e["close_reason"] = "服务正在关闭"
            ev = e.get("wakeup")
            if isinstance(ev, asyncio.Event):
                ev.set()
        await asyncio.gather(
            *(
                self._close_downstream_sse_bounded(
                    e, error_reason="服务正在关闭", timeout_sec=0.8
                )
                for e in entries
            ),
            return_exceptions=True,
        )
        self._active_streams.clear()

    # ------------------------------------------------------------------ GET /api/events
    async def handle_events(self, request: web.Request) -> web.StreamResponse:
        # 1. Authenticate session cookie + live RBAC + must_change_password=False
        # Both `admin` and `readonly` are allowed to subscribe.
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            return studio_auth_error(err_auth, status=status_code)

        # 2. Atomic synchronous concurrency reservation BEFORE any `await` (zero TOCTOU)
        session_hash = str(sess["session_hash"])
        if len(self._active_streams) >= self.max_streams_global:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "全局实时事件流并发数已达上限"},
                status=429,
            )
        per_sess_cnt = sum(
            1 for e in self._active_streams.values() if e.get("session_hash") == session_hash
        )
        if per_sess_cnt >= self.max_streams_per_session:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "当前会话实时事件流并发数已达上限"},
                status=429,
            )

        initial_role = str(sess.get("role") or "")
        wakeup = asyncio.Event()
        entry: dict[str, Any] = {
            "request": request,
            "stream_resp": None,
            "session_hash": session_hash,
            "username_key": sess.get("username_key"),
            "bot": str(sess["bot"]),
            "user_id": int(sess["user_id"]),
            "initial_role": initial_role,
            "closing": False,
            "downstream_closing": False,
            "close_task": None,
            "wakeup": wakeup,
        }
        entry_key = id(entry)
        self._active_streams[entry_key] = entry

        try:
            # Parse Last-Event-ID / after_seq before preparing stream
            raw_after = request.query.get("after_seq")
            if raw_after is None or not raw_after.strip():
                raw_after = request.headers.get("Last-Event-ID")
            has_resume = raw_after is not None and str(raw_after).strip() != ""
            after_seq = 0
            if has_resume:
                try:
                    after_seq = max(0, int(str(raw_after).strip()))
                except ValueError:
                    after_seq = 0

            # Re-verify live auth & non-revocation BEFORE committing 200 SSE headers
            if entry.get("closing"):
                return studio_auth_error("访问权限已被撤销", status=403)
            ok_pre, live_pre, err_pre, _sc_pre = await self.auth_mgr.authenticate_session_hash(
                session_hash
            )
            if entry.get("closing") or not ok_pre or not live_pre:
                reason = (
                    "password_change_required"
                    if err_pre == "password_change_required"
                    else "访问权限已被撤销"
                )
                return studio_auth_error(reason, status=403)
            if initial_role == "admin" and live_pre.get("role") != "admin":
                return studio_auth_error("权限已降级，实时事件流已拒绝", status=403)

            csp_val = (
                "default-src 'self'; script-src 'self' https://telegram.org; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                "font-src 'self' data:; connect-src 'self' ws: wss:; "
                "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
                if self.auth_mgr.auth_mode == "legacy"
                else "default-src 'self'; script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                "font-src 'self' data:; connect-src 'self' ws: wss:; "
                "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
            )
            sse_resp = web.StreamResponse(
                status=200,
                headers={
                    "Content-Type": "text/event-stream; charset=utf-8",
                    "Cache-Control": "no-store, max-age=0",
                    "X-Accel-Buffering": "no",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                    "Content-Security-Policy": csp_val,
                },
            )
            await sse_resp.prepare(request)
            entry["stream_resp"] = sse_resp

            if entry.get("closing"):
                await self._close_downstream_sse_bounded(
                    entry, error_reason="访问权限已被撤销", timeout_sec=0.8
                )
                return sse_resp

            last_write_ts = time.monotonic()

            async def _verify_live_session() -> bool:
                if entry.get("closing"):
                    return False
                ok_live, live_sess, err_live, _sc = await self.auth_mgr.authenticate_session_hash(
                    session_hash
                )
                if not ok_live or not live_sess:
                    reason = (
                        "password_change_required"
                        if err_live == "password_change_required"
                        else "访问权限已被撤销"
                    )
                    await self._terminate_stream_entry(
                        entry, error_reason=reason, await_downstream=True
                    )
                    return False
                live_role = str(live_sess.get("role") or "")
                if initial_role == "admin" and live_role != "admin":
                    await self._terminate_stream_entry(
                        entry,
                        error_reason="权限已降级，实时事件流已断开",
                        error_code="role_changed",
                        extra_role=live_role,
                        await_downstream=True,
                    )
                    return False
                return True

            async def _safe_write_frame(frame: bytes) -> bool:
                nonlocal last_write_ts
                if entry.get("closing"):
                    return False
                if not await _verify_live_session():
                    return False
                if entry.get("closing"):
                    return False
                try:
                    await sse_resp.write(frame)
                    last_write_ts = time.monotonic()
                    return True
                except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError, OSError):
                    entry["closing"] = True
                    return False

            # Initial replay or connected handshake frame
            latest_seq = self._next_seq - 1
            if has_resume:
                if self._dropped_before_seq > 0 and after_seq < self._dropped_before_seq:
                    earliest = self._events[0][0] if self._events else self._next_seq
                    resync_frame = self._format_sse_frame(
                        "resync_required",
                        {
                            "reason": "buffer_overflow",
                            "dropped_before_seq": self._dropped_before_seq,
                            "earliest_available_seq": earliest,
                            "latest_seq": latest_seq,
                        },
                        seq=latest_seq if latest_seq > 0 else None,
                    )
                    if not await _safe_write_frame(resync_frame):
                        return sse_resp
                    cursor = latest_seq
                else:
                    cursor = after_seq
                    replay_batch = [
                        (s, t, d) for (s, t, d) in list(self._events) if s > cursor
                    ]
                    if not replay_batch:
                        # Still flush a connected event so HTTP headers reach client promptly
                        if not await _safe_write_frame(
                            self._format_sse_frame(
                                "connected",
                                {"ok": True, "latest_seq": latest_seq, "role": initial_role},
                                seq=latest_seq if latest_seq > 0 else None,
                            )
                        ):
                            return sse_resp
                    for s, t, d in replay_batch:
                        if not await _safe_write_frame(self._format_sse_frame(t, d, seq=s)):
                            return sse_resp
                        cursor = s
            else:
                cursor = latest_seq
                if not await _safe_write_frame(
                    self._format_sse_frame(
                        "connected",
                        {"ok": True, "latest_seq": latest_seq, "role": initial_role},
                        seq=latest_seq if latest_seq > 0 else None,
                    )
                ):
                    return sse_resp

            # Live push + revocation watchdog + keepalive loop
            wait_step = min(self.revocation_check_interval, self.keepalive_interval)
            while not entry.get("closing") and not self._stopped:
                wakeup.clear()

                # Check ring buffer overflow relative to slow subscriber cursor
                if self._dropped_before_seq > 0 and cursor < self._dropped_before_seq:
                    cur_latest = self._next_seq - 1
                    earliest = self._events[0][0] if self._events else self._next_seq
                    if not await _safe_write_frame(
                        self._format_sse_frame(
                            "resync_required",
                            {
                                "reason": "buffer_overflow",
                                "dropped_before_seq": self._dropped_before_seq,
                                "earliest_available_seq": earliest,
                                "latest_seq": cur_latest,
                            },
                            seq=cur_latest if cur_latest > 0 else None,
                        )
                    ):
                        return sse_resp
                    cursor = cur_latest
                    continue

                pending_batch = [(s, t, d) for (s, t, d) in list(self._events) if s > cursor]
                if pending_batch:
                    for s, t, d in pending_batch:
                        if not await _safe_write_frame(self._format_sse_frame(t, d, seq=s)):
                            return sse_resp
                        cursor = s
                    continue

                try:
                    await asyncio.wait_for(wakeup.wait(), timeout=wait_step)
                except asyncio.TimeoutError:
                    pass

                if entry.get("closing") or self._stopped:
                    break
                if not await _verify_live_session():
                    return sse_resp
                if (time.monotonic() - last_write_ts) >= self.keepalive_interval:
                    if not await _safe_write_frame(b": keepalive\n\n"):
                        return sse_resp

            return sse_resp
        finally:
            self._active_streams.pop(entry_key, None)
            entry["closing"] = True
            close_task = entry.get("close_task")
            if close_task is not None and not close_task.done():
                try:
                    await asyncio.wait_for(close_task, timeout=0.9)
                except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                    pass
            if entry.get("stream_resp") is not None and not entry.get("downstream_closing"):
                await self._close_downstream_sse_bounded(
                    entry,
                    error_reason=entry.get("close_reason"),
                    error_code=entry.get("close_code"),
                    extra_role=entry.get("close_role"),
                    timeout_sec=0.8,
                )
