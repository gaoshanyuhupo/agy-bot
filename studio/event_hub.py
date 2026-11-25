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
import math
import os
from pathlib import Path
import sqlite3
import time
from typing import Any

from aiohttp import web

from .auth import StudioAuthManager, studio_auth_error
from .data_sources import (
    StudioDataSources,
    _SENSITIVE_HOST_PATH_RE,
    _sanitize_slug,
    map_group_history_entry_to_room_message,
    redact_secrets_only,
    truncate_utf8_bytes,
)
import studio_ipc

log = logging.getLogger("agy-studio.events")

DEFAULT_MAX_EVENTS = 256
MAX_SSE_EVENT_BYTES = 16 * 1024
MAX_STREAMS_PER_SESSION = 4
MAX_STREAMS_GLOBAL = 32
DEFAULT_KEEPALIVE_SEC = 15.0
DEFAULT_WATCHER_INTERVAL_SEC = 0.5

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
    "mirror_chat_id",
    "mirror_thread_id",
    "origin_chat_id",
    "origin_thread_id",
    "origin_msg_id",
    "scope_key",
    "turn_id",
    "owner_user_id",
    "user_id",
    "prompt",
    "response",
    "content",
    "thinking",
    "password",
    "password_hash",
    "csrf_token",
    "cookie",
    "token",
    "secret",
    "api_key",
    "authorization",
    "access_token",
    "refresh_token",
    "id_token",
    "code_verifier",
    "oauth_state",
    "profile_dir",
    "token_hash",
    "token_records",
    "salt",
    "raw_token",
    "plaintext_token",
    "bearer_token",
})

_VALID_CHAT_SYNC_SOURCES = frozenset({"web", "tg"})
_VALID_CHAT_SYNC_STATUSES = frozenset({"running", "done", "aborted", "error"})


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
            kl = ks.strip().lower()
            if kl in _FORBIDDEN_EVENT_KEYS or kl.replace("-", "_") in _FORBIDDEN_EVENT_KEYS:
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
        self._last_fp: tuple[Any, Any, Any, Any] | None = None
        self._last_chat_sync: dict[str, tuple[int, int, bytes]] | None = None
        self._mirror_key: tuple[int, int | None] | None = None
        self._mirror_file_fp: tuple[int, int, int] | None = None
        self._mirror_last_seq: int = 0
        self._mirror_published_order: deque[int] = deque()
        self._mirror_published_set: set[int] = set()
        self._mirror_bot_reply_seq: dict[str, int] = {}
        self._last_jobs_snapshot: dict[str, tuple[str, str]] = {}
        self._last_bots_busy: dict[str, tuple[bool, str, int]] = {}

        self.auth_mgr.add_revoke_listener(self._on_auth_revoked)

    # ------------------------------------------------------------------ Lifecycle & Watcher
    def start_watcher(self) -> None:
        if self._stopped or self.watcher_interval <= 0:
            return
        if self._watcher_task is None or self._watcher_task.done():
            self._watcher_task = asyncio.create_task(self._watch_state_loop())

    def _compute_fingerprints(self) -> tuple[Any, Any, Any, Any]:
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

        approvals_dir = bus_dir / "studio_approvals"
        att_count = 0
        att_max_mt = 0
        att_sum_sz = 0
        try:
            if approvals_dir.is_dir():
                for ent in os.scandir(approvals_dir):
                    if ent.name.endswith(".json") and not ent.name.endswith(".tmp") and not ent.name.startswith("."):
                        try:
                            st = ent.stat()
                            att_count += 1
                            if st.st_mtime_ns > att_max_mt:
                                att_max_mt = st.st_mtime_ns
                            att_sum_sz += st.st_size
                        except OSError:
                            continue
        except OSError:
            pass
        approvals_fp = (att_count, att_max_mt, att_sum_sz)

        return (tuple(bots_fp), jobs_fp, sched_fp, approvals_fp)

    def _read_chat_sync_snapshot(self) -> dict[str, tuple[int, int, bytes]]:
        """Read bounded raw snapshots of `BUS_DIR/chat_sync/*.json` for change detection."""
        sync_dir = self.data_sources.bus_dir / "chat_sync"
        snap: dict[str, tuple[int, int, bytes]] = {}
        try:
            if not sync_dir.is_dir():
                return snap
            for ent in os.scandir(sync_dir):
                name = ent.name
                if name.startswith(".") or not name.endswith(".json") or name.endswith(".tmp"):
                    continue
                try:
                    st = ent.stat()
                    if not ent.is_file() or st.st_size > 16384:
                        continue
                    with open(ent.path, "rb") as fh:
                        raw = fh.read(8192)
                    snap[name] = (st.st_mtime_ns, st.st_size, raw)
                except OSError:
                    continue
        except OSError:
            pass
        return snap

    def _is_excluded_sync_cid(self, cid: str) -> bool:
        """Return True if `cid` is invalid, internal, observer-sandbox, pure-llm, scheduled, or delegation."""
        ok_cid, _err, _sc = studio_ipc.validate_resume_cid(
            cid,
            summaries_db=self.data_sources.summaries_db,
            meta_file=self.data_sources.meta_file,
        )
        if not ok_cid:
            return True

        if self.data_sources.summaries_db.is_file():
            try:
                conn = sqlite3.connect(
                    f"file:{self.data_sources.summaries_db}?mode=ro", uri=True, timeout=1.5
                )
                try:
                    row = conn.execute(
                        "SELECT preview FROM conversation_summaries WHERE conversation_id = ?",
                        (cid,),
                    ).fetchone()
                finally:
                    conn.close()
                if row is not None:
                    prev_s = str(row[0] or "")
                    if "[ACB_SCHEDULED_TASK" in prev_s or "[ACB_TEAM_DELEGATION" in prev_s:
                        return True
            except Exception:
                pass

        if self.data_sources.meta_file.is_file():
            try:
                raw_meta = self.data_sources.meta_file.read_text(encoding="utf-8", errors="replace")
                meta_doc = json.loads(raw_meta)
                convs = meta_doc.get("conversations") if isinstance(meta_doc, dict) else {}
                entry = convs.get(cid) if isinstance(convs, dict) else None
                if isinstance(entry, dict):
                    s = entry.get("summary") if isinstance(entry.get("summary"), dict) else {}
                    prev_s = str(s.get("Preview") or "")
                    if "[ACB_SCHEDULED_TASK" in prev_s or "[ACB_TEAM_DELEGATION" in prev_s:
                        return True
            except Exception:
                pass

        return False

    def _publish_chat_sync_doc(self, fname: str, raw_bytes: bytes) -> None:
        """Parse a `chat_sync/*.json` signal and emit a strictly allowlisted `session_updated` event."""
        try:
            doc = json.loads(raw_bytes.decode("utf-8"))
        except Exception:
            return
        if not isinstance(doc, dict):
            return

        cid = str(doc.get("cid") or "").strip()
        if not studio_ipc.is_valid_cid(cid):
            return
        status_raw = str(doc.get("status") or "").strip().lower()
        if status_raw not in _VALID_CHAT_SYNC_STATUSES:
            return

        source_raw = str(doc.get("source") or "").strip().lower()
        source = source_raw if source_raw in _VALID_CHAT_SYNC_SOURCES else "tg"

        bot_raw = doc.get("bot") or Path(fname).stem
        bot_slug = _sanitize_slug(str(bot_raw), max_len=64)

        upd_raw = doc.get("updated_at")
        if isinstance(upd_raw, (int, float)) and not isinstance(upd_raw, bool) and math.isfinite(float(upd_raw)):
            updated_at = round(float(upd_raw), 3)
        else:
            updated_at = round(time.time(), 3)

        # Emit sanitized room_activity (ZERO cid/chat_id/paths) before session exclusion check
        # so group/delegation turns still drive live Thinking/Running indicators in Team panel.
        if bot_slug:
            is_running = status_raw == "running"
            self.publish(
                "room_activity",
                {
                    "room_id": "lobby",
                    "source": "chat_sync",
                    "bot": bot_slug,
                    "phase": "thinking" if is_running else "idle",
                    "busy": is_running,
                    "stage_label": "正在思考 / 调度" if is_running else "",
                    "updated_at": updated_at,
                },
            )

        if self._is_excluded_sync_cid(cid):
            return

        # Strict allowlist payload only: NEVER forward chat_id, thread_id, turn_id, prompt, response, or paths
        self.publish(
            "session_updated",
            {
                "cid": cid,
                "bot": bot_slug,
                "source": source,
                "status": status_raw,
                "busy": status_raw == "running",
                "updated_at": updated_at,
            },
        )

    @staticmethod
    def _norm_mirror_key(chat_id: int, thread_id: int | None) -> tuple[int, int | None]:
        cid = int(chat_id or 0)
        if thread_id is None or isinstance(thread_id, bool):
            tid: int | None = None
        else:
            try:
                tv = int(thread_id)
                tid = tv if tv > 0 else None
            except (TypeError, ValueError):
                tid = None
        return (cid, tid)

    @staticmethod
    def _norm_mirror_bot(bot: str | None) -> str:
        return str(bot or "").strip().lstrip("@").strip().lower()

    def _reset_mirror_state(self) -> None:
        self._mirror_key = None
        self._mirror_file_fp = None
        self._mirror_last_seq = 0
        self._mirror_published_order.clear()
        self._mirror_published_set.clear()
        self._mirror_bot_reply_seq.clear()

    def _record_mirror_published_seq(self, seq: int) -> None:
        if seq <= 0 or seq in self._mirror_published_set:
            return
        self._mirror_published_set.add(seq)
        self._mirror_published_order.append(seq)
        while len(self._mirror_published_order) > 256:
            old = self._mirror_published_order.popleft()
            self._mirror_published_set.discard(old)

    def ensure_mirror_baseline(self, chat_id: int, thread_id: int | None) -> int:
        """Anchor `_mirror_key` & `_mirror_last_seq` to disk max_seq before IPC; never regress an existing anchor."""
        mkey = self._norm_mirror_key(chat_id, thread_id)
        cid, tid = mkey
        if cid >= 0:
            return 0
        if self._mirror_key == mkey:
            return self._mirror_last_seq
        _entries, max_seq = self.data_sources.read_tg_mirror_history(cid, tid)
        self._mirror_key = mkey
        self._mirror_file_fp = None
        self._mirror_last_seq = max_seq
        self._mirror_published_order.clear()
        self._mirror_published_set.clear()
        self._mirror_bot_reply_seq.clear()
        return max_seq

    def note_mirror_seq_published(self, chat_id: int, thread_id: int | None, seq: int) -> bool:
        """Atomically claim HTTP publication of a TG mirror `seq`; returns False if already emitted."""
        mkey = self._norm_mirror_key(chat_id, thread_id)
        cid = mkey[0]
        seq_i = int(seq or 0)
        if cid >= 0 or seq_i <= 0:
            return False
        if self._mirror_key != mkey:
            self._mirror_key = mkey
            self._mirror_file_fp = None
            self._mirror_last_seq = max(0, seq_i - 1)
            self._mirror_published_order.clear()
            self._mirror_published_set.clear()
            self._mirror_bot_reply_seq.clear()
        if seq_i <= self._mirror_last_seq or seq_i in self._mirror_published_set:
            return False
        self._record_mirror_published_seq(seq_i)
        return True

    def has_mirror_bot_reply_after(
        self,
        chat_id: int,
        thread_id: int | None,
        bot: str,
        seq: int,
    ) -> bool:
        """Return True if watcher already emitted a reply from `bot` with seq > `seq` on this mirror."""
        mkey = self._norm_mirror_key(chat_id, thread_id)
        seq_i = int(seq or 0)
        if mkey[0] >= 0 or seq_i <= 0 or self._mirror_key != mkey:
            return False
        bot_key = self._norm_mirror_bot(bot)
        if not bot_key:
            return False
        return self._mirror_bot_reply_seq.get(bot_key, 0) > seq_i

    def _poll_tg_mirror_history(self, *, bootstrap: bool = False) -> None:
        """Incrementally watch `group_history/<chat_id>.json` and emit `room_message` SSE events (strictly read-only)."""
        mirror = self.data_sources.resolve_tg_mirror()
        if not mirror.get("bound"):
            self._reset_mirror_state()
            return

        mkey = self._norm_mirror_key(int(mirror["chat_id"]), mirror["thread_id"])
        cid, tid = mkey
        hist_path = self.data_sources.bus_dir / "group_history" / f"{cid}.json"
        try:
            st = hist_path.stat()
            fp = (st.st_ino, st.st_mtime_ns, st.st_size)
        except OSError:
            fp = (0, 0, 0)

        if self._mirror_key != mkey:
            entries, max_seq = self.data_sources.read_tg_mirror_history(cid, tid)
            self._mirror_key = mkey
            self._mirror_file_fp = fp
            self._mirror_last_seq = max_seq
            self._mirror_published_order.clear()
            self._mirror_published_set.clear()
            self._mirror_bot_reply_seq.clear()
            for e in entries[-64:]:
                self._record_mirror_published_seq(int(e.get("seq") or 0))
            return

        if fp == self._mirror_file_fp:
            return
        self._mirror_file_fp = fp
        if fp == (0, 0, 0):
            return

        entries, _max_seq = self.data_sources.read_tg_mirror_history(cid, tid)
        for raw_entry in entries:
            seq_val = int(raw_entry.get("seq") or 0)
            if seq_val <= self._mirror_last_seq:
                continue
            self._mirror_last_seq = max(self._mirror_last_seq, seq_val)
            if seq_val in self._mirror_published_set:
                continue
            self._record_mirror_published_seq(seq_val)
            msg = map_group_history_entry_to_room_message(raw_entry, room_id="lobby")
            ev_text, _ = truncate_utf8_bytes(str(msg.get("content") or ""), 12 * 1024)
            ev_payload: dict[str, Any] = {
                "room_id": "lobby",
                "seq": msg["seq"],
                "msg_id": msg["msg_id"],
                "ts": msg["ts"],
                "sender_type": msg["sender_type"],
                "sender": msg["sender"],
                "sender_role": msg["sender_role"],
                "source": msg["source"],
                "text": ev_text,
                "truncated": bool(msg.get("truncated")),
                "mentions": list(msg.get("mentions") or []),
                "chain_id": "",
                "hop": 0,
                "status": "done",
                "blocked_reason": "",
            }
            if msg.get("stage_tag"):
                ev_payload["stage_tag"] = str(msg["stage_tag"])
            if msg.get("job_id"):
                ev_payload["job_id"] = str(msg["job_id"])
            if msg.get("attachments"):
                ev_payload["attachments"] = list(msg["attachments"])
            if msg.get("context_files"):
                ev_payload["context_files"] = list(msg["context_files"])
            self.publish("room_message", ev_payload)
            if msg["sender_type"] == "bot" and msg["sender"]:
                bot_key = self._norm_mirror_bot(msg["sender"])
                if bot_key and seq_val > self._mirror_bot_reply_seq.get(bot_key, 0):
                    self._mirror_bot_reply_seq[bot_key] = seq_val
                self.publish(
                    "room_typing",
                    {
                        "room_id": "lobby",
                        "bot": msg["sender"],
                        "typing": False,
                        "chain_id": "",
                        "hop": 0,
                    },
                )
                self.publish(
                    "room_activity",
                    {
                        "room_id": "lobby",
                        "source": "group_history",
                        "bot": msg["sender"],
                        "role": msg["sender_role"],
                        "phase": str(msg.get("stage_tag") or "reply"),
                        "job_id": str(msg.get("job_id") or ""),
                    },
                )
            elif msg["sender_type"] == "human":
                self.publish(
                    "room_activity",
                    {
                        "room_id": "lobby",
                        "source": msg["source"],
                        "phase": "received",
                        "target_bots": list(msg.get("mentions") or []),
                        "stage_label": "收到用户指令，等待调度处理",
                    },
                )

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
                    cur_chat_sync = self._read_chat_sync_snapshot()
                    if self._last_fp is None:
                        self._last_fp = fp
                        self._last_chat_sync = cur_chat_sync
                        try:
                            b_init = self.data_sources.get_bots()
                            self._last_bots_busy = {
                                str(b.get("handle") or "").lower(): (
                                    bool(b.get("busy")),
                                    str(b.get("current_job") or ""),
                                    int(b.get("queue_depth") or 0),
                                )
                                for b in (b_init.get("bots") or [])
                                if b.get("handle")
                            }
                            j_init = self.data_sources.get_jobs_activity(limit=16)
                            self._last_jobs_snapshot = {
                                str(j.get("job_id") or ""): (
                                    str(j.get("status") or ""),
                                    str(j.get("progress") or ""),
                                )
                                for j in j_init
                                if j.get("job_id")
                            }
                        except Exception:
                            pass
                        try:
                            self._poll_tg_mirror_history(bootstrap=True)
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            _warn_throttled("tg_mirror_bootstrap", exc)
                        continue
                    prev_bots, prev_jobs, prev_sched, prev_approvals = self._last_fp
                    cur_bots, cur_jobs, cur_sched, cur_approvals = fp
                    prev_chat_sync = self._last_chat_sync or {}
                    self._last_fp = fp
                    self._last_chat_sync = cur_chat_sync

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
                            next_bots_busy: dict[str, tuple[bool, str, int]] = {}
                            for b in binfo.get("bots") or []:
                                h = str(b.get("handle") or "").lower()
                                if not h:
                                    continue
                                tup = (
                                    bool(b.get("busy")),
                                    str(b.get("current_job") or ""),
                                    int(b.get("queue_depth") or 0),
                                )
                                next_bots_busy[h] = tup
                                if self._last_bots_busy.get(h) != tup:
                                    b_busy, b_job, b_q = tup
                                    b_role = str(b.get("role") or "worker")
                                    if b_busy:
                                        b_phase = "running" if b_job else "thinking"
                                        b_stage = "正在处理派单" if b_job else (
                                            "正在思考 / 调度" if b_role == "coordinator" else "正在执行任务"
                                        )
                                    elif b_q > 0:
                                        b_phase = "queued"
                                        b_stage = f"排队等待中（{b_q} 单）"
                                    else:
                                        b_phase = "idle"
                                        b_stage = ""
                                    self.publish(
                                        "room_activity",
                                        {
                                            "room_id": "lobby",
                                            "source": "bots_watcher",
                                            "bot": h,
                                            "display_name": str(b.get("display_name") or h),
                                            "role": b_role,
                                            "phase": b_phase,
                                            "busy": b_busy,
                                            "job_id": b_job,
                                            "queue_depth": b_q,
                                            "stage_label": b_stage,
                                        },
                                    )
                            self._last_bots_busy = next_bots_busy
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            _warn_throttled("bots", exc)
                    if cur_jobs != prev_jobs:
                        try:
                            jinfo = self.data_sources.get_jobs(limit=1)
                            jact = self.data_sources.get_jobs_activity(limit=16)
                            changed_jobs: list[tuple[dict[str, Any], str]] = []
                            next_jobs_snap: dict[str, tuple[str, str]] = {}
                            for j in jact:
                                jid = str(j.get("job_id") or "")
                                if not jid:
                                    continue
                                st_s = str(j.get("status") or "")
                                prog_s = str(j.get("progress") or "")
                                tup = (st_s, prog_s)
                                next_jobs_snap[jid] = tup
                                prev_tup = self._last_jobs_snapshot.get(jid)
                                if prev_tup != tup:
                                    if prev_tup is not None and prev_tup[0] == "running" and st_s == "running" and prog_s != prev_tup[1]:
                                        j_phase = "tool_use"
                                    else:
                                        j_phase = st_s or "updated"
                                    changed_jobs.append((j, j_phase))
                            self._last_jobs_snapshot = next_jobs_snap

                            job_ev_payload: dict[str, Any] = {
                                "total": int(jinfo.get("total") or 0),
                                "counts": dict(jinfo.get("counts") or {}),
                                "source": "watcher",
                            }
                            if changed_jobs:
                                top_j, top_phase = changed_jobs[0]
                                job_ev_payload.update(
                                    {
                                        "job_id": top_j.get("job_id") or "",
                                        "bot": top_j.get("bot") or "",
                                        "status": top_j.get("status") or "",
                                        "label": top_j.get("label") or "",
                                        "phase": top_phase,
                                        "duration_s": top_j.get("duration_s"),
                                    }
                                )
                            self.publish("job_updated", job_ev_payload)

                            for cj, c_phase in changed_jobs[:6]:
                                self.publish(
                                    "room_activity",
                                    {
                                        "room_id": "lobby",
                                        "source": "jobs_watcher",
                                        "phase": c_phase,
                                        "job_id": cj.get("job_id") or "",
                                        "group_id": cj.get("group_id") or "",
                                        "bot": cj.get("bot") or "",
                                        "from_bot": cj.get("from_bot") or "",
                                        "status": cj.get("status") or "",
                                        "label": cj.get("label") or "",
                                        "stage_label": cj.get("progress") or "",
                                        "duration_s": cj.get("duration_s"),
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
                    if cur_approvals != prev_approvals:
                        try:
                            self.publish(
                                "attention_updated",
                                {
                                    "action": "watcher",
                                    "total_files": int(cur_approvals[0]),
                                    "source": "watcher",
                                },
                            )
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            _warn_throttled("approvals", exc)
                    if cur_chat_sync != prev_chat_sync:
                        try:
                            for fname, entry in sorted(cur_chat_sync.items()):
                                if entry != prev_chat_sync.get(fname):
                                    self._publish_chat_sync_doc(fname, entry[2])
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            _warn_throttled("chat_sync", exc)
                    try:
                        self._poll_tg_mirror_history(bootstrap=False)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        _warn_throttled("tg_mirror", exc)
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
                "cid",
                "bot",
                "job_id",
                "group_id",
                "schedule_id",
                "room_id",
                "seq",
                "msg_id",
                "sender_type",
                "sender",
                "sender_role",
                "chain_id",
                "hop",
                "blocked_reason",
                "typing",
                "stage_tag",
                "phase",
                "stage_label",
                "duration_s",
                "queue_depth",
                "from_bot",
                "display_name",
                "role",
                "item_id",
                "kind",
                "decision",
                "pending_count",
                "status",
                "count",
                "total",
                "online",
                "busy",
                "active",
                "paused",
                "updated_at",
                "reason",
                "code",
                "source",
            ):
                if k in data:
                    compact[k] = data[k]
            for text_k in ("message", "error", "label", "summary", "text"):
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
