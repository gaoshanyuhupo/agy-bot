"""Persistent FIFO job queue with atomic disk persistence, scope inspection, and selective cancellation.

Standalone-capable flat module (no top-level `import bridge`). When wired into
`bridge/bridge.py`, call `bind_host(bridge_module)` so dynamic config and
callbacks (`QUEUE_FILE`, `QUEUE_TTL_SEC`, `scope_key_for`, `log`, `send`,
`bot_bus`, `job_q`) resolve at call time without early binding or circular imports.
"""

from __future__ import annotations

import collections
import fcntl
import json
import os
import threading
import time
import uuid

try:
    import bot_bus as _default_bot_bus
except ImportError:
    from bridge import bot_bus as _default_bot_bus  # type: ignore[no-redef]

_host = None


def bind_host(host):
    """Bind the runtime bridge host module (or namespace) for lazy attribute resolution."""
    global _host
    _host = host
    return host


def _resolve_host(host=None):
    return host if host is not None else _host


def _default_scope_key_for(chat_id, thread_id=None):
    if thread_id is not None and str(thread_id).strip() not in ("", "0", "None"):
        return f"{chat_id}:{thread_id}"
    return str(chat_id)


def _host_scope_key_for(chat_id, thread_id=None, *, host=None):
    h = _resolve_host(host)
    fn = getattr(h, "scope_key_for", None) if h is not None else None
    if callable(fn):
        return fn(chat_id, thread_id)
    return _default_scope_key_for(chat_id, thread_id)


def _host_log(msg, *, host=None):
    h = _resolve_host(host)
    fn = getattr(h, "log", None) if h is not None else None
    if callable(fn):
        fn(msg)


def _host_bot_bus(*, host=None):
    h = _resolve_host(host)
    bb = getattr(h, "bot_bus", None) if h is not None else None
    return bb if bb is not None else _default_bot_bus


def _is_same_scope_or_readonly_child(active_scope, target_scope):
    """Return True if `active_scope` is identical to `target_scope` or a readonly child (`<target>:ro:<uid>`)."""
    if not active_scope or not target_scope:
        return False
    a = str(active_scope)
    t = str(target_scope)
    return a == t or a.startswith(f"{t}:ro:")


class _JobQueue:
    """Thread-safe FIFO job queue with atomic disk persistence, scope inspection, and selective cancellation."""

    def __init__(self, persist_path=None, *, use_global_queue_file=False, host=None):
        self._cond = threading.Condition()
        self._entries = collections.deque()     # pending items: {"qid": str, "enqueued_at": float, "item": Any}
        self._dispatched = collections.deque()  # currently executing items until task_done()
        self._dispatched_cancel_flags = {}      # qid -> "cancel" | "preempt" (for dequeue->run_agy window)
        self._persist_path = persist_path
        self._use_global_queue_file = bool(use_global_queue_file)
        self._host = host

    def _get_host(self):
        return self._host if self._host is not None else _host

    def _resolve_persist_path(self):
        if self._persist_path:
            return str(self._persist_path)
        if self._use_global_queue_file:
            h = self._get_host()
            return getattr(h, "QUEUE_FILE", None) if h is not None else None
        return None

    def _item_scope(self, item):
        if isinstance(item, tuple):
            if len(item) >= 3:
                return item[2]
            if len(item) == 2:
                return _host_scope_key_for(item[0], None, host=self._get_host())
        return None

    @staticmethod
    def _is_control_sentinel(item):
        if item == "__RELOAD__":
            return True
        if isinstance(item, tuple) and len(item) >= 2:
            payload = item[3] if len(item) >= 4 else item[1]
            if payload == "__RELOAD__":
                return True
        return False

    @classmethod
    def _serialize_entry(cls, entry, status="pending", *, host=None):
        item = entry["item"]
        if cls._is_control_sentinel(item):
            return None
        if isinstance(item, tuple) and len(item) == 4:
            chat_id, thread_id, skey, payload = item
        elif isinstance(item, tuple) and len(item) == 2:
            chat_id, payload = item
            thread_id = None
            skey = _host_scope_key_for(chat_id, None, host=host)
        else:
            return None

        if isinstance(payload, tuple) and len(payload) == 2:
            tag, val = payload
            if tag == "__CHAT_TURN__" and isinstance(val, dict):
                kind = "chat_turn"
                ser_payload = {
                    "prompt": str(val.get("prompt") or ""),
                    "origin_msg_id": int(val.get("origin_msg_id") or 0),
                    "mention_hop": int(val.get("mention_hop") or 0),
                    "chain_id": str(val.get("chain_id") or ""),
                    "user_role": str(val.get("user_role") or "admin"),
                    "user_id": val.get("user_id"),
                }
                if val.get("lb_takeover_kind"):
                    ser_payload["lb_takeover_kind"] = str(val.get("lb_takeover_kind"))
                    ser_payload["lb_session_gen"] = int(val.get("lb_session_gen") or 0)
                    ser_payload["lb_takeover_gen"] = int(val.get("lb_takeover_gen") or 0)
            elif tag == "__COMPACT__":
                kind = "compact"
                ser_payload = val
            elif tag == "__SCHEDULED__":
                kind = "scheduled"
                ser_payload = dict(val) if isinstance(val, dict) else val
            elif tag == "__BUS_JOB__":
                kind = "bus_job"
                ser_payload = str(val)
            else:
                return None
        elif isinstance(payload, str):
            kind = "text"
            ser_payload = payload
        else:
            return None

        return {
            "qid": entry["qid"],
            "enqueued_at": float(entry["enqueued_at"]),
            "status": status,
            "chat_id": chat_id,
            "thread_id": thread_id,
            "scope_key": skey,
            "kind": kind,
            "payload": ser_payload,
        }

    @staticmethod
    def _deserialize_record(rec, *, host=None):
        if not isinstance(rec, dict):
            return None
        kind = rec.get("kind")
        chat_id = rec.get("chat_id")
        thread_id = rec.get("thread_id")
        skey = rec.get("scope_key") or _host_scope_key_for(chat_id, thread_id, host=host)
        raw_payload = rec.get("payload")

        if kind == "text" and isinstance(raw_payload, str):
            if raw_payload == "__RELOAD__":
                return None
            payload = raw_payload
        elif kind == "chat_turn" and isinstance(raw_payload, dict):
            turn_meta = {
                "prompt": str(raw_payload.get("prompt") or ""),
                "origin_msg_id": int(raw_payload.get("origin_msg_id") or 0),
                "mention_hop": int(raw_payload.get("mention_hop") or 0),
                "chain_id": str(raw_payload.get("chain_id") or ""),
                "user_role": str(raw_payload.get("user_role") or "admin"),
                "user_id": raw_payload.get("user_id"),
            }
            if raw_payload.get("lb_takeover_kind"):
                turn_meta["lb_takeover_kind"] = str(raw_payload.get("lb_takeover_kind"))
                turn_meta["lb_session_gen"] = int(raw_payload.get("lb_session_gen") or 0)
                turn_meta["lb_takeover_gen"] = int(raw_payload.get("lb_takeover_gen") or 0)
            payload = ("__CHAT_TURN__", turn_meta)
        elif kind == "compact":
            payload = ("__COMPACT__", raw_payload)
        elif kind == "scheduled" and isinstance(raw_payload, dict):
            payload = ("__SCHEDULED__", raw_payload)
        elif kind == "bus_job" and raw_payload:
            payload = ("__BUS_JOB__", str(raw_payload))
        else:
            return None

        return (chat_id, thread_id, skey, payload)

    @staticmethod
    def _prompt_signature(rec):
        kind = rec.get("kind")
        raw_payload = rec.get("payload")
        if kind == "chat_turn" and isinstance(raw_payload, dict):
            return str(raw_payload.get("prompt") or "")
        if kind == "text" and isinstance(raw_payload, str):
            return raw_payload
        return None

    def _write_records_atomic(self, qpath, records):
        parent = os.path.dirname(os.path.abspath(qpath))
        os.makedirs(parent, exist_ok=True)
        lock_path = qpath + ".lock"
        lf_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lf_fd, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                tmp = f"{qpath}.{os.getpid()}.tmp"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as wf:
                    json.dump({"version": 1, "items": records}, wf, ensure_ascii=False)
                    wf.flush()
                os.chmod(tmp, 0o600)
                os.replace(tmp, qpath)
                os.chmod(qpath, 0o600)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    def _persist_locked(self):
        qpath = self._resolve_persist_path()
        if not qpath:
            return
        h = self._get_host()
        records = []
        for ent in self._dispatched:
            ser = self._serialize_entry(ent, status="dispatched", host=h)
            if ser is not None:
                records.append(ser)
        for ent in self._entries:
            ser = self._serialize_entry(ent, status="pending", host=h)
            if ser is not None:
                records.append(ser)
        try:
            self._write_records_atomic(qpath, records)
        except Exception as e:
            _host_log("queue persist error: %r" % e, host=h)

    def put(self, item, *, _persist=True, _enqueued_at=None, _qid=None):
        entry = {
            "qid": _qid or uuid.uuid4().hex[:12],
            "enqueued_at": float(_enqueued_at if _enqueued_at is not None else time.time()),
            "item": item,
        }
        with self._cond:
            self._entries.append(entry)
            if _persist and not self._is_control_sentinel(item):
                self._persist_locked()
            self._cond.notify()
        return entry["qid"]

    def put_front(self, item, *, _persist=True, _enqueued_at=None, _qid=None):
        """Atomically insert an urgent item at the head of the queue (ahead of all normal pending items)."""
        entry = {
            "qid": _qid or uuid.uuid4().hex[:12],
            "enqueued_at": float(_enqueued_at if _enqueued_at is not None else time.time()),
            "item": item,
        }
        with self._cond:
            self._entries.appendleft(entry)
            if _persist and not self._is_control_sentinel(item):
                self._persist_locked()
            self._cond.notify()
        return entry["qid"]

    def put_front_and_mark_dispatched_preempt(self, item, scope_key, *, _persist=True, _enqueued_at=None, _qid=None):
        """Atomically insert an urgent item at queue head and mark any same-scope dispatched item as preempted."""
        entry = {
            "qid": _qid or uuid.uuid4().hex[:12],
            "enqueued_at": float(_enqueued_at if _enqueued_at is not None else time.time()),
            "item": item,
        }
        marked_dispatched = 0
        with self._cond:
            self._entries.appendleft(entry)
            for dent in self._dispatched:
                if dent["qid"] != entry["qid"] and _is_same_scope_or_readonly_child(
                    self._item_scope(dent["item"]), scope_key
                ):
                    self._dispatched_cancel_flags[dent["qid"]] = "preempt"
                    marked_dispatched += 1
            if _persist and not self._is_control_sentinel(item):
                self._persist_locked()
            self._cond.notify()
        return entry["qid"], marked_dispatched

    def promote_to_front(self, qid, scope_key, *, _persist=True):
        """Move pending item `qid` to the head of the queue if it exists and belongs to `scope_key`."""
        ok, _marked, _reason = self.promote_to_front_and_mark_dispatched_preempt(
            qid,
            scope_key,
            claim_once=False,
            mark_dispatched=False,
            _persist=_persist,
        )
        return ok

    def promote_to_front_and_mark_dispatched_preempt(
        self,
        qid,
        scope_key,
        *,
        claim_once=True,
        mark_dispatched=True,
        _persist=True,
    ):
        """Atomically validate `(qid, scope_key)`, move pending item to head, persist, and optionally mark dispatched."""
        target_qid = str(qid or "").strip()
        if not target_qid or not scope_key:
            return False, 0, "invalid"
        marked_dispatched = 0
        with self._cond:
            target_idx = None
            target_ent = None
            for idx, ent in enumerate(self._entries):
                if ent["qid"] == target_qid:
                    target_idx = idx
                    target_ent = ent
                    break
            if target_ent is None:
                return False, 0, "missing_or_started"
            if self._item_scope(target_ent["item"]) != scope_key:
                return False, 0, "scope_mismatch"
            if claim_once and target_ent.get("preempt_claimed"):
                return False, 0, "already_claimed"
            if claim_once:
                target_ent["preempt_claimed"] = True
            moved = False
            if target_idx is not None and target_idx > 0:
                del self._entries[target_idx]
                self._entries.appendleft(target_ent)
                moved = True
            if mark_dispatched:
                for dent in self._dispatched:
                    if dent["qid"] != target_qid and _is_same_scope_or_readonly_child(
                        self._item_scope(dent["item"]), scope_key
                    ):
                        self._dispatched_cancel_flags[dent["qid"]] = "preempt"
                        marked_dispatched += 1
            if moved and _persist and not self._is_control_sentinel(target_ent["item"]):
                self._persist_locked()
            self._cond.notify()
        return True, marked_dispatched, "ok"

    def consume_dispatched_cancel(self, qid):
        """Pop and return any pending cancel/preempt flag (`'cancel'` | `'preempt'`) for a dispatched `qid`."""
        if not qid:
            return None
        with self._cond:
            return self._dispatched_cancel_flags.pop(qid, None)

    def get_entry(self):
        with self._cond:
            while not self._entries:
                self._cond.wait()
            entry = self._entries.popleft()
            if not self._is_control_sentinel(entry["item"]):
                self._dispatched.append(entry)
                self._persist_locked()
            return entry["qid"], entry["item"]

    def get(self):
        return self.get_entry()[1]

    def qsize(self):
        with self._cond:
            return len(self._entries)

    def empty(self):
        with self._cond:
            return not self._entries

    def task_done(self, qid=None):
        with self._cond:
            if qid is not None:
                self._dispatched_cancel_flags.pop(qid, None)
                for idx, ent in enumerate(self._dispatched):
                    if ent["qid"] == qid:
                        del self._dispatched[idx]
                        self._persist_locked()
                        return
            if self._dispatched:
                popped = self._dispatched.popleft()
                self._dispatched_cancel_flags.pop(popped["qid"], None)
                self._persist_locked()

    def count_scope(self, scope_key):
        with self._cond:
            return sum(1 for ent in self._entries if self._item_scope(ent["item"]) == scope_key)

    def cancel_scope_and_mark_dispatched(self, scope_key):
        """Atomically remove pending items in `scope_key` and flag matching `_dispatched` items as cancelled."""
        removed = 0
        marked_dispatched = 0
        kept = collections.deque()
        with self._cond:
            while self._entries:
                ent = self._entries.popleft()
                if self._item_scope(ent["item"]) == scope_key:
                    removed += 1
                else:
                    kept.append(ent)
            self._entries = kept
            for dent in self._dispatched:
                if _is_same_scope_or_readonly_child(self._item_scope(dent["item"]), scope_key):
                    self._dispatched_cancel_flags[dent["qid"]] = "cancel"
                    marked_dispatched += 1
            if removed:
                self._persist_locked()
        return removed, marked_dispatched

    def cancel_scope(self, scope_key):
        removed = 0
        kept = collections.deque()
        with self._cond:
            while self._entries:
                ent = self._entries.popleft()
                if self._item_scope(ent["item"]) == scope_key:
                    removed += 1
                else:
                    kept.append(ent)
            self._entries = kept
            if removed:
                self._persist_locked()
        return removed

    def cancel_web_turn(self, turn_id):
        """Remove a queued `__WEB_TURN__` matching `turn_id` without disturbing any Telegram items."""
        removed = False
        kept = collections.deque()
        with self._cond:
            while self._entries:
                ent = self._entries.popleft()
                item = ent["item"]
                payload = item[3] if isinstance(item, tuple) and len(item) >= 4 else None
                if (
                    isinstance(payload, tuple)
                    and len(payload) == 2
                    and payload[0] == "__WEB_TURN__"
                    and isinstance(payload[1], dict)
                    and payload[1].get("turn_id") == turn_id
                ):
                    removed = True
                else:
                    kept.append(ent)
            self._entries = kept
        return removed

    def has_pending_web_turn(self, *, cid=None, worktree_id=None):
        """Non-blocking probe under `self._cond` ONLY for queued web turns targeting `cid` or `worktree_id`."""
        with self._cond:
            for ent in self._entries:
                item = ent["item"]
                payload = item[3] if isinstance(item, tuple) and len(item) >= 4 else None
                if (
                    isinstance(payload, tuple)
                    and len(payload) == 2
                    and payload[0] == "__WEB_TURN__"
                    and isinstance(payload[1], dict)
                ):
                    req = payload[1]
                    if cid and req.get("cid") == cid:
                        return True
                    wt = req.get("worktree_info")
                    if worktree_id and isinstance(wt, dict) and wt.get("worktree_id") == worktree_id:
                        return True
        return False

    def cancel_bus_job(self, job_id):
        """Remove a queued `__BUS_JOB__` matching `job_id` without disturbing Telegram items or other jobs."""
        removed = False
        kept = collections.deque()
        with self._cond:
            while self._entries:
                ent = self._entries.popleft()
                item = ent["item"]
                payload = item[3] if isinstance(item, tuple) and len(item) >= 4 else None
                if (
                    isinstance(payload, tuple)
                    and len(payload) == 2
                    and payload[0] == "__BUS_JOB__"
                    and str(payload[1] or "") == str(job_id)
                ):
                    removed = True
                else:
                    kept.append(ent)
            self._entries = kept
            if removed:
                self._persist_locked()
        return removed

    def prune_stale_live_browser_wakes(self, scope_key, session_gen, takeover_gen, *, remove_all_ack=False):
        """Remove queued stale live-browser takeover/handback wake items for `scope_key`."""
        removed = 0
        kept = collections.deque()
        with self._cond:
            while self._entries:
                ent = self._entries.popleft()
                item = ent["item"]
                drop = False
                if self._item_scope(item) == scope_key and isinstance(item, tuple) and len(item) >= 4:
                    payload = item[3]
                    if (
                        isinstance(payload, tuple)
                        and len(payload) == 2
                        and payload[0] == "__CHAT_TURN__"
                        and isinstance(payload[1], dict)
                    ):
                        meta = payload[1]
                        lb_kind = meta.get("lb_takeover_kind")
                        if lb_kind in ("takeover_ack", "handback"):
                            item_sgen = int(meta.get("lb_session_gen") or 0)
                            item_tgen = int(meta.get("lb_takeover_gen") or 0)
                            if remove_all_ack and lb_kind == "takeover_ack":
                                drop = True
                            elif item_sgen < session_gen or (item_sgen == session_gen and item_tgen < takeover_gen):
                                drop = True
                if drop:
                    removed += 1
                else:
                    kept.append(ent)
            self._entries = kept
            if removed:
                self._persist_locked()
        return removed

    def clear_all_and_mark_dispatched(self):
        """Atomically clear all pending items and flag all currently `_dispatched` items as cancelled."""
        marked_dispatched = 0
        with self._cond:
            removed = len(self._entries)
            self._entries.clear()
            for dent in self._dispatched:
                self._dispatched_cancel_flags[dent["qid"]] = "cancel"
                marked_dispatched += 1
            if removed:
                self._persist_locked()
        return removed, marked_dispatched

    def clear_all(self):
        with self._cond:
            removed = len(self._entries)
            self._entries.clear()
            if removed:
                self._persist_locked()
        return removed

    def restore_from_disk(self, *, ttl_sec=None, recovered_in_flight=None):
        """Load persisted items from disk in FIFO order, enforcing TTL, in-flight dedup, and bus job checks."""
        qpath = self._resolve_persist_path()
        if not qpath or not os.path.isfile(qpath):
            return {"restored": 0, "dropped_expired": 0, "dropped_dedup": 0, "dropped_invalid": 0, "routes": {}}

        lock_path = qpath + ".lock"
        os.makedirs(os.path.dirname(os.path.abspath(qpath)), exist_ok=True)
        raw_items = []
        lf_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(lf_fd, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_SH)
            try:
                with open(qpath, "r", encoding="utf-8", errors="replace") as rf:
                    data = json.load(rf)
                if isinstance(data, dict) and isinstance(data.get("items"), list):
                    raw_items = data["items"]
            except Exception:
                raw_items = []
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

        if not raw_items:
            return {"restored": 0, "dropped_expired": 0, "dropped_dedup": 0, "dropped_invalid": 0, "routes": {}}

        h = self._get_host()
        default_ttl = getattr(h, "QUEUE_TTL_SEC", 3600) if h is not None else 3600
        effective_ttl = default_ttl if ttl_sec is None else int(ttl_sec)
        bb = _host_bot_bus(host=h)
        now = time.time()
        in_flight_sigs = set()
        for sig in (recovered_in_flight or ()):
            if isinstance(sig, tuple) and len(sig) >= 2:
                in_flight_sigs.add((str(sig[0]), str(sig[1])))

        restored = 0
        dropped_expired = 0
        dropped_dedup = 0
        dropped_invalid = 0
        routes = {}  # (chat_id, thread_id) -> count

        with self._cond:
            for rec in raw_items:
                if not isinstance(rec, dict):
                    dropped_invalid += 1
                    continue
                enq_at = float(rec.get("enqueued_at") or 0.0)
                if effective_ttl > 0 and (now - enq_at) > effective_ttl:
                    dropped_expired += 1
                    continue

                item = self._deserialize_record(rec, host=h)
                if item is None or self._is_control_sentinel(item):
                    dropped_invalid += 1
                    continue

                if rec.get("status") == "dispatched":
                    psig = self._prompt_signature(rec)
                    skey = str(rec.get("scope_key") or "")
                    cand_skeys = [skey]
                    if rec.get("kind") == "chat_turn" and isinstance(rec.get("payload"), dict):
                        pl = rec["payload"]
                        if pl.get("user_role") == "readonly":
                            uid = pl.get("user_id")
                            ro_skey = f"{skey}:ro:{uid if uid is not None else 'guest'}"
                            if ro_skey not in cand_skeys:
                                cand_skeys.insert(0, ro_skey)
                    if psig is not None:
                        matched_sig = next(((cs, psig) for cs in cand_skeys if (cs, psig) in in_flight_sigs), None)
                        if matched_sig is not None:
                            in_flight_sigs.discard(matched_sig)
                            dropped_dedup += 1
                            continue

                if rec.get("kind") == "bus_job":
                    jid = str(rec.get("payload") or "")
                    job = bb.get_job(jid) if jid else None
                    if (
                        not isinstance(job, dict)
                        or job.get("status") != "queued"
                        or bool(job.get("cancel_requested"))
                    ):
                        dropped_invalid += 1
                        continue

                self._entries.append(
                    {
                        "qid": str(rec.get("qid") or uuid.uuid4().hex[:12]),
                        "enqueued_at": enq_at or now,
                        "item": item,
                    }
                )
                restored += 1
                chat_id = item[0]
                thread_id = item[1]
                if chat_id and rec.get("kind") != "bus_job":
                    rkey = (chat_id, thread_id)
                    routes[rkey] = routes.get(rkey, 0) + 1

            self._persist_locked()

        return {
            "restored": restored,
            "dropped_expired": dropped_expired,
            "dropped_dedup": dropped_dedup,
            "dropped_invalid": dropped_invalid,
            "routes": routes,
        }


PersistentJobQueue = _JobQueue


def restore_persisted_queue(ttl_sec=None, recovered_in_flight=None, notify=True, *, queue_obj=None, host=None):
    """Restore queued tasks from QUEUE_FILE on startup and emit one summary notice per affected route."""
    h = _resolve_host(host)
    q = queue_obj if queue_obj is not None else (getattr(h, "job_q", None) if h is not None else None)
    if q is None:
        return {"restored": 0, "dropped_expired": 0, "dropped_dedup": 0, "dropped_invalid": 0, "routes": {}}
    summary = q.restore_from_disk(ttl_sec=ttl_sec, recovered_in_flight=recovered_in_flight)
    restored = summary["restored"]
    if restored or summary["dropped_expired"] or summary["dropped_dedup"] or summary["dropped_invalid"]:
        _host_log(
            "Queue recovery: restored=%d, expired=%d, dedup=%d, invalid=%d"
            % (restored, summary["dropped_expired"], summary["dropped_dedup"], summary["dropped_invalid"]),
            host=h,
        )
    send_fn = getattr(h, "send", None) if h is not None else None
    if notify and restored > 0 and callable(send_fn):
        for (chat_id, thread_id), cnt in summary["routes"].items():
            if not chat_id:
                continue
            try:
                send_fn(
                    chat_id,
                    f"🔄 <b>服务重启完成：</b>已按 FIFO 顺序自动恢复 <b>{cnt}</b> 条待处理排队任务，即将继续执行。",
                    parse_mode="HTML",
                    thread_id=thread_id,
                )
            except Exception as e:
                _host_log("restore_persisted_queue notify failed (%s): %r" % (chat_id, e), host=h)
    return summary
