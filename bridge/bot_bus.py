#!/usr/bin/env python3
"""Lightweight File-Backed Coordinator Bus for multi-bot task delegation in agy-cli-bot.

Shared by `bridge.py` (each Telegram bot process) and `bot_bus_mcp.py` (MCP tools exposed
only to coordinator/peer sessions). Uses atomic temp-file writes + `fcntl.flock` under
`~/.gemini/antigravity-cli/cache/bot_bus/` with zero external dependencies and zero secrets.
"""

from __future__ import annotations

import contextlib
import datetime
import fcntl
import hashlib
import json
import os
import re
import subprocess
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

HOME = os.path.expanduser("~")
BUS_DIR = os.environ.get(
    "AGY_BOT_BUS_DIR",
    os.path.join(HOME, ".gemini", "antigravity-cli", "cache", "bot_bus"),
)
JOBS_DIR = os.path.join(BUS_DIR, "jobs")
INBOX_DIR = os.path.join(BUS_DIR, "inbox")
GROUP_HISTORY_DIR = os.path.join(BUS_DIR, "group_history")
LOCK_FILE = os.path.join(BUS_DIR, "bus.lock")
CONFIG_FILE = os.path.join(BUS_DIR, "team_config.json")
ROSTER_FILE = os.path.join(BUS_DIR, "roster.json")
THREADS_FILE = os.path.join(BUS_DIR, "threads.json")
LOOP_GUARD_FILE = os.path.join(BUS_DIR, "loop_guard.json")
MENTION_CHAINS_FILE = os.path.join(BUS_DIR, "mention_chains.json")
ORIGIN_CTX_FILE = os.path.join(BUS_DIR, "origin_context.json")

VALID_ROLES = ("coordinator", "worker", "peer")
TERMINAL_STATUSES = frozenset({"done", "error", "cancelled"})
FAN_OUT_MAX = 8
DEFAULT_MAX_HOPS = 2
ONLINE_TTL_SECONDS = 45.0
JOB_RETENTION_LIMIT = 150
GROUP_HISTORY_LIMIT = 40
GROUP_HISTORY_INJECT_LIMIT = 15
GROUP_HISTORY_MAX_CHARS = 2400
HUMAN_CHAIN_TTL_SECONDS = 1800.0
MENTION_WINDOW_SECONDS = 300.0
MENTION_WINDOW_MAX = 6
MENTION_CHAIN_MAX_RELAYS = 4
_LOOP_WINDOW_SECONDS = 300.0
_LOOP_MAX_EVENTS = 12


def _ensure_dirs() -> None:
    os.makedirs(BUS_DIR, mode=0o700, exist_ok=True)
    os.makedirs(JOBS_DIR, mode=0o700, exist_ok=True)
    os.makedirs(INBOX_DIR, mode=0o700, exist_ok=True)
    os.makedirs(GROUP_HISTORY_DIR, mode=0o700, exist_ok=True)


@contextlib.contextmanager
def _bus_lock():
    _ensure_dirs()
    with open(LOCK_FILE, "a+", encoding="utf-8") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def _read_json(path: str, default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def _atomic_write_json(path: str, payload: Any) -> None:
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def normalize_handle(raw: str) -> str:
    """Normalize a bot handle (`@Foo_Bot` -> `foo_bot`)."""
    cleaned = (raw or "").strip().lstrip("@").lower()
    return re.sub(r"[^a-z0-9_.-]+", "", cleaned)


def _pid_alive(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- team configuration
def _load_team_config_unlocked() -> Dict[str, Any]:
    data = _read_json(CONFIG_FILE, None)
    if not isinstance(data, dict):
        return {"version": 1, "bots": {}}
    bots = data.get("bots")
    if not isinstance(bots, dict):
        data["bots"] = {}
    return data


def load_team_config() -> Dict[str, Any]:
    with _bus_lock():
        return _load_team_config_unlocked()


def resolve_bot_config(
    handle: str,
    *,
    env_role: str = "",
    env_model: str = "",
    env_project: str = "",
    env_specialty: str = "",
    fallback_workdir: str = "",
) -> Dict[str, Any]:
    """Return effective team config for `handle` by merging saved config with `.env` defaults."""
    norm = normalize_handle(handle)
    with _bus_lock():
        cfg = _load_team_config_unlocked()
        entry = dict((cfg.get("bots") or {}).get(norm) or {})

    role = entry.get("role") or (env_role if env_role in VALID_ROLES else "") or "peer"
    if role not in VALID_ROLES:
        role = "peer"
    team_mirror = cfg.get("mirror") if isinstance(cfg.get("mirror"), dict) else {}
    m_chat = entry.get("mirror_chat_id") if entry.get("mirror_chat_id") is not None else team_mirror.get("chat_id")
    m_thread = entry.get("mirror_thread_id") if entry.get("mirror_chat_id") is not None else team_mirror.get("thread_id")
    return {
        "role": role,
        "specialty": (entry.get("specialty") if entry.get("specialty") is not None else env_specialty) or "",
        "default_model": (entry.get("default_model") if entry.get("default_model") is not None else env_model) or "",
        "default_workdir": (entry.get("default_workdir") if entry.get("default_workdir") is not None else fallback_workdir) or "",
        "default_project": (entry.get("default_project") if entry.get("default_project") is not None else env_project) or "",
        "mirror_chat_id": int(m_chat or 0),
        "mirror_thread_id": m_thread,
        "max_hops": int(entry.get("max_hops") or DEFAULT_MAX_HOPS),
    }


def set_team_mirror(chat_id: int, thread_id: Optional[int] = None) -> Dict[str, Any]:
    """Configure (or clear when chat_id=0) the team-wide Telegram mirror group/Topic for worker cards."""
    with _bus_lock():
        cfg = _load_team_config_unlocked()
        if not chat_id:
            cfg["mirror"] = {"chat_id": 0, "thread_id": None}
        else:
            cfg["mirror"] = {"chat_id": int(chat_id), "thread_id": thread_id}
        _atomic_write_json(CONFIG_FILE, cfg)
        return dict(cfg["mirror"])


def update_bot_config(handle: str, **updates: Any) -> Dict[str, Any]:
    """Persist team configuration fields for `handle` under `bus.lock`."""
    norm = normalize_handle(handle)
    if not norm:
        raise ValueError("Bot handle is required")
    with _bus_lock():
        cfg = _load_team_config_unlocked()
        bots = cfg.setdefault("bots", {})
        cur = dict(bots.get(norm) or {})
        for k, v in updates.items():
            if k == "role" and v not in VALID_ROLES:
                raise ValueError(f"Invalid role: {v}")
            cur[k] = v
        cur["updated_at"] = int(time.time())
        bots[norm] = cur
        _atomic_write_json(CONFIG_FILE, cfg)
        return dict(cur)


def promote_sole_coordinator(coordinator_handle: str, *, worker_default_model: str = "gemini-3.8-flash-low") -> List[str]:
    """Set `coordinator_handle` as sole coordinator and demote all other known bots to worker."""
    coord = normalize_handle(coordinator_handle)
    changed = []
    with _bus_lock():
        cfg = _load_team_config_unlocked()
        roster = _read_json(ROSTER_FILE, {"bots": {}})
        all_handles = set((cfg.get("bots") or {}).keys()) | set((roster.get("bots") or {}).keys())
        all_handles.add(coord)
        bots_cfg = cfg.setdefault("bots", {})
        now = int(time.time())
        for h in sorted(all_handles):
            if not h:
                continue
            cur = dict(bots_cfg.get(h) or {})
            if h == coord:
                cur["role"] = "coordinator"
                cur["updated_at"] = now
            else:
                cur["role"] = "worker"
                if worker_default_model and not cur.get("default_model"):
                    cur["default_model"] = worker_default_model
                cur["updated_at"] = now
            bots_cfg[h] = cur
            changed.append(f"{h}={cur['role']}")
        _atomic_write_json(CONFIG_FILE, cfg)
    return changed


def set_all_peers() -> List[str]:
    """Set every known bot to `peer` role."""
    changed = []
    with _bus_lock():
        cfg = _load_team_config_unlocked()
        roster = _read_json(ROSTER_FILE, {"bots": {}})
        all_handles = set((cfg.get("bots") or {}).keys()) | set((roster.get("bots") or {}).keys())
        bots_cfg = cfg.setdefault("bots", {})
        now = int(time.time())
        for h in sorted(all_handles):
            if not h:
                continue
            cur = dict(bots_cfg.get(h) or {})
            cur["role"] = "peer"
            cur["updated_at"] = now
            bots_cfg[h] = cur
            changed.append(f"{h}=peer")
        _atomic_write_json(CONFIG_FILE, cfg)
    return changed


# ---------------------------------------------------------------- roster & discovery
def heartbeat_bot(info: Dict[str, Any]) -> Dict[str, Any]:
    """Register or refresh a live bridge bot's status on the shared roster."""
    norm = normalize_handle(info.get("handle") or "")
    if not norm:
        raise ValueError("heartbeat_bot requires non-empty handle")

    now = time.time()
    entry = dict(info)
    entry["handle"] = norm
    entry["last_seen"] = now

    with _bus_lock():
        roster = _read_json(ROSTER_FILE, {"version": 1, "bots": {}})
        if not isinstance(roster, dict):
            roster = {"version": 1, "bots": {}}
        bots = roster.setdefault("bots", {})
        # Remove any stale fallback `bot_<instance_id>` entry once real Telegram handle resolves
        inst_id = entry.get("instance_id")
        if inst_id and norm != f"bot_{inst_id}".lower():
            stale_fallback = f"bot_{inst_id}".lower()
            if stale_fallback in bots:
                bots.pop(stale_fallback, None)
        bots[norm] = entry
        _atomic_write_json(ROSTER_FILE, roster)
    return entry


def _merge_bot_view(handle: str, raw_roster: Dict[str, Any], raw_cfg: Dict[str, Any], now: float, team_mirror: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cfg = dict(raw_cfg or {})
    r = dict(raw_roster or {})
    pid = int(r.get("pid") or 0)
    last_seen = float(r.get("last_seen") or 0.0)
    online = bool(r) and _pid_alive(pid) and (now - last_seen) <= ONLINE_TTL_SECONDS
    role = cfg.get("role") or r.get("role") or "peer"
    if role not in VALID_ROLES:
        role = "peer"
    tm = team_mirror or {}
    m_chat = cfg.get("mirror_chat_id") if cfg.get("mirror_chat_id") is not None else tm.get("chat_id")
    m_thread = cfg.get("mirror_thread_id") if cfg.get("mirror_chat_id") is not None else tm.get("thread_id")

    return {
        "handle": handle,
        "display_name": r.get("display_name") or handle,
        "bot_id": int(r.get("bot_id") or 0),
        "instance_id": r.get("instance_id") or "",
        "role": role,
        "online": online,
        "busy": bool(r.get("busy")) if online else False,
        "current_job": r.get("current_job") if online else None,
        "queue_depth": int(r.get("queue_depth") or 0) if online else 0,
        "specialty": cfg.get("specialty") if cfg.get("specialty") is not None else (r.get("specialty") or ""),
        "default_model": cfg.get("default_model") or r.get("active_model") or "",
        "active_model": r.get("active_model") or "",
        "default_workdir": cfg.get("default_workdir") or r.get("workdir") or "",
        "default_project": cfg.get("default_project") if cfg.get("default_project") is not None else (r.get("project") or ""),
        "allowed_chats": list(r.get("allowed_chats") or []),
        "mirror_chat_id": int(m_chat or 0),
        "mirror_thread_id": m_thread,
        "last_seen": last_seen,
        "pid": pid,
    }


def list_roster(include_offline: bool = True) -> List[Dict[str, Any]]:
    now = time.time()
    with _bus_lock():
        roster = _read_json(ROSTER_FILE, {"bots": {}})
        cfg = _load_team_config_unlocked()
    r_bots = roster.get("bots") or {}
    c_bots = cfg.get("bots") or {}
    team_mirror = cfg.get("mirror") if isinstance(cfg.get("mirror"), dict) else {}
    handles = sorted(set(r_bots.keys()) | set(c_bots.keys()))
    out = []
    for h in handles:
        view = _merge_bot_view(h, r_bots.get(h), c_bots.get(h), now, team_mirror=team_mirror)
        if include_offline or view["online"]:
            out.append(view)
    role_order = {"coordinator": 0, "peer": 1, "worker": 2}
    out.sort(key=lambda b: (0 if b["online"] else 1, role_order.get(b["role"], 9), b["handle"]))
    return out


def resolve_target_bot(query: str, roster: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Resolve user/LLM target string (`@handle`, `handle`, `instance_id`, or unique role/substring)."""
    q = (query or "").strip()
    if not q:
        raise ValueError("Target bot cannot be empty")
    q_norm = normalize_handle(q)
    items = roster if roster is not None else list_roster(include_offline=True)
    if not items:
        raise ValueError("No bots registered on the Bot Bus roster yet")

    # 1. Exact handle or instance_id match
    for item in items:
        if item["handle"] == q_norm or (item.get("instance_id") and item["instance_id"].lower() == q.lower()):
            return item

    # 2. Exact display name match (case-insensitive)
    name_matches = [item for item in items if (item.get("display_name") or "").strip().lower() == q.lower()]
    if len(name_matches) == 1:
        return name_matches[0]

    # 3. Unique prefix / role match (`worker` if single worker online)
    if q_norm in VALID_ROLES:
        role_matches = [item for item in items if item["role"] == q_norm and item["online"]]
        if len(role_matches) == 1:
            return role_matches[0]
        if len(role_matches) > 1:
            raise ValueError(f"Multiple online bots with role '{q_norm}': {[b['handle'] for b in role_matches]}")

    prefix_matches = [item for item in items if item["handle"].startswith(q_norm)]
    if len(prefix_matches) == 1:
        return prefix_matches[0]

    known = ", ".join(f"@{b['handle']} ({b['role']}, {'online' if b['online'] else 'offline'})" for b in items)
    raise ValueError(f"Unknown or ambiguous bot '{query}'. Known bots: {known}")


# ---------------------------------------------------------------- inbox packets & jobs
def _job_path(job_id: str) -> str:
    safe_id = re.sub(r"[^a-zA-Z0-9_.-]+", "", job_id)
    return os.path.join(JOBS_DIR, f"{safe_id}.json")


def _drop_inbox_packet_unlocked(target_handle: str, packet: Dict[str, Any]) -> str:
    norm = normalize_handle(target_handle)
    bot_inbox = os.path.join(INBOX_DIR, norm)
    os.makedirs(bot_inbox, mode=0o700, exist_ok=True)
    ts_ms = int(time.time() * 1000)
    pkt_name = f"{ts_ms:013d}_{uuid.uuid4().hex[:8]}.json"
    pkt_path = os.path.join(bot_inbox, pkt_name)
    _atomic_write_json(pkt_path, packet)
    return pkt_path


def pop_inbox_packets(handle: str) -> List[Dict[str, Any]]:
    norm = normalize_handle(handle)
    if not norm:
        return []
    bot_inbox = os.path.join(INBOX_DIR, norm)
    if not os.path.isdir(bot_inbox):
        return []
    packets: List[Dict[str, Any]] = []
    with _bus_lock():
        try:
            names = sorted(fn for fn in os.listdir(bot_inbox) if fn.endswith(".json") and not fn.endswith(".tmp"))
        except OSError:
            return []
        for fn in names:
            fp = os.path.join(bot_inbox, fn)
            pkt = _read_json(fp, None)
            try:
                os.remove(fp)
            except OSError:
                pass
            if isinstance(pkt, dict):
                packets.append(pkt)
    return packets


def _prune_old_jobs_unlocked(limit: int = JOB_RETENTION_LIMIT) -> None:
    try:
        files = [fn for fn in os.listdir(JOBS_DIR) if fn.endswith(".json") and not fn.endswith(".tmp")]
    except OSError:
        return
    if len(files) <= limit:
        return
    entries = []
    for fn in files:
        fp = os.path.join(JOBS_DIR, fn)
        try:
            st = os.stat(fp)
            entries.append((st.st_mtime, fp))
        except OSError:
            continue
    entries.sort(key=lambda x: x[0])
    to_check = len(entries) - limit
    removed = 0
    for _mtime, fp in entries:
        if removed >= to_check:
            break
        data = _read_json(fp, {})
        if data.get("status") in TERMINAL_STATUSES:
            try:
                os.remove(fp)
                removed += 1
            except OSError:
                pass


def dispatch_assignments(
    from_bot: str,
    assignments: List[Dict[str, Any]],
    *,
    origin_scope_key: str = "",
    origin_chat_id: int = 0,
    origin_thread_id: Optional[int] = None,
    origin_msg_id: Optional[int] = None,
    parent_chain: Optional[Iterable[str]] = None,
    default_notify_group: bool = False,
    wake_on_async: bool = False,
) -> Dict[str, Any]:
    """Validate and enqueue 1..FAN_OUT_MAX delegation jobs atomically onto target bot inboxes."""
    sender = normalize_handle(from_bot)
    if not sender:
        raise ValueError("Sender bot handle could not be determined")
    if not assignments or not isinstance(assignments, list):
        raise ValueError("At least one assignment is required")
    if len(assignments) > FAN_OUT_MAX:
        raise ValueError(f"Too many fan-out assignments ({len(assignments)} > {FAN_OUT_MAX})")

    chain = [normalize_handle(c) for c in (parent_chain or []) if normalize_handle(c)]
    if not chain or chain[-1] != sender:
        chain.append(sender)
    if len(chain) > DEFAULT_MAX_HOPS:
        raise ValueError(f"Max delegation depth ({DEFAULT_MAX_HOPS}) reached: {' -> '.join(chain)}")

    now = time.time()
    group_id = f"batch-{uuid.uuid4().hex[:8]}"
    created_jobs: List[Dict[str, Any]] = []

    with _bus_lock():
        roster_raw = _read_json(ROSTER_FILE, {"bots": {}})
        cfg_raw = _load_team_config_unlocked()
        r_bots = roster_raw.get("bots") or {}
        c_bots = cfg_raw.get("bots") or {}
        handles = sorted(set(r_bots.keys()) | set(c_bots.keys()))
        team_mirror = cfg_raw.get("mirror") if isinstance(cfg_raw.get("mirror"), dict) else {}
        roster = [_merge_bot_view(h, r_bots.get(h), c_bots.get(h), now, team_mirror=team_mirror) for h in handles]

        resolved_specs = []
        for idx, spec in enumerate(assignments):
            if not isinstance(spec, dict):
                raise ValueError(f"Assignment #{idx + 1} must be an object")
            target_q = str(spec.get("bot") or "").strip()
            prompt = str(spec.get("prompt") or "").strip()
            if not prompt:
                raise ValueError(f"Assignment #{idx + 1} prompt cannot be empty")
            target = resolve_target_bot(target_q, roster=roster)
            th = target["handle"]
            if th == sender:
                raise ValueError(f"Cannot dispatch to self (@{sender}); execute directly or use invoke_subagent")
            if th in chain:
                raise ValueError(f"Cycle detected in delegation chain ({' -> '.join(chain)} -> {th})")
            if not target["online"]:
                raise ValueError(f"Target bot @{th} is currently offline")
            resolved_specs.append((spec, target))

        job_ids = [f"job-{uuid.uuid4().hex[:10]}" for _ in resolved_specs]
        for idx, ((spec, target), jid) in enumerate(zip(resolved_specs, job_ids)):
            job = {
                "job_id": jid,
                "group_id": group_id,
                "batch_index": idx,
                "batch_size": len(job_ids),
                "batch_job_ids": list(job_ids),
                "wake_on_async": bool(wake_on_async),
                "batch_notified": False,
                "label": str(spec.get("label") or "")[:120],
                "from_bot": sender,
                "target_bot": target["handle"],
                "prompt": str(spec.get("prompt") or "").strip(),
                "project": str(spec.get("project") or ""),
                "workdir": str(spec.get("workdir") or ""),
                "model": str(spec.get("model") or ""),
                "effort": str(spec.get("effort") or ""),
                "mode": str(spec.get("mode") or ""),
                "thread_key": str(spec.get("thread_key") or ""),
                "resume_cid": str(spec.get("resume_cid") or ""),
                "worktree": bool(spec.get("worktree", False)),
                "worktree_info": {},
                "notify_group": bool(spec.get("notify_group", default_notify_group)),
                "origin_scope_key": origin_scope_key or "",
                "origin_chat_id": int(origin_chat_id or 0),
                "origin_thread_id": origin_thread_id,
                "origin_msg_id": int(origin_msg_id or 0),
                "chain": list(chain) + [target["handle"]],
                "depth": len(chain),
                "status": "queued",
                "cancel_requested": False,
                "cancel_reason": "",
                "group_delivered": False,
                "created_at": now,
                "started_at": 0.0,
                "finished_at": 0.0,
                "worker_pid": 0,
                "worker_cid": "",
                "progress": "",
                "result_text": "",
                "error": "",
                "artifacts": [],
                "usage": {},
            }
            _atomic_write_json(_job_path(jid), job)
            _drop_inbox_packet_unlocked(
                target["handle"],
                {"type": "job", "job_id": jid, "from_bot": sender, "created_at": now},
            )
            created_jobs.append(job)

        _prune_old_jobs_unlocked()

    return {"group_id": group_id, "jobs": created_jobs}


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    fp = _job_path(job_id)
    if not os.path.isfile(fp):
        return None
    data = _read_json(fp, None)
    return data if isinstance(data, dict) else None


def list_jobs(limit: int = 20, status: Optional[str] = None, bot: Optional[str] = None) -> List[Dict[str, Any]]:
    _ensure_dirs()
    norm_bot = normalize_handle(bot or "") if bot else ""
    try:
        files = [fn for fn in os.listdir(JOBS_DIR) if fn.endswith(".json") and not fn.endswith(".tmp")]
    except OSError:
        return []
    jobs = []
    for fn in files:
        data = _read_json(os.path.join(JOBS_DIR, fn), None)
        if not isinstance(data, dict):
            continue
        if status and data.get("status") != status:
            continue
        if norm_bot and norm_bot not in (data.get("target_bot"), data.get("from_bot")):
            continue
        jobs.append(data)
    jobs.sort(key=lambda j: float(j.get("created_at") or 0), reverse=True)
    return jobs[: max(1, int(limit))]


def claim_job(job_id: str, worker_handle: str, worker_pid: int) -> Optional[Dict[str, Any]]:
    norm = normalize_handle(worker_handle)
    fp = _job_path(job_id)
    with _bus_lock():
        job = _read_json(fp, None)
        if not isinstance(job, dict):
            return None
        if job.get("target_bot") != norm:
            return None
        if job.get("status") != "queued":
            return None
        if job.get("cancel_requested"):
            job["status"] = "cancelled"
            job["finished_at"] = time.time()
            job["error"] = job.get("cancel_reason") or "cancelled before start"
            _atomic_write_json(fp, job)
            _maybe_notify_batch_done_unlocked(job)
            return None
        job["status"] = "running"
        job["started_at"] = time.time()
        job["worker_pid"] = int(worker_pid or os.getpid())
        _atomic_write_json(fp, job)
        return dict(job)


def update_job(job_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
    fp = _job_path(job_id)
    with _bus_lock():
        job = _read_json(fp, None)
        if not isinstance(job, dict):
            return None
        job.update(fields)
        _atomic_write_json(fp, job)
        return dict(job)


def is_job_cancelled(job_id: str) -> bool:
    job = get_job(job_id)
    return bool(job and (job.get("cancel_requested") or job.get("status") == "cancelled"))


def _maybe_notify_batch_done_unlocked(settled_job: Dict[str, Any]) -> None:
    if not settled_job.get("wake_on_async") or settled_job.get("batch_notified"):
        return
    job_ids = list(settled_job.get("batch_job_ids") or [settled_job["job_id"]])
    batch_jobs = []
    for jid in job_ids:
        j = settled_job if jid == settled_job["job_id"] else _read_json(_job_path(jid), None)
        if not isinstance(j, dict) or j.get("status") not in TERMINAL_STATUSES:
            return
        if j.get("batch_notified"):
            return
        batch_jobs.append(j)

    now = time.time()
    for j in batch_jobs:
        j["batch_notified"] = True
        _atomic_write_json(_job_path(j["job_id"]), j)

    sender = settled_job.get("from_bot") or ""
    if not sender:
        return
    _drop_inbox_packet_unlocked(
        sender,
        {
            "type": "batch_done",
            "group_id": settled_job.get("group_id"),
            "job_ids": job_ids,
            "origin_scope_key": settled_job.get("origin_scope_key") or "",
            "origin_chat_id": int(settled_job.get("origin_chat_id") or 0),
            "origin_thread_id": settled_job.get("origin_thread_id"),
            "chain": list(settled_job.get("chain") or []),
            "created_at": now,
        },
    )


def finish_job(
    job_id: str,
    *,
    status: str,
    result_text: str = "",
    error: str = "",
    worker_cid: str = "",
    artifacts: Optional[List[str]] = None,
    usage: Optional[Dict[str, Any]] = None,
    worktree_info: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    if status not in TERMINAL_STATUSES:
        raise ValueError(f"Invalid terminal status: {status}")
    fp = _job_path(job_id)
    with _bus_lock():
        job = _read_json(fp, None)
        if not isinstance(job, dict):
            return None
        now = time.time()
        job["status"] = status
        job["finished_at"] = now
        if result_text:
            job["result_text"] = result_text
        if error:
            job["error"] = error
        if worker_cid:
            job["worker_cid"] = worker_cid
        if artifacts is not None:
            job["artifacts"] = list(artifacts)
        if usage is not None:
            job["usage"] = dict(usage)
        if worktree_info is not None:
            job["worktree_info"] = dict(worktree_info)
        _atomic_write_json(fp, job)
        _maybe_notify_batch_done_unlocked(job)
        return dict(job)


def cancel_job(job_id: str, requester_bot: str = "", reason: str = "cancelled") -> Optional[Dict[str, Any]]:
    req = normalize_handle(requester_bot or "")
    fp = _job_path(job_id)
    with _bus_lock():
        job = _read_json(fp, None)
        if not isinstance(job, dict):
            return None
        if req and req not in (job.get("from_bot"), job.get("target_bot")):
            raise PermissionError(f"Only @{job.get('from_bot')} may cancel {job_id}")
        if job.get("status") in TERMINAL_STATUSES:
            return dict(job)
        job["cancel_requested"] = True
        job["cancel_reason"] = reason
        if job.get("status") == "queued":
            job["status"] = "cancelled"
            job["finished_at"] = time.time()
            job["error"] = reason
            _atomic_write_json(fp, job)
            _maybe_notify_batch_done_unlocked(job)
        else:
            _atomic_write_json(fp, job)
        return dict(job)


def retry_job(job_id: str, requester_bot: str, prompt_override: str = "") -> Dict[str, Any]:
    prev = get_job(job_id)
    if not prev:
        raise ValueError(f"Job not found: {job_id}")
    spec = {
        "bot": prev.get("target_bot"),
        "prompt": prompt_override.strip() or prev.get("prompt") or "",
        "label": prev.get("label") or f"retry:{job_id}",
        "project": prev.get("project") or "",
        "workdir": prev.get("workdir") or "",
        "model": prev.get("model") or "",
        "effort": prev.get("effort") or "",
        "mode": prev.get("mode") or "",
        "thread_key": prev.get("thread_key") or "",
        "resume_cid": prev.get("worker_cid") or prev.get("resume_cid") or "",
        "worktree": bool(prev.get("worktree")),
        "notify_group": bool(prev.get("notify_group")),
    }
    res = dispatch_assignments(
        requester_bot or prev.get("from_bot") or "",
        [spec],
        origin_scope_key=prev.get("origin_scope_key") or "",
        origin_chat_id=int(prev.get("origin_chat_id") or 0),
        origin_thread_id=prev.get("origin_thread_id"),
        origin_msg_id=int(prev.get("origin_msg_id") or 0) or None,
    )
    return res["jobs"][0]


def wait_for_jobs(
    job_ids: List[str],
    timeout_sec: float = 600.0,
    cancel_check: Optional[Any] = None,
) -> Tuple[List[Dict[str, Any]], bool]:
    """Wait until all `job_ids` settle or `timeout_sec` elapses.

    Returns `(jobs_list, all_settled)`. If `cancel_check()` returns True, returns early
    after requesting cancellation on unfinished jobs.
    """
    deadline = time.time() + max(1.0, float(timeout_sec))
    while True:
        jobs = [get_job(jid) or {"job_id": jid, "status": "error", "error": "missing"} for jid in job_ids]
        if all(j.get("status") in TERMINAL_STATUSES for j in jobs):
            return jobs, True
        if cancel_check is not None and cancel_check():
            for j in jobs:
                if j.get("status") not in TERMINAL_STATUSES:
                    try:
                        cancel_job(j["job_id"], reason="coordinator_cancelled")
                    except Exception:
                        pass
            jobs = [get_job(jid) or {"job_id": jid, "status": "cancelled"} for jid in job_ids]
            return jobs, False
        if time.time() >= deadline:
            return jobs, False
        time.sleep(0.25)


def enqueue_broadcast(
    target_bot: str,
    chat_id: int,
    message: str,
    *,
    thread_id: Optional[int] = None,
    from_bot: str = "",
) -> str:
    target = resolve_target_bot(target_bot)
    with _bus_lock():
        return _drop_inbox_packet_unlocked(
            target["handle"],
            {
                "type": "broadcast",
                "chat_id": int(chat_id),
                "thread_id": thread_id,
                "message": message,
                "from_bot": normalize_handle(from_bot),
                "created_at": time.time(),
            },
        )


def enqueue_group_say(
    sender_bot: str,
    chat_id: int,
    message: str,
    *,
    thread_id: Optional[int] = None,
    reply_to_message_id: Optional[int] = None,
    source_hop: int = 0,
    chain_id: str = "",
) -> str:
    """Enqueue a restricted `group_say` packet onto `sender_bot`'s own inbox."""
    sender = normalize_handle(sender_bot)
    if not sender:
        raise ValueError("Sender bot handle is required")
    cid = int(chat_id or 0)
    if cid >= 0:
        raise ValueError("group_say requires a group chat_id (< 0)")
    msg = (message or "").strip()
    if not msg:
        raise ValueError("group_say message cannot be empty")
    with _bus_lock():
        return _drop_inbox_packet_unlocked(
            sender,
            {
                "type": "group_say",
                "chat_id": cid,
                "thread_id": _norm_tid(thread_id),
                "reply_to_message_id": int(reply_to_message_id or 0) or None,
                "message": msg[:3000],
                "from_bot": sender,
                "source_hop": max(0, int(source_hop or 0)),
                "chain_id": str(chain_id or ""),
                "created_at": time.time(),
            },
        )


# ---------------------------------------------------------------- resumable thread index
def _thread_map_key(from_bot: str, target_bot: str, thread_key: str) -> str:
    return f"{normalize_handle(from_bot)}::{normalize_handle(target_bot)}::{thread_key.strip()}"


def thread_get(from_bot: str, target_bot: str, thread_key: str) -> str:
    if not thread_key or not thread_key.strip():
        return ""
    k = _thread_map_key(from_bot, target_bot, thread_key)
    with _bus_lock():
        data = _read_json(THREADS_FILE, {})
        entry = data.get(k)
        return str((entry or {}).get("cid") or "")


def thread_set(from_bot: str, target_bot: str, thread_key: str, cid: str) -> None:
    if not thread_key or not thread_key.strip() or not cid:
        return
    k = _thread_map_key(from_bot, target_bot, thread_key)
    with _bus_lock():
        data = _read_json(THREADS_FILE, {})
        if not isinstance(data, dict):
            data = {}
        data[k] = {"cid": cid, "updated_at": int(time.time())}
        if len(data) > 200:
            oldest = sorted(data.items(), key=lambda kv: int((kv[1] or {}).get("updated_at") or 0))[:-200]
            for old_k, _ in oldest:
                data.pop(old_k, None)
        _atomic_write_json(THREADS_FILE, data)


# ---------------------------------------------------------------- origin context & mention parser
def _norm_tid(tid: Any) -> Optional[int]:
    if tid is None or tid == "":
        return None
    try:
        val = int(tid)
    except (TypeError, ValueError):
        return None
    return val if val > 1 else None


_FENCED_CODE_RE = re.compile(r"```[\s\S]*?```")
_INLINE_CODE_RE = re.compile(r"(?<!`)(`+)(?!`)([^\n]*?)(?<!`)\1(?!`)")
_MENTION_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])@([A-Za-z0-9_]{3,32})(?![A-Za-z0-9_]*\.[A-Za-z]{2,})"
)


def extract_at_mentions(text: str) -> List[str]:
    """Extract normalized `@handle` mentions from full text while ignoring code blocks and emails/URLs."""
    if not text:
        return []
    stripped = _FENCED_CODE_RE.sub(" ", text)
    stripped = _INLINE_CODE_RE.sub(" ", stripped)
    seen: set[str] = set()
    out: List[str] = []
    for raw in _MENTION_RE.findall(stripped):
        norm = normalize_handle(raw)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
    return out


def _origin_context_key(scope_key: str, bot_handle: str = "") -> str:
    sk = (scope_key or "").strip()
    nb = normalize_handle(bot_handle or os.environ.get("AGY_BOT_HANDLE", ""))
    return f"{nb}:{sk}" if nb else sk


def set_origin_context(
    scope_key: str,
    *,
    bot_handle: str = "",
    chat_id: int = 0,
    thread_id: Optional[int] = None,
    msg_id: int = 0,
    mention_hop: int = 0,
    chain_id: str = "",
) -> None:
    """Persist latest inbound message context per `(bot_handle, scope_key)` for warm MCP sessions."""
    sk = (scope_key or "").strip()
    if not sk:
        return
    nb = normalize_handle(bot_handle or os.environ.get("AGY_BOT_HANDLE", ""))
    ctx_key = _origin_context_key(sk, nb)
    with _bus_lock():
        data = _read_json(ORIGIN_CTX_FILE, {})
        if not isinstance(data, dict):
            data = {}
        data[ctx_key] = {
            "bot_handle": nb,
            "scope_key": sk,
            "chat_id": int(chat_id or 0),
            "thread_id": _norm_tid(thread_id),
            "msg_id": int(msg_id or 0),
            "mention_hop": max(0, int(mention_hop or 0)),
            "chain_id": str(chain_id or ""),
            "updated_at": time.time(),
        }
        if len(data) > 100:
            oldest = sorted(data.items(), key=lambda kv: float((kv[1] or {}).get("updated_at") or 0))[:-100]
            for old_k, _ in oldest:
                data.pop(old_k, None)
        _atomic_write_json(ORIGIN_CTX_FILE, data)


def get_origin_context(scope_key: str, bot_handle: str = "") -> Dict[str, Any]:
    sk = (scope_key or "").strip()
    if not sk:
        return {}
    ctx_key = _origin_context_key(sk, bot_handle)
    with _bus_lock():
        data = _read_json(ORIGIN_CTX_FILE, {})
        entry = data.get(ctx_key) if isinstance(data, dict) else None
        return dict(entry) if isinstance(entry, dict) else {}


# ---------------------------------------------------------------- shared group chat ledger
def _group_history_path(chat_id: int) -> str:
    return os.path.join(GROUP_HISTORY_DIR, f"{int(chat_id)}.json")


def _cursor_key(bot_handle: str, thread_id: Optional[int]) -> str:
    norm_tid = _norm_tid(thread_id)
    return f"{normalize_handle(bot_handle)}:{norm_tid if norm_tid is not None else 'main'}"


def record_group_message(
    chat_id: int,
    *,
    msg_id: int = 0,
    thread_id: Optional[int] = None,
    sender_handle: str = "",
    sender_role: str = "",
    is_bot: bool = False,
    text: str = "",
    ts: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """Append a deduplicated group message to the per-chat ring ledger (`chat_id < 0` only)."""
    cid = int(chat_id or 0)
    if cid >= 0:
        return None
    excerpt = re.sub(r"\s+", " ", (text or "")).strip()[:500]
    if not excerpt:
        return None
    norm_tid = _norm_tid(thread_id)
    mid = int(msg_id or 0)
    now = float(ts or time.time())
    if is_bot:
        sender = normalize_handle(sender_handle) or "bot"
        role = sender_role if sender_role in VALID_ROLES else "bot"
    else:
        sender = re.sub(r"\s+", " ", (sender_handle or "").strip().lstrip("@"))[:32] or "user"
        role = "human"
    fp = hashlib.sha1(f"{norm_tid}|{sender}|{excerpt[:120]}".encode("utf-8", errors="replace")).hexdigest()[:12]

    path = _group_history_path(cid)
    with _bus_lock():
        data = _read_json(path, None)
        if not isinstance(data, dict):
            data = {"version": 1, "next_seq": 1, "entries": [], "cursors": {}}
        entries = list(data.get("entries") or [])
        if mid > 0:
            for existing in entries:
                if int(existing.get("msg_id") or 0) == mid:
                    return None
        else:
            for existing in entries[-5:]:
                if existing.get("fingerprint") == fp and abs(now - float(existing.get("ts") or 0)) < 5.0:
                    return None

        seq = int(data.get("next_seq") or (len(entries) + 1))
        entry = {
            "seq": seq,
            "msg_id": mid,
            "ts": now,
            "thread_id": norm_tid,
            "sender_handle": sender,
            "sender_role": role,
            "is_bot": bool(is_bot),
            "text_excerpt": excerpt,
            "fingerprint": fp,
        }
        entries.append(entry)
        if len(entries) > GROUP_HISTORY_LIMIT:
            entries = entries[-GROUP_HISTORY_LIMIT:]
        data["next_seq"] = seq + 1
        data["entries"] = entries
        if not isinstance(data.get("cursors"), dict):
            data["cursors"] = {}
        _atomic_write_json(path, data)
        return dict(entry)


def get_unseen_group_history(
    chat_id: int,
    bot_handle: str,
    *,
    thread_id: Optional[int] = None,
    limit: int = GROUP_HISTORY_INJECT_LIMIT,
    exclude_msg_id: int = 0,
    advance_cursor: bool = True,
) -> List[Dict[str, Any]]:
    """Return recent unseen messages in the same group/topic for `bot_handle`."""
    cid = int(chat_id or 0)
    norm_bot = normalize_handle(bot_handle)
    if cid >= 0 or not norm_bot:
        return []
    norm_tid = _norm_tid(thread_id)
    ex_mid = int(exclude_msg_id or 0)
    path = _group_history_path(cid)

    with _bus_lock():
        data = _read_json(path, None)
        if not isinstance(data, dict):
            return []
        entries = list(data.get("entries") or [])
        cursors = dict(data.get("cursors") or {})
        ckey = _cursor_key(norm_bot, norm_tid)
        cursor = int(cursors.get(ckey) or 0)

        thread_entries = [e for e in entries if _norm_tid(e.get("thread_id")) == norm_tid]
        if not thread_entries:
            return []

        unseen = [
            dict(e)
            for e in thread_entries
            if int(e.get("seq") or 0) > cursor
            and not (ex_mid and int(e.get("msg_id") or 0) == ex_mid)
            and not (bool(e.get("is_bot")) and normalize_handle(str(e.get("sender_handle") or "")) == norm_bot)
        ]
        selected = unseen[-max(1, int(limit)) :] if unseen else []

        if advance_cursor:
            max_seq = max(int(e.get("seq") or 0) for e in thread_entries)
            if max_seq > cursor:
                cursors[ckey] = max_seq
                data["cursors"] = cursors
                _atomic_write_json(path, data)
        return selected


def format_group_history_block(
    entries: List[Dict[str, Any]],
    max_chars: int = GROUP_HISTORY_MAX_CHARS,
) -> str:
    """Format group ledger entries into a bounded, injection-safe context preamble."""
    if not entries:
        return ""
    lines: List[str] = []
    for e in entries:
        ts_val = float(e.get("ts") or 0)
        try:
            t_str = datetime.datetime.fromtimestamp(ts_val).strftime("%H:%M") if ts_val > 0 else "--:--"
        except Exception:
            t_str = "--:--"
        sender = str(e.get("sender_handle") or "user")
        role = str(e.get("sender_role") or ("bot" if e.get("is_bot") else "human"))
        prefix = f"@{sender}" if e.get("is_bot") else sender
        excerpt = str(e.get("text_excerpt") or "").strip()
        if len(excerpt) > 220:
            excerpt = excerpt[:217] + "..."
        lines.append(f"[{t_str}] {prefix}({role}): {excerpt}")

    kept: List[str] = []
    total = 0
    budget = max(300, int(max_chars) - 120)
    for ln in reversed(lines):
        if total + len(ln) + 1 > budget and kept:
            break
        kept.append(ln)
        total += len(ln) + 1
    kept.reverse()
    body = "\n".join(kept)
    return (
        f"[群聊近期上下文（最近 {len(kept)} 条你尚未看过的同群/同Topic消息，仅供衔接前文）]\n"
        f"{body}"
    )


def format_unseen_group_history(
    chat_id: int,
    bot_handle: str,
    *,
    thread_id: Optional[int] = None,
    limit: int = GROUP_HISTORY_INJECT_LIMIT,
    max_chars: int = GROUP_HISTORY_MAX_CHARS,
    exclude_msg_id: int = 0,
    advance_cursor: bool = True,
) -> str:
    entries = get_unseen_group_history(
        chat_id,
        bot_handle,
        thread_id=thread_id,
        limit=limit,
        exclude_msg_id=exclude_msg_id,
        advance_cursor=advance_cursor,
    )
    return format_group_history_block(entries, max_chars=max_chars)


# ---------------------------------------------------------------- cross-process loop guard & mention relay
def _chain_scope_key(chat_id: int, thread_id: Optional[int]) -> str:
    norm_tid = _norm_tid(thread_id)
    return f"{int(chat_id)}:{norm_tid if norm_tid is not None else 'main'}"


def loop_guard_allow(scope_key: str, max_events: int = _LOOP_MAX_EVENTS, window_sec: float = _LOOP_WINDOW_SECONDS) -> bool:
    """Cross-process sliding-window guard preventing unchecked automated wake loops."""
    now = time.time()
    sk = str(scope_key or "default")
    with _bus_lock():
        data = _read_json(LOOP_GUARD_FILE, {})
        if not isinstance(data, dict):
            data = {}
        hist = [float(ts) for ts in (data.get(sk) or []) if (now - float(ts)) < window_sec]
        if len(hist) >= max_events:
            data[sk] = hist
            _atomic_write_json(LOOP_GUARD_FILE, data)
            return False
        hist.append(now)
        data[sk] = hist
        if len(data) > 200:
            for k in list(data.keys()):
                if not data[k] or (now - float(data[k][-1])) > max(window_sec, 3600.0):
                    data.pop(k, None)
        _atomic_write_json(LOOP_GUARD_FILE, data)
        return True


def mark_human_group_activity(
    chat_id: int,
    thread_id: Optional[int] = None,
    msg_id: int = 0,
) -> Optional[str]:
    """Anchor or refresh the active human-initiated `@handle` mention chain for `(chat_id, thread_id)`."""
    cid = int(chat_id or 0)
    if cid >= 0:
        return None
    skey = _chain_scope_key(cid, thread_id)
    mid = int(msg_id or 0)
    now = time.time()
    with _bus_lock():
        data = _read_json(MENTION_CHAINS_FILE, {})
        if not isinstance(data, dict):
            data = {}
        cur = data.get(skey)
        cur_mid = int(cur.get("human_msg_id") or 0) if isinstance(cur, dict) else 0
        if mid > 0 and cur_mid > 0 and mid <= cur_mid:
            return str(cur.get("chain_id") or "")
        prev_window = [
            float(t)
            for t in ((cur or {}).get("window_ts") or [])
            if (now - float(t)) < MENTION_WINDOW_SECONDS
        ]
        chain_id = f"hc-{mid or int(now * 1000)}-{uuid.uuid4().hex[:6]}"
        data[skey] = {
            "chain_id": chain_id,
            "human_ts": now,
            "human_msg_id": mid,
            "relays": 0,
            "window_ts": prev_window,
            "seen_relays": [],
        }
        for k in list(data.keys()):
            if (now - float((data[k] or {}).get("human_ts") or 0)) > 86400.0:
                data.pop(k, None)
        _atomic_write_json(MENTION_CHAINS_FILE, data)
        return chain_id


def relay_group_mentions(
    from_bot: str,
    chat_id: int,
    text: str,
    *,
    thread_id: Optional[int] = None,
    msg_id: int = 0,
    source_hop: int = 0,
    max_hops: int = DEFAULT_MAX_HOPS,
    exclude_bots: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Relay `@handle` mentions from a bot's group message to online sibling bot inboxes under cross-process loop guards."""
    cid = int(chat_id or 0)
    if cid >= 0:
        return {"relayed": [], "blocked_reason": "not_group_chat"}
    sender = normalize_handle(from_bot)
    if not sender:
        return {"relayed": [], "blocked_reason": "missing_sender"}
    excluded = {sender} | {normalize_handle(x) for x in (exclude_bots or []) if normalize_handle(x)}
    candidates = [h for h in extract_at_mentions(text) if h not in excluded]
    if not candidates:
        return {"relayed": [], "blocked_reason": ""}

    norm_tid = _norm_tid(thread_id)
    skey = _chain_scope_key(cid, norm_tid)
    now = time.time()
    mid = int(msg_id or 0)
    next_hop = max(0, int(source_hop or 0)) + 1

    with _bus_lock():
        roster_raw = _read_json(ROSTER_FILE, {"bots": {}})
        cfg_raw = _load_team_config_unlocked()
        r_bots = roster_raw.get("bots") or {}
        c_bots = cfg_raw.get("bots") or {}
        team_mirror = cfg_raw.get("mirror") if isinstance(cfg_raw.get("mirror"), dict) else {}
        online_handles: set[str] = set()
        for h in set(r_bots.keys()) | set(c_bots.keys()):
            view = _merge_bot_view(h, r_bots.get(h), c_bots.get(h), now, team_mirror=team_mirror)
            if view["online"] and view["handle"] not in excluded:
                achats = [int(x) for x in (view.get("allowed_chats") or [])]
                if not achats or cid in achats:
                    online_handles.add(view["handle"])

        targets = [h for h in candidates if h in online_handles]
        if not targets:
            return {"relayed": [], "blocked_reason": ""}

        chains = _read_json(MENTION_CHAINS_FILE, {})
        if not isinstance(chains, dict):
            chains = {}
        chain = chains.get(skey)
        if not isinstance(chain, dict) or not float(chain.get("human_ts") or 0):
            return {"relayed": [], "blocked_reason": "no_active_human_anchor"}
        if (now - float(chain["human_ts"])) > HUMAN_CHAIN_TTL_SECONDS:
            return {"relayed": [], "blocked_reason": "human_anchor_expired"}
        if next_hop > max(1, int(max_hops or DEFAULT_MAX_HOPS)):
            return {"relayed": [], "blocked_reason": f"max_hops_reached ({next_hop} > {max_hops})"}

        window_ts = [float(t) for t in (chain.get("window_ts") or []) if (now - float(t)) < MENTION_WINDOW_SECONDS]
        relays_used = int(chain.get("relays") or 0)
        seen_relays = list(chain.get("seen_relays") or [])
        chain_id = str(chain.get("chain_id") or "")

        relayed: List[str] = []
        blocked_reason = ""
        for th in targets:
            dedup_key = f"{chain_id}:{sender}:{th}:{mid}" if mid > 0 else ""
            if dedup_key and dedup_key in seen_relays:
                continue
            if len(window_ts) >= MENTION_WINDOW_MAX:
                blocked_reason = "window_rate_limited"
                break
            if relays_used >= MENTION_CHAIN_MAX_RELAYS:
                blocked_reason = "chain_relay_cap_reached"
                break
            _drop_inbox_packet_unlocked(
                th,
                {
                    "type": "group_mention",
                    "chat_id": cid,
                    "thread_id": norm_tid,
                    "from_bot": sender,
                    "msg_id": mid,
                    "text_excerpt": (text or "").strip()[:600],
                    "chain_id": chain_id,
                    "hop": next_hop,
                    "created_at": now,
                },
            )
            relayed.append(th)
            window_ts.append(now)
            relays_used += 1
            if dedup_key:
                seen_relays.append(dedup_key)

        chain["window_ts"] = window_ts[-MENTION_WINDOW_MAX:]
        chain["relays"] = relays_used
        chain["seen_relays"] = seen_relays[-32:]
        chains[skey] = chain
        _atomic_write_json(MENTION_CHAINS_FILE, chains)
        return {"relayed": relayed, "blocked_reason": blocked_reason}


def enqueue_scheduled_handoff(
    from_bot: str,
    to_bot: str,
    *,
    chat_id: int,
    thread_id: Optional[int] = None,
    msg_id: int = 0,
    task_id: str = "",
    task_name: str = "",
    text_excerpt: str = "",
) -> Dict[str, Any]:
    """Enqueue an overnight-safe `scheduled_handoff` wake packet onto `to_bot`'s inbox.

    Unlike `relay_group_mentions`, scheduled handoffs do NOT require a recent human
    anchor, while still enforcing self-handoff rejection and sliding-window rate limits
    outside `bus.lock` to prevent lock re-entrancy deadlocks.
    """
    sender = normalize_handle(from_bot)
    raw_target = (to_bot or "").strip()
    if not raw_target:
        return {"enqueued": False, "reason": "invalid_target"}

    cid = int(chat_id or 0)
    if cid == 0:
        return {"enqueued": False, "reason": "invalid_chat_id"}

    to_handle = ""
    try:
        resolved = resolve_target_bot(raw_target)
        to_handle = str(resolved.get("handle") or "")
    except ValueError:
        cand = normalize_handle(raw_target)
        if cand and cand not in VALID_ROLES:
            to_handle = cand

    if not to_handle:
        return {"enqueued": False, "reason": "unresolved_target"}

    if sender and sender == to_handle:
        return {"enqueued": False, "reason": "self_handoff"}

    # MUST run outside `with _bus_lock():` because `loop_guard_allow` acquires `bus.lock`.
    guard_key = f"sched_handoff:{task_id}:{to_handle}"
    if not loop_guard_allow(guard_key, max_events=2, window_sec=300):
        return {"enqueued": False, "reason": "rate_limited", "to_bot": to_handle}

    norm_tid = _norm_tid(thread_id)
    now = time.time()
    pkt = {
        "type": "scheduled_handoff",
        "from_bot": sender,
        "to_bot": to_handle,
        "chat_id": cid,
        "thread_id": norm_tid,
        "msg_id": int(msg_id or 0),
        "task_id": str(task_id or ""),
        "task_name": str(task_name or "")[:120],
        "text_excerpt": (text_excerpt or "").strip()[:800],
        "created_at": now,
    }
    with _bus_lock():
        pkt_path = _drop_inbox_packet_unlocked(to_handle, pkt)
    return {"enqueued": True, "to_bot": to_handle, "packet_path": pkt_path}


# ---------------------------------------------------------------- git worktree isolation
WORKTREE_DIR_NAME = ".worktrees"
WORKTREE_BRANCH_PREFIX = "agy-team/"
WORKTREE_CHANGED_FILES_LIMIT = 30
_GIT_ENV_STRIP = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
)


def _run_git(
    args: List[str],
    *,
    cwd: Optional[str] = None,
    timeout: float = 30.0,
) -> Tuple[bool, str, str]:
    """Run a non-interactive hardened Git subprocess without hanging on prompts."""
    env = dict(os.environ)
    for k in _GIT_ENV_STRIP:
        env.pop(k, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "/bin/false"
    env["SSH_ASKPASS"] = "/bin/false"
    env["GIT_SSH_COMMAND"] = "ssh -o BatchMode=yes"
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode == 0, proc.stdout or "", proc.stderr or ""
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "", repr(exc)


def _safe_worktree_id(job_id: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(job_id or "").strip()).strip("-")
    return cleaned[:80] or "job"


def _ensure_git_info_exclude(repo_root: str) -> bool:
    """Append `.worktrees/` to `<git-common-dir>/info/exclude` without touching `.gitignore`."""
    ok, out, _ = _run_git(["rev-parse", "--git-common-dir"], cwd=repo_root)
    if not ok or not out.strip():
        return False
    common_dir = out.strip()
    if not os.path.isabs(common_dir):
        common_dir = os.path.realpath(os.path.join(repo_root, common_dir))
    info_dir = os.path.join(common_dir, "info")
    os.makedirs(info_dir, exist_ok=True)
    exclude_path = os.path.join(info_dir, "exclude")

    existing = ""
    if os.path.isfile(exclude_path):
        with open(exclude_path, "r", encoding="utf-8", errors="replace") as f:
            existing = f.read()
        lines = {ln.strip() for ln in existing.splitlines()}
        if f"{WORKTREE_DIR_NAME}/" in lines or WORKTREE_DIR_NAME in lines:
            return True

    prefix = "\n" if existing and not existing.endswith("\n") else ""
    with open(exclude_path, "a", encoding="utf-8") as f:
        f.write(f"{prefix}{WORKTREE_DIR_NAME}/\n")
    return True


def prepare_job_worktree(workdir: str, job_id: str) -> Dict[str, Any]:
    """Create an isolated Git worktree `<repo>/.worktrees/<safe_id>` on `agy-team/<safe_id>`.

    Gracefully degrades (`active=False`) on missing dirs, non-Git dirs, unborn HEADs,
    or existing conflicting branches/directories without blocking job execution.
    """
    raw_wdir = os.path.realpath(os.path.expanduser(workdir)) if workdir else ""
    if not raw_wdir or not os.path.isdir(raw_wdir):
        return {"enabled": True, "active": False, "pruned": False, "reason": "workdir_missing"}

    ok_root, out_root, err_root = _run_git(["rev-parse", "--show-toplevel"], cwd=raw_wdir)
    if not ok_root or not out_root.strip():
        return {
            "enabled": True,
            "active": False,
            "pruned": False,
            "reason": "not_git_repo",
            "detail": err_root.strip()[:300],
        }
    repo_root = os.path.realpath(out_root.strip())

    ok_head, out_head, err_head = _run_git(["rev-parse", "--verify", "HEAD"], cwd=repo_root)
    if not ok_head or not out_head.strip():
        return {
            "enabled": True,
            "active": False,
            "pruned": False,
            "repo_root": repo_root,
            "reason": "unborn_or_invalid_head",
            "detail": err_head.strip()[:300],
        }
    base_commit = out_head.strip()

    safe_id = _safe_worktree_id(job_id)
    branch = f"{WORKTREE_BRANCH_PREFIX}{safe_id}"
    wt_root = os.path.join(repo_root, WORKTREE_DIR_NAME)
    wt_path = os.path.join(wt_root, safe_id)

    try:
        if not _ensure_git_info_exclude(repo_root):
            return {
                "enabled": True,
                "active": False,
                "pruned": False,
                "repo_root": repo_root,
                "base_commit": base_commit,
                "reason": "git_exclude_failed",
            }
        os.makedirs(wt_root, exist_ok=True)
    except OSError as exc:
        return {
            "enabled": True,
            "active": False,
            "pruned": False,
            "repo_root": repo_root,
            "base_commit": base_commit,
            "reason": "prepare_dir_failed",
            "detail": repr(exc)[:300],
        }

    if os.path.exists(wt_path):
        return {
            "enabled": True,
            "active": False,
            "pruned": False,
            "repo_root": repo_root,
            "base_commit": base_commit,
            "branch": branch,
            "reason": "worktree_path_exists",
        }

    has_branch, _, _ = _run_git(["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"], cwd=repo_root)
    if has_branch:
        # Only prune stale leftover branch if it has no unmerged commits
        del_ok, _, _ = _run_git(["branch", "-d", branch], cwd=repo_root)
        if not del_ok:
            return {
                "enabled": True,
                "active": False,
                "pruned": False,
                "repo_root": repo_root,
                "base_commit": base_commit,
                "branch": branch,
                "reason": "branch_already_exists",
            }

    ok_add, _, err_add = _run_git(
        ["worktree", "add", "-b", branch, wt_path, base_commit],
        cwd=repo_root,
        timeout=60.0,
    )
    if not ok_add:
        return {
            "enabled": True,
            "active": False,
            "pruned": False,
            "repo_root": repo_root,
            "base_commit": base_commit,
            "branch": branch,
            "reason": "worktree_add_failed",
            "detail": err_add.strip()[:300],
        }

    return {
        "enabled": True,
        "active": True,
        "path": os.path.realpath(wt_path),
        "branch": branch,
        "repo_root": repo_root,
        "base_commit": base_commit,
        "pruned": False,
    }


def _inspect_worktree_state(wt_path: str, base_commit: str) -> Dict[str, Any]:
    """Probe commit count and working-tree status inside an active worktree."""
    ok_rev = False
    commits: Optional[int] = None
    if base_commit:
        rev_success, out_rev, _ = _run_git(["rev-list", "--count", f"{base_commit}..HEAD"], cwd=wt_path)
        if rev_success:
            try:
                commits = int(out_rev.strip())
                ok_rev = True
            except ValueError:
                ok_rev = False

    ok_stat, out_stat, _ = _run_git(["status", "--porcelain", "--untracked-files=normal"], cwd=wt_path)
    dirty: Optional[bool] = None
    changed_files: List[str] = []
    if ok_stat:
        raw_lines = [ln.rstrip("\r") for ln in out_stat.splitlines() if ln.strip()]
        dirty = len(raw_lines) > 0
        for ln in raw_lines:
            fpath = ln[3:] if len(ln) > 3 else ln.strip()
            if " -> " in fpath:
                fpath = fpath.split(" -> ", 1)[1]
            if fpath and fpath not in changed_files:
                changed_files.append(fpath)

    if ok_rev and commits and commits > 0 and base_commit:
        ok_diff, out_diff, _ = _run_git(["diff", "--name-only", f"{base_commit}..HEAD"], cwd=wt_path)
        if ok_diff:
            for ln in out_diff.splitlines():
                fpath = ln.strip()
                if fpath and fpath not in changed_files:
                    changed_files.append(fpath)

    return {
        "ok_rev": ok_rev,
        "ok_stat": ok_stat,
        "inspection_failed": not (ok_rev and ok_stat),
        "commits": commits,
        "dirty": dirty,
        "changed_files": changed_files[:WORKTREE_CHANGED_FILES_LIMIT],
    }


def finalize_job_worktree(wt_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Auto-prune clean zero-commit worktrees; preserve any dirty, committed, or unreadable worktrees."""
    if not isinstance(wt_info, dict) or not wt_info:
        return {"enabled": False, "active": False, "pruned": False}
    if not wt_info.get("active"):
        out = dict(wt_info)
        out["active"] = False
        out.setdefault("pruned", False)
        return out

    wt_path = str(wt_info.get("path") or "")
    repo_root = str(wt_info.get("repo_root") or "")
    branch = str(wt_info.get("branch") or "")
    base_commit = str(wt_info.get("base_commit") or "")

    if not wt_path or not os.path.isdir(wt_path):
        return {
            "enabled": bool(wt_info.get("enabled", True)),
            "active": False,
            "path": wt_path,
            "branch": branch,
            "repo_root": repo_root,
            "base_commit": base_commit,
            "pruned": bool(wt_info.get("pruned", False)),
            "note": "worktree_dir_missing",
        }

    probe = _inspect_worktree_state(wt_path, base_commit)
    inspection_failed = probe["inspection_failed"]
    commits = probe["commits"]
    dirty = probe["dirty"]
    changed_files = probe["changed_files"]

    if not inspection_failed and commits == 0 and not dirty:
        rm_cwd = repo_root if (repo_root and os.path.isdir(repo_root)) else os.path.dirname(wt_path)
        ok_rm, _, err_rm = _run_git(["worktree", "remove", wt_path], cwd=rm_cwd)
        if ok_rm:
            if branch and repo_root and os.path.isdir(repo_root):
                _run_git(["branch", "-d", branch], cwd=repo_root)
            return {
                "enabled": True,
                "active": False,
                "path": wt_path,
                "branch": branch,
                "repo_root": repo_root,
                "base_commit": base_commit,
                "commits": 0,
                "dirty": False,
                "changed_files": [],
                "pruned": True,
                "inspection_failed": False,
                "note": "pruned_clean_worktree",
            }
        return {
            "enabled": True,
            "active": True,
            "path": wt_path,
            "branch": branch,
            "repo_root": repo_root,
            "base_commit": base_commit,
            "commits": 0,
            "dirty": False,
            "changed_files": [],
            "pruned": False,
            "inspection_failed": False,
            "note": f"prune_remove_failed: {err_rm.strip()[:200]}",
        }

    note = "inspection_failed_preserved" if inspection_failed else "preserved_with_changes"
    return {
        "enabled": True,
        "active": True,
        "path": wt_path,
        "branch": branch,
        "repo_root": repo_root,
        "base_commit": base_commit,
        "commits": commits,
        "dirty": dirty,
        "changed_files": changed_files,
        "pruned": False,
        "inspection_failed": inspection_failed,
        "note": note,
    }


def cleanup_job_worktree(job_id: str, force: bool = False) -> Dict[str, Any]:
    """Explicitly clean up a job's preserved worktree and branch after review/merge."""
    job = get_job(job_id)
    if not job:
        return {"ok": False, "job_id": job_id, "error": f"Job not found: {job_id}"}

    wt = (
        job.get("worktree_info")
        if isinstance(job.get("worktree_info"), dict) and job.get("worktree_info")
        else (job.get("worktree") if isinstance(job.get("worktree"), dict) else {})
    )
    if not wt or wt.get("pruned") or (not wt.get("active") and not wt.get("path")):
        return {
            "ok": True,
            "job_id": job_id,
            "pruned": bool(wt.get("pruned")) if wt else False,
            "already_clean": True,
            "note": "Worktree not active or already pruned.",
        }

    if not force and job.get("status") == "running":
        return {
            "ok": False,
            "job_id": job_id,
            "pruned": False,
            "error": "Job is still running; cancel it first or pass force=True.",
        }

    wt_path = str(wt.get("path") or "")
    repo_root = str(wt.get("repo_root") or "")
    branch = str(wt.get("branch") or "")
    base_commit = str(wt.get("base_commit") or "")

    if wt_path and os.path.isdir(wt_path):
        probe = _inspect_worktree_state(wt_path, base_commit)
        if not force:
            if not probe["ok_stat"]:
                return {
                    "ok": False,
                    "job_id": job_id,
                    "pruned": False,
                    "error": "Failed to inspect worktree status; pass force=True to force removal.",
                }
            if probe["dirty"]:
                return {
                    "ok": False,
                    "job_id": job_id,
                    "pruned": False,
                    "dirty": True,
                    "changed_files": probe["changed_files"],
                    "error": (
                        f"Worktree at {wt_path} has uncommitted changes. "
                        "Commit/merge or discard them first, or pass force=True."
                    ),
                }
            if not probe["ok_rev"]:
                return {
                    "ok": False,
                    "job_id": job_id,
                    "pruned": False,
                    "error": "Failed to inspect worktree commit history; pass force=True to force removal.",
                }
            if (probe["commits"] or 0) > 0:
                merged = False
                if branch and repo_root and os.path.isdir(repo_root):
                    merged, _, _ = _run_git(["merge-base", "--is-ancestor", branch, "HEAD"], cwd=repo_root)
                if not merged:
                    return {
                        "ok": False,
                        "job_id": job_id,
                        "pruned": False,
                        "commits": probe["commits"],
                        "branch": branch,
                        "error": (
                            f"Worktree branch {branch} has {probe['commits']} unmerged commit(s). "
                            "Merge into target branch first or pass force=True."
                        ),
                    }

        rm_cwd = repo_root if (repo_root and os.path.isdir(repo_root)) else os.path.dirname(wt_path)
        rm_args = ["worktree", "remove", "--force", wt_path] if force else ["worktree", "remove", wt_path]
        ok_rm, _, err_rm = _run_git(rm_args, cwd=rm_cwd)
        if not ok_rm:
            return {
                "ok": False,
                "job_id": job_id,
                "pruned": False,
                "error": f"git worktree remove failed: {err_rm.strip()[:300]}",
            }
    elif repo_root and os.path.isdir(repo_root):
        _run_git(["worktree", "prune"], cwd=repo_root)
        if branch and not force:
            has_br, _, _ = _run_git(["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"], cwd=repo_root)
            if has_br:
                merged, _, _ = _run_git(["merge-base", "--is-ancestor", branch, "HEAD"], cwd=repo_root)
                if not merged:
                    return {
                        "ok": False,
                        "job_id": job_id,
                        "pruned": False,
                        "branch": branch,
                        "error": (
                            f"Worktree directory is missing but branch {branch} has unmerged commits. "
                            "Merge first or pass force=True."
                        ),
                    }

    branch_deleted = False
    if branch and repo_root and os.path.isdir(repo_root):
        has_br, _, _ = _run_git(["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"], cwd=repo_root)
        if has_br:
            del_flag = "-D" if force else "-d"
            ok_br, _, err_br = _run_git(["branch", del_flag, branch], cwd=repo_root)
            if not ok_br:
                return {
                    "ok": False,
                    "job_id": job_id,
                    "pruned": False,
                    "error": f"Worktree removed but failed to delete branch {branch}: {err_br.strip()[:300]}",
                }
            branch_deleted = True

    wt_updated = dict(wt)
    wt_updated["pruned"] = True
    wt_updated["active"] = False
    wt_updated["note"] = "force_cleaned" if force else "cleaned"
    if isinstance(job.get("worktree"), dict) and not job.get("worktree_info"):
        update_job(job_id, worktree=wt_updated)
    else:
        update_job(job_id, worktree_info=wt_updated)

    return {
        "ok": True,
        "job_id": job_id,
        "pruned": True,
        "branch": branch,
        "branch_deleted": branch_deleted,
        "worktree": wt_updated,
    }


def format_worker_envelope(
    job: Dict[str, Any],
    effective_workdir: str,
    outbox_dir: str,
    worker_specialty: str = "",
    group_history: Optional[str] = None,
    worktree_info: Optional[Dict[str, Any]] = None,
) -> str:
    jid = job.get("job_id") or "?"
    sender = job.get("from_bot") or "coordinator"
    target = job.get("target_bot") or "worker"
    label = job.get("label") or ""
    prompt = job.get("prompt") or ""
    header = f"[ACB_TEAM_DELEGATION job={jid} from=@{sender} to=@{target}"
    if label:
        header += f' label="{label}"'
    header += "]"
    role_line = f"- 职责分工：{worker_specialty}\n" if worker_specialty else ""

    wt = worktree_info if worktree_info is not None else job.get("worktree_info")
    wt_line = ""
    if isinstance(wt, dict) and wt.get("active"):
        wt_branch = wt.get("branch") or ""
        wt_path = wt.get("path") or effective_workdir
        wt_root = wt.get("repo_root") or ""
        wt_line = (
            f"- 隔离 Worktree：已启用（分支 `{wt_branch}`，路径 `{wt_path}`）；"
            f"请仅在当前隔离工作目录内读写、提交与测试，严禁越权修改主检出目录"
            + (f"（`{wt_root}`）" if wt_root else "")
            + "。\n"
        )

    ctx_block = group_history if group_history is not None else ""
    origin_chat = int(job.get("origin_chat_id") or 0)
    if group_history is None and origin_chat < 0 and job.get("target_bot"):
        ctx_block = format_unseen_group_history(
            origin_chat,
            str(job.get("target_bot") or ""),
            thread_id=job.get("origin_thread_id"),
            exclude_msg_id=int(job.get("origin_msg_id") or 0),
            limit=12,
            max_chars=GROUP_HISTORY_MAX_CHARS,
            advance_cursor=True,
        )
    history_section = f"{ctx_block}\n\n" if ctx_block else ""
    return (
        f"{header}\n"
        f"你正在作为专职子 Bot（@{target}）执行主控 Bot（@{sender}）分派的任务。当前无人工实时交互，请勿反问用户，直接完成职责范围内工作并用清晰、结构化、可直接验收的总结回复（列出关键发现、改动文件或验证结果）。\n"
        f"{role_line}"
        f"- 工作目录：`{effective_workdir}`\n"
        f"{wt_line}"
        f"- 若生成截图或图片交付物，可写入 `{outbox_dir}/` 并在回复中注明完整路径。\n\n"
        f"{history_section}"
        f"任务简报：\n{prompt}"
    )


def summarize_job_brief(job: Dict[str, Any]) -> Dict[str, Any]:
    """Compact JSON-serializable summary returned to coordinator MCP tools."""
    started = float(job.get("started_at") or job.get("created_at") or 0)
    finished = float(job.get("finished_at") or 0)
    dur = round(max(0.0, finished - started), 2) if finished and started else None
    out: Dict[str, Any] = {
        "job_id": job.get("job_id"),
        "bot": f"@{job.get('target_bot')}",
        "label": job.get("label") or "",
        "status": job.get("status"),
        "duration_s": dur,
        "group_delivered": bool(job.get("group_delivered")),
    }
    if job.get("worker_cid"):
        out["worker_cid"] = job["worker_cid"]
    if job.get("progress") and job.get("status") == "running":
        out["progress"] = job["progress"]
    if job.get("result_text"):
        out["result"] = job["result_text"]
    if job.get("error"):
        out["error"] = job["error"]
    if job.get("artifacts"):
        out["artifacts"] = list(job["artifacts"])
    if job.get("usage"):
        out["usage"] = dict(job["usage"])
    wt_info = job.get("worktree_info")
    if isinstance(wt_info, dict) and wt_info:
        wt_summary: Dict[str, Any] = {}
        for bk in ("enabled", "active", "pruned"):
            if bk in wt_info:
                wt_summary[bk] = bool(wt_info[bk])
        for k in ("path", "branch", "repo_root", "base_commit", "commits", "dirty", "changed_files", "inspection_failed", "reason", "note"):
            if k in wt_info and wt_info[k] not in (None, "", []):
                wt_summary[k] = wt_info[k]
        if wt_summary:
            out["worktree"] = wt_summary
    elif job.get("worktree"):
        out["worktree"] = {"enabled": True, "active": False, "pruned": False}
    return out
