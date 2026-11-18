#!/usr/bin/env python3
"""Lightweight File-Backed Coordinator Bus for multi-bot task delegation in agy-cli-bot.

Shared by `bridge.py` (each Telegram bot process) and `bot_bus_mcp.py` (MCP tools exposed
only to coordinator/peer sessions). Uses atomic temp-file writes + `fcntl.flock` under
`~/.gemini/antigravity-cli/cache/bot_bus/` with zero external dependencies and zero secrets.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
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
LOCK_FILE = os.path.join(BUS_DIR, "bus.lock")
CONFIG_FILE = os.path.join(BUS_DIR, "team_config.json")
ROSTER_FILE = os.path.join(BUS_DIR, "roster.json")
THREADS_FILE = os.path.join(BUS_DIR, "threads.json")

VALID_ROLES = ("coordinator", "worker", "peer")
TERMINAL_STATUSES = frozenset({"done", "error", "cancelled"})
FAN_OUT_MAX = 8
DEFAULT_MAX_HOPS = 2
ONLINE_TTL_SECONDS = 45.0
JOB_RETENTION_LIMIT = 150
_LOOP_WINDOW_SECONDS = 300.0
_LOOP_MAX_EVENTS = 12


def _ensure_dirs() -> None:
    os.makedirs(BUS_DIR, mode=0o700, exist_ok=True)
    os.makedirs(JOBS_DIR, mode=0o700, exist_ok=True)
    os.makedirs(INBOX_DIR, mode=0o700, exist_ok=True)


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
                "notify_group": bool(spec.get("notify_group", default_notify_group)),
                "origin_scope_key": origin_scope_key or "",
                "origin_chat_id": int(origin_chat_id or 0),
                "origin_thread_id": origin_thread_id,
                "chain": list(chain) + [target["handle"]],
                "depth": len(chain),
                "status": "queued",
                "cancel_requested": False,
                "cancel_reason": "",
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
        "notify_group": bool(prev.get("notify_group")),
    }
    res = dispatch_assignments(
        requester_bot or prev.get("from_bot") or "",
        [spec],
        origin_scope_key=prev.get("origin_scope_key") or "",
        origin_chat_id=int(prev.get("origin_chat_id") or 0),
        origin_thread_id=prev.get("origin_thread_id"),
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


# ---------------------------------------------------------------- loop guard & prompt envelope
_loop_history: Dict[str, List[float]] = {}


def loop_guard_allow(scope_key: str, max_events: int = _LOOP_MAX_EVENTS, window_sec: float = _LOOP_WINDOW_SECONDS) -> bool:
    """Sliding-window guard ensuring automated async wake callbacks cannot loop unchecked."""
    now = time.time()
    hist = [ts for ts in _loop_history.get(scope_key, []) if (now - ts) < window_sec]
    if len(hist) >= max_events:
        _loop_history[scope_key] = hist
        return False
    hist.append(now)
    _loop_history[scope_key] = hist
    return True


def format_worker_envelope(job: Dict[str, Any], effective_workdir: str, outbox_dir: str) -> str:
    jid = job.get("job_id") or "?"
    sender = job.get("from_bot") or "coordinator"
    target = job.get("target_bot") or "worker"
    label = job.get("label") or ""
    prompt = job.get("prompt") or ""
    header = f"[ACB_TEAM_DELEGATION job={jid} from=@{sender} to=@{target}"
    if label:
        header += f' label="{label}"'
    header += "]"
    return (
        f"{header}\n"
        f"你正在作为专职子 Bot（@{target}）执行主控 Bot（@{sender}）分派的任务。当前无人工实时交互，请勿反问用户，直接完成任务并用清晰、结构化、可直接验收的总结回复（列出关键发现、改动文件或验证结果）。\n"
        f"- 工作目录：`{effective_workdir}`\n"
        f"- 若生成截图或图片交付物，可写入 `{outbox_dir}/` 并在回复中注明完整路径。\n\n"
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
    return out
