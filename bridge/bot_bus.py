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
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

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
DISPATCH_WINDOW_FILE = os.path.join(BUS_DIR, "dispatch_window.json")

VALID_ROLES = ("coordinator", "worker", "peer")
MODEL_MODE_DEFAULT = "default"
MODEL_MODE_FOLLOW = "follow"
MODEL_MODE_CUSTOM = "custom"
VALID_MODEL_MODES = (MODEL_MODE_DEFAULT, MODEL_MODE_FOLLOW, MODEL_MODE_CUSTOM)
TERMINAL_STATUSES = frozenset({"done", "error", "cancelled"})
JOB_ERROR_CODES = frozenset(
    {
        "OK",
        "WORKTREE_PREPARE_FAILED",
        "WORKER_ZOMBIE_REAPED",
        "BUDGET_EXCEEDED",
        "RETRY_LIMIT_EXCEEDED",
        "TAINT_POLICY_DENIED",
        "PRIVILEGE_ESCALATION_DENIED",
        "CANCELLED_LOCAL",
        "CANCELLED_BY_COORDINATOR",
        "TIMEOUT",
        "DRIVER_SPAWN_FAILED",
        "AGENT_EXEC_ERROR",
        "UNKNOWN_DRIVER",
    }
)
DEFAULT_BATCH_MAX_USD = 2.5
DEFAULT_BATCH_MAX_JOBS = 8
DEFAULT_MAX_RETRIES = 3
DEFAULT_WINDOW_MAX_JOBS_10M = 30
DEFAULT_JOB_MAX_RUNTIME_SEC = 2100.0
_DISPATCH_WINDOW_SECONDS = 600.0
TRUST_ORDER: Dict[str, int] = {
    "local_admin": 4,
    "local_worker": 3,
    "remote_trusted": 2,
    "remote_untrusted": 1,
    "readonly_guest": 0,
}
_TRUST_BY_RANK: Dict[int, str] = {r: k for k, r in TRUST_ORDER.items()}
TEAM_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
REMOTE_UNTRUSTED_MARKERS: Tuple[str, ...] = (
    "[REMOTE_AGENT_UNTRUSTED",
    "[REMOTE_HUB_MESSAGE",
    "[REMOTE_AGENT_PAYLOAD",
    "[REMOTE_HANDOFF",
)
FAN_OUT_MAX = 8
DEFAULT_MAX_HOPS = 2
ONLINE_TTL_SECONDS = 45.0
JOB_RETENTION_LIMIT = 150
GROUP_HISTORY_LIMIT = 40
GROUP_HISTORY_INJECT_LIMIT = 15
GROUP_HISTORY_MAX_CHARS = 2400
GROUP_HISTORY_FULL_TEXT_MAX_BYTES = 12 * 1024
SCHEDULED_HANDOFF_EXCERPT_LIMIT = 4000
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


def _parse_entry_model_state(entry: Dict[str, Any]) -> Tuple[str, str]:
    """Decode `(model_mode, configured_model)` from a `team_config.json` bot entry.

    Explicit `model_mode` (`default` | `follow` | `custom`) takes precedence; legacy entries
    without `model_mode` map missing/`None` -> `default`, `""` -> `follow`, non-empty -> `custom`.
    """
    raw_mode = str(entry.get("model_mode") or "").strip().lower()
    raw_dm = entry.get("default_model")
    clean_dm = str(raw_dm).strip() if isinstance(raw_dm, str) else (str(raw_dm).strip() if raw_dm is not None else "")
    if clean_dm == "__follow_dm__":
        clean_dm = ""

    if raw_mode in VALID_MODEL_MODES:
        if raw_mode == MODEL_MODE_DEFAULT:
            return MODEL_MODE_DEFAULT, ""
        if raw_mode == MODEL_MODE_FOLLOW:
            return MODEL_MODE_FOLLOW, ""
        if clean_dm:
            return MODEL_MODE_CUSTOM, clean_dm
        return MODEL_MODE_DEFAULT, ""

    if "default_model" not in entry or raw_dm is None:
        return MODEL_MODE_DEFAULT, ""
    if clean_dm == "":
        return MODEL_MODE_FOLLOW, ""
    return MODEL_MODE_CUSTOM, clean_dm


def resolve_bot_config(
    handle: str,
    *,
    env_role: str = "",
    env_model: str = "",
    env_effort: str = "",
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
    model_mode, configured_model = _parse_entry_model_state(entry)
    env_default_model = (env_model or "").strip()
    if model_mode == MODEL_MODE_CUSTOM:
        resolved_default_model = configured_model
    elif model_mode == MODEL_MODE_FOLLOW:
        resolved_default_model = ""
    else:
        resolved_default_model = env_default_model

    team_mirror = cfg.get("mirror") if isinstance(cfg.get("mirror"), dict) else {}
    m_chat = entry.get("mirror_chat_id") if entry.get("mirror_chat_id") is not None else team_mirror.get("chat_id")
    m_thread = entry.get("mirror_thread_id") if entry.get("mirror_chat_id") is not None else team_mirror.get("thread_id")
    return {
        "role": role,
        "specialty": (entry.get("specialty") if entry.get("specialty") is not None else env_specialty) or "",
        "model_mode": model_mode,
        "configured_model": configured_model,
        "env_default_model": env_default_model,
        "default_model": resolved_default_model,
        "default_effort": (entry.get("default_effort") if entry.get("default_effort") is not None else env_effort) or "",
        "model_updated_at": int(entry.get("model_updated_at") or 0),
        "model_rev": int(entry.get("model_rev") or 0),
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


def get_team_mirror() -> Dict[str, Any]:
    """Return normalized team-wide Telegram mirror binding (`chat_id < 0` when active, else `0`)."""
    cfg = load_team_config()
    tm = cfg.get("mirror") if isinstance(cfg.get("mirror"), dict) else {}
    raw_cid = tm.get("chat_id")
    if isinstance(raw_cid, bool):
        cid = 0
    else:
        try:
            cid = int(raw_cid or 0)
        except (TypeError, ValueError):
            cid = 0
    if cid >= 0:
        return {"chat_id": 0, "thread_id": None}
    return {"chat_id": cid, "thread_id": _norm_tid(tm.get("thread_id"))}


def _update_bot_config_unlocked(norm: str, **updates: Any) -> Dict[str, Any]:
    cfg = _load_team_config_unlocked()
    bots = cfg.setdefault("bots", {})
    cur = dict(bots.get(norm) or {})
    prev_rev = int(cur.get("model_rev") or 0)
    now = int(time.time())

    has_mode = "model_mode" in updates
    has_dm = "default_model" in updates
    for k, v in updates.items():
        if k == "role" and v not in VALID_ROLES:
            raise ValueError(f"Invalid role: {v}")
        if k == "model_mode":
            norm_mode = str(v or "").strip().lower()
            if norm_mode not in VALID_MODEL_MODES:
                raise ValueError(f"Invalid model_mode: {v}")
            cur["model_mode"] = norm_mode
        else:
            cur[k] = v

    if has_mode:
        mode_val = cur["model_mode"]
        if mode_val == MODEL_MODE_DEFAULT:
            cur["default_model"] = None
        elif mode_val == MODEL_MODE_FOLLOW:
            cur["default_model"] = ""
        elif mode_val == MODEL_MODE_CUSTOM:
            dm_clean = str(cur.get("default_model") or "").strip()
            if not dm_clean or dm_clean == "__follow_dm__":
                raise ValueError("Custom model_mode requires a non-empty default_model")
            cur["default_model"] = dm_clean
    elif has_dm:
        raw_dm = cur.get("default_model")
        if raw_dm is None:
            cur["model_mode"] = MODEL_MODE_DEFAULT
            cur["default_model"] = None
        else:
            dm_clean = str(raw_dm).strip()
            if not dm_clean or dm_clean == "__follow_dm__":
                cur["model_mode"] = MODEL_MODE_FOLLOW
                cur["default_model"] = ""
            else:
                cur["model_mode"] = MODEL_MODE_CUSTOM
                cur["default_model"] = dm_clean

    if has_mode or has_dm:
        if "model_updated_at" not in updates or not updates.get("model_updated_at"):
            cur["model_updated_at"] = now
        else:
            cur["model_updated_at"] = int(updates["model_updated_at"])
        explicit_rev = int(updates.get("model_rev") or 0) if "model_rev" in updates and updates.get("model_rev") is not None else 0
        cur["model_rev"] = max(prev_rev + 1, explicit_rev)

    cur["updated_at"] = now
    bots[norm] = cur
    _atomic_write_json(CONFIG_FILE, cfg)
    return dict(cur)


def update_bot_config(handle: str, **updates: Any) -> Dict[str, Any]:
    """Persist team configuration fields for `handle` under `bus.lock`."""
    norm = normalize_handle(handle)
    if not norm:
        raise ValueError("Bot handle is required")
    with _bus_lock():
        return _update_bot_config_unlocked(norm, **updates)


def _normalize_model_config_args(mode: str, model: str = "") -> Tuple[str, Optional[str]]:
    norm_mode = str(mode or MODEL_MODE_DEFAULT).strip().lower()
    if norm_mode not in VALID_MODEL_MODES:
        raise ValueError(f"Invalid model_mode: {mode}")
    if norm_mode == MODEL_MODE_CUSTOM:
        clean_model = str(model or "").strip()
        if not clean_model or clean_model == "__follow_dm__":
            raise ValueError("Custom model mode requires a concrete model slug")
        return MODEL_MODE_CUSTOM, clean_model
    if norm_mode == MODEL_MODE_FOLLOW:
        return MODEL_MODE_FOLLOW, ""
    return MODEL_MODE_DEFAULT, None


def set_bot_model_config(handle: str, mode: str, model: str = "") -> Dict[str, Any]:
    """Explicitly configure a bot's group/team model mode (`default`, `follow`, or `custom`)."""
    norm_mode, default_model_val = _normalize_model_config_args(mode, model)
    return update_bot_config(handle, model_mode=norm_mode, default_model=default_model_val)


def set_bot_model_and_notify(
    handle: str,
    mode: str,
    model: str = "",
    *,
    from_bot: str = "",
    chat_id: int = 0,
    thread_id: Optional[int] = None,
    notify_target: bool = True,
) -> Dict[str, Any]:
    """Atomically update `team_config.json` (bumping `model_rev`) and enqueue `sync_group_model` under one `_bus_lock()`."""
    norm = normalize_handle(handle)
    if not norm:
        raise ValueError("Bot handle is required")
    norm_mode, default_model_val = _normalize_model_config_args(mode, model)
    clean_model = default_model_val if norm_mode == MODEL_MODE_CUSTOM and default_model_val else ""
    with _bus_lock():
        rec = _update_bot_config_unlocked(norm, model_mode=norm_mode, default_model=default_model_val)
        if notify_target:
            _drop_inbox_packet_unlocked(
                norm,
                {
                    "type": "sync_group_model",
                    "target_bot": norm,
                    "from_bot": normalize_handle(from_bot) if from_bot else "",
                    "model_mode": norm_mode,
                    "model": clean_model,
                    "model_rev": int(rec.get("model_rev") or 0),
                    "model_updated_at": int(rec.get("model_updated_at") or 0),
                    "chat_id": int(chat_id or 0),
                    "thread_id": _norm_tid(thread_id),
                    "created_at": time.time(),
                },
            )
        return rec


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
                    cur["model_mode"] = MODEL_MODE_CUSTOM
                    cur["model_updated_at"] = now
                    cur["model_rev"] = int(cur.get("model_rev") or 0) + 1
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

    model_mode, configured_model = _parse_entry_model_state(cfg)
    env_default_model = str(r.get("env_default_model") or "").strip()
    if "dm_model" in r:
        dm_model = str(r.get("dm_model") or "").strip()
    else:
        dm_model = str(r.get("active_model") or "").strip()
    if dm_model == "__follow_dm__":
        dm_model = ""

    if model_mode == MODEL_MODE_CUSTOM:
        effective_model = configured_model
    elif model_mode == MODEL_MODE_FOLLOW:
        effective_model = dm_model or env_default_model
    else:
        effective_model = env_default_model

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
        "model_mode": model_mode,
        "configured_model": configured_model,
        "dm_model": dm_model,
        "env_default_model": env_default_model,
        "effective_model": effective_model,
        "model_updated_at": int(cfg.get("model_updated_at") or 0),
        "model_rev": int(cfg.get("model_rev") or 0),
        "default_model": effective_model,
        "default_effort": str(cfg.get("default_effort") if cfg.get("default_effort") is not None else (r.get("default_effort") or "")).strip(),
        "active_model": str(r.get("active_model") or dm_model or "").strip(),
        "default_workdir": cfg.get("default_workdir") or r.get("workdir") or "",
        "default_project": cfg.get("default_project") if cfg.get("default_project") is not None else (r.get("project") or ""),
        "allowed_chats": list(r.get("allowed_chats") or []),
        "ipc_sock": str(r.get("ipc_sock") or "") if online else "",
        "mirror_chat_id": int(m_chat or 0),
        "mirror_thread_id": m_thread,
        "last_seen": last_seen,
        "pid": pid,
    }


def _federation_mod():
    try:
        if __package__:
            from . import federation_registry as _fed  # type: ignore
        else:
            import federation_registry as _fed  # type: ignore
        return _fed
    except ImportError:
        return None


def _reject_unsafe_actor_id(raw: Any, *, field: str = "agent_id") -> str:
    """Fail-closed against path traversal, null bytes, or illegal dots in actor/agent IDs."""
    if not isinstance(raw, str):
        raise ValueError(f"Invalid {field} type: {type(raw).__name__}")
    cleaned = raw.strip()
    if not cleaned:
        return ""
    if ".." in cleaned or "/" in cleaned or "\\" in cleaned or "\x00" in cleaned:
        raise ValueError(f"Unsafe {field} rejected: {raw!r}")
    body = cleaned.lstrip("@")
    if "." in body:
        raise ValueError(f"Unsafe {field} rejected (dot not permitted): {raw!r}")
    return cleaned


def _merge_federated_roster(base_roster: List[Dict[str, Any]], *, include_offline: bool = True) -> List[Dict[str, Any]]:
    fed = _federation_mod()
    if fed is None or not fed.has_federation_state(BUS_DIR):
        return base_roster
    all_fed_agents = {
        str(a.get("agent_id") or ""): a
        for a in fed.list_agents(bus_dir=BUS_DIR, include_disabled=True, include_revoked=True)
        if isinstance(a, dict) and a.get("agent_id")
    }
    by_handle: Dict[str, Dict[str, Any]] = {str(b.get("handle") or ""): dict(b) for b in base_roster}
    # B7.3: Authoritative federation revoked/disabled state overrides legacy heartbeat/online state.
    for aid, ag in all_fed_agents.items():
        if ag.get("revoked"):
            by_handle.pop(aid, None)
        elif not ag.get("enabled", True):
            if aid in by_handle:
                by_handle[aid]["online"] = False
                by_handle[aid]["busy"] = False
                by_handle[aid]["enabled"] = False
                if not include_offline:
                    by_handle.pop(aid, None)

    fed_items = fed.list_effective_roster(bus_dir=BUS_DIR, include_offline=include_offline)
    for fitem in fed_items:
        h = str(fitem.get("handle") or "")
        if not h:
            continue
        if h in by_handle:
            existing = by_handle[h]
            existing["federated"] = True
            existing["kind"] = fitem.get("kind") or existing.get("kind") or "agy_local"
            existing["driver"] = fitem.get("driver") or existing.get("driver") or "agy"
            existing["transport"] = fitem.get("transport") or existing.get("transport") or "local_cli"
            existing["coordinator_peer"] = bool(fitem.get("coordinator_peer"))
            existing["host_server_invoke"] = bool(fitem.get("host_server_invoke"))
            existing["can_dispatch"] = bool(fitem.get("can_dispatch", False))
            existing["can_receive"] = bool(fitem.get("can_receive", True))
            existing["allowed_teams"] = list(fitem.get("allowed_teams") or [])
            existing["led_teams"] = list(fitem.get("led_teams") or [])
            existing["teams"] = list(fitem.get("teams") or [])
            existing["has_active_token"] = bool(fitem.get("has_active_token"))
            if not fitem.get("online"):
                existing["online"] = False
                existing["busy"] = False
        else:
            by_handle[h] = dict(fitem)
    merged = list(by_handle.values())
    role_order = {"coordinator": 0, "peer": 1, "worker": 2}
    merged.sort(key=lambda b: (0 if b.get("online") else 1, role_order.get(str(b.get("role") or ""), 9), str(b.get("handle") or "")))
    return merged


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
    return _merge_federated_roster(out, include_offline=include_offline)


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


def resolve_bot_by_id(bot_id: Any) -> Optional[Dict[str, Any]]:
    """Deterministically resolve a unique bot roster entry by numeric Telegram `bot_id` (fail-closed).

    Returns the merged bot view dict ONLY when exactly one unique normalized handle in `roster.json`
    matches the strict positive integer `bot_id`. Returns `None` on invalid ID, 0 matches, or >1 ambiguous matches.
    """
    if isinstance(bot_id, bool) or bot_id is None:
        return None
    if isinstance(bot_id, int):
        target_id = bot_id
    elif isinstance(bot_id, str):
        raw = bot_id.strip()
        if not raw or not raw.isascii() or not raw.isdigit():
            return None
        target_id = int(raw)
    else:
        return None
    if target_id <= 0:
        return None

    now = time.time()
    with _bus_lock():
        roster = _read_json(ROSTER_FILE, {"bots": {}})
        cfg = _load_team_config_unlocked()
    r_bots = roster.get("bots") if isinstance(roster, dict) else {}
    if not isinstance(r_bots, dict):
        return None
    c_bots = cfg.get("bots") if isinstance(cfg, dict) else {}
    team_mirror = cfg.get("mirror") if isinstance(cfg.get("mirror"), dict) else {}

    matches: List[Dict[str, Any]] = []
    seen_handles: set[str] = set()
    for raw_h, raw_entry in r_bots.items():
        if not isinstance(raw_entry, dict):
            continue
        raw_bid = raw_entry.get("bot_id")
        if isinstance(raw_bid, bool) or raw_bid is None:
            continue
        try:
            bid_int = int(raw_bid)
        except (TypeError, ValueError):
            continue
        if bid_int != target_id:
            continue
        norm_h = normalize_handle(str(raw_entry.get("handle") or raw_h or ""))
        if not norm_h or norm_h in seen_handles:
            continue
        seen_handles.add(norm_h)
        matches.append(_merge_bot_view(norm_h, raw_entry, (c_bots or {}).get(norm_h), now, team_mirror=team_mirror))

    if len(matches) != 1:
        return None
    return matches[0]


def enqueue_live_browser_takeover_event(target_bot: str, event: Dict[str, Any]) -> str:
    """Atomically enqueue a validated `live_browser_takeover_event` packet onto `target_bot`'s inbox."""
    norm_target = normalize_handle(target_bot)
    if not norm_target:
        raise ValueError("Target bot handle is required")
    if not isinstance(event, dict):
        raise ValueError("Event payload must be a dict")
    raw_uid = event.get("owner_uid")
    raw_cid = event.get("chat_id")
    if (
        isinstance(raw_uid, bool)
        or not isinstance(raw_uid, int)
        or raw_uid <= 0
        or isinstance(raw_cid, bool)
        or not isinstance(raw_cid, int)
        or raw_cid != raw_uid
    ):
        raise ValueError("live_browser_takeover_event requires chat_id == owner_uid > 0")
    raw_sgen = event.get("session_gen")
    raw_tgen = event.get("takeover_gen")
    if (
        isinstance(raw_sgen, bool)
        or not isinstance(raw_sgen, int)
        or raw_sgen < 0
        or isinstance(raw_tgen, bool)
        or not isinstance(raw_tgen, int)
        or raw_tgen < 0
    ):
        raise ValueError("live_browser_takeover_event requires non-negative integer session_gen and takeover_gen")
    if not isinstance(event.get("active"), bool):
        raise ValueError("live_browser_takeover_event requires boolean active")

    packet = dict(event)
    packet["type"] = "live_browser_takeover_event"
    packet["owner_bot"] = norm_target
    packet["owner_uid"] = raw_uid
    packet["chat_id"] = raw_cid
    packet["thread_id"] = None
    packet["session_gen"] = raw_sgen
    packet["takeover_gen"] = raw_tgen
    packet.setdefault("ts", time.time())
    with _bus_lock():
        return _drop_inbox_packet_unlocked(norm_target, packet)


# ---------------------------------------------------------------- inbox packets & jobs
def validate_team_id(team_id: Any) -> str:
    """Strictly validate `team_id` (`""` or `^[a-z0-9][a-z0-9_-]{1,63}$`; rejects traversal chars)."""
    if team_id is None or team_id == "":
        return ""
    if not isinstance(team_id, str):
        raise ValueError(f"Invalid team_id type: {type(team_id).__name__}")
    if "." in team_id or "/" in team_id or "\\" in team_id or "\x00" in team_id:
        raise ValueError(f"Unsafe team_id value: {team_id!r}")
    if not TEAM_ID_RE.fullmatch(team_id):
        raise ValueError(f"Invalid team_id format: {team_id!r} (expected ^[a-z0-9][a-z0-9_-]{{1,63}}$)")
    return team_id


def validate_job_id(job_id: Any) -> str:
    """Strictly validate `job_id` against path traversal and illegal characters (fail-closed)."""
    if not isinstance(job_id, str) or not job_id:
        raise ValueError(f"Invalid job_id: {job_id!r}")
    if ".." in job_id or "/" in job_id or "\\" in job_id or "\x00" in job_id or job_id in (".", ".."):
        raise ValueError(f"Unsafe job_id path traversal rejected: {job_id!r}")
    if not JOB_ID_RE.fullmatch(job_id):
        raise ValueError(f"Invalid job_id format: {job_id!r}")
    return job_id


def _normalize_trust_level(level: Any, *, default: str = "local_admin") -> str:
    if level is None:
        return default
    raw = str(level).strip().lower()
    if not raw:
        return default
    if raw in TRUST_ORDER:
        return raw
    return "readonly_guest"


def _min_trust_level(a: Any, b: Any, *, default: str = "remote_untrusted") -> str:
    na = _normalize_trust_level(a, default=default)
    nb = _normalize_trust_level(b, default=default)
    return _TRUST_BY_RANK[min(TRUST_ORDER[na], TRUST_ORDER[nb])]


def _min_runtime_mode(a: Optional[str], b: Optional[str], *, default: str = "") -> str:
    vals: List[str] = []
    for raw in (a, b):
        s = str(raw or "").strip().lower()
        if not s:
            continue
        vals.append("auto" if s == "auto" else "safe")
    if not vals:
        return default
    return "safe" if "safe" in vals else "auto"


def _is_remote_origin(origin: Any) -> bool:
    return str(origin or "").strip().lower().startswith("remote")


def _is_external_agent_origin(origin: Any) -> bool:
    orig = str(origin or "").strip().lower()
    if not orig:
        return False
    try:
        import memory_guard as _mg  # type: ignore

        return bool(_mg.is_external_agent_origin(orig))
    except Exception:
        try:
            from bridge import memory_guard as _mg  # type: ignore

            return bool(_mg.is_external_agent_origin(orig))
        except Exception:
            # Fail-closed if memory_guard cannot be imported
            return orig not in ("local_bus", "local_tg", "local_web", "local_tg_fast")


def _text_has_untrusted_taint(text: str) -> bool:
    if not text:
        return False
    if any(marker in text for marker in REMOTE_UNTRUSTED_MARKERS):
        return True
    try:
        import memory_guard as _mg  # type: ignore

        return bool(_mg.inspect_text(text).get("untrusted"))
    except Exception:
        return False


def _read_proc_stat_info(pid: int, proc_root: str = "/proc") -> Tuple[Optional[str], Optional[str]]:
    """Read `(state, starttime)` from `<proc_root>/<pid>/stat` (post-comm index 19 == field 22)."""
    stat_path = os.path.join(proc_root, str(pid), "stat")
    try:
        with open(stat_path, "r", encoding="utf-8", errors="ignore") as fh:
            raw = fh.read()
    except OSError:
        return None, None
    idx = raw.rfind(")")
    if idx < 0:
        return None, None
    rest = raw[idx + 2 :].split()
    if len(rest) <= 19:
        return None, None
    return rest[0], rest[19]


def _read_proc_euid(pid: int, proc_root: str = "/proc") -> Optional[int]:
    """Read effective UID from `<proc_root>/<pid>/status` (`Uid:` line), or None."""
    status_path = os.path.join(proc_root, str(pid), "status")
    try:
        with open(status_path, "r", encoding="utf-8", errors="ignore") as fh:
            raw = fh.read()
    except OSError:
        return None
    for line in raw.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            try:
                if len(parts) >= 3:
                    return int(parts[2])
                if len(parts) == 2:
                    return int(parts[1])
            except ValueError:
                return None
            return None
    return None


def _job_path(job_id: str) -> str:
    clean_id = validate_job_id(job_id)
    jobs_root = os.path.realpath(JOBS_DIR)
    candidate = os.path.join(JOBS_DIR, f"{clean_id}.json")
    cand_real = os.path.realpath(candidate)
    if not cand_real.startswith(jobs_root + os.sep):
        raise ValueError(f"Job path escapes JOBS_DIR: {job_id!r}")
    return candidate


_PKT_SEQ = 0
_LAST_PKT_NS_BY_DIR: Dict[str, int] = {}


def _scan_inbox_max_ns_unlocked() -> int:
    """Scan existing `INBOX_DIR/*/*.json` filenames under `_bus_lock()` to bootstrap watermark."""
    max_ns = 0
    try:
        if not os.path.isdir(INBOX_DIR):
            return 0
        for bot_entry in os.scandir(INBOX_DIR):
            if not bot_entry.is_dir(follow_symlinks=False):
                continue
            try:
                for pkt_entry in os.scandir(bot_entry.path):
                    fn = pkt_entry.name
                    if fn.endswith(".json") and not fn.endswith(".tmp"):
                        ts_ns = _inbox_sort_key(fn)[0]
                        if ts_ns > max_ns:
                            max_ns = ts_ns
            except OSError:
                continue
    except OSError:
        return max_ns
    return max_ns


def _next_monotonic_pkt_ns_unlocked() -> int:
    """Return a strictly increasing nanosecond timestamp shared across processes under `_bus_lock()`.

    When `.last_pkt_ns` is missing, empty, or corrupted, bootstraps from existing
    `INBOX_DIR/*/*.json` backlog. Fails closed (raises `OSError`) if watermark
    persistence cannot be committed atomically.
    """
    now_ns = time.time_ns()
    inbox_key = os.path.realpath(INBOX_DIR)
    wm_path = os.path.join(INBOX_DIR, ".last_pkt_ns")
    prev_ns = _LAST_PKT_NS_BY_DIR.get(inbox_key, 0)
    wm_valid = False
    try:
        with open(wm_path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        if raw.isdigit():
            file_ns = int(raw)
            if file_ns > 0:
                wm_valid = True
                if file_ns > prev_ns:
                    prev_ns = file_ns
    except (OSError, UnicodeError, ValueError):
        wm_valid = False

    if not wm_valid:
        backlog_ns = _scan_inbox_max_ns_unlocked()
        if backlog_ns > prev_ns:
            prev_ns = backlog_ns

    mono_ns = now_ns if now_ns > prev_ns else (prev_ns + 1)
    os.makedirs(INBOX_DIR, mode=0o700, exist_ok=True)
    tmp = f"{wm_path}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(str(mono_ns))
        os.chmod(tmp, 0o600)
        os.replace(tmp, wm_path)
    except OSError:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass
        raise
    _LAST_PKT_NS_BY_DIR[inbox_key] = mono_ns
    return mono_ns


def _inbox_sort_key(filename: str) -> Tuple[int, int, str]:
    """Normalize legacy 13-digit ms and 20-digit ns inbox filenames into unified `(ts_ns, seq, filename)` order."""
    stem = filename[:-5] if filename.endswith(".json") else filename
    parts = stem.split("_")
    ts_ns = 0
    seq = 0
    if parts and parts[0].isdigit():
        ts_part = parts[0]
        raw_ts = int(ts_part)
        if len(ts_part) <= 13 or raw_ts < 10**15:
            ts_ns = raw_ts * 1_000_000
        else:
            ts_ns = raw_ts
        if len(parts) >= 3 and parts[1].isdigit():
            seq = int(parts[1])
    return (ts_ns, seq, filename)


def _drop_inbox_packet_unlocked(target_handle: str, packet: Dict[str, Any]) -> str:
    global _PKT_SEQ
    norm = normalize_handle(target_handle)
    bot_inbox = os.path.join(INBOX_DIR, norm)
    os.makedirs(bot_inbox, mode=0o700, exist_ok=True)
    _PKT_SEQ = (_PKT_SEQ + 1) % 1_000_000
    ts_ns = _next_monotonic_pkt_ns_unlocked()
    pkt_name = f"{ts_ns:020d}_{_PKT_SEQ:06d}_{uuid.uuid4().hex[:8]}.json"
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
            names = sorted(
                (fn for fn in os.listdir(bot_inbox) if fn.endswith(".json") and not fn.endswith(".tmp")),
                key=_inbox_sort_key,
            )
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


def _record_dispatch_window_unlocked(now: float, count: int, max_jobs_10m: int) -> None:
    """Enforce and record 10-minute rolling job dispatch rate limit under `_bus_lock()`."""
    data = _read_json(DISPATCH_WINDOW_FILE, {"events": []})
    events = data.get("events") if isinstance(data, dict) else []
    if not isinstance(events, list):
        events = []
    cutoff = now - _DISPATCH_WINDOW_SECONDS
    recent = [float(ts) for ts in events if isinstance(ts, (int, float)) and float(ts) >= cutoff]
    if len(recent) + count > max_jobs_10m:
        raise ValueError(
            f"BUDGET_EXCEEDED: 10-minute dispatch window limit exceeded ({len(recent)} + {count} > {max_jobs_10m})"
        )
    recent.extend([now] * count)
    _atomic_write_json(DISPATCH_WINDOW_FILE, {"events": recent})


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
    team_id: str = "",
    agent_origin: str = "",
    trust_level: str = "",
    parent_trust_level: str = "",
    parent_agent_origin: str = "",
    parent_readonly: Optional[bool] = None,
    parent_untrusted: Optional[bool] = None,
    parent_tainted: Optional[bool] = None,
    parent_max_runtime_mode: str = "",
    batch_budget_usd: Optional[float] = None,
    max_batch_usd: Optional[float] = None,
    max_batch_jobs: Optional[int] = None,
    max_window_jobs_10m: Optional[int] = None,
    retry_count: int = 0,
    max_retries: Optional[int] = None,
    parent_job_id: str = "",
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate and enqueue 1..FAN_OUT_MAX delegation jobs atomically onto target bot inboxes."""
    _reject_unsafe_actor_id(from_bot, field="from_bot")
    sender = normalize_handle(from_bot)
    if not sender:
        raise ValueError("Sender bot handle could not be determined")
    if not assignments or not isinstance(assignments, list):
        raise ValueError("At least one assignment is required")

    # C2: Fail-closed if caller/parent session is readonly (monotonic OR with env)
    env_rbac_ro = os.environ.get("AGY_RBAC_ROLE", "").strip().lower() == "readonly"
    env_p_trust = os.environ.get("AGY_TRUST_LEVEL", "").strip()
    arg_p_trust = str(parent_trust_level or "").strip()
    arg_trust = str(trust_level or "").strip()
    eff_parent_ro = bool(parent_readonly) or env_rbac_ro
    for _raw_t in (arg_p_trust, env_p_trust, arg_trust):
        if _raw_t and _normalize_trust_level(_raw_t) == "readonly_guest":
            eff_parent_ro = True
    if eff_parent_ro:
        raise PermissionError("PRIVILEGE_ESCALATION_DENIED: readonly session cannot dispatch assignments")

    # C8b + P0-2: Strict team_id whitelist & monotonic env team binding
    env_team_id = validate_team_id(os.environ.get("AGY_BOT_TEAM_ID", "").strip())
    arg_team_id = validate_team_id(team_id)
    if env_team_id and arg_team_id and arg_team_id != env_team_id:
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: cross-team dispatch rejected ({arg_team_id!r} != {env_team_id!r})"
        )
    clean_team_id = env_team_id or arg_team_id

    # C7: Retry, batch size, and budget limits
    eff_max_retries = DEFAULT_MAX_RETRIES if max_retries is None else max(0, int(max_retries))
    eff_retry_count = max(0, int(retry_count or 0))
    if eff_retry_count > eff_max_retries:
        raise ValueError(
            f"RETRY_LIMIT_EXCEEDED: retry_count={eff_retry_count} exceeds max_retries={eff_max_retries}"
        )

    eff_max_jobs = DEFAULT_BATCH_MAX_JOBS if max_batch_jobs is None else max(1, int(max_batch_jobs))
    job_cap = min(FAN_OUT_MAX, eff_max_jobs)
    if len(assignments) > job_cap:
        raise ValueError(f"BUDGET_EXCEEDED: Too many fan-out assignments ({len(assignments)} > {job_cap})")

    cap_usd = DEFAULT_BATCH_MAX_USD if max_batch_usd is None else float(max_batch_usd)
    eff_budget_usd = cap_usd if batch_budget_usd is None else float(batch_budget_usd)
    if eff_budget_usd <= 0 or eff_budget_usd > cap_usd:
        raise ValueError(
            f"BUDGET_EXCEEDED: batch_budget_usd={eff_budget_usd} outside allowed range (0, {cap_usd}]"
        )
    est_total_usd = 0.0
    for spec in assignments:
        if isinstance(spec, dict) and spec.get("estimated_usd") is not None:
            est_total_usd += max(0.0, float(spec["estimated_usd"]))
    if est_total_usd > eff_budget_usd:
        raise ValueError(
            f"BUDGET_EXCEEDED: estimated batch cost ${est_total_usd:.4f} exceeds budget ${eff_budget_usd:.4f}"
        )

    if max_window_jobs_10m is not None:
        eff_window_max = max(1, int(max_window_jobs_10m))
    else:
        raw_wm = os.environ.get("AGY_BOT_BUS_WINDOW_MAX_JOBS_10M", "").strip()
        try:
            eff_window_max = max(1, int(raw_wm)) if raw_wm else DEFAULT_WINDOW_MAX_JOBS_10M
        except ValueError:
            eff_window_max = DEFAULT_WINDOW_MAX_JOBS_10M

    # P0-2: Monotonic agent_origin resolution (remote* cannot be downgraded to non-remote)
    env_origin = os.environ.get("AGY_AGENT_ORIGIN", "").strip().lower()
    arg_p_origin = str(parent_agent_origin or "").strip().lower()
    arg_origin = str(agent_origin or "").strip().lower()
    if _is_remote_origin(env_origin):
        if arg_origin and not _is_remote_origin(arg_origin):
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: cannot override remote agent_origin {env_origin!r} with {arg_origin!r}"
            )
        eff_origin = arg_origin if _is_remote_origin(arg_origin) else env_origin
    elif _is_remote_origin(arg_p_origin):
        if arg_origin and not _is_remote_origin(arg_origin):
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: cannot override remote agent_origin {arg_p_origin!r} with {arg_origin!r}"
            )
        eff_origin = arg_origin if _is_remote_origin(arg_origin) else arg_p_origin
    else:
        eff_origin = arg_origin or arg_p_origin or env_origin or "local_bus"
    parent_is_remote = _is_remote_origin(eff_origin)

    # C2: Parent taint & trust ceiling calculation (monotonic OR / min attenuation with env)
    env_untr = (
        os.environ.get("AGY_UNTRUSTED_SESSION", "").strip() == "1"
        or os.environ.get("AGY_MEMORY_READONLY", "").strip() == "1"
    )
    eff_parent_untr = bool(parent_untrusted) or env_untr or parent_is_remote
    eff_parent_tainted = bool(parent_tainted) or eff_parent_untr

    trust_candidates: List[str] = []
    if arg_p_trust:
        trust_candidates.append(_normalize_trust_level(arg_p_trust))
    if env_p_trust:
        trust_candidates.append(_normalize_trust_level(env_p_trust))
    if trust_candidates:
        eff_parent_trust = trust_candidates[0]
        for cand in trust_candidates[1:]:
            eff_parent_trust = _min_trust_level(eff_parent_trust, cand)
    else:
        eff_parent_trust = "remote_untrusted" if (eff_parent_untr or eff_parent_tainted) else "local_admin"

    if eff_parent_untr or eff_parent_tainted or parent_is_remote:
        eff_parent_trust = _min_trust_level(eff_parent_trust, "remote_untrusted")
    if TRUST_ORDER[eff_parent_trust] <= TRUST_ORDER["remote_untrusted"]:
        eff_parent_untr = True
        eff_parent_tainted = True

    env_max_mode = os.environ.get("AGY_MAX_RUNTIME_MODE", "").strip().lower()
    eff_parent_max_mode = _min_runtime_mode(parent_max_runtime_mode, env_max_mode, default="")
    if eff_parent_ro:
        eff_parent_max_mode = "safe"

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
        roster = _merge_federated_roster(roster, include_offline=True)
        fed = _federation_mod()
        fed_active = bool(fed is not None and fed.has_federation_state(BUS_DIR))

        resolved_specs = []
        sender_auth: Optional[Dict[str, Any]] = None
        fed_teams_by_id: Optional[Dict[str, Dict[str, Any]]] = None
        for idx, spec in enumerate(assignments):
            if not isinstance(spec, dict):
                raise ValueError(f"Assignment #{idx + 1} must be an object")
            target_q = str(spec.get("bot") or "").strip()
            _reject_unsafe_actor_id(target_q, field="target_bot")
            prompt = str(spec.get("prompt") or "").strip()
            if not prompt:
                raise ValueError(f"Assignment #{idx + 1} prompt cannot be empty")
            raw_spec_team = validate_team_id(spec.get("team_id") or "")
            if clean_team_id and raw_spec_team and raw_spec_team != clean_team_id:
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: assignment team_id {raw_spec_team!r} does not match bound team_id {clean_team_id!r}"
                )
            spec_team = clean_team_id or raw_spec_team
            raw_spec_origin = str(spec.get("agent_origin") or "").strip().lower()
            if parent_is_remote and raw_spec_origin and not _is_remote_origin(raw_spec_origin):
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: assignment cannot override remote agent_origin {eff_origin!r} with {raw_spec_origin!r}"
                )
            spec_origin = raw_spec_origin or eff_origin or "local_bus"
            target = resolve_target_bot(target_q, roster=roster)
            th = target["handle"]
            if th == sender:
                raise ValueError(f"Cannot dispatch to self (@{sender}); execute directly or use invoke_subagent")
            if th in chain:
                raise ValueError(f"Cycle detected in delegation chain ({' -> '.join(chain)} -> {th})")
            if not target["online"]:
                raise ValueError(f"Target bot @{th} is currently offline")
            if target.get("can_receive") is False:
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: target agent {th!r} has capabilities.can_receive=False"
                )
            if fed_active and fed is not None:
                auth_res = fed.authorize_team_action(
                    sender,
                    "dispatch",
                    team_id=spec_team,
                    target_agent_id=th,
                    bus_dir=BUS_DIR,
                    auth_token=auth_token,
                )
                sender_auth = auth_res
                # B1.4 / M2-B6: Auto-backfill unique allowed_team / led_team when caller omits team_id so jobs are never unscoped.
                if not spec_team:
                    led_list = list(auth_res.get("led_teams") or [])
                    allowed_list = list(auth_res.get("allowed_teams") or [])
                    if allowed_list:
                        if fed_teams_by_id is None:
                            fed_teams_by_id = {
                                t["team_id"]: t for t in fed.list_teams(bus_dir=BUS_DIR) if isinstance(t, dict)
                            }
                        is_global_c = bool(auth_res.get("is_coordinator_peer") or auth_res.get("is_legacy_coordinator"))
                        scoped_candidates = (
                            allowed_list if is_global_c else [tid for tid in allowed_list if tid in set(led_list)]
                        )
                        matching_allowed = [
                            tid
                            for tid in scoped_candidates
                            if th in ((fed_teams_by_id.get(tid) or {}).get("members") or [])
                        ]
                        if len(matching_allowed) == 1:
                            spec_team = matching_allowed[0]
                        else:
                            raise PermissionError(
                                f"PRIVILEGE_ESCALATION_DENIED: explicit team_id required when capabilities.allowed_teams={sorted(allowed_list)} is set for {sender!r}"
                            )
                    elif led_list:
                        if fed_teams_by_id is None:
                            fed_teams_by_id = {
                                t["team_id"]: t for t in fed.list_teams(bus_dir=BUS_DIR) if isinstance(t, dict)
                            }
                        matching_led = [
                            tid
                            for tid in led_list
                            if th in ((fed_teams_by_id.get(tid) or {}).get("members") or [])
                        ]
                        if len(matching_led) == 1:
                            spec_team = matching_led[0]
                        elif len(led_list) == 1 and not (
                            auth_res.get("is_coordinator_peer") or auth_res.get("is_legacy_coordinator")
                        ):
                            spec_team = led_list[0]
            resolved_specs.append((spec, target, spec_team, spec_origin))

        # B2: Server-side monotonic trust_level clamping against registered federation agent record.
        if fed_active and isinstance(sender_auth, dict):
            reg_agent = sender_auth.get("agent")
            if isinstance(reg_agent, dict) and reg_agent.get("trust_level"):
                reg_trust = _normalize_trust_level(reg_agent.get("trust_level"), default="remote_untrusted")
                eff_parent_trust = _min_trust_level(eff_parent_trust, reg_trust)
                if reg_trust == "readonly_guest" or eff_parent_trust == "readonly_guest":
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: registered agent {sender!r} with trust_level='readonly_guest' cannot dispatch assignments"
                    )
                if TRUST_ORDER[eff_parent_trust] <= TRUST_ORDER["remote_untrusted"]:
                    eff_parent_untr = True
                    eff_parent_tainted = True

        # Check & record 10-minute sliding window AFTER spec validation so invalid specs don't burn quota
        _record_dispatch_window_unlocked(now, len(resolved_specs), eff_window_max)

        job_ids = [f"job-{uuid.uuid4().hex[:10]}" for _ in resolved_specs]
        explicit_local_admin_parent = (
            bool(trust_candidates)
            and eff_parent_trust == "local_admin"
            and (not eff_parent_untr)
            and (not eff_parent_tainted)
            and (not eff_parent_ro)
            and (not _is_external_agent_origin(env_origin))
            and (not _is_external_agent_origin(arg_p_origin))
            and (not _is_external_agent_origin(eff_origin))
        )
        for idx, ((spec, target, spec_team, child_origin), jid) in enumerate(zip(resolved_specs, job_ids)):
            prompt_str = str(spec.get("prompt") or "").strip()
            child_is_remote = _is_remote_origin(child_origin)
            child_is_external = _is_external_agent_origin(child_origin)
            child_ro = bool(eff_parent_ro) or bool(spec.get("readonly", False))
            raw_child_trust = spec.get("trust_level") or trust_level or eff_parent_trust
            child_trust = _min_trust_level(eff_parent_trust, raw_child_trust)
            if child_is_remote:
                child_trust = _min_trust_level(child_trust, "remote_untrusted")
            if child_ro:
                child_trust = "readonly_guest"
            if child_trust == "readonly_guest":
                child_ro = True
            clean_local_admin_dispatch = (
                explicit_local_admin_parent
                and child_origin == "local_bus"
                and (not child_is_external)
                and (not child_ro)
                and (not bool(spec.get("untrusted", False)))
                and (not bool(spec.get("tainted", False)))
                and child_trust in ("local_admin", "local_worker")
            )
            prompt_tainted = False if clean_local_admin_dispatch else _text_has_untrusted_taint(prompt_str)
            child_untr = (
                bool(eff_parent_untr)
                or bool(spec.get("untrusted", False))
                or bool(spec.get("tainted", False))
                or child_ro
                or child_is_remote
                or prompt_tainted
                or (TRUST_ORDER[child_trust] <= TRUST_ORDER["remote_untrusted"])
            )
            child_tainted = bool(eff_parent_tainted) or bool(spec.get("tainted", False)) or child_untr
            if child_untr and not child_ro:
                child_trust = _min_trust_level(child_trust, "remote_untrusted")

            spec_max_mode = str(spec.get("max_runtime_mode") or "").strip().lower()
            eff_max_mode = _min_runtime_mode(eff_parent_max_mode, spec_max_mode, default="")
            if child_ro:
                eff_max_mode = "safe"

            req_mode = str(spec.get("mode") or "").strip().lower()
            if eff_max_mode:
                final_mode = _min_runtime_mode(eff_max_mode, req_mode, default=eff_max_mode)
            else:
                final_mode = req_mode

            wt_enabled = bool(spec.get("worktree", False))
            if "worktree_strict" in spec and spec.get("worktree_strict") is not None:
                wt_strict = bool(spec.get("worktree_strict"))
            else:
                wt_strict = wt_enabled

            child_retryable = bool(spec.get("retryable", True))
            job_max_rt = float(spec.get("max_runtime_sec") or DEFAULT_JOB_MAX_RUNTIME_SEC)

            job = {
                "job_id": jid,
                "group_id": group_id,
                "batch_index": idx,
                "batch_size": len(job_ids),
                "batch_job_ids": list(job_ids),
                "wake_on_async": bool(wake_on_async),
                "batch_notified": False,
                "batch_notified_at": 0.0,
                "batch_acked": False,
                "batch_acked_at": 0.0,
                "batch_replay_count": 0,
                "label": str(spec.get("label") or "")[:120],
                "from_bot": sender,
                "target_bot": target["handle"],
                "prompt": prompt_str,
                "project": str(spec.get("project") or ""),
                "workdir": str(spec.get("workdir") or ""),
                "model": str(spec.get("model") or ""),
                "effort": str(spec.get("effort") or ""),
                "mode": final_mode,
                "thread_key": str(spec.get("thread_key") or ""),
                "resume_cid": str(spec.get("resume_cid") or ""),
                "worktree": wt_enabled,
                "worktree_strict": wt_strict,
                "worktree_info": {},
                "notify_group": bool(spec.get("notify_group", default_notify_group)),
                "origin_scope_key": origin_scope_key or "",
                "origin_chat_id": int(origin_chat_id or 0),
                "origin_thread_id": origin_thread_id,
                "origin_msg_id": int(origin_msg_id or 0),
                "chain": list(chain) + [target["handle"]],
                "depth": len(chain),
                "team_id": spec_team,
                "agent_origin": child_origin,
                "trust_level": child_trust,
                "tainted": bool(child_tainted),
                "untrusted": bool(child_untr),
                "readonly": bool(child_ro),
                "max_runtime_mode": eff_max_mode,
                "retryable": child_retryable,
                "retry_count": eff_retry_count,
                "parent_job_id": str(parent_job_id or ""),
                "batch_budget_usd": eff_budget_usd,
                "max_runtime_sec": job_max_rt,
                "status": "queued",
                "cancel_requested": False,
                "cancel_reason": "",
                "group_delivered": False,
                "created_at": now,
                "started_at": 0.0,
                "finished_at": 0.0,
                "worker_pid": 0,
                "worker_starttime": "",
                "worker_euid": -1,
                "worker_cid": "",
                "progress": "",
                "result_text": "",
                "error": "",
                "error_code": "",
                "artifacts": [],
                "usage": {},
            }
            if target.get("federated"):
                job["target_driver"] = str(target.get("driver") or "")
                job["target_transport"] = str(target.get("transport") or "")
                job["target_kind"] = str(target.get("kind") or "")
            _atomic_write_json(_job_path(jid), job)
            _drop_inbox_packet_unlocked(
                target["handle"],
                {
                    "type": "job",
                    "job_id": jid,
                    "from_bot": sender,
                    "team_id": spec_team,
                    "agent_origin": child_origin,
                    "trust_level": child_trust,
                    "tainted": bool(child_tainted),
                    "created_at": now,
                },
            )
            created_jobs.append(job)

        _prune_old_jobs_unlocked()

    return {"group_id": group_id, "jobs": created_jobs}


def get_job(
    job_id: str,
    *,
    requester_bot: str = "",
    auth_token: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    fp = _job_path(job_id)
    if not os.path.isfile(fp):
        return None
    data = _read_json(fp, None)
    if not isinstance(data, dict):
        return None
    if requester_bot:
        _reject_unsafe_actor_id(requester_bot, field="requester_bot")
        fed = _federation_mod()
        if fed is not None and fed.has_federation_state(BUS_DIR):
            fed.authorize_team_action(
                normalize_handle(requester_bot),
                "status",
                team_id=str(data.get("team_id") or ""),
                job=data,
                bus_dir=BUS_DIR,
                auth_token=auth_token,
            )
    return data


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


def claim_job(
    job_id: str,
    worker_handle: str,
    worker_pid: int,
    *,
    worker_starttime: Optional[str] = None,
    worker_euid: Optional[int] = None,
    proc_root: str = "/proc",
) -> Optional[Dict[str, Any]]:
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
            job["error_code"] = job.get("error_code") or "CANCELLED_BY_COORDINATOR"
            _atomic_write_json(fp, job)
            _maybe_notify_batch_done_unlocked(job)
            return None
        pid = int(worker_pid or os.getpid())
        eff_st = worker_starttime
        if eff_st is None:
            _state, eff_st = _read_proc_stat_info(pid, proc_root=proc_root)
        eff_euid = worker_euid
        if eff_euid is None:
            eff_euid = _read_proc_euid(pid, proc_root=proc_root)
            if eff_euid is None and pid == os.getpid():
                eff_euid = os.geteuid()
        job["status"] = "running"
        job["started_at"] = time.time()
        job["worker_pid"] = pid
        job["worker_starttime"] = str(eff_st or "")
        job["worker_euid"] = int(eff_euid) if eff_euid is not None else -1
        job.setdefault("max_runtime_sec", DEFAULT_JOB_MAX_RUNTIME_SEC)
        _atomic_write_json(fp, job)
        return dict(job)


def reap_zombie_jobs(
    now: Optional[float] = None,
    grace_sec: float = 15.0,
    proc_root: str = "/proc",
) -> List[str]:
    """Reap orphaned/dead/reused-PID/zombie/timed-out `running` jobs atomically under `_bus_lock()`.

    CRITICAL SAFETY INVARIANT:
    - Never sends `os.kill` signals (especially never touches a reused PID whose `starttime` or `euid` mismatches).
    - Marks reaped jobs `status="error"`, `error_code="WORKER_ZOMBIE_REAPED"`, and notifies `batch_done` once.
    """
    eff_now = time.time() if now is None else float(now)
    eff_grace = max(0.0, float(grace_sec or 0.0))
    reaped: List[str] = []

    with _bus_lock():
        try:
            files = sorted(fn for fn in os.listdir(JOBS_DIR) if fn.endswith(".json") and not fn.endswith(".tmp"))
        except OSError:
            return []

        for fn in files:
            fp = os.path.join(JOBS_DIR, fn)
            job = _read_json(fp, None)
            if not isinstance(job, dict) or job.get("status") != "running":
                continue
            started_at = float(job.get("started_at") or job.get("created_at") or 0.0)
            elapsed = eff_now - started_at
            if elapsed < eff_grace:
                continue

            pid = int(job.get("worker_pid") or 0)
            recorded_st = str(job.get("worker_starttime") or "").strip()
            raw_euid = job.get("worker_euid")
            recorded_euid = int(raw_euid) if isinstance(raw_euid, int) and not isinstance(raw_euid, bool) else -1
            max_rt = float(job.get("max_runtime_sec") or DEFAULT_JOB_MAX_RUNTIME_SEC)

            state, cur_st = _read_proc_stat_info(pid, proc_root=proc_root) if pid > 1 else (None, None)
            cur_euid = _read_proc_euid(pid, proc_root=proc_root) if pid > 1 else None

            reason = ""
            if pid <= 1 or cur_st is None:
                reason = "worker_pid_missing"
            elif state in ("Z", "X"):
                reason = f"worker_process_state_{state}"
            elif recorded_st and str(cur_st) != recorded_st:
                reason = "worker_pid_reused_starttime_mismatch"
            elif recorded_euid >= 0 and (cur_euid is None or int(cur_euid) != recorded_euid):
                reason = "worker_pid_euid_mismatch"
            elif max_rt > 0 and elapsed > max_rt:
                reason = f"worker_max_runtime_exceeded ({int(elapsed)}s > {int(max_rt)}s)"

            if not reason:
                continue

            job["status"] = "error"
            job["error_code"] = "WORKER_ZOMBIE_REAPED"
            job["error"] = f"WORKER_ZOMBIE_REAPED: {reason}"
            job["finished_at"] = eff_now
            _atomic_write_json(fp, job)
            _maybe_notify_batch_done_unlocked(job)
            reaped.append(str(job.get("job_id") or fn[:-5]))

    return reaped


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
    any_tainted = any(bool(j.get("tainted") or j.get("untrusted")) for j in batch_jobs)
    for j in batch_jobs:
        j["batch_notified"] = True
        j["batch_notified_at"] = now
        j["batch_acked"] = False
        j.setdefault("batch_replay_count", 0)
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
            "tainted": any_tainted,
            "team_id": settled_job.get("team_id") or "",
            "agent_origin": settled_job.get("agent_origin") or "local_bus",
            "trust_level": settled_job.get("trust_level") or "local_admin",
            "created_at": now,
        },
    )


def mark_batch_wakeup_acked(job_ids: Iterable[str]) -> int:
    """Atomically mark `batch_acked=True` and `batch_acked_at` for the given jobs under `_bus_lock()`."""
    clean_ids: List[str] = []
    seen: set[str] = set()
    for raw_id in job_ids or ():
        try:
            jid = validate_job_id(str(raw_id or "").strip())
        except ValueError:
            continue
        if jid not in seen:
            seen.add(jid)
            clean_ids.append(jid)
    if not clean_ids:
        return 0

    acked = 0
    now = time.time()
    with _bus_lock():
        for jid in clean_ids:
            fp = _job_path(jid)
            job = _read_json(fp, None)
            if not isinstance(job, dict):
                continue
            if job.get("batch_acked"):
                continue
            job["batch_acked"] = True
            job["batch_acked_at"] = now
            _atomic_write_json(fp, job)
            acked += 1
    return acked


def requeue_unacked_batch_done(
    for_bot: str,
    *,
    now: Optional[float] = None,
    min_age_sec: float = 90.0,
    max_age_sec: float = 1800.0,
    max_replays: int = 2,
    exclude_group_ids: Optional[Iterable[str]] = None,
) -> List[str]:
    """Re-deliver unacked `batch_done` notifications for `for_bot` after restart/crash loss.

    Scans terminal jobs owned by `for_bot` with `wake_on_async=True`, `batch_notified=True`,
    `batch_acked=False`, `batch_replay_count < max_replays`, and age within `[min_age_sec, max_age_sec]`.
    Deduplicates by `group_id`, skips any `group_id` listed in `exclude_group_ids` or already waiting
    as a `batch_done` packet inside `INBOX_DIR/<for_bot>/`, atomically increments `batch_replay_count`
    and refreshes `batch_notified_at`, and re-drops a `batch_done` packet into `for_bot`'s inbox.
    """
    target = normalize_handle(for_bot or "")
    if not target:
        return []
    eff_now = time.time() if now is None else float(now)
    eff_min = max(0.0, float(min_age_sec))
    eff_max = max(eff_min, float(max_age_sec))
    eff_max_replays = max(0, int(max_replays))
    if eff_max_replays <= 0:
        return []

    replayed_groups: List[str] = []
    with _bus_lock():
        excluded_groups: set[str] = {
            str(g).strip() for g in (exclude_group_ids or ()) if str(g).strip()
        }
        bot_inbox = os.path.join(INBOX_DIR, target)
        if os.path.isdir(bot_inbox):
            try:
                for pfn in os.listdir(bot_inbox):
                    if not (pfn.endswith(".json") and not pfn.endswith(".tmp")):
                        continue
                    pkt = _read_json(os.path.join(bot_inbox, pfn), None)
                    if isinstance(pkt, dict) and pkt.get("type") == "batch_done":
                        pgid = str(pkt.get("group_id") or "").strip()
                        if pgid:
                            excluded_groups.add(pgid)
            except OSError:
                pass

        try:
            files = sorted(fn for fn in os.listdir(JOBS_DIR) if fn.endswith(".json") and not fn.endswith(".tmp"))
        except OSError:
            return []

        groups: Dict[str, List[Dict[str, Any]]] = {}
        for fn in files:
            job = _read_json(os.path.join(JOBS_DIR, fn), None)
            if not isinstance(job, dict):
                continue
            if normalize_handle(str(job.get("from_bot") or "")) != target:
                continue
            if not job.get("wake_on_async") or not job.get("batch_notified"):
                continue
            if job.get("batch_acked"):
                continue
            if job.get("status") not in TERMINAL_STATUSES:
                continue
            gid = str(job.get("group_id") or job.get("job_id") or "").strip()
            if not gid or gid in excluded_groups:
                continue
            groups.setdefault(gid, []).append(job)

        for gid in sorted(groups.keys()):
            if gid in excluded_groups:
                continue
            seed = groups[gid][0]
            raw_jids = list(seed.get("batch_job_ids") or [j.get("job_id") for j in groups[gid] if j.get("job_id")])
            batch_jids: List[str] = []
            seen_j: set[str] = set()
            for rj in raw_jids:
                try:
                    cj = validate_job_id(str(rj or "").strip())
                except ValueError:
                    continue
                if cj not in seen_j:
                    seen_j.add(cj)
                    batch_jids.append(cj)
            if not batch_jids:
                continue

            batch_jobs: List[Dict[str, Any]] = []
            eligible = True
            for jid in batch_jids:
                bj = _read_json(_job_path(jid), None)
                if not isinstance(bj, dict):
                    eligible = False
                    break
                if bj.get("status") not in TERMINAL_STATUSES:
                    eligible = False
                    break
                if not bj.get("wake_on_async") or not bj.get("batch_notified") or bj.get("batch_acked"):
                    eligible = False
                    break
                batch_jobs.append(bj)
            if not eligible or not batch_jobs:
                continue

            rep = batch_jobs[0]
            eff_gid = str(rep.get("group_id") or gid).strip()
            if eff_gid in excluded_groups:
                continue

            replay_count = max(int(bj.get("batch_replay_count") or 0) for bj in batch_jobs)
            if replay_count >= eff_max_replays:
                continue
            notified_at = max(
                float(bj.get("batch_notified_at") or bj.get("finished_at") or 0.0) for bj in batch_jobs
            )
            if notified_at <= 0.0:
                continue
            age = eff_now - notified_at
            if age < eff_min or age > eff_max:
                continue

            next_replay = replay_count + 1
            any_tainted = any(bool(bj.get("tainted") or bj.get("untrusted")) for bj in batch_jobs)
            for bj in batch_jobs:
                bj["batch_replay_count"] = next_replay
                bj["batch_notified_at"] = eff_now
                _atomic_write_json(_job_path(bj["job_id"]), bj)

            _drop_inbox_packet_unlocked(
                target,
                {
                    "type": "batch_done",
                    "group_id": eff_gid,
                    "job_ids": batch_jids,
                    "origin_scope_key": rep.get("origin_scope_key") or "",
                    "origin_chat_id": int(rep.get("origin_chat_id") or 0),
                    "origin_thread_id": rep.get("origin_thread_id"),
                    "chain": list(rep.get("chain") or []),
                    "tainted": any_tainted,
                    "team_id": rep.get("team_id") or "",
                    "agent_origin": rep.get("agent_origin") or "local_bus",
                    "trust_level": rep.get("trust_level") or "local_admin",
                    "replayed": True,
                    "replay_count": next_replay,
                    "created_at": eff_now,
                },
            )
            excluded_groups.add(eff_gid)
            replayed_groups.append(eff_gid)

    return replayed_groups


def finish_job(
    job_id: str,
    *,
    status: str,
    result_text: str = "",
    error: str = "",
    error_code: str = "",
    tainted: Optional[bool] = None,
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
        clean_code = str(error_code or "").strip().upper()
        if not clean_code:
            if status == "done":
                clean_code = "OK"
            elif status == "cancelled":
                clean_code = "CANCELLED_LOCAL" if "local" in str(error or "").lower() else "CANCELLED_BY_COORDINATOR"
            else:
                clean_code = "AGENT_EXEC_ERROR"
        job["error_code"] = clean_code
        if tainted is True:
            job["tainted"] = True
            job["untrusted"] = True
        if worker_cid:
            job["worker_cid"] = worker_cid
        if artifacts is not None:
            job["artifacts"] = list(artifacts)
        if usage is not None:
            job["usage"] = dict(usage)
        if worktree_info is not None:
            job["worktree_info"] = dict(worktree_info)
        _atomic_write_json(fp, job)

        # C7: Cumulative batch cost circuit breaker — auto-cancel remaining queued siblings
        batch_ids = list(job.get("batch_job_ids") or [job["job_id"]])
        budget_limit = float(job.get("batch_budget_usd") or DEFAULT_BATCH_MAX_USD)
        if budget_limit > 0 and len(batch_ids) > 1:
            total_usd = 0.0
            siblings: List[Tuple[str, Dict[str, Any]]] = []
            for bid in batch_ids:
                bj = job if bid == job["job_id"] else _read_json(_job_path(bid), None)
                if isinstance(bj, dict):
                    try:
                        total_usd += float((bj.get("usage") or {}).get("usd") or 0.0)
                    except (TypeError, ValueError):
                        pass
                    if bid != job["job_id"]:
                        siblings.append((bid, bj))
            if total_usd > budget_limit:
                for bid, sib in siblings:
                    if sib.get("status") == "queued":
                        sib["status"] = "cancelled"
                        sib["cancel_requested"] = True
                        sib["cancel_reason"] = "BUDGET_EXCEEDED"
                        sib["error_code"] = "BUDGET_EXCEEDED"
                        sib["error"] = (
                            f"BUDGET_EXCEEDED: cumulative batch cost ${total_usd:.4f} exceeded ${budget_limit:.4f}"
                        )
                        sib["finished_at"] = now
                        _atomic_write_json(_job_path(bid), sib)

        _maybe_notify_batch_done_unlocked(job)
        return dict(job)


def cancel_job(
    job_id: str,
    requester_bot: str = "",
    reason: str = "cancelled",
    *,
    auth_token: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if requester_bot:
        _reject_unsafe_actor_id(requester_bot, field="requester_bot")
    req = normalize_handle(requester_bot or "")
    fp = _job_path(job_id)
    with _bus_lock():
        job = _read_json(fp, None)
        if not isinstance(job, dict):
            return None
        fed = _federation_mod()
        fed_active = bool(fed is not None and fed.has_federation_state(BUS_DIR))
        if req and fed_active and fed is not None:
            fed.authorize_team_action(
                req,
                "cancel",
                team_id=str(job.get("team_id") or ""),
                job=job,
                bus_dir=BUS_DIR,
                auth_token=auth_token,
            )
        elif req and req not in (job.get("from_bot"), job.get("target_bot")):
            raise PermissionError(f"Only @{job.get('from_bot')} may cancel {job_id}")
        if job.get("status") in TERMINAL_STATUSES:
            return dict(job)
        job["cancel_requested"] = True
        job["cancel_reason"] = reason
        if job.get("status") == "queued":
            job["status"] = "cancelled"
            job["finished_at"] = time.time()
            job["error"] = reason
            job["error_code"] = (
                "CANCELLED_LOCAL" if "local" in str(reason or "").lower() else "CANCELLED_BY_COORDINATOR"
            )
            _atomic_write_json(fp, job)
            _maybe_notify_batch_done_unlocked(job)
        else:
            _atomic_write_json(fp, job)
        return dict(job)


def dispatch_jobs_in_dir(
    bus_dir: str,
    from_bot: str,
    assignments: List[Dict[str, Any]],
    *,
    max_fanout: int = 6,
) -> Dict[str, Any]:
    """Atomically enqueue jobs into an explicit `bus_dir` under `bus.lock` (safe for multi-dir / Studio isolation)."""
    bdir = os.path.abspath(bus_dir)
    jobs_dir = os.path.join(bdir, "jobs")
    inbox_dir = os.path.join(bdir, "inbox")
    lock_file = os.path.join(bdir, "bus.lock")
    os.makedirs(bdir, mode=0o700, exist_ok=True)
    os.makedirs(jobs_dir, mode=0o700, exist_ok=True)
    os.makedirs(inbox_dir, mode=0o700, exist_ok=True)

    sender = normalize_handle(from_bot) or "studio"
    if not assignments or not isinstance(assignments, list):
        raise ValueError("At least one assignment is required")
    if len(assignments) > max_fanout:
        raise ValueError(f"Too many fan-out assignments ({len(assignments)} > {max_fanout})")

    now = time.time()
    group_id = f"batch-{uuid.uuid4().hex[:8]}"
    created_jobs: List[Dict[str, Any]] = []

    with open(lock_file, "a+", encoding="utf-8") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            job_ids = [f"job-{uuid.uuid4().hex[:10]}" for _ in assignments]
            wm_path = os.path.join(inbox_dir, ".last_pkt_ns")
            prev_ns = 0
            try:
                with open(wm_path, "r", encoding="utf-8") as wf:
                    raw_wm = wf.read().strip()
                if raw_wm.isdigit():
                    prev_ns = int(raw_wm)
            except OSError:
                prev_ns = 0

            for idx, (spec, jid) in enumerate(zip(assignments, job_ids)):
                th = normalize_handle(str(spec.get("bot") or ""))
                if not th:
                    raise ValueError(f"Assignment #{idx + 1} requires a valid target bot")
                job = {
                    "job_id": jid,
                    "group_id": group_id,
                    "batch_index": idx,
                    "batch_size": len(job_ids),
                    "batch_job_ids": list(job_ids),
                    "wake_on_async": False,
                    "batch_notified": False,
                    "batch_notified_at": 0.0,
                    "batch_acked": False,
                    "batch_acked_at": 0.0,
                    "batch_replay_count": 0,
                    "label": str(spec.get("label") or "")[:120],
                    "from_bot": sender,
                    "target_bot": th,
                    "prompt": str(spec.get("prompt") or "").strip(),
                    "project": str(spec.get("project") or ""),
                    "workdir": str(spec.get("workdir") or ""),
                    "model": str(spec.get("model") or ""),
                    "effort": str(spec.get("effort") or ""),
                    "mode": str(spec.get("mode") or ""),
                    "thread_key": "",
                    "resume_cid": "",
                    "worktree": False,
                    "worktree_info": {},
                    "notify_group": False,
                    "origin_scope_key": "",
                    "origin_chat_id": 0,
                    "origin_thread_id": None,
                    "origin_msg_id": 0,
                    "chain": [sender, th],
                    "depth": 1,
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
                safe_id = re.sub(r"[^a-zA-Z0-9_.-]+", "", jid)
                _atomic_write_json(os.path.join(jobs_dir, f"{safe_id}.json"), job)

                bot_inbox = os.path.join(inbox_dir, th)
                os.makedirs(bot_inbox, mode=0o700, exist_ok=True)
                now_ns = time.time_ns()
                mono_ns = now_ns if now_ns > prev_ns else (prev_ns + 1)
                prev_ns = mono_ns
                pkt_name = f"{mono_ns:020d}_{idx:06d}_{uuid.uuid4().hex[:8]}.json"
                _atomic_write_json(
                    os.path.join(bot_inbox, pkt_name),
                    {"type": "job", "job_id": jid, "from_bot": sender, "created_at": now},
                )
                created_jobs.append(job)

            if prev_ns > 0:
                tmp_wm = f"{wm_path}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp"
                with open(tmp_wm, "w", encoding="utf-8") as wf:
                    wf.write(str(prev_ns))
                os.chmod(tmp_wm, 0o600)
                os.replace(tmp_wm, wm_path)
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    return {"group_id": group_id, "jobs": created_jobs}


def _drop_inbox_packet_in_dir_unlocked(inbox_dir: str, target_handle: str, packet: Dict[str, Any]) -> str:
    """Drop an inbox packet into an explicit `inbox_dir/<target_handle>/` under the caller's bus lock."""
    global _PKT_SEQ
    norm = normalize_handle(target_handle)
    bot_inbox = os.path.join(inbox_dir, norm)
    os.makedirs(bot_inbox, mode=0o700, exist_ok=True)
    wm_path = os.path.join(inbox_dir, ".last_pkt_ns")
    inbox_key = os.path.realpath(inbox_dir)
    prev_ns = _LAST_PKT_NS_BY_DIR.get(inbox_key, 0)
    try:
        with open(wm_path, "r", encoding="utf-8") as wf:
            raw_wm = wf.read().strip()
        if raw_wm.isdigit() and int(raw_wm) > prev_ns:
            prev_ns = int(raw_wm)
    except OSError:
        pass
    now_ns = time.time_ns()
    mono_ns = now_ns if now_ns > prev_ns else (prev_ns + 1)
    os.makedirs(inbox_dir, mode=0o700, exist_ok=True)
    tmp_wm = f"{wm_path}.{os.getpid()}.{uuid.uuid4().hex[:6]}.tmp"
    with open(tmp_wm, "w", encoding="utf-8") as wf:
        wf.write(str(mono_ns))
    os.chmod(tmp_wm, 0o600)
    os.replace(tmp_wm, wm_path)
    _LAST_PKT_NS_BY_DIR[inbox_key] = mono_ns
    _PKT_SEQ = (_PKT_SEQ + 1) % 1_000_000
    pkt_name = f"{mono_ns:020d}_{_PKT_SEQ:06d}_{uuid.uuid4().hex[:8]}.json"
    pkt_path = os.path.join(bot_inbox, pkt_name)
    _atomic_write_json(pkt_path, packet)
    return pkt_path


def _maybe_notify_batch_done_in_dir_unlocked(
    bus_dir: str,
    settled_job: Dict[str, Any],
    *,
    now: Optional[float] = None,
) -> None:
    """Check if all sibling jobs in `bus_dir` are terminal and emit `batch_done` atomically under lock."""
    if not settled_job.get("wake_on_async") or settled_job.get("batch_notified"):
        return
    jobs_dir = os.path.join(bus_dir, "jobs")
    inbox_dir = os.path.join(bus_dir, "inbox")
    job_ids = list(settled_job.get("batch_job_ids") or [settled_job["job_id"]])
    batch_jobs: List[Dict[str, Any]] = []
    for jid in job_ids:
        clean_jid = validate_job_id(jid)
        j = (
            settled_job
            if clean_jid == settled_job.get("job_id")
            else _read_json(os.path.join(jobs_dir, f"{clean_jid}.json"), None)
        )
        if not isinstance(j, dict) or j.get("status") not in TERMINAL_STATUSES:
            return
        if j.get("batch_notified"):
            return
        batch_jobs.append(j)

    eff_now = time.time() if now is None else float(now)
    any_tainted = any(bool(j.get("tainted") or j.get("untrusted")) for j in batch_jobs)
    for j in batch_jobs:
        j["batch_notified"] = True
        j["batch_notified_at"] = eff_now
        j["batch_acked"] = False
        j.setdefault("batch_replay_count", 0)
        _atomic_write_json(os.path.join(jobs_dir, f"{validate_job_id(j['job_id'])}.json"), j)

    sender = normalize_handle(str(settled_job.get("from_bot") or ""))
    if not sender:
        return
    _drop_inbox_packet_in_dir_unlocked(
        inbox_dir,
        sender,
        {
            "type": "batch_done",
            "group_id": settled_job.get("group_id"),
            "job_ids": job_ids,
            "origin_scope_key": settled_job.get("origin_scope_key") or "",
            "origin_chat_id": int(settled_job.get("origin_chat_id") or 0),
            "origin_thread_id": settled_job.get("origin_thread_id"),
            "chain": list(settled_job.get("chain") or []),
            "tainted": any_tainted,
            "team_id": settled_job.get("team_id") or "",
            "agent_origin": settled_job.get("agent_origin") or "local_bus",
            "trust_level": settled_job.get("trust_level") or "local_admin",
            "created_at": eff_now,
        },
    )


def cancel_job_in_dir(
    bus_dir: str,
    job_id: str,
    *,
    reason: str = "cancelled_by_studio",
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Atomically cancel a job in an explicit `bus_dir`. Returns `(job_dict_or_none, already_terminal)`."""
    clean_id = validate_job_id(job_id)
    bdir = os.path.abspath(bus_dir)
    jobs_dir = os.path.join(bdir, "jobs")
    lock_file = os.path.join(bdir, "bus.lock")
    os.makedirs(bdir, mode=0o700, exist_ok=True)
    fp = os.path.join(jobs_dir, f"{clean_id}.json")
    if not os.path.isfile(fp):
        return None, False

    with open(lock_file, "a+", encoding="utf-8") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            job = _read_json(fp, None)
            if not isinstance(job, dict):
                return None, False
            st = str(job.get("status") or "").lower()
            if st in TERMINAL_STATUSES or st == "failed":
                return dict(job), True
            job["cancel_requested"] = True
            job["cancel_reason"] = reason
            if st == "queued":
                now = time.time()
                job["status"] = "cancelled"
                job["finished_at"] = now
                job["error"] = reason
                job["error_code"] = (
                    "CANCELLED_LOCAL" if "local" in str(reason or "").lower() else "CANCELLED_BY_COORDINATOR"
                )
                _atomic_write_json(fp, job)
                _maybe_notify_batch_done_in_dir_unlocked(bdir, job, now=now)
            else:
                _atomic_write_json(fp, job)
            return dict(job), False
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def retry_job(
    job_id: str,
    requester_bot: str,
    prompt_override: str = "",
    *,
    force_non_idempotent: bool = False,
    max_retries: Optional[int] = None,
    caller_team_id: Optional[str] = None,
    caller_agent_origin: Optional[str] = None,
    caller_trust_level: Optional[str] = None,
    caller_readonly: Optional[bool] = None,
    caller_untrusted: Optional[bool] = None,
    caller_tainted: Optional[bool] = None,
    caller_max_runtime_mode: Optional[str] = None,
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    if requester_bot:
        _reject_unsafe_actor_id(requester_bot, field="requester_bot")
    # P0-1: Read current session security context (caller args monotonically intersected with env)
    env_rbac_ro = os.environ.get("AGY_RBAC_ROLE", "").strip().lower() == "readonly"
    env_untr = (
        os.environ.get("AGY_UNTRUSTED_SESSION", "").strip() == "1"
        or os.environ.get("AGY_MEMORY_READONLY", "").strip() == "1"
    )
    env_trust = os.environ.get("AGY_TRUST_LEVEL", "").strip()
    env_team_id = validate_team_id(os.environ.get("AGY_BOT_TEAM_ID", "").strip())
    env_origin = os.environ.get("AGY_AGENT_ORIGIN", "").strip().lower()
    env_max_mode = os.environ.get("AGY_MAX_RUNTIME_MODE", "").strip().lower()

    arg_caller_team = validate_team_id(caller_team_id or "")
    if env_team_id and arg_caller_team and arg_caller_team != env_team_id:
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: caller team_id {arg_caller_team!r} does not match bound team_id {env_team_id!r}"
        )
    eff_caller_team = env_team_id or arg_caller_team

    arg_caller_trust = str(caller_trust_level or "").strip()
    eff_caller_ro = bool(caller_readonly) or env_rbac_ro
    for _raw_t in (arg_caller_trust, env_trust):
        if _raw_t and _normalize_trust_level(_raw_t) == "readonly_guest":
            eff_caller_ro = True
    if eff_caller_ro:
        raise PermissionError("PRIVILEGE_ESCALATION_DENIED: readonly session cannot retry jobs")

    prev = get_job(job_id)
    if not prev:
        raise ValueError(f"Job not found: {job_id}")

    prev_team_id = validate_team_id(prev.get("team_id") or "")
    if eff_caller_team and prev_team_id != eff_caller_team:
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: cross-team retry rejected (session team_id={eff_caller_team!r}, job team_id={prev_team_id!r})"
        )
    fed = _federation_mod()
    reg_caller_trust = ""
    if requester_bot and fed is not None and fed.has_federation_state(BUS_DIR):
        retry_auth = fed.authorize_team_action(
            normalize_handle(requester_bot),
            "retry",
            team_id=prev_team_id,
            job=prev,
            bus_dir=BUS_DIR,
            auth_token=auth_token,
        )
        reg_agent = retry_auth.get("agent") if isinstance(retry_auth, dict) else None
        if isinstance(reg_agent, dict) and reg_agent.get("trust_level"):
            reg_caller_trust = _normalize_trust_level(reg_agent.get("trust_level"), default="remote_untrusted")
            if reg_caller_trust == "readonly_guest":
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: registered agent {normalize_handle(requester_bot)!r} with trust_level='readonly_guest' cannot retry jobs"
                )
    eff_team_id = eff_caller_team or prev_team_id

    if prev.get("retryable") is False and not force_non_idempotent:
        raise ValueError(
            f"Job {job_id} is marked non-idempotent (retryable=False); refusing retry without force_non_idempotent=True"
        )
    next_retry_count = int(prev.get("retry_count") or 0) + 1
    eff_max_retries = DEFAULT_MAX_RETRIES if max_retries is None else max(0, int(max_retries))
    if next_retry_count > eff_max_retries:
        raise ValueError(
            f"RETRY_LIMIT_EXCEEDED: job {job_id} retry {next_retry_count} exceeds max_retries={eff_max_retries}"
        )

    prev_origin = str(prev.get("agent_origin") or "local_bus").strip().lower() or "local_bus"
    arg_caller_origin = str(caller_agent_origin or "").strip().lower()
    if _is_remote_origin(env_origin):
        eff_caller_origin = arg_caller_origin if _is_remote_origin(arg_caller_origin) else env_origin
    else:
        eff_caller_origin = arg_caller_origin or env_origin

    if _is_remote_origin(eff_caller_origin):
        eff_origin = eff_caller_origin
    elif _is_remote_origin(prev_origin):
        eff_origin = prev_origin
    else:
        eff_origin = prev_origin or eff_caller_origin or "local_bus"

    prev_ro = bool(prev.get("readonly", False))
    eff_ro = prev_ro or eff_caller_ro

    eff_caller_untr = bool(caller_untrusted) or env_untr or _is_remote_origin(eff_caller_origin)
    eff_caller_tainted = bool(caller_tainted) or eff_caller_untr
    prev_untr = (
        bool(prev.get("untrusted", False))
        or bool(prev.get("tainted", False))
        or prev_ro
        or _is_remote_origin(prev_origin)
    )
    prev_tainted = bool(prev.get("tainted", False)) or prev_untr

    eff_untr = prev_untr or eff_caller_untr or eff_ro or _is_remote_origin(eff_origin)
    eff_tainted = prev_tainted or eff_caller_tainted or eff_untr

    prev_trust = _normalize_trust_level(
        prev.get("trust_level"),
        default=("readonly_guest" if prev_ro else ("remote_untrusted" if prev_untr else "local_admin")),
    )
    eff_trust = prev_trust
    for _raw_t in (arg_caller_trust, env_trust, reg_caller_trust):
        if _raw_t:
            eff_trust = _min_trust_level(eff_trust, _raw_t)
    if eff_ro:
        eff_trust = "readonly_guest"
    elif eff_untr or eff_tainted or _is_remote_origin(eff_origin):
        eff_trust = _min_trust_level(eff_trust, "remote_untrusted")
    if eff_trust == "readonly_guest":
        eff_ro = True
        eff_untr = True
        eff_tainted = True
    if TRUST_ORDER[eff_trust] <= TRUST_ORDER["remote_untrusted"]:
        eff_untr = True
        eff_tainted = True

    prev_max_mode = str(prev.get("max_runtime_mode") or "").strip().lower()
    caller_eff_max_mode = _min_runtime_mode(caller_max_runtime_mode, env_max_mode, default="")
    eff_max_mode = _min_runtime_mode(prev_max_mode, caller_eff_max_mode, default="")
    if eff_ro:
        eff_max_mode = "safe"

    raw_prev_mode = str(prev.get("mode") or "").strip().lower()
    eff_mode = _min_runtime_mode(eff_max_mode, raw_prev_mode, default=eff_max_mode) if eff_max_mode else raw_prev_mode

    wt_enabled = bool(prev.get("worktree"))
    wt_strict = bool(prev.get("worktree_strict", wt_enabled))

    spec = {
        "bot": prev.get("target_bot"),
        "prompt": prompt_override.strip() or prev.get("prompt") or "",
        "label": prev.get("label") or f"retry:{job_id}",
        "project": prev.get("project") or "",
        "workdir": prev.get("workdir") or "",
        "model": prev.get("model") or "",
        "effort": prev.get("effort") or "",
        "mode": eff_mode,
        "thread_key": prev.get("thread_key") or "",
        "resume_cid": prev.get("worker_cid") or prev.get("resume_cid") or "",
        "worktree": wt_enabled,
        "worktree_strict": wt_strict,
        "notify_group": bool(prev.get("notify_group")),
        "team_id": eff_team_id,
        "agent_origin": eff_origin,
        "trust_level": eff_trust,
        "tainted": eff_tainted,
        "untrusted": eff_untr,
        "readonly": eff_ro,
        "max_runtime_mode": eff_max_mode,
        "retryable": bool(prev.get("retryable", True)),
        "max_runtime_sec": float(prev.get("max_runtime_sec") or DEFAULT_JOB_MAX_RUNTIME_SEC),
    }
    res = dispatch_assignments(
        requester_bot or prev.get("from_bot") or "",
        [spec],
        origin_scope_key=prev.get("origin_scope_key") or "",
        origin_chat_id=int(prev.get("origin_chat_id") or 0),
        origin_thread_id=prev.get("origin_thread_id"),
        origin_msg_id=int(prev.get("origin_msg_id") or 0) or None,
        default_notify_group=bool(prev.get("notify_group", False)),
        wake_on_async=bool(prev.get("wake_on_async", True)),
        team_id=eff_team_id,
        agent_origin=eff_origin,
        parent_trust_level=("remote_untrusted" if eff_ro else eff_trust),
        parent_agent_origin=eff_origin,
        parent_readonly=eff_caller_ro,
        parent_untrusted=eff_untr,
        parent_tainted=eff_tainted,
        parent_max_runtime_mode=eff_max_mode,
        batch_budget_usd=prev.get("batch_budget_usd"),
        retry_count=next_retry_count,
        max_retries=eff_max_retries,
        parent_job_id=job_id,
        auth_token=auth_token,
    )
    return res["jobs"][0]


def wait_for_jobs(
    job_ids: List[str],
    timeout_sec: float = 600.0,
    cancel_check: Optional[Any] = None,
) -> Tuple[List[Dict[str, Any]], bool]:
    """Wait until all `job_ids` settle or `timeout_sec` elapses.

    Returns `(jobs_list, all_settled)`. If `cancel_check()` returns True, returns early
    after requesting cancellation on unfinished jobs. Periodically reaps zombie jobs every 5s.
    """
    deadline = time.time() + max(1.0, float(timeout_sec))
    last_reap = 0.0
    while True:
        now = time.time()
        if (now - last_reap) >= 5.0:
            last_reap = now
            try:
                reap_zombie_jobs(now=now)
            except Exception:
                pass
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
        if now >= deadline:
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


def notify_bot_model_sync(
    target_bot: str,
    *,
    model_mode: str,
    model: str = "",
    from_bot: str = "",
    chat_id: int = 0,
    thread_id: Optional[int] = None,
    model_rev: Optional[int] = None,
    model_updated_at: Optional[int] = None,
) -> str:
    """Enqueue a `sync_group_model` packet so `target_bot` immediately syncs its group scope model."""
    norm_target = normalize_handle(target_bot)
    if not norm_target:
        raise ValueError("Target bot handle is required")
    norm_mode = str(model_mode or MODEL_MODE_DEFAULT).strip().lower()
    if norm_mode not in VALID_MODEL_MODES:
        raise ValueError(f"Invalid model_mode: {model_mode}")
    clean_model = str(model or "").strip() if norm_mode == MODEL_MODE_CUSTOM else ""
    if clean_model == "__follow_dm__":
        clean_model = ""
    with _bus_lock():
        entry: Dict[str, Any] = {}
        if model_rev is None or model_updated_at is None:
            cfg = _load_team_config_unlocked()
            entry = dict((cfg.get("bots") or {}).get(norm_target) or {})
        eff_rev = int(model_rev) if model_rev is not None else int(entry.get("model_rev") or 0)
        eff_upd = int(model_updated_at) if model_updated_at is not None else int(entry.get("model_updated_at") or 0)
        return _drop_inbox_packet_unlocked(
            norm_target,
            {
                "type": "sync_group_model",
                "target_bot": norm_target,
                "from_bot": normalize_handle(from_bot) if from_bot else "",
                "model_mode": norm_mode,
                "model": clean_model,
                "model_rev": eff_rev,
                "model_updated_at": eff_upd,
                "chat_id": int(chat_id or 0),
                "thread_id": _norm_tid(thread_id),
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


_GH_PEM_DASH = "-" * 5
_GH_PEM_TYPE = r"(?:[A-Z0-9-]{1,24}[ \t]+){0,4}"
_GH_REDACT_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(
        rf"{_GH_PEM_DASH}BEGIN[ \t]+{_GH_PEM_TYPE}PRIVATE[ \t]+KEY{_GH_PEM_DASH}"
        rf"[\s\S]*?"
        rf"{_GH_PEM_DASH}END[ \t]+{_GH_PEM_TYPE}PRIVATE[ \t]+KEY{_GH_PEM_DASH}"
    ),
    re.compile(rf"{_GH_PEM_DASH}(?:BEGIN|END)[ \t]+{_GH_PEM_TYPE}PRIVATE[ \t]+KEY{_GH_PEM_DASH}[^\r\n]*"),
    re.compile(r"(?im)^(?:set-)?cookie\s*:\s*[^\r\n]+"),
    re.compile(r"(?i)\bagy_studio_session\s*=\s*[^\s;,\"'`)\]}]+"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"\b\d{8,11}:[A-Za-z0-9_-]{24,45}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{16,}\b"),
    re.compile(r"\bsk-(?:proj-|ant-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:cfut|cfsd|cfat|ibk|ibssh|alt)_[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bhvs\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}\b"),
    re.compile(r"\b(?:lv[12]|kv/data|secret/data)/[A-Za-z0-9_./*-]+\b"),
    re.compile(r"(?i)\b(?:bearer|basic)\s+[^\s,;\"'`)\]}]+"),
    re.compile(
        r"""(?i)(?<![A-Za-z0-9_.-])(?:"|')?[A-Za-z0-9_.-]{0,40}"""
        r"""(?:token|apikey|api_key|key|secret|password|passwd|pwd|cookie|session|authorization|credential)"""
        r"""(?:"|')?\s*[:=]\s*(?:"(?:[^"\\]|\\.)+"|'(?:[^'\\]|\\.)+')"""
    ),
    re.compile(
        r"""(?i)(?<![A-Za-z0-9_.-])(?:"|')?\b[A-Za-z0-9_.-]{0,40}"""
        r"""(?:token|apikey|api_key|key|secret|password|passwd|pwd|cookie|session|authorization|credential)\b"""
        r"""(?:"|')?\s*[:=]\s*[^\s,;\"'`&)\]}]+"""
    ),
    re.compile(
        r"(?:(?<=^)|(?<=[\s(\[\{\"'`=:;,+\-]))"
        r"(?:(?i:file):///(?:home|Users|root|etc|var|tmp|opt|srv|proc|run|mnt|media|data|private|secrets)/[^\s,'\"`<>)\]}]+"
        r"|/(?:home|Users|root|etc|var|tmp|opt|srv|proc|run|mnt|media|data|private|secrets)/[^\s,'\"`<>)\]}]+"
        r"|~/[^\s,'\"`<>)\]}]+"
        r"|[A-Za-z]:[\\/][^\s,'\"`<>)\]}]+"
        r"|[^\s(\[\{\"'`=:;,<>)\]}+\-]+\.sock\b)"
    ),
)


def _sanitize_group_full_text(
    raw: Any,
    *,
    max_bytes: int = GROUP_HISTORY_FULL_TEXT_MAX_BYTES,
) -> Tuple[str, bool]:
    """Preserve Markdown/newlines while redacting secrets/host-paths and bounding UTF-8 bytes."""
    text = str(raw if raw is not None else "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return "", False
    for pat in _GH_REDACT_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    raw_bytes = text.encode("utf-8")
    if len(raw_bytes) <= max_bytes:
        return text, False
    return raw_bytes[:max_bytes].decode("utf-8", errors="ignore"), True


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
    source: str = "tg",
) -> Optional[Dict[str, Any]]:
    """Append a deduplicated group message to the per-chat ring ledger (`chat_id < 0` only)."""
    cid = int(chat_id or 0)
    if cid >= 0:
        return None
    excerpt = re.sub(r"\s+", " ", (text or "")).strip()[:500]
    if not excerpt:
        return None
    full_text, full_truncated = _sanitize_group_full_text(
        text,
        max_bytes=GROUP_HISTORY_FULL_TEXT_MAX_BYTES,
    )
    src_norm = "web" if str(source or "").strip().lower() == "web" else "tg"
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
            "full_text": full_text,
            "truncated": bool(full_truncated),
            "source": src_norm,
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
    raw_excerpt = (text_excerpt or "").strip()
    full_len = len(raw_excerpt)
    truncated = full_len > SCHEDULED_HANDOFF_EXCERPT_LIMIT
    pkt = {
        "type": "scheduled_handoff",
        "from_bot": sender,
        "to_bot": to_handle,
        "chat_id": cid,
        "thread_id": norm_tid,
        "msg_id": int(msg_id or 0),
        "task_id": str(task_id or ""),
        "task_name": str(task_name or "")[:120],
        "text_excerpt": raw_excerpt[:SCHEDULED_HANDOFF_EXCERPT_LIMIT],
        "full_len": full_len,
        "truncated": truncated,
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

    # C5: Fail-closed symlink & containment checks before creating or writing anything
    if os.path.islink(wt_root) or os.path.islink(wt_path):
        return {
            "enabled": True,
            "active": False,
            "pruned": False,
            "repo_root": repo_root,
            "base_commit": base_commit,
            "branch": branch,
            "reason": "unsafe_worktree_path",
        }
    if os.path.exists(wt_root):
        wt_root_real_pre = os.path.realpath(wt_root)
        if not wt_root_real_pre.startswith(repo_root + os.sep):
            return {
                "enabled": True,
                "active": False,
                "pruned": False,
                "repo_root": repo_root,
                "base_commit": base_commit,
                "branch": branch,
                "reason": "unsafe_worktree_path",
            }

    created_wt_root = False

    def _cleanup_empty_wt_root() -> None:
        if created_wt_root and os.path.isdir(wt_root) and not os.path.islink(wt_root):
            try:
                os.rmdir(wt_root)
            except OSError:
                pass

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
        if not os.path.exists(wt_root):
            os.makedirs(wt_root, exist_ok=True)
            created_wt_root = True
    except OSError as exc:
        _cleanup_empty_wt_root()
        return {
            "enabled": True,
            "active": False,
            "pruned": False,
            "repo_root": repo_root,
            "base_commit": base_commit,
            "reason": "prepare_dir_failed",
            "detail": repr(exc)[:300],
        }

    wt_root_real = os.path.realpath(wt_root)
    wt_path_real = os.path.realpath(wt_path)
    if (
        os.path.islink(wt_root)
        or os.path.islink(wt_path)
        or not wt_root_real.startswith(repo_root + os.sep)
        or not wt_path_real.startswith(wt_root_real + os.sep)
        or wt_path_real == wt_root_real
    ):
        _cleanup_empty_wt_root()
        return {
            "enabled": True,
            "active": False,
            "pruned": False,
            "repo_root": repo_root,
            "base_commit": base_commit,
            "branch": branch,
            "reason": "unsafe_worktree_path",
        }

    if os.path.exists(wt_path):
        _cleanup_empty_wt_root()
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
            _cleanup_empty_wt_root()
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
        _cleanup_empty_wt_root()
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


def cleanup_job_worktree(
    job_id: str,
    force: bool = False,
    *,
    requester_bot: str = "",
    auth_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Explicitly clean up a job's preserved worktree and branch after review/merge."""
    if requester_bot:
        _reject_unsafe_actor_id(requester_bot, field="requester_bot")
    job = get_job(job_id)
    if not job:
        return {"ok": False, "job_id": job_id, "error": f"Job not found: {job_id}"}
    if requester_bot:
        fed = _federation_mod()
        if fed is not None and fed.has_federation_state(BUS_DIR):
            fed.authorize_team_action(
                normalize_handle(requester_bot),
                "cleanup_worktree",
                team_id=str(job.get("team_id") or ""),
                job=job,
                bus_dir=BUS_DIR,
                auth_token=auth_token,
            )

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


# ---------------------------------------------------------------------------
# Studio Per-Session Isolated Git Worktree Helpers (Pillar 1)
# ---------------------------------------------------------------------------

STUDIO_WORKTREE_BRANCH_PREFIX = "agy-studio/"
STUDIO_WORKTREE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$")
_STUDIO_WORKTREES_FILENAME = "studio_worktrees.json"


def is_valid_studio_worktree_id(raw: Any) -> bool:
    """Strictly validate a Studio worktree slug (`^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$`)."""
    if not isinstance(raw, str):
        return False
    if ".." in raw or "/" in raw or "\\" in raw or "\x00" in raw:
        return False
    return bool(STUDIO_WORKTREE_ID_RE.fullmatch(raw))


def sanitize_studio_worktree_meta(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return strictly allowlisted worktree metadata with ZERO host filesystem paths."""
    if not isinstance(raw, dict):
        return {"active": False}
    out: Dict[str, Any] = {"active": bool(raw.get("active", False))}
    wt_id = str(raw.get("worktree_id") or "").strip()
    if wt_id and is_valid_studio_worktree_id(wt_id):
        out["worktree_id"] = wt_id
    branch = str(raw.get("branch") or "").strip()
    if branch and not branch.startswith("/") and ".." not in branch:
        out["branch"] = branch[:128]
    project_id = str(raw.get("project_id") or "").strip()
    if project_id and "/" not in project_id and "\\" not in project_id and ".." not in project_id:
        out["project_id"] = project_id[:64]
    cid = str(raw.get("cid") or "").strip()
    if cid:
        out["cid"] = cid[:64]
    bot = str(raw.get("bot") or "").strip()
    if bot:
        out["bot"] = bot[:64]
    reason = str(raw.get("reason") or "").strip()
    if reason and not out["active"]:
        out["reason"] = re.sub(r"[^a-zA-Z0-9_-]+", "_", reason)[:64]
    if raw.get("created_at") is not None:
        try:
            out["created_at"] = int(raw["created_at"])
        except (TypeError, ValueError):
            pass
    if raw.get("dirty_count") is not None:
        try:
            out["dirty_count"] = max(0, int(raw["dirty_count"]))
        except (TypeError, ValueError):
            pass
    if raw.get("commits_ahead") is not None:
        try:
            out["commits_ahead"] = max(0, int(raw["commits_ahead"]))
        except (TypeError, ValueError):
            pass
    if "busy" in raw:
        out["busy"] = bool(raw.get("busy"))
    return out


def resolve_studio_worktree_dir(repo_root: str, wt_id: str) -> Tuple[bool, Optional[str], int, str]:
    """Validate and resolve `<repo_root>/.worktrees/<wt_id>` rejecting symlinks and path escape.

    Returns `(ok, resolved_path, http_status, error_message)`.
    """
    if not is_valid_studio_worktree_id(wt_id):
        return False, None, 400, "非法的 worktree_id 格式"
    if not repo_root or not os.path.isdir(repo_root):
        return False, None, 404, "项目工作区目录不可访问"
    repo_real = os.path.realpath(repo_root)
    wt_root = os.path.join(repo_real, WORKTREE_DIR_NAME)
    if os.path.islink(wt_root):
        return False, None, 403, "禁止访问符号链接 worktree 目录"
    if not os.path.exists(wt_root):
        return False, None, 404, "未找到对应的 worktree"
    if not os.path.isdir(wt_root):
        return False, None, 404, "未找到对应的 worktree"
    wt_root_real = os.path.realpath(wt_root)
    if not wt_root_real.startswith(repo_real + os.sep):
        return False, None, 403, "worktree 目录越界，已拒绝访问"

    wt_dir = os.path.join(wt_root_real, wt_id)
    if os.path.islink(wt_dir):
        return False, None, 403, "禁止访问符号链接 worktree 目录"
    if not os.path.exists(wt_dir):
        return False, None, 404, "未找到对应的 worktree"
    if not os.path.isdir(wt_dir):
        return False, None, 404, "未找到对应的 worktree"
    wt_real = os.path.realpath(wt_dir)
    if not wt_real.startswith(wt_root_real + os.sep) or wt_real == wt_root_real:
        return False, None, 403, "worktree 路径越界，已拒绝访问"
    return True, wt_real, 200, ""


def prepare_studio_worktree(
    workdir: str,
    wt_id: Optional[str] = None,
    *,
    project_id: str = "",
) -> Dict[str, Any]:
    """Create an isolated Studio session Git worktree `<repo>/.worktrees/<wt_id>` on `agy-studio/<wt_id>`.

    Safely degrades (`active=False`, zero `.worktrees/` residue, zero host path leakage in sanitized output)
    on non-Git directories or unborn/invalid HEAD. Writes `.worktrees/` ONLY to `<git-common-dir>/info/exclude`
    and NEVER modifies `.gitignore`.
    """
    raw_wdir = os.path.realpath(os.path.expanduser(workdir)) if workdir else ""
    if not raw_wdir or not os.path.isdir(raw_wdir):
        return {"enabled": True, "active": False, "reason": "workdir_missing"}

    ok_root, out_root, _err_root = _run_git(["rev-parse", "--show-toplevel"], cwd=raw_wdir)
    if not ok_root or not out_root.strip():
        return {"enabled": True, "active": False, "reason": "not_git_repo"}
    repo_root = os.path.realpath(out_root.strip())

    ok_head, out_head, _err_head = _run_git(["rev-parse", "--verify", "HEAD"], cwd=repo_root)
    if not ok_head or not out_head.strip():
        return {"enabled": True, "active": False, "reason": "unborn_or_invalid_head"}
    base_commit = out_head.strip()

    chosen_id = str(wt_id or "").strip() or f"wt-{uuid.uuid4().hex[:12]}"
    if not is_valid_studio_worktree_id(chosen_id):
        return {"enabled": True, "active": False, "reason": "invalid_worktree_id"}

    branch = f"{STUDIO_WORKTREE_BRANCH_PREFIX}{chosen_id}"
    wt_root = os.path.join(repo_root, WORKTREE_DIR_NAME)
    if os.path.islink(wt_root):
        return {"enabled": True, "active": False, "reason": "unsafe_worktree_root"}
    wt_path = os.path.join(wt_root, chosen_id)
    if os.path.islink(wt_path) or os.path.exists(wt_path):
        return {"enabled": True, "active": False, "reason": "worktree_path_exists"}

    if not _ensure_git_info_exclude(repo_root):
        return {"enabled": True, "active": False, "reason": "git_exclude_failed"}

    created_wt_root = False
    try:
        if not os.path.exists(wt_root):
            os.makedirs(wt_root, exist_ok=True)
            created_wt_root = True
    except OSError:
        return {"enabled": True, "active": False, "reason": "prepare_dir_failed"}

    has_branch, _, _ = _run_git(["show-ref", "--verify", "--quiet", f"refs/heads/{branch}"], cwd=repo_root)
    if has_branch:
        del_ok, _, _ = _run_git(["branch", "-d", branch], cwd=repo_root)
        if not del_ok:
            if created_wt_root:
                try:
                    os.rmdir(wt_root)
                except OSError:
                    pass
            return {"enabled": True, "active": False, "reason": "branch_already_exists"}

    ok_add, _, _err_add = _run_git(
        ["worktree", "add", "-b", branch, wt_path, base_commit],
        cwd=repo_root,
        timeout=60.0,
    )
    if not ok_add:
        if created_wt_root:
            try:
                os.rmdir(wt_root)
            except OSError:
                pass
        return {"enabled": True, "active": False, "reason": "worktree_add_failed"}

    return {
        "enabled": True,
        "active": True,
        "worktree_id": chosen_id,
        "project_id": project_id,
        "path": os.path.realpath(wt_path),
        "branch": branch,
        "repo_root": repo_root,
        "base_commit": base_commit,
        "created_at": int(time.time()),
    }


def inspect_studio_worktree(
    repo_root: str,
    wt_id: str,
    *,
    base_commit: str = "",
) -> Tuple[int, Dict[str, Any]]:
    """Inspect a Studio worktree's branch, dirty file count, and commits ahead (zero host paths)."""
    ok_res, wt_real, sc, err = resolve_studio_worktree_dir(repo_root, wt_id)
    if not ok_res or not wt_real:
        return sc, {"ok": False, "error": err}

    ok_br, out_br, _ = _run_git(["symbolic-ref", "--quiet", "--short", "HEAD"], cwd=wt_real)
    branch = out_br.strip() if ok_br and out_br.strip() else ""
    if not branch:
        ok_abr, out_abr, _ = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=wt_real)
        branch = out_abr.strip() if ok_abr and out_abr.strip() else ""

    ok_stat, out_stat, _ = _run_git(["status", "--porcelain=v1", "-uall"], cwd=wt_real)
    dirty_count = len([ln for ln in out_stat.splitlines() if ln.strip()]) if ok_stat else 0

    ref_base = base_commit.strip()
    if not ref_base:
        ok_mh, out_mh, _ = _run_git(["rev-parse", "--verify", "HEAD"], cwd=os.path.realpath(repo_root))
        if ok_mh and out_mh.strip():
            ref_base = out_mh.strip()

    ok_rev = False
    commits_ahead = 0
    if ref_base:
        ok_rev, out_rev, _ = _run_git(["rev-list", "--count", f"{ref_base}..HEAD"], cwd=wt_real)
        if ok_rev:
            try:
                commits_ahead = max(0, int(out_rev.strip()))
            except ValueError:
                ok_rev = False

    return 200, {
        "ok": True,
        "worktree_id": wt_id,
        "branch": branch,
        "dirty_count": dirty_count,
        "commits_ahead": commits_ahead,
        "ok_stat": ok_stat,
        "ok_rev": ok_rev,
    }


def cleanup_studio_worktree(
    repo_root: str,
    wt_id: str,
    *,
    force: bool = False,
    branch: str = "",
    base_commit: str = "",
) -> Tuple[int, Dict[str, Any]]:
    """Safely remove a Studio worktree and its `agy-studio/<wt_id>` branch.

    Refuses (`409`) dirty or unmerged worktrees unless `force=True`.
    Never exposes host absolute paths in responses.
    """
    ok_res, wt_real, sc, err = resolve_studio_worktree_dir(repo_root, wt_id)
    if not ok_res or not wt_real:
        return sc, {"ok": False, "code": "invalid_worktree" if sc == 400 else ("unsafe_path" if sc == 403 else "not_found"), "error": err}

    repo_real = os.path.realpath(repo_root)
    sc_insp, insp = inspect_studio_worktree(repo_real, wt_id, base_commit=base_commit)
    if sc_insp != 200:
        return sc_insp, insp

    actual_branch = str(insp.get("branch") or branch or f"{STUDIO_WORKTREE_BRANCH_PREFIX}{wt_id}").strip()
    dirty_count = int(insp.get("dirty_count") or 0)
    commits_ahead = int(insp.get("commits_ahead") or 0)

    if not force:
        if not insp.get("ok_stat"):
            return 409, {
                "ok": False,
                "code": "worktree_inspection_failed",
                "dirty_count": dirty_count,
                "commits_ahead": commits_ahead,
                "error": "无法检查 worktree 状态，请确认后使用 force=true 强制清理",
            }
        if dirty_count > 0:
            return 409, {
                "ok": False,
                "code": "worktree_dirty",
                "dirty_count": dirty_count,
                "commits_ahead": commits_ahead,
                "error": f"worktree 存在 {dirty_count} 个未提交变更，请先提交/丢弃或传 force=true 强制清理",
            }
        if not insp.get("ok_rev"):
            return 409, {
                "ok": False,
                "code": "worktree_inspection_failed",
                "dirty_count": dirty_count,
                "commits_ahead": commits_ahead,
                "error": "无法检查 worktree 提交历史，请确认后使用 force=true 强制清理",
            }
        if commits_ahead > 0:
            merged = False
            if actual_branch:
                merged, _, _ = _run_git(["merge-base", "--is-ancestor", actual_branch, "HEAD"], cwd=repo_real)
            if not merged:
                return 409, {
                    "ok": False,
                    "code": "worktree_unmerged",
                    "dirty_count": dirty_count,
                    "commits_ahead": commits_ahead,
                    "branch": actual_branch,
                    "error": f"worktree 分支 {actual_branch} 存在 {commits_ahead} 个未合并提交，请先合并或传 force=true 强制清理",
                }

    rm_args = ["worktree", "remove", "--force", wt_real] if force else ["worktree", "remove", wt_real]
    ok_rm, _, _err_rm = _run_git(rm_args, cwd=repo_real, timeout=30.0)
    if not ok_rm:
        return 500, {
            "ok": False,
            "code": "worktree_remove_failed",
            "error": "删除 Git worktree 失败",
        }

    _run_git(["worktree", "prune"], cwd=repo_real, timeout=15.0)

    branch_deleted = False
    target_branch = f"{STUDIO_WORKTREE_BRANCH_PREFIX}{wt_id}"
    if actual_branch.startswith(STUDIO_WORKTREE_BRANCH_PREFIX):
        target_branch = actual_branch
    has_br, _, _ = _run_git(["show-ref", "--verify", "--quiet", f"refs/heads/{target_branch}"], cwd=repo_real)
    if has_br:
        del_flag = "-D" if force else "-d"
        ok_br, _, _ = _run_git(["branch", del_flag, target_branch], cwd=repo_real)
        branch_deleted = bool(ok_br)

    wt_root = os.path.join(repo_real, WORKTREE_DIR_NAME)
    if os.path.isdir(wt_root) and not os.path.islink(wt_root):
        try:
            os.rmdir(wt_root)
        except OSError:
            pass

    return 200, {
        "ok": True,
        "worktree_id": wt_id,
        "branch": target_branch,
        "branch_deleted": branch_deleted,
        "cleaned": True,
    }


def studio_worktrees_registry_path(bus_dir: Optional[str] = None) -> str:
    base = str(bus_dir or BUS_DIR)
    return os.path.join(base, _STUDIO_WORKTREES_FILENAME)


def _read_studio_worktrees_unlocked(reg_path: str) -> Dict[str, Dict[str, Any]]:
    if not os.path.isfile(reg_path) or os.path.islink(reg_path):
        return {}
    try:
        with open(reg_path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except Exception:
        return {}
    items = doc.get("worktrees") if isinstance(doc, dict) else None
    if not isinstance(items, dict):
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for wt_id, meta in items.items():
        if is_valid_studio_worktree_id(wt_id) and isinstance(meta, dict):
            clean = sanitize_studio_worktree_meta(meta)
            clean["worktree_id"] = wt_id
            if meta.get("base_commit") and re.fullmatch(r"[0-9a-f]{7,40}", str(meta.get("base_commit"))):
                clean["base_commit"] = str(meta["base_commit"])
            if meta.get("scope_key"):
                clean["scope_key"] = str(meta["scope_key"])[:128]
            out[wt_id] = clean
    return out


def _write_studio_worktrees_unlocked(reg_path: str, items: Dict[str, Dict[str, Any]]) -> None:
    payload = {"version": 1, "updated_at": int(time.time()), "worktrees": items}
    raw = (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    tmp = f"{reg_path}.tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, reg_path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_studio_worktrees(bus_dir: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Read sanitized Studio worktree registry (`BUS_DIR/studio_worktrees.json`)."""
    reg_path = studio_worktrees_registry_path(bus_dir)
    return _read_studio_worktrees_unlocked(reg_path)


def _mutate_studio_worktrees_atomic(
    reg_path: str,
    mutator: Callable[[Dict[str, Dict[str, Any]]], bool],
) -> None:
    """Atomically read-modify-write `studio_worktrees.json` inside a single `fcntl.flock(LOCK_EX)`."""
    parent = os.path.dirname(reg_path)
    os.makedirs(parent, exist_ok=True)
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    lock_path = reg_path + ".lock"
    lfd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lfd, fcntl.LOCK_EX)
        try:
            current = _read_studio_worktrees_unlocked(reg_path)
            if mutator(current):
                _write_studio_worktrees_unlocked(reg_path, current)
        finally:
            fcntl.flock(lfd, fcntl.LOCK_UN)
    finally:
        os.close(lfd)


def _write_studio_worktrees_atomic(reg_path: str, items: Dict[str, Dict[str, Any]]) -> None:
    def _replace_all(current: Dict[str, Dict[str, Any]]) -> bool:
        current.clear()
        current.update(items)
        return True

    _mutate_studio_worktrees_atomic(reg_path, _replace_all)


def upsert_studio_worktree_meta(
    wt_id: str,
    meta: Dict[str, Any],
    *,
    bus_dir: Optional[str] = None,
) -> None:
    """Atomically upsert sanitized metadata for `wt_id` into `BUS_DIR/studio_worktrees.json`."""
    if not is_valid_studio_worktree_id(wt_id):
        return
    reg_path = studio_worktrees_registry_path(bus_dir)
    clean = sanitize_studio_worktree_meta(meta)
    clean["worktree_id"] = wt_id
    if meta.get("base_commit") and re.fullmatch(r"[0-9a-f]{7,40}", str(meta.get("base_commit"))):
        clean["base_commit"] = str(meta["base_commit"])
    if meta.get("scope_key"):
        clean["scope_key"] = str(meta["scope_key"])[:128]

    def _mutator(current: Dict[str, Dict[str, Any]]) -> bool:
        current[wt_id] = clean
        return True

    _mutate_studio_worktrees_atomic(reg_path, _mutator)


def remove_studio_worktree_meta(wt_id: str, *, bus_dir: Optional[str] = None) -> None:
    """Atomically remove `wt_id` from `BUS_DIR/studio_worktrees.json`."""
    if not is_valid_studio_worktree_id(wt_id):
        return
    reg_path = studio_worktrees_registry_path(bus_dir)
    if not os.path.isfile(reg_path):
        return

    def _mutator(current: Dict[str, Dict[str, Any]]) -> bool:
        if wt_id in current:
            current.pop(wt_id, None)
            return True
        return False

    _mutate_studio_worktrees_atomic(reg_path, _mutator)


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
    if job.get("error_code"):
        out["error_code"] = str(job["error_code"])
    if job.get("team_id"):
        out["team_id"] = str(job["team_id"])
    if job.get("agent_origin"):
        out["agent_origin"] = str(job["agent_origin"])
    if job.get("trust_level"):
        out["trust_level"] = str(job["trust_level"])
    if job.get("tainted"):
        out["tainted"] = True
    if job.get("untrusted"):
        out["untrusted"] = True
    if job.get("readonly"):
        out["readonly"] = True
    if job.get("max_runtime_mode"):
        out["max_runtime_mode"] = str(job["max_runtime_mode"])
    if "retryable" in job:
        out["retryable"] = bool(job.get("retryable", True))
    if job.get("batch_budget_usd") is not None:
        out["batch_budget_usd"] = float(job["batch_budget_usd"])
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
