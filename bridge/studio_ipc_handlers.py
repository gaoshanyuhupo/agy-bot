"""Studio IPC handler callbacks, redaction helpers, and lifecycle (`_start_studio_ipc` / `_stop_studio_ipc`).

Standalone-capable flat module (no top-level `import bridge`). When wired into
`bridge/bridge.py`, call `bind_host(bridge_module)` so all shared state (`state`,
`state_lock`, `session_lock`, `_session_pool`, `job_q`, `_studio_ipc_buffer`,
`_studio_ipc_server`, `cancel_requested`, `MCP_CONFIG_FILE`, `SKILLS_SEARCH_DIRS`)
remains a single source of truth on the host module and respects runtime monkeypatches.

Lock Hierarchy Invariants (strictly preserved):
- NEVER nest `state_lock -> session_lock`.
- NEVER nest `job_q._cond <-> session_lock`.
- NEVER run blocking `git` calls while holding `state_lock` or `session_lock`.
"""

from __future__ import annotations

import collections
import datetime
import difflib
import json
import os
import re
import stat
import threading
import time
import uuid

try:
    import bot_bus as _default_bot_bus
except ImportError:
    from bridge import bot_bus as _default_bot_bus  # type: ignore[no-redef]

try:
    import bot_profiles as _default_bot_profiles
except ImportError:
    from bridge import bot_profiles as _default_bot_profiles  # type: ignore[no-redef]

try:
    import gateway_adapter as _default_gateway_adapter
except ImportError:
    from bridge import gateway_adapter as _default_gateway_adapter  # type: ignore[no-redef]

try:
    import scheduler as _default_scheduler
except ImportError:
    from bridge import scheduler as _default_scheduler  # type: ignore[no-redef]

try:
    import studio_ipc as _default_studio_ipc
except ImportError:
    from bridge import studio_ipc as _default_studio_ipc  # type: ignore[no-redef]

_host = None


def bind_host(host):
    """Bind the runtime bridge host module (or namespace) for lazy attribute resolution."""
    global _host
    _host = host
    return host


def _h(host=None):
    target = host if host is not None else _host
    if target is None:
        raise RuntimeError("studio_ipc_handlers host is not bound; call bind_host(bridge_module) first")
    return target


def _mod(name, fallback, *, host=None):
    target = host if host is not None else _host
    if target is None:
        return fallback
    val = getattr(target, name, None)
    return val if val is not None else fallback


# ---------------------------------------------------------------- Redaction & Sanitization Constants
_undo_apply_lock = threading.Lock()
_studio_attention_receipts = collections.deque(maxlen=128)

_IPC_SECRET_PATTERNS = (
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"(?<![A-Za-z0-9_.-])\d{8,11}:[A-Za-z0-9_-]{24,45}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{16,}\b"),
    re.compile(r"\bsk-(?:proj-|ant-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:cfut|cfsd|cfat|ibk|ibssh|alt)_[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bhvs\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\b(?:lv[12]|kv/data|secret/data)/[A-Za-z0-9_./*-]+\b"),
    re.compile(r"(?i)\b(?:bearer|basic)\s+[^\s,;\"'`)\]}]+"),
    re.compile(
        r"""(?i)(?<![A-Za-z0-9_.-])(?:token|apikey|api_key|key|secret|password|passwd|pwd|cookie|authorization|credential)\s*[:=]\s*[^\s,;\"'`&)\]}]+"""
    ),
)
_IPC_HOST_PATH_RE = re.compile(
    r"(?:(?<=^)|(?<=[\s(\[\{\"'`=:;,+\-]))"
    r"(?:(?i:file):///(?:home|Users|root|etc|var|tmp|opt|srv|proc|run|mnt|media|data|private|secrets)/[^\s,'\"`<>)\]}]+"
    r"|/(?:home|Users|root|etc|var|tmp|opt|srv|proc|run|mnt|media|data|private|secrets)/[^\s,'\"`<>)\]}]+"
    r"|~/[^\s,'\"`<>)\]}]+"
    r"|[A-Za-z]:[\\/][^\s,'\"`<>)\]}]+"
    r"|[^\s(\[\{\"'`=:;,<>)\]}+\-]+\.sock\b)"
)
MAX_IPC_MODEL_SLUG_LEN = 160
_IPC_SLUG_CLEAN_RE = re.compile(r"[^A-Za-z0-9._:@/-]+")
_IPC_CTRL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")

_IPC_SENSITIVE_EXACT_NAMES = frozenset({
    ".env",
    ".envrc",
    "users.json",
    "auth_users.json",
    "sessions.json",
    ".bao_credentials.json",
    "auth.json",
    "credentials.json",
    "audit.jsonl",
    "mcp_config.json",
})
_IPC_SENSITIVE_SUFFIXES = (
    ".token",
    ".secret",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".db",
    ".db-wal",
    ".db-shm",
    ".db-journal",
    ".sqlite",
    ".sqlite3",
    ".sock",
)
_IPC_SENSITIVE_SUBSTRINGS = (
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".sqlite",
)
_IPC_CHECKPOINT_DIFF_MAX_BYTES = 256 * 1024


def _redact_ipc_text(raw, max_len=160):
    text = str(raw or "").strip()
    if not text:
        return ""
    for pat in _IPC_SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    text = _IPC_HOST_PATH_RE.sub("[REDACTED]", text)
    text = re.sub(r"\s+", " ", text).strip()
    if max_len and len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def _sanitize_ipc_slug(raw, max_len=64):
    text = str(raw or "").strip()
    if not text:
        return ""
    text = _IPC_CTRL_CHARS_RE.sub("", text).strip()
    if not text:
        return ""
    if text.startswith(("/", "~")):
        text = os.path.basename(text)
    if ".." in text:
        return "[REDACTED]"
    for pat in _IPC_SECRET_PATTERNS:
        if pat.search(text):
            return "[REDACTED]"
    if _IPC_HOST_PATH_RE.search(text):
        return "[REDACTED]"
    return _IPC_SLUG_CLEAN_RE.sub("_", text)[:max_len]


def _is_ipc_sensitive_rel_path(rel_path):
    norm = str(rel_path or "").replace("\\", "/").strip("/")
    if not norm:
        return False
    for part in norm.split("/"):
        low = part.strip().lower()
        if not low:
            continue
        if low == ".git" or low == ".env" or low.startswith(".env."):
            return True
        if low in _IPC_SENSITIVE_EXACT_NAMES:
            return True
        if any(low.endswith(suf) for suf in _IPC_SENSITIVE_SUFFIXES):
            return True
        if any(sub in low for sub in _IPC_SENSITIVE_SUBSTRINGS):
            return True
    return False


def _redact_ipc_multiline(raw):
    """Redact secrets and host paths from multiline diff content while preserving newlines."""
    text = str(raw or "")
    if not text:
        return ""
    for pat in _IPC_SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    text = _IPC_HOST_PATH_RE.sub("[REDACTED]", text)
    return text


def _truncate_utf8_bytes_ipc(text, max_bytes):
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text, False
    return raw[:max_bytes].decode("utf-8", errors="ignore"), True


def _parse_skill_frontmatter(skill_md_path):
    """Parse ONLY `name` and `description` from a SKILL.md YAML frontmatter block."""
    name = ""
    desc = ""
    try:
        with open(skill_md_path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return "", ""
    lines = head.splitlines()
    if not lines or lines[0].strip() != "---":
        return "", ""
    for line in lines[1:40]:
        s = line.strip()
        if s == "---":
            break
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        kl = k.strip().lower()
        val = v.strip().strip("'\"")
        if kl == "name" and val:
            name = val
        elif kl == "description" and val:
            desc = val
    return name, desc


def _is_forbidden_webui_schedule(task):
    """Defense-in-depth Bridge check: reject any `script` or shell/precheck_cmd task from WebUI IPC."""
    if not isinstance(task, dict):
        return True
    ttype = str(task.get("task_type") or "").strip().lower()
    if ttype == "script":
        return True
    if str(task.get("precheck_cmd") or "").strip():
        return True
    payload = task.get("payload")
    if isinstance(payload, dict):
        for key in ("precheck_cmd", "script", "command", "cmd", "shell"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return True
            if val is not None and not isinstance(val, str) and bool(val):
                return True
    return False


# ---------------------------------------------------------------- Socket, RBAC & Meta Handlers
def _studio_ipc_sock_path():
    h = _h()
    srv = getattr(h, "_studio_ipc_server", None)
    if srv is None:
        return ""
    try:
        return str(srv.sock_path)
    except Exception:
        return ""


def _resolve_studio_users_json_role(user_id):
    """Live-recompute role from Studio `users.json` when present (fail-closed on symlink/corruption)."""
    h = _h()
    users_path = os.environ.get("AGY_STUDIO_USERS_FILE", "").strip() or getattr(h, "STUDIO_USERS_FILE", "")
    if not users_path:
        return None
    if os.path.islink(users_path):
        return "denied"
    if not os.path.isfile(users_path):
        return None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(users_path, flags)
        try:
            with os.fdopen(fd, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            return "denied"
    except Exception:
        return "denied"
    if not isinstance(doc, dict) or not isinstance(doc.get("users"), dict):
        return "denied"
    target_uid = int(user_id)
    matched_roles = []
    for rec in doc["users"].values():
        if not isinstance(rec, dict):
            return "denied"
        if "enabled" in rec and not isinstance(rec.get("enabled"), bool):
            return "denied"
        if "disabled" in rec and not isinstance(rec.get("disabled"), bool):
            return "denied"
        rec_uid = rec.get("user_id")
        if isinstance(rec_uid, bool) or not isinstance(rec_uid, int):
            continue
        if rec_uid != target_uid:
            continue
        if rec.get("enabled") is False or bool(rec.get("disabled", False)):
            continue
        r = str(rec.get("role") or "").strip().lower()
        if r in ("admin", "readonly"):
            matched_roles.append(r)
    if not matched_roles:
        return "denied"
    if "admin" in matched_roles:
        return "admin"
    return "readonly"


def _studio_ipc_resolve_role(user_id):
    h = _h()
    env_role = h._get_user_role(user_id, from_user={"id": int(user_id)}, allow_uid_fallback=True)
    if env_role not in ("admin", "readonly"):
        return "denied"
    resolve_users_fn = getattr(h, "_resolve_studio_users_json_role", _resolve_studio_users_json_role)
    users_role = resolve_users_fn(user_id)
    if users_role is None:
        return env_role
    if users_role not in ("admin", "readonly"):
        return "denied"
    if env_role == "admin" and users_role == "admin":
        return "admin"
    return "readonly"


def _studio_ipc_get_meta():
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    cfg = h._current_bot_cfg()
    sc = h.get_scope_state(h.PRIMARY_SCOPE_KEY)
    try:
        models_raw = h.agy_models(include_gateways=True, force_refresh=False)
    except Exception:
        models_raw = []
    models_out = [
        {"id": _sanitize_ipc_slug(slug, max_len=MAX_IPC_MODEL_SLUG_LEN), "label": _redact_ipc_text(desc, max_len=160)}
        for slug, desc in models_raw[:120]
    ]
    try:
        projs_raw = h.list_agy_projects()
    except Exception:
        projs_raw = []
    # Never expose raw filesystem paths in Studio IPC meta
    projects_out = [{"id": str(p.get("id") or ""), "name": str(p.get("name") or "")} for p in projs_raw if p.get("id")]
    model_mode = str(cfg.get("model_mode") or bb.MODEL_MODE_DEFAULT)
    configured_model = str(cfg.get("configured_model") or "")
    dm_eff = h._resolve_dm_effective_model() or ""
    if model_mode == bb.MODEL_MODE_CUSTOM:
        effective_model = configured_model or dm_eff
    elif model_mode == bb.MODEL_MODE_FOLLOW:
        effective_model = dm_eff
    else:
        effective_model = h.ENV_BOT_MODEL or dm_eff
    default_effort = str(sc.get("effort") or cfg.get("default_effort") or h.ENV_BOT_EFFORT or "").strip().lower()
    with h.session_lock:
        busy = bool(h.turn_running)
        active_web_id = h.turn_running_web_id
        active_cid = h.turn_running_cid
    return {
        "handle": h._current_bot_handle(),
        "display_name": h.BOT_META.get("first_name") or h._current_bot_handle(),
        "role": cfg.get("role") or "peer",
        "busy": busy,
        "active_turn_id": active_web_id,
        "active_cid": active_cid,
        "model_mode": model_mode,
        "active_model": _sanitize_ipc_slug(effective_model or dm_eff or "", max_len=MAX_IPC_MODEL_SLUG_LEN),
        "effective_model": _sanitize_ipc_slug(effective_model or "", max_len=MAX_IPC_MODEL_SLUG_LEN),
        "default_effort": default_effort if default_effort in ("", "low", "medium", "high", "xhigh", "max") else "",
        "default_project": h.current_project(h.PRIMARY_SCOPE_KEY) or "",
        "efforts": list(h.EFFORTS),
        "models": models_out,
        "projects": projects_out,
    }


# ---------------------------------------------------------------- Turn, Job & Schedule Handlers
def _studio_ipc_enqueue_turn(req):
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    sipc = _mod("studio_ipc", _default_studio_ipc, host=h)
    cid = req.get("cid")
    uid = int(req["user_id"])
    priority = str(req.get("priority") or "normal").strip().lower()
    if priority not in ("normal", "urgent"):
        priority = "normal"
    interrupt_current = req.get("interrupt_current") is True

    # Snapshot running state safely without nesting job_q._cond and session_lock.
    with h.session_lock:
        cur_running = bool(h.turn_running)
        cur_running_cid = h.turn_running_cid
        cur_running_web_id = h.turn_running_web_id

    target_abort_tid = None
    should_interrupt_running = False
    running_same_cid = bool(cid and cur_running and cur_running_cid == cid)

    if cid:
        active_tid = h._studio_ipc_buffer.find_active_turn_for_cid(cid)
        if active_tid:
            active_info = h._studio_ipc_buffer.get_turn_info(active_tid)
            if active_info is not None and int(active_info["owner_user_id"]) != uid:
                if interrupt_current:
                    return 403, {"ok": False, "code": "forbidden", "error": "无权中止其他用户的对话轮次"}
                return 409, {"ok": False, "code": "session_busy", "error": "会话已有排队或执行中的轮次（session_busy）"}
            if not interrupt_current:
                return 409, {"ok": False, "code": "session_busy", "error": "会话已有排队或执行中的轮次（session_busy）"}
            target_abort_tid = active_tid

        if running_same_cid:
            if not interrupt_current:
                return 409, {"ok": False, "code": "session_busy", "error": "会话正在执行中（session_busy）"}
            # Confirm running turn belongs to `uid` (web turn or owner-matched TG turn).
            if cur_running_web_id:
                run_info = h._studio_ipc_buffer.get_turn_info(cur_running_web_id)
                if run_info is None or int(run_info["owner_user_id"]) != uid:
                    return 403, {"ok": False, "code": "forbidden", "error": "无权中止其他用户的对话轮次"}
                target_abort_tid = cur_running_web_id
                should_interrupt_running = True
            else:
                owner_active = h._studio_ipc_buffer.find_active_turn_for_cid_and_owner(cid, uid)
                if owner_active is None:
                    return 409, {"ok": False, "code": "session_busy", "error": "会话正在执行其他来源轮次（session_busy）"}
                target_abort_tid = owner_active["turn_id"]
                should_interrupt_running = True
        else:
            if sipc.is_conversation_locked(bb.BUS_DIR, cid):
                return 409, {"ok": False, "code": "session_busy", "error": "会话已被其他进程占用（session_busy）"}
    elif interrupt_current and cur_running and cur_running_web_id:
        run_info = h._studio_ipc_buffer.get_turn_info(cur_running_web_id)
        if run_info is not None and int(run_info["owner_user_id"]) == uid:
            target_abort_tid = cur_running_web_id
            should_interrupt_running = True
            if not cid and cur_running_cid:
                cid = cur_running_cid

    turn_id = f"turn-{uuid.uuid4().hex[:16]}"
    scope_key = f"web:{uid}:{cid or turn_id}"
    sync_tg = req.get("sync_tg") is True
    raw_worktree_flag = req.get("worktree", False)
    if not isinstance(raw_worktree_flag, bool):
        return 400, {"ok": False, "error": "worktree 必须为布尔值（true/false）"}
    want_worktree = raw_worktree_flag

    # Snapshot any existing bound worktree for `cid` under state_lock ONLY (release before any git I/O).
    bound_wt_info = None
    if cid:
        with h.state_lock:
            wt_by_cid = h.state.get("worktrees_by_cid")
            if isinstance(wt_by_cid, dict) and isinstance(wt_by_cid.get(cid), dict):
                bound_wt_info = dict(wt_by_cid[cid])
            if bound_wt_info is None:
                sc_existing = (h.state.get("scopes") or {}).get(scope_key)
                if isinstance(sc_existing, dict) and isinstance(sc_existing.get("worktree"), dict):
                    bound_wt_info = dict(sc_existing["worktree"])

    # Verify existing bound worktree still exists safely on disk (no symlinks)
    worktree_info = None
    if isinstance(bound_wt_info, dict) and bound_wt_info.get("active"):
        b_root = str(bound_wt_info.get("repo_root") or "").strip()
        b_wt_id = str(bound_wt_info.get("worktree_id") or "").strip()
        if b_root and b_wt_id:
            ok_wt_dir, wt_real_dir, _sc_wt, _err_wt = bb.resolve_studio_worktree_dir(b_root, b_wt_id)
            if ok_wt_dir and wt_real_dir:
                worktree_info = dict(bound_wt_info)
                worktree_info["path"] = wt_real_dir

    # Prepare new isolated worktree OUTSIDE all locks (strictly zero git calls under state_lock / session_lock)
    req_project = req.get("project")
    resolved_proj_id = None
    resolved_proj_workdir = None
    if req_project:
        for p in h.list_agy_projects():
            if p.get("id") == req_project or p.get("name") == req_project:
                resolved_proj_id = str(p.get("id") or "")
                resolved_proj_workdir = str(p.get("workdir") or "")
                break
    elif worktree_info is None and want_worktree:
        # Fallback to primary scope's configured project if caller omitted explicit project
        cur_p = h.current_project(h.PRIMARY_SCOPE_KEY)
        if cur_p:
            for p in h.list_agy_projects():
                if p.get("id") == cur_p or p.get("name") == cur_p:
                    resolved_proj_id = str(p.get("id") or "")
                    resolved_proj_workdir = str(p.get("workdir") or "")
                    break

    if worktree_info is None and want_worktree:
        if resolved_proj_id and resolved_proj_workdir:
            wt_slug = f"wt-{uuid.uuid4().hex[:12]}"
            prep = bb.prepare_studio_worktree(
                resolved_proj_workdir,
                wt_slug,
                project_id=resolved_proj_id,
            )
            if prep.get("active"):
                prep["scope_key"] = scope_key
                prep["bot"] = h._current_bot_handle()
                if cid:
                    prep["cid"] = cid
                worktree_info = prep
                with h.state_lock:
                    sc_wt = h._ensure_scope_locked(scope_key)
                    sc_wt["worktree"] = dict(prep)
                    if cid:
                        wt_map = h.state.setdefault("worktrees_by_cid", {})
                        if isinstance(wt_map, dict):
                            wt_map[cid] = dict(prep)
                h.save_state()
                try:
                    bb.upsert_studio_worktree_meta(
                        str(prep["worktree_id"]),
                        prep,
                        bus_dir=bb.BUS_DIR,
                    )
                except Exception as wreg_err:
                    h.log("upsert_studio_worktree_meta enqueue error: %r" % wreg_err)
            else:
                worktree_info = prep
        else:
            worktree_info = {"enabled": True, "active": False, "reason": "project_not_whitelisted"}

    sanitized_wt = (
        bb.sanitize_studio_worktree_meta(worktree_info)
        if isinstance(worktree_info, dict)
        else None
    )

    h._studio_ipc_buffer.create_turn(
        turn_id,
        owner_user_id=uid,
        actor_username=str(req.get("actor_username") or ""),
        bot_handle=h._current_bot_handle(),
        scope_key=scope_key,
        cid=cid,
        source="web",
        prompt_preview=h._make_prompt_preview(req["prompt"]),
    )
    web_req = {
        "turn_id": turn_id,
        "user_id": uid,
        "actor_username": str(req.get("actor_username") or ""),
        "scope_key": scope_key,
        "prompt": req["prompt"],
        "cid": cid,
        "project": resolved_proj_id or req.get("project"),
        "model": req.get("model"),
        "effort": req.get("effort"),
        "sync_tg": sync_tg,
        "worktree": want_worktree,
        "worktree_info": worktree_info,
        "priority": priority,
    }

    # Put urgent/interrupt turn at the head of the queue BEFORE interrupting the running turn,
    # so the worker picks up this turn immediately after the interrupted turn exits cleanly.
    if priority == "urgent" or interrupt_current:
        new_qid = h.job_q.put_front((0, None, scope_key, ("__WEB_TURN__", web_req)))
    else:
        new_qid = h.job_q.put((0, None, scope_key, ("__WEB_TURN__", web_req)))

    interrupted_turn_id = None
    if interrupt_current and target_abort_tid:
        if h.job_q.cancel_web_turn(target_abort_tid):
            interrupted_turn_id = target_abort_tid
            h._studio_ipc_buffer.mark_aborted(target_abort_tid)
            h._studio_ipc_buffer.append(
                target_abort_tid,
                "aborted",
                {"conversation_id": cid, "partial_text": "", "reason": "preempted_by_urgent"},
            )
        elif should_interrupt_running:
            to_kill = None
            aborted_running = False
            with h.session_lock:
                if (
                    h.turn_running
                    and h.turn_running_qid != new_qid
                    and h.turn_running_web_id != turn_id
                    and (
                        (h.turn_running_web_id == target_abort_tid)
                        or (not h.turn_running_web_id and cid and h.turn_running_cid == cid)
                    )
                ):
                    h.cancel_requested = True
                    target_sk = h.turn_running_scope
                    if target_sk:
                        to_kill = h._session_pool.pop(target_sk, None)
                    aborted_running = True
            if aborted_running:
                interrupted_turn_id = target_abort_tid
                h._studio_ipc_buffer.mark_aborted(target_abort_tid)
                if to_kill is not None:
                    h.close_session_async(to_kill, force=True)

    resp_202 = {
        "ok": True,
        "turn_id": turn_id,
        "bot": h._current_bot_handle(),
        "cid": cid,
        "status": "queued",
        "priority": priority,
        "interrupted_turn_id": interrupted_turn_id,
    }
    if sanitized_wt is not None:
        resp_202["worktree"] = sanitized_wt
    return 202, resp_202


def _studio_ipc_abort_turn(turn_id, user_id):
    h = _h()
    info = h._studio_ipc_buffer.get_turn_info(turn_id)
    if info is None:
        return 404, {"ok": False, "error": "未找到对应的对话轮次"}
    if int(info["owner_user_id"]) != int(user_id):
        return 403, {"ok": False, "error": "无权中止其他用户的对话轮次"}

    if h.job_q.cancel_web_turn(turn_id):
        h._studio_ipc_buffer.mark_aborted(turn_id)
        h._studio_ipc_buffer.append(
            turn_id,
            "aborted",
            {"conversation_id": info.get("cid"), "partial_text": "", "reason": "cancelled_in_queue"},
        )
        return 200, {"ok": True, "aborted": True, "turn_id": turn_id, "was_queued": True}

    to_kill = None
    aborted_running = False
    with h.session_lock:
        if h.turn_running and h.turn_running_web_id == turn_id:
            h.cancel_requested = True
            target_sk = h.turn_running_scope
            if target_sk:
                to_kill = h._session_pool.pop(target_sk, None)
            aborted_running = True

    if aborted_running:
        h._studio_ipc_buffer.mark_aborted(turn_id)
        if to_kill is not None:
            h.close_session_async(to_kill, force=True)
        return 200, {"ok": True, "aborted": True, "turn_id": turn_id, "was_running": True}

    # Never touch unrelated Telegram turns or already-finished turns
    return 200, {"ok": True, "aborted": False, "turn_id": turn_id, "status": info["status"]}


def _studio_ipc_cancel_job(job_id, user_id):
    """Precisely cancel a queued or running bus job without affecting unrelated Telegram turns or other jobs."""
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    job = bb.get_job(job_id)
    if not isinstance(job, dict):
        return 404, {"ok": False, "error": "未找到对应的派工单"}

    cur_status = str(job.get("status") or "").lower()
    if cur_status in bb.TERMINAL_STATUSES:
        return 200, {
            "ok": True,
            "job_id": job_id,
            "already_terminal": True,
            "cancelled": False,
            "status": cur_status,
        }

    removed_from_q = h.job_q.cancel_bus_job(job_id)
    updated = bb.cancel_job(job_id, reason="cancelled_by_studio")
    updated_status = str((updated or job).get("status") or cur_status).lower()

    matched_running = False
    with h.session_lock:
        if (
            h.turn_running
            and h._active_bus_job_id == job_id
            and h.turn_running_scope == f"bus:{job_id}"
        ):
            h.cancel_requested = True
            matched_running = True

    if matched_running:
        return 200, {
            "ok": True,
            "job_id": job_id,
            "already_terminal": False,
            "cancelled": True,
            "was_running": True,
            "status": "cancelling",
        }
    if removed_from_q or updated_status == "cancelled":
        return 200, {
            "ok": True,
            "job_id": job_id,
            "already_terminal": False,
            "cancelled": True,
            "was_queued": True,
            "status": "cancelled",
        }
    return 200, {
        "ok": True,
        "job_id": job_id,
        "already_terminal": updated_status in bb.TERMINAL_STATUSES,
        "cancelled": bool((updated or {}).get("cancel_requested")),
        "status": updated_status,
    }


def _studio_ipc_run_schedule(schedule_id, user_id):
    """Trigger a single safe scheduled task immediately; strictly refuses `script` and `precheck_cmd`."""
    h = _h()
    sched = _mod("scheduler", _default_scheduler, host=h)
    task = sched.task_mgr.get_task(schedule_id)
    if not isinstance(task, dict):
        return 404, {"ok": False, "error": "未找到对应的定时任务"}

    # Defense-in-depth RCE ban on Bridge side: NEVER execute shell=True tasks via WebUI/IPC
    if _is_forbidden_webui_schedule(task):
        return 403, {
            "ok": False,
            "source": "bridge_ipc",
            "error": "禁止通过 WebUI/IPC 触发 script 或包含 precheck_cmd 的定时任务",
        }

    task_copy = json.loads(json.dumps(task))
    deliv = task_copy.setdefault("delivery", {})
    target_chat = deliv.get("target_chat_id")
    target_thread = h._normalize_thread_id(deliv.get("target_thread_id"))
    if not target_chat:
        if h.ALLOWED:
            target_chat = h.PRIMARY_CHAT_ID or next(iter(h.ALLOWED))
        elif user_id:
            target_chat = int(user_id)
        if target_chat:
            deliv["target_chat_id"] = target_chat

    skey = h.scope_key_for(target_chat or 0, target_thread)
    h.job_q.put((target_chat or 0, target_thread, skey, ("__SCHEDULED__", task_copy)))
    return 202, {
        "ok": True,
        "queued": True,
        "schedule_id": schedule_id,
        "task_type": str(task.get("task_type") or ""),
        "bot": h._current_bot_handle(),
    }


# ---------------------------------------------------------------- MCP / Skills / Project Discovery
def _collect_sanitized_mcp_list():
    """Return strictly allowlisted MCP metadata: `{name, transport, enabled}` ONLY.

    NEVER exposes `env`, `headers`, `command`, `args`, `url`, `lv1/...`, tokens, or host paths.
    """
    h = _h()
    cfg_path = getattr(h, "MCP_CONFIG_FILE", "")
    if not cfg_path or not os.path.isfile(cfg_path):
        return []
    try:
        with open(cfg_path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except Exception:
        return []
    servers = doc.get("mcpServers") if isinstance(doc, dict) else None
    if not isinstance(servers, dict):
        return []
    out = []
    for raw_name, srv_cfg in sorted(servers.items()):
        if not isinstance(srv_cfg, dict):
            continue
        safe_name = _sanitize_ipc_slug(raw_name, max_len=64)
        if not safe_name:
            continue
        raw_type = str(srv_cfg.get("type") or srv_cfg.get("transport") or "").strip().lower()
        if raw_type in ("sse", "http", "streamable-http", "stdio"):
            transport = raw_type
        elif srv_cfg.get("url") or srv_cfg.get("serverUrl"):
            transport = "http"
        elif srv_cfg.get("command"):
            transport = "stdio"
        else:
            transport = "unknown"
        enabled = not bool(srv_cfg.get("disabled", False))
        out.append({
            "name": safe_name,
            "transport": transport,
            "enabled": enabled,
        })
    return out[:64]


def _collect_sanitized_skills_list():
    """Return strictly allowlisted Skills metadata: `{name, scope, description (<=160)}` ONLY.

    When `SKILLS_SEARCH_DIRS` is not overridden by tests, resolves effective skills strictly
    according to per-bot isolation (Worker: own + allowlisted catalog; Coordinator: own +
    full team aggregated + catalog).
    """
    h = _h()
    bp = _mod("bot_profiles", _default_bot_profiles, host=h)
    search_dirs = getattr(h, "SKILLS_SEARCH_DIRS", None)
    if search_dirs is not None:
        roots = list(search_dirs)
        items = []
        seen = set()
        for scope, root_dir in roots:
            if not root_dir or not os.path.isdir(root_dir):
                continue
            try:
                entries = sorted(os.scandir(root_dir), key=lambda e: e.name)
            except OSError:
                continue
            for ent in entries:
                if not ent.is_dir(follow_symlinks=False):
                    continue
                md_path = os.path.join(ent.path, "SKILL.md")
                if os.path.islink(md_path) or not os.path.isfile(md_path):
                    continue
                parsed_name, parsed_desc = _parse_skill_frontmatter(md_path)
                safe_name = _sanitize_ipc_slug(parsed_name or ent.name, max_len=64)
                if not safe_name:
                    continue
                key = (str(scope), safe_name)
                if key in seen:
                    continue
                seen.add(key)
                safe_desc = _redact_ipc_text(parsed_desc, max_len=160)
                items.append({
                    "name": safe_name,
                    "scope": _sanitize_ipc_slug(scope, max_len=24) or "workspace",
                    "description": safe_desc,
                })
                if len(items) >= 120:
                    return items
        return items

    try:
        resolved = bp.resolve_effective_skills(
            h._current_bot_handle(),
            role=h._current_bot_role(),
            catalog_dirs=[os.path.join(h.WORKDIR, ".agents", "skills")],
            include_paths=False,
        )
        items = []
        seen = set()
        for sk in resolved.get("effective_skills") or []:
            safe_name = _sanitize_ipc_slug(sk.get("name") or sk.get("slug") or "", max_len=64)
            if not safe_name:
                continue
            raw_scope = str(sk.get("scope") or "workspace")
            if raw_scope == "team_bot" and sk.get("owner"):
                scope_label = f"bot:{_sanitize_ipc_slug(sk.get('owner'), max_len=20)}"
            else:
                scope_label = _sanitize_ipc_slug(raw_scope, max_len=24) or "workspace"
            key = (scope_label, safe_name)
            if key in seen:
                continue
            seen.add(key)
            items.append({
                "name": safe_name,
                "scope": scope_label,
                "description": _redact_ipc_text(sk.get("description") or "", max_len=160),
            })
            if len(items) >= 120:
                return items
        return items
    except Exception:
        return []


def _resolve_project_by_id_or_workdir():
    """Return `(by_id, by_realpath)` maps built from `list_agy_projects()`."""
    h = _h()
    by_id = {}
    by_real = {}
    try:
        projs = h.list_agy_projects()
    except Exception:
        projs = []
    for p in projs:
        pid = str(p.get("id") or "").strip()
        wdir = str(p.get("workdir") or "").strip()
        if pid:
            by_id[pid] = p
        if wdir:
            by_real[os.path.realpath(wdir)] = pid
    return by_id, by_real


# ---------------------------------------------------------------- Undo / Redo / Worktree Handlers
def _resolve_checkpoint_workdir_owner(wdir, *, by_real):
    """Resolve checkpoint `wdir` strictly to `(project_id, worktree_id, allowed)`.

    Supports:
    - Exact whitelisted project root -> `(pid, "", True)`
    - Single-level `<proj_root>/.worktrees/<wt_id>` with non-symlink `.worktrees` and `<wt_id>` -> `(pid, wt_id, True)`
    - Legacy default `WORKDIR` (or single-level `WORKDIR/.worktrees/<wt_id>`) -> `("", wt_id, True)`

    Strictly rejects sibling-prefix spoofing such as `<proj_root>-evil/.worktrees/wt1` and any symlinked root.
    """
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    sipc = _mod("studio_ipc", _default_studio_ipc, host=h)
    raw = str(wdir or "").strip()
    if not raw:
        return "", "", False
    if os.path.islink(raw):
        return "", "", False
    rw = os.path.realpath(raw)
    if not rw:
        return "", "", False
    if rw in by_real:
        return str(by_real[rw]), "", True

    def _match_single_level_worktree(base_real):
        wt_root_raw = os.path.join(base_real, bb.WORKTREE_DIR_NAME)
        if os.path.islink(wt_root_raw):
            return None
        wt_root_real = os.path.realpath(wt_root_raw)
        if not wt_root_real.startswith(base_real + os.sep):
            return None
        prefix = wt_root_real + os.sep
        if not rw.startswith(prefix):
            return None
        remainder = rw[len(prefix):]
        if not remainder or "/" in remainder or "\\" in remainder or os.sep in remainder:
            return None
        if not sipc.is_valid_worktree_id(remainder):
            return None
        wt_cand = os.path.join(wt_root_real, remainder)
        if os.path.islink(wt_cand):
            return None
        if os.path.realpath(wt_cand) != rw:
            return None
        return remainder

    for proj_real, pid in by_real.items():
        matched_wt = _match_single_level_worktree(proj_real)
        if matched_wt is not None:
            return str(pid), matched_wt, True

    default_real = os.path.realpath(h.WORKDIR)
    if rw == default_real:
        return "", "", True
    matched_default_wt = _match_single_level_worktree(default_real)
    if matched_default_wt is not None:
        return "", matched_default_wt, True

    return "", "", False


def _sanitize_undo_entry_for_ipc(entry, *, by_real, is_top):
    wdir = str(entry.get("workdir") or "").strip()
    pid, wt_id, _allowed = _resolve_checkpoint_workdir_owner(wdir, by_real=by_real)
    raw_changes = entry.get("changes") or []
    safe_changes = []
    for ch in raw_changes[:50]:
        if not isinstance(ch, dict):
            continue
        raw_rel = str(ch.get("path") or "")
        if _is_ipc_sensitive_rel_path(raw_rel):
            continue
        rel = _redact_ipc_text(raw_rel, max_len=200)
        act = _sanitize_ipc_slug(ch.get("action") or "modified", max_len=24)
        safe_changes.append({"path": rel, "action": act})
    return {
        "entry_id": _sanitize_ipc_slug(entry.get("id") or "", max_len=64),
        "ts": int(entry.get("ts") or 0),
        "cid": str(entry.get("conv") or ""),
        "project_id": _sanitize_ipc_slug(pid, max_len=64),
        "worktree_id": _sanitize_ipc_slug(wt_id, max_len=64) if wt_id else "",
        "prompt": _redact_ipc_text(entry.get("prompt") or "", max_len=120),
        "truncated": bool(entry.get("truncated", False)),
        "changes_count": len(safe_changes),
        "changes": safe_changes,
        "is_top": bool(is_top),
    }


def _studio_ipc_list_undo(user_id, cid=None, project_id=None, worktree_id=None):
    h = _h()
    sipc = _mod("studio_ipc", _default_studio_ipc, host=h)
    by_id, by_real = _resolve_project_by_id_or_workdir()
    target_pid = None
    if project_id:
        proj = by_id.get(project_id)
        if not proj:
            return 404, {"ok": False, "error": "未找到对应的白名单项目"}
        target_pid = str(proj.get("id") or project_id)
    if worktree_id and not sipc.is_valid_worktree_id(worktree_id):
        return 400, {"ok": False, "error": "非法的 worktree_id 格式"}

    undo_out = []
    redo_out = []
    with h.state_lock:
        scopes = h.state.get("scopes") or {}
        for _skey, sc in scopes.items():
            if not isinstance(sc, dict):
                continue
            for stack_name, bucket in (("undo_stack", undo_out), ("redo_stack", redo_out)):
                stk = sc.get(stack_name) or []
                if not isinstance(stk, list):
                    continue
                top_idx = len(stk) - 1
                for idx, ent in enumerate(stk):
                    if not isinstance(ent, dict):
                        continue
                    ent_cid = str(ent.get("conv") or "")
                    if cid and ent_cid != cid:
                        continue
                    ent_wdir = str(ent.get("workdir") or "").strip()
                    ent_pid, ent_wt_id, allowed = _resolve_checkpoint_workdir_owner(ent_wdir, by_real=by_real)
                    if not allowed:
                        continue
                    if target_pid and ent_pid != target_pid:
                        continue
                    if worktree_id and ent_wt_id != worktree_id:
                        continue
                    bucket.append(
                        _sanitize_undo_entry_for_ipc(ent, by_real=by_real, is_top=(idx == top_idx))
                    )

    undo_out.sort(key=lambda x: (not x["is_top"], -int(x["ts"])))
    redo_out.sort(key=lambda x: (not x["is_top"], -int(x["ts"])))
    return 200, {
        "ok": True,
        "bot": h._current_bot_handle(),
        "undo_stack": undo_out[:30],
        "redo_stack": redo_out[:30],
    }


def _studio_ipc_get_undo_diff(user_id, entry_id, cid=None, project_id=None):
    """Compute sanitized per-file unified diff for an undo/redo checkpoint from `acb_undo` blobs."""
    h = _h()
    sipc = _mod("studio_ipc", _default_studio_ipc, host=h)
    if not sipc.is_valid_undo_entry_id(entry_id):
        return 400, {"ok": False, "code": "invalid_entry_id", "error": "无效的检查点 entry_id"}
    if cid and not sipc.is_valid_cid(cid):
        return 400, {"ok": False, "code": "invalid_cid", "error": "无效的会话 ID 格式"}

    by_id, by_real = _resolve_project_by_id_or_workdir()
    target_pid = None
    if project_id:
        proj = by_id.get(project_id)
        if not proj:
            return 404, {"ok": False, "code": "project_not_found", "error": "未找到对应的白名单项目"}
        target_pid = str(proj.get("id") or project_id)

    matched_entry = None
    with h.state_lock:
        scopes = h.state.get("scopes") or {}
        for _skey, sc in scopes.items():
            if not isinstance(sc, dict):
                continue
            for stack_name in ("undo_stack", "redo_stack"):
                stk = sc.get(stack_name) or []
                for ent in stk:
                    if isinstance(ent, dict) and str(ent.get("id") or "") == entry_id:
                        matched_entry = dict(ent)
                        break
                if matched_entry is not None:
                    break
            if matched_entry is not None:
                break

    if matched_entry is None:
        return 404, {"ok": False, "code": "not_found", "error": "未找到对应的检查点"}

    entry_cid = str(matched_entry.get("conv") or "").strip()
    if cid and entry_cid != cid:
        return 403, {"ok": False, "code": "cid_mismatch", "error": "检查点不属于指定会话"}

    entry_wdir = str(matched_entry.get("workdir") or "").strip()
    ent_pid, ent_wt_id, allowed = _resolve_checkpoint_workdir_owner(entry_wdir, by_real=by_real)
    if not allowed:
        return 403, {"ok": False, "code": "workdir_not_allowed", "error": "检查点工作目录不在白名单内"}
    if target_pid and ent_pid != target_pid:
        return 403, {"ok": False, "code": "project_mismatch", "error": "检查点不属于指定项目"}

    raw_changes = matched_entry.get("changes") or []
    files_out = []
    combined_chunks = []
    total_added = 0
    total_deleted = 0
    total_bytes = 0
    truncated = bool(matched_entry.get("truncated", False))
    wdir_exists = bool(entry_wdir and os.path.isdir(entry_wdir) and not os.path.islink(entry_wdir))

    for ch in raw_changes[:300]:
        if not isinstance(ch, dict):
            continue
        rel = str(ch.get("path") or "").strip()
        if not rel or "\x00" in rel or "\\" in rel or os.path.isabs(rel) or rel.startswith("/"):
            continue
        parts = rel.split("/")
        if any(p in ("", ".", "..") for p in parts):
            continue
        if _is_ipc_sensitive_rel_path(rel):
            continue
        # Reject symlinks recorded in modes or currently present on disk
        pre_mode = ch.get("pre_mode")
        post_mode = ch.get("post_mode")
        if (isinstance(pre_mode, int) and stat.S_ISLNK(pre_mode)) or (
            isinstance(post_mode, int) and stat.S_ISLNK(post_mode)
        ):
            continue
        if wdir_exists and h._safe_under_workdir(entry_wdir, rel) is None:
            continue

        act = _sanitize_ipc_slug(ch.get("action") or "modified", max_len=24) or "modified"
        pre_sha1 = ch.get("pre_sha1")
        post_sha1 = ch.get("post_sha1")
        if pre_sha1 is not None and str(pre_sha1) != "":
            if not sipc.is_valid_sha1_hex(str(pre_sha1)):
                return 400, {"ok": False, "code": "invalid_sha1", "error": "检查点包含非法的 pre_sha1 格式"}
        if post_sha1 is not None and str(post_sha1) != "":
            if not sipc.is_valid_sha1_hex(str(post_sha1)):
                return 400, {"ok": False, "code": "invalid_sha1", "error": "检查点包含非法的 post_sha1 格式"}

        pre_bytes = b""
        post_bytes = b""
        missing_blob = False
        if pre_sha1:
            try:
                pre_bytes = h._undo_read_blob(str(pre_sha1))
            except OSError:
                missing_blob = True
        if post_sha1:
            try:
                post_bytes = h._undo_read_blob(str(post_sha1))
            except OSError:
                missing_blob = True

        safe_rel = _redact_ipc_text(rel, max_len=200)
        if b"\x00" in pre_bytes or b"\x00" in post_bytes:
            files_out.append({
                "path": safe_rel,
                "action": act,
                "is_binary": True,
                "added": 0,
                "deleted": 0,
                "diff": "",
                "truncated": False,
                "missing_blob": missing_blob,
            })
            continue

        pre_text = pre_bytes.decode("utf-8", errors="replace") if pre_bytes else ""
        post_text = post_bytes.decode("utf-8", errors="replace") if post_bytes else ""
        pre_lines = pre_text.splitlines()
        post_lines = post_text.splitlines()
        from_label = "/dev/null" if act == "created" else f"a/{rel}"
        to_label = "/dev/null" if act == "deleted" else f"b/{rel}"
        diff_lines = list(
            difflib.unified_diff(
                pre_lines,
                post_lines,
                fromfile=from_label,
                tofile=to_label,
                lineterm="",
            )
        )
        added_cnt = sum(1 for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++"))
        deleted_cnt = sum(1 for ln in diff_lines if ln.startswith("-") and not ln.startswith("---"))
        total_added += added_cnt
        total_deleted += deleted_cnt

        raw_file_diff = "\n".join(diff_lines)
        redacted_file_diff = _redact_ipc_multiline(raw_file_diff)
        file_trunc = False
        remaining = max(0, _IPC_CHECKPOINT_DIFF_MAX_BYTES - total_bytes)
        if remaining == 0 and redacted_file_diff:
            redacted_file_diff = ""
            file_trunc = True
            truncated = True
        else:
            bounded_file_diff, did_trunc = _truncate_utf8_bytes_ipc(redacted_file_diff, remaining)
            if did_trunc:
                file_trunc = True
                truncated = True
            redacted_file_diff = bounded_file_diff
            total_bytes += len(redacted_file_diff.encode("utf-8"))

        if redacted_file_diff:
            combined_chunks.append(redacted_file_diff)

        files_out.append({
            "path": safe_rel,
            "action": act,
            "is_binary": False,
            "added": added_cnt,
            "deleted": deleted_cnt,
            "diff": redacted_file_diff,
            "truncated": file_trunc,
            "missing_blob": missing_blob,
        })

    combined_diff, comb_trunc = _truncate_utf8_bytes_ipc("\n\n".join(combined_chunks), _IPC_CHECKPOINT_DIFF_MAX_BYTES)
    if comb_trunc:
        truncated = True

    return 200, {
        "ok": True,
        "bot": h._current_bot_handle(),
        "entry_id": entry_id,
        "ts": int(matched_entry.get("ts") or 0),
        "cid": entry_cid,
        "project_id": _sanitize_ipc_slug(ent_pid, max_len=64),
        "worktree_id": _sanitize_ipc_slug(ent_wt_id, max_len=64) if ent_wt_id else "",
        "prompt": _redact_ipc_text(matched_entry.get("prompt") or "", max_len=120),
        "added": total_added,
        "deleted": total_deleted,
        "files": files_out,
        "diff": combined_diff,
        "truncated": truncated,
    }


def _studio_ipc_apply_checkpoint(req, *, reverse=False):
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    sipc = _mod("studio_ipc", _default_studio_ipc, host=h)
    entry_id = str(req.get("entry_id") or "").strip()
    req_cid = req.get("cid")
    req_pid = req.get("project_id")
    force = bool(req.get("force", False))
    stack_key = "redo_stack" if reverse else "undo_stack"
    other_key = "undo_stack" if reverse else "redo_stack"

    by_id, by_real = _resolve_project_by_id_or_workdir()
    target_pid = None
    if req_pid:
        proj = by_id.get(req_pid)
        if not proj:
            return 404, {"ok": False, "code": "project_not_found", "error": "未找到对应的白名单项目"}
        target_pid = str(proj.get("id") or req_pid)

    undo_lock = getattr(h, "_undo_apply_lock", _undo_apply_lock)
    with undo_lock:
        # 1. Locate checkpoint under state_lock
        matched_skey = None
        matched_entry = None
        found_non_top = False
        found_consumed = False
        with h.state_lock:
            scopes = h.state.get("scopes") or {}
            for skey, sc in scopes.items():
                if not isinstance(sc, dict):
                    continue
                stk = sc.get(stack_key) or []
                for idx, ent in enumerate(stk):
                    if isinstance(ent, dict) and str(ent.get("id") or "") == entry_id:
                        if idx == len(stk) - 1:
                            matched_skey = skey
                            matched_entry = dict(ent)
                        else:
                            found_non_top = True
                        break
                if matched_entry is not None:
                    break
                other_stk = sc.get(other_key) or []
                for ent in other_stk:
                    if isinstance(ent, dict) and str(ent.get("id") or "") == entry_id:
                        found_consumed = True
                        break

        if matched_entry is None:
            if found_non_top:
                return 409, {"ok": False, "code": "not_stack_top", "error": "仅允许操作当前栈顶检查点"}
            if found_consumed:
                return 409, {"ok": False, "code": "already_consumed", "error": "该检查点已被消费或已变更"}
            return 404, {"ok": False, "code": "not_found", "error": "未找到对应的检查点"}

        entry_cid = str(matched_entry.get("conv") or "").strip()
        if req_cid and entry_cid != req_cid:
            return 403, {"ok": False, "code": "cid_mismatch", "error": "检查点不属于指定会话"}
        entry_wdir = str(matched_entry.get("workdir") or "").strip()
        ent_pid, ent_wt_id, allowed_wdir = _resolve_checkpoint_workdir_owner(entry_wdir, by_real=by_real)
        if not allowed_wdir:
            return 403, {"ok": False, "code": "workdir_not_allowed", "error": "检查点工作目录不在白名单内"}
        if target_pid and ent_pid != target_pid:
            return 403, {"ok": False, "code": "project_mismatch", "error": "检查点不属于指定项目"}

        # 2. Check active session lock & non-blocking ConversationLease
        with h.session_lock:
            busy_now = bool(
                h.turn_running
                and (
                    h.turn_running_scope == matched_skey
                    or (entry_cid and h.turn_running_cid == entry_cid)
                    or (ent_wt_id and h.turn_running_worktree_id == ent_wt_id)
                )
            )
        if busy_now or (entry_cid and h._studio_ipc_buffer.find_active_turn_for_cid(entry_cid)):
            return 409, {"ok": False, "code": "session_busy", "error": "会话正在执行中，暂不可回滚/重做（session_busy）"}

        conv_lease = None
        if entry_cid and sipc.is_valid_cid(entry_cid):
            conv_lease = sipc.ConversationLease.try_acquire(bb.BUS_DIR, entry_cid)
            if conv_lease is None:
                return 409, {"ok": False, "code": "session_busy", "error": "会话已被其他进程占用（session_busy）"}

        try:
            # Re-verify session_lock after acquiring cross-process lease
            with h.session_lock:
                if h.turn_running and (
                    h.turn_running_scope == matched_skey
                    or (entry_cid and h.turn_running_cid == entry_cid)
                    or (ent_wt_id and h.turn_running_worktree_id == ent_wt_id)
                ):
                    return 409, {"ok": False, "code": "session_busy", "error": "会话正在执行中（session_busy）"}

            with h.state_lock:
                sc_live = h._ensure_scope_locked(matched_skey)
                live_stk = list(sc_live.get(stack_key) or [])
                if not live_stk or str(live_stk[-1].get("id") or "") != entry_id:
                    return 409, {"ok": False, "code": "already_consumed", "error": "检查点栈顶状态已变化"}
                live_entry = dict(live_stk[-1])

                ok_apply, applied, conflicts, path_errors, _ = h._apply_checkpoint_changes_detailed(
                    live_entry, reverse=reverse, force=force
                )
                if path_errors:
                    safe_errs = [_redact_ipc_text(c, max_len=160) for c in path_errors[:10]]
                    return 403, {
                        "ok": False,
                        "code": "unsafe_path",
                        "error": "安全拦截：检查点包含非法路径或符号链接逃逸，已拒绝执行",
                        "conflicts": safe_errs,
                    }
                if not ok_apply:
                    safe_conf = [_redact_ipc_text(c, max_len=160) for c in conflicts[:10]]
                    return 409, {
                        "ok": False,
                        "code": "conflict",
                        "error": "检测到文件在检查点之后被外部修改，默认拒绝覆盖（确认后可使用 force 强制执行）",
                        "conflicts": safe_conf,
                    }

                popped = live_stk.pop()
                other_stk = list(sc_live.get(other_key) or [])
                other_stk.append(popped)
                sc_live[stack_key] = live_stk
                sc_live[other_key] = other_stk[-h._UNDO_STACK_LIMIT:]

                if not reverse:
                    reverted_paths = [rel for _act, rel in applied]
                    ts_str = datetime.datetime.now().strftime("%H:%M:%S")
                    notice = (
                        f"[系统提示：用户在 {ts_str} 执行了 /undo，已将工作区文件回滚恢复到改动前状态"
                        f"（涉及：{', '.join(reverted_paths[:10])}{' 等' if len(reverted_paths) > 10 else ''}）。"
                        f"请以当前磁盘上真实文件内容为准，勿假设上一轮的编辑仍然存在。]"
                    )
                    sc_live["pending_undo_notice"] = notice
                    if entry_cid:
                        sc_live["pending_undo_notice_cid"] = entry_cid
                        h._record_pending_undo_notice_by_cid_locked(entry_cid, notice)
                    else:
                        sc_live.pop("pending_undo_notice_cid", None)
                else:
                    sc_live["pending_undo_notice"] = None
                    sc_live.pop("pending_undo_notice_cid", None)
                    by_cid_notices = h.state.get("pending_undo_notices_by_cid")
                    if entry_cid and isinstance(by_cid_notices, dict):
                        by_cid_notices.pop(entry_cid, None)

                h._sync_top_level_mirrors_locked()
                rem_undo = len(sc_live.get("undo_stack") or [])
                rem_redo = len(sc_live.get("redo_stack") or [])
            h.save_state()

            return 200, {
                "ok": True,
                "action": "redo" if reverse else "undo",
                "bot": h._current_bot_handle(),
                "entry_id": entry_id,
                "cid": entry_cid,
                "project_id": _sanitize_ipc_slug(ent_pid, max_len=64),
                "worktree_id": _sanitize_ipc_slug(ent_wt_id, max_len=64) if ent_wt_id else "",
                "applied": [
                    {"action": _sanitize_ipc_slug(a, max_len=24), "path": _redact_ipc_text(p, max_len=200)}
                    for a, p in applied
                ],
                "remaining_undo": rem_undo,
                "remaining_redo": rem_redo,
            }
        finally:
            if conv_lease is not None:
                conv_lease.release()


def _studio_ipc_cleanup_worktree(req):
    """Safely clean up a Studio session worktree with strict lock ordering (C5, C6).

    Never holds `state_lock` or `session_lock` during blocking `git` calls and never nests
    `job_q._cond` with `session_lock` or `state_lock` with `session_lock`.
    If the associated session has an active turn, ALWAYS returns `409 session_busy` even with `force=True`.
    """
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    sipc = _mod("studio_ipc", _default_studio_ipc, host=h)
    wt_id = str(req.get("worktree_id") or "").strip()
    if not sipc.is_valid_worktree_id(wt_id):
        return 400, {"ok": False, "code": "invalid_worktree_id", "error": "非法的 worktree_id 格式"}
    pid = str(req.get("project_id") or "").strip()
    raw_force = req.get("force", False)
    if not isinstance(raw_force, bool):
        return 400, {"ok": False, "code": "invalid_force", "error": "force 必须为布尔值"}
    force = raw_force

    by_id, _by_real = _resolve_project_by_id_or_workdir()
    proj = by_id.get(pid)
    if not proj or not proj.get("workdir"):
        return 404, {"ok": False, "code": "project_not_found", "error": "未找到对应的白名单项目"}
    repo_root = str(proj["workdir"])

    ok_dir, wt_real, sc_dir, err_dir = bb.resolve_studio_worktree_dir(repo_root, wt_id)
    if not ok_dir or not wt_real:
        code_map = {400: "invalid_worktree_id", 403: "unsafe_path", 404: "not_found"}
        return sc_dir, {"ok": False, "code": code_map.get(sc_dir, "error"), "error": err_dir}

    undo_lock = getattr(h, "_undo_apply_lock", _undo_apply_lock)
    with undo_lock:
        # 1. Snapshot matching scope/cid bindings under state_lock ONLY (release immediately).
        bound_scopes = set()
        bound_cids = set()
        branch_hint = ""
        base_commit_hint = ""
        with h.state_lock:
            for skey, sc in (h.state.get("scopes") or {}).items():
                if not isinstance(sc, dict):
                    continue
                wt = sc.get("worktree")
                if isinstance(wt, dict) and str(wt.get("worktree_id") or "") == wt_id:
                    bound_scopes.add(skey)
                    c = str(wt.get("cid") or sc.get("conversation_id") or "").strip()
                    if c:
                        bound_cids.add(c)
                    if wt.get("branch") and not branch_hint:
                        branch_hint = str(wt["branch"])
                    if wt.get("base_commit") and not base_commit_hint:
                        base_commit_hint = str(wt["base_commit"])
            for cid_k, wt in (h.state.get("worktrees_by_cid") or {}).items():
                if isinstance(wt, dict) and str(wt.get("worktree_id") or "") == wt_id:
                    bound_cids.add(str(cid_k))
                    if wt.get("scope_key"):
                        bound_scopes.add(str(wt["scope_key"]))
                    if wt.get("branch") and not branch_hint:
                        branch_hint = str(wt["branch"])
                    if wt.get("base_commit") and not base_commit_hint:
                        base_commit_hint = str(wt["base_commit"])

        # Also check shared registry for cid/base_commit metadata
        reg_meta = bb.load_studio_worktrees(bb.BUS_DIR).get(wt_id)
        if isinstance(reg_meta, dict):
            if reg_meta.get("cid"):
                bound_cids.add(str(reg_meta["cid"]))
            if reg_meta.get("branch") and not branch_hint:
                branch_hint = str(reg_meta["branch"])
            if reg_meta.get("base_commit") and not base_commit_hint:
                base_commit_hint = str(reg_meta["base_commit"])

        # 2. Check active turn under session_lock ONLY (never nested with state_lock or job_q._cond).
        with h.session_lock:
            busy_now = bool(
                h.turn_running
                and (
                    h.turn_running_worktree_id == wt_id
                    or (h.turn_running_scope in bound_scopes)
                    or (h.turn_running_cid and h.turn_running_cid in bound_cids)
                )
            )
        if busy_now:
            return 409, {
                "ok": False,
                "code": "session_busy",
                "error": "关联会话正在执行中，暂不可清理 worktree（session_busy）",
            }
        for c in bound_cids:
            if h._studio_ipc_buffer.find_active_turn_for_cid(c):
                return 409, {
                    "ok": False,
                    "code": "session_busy",
                    "error": "关联会话已有排队或执行中的轮次（session_busy）",
                }
        if h.job_q.has_pending_web_turn(worktree_id=wt_id) or any(
            h.job_q.has_pending_web_turn(cid=c) for c in bound_cids
        ):
            return 409, {
                "ok": False,
                "code": "session_busy",
                "error": "关联会话仍有排队中的轮次（session_busy）",
            }

        # 3. Acquire cross-process ConversationLease for every bound cid (serializes turn/undo/cleanup).
        leases = []
        try:
            for c in sorted(bound_cids):
                if sipc.is_valid_cid(c):
                    lease = sipc.ConversationLease.try_acquire(bb.BUS_DIR, c)
                    if lease is None:
                        return 409, {
                            "ok": False,
                            "code": "session_busy",
                            "error": "关联会话已被其他进程占用（session_busy）",
                        }
                    leases.append(lease)

            # Re-verify session_lock & pop any idle warm AgentSession whose cwd is inside this worktree.
            warm_to_close = []
            with h.session_lock:
                if h.turn_running and (
                    h.turn_running_worktree_id == wt_id
                    or (h.turn_running_scope in bound_scopes)
                    or (h.turn_running_cid and h.turn_running_cid in bound_cids)
                ):
                    return 409, {
                        "ok": False,
                        "code": "session_busy",
                        "error": "关联会话正在执行中，暂不可清理 worktree（session_busy）",
                    }
                for sk_k, s_obj in list(h._session_pool.items()):
                    s_wdir = os.path.realpath(str(getattr(s_obj, "workdir", "") or ""))
                    if s_wdir == wt_real or s_wdir.startswith(wt_real + os.sep):
                        h._session_pool.pop(sk_k, None)
                        warm_to_close.append(s_obj)

            # Close evicted idle warm sessions OUTSIDE session_lock before running git worktree remove.
            for old_s in warm_to_close:
                try:
                    old_s.close(force=False)
                except Exception:
                    pass

            # 4. Run blocking git cleanup strictly OUTSIDE state_lock and session_lock.
            sc_clean, res_clean = bb.cleanup_studio_worktree(
                repo_root,
                wt_id,
                force=force,
                branch=branch_hint,
                base_commit=base_commit_hint,
            )
            if sc_clean != 200:
                return sc_clean, res_clean

            # 5. Purge worktree metadata from Bridge state and shared registry.
            with h.state_lock:
                for _skey, sc in (h.state.get("scopes") or {}).items():
                    if isinstance(sc, dict) and isinstance(sc.get("worktree"), dict):
                        if str(sc["worktree"].get("worktree_id") or "") == wt_id:
                            sc.pop("worktree", None)
                wt_map = h.state.get("worktrees_by_cid")
                if isinstance(wt_map, dict):
                    for cid_k in list(wt_map.keys()):
                        ent_wt = wt_map.get(cid_k)
                        if isinstance(ent_wt, dict) and str(ent_wt.get("worktree_id") or "") == wt_id:
                            wt_map.pop(cid_k, None)
            h.save_state()
            try:
                bb.remove_studio_worktree_meta(wt_id, bus_dir=bb.BUS_DIR)
            except Exception:
                pass
            return 200, {
                **res_clean,
                "project_id": _sanitize_ipc_slug(pid, max_len=64),
                "bot": h._current_bot_handle(),
            }
        finally:
            for lease in leases:
                lease.release()


def _studio_ipc_apply_undo(req):
    h = _h()
    fn = getattr(h, "_studio_ipc_apply_checkpoint", _studio_ipc_apply_checkpoint)
    return fn(req, reverse=False)


def _studio_ipc_apply_redo(req):
    h = _h()
    fn = getattr(h, "_studio_ipc_apply_checkpoint", _studio_ipc_apply_checkpoint)
    return fn(req, reverse=True)


# ---------------------------------------------------------------- Bot Config / Profile / Skill Handlers
def _studio_ipc_get_bot_config():
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    cfg = h._current_bot_cfg()
    sc = h.get_scope_state(h.PRIMARY_SCOPE_KEY)
    try:
        models_raw = h.agy_models(include_gateways=True, force_refresh=False)
    except Exception:
        models_raw = []
    models_out = [
        {"id": _sanitize_ipc_slug(slug, max_len=MAX_IPC_MODEL_SLUG_LEN), "label": _redact_ipc_text(desc, max_len=160)}
        for slug, desc in models_raw[:120]
    ]
    try:
        projs_raw = h.list_agy_projects()
    except Exception:
        projs_raw = []
    projects_out = [
        {"id": _sanitize_ipc_slug(p.get("id") or "", max_len=64), "name": _redact_ipc_text(p.get("name") or "", max_len=80)}
        for p in projs_raw
        if p.get("id")
    ]
    model_mode = str(cfg.get("model_mode") or bb.MODEL_MODE_DEFAULT)
    configured_model = str(cfg.get("configured_model") or "")
    dm_eff = h._resolve_dm_effective_model() or ""
    if model_mode == bb.MODEL_MODE_CUSTOM:
        effective_model = configured_model or dm_eff
    elif model_mode == bb.MODEL_MODE_FOLLOW:
        effective_model = dm_eff
    else:
        effective_model = h.ENV_BOT_MODEL or dm_eff

    default_effort = str(sc.get("effort") or cfg.get("default_effort") or h.ENV_BOT_EFFORT or "").strip().lower()
    with h.session_lock:
        busy = bool(h.turn_running)
    return {
        "handle": h._current_bot_handle(),
        "display_name": _redact_ipc_text(h.BOT_META.get("first_name") or h._current_bot_handle(), max_len=64),
        "role": _sanitize_ipc_slug(cfg.get("role") or "peer", max_len=24),
        "specialty": _redact_ipc_text(cfg.get("specialty") or "", max_len=160),
        "model_mode": model_mode,
        "configured_model": _sanitize_ipc_slug(configured_model, max_len=MAX_IPC_MODEL_SLUG_LEN),
        "effective_model": _sanitize_ipc_slug(effective_model, max_len=MAX_IPC_MODEL_SLUG_LEN),
        "dm_model": _sanitize_ipc_slug(h._resolve_dm_raw_model() or "", max_len=MAX_IPC_MODEL_SLUG_LEN),
        "env_default_model": _sanitize_ipc_slug(h.ENV_BOT_MODEL or "", max_len=MAX_IPC_MODEL_SLUG_LEN),
        "default_effort": default_effort if default_effort in ("", "low", "medium", "high", "xhigh", "max") else "",
        "default_project": _sanitize_ipc_slug(h.current_project(h.PRIMARY_SCOPE_KEY) or cfg.get("default_project") or "", max_len=64),
        "efforts": list(h.EFFORTS),
        "models": models_out,
        "projects": projects_out,
        "skills": _collect_sanitized_skills_list(),
        "mcp_servers": _collect_sanitized_mcp_list(),
        "busy": busy,
        "queue_depth": h.job_q.qsize(),
    }


def _is_allowed_bot_config_model(clean_model):
    """Hot-validate a native or external gateway model slug against current catalog & gateways.json."""
    h = _h()
    gwa = _mod("gateway_adapter", _default_gateway_adapter, host=h)
    if (
        not isinstance(clean_model, str)
        or not clean_model
        or len(clean_model) > MAX_IPC_MODEL_SLUG_LEN
        or ".." in clean_model
        or clean_model.startswith(("/", "~"))
        or _IPC_CTRL_CHARS_RE.search(clean_model)
    ):
        return False

    try:
        catalog = h.agy_models(include_gateways=True, force_refresh=False) or []
    except Exception:
        catalog = []
    allowed_models = {str(slug) for slug, _ in catalog}
    if clean_model in allowed_models:
        return True

    # Support explicit `gw:<gw_id>:<upstream_model>` even when upstream_model is unique across gateways
    explicit = gwa.parse_gateway_model_ref(clean_model)
    if explicit is not None:
        gid, upstream = explicit
        try:
            gws = h._get_gateways_map()
        except Exception:
            return False
        gw = gws.get(gid)
        if gw is None or not gw.enabled:
            return False
        if not gwa.model_matches_filters(upstream, gw.include_models, gw.exclude_models):
            return False
        try:
            gw_catalogs = h._get_gateway_catalogs({gid: gw}, force_refresh=False)
            exposed = list(gw_catalogs.get(gid) or ())
        except Exception:
            exposed = []
        for static_m in gw.models:
            if static_m not in exposed and gwa.model_matches_filters(
                static_m, gw.include_models, gw.exclude_models
            ):
                exposed.append(static_m)
        return upstream in exposed

    return False


def _studio_ipc_update_bot_config(req):
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    allowed_fields = {"user_id", "actor_username", "model_mode", "model", "default_effort", "default_project"}
    extra = set(req.keys()) - allowed_fields
    if extra:
        return 400, {"ok": False, "error": f"存在未允许的配置字段: {sorted(extra)[0]}"}

    has_model_mode = "model_mode" in req
    has_model = "model" in req
    has_effort = "default_effort" in req
    has_project = "default_project" in req
    if not (has_model_mode or has_model or has_effort or has_project):
        return 400, {"ok": False, "error": "至少需要提供一个可更新配置字段"}

    norm_mode = None
    clean_model = ""
    if has_model_mode or has_model:
        if not has_model_mode:
            return 400, {"ok": False, "error": "修改模型时必须显式提供 model_mode"}
        raw_mode = req.get("model_mode")
        if not isinstance(raw_mode, str):
            return 400, {"ok": False, "error": "model_mode 必须为字符串"}
        norm_mode = raw_mode.strip().lower()
        if norm_mode not in ("default", "follow", "custom"):
            return 400, {"ok": False, "error": "model_mode 仅允许 default / follow / custom"}
        raw_m = req.get("model")
        if norm_mode == "custom":
            if not isinstance(raw_m, str) or not raw_m.strip():
                return 400, {"ok": False, "error": "custom 模式必须指定具体模型 slug"}
            clean_model = raw_m.strip()
            if not _is_allowed_bot_config_model(clean_model):
                return 400, {"ok": False, "error": "指定模型不在可用模型白名单内"}
        else:
            if raw_m is not None and str(raw_m).strip() != "":
                return 400, {"ok": False, "error": "非 custom 模式不允许指定 model 参数"}

    norm_effort = None
    if has_effort:
        raw_ef = req.get("default_effort")
        if raw_ef is None:
            norm_effort = ""
        elif isinstance(raw_ef, str):
            norm_effort = raw_ef.strip().lower()
        else:
            return 400, {"ok": False, "error": "default_effort 必须为字符串"}
        if norm_effort not in ("", "low", "medium", "high", "xhigh", "max"):
            return 400, {"ok": False, "error": "default_effort 仅允许空值或 low/medium/high/xhigh/max"}

    resolved_proj_id = None
    resolved_proj_wdir = None
    if has_project:
        raw_p = req.get("default_project")
        if raw_p is None:
            resolved_proj_id = ""
            resolved_proj_wdir = h.WORKDIR
        elif isinstance(raw_p, str):
            p_str = raw_p.strip()
            if p_str == "":
                resolved_proj_id = ""
                resolved_proj_wdir = h.WORKDIR
            else:
                by_id, _ = _resolve_project_by_id_or_workdir()
                matched = by_id.get(p_str)
                if not matched:
                    return 400, {"ok": False, "error": "default_project 不在项目白名单内"}
                resolved_proj_id = str(matched["id"])
                resolved_proj_wdir = str(matched.get("workdir") or h.WORKDIR)
        else:
            return 400, {"ok": False, "error": "default_project 必须为字符串"}

    me = h._current_bot_handle()
    if norm_mode is not None:
        h._set_team_bot_model(me, norm_mode, clean_model)
        if norm_mode == "custom":
            h.update_scope_state(h.PRIMARY_SCOPE_KEY, model=clean_model)
        elif norm_mode == "default":
            h.update_scope_state(h.PRIMARY_SCOPE_KEY, model=None)

    cfg_updates = {}
    scope_updates = {}
    if norm_effort is not None:
        cfg_updates["default_effort"] = norm_effort
        scope_updates["effort"] = norm_effort or None
    if resolved_proj_id is not None:
        cfg_updates["default_project"] = resolved_proj_id
        scope_updates["project"] = resolved_proj_id or None
        scope_updates["workdir"] = resolved_proj_wdir
    if cfg_updates:
        bb.update_bot_config(me, **cfg_updates)
    if scope_updates:
        h.update_scope_state(h.PRIMARY_SCOPE_KEY, **scope_updates)

    h.save_state()
    h.invalidate_session("studio_bot_config", scope_key=h.PRIMARY_SCOPE_KEY)
    h._publish_bot_heartbeat()
    get_cfg_fn = getattr(h, "_studio_ipc_get_bot_config", _studio_ipc_get_bot_config)
    return 200, {"ok": True, **get_cfg_fn()}


def _studio_ipc_get_bot_profile():
    h = _h()
    bp = _mod("bot_profiles", _default_bot_profiles, host=h)
    cfg = h._current_bot_cfg()
    me = h._current_bot_handle()
    role = h._current_bot_role()
    return bp.get_bot_profile_bundle(
        me,
        role=role,
        specialty=str(cfg.get("specialty") or ""),
        catalog_dirs=[os.path.join(h.WORKDIR, ".agents", "skills")],
    )


def _studio_ipc_update_bot_profile(req):
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    bp = _mod("bot_profiles", _default_bot_profiles, host=h)
    allowed_fields = {
        "user_id",
        "actor_username",
        "expected_rev",
        "doc",
        "content",
        "docs",
        "skills_policy",
        "specialty",
    }
    extra = set(req.keys()) - allowed_fields
    if extra:
        return 400, {"ok": False, "error": f"存在未允许的 Profile 字段: {sorted(extra)[0]}"}

    me = h._current_bot_handle()
    role = h._current_bot_role()
    actor = str(req.get("actor_username") or f"uid:{req.get('user_id', '')}")[:64]
    sc, res = bp.update_bot_profile(
        me,
        expected_rev=req.get("expected_rev"),
        doc=req.get("doc"),
        content=req.get("content"),
        docs=req.get("docs"),
        skills_policy=req.get("skills_policy"),
        specialty=req.get("specialty"),
        updated_by=actor,
        role=role,
        catalog_dirs=[os.path.join(h.WORKDIR, ".agents", "skills")],
    )
    if sc == 200 and res.get("ok"):
        if "specialty" in req and isinstance(res.get("specialty"), str):
            try:
                bb.update_bot_config(me, specialty=res["specialty"])
            except Exception:
                pass
        h.invalidate_session("studio_bot_profile")
        h._publish_bot_heartbeat()
    return sc, res


def _studio_ipc_get_bot_skill(slug):
    h = _h()
    bp = _mod("bot_profiles", _default_bot_profiles, host=h)
    return bp.get_bot_skill(
        h._current_bot_handle(),
        slug,
        role=h._current_bot_role(),
    )


def _studio_ipc_put_bot_skill(req):
    h = _h()
    bp = _mod("bot_profiles", _default_bot_profiles, host=h)
    allowed_fields = {"user_id", "actor_username", "slug", "content", "expected_rev"}
    extra = set(req.keys()) - allowed_fields
    if extra:
        return 400, {"ok": False, "error": f"存在未允许的 Skill 字段: {sorted(extra)[0]}"}
    me = h._current_bot_handle()
    role = h._current_bot_role()
    actor = str(req.get("actor_username") or f"uid:{req.get('user_id', '')}")[:64]
    sc, res = bp.put_bot_skill(
        me,
        str(req.get("slug") or ""),
        content=req.get("content"),
        expected_rev=req.get("expected_rev"),
        updated_by=actor,
        role=role,
    )
    if sc == 200 and res.get("ok"):
        h.invalidate_session("studio_bot_skill")
        h._publish_bot_heartbeat()
    return sc, res


def _studio_ipc_delete_bot_skill(req):
    h = _h()
    bp = _mod("bot_profiles", _default_bot_profiles, host=h)
    allowed_fields = {"user_id", "actor_username", "slug", "expected_rev"}
    extra = set(req.keys()) - allowed_fields
    if extra:
        return 400, {"ok": False, "error": f"存在未允许的删除字段: {sorted(extra)[0]}"}
    me = h._current_bot_handle()
    role = h._current_bot_role()
    actor = str(req.get("actor_username") or f"uid:{req.get('user_id', '')}")[:64]
    sc, res = bp.delete_bot_skill(
        me,
        str(req.get("slug") or ""),
        expected_rev=req.get("expected_rev"),
        updated_by=actor,
        role=role,
    )
    if sc == 200 and res.get("ok"):
        h.invalidate_session("studio_bot_skill")
        h._publish_bot_heartbeat()
    return sc, res


# ---------------------------------------------------------------- Hot Reload, Accounts, Attention, Rooms & TG Mirror
def _schedule_ipc_hot_reload(delay_sec=0.25):
    """Trigger graceful hot reload via Bridge's own fixed `RELOAD_TRIGGER` & `job_q` after `delay_sec`."""
    h = _h()

    def _emit():
        try:
            with open(h.RELOAD_TRIGGER, "w", encoding="utf-8") as fh:
                fh.write(f"studio-ipc {int(time.time())}\n")
        except OSError as exc:
            h.log("Failed to touch RELOAD_TRIGGER: %r" % exc)
        try:
            h.job_q.put((0, None, h.PRIMARY_SCOPE_KEY, "__RELOAD__"))
        except Exception as exc:
            h.log("Failed to enqueue __RELOAD__: %r" % exc)

    t = threading.Timer(max(0.05, float(delay_sec)), _emit)
    t.daemon = True
    t.name = "studio-ipc-reload"
    t.start()
    return t


def _recycle_warm_sessions_for_account_switch(reason="account_switch", account_id=None):
    """Recycle idle warm `AgentSession` processes and mark any running session dirty (never force-killing active turns)."""
    h = _h()
    to_close = []
    recycled_idle = 0
    deferred_running = 0
    with h.session_lock:
        for sk in list(h._session_pool.keys()):
            if h.turn_running and h.turn_running_scope == sk:
                h.session_dirty_scopes.add(sk)
                deferred_running += 1
                h.log("Marked running session dirty for account switch (%s · scope=%s)" % (reason, sk))
            else:
                sess = h._session_pool.pop(sk, None)
                h.session_dirty_scopes.discard(sk)
                if sess is not None:
                    to_close.append(sess)
                    recycled_idle += 1
                    h.log("Recycling idle warm session for account switch (%s · scope=%s)" % (reason, sk))
        dirty_count = len(h.session_dirty_scopes)
    for sess in to_close:
        h.close_session_async(sess, force=False)
    return {
        "recycled_idle": recycled_idle,
        "deferred_running": deferred_running,
        "dirty_scopes_count": dirty_count,
        "account_id": str(account_id or ""),
    }


def _studio_ipc_recycle_accounts(req):
    """Handle `POST /ipc/accounts/recycle`: recycle idle warm sessions without killing in-flight turns."""
    h = _h()
    aid = req.get("account_id")
    reason = str(req.get("reason") or "account_switch").strip() or "account_switch"
    recycle_fn = getattr(h, "_recycle_warm_sessions_for_account_switch", _recycle_warm_sessions_for_account_switch)
    stats = recycle_fn(reason=f"ipc:{reason}", account_id=aid)
    return 200, {
        "ok": True,
        "bot": h._current_bot_handle(),
        **stats,
    }


def _studio_ipc_reload_bot(user_id):
    """Run synchronous `_pre_reload_self_check()` and schedule zero-downtime reload if healthy."""
    h = _h()
    ok_chk, detail = h._pre_reload_self_check()
    if not ok_chk:
        return 422, {
            "ok": False,
            "code": "self_check_failed",
            "error": f"热重载前置自检失败，已中止重启: {_redact_ipc_text(detail, max_len=240)}",
        }
    sched_fn = getattr(h, "_schedule_ipc_hot_reload", _schedule_ipc_hot_reload)
    sched_fn(delay_sec=0.25)
    return 202, {
        "ok": True,
        "bot": h._current_bot_handle(),
        "scheduled": True,
        "self_check": "passed",
        "delay_ms": 250,
    }


def _studio_ipc_attention_notify(req):
    """Record a Studio Attention Queue approval/rejection receipt (no TG delivery, no chat_sync)."""
    h = _h()
    rec = {
        "ts": round(time.time(), 3),
        "item_id": _sanitize_ipc_slug(req.get("item_id") or "", max_len=64),
        "kind": _sanitize_ipc_slug(req.get("kind") or "action", max_len=32),
        "decision": _sanitize_ipc_slug(req.get("decision") or "", max_len=16),
        "user_id": int(req.get("user_id") or 0),
        "actor_username": _sanitize_ipc_slug(req.get("actor_username") or "", max_len=64),
    }
    receipts = getattr(h, "_studio_attention_receipts", _studio_attention_receipts)
    receipts.append(rec)
    h.log(
        "Studio attention notify: item=%s kind=%s decision=%s"
        % (rec["item_id"], rec["kind"], rec["decision"])
    )
    return 200, {
        "ok": True,
        "accepted": True,
        "bot": h._current_bot_handle(),
        "item_id": rec["item_id"],
        "decision": rec["decision"],
    }


def _resolve_studio_mirror_target():
    """Resolve server-side Telegram mirror `(chat_id, thread_id)` from env or `team_config.json`."""
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    raw_env = os.environ.get("AGY_STUDIO_MIRROR_CHAT_ID", "").strip()
    if raw_env:
        if raw_env.lower() in ("0", "off", "false", "none", "disabled"):
            return 0, None
        try:
            env_cid = int(raw_env)
        except ValueError:
            return 0, None
        if env_cid >= 0:
            return 0, None
        raw_tid = os.environ.get("AGY_STUDIO_MIRROR_THREAD_ID", "").strip()
        return env_cid, h._normalize_thread_id(raw_tid) if raw_tid else None

    tm = bb.get_team_mirror()
    cid = int(tm.get("chat_id") or 0)
    if cid >= 0:
        return 0, None
    return cid, h._normalize_thread_id(tm.get("thread_id"))


def _studio_ipc_tg_group_send(req):
    """Mirror an authenticated Web admin message into the whitelisted TG group & enqueue real group turn."""
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    sipc = _mod("studio_ipc", _default_studio_ipc, host=h)
    resolve_mirror_fn = getattr(h, "_resolve_studio_mirror_target", _resolve_studio_mirror_target)
    mirror_chat_id, mirror_thread_id = resolve_mirror_fn()
    if not mirror_chat_id or int(mirror_chat_id) >= 0:
        return 400, {"ok": False, "error": "服务端未配置有效的 TG 镜像工作群"}
    if int(mirror_chat_id) not in h.ALLOWED or not h._is_authorized(int(mirror_chat_id)):
        return 403, {"ok": False, "error": "TG 镜像工作群不在当前 Bot 的白名单内"}

    uid = int(req["user_id"])
    priority = str(req.get("priority") or "normal").strip().lower()
    if priority not in ("normal", "urgent"):
        priority = "normal"
    interrupt_current = req.get("interrupt_current") is True
    safe_content = sipc.neutralize_control_tags(req.get("content") or "").strip()
    if not safe_content:
        return 400, {"ok": False, "error": "消息正文不能为空"}
    if len(safe_content.encode("utf-8")) > sipc.MAX_TG_GROUP_CONTENT_BYTES:
        return 413, {"ok": False, "error": "消息正文超过 16 KiB 上限"}

    raw_actor = re.sub(r"[\x00-\x1f\x7f\r\n]+", " ", str(req.get("actor_username") or "")).strip()
    actor = sipc.neutralize_control_tags(raw_actor)[:48] or f"uid:{uid}"

    project = req.get("project")
    override_project = None
    override_workdir = None
    if project:
        proj_clean = str(project).strip()
        for p in h.list_agy_projects():
            if p.get("id") == proj_clean or p.get("name") == proj_clean:
                override_project = p.get("id")
                override_workdir = p.get("workdir")
                break
        if override_project is None:
            return 400, {"ok": False, "error": "项目不在服务端白名单内"}

    mirror_to_tg = bool(req.get("mirror_human_to_tg", True))
    sent_mid = int(req.get("origin_msg_id") or 0)
    recorded_entry = None
    chain_id = ""

    if mirror_to_tg:
        sep = "\n" if "\n" in safe_content else " "
        tg_text = f"💬 [Web · {actor}]{sep}{safe_content}"
        sent_mid_raw = h.send(
            int(mirror_chat_id),
            tg_text,
            thread_id=mirror_thread_id,
            disable_web_page_preview=True,
        )
        sent_mid = int(sent_mid_raw or 0)
        if sent_mid <= 0:
            return 502, {"ok": False, "error": "向 Telegram 工作群发送镜像消息失败"}
        recorded_entry = bb.record_group_message(
            int(mirror_chat_id),
            msg_id=sent_mid,
            thread_id=mirror_thread_id,
            sender_handle=actor,
            sender_role="human",
            is_bot=False,
            text=safe_content,
            source="web",
        )
        chain_id = bb.mark_human_group_activity(
            int(mirror_chat_id),
            thread_id=mirror_thread_id,
            msg_id=sent_mid,
        ) or ""

    skey = h.scope_key_for(int(mirror_chat_id), mirror_thread_id)
    item_payload = (
        "__CHAT_TURN__",
        {
            "prompt": safe_content,
            "origin_msg_id": int(sent_mid or 0),
            "mention_hop": 0,
            "chain_id": str(chain_id or ""),
            "user_role": "admin",
            "user_id": uid,
            "override_project": override_project,
            "override_workdir": override_workdir,
        },
    )
    interrupted_current = False
    if interrupt_current:
        new_qid, marked_dispatched = h.job_q.put_front_and_mark_dispatched_preempt(
            (int(mirror_chat_id), mirror_thread_id, skey, item_payload),
            skey,
        )
        preempted_active, _other_scope_busy, to_kill, _preempted_gen = h._preempt_active_turn_for_scope(
            skey,
            exclude_qid=new_qid,
        )
        if to_kill is not None:
            h.close_session_async(to_kill, force=True)
        interrupted_current = bool(preempted_active or marked_dispatched > 0)
    elif priority == "urgent":
        h.job_q.put_front((int(mirror_chat_id), mirror_thread_id, skey, item_payload))
    else:
        h.job_q.put((int(mirror_chat_id), mirror_thread_id, skey, item_payload))

    entry_payload = None
    seq_val = 0
    if isinstance(recorded_entry, dict):
        seq_val = int(recorded_entry.get("seq") or 0)
        entry_payload = {
            "seq": seq_val,
            "ts": float(recorded_entry.get("ts") or time.time()),
            "sender_handle": str(recorded_entry.get("sender_handle") or actor),
            "sender_role": str(recorded_entry.get("sender_role") or "human"),
            "is_bot": False,
            "full_text": str(recorded_entry.get("full_text") or safe_content),
            "text_excerpt": str(recorded_entry.get("text_excerpt") or ""),
            "truncated": bool(recorded_entry.get("truncated", False)),
            "source": str(recorded_entry.get("source") or "web"),
        }
    return 202, {
        "ok": True,
        "queued": True,
        "bot": h._current_bot_handle(),
        "mirrored_to_tg": bool(mirror_to_tg),
        "origin_msg_id": int(sent_mid or 0),
        "seq": seq_val,
        "entry": entry_payload,
        "priority": priority,
        "interrupted_current": interrupted_current,
    }


def _studio_ipc_room_turn(req):
    """Execute a single isolated Web Room turn in `scope_key = room:<room_id>` (zero TG/chat_sync)."""
    h = _h()
    sipc = _mod("studio_ipc", _default_studio_ipc, host=h)
    room_id = str(req.get("room_id") or "").strip().lower()
    if not sipc.is_valid_room_id(room_id):
        return 400, {"ok": False, "error": "非法的 room_id 格式"}
    priority = str(req.get("priority") or "normal").strip().lower()
    if priority not in ("normal", "urgent"):
        priority = "normal"
    interrupt_current = req.get("interrupt_current") is True
    turn_id = f"room-{uuid.uuid4().hex[:16]}"
    scope_key = f"room:{room_id}"
    done_ev = threading.Event()
    result_box = {"status": "error", "reply": "", "error": ""}
    room_req = {
        "turn_id": turn_id,
        "user_id": int(req["user_id"]),
        "actor_username": str(req.get("actor_username") or ""),
        "room_id": room_id,
        "scope_key": scope_key,
        "prompt": str(req["prompt"]),
        "chain_id": str(req.get("chain_id") or ""),
        "hop": int(req.get("hop") or 0),
        "project": req.get("project"),
        "done_ev": done_ev,
        "result_box": result_box,
    }
    interrupted_current = False
    if interrupt_current:
        new_qid, marked_dispatched = h.job_q.put_front_and_mark_dispatched_preempt(
            (0, None, scope_key, ("__ROOM_TURN__", room_req)),
            scope_key,
        )
        preempted_active, _other_scope_busy, to_kill, _preempted_gen = h._preempt_active_turn_for_scope(
            scope_key,
            exclude_qid=new_qid,
        )
        if to_kill is not None:
            h.close_session_async(to_kill, force=True)
        interrupted_current = bool(preempted_active or marked_dispatched > 0)
    elif priority == "urgent":
        h.job_q.put_front((0, None, scope_key, ("__ROOM_TURN__", room_req)))
    else:
        h.job_q.put((0, None, scope_key, ("__ROOM_TURN__", room_req)))
    if not done_ev.wait(timeout=120.0):
        return 504, {"ok": False, "error": "群聊室 Bot 回复超时", "bot": h._current_bot_handle()}
    if result_box.get("status") != "done":
        return 500, {
            "ok": False,
            "bot": h._current_bot_handle(),
            "room_id": room_id,
            "error": _redact_ipc_text(result_box.get("error") or "room turn failed", max_len=240),
        }
    return 200, {
        "ok": True,
        "bot": h._current_bot_handle(),
        "room_id": room_id,
        "turn_id": turn_id,
        "status": "done",
        "reply": str(result_box.get("reply") or ""),
        "interrupted_current": interrupted_current,
    }


def _execute_room_turn(room_req, *, claimed_turn_gen=None, claimed_qid=None):
    h = _h()
    turn_id = room_req["turn_id"]
    uid = int(room_req["user_id"])
    scope_key = room_req["scope_key"]
    project = room_req.get("project")
    done_ev = room_req["done_ev"]
    result_box = room_req["result_box"]

    override_workdir = None
    if project:
        for p in h.list_agy_projects():
            if p.get("id") == project or p.get("name") == project:
                override_workdir = p.get("workdir")
                project = p.get("id")
                break

    deltas = []
    final_resp = {"text": "", "status": "done", "error": ""}

    def _room_sink(ev_type, payload):
        data = payload if isinstance(payload, dict) else {}
        if ev_type == "text_delta":
            d = data.get("delta")
            if isinstance(d, str) and d:
                deltas.append(d)
        elif ev_type == "done":
            resp = data.get("response")
            if isinstance(resp, str) and resp:
                final_resp["text"] = resp
            final_resp["status"] = "done"
        elif ev_type in ("error", "aborted"):
            final_resp["status"] = ev_type
            final_resp["error"] = str(data.get("error") or ev_type)

    try:
        h.run_agy(
            0,
            room_req["prompt"],
            thread_id=None,
            scope_key=scope_key,
            user_role="admin",
            user_id=uid,
            event_sink=_room_sink,
            web_turn_id=turn_id,
            override_project=project,
            override_workdir=override_workdir,
            sync_tg=False,
            claimed_turn_gen=claimed_turn_gen,
            claimed_qid=claimed_qid,
        )
        reply_text = "".join(deltas).strip() or final_resp["text"].strip()
        result_box["status"] = final_resp["status"]
        result_box["reply"] = reply_text
        result_box["error"] = final_resp["error"]
    except Exception as exc:
        h.log("room turn %s failed: %r" % (turn_id, exc))
        result_box["status"] = "error"
        result_box["error"] = f"bridge room execution error: {type(exc).__name__}"
    finally:
        done_ev.set()


def _execute_web_turn(web_req, *, claimed_turn_gen=None, claimed_qid=None):
    h = _h()
    turn_id = web_req["turn_id"]
    uid = int(web_req["user_id"])
    scope_key = web_req["scope_key"]
    project = web_req.get("project")
    override_workdir = None
    if project:
        for p in h.list_agy_projects():
            if p.get("id") == project or p.get("name") == project:
                override_workdir = p.get("workdir")
                project = p.get("id")
                break
    wt_info = web_req.get("worktree_info")
    if isinstance(wt_info, dict) and wt_info.get("active") and wt_info.get("path"):
        wt_p = str(wt_info["path"])
        if os.path.isdir(wt_p) and not os.path.islink(wt_p):
            override_workdir = os.path.realpath(wt_p)

    def _sink(ev_type, payload):
        h._studio_ipc_buffer.append(turn_id, ev_type, payload)

    try:
        h.run_agy(
            0,
            web_req["prompt"],
            thread_id=None,
            scope_key=scope_key,
            user_role="admin",
            user_id=uid,
            event_sink=_sink,
            web_turn_id=turn_id,
            override_cid=web_req.get("cid"),
            override_model=web_req.get("model"),
            override_effort=web_req.get("effort"),
            override_project=project,
            override_workdir=override_workdir,
            override_worktree_info=wt_info,
            sync_tg=(web_req.get("sync_tg") is True),
            claimed_turn_gen=claimed_turn_gen,
            claimed_qid=claimed_qid,
        )
    except Exception as exc:
        h.log("web turn %s failed: %r" % (turn_id, exc))
        h._studio_ipc_buffer.append(
            turn_id,
            "error",
            {"conversation_id": web_req.get("cid"), "error": f"bridge execution error: {type(exc).__name__}", "status": "ERROR"},
        )
    finally:
        info = h._studio_ipc_buffer.get_turn_info(turn_id)
        if info is not None and not info.get("finished"):
            h._studio_ipc_buffer.append(
                turn_id,
                "error",
                {"conversation_id": info.get("cid"), "error": "turn ended unexpectedly", "status": "ERROR"},
            )


def _start_studio_ipc():
    h = _h()
    bb = _mod("bot_bus", _default_bot_bus, host=h)
    sipc = _mod("studio_ipc", _default_studio_ipc, host=h)
    if os.environ.get("AGY_STUDIO_IPC_DISABLE", "").strip() == "1":
        return None
    existing = getattr(h, "_studio_ipc_server", None)
    if existing is not None:
        return existing
    try:
        srv = sipc.StudioIPCServer(
            bus_dir=bb.BUS_DIR,
            bot_handle=h._current_bot_handle(),
            resolve_role_fn=getattr(h, "_studio_ipc_resolve_role", _studio_ipc_resolve_role),
            get_meta_fn=getattr(h, "_studio_ipc_get_meta", _studio_ipc_get_meta),
            enqueue_turn_fn=getattr(h, "_studio_ipc_enqueue_turn", _studio_ipc_enqueue_turn),
            abort_turn_fn=getattr(h, "_studio_ipc_abort_turn", _studio_ipc_abort_turn),
            cancel_job_fn=getattr(h, "_studio_ipc_cancel_job", _studio_ipc_cancel_job),
            run_schedule_fn=getattr(h, "_studio_ipc_run_schedule", _studio_ipc_run_schedule),
            list_undo_fn=getattr(h, "_studio_ipc_list_undo", _studio_ipc_list_undo),
            diff_undo_fn=getattr(h, "_studio_ipc_get_undo_diff", _studio_ipc_get_undo_diff),
            apply_undo_fn=getattr(h, "_studio_ipc_apply_undo", _studio_ipc_apply_undo),
            apply_redo_fn=getattr(h, "_studio_ipc_apply_redo", _studio_ipc_apply_redo),
            cleanup_worktree_fn=getattr(h, "_studio_ipc_cleanup_worktree", _studio_ipc_cleanup_worktree),
            get_bot_config_fn=getattr(h, "_studio_ipc_get_bot_config", _studio_ipc_get_bot_config),
            update_bot_config_fn=getattr(h, "_studio_ipc_update_bot_config", _studio_ipc_update_bot_config),
            reload_bot_fn=getattr(h, "_studio_ipc_reload_bot", _studio_ipc_reload_bot),
            get_bot_profile_fn=getattr(h, "_studio_ipc_get_bot_profile", _studio_ipc_get_bot_profile),
            update_bot_profile_fn=getattr(h, "_studio_ipc_update_bot_profile", _studio_ipc_update_bot_profile),
            get_bot_skill_fn=getattr(h, "_studio_ipc_get_bot_skill", _studio_ipc_get_bot_skill),
            put_bot_skill_fn=getattr(h, "_studio_ipc_put_bot_skill", _studio_ipc_put_bot_skill),
            delete_bot_skill_fn=getattr(h, "_studio_ipc_delete_bot_skill", _studio_ipc_delete_bot_skill),
            room_turn_fn=getattr(h, "_studio_ipc_room_turn", _studio_ipc_room_turn),
            attention_notify_fn=getattr(h, "_studio_ipc_attention_notify", _studio_ipc_attention_notify),
            tg_group_send_fn=getattr(h, "_studio_ipc_tg_group_send", _studio_ipc_tg_group_send),
            recycle_accounts_fn=getattr(h, "_studio_ipc_recycle_accounts", _studio_ipc_recycle_accounts),
            buffer=h._studio_ipc_buffer,
            summaries_db=h.SUMMARIES_DB,
            meta_file=h.META_FILE,
        )
        srv.start()
        h._studio_ipc_server = srv
        h.log("Studio IPC server listening on %s" % srv.sock_path)
        return srv
    except Exception as e:
        h.log("Failed to start Studio IPC server: %r" % e)
        return None


def _stop_studio_ipc():
    h = _h()
    srv = getattr(h, "_studio_ipc_server", None)
    h._studio_ipc_server = None
    if srv is not None:
        try:
            srv.stop()
        except Exception as e:
            h.log("Error stopping Studio IPC server: %r" % e)
