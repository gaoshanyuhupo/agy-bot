#!/usr/bin/env python3
"""Stdio MCP server exposing `acb-team` Coordinator Bus tools for agy-cli-bot.

Role-gated via `AGY_BOT_BUS_ENABLE` and `AGY_BOT_BUS_ROLE`:
- `coordinator` / `peer` (`AGY_BOT_BUS_ENABLE=1`, `AGY_BOT_BUS_ROLE=coordinator|peer`):
  full orchestration tools (`team_roster`, `team_dispatch`, `team_job`, `team_broadcast`, `group_say`).
- `worker` (`AGY_BOT_BUS_ENABLE=1`, `AGY_BOT_BUS_ROLE=worker`):
  strictly minimal group collaboration tools (`team_roster` read-only, `group_say` restricted);
  delegation/job-control tools (`team_dispatch`, `team_job`, `team_broadcast`) are omitted and denied.
- All other contexts (`AGY_BOT_BUS_ENABLE!=1`, terminal CLI, scheduled tasks, `agy-llm-shim`):
  `tools/list` returns `[]` so zero schema tokens leak.
"""

from __future__ import annotations

import json
import os
import queue
import signal
import sys
import threading
from typing import Any, Dict, FrozenSet, List

try:
    import bot_bus
    import federation_registry
    import memory_guard
except ImportError:
    _THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    if _THIS_DIR not in sys.path:
        sys.path.insert(0, _THIS_DIR)
    import bot_bus
    import federation_registry
    import memory_guard

_STDOUT_LOCK = threading.Lock()
_STDIN_EOF = threading.Event()
_REQ_QUEUE: "queue.Queue[Dict[str, Any]]" = queue.Queue()

COORDINATOR_INSTRUCTIONS = (
    "You have `acb-team` multi-bot delegation tools on the local Coordinator Bus.\n"
    "- Act strictly as the orchestrator (`coordinator`): break down requests, delegate execution to specialists, monitor progress, and synthesize clear reports.\n"
    "- Keep yourself free to accept new user instructions at any time: DO NOT perform lengthy coding, full test runs, deployments, or releases inline when a specialist worker is available — delegate promptly and end your turn concisely.\n"
    "- Inspect live teammate bots (`role`, `specialty`, `default_model`, `online`, `busy`) with `team_roster` and route by specialty:\n"
    "  * Developer worker: code implementation, refactoring, local deploy/sync, Git commits, tags, and releases.\n"
    "  * Tester worker: unit/security/regression verification, post-release checks, and collecting/summarizing post-release GitHub Issues, PRs, CI status, and external feedback.\n"
    "- `team_dispatch` defaults to `wait=false` (non-blocking async with automatic `batch_done` wake-up). Keep `wait=false` for normal dev, release, test, and collection tasks so you stay immediately idle for new user instructions; on `batch_done`, verify results and asynchronously chain the next stage (e.g., Dev -> Test/Feedback) or report to the user. Pass `wait=true` only for tiny <15s read-only checks.\n"
    "- Permission `mode` guidance: for trusted workers performing dev or read-only QA tasks that need `run_command` (e.g. `unittest`, `ruff`, `verify_gate.py`), omit `mode` or use `mode=\"auto\"`; reserve `mode=\"safe\"` strictly for restricted/untrusted tasks that do not require shell command execution (headless `mode=\"safe\"` omits `--dangerously-skip-permissions` and aborts if `run_command` requires interactive approval).\n"
    "- Keep workdirs/files partitioned, or pass `worktree: true` on `team_dispatch` when multiple workers need to edit the same Git repository concurrently in isolated worktrees/branches; after verification/merge, call `team_job(action=\"cleanup_worktree\", job_id=...)` to clean up.\n"
    "- Inspect, cancel, retry, or clean up worktrees for background worker jobs via `team_job`; send plain status notices via `team_broadcast`."
)


WORKER_INSTRUCTIONS = (
    "You have minimal group-chat collaboration tools on the local Coordinator Bus (`acb-team`).\n"
    "- You are operating as a specialist `worker` bot. You do NOT have delegation or job-management permissions (`team_dispatch`/`team_job` are disabled).\n"
    "- Use `team_roster` (read-only) when you need to inspect teammate `@handle`s and specialties.\n"
    "- Use `group_say` sparingly during long-running tasks to post concise progress milestones or ask a teammate/user a brief clarifying question directly in the active group chat.\n"
    "- Always return your full final deliverable in your normal turn response."
)

_COORDINATOR_TOOLS: FrozenSet[str] = frozenset(
    {"team_roster", "team_dispatch", "team_job", "team_broadcast", "group_say"}
)
_WORKER_TOOLS: FrozenSet[str] = frozenset({"team_roster", "group_say"})


_VALID_BUS_ROLES: FrozenSet[str] = frozenset({"coordinator", "peer", "worker"})


def _bus_enabled() -> bool:
    if os.environ.get("AGY_BOT_BUS_ENABLE", "").strip() != "1":
        return False
    if os.environ.get("AGY_RBAC_ROLE", "").strip().lower() == "readonly":
        return False
    if not _my_handle():
        return False
    return True


def _federation_auth_token() -> Any:
    raw = os.environ.get("AGY_FEDERATION_TOKEN", "").strip()
    return raw or None


def _bus_role() -> str:
    if not _bus_enabled():
        return "disabled"
    raw = os.environ.get("AGY_BOT_BUS_ROLE", "").strip().lower()
    if raw not in _VALID_BUS_ROLES:
        return "disabled"
    me = _my_handle()
    auth = federation_registry.resolve_actor_authority(
        me,
        bus_dir=bot_bus.BUS_DIR,
        auth_token=_federation_auth_token(),
        env=dict(os.environ),
    )
    if auth.get("federation_active") or auth.get("has_legacy_bots"):
        if not auth.get("authorized"):
            return "disabled"
        agent = auth.get("agent")
        if isinstance(agent, dict):
            if agent.get("kind") != "agy_local" and not auth.get("token_verified"):
                return "disabled"
            if str(agent.get("trust_level") or "").strip().lower() == "readonly_guest":
                return "disabled"
            if not auth.get("can_dispatch"):
                return "worker"
        if auth.get("is_coordinator_peer") or auth.get("is_legacy_coordinator") or auth.get("led_teams"):
            return "coordinator" if raw in ("coordinator", "peer") else raw
        if auth.get("is_legacy_peer"):
            return "peer" if raw in ("coordinator", "peer") else raw
        return "worker"
    return raw


def _allowed_tool_names() -> FrozenSet[str]:
    role = _bus_role()
    if role in ("coordinator", "peer"):
        return _COORDINATOR_TOOLS
    if role == "worker":
        return _WORKER_TOOLS
    return frozenset()


def _my_handle() -> str:
    return bot_bus.normalize_handle(os.environ.get("AGY_BOT_HANDLE", ""))


def _origin_context() -> Dict[str, Any]:
    scope_key = os.environ.get("AGY_BOT_SCOPE_KEY", "").strip()
    raw_tid = os.environ.get("AGY_BOT_THREAD_ID", "").strip()
    thread_id = int(raw_tid) if raw_tid.lstrip("-").isdigit() else None
    raw_chat = os.environ.get("AGY_BOT_CHAT_ID", "").strip()
    chat_id = int(raw_chat) if raw_chat.lstrip("-").isdigit() else 0
    raw_mid = os.environ.get("AGY_BOT_ORIGIN_MSG_ID", "").strip()
    origin_msg_id = int(raw_mid) if raw_mid.isdigit() else 0
    raw_hop = os.environ.get("AGY_BOT_MENTION_HOP", "").strip()
    mention_hop = int(raw_hop) if raw_hop.isdigit() else 0
    chain_id = os.environ.get("AGY_BOT_CHAIN_ID", "").strip()
    raw_chain = os.environ.get("AGY_BOT_CHAIN", "").strip()
    chain = [bot_bus.normalize_handle(x) for x in raw_chain.split(",") if bot_bus.normalize_handle(x)]

    # Warm AgySession processes inherit spawn-time env vars; read latest origin context live from bus if available.
    me = _my_handle()
    if scope_key:
        live_ctx = bot_bus.get_origin_context(scope_key, bot_handle=me)
        if live_ctx:
            if int(live_ctx.get("chat_id") or 0):
                chat_id = int(live_ctx["chat_id"])
            if live_ctx.get("thread_id") is not None or int(live_ctx.get("chat_id") or 0):
                thread_id = live_ctx.get("thread_id")
            if int(live_ctx.get("msg_id") or 0):
                origin_msg_id = int(live_ctx["msg_id"])
            if "mention_hop" in live_ctx and live_ctx.get("mention_hop") is not None:
                try:
                    mention_hop = max(0, int(live_ctx["mention_hop"]))
                except (TypeError, ValueError):
                    pass
            if "chain_id" in live_ctx and live_ctx.get("chain_id") is not None:
                chain_id = str(live_ctx.get("chain_id") or "")

    return {
        "origin_scope_key": scope_key,
        "origin_chat_id": chat_id,
        "origin_thread_id": thread_id,
        "origin_msg_id": origin_msg_id,
        "mention_hop": mention_hop,
        "chain_id": chain_id,
        "parent_chain": chain,
    }


def _send_json(payload: Dict[str, Any]) -> None:
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    with _STDOUT_LOCK:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def _reply_ok(req_id: Any, result: Any) -> None:
    _send_json({"jsonrpc": "2.0", "id": req_id, "result": result})


def _reply_err(req_id: Any, code: int, message: str) -> None:
    _send_json({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def _tool_text(payload: Any, *, is_error: bool = False) -> Dict[str, Any]:
    txt = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2)
    return {"content": [{"type": "text", "text": txt}], "isError": bool(is_error)}


def _tool_schemas() -> List[Dict[str, Any]]:
    allowed = _allowed_tool_names()
    if not allowed:
        return []
    all_tools = [
        {
            "name": "team_roster",
            "description": "List all registered sibling bots on the local Coordinator Bus with online status, role (coordinator/worker/peer), specialty, default model/workdir, and active queue depth.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "include_offline": {
                        "type": "boolean",
                        "description": "Include offline configured bots (default true).",
                    }
                },
            },
        },
        {
            "name": "team_dispatch",
            "description": (
                "Delegate a task to one bot or fan out parallel tasks to multiple bots (up to 8). "
                "Provide either `bot` + `prompt` for one target, or `assignments` array for parallel fan-out."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "bot": {
                        "type": "string",
                        "description": "Target bot handle (e.g. '@example_main_bot' or 'example_main_bot'), or comma-separated handles.",
                    },
                    "prompt": {
                        "type": "string",
                        "description": "Self-contained task brief when using single/shared `bot`.",
                    },
                    "assignments": {
                        "type": "array",
                        "description": "Parallel fan-out list (each item: {bot, prompt, label?, project?, workdir?, model?, effort?, mode?, thread_key?, worktree?}).",
                        "items": {
                            "type": "object",
                            "properties": {
                                "bot": {"type": "string"},
                                "prompt": {"type": "string"},
                                "label": {"type": "string"},
                                "project": {"type": "string"},
                                "workdir": {"type": "string"},
                                "model": {"type": "string"},
                                "effort": {"type": "string"},
                                "mode": {
                                    "type": "string",
                                    "description": "Optional permission mode (auto|safe). Omit or use 'auto' for trusted workers that run commands (e.g. unittest/ruff/verify_gate.py); use 'safe' only for restricted/untrusted tasks that do not need run_command.",
                                },
                                "thread_key": {"type": "string"},
                                "worktree": {"type": "boolean"},
                            },
                            "required": ["bot", "prompt"],
                        },
                    },
                    "label": {"type": "string", "description": "Short task title for tracking cards."},
                    "project": {"type": "string", "description": "Optional Antigravity project override."},
                    "workdir": {"type": "string", "description": "Optional workspace path override."},
                    "model": {"type": "string", "description": "Optional model slug override."},
                    "effort": {"type": "string", "description": "Optional effort override (low|medium|high|xhigh|max)."},
                    "mode": {
                        "type": "string",
                        "description": (
                            "Optional permission mode (auto|safe). For trusted workers running commands "
                            "(e.g. unittest/ruff/verify_gate.py) in read-only QA or dev tasks, omit `mode` "
                            "or use `mode=\"auto\"`; only use `mode=\"safe\"` for restricted/untrusted tasks "
                            "that do not require `run_command` (headless `mode=\"safe\"` omits "
                            "`--dangerously-skip-permissions` and aborts if a command awaits interactive approval)."
                        ),
                    },
                    "thread_key": {
                        "type": "string",
                        "description": "Optional persistent worker thread key to resume multi-turn state across dispatches.",
                    },
                    "worktree": {
                        "type": "boolean",
                        "description": "Create an isolated Git worktree (<repo>/.worktrees/<job_id>, branch agy-team/<job_id>) per worker so concurrent workers can edit the same repository safely without conflicts (default false).",
                    },
                    "wait": {
                        "type": "boolean",
                        "description": "Wait synchronously for completion (default false — async dispatch keeps the coordinator free for new user instructions and triggers `batch_done` automatically on settle). Set true only for quick <15s read-only checks.",
                    },
                    "timeout_sec": {
                        "type": "number",
                        "description": "Max seconds to wait when `wait=true` (default 600, max 1500).",
                    },
                    "notify_group": {
                        "type": "boolean",
                        "description": "Mirror worker progress/completion message to active group chat or configured team mirror (defaults to true when dispatched from a group chat).",
                    },
                },
            },
        },
        {
            "name": "team_job",
            "description": "Inspect, list, cancel, retry, or clean up worktrees for delegated Bot Bus jobs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list", "status", "cancel", "retry", "cleanup_worktree"],
                        "description": "Operation to perform.",
                    },
                    "job_id": {"type": "string", "description": "Job ID for status/cancel/retry/cleanup_worktree."},
                    "limit": {"type": "integer", "description": "Max jobs for action=list (default 10)."},
                    "reason": {"type": "string", "description": "Cancellation reason."},
                    "prompt_override": {"type": "string", "description": "Optional corrected brief for action=retry."},
                    "force": {
                        "type": "boolean",
                        "description": "For action=cleanup_worktree: force removal even if uncommitted changes or unmerged commits remain (default false).",
                    },
                },
                "required": ["action"],
            },
        },
        {
            "name": "team_broadcast",
            "description": "Post a plain status/notice message to Telegram via a bot account without triggering another LLM turn.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Markdown/text notice to post."},
                    "bot": {"type": "string", "description": "Sender bot handle (defaults to current bot)."},
                    "chat_id": {"type": "integer", "description": "Target Telegram chat_id (defaults to current chat or configured mirror)."},
                    "thread_id": {"type": "integer", "description": "Optional Telegram Topic message_thread_id."},
                },
                "required": ["message"],
            },
        },
        {
            "name": "group_say",
            "description": (
                "Post a brief conversational update or question directly into the active group chat as yourself "
                "(restricted to the bound group/topic; cannot dispatch jobs or spoof other bots)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Concise markdown/text message to post to the group."},
                    "reply_to_msg_id": {"type": "integer", "description": "Optional Telegram message_id to reply to."},
                },
                "required": ["message"],
            },
        },
    ]
    return [tool for tool in all_tools if tool["name"] in allowed]


def _is_global_coordinator_auth(auth: Dict[str, Any]) -> bool:
    return bool(auth.get("is_coordinator_peer") or auth.get("is_legacy_coordinator"))


def _filter_jobs_for_actor(jobs: List[Dict[str, Any]], auth: Dict[str, Any], me: str) -> List[Dict[str, Any]]:
    """Scope job listings strictly to allowed teams / teams led by `me` or jobs where `me` is sender/target (B1, M2-C4)."""
    if not auth.get("federation_active"):
        return jobs
    allowed_teams = set(auth.get("allowed_teams") or [])
    if _is_global_coordinator_auth(auth):
        if not allowed_teams:
            return jobs
        return [
            j
            for j in jobs
            if isinstance(j, dict) and str(j.get("team_id") or "").strip() in allowed_teams
        ]
    led_teams = set(auth.get("led_teams") or [])
    filtered: List[Dict[str, Any]] = []
    for j in jobs:
        if not isinstance(j, dict):
            continue
        j_team = str(j.get("team_id") or "").strip()
        if allowed_teams and j_team not in allowed_teams:
            continue
        if (j_team and j_team in led_teams) or j.get("from_bot") == me or j.get("target_bot") == me:
            filtered.append(j)
    return filtered


def _filter_teams_for_actor(teams: List[Dict[str, Any]], auth: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Scope team metadata strictly to allowed teams and teams led by or containing the actor (B1, M2-C4)."""
    if not auth.get("federation_active"):
        return teams
    allowed_cap_teams = set(auth.get("allowed_teams") or [])
    if _is_global_coordinator_auth(auth):
        if not allowed_cap_teams:
            return teams
        return [t for t in teams if isinstance(t, dict) and t.get("team_id") in allowed_cap_teams]
    scoped_teams = set(auth.get("led_teams") or []) | set(auth.get("member_teams") or [])
    if allowed_cap_teams:
        scoped_teams &= allowed_cap_teams
    return [t for t in teams if isinstance(t, dict) and t.get("team_id") in scoped_teams]


def _handle_team_roster(args: Dict[str, Any]) -> Dict[str, Any]:
    include_offline = bool(args.get("include_offline", True))
    me = _my_handle()
    fed_active = federation_registry.has_federation_state(bot_bus.BUS_DIR)
    auth: Dict[str, Any] = {"federation_active": fed_active}
    if fed_active:
        auth = federation_registry.authorize_team_action(
            me,
            "list",
            bus_dir=bot_bus.BUS_DIR,
            auth_token=_federation_auth_token(),
            env=dict(os.environ),
        )
    roster = bot_bus.list_roster(include_offline=include_offline)
    raw_jobs = bot_bus.list_jobs(
        limit=(bot_bus.JOB_RETENTION_LIMIT if (fed_active and not _is_global_coordinator_auth(auth)) else 6)
    )
    scoped_jobs = _filter_jobs_for_actor(raw_jobs, auth, me)[:6]
    recent = [bot_bus.summarize_job_brief(j) for j in scoped_jobs]
    payload: Dict[str, Any] = {
        "self_bot": f"@{me}" if me else "",
        "roster": roster,
        "recent_jobs": recent,
    }
    if fed_active:
        all_teams = federation_registry.list_teams(bus_dir=bot_bus.BUS_DIR)
        payload["teams"] = _filter_teams_for_actor(all_teams, auth)
    return _tool_text(payload)


def _session_security_env() -> Dict[str, Any]:
    env_team_id = os.environ.get("AGY_BOT_TEAM_ID", "").strip()
    env_trust_level = os.environ.get("AGY_TRUST_LEVEL", "").strip()
    env_agent_origin = os.environ.get("AGY_AGENT_ORIGIN", "").strip().lower()
    norm_env_trust = bot_bus._normalize_trust_level(env_trust_level) if env_trust_level else ""
    env_trust_is_ro = norm_env_trust == "readonly_guest"
    env_trust_is_non_local = (
        bool(norm_env_trust)
        and bot_bus.TRUST_ORDER.get(norm_env_trust, 0) < bot_bus.TRUST_ORDER["local_worker"]
    )
    env_origin_is_external = memory_guard.is_external_agent_origin(env_agent_origin)
    env_readonly = (
        os.environ.get("AGY_RBAC_ROLE", "").strip().lower() == "readonly"
        or env_trust_is_ro
    )
    env_untrusted = (
        os.environ.get("AGY_UNTRUSTED_SESSION", "").strip() == "1"
        or os.environ.get("AGY_MEMORY_READONLY", "").strip() == "1"
        or env_origin_is_external
        or env_readonly
        or env_trust_is_non_local
    )
    env_max_mode = os.environ.get("AGY_MAX_RUNTIME_MODE", "").strip().lower()
    if env_readonly:
        env_max_mode = "safe"
    return {
        "team_id": env_team_id,
        "trust_level": norm_env_trust or env_trust_level,
        "agent_origin": env_agent_origin,
        "untrusted": env_untrusted,
        "readonly": env_readonly,
        "external_origin": env_origin_is_external,
        "non_local_trust": env_trust_is_non_local,
        "max_runtime_mode": env_max_mode,
    }


def _assert_dispatch_allowed(
    sec: Dict[str, Any],
    *,
    action: str,
    require_orchestrator: bool = True,
) -> Dict[str, Any]:
    """Fail-closed hard block combining session taint guards and server-side authority verification (C3, C4).

    Never trusts forged process environment claims (`AGY_BOT_BUS_ROLE=coordinator`,
    `AGY_TRUST_LEVEL=local_admin`) when `federation_registry` / `team_config.json` do not grant authority.
    """
    me = _my_handle()
    auth_token = _federation_auth_token()
    auth = federation_registry.resolve_actor_authority(
        me,
        bus_dir=bot_bus.BUS_DIR,
        auth_token=auth_token,
        env=dict(os.environ),
    )

    # B2: Authoritative server-side trust_level clamping (blocks forged AGY_TRUST_LEVEL=local_admin).
    agent = auth.get("agent")
    reg_trust = ""
    if isinstance(agent, dict) and agent.get("trust_level"):
        reg_trust = bot_bus._normalize_trust_level(agent.get("trust_level"), default="remote_untrusted")
    sec_trust = str(sec.get("trust_level") or "").strip()
    if sec_trust and reg_trust:
        eff_trust = bot_bus._min_trust_level(sec_trust, reg_trust)
    else:
        eff_trust = reg_trust or sec_trust
    eff_readonly = bool(sec.get("readonly")) or (eff_trust == "readonly_guest") or (reg_trust == "readonly_guest")
    eff_untrusted = (
        bool(sec.get("untrusted"))
        or eff_readonly
        or (bool(eff_trust) and bot_bus.TRUST_ORDER.get(eff_trust, 0) <= bot_bus.TRUST_ORDER["remote_untrusted"])
    )

    if reg_trust in ("readonly_guest", "remote_untrusted") or eff_trust in ("readonly_guest", "remote_untrusted"):
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: server-side agent trust_level "
            f"(registered={reg_trust or 'none'!r}, effective={eff_trust or 'none'!r}) cannot perform {action}"
        )

    # An explicitly verified federated agent token with Owner-granted orchestration rights
    # is permitted only if not readonly/untrusted/tainted; otherwise untrusted/external env ALWAYS fails closed.
    token_authenticated_federated = (
        bool(auth.get("token_verified"))
        and bool(auth.get("authorized"))
        and not eff_readonly
        and os.environ.get("AGY_UNTRUSTED_SESSION", "").strip() != "1"
        and os.environ.get("AGY_MEMORY_READONLY", "").strip() != "1"
        and reg_trust not in ("readonly_guest", "remote_untrusted")
        and eff_trust not in ("readonly_guest", "remote_untrusted")
    )

    if not token_authenticated_federated:
        if (
            eff_readonly
            or sec.get("untrusted")
            or sec.get("external_origin")
            or sec.get("non_local_trust")
        ):
            reasons: List[str] = []
            if eff_readonly:
                reasons.append("readonly")
            if sec.get("external_origin"):
                reasons.append(f"external_origin={sec.get('agent_origin')!r}")
            if sec.get("non_local_trust"):
                reasons.append(f"non_local_trust={eff_trust or sec.get('trust_level')!r}")
            if not reasons:
                reasons.append("untrusted_session")
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: untrusted/external/non-local session cannot perform {action} ({', '.join(reasons)})"
            )

    # Server-side authoritative verification against federation_registry + team_config.json
    if auth.get("federation_active") or auth.get("has_legacy_bots"):
        if not auth.get("authorized"):
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: server-side authority rejected {me!r} for {action} ({auth.get('reason') or 'unauthorized'})"
            )
        if isinstance(agent, dict) and agent.get("kind") != "agy_local" and not auth.get("token_verified"):
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: external agent {me!r} requires valid verified federation token for {action}"
            )
        if require_orchestrator:
            if isinstance(agent, dict) and not auth.get("can_dispatch"):
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: agent {me!r} has capabilities.can_dispatch=False and cannot perform {action}"
                )
            has_orch_auth = bool(
                auth.get("is_coordinator_peer")
                or auth.get("is_legacy_coordinator")
                or auth.get("is_legacy_peer")
                or auth.get("led_teams")
            )
            if not has_orch_auth:
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: actor {me!r} lacks server-side coordinator/leader authority for {action} (forged env role ignored)"
                )
    auth = dict(auth)
    auth["effective_trust_level"] = eff_trust
    auth["effective_readonly"] = eff_readonly
    auth["effective_untrusted"] = eff_untrusted
    return auth


def _enforce_bound_dispatch_fields(
    entry: Dict[str, Any],
    *,
    env_team_id: str,
    env_agent_origin: str,
) -> None:
    raw_tid = str(entry.get("team_id") or "").strip()
    if env_team_id:
        if raw_tid and raw_tid != env_team_id:
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: team_id override rejected ({raw_tid!r} != {env_team_id!r})"
            )
        entry["team_id"] = env_team_id
    raw_origin = str(entry.get("agent_origin") or "").strip().lower()
    if memory_guard.is_external_agent_origin(env_agent_origin):
        if raw_origin and not memory_guard.is_external_agent_origin(raw_origin):
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: cannot override external agent_origin {env_agent_origin!r} with {raw_origin!r}"
            )
        entry["agent_origin"] = raw_origin or env_agent_origin


def _build_assignment_list(args: Dict[str, Any]) -> List[Dict[str, Any]]:
    env_team_id = os.environ.get("AGY_BOT_TEAM_ID", "").strip()
    env_agent_origin = os.environ.get("AGY_AGENT_ORIGIN", "").strip().lower()
    raw_items = args.get("assignments")
    shared_defaults = {
        k: args[k]
        for k in (
            "label",
            "project",
            "workdir",
            "model",
            "effort",
            "mode",
            "thread_key",
            "worktree",
            "worktree_strict",
            "retryable",
            "team_id",
            "trust_level",
            "agent_origin",
            "readonly",
            "untrusted",
            "max_runtime_mode",
        )
        if args.get(k) not in (None, "")
    }
    _enforce_bound_dispatch_fields(
        shared_defaults,
        env_team_id=env_team_id,
        env_agent_origin=env_agent_origin,
    )
    if isinstance(raw_items, list) and raw_items:
        out = []
        for item in raw_items:
            if not isinstance(item, dict):
                raise ValueError("Each entry in `assignments` must be an object")
            merged = dict(shared_defaults)
            merged.update({k: v for k, v in item.items() if v not in (None, "")})
            _enforce_bound_dispatch_fields(
                merged,
                env_team_id=env_team_id,
                env_agent_origin=env_agent_origin,
            )
            out.append(merged)
        return out

    bot_arg = str(args.get("bot") or "").strip()
    prompt = str(args.get("prompt") or "").strip()
    if not bot_arg or not prompt:
        raise ValueError("Provide either `assignments` list OR both `bot` and `prompt`.")

    targets = [t.strip() for t in bot_arg.split(",") if t.strip()]
    out = []
    for t in targets:
        entry = dict(shared_defaults)
        entry["bot"] = t
        entry["prompt"] = prompt
        _enforce_bound_dispatch_fields(
            entry,
            env_team_id=env_team_id,
            env_agent_origin=env_agent_origin,
        )
        out.append(entry)
    return out


def _handle_team_dispatch(args: Dict[str, Any]) -> Dict[str, Any]:
    me = _my_handle()
    if not me:
        return _tool_text("AGY_BOT_HANDLE missing in session environment.", is_error=True)

    sec = _session_security_env()
    auth = _assert_dispatch_allowed(sec, action="team_dispatch")
    env_team_id = sec["team_id"]
    eff_trust_level = auth.get("effective_trust_level") or sec["trust_level"]
    env_agent_origin = sec["agent_origin"]
    eff_untrusted = bool(auth.get("effective_untrusted", sec["untrusted"]))
    eff_readonly = bool(auth.get("effective_readonly", sec["readonly"]))

    req_team_id = str(args.get("team_id") or "").strip()
    if env_team_id and req_team_id and req_team_id != env_team_id:
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: team_id override rejected ({req_team_id!r} != {env_team_id!r})"
        )
    req_origin = str(args.get("agent_origin") or "").strip().lower()
    if memory_guard.is_external_agent_origin(env_agent_origin) and req_origin and not memory_guard.is_external_agent_origin(req_origin):
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: cannot override external agent_origin {env_agent_origin!r} with {req_origin!r}"
        )

    assignments = _build_assignment_list(args)
    wait = bool(args.get("wait", False))
    timeout_sec = max(10.0, min(1500.0, float(args.get("timeout_sec", 600) or 600)))
    origin = _origin_context()
    if "notify_group" in args and args.get("notify_group") is not None:
        notify_group = bool(args.get("notify_group"))
    else:
        notify_group = int(origin["origin_chat_id"] or 0) < 0

    eff_team_id = env_team_id or req_team_id
    eff_origin = (
        "local_bus"
        if (not req_origin and env_agent_origin in ("", "local_bus", "local_tg", "local_web", "local_tg_fast"))
        else (req_origin or env_agent_origin)
    )

    created = bot_bus.dispatch_assignments(
        me,
        assignments,
        origin_scope_key=origin["origin_scope_key"],
        origin_chat_id=origin["origin_chat_id"],
        origin_thread_id=origin["origin_thread_id"],
        origin_msg_id=origin["origin_msg_id"] or None,
        parent_chain=origin["parent_chain"],
        default_notify_group=notify_group,
        wake_on_async=not wait,
        team_id=eff_team_id,
        agent_origin=eff_origin,
        parent_trust_level=eff_trust_level,
        parent_agent_origin=env_agent_origin,
        parent_untrusted=eff_untrusted,
        parent_tainted=eff_untrusted,
        parent_readonly=eff_readonly,
        parent_max_runtime_mode=sec["max_runtime_mode"],
        batch_budget_usd=args.get("batch_budget_usd"),
        auth_token=_federation_auth_token(),
    )
    job_ids = [j["job_id"] for j in created["jobs"]]

    if not wait:
        return _tool_text({
            "mode": "async",
            "group_id": created["group_id"],
            "dispatched": [bot_bus.summarize_job_brief(j) for j in created["jobs"]],
            "note": "Dispatched asynchronously (default wait=false). Report this brief dispatch status and end your turn promptly so you remain free for new user instructions; `batch_done` will wake you once all jobs settle.",
        })

    settled, all_done = bot_bus.wait_for_jobs(
        job_ids,
        timeout_sec=timeout_sec,
        cancel_check=lambda: _STDIN_EOF.is_set(),
    )
    summaries = [bot_bus.summarize_job_brief(j) for j in settled]
    has_err = any(j.get("status") in ("error", "cancelled") for j in settled)
    return _tool_text(
        {
            "mode": "sync",
            "group_id": created["group_id"],
            "all_settled": all_done,
            "timed_out": (not all_done) and not _STDIN_EOF.is_set(),
            "results": summaries,
        },
        is_error=has_err and len(summaries) == 1,
    )


def _handle_team_job(args: Dict[str, Any]) -> Dict[str, Any]:
    action = str(args.get("action") or "").strip().lower()
    me = _my_handle()
    if action == "list":
        limit = max(1, min(30, int(args.get("limit", 10) or 10)))
        fed_active = federation_registry.has_federation_state(bot_bus.BUS_DIR)
        auth: Dict[str, Any] = {"federation_active": fed_active}
        if fed_active:
            auth = federation_registry.authorize_team_action(
                me,
                "list",
                bus_dir=bot_bus.BUS_DIR,
                auth_token=_federation_auth_token(),
                env=dict(os.environ),
            )
        raw_jobs = bot_bus.list_jobs(
            limit=(bot_bus.JOB_RETENTION_LIMIT if (fed_active and not _is_global_coordinator_auth(auth)) else limit)
        )
        scoped = _filter_jobs_for_actor(raw_jobs, auth, me)[:limit]
        jobs = [bot_bus.summarize_job_brief(j) for j in scoped]
        return _tool_text({"jobs": jobs})

    jid = str(args.get("job_id") or "").strip()
    if not jid:
        return _tool_text("`job_id` is required for this action.", is_error=True)

    if action == "status":
        job = bot_bus.get_job(jid, requester_bot=me, auth_token=_federation_auth_token())
        if not job:
            return _tool_text(f"Job not found: {jid}", is_error=True)
        return _tool_text(bot_bus.summarize_job_brief(job))

    if action == "cancel":
        sec = _session_security_env()
        _assert_dispatch_allowed(sec, action="team_job(cancel)")
        job = bot_bus.cancel_job(
            jid,
            requester_bot=me,
            reason=str(args.get("reason") or "cancelled_by_coordinator"),
            auth_token=_federation_auth_token(),
        )
        if not job:
            return _tool_text(f"Job not found: {jid}", is_error=True)
        return _tool_text({"cancelled": bot_bus.summarize_job_brief(job)})

    if action == "retry":
        sec = _session_security_env()
        auth = _assert_dispatch_allowed(sec, action="team_job(retry)")
        eff_trust = auth.get("effective_trust_level") or sec["trust_level"]
        eff_readonly = bool(auth.get("effective_readonly", sec["readonly"]))
        eff_untrusted = bool(auth.get("effective_untrusted", sec["untrusted"]))
        job = bot_bus.retry_job(
            jid,
            requester_bot=me,
            prompt_override=str(args.get("prompt_override") or ""),
            caller_team_id=sec["team_id"],
            caller_agent_origin=sec["agent_origin"],
            caller_trust_level=eff_trust,
            caller_readonly=eff_readonly,
            caller_untrusted=eff_untrusted,
            caller_tainted=eff_untrusted,
            caller_max_runtime_mode=sec["max_runtime_mode"],
            auth_token=_federation_auth_token(),
        )
        return _tool_text({"retried": bot_bus.summarize_job_brief(job)})

    if action == "cleanup_worktree":
        sec = _session_security_env()
        _assert_dispatch_allowed(sec, action="team_job(cleanup_worktree)")
        force = bool(args.get("force", False))
        res = bot_bus.cleanup_job_worktree(
            jid,
            force=force,
            requester_bot=me,
            auth_token=_federation_auth_token(),
        )
        return _tool_text(res, is_error=not bool(res.get("ok")))

    return _tool_text(f"Unknown action: {action}", is_error=True)


def _handle_team_broadcast(args: Dict[str, Any]) -> Dict[str, Any]:
    sec = _session_security_env()
    auth = _assert_dispatch_allowed(sec, action="team_broadcast")
    msg = str(args.get("message") or "").strip()
    if not msg:
        return _tool_text("`message` cannot be empty.", is_error=True)
    me = _my_handle()
    target_bot = str(args.get("bot") or me or "").strip()
    if not target_bot:
        return _tool_text("Target bot handle unavailable.", is_error=True)
    bot_bus._reject_unsafe_actor_id(target_bot, field="bot")
    norm_target = bot_bus.normalize_handle(target_bot)
    if auth.get("federation_active") and (not _is_global_coordinator_auth(auth) or auth.get("allowed_teams")):
        if norm_target != me:
            federation_registry.authorize_team_action(
                me,
                "broadcast",
                team_id=sec.get("team_id") or "",
                target_agent_id=norm_target,
                bus_dir=bot_bus.BUS_DIR,
                auth_token=_federation_auth_token(),
                env=dict(os.environ),
            )
    origin = _origin_context()
    chat_id = int(args.get("chat_id") or origin["origin_chat_id"] or 0)
    thread_id = args.get("thread_id")
    if thread_id is None:
        thread_id = origin["origin_thread_id"]
    if not chat_id:
        roster = {b["handle"]: b for b in bot_bus.list_roster()}
        binfo = roster.get(bot_bus.normalize_handle(target_bot)) or {}
        chat_id = int(binfo.get("mirror_chat_id") or 0)
        if binfo.get("mirror_thread_id") is not None:
            thread_id = binfo.get("mirror_thread_id")
    if not chat_id:
        return _tool_text("No target chat_id available for broadcast.", is_error=True)

    bot_bus.enqueue_broadcast(target_bot, chat_id, msg, thread_id=thread_id, from_bot=me)
    return _tool_text({"ok": True, "bot": f"@{bot_bus.normalize_handle(target_bot)}", "chat_id": chat_id, "thread_id": thread_id})


def _handle_group_say(args: Dict[str, Any]) -> Dict[str, Any]:
    sec = _session_security_env()
    _assert_dispatch_allowed(sec, action="group_say", require_orchestrator=False)
    msg = str(args.get("message") or "").strip()
    if not msg:
        return _tool_text("`message` cannot be empty.", is_error=True)
    me = _my_handle()
    if not me:
        return _tool_text("AGY_BOT_HANDLE missing in session environment.", is_error=True)

    origin = _origin_context()
    chat_id = int(origin["origin_chat_id"] or 0)
    thread_id = origin["origin_thread_id"]
    if not chat_id:
        bcfg = bot_bus.resolve_bot_config(me)
        chat_id = int(bcfg.get("mirror_chat_id") or 0)
        if chat_id and bcfg.get("mirror_thread_id") is not None:
            thread_id = bcfg.get("mirror_thread_id")
    if chat_id >= 0:
        return _tool_text("group_say requires an active group chat context (chat_id < 0).", is_error=True)

    raw_reply = args.get("reply_to_msg_id")
    reply_mid = int(raw_reply) if raw_reply is not None and str(raw_reply).isdigit() else None
    bot_bus.enqueue_group_say(
        me,
        chat_id,
        msg,
        thread_id=thread_id,
        reply_to_message_id=reply_mid,
        source_hop=origin.get("mention_hop", 0),
        chain_id=origin.get("chain_id", ""),
    )
    return _tool_text({"ok": True, "bot": f"@{me}", "chat_id": chat_id, "thread_id": thread_id})


_TOOL_DISPATCH = {
    "team_roster": _handle_team_roster,
    "team_dispatch": _handle_team_dispatch,
    "team_job": _handle_team_job,
    "team_broadcast": _handle_team_broadcast,
    "group_say": _handle_group_say,
}


def _handle_request(req: Dict[str, Any]) -> None:
    req_id = req.get("id")
    method = req.get("method") or ""
    params = req.get("params") or {}

    if method == "initialize":
        proto = params.get("protocolVersion") or "2024-11-05"
        res: Dict[str, Any] = {
            "protocolVersion": proto,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "acb-team", "version": "1.0.0"},
        }
        role = _bus_role()
        if role == "worker":
            res["instructions"] = WORKER_INSTRUCTIONS
        elif role in ("coordinator", "peer"):
            res["instructions"] = COORDINATOR_INSTRUCTIONS
        if req_id is not None:
            _reply_ok(req_id, res)
        return

    if method in ("notifications/initialized", "notifications/cancelled"):
        return

    if method == "ping":
        if req_id is not None:
            _reply_ok(req_id, {})
        return

    if method == "tools/list":
        if req_id is not None:
            _reply_ok(req_id, {"tools": _tool_schemas()})
        return

    if method == "tools/call":
        if req_id is None:
            return
        role = _bus_role()
        if not _bus_enabled() or role == "disabled":
            if os.environ.get("AGY_RBAC_ROLE", "").strip().lower() == "readonly":
                _reply_ok(
                    req_id,
                    _tool_text(
                        "PRIVILEGE_ESCALATION_DENIED: `acb-team` is disabled on readonly session.",
                        is_error=True,
                    ),
                )
            else:
                _reply_ok(
                    req_id,
                    _tool_text("`acb-team` is disabled on this session.", is_error=True),
                )
            return
        tname = params.get("name") or ""
        if tname not in _allowed_tool_names():
            _reply_ok(
                req_id,
                _tool_text(f"Tool `{tname}` is not permitted for role `{role}`.", is_error=True),
            )
            return
        args = params.get("arguments") or {}
        fn = _TOOL_DISPATCH.get(tname)
        if not fn:
            _reply_err(req_id, -32602, f"Unknown tool: {tname}")
            return
        try:
            res = fn(args)
        except Exception as exc:
            tok = _federation_auth_token()
            safe_exc = federation_registry.redact_secrets(str(exc), extra_secrets=([tok] if tok else ()))
            res = _tool_text(f"{tname} error: {safe_exc}", is_error=True)
        _reply_ok(req_id, res)
        return

    if req_id is not None:
        _reply_err(req_id, -32601, f"Method not found: {method}")


def _stdin_reader() -> None:
    try:
        for raw in sys.stdin:
            line = raw.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                if isinstance(msg, dict):
                    _REQ_QUEUE.put(msg)
            except Exception:
                continue
    except Exception:
        pass
    finally:
        _STDIN_EOF.set()
        _REQ_QUEUE.put(None)  # type: ignore[arg-type]


def main() -> int:
    def _on_sig(_signum, _frame):
        _STDIN_EOF.set()
        _REQ_QUEUE.put(None)  # type: ignore[arg-type]

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _on_sig)
        except Exception:
            pass

    t = threading.Thread(target=_stdin_reader, daemon=True)
    t.start()
    active_threads: List[threading.Thread] = []
    while True:
        req = _REQ_QUEUE.get()
        if req is None:
            break
        active_threads = [th for th in active_threads if th.is_alive()]
        method = req.get("method") or ""
        if method == "tools/call":
            # Execute tools/call on a worker thread so stdin reader / cancel / ping stay non-blocking
            ct = threading.Thread(target=_handle_request, args=(req,), daemon=True)
            active_threads.append(ct)
            ct.start()
        else:
            _handle_request(req)
    # Give in-flight wait_for_jobs threads a moment to observe _STDIN_EOF and cancel active worker jobs cleanly
    for th in active_threads:
        if th.is_alive():
            th.join(timeout=3.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
