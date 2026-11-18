#!/usr/bin/env python3
"""Stdio MCP server exposing `acb-team` coordinator tools for agy-cli-bot.

Enabled strictly when `AGY_BOT_BUS_ENABLE=1` (injected only into coordinator/peer
interactive bridge sessions). For all other sessions (`worker`, `agy-llm-shim`,
terminal CLI, disposable scheduled tasks), `tools/list` returns `[]` so zero schema
tokens or delegation tools leak into unintended contexts.
"""

from __future__ import annotations

import json
import os
import queue
import signal
import sys
import threading
from typing import Any, Dict, List

try:
    import bot_bus
except ImportError:
    _THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    if _THIS_DIR not in sys.path:
        sys.path.insert(0, _THIS_DIR)
    import bot_bus

_STDOUT_LOCK = threading.Lock()
_STDIN_EOF = threading.Event()
_REQ_QUEUE: "queue.Queue[Dict[str, Any]]" = queue.Queue()

COORDINATOR_INSTRUCTIONS = (
    "You have `acb-team` multi-bot delegation tools on the local Coordinator Bus.\n"
    "- Inspect live teammate bots (`role`, `specialty`, `default_model`, `online`, `busy`) with `team_roster` before delegating.\n"
    "- Delegate bounded or specialist tasks (browser/email/light ops/parallel research) via `team_dispatch` "
    "(single `bot`+`prompt` or parallel `assignments` fan-out up to 8 tasks). Use `wait=true` (default) to get settled results inline, "
    "or `wait=false` for background execution with automatic batch completion wake-up.\n"
    "- Keep workdirs/files partitioned so you and a worker never edit the exact same file concurrently.\n"
    "- Inspect, cancel, or retry failed worker jobs via `team_job`; send plain status notices via `team_broadcast`."
)


def _bus_enabled() -> bool:
    return os.environ.get("AGY_BOT_BUS_ENABLE", "").strip() == "1"


def _my_handle() -> str:
    return bot_bus.normalize_handle(os.environ.get("AGY_BOT_HANDLE", ""))


def _origin_context() -> Dict[str, Any]:
    raw_tid = os.environ.get("AGY_BOT_THREAD_ID", "").strip()
    thread_id = int(raw_tid) if raw_tid.lstrip("-").isdigit() else None
    raw_chat = os.environ.get("AGY_BOT_CHAT_ID", "").strip()
    chat_id = int(raw_chat) if raw_chat.lstrip("-").isdigit() else 0
    raw_chain = os.environ.get("AGY_BOT_CHAIN", "").strip()
    chain = [bot_bus.normalize_handle(x) for x in raw_chain.split(",") if bot_bus.normalize_handle(x)]
    return {
        "origin_scope_key": os.environ.get("AGY_BOT_SCOPE_KEY", "").strip(),
        "origin_chat_id": chat_id,
        "origin_thread_id": thread_id,
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
    if not _bus_enabled():
        return []
    return [
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
                        "description": "Parallel fan-out list (each item: {bot, prompt, label?, project?, workdir?, model?, effort?, mode?, thread_key?}).",
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
                                "mode": {"type": "string"},
                                "thread_key": {"type": "string"},
                            },
                            "required": ["bot", "prompt"],
                        },
                    },
                    "label": {"type": "string", "description": "Short task title for tracking cards."},
                    "project": {"type": "string", "description": "Optional Antigravity project override."},
                    "workdir": {"type": "string", "description": "Optional workspace path override."},
                    "model": {"type": "string", "description": "Optional model slug override."},
                    "effort": {"type": "string", "description": "Optional effort override (low|medium|high|xhigh|max)."},
                    "mode": {"type": "string", "description": "Optional permission mode (auto|safe)."},
                    "thread_key": {
                        "type": "string",
                        "description": "Optional persistent worker thread key to resume multi-turn state across dispatches.",
                    },
                    "wait": {
                        "type": "boolean",
                        "description": "Wait synchronously for completion and return full results (default true). Set false for async dispatch with completion wake-up.",
                    },
                    "timeout_sec": {
                        "type": "number",
                        "description": "Max seconds to wait when `wait=true` (default 600, max 1500).",
                    },
                    "notify_group": {
                        "type": "boolean",
                        "description": "Mirror worker progress/completion card to configured team mirror chat/Topic (default false).",
                    },
                },
            },
        },
        {
            "name": "team_job",
            "description": "Inspect, list, cancel, or retry delegated Bot Bus jobs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list", "status", "cancel", "retry"],
                        "description": "Operation to perform.",
                    },
                    "job_id": {"type": "string", "description": "Job ID for status/cancel/retry."},
                    "limit": {"type": "integer", "description": "Max jobs for action=list (default 10)."},
                    "reason": {"type": "string", "description": "Cancellation reason."},
                    "prompt_override": {"type": "string", "description": "Optional corrected brief for action=retry."},
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
    ]


def _handle_team_roster(args: Dict[str, Any]) -> Dict[str, Any]:
    include_offline = bool(args.get("include_offline", True))
    roster = bot_bus.list_roster(include_offline=include_offline)
    me = _my_handle()
    recent = [bot_bus.summarize_job_brief(j) for j in bot_bus.list_jobs(limit=6)]
    return _tool_text({
        "self_bot": f"@{me}" if me else "",
        "roster": roster,
        "recent_jobs": recent,
    })


def _build_assignment_list(args: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw_items = args.get("assignments")
    shared_defaults = {
        k: args[k]
        for k in ("label", "project", "workdir", "model", "effort", "mode", "thread_key")
        if args.get(k) not in (None, "")
    }
    if isinstance(raw_items, list) and raw_items:
        out = []
        for item in raw_items:
            if not isinstance(item, dict):
                raise ValueError("Each entry in `assignments` must be an object")
            merged = dict(shared_defaults)
            merged.update({k: v for k, v in item.items() if v not in (None, "")})
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
        out.append(entry)
    return out


def _handle_team_dispatch(args: Dict[str, Any]) -> Dict[str, Any]:
    me = _my_handle()
    if not me:
        return _tool_text("AGY_BOT_HANDLE missing in session environment.", is_error=True)

    assignments = _build_assignment_list(args)
    wait = bool(args.get("wait", True))
    timeout_sec = max(10.0, min(1500.0, float(args.get("timeout_sec", 600) or 600)))
    notify_group = bool(args.get("notify_group", False))
    origin = _origin_context()

    created = bot_bus.dispatch_assignments(
        me,
        assignments,
        origin_scope_key=origin["origin_scope_key"],
        origin_chat_id=origin["origin_chat_id"],
        origin_thread_id=origin["origin_thread_id"],
        parent_chain=origin["parent_chain"],
        default_notify_group=notify_group,
        wake_on_async=not wait,
    )
    job_ids = [j["job_id"] for j in created["jobs"]]

    if not wait:
        return _tool_text({
            "mode": "async",
            "group_id": created["group_id"],
            "dispatched": [bot_bus.summarize_job_brief(j) for j in created["jobs"]],
            "note": "Dispatched asynchronously. Batch completion will automatically notify this coordinator scope once all jobs settle.",
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
        jobs = [bot_bus.summarize_job_brief(j) for j in bot_bus.list_jobs(limit=limit)]
        return _tool_text({"jobs": jobs})

    jid = str(args.get("job_id") or "").strip()
    if not jid:
        return _tool_text("`job_id` is required for this action.", is_error=True)

    if action == "status":
        job = bot_bus.get_job(jid)
        if not job:
            return _tool_text(f"Job not found: {jid}", is_error=True)
        return _tool_text(bot_bus.summarize_job_brief(job))

    if action == "cancel":
        job = bot_bus.cancel_job(jid, requester_bot=me, reason=str(args.get("reason") or "cancelled_by_coordinator"))
        if not job:
            return _tool_text(f"Job not found: {jid}", is_error=True)
        return _tool_text({"cancelled": bot_bus.summarize_job_brief(job)})

    if action == "retry":
        job = bot_bus.retry_job(jid, requester_bot=me, prompt_override=str(args.get("prompt_override") or ""))
        return _tool_text({"retried": bot_bus.summarize_job_brief(job)})

    return _tool_text(f"Unknown action: {action}", is_error=True)


def _handle_team_broadcast(args: Dict[str, Any]) -> Dict[str, Any]:
    msg = str(args.get("message") or "").strip()
    if not msg:
        return _tool_text("`message` cannot be empty.", is_error=True)
    me = _my_handle()
    target_bot = str(args.get("bot") or me or "").strip()
    if not target_bot:
        return _tool_text("Target bot handle unavailable.", is_error=True)
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


_TOOL_DISPATCH = {
    "team_roster": _handle_team_roster,
    "team_dispatch": _handle_team_dispatch,
    "team_job": _handle_team_job,
    "team_broadcast": _handle_team_broadcast,
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
        if _bus_enabled():
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
        if not _bus_enabled():
            _reply_ok(
                req_id,
                _tool_text("`acb-team` is disabled on this worker/non-coordinator session.", is_error=True),
            )
            return
        tname = params.get("name") or ""
        args = params.get("arguments") or {}
        fn = _TOOL_DISPATCH.get(tname)
        if not fn:
            _reply_err(req_id, -32602, f"Unknown tool: {tname}")
            return
        try:
            res = fn(args)
        except Exception as exc:
            res = _tool_text(f"{tname} error: {exc}", is_error=True)
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
