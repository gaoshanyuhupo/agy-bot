#!/usr/bin/env python3
"""Taint-aware `PreToolUse` mechanical guardrail for Antigravity CLI.

Enforces outbound/high-risk shell, MCP write/exfil, and guardrail-path tamper blocking
whenever a session is tainted via:
1. Environment variables (`AGY_UNTRUSTED_SESSION=1` or `AGY_MEMORY_READONLY=1`),
2. Persistent taint registry (`memory_taint.json`), or
3. Real-time same-turn inspection of `transcriptPath` tail steps & prompt input.

CRITICAL INVARIANTS:
- NEVER skips when `AGY_INTERNAL_OBSERVER=1` (scheduled/unattended tasks set it alongside taint).
- Fail-Closed on tainted sessions: malformed stdin JSON, unavailable `memory_guard`, or evaluation
  exceptions emit `{"decision": "deny", "reason": "..."}` with exit code 0.
- Clean sessions and whitelisted safe calls strictly emit empty stdout (`""`) with exit code 0
  (NEVER `{}` and NEVER `{"decision": "allow"}`).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple


def _load_memory_guard():
    candidates = [
        Path(__file__).resolve().parents[1] / "bridge",
        Path(os.environ.get("AGY_BRIDGE_DIR", str(Path.home() / "agy-tg-bridge"))),
    ]
    for cand in candidates:
        if (cand / "memory_guard.py").is_file():
            if str(cand) not in sys.path:
                sys.path.insert(0, str(cand))
            break
    try:
        import memory_guard  # type: ignore

        return memory_guard
    except Exception:
        return None


_MEMORY_GUARD = _load_memory_guard()

TAINT_FILE = Path(
    os.environ.get(
        "AGY_MEMORY_TAINT_FILE",
        str(Path.home() / ".gemini" / "antigravity-cli" / "cache" / "memory_taint.json"),
    )
)

_FALLBACK_MARKERS: Tuple[str, ...] = (
    "[ACB_SCHEDULED_TASK",
    "[ACB_SCHEDULED_HANDOFF",
    "[REPO_WATCH_DELTA",
    "[GITHUB_WEBHOOK",
    "[BENCHMARK_DIGEST",
    "[PRECHECK_TRUNCATED",
    "[UNTRUSTED_EXTERNAL_DATA",
    "UNTRUSTED_WARNING",
    "不可信外部数据",
    "[EXTERNAL_UNTRUSTED",
    "[ACB_READONLY_GUEST",
    "[UNTRUSTED_WEB_ROOM_MESSAGE",
)

_FALLBACK_POISON_RE = re.compile(
    r"(?i)(?:ignore\s+(?:all\s+|any\s+)?previous\s+instructions|"
    r"save\s+to\s+memory|write\s+to\s+ecc-active-instincts|"
    r"ecc-homunculus|(?:curl|wget)\s+[^\n|]{3,200}\|\s*(?:ba|z)?sh\b)"
)

_RAW_CID_RE = re.compile(r'"(?:conversationId|session_id)"\s*:\s*"([^"]+)"')


def _resolve_taint_path() -> Path:
    env_val = os.environ.get("AGY_MEMORY_TAINT_FILE", "").strip()
    if env_val:
        return Path(env_val).expanduser()
    return TAINT_FILE


def _is_cid_tainted(cid: str) -> bool:
    if not cid:
        return False
    tf = _resolve_taint_path()
    if _MEMORY_GUARD is not None:
        try:
            return bool(_MEMORY_GUARD.is_tainted(cid, taint_file=tf))
        except Exception:
            pass
    try:
        if tf.is_file():
            data = json.loads(tf.read_text(encoding="utf-8", errors="replace"))
            entries = data.get("entries") if isinstance(data, dict) and "entries" in data else data
            return isinstance(entries, dict) and cid in entries
    except Exception:
        pass
    return False


def _mark_cid_tainted(cid: str, reason: str) -> None:
    if not cid or _MEMORY_GUARD is None:
        return
    try:
        _MEMORY_GUARD.mark_tainted(
            cid,
            reason=reason,
            source="hook_pretool:taint_outbound_guard",
            taint_file=_resolve_taint_path(),
        )
    except Exception:
        pass


def _record_block() -> None:
    if _MEMORY_GUARD is None:
        return
    try:
        _MEMORY_GUARD.record_guard_block(1, taint_file=_resolve_taint_path())
    except Exception:
        pass


def _is_owner_direct_session() -> bool:
    """Return True ONLY when process-level env explicitly indicates a clean Owner direct channel."""
    if _MEMORY_GUARD is not None:
        try:
            return bool(_MEMORY_GUARD.is_owner_direct_env())
        except Exception:
            return False
    trust = os.environ.get("AGY_TRUST_LEVEL", "").strip().lower()
    if trust != "local_admin":
        return False
    if (
        os.environ.get("AGY_UNTRUSTED_SESSION") == "1"
        or os.environ.get("AGY_MEMORY_READONLY") == "1"
        or os.environ.get("AGY_RBAC_ROLE", "").strip().lower() == "readonly"
    ):
        return False
    orig = os.environ.get("AGY_AGENT_ORIGIN", "").strip().lower()
    if orig.startswith("remote") or orig in (
        "webhook",
        "github_webhook",
        "scheduled",
        "scheduled_handoff",
        "web_room",
        "remote_hub",
        "remote_untrusted",
        "remote_batch_done",
    ):
        return False
    return True


def _read_tail_steps_with_meta(
    transcript_path: str,
    max_bytes: int = 65536,
    *,
    hard_cap_bytes: int = 4 * 1024 * 1024,
    expand_to_user_input: bool = False,
) -> Tuple[List[Dict[str, Any]], bool]:
    if _MEMORY_GUARD is not None and hasattr(_MEMORY_GUARD, "read_transcript_tail_steps_with_meta"):
        try:
            steps, meta = _MEMORY_GUARD.read_transcript_tail_steps_with_meta(
                transcript_path,
                max_bytes=max_bytes,
                hard_cap_bytes=hard_cap_bytes,
                expand_to_user_input=expand_to_user_input,
            )
            return steps, bool(isinstance(meta, dict) and meta.get("truncated"))
        except Exception:
            pass
    if not transcript_path:
        return [], False
    tp = Path(transcript_path)
    if not tp.is_file():
        return [], False
    try:
        size = tp.stat().st_size
        if size <= 0:
            return [], False
        window = max(1, int(max_bytes))
        hard_cap = max(window, int(hard_cap_bytes))
        steps: List[Dict[str, Any]] = []
        last_seek_pos = 0
        with open(tp, "rb") as fb:
            while True:
                seek_pos = max(0, size - window)
                last_seek_pos = seek_pos
                fb.seek(seek_pos)
                raw_lines = fb.read().splitlines()
                if seek_pos > 0:
                    raw_lines = raw_lines[1:]
                parsed: List[Dict[str, Any]] = []
                for rl in raw_lines:
                    if not rl.strip():
                        continue
                    try:
                        obj = json.loads(rl.decode("utf-8", "replace"))
                    except json.JSONDecodeError:
                        continue
                    if isinstance(obj, dict):
                        parsed.append(obj)
                steps = parsed
                if seek_pos == 0 or window >= hard_cap:
                    break
                if not steps:
                    window = min(hard_cap, window * 2)
                    continue
                if expand_to_user_input and not any(st.get("type") == "USER_INPUT" for st in steps):
                    window = min(hard_cap, window * 2)
                    continue
                break
        return steps, (last_seek_pos > 0)
    except OSError:
        return [], False


def _read_tail_steps(
    transcript_path: str,
    max_bytes: int = 65536,
    *,
    hard_cap_bytes: int = 4 * 1024 * 1024,
    expand_to_user_input: bool = False,
) -> List[Dict[str, Any]]:
    steps, _truncated = _read_tail_steps_with_meta(
        transcript_path,
        max_bytes=max_bytes,
        hard_cap_bytes=hard_cap_bytes,
        expand_to_user_input=expand_to_user_input,
    )
    return steps


def _inspect_context_for_taint(
    payload: Dict[str, Any],
    tail_steps: List[Dict[str, Any]],
    *,
    owner_direct: bool = False,
    truncated: bool = False,
) -> Tuple[bool, str]:
    """Inspect context for taint.

    - Fail-Closed on head-truncated transcripts where `USER_INPUT` was pushed past the 4MB window:
      returns `(True, "turn_window_truncated_no_user_input")` regardless of Owner vs non-Owner,
      without falsely tainting non-truncated empty or short transcripts.
    - In clean Owner direct sessions (`AGY_TRUST_LEVEL=local_admin` and non-sticky):
      skip `USER_INPUT` / `PLANNER_RESPONSE` / verified workspace-local offline tools;
      ONLY scan external/unverified/orphaned tool results AFTER the latest `USER_INPUT`.
    - In non-Owner / default sessions:
      inspect prompt metadata and ALL tail transcript steps (Fail-Closed).
    """
    if owner_direct:
        cwd = str(payload.get("cwd") or "")
        ws_paths = payload.get("workspacePaths")
        if not isinstance(ws_paths, list):
            ws_paths = None
        if _MEMORY_GUARD is not None and hasattr(_MEMORY_GUARD, "slice_current_turn_steps"):
            turn_steps, found_user = _MEMORY_GUARD.slice_current_turn_steps(tail_steps)
            if truncated and not found_user:
                return True, "turn_window_truncated_no_user_input"
            res = _MEMORY_GUARD.inspect_turn_external_steps(
                turn_steps,
                cwd=cwd,
                workspace_paths=ws_paths,
            )
            if res.get("untrusted"):
                return True, ",".join(res.get("reasons", [])[:4]) or "untrusted_external_tool"
            return False, ""
        # Fallback when memory_guard failed to import: Fail-Closed scan current turn steps
        last_u = -1
        for i, st in enumerate(tail_steps):
            if isinstance(st, dict) and st.get("type") == "USER_INPUT":
                last_u = i
        if truncated and last_u < 0:
            return True, "turn_window_truncated_no_user_input"
        turn_steps = tail_steps[last_u + 1 :] if last_u >= 0 else tail_steps
        external_only = [
            st for st in turn_steps if isinstance(st, dict) and st.get("type") not in ("USER_INPUT", "PLANNER_RESPONSE", "CHECKPOINT", "SYSTEM_MESSAGE")
        ]
        blob = json.dumps(external_only, ensure_ascii=False)
        for m in _FALLBACK_MARKERS:
            if m in blob:
                return True, f"marker:{m}"
        if _FALLBACK_POISON_RE.search(blob):
            return True, "poison:fallback"
        return False, ""

    if truncated and not any(isinstance(st, dict) and st.get("type") == "USER_INPUT" for st in tail_steps):
        return True, "turn_window_truncated_no_user_input"

    context_payload: Dict[str, Any] = {}
    for k in ("lastUserInput", "prompt"):
        val = payload.get(k)
        if isinstance(val, str) and val:
            context_payload[k] = val

    if _MEMORY_GUARD is not None:
        res = _MEMORY_GUARD.inspect_payload(context_payload, tail_steps)
        if res.get("untrusted"):
            return True, ",".join(res.get("reasons", [])[:4]) or "untrusted_context"
        return False, ""

    blob = json.dumps({"payload": context_payload, "steps": tail_steps}, ensure_ascii=False)
    for m in _FALLBACK_MARKERS:
        if m in blob:
            return True, f"marker:{m}"
    if _FALLBACK_POISON_RE.search(blob):
        return True, "poison:fallback"
    return False, ""


def _emit_deny(reason: str) -> int:
    clean_reason = str(reason or "").strip() or "[taint-outbound-guard] Blocked high-risk tool call"
    print(json.dumps({"decision": "deny", "reason": clean_reason}, ensure_ascii=False))
    return 0


def _emit_pass() -> int:
    # Empty stdout + exit 0 is the verified zero-false-block, zero-downgrade pass-through
    # contract for Antigravity CLI >= 1.5.14 PreToolUse hooks (never emit `{}` or `allow`).
    return 0


def _extract_raw_cid(raw_stdin: str) -> str:
    m = _RAW_CID_RE.search(raw_stdin or "")
    return m.group(1).strip() if m else ""


def _extract_raw_transcript_path(raw_stdin: str) -> str:
    m = re.search(r'"(?:transcriptPath|transcript_path)"\s*:\s*"([^"]+)"', raw_stdin or "")
    return m.group(1).strip() if m else ""


def main() -> int:
    env_untrusted = (
        os.environ.get("AGY_UNTRUSTED_SESSION") == "1"
        or os.environ.get("AGY_MEMORY_READONLY") == "1"
    )
    turn_taint_only = os.environ.get("AGY_TURN_TAINT_ONLY") == "1"
    owner_direct = _is_owner_direct_session()
    tainted = env_untrusted
    taint_scope = "owner_turn" if (env_untrusted and turn_taint_only) else "session"
    cid = ""
    taint_reasons: List[str] = ["env_untrusted_session"] if env_untrusted else []

    try:
        raw_stdin = sys.stdin.read()
        payload: Optional[Dict[str, Any]] = None
        if raw_stdin.strip():
            try:
                loaded = json.loads(raw_stdin)
                if isinstance(loaded, dict):
                    payload = loaded
            except json.JSONDecodeError:
                payload = None

        if payload is None:
            raw_cid = _extract_raw_cid(raw_stdin)
            if raw_cid and _is_cid_tainted(raw_cid):
                tainted = True
                taint_scope = "session"
            elif not tainted:
                raw_tp = _extract_raw_transcript_path(raw_stdin)
                if raw_tp:
                    tail_steps, truncated = _read_tail_steps_with_meta(
                        raw_tp, max_bytes=65536, expand_to_user_input=True
                    )
                    found_untr, reason = _inspect_context_for_taint(
                        {}, tail_steps, owner_direct=owner_direct, truncated=truncated
                    )
                    if found_untr:
                        tainted = True
                        taint_reasons.append(reason)
                        if owner_direct:
                            taint_scope = "owner_turn"
                        else:
                            taint_scope = "session"
                            if raw_cid and not turn_taint_only:
                                _mark_cid_tainted(raw_cid, reason)
            if tainted:
                _record_block()
                return _emit_deny(
                    "[taint-outbound-guard] Fail-closed: malformed or missing PreToolUse JSON payload in tainted session"
                )
            return _emit_pass()

        cid = str(payload.get("conversationId") or payload.get("session_id") or "").strip()

        if env_untrusted and cid and not turn_taint_only:
            _mark_cid_tainted(cid, "env_untrusted_session")

        if cid and _is_cid_tainted(cid):
            tainted = True
            taint_scope = "session"
            if "taint_registry" not in taint_reasons:
                taint_reasons.append("taint_registry")

        if not tainted:
            tpath = str(payload.get("transcriptPath") or payload.get("transcript_path") or "")
            tail_steps, truncated = (
                _read_tail_steps_with_meta(tpath, max_bytes=65536, expand_to_user_input=True)
                if tpath
                else ([], False)
            )
            found_untrusted, reason = _inspect_context_for_taint(
                payload, tail_steps, owner_direct=owner_direct, truncated=truncated
            )
            if found_untrusted:
                tainted = True
                taint_reasons.append(reason)
                if owner_direct:
                    # Plan A (C6): Owner turn-scoped taint does NOT permanently taint memory_taint.json
                    taint_scope = "owner_turn"
                else:
                    taint_scope = "session"
                    if cid and not turn_taint_only:
                        _mark_cid_tainted(cid, reason)

        if not tainted:
            return _emit_pass()

        if _MEMORY_GUARD is None:
            return _emit_deny(
                "[taint-outbound-guard] Fail-closed: memory_guard module unavailable in tainted session"
            )

        tool_call = payload.get("toolCall")
        if not isinstance(tool_call, dict):
            tool_call = payload.get("tool_call")
        if not isinstance(tool_call, dict):
            _record_block()
            return _emit_deny(
                "[taint-outbound-guard] Fail-closed: missing toolCall object in tainted session"
            )

        tool_name = str(
            tool_call.get("name") or payload.get("toolName") or payload.get("tool_name") or ""
        ).strip()
        raw_args = tool_call.get("args")
        if not isinstance(raw_args, dict):
            raw_args = tool_call.get("arguments")
        tool_args = raw_args if isinstance(raw_args, dict) else {}
        cwd = str(payload.get("cwd") or "")
        ws_paths = payload.get("workspacePaths")
        if not isinstance(ws_paths, list):
            ws_paths = None

        result = _MEMORY_GUARD.evaluate_tainted_tool_call(
            tool_name,
            tool_args,
            tainted=True,
            taint_reason=",".join(taint_reasons),
            cwd=cwd,
            taint_file=_resolve_taint_path(),
            taint_scope=taint_scope,
            workspace_paths=ws_paths,
        )
        if result.get("blocked"):
            _record_block()
            return _emit_deny(str(result.get("reason") or "[taint-outbound-guard] Blocked high-risk tool call"))

        return _emit_pass()
    except Exception as exc:
        if tainted or (cid and _is_cid_tainted(cid)):
            _record_block()
            return _emit_deny(
                f"[taint-outbound-guard] Fail-closed internal error in tainted session: {type(exc).__name__}"
            )
        return _emit_pass()


if __name__ == "__main__":
    sys.exit(main())
