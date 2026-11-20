#!/usr/bin/env python3
"""Lightweight Antigravity CLI hook pre-filter before invoking `claude-mem` (`bun`).

Filters out wasteful or untrusted invocations before spawning Bun or triggering background LLM calls:
- Skips internal background observer calls (`AGY_INTERNAL_OBSERVER=1`, `/observer-sandbox`, or `shim_session.json` CIDs)
- Enforces anti-poisoning taint checks (`memory_taint.json`, `AGY_UNTRUSTED_SESSION`, `AGY_MEMORY_READONLY`,
  and full-step payload/transcript inspection) and blocks `session-init` / `summarize` writes on tainted sessions
- Skips `session-init` when `invocationNum > 0` (avoids per-tool Bun spawns & file-context prompt bloat)
- Skips slash commands (`/compact`, `/cost`, `/status`, ...) and `<STATELESS_TASK>` prompts
- Skips `summarize` when the transcript just ended on a `CHECKPOINT` or a trivial 0-tool short ack
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


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

SHIM_STATE_FILE = Path(os.environ.get("AGY_SHIM_STATE_FILE", str(Path.home() / "agy-mem-hub/state/shim_session.json")))
TAINT_FILE = Path(
    os.environ.get(
        "AGY_MEMORY_TAINT_FILE",
        str(Path.home() / ".gemini" / "antigravity-cli" / "cache" / "memory_taint.json"),
    )
)
BUN_BIN = os.environ.get("AGY_BUN_BIN", str(Path.home() / ".bun/bin/bun"))
WORKER_CJS = os.environ.get(
    "CLAUDE_MEM_WORKER_CJS",
    str(Path.home() / ".claude/plugins/marketplaces/thedotmack/plugin/scripts/worker-service.cjs"),
)

USER_REQ_RE = re.compile(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", re.S)
SLASH_CMD_RE = re.compile(
    r"^/(?:compact|cost|usage|bill|status|context|model|effort|new|help|sessions|resume|project|reload|cancel|mode|thinking|files|get|dream)\b",
    re.IGNORECASE,
)

_FALLBACK_MARKERS = (
    "[ACB_SCHEDULED_TASK",
    "[ACB_SCHEDULED_HANDOFF",
    "[REPO_WATCH_DELTA",
    "[GITHUB_WEBHOOK",
    "[BENCHMARK_DIGEST",
    "UNTRUSTED_WARNING",
    "不可信外部数据",
    "[EXTERNAL_UNTRUSTED",
    "[ACB_READONLY_GUEST",
)
_FALLBACK_POISON_RE = re.compile(
    r"(?i)(?:ignore\s+(?:all\s+|any\s+)?previous\s+instructions|"
    r"save\s+to\s+memory|write\s+to\s+ecc-active-instincts|"
    r"ecc-homunculus|(?:curl|wget)\s+[^\n|]{3,200}\|\s*(?:ba|z)?sh\b)"
)


def _get_observer_cids() -> set[str]:
    cids: set[str] = set()
    try:
        if SHIM_STATE_FILE.is_file():
            data = json.loads(SHIM_STATE_FILE.read_text(encoding="utf-8"))
            cur = data.get("conversation_id")
            if isinstance(cur, str) and cur.strip():
                cids.add(cur.strip())
            hist = data.get("observer_cids") or []
            if isinstance(hist, list):
                for item in hist:
                    if isinstance(item, str) and item.strip():
                        cids.add(item.strip())
    except Exception:
        pass
    return cids


def _unwrap_user_text(raw: str) -> str:
    if not raw:
        return ""
    m = USER_REQ_RE.search(raw)
    if m:
        return m.group(1).strip()
    cleaned = re.sub(r"<CONTEXT_SUMMARY>.*?</CONTEXT_SUMMARY>", "", raw, flags=re.S)
    cleaned = re.sub(r"<ADDITIONAL_METADATA>.*?</ADDITIONAL_METADATA>", "", cleaned, flags=re.S)
    cleaned = re.sub(r"<SYSTEM_MESSAGE>.*?</SYSTEM_MESSAGE>", "", cleaned, flags=re.S)
    return cleaned.strip()


def _is_internal_observer(payload: dict[str, Any]) -> bool:
    if os.environ.get("AGY_INTERNAL_OBSERVER") == "1":
        return True
    cid = str(payload.get("conversationId") or payload.get("session_id") or "").strip()
    if cid and cid in _get_observer_cids():
        return True
    cwd = str(payload.get("cwd") or "")
    if "/observer-sandbox" in cwd:
        return True
    ws_list = payload.get("workspacePaths") or []
    if isinstance(ws_list, list) and any("/observer-sandbox" in str(w) for w in ws_list):
        return True
    return False


def _is_cid_tainted(cid: str) -> bool:
    if not cid:
        return False
    if _MEMORY_GUARD is not None:
        return _MEMORY_GUARD.is_tainted(cid)
    try:
        if TAINT_FILE.is_file():
            data = json.loads(TAINT_FILE.read_text(encoding="utf-8", errors="replace"))
            entries = data.get("entries") if isinstance(data, dict) and "entries" in data else data
            return isinstance(entries, dict) and cid in entries
    except Exception:
        pass
    return False


def _mark_cid_tainted(cid: str, reason: str, event: str) -> None:
    if not cid:
        return
    if _MEMORY_GUARD is not None:
        _MEMORY_GUARD.mark_tainted(cid, reason=reason, source=f"hook_gate:{event}")


def _record_block() -> None:
    if _MEMORY_GUARD is not None:
        _MEMORY_GUARD.record_guard_block(1)


def _inspect_payload_and_steps(payload: dict[str, Any], tail_steps: list[dict[str, Any]]) -> tuple[bool, str]:
    if _MEMORY_GUARD is not None:
        res = _MEMORY_GUARD.inspect_payload(payload, tail_steps)
        if res["untrusted"]:
            return True, ",".join(res["reasons"][:4])
        return False, ""
    blob = json.dumps({"payload": payload, "steps": tail_steps}, ensure_ascii=False)
    for m in _FALLBACK_MARKERS:
        if m in blob:
            return True, f"marker:{m}"
    if _FALLBACK_POISON_RE.search(blob):
        return True, "poison:fallback"
    return False, ""


def _read_tail_steps(
    transcript_path: str,
    max_bytes: int = 65536,
    *,
    hard_cap_bytes: int = 4 * 1024 * 1024,
) -> list[dict[str, Any]]:
    if not transcript_path:
        return []
    tp = Path(transcript_path)
    if not tp.is_file():
        return []
    try:
        size = tp.stat().st_size
        if size <= 0:
            return []
        window = max(1, int(max_bytes))
        hard_cap = max(window, int(hard_cap_bytes))
        with open(tp, "rb") as fb:
            while True:
                seek_pos = max(0, size - window)
                fb.seek(seek_pos)
                raw_lines = fb.read().splitlines()
                if seek_pos == 0:
                    break
                non_empty_tail = [rl for rl in raw_lines[1:] if rl.strip()]
                if non_empty_tail or window >= hard_cap:
                    raw_lines = raw_lines[1:]
                    break
                window = min(hard_cap, window * 2)
        steps: list[dict[str, Any]] = []
        for rl in raw_lines:
            if not rl.strip():
                continue
            try:
                obj = json.loads(rl.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                steps.append(obj)
        return steps
    except OSError:
        return []


def _extract_prompt_text(payload: dict[str, Any], tail_steps: list[dict[str, Any]]) -> str:
    raw = str(payload.get("lastUserInput") or payload.get("prompt") or "")
    if not raw.strip() and tail_steps:
        for st in reversed(tail_steps):
            if st.get("type") == "USER_INPUT":
                raw = str(st.get("content") or "")
                break
    return _unwrap_user_text(raw)


def _should_skip_summarize(tail_steps: list[dict[str, Any]]) -> bool:
    if not tail_steps:
        return False
    # If the last valid step is CHECKPOINT, compaction just ran; do not trigger duplicate summary.
    if tail_steps[-1].get("type") == "CHECKPOINT":
        return True
    # Inspect all PLANNER_RESPONSE steps since the most recent USER_INPUT
    tool_count = 0
    reply_chars = 0
    saw_user = False
    for st in reversed(tail_steps):
        stype = st.get("type")
        if stype == "USER_INPUT":
            saw_user = True
            break
        if stype == "PLANNER_RESPONSE":
            tcs = st.get("tool_calls") or []
            if isinstance(tcs, list):
                tool_count += len(tcs)
            reply_chars += len(str(st.get("content") or "").strip())
        elif stype == "CHECKPOINT":
            return True
    if saw_user and tool_count == 0 and reply_chars < 120:
        return True
    return False


def main() -> int:
    try:
        event = sys.argv[1] if len(sys.argv) > 1 else ""
        if event not in ("context", "session-init", "summarize"):
            print("{}")
            return 0

        if os.environ.get("AGY_INTERNAL_OBSERVER") == "1":
            print("{}")
            return 0

        raw_stdin = sys.stdin.read()
        payload: dict[str, Any] = {}
        if raw_stdin.strip():
            try:
                loaded = json.loads(raw_stdin)
                if isinstance(loaded, dict):
                    payload = loaded
            except json.JSONDecodeError:
                payload = {}

        if _is_internal_observer(payload):
            print("{}")
            return 0

        cid = str(payload.get("conversationId") or payload.get("session_id") or "").strip()
        env_untrusted = (
            os.environ.get("AGY_UNTRUSTED_SESSION") == "1"
            or os.environ.get("AGY_MEMORY_READONLY") == "1"
        )
        if env_untrusted and cid:
            _mark_cid_tainted(cid, "env_untrusted_session", event)

        if event in ("session-init", "summarize") and (env_untrusted or _is_cid_tainted(cid)):
            _record_block()
            print("{}")
            return 0

        inv_num = payload.get("invocationNum")
        if event == "session-init" and isinstance(inv_num, int) and inv_num > 0:
            print("{}")
            return 0

        tpath = str(payload.get("transcriptPath") or payload.get("transcript_path") or "")
        tail_steps: list[dict[str, Any]] = _read_tail_steps(tpath, max_bytes=65536) if tpath else []

        is_untrusted, untrusted_reason = _inspect_payload_and_steps(payload, tail_steps)
        if is_untrusted:
            if cid:
                _mark_cid_tainted(cid, untrusted_reason, event)
            if event in ("session-init", "summarize"):
                _record_block()
                print("{}")
                return 0

        if event in ("session-init", "summarize"):
            prompt_text = _extract_prompt_text(payload, tail_steps)
            if prompt_text.startswith("<STATELESS_TASK") or SLASH_CMD_RE.match(prompt_text):
                print("{}")
                return 0
            if event == "summarize" and _should_skip_summarize(tail_steps):
                print("{}")
                return 0

        proc = subprocess.run(
            [BUN_BIN, WORKER_CJS, "hook", "antigravity-cli", event],
            input=raw_stdin,
            text=True,
            capture_output=True,
            timeout=28,
            check=False,
        )
        out = (proc.stdout or "").strip()
        print(out if out else "{}")
        return 0
    except Exception:
        print("{}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
