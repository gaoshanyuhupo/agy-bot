#!/usr/bin/env python3
"""Native Antigravity (`agy`) Continuous-Learning v2 ("Instinct -> Skill" + Dream) Daemon & CLI.

- Zero foreground hook latency: tails `~/.gemini/antigravity-cli/brain/*/.system_generated/logs/transcript.jsonl`
  asynchronously (skipping internal observer & tainted untrusted sessions).
- Anti-poisoning defense: checks `memory_guard` sticky taint registry and inspects EVERY harvested
  step (USER_INPUT + PLANNER_RESPONSE + tool calls/outputs) plus LLM candidate instincts.
- Scrubs secrets before persisting observations to `~/.local/share/ecc-homunculus/observations.jsonl`.
- Calls our local `agy-llm-shim` (`http://127.0.0.1:18791/v1/chat/completions`)
  to extract/update atomic instincts (`0.30`..`0.95` confidence) in ECC v2.1 YAML format.
- Periodic Dream consolidation (`dream`): deduplicates/merges fragmented instincts, applies gentle
  time decay with safe archival, compresses/archives analyzed `observations.jsonl` history with exact
  offset recalculation, and syncs `>= 0.80` instincts deterministically without breaking prefix cache.
"""

from __future__ import annotations

import argparse
import fcntl
import gzip
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


def _load_bridge_module(mod_name: str):
    candidates = [
        Path(__file__).resolve().parents[1] / "bridge",
        Path(os.environ.get("AGY_BRIDGE_DIR", str(Path.home() / "agy-tg-bridge"))),
    ]
    for cand in candidates:
        if (cand / f"{mod_name}.py").is_file():
            if str(cand) not in sys.path:
                sys.path.insert(0, str(cand))
            break
    try:
        return __import__(mod_name)
    except Exception:
        return None


_MEMORY_GUARD = _load_bridge_module("memory_guard")
_BOT_PROFILES = _load_bridge_module("bot_profiles")

SHIM_URL = os.environ.get("AGY_SHIM_COMPLETIONS_URL", "http://127.0.0.1:18791/v1/chat/completions")
SHIM_MODEL = os.environ.get("AGY_SHIM_MODEL", "gemini-3.8-flash-low")

BRAIN_ROOT = Path(os.environ.get("AGY_BRAIN_ROOT", str(Path.home() / ".gemini" / "antigravity-cli" / "brain")))
HOMUNCULUS_DIR = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "ecc-homunculus"
PERSONAL_INSTINCTS_DIR = HOMUNCULUS_DIR / "instincts" / "personal"
EVOLVED_SKILLS_DIR = HOMUNCULUS_DIR / "evolved" / "skills"
ARCHIVE_DIR = HOMUNCULUS_DIR / "archive"
ARCHIVE_INSTINCTS_DIR = ARCHIVE_DIR / "instincts"
OBSERVATIONS_FILE = HOMUNCULUS_DIR / "observations.jsonl"
LOCAL_ACTIVE_RULE_FILE = HOMUNCULUS_DIR / "active-instincts.md"

HUB_DIR = Path(os.environ.get("AGY_MEM_HUB_DIR", str(Path.home() / "agy-mem-hub")))
STATE_DIR = HUB_DIR / "state"
SHIM_STATE_FILE = STATE_DIR / "shim_session.json"
DAEMON_STATE_FILE = STATE_DIR / "instinct_daemon_state.json"
MEMORY_TAINT_FILE = Path(
    os.environ.get(
        "AGY_MEMORY_TAINT_FILE",
        str(Path.home() / ".gemini" / "antigravity-cli" / "cache" / "memory_taint.json"),
    )
)

BOT_PROFILES_DIR = Path(
    os.environ.get("AGY_BOT_PROFILES_DIR", str(Path.home() / ".config" / "agy-tg-bridge" / "bots"))
)
BUS_DIR = Path(
    os.environ.get("AGY_BOT_BUS_DIR", str(Path.home() / ".config" / "agy-tg-bridge" / "bus"))
)

WORKSPACE_DIR = Path(os.environ.get("AGY_WORKSPACE_DIR", str(Path.home() / "agy-workspace")))
WORKSPACE_AGENTS_DIR = WORKSPACE_DIR / ".agents"
ACTIVE_RULE_FILE = LOCAL_ACTIVE_RULE_FILE
SHARED_WORKSPACE_RULE_FILE = WORKSPACE_AGENTS_DIR / "rules" / "ecc-active-instincts.md"
CLAUDE_MEM_RECENT_RULE_FILE = WORKSPACE_AGENTS_DIR / "rules" / "claude-mem-recent.md"
WORKSPACE_SKILLS_DIR = WORKSPACE_AGENTS_DIR / "skills"
INSTINCT_CLI = WORKSPACE_SKILLS_DIR / "continuous-learning-v2" / "scripts" / "instinct-cli.py"
CLAUDE_MEM_CONTEXT_URL = "http://127.0.0.1:37701/api/context/inject?projects=agy-workspace"
BRIDGE_RELOAD_FILES = [
    Path("/tmp/agy_bridge_reload"),
    Path("/tmp/agy_bridge_sg_reload"),
    Path("/tmp/agy_bridge_jeff_reload"),
    Path("/tmp/agy_bridge_sgcli_reload"),
]


def _resolve_global_plugin_dir() -> Path | None:
    """Global `ecc-instincts` plugin projection is permanently disabled to prevent cross-bot leakage."""
    return None


GLOBAL_PLUGIN_DIR: Path | None = _resolve_global_plugin_dir()
GLOBAL_PLUGIN_MANIFEST: Path | None = None
GLOBAL_PLUGIN_RULE_FILE: Path | None = None
GLOBAL_PLUGIN_SKILLS_DIR: Path | None = None

POLL_INTERVAL_SEC = 180
MIN_OBS_FOR_BATCH = 40
MIN_OBS_ON_CORRECTION = 6
ANALYSIS_COOLDOWN_SEC = int(os.environ.get("AGY_ANALYSIS_COOLDOWN_SEC", "1800") or "1800")
CORRECTION_COOLDOWN_SEC = int(os.environ.get("AGY_CORRECTION_COOLDOWN_SEC", "300") or "300")
MAX_EVOLVED_SKILLS = int(os.environ.get("AGY_MAX_EVOLVED_SKILLS", "16") or "16")
EVOLVE_DELTA_MIN = int(os.environ.get("AGY_EVOLVE_DELTA_MIN", "3") or "3")
EVOLVE_COOLDOWN_SEC = int(os.environ.get("AGY_EVOLVE_COOLDOWN_SEC", "21600") or "21600")
ACTIVE_RULE_CORE_SLOTS = int(os.environ.get("AGY_ACTIVE_RULE_CORE_SLOTS", "15") or "15")
ACTIVE_RULE_RECENT_SLOTS = int(os.environ.get("AGY_ACTIVE_RULE_RECENT_SLOTS", "5") or "5")
ACTIVE_RULE_RECENT_DAYS = int(os.environ.get("AGY_ACTIVE_RULE_RECENT_DAYS", "7") or "7")
ACTIVE_RULE_RECENT_MIN_CONF = float(os.environ.get("AGY_ACTIVE_RULE_RECENT_MIN_CONF", "0.70") or "0.70")

DREAM_INTERVAL_SEC = int(os.environ.get("AGY_DREAM_INTERVAL_SEC", "86400") or "86400")
DREAM_MAX_OBS_LINES = int(os.environ.get("AGY_DREAM_MAX_OBS_LINES", "2000") or "2000")
DREAM_OBS_KEEP_TAIL = int(os.environ.get("AGY_DREAM_OBS_KEEP_TAIL", "500") or "500")
DREAM_DECAY_GRACE_DAYS = int(os.environ.get("AGY_DREAM_DECAY_GRACE_DAYS", "14") or "14")
DREAM_ARCHIVE_CONF = float(os.environ.get("AGY_DREAM_ARCHIVE_CONF", "0.35") or "0.35")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [agy-instinct] %(levelname)s %(message)s",
)
log = logging.getLogger("agy-instinct")

SECRET_PATTERNS = [
    re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})"),
    re.compile(r"(?:hvs\.[A-Za-z0-9_-]{16,255}|s\.[A-Za-z0-9]{16,255}|alt_[A-Za-z0-9]{20,255})"),
    re.compile(r"(?:sk-[A-Za-z0-9_-]{20,255}|AIza[0-9A-Za-z_-]{30,60})"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password|authorization)\s*[:=]\s*['\"]?)([A-Za-z0-9_\-/.+=]{10,256})"),
]

CORRECTION_RE = re.compile(
    r"(不对|不要|别用|改成|以后记住|记住|不要这样|应该用|换成|no,\s*use|instead of|don't use|always use|prefer )",
    re.IGNORECASE,
)

_FALLBACK_MARKERS = (
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
    r"ecc-homunculus|(?:curl|wget)\s+[^\n|]{3,200}\|\s*(?:ba|z)?sh\b|"
    r"\beval\s*\(\s*(?:__import__|base64|urllib|requests))"
)


def _get_tainted_cids() -> set[str]:
    if _MEMORY_GUARD is not None:
        return _MEMORY_GUARD.get_tainted_cids(taint_file=MEMORY_TAINT_FILE)
    tf = MEMORY_TAINT_FILE
    try:
        if tf.is_file():
            raw = json.loads(tf.read_text(encoding="utf-8", errors="replace"))
            entries = raw.get("entries") if isinstance(raw, dict) and "entries" in raw else raw
            if isinstance(entries, dict):
                return {str(k).strip() for k in entries.keys() if str(k).strip()}
    except Exception:
        pass
    return set()


def _mark_cid_tainted(cid: str, reason: str, source: str = "instinct_daemon") -> None:
    if _MEMORY_GUARD is not None:
        _MEMORY_GUARD.mark_tainted(cid, reason=reason, source=source, taint_file=MEMORY_TAINT_FILE)


def _record_guard_block(count: int = 1) -> None:
    if _MEMORY_GUARD is not None:
        _MEMORY_GUARD.record_guard_block(count, taint_file=MEMORY_TAINT_FILE)


def _inspect_text(text: str) -> tuple[bool, str]:
    if _MEMORY_GUARD is not None:
        res = _MEMORY_GUARD.inspect_text(text)
        return bool(res["untrusted"]), ",".join(res["reasons"][:4])
    for m in _FALLBACK_MARKERS:
        if m in text:
            return True, f"marker:{m}"
    if _FALLBACK_POISON_RE.search(text):
        return True, "poison:fallback"
    return False, ""


def _inspect_step(step: dict[str, Any]) -> tuple[bool, str]:
    if _MEMORY_GUARD is not None:
        res = _MEMORY_GUARD.inspect_step(step)
        return bool(res["untrusted"]), ",".join(res["reasons"][:4])
    return _inspect_text(json.dumps(step, ensure_ascii=False))


def _split_steps_into_turns(steps: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group transcript steps into per-turn slices bounded by `USER_INPUT`."""
    turns: list[list[dict[str, Any]]] = []
    cur: list[dict[str, Any]] = []
    for st in steps:
        if st.get("type") == "USER_INPUT":
            if cur:
                turns.append(cur)
            cur = [st]
        else:
            cur.append(st)
    if cur:
        turns.append(cur)
    return turns


def _classify_harvest_turn(
    turn_steps: list[dict[str, Any]],
    *,
    workspace_paths: list[str] | None = None,
) -> tuple[str, str]:
    """Classify a single transcript turn for instinct harvesting.

    Returns:
      - `("session_taint", reason)` if a `USER_INPUT` carries an untrusted external source marker
        (e.g. `[BENCHMARK_DIGEST]`, `UNTRUSTED_WARNING`, `[GITHUB_WEBHOOK`, `[ACB_READONLY_GUEST`)
      - `("turn_skip", reason)` if the turn has a poisoned external/orphaned tool result
        without poisoning the entire session (`memory_taint.json`)
      - `("clean", "")` if safe to harvest (normal `USER_INPUT` without untrusted source markers
        is NEVER skipped merely for mentioning memory/rule keywords)
    """
    for st in turn_steps:
        if st.get("type") == "USER_INPUT":
            raw_txt = str(st.get("content") or "")
            if _MEMORY_GUARD is not None:
                res = _MEMORY_GUARD.inspect_text(raw_txt)
                if res.get("markers"):
                    return "session_taint", ",".join(res.get("reasons", [])[:4]) or "untrusted_marker"
            else:
                for m in _FALLBACK_MARKERS:
                    if m in raw_txt:
                        return "session_taint", f"marker:{m}"

    ws_list = list(workspace_paths) if workspace_paths else [str(WORKSPACE_DIR)]
    if _MEMORY_GUARD is not None and hasattr(_MEMORY_GUARD, "inspect_turn_external_steps"):
        ext_res = _MEMORY_GUARD.inspect_turn_external_steps(
            turn_steps,
            cwd=str(WORKSPACE_DIR),
            workspace_paths=ws_list,
        )
        if ext_res.get("untrusted"):
            return "turn_skip", ",".join(ext_res.get("reasons", [])[:4]) or "untrusted_external_tool"
        return "clean", ""

    for st in turn_steps:
        if st.get("type") in ("USER_INPUT", "PLANNER_RESPONSE", "CHECKPOINT", "SYSTEM_MESSAGE"):
            continue
        is_bad, bad_reason = _inspect_step(st)
        if is_bad:
            return "turn_skip", bad_reason or "untrusted_step"
    return "clean", ""


def _validate_instinct_candidate(inst: dict[str, Any], *, is_existing: bool = False) -> tuple[bool, str]:
    if _MEMORY_GUARD is not None:
        return _MEMORY_GUARD.validate_instinct_candidate(inst, is_existing=is_existing)
    blob = json.dumps(inst, ensure_ascii=False)
    if is_existing:
        if _FALLBACK_POISON_RE.search(blob):
            return False, "poison:fallback"
        return True, ""
    bad, reason = _inspect_text(blob)
    return (not bad), reason


def scrub_secrets(text: str) -> str:
    if not text:
        return ""
    out = text
    for idx, pat in enumerate(SECRET_PATTERNS):
        if idx == 3:
            out = pat.sub(r"\1[REDACTED]", out)
        else:
            out = pat.sub("[REDACTED]", out)
    return out


def unwrap_user_request(text: str) -> str:
    m = re.search(r"<USER_REQUEST>\s*([\s\S]*?)\s*</USER_REQUEST>", text)
    if m:
        return m.group(1).strip()
    cleaned = re.sub(r"<CONTEXT_SUMMARY>[\s\S]*?</CONTEXT_SUMMARY>", "", text)
    cleaned = re.sub(r"<ADDITIONAL_METADATA>[\s\S]*?</ADDITIONAL_METADATA>", "", cleaned)
    cleaned = re.sub(r"<SYSTEM_MESSAGE>[\s\S]*?</SYSTEM_MESSAGE>", "", cleaned)
    return cleaned.strip()


SCHEDULED_CIDS_FILE = Path(
    os.environ.get(
        "AGY_SCHEDULED_CIDS_FILE",
        str(Path.home() / ".gemini" / "antigravity-cli" / "cache" / "scheduled_cids.json"),
    )
)


def get_observer_cids() -> set[str]:
    cids: set[str] = set()
    try:
        if SHIM_STATE_FILE.exists():
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
    try:
        if SCHEDULED_CIDS_FILE.exists():
            sched_list = json.loads(SCHEDULED_CIDS_FILE.read_text(encoding="utf-8"))
            if isinstance(sched_list, list):
                for item in sched_list:
                    if isinstance(item, str) and item.strip():
                        cids.add(item.strip())
    except Exception:
        pass
    return cids


_STATE_THREAD_LOCK = threading.Lock()


def _state_lock_path() -> Path:
    return DAEMON_STATE_FILE.with_name(DAEMON_STATE_FILE.name + ".lock")


def _default_daemon_state() -> dict[str, Any]:
    return {
        "transcript_offsets": {},
        "last_analyzed_obs_line": 0,
        "last_analysis_ts": 0.0,
        "poison_blocked_count": 0,
        "last_dream_ts": 0.0,
        "obs_compaction_gen": 0,
        "pending_correction": False,
        "evolved_domain_counts": {},
        "last_evolve_ts": 0.0,
        "per_bot_obs_offsets": {},
        "per_bot_last_analysis_ts": {},
        "per_bot_pending_correction": {},
        "per_bot_obs_compaction_gen": {},
        "per_bot_evolved_domain_counts": {},
        "per_bot_last_evolve_ts": {},
        "per_bot_last_dream_ts": 0.0,
        "per_bot_last_dream_summary": {},
    }


def _read_daemon_state_unlocked() -> dict[str, Any]:
    try:
        if DAEMON_STATE_FILE.exists():
            data = json.loads(DAEMON_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data.setdefault("transcript_offsets", {})
                data.setdefault("last_analyzed_obs_line", 0)
                data.setdefault("last_analysis_ts", 0.0)
                data.setdefault("poison_blocked_count", 0)
                data.setdefault("last_dream_ts", 0.0)
                data.setdefault("obs_compaction_gen", 0)
                data.setdefault("pending_correction", False)
                data.setdefault("evolved_domain_counts", {})
                data.setdefault("last_evolve_ts", 0.0)
                return data
    except Exception:
        pass
    return _default_daemon_state()


def _write_daemon_state_unlocked(st: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = DAEMON_STATE_FILE.with_name(f".{DAEMON_STATE_FILE.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(st, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(DAEMON_STATE_FILE)


def load_daemon_state() -> dict[str, Any]:
    if not DAEMON_STATE_FILE.exists():
        return _default_daemon_state()
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    lock_p = _state_lock_path()
    try:
        with _STATE_THREAD_LOCK:
            with open(lock_p, "a+", encoding="utf-8") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_SH)
                try:
                    return _read_daemon_state_unlocked()
                finally:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except OSError:
        return _read_daemon_state_unlocked()


def save_daemon_state(st: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    lock_p = _state_lock_path()
    with _STATE_THREAD_LOCK:
        with open(lock_p, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                _write_daemon_state_unlocked(st)
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def _update_daemon_state(mutator) -> dict[str, Any]:
    """Atomically read-modify-write DAEMON_STATE_FILE under thread lock + flock."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    lock_p = _state_lock_path()
    with _STATE_THREAD_LOCK:
        with open(lock_p, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                st = _read_daemon_state_unlocked()
                mutator(st)
                _write_daemon_state_unlocked(st)
                return st
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def ensure_dirs() -> None:
    for d in (
        PERSONAL_INSTINCTS_DIR,
        EVOLVED_SKILLS_DIR,
        ARCHIVE_INSTINCTS_DIR,
        STATE_DIR,
        WORKSPACE_AGENTS_DIR / "rules",
        WORKSPACE_SKILLS_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True)


def _obs_lock_path() -> Path:
    return OBSERVATIONS_FILE.with_name(OBSERVATIONS_FILE.name + ".lock")


def harvest_transcripts(state: dict[str, Any]) -> tuple[int, bool]:
    """Read new steps from agy brain transcripts and append sanitized observations.

    Enforces sticky taint filtering (`get_tainted_cids()`) AND per-step inspection across
    all newly arrived steps (closing the `lines[:12]` bypass).
    """
    ensure_dirs()
    observer_cids = get_observer_cids()
    tainted_cids = _get_tainted_cids()
    offsets: dict[str, int] = state.setdefault("transcript_offsets", {})
    appended = 0
    saw_correction = False

    if not BRAIN_ROOT.is_dir():
        return 0, False

    for brain_dir in sorted(BRAIN_ROOT.iterdir()):
        if not brain_dir.is_dir():
            continue
        cid = brain_dir.name
        if cid in observer_cids:
            continue

        tpath = brain_dir / ".system_generated" / "logs" / "transcript.jsonl"
        if not tpath.is_file():
            continue

        try:
            lines = tpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue

        total = len(lines)
        if cid in tainted_cids:
            prev_off = int(offsets.get(cid) or 0)
            if prev_off < total:
                state["poison_blocked_count"] = int(state.get("poison_blocked_count") or 0) + 1
                _record_guard_block(1)
            offsets[cid] = total
            continue

        head_sample = "\n".join(lines[:12])
        if "<STATELESS_TASK>" in head_sample or "[ACB_SCHEDULED_TASK" in head_sample:
            if "[ACB_SCHEDULED_TASK" in head_sample:
                _mark_cid_tainted(cid, "marker:[ACB_SCHEDULED_TASK", "instinct_daemon:head")
                tainted_cids.add(cid)
                if int(offsets.get(cid) or 0) < total:
                    state["poison_blocked_count"] = int(state.get("poison_blocked_count") or 0) + 1
                    _record_guard_block(1)
            offsets[cid] = total
            continue

        if cid not in offsets:
            # First time seeing an existing transcript: start near tail (last 30 lines)
            offsets[cid] = max(0, total - 30)

        start_idx = offsets[cid]
        if start_idx > total:
            start_idx = 0
        if start_idx >= total:
            continue

        new_obs: list[dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tainted_now = False

        parsed_steps: list[dict[str, Any]] = []
        for raw in lines[start_idx:]:
            raw = raw.strip()
            if not raw:
                continue
            try:
                step = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(step, dict):
                parsed_steps.append(step)

        for turn_steps in _split_steps_into_turns(parsed_steps):
            verdict, bad_reason = _classify_harvest_turn(turn_steps)
            if verdict == "session_taint":
                _mark_cid_tainted(cid, bad_reason or "untrusted_step", "instinct_daemon:harvest")
                tainted_cids.add(cid)
                state["poison_blocked_count"] = int(state.get("poison_blocked_count") or 0) + 1
                _record_guard_block(1)
                tainted_now = True
                new_obs.clear()
                log.warning("Blocked tainted/poisoned transcript %s at turn (%s)", cid[:12], bad_reason)
                break
            if verdict == "turn_skip":
                state["poison_blocked_count"] = int(state.get("poison_blocked_count") or 0) + 1
                _record_guard_block(1)
                log.info("Skipped single tainted external turn in transcript %s (%s)", cid[:12], bad_reason)
                continue

            for step in turn_steps:
                stype = step.get("type")
                ts = step.get("created_at") or now_iso

                if stype == "USER_INPUT":
                    raw_content = str(step.get("content") or "")
                    if "<STATELESS_TASK" in raw_content:
                        continue
                    user_txt = scrub_secrets(unwrap_user_request(raw_content))
                    if not user_txt or user_txt.startswith("/compact") or "<STATELESS_TASK" in user_txt:
                        continue
                    if CORRECTION_RE.search(user_txt):
                        saw_correction = True
                    new_obs.append(
                        {
                            "timestamp": ts,
                            "event": "user_prompt",
                            "session": cid[:8],
                            "input": user_txt[:1200],
                            "project_id": "global",
                            "project_name": "agy-workspace",
                        }
                    )
                elif stype == "PLANNER_RESPONSE":
                    tcalls = step.get("tool_calls") or []
                    if isinstance(tcalls, list):
                        for tc in tcalls[:6]:
                            if not isinstance(tc, dict):
                                continue
                            tname = str(tc.get("name") or tc.get("tool_name") or "tool")
                            targs = scrub_secrets(json.dumps(tc.get("arguments") or tc.get("args") or {}, ensure_ascii=False))
                            new_obs.append(
                                {
                                    "timestamp": ts,
                                    "event": "tool_start",
                                    "session": cid[:8],
                                    "tool": tname,
                                    "input": targs[:800],
                                    "project_id": "global",
                                    "project_name": "agy-workspace",
                                }
                            )
                    resp_txt = scrub_secrets(str(step.get("content") or "").strip())
                    if resp_txt:
                        new_obs.append(
                            {
                                "timestamp": ts,
                                "event": "assistant_reply",
                                "session": cid[:8],
                                "output": resp_txt[:800],
                                "project_id": "global",
                                "project_name": "agy-workspace",
                            }
                        )

        offsets[cid] = total
        if tainted_now:
            continue
        if new_obs:
            lock_p = _obs_lock_path()
            lock_p.parent.mkdir(parents=True, exist_ok=True)
            with open(lock_p, "a+", encoding="utf-8") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
                try:
                    with OBSERVATIONS_FILE.open("a", encoding="utf-8") as f:
                        for row in new_obs:
                            f.write(json.dumps(row, ensure_ascii=False) + "\n")
                finally:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
            appended += len(new_obs)
        if tainted_now:
            continue

    return appended, saw_correction


def _extract_action_from_body(body: str) -> str:
    act_m = re.search(r"## Action\s*\n([\s\S]*?)(?:\n## |\Z)", body or "")
    if act_m:
        return act_m.group(1).strip()
    return (body or "").strip()


def _extract_evidence_from_body(body: str) -> list[str]:
    ev_m = re.search(r"## Evidence\s*\n([\s\S]*?)$", body or "")
    src = ev_m.group(1) if ev_m else (body or "")
    return [e.strip() for e in re.findall(r"^- (.+)$", src, re.MULTILINE) if e.strip()]


def _extract_title_from_body(body: str, fallback: str) -> str:
    m = re.search(r"^#\s+(.+)$", body or "", re.MULTILINE)
    return m.group(1).strip() if m else fallback


def _extract_last_observed_date(meta: dict[str, Any]) -> date:
    body = str(meta.get("body") or "")
    matches = re.findall(r"Last observed:\s*(\d{4}-\d{2}-\d{2})", body)
    if matches:
        try:
            return datetime.strptime(matches[-1], "%Y-%m-%d").date()
        except ValueError:
            pass
    p = meta.get("path")
    if p:
        try:
            return datetime.fromtimestamp(Path(p).stat().st_mtime, tz=timezone.utc).date()
        except OSError:
            pass
    return datetime.now(timezone.utc).date()


def load_existing_instincts() -> dict[str, dict[str, Any]]:
    ensure_dirs()
    result: dict[str, dict[str, Any]] = {}
    for p in sorted(PERSONAL_INSTINCTS_DIR.glob("*.yaml")):
        try:
            txt = p.read_text(encoding="utf-8")
            m = re.match(r"^---\n([\s\S]*?)\n---\n([\s\S]*)$", txt)
            if not m:
                continue
            fm_raw, body = m.group(1), m.group(2).strip()
            meta: dict[str, Any] = {}
            for line in fm_raw.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                if v.startswith('"') and v.endswith('"'):
                    try:
                        v = json.loads(v)
                    except Exception:
                        v = v.strip('"')
                meta[k] = v
            iid = str(meta.get("id") or p.stem)
            meta["id"] = iid
            meta["confidence"] = float(meta.get("confidence") or 0.5)
            meta["body"] = body
            meta["action"] = _extract_action_from_body(body)
            meta["evidence"] = _extract_evidence_from_body(body)
            meta["title"] = _extract_title_from_body(body, iid.replace("-", " ").title())
            meta["path"] = str(p)
            result[iid] = meta
        except Exception:
            continue
    return result


def write_instinct_yaml(inst: dict[str, Any], *, preserve_last_observed: bool = False) -> Path:
    ensure_dirs()
    raw_id = str(inst.get("id") or "").strip().lower()
    clean_id = re.sub(r"[^a-z0-9._-]+", "-", raw_id).strip("-")[:80] or "learned-pattern"
    trigger = str(inst.get("trigger") or "when working in agy-workspace").strip()
    conf = max(0.30, min(0.95, round(float(inst.get("confidence") or 0.5), 2)))
    domain = re.sub(r"[^a-z0-9_-]+", "-", str(inst.get("domain") or "workflow").lower()).strip("-") or "workflow"
    title = str(inst.get("title") or clean_id.replace("-", " ").title()).strip()
    action = str(inst.get("action") or "").strip()
    evidence_list = inst.get("evidence") or []
    if isinstance(evidence_list, str):
        evidence_list = [evidence_list]

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ev_lines = [f"- {str(e).strip()}" for e in evidence_list if str(e).strip()][:6]
    if not preserve_last_observed:
        ev_lines = [e for e in ev_lines if not e.startswith("- Last observed:")]
        ev_lines.append(f"- Last observed: {today}")
    elif not any("Last observed" in e for e in ev_lines):
        ev_lines.append(f"- Last observed: {today}")

    yaml_text = (
        "---\n"
        f"id: {clean_id}\n"
        f"trigger: {json.dumps(trigger, ensure_ascii=False)}\n"
        f"confidence: {conf}\n"
        f"domain: {json.dumps(domain, ensure_ascii=False)}\n"
        'source: "session-observation"\n'
        "scope: global\n"
        "---\n\n"
        f"# {title}\n\n"
        "## Action\n"
        f"{action}\n\n"
        "## Evidence\n"
        + "\n".join(ev_lines)
        + "\n"
    )
    out_path = PERSONAL_INSTINCTS_DIR / f"{clean_id}.yaml"
    tmp = out_path.with_suffix(".yaml.tmp")
    tmp.write_text(yaml_text, encoding="utf-8")
    tmp.replace(out_path)
    return out_path


def touch_bridge_reloads() -> None:
    """Signal idle Telegram bridges to hot-reload updated skills/rules."""
    for rf in BRIDGE_RELOAD_FILES:
        try:
            rf.touch()
        except Exception:
            pass


def sync_claude_mem_recent_rule() -> bool:
    """Ensure rolling claude-mem timeline is NOT written as an `always_on` rule file."""
    if CLAUDE_MEM_RECENT_RULE_FILE.exists():
        try:
            CLAUDE_MEM_RECENT_RULE_FILE.unlink()
            return True
        except Exception:
            pass
    return False


def _write_text_if_changed(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    old = path.read_text(encoding="utf-8") if path.is_file() else ""
    if old == content:
        return False
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
    return True


def _ensure_global_plugin_manifest() -> bool:
    if GLOBAL_PLUGIN_DIR is None or GLOBAL_PLUGIN_MANIFEST is None:
        return False
    manifest = json.dumps(
        {
            "name": "ecc-instincts",
            "displayName": "ECC Learned Instincts",
            "version": "1.0.0",
            "description": (
                "Auto-synced high-confidence ECC learned instincts and evolved skills "
                "available globally across all Antigravity workspaces."
            ),
        },
        indent=2,
        ensure_ascii=False,
    ) + "\n"
    return _write_text_if_changed(GLOBAL_PLUGIN_MANIFEST, manifest)


def _select_active_instincts(
    existing: dict[str, dict[str, Any]],
    *,
    today: date | None = None,
) -> list[dict[str, Any]]:
    """Select active instincts via two-pool allocation (core >=0.80 + reserved recent >=0.70),
    breaking confidence ties by recency and outputting deterministic (domain, id) order.
    """
    ref_today = today or datetime.now(timezone.utc).date()
    valid: list[dict[str, Any]] = []
    for v in existing.values():
        ok, _reason = _validate_instinct_candidate(v, is_existing=True)
        if not ok:
            continue
        valid.append(v)

    # Pool 1: Core high-confidence instincts (>= 0.80), tie-broken by recency before id
    core_candidates = [v for v in valid if float(v.get("confidence", 0)) >= 0.80]
    core_candidates.sort(
        key=lambda x: (
            -float(x.get("confidence", 0)),
            -_extract_last_observed_date(x).toordinal(),
            str(x.get("id", "")),
        )
    )
    core_selected = core_candidates[: max(0, ACTIVE_RULE_CORE_SLOTS)]
    selected_ids = {str(x.get("id", "")) for x in core_selected}

    # Pool 2: Reserved recent slots so freshly learned/confirmed instincts take effect immediately
    recent_selected: list[dict[str, Any]] = []
    if ACTIVE_RULE_RECENT_SLOTS > 0:
        recent_candidates: list[dict[str, Any]] = []
        for v in valid:
            vid = str(v.get("id", ""))
            if vid in selected_ids:
                continue
            conf = float(v.get("confidence", 0))
            if conf < ACTIVE_RULE_RECENT_MIN_CONF:
                continue
            last_obs = _extract_last_observed_date(v)
            age_days = (ref_today - last_obs).days
            if age_days <= ACTIVE_RULE_RECENT_DAYS:
                recent_candidates.append(v)
        recent_candidates.sort(
            key=lambda x: (
                -_extract_last_observed_date(x).toordinal(),
                -float(x.get("confidence", 0)),
                str(x.get("id", "")),
            )
        )
        recent_selected = recent_candidates[:ACTIVE_RULE_RECENT_SLOTS]

    selected = core_selected + recent_selected
    # Sort deterministically by (domain, id) so minor confidence updates do not reorder or mutate <user_rules>
    selected.sort(key=lambda x: (str(x.get("domain", "general")), str(x.get("id", ""))))
    return selected


def sync_active_instincts_rule(*, today: date | None = None) -> tuple[int, bool]:
    """Render selected instincts into isolated `LOCAL_ACTIVE_RULE_FILE` ONLY.

    Strictly ZERO writes to `~/.gemini/config/plugins/ecc-instincts/` or shared
    `agy-workspace/.agents/rules/ecc-active-instincts.md` to prevent cross-bot rule leakage.
    """
    existing = load_existing_instincts()
    active = _select_active_instincts(existing, today=today)

    if not active:
        changed = False
        if ACTIVE_RULE_FILE.exists():
            ACTIVE_RULE_FILE.unlink()
            changed = True
        return 0, changed

    body_lines = [
        "# Learned Instincts (ECC Auto-Synced · Isolated)",
        "",
        "Apply these verified user & workflow preferences when their trigger matches:",
        "",
    ]
    for inst in active:
        trig = re.sub(r"^when\s+", "", str(inst.get("trigger", "")).strip(), flags=re.IGNORECASE)
        body = inst.get("body", "")
        act_m = re.search(r"## Action\s*\n\s*(.+?)(?:\n\n|\n##|$)", body, re.DOTALL)
        act_txt = act_m.group(1).strip().replace("\n", " ") if act_m else body.splitlines()[0]
        body_lines.append(f"- **[{inst.get('domain', 'general')}]** When {trig}: {act_txt}")

    rendered = "\n".join(body_lines) + "\n"
    changed = _write_text_if_changed(ACTIVE_RULE_FILE, rendered)
    return len(active), changed


def _clean_evolved_slug(raw_slug: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", raw_slug.lower()).strip("-")
    s = re.sub(r"^(?:evolved-)+", "", s).strip("-")
    return s


def _normalize_skill_frontmatter(md_text: str, clean_slug: str) -> str:
    expected_name = f"evolved-{clean_slug}"
    stripped = md_text.lstrip()
    m = re.match(r"^---\n([\s\S]*?)\n---\n([\s\S]*)$", stripped)
    if not m:
        return (
            "---\n"
            f"name: {expected_name}\n"
            f"description: Evolved skill auto-generated from high-confidence instincts ({clean_slug}).\n"
            "---\n\n" + stripped
        )
    fm_lines = m.group(1).splitlines()
    body = m.group(2)
    replaced = False
    new_fm_lines: list[str] = []
    for line in fm_lines:
        if re.match(r"^\s*name\s*:", line):
            new_fm_lines.append(f"name: {expected_name}")
            replaced = True
        else:
            new_fm_lines.append(line)
    if not replaced:
        new_fm_lines.insert(0, f"name: {expected_name}")
    return "---\n" + "\n".join(new_fm_lines) + "\n---\n" + body


def sync_evolved_skills() -> tuple[list[str], bool]:
    """Normalize evolved skills inside `EVOLVED_SKILLS_DIR` ONLY (zero writes to shared workspace or global plugin)."""
    synced: list[str] = []
    any_changed = False
    candidate_dirs = [EVOLVED_SKILLS_DIR]
    projects_root = HOMUNCULUS_DIR / "projects"
    if projects_root.is_dir():
        for pdir in projects_root.iterdir():
            es = pdir / "evolved" / "skills"
            if es.is_dir():
                candidate_dirs.append(es)

    by_slug: dict[str, tuple[tuple[int, int], str]] = {}
    for sroot in candidate_dirs:
        if not sroot.is_dir():
            continue
        for item in sorted(sroot.iterdir()):
            if item.is_dir() and (item / "SKILL.md").is_file():
                raw_slug = item.name
                src_text = (item / "SKILL.md").read_text(encoding="utf-8")
            elif item.is_file() and item.suffix == ".md":
                raw_slug = item.stem
                src_text = item.read_text(encoding="utf-8")
            else:
                continue

            clean_slug = _clean_evolved_slug(raw_slug)
            if not clean_slug:
                continue
            normalized = _normalize_skill_frontmatter(src_text, clean_slug)
            is_llm_rich = 0 if "Source instincts -" in src_text else 1
            rank = (is_llm_rich, len(normalized))
            prev = by_slug.get(clean_slug)
            if prev is None or rank > prev[0]:
                by_slug[clean_slug] = (rank, normalized)

    chosen = sorted(by_slug.items(), key=lambda kv: (-kv[1][0][0], -kv[1][0][1], kv[0]))[:MAX_EVOLVED_SKILLS]

    for clean_slug, (_rank, normalized) in sorted(chosen, key=lambda kv: kv[0]):
        dest_file = EVOLVED_SKILLS_DIR / clean_slug / "SKILL.md"
        if _write_text_if_changed(dest_file, normalized):
            any_changed = True
        synced.append(str(dest_file))
    return synced, any_changed


# ---------------------------------------------------------------------------
# Per-Bot Isolated Instincts & Evolved Skills Pipeline + Coordinator Aggregation
# ---------------------------------------------------------------------------


def _resolve_cid_owner_handle(
    cid: str,
    *,
    bus_dir: Path | None = None,
) -> str | None:
    """Resolve `cid` to its owning bot handle via `BUS_DIR/cid_owners.json` (with bus jobs fallback)."""
    bdir = bus_dir or BUS_DIR
    if _BOT_PROFILES is not None:
        owner = _BOT_PROFILES.lookup_cid_owner(cid, bus_dir=bdir)
        if owner:
            return owner
    else:
        owners_file = bdir / "cid_owners.json"
        if owners_file.is_file():
            try:
                data = json.loads(owners_file.read_text(encoding="utf-8", errors="replace"))
                entry = (data.get("owners") or {}).get(cid)
                if isinstance(entry, dict) and entry.get("handle"):
                    return str(entry["handle"]).strip().lower()
                if isinstance(entry, str) and entry.strip():
                    return entry.strip().lower()
            except Exception:
                pass

    # Fallback: inspect BUS_DIR/jobs/*.json for recorded worker conversation_id
    jobs_dir = bdir / "jobs"
    if jobs_dir.is_dir():
        try:
            for jf in jobs_dir.glob("*.json"):
                try:
                    jdata = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    continue
                if isinstance(jdata, dict) and str(jdata.get("conversation_id") or "") == cid:
                    tb = str(jdata.get("target_bot") or "").strip().lstrip("@").lower()
                    if tb:
                        return tb
        except OSError:
            pass
    return None


def _bot_instincts_paths(handle: str, *, profiles_dir: Path | None = None) -> dict[str, Path]:
    pdir = profiles_dir or BOT_PROFILES_DIR
    bdir = pdir / handle
    idir = bdir / "instincts"
    return {
        "bot_dir": bdir,
        "instincts_dir": idir,
        "observations": idir / "observations.jsonl",
        "personal": idir / "personal",
        "archived": idir / "archived",
        "active_md": idir / "active-instincts.md",
        "daemon_state": idir / "daemon_state.json",
        "skills_dir": bdir / "skills",
    }


def harvest_transcripts_per_bot(
    state: dict[str, Any],
    *,
    profiles_dir: Path | None = None,
    bus_dir: Path | None = None,
) -> dict[str, Any]:
    """Harvest clean transcripts strictly into each owning bot's `bots/<handle>/instincts/observations.jsonl`.

    - Unknown-owner CIDs are NEVER mixed into any Worker's observations.
    - Tainted sessions & poisoned steps are 100% blocked and marked in `memory_taint.json`.
    - Zero writes to global plugin or shared workspace `.agents/`.
    """
    pdir = profiles_dir or BOT_PROFILES_DIR
    bdir = bus_dir or BUS_DIR
    observer_cids = get_observer_cids()
    tainted_cids = _get_tainted_cids()
    offsets: dict[str, int] = state.setdefault("transcript_offsets", {})

    per_bot_appended: dict[str, int] = {}
    saw_correction_bots: set[str] = set()
    unknown_owner_skipped = 0
    tainted_skipped = 0

    if not BRAIN_ROOT.is_dir():
        return {
            "per_bot_appended": per_bot_appended,
            "saw_correction_bots": [],
            "unknown_owner_skipped": unknown_owner_skipped,
            "tainted_skipped": tainted_skipped,
        }

    for brain_dir in sorted(BRAIN_ROOT.iterdir()):
        if not brain_dir.is_dir():
            continue
        cid = brain_dir.name
        if cid in observer_cids:
            continue
        tpath = brain_dir / ".system_generated" / "logs" / "transcript.jsonl"
        if not tpath.is_file():
            continue

        owner_handle = _resolve_cid_owner_handle(cid, bus_dir=bdir)
        if not owner_handle:
            unknown_owner_skipped += 1
            continue

        try:
            lines = tpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        total = len(lines)

        if cid in tainted_cids:
            prev_off = int(offsets.get(cid) or 0)
            if prev_off < total:
                state["poison_blocked_count"] = int(state.get("poison_blocked_count") or 0) + 1
                _record_guard_block(1)
            offsets[cid] = total
            tainted_skipped += 1
            continue

        head_sample = "\n".join(lines[:12])
        if "<STATELESS_TASK>" in head_sample or "[ACB_SCHEDULED_TASK" in head_sample:
            if "[ACB_SCHEDULED_TASK" in head_sample:
                _mark_cid_tainted(cid, "marker:[ACB_SCHEDULED_TASK", "instinct_daemon:per_bot_head")
                tainted_cids.add(cid)
                tainted_skipped += 1
                _record_guard_block(1)
            offsets[cid] = total
            continue

        start_idx = int(offsets.get(cid) or 0)
        if start_idx > total:
            start_idx = 0
        if start_idx >= total:
            continue

        new_obs: list[dict[str, Any]] = []
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        parsed_steps: list[dict[str, Any]] = []
        for raw in lines[start_idx:]:
            raw = raw.strip()
            if not raw:
                continue
            try:
                step = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(step, dict):
                parsed_steps.append(step)

        for turn_steps in _split_steps_into_turns(parsed_steps):
            verdict, bad_reason = _classify_harvest_turn(turn_steps)
            if verdict == "session_taint":
                _mark_cid_tainted(cid, bad_reason or "untrusted_step", "instinct_daemon:per_bot")
                tainted_cids.add(cid)
                state["poison_blocked_count"] = int(state.get("poison_blocked_count") or 0) + 1
                _record_guard_block(1)
                tainted_skipped += 1
                new_obs.clear()
                break
            if verdict == "turn_skip":
                state["poison_blocked_count"] = int(state.get("poison_blocked_count") or 0) + 1
                _record_guard_block(1)
                tainted_skipped += 1
                continue

            for step in turn_steps:
                stype = step.get("type")
                ts = step.get("created_at") or now_iso
                if stype == "USER_INPUT":
                    raw_content = str(step.get("content") or "")
                    if "<STATELESS_TASK" in raw_content:
                        continue
                    user_txt = scrub_secrets(unwrap_user_request(raw_content))
                    if not user_txt or user_txt.startswith("/compact") or "<STATELESS_TASK" in user_txt:
                        continue
                    if CORRECTION_RE.search(user_txt):
                        saw_correction_bots.add(owner_handle)
                    new_obs.append(
                        {
                            "timestamp": ts,
                            "event": "user_prompt",
                            "session": cid[:8],
                            "input": user_txt[:1200],
                            "project_id": f"bot-{owner_handle}",
                            "project_name": f"bot-{owner_handle}",
                            "bot": owner_handle,
                        }
                    )
                elif stype == "PLANNER_RESPONSE":
                    resp_txt = scrub_secrets(str(step.get("content") or "").strip())
                    if resp_txt:
                        new_obs.append(
                            {
                                "timestamp": ts,
                                "event": "assistant_reply",
                                "session": cid[:8],
                                "output": resp_txt[:800],
                                "project_id": f"bot-{owner_handle}",
                                "project_name": f"bot-{owner_handle}",
                                "bot": owner_handle,
                            }
                        )

        offsets[cid] = total
        if new_obs:
            paths = _bot_instincts_paths(owner_handle, profiles_dir=pdir)
            paths["instincts_dir"].mkdir(parents=True, exist_ok=True)
            os.chmod(paths["bot_dir"], 0o700)
            os.chmod(paths["instincts_dir"], 0o700)
            obs_file = paths["observations"]
            lock_p = obs_file.with_name(obs_file.name + ".lock")
            with open(lock_p, "a+", encoding="utf-8") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
                try:
                    with obs_file.open("a", encoding="utf-8") as fh:
                        for row in new_obs:
                            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                    os.chmod(obs_file, 0o600)
                finally:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
            per_bot_appended[owner_handle] = per_bot_appended.get(owner_handle, 0) + len(new_obs)

    return {
        "per_bot_appended": per_bot_appended,
        "saw_correction_bots": sorted(saw_correction_bots),
        "unknown_owner_skipped": unknown_owner_skipped,
        "tainted_skipped": tainted_skipped,
    }


def load_bot_instincts(
    handle: str,
    *,
    profiles_dir: Path | None = None,
) -> dict[str, dict[str, Any]]:
    paths = _bot_instincts_paths(handle, profiles_dir=profiles_dir)
    p_dir = paths["personal"]
    if not p_dir.is_dir():
        return {}
    result: dict[str, dict[str, Any]] = {}
    for p in sorted(p_dir.glob("*.yaml")):
        try:
            txt = p.read_text(encoding="utf-8")
            m = re.match(r"^---\n([\s\S]*?)\n---\n([\s\S]*)$", txt)
            if not m:
                continue
            fm_raw, body = m.group(1), m.group(2).strip()
            meta: dict[str, Any] = {}
            for line in fm_raw.splitlines():
                if ":" not in line:
                    continue
                k, v = line.split(":", 1)
                k = k.strip()
                v = v.strip()
                if v.startswith('"') and v.endswith('"'):
                    try:
                        v = json.loads(v)
                    except Exception:
                        v = v.strip('"')
                meta[k] = v
            iid = str(meta.get("id") or p.stem)
            meta["id"] = iid
            meta["confidence"] = float(meta.get("confidence") or 0.5)
            meta["body"] = body
            meta["action"] = _extract_action_from_body(body)
            meta["evidence"] = _extract_evidence_from_body(body)
            meta["title"] = _extract_title_from_body(body, iid.replace("-", " ").title())
            meta["path"] = str(p)
            result[iid] = meta
        except Exception:
            continue
    return result


def write_bot_instinct_yaml(
    handle: str,
    inst: dict[str, Any],
    *,
    profiles_dir: Path | None = None,
    preserve_last_observed: bool = False,
) -> Path | None:
    ok, _reason = _validate_instinct_candidate(inst, is_existing=False)
    if not ok:
        _record_guard_block(1)
        return None
    paths = _bot_instincts_paths(handle, profiles_dir=profiles_dir)
    paths["personal"].mkdir(parents=True, exist_ok=True)
    os.chmod(paths["bot_dir"], 0o700)
    os.chmod(paths["instincts_dir"], 0o700)
    os.chmod(paths["personal"], 0o700)

    raw_id = str(inst.get("id") or "").strip().lower()
    clean_id = re.sub(r"[^a-z0-9._-]+", "-", raw_id).strip("-")[:80] or "learned-pattern"
    trigger = str(inst.get("trigger") or f"when operating as @{handle}").strip()
    conf = max(0.30, min(0.95, round(float(inst.get("confidence") or 0.5), 2)))
    domain = re.sub(r"[^a-z0-9_-]+", "-", str(inst.get("domain") or "workflow").lower()).strip("-") or "workflow"
    title = str(inst.get("title") or clean_id.replace("-", " ").title()).strip()
    action = str(inst.get("action") or "").strip()
    evidence_list = inst.get("evidence") or []
    if isinstance(evidence_list, str):
        evidence_list = [evidence_list]
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ev_lines = [f"- {str(e).strip()}" for e in evidence_list if str(e).strip()][:6]
    if not preserve_last_observed:
        ev_lines = [e for e in ev_lines if not e.startswith("- Last observed:")]
        ev_lines.append(f"- Last observed: {today}")
    elif not any("Last observed" in e for e in ev_lines):
        ev_lines.append(f"- Last observed: {today}")

    yaml_text = (
        "---\n"
        f"id: {clean_id}\n"
        f"trigger: {json.dumps(trigger, ensure_ascii=False)}\n"
        f"confidence: {conf}\n"
        f"domain: {json.dumps(domain, ensure_ascii=False)}\n"
        'source: "session-observation"\n'
        f"scope: bot-{handle}\n"
        "---\n\n"
        f"# {title}\n\n"
        "## Action\n"
        f"{action}\n\n"
        "## Evidence\n"
        + "\n".join(ev_lines)
        + "\n"
    )
    out_path = paths["personal"] / f"{clean_id}.yaml"
    tmp = out_path.with_suffix(".yaml.tmp")
    tmp.write_text(yaml_text, encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(out_path)
    os.chmod(out_path, 0o600)
    return out_path


def sync_bot_active_instincts(
    handle: str,
    *,
    profiles_dir: Path | None = None,
    today: date | None = None,
) -> tuple[int, bool]:
    """Deterministically render `bots/<handle>/instincts/active-instincts.md` (`0600`) with zero global writes."""
    paths = _bot_instincts_paths(handle, profiles_dir=profiles_dir)
    existing = load_bot_instincts(handle, profiles_dir=profiles_dir)
    active = _select_active_instincts(existing, today=today)
    target = paths["active_md"]
    if not active:
        if target.exists():
            target.unlink()
            return 0, True
        return 0, False

    lines = [
        f"# Learned Instincts for @{handle}",
        "",
        "Apply these verified preferences when their trigger matches:",
        "",
    ]
    for inst in active:
        trig = re.sub(r"^when\s+", "", str(inst.get("trigger", "")).strip(), flags=re.IGNORECASE)
        body = inst.get("body", "")
        act_m = re.search(r"## Action\s*\n\s*(.+?)(?:\n\n|\n##|$)", body, re.DOTALL)
        act_txt = act_m.group(1).strip().replace("\n", " ") if act_m else body.splitlines()[0]
        lines.append(f"- **[{inst.get('domain', 'general')}]** When {trig}: {act_txt}")

    rendered = "\n".join(lines) + "\n"
    changed = _write_text_if_changed(target, rendered)
    if target.is_file():
        os.chmod(target, 0o600)
    return len(active), changed


def sync_bot_evolved_skills(
    handle: str,
    *,
    evolved_items: dict[str, str] | None = None,
    profiles_dir: Path | None = None,
) -> tuple[list[str], bool]:
    """Write evolved skills strictly into `bots/<handle>/skills/evolved-<slug>/SKILL.md` (`0600`)."""
    paths = _bot_instincts_paths(handle, profiles_dir=profiles_dir)
    paths["skills_dir"].mkdir(parents=True, exist_ok=True)
    os.chmod(paths["bot_dir"], 0o700)
    os.chmod(paths["skills_dir"], 0o700)

    synced: list[str] = []
    any_changed = False
    src_map = evolved_items or {}
    for raw_slug, md_text in sorted(src_map.items()):
        clean_slug = _clean_evolved_slug(raw_slug)
        if not clean_slug:
            continue
        bad_md, _ = _inspect_text(f"{clean_slug}\n{md_text}")
        if bad_md:
            _record_guard_block(1)
            continue
        normalized = _normalize_skill_frontmatter(md_text, clean_slug)
        dest_dir = paths["skills_dir"] / f"evolved-{clean_slug}"
        dest_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(dest_dir, 0o700)
        dest_file = dest_dir / "SKILL.md"
        if _write_text_if_changed(dest_file, normalized):
            any_changed = True
        os.chmod(dest_file, 0o600)
        synced.append(str(dest_file))
    return synced, any_changed


def _list_bot_profile_handles(profiles_dir: Path | None = None) -> list[str]:
    pdir = profiles_dir or BOT_PROFILES_DIR
    handles: list[str] = []
    if pdir.is_dir():
        for ent in sorted(pdir.iterdir()):
            if ent.is_dir() and not ent.is_symlink() and not ent.name.startswith("."):
                handles.append(ent.name)
    return handles


def _archive_bot_instinct_file(src_path: Path, archived_dir: Path, tag: str) -> Path:
    archived_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(archived_dir, 0o700)
    ts_tag = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    dest = archived_dir / f"{src_path.stem}-{tag}-{ts_tag}{src_path.suffix}"
    counter = 1
    while dest.exists():
        dest = archived_dir / f"{src_path.stem}-{tag}-{ts_tag}-{counter}{src_path.suffix}"
        counter += 1
    shutil.move(str(src_path), str(dest))
    os.chmod(dest, 0o600)
    return dest


def _compact_bot_observations_if_needed(
    handle: str,
    state: dict[str, Any],
    *,
    dry_run: bool = False,
    profiles_dir: Path | None = None,
    max_lines: int | None = None,
    keep_tail: int | None = None,
) -> dict[str, int]:
    """Compress & gzip-archive a single bot's `observations.jsonl` into `bots/<handle>/instincts/archived/`."""
    res = {"total_before": 0, "archived_lines": 0, "dropped_poison": 0, "total_after": 0}
    paths = _bot_instincts_paths(handle, profiles_dir=profiles_dir)
    obs_file = paths["observations"]
    if not obs_file.is_file():
        return res

    max_l = DREAM_MAX_OBS_LINES if max_lines is None else max(20, int(max_lines))
    tail_n = DREAM_OBS_KEEP_TAIL if keep_tail is None else max(0, int(keep_tail))

    lock_p = obs_file.with_name(obs_file.name + ".lock")
    lock_p.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_p, "a+", encoding="utf-8") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            lines = obs_file.read_text(encoding="utf-8", errors="replace").splitlines()
            total = len(lines)
            res["total_before"] = total
            if total <= max_l:
                res["total_after"] = total
                return res

            fresh_state = load_daemon_state() if DAEMON_STATE_FILE.exists() else state
            pb_offsets = fresh_state.get("per_bot_obs_offsets") or state.get("per_bot_obs_offsets") or {}
            last_idx = int(pb_offsets.get(handle) or 0)
            last_idx = max(0, min(total, last_idx))
            effective_tail = min(tail_n, last_idx)
            archive_end = max(0, last_idx - effective_tail)
            if archive_end <= 0:
                res["total_after"] = total
                return res

            raw_archive = lines[:archive_end]
            raw_remaining = lines[archive_end:]
            analyzed_in_remaining = last_idx - archive_end

            clean_archive: list[str] = []
            for ln in raw_archive:
                bad, _ = _inspect_text(ln)
                if bad:
                    res["dropped_poison"] += 1
                    continue
                clean_archive.append(ln)

            clean_remaining: list[str] = []
            new_last_idx = analyzed_in_remaining
            for idx, ln in enumerate(raw_remaining):
                bad, _ = _inspect_text(ln)
                if bad:
                    res["dropped_poison"] += 1
                    if idx < analyzed_in_remaining:
                        new_last_idx = max(0, new_last_idx - 1)
                    continue
                clean_remaining.append(ln)

            res["archived_lines"] = len(clean_archive)
            res["total_after"] = len(clean_remaining)

            if not dry_run:
                if clean_archive:
                    paths["archived"].mkdir(parents=True, exist_ok=True)
                    os.chmod(paths["archived"], 0o700)
                    ym = datetime.now(timezone.utc).strftime("%Y%m")
                    gz_path = paths["archived"] / f"observations-{ym}.jsonl.gz"
                    with gzip.open(gz_path, "at", encoding="utf-8") as gz:
                        for ln in clean_archive:
                            gz.write(ln + "\n")
                    os.chmod(gz_path, 0o600)

                tmp = obs_file.with_name(f".{obs_file.name}.{os.getpid()}.tmp")
                tmp.write_text(("\n".join(clean_remaining) + "\n") if clean_remaining else "", encoding="utf-8")
                os.chmod(tmp, 0o600)
                tmp.replace(obs_file)
                os.chmod(obs_file, 0o600)
                if res["dropped_poison"]:
                    _record_guard_block(res["dropped_poison"])

                def _commit_bot_compact(latest: dict[str, Any]) -> None:
                    offs = latest.setdefault("per_bot_obs_offsets", {})
                    offs[handle] = new_last_idx
                    gens = latest.setdefault("per_bot_obs_compaction_gen", {})
                    gens[handle] = int(gens.get(handle) or 0) + 1
                    if res["dropped_poison"]:
                        latest["poison_blocked_count"] = (
                            int(latest.get("poison_blocked_count") or 0) + res["dropped_poison"]
                        )

                updated_st = _update_daemon_state(_commit_bot_compact)
                state["per_bot_obs_offsets"] = updated_st.get("per_bot_obs_offsets") or {}
                state["per_bot_obs_compaction_gen"] = updated_st.get("per_bot_obs_compaction_gen") or {}
                state["poison_blocked_count"] = updated_st.get("poison_blocked_count") or 0
            return res
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def evolve_bot_skills(
    handle: str,
    *,
    profiles_dir: Path | None = None,
    quiet: bool = True,
) -> dict[str, Any]:
    """Synthesize or refresh one evolved skill strictly inside `bots/<handle>/skills/evolved-<slug>/SKILL.md`."""
    pdir = profiles_dir or BOT_PROFILES_DIR
    paths = _bot_instincts_paths(handle, profiles_dir=pdir)
    existing = load_bot_instincts(handle, profiles_dir=pdir)
    strong = [v for v in existing.values() if float(v.get("confidence", 0)) >= 0.70]
    strong.sort(
        key=lambda x: (
            -_extract_last_observed_date(x).toordinal(),
            -float(x.get("confidence", 0)),
            str(x.get("id", "")),
        )
    )
    existing_own_dirs = (
        [d for d in sorted(paths["skills_dir"].iterdir()) if d.is_dir() and not d.is_symlink() and (d / "SKILL.md").is_file()]
        if paths["skills_dir"].is_dir()
        else []
    )
    existing_skill_names = sorted(d.name for d in existing_own_dirs)
    existing_evolved_slugs = sorted(
        {
            _clean_evolved_slug(d.name)
            for d in existing_own_dirs
            if d.name.startswith("evolved-") and _clean_evolved_slug(d.name)
        }
    )
    at_skill_cap = len(existing_evolved_slugs) >= MAX_EVOLVED_SKILLS
    synced: list[str] = []
    changed = False

    if len(strong) >= 3:
        cap_instruction = (
            "Skill count is at cap: you MUST refresh one existing `evolved-*` slug from `existing_evolved_slugs` "
            "(returning that exact slug without the `evolved-` prefix) by merging new strong instincts into it, "
            "or output `{}` if none needs updating."
            if at_skill_cap
            else (
                "If 3 or more instincts form a coherent reusable workflow/domain NOT already covered by existing "
                "bot skills, synthesize ONE new Antigravity SKILL.md bundle; OR if an existing `evolved-*` "
                "skill in `existing_evolved_slugs` is missing recent strong instincts, refresh it by returning its "
                "existing slug."
            )
        )
        sys_p = (
            f"You are the ECC Skill Evolution Engine for bot @{handle}.\n"
            f"{cap_instruction}\n"
            "Output strict JSON: "
            '{"slug":"short-kebab-name","description":"When to activate this skill","markdown":"Full markdown body (without frontmatter)"}. '
            "Do NOT include an `evolved-` prefix in `slug`. "
            "If nothing new or worth refreshing remains, output `{}`."
        )
        usr_p = json.dumps(
            {
                "bot": handle,
                "already_existing_skills": existing_skill_names,
                "existing_evolved_slugs": existing_evolved_slugs,
                "at_skill_cap": at_skill_cap,
                "strong_instincts": [
                    {
                        "id": v.get("id"),
                        "trigger": v.get("trigger"),
                        "confidence": v.get("confidence"),
                        "domain": v.get("domain"),
                        "last_observed": _extract_last_observed_date(v).strftime("%Y-%m-%d"),
                        "body": v.get("body"),
                    }
                    for v in strong[:40]
                ],
            },
            ensure_ascii=False,
        )
        try:
            raw = call_shim_json(sys_p, usr_p, timeout=150)
            obj_m = re.search(r"\{[\s\S]*\}", raw)
            if obj_m:
                data = json.loads(obj_m.group(0))
                slug = _clean_evolved_slug(str(data.get("slug") or ""))
                md = str(data.get("markdown") or "").strip()
                desc = str(data.get("description") or "").strip()
                bad_md, _ = _inspect_text(f"{slug}\n{desc}\n{md}")
                allowed_slug = (not at_skill_cap) or (slug in existing_evolved_slugs)
                if slug and md and desc and not bad_md and allowed_slug:
                    full_md = (
                        "---\n"
                        f"name: evolved-{slug}\n"
                        f"description: {json.dumps(desc, ensure_ascii=False)}\n"
                        "---\n\n"
                        f"{md}\n"
                    )
                    synced, changed = sync_bot_evolved_skills(
                        handle,
                        evolved_items={slug: full_md},
                        profiles_dir=pdir,
                    )
        except Exception as e:
            if not quiet:
                log.warning("Per-bot LLM skill synthesis skipped for @%s: %s", handle, e)

    return {
        "handle": handle,
        "strong_instincts": len(strong),
        "synced_skills": synced,
        "changed": changed,
    }


def evolve_per_bot_skills(
    *,
    profiles_dir: Path | None = None,
    quiet: bool = False,
) -> dict[str, Any]:
    """Run per-bot skill evolution across all registered bots (zero global plugin or shared workspace writes)."""
    pdir = profiles_dir or BOT_PROFILES_DIR
    per_bot: dict[str, Any] = {}
    for handle in _list_bot_profile_handles(pdir):
        per_bot[handle] = evolve_bot_skills(handle, profiles_dir=pdir, quiet=quiet)
    return {
        "mode": "per_bot",
        "per_bot": per_bot,
        "coordinator_aggregation": build_coordinator_aggregation_view(profiles_dir=pdir),
    }


def analyze_per_bot_observations_batch(
    force: bool = False,
    *,
    profiles_dir: Path | None = None,
    bus_dir: Path | None = None,
) -> dict[str, Any]:
    """Per-bot isolated transcript harvesting, LLM instinct extraction, active-instincts sync & skill evolution.

    Strictly isolates observations, personal YAML instincts, active-instincts.md, and evolved skills
    under `bots/<handle>/` (`0700`/`0600`) with zero writes to global plugin or shared `.agents/`.
    """
    ensure_dirs()
    pdir = profiles_dir or BOT_PROFILES_DIR
    bdir = bus_dir or BUS_DIR

    state = load_daemon_state()
    poison_before_harvest = int(state.get("poison_blocked_count") or 0)
    harvest_res = harvest_transcripts_per_bot(state, profiles_dir=pdir, bus_dir=bdir)
    harvest_poison_delta = max(0, int(state.get("poison_blocked_count") or 0) - poison_before_harvest)
    harvested_offsets = dict(state.get("transcript_offsets") or {})
    saw_corr_bots = list(harvest_res.get("saw_correction_bots") or [])

    def _save_per_bot_harvest(latest: dict[str, Any]) -> None:
        offsets = latest.setdefault("transcript_offsets", {})
        for cid, off in harvested_offsets.items():
            offsets[cid] = max(int(offsets.get(cid) or 0), int(off))
        pb_corr = latest.setdefault("per_bot_pending_correction", {})
        for h in saw_corr_bots:
            pb_corr[h] = True
        if harvest_poison_delta:
            latest["poison_blocked_count"] = int(latest.get("poison_blocked_count") or 0) + harvest_poison_delta

    state = _update_daemon_state(_save_per_bot_harvest)

    handles = sorted(
        set(_list_bot_profile_handles(pdir))
        | set((harvest_res.get("per_bot_appended") or {}).keys())
    )
    bots_results: dict[str, Any] = {}
    any_analyzed = False

    sys_prompt = (
        "You are the ECC Continuous-Learning v2.1 Observer Engine running on Antigravity CLI.\n"
        "Analyze session observations (user prompts/corrections, tool usage, error fixes, repeated workflows) "
        "and extract ONLY genuinely reusable atomic instincts for this specific bot.\n"
        "Rules:\n"
        "1. Be conservative: ignore one-off trivial Q&A; prioritize explicit user preferences/corrections, "
        "infrastructure conventions, and repeated multi-step workflows.\n"
        "2. Merge with existing instincts by reusing the same `id` and increasing `confidence` (+0.05..+0.15) "
        "when re-confirmed, or decreasing (-0.10) if contradicted.\n"
        "3. Initial confidence: explicit user rule/correction = 0.65..0.75; repeated workflow = 0.45..0.60; tentative = 0.35.\n"
        "4. Never include raw secrets, tokens, or personal data.\n"
        "5. Output STRICTLY a JSON array (no markdown prose outside JSON): "
        '[{"id":"kebab-case-id","title":"Short Title","trigger":"when ...","action":"Concise actionable rule","domain":"workflow|code-style|ops|debugging|security|telegram","confidence":0.65,"evidence":["brief evidence 1"]}] '
        "or `[]` if no clear reusable pattern is present."
    )

    for handle in handles:
        paths = _bot_instincts_paths(handle, profiles_dir=pdir)
        obs_file = paths["observations"]
        if not obs_file.is_file():
            bots_results[handle] = {"status": "no_observations"}
            continue

        lock_p = obs_file.with_name(obs_file.name + ".lock")
        lock_p.parent.mkdir(parents=True, exist_ok=True)
        with open(lock_p, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_SH)
            try:
                cur_state = load_daemon_state()
                all_lines = obs_file.read_text(encoding="utf-8", errors="replace").splitlines()
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

        pb_gens = cur_state.get("per_bot_obs_compaction_gen") or {}
        start_compaction_gen = int(pb_gens.get(handle) or 0)
        pb_offsets = cur_state.get("per_bot_obs_offsets") or {}
        last_idx = int(pb_offsets.get(handle) or 0)
        if last_idx > len(all_lines):
            last_idx = 0
        batch_end_idx = len(all_lines)
        last_batch_line = all_lines[-1] if all_lines else ""

        pending_raw = all_lines[last_idx:]
        pending: list[str] = []
        obs_poison_delta = 0
        for ln in pending_raw:
            bad, _reason = _inspect_text(ln)
            if bad:
                obs_poison_delta += 1
                _record_guard_block(1)
                continue
            pending.append(ln)

        pb_corr_map = cur_state.get("per_bot_pending_correction") or {}
        effective_corr = (handle in saw_corr_bots) or bool(pb_corr_map.get(handle))
        min_needed = MIN_OBS_ON_CORRECTION if effective_corr else MIN_OBS_FOR_BATCH
        effective_cooldown = CORRECTION_COOLDOWN_SEC if effective_corr else ANALYSIS_COOLDOWN_SEC
        pb_last_ts_map = cur_state.get("per_bot_last_analysis_ts") or {}
        last_ts = float(pb_last_ts_map.get(handle) or 0.0)

        if not force:
            if len(pending) < min_needed:
                if obs_poison_delta:
                    _update_daemon_state(
                        lambda st, d=obs_poison_delta: st.__setitem__(
                            "poison_blocked_count", int(st.get("poison_blocked_count") or 0) + d
                        )
                    )
                bots_results[handle] = {
                    "status": "waiting_for_more",
                    "pending": len(pending),
                    "needed": min_needed,
                }
                continue
            if (time.time() - last_ts) < effective_cooldown:
                if obs_poison_delta:
                    _update_daemon_state(
                        lambda st, d=obs_poison_delta: st.__setitem__(
                            "poison_blocked_count", int(st.get("poison_blocked_count") or 0) + d
                        )
                    )
                bots_results[handle] = {
                    "status": "cooldown",
                    "pending": len(pending),
                    "cooldown_sec": effective_cooldown,
                }
                continue

        if not pending:
            def _commit_bot_empty(
                latest: dict[str, Any],
                *,
                _h: str = handle,
                _gen: int = start_compaction_gen,
                _end: int = batch_end_idx,
                _pd: int = obs_poison_delta,
            ) -> None:
                gens = latest.get("per_bot_obs_compaction_gen") or {}
                if int(gens.get(_h) or 0) == _gen:
                    offs = latest.setdefault("per_bot_obs_offsets", {})
                    offs[_h] = max(int(offs.get(_h) or 0), _end)
                latest.setdefault("per_bot_pending_correction", {})[_h] = False
                if _pd:
                    latest["poison_blocked_count"] = int(latest.get("poison_blocked_count") or 0) + _pd

            _update_daemon_state(_commit_bot_empty)
            bots_results[handle] = {"status": "up_to_date", "updated": 0}
            continue

        batch_slice = pending[-60:]
        existing = load_bot_instincts(handle, profiles_dir=pdir)
        existing_summary = [
            {
                "id": k,
                "trigger": v.get("trigger"),
                "confidence": v.get("confidence"),
                "domain": v.get("domain"),
            }
            for k, v in existing.items()
        ]
        usr_prompt = (
            f"Bot handle: @{handle}\n"
            f"Existing instincts:\n{json.dumps(existing_summary, ensure_ascii=False)}\n\n"
            f"Recent observations ({len(batch_slice)} items):\n" + "\n".join(batch_slice)
        )

        raw_reply = call_shim_json(sys_prompt, usr_prompt, timeout=150)
        arr_match = re.search(r"\[[\s\S]*\]", raw_reply)
        items: list[dict[str, Any]] = []
        if arr_match:
            try:
                parsed = json.loads(arr_match.group(0))
                if isinstance(parsed, list):
                    items = [x for x in parsed if isinstance(x, dict) and x.get("id") and x.get("action")]
            except json.JSONDecodeError:
                log.warning("Could not parse JSON array from per-bot observer reply (@%s): %s", handle, raw_reply[:250])

        written_ids: list[str] = []
        blocked_candidates = 0
        for item in items[:8]:
            iid = re.sub(r"[^a-z0-9._-]+", "-", str(item["id"]).lower()).strip("-")
            if iid in existing:
                old_ev = [e for e in (existing[iid].get("evidence") or []) if not e.startswith("Last observed:")]
                new_ev = item.get("evidence") or []
                if isinstance(new_ev, str):
                    new_ev = [new_ev]
                item["evidence"] = list(dict.fromkeys(old_ev + [str(x) for x in new_ev]))[-5:]
            out_p = write_bot_instinct_yaml(handle, item, profiles_dir=pdir)
            if out_p is None:
                blocked_candidates += 1
                continue
            written_ids.append(out_p.stem)

        now_ts = time.time()
        total_poison_delta = obs_poison_delta + blocked_candidates

        def _commit_bot_analysis(
            latest: dict[str, Any],
            *,
            _h: str = handle,
            _gen: int = start_compaction_gen,
            _start: int = last_idx,
            _end: int = batch_end_idx,
            _last_ln: str = last_batch_line,
            _obs_f: Path = obs_file,
            _now: float = now_ts,
            _pd: int = total_poison_delta,
        ) -> None:
            gens = latest.get("per_bot_obs_compaction_gen") or {}
            offs = latest.setdefault("per_bot_obs_offsets", {})
            if int(gens.get(_h) or 0) == _gen:
                offs[_h] = max(int(offs.get(_h) or 0), _end)
            else:
                cur_lines = (
                    _obs_f.read_text(encoding="utf-8", errors="replace").splitlines()
                    if _obs_f.is_file()
                    else []
                )
                cur_idx = int(offs.get(_h) or 0)
                if _last_ln:
                    found_pos = None
                    for idx_c in range(max(0, cur_idx), len(cur_lines)):
                        if cur_lines[idx_c] == _last_ln:
                            found_pos = idx_c + 1
                    if found_pos is not None:
                        offs[_h] = found_pos
                    else:
                        offs[_h] = min(len(cur_lines), cur_idx + max(0, _end - _start))
                else:
                    offs[_h] = min(len(cur_lines), cur_idx)
            latest.setdefault("per_bot_last_analysis_ts", {})[_h] = _now
            latest.setdefault("per_bot_pending_correction", {})[_h] = False
            if _pd:
                latest["poison_blocked_count"] = int(latest.get("poison_blocked_count") or 0) + _pd

        state = _update_daemon_state(_commit_bot_analysis)

        active_count, _active_changed = sync_bot_active_instincts(handle, profiles_dir=pdir)
        latest_instincts = load_bot_instincts(handle, profiles_dir=pdir)
        by_domain: dict[str, list[dict[str, Any]]] = {}
        for v in latest_instincts.values():
            if float(v.get("confidence", 0)) >= 0.80:
                dom = str(v.get("domain") or "general")
                by_domain.setdefault(dom, []).append(v)

        pb_ev_counts_all = state.get("per_bot_evolved_domain_counts") or {}
        dom_counts: dict[str, int] = {}
        if isinstance(pb_ev_counts_all.get(handle), dict):
            for k, val in pb_ev_counts_all[handle].items():
                try:
                    dom_counts[str(k)] = int(val)
                except (TypeError, ValueError):
                    pass

        ready_domains = [
            d
            for d, items_d in by_domain.items()
            if len(items_d) >= 3 and (d not in dom_counts or len(items_d) >= dom_counts[d] + EVOLVE_DELTA_MIN)
        ]
        pb_last_ev_map = state.get("per_bot_last_evolve_ts") or {}
        last_ev_ts = float(pb_last_ev_map.get(handle) or 0.0)
        evolve_due = (not last_ev_ts) or ((now_ts - last_ev_ts) >= EVOLVE_COOLDOWN_SEC)
        evolved_skills: list[str] = []
        if ready_domains and evolve_due:
            ev_res = evolve_bot_skills(handle, profiles_dir=pdir, quiet=True)
            evolved_skills = list(ev_res.get("synced_skills") or [])

            def _record_bot_evolved(
                latest: dict[str, Any],
                *,
                _h: str = handle,
                _ready: list[str] = ready_domains,
                _by_dom: dict[str, list[dict[str, Any]]] = by_domain,
                _now: float = now_ts,
            ) -> None:
                ev_map = latest.setdefault("per_bot_evolved_domain_counts", {}).setdefault(_h, {})
                for d in _ready:
                    ev_map[d] = len(_by_dom.get(d) or [])
                latest.setdefault("per_bot_last_evolve_ts", {})[_h] = _now

            _update_daemon_state(_record_bot_evolved)

        any_analyzed = True
        bots_results[handle] = {
            "status": "analyzed",
            "observations_processed": len(pending),
            "instincts_written": written_ids,
            "candidates_blocked": blocked_candidates,
            "active_instincts_synced": active_count,
            "evolved_skills_synced": evolved_skills,
        }

    sync_claude_mem_recent_rule()
    return {
        "status": "analyzed" if any_analyzed else ("up_to_date" if bots_results else "no_observations"),
        "mode": "per_bot",
        "harvest": harvest_res,
        "per_bot": bots_results,
        "reloads_armed": False,
    }


def run_per_bot_dream(
    *,
    dry_run: bool = False,
    force: bool = False,
    quiet: bool = False,
    use_llm: bool = False,
    profiles_dir: Path | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    """Per-bot Dream consolidation across every bot under `profiles_dir`.

    For each bot independently:
    1. Re-validates personal instincts & quarantines unsafe entries to `bots/<handle>/instincts/archived/`
    2. Applies gentle time decay & archives below-threshold instincts to `bots/<handle>/instincts/archived/`
    3. Deduplicates/merges similar domain instincts within that bot only
    4. Compacts `bots/<handle>/instincts/observations.jsonl` with rolling gzip archive
    5. Deterministically refreshes `bots/<handle>/instincts/active-instincts.md` (`0600`)
    """
    ensure_dirs()
    pdir = profiles_dir or BOT_PROFILES_DIR
    state = load_daemon_state()
    now_ts = time.time()
    last_dream_ts = float(state.get("per_bot_last_dream_ts") or 0.0)
    if not force and (now_ts - last_dream_ts) < DREAM_INTERVAL_SEC:
        return {
            "status": "cooldown",
            "mode": "per_bot",
            "last_dream_ts": last_dream_ts,
            "next_due_in_sec": int(DREAM_INTERVAL_SEC - (now_ts - last_dream_ts)),
        }

    ref_today = today or datetime.now(timezone.utc).date()
    handles = _list_bot_profile_handles(pdir)
    per_bot_results: dict[str, Any] = {}
    total_quarantine_poison = 0

    for handle in handles:
        paths = _bot_instincts_paths(handle, profiles_dir=pdir)
        existing = load_bot_instincts(handle, profiles_dir=pdir)
        quarantined_ids: list[str] = []
        decayed_ids: list[str] = []
        archived_low_conf_ids: list[str] = []
        merged_groups: list[dict[str, Any]] = []
        survivors: list[dict[str, Any]] = []

        for iid, meta in sorted(existing.items()):
            ok, bad_reason = _validate_instinct_candidate(meta, is_existing=True)
            if not ok:
                quarantined_ids.append(iid)
                if not dry_run:
                    _archive_bot_instinct_file(Path(meta["path"]), paths["archived"], "quarantined")
                    total_quarantine_poison += 1
                    _record_guard_block(1)
                log.warning("Per-bot Dream quarantined unsafe instinct @%s/%s (%s)", handle, iid, bad_reason)
                continue

            last_obs = _extract_last_observed_date(meta)
            days_stale = max(0, (ref_today - last_obs).days)
            old_conf = float(meta.get("confidence") or 0.5)
            new_conf = old_conf
            if days_stale > DREAM_DECAY_GRACE_DAYS:
                weeks_over = (days_stale - DREAM_DECAY_GRACE_DAYS) / 7.0
                decay = round(min(0.30, max(0.02, weeks_over * 0.03)), 2)
                new_conf = round(max(0.10, old_conf - decay), 2)

            if new_conf < DREAM_ARCHIVE_CONF:
                archived_low_conf_ids.append(iid)
                if not dry_run:
                    _archive_bot_instinct_file(Path(meta["path"]), paths["archived"], "decayed")
                continue

            updated = dict(meta)
            if new_conf != old_conf:
                updated["confidence"] = new_conf
                decayed_ids.append(iid)
                if not dry_run:
                    write_bot_instinct_yaml(handle, updated, profiles_dir=pdir, preserve_last_observed=True)
            survivors.append(updated)

        by_domain: dict[str, list[dict[str, Any]]] = {}
        for item in survivors:
            dom = str(item.get("domain") or "workflow").lower()
            by_domain.setdefault(dom, []).append(item)

        for _dom, dom_items in sorted(by_domain.items()):
            used: set[str] = set()
            for i, anchor in enumerate(dom_items):
                aid = str(anchor["id"])
                if aid in used:
                    continue
                cluster = [anchor]
                used.add(aid)
                for cand in dom_items[i + 1 :]:
                    cid = str(cand["id"])
                    if cid in used:
                        continue
                    if _instinct_similarity(anchor, cand) >= 0.50:
                        cluster.append(cand)
                        used.add(cid)
                if len(cluster) >= 2:
                    merged = _merge_instinct_cluster(cluster, use_llm=use_llm)
                    ok, _ = _validate_instinct_candidate(merged, is_existing=True)
                    if not ok:
                        continue
                    merged_id = str(merged["id"])
                    absorbed = [c for c in cluster if str(c["id"]) != merged_id]
                    merged_groups.append({"kept": merged_id, "absorbed": [str(a["id"]) for a in absorbed]})
                    if not dry_run:
                        write_bot_instinct_yaml(handle, merged, profiles_dir=pdir, preserve_last_observed=True)
                        for abs_item in absorbed:
                            abs_p = Path(abs_item["path"])
                            if abs_p.is_file():
                                _archive_bot_instinct_file(abs_p, paths["archived"], "merged")

        obs_compaction = _compact_bot_observations_if_needed(
            handle,
            state,
            dry_run=dry_run,
            profiles_dir=pdir,
        )

        active_rules = 0
        rules_changed = False
        if not dry_run:
            active_rules, rules_changed = sync_bot_active_instincts(
                handle,
                profiles_dir=pdir,
                today=ref_today,
            )
        else:
            survivor_map = {str(s.get("id", "")): s for s in survivors}
            active_rules = len(_select_active_instincts(survivor_map, today=ref_today))

        per_bot_results[handle] = {
            "quarantined_ids": quarantined_ids,
            "decayed_ids": decayed_ids,
            "archived_low_conf_ids": archived_low_conf_ids,
            "merged_groups": merged_groups,
            "observations_compaction": obs_compaction,
            "active_instincts_synced": active_rules,
            "rules_changed": rules_changed,
        }

    if not dry_run:
        sync_claude_mem_recent_rule()
        summary = {
            "ts": now_ts,
            "bots_processed": len(handles),
            "quarantined": sum(len(v["quarantined_ids"]) for v in per_bot_results.values()),
            "decayed": sum(len(v["decayed_ids"]) for v in per_bot_results.values()),
            "archived_low_conf": sum(len(v["archived_low_conf_ids"]) for v in per_bot_results.values()),
            "merged_groups": sum(len(v["merged_groups"]) for v in per_bot_results.values()),
            "obs_archived_lines": sum(v["observations_compaction"]["archived_lines"] for v in per_bot_results.values()),
        }

        def _commit_per_bot_dream(latest: dict[str, Any]) -> None:
            latest["per_bot_last_dream_ts"] = now_ts
            latest["per_bot_last_dream_summary"] = summary
            if total_quarantine_poison:
                latest["poison_blocked_count"] = (
                    int(latest.get("poison_blocked_count") or 0) + total_quarantine_poison
                )

        state = _update_daemon_state(_commit_per_bot_dream)

    result = {
        "status": "dry_run" if dry_run else "dreamed",
        "mode": "per_bot",
        "dry_run": dry_run,
        "per_bot": per_bot_results,
        "coordinator_aggregation": build_coordinator_aggregation_view(profiles_dir=pdir),
        "poison_blocked_count": int(state.get("poison_blocked_count") or 0),
        "reloads_armed": False,
    }
    if not quiet:
        log.info("Per-bot Dream consolidation finished: %s", json.dumps(result, ensure_ascii=False))
    return result


def build_coordinator_aggregation_view(
    *,
    profiles_dir: Path | None = None,
) -> dict[str, Any]:
    """Build a read-only full-team aggregation of all bots' instincts and own/evolved skills for Coordinator."""
    pdir = profiles_dir or BOT_PROFILES_DIR
    handles: list[str] = []
    if pdir.is_dir():
        for ent in sorted(pdir.iterdir()):
            if ent.is_dir() and not ent.is_symlink() and not ent.name.startswith("."):
                handles.append(ent.name)

    bots_view: dict[str, Any] = {}
    all_skills: list[dict[str, Any]] = []
    all_instincts: list[dict[str, Any]] = []
    for h in handles:
        insts = load_bot_instincts(h, profiles_dir=pdir)
        active = _select_active_instincts(insts)
        sk_dir = pdir / h / "skills"
        bot_skills: list[dict[str, Any]] = []
        if sk_dir.is_dir():
            for sd in sorted(sk_dir.iterdir()):
                if sd.is_dir() and not sd.is_symlink() and (sd / "SKILL.md").is_file():
                    bot_skills.append({"owner": h, "slug": sd.name, "evolved": sd.name.startswith("evolved-")})
                    all_skills.append({"owner": h, "slug": sd.name, "evolved": sd.name.startswith("evolved-")})
        for ins in active:
            all_instincts.append(
                {
                    "owner": h,
                    "id": ins.get("id"),
                    "domain": ins.get("domain"),
                    "trigger": ins.get("trigger"),
                    "action": ins.get("action"),
                }
            )
        bots_view[h] = {
            "instincts_count": len(insts),
            "active_instincts_count": len(active),
            "skills": bot_skills,
        }
    return {
        "bots": bots_view,
        "all_skills": all_skills,
        "all_instincts": all_instincts,
    }


def call_shim_json(system_prompt: str, user_prompt: str, timeout: int = 120) -> str:
    payload = json.dumps(
        {
            "model": SHIM_MODEL,
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        },
        ensure_ascii=False,
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    shim_api_key = os.environ.get("AGY_SHIM_API_KEY", "").strip()
    if shim_api_key:
        headers["Authorization"] = f"Bearer {shim_api_key}"
    req = urllib.request.Request(
        SHIM_URL,
        data=payload,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return str(data["choices"][0]["message"]["content"])


def analyze_observations_batch(force: bool = False) -> dict[str, Any]:
    state = load_daemon_state()
    poison_before_harvest = int(state.get("poison_blocked_count") or 0)
    harvested, saw_corr = harvest_transcripts(state)
    harvest_poison_delta = max(0, int(state.get("poison_blocked_count") or 0) - poison_before_harvest)
    harvested_offsets = dict(state.get("transcript_offsets") or {})

    def _save_harvest(latest: dict[str, Any]) -> None:
        offsets = latest.setdefault("transcript_offsets", {})
        for cid, off in harvested_offsets.items():
            offsets[cid] = max(int(offsets.get(cid) or 0), int(off))
        if saw_corr:
            latest["pending_correction"] = True
        if harvest_poison_delta:
            latest["poison_blocked_count"] = int(latest.get("poison_blocked_count") or 0) + harvest_poison_delta

    state = _update_daemon_state(_save_harvest)
    effective_corr = saw_corr or bool(state.get("pending_correction"))

    if not OBSERVATIONS_FILE.is_file():
        return {"status": "no_observations", "harvested": harvested}

    lock_p = _obs_lock_path()
    lock_p.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_p, "a+", encoding="utf-8") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_SH)
        try:
            state = load_daemon_state()
            all_lines = OBSERVATIONS_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    start_compaction_gen = int(state.get("obs_compaction_gen") or 0)
    last_idx = int(state.get("last_analyzed_obs_line") or 0)
    if last_idx > len(all_lines):
        last_idx = 0
    batch_end_idx = len(all_lines)
    last_batch_line = all_lines[-1] if all_lines else ""

    pending_raw = all_lines[last_idx:]
    pending: list[str] = []
    obs_poison_delta = 0
    for ln in pending_raw:
        bad, _reason = _inspect_text(ln)
        if bad:
            obs_poison_delta += 1
            _record_guard_block(1)
            continue
        pending.append(ln)

    min_needed = MIN_OBS_ON_CORRECTION if effective_corr else MIN_OBS_FOR_BATCH
    effective_cooldown = CORRECTION_COOLDOWN_SEC if effective_corr else ANALYSIS_COOLDOWN_SEC
    if not force:
        if len(pending) < min_needed:
            if obs_poison_delta:
                _update_daemon_state(
                    lambda st: st.__setitem__(
                        "poison_blocked_count", int(st.get("poison_blocked_count") or 0) + obs_poison_delta
                    )
                )
            return {"status": "waiting_for_more", "pending": len(pending), "needed": min_needed}
        if (time.time() - float(state.get("last_analysis_ts") or 0)) < effective_cooldown:
            if obs_poison_delta:
                _update_daemon_state(
                    lambda st: st.__setitem__(
                        "poison_blocked_count", int(st.get("poison_blocked_count") or 0) + obs_poison_delta
                    )
                )
            return {"status": "cooldown", "pending": len(pending), "cooldown_sec": effective_cooldown}

    if not pending:
        def _commit_empty(latest: dict[str, Any]) -> None:
            if int(latest.get("obs_compaction_gen") or 0) == start_compaction_gen:
                latest["last_analyzed_obs_line"] = max(int(latest.get("last_analyzed_obs_line") or 0), batch_end_idx)
            latest["pending_correction"] = False
            if obs_poison_delta:
                latest["poison_blocked_count"] = int(latest.get("poison_blocked_count") or 0) + obs_poison_delta

        _update_daemon_state(_commit_empty)
        return {"status": "up_to_date", "updated": 0}

    batch_slice = pending[-60:]
    existing = load_existing_instincts()
    existing_summary = [
        {
            "id": k,
            "trigger": v.get("trigger"),
            "confidence": v.get("confidence"),
            "domain": v.get("domain"),
        }
        for k, v in existing.items()
    ]

    sys_prompt = (
        "You are the ECC Continuous-Learning v2.1 Observer Engine running on Antigravity CLI.\n"
        "Analyze session observations (user prompts/corrections, tool usage, error fixes, repeated workflows) "
        "and extract ONLY genuinely reusable atomic instincts.\n"
        "Rules:\n"
        "1. Be conservative: ignore one-off trivial Q&A; prioritize explicit user preferences/corrections, "
        "infrastructure conventions, and repeated multi-step workflows.\n"
        "2. Merge with existing instincts by reusing the same `id` and increasing `confidence` (+0.05..+0.15) "
        "when re-confirmed, or decreasing (-0.10) if contradicted.\n"
        "3. Initial confidence: explicit user rule/correction = 0.65..0.75; repeated workflow = 0.45..0.60; tentative = 0.35.\n"
        "4. Never include raw secrets, tokens, or personal data.\n"
        "5. Output STRICTLY a JSON array (no markdown prose outside JSON): "
        '[{"id":"kebab-case-id","title":"Short Title","trigger":"when ...","action":"Concise actionable rule","domain":"workflow|code-style|ops|debugging|security|telegram","confidence":0.65,"evidence":["brief evidence 1"]}] '
        "or `[]` if no clear reusable pattern is present."
    )

    usr_prompt = (
        f"Existing instincts:\n{json.dumps(existing_summary, ensure_ascii=False)}\n\n"
        f"Recent observations ({len(batch_slice)} items):\n" + "\n".join(batch_slice)
    )

    raw_reply = call_shim_json(sys_prompt, usr_prompt, timeout=150)
    arr_match = re.search(r"\[[\s\S]*\]", raw_reply)
    items: list[dict[str, Any]] = []
    if arr_match:
        try:
            parsed = json.loads(arr_match.group(0))
            if isinstance(parsed, list):
                items = [x for x in parsed if isinstance(x, dict) and x.get("id") and x.get("action")]
        except json.JSONDecodeError:
            log.warning("Could not parse JSON array from observer reply: %s", raw_reply[:250])

    written_ids: list[str] = []
    blocked_candidates = 0
    for item in items[:8]:
        ok, block_reason = _validate_instinct_candidate(item, is_existing=False)
        if not ok:
            blocked_candidates += 1
            _record_guard_block(1)
            log.warning("Rejected unsafe instinct candidate %r (%s)", item.get("id"), block_reason)
            continue

        iid = re.sub(r"[^a-z0-9._-]+", "-", str(item["id"]).lower()).strip("-")
        if iid in existing:
            old_ev = [e for e in (existing[iid].get("evidence") or []) if not e.startswith("Last observed:")]
            new_ev = item.get("evidence") or []
            if isinstance(new_ev, str):
                new_ev = [new_ev]
            merged_ev = list(dict.fromkeys(old_ev + [str(x) for x in new_ev]))[-5:]
            item["evidence"] = merged_ev
        out_p = write_instinct_yaml(item)
        written_ids.append(out_p.stem)

    now_ts = time.time()
    total_poison_delta = obs_poison_delta + blocked_candidates

    def _commit_analysis(latest: dict[str, Any]) -> None:
        if int(latest.get("obs_compaction_gen") or 0) == start_compaction_gen:
            latest["last_analyzed_obs_line"] = max(int(latest.get("last_analyzed_obs_line") or 0), batch_end_idx)
        else:
            cur_lines = (
                OBSERVATIONS_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
                if OBSERVATIONS_FILE.is_file()
                else []
            )
            cur_idx = int(latest.get("last_analyzed_obs_line") or 0)
            if last_batch_line:
                found_pos = None
                for idx_c in range(max(0, cur_idx), len(cur_lines)):
                    if cur_lines[idx_c] == last_batch_line:
                        found_pos = idx_c + 1
                if found_pos is not None:
                    latest["last_analyzed_obs_line"] = found_pos
                else:
                    latest["last_analyzed_obs_line"] = min(
                        len(cur_lines), cur_idx + max(0, batch_end_idx - last_idx)
                    )
            else:
                latest["last_analyzed_obs_line"] = min(len(cur_lines), cur_idx)
        latest["last_analysis_ts"] = now_ts
        latest["pending_correction"] = False
        if total_poison_delta:
            latest["poison_blocked_count"] = int(latest.get("poison_blocked_count") or 0) + total_poison_delta

    state = _update_daemon_state(_commit_analysis)

    synced_rules, _rules_changed = sync_active_instincts_rule()
    sync_claude_mem_recent_rule()

    latest_instincts = load_existing_instincts()
    by_domain: dict[str, list[dict[str, Any]]] = {}
    for v in latest_instincts.values():
        if float(v.get("confidence", 0)) >= 0.80:
            dom = str(v.get("domain") or "general")
            by_domain.setdefault(dom, []).append(v)

    dom_counts: dict[str, int] = {}
    raw_counts = state.get("evolved_domain_counts")
    if isinstance(raw_counts, dict):
        for k, val in raw_counts.items():
            try:
                dom_counts[str(k)] = int(val)
            except (TypeError, ValueError):
                pass
    for legacy_dom in list(state.get("evolved_domains") or []):
        dom_counts.setdefault(str(legacy_dom), 3)

    ready_domains = [
        d
        for d, items_d in by_domain.items()
        if len(items_d) >= 3 and (d not in dom_counts or len(items_d) >= dom_counts[d] + EVOLVE_DELTA_MIN)
    ]
    last_evolve_ts = float(state.get("last_evolve_ts") or 0.0)
    evolve_due = (not last_evolve_ts) or ((now_ts - last_evolve_ts) >= EVOLVE_COOLDOWN_SEC)
    sync_evolved_skills()
    if ready_domains and evolve_due:
        try:
            evolve_with_llm_and_cli(quiet=True)
            sync_evolved_skills()

            def _record_evolved(latest: dict[str, Any]) -> None:
                ev_doms = latest.setdefault("evolved_domains", [])
                ev_counts = latest.setdefault("evolved_domain_counts", {})
                for d in ready_domains:
                    if d not in ev_doms:
                        ev_doms.append(d)
                    ev_counts[d] = len(by_domain.get(d) or [])
                latest["last_evolve_ts"] = now_ts

            _update_daemon_state(_record_evolved)
        except Exception as e:
            log.warning("Auto-evolve check skipped: %s", e)

    return {
        "status": "analyzed",
        "observations_processed": len(pending),
        "instincts_written": written_ids,
        "candidates_blocked": blocked_candidates,
        "active_rules_synced": synced_rules,
        "reloads_armed": False,
    }


def _archive_instinct_file(src_path: Path, tag: str) -> Path:
    ARCHIVE_INSTINCTS_DIR.mkdir(parents=True, exist_ok=True)
    ts_tag = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    dest = ARCHIVE_INSTINCTS_DIR / f"{src_path.stem}-{tag}-{ts_tag}{src_path.suffix}"
    counter = 1
    while dest.exists():
        dest = ARCHIVE_INSTINCTS_DIR / f"{src_path.stem}-{tag}-{ts_tag}-{counter}{src_path.suffix}"
        counter += 1
    shutil.move(str(src_path), str(dest))
    return dest


_STOPWORDS = frozenset(
    {
        "when",
        "always",
        "never",
        "use",
        "using",
        "the",
        "and",
        "for",
        "with",
        "before",
        "after",
        "into",
        "from",
        "that",
        "this",
        "agy",
        "workspace",
    }
)


def _tokenize_for_similarity(text: str) -> set[str]:
    low = (text or "").lower()
    words = {w for w in re.findall(r"[a-z0-9_-]{2,}", low) if w not in _STOPWORDS}
    cjk_runs = re.findall(r"[\u4e00-\u9fff]+", low)
    for run in cjk_runs:
        if len(run) == 1:
            words.add(run)
        else:
            for i in range(len(run) - 1):
                words.add(run[i : i + 2])
    return words


def _norm_trigger(trigger: str) -> str:
    s = re.sub(r"^when\s+", "", (trigger or "").strip().lower())
    s = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", " ", s).strip()
    return s


def _instinct_similarity(a: dict[str, Any], b: dict[str, Any]) -> float:
    if str(a.get("domain") or "workflow").lower() != str(b.get("domain") or "workflow").lower():
        return 0.0
    ta = _norm_trigger(str(a.get("trigger") or ""))
    tb = _norm_trigger(str(b.get("trigger") or ""))
    if ta and tb and ta == tb:
        return 1.0
    toks_a = _tokenize_for_similarity(f"{a.get('trigger', '')} {a.get('action', '')}")
    toks_b = _tokenize_for_similarity(f"{b.get('trigger', '')} {b.get('action', '')}")
    if not toks_a or not toks_b:
        return 0.0
    inter = len(toks_a & toks_b)
    union = len(toks_a | toks_b)
    return inter / union if union else 0.0


_MERGE_CLAUSE_SPLIT_RE = re.compile(r"[;\n；]+")
_BOILERPLATE_PREFIX_RE = re.compile(
    r"^(?:always|ensure(?:\s+you)?|make\s+sure(?:\s+to)?|be\s+sure\s+to|"
    r"remember\s+to|you\s+should|explicitly)\s+",
    re.IGNORECASE,
)


def _normalize_clause(text: str) -> str:
    s = re.sub(r"\s+", " ", (text or "").strip().lower())
    return s.rstrip(".。;；,，")


def _extract_action_clauses(action: str) -> list[str]:
    clauses: list[str] = []
    for part in _MERGE_CLAUSE_SPLIT_RE.split(action or ""):
        cleaned = re.sub(r"\s+", " ", part).strip(" ;；")
        if cleaned:
            clauses.append(cleaned)
    return clauses


def _condense_clause(clause: str) -> str:
    condensed = _BOILERPLATE_PREFIX_RE.sub("", clause.strip())
    return condensed.strip() or clause.strip()


def _merge_instinct_cluster_local(cluster: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(
        cluster,
        key=lambda x: (
            -float(x.get("confidence") or 0.0),
            -_extract_last_observed_date(x).toordinal(),
            str(x.get("id") or ""),
        ),
    )
    primary = dict(ordered[0])
    absorbed = ordered[1:]

    max_conf = max(float(x.get("confidence") or 0.5) for x in ordered)
    boosted = min(0.95, round(max_conf + 0.04 * min(3, len(absorbed)), 2))

    # Clause-level deduplication & condensation so shared clauses don't crowd out trailing core directives
    dedup_clauses: list[str] = []
    kept_norms: list[str] = []
    kept_tokens: list[set[str]] = []
    for item in ordered:
        for clause in _extract_action_clauses(str(item.get("action") or "")):
            norm = _normalize_clause(clause)
            if not norm:
                continue
            toks = _tokenize_for_similarity(clause)
            is_dup = False
            for idx, prev_norm in enumerate(kept_norms):
                if norm == prev_norm or norm in prev_norm:
                    is_dup = True
                    break
                if prev_norm in norm and len(norm) > len(prev_norm):
                    dedup_clauses[idx] = clause
                    kept_norms[idx] = norm
                    kept_tokens[idx] = toks
                    is_dup = True
                    break
                prev_toks = kept_tokens[idx]
                if toks and prev_toks and (len(toks & prev_toks) / len(toks | prev_toks)) >= 0.80:
                    is_dup = True
                    break
            if not is_dup:
                dedup_clauses.append(clause)
                kept_norms.append(norm)
                kept_tokens.append(toks)

    if not dedup_clauses:
        merged_action = str(ordered[0].get("action") or "").strip()
    else:
        merged_action = "; ".join(dedup_clauses)
        if len(merged_action) > 700:
            condensed = [_condense_clause(c) if i > 0 else c for i, c in enumerate(dedup_clauses)]
            merged_condensed = "; ".join(condensed)
            if len(merged_condensed) <= 1500:
                merged_action = merged_condensed
            else:
                max_budget = 1500
                tail_budget = sum(len(c) + 2 for c in condensed[1:])
                head_cap = max(500, max_budget - tail_budget)
                head_text = (
                    condensed[0]
                    if len(condensed[0]) <= head_cap
                    else (condensed[0][: max(40, head_cap - 3)].rstrip() + "...")
                )
                tail_clauses: list[str] = []
                used_len = len(head_text)
                for c in reversed(condensed[1:]):
                    add_len = len(c) + 2
                    if used_len + add_len <= max_budget:
                        tail_clauses.append(c)
                        used_len += add_len
                    elif max_budget - used_len > 40:
                        avail = max_budget - used_len - 5
                        tail_clauses.append(c[:avail].rstrip() + "...")
                        used_len = max_budget
                        break
                    else:
                        break
                merged_action = "; ".join([head_text] + list(reversed(tail_clauses)))

    # Merge evidence lines, preserving newest Last observed date
    ev_items: list[str] = []
    latest_date = max(_extract_last_observed_date(x) for x in ordered)
    for item in ordered:
        for ev in item.get("evidence") or []:
            ev_s = str(ev).strip()
            if not ev_s or ev_s.startswith("Last observed:"):
                continue
            if ev_s not in ev_items:
                ev_items.append(ev_s)
    ev_items = ev_items[-5:]
    ev_items.append(f"Last observed: {latest_date.strftime('%Y-%m-%d')}")

    primary["confidence"] = boosted
    primary["action"] = merged_action
    primary["evidence"] = ev_items
    return primary


def _merge_instinct_cluster(cluster: list[dict[str, Any]], *, use_llm: bool = False) -> dict[str, Any]:
    local_merged = _merge_instinct_cluster_local(cluster)
    if not use_llm:
        return local_merged
    try:
        sys_p = (
            "Consolidate duplicate ECC instincts into ONE concise atomic rule. "
            'Return strict JSON: {"trigger":"when ...","action":"...","title":"..."}'
        )
        usr_p = json.dumps(
            [
                {
                    "id": x.get("id"),
                    "trigger": x.get("trigger"),
                    "action": x.get("action"),
                    "confidence": x.get("confidence"),
                }
                for x in cluster
            ],
            ensure_ascii=False,
        )
        raw = call_shim_json(sys_p, usr_p, timeout=60)
        obj_m = re.search(r"\{[\s\S]*\}", raw)
        if obj_m:
            data = json.loads(obj_m.group(0))
            cand = dict(local_merged)
            if data.get("trigger"):
                cand["trigger"] = str(data["trigger"]).strip()
            if data.get("action"):
                cand["action"] = str(data["action"]).strip()
            if data.get("title"):
                cand["title"] = str(data["title"]).strip()
            llm_only = {
                "id": cand.get("id"),
                "title": cand.get("title"),
                "trigger": cand.get("trigger"),
                "action": cand.get("action"),
                "domain": cand.get("domain"),
            }
            ok_llm, _ = _validate_instinct_candidate(llm_only, is_existing=False)
            ok_full, _ = _validate_instinct_candidate(cand, is_existing=True)
            if ok_llm and ok_full:
                return cand
    except Exception as e:
        log.warning("Dream LLM merge fallback to local deterministic merge: %s", e)
    return local_merged


def _compact_observations_if_needed(
    state: dict[str, Any],
    *,
    dry_run: bool = False,
    max_lines: int | None = None,
    keep_tail: int | None = None,
) -> dict[str, int]:
    """Compress & gzip-archive already-analyzed observations.jsonl lines without offset drift."""
    res = {"total_before": 0, "archived_lines": 0, "dropped_poison": 0, "total_after": 0}
    if not OBSERVATIONS_FILE.is_file():
        return res

    max_l = DREAM_MAX_OBS_LINES if max_lines is None else max(20, int(max_lines))
    tail_n = DREAM_OBS_KEEP_TAIL if keep_tail is None else max(0, int(keep_tail))

    lock_p = _obs_lock_path()
    lock_p.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_p, "a+", encoding="utf-8") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            lines = OBSERVATIONS_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
            total = len(lines)
            res["total_before"] = total
            if total <= max_l:
                res["total_after"] = total
                return res

            fresh_state = load_daemon_state() if DAEMON_STATE_FILE.exists() else state
            last_idx = int(fresh_state.get("last_analyzed_obs_line") or state.get("last_analyzed_obs_line") or 0)
            last_idx = max(0, min(total, last_idx))
            effective_tail = min(tail_n, last_idx)
            archive_end = max(0, last_idx - effective_tail)
            if archive_end <= 0:
                res["total_after"] = total
                return res

            raw_archive = lines[:archive_end]
            raw_remaining = lines[archive_end:]
            analyzed_in_remaining = last_idx - archive_end

            clean_archive: list[str] = []
            for ln in raw_archive:
                bad, _ = _inspect_text(ln)
                if bad:
                    res["dropped_poison"] += 1
                    continue
                clean_archive.append(ln)

            clean_remaining: list[str] = []
            new_last_idx = analyzed_in_remaining
            for idx, ln in enumerate(raw_remaining):
                bad, _ = _inspect_text(ln)
                if bad:
                    res["dropped_poison"] += 1
                    if idx < analyzed_in_remaining:
                        new_last_idx = max(0, new_last_idx - 1)
                    continue
                clean_remaining.append(ln)

            res["archived_lines"] = len(clean_archive)
            res["total_after"] = len(clean_remaining)

            if not dry_run:
                if clean_archive:
                    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
                    ym = datetime.now(timezone.utc).strftime("%Y%m")
                    gz_path = ARCHIVE_DIR / f"observations-{ym}.jsonl.gz"
                    with gzip.open(gz_path, "at", encoding="utf-8") as gz:
                        for ln in clean_archive:
                            gz.write(ln + "\n")

                tmp = OBSERVATIONS_FILE.with_name(f".{OBSERVATIONS_FILE.name}.{os.getpid()}.tmp")
                tmp.write_text(("\n".join(clean_remaining) + "\n") if clean_remaining else "", encoding="utf-8")
                tmp.replace(OBSERVATIONS_FILE)
                if res["dropped_poison"]:
                    _record_guard_block(res["dropped_poison"])

                def _commit_compact(latest: dict[str, Any]) -> None:
                    latest["last_analyzed_obs_line"] = new_last_idx
                    latest["obs_compaction_gen"] = int(latest.get("obs_compaction_gen") or 0) + 1
                    if res["dropped_poison"]:
                        latest["poison_blocked_count"] = (
                            int(latest.get("poison_blocked_count") or 0) + res["dropped_poison"]
                        )

                updated_st = _update_daemon_state(_commit_compact)
                state["last_analyzed_obs_line"] = updated_st["last_analyzed_obs_line"]
                state["obs_compaction_gen"] = updated_st["obs_compaction_gen"]
                state["poison_blocked_count"] = updated_st["poison_blocked_count"]
            return res
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def run_dream(
    *,
    dry_run: bool = False,
    force: bool = False,
    quiet: bool = False,
    use_llm: bool = False,
    today: date | None = None,
    per_bot: bool = False,
    profiles_dir: Path | None = None,
) -> dict[str, Any]:
    """Periodic Dream memory consolidation:
    1. Anti-poisoning re-validation on existing instincts
    2. Gentle time decay & low-confidence archival
    3. Similarity-based instinct deduplication & merge (deterministic local + optional LLM)
    4. `observations.jsonl` rolling gzip archival with exact `last_analyzed_obs_line` recalculation
    5. Deterministic `ecc-active-instincts.md` sync (preserving prompt cache, zero bridge reload)
    """
    if per_bot or profiles_dir is not None:
        return run_per_bot_dream(
            dry_run=dry_run,
            force=force,
            quiet=quiet,
            use_llm=use_llm,
            profiles_dir=profiles_dir,
            today=today,
        )
    ensure_dirs()
    state = load_daemon_state()
    now_ts = time.time()
    last_dream_ts = float(state.get("last_dream_ts") or 0.0)
    if not force and (now_ts - last_dream_ts) < DREAM_INTERVAL_SEC:
        return {
            "status": "cooldown",
            "last_dream_ts": last_dream_ts,
            "next_due_in_sec": int(DREAM_INTERVAL_SEC - (now_ts - last_dream_ts)),
        }

    ref_today = today or datetime.now(timezone.utc).date()
    existing = load_existing_instincts()

    quarantined_ids: list[str] = []
    decayed_ids: list[str] = []
    archived_low_conf_ids: list[str] = []
    merged_groups: list[dict[str, Any]] = []
    survivors: list[dict[str, Any]] = []
    dream_quarantine_poison = 0

    # 1 & 2. Anti-poisoning validation + time decay + low-confidence archival
    for iid, meta in sorted(existing.items()):
        ok, bad_reason = _validate_instinct_candidate(meta, is_existing=True)
        if not ok:
            quarantined_ids.append(iid)
            if not dry_run:
                _archive_instinct_file(Path(meta["path"]), "quarantined")
                dream_quarantine_poison += 1
                _record_guard_block(1)
            log.warning("Dream quarantined unsafe instinct %s (%s)", iid, bad_reason)
            continue

        last_obs = _extract_last_observed_date(meta)
        days_stale = max(0, (ref_today - last_obs).days)
        old_conf = float(meta.get("confidence") or 0.5)
        new_conf = old_conf
        if days_stale > DREAM_DECAY_GRACE_DAYS:
            weeks_over = (days_stale - DREAM_DECAY_GRACE_DAYS) / 7.0
            decay = round(min(0.30, max(0.02, weeks_over * 0.03)), 2)
            new_conf = round(max(0.10, old_conf - decay), 2)

        if new_conf < DREAM_ARCHIVE_CONF:
            archived_low_conf_ids.append(iid)
            if not dry_run:
                _archive_instinct_file(Path(meta["path"]), "decayed")
            continue

        updated = dict(meta)
        if new_conf != old_conf:
            updated["confidence"] = new_conf
            decayed_ids.append(iid)
            if not dry_run:
                write_instinct_yaml(updated, preserve_last_observed=True)
        survivors.append(updated)

    # 3. Cluster & merge fragmented/duplicate instincts per domain
    by_domain: dict[str, list[dict[str, Any]]] = {}
    for item in survivors:
        dom = str(item.get("domain") or "workflow").lower()
        by_domain.setdefault(dom, []).append(item)

    for _dom, dom_items in sorted(by_domain.items()):
        used: set[str] = set()
        for i, anchor in enumerate(dom_items):
            aid = str(anchor["id"])
            if aid in used:
                continue
            cluster = [anchor]
            used.add(aid)
            for cand in dom_items[i + 1 :]:
                cid = str(cand["id"])
                if cid in used:
                    continue
                if _instinct_similarity(anchor, cand) >= 0.50:
                    cluster.append(cand)
                    used.add(cid)
            if len(cluster) >= 2:
                merged = _merge_instinct_cluster(cluster, use_llm=use_llm)
                ok, _ = _validate_instinct_candidate(merged, is_existing=True)
                if not ok:
                    continue
                merged_id = str(merged["id"])
                absorbed = [c for c in cluster if str(c["id"]) != merged_id]
                merged_groups.append({"kept": merged_id, "absorbed": [str(a["id"]) for a in absorbed]})
                if not dry_run:
                    write_instinct_yaml(merged, preserve_last_observed=True)
                    for abs_item in absorbed:
                        abs_p = Path(abs_item["path"])
                        if abs_p.is_file():
                            _archive_instinct_file(abs_p, "merged")

    # 4. Compact & archive observations.jsonl
    obs_compaction = _compact_observations_if_needed(state, dry_run=dry_run)

    # 5. Deterministic active rules sync (no bridge reload!)
    active_rules = 0
    rules_changed = False
    if not dry_run:
        active_rules, rules_changed = sync_active_instincts_rule(today=ref_today)
        sync_claude_mem_recent_rule()
        summary = {
            "ts": now_ts,
            "quarantined": len(quarantined_ids),
            "decayed": len(decayed_ids),
            "archived_low_conf": len(archived_low_conf_ids),
            "merged_groups": len(merged_groups),
            "obs_archived_lines": obs_compaction["archived_lines"],
            "active_rules_synced": active_rules,
        }

        def _commit_dream(latest: dict[str, Any]) -> None:
            latest["last_dream_ts"] = now_ts
            latest["last_dream_summary"] = summary
            if dream_quarantine_poison:
                latest["poison_blocked_count"] = (
                    int(latest.get("poison_blocked_count") or 0) + dream_quarantine_poison
                )

        state = _update_daemon_state(_commit_dream)
    else:
        survivor_map = {str(s.get("id", "")): s for s in survivors}
        active_rules = len(_select_active_instincts(survivor_map, today=ref_today))

    result = {
        "status": "dry_run" if dry_run else "dreamed",
        "dry_run": dry_run,
        "quarantined_ids": quarantined_ids,
        "decayed_ids": decayed_ids,
        "archived_low_conf_ids": archived_low_conf_ids,
        "merged_groups": merged_groups,
        "observations_compaction": obs_compaction,
        "active_rules_synced": active_rules,
        "rules_changed": rules_changed,
        "poison_blocked_count": int(state.get("poison_blocked_count") or 0),
        "reloads_armed": False,
    }
    if not quiet:
        log.info("Dream consolidation finished: %s", json.dumps(result, ensure_ascii=False))
    return result


def get_dream_status(*, profiles_dir: Path | None = None) -> dict[str, Any]:
    """Return read-only Dream, Per-Bot Isolation, Coordinator Aggregation & Memory Guard status summary."""
    pdir = profiles_dir or BOT_PROFILES_DIR
    state = load_daemon_state()
    existing = load_existing_instincts()
    archived_cnt = len(list(ARCHIVE_INSTINCTS_DIR.glob("*.yaml"))) if ARCHIVE_INSTINCTS_DIR.is_dir() else 0
    obs_lines = 0
    if OBSERVATIONS_FILE.is_file():
        try:
            obs_lines = len(OBSERVATIONS_FILE.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            obs_lines = 0
    guard_stats = _MEMORY_GUARD.get_guard_stats(taint_file=MEMORY_TAINT_FILE) if _MEMORY_GUARD is not None else {}
    selected_active = _select_active_instincts(existing)
    coord_agg = build_coordinator_aggregation_view(profiles_dir=pdir)
    per_bot_evolved_cnt = sum(1 for sk in coord_agg["all_skills"] if sk.get("evolved"))
    local_evolved_cnt = (
        len([d for d in EVOLVED_SKILLS_DIR.iterdir() if d.is_dir() and (d / "SKILL.md").is_file()])
        if EVOLVED_SKILLS_DIR.is_dir()
        else 0
    )
    evolved_cnt = per_bot_evolved_cnt + local_evolved_cnt
    plugin_synced = bool(
        GLOBAL_PLUGIN_MANIFEST is not None
        and GLOBAL_PLUGIN_MANIFEST.is_file()
        and GLOBAL_PLUGIN_RULE_FILE is not None
        and GLOBAL_PLUGIN_RULE_FILE.is_file()
    )
    return {
        "personal_instincts": len(existing),
        "active_rules_count": len(selected_active),
        "high_conf_instincts_count": sum(1 for v in existing.values() if float(v.get("confidence") or 0) >= 0.80),
        "core_active_slots": ACTIVE_RULE_CORE_SLOTS,
        "recent_active_slots": ACTIVE_RULE_RECENT_SLOTS,
        "evolved_skills_count": evolved_cnt,
        "per_bot_evolved_skills_count": per_bot_evolved_cnt,
        "max_evolved_skills": MAX_EVOLVED_SKILLS,
        "global_plugin_dir": str(GLOBAL_PLUGIN_DIR) if GLOBAL_PLUGIN_DIR is not None else None,
        "global_plugin_synced": plugin_synced,
        "archived_instincts": archived_cnt,
        "observations_lines": obs_lines,
        "last_analyzed_obs_line": int(state.get("last_analyzed_obs_line") or 0),
        "last_dream_ts": float(state.get("last_dream_ts") or 0.0),
        "last_dream_summary": state.get("last_dream_summary") or {},
        "per_bot_last_dream_ts": float(state.get("per_bot_last_dream_ts") or 0.0),
        "per_bot_last_dream_summary": state.get("per_bot_last_dream_summary") or {},
        "per_bot": coord_agg["bots"],
        "coordinator_aggregation": coord_agg,
        "poison_blocked_count": int(state.get("poison_blocked_count") or 0),
        "guard": guard_stats,
    }


def evolve_with_llm_and_cli(quiet: bool = False) -> int:
    """Run ECC's native `instinct-cli.py evolve --generate`, plus LLM synthesis or incremental refresh
    when >=3 strong instincts exist (even when already at MAX_EVOLVED_SKILLS cap, by refreshing an existing skill).
    """
    subprocess.run(
        [sys.executable, str(INSTINCT_CLI), "evolve", "--generate"],
        check=False,
        stdout=subprocess.DEVNULL if quiet else None,
        stderr=subprocess.DEVNULL if quiet else None,
    )
    synced, skills_changed = sync_evolved_skills()

    existing = load_existing_instincts()
    strong = [v for v in existing.values() if float(v.get("confidence", 0)) >= 0.70]
    strong.sort(
        key=lambda x: (
            -_extract_last_observed_date(x).toordinal(),
            -float(x.get("confidence", 0)),
            str(x.get("id", "")),
        )
    )
    existing_skill_names = sorted(
        ({d.name for d in WORKSPACE_SKILLS_DIR.iterdir() if d.is_dir()} if WORKSPACE_SKILLS_DIR.is_dir() else set())
        | {Path(p).parent.name for p in synced}
    )
    existing_evolved_slugs = sorted(
        {_clean_evolved_slug(Path(p).parent.name) for p in synced if _clean_evolved_slug(Path(p).parent.name)}
    )
    at_skill_cap = len(synced) >= MAX_EVOLVED_SKILLS
    if len(strong) >= 3:
        cap_instruction = (
            "Skill count is at cap: you MUST refresh one existing `evolved-*` slug from `existing_evolved_slugs` "
            "(returning that exact slug without the `evolved-` prefix) by merging new strong instincts into it, "
            "or output `{}` if none needs updating."
            if at_skill_cap
            else (
                "If 3 or more instincts form a coherent reusable workflow/domain NOT already covered by existing "
                "workspace skills, synthesize ONE new Antigravity SKILL.md bundle; OR if an existing `evolved-*` "
                "skill in `existing_evolved_slugs` is missing recent strong instincts, refresh it by returning its "
                "existing slug."
            )
        )
        sys_p = (
            "You are the ECC Skill Evolution Engine for Antigravity CLI (`agy`).\n"
            f"{cap_instruction}\n"
            "Output strict JSON: "
            '{"slug":"short-kebab-name","description":"When to activate this skill","markdown":"Full markdown body (without frontmatter)"}. '
            "Do NOT include an `evolved-` prefix in `slug`. "
            "If nothing new or worth refreshing remains, output `{}`."
        )
        usr_p = json.dumps(
            {
                "already_existing_skills": existing_skill_names,
                "existing_evolved_slugs": existing_evolved_slugs,
                "at_skill_cap": at_skill_cap,
                "strong_instincts": [
                    {
                        "id": v.get("id"),
                        "trigger": v.get("trigger"),
                        "confidence": v.get("confidence"),
                        "domain": v.get("domain"),
                        "last_observed": _extract_last_observed_date(v).strftime("%Y-%m-%d"),
                        "body": v.get("body"),
                    }
                    for v in strong[:40]
                ],
            },
            ensure_ascii=False,
        )
        try:
            raw = call_shim_json(sys_p, usr_p, timeout=150)
            obj_m = re.search(r"\{[\s\S]*\}", raw)
            if obj_m:
                data = json.loads(obj_m.group(0))
                slug = _clean_evolved_slug(str(data.get("slug") or ""))
                md = str(data.get("markdown") or "").strip()
                desc = str(data.get("description") or "").strip()
                bad_md, _ = _inspect_text(f"{slug}\n{desc}\n{md}")
                allowed_slug = (not at_skill_cap) or (slug in existing_evolved_slugs)
                if slug and md and desc and not bad_md and allowed_slug:
                    skill_file = EVOLVED_SKILLS_DIR / slug / "SKILL.md"
                    skill_file.parent.mkdir(parents=True, exist_ok=True)
                    full_md = (
                        "---\n"
                        f"name: evolved-{slug}\n"
                        f"description: {json.dumps(desc, ensure_ascii=False)}\n"
                        "---\n\n"
                        f"{md}\n"
                    )
                    skill_file.write_text(full_md, encoding="utf-8")
                    synced, ch2 = sync_evolved_skills()
                    skills_changed = skills_changed or ch2
        except Exception as e:
            log.warning("LLM skill synthesis skipped: %s", e)

    if not quiet:
        if synced:
            print(f"\nSynced {len(synced)} evolved skill(s) into isolated local skill store (zero shared workspace or global plugin writes):")
            for s in synced:
                print(f"  - {s}")
        else:
            print("\nActive instincts synced to isolated local store (accumulate more related instincts to synthesize multi-step SKILL.md).")
    return 0


def run_daemon_loop() -> None:
    ensure_dirs()
    sync_claude_mem_recent_rule()
    for handle in _list_bot_profile_handles():
        try:
            sync_bot_active_instincts(handle)
        except Exception as e:
            log.warning("Startup per-bot instinct sync failed for @%s: %s", handle, e)
    log.info("Starting agy-instinct-daemon in per-bot isolation mode (poll=%ds, dream=%ds, shim=%s, model=%s)", POLL_INTERVAL_SEC, DREAM_INTERVAL_SEC, SHIM_URL, SHIM_MODEL)
    while True:
        try:
            res = analyze_per_bot_observations_batch(force=False)
            if res.get("status") == "analyzed":
                log.info("Per-bot instinct batch analyzed: %s", res)
            dream_res = run_per_bot_dream(force=False, quiet=True)
            if dream_res.get("status") == "dreamed":
                log.info("Periodic per-bot Dream consolidation completed: %s", dream_res)
        except Exception as e:
            log.warning("Instinct loop iteration error: %s", e)
        time.sleep(POLL_INTERVAL_SEC)


def main() -> int:
    parser = argparse.ArgumentParser(description="Antigravity ECC Continuous-Learning v2 Per-Bot Daemon & CLI")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("daemon", help="Run background per-bot transcript-to-instinct observer loop")
    sub.add_parser("analyze-now", help="Harvest transcripts per-bot and run instinct extraction immediately")
    p_sync = sub.add_parser("sync", help="Sync per-bot active instincts & print coordinator aggregation")
    p_sync.add_argument("--reload", action="store_true", help="Explicitly queue zero-downtime bridge reload")
    sub.add_parser("status", help="Show per-bot ECC instinct & Dream status")
    sub.add_parser("evolve", help="Cluster and evolve high-confidence per-bot instincts into bots/<handle>/skills/")
    p_dream = sub.add_parser("dream", help="Consolidate per-bot instincts, apply decay, and compact observations")
    p_dream.add_argument("--dry-run", action="store_true", help="Preview consolidation without writing files")
    p_dream.add_argument("--force", action="store_true", help="Bypass DREAM_INTERVAL_SEC cooldown")
    p_dream.add_argument("--quiet", action="store_true", help="Suppress verbose log output")
    p_dream.add_argument("--use-llm", action="store_true", help="Allow optional LLM merge refinement via agy-llm-shim")
    sub.add_parser("dream-status", help="Print JSON summary of Memory Guard, Per-Bot & Dream status")

    args, rest = parser.parse_known_args()
    cmd = args.cmd or "status"

    if cmd == "daemon":
        run_daemon_loop()
        return 0
    if cmd == "analyze-now":
        res = analyze_per_bot_observations_batch(force=True)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    if cmd == "dream":
        res = run_per_bot_dream(
            dry_run=bool(getattr(args, "dry_run", False)),
            force=bool(getattr(args, "force", False)),
            quiet=bool(getattr(args, "quiet", False)),
            use_llm=bool(getattr(args, "use_llm", False)),
        )
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    if cmd == "dream-status":
        print(json.dumps(get_dream_status(), indent=2, ensure_ascii=False))
        return 0
    if cmd == "sync":
        per_bot_sync: dict[str, Any] = {}
        any_changed = False
        for handle in _list_bot_profile_handles():
            n_active, changed = sync_bot_active_instincts(handle)
            per_bot_sync[handle] = {"active_instincts_synced": n_active, "changed": changed}
            any_changed = any_changed or changed
        m_ch = sync_claude_mem_recent_rule()
        if getattr(args, "reload", False) and any_changed:
            touch_bridge_reloads()
        print(
            json.dumps(
                {
                    "mode": "per_bot",
                    "per_bot": per_bot_sync,
                    "coordinator_aggregation": build_coordinator_aggregation_view(),
                    "claude_mem_recent_removed": m_ch,
                    "global_plugin_dir": str(GLOBAL_PLUGIN_DIR) if GLOBAL_PLUGIN_DIR is not None else None,
                    "global_plugin_rule_synced": bool(GLOBAL_PLUGIN_RULE_FILE and GLOBAL_PLUGIN_RULE_FILE.is_file()),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    if cmd == "evolve":
        ev_res = evolve_per_bot_skills(quiet=False)
        print(json.dumps(ev_res, indent=2, ensure_ascii=False))
        return 0
    if cmd == "status":
        for handle in _list_bot_profile_handles():
            sync_bot_active_instincts(handle)
        sync_claude_mem_recent_rule()
        print(json.dumps(get_dream_status(), indent=2, ensure_ascii=False))
        return 0

    return subprocess.call([sys.executable, str(INSTINCT_CLI), cmd, *rest])


if __name__ == "__main__":
    sys.exit(main())
