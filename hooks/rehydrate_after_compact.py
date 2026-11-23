#!/usr/bin/env python3
"""Antigravity PreInvocation hook: Post-Compaction State Rehydration (+ /fork lineage stitching).

Adapted for local multi-bot environment:
- Bypasses internal background observer (`AGY_INTERNAL_OBSERVER=1` / `observer-sandbox` / `shim_session.json`).
- Excludes sensitive credential/profile directories and already-injected `.agents/rules/` from file rehydration.
- Filters bare `/compact` slash-command noise from user timeline.
"""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

MARKER_PREFIX = "[POST-COMPACT REHYDRATION v1"

BUDGET_ALL_USER_CHARS = 8_000
BUDGET_RECENT_TURNS_CHARS = 8_500
BUDGET_PLAN_SPECS_CHARS = 2_500
BUDGET_SINGLE_SPEC_CHARS = 1_500
MAX_KEPT_TURNS = 6
MAX_TURN_CHARS = 1_600

MAX_MODIFIED_FILES = 6
MAX_REFERENCED_FILES = 5
MAX_TOUCHED_SKILLS = 4
MAX_FORK_DEPTH = 8
FRESH_CHECKPOINT_MAX_GAP = 8

SHIM_STATE_FILE = Path(os.environ.get("AGY_SHIM_STATE_FILE", str(Path.home() / "agy-mem-hub/state/shim_session.json")))

SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".ico",
    ".pdf", ".pptx", ".docx", ".xlsx", ".zip", ".tar", ".gz", ".tgz", ".7z",
    ".mp4", ".mov", ".avi", ".mp3", ".wav", ".ogg",
    ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a",
    ".pt", ".pth", ".ckpt", ".safetensors", ".onnx", ".npy", ".npz", ".ply",
    ".db", ".sqlite", ".sqlite3", ".wal", ".shm", ".pb", ".pyc",
    ".pem", ".key", ".p12", ".pfx", ".env",
}

SKIP_PATH_SUBSTRINGS = (
    "/.system_generated/",
    "/node_modules/",
    "/.git/",
    "/__pycache__/",
    "/dev/shm/",
    "/tmp/",
    "/antigravity-cli/log/",
    "/antigravity-cli/history.jsonl",
    "/antigravity-cli/builtin/skills/antigravity_guide/",
    "/antigravity-cli/builtin/skills/agy-customizations/",
    "/.config/openbao/",
    "/.claude-mem/",
    "/.local/share/camoufox-profiles/",
    "/.cache/camoufox-profiles/",
    "/.agents/rules/",
    "/observer-sandbox/",
)

USER_REQ_RE = re.compile(r"<USER_REQUEST>\s*(.*?)\s*</USER_REQUEST>", re.S)


def get_observer_cids() -> set[str]:
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


def is_internal_observer_payload(payload: dict[str, Any], observer_cids: set[str]) -> bool:
    if os.environ.get("AGY_INTERNAL_OBSERVER") == "1":
        return True
    cid = str(payload.get("conversationId") or "").strip()
    if cid and cid in observer_cids:
        return True
    cwd = str(payload.get("cwd") or "")
    if "/observer-sandbox" in cwd:
        return True
    ws_list = payload.get("workspacePaths") or []
    if isinstance(ws_list, list) and any("/observer-sandbox" in str(w) for w in ws_list):
        return True
    return False


def extract_user_text(raw: str) -> str:
    if not raw:
        return ""
    matches = USER_REQ_RE.findall(raw)
    if matches:
        text = "\n".join(m.strip() for m in matches if m.strip())
    else:
        cleaned = re.sub(r"<CONTEXT_SUMMARY>.*?</CONTEXT_SUMMARY>", "", raw, flags=re.S)
        cleaned = re.sub(r"<ADDITIONAL_METADATA>.*?</ADDITIONAL_METADATA>", "", cleaned, flags=re.S)
        cleaned = re.sub(r"<SYSTEM_MESSAGE>.*?</SYSTEM_MESSAGE>", "", cleaned, flags=re.S)
        text = cleaned.strip()
    if text == "/compact" or text.startswith("<STATELESS_TASK"):
        return ""
    return text


def summarize_tool_calls(tool_calls: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for tc in tool_calls[:8]:
        name = tc.get("name", "?")
        args = tc.get("args") or tc.get("arguments") or {}
        if name in ("read_file", "edit_file", "write_file"):
            p = args.get("Path", "")
            parts.append(f"{name}({os.path.basename(p) or p})")
        elif name == "run_command":
            cmd = (args.get("CommandLine") or "").strip().replace("\n", " ")
            if len(cmd) > 60:
                cmd = cmd[:57] + "..."
            parts.append(f"run_command(`{cmd}`)")
        else:
            parts.append(name)
    if len(tool_calls) > 8:
        parts.append(f"+{len(tool_calls) - 8} more")
    return ", ".join(parts)


def is_eligible_text_file(path_str: str) -> bool:
    if not path_str or not path_str.startswith("/"):
        return False
    bname = os.path.basename(path_str).lower()
    if bname == ".env" or bname.startswith(".env.") or bname in ("card.json", "credentials.json", "secrets.json"):
        return False
    for sub in SKIP_PATH_SUBSTRINGS:
        if sub in path_str:
            return False
    if Path(path_str).suffix.lower() in SKIP_EXTS:
        return False
    p = Path(path_str)
    try:
        if not p.is_file():
            return False
        st = p.stat()
        return 0 < st.st_size <= 2 * 1024 * 1024
    except OSError:
        return False


def is_plan_or_spec(path_str: str) -> bool:
    name = os.path.basename(path_str)
    upper = name.upper()
    if upper in ("README.MD", "SKILL.MD"):
        return False
    return upper.endswith(".MD") and any(k in upper for k in ("SPEC", "PLAN", "HANDOFF"))


def is_skill_file(path_str: str) -> bool:
    return os.path.basename(path_str) == "SKILL.md"


def read_text_clipped(path_str: str, max_chars: int) -> str | None:
    try:
        with open(path_str, "r", encoding="utf-8") as f:
            text = f.read(max_chars * 3)
    except (OSError, UnicodeDecodeError):
        return None
    if len(text) <= max_chars:
        return text
    head_len = int(max_chars * 0.68)
    tail_len = max_chars - head_len - 80
    omitted = len(text) - head_len - max(0, tail_len)
    return (
        f"{text[:head_len]}\n"
        f"... [truncated ~{omitted} chars in middle; read_file for full content] ...\n"
        f"{text[-tail_len:] if tail_len > 0 else ''}"
    )


def parse_iso_epoch(ts_str: Any) -> float | None:
    if not isinstance(ts_str, str) or not ts_str:
        return None
    try:
        norm = ts_str[:-1] + "+00:00" if ts_str.endswith("Z") else ts_str
        return datetime.fromisoformat(norm).timestamp()
    except ValueError:
        return None


def infer_cid_from_transcript_path(tpath: Path) -> str:
    parts = tpath.parts
    if len(parts) >= 4 and parts[-2] == "logs" and parts[-3] == ".system_generated":
        return parts[-4]
    return tpath.parent.name


def read_first_step_info(jsonl_path: Path) -> tuple[int, float | None] | None:
    try:
        with open(jsonl_path, "rb") as f:
            for _ in range(16):
                raw = f.readline()
                if not raw:
                    return None
                if not raw.strip():
                    continue
                obj = json.loads(raw.decode("utf-8", "replace"))
                sidx = obj.get("step_index")
                if isinstance(sidx, int):
                    return sidx, parse_iso_epoch(obj.get("created_at"))
    except (OSError, json.JSONDecodeError):
        return None
    return None


def find_step_epoch_in_transcript(jsonl_path: Path, target_step: int) -> tuple[int, float | None] | None:
    try:
        st_size = jsonl_path.stat().st_size
        if st_size <= 0:
            return None
        tail_window = 65536
        with open(jsonl_path, "rb") as fb:
            seek_pos = max(0, st_size - tail_window)
            fb.seek(seek_pos)
            chunk = fb.read()
        raw_lines = chunk.splitlines()
        if seek_pos > 0 and raw_lines:
            raw_lines = raw_lines[1:]

        last_step: int | None = None
        for raw in reversed(raw_lines):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            sidx = obj.get("step_index")
            if not isinstance(sidx, int):
                continue
            if last_step is None:
                last_step = sidx
                if last_step < target_step:
                    return None
            if sidx == target_step:
                return last_step, parse_iso_epoch(obj.get("created_at"))
            if sidx < target_step:
                return None

        step_pat = re.compile(rb'"step_index"\s*:\s*' + str(target_step).encode("ascii") + rb"\b")
        with open(jsonl_path, "rb") as fb:
            for raw in fb:
                if step_pat.search(raw[:160]):
                    try:
                        obj = json.loads(raw.decode("utf-8", "replace"))
                    except json.JSONDecodeError:
                        continue
                    if obj.get("step_index") == target_step:
                        return (last_step or target_step), parse_iso_epoch(obj.get("created_at"))
        return None
    except OSError:
        return None


def load_history_fork_hints(brain_dir: Path) -> tuple[dict[str, set[str]], list[tuple[str, float]]]:
    cid_workspaces: dict[str, set[str]] = {}
    fork_events: list[tuple[str, float]] = []
    hist_path = brain_dir.parent / "history.jsonl"
    if not hist_path.is_file():
        return cid_workspaces, fork_events
    try:
        st_size = hist_path.stat().st_size
        with open(hist_path, "rb") as fb:
            seek_pos = max(0, st_size - 524288)
            fb.seek(seek_pos)
            lines = fb.read().splitlines()
        if seek_pos > 0 and lines:
            lines = lines[1:]
        for raw in lines:
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                continue
            cid = obj.get("conversationId")
            ws = obj.get("workspace")
            if isinstance(cid, str) and cid:
                if isinstance(ws, str) and ws:
                    cid_workspaces.setdefault(cid, set()).add(ws)
                if obj.get("display") == "/fork" and isinstance(obj.get("timestamp"), (int, float)):
                    fork_events.append((cid, float(obj["timestamp"]) / 1000.0))
    except OSError:
        pass
    return cid_workspaces, fork_events


def validate_cached_ancestors(cached: Any, cur_first_step: int) -> list[dict[str, Any]] | None:
    if not isinstance(cached, list) or not cached:
        return None
    cleaned: list[dict[str, Any]] = []
    for item in cached:
        if not isinstance(item, dict):
            return None
        p_str, cid, s_min, s_max = item.get("path"), item.get("cid"), item.get("min_step"), item.get("max_step")
        if (
            not isinstance(p_str, str) or not isinstance(cid, str)
            or not isinstance(s_min, int) or not isinstance(s_max, int)
            or s_min > s_max or not Path(p_str).is_file()
        ):
            return None
        cleaned.append({"cid": cid, "path": p_str, "min_step": s_min, "max_step": s_max})
    for idx in range(len(cleaned) - 1):
        if cleaned[idx]["max_step"] + 1 != cleaned[idx + 1]["min_step"]:
            return None
    return cleaned if cleaned[-1]["max_step"] + 1 == cur_first_step else None


def resolve_fork_ancestors(full_path: Path, cached_ancestors: Any = None) -> list[dict[str, Any]]:
    first_info = read_first_step_info(full_path)
    if first_info is None or first_info[0] <= 0:
        return []
    cur_first_step, cur_first_epoch = first_info
    valid_cache = validate_cached_ancestors(cached_ancestors, cur_first_step)
    if valid_cache is not None:
        return valid_cache

    parts = full_path.parts
    if len(parts) < 5 or parts[-2] != "logs" or parts[-3] != ".system_generated":
        return []
    brain_dir = full_path.parents[3]
    if not brain_dir.is_dir():
        return []

    observer_cids = get_observer_cids()
    cid_workspaces, fork_events = load_history_fork_hints(brain_dir)
    cur_cid = infer_cid_from_transcript_path(full_path)
    visited: set[str] = {cur_cid}
    visited.update(observer_cids)
    ancestors_rev: list[dict[str, Any]] = []
    child_cid, child_first_step, child_first_epoch = cur_cid, cur_first_step, cur_first_epoch

    for _ in range(MAX_FORK_DEPTH):
        if child_first_step <= 0:
            break
        need_prev = child_first_step - 1
        child_ws = cid_workspaces.get(child_cid, set())
        best_score: tuple[int, int, int, float] | None = None
        best_seg: tuple[str, Path, int, float | None] | None = None

        try:
            cand_dirs = list(brain_dir.iterdir())
        except OSError:
            break

        for cand_dir in cand_dirs:
            cand_cid = cand_dir.name
            if cand_cid in visited or not cand_dir.is_dir():
                continue
            cand_logs = cand_dir / ".system_generated" / "logs"
            cand_full = cand_logs / "transcript_full.jsonl"
            if not cand_full.is_file():
                cand_full = cand_logs / "transcript.jsonl"
                if not cand_full.is_file():
                    continue
            cand_first = read_first_step_info(cand_full)
            if cand_first is None or cand_first[0] < 0 or cand_first[0] > need_prev:
                continue
            hit = find_step_epoch_in_transcript(cand_full, need_prev)
            if hit is None:
                continue
            cand_last_step, prev_epoch = hit
            if child_first_epoch is not None and prev_epoch is not None:
                if prev_epoch > child_first_epoch + 5.0:
                    continue
                time_delta = max(0.0, child_first_epoch - prev_epoch)
            else:
                time_delta = 1e9

            fork_cmd_match = int(any(
                fcid == cand_cid
                and (prev_epoch is None or fts >= prev_epoch - 5.0)
                and (child_first_epoch is None or fts <= child_first_epoch + 5.0)
                for fcid, fts in fork_events
            ))
            cand_ws = cid_workspaces.get(cand_cid, set())
            same_ws = int(bool(child_ws and cand_ws and (child_ws & cand_ws)))
            exact_tip = int(cand_last_step == need_prev)
            score = (fork_cmd_match, same_ws, exact_tip, -time_delta)
            if best_score is None or score > best_score:
                best_score = score
                best_seg = (cand_cid, cand_full, cand_first[0], cand_first[1])

        if best_seg is None:
            break
        p_cid, p_path, p_first_step, p_first_epoch = best_seg
        ancestors_rev.append({"cid": p_cid, "path": str(p_path), "min_step": p_first_step, "max_step": need_prev})
        visited.add(p_cid)
        child_cid, child_first_step, child_first_epoch = p_cid, p_first_step, p_first_epoch
        if p_first_step <= 0:
            break

    ancestors_rev.reverse()
    return ancestors_rev


def find_transcript_files(payload: dict[str, Any]) -> tuple[Path | None, Path | None, Path | None]:
    tp = payload.get("transcriptPath") or ""
    ad = payload.get("artifactDirectoryPath") or ""
    cid = payload.get("conversationId") or ""
    candidates: list[Path] = []
    if tp:
        candidates.append(Path(tp))
    if ad:
        candidates.append(Path(ad) / ".system_generated" / "logs" / "transcript.jsonl")
    if cid:
        candidates.append(
            Path.home() / ".gemini" / "antigravity-cli" / "brain" / cid / ".system_generated" / "logs" / "transcript.jsonl"
        )
    compact_path = next((c for c in candidates if c.is_file()), None)
    if compact_path is None:
        return None, None, None
    logs_dir = compact_path.parent
    full_path = logs_dir / "transcript_full.jsonl"
    return compact_path, (full_path if full_path.is_file() else compact_path), logs_dir / "rehydrate_state.json"


def scan_compact_tail(compact_path: Path, prev_offset: int, prev_cp: int | None) -> tuple[int | None, int, int]:
    st_size = compact_path.stat().st_size
    if st_size == prev_offset and prev_offset > 0:
        return prev_cp, -1, st_size
    use_incremental = False
    if 0 < prev_offset < st_size:
        with open(compact_path, "rb") as fb_chk:
            fb_chk.seek(prev_offset - 1)
            use_incremental = fb_chk.read(1) == b"\n"
    latest_cp = prev_cp if use_incremental else None
    max_step = -1
    with open(compact_path, "rb") as fb:
        if use_incremental:
            fb.seek(prev_offset)
        for raw_line in fb:
            if not raw_line.strip():
                continue
            if b'"CHECKPOINT"' in raw_line:
                try:
                    obj = json.loads(raw_line.decode("utf-8", "replace"))
                    sidx = obj.get("step_index", -1)
                    max_step = max(max_step, sidx)
                    if obj.get("type") == "CHECKPOINT":
                        latest_cp = sidx
                except json.JSONDecodeError:
                    pass
            else:
                m = re.search(rb'"step_index"\s*:\s*(\d+)', raw_line[:128])
                if m:
                    max_step = max(max_step, int(m.group(1)))
    return latest_cp, max_step, st_size


def build_rehydration(
    full_path: Path,
    up_to_checkpoint_step: int | None = None,
    ancestors: list[dict[str, Any]] | None = None,
) -> tuple[str, dict[str, Any]] | None:
    checkpoints: list[int] = []
    already_rehydrated_after: set[int] = set()
    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
        last_cp: int | None = None
        for line in f:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            step_idx = obj.get("step_index", -1)
            if up_to_checkpoint_step is not None and step_idx > up_to_checkpoint_step:
                break
            stype = obj.get("type")
            if stype == "CHECKPOINT":
                checkpoints.append(step_idx)
                last_cp = step_idx
            elif stype == "SYSTEM_MESSAGE" and last_cp is not None:
                if MARKER_PREFIX in str(obj.get("content") or ""):
                    already_rehydrated_after.add(last_cp)

    if not checkpoints:
        return None
    target_cp = checkpoints[-1]
    if up_to_checkpoint_step is None and target_cp in already_rehydrated_after:
        return None

    cur_cid = infer_cid_from_transcript_path(full_path)
    cur_first_info = read_first_step_info(full_path)
    cur_first_step = cur_first_info[0] if cur_first_info is not None else 0
    resolved_ancestors = ancestors if ancestors is not None else resolve_fork_ancestors(full_path)
    segments: list[dict[str, Any]] = [
        *resolved_ancestors,
        {"cid": cur_cid, "path": str(full_path), "min_step": cur_first_step, "max_step": target_cp - 1},
    ]

    user_messages: list[tuple[int, str]] = []
    dialogue_entries: list[str] = []
    modified_touch: dict[str, int] = {}
    read_touch: dict[str, int] = {}
    plan_spec_touch: dict[str, int] = {}
    skill_touch: dict[str, int] = {}
    pending_tools: list[str] = []

    for seg_idx, seg in enumerate(segments):
        seg_path = Path(seg["path"])
        seg_min = int(seg["min_step"])
        seg_max = min(int(seg["max_step"]), target_cp - 1)
        if seg_min > seg_max or not seg_path.is_file():
            continue
        if seg_idx > 0:
            fork_banner = f"--- [/fork branch {str(segments[seg_idx - 1]['cid'])[:8]} -> {str(seg['cid'])[:8]} @ step {seg_min}] ---"
            user_messages.append((seg_min, fork_banner))
            dialogue_entries.append(fork_banner)

        with open(seg_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                step_idx = obj.get("step_index", -1)
                if step_idx < seg_min:
                    continue
                if step_idx > seg_max:
                    break
                stype = obj.get("type")
                if stype == "USER_INPUT":
                    utext = extract_user_text(str(obj.get("content") or ""))
                    if utext:
                        user_messages.append((step_idx, utext))
                        dialogue_entries.append(f"[Step {step_idx} | User]:\n{utext}")
                    pending_tools.clear()
                elif stype == "PLANNER_RESPONSE":
                    tcs = _filter_tool_calls_for_worker(obj.get("tool_calls") or [])
                    if tcs:
                        pending_tools.append(summarize_tool_calls(tcs))
                        for tc in tcs:
                            tname = tc.get("name")
                            targs = tc.get("args") or tc.get("arguments") or {}
                            fpath = targs.get("Path")
                            if isinstance(fpath, str) and fpath.startswith("/"):
                                if is_skill_file(fpath) and is_eligible_text_file(fpath):
                                    skill_touch[fpath] = step_idx
                                elif is_plan_or_spec(fpath) and is_eligible_text_file(fpath):
                                    plan_spec_touch[fpath] = step_idx
                                elif tname in ("edit_file", "write_file"):
                                    modified_touch[fpath] = step_idx
                                elif tname == "read_file":
                                    read_touch[fpath] = step_idx
                    mcontent = str(obj.get("content") or "").strip()
                    if mcontent:
                        tool_prefix = ""
                        if pending_tools:
                            joined_tools = " -> ".join(pending_tools[:6])
                            if len(pending_tools) > 6:
                                joined_tools += f" (+{len(pending_tools) - 6} steps)"
                            tool_prefix = f"  (Tools run: {joined_tools})\n"
                            pending_tools.clear()
                        dialogue_entries.append(f"[Step {step_idx} | Assistant]:\n{tool_prefix}{mcontent}")

    if pending_tools:
        dialogue_entries.append(f"[Pre-Compaction In-Progress Tools]: {' -> '.join(pending_tools[:6])}")

    real_user_count = 0
    user_lines: list[str] = []
    for s, txt in user_messages:
        if txt.startswith("--- [/fork branch "):
            user_lines.append(f"- {txt}")
        else:
            real_user_count += 1
            clipped_txt = txt if len(txt) <= 600 else (txt[:420] + " ...[clipped]... " + txt[-140:])
            user_lines.append(f"- [#{real_user_count} @ step {s}]: {clipped_txt}")

    all_user_block = "\n".join(user_lines)
    if len(all_user_block) > BUDGET_ALL_USER_CHARS and len(user_lines) > 8:
        head_part = "\n".join(user_lines[:4])
        tail_lines: list[str] = []
        used = len(head_part) + 100
        for ul in reversed(user_lines[4:]):
            if used + len(ul) + 1 > BUDGET_ALL_USER_CHARS:
                break
            tail_lines.append(ul)
            used += len(ul) + 1
        tail_lines.reverse()
        all_user_block = f"{head_part}\n- [... earlier middle prompts omitted for budget ...]\n" + "\n".join(tail_lines)

    kept_turns: list[str] = []
    used_turns = 0
    for entry in reversed(dialogue_entries):
        if len(kept_turns) >= MAX_KEPT_TURNS:
            break
        clipped_entry = (
            entry
            if len(entry) <= MAX_TURN_CHARS
            else (entry[:1100] + "\n...[turn clipped]...\n" + entry[-400:])
        )
        if used_turns + len(clipped_entry) > BUDGET_RECENT_TURNS_CHARS and kept_turns:
            break
        kept_turns.append(clipped_entry)
        used_turns += len(clipped_entry) + 2
    kept_turns.reverse()

    spec_blocks: list[str] = []
    used_specs = 0
    for spath, sstep in sorted(plan_spec_touch.items(), key=lambda x: x[1], reverse=True):
        if not is_eligible_text_file(spath):
            continue
        rem = BUDGET_PLAN_SPECS_CHARS - used_specs
        if rem < 400:
            break
        content = read_text_clipped(spath, min(BUDGET_SINGLE_SPEC_CHARS, rem))
        if content:
            block = f"### `{spath}` (touched @ step {sstep})\n```\n{content}\n```"
            spec_blocks.append(block)
            used_specs += len(block)

    mod_candidates = [
        (p, st) for p, st in sorted(modified_touch.items(), key=lambda x: x[1], reverse=True)
        if p not in plan_spec_touch and p not in skill_touch and is_eligible_text_file(p)
    ][:MAX_MODIFIED_FILES]
    mod_set = {p for p, _ in mod_candidates}
    ref_candidates = [
        (p, st) for p, st in sorted(read_touch.items(), key=lambda x: x[1], reverse=True)
        if p not in plan_spec_touch and p not in skill_touch and p not in mod_set and is_eligible_text_file(p)
    ][:MAX_REFERENCED_FILES]
    skill_candidates = [
        (p, st) for p, st in sorted(skill_touch.items(), key=lambda x: x[1], reverse=True)
        if is_eligible_text_file(p)
    ][:MAX_TOUCHED_SKILLS]

    index_lines: list[str] = []
    for role_label, items in (
        ("Modified", mod_candidates),
        ("Referenced", ref_candidates),
        ("Skill", skill_candidates),
    ):
        for fpath, fstep in items:
            try:
                sz_kb = Path(fpath).stat().st_size / 1024.0
                size_tag = f" ({sz_kb:.1f} KB)"
            except OSError:
                size_tag = ""
            index_lines.append(f"- [{role_label} @ step {fstep}] `{fpath}`{size_tag}")

    index_lines, spec_blocks = _filter_rehydration_for_bot(index_lines, spec_blocks)

    lineage_tag = ""
    if resolved_ancestors:
        chain_parts = [
            f"{str(seg['cid'])[:8]}({seg['min_step']}..{min(int(seg['max_step']), target_cp - 1)})"
            for seg in segments
            if int(seg["min_step"]) <= min(int(seg["max_step"]), target_cp - 1)
        ]
        lineage_tag = f" | fork_lineage={'->'.join(chain_parts)}"

    sections = [
        f"{MARKER_PREFIX} | checkpoint={target_cp}{lineage_tag}]",
        (
            "The harness just compacted earlier history into `<CONTEXT_SUMMARY>`, which is lossy. "
            "Below is the lossless state automatically rehydrated from `transcript_full.jsonl` "
            "(including any `/fork` ancestor transcripts). "
            "Whenever `<CONTEXT_SUMMARY>` conflicts with or omits details present in these verbatim records, "
            "trust the verbatim text below and use `read_file` on demand for any file paths listed."
        ),
        f"## 1. Complete User Request Timeline ({real_user_count} messages verbatim)\n{all_user_block}",
        (
            f"## 2. Recent Pre-Compaction Verbatim Dialogue ({len(kept_turns)} entries kept verbatim)\n"
            "*(Note: The messages below are the actual pre-compaction turns kept verbatim.)*\n\n"
            + "\n\n".join(kept_turns)
        ),
    ]
    if spec_blocks:
        sections.append("## 3. Active Plan & Spec Docs\n" + "\n\n".join(spec_blocks))
    if index_lines:
        sections.append(
            "## 4. Recently Touched Workspace Files & Skills (Paths Only — `read_file` on demand)\n"
            + "\n".join(index_lines)
        )
    bot_identity_block = _build_bot_identity_rehydration_section()
    if bot_identity_block:
        sections.append(f"## 5. Active Bot Identity & Memory Scope\n{bot_identity_block}")

    full_msg = "\n\n".join(sections)
    return full_msg, {
        "checkpoint": target_cp,
        "fork_hops": len(resolved_ancestors),
        "user_msgs": real_user_count,
        "kept_turns": len(kept_turns),
        "specs": len(spec_blocks),
        "indexed_paths": len(index_lines),
        "chars": len(full_msg),
        "est_tokens": len(full_msg) // 3,
    }


def _load_bot_profiles_module():
    candidates = [
        Path(__file__).resolve().parents[1] / "bridge",
        Path(os.environ.get("AGY_BRIDGE_DIR", str(Path.home() / "agy-tg-bridge"))),
    ]
    for cand in candidates:
        if (cand / "bot_profiles.py").is_file():
            if str(cand) not in sys.path:
                sys.path.insert(0, str(cand))
            break
    try:
        import bot_profiles  # type: ignore

        return bot_profiles
    except Exception:
        return None


def _is_cross_bot_or_mem_text(
    text: str,
    self_handle: str,
    profiles_root: Path,
    *,
    skill_policy: tuple[str, set[str]] | None = None,
) -> bool:
    if not text:
        return False
    low = text.replace("\\", "/").lower()
    if (
        "/.claude-mem/" in low
        or low.endswith("/.claude-mem")
        or "/.claude-mem`" in low
        or re.search(r"(?:^|[\s`'\"(/])\.claude-mem(?:/|[`'\"\s)>]|$)", low)
        or re.search(r"(?:^|[\s`'\"(/])claude-mem\.db(?:-wal|-shm)?(?:[`'\"\s)>]|$)", low)
    ):
        return True
    root_variants: list[str] = ["/.config/agy-tg-bridge/bots"]
    for p in (profiles_root, profiles_root.resolve(strict=False)):
        s = str(p).replace("\\", "/").rstrip("/").lower()
        if s and s not in root_variants:
            root_variants.append(s)
    for root_s in root_variants:
        pat = re.compile(re.escape(root_s) + r"/([^/\s`\"'<>)]+)")
        for m in pat.finditer(low):
            seg = m.group(1).strip()
            if seg and seg != self_handle:
                return True
    if skill_policy is not None:
        policy_mode, allowed_catalog = skill_policy
        if policy_mode != "all":
            allowed_low = {str(s).lower() for s in (allowed_catalog or set())}
            for m in re.finditer(r"(?:^|[\s`'\"(/])\.agents/skills/([^/\s`'\"<>)]+)", low):
                slug = m.group(1).strip().rstrip(".,;:")
                if slug and slug not in allowed_low:
                    return True
            if re.search(r"(?:^|[\s`'\"(/])\.agents/skills/?(?:[`'\"\s)>.,;:]|$)", low):
                return True
    return False


def _resolve_worker_filter_ctx() -> tuple[str, Path, tuple[str, set[str]]] | None:
    raw_handle = os.environ.get("AGY_BOT_HANDLE", "").strip()
    if not raw_handle:
        return None
    role = str(os.environ.get("AGY_BOT_BUS_ROLE", "worker") or "worker").strip().lower()
    if role == "coordinator":
        return None
    bp = _load_bot_profiles_module()
    if bp is None:
        return None
    norm_handle = bp.normalize_bot_handle(raw_handle)
    if not norm_handle:
        return None
    profiles_root = bp.resolve_profiles_dir()
    try:
        skill_policy = bp.get_worker_allowed_catalog_slugs(norm_handle, profiles_dir=profiles_root)
    except Exception:
        skill_policy = ("allowlist", set())
    return norm_handle, profiles_root, skill_policy


def _filter_tool_calls_for_worker(tcs: list[Any]) -> list[Any]:
    if not tcs or not os.environ.get("AGY_BOT_HANDLE", "").strip():
        return tcs
    ctx = _resolve_worker_filter_ctx()
    if ctx is None:
        return tcs
    norm_handle, profiles_root, skill_policy = ctx
    kept: list[Any] = []
    for tc in tcs:
        if not isinstance(tc, dict):
            kept.append(tc)
            continue
        targs = tc.get("args") or tc.get("arguments") or {}
        blocked = False
        if isinstance(targs, dict):
            for val in targs.values():
                if isinstance(val, str):
                    if _is_cross_bot_or_mem_text(
                        val, norm_handle, profiles_root, skill_policy=skill_policy
                    ):
                        blocked = True
                        break
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and _is_cross_bot_or_mem_text(
                            item, norm_handle, profiles_root, skill_policy=skill_policy
                        ):
                            blocked = True
                            break
                    if blocked:
                        break
            if not blocked:
                try:
                    serialized = json.dumps(targs, ensure_ascii=False)
                    if _is_cross_bot_or_mem_text(
                        serialized, norm_handle, profiles_root, skill_policy=skill_policy
                    ):
                        blocked = True
                except Exception:
                    pass
        if not blocked:
            kept.append(tc)
    return kept


def _filter_rehydration_for_bot(
    index_lines: list[str],
    spec_blocks: list[str],
) -> tuple[list[str], list[str]]:
    ctx = _resolve_worker_filter_ctx()
    if ctx is None:
        return index_lines, spec_blocks
    norm_handle, profiles_root, skill_policy = ctx
    filtered_index = [
        ln
        for ln in index_lines
        if not _is_cross_bot_or_mem_text(
            ln, norm_handle, profiles_root, skill_policy=skill_policy
        )
    ]
    filtered_specs = [
        sb
        for sb in spec_blocks
        if not _is_cross_bot_or_mem_text(
            sb, norm_handle, profiles_root, skill_policy=skill_policy
        )
    ]
    return filtered_index, filtered_specs


def _summarize_bot_rules_snippet(bp: Any, bot_dir: Path, max_chars: int = 240) -> str:
    rules_path = bot_dir / "RULES.md"
    if not rules_path.is_file() or rules_path.is_symlink():
        return ""
    try:
        raw = bp._read_text_nofollow(rules_path, base_dir=bot_dir, max_bytes=4096)
    except Exception:
        return ""
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return ""
    joined = " | ".join(lines)
    if len(joined) > max_chars:
        return joined[: max_chars - 1].rstrip() + "…"
    return joined


def _build_bot_identity_rehydration_section() -> str:
    raw_handle = os.environ.get("AGY_BOT_HANDLE", "").strip()
    if not raw_handle:
        return ""
    bp = _load_bot_profiles_module()
    if bp is None:
        return ""
    norm_handle = bp.normalize_bot_handle(raw_handle)
    if not norm_handle:
        return ""
    role = str(os.environ.get("AGY_BOT_BUS_ROLE", "worker") or "worker").strip().lower()
    effective_role = "coordinator" if role == "coordinator" else "worker"

    parts: list[str] = []
    try:
        _rev, rendered = bp.render_bot_profile_prompt(
            norm_handle,
            role=effective_role,
            max_section_chars=3000,
        )
        if rendered:
            parts.append(rendered)
    except Exception:
        pass

    if effective_role == "coordinator":
        try:
            root = bp.resolve_profiles_dir()
            handles = bp.list_profile_handles(profiles_dir=root)
            overview_lines: list[str] = []
            for h in handles:
                bot_dir = root / h
                sk_info = bp.resolve_effective_skills(
                    h,
                    role="coordinator" if h == norm_handle else "worker",
                    profiles_dir=root,
                    include_paths=False,
                )
                own_slugs = [str(s.get("slug") or "") for s in sk_info.get("own_skills") or [] if s.get("slug")]
                en_cat = [
                    str(s.get("slug") or "")
                    for s in sk_info.get("catalog_skills") or []
                    if s.get("enabled") and s.get("slug")
                ]
                rules_snip = _summarize_bot_rules_snippet(bp, bot_dir)
                item = f"- `@{h}` | `memory_project=bot-{h}`"
                if own_slugs:
                    item += f" | own_skills={','.join(own_slugs[:12])}"
                if en_cat:
                    item += f" | catalog_skills={','.join(en_cat[:12])}"
                if rules_snip:
                    item += f" | rules: {rules_snip}"
                overview_lines.append(item)
            if overview_lines:
                parts.append(
                    "### Team Bots Aggregation (Coordinator Full Visibility)\n"
                    + "\n".join(overview_lines)
                )
        except Exception:
            pass

    return "\n\n".join(parts).strip()


def save_state(state_path: Path, cp: int | None, offset: int, fork_ancestors: list[dict[str, Any]] | None = None) -> None:
    try:
        data: dict[str, Any] = {"last_rehydrated_checkpoint": cp, "checked_offset": offset}
        if fork_ancestors:
            data["fork_ancestors"] = fork_ancestors
        state_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def main() -> None:
    try:
        if os.environ.get("AGY_INTERNAL_OBSERVER") == "1":
            print("{}")
            return
        raw_in = sys.stdin.read()
        if not raw_in.strip():
            print("{}")
            return
        payload = json.loads(raw_in)
        if is_internal_observer_payload(payload, get_observer_cids()):
            print("{}")
            return

        compact_path, full_path, state_path = find_transcript_files(payload)
        if compact_path is None or full_path is None or state_path is None:
            print("{}")
            return

        had_state = state_path.is_file()
        state: dict[str, Any] = {}
        if had_state:
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                had_state = False

        prev_cp = state.get("last_rehydrated_checkpoint")
        prev_offset = int(state.get("checked_offset") or 0)
        cached_ancestors = state.get("fork_ancestors")
        latest_cp, max_step, new_offset = scan_compact_tail(compact_path, prev_offset, prev_cp)

        if latest_cp is None or latest_cp == prev_cp:
            save_state(state_path, latest_cp, new_offset, cached_ancestors)
            print("{}")
            return

        if not had_state and max_step > latest_cp and (max_step - latest_cp) > FRESH_CHECKPOINT_MAX_GAP:
            ancestors = resolve_fork_ancestors(full_path, cached_ancestors)
            save_state(state_path, latest_cp, new_offset, ancestors)
            print("{}")
            return

        ancestors = resolve_fork_ancestors(full_path, cached_ancestors)
        res = build_rehydration(full_path, ancestors=ancestors)
        save_state(state_path, latest_cp, new_offset, ancestors)
        if res is None:
            print("{}")
            return

        full_msg, _ = res
        print(json.dumps({"injectSteps": [{"systemMessage": {"systemMessage": full_msg}}]}, ensure_ascii=False))
    except Exception:
        print("{}")


if __name__ == "__main__":
    main()
