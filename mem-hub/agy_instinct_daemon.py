#!/usr/bin/env python3
"""Native Antigravity (`agy`) Continuous-Learning v2 ("Instinct -> Skill") Daemon & CLI.

- Zero foreground hook latency: tails `~/.gemini/antigravity-cli/brain/*/.system_generated/logs/transcript.jsonl`
  asynchronously (skipping the internal observer session).
- Scrubs secrets before persisting observations to `~/.local/share/ecc-homunculus/observations.jsonl`.
- Calls our local `agy-llm-shim` (`http://127.0.0.1:18791/v1/chat/completions`, `gemini-3.8-flash-high`)
  to extract/update atomic instincts (`0.30`..`0.95` confidence) in ECC v2.1 YAML format.
- Syncs high-confidence instincts (`>= 0.60`) to `$HOME/agy-workspace/.agents/rules/ecc-active-instincts.md`
  and syncs evolved skills (`evolve`) to `$HOME/agy-workspace/.agents/skills/evolved-<slug>/SKILL.md`.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHIM_URL = os.environ.get("AGY_SHIM_COMPLETIONS_URL", "http://127.0.0.1:18791/v1/chat/completions")
SHIM_MODEL = os.environ.get("AGY_SHIM_MODEL", "gemini-3.8-flash-low")

BRAIN_ROOT = Path.home() / ".gemini" / "antigravity-cli" / "brain"
HOMUNCULUS_DIR = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))) / "ecc-homunculus"
PERSONAL_INSTINCTS_DIR = HOMUNCULUS_DIR / "instincts" / "personal"
EVOLVED_SKILLS_DIR = HOMUNCULUS_DIR / "evolved" / "skills"
OBSERVATIONS_FILE = HOMUNCULUS_DIR / "observations.jsonl"

HUB_DIR = Path(os.environ.get("AGY_MEM_HUB_DIR", str(Path.home() / "agy-mem-hub")))
STATE_DIR = HUB_DIR / "state"
SHIM_STATE_FILE = STATE_DIR / "shim_session.json"
DAEMON_STATE_FILE = STATE_DIR / "instinct_daemon_state.json"

WORKSPACE_AGENTS_DIR = Path(os.environ.get("AGY_WORKSPACE_DIR", str(Path.home() / "agy-workspace"))) / ".agents"
ACTIVE_RULE_FILE = WORKSPACE_AGENTS_DIR / "rules" / "ecc-active-instincts.md"
CLAUDE_MEM_RECENT_RULE_FILE = WORKSPACE_AGENTS_DIR / "rules" / "claude-mem-recent.md"
WORKSPACE_SKILLS_DIR = WORKSPACE_AGENTS_DIR / "skills"
INSTINCT_CLI = WORKSPACE_SKILLS_DIR / "continuous-learning-v2" / "scripts" / "instinct-cli.py"
CLAUDE_MEM_CONTEXT_URL = "http://127.0.0.1:37701/api/context/inject?projects=agy-workspace"
BRIDGE_RELOAD_FILES = [Path("/tmp/agy_bridge_reload"), Path("/tmp/agy_bridge_sg_reload")]

POLL_INTERVAL_SEC = 180
MIN_OBS_FOR_BATCH = 40
MIN_OBS_ON_CORRECTION = 6
ANALYSIS_COOLDOWN_SEC = 1800
MAX_EVOLVED_SKILLS = 8

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


SCHEDULED_CIDS_FILE = Path.home() / ".gemini" / "antigravity-cli" / "cache" / "scheduled_cids.json"


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


def load_daemon_state() -> dict[str, Any]:
    try:
        if DAEMON_STATE_FILE.exists():
            return json.loads(DAEMON_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {"transcript_offsets": {}, "last_analyzed_obs_line": 0, "last_analysis_ts": 0.0}


def save_daemon_state(st: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = DAEMON_STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(DAEMON_STATE_FILE)


def ensure_dirs() -> None:
    for d in (
        PERSONAL_INSTINCTS_DIR,
        EVOLVED_SKILLS_DIR,
        STATE_DIR,
        WORKSPACE_AGENTS_DIR / "rules",
        WORKSPACE_SKILLS_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True)


def harvest_transcripts(state: dict[str, Any]) -> tuple[int, bool]:
    """Read new steps from agy brain transcripts and append sanitized observations."""
    ensure_dirs()
    observer_cids = get_observer_cids()
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
        head_sample = "\n".join(lines[:12])
        if "<STATELESS_TASK>" in head_sample or "[ACB_SCHEDULED_TASK" in head_sample:
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

        for raw in lines[start_idx:]:
            raw = raw.strip()
            if not raw:
                continue
            try:
                step = json.loads(raw)
            except json.JSONDecodeError:
                continue

            stype = step.get("type")
            ts = step.get("created_at") or now_iso

            if stype == "USER_INPUT":
                user_txt = scrub_secrets(unwrap_user_request(str(step.get("content") or "")))
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
        if new_obs:
            with OBSERVATIONS_FILE.open("a", encoding="utf-8") as f:
                for row in new_obs:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
            appended += len(new_obs)

    return appended, saw_correction


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
            meta["confidence"] = float(meta.get("confidence") or 0.5)
            meta["body"] = body
            meta["path"] = str(p)
            result[iid] = meta
        except Exception:
            continue
    return result


def write_instinct_yaml(inst: dict[str, Any]) -> Path:
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
    if not any("Last observed" in e for e in ev_lines):
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
    """Ensure rolling claude-mem timeline is NOT written as an `always_on` rule file.

    Mutating `.agents/rules/claude-mem-recent.md` every 30s invalidates `<user_rules>` at the top
    of the system prompt and wipes out 100k+ token prompt prefix caches across active sessions.
    Cross-session memory is already injected once at `SessionStart` and searchable on demand via
    the `claude-mem` MCP server / `mem-search` skill.
    """
    if CLAUDE_MEM_RECENT_RULE_FILE.exists():
        try:
            CLAUDE_MEM_RECENT_RULE_FILE.unlink()
            return True
        except Exception:
            pass
    return False


def sync_active_instincts_rule() -> tuple[int, bool]:
    """Render high-confidence (>=0.80) instincts into .agents/rules/ecc-active-instincts.md
    using deterministic ordering and omitting volatile confidence percentages to preserve prompt cache.
    """
    existing = load_existing_instincts()
    active = [v for v in existing.values() if float(v.get("confidence", 0)) >= 0.80]
    active.sort(key=lambda x: (-float(x.get("confidence", 0)), str(x.get("id", ""))))
    active = active[:15]
    # Sort deterministically by (domain, id) so minor confidence updates do not reorder or mutate <user_rules>
    active.sort(key=lambda x: (str(x.get("domain", "general")), str(x.get("id", ""))))

    if not active:
        if ACTIVE_RULE_FILE.exists():
            ACTIVE_RULE_FILE.unlink()
            return 0, True
        return 0, False

    lines = [
        "---",
        "trigger: always_on",
        "description: Auto-synced high-confidence learned instincts from ECC continuous-learning-v2",
        "---",
        "",
        "# Learned Workspace Instincts (ECC Auto-Synced)",
        "",
        "Apply these verified user & workflow preferences when their trigger matches:",
        "",
    ]
    for inst in active:
        trig = re.sub(r"^when\s+", "", str(inst.get("trigger", "")).strip(), flags=re.IGNORECASE)
        body = inst.get("body", "")
        act_m = re.search(r"## Action\s*\n\s*(.+?)(?:\n\n|\n##|$)", body, re.DOTALL)
        act_txt = act_m.group(1).strip().replace("\n", " ") if act_m else body.splitlines()[0]
        lines.append(f"- **[{inst.get('domain', 'general')}]** When {trig}: {act_txt}")

    rendered = "\n".join(lines) + "\n"
    ACTIVE_RULE_FILE.parent.mkdir(parents=True, exist_ok=True)
    old = ACTIVE_RULE_FILE.read_text(encoding="utf-8") if ACTIVE_RULE_FILE.is_file() else ""
    changed = old != rendered
    if changed:
        tmp = ACTIVE_RULE_FILE.with_suffix(".md.tmp")
        tmp.write_text(rendered, encoding="utf-8")
        tmp.replace(ACTIVE_RULE_FILE)
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
    """Mirror evolved skills from ~/.local/share/ecc-homunculus/**/evolved/skills into workspace .agents/skills/."""
    synced: list[str] = []
    any_changed = False
    candidate_dirs = [EVOLVED_SKILLS_DIR]
    projects_root = HOMUNCULUS_DIR / "projects"
    if projects_root.is_dir():
        for pdir in projects_root.iterdir():
            es = pdir / "evolved" / "skills"
            if es.is_dir():
                candidate_dirs.append(es)

    # Collect candidates keyed by deduplicated clean_slug; prefer LLM-synthesized skills over raw boilerplate stubs
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

    # Cap total active evolved skills by richness/size so <skills> prompt stays lean
    chosen = sorted(by_slug.items(), key=lambda kv: (-kv[1][0][0], -kv[1][0][1], kv[0]))[:MAX_EVOLVED_SKILLS]

    for clean_slug, (_rank, normalized) in sorted(chosen, key=lambda kv: kv[0]):
        dest_name = f"evolved-{clean_slug}"
        dest_dir = WORKSPACE_SKILLS_DIR / dest_name
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / "SKILL.md"
        old = dest_file.read_text(encoding="utf-8") if dest_file.is_file() else ""
        if old != normalized:
            dest_file.write_text(normalized, encoding="utf-8")
            any_changed = True
        synced.append(str(dest_file))
    return synced, any_changed


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
    harvested, saw_corr = harvest_transcripts(state)
    save_daemon_state(state)

    if not OBSERVATIONS_FILE.is_file():
        return {"status": "no_observations", "harvested": harvested}

    all_lines = OBSERVATIONS_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    last_idx = int(state.get("last_analyzed_obs_line") or 0)
    if last_idx > len(all_lines):
        last_idx = 0
    pending = all_lines[last_idx:]

    min_needed = MIN_OBS_ON_CORRECTION if saw_corr else MIN_OBS_FOR_BATCH
    if not force:
        if len(pending) < min_needed:
            return {"status": "waiting_for_more", "pending": len(pending), "needed": min_needed}
        if (time.time() - float(state.get("last_analysis_ts") or 0)) < ANALYSIS_COOLDOWN_SEC:
            return {"status": "cooldown", "pending": len(pending)}

    if not pending:
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
    # Extract JSON array from reply
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
    for item in items[:8]:
        iid = re.sub(r"[^a-z0-9._-]+", "-", str(item["id"]).lower()).strip("-")
        if iid in existing:
            # Preserve prior evidence lines and merge
            old_body = existing[iid].get("body", "")
            old_ev = re.findall(r"^- (.+)$", old_body, re.MULTILINE)
            old_ev = [e for e in old_ev if not e.startswith("Last observed:")]
            new_ev = item.get("evidence") or []
            if isinstance(new_ev, str):
                new_ev = [new_ev]
            merged_ev = list(dict.fromkeys(old_ev + [str(x) for x in new_ev]))[-5:]
            item["evidence"] = merged_ev
        out_p = write_instinct_yaml(item)
        written_ids.append(out_p.stem)

    state["last_analyzed_obs_line"] = len(all_lines)
    state["last_analysis_ts"] = time.time()
    save_daemon_state(state)

    synced_rules, rules_changed = sync_active_instincts_rule()
    sync_claude_mem_recent_rule()

    # Auto-evolve when 3+ high-confidence (>=0.80) instincts exist in a domain not yet evolved,
    # staying under MAX_EVOLVED_SKILLS to keep <skills> prompt overhead bounded.
    latest_instincts = load_existing_instincts()
    by_domain: dict[str, list[dict[str, Any]]] = {}
    for v in latest_instincts.values():
        if float(v.get("confidence", 0)) >= 0.80:
            dom = str(v.get("domain") or "general")
            by_domain.setdefault(dom, []).append(v)
    evolved_domains: list[str] = state.setdefault("evolved_domains", [])
    new_ready_domains = [d for d, items_d in by_domain.items() if len(items_d) >= 3 and d not in evolved_domains]
    current_synced, _ = sync_evolved_skills()
    if new_ready_domains and len(current_synced) < MAX_EVOLVED_SKILLS:
        try:
            evolve_with_llm_and_cli(quiet=True)
            sync_evolved_skills()
            evolved_domains.extend(new_ready_domains)
            save_daemon_state(state)
        except Exception as e:
            log.warning("Auto-evolve check skipped: %s", e)

    # Never auto-touch bridge reload sentinels from the background observer daemon:
    # killing warm AgySession processes wipes 100k+ token prompt prefix caches mid-conversation.
    return {
        "status": "analyzed",
        "observations_processed": len(pending),
        "instincts_written": written_ids,
        "active_rules_synced": synced_rules,
        "reloads_armed": False,
    }


def evolve_with_llm_and_cli(quiet: bool = False) -> int:
    """Run ECC's native `instinct-cli.py evolve --generate`, plus LLM synthesis when >=2 related instincts exist."""
    subprocess.run(
        [sys.executable, str(INSTINCT_CLI), "evolve", "--generate"],
        check=False,
        stdout=subprocess.DEVNULL if quiet else None,
        stderr=subprocess.DEVNULL if quiet else None,
    )
    synced, skills_changed = sync_evolved_skills()

    existing = load_existing_instincts()
    strong = [v for v in existing.values() if float(v.get("confidence", 0)) >= 0.70]
    existing_skill_names = sorted(
        ({d.name for d in WORKSPACE_SKILLS_DIR.iterdir() if d.is_dir()} if WORKSPACE_SKILLS_DIR.is_dir() else set())
        | {Path(p).parent.name for p in synced}
    )
    if len(synced) < MAX_EVOLVED_SKILLS and len(strong) >= 3:
        sys_p = (
            "You are the ECC Skill Evolution Engine for Antigravity CLI (`agy`).\n"
            "Given high-confidence learned instincts and ALL already existing workspace skill names, if 3 or more instincts "
            "form a coherent reusable workflow/domain NOT already covered by existing workspace or evolved skills, "
            "synthesize ONE Antigravity SKILL.md bundle as JSON: "
            '{"slug":"short-kebab-name","description":"When to activate this skill","markdown":"Full markdown body (without frontmatter)"}. '
            "Do NOT include an `evolved-` prefix in `slug`. "
            "If already covered by any existing skill or only unrelated single-line preferences remain, output `{}`."
        )
        usr_p = json.dumps(
            {
                "already_existing_skills": existing_skill_names,
                "strong_instincts": [
                    {
                        "id": v.get("id"),
                        "trigger": v.get("trigger"),
                        "confidence": v.get("confidence"),
                        "domain": v.get("domain"),
                        "body": v.get("body"),
                    }
                    for v in strong
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
                if slug and md and desc:
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
            print(f"\nSynced {len(synced)} evolved skill(s) into Antigravity workspace (.agents/skills/):")
            for s in synced:
                print(f"  - {s}")
        else:
            print("\nActive instincts synced to .agents/rules/ecc-active-instincts.md (accumulate more related instincts to synthesize multi-step SKILL.md).")
    return 0


def run_daemon_loop() -> None:
    ensure_dirs()
    sync_claude_mem_recent_rule()
    sync_active_instincts_rule()
    log.info("Starting agy-instinct-daemon (poll=%ds, shim=%s, model=%s)", POLL_INTERVAL_SEC, SHIM_URL, SHIM_MODEL)
    while True:
        try:
            res = analyze_observations_batch(force=False)
            if res.get("status") == "analyzed":
                log.info("Instinct batch analyzed: %s", res)
        except Exception as e:
            log.warning("Instinct loop iteration error: %s", e)
        time.sleep(POLL_INTERVAL_SEC)


def main() -> int:
    parser = argparse.ArgumentParser(description="Antigravity ECC Continuous-Learning v2 Daemon & CLI")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("daemon", help="Run background transcript-to-instinct observer loop")
    sub.add_parser("analyze-now", help="Harvest transcripts and run instinct extraction immediately")
    p_sync = sub.add_parser("sync", help="Sync high-confidence instincts & evolved skills to .agents/")
    p_sync.add_argument("--reload", action="store_true", help="Explicitly queue zero-downtime bridge reload")
    sub.add_parser("status", help="Show ECC instinct status")
    sub.add_parser("evolve", help="Cluster and evolve high-confidence instincts into .agents/skills/")

    args, rest = parser.parse_known_args()
    cmd = args.cmd or "status"

    if cmd == "daemon":
        run_daemon_loop()
        return 0
    if cmd == "analyze-now":
        res = analyze_observations_batch(force=True)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0
    if cmd == "sync":
        n_rules, r_ch = sync_active_instincts_rule()
        m_ch = sync_claude_mem_recent_rule()
        skills, s_ch = sync_evolved_skills()
        if getattr(args, "reload", False) and (r_ch or s_ch):
            touch_bridge_reloads()
        print(
            json.dumps(
                {
                    "active_rules_synced": n_rules,
                    "claude_mem_recent_removed": m_ch,
                    "evolved_skills_synced": skills,
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    if cmd == "evolve":
        return evolve_with_llm_and_cli()
    if cmd == "status":
        sync_active_instincts_rule()
        sync_claude_mem_recent_rule()
        return subprocess.call([sys.executable, str(INSTINCT_CLI), "status", *rest])

    return subprocess.call([sys.executable, str(INSTINCT_CLI), cmd, *rest])


if __name__ == "__main__":
    sys.exit(main())
