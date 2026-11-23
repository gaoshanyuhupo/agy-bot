#!/usr/bin/env python3
"""Generic, Desensitized, Idempotent Migration Tool for Per-Bot Isolation.

Safely migrates historical `claude-mem` sessions/observations, bot-owned skills,
sanitized transcript summaries, and legacy global `ecc-instincts` artifacts into
isolated per-bot profiles (`<profiles_dir>/<handle>/` & `bot-<handle>` projects).

Guarantees:
- 100% generic & desensitized (zero hardcoded handles, domains, or host paths).
- `--dry-run` performs ZERO disk or SQLite writes and outputs structured JSON stats.
- Online SQLite Backup API (`src_conn.backup(dst_conn)`) backs up `claude-mem.db`
  safely even in WAL mode before any DB mutation, plus backups of ECC/configs/skills.
- Strictly idempotent: running twice produces 0 additional diffs and NEVER overwrites
  non-empty user-edited `SOUL.md` / `RULES.md` / `MEMORY.md`.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
from typing import Any, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import bot_profiles  # noqa: E402
import memory_guard  # noqa: E402

_SECRET_REDACT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})"),
    re.compile(r"(?:hvs\.[A-Za-z0-9_-]{16,255}|s\.[A-Za-z0-9]{16,255}|alt_[A-Za-z0-9]{20,255})"),
    re.compile(r"(?:sk-[A-Za-z0-9_-]{20,255}|AIza[0-9A-Za-z_-]{30,60})"),
    re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password|authorization)\s*[:=]\s*['\"]?)([A-Za-z0-9_\-/.+=]{10,256})"),
)
_USER_REQ_RE = re.compile(r"<USER_REQUEST>\s*([\s\S]*?)\s*</USER_REQUEST>")


def _redact_text(text: str) -> str:
    out = str(text or "")
    for idx, pat in enumerate(_SECRET_REDACT_PATTERNS):
        if idx == 4:
            out = pat.sub(r"\1[REDACTED]", out)
        else:
            out = pat.sub("[REDACTED]", out)
    return out


def _parse_kv_assignments(raw_items: Sequence[str] | None) -> dict[str, list[str]]:
    """Parse repeatable `HANDLE=item1,item2` CLI arguments into `{handle: [items]}`."""
    mapping: dict[str, list[str]] = {}
    for raw in raw_items or []:
        s = str(raw or "").strip()
        if not s:
            continue
        if "=" not in s:
            raise ValueError(f"Expected HANDLE=VALUE format, got: {raw!r}")
        raw_h, raw_vals = s.split("=", 1)
        h = bot_profiles.normalize_bot_handle(raw_h)
        if not h:
            raise ValueError(f"Invalid bot handle in assignment: {raw_h!r}")
        vals = [v.strip() for v in raw_vals.split(",") if v.strip()]
        if vals:
            bucket = mapping.setdefault(h, [])
            for v in vals:
                if v not in bucket:
                    bucket.append(v)
    return mapping


def _parse_obs_id_specs(raw_items: Sequence[str] | None) -> dict[str, list[int]]:
    """Parse repeatable `HANDLE=176-178,190` into `{handle: [176, 177, 178, 190]}`."""
    kv = _parse_kv_assignments(raw_items)
    out: dict[str, list[int]] = {}
    for h, specs in kv.items():
        ids: list[int] = []
        seen: set[int] = set()
        for spec in specs:
            if "-" in spec:
                parts = spec.split("-", 1)
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    lo, hi = int(parts[0]), int(parts[1])
                    if 0 < lo <= hi and (hi - lo) <= 10000:
                        for num in range(lo, hi + 1):
                            if num not in seen:
                                seen.add(num)
                                ids.append(num)
                        continue
                raise ValueError(f"Invalid observation ID range: {spec!r}")
            if not spec.isdigit() or int(spec) <= 0:
                raise ValueError(f"Invalid observation ID: {spec!r}")
            num = int(spec)
            if num not in seen:
                seen.add(num)
                ids.append(num)
        if ids:
            out[h] = ids
    return out


def backup_sqlite_online(src_db: Path, dst_db: Path) -> Path:
    """Safely back up a SQLite database (including WAL mode) using SQLite Online Backup API."""
    dst_db.parent.mkdir(parents=True, exist_ok=True)
    src_conn = sqlite3.connect(f"file:{src_db}?mode=ro", uri=True, timeout=10.0)
    try:
        dst_conn = sqlite3.connect(str(dst_db), timeout=10.0)
        try:
            src_conn.backup(dst_conn)
            dst_conn.commit()
        finally:
            dst_conn.close()
    finally:
        src_conn.close()
    os.chmod(dst_db, 0o600)
    return dst_db


def _backup_path_if_exists(src: Path, backup_root: Path, rel_name: str) -> str | None:
    if not src.exists():
        return None
    dst = backup_root / rel_name
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, symlinks=False)
    else:
        shutil.copy2(src, dst)
        os.chmod(dst, 0o600)
    return str(dst)


def _extract_sanitized_transcript_summary(
    source_spec: str,
    *,
    brain_root: Path,
    max_bullets: int = 8,
) -> tuple[str, str]:
    """Extract a strictly sanitized factual summary (zero secrets / zero untrusted instructions) from a transcript.

    Returns `(cid_tag, markdown_block)`.
    """
    cand = Path(source_spec).expanduser()
    if cand.is_file():
        tpath = cand
        cid_tag = cand.parent.parent.parent.name if cand.parent.name == "logs" else cand.stem
    else:
        cid_tag = source_spec.strip()
        tpath = None
        if brain_root.is_dir():
            for d in sorted(brain_root.iterdir()):
                if d.is_dir() and (d.name == cid_tag or d.name.startswith(cid_tag)):
                    for fname in ("transcript_full.jsonl", "transcript.jsonl"):
                        fp = d / ".system_generated" / "logs" / fname
                        if fp.is_file():
                            tpath = fp
                            cid_tag = d.name
                            break
                if tpath is not None:
                    break
        if tpath is None:
            raise FileNotFoundError(f"Transcript not found for spec: {source_spec}")

    bullets: list[str] = []
    seen_norm: set[str] = set()
    for line in tpath.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            step = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(step, dict):
            continue
        if step.get("type") != "USER_INPUT":
            continue
        raw = str(step.get("content") or "")
        m = _USER_REQ_RE.search(raw)
        txt = m.group(1).strip() if m else raw.strip()
        if not txt or txt.startswith("/") or "<STATELESS_TASK" in txt:
            continue
        # Anti-poisoning check: drop any untrusted/injection lines
        insp = memory_guard.inspect_text(txt)
        if insp["untrusted"]:
            continue
        clean = " ".join(_redact_text(txt).split())[:220]
        norm_key = clean.lower()
        if clean and norm_key not in seen_norm:
            seen_norm.add(norm_key)
            bullets.append(f"- {clean}")
            if len(bullets) >= max_bullets:
                break

    marker_start = f"<!-- MIGRATED_SUMMARY:{cid_tag} -->"
    marker_end = f"<!-- /MIGRATED_SUMMARY:{cid_tag} -->"
    body = "\n".join(bullets) if bullets else "- (No clean user requests extracted from transcript.)"
    block = f"{marker_start}\n### Historical Session Summary (`{cid_tag[:12]}`)\n{body}\n{marker_end}"
    return cid_tag, block


def _match_session_rows(conn: sqlite3.Connection, specs: Sequence[str]) -> list[tuple[int, str, str, str]]:
    """Return matched `(id, content_session_id, memory_session_id, project)` tuples."""
    if not specs:
        return []
    rows = conn.execute(
        "SELECT id, content_session_id, COALESCE(memory_session_id, ''), project FROM sdk_sessions"
    ).fetchall()
    matched: list[tuple[int, str, str, str]] = []
    seen_ids: set[int] = set()
    for row in rows:
        sid, csid, msid, proj = int(row[0]), str(row[1] or ""), str(row[2] or ""), str(row[3] or "")
        for sp in specs:
            if csid == sp or csid.startswith(sp) or (msid and (msid == sp or msid.startswith(sp))):
                if sid not in seen_ids:
                    seen_ids.add(sid)
                    matched.append((sid, csid, msid, proj))
                break
    return matched


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _table_has_column(conn: sqlite3.Connection, table_name: str, col_name: str) -> bool:
    try:
        cols = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return any(str(c[1]) == col_name for c in cols)
    except sqlite3.Error:
        return False


def run_migration(
    *,
    profiles_dir: Path,
    bus_dir: Path,
    claude_mem_db: Path,
    workspace_dir: Path,
    gemini_config_dir: Path,
    brain_root: Path | None = None,
    assign_sessions: dict[str, list[str]] | None = None,
    assign_observations: dict[str, list[int]] | None = None,
    migrate_skills: dict[str, list[str]] | None = None,
    seed_summaries: dict[str, list[str]] | None = None,
    disable_global_ecc_plugin: bool = False,
    configure_mcp_proxy: bool = False,
    backup_dir: Path | None = None,
    dry_run: bool = False,
    coordinator_handles: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Execute or dry-run per-bot isolation migration with strict idempotency & WAL-safe backups."""
    sess_map = assign_sessions or {}
    obs_map = assign_observations or {}
    skills_map = migrate_skills or {}
    summary_map = seed_summaries or {}
    coord_set = {
        h
        for h in (bot_profiles.normalize_bot_handle(x) for x in (coordinator_handles or []))
        if h
    }
    eff_brain = brain_root or (gemini_config_dir.parent / "antigravity-cli" / "brain")

    all_handles = sorted(
        set(sess_map.keys())
        | set(obs_map.keys())
        | set(skills_map.keys())
        | set(summary_map.keys())
        | coord_set
    )

    ts_tag = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    eff_backup_dir = backup_dir or (profiles_dir / ".migration_backups" / ts_tag)

    report: dict[str, Any] = {
        "ok": True,
        "dry_run": bool(dry_run),
        "handles": all_handles,
        "backup_dir": None if dry_run else str(eff_backup_dir),
        "backups": [],
        "profiles_initialized": [],
        "db_migration": {
            "sessions_updated": 0,
            "observations_updated": 0,
            "summaries_updated": 0,
            "user_prompts_verified": 0,
            "manual_observations_updated": 0,
            "by_handle": {},
        },
        "skills_migrated": {},
        "summaries_seeded": {},
        "global_ecc_cleaned": [],
        "mcp_proxy_configured": False,
        "changes_applied": 0,
    }

    # 1. Pre-flight backup (skipped strictly in dry-run)
    if not dry_run:
        eff_backup_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(eff_backup_dir, 0o700)
        if claude_mem_db.is_file():
            bak_db = backup_sqlite_online(claude_mem_db, eff_backup_dir / "claude-mem.db")
            report["backups"].append(str(bak_db))
        for src_p, rel_n in (
            (gemini_config_dir / "mcp_config.json", "gemini/mcp_config.json"),
            (gemini_config_dir / "hooks.json", "gemini/hooks.json"),
            (gemini_config_dir / "config.json", "gemini/config.json"),
            (gemini_config_dir / "plugins" / "ecc-instincts", "gemini/plugins/ecc-instincts"),
            (workspace_dir / ".agents" / "rules" / "ecc-active-instincts.md", "workspace/ecc-active-instincts.md"),
        ):
            backed = _backup_path_if_exists(src_p, eff_backup_dir, rel_n)
            if backed:
                report["backups"].append(backed)

    # 2. Ensure target bot profiles exist (never overwriting existing non-empty docs)
    for h in all_handles:
        role = "coordinator" if h in coord_set else "worker"
        target_pjson = profiles_dir / h / "profile.json"
        if not target_pjson.exists():
            report["profiles_initialized"].append(h)
            if not dry_run:
                bot_profiles.ensure_bot_profile(h, role=role, profiles_dir=profiles_dir)
                report["changes_applied"] += 1

    # 3. Migrate claude-mem.db sessions & observations
    if claude_mem_db.is_file() and (sess_map or obs_map):
        uri_mode = "ro" if dry_run else "rw"
        conn = sqlite3.connect(f"file:{claude_mem_db}?mode={uri_mode}", uri=True, timeout=10.0)
        try:
            has_obs = _table_exists(conn, "observations")
            has_sum = _table_exists(conn, "session_summaries")
            has_up = _table_exists(conn, "user_prompts")
            up_has_project = has_up and _table_has_column(conn, "user_prompts", "project")

            if not dry_run:
                conn.execute("BEGIN IMMEDIATE")

            for h, specs in sorted(sess_map.items()):
                target_proj = f"bot-{h}"
                h_stats = report["db_migration"]["by_handle"].setdefault(
                    h,
                    {
                        "target_project": target_proj,
                        "sessions_matched": [],
                        "sessions_updated": 0,
                        "observations_updated": 0,
                        "summaries_updated": 0,
                        "user_prompts_verified": 0,
                        "manual_observations_updated": 0,
                    },
                )
                matched_rows = _match_session_rows(conn, specs)
                for sid, csid, msid, cur_proj in matched_rows:
                    h_stats["sessions_matched"].append(csid)
                    if cur_proj != target_proj:
                        h_stats["sessions_updated"] += 1
                        report["db_migration"]["sessions_updated"] += 1
                        if not dry_run:
                            conn.execute(
                                "UPDATE sdk_sessions SET project = ? WHERE id = ?",
                                (target_proj, sid),
                            )
                            report["changes_applied"] += 1

                    # Register CID owner atomically
                    if not dry_run:
                        bot_profiles.register_cid_owner(csid, h, bus_dir=bus_dir)

                    if msid and has_obs:
                        obs_cnt = int(
                            conn.execute(
                                "SELECT COUNT(*) FROM observations WHERE memory_session_id = ? AND project != ?",
                                (msid, target_proj),
                            ).fetchone()[0]
                        )
                        if obs_cnt > 0:
                            h_stats["observations_updated"] += obs_cnt
                            report["db_migration"]["observations_updated"] += obs_cnt
                            if not dry_run:
                                conn.execute(
                                    "UPDATE observations SET project = ? WHERE memory_session_id = ? AND project != ?",
                                    (target_proj, msid, target_proj),
                                )
                                report["changes_applied"] += obs_cnt

                    if msid and has_sum:
                        sum_cnt = int(
                            conn.execute(
                                "SELECT COUNT(*) FROM session_summaries WHERE memory_session_id = ? AND project != ?",
                                (msid, target_proj),
                            ).fetchone()[0]
                        )
                        if sum_cnt > 0:
                            h_stats["summaries_updated"] += sum_cnt
                            report["db_migration"]["summaries_updated"] += sum_cnt
                            if not dry_run:
                                conn.execute(
                                    "UPDATE session_summaries SET project = ? WHERE memory_session_id = ? AND project != ?",
                                    (target_proj, msid, target_proj),
                                )
                                report["changes_applied"] += sum_cnt

                    if has_up:
                        up_cnt = int(
                            conn.execute(
                                "SELECT COUNT(*) FROM user_prompts WHERE content_session_id = ? OR session_db_id = ?",
                                (csid, sid),
                            ).fetchone()[0]
                        )
                        h_stats["user_prompts_verified"] += up_cnt
                        report["db_migration"]["user_prompts_verified"] += up_cnt
                        if up_has_project and not dry_run:
                            conn.execute(
                                "UPDATE user_prompts SET project = ? WHERE (content_session_id = ? OR session_db_id = ?) AND project != ?",
                                (target_proj, csid, sid, target_proj),
                            )

            for h, obs_ids in sorted(obs_map.items()):
                if not has_obs or not obs_ids:
                    continue
                target_proj = f"bot-{h}"
                h_stats = report["db_migration"]["by_handle"].setdefault(
                    h,
                    {
                        "target_project": target_proj,
                        "sessions_matched": [],
                        "sessions_updated": 0,
                        "observations_updated": 0,
                        "summaries_updated": 0,
                        "user_prompts_verified": 0,
                        "manual_observations_updated": 0,
                    },
                )
                placeholders = ",".join("?" for _ in obs_ids)
                cnt = int(
                    conn.execute(
                        f"SELECT COUNT(*) FROM observations WHERE id IN ({placeholders}) AND project != ?",
                        [*obs_ids, target_proj],
                    ).fetchone()[0]
                )
                if cnt > 0:
                    h_stats["manual_observations_updated"] += cnt
                    report["db_migration"]["manual_observations_updated"] += cnt
                    if not dry_run:
                        conn.execute(
                            f"UPDATE observations SET project = ? WHERE id IN ({placeholders}) AND project != ?",
                            [target_proj, *obs_ids, target_proj],
                        )
                        report["changes_applied"] += cnt

            if not dry_run:
                conn.commit()
        except Exception:
            if not dry_run:
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
            raise
        finally:
            conn.close()

    # 4. Migrate dedicated skills (including scripts/ subdirs) into `bots/<handle>/skills/<slug>/`
    src_skills_root = workspace_dir / ".agents" / "skills"
    for h, slugs in sorted(skills_map.items()):
        migrated_for_h: list[str] = []
        for slug in slugs:
            if not bot_profiles.is_valid_skill_slug(slug):
                raise ValueError(f"Invalid skill slug to migrate: {slug!r}")
            src_sk = src_skills_root / slug
            dst_sk = profiles_dir / h / "skills" / slug
            if not src_sk.is_dir():
                if dst_sk.is_dir():
                    continue
                continue
            # Check idempotency: skip if destination already matches
            needs_copy = not dst_sk.is_dir()
            if not needs_copy:
                src_md = (src_sk / "SKILL.md").read_bytes() if (src_sk / "SKILL.md").is_file() else b""
                dst_md = (dst_sk / "SKILL.md").read_bytes() if (dst_sk / "SKILL.md").is_file() else b""
                needs_copy = src_md != dst_md
            if needs_copy:
                migrated_for_h.append(slug)
                if not dry_run:
                    _backup_path_if_exists(src_sk, eff_backup_dir, f"skills/{slug}")
                    dst_sk.parent.mkdir(parents=True, exist_ok=True)
                    os.chmod(dst_sk.parent, 0o700)
                    if dst_sk.exists():
                        shutil.rmtree(dst_sk)
                    shutil.copytree(src_sk, dst_sk, symlinks=False)
                    os.chmod(dst_sk, 0o700)
                    for root_d, _dirs, files in os.walk(dst_sk):
                        os.chmod(root_d, 0o700)
                        for fn in files:
                            fp = Path(root_d) / fn
                            if fp.suffix in (".py", ".sh") and (fp.stat().st_mode & 0o100):
                                os.chmod(fp, 0o700)
                            else:
                                os.chmod(fp, 0o600)
                    report["changes_applied"] += 1
        if migrated_for_h:
            report["skills_migrated"][h] = migrated_for_h

    # 5. Seed sanitized factual summary from transcript into `MEMORY.md` (idempotent, never overwrites existing text)
    for h, specs in sorted(summary_map.items()):
        seeded_list: list[str] = []
        role = "coordinator" if h in coord_set else "worker"
        for spec in specs:
            cid_tag, block = _extract_sanitized_transcript_summary(spec, brain_root=eff_brain)
            marker = f"<!-- MIGRATED_SUMMARY:{cid_tag} -->"
            mem_path = profiles_dir / h / "MEMORY.md"
            existing_txt = mem_path.read_text(encoding="utf-8", errors="replace") if mem_path.is_file() else ""
            if marker in existing_txt:
                continue
            seeded_list.append(cid_tag)
            if not dry_run:
                bot_profiles.ensure_bot_profile(h, role=role, profiles_dir=profiles_dir)
                cur_rev = bot_profiles.get_profile_rev(h, role=role, profiles_dir=profiles_dir)
                combined = (existing_txt.rstrip() + "\n\n" + block + "\n") if existing_txt.strip() else (block + "\n")
                if len(combined.encode("utf-8")) > bot_profiles.MAX_DOC_BYTES:
                    combined = combined.encode("utf-8")[: bot_profiles.MAX_DOC_BYTES - 32].decode(
                        "utf-8", errors="ignore"
                    ) + "\n"
                sc, _res = bot_profiles.update_bot_profile(
                    h,
                    expected_rev=cur_rev,
                    doc="MEMORY.md",
                    content=combined,
                    updated_by="migrate_bot_isolation",
                    role=role,
                    profiles_dir=profiles_dir,
                )
                if sc == 200:
                    report["changes_applied"] += 1
        if seeded_list:
            report["summaries_seeded"][h] = seeded_list

    # 6. Clean legacy global `ecc-instincts` leakage (backed up in Step 1)
    if disable_global_ecc_plugin:
        ecc_plugin = gemini_config_dir / "plugins" / "ecc-instincts"
        shared_rule = workspace_dir / ".agents" / "rules" / "ecc-active-instincts.md"
        for target in (ecc_plugin, shared_rule):
            if target.exists():
                report["global_ecc_cleaned"].append(str(target))
                if not dry_run:
                    if target.is_dir():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                    report["changes_applied"] += 1

    # 7. Optional atomic MCP proxy configuration
    if configure_mcp_proxy:
        mcp_cfg = gemini_config_dir / "mcp_config.json"
        if not dry_run:
            changed = bot_profiles.ensure_claude_mem_proxy_configured(
                mcp_config_path=mcp_cfg,
                proxy_script=BRIDGE_DIR / "claude_mem_mcp_proxy.py",
                python_exe=sys.executable,
            )
            report["mcp_proxy_configured"] = bool(changed)
            if changed:
                report["changes_applied"] += 1
        else:
            report["mcp_proxy_configured"] = True

    return report


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Idempotent per-bot memory/skills/profile isolation migration tool."
    )
    p.add_argument(
        "--profiles-dir",
        type=Path,
        default=bot_profiles.resolve_profiles_dir(),
        help="Per-bot profiles directory (default: $AGY_BOT_PROFILES_DIR or ~/.config/agy-tg-bridge/bots)",
    )
    p.add_argument(
        "--bus-dir",
        type=Path,
        default=bot_profiles.resolve_bus_dir(),
        help="Bot bus directory (default: $AGY_BOT_BUS_DIR or ~/.config/agy-tg-bridge/bus)",
    )
    p.add_argument(
        "--claude-mem-db",
        type=Path,
        default=bot_profiles.resolve_claude_mem_db(),
        help="Path to claude-mem SQLite DB (default: ~/.claude-mem/claude-mem.db)",
    )
    p.add_argument(
        "--workspace-dir",
        type=Path,
        default=Path(os.environ.get("AGY_WORKSPACE_DIR", str(Path.home() / "agy-workspace"))).expanduser(),
        help="Workspace directory containing shared .agents/skills",
    )
    p.add_argument(
        "--gemini-config-dir",
        type=Path,
        default=Path.home() / ".gemini" / "config",
        help="Gemini CLI config directory (default: ~/.gemini/config)",
    )
    p.add_argument(
        "--brain-root",
        type=Path,
        default=None,
        help="Antigravity brain root directory for transcript summary extraction",
    )
    p.add_argument(
        "--assign-sessions",
        action="append",
        default=[],
        help="Assign historical session CIDs/prefixes to a bot: HANDLE=cid1,cid2",
    )
    p.add_argument(
        "--assign-observations",
        action="append",
        default=[],
        help="Assign historical observation IDs/ranges to a bot: HANDLE=176-178,200",
    )
    p.add_argument(
        "--migrate-skills",
        action="append",
        default=[],
        help="Migrate workspace skills into a bot's own skills/: HANDLE=slug1,slug2",
    )
    p.add_argument(
        "--seed-summary-from-transcript",
        action="append",
        default=[],
        help="Seed sanitized factual summary from transcript CID/path into MEMORY.md: HANDLE=cid_or_path",
    )
    p.add_argument(
        "--coordinator",
        action="append",
        default=[],
        help="Mark a handle as coordinator role when initializing its profile",
    )
    p.add_argument(
        "--disable-global-ecc-plugin",
        action="store_true",
        help="Back up and remove legacy global ecc-instincts plugin & shared active rule",
    )
    p.add_argument(
        "--configure-mcp-proxy",
        action="store_true",
        help="Atomically wrap claude-mem in mcp_config.json with claude_mem_mcp_proxy.py",
    )
    p.add_argument(
        "--backup-dir",
        type=Path,
        default=None,
        help="Explicit backup directory path for pre-migration snapshots",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview migration plan with strictly zero disk/DB writes",
    )
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    report = run_migration(
        profiles_dir=args.profiles_dir.expanduser(),
        bus_dir=args.bus_dir.expanduser(),
        claude_mem_db=args.claude_mem_db.expanduser(),
        workspace_dir=args.workspace_dir.expanduser(),
        gemini_config_dir=args.gemini_config_dir.expanduser(),
        brain_root=args.brain_root.expanduser() if args.brain_root else None,
        assign_sessions=_parse_kv_assignments(args.assign_sessions),
        assign_observations=_parse_obs_id_specs(args.assign_observations),
        migrate_skills=_parse_kv_assignments(args.migrate_skills),
        seed_summaries=_parse_kv_assignments(args.seed_summary_from_transcript),
        disable_global_ecc_plugin=bool(args.disable_global_ecc_plugin),
        configure_mcp_proxy=bool(args.configure_mcp_proxy),
        backup_dir=args.backup_dir.expanduser() if args.backup_dir else None,
        dry_run=bool(args.dry_run),
        coordinator_handles=args.coordinator,
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
