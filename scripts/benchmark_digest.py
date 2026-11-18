#!/usr/bin/env python3
"""Weekly Upstream Benchmark Digest (`scripts/benchmark_digest.py`).

Pure Python 3.11+ standard-library tool that monitors configurable benchmark
repositories (injected via `--repos-file` or `--repo` / `--repos`), extracts
non-draft releases, recently merged PRs, and default-branch commits, performs
incremental deduplication with `0o600` atomic state persistence, neutralizes
prompt-injection payloads, and outputs `[SILENT]` when nothing changed.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from . import repo_watch  # type: ignore[no-redef]
except ImportError:
    _SCRIPTS_DIR = Path(__file__).resolve().parent
    if str(_SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS_DIR))
    import repo_watch  # type: ignore[no-redef]

DEFAULT_SINCE_HOURS = 168
DEFAULT_MAX_ITEMS = 10
MAX_SEEN_RELEASES = 100
MAX_SEEN_PRS = 200
MAX_SEEN_COMMITS = 200

_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_CTRL_SINGLELINE_RE = re.compile(r"[\x00-\x1f\x7f]+")
_CTRL_MULTILINE_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FORGED_TAG_RE = re.compile(
    r"\[(?=(?:ACB_|REPO_WATCH_|BENCHMARK_|UNTRUSTED_|SILENT\b|NO_HANDOFF_))",
    re.IGNORECASE,
)


def default_state_file() -> Path:
    """Compute default persistent state path under the user's cache directory."""
    return Path.home() / ".gemini" / "antigravity-cli" / "cache" / "benchmark_digest_state.json"


def sanitize_untrusted_text(text: Any, *, limit: int = 240, multiline: bool = False) -> str:
    """Strip control/zero-width chars, neutralize forged protocol tags, and truncate."""
    if text is None:
        return ""
    s = str(text)
    s = _ZERO_WIDTH_RE.sub("", s)
    if multiline:
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        s = _CTRL_MULTILINE_RE.sub(" ", s)
    else:
        s = _CTRL_SINGLELINE_RE.sub(" ", s)
        s = re.sub(r"\s+", " ", s)
    s = _FORGED_TAG_RE.sub("(", s)
    return repo_watch._truncate_text(s, limit)


def _parse_iso_dt(raw: Any) -> Optional[datetime.datetime]:
    if not raw or not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _within_cutoff(ts_raw: Any, cutoff: datetime.datetime) -> bool:
    dt = _parse_iso_dt(ts_raw)
    if dt is None:
        return False
    return dt >= cutoff


def load_repo_targets(
    *,
    repos_file: Optional[Path] = None,
    cli_repos: Sequence[str] = (),
    cli_repos_csv: Sequence[str] = (),
) -> List[Dict[str, str]]:
    """Load, validate, and deduplicate repository targets preserving order."""
    entries: List[Dict[str, str]] = []

    if repos_file is not None:
        if not repos_file.is_file():
            raise ValueError(f"Repos config file not found: {repos_file}")
        try:
            raw_data = json.loads(repos_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Failed to parse repos config {repos_file}: {exc}") from exc

        if isinstance(raw_data, dict):
            if "repos" not in raw_data or not isinstance(raw_data["repos"], list):
                raise ValueError(f"Repos config object in {repos_file} must contain a 'repos' list")
            raw_list = raw_data["repos"]
        elif isinstance(raw_data, list):
            raw_list = raw_data
        else:
            raise ValueError(f"Repos config in {repos_file} must be a JSON list or {{\"repos\": [...]}}")

        for idx, item in enumerate(raw_list):
            if isinstance(item, str):
                repo_name = repo_watch.validate_repo(item)
                entries.append({"repo": repo_name, "category": "", "note": ""})
            elif isinstance(item, dict):
                raw_repo = item.get("repo")
                if not isinstance(raw_repo, str):
                    raise ValueError(f"Entry #{idx} in {repos_file} is missing string 'repo' field")
                repo_name = repo_watch.validate_repo(raw_repo)
                entries.append(
                    {
                        "repo": repo_name,
                        "category": sanitize_untrusted_text(item.get("category") or "", limit=60),
                        "note": sanitize_untrusted_text(item.get("note") or "", limit=120),
                    }
                )
            else:
                raise ValueError(f"Invalid entry #{idx} in {repos_file}: expected string or object")

    for raw in cli_repos:
        if raw and raw.strip():
            entries.append({"repo": repo_watch.validate_repo(raw), "category": "", "note": ""})

    for csv_val in cli_repos_csv:
        for part in (csv_val or "").split(","):
            if part.strip():
                entries.append({"repo": repo_watch.validate_repo(part), "category": "", "note": ""})

    deduped: List[Dict[str, str]] = []
    seen: set[str] = set()
    for ent in entries:
        key = ent["repo"].lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ent)

    if not deduped:
        raise ValueError("No target repositories configured (use --repos-file, --repo, or --repos)")
    return deduped


def collect_repo_snapshot(
    repo: str,
    *,
    since_cutoff: datetime.datetime,
    max_items: int = DEFAULT_MAX_ITEMS,
) -> Dict[str, Any]:
    """Collect metadata, non-draft releases, default-branch commits, and merged PRs for one repo."""
    per_page = max(1, min(int(max_items), 100))
    fetch_limit = max(per_page, min(per_page * 3, 100))

    repo_data = repo_watch.github_get_json(f"repos/{repo}")
    if not isinstance(repo_data, dict):
        raise RuntimeError(f"Unexpected repo metadata payload for {repo}")

    default_branch = str(repo_data.get("default_branch") or "main").strip() or "main"

    raw_releases = repo_watch._github_get_optional_json(
        f"repos/{repo}/releases?per_page={min(fetch_limit, 30)}",
        [],
    )
    releases = [
        r
        for r in (raw_releases if isinstance(raw_releases, list) else [])
        if isinstance(r, dict) and not bool(r.get("draft"))
    ]

    since_iso = since_cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    branch_q = urllib.parse.quote(default_branch, safe="")
    raw_commits = repo_watch._github_get_optional_json(
        f"repos/{repo}/commits?sha={branch_q}&since={since_iso}&per_page={fetch_limit}",
        [],
    )
    commits = [c for c in (raw_commits if isinstance(raw_commits, list) else []) if isinstance(c, dict)]

    raw_pulls = repo_watch._github_get_optional_json(
        f"repos/{repo}/pulls?state=closed&sort=updated&direction=desc&per_page={fetch_limit}",
        [],
    )
    merged_prs = [
        p
        for p in (raw_pulls if isinstance(raw_pulls, list) else [])
        if isinstance(p, dict) and p.get("merged_at")
    ]

    return {
        "repo": repo_data,
        "default_branch": default_branch,
        "releases": releases,
        "commits": commits,
        "merged_prs": merged_prs,
    }


def _summarize_release(rel: Dict[str, Any]) -> Dict[str, Any]:
    pub = str(rel.get("published_at") or rel.get("created_at") or "")
    tag = sanitize_untrusted_text(rel.get("tag_name") or "", limit=80)
    name = sanitize_untrusted_text(rel.get("name") or tag or "", limit=140)
    return {
        "id": rel.get("id"),
        "tag_name": tag,
        "name": name,
        "prerelease": bool(rel.get("prerelease")),
        "published_at": pub,
        "html_url": sanitize_untrusted_text(rel.get("html_url") or "", limit=240),
        "summary": sanitize_untrusted_text(rel.get("body") or "", limit=260),
    }


def _summarize_merged_pr(pr: Dict[str, Any]) -> Dict[str, Any]:
    author = ((pr.get("user") or {}).get("login")) or "unknown"
    return {
        "number": pr.get("number"),
        "title": sanitize_untrusted_text(pr.get("title") or "", limit=180),
        "author": sanitize_untrusted_text(author, limit=80),
        "merged_at": str(pr.get("merged_at") or ""),
        "html_url": sanitize_untrusted_text(pr.get("html_url") or "", limit=240),
    }


def _summarize_commit(cm: Dict[str, Any]) -> Dict[str, Any]:
    sha = str(cm.get("sha") or "")
    commit_obj = cm.get("commit") or {}
    msg_line = str(commit_obj.get("message") or "").splitlines()[0] if commit_obj.get("message") else ""
    author = (
        ((cm.get("author") or {}).get("login"))
        or ((commit_obj.get("author") or {}).get("name"))
        or ((commit_obj.get("committer") or {}).get("name"))
        or "unknown"
    )
    date_str = str(
        ((commit_obj.get("committer") or {}).get("date"))
        or ((commit_obj.get("author") or {}).get("date"))
        or ""
    )
    return {
        "sha": sha,
        "short_sha": sha[:8],
        "author": sanitize_untrusted_text(author, limit=80),
        "date": date_str,
        "message": sanitize_untrusted_text(msg_line, limit=180),
        "html_url": sanitize_untrusted_text(cm.get("html_url") or "", limit=240),
    }


def compute_repo_delta_and_state(
    target: Dict[str, str],
    snapshot: Dict[str, Any],
    prev_repo_state: Optional[Dict[str, Any]],
    *,
    since_cutoff: datetime.datetime,
    max_items: int = DEFAULT_MAX_ITEMS,
    checked_at: str = "",
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Compute incremental delta and updated bounded per-repo state."""
    repo = target["repo"]
    repo_data = snapshot["repo"]
    prev = prev_repo_state or {}

    prev_rel_ids = {str(k): str(v) for k, v in (prev.get("seen_release_ids") or {}).items()}
    prev_pr_nums = {str(k): str(v) for k, v in (prev.get("seen_merged_prs") or {}).items()}
    prev_commits = [str(s) for s in (prev.get("seen_commit_shas") or []) if s]
    prev_commit_set = set(prev_commits)

    new_releases: List[Dict[str, Any]] = []
    curr_rel_ids: Dict[str, str] = {}
    for rel in snapshot["releases"]:
        rid = rel.get("id")
        if rid is None:
            continue
        rid_str = str(rid)
        pub = str(rel.get("published_at") or rel.get("created_at") or "")
        curr_rel_ids[rid_str] = pub
        if rid_str not in prev_rel_ids and _within_cutoff(pub, since_cutoff):
            if len(new_releases) < max_items:
                new_releases.append(_summarize_release(rel))

    new_merged_prs: List[Dict[str, Any]] = []
    curr_pr_nums: Dict[str, str] = {}
    for pr in snapshot["merged_prs"]:
        num = pr.get("number")
        if num is None:
            continue
        num_str = str(num)
        merged_at = str(pr.get("merged_at") or "")
        curr_pr_nums[num_str] = merged_at
        if num_str not in prev_pr_nums and _within_cutoff(merged_at, since_cutoff):
            if len(new_merged_prs) < max_items:
                new_merged_prs.append(_summarize_merged_pr(pr))

    new_commits: List[Dict[str, Any]] = []
    curr_commit_shas: List[str] = []
    for cm in snapshot["commits"]:
        sha = str(cm.get("sha") or "").strip()
        if not sha:
            continue
        curr_commit_shas.append(sha)
        summary = _summarize_commit(cm)
        if sha not in prev_commit_set and _within_cutoff(summary["date"], since_cutoff):
            if len(new_commits) < max_items:
                new_commits.append(summary)

    merged_rel_ids = dict(prev_rel_ids)
    merged_rel_ids.update(curr_rel_ids)
    if len(merged_rel_ids) > MAX_SEEN_RELEASES:
        ordered_rels = sorted(merged_rel_ids.items(), key=lambda kv: kv[1], reverse=True)
        merged_rel_ids = dict(ordered_rels[:MAX_SEEN_RELEASES])

    merged_pr_nums = dict(prev_pr_nums)
    merged_pr_nums.update(curr_pr_nums)
    if len(merged_pr_nums) > MAX_SEEN_PRS:
        ordered_prs = sorted(merged_pr_nums.items(), key=lambda kv: kv[1], reverse=True)
        merged_pr_nums = dict(ordered_prs[:MAX_SEEN_PRS])

    merged_commits: List[str] = []
    seen_c: set[str] = set()
    for sha in curr_commit_shas + prev_commits:
        if sha not in seen_c:
            seen_c.add(sha)
            merged_commits.append(sha)
        if len(merged_commits) >= MAX_SEEN_COMMITS:
            break

    next_repo_state = {
        "default_branch": snapshot["default_branch"],
        "pushed_at": str(repo_data.get("pushed_at") or ""),
        "stars": int(repo_data.get("stargazers_count") or 0),
        "last_checked_at": checked_at or repo_watch._utc_now_iso(),
        "seen_release_ids": merged_rel_ids,
        "seen_merged_prs": merged_pr_nums,
        "seen_commit_shas": merged_commits,
    }

    delta = {
        "repo": repo,
        "category": target.get("category") or "",
        "note": target.get("note") or "",
        "default_branch": sanitize_untrusted_text(snapshot["default_branch"], limit=80),
        "stars": int(repo_data.get("stargazers_count") or 0),
        "pushed_at": str(repo_data.get("pushed_at") or ""),
        "releases": new_releases,
        "merged_prs": new_merged_prs,
        "commits": new_commits,
        "has_changes": bool(new_releases or new_merged_prs or new_commits),
    }
    return delta, next_repo_state


def format_digest_text(
    deltas: Sequence[Dict[str, Any]],
    errors: Dict[str, str],
    *,
    total_repos: int,
    since_hours: int,
) -> str:
    """Format multi-repo upstream benchmark digest or `[SILENT]` when empty."""
    active_deltas = [d for d in deltas if d.get("has_changes")]
    if not active_deltas and not errors:
        return "[SILENT]"

    lines = [
        (
            f"[BENCHMARK_DIGEST_DELTA repos={total_repos} active={len(active_deltas)} "
            f"errors={len(errors)} since_hours={since_hours}]"
        ),
        repo_watch.UNTRUSTED_WARNING,
    ]

    for d in active_deltas:
        cat_part = f" [{d['category']}]" if d.get("category") else ""
        note_part = f" — {d['note']}" if d.get("note") else ""
        lines.append(
            f"\n## {d['repo']}{cat_part} (branch={d['default_branch']}, stars={d['stars']}){note_part}"
        )
        if d.get("releases"):
            lines.append("### Releases")
            for rel in d["releases"]:
                pre_tag = " [prerelease]" if rel.get("prerelease") else ""
                lines.append(
                    f"- {rel['tag_name']}{pre_tag} ({rel['name']}) @ {rel['published_at']} | {rel['html_url']}"
                )
                if rel.get("summary"):
                    lines.append(f"  摘要: {rel['summary']}")
        if d.get("merged_prs"):
            lines.append("### Merged PRs")
            for pr in d["merged_prs"]:
                lines.append(
                    f"- PR #{pr['number']} {pr['title']} | by {pr['author']} @ {pr['merged_at']} | {pr['html_url']}"
                )
        if d.get("commits"):
            lines.append("### Recent Commits")
            for cm in d["commits"]:
                lines.append(f"- {cm['short_sha']} ({cm['author']} @ {cm['date']}): {cm['message']}")

    if errors:
        lines.append("\n## Errors")
        for repo, msg in errors.items():
            lines.append(f"- {repo}: {msg}")

    return "\n".join(lines)


def run_digest(
    targets: Sequence[Dict[str, str]],
    *,
    state_file: Path,
    since_hours: int = DEFAULT_SINCE_HOURS,
    max_items: int = DEFAULT_MAX_ITEMS,
    seed: bool = False,
    verbose_seed: bool = False,
    first_run_silent: bool = False,
    output_format: str = "text",
    now: Optional[datetime.datetime] = None,
) -> Tuple[int, str]:
    """Execute one upstream benchmark digest cycle across all target repos."""
    if not targets:
        raise ValueError("Target repository list must not be empty")
    if since_hours <= 0:
        raise ValueError("--since-hours must be > 0")
    if max_items < 1:
        raise ValueError("--max-items must be >= 1")

    now_utc = (now or datetime.datetime.now(datetime.timezone.utc)).astimezone(datetime.timezone.utc)
    checked_at = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    since_cutoff = now_utc - datetime.timedelta(hours=since_hours)

    prev_state = repo_watch._load_state(state_file)
    prev_repos = (prev_state or {}).get("repos") or {}
    is_cold_start = prev_state is None

    next_repos: Dict[str, Any] = dict(prev_repos) if isinstance(prev_repos, dict) else {}
    deltas: List[Dict[str, Any]] = []
    errors: Dict[str, str] = {}
    succeeded = 0

    for target in targets:
        repo = target["repo"]
        prev_repo_state = prev_repos.get(repo) if isinstance(prev_repos, dict) else None
        try:
            snapshot = collect_repo_snapshot(repo, since_cutoff=since_cutoff, max_items=max_items)
            delta, next_repo_state = compute_repo_delta_and_state(
                target,
                snapshot,
                prev_repo_state if isinstance(prev_repo_state, dict) else None,
                since_cutoff=since_cutoff,
                max_items=max_items,
                checked_at=checked_at,
            )
            next_repos[repo] = next_repo_state
            deltas.append(delta)
            succeeded += 1
        except Exception as exc:
            errors[repo] = sanitize_untrusted_text(str(exc), limit=240)

    if succeeded == 0:
        if output_format == "json":
            return 1, json.dumps(
                {
                    "ok": False,
                    "silent": False,
                    "total_repos": len(targets),
                    "succeeded": 0,
                    "errors": errors,
                },
                ensure_ascii=False,
                indent=2,
            )
        err_lines = ["[BENCHMARK_DIGEST_ERROR] All target repositories failed:"]
        for r, m in errors.items():
            err_lines.append(f"- {r}: {m}")
        return 1, "\n".join(err_lines)

    next_state = {
        "schema_version": 1,
        "last_checked_at": checked_at,
        "since_hours": since_hours,
        "repos": next_repos,
    }
    repo_watch._save_state_atomic(state_file, next_state)

    baseline_silent = seed or (first_run_silent and is_cold_start)
    if baseline_silent:
        if output_format == "json":
            is_silent = not errors and not (seed and verbose_seed)
            return 0, json.dumps(
                {
                    "ok": True,
                    "seeded": True,
                    "first_run_silent": bool(first_run_silent and is_cold_start),
                    "silent": is_silent,
                    "total_repos": len(targets),
                    "succeeded": succeeded,
                    "errors": errors,
                    "state_file": str(state_file),
                },
                ensure_ascii=False,
                indent=2,
            )
        if errors:
            lines = [
                f"[BENCHMARK_DIGEST_SEED repos={len(targets)} succeeded={succeeded} errors={len(errors)}]",
                *[f"- ERROR {r}: {m}" for r, m in errors.items()],
            ]
            return 0, "\n".join(lines)
        if seed and verbose_seed:
            return 0, (
                f"[BENCHMARK_DIGEST_SEED repos={len(targets)} succeeded={succeeded}] "
                f"state_file={state_file}"
            )
        return 0, "[SILENT]"

    active_deltas = [d for d in deltas if d.get("has_changes")]
    if output_format == "json":
        is_silent = not active_deltas and not errors
        payload: Dict[str, Any] = {
            "ok": True,
            "silent": is_silent,
            "last_checked_at": checked_at,
            "since_hours": since_hours,
            "total_repos": len(targets),
            "succeeded": succeeded,
            "deltas": active_deltas,
            "errors": errors,
        }
        if not is_silent:
            payload["untrusted_warning"] = repo_watch.UNTRUSTED_WARNING
        return 0, json.dumps(payload, ensure_ascii=False, indent=2)

    return 0, format_digest_text(
        deltas,
        errors,
        total_repos=len(targets),
        since_hours=since_hours,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Weekly Upstream Benchmark Digest")
    parser.add_argument("--repos-file", default="", help="JSON file with target repositories list")
    parser.add_argument("--repo", action="append", default=[], help="Target <owner/name> repository (repeatable)")
    parser.add_argument("--repos", action="append", default=[], help="Comma-separated <owner/name> repositories")
    parser.add_argument("--state-file", default="", help="Path to persistent digest state JSON file")
    parser.add_argument(
        "--since-hours",
        type=int,
        default=DEFAULT_SINCE_HOURS,
        help=f"Lookback window in hours (default: {DEFAULT_SINCE_HOURS})",
    )
    parser.add_argument(
        "--max-items",
        type=int,
        default=DEFAULT_MAX_ITEMS,
        help=f"Max items per category per repo (default: {DEFAULT_MAX_ITEMS})",
    )
    parser.add_argument("--seed", action="store_true", help="Record baseline state without emitting digest")
    parser.add_argument("--verbose-seed", action="store_true", help="Print baseline summary when --seed is set")
    parser.add_argument(
        "--first-run-silent",
        action="store_true",
        help="When state file does not exist, record baseline and output [SILENT]",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format (default: text)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        repos_file = Path(args.repos_file).expanduser() if args.repos_file else None
        targets = load_repo_targets(
            repos_file=repos_file,
            cli_repos=args.repo,
            cli_repos_csv=args.repos,
        )
        state_path = Path(args.state_file).expanduser() if args.state_file else default_state_file()
        rc, output = run_digest(
            targets,
            state_file=state_path,
            since_hours=args.since_hours,
            max_items=args.max_items,
            seed=bool(args.seed),
            verbose_seed=bool(args.verbose_seed),
            first_run_silent=bool(args.first_run_silent),
            output_format=args.format,
        )
        print(output)
        return rc
    except Exception as exc:
        print(f"[BENCHMARK_DIGEST_ERROR] {sanitize_untrusted_text(str(exc), limit=300)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
