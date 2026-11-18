#!/usr/bin/env python3
"""Offline unit tests for `scripts/repo_watch.py` (all HTTP/CLI calls mocked)."""

from __future__ import annotations

import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import repo_watch  # noqa: E402


def _make_api_router(state_box: dict):
    """Build a fake `github_get_json(endpoint)` backed by `state_box`."""

    def _fake_get(endpoint: str):
        ep = endpoint.split("?", 1)[0]
        if ep == "repos/example/demo-repo":
            return state_box["repo"]
        if ep == "repos/example/demo-repo/issues":
            return state_box["issues"]
        if ep == "repos/example/demo-repo/issues/comments":
            return state_box["issue_comments"]
        if ep == "repos/example/demo-repo/pulls":
            return state_box["prs"]
        if ep == "repos/example/demo-repo/pulls/comments":
            return state_box["pr_comments"]
        if ep == "repos/example/demo-repo/releases":
            return state_box["releases"]
        if ep == "repos/example/demo-repo/actions/runs":
            return {"workflow_runs": state_box["runs"]}
        if ep == "repos/example/demo-repo/forks":
            return state_box.get("forks_list", [])
        if ep == "repos/example/demo-repo/stargazers":
            return state_box.get("stargazers_list", [])
        if ep == "repos/example/demo-repo/commits":
            return state_box.get("commits", [])
        raise AssertionError(f"Unexpected endpoint: {endpoint}")

    return _fake_get


class TestRepoWatchValidationAndAuth(unittest.TestCase):
    """Verify `--repo` injection guard and 3-tier auth chain."""

    def test_validate_repo_accepts_valid_and_rejects_injection(self):
        self.assertEqual("example/demo-repo", repo_watch.validate_repo("example/demo-repo"))
        self.assertEqual("org_1/app.v2", repo_watch.validate_repo(" org_1/app.v2 "))

        bad_inputs = [
            "",
            "just-owner",
            "owner/repo/extra",
            "owner/repo?per_page=1",
            "owner/repo#frag",
            "../secret",
            "owner/..",
            "./repo",
            "owner/repo;rm -rf /",
        ]
        for bad in bad_inputs:
            with self.subTest(repo=bad):
                with self.assertRaises(ValueError):
                    repo_watch.validate_repo(bad)

        # CLI returns non-zero on invalid repo
        with mock.patch("sys.stderr", new_callable=io.StringIO):
            rc = repo_watch.main(["--repo", "bad/../repo"])
        self.assertEqual(1, rc)

    def test_auth_chain_token_then_gh_cli_then_anonymous(self):
        # 1. GH_TOKEN -> urllib with Bearer header
        captured_reqs = []

        class _FakeResp:
            def __init__(self, payload):
                self._raw = json.dumps(payload).encode("utf-8")

            def read(self):
                return self._raw

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def fake_urlopen(req, timeout=20):
            captured_reqs.append(req)
            return _FakeResp({"stargazers_count": 5})

        with (
            mock.patch.dict(os.environ, {"GH_TOKEN": "MOCK_GITHUB_TOKEN_FOR_TEST"}, clear=False),
            mock.patch("urllib.request.urlopen", side_effect=fake_urlopen),
        ):
            data = repo_watch.github_get_json("repos/example/demo-repo")
        self.assertEqual(5, data["stargazers_count"])
        self.assertEqual("Bearer MOCK_GITHUB_TOKEN_FOR_TEST", captured_reqs[0].headers.get("Authorization"))

        # 2. No token + gh-bao present -> subprocess `gh-bao api ...`
        fake_proc = mock.MagicMock(returncode=0, stdout='{"ok": true}', stderr="")
        with (
            mock.patch.dict(os.environ, {"GH_TOKEN": "", "GITHUB_TOKEN": ""}, clear=False),
            mock.patch("shutil.which", side_effect=lambda cmd: "/usr/local/bin/gh-bao" if cmd == "gh-bao" else None),
            mock.patch("subprocess.run", return_value=fake_proc) as run_mock,
        ):
            data2 = repo_watch.github_get_json("repos/example/demo-repo")
        self.assertEqual({"ok": True}, data2)
        self.assertEqual(["/usr/local/bin/gh-bao", "api", "repos/example/demo-repo"], run_mock.call_args[0][0])

        # 3. No token + no gh -> anonymous urllib without Authorization header
        captured_reqs.clear()
        with (
            mock.patch.dict(os.environ, {"GH_TOKEN": "", "GITHUB_TOKEN": ""}, clear=False),
            mock.patch("shutil.which", return_value=None),
            mock.patch("urllib.request.urlopen", side_effect=fake_urlopen),
        ):
            data3 = repo_watch.github_get_json("repos/example/demo-repo")
        self.assertEqual(5, data3["stargazers_count"])
        self.assertIsNone(captured_reqs[0].headers.get("Authorization"))


class TestRepoWatchDeltaAndTiers(unittest.TestCase):
    """Verify seed, cold-start, silent, info, actionable, PR separation, and truncation."""

    def _base_box(self) -> dict:
        return {
            "repo": {
                "stargazers_count": 10,
                "forks_count": 2,
                "open_issues_count": 0,
                "pushed_at": "2026-11-18T00:00:00Z",
                "default_branch": "main",
            },
            "issues": [
                # Closed issue + a PR returned by GitHub's /issues endpoint (must be stripped!)
                {
                    "number": 1,
                    "title": "Old closed issue",
                    "state": "closed",
                    "updated_at": "2026-11-10T00:00:00Z",
                    "comments": 0,
                    "user": {"login": "alice"},
                    "html_url": "https://github.com/example/demo-repo/issues/1",
                    "body": "done",
                },
                {
                    "number": 2,
                    "title": "PR disguised inside /issues",
                    "state": "open",
                    "updated_at": "2026-11-10T00:00:00Z",
                    "pull_request": {"url": "https://api.github.com/repos/example/demo-repo/pulls/2"},
                    "user": {"login": "bob"},
                    "html_url": "https://github.com/example/demo-repo/pull/2",
                    "body": "pr body",
                },
            ],
            "issue_comments": [],
            "prs": [],
            "pr_comments": [],
            "releases": [],
            "runs": [
                {"id": 500, "name": "CI", "conclusion": "success", "head_branch": "main", "head_sha": "abc123456"}
            ],
            "forks_list": [],
            "stargazers_list": [],
            "commits": [{"sha": "aaa111222", "commit": {"message": "chore: release", "author": {"name": "alice"}}}],
        }

    def test_seed_cold_start_and_silent_mode(self):
        box = self._base_box()
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "state.json"
            with mock.patch.object(repo_watch, "github_get_json", side_effect=_make_api_router(box)):
                rc, out = repo_watch.run_watch("example/demo-repo", state_file=state_file, seed=True)
                self.assertEqual(0, rc)
                self.assertEqual("[SILENT]", out)
                self.assertTrue(state_file.is_file())
                mode = stat.S_IMODE(state_file.stat().st_mode)
                self.assertEqual(0o600, mode)
                saved = json.loads(state_file.read_text(encoding="utf-8"))
                self.assertEqual(1, saved["schema_version"])
                # PR #2 from /issues must NOT appear in state["issues"]
                self.assertIn("1", saved["issues"])
                self.assertNotIn("2", saved["issues"])

                # Next run with zero changes -> strictly [SILENT], updates last_checked_at
                saved["last_checked_at"] = "2020-01-01T00:00:00Z"
                state_file.write_text(json.dumps(saved), encoding="utf-8")
                rc2, out2 = repo_watch.run_watch("example/demo-repo", state_file=state_file)
                self.assertEqual(0, rc2)
                self.assertEqual("[SILENT]", out2)
                saved2 = json.loads(state_file.read_text(encoding="utf-8"))
                self.assertNotEqual("2020-01-01T00:00:00Z", saved2["last_checked_at"])

            # Cold start (no state file) with only closed issues and success CI -> [SILENT]
            cold_state_silent = Path(tmp) / "cold_silent.json"
            with mock.patch.object(repo_watch, "github_get_json", side_effect=_make_api_router(box)):
                rc_c1, out_c1 = repo_watch.run_watch("example/demo-repo", state_file=cold_state_silent)
            self.assertEqual(0, rc_c1)
            self.assertEqual("[SILENT]", out_c1)

            # Cold start with an open issue -> tier=actionable
            box["issues"].append(
                {
                    "number": 3,
                    "title": "Existing open bug",
                    "state": "open",
                    "updated_at": "2026-11-18T01:00:00Z",
                    "comments": 0,
                    "user": {"login": "alice"},
                    "html_url": "https://github.com/example/demo-repo/issues/3",
                    "body": "need help",
                }
            )
            cold_state_act = Path(tmp) / "cold_act.json"
            with mock.patch.object(repo_watch, "github_get_json", side_effect=_make_api_router(box)):
                rc_c2, out_c2 = repo_watch.run_watch("example/demo-repo", state_file=cold_state_act)
            self.assertEqual(0, rc_c2)
            self.assertTrue(out_c2.startswith("[REPO_WATCH_DELTA repo=example/demo-repo tier=actionable]"))
            self.assertIn(repo_watch.UNTRUSTED_WARNING, out_c2)
            self.assertIn("#3", out_c2)

    def test_info_and_actionable_tiers_and_commit_flag(self):
        box = self._base_box()
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "state.json"
            with mock.patch.object(repo_watch, "github_get_json", side_effect=_make_api_router(box)):
                repo_watch.run_watch("example/demo-repo", state_file=state_file, seed=True)

            # Info-only change: star +2, fork +1, new release (normal commit ignored by default)
            box["repo"]["stargazers_count"] = 12
            box["repo"]["forks_count"] = 3
            box["stargazers_list"] = [{"login": "star_user_1"}, {"login": "star_user_2"}]
            box["forks_list"] = [{"full_name": "forker/demo-repo", "owner": {"login": "forker"}}]
            box["releases"] = [
                {
                    "id": 900,
                    "tag_name": "v1.1.0",
                    "name": "v1.1.0",
                    "published_at": "2026-11-18T02:00:00Z",
                    "html_url": "https://github.com/example/demo-repo/releases/tag/v1.1.0",
                }
            ]
            with mock.patch.object(repo_watch, "github_get_json", side_effect=_make_api_router(box)):
                rc_info, out_info = repo_watch.run_watch("example/demo-repo", state_file=state_file)
            self.assertEqual(0, rc_info)
            self.assertTrue(
                out_info.startswith("[REPO_WATCH_DELTA repo=example/demo-repo tier=info]\n[NO_HANDOFF_RECOMMENDED]")
            )
            self.assertIn("Stars: 10 -> 12 (+2)", out_info)
            self.assertIn("forker/demo-repo", out_info)
            self.assertIn("v1.1.0", out_info)

            # Actionable change: new issue with huge body (>800 chars), comment, PR, PR review comment, failed CI run
            long_body = "A" * 1200
            box["issues"].append(
                {
                    "number": 10,
                    "title": "Feature request",
                    "state": "open",
                    "updated_at": "2026-11-18T03:00:00Z",
                    "comments": 1,
                    "user": {"login": "alice"},
                    "html_url": "https://github.com/example/demo-repo/issues/10",
                    "body": long_body,
                }
            )
            box["issue_comments"].append(
                {
                    "id": 2001,
                    "updated_at": "2026-11-18T03:01:00Z",
                    "issue_url": "https://api.github.com/repos/example/demo-repo/issues/10",
                    "html_url": "https://github.com/example/demo-repo/issues/10#issuecomment-2001",
                    "user": {"login": "bob"},
                    "body": "plus one",
                }
            )
            box["prs"].append(
                {
                    "number": 11,
                    "title": "Fix typo",
                    "state": "open",
                    "updated_at": "2026-11-18T03:02:00Z",
                    "merged_at": None,
                    "user": {"login": "contributor"},
                    "head": {"ref": "patch-1"},
                    "base": {"ref": "main"},
                    "html_url": "https://github.com/example/demo-repo/pull/11",
                    "body": "Fixes typo",
                }
            )
            box["pr_comments"].append(
                {
                    "id": 3001,
                    "updated_at": "2026-11-18T03:03:00Z",
                    "pull_request_url": "https://api.github.com/repos/example/demo-repo/pulls/11",
                    "html_url": "https://github.com/example/demo-repo/pull/11#discussion_r3001",
                    "path": "README.md",
                    "user": {"login": "reviewer"},
                    "body": "Looks clean",
                }
            )
            box["runs"].append(
                {
                    "id": 501,
                    "name": "Lint & Test",
                    "conclusion": "failure",
                    "head_branch": "main",
                    "head_sha": "def987654321",
                    "html_url": "https://github.com/example/demo-repo/actions/runs/501",
                    "updated_at": "2026-11-18T03:04:00Z",
                }
            )
            with mock.patch.object(repo_watch, "github_get_json", side_effect=_make_api_router(box)):
                rc_act, out_act = repo_watch.run_watch("example/demo-repo", state_file=state_file, output_format="json")
            self.assertEqual(0, rc_act)
            parsed = json.loads(out_act)
            self.assertEqual("actionable", parsed["tier"])
            self.assertEqual(repo_watch.UNTRUSTED_WARNING, parsed["untrusted_warning"])
            self.assertLessEqual(len(parsed["actionable"]["issues"][0]["body"]), 800)
            self.assertEqual(1, len(parsed["actionable"]["issue_comments"]))
            self.assertEqual(1, len(parsed["actionable"]["prs"]))
            self.assertEqual(1, len(parsed["actionable"]["pr_comments"]))
            self.assertEqual([501], [r["id"] for r in parsed["actionable"]["failed_runs"]])

            # Re-running same snapshot -> [SILENT] (already recorded failed run 501, issues, PRs)
            with mock.patch.object(repo_watch, "github_get_json", side_effect=_make_api_router(box)):
                rc_re, out_re = repo_watch.run_watch("example/demo-repo", state_file=state_file)
            self.assertEqual(0, rc_re)
            self.assertEqual("[SILENT]", out_re)

            # Head commit change only: ignored without --include-commits, reported as info with --include-commits
            box["commits"] = [{"sha": "bbb222333", "commit": {"message": "feat: new", "author": {"name": "alice"}}}]
            with mock.patch.object(repo_watch, "github_get_json", side_effect=_make_api_router(box)):
                _, out_no_cm = repo_watch.run_watch("example/demo-repo", state_file=state_file, include_commits=False)
                self.assertEqual("[SILENT]", out_no_cm)
                _, out_with_cm = repo_watch.run_watch("example/demo-repo", state_file=state_file, include_commits=True)
                self.assertTrue(out_with_cm.startswith("[REPO_WATCH_DELTA repo=example/demo-repo tier=info]"))
                self.assertIn("bbb22233", out_with_cm)


if __name__ == "__main__":
    unittest.main()
