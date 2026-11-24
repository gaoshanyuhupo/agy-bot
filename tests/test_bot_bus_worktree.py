#!/usr/bin/env python3
"""Offline unit & integration tests for optional Git worktree isolation in `bot_bus` / `acb-team`."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
SCRIPTS_DIR = REPO_ROOT / "scripts"
for p in (BRIDGE_DIR, SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(k, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "/bin/false"
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=check,
    )


def _init_repo(repo_dir: Path, *, commit: bool = True) -> Path:
    repo_dir.mkdir(parents=True, exist_ok=True)
    _git(repo_dir, "init", "-q")
    _git(repo_dir, "config", "user.name", "ci-test")
    _git(repo_dir, "config", "user.email", "ci-test@example.com")
    if commit:
        (repo_dir / "src").mkdir(exist_ok=True)
        (repo_dir / "src" / "app.py").write_text("VALUE = 'initial'\n", encoding="utf-8")
        (repo_dir / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
        _git(repo_dir, "add", "-A")
        _git(repo_dir, "commit", "-q", "-m", "initial commit")
    return repo_dir


class TestBotBusWorktreeIsolation(unittest.TestCase):
    """Verify worktree lifecycle, concurrent editing isolation, MCP integration, and bridge execution."""

    def _load_bus(self, bus_dir: str):
        env_patch = {
            "AGY_BOT_BUS_DIR": bus_dir,
            "AGY_BOT_BUS_ENABLE": "1",
            "AGY_BOT_BUS_ROLE": "coordinator",
            "AGY_BOT_HANDLE": "bot_one",
            "AGY_BOT_CHAT_ID": "123456789",
            "AGY_BOT_SCOPE_KEY": "dm:123456789",
            "AGY_BOT_CHAIN": "",
            "AGY_BOT_ORIGIN_MSG_ID": "0",
            "AGY_BOT_MENTION_HOP": "0",
        }
        with mock.patch.dict(os.environ, env_patch, clear=False):
            import bot_bus  # noqa: E402
            import bot_bus_mcp  # noqa: E402

            importlib.reload(bot_bus)
            importlib.reload(bot_bus_mcp)
            return bot_bus, bot_bus_mcp

    def _load_bridge(self, tmp: str):
        env_patch = {
            "AGY_BOT_BUS_DIR": tmp,
            "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
            "AGY_TG_WORKDIR": tmp,
            "AGY_TG_ALLOWED_CHATS": "-1001234567890",
            "AGY_TG_BOT_TOKEN": "1234567890:EXAMPLE_TOKEN_FOR_TEST_ONLY",
            "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
            "AGY_BOT_CHAIN": "",
            "AGY_BOT_ORIGIN_MSG_ID": "0",
            "AGY_BOT_MENTION_HOP": "0",
        }
        with mock.patch.dict(os.environ, env_patch, clear=False):
            import bridge  # noqa: E402

            importlib.reload(bridge)
            return bridge

    def test_concurrent_same_file_edits_are_isolated_and_zero_pollution(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bot_bus, _ = self._load_bus(str(tmp_path / "bus"))
            repo = _init_repo(tmp_path / "repo")

            wt_a = bot_bus.prepare_job_worktree(str(repo), "job-wt-a")
            wt_b = bot_bus.prepare_job_worktree(str(repo), "job-wt-b")

            self.assertTrue(wt_a["active"], wt_a)
            self.assertTrue(wt_b["active"], wt_b)
            self.assertNotEqual(wt_a["path"], wt_b["path"])
            self.assertEqual("agy-team/job-wt-a", wt_a["branch"])
            self.assertEqual("agy-team/job-wt-b", wt_b["branch"])

            # Both workers edit the exact same relative file simultaneously
            file_a = Path(wt_a["path"]) / "src" / "app.py"
            file_b = Path(wt_b["path"]) / "src" / "app.py"
            file_main = repo / "src" / "app.py"

            file_a.write_text("VALUE = 'worker_a'\n", encoding="utf-8")
            file_b.write_text("VALUE = 'worker_b'\n", encoding="utf-8")

            self.assertEqual("VALUE = 'worker_a'\n", file_a.read_text(encoding="utf-8"))
            self.assertEqual("VALUE = 'worker_b'\n", file_b.read_text(encoding="utf-8"))
            self.assertEqual("VALUE = 'initial'\n", file_main.read_text(encoding="utf-8"))

            # .git/info/exclude isolates .worktrees/ without touching .gitignore or polluting git status
            exclude_file = repo / ".git" / "info" / "exclude"
            self.assertTrue(exclude_file.is_file())
            exclude_lines = [ln.strip() for ln in exclude_file.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(1, exclude_lines.count(".worktrees/"))
            self.assertEqual("*.pyc\n", (repo / ".gitignore").read_text(encoding="utf-8"))
            self.assertEqual("", _git(repo, "status", "--porcelain").stdout.strip())

    def test_finalize_auto_prunes_clean_zero_commit_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bot_bus, _ = self._load_bus(str(tmp_path / "bus"))
            repo = _init_repo(tmp_path / "repo")

            wt = bot_bus.prepare_job_worktree(str(repo), "job-clean")
            self.assertTrue(wt["active"])
            self.assertTrue(os.path.isdir(wt["path"]))

            fin = bot_bus.finalize_job_worktree(wt)
            self.assertTrue(fin["pruned"])
            self.assertFalse(fin["active"])
            self.assertEqual(0, fin["commits"])
            self.assertFalse(fin["dirty"])
            self.assertFalse(fin["inspection_failed"])
            self.assertFalse(os.path.exists(wt["path"]))

            br = _git(repo, "show-ref", "--verify", f"refs/heads/{wt['branch']}", check=False)
            self.assertNotEqual(0, br.returncode)

    def test_finalize_preserves_committed_dirty_and_inspection_failed_worktrees(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bot_bus, _ = self._load_bus(str(tmp_path / "bus"))
            repo = _init_repo(tmp_path / "repo")

            # 1. Committed changes -> preserved with commit count & changed_files
            wt_commit = bot_bus.prepare_job_worktree(str(repo), "job-committed")
            wt_c_path = Path(wt_commit["path"])
            (wt_c_path / "src" / "app.py").write_text("VALUE = 'committed'\n", encoding="utf-8")
            _git(wt_c_path, "add", "src/app.py")
            _git(wt_c_path, "commit", "-q", "-m", "worker commit")

            fin_c = bot_bus.finalize_job_worktree(wt_commit)
            self.assertFalse(fin_c["pruned"])
            self.assertTrue(fin_c["active"])
            self.assertEqual(1, fin_c["commits"])
            self.assertFalse(fin_c["dirty"])
            self.assertIn("src/app.py", fin_c["changed_files"])
            self.assertTrue(os.path.isdir(wt_commit["path"]))

            # 2. Uncommitted dirty + >30 files -> preserved and changed_files capped at 30
            wt_dirty = bot_bus.prepare_job_worktree(str(repo), "job-dirty")
            wt_d_path = Path(wt_dirty["path"])
            for idx in range(35):
                (wt_d_path / f"extra_{idx:02d}.txt").write_text(f"data {idx}\n", encoding="utf-8")

            fin_d = bot_bus.finalize_job_worktree(wt_dirty)
            self.assertFalse(fin_d["pruned"])
            self.assertTrue(fin_d["active"])
            self.assertEqual(0, fin_d["commits"])
            self.assertTrue(fin_d["dirty"])
            self.assertEqual(30, len(fin_d["changed_files"]))
            self.assertTrue(os.path.isdir(wt_dirty["path"]))

            # 3. Probe failure -> preserved with inspection_failed=True even when tree is clean
            wt_fail = bot_bus.prepare_job_worktree(str(repo), "job-probe-fail")
            with mock.patch.object(bot_bus, "_run_git", return_value=(False, "", "simulated error")):
                fin_f = bot_bus.finalize_job_worktree(wt_fail)
            self.assertFalse(fin_f["pruned"])
            self.assertTrue(fin_f["active"])
            self.assertTrue(fin_f["inspection_failed"])
            self.assertTrue(os.path.isdir(wt_fail["path"]))

            # 4. Non-active / missing dir safe return
            self.assertEqual({"enabled": False, "active": False, "pruned": False}, bot_bus.finalize_job_worktree(None))
            missing_fin = bot_bus.finalize_job_worktree({"enabled": True, "active": True, "path": str(tmp_path / "gone")})
            self.assertFalse(missing_fin["active"])
            self.assertEqual("worktree_dir_missing", missing_fin["note"])

    def test_non_git_and_unborn_head_degrade_gracefully(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bot_bus, _ = self._load_bus(str(tmp_path / "bus"))

            plain_dir = tmp_path / "plain"
            plain_dir.mkdir()
            res_plain = bot_bus.prepare_job_worktree(str(plain_dir), "job-plain")
            self.assertTrue(res_plain["enabled"])
            self.assertFalse(res_plain["active"])
            self.assertEqual("not_git_repo", res_plain["reason"])

            unborn_repo = _init_repo(tmp_path / "unborn", commit=False)
            res_unborn = bot_bus.prepare_job_worktree(str(unborn_repo), "job-unborn")
            self.assertTrue(res_unborn["enabled"])
            self.assertFalse(res_unborn["active"])
            self.assertEqual("unborn_or_invalid_head", res_unborn["reason"])

            res_missing = bot_bus.prepare_job_worktree(str(tmp_path / "missing"), "job-missing")
            self.assertFalse(res_missing["active"])
            self.assertEqual("workdir_missing", res_missing["reason"])

    def test_mcp_dispatch_retry_summarize_and_cleanup_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bot_bus, bot_bus_mcp = self._load_bus(str(tmp_path / "bus"))
            repo = _init_repo(tmp_path / "repo")

            bot_bus.update_bot_config("bot_one", role="coordinator", specialty="orchestrator")
            bot_bus.update_bot_config("bot_two", role="worker", specialty="developer")
            bot_bus.update_bot_config("bota", role="worker", specialty="tester")
            for h, role in (("bot_one", "coordinator"), ("bot_two", "worker"), ("bota", "worker")):
                bot_bus.heartbeat_bot({"handle": h, "pid": os.getpid(), "role": role, "busy": False})

            # Schema & coordinator instructions checks
            with mock.patch.dict(
                os.environ,
                {
                    "AGY_BOT_BUS_ENABLE": "1",
                    "AGY_BOT_BUS_ROLE": "coordinator",
                    "AGY_BOT_HANDLE": "bot_one",
                    "AGY_RBAC_ROLE": "",
                },
                clear=False,
            ):
                schemas = {t["name"]: t for t in bot_bus_mcp._tool_schemas()}
            td_props = schemas["team_dispatch"]["inputSchema"]["properties"]
            self.assertIn("worktree", td_props)
            self.assertIn("worktree", td_props["assignments"]["items"]["properties"])
            tj_props = schemas["team_job"]["inputSchema"]["properties"]
            self.assertIn("cleanup_worktree", tj_props["action"]["enum"])
            self.assertIn("force", tj_props)
            self.assertIn("worktree", bot_bus_mcp.COORDINATOR_INSTRUCTIONS)
            self.assertIn("cleanup_worktree", bot_bus_mcp.COORDINATOR_INSTRUCTIONS)

            # Top-level worktree=True inherited and overridable per-assignment
            coord_env = {
                "AGY_BOT_BUS_ENABLE": "1",
                "AGY_BOT_BUS_ROLE": "coordinator",
                "AGY_BOT_HANDLE": "bot_one",
                "AGY_BOT_CHAIN": "",
                "AGY_BOT_CHAT_ID": "123456789",
                "AGY_BOT_SCOPE_KEY": "dm:123456789",
            }
            with mock.patch.dict(os.environ, coord_env, clear=False):
                res = bot_bus_mcp._handle_team_dispatch(
                    {
                        "worktree": True,
                        "workdir": str(repo),
                        "assignments": [
                            {"bot": "@bot_two", "prompt": "Edit module A"},
                            {"bot": "@bota", "prompt": "Read-only check", "worktree": False},
                        ],
                    }
                )
            self.assertFalse(res.get("isError"), res)
            dispatched = json.loads(res["content"][0]["text"])["dispatched"]
            job_wt = bot_bus.get_job(dispatched[0]["job_id"])
            job_no_wt = bot_bus.get_job(dispatched[1]["job_id"])
            self.assertTrue(job_wt["worktree"])
            self.assertFalse(job_no_wt["worktree"])
            self.assertIn("worktree", dispatched[0])
            self.assertNotIn("worktree", dispatched[1])

            # retry_job preserves worktree boolean
            with mock.patch.dict(os.environ, coord_env, clear=False):
                retried_res = bot_bus_mcp._handle_team_job({"action": "retry", "job_id": job_wt["job_id"]})
            self.assertFalse(retried_res.get("isError"), retried_res)
            retried_id = json.loads(retried_res["content"][0]["text"])["retried"]["job_id"]
            self.assertTrue(bot_bus.get_job(retried_id)["worktree"])

            # Simulate worker running & leaving uncommitted changes in job_wt's worktree
            wt_info = bot_bus.prepare_job_worktree(str(repo), job_wt["job_id"])
            (Path(wt_info["path"]) / "dirty.txt").write_text("unsaved\n", encoding="utf-8")
            fin_info = bot_bus.finalize_job_worktree(wt_info)
            bot_bus.finish_job(job_wt["job_id"], status="done", result_text="done", worktree_info=fin_info)

            brief = bot_bus.summarize_job_brief(bot_bus.get_job(job_wt["job_id"]))
            self.assertTrue(brief["worktree"]["active"])
            self.assertFalse(brief["worktree"]["pruned"])
            self.assertTrue(brief["worktree"]["dirty"])
            self.assertIn("dirty.txt", brief["worktree"]["changed_files"])

            # cleanup_worktree without force refuses dirty tree
            refused = bot_bus_mcp._handle_team_job({"action": "cleanup_worktree", "job_id": job_wt["job_id"]})
            self.assertTrue(refused.get("isError"), refused)
            self.assertIn("force=True", refused["content"][0]["text"])
            self.assertTrue(os.path.isdir(wt_info["path"]))

            # cleanup_worktree with force=True removes dirty worktree + branch and updates pruned=True
            forced = bot_bus_mcp._handle_team_job(
                {"action": "cleanup_worktree", "job_id": job_wt["job_id"], "force": True}
            )
            self.assertFalse(forced.get("isError"), forced)
            forced_payload = json.loads(forced["content"][0]["text"])
            self.assertTrue(forced_payload["ok"])
            self.assertTrue(forced_payload["pruned"])
            self.assertFalse(os.path.exists(wt_info["path"]))
            self.assertTrue(bot_bus.get_job(job_wt["job_id"])["worktree_info"]["pruned"])

            # Idempotent repeat cleanup returns ok
            again = bot_bus_mcp._handle_team_job({"action": "cleanup_worktree", "job_id": job_wt["job_id"]})
            self.assertFalse(again.get("isError"), again)
            self.assertTrue(json.loads(again["content"][0]["text"])["already_clean"])

            # Unmerged commit refused without force, allowed once merged into main HEAD
            wt_m_job = bot_bus.dispatch_assignments(
                "bot_one", [{"bot": "bot_two", "prompt": "commit work", "workdir": str(repo), "worktree": True}]
            )["jobs"][0]
            wt_m = bot_bus.prepare_job_worktree(str(repo), wt_m_job["job_id"])
            (Path(wt_m["path"]) / "feature.py").write_text("X = 1\n", encoding="utf-8")
            _git(Path(wt_m["path"]), "add", "feature.py")
            _git(Path(wt_m["path"]), "commit", "-q", "-m", "add feature")
            bot_bus.finish_job(
                wt_m_job["job_id"], status="done", result_text="committed", worktree_info=bot_bus.finalize_job_worktree(wt_m)
            )
            refuse_unmerged = bot_bus.cleanup_job_worktree(wt_m_job["job_id"], force=False)
            self.assertFalse(refuse_unmerged["ok"])
            self.assertIn("unmerged", refuse_unmerged["error"])

            _git(repo, "merge", "--ff-only", wt_m["branch"])
            clean_after_merge = bot_bus.cleanup_job_worktree(wt_m_job["job_id"], force=False)
            self.assertTrue(clean_after_merge["ok"], clean_after_merge)
            self.assertTrue(clean_after_merge["pruned"])

    def test_format_worker_envelope_and_execute_bus_job_worktree_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bridge = self._load_bridge(str(tmp_path / "bus"))
            bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_one", "pid": os.getpid(), "role": "coordinator", "allowed_chats": [-1001234567890]}
            )
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_two", "pid": os.getpid(), "role": "worker", "allowed_chats": [-1001234567890]}
            )

            repo = _init_repo(tmp_path / "repo")

            # Verify snapshot_workspace_files & security_audit ignore .worktrees/
            (repo / ".worktrees" / "dummy").mkdir(parents=True)
            (repo / ".worktrees" / "dummy" / "ignored.py").write_text("x = 1\n", encoding="utf-8")
            snap = bridge.snapshot_workspace_files(workdir=str(repo))
            self.assertFalse(any(".worktrees" in p for p in snap))
            self.assertIn("/.worktrees/", bridge._NOISE_ASSET_SEGMENTS)

            import security_audit  # noqa: E402

            self.assertIn(".worktrees", security_audit.SKIP_DIRS)

            # 1. Worker commits inside isolated worktree during _execute_bus_job
            dispatched = bridge.bot_bus.dispatch_assignments(
                "bot_one",
                [
                    {
                        "bot": "bot_two",
                        "prompt": "modify app inside worktree",
                        "workdir": str(repo),
                        "worktree": True,
                        "notify_group": False,
                    }
                ],
            )
            jid_commit = dispatched["jobs"][0]["job_id"]
            seen_pwds: list[str] = []
            seen_prompts: list[str] = []

            orig_popen = subprocess.Popen

            def _fake_popen_commit(cmd, **kwargs):
                if not cmd or cmd[0] != bridge.AGY_BIN:
                    return orig_popen(cmd, **kwargs)
                cwd = kwargs.get("cwd") or ""
                seen_pwds.append(cwd)
                seen_prompts.append(cmd[-1])
                (Path(cwd) / "src" / "app.py").write_text("VALUE = 'from_worker'\n", encoding="utf-8")
                _git(Path(cwd), "add", "src/app.py")
                _git(Path(cwd), "commit", "-q", "-m", "worker change")

                class _Proc:
                    pid = 88888
                    returncode = 0
                    stdout = iter(
                        [
                            json.dumps(
                                {
                                    "event": "result",
                                    "result": {
                                        "status": "SUCCESS",
                                        "conversation_id": "conv-wt-1",
                                        "response": "updated in worktree",
                                    },
                                }
                            )
                            + "\n"
                        ]
                    )
                    stderr = iter([])

                    def wait(self, timeout=None):
                        return 0

                return _Proc()

            with mock.patch.object(bridge.subprocess, "Popen", side_effect=_fake_popen_commit):
                bridge._execute_bus_job(jid_commit)

            expected_wt = os.path.realpath(str(repo / ".worktrees" / jid_commit))
            self.assertEqual([expected_wt], seen_pwds)
            self.assertIn(f"agy-team/{jid_commit}", seen_prompts[0])
            self.assertIn("隔离 Worktree", seen_prompts[0])
            self.assertEqual("VALUE = 'initial'\n", (repo / "src" / "app.py").read_text(encoding="utf-8"))

            done_job = bridge.bot_bus.get_job(jid_commit)
            self.assertEqual("done", done_job["status"])
            self.assertFalse(done_job["worktree_info"]["pruned"])
            self.assertEqual(1, done_job["worktree_info"]["commits"])
            self.assertIn("src/app.py", done_job["worktree_info"]["changed_files"])

            # 2. Worker makes no changes and raises -> finally still auto-prunes clean worktree
            dispatched_err = bridge.bot_bus.dispatch_assignments(
                "bot_one",
                [
                    {
                        "bot": "bot_two",
                        "prompt": "noop crash",
                        "workdir": str(repo),
                        "worktree": True,
                        "notify_group": False,
                    }
                ],
            )
            jid_err = dispatched_err["jobs"][0]["job_id"]

            def _fake_popen_crash(cmd, **kwargs):
                if not cmd or cmd[0] != bridge.AGY_BIN:
                    return orig_popen(cmd, **kwargs)
                raise RuntimeError("boom")

            with mock.patch.object(bridge.subprocess, "Popen", side_effect=_fake_popen_crash):
                bridge._execute_bus_job(jid_err)

            err_job = bridge.bot_bus.get_job(jid_err)
            self.assertEqual("error", err_job["status"])
            self.assertTrue(err_job["worktree_info"]["pruned"])
            self.assertFalse(os.path.exists(repo / ".worktrees" / jid_err))


if __name__ == "__main__":
    unittest.main()
