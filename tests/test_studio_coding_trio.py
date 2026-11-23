#!/usr/bin/env python3
"""P0 Contract Tests — AGY Studio Coding Workbench Trio (`C1`–`C8`).

Covers:
- Pillar 1: Per-Session Isolated Git Worktree (creation, degradation, no `--project` pullback, cleanup)
- Pillar 2: Turn-by-Turn Checkpoint Diff Viewer & Worktree Undo/Redo ownership
- Pillar 3: Safe Git Workflow (Status / Commit / Push / Open PR + sensitive/symlink/secret guards)
- Concurrency & AST lock-ordering invariants (C6)
- UI race guards, Demo parity, and public export registration (C8)

Runs 100% offline in temporary directories with zero real git push, zero real PRs,
and zero real browser processes.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from aiohttp.test_utils import TestClient, TestServer

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import bot_bus  # noqa: E402
import bridge as bridge_mod  # noqa: E402
import studio_ipc  # noqa: E402
from studio.auth import (  # noqa: E402
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.data_sources import StudioDataSources  # noqa: E402
from studio.server import GIT_WORKFLOW_KEY, create_app  # noqa: E402

BOT_TOKEN_TEST = "123456789:EXAMPLE_TRIO_TOKEN_0001"
ADMIN_UID = 111111111
READONLY_UID = 222222222
TEST_BOT_HANDLE = "example_trio_bot"
TEST_PASS_ADMIN = "EXAMPLE_ADMIN_PASS_TRIO"
TEST_PASS_RO = "EXAMPLE_RO_PASS_TRIO"
TEST_PASS_FORCE = "EXAMPLE_FORCE_PASS_TRIO"
SYNTHETIC_GH_PAT = "ghp_" + "ExampleSyntheticToken1234567890"
SYNTHETIC_OB_TOK = "hvs." + "ExampleOpenBaoToken1234567890"


def _write_env(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _git_init_repo(repo_dir: Path, *, with_commit: bool = True, branch: str = "main") -> None:
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", branch], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Example Dev"], cwd=repo_dir, check=True, capture_output=True)
    if with_commit:
        (repo_dir / "README.md").write_text("# Example Repo\nline 2\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=repo_dir, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial commit"], cwd=repo_dir, check=True, capture_output=True)


class _TrioBaseTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_studio_trio_")
        self.tmp = Path(self._td.name)
        self.config_dir = self.tmp / "studio-config"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bot_bus"
        self.projects_dir = self.tmp / "projects"
        self.undo_dir = self.tmp / "acb_undo"
        self.undo_blobs_dir = self.undo_dir / "blobs"
        self.git_proj = self.tmp / "repos" / "git-proj"
        self.nongit_proj = self.tmp / "repos" / "nongit-proj"
        self.unborn_proj = self.tmp / "repos" / "unborn-proj"
        self.evil_sibling = self.tmp / "repos" / "git-proj-evil"
        self.outside_dir = self.tmp / "outside"
        self.audit_log = self.config_dir / "audit.jsonl"

        for d in (
            self.config_dir,
            self.bridge_dir,
            self.bus_dir / "jobs",
            self.bus_dir / "inbox",
            self.projects_dir,
            self.undo_blobs_dir,
            self.nongit_proj,
            self.evil_sibling / ".worktrees" / "wt-evil1",
            self.outside_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

        _git_init_repo(self.git_proj, with_commit=True, branch="main")
        _git_init_repo(self.unborn_proj, with_commit=False, branch="main")
        (self.nongit_proj / "notes.txt").write_text("plain dir\n", encoding="utf-8")
        (self.outside_dir / "secret.txt").write_text("OUTSIDE_SECRET_DATA\n", encoding="utf-8")

        for pid, pdir in (
            ("git-proj", self.git_proj),
            ("nongit-proj", self.nongit_proj),
            ("unborn-proj", self.unborn_proj),
        ):
            (self.projects_dir / f"{pid}.json").write_text(
                json.dumps({
                    "id": pid,
                    "name": pid,
                    "projectResources": {
                        "resources": [{"folderUri": f"file://{pdir}"}]
                    },
                }),
                encoding="utf-8",
            )

        _write_env(
            self.bridge_dir / ".env",
            [
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_TEST}",
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                f"AGY_TG_READONLY_USERS={READONLY_UID}",
            ],
        )

        now_i = int(time.time())
        self.users_path = self.config_dir / "users.json"
        save_users_file_atomic(
            self.users_path,
            {
                "admin": {
                    "username": "admin",
                    "role": "admin",
                    "password_hash": hash_password_scrypt(TEST_PASS_ADMIN),
                    "must_change_password": False,
                    "bot": "main",
                    "user_id": ADMIN_UID,
                    "enabled": True,
                    "password_version": 1,
                    "created_at": now_i,
                    "updated_at": now_i,
                },
                "viewer": {
                    "username": "viewer",
                    "role": "readonly",
                    "password_hash": hash_password_scrypt(TEST_PASS_RO),
                    "must_change_password": False,
                    "bot": "main",
                    "user_id": READONLY_UID,
                    "enabled": True,
                    "password_version": 1,
                    "created_at": now_i,
                    "updated_at": now_i,
                },
                "forcechange": {
                    "username": "forcechange",
                    "role": "admin",
                    "password_hash": hash_password_scrypt(TEST_PASS_FORCE),
                    "must_change_password": True,
                    "bot": "main",
                    "user_id": ADMIN_UID,
                    "enabled": True,
                    "password_version": 1,
                    "created_at": now_i,
                    "updated_at": now_i,
                },
            },
        )

        # Configure Bridge module globals in complete isolation
        self._patches = [
            mock.patch.object(bot_bus, "BUS_DIR", str(self.bus_dir)),
            mock.patch.object(bridge_mod, "ACB_UNDO_DIR", str(self.undo_dir)),
            mock.patch.object(bridge_mod, "ACB_UNDO_BLOBS_DIR", str(self.undo_blobs_dir)),
            mock.patch.object(bridge_mod, "WORKDIR", str(self.git_proj)),
            mock.patch.object(bridge_mod, "STATE_FILE", str(self.tmp / "bridge_state.json")),
            mock.patch.object(
                bridge_mod,
                "list_agy_projects",
                side_effect=lambda: [
                    {"id": "git-proj", "name": "git-proj", "workdir": str(self.git_proj)},
                    {"id": "nongit-proj", "name": "nongit-proj", "workdir": str(self.nongit_proj)},
                    {"id": "unborn-proj", "name": "unborn-proj", "workdir": str(self.unborn_proj)},
                ],
            ),
            mock.patch.object(bridge_mod, "_current_bot_handle", return_value=TEST_BOT_HANDLE),
            mock.patch.object(bridge_mod, "save_state", return_value=None),
            mock.patch.object(bridge_mod, "_sync_top_level_mirrors_locked", return_value=None),
            mock.patch.object(bridge_mod, "state", {"scopes": {}, "worktrees_by_cid": {}}),
            mock.patch.object(bridge_mod, "_studio_ipc_buffer", studio_ipc.TurnEventBuffer()),
            mock.patch.object(bridge_mod, "job_q", type(bridge_mod.job_q)()),
            mock.patch.object(bridge_mod, "_session_pool", {}),
            mock.patch.object(bridge_mod, "turn_running", False),
            mock.patch.object(bridge_mod, "turn_running_scope", None),
            mock.patch.object(bridge_mod, "turn_running_cid", None),
            mock.patch.object(bridge_mod, "turn_running_worktree_id", None),
            mock.patch.object(bridge_mod, "turn_running_web_id", None),
        ]
        for p in self._patches:
            p.start()

        # Start real in-process AF_UNIX StudioIPCServer backed by Bridge functions
        self.ipc_server = studio_ipc.StudioIPCServer(
            bus_dir=self.bus_dir,
            bot_handle=TEST_BOT_HANDLE,
            resolve_role_fn=lambda uid: "admin" if int(uid) == ADMIN_UID else "readonly",
            get_meta_fn=lambda: {
                "handle": TEST_BOT_HANDLE,
                "busy": bool(bridge_mod.turn_running),
                "models": [{"id": "example-model", "label": "Example"}],
                "projects": [
                    {"id": "git-proj", "name": "git-proj"},
                    {"id": "nongit-proj", "name": "nongit-proj"},
                    {"id": "unborn-proj", "name": "unborn-proj"},
                ],
            },
            enqueue_turn_fn=bridge_mod._studio_ipc_enqueue_turn,
            abort_turn_fn=bridge_mod._studio_ipc_abort_turn,
            list_undo_fn=bridge_mod._studio_ipc_list_undo,
            diff_undo_fn=bridge_mod._studio_ipc_get_undo_diff,
            apply_undo_fn=bridge_mod._studio_ipc_apply_undo,
            apply_redo_fn=bridge_mod._studio_ipc_apply_redo,
            cleanup_worktree_fn=bridge_mod._studio_ipc_cleanup_worktree,
            buffer=bridge_mod._studio_ipc_buffer,
        )
        self.ipc_server.start()

        self.auth_mgr = StudioAuthManager(
            auth_mode="password",
            bridge_dir=self.bridge_dir,
            config_dir=self.config_dir,
            public_url="",
        )
        self.data_sources = StudioDataSources(
            bus_dir=self.bus_dir,
            projects_dir=self.projects_dir,
            brain_root=self.tmp / "brain",
            summaries_db=self.tmp / "summaries.db",
            meta_file=self.tmp / "meta.json",
        )
        self.app = create_app(
            auth_mgr=self.auth_mgr,
            data_sources=self.data_sources,
            audit_log_path=self.audit_log,
        )
        self.server = TestServer(self.app)
        self.client = TestClient(self.server)
        await self.client.start_server()
        self.origin = f"http://127.0.0.1:{self.server.port}"

    async def asyncTearDown(self) -> None:
        await self.client.close()
        self.ipc_server.stop()
        for p in reversed(self._patches):
            p.stop()
        self._td.cleanup()

    async def _login(self, username: str, password: str) -> tuple[dict[str, str], str]:
        resp = await self.client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
            headers={"Origin": self.origin},
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        cookie_val = resp.cookies["agy_studio_session"].value
        # Clear TestClient cookie jar so unauthenticated calls do not inherit cached session cookies
        self.client.session.cookie_jar.clear()
        return {"agy_studio_session": cookie_val}, str(data["csrf_token"])

    def _write_headers(self, csrf: str, *, origin: str | None = None, content_type: str = "application/json") -> dict[str, str]:
        hdrs = {
            "X-Studio-CSRF": csrf,
            "Content-Type": content_type,
        }
        if origin is not None:
            hdrs["Origin"] = origin
        return hdrs


class TestStudioCodingWorkbenchTrio(_TrioBaseTest):
    # ------------------------------------------------------------------ C1
    async def test_c1_write_gate_and_read_rbac(self) -> None:
        admin_cookies, admin_csrf = await self._login("admin", TEST_PASS_ADMIN)
        ro_cookies, ro_csrf = await self._login("viewer", TEST_PASS_RO)
        fc_cookies, fc_csrf = await self._login("forcechange", TEST_PASS_FORCE)

        # Read APIs unauthenticated -> 401; must_change_password -> 403; authenticated -> 200 + headers
        for path in ("/api/worktrees?project_id=git-proj", "/api/git/status?project_id=git-proj"):
            self.client.session.cookie_jar.clear()
            r_unauth = await self.client.get(path)
            self.assertEqual(r_unauth.status, 401)
            r_fc = await self.client.get(path, cookies=fc_cookies)
            self.assertEqual(r_fc.status, 403)
            r_ro = await self.client.get(path, cookies=ro_cookies)
            self.assertEqual(r_ro.status, 200)
            self.assertIn("no-store", r_ro.headers.get("Cache-Control", ""))
            self.assertEqual(r_ro.headers.get("Referrer-Policy"), "no-referrer")
            raw_txt = await r_ro.text()
            self.assertNotIn(str(self.tmp), raw_txt)

        # Checkpoint diff: unauth -> 401; readonly -> 403
        self.client.session.cookie_jar.clear()
        r_cd_unauth = await self.client.get("/api/undo/checkpoints/u1234567/diff")
        self.assertEqual(r_cd_unauth.status, 401)
        r_cd_ro = await self.client.get("/api/undo/checkpoints/u1234567/diff", cookies=ro_cookies)
        self.assertEqual(r_cd_ro.status, 403)

        # 4-layer write gate on all mutating endpoints
        write_cases = [
            ("/api/chat/send", {"prompt": "hello", "project": "git-proj"}),
            ("/api/worktrees/wt-check01/cleanup", {"project_id": "git-proj", "force": False}),
            ("/api/git/commit", {"project_id": "git-proj", "message": "test", "stage_mode": "staged"}),
            ("/api/git/push", {"project_id": "git-proj"}),
            ("/api/git/pr", {"project_id": "git-proj", "title": "PR title"}),
        ]
        for path, payload in write_cases:
            # 1) Missing Origin -> 403
            r1 = await self.client.post(
                path,
                data=json.dumps(payload),
                cookies=admin_cookies,
                headers=self._write_headers(admin_csrf, origin=None),
            )
            self.assertEqual(r1.status, 403, f"missing Origin must fail on {path}")
            # 2) Cross-site Origin -> 403
            r2 = await self.client.post(
                path,
                data=json.dumps(payload),
                cookies=admin_cookies,
                headers=self._write_headers(admin_csrf, origin="https://evil.example.com"),
            )
            self.assertEqual(r2.status, 403, f"cross-site Origin must fail on {path}")
            # 3) Non-JSON Content-Type -> 415
            r3 = await self.client.post(
                path,
                data="{}",
                cookies=admin_cookies,
                headers=self._write_headers(admin_csrf, origin=self.origin, content_type="text/plain"),
            )
            self.assertEqual(r3.status, 415, f"non-JSON must return 415 on {path}")
            # 4) Unauthenticated -> 401
            self.client.session.cookie_jar.clear()
            r4 = await self.client.post(
                path,
                data=json.dumps(payload),
                headers=self._write_headers(admin_csrf, origin=self.origin),
            )
            self.assertEqual(r4.status, 401, f"unauth must return 401 on {path}")
            # 5) must_change_password -> 403
            r5 = await self.client.post(
                path,
                data=json.dumps(payload),
                cookies=fc_cookies,
                headers=self._write_headers(fc_csrf, origin=self.origin),
            )
            self.assertEqual(r5.status, 403, f"must_change_password must return 403 on {path}")
            # 6) Bad CSRF -> 403
            r6 = await self.client.post(
                path,
                data=json.dumps(payload),
                cookies=admin_cookies,
                headers=self._write_headers("bad-csrf-token", origin=self.origin),
            )
            self.assertEqual(r6.status, 403, f"bad CSRF must return 403 on {path}")
            # 7) Readonly role -> 403
            r7 = await self.client.post(
                path,
                data=json.dumps(payload),
                cookies=ro_cookies,
                headers=self._write_headers(ro_csrf, origin=self.origin),
            )
            self.assertEqual(r7.status, 403, f"readonly must return 403 on {path}")

        # Audit log exists with 0600 permissions
        self.assertTrue(self.audit_log.is_file())
        mode = stat.S_IMODE(self.audit_log.stat().st_mode)
        self.assertEqual(mode, 0o600)

    # ------------------------------------------------------------------ C2
    async def test_c2_forbidden_keys_worktree_traversal_and_git_flag_injection(self) -> None:
        cookies, csrf = await self._login("admin", TEST_PASS_ADMIN)
        hdrs = self._write_headers(csrf, origin=self.origin)

        # Recursive forbidden keys rejected on chat/send and git/worktree endpoints
        for bad_body in (
            {"prompt": "hi", "workdir": "/tmp"},
            {"prompt": "hi", "nested": {"cwd": "/etc"}},
            {"prompt": "hi", "meta": [{"worktree_path": "/tmp/x"}]},
            {"prompt": "hi", "root": "/"},
        ):
            r = await self.client.post("/api/chat/send", data=json.dumps(bad_body), cookies=cookies, headers=hdrs)
            self.assertEqual(r.status, 400)

        # Worktree symlink & traversal checks on workspace/files/git APIs
        wt_parent = self.git_proj / ".worktrees"
        wt_parent.mkdir(exist_ok=True)
        os.symlink(str(self.outside_dir), str(wt_parent / "wt-symlink"))

        for bad_wt in ("../outside", "-flag", "a/b"):
            r_bad = await self.client.get(
                f"/api/workspace/tree?project_id=git-proj&worktree_id={bad_wt}",
                cookies=cookies,
            )
            self.assertEqual(r_bad.status, 400)

        for ep in (
            "/api/workspace/tree?project_id=git-proj&worktree_id=wt-symlink",
            "/api/workspace/file?project_id=git-proj&worktree_id=wt-symlink&path=secret.txt",
            "/api/workspace/diff?project_id=git-proj&worktree_id=wt-symlink",
            "/api/git/status?project_id=git-proj&worktree_id=wt-symlink",
        ):
            r_sym = await self.client.get(ep, cookies=cookies)
            self.assertEqual(r_sym.status, 403, f"symlink worktree must be 403 on {ep}")

        r_miss = await self.client.get(
            "/api/git/status?project_id=git-proj&worktree_id=wt-nonexistent",
            cookies=cookies,
        )
        self.assertEqual(r_miss.status, 404)
        (wt_parent / "wt-symlink").unlink()

        # Commit: reject extra/forbidden keys (amend/no_verify/args) and unsafe paths
        for bad_commit in (
            {"project_id": "git-proj", "message": "x", "stage_mode": "all", "amend": True},
            {"project_id": "git-proj", "message": "x", "stage_mode": "all", "no_verify": True},
            {"project_id": "git-proj", "message": "x", "stage_mode": "all", "args": ["--amend"]},
            {"project_id": "git-proj", "message": "x", "stage_mode": "paths", "paths": ["--all"]},
            {"project_id": "git-proj", "message": "x", "stage_mode": "paths", "paths": ["../outside/secret.txt"]},
        ):
            r = await self.client.post("/api/git/commit", data=json.dumps(bad_commit), cookies=cookies, headers=hdrs)
            self.assertEqual(r.status, 400)

        # Safe commit with literal message `--amend` passed via `-F -` stdin creates a NEW commit (2 commits total)
        (self.git_proj / "safe.txt").write_text("hello safe\n", encoding="utf-8")
        r_ok = await self.client.post(
            "/api/git/commit",
            data=json.dumps({
                "project_id": "git-proj",
                "message": "--amend --no-verify literal subject",
                "stage_mode": "paths",
                "paths": ["safe.txt"],
            }),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_ok.status, 200)
        d_ok = await r_ok.json()
        self.assertTrue(d_ok["ok"])
        cnt = subprocess.check_output(["git", "rev-list", "--count", "HEAD"], cwd=self.git_proj, text=True).strip()
        self.assertEqual(cnt, "2")

        # PR validation: base regex, title newline, head == base, stdin --body-file -, https:// pr_url enforcement
        subprocess.run(
            ["git", "remote", "add", "origin", "https://github.com/example-org/example-repo.git"],
            cwd=self.git_proj,
            check=True,
        )
        subprocess.run(["git", "checkout", "-b", "feat/trio-pr"], cwd=self.git_proj, check=True, capture_output=True)

        for bad_pr in (
            {"project_id": "git-proj", "title": "bad\nnewline"},
            {"project_id": "git-proj", "title": "ok", "base": "-evil"},
            {"project_id": "git-proj", "title": "ok", "base": "main..other"},
            {"project_id": "git-proj", "title": "ok", "base": "bad branch"},
            {"project_id": "git-proj", "title": "ok", "base": "feat/trio-pr"},  # head == base
            {"project_id": "git-proj", "title": "ok", "repo": "evil/repo"},
        ):
            r = await self.client.post("/api/git/pr", data=json.dumps(bad_pr), cookies=cookies, headers=hdrs)
            self.assertEqual(r.status, 400, f"expected 400 for {bad_pr}")

        git_svc = self.app[GIT_WORKFLOW_KEY]
        captured_gh: dict[str, object] = {}

        async def _fake_gh_bad_url(root, args, *, stdin_bytes=None, extra_env=None, timeout=30.0):
            captured_gh["args"] = list(args)
            captured_gh["stdin"] = stdin_bytes
            captured_gh["env"] = dict(extra_env or {})
            return 0, "javascript:alert(1)\n", ""

        with (
            mock.patch.object(git_svc, "_get_github_token", return_value=SYNTHETIC_GH_PAT),
            mock.patch.object(git_svc, "_run_gh", side_effect=_fake_gh_bad_url),
        ):
            r_js = await self.client.post(
                "/api/git/pr",
                data=json.dumps({
                    "project_id": "git-proj",
                    "title": "Test PR",
                    "body": "--repo evil/inject\nbody text",
                    "base": "main",
                }),
                cookies=cookies,
                headers=hdrs,
            )
            self.assertEqual(r_js.status, 502)
            self.assertIn("--body-file", captured_gh["args"])
            self.assertIn("-", captured_gh["args"])
            self.assertEqual(captured_gh["stdin"], b"--repo evil/inject\nbody text")

        async def _fake_gh_ok(root, args, *, stdin_bytes=None, extra_env=None, timeout=30.0):
            return 0, "https://github.com/example-org/example-repo/pull/9\n", ""

        with (
            mock.patch.object(git_svc, "_get_github_token", return_value=SYNTHETIC_GH_PAT),
            mock.patch.object(git_svc, "_run_gh", side_effect=_fake_gh_ok),
        ):
            r_good = await self.client.post(
                "/api/git/pr",
                data=json.dumps({"project_id": "git-proj", "title": "Good PR", "base": "main", "draft": True}),
                cookies=cookies,
                headers=hdrs,
            )
            self.assertEqual(r_good.status, 200)
            d_good = await r_good.json()
            self.assertEqual(d_good["pr_url"], "https://github.com/example-org/example-repo/pull/9")
            self.assertTrue(d_good["draft"])

    # ------------------------------------------------------------------ C3
    async def test_c3_sensitive_file_symlink_secret_scan_and_openbao_zero_leak(self) -> None:
        cookies, csrf = await self._login("admin", TEST_PASS_ADMIN)
        hdrs = self._write_headers(csrf, origin=self.origin)

        # 1) Sensitive file (.env) blocked under stage_mode="all" and "paths" with ZERO index residue
        env_file = self.git_proj / ".env"
        env_file.write_text("SECRET_KEY=demo_value\n", encoding="utf-8")
        r_all = await self.client.post(
            "/api/git/commit",
            data=json.dumps({"project_id": "git-proj", "message": "add env", "stage_mode": "all"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_all.status, 403)
        staged_after = subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=self.git_proj, text=True)
        self.assertEqual(staged_after.strip(), "")

        r_paths = await self.client.post(
            "/api/git/commit",
            data=json.dumps({"project_id": "git-proj", "message": "add env", "stage_mode": "paths", "paths": [".env"]}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_paths.status, 403)

        # Even if pre-staged manually, staged mode blocks AND cleans index
        subprocess.run(["git", "add", ".env"], cwd=self.git_proj, check=True)
        r_pre = await self.client.post(
            "/api/git/commit",
            data=json.dumps({"project_id": "git-proj", "message": "staged env", "stage_mode": "staged"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_pre.status, 403)
        staged_after_pre = subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=self.git_proj, text=True)
        self.assertEqual(staged_after_pre.strip(), "")
        env_file.unlink()

        # 2) Symlink (mode 120000) blocked under all, paths, and pre-staged with zero index residue
        sym_file = self.git_proj / "link_outside.txt"
        os.symlink(str(self.outside_dir / "secret.txt"), str(sym_file))
        r_sym_all = await self.client.post(
            "/api/git/commit",
            data=json.dumps({"project_id": "git-proj", "message": "add symlink", "stage_mode": "all"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_sym_all.status, 403)
        r_sym_paths = await self.client.post(
            "/api/git/commit",
            data=json.dumps({"project_id": "git-proj", "message": "add symlink", "stage_mode": "paths", "paths": ["link_outside.txt"]}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_sym_paths.status, 403)
        subprocess.run(["git", "add", "link_outside.txt"], cwd=self.git_proj, check=True)
        r_sym_st = await self.client.post(
            "/api/git/commit",
            data=json.dumps({"project_id": "git-proj", "message": "staged symlink", "stage_mode": "staged"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_sym_st.status, 403)
        self.assertEqual(
            subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=self.git_proj, text=True).strip(),
            "",
        )
        sym_file.unlink()

        # 3) Pre-commit secret scan blocks ghp_ / BEGIN PRIVATE KEY / OpenBao token without echoing raw value
        synthetic_pem = (
            "".join(["-----BEGIN ", "PRIVATE KEY-----\n"])
            + "MIIEvAIBADANBg\n"
            + "".join(["-----END ", "PRIVATE KEY-----"])
        )
        for secret_val in (
            SYNTHETIC_GH_PAT,
            synthetic_pem,
            SYNTHETIC_OB_TOK,
        ):
            (self.git_proj / "leak.py").write_text(f'TOKEN = """{secret_val}"""\n', encoding="utf-8")
            r_sec = await self.client.post(
                "/api/git/commit",
                data=json.dumps({"project_id": "git-proj", "message": "oops", "stage_mode": "all"}),
                cookies=cookies,
                headers=hdrs,
            )
            self.assertEqual(r_sec.status, 403)
            raw_body = await r_sec.text()
            self.assertIn("secret_detected", raw_body)
            self.assertNotIn(SYNTHETIC_GH_PAT, raw_body)
            self.assertNotIn(SYNTHETIC_OB_TOK, raw_body)
            self.assertNotIn("MIIEvAIBADANBg", raw_body)
        (self.git_proj / "leak.py").unlink()

        # 4) OpenBao ephemeral GH_TOKEN injection: zero `.git/config` mutation and full redaction on stderr leak
        subprocess.run(
            ["git", "remote", "add", "origin", "https://github.com/example-org/example-repo.git"],
            cwd=self.git_proj,
            check=True,
        )
        subprocess.run(["git", "checkout", "-b", "feat/push-check"], cwd=self.git_proj, check=True, capture_output=True)
        git_cfg_before = hashlib.sha256((self.git_proj / ".git" / "config").read_bytes()).hexdigest()

        git_svc = self.app[GIT_WORKFLOW_KEY]
        real_run_git = git_svc._run_git
        captured_push: dict[str, object] = {}

        async def _intercept_push(root, args, *, stdin_bytes=None, extra_env=None, extra_git_cfg=None, timeout=10.0):
            if args and args[0] == "push":
                captured_push["args"] = list(args)
                captured_push["extra_env"] = dict(extra_env or {})
                captured_push["extra_git_cfg"] = list(extra_git_cfg or [])
                return 1, "", f"fatal: auth failed for token {SYNTHETIC_GH_PAT} at {self.tmp}/secret"
            return await real_run_git(
                root,
                args,
                stdin_bytes=stdin_bytes,
                extra_env=extra_env,
                extra_git_cfg=extra_git_cfg,
                timeout=timeout,
            )

        with (
            mock.patch.object(git_svc, "_get_github_token", return_value=SYNTHETIC_GH_PAT),
            mock.patch.object(git_svc, "_run_git", side_effect=_intercept_push),
        ):
            r_push = await self.client.post(
                "/api/git/push",
                data=json.dumps({"project_id": "git-proj"}),
                cookies=cookies,
                headers=hdrs,
            )
            self.assertEqual(r_push.status, 502)
            txt = await r_push.text()
            self.assertNotIn(SYNTHETIC_GH_PAT, txt)
            self.assertNotIn(str(self.tmp), txt)
            self.assertEqual(captured_push["extra_env"].get("GH_TOKEN"), SYNTHETIC_GH_PAT)
            self.assertEqual(
                captured_push["extra_git_cfg"],
                ["credential.helper=", "credential.helper=!gh auth git-credential"],
            )

        git_cfg_after = hashlib.sha256((self.git_proj / ".git" / "config").read_bytes()).hexdigest()
        self.assertEqual(git_cfg_before, git_cfg_after)
        audit_text = self.audit_log.read_text(encoding="utf-8")
        self.assertNotIn(SYNTHETIC_GH_PAT, audit_text)
        self.assertNotIn(SYNTHETIC_OB_TOK, audit_text)

    # ------------------------------------------------------------------ C4
    async def test_c4_force_push_ban_protected_branch_and_remote_guard(self) -> None:
        cookies, csrf = await self._login("admin", TEST_PASS_ADMIN)
        hdrs = self._write_headers(csrf, origin=self.origin)

        # Ban force / force_with_lease / remote / url / refspec and non-bool confirm_protected
        for bad_push in (
            {"project_id": "git-proj", "force": True},
            {"project_id": "git-proj", "force_with_lease": True},
            {"project_id": "git-proj", "remote": "upstream"},
            {"project_id": "git-proj", "url": "https://evil.example.com/r.git"},
            {"project_id": "git-proj", "refspec": "+HEAD:main"},
            {"project_id": "git-proj", "confirm_protected": "true"},
            {"project_id": "git-proj", "confirm_protected": 1},
        ):
            r = await self.client.post("/api/git/push", data=json.dumps(bad_push), cookies=cookies, headers=hdrs)
            self.assertEqual(r.status, 400, f"expected 400 for {bad_push}")

        # Missing origin remote -> 404
        r_norem = await self.client.post(
            "/api/git/push",
            data=json.dumps({"project_id": "git-proj"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_norem.status, 404)

        subprocess.run(
            ["git", "remote", "add", "origin", "https://github.com/example-org/example-repo.git"],
            cwd=self.git_proj,
            check=True,
        )

        # Protected branch (`main`) without confirm_protected: true -> 409 protected_branch
        r_prot = await self.client.post(
            "/api/git/push",
            data=json.dumps({"project_id": "git-proj"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_prot.status, 409)
        d_prot = await r_prot.json()
        self.assertEqual(d_prot.get("code"), "protected_branch")

        # Explicit confirm_protected: true executes non-force push to hardcoded `origin`
        git_svc = self.app[GIT_WORKFLOW_KEY]
        real_run_git = git_svc._run_git
        seen_push_args: list[str] = []

        async def _mock_push_ok(root, args, **kw):
            if args and args[0] == "push":
                seen_push_args.extend(args)
                return 0, "", "pushed ok"
            return await real_run_git(root, args, **kw)

        with (
            mock.patch.object(git_svc, "_get_github_token", return_value=SYNTHETIC_GH_PAT),
            mock.patch.object(git_svc, "_run_git", side_effect=_mock_push_ok),
        ):
            r_ok = await self.client.post(
                "/api/git/push",
                data=json.dumps({"project_id": "git-proj", "confirm_protected": True}),
                cookies=cookies,
                headers=hdrs,
            )
            self.assertEqual(r_ok.status, 200)
            self.assertEqual(seen_push_args, ["push", "-u", "origin", "refs/heads/main:refs/heads/main"])

        # Detached HEAD -> 400 detached_head
        subprocess.run(["git", "checkout", "--detach", "HEAD"], cwd=self.git_proj, check=True, capture_output=True)
        r_det = await self.client.post(
            "/api/git/push",
            data=json.dumps({"project_id": "git-proj", "confirm_protected": True}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_det.status, 400)
        d_det = await r_det.json()
        self.assertEqual(d_det.get("code"), "detached_head")

    # ------------------------------------------------------------------ C5
    async def test_c5_worktree_isolation_degradation_agy_no_project_and_cleanup_safety(self) -> None:
        cookies, csrf = await self._login("admin", TEST_PASS_ADMIN)
        hdrs = self._write_headers(csrf, origin=self.origin)

        # Non-bool worktree -> 400
        for bad_val in ("true", 1, []):
            r = await self.client.post(
                "/api/chat/send",
                data=json.dumps({"prompt": "hi", "project": "git-proj", "worktree": bad_val}),
                cookies=cookies,
                headers=hdrs,
            )
            self.assertEqual(r.status, 400)

        # Safe degradation: non-Git repo -> active=False, reason=not_git_repo, zero .worktrees dir, zero host paths
        r_ng = await self.client.post(
            "/api/chat/send",
            data=json.dumps({"prompt": "hi nongit", "project": "nongit-proj", "worktree": True}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_ng.status, 202)
        d_ng = await r_ng.json()
        self.assertEqual(d_ng["worktree"]["active"], False)
        self.assertEqual(d_ng["worktree"]["reason"], "not_git_repo")
        self.assertFalse((self.nongit_proj / ".worktrees").exists())
        self.assertNotIn(str(self.tmp), json.dumps(d_ng))

        # Safe degradation: unborn HEAD -> active=False, reason=unborn_or_invalid_head, zero .worktrees dir
        r_ub = await self.client.post(
            "/api/chat/send",
            data=json.dumps({"prompt": "hi unborn", "project": "unborn-proj", "worktree": True}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_ub.status, 202)
        d_ub = await r_ub.json()
        self.assertEqual(d_ub["worktree"]["active"], False)
        self.assertEqual(d_ub["worktree"]["reason"], "unborn_or_invalid_head")
        self.assertFalse((self.unborn_proj / ".worktrees").exists())
        self.assertNotIn(str(self.tmp), json.dumps(d_ub))

        # Valid Git repo with worktree=True: creates .worktrees/<wt_id>, writes info/exclude ONLY (never .gitignore)
        self.assertFalse((self.git_proj / ".gitignore").exists())
        r_wt = await self.client.post(
            "/api/chat/send",
            data=json.dumps({"prompt": "implement feature", "project": "git-proj", "worktree": True}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_wt.status, 202)
        d_wt = await r_wt.json()
        wt_meta = d_wt["worktree"]
        self.assertTrue(wt_meta["active"])
        wt_id = wt_meta["worktree_id"]
        self.assertTrue(wt_meta["branch"].startswith("agy-studio/"))
        self.assertNotIn(str(self.tmp), json.dumps(d_wt))
        self.assertFalse((self.git_proj / ".gitignore").exists())
        exclude_txt = (self.git_proj / ".git" / "info" / "exclude").read_text(encoding="utf-8")
        self.assertIn(".worktrees/", exclude_txt)

        wt_dir = self.git_proj / ".worktrees" / wt_id
        self.assertTrue(wt_dir.is_dir())

        # Verify AgySession in worktree mode locks cwd to wt_dir and OMITS `--project`
        spawned_calls: list[tuple[list[str], str]] = []

        class _DummyProc:
            pid = None
            stdin = mock.MagicMock()
            stdout = iter([])
            stderr = iter([])

            def poll(self):
                return 0

        def _fake_popen(cmd, **kw):
            spawned_calls.append((list(cmd), str(kw.get("cwd") or "")))
            return _DummyProc()

        with mock.patch.object(bridge_mod.subprocess, "Popen", side_effect=_fake_popen):
            s_wt = bridge_mod.AgySession(
                None, "auto", None, None, project="git-proj", workdir=str(wt_dir), is_worktree=True
            )
            self.assertEqual(spawned_calls[-1][1], str(wt_dir))
            self.assertNotIn("--project", spawned_calls[-1][0])
            s_main = bridge_mod.AgySession(
                None, "auto", None, None, project="git-proj", workdir=str(self.git_proj), is_worktree=False
            )
            self.assertIn("--project", spawned_calls[-1][0])
            self.assertTrue(s_wt.is_worktree)
            self.assertFalse(s_main.is_worktree)

        # Clear queued job so worktree isn't considered queued-busy during dirty/unmerged checks
        bridge_mod.job_q.cancel_web_turn(d_wt["turn_id"])

        # GET /api/worktrees lists the worktree with zero host paths
        r_list = await self.client.get("/api/worktrees?project_id=git-proj", cookies=cookies)
        self.assertEqual(r_list.status, 200)
        d_list = await r_list.json()
        self.assertEqual(len(d_list["worktrees"]), 1)
        self.assertEqual(d_list["worktrees"][0]["worktree_id"], wt_id)
        self.assertNotIn(str(self.tmp), json.dumps(d_list))

        # Cleanup safety: non-bool force -> 400
        r_bf = await self.client.post(
            f"/api/worktrees/{wt_id}/cleanup",
            data=json.dumps({"project_id": "git-proj", "force": "yes"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_bf.status, 400)

        # Dirty file -> 409 worktree_dirty when force=False
        (wt_dir / "dirty.txt").write_text("uncommitted\n", encoding="utf-8")
        r_dirty = await self.client.post(
            f"/api/worktrees/{wt_id}/cleanup",
            data=json.dumps({"project_id": "git-proj", "force": False}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_dirty.status, 409)
        self.assertEqual((await r_dirty.json()).get("code"), "worktree_dirty")

        # Commit dirty file -> now unmerged commit -> 409 worktree_unmerged when force=False
        subprocess.run(["git", "add", "dirty.txt"], cwd=wt_dir, check=True)
        subprocess.run(["git", "commit", "-m", "wt commit"], cwd=wt_dir, check=True, capture_output=True)
        r_unm = await self.client.post(
            f"/api/worktrees/{wt_id}/cleanup",
            data=json.dumps({"project_id": "git-proj", "force": False}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_unm.status, 409)
        self.assertEqual((await r_unm.json()).get("code"), "worktree_unmerged")

        # Active running turn -> EVEN WITH force=True MUST return 409 session_busy!
        with (
            mock.patch.object(bridge_mod, "turn_running", True),
            mock.patch.object(bridge_mod, "turn_running_worktree_id", wt_id),
        ):
            r_busy = await self.client.post(
                f"/api/worktrees/{wt_id}/cleanup",
                data=json.dumps({"project_id": "git-proj", "force": True}),
                cookies=cookies,
                headers=hdrs,
            )
            self.assertEqual(r_busy.status, 409)
            self.assertEqual((await r_busy.json()).get("code"), "session_busy")

        # Idle + force=True -> 200, removes worktree dir AND deletes agy-studio/<wt_id> branch
        r_clean = await self.client.post(
            f"/api/worktrees/{wt_id}/cleanup",
            data=json.dumps({"project_id": "git-proj", "force": True}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_clean.status, 200)
        d_clean = await r_clean.json()
        self.assertTrue(d_clean["cleaned"])
        self.assertFalse(wt_dir.exists())
        br_check = subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", f"refs/heads/agy-studio/{wt_id}"],
            cwd=self.git_proj,
        )
        self.assertNotEqual(br_check.returncode, 0)

    # ------------------------------------------------------------------ C6
    async def test_c6_bridge_lock_ordering_ast_and_serial_concurrency(self) -> None:
        # 1) Static AST verification of lock hierarchy and zero blocking git under lock
        src = (BRIDGE_DIR / "bridge.py").read_text(encoding="utf-8")
        tree = ast.parse(src, filename="bridge/bridge.py")

        lock_nesting_violations: list[str] = []
        git_under_lock_violations: list[str] = []
        git_call_names = {
            "_run_git",
            "prepare_job_worktree",
            "finalize_job_worktree",
            "cleanup_job_worktree",
            "prepare_studio_worktree",
            "inspect_studio_worktree",
            "cleanup_studio_worktree",
        }

        def _lock_name(ctx_expr: ast.AST) -> str | None:
            if isinstance(ctx_expr, ast.Name) and ctx_expr.id in ("state_lock", "session_lock"):
                return ctx_expr.id
            if isinstance(ctx_expr, ast.Attribute) and ctx_expr.attr == "_cond":
                return "job_q._cond"
            return None

        def _walk(node: ast.AST, active_locks: list[str], func_name: str) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # New function definition starts its own dynamic lock stack
                for stmt in node.body:
                    _walk(stmt, [], node.name)
                return
            if isinstance(node, ast.With):
                added: list[str] = []
                for item in node.items:
                    lname = _lock_name(item.context_expr)
                    if lname:
                        if lname == "session_lock" and "state_lock" in active_locks:
                            lock_nesting_violations.append(f"{func_name}:L{node.lineno} state_lock->session_lock")
                        if (lname == "session_lock" and "job_q._cond" in active_locks) or (
                            lname == "job_q._cond" and "session_lock" in active_locks
                        ):
                            lock_nesting_violations.append(f"{func_name}:L{node.lineno} job_q._cond<->session_lock")
                        added.append(lname)
                next_locks = active_locks + added
                for stmt in node.body:
                    _walk(stmt, next_locks, func_name)
                return
            if isinstance(node, ast.Call) and ("state_lock" in active_locks or "session_lock" in active_locks):
                callee = ""
                if isinstance(node.func, ast.Name):
                    callee = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    callee = node.func.attr
                if callee in git_call_names:
                    git_under_lock_violations.append(f"{func_name}:L{node.lineno} {callee} under {active_locks}")
                elif callee in ("run", "Popen", "check_output", "check_call"):
                    if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)) and node.args[0].elts:
                        first = node.args[0].elts[0]
                        if isinstance(first, ast.Constant) and first.value == "git":
                            git_under_lock_violations.append(
                                f"{func_name}:L{node.lineno} subprocess git under {active_locks}"
                            )
            for child in ast.iter_child_nodes(node):
                _walk(child, active_locks, func_name)

        _walk(tree, [], "<module>")
        self.assertEqual(lock_nesting_violations, [], f"Lock nesting violations: {lock_nesting_violations}")
        self.assertEqual(git_under_lock_violations, [], f"Git-under-lock violations: {git_under_lock_violations}")

        # 2) Runtime serialization via ConversationLease for same cid across turn / undo / cleanup
        cid = "conv_c6_serial_1234"
        wt_prep = bot_bus.prepare_studio_worktree(str(self.git_proj), "wt-c6serial", project_id="git-proj")
        self.assertTrue(wt_prep["active"])
        wt_prep["cid"] = cid
        wt_prep["scope_key"] = f"web:{ADMIN_UID}:{cid}"
        bridge_mod.state["worktrees_by_cid"][cid] = dict(wt_prep)
        bot_bus.upsert_studio_worktree_meta("wt-c6serial", wt_prep, bus_dir=str(self.bus_dir))

        # Seed a checkpoint on the same cid
        wt_file = Path(wt_prep["path"]) / "app.py"
        wt_file.write_text("v = 1\n", encoding="utf-8")
        pre_sha = bridge_mod._undo_store_file_blob(str(wt_file))
        wt_file.write_text("v = 2\n", encoding="utf-8")
        post_sha = bridge_mod._undo_store_file_blob(str(wt_file))
        bridge_mod.state["scopes"][f"web:{ADMIN_UID}:{cid}"] = {
            "undo_stack": [{
                "id": "uc6top01",
                "ts": int(time.time()),
                "workdir": wt_prep["path"],
                "conv": cid,
                "prompt": "c6 test",
                "truncated": False,
                "changes": [{"path": "app.py", "action": "modified", "pre_sha1": pre_sha, "post_sha1": post_sha}],
            }],
            "redo_stack": [],
            "worktree": dict(wt_prep),
        }

        lease = studio_ipc.ConversationLease.try_acquire(self.bus_dir, cid)
        self.assertIsNotNone(lease)
        try:
            sc_enq, d_enq = bridge_mod._studio_ipc_enqueue_turn({"user_id": ADMIN_UID, "cid": cid, "prompt": "hi"})
            self.assertEqual(sc_enq, 409)
            self.assertEqual(d_enq.get("code"), "session_busy")

            sc_undo, d_undo = bridge_mod._studio_ipc_apply_undo({"entry_id": "uc6top01", "cid": cid, "project_id": "git-proj"})
            self.assertEqual(sc_undo, 409)
            self.assertEqual(d_undo.get("code"), "session_busy")

            sc_cln, d_cln = bridge_mod._studio_ipc_cleanup_worktree({
                "worktree_id": "wt-c6serial",
                "project_id": "git-proj",
                "force": True,
            })
            self.assertEqual(sc_cln, 409)
            self.assertEqual(d_cln.get("code"), "session_busy")
        finally:
            assert lease is not None
            lease.release()

        # After lease release, force cleanup succeeds
        sc_ok, d_ok = bridge_mod._studio_ipc_cleanup_worktree({
            "worktree_id": "wt-c6serial",
            "project_id": "git-proj",
            "force": True,
        })
        self.assertEqual(sc_ok, 200)
        self.assertTrue(d_ok["cleaned"])

    # ------------------------------------------------------------------ C7
    async def test_c7_checkpoint_diff_security_and_worktree_undo_redo(self) -> None:
        cookies, csrf = await self._login("admin", TEST_PASS_ADMIN)
        hdrs = self._write_headers(csrf, origin=self.origin)

        # Create worktree for git-proj
        wt_prep = bot_bus.prepare_studio_worktree(str(self.git_proj), "wt-c7undo", project_id="git-proj")
        self.assertTrue(wt_prep["active"])
        wt_dir = Path(wt_prep["path"])
        cid = "conv_c7_worktree_01"

        # Prepare pre/post blobs: text file (with secret to verify redaction), binary file, sensitive .env, and large file (>256 KiB)
        f_code = wt_dir / "mod.py"
        f_code.write_text("alpha = 1\nbeta = 2\n", encoding="utf-8")
        pre_code = bridge_mod._undo_store_file_blob(str(f_code))
        f_code.write_text(f"alpha = 1\nbeta = 3\ngamma = '{SYNTHETIC_GH_PAT}'\n", encoding="utf-8")
        post_code = bridge_mod._undo_store_file_blob(str(f_code))

        f_bin = wt_dir / "img.bin"
        f_bin.write_bytes(b"\x89PNG\r\n\x00\x01\x02RAW_BINARY_PAYLOAD")
        post_bin = bridge_mod._undo_store_file_blob(str(f_bin))

        f_env = wt_dir / ".env"
        f_env.write_text("SECRET=should_not_appear\n", encoding="utf-8")
        post_env = bridge_mod._undo_store_file_blob(str(f_env))

        f_big = wt_dir / "big.txt"
        f_big.write_text("A" * 300_000 + "\n", encoding="utf-8")
        post_big = bridge_mod._undo_store_file_blob(str(f_big))

        skey = f"web:{ADMIN_UID}:{cid}"
        bridge_mod.state["scopes"][skey] = {
            "undo_stack": [
                {
                    "id": "uc7older1",
                    "ts": int(time.time()) - 20,
                    "workdir": str(wt_dir),
                    "conv": cid,
                    "prompt": "older turn",
                    "truncated": False,
                    "changes": [{"path": "mod.py", "action": "modified", "pre_sha1": pre_code, "post_sha1": post_code}],
                },
                {
                    "id": "uc7top001",
                    "ts": int(time.time()) - 10,
                    "workdir": str(wt_dir),
                    "conv": cid,
                    "prompt": "worktree turn diff",
                    "truncated": False,
                    "changes": [
                        {"path": "mod.py", "action": "modified", "pre_sha1": pre_code, "post_sha1": post_code},
                        {"path": "img.bin", "action": "created", "post_sha1": post_bin},
                        {"path": ".env", "action": "created", "post_sha1": post_env},
                        {"path": "big.txt", "action": "created", "post_sha1": post_big},
                    ],
                },
            ],
            "redo_stack": [],
        }

        # Bad entry_id format -> 400
        r_bad_id = await self.client.get("/api/undo/checkpoints/..%2Fevil/diff", cookies=cookies)
        self.assertIn(r_bad_id.status, (400, 404))
        r_bad_id2 = await self.client.get("/api/undo/checkpoints/bad$id/diff", cookies=cookies)
        self.assertEqual(r_bad_id2.status, 400)

        # Cross-cid -> 403; cross-project -> 403
        r_xcid = await self.client.get("/api/undo/checkpoints/uc7top001/diff?cid=other_cid_999999", cookies=cookies)
        self.assertEqual(r_xcid.status, 403)
        r_xproj = await self.client.get("/api/undo/checkpoints/uc7top001/diff?project_id=nongit-proj", cookies=cookies)
        self.assertEqual(r_xproj.status, 403)

        # Valid admin diff request: checks redaction, binary zero raw bytes, .env filtered, 256 KiB truncation, +added/-deleted
        r_diff = await self.client.get(
            f"/api/undo/checkpoints/uc7top001/diff?cid={cid}&project_id=git-proj",
            cookies=cookies,
        )
        self.assertEqual(r_diff.status, 200)
        d_diff = await r_diff.json()
        self.assertEqual(d_diff["project_id"], "git-proj")
        self.assertEqual(d_diff["worktree_id"], "wt-c7undo")
        self.assertTrue(d_diff["truncated"])
        self.assertLessEqual(len(d_diff["diff"].encode("utf-8")), 256 * 1024)
        self.assertNotIn(SYNTHETIC_GH_PAT, json.dumps(d_diff))
        self.assertNotIn("RAW_BINARY_PAYLOAD", json.dumps(d_diff))
        self.assertNotIn("should_not_appear", json.dumps(d_diff))
        paths_seen = [f["path"] for f in d_diff["files"]]
        self.assertNotIn(".env", paths_seen)
        mod_f = next(f for f in d_diff["files"] if f["path"] == "mod.py")
        self.assertEqual(mod_f["added"], 2)
        self.assertEqual(mod_f["deleted"], 1)
        bin_f = next(f for f in d_diff["files"] if f["path"] == "img.bin")
        self.assertTrue(bin_f["is_binary"])
        self.assertEqual(bin_f["diff"], "")

        # Invalid non-40-hex sha1 -> 400
        bridge_mod.state["scopes"]["bad_sha_scope"] = {
            "undo_stack": [{
                "id": "ubadsha01",
                "ts": int(time.time()),
                "workdir": str(wt_dir),
                "conv": cid,
                "prompt": "bad sha",
                "changes": [{"path": "mod.py", "action": "modified", "pre_sha1": "not-a-sha1", "post_sha1": post_code}],
            }],
            "redo_stack": [],
        }
        r_bsha = await self.client.get("/api/undo/checkpoints/ubadsha01/diff", cookies=cookies)
        self.assertEqual(r_bsha.status, 400)
        bridge_mod.state["scopes"].pop("bad_sha_scope", None)

        # Sibling prefix spoofing `<proj_root>-evil/.worktrees/wt-evil1` MUST return 403 workdir_not_allowed!
        bridge_mod.state["scopes"]["evil_scope"] = {
            "undo_stack": [{
                "id": "uevilwt01",
                "ts": int(time.time()),
                "workdir": str(self.evil_sibling / ".worktrees" / "wt-evil1"),
                "conv": cid,
                "prompt": "evil prefix",
                "changes": [{"path": "mod.py", "action": "modified", "pre_sha1": pre_code, "post_sha1": post_code}],
            }],
            "redo_stack": [],
        }
        r_evil_diff = await self.client.get("/api/undo/checkpoints/uevilwt01/diff", cookies=cookies)
        self.assertEqual(r_evil_diff.status, 403)
        self.assertEqual((await r_evil_diff.json()).get("code"), "workdir_not_allowed")

        r_evil_apply = await self.client.post(
            "/api/undo/apply",
            data=json.dumps({"entry_id": "uevilwt01", "cid": cid}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_evil_apply.status, 403)
        self.assertEqual((await r_evil_apply.json()).get("code"), "workdir_not_allowed")
        bridge_mod.state["scopes"].pop("evil_scope", None)

        # Worktree Undo/Redo: non-top -> 409; external edit -> 409 conflict; clean undo -> restores worktree ONLY (main repo untouched)
        r_nontop = await self.client.post(
            "/api/undo/apply",
            data=json.dumps({"entry_id": "uc7older1", "cid": cid, "project_id": "git-proj"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_nontop.status, 409)
        self.assertEqual((await r_nontop.json()).get("code"), "not_stack_top")

        # Keep clean single-file top checkpoint for undo/redo verification
        bridge_mod.state["scopes"][skey]["undo_stack"][-1]["changes"] = [
            {"path": "mod.py", "action": "modified", "pre_sha1": pre_code, "post_sha1": post_code}
        ]
        # External modification causes 409 conflict
        f_code.write_text("external edit\n", encoding="utf-8")
        r_conf = await self.client.post(
            "/api/undo/apply",
            data=json.dumps({"entry_id": "uc7top001", "cid": cid, "project_id": "git-proj", "force": False}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_conf.status, 409)
        self.assertEqual((await r_conf.json()).get("code"), "conflict")

        # Restore expected post content and apply clean undo -> restores worktree mod.py, main repo untouched!
        f_code.write_text(f"alpha = 1\nbeta = 3\ngamma = '{SYNTHETIC_GH_PAT}'\n", encoding="utf-8")
        r_undo = await self.client.post(
            "/api/undo/apply",
            data=json.dumps({"entry_id": "uc7top001", "cid": cid, "project_id": "git-proj"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_undo.status, 200)
        d_undo = await r_undo.json()
        self.assertEqual(d_undo["worktree_id"], "wt-c7undo")
        self.assertEqual(f_code.read_text(encoding="utf-8"), "alpha = 1\nbeta = 2\n")
        self.assertFalse((self.git_proj / "mod.py").exists())

        # Redo restores post content in worktree
        r_redo = await self.client.post(
            "/api/undo/redo",
            data=json.dumps({"entry_id": "uc7top001", "cid": cid, "project_id": "git-proj"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_redo.status, 200)
        self.assertIn("beta = 3", f_code.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------ C8
    def test_c8_ui_race_demo_parity_and_export_registration(self) -> None:
        panel_src = (REPO_ROOT / "webui" / "src" / "components" / "FilesDiffPanel.tsx").read_text(encoding="utf-8")
        ws_src = (REPO_ROOT / "webui" / "src" / "components" / "WorkspaceView.tsx").read_text(encoding="utf-8")
        mock_src = (REPO_ROOT / "webui" / "src" / "demo" / "mockApi.ts").read_text(encoding="utf-8")

        # Monotonic seqRef + projectIdRef + worktreeIdRef guards
        for ref_name in (
            "treeSeqRef",
            "diffSeqRef",
            "undoSeqRef",
            "ckptDiffSeqRef",
            "worktreesSeqRef",
            "gitStatusSeqRef",
            "projectIdRef",
            "worktreeIdRef",
        ):
            self.assertIn(ref_name, panel_src)

        # Safe HTTPS external PR link guard + readonly gate
        self.assertIn("isSafeHttpsUrl", panel_src)
        self.assertIn('rel="noopener noreferrer"', panel_src)
        self.assertIn("isReadonly", panel_src)

        # WorkspaceView worktree toggle & linkage to FilesDiffPanel
        self.assertIn("selectedWorktreeId", ws_src)
        self.assertIn("worktreeEnabled", ws_src)

        # Demo mock parity for all new APIs
        for fn_name in (
            "fetchCheckpointDiff",
            "fetchWorktrees",
            "cleanupWorktree",
            "fetchGitStatus",
            "gitCommit",
            "gitPush",
            "gitCreatePr",
        ):
            self.assertIn(f"export async function {fn_name}", mock_src)

        # Public export registration (private source repo only; public repo omits scripts/export_public.py)
        if (SCRIPTS_DIR / "export_public.py").is_file():
            import export_public  # noqa: E402

            self.assertIn("tests/test_studio_coding_trio.py", export_public.CORE_SYNC_EXACT)
            self.assertTrue(export_public.is_public_core("studio/git_workflow.py"))
            self.assertTrue(export_public.is_public_core("tests/test_studio_coding_trio.py"))

    # ------------------------------------------------------------------ Round 2 Remediation Counterexamples
    async def test_c3_pre_staged_file_secret_rollback_zero_index_residue(self) -> None:
        """P0 C2/C3: Pre-staged file later edited with a secret must atomically restore index on 403."""
        cookies, csrf = await self._login("admin", TEST_PASS_ADMIN)
        hdrs = self._write_headers(csrf, origin=self.origin)

        app_file = self.git_proj / "app.py"
        app_file.write_text("SAFE_VALUE = 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=self.git_proj, check=True)
        expected_cached_diff = subprocess.check_output(
            ["git", "diff", "--cached"], cwd=self.git_proj, text=True
        )
        self.assertIn("+SAFE_VALUE = 1", expected_cached_diff)

        # Append a synthetic GitHub PAT to the already-staged file in the working tree
        app_file.write_text(f"SAFE_VALUE = 1\nLEAK = '{SYNTHETIC_GH_PAT}'\n", encoding="utf-8")

        for payload in (
            {"project_id": "git-proj", "message": "all mode leak", "stage_mode": "all"},
            {"project_id": "git-proj", "message": "paths mode leak", "stage_mode": "paths", "paths": ["app.py"]},
        ):
            r = await self.client.post(
                "/api/git/commit",
                data=json.dumps(payload),
                cookies=cookies,
                headers=hdrs,
            )
            self.assertEqual(r.status, 403, f"expected 403 for {payload}")
            body = await r.json()
            self.assertEqual(body.get("code"), "secret_detected")
            cached_after = subprocess.check_output(
                ["git", "diff", "--cached"], cwd=self.git_proj, text=True
            )
            self.assertEqual(cached_after, expected_cached_diff)
            self.assertNotIn(SYNTHETIC_GH_PAT, cached_after)
            # Working tree file must remain untouched
            self.assertIn(SYNTHETIC_GH_PAT, app_file.read_text(encoding="utf-8"))

    async def test_c2_stage_mode_paths_rejects_wildcards_and_directories(self) -> None:
        """P0 C2: stage_mode=paths must reject glob wildcards, magic pathspecs, and directories with 400."""
        cookies, csrf = await self._login("admin", TEST_PASS_ADMIN)
        hdrs = self._write_headers(csrf, origin=self.origin)

        sub_dir = self.git_proj / "subdir"
        sub_dir.mkdir(exist_ok=True)
        (sub_dir / "nested.txt").write_text("nested\n", encoding="utf-8")
        (self.git_proj / "other.txt").write_text("other\n", encoding="utf-8")
        (self.git_proj / ".env").write_text("SECRET=1\n", encoding="utf-8")

        cnt_before = subprocess.check_output(
            ["git", "rev-list", "--count", "HEAD"], cwd=self.git_proj, text=True
        ).strip()

        for bad_paths in (["*"], [".e*"], [":(glob)*.txt"], ["subdir"], ["subdir/"]):
            r = await self.client.post(
                "/api/git/commit",
                data=json.dumps({
                    "project_id": "git-proj",
                    "message": "bad pathspec",
                    "stage_mode": "paths",
                    "paths": bad_paths,
                }),
                cookies=cookies,
                headers=hdrs,
            )
            self.assertEqual(r.status, 400, f"expected 400 for paths={bad_paths}")
            staged = subprocess.check_output(
                ["git", "diff", "--cached", "--name-only"], cwd=self.git_proj, text=True
            ).strip()
            self.assertEqual(staged, "")

        cnt_after = subprocess.check_output(
            ["git", "rev-list", "--count", "HEAD"], cwd=self.git_proj, text=True
        ).strip()
        self.assertEqual(cnt_before, cnt_after)
        (self.git_proj / ".env").unlink()

    async def test_c5_worktree_compact_preserves_no_project_and_warm_session(self) -> None:
        """P0 C5: Compact on a worktree session must pass is_worktree=True, omit --project, and keep warm session."""
        wt_prep = bot_bus.prepare_studio_worktree(str(self.git_proj), "wt-cmpct01", project_id="git-proj")
        self.assertTrue(wt_prep["active"])
        wt_dir = Path(wt_prep["path"])
        cid = "conv_wt_compact_01"
        skey = f"web:{ADMIN_UID}:{cid}"

        spawned_calls: list[tuple[list[str], str]] = []

        class _DummyCompactProc:
            pid = None
            stdin = mock.MagicMock()
            stdout = iter([
                json.dumps({"event": "result", "status": "SUCCESS", "conversation_id": cid}) + "\n"
            ])
            stderr = iter([])

            def poll(self):
                return None

        def _fake_popen(cmd, **kw):
            spawned_calls.append((list(cmd), str(kw.get("cwd") or "")))
            return _DummyCompactProc()

        # 1) Cold spawn via _execute_compact_on_session(..., is_worktree=True) omits --project & locks cwd=wt_dir
        with (
            mock.patch.object(bridge_mod.subprocess, "Popen", side_effect=_fake_popen),
            mock.patch.object(bridge_mod, "get_transcript_line_count", return_value=10),
        ):
            ok, _dur, err = bridge_mod._execute_compact_on_session(
                skey, cid, "auto", None, None, "git-proj", str(wt_dir),
                is_worktree=True,
            )
            self.assertTrue(ok, f"compact failed: {err}")
            self.assertEqual(len(spawned_calls), 1)
            self.assertEqual(spawned_calls[0][1], str(wt_dir))
            self.assertNotIn("--project", spawned_calls[0][0])

            # 2) Subsequent compact with warm worktree session in pool MUST reuse it (zero eviction/respawn)
            warm_sess = bridge_mod._session_pool.get(skey)
            self.assertIsNotNone(warm_sess)
            self.assertTrue(warm_sess.is_worktree)
            with (
                mock.patch.object(warm_sess, "is_alive", return_value=True),
                mock.patch.object(warm_sess, "send_user_prompt"),
                mock.patch.object(
                    warm_sess,
                    "next_event",
                    side_effect=[{"event": "result", "result": {"status": "SUCCESS", "conversation_id": cid}}],
                ),
                mock.patch.object(warm_sess, "close") as m_close,
            ):
                ok2, _dur2, err2 = bridge_mod._execute_compact_on_session(
                    skey, cid, "auto", None, None, "git-proj", str(wt_dir),
                    is_worktree=True,
                )
                self.assertTrue(ok2, f"warm compact failed: {err2}")
                self.assertEqual(len(spawned_calls), 1, "warm worktree session must not be evicted/respawned")
                m_close.assert_not_called()

        # 3) _maybe_post_turn_auto_compact forwards is_worktree=True
        with (
            mock.patch.object(bridge_mod, "should_auto_compact", return_value=(True, {"raw_ctx_tokens": 90000, "total_lines": 50})),
            mock.patch.object(bridge_mod, "LiveDraftStreamer"),
            mock.patch.object(bridge_mod, "get_context_stats", return_value={"just_compacted": True, "ctx_tokens": 14000}),
            mock.patch.object(bridge_mod, "tg_send_in_route"),
            mock.patch.object(bridge_mod, "_execute_compact_on_session", return_value=(True, 0.5, "")) as m_exec,
        ):
            bridge_mod._maybe_post_turn_auto_compact(
                ADMIN_UID, cid, "auto", None, None,
                project="git-proj", workdir=str(wt_dir), scope_key=skey, is_worktree=True,
            )
            m_exec.assert_called_once()
            self.assertTrue(m_exec.call_args.kwargs.get("is_worktree"))

    async def test_c1_nongit_push_and_pr_record_audit_log(self) -> None:
        """P1 C1: Non-Git POST /api/git/push and POST /api/git/pr must return 400 and append audit entries."""
        cookies, csrf = await self._login("admin", TEST_PASS_ADMIN)
        hdrs = self._write_headers(csrf, origin=self.origin)

        before_lines = (
            self.audit_log.read_text(encoding="utf-8").splitlines()
            if self.audit_log.exists()
            else []
        )

        r_push = await self.client.post(
            "/api/git/push",
            data=json.dumps({"project_id": "nongit-proj"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_push.status, 400)

        r_pr = await self.client.post(
            "/api/git/pr",
            data=json.dumps({"project_id": "nongit-proj", "title": "Non-git PR"}),
            cookies=cookies,
            headers=hdrs,
        )
        self.assertEqual(r_pr.status, 400)

        after_lines = self.audit_log.read_text(encoding="utf-8").splitlines()
        new_records = [json.loads(ln) for ln in after_lines[len(before_lines) :]]
        push_rec = [rec for rec in new_records if rec.get("action") == "git.push"]
        pr_rec = [rec for rec in new_records if rec.get("action") == "git.pr"]
        self.assertTrue(
            any(rec.get("status_code") == 400 and rec.get("outcome") == "denied_not_git" and rec.get("target_id") == "nongit-proj" for rec in push_rec),
            f"missing git.push denied_not_git audit record: {new_records}",
        )
        self.assertTrue(
            any(rec.get("status_code") == 400 and rec.get("outcome") == "denied_not_git" and rec.get("target_id") == "nongit-proj" for rec in pr_rec),
            f"missing git.pr denied_not_git audit record: {new_records}",
        )

    async def test_c5_missing_or_symlink_worktree_falls_back_to_project_dir_no_ghost(self) -> None:
        """P1 C5: Vanished or symlinked worktree at run_agy start must fall back to project workdir (not global WORKDIR) and never re-register ghost metadata."""
        global_default_wd = self.tmp / "global-default-wd"
        global_default_wd.mkdir(parents=True, exist_ok=True)
        wt_prep = bot_bus.prepare_studio_worktree(str(self.git_proj), "wt-vanish01", project_id="git-proj")
        self.assertTrue(wt_prep["active"])
        wt_dir = Path(wt_prep["path"])

        # Remove worktree directory right before run_agy starts (simulating cleanup/vanish race)
        shutil.rmtree(wt_dir)
        self.assertFalse(wt_dir.exists())

        cid = "conv_wt_vanish_01"
        skey = f"web:{ADMIN_UID}:{cid}"
        captured_acq: list[dict[str, object]] = []
        captured_events: list[tuple[str, dict[str, object]]] = []

        class _FakeDoneSess:
            def __init__(self, c: str) -> None:
                self.cid = c
                self.last_used = time.time()
                self._events = [
                    {
                        "event": "result",
                        "result": {
                            "status": "SUCCESS",
                            "conversation_id": c,
                            "response": "fallback ok",
                            "usage": {},
                        },
                    }
                ]

            def send_user_prompt(self, *_a, **_kw) -> None:
                return None

            def next_event(self, timeout=0.25):
                return self._events.pop(0) if self._events else {"event": "__eof__"}

            def get_stderr_text(self) -> str:
                return ""

        def _fake_acquire(scope_key, conv, mode, model, effort, project, workdir, **kw):
            captured_acq.append({"workdir": workdir, "project": project, "is_worktree": kw.get("is_worktree", False)})
            return _FakeDoneSess(conv or cid), False

        with (
            mock.patch.object(bridge_mod, "WORKDIR", str(global_default_wd)),
            mock.patch.object(bridge_mod, "_acquire_session", side_effect=_fake_acquire),
            mock.patch.object(bridge_mod, "_maybe_post_turn_auto_compact"),
            mock.patch.object(bridge_mod, "LiveDraftStreamer"),
            mock.patch.object(bridge_mod, "get_transcript_line_count", return_value=0),
            mock.patch.object(bridge_mod, "snapshot_workspace_files", return_value={}),
            mock.patch.object(bridge_mod, "snapshot_undo_manifest", return_value=None),
        ):
            bridge_mod.run_agy(
                ADMIN_UID,
                "hello fallback",
                scope_key=skey,
                user_id=ADMIN_UID,
                event_sink=lambda ev, payload: captured_events.append((ev, dict(payload))),
                override_project="git-proj",
                override_workdir=str(self.git_proj),
                override_cid=cid,
                override_worktree_info=dict(wt_prep),
                web_turn_id="wturn_vanish_01",
                sync_tg=False,
            )

        self.assertEqual(len(captured_acq), 1)
        self.assertEqual(captured_acq[0]["workdir"], os.path.realpath(str(self.git_proj)))
        self.assertNotEqual(captured_acq[0]["workdir"], os.path.realpath(str(global_default_wd)))
        self.assertFalse(captured_acq[0]["is_worktree"])
        self.assertNotIn(cid, bridge_mod.state.get("worktrees_by_cid", {}))
        self.assertIsNone(bridge_mod.state.get("scopes", {}).get(skey, {}).get("worktree"))
        self.assertNotIn("wt-vanish01", bot_bus.load_studio_worktrees(str(self.bus_dir)))
        done_evs = [p for ev, p in captured_events if ev == "done"]
        self.assertEqual(len(done_evs), 1)
        self.assertEqual(done_evs[0].get("worktree"), {"active": False, "reason": "worktree_missing"})

        # Also test symlink replacement race at run_agy start -> falls back to project workdir, zero ghost
        os.symlink(str(self.outside_dir), str(wt_dir))
        cid_sym = "conv_wt_symlink_02"
        skey_sym = f"web:{ADMIN_UID}:{cid_sym}"
        captured_acq.clear()
        captured_events.clear()
        with (
            mock.patch.object(bridge_mod, "WORKDIR", str(global_default_wd)),
            mock.patch.object(bridge_mod, "_acquire_session", side_effect=_fake_acquire),
            mock.patch.object(bridge_mod, "_maybe_post_turn_auto_compact"),
            mock.patch.object(bridge_mod, "LiveDraftStreamer"),
            mock.patch.object(bridge_mod, "get_transcript_line_count", return_value=0),
            mock.patch.object(bridge_mod, "snapshot_workspace_files", return_value={}),
            mock.patch.object(bridge_mod, "snapshot_undo_manifest", return_value=None),
        ):
            bridge_mod.run_agy(
                ADMIN_UID,
                "hello symlink fallback",
                scope_key=skey_sym,
                user_id=ADMIN_UID,
                event_sink=lambda ev, payload: captured_events.append((ev, dict(payload))),
                override_project="git-proj",
                override_workdir=str(self.git_proj),
                override_cid=cid_sym,
                override_worktree_info=dict(wt_prep),
                web_turn_id="wturn_symlink_02",
                sync_tg=False,
            )
        wt_dir.unlink()
        self.assertEqual(len(captured_acq), 1)
        self.assertEqual(captured_acq[0]["workdir"], os.path.realpath(str(self.git_proj)))
        self.assertFalse(captured_acq[0]["is_worktree"])
        self.assertNotIn(cid_sym, bridge_mod.state.get("worktrees_by_cid", {}))
        self.assertNotIn("wt-vanish01", bot_bus.load_studio_worktrees(str(self.bus_dir)))
        done_sym_evs = [p for ev, p in captured_events if ev == "done"]
        self.assertEqual(len(done_sym_evs), 1)
        self.assertEqual(done_sym_evs[0].get("worktree"), {"active": False, "reason": "worktree_missing"})

    def test_c6_concurrent_studio_worktrees_registry_atomic_rmw(self) -> None:
        """P1 C6: Concurrent upsert/remove on studio_worktrees.json under single flock must have zero lost updates."""
        total_keep = 16
        total_del = 8
        for i in range(total_del):
            bot_bus.upsert_studio_worktree_meta(
                f"wt-rm{i:02d}",
                {"active": True, "project_id": "git-proj", "branch": f"agy-studio/wt-rm{i:02d}"},
                bus_dir=str(self.bus_dir),
            )

        barrier = threading.Barrier(total_keep + total_del)
        errors: list[BaseException] = []

        def _worker_upsert(idx: int) -> None:
            try:
                barrier.wait(timeout=5.0)
                bot_bus.upsert_studio_worktree_meta(
                    f"wt-kp{idx:02d}",
                    {"active": True, "project_id": "git-proj", "branch": f"agy-studio/wt-kp{idx:02d}"},
                    bus_dir=str(self.bus_dir),
                )
            except BaseException as exc:
                errors.append(exc)

        def _worker_remove(idx: int) -> None:
            try:
                barrier.wait(timeout=5.0)
                bot_bus.remove_studio_worktree_meta(f"wt-rm{idx:02d}", bus_dir=str(self.bus_dir))
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker_upsert, args=(i,)) for i in range(total_keep)] + [
            threading.Thread(target=_worker_remove, args=(i,)) for i in range(total_del)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15.0)

        self.assertEqual(errors, [])
        final_reg = bot_bus.load_studio_worktrees(str(self.bus_dir))
        for i in range(total_keep):
            self.assertIn(f"wt-kp{i:02d}", final_reg, f"lost concurrent upsert wt-kp{i:02d}")
        for i in range(total_del):
            self.assertNotIn(f"wt-rm{i:02d}", final_reg, f"stale removed entry wt-rm{i:02d}")


if __name__ == "__main__":
    unittest.main()
