#!/usr/bin/env python3
"""Phase B M1 Contract Tests — Workspace Files, Git Diff & Single-Writer Undo/Redo (`PB-C1`, `PB-C2`, `PB-C7`, `PB-C8`).

Runs completely isolated in temporary directories with real in-process AF_UNIX
`StudioIPCServer` and aiohttp `TestClient` (zero real browsers, zero systemd
mutations, zero host state changes).
"""

from __future__ import annotations

import ast
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import aiohttp
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
from studio.server import create_app  # noqa: E402

BOT_TOKEN_TEST = "123456789:EXAMPLE_M1_FILES_TOKEN_0001"
ADMIN_UID = 111111111
READONLY_UID = 222222222
TEST_BOT_HANDLE = "example_files_bot"
TEST_PASS_ADMIN = "EXAMPLE_ADMIN_PASS_M1"
TEST_PASS_RO = "EXAMPLE_RO_PASS_M1"
TEST_PASS_FORCE = "EXAMPLE_FORCE_PASS_M1"


def _write_env(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _uds_http_request(
    sock_path: Path,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    class _UnixHTTPConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(str(sock_path))
            self.sock = s

    conn = _UnixHTTPConnection("localhost")
    try:
        try:
            conn.request(method, path, body=body, headers=headers or {})
        except (BrokenPipeError, ConnectionResetError):
            if conn.sock is None:
                raise
        resp = conn.getresponse()
        raw = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, hdrs, raw
    finally:
        conn.close()


class _WorkspaceFilesBaseTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_pb_m1_files_")
        self.tmp = Path(self._td.name)
        self.config_dir = self.tmp / "studio-config"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bot_bus"
        self.projects_dir = self.tmp / "projects"
        self.proj_dir = self.tmp / "repos" / "safe-proj"
        self.proj2_dir = self.tmp / "repos" / "other-proj"
        self.outside_dir = self.tmp / "outside-secret"
        self.audit_log = self.config_dir / "audit.jsonl"

        for d in (
            self.config_dir,
            self.bridge_dir,
            self.bus_dir / "jobs",
            self.bus_dir / "inbox",
            self.projects_dir,
            self.proj_dir,
            self.proj2_dir,
            self.outside_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

        (self.outside_dir / "secret.txt").write_text("TOP_SECRET_OUTSIDE_DATA\n", encoding="utf-8")

        (self.projects_dir / "safe-proj.json").write_text(
            json.dumps({
                "id": "safe-proj",
                "name": "Safe Project",
                "projectResources": {
                    "resources": [{"folderUri": f"file://{self.proj_dir}"}]
                },
            }),
            encoding="utf-8",
        )
        (self.projects_dir / "other-proj.json").write_text(
            json.dumps({
                "id": "other-proj",
                "name": "Other Project",
                "projectResources": {
                    "resources": [{"folderUri": f"file://{self.proj2_dir}"}]
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
        users_map = {
            "admin_user": {
                "username": "admin_user",
                "password_hash": hash_password_scrypt(TEST_PASS_ADMIN),
                "role": "admin",
                "bot": "main",
                "user_id": ADMIN_UID,
                "enabled": True,
                "must_change_password": False,
                "password_version": 1,
                "created_at": now_i,
                "updated_at": now_i,
            },
            "ro_user": {
                "username": "ro_user",
                "password_hash": hash_password_scrypt(TEST_PASS_RO),
                "role": "readonly",
                "bot": "main",
                "user_id": READONLY_UID,
                "enabled": True,
                "must_change_password": False,
                "password_version": 1,
                "created_at": now_i,
                "updated_at": now_i,
            },
            "force_user": {
                "username": "force_user",
                "password_hash": hash_password_scrypt(TEST_PASS_FORCE),
                "role": "admin",
                "bot": "main",
                "user_id": ADMIN_UID,
                "enabled": True,
                "must_change_password": True,
                "password_version": 1,
                "created_at": now_i,
                "updated_at": now_i,
            },
        }
        save_users_file_atomic(self.config_dir / "users.json", users_map)

        now = time.time()
        (self.bus_dir / "roster.json").write_text(
            json.dumps({
                "version": 1,
                "bots": {
                    TEST_BOT_HANDLE: {
                        "handle": TEST_BOT_HANDLE,
                        "display_name": "Example Files Bot",
                        "role": "worker",
                        "pid": os.getpid(),
                        "last_seen": now,
                        "busy": False,
                        "active_model": "gemini-3.8-flash",
                        "default_project": "safe-proj",
                    },
                },
            }),
            encoding="utf-8",
        )

        self.auth = StudioAuthManager(
            config_dir=self.config_dir,
            bridge_dir=self.bridge_dir,
            auth_mode="password",
        )
        self.sources = StudioDataSources(
            bus_dir=self.bus_dir,
            schedules_file=self.tmp / "schedules.json",
            projects_dir=self.projects_dir,
            cost_ledger_file=self.tmp / "cost_ledger.json",
            cost_config_file=self.tmp / "cost_config.json",
            quota_cache_file=self.tmp / "quota.json",
            brain_root=self.tmp / "brain",
            summaries_db=self.tmp / "summaries.db",
            meta_file=self.tmp / "meta.json",
        )
        self.app = create_app(
            auth_mgr=self.auth,
            data_sources=self.sources,
            revocation_check_interval=0.1,
            audit_log_path=self.audit_log,
            sse_keepalive_interval=5.0,
            event_hub_max_events=16,
            event_watcher_interval=0.0,
        )
        self.server = TestServer(self.app)
        self.client = TestClient(self.server, cookie_jar=aiohttp.DummyCookieJar())
        await self.client.start_server()
        self._ipc_servers: list[studio_ipc.StudioIPCServer] = []

    async def asyncTearDown(self) -> None:
        for srv in self._ipc_servers:
            srv.stop()
        await self.client.close()
        self._td.cleanup()

    def _origin(self) -> str:
        return str(self.client.make_url("/")).rstrip("/")

    async def _login(self, username: str, password: str) -> tuple[dict[str, str], str]:
        resp = await self.client.post(
            "/api/auth/login",
            headers={"Origin": self._origin(), "Content-Type": "application/json"},
            json={"username": username, "password": password},
        )
        self.assertEqual(resp.status, 200, await resp.text())
        data = await resp.json()
        cookies = {k: v.value for k, v in resp.cookies.items()}
        return cookies, str(data["csrf_token"])

    def _read_audit_lines(self) -> list[dict[str, object]]:
        if not self.audit_log.is_file():
            return []
        out = []
        for ln in self.audit_log.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                out.append(json.loads(ln))
        return out


class TestPBC1WorkspaceFilesAndDiff(_WorkspaceFilesBaseTest):
    async def test_pb_c1_projects_whitelist_only_no_workdir_and_rejects_raw_workdir(self) -> None:
        # Unauthenticated blocked
        r_unauth = await self.client.get("/api/projects")
        self.assertEqual(r_unauth.status, 401)

        ro_cookies, _ = await self._login("ro_user", TEST_PASS_RO)
        r_proj = await self.client.get("/api/projects", cookies=ro_cookies)
        self.assertEqual(r_proj.status, 200)
        pdata = await r_proj.json()
        self.assertTrue(pdata["ok"])
        self.assertEqual(len(pdata["projects"]), 2)
        for p in pdata["projects"]:
            self.assertEqual(set(p.keys()), {"id", "name", "is_git"})
            self.assertNotIn("workdir", p)
        self.assertNotIn(str(self.proj_dir), json.dumps(pdata))

        # Raw workdir parameter unconditionally rejected (400)
        for ep in (
            f"/api/files/tree?project_id=safe-proj&workdir={self.outside_dir}",
            f"/api/files/content?project_id=safe-proj&path=a.txt&workdir={self.outside_dir}",
            f"/api/files/diff?project_id=safe-proj&workdir={self.outside_dir}",
        ):
            resp = await self.client.get(ep, cookies=ro_cookies)
            self.assertEqual(resp.status, 400, f"Expected 400 for {ep}")

        # Unknown project_id -> 404
        r_unk = await self.client.get("/api/files/tree?project_id=nonexistent-proj", cookies=ro_cookies)
        self.assertEqual(r_unk.status, 404)

    async def test_pb_c1_path_traversal_null_absolute_dash_and_symlink_escape(self) -> None:
        ro_cookies, _ = await self._login("ro_user", TEST_PASS_RO)
        (self.proj_dir / "hello.py").write_text("print('hi')\n", encoding="utf-8")

        # Symlinks: direct file symlink, parent directory symlink, and dangling symlink
        os.symlink(self.outside_dir / "secret.txt", self.proj_dir / "link_secret.txt")
        os.symlink(self.outside_dir, self.proj_dir / "link_dir")
        os.symlink("/etc/shadow_nonexistent_placeholder", self.proj_dir / "dangling.txt")

        # Verify symlinks are hidden in tree listing
        r_tree = await self.client.get("/api/files/tree?project_id=safe-proj", cookies=ro_cookies)
        self.assertEqual(r_tree.status, 200)
        tree_names = [e["name"] for e in (await r_tree.json())["entries"]]
        self.assertIn("hello.py", tree_names)
        self.assertNotIn("link_secret.txt", tree_names)
        self.assertNotIn("link_dir", tree_names)
        self.assertNotIn("dangling.txt", tree_names)

        # Attack paths on /api/files/content
        attack_paths = [
            "../outside-secret/secret.txt",
            "sub/../../outside-secret/secret.txt",
            "/etc/passwd",
            "hello.py\x00.txt",
            "-p",
            "--output=/tmp/pwn",
            "link_secret.txt",
            "link_dir/secret.txt",
            "dangling.txt",
        ]
        for bad in attack_paths:
            resp = await self.client.get(
                "/api/files/content",
                params={"project_id": "safe-proj", "path": bad},
                cookies=ro_cookies,
            )
            body = await resp.text()
            self.assertIn(resp.status, (400, 403), f"Attack path {bad!r} got {resp.status}: {body}")
            self.assertNotIn("TOP_SECRET_OUTSIDE_DATA", body)
            self.assertNotIn("root:x:", body)

        # Attack dir on /api/files/tree
        for bad_dir in ("../outside-secret", "link_dir", "/etc", "-f"):
            resp = await self.client.get(
                "/api/files/tree",
                params={"project_id": "safe-proj", "dir": bad_dir},
                cookies=ro_cookies,
            )
            self.assertIn(resp.status, (400, 403), f"Bad dir {bad_dir!r} got {resp.status}")

    async def test_pb_c1_sensitive_file_blacklist_hidden_in_tree_and_403_in_preview_diff(self) -> None:
        ro_cookies, _ = await self._login("ro_user", TEST_PASS_RO)
        (self.proj_dir / "src").mkdir()
        (self.proj_dir / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")

        # Create every sensitive file pattern
        sensitive_files = [
            ".env",
            ".env.local",
            ".env.production",
            "bot.token",
            "app.secret",
            ".git/config",
            ".git/HEAD",
            "users.json",
            "auth_users.json",
            "sessions.json",
            "tls.pem",
            "priv.key",
            "cert.p12",
            "cert.pfx",
            "keys/id_rsa",
            "keys/my_id_ed25519.pub",
            ".bao_credentials.json",
            "auth.json",
            "credentials.json",
            "state.db",
            "cache.sqlite3",
            "data.sqlite-wal",
            "audit.jsonl",
            "ipc/bot.sock",
            "cfg/mcp_config.json",
        ]
        for rel in sensitive_files:
            fp = self.proj_dir / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text("SENSITIVE_MARKER_DO_NOT_LEAK\n", encoding="utf-8")

        # Heavy dirs
        for hdir in ("node_modules", "__pycache__", "dist", "venv", ".venv", ".worktrees", ".rollback"):
            d = self.proj_dir / hdir
            d.mkdir(exist_ok=True)
            (d / "ignored.txt").write_text("ignored\n", encoding="utf-8")

        # Tree hides ALL sensitive files and heavy dirs
        r_tree = await self.client.get("/api/files/tree?project_id=safe-proj&depth=2", cookies=ro_cookies)
        self.assertEqual(r_tree.status, 200)
        raw_tree_json = await r_tree.text()
        self.assertIn("main.py", raw_tree_json)
        for name in (".env", "users.json", "mcp_config.json", "node_modules", "__pycache__", ".git", "id_rsa"):
            self.assertNotIn(name, raw_tree_json)

        # Preview & Diff MUST return 403 for every sensitive file with ZERO content
        for rel in sensitive_files:
            r_c = await self.client.get(
                "/api/files/content",
                params={"project_id": "safe-proj", "path": rel},
                cookies=ro_cookies,
            )
            txt_c = await r_c.text()
            self.assertEqual(r_c.status, 403, f"Expected 403 for content {rel}, got {r_c.status}")
            self.assertNotIn("SENSITIVE_MARKER_DO_NOT_LEAK", txt_c)

            r_d = await self.client.get(
                "/api/files/diff",
                params={"project_id": "safe-proj", "path": rel},
                cookies=ro_cookies,
            )
            txt_d = await r_d.text()
            self.assertEqual(r_d.status, 403, f"Expected 403 for diff {rel}, got {r_d.status}")
            self.assertNotIn("SENSITIVE_MARKER_DO_NOT_LEAK", txt_d)

    async def test_pb_c1_binary_detection_size_line_caps_and_tree_400_cap(self) -> None:
        ro_cookies, _ = await self._login("ro_user", TEST_PASS_RO)

        # Binary file
        (self.proj_dir / "img.bin").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00BINARY_SECRET_BYTES")
        r_bin = await self.client.get(
            "/api/files/content",
            params={"project_id": "safe-proj", "path": "img.bin"},
            cookies=ro_cookies,
        )
        self.assertEqual(r_bin.status, 200)
        bdata = await r_bin.json()
        self.assertTrue(bdata["is_binary"])
        self.assertEqual(bdata["content"], "")
        self.assertNotIn("BINARY_SECRET_BYTES", json.dumps(bdata))

        # Line cap (>1500 lines) & byte cap (>64 KiB)
        (self.proj_dir / "many_lines.txt").write_text(
            "\n".join(f"line-{i}" for i in range(2000)) + "\n",
            encoding="utf-8",
        )
        r_ml = await self.client.get(
            "/api/files/content",
            params={"project_id": "safe-proj", "path": "many_lines.txt"},
            cookies=ro_cookies,
        )
        mdata = await r_ml.json()
        self.assertTrue(mdata["truncated"])
        self.assertLessEqual(mdata["lines"], 1500)

        (self.proj_dir / "big_bytes.txt").write_text("A" * (90 * 1024), encoding="utf-8")
        r_bb = await self.client.get(
            "/api/files/content",
            params={"project_id": "safe-proj", "path": "big_bytes.txt"},
            cookies=ro_cookies,
        )
        bbdata = await r_bb.json()
        self.assertTrue(bbdata["truncated"])
        self.assertLessEqual(len(bbdata["content"].encode("utf-8")), 64 * 1024)

        # Tree 400-entry cap
        many_dir = self.proj_dir / "many"
        many_dir.mkdir()
        for idx in range(420):
            (many_dir / f"f_{idx:03d}.txt").write_text("x", encoding="utf-8")
        r_tr = await self.client.get(
            "/api/files/tree",
            params={"project_id": "safe-proj", "dir": "many", "depth": "1"},
            cookies=ro_cookies,
        )
        tdata = await r_tr.json()
        self.assertTrue(tdata["truncated"])
        self.assertEqual(tdata["total"], 400)

    async def test_pb_c1_git_diff_safe_flags_scope_validation_and_secret_redaction(self) -> None:
        ro_cookies, _ = await self._login("ro_user", TEST_PASS_RO)

        def _git(*args: str) -> None:
            subprocess.run(
                ["git", "-C", str(self.proj_dir), *args],
                check=True,
                capture_output=True,
                text=True,
            )

        _git("init")
        _git("config", "user.email", "dev@example.com")
        _git("config", "user.name", "Example Dev")
        (self.proj_dir / "app.py").write_text("val = 1\n", encoding="utf-8")
        (self.proj_dir / ".env").write_text("OLD=1\n", encoding="utf-8")
        _git("add", "app.py", ".env")
        _git("commit", "-m", "init")

        # Modify app.py (staged) + add unstaged line with secrets & host path, and modify .env
        fake_ghp = "ghp_" + "EXAMPLE1234567890ABCD"
        fake_vault = "lv1" + "/services/demo_secret"
        fake_home = "/" + "home" + "/alice/private/key.txt"
        (self.proj_dir / "app.py").write_text(
            f"val = 2\ntok = '{fake_ghp}'\n",
            encoding="utf-8",
        )
        _git("add", "app.py")
        (self.proj_dir / "app.py").write_text(
            f"val = 2\ntok = '{fake_ghp}'\nv = '{fake_vault}'\np = '{fake_home}'\n",
            encoding="utf-8",
        )
        (self.proj_dir / ".env").write_text("TOP_SECRET_ENV_VALUE=super_secret_123\n", encoding="utf-8")

        # Validate content redaction too
        r_cont = await self.client.get(
            "/api/files/content",
            params={"project_id": "safe-proj", "path": "app.py"},
            cookies=ro_cookies,
        )
        cdata = await r_cont.json()
        self.assertNotIn(fake_ghp, cdata["content"])
        self.assertNotIn(fake_vault, cdata["content"])
        self.assertNotIn(fake_home, cdata["content"])
        self.assertIn("[REDACTED]", cdata["content"])

        # Reject invalid scope, ref injection, dash-prefixed path
        for bad_q in (
            {"project_id": "safe-proj", "scope": "arbitrary"},
            {"project_id": "safe-proj", "ref": "-p"},
            {"project_id": "safe-proj", "path": "--no-index"},
        ):
            r_bad = await self.client.get("/api/files/diff", params=bad_q, cookies=ro_cookies)
            self.assertEqual(r_bad.status, 400, f"Expected 400 for {bad_q}")

        # Spy on asyncio.create_subprocess_exec to assert exact safe flags
        orig_exec = __import__("asyncio").create_subprocess_exec
        recorded_cmds: list[tuple[str, ...]] = []

        async def _spy_exec(*args: object, **kwargs: object) -> object:
            recorded_cmds.append(tuple(str(a) for a in args))
            return await orig_exec(*args, **kwargs)

        with mock.patch("studio.workspace_files.asyncio.create_subprocess_exec", side_effect=_spy_exec):
            r_all = await self.client.get(
                "/api/files/diff",
                params={"project_id": "safe-proj", "scope": "all"},
                cookies=ro_cookies,
            )
            self.assertEqual(r_all.status, 200)
            d_all = await r_all.json()
            self.assertTrue(d_all["is_git"])
            # .env MUST NOT appear in changed files or diff output
            self.assertFalse(any(f["path"] == ".env" for f in d_all["files"]))
            self.assertNotIn("TOP_SECRET_ENV_VALUE", d_all["diff"])
            # Secrets & host paths redacted
            self.assertNotIn(fake_ghp, d_all["diff"])
            self.assertNotIn(fake_vault, d_all["diff"])
            self.assertNotIn(fake_home, d_all["diff"])
            self.assertIn("[REDACTED]", d_all["diff"])

            r_st = await self.client.get(
                "/api/files/diff",
                params={"project_id": "safe-proj", "scope": "staged", "path": "app.py"},
                cookies=ro_cookies,
            )
            self.assertEqual(r_st.status, 200)
            r_un = await self.client.get(
                "/api/files/diff",
                params={"project_id": "safe-proj", "scope": "unstaged", "path": "app.py"},
                cookies=ro_cookies,
            )
            self.assertEqual(r_un.status, 200)

        diff_cmds = [c for c in recorded_cmds if c and c[0] == "git" and "diff" in c]
        self.assertGreaterEqual(len(diff_cmds), 3)
        for cmd in diff_cmds:
            self.assertIn("-c", cmd)
            self.assertIn("core.fsmonitor=false", cmd)
            self.assertIn("core.quotePath=false", cmd)
            self.assertIn("--no-ext-diff", cmd)
            self.assertIn("--no-textconv", cmd)
            self.assertIn("--no-color", cmd)
            self.assertIn("--", cmd)

    async def test_pb_c1_block1_diff_plus_minus_file_uri_symlink_mode_120000_p2_and_redos(self) -> None:
        from studio.data_sources import _SENSITIVE_HOST_PATH_RE
        from studio.workspace_files import _filter_sensitive_unified_diff, redact_workspace_text

        ro_cookies, _ = await self._login("ro_user", TEST_PASS_RO)

        # 1. Diff +/- host paths & file:/// URI redaction in BOTH Studio and Bridge IPC regexes,
        #    while preserving normal https://example.com URLs
        home_seg = "/" + "home"
        alice_secret = f"{home_seg}/alice/secret/app.py"
        bob_priv = f"{home_seg}/bob/private.txt"
        alice_wallet_uri = f"file://{home_seg}/alice/wallet.dat"
        ok_https_url = f"https://example.com{home_seg}/alice/docs"
        rel_diff_hdr = f"b{home_seg}/normal_rel.py"
        sample = "\n".join([
            f"+{alice_secret}",
            f"-{bob_priv}",
            "+~/ssh/id_test",
            "-~/notes.txt",
            "+/etc/shadow",
            f"+{alice_wallet_uri}",
            "-file:///etc/hosts",
            "FILE:///var/run/service.sock",
            f"ok_url = '{ok_https_url}'",
            "ok_http = 'http://example.com/etc/guide'",
            f"+++ {rel_diff_hdr}",
        ])
        for fn in (redact_workspace_text, lambda s: bridge_mod._redact_ipc_text(s, max_len=0)):
            red = fn(sample)
            self.assertNotIn(alice_secret, red)
            self.assertNotIn(bob_priv, red)
            self.assertNotIn("~/ssh/id_test", red)
            self.assertNotIn("~/notes.txt", red)
            self.assertNotIn("/etc/shadow", red)
            self.assertNotIn(alice_wallet_uri, red)
            self.assertNotIn("file:///etc/hosts", red)
            self.assertNotIn("FILE:///var/run/service.sock", red)
            self.assertIn(ok_https_url, red)
            self.assertIn("http://example.com/etc/guide", red)
            self.assertIn(rel_diff_hdr, red)

        # 2. ReDoS linear-time guard (< 0.1s on 32 KiB adversarial payloads)
        adversarial_inputs = [
            "-a" * 16384,
            "+a" * 16384,
            "a" * 32768,
            "-/" * 16384,
            ("a-b+c:" * 5462)[:32768],
            ("x.y" * 10923)[:32768],
        ]
        for pat in (_SENSITIVE_HOST_PATH_RE, bridge_mod._IPC_HOST_PATH_RE):
            for payload in adversarial_inputs:
                t0 = time.perf_counter()
                pat.sub("[REDACTED]", payload)
                dt = time.perf_counter() - t0
                self.assertLess(dt, 0.1, f"Regex ReDoS detected ({dt:.4f}s) on payload prefix {payload[:16]!r}")

        # 3. _filter_sensitive_unified_diff drops ALL mode 120000 symlink sections
        raw_symlink_diff = (
            "diff --git a/good.py b/good.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/good.py\n"
            "+++ b/good.py\n"
            "@@ -1 +1 @@\n"
            "-x = 1\n"
            "+x = 2\n"
            "diff --git a/link_new b/link_new\n"
            "new file mode 120000\n"
            "index 0000000..aaaaaaa\n"
            "--- /dev/null\n"
            "+++ b/link_new\n"
            "@@ -0,0 +1 @@\n"
            "+/etc/passwd\n"
            "diff --git a/link_old b/link_old\n"
            "old mode 120000\n"
            "new mode 100644\n"
            "--- a/link_old\n"
            "+++ b/link_old\n"
            "@@ -1 +1 @@\n"
            f"-{home_seg}/alice/secret\n"
            "+regular\n"
            "diff --git a/link_tomode b/link_tomode\n"
            "old mode 100644\n"
            "new mode 120000\n"
            "--- a/link_tomode\n"
            "+++ b/link_tomode\n"
            "@@ -1 +1 @@\n"
            "-regular\n"
            "+/etc/shadow\n"
            "diff --git a/link_del b/link_del\n"
            "deleted file mode 120000\n"
            "index bbbbbbb..0000000\n"
            "--- a/link_del\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-/root/secret\n"
            "diff --git a/link_mod b/link_mod\n"
            "index ccccccc..ddddddd 120000\n"
            "--- a/link_mod\n"
            "+++ b/link_mod\n"
            "@@ -1 +1 @@\n"
            "-/tmp/old\n"
            "+/tmp/new\n"
        )
        filtered = _filter_sensitive_unified_diff(raw_symlink_diff)
        self.assertIn("diff --git a/good.py b/good.py", filtered)
        self.assertIn("+x = 2", filtered)
        for blocked_name in ("link_new", "link_old", "link_tomode", "link_del", "link_mod", "120000"):
            self.assertNotIn(blocked_name, filtered)

        # 4. P2 blacklist additions: .envrc, *.db-wal, *.db-shm, *.db-journal
        p2_sensitive = [".envrc", "app.db-wal", "app.db-shm", "app.db-journal"]
        for rel in p2_sensitive:
            (self.proj_dir / rel).write_text("P2_SENSITIVE_MARKER\n", encoding="utf-8")
        r_tree = await self.client.get("/api/files/tree?project_id=safe-proj", cookies=ro_cookies)
        tree_txt = await r_tree.text()
        for rel in p2_sensitive:
            self.assertNotIn(rel, tree_txt)
            r_c = await self.client.get(
                "/api/files/content",
                params={"project_id": "safe-proj", "path": rel},
                cookies=ro_cookies,
            )
            self.assertEqual(r_c.status, 403)
            r_d = await self.client.get(
                "/api/files/diff",
                params={"project_id": "safe-proj", "path": rel},
                cookies=ro_cookies,
            )
            self.assertEqual(r_d.status, 403)

        # 5. P2 non-blocking FIFO / non-regular file rejection + fstat error fd cleanup
        fifo_path = self.proj_dir / "pipe.fifo"
        os.mkfifo(fifo_path)
        t_fifo = time.perf_counter()
        r_fifo = await self.client.get(
            "/api/files/content",
            params={"project_id": "safe-proj", "path": "pipe.fifo"},
            cookies=ro_cookies,
        )
        self.assertLess(time.perf_counter() - t_fifo, 1.0)
        self.assertEqual(r_fifo.status, 400)

        (self.proj_dir / "reg.txt").write_text("hello\n", encoding="utf-8")
        closed_fds: list[int] = []
        real_close = os.close

        def _spy_close(fd: int) -> None:
            closed_fds.append(fd)
            real_close(fd)

        with (
            mock.patch("studio.workspace_files.os.fstat", side_effect=OSError("boom")),
            mock.patch("studio.workspace_files.os.close", side_effect=_spy_close),
        ):
            r_fstat_err = await self.client.get(
                "/api/files/content",
                params={"project_id": "safe-proj", "path": "reg.txt"},
                cookies=ro_cookies,
            )
            self.assertEqual(r_fstat_err.status, 500)
            self.assertGreaterEqual(len(closed_fds), 1)


class TestPBC2UndoHardeningAndProxy(_WorkspaceFilesBaseTest):
    def _write_blob(self, blobs_dir: Path, data: bytes) -> str:
        import hashlib
        import zlib
        h = hashlib.sha1(data).hexdigest()
        sub = blobs_dir / h[:2]
        sub.mkdir(parents=True, exist_ok=True)
        (sub / f"{h}.z").write_bytes(zlib.compress(data))
        return h

    def test_pb_c2_bridge_apply_checkpoint_blocks_symlink_and_parent_symlink_even_with_force_true(self) -> None:
        """PB-C2 critical regression: unsafe path/symlink MUST fail-closed entire batch even with force=True."""
        blobs_dir = self.tmp / "undo_blobs"
        ext_file = self.outside_dir / "victim.txt"
        ext_file.write_text("ORIGINAL_OUTSIDE_CONTENT\n", encoding="utf-8")

        sibling = self.proj_dir / "sibling.txt"
        sibling.write_text("SIBLING_CURRENT\n", encoding="utf-8")
        sib_pre_sha = self._write_blob(blobs_dir, b"SIBLING_OLD\n")
        sib_post_sha = self._write_blob(blobs_dir, b"SIBLING_CURRENT\n")
        pwn_sha = self._write_blob(blobs_dir, b"OVERWRITTEN_BY_UNDO\n")

        with mock.patch.object(bridge_mod, "ACB_UNDO_BLOBS_DIR", str(blobs_dir)):
            # Case A: target file itself is a symlink pointing outside workdir
            sym_target = self.proj_dir / "evil_link.txt"
            os.symlink(ext_file, sym_target)
            entry_a = {
                "id": "u000001",
                "workdir": str(self.proj_dir),
                "changes": [
                    {"path": "sibling.txt", "action": "modified", "pre_sha1": sib_pre_sha, "post_sha1": sib_post_sha},
                    {"path": "evil_link.txt", "action": "modified", "pre_sha1": pwn_sha, "post_sha1": pwn_sha},
                ],
            }
            ok, applied, conflicts, _ = bridge_mod._apply_checkpoint_changes(entry_a, reverse=False, force=True)
            self.assertFalse(ok)
            self.assertEqual(applied, [])
            self.assertTrue(conflicts)
            self.assertEqual(ext_file.read_text(encoding="utf-8"), "ORIGINAL_OUTSIDE_CONTENT\n")
            self.assertEqual(sibling.read_text(encoding="utf-8"), "SIBLING_CURRENT\n")
            sym_target.unlink()

            # Case B: intermediate parent directory is a symlink pointing outside workdir
            os.symlink(self.outside_dir, self.proj_dir / "linked_sub")
            entry_b = {
                "id": "u000002",
                "workdir": str(self.proj_dir),
                "changes": [
                    {"path": "sibling.txt", "action": "modified", "pre_sha1": sib_pre_sha, "post_sha1": sib_post_sha},
                    {"path": "linked_sub/victim.txt", "action": "modified", "pre_sha1": pwn_sha, "post_sha1": pwn_sha},
                ],
            }
            ok_b, applied_b, _, _ = bridge_mod._apply_checkpoint_changes(entry_b, reverse=False, force=True)
            self.assertFalse(ok_b)
            self.assertEqual(applied_b, [])
            self.assertEqual(ext_file.read_text(encoding="utf-8"), "ORIGINAL_OUTSIDE_CONTENT\n")
            self.assertEqual(sibling.read_text(encoding="utf-8"), "SIBLING_CURRENT\n")
            (self.proj_dir / "linked_sub").unlink()

            # Case C: dangling symlink & `..` traversal with force=True
            os.symlink(self.outside_dir / "new_pwned.txt", self.proj_dir / "dangling_link.txt")
            entry_c = {
                "id": "u000003",
                "workdir": str(self.proj_dir),
                "changes": [
                    {"path": "dangling_link.txt", "action": "modified", "pre_sha1": pwn_sha, "post_sha1": pwn_sha},
                ],
            }
            ok_c, _, _, _ = bridge_mod._apply_checkpoint_changes(entry_c, reverse=False, force=True)
            self.assertFalse(ok_c)
            self.assertFalse((self.outside_dir / "new_pwned.txt").exists())

            entry_d = {
                "id": "u000004",
                "workdir": str(self.proj_dir),
                "changes": [
                    {"path": "../outside-secret/victim.txt", "action": "deleted", "pre_sha1": pwn_sha},
                ],
            }
            ok_d, _, _, _ = bridge_mod._apply_checkpoint_changes(entry_d, reverse=False, force=True)
            self.assertFalse(ok_d)
            self.assertEqual(ext_file.read_text(encoding="utf-8"), "ORIGINAL_OUTSIDE_CONTENT\n")

    async def test_pb_c2_undo_write_gate_rbac_forbidden_fields_ipc_role_and_lifecycle(self) -> None:
        blobs_dir = self.tmp / "undo_blobs_ipc"
        cid1 = "conv_pb_c2_0001"
        cid2 = "conv_pb_c2_0002"
        f_doc = self.proj_dir / "doc.txt"
        pre_bytes = b"version-1\n"
        post_bytes = b"version-2\n"
        pre_sha = self._write_blob(blobs_dir, pre_bytes)
        post_sha = self._write_blob(blobs_dir, post_bytes)
        f_doc.write_bytes(post_bytes)

        fake_state = {
            "scopes": {
                f"web:{ADMIN_UID}:{cid1}": {
                    "conversation_id": cid1,
                    "undo_stack": [
                        {
                            "id": "u100001",
                            "ts": int(time.time()) - 10,
                            "workdir": str(self.proj_dir),
                            "conv": cid1,
                            "prompt": "older checkpoint",
                            "changes": [{"path": "doc.txt", "action": "modified", "pre_sha1": pre_sha, "post_sha1": post_sha}],
                        },
                        {
                            "id": "u100002",
                            "ts": int(time.time()),
                            "workdir": str(self.proj_dir),
                            "conv": cid1,
                            "prompt": "latest checkpoint",
                            "changes": [{"path": "doc.txt", "action": "modified", "pre_sha1": pre_sha, "post_sha1": post_sha}],
                        },
                    ],
                    "redo_stack": [],
                    "pending_undo_notice": None,
                }
            }
        }

        def _fake_projects() -> list[dict[str, str]]:
            return [
                {"id": "safe-proj", "name": "Safe Project", "workdir": str(self.proj_dir)},
                {"id": "other-proj", "name": "Other Project", "workdir": str(self.proj2_dir)},
            ]

        def _resolve_role(uid: int) -> str:
            if uid == ADMIN_UID:
                return "admin"
            if uid == READONLY_UID:
                return "readonly"
            return "denied"

        with (
            mock.patch.object(bridge_mod, "ACB_UNDO_BLOBS_DIR", str(blobs_dir)),
            mock.patch.object(bridge_mod, "state", fake_state),
            mock.patch.object(bridge_mod, "save_state", lambda: None),
            mock.patch.object(bridge_mod, "list_agy_projects", _fake_projects),
            mock.patch.object(bridge_mod, "turn_running", False),
            mock.patch.object(bridge_mod, "_current_bot_handle", lambda: TEST_BOT_HANDLE),
            mock.patch.object(bot_bus, "BUS_DIR", str(self.bus_dir)),
        ):
            srv = studio_ipc.StudioIPCServer(
                bus_dir=self.bus_dir,
                bot_handle=TEST_BOT_HANDLE,
                resolve_role_fn=_resolve_role,
                get_meta_fn=lambda: {"handle": TEST_BOT_HANDLE},
                enqueue_turn_fn=lambda _r: (202, {"ok": True}),
                abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
                list_undo_fn=bridge_mod._studio_ipc_list_undo,
                apply_undo_fn=bridge_mod._studio_ipc_apply_undo,
                apply_redo_fn=bridge_mod._studio_ipc_apply_redo,
            )
            srv.start()
            self._ipc_servers.append(srv)

            admin_cookies, admin_csrf = await self._login("admin_user", TEST_PASS_ADMIN)
            ro_cookies, ro_csrf = await self._login("ro_user", TEST_PASS_RO)
            force_cookies, force_csrf = await self._login("force_user", TEST_PASS_FORCE)

            # 1. Readonly rejected on GET /api/undo/checkpoints and POST /api/undo/apply
            r_ro_list = await self.client.get("/api/undo/checkpoints", cookies=ro_cookies)
            self.assertEqual(r_ro_list.status, 403)
            r_ro_apply = await self.client.post(
                "/api/undo/apply",
                headers={"Origin": self._origin(), "Content-Type": "application/json", "X-Studio-CSRF": ro_csrf},
                cookies=ro_cookies,
                json={"entry_id": "u100002", "bot": TEST_BOT_HANDLE},
            )
            self.assertEqual(r_ro_apply.status, 403)

            # 2. Direct IPC call with READONLY_UID + spoofed role="admin" MUST be 403
            sc_ipc, _, _ = _uds_http_request(
                srv.sock_path,
                "POST",
                "/ipc/undo/apply",
                headers={
                    "X-Bridge-IPC-Token": srv.token,
                    "Content-Type": "application/json",
                },
                body=json.dumps({"user_id": READONLY_UID, "role": "admin", "entry_id": "u100002"}).encode("utf-8"),
            )
            self.assertEqual(sc_ipc, 403)

            # 3. Four-layer write gates: bad Origin (403), bad Content-Type (415), must_change_password (403), bad CSRF (403)
            r_orig = await self.client.post(
                "/api/undo/apply",
                headers={"Origin": "https://evil.example.com", "Content-Type": "application/json", "X-Studio-CSRF": admin_csrf},
                cookies=admin_cookies,
                json={"entry_id": "u100002"},
            )
            self.assertEqual(r_orig.status, 403)

            r_ct = await self.client.post(
                "/api/undo/apply",
                headers={"Origin": self._origin(), "Content-Type": "text/plain", "X-Studio-CSRF": admin_csrf},
                cookies=admin_cookies,
                data='{"entry_id":"u100002"}',
            )
            self.assertEqual(r_ct.status, 415)

            r_force_pw = await self.client.post(
                "/api/undo/apply",
                headers={"Origin": self._origin(), "Content-Type": "application/json", "X-Studio-CSRF": force_csrf},
                cookies=force_cookies,
                json={"entry_id": "u100002"},
            )
            self.assertEqual(r_force_pw.status, 403)

            r_csrf = await self.client.post(
                "/api/undo/apply",
                headers={"Origin": self._origin(), "Content-Type": "application/json", "X-Studio-CSRF": "wrong-csrf"},
                cookies=admin_cookies,
                json={"entry_id": "u100002"},
            )
            self.assertEqual(r_csrf.status, 403)

            # 4. Forbidden fields rejected (400)
            for forb_body in (
                {"entry_id": "u100002", "workdir": str(self.proj_dir)},
                {"entry_id": "u100002", "changes": []},
                {"entry_id": "u100002", "sha1": pre_sha},
                {"entry_id": "u100002", "role": "admin"},
                {"entry_id": "u100002", "ipc_sock": "/tmp/x.sock"},
            ):
                r_f = await self.client.post(
                    "/api/undo/apply",
                    headers={"Origin": self._origin(), "Content-Type": "application/json", "X-Studio-CSRF": admin_csrf},
                    cookies=admin_cookies,
                    json=forb_body,
                )
                self.assertEqual(r_f.status, 400, f"Expected 400 for {forb_body}")

            # 5. Admin lists checkpoints (zero workdir leaked)
            r_list = await self.client.get(
                f"/api/undo/checkpoints?bot={TEST_BOT_HANDLE}&cid={cid1}&project_id=safe-proj",
                cookies=admin_cookies,
            )
            self.assertEqual(r_list.status, 200)
            ldata = await r_list.json()
            self.assertEqual(len(ldata["undo_stack"]), 2)
            self.assertNotIn(str(self.proj_dir), json.dumps(ldata))

            # 6. Non-top, forged, wrong-cid, wrong-project rejections
            hdrs_ok = {"Origin": self._origin(), "Content-Type": "application/json", "X-Studio-CSRF": admin_csrf}
            r_nontop = await self.client.post(
                "/api/undo/apply", headers=hdrs_ok, cookies=admin_cookies,
                json={"entry_id": "u100001", "bot": TEST_BOT_HANDLE},
            )
            self.assertEqual(r_nontop.status, 409)

            r_forged = await self.client.post(
                "/api/undo/apply", headers=hdrs_ok, cookies=admin_cookies,
                json={"entry_id": "u999999", "bot": TEST_BOT_HANDLE},
            )
            self.assertEqual(r_forged.status, 404)

            r_badcid = await self.client.post(
                "/api/undo/apply", headers=hdrs_ok, cookies=admin_cookies,
                json={"entry_id": "u100002", "bot": TEST_BOT_HANDLE, "cid": cid2},
            )
            self.assertEqual(r_badcid.status, 403)

            r_badproj = await self.client.post(
                "/api/undo/apply", headers=hdrs_ok, cookies=admin_cookies,
                json={"entry_id": "u100002", "bot": TEST_BOT_HANDLE, "project_id": "other-proj"},
            )
            self.assertEqual(r_badproj.status, 403)

            # 7. Active ConversationLease held -> 409 session_busy (zero mutation)
            lease = studio_ipc.ConversationLease.try_acquire(self.bus_dir, cid1)
            self.assertIsNotNone(lease)
            try:
                r_busy = await self.client.post(
                    "/api/undo/apply", headers=hdrs_ok, cookies=admin_cookies,
                    json={"entry_id": "u100002", "bot": TEST_BOT_HANDLE},
                )
                self.assertEqual(r_busy.status, 409)
                self.assertEqual((await r_busy.json()).get("code"), "session_busy")
                self.assertEqual(f_doc.read_bytes(), post_bytes)
            finally:
                assert lease is not None
                lease.release()

            # 8. External modification conflict -> default force=False returns 409; force=True succeeds
            f_doc.write_bytes(b"external-edit\n")
            r_conf = await self.client.post(
                "/api/undo/apply", headers=hdrs_ok, cookies=admin_cookies,
                json={"entry_id": "u100002", "bot": TEST_BOT_HANDLE, "force": False},
            )
            self.assertEqual(r_conf.status, 409)
            self.assertEqual((await r_conf.json()).get("code"), "conflict")
            self.assertEqual(f_doc.read_bytes(), b"external-edit\n")

            r_apply = await self.client.post(
                "/api/undo/apply", headers=hdrs_ok, cookies=admin_cookies,
                json={"entry_id": "u100002", "bot": TEST_BOT_HANDLE, "force": True},
            )
            self.assertEqual(r_apply.status, 200)
            self.assertEqual(f_doc.read_bytes(), pre_bytes)

            # Consumed entry cannot be re-applied -> 409 already_consumed
            r_again = await self.client.post(
                "/api/undo/apply", headers=hdrs_ok, cookies=admin_cookies,
                json={"entry_id": "u100002", "bot": TEST_BOT_HANDLE},
            )
            self.assertEqual(r_again.status, 409)
            self.assertEqual((await r_again.json()).get("code"), "already_consumed")

            # Verify pending_undo_notice recorded for cid1
            self.assertIn(cid1, fake_state.get("pending_undo_notices_by_cid") or {})

            # 9. Redo restores post_bytes and clears pending_undo_notice
            r_redo = await self.client.post(
                "/api/undo/redo", headers=hdrs_ok, cookies=admin_cookies,
                json={"entry_id": "u100002", "bot": TEST_BOT_HANDLE},
            )
            self.assertEqual(r_redo.status, 200)
            self.assertEqual(f_doc.read_bytes(), post_bytes)
            self.assertNotIn(cid1, fake_state.get("pending_undo_notices_by_cid") or {})

            # 10. Audit log 0600 permissions, records allow & deny, zero CSRF/file contents
            st_mode = stat.S_IMODE(self.audit_log.stat().st_mode)
            self.assertEqual(st_mode, 0o600)
            audit_raw = self.audit_log.read_text(encoding="utf-8")
            self.assertNotIn(admin_csrf, audit_raw)
            self.assertNotIn("version-1", audit_raw)
            audit_entries = self._read_audit_lines()
            actions = {e["action"] for e in audit_entries}
            outcomes = {e["outcome"] for e in audit_entries}
            self.assertIn("undo.apply", actions)
            self.assertIn("undo.redo", actions)
            self.assertIn("denied_origin", outcomes)
            self.assertIn("denied_content_type", outcomes)
            self.assertIn("denied_csrf", outcomes)
            self.assertIn("denied_rbac", outcomes)
            self.assertIn("allowed_force", outcomes)
            self.assertIn("allowed", outcomes)

    def test_pb_c2_web_turn_consumes_pending_undo_notice_only_for_matching_cid(self) -> None:
        """Align with bridge.py:4802 — Web turn consumes `pending_undo_notice` ONLY when `cid` matches."""
        cid_match = "conv_notice_match_01"
        cid_other = "conv_notice_other_02"
        notice_txt = "[系统提示：用户在 10:00:00 执行了 /undo]"
        fake_state = {
            "scopes": {
                f"web:{ADMIN_UID}:{cid_match}": {
                    "conversation_id": cid_match,
                    "pending_undo_notice": notice_txt,
                    "pending_undo_notice_cid": cid_match,
                },
                f"web:{ADMIN_UID}:{cid_other}": {
                    "conversation_id": cid_other,
                    "pending_undo_notice": None,
                },
            },
            "pending_undo_notices_by_cid": {
                cid_match: notice_txt,
            },
        }
        seen_prompts: list[str] = []

        class _FakeSess:
            def __init__(self, cid_val: str) -> None:
                self.cid = cid_val
                self._events: list[dict[str, object]] = []

            def send_user_prompt(self, prompt_text: str) -> None:
                seen_prompts.append(prompt_text)
                self._events = [
                    {"event": "init", "conversation_id": self.cid},
                    {"event": "result", "status": "SUCCESS", "response": "ok", "conversation_id": self.cid},
                    {"event": "__eof__"},
                ]

            def next_event(self, timeout: float = 0.25) -> dict[str, object] | None:
                return self._events.pop(0) if self._events else {"event": "__eof__"}

            def get_stderr_text(self) -> str:
                return ""

            def close(self, force: bool = False) -> None:
                return None

        def _fake_acquire(_sk: str, conv: str | None, *_a: object, **_kw: object) -> tuple[_FakeSess, bool]:
            return _FakeSess(conv or cid_other), False

        with (
            mock.patch.object(bridge_mod, "state", fake_state),
            mock.patch.object(bridge_mod, "save_state", lambda: None),
            mock.patch.object(bridge_mod, "WORKDIR", str(self.proj_dir)),
            mock.patch.object(bridge_mod, "_acquire_session", _fake_acquire),
            mock.patch.object(bridge_mod, "snapshot_workspace_files", lambda **_kw: {}),
            mock.patch.object(bridge_mod, "snapshot_undo_manifest", lambda *_a, **_kw: None),
            mock.patch.object(bridge_mod, "get_transcript_line_count", lambda *_a: 0),
            mock.patch.object(bridge_mod, "finalize_turn_undo", lambda *_a, **_kw: 0),
            mock.patch.object(bot_bus, "BUS_DIR", str(self.bus_dir)),
        ):
            # 1. Web turn with DIFFERENT cid does NOT receive or consume cid_match's notice
            bridge_mod.run_agy(
                0,
                "hello other",
                scope_key=f"web:{ADMIN_UID}:{cid_other}",
                user_role="admin",
                user_id=ADMIN_UID,
                event_sink=lambda _e, _p: None,
                web_turn_id="turn-other-01",
                override_cid=cid_other,
            )
            self.assertEqual(len(seen_prompts), 1)
            self.assertNotIn(notice_txt, seen_prompts[0])
            self.assertIn(cid_match, fake_state["pending_undo_notices_by_cid"])

            # 2. Web turn with MATCHING cid DOES receive and consume notice
            bridge_mod.run_agy(
                0,
                "hello match",
                scope_key=f"web:{ADMIN_UID}:{cid_match}",
                user_role="admin",
                user_id=ADMIN_UID,
                event_sink=lambda _e, _p: None,
                web_turn_id="turn-match-01",
                override_cid=cid_match,
            )
            self.assertEqual(len(seen_prompts), 2)
            self.assertIn(notice_txt, seen_prompts[1])
            self.assertNotIn(cid_match, fake_state["pending_undo_notices_by_cid"])

    def test_pb_c2_block3_pending_undo_notices_bounded_lru_and_tg_cross_session_isolation(self) -> None:
        """BLOCK-3: `pending_undo_notices_by_cid` bounded LRU <= 64 & TG non-Web turn never leaks cid-A to cid-B."""
        # 1. Bounded LRU <= 64
        fake_state_lru: dict[str, object] = {"scopes": {}, "pending_undo_notices_by_cid": {}}
        with mock.patch.object(bridge_mod, "state", fake_state_lru):
            for i in range(70):
                bridge_mod._record_pending_undo_notice_by_cid_locked(f"cid_{i:03d}", f"notice_{i}")
            # Refresh an existing key (cid_010) to move it to MRU tail, then insert 10 more
            bridge_mod._record_pending_undo_notice_by_cid_locked("cid_010", "notice_010_refreshed")
            for i in range(70, 80):
                bridge_mod._record_pending_undo_notice_by_cid_locked(f"cid_{i:03d}", f"notice_{i}")

            by_cid = fake_state_lru["pending_undo_notices_by_cid"]
            assert isinstance(by_cid, dict)
            self.assertLessEqual(len(by_cid), bridge_mod._PENDING_UNDO_NOTICES_MAX)
            self.assertEqual(len(by_cid), 64)
            # Oldest keys evicted, refreshed MRU key & newest keys retained
            self.assertNotIn("cid_000", by_cid)
            self.assertNotIn("cid_015", by_cid)
            self.assertIn("cid_010", by_cid)
            self.assertEqual(by_cid["cid_010"], "notice_010_refreshed")
            self.assertIn("cid_079", by_cid)

        # 2. TG non-Web turn cross-session isolation inside same scope
        cid_a = "conv_tg_cid_a"
        cid_b = "conv_tg_cid_b"
        cid_c = "conv_tg_cid_c"
        notice_a = "[系统提示：cid-A 已执行 /undo]"
        notice_c = "[系统提示：cid-C 已执行 /undo]"
        skey = bridge_mod.scope_key_for(ADMIN_UID, None)
        fake_state_tg = {
            "scopes": {
                skey: {
                    "conversation_id": cid_b,
                    "pending_undo_notice": notice_a,
                    "pending_undo_notice_cid": cid_a,
                },
            },
            "pending_undo_notices_by_cid": {
                cid_a: notice_a,
                cid_c: notice_c,
            },
        }
        seen_prompts: list[str] = []

        class _FakeSessTG:
            def __init__(self, cid_val: str) -> None:
                self.cid = cid_val
                self._events: list[dict[str, object]] = []

            def send_user_prompt(self, prompt_text: str) -> None:
                seen_prompts.append(prompt_text)
                self._events = [
                    {"event": "init", "conversation_id": self.cid},
                    {"event": "result", "status": "SUCCESS", "response": "ok", "conversation_id": self.cid},
                    {"event": "__eof__"},
                ]

            def next_event(self, timeout: float = 0.25) -> dict[str, object] | None:
                return self._events.pop(0) if self._events else {"event": "__eof__"}

            def get_stderr_text(self) -> str:
                return ""

            def close(self, force: bool = False) -> None:
                return None

        class _FakeStreamer:
            status_override = None

            def __init__(self, *_a: object, **kwargs: object) -> None:
                self.start_line = kwargs.get("start_line", 0)

            def start(self) -> None:
                pass

            def stop(self) -> None:
                pass

            def set_cid(self, _c: object) -> None:
                pass

            def set_status_override(self, _v: object) -> None:
                pass

            def on_thinking(self, *_a: object, **_kw: object) -> None:
                pass

            def on_text_delta(self, *_a: object, **_kw: object) -> None:
                pass

            def finalize_step(self, text: str, **_kw: object) -> tuple[int, str]:
                return (201, f"<p>{text}</p>")

        with (
            mock.patch.object(bridge_mod, "state", fake_state_tg),
            mock.patch.object(bridge_mod, "save_state", lambda: None),
            mock.patch.object(bridge_mod, "WORKDIR", str(self.proj_dir)),
            mock.patch.object(bridge_mod, "_acquire_session", lambda _sk, conv, *_a, **_kw: (_FakeSessTG(conv or cid_b), False)),
            mock.patch.object(bridge_mod, "LiveDraftStreamer", _FakeStreamer),
            mock.patch.object(bridge_mod, "send", lambda *_a, **_kw: None),
            mock.patch.object(bridge_mod, "send_rich", lambda *_a, **_kw: (1, "ok")),
            mock.patch.object(bridge_mod, "push_step_images", lambda *_a, **_kw: None),
            mock.patch.object(bridge_mod, "_record_and_relay_bot_group_msg", lambda *_a, **_kw: None),
            mock.patch.object(bridge_mod, "_maybe_post_turn_auto_compact", lambda *_a, **_kw: None),
            mock.patch.object(bridge_mod, "snapshot_workspace_files", lambda **_kw: {}),
            mock.patch.object(bridge_mod, "snapshot_undo_manifest", lambda *_a, **_kw: None),
            mock.patch.object(bridge_mod, "get_transcript_line_count", lambda *_a: 0),
            mock.patch.object(bridge_mod, "finalize_turn_undo", lambda *_a, **_kw: 0),
            mock.patch.object(bot_bus, "BUS_DIR", str(self.bus_dir)),
        ):
            # A. TG turn on cid_b MUST NOT consume cid_a's notice
            bridge_mod.run_agy(ADMIN_UID, "tg turn b", scope_key=skey, user_role="admin", user_id=ADMIN_UID)
            self.assertEqual(len(seen_prompts), 1)
            self.assertNotIn(notice_a, seen_prompts[0])
            self.assertEqual(fake_state_tg["scopes"][skey]["pending_undo_notice"], notice_a)
            self.assertEqual(fake_state_tg["scopes"][skey]["pending_undo_notice_cid"], cid_a)
            self.assertIn(cid_a, fake_state_tg["pending_undo_notices_by_cid"])

            # B. TG turn on cid_c consumes ONLY cid_c's notice from by_cid_notices, keeping cid_a intact
            fake_state_tg["scopes"][skey]["conversation_id"] = cid_c
            bridge_mod.run_agy(ADMIN_UID, "tg turn c", scope_key=skey, user_role="admin", user_id=ADMIN_UID)
            self.assertEqual(len(seen_prompts), 2)
            self.assertIn(notice_c, seen_prompts[1])
            self.assertNotIn(notice_a, seen_prompts[1])
            self.assertNotIn(cid_c, fake_state_tg["pending_undo_notices_by_cid"])
            self.assertEqual(fake_state_tg["scopes"][skey]["pending_undo_notice"], notice_a)

            # C. TG turn on cid_a consumes cid_a's notice and cleans scope fields + by_cid map
            fake_state_tg["scopes"][skey]["conversation_id"] = cid_a
            bridge_mod.run_agy(ADMIN_UID, "tg turn a", scope_key=skey, user_role="admin", user_id=ADMIN_UID)
            self.assertEqual(len(seen_prompts), 3)
            self.assertIn(notice_a, seen_prompts[2])
            self.assertIsNone(fake_state_tg["scopes"][skey]["pending_undo_notice"])
            self.assertNotIn("pending_undo_notice_cid", fake_state_tg["scopes"][skey])
            self.assertNotIn(cid_a, fake_state_tg["pending_undo_notices_by_cid"])


class TestPBC7C8StaticInvariants(unittest.TestCase):
    def test_pb_c7_c8_static_boundaries_no_direct_writes_no_dangerous_html_and_export_registered(self) -> None:
        # 1. studio/workspace_files.py MUST NOT write files or touch acb_undo directly
        wf_src = (REPO_ROOT / "studio" / "workspace_files.py").read_text(encoding="utf-8")
        self.assertNotIn("acb_undo", wf_src.replace("`acb_undo`", ""))
        wf_tree = ast.parse(wf_src)
        for node in ast.walk(wf_tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, {"write_text", "write_bytes", "unlink", "rmdir"})

        # 2. Frontend M1 components have ZERO dangerouslySetInnerHTML
        for rel in (
            "webui/src/components/FilesDiffPanel.tsx",
            "webui/src/components/BotsView.tsx",
            "webui/src/components/WorkspaceView.tsx",
        ):
            txt = (REPO_ROOT / rel).read_text(encoding="utf-8")
            self.assertNotIn("dangerouslySetInnerHTML", txt, f"Found dangerouslySetInnerHTML in {rel}")

        # 3. PB-C8: Both new test suites registered in CORE_SYNC_EXACT (when running in private repo)
        if (REPO_ROOT / "scripts" / "export_public.py").is_file():
            import export_public

            self.assertIn("tests/test_studio_files_undo.py", export_public.CORE_SYNC_EXACT)
            self.assertIn("tests/test_studio_bot_control.py", export_public.CORE_SYNC_EXACT)


if __name__ == "__main__":
    unittest.main()
