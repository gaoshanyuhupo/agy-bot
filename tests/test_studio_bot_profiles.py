#!/usr/bin/env python3
"""Prod-Release Contract Tests — Studio Bot Profile/Rules/Soul/Memory/Skills & Bridge IPC (C1, C2, C3).

Verifies:
- C1: GET auth + Cache-Control: no-store + Referrer-Policy: no-referrer + zero host paths/tokens;
      4-layer write gate on PUT /profile, PUT /skills/{slug}, DELETE /skills/{slug}
      (Origin/Sec-Fetch-Site -> 403, non-JSON -> 415, unauth/must_change_password -> 401/403,
      CSRF/live readonly -> 403); 0600 append-only audit log with zero plaintext doc content;
      Studio performs zero direct disk writes to AGY_BOT_PROFILES_DIR.
- C2: Strict doc allowlist (SOUL.md/RULES.md/MEMORY.md), slug regex (rejects ./../__proto__/slashes),
      24 KiB UTF-8 doc cap (including 24 KiB JSON-escaped payload accepted over 128 KiB IPC),
      NUL-byte & recursive forbidden-key rejection, expected_rev 409 Conflict with zero disk write,
      0700/0600 permissions & symlink defense.
- C3: Bridge UDS IPC live RBAC (ignores spoofed role:"admin" for readonly), _inject_bot_isolation_env,
      Prompt Cache protection (injects [ACB_BOT_PROFILE] on turn 1, zero re-inject on turn 2 with same rev,
      re-injects on rev change), cid_owners.json registration, and atomic mcp_config.json proxy wrap.
"""

from __future__ import annotations

import ast
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
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

import bot_profiles  # noqa: E402
import bridge as bridge_mod  # noqa: E402
import studio_ipc  # noqa: E402
from studio.auth import (  # noqa: E402
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.data_sources import StudioDataSources  # noqa: E402
from studio.server import create_app  # noqa: E402

BOT_TOKEN_TEST = "123456789:EXAMPLE_PROF_TEST_TOKEN_0001"
ADMIN_UID = 111111111
READONLY_UID = 222222222
WORKER_BOT = "example_worker_bot"
COORD_BOT = "example_coord_bot"
TEST_PASS_ADMIN = "EXAMPLE_ADMIN_PASS_PROF"
TEST_PASS_RO = "EXAMPLE_RO_PASS_PROF"
TEST_PASS_FORCE = "EXAMPLE_FORCE_PASS_PROF"


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
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        raw = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, hdrs, raw
    finally:
        conn.close()


class TestStudioBotProfilesAndIPC(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_bot_prof_test_")
        self.tmp = Path(self._td.name)
        self.config_dir = self.tmp / "studio-config"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bot_bus"
        self.profiles_dir = self.tmp / "bot_profiles"
        self.workspace_dir = self.tmp / "workspace"
        self.projects_dir = self.tmp / "projects"
        self.audit_log = self.config_dir / "audit.jsonl"

        for d in (
            self.config_dir,
            self.bridge_dir,
            self.bus_dir / "jobs",
            self.bus_dir / "inbox",
            self.profiles_dir,
            self.workspace_dir / ".agents" / "skills" / "safe-catalog-skill",
            self.projects_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

        (self.workspace_dir / ".agents" / "skills" / "safe-catalog-skill" / "SKILL.md").write_text(
            "---\nname: safe-catalog-skill\ndescription: Shared catalog skill\n---\n# Catalog\n",
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
        save_users_file_atomic(
            self.config_dir / "users.json",
            {
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
            },
        )

        now = time.time()
        (self.bus_dir / "roster.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "bots": {
                        WORKER_BOT: {
                            "handle": WORKER_BOT,
                            "display_name": "Worker Bot",
                            "role": "worker",
                            "pid": os.getpid(),
                            "last_seen": now,
                            "busy": False,
                            "active_model": "gemini-3.8-flash",
                        },
                        COORD_BOT: {
                            "handle": COORD_BOT,
                            "display_name": "Coordinator Bot",
                            "role": "coordinator",
                            "pid": os.getpid(),
                            "last_seen": now,
                            "busy": False,
                            "active_model": "gemini-3.8-flash",
                        },
                    },
                }
            ),
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
        )

        self.ipc_worker = self._start_ipc_for(WORKER_BOT, role="worker")
        self.ipc_coord = self._start_ipc_for(COORD_BOT, role="coordinator")

        app = create_app(
            auth_mgr=self.auth,
            data_sources=self.sources,
            audit_log_path=self.audit_log,
        )
        self.server = TestServer(app)
        self.client = TestClient(self.server)
        await self.client.start_server()

    def _start_ipc_for(self, handle: str, *, role: str) -> studio_ipc.StudioIPCServer:
        cat_dirs = [self.workspace_dir / ".agents" / "skills"]
        pdir = self.profiles_dir
        db_p = self.tmp / "claude-mem.db"

        def _resolve_role(uid: int) -> str:
            if uid == ADMIN_UID:
                return "admin"
            if uid == READONLY_UID:
                return "readonly"
            return "denied"

        srv = studio_ipc.StudioIPCServer(
            bus_dir=self.bus_dir,
            bot_handle=handle,
            resolve_role_fn=_resolve_role,
            get_meta_fn=lambda: {"bot": handle},
            enqueue_turn_fn=lambda _req: (200, {"ok": True}),
            abort_turn_fn=lambda _tid, _uid: (200, {"ok": True}),
            get_bot_profile_fn=lambda: bot_profiles.get_bot_profile_bundle(
                handle, role=role, profiles_dir=pdir, catalog_dirs=cat_dirs, claude_mem_db=db_p
            ),
            update_bot_profile_fn=lambda req: bot_profiles.update_bot_profile(
                handle,
                expected_rev=req.get("expected_rev"),
                doc=req.get("doc"),
                content=req.get("content"),
                docs=req.get("docs"),
                skills_policy=req.get("skills_policy"),
                specialty=req.get("specialty"),
                updated_by=str(req.get("actor_username") or "admin"),
                role=role,
                profiles_dir=pdir,
                catalog_dirs=cat_dirs,
                claude_mem_db=db_p,
            ),
            get_bot_skill_fn=lambda slug: bot_profiles.get_bot_skill(
                handle, slug, role=role, profiles_dir=pdir
            ),
            put_bot_skill_fn=lambda req: bot_profiles.put_bot_skill(
                handle,
                str(req.get("slug") or ""),
                content=req.get("content"),
                expected_rev=req.get("expected_rev"),
                updated_by=str(req.get("actor_username") or "admin"),
                role=role,
                profiles_dir=pdir,
            ),
            delete_bot_skill_fn=lambda req: bot_profiles.delete_bot_skill(
                handle,
                str(req.get("slug") or ""),
                expected_rev=req.get("expected_rev"),
                updated_by=str(req.get("actor_username") or "admin"),
                role=role,
                profiles_dir=pdir,
            ),
        )
        srv.start()
        return srv

    async def asyncTearDown(self) -> None:
        await self.client.close()
        self.ipc_worker.stop()
        self.ipc_coord.stop()
        self._td.cleanup()

    async def _login(self, username: str, password: str) -> tuple[TestClient, str]:
        origin = str(self.server.make_url("/")).rstrip("/")
        cli = TestClient(self.server)
        await cli.start_server()
        resp = await cli.post(
            "/api/auth/login",
            json={"username": username, "password": password},
            headers={"Origin": origin, "Content-Type": "application/json"},
        )
        self.assertEqual(200, resp.status)
        data = await resp.json()
        return cli, str(data.get("csrf_token") or "")

    async def test_c1_profile_and_skills_auth_headers_four_layer_write_gate_and_audit(self) -> None:
        origin = str(self.server.make_url("/")).rstrip("/")

        # Unauthenticated GET -> 401
        r_unauth = await self.client.get(f"/api/bots/{WORKER_BOT}/profile")
        self.assertEqual(401, r_unauth.status)

        admin_cli, admin_csrf = await self._login("admin_user", TEST_PASS_ADMIN)
        ro_cli, ro_csrf = await self._login("ro_user", TEST_PASS_RO)
        force_cli, force_csrf = await self._login("force_user", TEST_PASS_FORCE)
        try:
            # Authenticated GET returns Cache-Control: no-store + Referrer-Policy: no-referrer & zero host paths
            r_get = await admin_cli.get(f"/api/bots/{WORKER_BOT}/profile")
            self.assertEqual(200, r_get.status)
            self.assertIn("no-store", (r_get.headers.get("Cache-Control") or "").lower())
            self.assertEqual("no-referrer", (r_get.headers.get("Referrer-Policy") or "").lower())
            raw_text = await r_get.text()
            self.assertNotIn(str(self.profiles_dir), raw_text)
            self.assertNotIn(BOT_TOKEN_TEST, raw_text)
            prof = json.loads(raw_text)
            self.assertTrue(prof["ok"])
            self.assertEqual(1, prof["rev"])
            self.assertEqual(f"bot-{WORKER_BOT}", prof["memory_project"])

            # Gate 1a: Missing/bad Origin -> 403
            r_orig = await admin_cli.put(
                f"/api/bots/{WORKER_BOT}/profile",
                json={"expected_rev": 1, "doc": "SOUL.md", "content": "hi"},
                headers={"Origin": "https://evil.example.com", "X-Studio-CSRF": admin_csrf},
            )
            self.assertEqual(403, r_orig.status)

            # Gate 1b: Bad Sec-Fetch-Site -> 403
            r_sfs = await admin_cli.put(
                f"/api/bots/{WORKER_BOT}/profile",
                json={"expected_rev": 1, "doc": "SOUL.md", "content": "hi"},
                headers={
                    "Origin": origin,
                    "Sec-Fetch-Site": "cross-site",
                    "X-Studio-CSRF": admin_csrf,
                },
            )
            self.assertEqual(403, r_sfs.status)

            # Gate 2: Non-JSON Content-Type -> 415
            r_ct = await admin_cli.put(
                f"/api/bots/{WORKER_BOT}/profile",
                data="plain text",
                headers={
                    "Origin": origin,
                    "Content-Type": "text/plain",
                    "X-Studio-CSRF": admin_csrf,
                },
            )
            self.assertEqual(415, r_ct.status)

            # Gate 3: must_change_password=True -> 403
            r_force = await force_cli.put(
                f"/api/bots/{WORKER_BOT}/profile",
                json={"expected_rev": 1, "doc": "SOUL.md", "content": "hi"},
                headers={"Origin": origin, "X-Studio-CSRF": force_csrf},
            )
            self.assertEqual(403, r_force.status)

            # Gate 4a: Missing CSRF -> 403
            r_csrf = await admin_cli.put(
                f"/api/bots/{WORKER_BOT}/profile",
                json={"expected_rev": 1, "doc": "SOUL.md", "content": "hi"},
                headers={"Origin": origin},
            )
            self.assertEqual(403, r_csrf.status)

            # Gate 4b: Readonly user -> 403 on profile PUT, skill PUT, skill DELETE
            for method, path, payload in (
                ("PUT", f"/api/bots/{WORKER_BOT}/profile", {"expected_rev": 1, "doc": "SOUL.md", "content": "x"}),
                ("PUT", f"/api/bots/{WORKER_BOT}/skills/custom-sk", {"expected_rev": 1, "content": "# S"}),
                ("DELETE", f"/api/bots/{WORKER_BOT}/skills/custom-sk", {"expected_rev": 1}),
            ):
                r_ro = await ro_cli.request(
                    method,
                    path,
                    json=payload,
                    headers={"Origin": origin, "X-Studio-CSRF": ro_csrf},
                )
                self.assertEqual(403, r_ro.status)

            # Valid admin PUT -> 200 and audit log is 0600 without logging secret/doc body
            secret_doc_marker = "UNIQUE_DOC_BODY_NEVER_IN_AUDIT_9981"
            r_ok = await admin_cli.put(
                f"/api/bots/{WORKER_BOT}/profile",
                json={"expected_rev": 1, "doc": "SOUL.md", "content": f"# Soul\n{secret_doc_marker}\n"},
                headers={"Origin": origin, "X-Studio-CSRF": admin_csrf},
            )
            self.assertEqual(200, r_ok.status)
            saved = await r_ok.json()
            self.assertEqual(2, saved["rev"])
            self.assertIn(secret_doc_marker, saved["docs"]["SOUL.md"])

            # Verify 0600 audit log recorded branches and NEVER leaked document plaintext
            self.assertTrue(self.audit_log.is_file())
            self.assertEqual(0o600, stat.S_IMODE(self.audit_log.stat().st_mode))
            audit_raw = self.audit_log.read_text(encoding="utf-8")
            self.assertIn("bot.profile.put", audit_raw)
            self.assertNotIn(secret_doc_marker, audit_raw)

            # Verify Studio bot_control.py performs ZERO direct file writes to profiles_dir
            bc_src = (REPO_ROOT / "studio" / "bot_control.py").read_text(encoding="utf-8")
            tree = ast.parse(bc_src)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, ("write_text", "write_bytes"))
        finally:
            await admin_cli.close()
            await ro_cli.close()
            await force_cli.close()

    async def test_c2_whitelist_size_limit_optimistic_lock_and_symlink_defense(self) -> None:
        origin = str(self.server.make_url("/")).rstrip("/")
        admin_cli, admin_csrf = await self._login("admin_user", TEST_PASS_ADMIN)
        hdrs = {"Origin": origin, "X-Studio-CSRF": admin_csrf}
        try:
            # Invalid doc name (case-sensitive & traversal)
            for bad_doc in ("soul.md", "../SOUL.md", "AGENTS.md", "profile.json"):
                r = await admin_cli.put(
                    f"/api/bots/{WORKER_BOT}/profile",
                    json={"expected_rev": 1, "doc": bad_doc, "content": "x"},
                    headers=hdrs,
                )
                self.assertEqual(400, r.status, f"bad_doc={bad_doc}")

            # NUL byte rejected
            r_nul = await admin_cli.put(
                f"/api/bots/{WORKER_BOT}/profile",
                json={"expected_rev": 1, "doc": "RULES.md", "content": "abc\x00def"},
                headers=hdrs,
            )
            self.assertEqual(400, r_nul.status)

            # Recursive forbidden keys rejected
            r_forb = await admin_cli.put(
                f"/api/bots/{WORKER_BOT}/profile",
                json={
                    "expected_rev": 1,
                    "skills_policy": {"mode": "allowlist", "workdir": "/tmp"},
                },
                headers=hdrs,
            )
            self.assertEqual(400, r_forb.status)

            # 24 KiB UTF-8 Markdown with heavy JSON-escaping (newlines/quotes) succeeds over 128 KiB IPC
            heavy_md = ('"\\\n' * 8192)  # exact 24576 UTF-8 bytes, expands to ~49 KiB in JSON!
            self.assertEqual(24 * 1024, len(heavy_md.encode("utf-8")))
            r_max = await admin_cli.put(
                f"/api/bots/{WORKER_BOT}/profile",
                json={"expected_rev": 1, "doc": "RULES.md", "content": heavy_md},
                headers=hdrs,
            )
            self.assertEqual(200, r_max.status)
            self.assertEqual(2, (await r_max.json())["rev"])

            # 24 KiB + 1 byte rejected with 413
            r_over = await admin_cli.put(
                f"/api/bots/{WORKER_BOT}/profile",
                json={"expected_rev": 2, "doc": "RULES.md", "content": "a" * (24 * 1024 + 1)},
                headers=hdrs,
            )
            self.assertEqual(413, r_over.status)

            # Optimistic lock mismatch -> 409 Conflict with current_rev & zero disk mutation
            rules_path = self.profiles_dir / WORKER_BOT / "RULES.md"
            before_bytes = rules_path.read_bytes()
            r_conf = await admin_cli.put(
                f"/api/bots/{WORKER_BOT}/profile",
                json={"expected_rev": 1, "doc": "RULES.md", "content": "stale overwrite"},
                headers=hdrs,
            )
            self.assertEqual(409, r_conf.status)
            conf_data = await r_conf.json()
            self.assertEqual(2, conf_data.get("current_rev"))
            self.assertEqual(before_bytes, rules_path.read_bytes())

            # Invalid skill slugs rejected
            for bad_slug in ("__proto__", "UPPER", "bad.slug", "constructor"):
                r_sl = await admin_cli.put(
                    f"/api/bots/{WORKER_BOT}/skills/{bad_slug}",
                    json={"expected_rev": 2, "content": "# X"},
                    headers=hdrs,
                )
                self.assertEqual(400, r_sl.status, f"bad_slug={bad_slug}")

            # Create, read, update, delete own skill + Coordinator aggregation check
            r_sk_put = await admin_cli.put(
                f"/api/bots/{WORKER_BOT}/skills/worker-own-skill",
                json={
                    "expected_rev": 2,
                    "content": "---\nname: worker-own-skill\ndescription: Private worker workflow\n---\n# Own\n",
                },
                headers=hdrs,
            )
            self.assertEqual(200, r_sk_put.status)
            self.assertEqual(3, (await r_sk_put.json())["rev"])

            # Verify 0700 dir & 0600 file permissions
            bot_dir = self.profiles_dir / WORKER_BOT
            skill_md = bot_dir / "skills" / "worker-own-skill" / "SKILL.md"
            self.assertEqual(0o700, stat.S_IMODE(bot_dir.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(skill_md.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE((bot_dir / "profile.json").stat().st_mode))

            # Coordinator GET profile aggregates worker's own skill
            r_coord = await admin_cli.get(f"/api/bots/{COORD_BOT}/profile")
            self.assertEqual(200, r_coord.status)
            coord_prof = await r_coord.json()
            team_slugs = {(s.get("owner"), s.get("slug")) for s in coord_prof["team_skills"]}
            self.assertIn((WORKER_BOT, "worker-own-skill"), team_slugs)

            # Delete skill with stale rev -> 409; with exact rev -> 200
            r_del_409 = await admin_cli.delete(
                f"/api/bots/{WORKER_BOT}/skills/worker-own-skill",
                json={"expected_rev": 2},
                headers=hdrs,
            )
            self.assertEqual(409, r_del_409.status)
            r_del_ok = await admin_cli.delete(
                f"/api/bots/{WORKER_BOT}/skills/worker-own-skill",
                json={"expected_rev": 3},
                headers=hdrs,
            )
            self.assertEqual(200, r_del_ok.status)
            self.assertFalse(skill_md.exists())

            # Symlink defense: replacing SOUL.md with symlink must fail-closed (403)
            outside_file = self.tmp / "outside_secret.txt"
            outside_file.write_text("do-not-overwrite", encoding="utf-8")
            soul_path = bot_dir / "SOUL.md"
            soul_path.unlink()
            soul_path.symlink_to(outside_file)
            sc_sym, res_sym = bot_profiles.update_bot_profile(
                WORKER_BOT,
                expected_rev=4,
                doc="SOUL.md",
                content="pwned",
                profiles_dir=self.profiles_dir,
            )
            self.assertEqual(403, sc_sym)
            self.assertEqual("do-not-overwrite", outside_file.read_text(encoding="utf-8"))
        finally:
            await admin_cli.close()

    async def test_c3_direct_ipc_rbac_env_injection_prompt_cache_and_mcp_config(self) -> None:
        # 1. Direct UDS IPC ignores spoofed role:"admin" for readonly UID -> 403
        body = json.dumps(
            {
                "user_id": READONLY_UID,
                "role": "admin",
                "expected_rev": 1,
                "doc": "SOUL.md",
                "content": "spoofed",
            }
        ).encode("utf-8")
        sc, _hdrs, _raw = _uds_http_request(
            self.ipc_worker.sock_path,
            "POST",
            "/ipc/bot/profile",
            headers={
                "X-Bridge-IPC-Token": self.ipc_worker.token,
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        self.assertEqual(403, sc)

        # Proxy header unconditionally rejected
        sc_px, _h2, _r2 = _uds_http_request(
            self.ipc_worker.sock_path,
            "GET",
            "/ipc/bot/profile",
            headers={
                "X-Bridge-IPC-Token": self.ipc_worker.token,
                "X-Forwarded-For": "127.0.0.1",
            },
        )
        self.assertEqual(403, sc_px)

        # 2. _inject_bot_isolation_env sets all 5 isolation env vars accurately
        with mock.patch.dict(os.environ, {"AGY_BOT_PROFILES_DIR": str(self.profiles_dir)}, clear=False):
            env_w: dict[str, str] = {}
            bridge_mod._inject_bot_isolation_env(env_w, handle=WORKER_BOT, role="worker")
            self.assertEqual(WORKER_BOT, env_w["AGY_BOT_HANDLE"])
            self.assertEqual("worker", env_w["AGY_BOT_BUS_ROLE"])
            self.assertEqual(f"bot-{WORKER_BOT}", env_w["AGY_BOT_MEMORY_PROJECT"])
            self.assertEqual("isolated", env_w["AGY_BOT_MEMORY_SCOPE"])
            self.assertEqual(str(self.profiles_dir), env_w["AGY_BOT_PROFILES_DIR"])

            env_c: dict[str, str] = {}
            bridge_mod._inject_bot_isolation_env(env_c, handle=COORD_BOT, role="coordinator")
            self.assertEqual("coordinator_all", env_c["AGY_BOT_MEMORY_SCOPE"])

        # 3. CID ownership atomic registration & lookup
        self.assertTrue(bot_profiles.register_cid_owner("cid-alpha-1234", WORKER_BOT, bus_dir=self.bus_dir))
        self.assertEqual(WORKER_BOT, bot_profiles.lookup_cid_owner("cid-alpha-1234", bus_dir=self.bus_dir))
        self.assertEqual(0o600, stat.S_IMODE((self.bus_dir / "cid_owners.json").stat().st_mode))

        # 4. Prompt renderer & Prompt Cache rev-gating verification
        bot_profiles.ensure_bot_profile(WORKER_BOT, role="worker", profiles_dir=self.profiles_dir)
        sc_u, _ = bot_profiles.update_bot_profile(
            WORKER_BOT,
            expected_rev=1,
            doc="SOUL.md",
            content="I am an isolated worker persona.",
            profiles_dir=self.profiles_dir,
        )
        self.assertEqual(200, sc_u)
        rev1, block1 = bot_profiles.render_bot_profile_prompt(
            WORKER_BOT, role="worker", profiles_dir=self.profiles_dir
        )
        self.assertEqual(2, rev1)
        self.assertIn(f"[ACB_BOT_PROFILE rev=2 handle={WORKER_BOT}", block1)
        self.assertIn("I am an isolated worker persona.", block1)

        # 5. Atomic mcp_config.json wrapper preserves altare and acb-team untouched
        mcp_cfg = self.tmp / "mcp_config.json"
        mcp_cfg.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "altare": {"command": "/usr/local/bin/altr", "args": ["mcp"]},
                        "acb-team": {"command": "python3", "args": ["bot_bus_mcp.py"]},
                        "claude-mem": {"command": "bun", "args": ["mcp-server.cjs"]},
                    }
                }
            ),
            encoding="utf-8",
        )
        changed = bot_profiles.ensure_claude_mem_proxy_configured(
            mcp_config_path=mcp_cfg,
            proxy_script=BRIDGE_DIR / "claude_mem_mcp_proxy.py",
            lock_path=self.tmp / "mcp.lock",
        )
        self.assertTrue(changed)
        updated_cfg = json.loads(mcp_cfg.read_text(encoding="utf-8"))
        self.assertEqual({"command": "/usr/local/bin/altr", "args": ["mcp"]}, updated_cfg["mcpServers"]["altare"])
        self.assertEqual({"command": "python3", "args": ["bot_bus_mcp.py"]}, updated_cfg["mcpServers"]["acb-team"])
        self.assertIn("claude_mem_mcp_proxy.py", updated_cfg["mcpServers"]["claude-mem"]["args"][0])
        # Second call is idempotent
        self.assertFalse(
            bot_profiles.ensure_claude_mem_proxy_configured(
                mcp_config_path=mcp_cfg,
                proxy_script=BRIDGE_DIR / "claude_mem_mcp_proxy.py",
                lock_path=self.tmp / "mcp.lock",
            )
        )

    async def test_c3_prompt_cache_rev_gated_injection_on_run_agy(self) -> None:
        """Verify [ACB_BOT_PROFILE] injects on turn 1, skips on turn 2 (same rev), and re-injects after rev bump."""
        pdir = self.profiles_dir
        bot_profiles.ensure_bot_profile(WORKER_BOT, role="worker", profiles_dir=pdir)
        bot_profiles.update_bot_profile(
            WORKER_BOT,
            expected_rev=1,
            doc="SOUL.md",
            content="Soul v2 cache test",
            profiles_dir=pdir,
        )

        captured_prompts: list[str] = []

        class _FakeSession:
            def __init__(self) -> None:
                self.cid = "conv-cache-0001"
                self._events: list[dict] = []

            def is_alive(self) -> bool:
                return True

            def matches(self, *_args, **_kwargs) -> bool:
                return True

            def send_user_prompt(self, text: str, raw_slash: bool = False) -> None:
                captured_prompts.append(text)
                self._events = [
                    {"event": "init", "conversation_id": self.cid},
                    {
                        "event": "result",
                        "result": {"status": "SUCCESS", "response": "ok", "conversation_id": self.cid},
                    },
                ]

            def next_event(self, timeout: float = 0.25):
                if self._events:
                    return self._events.pop(0)
                return {"event": "__eof__"}

            def get_stderr_text(self) -> str:
                return ""

        fake_sess = _FakeSession()
        skey = "cache_test_scope"

        with (
            mock.patch.dict(os.environ, {"AGY_BOT_PROFILES_DIR": str(pdir)}, clear=False),
            mock.patch.object(bridge_mod, "_current_bot_handle", return_value=WORKER_BOT),
            mock.patch.object(bridge_mod, "_current_bot_role", return_value="worker"),
            mock.patch.object(bridge_mod, "_acquire_session", return_value=(fake_sess, True)),
            mock.patch.object(bridge_mod, "save_state"),
            mock.patch.object(bridge_mod, "send_rich", return_value=(1, "ok")),
            mock.patch.object(bridge_mod, "send", return_value=1),
            mock.patch.object(bridge_mod, "tg", return_value=None),
            mock.patch.object(bridge_mod, "_record_and_relay_bot_group_msg"),
            mock.patch.object(bridge_mod.bot_bus, "BUS_DIR", str(self.bus_dir)),
        ):
            with bridge_mod.state_lock:
                bridge_mod.state.setdefault("scopes", {}).pop(skey, None)

            # Turn 1 (conv is None): MUST inject [ACB_BOT_PROFILE rev=2 ...]
            bridge_mod.run_agy(ADMIN_UID, "Turn 1 hello", scope_key=skey, user_role="admin", user_id=ADMIN_UID)
            self.assertEqual(1, len(captured_prompts))
            self.assertIn("[ACB_BOT_PROFILE rev=2 ", captured_prompts[0])
            self.assertIn("Soul v2 cache test", captured_prompts[0])

            # Turn 2 (conv set, rev unchanged): MUST NOT re-inject [ACB_BOT_PROFILE] (Prompt Cache preserved!)
            bridge_mod.run_agy(ADMIN_UID, "Turn 2 follow up", scope_key=skey, user_role="admin", user_id=ADMIN_UID)
            self.assertEqual(2, len(captured_prompts))
            self.assertNotIn("[ACB_BOT_PROFILE ", captured_prompts[1])

            # Update profile -> rev bumps to 3 -> Turn 3 MUST re-inject updated [ACB_BOT_PROFILE rev=3 ...]
            bot_profiles.update_bot_profile(
                WORKER_BOT,
                expected_rev=2,
                doc="SOUL.md",
                content="Soul v3 updated",
                profiles_dir=pdir,
            )
            bridge_mod.run_agy(ADMIN_UID, "Turn 3 after update", scope_key=skey, user_role="admin", user_id=ADMIN_UID)
            self.assertEqual(3, len(captured_prompts))
            self.assertIn("[ACB_BOT_PROFILE rev=3 ", captured_prompts[2])
            self.assertIn("Soul v3 updated", captured_prompts[2])


if __name__ == "__main__":
    unittest.main()
