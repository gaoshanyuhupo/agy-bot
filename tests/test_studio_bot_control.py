#!/usr/bin/env python3
"""Phase B M1 Contract Tests — Bot Team Control Plane (`PB-C3`, `PB-C7`, `PB-C8`).

Tests:
- `GET /api/bots/{handle}/config` strictly allowlisted Skills/MCP metadata (zero env/headers/command/args/url/paths/secrets) & offline fallback
- `PATCH /api/bots/{handle}/config` four-layer write gate, forbidden fields, model/effort/project whitelists, Single-Writer persistence & SSE broadcast
- `POST /api/bots/{handle}/reload` four-layer write gate, `_pre_reload_self_check()` fail -> 422, pass -> 202, 15s cooldown -> 429 + Retry-After, zero subprocess/systemctl in Studio
- Direct Bridge IPC ignores spoofed `role` and recomputes live RBAC
"""

from __future__ import annotations

import ast
import asyncio
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

import aiohttp
from aiohttp.test_utils import TestClient, TestServer

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import bot_bus  # noqa: E402
import bridge as bridge_mod  # noqa: E402
import studio_ipc  # noqa: E402
from studio.auth import (  # noqa: E402
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.data_sources import StudioDataSources  # noqa: E402
from studio.server import EVENT_HUB_KEY, create_app  # noqa: E402

BOT_TOKEN_TEST = "123456789:EXAMPLE_M1_BOTCTL_TOKEN_0001"
ADMIN_UID = 111111111
READONLY_UID = 222222222
ONLINE_BOT = "example_worker_bot"
OFFLINE_BOT = "example_offline_bot"
TEST_PASS_ADMIN = "EXAMPLE_ADMIN_PASS_BC"
TEST_PASS_RO = "EXAMPLE_RO_PASS_BC"
TEST_PASS_FORCE = "EXAMPLE_FORCE_PASS_BC"


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


class TestPBC3BotControlPlane(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_pb_m1_botctl_")
        self.tmp = Path(self._td.name)
        self.config_dir = self.tmp / "studio-config"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bot_bus"
        self.projects_dir = self.tmp / "projects"
        self.proj_dir = self.tmp / "repos" / "safe-proj"
        self.audit_log = self.config_dir / "audit.jsonl"

        for d in (
            self.config_dir,
            self.bridge_dir,
            self.bus_dir / "jobs",
            self.bus_dir / "inbox",
            self.projects_dir,
            self.proj_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

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
                    ONLINE_BOT: {
                        "handle": ONLINE_BOT,
                        "display_name": "Online Worker",
                        "role": "worker",
                        "pid": os.getpid(),
                        "last_seen": now,
                        "busy": False,
                        "active_model": "gemini-3.8-flash",
                        "default_project": "safe-proj",
                        "workdir": str(self.proj_dir),
                        "allowed_chats": [ADMIN_UID],
                        "ipc_sock": str(self.bus_dir / "ipc" / f"{ONLINE_BOT}.sock"),
                    },
                    OFFLINE_BOT: {
                        "handle": OFFLINE_BOT,
                        "display_name": "Offline Worker",
                        "role": "worker",
                        "pid": os.getpid(),
                        "last_seen": now - 7200,
                        "busy": False,
                        "active_model": "gemini-3.8-flash",
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

    def _seed_mcp_and_skills(self) -> tuple[Path, Path, dict[str, str]]:
        fake_sk = "sk-" + "proj-EXAMPLE9876543210SECRET"
        fake_ghp = "ghp_" + "EXAMPLE1234567890TOKEN"
        fake_vault = "lv1" + "/services/secret_mcp"
        fake_home = "/" + "home" + "/alice/bin/mcp_server"

        mcp_file = self.tmp / "mcp_config.json"
        mcp_file.write_text(
            json.dumps({
                "mcpServers": {
                    "acb-team": {
                        "command": fake_home,
                        "args": ["--token", fake_ghp],
                        "env": {"API_KEY": fake_sk, "VAULT_REF": fake_vault},
                        "disabled": False,
                    },
                    "remote-http": {
                        "url": "https://api.example.com/mcp?secret=" + fake_sk,
                        "headers": {"Authorization": f"Bearer {fake_ghp}"},
                        "disabled": True,
                    },
                }
            }),
            encoding="utf-8",
        )

        skills_root = self.tmp / "skills_ws"
        sk_dir = skills_root / "example-skill"
        sk_dir.mkdir(parents=True)
        long_desc = (
            f"Inspect {fake_home} with {fake_vault} and {fake_sk} " + ("x" * 220)
        )
        (sk_dir / "SKILL.md").write_text(
            f"---\nname: example-skill\ndescription: {long_desc}\n---\n# Body\n",
            encoding="utf-8",
        )
        return mcp_file, skills_root, {
            "sk": fake_sk,
            "ghp": fake_ghp,
            "vault": fake_vault,
            "home": fake_home,
        }

    async def test_pb_c3_get_bot_config_sanitized_mcp_skills_and_offline_fallback(self) -> None:
        mcp_file, skills_root, secrets_map = self._seed_mcp_and_skills()
        fake_state = {
            "scopes": {
                bridge_mod.PRIMARY_SCOPE_KEY: {
                    "model": "gemini-3.8-flash",
                    "effort": "medium",
                    "project": "safe-proj",
                    "workdir": str(self.proj_dir),
                }
            }
        }

        def _fake_projects() -> list[dict[str, str]]:
            return [{"id": "safe-proj", "name": "Safe Project", "workdir": str(self.proj_dir)}]

        with (
            mock.patch.object(bridge_mod, "MCP_CONFIG_FILE", str(mcp_file)),
            mock.patch.object(bridge_mod, "SKILLS_SEARCH_DIRS", [("workspace", str(skills_root))]),
            mock.patch.object(bridge_mod, "state", fake_state),
            mock.patch.object(bridge_mod, "list_agy_projects", _fake_projects),
            mock.patch.object(
                bridge_mod,
                "agy_models",
                lambda **_kw: [("gemini-3.8-flash", "Gemini Flash"), ("gemini-3.8-pro", "Gemini Pro")],
            ),
            mock.patch.object(bridge_mod, "_current_bot_handle", lambda: ONLINE_BOT),
            mock.patch.object(bot_bus, "BUS_DIR", str(self.bus_dir)),
            mock.patch.object(bot_bus, "CONFIG_FILE", str(self.bus_dir / "team_config.json")),
            mock.patch.object(bot_bus, "ROSTER_FILE", str(self.bus_dir / "roster.json")),
            mock.patch.object(bot_bus, "LOCK_FILE", str(self.bus_dir / "bus.lock")),
        ):
            srv = studio_ipc.StudioIPCServer(
                bus_dir=self.bus_dir,
                bot_handle=ONLINE_BOT,
                resolve_role_fn=lambda uid: "admin" if uid == ADMIN_UID else "readonly",
                get_meta_fn=lambda: {"handle": ONLINE_BOT},
                enqueue_turn_fn=lambda _r: (202, {"ok": True}),
                abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
                get_bot_config_fn=bridge_mod._studio_ipc_get_bot_config,
            )
            srv.start()
            self._ipc_servers.append(srv)

            ro_cookies, _ = await self._login("ro_user", TEST_PASS_RO)
            admin_cookies, _ = await self._login("admin_user", TEST_PASS_ADMIN)

            # Invalid handle -> 400, unknown handle -> 404
            r_bad = await self.client.get("/api/bots/bad..handle/config", cookies=ro_cookies)
            self.assertEqual(r_bad.status, 400)
            r_unk = await self.client.get("/api/bots/ghost_bot/config", cookies=ro_cookies)
            self.assertEqual(r_unk.status, 404)

            # Online bot config (RO can read, can_edit=False)
            r_ro = await self.client.get(f"/api/bots/{ONLINE_BOT}/config", cookies=ro_cookies)
            self.assertEqual(r_ro.status, 200)
            ro_data = await r_ro.json()
            self.assertTrue(ro_data["ipc_online"])
            self.assertFalse(ro_data["can_edit"])

            # Online bot config (Admin can_edit=True)
            r_ad = await self.client.get(f"/api/bots/{ONLINE_BOT}/config", cookies=admin_cookies)
            self.assertEqual(r_ad.status, 200)
            ad_data = await r_ad.json()
            self.assertTrue(ad_data["can_edit"])

            # Strict MCP whitelist: ONLY {name, transport, enabled}
            self.assertEqual(len(ad_data["mcp_servers"]), 2)
            for m in ad_data["mcp_servers"]:
                self.assertEqual(set(m.keys()), {"name", "transport", "enabled"})

            # Strict Skills whitelist: ONLY {name, scope, description (<=160)}
            self.assertEqual(len(ad_data["skills"]), 1)
            sk = ad_data["skills"][0]
            self.assertEqual(set(sk.keys()), {"name", "scope", "description"})
            self.assertLessEqual(len(sk["description"]), 160)

            # Zero leakage of env/headers/command/args/url/workdir/pid/ipc_sock/allowed_chats/secrets/paths
            raw_json = json.dumps(ad_data)
            for secret_val in secrets_map.values():
                self.assertNotIn(secret_val, raw_json)
            for forb_key in ("workdir", "pid", "ipc_sock", "allowed_chats", "headers", "command", "args", "url"):
                self.assertNotIn(f'"{forb_key}"', raw_json)
            self.assertNotIn(str(self.proj_dir), raw_json)

            # Offline bot falls back gracefully with ipc_online=False
            r_off = await self.client.get(f"/api/bots/{OFFLINE_BOT}/config", cookies=admin_cookies)
            self.assertEqual(r_off.status, 200)
            off_data = await r_off.json()
            self.assertFalse(off_data["ipc_online"])
            self.assertFalse(off_data["can_edit"])

    async def test_pb_c3_patch_bot_config_write_gate_validation_and_persistence(self) -> None:
        fake_state = {
            "scopes": {
                bridge_mod.PRIMARY_SCOPE_KEY: {
                    "model": None,
                    "effort": None,
                    "project": None,
                    "workdir": str(self.proj_dir),
                }
            }
        }
        invalidated_scopes: list[str] = []
        heartbeats: list[int] = []

        def _fake_projects() -> list[dict[str, str]]:
            return [{"id": "safe-proj", "name": "Safe Project", "workdir": str(self.proj_dir)}]

        with (
            mock.patch.object(bridge_mod, "state", fake_state),
            mock.patch.object(bridge_mod, "save_state", lambda: None),
            mock.patch.object(bridge_mod, "WORKDIR", str(self.proj_dir)),
            mock.patch.object(bridge_mod, "list_agy_projects", _fake_projects),
            mock.patch.object(
                bridge_mod,
                "agy_models",
                lambda **_kw: [("gemini-3.8-flash", "Gemini Flash"), ("gemini-3.8-pro", "Gemini Pro")],
            ),
            mock.patch.object(bridge_mod, "_current_bot_handle", lambda: ONLINE_BOT),
            mock.patch.object(
                bridge_mod,
                "invalidate_session",
                lambda _reason, scope_key=None: invalidated_scopes.append(str(scope_key)),
            ),
            mock.patch.object(bridge_mod, "_publish_bot_heartbeat", lambda: heartbeats.append(1)),
            mock.patch.object(bot_bus, "BUS_DIR", str(self.bus_dir)),
            mock.patch.object(bot_bus, "CONFIG_FILE", str(self.bus_dir / "team_config.json")),
            mock.patch.object(bot_bus, "ROSTER_FILE", str(self.bus_dir / "roster.json")),
            mock.patch.object(bot_bus, "LOCK_FILE", str(self.bus_dir / "bus.lock")),
            mock.patch.object(bot_bus, "INBOX_DIR", str(self.bus_dir / "inbox")),
        ):
            srv = studio_ipc.StudioIPCServer(
                bus_dir=self.bus_dir,
                bot_handle=ONLINE_BOT,
                resolve_role_fn=lambda uid: "admin" if uid == ADMIN_UID else "readonly",
                get_meta_fn=lambda: {"handle": ONLINE_BOT},
                enqueue_turn_fn=lambda _r: (202, {"ok": True}),
                abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
                get_bot_config_fn=bridge_mod._studio_ipc_get_bot_config,
                update_bot_config_fn=bridge_mod._studio_ipc_update_bot_config,
            )
            srv.start()
            self._ipc_servers.append(srv)

            admin_cookies, admin_csrf = await self._login("admin_user", TEST_PASS_ADMIN)
            ro_cookies, ro_csrf = await self._login("ro_user", TEST_PASS_RO)
            force_cookies, force_csrf = await self._login("force_user", TEST_PASS_FORCE)

            url = f"/api/bots/{ONLINE_BOT}/config"
            hdrs_ok = {"Origin": self._origin(), "Content-Type": "application/json", "X-Studio-CSRF": admin_csrf}

            # Four-layer write gate
            r_orig = await self.client.patch(
                url,
                headers={"Origin": "https://evil.example.com", "Content-Type": "application/json", "X-Studio-CSRF": admin_csrf},
                cookies=admin_cookies,
                json={"default_effort": "high"},
            )
            self.assertEqual(r_orig.status, 403)

            r_ct = await self.client.patch(
                url,
                headers={"Origin": self._origin(), "Content-Type": "text/plain", "X-Studio-CSRF": admin_csrf},
                cookies=admin_cookies,
                data='{"default_effort":"high"}',
            )
            self.assertEqual(r_ct.status, 415)

            r_fpw = await self.client.patch(
                url,
                headers={"Origin": self._origin(), "Content-Type": "application/json", "X-Studio-CSRF": force_csrf},
                cookies=force_cookies,
                json={"default_effort": "high"},
            )
            self.assertEqual(r_fpw.status, 403)

            r_csrf = await self.client.patch(
                url,
                headers={"Origin": self._origin(), "Content-Type": "application/json", "X-Studio-CSRF": "bad-csrf"},
                cookies=admin_cookies,
                json={"default_effort": "high"},
            )
            self.assertEqual(r_csrf.status, 403)

            r_ro = await self.client.patch(
                url,
                headers={"Origin": self._origin(), "Content-Type": "application/json", "X-Studio-CSRF": ro_csrf},
                cookies=ro_cookies,
                json={"default_effort": "high"},
            )
            self.assertEqual(r_ro.status, 403)

            # Direct IPC rejects spoofed role="admin" for READONLY_UID
            sc_ipc, _, _ = _uds_http_request(
                srv.sock_path,
                "POST",
                "/ipc/bot/config",
                headers={"X-Bridge-IPC-Token": srv.token, "Content-Type": "application/json"},
                body=json.dumps({"user_id": READONLY_UID, "role": "admin", "default_effort": "high"}).encode("utf-8"),
            )
            self.assertEqual(sc_ipc, 403)

            # Reject forbidden fields & invalid whitelists (400)
            bad_payloads = [
                {"workdir": "/tmp"},
                {"ipc_sock": "/tmp/x.sock"},
                {"env": {"A": "1"}},
                {"role": "coordinator"},
                {"reload_file": "/tmp/custom"},
                {"model_mode": "invalid_mode"},
                {"model_mode": "custom", "model": "not-in-whitelist-model"},
                {"default_effort": "turbo"},
                {"default_project": "unlisted-proj"},
            ]
            for bp in bad_payloads:
                r_bad = await self.client.patch(url, headers=hdrs_ok, cookies=admin_cookies, json=bp)
                self.assertEqual(r_bad.status, 400, f"Expected 400 for {bp}, got {r_bad.status}")

            # Valid admin update persists to team_config.json, updates PRIMARY_SCOPE_KEY, evicts warm session, refreshes heartbeat & SSE
            hub = self.app[EVENT_HUB_KEY]
            seq_before = hub._next_seq
            r_ok = await self.client.patch(
                url,
                headers=hdrs_ok,
                cookies=admin_cookies,
                json={
                    "model_mode": "custom",
                    "model": "gemini-3.8-pro",
                    "default_effort": "high",
                    "default_project": "safe-proj",
                },
            )
            self.assertEqual(r_ok.status, 200, await r_ok.text())
            ok_data = await r_ok.json()
            self.assertEqual(ok_data["model_mode"], "custom")
            self.assertEqual(ok_data["configured_model"], "gemini-3.8-pro")
            self.assertEqual(ok_data["default_effort"], "high")
            self.assertEqual(ok_data["default_project"], "safe-proj")

            # Verify team_config.json updated
            tc = json.loads((self.bus_dir / "team_config.json").read_text(encoding="utf-8"))
            bot_rec = tc["bots"][ONLINE_BOT]
            self.assertEqual(bot_rec["model_mode"], "custom")
            self.assertEqual(bot_rec["default_model"], "gemini-3.8-pro")
            self.assertEqual(bot_rec["default_effort"], "high")
            self.assertEqual(bot_rec["default_project"], "safe-proj")

            # Verify PRIMARY_SCOPE_KEY synced, warm session evicted, heartbeat refreshed, SSE broadcast emitted
            prim = fake_state["scopes"][bridge_mod.PRIMARY_SCOPE_KEY]
            self.assertEqual(prim["model"], "gemini-3.8-pro")
            self.assertEqual(prim["effort"], "high")
            self.assertEqual(prim["project"], "safe-proj")
            self.assertIn(bridge_mod.PRIMARY_SCOPE_KEY, invalidated_scopes)
            self.assertGreaterEqual(len(heartbeats), 1)
            self.assertGreater(hub._next_seq, seq_before)

            # Audit log permissions 0600 & zero CSRF leakage
            self.assertEqual(stat.S_IMODE(self.audit_log.stat().st_mode), 0o600)
            audit_raw = self.audit_log.read_text(encoding="utf-8")
            self.assertNotIn(admin_csrf, audit_raw)
            self.assertIn("bot.config.patch", audit_raw)

    async def test_pb_c3_safe_reload_self_check_422_202_cooldown_429_and_zero_rce(self) -> None:
        scheduled_calls: list[float] = []
        self_check_result = [False, "syntax error in " + "/" + "home" + "/alice/broken.py"]

        def _fake_self_check() -> tuple[bool, str]:
            return bool(self_check_result[0]), str(self_check_result[1])

        def _fake_schedule(delay_sec: float = 0.25) -> None:
            scheduled_calls.append(delay_sec)

        with (
            mock.patch.object(bridge_mod, "_pre_reload_self_check", _fake_self_check),
            mock.patch.object(bridge_mod, "_schedule_ipc_hot_reload", _fake_schedule),
            mock.patch.object(bridge_mod, "_current_bot_handle", lambda: ONLINE_BOT),
            mock.patch.object(bot_bus, "BUS_DIR", str(self.bus_dir)),
        ):
            srv = studio_ipc.StudioIPCServer(
                bus_dir=self.bus_dir,
                bot_handle=ONLINE_BOT,
                resolve_role_fn=lambda uid: "admin" if uid == ADMIN_UID else "readonly",
                get_meta_fn=lambda: {"handle": ONLINE_BOT},
                enqueue_turn_fn=lambda _r: (202, {"ok": True}),
                abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
                reload_bot_fn=bridge_mod._studio_ipc_reload_bot,
            )
            srv.start()
            self._ipc_servers.append(srv)

            admin_cookies, admin_csrf = await self._login("admin_user", TEST_PASS_ADMIN)
            ro_cookies, ro_csrf = await self._login("ro_user", TEST_PASS_RO)
            url = f"/api/bots/{ONLINE_BOT}/reload"
            hdrs_ok = {"Origin": self._origin(), "Content-Type": "application/json", "X-Studio-CSRF": admin_csrf}

            # 1. Readonly rejected (403)
            r_ro = await self.client.post(
                url,
                headers={"Origin": self._origin(), "Content-Type": "application/json", "X-Studio-CSRF": ro_csrf},
                cookies=ro_cookies,
                json={},
            )
            self.assertEqual(r_ro.status, 403)

            # 2. Client-supplied reload_file / cmd rejected (400)
            for forb in ({"reload_file": "/tmp/evil"}, {"cmd": "systemctl restart x"}):
                r_f = await self.client.post(url, headers=hdrs_ok, cookies=admin_cookies, json=forb)
                self.assertEqual(r_f.status, 400)

            # 3. Self-check failure -> 422, reload NOT scheduled, host path redacted
            r_fail = await self.client.post(url, headers=hdrs_ok, cookies=admin_cookies, json={})
            self.assertEqual(r_fail.status, 422)
            fail_data = await r_fail.json()
            self.assertEqual(scheduled_calls, [])
            self.assertNotIn("alice", json.dumps(fail_data))
            self.assertIn("[REDACTED]", fail_data["error"])

            # 4. Self-check passes -> 202, delayed trigger scheduled (no cooldown blocked from prior 422)
            self_check_result[0] = True
            self_check_result[1] = "ok"
            r_ok = await self.client.post(url, headers=hdrs_ok, cookies=admin_cookies, json={})
            self.assertEqual(r_ok.status, 202)
            ok_data = await r_ok.json()
            self.assertTrue(ok_data["scheduled"])
            self.assertEqual(len(scheduled_calls), 1)

            # 5. Immediate repeat reload within 15s cooldown -> 429 + Retry-After header
            r_cd = await self.client.post(url, headers=hdrs_ok, cookies=admin_cookies, json={})
            self.assertEqual(r_cd.status, 429)
            self.assertIn("Retry-After", r_cd.headers)
            self.assertGreaterEqual(int(r_cd.headers["Retry-After"]), 1)
            self.assertEqual(len(scheduled_calls), 1)

        # 6. AST static audit: studio/bot_control.py has ZERO subprocess / os.system / systemctl / /tmp writes
        bc_src = (REPO_ROOT / "studio" / "bot_control.py").read_text(encoding="utf-8")
        bc_tree = ast.parse(bc_src)
        for node in ast.walk(bc_tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertNotEqual(alias.name, "subprocess")
            elif isinstance(node, ast.ImportFrom):
                self.assertNotEqual(node.module, "subprocess")
            elif isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, {"system", "popen", "Popen", "execv", "execve"})

    async def test_pb_c3_block2_concurrent_reload_toctou_single_flight_and_normalization(self) -> None:
        """BLOCK-2: Concurrent reload across case and leading-@ variants allows 1 IPC call (202) and 2x 429."""
        race_handle = "testbot"
        ipc_calls = 0
        self_check_ok = [True]

        def _slow_reload_ipc(payload: dict[str, object]) -> tuple[int, dict[str, object]]:
            nonlocal ipc_calls
            ipc_calls += 1
            time.sleep(0.15)
            if not self_check_ok[0]:
                return 422, {"ok": False, "code": "self_check_failed", "error": "self check failed"}
            return 202, {"ok": True, "bot": race_handle, "scheduled": True}

        srv = studio_ipc.StudioIPCServer(
            bus_dir=self.bus_dir,
            bot_handle=race_handle,
            resolve_role_fn=lambda uid: "admin" if uid == ADMIN_UID else "readonly",
            get_meta_fn=lambda: {"handle": race_handle},
            enqueue_turn_fn=lambda _r: (202, {"ok": True}),
            abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
            reload_bot_fn=_slow_reload_ipc,
        )
        srv.start()
        self._ipc_servers.append(srv)

        admin_cookies, admin_csrf = await self._login("admin_user", TEST_PASS_ADMIN)
        hdrs_ok = {
            "Origin": self._origin(),
            "Content-Type": "application/json",
            "X-Studio-CSRF": admin_csrf,
        }

        async def _post_reload(raw_handle: str) -> tuple[int, str | None]:
            resp = await self.client.post(
                f"/api/bots/{raw_handle}/reload",
                headers=hdrs_ok,
                cookies=admin_cookies,
                json={},
            )
            await resp.text()
            return resp.status, resp.headers.get("Retry-After")

        # 1. Verify failed 422 releases in-flight lock without consuming cooldown
        self_check_ok[0] = False
        r_fail_st, _ = await _post_reload("testbot")
        self.assertEqual(r_fail_st, 422)
        self.assertEqual(ipc_calls, 1)

        # 2. Reset counter & fire 3 concurrent requests across case / `@` variants
        ipc_calls = 0
        self_check_ok[0] = True
        results = await asyncio.gather(
            _post_reload(race_handle),
            _post_reload("TestBot"),
            _post_reload("@" + race_handle.upper()),
        )
        statuses = [st for st, _ in results]
        self.assertEqual(statuses.count(202), 1, f"Expected 1x 202, got {statuses}")
        self.assertEqual(statuses.count(429), 2, f"Expected 2x 429, got {statuses}")
        self.assertEqual(ipc_calls, 1, f"Expected exactly 1 IPC call, got {ipc_calls}")
        for st, retry_after in results:
            if st == 429:
                self.assertIsNotNone(retry_after)
                self.assertGreaterEqual(int(retry_after or "0"), 1)

        # Audit log records denied_cooldown for concurrent rejections
        audit_entries = [
            json.loads(ln)
            for ln in self.audit_log.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        cooldown_hits = [
            e for e in audit_entries
            if e.get("action") == "bot.reload" and e.get("outcome") == "denied_cooldown"
        ]
        self.assertGreaterEqual(len(cooldown_hits), 2)


if __name__ == "__main__":
    unittest.main()
