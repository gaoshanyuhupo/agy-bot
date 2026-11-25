#!/usr/bin/env python3
"""Comprehensive M3 Federation Control Plane, WebUI, Telegram & Export Tests (M3-C1..M3-C8).

Covers:
- M3-C1: Studio 4-layer Admin write gate (9 negative counterexamples) & server-side OwnerAuth.
- M3-C2: One-time Bearer token lifecycle, immediate Kill-Switch, zero leakage across GET/audit/SSE/logs.
- M3-C3: Multi-team dynamic leader assignment across heterogeneous agent kinds without silent escalation.
- M3-C4: Anti-symlink/traversal fail-closed audit reader & anti-SSRF loopback-only Hub health probe.
- M3-C5: Frontend one-time token zero-persistence static invariants, CSP compliance, zero-data `/federation` shell.
- M3-C6: Telegram `/team` 100% backward compatibility & `/agent` strict human-Admin + clean-session RBAC.
- M3-C7: Telegram group chat (`chat_id < 0`) hard pre-block for plaintext `agy_fed_` tokens & DM-only delivery.
- M3-C8: Public export whitelist coverage for all federation modules & test suites.
"""

from __future__ import annotations

import ast
import asyncio
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (str(REPO_ROOT), str(BRIDGE_DIR), str(SCRIPTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import access_control  # noqa: E402
import bot_bus  # noqa: E402
import bridge as tg_bridge  # noqa: E402
try:
    import export_public  # noqa: E402
except ImportError:
    export_public = None  # type: ignore[assignment]
import federation_hub  # noqa: E402
import federation_registry  # noqa: E402
import memory_guard  # noqa: E402
from studio.auth import (  # noqa: E402
    SESSION_COOKIE_NAME,
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.data_sources import StudioDataSources, redact_secrets_only  # noqa: E402
from studio.event_hub import _sanitize_event_value  # noqa: E402
from studio.federation_service import (  # noqa: E402
    StudioFederationService,
    _validate_loopback_hub_target,
)
from studio.server import (  # noqa: E402
    EVENT_HUB_KEY,
    FEDERATION_SERVICE_KEY,
    SanitizedAccessLogger,
    create_app,
)

ADMIN_UID = 111111111
READONLY_UID = 222222222
FORCED_PW_UID = 333333333
GROUP_CHAT_ID = -1001234567890
MIRROR_GROUP_ID = GROUP_CHAT_ID - 1

ADMIN_PASS = "EXAMPLE_FED_ADMIN_PASS_01"
RO_PASS = "EXAMPLE_FED_RO_PASS_01"
FORCED_PASS = "EXAMPLE_FED_FORCED_PASS_01"

# Dynamically assembled synthetic fixtures (zero real credentials)
SYNTH_PREFIX = "agy_" + "fed_"
SYNTH_FAKE_SK = "sk-" + "EXAMPLE_FED_TEST_PLACEHOLDER_0001"
SYNTH_FAKE_FED = SYNTH_PREFIX + "demo.tok_000011112222.EXAMPLE_PLACEHOLDER_SECRET_XYZ"
SYNTH_IMDS_IP = ".".join(("169", "254", "169", "254"))
SYNTH_IMDS_URL = "http://" + SYNTH_IMDS_IP + "/latest/meta-data"
SYNTH_HOST_PATH = "/home/" + "example_user/secret.txt"


def _clean_owner_env() -> dict[str, str]:
    clean = dict(os.environ)
    for k in (
        "AGY_UNTRUSTED_SESSION",
        "AGY_MEMORY_READONLY",
        "AGY_RBAC_ROLE",
        "AGY_AGENT_ORIGIN",
        "AGY_TRUST_LEVEL",
        "AGY_BOT_BUS_ROLE",
    ):
        clean.pop(k, None)
    return clean


class _FederationTestBase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_fed_studio_")
        self.tmp = Path(self._td.name)
        self.studio_cfg = self.tmp / "studio-cfg"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bus"
        self.audit_log = self.studio_cfg / "studio_audit.jsonl"
        for d in (self.studio_cfg, self.bridge_dir, self.bus_dir):
            d.mkdir(parents=True, exist_ok=True)

        (self.bridge_dir / ".env").write_text(
            "\n".join(
                [
                    "AGY_TG_BOT_TOKEN=123456789:EXAMPLE_FED_TEST_TOKEN_0001",
                    f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID},{FORCED_PW_UID}",
                    f"AGY_TG_ADMIN_USERS={ADMIN_UID},{FORCED_PW_UID}",
                    f"AGY_TG_READONLY_USERS={READONLY_UID}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        self._env_patch = mock.patch.dict(os.environ, _clean_owner_env(), clear=True)
        self._env_patch.start()

        now_i = int(time.time())
        save_users_file_atomic(
            self.studio_cfg / "users.json",
            {
                "adminuser": {
                    "username": "AdminUser",
                    "user_id": ADMIN_UID,
                    "role": "admin",
                    "bot": "main",
                    "password_hash": hash_password_scrypt(ADMIN_PASS),
                    "must_change_password": False,
                    "enabled": True,
                    "password_version": 1,
                    "created_at": now_i,
                    "updated_at": now_i,
                },
                "vieweruser": {
                    "username": "ViewerUser",
                    "user_id": READONLY_UID,
                    "role": "readonly",
                    "bot": "main",
                    "password_hash": hash_password_scrypt(RO_PASS),
                    "must_change_password": False,
                    "enabled": True,
                    "password_version": 1,
                    "created_at": now_i,
                    "updated_at": now_i,
                },
                "forcedpwuser": {
                    "username": "ForcedPwUser",
                    "user_id": FORCED_PW_UID,
                    "role": "admin",
                    "bot": "main",
                    "password_hash": hash_password_scrypt(FORCED_PASS),
                    "must_change_password": True,
                    "enabled": True,
                    "password_version": 1,
                    "created_at": now_i,
                    "updated_at": now_i,
                },
            },
        )

        self.auth_mgr = StudioAuthManager(
            config_dir=self.studio_cfg,
            bridge_dir=self.bridge_dir,
            auth_mode="password",
        )
        self.sources = StudioDataSources(
            bus_dir=self.bus_dir,
            projects_dir=self.tmp / "projects",
            brain_root=self.tmp / "sessions",
            live_browser_config_dir=self.tmp / "live-browser",
        )
        self.app = create_app(
            auth_mgr=self.auth_mgr,
            data_sources=self.sources,
            audit_log_path=self.audit_log,
            event_watcher_interval=60.0,
            federation_hub_host="127.0.0.1",
            federation_hub_port=1,  # default unreachable closed port unless overridden in test
        )
        self.fed_svc: StudioFederationService = self.app[FEDERATION_SERVICE_KEY]
        self.server = TestServer(self.app)
        await self.server.start_server()
        self.client = TestClient(self.server, cookie_jar=aiohttp.DummyCookieJar())
        await self.client.start_server()
        self.origin = f"http://{self.server.host}:{self.server.port}"

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.server.close()
        self._env_patch.stop()
        self._td.cleanup()

    async def _login(self, username: str, password: str) -> tuple[str, str]:
        resp = await self.client.post(
            "/api/auth/login",
            headers={"Origin": self.origin, "Content-Type": "application/json"},
            data=json.dumps({"username": username, "password": password}),
        )
        self.assertEqual(resp.status, 200, await resp.text())
        data = await resp.json()
        cookie = resp.cookies[SESSION_COOKIE_NAME].value
        return cookie, data["csrf_token"]

    def _admin_headers(self, cookie: str, csrf: str, **extra: str) -> dict[str, str]:
        h = {
            "Origin": self.origin,
            "Sec-Fetch-Site": "same-origin",
            "Content-Type": "application/json",
            "X-Studio-CSRF": csrf,
            "Cookie": f"{SESSION_COOKIE_NAME}={cookie}",
        }
        h.update(extra)
        return h


class TestM3C1StudioWriteGateAndOwnerAuth(_FederationTestBase):
    """M3-C1: 9 negative write-gate counterexamples + server-only OwnerAuth construction."""

    async def test_m3_c1_all_nine_write_gate_counterexamples_fail_closed(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        ro_cookie, ro_csrf = await self._login("ViewerUser", RO_PASS)
        forced_cookie, forced_csrf = await self._login("ForcedPwUser", FORCED_PASS)

        valid_payload = json.dumps(
            {"agent_id": "hermes_gate_test", "kind": "hermes_local", "profile": "default"}
        )

        with mock.patch.object(
            federation_registry, "make_owner_auth", wraps=federation_registry.make_owner_auth
        ) as spy_owner_auth:
            # 1. Unauthenticated (no cookie) -> 401
            r1 = await self.client.post(
                "/api/federation/agents",
                headers={"Origin": self.origin, "Content-Type": "application/json"},
                data=valid_payload,
            )
            self.assertEqual(r1.status, 401)
            self.assertEqual((await r1.json()).get("source"), "studio_auth")
            self.assertEqual(r1.headers.get("Cache-Control"), "no-store, max-age=0")
            self.assertEqual(r1.headers.get("Referrer-Policy"), "no-referrer")

            # 2. must_change_password=True -> 403
            r2 = await self.client.post(
                "/api/federation/agents",
                headers=self._admin_headers(forced_cookie, forced_csrf),
                data=valid_payload,
            )
            self.assertEqual(r2.status, 403)
            self.assertEqual((await r2.json()).get("source"), "studio_auth")

            # 3. readonly user -> 403
            r3 = await self.client.post(
                "/api/federation/agents",
                headers=self._admin_headers(ro_cookie, ro_csrf),
                data=valid_payload,
            )
            self.assertEqual(r3.status, 403)
            self.assertEqual((await r3.json()).get("source"), "studio_auth")

            # 4a. Missing Origin -> 403
            h_no_orig = self._admin_headers(admin_cookie, admin_csrf)
            h_no_orig.pop("Origin", None)
            r4a = await self.client.post("/api/federation/agents", headers=h_no_orig, data=valid_payload)
            self.assertEqual(r4a.status, 403)
            self.assertEqual((await r4a.json()).get("source"), "studio_auth")

            # 4b. Cross-site Origin -> 403
            r4b = await self.client.post(
                "/api/federation/agents",
                headers=self._admin_headers(admin_cookie, admin_csrf, Origin="https://evil.example.com"),
                data=valid_payload,
            )
            self.assertEqual(r4b.status, 403)
            self.assertEqual((await r4b.json()).get("source"), "studio_auth")

            # 5. Sec-Fetch-Site: cross-site -> 403
            r5 = await self.client.post(
                "/api/federation/agents",
                headers=self._admin_headers(admin_cookie, admin_csrf, **{"Sec-Fetch-Site": "cross-site"}),
                data=valid_payload,
            )
            self.assertEqual(r5.status, 403)
            self.assertEqual((await r5.json()).get("source"), "studio_auth")

            # 6. Content-Type: text/plain & application/x-www-form-urlencoded -> 415
            for bad_ct in ("text/plain", "application/x-www-form-urlencoded"):
                r6 = await self.client.post(
                    "/api/federation/agents",
                    headers=self._admin_headers(admin_cookie, admin_csrf, **{"Content-Type": bad_ct}),
                    data=valid_payload,
                )
                self.assertEqual(r6.status, 415)
                self.assertEqual((await r6.json()).get("source"), "studio_auth")

            # 7. Missing / forged X-Studio-CSRF -> 403
            h_no_csrf = self._admin_headers(admin_cookie, admin_csrf)
            h_no_csrf.pop("X-Studio-CSRF", None)
            r7a = await self.client.post("/api/federation/agents", headers=h_no_csrf, data=valid_payload)
            self.assertEqual(r7a.status, 403)
            r7b = await self.client.post(
                "/api/federation/agents",
                headers=self._admin_headers(admin_cookie, "forged-csrf-value"),
                data=valid_payload,
            )
            self.assertEqual(r7b.status, 403)

            # 9. Client body privilege/secret injection -> 400
            for forged in (
                {"agent_id": "a1", "kind": "hermes_local", "profile": "default", "owner_auth": {"is_owner": True}},
                {"agent_id": "a1", "kind": "hermes_local", "profile": "default", "is_owner": True},
                {"agent_id": "a1", "kind": "hermes_local", "profile": "default", "role": "owner"},
                {"agent_id": "a1", "kind": "hermes_local", "profile": "default", "token_records": []},
                {"agent_id": "a1", "kind": "hermes_local", "profile": "default", "token_hash": "abcd"},
                {"agent_id": "a1", "kind": "hermes_local", "profile": "default", "salt": "1234"},
                {"agent_id": "a1", "kind": "hermes_local", "profile": "default", "api_key": SYNTH_FAKE_SK},
                {"agent_id": "a1", "kind": "hermes_local", "profile": "default", "token": SYNTH_FAKE_FED},
                {"agent_id": "a1", "kind": "hermes_local", "profile": "default", "password": "EXAMPLE_RAW_PASSWORD"},
                {"agent_id": "a1", "kind": "hermes_local", "profile": "default", "display_name": SYNTH_FAKE_SK},
            ):
                r9 = await self.client.post(
                    "/api/federation/agents",
                    headers=self._admin_headers(admin_cookie, admin_csrf),
                    data=json.dumps(forged),
                )
                self.assertEqual(r9.status, 400, f"Expected 400 for forged payload {forged!r}")

            # 8. Revoked / destroyed session -> 401/403
            r_logout = await self.client.post(
                "/api/auth/logout",
                headers=self._admin_headers(admin_cookie, admin_csrf),
                data="{}",
            )
            self.assertEqual(r_logout.status, 200)
            r8 = await self.client.post(
                "/api/federation/agents",
                headers=self._admin_headers(admin_cookie, admin_csrf),
                data=valid_payload,
            )
            self.assertIn(r8.status, (401, 403))

            # OwnerAuth must NEVER have been constructed on any rejected call
            self.assertEqual(spy_owner_auth.call_count, 0)

        # Disk files remain untouched
        self.assertFalse(Path(federation_registry.agents_file_path(str(self.bus_dir))).exists())
        self.assertFalse(Path(federation_registry.teams_file_path(str(self.bus_dir))).exists())


class TestM3C2TokenLifecycleKillSwitchZeroLeakage(_FederationTestBase):
    """M3-C2: One-time token delivery, immediate Kill-Switch, zero leakage across GET/audit/SSE/logs."""

    async def test_m3_c2_token_mint_rotate_zero_leak_and_instant_kill_switch(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        headers = self._admin_headers(admin_cookie, admin_csrf)

        # 1. Create agent with mint_token=True -> returns one-time token with no-store & Pragma: no-cache
        r_create = await self.client.post(
            "/api/federation/agents",
            headers=headers,
            data=json.dumps(
                {
                    "agent_id": "hermes_alpha",
                    "display_name": "Hermes Alpha",
                    "kind": "hermes_local",
                    "profile": "alpha",
                    "capabilities": {"coordinator_peer": True, "can_dispatch": True, "can_receive": True},
                    "mint_token": True,
                }
            ),
        )
        self.assertEqual(r_create.status, 200, await r_create.text())
        self.assertEqual(r_create.headers.get("Cache-Control"), "no-store, max-age=0")
        self.assertEqual(r_create.headers.get("Pragma"), "no-cache")
        d_create = await r_create.json()
        tok1 = d_create["token"]
        self.assertTrue(tok1.startswith(SYNTH_PREFIX))
        self.assertIsNotNone(federation_registry.verify_agent_token(tok1, bus_dir=str(self.bus_dir)))

        # 2. Mint additional token via POST /tokens
        r_mint = await self.client.post(
            "/api/federation/agents/hermes_alpha/tokens",
            headers=headers,
            data=json.dumps({"label": "extra"}),
        )
        self.assertEqual(r_mint.status, 200)
        self.assertEqual(r_mint.headers.get("Cache-Control"), "no-store, max-age=0")
        self.assertEqual(r_mint.headers.get("Pragma"), "no-cache")
        tok2 = (await r_mint.json())["token"]
        self.assertTrue(tok2.startswith(SYNTH_PREFIX))

        # 3. Rotate token -> revokes tok1 & tok2, returns tok3
        r_rot = await self.client.post(
            "/api/federation/agents/hermes_alpha/rotate",
            headers=headers,
            data=json.dumps({"label": "rot1", "revoke_existing": True}),
        )
        self.assertEqual(r_rot.status, 200)
        self.assertEqual(r_rot.headers.get("Cache-Control"), "no-store, max-age=0")
        self.assertEqual(r_rot.headers.get("Pragma"), "no-cache")
        d_rot = await r_rot.json()
        tok3 = d_rot["token"]
        self.assertEqual(d_rot["revoked_previous"], 2)
        self.assertIsNone(federation_registry.verify_agent_token(tok1, bus_dir=str(self.bus_dir)))
        self.assertIsNone(federation_registry.verify_agent_token(tok2, bus_dir=str(self.bus_dir)))
        self.assertIsNotNone(federation_registry.verify_agent_token(tok3, bus_dir=str(self.bus_dir)))

        # 4. Inspect ALL GET endpoints, Studio audit JSONL, SSE ring buffer, and AccessLogger -> 0 leaks
        get_headers = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        for path in (
            "/api/federation/overview",
            "/api/federation/agents",
            "/api/federation/agents/hermes_alpha",
            "/api/federation/teams",
            "/api/federation/audit",
        ):
            rg = await self.client.get(path, headers=get_headers)
            self.assertEqual(rg.status, 200, f"GET {path} failed")
            txt = await rg.text()
            for forbidden in (SYNTH_PREFIX, tok1, tok2, tok3, "token_hash", "token_records", '"salt"'):
                self.assertNotIn(forbidden, txt, f"Leak {forbidden!r} found in GET {path}")

        audit_txt = self.audit_log.read_text(encoding="utf-8")
        for forbidden in (SYNTH_PREFIX, tok1, tok2, tok3, "token_hash", "token_records"):
            self.assertNotIn(forbidden, audit_txt)

        # SSE buffer & sanitizer checks
        event_hub = self.app[EVENT_HUB_KEY]
        for _seq, _etype, ev_data in list(event_hub._events):
            ev_txt = json.dumps(ev_data)
            for forbidden in (SYNTH_PREFIX, tok1, tok2, tok3, "token_hash", "token_records", "salt"):
                self.assertNotIn(forbidden, ev_txt)

        sanitized_ev = _sanitize_event_value(
            {
                "agent_id": "hermes_alpha",
                "token_hash": "deadbeef",
                "token_records": [{"salt": "1234"}],
                "salt": "abcd",
                "raw_token": tok3,
                "plaintext_token": tok3,
                "bearer_token": tok3,
                "note": f"oops {tok3}",
            }
        )
        for forbidden_k in ("token_hash", "token_records", "salt", "raw_token", "plaintext_token", "bearer_token"):
            self.assertNotIn(forbidden_k, sanitized_ev)
        self.assertNotIn(SYNTH_PREFIX, json.dumps(sanitized_ev))
        self.assertNotIn(SYNTH_PREFIX, redact_secrets_only(f"token is {SYNTH_FAKE_FED}"))

        # SanitizedAccessLogger strips query params
        self.assertEqual(
            SanitizedAccessLogger.sanitize_target("/api/federation/agents", f"/api/federation/agents?t={tok3}"),
            "/api/federation/agents",
        )

        # 5. Real FederationHubServer verifies tok3 works BEFORE Kill-Switch, then returns 401 IMMEDIATELY AFTER
        hub = federation_hub.FederationHubServer(
            host="127.0.0.1",
            port=0,
            bus_dir=str(self.bus_dir),
            require_replay_headers=False,
        )
        hub_thread = threading.Thread(target=hub.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        hub_thread.start()
        try:
            hub_url = f"http://127.0.0.1:{hub.server_port}/hub/v1/me"
            async with aiohttp.ClientSession(trust_env=False) as http:
                async with http.get(hub_url, headers={"Authorization": f"Bearer {tok3}"}) as pre_resp:
                    self.assertEqual(pre_resp.status, 200)

                # Trigger Kill-Switch via Studio API
                r_rev = await self.client.post(
                    "/api/federation/agents/hermes_alpha/revoke",
                    headers=headers,
                    data="{}",
                )
                self.assertEqual(r_rev.status, 200)
                self.assertTrue((await r_rev.json())["agent"]["revoked"])

                # Same-millisecond invalidation in both registry and live Hub
                self.assertIsNone(federation_registry.verify_agent_token(tok3, bus_dir=str(self.bus_dir)))
                async with http.get(hub_url, headers={"Authorization": f"Bearer {tok3}"}) as post_resp:
                    self.assertEqual(post_resp.status, 401)
        finally:
            hub.shutdown()
            hub.server_close()
            hub_thread.join(timeout=2.0)


class TestM3C3MultiTeamDynamicLeaderAndLeastPrivilege(_FederationTestBase):
    """M3-C3: Dynamic leader assignment across heterogeneous kinds, invalid ID rejection, no silent escalation."""

    async def test_m3_c3_heterogeneous_leaders_and_no_silent_escalation(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        headers = self._admin_headers(admin_cookie, admin_csrf)

        agents_to_add = [
            {"agent_id": "ag_hlocal", "kind": "hermes_local", "profile": "p1", "capabilities": {"can_dispatch": False}},
            {"agent_id": "ag_hremote", "kind": "hermes_remote", "endpoint_url": "https://h.example.com", "capabilities": {"can_dispatch": True}},
            {"agent_id": "ag_muse", "kind": "muse_remote", "endpoint_url": "https://m.example.com", "capabilities": {"can_dispatch": False}},
            {"agent_id": "ag_a2a", "kind": "http_a2a", "endpoint_url": "https://a.example.com", "capabilities": {"can_dispatch": True}},
            {"agent_id": "ag_pull", "kind": "pull_worker", "capabilities": {"can_dispatch": False}},
            {"agent_id": "ag_local", "kind": "agy_local", "capabilities": {"can_dispatch": True}},
            {"agent_id": "ag_revoked", "kind": "hermes_local", "profile": "p2"},
        ]
        for payload in agents_to_add:
            r = await self.client.post("/api/federation/agents", headers=headers, data=json.dumps(payload))
            self.assertEqual(r.status, 200, await r.text())

        # Revoke ag_revoked
        r_rev = await self.client.post("/api/federation/agents/ag_revoked/revoke", headers=headers, data="{}")
        self.assertEqual(r_rev.status, 200)

        # 1. Create team with hermes_local (can_dispatch=False) -> succeeds WITHOUT silent privilege escalation
        r_ct = await self.client.post(
            "/api/federation/teams",
            headers=headers,
            data=json.dumps(
                {
                    "team_id": "team-ops",
                    "display_name": "Ops Team",
                    "leader_agent_id": "ag_hlocal",
                    "co_leaders": ["ag_muse"],
                    "members": ["ag_pull", "ag_local"],
                }
            ),
        )
        self.assertEqual(r_ct.status, 200, await r_ct.text())
        d_ct = await r_ct.json()
        self.assertEqual(d_ct["team"]["leader_agent_id"], "ag_hlocal")
        self.assertIs(d_ct["leader_can_dispatch"], False)
        self.assertTrue(d_ct["warnings"])

        # Verify ag_hlocal was NOT silently escalated on disk
        rec_hlocal = federation_registry.get_agent("ag_hlocal", bus_dir=str(self.bus_dir))
        assert rec_hlocal is not None
        self.assertFalse(rec_hlocal["capabilities"]["can_dispatch"])
        self.assertFalse(rec_hlocal["capabilities"]["coordinator_peer"])
        self.assertFalse(rec_hlocal["capabilities"]["host_server_invoke"])

        # Dynamically switch leader across all heterogeneous kinds
        for next_leader, expect_dispatch in (
            ("ag_hremote", True),
            ("ag_muse", False),
            ("ag_a2a", True),
            ("ag_pull", False),
            ("ag_local", True),
        ):
            r_sl = await self.client.post(
                "/api/federation/teams/team-ops/leader",
                headers=headers,
                data=json.dumps({"leader_agent_id": next_leader}),
            )
            self.assertEqual(r_sl.status, 200, await r_sl.text())
            d_sl = await r_sl.json()
            self.assertEqual(d_sl["team"]["leader_agent_id"], next_leader)
            self.assertIs(d_sl["leader_can_dispatch"], expect_dispatch)
            if not expect_dispatch:
                self.assertTrue(d_sl["warnings"])
                ag_after = federation_registry.get_agent(next_leader, bus_dir=str(self.bus_dir))
                assert ag_after is not None
                self.assertFalse(ag_after["capabilities"]["can_dispatch"])

        # 2. Unregistered / revoked agent rejected with 400
        for bad_leader in ("nonexistent_agent", "ag_revoked"):
            r_bad = await self.client.post(
                "/api/federation/teams/team-ops/leader",
                headers=headers,
                data=json.dumps({"leader_agent_id": bad_leader}),
            )
            self.assertEqual(r_bad.status, 400)

        # 3. Invalid IDs (traversal / slash / dot / uppercase / overlong) rejected with 400
        for bad_id in ("../escape", "a/b", "a.b", "UPPER_ID", "a" * 65):
            r_bad_ag = await self.client.post(
                "/api/federation/agents",
                headers=headers,
                data=json.dumps({"agent_id": bad_id, "kind": "hermes_local", "profile": "p1"}),
            )
            self.assertEqual(r_bad_ag.status, 400, f"Expected 400 for agent_id={bad_id!r}")
            r_bad_tm = await self.client.post(
                "/api/federation/teams",
                headers=headers,
                data=json.dumps({"team_id": bad_id}),
            )
            self.assertEqual(r_bad_tm.status, 400, f"Expected 400 for team_id={bad_id!r}")


class TestM3C4AuditSymlinkProtectionAndHealthAntiSSRF(_FederationTestBase):
    """M3-C4: Anti-symlink audit log reader + anti-SSRF loopback-only Hub health probe."""

    async def test_m3_c4_audit_symlink_and_pagination_and_redaction(self) -> None:
        admin_cookie, _ = await self._login("AdminUser", ADMIN_PASS)
        ro_cookie, _ = await self._login("ViewerUser", RO_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        ro_get = {"Cookie": f"{SESSION_COOKIE_NAME}={ro_cookie}"}

        # Readonly cannot access audit
        r_ro = await self.client.get("/api/federation/audit", headers=ro_get)
        self.assertEqual(r_ro.status, 403)

        # Invalid pagination -> 400
        for qs in ("?limit=-1", "?limit=abc", "?offset=-1", "?offset=abc"):
            r_bad = await self.client.get(f"/api/federation/audit{qs}", headers=admin_get)
            self.assertEqual(r_bad.status, 400, f"Expected 400 for {qs}")

        # Real audit.jsonl with secret & host path -> redacted & limit clamped <= 200
        fed_dir = self.bus_dir / "federation"
        fed_dir.mkdir(parents=True, exist_ok=True)
        audit_file = fed_dir / "audit.jsonl"
        audit_file.write_text(
            json.dumps(
                {
                    "ts": time.time(),
                    "event": "host_exec",
                    "actor_id": "hermes_1",
                    "action": "uptime",
                    "outcome": "ok",
                    "reason": f"path {SYNTH_HOST_PATH} leaked {SYNTH_FAKE_FED}",
                    "token_hash": "must_strip",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        r_ok = await self.client.get("/api/federation/audit?limit=999999&offset=0", headers=admin_get)
        self.assertEqual(r_ok.status, 200)
        d_ok = await r_ok.json()
        self.assertLessEqual(d_ok["limit"], 200)
        txt_ok = json.dumps(d_ok)
        self.assertNotIn(SYNTH_PREFIX, txt_ok)
        self.assertNotIn(SYNTH_HOST_PATH, txt_ok)
        self.assertNotIn("token_hash", txt_ok)

        # Symlink audit.jsonl pointing to sensitive target -> 403 & zero bytes leaked
        sensitive_target = self.tmp / "outside_secret.txt"
        sensitive_target.write_text("TOP_SECRET_CANARY_LINE\n", encoding="utf-8")
        audit_file.unlink()
        os.symlink(sensitive_target, audit_file)
        r_sym_file = await self.client.get("/api/federation/audit", headers=admin_get)
        self.assertEqual(r_sym_file.status, 403)
        self.assertNotIn("TOP_SECRET_CANARY_LINE", await r_sym_file.text())

        # Symlink federation/ directory itself -> 403 & zero bytes leaked
        audit_file.unlink()
        fed_dir.rmdir()
        outside_dir = self.tmp / "outside_fed_dir"
        outside_dir.mkdir()
        (outside_dir / "audit.jsonl").write_text('{"event":"DIR_SYMLINK_CANARY"}\n', encoding="utf-8")
        os.symlink(outside_dir, fed_dir)
        r_sym_dir = await self.client.get("/api/federation/audit", headers=admin_get)
        self.assertEqual(r_sym_dir.status, 403)
        self.assertNotIn("DIR_SYMLINK_CANARY", await r_sym_dir.text())

    async def test_m3_c4_health_probe_anti_ssrf_redirects_and_timeout(self) -> None:
        admin_cookie, _ = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}

        # Unit check on loopback validator
        for bad_host in ("198.51.100.1", SYNTH_IMDS_IP, "evil.example.com", "localhost", "0.0.0.0", "127.0.0.2"):
            ok, _, _, _ = _validate_loopback_hub_target(bad_host, 18799)
            self.assertFalse(ok, f"Expected non-canonical host rejection for {bad_host!r}")
        for good_host in ("127.0.0.1", "::1", "[::1]"):
            ok, _, _, _ = _validate_loopback_hub_target(good_host, 18799)
            self.assertTrue(ok, f"Expected loopback acceptance for {good_host!r}")

        # Start stub loopback HTTP server with modes: ok, redirect, stall
        stub_mode = {"mode": "ok"}
        redirect_target_hit = {"count": 0}

        async def handle_stub_health(_req: web.Request) -> web.Response:
            m = stub_mode["mode"]
            if m == "redirect":
                raise web.HTTPFound(location="/redirect-target")
            if m == "stall":
                await asyncio.sleep(2.0)
                return web.json_response({"ok": True})
            return web.json_response({"ok": True, "service": "agy-federation-hub", "extra_debug": "ignored"})

        async def handle_redirect_target(_req: web.Request) -> web.Response:
            redirect_target_hit["count"] += 1
            return web.json_response({"ok": True})

        stub_app = web.Application()
        stub_app.router.add_get("/hub/v1/health", handle_stub_health)
        stub_app.router.add_get("/redirect-target", handle_redirect_target)
        stub_server = TestServer(stub_app)
        await stub_server.start_server()
        try:
            self.fed_svc._hub_host_override = "127.0.0.1"
            self.fed_svc._hub_port_override = stub_server.port
            self.fed_svc.health_timeout_sec = 0.4

            # 1. Healthy probe ignores client ?url=/?host=/?port= SSRF attempts
            r_ok = await self.client.get(
                f"/api/federation/health?url={SYNTH_IMDS_URL}&host=evil.example.com&port=22",
                headers=admin_get,
            )
            self.assertEqual(r_ok.status, 200)
            d_ok = await r_ok.json()
            self.assertTrue(d_ok["reachable"])
            self.assertEqual(d_ok["status"], "healthy")
            self.assertNotIn("extra_debug", d_ok)

            # 2. 302 redirect -> fail-closed & never follows redirect
            stub_mode["mode"] = "redirect"
            r_red = await self.client.get("/api/federation/health", headers=admin_get)
            self.assertEqual(r_red.status, 200)
            d_red = await r_red.json()
            self.assertFalse(d_red["reachable"])
            self.assertEqual(d_red["status"], "redirect_blocked")
            self.assertEqual(redirect_target_hit["count"], 0)

            # 3. Stalled stub -> bounded timeout fail-closed
            stub_mode["mode"] = "stall"
            t0 = time.monotonic()
            r_to = await self.client.get("/api/federation/health", headers=admin_get)
            elapsed = time.monotonic() - t0
            self.assertEqual(r_to.status, 200)
            d_to = await r_to.json()
            self.assertFalse(d_to["reachable"])
            self.assertEqual(d_to["status"], "timeout")
            self.assertLess(elapsed, 2.0)

            # 4. Misconfigured non-loopback hub_host -> fail-closed without network call
            self.fed_svc._hub_host_override = "198.51.100.5"
            r_bad_cfg = await self.client.get("/api/federation/health", headers=admin_get)
            self.assertEqual(r_bad_cfg.status, 200)
            d_bad = await r_bad_cfg.json()
            self.assertFalse(d_bad["reachable"])
            self.assertEqual(d_bad["status"], "misconfigured")
        finally:
            await stub_server.close()


class TestM3C5FrontendZeroPersistenceCspAndSpaShell(_FederationTestBase):
    """M3-C5: Static security invariants on FederationView + unauthenticated zero-data `/federation` shell."""

    async def test_m3_c5_frontend_static_invariants_and_spa_shell(self) -> None:
        fed_tsx = (REPO_ROOT / "webui" / "src" / "components" / "FederationView.tsx").read_text(encoding="utf-8")

        # Zero client persistence of one-time tokens
        for forbidden_sink in (
            "localStorage",
            "sessionStorage",
            "document.cookie",
            "workbench/state",
            "dangerouslySetInnerHTML",
            "<script",
            "unp" + "kg" + "." + "com",
            "cdn." + "jsdelivr",
            "cdnjs." + "cloudflare",
        ):
            self.assertNotIn(forbidden_sink, fed_tsx, f"Forbidden pattern {forbidden_sink!r} in FederationView.tsx")

        # Cleanup on close / tab switch / unmount present
        self.assertIn("setOneTimeToken(null)", fed_tsx)

        # Backend federation_service.py contains zero shell/subprocess calls
        svc_src = (REPO_ROOT / "studio" / "federation_service.py").read_text(encoding="utf-8")
        tree = ast.parse(svc_src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                for m in mods:
                    self.assertNotIn("subprocess", m)
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, ("system", "popen", "Popen", "create_subprocess_shell"))

        # Unauthenticated GET /federation returns zero-data SPA shell with no-store & CSP script-src 'self'
        r_spa = await self.client.get("/federation")
        self.assertEqual(r_spa.status, 200)
        self.assertEqual(r_spa.headers.get("Cache-Control"), "no-store, max-age=0")
        csp = r_spa.headers.get("Content-Security-Policy", "")
        self.assertIn("script-src 'self'", csp)
        body = await r_spa.text()
        self.assertNotIn(SYNTH_PREFIX, body)
        self.assertNotIn("token_records", body)


class TestM3C6AndC7TelegramCommands(unittest.TestCase):
    """M3-C6 & M3-C7: Telegram `/team` compatibility, `/agent` human-Admin RBAC, group token hard block, DM delivery."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_tg_fed_")
        self.tmp = Path(self._td.name)
        self.bus_dir = str(self.tmp / "bus")
        os.makedirs(self.bus_dir, exist_ok=True)
        self.taint_file = str(self.tmp / "taint.json")
        self.sent_messages: list[dict[str, object]] = []
        self.logged_lines: list[str] = []

        self._env_patch = mock.patch.dict(os.environ, _clean_owner_env(), clear=True)
        self._env_patch.start()

        self._patches = [
            mock.patch.object(bot_bus, "BUS_DIR", self.bus_dir),
            mock.patch.object(tg_bridge, "MEMORY_TAINT_FILE", self.taint_file),
            mock.patch.object(tg_bridge, "ALLOWED", {ADMIN_UID, READONLY_UID, GROUP_CHAT_ID}),
            mock.patch.object(tg_bridge, "ALLOWED_USERS", {ADMIN_UID, READONLY_UID}),
            mock.patch.object(tg_bridge, "ADMIN_USERS", {ADMIN_UID}),
            mock.patch.object(tg_bridge, "READONLY_USERS", {READONLY_UID}),
            mock.patch.object(tg_bridge, "ALLOW_GROUP_READONLY", True),
            mock.patch.object(tg_bridge, "send", side_effect=self._fake_send),
            mock.patch.object(tg_bridge, "log", side_effect=self._fake_log),
            mock.patch.object(tg_bridge, "register_bot_commands_async", return_value=None),
            mock.patch.object(tg_bridge, "invalidate_session", return_value=None),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self) -> None:
        for p in reversed(self._patches):
            p.stop()
        self._env_patch.stop()
        self._td.cleanup()

    def _fake_send(self, chat_id, text, **kwargs):
        self.sent_messages.append({"chat_id": chat_id, "text": str(text), "kwargs": kwargs})

    def _fake_log(self, msg):
        self.logged_lines.append(str(msg))

    def test_m3_c6_access_control_and_team_compat_and_rbac_denials(self) -> None:
        # 1. access_control & _KNOWN_BRIDGE_COMMANDS registration
        self.assertIn("/agent", tg_bridge._KNOWN_BRIDGE_COMMANDS)
        self.assertIn("/agents", tg_bridge._KNOWN_BRIDGE_COMMANDS)
        self.assertFalse(access_control.is_command_allowed_for_role("readonly", "/agent", "list")[0])
        self.assertFalse(access_control.is_command_allowed_for_role("readonly", "/agents", "token a")[0])
        self.assertFalse(access_control.is_command_allowed_for_role("denied", "/agent", "list")[0])
        self.assertTrue(access_control.is_command_allowed_for_role("admin", "/agent", "list")[0])
        # Empty /team remains viewable for readonly, while /team create is denied
        self.assertTrue(access_control.is_command_allowed_for_role("readonly", "/team", "")[0])
        self.assertFalse(access_control.is_command_allowed_for_role("readonly", "/team", "create t1")[0])

        # 2. Legacy empty `/team` & `/team peer` still work without regression
        default_real_cfg = Path.home() / ".gemini" / "antigravity-cli" / "cache" / "bot_bus" / "team_config.json"
        real_cfg_before = default_real_cfg.read_bytes() if default_real_cfg.is_file() else None

        tg_bridge.cmd_team(ADMIN_UID, "")
        self.assertTrue(self.sent_messages)
        self.sent_messages.clear()
        tg_bridge.cmd_team(ADMIN_UID, "peer")
        self.assertTrue(any("Peer" in str(m["text"]) for m in self.sent_messages))
        self.sent_messages.clear()

        # Verify `/team peer` wrote ONLY into isolated self.bus_dir and never touched host team_config.json
        self.assertTrue((Path(self.bus_dir) / "team_config.json").is_file())
        real_cfg_after = default_real_cfg.read_bytes() if default_real_cfg.is_file() else None
        self.assertEqual(real_cfg_before, real_cfg_after)

        # 3. Negative caller cases: readonly, denied, is_bot=True, from_user=None
        bad_callers = [
            (READONLY_UID, {"id": READONLY_UID, "is_bot": False}),
            (999999999, {"id": 999999999, "is_bot": False}),
            (ADMIN_UID, {"id": ADMIN_UID, "is_bot": True}),
            (ADMIN_UID, None),
        ]
        for cid, user in bad_callers:
            tg_bridge.cmd_agent(cid, "add evil_bot hermes_local --profile p1", from_user=user)
            tg_bridge.cmd_team(cid, "create evil_team --leader evil_bot", from_user=user)

        # 4. Untrusted / memory-readonly env markers fail-closed
        admin_user = {"id": ADMIN_UID, "is_bot": False}
        for env_key in ("AGY_UNTRUSTED_SESSION", "AGY_MEMORY_READONLY"):
            with mock.patch.dict(os.environ, {env_key: "1"}):
                tg_bridge.cmd_agent(ADMIN_UID, "add env_evil hermes_local --profile p1", from_user=admin_user)
                tg_bridge.cmd_team(ADMIN_UID, "create env_team --leader env_evil", from_user=admin_user)

        # 5. Tainted conversation_id fail-closed
        conv_id = "conv-tainted-m3"
        memory_guard.mark_tainted(conv_id, source="untrusted_tool", taint_file=self.taint_file)
        with mock.patch.object(tg_bridge, "get_scope_value", return_value=conv_id):
            tg_bridge.cmd_agent(ADMIN_UID, "add taint_evil hermes_local --profile p1", from_user=admin_user)
            tg_bridge.cmd_team(ADMIN_UID, "create taint_team --leader taint_evil", from_user=admin_user)

        # Zero mutations on disk across all negative cases
        self.assertFalse(os.path.exists(federation_registry.agents_file_path(self.bus_dir)))
        self.assertFalse(os.path.exists(federation_registry.teams_file_path(self.bus_dir)))

    def test_m3_c7_group_chat_hard_blocks_tokens_and_dm_delivers_safely(self) -> None:
        default_real_cfg = Path.home() / ".gemini" / "antigravity-cli" / "cache" / "bot_bus" / "team_config.json"
        real_cfg_before = default_real_cfg.read_bytes() if default_real_cfg.is_file() else None

        admin_user = {"id": ADMIN_UID, "is_bot": False}
        # Bind a team_mirror group to verify DM token NEVER leaks to mirror chat
        bot_bus.set_team_mirror(MIRROR_GROUP_ID, None)
        isolated_cfg = Path(self.bus_dir) / "team_config.json"
        self.assertTrue(isolated_cfg.is_file())
        self.assertEqual(
            MIRROR_GROUP_ID,
            json.loads(isolated_cfg.read_text(encoding="utf-8")).get("mirror", {}).get("chat_id"),
        )
        real_cfg_after = default_real_cfg.read_bytes() if default_real_cfg.is_file() else None
        self.assertEqual(real_cfg_before, real_cfg_after)

        # Register agent alpha via legitimate human admin in DM (without --mint)
        tg_bridge.cmd_agent(
            ADMIN_UID,
            "add alpha hermes_local --profile default --display AlphaNode",
            from_user=admin_user,
        )
        ag_before = federation_registry.get_agent("alpha", bus_dir=self.bus_dir)
        assert ag_before is not None
        self.assertEqual(ag_before["active_token_count"], 0)
        self.sent_messages.clear()
        self.logged_lines.clear()

        # Spy on registry token functions to verify group chat blocks BEFORE calling them
        with (
            mock.patch.object(
                federation_registry, "mint_agent_token", wraps=federation_registry.mint_agent_token
            ) as spy_mint,
            mock.patch.object(
                federation_registry, "rotate_agent_token", wraps=federation_registry.rotate_agent_token
            ) as spy_rotate,
        ):
            # Group chat (chat_id < 0) attempts: token / mint / rotate / add --mint
            tg_bridge.cmd_agent(GROUP_CHAT_ID, "token alpha", from_user=admin_user)
            tg_bridge.cmd_agent(GROUP_CHAT_ID, "mint alpha", from_user=admin_user)
            tg_bridge.cmd_agent(GROUP_CHAT_ID, "rotate alpha", from_user=admin_user)
            tg_bridge.cmd_agent(GROUP_CHAT_ID, "add beta hermes_local --profile p2 --mint", from_user=admin_user)

            # Registry token functions must NEVER have been invoked!
            self.assertEqual(spy_mint.call_count, 0)
            self.assertEqual(spy_rotate.call_count, 0)

        # Disk unchanged: alpha still has 0 tokens, beta was NOT created
        self.assertEqual(federation_registry.get_agent("alpha", bus_dir=self.bus_dir)["active_token_count"], 0)
        self.assertIsNone(federation_registry.get_agent("beta", bus_dir=self.bus_dir))
        # Zero agy_fed_ in sent group messages or logs
        for m in self.sent_messages:
            self.assertNotIn(SYNTH_PREFIX, str(m["text"]))
        for ln in self.logged_lines:
            self.assertNotIn(SYNTH_PREFIX, ln)

        # Legitimate human admin in DM (chat_id > 0) CAN mint & rotate one-time token
        self.sent_messages.clear()
        self.logged_lines.clear()
        tg_bridge.cmd_agent(ADMIN_UID, "token alpha", from_user=admin_user)
        self.assertEqual(len(self.sent_messages), 1)
        self.assertEqual(self.sent_messages[0]["chat_id"], ADMIN_UID)
        dm_text = str(self.sent_messages[0]["text"])
        m_tok = re.search(rf"{re.escape(SYNTH_PREFIX)}[A-Za-z0-9._-]+", dm_text)
        self.assertIsNotNone(m_tok)
        dm_token = m_tok.group(0)
        self.assertIsNotNone(federation_registry.verify_agent_token(dm_token, bus_dir=self.bus_dir))

        # Never forwarded to mirror group & never logged
        self.assertFalse(any(m["chat_id"] == MIRROR_GROUP_ID for m in self.sent_messages))
        self.assertFalse(any(SYNTH_PREFIX in ln for ln in self.logged_lines))

        # Test /team create & /team leader warning (no silent privilege escalation)
        self.sent_messages.clear()
        tg_bridge.cmd_team(ADMIN_UID, "create squad1 --leader alpha --name SquadOne", from_user=admin_user)
        self.assertTrue(any("can_dispatch=false" in str(m["text"]) for m in self.sent_messages))
        self.assertFalse(
            federation_registry.get_agent("alpha", bus_dir=self.bus_dir)["capabilities"]["can_dispatch"]
        )

        # Grant can_dispatch=true and revoke Kill-Switch
        tg_bridge.cmd_agent(ADMIN_UID, "grant alpha can_dispatch=true coordinator_peer=true", from_user=admin_user)
        self.assertTrue(
            federation_registry.get_agent("alpha", bus_dir=self.bus_dir)["capabilities"]["can_dispatch"]
        )
        tg_bridge.cmd_agent(ADMIN_UID, "revoke alpha", from_user=admin_user)
        self.assertIsNone(federation_registry.verify_agent_token(dm_token, bus_dir=self.bus_dir))


class TestM3Round1QAHardening(_FederationTestBase):
    """QA Round 1 regression suite covering M3-B1, M3-B2, M3-B3 and Follow-ups 1–3."""

    async def test_m3_b1_secret_ref_admin_roundtrip_and_readonly_masking(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        ro_cookie, _ = await self._login("ViewerUser", RO_PASS)
        admin_write = self._admin_headers(admin_cookie, admin_csrf)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        ro_get = {"Cookie": f"{SESSION_COOKIE_NAME}={ro_cookie}"}

        ref_path = "/".join(("lv1", "services", "hermes-r1")) + "#api_key"
        r_create = await self.client.post(
            "/api/federation/agents",
            headers=admin_write,
            data=json.dumps(
                {
                    "agent_id": "hermes_r1",
                    "kind": "hermes_remote",
                    "endpoint_url": "https://hermes-r1.example.com",
                    "secret_ref": ref_path,
                }
            ),
        )
        self.assertEqual(r_create.status, 200)
        d_create = await r_create.json()
        self.assertEqual(d_create["agent"]["secret_ref"], ref_path)
        self.assertTrue(d_create["agent"]["has_secret_ref"])

        # Admin GET endpoints return validated secret_ref intact
        for ep in ("/api/federation/overview", "/api/federation/agents", "/api/federation/agents/hermes_r1"):
            r_ag = await self.client.get(ep, headers=admin_get)
            self.assertEqual(r_ag.status, 200)
            d_ag = await r_ag.json()
            rec = d_ag["agent"] if "agent" in d_ag else next(a for a in d_ag["agents"] if a["agent_id"] == "hermes_r1")
            self.assertEqual(rec["secret_ref"], ref_path)
            self.assertTrue(rec["has_secret_ref"])

        # Readonly GET endpoints NEVER leak internal OpenBao mount paths
        for ep in ("/api/federation/overview", "/api/federation/agents", "/api/federation/agents/hermes_r1"):
            r_ro = await self.client.get(ep, headers=ro_get)
            self.assertEqual(r_ro.status, 200)
            d_ro = await r_ro.json()
            self.assertNotIn(ref_path, json.dumps(d_ro))
            rec = d_ro["agent"] if "agent" in d_ro else next(a for a in d_ro["agents"] if a["agent_id"] == "hermes_r1")
            self.assertEqual(rec["secret_ref"], "")
            self.assertTrue(rec["has_secret_ref"])

        # Admin PATCH round-trip succeeds with 200 and preserves secret_ref on disk
        r_patch = await self.client.patch(
            "/api/federation/agents/hermes_r1",
            headers=admin_write,
            data=json.dumps(
                {
                    "display_name": "Hermes R1 Edited",
                    "secret_ref": ref_path,
                }
            ),
        )
        self.assertEqual(r_patch.status, 200)
        d_patch = await r_patch.json()
        self.assertEqual(d_patch["agent"]["display_name"], "Hermes R1 Edited")
        self.assertEqual(d_patch["agent"]["secret_ref"], ref_path)
        on_disk = federation_registry.get_agent("hermes_r1", bus_dir=self.bus_dir)
        assert on_disk is not None
        self.assertEqual(on_disk["secret_ref"], ref_path)

    async def test_m3_b2_strict_types_no_500_and_no_string_bool_coercion(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        headers = self._admin_headers(admin_cookie, admin_csrf)

        # String "false" for mint_token MUST be rejected with 400 (NEVER mint a real token!)
        r_str_mint = await self.client.post(
            "/api/federation/agents",
            headers=headers,
            data=json.dumps(
                {
                    "agent_id": "a_bool_bad",
                    "kind": "hermes_local",
                    "profile": "p1",
                    "mint_token": "false",
                }
            ),
        )
        self.assertEqual(r_str_mint.status, 400)
        self.assertNotIn(SYNTH_PREFIX, await r_str_mint.text())
        self.assertIsNone(federation_registry.get_agent("a_bool_bad", bus_dir=self.bus_dir))

        # Other non-bool booleans rejected with 400
        for bad_agent_body in (
            {"agent_id": "a_b1", "kind": "hermes_local", "profile": "p1", "enabled": "true"},
            {"agent_id": "a_b2", "kind": "hermes_local", "profile": "p1", "overwrite": 1},
            {"agent_id": "a_b3", "kind": "hermes_local", "profile": "p1", "capabilities": {"can_dispatch": "true"}},
            {"agent_id": "a_b4", "kind": "hermes_local", "profile": "p1", "capabilities": {"allowed_teams": "t1"}},
        ):
            r_bad = await self.client.post("/api/federation/agents", headers=headers, data=json.dumps(bad_agent_body))
            self.assertEqual(r_bad.status, 400)

        # Register valid agent and team for PATCH/rotate/leader checks
        r_ag = await self.client.post(
            "/api/federation/agents",
            headers=headers,
            data=json.dumps({"agent_id": "worker_typed", "kind": "hermes_local", "profile": "p1"}),
        )
        self.assertEqual(r_ag.status, 200)

        # Rotate with string "false" rejected with 400
        r_rot = await self.client.post(
            "/api/federation/agents/worker_typed/rotate",
            headers=headers,
            data=json.dumps({"revoke_existing": "false"}),
        )
        self.assertEqual(r_rot.status, 400)

        # Create team with invalid members/co_leaders/overwrite returns 400 (NEVER 500)
        for bad_team_body in (
            {"team_id": "t_bad1", "members": 123},
            {"team_id": "t_bad2", "co_leaders": 123},
            {"team_id": "t_bad3", "members": "aa"},
            {"team_id": "t_bad4", "members": [123]},
            {"team_id": "t_bad5", "overwrite": "false"},
        ):
            r_tb = await self.client.post("/api/federation/teams", headers=headers, data=json.dumps(bad_team_body))
            self.assertEqual(r_tb.status, 400, f"Expected 400 for {bad_team_body!r}, got {r_tb.status}")

        r_tm = await self.client.post(
            "/api/federation/teams",
            headers=headers,
            data=json.dumps({"team_id": "t_typed", "leader_agent_id": "worker_typed"}),
        )
        self.assertEqual(r_tm.status, 200)

        # PATCH team and set_leader with non-list members/co_leaders return 400 (NEVER 500)
        for bad_patch in ({"members": 123}, {"co_leaders": "str"}, {"members": [None]}):
            r_pt = await self.client.patch("/api/federation/teams/t_typed", headers=headers, data=json.dumps(bad_patch))
            self.assertEqual(r_pt.status, 400)

        r_ld = await self.client.post(
            "/api/federation/teams/t_typed/leader",
            headers=headers,
            data=json.dumps({"leader_agent_id": "worker_typed", "co_leaders": 123}),
        )
        self.assertEqual(r_ld.status, 400)

    async def test_m3_b3_hyphenated_secret_keys_and_followups(self) -> None:
        from studio.event_hub import _sanitize_event_value

        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        headers = self._admin_headers(admin_cookie, admin_csrf)

        # M3-B3: Hyphenated forbidden keys stripped in both audit output & SSE sanitizer
        m_hash = "_".join(("MARKER", "HYPHEN", "H1"))
        m_raw = "_".join(("MARKER", "HYPHEN", "R2"))
        m_bearer = "_".join(("MARKER", "HYPHEN", "B3"))
        fed_dir = self.bus_dir / "federation"
        fed_dir.mkdir(parents=True, exist_ok=True)
        (fed_dir / "audit.jsonl").write_text(
            json.dumps(
                {
                    "ts": time.time(),
                    "event": "probe_hyphen",
                    "actor_id": "hermes_1",
                    "token-hash": m_hash,
                    "raw-token": m_raw,
                    "bearer-token": m_bearer,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        r_aud = await self.client.get("/api/federation/audit", headers=admin_get)
        self.assertEqual(r_aud.status, 200)
        aud_txt = await r_aud.text()
        self.assertNotIn(m_hash, aud_txt)
        self.assertNotIn(m_raw, aud_txt)
        self.assertNotIn(m_bearer, aud_txt)

        san_ev = _sanitize_event_value(
            {
                "ok": True,
                "token-hash": "ev_h1",
                "raw-token": "ev_r2",
                "plaintext-token": "ev_p3",
                "bearer-token": "ev_b4",
            }
        )
        self.assertEqual(san_ev, {"ok": True})

        # Follow-up 1: pull_worker -> hermes_local PATCH resets driver & transport defaults
        r_pw = await self.client.post(
            "/api/federation/agents",
            headers=headers,
            data=json.dumps({"agent_id": "pw_switch", "kind": "pull_worker"}),
        )
        self.assertEqual(r_pw.status, 200)
        r_sw = await self.client.patch(
            "/api/federation/agents/pw_switch",
            headers=headers,
            data=json.dumps({"kind": "hermes_local", "profile": "p_sw"}),
        )
        self.assertEqual(r_sw.status, 200)
        d_sw = await r_sw.json()
        self.assertEqual(d_sw["agent"]["kind"], "hermes_local")
        self.assertEqual(d_sw["agent"]["driver"], "hermes_local")
        self.assertEqual(d_sw["agent"]["transport"], "local_cli")

        # Follow-up 3: Deleted team leader reports leader_can_dispatch=False with warning
        r_t = await self.client.post(
            "/api/federation/teams",
            headers=headers,
            data=json.dumps({"team_id": "t_orphan", "leader_agent_id": "pw_switch"}),
        )
        self.assertEqual(r_t.status, 200)
        r_del = await self.client.delete("/api/federation/agents/pw_switch", headers=headers)
        self.assertEqual(r_del.status, 200)
        r_list = await self.client.get("/api/federation/teams", headers=admin_get)
        self.assertEqual(r_list.status, 200)
        d_list = await r_list.json()
        t_rec = next(t for t in d_list["teams"] if t["team_id"] == "t_orphan")
        self.assertFalse(t_rec["leader_can_dispatch"])
        self.assertTrue(t_rec["warnings"])


class TestM3C8ExportWhitelistCoverage(unittest.TestCase):
    """M3-C8: Export whitelist covers all federation code and test suites."""

    @unittest.skipIf(export_public is None, "export_public.py is only present in private operator repo")
    def test_m3_c8_export_public_whitelist_covers_federation_files(self) -> None:
        assert export_public is not None
        required_exact = (
            "tests/test_external_drivers.py",
            "tests/test_federation_hub.py",
            "tests/test_federation_registry.py",
            "tests/test_studio_federation.py",
        )
        for rel in required_exact:
            self.assertIn(rel, export_public.CORE_SYNC_EXACT)
            self.assertTrue(export_public.is_public_core(rel), f"is_public_core({rel!r}) returned False")

        for core_rel in (
            "studio/federation_service.py",
            "webui/src/components/FederationView.tsx",
            "bridge/federation_registry.py",
            "bridge/federation_hub.py",
            "bridge/external_drivers.py",
        ):
            self.assertTrue(export_public.is_public_core(core_rel), f"is_public_core({core_rel!r}) returned False")


if __name__ == "__main__":
    unittest.main()
