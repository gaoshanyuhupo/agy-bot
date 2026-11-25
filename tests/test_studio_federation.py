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
    _merge_single_timeline_job,
    _validate_hub_public_url,
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

    def test_c6_telegram_agent_token_peek_group_topic_block_and_dm_scope(self) -> None:
        default_real_cfg = Path.home() / ".gemini" / "antigravity-cli" / "cache" / "bot_bus" / "team_config.json"
        real_cfg_before = default_real_cfg.read_bytes() if default_real_cfg.is_file() else None

        admin_user = {"id": ADMIN_UID, "is_bot": False}
        bot_bus.set_team_mirror(MIRROR_GROUP_ID, None)
        tg_bridge.cmd_agent(ADMIN_UID, "add peek_tg pull_worker", from_user=admin_user)
        agents_path = Path(federation_registry.agents_file_path(self.bus_dir))
        self.sent_messages.clear()
        self.logged_lines.clear()

        # C6-1: Group chat (chat_id < 0) AND Topic (thread_id != None, even with DM chat_id) MUST block BEFORE registry
        before_bytes = agents_path.read_bytes()
        with (
            mock.patch.object(
                federation_registry, "mint_agent_token", wraps=federation_registry.mint_agent_token
            ) as spy_mint,
            mock.patch.object(
                federation_registry, "rotate_agent_token", wraps=federation_registry.rotate_agent_token
            ) as spy_rotate,
        ):
            tg_bridge.cmd_agent(GROUP_CHAT_ID, "token peek_tg peek", from_user=admin_user)
            tg_bridge.cmd_agent(GROUP_CHAT_ID, "mint peek_tg peek", from_user=admin_user)
            tg_bridge.cmd_agent(GROUP_CHAT_ID, "rotate peek_tg peek", from_user=admin_user)
            tg_bridge.cmd_agent(GROUP_CHAT_ID, "token peek_tg peek", thread_id=42, from_user=admin_user)
            tg_bridge.cmd_agent(ADMIN_UID, "token peek_tg peek", thread_id=42, from_user=admin_user)
            tg_bridge.cmd_agent(ADMIN_UID, "mint peek_tg peek", thread_id=99, from_user=admin_user)
            tg_bridge.cmd_agent(ADMIN_UID, "rotate peek_tg peek", thread_id=7, from_user=admin_user)
            self.assertEqual(spy_mint.call_count, 0)
            self.assertEqual(spy_rotate.call_count, 0)
        self.assertEqual(before_bytes, agents_path.read_bytes())
        for m in self.sent_messages:
            self.assertNotIn(SYNTH_PREFIX, str(m["text"]))
        for ln in self.logged_lines:
            self.assertNotIn(SYNTH_PREFIX, ln)

        # C6-2a: Valid DM with invalid scope or extra args MUST reject BEFORE registry with 0 disk mutations
        self.sent_messages.clear()
        self.logged_lines.clear()
        with (
            mock.patch.object(
                federation_registry, "mint_agent_token", wraps=federation_registry.mint_agent_token
            ) as spy_mint,
            mock.patch.object(
                federation_registry, "rotate_agent_token", wraps=federation_registry.rotate_agent_token
            ) as spy_rotate,
        ):
            tg_bridge.cmd_agent(ADMIN_UID, "token peek_tg admin", from_user=admin_user)
            tg_bridge.cmd_agent(ADMIN_UID, "mint peek_tg PEEK", from_user=admin_user)
            tg_bridge.cmd_agent(ADMIN_UID, "rotate peek_tg peek extra_arg", from_user=admin_user)
            self.assertEqual(spy_mint.call_count, 0)
            self.assertEqual(spy_rotate.call_count, 0)
        self.assertEqual(before_bytes, agents_path.read_bytes())

        # C6-2b: Valid DM delivers full & peek tokens with thread_id=None, Scope label, no log, no mirror
        self.sent_messages.clear()
        self.logged_lines.clear()
        tg_bridge.cmd_agent(ADMIN_UID, "token peek_tg", from_user=admin_user)
        m_full = re.search(rf"{re.escape(SYNTH_PREFIX)}[A-Za-z0-9._-]+", str(self.sent_messages[-1]["text"]))
        self.assertIsNotNone(m_full)
        full_tok = m_full.group(0)
        self.assertIn("Scope: <code>full</code>", str(self.sent_messages[-1]["text"]))
        self.assertIsNone(self.sent_messages[-1]["kwargs"].get("thread_id"))

        self.sent_messages.clear()
        tg_bridge.cmd_agent(ADMIN_UID, "token peek_tg peek", from_user=admin_user)
        self.assertEqual(len(self.sent_messages), 1)
        self.assertEqual(self.sent_messages[0]["chat_id"], ADMIN_UID)
        self.assertIsNone(self.sent_messages[0]["kwargs"].get("thread_id"))
        peek_msg = str(self.sent_messages[0]["text"])
        self.assertIn("Scope: <code>peek</code>", peek_msg)
        self.assertIn("/peek", peek_msg)
        m_peek1 = re.search(rf"{re.escape(SYNTH_PREFIX)}[A-Za-z0-9._-]+", peek_msg)
        self.assertIsNotNone(m_peek1)
        peek_tok1 = m_peek1.group(0)
        self.assertIsNone(federation_registry.verify_agent_token(peek_tok1, bus_dir=self.bus_dir))
        self.assertIsNotNone(
            federation_registry.verify_agent_token(peek_tok1, bus_dir=self.bus_dir, allowed_scopes=("full", "peek"))
        )

        # Rotate peek in DM -> revokes old peek, keeps full intact
        self.sent_messages.clear()
        tg_bridge.cmd_agent(ADMIN_UID, "rotate peek_tg peek", from_user=admin_user)
        self.assertEqual(len(self.sent_messages), 1)
        self.assertIsNone(self.sent_messages[0]["kwargs"].get("thread_id"))
        m_peek2 = re.search(rf"{re.escape(SYNTH_PREFIX)}[A-Za-z0-9._-]+", str(self.sent_messages[0]["text"]))
        self.assertIsNotNone(m_peek2)
        peek_tok2 = m_peek2.group(0)
        self.assertIsNone(
            federation_registry.verify_agent_token(peek_tok1, bus_dir=self.bus_dir, allowed_scopes=("full", "peek"))
        )
        self.assertIsNotNone(
            federation_registry.verify_agent_token(peek_tok2, bus_dir=self.bus_dir, allowed_scopes=("full", "peek"))
        )
        self.assertIsNotNone(federation_registry.verify_agent_token(full_tok, bus_dir=self.bus_dir))

        self.assertFalse(any(m["chat_id"] == MIRROR_GROUP_ID for m in self.sent_messages))
        self.assertFalse(any(SYNTH_PREFIX in ln for ln in self.logged_lines))
        real_cfg_after = default_real_cfg.read_bytes() if default_real_cfg.is_file() else None
        self.assertEqual(real_cfg_before, real_cfg_after)


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

    async def test_c6_studio_token_scope_validation_and_gates(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        ro_cookie, ro_csrf = await self._login("ViewerUser", RO_PASS)
        admin_hdrs = self._admin_headers(admin_cookie, admin_csrf)

        r_create = await self.client.post(
            "/api/federation/agents",
            headers=admin_hdrs,
            data=json.dumps({"agent_id": "studio_peek_ag", "kind": "pull_worker"}),
        )
        self.assertEqual(r_create.status, 200)

        agents_path = Path(federation_registry.agents_file_path(str(self.bus_dir)))
        before_bytes = agents_path.read_bytes()

        # C6-3a: Malformed scope values MUST return 400 with 0 disk mutations on both mint & rotate
        bad_scopes: list[object] = ["admin", "", "* ", ["peek"], True, 123, None]
        for bad_scope in bad_scopes:
            for endpoint in (
                "/api/federation/agents/studio_peek_ag/tokens",
                "/api/federation/agents/studio_peek_ag/rotate",
            ):
                r_bad = await self.client.post(
                    endpoint,
                    headers=admin_hdrs,
                    data=json.dumps({"scope": bad_scope}),
                )
                self.assertEqual(r_bad.status, 400, f"{endpoint} with scope={bad_scope!r} -> {r_bad.status}")
        self.assertEqual(before_bytes, agents_path.read_bytes())

        # C6-3b: Missing CSRF / bad Origin / readonly / unauthenticated -> 401/403 with 0 disk mutations
        r_unauth = await self.client.post(
            "/api/federation/agents/studio_peek_ag/tokens",
            headers={"Origin": self.origin, "Content-Type": "application/json"},
            data=json.dumps({"scope": "peek"}),
        )
        self.assertEqual(r_unauth.status, 401)

        r_no_csrf = await self.client.post(
            "/api/federation/agents/studio_peek_ag/tokens",
            headers={
                "Origin": self.origin,
                "Content-Type": "application/json",
                "Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}",
            },
            data=json.dumps({"scope": "peek"}),
        )
        self.assertEqual(r_no_csrf.status, 403)

        r_bad_orig = await self.client.post(
            "/api/federation/agents/studio_peek_ag/tokens",
            headers={**admin_hdrs, "Origin": "https://evil.example.com"},
            data=json.dumps({"scope": "peek"}),
        )
        self.assertEqual(r_bad_orig.status, 403)

        r_ro = await self.client.post(
            "/api/federation/agents/studio_peek_ag/tokens",
            headers=self._admin_headers(ro_cookie, ro_csrf),
            data=json.dumps({"scope": "peek"}),
        )
        self.assertEqual(r_ro.status, 403)
        self.assertEqual(before_bytes, agents_path.read_bytes())

        # C6-3c: Valid omitted scope defaults to "full" + Cache-Control: no-store
        r_def = await self.client.post(
            "/api/federation/agents/studio_peek_ag/tokens",
            headers=admin_hdrs,
            data=json.dumps({}),
        )
        self.assertEqual(r_def.status, 200)
        self.assertIn("no-store", r_def.headers.get("Cache-Control", "").lower())
        d_def = await r_def.json()
        self.assertEqual(d_def["scope"], "full")
        full_tok = d_def["token"]
        self.assertIsNotNone(federation_registry.verify_agent_token(full_tok, bus_dir=str(self.bus_dir)))

        # C6-3d: Valid {"scope": "peek"} returns 200 + no-store + scoped peek token
        r_peek = await self.client.post(
            "/api/federation/agents/studio_peek_ag/tokens",
            headers=admin_hdrs,
            data=json.dumps({"scope": "peek", "label": "hook-5s"}),
        )
        self.assertEqual(r_peek.status, 200)
        self.assertIn("no-store", r_peek.headers.get("Cache-Control", "").lower())
        d_peek = await r_peek.json()
        self.assertEqual(d_peek["scope"], "peek")
        peek_tok1 = d_peek["token"]
        self.assertIsNone(federation_registry.verify_agent_token(peek_tok1, bus_dir=str(self.bus_dir)))
        self.assertIsNotNone(
            federation_registry.verify_agent_token(
                peek_tok1,
                bus_dir=str(self.bus_dir),
                allowed_scopes=("full", "peek"),
            )
        )

        # Rotate peek token via Studio -> revokes old peek, keeps full token valid
        r_rot = await self.client.post(
            "/api/federation/agents/studio_peek_ag/rotate",
            headers=admin_hdrs,
            data=json.dumps({"scope": "peek", "revoke_existing": True}),
        )
        self.assertEqual(r_rot.status, 200)
        self.assertIn("no-store", r_rot.headers.get("Cache-Control", "").lower())
        d_rot = await r_rot.json()
        self.assertEqual(d_rot["scope"], "peek")
        self.assertEqual(d_rot["revoked_previous"], 1)
        self.assertIsNone(
            federation_registry.verify_agent_token(
                peek_tok1,
                bus_dir=str(self.bus_dir),
                allowed_scopes=("full", "peek"),
            )
        )
        self.assertIsNotNone(
            federation_registry.verify_agent_token(
                d_rot["token"],
                bus_dir=str(self.bus_dir),
                allowed_scopes=("full", "peek"),
            )
        )
        self.assertIsNotNone(federation_registry.verify_agent_token(full_tok, bus_dir=str(self.bus_dir)))


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
            "webui/src/components/FederationWorkbenchView.tsx",
            "bridge/federation_registry.py",
            "bridge/federation_hub.py",
            "bridge/external_drivers.py",
        ):
            self.assertTrue(export_public.is_public_core(core_rel), f"is_public_core({core_rel!r}) returned False")


# ==============================================================================
# Federation Workbench + AGY_FEDERATION_HUB_PUBLIC_URL Contract Tests (W1..W7)
# ==============================================================================


class TestWorkbenchW1WriteGateAndReadonly(_FederationTestBase):
    """W1: 4-layer Admin write gate (9 counterexamples), oversized body, read gates, readonly isolation."""

    async def test_w1_write_endpoints_nine_counterexamples_and_read_gates(self) -> None:
        from studio.chat_service import MAX_PROMPT_BODY_BYTES

        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        ro_cookie, ro_csrf = await self._login("ViewerUser", RO_PASS)
        forced_cookie, forced_csrf = await self._login("ForcedPwUser", FORCED_PASS)
        admin_hdrs = self._admin_headers(admin_cookie, admin_csrf)

        # Register a pull_worker agent with secret_ref to verify readonly secret_ref masking too
        r_reg = await self.client.post(
            "/api/federation/agents",
            headers=admin_hdrs,
            data=json.dumps(
                {
                    "agent_id": "wb_pull_1",
                    "display_name": "WB Pull 1",
                    "kind": "pull_worker",
                    "secret_ref": "lv" + "1" + "/services/demo-wb#token",
                }
            ),
        )
        self.assertEqual(r_reg.status, 200, await r_reg.text())

        # Read endpoints: unauthenticated -> 401; must_change_password -> 403; readonly -> 200 + masked
        for read_path in (
            "/api/federation/workbench",
            "/api/federation/workbench/agents/wb_pull_1/timeline",
        ):
            r_unauth = await self.client.get(read_path)
            self.assertEqual(r_unauth.status, 401, read_path)
            r_forced = await self.client.get(
                read_path,
                headers={"Cookie": f"{SESSION_COOKIE_NAME}={forced_cookie}"},
            )
            self.assertEqual(r_forced.status, 403, read_path)
            r_ro = await self.client.get(
                read_path,
                headers={"Cookie": f"{SESSION_COOKIE_NAME}={ro_cookie}"},
            )
            self.assertEqual(r_ro.status, 200, f"{read_path}: {await r_ro.text()}")
            self.assertEqual(r_ro.headers.get("Cache-Control"), "no-store, max-age=0")
            d_ro = await r_ro.json()
            self.assertFalse(d_ro["can_edit"])
            if "agents" in d_ro:
                self.assertEqual(d_ro["agents"][0]["secret_ref"], "")
            else:
                self.assertEqual(d_ro["agent"]["secret_ref"], "")

        # Verify write endpoints fail closed across all 9 counterexamples with 0 make_owner_auth calls & 0 disk writes
        write_cases = [
            ("/api/federation/workbench/agents/wb_pull_1/dispatch", json.dumps({"prompt": "ping"})),
            ("/api/federation/workbench/agents/wb_pull_1/jobs/pull-demo-1/cancel", json.dumps({"reason": "stop"})),
        ]
        pq_dir = Path(federation_registry.pull_queue_dir(str(self.bus_dir)))
        jobs_dir = self.bus_dir / "jobs"

        with mock.patch.object(
            federation_registry, "make_owner_auth", wraps=federation_registry.make_owner_auth
        ) as spy_owner:
            for endpoint, payload in write_cases:
                # 1. Unauthenticated -> 401
                r1 = await self.client.post(
                    endpoint,
                    headers={"Origin": self.origin, "Content-Type": "application/json"},
                    data=payload,
                )
                self.assertEqual(r1.status, 401, endpoint)

                # 2. must_change_password=True -> 403
                r2 = await self.client.post(
                    endpoint,
                    headers=self._admin_headers(forced_cookie, forced_csrf),
                    data=payload,
                )
                self.assertEqual(r2.status, 403, endpoint)

                # 3. readonly -> 403
                r3 = await self.client.post(
                    endpoint,
                    headers=self._admin_headers(ro_cookie, ro_csrf),
                    data=payload,
                )
                self.assertEqual(r3.status, 403, endpoint)

                # 4a. Missing Origin -> 403
                h_no_orig = self._admin_headers(admin_cookie, admin_csrf)
                h_no_orig.pop("Origin", None)
                r4a = await self.client.post(endpoint, headers=h_no_orig, data=payload)
                self.assertEqual(r4a.status, 403, endpoint)

                # 4b. Cross-site Origin -> 403
                r4b = await self.client.post(
                    endpoint,
                    headers=self._admin_headers(admin_cookie, admin_csrf, Origin="https://evil.example.com"),
                    data=payload,
                )
                self.assertEqual(r4b.status, 403, endpoint)

                # 5. Sec-Fetch-Site: cross-site -> 403
                r5 = await self.client.post(
                    endpoint,
                    headers=self._admin_headers(admin_cookie, admin_csrf, **{"Sec-Fetch-Site": "cross-site"}),
                    data=payload,
                )
                self.assertEqual(r5.status, 403, endpoint)

                # 6. Non-JSON Content-Type -> 415
                for bad_ct in ("text/plain", "application/x-www-form-urlencoded"):
                    r6 = await self.client.post(
                        endpoint,
                        headers=self._admin_headers(admin_cookie, admin_csrf, **{"Content-Type": bad_ct}),
                        data=payload,
                    )
                    self.assertEqual(r6.status, 415, f"{endpoint} {bad_ct}")

                # 7. Missing & forged X-Studio-CSRF -> 403
                h_no_csrf = self._admin_headers(admin_cookie, admin_csrf)
                h_no_csrf.pop("X-Studio-CSRF", None)
                r7a = await self.client.post(endpoint, headers=h_no_csrf, data=payload)
                self.assertEqual(r7a.status, 403, endpoint)
                r7b = await self.client.post(
                    endpoint,
                    headers=self._admin_headers(admin_cookie, "forged-csrf-token"),
                    data=payload,
                )
                self.assertEqual(r7b.status, 403, endpoint)

                # 9. Oversized body > MAX_PROMPT_BODY_BYTES -> 413
                oversized = json.dumps({"prompt": "x" * (MAX_PROMPT_BODY_BYTES + 256)})
                r9 = await self.client.post(endpoint, headers=admin_hdrs, data=oversized)
                self.assertEqual(r9.status, 413, endpoint)

            # 8. Logged-out / revoked session -> 401/403
            r_out = await self.client.post("/api/auth/logout", headers=admin_hdrs, data="{}")
            self.assertEqual(r_out.status, 200)
            for endpoint, payload in write_cases:
                r8 = await self.client.post(endpoint, headers=admin_hdrs, data=payload)
                self.assertIn(r8.status, (401, 403), endpoint)

            self.assertEqual(spy_owner.call_count, 0)

        self.assertFalse(pq_dir.exists())
        self.assertFalse(jobs_dir.exists())
        audit_text = self.audit_log.read_text(encoding="utf-8")
        for expected_outcome in (
            "denied_auth_401",
            "denied_auth_403",
            "denied_rbac",
            "denied_origin",
            "denied_sec_fetch_site",
            "denied_content_type",
            "denied_csrf",
        ):
            self.assertIn(expected_outcome, audit_text)


class TestWorkbenchW2FieldInjectionAndTargetEligibility(_FederationTestBase):
    """W2: Forbidden client keys, strict types, plaintext secrets, target eligibility, pull vs push routing."""

    async def test_w2_forbidden_keys_type_validation_plaintext_secrets_and_target_routing(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        headers = self._admin_headers(admin_cookie, admin_csrf)

        agents_specs = [
            {"agent_id": "ag_pull_ok", "kind": "pull_worker"},
            {"agent_id": "ag_push_ok", "kind": "hermes_remote", "endpoint_url": "https://node.example.com"},
            {"agent_id": "ag_local_no", "kind": "agy_local"},
            {"agent_id": "ag_mcp_no", "kind": "mcp_inbound_only"},
            {"agent_id": "ag_disabled", "kind": "pull_worker", "enabled": False},
            {"agent_id": "ag_revoked", "kind": "pull_worker"},
            {"agent_id": "ag_norecv", "kind": "pull_worker", "capabilities": {"can_receive": False}},
        ]
        for spec in agents_specs:
            r = await self.client.post("/api/federation/agents", headers=headers, data=json.dumps(spec))
            self.assertEqual(r.status, 200, await r.text())
        r_rev = await self.client.post("/api/federation/agents/ag_revoked/revoke", headers=headers, data="{}")
        self.assertEqual(r_rev.status, 200)

        # 1. Forbidden keys, unknown fields, non-strict types, empty prompt, plaintext secrets -> all 400
        bad_payloads = [
            {"prompt": "hi", "owner_auth": {"is_owner": True}},
            {"prompt": "hi", "is_owner": True},
            {"prompt": "hi", "role": "owner"},
            {"prompt": "hi", "token": SYNTH_FAKE_FED},
            {"prompt": "hi", "api_key": SYNTH_FAKE_SK},
            {"prompt": "hi", "password": "EXAMPLE_RAW_PASSWORD"},
            {"prompt": "hi", "cmd": "id"},
            {"prompt": "hi", "shell": "/bin/sh"},
            {"prompt": "hi", "workdir": "/tmp"},
            {"prompt": "hi", "target_chat_id": -100123},
            {"prompt": "hi", "agent_origin": "local_owner"},
            {"prompt": "hi", "trust_override": "local_admin"},
            {"prompt": "hi", "unknown_extra_field": 1},
            {"prompt": ""},
            {"prompt": "   \t\n  "},
            {"prompt": 12345},
            {"prompt": "hi", "label": 999},
            {"prompt": "hi", "timeout_s": True},
            {"prompt": "hi", "timeout_s": "30"},
            {"prompt": "hi", "timeout_s": 0},
            {"prompt": f"leak {SYNTH_FAKE_SK}"},
            {"prompt": f"leak {SYNTH_FAKE_FED}"},
            {"prompt": "hi", "label": f"bad {SYNTH_FAKE_SK}"},
        ]
        for bad in bad_payloads:
            r_bad = await self.client.post(
                "/api/federation/workbench/agents/ag_pull_ok/dispatch",
                headers=headers,
                data=json.dumps(bad),
            )
            self.assertEqual(r_bad.status, 400, f"Expected 400 for {bad!r}, got {r_bad.status}")

        # 2. Target eligibility fail-closed
        for bad_aid, expected_codes in (
            ("ag_local_no", (400,)),
            ("ag_mcp_no", (400,)),
            ("unregistered_node", (404,)),
            ("ag_disabled", (403,)),
            ("ag_revoked", (403,)),
            ("ag_norecv", (403,)),
        ):
            r_inel = await self.client.post(
                f"/api/federation/workbench/agents/{bad_aid}/dispatch",
                headers=headers,
                data=json.dumps({"prompt": "check eligibility"}),
            )
            self.assertIn(r_inel.status, expected_codes, f"Unexpected status for {bad_aid}: {r_inel.status}")

        pq_dir = Path(federation_registry.pull_queue_dir(str(self.bus_dir)))
        jobs_dir = self.bus_dir / "jobs"
        self.assertFalse(pq_dir.exists())
        self.assertFalse(jobs_dir.exists())

        # 3. Valid pull_worker dispatch -> writes ONLY to PullWorkerQueue, NOT bot_bus
        r_pull = await self.client.post(
            "/api/federation/workbench/agents/ag_pull_ok/dispatch",
            headers=headers,
            data=json.dumps({"prompt": "run edge check", "label": "edge-check", "timeout_s": 120}),
        )
        self.assertEqual(r_pull.status, 200, await r_pull.text())
        d_pull = await r_pull.json()
        self.assertEqual(d_pull["dispatch_mode"], "pull")
        pull_jid = d_pull["job"]["job_id"]
        self.assertTrue((pq_dir / f"{pull_jid}.json").is_file())
        self.assertFalse((jobs_dir / f"{pull_jid}.json").exists())

        # 4. Valid push external agent dispatch -> writes via explicit bus_dir to bot_bus, NOT pull_queue
        r_push = await self.client.post(
            "/api/federation/workbench/agents/ag_push_ok/dispatch",
            headers=headers,
            data=json.dumps({"prompt": "run remote push task", "label": "push-task"}),
        )
        self.assertEqual(r_push.status, 200, await r_push.text())
        d_push = await r_push.json()
        self.assertEqual(d_push["dispatch_mode"], "push")
        push_jid = d_push["job"]["job_id"]
        self.assertTrue((jobs_dir / f"{push_jid}.json").is_file())
        self.assertFalse((pq_dir / f"{push_jid}.json").exists())


class TestWorkbenchW3TraversalAntiSymlinkAndZeroSideEffects(_FederationTestBase):
    """W3: Malformed IDs, directory/file symlinks rejected with 0 bytes leaked, empty BUS_DIR zero side effects."""

    async def test_w3_malformed_ids_symlinks_and_empty_bus_zero_side_effects(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        admin_hdrs = self._admin_headers(admin_cookie, admin_csrf)

        # 3. Empty BUS_DIR -> GET workbench returns 200 and creates ZERO dirs or .lock files
        self.assertEqual(list(self.bus_dir.iterdir()), [])
        r_empty = await self.client.get("/api/federation/workbench", headers=admin_get)
        self.assertEqual(r_empty.status, 200, await r_empty.text())
        self.assertEqual((await r_empty.json())["agents"], [])
        self.assertEqual(list(self.bus_dir.iterdir()), [])

        # 1. Malformed agent_id / job_id -> 400 without touching disk
        for bad_aid in ("UPPER_BAD", "bad.dot", "a" * 65):
            r1 = await self.client.get(
                f"/api/federation/workbench/agents/{bad_aid}/timeline",
                headers=admin_get,
            )
            self.assertEqual(r1.status, 400, f"GET timeline bad_aid={bad_aid}")
            r2 = await self.client.post(
                f"/api/federation/workbench/agents/{bad_aid}/dispatch",
                headers=admin_hdrs,
                data=json.dumps({"prompt": "hi"}),
            )
            self.assertEqual(r2.status, 400, f"POST dispatch bad_aid={bad_aid}")

        for bad_jid in ("..escape", "job..bad", "a" * 130):
            r_cj = await self.client.post(
                f"/api/federation/workbench/agents/wb_sym/jobs/{bad_jid}/cancel",
                headers=admin_hdrs,
                data="{}",
            )
            self.assertEqual(r_cj.status, 400, f"POST cancel bad_jid={bad_jid}")

        self.assertEqual(list(self.bus_dir.iterdir()), [])

        # Prepare canary outside BUS_DIR
        canary = "TOP_SECRET_SYMLINK_CANARY_W3"
        outside_file = self.tmp / "outside_canary.json"
        outside_file.write_text(json.dumps({"prompt": canary, "event_id": canary}), encoding="utf-8")
        outside_dir = self.tmp / "outside_dir"
        outside_dir.mkdir()
        (outside_dir / "leak.json").write_text(
            json.dumps({"job_id": "j1", "target_agent_id": "wb_sym", "target_bot": "wb_sym", "prompt": canary}),
            encoding="utf-8",
        )

        # Register real agent wb_sym
        r_reg = await self.client.post(
            "/api/federation/agents",
            headers=admin_hdrs,
            data=json.dumps({"agent_id": "wb_sym", "kind": "pull_worker"}),
        )
        self.assertEqual(r_reg.status, 200)

        fed_dir = self.bus_dir / "federation"
        pq_dir = fed_dir / "pull_queue"
        le_root = fed_dir / "leader_events"
        le_ag = le_root / "wb_sym"
        jobs_dir = self.bus_dir / "jobs"

        # 2a. Symlinked pull_queue/ dir -> 403, 0 canary leaked
        os.symlink(outside_dir, pq_dir)
        for path in ("/api/federation/workbench", "/api/federation/workbench/agents/wb_sym/timeline"):
            r = await self.client.get(path, headers=admin_get)
            self.assertEqual(r.status, 403, f"pull_queue dir symlink {path}")
            self.assertNotIn(canary, await r.text())
        pq_dir.unlink()

        # 2b. Symlinked .json inside pull_queue/ -> 403, 0 canary leaked
        pq_dir.mkdir(parents=True)
        os.symlink(outside_file, pq_dir / "evil.json")
        r = await self.client.get("/api/federation/workbench/agents/wb_sym/timeline", headers=admin_get)
        self.assertEqual(r.status, 403)
        self.assertNotIn(canary, await r.text())
        (pq_dir / "evil.json").unlink()

        # 2c. Symlinked leader_events/ root dir -> 403
        os.symlink(outside_dir, le_root)
        r = await self.client.get("/api/federation/workbench/agents/wb_sym/timeline", headers=admin_get)
        self.assertEqual(r.status, 403)
        self.assertNotIn(canary, await r.text())
        le_root.unlink()

        # 2d. Symlinked leader_events/<aid>/ dir -> 403
        le_root.mkdir(parents=True)
        os.symlink(outside_dir, le_ag)
        r = await self.client.get("/api/federation/workbench/agents/wb_sym/timeline", headers=admin_get)
        self.assertEqual(r.status, 403)
        self.assertNotIn(canary, await r.text())
        le_ag.unlink()

        # 2e. Symlinked .json inside leader_events/<aid>/ -> 403
        le_ag.mkdir(parents=True)
        os.symlink(outside_file, le_ag / "ev.json")
        r = await self.client.get("/api/federation/workbench/agents/wb_sym/timeline", headers=admin_get)
        self.assertEqual(r.status, 403)
        self.assertNotIn(canary, await r.text())
        (le_ag / "ev.json").unlink()

        # 2f. Symlinked jobs/ dir & symlinked .json inside jobs/ -> 403
        os.symlink(outside_dir, jobs_dir)
        r = await self.client.get("/api/federation/workbench/agents/wb_sym/timeline", headers=admin_get)
        self.assertEqual(r.status, 403)
        self.assertNotIn(canary, await r.text())
        jobs_dir.unlink()

        jobs_dir.mkdir(parents=True)
        os.symlink(outside_file, jobs_dir / "evil_job.json")
        r = await self.client.get("/api/federation/workbench/agents/wb_sym/timeline", headers=admin_get)
        self.assertEqual(r.status, 403)
        self.assertNotIn(canary, await r.text())
        (jobs_dir / "evil_job.json").unlink()

        # 2g. Symlinked federation/ dir itself -> 403
        import shutil

        shutil.rmtree(fed_dir)
        os.symlink(outside_dir, fed_dir)
        r = await self.client.get("/api/federation/workbench", headers=admin_get)
        self.assertEqual(r.status, 403)
        self.assertNotIn(canary, await r.text())

    async def test_w3_write_path_inbox_and_lock_symlinks_rejected_zero_outside_writes(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_hdrs = self._admin_headers(admin_cookie, admin_csrf)

        for spec in (
            {"agent_id": "wb_push_sym", "kind": "hermes_remote", "endpoint_url": "https://push.example.com"},
            {"agent_id": "wb_pull_sym", "kind": "pull_worker"},
        ):
            r_reg = await self.client.post("/api/federation/agents", headers=admin_hdrs, data=json.dumps(spec))
            self.assertEqual(r_reg.status, 200, await r_reg.text())

        outside_dir = self.tmp / "outside_write_sink"
        outside_dir.mkdir()
        inbox_dir = self.bus_dir / "inbox"
        jobs_dir = self.bus_dir / "jobs"
        bus_lock = self.bus_dir / "bus.lock"
        pq_dir = Path(federation_registry.pull_queue_dir(str(self.bus_dir)))
        pq_lock = pq_dir / ".lock"

        # Seed an in-flight push job and pull job for cancel anti-symlink tests
        jobs_dir.mkdir(parents=True, exist_ok=True)
        (jobs_dir / "job-push-sym-1.json").write_text(
            json.dumps(
                {
                    "job_id": "job-push-sym-1",
                    "target_bot": "wb_push_sym",
                    "from_bot": "studio",
                    "prompt": "push sym test",
                    "status": "queued",
                    "cancel_requested": False,
                    "created_at": time.time() - 5,
                }
            ),
            encoding="utf-8",
        )
        pq_dir.mkdir(parents=True, exist_ok=True)
        (pq_dir / "pull-sym-1.json").write_text(
            json.dumps(
                {
                    "job_id": "pull-sym-1",
                    "target_agent_id": "wb_pull_sym",
                    "prompt": "pull sym test",
                    "status": "queued",
                    "cancelled": False,
                    "created_at": time.time() - 5,
                }
            ),
            encoding="utf-8",
        )

        # 1. <BUS_DIR>/inbox -> <outside> blocks BOTH push dispatch and push cancel with 0 writes to <outside>
        os.symlink(outside_dir, inbox_dir)
        try:
            r_d = await self.client.post(
                "/api/federation/workbench/agents/wb_push_sym/dispatch",
                headers=admin_hdrs,
                data=json.dumps({"prompt": "should block inbox symlink"}),
            )
            self.assertEqual(r_d.status, 403)
            self.assertEqual((await r_d.json()).get("code"), "SECURITY_SYMLINK_REJECTED")

            r_c = await self.client.post(
                "/api/federation/workbench/agents/wb_push_sym/jobs/job-push-sym-1/cancel",
                headers=admin_hdrs,
                data="{}",
            )
            self.assertEqual(r_c.status, 403)
            self.assertEqual((await r_c.json()).get("code"), "SECURITY_SYMLINK_REJECTED")
            self.assertEqual(list(outside_dir.iterdir()), [])
        finally:
            inbox_dir.unlink()

        # 2. <BUS_DIR>/inbox/<aid> -> <outside> blocks BOTH push dispatch and push cancel with 0 writes to <outside>
        inbox_dir.mkdir(parents=True, exist_ok=True)
        inbox_aid = inbox_dir / "wb_push_sym"
        os.symlink(outside_dir, inbox_aid)
        try:
            r_d = await self.client.post(
                "/api/federation/workbench/agents/wb_push_sym/dispatch",
                headers=admin_hdrs,
                data=json.dumps({"prompt": "should block inbox aid symlink"}),
            )
            self.assertEqual(r_d.status, 403)
            self.assertEqual((await r_d.json()).get("code"), "SECURITY_SYMLINK_REJECTED")

            r_c = await self.client.post(
                "/api/federation/workbench/agents/wb_push_sym/jobs/job-push-sym-1/cancel",
                headers=admin_hdrs,
                data="{}",
            )
            self.assertEqual(r_c.status, 403)
            self.assertEqual((await r_c.json()).get("code"), "SECURITY_SYMLINK_REJECTED")
            self.assertEqual(list(outside_dir.iterdir()), [])
        finally:
            inbox_aid.unlink()

        # 3. <BUS_DIR>/bus.lock -> <outside>/bus.lock blocks BOTH push dispatch and push cancel with 0 writes to <outside>
        outside_bus_lock = outside_dir / "bus.lock"
        os.symlink(outside_bus_lock, bus_lock)
        try:
            r_d = await self.client.post(
                "/api/federation/workbench/agents/wb_push_sym/dispatch",
                headers=admin_hdrs,
                data=json.dumps({"prompt": "should block bus.lock symlink"}),
            )
            self.assertEqual(r_d.status, 403)
            self.assertEqual((await r_d.json()).get("code"), "SECURITY_SYMLINK_REJECTED")

            r_c = await self.client.post(
                "/api/federation/workbench/agents/wb_push_sym/jobs/job-push-sym-1/cancel",
                headers=admin_hdrs,
                data="{}",
            )
            self.assertEqual(r_c.status, 403)
            self.assertEqual((await r_c.json()).get("code"), "SECURITY_SYMLINK_REJECTED")
            self.assertFalse(outside_bus_lock.exists())
            self.assertEqual(list(outside_dir.iterdir()), [])
        finally:
            bus_lock.unlink()

        # 4. <BUS_DIR>/federation/pull_queue/.lock -> <outside>/pq.lock blocks BOTH pull dispatch and pull cancel
        outside_pq_lock = outside_dir / "pq.lock"
        os.symlink(outside_pq_lock, pq_lock)
        try:
            r_d = await self.client.post(
                "/api/federation/workbench/agents/wb_pull_sym/dispatch",
                headers=admin_hdrs,
                data=json.dumps({"prompt": "should block pull .lock symlink"}),
            )
            self.assertEqual(r_d.status, 403)
            self.assertEqual((await r_d.json()).get("code"), "SECURITY_SYMLINK_REJECTED")

            r_c = await self.client.post(
                "/api/federation/workbench/agents/wb_pull_sym/jobs/pull-sym-1/cancel",
                headers=admin_hdrs,
                data="{}",
            )
            self.assertEqual(r_c.status, 403)
            self.assertEqual((await r_c.json()).get("code"), "SECURITY_SYMLINK_REJECTED")
            self.assertFalse(outside_pq_lock.exists())
            self.assertEqual(list(outside_dir.iterdir()), [])
        finally:
            pq_lock.unlink()

        # Verify jobs remained untouched and audit log recorded denied_symlink
        self.assertEqual(json.loads((jobs_dir / "job-push-sym-1.json").read_text(encoding="utf-8"))["status"], "queued")
        self.assertEqual(json.loads((pq_dir / "pull-sym-1.json").read_text(encoding="utf-8"))["status"], "queued")
        audit_text = self.audit_log.read_text(encoding="utf-8")
        self.assertIn("denied_symlink", audit_text)


class TestWorkbenchW4RedactionLeaderSummaryAndFrontendXSS(_FederationTestBase):
    """W4: Cross-endpoint deep secret/path redaction, safe leader_events summary, frontend XSS & zero-persistence."""

    async def test_w4_deep_redaction_leader_events_summary_and_frontend_static_guards(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        headers = self._admin_headers(admin_cookie, admin_csrf)

        r_reg = await self.client.post(
            "/api/federation/agents",
            headers=headers,
            data=json.dumps({"agent_id": "wb_redact", "kind": "pull_worker", "mint_token": True}),
        )
        self.assertEqual(r_reg.status, 200)
        minted_tok = (await r_reg.json())["token"]

        # Plant dirty pull_queue job & leader_event on disk with secrets, hashes, host paths, and XSS payloads
        pq_dir = Path(federation_registry.pull_queue_dir(str(self.bus_dir)))
        pq_dir.mkdir(parents=True, exist_ok=True)
        (pq_dir / "pull-dirty-1.json").write_text(
            json.dumps(
                {
                    "job_id": "pull-dirty-1",
                    "target_agent_id": "wb_redact",
                    "from_agent_id": "",
                    "team_id": "team-1",
                    "prompt": f"check {SYNTH_HOST_PATH} with {SYNTH_FAKE_SK}",
                    "result_text": f"done {SYNTH_FAKE_FED} <script>alert(1)</script> <img src=x onerror=alert(1)>",
                    "error": f"err {SYNTH_HOST_PATH} {minted_tok}",
                    "cancel_reason": f"reason {SYNTH_FAKE_SK}",
                    "status": "done",
                    "token_hash": "LEAK_HASH_999",
                    "salt": "LEAK_SALT_999",
                    "metadata": {"source": "studio", "api_key": SYNTH_FAKE_SK},
                    "created_at": time.time() - 30,
                    "finished_at": time.time() - 10,
                }
            ),
            encoding="utf-8",
        )

        le_dir = self.bus_dir / "federation" / "leader_events" / "wb_redact"
        le_dir.mkdir(parents=True, exist_ok=True)
        (le_dir / "0001_ev-1.json").write_text(
            json.dumps(
                {
                    "event_id": "ev-redact-1",
                    "type": "batch_done",
                    "group_id": "grp-1",
                    "team_id": "team-1",
                    "job_ids": ["pull-dirty-1"],
                    "jobs": [{"job_id": "pull-dirty-1", "status": "done", "result_text": "SENSITIVE_RAW_JOB_PAYLOAD"}],
                    "sensitive_extra_blob": "MUST_NOT_APPEAR_IN_SUMMARY",
                    "token_records": [{"token_hash": "LEAK_EV_HASH"}],
                    "created_at": time.time() - 5,
                }
            ),
            encoding="utf-8",
        )

        for path in ("/api/federation/workbench", "/api/federation/workbench/agents/wb_redact/timeline"):
            r = await self.client.get(path, headers=admin_get)
            self.assertEqual(r.status, 200, await r.text())
            self.assertEqual(r.headers.get("Cache-Control"), "no-store, max-age=0")
            body_txt = await r.text()
            for forbidden in (
                SYNTH_FAKE_SK,
                SYNTH_FAKE_FED,
                SYNTH_PREFIX,
                minted_tok,
                SYNTH_HOST_PATH,
                "LEAK_HASH_999",
                "LEAK_SALT_999",
                "LEAK_EV_HASH",
                "token_hash",
                "token_records",
                "SENSITIVE_RAW_JOB_PAYLOAD",
                "MUST_NOT_APPEAR_IN_SUMMARY",
            ):
                self.assertNotIn(forbidden, body_txt, f"Leak {forbidden!r} in {path}")

        # Verify SSE ring buffer & audit log contain zero secrets
        for _seq, _et, ev_data in list(self.app[EVENT_HUB_KEY]._events):
            ev_txt = json.dumps(ev_data)
            self.assertNotIn(SYNTH_PREFIX, ev_txt)
            self.assertNotIn(minted_tok, ev_txt)
        audit_txt = self.audit_log.read_text(encoding="utf-8")
        self.assertNotIn(SYNTH_PREFIX, audit_txt)
        self.assertNotIn(minted_tok, audit_txt)

        # Static XSS & zero-persistence guards on FederationWorkbenchView.tsx and FederationView.tsx
        wb_tsx = (REPO_ROOT / "webui" / "src" / "components" / "FederationWorkbenchView.tsx").read_text(
            encoding="utf-8"
        )
        fed_tsx = (REPO_ROOT / "webui" / "src" / "components" / "FederationView.tsx").read_text(
            encoding="utf-8"
        )
        for src_name, src_txt in (("FederationWorkbenchView.tsx", wb_tsx), ("FederationView.tsx", fed_tsx)):
            for sink in (
                "dangerouslySetInnerHTML",
                "innerHTML",
                "<script",
                "localStorage",
                "sessionStorage",
                "document.cookie",
                "workbench/state",
                "unp" + "kg" + "." + "com",
                "cdn." + "jsdelivr",
                "cdnjs." + "cloudflare",
            ):
                self.assertNotIn(sink, src_txt, f"Forbidden sink {sink!r} in {src_name}")
        self.assertIn("SafeMarkdown", wb_tsx)
        self.assertIn("setOneTimeToken(null)", fed_tsx)


class TestWorkbenchW5HubPublicUrlValidationAndAntiSSRF(_FederationTestBase):
    """W5: Strict AGY_FEDERATION_HUB_PUBLIC_URL validation & Anti-SSRF loopback-only health probe."""

    async def test_w5_public_url_validator_hub_config_and_loopback_only_health(self) -> None:
        # 1. Invalid values fail-closed to ""
        invalid_urls = [
            "",
            "http://hub.example.com",
            "http://hub.example.com:18799",
            "https://user:pass@hub.example.com",
            "https://user@hub.example.com",
            "https://hub.example.com?a=1",
            "https://hub.example.com?",
            "https://hub.example.com#frag",
            "https://hub.example.com#",
            "https://hub.example.com/hub",
            "https://hub.example.com/hub/mcp",
            "https://hub.example.com:",
            "https://hub.example.com:0",
            "https://hub.example.com:99999",
            "https://hub.example.com\r\n",
            "https://hub.example.com ",
            " https://hub.example.com",
            "http://" + ".".join(("127", "0", "0", "2")) + ":18799",
            f"http://{SYNTH_IMDS_IP}",
            f"https://{SYNTH_IMDS_IP}",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "ftp://hub.example.com",
            "http://[0:0:0:0:0:0:0:1]:18799",
        ]
        for bad in invalid_urls:
            self.assertEqual(_validate_hub_public_url(bad), "", f"Expected rejection for {bad!r}")

        # 2. Valid values normalized (trailing slash stripped)
        valid_cases = [
            ("https://hub.example.com/", "https://hub.example.com"),
            ("https://hub.example.com", "https://hub.example.com"),
            ("https://hub.example.com:8443", "https://hub.example.com:8443"),
            ("https://hub.example.com:8443/", "https://hub.example.com:8443"),
            ("http://127.0.0.1:18799", "http://127.0.0.1:18799"),
            ("http://127.0.0.1:18799/", "http://127.0.0.1:18799"),
            ("http://localhost:18799/", "http://localhost:18799"),
            ("http://[::1]:18799", "http://[::1]:18799"),
        ]
        for raw, expected in valid_cases:
            self.assertEqual(_validate_hub_public_url(raw), expected, f"Expected {expected!r} for {raw!r}")

        # 3. End-to-end API behavior + Anti-SSRF proof: probe_hub_health NEVER requests public_url
        admin_cookie, _ = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}

        loopback_hits: list[str] = []

        async def handle_stub_health(_req: web.Request) -> web.Response:
            loopback_hits.append(str(_req.url))
            return web.json_response({"ok": True, "service": "agy-federation-hub"})

        stub_app = web.Application()
        stub_app.router.add_get("/hub/v1/health", handle_stub_health)
        stub_server = TestServer(stub_app)
        await stub_server.start_server()
        try:
            self.fed_svc._hub_host_override = "127.0.0.1"
            self.fed_svc._hub_port_override = stub_server.port
            expected_loopback_mcp = f"http://127.0.0.1:{stub_server.port}/hub/mcp"

            # Invalid env -> public_url="" and mcp_url falls back to loopback
            with mock.patch.dict(os.environ, {"AGY_FEDERATION_HUB_PUBLIC_URL": "http://hub.example.com"}):
                r_inv = await self.client.get("/api/federation/overview", headers=admin_get)
                self.assertEqual(r_inv.status, 200)
                hc = (await r_inv.json())["hub_config"]
                self.assertEqual(hc["public_url"], "")
                self.assertEqual(hc["loopback_mcp_url"], expected_loopback_mcp)
                self.assertEqual(hc["mcp_url"], expected_loopback_mcp)

            # Valid public URL -> exposed in hub_config, while health probe strictly hits loopback only
            probed_urls: list[str] = []
            orig_get = aiohttp.ClientSession.get

            def spy_get(session_self, url, *args, **kwargs):
                probed_urls.append(str(url))
                return orig_get(session_self, url, *args, **kwargs)

            with (
                mock.patch.dict(os.environ, {"AGY_FEDERATION_HUB_PUBLIC_URL": "https://hub.example.com/"}),
                mock.patch.object(aiohttp.ClientSession, "get", new=spy_get),
            ):
                r_ov = await self.client.get("/api/federation/overview", headers=admin_get)
                self.assertEqual(r_ov.status, 200)
                d_ov = await r_ov.json()
                self.assertEqual(d_ov["hub_config"]["public_url"], "https://hub.example.com")
                self.assertEqual(d_ov["hub_config"]["loopback_mcp_url"], expected_loopback_mcp)
                self.assertEqual(d_ov["hub_config"]["mcp_url"], "https://hub.example.com/hub/mcp")
                self.assertTrue(d_ov["hub_health"]["reachable"])

                r_hl = await self.client.get("/api/federation/health", headers=admin_get)
                self.assertEqual(r_hl.status, 200)
                self.assertTrue((await r_hl.json())["reachable"])

                r_wb = await self.client.get("/api/federation/workbench", headers=admin_get)
                self.assertEqual(r_wb.status, 200)
                self.assertEqual((await r_wb.json())["hub_config"]["public_url"], "https://hub.example.com")

            self.assertTrue(probed_urls)
            for u in probed_urls:
                self.assertTrue(u.startswith(f"http://127.0.0.1:{stub_server.port}/hub/v1/health"), u)
                self.assertNotIn("hub.example.com", u)
        finally:
            await stub_server.close()

    async def test_w5_blocker1_alt_ipv4_ipv6_mapped_zone_and_noncanonical_loopback_rejected(self) -> None:
        # Alternative IPv4 encodings, IPv6 zone IDs, IPv4-mapped IPv6, and non-canonical loopbacks MUST fail-closed
        https_prefix = "https" + "://"
        ip_127_0_0_1 = ".".join(("127", "0", "0", "1"))
        ip_127_0_0_2 = ".".join(("127", "0", "0", "2"))
        ip_169_254_short = ".".join(("169", "254", "43518"))
        imds_dec = str(0xA9FEA9FE)
        loopback_dec = str(0x7F000001)
        bypass_urls = [
            f"{https_prefix}{imds_dec}",
            f"{https_prefix}0251.0376.0251.0376",
            f"{https_prefix}0xa9.0xfe.0xa9.0xfe",
            f"{https_prefix}{ip_169_254_short}",
            f"{https_prefix}0",
            f"{https_prefix}{loopback_dec}",
            f"{https_prefix}127.1",
            f"{https_prefix}0x7f000001",
            f"{https_prefix}[2001:db8::1%eth0]",
            f"{https_prefix}[2001:db8::1%25eth0]",
            f"{https_prefix}{ip_127_0_0_2}",
            f"{https_prefix}[::ffff:{ip_127_0_0_1}]",
            f"{https_prefix}[::ffff:{ip_127_0_0_2}]",
            f"{https_prefix}[::ffff:{SYNTH_IMDS_IP}]",
            f"{https_prefix}[0:0:0:0:0:0:0:1]",
            f"{https_prefix}hub%2eexample.com",
            f"{https_prefix}singlelabel",
        ]
        for bad in bypass_urls:
            self.assertEqual(_validate_hub_public_url(bad), "", f"Expected bypass rejection for {bad!r}")

        # Legitimate canonical HTTPS targets remain accepted
        punycode_host = ".".join(("hub", "xn--fiqs8s"))
        for raw, expected in (
            (f"{https_prefix}localhost", f"{https_prefix}localhost"),
            (f"{https_prefix}localhost:8443/", f"{https_prefix}localhost:8443"),
            (f"{https_prefix}{ip_127_0_0_1}:8443/", f"{https_prefix}{ip_127_0_0_1}:8443"),
            (f"{https_prefix}[::1]:8443/", f"{https_prefix}[::1]:8443"),
            (f"{https_prefix}{punycode_host}:8443/", f"{https_prefix}{punycode_host}:8443"),
        ):
            self.assertEqual(_validate_hub_public_url(raw), expected, f"Expected valid URL for {raw!r}")


class TestWorkbenchW6DedupMergeAndCancelIdempotency(_FederationTestBase):
    """W6: Cross-source dedup merge, cross-agent isolation, terminal idempotency, dual atomic cancel, dotted job_id."""

    async def test_w6_cross_source_dedup_cross_agent_isolation_and_atomic_dual_cancel(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        headers = self._admin_headers(admin_cookie, admin_csrf)

        for aid in ("ag_alpha", "ag_beta"):
            r = await self.client.post(
                "/api/federation/agents",
                headers=headers,
                data=json.dumps({"agent_id": aid, "kind": "pull_worker"}),
            )
            self.assertEqual(r.status, 200)

        pq_dir = Path(federation_registry.pull_queue_dir(str(self.bus_dir)))
        pq_dir.mkdir(parents=True, exist_ok=True)
        jobs_dir = self.bus_dir / "jobs"
        jobs_dir.mkdir(parents=True, exist_ok=True)
        now = time.time()

        # 1. Same job_id in both PullWorkerQueue (done) and bot_bus (running) + other agent job interference
        (pq_dir / "job-shared-done.json").write_text(
            json.dumps(
                {
                    "job_id": "job-shared-done",
                    "target_agent_id": "ag_alpha",
                    "prompt": "shared task",
                    "status": "done",
                    "result_text": "FINAL_ALPHA_RESULT",
                    "created_at": now - 60,
                    "claimed_at": now - 55,
                    "finished_at": now - 40,
                    "metadata": {"bridged_from_bot_bus": True},
                }
            ),
            encoding="utf-8",
        )
        (jobs_dir / "job-shared-done.json").write_text(
            json.dumps(
                {
                    "job_id": "job-shared-done",
                    "target_bot": "ag_alpha",
                    "from_bot": "coord_bot",
                    "origin_chat_id": -100999,
                    "prompt": "shared task",
                    "status": "running",
                    "created_at": now - 60,
                    "started_at": now - 55,
                    "finished_at": 0.0,
                }
            ),
            encoding="utf-8",
        )
        # Other agent's job that must NEVER leak into ag_alpha's timeline
        (pq_dir / "pull-beta-only.json").write_text(
            json.dumps(
                {
                    "job_id": "pull-beta-only",
                    "target_agent_id": "ag_beta",
                    "prompt": "beta secret task",
                    "status": "queued",
                    "created_at": now - 20,
                }
            ),
            encoding="utf-8",
        )

        # In-flight bridged job in BOTH PullWorkerQueue (queued) and bot_bus (queued)
        (pq_dir / "job-bridged-inflight.json").write_text(
            json.dumps(
                {
                    "job_id": "job-bridged-inflight",
                    "target_agent_id": "ag_alpha",
                    "prompt": "bridged cancel test",
                    "status": "queued",
                    "cancelled": False,
                    "created_at": now - 15,
                    "metadata": {"bridged_from_bot_bus": True},
                }
            ),
            encoding="utf-8",
        )
        (jobs_dir / "job-bridged-inflight.json").write_text(
            json.dumps(
                {
                    "job_id": "job-bridged-inflight",
                    "target_bot": "ag_alpha",
                    "from_bot": "studio",
                    "prompt": "bridged cancel test",
                    "status": "queued",
                    "cancel_requested": False,
                    "created_at": now - 15,
                }
            ),
            encoding="utf-8",
        )

        # Dotted bot_bus job_id (invalid for PULL_JOB_ID_RE, valid for bot_bus.JOB_ID_RE)
        (jobs_dir / "job-2026.11.dotted.json").write_text(
            json.dumps(
                {
                    "job_id": "job-2026.11.dotted",
                    "target_bot": "ag_alpha",
                    "from_bot": "studio",
                    "prompt": "dotted bus job",
                    "status": "queued",
                    "cancel_requested": False,
                    "created_at": now - 10,
                }
            ),
            encoding="utf-8",
        )

        r_tl = await self.client.get(
            "/api/federation/workbench/agents/ag_alpha/timeline",
            headers=admin_get,
        )
        self.assertEqual(r_tl.status, 200, await r_tl.text())
        tl = (await r_tl.json())["timeline"]
        jids = [item["job_id"] for item in tl]
        # Strict dedup + zero cross-agent leakage
        self.assertEqual(jids.count("job-shared-done"), 1)
        self.assertNotIn("pull-beta-only", jids)
        shared = next(it for it in tl if it["job_id"] == "job-shared-done")
        self.assertEqual(shared["status"], "done")
        self.assertEqual(shared["result_text"], "FINAL_ALPHA_RESULT")
        self.assertEqual(shared["source"], "telegram")
        self.assertTrue(shared["bridged"])

        # 2. Cross-agent cancel rejected with 404, target untouched
        r_x = await self.client.post(
            "/api/federation/workbench/agents/ag_alpha/jobs/pull-beta-only/cancel",
            headers=headers,
            data="{}",
        )
        self.assertEqual(r_x.status, 404)
        beta_after = json.loads((pq_dir / "pull-beta-only.json").read_text(encoding="utf-8"))
        self.assertEqual(beta_after["status"], "queued")

        # 3. Terminal `done` job cancel -> idempotent, never overwrites result_text or status
        r_term = await self.client.post(
            "/api/federation/workbench/agents/ag_alpha/jobs/job-shared-done/cancel",
            headers=headers,
            data=json.dumps({"reason": "late_cancel"}),
        )
        self.assertEqual(r_term.status, 200)
        d_term = await r_term.json()
        self.assertTrue(d_term["already_terminal"])
        self.assertFalse(d_term["cancelled"])
        self.assertEqual(d_term["status"], "done")
        self.assertEqual(d_term["job"]["result_text"], "FINAL_ALPHA_RESULT")

        # Non-existent job cancel -> 404
        r_404 = await self.client.post(
            "/api/federation/workbench/agents/ag_alpha/jobs/job-does-not-exist/cancel",
            headers=headers,
            data="{}",
        )
        self.assertEqual(r_404.status, 404)

        # 4. In-flight bridged job cancel -> dual-side atomic cancel (both pull_queue and bot_bus cancelled)
        r_dual = await self.client.post(
            "/api/federation/workbench/agents/ag_alpha/jobs/job-bridged-inflight/cancel",
            headers=headers,
            data=json.dumps({"reason": "operator_stop"}),
        )
        self.assertEqual(r_dual.status, 200, await r_dual.text())
        d_dual = await r_dual.json()
        self.assertTrue(d_dual["cancelled"])
        self.assertEqual(d_dual["status"], "cancelled")
        pq_after = json.loads((pq_dir / "job-bridged-inflight.json").read_text(encoding="utf-8"))
        bus_after = json.loads((jobs_dir / "job-bridged-inflight.json").read_text(encoding="utf-8"))
        self.assertEqual(pq_after["status"], "cancelled")
        self.assertEqual(bus_after["status"], "cancelled")

        # 5. Dotted bot_bus job_id cancel succeeds cleanly without PullWorkerQueue ValueError
        r_dot = await self.client.post(
            "/api/federation/workbench/agents/ag_alpha/jobs/job-2026.11.dotted/cancel",
            headers=headers,
            data="{}",
        )
        self.assertEqual(r_dot.status, 200, await r_dot.text())
        self.assertTrue((await r_dot.json())["cancelled"])
        dot_after = json.loads((jobs_dir / "job-2026.11.dotted.json").read_text(encoding="utf-8"))
        self.assertEqual(dot_after["status"], "cancelled")

    async def test_w6_blocker3_terminal_priority_cancel_race_and_value_error_not_silenced(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        headers = self._admin_headers(admin_cookie, admin_csrf)

        r_reg = await self.client.post(
            "/api/federation/agents",
            headers=headers,
            data=json.dumps({"agent_id": "ag_race", "kind": "pull_worker"}),
        )
        self.assertEqual(r_reg.status, 200, await r_reg.text())

        pq_dir = Path(federation_registry.pull_queue_dir(str(self.bus_dir)))
        pq_dir.mkdir(parents=True, exist_ok=True)
        jobs_dir = self.bus_dir / "jobs"
        jobs_dir.mkdir(parents=True, exist_ok=True)
        now = time.time()

        # 1. Terminal merge semantic priority: pull=done(T1) + bus=cancelled(T2 > T1) MUST stay `done` & preserve result_text
        t1 = now - 50
        t2 = now - 10
        merged_done_vs_cancel = _merge_single_timeline_job(
            "job-term-prio-1",
            {
                "job_id": "job-term-prio-1",
                "target_agent_id": "ag_race",
                "prompt": "priority check",
                "status": "done",
                "result_text": "DONE_AT_T1_PRESERVED",
                "created_at": now - 80,
                "finished_at": t1,
            },
            {
                "job_id": "job-term-prio-1",
                "target_bot": "ag_race",
                "from_bot": "studio",
                "prompt": "priority check",
                "status": "cancelled",
                "cancel_reason": "late_cancel_t2",
                "created_at": now - 80,
                "finished_at": t2,
            },
            is_admin=True,
            now_ts=now,
        )
        self.assertEqual(merged_done_vs_cancel["status"], "done")
        self.assertEqual(merged_done_vs_cancel["result_text"], "DONE_AT_T1_PRESERVED")

        # Also verify `error` > `cancelled` regardless of newer cancelled timestamp, and same-class uses finished_at
        merged_err_vs_cancel = _merge_single_timeline_job(
            "job-term-prio-2",
            {"job_id": "job-term-prio-2", "status": "error", "error": "ERR_T1", "finished_at": t1, "created_at": now - 80},
            {"job_id": "job-term-prio-2", "status": "cancelled", "cancel_reason": "C_T2", "finished_at": t2, "created_at": now - 80},
            is_admin=True,
            now_ts=now,
        )
        self.assertEqual(merged_err_vs_cancel["status"], "error")
        self.assertEqual(merged_err_vs_cancel["error"], "ERR_T1")

        merged_same_class = _merge_single_timeline_job(
            "job-term-prio-3",
            {"job_id": "job-term-prio-3", "status": "done", "result_text": "OLDER_DONE", "finished_at": t1, "created_at": now - 80},
            {"job_id": "job-term-prio-3", "status": "done", "result_text": "NEWER_DONE", "finished_at": t2, "created_at": now - 80},
            is_admin=True,
            now_ts=now,
        )
        self.assertEqual(merged_same_class["status"], "done")
        self.assertEqual(merged_same_class["result_text"], "NEWER_DONE")

        # Verify end-to-end via timeline endpoint for pull=done(T1) + bus=cancelled(T2 > T1)
        (pq_dir / "job-merge-e2e.json").write_text(
            json.dumps(
                {
                    "job_id": "job-merge-e2e",
                    "target_agent_id": "ag_race",
                    "prompt": "merge e2e",
                    "status": "done",
                    "result_text": "E2E_DONE_T1",
                    "created_at": now - 90,
                    "finished_at": t1,
                }
            ),
            encoding="utf-8",
        )
        (jobs_dir / "job-merge-e2e.json").write_text(
            json.dumps(
                {
                    "job_id": "job-merge-e2e",
                    "target_bot": "ag_race",
                    "from_bot": "studio",
                    "prompt": "merge e2e",
                    "status": "cancelled",
                    "cancel_reason": "late_bus_cancel",
                    "created_at": now - 90,
                    "finished_at": t2,
                }
            ),
            encoding="utf-8",
        )
        r_tl = await self.client.get("/api/federation/workbench/agents/ag_race/timeline", headers=admin_get)
        self.assertEqual(r_tl.status, 200)
        e2e_item = next(it for it in (await r_tl.json())["timeline"] if it["job_id"] == "job-merge-e2e")
        self.assertEqual(e2e_item["status"], "done")
        self.assertEqual(e2e_item["result_text"], "E2E_DONE_T1")

        # 2. Dual-side cancel race: PullWorkerQueue.cancel() returns already `done` -> MUST skip bot_bus.cancel_job_in_dir()
        race_jid = "job-race-done-1"
        (pq_dir / f"{race_jid}.json").write_text(
            json.dumps(
                {
                    "job_id": race_jid,
                    "target_agent_id": "ag_race",
                    "prompt": "race cancel task",
                    "status": "claimed",
                    "cancelled": False,
                    "created_at": now - 30,
                }
            ),
            encoding="utf-8",
        )
        (jobs_dir / f"{race_jid}.json").write_text(
            json.dumps(
                {
                    "job_id": race_jid,
                    "target_bot": "ag_race",
                    "from_bot": "studio",
                    "prompt": "race cancel task",
                    "status": "running",
                    "cancel_requested": False,
                    "created_at": now - 30,
                }
            ),
            encoding="utf-8",
        )
        raced_done_rec = {
            "job_id": race_jid,
            "target_agent_id": "ag_race",
            "prompt": "race cancel task",
            "status": "done",
            "result_text": "RACED_DONE_RESULT_INTACT",
            "cancelled": False,
            "created_at": now - 30,
            "finished_at": now - 1,
        }
        with (
            mock.patch.object(federation_registry.PullWorkerQueue, "cancel", return_value=raced_done_rec),
            mock.patch.object(bot_bus, "cancel_job_in_dir", wraps=bot_bus.cancel_job_in_dir) as spy_bus_cancel,
        ):
            r_race = await self.client.post(
                f"/api/federation/workbench/agents/ag_race/jobs/{race_jid}/cancel",
                headers=headers,
                data=json.dumps({"reason": "too_late"}),
            )
            self.assertEqual(r_race.status, 200, await r_race.text())
            d_race = await r_race.json()
            self.assertTrue(d_race["already_terminal"])
            self.assertFalse(d_race["cancelled"])
            self.assertEqual(d_race["status"], "done")
            self.assertEqual(d_race["job"]["result_text"], "RACED_DONE_RESULT_INTACT")
            self.assertEqual(spy_bus_cancel.call_count, 0)

        # bot_bus job on disk MUST remain untouched (not overwritten to cancelled)
        bus_race_after = json.loads((jobs_dir / f"{race_jid}.json").read_text(encoding="utf-8"))
        self.assertEqual(bus_race_after["status"], "running")
        self.assertFalse(bus_race_after["cancel_requested"])

        # Same race when PullWorkerQueue.cancel() returns already `error`
        raced_err_rec = {
            "job_id": race_jid,
            "target_agent_id": "ag_race",
            "prompt": "race cancel task",
            "status": "error",
            "error": "WORKER_FAILED_FIRST",
            "cancelled": False,
            "created_at": now - 30,
            "finished_at": now - 1,
        }
        with (
            mock.patch.object(federation_registry.PullWorkerQueue, "cancel", return_value=raced_err_rec),
            mock.patch.object(bot_bus, "cancel_job_in_dir", wraps=bot_bus.cancel_job_in_dir) as spy_bus_cancel_err,
        ):
            r_race_err = await self.client.post(
                f"/api/federation/workbench/agents/ag_race/jobs/{race_jid}/cancel",
                headers=headers,
                data="{}",
            )
            self.assertEqual(r_race_err.status, 200, await r_race_err.text())
            d_err = await r_race_err.json()
            self.assertTrue(d_err["already_terminal"])
            self.assertFalse(d_err["cancelled"])
            self.assertEqual(d_err["status"], "error")
            self.assertEqual(d_err["job"]["error"], "WORKER_FAILED_FIRST")
            self.assertEqual(spy_bus_cancel_err.call_count, 0)

        # 3. PullWorkerQueue.cancel() raising ValueError MUST NOT silently return 200 OK
        with (
            mock.patch.object(
                federation_registry.PullWorkerQueue,
                "cancel",
                side_effect=ValueError("invalid pull queue state"),
            ),
            mock.patch.object(bot_bus, "cancel_job_in_dir", wraps=bot_bus.cancel_job_in_dir) as spy_bus_cancel_ve,
        ):
            r_ve = await self.client.post(
                f"/api/federation/workbench/agents/ag_race/jobs/{race_jid}/cancel",
                headers=headers,
                data="{}",
            )
            self.assertEqual(r_ve.status, 400, f"Expected 400 on ValueError, got {r_ve.status}")
            self.assertIn("invalid pull queue state", await r_ve.text())
            self.assertEqual(spy_bus_cancel_ve.call_count, 0)
        audit_text = self.audit_log.read_text(encoding="utf-8")
        self.assertIn("invalid_request", audit_text)
        self.assertIn('"status_code":400', audit_text.replace(" ", ""))


class TestWorkbenchW7NavigationSpaShellDemoAndRedlines(_FederationTestBase):
    """W7: Navigation order, zero-data /federation-workbench SPA shell, zero personal domains."""

    async def test_w7_navigation_order_spa_shell_and_zero_personal_domains(self) -> None:
        # 1. Desktop nav order: DESKTOP_NAV_ITEMS[0] == workspace, [1] == federation-workbench
        app_tsx = (REPO_ROOT / "webui" / "src" / "App.tsx").read_text(encoding="utf-8")
        nav_match = re.search(r"const DESKTOP_NAV_ITEMS[^=]*=\s*\[(.*?)\];", app_tsx, re.DOTALL)
        self.assertIsNotNone(nav_match)
        desktop_ids = re.findall(r'id:\s*"([^"]+)"', nav_match.group(1))
        self.assertGreaterEqual(len(desktop_ids), 2)
        self.assertEqual(desktop_ids[0], "workspace")
        self.assertEqual(desktop_ids[1], "federation-workbench")
        self.assertIn('path === "federation-workbench"', app_tsx)
        self.assertIn("FederationWorkbenchView", app_tsx)

        # MobileMoreSheet order: SHEET_ITEMS[0] == federation-workbench
        sheet_tsx = (REPO_ROOT / "webui" / "src" / "components" / "MobileMoreSheet.tsx").read_text(
            encoding="utf-8"
        )
        sheet_match = re.search(r"const SHEET_ITEMS[^=]*=\s*\[(.*?)\];", sheet_tsx, re.DOTALL)
        self.assertIsNotNone(sheet_match)
        sheet_ids = re.findall(r'id:\s*"([^"]+)"', sheet_match.group(1))
        self.assertGreaterEqual(len(sheet_ids), 1)
        self.assertEqual(sheet_ids[0], "federation-workbench")

        # Two-way navigation buttons present
        fed_tsx = (REPO_ROOT / "webui" / "src" / "components" / "FederationView.tsx").read_text(encoding="utf-8")
        wb_tsx = (REPO_ROOT / "webui" / "src" / "components" / "FederationWorkbenchView.tsx").read_text(
            encoding="utf-8"
        )
        self.assertIn('onNavigate("federation-workbench")', fed_tsx)
        self.assertIn('onNavigate("federation")', wb_tsx)

        # 2. Unauthenticated GET /federation-workbench returns 200 zero-data SPA shell with no-store & CSP
        r_spa = await self.client.get("/federation-workbench")
        self.assertEqual(r_spa.status, 200)
        self.assertEqual(r_spa.headers.get("Cache-Control"), "no-store, max-age=0")
        self.assertIn("script-src 'self'", r_spa.headers.get("Content-Security-Policy", ""))
        spa_txt = await r_spa.text()
        self.assertNotIn(SYNTH_PREFIX, spa_txt)
        self.assertNotIn("token_records", spa_txt)

        # 3. Zero personal domains / real private IDs in all touched runtime & demo files
        personal_tokens = (
            ".".join(("gaoshan", "de5", "net")),
            ".".join(("fisht", "de5", "net")),
            "-".join(("muse", "f01")),
        )
        for rel in (
            "studio/federation_service.py",
            "studio/server.py",
            "webui/src/components/FederationView.tsx",
            "webui/src/components/FederationWorkbenchView.tsx",
            "webui/src/demo/mockApi.ts",
        ):
            content = (REPO_ROOT / rel).read_text(encoding="utf-8")
            for ptok in personal_tokens:
                self.assertNotIn(ptok, content, f"Personal marker {ptok!r} found in {rel}")


if __name__ == "__main__":
    unittest.main()
