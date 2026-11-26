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
import studio.federation_service as federation_service  # noqa: E402
from studio.federation_service import (  # noqa: E402
    MAX_FED_JOB_META_BYTES,
    MAX_WORKBENCH_JSON_BYTES,
    StudioFederationService,
    _merge_single_timeline_job,
    _read_job_meta_map_safe,
    _read_presence_map_no_symlink,
    _strip_context_wrapper,
    _upsert_job_meta_atomic,
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
            federation_workbench_state_path=self.studio_cfg / "studio_federation_workbench_state.json",
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
            # FW5: `prompt` containing example Bearer/sk-/agy_fed_ text is now sanitized & accepted 200
            # (verified in TestFederationWorkbenchUpgradeFW1ToFW7.test_fw5_*), while metadata fields like
            # `label` still fail-closed 400 on plaintext secrets.
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


class TestWorkbenchPresenceP4AndP6(_FederationTestBase):
    """P4 & P6: Studio read-only presence anti-symlink, dirty/future sanitization, status sync, Hub E2E, and WebUI guards."""

    async def test_p4_studio_presence_readonly_anti_symlink_sanitization_and_status_sync(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        headers = self._admin_headers(admin_cookie, admin_csrf)

        # 1. Empty BUS_DIR -> 200 OK, zero creation of federation/ or presence.json
        self.assertEqual(list(self.bus_dir.iterdir()), [])
        r_empty = await self.client.get("/api/federation/workbench", headers=admin_get)
        self.assertEqual(r_empty.status, 200, await r_empty.text())
        self.assertEqual((await r_empty.json())["agents"], [])
        self.assertFalse((self.bus_dir / "federation").exists())

        # Register agents covering online, stale, offline, revoked, disabled, dirty, future
        for spec in (
            {"agent_id": "pull_worker_demo", "kind": "pull_worker"},
            {"agent_id": "node_stale", "kind": "pull_worker"},
            {"agent_id": "node_offline", "kind": "pull_worker"},
            {"agent_id": "node_revoked", "kind": "pull_worker"},
            {"agent_id": "node_disabled", "kind": "pull_worker", "enabled": False},
            {"agent_id": "node_dirty", "kind": "pull_worker"},
            {"agent_id": "node_future", "kind": "pull_worker"},
        ):
            r_reg = await self.client.post("/api/federation/agents", headers=headers, data=json.dumps(spec))
            self.assertEqual(r_reg.status, 200, await r_reg.text())
        r_rev = await self.client.post("/api/federation/agents/node_revoked/revoke", headers=headers, data="{}")
        self.assertEqual(r_rev.status, 200)

        fed_dir = self.bus_dir / "federation"
        presence_path = fed_dir / "presence.json"
        canary = "TOP_SECRET_PRESENCE_CANARY_P4"
        outside_file = self.tmp / "outside_presence_canary.json"
        outside_file.write_text(json.dumps({"pull_worker_demo": {"last_seen_at": time.time(), "token": canary}}), encoding="utf-8")

        # 2. Symlink / FIFO / Dir at presence.json -> BOTH workbench & timeline fail-closed 403 SECURITY_SYMLINK_REJECTED
        os.symlink(outside_file, presence_path)
        for path in ("/api/federation/workbench", "/api/federation/workbench/agents/pull_worker_demo/timeline"):
            r = await self.client.get(path, headers=admin_get)
            self.assertEqual(r.status, 403, f"symlink presence.json {path}")
            body_txt = await r.text()
            self.assertIn("SECURITY_SYMLINK_REJECTED", body_txt)
            self.assertNotIn(canary, body_txt)
        presence_path.unlink()

        os.mkfifo(presence_path)
        for path in ("/api/federation/workbench", "/api/federation/workbench/agents/pull_worker_demo/timeline"):
            r = await self.client.get(path, headers=admin_get)
            self.assertEqual(r.status, 403, f"fifo presence.json {path}")
            self.assertEqual((await r.json()).get("code"), "SECURITY_SYMLINK_REJECTED")
        presence_path.unlink()

        presence_path.mkdir()
        for path in ("/api/federation/workbench", "/api/federation/workbench/agents/pull_worker_demo/timeline"):
            r = await self.client.get(path, headers=admin_get)
            self.assertEqual(r.status, 403, f"dir presence.json {path}")
            self.assertEqual((await r.json()).get("code"), "SECURITY_SYMLINK_REJECTED")
        presence_path.rmdir()

        # 3. Corrupted JSON & >1 MiB oversized file -> gracefully skipped (200 OK, null heartbeat)
        presence_path.write_text("{corrupted_json", encoding="utf-8")
        r_bad_json = await self.client.get("/api/federation/workbench", headers=admin_get)
        self.assertEqual(r_bad_json.status, 200)
        ag_bad = next(a for a in (await r_bad_json.json())["agents"] if a["agent_id"] == "pull_worker_demo")
        self.assertIsNone(ag_bad["last_heartbeat_at"])
        self.assertEqual(ag_bad["last_heartbeat_action"], "")

        now_int = int(time.time())
        oversized_blob = (
            f'{{"pull_worker_demo":{{"last_seen_at":{now_int},"pad":"' + ("A" * (1024 * 1024 + 512)) + '"}}'
        )
        presence_path.write_text(oversized_blob, encoding="utf-8")
        r_big = await self.client.get("/api/federation/workbench", headers=admin_get)
        self.assertEqual(r_big.status, 200)
        ag_big = next(a for a in (await r_big.json())["agents"] if a["agent_id"] == "pull_worker_demo")
        self.assertIsNone(ag_big["last_heartbeat_at"])

        # 4. Unit sanitization of NaN / Infinity / bool / negative / string / future timestamps
        now = time.time()
        presence_path.write_text(
            '{'
            '"pull_worker_demo":{"last_seen_at":NaN,"last_action":"peek"},'
            '"node_stale":{"last_seen_at":Infinity,"last_action":"inbox"},'
            '"node_offline":{"last_seen_at":true,"last_action":"claim"},'
            '"node_dirty":{"last_seen_at":-1,"last_action":"result"},'
            f'"node_future":{{"last_seen_at":"{int(now)}","last_action":"mcp"}}'
            '}',
            encoding="utf-8",
        )
        ok_p, parsed_dirty, err_p = _read_presence_map_no_symlink(str(self.bus_dir), now_ts=now)
        self.assertTrue(ok_p, err_p)
        self.assertEqual(parsed_dirty, {})

        # 5. Full status window mapping, revocation/disabled precedence, XSS/secret/future scrubbing, and list==timeline parity
        now = time.time()
        presence_payload = {
            "pull_worker_demo": {"last_seen_at": round(now - 12.0, 3), "last_peek_at": round(now - 12.0, 3), "last_action": "peek"},
            "node_stale": {"last_seen_at": round(now - 301.0, 3), "last_action": "inbox"},
            "node_offline": {"last_seen_at": round(now - 3601.0, 3), "last_action": "claim"},
            "node_revoked": {"last_seen_at": round(now - 5.0, 3), "last_action": "peek"},
            "node_disabled": {"last_seen_at": round(now - 5.0, 3), "last_action": "peek"},
            "node_dirty": {
                "last_seen_at": round(now - 15.0, 3),
                "last_action": "<script>alert(1)</script>",
                "token": SYNTH_FAKE_FED,
                "ip": "198.51.100.77",
            },
            "node_future": {"last_seen_at": round(now + 86400.0, 3), "last_action": SYNTH_FAKE_FED},
        }
        presence_path.write_text(json.dumps(presence_payload), encoding="utf-8")

        r_list = await self.client.get("/api/federation/workbench", headers=admin_get)
        self.assertEqual(r_list.status, 200, await r_list.text())
        list_raw_txt = await r_list.text()
        for forbidden in ("<script>", SYNTH_FAKE_FED, "198.51.100.77"):
            self.assertNotIn(forbidden, list_raw_txt)
        list_by_id = {a["agent_id"]: a for a in (await r_list.json())["agents"]}

        expected_statuses = {
            "pull_worker_demo": ("online", "peek", True),
            "node_stale": ("stale", "inbox", True),
            "node_offline": ("offline", "claim", True),
            "node_revoked": ("revoked", "peek", True),
            "node_disabled": ("disabled", "peek", True),
            "node_dirty": ("online", "", True),
            "node_future": ("offline", "", False),
        }

        for aid, (exp_status, exp_action, expect_hb_ts) in expected_statuses.items():
            list_ag = list_by_id[aid]
            self.assertEqual(list_ag["runtime_status"], exp_status, f"list status mismatch for {aid}")
            self.assertEqual(list_ag["last_heartbeat_action"], exp_action, f"list action mismatch for {aid}")
            if expect_hb_ts:
                self.assertIsInstance(list_ag["last_heartbeat_at"], float)
            else:
                self.assertIsNone(list_ag["last_heartbeat_at"])

            # Verify 100% parity with detail timeline endpoint
            r_tl = await self.client.get(f"/api/federation/workbench/agents/{aid}/timeline", headers=admin_get)
            self.assertEqual(r_tl.status, 200, f"timeline {aid}: {await r_tl.text()}")
            tl_raw = await r_tl.text()
            for forbidden in ("<script>", SYNTH_FAKE_FED, "198.51.100.77"):
                self.assertNotIn(forbidden, tl_raw)
            tl_ag = (await r_tl.json())["agent"]
            self.assertEqual(tl_ag["runtime_status"], list_ag["runtime_status"], aid)
            self.assertEqual(tl_ag["last_heartbeat_at"], list_ag["last_heartbeat_at"], aid)
            self.assertEqual(tl_ag["last_heartbeat_action"], list_ag["last_heartbeat_action"], aid)
            self.assertEqual(tl_ag["last_activity_at"], list_ag["last_activity_at"], aid)

        # 6. End-to-end Hub /peek -> presence.json -> Studio workbench & timeline both show online + peek
        presence_path.unlink()
        owner = federation_registry.make_owner_auth("owner")
        tok_peek = federation_registry.mint_agent_token(
            "pull_worker_demo", owner_auth=owner, scope="peek", bus_dir=str(self.bus_dir)
        )["token"]
        hub_srv = federation_hub.FederationHubServer(
            host="127.0.0.1", port=0, bus_dir=str(self.bus_dir), presence_flush_interval_sec=0.0
        )
        hub_thread = threading.Thread(target=hub_srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        hub_thread.start()
        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(
                    f"http://127.0.0.1:{hub_srv.bound_port}/hub/v1/agents/pull_worker_demo/peek",
                    headers={"Authorization": f"Bearer {tok_peek}"},
                ) as hub_resp:
                    self.assertEqual(hub_resp.status, 200)
        finally:
            hub_srv.close_hub()
            hub_thread.join(timeout=2.0)

        r_wb_e2e = await self.client.get("/api/federation/workbench", headers=admin_get)
        self.assertEqual(r_wb_e2e.status, 200)
        wb_ag = next(a for a in (await r_wb_e2e.json())["agents"] if a["agent_id"] == "pull_worker_demo")
        self.assertEqual(wb_ag["runtime_status"], "online")
        self.assertEqual(wb_ag["last_heartbeat_action"], "peek")
        self.assertIsInstance(wb_ag["last_heartbeat_at"], float)

        r_tl_e2e = await self.client.get("/api/federation/workbench/agents/pull_worker_demo/timeline", headers=admin_get)
        self.assertEqual(r_tl_e2e.status, 200)
        tl_ag_e2e = (await r_tl_e2e.json())["agent"]
        self.assertEqual(tl_ag_e2e["runtime_status"], "online")
        self.assertEqual(tl_ag_e2e["last_heartbeat_action"], "peek")
        self.assertEqual(tl_ag_e2e["last_heartbeat_at"], wb_ag["last_heartbeat_at"])

    async def test_p6_frontend_presence_xss_guard_polling_and_demo_invariants(self) -> None:
        wb_tsx = (REPO_ROOT / "webui" / "src" / "components" / "FederationWorkbenchView.tsx").read_text(encoding="utf-8")
        types_ts = (REPO_ROOT / "webui" / "src" / "types.ts").read_text(encoding="utf-8")
        mock_ts = (REPO_ROOT / "webui" / "src" / "demo" / "mockApi.ts").read_text(encoding="utf-8")

        # Pure text rendering + strict action whitelist + zero dangerous HTML sinks
        for forbidden in ("dangerouslySetInnerHTML", "innerHTML", "<script"):
            self.assertNotIn(forbidden, wb_tsx)
        self.assertIn("HEARTBEAT_ACTION_LABELS", wb_tsx)
        self.assertIn("hasOwnProperty.call(HEARTBEAT_ACTION_LABELS", wb_tsx)
        for act in ("peek", "inbox", "claim", "result", "events_ack", "mcp"):
            self.assertIn(f'{act}: "{act}"', wb_tsx)

        # Single mutually-exclusive polling useEffect (4s active / 30s idle) + clearInterval + monotonic gen refs
        self.assertIn("POLL_ACTIVE_INTERVAL_MS = 4000", wb_tsx)
        self.assertIn("POLL_IDLE_INTERVAL_MS = 30000", wb_tsx)
        self.assertEqual(wb_tsx.count("setInterval("), 1)
        self.assertEqual(wb_tsx.count("clearInterval("), 1)
        self.assertIn("listGenRef", wb_tsx)
        self.assertIn("reqGenRef", wb_tsx)

        # TypeScript interface & Demo mockApi parity
        self.assertIn("last_heartbeat_at?: number | null;", types_ts)
        self.assertIn("last_heartbeat_action?: string;", types_ts)
        self.assertIn("last_heartbeat_at:", mock_ts)
        self.assertIn("last_heartbeat_action:", mock_ts)


class TestFederationWorkbenchUpgradeFW1ToFW7(_FederationTestBase):
    """FW1..FW7: Independent state sync, optimistic locking, anti-symlink/FIFO, multi-turn context, Push/Pull compat, and UI guards."""

    async def test_fw1_state_write_gate_live_rbac_128kib_and_get_headers(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        ro_cookie, ro_csrf = await self._login("ViewerUser", RO_PASS)
        forced_cookie, forced_csrf = await self._login("ForcedPwUser", FORCED_PASS)

        state_file = self.studio_cfg / "studio_federation_workbench_state.json"
        self.assertFalse(state_file.exists())

        # GET auth gates & Cache-Control
        r_unauth_get = await self.client.get("/api/federation/workbench/state")
        self.assertEqual(r_unauth_get.status, 401)

        r_forced_get = await self.client.get(
            "/api/federation/workbench/state",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={forced_cookie}"},
        )
        self.assertEqual(r_forced_get.status, 403)

        r_admin_get = await self.client.get(
            "/api/federation/workbench/state",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"},
        )
        self.assertEqual(r_admin_get.status, 200)
        self.assertEqual(r_admin_get.headers.get("Cache-Control"), "no-store, max-age=0")
        d_admin_get = await r_admin_get.json()
        self.assertTrue(d_admin_get["ok"])
        self.assertEqual(d_admin_get["version"], 0)
        self.assertTrue(d_admin_get["can_edit"])

        r_ro_get = await self.client.get(
            "/api/federation/workbench/state",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={ro_cookie}"},
        )
        self.assertEqual(r_ro_get.status, 200)
        self.assertEqual(r_ro_get.headers.get("Cache-Control"), "no-store, max-age=0")
        d_ro_get = await r_ro_get.json()
        self.assertFalse(d_ro_get["can_edit"])
        self.assertFalse(state_file.exists())

        valid_body = json.dumps(
            {
                "expected_version": 0,
                "state": {
                    "customProjects": [{"id": "proj-alpha", "name": "Alpha Ops", "description": "Edge tasks"}],
                    "conversations": [
                        {
                            "id": "conv-alpha-1",
                            "agentId": "pull_worker_demo",
                            "projectId": "proj-alpha",
                            "title": "Health Check",
                        }
                    ],
                },
            }
        )

        # PUT Gate 1a: missing Origin -> 403
        h_no_origin = self._admin_headers(admin_cookie, admin_csrf)
        h_no_origin.pop("Origin", None)
        self.assertEqual(
            (await self.client.put("/api/federation/workbench/state", headers=h_no_origin, data=valid_body)).status,
            403,
        )

        # PUT Gate 1a: cross-site Origin -> 403
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers=self._admin_headers(admin_cookie, admin_csrf, Origin="https://evil.example.com"),
                    data=valid_body,
                )
            ).status,
            403,
        )

        # PUT Gate 1b: Sec-Fetch-Site: cross-site -> 403
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers=self._admin_headers(admin_cookie, admin_csrf, **{"Sec-Fetch-Site": "cross-site"}),
                    data=valid_body,
                )
            ).status,
            403,
        )

        # PUT Gate 2: Content-Type: text/plain -> 415
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers=self._admin_headers(admin_cookie, admin_csrf, **{"Content-Type": "text/plain"}),
                    data=valid_body,
                )
            ).status,
            415,
        )

        # PUT Gate 3: unauthenticated -> 401; must_change_password=True -> 403
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers={"Origin": self.origin, "Content-Type": "application/json"},
                    data=valid_body,
                )
            ).status,
            401,
        )
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers=self._admin_headers(forced_cookie, forced_csrf),
                    data=valid_body,
                )
            ).status,
            403,
        )

        # PUT Gate 4a: missing/wrong CSRF -> 403
        h_no_csrf = self._admin_headers(admin_cookie, admin_csrf)
        h_no_csrf.pop("X-Studio-CSRF", None)
        self.assertEqual(
            (await self.client.put("/api/federation/workbench/state", headers=h_no_csrf, data=valid_body)).status,
            403,
        )
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers=self._admin_headers(admin_cookie, "wrong-csrf-token"),
                    data=valid_body,
                )
            ).status,
            403,
        )

        # PUT Gate 4b: readonly user -> 403 & zero disk write
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers=self._admin_headers(ro_cookie, ro_csrf),
                    data=valid_body,
                )
            ).status,
            403,
        )
        self.assertFalse(state_file.exists())

        # PUT Gate 4b: live RBAC demotion of already-logged-in admin -> 403 & zero disk write
        users_fp = self.studio_cfg / "users.json"
        users_by_key = json.loads(users_fp.read_text(encoding="utf-8"))["users"]
        users_by_key["adminuser"]["role"] = "readonly"
        save_users_file_atomic(users_fp, users_by_key)
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers=self._admin_headers(admin_cookie, admin_csrf),
                    data=valid_body,
                )
            ).status,
            403,
        )
        self.assertFalse(state_file.exists())

        # Restore admin role
        users_by_key["adminuser"]["role"] = "admin"
        save_users_file_atomic(users_fp, users_by_key)

        # Body > 128 KiB -> 413
        oversized = '{"expected_version":0,"state":{"customProjects":[{"id":"p1","name":"' + ("x" * (129 * 1024)) + '"}]}}'
        r_big = await self.client.put(
            "/api/federation/workbench/state",
            headers=self._admin_headers(admin_cookie, admin_csrf),
            data=oversized,
        )
        self.assertEqual(r_big.status, 413)
        self.assertFalse(state_file.exists())

        # Valid admin PUT -> 200, audit log, SSE broadcast
        event_hub = self.app[EVENT_HUB_KEY]
        with mock.patch.object(event_hub, "publish", wraps=event_hub.publish) as spy_pub:
            r_ok = await self.client.put(
                "/api/federation/workbench/state",
                headers=self._admin_headers(admin_cookie, admin_csrf),
                data=valid_body,
            )
            self.assertEqual(r_ok.status, 200, await r_ok.text())
            d_ok = await r_ok.json()
            self.assertEqual(d_ok["version"], 1)
            self.assertTrue(d_ok["can_edit"])
            self.assertEqual(len(d_ok["state"]["customProjects"]), 1)
            self.assertTrue(
                any(
                    c.args and c.args[0] == "federation_updated" and (c.args[1] or {}).get("action") == "workbench_state_updated"
                    for c in spy_pub.call_args_list
                ),
                "Expected federation_updated SSE broadcast with action=workbench_state_updated",
            )
        audit_text = self.audit_log.read_text(encoding="utf-8")
        self.assertIn("federation.workbench.state.put", audit_text)

    async def test_fw2_optimistic_lock_409_proto_pollution_host_paths_and_quotas(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        headers = self._admin_headers(admin_cookie, admin_csrf)

        # Initial save -> version 1
        r1 = await self.client.put(
            "/api/federation/workbench/state",
            headers=headers,
            data=json.dumps(
                {
                    "expected_version": 0,
                    "state": {"customProjects": [{"id": "proj-v1", "name": "V1 Project"}]},
                }
            ),
        )
        self.assertEqual(r1.status, 200)
        self.assertEqual((await r1.json())["version"], 1)

        # Stale expected_version=0 -> 409 Conflict with latest snapshot & zero disk overwrite
        r_conflict = await self.client.put(
            "/api/federation/workbench/state",
            headers=headers,
            data=json.dumps(
                {
                    "expected_version": 0,
                    "state": {"customProjects": [{"id": "proj-stale", "name": "Stale"}]},
                }
            ),
        )
        self.assertEqual(r_conflict.status, 409)
        d_c = await r_conflict.json()
        self.assertEqual(d_c.get("code"), "version_conflict")
        self.assertEqual(d_c.get("version"), 1)
        self.assertIsNotNone(d_c.get("updated_at"))
        self.assertEqual(d_c["state"]["customProjects"][0]["id"], "proj-v1")

        # Verify disk untouched
        disk_doc = json.loads((self.studio_cfg / "studio_federation_workbench_state.json").read_text(encoding="utf-8"))
        self.assertEqual(disk_doc["version"], 1)
        self.assertEqual(disk_doc["state"]["customProjects"][0]["id"], "proj-v1")

        # Invalid expected_version values -> 400
        for bad_ver in (True, False, -1, 1.5, "1", None):
            r_bv = await self.client.put(
                "/api/federation/workbench/state",
                headers=headers,
                data=json.dumps({"expected_version": bad_ver, "state": {}}),
            )
            self.assertEqual(r_bv.status, 400, f"expected_version={bad_ver!r} should be 400")

        # Prototype pollution keys (top-level, nested, AND space-wrapped) -> 400 & zero disk overwrite
        for proto_payload in (
            '{"expected_version":1,"__proto__":{"polluted":true},"state":{}}',
            '{"expected_version":1," __proto__ ":{"polluted":true},"state":{}}',
            '{"expected_version":1,"state":{"renamedProjects":{"prototype":"bad"}}}',
            '{"expected_version":1,"state":{"renamedProjects":{" prototype ":"bad"}}}',
            '{"expected_version":1,"state":{"renamedProjects":{" constructor ":"bad"}}}',
            '{"expected_version":1,"state":{"customProjects":[{"id":"p1","name":"ok","constructor":{}}]}}',
            '{"expected_version":1,"state":{"customProjects":[{"id":"p1","name":"ok"," constructor ":{}}]}}',
            '{"expected_version":1,"state":{"customProjects":[{"id":"constructor","name":"Bad"}]}}',
            '{"expected_version":1,"state":{"customProjects":[{"id":"prototype","name":"Bad"}]}}',
            '{"expected_version":1,"state":{"customProjects":[{"id":"__proto__","name":"Bad"}]}}',
            '{"expected_version":1,"state":{"conversations":[{"id":"constructor","agentId":"ag1","projectId":"default","title":"T"}]}}',
            '{"expected_version":1,"state":{"conversations":[{"id":"c1","agentId":"constructor","projectId":"default","title":"T"}]}}',
            '{"expected_version":1,"state":{"conversations":[{"id":"c1","agentId":"ag1","projectId":"prototype","title":"T"}]}}',
            '{"expected_version":1,"state":{"uiPrefs":{"selectedAgentId":"constructor"}}}',
            '{"expected_version":1,"state":{"uiPrefs":{"selectedProjectId":"prototype"}}}',
            '{"expected_version":1,"state":{"uiPrefs":{"selectedConversationId":"__proto__"}}}',
        ):
            r_pp = await self.client.put("/api/federation/workbench/state", headers=headers, data=proto_payload)
            self.assertEqual(r_pp.status, 400, proto_payload)

        # Verify disk remains untouched at version 1 after all prototype attacks
        disk_doc_after_proto = json.loads(
            (self.studio_cfg / "studio_federation_workbench_state.json").read_text(encoding="utf-8")
        )
        self.assertEqual(disk_doc_after_proto["version"], 1)
        self.assertEqual(disk_doc_after_proto["state"]["customProjects"][0]["id"], "proj-v1")

        # Host path keys -> 400
        for path_key in ("workdir", "path", "cwd", "filepath", "dir", "folder_uri"):
            r_hp = await self.client.put(
                "/api/federation/workbench/state",
                headers=headers,
                data=json.dumps(
                    {
                        "expected_version": 1,
                        "state": {"customProjects": [{"id": "p1", "name": "ok", path_key: "/tmp/x"}]},
                    }
                ),
            )
            self.assertEqual(r_hp.status, 400, f"forbidden path key {path_key}")

        # Unknown top-level & state fields -> 400
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers=headers,
                    data=json.dumps({"expected_version": 1, "state": {}, "extraTop": 1}),
                )
            ).status,
            400,
        )
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers=headers,
                    data=json.dumps({"expected_version": 1, "state": {"unknownField": 1}}),
                )
            ).status,
            400,
        )

        # Quotas, control chars, traversal IDs -> 400
        too_many_projects = [{"id": f"proj-{i}", "name": f"P{i}"} for i in range(65)]
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers=headers,
                    data=json.dumps({"expected_version": 1, "state": {"customProjects": too_many_projects}}),
                )
            ).status,
            400,
        )
        too_many_convs = [
            {"id": f"conv-{i}", "agentId": "ag1", "projectId": "default", "title": f"C{i}"} for i in range(513)
        ]
        self.assertEqual(
            (
                await self.client.put(
                    "/api/federation/workbench/state",
                    headers=headers,
                    data=json.dumps({"expected_version": 1, "state": {"conversations": too_many_convs}}),
                )
            ).status,
            400,
        )
        for bad_state in (
            {"customProjects": [{"id": "../escape", "name": "Bad"}]},
            {"customProjects": [{"id": "p1", "name": "bad\x00ctrl"}]},
            {"customProjects": [{"id": "p1", "name": "x" * 65}]},
            {"pinnedConversationIds": ["../etc/passwd"]},
            {"renamedConversations": {"conv-1": "line1\nline2"}},
        ):
            r_bs = await self.client.put(
                "/api/federation/workbench/state",
                headers=headers,
                data=json.dumps({"expected_version": 1, "state": bad_state}),
            )
            self.assertEqual(r_bs.status, 400, f"bad_state={bad_state!r}")

    async def test_fw3_anti_symlink_fifo_get_zero_side_effects_and_permissions(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        headers = self._admin_headers(admin_cookie, admin_csrf)

        # 1. Non-existent parent dir -> GET 200 (version=0) with ZERO dir/file creation
        nested_dir = self.tmp / "fresh_fed_state_root" / "sub"
        fresh_state = nested_dir / "studio_federation_workbench_state.json"
        self.fed_svc.workbench_state_path = fresh_state
        r_empty = await self.client.get("/api/federation/workbench/state", headers=admin_get)
        self.assertEqual(r_empty.status, 200)
        self.assertEqual((await r_empty.json())["version"], 0)
        self.assertFalse((self.tmp / "fresh_fed_state_root").exists())

        # 2. Normal PUT -> parent 0700, file & .lock 0600, independent from studio_workbench_state.json
        valid_body = json.dumps({"expected_version": 0, "state": {"customProjects": [{"id": "p1", "name": "P1"}]}})
        r_save = await self.client.put("/api/federation/workbench/state", headers=headers, data=valid_body)
        self.assertEqual(r_save.status, 200, await r_save.text())
        self.assertEqual(os.stat(nested_dir).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(fresh_state).st_mode & 0o777, 0o600)
        lock_file = nested_dir / f".{fresh_state.name}.lock"
        self.assertTrue(lock_file.exists())
        self.assertEqual(os.stat(lock_file).st_mode & 0o777, 0o600)
        self.assertFalse((nested_dir / "studio_workbench_state.json").exists())

        # 3. Symlink state file -> GET & PUT fail-closed 403 SECURITY_SYMLINK_REJECTED
        outside = self.tmp / "outside_state_canary.json"
        outside.write_text('{"version":99,"state":{}}', encoding="utf-8")
        fresh_state.unlink()
        os.symlink(outside, fresh_state)
        for method in ("get", "put"):
            r = (
                await self.client.get("/api/federation/workbench/state", headers=admin_get)
                if method == "get"
                else await self.client.put("/api/federation/workbench/state", headers=headers, data=valid_body)
            )
            self.assertEqual(r.status, 403, f"symlink state file {method}")
            self.assertEqual((await r.json()).get("code"), "SECURITY_SYMLINK_REJECTED")
        fresh_state.unlink()

        # 4. FIFO state file -> non-blocking immediate 403 SECURITY_SYMLINK_REJECTED
        os.mkfifo(fresh_state)
        for method in ("get", "put"):
            r = await asyncio.wait_for(
                self.client.get("/api/federation/workbench/state", headers=admin_get)
                if method == "get"
                else self.client.put("/api/federation/workbench/state", headers=headers, data=valid_body),
                timeout=2.0,
            )
            self.assertEqual(r.status, 403, f"fifo state file {method}")
            self.assertEqual((await r.json()).get("code"), "SECURITY_SYMLINK_REJECTED")
        fresh_state.unlink()

        # 5. Symlink & FIFO .lock -> GET & PUT non-blocking 403 SECURITY_SYMLINK_REJECTED
        lock_file.unlink()
        os.symlink(outside, lock_file)
        for method in ("get", "put"):
            r = (
                await self.client.get("/api/federation/workbench/state", headers=admin_get)
                if method == "get"
                else await self.client.put("/api/federation/workbench/state", headers=headers, data=valid_body)
            )
            self.assertEqual(r.status, 403, f"symlink lock {method}")
            self.assertEqual((await r.json()).get("code"), "SECURITY_SYMLINK_REJECTED")
        lock_file.unlink()

        os.mkfifo(lock_file)
        for method in ("get", "put"):
            r = await asyncio.wait_for(
                self.client.get("/api/federation/workbench/state", headers=admin_get)
                if method == "get"
                else self.client.put("/api/federation/workbench/state", headers=headers, data=valid_body),
                timeout=2.0,
            )
            self.assertEqual(r.status, 403, f"fifo lock {method}")
            self.assertEqual((await r.json()).get("code"), "SECURITY_SYMLINK_REJECTED")
        lock_file.unlink()

        # 6. Symlink parent directory -> GET & PUT 403 SECURITY_SYMLINK_REJECTED
        sym_parent = self.tmp / "sym_parent_link"
        os.symlink(nested_dir, sym_parent)
        self.fed_svc.workbench_state_path = sym_parent / "studio_federation_workbench_state.json"
        for method in ("get", "put"):
            r = (
                await self.client.get("/api/federation/workbench/state", headers=admin_get)
                if method == "get"
                else await self.client.put("/api/federation/workbench/state", headers=headers, data=valid_body)
            )
            self.assertEqual(r.status, 403, f"symlink parent {method}")
            self.assertEqual((await r.json()).get("code"), "SECURITY_SYMLINK_REJECTED")

        # 7. Zero residual .lock file created when target state / job_meta file is symlink or FIFO
        clean_dir = self.tmp / "zero_lock_residue_dir"
        clean_dir.mkdir(mode=0o700)
        for kind in ("symlink", "fifo"):
            st_target = clean_dir / f"state_{kind}.json"
            st_lock = clean_dir / f".{st_target.name}.lock"
            if kind == "symlink":
                os.symlink(outside, st_target)
            else:
                os.mkfifo(st_target)
            self.fed_svc.workbench_state_path = st_target
            r_rej = await asyncio.wait_for(
                self.client.put("/api/federation/workbench/state", headers=headers, data=valid_body),
                timeout=2.0,
            )
            self.assertEqual(r_rej.status, 403, f"zero-lock {kind} state")
            self.assertFalse(st_lock.exists(), f"residual .lock created for {kind} state target")

            jm_target = clean_dir / f"job_meta_{kind}.json"
            jm_lock = clean_dir / f".{jm_target.name}.lock"
            if kind == "symlink":
                os.symlink(outside, jm_target)
            else:
                os.mkfifo(jm_target)
            ok_up, err_up = _upsert_job_meta_atomic(jm_target, "job-x", {"agent_id": "a1"})
            self.assertFalse(ok_up)
            self.assertIn("SECURITY_SYMLINK_REJECTED", err_up)
            self.assertFalse(jm_lock.exists(), f"residual .lock created for {kind} job_meta target")

    async def test_fw4_multiturn_context_isolation_bounds_redaction_and_anti_nesting(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        headers = self._admin_headers(admin_cookie, admin_csrf)

        for aid in ("agent_a", "agent_b"):
            r_reg = await self.client.post(
                "/api/federation/agents",
                headers=headers,
                data=json.dumps({"agent_id": aid, "kind": "pull_worker"}),
            )
            self.assertEqual(r_reg.status, 200, await r_reg.text())

        # Strict bool check on include_context
        for bad_ic in ("true", 1, 0):
            r_bad = await self.client.post(
                "/api/federation/workbench/agents/agent_a/dispatch",
                headers=headers,
                data=json.dumps({"prompt": "hi", "conversation_id": "conv-1", "include_context": bad_ic}),
            )
            self.assertEqual(r_bad.status, 400, f"include_context={bad_ic!r} must return 400")

        pq_dir = self.bus_dir / "federation" / "pull_queue"
        pq_dir.mkdir(parents=True, exist_ok=True)
        now = time.time()
        synth_ghp = "ghp_" + ("A" * 24)

        # Seed 10 completed turns in (agent_a, conv-1) containing secrets & host paths
        for i in range(1, 11):
            jid = f"pull-hist-{i:02d}"
            (pq_dir / f"{jid}.json").write_text(
                json.dumps(
                    {
                        "job_id": jid,
                        "target_agent_id": "agent_a",
                        "prompt": f"Turn {i} prompt with {SYNTH_FAKE_FED} and {SYNTH_HOST_PATH}",
                        "result_text": f"Turn {i} reply with {SYNTH_FAKE_SK} and {synth_ghp} and {'Z' * 600}",
                        "status": "done",
                        "cancelled": False,
                        "created_at": now - (100 - i),
                        "finished_at": now - (99 - i),
                        "metadata": {
                            "source": "studio",
                            "project_id": "proj-1",
                            "conversation_id": "conv-1",
                            "display_prompt": f"Turn {i} prompt with [REDACTED]",
                        },
                    }
                ),
                encoding="utf-8",
            )

        # Seed cross-agent, cross-conversation, unfinished, and cancelled distractors
        for jid, aid, cid, st, marker in (
            ("pull-other-agent", "agent_b", "conv-1", "done", "CROSS_AGENT_LEAK_CANARY"),
            ("pull-other-conv", "agent_a", "conv-2", "done", "CROSS_CONV_LEAK_CANARY"),
            ("pull-unfinished", "agent_a", "conv-1", "queued", "UNFINISHED_CANARY"),
            ("pull-cancelled", "agent_a", "conv-1", "cancelled", "CANCELLED_CANARY"),
        ):
            (pq_dir / f"{jid}.json").write_text(
                json.dumps(
                    {
                        "job_id": jid,
                        "target_agent_id": aid,
                        "prompt": marker,
                        "result_text": marker,
                        "status": st,
                        "cancelled": st == "cancelled",
                        "created_at": now - 5,
                        "metadata": {"source": "studio", "conversation_id": cid, "display_prompt": marker},
                    }
                ),
                encoding="utf-8",
            )

        # 1. include_context=False -> context_turns=0
        r_no_ctx = await self.client.post(
            "/api/federation/workbench/agents/agent_a/dispatch",
            headers=headers,
            data=json.dumps(
                {
                    "prompt": "fresh question no context",
                    "project_id": "proj-1",
                    "conversation_id": "conv-1",
                    "include_context": False,
                }
            ),
        )
        self.assertEqual(r_no_ctx.status, 200, await r_no_ctx.text())
        d_nc = await r_no_ctx.json()
        self.assertEqual(d_nc["job"]["context_turns"], 0)
        raw_nc = json.loads((pq_dir / f"{d_nc['job']['job_id']}.json").read_text(encoding="utf-8"))
        self.assertEqual(raw_nc["prompt"], "fresh question no context")

        # 2. include_context=True -> <= 6 turns, <= 3600 chars prefix, strict isolation & redaction
        r_ctx = await self.client.post(
            "/api/federation/workbench/agents/agent_a/dispatch",
            headers=headers,
            data=json.dumps(
                {
                    "prompt": "follow up round 11",
                    "project_id": "proj-1",
                    "conversation_id": "conv-1",
                    "conversation_title": "Ops Thread",
                    "include_context": True,
                }
            ),
        )
        self.assertEqual(r_ctx.status, 200, await r_ctx.text())
        d_ctx = await r_ctx.json()
        ctx_turns = d_ctx["job"]["context_turns"]
        self.assertGreater(ctx_turns, 0)
        self.assertLessEqual(ctx_turns, 6)
        self.assertEqual(d_ctx["job"]["display_prompt"], "follow up round 11")

        raw_ctx_job = json.loads((pq_dir / f"{d_ctx['job']['job_id']}.json").read_text(encoding="utf-8"))
        dispatched_prompt = raw_ctx_job["prompt"]
        self.assertIn("[AGY_FED_CONVERSATION_CONTEXT]", dispatched_prompt)
        self.assertIn("[CURRENT_USER_MESSAGE]", dispatched_prompt)
        self.assertTrue(dispatched_prompt.endswith("follow up round 11"))
        prefix_only = dispatched_prompt[: dispatched_prompt.rfind("\nfollow up round 11")]
        self.assertLessEqual(len(prefix_only), 3600)
        self.assertIn("Turn 10", prefix_only)
        self.assertNotIn("Turn 1 ", prefix_only)
        for forbidden in (
            "CROSS_AGENT_LEAK_CANARY",
            "CROSS_CONV_LEAK_CANARY",
            "UNFINISHED_CANARY",
            "CANCELLED_CANARY",
            SYNTH_FAKE_FED,
            SYNTH_FAKE_SK,
            synth_ghp,
            SYNTH_HOST_PATH,
        ):
            self.assertNotIn(forbidden, dispatched_prompt)

        # 3. Complete round 11 and send round 12 -> zero recursive header nesting
        raw_ctx_job["status"] = "done"
        raw_ctx_job["result_text"] = "round 11 done"
        raw_ctx_job["finished_at"] = time.time()
        (pq_dir / f"{d_ctx['job']['job_id']}.json").write_text(json.dumps(raw_ctx_job), encoding="utf-8")

        r_ctx2 = await self.client.post(
            "/api/federation/workbench/agents/agent_a/dispatch",
            headers=headers,
            data=json.dumps(
                {
                    "prompt": "follow up round 12",
                    "project_id": "proj-1",
                    "conversation_id": "conv-1",
                    "include_context": True,
                }
            ),
        )
        self.assertEqual(r_ctx2.status, 200, await r_ctx2.text())
        raw_ctx2 = json.loads((pq_dir / f"{(await r_ctx2.json())['job']['job_id']}.json").read_text(encoding="utf-8"))
        self.assertEqual(raw_ctx2["prompt"].count("[AGY_FED_CONVERSATION_CONTEXT]"), 1)
        self.assertEqual(raw_ctx2["prompt"].count("[CURRENT_USER_MESSAGE]"), 1)
        self.assertIn("follow up round 11", raw_ctx2["prompt"])

    async def test_fw5_pull_plaintext_secret_compat_push_meta_and_timeline_filtering(self) -> None:
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        headers = self._admin_headers(admin_cookie, admin_csrf)

        for spec in (
            {"agent_id": "pull_sec_compat", "kind": "pull_worker"},
            {"agent_id": "push_meta_node", "kind": "hermes_remote", "endpoint_url": "https://node.example.com/a2a"},
        ):
            r_reg = await self.client.post("/api/federation/agents", headers=headers, data=json.dumps(spec))
            self.assertEqual(r_reg.status, 200, await r_reg.text())

        # 1. Pull dispatch whose prompt contains Bearer/Authorization/sk-/ghp_/agy_fed_ MUST NOT trigger 400
        synth_ghp = "ghp_" + ("B" * 24)
        secret_prompt = (
            f"Bearer EXAMPLE_LEAD_TOK_12345678 inspect Authorization: Bearer EXAMPLE_HDR_99887766 "
            f"and {SYNTH_FAKE_SK} {synth_ghp} {SYNTH_FAKE_FED}"
        )
        r_pull_sec = await self.client.post(
            "/api/federation/workbench/agents/pull_sec_compat/dispatch",
            headers=headers,
            data=json.dumps(
                {
                    "prompt": secret_prompt,
                    "label": "secret-redaction-check",
                    "project_id": "default",
                    "conversation_id": "conv-sec-1",
                    "conversation_title": "Audit Auth Header",
                }
            ),
        )
        self.assertEqual(r_pull_sec.status, 200, await r_pull_sec.text())
        d_ps = await r_pull_sec.json()
        for raw_tok in ("EXAMPLE_LEAD_TOK_12345678", "EXAMPLE_HDR_99887766", SYNTH_FAKE_SK, synth_ghp, SYNTH_FAKE_FED):
            self.assertNotIn(raw_tok, d_ps["job"]["display_prompt"])
            self.assertNotIn(raw_tok, d_ps["job"]["prompt"])
        self.assertIn("[REDACTED]", d_ps["job"]["display_prompt"])
        # Verify timeline & pull_inbox also return sanitized prompt_preview cleanly
        r_ps_tl = await self.client.get(
            "/api/federation/workbench/agents/pull_sec_compat/timeline", headers=admin_get
        )
        self.assertEqual(r_ps_tl.status, 200)
        d_ps_tl = await r_ps_tl.json()
        self.assertTrue(len(d_ps_tl["pull_inbox"]) >= 1)
        for raw_tok in ("EXAMPLE_LEAD_TOK_12345678", "EXAMPLE_HDR_99887766", SYNTH_FAKE_SK, synth_ghp, SYNTH_FAKE_FED):
            self.assertNotIn(raw_tok, d_ps_tl["pull_inbox"][0]["prompt_preview"])

        # 2. Push node preserves project_id / conversation_id / conversation_title / context_turns without touching bot_bus.py
        r_push1 = await self.client.post(
            "/api/federation/workbench/agents/push_meta_node/dispatch",
            headers=headers,
            data=json.dumps(
                {
                    "prompt": "push round 1",
                    "project_id": "proj-push",
                    "conversation_id": "conv-push-1",
                    "conversation_title": "Push Multi-Turn",
                }
            ),
        )
        self.assertEqual(r_push1.status, 200, await r_push1.text())
        push_jid = (await r_push1.json())["job"]["job_id"]

        # Timeline returns metadata AND keeps node-level has_active_jobs=True even when filtered to an idle conversation
        r_tl_all = await self.client.get(
            "/api/federation/workbench/agents/push_meta_node/timeline", headers=admin_get
        )
        self.assertEqual(r_tl_all.status, 200)
        d_all = await r_tl_all.json()
        item_p = next(it for it in d_all["timeline"] if it["job_id"] == push_jid)
        self.assertEqual(item_p["project_id"], "proj-push")
        self.assertEqual(item_p["conversation_id"], "conv-push-1")
        self.assertEqual(item_p["conversation_title"], "Push Multi-Turn")
        self.assertEqual(item_p["display_prompt"], "push round 1")
        self.assertTrue(d_all["has_active_jobs"])

        r_tl_idle = await self.client.get(
            "/api/federation/workbench/agents/push_meta_node/timeline?conversation_id=conv-empty-other",
            headers=admin_get,
        )
        self.assertEqual(r_tl_idle.status, 200)
        d_idle = await r_tl_idle.json()
        self.assertEqual(d_idle["timeline"], [])
        self.assertTrue(d_idle["has_active_jobs"], "Node-level has_active_jobs must stay True when filtering to idle conv")

        # 3. Legacy dispatch {"prompt": "ping"} 100% compatible
        r_leg = await self.client.post(
            "/api/federation/workbench/agents/pull_sec_compat/dispatch",
            headers=headers,
            data=json.dumps({"prompt": "ping"}),
        )
        self.assertEqual(r_leg.status, 200, await r_leg.text())
        self.assertEqual((await r_leg.json())["job"]["context_turns"], 0)

        # 4. Invalid timeline query filter params -> 400
        for bad_q in ("conversation_id=../bad", "project_id=../bad", "project_id=constructor", "conversation_id=prototype"):
            r_bq = await self.client.get(
                f"/api/federation/workbench/agents/push_meta_node/timeline?{bad_q}", headers=admin_get
            )
            self.assertEqual(r_bq.status, 400, bad_q)

        # 5. Cancel Push job preserves project_id / conversation_id / conversation_title (active & idempotent repeat)
        r_cancel_push = await self.client.post(
            f"/api/federation/workbench/agents/push_meta_node/jobs/{push_jid}/cancel",
            headers=headers,
            data=json.dumps({"reason": "user_cancelled_test"}),
        )
        self.assertEqual(r_cancel_push.status, 200, await r_cancel_push.text())
        d_cp = await r_cancel_push.json()
        self.assertTrue(d_cp["cancelled"])
        self.assertEqual(d_cp["status"], "cancelled")
        self.assertEqual(d_cp["job"]["project_id"], "proj-push")
        self.assertEqual(d_cp["job"]["conversation_id"], "conv-push-1")
        self.assertEqual(d_cp["job"]["conversation_title"], "Push Multi-Turn")

        # Repeat cancel (already-terminal branch) STILL preserves Push sidecar metadata
        r_cancel_again = await self.client.post(
            f"/api/federation/workbench/agents/push_meta_node/jobs/{push_jid}/cancel",
            headers=headers,
            data=json.dumps({}),
        )
        self.assertEqual(r_cancel_again.status, 200, await r_cancel_again.text())
        d_cp2 = await r_cancel_again.json()
        self.assertTrue(d_cp2["already_terminal"])
        self.assertEqual(d_cp2["job"]["project_id"], "proj-push")
        self.assertEqual(d_cp2["job"]["conversation_id"], "conv-push-1")
        self.assertEqual(d_cp2["job"]["conversation_title"], "Push Multi-Turn")

        # Cancel fails closed (403 SECURITY_SYMLINK_REJECTED) if job_meta sidecar is replaced by symlink/FIFO
        r_push_sym = await self.client.post(
            "/api/federation/workbench/agents/push_meta_node/dispatch",
            headers=headers,
            data=json.dumps({"prompt": "push before symlink check", "conversation_id": "conv-sym-1"}),
        )
        self.assertEqual(r_push_sym.status, 200)
        sym_jid = (await r_push_sym.json())["job"]["job_id"]
        orig_meta_path = self.fed_svc.job_meta_path
        fifo_meta = self.tmp / "fifo_job_meta.json"
        os.mkfifo(fifo_meta)
        try:
            self.fed_svc.job_meta_path = fifo_meta
            r_cancel_fifo = await asyncio.wait_for(
                self.client.post(
                    f"/api/federation/workbench/agents/push_meta_node/jobs/{sym_jid}/cancel",
                    headers=headers,
                    data=json.dumps({}),
                ),
                timeout=2.0,
            )
            self.assertEqual(r_cancel_fifo.status, 403)
            self.assertEqual((await r_cancel_fifo.json()).get("code"), "SECURITY_SYMLINK_REJECTED")
        finally:
            self.fed_svc.job_meta_path = orig_meta_path

    async def test_fw5_round2_job_meta_budget_45x62kib_and_strip_context_wrapper(self) -> None:
        """BLOCKER-2 & BLOCKER-3 regression: 45x62KiB sidecar budget never truncates/wipes, and _strip_context_wrapper preserves literal markers."""
        # 1. Unit tests for _strip_context_wrapper literal preservation & genuine leading wrapper stripping
        literal_body = "Explain why [AGY_FED_CONVERSATION_CONTEXT] and [CURRENT_USER_MESSAGE] appear in logs."
        self.assertEqual(_strip_context_wrapper(literal_body), literal_body)

        unclosed_lead = "[AGY_FED_CONVERSATION_CONTEXT] is mentioned at the start without closing tag"
        self.assertEqual(_strip_context_wrapper(unclosed_lead), unclosed_lead)

        no_marker_after_end = "[AGY_FED_CONVERSATION_CONTEXT]\nhi\n[/AGY_FED_CONVERSATION_CONTEXT]\nRegular text"
        self.assertEqual(_strip_context_wrapper(no_marker_after_end), no_marker_after_end)

        genuine_wrapped_with_literal_body = (
            "[AGY_FED_CONVERSATION_CONTEXT]\nUser: prev\nAssistant: ok\n"
            "[/AGY_FED_CONVERSATION_CONTEXT]\n[CURRENT_USER_MESSAGE]\n"
            + literal_body
        )
        self.assertEqual(_strip_context_wrapper(genuine_wrapped_with_literal_body), literal_body)

        nested_genuine = (
            "[AGY_FED_CONVERSATION_CONTEXT]\nouter\n[/AGY_FED_CONVERSATION_CONTEXT]\n[CURRENT_USER_MESSAGE]\n"
            "[AGY_FED_CONVERSATION_CONTEXT]\ninner\n[/AGY_FED_CONVERSATION_CONTEXT]\n[CURRENT_USER_MESSAGE]\n"
            "Final user prompt"
        )
        self.assertEqual(_strip_context_wrapper(nested_genuine), "Final user prompt")

        # 2. 45 consecutive 62 KiB prompt entries via _upsert_job_meta_atomic -> strictly <= 1.5 MiB (< 2 MiB read cap), zero wipe
        stress_meta = self.tmp / "stress_45x62kib_job_meta.json"
        payload_62k = "P" * (62 * 1024)
        for i in range(45):
            ok_s, err_s = _upsert_job_meta_atomic(
                stress_meta,
                f"job-62k-{i:03d}",
                {
                    "agent_id": "push_bulk_node",
                    "project_id": "proj-bulk",
                    "conversation_id": "conv-bulk-62k",
                    "conversation_title": "62KiB Sidecar Stress",
                    "display_prompt": f"turn-{i:03d}-{payload_62k}",
                    "ts": 1700001000.0 + i,
                },
            )
            self.assertTrue(ok_s, err_s)
            self.assertLessEqual(stress_meta.stat().st_size, MAX_FED_JOB_META_BYTES)
            self.assertLess(stress_meta.stat().st_size, MAX_WORKBENCH_JSON_BYTES * 2)
        ok_srd, srd_map, err_srd = _read_job_meta_map_safe(stress_meta)
        self.assertTrue(ok_srd, err_srd)
        self.assertEqual(len(srd_map), 45, "All 45 62KiB entries must stay intact without truncation wipe")
        self.assertIn("job-62k-000", srd_map)
        self.assertIn("job-62k-044", srd_map)

        # 3. Direct byte-budget eviction check on _upsert_job_meta_atomic (strictly <= budget, oldest evicted first)
        budget_meta = self.tmp / "budget_evict_job_meta.json"
        with mock.patch.object(federation_service, "MAX_FED_JOB_META_BYTES", 8192):
            for i in range(30):
                ok_u, err_u = _upsert_job_meta_atomic(
                    budget_meta,
                    f"job-ev-{i:03d}",
                    {
                        "agent_id": "push_bulk_node",
                        "project_id": "proj-bulk",
                        "conversation_id": "conv-bulk",
                        "conversation_title": "Bulk Test",
                        "display_prompt": f"item-{i:03d}-" + ("X" * 1024),
                        "ts": 1700000000.0 + i,
                    },
                )
                self.assertTrue(ok_u, err_u)
                self.assertLessEqual(budget_meta.stat().st_size, 8192)
        ok_rd, rd_map, err_rd = _read_job_meta_map_safe(budget_meta)
        self.assertTrue(ok_rd, err_rd)
        self.assertGreater(len(rd_map), 0)
        self.assertIn("job-ev-029", rd_map)
        self.assertNotIn("job-ev-000", rd_map)

        # 4. E2E HTTP: 45 consecutive 28 KiB prompts to Push node -> zero silent wipe, file <= 1.5 MiB, lossless bubbles
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        headers = self._admin_headers(admin_cookie, admin_csrf)

        r_reg = await self.client.post(
            "/api/federation/agents",
            headers=headers,
            data=json.dumps(
                {
                    "agent_id": "push_bulk_node",
                    "kind": "hermes_remote",
                    "endpoint_url": "https://bulk.example.com/a2a",
                }
            ),
        )
        self.assertEqual(r_reg.status, 200, await r_reg.text())

        dispatched_jids: list[str] = []
        prompt_tail_marker = "TAIL_MARKER_LOSSLESS_CHECK"
        body_28k_prefix = "A" * (28 * 1024 - 80)
        for idx in range(45):
            big_prompt = f"Turn-{idx:02d} {body_28k_prefix} {prompt_tail_marker}-{idx:02d}"
            r_d = await self.client.post(
                "/api/federation/workbench/agents/push_bulk_node/dispatch",
                headers=headers,
                data=json.dumps(
                    {
                        "prompt": big_prompt,
                        "project_id": "proj-bulk",
                        "conversation_id": "conv-bulk-45",
                        "conversation_title": "Large Prompt Stress",
                        "include_context": False,
                    }
                ),
            )
            self.assertEqual(r_d.status, 200, await r_d.text())
            d_j = (await r_d.json())["job"]
            dispatched_jids.append(d_j["job_id"])
            self.assertTrue(d_j["display_prompt"].endswith(f"{prompt_tail_marker}-{idx:02d}"))

        meta_size = self.fed_svc.job_meta_path.stat().st_size
        self.assertLessEqual(meta_size, MAX_FED_JOB_META_BYTES)
        self.assertLess(meta_size, MAX_WORKBENCH_JSON_BYTES * 2)

        ok_m, m_map, err_m = _read_job_meta_map_safe(self.fed_svc.job_meta_path)
        self.assertTrue(ok_m, err_m)
        self.assertEqual(len(m_map), 45, "All 45 entries must remain intact without silent wipe")
        self.assertIn(dispatched_jids[0], m_map)
        self.assertIn(dispatched_jids[-1], m_map)

        r_tl = await self.client.get(
            "/api/federation/workbench/agents/push_bulk_node/timeline?limit=100", headers=admin_get
        )
        self.assertEqual(r_tl.status, 200)
        tl_by_id = {it["job_id"]: it for it in (await r_tl.json())["timeline"]}
        self.assertEqual(len(tl_by_id), 45)
        for idx, jid in enumerate(dispatched_jids):
            self.assertEqual(tl_by_id[jid]["project_id"], "proj-bulk")
            self.assertEqual(tl_by_id[jid]["conversation_id"], "conv-bulk-45")
            self.assertEqual(tl_by_id[jid]["conversation_title"], "Large Prompt Stress")
            self.assertTrue(
                tl_by_id[jid]["display_prompt"].endswith(f"{prompt_tail_marker}-{idx:02d}"),
                f"Job {idx} display_prompt must be lossless in timeline",
            )

    async def test_fw6_and_fw7_frontend_invariants_demo_parity_and_redlines(self) -> None:
        wb_tsx = (REPO_ROOT / "webui" / "src" / "components" / "FederationWorkbenchView.tsx").read_text(
            encoding="utf-8"
        )
        api_ts = (REPO_ROOT / "webui" / "src" / "api.ts").read_text(encoding="utf-8")
        mock_ts = (REPO_ROOT / "webui" / "src" / "demo" / "mockApi.ts").read_text(encoding="utf-8")

        # FW6: XSS, proto guard, control-char normalization, race guard, 409 single retry, readonly zero PUT, single polling interval
        for forbidden in ("dangerouslySetInnerHTML", "innerHTML", "<script", "WorkspaceFilePickerPopover", "worktree"):
            self.assertNotIn(forbidden, wb_tsx)
        self.assertIn("FORBIDDEN_PROTO_KEYS", wb_tsx)
        self.assertIn("CTRL_CHARS_RE", wb_tsx)
        self.assertIn("normalizeSingleLineText", wb_tsx)
        self.assertIn("const trimmed = key.trim();", wb_tsx)
        self.assertIn("Object.prototype.hasOwnProperty.call(wbState.readAtByConversation", wb_tsx)
        self.assertIn("Object.prototype.hasOwnProperty.call(expandedProjectLists", wb_tsx)
        self.assertIn("convMatchesAgent", wb_tsx)
        self.assertIn("belongsToResolved", wb_tsx)
        self.assertIn("flushStateSyncQueue", wb_tsx)
        self.assertIn("mergeFedWorkbenchStates", wb_tsx)
        self.assertIn("if (!canEdit || stateSyncInFlightRef.current) return;", wb_tsx)
        self.assertIn("const targetAgentId = selectedAgent.agent_id;", wb_tsx)
        self.assertIn("const targetConversationId =", wb_tsx)
        self.assertIn("isComposingRef", wb_tsx)
        self.assertEqual(wb_tsx.count("setInterval("), 1)
        self.assertEqual(wb_tsx.count("clearInterval("), 1)

        # FW7: API & Demo exports parity for new federation workbench state endpoints
        for sym in (
            "fetchFederationWorkbenchState",
            "updateFederationWorkbenchState",
            "fetchFederationChatroomMessages",
            "sendFederationChatroomMessage",
        ):
            self.assertIn(sym, api_ts)
            self.assertIn(sym, mock_ts)


class _DummyJobQ:
    def __init__(self) -> None:
        self.items: list[tuple] = []

    def put(self, item: tuple) -> int:
        self.items.append(("put", item))
        return len(self.items)

    def put_front(self, item: tuple) -> int:
        self.items.append(("put_front", item))
        return len(self.items)

    def put_front_and_mark_dispatched_preempt(self, item: tuple, _skey: str) -> tuple[int, int]:
        self.items.append(("preempt", item))
        return len(self.items), 0


class _DummyBridgeHost:
    def __init__(self, bus_dir: Path, handle: str, *, allowed: set[int], authorized: bool = True) -> None:
        self.bus_dir = bus_dir
        self._handle = handle
        self.ALLOWED = set(allowed)
        self._authorized = authorized
        self.job_q = _DummyJobQ()
        self.sent_calls: list[dict[str, object]] = []
        self.recorded_entries: list[dict[str, object]] = []
        self.human_activity_calls: list[dict[str, object]] = []
        self._seq = 0
        self._msg_id = 100
        self.bot_bus = self._make_bus_proxy()

    def _make_bus_proxy(self):
        host = self

        class _BusProxy:
            BUS_DIR = str(host.bus_dir)

            @staticmethod
            def _effective_bus_dir() -> str:
                return str(host.bus_dir)

            @staticmethod
            def get_team_mirror() -> dict[str, object]:
                p = host.bus_dir / "team_config.json"
                if p.is_file():
                    doc = json.loads(p.read_text(encoding="utf-8"))
                    if isinstance(doc.get("mirror"), dict):
                        return doc["mirror"]
                return {}

            @staticmethod
            def record_group_message(
                chat_id: int,
                *,
                msg_id: int = 0,
                thread_id: int | None = None,
                sender_handle: str = "",
                sender_role: str = "",
                is_bot: bool = False,
                text: str = "",
                ts: float | None = None,
                source: str = "tg",
            ) -> dict[str, object]:
                host._seq += 1
                entry = {
                    "seq": host._seq,
                    "msg_id": msg_id,
                    "ts": float(ts or time.time()),
                    "thread_id": thread_id,
                    "sender_handle": sender_handle,
                    "sender_role": sender_role,
                    "is_bot": bool(is_bot),
                    "full_text": text,
                    "text_excerpt": text[:500],
                    "truncated": False,
                    "source": source,
                }
                host.recorded_entries.append({"chat_id": chat_id, **entry})
                gh_dir = host.bus_dir / "group_history"
                gh_dir.mkdir(parents=True, exist_ok=True)
                gh_file = gh_dir / f"{chat_id}.json"
                doc = (
                    json.loads(gh_file.read_text(encoding="utf-8"))
                    if gh_file.is_file()
                    else {"version": 1, "next_seq": 1, "entries": [], "cursors": {}}
                )
                doc["entries"].append(entry)
                doc["next_seq"] = host._seq + 1
                gh_file.write_text(json.dumps(doc), encoding="utf-8")
                return dict(entry)

            @staticmethod
            def mark_human_group_activity(
                chat_id: int,
                thread_id: int | None = None,
                msg_id: int = 0,
            ) -> str:
                host.human_activity_calls.append(
                    {"chat_id": chat_id, "thread_id": thread_id, "msg_id": msg_id}
                )
                return f"chain-{msg_id}"

        return _BusProxy()

    def _current_bot_handle(self) -> str:
        return self._handle

    def _is_authorized(self, chat_id: int) -> bool:
        return self._authorized and (int(chat_id) in self.ALLOWED)

    @staticmethod
    def _normalize_thread_id(raw: object) -> int | None:
        if raw is None or isinstance(raw, bool):
            return None
        try:
            v = int(raw)
            return v if v > 0 else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def list_agy_projects() -> list[dict[str, str]]:
        return []

    @staticmethod
    def scope_key_for(chat_id: int, thread_id: int | None) -> str:
        return f"g:{chat_id}:{thread_id or 0}"

    def send(
        self,
        chat_id: int,
        text: str,
        *,
        thread_id: int | None = None,
        disable_web_page_preview: bool = True,
    ) -> int:
        self._msg_id += 1
        self.sent_calls.append(
            {
                "chat_id": int(chat_id),
                "text": text,
                "thread_id": thread_id,
                "disable_web_page_preview": disable_web_page_preview,
            }
        )
        return self._msg_id


class TestFederationChatroomFC1ToFC7(_FederationTestBase):
    """Comprehensive Prod-Release self-verification for FC1..FC7 (Standalone Federation Chatroom TG Mirror)."""

    FED_CHAT_ID = GROUP_CHAT_ID - 10
    TEAM_CHAT_ID = GROUP_CHAT_ID - 20

    @staticmethod
    def _at(handle: str) -> str:
        return "@" + handle

    def _write_team_config(
        self,
        *,
        team_mirror: dict[str, object] | None = None,
        fed_mirror: dict[str, object] | None = None,
        bots: dict[str, object] | None = None,
    ) -> None:
        doc: dict[str, object] = {"version": 1, "bots": bots or {}}
        if team_mirror is not None:
            doc["mirror"] = team_mirror
        if fed_mirror is not None:
            doc["federation_mirror"] = fed_mirror
        (self.bus_dir / "team_config.json").write_text(json.dumps(doc), encoding="utf-8")

    def _write_roster(self, bots: dict[str, dict[str, object]]) -> None:
        (self.bus_dir / "roster.json").write_text(
            json.dumps({"version": 1, "bots": bots}), encoding="utf-8"
        )

    def _start_ipc_server(
        self,
        handle: str,
        host: _DummyBridgeHost,
    ):
        import studio_ipc as sipc
        import studio_ipc_handlers as handlers

        def _tg_send(req: dict[str, object]) -> tuple[int, dict[str, object]]:
            prev = handlers._host
            handlers.bind_host(host)
            try:
                return handlers._studio_ipc_tg_group_send(req)
            finally:
                handlers._host = prev

        srv = sipc.StudioIPCServer(
            bus_dir=self.bus_dir,
            bot_handle=handle,
            resolve_role_fn=lambda uid: "admin" if int(uid) == ADMIN_UID else "readonly",
            get_meta_fn=lambda: {"handle": handle, "role": "coordinator"},
            enqueue_turn_fn=lambda _r: (202, {"ok": True}),
            abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
            tg_group_send_fn=_tg_send,
        )
        srv.start()
        return srv

    async def _post_uds_ipc(
        self,
        sock_path: Path,
        token: str,
        payload: dict[str, object],
    ) -> tuple[int, dict[str, object]]:
        connector = aiohttp.UnixConnector(path=str(sock_path))
        async with aiohttp.ClientSession(connector=connector) as cli:
            async with cli.post(
                "http://localhost/ipc/tg_group/send",
                headers={"X-Bridge-IPC-Token": token, "Content-Type": "application/json"},
                json=payload,
            ) as resp:
                data = await resp.json()
                return resp.status, data

    def _setup_online_coord_and_worker(
        self,
        *,
        allowed: set[int] | None = None,
        authorized: bool = True,
        start_worker: bool = True,
    ) -> tuple[_DummyBridgeHost, object, _DummyBridgeHost | None, object | None]:
        now = time.time()
        cur_pid = os.getpid()
        self._write_roster(
            {
                "coord_bot": {
                    "handle": "coord_bot",
                    "role": "coordinator",
                    "pid": cur_pid,
                    "last_seen": now,
                    "online": True,
                },
                "local_dev": {
                    "handle": "local_dev",
                    "role": "worker",
                    "pid": cur_pid,
                    "last_seen": now,
                    "online": True,
                },
                "offline_dev": {
                    "handle": "offline_dev",
                    "role": "worker",
                    "pid": 0,
                    "last_seen": now - 9999,
                    "online": False,
                },
            }
        )
        allow_set = allowed if allowed is not None else {self.FED_CHAT_ID, self.TEAM_CHAT_ID}
        coord_host = _DummyBridgeHost(self.bus_dir, "coord_bot", allowed=allow_set, authorized=authorized)
        coord_srv = self._start_ipc_server("coord_bot", coord_host)
        worker_host = None
        worker_srv = None
        if start_worker:
            worker_host = _DummyBridgeHost(self.bus_dir, "local_dev", allowed=allow_set, authorized=authorized)
            worker_srv = self._start_ipc_server("local_dev", worker_host)
        return coord_host, coord_srv, worker_host, worker_srv

    async def test_fc1_cross_group_isolation_bridge_auth_and_zero_chat_id_leak(self) -> None:
        """FC1: Zero fallback to team_mirror, Bridge 403 unauthorized chat, nested forbidden keys 400, zero chat_id/thread_id leak."""
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        admin_hdrs = self._admin_headers(admin_cookie, admin_csrf)

        # 1. Only team_mirror configured (NO federation_mirror) -> zero fallback
        self._write_team_config(team_mirror={"chat_id": self.TEAM_CHAT_ID, "thread_id": 7})
        coord_host, coord_srv, _wh, worker_srv = self._setup_online_coord_and_worker()
        try:
            sc_ipc, data_ipc = await self._post_uds_ipc(
                coord_srv.sock_path,
                coord_srv.token,
                {"user_id": ADMIN_UID, "content": "hello", "channel": "federation_mirror"},
            )
            self.assertEqual(sc_ipc, 400, data_ipc)
            self.assertEqual(coord_host.sent_calls, [])

            r_get = await self.client.get("/api/federation/workbench/chatroom/messages", headers=admin_get)
            self.assertEqual(r_get.status, 200)
            g_body = await r_get.json()
            self.assertFalse(g_body["bound"])
            self.assertEqual(g_body["messages"], [])
            self.assertNotIn(str(self.TEAM_CHAT_ID), json.dumps(g_body))

            r_post = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": "should fail closed"}),
            )
            self.assertEqual(r_post.status, 400)
            self.assertEqual(coord_host.sent_calls, [])

            # Explicit env disable values must NEVER fallback even when team_config has federation_mirror
            self._write_team_config(
                team_mirror={"chat_id": self.TEAM_CHAT_ID},
                fed_mirror={"chat_id": self.FED_CHAT_ID, "title": "联邦群"},
            )
            for dis_val in ("0", "off", "false", "none", "disabled"):
                with mock.patch.dict(os.environ, {"AGY_STUDIO_FEDERATION_MIRROR_CHAT_ID": dis_val}):
                    self.assertIsNone(self.sources.resolve_federation_tg_mirror())
                    sc_d, _ = await self._post_uds_ipc(
                        coord_srv.sock_path,
                        coord_srv.token,
                        {"user_id": ADMIN_UID, "content": "hi", "channel": "federation_mirror"},
                    )
                    self.assertEqual(sc_d, 400)
        finally:
            coord_srv.stop()
            if worker_srv:
                worker_srv.stop()

        # 2. Unauthorized federation_mirror chat_id -> Bridge IPC 403, zero TG call, zero group_history write
        self._write_team_config(fed_mirror={"chat_id": self.FED_CHAT_ID, "title": "联邦群"})
        unauth_host, unauth_srv, _, _ = self._setup_online_coord_and_worker(
            allowed={self.TEAM_CHAT_ID}, start_worker=False
        )
        try:
            sc_unauth, data_unauth = await self._post_uds_ipc(
                unauth_srv.sock_path,
                unauth_srv.token,
                {"user_id": ADMIN_UID, "content": "hi", "channel": "federation_mirror"},
            )
            self.assertEqual(sc_unauth, 403, data_unauth)
            self.assertEqual(unauth_host.sent_calls, [])
            self.assertFalse((self.bus_dir / "group_history" / f"{self.FED_CHAT_ID}.json").exists())
        finally:
            unauth_srv.stop()

        # 3. Top-level & nested forbidden keys + invalid channel -> 400 on both Studio HTTP and Bridge IPC
        coord_host, coord_srv, _, worker_srv = self._setup_online_coord_and_worker()
        try:
            bad_ipc_payloads = [
                {"user_id": ADMIN_UID, "content": "hi", "channel": "../team_mirror"},
                {"user_id": ADMIN_UID, "content": "hi", "channel": " federation_mirror "},
                {"user_id": ADMIN_UID, "content": "hi", "channel": 123},
                {"user_id": ADMIN_UID, "content": "hi", "chat_id": self.FED_CHAT_ID},
                {"user_id": ADMIN_UID, "content": "hi", "target_chat_id": self.FED_CHAT_ID},
                {"user_id": ADMIN_UID, "content": "hi", "thread_id": 5},
                {"user_id": ADMIN_UID, "content": "hi", "mirror_chat_id": self.FED_CHAT_ID},
                {"user_id": ADMIN_UID, "content": "hi", "scope_key": "g:1"},
                {"user_id": ADMIN_UID, "content": "hi", "nested": {"target_thread_id": 9}},
                {"user_id": ADMIN_UID, "content": "hi", "nested": [{" constructor ": {}}]},
            ]
            for bp in bad_ipc_payloads:
                sc_b, _ = await self._post_uds_ipc(coord_srv.sock_path, coord_srv.token, bp)
                self.assertEqual(sc_b, 400, f"Expected 400 for IPC payload {bp}")

            bad_http_payloads = [
                {"content": "hi", "chat_id": self.FED_CHAT_ID},
                {"content": "hi", "target_chat_id": self.FED_CHAT_ID},
                {"content": "hi", "thread_id": 3},
                {"content": "hi", "target_thread_id": 3},
                {"content": "hi", "mirror_chat_id": self.FED_CHAT_ID},
                {"content": "hi", "mirror_thread_id": 3},
                {"content": "hi", "scope_key": "g:1"},
                {"content": "hi", "role": "admin"},
                {"content": "hi", "channel": "../team_mirror"},
                {"content": "hi", "extra": {"chat_id": self.FED_CHAT_ID}},
            ]
            for bp in bad_http_payloads:
                r_b = await self.client.post(
                    "/api/federation/workbench/chatroom/messages",
                    headers=admin_hdrs,
                    data=json.dumps(bp),
                )
                self.assertEqual(r_b.status, 400, f"Expected 400 for HTTP payload {bp}")

            # 4. Zero chat_id/thread_id leak across GET/POST/audit/EventHub + zero lobby event bleed
            r_ok = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": f"ping chat {self.FED_CHAT_ID}"}),
            )
            self.assertEqual(r_ok.status, 200, await r_ok.text())
            post_raw = await r_ok.text()
            self.assertNotIn("chat_id", post_raw)
            self.assertNotIn("thread_id", post_raw)
            self.assertNotIn(str(self.FED_CHAT_ID), post_raw)

            r_get2 = await self.client.get("/api/federation/workbench/chatroom/messages", headers=admin_get)
            self.assertEqual(r_get2.status, 200)
            get_raw = await r_get2.text()
            self.assertNotIn("chat_id", get_raw)
            self.assertNotIn("thread_id", get_raw)
            self.assertNotIn(str(self.FED_CHAT_ID), get_raw)

            audit_txt = self.audit_log.read_text(encoding="utf-8")
            self.assertNotIn(str(self.FED_CHAT_ID), audit_txt)
            self.assertNotIn("chat_id", audit_txt)

            # EventHub federation watcher emits ONLY federation_updated, NEVER lobby room_message/room_activity
            hub = self.app[EVENT_HUB_KEY]
            hub._poll_federation_tg_mirror_history(bootstrap=True)
            before_ev_cnt = len(hub._events)
            # Append a new message to federation group_history directly
            coord_host.bot_bus.record_group_message(
                self.FED_CHAT_ID,
                msg_id=5001,
                sender_handle="ext_peer",
                sender_role="worker",
                is_bot=True,
                text=f"reply mentioning {self.FED_CHAT_ID}",
                source="federation",
            )
            hub._poll_federation_tg_mirror_history(bootstrap=False)
            new_events = list(hub._events)[before_ev_cnt:]
            self.assertTrue(
                any(ev[1] == "federation_updated" and ev[2].get("action") == "chatroom_updated" for ev in new_events),
                f"Expected federation_updated chatroom_updated event, got {new_events}",
            )
            for _seq, ev_name, ev_data in new_events:
                self.assertNotEqual(ev_name, "room_message")
                self.assertNotEqual(ev_name, "room_activity")
                ev_str = json.dumps(ev_data)
                self.assertNotIn("chat_id", ev_str)
                self.assertNotIn("thread_id", ev_str)
                self.assertNotIn(str(self.FED_CHAT_ID), ev_str)
                self.assertNotIn("content", ev_data)
        finally:
            coord_srv.stop()
            if worker_srv:
                worker_srv.stop()

    async def test_fc2_write_gate_live_rbac_rate_limit_size_caps_and_unbound(self) -> None:
        """FC2: 4-layer admin gate, live users.json downgrade/disable, 429+Retry-After, 413 fixed & chunked + 16KiB, 400 proto/shell."""
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        ro_cookie, ro_csrf = await self._login("ViewerUser", RO_PASS)
        forced_cookie, forced_csrf = await self._login("ForcedPwUser", FORCED_PASS)

        self._write_team_config(fed_mirror={"chat_id": self.FED_CHAT_ID, "title": "联邦群"})
        coord_host, coord_srv, _, worker_srv = self._setup_online_coord_and_worker()
        try:
            body_ok = json.dumps({"content": "hello"})

            # 1a. Missing / cross Origin -> 403
            r = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers={"Content-Type": "application/json", "X-Studio-CSRF": admin_csrf, "Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"},
                data=body_ok,
            )
            self.assertEqual(r.status, 403)
            r = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=self._admin_headers(admin_cookie, admin_csrf, Origin="https://evil.example.com"),
                data=body_ok,
            )
            self.assertEqual(r.status, 403)

            # 1b. Cross-site Sec-Fetch-Site -> 403
            r = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=self._admin_headers(admin_cookie, admin_csrf, **{"Sec-Fetch-Site": "cross-site"}),
                data=body_ok,
            )
            self.assertEqual(r.status, 403)

            # 1c. Non-JSON Content-Type -> 415
            r = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=self._admin_headers(admin_cookie, admin_csrf, **{"Content-Type": "text/plain"}),
                data=body_ok,
            )
            self.assertEqual(r.status, 415)

            # 1d. Unauthenticated / invalid cookie -> 401; must_change_password -> 403
            r = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers={"Origin": self.origin, "Content-Type": "application/json"},
                data=body_ok,
            )
            self.assertEqual(r.status, 401)
            r = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=self._admin_headers(forced_cookie, forced_csrf),
                data=body_ok,
            )
            self.assertEqual(r.status, 403)

            # 1e. Missing/wrong CSRF -> 403
            r = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=self._admin_headers(admin_cookie, "wrong-csrf"),
                data=body_ok,
            )
            self.assertEqual(r.status, 403)

            # 1f. Readonly user -> 403
            r = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=self._admin_headers(ro_cookie, ro_csrf),
                data=body_ok,
            )
            self.assertEqual(r.status, 403)
            self.assertEqual(coord_host.sent_calls, [])

            # 3. Size caps: fixed Content-Length > 32KiB -> 413; chunked > 32KiB -> 413; content > 16KiB -> 413
            admin_hdrs = self._admin_headers(admin_cookie, admin_csrf)
            big_fixed = json.dumps({"content": "A" * (34 * 1024)})
            r = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=big_fixed,
            )
            self.assertEqual(r.status, 413)

            async def _chunked_big():
                yield b'{"content":"'
                for _ in range(9):
                    yield b"B" * 4096
                yield b'"}'

            r_chunked = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=_chunked_big(),
            )
            self.assertEqual(r_chunked.status, 413)

            over_16k = json.dumps({"content": "C" * (16 * 1024 + 50)})
            r_16k = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=over_16k,
            )
            self.assertEqual(r_16k.status, 413)

            # 4. Unknown field, prototype pollution (padded whitespace), privilege/shell nested -> 400
            for bad in (
                {"content": "hi", "unknown_field": 1},
                {"content": "hi", " constructor ": {"pollute": True}},
                {"content": "hi", "nested": {"__proto__": {"a": 1}}},
                {"content": "hi", "owner_auth": True},
                {"content": "hi", "nested": {"cmd": "id"}},
            ):
                r_bad = await self.client.post(
                    "/api/federation/workbench/chatroom/messages",
                    headers=admin_hdrs,
                    data=json.dumps(bad),
                )
                self.assertEqual(r_bad.status, 400, f"Expected 400 for {bad}")

            # 2. Sliding-window rate limit -> 429 + valid integer Retry-After
            self.fed_svc.chatroom_rate_limit_max = 2
            self.fed_svc._chatroom_rate_buckets.clear()
            for _ in range(2):
                r_ok = await self.client.post(
                    "/api/federation/workbench/chatroom/messages",
                    headers=admin_hdrs,
                    data=body_ok,
                )
                self.assertEqual(r_ok.status, 200)
            r_429 = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=body_ok,
            )
            self.assertEqual(r_429.status, 429)
            ra = r_429.headers.get("Retry-After", "")
            self.assertTrue(ra.isdigit() and int(ra) >= 1, f"Invalid Retry-After: {ra!r}")

            # 1g. Live RBAC downgrade in users.json -> immediate 403 on existing admin session
            self.fed_svc.chatroom_rate_limit_max = 20
            users_path = self.studio_cfg / "users.json"
            users_doc = json.loads(users_path.read_text(encoding="utf-8"))
            users_doc["users"]["adminuser"]["role"] = "readonly"
            save_users_file_atomic(users_path, users_doc["users"])
            r_down = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=body_ok,
            )
            self.assertEqual(r_down.status, 403)
        finally:
            coord_srv.stop()
            if worker_srv:
                worker_srv.stop()

    async def test_fc3_anti_symlink_and_fifo_and_zero_file_creation(self) -> None:
        """FC3: Anti-symlink & anti-FIFO on group_history/<cid>.json and team_config.json + zero creation on missing."""
        admin_cookie, _ = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        hub = self.app[EVENT_HUB_KEY]

        # 1. Missing group_history dir & file -> empty list + ZERO file/dir created
        self._write_team_config(fed_mirror={"chat_id": self.FED_CHAT_ID, "title": "联邦群"})
        gh_dir = self.bus_dir / "group_history"
        self.assertFalse(gh_dir.exists())
        r_empty = await self.client.get("/api/federation/workbench/chatroom/messages", headers=admin_get)
        self.assertEqual(r_empty.status, 200)
        d_empty = await r_empty.json()
        self.assertTrue(d_empty["bound"])
        self.assertEqual(d_empty["messages"], [])
        self.assertFalse(gh_dir.exists(), "GET must NOT create group_history directory")

        # 2. Symlink group_history dir -> 403 and EventHub watcher skips safely
        outside_dir = self.tmp / "outside_dir"
        outside_dir.mkdir()
        os.symlink(outside_dir, gh_dir)
        r_sym_dir = await self.client.get("/api/federation/workbench/chatroom/messages", headers=admin_get)
        self.assertEqual(r_sym_dir.status, 403)
        hub._poll_federation_tg_mirror_history(bootstrap=False)
        gh_dir.unlink()

        # 3. Symlink <cid>.json -> 403 and EventHub watcher skips safely
        gh_dir.mkdir()
        outside_file = self.tmp / "outside.json"
        outside_file.write_text('{"entries":[]}', encoding="utf-8")
        hist_file = gh_dir / f"{self.FED_CHAT_ID}.json"
        os.symlink(outside_file, hist_file)
        r_sym_f = await self.client.get("/api/federation/workbench/chatroom/messages", headers=admin_get)
        self.assertEqual(r_sym_f.status, 403)
        hub._poll_federation_tg_mirror_history(bootstrap=False)
        hist_file.unlink()

        # 4. FIFO <cid>.json -> 403 without blocking event loop; EventHub skips without hanging
        os.mkfifo(hist_file)
        t0 = time.monotonic()
        r_fifo_f = await asyncio.wait_for(
            self.client.get("/api/federation/workbench/chatroom/messages", headers=admin_get),
            timeout=2.0,
        )
        self.assertEqual(r_fifo_f.status, 403)
        hub._poll_federation_tg_mirror_history(bootstrap=False)
        self.assertLess(time.monotonic() - t0, 2.0)
        hist_file.unlink()

        # 5. Symlink & FIFO team_config.json -> 403 without hanging
        tc_path = self.bus_dir / "team_config.json"
        tc_path.unlink()
        os.symlink(outside_file, tc_path)
        r_sym_tc = await self.client.get("/api/federation/workbench/chatroom/messages", headers=admin_get)
        self.assertEqual(r_sym_tc.status, 403)
        hub._poll_federation_tg_mirror_history(bootstrap=False)
        tc_path.unlink()

        os.mkfifo(tc_path)
        t1 = time.monotonic()
        r_fifo_tc = await asyncio.wait_for(
            self.client.get("/api/federation/workbench/chatroom/messages", headers=admin_get),
            timeout=2.0,
        )
        self.assertEqual(r_fifo_tc.status, 403)
        hub._poll_federation_tg_mirror_history(bootstrap=False)
        self.assertLess(time.monotonic() - t1, 2.0)
        tc_path.unlink()

    async def test_fc4_smart_at_routing_and_relay_sender_anti_loop(self) -> None:
        """FC4: Smart mention routing (none / local / external / mixed / offline / revoked) + relay_sender constraints."""
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_hdrs = self._admin_headers(admin_cookie, admin_csrf)

        # Register an active Pull external agent `muse-f01` and a revoked agent `revoked-f02`
        r_reg1 = await self.client.post(
            "/api/federation/agents",
            headers=admin_hdrs,
            data=json.dumps({"agent_id": "muse-f01", "kind": "pull_worker", "display_name": "Muse Node"}),
        )
        self.assertEqual(r_reg1.status, 200, await r_reg1.text())
        r_reg2 = await self.client.post(
            "/api/federation/agents",
            headers=admin_hdrs,
            data=json.dumps({"agent_id": "revoked-f02", "kind": "pull_worker"}),
        )
        self.assertEqual(r_reg2.status, 200)
        r_rev = await self.client.post("/api/federation/agents/revoked-f02/revoke", headers=admin_hdrs, data="{}")
        self.assertEqual(r_rev.status, 200)

        self._write_team_config(fed_mirror={"chat_id": self.FED_CHAT_ID, "title": "联邦群"})
        coord_host, coord_srv, worker_host, worker_srv = self._setup_online_coord_and_worker()
        assert worker_host is not None and worker_srv is not None
        try:
            # 1. No mention -> routes to online coordinator with dispatch_turn=True
            r1 = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": "全体汇报进度"}),
            )
            self.assertEqual(r1.status, 200, await r1.text())
            d1 = await r1.json()
            self.assertEqual(d1["routed_local"], ["coord_bot"])
            self.assertEqual(d1["routed_external"], [])
            self.assertEqual(len(coord_host.sent_calls), 1)
            self.assertEqual(len(coord_host.job_q.items), 1)

            # 2a. Explicit local_dev mention -> routes ONLY to local_dev (NOT coord_bot)
            r2 = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": f"{self._at('local_dev')} 检查构建日志"}),
            )
            self.assertEqual(r2.status, 200, await r2.text())
            d2 = await r2.json()
            self.assertEqual(d2["routed_local"], ["local_dev"])
            self.assertEqual(len(worker_host.sent_calls), 1)
            self.assertEqual(len(worker_host.job_q.items), 1)
            self.assertEqual(len(coord_host.job_q.items), 1)  # unchanged

            # 2b. Offline or non-existent local bot -> 503, NO fallback to coordinator, ZERO TG send
            for bad_mention in (
                f"{self._at('offline_dev')} ping",
                f"{self._at('nonexistent_bot')} ping",
            ):
                r_off = await self.client.post(
                    "/api/federation/workbench/chatroom/messages",
                    headers=admin_hdrs,
                    data=json.dumps({"content": bad_mention}),
                )
                self.assertEqual(r_off.status, 503)
            self.assertEqual(len(coord_host.sent_calls), 1)
            self.assertEqual(len(coord_host.job_q.items), 1)

            # 3a. Revoked external agent -> fail-closed 403 BEFORE mirroring to TG
            r_rev_msg = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": f"{self._at('revoked-f02')} 请执行"}),
            )
            self.assertEqual(r_rev_msg.status, 403)
            self.assertEqual(len(coord_host.sent_calls), 1)

            # 3b. Valid external agent (muse-f01) -> mirrors ONCE via coordinator with dispatch_turn=False (NO coordinator turn!), dispatches PullQueue
            r3 = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": f"{self._at('muse-f01')} 巡检外部节点健康状态"}),
            )
            self.assertEqual(r3.status, 200, await r3.text())
            d3 = await r3.json()
            self.assertEqual(d3["routed_local"], [])
            self.assertEqual(d3["routed_external"], ["muse-f01"])
            self.assertEqual(len(d3["external_jobs"]), 1)
            self.assertEqual(len(coord_host.sent_calls), 2)  # mirrored once
            self.assertEqual(len(coord_host.job_q.items), 1)  # coordinator turn NOT triggered!

            # 3c. Fail-closed on IPC 400: NEVER strip channel/dispatch_turn and retry
            ipc_calls_400: list[dict[str, object]] = []
            orig_ipc_fn = coord_srv.tg_group_send_fn

            def _reject_400_once(req: dict[str, object]) -> tuple[int, dict[str, object]]:
                ipc_calls_400.append(dict(req))
                return 400, {"ok": False, "error": "不支持的字段: channel"}

            coord_srv.tg_group_send_fn = _reject_400_once
            try:
                r_no_retry = await self.client.post(
                    "/api/federation/workbench/chatroom/messages",
                    headers=admin_hdrs,
                    data=json.dumps({"content": f"{self._at('muse-f01')} 不得剥离字段重试"}),
                )
                self.assertEqual(r_no_retry.status, 400)
                self.assertEqual(len(ipc_calls_400), 1, "Must fail-closed without stripping fields and retrying")
                self.assertEqual(ipc_calls_400[0].get("channel"), "federation_mirror")
                self.assertIs(ipc_calls_400[0].get("dispatch_turn"), False)
            finally:
                coord_srv.tg_group_send_fn = orig_ipc_fn

            # 4. Mixed local_dev + muse-f01 -> mirrored ONCE total, local turn + external job both dispatched
            prev_total_sends = len(coord_host.sent_calls) + len(worker_host.sent_calls)
            r4 = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": f"{self._at('local_dev')} {self._at('muse-f01')} 协同联调"}),
            )
            self.assertEqual(r4.status, 200, await r4.text())
            d4 = await r4.json()
            self.assertEqual(d4["routed_local"], ["local_dev"])
            self.assertEqual(d4["routed_external"], ["muse-f01"])
            self.assertEqual(len(d4["external_jobs"]), 1)
            self.assertEqual(len(coord_host.sent_calls) + len(worker_host.sent_calls), prev_total_sends + 1)
            self.assertEqual(len(worker_host.job_q.items), 2)

            # 5. relay_sender hard constraints on Bridge IPC
            for bad_relay_body in (
                {"user_id": ADMIN_UID, "content": "r", "channel": "federation_mirror", "dispatch_turn": True, "relay_sender": "muse-f01"},
                {"user_id": ADMIN_UID, "content": "r", "channel": "federation_mirror", "dispatch_turn": False, "mirror_human_to_tg": False, "relay_sender": "muse-f01"},
                {"user_id": ADMIN_UID, "content": "r", "channel": "federation_mirror", "dispatch_turn": False, "relay_sender": "../bad"},
                {"user_id": ADMIN_UID, "content": "r", "channel": "federation_mirror", "dispatch_turn": False, "relay_sender": "[ACB_TEAM]"},
                {"user_id": ADMIN_UID, "content": "r", "channel": "federation_mirror", "dispatch_turn": False, "relay_sender": "constructor"},
            ):
                sc_br, _ = await self._post_uds_ipc(coord_srv.sock_path, coord_srv.token, bad_relay_body)
                self.assertEqual(sc_br, 400, f"Expected 400 for {bad_relay_body}")

            prev_human_act = len(coord_host.human_activity_calls)
            prev_q_len = len(coord_host.job_q.items)
            sc_rel, data_rel = await self._post_uds_ipc(
                coord_srv.sock_path,
                coord_srv.token,
                {
                    "user_id": ADMIN_UID,
                    "content": "外部节点巡检全部通过",
                    "channel": "federation_mirror",
                    "dispatch_turn": False,
                    "mirror_human_to_tg": True,
                    "relay_sender": "muse-f01",
                },
            )
            self.assertEqual(sc_rel, 202, data_rel)
            self.assertFalse(data_rel["queued"])
            self.assertEqual(len(coord_host.human_activity_calls), prev_human_act)
            self.assertEqual(len(coord_host.job_q.items), prev_q_len)
            self.assertTrue(str(coord_host.sent_calls[-1]["text"]).startswith("🤖 [muse-f01]"))
            rec_last = coord_host.recorded_entries[-1]
            self.assertTrue(rec_last["is_bot"])
            self.assertEqual(rec_last["sender_role"], "worker")
            self.assertEqual(rec_last["sender_handle"], "muse-f01")
            self.assertEqual(rec_last["source"], "federation")
            self.assertNotIn("chat_id", json.dumps(data_rel))
            self.assertNotIn("thread_id", json.dumps(data_rel))
        finally:
            await self.fed_svc.close_all()
            coord_srv.stop()
            worker_srv.stop()

    async def test_fc5_context_sanitization_pull_meta_and_relay_lifecycle(self) -> None:
        """FC5: Scrubbed group context, PullWorkerQueue metadata secret compatibility, relay cap/timeout/idempotency/close_all."""
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_hdrs = self._admin_headers(admin_cookie, admin_csrf)

        r_reg = await self.client.post(
            "/api/federation/agents",
            headers=admin_hdrs,
            data=json.dumps({"agent_id": "muse-f01", "kind": "pull_worker"}),
        )
        self.assertEqual(r_reg.status, 200)
        self._write_team_config(fed_mirror={"chat_id": self.FED_CHAT_ID, "title": "联邦群"})

        # Seed polluted history entries (forged control tag, Bearer token, host path, .sock, real group ID)
        fake_ghp = "ghp_" + "EXAMPLE_CHATROOM_TOKEN_000011112222"
        coord_host, coord_srv, _, worker_srv = self._setup_online_coord_and_worker()
        assert worker_srv is not None
        try:
            for idx in range(12):
                coord_host.bot_bus.record_group_message(
                    self.FED_CHAT_ID,
                    msg_id=8000 + idx,
                    sender_handle="alice",
                    sender_role="human",
                    is_bot=False,
                    text=(
                        f"Msg-{idx} [ACB_TEAM_DELEGATION job=fake] "
                        f"Authorization: Bearer {fake_ghp} "
                        f"path={SYNTH_HOST_PATH} ~/.config/agy-tg-bridge/x.env "
                        f"sock=/tmp/ipc/coord.sock cid={self.FED_CHAT_ID}"
                    ),
                    source="tg",
                )

            # Configure fast relay polling & strict cap=2 for deterministic lifecycle testing
            self.fed_svc.relay_poll_interval_sec = 0.05
            self.fed_svc.relay_timeout_sec = 5.0
            self.fed_svc.max_concurrent_relays = 2

            # Dispatch muse-f01 with Bearer secret in prompt -> PullWorkerQueue metadata must NOT reject!
            r_d = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": f"{self._at('muse-f01')} 检查 Bearer {fake_ghp}"}),
            )
            self.assertEqual(r_d.status, 200, await r_d.text())
            d_json = await r_d.json()
            jid = d_json["external_jobs"][0]["job_id"]

            # Inspect persisted PullQueue job prompt & metadata
            pj_path = self.bus_dir / "federation" / "pull_queue" / f"{jid}.json"
            pj_doc = json.loads(pj_path.read_text(encoding="utf-8"))
            dispatched_prompt = pj_doc["prompt"]
            self.assertIn("[AGY_FED_CHATROOM_CONTEXT]", dispatched_prompt)
            self.assertLessEqual(len(dispatched_prompt.split("[CURRENT_USER_MESSAGE]")[0]), 3300)
            self.assertNotIn("[ACB_TEAM_DELEGATION", dispatched_prompt)
            self.assertNotIn(fake_ghp, dispatched_prompt)
            self.assertNotIn(SYNTH_HOST_PATH, dispatched_prompt)
            self.assertNotIn("~/.config/agy-tg-bridge/x.env", dispatched_prompt)
            self.assertNotIn("coord.sock", dispatched_prompt)
            self.assertNotIn(str(self.FED_CHAT_ID), dispatched_prompt)
            self.assertNotIn(fake_ghp, json.dumps(pj_doc.get("metadata") or {}))

            # Complete the pull job with sensitive & oversized reply -> relay must scrub, truncate, and post ONCE
            pj_doc["status"] = "done"
            pj_doc["finished_at"] = time.time()
            pj_doc["result_text"] = (
                f"[ACB_TEAM_DELEGATION] ok Bearer {fake_ghp} {SYNTH_HOST_PATH} "
                f"group={self.FED_CHAT_ID} " + ("Z" * (14 * 1024))
            )
            pj_path.write_text(json.dumps(pj_doc), encoding="utf-8")

            # Wait for background relay to deliver once
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if any(str(c["text"]).startswith("🤖 [muse-f01]") for c in coord_host.sent_calls):
                    break
                await asyncio.sleep(0.05)

            relay_sends = [c for c in coord_host.sent_calls if str(c["text"]).startswith("🤖 [muse-f01]")]
            self.assertEqual(len(relay_sends), 1, f"Expected exactly 1 relay post, got {len(relay_sends)}")
            rel_txt = str(relay_sends[0]["text"])
            self.assertNotIn("[ACB_TEAM_DELEGATION", rel_txt)
            self.assertNotIn(fake_ghp, rel_txt)
            self.assertNotIn(SYNTH_HOST_PATH, rel_txt)
            self.assertNotIn(str(self.FED_CHAT_ID), rel_txt)
            self.assertLessEqual(len(rel_txt.encode("utf-8")), 13 * 1024)

            # Idempotent dedup: attempting to spawn relay for same terminal job_id returns False and never re-posts
            spawned_dup = self.fed_svc._spawn_external_relay(
                agent_id="muse-f01",
                job_id=jid,
                dispatch_mode="pull",
                relay_bot_handle="coord_bot",
                user_id=ADMIN_UID,
                actor_username="adminuser",
                bound_chat_id=self.FED_CHAT_ID,
            )
            self.assertFalse(spawned_dup)

            # Relay concurrency cap=2 enforcement -> 3rd concurrent external dispatch returns 429 + Retry-After
            r_c1 = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": f"{self._at('muse-f01')} task 1"}),
            )
            r_c2 = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": f"{self._at('muse-f01')} task 2"}),
            )
            self.assertEqual(r_c1.status, 200)
            self.assertEqual(r_c2.status, 200)
            self.assertEqual(len(self.fed_svc._relay_tasks), 2)
            r_c3 = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": f"{self._at('muse-f01')} task 3"}),
            )
            self.assertEqual(r_c3.status, 429)
            self.assertTrue(r_c3.headers.get("Retry-After", "").isdigit())

            # Graceful cleanup via close_all() cancels all in-flight relay tasks with zero residuals
            await self.fed_svc.close_all()
            self.assertEqual(len(self.fed_svc._relay_tasks), 0)

            # Hard timeout test: short relay_timeout_sec exits cleanly
            self.fed_svc._closed = False
            self.fed_svc.relay_timeout_sec = 0.12
            ok_sp = self.fed_svc._spawn_external_relay(
                agent_id="muse-f01",
                job_id="pull-timeout-test-01",
                dispatch_mode="pull",
                relay_bot_handle="coord_bot",
                user_id=ADMIN_UID,
                actor_username="adminuser",
                bound_chat_id=self.FED_CHAT_ID,
            )
            self.assertTrue(ok_sp)
            await asyncio.sleep(0.25)
            self.assertNotIn("pull-timeout-test-01", self.fed_svc._relay_tasks)
        finally:
            await self.fed_svc.close_all()
            coord_srv.stop()
            worker_srv.stop()

    async def test_fc6_and_fc7_frontend_chatroom_invariants_and_server_cleanup(self) -> None:
        """FC6 & FC7: Frontend chatroom XSS/race/debounce/readonly invariants, server.py close_all wiring, demo parity."""
        wb_tsx = (REPO_ROOT / "webui" / "src" / "components" / "FederationWorkbenchView.tsx").read_text(
            encoding="utf-8"
        )
        srv_py = (REPO_ROOT / "studio" / "server.py").read_text(encoding="utf-8")
        api_ts = (REPO_ROOT / "webui" / "src" / "api.ts").read_text(encoding="utf-8")
        mock_ts = (REPO_ROOT / "webui" / "src" / "demo" / "mockApi.ts").read_text(encoding="utf-8")

        # FC6: Frontend invariants
        self.assertIn("activePaneMode", wb_tsx)
        self.assertIn("chatroomGenRef", wb_tsx)
        self.assertIn("CHATROOM_SSE_DEBOUNCE_MS", wb_tsx)
        self.assertIn("clearTimeout(chatroomSseDebounceRef.current)", wb_tsx)
        self.assertIn("if (!canEdit || !chatroomData?.bound || chatroomSending) return;", wb_tsx)
        self.assertIn("<SafeMarkdown content={msg.content || \"\"}", wb_tsx)
        for forbidden in ("dangerouslySetInnerHTML", "innerHTML", "<script"):
            self.assertNotIn(forbidden, wb_tsx)
        self.assertEqual(wb_tsx.count("setInterval("), 1)
        self.assertEqual(wb_tsx.count("clearInterval("), 1)

        # FC5/FC7: server.py _on_cleanup calls federation_svc.close_all() and registers chatroom routes
        self.assertIn("await federation_svc.close_all()", srv_py)
        self.assertIn("/api/federation/workbench/chatroom/messages", srv_py)

        # FC7: API & Demo parity
        for sym in ("fetchFederationChatroomMessages", "sendFederationChatroomMessage"):
            self.assertIn(f"export function {sym}", api_ts)
            self.assertIn(f"export async function {sym}", mock_ts)

    async def test_blocker1_pull_queue_and_federation_lock_symlinks_rejected(self) -> None:
        """BLOCKER-1: Symlinked pull_queue.lock / .lock / federation.lock rejected 403 with zero TG send & zero queue write."""
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_hdrs = self._admin_headers(admin_cookie, admin_csrf)

        r_reg = await self.client.post(
            "/api/federation/agents",
            headers=admin_hdrs,
            data=json.dumps({"agent_id": "muse-f01", "kind": "pull_worker", "display_name": "Muse Node"}),
        )
        self.assertEqual(r_reg.status, 200, await r_reg.text())

        self._write_team_config(fed_mirror={"chat_id": self.FED_CHAT_ID, "title": "联邦群"})
        coord_host, coord_srv, _, worker_srv = self._setup_online_coord_and_worker()
        assert worker_srv is not None
        try:
            pq_dir = self.bus_dir / "federation" / "pull_queue"
            pq_dir.mkdir(parents=True, exist_ok=True)
            outside_target = self.tmp / "outside_lock_target.txt"
            outside_target.write_text("UNTOUCHED_LOCK_CANARY", encoding="utf-8")

            lock_cases = [
                ("pull_queue.lock", pq_dir / "pull_queue.lock"),
                (".lock", pq_dir / ".lock"),
                ("federation.lock", self.bus_dir / "federation" / "federation.lock"),
            ]
            for label, lock_path in lock_cases:
                if lock_path.exists() or lock_path.is_symlink():
                    lock_path.unlink()
                os.symlink(outside_target, lock_path)
                try:
                    # 1. Chatroom POST mentioning external agent must fail-closed 403 SECURITY_SYMLINK_REJECTED, zero TG send, zero queue write
                    r_chat = await self.client.post(
                        "/api/federation/workbench/chatroom/messages",
                        headers=admin_hdrs,
                        data=json.dumps({"content": f"{self._at('muse-f01')} should block on {label}"}),
                    )
                    self.assertEqual(r_chat.status, 403, f"chatroom POST should return 403 for {label}")
                    chat_body = await r_chat.json()
                    self.assertEqual(chat_body.get("code"), "SECURITY_SYMLINK_REJECTED", chat_body)
                    self.assertEqual(coord_host.sent_calls, [], f"Zero TG send required for {label}")
                    self.assertEqual(list(pq_dir.glob("*.json")), [], f"Zero pull_queue writes required for {label}")
                    self.assertEqual(outside_target.read_text(encoding="utf-8"), "UNTOUCHED_LOCK_CANARY")
                    self.assertEqual(self.fed_svc._relay_reserved, 0)

                    # 2. Workbench direct pull dispatch must also fail-closed 403 SECURITY_SYMLINK_REJECTED
                    r_wb = await self.client.post(
                        "/api/federation/workbench/agents/muse-f01/dispatch",
                        headers=admin_hdrs,
                        data=json.dumps({"prompt": f"wb dispatch blocked by {label}"}),
                    )
                    self.assertEqual(r_wb.status, 403, f"workbench dispatch should return 403 for {label}")
                    wb_body = await r_wb.json()
                    self.assertEqual(wb_body.get("code"), "SECURITY_SYMLINK_REJECTED", wb_body)
                    self.assertEqual(list(pq_dir.glob("*.json")), [], f"Zero pull_queue writes on wb dispatch for {label}")
                finally:
                    if lock_path.is_symlink():
                        lock_path.unlink()
        finally:
            await self.fed_svc.close_all()
            coord_srv.stop()
            worker_srv.stop()

    async def test_blocker2_env_bound_team_config_and_roster_symlink_and_fifo_rejected(self) -> None:
        """BLOCKER-2: Env-bound federation mirror rejects symlink/FIFO team_config.json, roster.json & bus_dir (GET & POST)."""
        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_get = {"Cookie": f"{SESSION_COOKIE_NAME}={admin_cookie}"}
        admin_hdrs = self._admin_headers(admin_cookie, admin_csrf)

        self._write_team_config(fed_mirror={"chat_id": self.FED_CHAT_ID, "title": "联邦群"})
        coord_host, coord_srv, _, worker_srv = self._setup_online_coord_and_worker()
        assert worker_srv is not None
        canary = "SECRET_CANARY_DO_NOT_LEAK_BLOCKER2"
        outside_secret = self.tmp / "outside_secret.json"
        outside_secret.write_text(json.dumps({"bots": {"leak_bot": {"display_name": canary}}}), encoding="utf-8")

        orig_tc = (self.bus_dir / "team_config.json").read_text(encoding="utf-8")
        orig_roster = (self.bus_dir / "roster.json").read_text(encoding="utf-8")

        try:
            with mock.patch.dict(
                os.environ,
                {"AGY_STUDIO_FEDERATION_MIRROR_CHAT_ID": str(self.FED_CHAT_ID)},
            ):
                for fname in ("team_config.json", "roster.json"):
                    target_path = self.bus_dir / fname
                    for kind in ("symlink", "fifo"):
                        if target_path.exists() or target_path.is_symlink():
                            target_path.unlink()
                        if kind == "symlink":
                            os.symlink(outside_secret, target_path)
                        else:
                            os.mkfifo(target_path)
                        try:
                            t0 = time.monotonic()
                            r_get = await asyncio.wait_for(
                                self.client.get("/api/federation/workbench/chatroom/messages", headers=admin_get),
                                timeout=2.0,
                            )
                            self.assertLess(time.monotonic() - t0, 2.0, f"GET blocked on {fname} ({kind})")
                            self.assertEqual(r_get.status, 403, f"GET must return 403 for {fname} ({kind})")
                            get_txt = await r_get.text()
                            self.assertIn("SECURITY_SYMLINK_REJECTED", get_txt)
                            self.assertNotIn(canary, get_txt)

                            t1 = time.monotonic()
                            r_post = await asyncio.wait_for(
                                self.client.post(
                                    "/api/federation/workbench/chatroom/messages",
                                    headers=admin_hdrs,
                                    data=json.dumps({"content": f"blocked {fname} {kind}"}),
                                ),
                                timeout=2.0,
                            )
                            self.assertLess(time.monotonic() - t1, 2.0, f"POST blocked on {fname} ({kind})")
                            self.assertEqual(r_post.status, 403, f"POST must return 403 for {fname} ({kind})")
                            post_txt = await r_post.text()
                            self.assertIn("SECURITY_SYMLINK_REJECTED", post_txt)
                            self.assertNotIn(canary, post_txt)
                            self.assertEqual(coord_host.sent_calls, [], f"Zero TG send for {fname} ({kind})")
                        finally:
                            if target_path.exists() or target_path.is_symlink():
                                target_path.unlink()
                            # Restore clean regular files before next case
                            (self.bus_dir / "team_config.json").write_text(orig_tc, encoding="utf-8")
                            (self.bus_dir / "roster.json").write_text(orig_roster, encoding="utf-8")

                # Also verify symlinked bus_dir itself fails closed 403 on GET & POST under env binding
                sym_bus = self.tmp / "symlink_bus_dir"
                os.symlink(self.bus_dir, sym_bus)
                orig_ds_bus = self.sources.bus_dir
                self.sources.bus_dir = sym_bus
                try:
                    r_g_sym = await asyncio.wait_for(
                        self.client.get("/api/federation/workbench/chatroom/messages", headers=admin_get),
                        timeout=2.0,
                    )
                    self.assertEqual(r_g_sym.status, 403)
                    self.assertIn("SECURITY_SYMLINK_REJECTED", await r_g_sym.text())

                    r_p_sym = await asyncio.wait_for(
                        self.client.post(
                            "/api/federation/workbench/chatroom/messages",
                            headers=admin_hdrs,
                            data=json.dumps({"content": "blocked symlink bus_dir"}),
                        ),
                        timeout=2.0,
                    )
                    self.assertEqual(r_p_sym.status, 403)
                    self.assertIn("SECURITY_SYMLINK_REJECTED", await r_p_sym.text())
                    self.assertEqual(coord_host.sent_calls, [])
                finally:
                    self.sources.bus_dir = orig_ds_bus
                    sym_bus.unlink()
        finally:
            await self.fed_svc.close_all()
            coord_srv.stop()
            worker_srv.stop()

    async def test_followup_relay_reservation_prevents_burst_race_and_rolls_back(self) -> None:
        """Follow-up: Atomic relay slot reservation blocks burst race with 429 and rolls back cleanly on failure."""
        import threading

        admin_cookie, admin_csrf = await self._login("AdminUser", ADMIN_PASS)
        admin_hdrs = self._admin_headers(admin_cookie, admin_csrf)

        r_reg = await self.client.post(
            "/api/federation/agents",
            headers=admin_hdrs,
            data=json.dumps({"agent_id": "muse-f01", "kind": "pull_worker", "display_name": "Muse Node"}),
        )
        self.assertEqual(r_reg.status, 200)
        self._write_team_config(fed_mirror={"chat_id": self.FED_CHAT_ID, "title": "联邦群"})
        coord_host, coord_srv, _, worker_srv = self._setup_online_coord_and_worker()
        assert worker_srv is not None
        try:
            self.fed_svc.max_concurrent_relays = 1
            self.fed_svc.relay_poll_interval_sec = 0.05
            self.fed_svc.relay_timeout_sec = 5.0

            # Part A: Pause Request 1 mid-IPC after reserving the 1 slot -> concurrent Request 2 must get 429 immediately
            orig_ipc_fn = coord_srv.tg_group_send_fn
            ipc_entered = threading.Event()
            ipc_release = threading.Event()

            def _gated_ipc(req: dict[str, object]) -> tuple[int, dict[str, object]]:
                ipc_entered.set()
                ipc_release.wait(timeout=3.0)
                return orig_ipc_fn(req)

            coord_srv.tg_group_send_fn = _gated_ipc
            try:
                t1 = asyncio.create_task(
                    self.client.post(
                        "/api/federation/workbench/chatroom/messages",
                        headers=admin_hdrs,
                        data=json.dumps({"content": f"{self._at('muse-f01')} burst req 1"}),
                    )
                )
                # Wait until Request 1 has reserved its slot and entered IPC
                deadline = time.monotonic() + 2.0
                while not ipc_entered.is_set() and time.monotonic() < deadline:
                    await asyncio.sleep(0.01)
                self.assertTrue(ipc_entered.is_set(), "Request 1 did not reach IPC gate")
                self.assertEqual(self.fed_svc._relay_reserved, 1)

                # Burst Request 2 arrives while Request 1 is still awaiting IPC -> must be rejected 429
                r2 = await self.client.post(
                    "/api/federation/workbench/chatroom/messages",
                    headers=admin_hdrs,
                    data=json.dumps({"content": f"{self._at('muse-f01')} burst req 2"}),
                )
                self.assertEqual(r2.status, 429)
                d2 = await r2.json()
                self.assertEqual(d2.get("code"), "relay_capacity_exceeded")

                ipc_release.set()
                r1 = await t1
                self.assertEqual(r1.status, 200, await r1.text())
                self.assertEqual(self.fed_svc._relay_reserved, 0)
                self.assertEqual(len(self.fed_svc._relay_tasks), 1)
            finally:
                ipc_release.set()
                coord_srv.tg_group_send_fn = orig_ipc_fn

            await self.fed_svc.close_all()
            self.fed_svc._closed = False

            # Part B: Rollback on IPC error -> _relay_reserved returns to 0 and next valid request succeeds
            coord_srv.tg_group_send_fn = lambda _req: (502, {"ok": False, "error": "simulated ipc failure"})
            try:
                r_fail = await self.client.post(
                    "/api/federation/workbench/chatroom/messages",
                    headers=admin_hdrs,
                    data=json.dumps({"content": f"{self._at('muse-f01')} ipc fail rollback"}),
                )
                self.assertEqual(r_fail.status, 502)
                self.assertEqual(self.fed_svc._relay_reserved, 0)
                self.assertEqual(len(self.fed_svc._relay_tasks), 0)
            finally:
                coord_srv.tg_group_send_fn = orig_ipc_fn

            # Next request after rollback succeeds cleanly (proving zero leaked reservation)
            r_ok = await self.client.post(
                "/api/federation/workbench/chatroom/messages",
                headers=admin_hdrs,
                data=json.dumps({"content": f"{self._at('muse-f01')} after rollback"}),
            )
            self.assertEqual(r_ok.status, 200, await r_ok.text())
            self.assertEqual(self.fed_svc._relay_reserved, 0)
            self.assertEqual(len(self.fed_svc._relay_tasks), 1)
        finally:
            await self.fed_svc.close_all()
            coord_srv.stop()
            worker_srv.stop()


if __name__ == "__main__":
    unittest.main()
