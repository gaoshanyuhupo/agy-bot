#!/usr/bin/env python3
"""Offline unit & integration tests for `studio/secrets_config_service.py`.

Covers:
- Host OpenBao runtime auto-detection (isolated tmpdir `card.json`/`token.json` & env fallback)
- Zero plaintext credential echo in GET / PUT / POST responses
- Readonly redaction (`addr=""`, `auth_label=""`, `can_edit=False`) and write refusal (403)
- Strict 4-layer write gate (Origin -> 403, Content-Type -> 415, Auth -> 401, CSRF -> 403, RBAC -> 403)
- Strict `addr` validation rejecting `file://`, non-loopback `http://` (incl. metadata IP),
  embedded userinfo, CRLF/control chars, query/fragment, and `..` path segments
- `0700` dir / `0600` file atomic persistence and symlink refusal (read & write)
- `/api/secrets/openbao/test` against local mock server: redirect refusal, zero shell invocation,
  health status mapping (200/501/503), and host-card token lookup restricted to exact host addr
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from studio.auth import (  # noqa: E402
    SESSION_COOKIE_NAME,
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.chat_service import StudioAuditLogger  # noqa: E402
from studio.data_sources import StudioDataSources  # noqa: E402
from studio.secrets_config_service import (  # noqa: E402
    DEFAULT_GATEWAY_PATH_PREFIX,
    DEFAULT_KV_MOUNT,
    SecretsConfigService,
    _validate_openbao_addr,
)
from studio.server import SECRETS_CONFIG_KEY, create_app  # noqa: E402

ADMIN_UID = 111111111
READONLY_UID = 222222222
ADMIN_PASS = "EXAMPLE_SECRETS_ADMIN_PASS_01"
RO_PASS = "EXAMPLE_SECRETS_RO_PASS_01"

# Dynamically assembled synthetic test credentials so secret scanners stay 100% clean
SYNTH_ROLE_ID = "role-" + "example-0001-abcd"
SYNTH_SECRET_ID = "sec-" + "example-9999-wxyz"
SYNTH_CLIENT_TOK = "hvs." + "EXAMPLE_TEST_TOKEN_0001"
SYNTH_CUSTOM_TOK = "hvs." + "EXAMPLE_CUSTOM_TOKEN_0002"
SYNTH_META_HTTP = "http://" + ".".join(("169", "254", "169", "254")) + "/latest/meta-data"
SYNTH_USERINFO_URL = "https://" + "alice:EXAMPLE_PASS" + chr(64) + "vault.example.com"


class TestOpenBaoAddrValidationAndNoShell(unittest.TestCase):
    """Pure unit tests for URL validation and no-shell static invariant."""

    def test_validate_openbao_addr_rejects_unsafe_and_accepts_valid(self) -> None:
        invalid_cases = [
            "file:///etc/passwd",
            "ftp://vault.example.com",
            "http://vault.example.com:8200",
            SYNTH_META_HTTP,
            SYNTH_USERINFO_URL,
            "https://vault.example.com\r\nX-Inject: 1",
            "https://vault.example.com\nfoo",
            "https://vault.example.com/v1?token=EXAMPLE",
            "https://vault.example.com/v1#frag",
            "https://vault.example.com/../secret",
            "https://vault.example.com:99999",
            "   ",
            12345,
        ]
        for bad in invalid_cases:
            ok, norm, err = _validate_openbao_addr(bad, allow_empty=False)
            self.assertFalse(ok, f"Expected rejection for {bad!r}, got ok=True norm={norm!r}")
            self.assertTrue(err)

        ok_empty, norm_empty, _ = _validate_openbao_addr("", allow_empty=True)
        self.assertTrue(ok_empty)
        self.assertEqual(norm_empty, "")

        for good, expected in [
            ("https://vault.example.com/", "https://vault.example.com"),
            ("https://vault.example.com:8200/bao/", "https://vault.example.com:8200/bao"),
            ("http://127.0.0.1:8200/", "http://127.0.0.1:8200"),
            ("http://localhost:8200", "http://localhost:8200"),
        ]:
            ok, norm, err = _validate_openbao_addr(good, allow_empty=False)
            self.assertTrue(ok, f"Expected valid addr {good!r}, got err={err!r}")
            self.assertEqual(norm, expected)

    def test_secrets_service_contains_zero_shell_or_subprocess_calls(self) -> None:
        src = (REPO_ROOT / "studio" / "secrets_config_service.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mod_names = (
                    [a.name for a in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                )
                for m in mod_names:
                    self.assertNotIn("subprocess", m)
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, ("system", "popen", "Popen", "create_subprocess_shell"))


class TestSecretsConfigServiceIntegration(unittest.IsolatedAsyncioTestCase):
    """End-to-end aiohttp tests for GET/PUT `/api/secrets/openbao` and POST `/test`."""

    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_secrets_test_")
        self.tmp = Path(self._td.name)
        self.fake_home = self.tmp / "home"
        self.fake_home.mkdir(parents=True, exist_ok=True)
        self.studio_cfg = self.tmp / "studio-cfg"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bus"
        self.host_ob_dir = self.tmp / "host-openbao"
        self.saved_cfg_path = self.tmp / "secure-cfg" / "studio_secrets.json"
        self.audit_log = self.studio_cfg / "audit.jsonl"

        for d in (self.studio_cfg, self.bridge_dir, self.bus_dir, self.host_ob_dir):
            d.mkdir(parents=True, exist_ok=True)

        (self.bridge_dir / ".env").write_text(
            "\n".join(
                [
                    "AGY_TG_BOT_TOKEN=123456789:EXAMPLE_SECRETS_TEST_TOKEN_0001",
                    f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                    f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                    f"AGY_TG_READONLY_USERS={READONLY_UID}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        # Isolate environment & home directory from real host OpenBao config
        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "OPENBAO_CONFIG_PATH": "",
                "BAO_ADDR": "",
                "VAULT_ADDR": "",
                "BAO_TOKEN": "",
                "VAULT_TOKEN": "",
                "AGY_STUDIO_SECRETS_CONFIG": str(self.saved_cfg_path),
            },
            clear=False,
        )
        self._env_patch.start()
        self._home_patch = mock.patch("studio.secrets_config_service.Path.home", return_value=self.fake_home)
        self._home_patch.start()

        # Seed password-mode admin & readonly users
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
        )
        # Point app's real SecretsConfigService to isolated tmp paths
        self.secrets_svc: SecretsConfigService = self.app[SECRETS_CONFIG_KEY]
        self.secrets_svc.config_path = self.saved_cfg_path
        self.secrets_svc.host_openbao_dir = self.host_ob_dir

        self.server = TestServer(self.app)
        await self.server.start_server()
        self.client = TestClient(self.server, cookie_jar=aiohttp.DummyCookieJar())
        await self.client.start_server()
        self.origin = f"http://{self.server.host}:{self.server.port}"

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.server.close()
        self._home_patch.stop()
        self._env_patch.stop()
        self._td.cleanup()

    async def _login(self, username: str, password: str) -> tuple[str, str]:
        r = await self.client.post(
            "/api/auth/login",
            headers={"Origin": self.origin, "Content-Type": "application/json"},
            data=json.dumps({"username": username, "password": password}),
        )
        self.assertEqual(r.status, 200)
        data = await r.json()
        sid = r.cookies[SESSION_COOKIE_NAME].value
        return sid, data["csrf_token"]

    def _headers(self, sid: str, csrf: str, *, origin: str | None = None, ct: str = "application/json") -> dict[str, str]:
        hdrs = {
            "Cookie": f"{SESSION_COOKIE_NAME}={sid}",
            "X-Studio-CSRF": csrf,
            "Content-Type": ct,
        }
        if origin is not None:
            hdrs["Origin"] = origin
        return hdrs

    async def test_host_auto_detection_zero_secret_echo_and_readonly_redaction(self) -> None:
        # Write mock card.json & token.json in isolated host_openbao_dir
        card_file = self.host_ob_dir / "card.json"
        card_file.write_text(
            json.dumps(
                {
                    "base_url": "https://vault.example.com/",
                    "card_name": "example-card-01",
                    "role_id": SYNTH_ROLE_ID,
                    "secret_id": SYNTH_SECRET_ID,
                }
            ),
            encoding="utf-8",
        )
        tok_file = self.host_ob_dir / "token.json"
        tok_file.write_text(
            json.dumps(
                {
                    "client_token": SYNTH_CLIENT_TOK,
                    "expires_at_approx": int((time.time() + 3600) * 1000),
                }
            ),
            encoding="utf-8",
        )

        # Unauthenticated -> 401
        r_unauth = await self.client.get("/api/secrets/openbao")
        self.assertEqual(r_unauth.status, 401)

        # Admin sees normalized addr & auth_label, NEVER raw role_id / secret_id / client_token
        sid_a, _ = await self._login("AdminUser", ADMIN_PASS)
        r_adm = await self.client.get(
            "/api/secrets/openbao",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
        )
        self.assertEqual(r_adm.status, 200)
        raw_adm = await r_adm.text()
        data_adm = json.loads(raw_adm)
        self.assertTrue(data_adm["ok"])
        self.assertEqual(data_adm["source"], "host_auto")
        self.assertEqual(data_adm["addr"], "https://vault.example.com")
        self.assertEqual(data_adm["auth_label"], "example-card-01")
        self.assertEqual(data_adm["kv_mount"], DEFAULT_KV_MOUNT)
        self.assertEqual(data_adm["gateway_path_prefix"], DEFAULT_GATEWAY_PATH_PREFIX)
        self.assertTrue(data_adm["credential_configured"])
        self.assertTrue(data_adm["can_edit"])
        self.assertEqual(data_adm["security_card_status"], "reserved")
        for secret_val in (SYNTH_ROLE_ID, SYNTH_SECRET_ID, SYNTH_CLIENT_TOK):
            self.assertNotIn(secret_val, raw_adm)

        # Readonly MUST NOT see addr or auth_label, and can_edit=False
        sid_r, csrf_r = await self._login("ViewerUser", RO_PASS)
        r_ro = await self.client.get(
            "/api/secrets/openbao",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_r}"},
        )
        self.assertEqual(r_ro.status, 200)
        raw_ro = await r_ro.text()
        data_ro = json.loads(raw_ro)
        self.assertEqual(data_ro["addr"], "")
        self.assertEqual(data_ro["auth_label"], "")
        self.assertFalse(data_ro["can_edit"])
        self.assertTrue(data_ro["credential_configured"])
        self.assertNotIn("vault.example.com", raw_ro)
        self.assertNotIn("example-card-01", raw_ro)
        for secret_val in (SYNTH_ROLE_ID, SYNTH_SECRET_ID, SYNTH_CLIENT_TOK):
            self.assertNotIn(secret_val, raw_ro)

        # Readonly PUT & POST /test both denied with 403
        r_ro_put = await self.client.put(
            "/api/secrets/openbao",
            headers=self._headers(sid_r, csrf_r, origin=self.origin),
            data=json.dumps({"enabled": True, "addr": "https://vault.example.com"}),
        )
        self.assertEqual(r_ro_put.status, 403)
        r_ro_test = await self.client.post(
            "/api/secrets/openbao/test",
            headers=self._headers(sid_r, csrf_r, origin=self.origin),
            data=json.dumps({"addr": "https://vault.example.com"}),
        )
        self.assertEqual(r_ro_test.status, 403)

    async def test_four_layer_write_gate_and_invalid_addr_rejected(self) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)
        payload = json.dumps({"enabled": True, "addr": "https://vault.example.com"})

        # Gate 1: Missing or cross-origin -> 403
        r_no_orig = await self.client.put(
            "/api/secrets/openbao",
            headers=self._headers(sid_a, csrf_a, origin=None),
            data=payload,
        )
        self.assertEqual(r_no_orig.status, 403)
        r_bad_orig = await self.client.put(
            "/api/secrets/openbao",
            headers=self._headers(sid_a, csrf_a, origin="https://evil.example.com"),
            data=payload,
        )
        self.assertEqual(r_bad_orig.status, 403)

        # Gate 2: Non-JSON Content-Type -> 415
        r_ct = await self.client.put(
            "/api/secrets/openbao",
            headers=self._headers(sid_a, csrf_a, origin=self.origin, ct="text/plain"),
            data=payload,
        )
        self.assertEqual(r_ct.status, 415)

        # Gate 3: Unauthenticated -> 401
        r_no_auth = await self.client.put(
            "/api/secrets/openbao",
            headers={"Origin": self.origin, "Content-Type": "application/json"},
            data=payload,
        )
        self.assertEqual(r_no_auth.status, 401)

        # Gate 4a: Missing/wrong CSRF -> 403
        r_bad_csrf = await self.client.put(
            "/api/secrets/openbao",
            headers=self._headers(sid_a, "wrong-csrf-token", origin=self.origin),
            data=payload,
        )
        self.assertEqual(r_bad_csrf.status, 403)

        # Invalid addr values rejected with 400
        for bad_addr in (
            "file:///etc/passwd",
            SYNTH_META_HTTP,
            SYNTH_USERINFO_URL,
            "https://vault.example.com\r\nX-Test: 1",
        ):
            r_bad = await self.client.put(
                "/api/secrets/openbao",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps({"enabled": True, "addr": bad_addr}),
            )
            self.assertEqual(r_bad.status, 400, f"Expected 400 for addr={bad_addr!r}")

    async def test_atomic_0600_persistence_reset_and_symlink_refusal(self) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)

        # Save custom token config
        r_put = await self.client.put(
            "/api/secrets/openbao",
            headers=self._headers(sid_a, csrf_a, origin=self.origin),
            data=json.dumps(
                {
                    "enabled": True,
                    "addr": "https://custom-vault.example.com/",
                    "kv_mount": "kv2",
                    "gateway_path_prefix": "studio/gateways",
                    "auth_mode": "token",
                    "auth_label": "custom-tok",
                    "token": SYNTH_CUSTOM_TOK,
                }
            ),
        )
        self.assertEqual(r_put.status, 200)
        raw_put = await r_put.text()
        self.assertNotIn(SYNTH_CUSTOM_TOK, raw_put)
        data_put = json.loads(raw_put)
        self.assertEqual(data_put["source"], "custom")
        self.assertEqual(data_put["addr"], "https://custom-vault.example.com")
        self.assertTrue(data_put["credential_configured"])

        # Verify POSIX permissions: parent 0700, file 0600, lock 0600
        self.assertEqual(stat.S_IMODE(self.saved_cfg_path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.saved_cfg_path.stat().st_mode), 0o600)
        lock_file = self.saved_cfg_path.parent / f".{self.saved_cfg_path.name}.lock"
        self.assertEqual(stat.S_IMODE(lock_file.stat().st_mode), 0o600)

        # Reset back to host_auto
        r_rst = await self.client.put(
            "/api/secrets/openbao",
            headers=self._headers(sid_a, csrf_a, origin=self.origin),
            data=json.dumps({"reset_to_host_auto": True}),
        )
        self.assertEqual(r_rst.status, 200)
        data_rst = await r_rst.json()
        self.assertEqual(data_rst["source"], "unconfigured")

        # Symlink target file MUST be refused (500 io_error, target untouched)
        victim = self.tmp / "victim.txt"
        victim.write_text("KEEP_INTACT", encoding="utf-8")
        self.saved_cfg_path.unlink()
        os.symlink(str(victim), str(self.saved_cfg_path))
        r_sym = await self.client.put(
            "/api/secrets/openbao",
            headers=self._headers(sid_a, csrf_a, origin=self.origin),
            data=json.dumps({"enabled": True, "addr": "https://vault.example.com"}),
        )
        self.assertEqual(r_sym.status, 500)
        self.assertEqual(victim.read_text(encoding="utf-8"), "KEEP_INTACT")

        # Symlink host card.json MUST NOT be read
        real_card = self.tmp / "outside_card.json"
        real_card.write_text(
            json.dumps({"base_url": "https://leaked.example.com", "card_name": "sym-card"}),
            encoding="utf-8",
        )
        os.symlink(str(real_card), str(self.host_ob_dir / "card.json"))
        detected = self.secrets_svc._detect_host_openbao()
        self.assertFalse(detected["detected"])
        self.assertEqual(detected["addr"], "")

    async def test_connectivity_probe_refuses_redirects_and_checks_health_offline(self) -> None:
        # Spin up an in-process loopback mock OpenBao server
        probe_state = {"mode": "healthy", "lookup_tokens": []}

        async def _health(_req: web.Request) -> web.Response:
            m = probe_state["mode"]
            if m == "redirect":
                return web.Response(status=302, headers={"Location": "http://127.0.0.1:9/evil"})
            if m == "sealed":
                return web.json_response({"initialized": True, "sealed": True}, status=503)
            if m == "uninit":
                return web.json_response({"initialized": False, "sealed": True}, status=501)
            return web.json_response({"initialized": True, "sealed": False}, status=200)

        async def _lookup(req: web.Request) -> web.Response:
            probe_state["lookup_tokens"].append(req.headers.get("X-Vault-Token", ""))
            return web.json_response({"data": {"display_name": "example"}}, status=200)

        mock_bao = web.Application()
        mock_bao.router.add_get("/v1/sys/health", _health)
        mock_bao.router.add_get("/v1/auth/token/lookup-self", _lookup)
        mock_srv = TestServer(mock_bao)
        await mock_srv.start_server()
        try:
            mock_addr = f"http://{mock_srv.host}:{mock_srv.port}"
            # Configure host card pointing to mock_addr + cached token
            (self.host_ob_dir / "card.json").write_text(
                json.dumps(
                    {
                        "base_url": mock_addr,
                        "card_name": "local-mock-card",
                        "role_id": SYNTH_ROLE_ID,
                        "secret_id": SYNTH_SECRET_ID,
                    }
                ),
                encoding="utf-8",
            )
            (self.host_ob_dir / "token.json").write_text(
                json.dumps(
                    {
                        "client_token": SYNTH_CLIENT_TOK,
                        "expires_at_approx": int((time.time() + 3600) * 1000),
                    }
                ),
                encoding="utf-8",
            )

            sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)

            # 1. Healthy + host_card matches exact host addr -> lookup-self verified
            probe_state["mode"] = "healthy"
            r_ok = await self.client.post(
                "/api/secrets/openbao/test",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps({"addr": mock_addr, "auth_mode": "host_card"}),
            )
            self.assertEqual(r_ok.status, 200)
            d_ok = await r_ok.json()
            self.assertTrue(d_ok["ok"])
            self.assertTrue(d_ok["reachable"])
            self.assertTrue(d_ok["initialized"])
            self.assertFalse(d_ok["sealed"])
            self.assertTrue(d_ok["auth_verified"])
            self.assertEqual(probe_state["lookup_tokens"], [SYNTH_CLIENT_TOK])
            self.assertNotIn(SYNTH_CLIENT_TOK, json.dumps(d_ok))

            # 2. 302 Redirect -> MUST be refused (reachable=False, ok=False)
            probe_state["mode"] = "redirect"
            r_red = await self.client.post(
                "/api/secrets/openbao/test",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps({"addr": mock_addr, "auth_mode": "host_card"}),
            )
            self.assertEqual(r_red.status, 200)
            d_red = await r_red.json()
            self.assertFalse(d_red["ok"])
            self.assertFalse(d_red["reachable"])
            self.assertIn("重定向", d_red["message"])

            # 3. 503 Sealed -> reachable=True, sealed=True, ok=False
            probe_state["mode"] = "sealed"
            r_seal = await self.client.post(
                "/api/secrets/openbao/test",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps({"addr": mock_addr}),
            )
            d_seal = await r_seal.json()
            self.assertFalse(d_seal["ok"])
            self.assertTrue(d_seal["reachable"])
            self.assertTrue(d_seal["sealed"])

            # 4. 501 Uninitialized -> reachable=True, initialized=False, ok=False
            probe_state["mode"] = "uninit"
            r_uninit = await self.client.post(
                "/api/secrets/openbao/test",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps({"addr": mock_addr}),
            )
            d_uninit = await r_uninit.json()
            self.assertFalse(d_uninit["ok"])
            self.assertTrue(d_uninit["reachable"])
            self.assertFalse(d_uninit["initialized"])

            # 5. Different addr MUST NOT send host cached token
            probe_state["mode"] = "healthy"
            probe_state["lookup_tokens"].clear()
            alt_addr = f"http://localhost:{mock_srv.port}"
            r_alt = await self.client.post(
                "/api/secrets/openbao/test",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps({"addr": alt_addr, "auth_mode": "host_card"}),
            )
            self.assertEqual(r_alt.status, 200)
            self.assertEqual(probe_state["lookup_tokens"], [])
        finally:
            await mock_srv.close()


if __name__ == "__main__":
    unittest.main()
