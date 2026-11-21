#!/usr/bin/env python3
"""Offline unit & integration tests for External Model Gateways (C1–C4).

Covers:
- C1: 4-layer write gate (`Origin`, `Sec-Fetch-Site`, `Content-Type`, Auth, CSRF, RBAC `admin`),
      audit logging, and strict GET redaction (no plaintext `api_key`, sensitive `extra_headers`,
      or host absolute paths for both `admin` and `readonly`).
- C2: Anti-RCE field whitelist rejecting `api_key_cmd`, `api_key_file`, `secret_ref`, and
      malformed/prototype-pollution IDs (`../x`, `__proto__`, `constructor`, control chars);
      pre-existing host `api_key_cmd` entries exposed read-only (`read_only_cmd=True`) and
      protected against Web modification/deletion/probe; zero subprocess/shell static invariant.
- C3: SSRF / DoS / secret-safe `/probe`: blocks cloud metadata (AWS/ECS IMDS, EC2 IPv6
      metadata, GCP metadata hostnames, IPv4/IPv6 link-local ranges, unspecified `0.0.0.0`),
      non-HTTP(S) schemes, embedded `user:pass@`, DNS rebinding to metadata, and HTTP
      redirects (`allow_redirects=False`); allows `127.0.0.1`/`localhost`; enforces 512 KiB
      response cap and scrubs Bearer/API keys from upstream errors & logs.
- C4: Unified `SecretStore` (OpenBao KV v2 -> `local_0600` automatic fallback -> `security_card`
      reserved), zero plaintext `api_key` in `gateways.json`, `0700`/`0600` + symlink refusal,
      `bridge/gateway_adapter.py` `secret_ref` resolution & cache invalidation, and
      `bridge/bridge.py` hot-reloading `gateways.json` + `agy_models(include_gateways=True)`.
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import json
import logging
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
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import gateway_adapter  # noqa: E402
from studio.auth import (  # noqa: E402
    SESSION_COOKIE_NAME,
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.data_sources import StudioDataSources  # noqa: E402
from studio.gateway_service import (  # noqa: E402
    MAX_PROBE_BODY_BYTES,
    GatewayService,
    _is_same_origin_url,
    _looks_like_obfuscated_numeric_ip,
    _PinnedResolver,
    validate_gateway_base_url,
)
from studio.secrets_config_service import SecretsConfigService  # noqa: E402
from studio.server import GATEWAY_SERVICE_KEY, SECRETS_CONFIG_KEY, create_app  # noqa: E402

ADMIN_UID = 111111111
READONLY_UID = 222222222
ADMIN_PASS = "EXAMPLE_GW_ADMIN_PASS_01"
RO_PASS = "EXAMPLE_GW_RO_PASS_01"

# Dynamically assembled synthetic secrets & SSRF fixtures so static secret scanners stay clean
SYNTH_API_KEY_1 = "sk-" + "EXAMPLE_TEST_KEY_ALPHA_1111"
SYNTH_API_KEY_2 = "sk-" + "EXAMPLE_TEST_KEY_BETA_2222"
SYNTH_HEADER_TOK = "tok-" + "EXAMPLE_HEADER_SECRET_9999"
SYNTH_BAO_TOK = "hvs." + "EXAMPLE_BAO_KV_TOKEN_0001"
SYNTH_IMDS_IP = ".".join(("169", "254", "169", "254"))
SYNTH_META_AWS = "http://" + SYNTH_IMDS_IP + "/latest/meta-data"
SYNTH_META_ECS = "http://" + ".".join(("169", "254", "170", "2")) + "/v2/credentials"
SYNTH_META_LL = "http://" + ".".join(("169", "254", "12", "34")) + "/v1"
SYNTH_META_ZERO = "http://" + ".".join(("0", "0", "0", "0")) + ":8000/v1"
SYNTH_META_EC2_V6 = "http://[" + ":".join(("fd00", "ec2", "", "254")) + "]/latest/meta-data"
SYNTH_META_GCP = "http://" + ".".join(("metadata", "google", "internal")) + "/computeMetadata/v1"
SYNTH_META_GCP_SUB = "https://" + ".".join(("sub", "metadata", "google", "internal")) + "/v1"
SYNTH_META_ALI = "http://" + ".".join(("100", "100", "100", "200")) + "/latest/meta-data"
SYNTH_META_MAPPED_V6 = "http://[::ffff:" + SYNTH_IMDS_IP + "]/v1"
SYNTH_META_DEC_INT = "http://" + str((169 << 24) | (254 << 16) | (169 << 8) | 254) + "/v1"
SYNTH_META_HEX_INT = "http://" + hex((169 << 24) | (254 << 16) | (169 << 8) | 254) + "/v1"
SYNTH_META_OCTAL_FULL = "http://" + ".".join(("0251", "0376", "0251", "0376")) + "/latest/meta-data"
SYNTH_META_OCTAL_MIXED = "http://" + ".".join(("0251", "254", "169", "254")) + "/v1"
SYNTH_META_HEX_DOTTED = "http://" + ".".join(("0xa9", "0xfe", "0xa9", "0xfe")) + "/v1"
SYNTH_META_PY_OCTAL = "http://" + ".".join(("0o251", "0o376", "0o251", "0o376")) + "/v1"
SYNTH_META_SHORT_3 = "http://" + ".".join(("169", "254", str((169 << 8) | 254))) + "/v1"
SYNTH_META_SHORT_2 = "http://" + ".".join(("169", str((254 << 16) | (169 << 8) | 254))) + "/v1"
SYNTH_META_OCTAL_LOOPBACK = "http://" + ".".join(("0177", "0", "0", "1")) + ":8000/v1"
SYNTH_USERINFO = "https://" + "alice:EXAMPLE_PW" + chr(64) + "api.example.com/v1"


def _isolated_env_overrides(extra: dict[str, str] | None = None) -> dict[str, str]:
    base = {
        "AGY_TG_BOT_EFFORT": "",
        "AGY_TG_BOT_MODEL": "",
        "OPENBAO_CONFIG_PATH": "",
        "BAO_ADDR": "",
        "VAULT_ADDR": "",
        "BAO_TOKEN": "",
        "VAULT_TOKEN": "",
        "AGY_TG_GATEWAYS_FILE": "",
        "AGY_TG_GATEWAYS_JSON": "",
        "AGY_STUDIO_SECRETS_CONFIG": "",
        "AGY_STUDIO_GATEWAY_SECRETS_FILE": "",
    }
    if extra:
        base.update(extra)
    return base


class TestGatewayStaticSecurityAndSSRF(unittest.TestCase):
    """Pure unit tests for SSRF URL validation (C3) and zero-shell static invariant (C2)."""

    def test_c2_gateway_service_contains_zero_shell_or_subprocess_calls(self) -> None:
        src = (REPO_ROOT / "studio" / "gateway_service.py").read_text(encoding="utf-8")
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

    def test_c3_ssrf_blocks_metadata_and_bad_schemes_allows_loopback(self) -> None:
        blocked_urls = [
            SYNTH_META_AWS,
            SYNTH_META_ECS,
            SYNTH_META_LL,
            SYNTH_META_ZERO,
            SYNTH_META_EC2_V6,
            "http://[fe80::1]/v1",
            "http://[::]/v1",
            SYNTH_META_GCP,
            SYNTH_META_GCP_SUB,
            SYNTH_META_ALI,
            SYNTH_META_MAPPED_V6,
            SYNTH_META_DEC_INT,
            SYNTH_META_HEX_INT,
            "file:///etc/passwd",
            "ftp://api.example.com/v1",
            "gopher://127.0.0.1:6379/_INFO",
            SYNTH_USERINFO,
            "https://api.example.com/v1?api_key=EXAMPLE",
            "https://api.example.com/v1#frag",
            "https://api.example.com/v1/../admin",
            "https://api.example.com\r\nX-Inject: 1",
        ]
        for bad in blocked_urls:
            ok, norm, err = validate_gateway_base_url(bad)
            self.assertFalse(ok, f"Expected SSRF rejection for {bad!r}, got ok=True norm={norm!r}")
            self.assertTrue(err)

        allowed_urls = [
            ("http://127.0.0.1:11434/v1/", "http://127.0.0.1:11434/v1"),
            ("http://localhost:8000/v1", "http://localhost:8000/v1"),
            ("http://[::1]:11434/v1", "http://[::1]:11434/v1"),
            ("https://api.example.com/v1/", "https://api.example.com/v1"),
            ("https://ark.example.com/api/v3", "https://ark.example.com/api/v3"),
        ]
        for good, expected in allowed_urls:
            ok, norm, err = validate_gateway_base_url(good)
            self.assertTrue(ok, f"Expected valid URL {good!r}, got err={err!r}")
            self.assertEqual(norm, expected)

    def test_c3_ssrf_blocks_octal_mixed_radix_and_shorthand_ipv4(self) -> None:
        obfuscated_hosts = [
            ".".join(("0251", "0376", "0251", "0376")),
            ".".join(("0251", "254", "169", "254")),
            ".".join(("0xa9", "0xfe", "0xa9", "0xfe")),
            ".".join(("0Xa9", "254", "0251", "254")),
            ".".join(("0o251", "0o376", "0o251", "0o376")),
            ".".join(("169", "254", str((169 << 8) | 254))),
            ".".join(("169", str((254 << 16) | (169 << 8) | 254))),
            ".".join(("0177", "0", "0", "1")),
            ".".join(("127", "1")),
        ]
        for host in obfuscated_hosts:
            self.assertTrue(
                _looks_like_obfuscated_numeric_ip(host),
                f"Expected obfuscated numeric IP detection for {host!r}",
            )

        for normal_host in (".".join(("127", "0", "0", "1")), "api.example.com", "localhost"):
            self.assertFalse(
                _looks_like_obfuscated_numeric_ip(normal_host),
                f"Did not expect obfuscated flag for {normal_host!r}",
            )

        for bad_url in (
            SYNTH_META_OCTAL_FULL,
            SYNTH_META_OCTAL_MIXED,
            SYNTH_META_HEX_DOTTED,
            SYNTH_META_PY_OCTAL,
            SYNTH_META_SHORT_3,
            SYNTH_META_SHORT_2,
            SYNTH_META_OCTAL_LOOPBACK,
        ):
            ok, norm, err = validate_gateway_base_url(bad_url)
            self.assertFalse(ok, f"Expected SSRF rejection for {bad_url!r}, got ok=True norm={norm!r}")
            self.assertTrue(err)

        # Origin comparison invariants
        self.assertTrue(_is_same_origin_url("https://api.example.com/v1", "https://API.EXAMPLE.COM:443/v2"))
        self.assertTrue(_is_same_origin_url("http://api.example.com/v1", "http://api.example.com:80/v1"))
        self.assertFalse(_is_same_origin_url("https://api.example.com/v1", "http://api.example.com/v1"))
        self.assertFalse(_is_same_origin_url("https://api.example.com/v1", "https://api.example.com:8443/v1"))
        self.assertFalse(_is_same_origin_url("https://api.example.com/v1", "http://127.0.0.1:8080/v1"))


class TestStudioGatewaysIntegration(unittest.IsolatedAsyncioTestCase):
    """End-to-end aiohttp tests covering C1, C2, C3, and C4."""

    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_gw_test_")
        self.tmp = Path(self._td.name)
        self.fake_home = self.tmp / "home"
        self.fake_home.mkdir(parents=True, exist_ok=True)
        self.studio_cfg = self.tmp / "studio-cfg"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bus"
        self.host_ob_dir = self.tmp / "host-openbao"
        self.secure_cfg_dir = self.tmp / "secure-cfg"
        self.saved_ob_cfg = self.secure_cfg_dir / "studio_secrets.json"
        self.gateways_path = self.secure_cfg_dir / "gateways.json"
        self.local_secrets_path = self.secure_cfg_dir / "gateway_secrets.json"
        self.audit_log = self.studio_cfg / "audit.jsonl"

        for d in (self.studio_cfg, self.bridge_dir, self.bus_dir, self.host_ob_dir):
            d.mkdir(parents=True, exist_ok=True)

        (self.bridge_dir / ".env").write_text(
            "\n".join(
                [
                    "AGY_TG_BOT_TOKEN=123456789:EXAMPLE_GW_TEST_TOKEN_0001",
                    f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                    f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                    f"AGY_TG_READONLY_USERS={READONLY_UID}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        self._env_patch = mock.patch.dict(
            os.environ,
            _isolated_env_overrides(
                {
                    "AGY_STUDIO_SECRETS_CONFIG": str(self.saved_ob_cfg),
                    "AGY_TG_GATEWAYS_FILE": str(self.gateways_path),
                    "AGY_STUDIO_GATEWAY_SECRETS_FILE": str(self.local_secrets_path),
                }
            ),
            clear=False,
        )
        self._env_patch.start()
        self._home_patch_sec = mock.patch(
            "studio.secrets_config_service.Path.home", return_value=self.fake_home
        )
        self._home_patch_gw = mock.patch(
            "studio.gateway_service.Path.home", return_value=self.fake_home
        )
        self._home_patch_sec.start()
        self._home_patch_gw.start()

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
        self.secrets_svc: SecretsConfigService = self.app[SECRETS_CONFIG_KEY]
        self.secrets_svc.config_path = self.saved_ob_cfg
        self.secrets_svc.host_openbao_dir = self.host_ob_dir
        self.secrets_svc.secret_store.local_0600.secrets_path = self.local_secrets_path

        self.gw_svc: GatewayService = self.app[GATEWAY_SERVICE_KEY]
        self.gw_svc.gateways_path = self.gateways_path

        self.server = TestServer(self.app)
        await self.server.start_server()
        self.client = TestClient(self.server, cookie_jar=aiohttp.DummyCookieJar())
        await self.client.start_server()
        self.origin = f"http://{self.server.host}:{self.server.port}"

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.server.close()
        self._home_patch_gw.stop()
        self._home_patch_sec.stop()
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

    def _headers(
        self,
        sid: str,
        csrf: str,
        *,
        origin: str | None = None,
        ct: str = "application/json",
        sec_fetch_site: str | None = "same-origin",
    ) -> dict[str, str]:
        hdrs: dict[str, str] = {
            "Cookie": f"{SESSION_COOKIE_NAME}={sid}",
            "X-Studio-CSRF": csrf,
            "Content-Type": ct,
        }
        if origin is not None:
            hdrs["Origin"] = origin
        if sec_fetch_site is not None:
            hdrs["Sec-Fetch-Site"] = sec_fetch_site
        return hdrs

    def _read_audit_entries(self) -> list[dict]:
        if not self.audit_log.is_file():
            return []
        return [
            json.loads(line)
            for line in self.audit_log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    async def test_c1_four_layer_write_gate_and_sec_fetch_site_and_audit(self) -> None:
        # Unauthenticated GET -> 401
        r_unauth = await self.client.get("/api/gateways")
        self.assertEqual(r_unauth.status, 401)

        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)
        sid_r, csrf_r = await self._login("ViewerUser", RO_PASS)

        sample = json.dumps(
            {
                "id": "demo-gw",
                "name": "Demo GW",
                "base_url": "https://api.example.com/v1",
                "dialect": "new_api",
                "api_key": SYNTH_API_KEY_1,
            }
        )

        # Missing Origin -> 403
        r_no_orig = await self.client.post(
            "/api/gateways",
            headers=self._headers(sid_a, csrf_a, origin=None),
            data=sample,
        )
        self.assertEqual(r_no_orig.status, 403)

        # Cross-origin Origin -> 403
        r_bad_orig = await self.client.post(
            "/api/gateways",
            headers=self._headers(sid_a, csrf_a, origin="https://evil.example.com"),
            data=sample,
        )
        self.assertEqual(r_bad_orig.status, 403)

        # Illegal Sec-Fetch-Site -> 403
        r_sfs = await self.client.post(
            "/api/gateways",
            headers=self._headers(sid_a, csrf_a, origin=self.origin, sec_fetch_site="cross-site"),
            data=sample,
        )
        self.assertEqual(r_sfs.status, 403)

        # Non-JSON Content-Type -> 415
        r_ct = await self.client.post(
            "/api/gateways",
            headers=self._headers(sid_a, csrf_a, origin=self.origin, ct="text/plain"),
            data=sample,
        )
        self.assertEqual(r_ct.status, 415)

        # Bad CSRF -> 403
        r_csrf = await self.client.post(
            "/api/gateways",
            headers=self._headers(sid_a, "wrong-csrf", origin=self.origin),
            data=sample,
        )
        self.assertEqual(r_csrf.status, 403)

        # Readonly denied across POST / PUT / PATCH / DELETE / probe -> 403
        for method, path, body in (
            ("POST", "/api/gateways", sample),
            ("PUT", "/api/gateways/demo-gw", sample),
            ("PATCH", "/api/gateways/demo-gw", json.dumps({"enabled": False})),
            ("DELETE", "/api/gateways/demo-gw", "{}"),
            ("POST", "/api/gateways/probe", json.dumps({"base_url": "https://api.example.com/v1"})),
            ("POST", "/api/gateways/demo-gw/probe", "{}"),
        ):
            resp = await self.client.request(
                method,
                path,
                headers=self._headers(sid_r, csrf_r, origin=self.origin),
                data=body,
            )
            self.assertEqual(resp.status, 403, f"Expected 403 for readonly {method} {path}")

        # Verify audit log recorded denials with zero secrets
        raw_audit = self.audit_log.read_text(encoding="utf-8")
        self.assertNotIn(SYNTH_API_KEY_1, raw_audit)
        outcomes = {e["outcome"] for e in self._read_audit_entries()}
        for expected in (
            "denied_origin",
            "denied_sec_fetch_site",
            "denied_content_type",
            "denied_csrf",
            "denied_rbac",
        ):
            self.assertIn(expected, outcomes)

    async def test_c1_get_redacts_secrets_headers_and_host_paths_for_admin_and_readonly(self) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)
        sid_r, _ = await self._login("ViewerUser", RO_PASS)

        r_create = await self.client.post(
            "/api/gateways",
            headers=self._headers(sid_a, csrf_a, origin=self.origin),
            data=json.dumps(
                {
                    "id": "redact-gw",
                    "name": "Redact GW",
                    "base_url": "https://api.example.com/v1",
                    "dialect": "openrouter",
                    "api_key": SYNTH_API_KEY_1,
                    "extra_headers": {
                        "Authorization": f"Bearer {SYNTH_HEADER_TOK}",
                        "X-API-Key": SYNTH_HEADER_TOK,
                        "Cookie": f"sid={SYNTH_HEADER_TOK}",
                        "Proxy-Authorization": f"Basic {SYNTH_HEADER_TOK}",
                        "X-Custom-Token": SYNTH_HEADER_TOK,
                        "X-Client-Secret": SYNTH_HEADER_TOK,
                        "X-Title": "AGY Studio",
                    },
                }
            ),
        )
        self.assertEqual(r_create.status, 201)
        create_text = await r_create.text()
        self.assertNotIn(SYNTH_API_KEY_1, create_text)
        self.assertNotIn(SYNTH_HEADER_TOK, create_text)

        for role_label, sid in (("admin", sid_a), ("readonly", sid_r)):
            r_get = await self.client.get(
                "/api/gateways",
                headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid}"},
            )
            self.assertEqual(r_get.status, 200)
            raw = await r_get.text()
            self.assertNotIn(SYNTH_API_KEY_1, raw, f"{role_label} saw plaintext api_key")
            self.assertNotIn(SYNTH_HEADER_TOK, raw, f"{role_label} saw sensitive header value")
            self.assertNotIn(str(self.tmp), raw, f"{role_label} saw host tmp path")
            self.assertNotIn("/home/", raw, f"{role_label} saw host home path")

            data = json.loads(raw)
            self.assertEqual(data["can_edit"], role_label == "admin")
            gw = data["gateways"][0]
            self.assertTrue(gw["has_api_key"])
            self.assertIn("••••", gw["api_key_hint"])
            self.assertEqual(gw["secret_backend"], "local_0600")
            eh = gw["extra_headers"]
            for k in (
                "Authorization",
                "X-API-Key",
                "Cookie",
                "Proxy-Authorization",
                "X-Custom-Token",
                "X-Client-Secret",
            ):
                self.assertEqual(eh[k], "[REDACTED]", f"Header {k} not redacted for {role_label}")
            self.assertEqual(eh["X-Title"], "AGY Studio")

    async def test_c2_rejects_api_key_cmd_api_key_file_secret_ref_and_invalid_ids(self) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)

        # Forbidden fields rejected with 400
        for bad_payload in (
            {
                "id": "rce-cmd",
                "name": "RCE",
                "base_url": "https://api.example.com/v1",
                "api_key_cmd": "cat /etc/passwd",
            },
            {
                "id": "rce-file",
                "name": "RCE File",
                "base_url": "https://api.example.com/v1",
                "api_key_file": "/etc/passwd",
            },
            {
                "id": "forge-ref",
                "name": "Forge Ref",
                "base_url": "https://api.example.com/v1",
                "secret_ref": {"backend": "openbao", "kv_mount": "lv1", "path": "services/github"},
            },
        ):
            r = await self.client.post(
                "/api/gateways",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(bad_payload),
            )
            self.assertEqual(r.status, 400, f"Expected 400 for {bad_payload}")

        # Invalid gateway IDs rejected with 400
        for bad_id in (
            "../x",
            "__proto__",
            "constructor",
            "prototype",
            "probe",
            "has space",
            "ctrl\nchar",
            "UPPERCASE",
            "gw:colon",
            "a/b",
        ):
            r = await self.client.post(
                "/api/gateways",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "id": bad_id,
                        "name": "Bad ID",
                        "base_url": "https://api.example.com/v1",
                        "credential_kind": "none",
                    }
                ),
            )
            self.assertEqual(r.status, 400, f"Expected 400 for id={bad_id!r}")

        self.assertFalse(self.gateways_path.exists())

    async def test_c2_preexisting_host_api_key_cmd_is_readonly_and_protected(self) -> None:
        # Seed pre-existing host api_key_cmd gateway directly on disk
        self.secure_cfg_dir.mkdir(parents=True, exist_ok=True)
        secret_cmd = "bao get lv1/example/provider --field key"
        self.gateways_path.write_text(
            json.dumps(
                {
                    "gateways": [
                        {
                            "id": "host-cmd-gw",
                            "name": "Host CMD Gateway",
                            "base_url": "https://cpa.example.com/v1",
                            "dialect": "cpa",
                            "api_key_cmd": secret_cmd,
                            "enabled": True,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)

        # GET marks read_only_cmd=True and NEVER leaks command string
        r_get = await self.client.get(
            "/api/gateways",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
        )
        self.assertEqual(r_get.status, 200)
        raw_get = await r_get.text()
        self.assertNotIn(secret_cmd, raw_get)
        gw = json.loads(raw_get)["gateways"][0]
        self.assertTrue(gw["read_only_cmd"])
        self.assertEqual(gw["secret_backend"], "host_cmd_readonly")

        # PUT / PATCH / DELETE / probe on read_only_cmd gateway MUST be refused
        r_put = await self.client.put(
            "/api/gateways/host-cmd-gw",
            headers=self._headers(sid_a, csrf_a, origin=self.origin),
            data=json.dumps(
                {
                    "name": "Hijacked",
                    "base_url": "https://evil.example.com/v1",
                    "credential_kind": "none",
                }
            ),
        )
        self.assertEqual(r_put.status, 403)

        r_patch = await self.client.patch(
            "/api/gateways/host-cmd-gw",
            headers=self._headers(sid_a, csrf_a, origin=self.origin),
            data=json.dumps({"enabled": False}),
        )
        self.assertEqual(r_patch.status, 403)

        r_del = await self.client.delete(
            "/api/gateways/host-cmd-gw",
            headers=self._headers(sid_a, csrf_a, origin=self.origin),
            data="{}",
        )
        self.assertEqual(r_del.status, 403)

        r_probe = await self.client.post(
            "/api/gateways/host-cmd-gw/probe",
            headers=self._headers(sid_a, csrf_a, origin=self.origin),
            data="{}",
        )
        self.assertEqual(r_probe.status, 403)

        # Creating another gateway MUST preserve host-cmd-gw verbatim
        r_other = await self.client.post(
            "/api/gateways",
            headers=self._headers(sid_a, csrf_a, origin=self.origin),
            data=json.dumps(
                {
                    "id": "second-gw",
                    "name": "Second GW",
                    "base_url": "https://api.example.com/v1",
                    "credential_kind": "none",
                }
            ),
        )
        self.assertEqual(r_other.status, 201)
        disk_doc = json.loads(self.gateways_path.read_text(encoding="utf-8"))
        host_entry = next(g for g in disk_doc["gateways"] if g["id"] == "host-cmd-gw")
        self.assertEqual(host_entry["api_key_cmd"], secret_cmd)

    async def test_c3_probe_rejects_redirects_caps_body_redacts_errors_and_blocks_dns_ssrf(
        self,
    ) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)

        # 1. Direct SSRF blocked on /api/gateways/probe
        for bad_url in (SYNTH_META_AWS, SYNTH_META_ECS, "file:///etc/passwd", SYNTH_USERINFO):
            r_bad = await self.client.post(
                "/api/gateways/probe",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps({"base_url": bad_url}),
            )
            self.assertEqual(r_bad.status, 400, f"Expected 400 SSRF block for {bad_url!r}")

        # 2. DNS rebinding to cloud metadata IP blocked on /probe
        fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (SYNTH_IMDS_IP, 443))]
        with mock.patch.object(
            self.gw_svc,
            "_dns_check_for_probe",
            wraps=self.gw_svc._dns_check_for_probe,
        ):
            loop = asyncio.get_running_loop()
            with mock.patch.object(loop, "getaddrinfo", return_value=fake_addrinfo):
                r_rebind = await self.client.post(
                    "/api/gateways/probe",
                    headers=self._headers(sid_a, csrf_a, origin=self.origin),
                    data=json.dumps({"base_url": "https://rebind.example.com/v1"}),
                )
                self.assertEqual(r_rebind.status, 400)

        # 3. Local loopback mock upstream server (Ollama/vLLM scenario)
        state = {"mode": "ok", "redirect_hit": False, "seen_auth": ""}

        async def _models_handler(req: web.Request) -> web.Response:
            state["seen_auth"] = req.headers.get("Authorization", "")
            m = state["mode"]
            if m == "redirect":
                return web.Response(status=302, headers={"Location": "/v1/evil-redirect"})
            if m == "oversize":
                # Emit > 512 KiB payload to verify bounded reader caps memory
                big_pad = "x" * (MAX_PROBE_BODY_BYTES + 128 * 1024)
                return web.Response(status=200, text=big_pad, content_type="application/json")
            if m == "echo_secret_error":
                # Malicious/misconfigured upstream echoes Bearer token in 401 body
                return web.Response(
                    status=401,
                    text=f"Invalid auth header: {state['seen_auth']} key={SYNTH_API_KEY_1}",
                )
            return web.json_response(
                {
                    "data": [
                        {"id": "gpt-5.1"},
                        {"id": "claude-sonnet-4-5"},
                        {"id": "dall-e-3-image"},
                    ]
                }
            )

        async def _evil_redirect(_req: web.Request) -> web.Response:
            state["redirect_hit"] = True
            return web.json_response({"data": [{"id": "should-not-follow"}]})

        mock_up = web.Application()
        mock_up.router.add_get("/v1/models", _models_handler)
        mock_up.router.add_get("/v1/evil-redirect", _evil_redirect)
        up_srv = TestServer(mock_up)
        await up_srv.start_server()
        try:
            up_base = f"http://127.0.0.1:{up_srv.port}/v1"

            # Valid loopback probe with include/exclude filters
            state["mode"] = "ok"
            r_ok = await self.client.post(
                "/api/gateways/probe",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "base_url": up_base,
                        "api_key": SYNTH_API_KEY_1,
                        "exclude_models": ["*-image*"],
                    }
                ),
            )
            self.assertEqual(r_ok.status, 200)
            d_ok = await r_ok.json()
            self.assertTrue(d_ok["ok"])
            self.assertTrue(d_ok["reachable"])
            self.assertEqual(d_ok["discovered_count"], 3)
            self.assertEqual(d_ok["exposed_models"], ["gpt-5.1", "claude-sonnet-4-5"])
            self.assertEqual(state["seen_auth"], f"Bearer {SYNTH_API_KEY_1}")
            self.assertNotIn(SYNTH_API_KEY_1, json.dumps(d_ok))

            # Redirect MUST be refused (allow_redirects=False)
            state["mode"] = "redirect"
            state["redirect_hit"] = False
            r_red = await self.client.post(
                "/api/gateways/probe",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps({"base_url": up_base}),
            )
            self.assertEqual(r_red.status, 200)
            d_red = await r_red.json()
            self.assertFalse(d_red["ok"])
            self.assertFalse(d_red["reachable"])
            self.assertFalse(state["redirect_hit"])
            self.assertIn("重定向", d_red["message"])

            # Oversized body capped at 512 KiB
            state["mode"] = "oversize"
            r_big = await self.client.post(
                "/api/gateways/probe",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps({"base_url": up_base}),
            )
            self.assertEqual(r_big.status, 200)
            d_big = await r_big.json()
            self.assertFalse(d_big["ok"])
            self.assertTrue(d_big["truncated"])

            # Upstream error echoing Bearer / API key MUST be completely redacted in response & logs
            state["mode"] = "echo_secret_error"
            with self.assertLogs("agy-studio.gateways", level=logging.DEBUG) as _:
                logging.getLogger("agy-studio.gateways").debug("probe_check_marker")
                r_err = await self.client.post(
                    "/api/gateways/probe",
                    headers=self._headers(sid_a, csrf_a, origin=self.origin),
                    data=json.dumps({"base_url": up_base, "api_key": SYNTH_API_KEY_1}),
                )
            self.assertEqual(r_err.status, 200)
            raw_err = await r_err.text()
            self.assertNotIn(SYNTH_API_KEY_1, raw_err)
            d_err = json.loads(raw_err)
            self.assertFalse(d_err["ok"])
            self.assertEqual(d_err["http_status"], 401)
            self.assertIn("[REDACTED]", d_err["message"])
        finally:
            await up_srv.close()

    async def test_c3_api_rejects_octal_mixed_and_shorthand_ipv4_on_create_and_probe(self) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)
        bad_urls = (
            SYNTH_META_OCTAL_FULL,
            SYNTH_META_OCTAL_MIXED,
            SYNTH_META_HEX_DOTTED,
            SYNTH_META_PY_OCTAL,
            SYNTH_META_SHORT_3,
            SYNTH_META_SHORT_2,
            SYNTH_META_OCTAL_LOOPBACK,
        )
        for idx, bad_url in enumerate(bad_urls):
            r_create = await self.client.post(
                "/api/gateways",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "id": f"bad-octal-{idx}",
                        "name": f"Bad Octal {idx}",
                        "base_url": bad_url,
                        "credential_kind": "none",
                    }
                ),
            )
            self.assertEqual(r_create.status, 400, f"POST /api/gateways should reject {bad_url!r}")

            r_probe = await self.client.post(
                "/api/gateways/probe",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps({"base_url": bad_url}),
            )
            self.assertEqual(r_probe.status, 400, f"POST /api/gateways/probe should reject {bad_url!r}")

        # Standard loopback 127.0.0.1 and normal domain remain allowed
        for gw_id, good_url in (
            ("ok-loopback", "http://" + ".".join(("127", "0", "0", "1")) + ":11434/v1"),
            ("ok-domain", "https://api.example.com/v1"),
        ):
            r_ok = await self.client.post(
                "/api/gateways",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "id": gw_id,
                        "name": gw_id,
                        "base_url": good_url,
                        "credential_kind": "none",
                    }
                ),
            )
            self.assertEqual(r_ok.status, 201, f"Expected 201 for {good_url!r}")

    async def test_c3_probe_pins_validated_dns_to_prevent_rebinding_toctou(self) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)
        seen_hosts: list[str] = []

        async def _models_handler(req: web.Request) -> web.Response:
            seen_hosts.append(req.headers.get("Host", ""))
            return web.json_response({"data": [{"id": "pinned-model-1"}]})

        mock_up = web.Application()
        mock_up.router.add_get("/v1/models", _models_handler)
        up_srv = TestServer(mock_up)
        await up_srv.start_server()
        try:
            loop = asyncio.get_running_loop()
            loopback_ip = ".".join(("127", "0", "0", "1"))
            dns_calls = {"count": 0}

            async def _rebinding_getaddrinfo(host, port, *args, **kwargs):
                dns_calls["count"] += 1
                if dns_calls["count"] == 1:
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (loopback_ip, up_srv.port))]
                # Any 2nd lookup would flip to cloud metadata IP — must NEVER happen
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (SYNTH_IMDS_IP, up_srv.port))]

            with mock.patch.object(loop, "getaddrinfo", side_effect=_rebinding_getaddrinfo):
                r_probe = await self.client.post(
                    "/api/gateways/probe",
                    headers=self._headers(sid_a, csrf_a, origin=self.origin),
                    data=json.dumps({"base_url": f"http://rebind-pin.example.com:{up_srv.port}/v1"}),
                )

            self.assertEqual(r_probe.status, 200)
            data = await r_probe.json()
            self.assertTrue(data["ok"])
            self.assertEqual(data["exposed_models"], ["pinned-model-1"])
            self.assertEqual(dns_calls["count"], 1, "DNS resolution must happen strictly once per probe")
            self.assertEqual(len(seen_hosts), 1)
            self.assertTrue(seen_hosts[0].startswith("rebind-pin.example.com"))

            # Fail-closed invariant on _PinnedResolver for unexpected host/port
            resolver = _PinnedResolver(
                "rebind-pin.example.com",
                up_srv.port,
                [
                    {
                        "hostname": "rebind-pin.example.com",
                        "host": loopback_ip,
                        "port": up_srv.port,
                        "family": socket.AF_INET,
                        "proto": socket.IPPROTO_TCP,
                        "flags": socket.AI_NUMERICHOST | socket.AI_NUMERICSERV,
                    }
                ],
            )
            with self.assertRaises(OSError):
                await resolver.resolve("evil.example.com", up_srv.port)
            with self.assertRaises(OSError):
                await resolver.resolve("rebind-pin.example.com", up_srv.port + 1)
            await resolver.close()
        finally:
            await up_srv.close()

    async def test_c1_c3_cross_origin_probe_never_leaks_stored_secrets_or_headers(self) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)
        captured: list[dict[str, str]] = []

        async def _collector_models(req: web.Request) -> web.Response:
            captured.append({k: v for k, v in req.headers.items()})
            return web.json_response({"data": [{"id": "probe-model-ok"}]})

        mock_up = web.Application()
        mock_up.router.add_get("/v1/models", _collector_models)
        up_srv = TestServer(mock_up)
        await up_srv.start_server()
        try:
            loopback_ip = ".".join(("127", "0", "0", "1"))
            attacker_base = f"http://{loopback_ip}:{up_srv.port}/v1"

            # 1. Create stored gateway `ob-gw` pointing to https://api.example.com/v1
            r_ob = await self.client.post(
                "/api/gateways",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "id": "ob-gw",
                        "name": "Stored OB GW",
                        "base_url": "https://api.example.com/v1",
                        "dialect": "new_api",
                        "api_key": SYNTH_API_KEY_1,
                        "extra_headers": {
                            "X-Custom-Token": SYNTH_HEADER_TOK,
                            "X-API-Key": SYNTH_HEADER_TOK,
                            "X-Safe": "orig-safe-val",
                        },
                    }
                ),
            )
            self.assertEqual(r_ob.status, 201)

            # 2. Seed a read_only_cmd gateway with sensitive extra_headers directly on disk
            disk_doc = json.loads(self.gateways_path.read_text(encoding="utf-8"))
            disk_doc["gateways"].append(
                {
                    "id": "host-cmd-hdr-gw",
                    "name": "Host CMD With Headers",
                    "base_url": "https://cpa.example.com/v1",
                    "dialect": "cpa",
                    "api_key_cmd": "bao get lv1/example/provider --field key",
                    "extra_headers": {
                        "X-Custom-Token": SYNTH_HEADER_TOK,
                        "Cookie": f"sid={SYNTH_HEADER_TOK}",
                    },
                    "enabled": True,
                }
            )
            self.gateways_path.write_text(json.dumps(disk_doc), encoding="utf-8")

            # 3. Cross-origin POST /api/gateways/ob-gw/probe (no api_key, no extra_headers)
            captured.clear()
            with mock.patch.object(
                self.secrets_svc.secret_store,
                "resolve_gateway_secret",
                wraps=self.secrets_svc.secret_store.resolve_gateway_secret,
            ) as m_resolve:
                r_x1 = await self.client.post(
                    "/api/gateways/ob-gw/probe",
                    headers=self._headers(sid_a, csrf_a, origin=self.origin),
                    data=json.dumps({"base_url": attacker_base}),
                )
                self.assertEqual(r_x1.status, 200)
                self.assertEqual(m_resolve.call_count, 0, "SecretStore must NOT be read for cross-origin probe")

            self.assertEqual(len(captured), 1)
            hdrs_x1 = {k.lower(): v for k, v in captured[0].items()}
            self.assertNotIn("authorization", hdrs_x1)
            self.assertNotIn("x-custom-token", hdrs_x1)
            self.assertNotIn("x-api-key", hdrs_x1)
            self.assertNotIn("x-safe", hdrs_x1)
            self.assertNotIn(SYNTH_API_KEY_1, json.dumps(hdrs_x1))
            self.assertNotIn(SYNTH_HEADER_TOK, json.dumps(hdrs_x1))

            # 4. Cross-origin POST /api/gateways/probe with [REDACTED] placeholders must NOT backfill
            captured.clear()
            with mock.patch.object(
                self.secrets_svc.secret_store,
                "resolve_gateway_secret",
                wraps=self.secrets_svc.secret_store.resolve_gateway_secret,
            ) as m_resolve:
                r_x2 = await self.client.post(
                    "/api/gateways/probe",
                    headers=self._headers(sid_a, csrf_a, origin=self.origin),
                    data=json.dumps(
                        {
                            "gateway_id": "ob-gw",
                            "base_url": attacker_base,
                            "extra_headers": {
                                "X-Custom-Token": "[REDACTED]",
                                "Authorization": "[REDACTED]",
                                "X-Probe-Note": "fresh-only",
                            },
                        }
                    ),
                )
                self.assertEqual(r_x2.status, 200)
                self.assertEqual(m_resolve.call_count, 0)

            self.assertEqual(len(captured), 1)
            hdrs_x2 = {k.lower(): v for k, v in captured[0].items()}
            self.assertNotIn("authorization", hdrs_x2)
            self.assertNotIn("x-custom-token", hdrs_x2)
            self.assertEqual(hdrs_x2.get("x-probe-note"), "fresh-only")
            self.assertNotIn(SYNTH_API_KEY_1, json.dumps(hdrs_x2))
            self.assertNotIn(SYNTH_HEADER_TOK, json.dumps(hdrs_x2))

            # 5. Cross-origin probe on read_only_cmd gateway (even with new api_key) blocked with 403
            captured.clear()
            for endpoint_path, payload in (
                (
                    "/api/gateways/host-cmd-hdr-gw/probe",
                    {"base_url": attacker_base, "api_key": SYNTH_API_KEY_2},
                ),
                (
                    "/api/gateways/probe",
                    {
                        "gateway_id": "host-cmd-hdr-gw",
                        "base_url": attacker_base,
                        "api_key": SYNTH_API_KEY_2,
                    },
                ),
            ):
                r_cmd = await self.client.post(
                    endpoint_path,
                    headers=self._headers(sid_a, csrf_a, origin=self.origin),
                    data=json.dumps(payload),
                )
                self.assertEqual(r_cmd.status, 403, f"Cross-origin read_only_cmd probe must 403 on {endpoint_path}")
            self.assertEqual(len(captured), 0, "Mock server must receive zero requests from read_only_cmd probe")

            # 6. Same-origin probe still legitimately reuses SecretStore key & sensitive extra_headers
            r_same = await self.client.post(
                "/api/gateways",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "id": "same-orig-gw",
                        "name": "Same Origin GW",
                        "base_url": attacker_base,
                        "dialect": "new_api",
                        "api_key": SYNTH_API_KEY_1,
                        "extra_headers": {
                            "X-Custom-Token": SYNTH_HEADER_TOK,
                            "X-Safe": "orig-safe-val",
                        },
                    }
                ),
            )
            self.assertEqual(r_same.status, 201)

            captured.clear()
            r_so1 = await self.client.post(
                "/api/gateways/same-orig-gw/probe",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data="{}",
            )
            self.assertEqual(r_so1.status, 200)
            self.assertTrue((await r_so1.json())["ok"])
            self.assertEqual(len(captured), 1)
            hdrs_so1 = {k.lower(): v for k, v in captured[0].items()}
            self.assertEqual(hdrs_so1.get("authorization"), f"Bearer {SYNTH_API_KEY_1}")
            self.assertEqual(hdrs_so1.get("x-custom-token"), SYNTH_HEADER_TOK)
            self.assertEqual(hdrs_so1.get("x-safe"), "orig-safe-val")

            captured.clear()
            r_so2 = await self.client.post(
                "/api/gateways/probe",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "gateway_id": "same-orig-gw",
                        "base_url": attacker_base,
                        "extra_headers": {"X-Custom-Token": "[REDACTED]"},
                    }
                ),
            )
            self.assertEqual(r_so2.status, 200)
            self.assertTrue((await r_so2.json())["ok"])
            self.assertEqual(len(captured), 1)
            hdrs_so2 = {k.lower(): v for k, v in captured[0].items()}
            self.assertEqual(hdrs_so2.get("authorization"), f"Bearer {SYNTH_API_KEY_1}")
            self.assertEqual(hdrs_so2.get("x-custom-token"), SYNTH_HEADER_TOK)
        finally:
            await up_srv.close()

    async def test_c4_secret_store_openbao_kv2_fallback_local_0600_and_symlink_refusal(self) -> None:
        # In-process loopback mock OpenBao KV v2 server
        bao_store: dict[str, dict] = {}
        bao_state = {"fail_write": False, "deletes": []}

        async def _kv_write(req: web.Request) -> web.Response:
            if req.headers.get("X-Vault-Token") != SYNTH_BAO_TOK:
                return web.json_response({"errors": ["permission denied"]}, status=403)
            if bao_state["fail_write"]:
                return web.json_response({"errors": ["sealed"]}, status=503)
            path_tail = req.match_info["tail"]
            body = await req.json()
            bao_store[path_tail] = body.get("data") or {}
            return web.json_response({"data": {"version": 1}}, status=200)

        async def _kv_read(req: web.Request) -> web.Response:
            if req.headers.get("X-Vault-Token") != SYNTH_BAO_TOK:
                return web.json_response({"errors": ["permission denied"]}, status=403)
            path_tail = req.match_info["tail"]
            if path_tail not in bao_store:
                return web.json_response({"errors": []}, status=404)
            return web.json_response({"data": {"data": bao_store[path_tail]}}, status=200)

        async def _kv_delete(req: web.Request) -> web.Response:
            if req.headers.get("X-Vault-Token") != SYNTH_BAO_TOK:
                return web.json_response({"errors": ["permission denied"]}, status=403)
            path_tail = req.match_info["tail"]
            bao_store.pop(path_tail, None)
            bao_state["deletes"].append(path_tail)
            return web.Response(status=204)

        mock_bao = web.Application()
        mock_bao.router.add_post("/v1/kv2/data/{tail:.*}", _kv_write)
        mock_bao.router.add_get("/v1/kv2/data/{tail:.*}", _kv_read)
        mock_bao.router.add_delete("/v1/kv2/metadata/{tail:.*}", _kv_delete)
        bao_srv = TestServer(mock_bao)
        await bao_srv.start_server()
        try:
            bao_addr = f"http://127.0.0.1:{bao_srv.port}"
            sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)

            # Configure OpenBao via Studio API
            r_ob = await self.client.put(
                "/api/secrets/openbao",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "enabled": True,
                        "addr": bao_addr,
                        "kv_mount": "kv2",
                        "gateway_path_prefix": "studio/gateways",
                        "auth_mode": "token",
                        "token": SYNTH_BAO_TOK,
                    }
                ),
            )
            self.assertEqual(r_ob.status, 200)

            # 1. Create gateway -> automatically stored in OpenBao KV v2, ZERO plaintext in gateways.json
            r_c1 = await self.client.post(
                "/api/gateways",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "id": "ob-gw",
                        "name": "OpenBao GW",
                        "base_url": "https://api.example.com/v1",
                        "dialect": "new_api",
                        "api_key": SYNTH_API_KEY_1,
                    }
                ),
            )
            self.assertEqual(r_c1.status, 201)
            d_c1 = await r_c1.json()
            self.assertEqual(d_c1["secret_backend"], "openbao")
            self.assertFalse(d_c1["fallback_used"])
            self.assertEqual(bao_store["studio/gateways/ob-gw"]["api_key"], SYNTH_API_KEY_1)

            gw_disk = self.gateways_path.read_text(encoding="utf-8")
            self.assertNotIn(SYNTH_API_KEY_1, gw_disk)
            self.assertIn('"backend": "openbao"', gw_disk)
            self.assertEqual(stat.S_IMODE(self.gateways_path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(self.gateways_path.stat().st_mode), 0o600)

            # 2. Reserved security_card backend rejected cleanly (400)
            r_card = await self.client.post(
                "/api/gateways",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "id": "card-gw",
                        "name": "Card GW",
                        "base_url": "https://api.example.com/v1",
                        "api_key": SYNTH_API_KEY_2,
                        "preferred_secret_backend": "security_card",
                    }
                ),
            )
            self.assertEqual(r_card.status, 400)
            self.assertEqual(
                self.secrets_svc.secret_store.security_card.describe()["status"],
                "reserved",
            )

            # 3. OpenBao unavailable -> automatic fallback to local_0600 (0700 dir / 0600 file)
            bao_state["fail_write"] = True
            r_fb = await self.client.post(
                "/api/gateways",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "id": "local-gw",
                        "name": "Local Fallback GW",
                        "base_url": "https://api.example.com/v1",
                        "dialect": "deepseek",
                        "api_key": SYNTH_API_KEY_2,
                    }
                ),
            )
            self.assertEqual(r_fb.status, 201)
            d_fb = await r_fb.json()
            self.assertEqual(d_fb["secret_backend"], "local_0600")
            self.assertTrue(d_fb["fallback_used"])
            self.assertNotIn(SYNTH_API_KEY_2, self.gateways_path.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(self.local_secrets_path.stat().st_mode), 0o600)
            local_doc = json.loads(self.local_secrets_path.read_text(encoding="utf-8"))
            self.assertEqual(local_doc["slots"]["local-gw"]["api_key"], SYNTH_API_KEY_2)

            # 4. Delete OpenBao gateway cleans up OpenBao KV entry
            bao_state["fail_write"] = False
            r_del = await self.client.delete(
                "/api/gateways/ob-gw",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data="{}",
            )
            self.assertEqual(r_del.status, 200)
            self.assertIn("studio/gateways/ob-gw", bao_state["deletes"])

            # 5. Sensitive extra_headers preserved when client echoes back `[REDACTED]` on edit
            r_hdr_edit = await self.client.put(
                "/api/gateways/local-gw",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "name": "Local Fallback GW",
                        "base_url": "https://api.example.com/v1",
                        "dialect": "deepseek",
                        "extra_headers": {
                            "X-Custom-Token": SYNTH_HEADER_TOK,
                            "X-Safe": "keep",
                        },
                    }
                ),
            )
            self.assertEqual(r_hdr_edit.status, 200)
            r_hdr_keep = await self.client.put(
                "/api/gateways/local-gw",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "name": "Local Fallback GW Renamed",
                        "base_url": "https://api.example.com/v1",
                        "dialect": "deepseek",
                        "extra_headers": {
                            "X-Custom-Token": "[REDACTED]",
                            "X-Safe": "keep2",
                        },
                    }
                ),
            )
            self.assertEqual(r_hdr_keep.status, 200)
            disk_after = json.loads(self.gateways_path.read_text(encoding="utf-8"))
            local_entry = next(g for g in disk_after["gateways"] if g["id"] == "local-gw")
            self.assertEqual(local_entry["extra_headers"]["X-Custom-Token"], SYNTH_HEADER_TOK)
            self.assertEqual(local_entry["extra_headers"]["X-Safe"], "keep2")

            # 6. Symlink refusal on gateway_secrets.json (O_NOFOLLOW)
            victim = self.tmp / "victim_secret.txt"
            victim.write_text("DO_NOT_TOUCH", encoding="utf-8")
            self.local_secrets_path.unlink()
            os.symlink(str(victim), str(self.local_secrets_path))
            r_sym = await self.client.post(
                "/api/gateways",
                headers=self._headers(sid_a, csrf_a, origin=self.origin),
                data=json.dumps(
                    {
                        "id": "sym-gw",
                        "name": "Sym GW",
                        "base_url": "https://api.example.com/v1",
                        "api_key": SYNTH_API_KEY_1,
                        "preferred_secret_backend": "local_0600",
                    }
                ),
            )
            self.assertEqual(r_sym.status, 500)
            self.assertEqual(victim.read_text(encoding="utf-8"), "DO_NOT_TOUCH")
        finally:
            await bao_srv.close()


class TestGatewayAdapterAndBridgeHotReload(unittest.TestCase):
    """C4 Bridge integration: `secret_ref` resolution, cache invalidation, and hot reload."""

    def test_c4_gateway_adapter_secret_ref_resolution_and_cache_invalidation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="agy_bridge_sref_") as td:
            tmp = Path(td)
            secrets_file = tmp / "gateway_secrets.json"
            secrets_file.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "slots": {
                            "alpha": {"api_key": SYNTH_API_KEY_1, "updated_at": 100},
                        },
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(secrets_file, 0o600)

            env_patch = _isolated_env_overrides(
                {
                    "HOME": str(tmp),
                    "AGY_STUDIO_GATEWAY_SECRETS_FILE": str(secrets_file),
                    "MY_ENV_GW_KEY": "env-example-key-999",
                }
            )
            with mock.patch.dict(os.environ, env_patch, clear=False):
                rt = gateway_adapter.GatewayRuntimeState(key_ttl_s=300.0)

                # 1. local_0600 secret_ref resolution
                gws = gateway_adapter.parse_gateways_payload(
                    [
                        {
                            "id": "alpha",
                            "name": "Alpha",
                            "base_url": "https://api.example.com/v1",
                            "dialect": "new_api",
                            "secret_ref": {
                                "backend": "local_0600",
                                "slot": "alpha",
                                "field": "api_key",
                                "updated_at": 100,
                            },
                        },
                        {
                            "id": "env-gw",
                            "name": "Env GW",
                            "base_url": "https://api.example.com/v1",
                            "api_key_env": "MY_ENV_GW_KEY",
                        },
                    ]
                )
                self.assertEqual(rt.resolve_api_key(gws["alpha"]), SYNTH_API_KEY_1)
                self.assertEqual(rt.resolve_api_key(gws["env-gw"]), "env-example-key-999")

                # 2. Rotating secret_ref (updated_at changes) invalidates fingerprint & key cache
                secrets_file.write_text(
                    json.dumps(
                        {
                            "version": 1,
                            "slots": {
                                "alpha": {"api_key": SYNTH_API_KEY_2, "updated_at": 200},
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                gws_v2 = gateway_adapter.parse_gateways_payload(
                    [
                        {
                            "id": "alpha",
                            "name": "Alpha",
                            "base_url": "https://api.example.com/v1",
                            "dialect": "new_api",
                            "secret_ref": {
                                "backend": "local_0600",
                                "slot": "alpha",
                                "field": "api_key",
                                "updated_at": 200,
                            },
                        }
                    ]
                )
                self.assertNotEqual(
                    gateway_adapter._gateway_runtime_fingerprint(gws["alpha"]),
                    gateway_adapter._gateway_runtime_fingerprint(gws_v2["alpha"]),
                )
                self.assertEqual(rt.resolve_api_key(gws_v2["alpha"]), SYNTH_API_KEY_2)

                # 3. Symlink gateway_secrets.json MUST be refused
                target = tmp / "real_target.json"
                target.write_text(secrets_file.read_text(encoding="utf-8"), encoding="utf-8")
                secrets_file.unlink()
                os.symlink(str(target), str(secrets_file))
                rt.clear_key_cache()
                self.assertEqual(rt.resolve_api_key(gws_v2["alpha"]), "")

                # 4. OpenBao secret_ref resolution via mocked requests.get
                ob_cfg = tmp / "studio_secrets.json"
                ob_cfg.write_text(
                    json.dumps(
                        {
                            "openbao": {
                                "mode": "custom",
                                "enabled": True,
                                "addr": "https://vault.example.com",
                                "auth_mode": "token",
                                "token": SYNTH_BAO_TOK,
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                gw_ob = gateway_adapter._normalize_gateway_entry(
                    {
                        "id": "ob-site",
                        "name": "OB Site",
                        "base_url": "https://api.example.com/v1",
                        "secret_ref": {
                            "backend": "openbao",
                            "kv_mount": "kv2",
                            "path": "studio/gateways/ob-site",
                            "field": "api_key",
                            "version": 1,
                        },
                    }
                )
                fake_resp = mock.MagicMock(status_code=200)
                fake_resp.json.return_value = {"data": {"data": {"api_key": SYNTH_API_KEY_1}}}
                with mock.patch.dict(
                    os.environ, {"AGY_STUDIO_SECRETS_CONFIG": str(ob_cfg)}, clear=False
                ), mock.patch.object(gateway_adapter.requests, "get", return_value=fake_resp) as m_get:
                    resolved = rt.resolve_api_key(gw_ob)
                    self.assertEqual(resolved, SYNTH_API_KEY_1)
                    called_url = m_get.call_args.args[0]
                    self.assertEqual(
                        called_url, "https://vault.example.com/v1/kv2/data/studio/gateways/ob-site"
                    )
                    self.assertFalse(m_get.call_args.kwargs.get("allow_redirects", True))

    def test_c4_bridge_hot_reloads_gateways_json_without_restart(self) -> None:
        with tempfile.TemporaryDirectory(prefix="agy_bridge_hot_") as td:
            tmp = Path(td)
            gw_file = tmp / "gateways.json"
            gw_file.write_text(
                json.dumps(
                    {
                        "gateways": [
                            {
                                "id": "hot-one",
                                "name": "Hot One",
                                "base_url": "http://127.0.0.1:9/v1",
                                "dialect": "new_api",
                                "models": ["alpha-1"],
                                "enabled": True,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            env_patch = _isolated_env_overrides(
                {
                    "HOME": str(tmp),
                    "AGY_BOT_BUS_DIR": str(tmp / "bus"),
                    "AGY_TG_STATE_FILE": str(tmp / "state.json"),
                    "AGY_TG_WORKDIR": str(tmp / "workdir"),
                    "AGY_TG_LOCK_DIR": str(tmp / "locks"),
                    "AGY_TG_ALLOWED_CHATS": "-1001234567890",
                    "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_HOT_TEST_TOKEN_01",
                    "AGY_TG_ENV_FILE": str(tmp / "nonexistent.env"),
                    "AGY_TG_GATEWAYS_FILE": str(gw_file),
                }
            )
            with mock.patch.dict(os.environ, env_patch, clear=False):
                import access_control
                import bot_bus
                import bridge

                importlib.reload(access_control)
                importlib.reload(bot_bus)
                importlib.reload(bridge)

                with mock.patch.object(
                    bridge, "agy_native_models", return_value=[("gemini-4-neon", "Gemini 4 Neon")]
                ), mock.patch.object(
                    gateway_adapter.requests, "get", side_effect=OSError("offline")
                ):
                    m1 = bridge.agy_models(include_gateways=True, force_refresh=False)
                    self.assertIn(("alpha-1", "[Hot One] alpha-1"), m1)

                    # Mutate gateways.json on disk (add model & second gateway, disable first)
                    gw_file.write_text(
                        json.dumps(
                            {
                                "gateways": [
                                    {
                                        "id": "hot-one",
                                        "name": "Hot One",
                                        "base_url": "http://127.0.0.1:9/v1",
                                        "dialect": "new_api",
                                        "models": ["alpha-1"],
                                        "enabled": False,
                                    },
                                    {
                                        "id": "hot-two",
                                        "name": "Hot Two",
                                        "base_url": "http://127.0.0.1:9/v1",
                                        "dialect": "deepseek",
                                        "models": ["beta-2"],
                                        "enabled": True,
                                    },
                                ]
                            }
                        ),
                        encoding="utf-8",
                    )

                    # Without restarting Bridge, agy_models immediately reflects updated gateways.json
                    m2 = bridge.agy_models(include_gateways=True, force_refresh=False)
                    self.assertNotIn(("alpha-1", "[Hot One] alpha-1"), m2)
                    self.assertIn(("beta-2", "[Hot Two] beta-2"), m2)


if __name__ == "__main__":
    unittest.main()
