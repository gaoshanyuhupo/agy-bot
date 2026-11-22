#!/usr/bin/env python3
"""Milestone 2 Offline Contract Tests — AGY Studio Multi-Google-Account API & Multi-Plan Costs.

Covers Pre-Flight Contracts C1, C2, C5, C6, C7, C8:
- C1: Four-layer Studio write gate (Origin, Sec-Fetch-Site, Content-Type 415, <=32 KiB 413,
      Auth 401, must_change_password 403, X-Studio-CSRF 403, readonly RBAC 403),
      per-session OAuth flow isolation (admin B -> 403, zero auth_url/state leak),
      anti-symlink 0600 JSONL audit log with zero secret/path leakage, and strictly
      desensitized GET /api/google-accounts & GET /api/costs payloads.
- C2: Session logout (`/api/auth/logout`) and `app.on_cleanup` automatically terminate
      and reap active headless OAuth subprocesses (0 orphan processes); wrong state -> 400;
      replay submit -> 409.
- C5: Account activation triggers Bridge UDS IPC `/ipc/accounts/recycle` (with graceful
      degradation when offline sockets exist, never rolling back switch) + SSE `accounts_updated`.
- C6: Per-account PATCH weekly reset UTC anchor preserves global default; `GET /api/costs`
      is 100% backward-compatible with legacy ledgers/configs and filters cleanly by
      `account_id` and `plan_tier` with `by_account_month`, `by_plan_month`, `accounts_quota`.
- 100% offline (`TemporaryDirectory` + mocked subprocess/HTTP + cleared AGY_* env vars).
"""

from __future__ import annotations

import datetime
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
import unittest

from aiohttp.test_utils import TestClient, TestServer

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import cost_usage  # noqa: E402
import google_accounts as ga  # noqa: E402
import studio_ipc  # noqa: E402
from studio.auth import (  # noqa: E402
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.data_sources import StudioDataSources  # noqa: E402
from studio.google_accounts_service import StudioGoogleAccountsService  # noqa: E402
from studio.server import EVENT_HUB_KEY, GOOGLE_ACCOUNTS_KEY, create_app  # noqa: E402


BOT_TOKEN_TEST = "123456789:" + "EXAMPLE_M2_GA_TOKEN_0001"
ADMIN_UID_A = 111111111
ADMIN_UID_B = ADMIN_UID_A + 1
READONLY_UID = 222222222
PASS_ADMIN_A = "EXAMPLE_ADMIN_A_PASS_M2"
PASS_ADMIN_B = "EXAMPLE_ADMIN_B_PASS_M2"
PASS_RO = "EXAMPLE_RO_PASS_M2"
PASS_FORCE = "EXAMPLE_FORCE_PASS_M2"

SYNTH_ACCESS_A = "ya29." + "SYNTH_TEST_ACC_ALPHA_999"
SYNTH_REFRESH_A = "1//" + "SYNTH_TEST_REF_ALPHA_999"
SYNTH_ACCESS_B = "ya29." + "SYNTH_TEST_ACC_BETA_888"
SYNTH_REFRESH_B = "1//" + "SYNTH_TEST_REF_BETA_888"
SYNTH_OAUTH_STATE = "synth_pkce_state_tok_777"
SYNTH_OAUTH_CODE = "4/0SynthTestAuthCodeValue1234567890"


def _write_env(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _make_token_bytes(access: str, refresh: str, email: str) -> bytes:
    future_iso = (
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {
        "auth_method": "oauth-personal",
        "id_token_email": email,
        "token": {
            "access_token": access,
            "refresh_token": refresh,
            "expiry": future_iso,
        },
    }
    return json.dumps(doc).encode("utf-8")


class _FakeOAuthStdin:
    def __init__(self, on_write) -> None:
        self._on_write = on_write
        self.written: list[str] = []
        self.closed = False

    def write(self, data: str) -> int:
        self.written.append(data)
        self._on_write(data)
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class _FakeOAuthProc:
    """Offline mock of `agy acp --login` subprocess with process-group termination tracking."""

    def __init__(
        self,
        *,
        auth_url: str,
        token_path: Path,
        token_bytes: bytes,
    ) -> None:
        self.pid = -1  # Prevent os.killpg from targeting any real host PID
        self.stdout = io.StringIO(f"Open the following URL to sign in:\n{auth_url}\n")
        self.stderr = io.StringIO("")
        self._token_path = token_path
        self._token_bytes = token_bytes
        self._done_ev = threading.Event()
        self._rc: int | None = None
        self.terminated = False
        self.killed = False
        self.stdin = _FakeOAuthStdin(self._handle_stdin)

    def _handle_stdin(self, data: str) -> None:
        if data.strip():
            self._token_path.parent.mkdir(parents=True, exist_ok=True)
            self._token_path.write_bytes(self._token_bytes)
            os.chmod(self._token_path, 0o600)
            self._rc = 0
            self._done_ev.set()

    def poll(self) -> int | None:
        return self._rc

    def wait(self, timeout: float | None = None) -> int:
        if self._done_ev.wait(timeout=timeout):
            return 0 if self._rc is None else self._rc
        raise TimeoutError("fake proc wait timed out")

    def terminate(self) -> None:
        self.terminated = True
        if self._rc is None:
            self._rc = -15
        self._done_ev.set()

    def kill(self) -> None:
        self.killed = True
        if self._rc is None:
            self._rc = -9
        self._done_ev.set()


class TestStudioGoogleAccountsM2(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        # Explicitly scrub ambient AGY_* environment variables to guarantee zero host bleed
        self._env_backup = dict(os.environ)
        for k in list(os.environ.keys()):
            if k.startswith(("AGY_TG_BOT_", "AGY_STUDIO_", "AGY_GOOGLE_ACCOUNTS_", "AGY_HOST_OAUTH_")):
                os.environ.pop(k, None)

        self._td = tempfile.TemporaryDirectory(prefix="agy_m2_studio_ga_")
        self.tmp = Path(self._td.name)
        self.config_dir = self.tmp / "studio-config"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bot_bus"
        self.accounts_dir = self.tmp / "accounts"
        self.host_token_path = self.tmp / "host-gemini" / "antigravity-oauth-token"
        self.cost_ledger_file = self.tmp / "cache" / "cost_ledger_v2.json"
        self.cost_config_file = self.tmp / "cache" / "cost_config.json"
        self.quota_cache_file = self.tmp / "cache" / "quota_usage.json"
        self.audit_log_path = self.config_dir / "google_accounts_audit.jsonl"

        for d in (
            self.config_dir,
            self.bridge_dir,
            self.bus_dir / "ipc",
            self.bus_dir / "jobs",
            self.host_token_path.parent,
            self.cost_ledger_file.parent,
        ):
            d.mkdir(parents=True, exist_ok=True)

        _write_env(
            self.bridge_dir / ".env",
            [
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_TEST}",
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID_A},{ADMIN_UID_B},{READONLY_UID}",
                f"AGY_TG_ADMIN_USERS={ADMIN_UID_A},{ADMIN_UID_B}",
                f"AGY_TG_READONLY_USERS={READONLY_UID}",
            ],
        )

        now_i = int(time.time())
        users_map = {
            "admin_a": {
                "username": "admin_a",
                "password_hash": hash_password_scrypt(PASS_ADMIN_A),
                "role": "admin",
                "bot": "main",
                "user_id": ADMIN_UID_A,
                "enabled": True,
                "must_change_password": False,
                "password_version": 1,
                "created_at": now_i,
                "updated_at": now_i,
            },
            "admin_b": {
                "username": "admin_b",
                "password_hash": hash_password_scrypt(PASS_ADMIN_B),
                "role": "admin",
                "bot": "main",
                "user_id": ADMIN_UID_B,
                "enabled": True,
                "must_change_password": False,
                "password_version": 1,
                "created_at": now_i,
                "updated_at": now_i,
            },
            "ro_user": {
                "username": "ro_user",
                "password_hash": hash_password_scrypt(PASS_RO),
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
                "password_hash": hash_password_scrypt(PASS_FORCE),
                "role": "admin",
                "bot": "main",
                "user_id": ADMIN_UID_A,
                "enabled": True,
                "must_change_password": True,
                "password_version": 1,
                "created_at": now_i,
                "updated_at": now_i,
            },
        }
        save_users_file_atomic(self.config_dir / "users.json", users_map)

        # Seed initial host token for automatic primary adoption
        self.host_token_path.write_bytes(
            _make_token_bytes(SYNTH_ACCESS_A, SYNTH_REFRESH_A, "alice.alpha@example.com")
        )
        os.chmod(self.host_token_path, 0o600)

        self.spawned_procs: list[_FakeOAuthProc] = []
        self.recycle_calls: list[dict] = []

        def _fake_http(method: str, url: str, *, access_token: str, json_body=None, timeout_sec=10.0):
            is_beta = access_token == SYNTH_ACCESS_B
            if "userinfo" in url:
                return {
                    "id": "uid-beta-002" if is_beta else "uid-alpha-001",
                    "email": "bob.beta@example.com" if is_beta else "alice.alpha@example.com",
                }
            if "loadCodeAssist" in url:
                return {
                    "paidTier": {"id": "google-ai-pro" if is_beta else "google-ai-ultra"},
                    "currentTier": {"id": "pro" if is_beta else "ultra"},
                    "cloudaicompanionProject": "proj-demo",
                }
            if "retrieveUserQuotaSummary" in url:
                rst_5h = (
                    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=3)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                rst_wk = (
                    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=4)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                return {
                    "groups": [
                        {
                            "displayName": "Gemini",
                            "buckets": [
                                {
                                    "bucketId": "gemini-5h",
                                    "window": "5h",
                                    "remainingFraction": 0.9 if is_beta else 0.7,
                                    "resetTime": rst_5h,
                                },
                                {
                                    "bucketId": "gemini-weekly",
                                    "window": "weekly",
                                    "remainingFraction": 0.85 if is_beta else 0.65,
                                    "resetTime": rst_wk,
                                },
                            ],
                        },
                        {
                            "displayName": "Claude & GPT",
                            "buckets": [
                                {
                                    "bucketId": "3p-5h",
                                    "window": "5h",
                                    "remainingFraction": 0.95 if is_beta else 0.4,
                                    "resetTime": rst_5h,
                                },
                                {
                                    "bucketId": "3p-weekly",
                                    "window": "weekly",
                                    "remainingFraction": 0.92 if is_beta else 0.35,
                                    "resetTime": rst_wk,
                                },
                            ],
                        },
                    ]
                }
            return {}

        def _fake_popen(cmd, **kwargs):
            # Locate --gemini-dir argument
            gdir = Path(cmd[cmd.index("--gemini-dir") + 1])
            tpath = gdir / "antigravity-acp" / "antigravity-oauth-token"
            auth_url = (
                "https://accounts.google.com/o/oauth2/auth"
                f"?client_id=test&redirect_uri=https%3A%2F%2Fantigravity.google%2Foauth-callback"
                f"&response_type=code&state={SYNTH_OAUTH_STATE}"
            )
            proc = _FakeOAuthProc(
                auth_url=auth_url,
                token_path=tpath,
                token_bytes=_make_token_bytes(SYNTH_ACCESS_B, SYNTH_REFRESH_B, "bob.beta@example.com"),
            )
            self.spawned_procs.append(proc)
            return proc

        async def _fake_recycle(*, account_id: str, sess: dict, reason: str):
            self.recycle_calls.append({
                "account_id": account_id,
                "username": sess.get("username"),
                "reason": reason,
            })
            return [{"handle": "mock_bot", "ok": True, "status": 200, "recycled": True}]

        self.auth_mgr = StudioAuthManager(
            config_dir=self.config_dir,
            bridge_dir=self.bridge_dir,
            auth_mode="password",
            public_url="",
        )
        self.data_sources = StudioDataSources(
            bus_dir=self.bus_dir,
            cost_ledger_file=self.cost_ledger_file,
            cost_config_file=self.cost_config_file,
            quota_cache_file=self.quota_cache_file,
            google_accounts_dir=self.accounts_dir,
        )
        self.ga_mgr = ga.GoogleAccountManager(
            root_dir=self.accounts_dir,
            host_token_path=self.host_token_path,
            quota_cache_file=self.quota_cache_file,
            cost_config_file=self.cost_config_file,
            http_request_fn=_fake_http,
            popen_fn=_fake_popen,
            auto_adopt_host=True,
        )
        self.login_flows = ga.GoogleLoginFlowManager(
            self.ga_mgr,
            popen_fn=_fake_popen,
            auto_probe_on_login=True,
        )
        self.ga_service = StudioGoogleAccountsService(
            self.auth_mgr,
            self.data_sources,
            event_hub=None,  # wired after app creation below
            audit_log_path=self.audit_log_path,
            recycle_callback=_fake_recycle,
            account_manager=self.ga_mgr,
            login_flow_manager=self.login_flows,
        )
        self.app = create_app(
            auth_mgr=self.auth_mgr,
            data_sources=self.data_sources,
            audit_log_path=self.config_dir / "studio_audit.jsonl",
            event_watcher_interval=0.0,
            google_accounts_service=self.ga_service,
        )
        self.ga_service.event_hub = self.app[EVENT_HUB_KEY]
        self.server = TestServer(self.app)
        self.client = TestClient(self.server)
        await self.client.start_server()
        self.origin = f"http://{self.server.host}:{self.server.port}"

    async def asyncTearDown(self) -> None:
        try:
            await self.client.close()
        finally:
            self._td.cleanup()
            os.environ.clear()
            os.environ.update(self._env_backup)

    async def _login_client(self, username: str, password: str) -> tuple[TestClient, str]:
        cli = TestClient(self.server)
        await cli.start_server()
        resp = await cli.post(
            "/api/auth/login",
            headers={"Origin": self.origin, "Content-Type": "application/json"},
            json={"username": username, "password": password},
        )
        self.assertEqual(resp.status, 200, await resp.text())
        data = await resp.json()
        return cli, str(data["csrf_token"])

    def _write_headers(self, csrf: str, **overrides: str) -> dict[str, str]:
        hdrs = {
            "Origin": self.origin,
            "Sec-Fetch-Site": "same-origin",
            "Content-Type": "application/json",
            "X-Studio-CSRF": csrf,
        }
        hdrs.update(overrides)
        return hdrs

    # ------------------------------------------------------------------ C1: Write Gate Matrix
    async def test_c1_four_layer_write_gate_and_rbac_enforcement(self) -> None:
        admin_cli, admin_csrf = await self._login_client("admin_a", PASS_ADMIN_A)
        ro_cli, ro_csrf = await self._login_client("ro_user", PASS_RO)
        force_cli, force_csrf = await self._login_client("force_user", PASS_FORCE)
        anon_cli = TestClient(self.server)
        await anon_cli.start_server()
        try:
            # 1. Missing Origin -> 403
            h = self._write_headers(admin_csrf)
            h.pop("Origin")
            r = await admin_cli.post("/api/google-accounts", headers=h, json={"account_id": "acct_x"})
            self.assertEqual(r.status, 403)

            # 2. Cross-origin Origin -> 403
            r = await admin_cli.post(
                "/api/google-accounts",
                headers=self._write_headers(admin_csrf, Origin="https://evil.example.com"),
                json={"account_id": "acct_x"},
            )
            self.assertEqual(r.status, 403)

            # 3. Cross-site Sec-Fetch-Site -> 403
            r = await admin_cli.post(
                "/api/google-accounts",
                headers=self._write_headers(admin_csrf, **{"Sec-Fetch-Site": "cross-site"}),
                json={"account_id": "acct_x"},
            )
            self.assertEqual(r.status, 403)

            # 4. Non-JSON Content-Type -> 415
            r = await admin_cli.post(
                "/api/google-accounts",
                headers=self._write_headers(admin_csrf, **{"Content-Type": "text/plain"}),
                data='{"account_id":"acct_x"}',
            )
            self.assertEqual(r.status, 415)

            # 5. Unauthenticated -> 401
            r = await anon_cli.post(
                "/api/google-accounts",
                headers=self._write_headers("fake-csrf"),
                json={"account_id": "acct_x"},
            )
            self.assertEqual(r.status, 401)

            # 6. must_change_password=True -> 403
            r = await force_cli.post(
                "/api/google-accounts",
                headers=self._write_headers(force_csrf),
                json={"account_id": "acct_x"},
            )
            self.assertEqual(r.status, 403)

            # 7. Missing / wrong X-Studio-CSRF -> 403
            r = await admin_cli.post(
                "/api/google-accounts",
                headers=self._write_headers("wrong-csrf-token"),
                json={"account_id": "acct_x"},
            )
            self.assertEqual(r.status, 403)

            # 8. Oversized payload (> 32 KiB) -> 413
            huge = json.dumps({"account_id": "acct_x", "alias": "a" * (33 * 1024)})
            r = await admin_cli.post(
                "/api/google-accounts",
                headers=self._write_headers(admin_csrf),
                data=huge,
            )
            self.assertEqual(r.status, 413)

            # 9. Readonly role -> GET /api/google-accounts allowed (can_edit=False), writes -> 403
            r_list = await ro_cli.get("/api/google-accounts")
            self.assertEqual(r_list.status, 200)
            list_data = await r_list.json()
            self.assertFalse(list_data["can_edit"])

            for method, path, body in (
                ("POST", "/api/google-accounts", {"account_id": "ro_add"}),
                ("PATCH", "/api/google-accounts/primary", {"alias": "hacked"}),
                ("DELETE", "/api/google-accounts/primary", {}),
                ("POST", "/api/google-accounts/primary/login/start", {}),
                ("POST", "/api/google-accounts/primary/logout", {}),
                ("POST", "/api/google-accounts/primary/activate", {}),
                ("POST", "/api/google-accounts/primary/refresh-quota", {}),
                ("POST", "/api/google-accounts/refresh-all", {}),
            ):
                r_ro = await ro_cli.request(
                    method,
                    path,
                    headers=self._write_headers(ro_csrf),
                    json=body,
                )
                self.assertEqual(r_ro.status, 403, f"readonly must be denied on {method} {path}")

            # 10. Forbidden client keys rejected -> 400
            r_forb = await admin_cli.post(
                "/api/google-accounts",
                headers=self._write_headers(admin_csrf),
                json={"account_id": "acct_x", "profile_dir": "/tmp/evil"},
            )
            self.assertEqual(r_forb.status, 400)
        finally:
            await admin_cli.close()
            await ro_cli.close()
            await force_cli.close()
            await anon_cli.close()

    # ------------------------------------------------------------------ C1 & C2: OAuth Isolation + Lifecycle
    async def test_c1_c2_oauth_session_isolation_replay_and_audit_desensitization(self) -> None:
        admin_a, csrf_a = await self._login_client("admin_a", PASS_ADMIN_A)
        admin_b, csrf_b = await self._login_client("admin_b", PASS_ADMIN_B)
        ro_cli, _ = await self._login_client("ro_user", PASS_RO)
        try:
            # Add slot `pro_slot`
            r_add = await admin_a.post(
                "/api/google-accounts",
                headers=self._write_headers(csrf_a),
                json={"account_id": "pro_slot", "alias": "Pro Work"},
            )
            self.assertEqual(r_add.status, 201, await r_add.text())

            # Start OAuth login as admin_a
            r_start = await admin_a.post(
                "/api/google-accounts/pro_slot/login/start",
                headers=self._write_headers(csrf_a),
                json={},
            )
            self.assertEqual(r_start.status, 201, await r_start.text())
            start_data = await r_start.json()
            flow = start_data["flow"]
            flow_id = flow["flow_id"]
            self.assertIn("https://accounts.google.com/o/oauth2/auth?", flow["auth_url"])
            self.assertNotIn("oauth_state", flow)
            self.assertNotIn("profile_dir", flow)

            # GET status by owner admin_a succeeds and omits oauth_state & auth_url & profile_dir
            r_st_a = await admin_a.get(f"/api/google-accounts/login/{flow_id}")
            self.assertEqual(r_st_a.status, 200)
            st_a_txt = await r_st_a.text()
            st_a_data = json.loads(st_a_txt)
            self.assertEqual(st_a_data["flow"]["status"], "awaiting_code")
            self.assertNotIn("oauth_state", st_a_data["flow"])
            self.assertNotIn("auth_url", st_a_data["flow"])
            self.assertNotIn("profile_dir", st_a_data["flow"])
            self.assertNotIn(SYNTH_OAUTH_STATE, st_a_txt)

            # Readonly user cannot read login status -> 403
            r_st_ro = await ro_cli.get(f"/api/google-accounts/login/{flow_id}")
            self.assertEqual(r_st_ro.status, 403)

            # Cross-session admin_b denied (403) on GET status, POST submit, POST cancel with ZERO auth_url/state leak
            for method, path, payload in (
                ("GET", f"/api/google-accounts/login/{flow_id}", None),
                ("POST", f"/api/google-accounts/login/{flow_id}/submit", {"code_or_url": SYNTH_OAUTH_CODE}),
                ("POST", f"/api/google-accounts/login/{flow_id}/cancel", {}),
            ):
                if method == "GET":
                    r_x = await admin_b.get(path)
                else:
                    r_x = await admin_b.request(
                        method,
                        path,
                        headers=self._write_headers(csrf_b),
                        json=payload,
                    )
                txt_x = await r_x.text()
                self.assertEqual(r_x.status, 403, f"cross-session {method} {path} must be 403")
                self.assertNotIn("accounts.google.com", txt_x)
                self.assertNotIn(SYNTH_OAUTH_STATE, txt_x)

            # Wrong state in callback URL -> 400 (flow stays active)
            bad_cb = f"https://antigravity.google/oauth-callback?state=wrong_state&code={SYNTH_OAUTH_CODE}"
            r_bad = await admin_a.post(
                f"/api/google-accounts/login/{flow_id}/submit",
                headers=self._write_headers(csrf_a),
                json={"code_or_url": bad_cb},
            )
            self.assertEqual(r_bad.status, 400)

            # Valid callback URL completes login -> 200
            good_cb = f"https://antigravity.google/oauth-callback?state={SYNTH_OAUTH_STATE}&code={SYNTH_OAUTH_CODE}"
            r_ok = await admin_a.post(
                f"/api/google-accounts/login/{flow_id}/submit",
                headers=self._write_headers(csrf_a),
                json={"code_or_url": good_cb},
            )
            self.assertEqual(r_ok.status, 200, await r_ok.text())
            ok_data = await r_ok.json()
            self.assertEqual(ok_data["flow"]["status"], "completed")
            self.assertEqual(ok_data["flow"]["account"]["plan_tier"], "pro")

            # Replay submit on completed flow -> 409
            r_replay = await admin_a.post(
                f"/api/google-accounts/login/{flow_id}/submit",
                headers=self._write_headers(csrf_a),
                json={"code_or_url": good_cb},
            )
            self.assertEqual(r_replay.status, 409)

            # Verify GET /api/google-accounts response has zero raw email, tokens, state, or host paths
            r_list = await admin_a.get("/api/google-accounts")
            self.assertEqual(r_list.status, 200)
            list_txt = await r_list.text()
            for forbidden in (
                "alice.alpha@example.com",
                "bob.beta@example.com",
                SYNTH_ACCESS_A,
                SYNTH_REFRESH_A,
                SYNTH_ACCESS_B,
                SYNTH_REFRESH_B,
                SYNTH_OAUTH_STATE,
                SYNTH_OAUTH_CODE,
                "profile_dir",
                str(self.tmp),
            ):
                self.assertNotIn(forbidden, list_txt, f"Leak detected in GET /api/google-accounts: {forbidden}")
            list_json = json.loads(list_txt)
            masked_emails = {a["email_masked"] for a in list_json["accounts"]}
            self.assertIn("b***a@example.com", masked_emails)

            # Verify 0600 JSONL audit log schema and zero secret/path leakage
            self.assertTrue(self.audit_log_path.is_file())
            mode = stat.S_IMODE(os.stat(self.audit_log_path).st_mode)
            self.assertEqual(mode, 0o600)
            audit_raw = self.audit_log_path.read_text(encoding="utf-8")
            for forbidden in (
                SYNTH_ACCESS_A,
                SYNTH_REFRESH_A,
                SYNTH_ACCESS_B,
                SYNTH_REFRESH_B,
                SYNTH_OAUTH_STATE,
                SYNTH_OAUTH_CODE,
                "accounts.google.com",
                "oauth-callback",
                "alice.alpha@example.com",
                "bob.beta@example.com",
                "profile_dir",
                str(self.tmp),
            ):
                self.assertNotIn(forbidden, audit_raw, f"Leak detected in audit log: {forbidden}")
            records = [json.loads(ln) for ln in audit_raw.splitlines() if ln.strip()]
            self.assertGreaterEqual(len(records), 4)
            expected_keys = {"ts", "actor", "role", "action", "account_id", "flow_id", "ok", "error"}
            for rec in records:
                self.assertEqual(set(rec.keys()), expected_keys)
        finally:
            await admin_a.close()
            await admin_b.close()
            await ro_cli.close()

    async def test_c2_logout_and_server_cleanup_terminate_active_oauth_flows(self) -> None:
        admin_a, csrf_a = await self._login_client("admin_a", PASS_ADMIN_A)
        admin_b, csrf_b = await self._login_client("admin_b", PASS_ADMIN_B)
        try:
            # Start flow 1 in session A, then logout session A -> proc 1 terminated immediately
            r1 = await admin_a.post(
                "/api/google-accounts/primary/login/start",
                headers=self._write_headers(csrf_a),
                json={},
            )
            self.assertEqual(r1.status, 201)
            proc1 = self.spawned_procs[-1]
            self.assertFalse(proc1.terminated)

            r_logout = await admin_a.post(
                "/api/auth/logout",
                headers=self._write_headers(csrf_a),
                json={},
            )
            self.assertEqual(r_logout.status, 200)
            self.assertTrue(proc1.terminated, "Session logout must terminate active OAuth subprocess")

            # Start flow 2 in session B, then trigger server cleanup -> proc 2 terminated immediately
            r2 = await admin_b.post(
                "/api/google-accounts/primary/login/start",
                headers=self._write_headers(csrf_b),
                json={},
            )
            self.assertEqual(r2.status, 201)
            proc2 = self.spawned_procs[-1]
            self.assertFalse(proc2.terminated)

            cleaned = await self.app[GOOGLE_ACCOUNTS_KEY].close_all()
            self.assertGreaterEqual(cleaned, 1)
            self.assertTrue(proc2.terminated, "Server cleanup must terminate remaining active OAuth subprocesses")
        finally:
            await admin_a.close()
            await admin_b.close()

    # ------------------------------------------------------------------ C5: Activate + IPC + SSE
    async def test_c5_activate_triggers_ipc_recycle_and_sse_broadcast(self) -> None:
        admin_a, csrf_a = await self._login_client("admin_a", PASS_ADMIN_A)
        try:
            # Create & register a second ready account
            self.ga_mgr.add_account("pro_two", "Pro Two")
            tpath2 = self.ga_mgr.token_path_for("pro_two")
            tok2_bytes = _make_token_bytes(SYNTH_ACCESS_B, SYNTH_REFRESH_B, "bob.beta@example.com")
            tpath2.write_bytes(tok2_bytes)
            os.chmod(tpath2, 0o600)
            self.ga_mgr.register_logged_in_account(
                "pro_two",
                alias="Pro Two",
                token_doc=ga.parse_oauth_token_bytes(tok2_bytes),
            )

            hub = self.app[EVENT_HUB_KEY]
            seq_before = hub._next_seq

            # Refresh all (offline mocked) to populate multi-plan summary
            r_ref_all = await admin_a.post(
                "/api/google-accounts/refresh-all",
                headers=self._write_headers(csrf_a),
                json={},
            )
            self.assertEqual(r_ref_all.status, 200, await r_ref_all.text())
            ref_data = await r_ref_all.json()
            self.assertTrue(ref_data["all_succeeded"])
            tier_ids = [t["plan_tier"] for t in ref_data["snapshot"]["by_plan"]["tiers"]]
            self.assertEqual(tier_ids, ["ultra", "pro"])

            # Activate pro_two
            r_act = await admin_a.post(
                "/api/google-accounts/pro_two/activate",
                headers=self._write_headers(csrf_a),
                json={},
            )
            self.assertEqual(r_act.status, 200, await r_act.text())
            act_data = await r_act.json()
            self.assertEqual(act_data["active_account_id"], "pro_two")
            self.assertTrue(act_data["switched"])
            self.assertEqual(len(self.recycle_calls), 1)
            self.assertEqual(self.recycle_calls[0]["account_id"], "pro_two")
            self.assertEqual(self.recycle_calls[0]["username"], "admin_a")

            # Verify SSE hub recorded `accounts_updated` event
            ev_types = [ev[1] for ev in list(hub._events) if ev[0] >= seq_before]
            self.assertIn("accounts_updated", ev_types)

            # Also verify real UDS IPC + offline socket graceful degradation (no rollback)
            ipc_dir = self.bus_dir / "ipc"
            recycled_ipc: list[dict] = []

            def _on_ipc_recycle(req_acc: dict):
                recycled_ipc.append(req_acc)
                return 200, {"ok": True, "recycled": True}

            ipc_srv = studio_ipc.StudioIPCServer(
                bus_dir=self.bus_dir,
                bot_handle="online_bot",
                resolve_role_fn=lambda uid: "admin" if uid == ADMIN_UID_A else "denied",
                get_meta_fn=lambda: {"bot": "online_bot"},
                enqueue_turn_fn=lambda _p: (200, {"ok": True}),
                abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
                recycle_accounts_fn=_on_ipc_recycle,
            )
            ipc_srv.start()
            # Also drop an offline dead socket + token to verify graceful degradation
            (ipc_dir / "dead_bot.sock").write_text("", encoding="utf-8")
            (ipc_dir / "dead_bot.token").write_text("dead-tok\n", encoding="utf-8")
            try:
                self.ga_service._recycle_callback = None
                r_sw_back = await admin_a.post(
                    "/api/google-accounts/primary/activate",
                    headers=self._write_headers(csrf_a),
                    json={},
                )
                self.assertEqual(r_sw_back.status, 200, await r_sw_back.text())
                sw_back = await r_sw_back.json()
                self.assertEqual(sw_back["active_account_id"], "primary")
                self.assertEqual(len(recycled_ipc), 1)
                self.assertEqual(recycled_ipc[0]["account_id"], "primary")
                self.assertEqual(recycled_ipc[0]["user_id"], ADMIN_UID_A)
                by_handle = {r["handle"]: r for r in sw_back["recycle_results"]}
                self.assertTrue(by_handle["online_bot"]["ok"])
                self.assertFalse(by_handle["dead_bot"]["ok"])
                self.assertEqual(by_handle["dead_bot"]["status"], "offline")
            finally:
                ipc_srv.stop()
        finally:
            await admin_a.close()

    # ------------------------------------------------------------------ C6: Weekly Reset Patch & Costs Filter
    async def test_c6_patch_weekly_reset_preserves_global_and_costs_backward_compat_and_filters(self) -> None:
        admin_a, csrf_a = await self._login_client("admin_a", PASS_ADMIN_A)
        try:
            # 1. Legacy cost_ledger_v2.json (no account_id / plan_tier) & no cost_config.json
            now_utc = datetime.datetime.now(datetime.timezone.utc)
            hour_key = now_utc.strftime("%Y-%m-%dT%H")
            legacy_ledger = {
                "version": 1,
                "conversations": {
                    "conv_legacy": {
                        "project_id": "demo",
                        "is_observer": False,
                        "is_scheduled": False,
                        "hours": {
                            hour_key: {
                                "gemini-4-neon": [100_000, 400_000, 50_000, 4, 1.25, 3.0],
                            }
                        },
                    }
                },
            }
            self.cost_ledger_file.write_text(json.dumps(legacy_ledger), encoding="utf-8")

            r_legacy = await admin_a.get("/api/costs?scope=all")
            self.assertEqual(r_legacy.status, 200)
            legacy_data = await r_legacy.json()
            for required_key in (
                "ok",
                "readonly",
                "scope",
                "tz_label",
                "week_window",
                "today",
                "week",
                "month",
                "d7",
                "d30",
                "daily_14d",
                "by_model_week",
                "by_model_month",
                "quota_groups",
                "by_account_month",
                "by_plan_month",
                "accounts_quota",
                "filter",
            ):
                self.assertIn(required_key, legacy_data)
            self.assertAlmostEqual(legacy_data["month"]["cost_usd"], 1.25, places=4)
            self.assertEqual(legacy_data["by_account_month"][0]["account_id"], "unassigned")
            self.assertEqual(legacy_data["by_plan_month"][0]["plan_tier"], "unknown")

            # 2. PATCH per-account weekly reset anchor does NOT overwrite global default (4, 23, 0)
            r_patch = await admin_a.patch(
                "/api/google-accounts/primary",
                headers=self._write_headers(csrf_a),
                json={
                    "alias": "Primary Ultra",
                    "weekly_reset_utc_weekday": 1,
                    "weekly_reset_utc_hour": 9,
                },
            )
            self.assertEqual(r_patch.status, 200, await r_patch.text())
            patch_data = await r_patch.json()
            self.assertEqual(patch_data["account"]["alias"], "Primary Ultra")
            self.assertEqual(patch_data["account"]["weekly_reset_utc"], {"weekday": 1, "hour": 9, "minute": 0})
            self.assertEqual(
                cost_usage.load_weekly_reset_utc(str(self.cost_config_file)),
                cost_usage.DEFAULT_WEEKLY_RESET_UTC,
            )
            self.assertEqual(
                cost_usage.load_weekly_reset_utc(str(self.cost_config_file), account_id="primary"),
                (1, 9, 0),
            )

            # 3. Multi-account / multi-plan ledger filtering
            multi_ledger = {
                "version": 1,
                "conversations": {
                    "conv_ultra": {
                        "project_id": "demo",
                        "is_observer": False,
                        "is_scheduled": False,
                        "account_id": "primary",
                        "plan_tier": "ultra",
                        "hours": {
                            hour_key: {"gemini-4-neon": [200_000, 500_000, 80_000, 5, 4.5, 9.0]}
                        },
                    },
                    "conv_pro": {
                        "project_id": "demo",
                        "is_observer": False,
                        "is_scheduled": False,
                        "account_id": "pro_slot",
                        "plan_tier": "pro",
                        "hours": {
                            hour_key: {"claude-opus-5-5": [100_000, 200_000, 40_000, 3, 2.25, 4.5]}
                        },
                    },
                    "conv_legacy": legacy_ledger["conversations"]["conv_legacy"],
                },
            }
            self.cost_ledger_file.write_text(json.dumps(multi_ledger), encoding="utf-8")

            r_all = await admin_a.get("/api/costs?scope=all")
            self.assertEqual(r_all.status, 200)
            all_data = await r_all.json()
            self.assertAlmostEqual(all_data["month"]["cost_usd"], 8.0, places=4)
            self.assertEqual(len(all_data["by_account_month"]), 3)
            self.assertEqual(len(all_data["by_plan_month"]), 3)

            r_acct = await admin_a.get("/api/costs?scope=all&account_id=primary")
            self.assertEqual(r_acct.status, 200)
            acct_data = await r_acct.json()
            self.assertEqual(acct_data["filter"], {"account_id": "primary", "plan_tier": None})
            self.assertAlmostEqual(acct_data["month"]["cost_usd"], 4.5, places=4)
            self.assertEqual([r["account_id"] for r in acct_data["by_account_month"]], ["primary"])

            r_plan = await admin_a.get("/api/costs?scope=all&plan_tier=pro")
            self.assertEqual(r_plan.status, 200)
            plan_data = await r_plan.json()
            self.assertEqual(plan_data["filter"], {"account_id": None, "plan_tier": "pro"})
            self.assertAlmostEqual(plan_data["month"]["cost_usd"], 2.25, places=4)
            self.assertEqual([r["plan_tier"] for r in plan_data["by_plan_month"]], ["pro"])

            # Verify zero host paths / emails / tokens in GET /api/costs output
            all_txt = json.dumps(all_data)
            for forbidden in ("alice.alpha@example.com", SYNTH_ACCESS_A, SYNTH_REFRESH_A, str(self.tmp)):
                self.assertNotIn(forbidden, all_txt)
        finally:
            await admin_a.close()

    async def test_c1_symlink_audit_log_refused_fail_closed(self) -> None:
        victim = self.tmp / "victim.txt"
        victim.write_text("KEEP_INTACT\n", encoding="utf-8")
        symlink_audit = self.config_dir / "symlink_audit.jsonl"
        symlink_audit.symlink_to(victim)

        from studio.google_accounts_service import _AccountsAuditLogger

        logger = _AccountsAuditLogger(symlink_audit)
        logger.record(action="add", ok=True, account_id="primary")
        self.assertEqual(victim.read_text(encoding="utf-8"), "KEEP_INTACT\n")


if __name__ == "__main__":
    unittest.main()
