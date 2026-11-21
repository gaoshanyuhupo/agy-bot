#!/usr/bin/env python3
"""Comprehensive unit & integration tests for AGY Studio WebUI Phase 1 MVP.

Covers:
1. Dual-track zero-trust auth (Telegram Mini App HMAC + 60s single-use `#t=` Magic Link)
   with strict no-fallback, SHA-256 hash-only storage, GET non-consumption, sanitized
   access logging (zero credential leakage), concurrent redeem single-use guarantee, and TTL expiry.
2. Bridge `/webui` & `/studio` slash command (group refusal + private DM issuance + readonly allowed
   + Telegram link preview explicitly disabled).
3. Strict public HTTPS Same-Origin (`normalize_origin`, `expected_origins`, `AGY_STUDIO_ALLOWED_ORIGINS`,
   unconditional `Secure` cookie in public HTTPS mode, `frame-ancestors 'none'` CSP, anti-CSWSH,
   anti-forwarded-header origin expansion, pure local dev mode).
4. Live `.env*` RBAC recomputation, instant downgrade (`role_changed` + close 4008), instant revocation
   (0 post-revocation text/binary frames), logout cleanup, and upstream takeover release + AI resume
   when last eligible admin disconnects/downgrades/revokes (including when readonly viewers remain,
   while preserving takeover if another eligible admin remains).
5. Loopback-only `_authenticate_internal_delegated` in `live_browser_server.py` (anti-spoofing,
   rejecting caller-supplied `role` / `X-Studio-Role`, anti-forwarded-header, zero fallback).
6. Isolated E2E WS proxy + multipart `/api/browser/upload` (positive & negative) + `/api/browser/download`.
7. Strictly read-only whitelisted telemetry APIs with deep redaction (emails, absolute paths,
   Telegram/long IDs, URL query/fragment, non-standard credentials) and owner-scoped browser status URL.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import importlib
import importlib.util
import json
import logging
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import unittest
from unittest import mock
import urllib.parse

import aiohttp
from aiohttp import WSMsgType, web
from aiohttp.test_utils import TestClient, TestServer

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

from studio.auth import (  # noqa: E402
    SESSION_COOKIE_NAME,
    StudioAuthManager,
    hash_password_scrypt,
    load_users_file,
    main as studio_auth_cli_main,
    normalize_origin,
    save_users_file_atomic,
)
from studio.browser_proxy import (  # noqa: E402
    BrowserProxy,
    HTTP_SESSION_KEY,
    WS_CLOSE_AUTH_FORBIDDEN,
    WS_CLOSE_ROLE_CHANGED,
)
from studio.data_sources import (  # noqa: E402
    StudioDataSources,
    redact_sensitive_text,
    sanitize_url_origin,
    sanitize_url_origin_path,
)
from studio.server import SanitizedAccessLogger, create_app  # noqa: E402

BOT_TOKEN_MAIN = "123456789:EXAMPLE_STUDIO_TEST_TOKEN_MAIN_0001"
BOT_TOKEN_SG = "123456789:EXAMPLE_STUDIO_TEST_TOKEN_SG_000002"
ADMIN_UID = 111111111
ADMIN_UID_2 = 987654321
READONLY_UID = 222222222
OUTSIDER_UID = 333333333
GROUP_CHAT_ID = -1001234567890
PUBLIC_ORIGIN = "https://studio.example.com"


def _make_tg_init_data(
    bot_token: str,
    user_id: int,
    *,
    auth_date: int | None = None,
    username: str = "tester",
) -> str:
    ts = int(time.time()) if auth_date is None else int(auth_date)
    user_json = json.dumps(
        {"id": user_id, "first_name": "Test", "username": username},
        separators=(",", ":"),
    )
    pairs = [
        ("auth_date", str(ts)),
        ("query_id", "AAHdF6IQAAAAAN0XohDhrOrc"),
        ("user", user_json),
    ]
    dcs = "\n".join(f"{k}={v}" for k, v in sorted(pairs))
    secret = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
    sig = hmac.new(secret, dcs.encode("utf-8"), hashlib.sha256).hexdigest()
    return urllib.parse.urlencode(pairs + [("hash", sig)])


def _write_env(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _load_live_browser_module():
    mod_path = REPO_ROOT / ".agents/skills/live-browser/scripts/live_browser_server.py"
    spec = importlib.util.spec_from_file_location("live_browser_server_studio_test", mod_path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _extract_magic_fragment_token(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    assert parsed.query == "", f"Magic link must NOT carry query params: {url}"
    frag_qs = urllib.parse.parse_qs(parsed.fragment)
    return frag_qs["t"][0]


def _extract_session_cookie(resp: aiohttp.ClientResponse) -> str:
    morsel = resp.cookies.get(SESSION_COOKIE_NAME)
    return morsel.value if morsel is not None else ""


class _ListLogHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(self.format(record))


class TestStudioMvp(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.bridge_dir = self.tmp / "bridge_env"
        self.bridge_dir.mkdir()
        self.studio_cfg = self.tmp / "studio_cfg"
        self.live_cfg = self.tmp / "live_cfg"
        self.live_cfg.mkdir()
        self.bus_dir = self.tmp / "bus"
        (self.bus_dir / "jobs").mkdir(parents=True)
        self.dist_dir = self.tmp / "dist"
        (self.dist_dir / "assets").mkdir(parents=True)
        (self.dist_dir / "index.html").write_text(
            "<!doctype html><html><head><title>AGY Studio</title></head><body><div id='root'></div></body></html>",
            encoding="utf-8",
        )
        (self.dist_dir / "assets" / "app.js").write_text("console.log('studio');", encoding="utf-8")

        self.live_token = "EXAMPLE_LIVE_LOCAL_TOKEN_FOR_STUDIO_TEST_1234"
        (self.live_cfg / "local.token").write_text(self.live_token + "\n", encoding="utf-8")

        # Main bot has ADMIN_UID (admin) + READONLY_UID (readonly)
        _write_env(
            self.bridge_dir / ".env",
            [
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_MAIN}",
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID},{GROUP_CHAT_ID}",
                f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                f"AGY_TG_READONLY_USERS={READONLY_UID}",
            ],
        )
        # Second bot has only ADMIN_UID
        _write_env(
            self.bridge_dir / ".env.sg",
            [
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_SG}",
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID}",
                f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
            ],
        )

        # Dynamically construct synthetic PII/secret fixtures (never literal secrets in repo)
        self._fake_ghp = "ghp_" + "1234567890abcdef123456"
        self._fake_sk = "sk-" + "proj-abcdef1234567890abcdef"
        self._fake_email = "alice.secret" + "@" + "privatecorp.example"
        self._fake_path_home = "/" + "home" + "/alice/.config/secret.env"
        self._fake_path_tmp = "/" + "tmp" + "/dump-secret.log"
        self._fake_tg_grp = "-100" + "99887" + "76655"
        self._fake_tg_uid = "88776" + "65544"
        self._fake_url_q = "secret_query_tok_987"
        self._fake_url_f = "secret_frag_val_654"
        self._fake_url_full = f"https://app.example.org/docs/report?token={self._fake_url_q}#{self._fake_url_f}"
        self._fake_nonstd_cred = "my_password=" + "hunter2secret99"
        self._fake_bearer = "Bearer " + "shortTok9988"
        self._fake_vault_path = "lv1/" + "services/secret-vault"

        now = time.time()
        (self.bus_dir / "roster.json").write_text(
            json.dumps({
                "version": 1,
                "bots": {
                    "example_main_bot": {
                        "handle": "example_main_bot",
                        "display_name": f"Main Bot {self._fake_email}",
                        "role": "coordinator",
                        "pid": os.getpid(),
                        "last_seen": now,
                        "busy": False,
                        "active_model": "gemini-4-neon",
                        "specialty": f"Ops {self._fake_path_home} {self._fake_bearer} {self._fake_vault_path}",
                        "default_project": f"{self._fake_path_home}",
                        "allowed_chats": [ADMIN_UID, GROUP_CHAT_ID],
                    }
                },
            }),
            encoding="utf-8",
        )
        (self.bus_dir / "jobs" / "job-1.json").write_text(
            json.dumps({
                "job_id": "job-1",
                "group_id": "batch-1",
                "label": (
                    f"Audit {self._fake_email} {self._fake_path_tmp} {self._fake_tg_grp} "
                    f"{self._fake_tg_uid} {self._fake_url_full} {self._fake_nonstd_cred}"
                ),
                "from_bot": "example_main_bot",
                "target_bot": "example_worker_bot",
                "status": "done",
                "project": "agy-cli-bot",
                "model": "gemini-3.8-flash",
                "created_at": now - 20,
                "started_at": now - 15,
                "finished_at": now - 5,
                "prompt": f"RAW_PROMPT_MUST_NOT_LEAK {self._fake_email}",
                "result_summary": f"RAW_SUMMARY_LEAK {self._fake_ghp} {self._fake_sk} {self._fake_email}",
                "error": f"Traceback: {self._fake_path_home} AGY_TG_BOT_TOKEN={BOT_TOKEN_MAIN}",
            }),
            encoding="utf-8",
        )
        self.schedules_file = self.tmp / "scheduled_tasks.json"
        self.schedules_file.write_text(
            json.dumps({
                "version": 1,
                "tasks": {
                    "task-1": {
                        "id": "task-1",
                        "name": f"Daily Report {self._fake_email} {self._fake_tg_grp} {self._fake_url_full}",
                        "enabled": True,
                        "schedule_type": "cron",
                        "schedule_expr": "0 9 * * *",
                        "task_type": "cost_report",
                        "execution": {"model": "gemini-3.8-flash", "project": "agy-cli-bot"},
                        "delivery": {"target_chat_id": ADMIN_UID},
                        "state": {
                            "next_run_at": "2026-11-21T01:00:00Z",
                            "last_status": "error",
                            "run_count": 3,
                            "last_error": f"RAW_SCHED_ERR {self._fake_path_home} {self._fake_nonstd_cred}",
                        },
                    }
                },
            }),
            encoding="utf-8",
        )
        self.cost_ledger_file = self.tmp / "cost_ledger_v2.json"
        hour_key = time.strftime("%Y-%m-%dT%H", time.gmtime(now))
        self.cost_ledger_file.write_text(
            json.dumps({
                "version": 1,
                "conversations": {
                    "conv-1": {
                        "project_id": "agy-cli-bot",
                        "is_observer": False,
                        "is_scheduled": False,
                        "hours": {
                            hour_key: {
                                "gemini-3.8-flash": [100000, 400000, 50000, 4, 0.2925, 0.5625]
                            }
                        },
                    }
                },
            }),
            encoding="utf-8",
        )

        self.clock = [now]
        self.auth_mgr = StudioAuthManager(
            config_dir=self.studio_cfg,
            bridge_dir=self.bridge_dir,
            auth_mode="legacy",
            public_url=PUBLIC_ORIGIN,
            allowed_origins="",
            now_fn=lambda: self.clock[0],
        )
        self.sources = StudioDataSources(
            bus_dir=self.bus_dir,
            schedules_file=self.schedules_file,
            cost_ledger_file=self.cost_ledger_file,
            cost_config_file=self.tmp / "cost_config.json",
            quota_cache_file=self.tmp / "quota_usage.json",
            live_browser_url="http://127.0.0.1:19999",
            live_browser_config_dir=self.live_cfg,
        )
        self.app = create_app(
            auth_mgr=self.auth_mgr,
            data_sources=self.sources,
            static_dist_dir=self.dist_dir,
            revocation_check_interval=0.08,
        )
        self.server = TestServer(self.app)
        self.client = TestClient(self.server)
        await self.client.start_server()
        self._sid = ""

    async def asyncTearDown(self) -> None:
        await self.client.close()
        self._tmp.cleanup()

    def _origin(self) -> str:
        return PUBLIC_ORIGIN

    def _loopback_origin(self) -> str:
        return f"http://{self.server.host}:{self.server.port}"

    def _cookie_hdr(self, sid: str | None = None) -> dict[str, str]:
        val = self._sid if sid is None else sid
        return {"Cookie": f"{SESSION_COOKIE_NAME}={val}"} if val else {}

    async def _login_magic(self, bot: str, uid: int) -> tuple[dict, str, str]:
        r_issue = await self.client.post(
            "/internal/magic-link",
            headers={"X-Studio-Internal-Token": self.auth_mgr.local_token},
            json={"bot": bot, "user_id": uid},
        )
        self.assertEqual(r_issue.status, 200)
        issued = await r_issue.json()
        tok = _extract_magic_fragment_token(issued["url"])

        r_red = await self.client.post(
            "/api/auth/redeem",
            headers={"Origin": self._origin()},
            json={"token": tok},
        )
        self.assertEqual(r_red.status, 200)
        sc = r_red.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", sc)
        self.assertIn("SameSite=Lax", sc)
        self.assertIn("Secure", sc)
        sid = _extract_session_cookie(r_red)
        self.assertTrue(sid)
        self._sid = sid
        body = await r_red.json()
        return body, tok, sid

    # ---------------------------------------------------------------- 1. Unauth & Security Headers
    async def test_unauthenticated_zero_data_and_security_headers(self) -> None:
        r_home = await self.client.get("/")
        self.assertEqual(r_home.status, 200)
        html = await r_home.text()
        self.assertIn("AGY Studio", html)
        self.assertNotIn("example_main_bot", html)
        self.assertEqual(r_home.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r_home.headers.get("Referrer-Policy"), "no-referrer")
        csp = r_home.headers.get("Content-Security-Policy", "")
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("web.telegram.org", csp)

        for ep in (
            "/api/auth/me",
            "/api/overview",
            "/api/bots",
            "/api/jobs",
            "/api/schedules",
            "/api/costs",
            "/api/browser/status",
        ):
            r = await self.client.get(ep)
            self.assertEqual(r.status, 401, ep)
            data = await r.json()
            self.assertFalse(data["ok"])
            self.assertEqual(data["source"], "studio_auth")
            self.assertEqual(r.headers.get("Cache-Control"), "no-store, max-age=0")

    # ---------------------------------------------------------------- 2. Strict Origin & normalize_origin (P0-2)
    async def test_strict_origin_normalization_public_https_and_local_mode(self) -> None:
        # Unit checks for normalize_origin
        self.assertEqual(normalize_origin("https://studio.example.com"), "https://studio.example.com")
        self.assertEqual(normalize_origin("https://studio.example.com:443"), "https://studio.example.com")
        self.assertEqual(normalize_origin("http://127.0.0.1:8080"), "http://127.0.0.1:8080")
        for bad in (
            "",
            None,
            "null",
            "NULL",
            "https://studio.example.com/",
            "https://studio.example.com/path",
            "https://studio.example.com?",
            "https://studio.example.com?a=1",
            "https://studio.example.com#",
            "https://studio.example.com#frag",
            "https://studio.example.com:",
            "https://studio.example.com;params",
            "https://user@studio.example.com",
            "https://user:pass@studio.example.com",
            "https://studio.example.com:99999",
            "https://studio.example.com:abc",
            "https://studio.example.com:0",
            "https://studio.example.com:0443",
            "https://studio.example.com:-1",
            "ftp://studio.example.com",
            "javascript:alert(1)",
            "https://studio.example.com\r\nX-Injected: 1",
        ):
            self.assertEqual(normalize_origin(bad), "", f"Expected rejection for Origin={bad!r}")

        # Startup fail-fast validation: public mode rejects http:// or malformed public_url / allowed_origins
        for bad_pub, bad_extra in (
            ("http://studio.example.com", ""),
            ("https://studio.example.com?", ""),
            ("https://studio.example.com#", ""),
            ("https://studio.example.com:", ""),
            ("https://studio.example.com/path", ""),
            ("https://studio.example.com", "http://alt.example.com"),
            ("https://studio.example.com", "https://alt.example.com, invalid-origin"),
            ("https://studio.example.com", "https://alt.example.com?"),
        ):
            with self.assertRaises(ValueError, msg=f"Expected ValueError for public_url={bad_pub!r}, extra={bad_extra!r}"):
                StudioAuthManager(
                    config_dir=self.studio_cfg,
                    bridge_dir=self.bridge_dir,
                    public_url=bad_pub,
                    allowed_origins=bad_extra,
                    now_fn=lambda: self.clock[0],
                )

        # Uppercase HTTPS public_url normalizes to lowercase, accepts Origin, and unconditionally sets Secure cookie
        auth_upper = StudioAuthManager(
            config_dir=self.studio_cfg,
            bridge_dir=self.bridge_dir,
            auth_mode="legacy",
            public_url="HTTPS://WB.EXAMPLE.COM",
            allowed_origins="HTTPS://ALT.EXAMPLE.COM:443",
            now_fn=lambda: self.clock[0],
        )
        self.assertEqual(auth_upper.public_url, "https://wb.example.com")
        self.assertIn("https://alt.example.com", auth_upper.extra_allowed_origins)
        app_upper = create_app(auth_mgr=auth_upper, data_sources=self.sources, static_dist_dir=self.dist_dir)
        init_admin = _make_tg_init_data(BOT_TOKEN_MAIN, ADMIN_UID, auth_date=int(self.clock[0]))
        async with TestClient(TestServer(app_upper)) as cli_upper:
            r_up_ok = await cli_upper.post(
                "/api/auth/telegram",
                headers={"Origin": "https://wb.example.com"},
                json={"initData": init_admin},
            )
            self.assertEqual(r_up_ok.status, 200)
            self.assertIn("Secure", r_up_ok.headers.get("Set-Cookie", ""))
            r_up_cap = await cli_upper.post(
                "/api/auth/telegram",
                headers={"Origin": "HTTPS://WB.EXAMPLE.COM"},
                json={"initData": init_admin},
            )
            self.assertEqual(r_up_cap.status, 200)
            self.assertIn("Secure", r_up_cap.headers.get("Set-Cookie", ""))

        sess, _, sid = await self._login_magic("main", ADMIN_UID)
        csrf = sess["csrf_token"]

        # Public HTTPS mode rejects http:// same-host, loopback origin, forged X-Forwarded-*, path/query/bad-port, missing/null
        bad_origin_cases = [
            {},  # missing Origin
            {"Origin": "null"},
            {"Origin": "http://studio.example.com"},
            {"Origin": self._loopback_origin()},
            {"Origin": "https://evil.example.com", "X-Forwarded-Host": "evil.example.com", "X-Forwarded-Proto": "https"},
            {"Origin": "http://studio.example.com", "X-Forwarded-Host": "studio.example.com", "X-Forwarded-Proto": "http"},
            {"Origin": "https://studio.example.com/"},
            {"Origin": "https://studio.example.com/api"},
            {"Origin": "https://studio.example.com?"},
            {"Origin": "https://studio.example.com#"},
            {"Origin": "https://studio.example.com:"},
            {"Origin": "https://studio.example.com?x=1"},
            {"Origin": "https://studio.example.com:99999"},
            {"Origin": "https://studio.example.com:abc"},
            {"Origin": "https://user@studio.example.com"},
        ]
        for hdrs in bad_origin_cases:
            # 1) POST /api/auth/telegram -> 403 (never 500)
            r_tg = await self.client.post("/api/auth/telegram", headers=hdrs, json={"initData": init_admin})
            self.assertEqual(r_tg.status, 403, f"telegram should 403 for {hdrs}")
            self.assertEqual((await r_tg.json())["source"], "studio_auth")
            # 2) POST /api/auth/redeem -> 403
            r_red = await self.client.post("/api/auth/redeem", headers=hdrs, json={"token": "x" * 24})
            self.assertEqual(r_red.status, 403, f"redeem should 403 for {hdrs}")
            # 3) POST /api/auth/logout -> 403
            r_lo = await self.client.post(
                "/api/auth/logout",
                headers={**hdrs, **self._cookie_hdr(sid), "X-Studio-CSRF": csrf},
            )
            self.assertEqual(r_lo.status, 403, f"logout should 403 for {hdrs}")
            # 4) GET /ws/browser -> 403
            r_ws = await self.client.get("/ws/browser", headers={**hdrs, **self._cookie_hdr(sid)})
            self.assertEqual(r_ws.status, 403, f"ws should 403 for {hdrs}")

        # Public HTTPS mode unconditionally sets Secure cookie even on plain loopback HTTP without X-Forwarded-Proto
        r_ok = await self.client.post(
            "/api/auth/telegram",
            headers={"Origin": PUBLIC_ORIGIN},
            json={"initData": init_admin},
        )
        self.assertEqual(r_ok.status, 200)
        sc = r_ok.headers.get("Set-Cookie", "")
        self.assertIn("Secure", sc)
        self.assertIn("HttpOnly", sc)
        self.assertIn("SameSite=Lax", sc)

        # Explicit AGY_STUDIO_ALLOWED_ORIGINS allows additional configured HTTPS origin
        auth_extra = StudioAuthManager(
            config_dir=self.studio_cfg,
            bridge_dir=self.bridge_dir,
            auth_mode="legacy",
            public_url=PUBLIC_ORIGIN,
            allowed_origins="https://alt.example.com",
            now_fn=lambda: self.clock[0],
        )
        app_extra = create_app(auth_mgr=auth_extra, data_sources=self.sources, static_dist_dir=self.dist_dir)
        async with TestClient(TestServer(app_extra)) as cli_extra:
            r_alt = await cli_extra.post(
                "/api/auth/telegram",
                headers={"Origin": "https://alt.example.com"},
                json={"initData": init_admin},
            )
            self.assertEqual(r_alt.status, 200)

        # Pure local dev mode (public_url="") allows exact scheme://host; forged X-Forwarded-Proto / CF-Visitor
        # MUST NOT expand Origin and MUST NOT alter Cookie Secure attribute!
        auth_local = StudioAuthManager(
            config_dir=self.studio_cfg,
            bridge_dir=self.bridge_dir,
            auth_mode="legacy",
            public_url="",
            allowed_origins="",
            now_fn=lambda: self.clock[0],
        )
        app_local = create_app(auth_mgr=auth_local, data_sources=self.sources, static_dist_dir=self.dist_dir)
        local_srv = TestServer(app_local)
        async with TestClient(local_srv) as cli_local:
            local_orig = f"http://{local_srv.host}:{local_srv.port}"
            r_loc_ok = await cli_local.post(
                "/api/auth/telegram",
                headers={
                    "Origin": local_orig,
                    "X-Forwarded-Proto": "https",
                    "CF-Visitor": '{"scheme":"https"}',
                },
                json={"initData": init_admin},
            )
            self.assertEqual(r_loc_ok.status, 200)
            self.assertNotIn("Secure", r_loc_ok.headers.get("Set-Cookie", ""))
            r_loc_forged = await cli_local.post(
                "/api/auth/telegram",
                headers={"Origin": "https://forged.example.com", "X-Forwarded-Host": "forged.example.com", "X-Forwarded-Proto": "https"},
                json={"initData": init_admin},
            )
            self.assertEqual(r_loc_forged.status, 403)

    # ---------------------------------------------------------------- 3. Track A: Telegram Auth
    async def test_telegram_track_positive_negative_and_no_elevation(self) -> None:
        init_admin = _make_tg_init_data(BOT_TOKEN_MAIN, ADMIN_UID, auth_date=int(self.clock[0]))
        # Expired initData (>3600s) rejected
        init_old = _make_tg_init_data(BOT_TOKEN_MAIN, ADMIN_UID, auth_date=int(self.clock[0]) - 4000)
        r_old = await self.client.post(
            "/api/auth/telegram",
            headers={"Origin": self._origin()},
            json={"initData": init_old},
        )
        self.assertEqual(r_old.status, 403)
        self.assertEqual((await r_old.json())["source"], "studio_auth")

        # Outsider rejected
        init_out = _make_tg_init_data(BOT_TOKEN_MAIN, OUTSIDER_UID, auth_date=int(self.clock[0]))
        r_out = await self.client.post(
            "/api/auth/telegram",
            headers={"Origin": self._origin()},
            json={"initData": init_out},
        )
        self.assertEqual(r_out.status, 403)

        # Readonly user gets readonly (never elevated to admin)
        init_ro = _make_tg_init_data(BOT_TOKEN_MAIN, READONLY_UID, auth_date=int(self.clock[0]))
        r_ro = await self.client.post(
            "/api/auth/telegram",
            headers={"Origin": self._origin()},
            json={"initData": init_ro},
        )
        self.assertEqual(r_ro.status, 200)
        body_ro = await r_ro.json()
        self.assertEqual(body_ro["role"], "readonly")
        self.assertEqual(body_ro["auth_track"], "telegram")

        # Cross-bot signing: READONLY_UID signed by sg bot (not in sg whitelist) -> 403
        init_wrong_bot = _make_tg_init_data(BOT_TOKEN_SG, READONLY_UID, auth_date=int(self.clock[0]))
        r_wb = await self.client.post(
            "/api/auth/telegram",
            headers={"Origin": self._origin()},
            json={"initData": init_wrong_bot},
        )
        self.assertEqual(r_wb.status, 403)

        # Admin valid
        r_ok = await self.client.post(
            "/api/auth/telegram",
            headers={"Origin": self._origin()},
            json={"initData": init_admin},
        )
        self.assertEqual(r_ok.status, 200)
        self.assertEqual((await r_ok.json())["role"], "admin")

    # ---------------------------------------------------------------- 4. Track B: Magic Link `#t=`, Zero-Log, Concurrent Redeem (P0-1)
    async def test_magic_link_fragment_zero_access_log_concurrent_redeem_and_ttl(self) -> None:
        # Reject missing / bad internal token
        r_bad_tok = await self.client.post(
            "/internal/magic-link",
            headers={"X-Studio-Internal-Token": "wrong"},
            json={"bot": "main", "user_id": ADMIN_UID},
        )
        self.assertEqual(r_bad_tok.status, 403)

        # Reject X-Forwarded-For & CF-Connecting-IP even on loopback
        for hdr in ({"X-Forwarded-For": "198.51.100.1"}, {"CF-Connecting-IP": "198.51.100.2"}):
            r_fwd = await self.client.post(
                "/internal/magic-link",
                headers={"X-Studio-Internal-Token": self.auth_mgr.local_token, **hdr},
                json={"bot": "main", "user_id": ADMIN_UID},
            )
            self.assertEqual(r_fwd.status, 403)

        # Reject unauthorized outsider
        r_unauth = await self.client.post(
            "/internal/magic-link",
            headers={"X-Studio-Internal-Token": self.auth_mgr.local_token},
            json={"bot": "main", "user_id": OUTSIDER_UID},
        )
        self.assertEqual(r_unauth.status, 403)

        # Issue for readonly user -> MUST use `#t=...` fragment (zero query)
        r_issue = await self.client.post(
            "/internal/magic-link",
            headers={"X-Studio-Internal-Token": self.auth_mgr.local_token},
            json={"bot": "main", "user_id": READONLY_UID},
        )
        self.assertEqual(r_issue.status, 200)
        issued = await r_issue.json()
        self.assertEqual(issued["role"], "readonly")
        self.assertEqual(issued["ttl_seconds"], 60)
        self.assertIn("/auth/magic#t=", issued["url"])
        self.assertNotIn("?t=", issued["url"])
        raw_tok = _extract_magic_fragment_token(issued["url"])

        # Raw token must NOT be stored in memory (SHA-256 hash only)
        self.assertNotIn(raw_tok, self.auth_mgr._magic_tokens)
        self.assertIn(hashlib.sha256(raw_tok.encode()).hexdigest(), self.auth_mgr._magic_tokens)

        # Spin up real AppRunner with SanitizedAccessLogger to verify ZERO token in access logs
        # (including query params of any key name, Referer headers, and User-Agent headers!)
        capture_logger = logging.getLogger(f"test_studio_access_{id(self)}")
        capture_logger.setLevel(logging.INFO)
        capture_logger.propagate = False
        handler = _ListLogHandler()
        capture_logger.addHandler(handler)
        runner = web.AppRunner(
            self.app,
            access_log=capture_logger,
            access_log_class=SanitizedAccessLogger,
        )
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        try:
            sock = site._server.sockets[0]  # type: ignore[union-attr]
            port = sock.getsockname()[1]
            async with aiohttp.ClientSession() as raw_cli:
                # 1) Normal browser navigation to /auth/magic (fragment never sent)
                async with raw_cli.get(f"http://127.0.0.1:{port}/auth/magic") as r1:
                    self.assertEqual(r1.status, 200)
                # 2) Legacy ?t=<raw_tok> + synthetic token in Referer & User-Agent -> ZERO leak in logs!
                async with raw_cli.get(
                    f"http://127.0.0.1:{port}/auth/magic?t={raw_tok}",
                    headers={
                        "Referer": f"https://example.com/auth/magic?t={raw_tok}",
                        "User-Agent": f"StudioTestAgent/{raw_tok}",
                    },
                ) as r2:
                    self.assertEqual(r2.status, 200)
                # 3) Arbitrary query key on /healthz + Referer -> ALL query params & headers stripped!
                tok_q_url = f"http://127.0.0.1:{port}/healthz?foo={raw_tok}&" + "token=" + raw_tok
                async with raw_cli.get(
                    tok_q_url,
                    headers={"Referer": f"https://example.com/callback?code={raw_tok}"},
                ) as r3:
                    self.assertEqual(r3.status, 200)
        finally:
            await runner.cleanup()
            capture_logger.removeHandler(handler)

        combined_logs = "\n".join(handler.messages)
        self.assertTrue(combined_logs, "Expected access log entries to be captured")
        self.assertNotIn(raw_tok, combined_logs, "Raw magic token MUST NEVER appear in server access logs")
        self.assertNotIn("Referer", combined_logs)
        self.assertNotIn("StudioTestAgent", combined_logs)
        self.assertNotIn("?t=", combined_logs)
        self.assertNotIn("?foo=", combined_logs)
        self.assertIn('"GET /auth/magic HTTP/1.1"', combined_logs)
        self.assertIn('"GET /healthz HTTP/1.1"', combined_logs)

        # Verify SPA shell does NOT statically load third-party Telegram SDK and does NOT accept `?t=` query
        real_index_html = (REPO_ROOT / "webui" / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("telegram-web-app.js", real_index_html)
        bootstrap_ts = (REPO_ROOT / "webui" / "src" / "bootstrapAuth.ts").read_text(encoding="utf-8")
        app_tsx = (REPO_ROOT / "webui" / "src" / "App.tsx").read_text(encoding="utf-8")
        self.assertNotIn("legacyQueryToken", app_tsx)
        self.assertNotIn("new URLSearchParams(window.location.search)", bootstrap_ts)
        self.assertNotIn("new URLSearchParams(window.location.search)", app_tsx)

        # GET /auth/magic did NOT consume the token
        self.assertIn(hashlib.sha256(raw_tok.encode()).hexdigest(), self.auth_mgr._magic_tokens)

        # Zero cross-track fallback: passing magic token to /api/auth/telegram fails
        r_cross_track = await self.client.post(
            "/api/auth/telegram",
            headers={"Origin": self._origin()},
            json={"initData": raw_tok},
        )
        self.assertEqual(r_cross_track.status, 403)

        # Concurrent POST /api/auth/redeem (5 simultaneous requests) -> AT MOST 1 succeeds!
        async def _try_redeem() -> tuple[int, dict]:
            resp = await self.client.post(
                "/api/auth/redeem",
                headers={"Origin": self._origin()},
                json={"token": raw_tok},
            )
            return resp.status, await resp.json()

        results = await asyncio.gather(*(_try_redeem() for _ in range(5)))
        ok_results = [r for r in results if r[0] == 200]
        fail_results = [r for r in results if r[0] == 403]
        self.assertEqual(len(ok_results), 1, f"Concurrent redeem must succeed exactly once: {results}")
        self.assertEqual(len(fail_results), 4)
        self.assertEqual(ok_results[0][1]["role"], "readonly")
        self.assertEqual(ok_results[0][1]["auth_track"], "magic_link")

        # TTL expiry test (61 seconds later)
        r_issue2 = await self.client.post(
            "/internal/magic-link",
            headers={"X-Studio-Internal-Token": self.auth_mgr.local_token},
            json={"bot": "main", "user_id": ADMIN_UID},
        )
        tok2 = _extract_magic_fragment_token((await r_issue2.json())["url"])
        self.clock[0] += 61.0
        r_exp = await self.client.post(
            "/api/auth/redeem",
            headers={"Origin": self._origin()},
            json={"token": tok2},
        )
        self.assertEqual(r_exp.status, 403)

    # ---------------------------------------------------------------- 5. CSRF, Logout & Whitelisted Read-Only Telemetry (P0-4)
    async def test_csrf_logout_whitelisted_telemetry_and_deep_redaction(self) -> None:
        # Unit checks on sanitize_url_origin, sanitize_url_origin_path & redact_sensitive_text (P0-4)
        self.assertEqual(
            sanitize_url_origin("https://example.com/u/alice%40corp.com/view?t=secret#frag"),
            "https://example.com",
        )
        self.assertEqual(
            sanitize_url_origin_path(
                f"https://user:pass@app.example.com/docs/42?t={self._fake_url_q}#{self._fake_url_f}"
            ),
            "https://app.example.com/docs/42",
        )
        self.assertNotIn(
            "alice",
            sanitize_url_origin_path("https://example.com/u/alice%40corp.com/view"),
        )
        syn_jtok = "json" + "_tok_991_val"
        syn_japi = "json" + "_api_992_val"
        syn_jsec = "json" + "_sec_993_val"
        syn_jpwd = "json" + "_pwd_994_val"
        syn_jauth = "json" + "_auth_995_val"
        quoted_json_secrets = json.dumps({
            "token": syn_jtok,
            "api_key": syn_japi,
            "secret": syn_jsec,
            "password": syn_jpwd,
            "authorization": "Bearer " + syn_jauth,
        })
        nonstd_posix_path = "/" + "srv" + "/private/data.json"
        custom_posix_path = "/" + "custom_dir" + "/private/vault.yml"
        win_abs_path = "C:\\" + "Users\\alice\\secrets.txt"
        red = redact_sensitive_text(
            f"{self._fake_email} {self._fake_path_home} {nonstd_posix_path} {custom_posix_path} {win_abs_path} "
            f"{self._fake_tg_grp} {self._fake_tg_uid} {self._fake_url_full} {self._fake_nonstd_cred} "
            f"{self._fake_bearer} {self._fake_vault_path} {quoted_json_secrets}",
            max_len=600,
        )
        for forbidden in (
            self._fake_email,
            self._fake_path_home,
            nonstd_posix_path,
            custom_posix_path,
            win_abs_path,
            self._fake_tg_grp,
            self._fake_tg_uid,
            self._fake_url_q,
            self._fake_url_f,
            "hunter2secret99",
            "shortTok9988",
            self._fake_vault_path,
            syn_jtok,
            syn_japi,
            syn_jsec,
            syn_jpwd,
            syn_jauth,
        ):
            self.assertNotIn(forbidden, red, f"Leaked {forbidden!r} in redacted text: {red!r}")

        # Add invalid schedule timestamp + abnormal model/quota labels to fixtures to verify API-level strict whitelisting
        sched_raw = json.loads(self.schedules_file.read_text(encoding="utf-8"))
        sched_raw["tasks"]["task-bad-ts"] = {
            "id": "task-bad-ts",
            "name": f'Check {quoted_json_secrets} {nonstd_posix_path}',
            "enabled": False,
            "schedule_type": "cron",
            "schedule_expr": "0 8 * * *",
            "task_type": "check",
            "execution": {"model": "free text model /srv/private/data.json", "project": "agy-cli-bot"},
            "state": {
                "next_run_at": "NOT_A_VALID_ISO_TIMESTAMP_LEAK",
                "last_run_at": "INVALID_LAST_RUN_SECRET",
                "last_status": "ok",
                "run_count": 1,
            },
        }
        self.schedules_file.write_text(json.dumps(sched_raw), encoding="utf-8")

        cost_raw = json.loads(self.cost_ledger_file.read_text(encoding="utf-8"))
        hour_key = next(iter(cost_raw["conversations"]["conv-1"]["hours"].keys()))
        cost_raw["conversations"]["conv-1"]["hours"][hour_key]["bad free text model " + self._fake_email] = [
            1000, 0, 500, 1, 0.01, 0.01
        ]
        self.cost_ledger_file.write_text(json.dumps(cost_raw), encoding="utf-8")
        (self.tmp / "quota_usage.json").write_text(
            json.dumps({
                "groups": [
                    {
                        "name": "valid-group-1",
                        "buckets": [
                            {"name": "5h_window", "window": "5h", "remaining_fraction": 0.75},
                            {"name": "free text leak " + self._fake_email, "window": "bad window /srv/x", "remaining_fraction": 0.5},
                        ],
                    },
                    {
                        "name": "bad group with space & secret " + nonstd_posix_path,
                        "buckets": [],
                    },
                ]
            }),
            encoding="utf-8",
        )

        sess, _, sid = await self._login_magic("main", ADMIN_UID)
        csrf = sess["csrf_token"]

        forbidden_payload_tokens = (
            self._fake_ghp,
            self._fake_sk,
            BOT_TOKEN_MAIN,
            self._fake_email,
            self._fake_path_home,
            self._fake_path_tmp,
            self._fake_tg_grp,
            self._fake_tg_uid,
            self._fake_url_q,
            self._fake_url_f,
            "hunter2secret99",
            "shortTok9988",
            self._fake_vault_path,
            "RAW_PROMPT_MUST_NOT_LEAK",
            "RAW_SUMMARY_LEAK",
            "RAW_SCHED_ERR",
            str(GROUP_CHAT_ID),
        )

        # Read-only APIs work and have ZERO PII/secret/raw-text leakage
        for ep in ("/api/bots", "/api/jobs", "/api/schedules", "/api/costs?scope=all", "/api/overview"):
            resp = await self.client.get(ep, headers=self._cookie_hdr(sid))
            self.assertEqual(resp.status, 200, ep)
            txt = await resp.text()
            for tok in forbidden_payload_tokens:
                self.assertNotIn(tok, txt, f"{ep} leaked {tok!r}: {txt}")

        # Verify whitelisted schema for /api/jobs and /api/schedules (no raw summary_preview/error/last_error)
        jobs_data = await (await self.client.get("/api/jobs", headers=self._cookie_hdr(sid))).json()
        self.assertEqual(len(jobs_data["jobs"]), 1)
        j0 = jobs_data["jobs"][0]
        self.assertNotIn("summary_preview", j0)
        self.assertNotIn("error", j0)
        self.assertNotIn("prompt", j0)
        self.assertTrue(j0["has_summary"])
        self.assertTrue(j0["has_error"])
        self.assertEqual(j0["error_code"], "execution_error")

        sched_data = await (await self.client.get("/api/schedules", headers=self._cookie_hdr(sid))).json()
        self.assertEqual(sched_data["active"], 1)
        by_id = {s["id"]: s for s in sched_data["schedules"]}
        s0 = by_id["task-1"]
        self.assertNotIn("last_error", s0)
        self.assertNotIn("target_chat_id", json.dumps(sched_data))
        self.assertTrue(s0["has_last_error"])
        self.assertEqual(s0["next_run_at"], "2026-11-21T01:00:00Z")
        s_bad = by_id["task-bad-ts"]
        self.assertIsNone(s_bad["next_run_at"])
        self.assertIsNone(s_bad["last_run_at"])
        self.assertEqual(s_bad["model"], "unknown")
        self.assertNotIn("NOT_A_VALID_ISO_TIMESTAMP_LEAK", json.dumps(sched_data))
        self.assertNotIn("INVALID_LAST_RUN_SECRET", json.dumps(sched_data))
        self.assertNotIn(syn_jtok, json.dumps(sched_data))
        self.assertNotIn(nonstd_posix_path, json.dumps(sched_data))

        costs_data = await (await self.client.get("/api/costs?scope=all", headers=self._cookie_hdr(sid))).json()
        week_families = {r["family"] for r in costs_data["by_model_week"]}
        self.assertIn("gemini-3.8-flash", week_families)
        self.assertIn("unknown", week_families)
        self.assertNotIn(self._fake_email, json.dumps(costs_data))
        self.assertNotIn(nonstd_posix_path, json.dumps(costs_data))
        q_groups = costs_data["quota_groups"]
        self.assertEqual(q_groups[0]["name"], "valid-group-1")
        self.assertEqual(q_groups[0]["buckets"][0]["name"], "5h_window")
        self.assertEqual(q_groups[0]["buckets"][1]["name"], "unknown")
        self.assertEqual(q_groups[0]["buckets"][1]["window"], "unknown")
        self.assertEqual(q_groups[1]["name"], "unknown")

        # Management plane zero writes: unknown write endpoints return 404
        for method, path in (("POST", "/api/unknown-write"), ("PUT", "/api/rules"), ("DELETE", "/api/bots")):
            r_w = await self.client.request(
                method,
                path,
                headers={"Origin": self._origin(), "X-Studio-CSRF": csrf, **self._cookie_hdr(sid)},
            )
            self.assertEqual(r_w.status, 404)

        # Logout without CSRF -> 403
        r_no_csrf = await self.client.post(
            "/api/auth/logout",
            headers={"Origin": self._origin(), **self._cookie_hdr(sid)},
        )
        self.assertEqual(r_no_csrf.status, 403)

        # Logout with valid Origin + CSRF -> 200 and session invalidated
        r_out = await self.client.post(
            "/api/auth/logout",
            headers={"Origin": self._origin(), "X-Studio-CSRF": csrf, **self._cookie_hdr(sid)},
        )
        self.assertEqual(r_out.status, 200)
        r_after = await self.client.get("/api/auth/me", headers=self._cookie_hdr(sid))
        self.assertEqual(r_after.status, 401)

    # ---------------------------------------------------------------- 6. Live RBAC Downgrade & Revocation (HTTP)
    async def test_live_rbac_downgrade_and_instant_http_revocation(self) -> None:
        _, _, sid = await self._login_magic("main", ADMIN_UID)
        r1 = await self.client.get("/api/auth/me", headers=self._cookie_hdr(sid))
        self.assertEqual((await r1.json())["role"], "admin")

        # Downgrade ADMIN_UID to readonly in `.env`
        _write_env(
            self.bridge_dir / ".env",
            [
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_MAIN}",
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                f"AGY_TG_ADMIN_USERS={OUTSIDER_UID}",
                f"AGY_TG_READONLY_USERS={ADMIN_UID},{READONLY_UID}",
            ],
        )
        r2 = await self.client.get("/api/auth/me", headers=self._cookie_hdr(sid))
        self.assertEqual(r2.status, 200)
        self.assertEqual((await r2.json())["role"], "readonly")

        # Revoke ADMIN_UID completely from `.env`
        _write_env(
            self.bridge_dir / ".env",
            [
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_MAIN}",
                f"AGY_TG_ALLOWED_CHATS={READONLY_UID}",
                f"AGY_TG_READONLY_USERS={READONLY_UID}",
            ],
        )
        r3 = await self.client.get("/api/auth/me", headers=self._cookie_hdr(sid))
        self.assertEqual(r3.status, 403)
        self.assertEqual((await r3.json())["source"], "studio_auth")
        r4 = await self.client.get("/api/overview", headers=self._cookie_hdr(sid))
        self.assertEqual(r4.status, 401)

    # ---------------------------------------------------------------- 7. Isolated E2E: Browser WS Proxy, Downgrade/Revoke/Logout/Disconnect Takeover Release, Upload/Download & Status URL (P0-3, P0-4, P1)
    async def test_e2e_browser_proxy_revocation_downgrade_takeover_release_and_upload(self) -> None:
        lbs = _load_live_browser_module()
        lbs._BRIDGE_DIR = self.bridge_dir
        lbs.BRIDGE_ENV_FILES = {"main": self.bridge_dir / ".env", "sg": self.bridge_dir / ".env.sg"}

        # Construct isolated LiveBrowserHub (never launches Camoufox or touches pinned profile)
        hub = lbs.LiveBrowserHub({"public_url": ""}, self.live_token)
        hub.engine_mode = "async_hosted"
        hub.session_gen = 7
        hub.takeover_gen = 2
        hub.session_owner = ("main", ADMIN_UID)
        hub.url = f"https://portal.example.org/u/alice%40corp.com/view?token={self._fake_url_q}#{self._fake_url_f}"
        hub.title = f"Portal {self._fake_email}"
        hub.latest_jpeg = b"\xff\xd8\xff\xe0MOCK_JPEG_FRAME\xff\xd9"

        dl_file = self.tmp / "sample.txt"
        dl_file.write_text("hello-studio-download", encoding="utf-8")
        hub.downloads["dl-1"] = {
            "id": "dl-1",
            "path": str(dl_file),
            "filename": "sample.txt",
            "session_gen": 7,
            "owner_bot": "main",
            "owner_uid": ADMIN_UID,
            "created_ts": time.monotonic(),
        }

        class _FakeChooser:
            def __init__(self) -> None:
                self.files: list[str] = []

            async def set_files(self, paths: str | list[str]) -> None:
                self.files = [paths] if isinstance(paths, str) else list(paths)

        fake_chooser = _FakeChooser()
        hub.pending_filechoosers["fc-1"] = {
            "id": "fc-1",
            "chooser": fake_chooser,
            "page_id": None,
            "multiple": False,
            "created_ts": time.monotonic(),
            "session_gen": 7,
            "owner_bot": "main",
            "owner_uid": ADMIN_UID,
        }

        lb_app = web.Application()
        lb_app["hub"] = hub
        lb_app.router.add_get("/ws", lbs.handle_ws)
        lb_app.router.add_post("/api/upload", lbs.handle_api_upload)
        lb_app.router.add_get("/api/download/{download_id}", lbs.handle_api_download)
        lb_app.router.add_get("/internal/status", lbs.internal_status)

        lb_server = TestServer(lb_app)
        lb_client = TestClient(lb_server)
        await lb_client.start_server()
        try:
            # --- Direct live_browser_server delegated auth strict negative checks ---
            # 1) Reject X-Forwarded-For / CF-Connecting-IP on /api/download
            r_xff = await lb_client.get(
                "/api/download/dl-1",
                headers={
                    "X-Internal-Token": self.live_token,
                    "X-Studio-Bot": "main",
                    "X-Studio-User-Id": str(ADMIN_UID),
                    "X-Forwarded-For": "198.51.100.5",
                },
            )
            self.assertEqual(r_xff.status, 403)

            # 2) Reject caller-supplied X-Studio-Role header (must reject, not merely ignore!)
            r_role_hdr = await lb_client.get(
                "/api/download/dl-1",
                headers={
                    "X-Internal-Token": self.live_token,
                    "X-Studio-Bot": "main",
                    "X-Studio-User-Id": str(ADMIN_UID),
                    "X-Studio-Role": "admin",
                },
            )
            self.assertEqual(r_role_hdr.status, 403)

            # 3) Zero fallback: invalid X-TG-Init-Data + valid X-Internal-Token -> 403!
            r_nofb = await lb_client.get(
                "/api/download/dl-1",
                headers={
                    "X-TG-Init-Data": "hash=deadbeef&auth_date=1",
                    "X-Internal-Token": self.live_token,
                    "X-Studio-Bot": "main",
                    "X-Studio-User-Id": str(ADMIN_UID),
                },
            )
            self.assertEqual(r_nofb.status, 403)

            # 4) Direct WS: extra `role` field in `internal_auth` MUST BE REJECTED!
            async with lb_client.ws_connect("/ws", headers={"X-Internal-Token": self.live_token}) as dws:
                await dws.send_str(json.dumps({
                    "type": "internal_auth",
                    "bot": "main",
                    "user_id": READONLY_UID,
                    "role": "admin",
                }))
                err_role = json.loads((await dws.receive()).data)
                self.assertEqual(err_role["type"], "auth_error")
                close_role = await dws.receive()
                self.assertEqual(close_role.type, WSMsgType.CLOSE)

            # 5) Direct WS: invalid `auth` frame with valid X-Internal-Token -> NO fallback -> 4003
            async with lb_client.ws_connect("/ws", headers={"X-Internal-Token": self.live_token}) as dws2:
                await dws2.send_str(json.dumps({"type": "auth", "initData": "invalid"}))
                err_msg = json.loads((await dws2.receive()).data)
                self.assertEqual(err_msg["type"], "auth_error")
                close_msg = await dws2.receive()
                self.assertEqual(close_msg.type, WSMsgType.CLOSE)

            # --- Point Studio at isolated live_browser_server ---
            self.sources.live_browser_url = f"http://{lb_server.host}:{lb_server.port}"

            # Owner /api/browser/status returns STRICTLY origin (`scheme://host[:port]`, zero path/PII/query/fragment!)
            sess_adm, _, sid_adm = await self._login_magic("main", ADMIN_UID)
            csrf_adm = sess_adm["csrf_token"]
            r_bst_own = await self.client.get("/api/browser/status", headers=self._cookie_hdr(sid_adm))
            self.assertEqual(r_bst_own.status, 200)
            bst_own = await r_bst_own.json()
            self.assertEqual(bst_own["url"], "https://portal.example.org")
            self.assertNotIn("alice", bst_own["url"])
            self.assertNotIn("%40", bst_own["url"])
            self.assertNotIn(self._fake_url_q, bst_own["url"])
            self.assertNotIn(self._fake_url_f, bst_own["url"])
            self.assertNotIn(self._fake_email, bst_own["title"])

            # Non-owner /api/browser/status returns empty URL/title (restricted)
            _, _, sid_ro = await self._login_magic("main", READONLY_UID)
            r_bst_ro = await self.client.get("/api/browser/status", headers=self._cookie_hdr(sid_ro))
            self.assertEqual(r_bst_ro.status, 200)
            bst_ro = await r_bst_ro.json()
            self.assertTrue(bst_ro["session_restricted"])
            self.assertEqual(bst_ro["url"], "")
            self.assertEqual(bst_ro["title"], "")

            # --- P1: Multipart `/api/browser/upload` E2E (positive + negative) ---
            # Negative: missing CSRF -> 403
            form_bad = aiohttp.FormData()
            form_bad.add_field("file", b"hello-upload", filename="note.txt", content_type="text/plain")
            r_up_nocsrf = await self.client.post(
                "/api/browser/upload?chooser_id=fc-1",
                headers={"Origin": self._origin(), **self._cookie_hdr(sid_adm)},
                data=form_bad,
            )
            self.assertEqual(r_up_nocsrf.status, 403)

            # Negative: readonly user -> 403
            sess_ro_me = await (await self.client.get("/api/auth/me", headers=self._cookie_hdr(sid_ro))).json()
            form_ro = aiohttp.FormData()
            form_ro.add_field("file", b"hello-upload", filename="note.txt", content_type="text/plain")
            r_up_ro = await self.client.post(
                "/api/browser/upload?chooser_id=fc-1",
                headers={
                    "Origin": self._origin(),
                    "X-Studio-CSRF": sess_ro_me["csrf_token"],
                    **self._cookie_hdr(sid_ro),
                },
                data=form_ro,
            )
            self.assertEqual(r_up_ro.status, 403)

            # Positive: admin multipart upload succeeds & invokes Playwright filechooser.set_files!
            form_ok = aiohttp.FormData()
            form_ok.add_field("file", b"hello-studio-upload", filename="note.txt", content_type="text/plain")
            r_up_ok = await self.client.post(
                "/api/browser/upload?chooser_id=fc-1",
                headers={
                    "Origin": self._origin(),
                    "X-Studio-CSRF": csrf_adm,
                    **self._cookie_hdr(sid_adm),
                },
                data=form_ok,
            )
            self.assertEqual(r_up_ok.status, 200, await r_up_ok.text())
            self.assertEqual(len(fake_chooser.files), 1)
            self.assertTrue(fake_chooser.files[0].endswith("note.txt"))

            # --- Scenario A: Two admin WS sessions -> close 1 -> takeover PRESERVED; close last -> takeover RELEASED & AI resumed! ---
            _, _, sid_adm2 = await self._login_magic("main", ADMIN_UID)
            async with self.client.ws_connect(
                "/ws/browser", headers={"Origin": self._origin(), **self._cookie_hdr(sid_adm)}
            ) as cws1, self.client.ws_connect(
                "/ws/browser", headers={"Origin": self._origin(), **self._cookie_hdr(sid_adm2)}
            ) as cws2:
                # Drain initial auth_ok + state + jpeg on both
                for w in (cws1, cws2):
                    self.assertEqual(json.loads((await w.receive()).data)["role"], "admin")
                    self.assertEqual(json.loads((await w.receive()).data)["type"], "state")
                    self.assertEqual((await w.receive()).type, WSMsgType.BINARY)

                await hub.set_takeover(True, "Admin 1 takeover", owner=("main", ADMIN_UID))
                self.assertTrue(hub.takeover)
                self.assertFalse(hub.ai_allowed_event.is_set())

                # Close first tab while second eligible admin tab remains -> takeover MUST stay active
                await cws1.close()
                await asyncio.sleep(0.15)
                self.assertTrue(hub.takeover, "Takeover must stay active while another eligible admin WS remains")

            # Now both admin tabs closed -> takeover MUST auto-release & AI resume!
            for _ in range(20):
                if not hub.takeover and hub.ai_allowed_event.is_set():
                    break
                await asyncio.sleep(0.05)
            self.assertFalse(hub.takeover, "Takeover must release when last eligible admin disconnects")
            self.assertTrue(hub.ai_allowed_event.is_set(), "AI must resume when last eligible admin disconnects")

            # --- Scenario B: Disconnect while ONLY a readonly viewer remains -> takeover released & AI resumed! ---
            async with self.client.ws_connect(
                "/ws/browser", headers={"Origin": self._origin(), **self._cookie_hdr(sid_ro)}
            ) as ro_ws, self.client.ws_connect(
                "/ws/browser", headers={"Origin": self._origin(), **self._cookie_hdr(sid_adm)}
            ) as adm_ws:
                self.assertEqual(json.loads((await ro_ws.receive()).data)["role"], "readonly")
                _ = await ro_ws.receive()  # initial state
                self.assertEqual(json.loads((await adm_ws.receive()).data)["role"], "admin")
                _ = await adm_ws.receive()  # initial state
                _ = await adm_ws.receive()  # initial jpeg

                await hub.set_takeover(True, "Admin takeover with readonly bystander", owner=("main", ADMIN_UID))
                self.assertTrue(hub.takeover)
                self.assertFalse(hub.ai_allowed_event.is_set())

                await adm_ws.close()
                for _ in range(20):
                    if not hub.takeover and hub.ai_allowed_event.is_set():
                        break
                    await asyncio.sleep(0.05)
                self.assertFalse(hub.takeover, "Readonly viewer must NOT keep takeover alive after admin disconnects")
                self.assertTrue(hub.ai_allowed_event.is_set())

            # --- Scenario C: Logout while holding takeover -> WS closes immediately & takeover releases ---
            sess_lo, _, sid_lo = await self._login_magic("main", ADMIN_UID)
            async with self.client.ws_connect(
                "/ws/browser", headers={"Origin": self._origin(), **self._cookie_hdr(sid_lo)}
            ) as lo_ws:
                self.assertEqual(json.loads((await lo_ws.receive()).data)["role"], "admin")
                _ = await lo_ws.receive()
                _ = await lo_ws.receive()

                await hub.set_takeover(True, "Admin takeover before logout", owner=("main", ADMIN_UID))
                self.assertTrue(hub.takeover)

                r_lo = await self.client.post(
                    "/api/auth/logout",
                    headers={
                        "Origin": self._origin(),
                        "X-Studio-CSRF": sess_lo["csrf_token"],
                        **self._cookie_hdr(sid_lo),
                    },
                )
                self.assertEqual(r_lo.status, 200)
                closed_on_logout = False
                for _ in range(5):
                    nxt = await asyncio.wait_for(lo_ws.receive(), timeout=2.0)
                    if nxt.type in (WSMsgType.CLOSE, WSMsgType.CLOSED):
                        self.assertEqual(nxt.data, WS_CLOSE_AUTH_FORBIDDEN)
                        closed_on_logout = True
                        break
                self.assertTrue(closed_on_logout)
            for _ in range(20):
                if not hub.takeover and hub.ai_allowed_event.is_set():
                    break
                await asyncio.sleep(0.05)
            self.assertFalse(hub.takeover)
            self.assertTrue(hub.ai_allowed_event.is_set())

            # --- Scenario D: Idle downgrade `admin -> readonly` -> role_changed + close 4008 + takeover release + 0 post-downgrade frames ---
            _, _, sid_dg = await self._login_magic("main", ADMIN_UID)
            async with self.client.ws_connect(
                "/ws/browser", headers={"Origin": self._origin(), **self._cookie_hdr(sid_dg)}
            ) as dg_ws:
                self.assertEqual(json.loads((await dg_ws.receive()).data)["role"], "admin")
                _ = await dg_ws.receive()  # initial state
                _ = await dg_ws.receive()  # initial jpeg

                await hub.set_takeover(True, "Admin takeover before idle downgrade", owner=("main", ADMIN_UID))
                # Drain state broadcast from set_takeover
                _ = await asyncio.wait_for(dg_ws.receive(), timeout=1.0)
                self.assertTrue(hub.takeover)

                # Downgrade ADMIN_UID to readonly while WS is idle
                _write_env(
                    self.bridge_dir / ".env",
                    [
                        f"AGY_TG_BOT_TOKEN={BOT_TOKEN_MAIN}",
                        f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                        f"AGY_TG_ADMIN_USERS={ADMIN_UID_2}",
                        f"AGY_TG_READONLY_USERS={ADMIN_UID},{READONLY_UID}",
                    ],
                )
                # Even if upstream pushes a binary frame right after downgrade, 0 binary frames may leak!
                await hub.broadcast_frame(b"POST_DOWNGRADE_FRAME_MUST_NOT_LEAK")
                saw_role_changed = False
                saw_close_4008 = False
                for _ in range(6):
                    nxt = await asyncio.wait_for(dg_ws.receive(), timeout=2.0)
                    if nxt.type == WSMsgType.BINARY:
                        self.assertNotEqual(nxt.data, b"POST_DOWNGRADE_FRAME_MUST_NOT_LEAK")
                    elif nxt.type == WSMsgType.TEXT:
                        pl = json.loads(nxt.data)
                        if pl.get("type") == "role_changed":
                            saw_role_changed = True
                            self.assertEqual(pl.get("role"), "readonly")
                    elif nxt.type == WSMsgType.CLOSE:
                        self.assertEqual(nxt.data, WS_CLOSE_ROLE_CHANGED)
                        saw_close_4008 = True
                        break
                self.assertTrue(saw_role_changed, "Expected role_changed notice on idle downgrade")
                self.assertTrue(saw_close_4008, "Expected WS close code 4008 on downgrade")

            for _ in range(20):
                if not hub.takeover and hub.ai_allowed_event.is_set():
                    break
                await asyncio.sleep(0.05)
            self.assertFalse(hub.takeover, "Takeover must release after idle downgrade to readonly")
            self.assertTrue(hub.ai_allowed_event.is_set(), "AI must resume after idle downgrade")

            # --- Scenario E: Instant revocation during binary frame stream -> 0 post-revocation binary frames + close 4003 ---
            _write_env(
                self.bridge_dir / ".env",
                [
                    f"AGY_TG_BOT_TOKEN={BOT_TOKEN_MAIN}",
                    f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                    f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                    f"AGY_TG_READONLY_USERS={READONLY_UID}",
                ],
            )
            _, _, sid_rev = await self._login_magic("main", ADMIN_UID)
            async with self.client.ws_connect(
                "/ws/browser", headers={"Origin": self._origin(), **self._cookie_hdr(sid_rev)}
            ) as rev_ws:
                self.assertEqual(json.loads((await rev_ws.receive()).data)["role"], "admin")
                _ = await rev_ws.receive()  # state
                _ = await rev_ws.receive()  # initial jpeg

                await hub.set_takeover(True, "Admin takeover before revoke", owner=("main", ADMIN_UID))
                _ = await asyncio.wait_for(rev_ws.receive(), timeout=1.0)

                # Revoke ADMIN_UID completely, then push a binary frame upstream
                _write_env(
                    self.bridge_dir / ".env",
                    [
                        f"AGY_TG_BOT_TOKEN={BOT_TOKEN_MAIN}",
                        f"AGY_TG_ALLOWED_CHATS={READONLY_UID}",
                        f"AGY_TG_READONLY_USERS={READONLY_UID}",
                    ],
                )
                await hub.broadcast_frame(b"POST_REVOKE_BINARY_MUST_NOT_LEAK")
                saw_close_4003 = False
                for _ in range(6):
                    nxt = await asyncio.wait_for(rev_ws.receive(), timeout=2.0)
                    if nxt.type == WSMsgType.BINARY:
                        self.assertNotEqual(nxt.data, b"POST_REVOKE_BINARY_MUST_NOT_LEAK")
                    elif nxt.type == WSMsgType.CLOSE:
                        self.assertEqual(nxt.data, WS_CLOSE_AUTH_FORBIDDEN)
                        saw_close_4003 = True
                        break
                self.assertTrue(saw_close_4003)

            for _ in range(20):
                if not hub.takeover and hub.ai_allowed_event.is_set():
                    break
                await asyncio.sleep(0.05)
            self.assertFalse(hub.takeover)
            self.assertTrue(hub.ai_allowed_event.is_set())

            # --- Scenario F (P0-3 #1): Ownerless `wait-human` MUST NEVER be released by readonly or unrelated WS disconnect ---
            _write_env(
                self.bridge_dir / ".env",
                [
                    f"AGY_TG_BOT_TOKEN={BOT_TOKEN_MAIN}",
                    f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                    f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                    f"AGY_TG_READONLY_USERS={READONLY_UID}",
                ],
            )
            _, _, sid_adm_f = await self._login_magic("main", ADMIN_UID)
            # Case F1: takeover_owner = None (pure localhost wait-human)
            await hub.set_takeover(True, "Local CLI wait-human", owner=None)
            hub.takeover_owner = None
            self.assertTrue(hub.takeover)
            self.assertFalse(hub.ai_allowed_event.is_set())
            async with self.client.ws_connect(
                "/ws/browser", headers={"Origin": self._origin(), **self._cookie_hdr(sid_ro)}
            ) as ro_ws_f:
                _ = await ro_ws_f.receive()  # auth_ok
                _ = await ro_ws_f.receive()  # state
            await asyncio.sleep(0.15)
            self.assertTrue(hub.takeover, "Readonly WS disconnect MUST NOT release ownerless wait-human!")
            self.assertFalse(hub.ai_allowed_event.is_set(), "AI MUST stay paused on ownerless wait-human!")

            # Case F2: takeover_owner = ("main", None) (owner_user_id is None) + admin WS disconnect
            hub.takeover_owner = ("main", None)
            async with self.client.ws_connect(
                "/ws/browser", headers={"Origin": self._origin(), **self._cookie_hdr(sid_adm_f)}
            ) as adm_ws_f:
                _ = await adm_ws_f.receive()
                _ = await adm_ws_f.receive()
                _ = await adm_ws_f.receive()
            await asyncio.sleep(0.15)
            self.assertTrue(hub.takeover, "Remote WS disconnect MUST NOT release ownerless (user_id=None) takeover!")
            self.assertFalse(hub.ai_allowed_event.is_set())
            await hub.set_takeover(False, "Localhost cleanup")

            # --- Scenario G (P0-3 #2): Stalled downstream close MUST NOT delay upstream close ---
            upstream_closed_ev = asyncio.Event()
            downstream_unblock_ev = asyncio.Event()
            close_order: list[str] = []

            class _FakeUpstreamWS:
                closed = False

                async def close(self) -> None:
                    self.closed = True
                    close_order.append("upstream")
                    upstream_closed_ev.set()

            class _StalledClientWS:
                closed = False

                async def send_str(self, _data: str) -> None:
                    return None

                async def close(self, **_kw: object) -> None:
                    close_order.append("downstream_start")
                    await downstream_unblock_ev.wait()
                    self.closed = True

            fake_proxy = BrowserProxy(self.auth_mgr, self.sources)
            stalled_entry = {
                "client_ws": _StalledClientWS(),
                "upstream_ws": _FakeUpstreamWS(),
                "session_hash": "sess-stalled-hash",
                "bot": "main",
                "user_id": ADMIN_UID,
                "role": "admin",
                "closing": False,
            }
            fake_proxy._active_sockets[1] = stalled_entry
            t0 = time.monotonic()
            await fake_proxy._on_auth_revoked("sess-stalled-hash", None, None)
            elapsed = time.monotonic() - t0
            self.assertTrue(upstream_closed_ev.is_set(), "Upstream WS MUST close immediately before downstream ACK!")
            self.assertEqual(close_order[0], "upstream")
            self.assertLess(elapsed, 0.5, f"Revoke MUST NOT block waiting on stalled client close (took {elapsed:.2f}s)")
            downstream_unblock_ev.set()
            await asyncio.sleep(0.05)

            # --- Scenario H (P0-3 #3): Two independent cookie sessions for same user — logout 1 MUST NOT kill 2 ---
            sess_a, _, sid_a = await self._login_magic("main", ADMIN_UID)
            sess_b, _, sid_b = await self._login_magic("main", ADMIN_UID)
            self.assertNotEqual(sid_a, sid_b)
            async with self.client.ws_connect(
                "/ws/browser", headers={"Origin": self._origin(), **self._cookie_hdr(sid_a)}
            ) as ws_a, self.client.ws_connect(
                "/ws/browser", headers={"Origin": self._origin(), **self._cookie_hdr(sid_b)}
            ) as ws_b:
                for w in (ws_a, ws_b):
                    self.assertEqual(json.loads((await w.receive()).data)["role"], "admin")
                    _ = await w.receive()  # state
                    _ = await w.receive()  # jpeg

                # Logout ONLY session A
                r_lo_a = await self.client.post(
                    "/api/auth/logout",
                    headers={
                        "Origin": self._origin(),
                        "X-Studio-CSRF": sess_a["csrf_token"],
                        **self._cookie_hdr(sid_a),
                    },
                )
                self.assertEqual(r_lo_a.status, 200)

                # Session A WS closes with 4003
                closed_a = False
                for _ in range(5):
                    nxt = await asyncio.wait_for(ws_a.receive(), timeout=2.0)
                    if nxt.type in (WSMsgType.CLOSE, WSMsgType.CLOSED):
                        closed_a = True
                        break
                self.assertTrue(closed_a, "Logged-out session A WS must close")

                # Session B HTTP cookie and WS MUST remain completely alive!
                r_me_b = await self.client.get("/api/auth/me", headers=self._cookie_hdr(sid_b))
                self.assertEqual(r_me_b.status, 200)
                await ws_b.send_str(json.dumps({"type": "ping", "t": 12345}))
                pong_b = json.loads((await asyncio.wait_for(ws_b.receive(), timeout=2.0)).data)
                self.assertEqual(pong_b.get("type"), "pong")
                self.assertFalse(ws_b.closed)

            # --- Scenario I (P0-3 #4): Concurrent takeover generation change MUST NOT be clobbered by stale disconnect ---
            await hub.set_takeover(True, "Gen 1 takeover", owner=("main", ADMIN_UID))
            old_sgen, old_tgen = hub.session_gen, hub.takeover_gen
            # Simulate concurrent new takeover generation (or new session_gen) taking ownership
            hub.session_gen += 1
            await hub.set_takeover(True, "Gen 2 takeover", owner=("main", ADMIN_UID))
            new_sgen, new_tgen = hub.session_gen, hub.takeover_gen
            self.assertNotEqual((old_sgen, old_tgen), (new_sgen, new_tgen))

            stale_released = await hub.release_takeover_on_disconnect(
                "main",
                ADMIN_UID,
                had_admin_role=True,
                expected_session_gen=old_sgen,
                expected_takeover_gen=old_tgen,
            )
            self.assertFalse(stale_released, "Stale disconnect snapshot MUST NOT release concurrent new takeover gen!")
            self.assertTrue(hub.takeover)
            self.assertFalse(hub.ai_allowed_event.is_set())
            await hub.set_takeover(False, "Cleanup after gen test")

            # Readonly user download blocked with studio_auth
            r_ro_dl = await self.client.get("/api/browser/download/dl-1", headers=self._cookie_hdr(sid_ro))
            self.assertEqual(r_ro_dl.status, 403)
            self.assertEqual((await r_ro_dl.json())["source"], "studio_auth")
        finally:
            await lb_client.close()

        # Upstream unreachable clearly reports source="upstream"
        self.sources.live_browser_url = "http://127.0.0.1:19998"
        r_up = await self.client.get(
            "/ws/browser",
            headers={"Origin": self._origin(), **self._cookie_hdr(sid_ro)},
        )
        self.assertEqual(r_up.status, 502)
        self.assertEqual((await r_up.json())["source"], "upstream")


class TestBridgeWebuiCommand(unittest.TestCase):
    """Verify `/webui` & `/studio` slash commands in `bridge/bridge.py` & `access_control.py`."""

    def test_webui_group_blocked_private_dm_fragment_and_preview_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            studio_cfg = Path(tmp) / "studio_cfg"
            studio_cfg.mkdir()
            tok_val = "EXAMPLE_STUDIO_INTERNAL_TOK_FOR_BRIDGE_TEST"
            (studio_cfg / "local.token").write_text(tok_val + "\n", encoding="utf-8")

            env_patch = {
                "AGY_BOT_BUS_DIR": os.path.join(tmp, "bus"),
                "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
                "AGY_MEMORY_TAINT_FILE": os.path.join(tmp, "memory_taint.json"),
                "AGY_TG_WORKDIR": os.path.join(tmp, "workdir"),
                "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
                "AGY_TG_ALLOWED_CHATS": f"{GROUP_CHAT_ID},{ADMIN_UID},{READONLY_UID}",
                "AGY_TG_ADMIN_USERS": str(ADMIN_UID),
                "AGY_TG_READONLY_USERS": str(READONLY_UID),
                "AGY_TG_BOT_TOKEN": BOT_TOKEN_MAIN,
                "AGY_TG_ENV_FILE": os.path.join(tmp, ".env"),
                "AGY_STUDIO_CONFIG_DIR": str(studio_cfg),
                "AGY_STUDIO_URL": "http://127.0.0.1:18796",
            }
            with mock.patch.dict(os.environ, env_patch, clear=False):
                import access_control  # noqa: E402
                import bot_bus  # noqa: E402
                import bridge  # noqa: E402

                importlib.reload(access_control)
                importlib.reload(bot_bus)
                importlib.reload(bridge)

                # Both admin & readonly allowed to execute /webui and /studio
                self.assertTrue(access_control.is_command_allowed_for_role("readonly", "/webui", "")[0])
                self.assertTrue(access_control.is_command_allowed_for_role("readonly", "/studio", "")[0])
                self.assertTrue(access_control.is_command_allowed_for_role("admin", "/webui", "")[0])

                sent_calls: list[tuple[str, dict]] = []
                fake_resp = mock.MagicMock()
                fake_resp.status_code = 200
                fake_resp.content = b'{"ok":true}'
                fake_resp.json.return_value = {
                    "ok": True,
                    "url": "https://studio.example.com/auth/magic#t=ONE_TIME_TOKEN_EXAMPLE",
                    "role": "readonly",
                    "ttl_seconds": 60,
                }

                with (
                    mock.patch.object(
                        bridge,
                        "send",
                        side_effect=lambda cid, txt, **kw: sent_calls.append((txt, kw)) or 1,
                    ),
                    mock.patch.object(bridge.requests, "post", return_value=fake_resp) as post_mock,
                ):
                    # 1) Group chat MUST refuse to issue magic link
                    bridge.cmd_webui(GROUP_CHAT_ID, "", from_user={"id": ADMIN_UID})
                    self.assertEqual(post_mock.call_count, 0)
                    self.assertIn("私聊", sent_calls[-1][0])

                    # 2) Private DM issues magic link with disable_web_page_preview=True
                    bridge.cmd_webui(READONLY_UID, "", from_user={"id": READONLY_UID})
                    self.assertEqual(post_mock.call_count, 1)
                    call_kw = post_mock.call_args.kwargs
                    self.assertEqual(call_kw["headers"]["X-Studio-Internal-Token"], tok_val)
                    self.assertEqual(call_kw["json"], {"bot": "main", "user_id": READONLY_UID})
                    last_txt, last_kw = sent_calls[-1]
                    self.assertIn("https://studio.example.com/auth/magic#t=ONE_TIME_TOKEN_EXAMPLE", last_txt)
                    self.assertTrue(last_kw.get("disable_web_page_preview"))
                    self.assertIn("60 秒", last_txt)
                    self.assertNotIn(tok_val, last_txt)

                # 3) Verify send() forwards disable_web_page_preview & link_preview_options to Telegram API
                tg_kw_captured: list[dict] = []
                fake_tg = mock.MagicMock()
                fake_tg.status_code = 200
                fake_tg.json.return_value = {"ok": True, "result": {"message_id": 99}}
                with mock.patch.object(
                    bridge,
                    "tg_send_in_route",
                    side_effect=lambda method, cid, **kw: tg_kw_captured.append(kw) or fake_tg,
                ):
                    bridge.send(READONLY_UID, "https://studio.example.com/auth/magic#t=ABC", disable_web_page_preview=True)
                self.assertEqual(len(tg_kw_captured), 1)
                self.assertTrue(tg_kw_captured[0].get("disable_web_page_preview"))
                self.assertEqual(tg_kw_captured[0].get("link_preview_options"), {"is_disabled": True})


class TestStudioPasswordAuth(unittest.IsolatedAsyncioTestCase):
    """Comprehensive Prod-Release tests covering C1–C8 for AGY Studio password auth mode."""

    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.bridge_dir = self.tmp / "bridge_env"
        self.bridge_dir.mkdir()
        self.studio_cfg = self.tmp / "studio_cfg"
        self.live_cfg = self.tmp / "live_cfg"
        self.live_cfg.mkdir()
        self.bus_dir = self.tmp / "bus"
        (self.bus_dir / "jobs").mkdir(parents=True)
        self.dist_dir = self.tmp / "dist"
        (self.dist_dir / "assets").mkdir(parents=True)
        (self.dist_dir / "index.html").write_text(
            "<!doctype html><html><head><title>AGY Studio</title></head><body><div id='root'></div></body></html>",
            encoding="utf-8",
        )
        self.live_token = "EXAMPLE_LIVE_LOCAL_TOKEN_FOR_PW_AUTH_TEST"
        (self.live_cfg / "local.token").write_text(self.live_token + "\n", encoding="utf-8")

        _write_env(
            self.bridge_dir / ".env",
            [
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_MAIN}",
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID},{GROUP_CHAT_ID}",
                f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                f"AGY_TG_READONLY_USERS={READONLY_UID}",
            ],
        )

        now = time.time()
        self.clock = [now]
        self.users_file = self.studio_cfg / "users.json"
        self.auth_mgr = StudioAuthManager(
            config_dir=self.studio_cfg,
            bridge_dir=self.bridge_dir,
            users_file=self.users_file,
            public_url=PUBLIC_ORIGIN,
            allowed_origins="",
            now_fn=lambda: self.clock[0],
        )
        self.sources = StudioDataSources(
            bus_dir=self.bus_dir,
            schedules_file=self.tmp / "scheduled_tasks.json",
            cost_ledger_file=self.tmp / "cost_ledger_v2.json",
            cost_config_file=self.tmp / "cost_config.json",
            quota_cache_file=self.tmp / "quota_usage.json",
            live_browser_url="http://127.0.0.1:19999",
            live_browser_config_dir=self.live_cfg,
        )
        self.app = create_app(
            auth_mgr=self.auth_mgr,
            data_sources=self.sources,
            static_dist_dir=self.dist_dir,
            revocation_check_interval=0.06,
        )
        self.server = TestServer(self.app)
        self.client = TestClient(self.server)
        await self.client.start_server()

    async def asyncTearDown(self) -> None:
        await self.client.close()
        self._tmp.cleanup()

    def _seed_user(
        self,
        username: str,
        password: str,
        *,
        role: str = "admin",
        bot: str = "main",
        user_id: int = ADMIN_UID,
        enabled: bool = True,
        must_change_password: bool = False,
        password_version: int = 1,
    ) -> None:
        existing: dict = {}
        if self.users_file.is_file():
            try:
                existing = json.loads(self.users_file.read_text(encoding="utf-8")).get("users", {})
            except Exception:
                existing = {}
        now_ts = int(self.clock[0])
        existing[username.strip().lower()] = {
            "username": username.strip(),
            "password_hash": hash_password_scrypt(password),
            "role": role,
            "bot": bot,
            "user_id": user_id,
            "enabled": enabled,
            "must_change_password": must_change_password,
            "password_version": password_version,
            "created_at": now_ts,
            "updated_at": now_ts,
        }
        save_users_file_atomic(self.users_file, existing)

    async def _login_pw(
        self,
        username: str,
        password: str,
        *,
        client: TestClient | None = None,
        origin: str = PUBLIC_ORIGIN,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[aiohttp.ClientResponse, dict, str]:
        cli = client or self.client
        hdrs = {"Origin": origin}
        if extra_headers:
            hdrs.update(extra_headers)
        resp = await cli.post(
            "/api/auth/login",
            headers=hdrs,
            json={"username": username, "password": password},
        )
        body = await resp.json()
        sid = _extract_session_cookie(resp)
        return resp, body, sid

    # ---------------------------------------------------------------- C1
    async def test_c1_auth_mode_isolation_and_fail_fast(self) -> None:
        # Default auth_mode is password
        self.assertEqual(self.auth_mgr.auth_mode, "password")

        # Fail-fast on invalid auth_mode (explicit arg or env var)
        for bad_mode in ("", "invalid", "oauth", "PASSWORD_X"):
            with self.assertRaises(ValueError):
                StudioAuthManager(
                    config_dir=self.studio_cfg,
                    bridge_dir=self.bridge_dir,
                    auth_mode=bad_mode,
                )
        with mock.patch.dict(os.environ, {"AGY_STUDIO_AUTH_MODE": "unsupported_mode"}):
            with self.assertRaises(ValueError):
                StudioAuthManager(config_dir=self.studio_cfg, bridge_dir=self.bridge_dir)

        # In password mode: legacy endpoints return 403 studio_auth without issuing any token/session
        init_admin = _make_tg_init_data(BOT_TOKEN_MAIN, ADMIN_UID, auth_date=int(self.clock[0]))
        r_tg = await self.client.post(
            "/api/auth/telegram",
            headers={"Origin": PUBLIC_ORIGIN},
            json={"initData": init_admin},
        )
        self.assertEqual(r_tg.status, 403)
        self.assertEqual((await r_tg.json())["source"], "studio_auth")
        self.assertEqual(_extract_session_cookie(r_tg), "")

        r_red = await self.client.post(
            "/api/auth/redeem",
            headers={"Origin": PUBLIC_ORIGIN},
            json={"token": "EXAMPLE_MAGIC_TOK_1234567890"},
        )
        self.assertEqual(r_red.status, 403)
        self.assertEqual((await r_red.json())["source"], "studio_auth")
        self.assertEqual(_extract_session_cookie(r_red), "")

        r_ml = await self.client.post(
            "/internal/magic-link",
            headers={"X-Studio-Internal-Token": self.auth_mgr.local_token},
            json={"bot": "main", "user_id": ADMIN_UID},
        )
        self.assertEqual(r_ml.status, 403)
        ml_body = await r_ml.json()
        self.assertEqual(ml_body["source"], "studio_auth")
        self.assertIn("账号密码", ml_body["error"])
        self.assertEqual(len(self.auth_mgr._magic_tokens), 0)
        self.assertEqual(len(self.auth_mgr._sessions), 0)

        # In legacy mode: password endpoints return 403 studio_auth
        legacy_auth = StudioAuthManager(
            config_dir=self.studio_cfg,
            bridge_dir=self.bridge_dir,
            auth_mode="legacy",
            public_url=PUBLIC_ORIGIN,
            now_fn=lambda: self.clock[0],
        )
        legacy_app = create_app(auth_mgr=legacy_auth, data_sources=self.sources, static_dist_dir=self.dist_dir)
        async with TestClient(TestServer(legacy_app)) as lcli:
            r_login = await lcli.post(
                "/api/auth/login",
                headers={"Origin": PUBLIC_ORIGIN},
                json={"username": "ExampleAdmin", "password": "EXAMPLE_INITIAL_PASS_01"},
            )
            self.assertEqual(r_login.status, 403)
            self.assertEqual((await r_login.json())["source"], "studio_auth")

            r_chg = await lcli.post(
                "/api/auth/change-password",
                headers={"Origin": PUBLIC_ORIGIN},
                json={
                    "current_password": "EXAMPLE_INITIAL_PASS_01",
                    "new_password": "EXAMPLE_ROTATED_PASS_02",
                },
            )
            self.assertEqual(r_chg.status, 403)
            self.assertEqual((await r_chg.json())["source"], "studio_auth")

    # ---------------------------------------------------------------- C2
    async def test_c2_users_store_fail_closed_scrypt_and_cli(self) -> None:
        # 1. Missing users.json -> fail-closed (401), MUST NOT auto-create users.json
        r_miss, b_miss, _ = await self._login_pw("ExampleAdmin", "EXAMPLE_INITIAL_PASS_01")
        self.assertEqual(r_miss.status, 401)
        self.assertEqual(b_miss["error"], "账号或密码错误")
        self.assertFalse(self.users_file.exists())

        # 2. Empty / corrupt JSON / missing fields / invalid scrypt params -> fail-closed
        self.studio_cfg.mkdir(parents=True, exist_ok=True)
        for bad_payload in (
            "",
            "{not-json",
            json.dumps({"version": 1, "users": "not-a-dict"}),
            json.dumps({"version": 1, "users": {"exampleadmin": {"username": "ExampleAdmin"}}}),
            json.dumps({
                "version": 1,
                "users": {
                    "exampleadmin": {
                        "username": "ExampleAdmin",
                        "password_hash": "scrypt$100$8$1$AAAA$BBBB",  # invalid n < 1024
                        "role": "admin",
                        "bot": "main",
                        "user_id": ADMIN_UID,
                        "enabled": True,
                        "must_change_password": False,
                        "password_version": 1,
                        "created_at": 1,
                        "updated_at": 1,
                    }
                },
            }),
        ):
            self.users_file.write_text(bad_payload, encoding="utf-8")
            r_bad, b_bad, _ = await self._login_pw("ExampleAdmin", "EXAMPLE_INITIAL_PASS_01")
            self.assertEqual(r_bad.status, 401)
            self.assertEqual(b_bad["error"], "账号或密码错误")
            self.auth_mgr.rate_limiter._ip_buckets.clear()
            self.auth_mgr.rate_limiter._user_buckets.clear()
            self.auth_mgr.rate_limiter._global_failures.clear()

        self.users_file.unlink(missing_ok=True)

        # 3. CLI strictly rejects plaintext --password flag
        import io
        from contextlib import redirect_stderr, redirect_stdout

        err_buf = io.StringIO()
        with redirect_stderr(err_buf):
            with self.assertRaises(SystemExit) as ctx_ex:
                studio_auth_cli_main([
                    "set-user",
                    "--users-file",
                    str(self.users_file),
                    "--username",
                    "ExampleAdmin",
                    "--bot",
                    "main",
                    "--user-id",
                    str(ADMIN_UID),
                    "--password",
                    "DUMMY_FORBIDDEN_FLAG_PW",
                ])
        self.assertNotEqual(ctx_ex.exception.code, 0)

        # 4. CLI set-user via --password-env writes 0700 dir + 0600 file + valid scrypt$16384$8$1$ hash
        out_buf = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"DUMMY_STUDIO_PW_ENV": "EXAMPLE_CLI_PASS_01"}),
            redirect_stdout(out_buf),
        ):
            rc = studio_auth_cli_main([
                "set-user",
                "--users-file",
                str(self.users_file),
                "--username",
                "ExampleAdmin",
                "--bot",
                "main",
                "--user-id",
                str(ADMIN_UID),
                "--role",
                "admin",
                "--password-env",
                "DUMMY_STUDIO_PW_ENV",
            ])
        self.assertEqual(rc, 0)
        self.assertTrue(self.users_file.is_file())
        self.assertEqual(os.stat(self.users_file).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.users_file.parent).st_mode & 0o777, 0o700)

        doc1 = json.loads(self.users_file.read_text(encoding="utf-8"))
        rec1 = doc1["users"]["exampleadmin"]
        self.assertEqual(rec1["username"], "ExampleAdmin")
        self.assertTrue(rec1["password_hash"].startswith("scrypt$16384$8$1$"))
        self.assertEqual(rec1["password_version"], 1)
        self.assertTrue(rec1["must_change_password"])

        # 5. CLI list-users NEVER prints password_hash
        list_buf = io.StringIO()
        with redirect_stdout(list_buf):
            rc_list = studio_auth_cli_main(["list-users", "--users-file", str(self.users_file), "--json"])
        self.assertEqual(rc_list, 0)
        list_txt = list_buf.getvalue()
        self.assertNotIn("password_hash", list_txt)
        self.assertNotIn("scrypt$", list_txt)
        self.assertIn("ExampleAdmin", list_txt)

        # 6. CLI set-user via --password-stdin updates with fresh salt & increments password_version
        out_buf2 = io.StringIO()
        with (
            mock.patch.object(sys, "stdin", io.StringIO("EXAMPLE_CLI_PASS_02\n")),
            redirect_stdout(out_buf2),
        ):
            rc2 = studio_auth_cli_main([
                "set-user",
                "--users-file",
                str(self.users_file),
                "--username",
                "ExampleAdmin",
                "--bot",
                "main",
                "--user-id",
                str(ADMIN_UID),
                "--role",
                "admin",
                "--no-must-change-password",
                "--password-stdin",
            ])
        self.assertEqual(rc2, 0)
        doc2 = json.loads(self.users_file.read_text(encoding="utf-8"))
        rec2 = doc2["users"]["exampleadmin"]
        self.assertEqual(rec2["password_version"], 2)
        self.assertFalse(rec2["must_change_password"])
        self.assertNotEqual(rec2["password_hash"], rec1["password_hash"])

        # Case-insensitive login succeeds with new password
        r_ok, b_ok, sid_ok = await self._login_pw("exampleadmin", "EXAMPLE_CLI_PASS_02")
        self.assertEqual(r_ok.status, 200)
        self.assertEqual(b_ok["username"], "ExampleAdmin")
        self.assertTrue(sid_ok)

        # 7. CLI disable-user, enable-user, delete-user
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                studio_auth_cli_main(["disable-user", "--users-file", str(self.users_file), "--username", "ExampleAdmin"]),
                0,
            )
            self.assertEqual(
                studio_auth_cli_main(["enable-user", "--users-file", str(self.users_file), "--username", "ExampleAdmin"]),
                0,
            )
            self.assertEqual(
                studio_auth_cli_main(["delete-user", "--users-file", str(self.users_file), "--username", "ExampleAdmin"]),
                0,
            )
        self.assertEqual(json.loads(self.users_file.read_text(encoding="utf-8"))["users"], {})

        # 8. CLI strictly disables flag abbreviation (allow_abbrev=False)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx_abbr:
                studio_auth_cli_main([
                    "list-users",
                    "--users",
                    str(self.users_file),
                ])
        self.assertNotEqual(ctx_abbr.exception.code, 0)

    # ---------------------------------------------------------------- C2 (BLOCK-2 regression)
    async def test_c2_single_corrupt_record_fails_whole_store_closed(self) -> None:
        import io
        from contextlib import redirect_stderr, redirect_stdout

        self._seed_user("ExampleGood", "EXAMPLE_GOOD_PASS_01", role="admin", must_change_password=False)
        valid_doc = json.loads(self.users_file.read_text(encoding="utf-8"))
        good_rec = dict(valid_doc["users"]["examplegood"])

        corrupt_cases: list[tuple[str, dict]] = [
            (
                "missing_fields",
                {"examplegood": good_rec, "brokenuser": {"username": "BrokenUser"}},
            ),
            (
                "invalid_scrypt_params",
                {
                    "examplegood": good_rec,
                    "brokenuser": {
                        **good_rec,
                        "username": "BrokenUser",
                        "password_hash": "scrypt$100$8$1$AAAA$BBBB",
                    },
                },
            ),
            (
                "key_username_mismatch",
                {
                    "examplegood": good_rec,
                    "wrongkey": {
                        **good_rec,
                        "username": "OtherName",
                    },
                },
            ),
            (
                "blank_key",
                {
                    "examplegood": good_rec,
                    "   ": {
                        **good_rec,
                        "username": "BlankKeyUser",
                    },
                },
            ),
        ]

        for label, users_payload in corrupt_cases:
            raw_text = json.dumps({"version": 1, "users": users_payload}, indent=2, ensure_ascii=False) + "\n"
            self.users_file.write_text(raw_text, encoding="utf-8")

            # 1. load_users_file MUST fail-closed for the whole store
            store_ok, loaded = load_users_file(self.users_file)
            self.assertFalse(store_ok, label)
            self.assertEqual(loaded, {}, label)

            # 2. Login even for the valid account MUST fail-closed with 401
            self.auth_mgr.rate_limiter._ip_buckets.clear()
            self.auth_mgr.rate_limiter._user_buckets.clear()
            self.auth_mgr.rate_limiter._global_failures.clear()
            r_login, b_login, _ = await self._login_pw("ExampleGood", "EXAMPLE_GOOD_PASS_01")
            self.assertEqual(r_login.status, 401, label)
            self.assertEqual(b_login["error"], "账号或密码错误", label)

            # 3. CLI list-users MUST exit non-zero
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc_list = studio_auth_cli_main(["list-users", "--users-file", str(self.users_file)])
            self.assertNotEqual(rc_list, 0, label)

            # 4. CLI set-user MUST exit non-zero AND preserve original users.json untouched
            with (
                mock.patch.dict(os.environ, {"DUMMY_STUDIO_PW_ENV": "EXAMPLE_NEW_USER_PASS_1"}),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                rc_set = studio_auth_cli_main([
                    "set-user",
                    "--users-file",
                    str(self.users_file),
                    "--username",
                    "AnotherGood",
                    "--bot",
                    "main",
                    "--user-id",
                    str(ADMIN_UID),
                    "--role",
                    "readonly",
                    "--password-env",
                    "DUMMY_STUDIO_PW_ENV",
                ])
            self.assertNotEqual(rc_set, 0, label)
            self.assertEqual(self.users_file.read_text(encoding="utf-8"), raw_text, label)

    # ---------------------------------------------------------------- C3
    async def test_c3_live_rbac_least_privilege_intersection_and_ws_revocation(self) -> None:
        # Seed 4 intersection combinations
        self._seed_user("UserAdmAdm", "EXAMPLE_PASS_A1", role="admin", user_id=ADMIN_UID)
        self._seed_user("UserAdmRo", "EXAMPLE_PASS_A2", role="admin", user_id=READONLY_UID)
        self._seed_user("UserRoAdm", "EXAMPLE_PASS_A3", role="readonly", user_id=ADMIN_UID)
        self._seed_user("UserRoRo", "EXAMPLE_PASS_A4", role="readonly", user_id=READONLY_UID)
        self._seed_user("UserDenied", "EXAMPLE_PASS_A5", role="admin", user_id=OUTSIDER_UID)

        for uname, pw, exp_role in (
            ("UserAdmAdm", "EXAMPLE_PASS_A1", "admin"),
            ("UserAdmRo", "EXAMPLE_PASS_A2", "readonly"),
            ("UserRoAdm", "EXAMPLE_PASS_A3", "readonly"),
            ("UserRoRo", "EXAMPLE_PASS_A4", "readonly"),
        ):
            r, body, _ = await self._login_pw(uname, pw)
            self.assertEqual(r.status, 200, uname)
            self.assertEqual(body["role"], exp_role, uname)

        r_den, b_den, _ = await self._login_pw("UserDenied", "EXAMPLE_PASS_A5")
        self.assertEqual(r_den.status, 401)
        self.assertEqual(b_den["error"], "账号或密码错误")

        # Isolated E2E WS test with mock live_browser_server verifying internal_auth payload (NO role!)
        # + live downgrade from users.json (role_changed + 4008) + disable / version bump / delete / env revoke (4003, 0 frames)
        lbs = _load_live_browser_module()
        lbs._BRIDGE_DIR = self.bridge_dir
        lbs.BRIDGE_ENV_FILES = {"main": self.bridge_dir / ".env"}
        hub = lbs.LiveBrowserHub({"public_url": ""}, self.live_token)
        hub.engine_mode = "async_hosted"
        hub.session_gen = 3
        hub.session_owner = ("main", ADMIN_UID)
        hub.latest_jpeg = b"\xff\xd8\xff\xe0MOCK_PW_JPEG\xff\xd9"

        captured_handshakes: list[dict] = []
        orig_handle_ws = lbs.handle_ws

        async def _spy_ws(request: web.Request) -> web.StreamResponse:
            return await orig_handle_ws(request)

        lb_app = web.Application()
        lb_app["hub"] = hub
        lb_app.router.add_get("/ws", _spy_ws)
        lb_srv = TestServer(lb_app)
        lb_cli = TestClient(lb_srv)
        await lb_cli.start_server()
        try:
            self.sources.live_browser_url = f"http://{lb_srv.host}:{lb_srv.port}"

            # Spy on upstream send_str for internal_auth frame
            orig_ws_connect = self.app[HTTP_SESSION_KEY].ws_connect

            async def _wrapped_ws_connect(*args, **kwargs):
                uws = await orig_ws_connect(*args, **kwargs)
                orig_send = uws.send_str

                async def _spy_send(data: str):
                    try:
                        pl = json.loads(data)
                        if isinstance(pl, dict) and pl.get("type") == "internal_auth":
                            captured_handshakes.append(pl)
                    except Exception:
                        pass
                    return await orig_send(data)

                uws.send_str = _spy_send  # type: ignore[method-assign]
                return uws

            with mock.patch.object(self.app[HTTP_SESSION_KEY], "ws_connect", side_effect=_wrapped_ws_connect):
                _, _, sid_adm = await self._login_pw("UserAdmAdm", "EXAMPLE_PASS_A1")
                async with self.client.ws_connect(
                    "/ws/browser",
                    headers={"Origin": PUBLIC_ORIGIN, "Cookie": f"{SESSION_COOKIE_NAME}={sid_adm}"},
                ) as ws1:
                    auth_ok = json.loads((await ws1.receive()).data)
                    self.assertEqual(auth_ok["role"], "admin")
                    _ = await ws1.receive()  # state
                    _ = await ws1.receive()  # jpeg

                    # Verify upstream handshake strictly sent ONLY {type, bot, user_id} (NO role!)
                    self.assertTrue(captured_handshakes)
                    self.assertEqual(set(captured_handshakes[-1].keys()), {"type", "bot", "user_id"})
                    self.assertNotIn("role", captured_handshakes[-1])

                    # Downgrade role in users.json (`admin` -> `readonly`) -> role_changed + close 4008
                    self._seed_user("UserAdmAdm", "EXAMPLE_PASS_A1", role="readonly", user_id=ADMIN_UID, password_version=1)
                    await hub.broadcast_frame(b"LEAK_AFTER_USERS_JSON_DOWNGRADE")
                    saw_rc = False
                    saw_4008 = False
                    for _ in range(6):
                        nxt = await asyncio.wait_for(ws1.receive(), timeout=2.0)
                        if nxt.type == WSMsgType.BINARY:
                            self.assertNotEqual(nxt.data, b"LEAK_AFTER_USERS_JSON_DOWNGRADE")
                        elif nxt.type == WSMsgType.TEXT:
                            pl = json.loads(nxt.data)
                            if pl.get("type") == "role_changed":
                                saw_rc = True
                                self.assertEqual(pl["role"], "readonly")
                        elif nxt.type == WSMsgType.CLOSE:
                            self.assertEqual(nxt.data, WS_CLOSE_ROLE_CHANGED)
                            saw_4008 = True
                            break
                    self.assertTrue(saw_rc)
                    self.assertTrue(saw_4008)

                # Test each revocation trigger on active WS: enabled=False, password_version bump, delete, .env removal
                for mode in ("disable", "bump_version", "delete", "env_revoke"):
                    _write_env(
                        self.bridge_dir / ".env",
                        [
                            f"AGY_TG_BOT_TOKEN={BOT_TOKEN_MAIN}",
                            f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                            f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                            f"AGY_TG_READONLY_USERS={READONLY_UID}",
                        ],
                    )
                    self._seed_user("UserAdmAdm", "EXAMPLE_PASS_A1", role="admin", user_id=ADMIN_UID, enabled=True, password_version=5)
                    r_in, _, sid_live = await self._login_pw("UserAdmAdm", "EXAMPLE_PASS_A1")
                    self.assertEqual(r_in.status, 200, mode)
                    async with self.client.ws_connect(
                        "/ws/browser",
                        headers={"Origin": PUBLIC_ORIGIN, "Cookie": f"{SESSION_COOKIE_NAME}={sid_live}"},
                    ) as ws_rev:
                        _ = await ws_rev.receive()  # auth_ok
                        _ = await ws_rev.receive()  # state
                        _ = await ws_rev.receive()  # jpeg

                        if mode == "disable":
                            self._seed_user("UserAdmAdm", "EXAMPLE_PASS_A1", role="admin", user_id=ADMIN_UID, enabled=False, password_version=5)
                        elif mode == "bump_version":
                            self._seed_user("UserAdmAdm", "EXAMPLE_PASS_A1", role="admin", user_id=ADMIN_UID, enabled=True, password_version=6)
                        elif mode == "delete":
                            doc = json.loads(self.users_file.read_text(encoding="utf-8"))
                            doc["users"].pop("useradmadm", None)
                            save_users_file_atomic(self.users_file, doc["users"])
                        elif mode == "env_revoke":
                            _write_env(
                                self.bridge_dir / ".env",
                                [
                                    f"AGY_TG_BOT_TOKEN={BOT_TOKEN_MAIN}",
                                    f"AGY_TG_ALLOWED_CHATS={READONLY_UID}",
                                    f"AGY_TG_READONLY_USERS={READONLY_UID}",
                                ],
                            )

                        await hub.broadcast_frame(b"POST_REVOKE_LEAK_FRAME")
                        saw_4003 = False
                        for _ in range(6):
                            nxt = await asyncio.wait_for(ws_rev.receive(), timeout=2.0)
                            if nxt.type == WSMsgType.BINARY:
                                self.assertNotEqual(nxt.data, b"POST_REVOKE_LEAK_FRAME", mode)
                            elif nxt.type == WSMsgType.CLOSE:
                                self.assertEqual(nxt.data, WS_CLOSE_AUTH_FORBIDDEN, mode)
                                saw_4003 = True
                                break
                        self.assertTrue(saw_4003, f"Expected WS 4003 on {mode}")

                    # Session evicted -> /api/auth/me must reject (401/403)
                    r_after = await self.client.get(
                        "/api/auth/me",
                        headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_live}"},
                    )
                    self.assertIn(r_after.status, (401, 403), mode)
        finally:
            await lb_cli.close()

    # ---------------------------------------------------------------- C4
    async def test_c4_must_change_password_hard_gate_http_ws_and_runtime(self) -> None:
        self._seed_user("ExampleInit", "EXAMPLE_TEMP_PASS_01", role="admin", must_change_password=True)
        r_in, body_in, sid = await self._login_pw("ExampleInit", "EXAMPLE_TEMP_PASS_01")
        self.assertEqual(r_in.status, 200)
        self.assertTrue(body_in["must_change_password"])
        csrf = body_in["csrf_token"]
        ck = {"Cookie": f"{SESSION_COOKIE_NAME}={sid}"}

        # /api/auth/me allowed with allow_password_change_only=True
        r_me = await self.client.get("/api/auth/me", headers=ck)
        self.assertEqual(r_me.status, 200)
        me_body = await r_me.json()
        self.assertTrue(me_body["must_change_password"])
        self.assertEqual(me_body["auth_mode"], "password")

        # ALL business APIs + WS MUST return 403 password_change_required BEFORE touching StudioDataSources or ws_connect!
        with (
            mock.patch.object(self.sources, "get_overview", side_effect=AssertionError("must not call get_overview")),
            mock.patch.object(self.sources, "get_bots", side_effect=AssertionError("must not call get_bots")),
            mock.patch.object(self.sources, "get_jobs", side_effect=AssertionError("must not call get_jobs")),
            mock.patch.object(self.sources, "get_schedules", side_effect=AssertionError("must not call get_schedules")),
            mock.patch.object(self.sources, "get_costs", side_effect=AssertionError("must not call get_costs")),
            mock.patch.object(self.sources, "get_browser_status", side_effect=AssertionError("must not call get_browser_status")),
            mock.patch.object(self.app[HTTP_SESSION_KEY], "ws_connect", side_effect=AssertionError("must not connect upstream WS")),
        ):
            for ep in (
                "/api/overview",
                "/api/bots",
                "/api/jobs",
                "/api/schedules",
                "/api/costs",
                "/api/browser/status",
                "/api/browser/download/dl-1",
            ):
                resp = await self.client.get(ep, headers=ck)
                self.assertEqual(resp.status, 403, ep)
                pl = await resp.json()
                self.assertEqual(pl["source"], "studio_auth")
                self.assertEqual(pl["error"], "password_change_required", ep)

            r_up = await self.client.post(
                "/api/browser/upload",
                headers={"Origin": PUBLIC_ORIGIN, "X-Studio-CSRF": csrf, **ck},
                data=b"dummy",
            )
            self.assertEqual(r_up.status, 403)
            self.assertEqual((await r_up.json())["error"], "password_change_required")

            r_ws = await self.client.get("/ws/browser", headers={"Origin": PUBLIC_ORIGIN, **ck})
            self.assertEqual(r_ws.status, 403)
            self.assertEqual((await r_ws.json())["error"], "password_change_required")

        # Logout IS allowed while must_change_password=True
        r_lo = await self.client.post(
            "/api/auth/logout",
            headers={"Origin": PUBLIC_ORIGIN, "X-Studio-CSRF": csrf, **ck},
        )
        self.assertEqual(r_lo.status, 200)

        # Runtime flip: active WS session closes with 4003 when must_change_password flips False -> True
        self._seed_user("ExampleFlip", "EXAMPLE_FLIP_PASS_01", role="admin", must_change_password=False)
        lbs = _load_live_browser_module()
        lbs._BRIDGE_DIR = self.bridge_dir
        lbs.BRIDGE_ENV_FILES = {"main": self.bridge_dir / ".env"}
        hub = lbs.LiveBrowserHub({"public_url": ""}, self.live_token)
        hub.engine_mode = "async_hosted"
        hub.session_gen = 4
        hub.session_owner = ("main", ADMIN_UID)
        hub.latest_jpeg = b"\xff\xd8\xff\xe0MOCK_FLIP_JPEG\xff\xd9"
        lb_app = web.Application()
        lb_app["hub"] = hub
        lb_app.router.add_get("/ws", lbs.handle_ws)
        lb_srv = TestServer(lb_app)
        lb_cli = TestClient(lb_srv)
        await lb_cli.start_server()
        try:
            self.sources.live_browser_url = f"http://{lb_srv.host}:{lb_srv.port}"
            _, _, sid_flip = await self._login_pw("ExampleFlip", "EXAMPLE_FLIP_PASS_01")
            ck_f = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_flip}"}
            async with self.client.ws_connect("/ws/browser", headers={"Origin": PUBLIC_ORIGIN, **ck_f}) as ws_f:
                _ = await ws_f.receive()  # auth_ok
                _ = await ws_f.receive()  # state
                _ = await ws_f.receive()  # jpeg

                # Flip must_change_password=True externally without changing password_version
                self._seed_user("ExampleFlip", "EXAMPLE_FLIP_PASS_01", role="admin", must_change_password=True, password_version=1)
                await hub.broadcast_frame(b"LEAK_AFTER_MUST_CHANGE_FLIP")
                saw_err = False
                saw_4003 = False
                for _ in range(6):
                    nxt = await asyncio.wait_for(ws_f.receive(), timeout=2.0)
                    if nxt.type == WSMsgType.BINARY:
                        self.assertNotEqual(nxt.data, b"LEAK_AFTER_MUST_CHANGE_FLIP")
                    elif nxt.type == WSMsgType.TEXT:
                        pl = json.loads(nxt.data)
                        if pl.get("type") == "auth_error" and pl.get("error") == "password_change_required":
                            saw_err = True
                    elif nxt.type == WSMsgType.CLOSE:
                        self.assertEqual(nxt.data, WS_CLOSE_AUTH_FORBIDDEN)
                        saw_4003 = True
                        break
                self.assertTrue(saw_err)
                self.assertTrue(saw_4003)

            # Session still valid on /api/auth/me (so user can change password), blocked on /api/bots
            self.assertEqual((await self.client.get("/api/auth/me", headers=ck_f)).status, 200)
            r_bots = await self.client.get("/api/bots", headers=ck_f)
            self.assertEqual(r_bots.status, 403)
            self.assertEqual((await r_bots.json())["error"], "password_change_required")
        finally:
            await lb_cli.close()

    # ---------------------------------------------------------------- C5
    async def test_c5_change_password_policy_csrf_origin_rotation_and_sibling_ws_eviction(self) -> None:
        self._seed_user("ExampleUser", "EXAMPLE_OLD_PASS_01", role="admin", must_change_password=False)

        lbs = _load_live_browser_module()
        lbs._BRIDGE_DIR = self.bridge_dir
        lbs.BRIDGE_ENV_FILES = {"main": self.bridge_dir / ".env"}
        hub = lbs.LiveBrowserHub({"public_url": ""}, self.live_token)
        hub.engine_mode = "async_hosted"
        hub.session_gen = 5
        hub.session_owner = ("main", ADMIN_UID)
        hub.latest_jpeg = b"\xff\xd8\xff\xe0MOCK_ROT_JPEG\xff\xd9"
        lb_app = web.Application()
        lb_app["hub"] = hub
        lb_app.router.add_get("/ws", lbs.handle_ws)
        lb_srv = TestServer(lb_app)
        lb_cli = TestClient(lb_srv)
        await lb_cli.start_server()
        try:
            self.sources.live_browser_url = f"http://{lb_srv.host}:{lb_srv.port}"

            # Two sibling sessions for the same user
            _, sess_self, sid_self = await self._login_pw("ExampleUser", "EXAMPLE_OLD_PASS_01")
            _, sess_sib, sid_sib = await self._login_pw("ExampleUser", "EXAMPLE_OLD_PASS_01")
            csrf_self = sess_self["csrf_token"]
            ck_self = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_self}"}
            ck_sib = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_sib}"}

            # Cross-origin & missing CSRF -> 403
            r_xorig = await self.client.post(
                "/api/auth/change-password",
                headers={"Origin": "https://evil.example.com", "X-Studio-CSRF": csrf_self, **ck_self},
                json={"current_password": "EXAMPLE_OLD_PASS_01", "new_password": "EXAMPLE_NEW_PASS_02"},
            )
            self.assertEqual(r_xorig.status, 403)

            r_nocsrf = await self.client.post(
                "/api/auth/change-password",
                headers={"Origin": PUBLIC_ORIGIN, **ck_self},
                json={"current_password": "EXAMPLE_OLD_PASS_01", "new_password": "EXAMPLE_NEW_PASS_02"},
            )
            self.assertEqual(r_nocsrf.status, 403)

            # Policy rejections -> 400
            for bad_new in (
                "",
                "short7!",
                "A" * 129,
                "        ",
                "EXAMPLE_OLD_PASS_01",  # equals current
                "exampleuser",  # equals username case-insensitively
                "EXAMPLEUSER",
            ):
                r_pol = await self.client.post(
                    "/api/auth/change-password",
                    headers={"Origin": PUBLIC_ORIGIN, "X-Studio-CSRF": csrf_self, **ck_self},
                    json={"current_password": "EXAMPLE_OLD_PASS_01", "new_password": bad_new},
                )
                self.assertEqual(r_pol.status, 400, f"Expected 400 for bad_new={bad_new!r}")

            # Wrong current password -> 401
            r_wrong = await self.client.post(
                "/api/auth/change-password",
                headers={"Origin": PUBLIC_ORIGIN, "X-Studio-CSRF": csrf_self, **ck_self},
                json={"current_password": "DUMMY_WRONG_CURR_99", "new_password": "EXAMPLE_NEW_PASS_02"},
            )
            self.assertEqual(r_wrong.status, 401)

            # Open active WS on BOTH sibling and caller's old session
            old_hash = json.loads(self.users_file.read_text(encoding="utf-8"))["users"]["exampleuser"]["password_hash"]
            async with (
                self.client.ws_connect("/ws/browser", headers={"Origin": PUBLIC_ORIGIN, **ck_self}) as ws_self_old,
                self.client.ws_connect("/ws/browser", headers={"Origin": PUBLIC_ORIGIN, **ck_sib}) as ws_sib,
            ):
                for w in (ws_self_old, ws_sib):
                    _ = await w.receive()  # auth_ok
                    _ = await w.receive()  # state
                    _ = await w.receive()  # jpeg

                # Valid password change!
                r_ok = await self.client.post(
                    "/api/auth/change-password",
                    headers={"Origin": PUBLIC_ORIGIN, "X-Studio-CSRF": csrf_self, **ck_self},
                    json={"current_password": "EXAMPLE_OLD_PASS_01", "new_password": "EXAMPLE_NEW_PASS_02"},
                )
                self.assertEqual(r_ok.status, 200)
                sc_hdr = r_ok.headers.get("Set-Cookie", "")
                self.assertIn("HttpOnly", sc_hdr)
                self.assertIn("Secure", sc_hdr)
                self.assertIn("SameSite=Lax", sc_hdr)
                sid_new = _extract_session_cookie(r_ok)
                body_new = await r_ok.json()
                self.assertTrue(sid_new)
                self.assertNotEqual(sid_new, sid_self)
                self.assertNotEqual(body_new["csrf_token"], csrf_self)
                self.assertFalse(body_new["must_change_password"])

                # BOTH sibling WS AND caller's old WS must close immediately with 4003
                for label, w in (("ws_self_old", ws_self_old), ("ws_sib", ws_sib)):
                    saw_4003 = False
                    for _ in range(6):
                        nxt = await asyncio.wait_for(w.receive(), timeout=2.0)
                        if nxt.type in (WSMsgType.CLOSE, WSMsgType.CLOSED):
                            self.assertEqual(nxt.data, WS_CLOSE_AUTH_FORBIDDEN, label)
                            saw_4003 = True
                            break
                    self.assertTrue(saw_4003, f"Expected {label} closed with 4003")

            # Disk persistence & permissions check
            self.assertEqual(os.stat(self.users_file).st_mode & 0o777, 0o600)
            rec_after = json.loads(self.users_file.read_text(encoding="utf-8"))["users"]["exampleuser"]
            self.assertEqual(rec_after["password_version"], 2)
            self.assertFalse(rec_after["must_change_password"])
            self.assertNotEqual(rec_after["password_hash"], old_hash)

            # Old session & sibling session both invalidated; new session works on API & fresh WS!
            self.assertEqual((await self.client.get("/api/auth/me", headers=ck_self)).status, 401)
            self.assertEqual((await self.client.get("/api/auth/me", headers=ck_sib)).status, 401)
            ck_new = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_new}"}
            self.assertEqual((await self.client.get("/api/bots", headers=ck_new)).status, 200)
            async with self.client.ws_connect("/ws/browser", headers={"Origin": PUBLIC_ORIGIN, **ck_new}) as ws_new:
                self.assertEqual(json.loads((await ws_new.receive()).data)["role"], "admin")

            # Old password fails, new password succeeds
            self.assertEqual((await self._login_pw("ExampleUser", "EXAMPLE_OLD_PASS_01"))[0].status, 401)
            self.assertEqual((await self._login_pw("ExampleUser", "EXAMPLE_NEW_PASS_02"))[0].status, 200)
        finally:
            await lb_cli.close()

    # ---------------------------------------------------------------- C5 (BLOCK-1 regression A)
    async def test_c5_concurrent_change_password_preserves_winner_session(self) -> None:
        import threading
        import studio.auth as auth_mod

        self._seed_user("ExampleRace", "EXAMPLE_RACE_OLD_01", role="admin", must_change_password=False)
        _, sess_a, sid_a = await self._login_pw("ExampleRace", "EXAMPLE_RACE_OLD_01")
        _, sess_b, sid_b = await self._login_pw("ExampleRace", "EXAMPLE_RACE_OLD_01")
        csrf_a = sess_a["csrf_token"]
        csrf_b = sess_b["csrf_token"]

        # Synchronize both concurrent requests inside hash_password_scrypt so BOTH pass pre-check &
        # current-password verification before either acquires the write lock.
        orig_hash = auth_mod.hash_password_scrypt
        barrier = threading.Barrier(2, timeout=5.0)

        def _sync_hash(pw: str) -> str:
            h = orig_hash(pw)
            barrier.wait()
            return h

        async def _post_change(sid: str, csrf: str, new_pw: str):
            resp = await self.client.post(
                "/api/auth/change-password",
                headers={
                    "Origin": PUBLIC_ORIGIN,
                    "X-Studio-CSRF": csrf,
                    "Cookie": f"{SESSION_COOKIE_NAME}={sid}",
                },
                json={"current_password": "EXAMPLE_RACE_OLD_01", "new_password": new_pw},
            )
            return resp.status, _extract_session_cookie(resp), await resp.json()

        with mock.patch.object(auth_mod, "hash_password_scrypt", side_effect=_sync_hash):
            res_a, res_b = await asyncio.gather(
                _post_change(sid_a, csrf_a, "EXAMPLE_RACE_NEW_A1"),
                _post_change(sid_b, csrf_b, "EXAMPLE_RACE_NEW_B2"),
            )

        statuses = sorted([res_a[0], res_b[0]])
        self.assertEqual(statuses, [200, 403])
        winner = res_a if res_a[0] == 200 else res_b
        sid_win = winner[1]
        self.assertTrue(sid_win)

        # After BOTH winner and loser have completed, winner's rotated cookie MUST remain valid (200)
        ck_win = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_win}"}
        r_me = await self.client.get("/api/auth/me", headers=ck_win)
        self.assertEqual(r_me.status, 200)
        self.assertEqual((await r_me.json())["username"], "ExampleRace")
        r_bots = await self.client.get("/api/bots", headers=ck_win)
        self.assertEqual(r_bots.status, 200)

        # Both old v1 cookies are invalidated
        self.assertIn(
            (await self.client.get("/api/auth/me", headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"})).status,
            (401, 403),
        )
        self.assertIn(
            (await self.client.get("/api/auth/me", headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_b}"})).status,
            (401, 403),
        )

    # ---------------------------------------------------------------- C5 (BLOCK-1 regression B)
    async def test_c5_stale_v1_session_cannot_evict_v2_http_or_ws(self) -> None:
        import io
        from contextlib import redirect_stdout

        self._seed_user("ExampleIso", "EXAMPLE_ISO_V1_01", role="admin", must_change_password=False)

        lbs = _load_live_browser_module()
        lbs._BRIDGE_DIR = self.bridge_dir
        lbs.BRIDGE_ENV_FILES = {"main": self.bridge_dir / ".env"}
        hub = lbs.LiveBrowserHub({"public_url": ""}, self.live_token)
        hub.engine_mode = "async_hosted"
        hub.session_gen = 6
        hub.session_owner = ("main", ADMIN_UID)
        hub.latest_jpeg = b"\xff\xd8\xff\xe0MOCK_ISO_JPEG\xff\xd9"
        lb_app = web.Application()
        lb_app["hub"] = hub
        lb_app.router.add_get("/ws", lbs.handle_ws)
        lb_srv = TestServer(lb_app)
        lb_cli = TestClient(lb_srv)
        await lb_cli.start_server()
        try:
            self.sources.live_browser_url = f"http://{lb_srv.host}:{lb_srv.port}"

            # 1. Obtain old v1 session
            r_v1, sess_v1, sid_v1 = await self._login_pw("ExampleIso", "EXAMPLE_ISO_V1_01")
            self.assertEqual(r_v1.status, 200)
            csrf_v1 = sess_v1["csrf_token"]
            ck_v1 = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_v1}"}

            # 2. Externally rotate password via CLI -> password_version bumps v1 -> v2
            with (
                mock.patch.dict(os.environ, {"DUMMY_ISO_V2_PW": "EXAMPLE_ISO_V2_02"}),
                redirect_stdout(io.StringIO()),
            ):
                rc = studio_auth_cli_main([
                    "set-user",
                    "--users-file",
                    str(self.users_file),
                    "--username",
                    "ExampleIso",
                    "--bot",
                    "main",
                    "--user-id",
                    str(ADMIN_UID),
                    "--role",
                    "admin",
                    "--no-must-change-password",
                    "--password-env",
                    "DUMMY_ISO_V2_PW",
                ])
            self.assertEqual(rc, 0)

            # 3. User logs in with v2 password (two sibling v2 logins must not evict each other) + opens /ws/browser
            r_v2, _, sid_v2 = await self._login_pw("ExampleIso", "EXAMPLE_ISO_V2_02")
            self.assertEqual(r_v2.status, 200)
            r_v2_sib, _, sid_v2_sib = await self._login_pw("ExampleIso", "EXAMPLE_ISO_V2_02")
            self.assertEqual(r_v2_sib.status, 200)
            ck_v2 = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_v2}"}
            ck_v2_sib = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_v2_sib}"}

            async with self.client.ws_connect("/ws/browser", headers={"Origin": PUBLIC_ORIGIN, **ck_v2}) as ws_v2:
                auth_ok = json.loads((await ws_v2.receive()).data)
                self.assertEqual(auth_ok["role"], "admin")
                _ = await ws_v2.receive()  # state
                _ = await ws_v2.receive()  # jpeg

                # 4a. Old tab sends stale v1 cookie to GET /api/auth/me and POST /api/auth/change-password
                r_old_me = await self.client.get("/api/auth/me", headers=ck_v1)
                self.assertIn(r_old_me.status, (401, 403))
                r_old_cp = await self.client.post(
                    "/api/auth/change-password",
                    headers={"Origin": PUBLIC_ORIGIN, "X-Studio-CSRF": csrf_v1, **ck_v1},
                    json={"current_password": "EXAMPLE_ISO_V1_01", "new_password": "EXAMPLE_ISO_V3_03"},
                )
                self.assertIn(r_old_cp.status, (401, 403))

                # 4b. Also explicitly exercise the in-memory version-mismatch branches in
                # authenticate_session_hash and change_password with lingering v1 sessions
                stale_raw_a = "EXAMPLE_STALE_V1_SID_A_1234567890"
                stale_hash_a = hashlib.sha256(stale_raw_a.encode("utf-8")).hexdigest()
                self.auth_mgr._sessions[stale_hash_a] = {
                    "session_hash": stale_hash_a,
                    "bot": "main",
                    "user_id": ADMIN_UID,
                    "role": "admin",
                    "auth_track": "password",
                    "csrf_token": "EXAMPLE_STALE_CSRF_A",
                    "user": {"id": ADMIN_UID, "username": "ExampleIso"},
                    "username": "ExampleIso",
                    "username_key": "exampleiso",
                    "password_version": 1,
                    "must_change_password": False,
                    "created_at": self.clock[0],
                    "last_seen": self.clock[0],
                    "expires_at": self.clock[0] + 3600,
                }
                r_stale_me = await self.client.get(
                    "/api/auth/me",
                    headers={"Cookie": f"{SESSION_COOKIE_NAME}={stale_raw_a}"},
                )
                self.assertEqual(r_stale_me.status, 403)
                self.assertNotIn(stale_hash_a, self.auth_mgr._sessions)

                stale_sess_b = {
                    "session_hash": hashlib.sha256(b"EXAMPLE_STALE_V1_SID_B").hexdigest(),
                    "bot": "main",
                    "user_id": ADMIN_UID,
                    "role": "admin",
                    "auth_track": "password",
                    "csrf_token": "EXAMPLE_STALE_CSRF_B",
                    "user": {"id": ADMIN_UID, "username": "ExampleIso"},
                    "username": "ExampleIso",
                    "username_key": "exampleiso",
                    "password_version": 1,
                    "must_change_password": False,
                    "created_at": self.clock[0],
                    "last_seen": self.clock[0],
                    "expires_at": self.clock[0] + 3600,
                }
                self.auth_mgr._sessions[stale_sess_b["session_hash"]] = dict(stale_sess_b)
                ok_cp, _, _, _, status_cp, _ = await self.auth_mgr.change_password(
                    stale_sess_b,
                    "EXAMPLE_ISO_V1_01",
                    "EXAMPLE_ISO_V3_03",
                    client_ip="127.0.0.1",
                )
                self.assertFalse(ok_cp)
                self.assertEqual(status_cp, 403)
                self.assertNotIn(stale_sess_b["session_hash"], self.auth_mgr._sessions)

                # 5. v2 HTTP sessions (primary + sibling) AND active v2 /ws/browser MUST remain completely unaffected!
                self.assertEqual((await self.client.get("/api/auth/me", headers=ck_v2)).status, 200)
                self.assertEqual((await self.client.get("/api/bots", headers=ck_v2)).status, 200)
                self.assertEqual((await self.client.get("/api/auth/me", headers=ck_v2_sib)).status, 200)
                self.assertFalse(ws_v2.closed)

                await hub.broadcast_frame(b"V2_STILL_ALIVE_FRAME")
                saw_frame = False
                for _ in range(4):
                    nxt = await asyncio.wait_for(ws_v2.receive(), timeout=2.0)
                    self.assertNotIn(nxt.type, (WSMsgType.CLOSE, WSMsgType.CLOSED))
                    if nxt.type == WSMsgType.BINARY and nxt.data == b"V2_STILL_ALIVE_FRAME":
                        saw_frame = True
                        break
                self.assertTrue(saw_frame, "Active v2 /ws/browser must keep receiving frames")
        finally:
            await lb_cli.close()

    # ---------------------------------------------------------------- C5 (BLOCK-1R regression)
    async def test_c5_login_scrypt_toctou_during_password_change_preserves_v2_session_and_ws(self) -> None:
        import studio.auth as auth_mod

        self._seed_user("ExampleToctou", "EXAMPLE_TOCTOU_V1_01", role="admin", must_change_password=False)

        lbs = _load_live_browser_module()
        lbs._BRIDGE_DIR = self.bridge_dir
        lbs.BRIDGE_ENV_FILES = {"main": self.bridge_dir / ".env"}
        hub = lbs.LiveBrowserHub({"public_url": ""}, self.live_token)
        hub.engine_mode = "async_hosted"
        hub.session_gen = 7
        hub.session_owner = ("main", ADMIN_UID)
        hub.latest_jpeg = b"\xff\xd8\xff\xe0MOCK_TOCTOU_JPEG\xff\xd9"
        lb_app = web.Application()
        lb_app["hub"] = hub
        lb_app.router.add_get("/ws", lbs.handle_ws)
        lb_srv = TestServer(lb_app)
        lb_cli = TestClient(lb_srv)
        await lb_cli.start_server()
        try:
            self.sources.live_browser_url = f"http://{lb_srv.host}:{lb_srv.port}"

            # 1. Obtain a legitimate v1 session to execute password rotation concurrently
            r_init, sess_init, sid_init = await self._login_pw("ExampleToctou", "EXAMPLE_TOCTOU_V1_01")
            self.assertEqual(r_init.status, 200)
            csrf_init = sess_init["csrf_token"]
            ck_init = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_init}"}

            # 2. Deterministically pause one v1 authenticate_password inside _run_scrypt_bounded
            orig_run_scrypt = self.auth_mgr._run_scrypt_bounded
            v1_scrypt_entered = asyncio.Event()
            release_v1_login = asyncio.Event()
            paused_once = False

            async def _hooked_run_scrypt(fn, *args):
                nonlocal paused_once
                res = await orig_run_scrypt(fn, *args)
                if (
                    not paused_once
                    and fn is auth_mod.verify_scrypt_hash
                    and args
                    and args[0] == "EXAMPLE_TOCTOU_V1_01"
                ):
                    paused_once = True
                    v1_scrypt_entered.set()
                    await release_v1_login.wait()
                return res

            with mock.patch.object(self.auth_mgr, "_run_scrypt_bounded", side_effect=_hooked_run_scrypt):
                t_v1_login = asyncio.create_task(
                    self._login_pw("ExampleToctou", "EXAMPLE_TOCTOU_V1_01")
                )
                await asyncio.wait_for(v1_scrypt_entered.wait(), timeout=5.0)

                # 3. While v1 login is suspended in scrypt, rotate password v1 -> v2 and open active v2 WS
                r_cp = await self.client.post(
                    "/api/auth/change-password",
                    headers={
                        "Origin": PUBLIC_ORIGIN,
                        "X-Studio-CSRF": csrf_init,
                        **ck_init,
                    },
                    json={
                        "current_password": "EXAMPLE_TOCTOU_V1_01",
                        "new_password": "EXAMPLE_TOCTOU_V2_02",
                    },
                )
                self.assertEqual(r_cp.status, 200)
                sid_v2 = _extract_session_cookie(r_cp)
                self.assertTrue(sid_v2)
                ck_v2 = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_v2}"}

                # Seed 1 failed login after rotation so we can verify stale v1 login does NOT clear rate limit
                r_seed_fail, _, _ = await self._login_pw("ExampleToctou", "DUMMY_WRONG_PASS_99")
                self.assertEqual(r_seed_fail.status, 401)
                failures_before = len(self.auth_mgr.rate_limiter._user_buckets.get("exampletoctou", ()))
                self.assertEqual(failures_before, 1)

                async with self.client.ws_connect("/ws/browser", headers={"Origin": PUBLIC_ORIGIN, **ck_v2}) as ws_v2:
                    auth_ok = json.loads((await ws_v2.receive()).data)
                    self.assertEqual(auth_ok["role"], "admin")
                    _ = await ws_v2.receive()  # state
                    _ = await ws_v2.receive()  # jpeg

                    # 4. Resume suspended v1 login -> MUST fail 401, issue NO cookie, keep/increment rate limit
                    release_v1_login.set()
                    r_v1_stale, body_v1_stale, sid_v1_stale = await asyncio.wait_for(t_v1_login, timeout=5.0)
                    self.assertEqual(r_v1_stale.status, 401)
                    self.assertEqual(body_v1_stale["error"], "账号或密码错误")
                    self.assertEqual(sid_v1_stale, "")
                    self.assertNotIn("Set-Cookie", r_v1_stale.headers)
                    failures_after = len(self.auth_mgr.rate_limiter._user_buckets.get("exampletoctou", ()))
                    self.assertEqual(failures_after, failures_before + 1)

                    # 5. Active v2 HTTP session AND /ws/browser MUST remain untouched and receive frames
                    r_v2_me = await self.client.get("/api/auth/me", headers=ck_v2)
                    self.assertEqual(r_v2_me.status, 200)
                    self.assertEqual((await r_v2_me.json())["username"], "ExampleToctou")
                    self.assertFalse(ws_v2.closed)

                    await hub.broadcast_frame(b"V2_AFTER_TOCTOU_FRAME")
                    saw_frame = False
                    for _ in range(4):
                        nxt = await asyncio.wait_for(ws_v2.receive(), timeout=2.0)
                        self.assertNotIn(nxt.type, (WSMsgType.CLOSE, WSMsgType.CLOSED))
                        if nxt.type == WSMsgType.BINARY and nxt.data == b"V2_AFTER_TOCTOU_FRAME":
                            saw_frame = True
                            break
                    self.assertTrue(saw_frame, "Active v2 /ws/browser must keep receiving frames after stale v1 login")

                    # 6. Defense-in-depth monotonicity: direct stale-version eviction with expected_password_version=1
                    # MUST NEVER evict newer password_version=2 HTTP session or active WS
                    await self.auth_mgr._evict_stale_username_sessions(
                        "exampletoctou",
                        expected_password_version=1,
                        expected_bot="main",
                        expected_user_id=ADMIN_UID,
                    )
                    self.assertEqual((await self.client.get("/api/auth/me", headers=ck_v2)).status, 200)
                    self.assertFalse(ws_v2.closed)
                    await hub.broadcast_frame(b"V2_AFTER_MONOTONIC_EVICT_FRAME")
                    saw_frame2 = False
                    for _ in range(4):
                        nxt = await asyncio.wait_for(ws_v2.receive(), timeout=2.0)
                        self.assertNotIn(nxt.type, (WSMsgType.CLOSE, WSMsgType.CLOSED))
                        if nxt.type == WSMsgType.BINARY and nxt.data == b"V2_AFTER_MONOTONIC_EVICT_FRAME":
                            saw_frame2 = True
                            break
                    self.assertTrue(saw_frame2, "Monotonicity guard must preserve v2 WS when expected_password_version=1")
        finally:
            await lb_cli.close()

    # ---------------------------------------------------------------- C6
    async def test_c6_anti_enumeration_constant_time_ip_spoof_and_bounded_rate_limit(self) -> None:
        self._seed_user("ExampleActive", "EXAMPLE_ACTIVE_PASS_1", role="admin", enabled=True)
        self._seed_user("ExampleDisabled", "EXAMPLE_DIS_PASS_1", role="admin", enabled=False)
        self._seed_user("ExampleDenied", "EXAMPLE_DEN_PASS_1", role="admin", user_id=OUTSIDER_UID)

        # 1. Input length bounds reject BEFORE entering scrypt
        import studio.auth as auth_mod

        with (
            mock.patch.object(auth_mod, "verify_scrypt_hash", side_effect=AssertionError("must not run scrypt")),
            mock.patch.object(auth_mod, "run_dummy_scrypt", side_effect=AssertionError("must not run dummy scrypt")),
        ):
            r_long_u, _, _ = await self._login_pw("U" * 65, "EXAMPLE_PASS_1234")
            self.assertEqual(r_long_u.status, 400)
            # Over MAX_PASSWORD_LEN (128 chars) rejected O(1) before UTF-8 encoding / scrypt
            r_long_p_129, _, _ = await self._login_pw("ExampleActive", "P" * 129)
            self.assertEqual(r_long_p_129.status, 400)
            r_long_p, _, _ = await self._login_pw("ExampleActive", "P" * 257)
            self.assertEqual(r_long_p.status, 400)
            # Multi-byte UTF-8 > 256 bytes even when len(str) <= 128
            r_utf8_p, _, _ = await self._login_pw("ExampleActive", "密" * 90)
            self.assertEqual(r_utf8_p.status, 400)

        # 2. Constant-time anti-enumeration: nonexistent, disabled, env-denied, wrong-password ALL run scrypt & return identical 401
        scrypt_calls: list[str] = []
        orig_verify = auth_mod.verify_scrypt_hash
        orig_dummy = auth_mod.run_dummy_scrypt

        def _spy_verify(pw: str, h: str) -> bool:
            scrypt_calls.append("verify")
            return orig_verify(pw, h)

        def _spy_dummy(pw: str) -> bool:
            scrypt_calls.append("dummy")
            return orig_dummy(pw)

        with (
            mock.patch.object(auth_mod, "verify_scrypt_hash", side_effect=_spy_verify),
            mock.patch.object(auth_mod, "run_dummy_scrypt", side_effect=_spy_dummy),
        ):
            cases = [
                ("NoSuchUser", "DUMMY_WRONG_PASS_01"),
                ("ExampleDisabled", "EXAMPLE_DIS_PASS_1"),
                ("ExampleDenied", "EXAMPLE_DEN_PASS_1"),
                ("ExampleActive", "DUMMY_WRONG_PASS_01"),
            ]
            for uname, pw in cases:
                before = len(scrypt_calls)
                r, body, _ = await self._login_pw(uname, pw)
                self.assertEqual(r.status, 401, uname)
                self.assertEqual(body["error"], "账号或密码错误", uname)
                self.assertEqual(len(scrypt_calls), before + 1, f"Must run scrypt for {uname}")

        # 3. Spoofed IP defense in local mode (public_url=""): ignores CF-Connecting-IP & X-Forwarded-For
        clock_loc = [1_700_000_000.0]
        auth_loc = StudioAuthManager(
            config_dir=self.studio_cfg,
            bridge_dir=self.bridge_dir,
            users_file=self.users_file,
            public_url="",
            now_fn=lambda: clock_loc[0],
            ip_max_failures=2,
            ip_window_sec=60.0,
            user_max_failures=10,
            global_max_failures=20,
        )
        app_loc = create_app(auth_mgr=auth_loc, data_sources=self.sources, static_dist_dir=self.dist_dir)
        srv_loc = TestServer(app_loc)
        async with TestClient(srv_loc) as cli_loc:
            loc_orig = f"http://{srv_loc.host}:{srv_loc.port}"
            for i in range(2):
                r, _, _ = await self._login_pw(
                    f"Ghost{i}",
                    "DUMMY_WRONG_PASS_01",
                    client=cli_loc,
                    origin=loc_orig,
                    extra_headers={
                        "CF-Connecting-IP": f"203.0.113.{i + 10}",
                        "X-Forwarded-For": f"198.51.100.{i + 10}",
                    },
                )
                self.assertEqual(r.status, 401)
            # 3rd attempt even with another spoofed CF-Connecting-IP MUST hit 429 on real peer 127.0.0.1 BEFORE scrypt!
            with mock.patch.object(auth_mod, "run_dummy_scrypt", side_effect=AssertionError("rate limit must run before scrypt")):
                r_429, b_429, _ = await self._login_pw(
                    "Ghost99",
                    "DUMMY_WRONG_PASS_01",
                    client=cli_loc,
                    origin=loc_orig,
                    extra_headers={"CF-Connecting-IP": "203.0.113.99", "X-Forwarded-For": "198.51.100.99"},
                )
            self.assertEqual(r_429.status, 429)
            self.assertTrue(r_429.headers.get("Retry-After"))
            self.assertGreaterEqual(b_429["retry_after"], 1)

        # 4. Public mode: X-Forwarded-For ignored, valid CF-Connecting-IP respected, bounded buckets (anti-OOM) + global cap + window recovery
        clock_pub = [1_700_000_000.0]
        auth_pub = StudioAuthManager(
            config_dir=self.studio_cfg,
            bridge_dir=self.bridge_dir,
            users_file=self.users_file,
            public_url=PUBLIC_ORIGIN,
            now_fn=lambda: clock_pub[0],
            ip_max_failures=3,
            ip_window_sec=60.0,
            max_ip_buckets=4,
            user_max_failures=2,
            user_window_sec=60.0,
            max_user_buckets=4,
            global_max_failures=7,
            global_window_sec=60.0,
        )
        app_pub = create_app(auth_mgr=auth_pub, data_sources=self.sources, static_dist_dir=self.dist_dir)
        async with TestClient(TestServer(app_pub)) as cli_pub:
            # Rotating X-Forwarded-For without CF-Connecting-IP uses peer -> username bucket trips at 2
            for i in range(2):
                r, _, _ = await self._login_pw(
                    "ExampleActive",
                    "DUMMY_WRONG_PASS_01",
                    client=cli_pub,
                    extra_headers={"X-Forwarded-For": f"198.51.100.{i + 1}"},
                )
                self.assertEqual(r.status, 401)
            r_u429, b_u429, _ = await self._login_pw(
                "exampleactive",
                "EXAMPLE_ACTIVE_PASS_1",
                client=cli_pub,
                extra_headers={"CF-Connecting-IP": "203.0.113.50"},
            )
            self.assertEqual(r_u429.status, 429)
            self.assertIn("Retry-After", r_u429.headers)
            self.assertGreaterEqual(b_u429["retry_after"], 1)

            # Flood distinct valid CF-Connecting-IPs and distinct usernames -> bounded memory (<=4) + global bucket 429 at 7 total!
            for i in range(5):
                r, _, _ = await self._login_pw(
                    f"FloodUser{i}",
                    "DUMMY_WRONG_PASS_01",
                    client=cli_pub,
                    extra_headers={"CF-Connecting-IP": f"203.0.113.{100 + i}"},
                )
                self.assertEqual(r.status, 401)
                self.assertLessEqual(len(auth_pub.rate_limiter._ip_buckets), 4)
                self.assertLessEqual(len(auth_pub.rate_limiter._user_buckets), 4)

            # Now global_failures == 7 -> 8th fails immediately with 429 BEFORE scrypt
            with mock.patch.object(auth_mod, "run_dummy_scrypt", side_effect=AssertionError("global 429 before scrypt")):
                r_g429, b_g429, _ = await self._login_pw(
                    "BrandNewUser",
                    "DUMMY_WRONG_PASS_01",
                    client=cli_pub,
                    extra_headers={"CF-Connecting-IP": "203.0.113.250"},
                )
            self.assertEqual(r_g429.status, 429)
            self.assertGreaterEqual(b_g429["retry_after"], 1)

            # Advance clock past window -> login recovers!
            clock_pub[0] += 61.0
            r_rec, _, sid_rec = await self._login_pw(
                "ExampleActive",
                "EXAMPLE_ACTIVE_PASS_1",
                client=cli_pub,
                extra_headers={"CF-Connecting-IP": "203.0.113.250"},
            )
            self.assertEqual(r_rec.status, 200)
            csrf_rec = (await r_rec.json())["csrf_token"]

            # 5. change-password wrong current_password also trips 429 + Retry-After
            for _ in range(2):
                r_cp_w = await cli_pub.post(
                    "/api/auth/change-password",
                    headers={
                        "Origin": PUBLIC_ORIGIN,
                        "X-Studio-CSRF": csrf_rec,
                        "Cookie": f"{SESSION_COOKIE_NAME}={sid_rec}",
                        "CF-Connecting-IP": "203.0.113.251",
                    },
                    json={"current_password": "DUMMY_WRONG_CURR_1", "new_password": "EXAMPLE_NEW_PASS_99"},
                )
                self.assertEqual(r_cp_w.status, 401)
            r_cp_429 = await cli_pub.post(
                "/api/auth/change-password",
                headers={
                    "Origin": PUBLIC_ORIGIN,
                    "X-Studio-CSRF": csrf_rec,
                    "Cookie": f"{SESSION_COOKIE_NAME}={sid_rec}",
                    "CF-Connecting-IP": "203.0.113.251",
                },
                json={"current_password": "EXAMPLE_ACTIVE_PASS_1", "new_password": "EXAMPLE_NEW_PASS_99"},
            )
            self.assertEqual(r_cp_429.status, 429)
            self.assertIn("Retry-After", r_cp_429.headers)

    # ---------------------------------------------------------------- C7
    async def test_c7_zero_credential_logs_and_frontend_hygiene(self) -> None:
        pw_old = "EXAMPLE_LOG_TEST_PASS_OLD_1"
        pw_new = "EXAMPLE_LOG_TEST_PASS_NEW_2"
        self._seed_user("ExampleLogUser", pw_old, role="admin", must_change_password=False)
        stored_hash = json.loads(self.users_file.read_text(encoding="utf-8"))["users"]["exampleloguser"]["password_hash"]
        salt_part = stored_hash.split("$")[4]

        access_logger = logging.getLogger(f"test_pw_access_{id(self)}")
        access_logger.setLevel(logging.INFO)
        access_logger.propagate = False
        app_logger = logging.getLogger("agy-studio")
        access_handler = _ListLogHandler()
        app_handler = _ListLogHandler()
        access_logger.addHandler(access_handler)
        app_logger.addHandler(app_handler)

        runner = web.AppRunner(self.app, access_log=access_logger, access_log_class=SanitizedAccessLogger)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        sid_val = ""
        csrf_val = ""
        try:
            port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
            async with aiohttp.ClientSession() as raw_cli:
                async with raw_cli.post(
                    f"http://127.0.0.1:{port}/api/auth/login",
                    params={"password": pw_old},
                    headers={
                        "Origin": PUBLIC_ORIGIN,
                        "Referer": "https://studio.example.com/?" + urllib.parse.urlencode({"password": pw_old}),
                        "User-Agent": f"TestAgent/{pw_old}",
                    },
                    json={"username": "ExampleLogUser", "password": pw_old},
                ) as r1:
                    self.assertEqual(r1.status, 200)
                    sid_val = _extract_session_cookie(r1)
                    csrf_val = (await r1.json())["csrf_token"]

                async with raw_cli.post(
                    f"http://127.0.0.1:{port}/api/auth/change-password",
                    params={"secret": pw_new},
                    headers={
                        "Origin": PUBLIC_ORIGIN,
                        "X-Studio-CSRF": csrf_val,
                        "Cookie": f"{SESSION_COOKIE_NAME}={sid_val}",
                        "Referer": "https://studio.example.com/?" + urllib.parse.urlencode({"csrf": csrf_val}),
                    },
                    json={"current_password": pw_old, "new_password": pw_new},
                ) as r2:
                    self.assertEqual(r2.status, 200)
        finally:
            await runner.cleanup()
            access_logger.removeHandler(access_handler)
            app_logger.removeHandler(app_handler)

        all_logs = "\n".join(access_handler.messages + app_handler.messages)
        self.assertTrue(access_handler.messages)
        for secret_val in (pw_old, pw_new, stored_hash, salt_part, sid_val, csrf_val):
            self.assertNotIn(secret_val, all_logs)
        self.assertNotIn("?password=", all_logs)
        self.assertNotIn("?secret=", all_logs)
        self.assertNotIn("Referer", all_logs)

        # Frontend storage hygiene & autoComplete attributes
        # Zero sessionStorage everywhere; localStorage is forbidden across all files EXCEPT the
        # two non-secret UI preferences (`SYNC_TG_STORAGE_KEY` & `WORKBENCH_STORAGE_KEY`)
        # inside `WorkspaceView.tsx`.
        webui_src = REPO_ROOT / "webui" / "src"
        allowed_ls_re = re.compile(
            r'localStorage\.(?:getItem\((?:SYNC_TG_STORAGE_KEY|WORKBENCH_STORAGE_KEY)\)'
            r'|setItem\(SYNC_TG_STORAGE_KEY,\s*(?:[A-Za-z_][A-Za-z0-9_]*\s*\?\s*"true"\s*:\s*"false"|"(?:true|false)")\)'
            r'|setItem\(WORKBENCH_STORAGE_KEY,\s*[A-Za-z_][A-Za-z0-9_]*\))'
        )
        for ts_file in webui_src.rglob("*.ts*"):
            txt = ts_file.read_text(encoding="utf-8")
            self.assertNotIn("sessionStorage", txt, str(ts_file))
            if ts_file.name == "WorkspaceView.tsx":
                self.assertIn('const SYNC_TG_STORAGE_KEY = "agy_studio_sync_tg";', txt)
                self.assertIn('const WORKBENCH_STORAGE_KEY = "agy_studio_workbench_v1";', txt)
                scrubbed = allowed_ls_re.sub("", txt)
                self.assertNotIn("localStorage", scrubbed, str(ts_file))
            else:
                self.assertNotIn("localStorage", txt, str(ts_file))
        login_tsx = (webui_src / "components" / "LoginView.tsx").read_text(encoding="utf-8")
        chg_tsx = (webui_src / "components" / "ChangePasswordModal.tsx").read_text(encoding="utf-8")
        self.assertIn('autoComplete="username"', login_tsx)
        self.assertIn('autoComplete="current-password"', login_tsx)
        self.assertIn('autoComplete="current-password"', chg_tsx)
        self.assertIn('autoComplete="new-password"', chg_tsx)

    # ---------------------------------------------------------------- C8
    async def test_c8_csp_tightening_zero_telegram_sdk_in_password_mode(self) -> None:
        # Password mode CSP MUST tighten script-src to 'self' (no telegram.org) and keep frame-ancestors 'none'
        r_home = await self.client.get("/")
        self.assertEqual(r_home.status, 200)
        csp_pw = r_home.headers.get("Content-Security-Policy", "")
        self.assertIn("script-src 'self';", csp_pw)
        self.assertNotIn("telegram.org", csp_pw)
        self.assertIn("frame-ancestors 'none'", csp_pw)

        # GET /api/auth/me returns auth_mode="password" on BOTH 401 and 200
        r_me_unauth = await self.client.get("/api/auth/me")
        self.assertEqual(r_me_unauth.status, 401)
        self.assertEqual((await r_me_unauth.json())["auth_mode"], "password")

        self._seed_user("ExampleCsp", "EXAMPLE_CSP_PASS_01", role="admin")
        r_in, b_in, sid = await self._login_pw("ExampleCsp", "EXAMPLE_CSP_PASS_01")
        self.assertEqual(r_in.status, 200)
        self.assertEqual(b_in["auth_mode"], "password")
        r_me_ok = await self.client.get("/api/auth/me", headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid}"})
        self.assertEqual(r_me_ok.status, 200)
        self.assertEqual((await r_me_ok.json())["auth_mode"], "password")

        # Legacy mode retains https://telegram.org in CSP and returns auth_mode="legacy" on /api/auth/me
        legacy_auth = StudioAuthManager(
            config_dir=self.studio_cfg,
            bridge_dir=self.bridge_dir,
            auth_mode="legacy",
            public_url=PUBLIC_ORIGIN,
            now_fn=lambda: self.clock[0],
        )
        legacy_app = create_app(auth_mgr=legacy_auth, data_sources=self.sources, static_dist_dir=self.dist_dir)
        async with TestClient(TestServer(legacy_app)) as lcli:
            r_lhome = await lcli.get("/")
            csp_leg = r_lhome.headers.get("Content-Security-Policy", "")
            self.assertIn("script-src 'self' https://telegram.org;", csp_leg)
            self.assertIn("frame-ancestors 'none'", csp_leg)
            r_lme = await lcli.get("/api/auth/me")
            self.assertEqual(r_lme.status, 401)
            self.assertEqual((await r_lme.json())["auth_mode"], "legacy")

        # Frontend C8 guard: fetchMe() runs BEFORE any loadTelegramSdkOnce() call, and password mode returns early
        app_tsx = (REPO_ROOT / "webui" / "src" / "App.tsx").read_text(encoding="utf-8")
        idx_fetch_me = app_tsx.index("await fetchMe()")
        idx_pw_return = app_tsx.index('if (detectedMode === "password")')
        idx_load_sdk = app_tsx.index("const sdkPromise = loadTelegramSdkOnce()")
        self.assertLess(idx_fetch_me, idx_pw_return)
        self.assertLess(idx_pw_return, idx_load_sdk)
        # Ensure no non-comment call to loadTelegramSdkOnce appears before the password-mode early return
        before_pw_lines = [
            ln for ln in app_tsx[:idx_pw_return].splitlines() if not ln.lstrip().startswith("//")
        ]
        self.assertNotIn("loadTelegramSdkOnce(", "\n".join(before_pw_lines))
        index_html = (REPO_ROOT / "webui" / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("telegram.org", index_html)


if __name__ == "__main__":
    unittest.main()
