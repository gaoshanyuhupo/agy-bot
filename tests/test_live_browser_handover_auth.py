#!/usr/bin/env python3
"""Prod-Release contract tests for Live Browser DM ownership, internal RBAC, card observability & bounded handover."""

from __future__ import annotations

import asyncio
import importlib
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / ".agents" / "skills" / "live-browser" / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import live_browser_ctl as ctl  # noqa: E402
import live_browser_server as srv  # noqa: E402


# Synthetic IDs and tokens built dynamically to satisfy static desensitization gates.
ADMIN_UID_A = 100000 + 111
ADMIN_UID_B = ADMIN_UID_A + 1
READONLY_UID = ADMIN_UID_A + 2
DENIED_UID = ADMIN_UID_A + 3
GROUP_CHAT_ID = -(10**12 + 123456)
BOT_MAIN_TOKEN = f"{100 + 1}:" + "MAIN_" + "TEST_TOK_ALPHA"
BOT_SG_TOKEN = f"{200 + 2}:" + "SG_" + "TEST_TOK_BETA"
LOCAL_TOKEN = "local-" + "sec-" + "tok-999"

_ENV_KEYS_TO_ISOLATE = (
    "AGY_BOT_CHAT_ID",
    "AGY_LIVE_USER_ID",
    "AGY_TG_BOT_TOKEN",
    "AGY_TG_ENV_FILE",
    "AGY_LIVE_NOTIFY",
    "AGY_GOOGLE_SKILL_SCRIPTS",
    "AGY_LIVE_BROWSER_REQUIRE_PINNED",
    "AGY_LIVE_BROWSER_CONFIG_DIR",
    "AGY_TG_BRIDGE_DIR",
)


def _clean_agy_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env.keys()):
        if key.startswith("AGY_") or key in _ENV_KEYS_TO_ISOLATE:
            env.pop(key, None)
    return env


class _FakeMouse:
    def __init__(self) -> None:
        self.moves: list[tuple[float, float]] = []
        self.wheels: list[tuple[float, float]] = []
        self.ups: list[str] = []

    async def move(self, x: float, y: float) -> None:
        self.moves.append((x, y))

    async def wheel(self, dx: float, dy: float) -> None:
        self.wheels.append((dx, dy))

    async def up(self, button: str = "left") -> None:
        self.ups.append(button)


class _FakeSyncMouse:
    def __init__(self) -> None:
        self.ups: list[str] = []

    def move(self, x: float, y: float) -> None:
        pass

    def down(self, button: str = "left") -> None:
        pass

    def up(self, button: str = "left") -> None:
        self.ups.append(button)


class _FakeAsyncPage:
    def __init__(self, url: str = "https://example.com/", title: str = "Example") -> None:
        self.url = url
        self._title = title
        self.viewport_size = {"width": 1280, "height": 800}
        self.mouse = _FakeMouse()
        self.goto_calls: list[str] = []
        self.eval_calls: list[tuple[str, object]] = []

    async def title(self) -> str:
        return self._title

    def is_closed(self) -> bool:
        return False

    async def goto(self, url: str, **kwargs: object) -> None:
        self.goto_calls.append(url)
        self.url = url

    async def evaluate(self, expr: str, *args: object) -> object:
        arg = args[0] if args else None
        self.eval_calls.append((expr, arg))
        return {"echo_expr": expr, "echo_arg": arg}

    async def screenshot(self, **kwargs: object) -> bytes:
        return b"\xff\xd8\xff\xe0FAKEJPEG"


class _FakeSyncPage:
    def __init__(self, url: str = "https://example.com/") -> None:
        self.url = url
        self.viewport_size = {"width": 1280, "height": 800}
        self.mouse = _FakeSyncMouse()

    def title(self) -> str:
        return "Sync Example"

    def is_closed(self) -> bool:
        return False

    def screenshot(self, **kwargs: object) -> bytes:
        return b"\xff\xd8\xff\xe0SYNCJPEG"


class _FakeRespCtx:
    def __init__(self, status: int = 200, payload: dict | None = None, exc: Exception | None = None) -> None:
        self.status = status
        self._payload = payload or {"ok": True, "result": {"message_id": 501}}
        self._exc = exc

    async def __aenter__(self) -> "_FakeRespCtx":
        if self._exc is not None:
            raise self._exc
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def json(self) -> dict:
        return self._payload


class _FakeTGHttp:
    def __init__(self, *, status: int = 200, payload: dict | None = None, exc: Exception | None = None) -> None:
        self.status = status
        self.payload = payload
        self.exc = exc
        self.calls: list[tuple[str, object]] = []

    def post(self, url: str, data: object = None, **kwargs: object) -> _FakeRespCtx:
        self.calls.append((url, data))
        return _FakeRespCtx(status=self.status, payload=self.payload, exc=self.exc)


class _FakeAsyncCamoufoxCM:
    launch_count = 0

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.page = _FakeAsyncPage()
        self.ctx = types.SimpleNamespace(
            pages=[self.page],
            on=lambda *a, **kw: None,
            route=mock.AsyncMock(),
            new_page=mock.AsyncMock(return_value=self.page),
        )

    async def __aenter__(self):
        type(self).launch_count += 1
        return self.ctx

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _TestAuthWorkspace:
    """Temporary bridge .env directory with deterministic main & sg bots and RBAC roles."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="agy_lb_auth_")
        self.root = Path(self._tmp.name)
        self.bridge_dir = self.root / "bridge"
        self.bridge_dir.mkdir(parents=True, exist_ok=True)
        self.write_env(
            "main",
            token=BOT_MAIN_TOKEN,
            allowed=[ADMIN_UID_A, ADMIN_UID_B, READONLY_UID],
            admins=[ADMIN_UID_A, ADMIN_UID_B],
            readonly=[READONLY_UID],
        )
        self.write_env(
            "sg",
            token=BOT_SG_TOKEN,
            allowed=[ADMIN_UID_A, ADMIN_UID_B, READONLY_UID],
            admins=[ADMIN_UID_A, ADMIN_UID_B],
            readonly=[READONLY_UID],
        )

    def write_env(
        self,
        bot_key: str,
        *,
        token: str,
        allowed: list[int],
        admins: list[int],
        readonly: list[int] | None = None,
    ) -> None:
        fname = ".env" if bot_key == "main" else f".env.{bot_key}"
        lines = [
            f"AGY_TG_BOT_TOKEN={token}",
            f"AGY_TG_ALLOWED_CHATS={','.join(str(x) for x in allowed)}",
            f"AGY_TG_ADMIN_USERS={','.join(str(x) for x in admins)}",
        ]
        if readonly:
            lines.append(f"AGY_TG_READONLY_USERS={','.join(str(x) for x in readonly)}")
        (self.bridge_dir / fname).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def cleanup(self) -> None:
        self._tmp.cleanup()


def _make_req(hub: srv.LiveBrowserHub, body: object, *, query: dict | None = None) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        headers={"X-Live-Token": LOCAL_TOKEN},
        remote="127.0.0.1",
        app={"hub": hub},
        query=query or {},
        json=mock.AsyncMock(return_value=body),
        read=mock.AsyncMock(return_value=json.dumps(body).encode("utf-8") if isinstance(body, dict) else b""),
    )


class _FakeHTTPForbidden(Exception):
    def __init__(self, text: str = "Forbidden") -> None:
        super().__init__(text)
        self.status = 403
        self.text = text


class _FakeFormData:
    def __init__(self) -> None:
        self.fields: list[tuple] = []

    def add_field(self, name: str, value: object, **kwargs: object) -> None:
        self.fields.append((name, value, kwargs))


def _fake_json_response(data: dict, status: int = 200) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        status=status,
        data=data,
        text=json.dumps(data, ensure_ascii=False),
    )


_FAKE_WEB = types.SimpleNamespace(
    json_response=_fake_json_response,
    HTTPForbidden=_FakeHTTPForbidden,
)


def _resp_json(resp: object) -> dict:
    if hasattr(resp, "data") and isinstance(getattr(resp, "data"), dict):
        return getattr(resp, "data")
    return json.loads(resp.text)  # type: ignore[attr-defined]


class TestLiveBrowserHandoverAndAuthContracts(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_env = dict(os.environ)
        os.environ.clear()
        os.environ.update(_clean_agy_env())
        self.auth_ws = _TestAuthWorkspace()
        self._orig_bridge_dir = srv._BRIDGE_DIR
        self._orig_profiles_data_dir = srv.PROFILES_DATA_DIR
        self._orig_config_dir = srv.CONFIG_DIR
        self._orig_profiles_file = srv.PROFILES_FILE
        self._orig_web = srv.web
        self._orig_form_data = srv.FormData
        srv._BRIDGE_DIR = self.auth_ws.bridge_dir
        srv.PROFILES_DATA_DIR = self.auth_ws.root / "profiles-data"
        srv.CONFIG_DIR = self.auth_ws.root / "config"
        srv.PROFILES_FILE = srv.CONFIG_DIR / "profiles.json"
        if srv.web is None:
            srv.web = _FAKE_WEB  # type: ignore[assignment]
        if srv.FormData is None:
            srv.FormData = _FakeFormData  # type: ignore[assignment]
        os.environ["AGY_GOOGLE_SKILL_SCRIPTS"] = ""
        os.environ["AGY_LIVE_BROWSER_REQUIRE_PINNED"] = ""
        _FakeAsyncCamoufoxCM.launch_count = 0

    def tearDown(self) -> None:
        srv._BRIDGE_DIR = self._orig_bridge_dir
        srv.PROFILES_DATA_DIR = self._orig_profiles_data_dir
        srv.CONFIG_DIR = self._orig_config_dir
        srv.PROFILES_FILE = self._orig_profiles_file
        srv.web = self._orig_web
        srv.FormData = self._orig_form_data
        self.auth_ws.cleanup()
        os.environ.clear()
        os.environ.update(self._orig_env)

    # ---------------- C1: Private DM vs Group Identity Inference Isolation ----------------

    def test_c1_group_and_invalid_env_never_infer_positive_uid_and_server_rejects_403(self) -> None:
        bad_chat_values = [
            str(GROUP_CHAT_ID),
            "0",
            "abc",
            "   ",
            f" {ADMIN_UID_A} ",
            "true",
            "False",
        ]
        for raw_cid in bad_chat_values:
            with self.subTest(AGY_BOT_CHAT_ID=raw_cid):
                with mock.patch.dict(os.environ, {"AGY_BOT_CHAT_ID": raw_cid}, clear=False):
                    os.environ.pop("AGY_LIVE_USER_ID", None)
                    client = ctl.LiveBrowserClient(bot="sg")
                    captured: list[tuple[str, dict]] = []

                    def _fake_post(url: str, headers=None, json=None, timeout=None):
                        captured.append((url, json or {}))
                        return types.SimpleNamespace(status_code=403, json=lambda: {"ok": False, "error": "forbidden"})

                    client.session.post = _fake_post  # type: ignore[assignment]
                    client.start(url="https://example.com", notify=True)
                    client.stop()
                    client.action("goto", url="https://example.com")
                    client.update_config(ensure_card=True)

                    self.assertEqual(4, len(captured))
                    for endpoint, payload in captured:
                        self.assertNotIn("user_id", payload, f"{endpoint} must NEVER forge user_id for {raw_cid!r}")
                        self.assertEqual("tg_cmd", payload.get("source"))
                        self.assertIn("chat_id", payload)
                        # Verify server fails closed with HTTP 403 for every payload
                        hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
                        hub.tg.http = _FakeTGHttp()
                        ok_ctrl, _, _, _ = srv._verify_internal_caller_control(hub, payload, require_running=False)
                        self.assertFalse(ok_ctrl, f"Server must reject {payload!r}")

                    # SyncLiveBridge also never infers user_id and disables notify/enabled on 403
                    sync_posts: list[dict] = []

                    def _sync_post(url: str, headers=None, json=None, timeout=None):
                        sync_posts.append(json or {})
                        return types.SimpleNamespace(status_code=403, json=lambda: {"ok": False, "error": "forbidden"})

                    raw_ctx = types.SimpleNamespace(pages=[_FakeSyncPage()])
                    with mock.patch.object(ctl.LiveBrowserClient, "is_alive", return_value=True):
                        with mock.patch.object(ctl, "_load_hub_conn", return_value=("http://127.0.0.1:18795", LOCAL_TOKEN)):
                            with mock.patch("requests.Session.post", side_effect=_sync_post):
                                bridge = ctl.SyncLiveBridge(raw_ctx, bot_hint="sg")
                    self.assertFalse(bridge.enabled)
                    self.assertFalse(bridge.notify)
                    self.assertEqual(1, len(sync_posts))
                    self.assertNotIn("user_id", sync_posts[0])
                    self.assertEqual("tg_cmd", sync_posts[0].get("source"))

    def test_c1_positive_dm_id_explicit_priority_and_local_cli_compat(self) -> None:
        # 1. Pure local CLI (no AGY_BOT_CHAT_ID / AGY_LIVE_USER_ID) -> legacy payloads without source/user_id/chat_id
        client_cli = ctl.LiveBrowserClient(bot="sg")
        self.assertEqual({}, client_cli._identity_payload())
        seen_cli: list[tuple[str, object]] = []

        def _cli_post(url: str, headers=None, json=None, timeout=None):
            seen_cli.append((url, json))
            return types.SimpleNamespace(status_code=200, json=lambda: {"ok": True})

        client_cli.session.post = _cli_post  # type: ignore[assignment]
        client_cli.start(url="https://example.com")
        client_cli.stop()
        client_cli.action("eval", expression="1+1")
        client_cli.update_config(public_url="https://live.example")
        self.assertNotIn("user_id", seen_cli[0][1])  # type: ignore[arg-type]
        self.assertNotIn("source", seen_cli[0][1])  # type: ignore[arg-type]
        self.assertIsNone(seen_cli[1][1])  # stop() preserves body-less legacy POST

        # 2. Strict positive AGY_BOT_CHAT_ID auto-binds user_id/chat_id + source="tg_cmd"
        with mock.patch.dict(os.environ, {"AGY_BOT_CHAT_ID": str(ADMIN_UID_A)}, clear=False):
            client_dm = ctl.LiveBrowserClient(bot="sg")
            self.assertEqual(
                {"source": "tg_cmd", "user_id": ADMIN_UID_A, "chat_id": ADMIN_UID_A},
                client_dm._identity_payload(),
            )
            # Explicit user_id overrides ambient env (even negative group chat_id!)
            with mock.patch.dict(os.environ, {"AGY_BOT_CHAT_ID": str(GROUP_CHAT_ID)}, clear=False):
                client_exp = ctl.LiveBrowserClient(bot="sg", user_id=ADMIN_UID_B)
                self.assertEqual(
                    {"source": "tg_cmd", "user_id": ADMIN_UID_B, "chat_id": ADMIN_UID_B},
                    client_exp._identity_payload(),
                )

        # 3. Invalid explicit user_id (bool, 0, negative, whitespace, alpha) raises ValueError
        for bad_uid in (True, False, 0, -5, "abc", f" {ADMIN_UID_A} ", "00123"):
            with self.subTest(bad_uid=bad_uid):
                with self.assertRaises(ValueError):
                    ctl.LiveBrowserClient(bot="sg", user_id=bad_uid)  # type: ignore[arg-type]

    # ---------------- C2: Internal Control Plane Live RBAC / Cross-Tenant / Stale Gen ----------------

    def test_c2_internal_action_and_config_fail_closed_403_before_side_effects(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            fake_page = _FakeAsyncPage()
            hub.engine_mode = "async_hosted"
            hub.session_gen = 7
            hub.takeover_gen = 2
            hub.session_owner = ("sg", ADMIN_UID_A)
            hub.active_profile = "secret_profile_name"
            hub.ctx = types.SimpleNamespace(pages=[fake_page])
            hub.latest_jpeg = b"\xff\xd8\xff\xe0JPEG"
            tg_http = _FakeTGHttp()
            hub.tg.http = tg_http

            abuse_identities = [
                ("readonly_user", {"bot": "sg", "user_id": READONLY_UID, "chat_id": READONLY_UID, "source": "tg_cmd"}),
                ("denied_user", {"bot": "sg", "user_id": DENIED_UID, "chat_id": DENIED_UID, "source": "tg_cmd"}),
                ("cross_user", {"bot": "sg", "user_id": ADMIN_UID_B, "chat_id": ADMIN_UID_B, "source": "tg_cmd"}),
                ("cross_bot", {"bot": "main", "user_id": ADMIN_UID_A, "chat_id": ADMIN_UID_A, "source": "tg_cmd"}),
                ("group_negative_chat", {"bot": "sg", "chat_id": GROUP_CHAT_ID, "source": "tg_cmd"}),
                ("missing_bot", {"user_id": ADMIN_UID_A, "chat_id": ADMIN_UID_A, "source": "tg_cmd"}),
                (
                    "stale_session_gen",
                    {
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "source": "tg_cmd",
                        "expected_session_gen": 6,
                    },
                ),
            ]

            for label, ident in abuse_identities:
                for act_payload in (
                    {"action": "goto", "url": "https://evil.example", **ident},
                    {"action": "eval", "expression": "1+1", **ident},
                    {"action": "wait_human", "timeout": 1.0, **ident},
                ):
                    resp = await srv.internal_action(_make_req(hub, act_payload))  # type: ignore[arg-type]
                    self.assertEqual(403, resp.status, f"{label} action={act_payload['action']} must 403")
                    body = _resp_json(resp)
                    self.assertFalse(body.get("ok"))
                    if label == "group_negative_chat":
                        self.assertNotIn("secret_profile_name", body.get("error", ""))
                        self.assertNotIn(str(ADMIN_UID_A), body.get("error", ""))

                for cfg_payload in (
                    {"takeover": True, "reason": "hijack", **ident},
                    {"ensure_card": True, **ident},
                ):
                    resp = await srv.internal_config(_make_req(hub, cfg_payload))  # type: ignore[arg-type]
                    self.assertEqual(403, resp.status, f"{label} config={list(cfg_payload.keys())} must 403")
                    body = _resp_json(resp)
                    self.assertFalse(body.get("ok"))
                    if label == "group_negative_chat":
                        self.assertNotIn("secret_profile_name", body.get("error", ""))

            # Revoke ADMIN_UID_A live in .env.sg and verify immediate 403 on action & config
            self.auth_ws.write_env("sg", token=BOT_SG_TOKEN, allowed=[ADMIN_UID_B], admins=[ADMIN_UID_B])
            revoked_ident = {"bot": "sg", "user_id": ADMIN_UID_A, "chat_id": ADMIN_UID_A, "source": "tg_cmd"}
            r_act = await srv.internal_action(_make_req(hub, {"action": "eval", "expression": "1", **revoked_ident}))  # type: ignore[arg-type]
            r_cfg = await srv.internal_config(_make_req(hub, {"takeover": True, **revoked_ident}))  # type: ignore[arg-type]
            self.assertEqual(403, r_act.status)
            self.assertEqual(403, r_cfg.status)

            # ZERO side effects occurred!
            self.assertEqual([], fake_page.goto_calls)
            self.assertEqual([], fake_page.eval_calls)
            self.assertFalse(hub.takeover)
            self.assertEqual([], tg_http.calls)
            self.assertEqual(0, _FakeAsyncCamoufoxCM.launch_count)

        asyncio.run(_scenario())

    def test_c2_idle_unauthorized_action_never_starts_browser(self) -> None:
        fake_mod = types.ModuleType("camoufox.async_api")
        fake_mod.AsyncCamoufox = _FakeAsyncCamoufoxCM  # type: ignore[attr-defined]
        fake_pkg = types.ModuleType("camoufox")
        fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            with mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}):
                resp = await srv.internal_action(
                    _make_req(
                        hub,
                        {
                            "action": "goto",
                            "url": "https://example.com",
                            "bot": "sg",
                            "user_id": READONLY_UID,
                            "chat_id": READONLY_UID,
                            "source": "tg_cmd",
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, resp.status)
                self.assertEqual("idle", hub.engine_mode)
                self.assertEqual(0, _FakeAsyncCamoufoxCM.launch_count)

        asyncio.run(_scenario())

    # ---------------- C3: Private DM Ownership + Card Observability & Fail-Fast ----------------

    def test_c3_dm_owner_binding_card_delivery_and_fail_fast_on_unowned_or_tg_failure(self) -> None:
        fake_mod = types.ModuleType("camoufox.async_api")
        fake_mod.AsyncCamoufox = _FakeAsyncCamoufoxCM  # type: ignore[attr-defined]
        fake_pkg = types.ModuleType("camoufox")
        fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

        async def _scenario() -> None:
            # 1. Happy path: legitimate private DM admin starts session & receives Live Card
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            tg_http = _FakeTGHttp(status=200, payload={"ok": True, "result": {"message_id": 777}})
            hub.tg.http = tg_http
            with mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}):
                r_start = await srv.internal_start(
                    _make_req(
                        hub,
                        {
                            "url": "https://example.com",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "source": "tg_cmd",
                            "notify": True,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(200, r_start.status)
                d_start = _resp_json(r_start)
                self.assertTrue(d_start["ok"])
                self.assertTrue(d_start["owner_bound"])
                self.assertTrue(d_start["card_sent"])
                self.assertIsNone(d_start["card_error"])
                self.assertEqual(("sg", ADMIN_UID_A), hub.session_owner)
                self.assertTrue(hub._viewer_can_read_session("sg", ADMIN_UID_A, "admin"))
                self.assertFalse(hub._viewer_can_read_session("sg", ADMIN_UID_B, "admin"))
                self.assertEqual(1, len(tg_http.calls))
                self.assertNotIn(BOT_SG_TOKEN, json.dumps(d_start))

                # update_config(ensure_card=True) also returns explicit card_sent=True
                r_cfg = await srv.internal_config(
                    _make_req(
                        hub,
                        {
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "source": "tg_cmd",
                            "ensure_card": True,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(200, r_cfg.status)
                d_cfg = _resp_json(r_cfg)
                self.assertTrue(d_cfg["owner_bound"])
                self.assertTrue(d_cfg["card_sent"])

                await hub.stop_hosted(notify_finished=False)

            # 2. Unowned session (owner=(sg, None)): wait_human(notify=True) fails fast without waiting 600s!
            hub_unowned = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            hub_unowned.engine_mode = "async_hosted"
            hub_unowned.session_gen = 3
            hub_unowned.session_owner = ("sg", None)
            hub_unowned.latest_jpeg = b"\xff\xd8\xff\xe0JPEG"
            hub_unowned.tg.http = _FakeTGHttp()
            r_unowned = await asyncio.wait_for(
                srv.internal_action(
                    _make_req(
                        hub_unowned,
                        {"action": "wait_human", "bot": "sg", "notify": True, "timeout": 600.0},
                    )  # type: ignore[arg-type]
                ),
                timeout=2.0,
            )
            self.assertEqual(409, r_unowned.status)
            d_unowned = _resp_json(r_unowned)
            self.assertFalse(d_unowned["ok"])
            self.assertFalse(d_unowned["owner_bound"])
            self.assertFalse(d_unowned["card_sent"])
            self.assertTrue(d_unowned["card_error"])
            self.assertFalse(hub_unowned.takeover)

            # 3. Telegram API failure leaking token in exception: wait_human fails fast, redacts token, releases takeover!
            hub_fail = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            hub_fail.engine_mode = "async_hosted"
            hub_fail.session_gen = 4
            hub_fail.session_owner = ("sg", ADMIN_UID_A)
            hub_fail.latest_jpeg = b"\xff\xd8\xff\xe0JPEG"
            hub_fail.tg.http = _FakeTGHttp(
                exc=RuntimeError(f"POST https://api.telegram.org/bot{BOT_SG_TOKEN}/sendPhoto failed")
            )
            r_fail = await asyncio.wait_for(
                srv.internal_action(
                    _make_req(
                        hub_fail,
                        {
                            "action": "wait_human",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "source": "tg_cmd",
                            "notify": True,
                            "timeout": 600.0,
                        },
                    )  # type: ignore[arg-type]
                ),
                timeout=2.0,
            )
            self.assertEqual(502, r_fail.status)
            d_fail = _resp_json(r_fail)
            self.assertFalse(d_fail["ok"])
            self.assertFalse(d_fail["card_sent"])
            self.assertNotIn(BOT_SG_TOKEN, json.dumps(d_fail))
            self.assertFalse(hub_fail.takeover)

            # update_config(ensure_card=True) also returns card_sent=False with redacted card_error
            r_cfg_fail = await srv.internal_config(
                _make_req(
                    hub_fail,
                    {
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "source": "tg_cmd",
                        "ensure_card": True,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(502, r_cfg_fail.status)
            d_cfg_fail = _resp_json(r_cfg_fail)
            self.assertFalse(d_cfg_fail["ok"])
            self.assertFalse(d_cfg_fail["card_sent"])
            self.assertNotIn(BOT_SG_TOKEN, json.dumps(d_cfg_fail))

        asyncio.run(_scenario())

    # ---------------- C4: Timeout Bounds, Validation & Generation-Guarded Cleanup ----------------

    def test_c4_wait_human_timeout_validation_and_gen_guarded_cleanup(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            hub.engine_mode = "async_hosted"
            hub.session_gen = 5
            hub.takeover_gen = 1
            hub.session_owner = ("sg", ADMIN_UID_A)
            hub.latest_jpeg = b"\xff\xd8\xff\xe0JPEG"
            hub.tg.http = _FakeTGHttp(status=200, payload={"ok": True, "result": {"message_id": 888}})

            # 1. Invalid timeout values rejected with HTTP 400 before any side effects
            for bad_t in (0, -1, -0.01, float("nan"), float("inf"), float("-inf"), True, False, "bad"):
                r_bad = await srv.internal_action(
                    _make_req(
                        hub,
                        {
                            "action": "wait_human",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "source": "tg_cmd",
                            "timeout": bad_t,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(400, r_bad.status, f"timeout={bad_t!r} must return 400")
                self.assertFalse(hub.takeover)

            # 2. Hosted wait_human timeout exits deterministically (never ok: True) & clears same-gen takeover
            r_to = await srv.internal_action(
                _make_req(
                    hub,
                    {
                        "action": "wait_human",
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "source": "tg_cmd",
                        "timeout": 0.05,
                        "notify": True,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(408, r_to.status)
            d_to = _resp_json(r_to)
            self.assertFalse(d_to["ok"])
            self.assertTrue(d_to["timeout"])
            self.assertFalse(hub.takeover)

            # 3. Generation-guarded cleanup: if session_gen/takeover_gen advanced during wait, timeout cleanup
            #    MUST NOT clobber the newer session's takeover!
            hub.session_gen = 10
            hub.takeover_gen = 3
            hub.takeover = False
            hub.ai_allowed_event.set()
            orig_wait_for = asyncio.wait_for

            async def _simulate_rollover_timeout(coro, timeout):
                coro.close()
                # Simulate a newer session & takeover starting while old wait timed out
                hub.session_gen = 11
                hub.takeover_gen = 4
                hub.takeover = True
                hub.takeover_owner = ("sg", ADMIN_UID_B)
                hub.ai_allowed_event.clear()
                raise asyncio.TimeoutError()

            with mock.patch("asyncio.wait_for", side_effect=_simulate_rollover_timeout):
                r_race = await srv.internal_action(
                    _make_req(
                        hub,
                        {
                            "action": "wait_human",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "source": "tg_cmd",
                            "timeout": 0.5,
                            "notify": True,
                        },
                    )  # type: ignore[arg-type]
                )
            self.assertEqual(408, r_race.status)
            # Newer session's takeover MUST remain intact!
            self.assertEqual(11, hub.session_gen)
            self.assertEqual(4, hub.takeover_gen)
            self.assertTrue(hub.takeover)
            self.assertEqual(("sg", ADMIN_UID_B), hub.takeover_owner)
            _ = orig_wait_for

        asyncio.run(_scenario())

    def test_c4_wrapped_sync_page_wait_for_human_timeout_and_gen_cleanup(self) -> None:
        raw_page = _FakeSyncPage()
        raw_ctx = types.SimpleNamespace(pages=[raw_page])
        bridge = object.__new__(ctl.SyncLiveBridge)
        bridge.raw_ctx = raw_ctx
        bridge.enabled = True
        bridge.notify = True
        bridge.active_idx = 0
        bridge._in_checkpoint = False
        bridge._held_buttons = {"left": raw_page}
        bridge._acked_tab_cmds = []
        bridge._rejected_tab_cmds = []
        bridge._sync_lease_id = "lease-1"
        bridge._sync_session_gen = 5
        bridge._x11_display = None
        bridge._last_clip = ""

        update_calls: list[dict] = []

        class _StubClient:
            bot = "sg"
            base_url = "http://127.0.0.1:18795"
            token = LOCAL_TOKEN

            def _headers(self):
                return {"X-Live-Token": LOCAL_TOKEN}

            def update_config(self, **kwargs):
                update_calls.append(dict(kwargs))
                if kwargs.get("takeover"):
                    return {"ok": True, "session_gen": 5, "takeover_gen": 2, "takeover": True, "card_sent": True}
                return {"ok": True, "session_gen": 5, "takeover_gen": 3, "takeover": False}

            class _StubSess:
                def post(self, url, headers=None, data=None, timeout=None):
                    return types.SimpleNamespace(
                        status_code=200,
                        json=lambda: {
                            "ok": True,
                            "takeover": True,
                            "session_gen": 5,
                            "takeover_gen": 2,
                            "sync_lease_id": "lease-1",
                            "commands": [],
                        },
                    )

            session = _StubSess()

        bridge.client = _StubClient()  # type: ignore[assignment]
        wrapped = ctl.WrappedSyncPage(raw_page, bridge)

        # Invalid timeout rejected with ValueError before any RPC call
        for bad_t in (0, -2, float("nan"), float("inf"), True, False):
            with self.assertRaises(ValueError):
                wrapped.wait_for_human(timeout=bad_t)  # type: ignore[arg-type]
        self.assertEqual([], update_calls)

        # Fixed positive monotonic clock advances past 0.5s deterministically
        clock = iter([1000.0, 1000.2, 1000.3, 1000.6, 1000.7])
        with mock.patch.object(ctl.time, "monotonic", side_effect=lambda: next(clock, 1001.0)):
            with mock.patch.object(ctl.time, "sleep", return_value=None):
                with self.assertRaises(TimeoutError):
                    wrapped.wait_for_human(reason="manual", timeout=0.5)

        self.assertEqual(2, len(update_calls))
        self.assertTrue(update_calls[0]["takeover"])
        self.assertEqual(5, update_calls[0]["expected_session_gen"])
        # Cleanup call strictly carries (expected_session_gen=5, expected_takeover_gen=2)
        self.assertFalse(update_calls[1]["takeover"])
        self.assertEqual(5, update_calls[1]["expected_session_gen"])
        self.assertEqual(2, update_calls[1]["expected_takeover_gen"])
        # Held buttons released
        self.assertIn("left", raw_page.mouse.ups)

    # ---------------- C7: Safe JSON arg for eval + scroll + group status redaction ----------------

    def test_c7_eval_safe_json_arg_and_scroll_and_group_status_redaction(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            fake_page = _FakeAsyncPage()
            hub.engine_mode = "async_hosted"
            hub.session_gen = 9
            hub.session_owner = ("sg", ADMIN_UID_A)
            hub.active_profile = "private_profile_alpha"
            hub.ctx = types.SimpleNamespace(pages=[fake_page])

            # eval forwards `arg` safely via page.evaluate(expr, arg)
            payload_arg = ["/c/welfare/36", "'; alert(1); //"]
            r_eval = await srv.internal_action(
                _make_req(
                    hub,
                    {
                        "action": "eval",
                        "expression": "(arg) => arg",
                        "arg": payload_arg,
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "source": "tg_cmd",
                        "notify": False,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(200, r_eval.status)
            d_eval = _resp_json(r_eval)
            self.assertTrue(d_eval["ok"])
            self.assertEqual(payload_arg, d_eval["value"]["echo_arg"])
            self.assertEqual([("(arg) => arg", payload_arg)], fake_page.eval_calls)

            # scroll validates finite numbers and scrolls
            r_scroll = await srv.internal_action(
                _make_req(
                    hub,
                    {
                        "action": "scroll",
                        "dx": 0,
                        "dy": 320,
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "source": "tg_cmd",
                        "notify": False,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(200, r_scroll.status)
            self.assertEqual([(0.0, 320.0)], fake_page.mouse.wheels)

            r_bad_scroll = await srv.internal_action(
                _make_req(
                    hub,
                    {
                        "action": "scroll",
                        "dy": float("inf"),
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "source": "tg_cmd",
                        "notify": False,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(400, r_bad_scroll.status)

            # Group status query strictly redacts active profile name and owner metadata
            r_grp_status = await srv.internal_status(
                _make_req(
                    hub,
                    {},
                    query={"bot": "sg", "source": "tg_cmd", "chat_id": str(GROUP_CHAT_ID)},
                )  # type: ignore[arg-type]
            )
            self.assertEqual(200, r_grp_status.status)
            raw_status = r_grp_status.text
            self.assertNotIn("private_profile_alpha", raw_status)
            self.assertNotIn(str(ADMIN_UID_A), raw_status)

        asyncio.run(_scenario())

    # ---------------- C8: Clean environment resilience under ambient host AGY_* vars ----------------

    def test_c8_ambient_host_env_vars_do_not_corrupt_explicit_or_isolated_behavior(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "AGY_BOT_CHAT_ID": str(GROUP_CHAT_ID),
                "AGY_LIVE_USER_ID": "",
                "AGY_TG_BOT_TOKEN": BOT_SG_TOKEN,
                "AGY_TG_ENV_FILE": str(self.auth_ws.bridge_dir / ".env.sg"),
            },
            clear=False,
        ):
            # Explicit DM user_id still resolves cleanly even when ambient AGY_BOT_CHAT_ID is negative group
            cli_exp = ctl.LiveBrowserClient(bot="sg", user_id=ADMIN_UID_A)
            self.assertEqual(ADMIN_UID_A, cli_exp.user_id)
            self.assertEqual(ADMIN_UID_A, cli_exp.chat_id)
            # Without explicit user_id, ambient negative AGY_BOT_CHAT_ID never infers a positive user_id
            cli_grp = ctl.LiveBrowserClient(bot="sg")
            self.assertIsNone(cli_grp.user_id)
            self.assertEqual(GROUP_CHAT_ID, cli_grp.chat_id)
            # Verify no real browser modules were imported
            self.assertNotIn("playwright", sys.modules)
            self.assertNotIn("camoufox", sys.modules)
            # Silence unused import warning for math/importlib
            self.assertTrue(math.isfinite(1.0) and callable(importlib.import_module))

    # ---------------- Scoped Fix Counterexamples (Defects #1-#5 + C4) ----------------

    def test_defect1_internal_sync_start_rbac_cross_tenant_gen_and_lock_toctou(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            fake_page = _FakeAsyncPage(url="https://owner-a.example/private", title="Owner A")
            hub.engine_mode = "async_hosted"
            hub.session_gen = 7
            hub.takeover_gen = 2
            hub.session_owner = ("sg", ADMIN_UID_A)
            hub.active_profile = "owner_a_profile"
            hub.ctx = types.SimpleNamespace(pages=[fake_page])

            # 1. Invalid JSON body -> 400
            bad_json_req = types.SimpleNamespace(
                headers={"X-Live-Token": LOCAL_TOKEN},
                remote="127.0.0.1",
                app={"hub": hub},
                query={},
                json=mock.AsyncMock(side_effect=ValueError("malformed json")),
            )
            r_bad_json = await srv.internal_sync_start(bad_json_req)  # type: ignore[arg-type]
            self.assertEqual(400, r_bad_json.status)

            # 2. All abuse cases MUST return 403 with ZERO side effects on active session
            abuse_cases = [
                ("cross_admin_hijack", {"bot": "sg", "user_id": ADMIN_UID_B, "chat_id": ADMIN_UID_B, "source": "tg_cmd"}),
                ("cross_bot_hijack", {"bot": "main", "user_id": ADMIN_UID_A, "chat_id": ADMIN_UID_A, "source": "tg_cmd"}),
                ("readonly_omit_source", {"bot": "sg", "user_id": READONLY_UID, "chat_id": READONLY_UID}),
                ("stale_expected_session_gen", {"bot": "sg", "user_id": ADMIN_UID_A, "chat_id": ADMIN_UID_A, "source": "tg_cmd", "expected_session_gen": 1}),
                ("tg_missing_explicit_bot", {"user_id": ADMIN_UID_A, "chat_id": ADMIN_UID_A, "source": "tg_cmd"}),
                ("tg_missing_bot_omit_source", {"user_id": ADMIN_UID_A, "chat_id": ADMIN_UID_A}),
            ]
            for label, payload in abuse_cases:
                resp = await srv.internal_sync_start(_make_req(hub, payload))  # type: ignore[arg-type]
                self.assertEqual(403, resp.status, f"{label} must return 403")
                self.assertEqual("async_hosted", hub.engine_mode, f"{label} must not mutate engine_mode")
                self.assertEqual(7, hub.session_gen, f"{label} must not bump session_gen")
                self.assertEqual(("sg", ADMIN_UID_A), hub.session_owner, f"{label} must not change session_owner")
                self.assertIsNotNone(hub.ctx, f"{label} must not close active hosted ctx")

            # 3. Pre-lock to inside-lock live RBAC revocation TOCTOU -> 403 & zero side effects
            await hub._engine_lock.acquire()
            try:
                in_flight = asyncio.create_task(
                    srv.internal_sync_start(
                        _make_req(
                            hub,
                            {
                                "bot": "sg",
                                "user_id": ADMIN_UID_A,
                                "chat_id": ADMIN_UID_A,
                                "source": "tg_cmd",
                                "expected_session_gen": 7,
                            },
                        )  # type: ignore[arg-type]
                    )
                )
                # Let task pass pre-lock verification and block waiting for `_engine_lock`
                await asyncio.sleep(0.02)
                self.assertFalse(in_flight.done())
                # Revoke ADMIN_UID_A while lock is held!
                self.auth_ws.write_env("sg", token=BOT_SG_TOKEN, allowed=[ADMIN_UID_B], admins=[ADMIN_UID_B])
            finally:
                hub._engine_lock.release()

            r_toctou = await in_flight
            self.assertEqual(403, r_toctou.status)
            self.assertEqual("async_hosted", hub.engine_mode)
            self.assertEqual(7, hub.session_gen)
            self.assertEqual(("sg", ADMIN_UID_A), hub.session_owner)
            self.assertIsNotNone(hub.ctx)

        asyncio.run(_scenario())

    def test_defect2_group_chat_scope_without_chat_id_rejected_403_all_control_endpoints(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            fake_page = _FakeAsyncPage()
            hub.engine_mode = "async_hosted"
            hub.session_gen = 8
            hub.session_owner = ("sg", ADMIN_UID_A)
            hub.active_profile = "group_secret_profile"
            hub.ctx = types.SimpleNamespace(pages=[fake_page])
            tg_http = _FakeTGHttp()
            hub.tg.http = tg_http

            for scope_val in ("group", "supergroup", "channel"):
                base_ident = {
                    "bot": "sg",
                    "user_id": ADMIN_UID_A,
                    "source": "tg_cmd",
                    "chat_scope": scope_val,
                }
                checks = [
                    ("internal_action", srv.internal_action, {"action": "goto", "url": "https://evil.example", **base_ident}),
                    ("internal_config", srv.internal_config, {"takeover": True, "ensure_card": True, **base_ident}),
                    ("internal_start", srv.internal_start, {"url": "https://evil.example", **base_ident}),
                    ("internal_stop", srv.internal_stop, {**base_ident}),
                    ("internal_sync_start", srv.internal_sync_start, {**base_ident}),
                ]
                for ep_name, handler, payload in checks:
                    resp = await handler(_make_req(hub, payload))  # type: ignore[arg-type]
                    self.assertEqual(403, resp.status, f"{ep_name} with chat_scope={scope_val} must return 403")
                    body = _resp_json(resp)
                    self.assertFalse(body.get("ok"))
                    self.assertNotIn("group_secret_profile", str(body.get("error", "")))

            # Zero side effects across all endpoints
            self.assertEqual("async_hosted", hub.engine_mode)
            self.assertEqual(8, hub.session_gen)
            self.assertEqual(("sg", ADMIN_UID_A), hub.session_owner)
            self.assertFalse(hub.takeover)
            self.assertEqual([], fake_page.goto_calls)
            self.assertEqual([], tg_http.calls)
            self.assertEqual(0, _FakeAsyncCamoufoxCM.launch_count)

        asyncio.run(_scenario())

    def test_defect3_wait_human_switch_redacts_user_b_state_and_multistep_reverify(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            hub.engine_mode = "async_hosted"
            hub.session_gen = 10
            hub.takeover_gen = 1
            hub.session_owner = ("sg", ADMIN_UID_A)
            hub.latest_jpeg = b"\xff\xd8\xff\xe0JPEG"
            hub.tg.http = _FakeTGHttp(status=200, payload={"ok": True, "result": {"message_id": 901}})

            user_b_url = "https://private-b.example/vault"
            user_b_title = "User B Confidential Dashboard"
            user_b_profile = "user_b_private_profile"

            def _switch_to_user_b() -> None:
                hub.session_gen = 11
                hub.takeover_gen = 2
                hub.session_owner = ("sg", ADMIN_UID_B)
                hub.active_profile = user_b_profile
                hub.url = user_b_url
                hub.title = user_b_title
                hub.tabs = [{"index": 0, "url": user_b_url, "title": user_b_title, "active": True}]

            # 1a. Timeout path after session switched from User A (gen=10) to User B (gen=11)
            async def _switch_and_timeout(coro, timeout):
                coro.close()
                _switch_to_user_b()
                raise asyncio.TimeoutError()

            with mock.patch("asyncio.wait_for", side_effect=_switch_and_timeout):
                r_to = await srv.internal_action(
                    _make_req(
                        hub,
                        {
                            "action": "wait_human",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "source": "tg_cmd",
                            "timeout": 0.5,
                            "notify": True,
                        },
                    )  # type: ignore[arg-type]
                )
            self.assertEqual(408, r_to.status)
            raw_to = json.dumps(_resp_json(r_to), ensure_ascii=False)
            for secret_b in (user_b_url, user_b_title, user_b_profile):
                self.assertNotIn(secret_b, raw_to)
            self.assertEqual([], _resp_json(r_to).get("tabs"))

            # 1b. Wakeup path after session switched from User A (gen=10) to User B (gen=11)
            hub.session_gen = 10
            hub.takeover_gen = 1
            hub.session_owner = ("sg", ADMIN_UID_A)
            hub.active_profile = "user_a_profile"
            hub.url = "https://a.example/"
            hub.title = "User A"
            hub.tabs = []

            async def _switch_and_wake(coro, timeout):
                coro.close()
                _switch_to_user_b()
                return True

            with mock.patch("asyncio.wait_for", side_effect=_switch_and_wake):
                r_wake = await srv.internal_action(
                    _make_req(
                        hub,
                        {
                            "action": "wait_human",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "source": "tg_cmd",
                            "timeout": 0.5,
                            "notify": True,
                        },
                    )  # type: ignore[arg-type]
                )
            self.assertEqual(409, r_wake.status)
            raw_wake = json.dumps(_resp_json(r_wake), ensure_ascii=False)
            for secret_b in (user_b_url, user_b_title, user_b_profile):
                self.assertNotIn(secret_b, raw_wake)
            self.assertEqual([], _resp_json(r_wake).get("tabs"))

            # 2. Multi-step actions re-verify live admin RBAC across awaits BEFORE second step executes
            second_step_calls: list[str] = []

            class _RevokingLocator:
                def __init__(self, auth_ws: _TestAuthWorkspace) -> None:
                    self._auth_ws = auth_ws

                @property
                def first(self):
                    return self

                async def bounding_box(self, **kwargs):
                    self._auth_ws.write_env("sg", token=BOT_SG_TOKEN, allowed=[ADMIN_UID_B], admins=[ADMIN_UID_B])
                    return {"x": 10.0, "y": 20.0, "width": 40.0, "height": 20.0}

                async def click(self, **kwargs):
                    second_step_calls.append("loc.click")

                async def fill(self, text: str, **kwargs):
                    self._auth_ws.write_env("sg", token=BOT_SG_TOKEN, allowed=[ADMIN_UID_B], admins=[ADMIN_UID_B])

            class _RevokingKeyboard:
                def __init__(self, auth_ws: _TestAuthWorkspace) -> None:
                    self._auth_ws = auth_ws

                async def type(self, text: str, **kwargs):
                    self._auth_ws.write_env("sg", token=BOT_SG_TOKEN, allowed=[ADMIN_UID_B], admins=[ADMIN_UID_B])

                async def press(self, key: str):
                    second_step_calls.append(f"keyboard.press:{key}")

            class _RevokingMouse:
                def __init__(self, auth_ws: _TestAuthWorkspace) -> None:
                    self._auth_ws = auth_ws

                async def move(self, x: float, y: float):
                    self._auth_ws.write_env("sg", token=BOT_SG_TOKEN, allowed=[ADMIN_UID_B], admins=[ADMIN_UID_B])

                async def wheel(self, dx: float, dy: float):
                    second_step_calls.append("mouse.wheel")

            class _RevokingPage(_FakeAsyncPage):
                def __init__(self, auth_ws: _TestAuthWorkspace) -> None:
                    super().__init__()
                    self._auth_ws = auth_ws
                    self.keyboard = _RevokingKeyboard(auth_ws)
                    self.mouse = _RevokingMouse(auth_ws)  # type: ignore[assignment]

                def locator(self, selector: str):
                    return _RevokingLocator(self._auth_ws)

            for act_payload in (
                {"action": "click", "target": "#btn"},
                {"action": "fill", "selector": "#inp", "text": "hello", "submit": True},
                {"action": "type", "text": "hello", "submit": True},
                {"action": "scroll", "dx": 0, "dy": 200},
            ):
                self.auth_ws.write_env(
                    "sg",
                    token=BOT_SG_TOKEN,
                    allowed=[ADMIN_UID_A, ADMIN_UID_B],
                    admins=[ADMIN_UID_A, ADMIN_UID_B],
                )
                hub2 = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
                hub2.engine_mode = "async_hosted"
                hub2.session_gen = 20
                hub2.session_owner = ("sg", ADMIN_UID_A)
                hub2.ctx = types.SimpleNamespace(pages=[_RevokingPage(self.auth_ws)])
                r_step = await srv.internal_action(
                    _make_req(
                        hub2,
                        {
                            **act_payload,
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "source": "tg_cmd",
                            "notify": False,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_step.status, f"revoked mid-{act_payload['action']} must return 403")
            self.assertEqual([], second_step_calls, "Second step MUST NOT execute after live RBAC revocation")

        asyncio.run(_scenario())

    def test_defect4_internal_config_takeover_ensure_card_rollback_and_prewrite_validation(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            hub.engine_mode = "async_hosted"
            hub.session_gen = 12
            hub.takeover_gen = 1
            hub.session_owner = ("sg", ADMIN_UID_A)
            hub.latest_jpeg = b"\xff\xd8\xff\xe0JPEG"
            hub.tg.http = _FakeTGHttp(
                exc=RuntimeError(f"POST https://api.telegram.org/bot{BOT_SG_TOKEN}/sendPhoto failed")
            )

            # 1. Invalid expected_takeover_gen rejects with 400 BEFORE mutating public_url!
            r_bad_param = await srv.internal_config(
                _make_req(
                    hub,
                    {
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "source": "tg_cmd",
                        "public_url": "https://mutated.example",
                        "takeover": True,
                        "expected_takeover_gen": "not-an-int",
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(400, r_bad_param.status)
            self.assertEqual("https://live.example", hub.config["public_url"])
            self.assertFalse(hub.takeover)

            # 2. Same request takeover=True + ensure_card=True where sendPhoto raises -> 502 AND hub.takeover rolled back to False!
            r_rb = await srv.internal_config(
                _make_req(
                    hub,
                    {
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "source": "tg_cmd",
                        "takeover": True,
                        "ensure_card": True,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(502, r_rb.status)
            d_rb = _resp_json(r_rb)
            self.assertFalse(d_rb["ok"])
            self.assertFalse(d_rb["card_sent"])
            self.assertFalse(d_rb["takeover"])
            self.assertFalse(hub.takeover)
            self.assertNotIn(BOT_SG_TOKEN, json.dumps(d_rb))

            # 3. Post-broadcast_state() live RBAC revocation aborts subsequent set_takeover with 403
            orig_broadcast = hub.broadcast_state

            async def _revoke_on_broadcast():
                self.auth_ws.write_env("sg", token=BOT_SG_TOKEN, allowed=[ADMIN_UID_B], admins=[ADMIN_UID_B])
                await orig_broadcast()

            with mock.patch.object(hub, "broadcast_state", side_effect=_revoke_on_broadcast):
                with mock.patch.object(srv, "save_local_config", return_value=None):
                    r_rev = await srv.internal_config(
                        _make_req(
                            hub,
                            {
                                "bot": "sg",
                                "user_id": ADMIN_UID_A,
                                "chat_id": ADMIN_UID_A,
                                "source": "tg_cmd",
                                "direct_app_url": "https://app.example",
                                "takeover": True,
                            },
                        )  # type: ignore[arg-type]
                    )
            self.assertEqual(403, r_rev.status)
            self.assertFalse(hub.takeover)

        asyncio.run(_scenario())

    def test_defect5_cli_expected_session_gen_and_c4_sync_checkpoint_timeout_validation(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            fake_page = _FakeAsyncPage()
            hub.engine_mode = "async_hosted"
            hub.session_gen = 7
            hub.ctx = types.SimpleNamespace(pages=[fake_page])

            # 1. Pure local CLI (is_tg=False) stale expected_session_gen rejected in internal_start & internal_stop
            r_start_stale = await srv.internal_start(
                _make_req(hub, {"bot": "sg", "expected_session_gen": 1, "url": "https://example.com"})  # type: ignore[arg-type]
            )
            self.assertEqual(403, r_start_stale.status)
            self.assertEqual(0, _FakeAsyncCamoufoxCM.launch_count)

            r_stop_stale = await srv.internal_stop(
                _make_req(hub, {"bot": "sg", "expected_session_gen": 1})  # type: ignore[arg-type]
            )
            self.assertEqual(403, r_stop_stale.status)
            self.assertEqual("async_hosted", hub.engine_mode)

            # Direct hub.start_hosted / stop_hosted (source="cli", actor=None) also enforce expected_session_gen
            with self.assertRaises(PermissionError):
                await hub.start_hosted(initial_url="https://example.com", expected_session_gen=1)
            ok_s, _ = await hub.stop_hosted(expected_session_gen=1)
            self.assertFalse(ok_s)
            self.assertEqual("async_hosted", hub.engine_mode)

        asyncio.run(_scenario())

        # 2. LiveBrowserClient.start / action / stop forward expected_session_gen cleanly
        client = ctl.LiveBrowserClient(bot="sg")
        sent_bodies: list[tuple[str, dict]] = []

        def _cap_post(url: str, headers=None, json=None, timeout=None):
            sent_bodies.append((url, dict(json or {})))
            return types.SimpleNamespace(status_code=200, json=lambda: {"ok": True})

        client.session.post = _cap_post  # type: ignore[assignment]
        client.start(url="https://example.com", expected_session_gen=4)
        client.action("eval", expression="1+1", expected_session_gen=5)
        client.stop(expected_session_gen=5)
        self.assertEqual(4, sent_bodies[0][1].get("expected_session_gen"))
        self.assertEqual(5, sent_bodies[1][1].get("expected_session_gen"))
        self.assertEqual(5, sent_bodies[2][1].get("expected_session_gen"))

        # 3. C4: SyncLiveBridge.sync_checkpoint validates takeover_timeout (allows None, rejects <=0/NaN/inf/bool)
        bridge = object.__new__(ctl.SyncLiveBridge)
        bridge.enabled = False
        bridge._in_checkpoint = False
        self.assertFalse(bridge.sync_checkpoint(takeover_timeout=None))
        self.assertFalse(bridge.sync_checkpoint(takeover_timeout=5.0))
        for bad_t in (0, -1, -0.5, float("nan"), float("inf"), float("-inf"), True, False, "bad"):
            with self.subTest(takeover_timeout=bad_t):
                with self.assertRaises(ValueError):
                    bridge.sync_checkpoint(takeover_timeout=bad_t)  # type: ignore[arg-type]

    def test_cross_bot_override_blocked_inside_telegram_bridge_turn(self) -> None:
        """A Telegram bot turn (e.g. sgcli / main) MUST bind to its own bot and reject --bot <other>."""
        sgcli_id = str(300 + 3)
        sgcli_tok = f"{sgcli_id}:" + "SGCLI_" + "TEST_TOK_GAMMA"
        sgcli_env = {
            "AGY_TG_ENV_FILE": "/tmp/mock-bridge/.env.sgcli",
            "AGY_TG_BOT_TOKEN": sgcli_tok,
            "AGY_BOT_CHAT_ID": str(ADMIN_UID_A),
            "AGY_BOT_HANDLE": "mock_sgcli_bot",
        }
        with mock.patch.dict(os.environ, sgcli_env, clear=False):
            # Default / auto resolves to canonical spawning bot key ("sgcli")
            self.assertEqual("sgcli", ctl.LiveBrowserClient().bot)
            self.assertEqual("sgcli", ctl.LiveBrowserClient(bot="auto").bot)
            # Explicit self key or self numeric bot_id is allowed
            self.assertEqual("sgcli", ctl.LiveBrowserClient(bot="sgcli").bot)
            self.assertEqual(sgcli_id, ctl.LiveBrowserClient(bot=sgcli_id).bot)
            # Cross-bot override (--bot sg / --bot main / other numeric ID) MUST fail closed
            for wrong_bot in ("sg", "main", "jeff", str(200 + 2)):
                with self.subTest(wrong_bot=wrong_bot):
                    with self.assertRaises(ValueError):
                        ctl.LiveBrowserClient(bot=wrong_bot)
                    with self.assertRaises(ValueError):
                        ctl.SyncLiveBridge(types.SimpleNamespace(pages=[]), bot_hint=wrong_bot)

            # CLI entrypoint fails closed with rc=1 and zero HTTP calls
            with mock.patch("requests.Session.post", side_effect=AssertionError("Must not call HTTP on cross-bot mismatch")):
                with mock.patch.object(sys, "argv", ["live-browser", "--bot", "sg", "start"]):
                    rc = ctl.main()
            self.assertEqual(1, rc)

        # Main bot (.env) resolves to "main" and rejects "--bot sg"
        main_env = {
            "AGY_TG_ENV_FILE": "/tmp/mock-bridge/.env",
            "AGY_TG_BOT_TOKEN": BOT_MAIN_TOKEN,
            "AGY_BOT_CHAT_ID": str(ADMIN_UID_A),
        }
        with mock.patch.dict(os.environ, main_env, clear=False):
            self.assertEqual("main", ctl.LiveBrowserClient(bot="auto").bot)
            with self.assertRaises(ValueError):
                ctl.LiveBrowserClient(bot="sg")

        # Pure standalone CLI (no Telegram bridge env vars) retains explicit --bot & default "sg" compatibility
        self.assertEqual("sg", ctl.LiveBrowserClient(bot="auto").bot)
        self.assertEqual("sgcli", ctl.LiveBrowserClient(bot="sgcli").bot)
        self.assertEqual("main", ctl.LiveBrowserClient(bot="main").bot)

    def test_p0_cross_bot_fail_closed_when_env_key_missing_only_token_and_chat_id(self) -> None:
        """Even without AGY_TG_ENV_FILE (env_key=None), a Telegram turn with token+chat_id MUST block --bot sg."""
        tok_id = str(300 + 7)
        tok_val = f"{tok_id}:" + "TOKEN_ONLY_" + "TEST_DELTA"
        for label, extra in (
            ("missing_env_file", {}),
            ("malformed_env_file", {"AGY_TG_ENV_FILE": "/tmp/../.env.sg"}),
        ):
            with self.subTest(case=label):
                env_vars = {
                    "AGY_TG_BOT_TOKEN": tok_val,
                    "AGY_BOT_CHAT_ID": str(ADMIN_UID_A),
                    **extra,
                }
                with mock.patch.dict(os.environ, env_vars, clear=False):
                    if "AGY_TG_ENV_FILE" not in extra:
                        os.environ.pop("AGY_TG_ENV_FILE", None)
                    self.assertEqual(tok_id, ctl.resolve_bot_target("auto"))
                    self.assertEqual(tok_id, ctl.LiveBrowserClient(bot=tok_id).bot)
                    for wrong_bot in ("sg", "main", "other_bot", str(200 + 2)):
                        with self.assertRaises(ValueError):
                            ctl.resolve_bot_target(wrong_bot)
                        with self.assertRaises(ValueError):
                            ctl.LiveBrowserClient(bot=wrong_bot)
                        with self.assertRaises(ValueError):
                            ctl.SyncLiveBridge(types.SimpleNamespace(pages=[]), bot_hint=wrong_bot)
                    with mock.patch(
                        "requests.Session.post",
                        side_effect=AssertionError("Must not call HTTP on cross-bot mismatch"),
                    ):
                        with mock.patch.object(sys, "argv", ["live-browser", "--bot", "sg", "start"]):
                            self.assertEqual(1, ctl.main())

    def test_p0_parse_env_file_bot_key_strict_sanitization(self) -> None:
        """_parse_env_file_bot_key rejects traversal, control chars, shell metachars, spaces, extra dots, ignored suffixes."""
        self.assertEqual("main", ctl._parse_env_file_bot_key("/tmp/mock-bridge/.env"))
        self.assertEqual("sgcli", ctl._parse_env_file_bot_key("/tmp/mock-bridge/.env.sgcli"))
        self.assertEqual("bot_01-a", ctl._parse_env_file_bot_key("/tmp/mock-bridge/.env.bot_01-a"))

        bad_inputs = [
            None,
            "",
            "   ",
            "/tmp/../.env.sg",
            "../.env",
            "/tmp/bridge/..\\.env.sg",
            "/tmp/.env.sg;id",
            "/tmp/.env.sg;rm",
            "/tmp/.env.sg bot",
            "/tmp/.env. ",
            "/tmp/.env.sg\n",
            "/tmp/.env.sg\r",
            "/tmp/\x00.env.sg",
            "/tmp/.env.\x1bsg",
            "/tmp/.env.sg\t",
            "/tmp/.env.sg\x7f",
            "/tmp/.env.sg.bak",
            "/tmp/.env.a.b",
            "/tmp/.env.bak",
            "/tmp/.env.tmp",
            "/tmp/.env.example",
            "/tmp/.env.EXAMPLE",
            "/tmp/.env.disabled",
            "/tmp/.env.orig",
            "/tmp/.env." + ("a" * 33),
            "/tmp/.env.sg/",
        ]
        for raw in bad_inputs:
            with self.subTest(raw=raw):
                self.assertIsNone(ctl._parse_env_file_bot_key(raw))


class TestTelegram429FloodWaitAndBackoffContract(unittest.TestCase):
    """Prod-Release contract tests C1-C4 & C8 for `TelegramLiveCardPublisher` 429/5xx/dedup/isolation."""

    class _FakeFormData:
        def __init__(self) -> None:
            self.fields: dict[str, object] = {}

        def add_field(self, name: str, value, **_kw) -> None:
            self.fields[name] = value

    class _ScriptedHTTP:
        def __init__(self, script: list[object]) -> None:
            self._script = list(script)
            self.calls: list[tuple[str, str]] = []

        def post(self, url: str, data=None, json=None):
            endpoint = url.rsplit("/", 1)[-1]
            self.calls.append((endpoint, url))
            if not self._script:
                raise AssertionError(f"Unexpected extra HTTP call to {endpoint}")
            item = self._script.pop(0)
            if isinstance(item, BaseException):
                raise item

            status_val = item.get("http_status", 200) if isinstance(item, dict) else 200
            headers_val = item.get("headers", {}) if isinstance(item, dict) else {}
            json_exc = item.get("json_exc") if isinstance(item, dict) else None
            payload = item.get("body", item) if isinstance(item, dict) else item

            class _Resp:
                status = status_val
                headers = headers_val

                async def __aenter__(self_r):
                    return self_r

                async def __aexit__(self_r, *_a):
                    return False

                async def json(self_r):
                    if json_exc is not None:
                        raise json_exc
                    return payload

            return _Resp()

    @staticmethod
    def _write_dual_bot_envs(bdir: Path, *, main_role: str = "admin", sg_role: str = "admin") -> tuple[Path, Path]:
        env_main = bdir / ".env"
        env_sg = bdir / ".env.sg"
        if main_role == "admin":
            env_main.write_text(
                f"AGY_TG_BOT_TOKEN={BOT_MAIN_TOKEN}\n"
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID_A}\n"
                f"AGY_TG_ADMIN_USERS={ADMIN_UID_A}\n",
                encoding="utf-8",
            )
        elif main_role == "readonly":
            env_main.write_text(
                f"AGY_TG_BOT_TOKEN={BOT_MAIN_TOKEN}\n"
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID_A}\n"
                f"AGY_TG_READONLY_USERS={ADMIN_UID_A}\n",
                encoding="utf-8",
            )
        else:
            env_main.write_text(
                f"AGY_TG_BOT_TOKEN={BOT_MAIN_TOKEN}\n"
                f"AGY_TG_ALLOWED_CHATS=\n",
                encoding="utf-8",
            )
        env_sg.write_text(
            f"AGY_TG_BOT_TOKEN={BOT_SG_TOKEN}\n"
            f"AGY_TG_ALLOWED_CHATS={ADMIN_UID_B}\n"
            f"AGY_TG_ADMIN_USERS={ADMIN_UID_B if sg_role == 'admin' else ''}\n",
            encoding="utf-8",
        )
        return env_main, env_sg

    def test_c1_429_parsing_warning_and_per_bot_cooldown_gate(self) -> None:
        """C1: parse parameters.retry_after (untruncated 12704s), HTTP Retry-After header, reject malformed/bool/NaN/<=0,
        emit sanitized WARNING, short-circuit ALL outbound calls for that bot (incl. force=True & refresh_single_card->502),
        and auto-resume cleanly after cooldown expires."""
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            env_main, env_sg = self._write_dual_bot_envs(bdir)
            sample_doc = bdir / "sample.txt"
            sample_doc.write_bytes(b"hello-c1")
            clock = [1000.0]

            async def _scenario() -> None:
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "BRIDGE_ENV_FILES", {"main": env_main, "sg": env_sg}),
                    mock.patch.object(srv, "FormData", self._FakeFormData),
                    mock.patch.object(srv.time, "monotonic", side_effect=lambda: clock[0]),
                ):
                    # 1. Parsing edge cases: JSON retry_after, Retry-After header fallback, bool/NaN/neg/0 fallback
                    class _HdrResp:
                        def __init__(self, headers=None):
                            self.headers = headers or {}

                    self.assertEqual(
                        12704.0,
                        srv.TelegramLiveCardPublisher._extract_retry_after(
                            _HdrResp(),
                            {"ok": False, "error_code": 429, "parameters": {"retry_after": 12704}},
                        ),
                    )
                    self.assertEqual(
                        45.0,
                        srv.TelegramLiveCardPublisher._extract_retry_after(
                            _HdrResp({"Retry-After": "45"}),
                            None,
                        ),
                    )
                    for bad in (True, False, float("nan"), float("inf"), -10, 0, "not-a-num"):
                        self.assertEqual(
                            srv.TelegramLiveCardPublisher._FLOOD_DEFAULT_COOLDOWN_S,
                            srv.TelegramLiveCardPublisher._extract_retry_after(
                                _HdrResp(),
                                {"ok": False, "error_code": 429, "parameters": {"retry_after": bad}},
                            ),
                            f"bad retry_after={bad!r} must use safe positive floor",
                        )

                    # 2. editMessageMedia hits 429 with retry_after=12704 and token embedded in description
                    http_obj = self._ScriptedHTTP(
                        [
                            {
                                "http_status": 429,
                                "body": {
                                    "ok": False,
                                    "error_code": 429,
                                    "description": f"Too Many Requests bot{BOT_MAIN_TOKEN}: retry after 12704",
                                    "parameters": {"retry_after": 12704},
                                },
                            },
                            # After cooldown expiry, subsequent calls succeed
                            {"http_status": 200, "body": {"ok": True, "result": {"message_id": 701}}},
                            {"http_status": 200, "body": {"ok": True, "result": {"message_id": 702}}},
                            # Header-only 429 (invalid JSON body + Retry-After: 45) on sendPhoto
                            {
                                "http_status": 429,
                                "headers": {"Retry-After": "45"},
                                "json_exc": ValueError("non-json gateway body"),
                            },
                        ]
                    )
                    hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, LOCAL_TOKEN)
                    hub.tg.http = http_obj
                    hub.engine_mode = "async_hosted"
                    hub.session_gen = 1
                    hub.session_owner = ("main", ADMIN_UID_A)
                    hub.latest_jpeg = b"JPEG_C1_FRAME_1"
                    hub.tg.cards[("main", ADMIN_UID_A)] = {
                        "bot_key": "main",
                        "chat_id": ADMIN_UID_A,
                        "message_id": 701,
                        "session_gen": 1,
                        "owner": ("main", ADMIN_UID_A),
                        "last_sha1": "stale_sha",
                        "last_caption": "stale_cap",
                        "last_markup": None,
                        "last_ts": 0.0,
                    }

                    with self.assertLogs("live-browser", level="WARNING") as cm:
                        await hub.tg.tick_updates(force=False)
                    self.assertEqual(["editMessageMedia"], [c[0] for c in http_obj.calls])
                    joined_logs = "\n".join(cm.output)
                    self.assertIn("429", joined_logs)
                    self.assertIn("12704", joined_logs)
                    self.assertNotIn(BOT_MAIN_TOKEN, joined_logs)
                    self.assertAlmostEqual(12704.0, hub.tg._bot_flood_remaining("main"), delta=0.1)

                    # 3. During active cooldown, EVERY outbound method for `main` short-circuits with 0 new HTTP calls
                    for step in range(5):
                        clock[0] += 1.2
                        await hub.tg.tick_updates(force=False)
                        await hub.tg.tick_updates(force=True)
                    self.assertIsNone(await hub.tg.ensure_card("main", force_new=True, preferred_user_id=ADMIN_UID_A))
                    self.assertFalse(await hub.tg.send_clip_message("main", "clip text", preferred_user_id=ADMIN_UID_A))
                    self.assertFalse(await hub.tg.send_photo_bytes("main", b"JPEG_HD", preferred_user_id=ADMIN_UID_A))
                    self.assertFalse(
                        await hub.tg.send_document_file(
                            "main", sample_doc, "sample.txt", preferred_user_id=ADMIN_UID_A
                        )
                    )
                    self.assertFalse(await hub.tg._retire_orphan_card_message(BOT_MAIN_TOKEN, ADMIN_UID_A, 701))
                    ok_ref, _msg_ref, st_ref = await hub.tg._refresh_single_card_with_status(
                        "main", ADMIN_UID_A, message_id=701, expected_session_gen=1
                    )
                    self.assertFalse(ok_ref)
                    self.assertEqual(502, st_ref)
                    self.assertEqual(1, len(http_obj.calls), "Zero new HTTP calls allowed during 429 cooldown")

                    # 4. Advance past 12704s cooldown -> auto-resumes normally
                    clock[0] = 1000.0 + 12705.0
                    self.assertEqual(0.0, hub.tg._bot_flood_remaining("main"))
                    await hub.tg.tick_updates(force=False)
                    self.assertEqual(2, len(http_obj.calls))
                    self.assertTrue(await hub.tg.send_clip_message("main", "after-cooldown", preferred_user_id=ADMIN_UID_A))
                    self.assertEqual(3, len(http_obj.calls))

                    # 5. Header-only Retry-After: 45 on send_photo_bytes triggers 45s cooldown
                    self.assertFalse(await hub.tg.send_photo_bytes("main", b"JPEG_HD2", preferred_user_id=ADMIN_UID_A))
                    self.assertAlmostEqual(45.0, hub.tg._bot_flood_remaining("main"), delta=0.1)
                    self.assertFalse(await hub.tg.send_document_file("main", sample_doc, "sample.txt", preferred_user_id=ADMIN_UID_A))
                    self.assertEqual(4, len(http_obj.calls))

            asyncio.run(_scenario())

    def test_c2_5xx_and_transport_error_bounded_exponential_backoff(self) -> None:
        """C2: consecutive 502/503 or transport exceptions apply bounded exponential backoff (cap 60s),
        never looping every 1.2s; 200 ok or 400 message-is-not-modified resets backoff to normal 3s cadence."""
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            env_main, env_sg = self._write_dual_bot_envs(bdir)
            clock = [500.0]

            async def _scenario() -> None:
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "BRIDGE_ENV_FILES", {"main": env_main, "sg": env_sg}),
                    mock.patch.object(srv, "FormData", self._FakeFormData),
                    mock.patch.object(srv.time, "monotonic", side_effect=lambda: clock[0]),
                ):
                    http_obj = self._ScriptedHTTP(
                        [
                            {"http_status": 502, "body": {"ok": False, "error_code": 502, "description": "Bad Gateway"}},
                            {"http_status": 503, "body": {"ok": False, "error_code": 503, "description": "Service Unavailable"}},
                            TimeoutError("connect timeout"),
                            ConnectionError("connection reset"),
                            {"http_status": 502, "body": {"ok": False, "error_code": 502, "description": "Bad Gateway"}},
                            {"http_status": 503, "body": {"ok": False, "error_code": 503, "description": "Service Unavailable"}},
                            {"http_status": 200, "body": {"ok": True, "result": {"message_id": 701}}},
                            {"http_status": 503, "body": {"ok": False, "error_code": 503, "description": "Service Unavailable"}},
                            {"http_status": 400, "body": {"ok": False, "error_code": 400, "description": "Bad Request: message is not modified"}},
                        ]
                    )
                    hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, LOCAL_TOKEN)
                    hub.tg.http = http_obj
                    hub.engine_mode = "async_hosted"
                    hub.session_gen = 1
                    hub.session_owner = ("main", ADMIN_UID_A)
                    hub.latest_jpeg = b"JPEG_C2_FRAME"
                    card = {
                        "bot_key": "main",
                        "chat_id": ADMIN_UID_A,
                        "message_id": 701,
                        "session_gen": 1,
                        "owner": ("main", ADMIN_UID_A),
                        "last_sha1": "old",
                        "last_caption": "old",
                        "last_markup": None,
                        "last_ts": 100.0,
                    }
                    hub.tg.cards[("main", ADMIN_UID_A)] = card

                    expected_delays = [3.0, 6.0, 12.0, 24.0, 48.0, 60.0]
                    for idx, exp_delay in enumerate(expected_delays, start=1):
                        await hub.tg.tick_updates(force=False)
                        self.assertEqual(idx, len(http_obj.calls))
                        self.assertEqual(idx, card["transient_err_streak"])
                        self.assertEqual(100.0, card["last_ts"], "last_ts must remain unchanged on failure")
                        self.assertAlmostEqual(clock[0] + exp_delay, card["backoff_until"], delta=0.01)
                        # Simulate 1.2s maintenance ticks inside the backoff window -> 0 calls!
                        clock[0] += min(1.2, exp_delay - 0.1)
                        await hub.tg.tick_updates(force=False)
                        self.assertEqual(idx, len(http_obj.calls), "Must not hammer every 1.2s during backoff")
                        clock[0] = card["backoff_until"] + 0.05

                    # 7th call: 200 ok resets streak & backoff to 0
                    await hub.tg.tick_updates(force=False)
                    self.assertEqual(7, len(http_obj.calls))
                    self.assertEqual(0, card["transient_err_streak"])
                    self.assertEqual(0.0, card["backoff_until"])

                    # Change frame + advance 3.1s -> 8th call hits 503 (streak=1, delay=3s)
                    hub.latest_jpeg = b"JPEG_C2_FRAME_2"
                    clock[0] += 3.1
                    await hub.tg.tick_updates(force=False)
                    self.assertEqual(8, len(http_obj.calls))
                    self.assertEqual(1, card["transient_err_streak"])

                    # After 3.1s backoff expires -> 400 'message is not modified' also resets backoff to 0
                    clock[0] += 3.1
                    await hub.tg.tick_updates(force=False)
                    self.assertEqual(9, len(http_obj.calls))
                    self.assertEqual(0, card["transient_err_streak"])
                    self.assertEqual(0.0, card["backoff_until"])

            asyncio.run(_scenario())

    def test_c3_static_frame_caption_dedup_across_wall_clock_seconds(self) -> None:
        """C3: static frame/title/url/status/takeover/profile/public_url across advancing wall-clock seconds
        hits (sha, caption, markup) dedup fast-path with 0 extra editMessageMedia calls; real changes still refresh."""
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            env_main, env_sg = self._write_dual_bot_envs(bdir)
            clock = [200.0]
            wall_sec = [0]

            def _fake_strftime(fmt, *_args):
                return f"12:00:{wall_sec[0]:02d}"

            async def _scenario() -> None:
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "BRIDGE_ENV_FILES", {"main": env_main, "sg": env_sg}),
                    mock.patch.object(srv, "FormData", self._FakeFormData),
                    mock.patch.object(srv.time, "monotonic", side_effect=lambda: clock[0]),
                    mock.patch.object(srv.time, "strftime", side_effect=_fake_strftime),
                ):
                    http_obj = self._ScriptedHTTP(
                        [
                            {"http_status": 200, "body": {"ok": True, "result": {"message_id": 701}}}
                            for _ in range(10)
                        ]
                    )
                    hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, LOCAL_TOKEN)
                    hub.tg.http = http_obj
                    hub.engine_mode = "async_hosted"
                    hub.session_gen = 1
                    hub.session_owner = ("main", ADMIN_UID_A)
                    hub.latest_jpeg = b"STATIC_JPEG_BYTES"
                    hub.title = "Example Page"
                    hub.url = "https://example.com/dashboard"
                    hub.ai_status = "空闲等待"
                    hub.active_profile = "prof-1"
                    hub.tg.cards[("main", ADMIN_UID_A)] = {
                        "bot_key": "main",
                        "chat_id": ADMIN_UID_A,
                        "message_id": 701,
                        "session_gen": 1,
                        "owner": ("main", ADMIN_UID_A),
                        "last_sha1": "",
                        "last_caption": "",
                        "last_markup": None,
                        "last_ts": 0.0,
                    }

                    cap_live = hub.tg._build_caption(finished=False)
                    self.assertNotIn("12:00:", cap_live, "Live caption must not contain per-second wall-clock time")

                    # 10 ticks spaced >3s apart with advancing wall clock -> ONLY 1 editMessageMedia call!
                    for i in range(10):
                        wall_sec[0] = i
                        clock[0] += 4.0
                        await hub.tg.tick_updates(force=False)
                    self.assertEqual(1, len(http_obj.calls), "Remaining 9 ticks must hit (sha, caption, markup) dedup")

                    # Real state mutations (jpeg, title, url, ai_status, takeover, public_url/markup) still refresh
                    mutations = [
                        lambda: setattr(hub, "latest_jpeg", b"CHANGED_JPEG_BYTES"),
                        lambda: setattr(hub, "title", "Updated Title"),
                        lambda: setattr(hub, "url", "https://example.com/next"),
                        lambda: setattr(hub, "ai_status", "点击登录"),
                        lambda: setattr(hub, "takeover", True),
                        lambda: hub.config.__setitem__("public_url", "https://example.com/panel"),
                    ]
                    expected_calls = 1
                    for mutate in mutations:
                        mutate()
                        clock[0] += 4.0
                        expected_calls += 1
                        await hub.tg.tick_updates(force=False)
                        self.assertEqual(expected_calls, len(http_obj.calls))

            asyncio.run(_scenario())

    def test_c4_cross_bot_isolation_rbac_precedence_and_retire_attempt_preservation(self) -> None:
        """C4: (1) Bot A 429 never blocks Bot B; (2) live RBAC & ownership checks run BEFORE cooldown
        (revoked drops cards immediately; unauthorized/stale refresh returns 403, not 502);
        (3) session_gen change still stages pending_retire_cards, and cooldown skips do NOT consume retire_attempts."""
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            env_main, env_sg = self._write_dual_bot_envs(bdir, main_role="admin", sg_role="admin")
            clock = [300.0]

            async def _scenario() -> None:
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "BRIDGE_ENV_FILES", {"main": env_main, "sg": env_sg}),
                    mock.patch.object(srv, "FormData", self._FakeFormData),
                    mock.patch.object(srv.time, "monotonic", side_effect=lambda: clock[0]),
                ):
                    http_obj = self._ScriptedHTTP(
                        [
                            # 1. Bot main hits 429 (12704s)
                            {
                                "http_status": 429,
                                "body": {
                                    "ok": False,
                                    "error_code": 429,
                                    "parameters": {"retry_after": 12704},
                                    "description": "Too Many Requests",
                                },
                            },
                            # 2. Bot sg ensure_card sendPhoto succeeds
                            {"http_status": 200, "body": {"ok": True, "result": {"message_id": 801}}},
                            # 3. Bot sg tick_updates editMessageMedia succeeds
                            {"http_status": 200, "body": {"ok": True, "result": {"message_id": 801}}},
                            # 4. Bot sg send_photo_bytes succeeds
                            {"http_status": 200, "body": {"ok": True, "result": {"message_id": 802}}},
                            # 5. After main cooldown expires, pending retire succeeds
                            {"http_status": 200, "body": {"ok": True, "result": {"message_id": 701}}},
                        ]
                    )
                    hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, LOCAL_TOKEN)
                    hub.tg.http = http_obj
                    hub.engine_mode = "async_hosted"
                    hub.session_gen = 5
                    hub.session_owner = ("main", ADMIN_UID_A)
                    hub.latest_jpeg = b"JPEG_C4_MAIN"
                    hub.tg.cards[("main", ADMIN_UID_A)] = {
                        "bot_key": "main",
                        "chat_id": ADMIN_UID_A,
                        "message_id": 701,
                        "session_gen": 5,
                        "owner": ("main", ADMIN_UID_A),
                        "last_sha1": "s0",
                        "last_caption": "c0",
                        "last_markup": None,
                        "last_ts": 0.0,
                    }

                    # Trigger 429 on `main`
                    await hub.tg.tick_updates(force=False)
                    self.assertGreater(hub.tg._bot_flood_remaining("main"), 12000.0)
                    self.assertEqual(0.0, hub.tg._bot_flood_remaining("sg"))

                    # (1) Switch session owner to `sg` (which also makes main's card stale!) -> `sg` works freely
                    hub.session_gen = 6
                    hub.session_owner = ("sg", ADMIN_UID_B)
                    hub.latest_jpeg = b"JPEG_C4_SG_1"
                    created_sg = await hub.tg.ensure_card("sg", preferred_user_id=ADMIN_UID_B)
                    self.assertIsNotNone(created_sg)
                    self.assertEqual(801, created_sg["message_id"])
                    hub.latest_jpeg = b"JPEG_C4_SG_2"
                    clock[0] += 4.0
                    await hub.tg.tick_updates(force=False)
                    self.assertTrue(await hub.tg.send_photo_bytes("sg", b"JPEG_SG_HD", preferred_user_id=ADMIN_UID_B))

                    # (3) Meanwhile `main`'s stale card 701 was staged into pending_retire_cards AND
                    # repeated ticks during `main`'s 429 cooldown NEVER consumed retire_attempts!
                    self.assertNotIn(("main", ADMIN_UID_A), hub.tg.cards)
                    self.assertIn(("main", ADMIN_UID_A, 701), hub.tg.pending_retire_cards)
                    for _ in range(4):
                        clock[0] += 4.0
                        await hub.tg.tick_updates(force=False)
                        await hub.tg.retire_cards(session_gen=5, mark_finished=True)
                    self.assertIn(("main", ADMIN_UID_A, 701), hub.tg.pending_retire_cards)
                    self.assertEqual(
                        0,
                        int(hub.tg.pending_retire_cards[("main", ADMIN_UID_A, 701)].get("retire_attempts") or 0),
                        "429 cooldown skip MUST NOT consume retire_attempts",
                    )

                    # (2) Wrong-owner / stale refresh_single_card during cooldown MUST return 403 (never 502)
                    ok_stale, _msg_stale, st_stale = await hub.tg._refresh_single_card_with_status(
                        "main", ADMIN_UID_A, message_id=701, expected_session_gen=5
                    )
                    self.assertFalse(ok_stale)
                    self.assertEqual(403, st_stale)

                    # Cooldown expires -> pending card 701 retires cleanly!
                    clock[0] = 300.0 + 12705.0
                    await hub.tg.tick_updates(force=False)
                    self.assertNotIn(("main", ADMIN_UID_A, 701), hub.tg.pending_retire_cards)

                    # (2b) Live RBAC revocation DURING cooldown immediately drops active & pending cards (403 on refresh)
                    hub.tg._bot_flood_until["main"] = clock[0] + 5000.0
                    hub.session_gen = 7
                    hub.session_owner = ("main", ADMIN_UID_A)
                    hub.tg.cards[("main", ADMIN_UID_A)] = {
                        "bot_key": "main",
                        "chat_id": ADMIN_UID_A,
                        "message_id": 709,
                        "session_gen": 7,
                        "owner": ("main", ADMIN_UID_A),
                        "last_sha1": "s",
                        "last_caption": "c",
                        "last_markup": None,
                        "last_ts": 0.0,
                    }
                    hub.tg.pending_retire_cards[("main", ADMIN_UID_A, 708)] = {
                        "bot_key": "main",
                        "chat_id": ADMIN_UID_A,
                        "message_id": 708,
                        "session_gen": 6,
                        "owner": ("main", ADMIN_UID_A),
                    }
                    self._write_dual_bot_envs(bdir, main_role="readonly", sg_role="admin")
                    ok_rev, _msg_rev, st_rev = await hub.tg._refresh_single_card_with_status(
                        "main", ADMIN_UID_A, message_id=709, expected_session_gen=7
                    )
                    self.assertFalse(ok_rev)
                    self.assertEqual(403, st_rev)
                    self.assertNotIn(("main", ADMIN_UID_A), hub.tg.cards)
                    self.assertNotIn(("main", ADMIN_UID_A, 708), hub.tg.pending_retire_cards)

            asyncio.run(_scenario())


class TestTakeoverStabilityContractC1C2(unittest.TestCase):
    """Contract C1 & C2: Same-owner takeover idempotency / gen preservation + CAS / cross-owner / RBAC / timeout invariants."""

    def setUp(self) -> None:
        self._orig_env = dict(os.environ)
        os.environ.clear()
        os.environ.update(_clean_agy_env())
        self.auth_ws = _TestAuthWorkspace()
        self.auth_ws.write_env(
            "main",
            token=BOT_MAIN_TOKEN,
            allowed=[ADMIN_UID_A, ADMIN_UID_B],
            admins=[ADMIN_UID_A, ADMIN_UID_B],
        )
        self.auth_ws.write_env(
            "sg",
            token=BOT_SG_TOKEN,
            allowed=[ADMIN_UID_B],
            admins=[ADMIN_UID_B],
        )
        self._orig_bridge_dir = srv._BRIDGE_DIR
        self._orig_profiles_data_dir = srv.PROFILES_DATA_DIR
        self._orig_config_dir = srv.CONFIG_DIR
        self._orig_profiles_file = srv.PROFILES_FILE
        self._orig_web = srv.web
        self._orig_form_data = srv.FormData
        srv._BRIDGE_DIR = self.auth_ws.bridge_dir
        srv.PROFILES_DATA_DIR = self.auth_ws.root / "profiles-data"
        srv.CONFIG_DIR = self.auth_ws.root / "config"
        srv.PROFILES_FILE = srv.CONFIG_DIR / "profiles.json"
        if srv.web is None:
            srv.web = _FAKE_WEB  # type: ignore[assignment]
        if srv.FormData is None:
            srv.FormData = _FakeFormData  # type: ignore[assignment]
        os.environ["AGY_GOOGLE_SKILL_SCRIPTS"] = ""
        os.environ["AGY_LIVE_BROWSER_REQUIRE_PINNED"] = ""

    def tearDown(self) -> None:
        srv._BRIDGE_DIR = self._orig_bridge_dir
        srv.PROFILES_DATA_DIR = self._orig_profiles_data_dir
        srv.CONFIG_DIR = self._orig_config_dir
        srv.PROFILES_FILE = self._orig_profiles_file
        srv.web = self._orig_web
        srv.FormData = self._orig_form_data
        self.auth_ws.cleanup()
        os.environ.clear()
        os.environ.update(self._orig_env)

    def test_c1_same_owner_idempotent_takeover_and_wait_human_preserves_gen_and_allows_inflight_input(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            hub.engine_mode = "async_hosted"
            hub.session_gen = 5
            hub.takeover_gen = 1
            hub.session_owner = ("main", ADMIN_UID_A)
            page = _FakeAsyncPage(url="https://app.example/dashboard", title="Dashboard")
            click_calls: list[tuple] = []

            async def _fake_click(x: float, y: float, **kw: object) -> None:
                click_calls.append((x, y, kw))

            page.mouse.click = _fake_click  # type: ignore[attr-defined]
            hub.ctx = types.SimpleNamespace(pages=[page])
            hub.latest_jpeg = b"\xff\xd8\xff\xe0JPEG"
            hub.tg.http = _FakeTGHttp(status=200, payload={"ok": True, "result": {"message_id": 501}})

            bus_emits: list[dict[str, object]] = []

            async def _spy_emit(**kw: object) -> dict[str, object]:
                bus_emits.append(dict(kw))
                return dict(kw)

            hub._emit_takeover_bus_event = _spy_emit  # type: ignore[method-assign]

            # 1. Initial False -> True takeover increments takeover_gen to G=2
            ok1, _, sgen1, g = await hub.set_takeover(
                True, reason="initial", owner=("main", ADMIN_UID_A), actor=("main", ADMIN_UID_A), source="miniapp_ws"
            )
            self.assertTrue(ok1)
            self.assertEqual(5, sgen1)
            self.assertEqual(2, g)
            self.assertEqual(("main", ADMIN_UID_A), hub.takeover_owner)
            self.assertEqual(1, len(bus_emits))

            # 2. Same-owner duplicate WS set_takeover(True) preserves takeover_gen == G & emits 0 duplicate bus events
            ok2, _, _, g2 = await hub.set_takeover(
                True, reason="dup ws", owner=("main", ADMIN_UID_A), actor=("main", ADMIN_UID_A), source="miniapp_ws"
            )
            self.assertTrue(ok2)
            self.assertEqual(g, g2, "Duplicate WS set_takeover(True) by same owner MUST preserve takeover_gen")
            self.assertEqual(("main", ADMIN_UID_A), hub.takeover_owner)
            self.assertEqual(1, len(bus_emits), "Duplicate same-owner takeover MUST NOT emit duplicate bus event")

            # 3. Same-owner internal HTTP /internal/takeover preserves takeover_gen == G & owner
            r_int = await srv.internal_takeover(
                _make_req(
                    hub,
                    {
                        "active": True,
                        "bot": "main",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "source": "tg_cmd",
                        "reason": "dup internal",
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(200, r_int.status)
            self.assertEqual(g, hub.takeover_gen)
            self.assertEqual(("main", ADMIN_UID_A), hub.takeover_owner)
            self.assertEqual(1, len(bus_emits))

            # 4. Triggering wait_human while same owner already holds takeover preserves takeover_gen == G
            #    AND an in-flight human input carrying takeover_gen == G executes cleanly (0 false stale_takeover)!
            inflight_done = asyncio.Event()

            async def _run_inflight_then_handback() -> None:
                while hub._wait_human_waiters == 0:
                    await asyncio.sleep(0.01)
                self.assertEqual(g, hub.takeover_gen, "wait_human MUST preserve same-owner takeover_gen")
                self.assertEqual(("main", ADMIN_UID_A), hub.takeover_owner)
                await hub._execute_human_cmd_async(
                    {
                        "action": "click",
                        "x": 120.0,
                        "y": 240.0,
                        "_session_gen": 5,
                        "_takeover_gen": g,
                        "_bot_key": "main",
                        "_user_id": ADMIN_UID_A,
                    }
                )
                inflight_done.set()
                await hub.set_takeover(False, reason="done", actor=("main", ADMIN_UID_A), source="miniapp_ws")

            task_hb = asyncio.create_task(_run_inflight_then_handback())
            res_wh = await hub.execute_ai_action(
                {"action": "wait_human", "timeout": 5.0, "notify": False},
                auth_ctx={"is_tg": False},
            )
            await task_hb
            self.assertTrue(inflight_done.is_set())
            self.assertTrue(res_wh["ok"])
            self.assertTrue(res_wh["resumed"])
            self.assertEqual(1, len(click_calls), "In-flight click carrying preserved takeover_gen=G MUST execute")
            self.assertEqual((120.0, 240.0), (click_calls[0][0], click_calls[0][1]))
            await hub._cancel_and_await_bg_tasks()

        asyncio.run(_scenario())

    def test_c2_takeover_cas_cross_owner_ownerless_rbac_and_timeout_invariants(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
            hub.engine_mode = "async_hosted"
            hub.session_gen = 8
            hub.takeover_gen = 3
            hub.session_owner = ("main", ADMIN_UID_A)
            hub.latest_jpeg = b"\xff\xd8\xff\xe0JPEG"
            hub.tg.http = _FakeTGHttp(status=200, payload={"ok": True, "result": {"message_id": 601}})

            ok_init, _, _, g = await hub.set_takeover(
                True, reason="init", owner=("main", ADMIN_UID_A), actor=("main", ADMIN_UID_A), source="miniapp_ws"
            )
            self.assertTrue(ok_init)
            self.assertEqual(4, g)

            # (a) Same-owner wrong expected_takeover_gen = G-1 -> fail-closed reject with 0 state mutation
            ok_cas, _, s_cas, t_cas = await hub.set_takeover(
                True,
                reason="stale cas",
                owner=("main", ADMIN_UID_A),
                expected_takeover_gen=g - 1,
                actor=("main", ADMIN_UID_A),
                source="miniapp_ws",
            )
            self.assertFalse(ok_cas)
            self.assertEqual(8, s_cas)
            self.assertEqual(g, t_cas)
            self.assertEqual(g, hub.takeover_gen)
            self.assertEqual(("main", ADMIN_UID_A), hub.takeover_owner)

            r_int_cas = await srv.internal_takeover(
                _make_req(
                    hub,
                    {
                        "active": True,
                        "bot": "main",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "source": "tg_cmd",
                        "expected_takeover_gen": g - 1,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(403, r_int_cas.status)
            self.assertEqual(g, hub.takeover_gen)

            # (b) Cross-owner & ownerless mismatch MUST NOT reuse idempotent path, hijack or erase owner
            for label, call_kw in (
                ("cross-bot actor", {"owner": ("sg", ADMIN_UID_B), "actor": ("sg", ADMIN_UID_B)}),
                ("same-bot other user actor", {"owner": ("main", ADMIN_UID_B), "actor": ("main", ADMIN_UID_B)}),
                ("internal cross-bot owner", {"owner": ("sg", ADMIN_UID_B), "actor": None}),
                ("internal same-bot other user", {"owner": ("main", ADMIN_UID_B), "actor": None}),
                ("internal bot-only ownerless tuple", {"owner": ("main", None), "actor": None}),
            ):
                ok_x, _, _, t_x = await hub.set_takeover(True, reason=label, **call_kw)
                self.assertFalse(ok_x, f"{label} MUST fail-closed")
                self.assertEqual(g, t_x)
                self.assertEqual(g, hub.takeover_gen)
                self.assertEqual(("main", ADMIN_UID_A), hub.takeover_owner, f"{label} MUST NOT overwrite owner")

            # Named takeover on unowned session + internal owner=None MUST NOT erase named takeover_owner
            hub.session_owner = None
            ok_erase, _, _, t_erase = await hub.set_takeover(True, reason="try erase", owner=None, actor=None)
            self.assertFalse(ok_erase)
            self.assertEqual(g, t_erase)
            self.assertEqual(("main", ADMIN_UID_A), hub.takeover_owner)
            hub.session_owner = ("main", ADMIN_UID_A)

            # Ownerless takeover vs named request MUST fail-closed; ownerless -> ownerless MUST NOT preserve gen
            hub.takeover_owner = None
            ok_mix_actor, _, _, _ = await hub.set_takeover(
                True, reason="named over ownerless", owner=("main", ADMIN_UID_A), actor=("main", ADMIN_UID_A)
            )
            self.assertFalse(ok_mix_actor)
            ok_mix_int, _, _, _ = await hub.set_takeover(
                True, reason="internal named over ownerless", owner=("main", ADMIN_UID_A), actor=None
            )
            self.assertFalse(ok_mix_int)
            hub.session_owner = None
            t_before_ownerless = hub.takeover_gen
            ok_ol, _, _, t_after_ownerless = await hub.set_takeover(True, reason="ownerless dup", owner=None, actor=None)
            self.assertTrue(ok_ol)
            self.assertEqual(t_before_ownerless + 1, t_after_ownerless, "Ownerless->ownerless MUST NOT preserve takeover_gen")
            self.assertIsNone(hub.takeover_owner)

            # Restore named takeover for (c) RBAC downgrade & revocation tests
            hub.session_owner = ("main", ADMIN_UID_A)
            hub.takeover = False
            hub.takeover_owner = None
            ok_re, _, _, g_rbac = await hub.set_takeover(
                True, reason="reacquire", owner=("main", ADMIN_UID_A), actor=("main", ADMIN_UID_A)
            )
            self.assertTrue(ok_re)

            # (c) Owner live RBAC downgraded to readonly OR denied: BOTH actor & internal calls MUST fail-closed
            for bad_role in ("readonly", "denied"):
                if bad_role == "readonly":
                    self.auth_ws.write_env(
                        "main",
                        token=BOT_MAIN_TOKEN,
                        allowed=[ADMIN_UID_A, ADMIN_UID_B],
                        admins=[ADMIN_UID_B],
                        readonly=[ADMIN_UID_A],
                    )
                else:
                    self.auth_ws.write_env(
                        "main",
                        token=BOT_MAIN_TOKEN,
                        allowed=[ADMIN_UID_B],
                        admins=[ADMIN_UID_B],
                    )
                ok_act_bad, _, _, _ = await hub.set_takeover(
                    True, reason=f"actor {bad_role}", owner=("main", ADMIN_UID_A), actor=("main", ADMIN_UID_A)
                )
                self.assertFalse(ok_act_bad, f"actor call under {bad_role} MUST fail-closed")
                ok_int_bad, _, _, _ = await hub.set_takeover(
                    True, reason=f"internal {bad_role}", owner=("main", ADMIN_UID_A), actor=None
                )
                self.assertFalse(ok_int_bad, f"internal call under {bad_role} MUST re-check live RBAC and fail-closed")
                self.assertEqual(g_rbac, hub.takeover_gen)

            # Restore admin RBAC for (d) monotonic release / disconnect / revocation / timeout invariants
            self.auth_ws.write_env(
                "main",
                token=BOT_MAIN_TOKEN,
                allowed=[ADMIN_UID_A, ADMIN_UID_B],
                admins=[ADMIN_UID_A, ADMIN_UID_B],
            )

            # (d1) Normal release increments takeover_gen
            ok_rel, _, _, g_after_rel = await hub.set_takeover(False, reason="release", actor=("main", ADMIN_UID_A))
            self.assertTrue(ok_rel)
            self.assertEqual(g_rbac + 1, g_after_rel)
            self.assertFalse(hub.takeover)

            # (d2) Disconnect auto-release increments takeover_gen
            ok_tk2, _, _, g_tk2 = await hub.set_takeover(True, owner=("main", ADMIN_UID_A), actor=("main", ADMIN_UID_A))
            self.assertTrue(ok_tk2)
            rel_disc = await hub.release_takeover_on_disconnect("main", ADMIN_UID_A, had_admin_role=True)
            self.assertTrue(rel_disc)
            self.assertEqual(g_tk2 + 1, hub.takeover_gen)
            self.assertFalse(hub.takeover)

            # (d3) Execution-boundary RBAC revocation increments takeover_gen
            ok_tk3, _, _, g_tk3 = await hub.set_takeover(True, owner=("main", ADMIN_UID_A), actor=("main", ADMIN_UID_A))
            self.assertTrue(ok_tk3)
            await hub._revoke_actor_on_exec_boundary("main", ADMIN_UID_A, "denied")
            self.assertEqual(g_tk3 + 1, hub.takeover_gen)
            self.assertFalse(hub.takeover)

            # (d4) Same-gen wait_human timeout cleanup strictly increments takeover_gen
            ok_tk4, _, _, g_tk4 = await hub.set_takeover(True, owner=("main", ADMIN_UID_A), actor=("main", ADMIN_UID_A))
            self.assertTrue(ok_tk4)
            r_to = await srv.internal_action(
                _make_req(
                    hub,
                    {
                        "action": "wait_human",
                        "bot": "main",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "source": "tg_cmd",
                        "timeout": 0.04,
                        "notify": False,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(408, r_to.status)
            self.assertFalse(hub.takeover)
            self.assertEqual(g_tk4 + 1, hub.takeover_gen, "Same-gen wait_human timeout cleanup MUST increment takeover_gen")

            # (d5) Cross-gen / owner-switch race during wait_human returns 408/409, preserves User B takeover & leaks 0 fields
            hub.session_gen = 20
            hub.takeover_gen = 10
            hub.session_owner = ("main", ADMIN_UID_A)
            hub.url = "https://user-a.example/page"
            hub.title = "User A"
            ok_tk5, _, _, g_tk5 = await hub.set_takeover(True, owner=("main", ADMIN_UID_A), actor=("main", ADMIN_UID_A))
            self.assertTrue(ok_tk5)

            async def _switch_to_user_b_and_timeout(coro, timeout):
                coro.close()
                hub.session_gen = 21
                hub.takeover_gen = 15
                hub.session_owner = ("sg", ADMIN_UID_B)
                hub.takeover = True
                hub.takeover_owner = ("sg", ADMIN_UID_B)
                hub.url = "https://secret-user-b.example/private?token=SECRET_B"
                hub.title = "Secret User B"
                hub.ai_allowed_event.clear()
                raise asyncio.TimeoutError()

            with mock.patch("asyncio.wait_for", side_effect=_switch_to_user_b_and_timeout):
                r_xto = await srv.internal_action(
                    _make_req(
                        hub,
                        {
                            "action": "wait_human",
                            "bot": "main",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "source": "tg_cmd",
                            "timeout": 0.5,
                            "notify": False,
                        },
                    )  # type: ignore[arg-type]
                )
            self.assertEqual(408, r_xto.status)
            d_xto = _resp_json(r_xto)
            self.assertNotIn("secret-user-b.example", json.dumps(d_xto))
            self.assertNotIn("Secret User B", json.dumps(d_xto))
            self.assertEqual(21, hub.session_gen)
            self.assertEqual(15, hub.takeover_gen)
            self.assertTrue(hub.takeover)
            self.assertEqual(("sg", ADMIN_UID_B), hub.takeover_owner)

            # Cross-gen wakeup (session switched to User B and ai_allowed_event set) -> 409 + 0 User B leak!
            hub.session_gen = 30
            hub.takeover_gen = 20
            hub.session_owner = ("main", ADMIN_UID_A)
            hub.takeover = False
            hub.takeover_owner = None
            hub.ai_allowed_event.set()

            async def _switch_to_user_b_and_wake(coro, timeout):
                coro.close()
                hub.session_gen = 31
                hub.takeover_gen = 25
                hub.session_owner = ("sg", ADMIN_UID_B)
                hub.takeover = True
                hub.takeover_owner = ("sg", ADMIN_UID_B)
                hub.url = "https://secret-user-b.example/wake"
                hub.title = "Secret User B Wake"
                return True

            with mock.patch("asyncio.wait_for", side_effect=_switch_to_user_b_and_wake):
                r_xwake = await srv.internal_action(
                    _make_req(
                        hub,
                        {
                            "action": "wait_human",
                            "bot": "main",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "source": "tg_cmd",
                            "timeout": 0.5,
                            "notify": False,
                        },
                    )  # type: ignore[arg-type]
                )
            self.assertEqual(409, r_xwake.status)
            d_xwake = _resp_json(r_xwake)
            self.assertNotIn("secret-user-b.example", json.dumps(d_xwake))
            self.assertNotIn("Secret User B Wake", json.dumps(d_xwake))
            self.assertTrue(hub.takeover)
            self.assertEqual(("sg", ADMIN_UID_B), hub.takeover_owner)
            await hub._cancel_and_await_bg_tasks()

        asyncio.run(_scenario())


class TestWorkstreamEBoundOwnerBotRBAC(unittest.TestCase):
    """C3, C4, C5: Token-derived active_owner_bot_id same-admin RBAC alignment and strict isolation boundaries."""

    def setUp(self) -> None:
        self._orig_env = dict(os.environ)
        os.environ.clear()
        os.environ.update(_clean_agy_env())
        self.auth_ws = _TestAuthWorkspace()
        self._orig_bridge_dir = srv._BRIDGE_DIR
        self._orig_profiles_data_dir = srv.PROFILES_DATA_DIR
        self._orig_config_dir = srv.CONFIG_DIR
        self._orig_profiles_file = srv.PROFILES_FILE
        self._orig_web = srv.web
        self._orig_form_data = srv.FormData
        srv._BRIDGE_DIR = self.auth_ws.bridge_dir
        srv.PROFILES_DATA_DIR = self.auth_ws.root / "profiles-data"
        srv.CONFIG_DIR = self.auth_ws.root / "config"
        srv.PROFILES_FILE = srv.CONFIG_DIR / "profiles.json"
        if srv.web is None:
            srv.web = _FAKE_WEB  # type: ignore[assignment]
        if srv.FormData is None:
            srv.FormData = _FakeFormData  # type: ignore[assignment]
        os.environ["AGY_GOOGLE_SKILL_SCRIPTS"] = ""
        os.environ["AGY_LIVE_BROWSER_REQUIRE_PINNED"] = ""

    def tearDown(self) -> None:
        srv._BRIDGE_DIR = self._orig_bridge_dir
        srv.PROFILES_DATA_DIR = self._orig_profiles_data_dir
        srv.CONFIG_DIR = self._orig_config_dir
        srv.PROFILES_FILE = self._orig_profiles_file
        srv.web = self._orig_web
        srv.FormData = self._orig_form_data
        self.auth_ws.cleanup()
        os.environ.clear()
        os.environ.update(self._orig_env)

    @staticmethod
    def _make_active_hub(
        *,
        owner: tuple[str, int | None] | None = ("main", ADMIN_UID_A),
        owner_bot_handle: str | None = "sg_bot",
        owner_bot_id: int | None = 202,
        takeover: bool = False,
        takeover_owner: tuple[str, int | None] | None = None,
    ) -> tuple[srv.LiveBrowserHub, _FakeAsyncPage]:
        hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, LOCAL_TOKEN)
        page = _FakeAsyncPage(url="https://app.example/dashboard", title="Admin Dashboard")
        hub.engine_mode = "async_hosted"
        hub.session_gen = 42
        hub.takeover_gen = 7
        hub.session_owner = owner
        hub.active_owner_bot = owner_bot_handle
        hub.active_owner_bot_id = owner_bot_id
        hub.active_profile = "work-profile"
        hub.url = page.url
        hub.title = page._title
        hub.tabs = [{"index": 0, "url": page.url, "title": page._title, "active": True}]
        hub.ctx = types.SimpleNamespace(pages=[page])
        hub.takeover = takeover
        hub.takeover_owner = takeover_owner
        if takeover:
            hub.ai_allowed_event.clear()
        else:
            hub.ai_allowed_event.set()
        return hub, page

    def test_c3_bound_owner_bot_same_admin_grant_token_derived_only_and_no_start_preempt(self) -> None:
        async def _scenario() -> None:
            # 1. Positive path: session owned by ("main", ADMIN_UID_A), bound to sg (bot_id=202 in id_map)
            hub, page = self._make_active_hub()

            # 1a. internal_status -> 200 unredacted full state
            r_st = await srv.internal_status(
                _make_req(
                    hub,
                    {},
                    query={
                        "source": "tg_cmd",
                        "chat_scope": "private",
                        "bot": "sg",
                        "user_id": str(ADMIN_UID_A),
                        "chat_id": str(ADMIN_UID_A),
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(200, r_st.status)
            d_st = _resp_json(r_st)
            self.assertTrue(d_st["running"])
            self.assertFalse(bool(d_st.get("session_restricted")))
            self.assertEqual("https://app.example/dashboard", d_st["url"])
            self.assertEqual("work-profile", d_st["profile"])

            # 1b. internal_action -> 200
            r_act = await srv.internal_action(
                _make_req(
                    hub,
                    {
                        "action": "eval",
                        "expression": "document.title",
                        "source": "tg_cmd",
                        "chat_scope": "private",
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                        "notify": False,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(200, r_act.status)
            self.assertTrue(_resp_json(r_act)["ok"])
            self.assertEqual(1, len(page.eval_calls))

            # 1c. internal_start & internal_sync_start MUST remain 403 (no preempt/restart by bound bot!)
            r_start = await srv.internal_start(
                _make_req(
                    hub,
                    {
                        "url": "https://example.org",
                        "restart": True,
                        "source": "tg_cmd",
                        "chat_scope": "private",
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(403, r_start.status)

            r_sync = await srv.internal_sync_start(
                _make_req(
                    hub,
                    {
                        "source": "tg_cmd",
                        "chat_scope": "private",
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "chat_id": ADMIN_UID_A,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(403, r_sync.status)

            # 1d. internal_stop (via stop_hosted) -> 200
            with mock.patch.object(hub, "_stop_hosted_locked", new=mock.AsyncMock()) as m_stop_locked:
                r_stop = await srv.internal_stop(
                    _make_req(
                        hub,
                        {
                            "source": "tg_cmd",
                            "chat_scope": "private",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                        },
                    )  # type: ignore[arg-type]
                )
            self.assertEqual(200, r_stop.status)
            m_stop_locked.assert_awaited_once()

            # 2. Handle-only spoof (active_owner_bot="sg" with active_owner_bot_id=None or unmapped 999999) -> ALL 403 / redacted!
            for bad_bid in (None, 999999, 101):
                hub_spoof, page_spoof = self._make_active_hub(owner_bot_handle="sg", owner_bot_id=bad_bid)
                r_st_bad = await srv.internal_status(
                    _make_req(
                        hub_spoof,
                        {},
                        query={
                            "source": "tg_cmd",
                            "chat_scope": "private",
                            "bot": "sg",
                            "user_id": str(ADMIN_UID_A),
                            "chat_id": str(ADMIN_UID_A),
                        },
                    )  # type: ignore[arg-type]
                )
                d_bad = _resp_json(r_st_bad)
                self.assertTrue(d_bad.get("session_restricted"), f"Handle-only spoof with bid={bad_bid} must redact")
                self.assertNotIn("app.example", json.dumps(d_bad))

                r_act_bad = await srv.internal_action(
                    _make_req(
                        hub_spoof,
                        {
                            "action": "eval",
                            "expression": "1+1",
                            "source": "tg_cmd",
                            "chat_scope": "private",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "notify": False,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_act_bad.status, f"Handle-only spoof action must return 403 (bid={bad_bid})")
                self.assertEqual([], page_spoof.eval_calls)

                r_stop_bad = await srv.internal_stop(
                    _make_req(
                        hub_spoof,
                        {
                            "source": "tg_cmd",
                            "chat_scope": "private",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_stop_bad.status, f"Handle-only spoof stop must return 403 (bid={bad_bid})")

        asyncio.run(_scenario())

    def test_c4_cross_tenant_revocation_group_rebind_and_unowned_isolation(self) -> None:
        async def _scenario() -> None:
            hub, _ = self._make_active_hub()

            # 1. Cross-user ADMIN_UID_B on bound bot sg -> redacted & 403
            r_st_b = await srv.internal_status(
                _make_req(
                    hub,
                    {},
                    query={
                        "source": "tg_cmd",
                        "chat_scope": "private",
                        "bot": "sg",
                        "user_id": str(ADMIN_UID_B),
                        "chat_id": str(ADMIN_UID_B),
                    },
                )  # type: ignore[arg-type]
            )
            self.assertTrue(_resp_json(r_st_b).get("session_restricted"))
            self.assertNotIn("app.example", json.dumps(_resp_json(r_st_b)))
            for ep_fn, ep_body in (
                (srv.internal_action, {"action": "eval", "expression": "1", "notify": False}),
                (srv.internal_stop, {}),
            ):
                r_b = await ep_fn(
                    _make_req(
                        hub,
                        {
                            **ep_body,
                            "source": "tg_cmd",
                            "chat_scope": "private",
                            "bot": "sg",
                            "user_id": ADMIN_UID_B,
                            "chat_id": ADMIN_UID_B,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_b.status)

            # 2. Group chat scope or negative chat_id on bound bot sg + ADMIN_UID_A -> redacted & 403
            for grp_fields in (
                {"chat_scope": "group", "user_id": ADMIN_UID_A},
                {"chat_scope": "private", "user_id": ADMIN_UID_A, "chat_id": GROUP_CHAT_ID},
            ):
                q_grp = {k: str(v) for k, v in grp_fields.items()}
                q_grp.update({"source": "tg_cmd", "bot": "sg"})
                r_stg = await srv.internal_status(_make_req(hub, {}, query=q_grp))  # type: ignore[arg-type]
                self.assertTrue(_resp_json(r_stg).get("session_restricted"))
                self.assertNotIn("app.example", json.dumps(_resp_json(r_stg)))

                r_actg = await srv.internal_action(
                    _make_req(
                        hub,
                        {"action": "eval", "expression": "1", "source": "tg_cmd", "bot": "sg", "notify": False, **grp_fields},
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_actg.status)
                r_stopg = await srv.internal_stop(
                    _make_req(hub, {"source": "tg_cmd", "bot": "sg", **grp_fields})  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_stopg.status)

            # 3. Unowned CLI sessions (None or ("main", None)) -> bound sg + ADMIN_UID_A gets redacted & 403
            for unowned in (None, ("main", None)):
                hub_cli, _ = self._make_active_hub(owner=unowned)
                r_st_u = await srv.internal_status(
                    _make_req(
                        hub_cli,
                        {},
                        query={"source": "tg_cmd", "chat_scope": "private", "bot": "sg", "user_id": str(ADMIN_UID_A)},
                    )  # type: ignore[arg-type]
                )
                self.assertTrue(_resp_json(r_st_u).get("session_restricted"))
                r_act_u = await srv.internal_action(
                    _make_req(
                        hub_cli,
                        {
                            "action": "eval",
                            "expression": "1",
                            "source": "tg_cmd",
                            "chat_scope": "private",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "notify": False,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_act_u.status)
                r_stop_u = await srv.internal_stop(
                    _make_req(
                        hub_cli,
                        {"source": "tg_cmd", "chat_scope": "private", "bot": "sg", "user_id": ADMIN_UID_A},
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_stop_u.status)

            # 4. Readonly / revoked ADMIN_UID_A on bound bot sg -> redacted & 403
            self.auth_ws.write_env(
                "sg",
                token=BOT_SG_TOKEN,
                allowed=[ADMIN_UID_A, ADMIN_UID_B],
                admins=[ADMIN_UID_B],
                readonly=[ADMIN_UID_A],
            )
            r_st_ro = await srv.internal_status(
                _make_req(
                    hub,
                    {},
                    query={"source": "tg_cmd", "chat_scope": "private", "bot": "sg", "user_id": str(ADMIN_UID_A)},
                )  # type: ignore[arg-type]
            )
            self.assertTrue(_resp_json(r_st_ro).get("session_restricted"))
            r_act_ro = await srv.internal_action(
                _make_req(
                    hub,
                    {
                        "action": "eval",
                        "expression": "1",
                        "source": "tg_cmd",
                        "chat_scope": "private",
                        "bot": "sg",
                        "user_id": ADMIN_UID_A,
                        "notify": False,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(403, r_act_ro.status)

            # Restore ADMIN_UID_A as admin on sg for multi-step await revocation & hot-rebind tests
            self.auth_ws.write_env(
                "sg",
                token=BOT_SG_TOKEN,
                allowed=[ADMIN_UID_A, ADMIN_UID_B],
                admins=[ADMIN_UID_A, ADMIN_UID_B],
            )

            # 5. Multi-step execute_ai_action: mid-flight revocation OR hot-rebind across await aborts 2nd step!
            for revoke_mode in ("rbac_downgrade", "hot_rebind"):
                self.auth_ws.write_env(
                    "sg",
                    token=BOT_SG_TOKEN,
                    allowed=[ADMIN_UID_A, ADMIN_UID_B],
                    admins=[ADMIN_UID_A, ADMIN_UID_B],
                )
                hub_ms, _ = self._make_active_hub()
                step2_calls: list[str] = []

                class _StepRevokingLoc:
                    @property
                    def first(self):
                        return self

                    async def fill(self, _text: str, **_kw: object) -> None:
                        if revoke_mode == "rbac_downgrade":
                            self.auth_ws_ref.write_env(
                                "sg",
                                token=BOT_SG_TOKEN,
                                allowed=[ADMIN_UID_A, ADMIN_UID_B],
                                admins=[ADMIN_UID_B],
                                readonly=[ADMIN_UID_A],
                            )
                        else:
                            hub_ms.active_owner_bot = "main_bot"
                            hub_ms.active_owner_bot_id = 101

                    def __init__(self, auth_ws_ref: _TestAuthWorkspace) -> None:
                        self.auth_ws_ref = auth_ws_ref

                class _StepKeyboard:
                    async def press(self, key: str) -> None:
                        step2_calls.append(f"press:{key}")

                ms_page = _FakeAsyncPage()
                ms_page.locator = lambda _sel: _StepRevokingLoc(self.auth_ws)  # type: ignore[attr-defined]
                ms_page.keyboard = _StepKeyboard()  # type: ignore[attr-defined]
                hub_ms.ctx = types.SimpleNamespace(pages=[ms_page])

                r_ms = await srv.internal_action(
                    _make_req(
                        hub_ms,
                        {
                            "action": "fill",
                            "selector": "#q",
                            "text": "hello",
                            "submit": True,
                            "source": "tg_cmd",
                            "chat_scope": "private",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "notify": False,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_ms.status, f"Mid-flight {revoke_mode} must abort with 403")
                self.assertEqual([], step2_calls, f"Mid-flight {revoke_mode} must execute 0 step-2 actions")

            # 6. Hot-rebind via /internal/owner-bot -> old bound bot sg immediately loses access
            self.auth_ws.write_env(
                "sg",
                token=BOT_SG_TOKEN,
                allowed=[ADMIN_UID_A, ADMIN_UID_B],
                admins=[ADMIN_UID_A, ADMIN_UID_B],
            )
            hub_rb, _ = self._make_active_hub()
            r_rb = await srv.internal_owner_bot(
                _make_req(
                    hub_rb,
                    {
                        "owner_bot": "main_bot",
                        "owner_bot_id": 101,
                        "source": "tg_cmd",
                        "chat_scope": "private",
                        "bot": "main",
                        "user_id": ADMIN_UID_A,
                    },
                )  # type: ignore[arg-type]
            )
            self.assertEqual(200, r_rb.status)
            r_old_st = await srv.internal_status(
                _make_req(
                    hub_rb,
                    {},
                    query={"source": "tg_cmd", "chat_scope": "private", "bot": "sg", "user_id": str(ADMIN_UID_A)},
                )  # type: ignore[arg-type]
            )
            self.assertTrue(_resp_json(r_old_st).get("session_restricted"))
            r_old_stop = await srv.internal_stop(
                _make_req(
                    hub_rb,
                    {"source": "tg_cmd", "chat_scope": "private", "bot": "sg", "user_id": ADMIN_UID_A},
                )  # type: ignore[arg-type]
            )
            self.assertEqual(403, r_old_stop.status)

            # 7. Session stop clears active_owner_bot_id immediately
            hub_clr, _ = self._make_active_hub()
            hub_clr._clear_session_caches()
            self.assertIsNone(hub_clr.active_owner_bot_id)
            self.assertFalse(hub_clr._is_bound_owner_bot_key("sg"))

        asyncio.run(_scenario())

    def test_c5_takeover_mutex_and_telegram_card_isolation(self) -> None:
        async def _scenario() -> None:
            hub, page = self._make_active_hub(
                owner=("main", ADMIN_UID_A),
                owner_bot_handle="sg_bot",
                owner_bot_id=202,
                takeover=True,
                takeover_owner=("main", ADMIN_UID_A),
            )
            hub.tg.cards[("main", ADMIN_UID_A)] = {
                "message_id": 777,
                "session_gen": hub.session_gen,
                "owner_bot": "main",
                "owner_uid": ADMIN_UID_A,
            }

            # 1. Bound bot sg CANNOT release, alter, or preempt takeover via set_takeover / internal_takeover / internal_config
            for want in (False, True):
                ok_tk, _err_tk, _, _ = await hub.set_takeover(
                    want,
                    reason="bound_bot_attempt",
                    actor=("sg", ADMIN_UID_A),
                    expected_session_gen=hub.session_gen,
                    expected_takeover_gen=hub.takeover_gen,
                )
                self.assertFalse(ok_tk)
                self.assertTrue(hub.takeover)
                self.assertEqual(("main", ADMIN_UID_A), hub.takeover_owner)

                r_tk = await srv.internal_takeover(
                    _make_req(
                        hub,
                        {
                            "active": want,
                            "source": "tg_cmd",
                            "chat_scope": "private",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_tk.status)
                self.assertTrue(hub.takeover)
                self.assertEqual(("main", ADMIN_UID_A), hub.takeover_owner)

                r_cfg = await srv.internal_config(
                    _make_req(
                        hub,
                        {
                            "takeover": want,
                            "source": "tg_cmd",
                            "chat_scope": "private",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_cfg.status)
                self.assertTrue(hub.takeover)
                self.assertEqual(("main", ADMIN_UID_A), hub.takeover_owner)

            # 2. Bound bot sg CANNOT bypass takeover barrier to execute mutating AI action
            act_task = asyncio.create_task(
                srv.internal_action(
                    _make_req(
                        hub,
                        {
                            "action": "goto",
                            "url": "https://example.org/blocked-by-takeover",
                            "source": "tg_cmd",
                            "chat_scope": "private",
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "notify": False,
                        },
                    )  # type: ignore[arg-type]
                )
            )
            await asyncio.sleep(0.05)
            self.assertFalse(act_task.done(), "Mutating AI action from bound bot MUST block while takeover is active")
            self.assertEqual([], page.goto_calls)
            act_task.cancel()
            try:
                await act_task
            except asyncio.CancelledError:
                pass

            # 3. Cross-bot TG Live Card callback from sg on main's card -> 403 everywhere
            for card_ep, card_body in (
                (srv.internal_stop, {}),
                (srv.internal_takeover, {"active": False}),
                (srv.internal_config, {"refresh_card": True}),
            ):
                r_card = await card_ep(
                    _make_req(
                        hub,
                        {
                            **card_body,
                            "source": "tg_card",
                            "from_card": True,
                            "bot": "sg",
                            "user_id": ADMIN_UID_A,
                            "chat_id": ADMIN_UID_A,
                            "message_id": 777,
                        },
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(403, r_card.status, f"Cross-bot TG card callback must return 403 on {card_ep.__name__}")

            self.assertTrue(hub.takeover)
            self.assertEqual(("main", ADMIN_UID_A), hub.takeover_owner)

        asyncio.run(_scenario())


if __name__ == "__main__":
    unittest.main()
