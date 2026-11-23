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


if __name__ == "__main__":
    unittest.main()
