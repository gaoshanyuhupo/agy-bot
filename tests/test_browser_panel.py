#!/usr/bin/env python3
"""Offline unit & integration tests for Live-Browser multi-fingerprint panel & Telegram `/browser`."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import importlib
import json
import os
import sys
import tempfile
import types
import unittest
import urllib.parse
from pathlib import Path
from typing import Any
from unittest import mock

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
LIVE_SCRIPTS = REPO_ROOT / ".agents/skills/live-browser/scripts"
for _p in (str(BRIDGE_DIR), str(LIVE_SCRIPTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import live_browser_server as srv  # noqa: E402


class _FakeHTTPForbidden(Exception):
    status = 403

    def __init__(self, text: str = "Forbidden") -> None:
        super().__init__(text)
        self.text = text


class _FakeJSONResponse:
    def __init__(self, data: dict, status: int = 200) -> None:
        self.data = data
        self.status = status


class _FakeWSMsgType:
    TEXT = "TEXT"
    BINARY = "BINARY"
    CLOSE = "CLOSE"


class _FakeWSMessage:
    def __init__(self, data: str, msg_type: str = _FakeWSMsgType.TEXT) -> None:
        self.data = data
        self.type = msg_type


class _FakeWebSocketResponse:
    def __init__(
        self,
        incoming: list[_FakeWSMessage],
        *,
        step_waits: list[Any] | None = None,
        final_wait: Any = None,
        wait_timeout: float = 5.0,
    ) -> None:
        self._incoming = list(incoming)
        self._step_waits = list(step_waits) if step_waits is not None else []
        self._final_wait = final_wait
        self._wait_timeout = float(wait_timeout)
        self.closed = False
        self.sent_text: list[str] = []
        self.sent_bytes: list[bytes] = []
        self.parsed_frames: list[dict] = []
        self._frame_event = asyncio.Event()

    async def prepare(self, _request) -> None:
        return None

    async def receive(self) -> _FakeWSMessage:
        if self._incoming:
            return self._incoming.pop(0)
        return _FakeWSMessage("", _FakeWSMsgType.CLOSE)

    async def send_str(self, payload: str) -> None:
        self.sent_text.append(payload)
        try:
            self.parsed_frames.append(json.loads(payload))
        except Exception:
            pass
        self._frame_event.set()

    async def send_bytes(self, payload: bytes) -> None:
        self.sent_bytes.append(payload)

    async def close(self) -> None:
        self.closed = True
        self._frame_event.set()

    async def _wait_for_predicate(self, pred: Any) -> None:
        if pred is None:
            return
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._wait_timeout
        while not pred(self.parsed_frames):
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise AssertionError(
                    f"Timed out waiting for WS state/frame predicate; observed frames: {self.parsed_frames}"
                )
            self._frame_event.clear()
            if pred(self.parsed_frames):
                return
            try:
                await asyncio.wait_for(self._frame_event.wait(), timeout=min(0.25, remaining))
            except asyncio.TimeoutError:
                pass

    def __aiter__(self):
        return self

    async def __anext__(self) -> _FakeWSMessage:
        if self._incoming:
            wait_pred = self._step_waits.pop(0) if self._step_waits else None
            if wait_pred is not None:
                await self._wait_for_predicate(wait_pred)
            else:
                await asyncio.sleep(0)
            return self._incoming.pop(0)
        if self._final_wait is not None:
            pred = self._final_wait
            self._final_wait = None
            await self._wait_for_predicate(pred)
        raise StopAsyncIteration


class _FakeWebModule:
    HTTPForbidden = _FakeHTTPForbidden

    @staticmethod
    def json_response(data: dict, status: int = 200) -> _FakeJSONResponse:
        return _FakeJSONResponse(data, status=status)


class _FakePage:
    def __init__(self, url: str = "https://example.com") -> None:
        self.url = url
        self.viewport_size = {"width": 1280, "height": 800}
        self._callbacks: dict[str, list] = {}

    def on(self, event: str, cb) -> None:
        self._callbacks.setdefault(event, []).append(cb)

    async def title(self) -> str:
        return "Example Browser Page"

    async def screenshot(self, **_kwargs) -> bytes:
        return b"FAKEJPEG"

    async def goto(self, url: str, **_kwargs) -> None:
        self.url = url


class _FakeContext:
    def __init__(self, display_num: int = 9) -> None:
        self.pages = [_FakePage()]
        self._callbacks: dict[str, list] = {}
        holder = types.SimpleNamespace(_display=display_num)

        def _close() -> int:
            return holder._display

        self.close = _close

    def on(self, event: str, cb) -> None:
        self._callbacks.setdefault(event, []).append(cb)

    async def route(self, pattern: str, handler) -> None:
        self._callbacks.setdefault("route", []).append((pattern, handler))

    async def new_page(self) -> _FakePage:
        p = _FakePage()
        self.pages.append(p)
        return p


class _FakeAsyncCamoufoxCM:
    recorded_calls: list[dict] = []

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        type(self).recorded_calls.append(kwargs)
        self.ctx = _FakeContext()

    async def __aenter__(self) -> _FakeContext:
        return self.ctx

    async def __aexit__(self, _exc_type, _exc, _tb) -> None:
        return None


def _build_signed_init_data(bot_token: str, user_id: int = 111) -> str:
    import time

    params = {
        "auth_date": str(int(time.time())),
        "query_id": "AAHdF6IQAAAAAN0XohDhrOrc",
        "user": json.dumps({"id": user_id, "first_name": "Tester"}, separators=(",", ":")),
    }
    check_str = "\n".join(f"{k}={params[k]}" for k in sorted(params))
    secret = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
    params["hash"] = hmac.new(secret, check_str.encode("utf-8"), hashlib.sha256).hexdigest()
    return urllib.parse.urlencode(params)


class TestLiveBrowserServerPanelWS(unittest.TestCase):
    """Offline tests for `live_browser_server` state_dict, WS profile switching & HTTP switch route."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.cfg_dir = self.root / "config"
        self.profiles_data = self.root / "profiles-data"
        self.cfg_dir.mkdir(parents=True, exist_ok=True)
        self.profiles_data.mkdir(parents=True, exist_ok=True)

        self._orig_env = os.environ.get("AGY_GOOGLE_SKILL_SCRIPTS")
        self._orig_cfg_dir = srv.CONFIG_DIR
        self._orig_cfg_file = srv.CONFIG_FILE
        self._orig_prof_file = srv.PROFILES_FILE
        self._orig_tok_file = srv.LOCAL_TOKEN_FILE
        self._orig_data_dir = srv.PROFILES_DATA_DIR

        srv.CONFIG_DIR = self.cfg_dir
        srv.CONFIG_FILE = self.cfg_dir / "config.json"
        srv.PROFILES_FILE = self.cfg_dir / "profiles.json"
        srv.LOCAL_TOKEN_FILE = self.cfg_dir / "local.token"
        srv.PROFILES_DATA_DIR = self.profiles_data
        os.environ["AGY_GOOGLE_SKILL_SCRIPTS"] = str(self.root / "no-google-skill")
        _FakeAsyncCamoufoxCM.recorded_calls.clear()

    def tearDown(self) -> None:
        srv.CONFIG_DIR = self._orig_cfg_dir
        srv.CONFIG_FILE = self._orig_cfg_file
        srv.PROFILES_FILE = self._orig_prof_file
        srv.LOCAL_TOKEN_FILE = self._orig_tok_file
        srv.PROFILES_DATA_DIR = self._orig_data_dir
        if self._orig_env is None:
            os.environ.pop("AGY_GOOGLE_SKILL_SCRIPTS", None)
        else:
            os.environ["AGY_GOOGLE_SKILL_SCRIPTS"] = self._orig_env
        self._tmp.cleanup()

    def _install_pinned_profile(self) -> Path:
        skill_dir = self.root / "google-profile-scripts"
        skill_dir.mkdir(parents=True, exist_ok=True)
        pinned_dir = self.profiles_data / "pinned_acct"
        pinned_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.profiles_data / "pinned_acct.lock"
        (skill_dir / "google_browser.py").write_text(
            "\n".join(
                [
                    "import os",
                    "from pathlib import Path",
                    f"PROFILE_DIR = Path({str(pinned_dir)!r})",
                    f"LOCK_PATH = Path({str(lock_path)!r})",
                    'PINNED_FINGERPRINT = {"headless": "virtual", "os": "windows", "humanize": True, "i_know_what_im_doing": True}',
                    "def _direct_env():",
                    "    env = dict(os.environ)",
                    '    for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):',
                    "        env.pop(k, None)",
                    '    env["NO_PROXY"] = "*"',
                    '    env["no_proxy"] = "*"',
                    "    return env",
                ]
            ),
            encoding="utf-8",
        )
        os.environ["AGY_GOOGLE_SKILL_SCRIPTS"] = str(skill_dir)
        return pinned_dir

    def test_state_dict_includes_masked_profiles_and_ai_busy(self) -> None:
        self._install_pinned_profile()
        srv.create_profile(
            "us-work",
            {
                "os": "macos",
                "proxy": "socks5://MOCK_USER:MOCK_PASS@proxy.example.com:1080",
            },
        )
        srv.create_profile(
            "bao-box",
            {
                "os": "linux",
                "persistent": False,
                "proxy_bao_ref": "kv/proxies/eu#url",
            },
        )
        hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "local-tok")
        hub.ai_busy_count = 1
        st = hub.state_dict()
        self.assertTrue(st["ai_busy"])
        self.assertIn("profiles", st)
        raw_dump = json.dumps(st)
        self.assertNotIn("MOCK_USER", raw_dump)
        self.assertNotIn("MOCK_PASS", raw_dump)

        by_name = {p["name"]: p for p in st["profiles"]}
        self.assertIn("pinned_acct", by_name)
        self.assertTrue(by_name["pinned_acct"]["pinned"])
        self.assertFalse(by_name["pinned_acct"]["has_proxy"])
        self.assertEqual("direct", by_name["pinned_acct"]["egress_display"])

        self.assertTrue(by_name["us-work"]["has_proxy"])
        self.assertEqual("socks5://***@" + "proxy.example.com:1080", by_name["us-work"]["egress_display"])
        self.assertIsNone(by_name["us-work"]["bao_ref"])

        self.assertTrue(by_name["bao-box"]["has_proxy"])
        self.assertFalse(by_name["bao-box"]["persistent"])
        self.assertEqual("kv/proxies/eu#url", by_name["bao-box"]["bao_ref"])

    def test_ws_list_switch_stop_and_error_toasts(self) -> None:
        self._install_pinned_profile()
        srv.create_profile(
            "mac-exit",
            {"os": "macos", "proxy": "http://MOCK_U:MOCK_P@proxy.example.com:8080"},
        )
        fake_mod = types.ModuleType("camoufox.async_api")
        fake_mod.AsyncCamoufox = _FakeAsyncCamoufoxCM  # type: ignore[attr-defined]
        fake_pkg = types.ModuleType("camoufox")
        fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

        bot_token = "123456789:EXAMPLE_WS_BOT_TOKEN_PAYLOAD_12345"
        init_data = _build_signed_init_data(bot_token, user_id=111)

        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "local-tok")
            incoming = [
                _FakeWSMessage(json.dumps({"type": "auth", "initData": init_data})),
                _FakeWSMessage(json.dumps({"type": "list_profiles"})),
                _FakeWSMessage(json.dumps({"type": "start_browser", "profile": "mac-exit", "url": "https://example.com", "session_gen": 0})),
                _FakeWSMessage(json.dumps({"type": "switch_profile", "profile": "nonexistent-prof", "session_gen": 1})),
                _FakeWSMessage(json.dumps({"type": "switch_profile", "profile": "default", "url": "https://example.org", "session_gen": 1})),
                _FakeWSMessage(json.dumps({"type": "stop_browser", "session_gen": 3})),
            ]
            ws_inst = _FakeWebSocketResponse(
                incoming,
                step_waits=[
                    # Before list_profiles: wait for initial auth_ok + state
                    lambda frames: any(f.get("type") == "state" for f in frames),
                    # Before start_browser(gen=0): wait for profiles_list
                    lambda frames: any(f.get("type") == "profiles_list" for f in frames),
                    # Before switch_profile(nonexistent, gen=1): wait for state confirming session_gen==1 & running
                    lambda frames: any(
                        f.get("type") == "state" and f.get("running") and f.get("session_gen") == 1
                        for f in frames
                    ),
                    # Before switch_profile(default, gen=1): wait for invalid profile toast
                    lambda frames: any(
                        f.get("type") == "toast"
                        and ("Profile 无效" in str(f.get("message", "")) or "not found" in str(f.get("message", "")))
                        for f in frames
                    ),
                    # Before stop_browser(gen=3): wait for state confirming session_gen==3 & running
                    lambda frames: any(
                        f.get("type") == "state" and f.get("running") and f.get("session_gen") == 3
                        for f in frames
                    ),
                ],
                final_wait=lambda frames: any(
                    f.get("type") == "state" and f.get("engine_mode") == "idle" and int(f.get("session_gen", 0)) >= 4
                    for f in frames
                ),
            )

            class _FakeWebWithWS(_FakeWebModule):
                @staticmethod
                def WebSocketResponse(**_kw):
                    return ws_inst

            req = types.SimpleNamespace(
                remote="127.0.0.1",
                app={"hub": hub},
            )
            with (
                mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}),
                mock.patch.object(srv, "web", _FakeWebWithWS),
                mock.patch.object(srv, "WSMsgType", _FakeWSMsgType),
                mock.patch.object(srv, "load_bot_credentials", return_value=({"main": bot_token}, {}, {111})),
                mock.patch.object(srv, "resolve_camoufox_display", return_value=None),
                mock.patch.object(srv, "read_x11_clipboard_async", new=mock.AsyncMock(return_value="")),
                mock.patch.object(hub.tg, "ensure_card", new=mock.AsyncMock(return_value=None)),
                mock.patch.object(hub.tg, "tick_updates", new=mock.AsyncMock(return_value=None)),
            ):
                await srv.handle_ws(req)  # type: ignore[arg-type]

            frames = [json.loads(s) for s in ws_inst.sent_text]
            types_seen = [f.get("type") for f in frames]
            self.assertIn("auth_ok", types_seen)
            self.assertIn("profiles_list", types_seen)
            prof_msg = next(f for f in frames if f.get("type") == "profiles_list")
            self.assertTrue(any(p["name"] == "mac-exit" for p in prof_msg["profiles"]))
            self.assertNotIn("MOCK_P", json.dumps(prof_msg))

            toast_msgs = [f["message"] for f in frames if f.get("type") == "toast"]
            self.assertTrue(any("Profile 无效" in m or "not found" in m for m in toast_msgs))

            # Verify start_browser used mac-exit, then switch_profile("default") used pinned profile
            self.assertEqual(2, len(_FakeAsyncCamoufoxCM.recorded_calls))
            self.assertEqual("macos", _FakeAsyncCamoufoxCM.recorded_calls[0]["os"])
            self.assertEqual("windows", _FakeAsyncCamoufoxCM.recorded_calls[1]["os"])
            self.assertEqual({"network.proxy.type": 0}, _FakeAsyncCamoufoxCM.recorded_calls[1]["firefox_user_prefs"])
            self.assertEqual("idle", hub.engine_mode)

        asyncio.run(_scenario())

    def test_ws_switch_blocked_during_takeover_or_ai_busy(self) -> None:
        self._install_pinned_profile()
        srv.create_profile("alt-prof", {"os": "linux"})
        bot_token = "123456789:EXAMPLE_WS_BOT_TOKEN_PAYLOAD_12345"
        init_data = _build_signed_init_data(bot_token, user_id=111)

        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "local-tok")
            hub.engine_mode = "async_hosted"
            hub.active_profile = "pinned_acct"
            hub.session_owner = ("main", 111)
            hub.takeover = True

            incoming = [
                _FakeWSMessage(json.dumps({"type": "auth", "initData": init_data})),
                _FakeWSMessage(json.dumps({"type": "switch_profile", "profile": "alt-prof", "session_gen": 0})),
            ]
            ws_inst = _FakeWebSocketResponse(
                incoming,
                step_waits=[lambda frames: any(f.get("type") == "state" for f in frames)],
                final_wait=lambda frames: any(
                    f.get("type") == "toast" and "人工接管" in str(f.get("message", "")) for f in frames
                ),
            )

            class _FakeWebWithWS(_FakeWebModule):
                @staticmethod
                def WebSocketResponse(**_kw):
                    return ws_inst

            req = types.SimpleNamespace(remote="127.0.0.1", app={"hub": hub})
            with (
                mock.patch.object(srv, "web", _FakeWebWithWS),
                mock.patch.object(srv, "WSMsgType", _FakeWSMsgType),
                mock.patch.object(srv, "load_bot_credentials", return_value=({"main": bot_token}, {}, {111})),
            ):
                await srv.handle_ws(req)  # type: ignore[arg-type]

            frames = [json.loads(s) for s in ws_inst.sent_text]
            toasts = [f["message"] for f in frames if f.get("type") == "toast"]
            self.assertTrue(any("人工接管" in m for m in toasts))

        asyncio.run(_scenario())

    def test_internal_profiles_switch_auth_and_switching(self) -> None:
        self._install_pinned_profile()
        srv.create_profile("lin-exit", {"os": "linux"})
        fake_mod = types.ModuleType("camoufox.async_api")
        fake_mod.AsyncCamoufox = _FakeAsyncCamoufoxCM  # type: ignore[attr-defined]
        fake_pkg = types.ModuleType("camoufox")
        fake_pkg.async_api = fake_mod  # type: ignore[attr-defined]

        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "secret-local-tok")

            class _FakeReq:
                def __init__(self, body: dict, token: str = "secret-local-tok", remote: str = "127.0.0.1") -> None:
                    self._body = body
                    self.headers = {"X-Live-Token": token}
                    self.remote = remote
                    self.app = {"hub": hub}

                async def json(self) -> dict:
                    return self._body

            with (
                mock.patch.object(srv, "web", _FakeWebModule),
                mock.patch.dict(sys.modules, {"camoufox": fake_pkg, "camoufox.async_api": fake_mod}),
            ):
                with self.assertRaises(_FakeHTTPForbidden):
                    await srv.internal_profiles_switch(_FakeReq({"profile": "lin-exit"}, token="bad-tok"))  # type: ignore[arg-type]

                resp_missing = await srv.internal_profiles_switch(_FakeReq({}))  # type: ignore[arg-type]
                self.assertEqual(400, resp_missing.status)

                resp_404 = await srv.internal_profiles_switch(_FakeReq({"profile": "missing"}))  # type: ignore[arg-type]
                self.assertEqual(404, resp_404.status)

                resp_ok = await srv.internal_profiles_switch(
                    _FakeReq({"profile": "lin-exit", "notify": False})  # type: ignore[arg-type]
                )
                self.assertEqual(200, resp_ok.status)
                self.assertTrue(resp_ok.data["ok"])
                self.assertEqual("lin-exit", resp_ok.data["profile"])
                self.assertIn("profiles", resp_ok.data)

                hub.takeover = True
                resp_conflict = await srv.internal_profiles_switch(
                    _FakeReq({"profile": "default", "notify": False})  # type: ignore[arg-type]
                )
                self.assertEqual(409, resp_conflict.status)
                hub.takeover = False
                await hub.stop_hosted(notify_finished=False)

        asyncio.run(_scenario())

    def test_internal_stop_concurrency_guards_and_empty_body(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "secret-local-tok")

            class _FakeStopReq:
                def __init__(
                    self,
                    *,
                    raw_body: bytes = b"",
                    query: dict[str, str] | None = None,
                    token: str = "secret-local-tok",
                ) -> None:
                    self._raw = raw_body
                    self.query = query or {}
                    self.headers = {"X-Live-Token": token}
                    self.remote = "127.0.0.1"
                    self.app = {"hub": hub}

                async def read(self) -> bytes:
                    return self._raw

            with (
                mock.patch.object(srv, "web", _FakeWebModule),
                mock.patch.object(hub, "stop_hosted", new=mock.AsyncMock(return_value=None)) as stop_mock,
            ):
                # 1. Empty body when idle -> 200 & calls stop_hosted(notify_finished=True)
                resp_empty = await srv.internal_stop(_FakeStopReq(raw_body=b""))  # type: ignore[arg-type]
                self.assertEqual(200, resp_empty.status)
                self.assertTrue(resp_empty.data["ok"])
                stop_mock.assert_awaited_once_with(notify_finished=True)

                # 2. sync_external -> 409 Conflict (even with force=true)
                stop_mock.reset_mock()
                hub.engine_mode = "sync_external"
                resp_sync = await srv.internal_stop(
                    _FakeStopReq(raw_body=json.dumps({"force": True}).encode("utf-8"))  # type: ignore[arg-type]
                )
                self.assertEqual(409, resp_sync.status)
                stop_mock.assert_not_awaited()

                # 3. ai_busy_count > 0 without force -> 409 Conflict
                hub.engine_mode = "async_hosted"
                hub.ai_busy_count = 2
                resp_busy = await srv.internal_stop(_FakeStopReq(raw_body=b""))  # type: ignore[arg-type]
                self.assertEqual(409, resp_busy.status)
                stop_mock.assert_not_awaited()

                # 4. ai_busy_count > 0 with body force=true -> 200
                resp_force_body = await srv.internal_stop(
                    _FakeStopReq(raw_body=json.dumps({"force": True}).encode("utf-8"))  # type: ignore[arg-type]
                )
                self.assertEqual(200, resp_force_body.status)
                stop_mock.assert_awaited_once_with(notify_finished=True)

                # 5. ai_busy_count > 0 with query ?force=true -> 200
                stop_mock.reset_mock()
                resp_force_query = await srv.internal_stop(
                    _FakeStopReq(raw_body=b"", query={"force": "true"})  # type: ignore[arg-type]
                )
                self.assertEqual(200, resp_force_query.status)
                stop_mock.assert_awaited_once_with(notify_finished=True)

                # 6. ai_busy_count > 0 with ?force=false / ?force=0 -> 409 Conflict
                for q_val in ("false", "0"):
                    stop_mock.reset_mock()
                    resp_no_force = await srv.internal_stop(
                        _FakeStopReq(raw_body=b"", query={"force": q_val})  # type: ignore[arg-type]
                    )
                    self.assertEqual(409, resp_no_force.status)
                    stop_mock.assert_not_awaited()

                # 7. Non-dict JSON body `[]` -> 400 Bad Request
                stop_mock.reset_mock()
                resp_list_body = await srv.internal_stop(
                    _FakeStopReq(raw_body=b"[]")  # type: ignore[arg-type]
                )
                self.assertEqual(400, resp_list_body.status)
                stop_mock.assert_not_awaited()

                # 8. Unauthorized call (bad token) -> 403 Forbidden
                stop_mock.reset_mock()
                with self.assertRaises(_FakeHTTPForbidden) as ctx_unauth:
                    await srv.internal_stop(
                        _FakeStopReq(raw_body=b"", token="wrong-tok")  # type: ignore[arg-type]
                    )
                self.assertEqual(403, ctx_unauth.exception.status)
                stop_mock.assert_not_awaited()

        asyncio.run(_scenario())


def _load_isolated_bridge(tmp: str, extra_env: dict[str, str] | None = None):
    env_patch = {
        "AGY_BOT_BUS_DIR": os.path.join(tmp, "bus"),
        "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
        "AGY_TG_WORKDIR": os.path.join(tmp, "workdir"),
        "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
        "AGY_TG_ALLOWED_CHATS": "-1001234567890,111",
        "AGY_TG_ADMIN_USERS": "111",
        "AGY_TG_READONLY_USERS": "222",
        "AGY_TG_ALLOW_GROUP_READONLY": "0",
        "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_BROWSER_PANEL_TEST_TOKEN_1",
        "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
        "AGY_LIVE_BROWSER_URL": "http://127.0.0.1:18795",
        "AGY_LIVE_BROWSER_CONFIG_DIR": os.path.join(tmp, "live-cfg"),
    }
    if extra_env:
        env_patch.update(extra_env)
    with mock.patch.dict(os.environ, env_patch, clear=False):
        import access_control  # noqa: E402
        import bot_bus  # noqa: E402
        import bridge  # noqa: E402

        importlib.reload(access_control)
        importlib.reload(bot_bus)
        importlib.reload(bridge)
        os.makedirs(bridge.WORKDIR, exist_ok=True)
        os.makedirs(bridge.UPLOADDIR, exist_ok=True)
        return bridge, access_control


class _FakeResp:
    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class TestBridgeBrowserPanelAndRbac(unittest.TestCase):
    """Offline tests for Telegram `/browser` panel, `web_app` private/group guard, callbacks & RBAC."""

    def test_browser_panel_offline_graceful_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _ac = _load_isolated_bridge(tmp)
            cfg_dir = Path(tmp) / "live-cfg"
            sent: list[tuple[int, str, dict]] = []
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir),
                        "AGY_LIVE_BROWSER_URL": "http://127.0.0.1:19999",
                    },
                    clear=False,
                ),
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append((cid, txt, kw)) or 1),
            ):
                # Missing local.token
                bridge.handle_message({
                    "chat": {"id": 111, "type": "private"},
                    "from": {"id": 111},
                    "message_id": 1,
                    "text": "/browser",
                })
                self.assertEqual(1, len(sent))
                self.assertIn("离线", sent[0][1])

                # Token exists, but HTTP connection fails
                cfg_dir.mkdir(parents=True, exist_ok=True)
                (cfg_dir / "local.token").write_text("tok123", encoding="utf-8")
                sent.clear()
                with mock.patch.object(bridge.requests, "get", side_effect=requests.exceptions.ConnectionError("refused")):
                    bridge.handle_message({
                        "chat": {"id": 111, "type": "private"},
                        "from": {"id": 111},
                        "message_id": 2,
                        "text": "/browser",
                    })
                self.assertEqual(1, len(sent))
                self.assertIn("未运行", sent[0][1])

    def test_private_includes_webapp_while_group_excludes_webapp_and_callbacks_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "live-cfg"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            (cfg_dir / "local.token").write_text("tok-local", encoding="utf-8")
            bridge, _ac = _load_isolated_bridge(tmp, extra_env={"AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir)})
            bridge.BOT_META.update({"bot_id": 100, "handle": "example_bot", "resolved": True})

            status_payload = {
                "ok": True,
                "running": True,
                "engine_mode": "async_hosted",
                "profile": "pinned_acct",
                "pinned": True,
                "os": "windows",
                "egress": "direct",
                "takeover": False,
                "ai_busy": False,
                "url": "https://example.com",
                "title": "Example",
                "public_url": "https://live.example.com",
            }
            profiles_payload = {
                "ok": True,
                "active_profile": "pinned_acct",
                "profiles": [
                    {"name": "pinned_acct", "pinned": True, "os": "windows", "persistent": True, "egress_display": "direct", "active": True},
                    {"name": "us-work", "pinned": False, "os": "macos", "persistent": True, "egress_display": "socks5://***@" + "proxy.example.com:1080", "active": False},
                ],
            }

            def _fake_get(url: str, **_kw):
                if url.endswith("/internal/status"):
                    return _FakeResp(200, status_payload)
                if url.endswith("/internal/profiles"):
                    return _FakeResp(200, profiles_payload)
                return _FakeResp(404, {"ok": False})

            sent: list[tuple[int, str, dict]] = []
            with (
                mock.patch.dict(os.environ, {"AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir)}, clear=False),
                mock.patch.object(bridge.requests, "get", side_effect=_fake_get),
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append((cid, txt, kw)) or 1),
            ):
                # Private chat (chat_id > 0) MUST include web_app button
                bridge.handle_message({
                    "chat": {"id": 111, "type": "private"},
                    "from": {"id": 111},
                    "message_id": 10,
                    "text": "/browser",
                })
                priv_kb = sent[0][2]["reply_markup"]["inline_keyboard"]
                self.assertTrue(any("web_app" in btn for row in priv_kb for btn in row))
                self.assertTrue(any(btn.get("callback_data") == "browser:switch:us-work" for row in priv_kb for btn in row))
                self.assertTrue(any(btn.get("callback_data") == "browser:stop" for row in priv_kb for btn in row))

                # Group chat (chat_id < 0) MUST NOT include any web_app button,
                # and SHOULD include deep-link URL button to private chat `/start browser`
                sent.clear()
                bridge.handle_message({
                    "chat": {"id": -1001234567890, "type": "supergroup"},
                    "from": {"id": 111},
                    "message_id": 11,
                    "text": "/profile",
                })
                grp_kb = sent[0][2]["reply_markup"]["inline_keyboard"]
                self.assertFalse(any("web_app" in btn for row in grp_kb for btn in row))
                self.assertTrue(
                    any(btn.get("url") == "https://t.me/example_bot?start=browser" for row in grp_kb for btn in row)
                )
                self.assertTrue(any(btn.get("callback_data") == "browser:refresh" for row in grp_kb for btn in row))
                self.assertIn("群聊", sent[0][1])

                # Private chat includes menu_set & menu_reset buttons
                self.assertTrue(any(btn.get("callback_data") == "browser:menu_set" for row in priv_kb for btn in row))
                self.assertTrue(any(btn.get("callback_data") == "browser:menu_reset" for row in priv_kb for btn in row))

                # Group chat with AGY_LIVE_BROWSER_DIRECT_APP_URL prefers direct link URL
                sent.clear()
                with mock.patch.dict(
                    os.environ,
                    {"AGY_LIVE_BROWSER_DIRECT_APP_URL": "https://t.me/example_bot/liveapp"},
                    clear=False,
                ):
                    bridge.handle_message({
                        "chat": {"id": -1001234567890, "type": "supergroup"},
                        "from": {"id": 111},
                        "message_id": 13,
                        "text": "/browser",
                    })
                direct_kb = sent[0][2]["reply_markup"]["inline_keyboard"]
                self.assertFalse(any("web_app" in btn for row in direct_kb for btn in row))
                self.assertTrue(
                    any(btn.get("url") == "https://t.me/example_bot/liveapp" for row in direct_kb for btn in row)
                )

                # Private `/start browser` deep link opens Live-Browser panel directly
                sent.clear()
                bridge.handle_message({
                    "chat": {"id": 111, "type": "private"},
                    "from": {"id": 111},
                    "message_id": 14,
                    "text": "/start browser",
                })
                self.assertEqual(1, len(sent))
                self.assertIn("Live-Browser", sent[0][1])
                start_kb = sent[0][2]["reply_markup"]["inline_keyboard"]
                self.assertTrue(any("web_app" in btn for row in start_kb for btn in row))

            # Test switch command and callback
            post_calls: list[tuple[str, dict]] = []
            tg_calls: list[tuple[str, dict]] = []

            def _fake_post(url: str, json=None, **_kw):
                post_calls.append((url, dict(json or {})))
                return _FakeResp(200, {"ok": True, **status_payload, "profile": "us-work"})

            with (
                mock.patch.dict(os.environ, {"AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir)}, clear=False),
                mock.patch.object(bridge.requests, "get", side_effect=_fake_get),
                mock.patch.object(bridge.requests, "post", side_effect=_fake_post),
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append((cid, txt, kw)) or 1),
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: tg_calls.append((m, kw)) or None),
            ):
                bridge.handle_message({
                    "chat": {"id": 111, "type": "private"},
                    "from": {"id": 111},
                    "message_id": 12,
                    "text": "/browser switch us-work",
                })
                self.assertTrue(any(u.endswith("/internal/profiles/switch") and b.get("profile") == "us-work" for u, b in post_calls))

                post_calls.clear()
                tg_calls.clear()
                bridge.handle_callback({
                    "id": "cb-sw",
                    "from": {"id": 111},
                    "message": {"chat": {"id": 111}, "message_id": 88},
                    "data": "browser:switch:us-work",
                })
                self.assertTrue(any(u.endswith("/internal/profiles/switch") for u, _ in post_calls))
                self.assertTrue(any(m == "editMessageText" for m, _ in tg_calls))

                # Live Card photo callbacks MUST NOT call editMessageText
                for cb_data, expected_ep in (
                    ("browser:takeover_on", "/internal/takeover"),
                    ("browser:takeover_off", "/internal/takeover"),
                    ("browser:card_refresh", "/internal/config"),
                    ("browser:card_stop", "/internal/stop"),
                ):
                    post_calls.clear()
                    tg_calls.clear()
                    bridge.handle_callback({
                        "id": f"cb-{cb_data}",
                        "from": {"id": 111},
                        "message": {"chat": {"id": 111}, "message_id": 99},
                        "data": cb_data,
                    })
                    self.assertTrue(any(u.endswith(expected_ep) for u, _ in post_calls), f"Missing POST {expected_ep} for {cb_data}")
                    self.assertFalse(any(m == "editMessageText" for m, _ in tg_calls), f"Should not editMessageText on photo card for {cb_data}")
                    if cb_data == "browser:card_refresh":
                        self.assertTrue(
                            any(b.get("refresh_card") is True and b.get("chat_id") == 111 and b.get("message_id") == 99 for _, b in post_calls),
                            f"Expected scoped card_refresh payload, got {post_calls}",
                        )

                # Group chat card_refresh must be rejected even for admin (card callbacks are DM-only)
                post_calls.clear()
                tg_calls.clear()
                bridge.handle_callback({
                    "id": "cb-grp-card",
                    "from": {"id": 111},
                    "message": {"chat": {"id": -1001234567890}, "message_id": 99},
                    "data": "browser:card_refresh",
                })
                self.assertEqual([], post_calls)
                self.assertTrue(any("私聊" in kw.get("text", "") for _, kw in tg_calls))

                # Private menu_set & menu_reset call setChatMenuButton
                tg_calls.clear()
                bridge.handle_callback({
                    "id": "cb-mset",
                    "from": {"id": 111},
                    "message": {"chat": {"id": 111}, "message_id": 100},
                    "data": "browser:menu_set",
                })
                self.assertTrue(
                    any(m == "setChatMenuButton" and kw.get("menu_button", {}).get("type") == "web_app" for m, kw in tg_calls)
                )

                tg_calls.clear()
                bridge.handle_callback({
                    "id": "cb-mrst",
                    "from": {"id": 111},
                    "message": {"chat": {"id": 111}, "message_id": 100},
                    "data": "browser:menu_reset",
                })
                self.assertTrue(
                    any(m == "setChatMenuButton" and kw.get("menu_button", {}).get("type") == "default" for m, kw in tg_calls)
                )

    def test_readonly_rbac_allows_browser_view_and_blocks_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "live-cfg"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            (cfg_dir / "local.token").write_text("tok-local", encoding="utf-8")
            bridge, _ac = _load_isolated_bridge(tmp, extra_env={"AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir)})
            bridge.BOT_META.update({"bot_id": 100, "handle": "example_bot", "resolved": True})

            sent_texts: list[str] = []
            tg_calls: list[tuple[str, dict]] = []

            def _fake_get(url: str, **_kw):
                if url.endswith("/internal/status"):
                    return _FakeResp(200, {"ok": True, "running": False, "engine_mode": "idle", "public_url": ""})
                return _FakeResp(200, {"ok": True, "profiles": [{"name": "default", "pinned": False, "os": "windows", "persistent": True, "egress_display": "direct"}]})

            with (
                mock.patch.dict(os.environ, {"AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir)}, clear=False),
                mock.patch.object(bridge.requests, "get", side_effect=_fake_get),
                mock.patch.object(bridge.requests, "post") as post_mock,
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent_texts.append(txt) or 1),
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: tg_calls.append((m, kw)) or None),
            ):
                # Allowed: `/browser` (no args) for readonly user 222 in allowed group
                bridge.handle_message({
                    "chat": {"id": -1001234567890, "type": "supergroup"},
                    "from": {"id": 222},
                    "message_id": 20,
                    "text": "/browser",
                })
                self.assertTrue(any("Live-Browser" in t for t in sent_texts))

                # Blocked: `/browser switch ...`, `/browser start`, `/browser stop`
                for bad in ("/browser switch us-work", "/browser start default", "/browser stop"):
                    sent_texts.clear()
                    bridge.handle_message({
                        "chat": {"id": -1001234567890, "type": "supergroup"},
                        "from": {"id": 222},
                        "message_id": 21,
                        "text": bad,
                    })
                    self.assertTrue(any("权限不足" in t for t in sent_texts), f"Expected RBAC block for {bad}")

                # Allowed callback: `browser:refresh`
                tg_calls.clear()
                bridge.handle_callback({
                    "id": "cb-ro-ok",
                    "from": {"id": 222},
                    "message": {"chat": {"id": -1001234567890}, "message_id": 30},
                    "data": "browser:refresh",
                })
                self.assertTrue(any(m == "editMessageText" for m, _ in tg_calls))

                # Blocked callbacks: mutating panel & card & menu callbacks
                for bad_cb in (
                    "browser:switch:us-work",
                    "browser:start:default",
                    "browser:stop",
                    "browser:takeover_on",
                    "browser:takeover_off",
                    "browser:card_refresh",
                    "browser:card_stop",
                    "browser:menu_set",
                    "browser:menu_reset",
                ):
                    tg_calls.clear()
                    bridge.handle_callback({
                        "id": "cb-ro-no",
                        "from": {"id": 222},
                        "message": {"chat": {"id": -1001234567890}, "message_id": 31},
                        "data": bad_cb,
                    })
                    self.assertTrue(
                        any("权限不足" in kw.get("text", "") for _, kw in tg_calls),
                        f"Expected RBAC callback denial for {bad_cb}",
                    )
                post_mock.assert_not_called()

    def test_p0_02_and_p2_06_bridge_passes_bot_uid_and_card_binding_metadata(self) -> None:
        """All Telegram /browser commands & card callbacks must explicitly propagate bot, positive user_id, chat_id, message_id."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "live-cfg"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            (cfg_dir / "local.token").write_text("tok-local", encoding="utf-8")
            bridge, _ac = _load_isolated_bridge(tmp, extra_env={"AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir)})
            bridge.BOT_META.update({"bot_id": 100, "handle": "example_bot", "resolved": True})

            post_calls: list[tuple[str, dict]] = []

            def _fake_post(url: str, json=None, **_kw):
                post_calls.append((url, dict(json or {})))
                return _FakeResp(200, {"ok": True})

            def _fake_get(url: str, **_kw):
                if url.endswith("/internal/status"):
                    return _FakeResp(200, {"ok": True, "running": True, "engine_mode": "async_hosted", "public_url": ""})
                return _FakeResp(200, {"ok": True, "profiles": []})

            with (
                mock.patch.dict(os.environ, {"AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir)}, clear=False),
                mock.patch.object(bridge.requests, "get", side_effect=_fake_get),
                mock.patch.object(bridge.requests, "post", side_effect=_fake_post),
                mock.patch.object(bridge, "send", return_value=1),
                mock.patch.object(bridge, "tg", return_value=None),
            ):
                # Private DM `/browser start`, `/browser switch`, `/browser stop` pass bot & user_id=111
                for cmd_txt in ("/browser start default", "/browser switch us-work", "/browser stop"):
                    bridge.cmd_browser(111, cmd_txt.split(" ", 1)[1], from_user={"id": 111})
                # Group `/browser start` passes positive triggering user_id=111 (never negative chat_id!)
                bridge.cmd_browser(-1001234567890, "start default", from_user={"id": 111})
                # All 4 private live-card callbacks pass bot, user_id, chat_id, message_id
                for cb_data in (
                    "browser:takeover_on",
                    "browser:takeover_off",
                    "browser:card_refresh",
                    "browser:card_stop",
                ):
                    bridge._handle_browser_callback(
                        "cb-1", 111, None, 909, cb_data, from_user={"id": 111}
                    )

            self.assertEqual(8, len(post_calls))
            for url, payload in post_calls[:4]:
                self.assertEqual("100", payload.get("bot"), f"Missing bot hint on {url}")
                self.assertEqual(111, payload.get("user_id"), f"Missing positive user_id on {url}")
            for url, payload in post_calls[4:]:
                self.assertEqual("100", payload.get("bot"), f"Missing bot hint on card callback {url}")
                self.assertEqual(111, payload.get("chat_id"), f"Missing chat_id on card callback {url}")
                self.assertEqual(909, payload.get("message_id"), f"Missing message_id on card callback {url}")
                self.assertEqual("tg_card", payload.get("source"), f"Missing source='tg_card' on {url}")
                self.assertTrue(payload.get("from_card"), f"Missing from_card=True on {url}")

            # Fail-closed: missing bot identity MUST NOT fall back to "main", and missing msg_id on card callback MUST be rejected!
            post_calls.clear()
            bridge._env_file = ""
            bridge.BOT_META.clear()
            with (
                mock.patch.dict(os.environ, {"AGY_TG_BOT_TOKEN": ""}, clear=False),
                mock.patch.object(bridge.requests, "post", side_effect=_fake_post),
                mock.patch.object(bridge, "send", return_value=1) as send_mock,
                mock.patch.object(bridge, "tg", return_value=None) as tg_mock,
            ):
                self.assertIsNone(bridge._live_browser_bot_hint())
                bridge.cmd_browser(111, "start default", from_user={"id": 111})
                bridge._handle_browser_callback("cb-nobot", 111, None, 909, "browser:takeover_on", from_user={"id": 111})
                bridge.BOT_META["bot_id"] = 100
                bridge._handle_browser_callback("cb-nomid", 111, None, 0, "browser:card_refresh", from_user={"id": 111})
                bridge._handle_browser_callback("cb-nonemid", 111, None, None, "browser:card_stop", from_user={"id": 111})
                self.assertEqual([], post_calls)
                self.assertTrue(send_mock.called)
                self.assertGreaterEqual(tg_mock.call_count, 3)

    def test_round5_tg_browser_status_passes_source_and_renders_redacted_restricted_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "live-cfg"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            (cfg_dir / "local.token").write_text("sec-tok", encoding="utf-8")
            bridge, _ac = _load_isolated_bridge(tmp, extra_env={"AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir)})
            bridge._env_file = "/tmp/.env"
            bridge.BOT_META["bot_id"] = 100

            get_calls: list[tuple[str, dict | None]] = []
            post_calls: list[tuple[str, dict]] = []

            class _FakeResp:
                def __init__(self, status_code: int, payload: dict) -> None:
                    self.status_code = status_code
                    self._payload = payload

                def json(self) -> dict:
                    return self._payload

            restricted_status = {
                "ok": True,
                "running": False,
                "session_restricted": True,
                "engine_mode": "idle",
                "profile": None,
                "url": "",
                "title": "",
                "public_url": "https://live.example.com",
                "profiles": [
                    {"name": "default", "pinned": False, "os": "windows", "egress_display": "direct", "active": False}
                ],
            }

            def _fake_get(url: str, **kw):
                get_calls.append((url, kw.get("params")))
                if url.endswith("/internal/status"):
                    return _FakeResp(200, restricted_status)
                if url.endswith("/internal/profiles"):
                    return _FakeResp(200, {"ok": True, "active_profile": None, "profiles": restricted_status["profiles"]})
                return _FakeResp(404, {"ok": False})

            def _fake_post(url: str, json=None, **_kw):
                post_calls.append((url, dict(json or {})))
                return _FakeResp(200, {"ok": True})

            with (
                mock.patch.dict(os.environ, {"AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir)}, clear=False),
                mock.patch.object(bridge.requests, "get", side_effect=_fake_get),
                mock.patch.object(bridge.requests, "post", side_effect=_fake_post),
                mock.patch.object(bridge, "send", return_value=1),
            ):
                text, kb = bridge.build_browser_panel(111, from_user={"id": 111})
                # Verify /internal/status & /internal/profiles received source=tg_cmd, bot, user_id
                self.assertEqual(2, len(get_calls))
                for _url, params in get_calls:
                    self.assertIsInstance(params, dict)
                    assert params is not None
                    self.assertEqual("tg_cmd", params.get("source"))
                    self.assertEqual("main", params.get("bot"))
                    self.assertEqual("111", params.get("user_id"))
                # Verify redacted panel copy and NO start/switch/stop control buttons when restricted!
                self.assertIn("已占用", text)
                self.assertIn("脱敏隔离", text)
                cb_datas = [
                    btn.get("callback_data", "")
                    for row in kb.get("inline_keyboard", [])
                    for btn in row
                    if isinstance(btn, dict)
                ]
                self.assertFalse(any(cb.startswith(("browser:start:", "browser:switch:")) or cb == "browser:stop" for cb in cb_datas))
                self.assertIn("browser:refresh", cb_datas)

                # Verify /browser start, switch, stop all include source='tg_cmd'
                bridge.cmd_browser(111, "start default https://example.com", from_user={"id": 111})
                bridge.cmd_browser(111, "switch default", from_user={"id": 111})
                bridge.cmd_browser(111, "stop", from_user={"id": 111})
                self.assertEqual(3, len(post_calls))
                for url, payload in post_calls:
                    self.assertEqual("tg_cmd", payload.get("source"), f"Missing source='tg_cmd' on {url}")
                    self.assertEqual("main", payload.get("bot"))
                    self.assertEqual(111, payload.get("user_id"))

    def test_round6_group_browser_panel_redacted_for_session_owner(self) -> None:
        """Round 6 §1: Group `/browser` MUST redact title/url/profile/egress even when invoked by the session owner."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "live-cfg"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            (cfg_dir / "local.token").write_text("r6-group-tok\n", encoding="utf-8")
            bridge, _ac = _load_isolated_bridge(tmp, extra_env={"AGY_TG_BOT_USERNAME": "example_bot"})
            bridge.BOT_META["handle"] = "example_bot"
            bridge.BOT_META["bot_key"] = "main"

            class _FakeResp:
                def __init__(self, status_code: int, payload: dict) -> None:
                    self.status_code = status_code
                    self._payload = payload

                def json(self) -> dict:
                    return self._payload

            owner_full_status = {
                "ok": True,
                "running": True,
                "engine_mode": "async_hosted",
                "profile": "secret-owner-profile",
                "pinned": True,
                "os": "windows",
                "egress": "socks5://***@" + "proxy.example.com:1080",
                "takeover": True,
                "ai_busy": False,
                "url": "https://private-banking.example/secret-account",
                "title": "CONFIDENTIAL OWNER DASHBOARD",
                "public_url": "https://live.example.com",
            }
            get_calls: list[tuple[str, dict | None]] = []

            def _fake_get(url: str, **kw):
                get_calls.append((url, kw.get("params")))
                if url.endswith("/internal/status"):
                    return _FakeResp(200, owner_full_status)
                if url.endswith("/internal/profiles"):
                    return _FakeResp(
                        200,
                        {
                            "ok": True,
                            "active_profile": "secret-owner-profile",
                            "profiles": [
                                {
                                    "name": "secret-owner-profile",
                                    "pinned": True,
                                    "os": "windows",
                                    "persistent": True,
                                    "egress_display": "socks5://***@" + "proxy.example.com:1080",
                                    "active": True,
                                }
                            ],
                        },
                    )
                return _FakeResp(404, {"ok": False})

            sent: list[tuple[int, str, dict]] = []
            with (
                mock.patch.dict(os.environ, {"AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir)}, clear=False),
                mock.patch.object(bridge.requests, "get", side_effect=_fake_get),
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append((cid, txt, kw)) or 1),
            ):
                # 1. Session owner (uid=111) invokes `/browser` in a group chat -> MUST be fully redacted!
                bridge.handle_message(
                    {
                        "chat": {"id": -1001234567890, "type": "supergroup"},
                        "from": {"id": 111},
                        "message_id": 501,
                        "text": "/browser",
                    }
                )
                self.assertEqual(1, len(sent))
                grp_cid, grp_text, grp_kw = sent[0]
                self.assertEqual(-1001234567890, grp_cid)
                for secret in (
                    "CONFIDENTIAL OWNER DASHBOARD",
                    "private-banking.example",
                    "secret-account",
                    "secret-owner-profile",
                    "proxy.example.com",
                    "socks5://",
                ):
                    self.assertNotIn(secret, grp_text, f"Group /browser body leaked {secret}!")
                self.assertIn("已占用", grp_text)
                grp_kb = grp_kw["reply_markup"]["inline_keyboard"]
                self.assertFalse(any("web_app" in btn for row in grp_kb for btn in row))
                self.assertTrue(
                    any(btn.get("url") == "https://t.me/example_bot?start=browser" for row in grp_kb for btn in row)
                )
                self.assertTrue(any(btn.get("callback_data") == "browser:refresh" for row in grp_kb for btn in row))
                # Verify query params conveyed group delivery scope to /internal/status
                st_params = next(p for u, p in get_calls if u.endswith("/internal/status"))
                assert st_params is not None
                self.assertEqual("group", st_params.get("chat_scope"))
                self.assertEqual("-1001234567890", st_params.get("chat_id"))

                # 2. Same owner in private DM (chat_id=111) still receives full details!
                sent.clear()
                bridge.handle_message(
                    {
                        "chat": {"id": 111, "type": "private"},
                        "from": {"id": 111},
                        "message_id": 502,
                        "text": "/browser",
                    }
                )
                self.assertEqual(1, len(sent))
                dm_text = sent[0][1]
                self.assertIn("CONFIDENTIAL OWNER DASHBOARD", dm_text)
                self.assertIn("https://private-banking.example/secret-account", dm_text)
                self.assertIn("secret-owner-profile", dm_text)
                self.assertIn("proxy.example.com", dm_text)

            # 3. Server-side /internal/status & _resolve_internal_tg_reader also redact group scope even for session owner!
            async def _server_check() -> None:
                bdir = Path(tmp) / "bridge-srv"
                bdir.mkdir(parents=True, exist_ok=True)
                (bdir / ".env").write_text(
                    "AGY_TG_BOT_TOKEN=123456789:EXAMPLE_GROUP_SCOPE_TOKEN_1\nAGY_TG_ALLOWED_CHATS=111,-1001234567890\nAGY_TG_ADMIN_USERS=111\n",
                    encoding="utf-8",
                )
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "r6-srv-tok")
                hub.engine_mode = "async_hosted"
                hub.session_owner = ("main", 111)
                hub.active_profile = "secret-owner-profile"
                hub.active_egress = "socks5://***@" + "proxy.example.com:1080"
                hub.url = "https://private-banking.example/secret-account"
                hub.title = "CONFIDENTIAL OWNER DASHBOARD"

                class _FakeReq:
                    def __init__(self, query: dict[str, str]) -> None:
                        self.query = query
                        self.headers = {"X-Live-Token": "r6-srv-tok"}
                        self.remote = "127.0.0.1"
                        self.app = {"hub": hub}

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "web", _FakeWebModule),
                ):
                    r_grp = await srv.internal_status(
                        _FakeReq(
                            {
                                "source": "tg_cmd",
                                "bot": "main",
                                "user_id": "111",
                                "chat_id": "-1001234567890",
                                "chat_scope": "group",
                            }
                        )  # type: ignore[arg-type]
                    )
                    self.assertTrue(r_grp.data.get("session_restricted"))
                    self.assertEqual("", r_grp.data.get("url"))
                    self.assertEqual("", r_grp.data.get("title"))
                    self.assertIsNone(r_grp.data.get("profile"))

                    r_dm = await srv.internal_status(
                        _FakeReq(
                            {
                                "source": "tg_cmd",
                                "bot": "main",
                                "user_id": "111",
                                "chat_id": "111",
                                "chat_scope": "private",
                            }
                        )  # type: ignore[arg-type]
                    )
                    self.assertFalse(r_dm.data.get("session_restricted"))
                    self.assertEqual("CONFIDENTIAL OWNER DASHBOARD", r_dm.data.get("title"))
                    self.assertEqual("https://private-banking.example/secret-account", r_dm.data.get("url"))

            asyncio.run(_server_check())

    def test_round7_group_browser_errors_and_restricted_profile_catalog_redacted(self) -> None:
        """Round 7 §2: Group `/browser` errors NEVER echo active profile/backend error; restricted/group status & profiles return profiles=[]."""
        with tempfile.TemporaryDirectory() as tmp:
            cfg_dir = Path(tmp) / "live-cfg"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            (cfg_dir / "local.token").write_text("r7-group-tok\n", encoding="utf-8")
            bridge, _ac = _load_isolated_bridge(tmp, extra_env={"AGY_TG_BOT_USERNAME": "example_bot"})
            bridge.BOT_META["handle"] = "example_bot"
            bridge.BOT_META["bot_key"] = "main"

            class _FakeResp:
                def __init__(self, status_code: int, payload: dict) -> None:
                    self.status_code = status_code
                    self._payload = payload

                def json(self) -> dict:
                    return self._payload

            post_bodies: list[tuple[str, dict]] = []

            def _fake_post_conflict(url: str, json=None, **_kw):
                post_bodies.append((url, dict(json or {})))
                return _FakeResp(
                    409,
                    {
                        "ok": False,
                        "error": "当前正在运行 Profile 'ultra-secret-profile'，请先执行 `live-browser stop` 或传入 `--restart`。",
                    },
                )

            def _fake_get_down(_url: str, **_kw):
                raise RuntimeError("http://127.0.0.1:18795/internal/status backend-secret-trace")

            sent: list[tuple[int, str, dict]] = []
            with (
                mock.patch.dict(os.environ, {"AGY_LIVE_BROWSER_CONFIG_DIR": str(cfg_dir)}, clear=False),
                mock.patch.object(bridge.requests, "post", side_effect=_fake_post_conflict),
                mock.patch.object(bridge.requests, "get", side_effect=_fake_get_down),
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append((cid, txt, kw)) or 1),
            ):
                # 1. Group `/browser start`, `switch`, `stop` on 409 conflict MUST NOT echo profile name or backend details!
                for sub_cmd in ("start other-prof", "switch other-prof", "stop"):
                    sent.clear()
                    bridge.cmd_browser(-1001234567890, sub_cmd, from_user={"id": 111})
                    self.assertEqual(1, len(sent))
                    grp_err_text = sent[0][1]
                    self.assertNotIn("ultra-secret-profile", grp_err_text)
                    self.assertNotIn("live-browser stop", grp_err_text)
                    self.assertIn("私聊", grp_err_text)
                self.assertTrue(all(body.get("chat_scope") == "group" for _, body in post_bodies))

                # 2. Group `/browser` when status endpoint is unreachable MUST NOT echo raw backend exception text!
                sent.clear()
                bridge.cmd_browser(-1001234567890, "", from_user={"id": 111})
                self.assertEqual(1, len(sent))
                self.assertNotIn("backend-secret-trace", sent[0][1])
                self.assertNotIn("127.0.0.1:18795", sent[0][1])
                self.assertIn("私聊", sent[0][1])

                # 3. Private DM `/browser start` still shows detailed error to the owner
                sent.clear()
                bridge.cmd_browser(111, "start other-prof", from_user={"id": 111})
                self.assertEqual(1, len(sent))
                self.assertIn("ultra-secret-profile", sent[0][1])

            # 4. Server-side: redacted status dict, group/restricted /internal/profiles, and group /internal/start 409!
            async def _server_check() -> None:
                bdir = Path(tmp) / "bridge-r7"
                bdir.mkdir(parents=True, exist_ok=True)
                (bdir / ".env").write_text(
                    "AGY_TG_BOT_TOKEN=123456789:EXAMPLE_R7_GROUP_TOKEN_1\nAGY_TG_ALLOWED_CHATS=111,-1001234567890\nAGY_TG_ADMIN_USERS=111\n",
                    encoding="utf-8",
                )
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "r7-srv-tok")
                hub.engine_mode = "async_hosted"
                hub.session_owner = ("main", 111)
                hub.active_profile = "ultra-secret-profile"

                class _FakeReq:
                    def __init__(self, query: dict[str, str] | None = None, body: dict | None = None) -> None:
                        self.query = query or {}
                        self._body = body or {}
                        self.headers = {"X-Live-Token": "r7-srv-tok"}
                        self.remote = "127.0.0.1"
                        self.app = {"hub": hub}

                    async def json(self) -> dict:
                        return self._body

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "web", _FakeWebModule),
                    mock.patch.object(srv, "discover_pinned_host_profile", return_value=None),
                    mock.patch.object(
                        srv,
                        "list_profiles",
                        return_value=[{"name": "ultra-secret-profile", "os": "windows", "active": True}],
                    ),
                ):
                    # Redacted status dict itself has profiles == []
                    self.assertEqual([], hub._redacted_state_dict().get("profiles"))

                    # Group-scoped /internal/status & /internal/profiles return profiles == []
                    r_st_grp = await srv.internal_status(
                        _FakeReq(
                            query={
                                "source": "tg_cmd",
                                "bot": "main",
                                "user_id": "111",
                                "chat_id": "-1001234567890",
                                "chat_scope": "group",
                            }
                        )  # type: ignore[arg-type]
                    )
                    self.assertTrue(r_st_grp.data.get("session_restricted"))
                    self.assertEqual([], r_st_grp.data.get("profiles"))

                    r_prof_grp = await srv.internal_profiles_list(
                        _FakeReq(
                            query={
                                "source": "tg_cmd",
                                "bot": "main",
                                "user_id": "111",
                                "chat_id": "-1001234567890",
                                "chat_scope": "group",
                            }
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual([], r_prof_grp.data.get("profiles"))
                    self.assertIsNone(r_prof_grp.data.get("active_profile"))

                    # Group-scoped /internal/start hitting 409 conflict does NOT leak active_profile!
                    r_start_grp = await srv.internal_start(
                        _FakeReq(
                            body={
                                "source": "tg_cmd",
                                "chat_scope": "group",
                                "bot": "main",
                                "user_id": 111,
                                "profile": "default",
                                "restart": False,
                            }
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(409, r_start_grp.status)
                    self.assertNotIn("ultra-secret-profile", str(r_start_grp.data.get("error", "")))

                    # Even when idle, group-scoped /internal/status and /internal/profiles do NOT expose profile catalog!
                    hub.engine_mode = "idle"
                    r_st_idle_grp = await srv.internal_status(
                        _FakeReq(
                            query={
                                "source": "tg_cmd",
                                "bot": "main",
                                "user_id": "111",
                                "chat_id": "-1001234567890",
                                "chat_scope": "group",
                            }
                        )  # type: ignore[arg-type]
                    )
                    self.assertFalse(bool(r_st_idle_grp.data.get("session_restricted")))
                    self.assertEqual([], r_st_idle_grp.data.get("profiles"))

                    r_prof_idle_grp = await srv.internal_profiles_list(
                        _FakeReq(
                            query={
                                "source": "tg_cmd",
                                "bot": "main",
                                "user_id": "111",
                                "chat_id": "-1001234567890",
                                "chat_scope": "group",
                            }
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual([], r_prof_idle_grp.data.get("profiles"))

            asyncio.run(_server_check())


if __name__ == "__main__":
    unittest.main()
