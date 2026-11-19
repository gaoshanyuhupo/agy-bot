#!/usr/bin/env python3
"""Offline unit tests for Live-Browser Phase 1+2 UX upgrades, multi-bot auth & sharp arrow cursor."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
import urllib.parse

REPO_ROOT = Path(__file__).resolve().parents[1]
LIVE_SCRIPTS = REPO_ROOT / ".agents/skills/live-browser/scripts"
INDEX_HTML_PATH = LIVE_SCRIPTS / "static/index.html"
if str(LIVE_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(LIVE_SCRIPTS))

import live_browser_ctl  # noqa: E402
import live_browser_server as srv  # noqa: E402


def _signed_init_data(bot_token: str, user_id: int = 111) -> str:
    params = {
        "auth_date": str(int(time.time())),
        "query_id": "AAHdF6IQAAAAAN0XohDhrOrc",
        "user": json.dumps({"id": user_id, "first_name": "Tester"}, separators=(",", ":")),
    }
    check_str = "\n".join(f"{k}={params[k]}" for k in sorted(params))
    secret = hmac.new(b"WebAppData", bot_token.encode("utf-8"), hashlib.sha256).digest()
    params["hash"] = hmac.new(secret, check_str.encode("utf-8"), hashlib.sha256).hexdigest()
    return urllib.parse.urlencode(params)


class _FakeMouse:
    def __init__(self) -> None:
        self.events: list[tuple] = []

    async def move(self, x: float, y: float) -> None:
        self.events.append(("move", x, y))

    async def down(self, *, button: str = "left") -> None:
        self.events.append(("down", button))

    async def up(self, *, button: str = "left") -> None:
        self.events.append(("up", button))

    async def click(self, x: float, y: float, **kwargs) -> None:
        self.events.append(("click", x, y, kwargs))

    async def dblclick(self, x: float, y: float) -> None:
        self.events.append(("dblclick", x, y))

    async def wheel(self, dx: float, dy: float) -> None:
        self.events.append(("wheel", dx, dy))


class _FakePage:
    def __init__(self, url: str = "https://example.com", title_text: str = "Example") -> None:
        self.url = url
        self._title = title_text
        self.title_calls = 0
        self.screenshot_qualities: list[int] = []
        self.next_jpeg: bytes = b"JPEG_FRAME_A"
        self.viewport_size = {"width": 1280, "height": 800}
        self.mouse = _FakeMouse()
        self._listeners: dict[str, list] = {}

    def on(self, event: str, cb) -> None:
        self._listeners.setdefault(event, []).append(cb)

    def emit(self, event: str, *args) -> None:
        for cb in list(self._listeners.get(event, [])):
            cb(*args)

    async def title(self) -> str:
        self.title_calls += 1
        return self._title

    async def screenshot(self, **kwargs) -> bytes:
        if "quality" in kwargs:
            self.screenshot_qualities.append(int(kwargs["quality"]))
        return self.next_jpeg

    async def evaluate(self, _expr: str, *_args):
        return None


class _FakeCtx:
    def __init__(self, pages: list[_FakePage]) -> None:
        self.pages = pages


class _FakeDialog:
    def __init__(self, dtype: str = "confirm", message: str = "Proceed?", default_value: str = "") -> None:
        self.type = dtype
        self.message = message
        self.default_value = default_value
        self.accepted: list[str | None] = []
        self.dismissed: int = 0

    async def accept(self, prompt_text: str | None = None) -> None:
        self.accepted.append(prompt_text)

    async def dismiss(self) -> None:
        self.dismissed += 1


class _FakeFileChooser:
    def __init__(self, multiple: bool = False) -> None:
        self._multiple = multiple
        self.received_files = None

    def is_multiple(self) -> bool:
        return self._multiple

    async def set_files(self, files) -> None:
        self.received_files = files


class _FakeDownload:
    def __init__(self, filename: str, payload: bytes) -> None:
        self.suggested_filename = filename
        self._payload = payload

    async def save_as(self, path: str) -> None:
        Path(path).write_bytes(self._payload)


class _FakeHTTPResp:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def json(self) -> dict:
        return self._payload


class _FakeFormData:
    def __init__(self) -> None:
        self.fields: dict[str, object] = {}

    def add_field(self, name: str, value, **_kwargs) -> None:
        self.fields[name] = value


class _FakeJSONResponse:
    def __init__(self, data: dict, status: int = 200) -> None:
        self.data = data
        self.status = status


class _FakeFileResponse:
    def __init__(self, path: Path, headers: dict | None = None) -> None:
        self.path = path
        self.headers = headers or {}
        self.status = 200


class _FakeHTTPForbidden(Exception):
    status = 403

    def __init__(self, text: str = "Forbidden") -> None:
        super().__init__(text)


class _FakeWeb:
    HTTPForbidden = _FakeHTTPForbidden

    @staticmethod
    def json_response(data: dict, status: int = 200) -> _FakeJSONResponse:
        return _FakeJSONResponse(data, status=status)

    @staticmethod
    def FileResponse(path: Path, headers: dict | None = None) -> _FakeFileResponse:
        return _FakeFileResponse(path, headers=headers)


class _FakeMultipartPart:
    def __init__(self, name: str, data: bytes, filename: str | None = None) -> None:
        self.name = name
        self.filename = filename
        self._data = data
        self._offset = 0

    async def text(self) -> str:
        return self._data.decode("utf-8")

    async def read_chunk(self, size: int = 65536) -> bytes:
        if self._offset >= len(self._data):
            return b""
        chunk = self._data[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk


class _FakeMultipartReader:
    def __init__(self, parts: list[_FakeMultipartPart]) -> None:
        self._parts = list(parts)

    async def next(self):
        return self._parts.pop(0) if self._parts else None


class TestMultiBotCredentialsAndPrivateRouting(unittest.TestCase):
    """Verify multi-bot .env* discovery, 3-bot HMAC auth, and strictly positive DM routing."""

    def test_discover_and_auth_all_three_bots_ignoring_backups(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOKEN_ABCDEF12345"
            tok_sg = "100002:EXAMPLE_SG_TOKEN_ABCDEF123456"
            tok_third = "100003:EXAMPLE_THIRD_TOKEN_ABCDEF123"
            (bdir / ".env").write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=-1001234567890,111\n",
                encoding="utf-8",
            )
            (bdir / ".env.sg").write_text(
                f"AGY_TG_BOT_TOKEN={tok_sg}\nAGY_TG_ALLOWED_CHATS=-1001234567890,222\n",
                encoding="utf-8",
            )
            (bdir / ".env.worker3").write_text(
                f"AGY_TG_BOT_TOKEN={tok_third}\nAGY_TG_ALLOWED_CHATS=-1001234567890,333\n",
                encoding="utf-8",
            )
            # Non-runtime files must be skipped
            (bdir / ".env.bak").write_text("AGY_TG_BOT_TOKEN=999:BAD_BAK_TOKEN\n", encoding="utf-8")
            (bdir / ".env.example").write_text("AGY_TG_BOT_TOKEN=998:BAD_EX_TOKEN\n", encoding="utf-8")
            (bdir / ".env.sg.tmp").write_text("AGY_TG_BOT_TOKEN=997:BAD_TMP_TOKEN\n", encoding="utf-8")

            with mock.patch.object(srv, "_BRIDGE_DIR", bdir):
                bots, id_map, allowed, by_bot = srv.load_bot_credentials_detailed()

            self.assertEqual({"main", "sg", "worker3"}, set(bots.keys()))
            self.assertEqual("worker3", id_map["100003"])
            self.assertEqual({-1001234567890, 111, 222, 333}, allowed)
            self.assertEqual({-1001234567890, 333}, by_bot["worker3"])

            for expected_bot, tok, uid in (
                ("main", tok_main, 111),
                ("sg", tok_sg, 222),
                ("worker3", tok_third, 333),
            ):
                ok, info, err = srv.verify_telegram_init_data(_signed_init_data(tok, uid), bots, allowed)
                self.assertTrue(ok, f"Auth failed for {expected_bot}: {err}")
                assert info is not None
                self.assertEqual(expected_bot, info["bot"])

    def test_resolve_private_chat_id_never_picks_negative_group(self) -> None:
        self.assertIsNone(srv._resolve_private_chat_id({-1001234567890, -555}))
        self.assertEqual(111, srv._resolve_private_chat_id({-1001234567890, 111, 222}))
        self.assertEqual(222, srv._resolve_private_chat_id({-1001234567890, 111, 222}, preferred_user_id=222))
        # Ignores preferred_user_id if not whitelisted or negative
        self.assertEqual(111, srv._resolve_private_chat_id({-1001234567890, 111}, preferred_user_id=999))
        self.assertEqual(111, srv._resolve_private_chat_id({-1001234567890, 111}, preferred_user_id=-1001234567890))
        # Prefers bot-specific positive chat over global lowest positive chat
        self.assertEqual(
            333,
            srv._resolve_private_chat_id({-1001234567890, 111, 333}, bot_allowed={-1001234567890, 333}),
        )

    def test_card_and_clip_and_media_route_to_positive_dm_with_quick_buttons(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub(
                {"host": "127.0.0.1", "port": 18795, "public_url": "https://live.example.com"},
                "local-tok",
            )
            hub.latest_jpeg = b"FAKEJPEG"
            hub.title = "Test Page"
            hub.url = "https://example.com"
            posts: list[tuple[str, dict]] = []

            class _FakeHttp:
                def post(self, url: str, data=None, json=None):
                    rec = {"data": getattr(data, "fields", data), "json": json}
                    posts.append((url, rec))
                    return _FakeHTTPResp({"ok": True, "result": {"message_id": 777}})

            hub.tg.http = _FakeHttp()
            tok = "100001:EXAMPLE_TOKEN_ABCDEF12345"

            with (
                mock.patch.object(srv, "FormData", _FakeFormData),
                mock.patch.object(
                    srv,
                    "load_bot_credentials",
                    return_value=({"main": tok}, {"100001": "main"}, {-1001234567890, 111, 222}),
                ),
            ):
                card = await hub.tg.ensure_card("main", preferred_user_id=222)
                self.assertIsNotNone(card)
                assert card is not None
                self.assertEqual(222, card["chat_id"])
                markup = json.loads(posts[0][1]["data"]["reply_markup"])
                self.assertEqual(2, len(markup["inline_keyboard"]))
                self.assertIn("web_app", markup["inline_keyboard"][0][0])
                row2_cbs = [b["callback_data"] for b in markup["inline_keyboard"][1]]
                self.assertEqual(["browser:takeover_on", "browser:card_refresh", "browser:card_stop"], row2_cbs)

                # When takeover=True, button flips to takeover_off
                hub.takeover = True
                mk_tk = json.loads(hub.tg._build_markup("main", finished=False) or "{}")
                self.assertEqual("browser:takeover_off", mk_tk["inline_keyboard"][1][0]["callback_data"])

                # Clip message routes to preferred positive user_id, never negative group
                ok_clip = await hub.tg.send_clip_message("main", "hello world", preferred_user_id=222)
                self.assertTrue(ok_clip)
                self.assertEqual(222, posts[-1][1]["json"]["chat_id"])

                # HD photo routes to positive DM
                ok_photo = await hub.tg.send_photo_bytes("main", b"HDJPEG", caption="HD", preferred_user_id=222)
                self.assertTrue(ok_photo)
                self.assertEqual("222", posts[-1][1]["data"]["chat_id"])

        asyncio.run(_scenario())


class TestStreamingMouseProtocolAndNativePageEvents(unittest.TestCase):
    """Verify frame dedup, adaptive FPS, metadata decoupling, mouse protocol, dialog/upload/download."""

    def test_frame_dedup_quality_presets_and_metadata_decoupling(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            p1 = _FakePage("https://example.com/1", "Page One")
            p2 = _FakePage("https://example.com/2", "Page Two")
            hub.ctx = _FakeCtx([p1, p2])
            hub.engine_mode = "async_hosted"

            frames_sent: list[bytes] = []
            hub.broadcast_frame = mock.AsyncMock(side_effect=lambda b: frames_sent.append(b))  # type: ignore[method-assign]

            # 1st capture broadcasts & refreshes tab metadata
            c1 = await hub._capture_once()
            self.assertTrue(c1)
            self.assertEqual(1, len(frames_sent))
            self.assertEqual(1, p1.title_calls)
            self.assertEqual(1, p2.title_calls)
            self.assertEqual(srv.QUALITY_PRESETS["balanced"]["stream_quality"], p1.screenshot_qualities[-1])

            # 2nd identical capture skips broadcast AND skips p.title()!
            c2 = await hub._capture_once()
            self.assertFalse(c2)
            self.assertEqual(1, len(frames_sent))
            self.assertEqual(1, p1.title_calls)
            self.assertEqual(1, p2.title_calls)
            self.assertEqual(1, hub._unchanged_frames)

            # Still-frame HD capture uses hd_quality even if page unchanged
            c3 = await hub._capture_once(hd=True)
            self.assertTrue(c3)
            self.assertEqual(2, len(frames_sent))
            self.assertEqual(srv.QUALITY_PRESETS["balanced"]["hd_quality"], p1.screenshot_qualities[-1])
            self.assertFalse(hub._hd_pending)

            # Adaptive sleep backs off when idle and speeds up when active
            hub._last_active_ts = time.monotonic() - 2.0
            hub._unchanged_frames = 10
            self.assertGreaterEqual(hub._compute_capture_sleep(True, False, time.monotonic()), 0.5)
            hub.mark_active()
            self.assertLessEqual(hub._compute_capture_sleep(True, True, time.monotonic()), 0.11)

            # Switch quality preset to 'hd'
            chosen = await hub.set_quality_preset("hd")
            self.assertEqual("hd", chosen)
            self.assertEqual("hd", hub.state_dict()["quality_preset"])
            await hub._capture_once()
            self.assertEqual(srv.QUALITY_PRESETS["hd"]["stream_quality"], p1.screenshot_qualities[-1])

        asyncio.run(_scenario())

    def test_mouse_protocol_and_move_coalescing(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            page = _FakePage()
            hub.ctx = _FakeCtx([page])
            hub.engine_mode = "async_hosted"

            # Coalesce consecutive move events in input_queue -> only latest kept
            await hub.input_queue.put({"action": "move", "x": 10, "y": 10})
            await hub.input_queue.put({"action": "move", "x": 20, "y": 30})
            await hub.input_queue.put({"action": "move", "x": 55, "y": 66})
            await hub.input_queue.put({"action": "click", "x": 55, "y": 66})
            first = await hub.input_queue.get()
            coalesced = hub._coalesce_queued_input(first)
            self.assertEqual({"action": "move", "x": 55, "y": 66}, coalesced)
            self.assertEqual(1, hub.input_queue.qsize())

            await hub._execute_human_cmd_async({"action": "move", "x": 55, "y": 66})
            await hub._execute_human_cmd_async({"action": "mousedown", "x": 100, "y": 120, "button": "left"})
            await hub._execute_human_cmd_async({"action": "mouseup", "x": 180, "y": 140, "button": "left"})
            await hub._execute_human_cmd_async({"action": "rightclick", "x": 200, "y": 210})
            await hub._execute_human_cmd_async({"action": "click", "x": 300, "y": 310, "click_count": 2})

            self.assertIn(("move", 55.0, 66.0), page.mouse.events)
            self.assertIn(("down", "left"), page.mouse.events)
            self.assertIn(("up", "left"), page.mouse.events)
            self.assertIn(("click", 200.0, 210.0, {"button": "right"}), page.mouse.events)
            self.assertIn(("click", 300.0, 310.0, {"button": "left", "click_count": 2}), page.mouse.events)

        asyncio.run(_scenario())

    def test_sync_bridge_exec_human_supports_new_mouse_actions(self) -> None:
        sync_events: list[tuple] = []

        class _SyncMouse:
            def move(self, x, y):
                sync_events.append(("move", x, y))

            def down(self, button="left"):
                sync_events.append(("down", button))

            def up(self, button="left"):
                sync_events.append(("up", button))

            def click(self, x, y, **kw):
                sync_events.append(("click", x, y, kw))

        fake_page = types.SimpleNamespace(mouse=_SyncMouse())
        fake_ctx = types.SimpleNamespace(pages=[fake_page])
        bridge = object.__new__(live_browser_ctl.SyncLiveBridge)
        bridge.raw_ctx = fake_ctx
        bridge.active_idx = 0

        bridge._exec_human_sync({"action": "move", "x": 12, "y": 34})
        bridge._exec_human_sync({"action": "mousedown", "x": 12, "y": 34, "button": "left"})
        bridge._exec_human_sync({"action": "mouseup", "x": 45, "y": 67, "button": "left"})
        bridge._exec_human_sync({"action": "rightclick", "x": 88, "y": 99})
        bridge._exec_human_sync({"action": "click", "x": 5, "y": 6, "click_count": 2})

        self.assertIn(("move", 12.0, 34.0), sync_events)
        self.assertIn(("down", "left"), sync_events)
        self.assertIn(("up", "left"), sync_events)
        self.assertIn(("click", 88.0, 99.0, {"button": "right"}), sync_events)
        self.assertIn(("click", 5.0, 6.0, {"button": "left", "click_count": 2}), sync_events)

    def test_native_dialog_pause_resolve_and_headless_auto_dismiss(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            broadcasts: list[dict] = []
            hub.broadcast_json = mock.AsyncMock(side_effect=lambda obj: broadcasts.append(obj))  # type: ignore[method-assign]

            # 1. No viewers and not takeover -> auto-dismisses immediately (no deadlock!)
            dlg_bg = _FakeDialog("alert", "Background alert")
            await hub._handle_page_dialog(dlg_bg)
            self.assertEqual(1, dlg_bg.dismissed)
            self.assertEqual(0, len(hub.pending_dialogs))

            # 2. Takeover active -> holds dialog, broadcasts dialog_open, resolves on prompt accept
            hub.takeover = True
            dlg_prompt = _FakeDialog("prompt", "Enter code:", "123")
            await hub._handle_page_dialog(dlg_prompt)
            self.assertEqual(1, len(hub.pending_dialogs))
            self.assertTrue(any(b.get("type") == "dialog_open" for b in broadcasts))
            did = next(iter(hub.pending_dialogs.keys()))

            ok = await hub.resolve_dialog(did, accept=True, prompt_text="999999")
            self.assertTrue(ok)
            self.assertEqual(["999999"], dlg_prompt.accepted)
            self.assertEqual(0, len(hub.pending_dialogs))

            # 3. Cleanup dismisses dangling dialogs on shutdown
            dlg_hang = _FakeDialog("confirm", "Leave?")
            await hub._handle_page_dialog(dlg_hang)
            self.assertEqual(1, len(hub.pending_dialogs))
            await hub._cleanup_pending_dialogs()
            self.assertEqual(1, dlg_hang.dismissed)
            self.assertEqual(0, len(hub.pending_dialogs))

        asyncio.run(_scenario())

    def test_filechooser_upload_auth_size_limit_and_download_cleanup(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            bot_tok = "100001:EXAMPLE_UPLOAD_TOKEN_1234567"
            valid_init = _signed_init_data(bot_tok, user_id=111)
            chooser = _FakeFileChooser(multiple=False)
            await hub._handle_page_filechooser(chooser)
            cid = next(iter(hub.pending_filechoosers.keys()))

            class _FakeUploadReq:
                def __init__(self, init_hdr: str, parts: list[_FakeMultipartPart], query_cid: str = "") -> None:
                    self.headers = {"X-TG-Init-Data": init_hdr}
                    self.query = {"chooser_id": query_cid} if query_cid else {}
                    self.app = {"hub": hub}
                    self._parts = parts

                async def multipart(self):
                    return _FakeMultipartReader(self._parts)

            with (
                mock.patch.object(srv, "web", _FakeWeb),
                mock.patch.object(srv, "load_bot_credentials", return_value=({"main": bot_tok}, {}, {111})),
            ):
                # 1. Bad HMAC -> 403
                r403 = await srv.handle_api_upload(_FakeUploadReq("bad=1", [], cid))  # type: ignore[arg-type]
                self.assertEqual(403, r403.status)

                # 2. Oversized file (> MAX_UPLOAD_BYTES) -> 413
                with mock.patch.object(srv, "MAX_UPLOAD_BYTES", 10):
                    r413 = await srv.handle_api_upload(
                        _FakeUploadReq(valid_init, [_FakeMultipartPart("files", b"0123456789ABCDEF", "big.bin")], cid)  # type: ignore[arg-type]
                    )
                    self.assertEqual(413, r413.status)
                    self.assertIsNone(chooser.received_files)

                # 3. Valid upload -> 200 and passes path to chooser.set_files
                r200 = await srv.handle_api_upload(
                    _FakeUploadReq(valid_init, [_FakeMultipartPart("files", b"hello-upload", "note.txt")], cid)  # type: ignore[arg-type]
                )
                self.assertEqual(200, r200.status)
                self.assertTrue(r200.data["ok"])
                self.assertIsInstance(chooser.received_files, str)
                self.assertTrue(Path(chooser.received_files).is_file())
                self.assertEqual(b"hello-upload", Path(chooser.received_files).read_bytes())

                # 4. Download handler saves file, auto-pushes <=20MB to TG DM, serves authenticated GET, cleans up
                hub.tg.send_document_file = mock.AsyncMock(return_value=True)  # type: ignore[method-assign]
                dl = _FakeDownload("report.pdf", b"%PDF-1.4 sample")
                await hub._handle_page_download(dl)
                self.assertEqual(1, len(hub.downloads))
                hub.tg.send_document_file.assert_awaited_once()
                did = next(iter(hub.downloads.keys()))
                dl_path = Path(hub.downloads[did]["path"])
                self.assertTrue(dl_path.is_file())

                dl_req = types.SimpleNamespace(
                    headers={"X-TG-Init-Data": valid_init},
                    match_info={"download_id": did},
                    app={"hub": hub},
                )
                dl_resp = await srv.handle_api_download(dl_req)  # type: ignore[arg-type]
                self.assertEqual(200, dl_resp.status)
                self.assertEqual(dl_path, dl_resp.path)

                hub._cleanup_transfer_dir(force_all=True)
                self.assertFalse(dl_path.exists())
                self.assertEqual(0, len(hub.downloads))

        asyncio.run(_scenario())

    def test_internal_takeover_endpoint(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
            hub.tg.tick_updates = mock.AsyncMock(return_value=None)  # type: ignore[method-assign]

            class _FakeReq:
                def __init__(self, body: dict, tok: str = "sec-tok") -> None:
                    self._body = body
                    self.headers = {"X-Live-Token": tok}
                    self.remote = "127.0.0.1"
                    self.app = {"hub": hub}

                async def json(self) -> dict:
                    return self._body

            with mock.patch.object(srv, "web", _FakeWeb):
                with self.assertRaises(_FakeHTTPForbidden):
                    await srv.internal_takeover(_FakeReq({"active": True}, tok="wrong"))  # type: ignore[arg-type]
                r_on = await srv.internal_takeover(_FakeReq({"active": True, "reason": "Card click"}))  # type: ignore[arg-type]
                self.assertEqual(200, r_on.status)
                self.assertTrue(hub.takeover)
                r_off = await srv.internal_takeover(_FakeReq({"active": False}))  # type: ignore[arg-type]
                self.assertEqual(200, r_off.status)
                self.assertFalse(hub.takeover)

        asyncio.run(_scenario())


class TestFrontendIndexHtmlRegression(unittest.TestCase):
    """Static structure & anti-regression checks on Mini App `static/index.html`."""

    def test_sharp_arrow_cursor_and_ux_controls_present(self) -> None:
        html_src = INDEX_HTML_PATH.read_text(encoding="utf-8")

        # Sharp small SVG arrow cursor anchored at tip & inverse scaled, replacing blobby .ripple
        self.assertIn('id="remote-cursor"', html_src)
        self.assertIn("transform-origin: 0 0", html_src)
        self.assertIn("updateCursorInverseScale", html_src)
        self.assertIn(".click-ring {", html_src)
        self.assertIn("r.className = 'click-ring '", html_src)
        self.assertNotIn("spawnRipple", html_src)
        self.assertNotIn(".ripple {", html_src)

        # Latest-frame single-slot decoder & exponential backoff reconnect
        self.assertIn("pendingFrameBlob", html_src)
        self.assertIn("decodingFrame", html_src)
        self.assertIn("RECONNECT_DELAYS", html_src)
        self.assertIn('id="reconnect-btn"', html_src)

        # Immersive fullscreen + TG WebApp 8.0+ safe-area & closing confirmation & landscape
        self.assertIn('id="immersive-btn"', html_src)
        self.assertIn('id="immersive-fab"', html_src)
        self.assertIn("--tg-safe-area-inset-top", html_src)
        self.assertIn("enableClosingConfirmation", html_src)
        self.assertIn("requestFullscreen", html_src)
        self.assertIn("(orientation: landscape)", html_src)

        # Anchor zoom + clampPan + 4 gesture modes (interact / trackpad / drag / extract) + hold toggle
        self.assertIn("function clampPan()", html_src)
        self.assertIn("setGestureMode('trackpad')", html_src)
        self.assertIn("setGestureMode('drag')", html_src)
        self.assertIn('id="trackpad-hold-btn"', html_src)
        self.assertIn("action: 'rightclick'", html_src)
        self.assertIn("click_count:", html_src)

        # P2 dialog, file upload, download banner, quality preset, HD screenshot, extra shortcut chips
        self.assertIn('id="dialog-sheet"', html_src)
        self.assertIn('id="upload-sheet"', html_src)
        self.assertIn("/api/upload", html_src)
        self.assertIn('id="download-banner"', html_src)
        self.assertIn('id="quality-badge"', html_src)
        self.assertIn("send_hd_screenshot", html_src)
        self.assertIn("Control+v", html_src)
        self.assertIn("Control+z", html_src)
        self.assertIn("Control+f", html_src)


if __name__ == "__main__":
    unittest.main()
