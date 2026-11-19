#!/usr/bin/env python3
"""Offline unit tests for Live-Browser Phase 1+2 UX upgrades, multi-bot auth & sharp arrow cursor."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path
import re
import shutil
import subprocess
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
        self.keyboard = types.SimpleNamespace(press=mock.AsyncMock(), type=mock.AsyncMock(), insert_text=mock.AsyncMock())
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
                ok, info, err = srv.verify_telegram_init_data(
                    _signed_init_data(tok, uid), bots, allowed, allowed_by_bot=by_bot
                )
                self.assertTrue(ok, f"Auth failed for {expected_bot}: {err}")
                assert info is not None
                self.assertEqual(expected_bot, info["bot"])
                self.assertEqual(uid, info["user_id"])
                self.assertEqual("admin", info["role"])

            # Cross-bot authorization MUST fail (uid=222 belongs to sg, NOT main!)
            ok_cross, info_cross, _ = srv.verify_telegram_init_data(
                _signed_init_data(tok_main, 222), bots, allowed, allowed_by_bot=by_bot
            )
            self.assertFalse(ok_cross)
            self.assertIsNone(info_cross)

    def test_resolve_private_chat_id_never_picks_negative_group_or_ambiguous_fallback(self) -> None:
        # Negative-only -> None
        self.assertIsNone(srv._resolve_private_chat_id({-1001234567890, -555}))
        # Ambiguous >=2 positive IDs with no preferred_user_id -> None (never guesses!)
        self.assertIsNone(srv._resolve_private_chat_id({-1001234567890, 111, 222}))
        # Exactly 1 positive ID with no preferred_user_id -> selected cleanly
        self.assertEqual(111, srv._resolve_private_chat_id({-1001234567890, 111}))
        # Explicit whitelisted positive preferred_user_id -> selected
        self.assertEqual(222, srv._resolve_private_chat_id({-1001234567890, 111, 222}, preferred_user_id=222))
        # Unwhitelisted or negative preferred_user_id -> None (NEVER falls back to another user!)
        self.assertIsNone(srv._resolve_private_chat_id({-1001234567890, 111}, preferred_user_id=999))
        self.assertIsNone(srv._resolve_private_chat_id({-1001234567890, 111}, preferred_user_id=-1001234567890))
        # Strictly consults bot_allowed (never global union!)
        self.assertEqual(
            333,
            srv._resolve_private_chat_id({-1001234567890, 111, 333}, bot_allowed={-1001234567890, 333}),
        )
        self.assertIsNone(
            srv._resolve_private_chat_id(
                {-1001234567890, 111, 333}, preferred_user_id=111, bot_allowed={-1001234567890, 333}
            )
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
            hub.session_gen = 1
            hub.session_owner = ("main", 111)
            bot_tok = "100001:EXAMPLE_UPLOAD_TOKEN_1234567"
            valid_init = _signed_init_data(bot_tok, user_id=111)
            chooser = _FakeFileChooser(multiple=False)
            await hub._handle_page_filechooser(chooser)
            cid = next(iter(hub.pending_filechoosers.keys()))

            class _FakeUploadReq:
                def __init__(self, init_hdr: str, parts: list[_FakeMultipartPart], query_cid: str = "") -> None:
                    self.headers = {"X-TG-Init-Data": init_hdr}
                    if query_cid:
                        self.headers["X-Chooser-Id"] = query_cid
                    self.query = {"chooser_id": query_cid} if query_cid else {}
                    self.app = {"hub": hub}
                    self._parts = parts
                    self.multipart_called = False

                async def multipart(self):
                    self.multipart_called = True
                    return _FakeMultipartReader(self._parts)

            with (
                mock.patch.object(srv, "web", _FakeWeb),
                mock.patch.object(srv, "load_bot_credentials", return_value=({"main": bot_tok}, {}, {111})),
            ):
                # 1. Bad HMAC -> 403
                r403 = await srv.handle_api_upload(_FakeUploadReq("bad=1", [], cid))  # type: ignore[arg-type]
                self.assertEqual(403, r403.status)

                # 2. Oversized file (> MAX_UPLOAD_BYTES) -> 413 and cleans up staging dir
                with mock.patch.object(srv, "MAX_UPLOAD_BYTES", 10):
                    r413 = await srv.handle_api_upload(
                        _FakeUploadReq(valid_init, [_FakeMultipartPart("files", b"0123456789ABCDEF", "big.bin")], cid)  # type: ignore[arg-type]
                    )
                    self.assertEqual(413, r413.status)
                    self.assertIsNone(chooser.received_files)
                    # Staging subdir cleaned up completely
                    xfer_entries = list(hub._transfer_dir.iterdir()) if hub._transfer_dir else []
                    self.assertEqual([], xfer_entries)

                # 3. Valid upload -> 200 and preserves original sanitized filename in chooser.set_files
                r200 = await srv.handle_api_upload(
                    _FakeUploadReq(valid_init, [_FakeMultipartPart("files", b"hello-upload", "note.txt")], cid)  # type: ignore[arg-type]
                )
                self.assertEqual(200, r200.status)
                self.assertTrue(r200.data["ok"])
                self.assertIsInstance(chooser.received_files, str)
                self.assertEqual("note.txt", Path(chooser.received_files).name)
                self.assertTrue(Path(chooser.received_files).is_file())
                self.assertEqual(b"hello-upload", Path(chooser.received_files).read_bytes())

                # 4. Download handler saves file, auto-pushes <=20MB to owner TG DM, serves authenticated GET with safe headers, cleans up
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
                self.assertEqual("nosniff", dl_resp.headers.get("X-Content-Type-Options"))
                self.assertEqual("application/octet-stream", dl_resp.headers.get("Content-Type"))
                self.assertIn("filename*=UTF-8''", dl_resp.headers.get("Content-Disposition", ""))

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
        self.assertIn('id="ai-cursor"', html_src)
        self.assertIn('d="M0 0L0 ', html_src)
        self.assertIn("onPointerCancel", html_src)
        self.assertIn("lostpointercapture", html_src)
        self.assertIn("X-Chooser-Id", html_src)


class _FakeWSViewer:
    """Minimal WebSocket fake for verifying scoped broadcasts, close codes, and RBAC."""

    def __init__(self, incoming: list[dict] | None = None) -> None:
        self.closed = False
        self.close_code: int | None = None
        self.sent_json: list[dict] = []
        self.sent_bytes: list[bytes] = []
        self._incoming = list(incoming or [])

    async def prepare(self, _req) -> None:
        return None

    async def receive(self):
        if not self._incoming:
            return types.SimpleNamespace(type=srv.WSMsgType.CLOSE, data=None)
        item = self._incoming.pop(0)
        return types.SimpleNamespace(type=srv.WSMsgType.TEXT, data=json.dumps(item))

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self._incoming or self.closed:
            raise StopAsyncIteration
        item = self._incoming.pop(0)
        return types.SimpleNamespace(type=srv.WSMsgType.TEXT, data=json.dumps(item))

    async def send_str(self, s: str) -> None:
        self.sent_json.append(json.loads(s))

    async def send_bytes(self, b: bytes) -> None:
        self.sent_bytes.append(b)

    async def close(self, code: int = 1000, message: bytes = b"") -> None:
        self.closed = True
        self.close_code = code


class TestP0SecurityIsolationAndPrivateRouting(unittest.TestCase):
    """P0-01 & P0-02 behavioral tests: per-bot auth, RBAC, session_gen, ownership, card retirement & cache clearing."""

    def test_tokenless_env_file_ignored_and_rbac_roles_parsed_per_bot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOK_ABCDEF12345"
            tok_sg = "100002:EXAMPLE_SG_TOK_ABCDEF1234567"
            (bdir / ".env").write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\n"
                "AGY_TG_ALLOWED_CHATS=-1001,111,112\n"
                "AGY_TG_ADMIN_USERS=111\n"
                "AGY_TG_READONLY_USERS=112\n",
                encoding="utf-8",
            )
            (bdir / ".env.sg").write_text(
                f"AGY_TG_BOT_TOKEN={tok_sg}\n"
                "AGY_TG_ALLOWED_CHATS=-1001,222,223\n"
                "AGY_TG_USER_ROLES=222:admin,223:readonly\n",
                encoding="utf-8",
            )
            # Token-less runtime file MUST NOT pollute allowed_chats or allowed_by_bot!
            (bdir / ".env.rogue").write_text(
                "AGY_TG_ALLOWED_CHATS=999999\n",
                encoding="utf-8",
            )

            with mock.patch.object(srv, "_BRIDGE_DIR", bdir):
                bots, _id_map, allowed, by_bot, roles = srv.load_bot_credentials_with_rbac()

            self.assertEqual({"main", "sg"}, set(bots.keys()))
            self.assertNotIn(999999, allowed)
            self.assertNotIn("rogue", by_bot)
            self.assertEqual("admin", roles["main"][111])
            self.assertEqual("readonly", roles["main"][112])
            self.assertEqual("admin", roles["sg"][222])
            self.assertEqual("readonly", roles["sg"][223])

            # Cross-bot check: uid=222 signed by main token MUST be rejected
            ok_cross, _, _ = srv.verify_telegram_init_data(
                _signed_init_data(tok_main, 222), bots, allowed, allowed_by_bot=by_bot, bot_roles=roles
            )
            self.assertFalse(ok_cross)

            # Readonly user authenticates with role='readonly'
            ok_ro, info_ro, _ = srv.verify_telegram_init_data(
                _signed_init_data(tok_main, 112), bots, allowed, allowed_by_bot=by_bot, bot_roles=roles
            )
            self.assertTrue(ok_ro)
            assert info_ro is not None
            self.assertEqual("readonly", info_ro["role"])

    def test_scoped_resource_broadcast_and_http_isolation_cross_bot_nonowner_readonly_stale_gen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOK_ABCDEF12345"
            tok_sg = "100002:EXAMPLE_SG_TOK_ABCDEF1234567"
            (bdir / ".env").write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\n"
                "AGY_TG_ALLOWED_CHATS=111,112,113\n"
                "AGY_TG_ADMIN_USERS=111,113\n"
                "AGY_TG_READONLY_USERS=112\n",
                encoding="utf-8",
            )
            (bdir / ".env.sg").write_text(
                f"AGY_TG_BOT_TOKEN={tok_sg}\n"
                "AGY_TG_ALLOWED_CHATS=222\n",
                encoding="utf-8",
            )

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
                hub.session_gen = 5
                hub.session_owner = ("main", 111)

                ws_owner = _FakeWSViewer()
                ws_other_user = _FakeWSViewer()
                ws_readonly = _FakeWSViewer()
                ws_cross_bot = _FakeWSViewer()
                for ws_obj, meta in (
                    (ws_owner, {"bot_key": "main", "user_id": 111, "role": "admin"}),
                    (ws_other_user, {"bot_key": "main", "user_id": 113, "role": "admin"}),
                    (ws_readonly, {"bot_key": "main", "user_id": 112, "role": "readonly"}),
                    (ws_cross_bot, {"bot_key": "sg", "user_id": 222, "role": "admin"}),
                ):
                    hub.viewers.add(ws_obj)  # type: ignore[arg-type]
                    hub.viewer_meta[ws_obj] = meta

                with mock.patch.object(srv, "_BRIDGE_DIR", bdir), mock.patch.object(srv, "web", _FakeWeb):
                    # 1. Dialog, filechooser, download notifications ONLY go to ws_owner!
                    dlg = _FakeDialog("confirm", "Secret confirm")
                    await hub._handle_page_dialog(dlg)
                    chooser = _FakeFileChooser(multiple=False)
                    await hub._handle_page_filechooser(chooser)
                    cid = next(iter(hub.pending_filechoosers.keys()))
                    hub.tg.send_document_file = mock.AsyncMock(return_value=False)  # type: ignore[method-assign]
                    await hub._handle_page_download(_FakeDownload("secret.txt", b"top-secret"))
                    did = next(iter(hub.downloads.keys()))

                    owner_types = [m.get("type") for m in ws_owner.sent_json]
                    self.assertIn("dialog_open", owner_types)
                    self.assertIn("filechooser_open", owner_types)
                    self.assertIn("download_ready", owner_types)
                    for other_ws in (ws_other_user, ws_readonly, ws_cross_bot):
                        other_types = [m.get("type") for m in other_ws.sent_json]
                        self.assertNotIn("dialog_open", other_types)
                        self.assertNotIn("filechooser_open", other_types)
                        self.assertNotIn("download_ready", other_types)

                    # 2. HTTP /api/upload & /api/download reject readonly, non-owner, cross-bot, stale gen!
                    def _mk_upload(init_hdr: str, req_cid: str):
                        return types.SimpleNamespace(
                            headers={"X-TG-Init-Data": init_hdr, "X-Chooser-Id": req_cid},
                            query={"chooser_id": req_cid},
                            app={"hub": hub},
                            multipart=mock.AsyncMock(side_effect=AssertionError("multipart should not run on rejected auth")),
                        )

                    for bad_init in (
                        _signed_init_data(tok_main, 112),  # readonly
                        _signed_init_data(tok_main, 113),  # non-owner admin same bot
                        _signed_init_data(tok_sg, 222),    # cross-bot admin
                    ):
                        r_up = await srv.handle_api_upload(_mk_upload(bad_init, cid))  # type: ignore[arg-type]
                        self.assertEqual(403, r_up.status)
                        r_dl = await srv.handle_api_download(
                            types.SimpleNamespace(
                                headers={"X-TG-Init-Data": bad_init},
                                match_info={"download_id": did},
                                app={"hub": hub},
                            )  # type: ignore[arg-type]
                        )
                        self.assertEqual(403, r_dl.status)

                    # Owner succeeds on download in current session_gen
                    owner_init = _signed_init_data(tok_main, 111)
                    r_dl_ok = await srv.handle_api_download(
                        types.SimpleNamespace(
                            headers={"X-TG-Init-Data": owner_init},
                            match_info={"download_id": did},
                            app={"hub": hub},
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(200, r_dl_ok.status)

                    # Advancing session_gen invalidates old download_id & chooser_id!
                    hub.session_gen += 1
                    r_dl_stale = await srv.handle_api_download(
                        types.SimpleNamespace(
                            headers={"X-TG-Init-Data": owner_init},
                            match_info={"download_id": did},
                            app={"hub": hub},
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(404, r_dl_stale.status)
                    r_up_stale = await srv.handle_api_upload(_mk_upload(owner_init, cid))  # type: ignore[arg-type]
                    self.assertEqual(404, r_up_stale.status)

                    await hub._cleanup_pending_dialogs()
                    hub._cleanup_transfer_dir(force_all=True)

            asyncio.run(_scenario())

    def test_ws_readonly_rejects_mutations_and_revoked_user_closed_4003(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOK_ABCDEF12345"
            (bdir / ".env").write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\n"
                "AGY_TG_ALLOWED_CHATS=111,112\n"
                "AGY_TG_ADMIN_USERS=111\n"
                "AGY_TG_READONLY_USERS=112\n",
                encoding="utf-8",
            )

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
                hub.engine_mode = "async_hosted"
                hub.ctx = _FakeCtx([_FakePage()])
                hub.session_gen = 1
                hub.session_owner = ("main", 111)

                fake_ws_type = types.SimpleNamespace(TEXT="TEXT", CLOSE="CLOSE")
                # Readonly viewer tries mutating operations -> all blocked!
                ro_ws = _FakeWSViewer(
                    [
                        {"type": "auth", "initData": _signed_init_data(tok_main, 112)},
                        {"type": "set_takeover", "active": True},
                        {"type": "input", "action": "click", "x": 10, "y": 10},
                        {"type": "stop_browser"},
                        {"type": "send_to_tg", "text": "hello"},
                        {"type": "send_hd_screenshot"},
                    ]
                )
                req = types.SimpleNamespace(app={"hub": hub}, remote="127.0.0.1")

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "WSMsgType", fake_ws_type),
                    mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ro_ws)),
                ):
                    await srv.handle_ws(req)  # type: ignore[arg-type]

                self.assertFalse(hub.takeover)
                self.assertEqual("async_hosted", hub.engine_mode)
                self.assertTrue(hub.input_queue.empty())
                toasts = [m.get("message", "") for m in ro_ws.sent_json if m.get("type") == "toast"]
                self.assertGreaterEqual(len(toasts), 4)
                self.assertTrue(all("只读" in t for t in toasts))

                # Unauthenticated / wrong user gets WS close code 4003
                bad_ws = _FakeWSViewer([{"type": "auth", "initData": _signed_init_data(tok_main, 999)}])
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "WSMsgType", fake_ws_type),
                    mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: bad_ws)),
                ):
                    await srv.handle_ws(req)  # type: ignore[arg-type]
                self.assertEqual(srv.WS_CLOSE_AUTH_FORBIDDEN, bad_ws.close_code)
                self.assertTrue(any(m.get("type") == "auth_error" for m in bad_ws.sent_json))

            asyncio.run(_scenario())

    def test_card_retirement_on_stop_cache_clearing_and_revocation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOK_ABCDEF12345"
            env_path = bdir / ".env"
            env_path.write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\n",
                encoding="utf-8",
            )

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
                hub.engine_mode = "async_hosted"
                hub.ctx = _FakeCtx([_FakePage()])
                hub.session_gen = 1
                hub.latest_jpeg = b"OLD_FRAME"
                hub.latest_clip = {"text": "old secret"}
                hub.url = "https://old.example.com"
                hub.title = "Old Title"
                hub.cursor = {"x": 10, "y": 20, "actor": "human", "ts": 1.0}

                posts: list[tuple[str, dict]] = []

                class _FakeHttp:
                    def post(self, url: str, data=None, json=None):
                        posts.append((url, {"data": getattr(data, "fields", data), "json": json}))
                        return _FakeHTTPResp({"ok": True, "result": {"message_id": 500}})

                hub.tg.http = _FakeHttp()

                with mock.patch.object(srv, "_BRIDGE_DIR", bdir), mock.patch.object(srv, "FormData", _FakeFormData):
                    card = await hub.tg.ensure_card("main", preferred_user_id=111)
                    self.assertIsNotNone(card)
                    self.assertIn(("main", 111), hub.tg.cards)

                    # Stop retires card and clears ALL stale caches!
                    await hub.stop_hosted(notify_finished=True)
                    self.assertEqual({}, hub.tg.cards)
                    self.assertIsNone(hub.latest_jpeg)
                    self.assertEqual({}, hub.latest_clip)
                    self.assertEqual("", hub.url)
                    self.assertEqual("", hub.title)
                    self.assertEqual({}, hub.cursor)
                    self.assertEqual(2, hub.session_gen)

                    # Recreate card then revoke user 111 from .env -> tick_updates retires card without sending!
                    hub.engine_mode = "async_hosted"
                    hub.latest_jpeg = b"NEW_FRAME"
                    await hub.tg.ensure_card("main", preferred_user_id=111)
                    self.assertIn(("main", 111), hub.tg.cards)
                    posts.clear()
                    env_path.write_text(f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=222\n", encoding="utf-8")
                    hub.latest_jpeg = b"SENSITIVE_FRAME_AFTER_REVOKE"
                    await hub.tg.tick_updates(force=True)
                    self.assertEqual({}, hub.tg.cards)
                    self.assertEqual([], posts)

            asyncio.run(_scenario())


class TestP1BarriersDialogsAndTransferBoundaries(unittest.TestCase):
    """P1-01, P1-03, P1-04 behavioral verification."""

    def test_takeover_handoff_barrier_releases_held_mouse_and_drops_stale_cmds(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            page = _FakePage()
            hub.ctx = _FakeCtx([page])
            hub.engine_mode = "async_hosted"
            hub.session_gen = 1
            hub.session_owner = ("main", 111)
            hub.tg.tick_updates = mock.AsyncMock(return_value=None)  # type: ignore[method-assign]

            await hub.set_takeover(True, "drag test", owner=("main", 111))
            gen_tk = hub.takeover_gen
            await hub._execute_human_cmd_async(
                {
                    "action": "mousedown",
                    "x": 100,
                    "y": 100,
                    "button": "left",
                    "_session_gen": 1,
                    "_takeover_gen": gen_tk,
                    "_bot_key": "main",
                    "_user_id": 111,
                }
            )
            self.assertIn("left", hub._mouse_buttons_down)

            # Enqueue stale click belonging to gen_tk
            stale_cmd = {
                "action": "click",
                "x": 200,
                "y": 200,
                "_session_gen": 1,
                "_takeover_gen": gen_tk,
                "_bot_key": "main",
                "_user_id": 111,
            }
            await hub.input_queue.put(stale_cmd)

            # Handback must drain queue, release held 'left' button via mouse.up, and set ai_allowed_event
            await hub.set_takeover(False)
            self.assertTrue(hub.input_queue.empty())
            self.assertEqual(set(), hub._mouse_buttons_down)
            self.assertIn(("up", "left"), page.mouse.events)
            self.assertTrue(hub.ai_allowed_event.is_set())

            # Executing stale_cmd directly MUST be dropped by generation check
            prev_len = len(page.mouse.events)
            await hub._execute_human_cmd_async(stale_cmd)
            self.assertEqual(prev_len, len(page.mouse.events))

        asyncio.run(_scenario())

    def test_ai_busy_decremented_before_final_state_broadcast(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            page = _FakePage()
            hub.ctx = _FakeCtx([page])
            hub.engine_mode = "async_hosted"
            hub.tg.tick_updates = mock.AsyncMock(return_value=None)  # type: ignore[method-assign]

            seen_states: list[bool] = []
            orig_bcast = hub.broadcast_state

            async def _spy_bcast() -> None:
                seen_states.append(hub.state_dict()["ai_busy"])
                await orig_bcast()

            hub.broadcast_state = _spy_bcast  # type: ignore[method-assign]
            res = await hub.execute_ai_action({"action": "press", "key": "Enter", "notify": False})
            self.assertTrue(res["ok"])
            self.assertGreaterEqual(len(seen_states), 1)
            self.assertFalse(seen_states[-1], "Final broadcasted state must report ai_busy=False")

        asyncio.run(_scenario())

    def test_sync_bridge_ignores_stale_mutating_cmds_after_handback_and_releases_held_buttons(self) -> None:
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

        fake_page = types.SimpleNamespace(
            url="https://example.com",
            viewport_size={"width": 1280, "height": 800},
            mouse=_SyncMouse(),
            title=lambda: "Example",
            screenshot=lambda **_kw: b"JPG",
        )
        fake_ctx = types.SimpleNamespace(pages=[fake_page])
        bridge = object.__new__(live_browser_ctl.SyncLiveBridge)
        bridge.raw_ctx = fake_ctx
        bridge.active_idx = 0
        bridge.enabled = True
        bridge.notify = False
        bridge._in_checkpoint = False
        bridge._held_buttons = {"left"}
        bridge._x11_display = None
        bridge._last_clip = ""

        class _Resp:
            def json(self):
                # takeover=False with stale click -> click must be ignored, held left button must be released!
                return {"ok": True, "takeover": False, "commands": [{"action": "click", "x": 50, "y": 50}]}

        bridge.client = types.SimpleNamespace(
            base_url="http://127.0.0.1:18795",
            bot="main",
            _headers=lambda: {"X-Live-Token": "tok"},
            session=types.SimpleNamespace(post=lambda *_a, **_kw: _Resp()),
        )
        bridge.sync_checkpoint(ai_status="step", allow_takeover_loop=True)
        self.assertNotIn(("click", 50.0, 50.0, {}), sync_events)
        self.assertIn(("up", "left"), sync_events)
        self.assertEqual(set(), bridge._held_buttons)

    def test_dialog_timeout_completes_hanging_dismiss_without_self_cancel(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            hub.takeover = True
            hub.session_gen = 1
            hub.session_owner = ("main", 111)
            ws_owner = _FakeWSViewer()
            hub.viewers.add(ws_owner)  # type: ignore[arg-type]
            hub.viewer_meta[ws_owner] = {"bot_key": "main", "user_id": 111, "role": "admin"}

            dismiss_completed = False
            task_cancelled = False

            class _HangingDialog:
                type = "confirm"
                message = "Wait for timeout"
                default_value = ""

                async def dismiss(self) -> None:
                    nonlocal dismiss_completed, task_cancelled
                    try:
                        await asyncio.sleep(0.03)
                        dismiss_completed = True
                    except asyncio.CancelledError:
                        task_cancelled = True
                        raise

            with mock.patch.object(srv, "DIALOG_TIMEOUT_SECONDS", 0.02):
                await hub._handle_page_dialog(_HangingDialog())
                self.assertEqual(1, len(hub.pending_dialogs))
                tt = next(iter(hub.pending_dialogs.values()))["timeout_task"]
                await asyncio.wait_for(tt, timeout=1.0)

            self.assertTrue(dismiss_completed, "Hanging dismiss() must complete without self-cancellation")
            self.assertFalse(task_cancelled)
            self.assertEqual(0, len(hub.pending_dialogs))
            self.assertTrue(any(m.get("type") == "dialog_closed" for m in ws_owner.sent_json))

        asyncio.run(_scenario())

    def test_orphaned_dialog_dismissed_on_disconnect_and_inflight_download_cancelled_before_cleanup(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            hub.engine_mode = "async_hosted"
            hub.ctx = _FakeCtx([_FakePage()])
            hub.session_gen = 1
            hub.session_owner = ("main", 111)
            ws_owner = _FakeWSViewer()
            hub.viewers.add(ws_owner)  # type: ignore[arg-type]
            hub.viewer_meta[ws_owner] = {"bot_key": "main", "user_id": 111, "role": "admin"}

            dlg = _FakeDialog("confirm", "Orphan me")
            await hub._handle_page_dialog(dlg)
            self.assertEqual(1, len(hub.pending_dialogs))

            # Simulate last eligible admin disconnecting
            hub.viewers.discard(ws_owner)  # type: ignore[arg-type]
            hub.viewer_meta.pop(ws_owner, None)
            await hub._dismiss_orphaned_dialogs_on_disconnect()
            self.assertEqual(1, dlg.dismissed)
            self.assertEqual(0, len(hub.pending_dialogs))

            # In-flight download task cancelled & awaited cleanly before transfer_dir rmtree on stop_hosted
            started = asyncio.Event()
            cancelled_flag = False

            class _SlowDownload:
                suggested_filename = "slow.zip"

                async def save_as(self, _path: str) -> None:
                    nonlocal cancelled_flag
                    started.set()
                    try:
                        await asyncio.sleep(5.0)
                    except asyncio.CancelledError:
                        cancelled_flag = True
                        raise

            dl_task = hub._track_bg_task(
                asyncio.create_task(
                    hub._handle_page_download(_SlowDownload(), session_gen=1, owner_bot="main", owner_uid=111)
                )
            )
            await asyncio.wait_for(started.wait(), timeout=1.0)
            await hub.stop_hosted(notify_finished=False)
            self.assertTrue(cancelled_flag)
            self.assertTrue(dl_task.done())
            self.assertIsNone(hub._transfer_dir)

        asyncio.run(_scenario())

    def test_upload_pre_disk_validation_single_file_reject_field_cap_and_download_caps(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            hub.session_gen = 1
            hub.session_owner = ("main", 111)
            bot_tok = "100001:EXAMPLE_UPLOAD_TOKEN_1234567"
            valid_init = _signed_init_data(bot_tok, user_id=111)

            with (
                mock.patch.object(srv, "web", _FakeWeb),
                mock.patch.object(srv, "load_bot_credentials", return_value=({"main": bot_tok}, {}, {111})),
            ):
                # 1. Missing or unknown chooser_id fails BEFORE calling multipart() (zero disk writes)
                mp_spy = mock.AsyncMock(side_effect=AssertionError("multipart should not be read"))
                r404 = await srv.handle_api_upload(
                    types.SimpleNamespace(
                        headers={"X-TG-Init-Data": valid_init, "X-Chooser-Id": "unknown"},
                        query={},
                        app={"hub": hub},
                        multipart=mp_spy,
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(404, r404.status)
                mp_spy.assert_not_called()

                # 2. Single-file chooser rejects 2 files with 400 and cleans up partial files
                chooser1 = _FakeFileChooser(multiple=False)
                await hub._handle_page_filechooser(chooser1)
                cid1 = next(iter(hub.pending_filechoosers.keys()))
                r_multi = await srv.handle_api_upload(
                    types.SimpleNamespace(
                        headers={"X-TG-Init-Data": valid_init, "X-Chooser-Id": cid1},
                        query={},
                        app={"hub": hub},
                        multipart=mock.AsyncMock(
                            return_value=_FakeMultipartReader(
                                [
                                    _FakeMultipartPart("files", b"aaa", "a.txt"),
                                    _FakeMultipartPart("files", b"bbb", "b.txt"),
                                ]
                            )
                        ),
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(400, r_multi.status)
                self.assertEqual([], list(hub._transfer_dir.iterdir()))

                # 3. Oversized non-file field (> 8 KiB) rejected with 413
                r_bigfield = await srv.handle_api_upload(
                    types.SimpleNamespace(
                        headers={"X-TG-Init-Data": valid_init, "X-Chooser-Id": cid1},
                        query={},
                        app={"hub": hub},
                        multipart=mock.AsyncMock(
                            return_value=_FakeMultipartReader(
                                [_FakeMultipartPart("junk", b"x" * (srv.MAX_UPLOAD_NONFILE_FIELD_BYTES + 100))]
                            )
                        ),
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(413, r_bigfield.status)

                # 4. Preserves sanitized original Unicode filename
                r_ok = await srv.handle_api_upload(
                    types.SimpleNamespace(
                        headers={"X-TG-Init-Data": valid_init, "X-Chooser-Id": cid1},
                        query={},
                        app={"hub": hub},
                        multipart=mock.AsyncMock(
                            return_value=_FakeMultipartReader(
                                [_FakeMultipartPart("files", b"pdf-bytes", "财务报表 2026.pdf")]
                            )
                        ),
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(200, r_ok.status)
                self.assertEqual("财务报表 2026.pdf", Path(chooser1.received_files).name)

                # 5. Download exceeding MAX_DOWNLOAD_BYTES is discarded cleanly
                with mock.patch.object(srv, "MAX_DOWNLOAD_BYTES", 8):
                    await hub._handle_page_download(_FakeDownload("huge.bin", b"ABCDEFGHIJ"))
                self.assertEqual(0, len(hub.downloads))

                # 6. RFC 5987 Content-Disposition strips control chars
                cd = srv._format_content_disposition('bad\r\n"name\x00中文.txt')
                self.assertNotIn("\r", cd)
                self.assertNotIn("\n", cd)
                self.assertNotIn("\x00", cd)
                self.assertIn("filename*=UTF-8''", cd)

                hub._cleanup_transfer_dir(force_all=True)

        asyncio.run(_scenario())


class TestP2StreamingDedupSyncAndScopedRefresh(unittest.TestCase):
    """P2-01, P2-04, P2-05, P2-06 behavioral verification."""

    def test_static_screen_hd_dedup_does_not_oscillate_and_metadata_change_pushes_state(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")

            class _QualityAwarePage(_FakePage):
                async def screenshot(self, **kwargs) -> bytes:
                    q = int(kwargs.get("quality", 58))
                    self.screenshot_qualities.append(q)
                    return b"STATIC_HD_BYTES" if q >= 80 else b"STATIC_NORMAL_BYTES"

            p = _QualityAwarePage("https://example.com", "Title 1")
            hub.ctx = _FakeCtx([p])
            hub.engine_mode = "async_hosted"

            state_pushes: list[dict] = []
            hub.broadcast_state = mock.AsyncMock(side_effect=lambda: state_pushes.append(hub.state_dict()))  # type: ignore[method-assign]

            # Sequence: [Normal, Normal, HD, Normal, Normal] -> MUST be [True, False, True, False, False]!
            results = [
                await hub._capture_once(hd=False),
                await hub._capture_once(hd=False),
                await hub._capture_once(hd=True),
                await hub._capture_once(hd=False),
                await hub._capture_once(hd=False),
            ]
            self.assertEqual([True, False, True, False, False], results)
            self.assertFalse(hub._hd_pending)
            self.assertTrue(hub._hd_settled)
            self.assertGreaterEqual(hub._unchanged_frames, 2)

            # Metadata change (title changes while pixels unchanged) MUST trigger broadcast_state()!
            state_pushes.clear()
            p._title = "Title 2 Updated"
            hub._tabs_dirty = True
            changed = await hub._capture_once(hd=False)
            self.assertFalse(changed)
            self.assertEqual("Title 2 Updated", hub.title)
            self.assertGreaterEqual(len(state_pushes), 1)
            self.assertEqual("Title 2 Updated", state_pushes[-1]["title"])

            # Concurrent page removal during _refresh_tabs_metadata MUST NOT raise IndexError
            p2 = _FakePage("https://example.com/2", "Tab 2")
            hub.ctx = _FakeCtx([p, p2])
            hub.active_tab_index = 1

            async def _shrinking_title() -> str:
                if len(hub.ctx.pages) > 1:
                    hub.ctx.pages.pop()
                return "Shrunk"

            p.title = _shrinking_title  # type: ignore[method-assign]
            hub._tabs_dirty = True
            await hub._refresh_tabs_metadata(force=True)
            self.assertEqual("Tab 2", hub.title)

        asyncio.run(_scenario())

    def test_chooser_cleanup_broadcasts_closed_and_ws_reconnect_replays_chooser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOK_ABCDEF12345"
            (bdir / ".env").write_text(f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\n", encoding="utf-8")

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
                hub.engine_mode = "async_hosted"
                page = _FakePage()
                hub.ctx = _FakeCtx([page])
                hub.session_gen = 1
                hub.session_owner = ("main", 111)

                chooser = _FakeFileChooser(multiple=True)
                await hub._handle_page_filechooser(chooser, page)
                cid = next(iter(hub.pending_filechoosers.keys()))

                # Reconnecting owner WS receives replayed filechooser_open
                fake_ws_type = types.SimpleNamespace(TEXT="TEXT", CLOSE="CLOSE")
                ws_reconn = _FakeWSViewer([{"type": "auth", "initData": _signed_init_data(tok_main, 111)}])
                req = types.SimpleNamespace(app={"hub": hub}, remote="127.0.0.1")
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "WSMsgType", fake_ws_type),
                    mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ws_reconn)),
                ):
                    await srv.handle_ws(req)  # type: ignore[arg-type]
                self.assertTrue(
                    any(m.get("type") == "filechooser_open" and m.get("chooser_id") == cid for m in ws_reconn.sent_json)
                )

                # Page close cleanup notifies owner with filechooser_closed
                ws_live = _FakeWSViewer()
                hub.viewers.add(ws_live)  # type: ignore[arg-type]
                hub.viewer_meta[ws_live] = {"bot_key": "main", "user_id": 111, "role": "admin"}
                await hub._cleanup_pending_filechoosers_async(page_id=id(page))
                self.assertEqual(0, len(hub.pending_filechoosers))
                self.assertTrue(
                    any(m.get("type") == "filechooser_closed" and m.get("chooser_id") == cid for m in ws_live.sent_json)
                )

            asyncio.run(_scenario())

    def test_sync_queue_cap_and_lease_timeout(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            hub.engine_mode = "sync_external"
            hub.session_gen = 1
            hub._sync_last_push_ts = time.monotonic() - (srv.SYNC_LEASE_TIMEOUT_SECONDS + 5.0)
            hub.takeover = True

            # Queue cap drops move/wheel first and preserves mouseup
            hub._enqueue_sync_cmd({"action": "mouseup", "button": "left", "x": 1, "y": 1})
            for i in range(srv.SYNC_CMD_QUEUE_MAX + 25):
                hub._enqueue_sync_cmd({"action": "move", "x": i, "y": i})
            self.assertEqual(srv.SYNC_CMD_QUEUE_MAX, len(hub.sync_cmd_queue))
            self.assertTrue(any(c.get("action") == "mouseup" for c in hub.sync_cmd_queue))

            # Lease expiry resets sync_external -> idle cleanly
            expired = await hub._expire_sync_session_if_stale()
            self.assertTrue(expired)
            self.assertEqual("idle", hub.engine_mode)
            self.assertIsNone(hub._sync_last_push_ts)
            self.assertFalse(hub.takeover)
            self.assertEqual([], hub.sync_cmd_queue)

            # None _sync_last_push_ts must never falsely expire an active sync session
            hub.engine_mode = "sync_external"
            hub.session_gen = 2
            hub._sync_last_push_ts = None
            self.assertFalse(await hub._expire_sync_session_if_stale())
            self.assertEqual("sync_external", hub.engine_mode)

            # Low-uptime VM regression: monotonic() < SYNC_LEASE_TIMEOUT_SECONDS + 5.0
            # produces a negative or zero _sync_last_push_ts and must still expire by delta
            with mock.patch.object(srv.time, "monotonic", return_value=10.0):
                hub.engine_mode = "sync_external"
                hub.session_gen = 3
                hub._sync_last_push_ts = 10.0 - (srv.SYNC_LEASE_TIMEOUT_SECONDS + 5.0)
                self.assertLess(hub._sync_last_push_ts, 0.0)
                self.assertTrue(await hub._expire_sync_session_if_stale())
                self.assertEqual("idle", hub.engine_mode)
                self.assertIsNone(hub._sync_last_push_ts)

            with mock.patch.object(srv.time, "monotonic", return_value=srv.SYNC_LEASE_TIMEOUT_SECONDS + 1.0):
                hub.engine_mode = "sync_external"
                hub.session_gen = 4
                hub._sync_last_push_ts = 0.0
                self.assertTrue(await hub._expire_sync_session_if_stale())
                self.assertEqual("idle", hub.engine_mode)
                self.assertIsNone(hub._sync_last_push_ts)

        asyncio.run(_scenario())

    def test_scoped_card_refresh_only_updates_matching_bot_and_chat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOK_ABCDEF12345"
            tok_sg = "100002:EXAMPLE_SG_TOK_ABCDEF1234567"
            (bdir / ".env").write_text(f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\n", encoding="utf-8")
            (bdir / ".env.sg").write_text(f"AGY_TG_BOT_TOKEN={tok_sg}\nAGY_TG_ALLOWED_CHATS=222\n", encoding="utf-8")

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                hub.engine_mode = "async_hosted"
                hub.ctx = _FakeCtx([_FakePage()])
                hub.session_gen = 3
                hub.latest_jpeg = b"FRAME"
                edited_targets: list[tuple[str, str]] = []

                class _FakeHttp:
                    def post(self, url: str, data=None, json=None):
                        fields = getattr(data, "fields", {})
                        if "editMessageMedia" in url:
                            edited_targets.append((url, str(fields.get("chat_id"))))
                        return _FakeHTTPResp({"ok": True, "result": {"message_id": 801}})

                hub.tg.http = _FakeHttp()

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "FormData", _FakeFormData),
                    mock.patch.object(srv, "web", _FakeWeb),
                ):
                    await hub.tg.ensure_card("main", preferred_user_id=111)
                    await hub.tg.ensure_card("sg", preferred_user_id=222)
                    edited_targets.clear()

                    # Scoped refresh for (main, 111) MUST NOT touch (sg, 222)!
                    req_ok = types.SimpleNamespace(
                        headers={"X-Live-Token": "sec-tok"},
                        remote="127.0.0.1",
                        app={"hub": hub},
                        json=mock.AsyncMock(return_value={"refresh_card": True, "bot": "main", "chat_id": 111, "message_id": 801}),
                    )
                    resp_ok = await srv.internal_config(req_ok)  # type: ignore[arg-type]
                    self.assertEqual(200, resp_ok.status)
                    self.assertEqual(1, len(edited_targets))
                    self.assertEqual("111", edited_targets[0][1])

                    # Wrong chat_id for main bot -> 403
                    req_bad = types.SimpleNamespace(
                        headers={"X-Live-Token": "sec-tok"},
                        remote="127.0.0.1",
                        app={"hub": hub},
                        json=mock.AsyncMock(return_value={"refresh_card": True, "bot": "main", "chat_id": 222, "message_id": 801}),
                    )
                    resp_bad = await srv.internal_config(req_bad)  # type: ignore[arg-type]
                    self.assertEqual(403, resp_bad.status)

            asyncio.run(_scenario())


class TestFrontendBehaviorNodeVM(unittest.TestCase):
    """Execute the real inline JS from `static/index.html` inside Node.js VM to verify P1/P2/P3 UX invariants."""

    def test_frontend_gestures_cursors_dialogs_decoder_and_reconnect_behaviors(self) -> None:
        html_src = INDEX_HTML_PATH.read_text(encoding="utf-8")
        blocks = re.findall(r"<script>(.*?)</script>", html_src, re.S)
        self.assertEqual(1, len(blocks))
        js_src = blocks[0]

        harness = r"""
const vm = require('vm');
const fs = require('fs');
const assert = require('assert');
const jsCode = fs.readFileSync(process.argv[2], 'utf8');

class FakeClassList {
  constructor(initial = []) { this._set = new Set(initial); }
  add(...xs) { xs.forEach((x) => this._set.add(x)); }
  remove(...xs) { xs.forEach((x) => this._set.delete(x)); }
  toggle(x, force) {
    if (typeof force === 'boolean') { force ? this._set.add(x) : this._set.delete(x); return force; }
    if (this._set.has(x)) { this._set.delete(x); return false; }
    this._set.add(x); return true;
  }
  contains(x) { return this._set.has(x); }
}

class FakeEl {
  constructor(id = '', tag = 'DIV') {
    this.id = id;
    this.tagName = tag;
    this.style = {};
    this.classList = new FakeClassList();
    this.className = '';
    this.textContent = '';
    this.innerHTML = '';
    this.value = '';
    this.disabled = false;
    this.width = 1280;
    this.height = 800;
    this.clientWidth = 400;
    this.clientHeight = 250;
    this.children = [];
    this._listeners = {};
    this._rect = { left: 0, top: 0, width: 400, height: 250 };
  }
  addEventListener(ev, fn) { (this._listeners[ev] ||= []).push(fn); }
  dispatch(ev, obj) { (this._listeners[ev] || []).forEach((fn) => fn(obj)); }
  getBoundingClientRect() { return this._rect; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter((x) => x !== c); }
  remove() {}
  focus() {}
  blur() {}
  select() {}
  setSelectionRange() {}
  setPointerCapture() {}
  setAttribute() {}
  closest() { return null; }
  getContext() {
    return {
      drawImage: (...args) => {
        if (sandbox.__throwDrawOnce) { sandbox.__throwDrawOnce = false; throw new Error('draw failed'); }
        sandbox.__drawCount++;
        sandbox.__lastDrawArgs = args;
      }
    };
  }
}

const elements = new Map();
function getEl(id) {
  if (!elements.has(id)) elements.set(id, new FakeEl(id));
  return elements.get(id);
}
const stageEl = getEl('stage');
stageEl.clientWidth = 400; stageEl.clientHeight = 250; stageEl._rect = { left: 0, top: 0, width: 400, height: 250 };
const screenEl = getEl('screen');
screenEl.width = 1280; screenEl.height = 800;
screenEl.clientWidth = 400; screenEl.clientHeight = 250;
screenEl._rect = { left: 0, top: 0, width: 400, height: 250 };

class FakeBlob { constructor(id) { this.id = id; } }
const wsInstances = [];
class FakeWS {
  static OPEN = 1; static CONNECTING = 0; static CLOSED = 3;
  constructor(url) {
    this.url = url; this.readyState = FakeWS.OPEN; this.sent = [];
    wsInstances.push(this);
  }
  send(s) { this.sent.push(JSON.parse(s)); }
  close() { this.readyState = FakeWS.CLOSED; }
}

const timers = [];
const intervals = [];
const sandbox = {
  console, Math, Date, JSON, Map, Set, Array, Number, String, Boolean, Promise, Object, Error, URL: class extends URL {},
  performance: { now: () => 1000 },
  Blob: FakeBlob,
  WebSocket: FakeWS,
  location: { protocol: 'https:', host: 'live.example.com' },
  __throwDrawOnce: false,
  __drawCount: 0,
  __lastDrawArgs: null,
  __revokedUrls: [],
  __bmpClosed: 0,
  setTimeout: (fn, ms) => { const id = timers.length + 1; timers.push({ id, fn, ms, cleared: false }); return id; },
  clearTimeout: (id) => { const t = timers.find((x) => x.id === id); if (t) t.cleared = true; },
  setInterval: (fn, ms) => { intervals.push({ fn, ms }); return intervals.length; },
  clearInterval: () => {},
  document: {
    getElementById: (id) => getEl(id),
    createElement: (tag) => new FakeEl('', tag.toUpperCase()),
    addEventListener: () => {},
    activeElement: null,
    body: new FakeEl('body', 'BODY'),
  },
  navigator: {},
  window: null,
};
sandbox.URL.createObjectURL = (b) => `blob://mock/${b && b.id ? b.id : 'x'}`;
sandbox.URL.revokeObjectURL = (u) => { sandbox.__revokedUrls.push(u); };
sandbox.window = sandbox;
sandbox.addEventListener = () => {};
sandbox.scrollTo = () => {};
sandbox.innerHeight = 800;
sandbox.Telegram = { WebApp: { initData: 'mock_init', ready() {}, expand() {}, disableVerticalSwipes() {} } };

// Image mock for fallback test
sandbox.Image = class FakeImage {
  set src(u) {
    this._src = u;
    this.naturalWidth = 1280;
    this.naturalHeight = 800;
    Promise.resolve().then(() => { if (this.onload) this.onload(); });
  }
};

vm.createContext(sandbox);
vm.runInContext(jsCode, sandbox);

(async () => {
  // Authenticate initial WS
  const sock1 = wsInstances[0];
  sock1.onopen();
  sock1.onmessage({ data: JSON.stringify({ type: 'auth_ok', bot: 'main', user_id: 111, role: 'admin' }) });
  sock1.onmessage({ data: JSON.stringify({
    type: 'state', running: true, engine_mode: 'async_hosted', takeover: true,
    vw: 1280, vh: 800, url: 'https://example.com', tabs: [], profiles: [{ name: 'nonpin', pinned: false }]
  }) });
  sock1.sent.length = 0;

  // 1. P1-01: Handback sends mouseup BEFORE set_takeover(false) when trackpad hold is active
  vm.runInContext("setGestureMode('trackpad'); toggleTrackpadHold();", sandbox);
  sock1.sent.length = 0;
  vm.runInContext("toggleTakeover();", sandbox);
  assert.strictEqual(sock1.sent.length, 2, 'Expected mouseup then set_takeover(false)');
  assert.strictEqual(sock1.sent[0].action, 'mouseup');
  assert.strictEqual(sock1.sent[1].type, 'set_takeover');
  assert.strictEqual(sock1.sent[1].active, false);

  // Restore takeover=true
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, takeover: true, vw: 1280, vh: 800 }) });
  sock1.sent.length = 0;

  // 2. P1-02: Trackpad tap (350ms) clicks strictly at trackpadCursor (NOT finger coords!)
  vm.runInContext("setGestureMode('trackpad'); trackpadX = 320; trackpadY = 200;", sandbox);
  sock1.sent.length = 0;
  stageEl.dispatch('pointerdown', { pointerId: 1, clientX: 380, clientY: 240, pointerType: 'touch', target: screenEl });
  vm.runInContext("gestureStart.t = Date.now() - 350;", sandbox);
  stageEl.dispatch('pointerup', { pointerId: 1, clientX: 380, clientY: 240, pointerType: 'touch', target: screenEl });
  assert.strictEqual(sock1.sent.length, 1);
  assert.strictEqual(sock1.sent[0].action, 'click');
  assert.strictEqual(sock1.sent[0].x, 320);
  assert.strictEqual(sock1.sent[0].y, 200);

  // 3. P1-02: pointercancel & lostpointercapture NEVER fire click/extract and release drag at lastValidRemote
  vm.runInContext("setGestureMode('interact');", sandbox);
  sock1.sent.length = 0;
  stageEl.dispatch('pointerdown', { pointerId: 2, clientX: 100, clientY: 100, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointercancel', { pointerId: 2, clientX: 100, clientY: 100, pointerType: 'touch', target: screenEl });
  assert.strictEqual(sock1.sent.length, 0, 'pointercancel must not trigger click');

  vm.runInContext("setGestureMode('drag');", sandbox);
  sock1.sent.length = 0;
  stageEl.dispatch('pointerdown', { pointerId: 3, clientX: 50, clientY: 50, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 3, clientX: 200, clientY: 125, pointerType: 'touch', target: screenEl });
  // Release outside canvas (-50, -50) -> MUST send mouseup at lastValidRemote (640, 400), NOT startRemote (160, 160)!
  stageEl.dispatch('pointerup', { pointerId: 3, clientX: -50, clientY: -50, pointerType: 'touch', target: screenEl });
  const upMsg = sock1.sent.find((m) => m.action === 'mouseup');
  assert(upMsg, 'Expected mouseup on drag release');
  assert.strictEqual(upMsg.x, 640);
  assert.strictEqual(upMsg.y, 400);

  // 4. P1-03: Multi-dialog queue renders sequentially and removes by dialog_id
  sock1.sent.length = 0;
  sock1.onmessage({ data: JSON.stringify({ type: 'dialog_open', dialog_id: 'd1', dialog_type: 'alert', message: 'First' }) });
  sock1.onmessage({ data: JSON.stringify({ type: 'dialog_open', dialog_id: 'd2', dialog_type: 'confirm', message: 'Second' }) });
  assert.strictEqual(getEl('dialog-msg').textContent, 'First');
  sock1.onmessage({ data: JSON.stringify({ type: 'dialog_closed', dialog_id: 'd1' }) });
  assert.strictEqual(getEl('dialog-msg').textContent, 'Second');
  vm.runInContext("submitDialog(true);", sandbox);
  assert(getEl('dialog-sheet').classList.contains('hidden'));
  assert.strictEqual(sock1.sent[0].dialog_id, 'd2');

  // 5. P2-02: Separate Human & AI cursors + Resize re-projection
  vm.runInContext("setGestureMode('trackpad'); trackpadX = 640; trackpadY = 400; positionHumanCursor(640, 400, 'human', true);", sandbox);
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, takeover: true, vw: 1280, vh: 800, cursor: { x: 100, y: 100, actor: 'ai', ts: 999 } }) });
  // Human cursor stayed at 50% (200.00px), AI cursor moved to #ai-cursor!
  assert.strictEqual(getEl('remote-cursor').style.left, '200.00px');
  assert.strictEqual(getEl('ai-cursor').style.left, '31.25px');
  // Resize stage to 800x500 -> re-projects BOTH cursors!
  stageEl.clientWidth = 800; stageEl.clientHeight = 500;
  screenEl.clientWidth = 800; screenEl.clientHeight = 500;
  screenEl._rect = { left: 0, top: 0, width: 800, height: 500 };
  vm.runInContext("fitCanvasLayout();", sandbox);
  assert.strictEqual(getEl('remote-cursor').style.left, '400.00px');
  assert.strictEqual(getEl('ai-cursor').style.left, '62.50px');

  // 6. P2-02: Extract mode pinch sets wasPinch -> zero extract messages sent
  vm.runInContext("setGestureMode('extract');", sandbox);
  sock1.sent.length = 0;
  stageEl.dispatch('pointerdown', { pointerId: 10, clientX: 100, clientY: 100, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerdown', { pointerId: 11, clientX: 200, clientY: 100, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerup', { pointerId: 11, clientX: 250, clientY: 100, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerup', { pointerId: 10, clientX: 100, clientY: 100, pointerType: 'touch', target: screenEl });
  assert.strictEqual(sock1.sent.filter((m) => m.type === 'extract').length, 0);

  // 7. P2-02: Trackpad two-finger distinguishes pinch zoom vs scroll
  vm.runInContext("setGestureMode('trackpad'); resetZoom();", sandbox);
  stageEl.dispatch('pointerdown', { pointerId: 20, clientX: 200, clientY: 200, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerdown', { pointerId: 21, clientX: 300, clientY: 200, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 21, clientX: 450, clientY: 200, pointerType: 'touch', target: screenEl });
  assert(vm.runInContext("scale", sandbox) > 1.5, 'Trackpad symmetric pinch must zoom');
  stageEl.dispatch('pointerup', { pointerId: 21, clientX: 450, clientY: 200, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerup', { pointerId: 20, clientX: 200, clientY: 200, pointerType: 'touch', target: screenEl });

  // 8. P2-03: URL auto-takeover waits for server state.takeover===true ACK (no optimistic flip!)
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, takeover: false, ai_busy: false, vw: 1280, vh: 800 }) });
  sock1.sent.length = 0;
  getEl('url-input').value = 'example.org';
  vm.runInContext("submitUrl();", sandbox);
  assert.strictEqual(vm.runInContext("state.takeover", sandbox), false, 'Must not optimistically mutate state.takeover');
  assert.strictEqual(sock1.sent.length, 1);
  assert.strictEqual(sock1.sent[0].type, 'set_takeover');
  // Now server ACKs takeover=true -> goto fires immediately!
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, takeover: true, ai_busy: false, vw: 1280, vh: 800 }) });
  assert.strictEqual(sock1.sent.length, 2);
  assert.strictEqual(sock1.sent[1].action, 'goto');
  assert.strictEqual(sock1.sent[1].url, 'https://example.org');

  // 9. P2-03 & P3: bmp.close() always runs on draw exception + Image fallback revokes URL + stale connGen dropped + FPS counts drawImage
  sandbox.__bmpClosed = 0;
  sandbox.__drawCount = 0;
  sandbox.__throwDrawOnce = true;
  sandbox.createImageBitmap = async (blob) => ({ width: 1280, height: 800, close() { sandbox.__bmpClosed++; } });
  const curGen = vm.runInContext("wsConnGen", sandbox);
  await vm.runInContext(`decodeAndDrawBlob(new Blob('f1'), ${curGen})`, sandbox);
  assert.strictEqual(sandbox.__bmpClosed, 1, 'bmp.close() must run in finally even when drawImage throws');
  assert.strictEqual(sandbox.__drawCount, 1, 'Image fallback must draw after createImageBitmap draw failure');
  assert.strictEqual(sandbox.__revokedUrls.length, 1, 'Image fallback must revokeObjectURL');
  assert.strictEqual(vm.runInContext("renderedFrameCount", sandbox), 1);

  // Stale connection frame is dropped
  const prevDraws = sandbox.__drawCount;
  await vm.runInContext(`decodeAndDrawBlob(new Blob('stale'), ${curGen - 1})`, sandbox);
  assert.strictEqual(sandbox.__drawCount, prevDraws, 'Stale connection generation frame must not draw');

  // 10. P2-03 & P3: WS close 4003 stops reconnect and keeps '未授权 (403)' across interval ticks
  const timersBefore = timers.length;
  sock1.onclose({ code: 4003 });
  assert.strictEqual(getEl('metrics-text').textContent, '未授权 (403)');
  assert.strictEqual(timers.length, timersBefore, '4003 must not schedule reconnect');
  intervals[0].fn();
  assert.strictEqual(getEl('metrics-text').textContent, '未授权 (403)', 'Interval must not overwrite 403 metrics');

  console.log('NODE_VM_ALL_PASS');
})().catch((err) => { console.error(err); process.exit(1); });
"""

        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("node binary not available in PATH")

        with tempfile.TemporaryDirectory() as tmp:
            js_file = Path(tmp) / "inline.js"
            harness_file = Path(tmp) / "harness.js"
            js_file.write_text(js_src, encoding="utf-8")
            harness_file.write_text(harness, encoding="utf-8")
            proc = subprocess.run(
                [node_bin, str(harness_file), str(js_file)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(
                0,
                proc.returncode,
                f"Node VM behavioral test failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
            )
            self.assertIn("NODE_VM_ALL_PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
