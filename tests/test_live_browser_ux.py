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
from typing import Any
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
            hub.engine_mode = "async_hosted"
            hub.session_owner = ("main", 222)
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
            hub.session_owner = ("main", 111)
            broadcasts: list[dict] = []
            hub.broadcast_json_to_owners = mock.AsyncMock(side_effect=lambda obj, **_kw: broadcasts.append(obj))  # type: ignore[method-assign]

            # 1. No viewers and not takeover -> auto-dismisses immediately (no deadlock!)
            dlg_bg = _FakeDialog("alert", "Background alert")
            await hub._handle_page_dialog(dlg_bg)
            self.assertEqual(1, dlg_bg.dismissed)
            self.assertEqual(0, len(hub.pending_dialogs))

            # 2. Takeover active -> holds dialog, broadcasts dialog_open to owner, resolves on prompt accept
            hub.takeover = True
            hub.takeover_owner = ("main", 111)
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
                hub.session_owner = ("main", 111)
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
                    hub.session_owner = ("main", 111)
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

            with mock.patch.object(srv, "_check_live_user_role", return_value="admin"):
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

            with (
                mock.patch.object(srv, "DIALOG_TIMEOUT_SECONDS", 0.02),
                mock.patch.object(
                    srv,
                    "load_bot_credentials",
                    return_value=({"main": "100001:EXAMPLE_TOK_1234567"}, {}, {111}),
                ),
            ):
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
            with mock.patch.object(
                srv,
                "load_bot_credentials",
                return_value=({"main": "100001:EXAMPLE_TOK_1234567"}, {}, {111}),
            ):
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
            # P2-01: Closed tab p2 MUST be evicted, active_tab_index clamped to 0, title updated to surviving tab, dirty preserved!
            self.assertEqual("Shrunk", hub.title)
            self.assertEqual(1, len(hub.tabs))
            self.assertEqual(0, hub.active_tab_index)
            self.assertTrue(hub.tabs[0]["active"])
            self.assertTrue(hub._tabs_dirty)

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
                with mock.patch.object(srv, "_BRIDGE_DIR", bdir):
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
                hub.session_owner = ("main", 111)
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
                    # Foreign bot card cannot be created for main:111's session; inject stale foreign card entry to verify isolation
                    self.assertIsNone(await hub.tg.ensure_card("sg", preferred_user_id=222))
                    hub.tg.cards[("sg", 222)] = {
                        "bot_key": "sg",
                        "chat_id": 222,
                        "message_id": 802,
                        "session_gen": 3,
                        "last_sha1": "",
                        "last_caption": "",
                        "last_markup": "",
                        "last_ts": 0.0,
                    }
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
      clearRect: (...args) => {
        sandbox.__clearCount++;
        sandbox.__lastClearArgs = args;
      },
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
  __clearCount: 0,
  __lastClearArgs: null,
  __lastDrawArgs: null,
  __revokedUrls: [],
  __bmpClosed: 0,
  __fetchCalls: [],
  FormData: class FakeFormData { constructor() { this.fields = []; } append(k, v, n) { this.fields.push([k, v, n]); } },
  fetch: async (url, opts) => {
    sandbox.__fetchCalls.push({ url, opts });
    if (sandbox.__fetchHook) return sandbox.__fetchHook(url, opts);
    return { ok: true, status: 200, json: async () => ({ ok: true }), blob: async () => new FakeBlob('dl') };
  },
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

  // 7. P2-02: Trackpad two-finger distinguishes pinch zoom vs scroll (requires paired moves)
  vm.runInContext("setGestureMode('trackpad'); resetZoom();", sandbox);
  stageEl.dispatch('pointerdown', { pointerId: 20, clientX: 200, clientY: 200, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerdown', { pointerId: 21, clientX: 300, clientY: 200, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 20, clientX: 150, clientY: 200, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 21, clientX: 350, clientY: 200, pointerType: 'touch', target: screenEl });
  assert(vm.runInContext("scale", sandbox) > 1.5, 'Trackpad symmetric pinch must zoom');
  stageEl.dispatch('pointerup', { pointerId: 21, clientX: 350, clientY: 200, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerup', { pointerId: 20, clientX: 150, clientY: 200, pointerType: 'touch', target: screenEl });

  // 8. P2-03: URL auto-takeover requires matching request-level takeover_ack (NOT global state!) and waits for barrier during ai_busy
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, session_gen: 7, takeover_gen: 1, takeover: false, ai_busy: true, vw: 1280, vh: 800 }) });
  sock1.sent.length = 0;
  getEl('url-input').value = 'example.org';
  vm.runInContext("submitUrl();", sandbox);
  assert.strictEqual(vm.runInContext("state.takeover", sandbox), false, 'Must not optimistically mutate state.takeover');
  assert.strictEqual(sock1.sent.length, 1, 'ai_busy must still send set_takeover to wait behind server barrier');
  assert.strictEqual(sock1.sent[0].type, 'set_takeover');
  const reqId1 = sock1.sent[0].req_id;
  assert(reqId1, 'set_takeover must carry req_id');
  // Unrelated global state takeover=true or mismatched req_id / wrong owner MUST NOT send goto!
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, session_gen: 7, takeover_gen: 2, takeover: true, ai_busy: false, vw: 1280, vh: 800 }) });
  sock1.onmessage({ data: JSON.stringify({ type: 'takeover_ack', req_id: 'other-req', ok: true, takeover: true, session_gen: 7, takeover_gen: 2, owner_bot: 'main', owner_uid: 111 }) });
  assert.strictEqual(sock1.sent.filter((m) => m.action === 'goto').length, 0, 'Global state or wrong req_id must never fire goto');
  // Matching req_id with ok:true & matching owner & gen fires goto with session_gen/takeover_gen!
  sock1.onmessage({ data: JSON.stringify({ type: 'takeover_ack', req_id: reqId1, ok: true, takeover: true, session_gen: 7, takeover_gen: 3, owner_bot: 'main', owner_uid: 111 }) });
  const gotoSent = sock1.sent.find((m) => m.action === 'goto');
  assert(gotoSent, 'Matching takeover_ack must fire goto');
  assert.strictEqual(gotoSent.url, 'https://example.org');
  assert.strictEqual(gotoSent.session_gen, 7);
  assert.strictEqual(gotoSent.takeover_gen, 3);

  // 8b. P1-02: Two-finger lift first finger + cancel second finger MUST NOT fire rightclick; clean 2-finger tap DOES
  vm.runInContext("setGestureMode('trackpad'); resetZoom();", sandbox);
  sock1.sent.length = 0;
  stageEl.dispatch('pointerdown', { pointerId: 30, clientX: 150, clientY: 150, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerdown', { pointerId: 31, clientX: 250, clientY: 150, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerup', { pointerId: 30, clientX: 150, clientY: 150, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointercancel', { pointerId: 31, clientX: 250, clientY: 150, pointerType: 'touch', target: screenEl });
  assert.strictEqual(sock1.sent.filter((m) => m.action === 'rightclick').length, 0, 'Lift 1st + cancel 2nd must never fire rightclick');
  // Clean two-finger tap fires rightclick only when BOTH lift cleanly
  stageEl.dispatch('pointerdown', { pointerId: 32, clientX: 150, clientY: 150, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerdown', { pointerId: 33, clientX: 250, clientY: 150, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerup', { pointerId: 32, clientX: 150, clientY: 150, pointerType: 'touch', target: screenEl });
  assert.strictEqual(sock1.sent.filter((m) => m.action === 'rightclick').length, 0, 'Must wait until second finger lifts');
  stageEl.dispatch('pointerup', { pointerId: 33, clientX: 250, clientY: 150, pointerType: 'touch', target: screenEl });
  assert.strictEqual(sock1.sent.filter((m) => m.action === 'rightclick').length, 1, 'Clean two-finger tap must fire rightclick');

  // 8c. P1-02: Late range_preview after pointercancel MUST be ignored (pill stays hidden)
  vm.runInContext("setGestureMode('extract'); lastPreviewSent = 0;", sandbox);
  sock1.sent.length = 0;
  stageEl.dispatch('pointerdown', { pointerId: 35, clientX: 100, clientY: 100, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 35, clientX: 180, clientY: 110, pointerType: 'touch', target: screenEl });
  const prevReq = sock1.sent.find((m) => m.type === 'extract' && m.mode === 'range_preview');
  assert(prevReq, 'Expected range_preview request');
  stageEl.dispatch('pointercancel', { pointerId: 35, clientX: 180, clientY: 110, pointerType: 'touch', target: screenEl });
  sock1.onmessage({ data: JSON.stringify({ type: 'selection_preview', text: 'stale text', extract_gen: prevReq.extract_gen }) });
  assert(getEl('live-sel-pill').classList.contains('hidden'), 'Stale range_preview after cancel must stay hidden');

  // 8d. P1-03: Dialog B arriving while editing Prompt A preserves user's prompt draft!
  sock1.onmessage({ data: JSON.stringify({ type: 'dialog_open', dialog_id: 'pa', dialog_type: 'prompt', message: 'Enter A', default_value: 'defaultA' }) });
  assert.strictEqual(getEl('dialog-prompt-input').value, 'defaultA');
  getEl('dialog-prompt-input').value = 'user-edited-draft';
  sock1.onmessage({ data: JSON.stringify({ type: 'dialog_open', dialog_id: 'pb', dialog_type: 'alert', message: 'Alert B' }) });
  assert.strictEqual(getEl('dialog-prompt-input').value, 'user-edited-draft', 'Dialog B must not clobber Prompt A draft');
  assert(getEl('dialog-type-label').textContent.includes('队列 +1'), 'Queue badge must update');
  vm.runInContext("closeDialogSheet();", sandbox);

  // 8e. P1-04: Download limit aligned to 50 MiB (26 MiB fetches, 51 MiB blocked without fetch)
  sandbox.__fetchCalls.length = 0;
  sock1.onmessage({ data: JSON.stringify({ type: 'download_ready', download_id: 'dl26', filename: 'big.bin', size: 26 * 1024 * 1024, auto_sent: false }) });
  await vm.runInContext("downloadLatestFile();", sandbox);
  assert.strictEqual(sandbox.__fetchCalls.length, 1, '26 MiB file must proceed to authenticated /api/download fetch');
  assert(sandbox.__fetchCalls[0].url.includes('/api/download/dl26'));
  sandbox.__fetchCalls.length = 0;
  sock1.onmessage({ data: JSON.stringify({ type: 'download_ready', download_id: 'dl51', filename: 'too_big.bin', size: 51 * 1024 * 1024, auto_sent: false }) });
  await vm.runInContext("downloadLatestFile();", sandbox);
  assert.strictEqual(sandbox.__fetchCalls.length, 0, '51 MiB file must be blocked before fetch');

  // 8f. P2-02: Symmetric pinch with alternating single-pointer updates MUST lock pinch (NOT scroll/wheel)!
  vm.runInContext("setGestureMode('trackpad'); resetZoom();", sandbox);
  sock1.sent.length = 0;
  stageEl.dispatch('pointerdown', { pointerId: 40, clientX: 150, clientY: 150, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerdown', { pointerId: 41, clientX: 250, clientY: 150, pointerType: 'touch', target: screenEl });
  // Alternate single-pointer diagonal outward steps that previously triggered midDelta > 8 before distDelta > 14
  stageEl.dispatch('pointermove', { pointerId: 40, clientX: 137, clientY: 140, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 41, clientX: 263, clientY: 160, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 40, clientX: 110, clientY: 130, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 41, clientX: 290, clientY: 170, pointerType: 'touch', target: screenEl });
  assert(vm.runInContext("scale", sandbox) > 1.3, 'Symmetric alternating pinch must zoom');
  assert.strictEqual(sock1.sent.filter((m) => m.action === 'wheel').length, 0, 'Symmetric pinch must emit zero wheel events');
  stageEl.dispatch('pointerup', { pointerId: 40, clientX: 110, clientY: 130, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerup', { pointerId: 41, clientX: 290, clientY: 170, pointerType: 'touch', target: screenEl });

  // 8g. P2-04: Upload A completing after Chooser B opens MUST NOT hide Chooser B!
  let resolveUploadA;
  sandbox.__fetchHook = () => new Promise((res) => { resolveUploadA = res; });
  sock1.onmessage({ data: JSON.stringify({ type: 'filechooser_open', chooser_id: 'chA', multiple: false }) });
  getEl('file-upload-input').files = [{ name: 'a.txt', size: 10 }];
  const uploadAPromise = (async () => {
    const cbs = getEl('file-upload-input')._listeners['change'] || [];
    for (const fn of cbs) await fn();
  })();
  // Chooser B opens while Upload A is in flight
  sock1.onmessage({ data: JSON.stringify({ type: 'filechooser_open', chooser_id: 'chB', multiple: true }) });
  resolveUploadA({ ok: true, status: 200, json: async () => ({ ok: true }) });
  await uploadAPromise;
  sandbox.__fetchHook = null;
  assert.strictEqual(vm.runInContext("activeChooserId", sandbox), 'chB');
  assert(!getEl('upload-sheet').classList.contains('hidden'), 'Upload A completion must not hide Chooser B');

  // 8g. Round 4 P2-04: Upload 404 for current activeChooserId closes local panel; 404 for older chooser A MUST NOT hide newer chooser B!
  sock1.onmessage({ data: JSON.stringify({ type: 'filechooser_open', chooser_id: 'ch404', multiple: false }) });
  assert.strictEqual(vm.runInContext("activeChooserId", sandbox), 'ch404');
  assert(!getEl('upload-sheet').classList.contains('hidden'));
  sandbox.__fetchHook = async () => ({ ok: false, status: 404, json: async () => ({ ok: false, error: 'expired' }) });
  getEl('file-upload-input').files = [{ name: 'gone.txt', size: 12 }];
  getEl('file-upload-input').dispatch('change', {});
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
  assert.strictEqual(vm.runInContext("activeChooserId", sandbox), null, '404 for current chooser must clear activeChooserId');
  assert(getEl('upload-sheet').classList.contains('hidden'), '404 for current chooser must close upload sheet');

  let resolve404Old;
  sandbox.__fetchHook = () => new Promise((res) => { resolve404Old = res; });
  sock1.onmessage({ data: JSON.stringify({ type: 'filechooser_open', chooser_id: 'chOld', multiple: false }) });
  getEl('file-upload-input').files = [{ name: 'old.txt', size: 10 }];
  getEl('file-upload-input').dispatch('change', {});
  sock1.onmessage({ data: JSON.stringify({ type: 'filechooser_open', chooser_id: 'chNew', multiple: false }) });
  resolve404Old({ ok: false, status: 404, json: async () => ({ ok: false, error: 'expired' }) });
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
  sandbox.__fetchHook = null;
  assert.strictEqual(vm.runInContext("activeChooserId", sandbox), 'chNew', '404 for old chooser must NOT clear newer chooser B');
  assert(!getEl('upload-sheet').classList.contains('hidden'), '404 for old chooser must NOT hide newer chooser B');

  // 8h. Round 4 P2-02: Wide near-vertical symmetric pinch -> zooms with ZERO wheel; Fast parallel 2-finger scroll -> emits wheel with scale === 1.0!
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, session_gen: 7, takeover_gen: 3, takeover: true, vw: 1280, vh: 800 }) });
  vm.runInContext("setGestureMode('trackpad'); resetZoom(); lastWheelSent = 0;", sandbox);
  sock1.sent.length = 0;
  // Wide near-vertical symmetric pinch (fingers horizontally separated 240px, moving near-vertically in opposite directions, alternating updates!)
  stageEl.dispatch('pointerdown', { pointerId: 40, clientX: 100, clientY: 200, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerdown', { pointerId: 41, clientX: 340, clientY: 200, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 40, clientX: 98, clientY: 140, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 41, clientX: 342, clientY: 260, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 40, clientX: 95, clientY: 100, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 41, clientX: 345, clientY: 300, pointerType: 'touch', target: screenEl });
  assert(vm.runInContext("scale", sandbox) > 1.05, 'Wide near-vertical symmetric pinch must zoom');
  assert.strictEqual(sock1.sent.filter((m) => m.action === 'wheel').length, 0, 'Wide near-vertical symmetric pinch must emit 0 wheel');
  stageEl.dispatch('pointerup', { pointerId: 41, clientX: 345, clientY: 300, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerup', { pointerId: 40, clientX: 95, clientY: 100, pointerType: 'touch', target: screenEl });

  // Fast parallel 2-finger scroll (large first jump on pointer 1 BEFORE pointer 2 arrives!)
  vm.runInContext("setGestureMode('trackpad'); resetZoom(); lastWheelSent = 0;", sandbox);
  sock1.sent.length = 0;
  stageEl.dispatch('pointerdown', { pointerId: 42, clientX: 150, clientY: 260, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerdown', { pointerId: 43, clientX: 220, clientY: 260, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 42, clientX: 150, clientY: 180, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 43, clientX: 220, clientY: 182, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 42, clientX: 150, clientY: 120, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 43, clientX: 220, clientY: 122, pointerType: 'touch', target: screenEl });
  assert.strictEqual(vm.runInContext("scale", sandbox), 1.0, 'Fast parallel 2-finger scroll must NOT zoom');
  assert(sock1.sent.filter((m) => m.action === 'wheel').length >= 1, 'Fast parallel 2-finger scroll must emit wheel');
  stageEl.dispatch('pointerup', { pointerId: 43, clientX: 220, clientY: 122, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerup', { pointerId: 42, clientX: 150, clientY: 120, pointerType: 'touch', target: screenEl });

  // 8i. Round 4 P2-03 + P0-01: Latest URL submit (even when takeover flips true first) invalidates old pending URL ACK, and set_takeover carries session_gen!
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, session_gen: 7, takeover_gen: 3, takeover: false, ai_busy: false, vw: 1280, vh: 800 }) });
  sock1.sent.length = 0;
  getEl('url-input').value = 'old-intent.example';
  vm.runInContext("submitUrl();", sandbox);
  assert.strictEqual(sock1.sent.length, 1);
  assert.strictEqual(sock1.sent[0].type, 'set_takeover');
  assert.strictEqual(sock1.sent[0].session_gen, 7, 'submitUrl set_takeover must include session_gen');
  const oldUrlReqId = sock1.sent[0].req_id;
  // Takeover becomes true via global state BEFORE oldUrlReqId ACK arrives, and user submits newer URL directly!
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, session_gen: 7, takeover_gen: 4, takeover: true, ai_busy: false, vw: 1280, vh: 800 }) });
  getEl('url-input').value = 'new-intent.example';
  vm.runInContext("submitUrl();", sandbox);
  // Late ACK for oldUrlReqId arrives now -> MUST be ignored (NEVER send goto old-intent.example!)
  sock1.onmessage({ data: JSON.stringify({ type: 'takeover_ack', req_id: oldUrlReqId, ok: true, takeover: true, session_gen: 7, takeover_gen: 4, owner_bot: 'main', owner_uid: 111 }) });
  const allGotos = sock1.sent.filter((m) => m.action === 'goto').map((m) => m.url);
  assert.deepStrictEqual(allGotos, ['https://new-intent.example'], 'Late ACK must NEVER replay superseded old URL');
  // toggleTakeover() must also include BOTH session_gen & takeover_gen
  sock1.sent.length = 0;
  vm.runInContext("toggleTakeover();", sandbox);
  const tkToggleMsg = sock1.sent.find((m) => m.type === 'set_takeover');
  assert(tkToggleMsg && tkToggleMsg.session_gen === 7 && tkToggleMsg.takeover_gen === 4, 'toggleTakeover must include both session_gen and takeover_gen');

  // 8j. Round 5 P2-02: Staggered same-direction two-finger pan MUST lock 'scroll' & emit wheel (NEVER pinch!)
  vm.runInContext("scale = 1.0; panX = 0; panY = 0; setGestureMode('trackpad');", sandbox);
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, session_gen: 8, takeover_gen: 10, takeover: true, ai_busy: false, vw: 1280, vh: 800 }) });
  sock1.sent.length = 0;
  // Two vertically stacked fingers; finger 50 moves 30px down first, then finger 51 moves 5px down (staggered same-direction pan)
  stageEl.dispatch('pointerdown', { pointerId: 50, clientX: 200, clientY: 160, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerdown', { pointerId: 51, clientX: 200, clientY: 220, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 50, clientX: 200, clientY: 190, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointermove', { pointerId: 51, clientX: 200, clientY: 225, pointerType: 'touch', target: screenEl });
  assert.strictEqual(vm.runInContext("twoFingerTrackpad && twoFingerTrackpad.mode", sandbox), 'scroll', 'Staggered same-direction pan must lock scroll, not pinch');
  assert.strictEqual(vm.runInContext("scale", sandbox), 1, 'Staggered same-direction pan must keep scale at 1x');
  assert(sock1.sent.some((m) => m.action === 'wheel'), 'Staggered same-direction pan must emit wheel');
  stageEl.dispatch('pointerup', { pointerId: 51, clientX: 200, clientY: 225, pointerType: 'touch', target: screenEl });
  stageEl.dispatch('pointerup', { pointerId: 50, clientX: 200, clientY: 190, pointerType: 'touch', target: screenEl });

  // 8k. Round 5 P2-03 + P0-01: Delayed ACK after same-session handback must NEVER roll back takeover state or emit old goto; extract carries both gens!
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, session_gen: 8, takeover_gen: 10, takeover: false, ai_busy: false, vw: 1280, vh: 800 }) });
  sock1.sent.length = 0;
  getEl('url-input').value = 'pending-before-handback.example';
  vm.runInContext("submitUrl();", sandbox);
  assert.strictEqual(sock1.sent.length, 1);
  assert.strictEqual(sock1.sent[0].type, 'set_takeover');
  assert.strictEqual(sock1.sent[0].session_gen, 8);
  assert.strictEqual(sock1.sent[0].takeover_gen, 10);
  const handbackReqId = sock1.sent[0].req_id;
  // Server advances takeover_gen to 12 via handback (`takeover: false`) in SAME session_gen=8!
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, session_gen: 8, takeover_gen: 12, takeover: false, ai_busy: false, vw: 1280, vh: 800 }) });
  // Now delayed ACK from takeover_gen=11 arrives for handbackReqId -> MUST be dropped!
  sock1.sent.length = 0;
  sock1.onmessage({ data: JSON.stringify({ type: 'takeover_ack', req_id: handbackReqId, ok: true, takeover: true, session_gen: 8, takeover_gen: 11, owner_bot: 'main', owner_uid: 111 }) });
  assert.strictEqual(vm.runInContext("state.takeover", sandbox), false, 'Delayed ACK must NOT roll back state.takeover');
  assert.strictEqual(vm.runInContext("state.takeover_gen", sandbox), 12, 'Delayed ACK must NOT roll back state.takeover_gen');
  assert.strictEqual(sock1.sent.filter((m) => m.action === 'goto').length, 0, 'Delayed ACK must NOT emit old goto');
  // Even if a pendingUrlGoto existed and state.takeover_gen was already ahead, older takeover_gen ACK is rejected directly
  vm.runInContext("pendingUrlGoto = { url: 'https://stale.example', reqId: 'r-stale-tgen', sessionGen: 8, takeoverGen: 10 };", sandbox);
  sock1.onmessage({ data: JSON.stringify({ type: 'takeover_ack', req_id: 'r-stale-tgen', ok: true, takeover: true, session_gen: 8, takeover_gen: 11, owner_bot: 'main', owner_uid: 111 }) });
  assert.strictEqual(vm.runInContext("state.takeover", sandbox), false);
  assert.strictEqual(vm.runInContext("state.takeover_gen", sandbox), 12);
  assert.strictEqual(sock1.sent.filter((m) => m.action === 'goto').length, 0);
  // sendWsExtract must carry BOTH session_gen & takeover_gen
  sock1.sent.length = 0;
  vm.runInContext("requestExtract('url');", sandbox);
  const extDualMsg = sock1.sent.find((m) => m.type === 'extract');
  assert(extDualMsg && extDualMsg.session_gen === 8 && extDualMsg.takeover_gen === 12, 'extract must send both session_gen and takeover_gen');
  // Restore state for downstream tests
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, session_gen: 7, takeover_gen: 4, takeover: true, ai_busy: false, vw: 1280, vh: 800 }) });

  // 9. P2-03 & P3: bmp.close() always runs on draw exception + Image fallback revokes URL + stale connGen/frameRenderGen dropped + FPS counts drawImage
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

  // In-flight bitmap blocked & canvas cleared when same socket changes session_gen!
  let resolveSlowBmp;
  sandbox.createImageBitmap = () => new Promise((res) => { resolveSlowBmp = res; });
  const clearBeforeGen = sandbox.__clearCount;
  const drawsBeforeGen = sandbox.__drawCount;
  const bmpClosedBefore = sandbox.__bmpClosed;
  const inflightP = vm.runInContext(`decodeAndDrawBlob(new Blob('old-gen'), wsConnGen, frameRenderGen)`, sandbox);
  sock1.onmessage({ data: JSON.stringify({ type: 'state', running: true, session_gen: 8, takeover: false, vw: 1280, vh: 800 }) });
  assert(sandbox.__clearCount > clearBeforeGen, 'Same-socket session_gen change must clear canvas');
  resolveSlowBmp({ width: 1280, height: 800, close() { sandbox.__bmpClosed++; } });
  await inflightP;
  assert.strictEqual(sandbox.__drawCount, drawsBeforeGen, 'In-flight bitmap from prior session_gen must not draw');
  assert.strictEqual(sandbox.__bmpClosed, bmpClosedBefore + 1, 'Dropped in-flight bitmap must still close()');

  // 10. P2-03 & P3: Ordinary disconnect clears canvas, drops in-flight bitmap, and periodic interval MUST NOT overwrite disconnected text!
  sandbox.createImageBitmap = () => new Promise((res) => { resolveSlowBmp = res; });
  const drawsBeforeClose = sandbox.__drawCount;
  const closeInflightP = vm.runInContext(`decodeAndDrawBlob(new Blob('pre-close'), wsConnGen, frameRenderGen)`, sandbox);
  sock1.readyState = FakeWS.CLOSED;
  sock1.onclose({ code: 1006 });
  resolveSlowBmp({ width: 1280, height: 800, close() { sandbox.__bmpClosed++; } });
  await closeInflightP;
  assert.strictEqual(sandbox.__drawCount, drawsBeforeClose, 'In-flight bitmap after onclose must not draw');
  assert.strictEqual(getEl('metrics-text').textContent, '连接已断开，重连中...');
  intervals[0].fn();
  assert.strictEqual(getEl('metrics-text').textContent, '连接已断开，重连中...', 'Periodic interval must NOT overwrite disconnected metrics with 实时');

  // 11. P2-03 & P3: WS close 4003 stops reconnect and keeps '未授权 (403)' across interval ticks
  vm.runInContext("connectWs();", sandbox);
  const sock2 = wsInstances[wsInstances.length - 1];
  sock2.onopen();
  const timersBefore = timers.length;
  sock2.onclose({ code: 4003 });
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


class TestRound2QABlockersAdversarialRegression(unittest.TestCase):
    """Deterministic adversarial regressions covering every Round 2 QA blocker (P0-01..P2-06)."""

    def test_p0_01_ws_read_isolation_live_revocation_client_gen_and_sync_extract_hardening(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOK_ABCDEF12345"
            tok_sg = "100002:EXAMPLE_SG_TOK_ABCDEF1234567"
            env_main = bdir / ".env"
            env_main.write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\n"
                "AGY_TG_ALLOWED_CHATS=111,112\n"
                "AGY_TG_ADMIN_USERS=111\n"
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
                hub.engine_mode = "async_hosted"
                hub.ctx = _FakeCtx([_FakePage("https://secret.example.com/inbox", "Private Inbox")])
                hub.session_gen = 4
                hub.takeover_gen = 2
                hub.takeover = True
                hub.session_owner = ("main", 111)
                hub.takeover_owner = ("main", 111)
                hub.url = "https://secret.example.com/inbox"
                hub.title = "Private Inbox"
                hub.tabs = [{"index": 0, "title": "Private Inbox", "url": hub.url, "active": True}]
                hub.latest_jpeg = b"SECRET_SESSION_JPEG"
                hub.latest_clip = {"text": "secret-clip-content"}

                fake_ws_type = types.SimpleNamespace(TEXT="TEXT", CLOSE="CLOSE")
                req = types.SimpleNamespace(app={"hub": hub}, remote="127.0.0.1")

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "WSMsgType", fake_ws_type),
                    mock.patch.object(srv, "web", _FakeWeb),
                ):
                    # 1. Cross-bot admin (sg:222) and same-bot non-owner readonly (main:112) receive redacted state & ZERO frames/clips!
                    for bad_init in (_signed_init_data(tok_sg, 222), _signed_init_data(tok_main, 112)):
                        ws_iso = _FakeWSViewer(
                            [
                                {"type": "auth", "initData": bad_init},
                                {"type": "extract", "mode": "url"},
                                {"type": "read_clipboard"},
                            ]
                        )
                        with mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ws_iso)):
                            await srv.handle_ws(req)  # type: ignore[arg-type]
                        self.assertEqual([], ws_iso.sent_bytes, "Isolated viewer must NEVER receive session JPEG")
                        st_msgs = [m for m in ws_iso.sent_json if m.get("type") == "state"]
                        self.assertTrue(st_msgs)
                        self.assertFalse(st_msgs[0]["running"])
                        self.assertTrue(st_msgs[0].get("session_restricted"))
                        self.assertEqual("", st_msgs[0]["url"])
                        self.assertEqual("", st_msgs[0]["title"])
                        self.assertEqual([], st_msgs[0]["tabs"])
                        self.assertFalse(any(m.get("type") == "clipboard" for m in ws_iso.sent_json))

                    # 2. Connected owner receives frames, then revocation immediately evicts with auth_error + 4003!
                    ws_owner = _FakeWSViewer()
                    hub.viewers.add(ws_owner)  # type: ignore[arg-type]
                    hub.viewer_meta[ws_owner] = {"bot_key": "main", "user_id": 111, "role": "admin"}
                    await hub.broadcast_frame(b"FRAME_BEFORE_REVOKE")
                    self.assertEqual([b"FRAME_BEFORE_REVOKE"], ws_owner.sent_bytes)

                    # Revoke user 111 in .env live
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\n"
                        "AGY_TG_ALLOWED_CHATS=112\n"
                        "AGY_TG_READONLY_USERS=112\n",
                        encoding="utf-8",
                    )
                    await hub.broadcast_frame(b"FRAME_AFTER_REVOKE")
                    self.assertEqual([b"FRAME_BEFORE_REVOKE"], ws_owner.sent_bytes)
                    self.assertTrue(ws_owner.closed)
                    self.assertEqual(srv.WS_CLOSE_AUTH_FORBIDDEN, ws_owner.close_code)
                    self.assertTrue(any(m.get("type") == "auth_error" for m in ws_owner.sent_json))
                    self.assertNotIn(ws_owner, hub.viewers)

                    # Restore user 111 as admin for client-gen & sync-extract checks
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\n"
                        "AGY_TG_ALLOWED_CHATS=111,112\n"
                        "AGY_TG_ADMIN_USERS=111\n"
                        "AGY_TG_READONLY_USERS=112\n",
                        encoding="utf-8",
                    )

                    # 3. Stale client-supplied session_gen / takeover_gen inputs are dropped (NOT overwritten with server gen!)
                    enqueued_inputs: list[dict] = []
                    orig_put = hub.input_queue.put

                    async def _spy_put(item: dict) -> None:
                        enqueued_inputs.append(dict(item))
                        await orig_put(item)

                    ws_stale_in = _FakeWSViewer(
                        [
                            {"type": "auth", "initData": _signed_init_data(tok_main, 111)},
                            {"type": "input", "action": "click", "x": 10, "y": 10, "session_gen": 3, "takeover_gen": 2},
                            {"type": "input", "action": "click", "x": 20, "y": 20, "session_gen": 4, "takeover_gen": 1},
                            {"type": "input", "action": "click", "x": 30, "y": 30, "session_gen": 4, "takeover_gen": 2},
                        ]
                    )
                    with (
                        mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ws_stale_in)),
                        mock.patch.object(hub.input_queue, "put", side_effect=_spy_put),
                    ):
                        await srv.handle_ws(req)  # type: ignore[arg-type]
                    self.assertEqual(1, len(enqueued_inputs))
                    self.assertEqual(30, enqueued_inputs[0]["x"])
                    self.assertEqual(4, enqueued_inputs[0]["_session_gen"])
                    self.assertEqual(2, enqueued_inputs[0]["_takeover_gen"])
                    # Also verify disconnect drained input_queue & bumped takeover_gen!
                    self.assertTrue(hub.input_queue.empty())
                    self.assertEqual(3, hub.takeover_gen)

                    # 4. Sync extract forwarding applies strict field whitelist (strips rogue fields, blocks unknown modes & missing session_gen/takeover_gen)
                    hub.engine_mode = "sync_external"
                    hub.takeover = False
                    hub.sync_cmd_queue.clear()
                    ext_tgen = hub.takeover_gen
                    ws_sync_ext = _FakeWSViewer(
                        [
                            {"type": "auth", "initData": _signed_init_data(tok_main, 111)},
                            {"type": "extract", "mode": "point", "x": 12, "y": 34},  # missing both gens -> dropped!
                            {"type": "extract", "mode": "point", "x": 12, "y": 34, "session_gen": 4},  # missing takeover_gen -> dropped!
                            {"type": "extract", "mode": "point", "x": 12, "y": 34, "session_gen": 4, "takeover_gen": ext_tgen, "evil": "rm -rf /", "action": "goto"},
                            {"type": "extract", "mode": "evil_mode", "x": 1, "y": 2, "session_gen": 4, "takeover_gen": ext_tgen},
                        ]
                    )
                    with mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ws_sync_ext)):
                        await srv.handle_ws(req)  # type: ignore[arg-type]
                    self.assertEqual(1, len(hub.sync_cmd_queue))
                    popped_ext = hub.pop_sync_cmds()
                    self.assertEqual(1, len(popped_ext))
                    self.assertTrue(bool(popped_ext[0].get("req_id")))
                    self.assertEqual(
                        {"action": "extract", "mode": "point", "session_gen": 4, "takeover_gen": ext_tgen, "x": 12.0, "y": 34.0},
                        {k: v for k, v in popped_ext[0].items() if k != "req_id"},
                    )

                    # 5. Live browser ctl Sync extract masks password inputs
                    ctl_src = (REPO_ROOT / ".agents/skills/live-browser/scripts/live_browser_ctl.py").read_text(encoding="utf-8")
                    self.assertIn("tp === 'password'", ctl_src)
                    self.assertIn("isSensitive", ctl_src)

                    # 6. Upload commit second check re-verifies live role (mid-upload downgrade to readonly -> 403!)
                    hub.engine_mode = "async_hosted"
                    chooser = _FakeFileChooser(multiple=False)
                    await hub._handle_page_filechooser(chooser)
                    cid = next(iter(hub.pending_filechoosers.keys()))

                    class _DowngradingReader:
                        def __init__(self) -> None:
                            self._parts = [_FakeMultipartPart("files", b"abc", "a.txt")]

                        async def next(self):
                            if self._parts:
                                p = self._parts.pop(0)
                                # Downgrade user 111 -> readonly BEFORE commit!
                                env_main.write_text(
                                    f"AGY_TG_BOT_TOKEN={tok_main}\n"
                                    "AGY_TG_ALLOWED_CHATS=111,112\n"
                                    "AGY_TG_READONLY_USERS=111,112\n",
                                    encoding="utf-8",
                                )
                                return p
                            return None

                    r_down = await srv.handle_api_upload(
                        types.SimpleNamespace(
                            headers={"X-TG-Init-Data": _signed_init_data(tok_main, 111), "X-Chooser-Id": cid},
                            query={},
                            app={"hub": hub},
                            multipart=mock.AsyncMock(return_value=_DowngradingReader()),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(403, r_down.status)
                    self.assertIsNone(chooser.received_files)
                    hub._cleanup_transfer_dir(force_all=True)

            asyncio.run(_scenario())

    def test_p0_02_card_owner_binding_fail_closed_bot_resolve_and_late_screenshot_drop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOK_ABCDEF12345"
            tok_sg = "100002:EXAMPLE_SG_TOK_ABCDEF1234567"
            (bdir / ".env").write_text(f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111,113\n", encoding="utf-8")
            (bdir / ".env.sg").write_text(f"AGY_TG_BOT_TOKEN={tok_sg}\nAGY_TG_ALLOWED_CHATS=222\n", encoding="utf-8")

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
                hub.engine_mode = "async_hosted"
                hub.session_gen = 2
                hub.session_owner = ("main", 111)
                hub.latest_jpeg = b"MAIN_OWNER_FRAME"
                posts: list[str] = []

                class _FakeHttp:
                    def post(self, url: str, **_kw):
                        posts.append(url)
                        return _FakeHTTPResp({"ok": True, "result": {"message_id": 501}})

                hub.tg.http = _FakeHttp()

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "FormData", _FakeFormData),
                ):
                    # 1. Fail-closed resolve_bot_key in multi-bot environment
                    self.assertIsNone(hub.resolve_bot_key(None))
                    self.assertIsNone(hub.resolve_bot_key("unknown_bot"))
                    self.assertEqual("main", hub.resolve_bot_key("main"))

                    # 2. ensure_card blocks cross-bot (sg:222) and same-bot non-owner (main:113)
                    self.assertIsNone(await hub.tg.ensure_card("sg", preferred_user_id=222))
                    self.assertIsNone(await hub.tg.ensure_card("main", preferred_user_id=113))
                    self.assertEqual([], posts)

                    # Owner (main:111) succeeds
                    card = await hub.tg.ensure_card("main", preferred_user_id=111)
                    self.assertIsNotNone(card)
                    self.assertEqual(1, len(posts))

                    # 3. Late screenshot returning after stop_hosted() MUST NOT backfill idle cache!
                    shot_started = asyncio.Event()
                    release_shot = asyncio.Event()

                    class _SlowShotPage(_FakePage):
                        async def screenshot(self, **_kw) -> bytes:
                            shot_started.set()
                            await release_shot.wait()
                            return b"STALE_LATE_JPEG"

                    hub.ctx = _FakeCtx([_SlowShotPage()])
                    cap_task = asyncio.create_task(hub._capture_once(force_broadcast=True))
                    await asyncio.wait_for(shot_started.wait(), timeout=1.0)
                    await hub.stop_hosted(notify_finished=False)
                    self.assertEqual("idle", hub.engine_mode)
                    self.assertIsNone(hub.latest_jpeg)
                    release_shot.set()
                    cap_ok = await cap_task
                    self.assertFalse(cap_ok)
                    self.assertIsNone(hub.latest_jpeg, "Late screenshot must never backfill idle latest_jpeg!")

            asyncio.run(_scenario())

    def test_p1_01_concurrent_takeover_handoff_disconnect_inflight_mousedown_and_sync_gen(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "tok")
            hub.engine_mode = "async_hosted"
            hub.session_gen = 1
            hub.session_owner = ("main", 111)

            up_entered = asyncio.Event()
            release_up = asyncio.Event()
            move_entered = asyncio.Event()
            release_move = asyncio.Event()

            class _SlowMouse:
                def __init__(self) -> None:
                    self.events: list[tuple] = []

                async def move(self, x: float, y: float) -> None:
                    self.events.append(("move", x, y))
                    if x == 77.0:
                        move_entered.set()
                        await release_move.wait()

                async def down(self, button: str = "left") -> None:
                    self.events.append(("down", button))

                async def up(self, button: str = "left") -> None:
                    self.events.append(("up", button))
                    up_entered.set()
                    await release_up.wait()

            page = _FakePage()
            page.mouse = _SlowMouse()  # type: ignore[assignment]
            hub.ctx = _FakeCtx([page])

            # 1. Overlapping set_takeover(False) (suspended in mouse.up) + set_takeover(True) stays atomic!
            await hub.set_takeover(True, "start", owner=("main", 111))
            hub._mouse_buttons_down.add("left")
            t_off = asyncio.create_task(hub.set_takeover(False))
            await asyncio.wait_for(up_entered.wait(), timeout=1.0)
            t_on = asyncio.create_task(hub.set_takeover(True, "reacquire", owner=("main", 111)))
            await asyncio.sleep(0.02)
            release_up.set()
            await asyncio.gather(t_off, t_on)
            self.assertTrue(hub.takeover)
            self.assertFalse(hub.ai_allowed_event.is_set(), "takeover=True must NEVER coexist with ai_allowed_event=True")

            # 2. Suspended mouse.move during mousedown + takeover_gen bump (disconnect) skips mouse.down!
            page.mouse.events.clear()
            tgen_before = hub.takeover_gen
            md_task = asyncio.create_task(
                hub._execute_human_cmd_async(
                    {
                        "action": "mousedown",
                        "x": 77.0,
                        "y": 88.0,
                        "button": "left",
                        "_session_gen": hub.session_gen,
                        "_takeover_gen": tgen_before,
                    }
                )
            )
            await asyncio.wait_for(move_entered.wait(), timeout=1.0)
            # Simulate disconnect invalidating takeover_gen BEFORE mouse.move finishes
            hub.takeover_gen += 1
            release_move.set()
            await md_task
            self.assertEqual([("move", 77.0, 88.0)], page.mouse.events, "mouse.down MUST NOT run after takeover_gen bumped")
            self.assertEqual(set(), hub._mouse_buttons_down)

            # 3. Sync pop_sync_cmds & SyncLiveBridge enforce takeover_gen end-to-end
            hub.engine_mode = "sync_external"
            hub.session_gen = 5
            hub.takeover = True
            hub.takeover_gen = 10
            hub.sync_cmd_queue = [
                {"action": "click", "x": 1, "y": 1, "session_gen": 5, "takeover_gen": 9},
                {"action": "click", "x": 2, "y": 2, "session_gen": 5, "takeover_gen": 10},
            ]
            popped = hub.pop_sync_cmds()
            self.assertEqual(1, len(popped))
            self.assertEqual(2, popped[0]["x"])
            self.assertEqual(10, popped[0]["takeover_gen"])

            # Client-side SyncLiveBridge also rejects mismatched takeover_gen commands
            import live_browser_ctl as ctl

            class _FakeSyncPage:
                url = "https://example.com"
                viewport_size = {"width": 1280, "height": 800}
                def __init__(self) -> None:
                    self.mouse = types.SimpleNamespace(click=mock.Mock(), up=mock.Mock(), move=mock.Mock(), down=mock.Mock())
                def screenshot(self, **_kw) -> bytes: return b"JPEG"
                def title(self) -> str: return "T"

            sp = _FakeSyncPage()
            bridge = ctl.SyncLiveBridge.__new__(ctl.SyncLiveBridge)
            bridge.raw_ctx = types.SimpleNamespace(pages=[sp])
            bridge.enabled = True
            bridge.notify = False
            bridge.active_idx = 0
            bridge._in_checkpoint = False
            bridge._held_buttons = set()
            bridge._sync_lease_id = "lease-1"
            bridge._sync_session_gen = 5
            bridge._x11_display = None
            bridge._last_clip = ""
            bridge.client = types.SimpleNamespace(
                bot="main",
                base_url="http://127.0.0.1:18795",
                _headers=lambda: {"X-Live-Token": "tok"},
                session=types.SimpleNamespace(
                    post=lambda *_a, **_kw: types.SimpleNamespace(
                        status_code=200,
                        json=lambda: {
                            "ok": True,
                            "session_gen": 5,
                            "takeover": True,
                            "takeover_gen": 11,
                            "commands": [
                                {"action": "click", "x": 10, "y": 10, "session_gen": 5, "takeover_gen": 10},
                            ],
                        },
                    )
                ),
            )
            bridge.sync_checkpoint(ai_status="chk", allow_takeover_loop=False)
            sp.mouse.click.assert_not_called()

        asyncio.run(_scenario())

    def test_p1_04_upload_nonfile_budget_framing_sem_release_and_download_write_cap(self) -> None:
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
                chooser = _FakeFileChooser(multiple=False)
                await hub._handle_page_filechooser(chooser)
                cid = next(iter(hub.pending_filechoosers.keys()))

                # 1. Combined non-file total budget (4 B cap): two 3 B non-file fields -> 413!
                with mock.patch.object(srv, "MAX_UPLOAD_NONFILE_TOTAL_BYTES", 4):
                    r_nf = await srv.handle_api_upload(
                        types.SimpleNamespace(
                            headers={"X-TG-Init-Data": valid_init, "X-Chooser-Id": cid},
                            query={},
                            app={"hub": hub},
                            multipart=mock.AsyncMock(
                                return_value=_FakeMultipartReader(
                                    [
                                        _FakeMultipartPart("f1", b"aaa"),
                                        _FakeMultipartPart("f2", b"bbb"),
                                        _FakeMultipartPart("files", b"ok", "x.txt"),
                                    ]
                                )
                            ),
                        )  # type: ignore[arg-type]
                    )
                self.assertEqual(413, r_nf.status)

                # 2. Unknown Content-Length framing overhead counts toward MAX_UPLOAD_TOTAL_BYTES -> 413!
                with mock.patch.object(srv, "MAX_UPLOAD_TOTAL_BYTES", 50):
                    r_fr = await srv.handle_api_upload(
                        types.SimpleNamespace(
                            headers={"X-TG-Init-Data": valid_init, "X-Chooser-Id": cid},
                            query={},
                            app={"hub": hub},
                            multipart=mock.AsyncMock(
                                return_value=_FakeMultipartReader(
                                    [_FakeMultipartPart("files", b"x", "a.txt")]
                                )
                            ),
                        )  # type: ignore[arg-type]
                    )
                self.assertEqual(413, r_fr.status)

                # 3. I/O failure during staging setup STILL releases _upload_sem (no permit leak!)
                before_permits = hub._upload_sem._value
                with mock.patch.object(hub, "_ensure_transfer_dir", side_effect=OSError("disk full")):
                    r_io = await srv.handle_api_upload(
                        types.SimpleNamespace(
                            headers={"X-TG-Init-Data": valid_init, "X-Chooser-Id": cid},
                            query={},
                            app={"hub": hub},
                            multipart=mock.AsyncMock(),
                        )  # type: ignore[arg-type]
                    )
                self.assertEqual(400, r_io.status)
                self.assertEqual(before_permits, hub._upload_sem._value, "Semaphore permit leaked on staging OSError!")

                # 4. Hanging oversized download (> MAX_DOWNLOAD_BYTES) is cancelled live & purged with zero leftovers
                cancel_called = False

                class _HangingOversizedDownload:
                    suggested_filename = "overflow.bin"

                    async def cancel(self) -> None:
                        nonlocal cancel_called
                        cancel_called = True

                    async def save_as(self, path: str) -> None:
                        Path(path).write_bytes(b"ABCDEFGHIJ")  # 10 B > 8 B
                        await asyncio.sleep(5.0)

                with mock.patch.object(srv, "MAX_DOWNLOAD_BYTES", 8):
                    await asyncio.wait_for(
                        hub._handle_page_download(_HangingOversizedDownload(), session_gen=1, owner_bot="main", owner_uid=111),
                        timeout=1.5,
                    )
                self.assertTrue(cancel_called, "Live download watcher must cancel oversized in-flight save_as")
                self.assertEqual(0, len(hub.downloads))
                if hub._transfer_dir and hub._transfer_dir.is_dir():
                    self.assertEqual([], list(hub._transfer_dir.iterdir()))

                hub._cleanup_transfer_dir(force_all=True)

        asyncio.run(_scenario())

    def test_p2_04_p2_05_p2_06_chooser_closed_sync_lease_and_card_precheck(self) -> None:
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
                hub.session_owner = ("main", 111)
                hub.latest_jpeg = b"FRAME"

                ws_owner = _FakeWSViewer()
                hub.viewers.add(ws_owner)  # type: ignore[arg-type]
                hub.viewer_meta[ws_owner] = {"bot_key": "main", "user_id": 111, "role": "admin"}

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "web", _FakeWeb),
                    mock.patch.object(srv, "FormData", _FakeFormData),
                ):
                    # P2-04: Expired chooser hit in handle_api_upload returns 404 AND broadcasts filechooser_closed
                    chooser = _FakeFileChooser(multiple=False)
                    await hub._handle_page_filechooser(chooser)
                    cid = next(iter(hub.pending_filechoosers.keys()))
                    hub.pending_filechoosers[cid]["created_ts"] = time.monotonic() - (srv.TRANSFER_TTL_SECONDS + 10.0)
                    ws_owner.sent_json.clear()
                    r_exp = await srv.handle_api_upload(
                        types.SimpleNamespace(
                            headers={"X-TG-Init-Data": _signed_init_data(tok_main, 111), "X-Chooser-Id": cid},
                            query={},
                            app={"hub": hub},
                            multipart=mock.AsyncMock(),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(404, r_exp.status)
                    self.assertTrue(
                        any(m.get("type") == "filechooser_closed" and m.get("chooser_id") == cid for m in ws_owner.sent_json)
                    )

                    # P2-06: Stale message_id / wrong owner card_refresh MUST return 403 BEFORE _capture_once runs!
                    hub.tg.http = types.SimpleNamespace(
                        post=lambda *_a, **_kw: _FakeHTTPResp({"ok": True, "result": {"message_id": 900}})
                    )
                    await hub.tg.ensure_card("main", preferred_user_id=111)
                    cap_spy = mock.AsyncMock(return_value=True)
                    with mock.patch.object(hub, "_capture_once", cap_spy):
                        r_old_mid = await srv.internal_config(
                            types.SimpleNamespace(
                                headers={"X-Live-Token": "sec-tok"},
                                remote="127.0.0.1",
                                app={"hub": hub},
                                json=mock.AsyncMock(
                                    return_value={"refresh_card": True, "bot": "main", "chat_id": 111, "message_id": 899}
                                ),
                            )  # type: ignore[arg-type]
                        )
                        self.assertEqual(403, r_old_mid.status)
                        cap_spy.assert_not_called()

                    # P2-06: Cross-owner card takeover / stop rejected with 403 without mutating session!
                    r_bad_tk = await srv.internal_takeover(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(
                                return_value={
                                    "active": True,
                                    "bot": "sg",
                                    "user_id": 222,
                                    "chat_id": 222,
                                    "message_id": 900,
                                    "from_card": True,
                                }
                            ),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(403, r_bad_tk.status)
                    self.assertFalse(hub.takeover)

                    r_bad_stop = await srv.internal_stop(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            read=mock.AsyncMock(
                                return_value=json.dumps(
                                    {"bot": "sg", "user_id": 222, "chat_id": 222, "message_id": 900, "from_card": True}
                                ).encode("utf-8")
                            ),
                            query={},
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(403, r_bad_stop.status)
                    self.assertEqual("async_hosted", hub.engine_mode)

                    # P2-05: Sync push while async_hosted returns 409 and MUST NOT overwrite engine_mode or ctx!
                    r_over = await srv.internal_sync_push(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={"lease_id": "fake"},
                            read=mock.AsyncMock(return_value=b"ROGUE_SYNC_JPEG"),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(409, r_over.status)
                    self.assertEqual("async_hosted", hub.engine_mode)
                    self.assertIsNotNone(hub.ctx)

                    # P2-05: Sync start issues lease_id; after lease expiry -> idle, late push returns 410 and NEVER revives!
                    r_start = await srv.internal_sync_start(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(return_value={"bot": "main", "user_id": 111}),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(200, r_start.status)
                    lease_id = r_start.data["sync_lease_id"]
                    sgen = r_start.data["session_gen"]
                    self.assertTrue(lease_id)

                    # Valid push succeeds
                    r_push_ok = await srv.internal_sync_push(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={"lease_id": lease_id, "session_gen": str(sgen), "url": "https://sync.example.com"},
                            read=mock.AsyncMock(return_value=b"SYNC_OK_JPEG"),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(200, r_push_ok.status)
                    self.assertEqual(b"SYNC_OK_JPEG", hub.latest_jpeg)

                    # Expire lease -> idle; late push with old lease_id rejected with 410 and latest_jpeg stays None!
                    hub._sync_last_push_ts = time.monotonic() - (srv.SYNC_LEASE_TIMEOUT_SECONDS + 5.0)
                    self.assertTrue(await hub._expire_sync_session_if_stale())
                    self.assertEqual("idle", hub.engine_mode)
                    self.assertIsNone(hub.latest_jpeg)

                    r_push_late = await srv.internal_sync_push(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={"lease_id": lease_id, "session_gen": str(sgen)},
                            read=mock.AsyncMock(return_value=b"ZOMBIE_JPEG"),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(410, r_push_late.status)
                    self.assertEqual("idle", hub.engine_mode)
                    self.assertIsNone(hub.latest_jpeg)

            asyncio.run(_scenario())


class TestRound4FinalClosureAdversarialRegression(unittest.TestCase):
    """Deterministic adversarial regressions for every Round 3 QA blocker closed in Round 4."""

    def test_p0_01_p0_02_unowned_denial_async_replay_broadcast_extract_missing_gen_and_exec_rbac(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOK_ABCDEF12345"
            env_main = bdir / ".env"
            env_main.write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\n"
                "AGY_TG_ALLOWED_CHATS=111,112\n"
                "AGY_TG_ADMIN_USERS=111,112\n",
                encoding="utf-8",
            )

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                hub.engine_mode = "async_hosted"
                hub.session_gen = 5
                hub.takeover = True
                hub.takeover_gen = 3
                hub.url = "https://private.example.com"
                hub.title = "Private"
                hub.latest_jpeg = b"PRIVATE_FRAME"
                hub.latest_clip = {"text": "private-clip"}
                hub.ctx = _FakeCtx([_FakePage("https://private.example.com", "Private")])
                fake_ws_type = types.SimpleNamespace(TEXT="TEXT", CLOSE="CLOSE")
                req = types.SimpleNamespace(app={"hub": hub}, remote="127.0.0.1")

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "WSMsgType", fake_ws_type),
                    mock.patch.object(srv, "FormData", _FakeFormData),
                    mock.patch.object(srv, "web", _FakeWeb),
                ):
                    # 1. Unowned session (None or uid=None) MUST deny remote WS read/write & TG card creation (localhost CLI only)!
                    for unowned in (None, ("main", None)):
                        hub.session_owner = unowned
                        ws_admin = _FakeWSViewer(
                            [
                                {"type": "auth", "initData": _signed_init_data(tok_main, 111)},
                                {"type": "extract", "mode": "url", "session_gen": 5},
                                {"type": "set_takeover", "active": True, "session_gen": 5, "req_id": "r-unowned"},
                            ]
                        )
                        with mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ws_admin)):
                            await srv.handle_ws(req)  # type: ignore[arg-type]
                        self.assertEqual([], ws_admin.sent_bytes, f"Unowned {unowned} must NEVER expose frames remotely")
                        st = next(m for m in ws_admin.sent_json if m.get("type") == "state")
                        self.assertTrue(st.get("session_restricted"))
                        self.assertEqual("", st["url"])
                        self.assertFalse(any(m.get("type") == "clipboard" for m in ws_admin.sent_json))
                        ack = next((m for m in ws_admin.sent_json if m.get("type") == "takeover_ack"), None)
                        self.assertIsNotNone(ack)
                        assert ack is not None
                        self.assertFalse(ack["ok"])
                        self.assertIsNone(await hub.tg.ensure_card("main", preferred_user_id=111))

                    # 2. Initial WS replay re-verifies live auth & session_gen before EVERY await send!
                    hub.session_owner = ("main", 111)
                    hub.takeover_owner = ("main", 111)

                    class _RevokeOnAuthOkWS(_FakeWSViewer):
                        async def send_str(self, payload: str) -> None:
                            await super().send_str(payload)
                            msg = json.loads(payload)
                            if msg.get("type") == "auth_ok":
                                # Revoke user 111 immediately after auth_ok before state/jpeg/dialogs are sent!
                                env_main.write_text(
                                    f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=112\n",
                                    encoding="utf-8",
                                )

                    ws_rev_replay = _RevokeOnAuthOkWS([{"type": "auth", "initData": _signed_init_data(tok_main, 111)}])
                    with mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ws_rev_replay)):
                        await srv.handle_ws(req)  # type: ignore[arg-type]
                    self.assertEqual([], ws_rev_replay.sent_bytes, "Revoked mid-replay must NEVER get JPEG")
                    self.assertEqual(srv.WS_CLOSE_AUTH_FORBIDDEN, ws_rev_replay.close_code)
                    self.assertTrue(any(m.get("type") == "auth_error" for m in ws_rev_replay.sent_json))
                    self.assertFalse(any(m.get("type") == "state" for m in ws_rev_replay.sent_json))

                    # Restore user 111 as admin
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111,112\nAGY_TG_ADMIN_USERS=111,112\n",
                        encoding="utf-8",
                    )

                    # 3. Broadcast TOCTOU: session_gen changes during first viewer's send -> second viewer NEVER gets stale gen frame!
                    ws_v1 = _FakeWSViewer()
                    ws_v2 = _FakeWSViewer()

                    def _wrap_bump(v: _FakeWSViewer) -> None:
                        orig_send = v.send_bytes

                        async def _mutate_gen_mid_broadcast(data: bytes) -> None:
                            await orig_send(data)
                            hub.session_gen += 1

                        v.send_bytes = _mutate_gen_mid_broadcast  # type: ignore[method-assign]

                    _wrap_bump(ws_v1)
                    _wrap_bump(ws_v2)
                    hub.viewers = {ws_v1, ws_v2}  # type: ignore[assignment]
                    hub.viewer_meta = {
                        ws_v1: {"bot_key": "main", "user_id": 111, "role": "admin"},
                        ws_v2: {"bot_key": "main", "user_id": 111, "role": "admin"},
                    }
                    await hub.broadcast_frame(b"GEN_BOUND_FRAME")
                    self.assertEqual(1, len(ws_v1.sent_bytes) + len(ws_v2.sent_bytes))
                    hub.viewers.clear()
                    hub.viewer_meta.clear()

                    # 4. Hosted extract post-await dual-generation check: session_gen or takeover_gen advances -> dropped!
                    cur_g = hub.session_gen
                    cur_t = hub.takeover_gen
                    extract_called: list[str] = []

                    async def _slow_extract(_data: dict, **_kw) -> dict:
                        extract_called.append("sgen")
                        hub.session_gen += 1
                        return {"text": "LEAKED_OLD_GEN", "source": "point", "url": hub.url, "ts": time.time()}

                    ws_ext_stale = _FakeWSViewer(
                        [
                            {"type": "auth", "initData": _signed_init_data(tok_main, 111)},
                            {"type": "extract", "mode": "point", "x": 10, "y": 10, "session_gen": cur_g, "takeover_gen": cur_t},
                        ]
                    )
                    with (
                        mock.patch.object(hub, "extract_content_async", side_effect=_slow_extract),
                        mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ws_ext_stale)),
                    ):
                        await srv.handle_ws(req)  # type: ignore[arg-type]
                    self.assertEqual(["sgen"], extract_called, "Test must enter extract_content_async before post-await drop")
                    self.assertFalse(
                        any(m.get("type") == "clipboard" for m in ws_ext_stale.sent_json),
                        "Post-await stale-session_gen extract result MUST be dropped",
                    )

                    # Also verify post-await takeover_gen change drops hosted extract result!
                    cur_g2 = hub.session_gen
                    cur_t2 = hub.takeover_gen

                    async def _slow_extract_tgen(_data: dict, **_kw) -> dict:
                        extract_called.append("tgen")
                        hub.takeover_gen += 1
                        return {"text": "LEAKED_OLD_TGEN", "source": "point", "url": hub.url, "ts": time.time()}

                    ws_ext_stale_t = _FakeWSViewer(
                        [
                            {"type": "auth", "initData": _signed_init_data(tok_main, 111)},
                            {"type": "extract", "mode": "point", "x": 10, "y": 10, "session_gen": cur_g2, "takeover_gen": cur_t2},
                        ]
                    )
                    with (
                        mock.patch.object(hub, "extract_content_async", side_effect=_slow_extract_tgen),
                        mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ws_ext_stale_t)),
                    ):
                        await srv.handle_ws(req)  # type: ignore[arg-type]
                    self.assertEqual(["sgen", "tgen"], extract_called)
                    self.assertFalse(
                        any(m.get("type") == "clipboard" for m in ws_ext_stale_t.sent_json),
                        "Post-await stale-takeover_gen extract result MUST be dropped",
                    )

                    # 5. Missing session_gen / takeover_gen on remote WS input, set_takeover & extract MUST be rejected!
                    hub.takeover = True
                    hub.takeover_gen = 9
                    enq: list[dict] = []
                    with mock.patch.object(hub.input_queue, "put", side_effect=lambda x: enq.append(x)):
                        ws_missing_gen = _FakeWSViewer(
                            [
                                {"type": "auth", "initData": _signed_init_data(tok_main, 111)},
                                {"type": "input", "action": "click", "x": 1, "y": 1},  # missing both gens
                                {"type": "input", "action": "goto", "url": "https://a.example", "session_gen": hub.session_gen},  # missing takeover_gen
                                {"type": "set_takeover", "active": False, "req_id": "no-gen-tk"},  # missing session_gen
                            ]
                        )
                        with mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ws_missing_gen)):
                            await srv.handle_ws(req)  # type: ignore[arg-type]
                    self.assertEqual([], enq, "Inputs missing session_gen or takeover_gen must NEVER be auto-filled")
                    no_gen_ack = next(m for m in ws_missing_gen.sent_json if m.get("req_id") == "no-gen-tk")
                    self.assertFalse(no_gen_ack["ok"])

                    # 6. Execution-boundary live RBAC: downgrade user 111 -> readonly AFTER enqueue aborts click & releases takeover + buttons!
                    page = _FakePage()
                    hub.ctx = _FakeCtx([page])
                    hub.takeover = True
                    hub.takeover_owner = ("main", 111)
                    hub._mouse_buttons_down.add("left")
                    ws_live = _FakeWSViewer()
                    hub.viewers.add(ws_live)  # type: ignore[arg-type]
                    hub.viewer_meta[ws_live] = {"bot_key": "main", "user_id": 111, "role": "admin"}
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\n"
                        "AGY_TG_ALLOWED_CHATS=111\n"
                        "AGY_TG_READONLY_USERS=111\n",
                        encoding="utf-8",
                    )
                    await hub._execute_human_cmd_async(
                        {
                            "action": "click",
                            "x": 55,
                            "y": 66,
                            "_session_gen": hub.session_gen,
                            "_takeover_gen": hub.takeover_gen,
                            "_bot_key": "main",
                            "_user_id": 111,
                        }
                    )
                    self.assertFalse(any(ev[0] == "click" for ev in page.mouse.events))
                    self.assertIn(("up", "left"), page.mouse.events)
                    self.assertFalse(hub.takeover)

            asyncio.run(_scenario())

    def test_p0_02_p2_06_p1_01_card_orphan_retire_mandatory_mid_and_in_lock_takeover_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOK_ABCDEF12345"
            (bdir / ".env").write_text(f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\n", encoding="utf-8")

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                hub.engine_mode = "async_hosted"
                hub.ctx = _FakeCtx([_FakePage()])
                hub.session_gen = 10
                hub.session_owner = ("main", 111)
                hub.latest_jpeg = b"GEN10_JPEG"

                # 1. ensure_card: session switches gen DURING sendPhoto -> card NOT registered, orphan retired!
                http_calls: list[tuple[str, Any]] = []
                send_started = asyncio.Event()
                allow_send_return = asyncio.Event()

                class _SlowCardResp:
                    async def __aenter__(self):
                        send_started.set()
                        await allow_send_return.wait()
                        return self

                    async def __aexit__(self, *_a):
                        return None

                    async def json(self):
                        return {"ok": True, "result": {"message_id": 777}}

                class _FakeHttp:
                    def post(self, url: str, data=None, json=None):
                        http_calls.append((url, json if json is not None else data))
                        if "sendPhoto" in url:
                            return _SlowCardResp()
                        return _FakeHTTPResp({"ok": True})

                hub.tg.http = _FakeHttp()
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "FormData", _FakeFormData),
                    mock.patch.object(srv, "web", _FakeWeb),
                ):
                    card_task = asyncio.create_task(hub.tg.ensure_card("main", preferred_user_id=111))
                    await asyncio.wait_for(send_started.wait(), timeout=1.0)
                    # Session advances to gen=11 mid-sendPhoto!
                    hub.session_gen = 11
                    allow_send_return.set()
                    res_card = await card_task
                    self.assertIsNone(res_card, "Card created during old gen MUST NOT register into new gen")
                    self.assertEqual({}, hub.tg.cards)
                    self.assertTrue(
                        any("editMessageCaption" in u for u, _ in http_calls),
                        "Orphan card must be silently retired",
                    )

                    # 2. Telegram card callbacks missing message_id (or <= 0) MUST return 403!
                    hub.tg.cards[("main", 111)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 888,
                        "session_gen": 11,
                        "last_sha1": "",
                        "last_caption": "",
                        "last_markup": "",
                        "last_ts": 0.0,
                    }
                    for bad_mid in (None, 0, -5):
                        r_rf = await srv.internal_config(
                            types.SimpleNamespace(
                                headers={"X-Live-Token": "sec-tok"},
                                remote="127.0.0.1",
                                app={"hub": hub},
                                json=mock.AsyncMock(
                                    return_value={
                                        "refresh_card": True,
                                        "bot": "main",
                                        "chat_id": 111,
                                        "message_id": bad_mid,
                                        "source": "tg_card",
                                    }
                                ),
                            )  # type: ignore[arg-type]
                        )
                        self.assertEqual(403, r_rf.status)
                        r_tk = await srv.internal_takeover(
                            types.SimpleNamespace(
                                headers={"X-Live-Token": "sec-tok"},
                                remote="127.0.0.1",
                                app={"hub": hub},
                                json=mock.AsyncMock(
                                    return_value={
                                        "active": True,
                                        "bot": "main",
                                        "user_id": 111,
                                        "chat_id": 111,
                                        "message_id": bad_mid,
                                        "from_card": True,
                                    }
                                ),
                            )  # type: ignore[arg-type]
                        )
                        self.assertEqual(403, r_tk.status)

                    # 3. P1-01 + P2-06: set_takeover & internal_stop re-check expected_session_gen & card INSIDE lock!
                    async with hub._takeover_lock:
                        tk_waiter = asyncio.create_task(
                            hub.set_takeover(
                                True,
                                "stale-card-tk",
                                owner=("main", 111),
                                expected_session_gen=11,
                                actor=("main", 111),
                                card_message_id=888,
                                require_card=True,
                            )
                        )
                        await asyncio.sleep(0.01)
                        hub.session_gen = 12  # Advances BEFORE waiter enters lock!
                    ok_tk, _err_tk, _, _ = await tk_waiter
                    self.assertFalse(ok_tk, "set_takeover must reject stale expected_session_gen INSIDE _takeover_lock")
                    self.assertFalse(hub.takeover)

                    # Update card to gen=12, then hold _engine_lock while advancing gen=13 -> card stop must return 403!
                    hub.tg.cards[("main", 111)]["session_gen"] = 12
                    async with hub._engine_lock:
                        stop_waiter = asyncio.create_task(
                            srv.internal_stop(
                                types.SimpleNamespace(
                                    headers={"X-Live-Token": "sec-tok"},
                                    remote="127.0.0.1",
                                    app={"hub": hub},
                                    read=mock.AsyncMock(
                                        return_value=json.dumps(
                                            {
                                                "bot": "main",
                                                "user_id": 111,
                                                "chat_id": 111,
                                                "message_id": 888,
                                                "from_card": True,
                                            }
                                        ).encode("utf-8")
                                    ),
                                    query={},
                                )  # type: ignore[arg-type]
                            )
                        )
                        await asyncio.sleep(0.01)
                        hub.session_gen = 13
                    r_stop_stale = await stop_waiter
                    self.assertEqual(403, r_stop_stale.status)
                    self.assertEqual("async_hosted", hub.engine_mode)

            asyncio.run(_scenario())

    def test_p2_05_sync_post_read_lease_invalidate_first_client_release_buttons_and_extract_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp)
            tok_main = "100001:EXAMPLE_MAIN_TOK_ABCDEF12345"
            (bdir / ".env").write_text(f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\n", encoding="utf-8")

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                with mock.patch.object(srv, "_BRIDGE_DIR", bdir), mock.patch.object(srv, "web", _FakeWeb):
                    r_s1 = await srv.internal_sync_start(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(return_value={"bot": "main", "user_id": 111}),
                        )  # type: ignore[arg-type]
                    )
                    lease1 = r_s1.data["sync_lease_id"]
                    gen1 = r_s1.data["session_gen"]

                    # 1. In-flight push whose lease expires DURING await request.read() MUST NOT write latest_jpeg or metadata!
                    read_entered = asyncio.Event()
                    release_read = asyncio.Event()

                    async def _slow_read() -> bytes:
                        read_entered.set()
                        await release_read.wait()
                        return b"STALE_INFLIGHT_JPEG"

                    push_task = asyncio.create_task(
                        srv.internal_sync_push(
                            types.SimpleNamespace(
                                headers={"X-Live-Token": "sec-tok"},
                                remote="127.0.0.1",
                                app={"hub": hub},
                                query={"lease_id": lease1, "session_gen": str(gen1), "url": "https://stale.example"},
                                read=_slow_read,
                            )  # type: ignore[arg-type]
                        )
                    )
                    await asyncio.wait_for(read_entered.wait(), timeout=1.0)
                    # Stop sync session while push is mid-read; verify lease/mode invalidated BEFORE retire_cards awaits!
                    state_during_retire: list[tuple[str, Any]] = []

                    async def _spy_retire(**_kw) -> int:
                        state_during_retire.append((hub.engine_mode, hub._sync_lease_id))
                        return 0

                    with mock.patch.object(hub.tg, "retire_cards", side_effect=_spy_retire):
                        r_stop = await srv.internal_sync_stop(
                            types.SimpleNamespace(
                                headers={"X-Live-Token": "sec-tok", "X-Sync-Lease-Id": lease1},
                                remote="127.0.0.1",
                                app={"hub": hub},
                                query={},
                                read=mock.AsyncMock(return_value=b""),
                            )  # type: ignore[arg-type]
                        )
                    self.assertEqual(200, r_stop.status)
                    self.assertEqual([("idle", None)], state_during_retire, "Sync lease must invalidate BEFORE async retire_cards!")

                    release_read.set()
                    r_stale_push = await push_task
                    self.assertEqual(410, r_stale_push.status)
                    self.assertIsNone(hub.latest_jpeg)
                    self.assertEqual("", hub.url)

                    # 2. Clipboard requires matching lease_id (missing/wrong -> 409)
                    r_s2 = await srv.internal_sync_start(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(return_value={"bot": "main", "user_id": 111}),
                        )  # type: ignore[arg-type]
                    )
                    lease2 = r_s2.data["sync_lease_id"]
                    r_clip_bad = await srv.internal_sync_clipboard(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={},
                            json=mock.AsyncMock(return_value={"text": "hijack", "lease_id": lease1}),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(409, r_clip_bad.status)
                    self.assertEqual({}, hub.latest_clip)

                    r_clip_ok = await srv.internal_sync_clipboard(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok", "X-Sync-Lease-Id": lease2},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={},
                            json=mock.AsyncMock(return_value={"text": "legit"}),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(200, r_clip_ok.status)
                    self.assertEqual("legit", hub.latest_clip.get("text"))

            asyncio.run(_scenario())

        # 3. SyncLiveBridge client: 409/410 exit releases held mouse buttons, and extract supports selection/range/range_preview!
        import live_browser_ctl as ctl

        pushed_clips: list[dict] = []
        eval_scripts: list[str] = []

        class _SyncPageExt:
            url = "https://sync-ext.example"
            viewport_size = {"width": 1280, "height": 800}

            def __init__(self) -> None:
                self.mouse = types.SimpleNamespace(up=mock.Mock(), move=mock.Mock(), down=mock.Mock(), click=mock.Mock())

            def screenshot(self, **_kw) -> bytes:
                return b"JPEG"

            def title(self) -> str:
                return "SyncPage"

            def evaluate(self, script: str, arg=None):
                eval_scripts.append(script)
                if "caretPositionFromPoint" in script:
                    return "range-text"
                if "window.getSelection" in script:
                    return "selected-text"
                return {"text": "point-text", "href": "", "source": "点字提取"}

        sp = _SyncPageExt()
        bridge = ctl.SyncLiveBridge.__new__(ctl.SyncLiveBridge)
        bridge.raw_ctx = types.SimpleNamespace(pages=[sp])
        bridge.enabled = True
        bridge.notify = False
        bridge.active_idx = 0
        bridge._in_checkpoint = False
        bridge._held_buttons = {"left"}
        bridge._sync_lease_id = "lease-x"
        bridge._sync_session_gen = 3
        bridge._x11_display = None
        bridge._last_clip = ""
        bridge._push_clip = lambda p: pushed_clips.append(dict(p))  # type: ignore[method-assign]
        bridge.client = types.SimpleNamespace(
            bot="main",
            base_url="http://127.0.0.1:18795",
            _headers=lambda: {"X-Live-Token": "tok"},
            session=types.SimpleNamespace(
                post=lambda *_a, **_kw: types.SimpleNamespace(status_code=410, json=lambda: {"ok": False})
            ),
        )
        # 410 rejection MUST release held left button and disable bridge!
        bridge.sync_checkpoint(ai_status="chk", allow_takeover_loop=False)
        self.assertFalse(bridge.enabled)
        self.assertEqual(set(), bridge._held_buttons)
        sp.mouse.up.assert_called_once_with(button="left")

        # Sync extract implements selection, range, range_preview, and point with sensitive masking
        bridge.enabled = True
        bridge._exec_human_sync({"action": "extract", "mode": "selection"})
        bridge._exec_human_sync({"action": "extract", "mode": "range", "x1": 10, "y1": 10, "x2": 90, "y2": 20})
        bridge._exec_human_sync(
            {"action": "extract", "mode": "range_preview", "x1": 10, "y1": 10, "x2": 90, "y2": 20, "extract_gen": 4}
        )
        self.assertEqual("selected-text", pushed_clips[0]["text"])
        self.assertEqual("range-text", pushed_clips[1]["text"])
        self.assertTrue(pushed_clips[2].get("preview"))
        self.assertEqual(4, pushed_clips[2].get("extract_gen"))
        self.assertTrue(all("one-time-code" in s and "cc-" in s and "password" in s for s in eval_scripts))

    def test_p1_04_p2_01_p2_04_raw_stream_upload_filename_dl_cl_tab_atomic_and_chooser_cancel(self) -> None:
        async def _scenario() -> None:
            hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
            hub.engine_mode = "async_hosted"
            hub.session_gen = 2
            hub.session_owner = ("main", 111)
            bot_tok = "100001:EXAMPLE_UPLOAD_TOKEN_1234567"
            valid_init = _signed_init_data(bot_tok, user_id=111)

            ws_owner = _FakeWSViewer()
            hub.viewers.add(ws_owner)  # type: ignore[arg-type]
            hub.viewer_meta[ws_owner] = {"bot_key": "main", "user_id": 111, "role": "admin"}

            with (
                mock.patch.object(srv, "web", _FakeWeb),
                mock.patch.object(srv, "load_bot_credentials", return_value=({"main": bot_tok}, {}, {111})),
            ):
                # 1. P1-04: _CountingStreamReader rejects raw wire stream over MAX_UPLOAD_TOTAL_REQUEST_BYTES (with unread_data accounting!)
                class _MemStream:
                    def __init__(self, payload: bytes) -> None:
                        self._buf = bytearray(payload)

                    def unread_data(self, data: bytes) -> None:
                        self._buf[:0] = data

                    async def read(self, n: int = -1) -> bytes:
                        if n < 0 or n >= len(self._buf):
                            out = bytes(self._buf)
                            self._buf.clear()
                            return out
                        out = bytes(self._buf[:n])
                        del self._buf[:n]
                        return out

                    async def readline(self, *_a, **_kw) -> bytes:
                        idx = self._buf.find(b"\n")
                        if idx < 0:
                            return await self.read(-1)
                        return await self.read(idx + 1)

                    def at_eof(self) -> bool:
                        return len(self._buf) == 0

                raw_mp = (
                    b"--BOUND123\r\n"
                    b'Content-Disposition: form-data; name="files"; filename="a.txt"\r\n'
                    b"Content-Type: text/plain\r\n\r\n"
                    b"hello\r\n"
                    b"--BOUND123--\r\n"
                )
                cs = srv._CountingStreamReader(_MemStream(raw_mp), max_bytes=len(raw_mp))
                line1 = await cs.readline()
                cs.unread_data(line1)
                line1_again = await cs.readline()
                self.assertEqual(line1, line1_again)
                rest = await cs.read(-1)
                self.assertEqual(len(raw_mp), cs.bytes_read)
                self.assertEqual(raw_mp, line1_again + rest)

                cs_small = srv._CountingStreamReader(_MemStream(raw_mp), max_bytes=40)
                with self.assertRaises(srv._UploadPayloadTooLargeError):
                    await cs_small.read(-1)

                # If aiohttp.MultipartReader is available, verify full end-to-end raw stream 413 in handle_api_upload!
                chooser = _FakeFileChooser(multiple=False)
                await hub._handle_page_filechooser(chooser)
                cid = next(iter(hub.pending_filechoosers.keys()))
                if srv.MultipartReader is not None:
                    with mock.patch.object(srv, "MAX_UPLOAD_TOTAL_REQUEST_BYTES", 40):
                        r_raw_413 = await srv.handle_api_upload(
                            types.SimpleNamespace(
                                headers={
                                    "X-TG-Init-Data": valid_init,
                                    "X-Chooser-Id": cid,
                                    "Content-Type": "multipart/form-data; boundary=BOUND123",
                                },
                                query={},
                                app={"hub": hub},
                                content=_MemStream(raw_mp),
                            )  # type: ignore[arg-type]
                        )
                    self.assertEqual(413, r_raw_413.status)

                # 2. P1-04: Part named "files" WITHOUT filename counts toward non-file budget (-> 413)!
                with mock.patch.object(srv, "MAX_UPLOAD_NONFILE_TOTAL_BYTES", 4):
                    r_nofn = await srv.handle_api_upload(
                        types.SimpleNamespace(
                            headers={"X-TG-Init-Data": valid_init, "X-Chooser-Id": cid},
                            query={},
                            app={"hub": hub},
                            multipart=mock.AsyncMock(
                                return_value=_FakeMultipartReader([_FakeMultipartPart("files", b"12345", None)])
                            ),
                        )  # type: ignore[arg-type]
                    )
                self.assertEqual(413, r_nofn.status)

                # 3. P1-04: Download with declared Content-Length > MAX_DOWNLOAD_BYTES cancels BEFORE save_as!
                save_as_called = False
                dl_cancelled = False

                class _DeclaredHugeDownload:
                    suggested_filename = "huge.iso"
                    content_length = 9999

                    async def cancel(self) -> None:
                        nonlocal dl_cancelled
                        dl_cancelled = True

                    async def save_as(self, _p: str) -> None:
                        nonlocal save_as_called
                        save_as_called = True

                with mock.patch.object(srv, "MAX_DOWNLOAD_BYTES", 100):
                    await hub._handle_page_download(_DeclaredHugeDownload(), session_gen=2, owner_bot="main", owner_uid=111)
                self.assertTrue(dl_cancelled)
                self.assertFalse(save_as_called, "Oversized declared Content-Length must cancel before save_as")

                # 4. P2-04: Chooser expiring mid-upload returns 404 + emits filechooser_closed (no set_files)!
                ws_owner.sent_json.clear()

                class _ExpiringReader:
                    def __init__(self) -> None:
                        self._done = False

                    async def next(self):
                        if not self._done:
                            self._done = True
                            hub.pending_filechoosers[cid]["created_ts"] = time.monotonic() - (srv.TRANSFER_TTL_SECONDS + 5.0)
                            return _FakeMultipartPart("files", b"ok", "ok.txt")
                        return None

                r_mid_exp = await srv.handle_api_upload(
                    types.SimpleNamespace(
                        headers={"X-TG-Init-Data": valid_init, "X-Chooser-Id": cid},
                        query={},
                        app={"hub": hub},
                        multipart=mock.AsyncMock(return_value=_ExpiringReader()),
                    )  # type: ignore[arg-type]
                )
                self.assertEqual(404, r_mid_exp.status)
                self.assertIsNone(chooser.received_files)
                self.assertTrue(any(m.get("type") == "filechooser_closed" and m.get("chooser_id") == cid for m in ws_owner.sent_json))

                # 5. P2-04: CancelledError during chooser.set_files STILL emits filechooser_closed!
                set_files_entered = asyncio.Event()

                class _BlockingChooser:
                    def is_multiple(self) -> bool:
                        return False

                    async def set_files(self, _files) -> None:
                        set_files_entered.set()
                        await asyncio.sleep(5.0)

                await hub._handle_page_filechooser(_BlockingChooser())
                cid2 = next(iter(hub.pending_filechoosers.keys()))
                ws_owner.sent_json.clear()
                up_task = asyncio.create_task(
                    srv.handle_api_upload(
                        types.SimpleNamespace(
                            headers={"X-TG-Init-Data": valid_init, "X-Chooser-Id": cid2},
                            query={},
                            app={"hub": hub},
                            multipart=mock.AsyncMock(
                                return_value=_FakeMultipartReader([_FakeMultipartPart("files", b"ok", "ok.txt")])
                            ),
                        )  # type: ignore[arg-type]
                    )
                )
                await asyncio.wait_for(set_files_entered.wait(), timeout=1.0)
                up_task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await up_task
                await asyncio.sleep(0.02)
                self.assertTrue(
                    any(m.get("type") == "filechooser_closed" and m.get("chooser_id") == cid2 for m in ws_owner.sent_json),
                    "Cancellation during set_files must still emit filechooser_closed",
                )
                hub._cleanup_transfer_dir(force_all=True)

            # 6. P2-01: Concurrent tab switch during viewport await MUST discard stale snapshot & preserve newer selection + dirty!
            eval_entered = asyncio.Event()
            release_eval = asyncio.Event()

            class _SlowViewportPage(_FakePage):
                def __init__(self, url: str, title: str) -> None:
                    super().__init__(url, title)
                    self.viewport_size = None  # force async evaluate()

                async def evaluate(self, _expr: str, *_a):
                    eval_entered.set()
                    await release_eval.wait()
                    return {"w": 1000, "h": 700}

            p0 = _SlowViewportPage("https://tab0.example", "Tab 0")
            p1 = _FakePage("https://tab1.example", "Tab 1")
            hub.ctx = _FakeCtx([p0, p1])
            hub.active_tab_index = 0
            hub.url = "https://initial.example"
            hub.title = "Initial"
            hub._tabs_dirty = True

            refresh_task = asyncio.create_task(hub._refresh_tabs_metadata(force=True))
            await asyncio.wait_for(eval_entered.wait(), timeout=1.0)
            # Concurrent tab switch to tab 1 while tab 0 viewport await is suspended!
            hub.active_tab_index = 1
            hub._tab_select_rev += 1
            release_eval.set()
            changed = await refresh_task
            self.assertFalse(changed, "Stale tab refresh must discard when _tab_select_rev changed mid-await")
            self.assertEqual(1, hub.active_tab_index, "Stale refresh must NEVER overwrite newer active_tab_index")
            self.assertEqual("https://initial.example", hub.url, "Stale refresh must NEVER partially write hub.url")
            self.assertTrue(hub._tabs_dirty, "Discarded stale refresh must preserve _tabs_dirty=True")

        asyncio.run(_scenario())


class TestRound5FinalPolishRegression(unittest.TestCase):
    """Deterministic Round 5 closure tests covering all 6 QA blocker groups."""

    def test_group1_stateless_retire_live_tick_recheck_tg_status_isolation_and_lock_scoped_start_stop(self) -> None:
        tok_main = "100:MAIN_TOK_ROUND5"
        tok_sg = "200:SG_TOK_ROUND5"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_main = tmp_path / ".env"
            env_sg = tmp_path / ".env.sg"
            env_main.write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111,112\nAGY_TG_ADMIN_USERS=111,112\n",
                encoding="utf-8",
            )
            env_sg.write_text(
                f"AGY_TG_BOT_TOKEN={tok_sg}\nAGY_TG_ALLOWED_CHATS=222\nAGY_TG_ADMIN_USERS=222\n",
                encoding="utf-8",
            )

            class _SpyCardHTTP:
                def __init__(self, on_post=None) -> None:
                    self.calls: list[tuple[str, dict]] = []
                    self._on_post = on_post

                def post(self, url: str, data=None, json=None):
                    rec = {"data": getattr(data, "fields", None), "json": json}
                    self.calls.append((url, rec))
                    if callable(self._on_post):
                        return _FakeHTTPResp(self._on_post(url, rec))
                    return _FakeHTTPResp({"ok": True, "result": {"message_id": 601}})

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, "sec-tok")
                hub.engine_mode = "async_hosted"
                hub.session_gen = 10
                hub.session_owner = ("main", 111)
                hub.active_profile = "user-a-prof"
                hub.url = "https://user-a.example/private"
                hub.title = "User A Page"
                hub.latest_jpeg = b"USER_A_FRAME"

                # 1. Stateless orphan retirement NEVER leaks newer session's title/URL/profile/egress!
                def _switch_mid_sendphoto(url: str, _rec: dict) -> dict:
                    if url.endswith("/sendPhoto"):
                        hub.session_gen = 11
                        hub.session_owner = ("sg", 222)
                        hub.title = "TOP_SECRET_USER_B_TITLE"
                        hub.url = "https://secret-b.example/bank"
                        hub.active_profile = "secret-b-prof"
                        hub.active_egress = "socks5://proxy.example.com:1080"
                        return {"ok": True, "result": {"message_id": 601}}
                    return {"ok": True}

                http_spy = _SpyCardHTTP(on_post=_switch_mid_sendphoto)
                hub.tg.http = http_spy
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", tmp_path),
                    mock.patch.object(srv, "FormData", _FakeFormData),
                    mock.patch.object(srv, "web", _FakeWeb),
                ):
                    res_orphan = await hub.tg.ensure_card("main", preferred_user_id=111)
                    self.assertIsNone(res_orphan)
                    edit_cap = [c for c in http_spy.calls if c[0].endswith("/editMessageCaption")]
                    self.assertEqual(1, len(edit_cap))
                    cap_txt = str(edit_cap[0][1]["json"]["caption"])
                    self.assertIn("远端浏览器会话已结束", cap_txt)
                    for secret_s in ("TOP_SECRET_USER_B_TITLE", "secret-b.example", "secret-b-prof", "proxy.example.com"):
                        self.assertNotIn(secret_s, cap_txt, f"Stateless retire leaked {secret_s}!")

                    # 2. Periodic tick_updates re-checks live auth inside _update_card_locked (no stale snapshot!)
                    hub.session_gen = 12
                    hub.session_owner = ("main", 111)
                    hub.latest_jpeg = b"GEN12_FRAME"
                    hub.tg.cards[("main", 111)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 612,
                        "session_gen": 12,
                        "owner": ("main", 111),
                        "last_sha1": "old",
                        "last_caption": "old",
                        "last_markup": "old",
                        "last_ts": 0.0,
                    }
                    # Revoke user 111 before tick_updates -> zero editMessageMedia calls & card popped!
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=112\nAGY_TG_ADMIN_USERS=112\n",
                        encoding="utf-8",
                    )
                    http_spy2 = _SpyCardHTTP()
                    hub.tg.http = http_spy2
                    await hub.tg.tick_updates(force=True)
                    self.assertEqual([], http_spy2.calls)
                    self.assertNotIn(("main", 111), hub.tg.cards)

                    # Restore user 111 admin
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111,112\nAGY_TG_ADMIN_USERS=111,112\n",
                        encoding="utf-8",
                    )

                    # 3. Telegram `/browser` status isolation (`/internal/status` & `/internal/profiles` with source=tg_cmd)
                    hub.engine_mode = "async_hosted"
                    hub.session_gen = 15
                    hub.session_owner = None  # unowned localhost CLI session
                    hub.url = "https://cli-private.example/secret"
                    hub.title = "CLI Secret"
                    hub.active_profile = "cli-prof"
                    r_tg_unowned = await srv.internal_status(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={"source": "tg_cmd", "bot": "main", "user_id": "111"},
                        )  # type: ignore[arg-type]
                    )
                    self.assertTrue(r_tg_unowned.data.get("session_restricted"))
                    self.assertEqual("", r_tg_unowned.data.get("url"))
                    self.assertEqual("", r_tg_unowned.data.get("title"))
                    self.assertIsNone(r_tg_unowned.data.get("profile"))

                    # Localhost CLI query (no source=tg_cmd / user_id) still sees full state
                    r_cli_st = await srv.internal_status(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={},
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual("https://cli-private.example/secret", r_cli_st.data.get("url"))

                    # Non-owner TG query against owned session -> redacted; owner -> full!
                    hub.session_owner = ("main", 111)
                    r_tg_other = await srv.internal_status(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={"source": "tg_cmd", "bot": "main", "user_id": "112"},
                        )  # type: ignore[arg-type]
                    )
                    self.assertTrue(r_tg_other.data.get("session_restricted"))
                    self.assertEqual("", r_tg_other.data.get("url"))
                    r_tg_owner = await srv.internal_status(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={"source": "tg_cmd", "bot": "main", "user_id": "111"},
                        )  # type: ignore[arg-type]
                    )
                    self.assertFalse(bool(r_tg_owner.data.get("session_restricted")))
                    self.assertEqual("https://cli-private.example/secret", r_tg_owner.data.get("url"))

                    # 4. Telegram `/browser start` with URL against another owner's active session -> 403, NEVER navigates!
                    page_a = _FakePage("https://user-a.example", "User A")
                    page_a.goto = mock.AsyncMock()  # type: ignore[method-assign]
                    hub.ctx = _FakeCtx([page_a])
                    r_hijack_start = await srv.internal_start(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(
                                return_value={
                                    "source": "tg_cmd",
                                    "bot": "main",
                                    "user_id": 112,
                                    "profile": "cli-prof",
                                    "url": "https://evil-nav.example",
                                }
                            ),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(403, r_hijack_start.status)
                    page_a.goto.assert_not_awaited()

                    # 5. Hosted stop_hosted() advances session_gen/takeover_gen & flips idle BEFORE retire_cards awaits!
                    hub.takeover = True
                    hub.takeover_gen = 5
                    state_at_retire: list[tuple] = []

                    async def _spy_retire_order(**kw) -> int:
                        state_at_retire.append(
                            (hub.engine_mode, hub.session_gen, hub.takeover_gen, hub.session_owner, kw.get("session_gen"))
                        )
                        return 0

                    with mock.patch.object(hub.tg, "retire_cards", side_effect=_spy_retire_order):
                        ok_s, _ = await hub.stop_hosted(notify_finished=True, actor=("main", 111), source="tg_cmd", expected_session_gen=15)
                    self.assertTrue(ok_s)
                    self.assertEqual([("idle", 16, 6, None, 15)], state_at_retire)

                    # 6. Internal card callback missing `bot` -> 403 even in single-bot setup (no auto-resolve fallback!)
                    env_sg.unlink()
                    hub.engine_mode = "async_hosted"
                    hub.session_gen = 20
                    hub.session_owner = ("main", 111)
                    hub.tg.cards[("main", 111)] = {"bot_key": "main", "chat_id": 111, "message_id": 888, "session_gen": 20}
                    r_nobot_tk = await srv.internal_takeover(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(
                                return_value={"active": True, "chat_id": 111, "user_id": 111, "message_id": 888, "source": "tg_card"}
                            ),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(403, r_nobot_tk.status)
                    r_nobot_rf = await srv.internal_config(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(
                                return_value={"refresh_card": True, "chat_id": 111, "message_id": 888, "source": "tg_card"}
                            ),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(403, r_nobot_rf.status)

            asyncio.run(_scenario())

    def test_group2_dual_gen_ws_compound_input_stepwise_auth_and_sync_internal_targeted_extract(self) -> None:
        tok_main = "100:MAIN_TOK_G2"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_main = tmp_path / ".env"
            env_main.write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111,112\nAGY_TG_ADMIN_USERS=111,112\n",
                encoding="utf-8",
            )
            fake_ws_type = types.SimpleNamespace(TEXT="TEXT")

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, "sec-tok")
                hub.engine_mode = "async_hosted"
                hub.session_gen = 9
                hub.takeover_gen = 4
                hub.takeover = False
                hub.session_owner = ("main", 111)
                hub.url = "https://example.com"
                hub.latest_jpeg = b"JPEG"
                req = types.SimpleNamespace(app={"hub": hub}, remote="127.0.0.1")

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", tmp_path),
                    mock.patch.object(srv, "WSMsgType", fake_ws_type),
                    mock.patch.object(srv, "web", _FakeWeb),
                ):
                    # 1. WS set_takeover & extract require BOTH session_gen AND takeover_gen!
                    ws_missing_tgen = _FakeWSViewer(
                        [
                            {"type": "auth", "initData": _signed_init_data(tok_main, 111)},
                            {"type": "set_takeover", "active": True, "session_gen": 9, "req_id": "no-tgen"},
                            {"type": "set_takeover", "active": True, "session_gen": 9, "takeover_gen": 3, "req_id": "stale-tgen"},
                            {"type": "extract", "mode": "url", "session_gen": 9},  # missing takeover_gen
                            {"type": "extract", "mode": "url", "session_gen": 9, "takeover_gen": 3},  # stale takeover_gen
                        ]
                    )
                    with mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ws_missing_tgen)):
                        await srv.handle_ws(req)  # type: ignore[arg-type]
                    self.assertFalse(hub.takeover)
                    acks = {m.get("req_id"): m for m in ws_missing_tgen.sent_json if m.get("type") == "takeover_ack"}
                    self.assertFalse(acks["no-tgen"]["ok"])
                    self.assertFalse(acks["stale-tgen"]["ok"])
                    self.assertFalse(any(m.get("type") == "clipboard" for m in ws_missing_tgen.sent_json))

                    # 2. Compound input (`type` with replace=True, submit=True): revoke admin after Control+A -> aborts Backspace/type/Enter!
                    kb_events: list[tuple[str, str]] = []

                    class _RevokeMidCompoundKeyboard:
                        async def press(self, key: str) -> None:
                            kb_events.append(("press", key))
                            if key == "Control+A":
                                env_main.write_text(
                                    f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\nAGY_TG_READONLY_USERS=111\n",
                                    encoding="utf-8",
                                )

                        async def type(self, txt: str, **_kw) -> None:
                            kb_events.append(("type", txt))

                        async def insert_text(self, txt: str) -> None:
                            kb_events.append(("insert_text", txt))

                    page_comp = _FakePage()
                    page_comp.keyboard = _RevokeMidCompoundKeyboard()  # type: ignore[assignment]
                    hub.ctx = _FakeCtx([page_comp])
                    hub.takeover = True
                    hub.takeover_owner = ("main", 111)
                    await hub._execute_human_cmd_async(
                        {
                            "action": "type",
                            "text": "secret",
                            "replace": True,
                            "submit": True,
                            "_session_gen": 9,
                            "_takeover_gen": 4,
                            "_bot_key": "main",
                            "_user_id": 111,
                        }
                    )
                    self.assertEqual([("press", "Control+A")], kb_events, "Compound input must stop immediately after mid-step revocation!")

                    # Restore admin 111
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111,112\nAGY_TG_ADMIN_USERS=111,112\n",
                        encoding="utf-8",
                    )

                    # 3. Sync queue _server_internal: forged client cleanup=True cannot bypass takeover gate!
                    hub.ctx = None
                    hub.engine_mode = "sync_external"
                    hub.session_gen = 20
                    hub.takeover = False
                    hub.takeover_gen = 7
                    hub.sync_cmd_queue = [
                        {"action": "mouseup", "button": "left", "session_gen": 20, "takeover_gen": 1, "cleanup": True},  # untrusted!
                        {"action": "mouseup", "button": "right", "session_gen": 20, "takeover_gen": 7, "cleanup": True, "_server_internal": True},
                    ]
                    popped = hub.pop_sync_cmds()
                    self.assertEqual(1, len(popped))
                    self.assertEqual("right", popped[0]["button"])
                    self.assertNotIn("_server_internal", popped[0])

                    # 4. Targeted Sync extract reply: routes ONLY to requester ws (never broadcasts to other viewer)!
                    r_sync = await srv.internal_sync_start(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(return_value={"bot": "main", "user_id": 111}),
                        )  # type: ignore[arg-type]
                    )
                    lease_id = r_sync.data["sync_lease_id"]
                    sgen = r_sync.data["session_gen"]
                    ws_req = _FakeWSViewer()
                    ws_other = _FakeWSViewer()
                    hub.viewers = {ws_req, ws_other}  # type: ignore[assignment]
                    hub.viewer_meta = {
                        ws_req: {"bot_key": "main", "user_id": 111, "role": "admin"},
                        ws_other: {"bot_key": "main", "user_id": 111, "role": "admin"},
                    }
                    hub._pending_sync_extracts["req-target-1"] = {
                        "bot_key": "main",
                        "user_id": 111,
                        "session_gen": sgen,
                        "takeover_gen": hub.takeover_gen,
                        "owner": hub.session_owner,
                        "ws": ws_req,
                        "created_ts": time.monotonic(),
                    }
                    r_clip = await srv.internal_sync_clipboard(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok", "X-Sync-Lease-Id": lease_id},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={},
                            json=mock.AsyncMock(
                                return_value={
                                    "text": "ONLY_FOR_REQUESTER",
                                    "req_id": "req-target-1",
                                    "session_gen": sgen,
                                    "takeover_gen": hub.takeover_gen,
                                }
                            ),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(200, r_clip.status)
                    self.assertTrue(any(m.get("text") == "ONLY_FOR_REQUESTER" for m in ws_req.sent_json))
                    self.assertEqual([], ws_other.sent_json, "Targeted Sync extract reply must NOT broadcast to other viewers!")

            asyncio.run(_scenario())

    def test_group3_group4_group5_sync_ttl_preread_per_page_release_upload_epilogue_chooser_gen_and_same_page_nav(self) -> None:
        tok_main = "100:MAIN_TOK_G345"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            env_main = tmp_path / ".env"
            env_main.write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\nAGY_TG_ADMIN_USERS=111\n",
                encoding="utf-8",
            )

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"public_url": "https://live.example"}, "sec-tok")
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", tmp_path),
                    mock.patch.object(srv, "web", _FakeWeb),
                ):
                    # 1. Group 3: Built-in TTL check in _check_sync_lease_active rejects expired lease WITHOUT maintenance tick!
                    r_start = await srv.internal_sync_start(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(return_value={"bot": "main", "user_id": 111}),
                        )  # type: ignore[arg-type]
                    )
                    lease1 = r_start.data["sync_lease_id"]
                    gen1 = r_start.data["session_gen"]
                    self.assertIn("takeover_gen", r_start.data)
                    # Simulate elapsed time past TTL without running _expire_sync_session_if_stale()!
                    hub._sync_last_push_ts = time.monotonic() - (srv.SYNC_LEASE_TIMEOUT_SECONDS + 5.0)
                    read_spy = mock.AsyncMock(return_value=b"FRAME")
                    r_expired_push = await srv.internal_sync_push(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok", "X-Sync-Lease-Id": lease1},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={"lease_id": lease1, "session_gen": str(gen1)},
                            read=read_spy,
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(410, r_expired_push.status, "Expired sync lease must be rejected immediately without maintenance tick")
                    self.assertEqual("idle", hub.engine_mode)
                    self.assertIsNone(hub._sync_lease_id)
                    read_spy.assert_not_awaited()

                    # 2. Group 3: /internal/sync/clipboard & /internal/sync/stop reject missing header/query lease BEFORE reading body!
                    r_s2 = await srv.internal_sync_start(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(return_value={"bot": "main", "user_id": 111}),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(200, r_s2.status)
                    clip_json_spy = mock.AsyncMock(return_value={"text": "should-not-read", "lease_id": r_s2.data["sync_lease_id"]})
                    r_clip_nohdr = await srv.internal_sync_clipboard(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={},
                            json=clip_json_spy,
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(409, r_clip_nohdr.status)
                    clip_json_spy.assert_not_awaited()

                    stop_read_spy = mock.AsyncMock(return_value=b"{}")
                    r_stop_nohdr = await srv.internal_sync_stop(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={},
                            read=stop_read_spy,
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual(409, r_stop_nohdr.status)
                    stop_read_spy.assert_not_awaited()

                    # 3. Group 4: Upload trailing epilogue bytes exceeding MAX_UPLOAD_TOTAL_REQUEST_BYTES -> 413 & NEVER calls set_files()!
                    if srv.MultipartReader is not None:
                        from aiohttp import StreamReader as _AioStreamReader

                        hub.engine_mode = "async_hosted"
                        hub.session_gen = 30
                        hub.session_owner = ("main", 111)
                        hub.takeover = True
                        hub.takeover_owner = ("main", 111)
                        chooser_ep = _FakeFileChooser(multiple=False)
                        await hub._handle_page_filechooser(chooser_ep)
                        cid_ep = next(iter(hub.pending_filechoosers.keys()))

                        boundary = "----AgyRound5EpilogueBoundary"
                        valid_mp = (
                            f"--{boundary}\r\n"
                            f'Content-Disposition: form-data; name="files"; filename="ok.txt"\r\n'
                            f"Content-Type: text/plain\r\n\r\n"
                            f"hi\r\n"
                            f"--{boundary}--\r\n"
                        ).encode("utf-8")
                        epilogue_bomb = b"Z" * 1024  # trailing bytes AFTER closing boundary!
                        full_body = valid_mp + epilogue_bomb

                        sr = _AioStreamReader(mock.MagicMock(), limit=2**20, loop=asyncio.get_running_loop())
                        sr.feed_data(full_body)
                        sr.feed_eof()

                        req_ep = types.SimpleNamespace(
                            app={"hub": hub},
                            headers={
                                "X-TG-Init-Data": _signed_init_data(tok_main, 111),
                                "X-Chooser-Id": cid_ep,
                                "Content-Type": f"multipart/form-data; boundary={boundary}",
                            },
                            query={},
                            content=sr,
                        )
                        with mock.patch.object(srv, "MAX_UPLOAD_TOTAL_REQUEST_BYTES", len(valid_mp) + 64):
                            r_ep = await srv.handle_api_upload(req_ep)  # type: ignore[arg-type]
                        self.assertEqual(413, r_ep.status, "Oversized trailing epilogue bytes must fail with 413 before set_files()")
                        self.assertIsNone(chooser_ep.received_files)

                    # 4. Group 4: filechooser_closed broadcasts strictly bind expected_session_gen (no cross-gen emission!)
                    hub.session_gen = 40
                    ws_owner = _FakeWSViewer()
                    hub.viewers = {ws_owner}  # type: ignore[assignment]
                    hub.viewer_meta = {ws_owner: {"bot_key": "main", "user_id": 111, "role": "admin"}}
                    hub.pending_filechoosers["stale-cid"] = {
                        "id": "stale-cid",
                        "chooser": _FakeFileChooser(),
                        "page_id": 1,
                        "multiple": False,
                        "created_ts": time.monotonic(),
                        "session_gen": 39,
                        "owner_bot": "main",
                        "owner_uid": 111,
                    }
                    await hub._cleanup_pending_filechoosers_async(page_id=1)
                    self.assertEqual([], ws_owner.sent_json, "Stale-gen filechooser_closed must NOT cross into newer session_gen=40")

                    # 5. Group 5: Same-page navigation (`framenavigated`) during viewport await advances revision & discards stale snapshot!
                    eval_started = asyncio.Event()
                    eval_release = asyncio.Event()

                    class _SamePageNavPage(_FakePage):
                        def __init__(self) -> None:
                            super().__init__("https://old-page.example", "Old Page")
                            self.viewport_size = None
                            self._cbs: dict[str, list] = {}

                        def on(self, ev: str, cb) -> None:
                            self._cbs.setdefault(ev, []).append(cb)

                        async def evaluate(self, _expr: str, *_a):
                            eval_started.set()
                            await eval_release.wait()
                            return {"w": 1200, "h": 720}

                    sp_page = _SamePageNavPage()
                    hub.ctx = _FakeCtx([sp_page])
                    hub.engine_mode = "async_hosted"
                    hub.active_tab_index = 0
                    hub.url = "https://before.example"
                    hub.title = "Before"
                    hub._tabs_dirty = True
                    hub._attach_page_listeners(sp_page)

                    ref_task = asyncio.create_task(hub._refresh_tabs_metadata(force=True))
                    await asyncio.wait_for(eval_started.wait(), timeout=1.0)
                    # Same-page navigation fires framenavigated while viewport evaluate is in flight!
                    sp_page.url = "https://new-page.example"
                    for cb in sp_page._cbs.get("framenavigated", []):
                        cb(types.SimpleNamespace(url="https://new-page.example"))
                    eval_release.set()
                    committed = await ref_task
                    self.assertFalse(committed, "Same-page navigation mid-await must discard stale metadata snapshot")
                    self.assertEqual("https://before.example", hub.url)
                    self.assertTrue(hub._tabs_dirty)

            asyncio.run(_scenario())

        # 6. Group 3 + Group 2 (SyncLiveBridge): per-page held-button release + about:blank new_tab + non-pinned Google block + container guard!
        import live_browser_ctl as ctl

        p0_ups: list[str] = []
        p1_ups: list[str] = []
        p0_gotos: list[str] = []
        new_tab_gotos: list[str] = []

        class _SyncFakeMouse:
            def __init__(self, ups: list[str]) -> None:
                self._ups = ups

            def move(self, _x: float, _y: float) -> None:
                pass

            def down(self, button: str = "left") -> None:
                pass

            def up(self, button: str = "left") -> None:
                self._ups.append(button)

        class _SyncFakePage:
            def __init__(self, ups: list[str], gotos: list[str], url: str = "https://a.example") -> None:
                self.url = url
                self.mouse = _SyncFakeMouse(ups)
                self._gotos = gotos

            def is_closed(self) -> bool:
                return False

            def bring_to_front(self) -> None:
                pass

            def goto(self, url: str, **_kw) -> None:
                self._gotos.append(url)
                self.url = url

        p0 = _SyncFakePage(p0_ups, p0_gotos)
        p1 = _SyncFakePage(p1_ups, [])
        fake_ctx = types.SimpleNamespace(
            pages=[p0, p1],
            new_page=lambda: _SyncFakePage([], new_tab_gotos, "about:blank"),
        )
        # Make new_page append to pages list
        def _new_page_fn():
            np = _SyncFakePage([], new_tab_gotos, "about:blank")
            fake_ctx.pages.append(np)
            return np

        fake_ctx.new_page = _new_page_fn
        bridge = ctl.SyncLiveBridge.__new__(ctl.SyncLiveBridge)
        bridge.raw_ctx = fake_ctx
        bridge.active_idx = 0
        bridge.enabled = True
        bridge._held_buttons = {}
        bridge._pinned_verified = False
        bridge._profile_dir = None

        # Press on page 0, switch to page 1, then release -> MUST release on page 0, NOT page 1!
        bridge._exec_human_sync({"action": "mousedown", "x": 10, "y": 10, "button": "left"})
        bridge._exec_human_sync({"action": "switch_tab", "index": 1})
        bridge._release_held_buttons_sync()
        self.assertEqual(["left"], p0_ups)
        self.assertEqual([], p1_ups)

        # Sync new_tab opens about:blank (NOT Google)
        bridge._exec_human_sync({"action": "new_tab"})
        self.assertEqual(["about:blank"], new_tab_gotos)

        # Non-pinned Sync goto blocks Google domain when host requires pinned
        with mock.patch.dict(srv.os.environ, {"AGY_LIVE_BROWSER_REQUIRE_PINNED": "1"}, clear=False):
            with mock.patch.object(srv, "discover_pinned_host_profile", return_value={"name": "pin", "profile_dir": "/tmp/pin"}):
                bridge.active_idx = 0
                bridge._exec_human_sync({"action": "goto", "url": "https://mail.google.com/mail"})
                self.assertEqual([], p0_gotos, "Non-pinned Sync goto must block Google domains on pinned host")

        # Sync point extract includes container-margin guard matching hosted extract_content_async
        ctl_src = (REPO_ROOT / ".agents/skills/live-browser/scripts/live_browser_ctl.py").read_text(encoding="utf-8")
        self.assertIn("Container-margin guard", ctl_src)
        self.assertIn("bestDist && d <= 60", ctl_src)


class TestRound6FinalClosureRegression(unittest.TestCase):
    """Round 6 synthetic regressions closing every remaining Round 5 QA gap."""

    def test_round6_ws_lifecycle_strict_gen_commit_rbac_and_periodic_retire_race(self) -> None:
        """Round 6 §3: strict lifecycle session_gen, pre-commit & pre-goto RBAC re-check, and periodic-update vs retire race."""
        tok_main = "100:MAIN_TOK_R6_LIFE"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bdir = root / "bridge"
            bdir.mkdir(parents=True, exist_ok=True)
            env_main = bdir / ".env"
            env_main.write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111,112\nAGY_TG_ADMIN_USERS=111\n",
                encoding="utf-8",
            )
            cfg_dir = root / "cfg"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            prof_dir = root / "profs"
            prof_dir.mkdir(parents=True, exist_ok=True)

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                hub.session_gen = 5
                fake_ws_type = types.SimpleNamespace(TEXT="TEXT", CLOSE="CLOSE")
                req = types.SimpleNamespace(app={"hub": hub}, remote="127.0.0.1")

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "CONFIG_DIR", cfg_dir),
                    mock.patch.object(srv, "PROFILES_FILE", cfg_dir / "profiles.json"),
                    mock.patch.object(srv, "PROFILES_DATA_DIR", prof_dir),
                    mock.patch.object(srv, "discover_pinned_host_profile", return_value=None),
                    mock.patch.object(srv, "WSMsgType", fake_ws_type),
                ):
                    srv.create_profile("r6-prof", {"os": "linux", "persistent": False})

                    # 3a. Missing/invalid/stale session_gen on start_browser / switch_profile / stop_browser MUST be rejected!
                    start_spy = mock.AsyncMock()
                    stop_spy = mock.AsyncMock(return_value=(True, "ok"))
                    ws_bad_life = _FakeWSViewer(
                        [
                            {"type": "auth", "initData": _signed_init_data(tok_main, 111)},
                            {"type": "start_browser", "profile": "r6-prof"},  # missing
                            {"type": "start_browser", "profile": "r6-prof", "session_gen": "not-an-int"},  # invalid
                            {"type": "start_browser", "profile": "r6-prof", "session_gen": 4},  # stale
                            {"type": "switch_profile", "profile": "r6-prof"},  # missing
                            {"type": "switch_profile", "profile": "r6-prof", "session_gen": 4},  # stale
                            {"type": "stop_browser"},  # missing
                            {"type": "stop_browser", "session_gen": 99},  # stale
                        ]
                    )
                    with (
                        mock.patch.object(srv, "web", types.SimpleNamespace(WebSocketResponse=lambda **_kw: ws_bad_life)),
                        mock.patch.object(hub, "start_hosted", side_effect=start_spy),
                        mock.patch.object(hub, "stop_hosted", side_effect=stop_spy),
                    ):
                        await srv.handle_ws(req)  # type: ignore[arg-type]
                        await asyncio.sleep(0.02)
                    start_spy.assert_not_called()
                    stop_spy.assert_not_called()
                    life_toasts = [m.get("message", "") for m in ws_bad_life.sent_json if m.get("type") == "toast"]
                    self.assertGreaterEqual(len(life_toasts), 7)
                    self.assertTrue(all("代次" in t for t in life_toasts))

                    # 3b-1. Revoke admin RBAC during async CM __aenter__ -> MUST abort before publishing & close CM!
                    cm_pre_commit: list[object] = []

                    class _RevokeDuringEnterCM:
                        def __init__(self, **_kw) -> None:
                            self.exited = False
                            self.page = _FakePage()
                            self.page.goto = mock.AsyncMock()  # type: ignore[method-assign]
                            self.ctx = _FakeCtx([self.page])
                            cm_pre_commit.append(self)

                        async def __aenter__(self):
                            # Admin 111 revoked while Camoufox is starting!
                            env_main.write_text(
                                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=112\nAGY_TG_ADMIN_USERS=112\n",
                                encoding="utf-8",
                            )
                            return self.ctx

                        async def __aexit__(self, *_a):
                            self.exited = True

                    with mock.patch.dict(
                        sys.modules,
                        {
                            "camoufox": types.SimpleNamespace(),
                            "camoufox.async_api": types.SimpleNamespace(AsyncCamoufox=_RevokeDuringEnterCM),
                        },
                    ):
                        with self.assertRaises(PermissionError):
                            await hub.start_hosted(
                                initial_url="https://example.com/secret",
                                profile="r6-prof",
                                notify_tg=False,
                                actor=("main", 111),
                                source="ws",
                                expected_session_gen=5,
                            )
                    self.assertEqual("idle", hub.engine_mode)
                    self.assertIsNone(hub.ctx)
                    self.assertTrue(cm_pre_commit and cm_pre_commit[0].exited)  # type: ignore[attr-defined]
                    cm_pre_commit[0].page.goto.assert_not_called()  # type: ignore[attr-defined]

                    # Restore admin 111
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111,112\nAGY_TG_ADMIN_USERS=111\n",
                        encoding="utf-8",
                    )

                    # 3b-2. Revoke admin RBAC during `await broadcast_state()` right before `page.goto()` -> abort, close CM, NO goto!
                    cm_pre_goto: list[object] = []

                    class _NormalCM:
                        def __init__(self, **_kw) -> None:
                            self.exited = False
                            self.page = _FakePage()
                            self.page.goto = mock.AsyncMock()  # type: ignore[method-assign]
                            self.ctx = _FakeCtx([self.page])
                            cm_pre_goto.append(self)

                        async def __aenter__(self):
                            return self.ctx

                        async def __aexit__(self, *_a):
                            self.exited = True

                    async def _revoke_on_bcast() -> None:
                        env_main.write_text(
                            f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=112\nAGY_TG_ADMIN_USERS=112\n",
                            encoding="utf-8",
                        )

                    with (
                        mock.patch.dict(
                            sys.modules,
                            {
                                "camoufox": types.SimpleNamespace(),
                                "camoufox.async_api": types.SimpleNamespace(AsyncCamoufox=_NormalCM),
                            },
                        ),
                        mock.patch.object(hub, "broadcast_state", side_effect=_revoke_on_bcast),
                    ):
                        with self.assertRaises(PermissionError):
                            await hub.start_hosted(
                                initial_url="https://example.com/must-not-goto",
                                profile="r6-prof",
                                notify_tg=False,
                                actor=("main", 111),
                                source="ws",
                                expected_session_gen=5,
                            )
                    self.assertEqual("idle", hub.engine_mode)
                    self.assertIsNone(hub.ctx)
                    self.assertTrue(cm_pre_goto and cm_pre_goto[0].exited)  # type: ignore[attr-defined]
                    cm_pre_goto[0].page.goto.assert_not_called()  # type: ignore[attr-defined]

                    # Restore admin 111 for 3c
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111,112\nAGY_TG_ADMIN_USERS=111\n",
                        encoding="utf-8",
                    )

                    # 3c. Queued periodic `tick_updates()` acquires card lock ahead of `retire_cards()` after session_gen changed:
                    #     MUST still edit Telegram card to stateless finished copy + empty keyboard before removing card!
                    class _RetireSpyHTTP:
                        def __init__(self) -> None:
                            self.calls: list[tuple[str, dict]] = []

                        def post(self, url: str, **kw):
                            self.calls.append((url, kw))

                            class _Resp:
                                async def __aenter__(self_r):
                                    return self_r

                                async def __aexit__(self_r, *_a):
                                    return False

                                async def json(self_r):
                                    return {"ok": True, "result": {"message_id": 777}}

                            return _Resp()

                    spy_http = _RetireSpyHTTP()
                    hub.tg.http = spy_http
                    hub.engine_mode = "idle"
                    hub.session_gen = 9
                    hub.session_owner = None
                    hub.latest_jpeg = b"OLD_FRAME_STILL_IN_FLIGHT"
                    hub.tg.cards[("main", 111)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 777,
                        "session_gen": 8,  # stale gen (stopped session)
                        "owner": ("main", 111),
                        "last_sha1": "old",
                        "last_caption": "live",
                        "last_markup": "live",
                        "last_ts": 0.0,
                    }
                    await hub.tg.tick_updates(force=True)
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    edit_caps = [c for c in spy_http.calls if c[0].endswith("/editMessageCaption")]
                    self.assertEqual(1, len(edit_caps), "Periodic update beating retire_cards MUST still retire Telegram card!")
                    cap_body = edit_caps[0][1]["json"]
                    self.assertEqual(777, cap_body["message_id"])
                    self.assertIn("远端浏览器会话已结束", cap_body["caption"])
                    self.assertEqual({"inline_keyboard": []}, cap_body["reply_markup"])

            asyncio.run(_scenario())

    def test_round6_sync_extract_dual_gen_no_fallback_broadcast_compound_tab_auth_and_sync_mouseup_edges(self) -> None:
        """Round 6 §4, §5, §6: Sync extract dual-gen + no fallback + cache order, new_tab/close_tab/capture auth, Sync mouseup edges, MiB units."""
        tok_main = "100:MAIN_TOK_R6_EXT"
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp) / "bridge"
            bdir.mkdir(parents=True, exist_ok=True)
            env_main = bdir / ".env"
            env_main.write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\nAGY_TG_ADMIN_USERS=111\n",
                encoding="utf-8",
            )

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                fake_ws_type = types.SimpleNamespace(TEXT="TEXT", CLOSE="CLOSE")

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "WSMsgType", fake_ws_type),
                    mock.patch.object(srv, "web", _FakeWeb),
                ):
                    # 4a & 4b: Sync extract dual-gen, offline target_ws drops strictly (no fallback to ws_b), stale/unknown req_id does NOT pollute latest_clip!
                    r_sync = await srv.internal_sync_start(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(return_value={"bot": "main", "user_id": 111}),
                        )  # type: ignore[arg-type]
                    )
                    lease_id = r_sync.data["sync_lease_id"]
                    sgen = r_sync.data["session_gen"]
                    tgen = hub.takeover_gen
                    hub.latest_clip = {"text": "INITIAL_SAFE_CLIP"}

                    ws_a = _FakeWSViewer()
                    ws_b = _FakeWSViewer()
                    hub.viewers = {ws_a, ws_b}  # type: ignore[assignment]
                    hub.viewer_meta = {
                        ws_a: {"bot_key": "main", "user_id": 111, "role": "admin"},
                        ws_b: {"bot_key": "main", "user_id": 111, "role": "admin"},
                    }

                    # (i) Unknown req_id MUST NOT write latest_clip or send to anyone
                    await srv.internal_sync_clipboard(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok", "X-Sync-Lease-Id": lease_id},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={},
                            json=mock.AsyncMock(
                                return_value={
                                    "text": "POLLUTED_UNKNOWN_REQ",
                                    "req_id": "unknown-999",
                                    "session_gen": sgen,
                                    "takeover_gen": tgen,
                                }
                            ),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual("INITIAL_SAFE_CLIP", hub.latest_clip.get("text"))
                    self.assertEqual([], ws_a.sent_json)
                    self.assertEqual([], ws_b.sent_json)

                    # (ii) Valid pending req_id, but takeover_gen changed before reply -> dropped & latest_clip untouched!
                    hub._pending_sync_extracts["req-tgen-stale"] = {
                        "bot_key": "main",
                        "user_id": 111,
                        "session_gen": sgen,
                        "takeover_gen": tgen,
                        "owner": hub.session_owner,
                        "ws": ws_a,
                        "created_ts": time.monotonic(),
                    }
                    hub.takeover_gen = tgen + 1
                    await srv.internal_sync_clipboard(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok", "X-Sync-Lease-Id": lease_id},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={},
                            json=mock.AsyncMock(
                                return_value={
                                    "text": "STALE_TGEN_CLIP",
                                    "req_id": "req-tgen-stale",
                                    "session_gen": sgen,
                                    "takeover_gen": tgen,
                                }
                            ),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual("INITIAL_SAFE_CLIP", hub.latest_clip.get("text"))
                    self.assertEqual([], ws_a.sent_json)
                    self.assertEqual([], ws_b.sent_json)

                    # (iii) Originating ws_a closes/disconnects -> reply DROPPED, NEVER falls back to ws_b, latest_clip untouched!
                    cur_tgen = hub.takeover_gen
                    hub._pending_sync_extracts["req-ws-closed"] = {
                        "bot_key": "main",
                        "user_id": 111,
                        "session_gen": sgen,
                        "takeover_gen": cur_tgen,
                        "owner": hub.session_owner,
                        "ws": ws_a,
                        "created_ts": time.monotonic(),
                    }
                    ws_a.closed = True
                    hub.viewers.discard(ws_a)
                    await srv.internal_sync_clipboard(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok", "X-Sync-Lease-Id": lease_id},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            query={},
                            json=mock.AsyncMock(
                                return_value={
                                    "text": "MUST_NOT_FALLBACK_TO_WS_B",
                                    "req_id": "req-ws-closed",
                                    "session_gen": sgen,
                                    "takeover_gen": cur_tgen,
                                }
                            ),
                        )  # type: ignore[arg-type]
                    )
                    self.assertEqual("INITIAL_SAFE_CLIP", hub.latest_clip.get("text"))
                    self.assertEqual([], ws_b.sent_json, "Offline requester WS MUST drop reply, NEVER broadcast to ws_b!")

                    # (iv) Sync extract queued in sync_cmd_queue with old takeover_gen is dropped on pop_sync_cmds!
                    hub.sync_cmd_queue = [
                        {
                            "action": "extract",
                            "mode": "point",
                            "req_id": "r-stale-q",
                            "session_gen": sgen,
                            "takeover_gen": cur_tgen - 1,
                            "_bot_key": "main",
                            "_user_id": 111,
                        },
                        {
                            "action": "extract",
                            "mode": "point",
                            "req_id": "r-ok-q",
                            "session_gen": sgen,
                            "takeover_gen": cur_tgen,
                            "_bot_key": "main",
                            "_user_id": 111,
                        },
                    ]
                    popped_q = hub.pop_sync_cmds()
                    self.assertEqual(1, len(popped_q))
                    self.assertEqual("r-ok-q", popped_q[0]["req_id"])

                    # 4c. Compound inputs: new_tab, close_tab, and capture -> broadcast_state mid-await revocation!
                    p0 = _FakePage()
                    p1 = _FakePage()
                    created_pages: list[object] = []

                    class _RevokingNewTabPage(_FakePage):
                        def __init__(self) -> None:
                            super().__init__()
                            self.closed = False
                            self.goto = mock.AsyncMock()  # type: ignore[method-assign]

                        def is_closed(self) -> bool:
                            return self.closed

                        async def close(self) -> None:
                            self.closed = True

                    class _RevokingCtx:
                        def __init__(self) -> None:
                            self.pages = [p0, p1]

                        async def new_page(self):
                            np = _RevokingNewTabPage()
                            self.pages.append(np)
                            created_pages.append(np)
                            # Revoke admin 111 during await new_page()!
                            env_main.write_text(
                                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=999\nAGY_TG_ADMIN_USERS=999\n",
                                encoding="utf-8",
                            )
                            return np

                    hub.engine_mode = "async_hosted"
                    hub.ctx = _RevokingCtx()
                    hub.active_tab_index = 0
                    hub.session_owner = ("main", 111)
                    hub.takeover = True
                    hub.takeover_owner = ("main", 111)
                    hub.session_gen = 30
                    hub.takeover_gen = 10
                    rev_before_nt = hub._tab_select_rev
                    await hub._execute_human_cmd_async(
                        {
                            "action": "new_tab",
                            "_bot_key": "main",
                            "_user_id": 111,
                            "_session_gen": 30,
                            "_takeover_gen": 10,
                        }
                    )
                    self.assertEqual(1, len(created_pages))
                    self.assertTrue(created_pages[0].closed, "Revoked new_tab MUST close newly created page!")  # type: ignore[attr-defined]
                    created_pages[0].goto.assert_not_called()  # type: ignore[attr-defined]
                    self.assertEqual(0, hub.active_tab_index)
                    self.assertEqual(rev_before_nt, hub._tab_select_rev)

                    # close_tab: revoke during await close() -> MUST NOT update active_tab_index or _tab_select_rev!
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\nAGY_TG_ADMIN_USERS=111\n",
                        encoding="utf-8",
                    )

                    class _RevokingClosePage(_FakePage):
                        async def close(self) -> None:
                            env_main.write_text(
                                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=999\nAGY_TG_ADMIN_USERS=999\n",
                                encoding="utf-8",
                            )

                    cp0 = _FakePage()
                    cp1 = _RevokingClosePage()
                    hub.ctx = _FakeCtx([cp0, cp1])
                    hub.active_tab_index = 1
                    hub.takeover = True
                    hub.takeover_owner = ("main", 111)
                    hub.takeover_gen = 11
                    rev_before_ct = hub._tab_select_rev
                    await hub._execute_human_cmd_async(
                        {
                            "action": "close_tab",
                            "index": 1,
                            "_bot_key": "main",
                            "_user_id": 111,
                            "_session_gen": 30,
                            "_takeover_gen": 11,
                        }
                    )
                    self.assertEqual(1, hub.active_tab_index, "Revoked close_tab MUST NOT update active_tab_index")
                    self.assertEqual(rev_before_ct, hub._tab_select_rev)

                    # Final capture -> broadcast_state: revoke during _capture_once() -> MUST skip broadcast_state()!
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\nAGY_TG_ADMIN_USERS=111\n",
                        encoding="utf-8",
                    )
                    hub.ctx = _FakeCtx([_FakePage()])
                    hub.active_tab_index = 0
                    hub.takeover = True
                    hub.takeover_owner = ("main", 111)
                    hub.takeover_gen = 12
                    bcast_spy = mock.AsyncMock()

                    async def _revoke_mid_capture(**_kw) -> None:
                        env_main.write_text(
                            f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=999\nAGY_TG_ADMIN_USERS=999\n",
                            encoding="utf-8",
                        )

                    with (
                        mock.patch.object(hub, "_capture_once", side_effect=_revoke_mid_capture),
                        mock.patch.object(hub, "broadcast_state", side_effect=bcast_spy),
                    ):
                        await hub._execute_human_cmd_async(
                            {
                                "action": "press",
                                "key": "Escape",
                                "_bot_key": "main",
                                "_user_id": 111,
                                "_session_gen": 30,
                                "_takeover_gen": 12,
                            }
                        )
                    bcast_spy.assert_not_called()

            asyncio.run(_scenario())

        # 5. Sync mouseup/mousedown edges (live_browser_ctl.py):
        #    (a) original pressed page already closed -> mouseup does NOT fall back to current page!
        #    (b) same button pressed on Page A then again on Page B -> Page A released first!
        import live_browser_ctl as ctl

        class _EdgeMouse:
            def __init__(self) -> None:
                self.downs: list[str] = []
                self.ups: list[str] = []

            def move(self, _x: float, _y: float) -> None:
                pass

            def down(self, button: str = "left") -> None:
                self.downs.append(button)

            def up(self, button: str = "left") -> None:
                self.ups.append(button)

        class _EdgePage:
            def __init__(self) -> None:
                self.url = "about:blank"
                self.closed = False
                self.mouse = _EdgeMouse()

            def is_closed(self) -> bool:
                return self.closed

            def bring_to_front(self) -> None:
                pass

        pa = _EdgePage()
        pb = _EdgePage()
        bridge = ctl.SyncLiveBridge.__new__(ctl.SyncLiveBridge)
        bridge.raw_ctx = types.SimpleNamespace(pages=[pa, pb])
        bridge.active_idx = 0
        bridge.enabled = True
        bridge._held_buttons = {}
        bridge._pinned_verified = False
        bridge._profile_dir = None

        # (a) Press on Page A -> Page A closes -> switch to Page B -> explicit mouseup MUST NOT hit Page B!
        bridge._exec_human_sync({"action": "mousedown", "x": 5, "y": 5, "button": "left"})
        pa.closed = True
        bridge.active_idx = 1
        bridge._exec_human_sync({"action": "mouseup", "x": 20, "y": 20, "button": "left"})
        self.assertEqual([], pb.mouse.ups, "Closed original page mouseup MUST NOT fall back to current page!")
        self.assertEqual({}, bridge._held_buttons)

        # (b) Re-open Page A: press left on Page A -> switch to Page B -> press left on Page B -> Page A MUST release first!
        pa.closed = False
        bridge.active_idx = 0
        bridge._exec_human_sync({"action": "mousedown", "x": 5, "y": 5, "button": "left"})
        bridge.active_idx = 1
        bridge._exec_human_sync({"action": "mousedown", "x": 15, "y": 15, "button": "left"})
        self.assertEqual(["left"], pa.mouse.ups, "Re-pressing same button on Page B MUST release Page A first!")
        self.assertEqual(["left"], pb.mouse.downs)
        bridge._exec_human_sync({"action": "mouseup", "x": 15, "y": 15, "button": "left"})
        self.assertEqual(["left"], pb.mouse.ups)

        # 6. Binary unit consistency (MiB, zero stale MB user-facing strings or wire-level/raw multipart comments)
        srv_src = (REPO_ROOT / ".agents/skills/live-browser/scripts/live_browser_server.py").read_text(encoding="utf-8")
        self.assertNotIn("}MB", srv_src)
        self.assertNotIn("wire-level", srv_src)
        self.assertNotIn("raw incoming multipart stream", srv_src)
        self.assertNotIn("raw multipart request", srv_src)
        self.assertIn("MiB 限制", srv_src)
        self.assertIn("MiB 服务端单文件上限", srv_src)

    def test_round7_unicode_int_card_retire_retry_hosted_extract_sync_dual_gen_real_events_and_origin_gen(self) -> None:
        """Round 7 §3, §4, §6: Unicode digit safety, card retire retry + lock contention, Hosted extract dual-gen cache, Sync mandatory dual-gen, real page/close events, synchronous origin_session_gen."""
        tok_main = "100:MAIN_TOK_R7_FULL"
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp) / "bridge"
            bdir.mkdir(parents=True, exist_ok=True)
            env_main = bdir / ".env"
            env_main.write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\nAGY_TG_ADMIN_USERS=111\n",
                encoding="utf-8",
            )

            # 3a. Strict integer parser rejects Unicode digits like "²" and "٢" safely
            self.assertIsNone(srv._parse_strict_int("²"))
            self.assertIsNone(srv._parse_strict_int("٢"))
            self.assertIsNone(srv._parse_strict_int(True))
            self.assertEqual(42, srv._parse_strict_int("42"))
            self.assertEqual(-7, srv._parse_strict_int("-7"))

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                fake_ws_type = types.SimpleNamespace(TEXT="TEXT", CLOSE="CLOSE")
                init_111 = _signed_init_data(tok_main, 111)

                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "WSMsgType", fake_ws_type),
                    mock.patch.object(srv, "web", _FakeWeb),
                ):
                    # 3a-ws: Sending Unicode "²" in start_browser/switch_profile/stop_browser cleanly rejects WITHOUT crashing/disconnecting WS!
                    class _LifecycleWS:
                        def __init__(self, msgs: list[dict]) -> None:
                            self._msgs = [
                                types.SimpleNamespace(type="TEXT", data=json.dumps(m))
                                for m in msgs
                            ]
                            self.sent: list[dict] = []
                            self.closed = False

                        async def prepare(self, _req) -> None:
                            return None

                        async def receive(self):
                            return self._msgs.pop(0) if self._msgs else types.SimpleNamespace(type="CLOSE", data="")

                        async def send_str(self, s: str) -> None:
                            self.sent.append(json.loads(s))

                        async def send_bytes(self, _b: bytes) -> None:
                            pass

                        async def close(self, **_kw) -> None:
                            self.closed = True

                        def __aiter__(self):
                            return self

                        async def __anext__(self):
                            if self._msgs:
                                return self._msgs.pop(0)
                            raise StopAsyncIteration

                    ws_u = _LifecycleWS(
                        [
                            {"type": "auth", "initData": init_111},
                            {"type": "start_browser", "session_gen": "²"},
                            {"type": "switch_profile", "profile": "default", "session_gen": "²"},
                            {"type": "stop_browser", "session_gen": "²"},
                            {"type": "list_profiles"},
                        ]
                    )

                    class _WSWeb(_FakeWeb):
                        @staticmethod
                        def WebSocketResponse(**_kw):
                            return ws_u

                    with mock.patch.object(srv, "web", _WSWeb):
                        await srv.handle_ws(types.SimpleNamespace(remote="127.0.0.1", app={"hub": hub}))  # type: ignore[arg-type]

                    self.assertFalse(ws_u.closed, "Unicode digit '²' MUST NOT crash/close WebSocket")
                    toasts = [m.get("message", "") for m in ws_u.sent if m.get("type") == "toast"]
                    self.assertEqual(3, sum("会话代次缺失或已变更" in t for t in toasts))
                    self.assertTrue(
                        any(m.get("type") == "profiles_list" for m in ws_u.sent),
                        "WS MUST stay alive after rejecting '²' and still serve subsequent messages!",
                    )

                    # 3b. Periodic card retirement: transient failure retains card for retry (even with latest_jpeg=None & idle);
                    #     succeeding retry removes card; bounded 3-attempt cap; real concurrent tick_updates vs retire_cards lock contention!
                    class _FlakyRetireHTTP:
                        def __init__(self, outcomes: list[object], *, hold_first_gate: asyncio.Event | None = None) -> None:
                            self._outcomes = list(outcomes)
                            self._hold_first_gate = hold_first_gate
                            self.first_entered = asyncio.Event()
                            self.calls: list[tuple[str, dict]] = []

                        def post(self, url: str, **kw):
                            self.calls.append((url, kw))
                            outcome = self._outcomes.pop(0) if self._outcomes else {"ok": True}
                            idx = len(self.calls)
                            outer = self

                            class _Resp:
                                status = outcome.get("http_status", 200) if isinstance(outcome, dict) else 200

                                async def __aenter__(self_r):
                                    if idx == 1 and outer._hold_first_gate is not None:
                                        outer.first_entered.set()
                                        await outer._hold_first_gate.wait()
                                    if isinstance(outcome, Exception):
                                        raise outcome
                                    return self_r

                                async def __aexit__(self_r, *_a):
                                    return False

                                async def json(self_r):
                                    assert isinstance(outcome, dict)
                                    return outcome

                            return _Resp()

                    flaky_http = _FlakyRetireHTTP(
                        [
                            RuntimeError("transient network timeout"),
                            {"ok": True, "result": {"message_id": 888}},
                        ]
                    )
                    hub.tg.http = flaky_http
                    hub.engine_mode = "idle"
                    hub.session_gen = 15
                    hub.latest_jpeg = None  # Even without a frame, stale card retry MUST run!
                    hub.tg.cards[("main", 111)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 888,
                        "session_gen": 14,
                        "owner": ("main", 111),
                        "last_sha1": "s",
                        "last_caption": "c",
                        "last_markup": "m",
                        "last_ts": 0.0,
                    }
                    # Attempt 1: transient failure -> card MUST move to pending_retire_cards with retire_attempts == 1
                    await hub.tg.tick_updates(force=True)
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertIn(("main", 111, 888), hub.tg.pending_retire_cards)
                    self.assertEqual(1, hub.tg.pending_retire_cards[("main", 111, 888)].get("retire_attempts"))
                    # Attempt 2: succeeds -> card MUST be removed
                    await hub.tg.tick_updates(force=True)
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertNotIn(("main", 111, 888), hub.tg.pending_retire_cards)
                    self.assertEqual(2, len(flaky_http.calls))

                    # Bounded 3-attempt cap: 3 consecutive 500s -> retained on attempts 1 & 2, dropped on attempt 3
                    cap_http = _FlakyRetireHTTP(
                        [
                            {"http_status": 500, "ok": False, "description": "Internal Server Error"},
                            {"http_status": 429, "ok": False, "description": "Too Many Requests"},
                            {"http_status": 502, "ok": False, "description": "Bad Gateway"},
                        ]
                    )
                    hub.tg.http = cap_http
                    hub.tg.cards[("main", 111)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 8881,
                        "session_gen": 14,
                        "owner": ("main", 111),
                        "last_sha1": "s",
                        "last_caption": "c",
                        "last_markup": "m",
                        "last_ts": 0.0,
                    }
                    await hub.tg.tick_updates(force=True)
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertIn(("main", 111, 8881), hub.tg.pending_retire_cards)
                    await hub.tg.tick_updates(force=True)
                    self.assertIn(("main", 111, 8881), hub.tg.pending_retire_cards)
                    await hub.tg.tick_updates(force=True)
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertNotIn(
                        ("main", 111, 8881),
                        hub.tg.pending_retire_cards,
                        "Card MUST drop after bounded 3 failed retire attempts",
                    )

                    # Real concurrent lock contention: tick_updates wins lock first, retire_cards waits behind it!
                    gate = asyncio.Event()
                    conc_http = _FlakyRetireHTTP(
                        [{"ok": True, "result": {"message_id": 889}}],
                        hold_first_gate=gate,
                    )
                    hub.tg.http = conc_http
                    hub.tg.cards[("main", 111)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 889,
                        "session_gen": 14,
                        "owner": ("main", 111),
                        "last_sha1": "s",
                        "last_caption": "c",
                        "last_markup": "m",
                        "last_ts": 0.0,
                    }
                    t_tick = asyncio.create_task(hub.tg.tick_updates(force=True))
                    await conc_http.first_entered.wait()
                    t_retire = asyncio.create_task(hub.tg.retire_cards(session_gen=14, mark_finished=True))
                    await asyncio.sleep(0)
                    # While tick_updates holds _lock, retire_cards is genuinely contending on _lock (not done yet)
                    self.assertFalse(t_retire.done())
                    gate.set()
                    await asyncio.gather(t_tick, t_retire)
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertEqual(1, len(conc_http.calls), "Serialized lock contention must retire exactly once")

                    # 4a. Hosted `extract_content_async` (`point` & `range`): takeover_gen change mid-extract MUST NOT pollute `latest_clip`!
                    class _GenBumpingPage(_FakePage):
                        def __init__(self, target_hub, ret_val) -> None:
                            super().__init__("https://extract.example", "Extract")
                            self._hub = target_hub
                            self._ret_val = ret_val

                        async def evaluate(self, _script: str, _arg=None):
                            self._hub.takeover_gen += 1
                            return self._ret_val

                    hub.engine_mode = "async_hosted"
                    hub.session_gen = 20
                    hub.takeover_gen = 5
                    hub.session_owner = ("main", 111)
                    hub.latest_clip = {"text": "SAFE_BEFORE_EXTRACT"}

                    hub.ctx = _FakeCtx(
                        [_GenBumpingPage(hub, {"text": "STALE_POINT", "label": "p"})]
                    )
                    res_pt = await hub.extract_content_async(
                        {"mode": "point", "x": 10, "y": 10},
                        expected_session_gen=20,
                        expected_takeover_gen=5,
                        expected_owner=("main", 111),
                        check_owner=True,
                    )
                    self.assertIsNone(res_pt)
                    self.assertEqual("SAFE_BEFORE_EXTRACT", hub.latest_clip.get("text"))

                    hub.takeover_gen = 6
                    hub.ctx = _FakeCtx([_GenBumpingPage(hub, "STALE_RANGE_TEXT")])
                    res_rg = await hub.extract_content_async(
                        {"mode": "range", "x1": 1, "y1": 1, "x2": 20, "y2": 20},
                        expected_session_gen=20,
                        expected_takeover_gen=6,
                        expected_owner=("main", 111),
                        check_owner=True,
                    )
                    self.assertIsNone(res_rg)
                    self.assertEqual("SAFE_BEFORE_EXTRACT", hub.latest_clip.get("text"))

                    # 4b. Sync `/internal/sync/clipboard` mandatory dual-gen on non-empty `req_id`
                    r_sync = await srv.internal_sync_start(
                        types.SimpleNamespace(
                            headers={"X-Live-Token": "sec-tok"},
                            remote="127.0.0.1",
                            app={"hub": hub},
                            json=mock.AsyncMock(return_value={"bot": "main", "user_id": 111}),
                        )  # type: ignore[arg-type]
                    )
                    lease_id = r_sync.data["sync_lease_id"]
                    sgen = r_sync.data["session_gen"]
                    tgen = hub.takeover_gen
                    ws_t = _FakeWSViewer()
                    hub.viewers = {ws_t}  # type: ignore[assignment]
                    hub.viewer_meta = {ws_t: {"bot_key": "main", "user_id": 111, "role": "admin"}}
                    hub.latest_clip = {"text": "SAFE_SYNC_CLIP"}
                    hub._pending_sync_extracts["req-strict-1"] = {
                        "bot_key": "main",
                        "user_id": 111,
                        "session_gen": sgen,
                        "takeover_gen": tgen,
                        "owner": hub.session_owner,
                        "ws": ws_t,
                        "created_ts": time.monotonic(),
                    }
                    for bad_body in (
                        {"text": "NO_GENS", "req_id": "req-strict-1"},
                        {"text": "MISSING_TGEN", "req_id": "req-strict-1", "session_gen": sgen},
                        {"text": "MISSING_SGEN", "req_id": "req-strict-1", "takeover_gen": tgen},
                        {"text": "UNICODE_TGEN", "req_id": "req-strict-1", "session_gen": sgen, "takeover_gen": "²"},
                        {"text": "UNICODE_SGEN", "req_id": "req-strict-1", "session_gen": "²", "takeover_gen": tgen},
                    ):
                        r_bad = await srv.internal_sync_clipboard(
                            types.SimpleNamespace(
                                headers={"X-Live-Token": "sec-tok", "X-Sync-Lease-Id": lease_id},
                                remote="127.0.0.1",
                                app={"hub": hub},
                                query={},
                                json=mock.AsyncMock(return_value=bad_body),
                            )  # type: ignore[arg-type]
                        )
                        self.assertEqual(400, r_bad.status, f"Expected 400 for {bad_body}")
                    self.assertEqual("SAFE_SYNC_CLIP", hub.latest_clip.get("text"))
                    self.assertEqual([], ws_t.sent_json)

                    # 4c. Real `page` and `close` callbacks during `new_tab` / `close_tab` revocation!
                    class _EventfulPage(_FakePage):
                        def __init__(self, url: str = "https://ev.example", *, fail_close: bool = False, on_close_hook=None) -> None:
                            super().__init__(url, "Ev")
                            self.closed = False
                            self._fail_close = fail_close
                            self._on_close_hook = on_close_hook
                            self.listeners: dict[str, list] = {}
                            self.goto = mock.AsyncMock()  # type: ignore[method-assign]

                        def on(self, ev: str, cb) -> None:
                            self.listeners.setdefault(ev, []).append(cb)

                        def is_closed(self) -> bool:
                            return self.closed

                        async def close(self) -> None:
                            if self._on_close_hook is not None:
                                self._on_close_hook()
                            if self._fail_close:
                                raise RuntimeError("revoked new_tab close failed")
                            self.closed = True
                            for cb in list(self.listeners.get("close", [])):
                                cb()

                    class _EventfulCtx:
                        def __init__(self, pages: list[object], new_page_factory=None) -> None:
                            self.pages = list(pages)
                            self.ctx_listeners: dict[str, list] = {}
                            self._factory = new_page_factory

                        def on(self, ev: str, cb) -> None:
                            self.ctx_listeners.setdefault(ev, []).append(cb)

                        async def route(self, _pat: str, _cb) -> None:
                            pass

                        async def new_page(self):
                            p = self._factory()
                            self.pages.append(p)
                            for cb in list(self.ctx_listeners.get("page", [])):
                                cb(p)
                            return p

                    # Start a real hosted session with _EventfulCtx so real `_on_new_page` is registered!
                    created_rev_pages: list[_EventfulPage] = []

                    def _make_revoked_page(*, fail_close: bool = False):
                        p = _EventfulPage("about:blank", fail_close=fail_close)
                        created_rev_pages.append(p)
                        # Revoke admin 111 during new_page() (BEFORE new_page returns!)
                        env_main.write_text(
                            f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=999\nAGY_TG_ADMIN_USERS=999\n",
                            encoding="utf-8",
                        )
                        return p

                    ev_cm_list: list[object] = []

                    class _EvCM:
                        def __init__(self, **_kw) -> None:
                            self.exited = False
                            self.p0 = _EventfulPage("https://p0.example")
                            self.p1 = _EventfulPage("https://p1.example")
                            self.ctx = _EventfulCtx([self.p0, self.p1], new_page_factory=lambda: _make_revoked_page(fail_close=False))
                            ev_cm_list.append(self)

                        async def __aenter__(self):
                            return self.ctx

                        async def __aexit__(self, *_a):
                            self.exited = True

                    hub_ev = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                    with (
                        mock.patch.object(srv, "discover_pinned_host_profile", return_value=None),
                        mock.patch.object(srv, "resolve_camoufox_display", return_value=None),
                        mock.patch.object(srv, "read_x11_clipboard_async", new=mock.AsyncMock(return_value="")),
                        mock.patch.dict(
                            sys.modules,
                            {"camoufox": types.SimpleNamespace(), "camoufox.async_api": types.SimpleNamespace(AsyncCamoufox=_EvCM)},
                        ),
                    ):
                        await hub_ev.start_hosted(actor=("main", 111), source="ws", notify_tg=False)
                        hub_ev.active_tab_index = 0
                        hub_ev.takeover = True
                        hub_ev.takeover_owner = ("main", 111)
                        rev_nt = hub_ev._tab_select_rev
                        await hub_ev._execute_human_cmd_async(
                            {
                                "action": "new_tab",
                                "_bot_key": "main",
                                "_user_id": 111,
                                "_session_gen": hub_ev.session_gen,
                                "_takeover_gen": hub_ev.takeover_gen,
                            }
                        )
                        self.assertEqual(1, len(created_rev_pages))
                        self.assertTrue(created_rev_pages[0].closed)
                        self.assertEqual(0, hub_ev.active_tab_index, "Real ctx.on('page') MUST NOT preemptively switch active_tab_index before post-await auth!")
                        self.assertEqual(rev_nt, hub_ev._tab_select_rev)

                        # Real `close` listener during revoked `close_tab` MUST NOT mutate active_tab_index or _tab_select_rev!
                        env_main.write_text(
                            f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\nAGY_TG_ADMIN_USERS=111\n",
                            encoding="utf-8",
                        )
                        hub_ev.takeover = True
                        hub_ev.takeover_owner = ("main", 111)
                        ev_cm = ev_cm_list[-1]
                        ev_cm.p1._on_close_hook = lambda: env_main.write_text(  # type: ignore[attr-defined]
                            f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=999\nAGY_TG_ADMIN_USERS=999\n",
                            encoding="utf-8",
                        )
                        hub_ev.active_tab_index = 1
                        rev_ct = hub_ev._tab_select_rev
                        await hub_ev._execute_human_cmd_async(
                            {
                                "action": "close_tab",
                                "index": 1,
                                "_bot_key": "main",
                                "_user_id": 111,
                                "_session_gen": hub_ev.session_gen,
                                "_takeover_gen": hub_ev.takeover_gen,
                            }
                        )
                        self.assertTrue(ev_cm.p1.closed, "close_tab must have actually executed p1.close() and fired close listener")  # type: ignore[attr-defined]
                        self.assertEqual(1, hub_ev.active_tab_index)
                        self.assertEqual(rev_ct, hub_ev._tab_select_rev)

                        # Revoked `new_tab` whose `close()` ALSO fails -> fail-closed cleanup aborts hosted session cleanly!
                        env_main.write_text(
                            f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\nAGY_TG_ADMIN_USERS=111\n",
                            encoding="utf-8",
                        )
                        hub_ev.takeover = True
                        hub_ev.takeover_owner = ("main", 111)
                        ev_cm.ctx._factory = lambda: _make_revoked_page(fail_close=True)  # type: ignore[attr-defined]
                        await asyncio.wait_for(
                            hub_ev._execute_human_cmd_async(
                                {
                                    "action": "new_tab",
                                    "_bot_key": "main",
                                    "_user_id": 111,
                                    "_session_gen": hub_ev.session_gen,
                                    "_takeover_gen": hub_ev.takeover_gen,
                                }
                            ),
                            timeout=3.0,
                        )
                        self.assertEqual("idle", hub_ev.engine_mode, "Revoked new_tab whose close() fails MUST abort session fail-closed")
                        self.assertTrue(ev_cm.exited)  # type: ignore[attr-defined]

                    # 6a. Synchronous origin_session_gen capture on dialog & filechooser:
                    #     if session_gen advances BEFORE the scheduled task runs, task MUST NOT register/broadcast into the newer gen!
                    env_main.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\nAGY_TG_ADMIN_USERS=111\n",
                        encoding="utf-8",
                    )
                    hub_og = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                    hub_og.engine_mode = "async_hosted"
                    hub_og.session_gen = 50
                    hub_og.session_owner = ("main", 111)
                    hub_og.takeover = True
                    ws_og = _FakeWSViewer()
                    hub_og.viewers = {ws_og}  # type: ignore[assignment]
                    hub_og.viewer_meta = {ws_og: {"bot_key": "main", "user_id": 111, "role": "admin"}}
                    og_page = _EventfulPage("https://og.example")
                    hub_og._attach_page_listeners(og_page)

                    fake_dialog = types.SimpleNamespace(
                        type="alert",
                        message="Stale Gen Alert",
                        default_value="",
                        dismiss=mock.AsyncMock(),
                    )
                    fake_chooser = types.SimpleNamespace(is_multiple=lambda: False)
                    # Fire both callbacks synchronously at gen=50, then IMMEDIATELY bump session_gen to 51 BEFORE event loop yields!
                    og_page.listeners["dialog"][0](fake_dialog)
                    og_page.listeners["filechooser"][0](fake_chooser)
                    hub_og.session_gen = 51
                    await asyncio.sleep(0.02)
                    fake_dialog.dismiss.assert_awaited_once()
                    self.assertEqual({}, hub_og.pending_dialogs)
                    self.assertEqual({}, hub_og.pending_filechoosers)
                    self.assertEqual([], ws_og.sent_json, "Stale-origin dialog/filechooser MUST NOT broadcast into newer session_gen 51!")

                    # Google ctx.route synchronous origin_session_gen capture: session_gen advances during await route.abort()
                    route_cb_holder: list[object] = []

                    class _RouteCtx:
                        async def route(self, _pat: str, cb) -> None:
                            route_cb_holder.append(cb)

                    with mock.patch.object(
                        srv, "discover_pinned_host_profile", return_value={"name": "pin", "profile_dir": Path(tmp)}
                    ):
                        await hub_og._install_non_pinned_google_guard(_RouteCtx(), is_pinned_verified=False)

                    class _GenBumpingRoute:
                        def __init__(self) -> None:
                            self.aborted = False
                            self.request = types.SimpleNamespace(
                                url="https://accounts.google.com/signin",
                                is_navigation_request=lambda: True,
                                resource_type="document",
                            )

                        async def abort(self, *_a) -> None:
                            self.aborted = True
                            hub_og.session_gen = 52

                        async def continue_(self) -> None:
                            pass

                    r_bump = _GenBumpingRoute()
                    await route_cb_holder[0](r_bump, r_bump.request)  # type: ignore[operator]
                    await asyncio.sleep(0.02)
                    self.assertTrue(r_bump.aborted)
                    self.assertEqual([], ws_og.sent_json, "Google block toast captured at gen=51 MUST NOT deliver into gen=52!")

                    # Verify 413 message explicitly reflects 25 MiB files + 64 KiB multipart overhead
                    srv_txt = (REPO_ROOT / ".agents/skills/live-browser/scripts/live_browser_server.py").read_text(encoding="utf-8")
                    self.assertIn("MiB 文件", srv_txt)
                    self.assertIn("KiB multipart 开销限制", srv_txt)

            asyncio.run(_scenario())

    def test_round8_unified_card_retire_cross_path_and_media_retry(self) -> None:
        """Round 8 Blocker 2: Explicit retire_cards() (caption & final-JPEG editMessageMedia) and periodic tick_updates() share response verification and the 3-attempt retry cap."""
        tok_main = "100:MAIN_TOK_R8_RETIRE"
        with tempfile.TemporaryDirectory() as tmp:
            bdir = Path(tmp) / "bridge"
            bdir.mkdir(parents=True, exist_ok=True)
            (bdir / ".env").write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\nAGY_TG_ADMIN_USERS=111\n",
                encoding="utf-8",
            )

            class _FlakyHTTP:
                def __init__(self, outcomes: list[object], *, hold_first_gate: asyncio.Event | None = None) -> None:
                    self._outcomes = list(outcomes)
                    self._hold_first_gate = hold_first_gate
                    self.first_entered = asyncio.Event()
                    self.calls: list[tuple[str, dict]] = []

                def post(self, url: str, **kw):
                    self.calls.append((url, kw))
                    outcome = self._outcomes.pop(0) if self._outcomes else {"ok": True}
                    idx = len(self.calls)
                    outer = self

                    class _Resp:
                        status = outcome.get("http_status", 200) if isinstance(outcome, dict) else 200

                        async def __aenter__(self_r):
                            if idx == 1 and outer._hold_first_gate is not None:
                                outer.first_entered.set()
                                await outer._hold_first_gate.wait()
                            if isinstance(outcome, Exception):
                                raise outcome
                            return self_r

                        async def __aexit__(self_r, *_a):
                            return False

                        async def json(self_r):
                            assert isinstance(outcome, dict)
                            return outcome

                    return _Resp()

            def _make_card(mid: int, gen: int) -> dict:
                return {
                    "bot_key": "main",
                    "chat_id": 111,
                    "message_id": mid,
                    "session_gen": gen,
                    "owner": ("main", 111),
                    "last_sha1": "s",
                    "last_caption": "c",
                    "last_markup": "m",
                    "last_ts": 0.0,
                }

            async def _scenario() -> None:
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "FormData", _FakeFormData),
                ):
                    # 1. Cross-path concurrent transient failure:
                    #    tick_updates() wins _lock -> 429 (attempt 1, retained)
                    #    queued explicit retire_cards() takes _lock -> 503 (attempt 2, STILL retained!)
                    #    next idle + latest_jpeg=None maintenance tick -> ok=True (attempt 3, succeeds & pops!)
                    gate = asyncio.Event()
                    http_cross = _FlakyHTTP(
                        [
                            {"http_status": 429, "ok": False, "description": "Too Many Requests"},
                            {"http_status": 503, "ok": False, "description": "Service Unavailable"},
                            {"ok": True, "result": {"message_id": 901}},
                        ],
                        hold_first_gate=gate,
                    )
                    hub.tg.http = http_cross
                    hub.engine_mode = "idle"
                    hub.session_gen = 15
                    hub.latest_jpeg = None
                    hub.tg.cards[("main", 111)] = _make_card(901, 14)

                    t_tick = asyncio.create_task(hub.tg.tick_updates(force=True))
                    await asyncio.wait_for(http_cross.first_entered.wait(), timeout=2.0)
                    t_retire = asyncio.create_task(hub.tg.retire_cards(session_gen=14, mark_finished=True))
                    await asyncio.sleep(0)
                    self.assertFalse(t_retire.done(), "retire_cards() must wait behind tick_updates() on _lock")
                    gate.set()
                    _, retired_cnt = await asyncio.gather(t_tick, t_retire)

                    self.assertEqual(0, retired_cnt, "Transient 503 in explicit retire_cards() MUST NOT claim retired")
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertIn(
                        ("main", 111, 901),
                        hub.tg.pending_retire_cards,
                        "Card MUST remain retained in pending_retire_cards after 429 + 503 (< 3 cap)",
                    )
                    self.assertEqual(2, hub.tg.pending_retire_cards[("main", 111, 901)].get("retire_attempts"))
                    self.assertEqual(2, len(http_cross.calls))

                    # Next idle/no-frame periodic maintenance tick succeeds (attempt 3) and removes card
                    await hub.tg.tick_updates(force=False)
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertNotIn(("main", 111, 901), hub.tg.pending_retire_cards)
                    self.assertEqual(3, len(http_cross.calls))

                    # 2. Explicit retire_cards() WITH final_jpeg (editMessageMedia path):
                    #    transient 503 retains record (attempt 1) -> subsequent idle retry succeeds & removes card!
                    http_media = _FlakyHTTP(
                        [
                            {"http_status": 503, "ok": False, "description": "Service Unavailable"},
                            {"ok": True, "result": {"message_id": 902}},
                        ]
                    )
                    hub.tg.http = http_media
                    hub.engine_mode = "idle"
                    hub.session_gen = 17
                    hub.latest_jpeg = None
                    hub.tg.cards[("main", 111)] = _make_card(902, 16)

                    retired_m1 = await hub.tg.retire_cards(
                        session_gen=16, mark_finished=True, final_jpeg=b"FINAL_JPEG_BYTES"
                    )
                    self.assertEqual(0, retired_m1)
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertIn(
                        ("main", 111, 902),
                        hub.tg.pending_retire_cards,
                        "editMessageMedia 503 MUST retain card in pending_retire_cards for retry",
                    )
                    self.assertEqual(1, hub.tg.pending_retire_cards[("main", 111, 902)].get("retire_attempts"))
                    self.assertTrue(http_media.calls[0][0].endswith("/editMessageMedia"))

                    await hub.tg.tick_updates(force=False)
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertNotIn(("main", 111, 902), hub.tg.pending_retire_cards)
                    self.assertTrue(http_media.calls[1][0].endswith("/editMessageCaption"))
                    self.assertEqual(2, len(http_media.calls))

                    # 3. Permanent terminal error on editMessageMedia (`message is not modified`) removes immediately
                    http_perm = _FlakyHTTP(
                        [
                            {"http_status": 400, "ok": False, "error_code": 400, "description": "Bad Request: message is not modified"},
                        ]
                    )
                    hub.tg.http = http_perm
                    hub.tg.cards[("main", 111)] = _make_card(903, 16)
                    retired_perm = await hub.tg.retire_cards(
                        session_gen=16, mark_finished=True, final_jpeg=b"FINAL_JPEG_BYTES"
                    )
                    self.assertEqual(1, retired_perm)
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertNotIn(("main", 111, 903), hub.tg.pending_retire_cards)

                    # 4. Shared 3-attempt cap across explicit (editMessageMedia + caption) & periodic paths
                    http_cap = _FlakyHTTP(
                        [
                            {"http_status": 503, "ok": False, "description": "Service Unavailable"},
                            {"http_status": 429, "ok": False, "description": "Too Many Requests"},
                            RuntimeError("network timeout"),
                        ]
                    )
                    hub.tg.http = http_cap
                    hub.tg.cards[("main", 111)] = _make_card(904, 16)

                    self.assertEqual(
                        0,
                        await hub.tg.retire_cards(session_gen=16, mark_finished=True, final_jpeg=b"FINAL_JPEG_BYTES"),
                    )
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertIn(("main", 111, 904), hub.tg.pending_retire_cards)
                    self.assertEqual(1, hub.tg.pending_retire_cards[("main", 111, 904)].get("retire_attempts"))

                    self.assertEqual(0, await hub.tg.retire_cards(session_gen=16, mark_finished=True))
                    self.assertIn(("main", 111, 904), hub.tg.pending_retire_cards)
                    self.assertEqual(2, hub.tg.pending_retire_cards[("main", 111, 904)].get("retire_attempts"))

                    await hub.tg.tick_updates(force=False)
                    self.assertNotIn(("main", 111), hub.tg.cards)
                    self.assertNotIn(
                        ("main", 111, 904),
                        hub.tg.pending_retire_cards,
                        "Card MUST be dropped once shared retire_attempts reaches cap of 3",
                    )
                    self.assertEqual(3, len(http_cap.calls))

            asyncio.run(_scenario())

    def test_round9_pending_retire_isolated_across_fast_same_owner_rollover_and_stale_callback(self) -> None:
        """Round 9 Blocker: Fast same-owner rollover (new card 702) and early stale callback (701) must never drop 701's retirement retry record."""
        tok_main = "991122:TEST_ROUND9_ROLLOVER_TOKEN"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bdir = root / "bridge"
            bdir.mkdir()
            (bdir / ".env").write_text(
                f"AGY_TG_BOT_TOKEN={tok_main}\nAGY_TG_ALLOWED_CHATS=111\nAGY_TG_ADMIN_USERS=111\n",
                encoding="utf-8",
            )
            cfg_dir = root / "cfg"
            cfg_dir.mkdir()
            prof_dir = root / "profs"
            prof_dir.mkdir()

            class _HostedPage(_FakePage):
                def __init__(self, url: str, title: str, jpeg_bytes: bytes) -> None:
                    super().__init__(url, title)
                    self._jpeg = jpeg_bytes
                    self.closed = False
                    self.goto = mock.AsyncMock()  # type: ignore[method-assign]

                def on(self, _ev: str, _cb) -> None:
                    pass

                def is_closed(self) -> bool:
                    return self.closed

                async def screenshot(self, **_kw):
                    return self._jpeg

                async def close(self) -> None:
                    self.closed = True

            class _HostedCtx:
                def __init__(self, page: _HostedPage) -> None:
                    self.pages = [page]

                def on(self, _ev: str, _cb) -> None:
                    pass

                async def route(self, _pat: str, _cb) -> None:
                    pass

            session_seq = {"n": 0}

            class _RolloverCM:
                def __init__(self, **_kw) -> None:
                    session_seq["n"] += 1
                    idx = session_seq["n"]
                    self.page = _HostedPage(
                        f"https://example.com/session-{idx}/secret-{idx}",
                        f"Session {idx} Private Title",
                        f"JPEG_FRAME_SESSION_{idx}".encode("ascii"),
                    )
                    self.ctx = _HostedCtx(self.page)
                    self.exited = False

                async def __aenter__(self):
                    return self.ctx

                async def __aexit__(self, *_a):
                    self.exited = True

            class _ScriptedTGHTTP:
                def __init__(self, outcomes: dict[str, list[object]]) -> None:
                    self._outcomes = {k: list(v) for k, v in outcomes.items()}
                    self.calls: list[tuple[str, dict]] = []

                def post(self, url: str, data=None, json=None):
                    endpoint = url.rsplit("/", 1)[-1]
                    rec = {
                        "endpoint": endpoint,
                        "fields": dict(getattr(data, "fields", {})) if data is not None else None,
                        "json": dict(json) if isinstance(json, dict) else json,
                    }
                    self.calls.append((endpoint, rec))
                    queue = self._outcomes.get(endpoint)
                    outcome = queue.pop(0) if queue else {"ok": True}

                    class _Resp:
                        status = outcome.get("http_status", 200) if isinstance(outcome, dict) else 200

                        async def __aenter__(self_r):
                            if isinstance(outcome, Exception):
                                raise outcome
                            return self_r

                        async def __aexit__(self_r, *_a):
                            return False

                        async def json(self_r):
                            assert isinstance(outcome, dict)
                            return outcome

                    return _Resp()

            async def _setup_retired_503_card(
                http_mock: _ScriptedTGHTTP,
            ) -> srv.LiveBrowserHub:
                """Start a real hosted session, publish card 701, stop_hosted -> editMessageMedia(701) hits 503."""
                hub = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                hub.tg.http = http_mock
                await hub.start_hosted(
                    profile="r9-prof",
                    notify_tg=False,
                    actor=("main", 111),
                    source="tg_cmd",
                )
                hub.latest_jpeg = b"GEN1_FRAME_701"
                card1 = await hub.tg.ensure_card("main", preferred_user_id=111)
                self.assertIsNotNone(card1)
                assert card1 is not None
                self.assertEqual(701, card1["message_id"])
                self.assertIn(("main", 111), hub.tg.cards)

                await hub.stop_hosted(notify_finished=True)
                self.assertEqual("idle", hub.engine_mode)
                self.assertNotIn(("main", 111), hub.tg.cards)
                self.assertIn(("main", 111, 701), hub.tg.pending_retire_cards)
                self.assertEqual(1, hub.tg.pending_retire_cards[("main", 111, 701)].get("retire_attempts"))
                media_calls = [c for c in http_mock.calls if c[0] == "editMessageMedia"]
                self.assertEqual(1, len(media_calls))
                self.assertEqual("701", media_calls[0][1]["fields"]["message_id"])
                return hub

            async def _scenario() -> None:
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "CONFIG_DIR", cfg_dir),
                    mock.patch.object(srv, "PROFILES_FILE", cfg_dir / "profiles.json"),
                    mock.patch.object(srv, "PROFILES_DATA_DIR", prof_dir),
                    mock.patch.object(srv, "discover_pinned_host_profile", return_value=None),
                    mock.patch.object(srv, "resolve_camoufox_display", return_value=None),
                    mock.patch.object(srv, "read_x11_clipboard_async", new=mock.AsyncMock(return_value="")),
                    mock.patch.object(srv, "FormData", _FakeFormData),
                    mock.patch.dict(
                        sys.modules,
                        {
                            "camoufox": types.SimpleNamespace(),
                            "camoufox.async_api": types.SimpleNamespace(AsyncCamoufox=_RolloverCM),
                        },
                    ),
                ):
                    srv.create_profile("r9-prof", {"os": "linux", "persistent": False})

                    # Branch 1 (Control): stay idle (latest_jpeg=None, hub.tg.cards empty) ->
                    # real `_tg_maintenance_loop` iteration drains `pending_retire_cards` & retires 701!
                    http_ctrl = _ScriptedTGHTTP(
                        {
                            "sendPhoto": [{"ok": True, "result": {"message_id": 701}}],
                            "editMessageMedia": [
                                {"http_status": 503, "ok": False, "description": "Service Unavailable"}
                            ],
                            "editMessageCaption": [{"ok": True, "result": {"message_id": 701}}],
                        }
                    )
                    hub1 = await _setup_retired_503_card(http_ctrl)
                    self.assertIsNone(hub1.latest_jpeg)
                    self.assertEqual({}, hub1.tg.cards)

                    async def _stop_after_one_tick(_delay: float) -> None:
                        raise asyncio.CancelledError()

                    with mock.patch.object(srv.asyncio, "sleep", side_effect=_stop_after_one_tick):
                        await hub1._tg_maintenance_loop()
                    self.assertNotIn(("main", 111, 701), hub1.tg.pending_retire_cards)
                    cap_calls1 = [c for c in http_ctrl.calls if c[0] == "editMessageCaption"]
                    self.assertEqual(1, len(cap_calls1))
                    self.assertEqual(701, cap_calls1[0][1]["json"]["message_id"])
                    self.assertEqual({"inline_keyboard": []}, cap_calls1[0][1]["json"]["reply_markup"])
                    self.assertIn("远端浏览器会话已结束", cap_calls1[0][1]["json"]["caption"])

                    # Branch 2 (Fast same-owner rollover + new card 702):
                    # New card 702 MUST NOT overwrite 701's retry record; maintenance updates 702 AND retires 701!
                    http_roll = _ScriptedTGHTTP(
                        {
                            "sendPhoto": [
                                {"ok": True, "result": {"message_id": 701}},
                                {"ok": True, "result": {"message_id": 702}},
                                {"ok": True, "result": {"message_id": 703}},
                            ],
                            "editMessageMedia": [
                                {"http_status": 503, "ok": False, "description": "Service Unavailable"},
                                {"ok": True, "result": {"message_id": 702}},
                                {"ok": True, "result": {"message_id": 702}},
                            ],
                            "editMessageCaption": [
                                {"ok": True, "result": {"message_id": 701}},
                                {"ok": True, "result": {"message_id": 702}},
                            ],
                        }
                    )
                    hub2 = await _setup_retired_503_card(http_roll)
                    await hub2.start_hosted(
                        profile="r9-prof",
                        notify_tg=False,
                        actor=("main", 111),
                        source="tg_cmd",
                    )
                    hub2.title = "TOP_SECRET_NEW_SESSION_TITLE"
                    hub2.url = "https://secret-new-session.example/vault"
                    hub2.latest_jpeg = b"GEN2_FRAME_702"
                    card2 = await hub2.tg.ensure_card("main", preferred_user_id=111)
                    self.assertIsNotNone(card2)
                    assert card2 is not None
                    self.assertEqual(702, card2["message_id"])
                    self.assertEqual(702, hub2.tg.cards[("main", 111)]["message_id"])
                    self.assertIn(
                        ("main", 111, 701),
                        hub2.tg.pending_retire_cards,
                        "Publishing new card 702 MUST NOT overwrite 701's pending_retire_cards entry",
                    )
                    self.assertEqual(1, hub2.tg.pending_retire_cards[("main", 111, 701)].get("retire_attempts"))

                    # Maintenance tick while new session + card 702 are active:
                    # - updates active card 702 via editMessageMedia
                    # - retires stale card 701 via stateless editMessageCaption (fixed copy + empty keyboard)
                    hub2.latest_jpeg = b"GEN2_FRAME_702_UPDATED"
                    await hub2.tg.tick_updates(force=True)
                    self.assertEqual(702, hub2.tg.cards[("main", 111)]["message_id"])
                    self.assertNotIn(("main", 111, 701), hub2.tg.pending_retire_cards)
                    cap_calls2 = [c for c in http_roll.calls if c[0] == "editMessageCaption"]
                    self.assertEqual(1, len(cap_calls2))
                    self.assertEqual(701, cap_calls2[0][1]["json"]["message_id"])
                    self.assertEqual({"inline_keyboard": []}, cap_calls2[0][1]["json"]["reply_markup"])
                    self.assertIn("远端浏览器会话已结束", cap_calls2[0][1]["json"]["caption"])
                    self.assertNotIn("TOP_SECRET_NEW_SESSION_TITLE", cap_calls2[0][1]["json"]["caption"])
                    self.assertNotIn("secret-new-session.example", cap_calls2[0][1]["json"]["caption"])
                    live_media_702 = [
                        c for c in http_roll.calls
                        if c[0] == "editMessageMedia" and c[1]["fields"]["message_id"] == "702"
                    ]
                    self.assertEqual(1, len(live_media_702))

                    # Subsequent maintenance tick MUST NOT retry 701 again, while 702 continues updating
                    hub2.latest_jpeg = b"GEN2_FRAME_702_UPDATED_2"
                    await hub2.tg.tick_updates(force=True)
                    self.assertEqual(1, len([c for c in http_roll.calls if c[0] == "editMessageCaption"]))
                    self.assertEqual(
                        2,
                        len([
                            c for c in http_roll.calls
                            if c[0] == "editMessageMedia" and c[1]["fields"]["message_id"] == "702"
                        ]),
                    )

                    # force_new replacement (702 -> 703) also stages 702 into pending_retire_cards without dropping it
                    card3 = await hub2.tg.ensure_card("main", force_new=True, preferred_user_id=111)
                    self.assertIsNotNone(card3)
                    assert card3 is not None
                    self.assertEqual(703, card3["message_id"])
                    self.assertIn(("main", 111, 702), hub2.tg.pending_retire_cards)
                    await hub2.tg.tick_updates(force=False)
                    self.assertNotIn(("main", 111, 702), hub2.tg.pending_retire_cards)
                    self.assertEqual(
                        [701, 702],
                        [c[1]["json"]["message_id"] for c in http_roll.calls if c[0] == "editMessageCaption"],
                    )
                    await hub2.stop_hosted(notify_finished=False)

                    # Branch 3 (Fast same-owner rollover + stale callback for 701 arrives BEFORE new card 702):
                    # Stale callback MUST be strictly rejected AND MUST NOT delete 701's retry record!
                    http_cb = _ScriptedTGHTTP(
                        {
                            "sendPhoto": [{"ok": True, "result": {"message_id": 701}}],
                            "editMessageMedia": [
                                {"http_status": 503, "ok": False, "description": "Service Unavailable"}
                            ],
                            "editMessageCaption": [
                                {"ok": True, "result": {"message_id": 701}},
                                {"http_status": 503, "ok": False, "description": "Service Unavailable"},
                                {"http_status": 429, "ok": False, "description": "Too Many Requests"},
                            ],
                        }
                    )
                    hub3 = await _setup_retired_503_card(http_cb)
                    await hub3.start_hosted(
                        profile="r9-prof",
                        notify_tg=False,
                        actor=("main", 111),
                        source="tg_cmd",
                    )
                    # New session is running, NO new card published yet; old button callback (701) arrives first!
                    ok_v, _msg_v, tok_v = hub3.tg.verify_card_control(
                        "main", 111, message_id=701, require_card=True, require_running=True
                    )
                    self.assertFalse(ok_v, "Old card 701 callback MUST be rejected in new session")
                    self.assertIsNone(tok_v)
                    ok_to, _msg_to, _sgen_to, _tgen_to = await hub3.set_takeover(
                        True,
                        reason="stale-btn",
                        actor=("main", 111),
                        card_message_id=701,
                        require_card=True,
                    )
                    self.assertFalse(ok_to, "Old card 701 MUST NOT take over new session")
                    self.assertFalse(hub3.takeover)
                    self.assertIn(
                        ("main", 111, 701),
                        hub3.tg.pending_retire_cards,
                        "Rejecting old callback MUST NOT delete 701's pending_retire_cards record",
                    )
                    self.assertEqual(1, hub3.tg.pending_retire_cards[("main", 111, 701)].get("retire_attempts"))

                    # Maintenance tick retires 701 cleanly even before any new card is created
                    await hub3.tg.tick_updates(force=False)
                    self.assertNotIn(("main", 111, 701), hub3.tg.pending_retire_cards)
                    cap_calls3 = [c for c in http_cb.calls if c[0] == "editMessageCaption"]
                    self.assertEqual(1, len(cap_calls3))
                    self.assertEqual(701, cap_calls3[0][1]["json"]["message_id"])

                    # Branch 3b: If a stale card (mid=705, retire_attempts=1) is STILL in `hub.tg.cards`
                    # when its old callback arrives, verify_card_control MUST reject AND migrate it to
                    # `pending_retire_cards` preserving `retire_attempts`, then cap cleanly at 3!
                    hub3.tg.cards[("main", 111)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 705,
                        "session_gen": hub3.session_gen - 1,
                        "owner": ("main", 111),
                        "retire_attempts": 1,
                        "last_sha1": "s",
                        "last_caption": "c",
                        "last_markup": "m",
                        "last_ts": 0.0,
                    }
                    ok_v2, _msg_v2, _tok_v2 = hub3.tg.verify_card_control(
                        "main", 111, message_id=705, require_card=True, require_running=True
                    )
                    self.assertFalse(ok_v2)
                    self.assertNotIn(("main", 111), hub3.tg.cards)
                    self.assertIn(("main", 111, 705), hub3.tg.pending_retire_cards)
                    self.assertEqual(1, hub3.tg.pending_retire_cards[("main", 111, 705)].get("retire_attempts"))

                    # Attempt 2 (503) -> retained with retire_attempts == 2
                    await hub3.tg.tick_updates(force=False)
                    self.assertIn(("main", 111, 705), hub3.tg.pending_retire_cards)
                    self.assertEqual(2, hub3.tg.pending_retire_cards[("main", 111, 705)].get("retire_attempts"))

                    # Attempt 3 (429) -> reaches shared cap of 3 and is safely dropped!
                    await hub3.tg.tick_updates(force=False)
                    self.assertNotIn(("main", 111, 705), hub3.tg.pending_retire_cards)
                    await hub3.stop_hosted(notify_finished=False)

            asyncio.run(_scenario())

    def test_round10_live_rbac_recheck_before_every_retire_and_orphan_request(self) -> None:
        """Round 10 Final Fix: Re-verify live RBAC inside lock right before EVERY outbound retire/orphan TG request; drop all active & pending cards immediately on revocation with zero new requests."""
        tok_main = "991122:TEST_ROUND10_RBAC_TOKEN"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bdir = root / "bridge"
            bdir.mkdir()
            env_path = bdir / ".env"

            def _set_role(role: str) -> None:
                if role == "admin":
                    env_path.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\n"
                        f"AGY_TG_ALLOWED_CHATS=111\n"
                        f"AGY_TG_ADMIN_USERS=111\n",
                        encoding="utf-8",
                    )
                elif role == "readonly":
                    env_path.write_text(
                        f"AGY_TG_BOT_TOKEN={tok_main}\n"
                        f"AGY_TG_ALLOWED_CHATS=111\n"
                        f"AGY_TG_READONLY_USERS=111\n"
                        f"AGY_TG_USER_ROLES=111:readonly\n",
                        encoding="utf-8",
                    )
                else:
                    raise ValueError(role)

            _set_role("admin")
            cfg_dir = root / "cfg"
            cfg_dir.mkdir()
            prof_dir = root / "profs"
            prof_dir.mkdir()

            class _HostedPage(_FakePage):
                def __init__(self, url: str, title: str, jpeg_bytes: bytes) -> None:
                    super().__init__(url, title)
                    self._jpeg = jpeg_bytes
                    self.closed = False
                    self.goto = mock.AsyncMock()  # type: ignore[method-assign]

                def on(self, _ev: str, _cb) -> None:
                    pass

                def is_closed(self) -> bool:
                    return self.closed

                async def screenshot(self, **_kw):
                    return self._jpeg

                async def close(self) -> None:
                    self.closed = True

            class _HostedCtx:
                def __init__(self, page: _HostedPage) -> None:
                    self.pages = [page]

                def on(self, _ev: str, _cb) -> None:
                    pass

                async def route(self, _pat: str, _cb) -> None:
                    pass

            class _CM:
                def __init__(self, **_kw) -> None:
                    self.page = _HostedPage(
                        "https://example.com/r10",
                        "Round 10 Hosted",
                        b"JPEG_R10_FRAME",
                    )
                    self.ctx = _HostedCtx(self.page)

                async def __aenter__(self):
                    return self.ctx

                async def __aexit__(self, *_a):
                    return False

            class _GatedTGHTTP:
                """Mock aiohttp session supporting deterministic mid-flight gates per endpoint/call."""

                def __init__(
                    self,
                    outcomes: dict[str, list[object]],
                    gates: dict[tuple[str, int], tuple[asyncio.Event, asyncio.Event]] | None = None,
                ) -> None:
                    self._outcomes = {k: list(v) for k, v in outcomes.items()}
                    self._gates = gates or {}
                    self._ep_counts: dict[str, int] = {}
                    self.calls: list[tuple[str, dict]] = []

                def post(self, url: str, data=None, json=None):
                    endpoint = url.rsplit("/", 1)[-1]
                    idx = self._ep_counts.get(endpoint, 0) + 1
                    self._ep_counts[endpoint] = idx
                    rec = {
                        "endpoint": endpoint,
                        "fields": dict(getattr(data, "fields", {})) if data is not None else None,
                        "json": dict(json) if isinstance(json, dict) else json,
                    }
                    self.calls.append((endpoint, rec))
                    queue = self._outcomes.get(endpoint)
                    outcome = queue.pop(0) if queue else {"ok": True}
                    gate = self._gates.get((endpoint, idx))

                    class _Resp:
                        status = outcome.get("http_status", 200) if isinstance(outcome, dict) else 200

                        async def __aenter__(self_r):
                            if gate is not None:
                                entered, release = gate
                                entered.set()
                                await release.wait()
                            if isinstance(outcome, Exception):
                                raise outcome
                            return self_r

                        async def __aexit__(self_r, *_a):
                            return False

                        async def json(self_r):
                            assert isinstance(outcome, dict)
                            return outcome

                    return _Resp()

            async def _scenario() -> None:
                with (
                    mock.patch.object(srv, "_BRIDGE_DIR", bdir),
                    mock.patch.object(srv, "BRIDGE_ENV_FILES", {"main": env_path}),
                    mock.patch.object(srv, "CONFIG_DIR", cfg_dir),
                    mock.patch.object(srv, "PROFILES_FILE", cfg_dir / "profiles.json"),
                    mock.patch.object(srv, "PROFILES_DATA_DIR", prof_dir),
                    mock.patch.object(srv, "discover_pinned_host_profile", return_value=None),
                    mock.patch.object(srv, "resolve_camoufox_display", return_value=None),
                    mock.patch.object(srv, "read_x11_clipboard_async", new=mock.AsyncMock(return_value="")),
                    mock.patch.object(srv, "FormData", _FakeFormData),
                    mock.patch.dict(
                        sys.modules,
                        {
                            "camoufox": types.SimpleNamespace(),
                            "camoufox.async_api": types.SimpleNamespace(AsyncCamoufox=_CM),
                        },
                    ),
                ):
                    srv.create_profile("r10-prof", {"os": "linux", "persistent": False})

                    # ------------------------------------------------------------------
                    # Case 1 (Round 9 Blocker exact repro): Batch retire mid-flight downgrade
                    # Same gen publishes 701, then force_new publishes 702 (701 in pending, 702 active).
                    # Real stop_hosted() suspends on editMessageMedia(701); downgrade 111 admin -> readonly
                    # while 701 is in flight; release 701 with 503 -> MUST NEVER send 702 AND MUST drop
                    # all active + pending cards for ("main", 111) immediately!
                    # ------------------------------------------------------------------
                    _set_role("admin")
                    g1_entered, g1_release = asyncio.Event(), asyncio.Event()
                    http1 = _GatedTGHTTP(
                        outcomes={
                            "sendPhoto": [
                                {"ok": True, "result": {"message_id": 701}},
                                {"ok": True, "result": {"message_id": 702}},
                            ],
                            "editMessageMedia": [
                                {"http_status": 503, "ok": False, "description": "Service Unavailable"},
                                {"ok": True, "result": {"message_id": 702}},
                            ],
                        },
                        gates={("editMessageMedia", 1): (g1_entered, g1_release)},
                    )
                    hub1 = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                    hub1.tg.http = http1
                    await hub1.start_hosted(
                        profile="r10-prof",
                        notify_tg=False,
                        actor=("main", 111),
                        source="tg_cmd",
                    )
                    hub1.latest_jpeg = b"GEN1_FRAME_R10"
                    c701 = await hub1.tg.ensure_card("main", preferred_user_id=111)
                    c702 = await hub1.tg.ensure_card("main", force_new=True, preferred_user_id=111)
                    self.assertIsNotNone(c701)
                    self.assertIsNotNone(c702)
                    self.assertIn(("main", 111, 701), hub1.tg.pending_retire_cards)
                    self.assertEqual(702, hub1.tg.cards[("main", 111)]["message_id"])

                    stop_task = asyncio.create_task(hub1.stop_hosted(notify_finished=True))
                    await asyncio.wait_for(g1_entered.wait(), timeout=2.0)

                    # Downgrade user from admin -> readonly while 701 is in flight
                    _set_role("readonly")
                    self.assertEqual("readonly", srv.load_bot_credentials_with_rbac()[4]["main"][111])
                    g1_release.set()
                    await asyncio.wait_for(stop_task, timeout=2.0)

                    media_calls1 = [c for c in http1.calls if c[0] == "editMessageMedia"]
                    cap_calls1 = [c for c in http1.calls if c[0] == "editMessageCaption"]
                    self.assertEqual(
                        ["701"],
                        [c[1]["fields"]["message_id"] for c in media_calls1],
                        "MUST NOT initiate editMessageMedia(702) after mid-flight RBAC downgrade!",
                    )
                    self.assertEqual([], cap_calls1, "MUST NOT initiate editMessageCaption(702) after downgrade!")
                    self.assertNotIn(("main", 111), hub1.tg.cards)
                    self.assertEqual(
                        [],
                        [k for k in hub1.tg.pending_retire_cards if k[0] == "main" and k[1] == 111],
                        "All pending_retire_cards for revoked (main, 111) MUST be cleared immediately",
                    )

                    # Bonus sub-check: direct _update_card_locked(..., finished=True) and retire_cards(session_gen=old)
                    # while revoked MUST also send ZERO requests and clear BOTH active & pending cards for (main, 111).
                    hub1.tg.cards[("main", 111)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 790,
                        "session_gen": 99,
                        "owner": ("main", 111),
                        "last_sha1": "s",
                        "last_caption": "c",
                        "last_markup": "m",
                        "last_ts": 0.0,
                    }
                    hub1.tg.pending_retire_cards[("main", 111, 789)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 789,
                        "session_gen": 98,
                        "owner": ("main", 111),
                    }
                    calls_before = len(http1.calls)
                    async with hub1.tg._lock:
                        ok_fin = await hub1.tg._update_card_locked(
                            ("main", 111),
                            tok_main,
                            finished=True,
                            force=True,
                            allow_stale_gen=True,
                            jpeg_override=b"STALE_JPEG",
                            card_override=hub1.tg.pending_retire_cards[("main", 111, 789)],
                        )
                    self.assertFalse(ok_fin)
                    self.assertEqual(calls_before, len(http1.calls), "_update_card_locked(finished=True) MUST re-check live RBAC")
                    self.assertNotIn(("main", 111), hub1.tg.cards)
                    self.assertEqual({}, hub1.tg.pending_retire_cards)

                    # Also check retire_cards(session_gen=old) when already revoked clears newer-gen active card too
                    hub1.tg.cards[("main", 111)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 792,
                        "session_gen": 100,
                        "owner": ("main", 111),
                    }
                    hub1.tg.pending_retire_cards[("main", 111, 791)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 791,
                        "session_gen": 99,
                        "owner": ("main", 111),
                    }
                    await hub1.tg.retire_cards(session_gen=99, mark_finished=True)
                    self.assertEqual(calls_before, len(http1.calls))
                    self.assertNotIn(("main", 111), hub1.tg.cards)
                    self.assertEqual({}, hub1.tg.pending_retire_cards)

                    # ------------------------------------------------------------------
                    # Case 2: tick_updates() with multiple pending_retire_cards (701, 702)
                    # Suspend editMessageCaption(701), downgrade admin -> readonly, release 503 ->
                    # MUST NOT send 702 and MUST clear all active + pending cards immediately!
                    # ------------------------------------------------------------------
                    _set_role("admin")
                    g2_entered, g2_release = asyncio.Event(), asyncio.Event()
                    http2 = _GatedTGHTTP(
                        outcomes={
                            "editMessageCaption": [
                                {"http_status": 503, "ok": False, "description": "Service Unavailable"},
                                {"ok": True, "result": {"message_id": 702}},
                            ],
                        },
                        gates={("editMessageCaption", 1): (g2_entered, g2_release)},
                    )
                    hub2 = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                    hub2.tg.http = http2
                    hub2.engine_mode = "idle"
                    hub2.tg.pending_retire_cards[("main", 111, 701)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 701,
                        "session_gen": 1,
                        "owner": ("main", 111),
                    }
                    hub2.tg.pending_retire_cards[("main", 111, 702)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 702,
                        "session_gen": 1,
                        "owner": ("main", 111),
                    }

                    tick_task = asyncio.create_task(hub2.tg.tick_updates(force=False))
                    await asyncio.wait_for(g2_entered.wait(), timeout=2.0)

                    _set_role("readonly")
                    g2_release.set()
                    await asyncio.wait_for(tick_task, timeout=2.0)

                    cap_calls2 = [c for c in http2.calls if c[0] == "editMessageCaption"]
                    self.assertEqual(
                        [701],
                        [c[1]["json"]["message_id"] for c in cap_calls2],
                        "tick_updates() MUST NOT initiate editMessageCaption(702) after mid-flight downgrade!",
                    )
                    self.assertEqual({}, hub2.tg.cards)
                    self.assertEqual({}, hub2.tg.pending_retire_cards)

                    # ------------------------------------------------------------------
                    # Case 3: ensure_card() sendPhoto in-flight downgrade -> ZERO orphan editMessageCaption!
                    # Suspend sendPhoto, downgrade admin -> readonly, release sendPhoto returning 709 ->
                    # MUST send ZERO editMessageCaption(709), register NO active/pending card, and drop prior records!
                    # ------------------------------------------------------------------
                    _set_role("admin")
                    g3_entered, g3_release = asyncio.Event(), asyncio.Event()
                    http3 = _GatedTGHTTP(
                        outcomes={
                            "sendPhoto": [{"ok": True, "result": {"message_id": 709}}],
                            "editMessageCaption": [{"ok": True, "result": {"message_id": 709}}],
                        },
                        gates={("sendPhoto", 1): (g3_entered, g3_release)},
                    )
                    hub3 = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                    hub3.tg.http = http3
                    await hub3.start_hosted(
                        profile="r10-prof",
                        notify_tg=False,
                        actor=("main", 111),
                        source="tg_cmd",
                    )
                    hub3.latest_jpeg = b"GEN1_FRAME_709"
                    # Pre-existing pending record for same (main, 111) should also be dropped on revocation
                    hub3.tg.pending_retire_cards[("main", 111, 700)] = {
                        "bot_key": "main",
                        "chat_id": 111,
                        "message_id": 700,
                        "session_gen": 0,
                        "owner": ("main", 111),
                    }

                    send_task = asyncio.create_task(hub3.tg.ensure_card("main", preferred_user_id=111))
                    await asyncio.wait_for(g3_entered.wait(), timeout=2.0)

                    _set_role("readonly")
                    g3_release.set()
                    res_card = await asyncio.wait_for(send_task, timeout=2.0)
                    self.assertIsNone(res_card)
                    self.assertEqual(
                        ["sendPhoto"],
                        [c[0] for c in http3.calls],
                        "Revoked in-flight sendPhoto MUST NOT follow up with orphan editMessageCaption(709)!",
                    )
                    self.assertNotIn(("main", 111), hub3.tg.cards)
                    self.assertEqual({}, hub3.tg.pending_retire_cards)
                    await hub3.stop_hosted(notify_finished=False)

                    # ------------------------------------------------------------------
                    # Case 4: Authorized control (admin unchanged)
                    # force_new dual-card stop retries both 701 & 702 cleanly and enforces shared 3-attempt cap per card.
                    # ------------------------------------------------------------------
                    _set_role("admin")
                    http4 = _GatedTGHTTP(
                        outcomes={
                            "sendPhoto": [
                                {"ok": True, "result": {"message_id": 701}},
                                {"ok": True, "result": {"message_id": 702}},
                            ],
                            "editMessageMedia": [
                                {"http_status": 503, "ok": False, "description": "Service Unavailable"},
                                {"http_status": 429, "ok": False, "description": "Too Many Requests"},
                            ],
                            "editMessageCaption": [
                                {"http_status": 503, "ok": False, "description": "Service Unavailable"},
                                {"ok": True, "result": {"message_id": 702}},
                                {"http_status": 503, "ok": False, "description": "Service Unavailable"},
                            ],
                        },
                    )
                    hub4 = srv.LiveBrowserHub({"host": "127.0.0.1", "port": 18795, "public_url": ""}, "sec-tok")
                    hub4.tg.http = http4
                    await hub4.start_hosted(
                        profile="r10-prof",
                        notify_tg=False,
                        actor=("main", 111),
                        source="tg_cmd",
                    )
                    hub4.latest_jpeg = b"GEN1_AUTH_OK"
                    await hub4.tg.ensure_card("main", preferred_user_id=111)
                    await hub4.tg.ensure_card("main", force_new=True, preferred_user_id=111)

                    await hub4.stop_hosted(notify_finished=True)
                    media_mids4 = [c[1]["fields"]["message_id"] for c in http4.calls if c[0] == "editMessageMedia"]
                    self.assertEqual(["701", "702"], media_mids4, "Authorized admin stop MUST attempt both 701 & 702")
                    self.assertEqual(1, hub4.tg.pending_retire_cards[("main", 111, 701)].get("retire_attempts"))
                    self.assertEqual(1, hub4.tg.pending_retire_cards[("main", 111, 702)].get("retire_attempts"))

                    # Tick 2: 701 gets 503 (attempt 2 -> retained), 702 gets 200 ok (retired & popped)
                    await hub4.tg.tick_updates(force=False)
                    self.assertEqual(2, hub4.tg.pending_retire_cards[("main", 111, 701)].get("retire_attempts"))
                    self.assertNotIn(("main", 111, 702), hub4.tg.pending_retire_cards)

                    # Tick 3: 701 gets 503 (attempt 3 -> hits shared cap of 3 and is popped)
                    await hub4.tg.tick_updates(force=False)
                    self.assertNotIn(("main", 111, 701), hub4.tg.pending_retire_cards)
                    self.assertEqual({}, hub4.tg.pending_retire_cards)

            asyncio.run(_scenario())


if __name__ == "__main__":
    unittest.main()
