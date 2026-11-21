#!/usr/bin/env python3
"""Offline unit & integration tests for multimodal attachments & workspace `@` context files.

Covers `studio/attachment_service.py`, `studio/chat_service.py`, `studio/room_service.py`,
and `studio/data_sources.py`:
- Valid image (PNG/JPEG/GIF/WebP), PDF, code, and audio/video upload + `att_id` resolution
- Rejection of `.svg` / `.svgz`, unsupported extensions, empty files, and forged bitmap magic bytes
- 4-layer write gate on `POST /api/chat/attachments` (Origin / Content-Type / Auth / CSRF / RBAC)
- `GET /api/chat/attachments/{id}`: `nosniff`, `private` cache-control, `inline` only for verified
  bitmaps (with `?download=1` override) and `attachment` forced for non-images / tampered files
- `context_files` sandbox blocking `..`, absolute paths, symlinks, `.env`, `*.token`, `.git`
- Attachment-only send (empty prompt/content) prompt injection and zero host-path leakage in
  API responses and `readonly` session/room views
"""

from __future__ import annotations

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
from aiohttp.test_utils import TestClient, TestServer

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import studio_ipc  # noqa: E402
from studio.attachment_service import (  # noqa: E402
    StudioAttachmentService,
    is_valid_attachment_id,
)
from studio.auth import (  # noqa: E402
    SESSION_COOKIE_NAME,
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.data_sources import (  # noqa: E402
    StudioDataSources,
    extract_message_attachments,
    map_group_history_entry_to_room_message,
)
from studio.server import ATTACHMENT_SERVICE_KEY, create_app  # noqa: E402

ADMIN_UID = 111111111
READONLY_UID = 222222222
ADMIN_PASS = "EXAMPLE_ATT_ADMIN_PASS_01"
RO_PASS = "EXAMPLE_ATT_RO_PASS_01"
TEST_BOT_HANDLE = "example_bot_main"

# Minimal valid raster magic headers
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"\x00" * 32
GIF_BYTES = b"GIF89a" + b"\x00" * 32
WEBP_BYTES = b"RIFF\x18\x00\x00\x00WEBP" + b"\x00" * 20
PDF_BYTES = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"
PY_BYTES = b"def hello():\n    return 42\n"
MP3_BYTES = b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\x00" * 16
MP4_BYTES = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 16


class TestStudioAttachmentsAndContext(unittest.IsolatedAsyncioTestCase):
    """End-to-end offline tests for attachment upload, preview, context sandbox, and send flows."""

    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_att_test_")
        self.tmp = Path(self._td.name)
        self.studio_cfg = self.tmp / "studio-cfg"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bus"
        self.projects_dir = self.tmp / "projects"
        self.sessions_dir = self.tmp / "sessions"
        self.upload_dir = self.tmp / "uploads" / "web"
        self.proj_root = self.tmp / "workspace-proj"
        self.audit_log = self.studio_cfg / "audit.jsonl"

        for d in (
            self.studio_cfg,
            self.bridge_dir,
            self.bus_dir,
            self.projects_dir,
            self.sessions_dir,
            self.proj_root,
        ):
            d.mkdir(parents=True, exist_ok=True)

        (self.bridge_dir / ".env").write_text(
            "\n".join(
                [
                    "AGY_TG_BOT_TOKEN=123456789:EXAMPLE_ATT_TEST_TOKEN_0001",
                    f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                    f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                    f"AGY_TG_READONLY_USERS={READONLY_UID}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        # Register one allowed project + sample files (including sensitive files to test blocking)
        (self.proj_root / "src").mkdir(parents=True, exist_ok=True)
        (self.proj_root / "src" / "demo.py").write_text("print('ok')\n", encoding="utf-8")
        (self.proj_root / ".env").write_text("API_KEY=EXAMPLE_BLOCKED_VAL\n", encoding="utf-8")
        (self.proj_root / "bot.token").write_text("EXAMPLE_TOKEN_BLOCKED\n", encoding="utf-8")
        (self.proj_root / ".git").mkdir(parents=True, exist_ok=True)
        (self.proj_root / ".git" / "config").write_text("[core]\n", encoding="utf-8")

        self.outside_file = self.tmp / "outside_secret.txt"
        self.outside_file.write_text("OUTSIDE_SECRET", encoding="utf-8")
        os.symlink(str(self.outside_file), str(self.proj_root / "escape_link.txt"))

        (self.projects_dir / "demo-proj.json").write_text(
            json.dumps(
                {
                    "id": "demo-proj",
                    "name": "Demo",
                    "projectResources": {
                        "resources": [{"folderUri": f"file://{self.proj_root}"}]
                    },
                }
            ),
            encoding="utf-8",
        )

        # Register one bot in bus roster & start an in-process mock UDS IPC server
        self.captured_chat_prompts: list[dict] = []
        self.captured_room_prompts: list[dict] = []
        self.ipc_srv = studio_ipc.StudioIPCServer(
            bus_dir=self.bus_dir,
            bot_handle=TEST_BOT_HANDLE,
            resolve_role_fn=lambda uid: "admin" if int(uid) == ADMIN_UID else "readonly",
            get_meta_fn=lambda: {
                "handle": TEST_BOT_HANDLE,
                "models": [],
                "projects": [{"id": "demo-proj", "name": "Demo", "workdir": str(self.proj_root)}],
            },
            enqueue_turn_fn=self._on_ipc_chat_send,
            abort_turn_fn=lambda tid, uid: (200, {"ok": True, "aborted": True, "turn_id": tid}),
            room_turn_fn=self._on_ipc_room_turn,
        )
        self.ipc_srv.start()

        (self.bus_dir / "roster.json").write_text(
            json.dumps(
                {
                    "bots": {
                        TEST_BOT_HANDLE: {
                            "handle": TEST_BOT_HANDLE,
                            "display_name": "Example Main",
                            "role": "coordinator",
                            "status": "online",
                            "last_seen": 9999999999.0,
                            "pid": os.getpid(),
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        # Seed password-mode users
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

        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "AGY_STUDIO_UPLOAD_DIR": str(self.upload_dir),
                "AGY_STUDIO_MIRROR_CHAT_ID": "0",
            },
            clear=False,
        )
        self._env_patch.start()

        self.auth_mgr = StudioAuthManager(
            config_dir=self.studio_cfg,
            bridge_dir=self.bridge_dir,
            auth_mode="password",
        )
        self.sources = StudioDataSources(
            bus_dir=self.bus_dir,
            projects_dir=self.projects_dir,
            brain_root=self.sessions_dir,
            live_browser_config_dir=self.tmp / "live-browser",
        )
        self.app = create_app(
            auth_mgr=self.auth_mgr,
            data_sources=self.sources,
            audit_log_path=self.audit_log,
            event_watcher_interval=60.0,
        )
        self.att_svc: StudioAttachmentService = self.app[ATTACHMENT_SERVICE_KEY]
        self.server = TestServer(self.app)
        await self.server.start_server()
        self.client = TestClient(self.server, cookie_jar=aiohttp.DummyCookieJar())
        await self.client.start_server()
        self.origin = f"http://{self.server.host}:{self.server.port}"

    def _on_ipc_chat_send(self, req: dict) -> tuple[int, dict]:
        self.captured_chat_prompts.append(dict(req))
        return 202, {
            "ok": True,
            "turn_id": "turn-att-0001",
            "bot": TEST_BOT_HANDLE,
            "cid": req.get("cid") or "conv_att_0001",
            "status": "queued",
        }

    def _on_ipc_room_turn(self, req: dict) -> tuple[int, dict]:
        self.captured_room_prompts.append(dict(req))
        return 200, {"ok": True, "reply": "已查看附件并完成分析"}

    async def asyncTearDown(self) -> None:
        await self.client.close()
        await self.server.close()
        self.ipc_srv.stop()
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

    async def _upload_file(
        self,
        sid: str,
        csrf: str,
        filename: str,
        payload: bytes,
        *,
        origin: str | None = None,
        content_type: str = "application/octet-stream",
    ) -> aiohttp.ClientResponse:
        form = aiohttp.FormData()
        form.add_field("file", payload, filename=filename, content_type=content_type)
        hdrs = {
            "Cookie": f"{SESSION_COOKIE_NAME}={sid}",
            "X-Studio-CSRF": csrf,
        }
        if origin is not None:
            hdrs["Origin"] = origin
        return await self.client.post("/api/chat/attachments", headers=hdrs, data=form)

    async def test_valid_uploads_magic_validation_and_get_headers(self) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)
        sid_r, _ = await self._login("ViewerUser", RO_PASS)

        # Upload valid image, PDF, code, audio, video
        cases = [
            ("shot.png", PNG_BYTES, "image", True),
            ("pic.jpg", JPEG_BYTES, "image", True),
            ("anim.gif", GIF_BYTES, "image", True),
            ("hero.webp", WEBP_BYTES, "image", True),
            ("spec.pdf", PDF_BYTES, "pdf", False),
            ("helper.py", PY_BYTES, "code", False),
            ("clip.mp3", MP3_BYTES, "audio", False),
            ("demo.mp4", MP4_BYTES, "video", False),
        ]
        uploaded: dict[str, dict] = {}
        for fname, raw, expected_kind, expect_inline in cases:
            r = await self._upload_file(sid_a, csrf_a, fname, raw, origin=self.origin)
            self.assertEqual(r.status, 201, f"Failed upload for {fname}")
            data = await r.json()
            self.assertTrue(data["ok"])
            att = data["attachment"]
            self.assertTrue(is_valid_attachment_id(att["id"]))
            self.assertEqual(att["kind"], expected_kind)
            self.assertNotIn("abs_path", att)
            self.assertNotIn(str(self.upload_dir), json.dumps(data))
            uploaded[fname] = att

            # Verify GET headers (accessible by authenticated readonly as well)
            r_get = await self.client.get(
                f"/api/chat/attachments/{att['id']}",
                headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_r}"},
            )
            self.assertEqual(r_get.status, 200)
            self.assertEqual(r_get.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertIn("private", r_get.headers.get("Cache-Control", ""))
            cd = r_get.headers.get("Content-Disposition", "")
            if expect_inline:
                self.assertTrue(cd.startswith("inline;"), f"{fname}: got {cd!r}")
            else:
                self.assertTrue(cd.startswith("attachment;"), f"{fname}: got {cd!r}")
            self.assertEqual(await r_get.read(), raw)

        # `?download=1` forces attachment even on valid PNG
        png_id = uploaded["shot.png"]["id"]
        r_dl = await self.client.get(
            f"/api/chat/attachments/{png_id}?download=1",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
        )
        self.assertEqual(r_dl.status, 200)
        self.assertTrue(r_dl.headers.get("Content-Disposition", "").startswith("attachment;"))

        # Verify directory 0700 and file 0600 permissions + server-side resolve_attachments
        self.assertEqual(stat.S_IMODE(self.upload_dir.stat().st_mode), 0o700)
        ok_res, resolved, sc_res, _ = self.att_svc.resolve_attachments([png_id])
        self.assertTrue(ok_res)
        self.assertEqual(sc_res, 200)
        self.assertEqual(len(resolved), 1)
        stored_p = Path(resolved[0]["abs_path"])
        self.assertEqual(stat.S_IMODE(stored_p.stat().st_mode), 0o600)

        # Unauthenticated GET -> 401; invalid ID -> 400; missing ID -> 404
        self.assertEqual((await self.client.get(f"/api/chat/attachments/{png_id}")).status, 401)
        self.assertEqual(
            (
                await self.client.get(
                    "/api/chat/attachments/bad-id",
                    headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
                )
            ).status,
            400,
        )
        self.assertEqual(
            (
                await self.client.get(
                    "/api/chat/attachments/att_1700000000000_abcdef012345",
                    headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
                )
            ).status,
            404,
        )

    async def test_rejects_svg_forged_bitmap_magic_empty_and_write_gates(self) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)
        sid_r, csrf_r = await self._login("ViewerUser", RO_PASS)

        # 1. Reject .svg and .svgz
        for svg_name in ("xss.svg", "xss.svgz"):
            r_svg = await self._upload_file(
                sid_a, csrf_a, svg_name, b"<svg onload=alert(1)></svg>", origin=self.origin
            )
            self.assertEqual(r_svg.status, 400)

        # 2. Reject disguised SVG / text payloads claiming to be raster images
        for bad_img, payload in (
            ("fake.png", b"<svg xmlns='http://www.w3.org/2000/svg'></svg>"),
            ("fake.jpg", b"not a jpeg header"),
            ("fake.webp", b"RIFF0000AVI "),
            ("fake.gif", b"<html><body>xss</body></html>"),
        ):
            r_bad = await self._upload_file(sid_a, csrf_a, bad_img, payload, origin=self.origin)
            self.assertEqual(r_bad.status, 400, f"Expected magic rejection for {bad_img}")

        # 3. Reject empty file & unsupported extension
        r_empty = await self._upload_file(sid_a, csrf_a, "empty.txt", b"", origin=self.origin)
        self.assertEqual(r_empty.status, 400)
        r_exe = await self._upload_file(sid_a, csrf_a, "run.exe", b"MZ\x90\x00", origin=self.origin)
        self.assertEqual(r_exe.status, 400)

        # 4. 4-layer write gate checks
        # Missing origin -> 403
        r_orig = await self._upload_file(sid_a, csrf_a, "a.png", PNG_BYTES, origin=None)
        self.assertEqual(r_orig.status, 403)
        # Wrong Content-Type -> 415
        r_ct = await self.client.post(
            "/api/chat/attachments",
            headers={
                "Cookie": f"{SESSION_COOKIE_NAME}={sid_a}",
                "Origin": self.origin,
                "X-Studio-CSRF": csrf_a,
                "Content-Type": "application/json",
            },
            data="{}",
        )
        self.assertEqual(r_ct.status, 415)
        # Wrong CSRF -> 403
        r_csrf = await self._upload_file(sid_a, "bad-csrf", "a.png", PNG_BYTES, origin=self.origin)
        self.assertEqual(r_csrf.status, 403)
        # Readonly RBAC -> 403
        r_ro = await self._upload_file(sid_r, csrf_r, "a.png", PNG_BYTES, origin=self.origin)
        self.assertEqual(r_ro.status, 403)

    async def test_context_files_sandbox_blocks_traversal_symlinks_and_secrets(self) -> None:
        # Allowed file inside whitelisted project
        ok_good, resolved, sc_good, err_good = self.att_svc.resolve_context_files(
            [chr(64) + "src/demo.py"], "demo-proj"
        )
        self.assertTrue(ok_good, err_good)
        self.assertEqual(sc_good, 200)
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0]["rel_path"], "src/demo.py")

        # Blocked paths: traversal, absolute path, symlink escape, .env, *.token, .git/config
        blocked = [
            "../outside_secret.txt",
            str(self.outside_file),
            "escape_link.txt",
            ".env",
            "bot.token",
            ".git/config",
        ]
        for bad_rel in blocked:
            ok_b, _, sc_b, _ = self.att_svc.resolve_context_files([bad_rel], "demo-proj")
            self.assertFalse(ok_b, f"Expected sandbox rejection for {bad_rel!r}")
            self.assertIn(sc_b, (400, 403))

    async def test_attachment_only_send_injection_and_zero_host_path_leak_for_readonly(self) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)
        sid_r, _ = await self._login("ViewerUser", RO_PASS)

        r_up = await self._upload_file(sid_a, csrf_a, "diagram.png", PNG_BYTES, origin=self.origin)
        self.assertEqual(r_up.status, 201)
        att_id = (await r_up.json())["attachment"]["id"]

        # 1. Attachment-only send on `/api/chat/send` (empty prompt!)
        r_send = await self.client.post(
            "/api/chat/send",
            headers={
                "Cookie": f"{SESSION_COOKIE_NAME}={sid_a}",
                "Origin": self.origin,
                "X-Studio-CSRF": csrf_a,
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "bot": TEST_BOT_HANDLE,
                    "prompt": "",
                    "project": "demo-proj",
                    "attachments": [att_id],
                    "context_files": ["src/demo.py"],
                }
            ),
        )
        self.assertEqual(r_send.status, 202)
        send_raw = await r_send.text()
        send_data = json.loads(send_raw)
        self.assertTrue(send_data["ok"])
        self.assertTrue(send_data["display_prompt"])
        self.assertEqual(len(send_data["attachments"]), 1)
        self.assertEqual(send_data["context_files"], ["src/demo.py"])
        # API response MUST NOT leak host upload dir or project root path
        self.assertNotIn(str(self.upload_dir), send_raw)
        self.assertNotIn(str(self.proj_root), send_raw)

        # Downstream Bridge IPC prompt DOES receive server-resolved paths for `read_file`
        self.assertEqual(len(self.captured_chat_prompts), 1)
        cli_prompt = self.captured_chat_prompts[0]["prompt"]
        self.assertIn("[已附加文件]", cli_prompt)
        self.assertIn("[已引用工作区文件]", cli_prompt)
        self.assertIn(att_id, cli_prompt)
        self.assertIn(str(self.upload_dir), cli_prompt)

        # 2. Simulate persisted transcript USER_INPUT & verify readonly `GET /api/sessions/{cid}/messages`
        # strips host paths completely while returning structured attachment & context_files metadata
        cid = "conv_att_0001"
        logs_dir = self.sessions_dir / cid / ".system_generated" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        (logs_dir / "transcript.jsonl").write_text(
            json.dumps(
                {
                    "type": "USER_INPUT",
                    "step_index": 1,
                    "created_at": "2026-11-21T10:00:00Z",
                    "content": cli_prompt,
                },
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        r_hist = await self.client.get(
            f"/api/sessions/{cid}/messages",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_r}"},
        )
        self.assertEqual(r_hist.status, 200)
        hist_raw = await r_hist.text()
        hist_data = json.loads(hist_raw)
        self.assertNotIn(str(self.upload_dir), hist_raw)
        self.assertNotIn(str(self.proj_root), hist_raw)
        self.assertEqual(len(hist_data["messages"]), 1)
        msg0 = hist_data["messages"][0]
        self.assertEqual(msg0["attachments"][0]["id"], att_id)
        self.assertEqual(msg0["context_files"], ["src/demo.py"])

        # 3. Attachment-only send in web room (`POST /api/rooms/lobby/messages`) & readonly GET
        r_room_send = await self.client.post(
            "/api/rooms/lobby/messages",
            headers={
                "Cookie": f"{SESSION_COOKIE_NAME}={sid_a}",
                "Origin": self.origin,
                "X-Studio-CSRF": csrf_a,
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "content": "",
                    "project": "demo-proj",
                    "attachments": [att_id],
                    "context_files": ["src/demo.py"],
                }
            ),
        )
        self.assertEqual(r_room_send.status, 201)
        room_send_raw = await r_room_send.text()
        self.assertNotIn(str(self.upload_dir), room_send_raw)
        self.assertNotIn(str(self.proj_root), room_send_raw)

        r_room_get = await self.client.get(
            "/api/rooms/lobby/messages",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_r}"},
        )
        self.assertEqual(r_room_get.status, 200)
        room_get_raw = await r_room_get.text()
        self.assertNotIn(str(self.upload_dir), room_get_raw)
        self.assertNotIn(str(self.proj_root), room_get_raw)
        room_msgs = json.loads(room_get_raw)["messages"]
        self.assertTrue(any(m.get("attachments") for m in room_msgs))

    async def test_spaces_parens_context_files_and_truncated_blocks_zero_host_path_leak(self) -> None:
        sid_a, csrf_a = await self._login("AdminUser", ADMIN_PASS)
        sid_r, _ = await self._login("ViewerUser", RO_PASS)

        # Create a workspace file with spaces and parentheses in its relative path
        spaced_rel = "docs/my report (v1).md"
        spaced_file = self.proj_root / spaced_rel
        spaced_file.parent.mkdir(parents=True, exist_ok=True)
        spaced_file.write_text("# Report (v1)\n", encoding="utf-8")

        # Also upload an attachment whose filename contains spaces and parentheses
        r_up = await self._upload_file(
            sid_a, csrf_a, "my diagram (v1).png", PNG_BYTES, origin=self.origin
        )
        self.assertEqual(r_up.status, 201)
        uploaded_att = (await r_up.json())["attachment"]
        att_id = uploaded_att["id"]
        att_name = uploaded_att["name"]

        # 1. Send via `/api/chat/send` referencing both spaced/parenthesized attachment & context file
        r_send = await self.client.post(
            "/api/chat/send",
            headers={
                "Cookie": f"{SESSION_COOKIE_NAME}={sid_a}",
                "Origin": self.origin,
                "X-Studio-CSRF": csrf_a,
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "bot": TEST_BOT_HANDLE,
                    "prompt": "请审阅带空格和括号的报告与图片",
                    "project": "demo-proj",
                    "attachments": [att_id],
                    "context_files": [spaced_rel],
                }
            ),
        )
        self.assertEqual(r_send.status, 202)
        send_raw = await r_send.text()
        self.assertNotIn(str(self.upload_dir), send_raw)
        self.assertNotIn(str(self.proj_root), send_raw)
        self.assertEqual(len(self.captured_chat_prompts), 1)
        cli_prompt = self.captured_chat_prompts[0]["prompt"]
        self.assertIn(spaced_rel, cli_prompt)
        self.assertIn(str(self.proj_root), cli_prompt)

        # 2. Replay full prompt + truncated attachment/context blocks via transcript & readonly GET
        synth_home_att = "/home/exampleuser/uploads/att_1700000000000_abcdef012345_my shot (1).png"
        synth_home_ctx = "/home/exampleuser/my workspace/docs/my report (v1).md"
        truncated_ctx_prompt = (
            "截断工作区引用测试\n\n"
            "[已引用工作区文件]\n"
            f"- {chr(64)}docs/my report (v1).md (项目: demo-proj, 文件位置: {synth_home_ctx[:-8]}"
        )
        truncated_att_prompt = (
            "截断附件块测试\n\n"
            "[已附加文件]\n"
            f"- [image|att_1700000000000_abcdef012345|12 KB] my shot (1).png (文件位置: {synth_home_att[:-10]}"
        )

        cid = "conv_att_spaces_trunc"
        logs_dir = self.sessions_dir / cid / ".system_generated" / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        transcript_lines = [
            json.dumps(
                {
                    "type": "USER_INPUT",
                    "step_index": 1,
                    "created_at": "2026-11-21T10:10:00Z",
                    "content": cli_prompt,
                },
                ensure_ascii=False,
            ),
            json.dumps(
                {
                    "type": "USER_INPUT",
                    "step_index": 2,
                    "created_at": "2026-11-21T10:11:00Z",
                    "content": truncated_ctx_prompt,
                },
                ensure_ascii=False,
            ),
            json.dumps(
                {
                    "type": "USER_INPUT",
                    "step_index": 3,
                    "created_at": "2026-11-21T10:12:00Z",
                    "content": truncated_att_prompt,
                },
                ensure_ascii=False,
            ),
        ]
        (logs_dir / "transcript.jsonl").write_text(
            "\n".join(transcript_lines) + "\n", encoding="utf-8"
        )

        r_hist = await self.client.get(
            f"/api/sessions/{cid}/messages",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_r}"},
        )
        self.assertEqual(r_hist.status, 200)
        hist_raw = await r_hist.text()
        hist_data = json.loads(hist_raw)

        # Zero host path leakage across all 3 messages in readonly view
        self.assertNotIn(str(self.upload_dir), hist_raw)
        self.assertNotIn(str(self.proj_root), hist_raw)
        self.assertNotIn("/home/exampleuser", hist_raw)
        self.assertNotIn("exampleuser", hist_raw)
        self.assertNotIn("文件位置:", hist_raw)

        self.assertEqual(len(hist_data["messages"]), 3)
        msg0 = hist_data["messages"][0]
        self.assertEqual(msg0["content"], "请审阅带空格和括号的报告与图片")
        self.assertEqual(msg0["context_files"], [spaced_rel])
        self.assertEqual(len(msg0["attachments"]), 1)
        self.assertEqual(msg0["attachments"][0]["id"], att_id)
        self.assertEqual(msg0["attachments"][0]["name"], att_name)

        # Direct test with literal unencoded spaces & parentheses in both attachment name and host path
        literal_spaced_att = (
            "含空格与括号的附件名称\n\n"
            "[已附加文件]\n"
            f"- [image|att_1700000000000_abcdef012345|12 KB] my shot (1).png (文件位置: {synth_home_att})\n"
            "提示：以上文件已由系统落盘，请直接使用 read_file 工具读取。"
        )
        clean_lit, atts_lit, ctx_lit = extract_message_attachments(literal_spaced_att)
        self.assertEqual(clean_lit, "含空格与括号的附件名称")
        self.assertEqual(ctx_lit, [])
        self.assertEqual(len(atts_lit), 1)
        self.assertEqual(atts_lit[0]["name"], "my shot (1).png")
        self.assertNotIn("exampleuser", json.dumps(atts_lit, ensure_ascii=False))

        # 3. Verify direct `extract_message_attachments` & `group_history`/SSE mapper on all cases
        for sample in (cli_prompt, truncated_ctx_prompt, truncated_att_prompt):
            clean_txt, _atts, _ctx = extract_message_attachments(sample)
            self.assertNotIn(str(self.upload_dir), clean_txt)
            self.assertNotIn(str(self.proj_root), clean_txt)
            self.assertNotIn("/home/exampleuser", clean_txt)
            self.assertNotIn("文件位置:", clean_txt)

            mapped = map_group_history_entry_to_room_message(
                {
                    "seq": 10,
                    "ts": 1700000010.0,
                    "sender_handle": "example_user",
                    "sender_role": "human",
                    "is_bot": False,
                    "full_text": sample,
                    "source": "web",
                }
            )
            dumped = json.dumps(mapped, ensure_ascii=False)
            self.assertNotIn(str(self.upload_dir), dumped)
            self.assertNotIn(str(self.proj_root), dumped)
            self.assertNotIn("/home/exampleuser", dumped)
            self.assertNotIn("exampleuser", dumped)
            self.assertNotIn("文件位置:", dumped)
            if sample == cli_prompt:
                self.assertEqual(mapped.get("context_files"), [spaced_rel])
                self.assertEqual(mapped["attachments"][0]["id"], att_id)


if __name__ == "__main__":
    unittest.main()
