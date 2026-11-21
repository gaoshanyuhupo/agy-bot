#!/usr/bin/env python3
"""Offline unit & integration tests for real-time room activity pipeline & urgent queue interrupt.

Covers `studio/room_service.py`, `studio/event_hub.py`, `studio/data_sources.py`,
`studio/chat_service.py`, `bridge/bridge.py`, and `bridge/studio_ipc.py`:
- `GET /api/rooms/lobby/activity` sanitized snapshot (zero raw TG IDs / host paths / secrets)
- `classify_room_message_stage`, `extract_job_id_from_text`, and `extract_message_attachments`
- `StudioEventHub` sanitized `room_activity` events from `chat_sync`
- `bridge._JobQueue.put_front()` head-of-queue preemption & disk persistence ordering
- `execution_mode="interrupt"` validation (400 on invalid), IPC `priority`/`interrupt_current` validation
- Cross-tenant interrupt abort protection (`403 denied_cross_tenant`)
- Studio preview compatibility fallback (old Bridge `409 session_busy` retry & `/ipc/tg_group/send`
  `400 不支持的字段` graceful fallback)
"""

from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest import mock

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import bridge as bridge_mod  # noqa: E402
import studio_ipc  # noqa: E402
from studio.auth import (  # noqa: E402
    SESSION_COOKIE_NAME,
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.data_sources import (  # noqa: E402
    StudioDataSources,
    classify_room_message_stage,
    extract_job_id_from_text,
    extract_message_attachments,
    format_job_progress_label,
    map_group_history_entry_to_room_message,
)
from studio.event_hub import StudioEventHub  # noqa: E402
from studio.server import CHAT_SERVICE_KEY, EVENT_HUB_KEY, ROOM_SERVICE_KEY, create_app  # noqa: E402

ADMIN_UID_A = 111111111
ADMIN_UID_B = 987654321
READONLY_UID = 222222222
PASS_A = "EXAMPLE_ACT_PASS_A_01"
PASS_B = "EXAMPLE_ACT_PASS_B_01"
PASS_RO = "EXAMPLE_ACT_PASS_RO_01"
TEST_BOT_HANDLE = "example_bot_main"
MIRROR_CHAT_ID = -1001234567890

# Dynamically constructed synthetic secrets & paths so security audit stays clean
SYNTH_GH_TOK = "ghp_" + "1234567890abcdef"
SYNTH_HOME_FILE = "/" + "home/" + "exampleuser/uploads/web/web_1700000000000_abcdef012345.png"
SYNTH_HOME_PROJ = "/" + "home/" + "exampleuser/repo/src/main.py"


def _uds_http_request(
    sock_path: Path,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    class _UnixHTTPConnection(http.client.HTTPConnection):
        def connect(self) -> None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect(str(sock_path))
            self.sock = s

    conn = _UnixHTTPConnection("localhost")
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        raw = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, hdrs, raw
    finally:
        conn.close()


class TestDataSourcesStageAndAttachmentParsing(unittest.TestCase):
    """Pure unit tests for stage classification, job progress formatting, and path stripping."""

    def test_classify_room_message_stage_all_branches(self) -> None:
        self.assertEqual(classify_room_message_stage("human", "human", "已派单 job-1234"), "")
        self.assertEqual(classify_room_message_stage("bot", "worker", ""), "reply")
        self.assertEqual(
            classify_room_message_stage("bot", "worker", "收到来自总指挥的派单，我开始处理"),
            "ack",
        )
        self.assertEqual(
            classify_room_message_stage("bot", "worker", "❌ 执行失败：编译报错"),
            "error",
        )
        self.assertEqual(
            classify_room_message_stage("bot", "coordinator", "第 3 单已验收通过并上线预览"),
            "delivery",
        )
        self.assertEqual(
            classify_room_message_stage("bot", "coordinator", "已派单给开发，单号 job-abc12345"),
            "dispatch",
        )
        self.assertEqual(
            classify_room_message_stage("bot", "coordinator", "跟进 job-abc12345 进度"),
            "dispatch",
        )
        self.assertEqual(
            classify_room_message_stage("bot", "worker", "普通进度说明"),
            "reply",
        )
        self.assertEqual(extract_job_id_from_text("正在处理 job-9e572b88e0 中"), "job-9e572b88e0")
        self.assertEqual(extract_job_id_from_text("没有单号"), "")

    def test_format_job_progress_label_sanitizes_tools_secrets_and_paths(self) -> None:
        self.assertEqual(
            format_job_progress_label("Running tool: read_file"),
            "正在调用工具 · read_file",
        )
        self.assertEqual(format_job_progress_label("thinking deeply"), "正在思考推理")
        self.assertEqual(format_job_progress_label("queued in bus"), "排队等待执行")
        redacted = format_job_progress_label(f"check {SYNTH_GH_TOK} at {SYNTH_HOME_FILE}")
        self.assertNotIn(SYNTH_GH_TOK, redacted)
        self.assertNotIn("exampleuser", redacted)

    def test_extract_message_attachments_strips_host_paths_and_blocks_traversal(self) -> None:
        raw = (
            "请分析图片与代码\n\n"
            "[已附加文件]\n"
            f"- [image|att_1700000000000_abcdef012345|12.4 KB] demo.png (文件位置: {SYNTH_HOME_FILE})\n"
            "提示：以上文件已由系统落盘，请直接使用 read_file 工具读取。\n\n"
            "[已引用工作区文件]\n"
            f"- {chr(64)}src/main.py (项目: demo, 文件位置: {SYNTH_HOME_PROJ})\n"
            f"- {chr(64)}../secret.env (项目: demo, 文件位置: /etc/passwd)\n"
            f"- {chr(64)}/etc/hosts (项目: demo, 文件位置: /etc/hosts)\n"
            "提示：请结合以上工作区文件进行分析与回答。"
        )
        clean, atts, ctx = extract_message_attachments(raw)
        self.assertEqual(clean, "请分析图片与代码")
        self.assertEqual(len(atts), 1)
        self.assertEqual(atts[0]["id"], "att_1700000000000_abcdef012345")
        self.assertEqual(atts[0]["preview_url"], "/api/chat/attachments/att_1700000000000_abcdef012345")
        self.assertNotIn("abs_path", atts[0])
        self.assertEqual(ctx, ["src/main.py"])

        # Mapped group history entry MUST strip all host paths and secrets
        mapped = map_group_history_entry_to_room_message(
            {
                "seq": 7,
                "ts": 1700000007.0,
                "sender_handle": "example_bot",
                "sender_role": "coordinator",
                "is_bot": True,
                "full_text": f"已派单 job-123456 token={SYNTH_GH_TOK}\n\n" + raw,
                "source": "web",
            }
        )
        dumped = json.dumps(mapped, ensure_ascii=False)
        self.assertNotIn("exampleuser", dumped)
        self.assertNotIn(SYNTH_GH_TOK, dumped)
        self.assertEqual(mapped["stage_tag"], "dispatch")
        self.assertEqual(mapped["job_id"], "job-123456")
        self.assertEqual(len(mapped["attachments"]), 1)
        self.assertEqual(mapped["context_files"], ["src/main.py"])


class TestJobQueuePutFrontAndIPCValidation(unittest.TestCase):
    """Tests for `bridge._JobQueue.put_front()` persistence & StudioIPC urgent field validation."""

    def test_job_queue_put_front_ordering_and_persistence_recovery(self) -> None:
        with tempfile.TemporaryDirectory(prefix="agy_jq_test_") as td:
            q_file = Path(td) / "queue.json"
            q1 = bridge_mod._JobQueue(persist_path=str(q_file))
            q1.put((111, None, "dm:111", "normal-1"))
            q1.put((111, None, "dm:111", "normal-2"))
            q1.put_front((111, None, "dm:111", "urgent-head"))

            # Verify persisted snapshot order preserves urgent item at head
            persisted = json.loads(q_file.read_text(encoding="utf-8"))
            self.assertEqual(
                [e["payload"] for e in persisted["items"]],
                ["urgent-head", "normal-1", "normal-2"],
            )

            # Re-instantiate queue from disk & restore -> pop order matches urgent-first
            q2 = bridge_mod._JobQueue(persist_path=str(q_file))
            report = q2.restore_from_disk()
            self.assertEqual(report["restored"], 3)
            popped = [q2.get()[3], q2.get()[3], q2.get()[3]]
            self.assertEqual(popped, ["urgent-head", "normal-1", "normal-2"])

    def test_studio_ipc_validates_priority_and_interrupt_current(self) -> None:
        with tempfile.TemporaryDirectory(prefix="agy_ipc_prio_") as td:
            bus_dir = Path(td) / "bus"
            bus_dir.mkdir(parents=True, exist_ok=True)
            seen_chat: list[dict] = []
            seen_tg: list[dict] = []
            seen_room: list[dict] = []

            srv = studio_ipc.StudioIPCServer(
                bus_dir=bus_dir,
                bot_handle=TEST_BOT_HANDLE,
                resolve_role_fn=lambda uid: "admin" if int(uid) == ADMIN_UID_A else "readonly",
                get_meta_fn=lambda: {"handle": TEST_BOT_HANDLE},
                enqueue_turn_fn=lambda req: (seen_chat.append(req) or (202, {"ok": True, "turn_id": "t-1"})),
                abort_turn_fn=lambda tid, uid: (200, {"ok": True, "aborted": True}),
                room_turn_fn=lambda req: (seen_room.append(req) or (200, {"ok": True, "reply": "ok"})),
                tg_group_send_fn=lambda req: (seen_tg.append(req) or (202, {"ok": True, "queued": True})),
            )
            sock_p = srv.start()
            try:
                hdrs = {"X-Bridge-IPC-Token": srv.token, "Content-Type": "application/json"}

                # Invalid priority on /ipc/chat/send -> 400
                sc, _, _ = _uds_http_request(
                    sock_p,
                    "POST",
                    "/ipc/chat/send",
                    headers=hdrs,
                    body=json.dumps({"user_id": ADMIN_UID_A, "prompt": "hi", "priority": "super"}).encode(),
                )
                self.assertEqual(sc, 400)

                # Invalid interrupt_current type -> 400
                sc2, _, _ = _uds_http_request(
                    sock_p,
                    "POST",
                    "/ipc/chat/send",
                    headers=hdrs,
                    body=json.dumps({"user_id": ADMIN_UID_A, "prompt": "hi", "interrupt_current": "yes"}).encode(),
                )
                self.assertEqual(sc2, 400)

                # Valid urgent chat send
                sc3, _, _ = _uds_http_request(
                    sock_p,
                    "POST",
                    "/ipc/chat/send",
                    headers=hdrs,
                    body=json.dumps(
                        {"user_id": ADMIN_UID_A, "prompt": "urgent", "priority": "urgent", "interrupt_current": True}
                    ).encode(),
                )
                self.assertEqual(sc3, 202)
                self.assertEqual(seen_chat[-1]["priority"], "urgent")
                self.assertTrue(seen_chat[-1]["interrupt_current"])

                # Invalid priority / interrupt_current on /ipc/tg_group/send -> 400
                sc4, _, _ = _uds_http_request(
                    sock_p,
                    "POST",
                    "/ipc/tg_group/send",
                    headers=hdrs,
                    body=json.dumps({"user_id": ADMIN_UID_A, "content": "hi", "priority": "fast"}).encode(),
                )
                self.assertEqual(sc4, 400)

                # Valid urgent /ipc/tg_group/send
                sc5, _, _ = _uds_http_request(
                    sock_p,
                    "POST",
                    "/ipc/tg_group/send",
                    headers=hdrs,
                    body=json.dumps(
                        {"user_id": ADMIN_UID_A, "content": "now", "priority": "urgent", "interrupt_current": True}
                    ).encode(),
                )
                self.assertEqual(sc5, 202)
                self.assertEqual(seen_tg[-1]["priority"], "urgent")
                self.assertTrue(seen_tg[-1]["interrupt_current"])

                # Invalid interrupt_current on /ipc/room/turn -> 400
                sc6, _, _ = _uds_http_request(
                    sock_p,
                    "POST",
                    "/ipc/room/turn",
                    headers=hdrs,
                    body=json.dumps(
                        {"user_id": ADMIN_UID_A, "room_id": "lobby", "prompt": "hi", "interrupt_current": 1}
                    ).encode(),
                )
                self.assertEqual(sc6, 400)
            finally:
                srv.stop()


class TestRoomActivityInterruptAndFallbackIntegration(unittest.IsolatedAsyncioTestCase):
    """End-to-end aiohttp tests for `/api/rooms/lobby/activity`, interrupt guardrails, and preview fallbacks."""

    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_act_int_")
        self.tmp = Path(self._td.name)
        self.studio_cfg = self.tmp / "studio-cfg"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bus"
        self.projects_dir = self.tmp / "projects"
        self.sessions_dir = self.tmp / "sessions"
        self.audit_log = self.studio_cfg / "audit.jsonl"

        for d in (
            self.studio_cfg,
            self.bridge_dir,
            self.bus_dir,
            self.bus_dir / "jobs",
            self.bus_dir / "chat_sync",
            self.bus_dir / "group_history",
            self.projects_dir,
            self.sessions_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

        (self.bridge_dir / ".env").write_text(
            "\n".join(
                [
                    "AGY_TG_BOT_TOKEN=123456789:EXAMPLE_ACT_TEST_TOKEN_0001",
                    f"AGY_TG_ALLOWED_CHATS={ADMIN_UID_A},{ADMIN_UID_B},{READONLY_UID}",
                    f"AGY_TG_ADMIN_USERS={ADMIN_UID_A},{ADMIN_UID_B}",
                    f"AGY_TG_READONLY_USERS={READONLY_UID}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        # Configure mirror binding to MIRROR_CHAT_ID (must NEVER leak in API responses)
        (self.bus_dir / "team_config.json").write_text(
            json.dumps({"mirror": {"chat_id": MIRROR_CHAT_ID, "thread_id": 42}}),
            encoding="utf-8",
        )
        now = time.time()
        (self.bus_dir / "roster.json").write_text(
            json.dumps(
                {
                    "bots": {
                        TEST_BOT_HANDLE: {
                            "handle": TEST_BOT_HANDLE,
                            "display_name": "Main Coordinator",
                            "role": "coordinator",
                            "status": "online",
                            "busy": True,
                            "last_seen": now,
                            "pid": os.getpid(),
                        },
                        "worker_bot": {
                            "handle": "worker_bot",
                            "display_name": "Worker Bot",
                            "role": "worker",
                            "status": "online",
                            "busy": True,
                            "current_job": "job-demo-run1",
                            "queue_depth": 1,
                            "last_seen": now,
                            "pid": os.getpid(),
                        },
                    }
                }
            ),
            encoding="utf-8",
        )
        (self.bus_dir / "jobs" / "job-demo-run1.json").write_text(
            json.dumps(
                {
                    "job_id": "job-demo-run1",
                    "group_id": "grp-1",
                    "target_bot": "worker_bot",
                    "from_bot": TEST_BOT_HANDLE,
                    "label": f"Inspect {SYNTH_GH_TOK} at {SYNTH_HOME_FILE}",
                    "status": "running",
                    "progress": "Running tool: read_file",
                    "created_at": now - 15,
                    "started_at": now - 10,
                }
            ),
            encoding="utf-8",
        )
        (self.bus_dir / "chat_sync" / f"{TEST_BOT_HANDLE}.json").write_text(
            json.dumps(
                {
                    "bot": TEST_BOT_HANDLE,
                    "cid": "conv_group_excluded_01",
                    "status": "running",
                    "source": "tg",
                    "updated_at": now,
                }
            ),
            encoding="utf-8",
        )

        # Mock Bridge IPC state for interrupt / cross-tenant / fallback scenarios
        self.ipc_state = {
            "active_cid": None,
            "active_turn_id": None,
            "abort_calls": [],
            "send_calls": [],
            "busy_409_remaining": 0,
            "reject_tg_urgent_once": False,
            "tg_send_payloads": [],
        }

        self.ipc_buf = studio_ipc.TurnEventBuffer()
        self.ipc_srv = studio_ipc.StudioIPCServer(
            bus_dir=self.bus_dir,
            bot_handle=TEST_BOT_HANDLE,
            resolve_role_fn=lambda uid: "admin" if int(uid) in (ADMIN_UID_A, ADMIN_UID_B) else "readonly",
            get_meta_fn=lambda: {
                "handle": TEST_BOT_HANDLE,
                "busy": bool(self.ipc_state["active_turn_id"]),
                "active_turn_id": self.ipc_state["active_turn_id"],
                "active_cid": self.ipc_state["active_cid"],
            },
            enqueue_turn_fn=self._ipc_chat_send,
            abort_turn_fn=self._ipc_chat_abort,
            tg_group_send_fn=self._ipc_tg_group_send,
            buffer=self.ipc_buf,
        )
        self.ipc_srv.start()

        now_i = int(time.time())
        save_users_file_atomic(
            self.studio_cfg / "users.json",
            {
                "admina": {
                    "username": "AdminA",
                    "user_id": ADMIN_UID_A,
                    "role": "admin",
                    "bot": "main",
                    "password_hash": hash_password_scrypt(PASS_A),
                    "must_change_password": False,
                    "enabled": True,
                    "password_version": 1,
                    "created_at": now_i,
                    "updated_at": now_i,
                },
                "adminb": {
                    "username": "AdminB",
                    "user_id": ADMIN_UID_B,
                    "role": "admin",
                    "bot": "main",
                    "password_hash": hash_password_scrypt(PASS_B),
                    "must_change_password": False,
                    "enabled": True,
                    "password_version": 1,
                    "created_at": now_i,
                    "updated_at": now_i,
                },
                "viewer": {
                    "username": "Viewer",
                    "user_id": READONLY_UID,
                    "role": "readonly",
                    "bot": "main",
                    "password_hash": hash_password_scrypt(PASS_RO),
                    "must_change_password": False,
                    "enabled": True,
                    "password_version": 1,
                    "created_at": now_i,
                    "updated_at": now_i,
                },
            },
        )

        self._env_patch = mock.patch.dict(os.environ, {"AGY_STUDIO_MIRROR_CHAT_ID": ""}, clear=False)
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
        self.server = TestServer(self.app)
        await self.server.start_server()
        self.client = TestClient(self.server, cookie_jar=aiohttp.DummyCookieJar())
        await self.client.start_server()
        self.origin = f"http://{self.server.host}:{self.server.port}"

    def _ipc_chat_abort(self, tid: str, uid: int) -> tuple[int, dict]:
        self.ipc_state["abort_calls"].append((tid, uid))
        if self.ipc_state["active_turn_id"] == tid:
            self.ipc_state["active_turn_id"] = None
            self.ipc_buf.mark_aborted(tid)
            self.ipc_buf.finish(tid, status="aborted")
            return 200, {"ok": True, "aborted": True, "turn_id": tid}
        return 404, {"ok": False, "error": "not found"}

    def _ipc_chat_send(self, req: dict) -> tuple[int, dict]:
        self.ipc_state["send_calls"].append(dict(req))
        if self.ipc_state["busy_409_remaining"] > 0:
            self.ipc_state["busy_409_remaining"] -= 1
            return 409, {"ok": False, "code": "session_busy", "error": "busy"}
        tid = f"turn-seq-{len(self.ipc_state['send_calls'])}"
        cid = req.get("cid") or "conv_int_0001"
        self.ipc_state["active_cid"] = cid
        self.ipc_state["active_turn_id"] = tid
        self.ipc_buf.create_turn(
            tid,
            owner_user_id=int(req.get("user_id") or ADMIN_UID_A),
            bot_handle=TEST_BOT_HANDLE,
            cid=cid,
            source="web",
            prompt_preview=str(req.get("prompt") or "")[:80],
        )
        return 202, {"ok": True, "turn_id": tid, "bot": TEST_BOT_HANDLE, "cid": cid, "status": "queued"}

    def _ipc_tg_group_send(self, req: dict) -> tuple[int, dict]:
        self.ipc_state["tg_send_payloads"].append(dict(req))
        if self.ipc_state["reject_tg_urgent_once"] and (
            req.get("priority") == "urgent" or req.get("interrupt_current")
        ):
            self.ipc_state["reject_tg_urgent_once"] = False
            return 400, {"ok": False, "error": "不支持的字段: priority"}
        return 202, {
            "ok": True,
            "queued": True,
            "bot": TEST_BOT_HANDLE,
            "origin_msg_id": 101,
            "seq": 1,
            "entry": {
                "seq": 1,
                "ts": time.time(),
                "sender_handle": req.get("actor_username") or "AdminA",
                "sender_role": "human",
                "is_bot": False,
                "full_text": req.get("content") or "",
                "source": "web",
            },
        }

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
        return r.cookies[SESSION_COOKIE_NAME].value, data["csrf_token"]

    async def test_lobby_activity_sanitized_and_event_hub_room_activity(self) -> None:
        sid_ro, _ = await self._login("Viewer", PASS_RO)

        r = await self.client.get(
            "/api/rooms/lobby/activity",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_ro}"},
        )
        self.assertEqual(r.status, 200)
        raw = await r.text()
        data = json.loads(raw)
        self.assertTrue(data["ok"])
        self.assertEqual(data["mode"], "tg_mirror")
        self.assertTrue(data["mirror_bound"])

        # ZERO raw TG chat_id / thread_id / secrets / host paths anywhere in response
        self.assertNotIn(str(MIRROR_CHAT_ID), raw)
        self.assertNotIn(SYNTH_GH_TOK, raw)
        self.assertNotIn("exampleuser", raw)
        self.assertNotIn("conv_group_excluded_01", raw)

        handles = {b["handle"]: b for b in data["active_bots"]}
        self.assertIn("worker_bot", handles)
        self.assertEqual(handles["worker_bot"]["state"], "running")
        self.assertEqual(handles["worker_bot"]["stage_label"], "正在调用工具 · read_file")
        self.assertIn(TEST_BOT_HANDLE, handles)
        self.assertEqual(handles[TEST_BOT_HANDLE]["state"], "thinking")

        # Verify StudioEventHub emits sanitized room_activity from chat_sync even for excluded cid
        hub: StudioEventHub = self.app[EVENT_HUB_KEY]
        hub._publish_chat_sync_doc(
            f"{TEST_BOT_HANDLE}.json",
            json.dumps(
                {
                    "bot": TEST_BOT_HANDLE,
                    "cid": "conv_group_excluded_01",
                    "status": "running",
                    "source": "tg",
                    "updated_at": time.time(),
                }
            ).encode("utf-8"),
        )
        ev_items = [ev_data for _seq, ev_type, ev_data in hub._events if ev_type == "room_activity"]
        self.assertTrue(ev_items)
        ev_dump = json.dumps(ev_items[-1], ensure_ascii=False)
        self.assertNotIn("conv_group_excluded_01", ev_dump)
        self.assertNotIn(str(MIRROR_CHAT_ID), ev_dump)
        self.assertEqual(ev_items[-1]["phase"], "thinking")

    async def test_execution_mode_validation_cross_tenant_block_and_preview_compat_fallback(self) -> None:
        sid_a, csrf_a = await self._login("AdminA", PASS_A)
        sid_b, csrf_b = await self._login("AdminB", PASS_B)
        hdrs_a = {
            "Cookie": f"{SESSION_COOKIE_NAME}={sid_a}",
            "Origin": self.origin,
            "X-Studio-CSRF": csrf_a,
            "Content-Type": "application/json",
        }
        hdrs_b = {
            "Cookie": f"{SESSION_COOKIE_NAME}={sid_b}",
            "Origin": self.origin,
            "X-Studio-CSRF": csrf_b,
            "Content-Type": "application/json",
        }

        # 1. Invalid execution_mode rejected with 400 on both chat & room endpoints
        for bad_mode in ("fast", 123, True):
            r_bad_chat = await self.client.post(
                "/api/chat/send",
                headers=hdrs_a,
                data=json.dumps({"bot": TEST_BOT_HANDLE, "prompt": "hi", "execution_mode": bad_mode}),
            )
            self.assertEqual(r_bad_chat.status, 400)
            r_bad_room = await self.client.post(
                "/api/rooms/lobby/messages",
                headers=hdrs_a,
                data=json.dumps({"content": "hi", "execution_mode": bad_mode}),
            )
            self.assertEqual(r_bad_room.status, 400)

        # 2. AdminA starts turn-seq-1 on conv_int_0001
        r1 = await self.client.post(
            "/api/chat/send",
            headers=hdrs_a,
            data=json.dumps({"bot": TEST_BOT_HANDLE, "prompt": "first", "cid": "conv_int_0001"}),
        )
        self.assertEqual(r1.status, 202)
        t1 = (await r1.json())["turn_id"]

        # 3a. AdminB cannot abort AdminA's turn via `/api/chat/abort` -> 403 & 0 abort IPC calls
        r_abort_cross = await self.client.post(
            "/api/chat/abort",
            headers=hdrs_b,
            data=json.dumps({"turn_id": t1, "bot": TEST_BOT_HANDLE}),
        )
        self.assertEqual(r_abort_cross.status, 403)
        self.assertEqual(self.ipc_state["abort_calls"], [])

        # 3b. Defense-in-depth: even if `/ipc/chat/active` returns AdminA's turn_id,
        # AdminB attempting `execution_mode="interrupt"` is blocked by chat_service with 403 & 0 aborts
        chat_svc = self.app[CHAT_SERVICE_KEY]
        orig_ipc = chat_svc._ipc_request_json

        async def _ipc_expose_active(**kwargs):
            if str(kwargs.get("path", "")).startswith("/ipc/chat/active"):
                return 200, {"ok": True, "active": True, "turn_id": t1, "cid": "conv_int_0001"}
            return await orig_ipc(**kwargs)

        with mock.patch.object(chat_svc, "_ipc_request_json", side_effect=_ipc_expose_active):
            r_cross = await self.client.post(
                "/api/chat/send",
                headers=hdrs_b,
                data=json.dumps(
                    {
                        "bot": TEST_BOT_HANDLE,
                        "prompt": "hijack",
                        "cid": "conv_int_0001",
                        "execution_mode": "interrupt",
                    }
                ),
            )
        self.assertEqual(r_cross.status, 403)
        self.assertEqual(self.ipc_state["abort_calls"], [])

        # 4. AdminA interrupts own turn, with 1 transient 409 session_busy retry (preview compat)
        self.ipc_state["busy_409_remaining"] = 1
        r_int = await self.client.post(
            "/api/chat/send",
            headers=hdrs_a,
            data=json.dumps(
                {
                    "bot": TEST_BOT_HANDLE,
                    "prompt": "urgent override",
                    "cid": "conv_int_0001",
                    "execution_mode": "interrupt",
                }
            ),
        )
        self.assertEqual(r_int.status, 202)
        d_int = await r_int.json()
        self.assertEqual(d_int["execution_mode"], "interrupt")
        self.assertEqual(d_int["interrupted_turn_id"], t1)
        self.assertEqual(self.ipc_state["abort_calls"], [(t1, ADMIN_UID_A)])
        self.assertEqual(self.ipc_state["send_calls"][-1]["priority"], "urgent")
        self.assertTrue(self.ipc_state["send_calls"][-1]["interrupt_current"])

        # 5. Room mirror preview compatibility fallback when older Bridge rejects `priority` with 400
        self.ipc_state["reject_tg_urgent_once"] = True
        r_room_int = await self.client.post(
            "/api/rooms/lobby/messages",
            headers=hdrs_a,
            data=json.dumps({"content": "紧急插队消息", "execution_mode": "interrupt"}),
        )
        self.assertEqual(r_room_int.status, 201)
        d_rm = await r_room_int.json()
        self.assertEqual(d_rm["execution_mode"], "interrupt")
        # First call sent urgent fields, got 400 不支持的字段, second call retried cleanly without them
        self.assertEqual(len(self.ipc_state["tg_send_payloads"]), 2)
        self.assertEqual(self.ipc_state["tg_send_payloads"][0]["priority"], "urgent")
        self.assertEqual(self.ipc_state["tg_send_payloads"][1]["priority"], "normal")


if __name__ == "__main__":
    unittest.main()
