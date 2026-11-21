#!/usr/bin/env python3
"""Phase B Contract Unit & Integration Tests (`PB-C1`..`PB-C8`).

Verifies Web Studio <-> Telegram bidirectional real-time synchronization under
`Prod-Release` gate invariants in complete isolation (temporary directories,
mocked `AgySession`, in-process AF_UNIX `StudioIPCServer`, aiohttp `TestClient`,
zero real browsers, zero live BUS_DIR or systemd mutations).
"""

from __future__ import annotations

import asyncio
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
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

import bot_bus  # noqa: E402
import bridge as bridge_mod  # noqa: E402
import studio_ipc  # noqa: E402
from studio.auth import (  # noqa: E402
    SESSION_COOKIE_NAME,
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.chat_service import MAX_SSE_EVENT_BYTES as CHAT_MAX_SSE_BYTES  # noqa: E402
from studio.data_sources import StudioDataSources  # noqa: E402
from studio.event_hub import MAX_SSE_EVENT_BYTES as HUB_MAX_SSE_BYTES  # noqa: E402
from studio.server import CHAT_SERVICE_KEY, EVENT_HUB_KEY, create_app  # noqa: E402

BOT_TOKEN_TEST = "123456789:EXAMPLE_PHASEB_TEST_TOKEN_0001"
ADMIN_UID_A = 111111111
ADMIN_UID_B = 987654321
READONLY_UID = 222222222
OUTSIDER_UID = 555555555
GROUP_CHAT_ID = -1001234567890
TEST_BOT_HANDLE = "example_sync_bot"

PASS_ADMIN_A = "EXAMPLE_SYNC_ADMIN_A_01"
PASS_ADMIN_B = "EXAMPLE_SYNC_ADMIN_B_01"
PASS_RO = "EXAMPLE_SYNC_RO_01"
PASS_FORCE = "EXAMPLE_SYNC_FORCE_01"


def _write_env(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
        try:
            conn.request(method, path, body=body, headers=headers or {})
        except (BrokenPipeError, ConnectionResetError):
            if conn.sock is None:
                raise
        resp = conn.getresponse()
        raw = resp.read()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, hdrs, raw
    finally:
        conn.close()


async def _read_sse_events(
    resp: aiohttp.ClientResponse,
    *,
    max_events: int = 20,
    timeout: float = 2.0,
) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    cur_event = "message"
    cur_id: str | None = None
    data_lines: list[str] = []
    deadline = time.monotonic() + timeout

    while len(events) < max_events:
        rem = deadline - time.monotonic()
        if rem <= 0:
            break
        try:
            raw_line = await asyncio.wait_for(resp.content.readline(), timeout=rem)
        except asyncio.TimeoutError:
            break
        if not raw_line:
            break
        line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
        if line == "":
            if data_lines:
                raw_data = "\n".join(data_lines)
                try:
                    parsed = json.loads(raw_data)
                except Exception:
                    parsed = raw_data
                events.append(
                    {
                        "event": cur_event,
                        "id": cur_id,
                        "data": parsed,
                        "raw_len": len(raw_data.encode("utf-8")),
                    }
                )
                cur_event = "message"
                cur_id = None
                data_lines = []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            cur_event = line[6:].strip()
        elif line.startswith("id:"):
            cur_id = line[3:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    return events


class _ScriptedFakeSession:
    """In-memory mock of `bridge.AgySession` with scriptable events and optional exception."""

    def __init__(
        self,
        events: list[dict],
        *,
        cid: str | None = None,
        raise_on_next: Exception | None = None,
        returncode: int = 0,
        hold_event: threading.Event | None = None,
    ) -> None:
        self.cid = cid
        self._events = list(events)
        self._raise_on_next = raise_on_next
        self._hold_event = hold_event
        self.proc = mock.Mock(returncode=returncode)
        self.last_used = time.time()
        self.closed = False
        self.sent_prompts: list[str] = []

    def send_user_prompt(self, prompt: str) -> None:
        self.sent_prompts.append(prompt)

    def next_event(self, timeout: float = 0.25):
        if self._hold_event is not None:
            self._hold_event.wait(timeout=timeout)
            return None
        if self._raise_on_next is not None:
            exc = self._raise_on_next
            self._raise_on_next = None
            raise exc
        if self._events:
            return self._events.pop(0)
        return {"event": "__eof__"}

    def peek_immediate_result(self, timeout: float = 0.065):
        if self._events and self._events[0].get("event") == "result":
            ev = self._events.pop(0)
            return ev.get("result") or ev, True
        return None, False

    def get_stderr_text(self) -> str:
        return ""

    def close(self, force: bool = False) -> None:
        self.closed = True


class _StubLiveDraftStreamer(bridge_mod._NoOpStreamer):
    """Test double matching `LiveDraftStreamer(chat_id, started, cid=..., ...)` signature."""

    def __init__(self, *_args, cid=None, start_line=0, **_kwargs) -> None:
        super().__init__(cid=cid, start_line=start_line)


class _PhaseBStudioBase(unittest.IsolatedAsyncioTestCase):
    """Isolated Studio + AF_UNIX Bridge IPC harness."""

    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_phaseb_")
        self.tmp = Path(self._td.name)
        self.config_dir = self.tmp / "studio-config"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bot_bus"
        self.brain_root = self.tmp / "brain"
        self.meta_file = self.tmp / "conversation_metadata.json"
        self.audit_log = self.config_dir / "audit.jsonl"

        self.config_dir.mkdir(parents=True)
        self.bridge_dir.mkdir(parents=True)
        (self.bus_dir / "jobs").mkdir(parents=True)
        (self.bus_dir / "inbox").mkdir(parents=True)
        self.brain_root.mkdir(parents=True)

        self.env_file = self.bridge_dir / ".env"
        _write_env(
            self.env_file,
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

        self.meta_file.write_text(
            json.dumps(
                {
                    "conversations": {
                        "conv_valid_0001": {
                            "summary": {
                                "Internal": False,
                                "Preview": "Normal user chat",
                                "UpdatedAt": "2026-11-21T01:00:00Z",
                                "WorkspaceURIs": ["file:///workspace/demo"],
                            }
                        },
                        "conv_internal_01": {
                            "summary": {
                                "Internal": True,
                                "Preview": "Internal observer session",
                                "UpdatedAt": "2026-11-21T01:01:00Z",
                                "WorkspaceURIs": ["file:///workspace/observer-sandbox"],
                            }
                        },
                        "conv_pure_llm_01": {
                            "agent_name": "pure-llm",
                            "summary": {
                                "Internal": False,
                                "Preview": "pure llm",
                                "UpdatedAt": "2026-11-21T01:02:00Z",
                                "WorkspaceURIs": ["file:///workspace/demo"],
                            },
                        },
                        "conv_sched_00001": {
                            "summary": {
                                "Internal": False,
                                "Preview": "[ACB_SCHEDULED_TASK id=s1] daily digest",
                                "UpdatedAt": "2026-11-21T01:03:00Z",
                                "WorkspaceURIs": ["file:///workspace/demo"],
                            }
                        },
                    }
                }
            ),
            encoding="utf-8",
        )

        (self.bus_dir / "roster.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "bots": {
                        TEST_BOT_HANDLE: {
                            "handle": TEST_BOT_HANDLE,
                            "display_name": "Sync Bot",
                            "role": "coordinator",
                            "pid": os.getpid(),
                            "last_seen": time.time(),
                            "busy": False,
                            "active_model": "gemini-3.8-flash",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        self.ipc_buf = studio_ipc.TurnEventBuffer()
        self.received_enqueues: list[dict] = []
        self.role_overrides: dict[int, str] = {
            ADMIN_UID_A: "admin",
            ADMIN_UID_B: "admin",
            READONLY_UID: "readonly",
        }
        self.peer_uid_box = [os.getuid()]

        def _enqueue(req: dict):
            self.received_enqueues.append(dict(req))
            tid = f"turn-{len(self.received_enqueues):016x}"
            self.ipc_buf.create_turn(
                tid,
                owner_user_id=int(req["user_id"]),
                actor_username=str(req.get("actor_username") or ""),
                bot_handle=TEST_BOT_HANDLE,
                cid=req.get("cid"),
                source="web",
                prompt_preview=str(req.get("prompt") or "")[:120],
            )
            return 202, {"ok": True, "turn_id": tid, "bot": TEST_BOT_HANDLE, "cid": req.get("cid"), "status": "queued"}

        self.ipc_srv = studio_ipc.StudioIPCServer(
            bus_dir=self.bus_dir,
            bot_handle=TEST_BOT_HANDLE,
            resolve_role_fn=lambda uid: self.role_overrides.get(int(uid), "denied"),
            get_meta_fn=lambda: {"handle": TEST_BOT_HANDLE, "models": [], "projects": []},
            enqueue_turn_fn=_enqueue,
            abort_turn_fn=lambda tid, uid: (200, {"ok": True, "aborted": True, "turn_id": tid}),
            buffer=self.ipc_buf,
            meta_file=self.meta_file,
            peer_uid_fn=lambda _conn: self.peer_uid_box[0],
        )
        self.ipc_srv.start()

        self.auth_mgr = StudioAuthManager(
            auth_mode="password",
            config_dir=self.config_dir,
            bridge_dir=self.bridge_dir,
            public_url="",
        )
        self.sources = StudioDataSources(
            bus_dir=self.bus_dir,
            brain_root=self.brain_root,
            meta_file=self.meta_file,
            summaries_db=self.tmp / "nonexistent_summaries.sqlite",
            schedules_file=self.tmp / "schedules.json",
        )
        self.app = create_app(
            auth_mgr=self.auth_mgr,
            data_sources=self.sources,
            audit_log_path=self.audit_log,
            revocation_check_interval=0.08,
            sse_keepalive_interval=5.0,
            event_watcher_interval=0.0,
        )
        self.server = TestServer(self.app)
        self.client = TestClient(self.server, cookie_jar=aiohttp.DummyCookieJar())
        await self.client.start_server()
        self.origin = f"http://{self.server.host}:{self.server.port}"

    async def asyncTearDown(self) -> None:
        await self.client.close()
        self.ipc_srv.stop()
        self._td.cleanup()

    async def _login(self, username: str, password: str) -> tuple[int, str, str]:
        resp = await self.client.post(
            "/api/auth/login",
            headers={"Origin": self.origin, "Content-Type": "application/json"},
            json={"username": username, "password": password},
        )
        data = await resp.json()
        sid = resp.cookies.get(SESSION_COOKIE_NAME)
        return resp.status, (sid.value if sid else ""), str(data.get("csrf_token") or "")

    def _write_headers(self, sid: str, csrf: str) -> dict[str, str]:
        return {
            "Origin": self.origin,
            "Content-Type": "application/json",
            "Cookie": f"{SESSION_COOKIE_NAME}={sid}",
            "X-Studio-CSRF": csrf,
        }


class TestPBC1SyncTgAuthAndTargetInjection(_PhaseBStudioBase):
    """PB-C1: sync_tg strict boolean, readonly/role-spoof 403, target injection stripped, fail-closed DM check."""

    async def test_pb_c1_studio_and_ipc_reject_readonly_non_bool_and_strip_target_injection(self) -> None:
        # (1) readonly calling Studio POST /api/chat/send with sync_tg=True -> 403 studio_auth
        sc_ro, sid_ro, csrf_ro = await self._login("ro_user", PASS_RO)
        self.assertEqual(sc_ro, 200)
        resp_ro = await self.client.post(
            "/api/chat/send",
            headers=self._write_headers(sid_ro, csrf_ro),
            json={"prompt": "hello", "sync_tg": True},
        )
        self.assertEqual(resp_ro.status, 403)
        self.assertEqual((await resp_ro.json()).get("source"), "studio_auth")
        self.assertEqual(len(self.received_enqueues), 0)

        # Direct IPC with readonly user_id + forged role="admin" -> 403 bridge_ipc
        sc_ipc_ro, _, raw_ipc_ro = _uds_http_request(
            self.ipc_srv.sock_path,
            "POST",
            "/ipc/chat/send",
            headers={"X-Bridge-IPC-Token": self.ipc_srv.token, "Content-Type": "application/json"},
            body=json.dumps({"user_id": READONLY_UID, "role": "admin", "prompt": "hi", "sync_tg": True}).encode(),
        )
        self.assertEqual(sc_ipc_ro, 403)
        self.assertEqual(json.loads(raw_ipc_ro).get("source"), "bridge_ipc")

        # (2) admin sending non-boolean sync_tg ("true", 1, 0) -> 400 at BOTH Studio and IPC
        sc_a, sid_a, csrf_a = await self._login("admin_a", PASS_ADMIN_A)
        self.assertEqual(sc_a, 200)
        for bad_val in ("true", 1, 0, "1", ["true"]):
            r_bad = await self.client.post(
                "/api/chat/send",
                headers=self._write_headers(sid_a, csrf_a),
                json={"prompt": "test", "sync_tg": bad_val},
            )
            self.assertEqual(r_bad.status, 400, f"Studio must reject non-bool sync_tg={bad_val!r}")

            sc_ib, _, _ = _uds_http_request(
                self.ipc_srv.sock_path,
                "POST",
                "/ipc/chat/send",
                headers={"X-Bridge-IPC-Token": self.ipc_srv.token, "Content-Type": "application/json"},
                body=json.dumps({"user_id": ADMIN_UID_A, "prompt": "test", "sync_tg": bad_val}).encode(),
            )
            self.assertEqual(sc_ib, 400, f"IPC must reject non-bool sync_tg={bad_val!r}")

        # Admin injecting chat_id / target_chat_id / thread_id / target_thread_id / role
        # -> all stripped, default sync_tg=False when omitted
        r_default = await self.client.post(
            "/api/chat/send",
            headers=self._write_headers(sid_a, csrf_a),
            json={
                "prompt": "clean default",
                "chat_id": GROUP_CHAT_ID,
                "target_chat_id": OUTSIDER_UID,
                "thread_id": 42,
                "target_thread_id": 99,
                "role": "admin",
            },
        )
        self.assertEqual(r_default.status, 202)
        req0 = self.received_enqueues[-1]
        self.assertIs(req0["sync_tg"], False)
        for forbidden_k in ("chat_id", "target_chat_id", "thread_id", "target_thread_id", "role"):
            self.assertNotIn(forbidden_k, req0)

        # Direct IPC with injected routing keys + sync_tg=True -> stripped cleanly
        sc_ok, _, _ = _uds_http_request(
            self.ipc_srv.sock_path,
            "POST",
            "/ipc/chat/send",
            headers={"X-Bridge-IPC-Token": self.ipc_srv.token, "Content-Type": "application/json"},
            body=json.dumps(
                {
                    "user_id": ADMIN_UID_A,
                    "prompt": "mirror me",
                    "sync_tg": True,
                    "chat_id": GROUP_CHAT_ID,
                    "target_chat_id": OUTSIDER_UID,
                    "thread_id": 42,
                    "target_thread_id": 88,
                    "role": "superadmin",
                }
            ).encode(),
        )
        self.assertEqual(sc_ok, 202)
        req1 = self.received_enqueues[-1]
        self.assertIs(req1["sync_tg"], True)
        for forbidden_k in ("chat_id", "target_chat_id", "thread_id", "target_thread_id", "role"):
            self.assertNotIn(forbidden_k, req1)

    def test_pb_c1_bridge_mirror_fail_closed_when_not_allowed_or_downgraded(self) -> None:
        # (3) Bridge DM mirror enforces uid > 0 and uid in ALLOWED and live_role == "admin"
        sent_plain: list[tuple] = []
        sent_rich: list[tuple] = []

        def _fake_send(cid, text, **kw):
            sent_plain.append((cid, text, kw))
            return 101

        def _fake_send_rich(cid, text, **kw):
            sent_rich.append((cid, text, kw))
            return (102, text)

        with (
            mock.patch.object(bridge_mod, "ALLOWED", {ADMIN_UID_A}),
            mock.patch.object(bridge_mod, "ADMIN_USERS", {ADMIN_UID_A}),
            mock.patch.object(bridge_mod, "READONLY_USERS", {READONLY_UID}),
            mock.patch.object(bridge_mod, "send", side_effect=_fake_send),
            mock.patch.object(bridge_mod, "send_rich", side_effect=_fake_send_rich),
        ):
            # Outsider, negative group chat, zero, bool, readonly -> 0 sends
            for bad_uid in (OUTSIDER_UID, GROUP_CHAT_ID, 0, -1, True, READONLY_UID):
                self.assertFalse(bridge_mod._mirror_web_prompt_to_tg(bad_uid, "secret?"))
                self.assertFalse(bridge_mod._mirror_web_result_to_tg(bad_uid, "done", "answer"))
            self.assertEqual(len(sent_plain), 0)
            self.assertEqual(len(sent_rich), 0)

            # Valid admin -> sends ONLY to (ADMIN_UID_A, thread_id=None) with HTML escaping
            self.assertTrue(bridge_mod._mirror_web_prompt_to_tg(ADMIN_UID_A, "<b>hello</b>"))
            self.assertTrue(bridge_mod._mirror_web_result_to_tg(ADMIN_UID_A, "done", "ok reply", cid="conv_valid_0001"))
            self.assertEqual(len(sent_plain), 1)
            self.assertEqual(sent_plain[0][0], ADMIN_UID_A)
            self.assertIsNone(sent_plain[0][2].get("thread_id"))
            self.assertIn("&lt;b&gt;hello&lt;/b&gt;", sent_plain[0][1])
            self.assertEqual(len(sent_rich), 1)
            self.assertEqual(sent_rich[0][0], ADMIN_UID_A)
            self.assertIsNone(sent_rich[0][2].get("thread_id"))
            self.assertIn("Web → TG", sent_rich[0][2].get("header_html", ""))

            # Live downgrade admin -> readonly before send -> fail-closed skip (0 new sends)
            with (
                mock.patch.object(bridge_mod, "ADMIN_USERS", set()),
                mock.patch.object(bridge_mod, "READONLY_USERS", {ADMIN_UID_A}),
            ):
                self.assertFalse(bridge_mod._mirror_web_prompt_to_tg(ADMIN_UID_A, "after downgrade"))
                self.assertFalse(bridge_mod._mirror_web_result_to_tg(ADMIN_UID_A, "done", "after downgrade"))
            self.assertEqual(len(sent_plain), 1)
            self.assertEqual(len(sent_rich), 1)


class TestPBC2ActiveTurnAndTgStreamTenantIsolation(_PhaseBStudioBase):
    """PB-C2: active-turn & tg-* cross-tenant isolation, group/readonly exclusion, cid validation."""

    async def test_pb_c2_active_turn_and_tg_stream_auth_tenant_and_cid_guards(self) -> None:
        tg_tid = "tg-0123456789abcdef"
        secret_tok = "ghp_" + "AbCdEf1234567890XyZ99"
        self.ipc_buf.create_turn(
            tg_tid,
            owner_user_id=ADMIN_UID_A,
            bot_handle=TEST_BOT_HANDLE,
            scope_key=str(ADMIN_UID_A),
            cid="conv_valid_0001",
            source="tg",
            prompt_preview=f"check token {secret_tok}",
        )
        self.ipc_buf.append(tg_tid, "turn_start", {"turn_id": tg_tid, "conversation_id": "conv_valid_0001"})
        self.ipc_buf.append(tg_tid, "text_delta", {"delta": "admin-A-only-stream-text"})

        # (1) Unauthenticated -> 401 studio_auth
        r_unauth = await self.client.get("/api/sessions/conv_valid_0001/active-turn")
        self.assertEqual(r_unauth.status, 401)
        self.assertEqual((await r_unauth.json()).get("source"), "studio_auth")
        r_unauth_s = await self.client.get(f"/api/chat/stream?turn_id={tg_tid}&bot={TEST_BOT_HANDLE}")
        self.assertEqual(r_unauth_s.status, 401)

        # readonly -> 403 studio_auth
        _, sid_ro, _ = await self._login("ro_user", PASS_RO)
        r_ro = await self.client.get(
            "/api/sessions/conv_valid_0001/active-turn",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_ro}"},
        )
        self.assertEqual(r_ro.status, 403)
        self.assertEqual((await r_ro.json()).get("source"), "studio_auth")
        r_ro_s = await self.client.get(
            f"/api/chat/stream?turn_id={tg_tid}&bot={TEST_BOT_HANDLE}",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_ro}"},
        )
        self.assertEqual(r_ro_s.status, 403)
        self.assertEqual((await r_ro_s.json()).get("source"), "studio_auth")

        # must_change_password=True -> 403 studio_auth
        _, sid_force, _ = await self._login("force_user", PASS_FORCE)
        r_force = await self.client.get(
            "/api/sessions/conv_valid_0001/active-turn",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_force}"},
        )
        self.assertEqual(r_force.status, 403)
        self.assertEqual((await r_force.json()).get("source"), "studio_auth")
        r_force_s = await self.client.get(
            f"/api/chat/stream?turn_id={tg_tid}&bot={TEST_BOT_HANDLE}",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_force}"},
        )
        self.assertEqual(r_force_s.status, 403)

        # (2) Admin B cannot discover Admin A's active turn or subscribe to tg-<A>
        _, sid_b, _ = await self._login("admin_b", PASS_ADMIN_B)
        r_b_active = await self.client.get(
            "/api/sessions/conv_valid_0001/active-turn",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_b}"},
        )
        self.assertEqual(r_b_active.status, 200)
        b_data = await r_b_active.json()
        self.assertFalse(b_data.get("active"))
        self.assertNotIn("turn_id", b_data)
        self.assertNotIn("owner_user_id", b_data)

        # Direct IPC /ipc/chat/active for Admin B also returns active=False
        sc_ib, _, raw_ib = _uds_http_request(
            self.ipc_srv.sock_path,
            "GET",
            f"/ipc/chat/active?cid=conv_valid_0001&user_id={ADMIN_UID_B}",
            headers={"X-Bridge-IPC-Token": self.ipc_srv.token},
        )
        self.assertEqual(sc_ib, 200)
        self.assertFalse(json.loads(raw_ib).get("active"))

        # Admin B subscribing to tg-<A> via Studio and direct IPC -> 403 & 0 frames leaked
        r_b_stream = await self.client.get(
            f"/api/chat/stream?turn_id={tg_tid}&bot={TEST_BOT_HANDLE}",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_b}"},
        )
        self.assertEqual(r_b_stream.status, 403)
        b_body = await r_b_stream.text()
        self.assertNotIn("admin-A-only-stream-text", b_body)

        sc_ibs, _, raw_ibs = _uds_http_request(
            self.ipc_srv.sock_path,
            "GET",
            f"/ipc/chat/stream?turn_id={tg_tid}&user_id={ADMIN_UID_B}",
            headers={"X-Bridge-IPC-Token": self.ipc_srv.token},
        )
        self.assertEqual(sc_ibs, 403)
        self.assertNotIn(b"admin-A-only-stream-text", raw_ibs)

        # Admin A CAN discover active turn (secret redacted) and stream it
        _, sid_a, _ = await self._login("admin_a", PASS_ADMIN_A)
        r_a_active = await self.client.get(
            "/api/sessions/conv_valid_0001/active-turn",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
        )
        self.assertEqual(r_a_active.status, 200)
        a_data = await r_a_active.json()
        self.assertTrue(a_data["active"])
        self.assertEqual(a_data["turn_id"], tg_tid)
        self.assertEqual(a_data["source"], "tg")
        self.assertNotIn(secret_tok, a_data.get("prompt_preview", ""))

        # Unknown non-tg turn_id still rejected 403 at Studio
        r_unk = await self.client.get(
            "/api/chat/stream?turn_id=turn-deadbeef00001111",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
        )
        self.assertEqual(r_unk.status, 403)
        self.assertEqual((await r_unk.json()).get("source"), "studio_auth")

        # (4) Invalid cid -> 400, internal/observer/pure-llm cid -> 403
        for bad_cid in ("short", "bad$cid!1234", "a..b..c..d"):
            r_400 = await self.client.get(
                f"/api/sessions/{bad_cid}/active-turn",
                headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
            )
            self.assertEqual(r_400.status, 400, f"Expected 400 for cid={bad_cid!r}")

        for restricted_cid in ("conv_internal_01", "conv_pure_llm_01"):
            r_403 = await self.client.get(
                f"/api/sessions/{restricted_cid}/active-turn",
                headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
            )
            self.assertEqual(r_403.status, 403, f"Expected 403 for restricted cid={restricted_cid!r}")

            sc_i403, _, _ = _uds_http_request(
                self.ipc_srv.sock_path,
                "GET",
                f"/ipc/chat/active?cid={restricted_cid}&user_id={ADMIN_UID_A}",
                headers={"X-Bridge-IPC-Token": self.ipc_srv.token},
            )
            self.assertEqual(sc_i403, 403)

        # Finish turn cleanly so buffer doesn't linger
        self.ipc_buf.append(tg_tid, "done", {"conversation_id": "conv_valid_0001", "status": "SUCCESS"})

    def test_pb_c2_tg_group_and_readonly_turns_never_enter_ipc_buffer(self) -> None:
        # (3) TG group chat turn (chat_id < 0) and TG readonly turn NEVER write to _studio_ipc_buffer
        buf = studio_ipc.TurnEventBuffer()
        with tempfile.TemporaryDirectory(prefix="agy_grp_ro_") as td:
            bus_dir = Path(td) / "bus"
            bus_dir.mkdir(parents=True)
            fake_sess_grp = _ScriptedFakeSession(
                [
                    {"event": "init", "conversation_id": "conv_group_00001"},
                    {"event": "result", "status": "SUCCESS", "conversation_id": "conv_group_00001", "response": "group ok"},
                ],
                cid="conv_group_00001",
            )
            fake_sess_ro = _ScriptedFakeSession(
                [
                    {"event": "init", "conversation_id": "conv_ro_00000001"},
                    {"event": "result", "status": "SUCCESS", "conversation_id": "conv_ro_00000001", "response": "ro ok"},
                ],
                cid="conv_ro_00000001",
            )
            with (
                mock.patch.object(bot_bus, "BUS_DIR", str(bus_dir)),
                mock.patch.object(bridge_mod, "_studio_ipc_buffer", buf),
                mock.patch.object(bridge_mod, "ALLOWED", {ADMIN_UID_A, READONLY_UID, GROUP_CHAT_ID}),
                mock.patch.object(bridge_mod, "ADMIN_USERS", {ADMIN_UID_A}),
                mock.patch.object(bridge_mod, "READONLY_USERS", {READONLY_UID}),
                mock.patch.object(bridge_mod, "save_state"),
                mock.patch.object(bridge_mod, "LiveDraftStreamer", _StubLiveDraftStreamer),
                mock.patch.object(bridge_mod, "send", return_value=1),
                mock.patch.object(bridge_mod, "send_rich", return_value=(1, "ok")),
                mock.patch.object(bridge_mod, "push_step_images"),
                mock.patch.object(bridge_mod, "_maybe_post_turn_auto_compact"),
                mock.patch.object(bridge_mod, "_record_and_relay_bot_group_msg"),
                mock.patch.object(bridge_mod, "_compute_workspace_diff_and_footer", return_value=("", None)),
                mock.patch.object(bridge_mod, "get_turn_details", return_value=([], [], 0)),
                mock.patch.object(bridge_mod, "_current_bot_handle", return_value=TEST_BOT_HANDLE),
            ):
                with mock.patch.object(bridge_mod, "_acquire_session", return_value=(fake_sess_grp, False)):
                    bridge_mod.run_agy(
                        GROUP_CHAT_ID,
                        "group question",
                        user_role="admin",
                        user_id=ADMIN_UID_A,
                        override_cid="conv_group_00001",
                    )
                self.assertEqual(len(buf._turns), 0, "TG group turn MUST NOT write to _studio_ipc_buffer")
                # Non-internal group turn SHOULD write sanitized chat_sync file
                sync_file = bus_dir / "chat_sync" / f"{TEST_BOT_HANDLE}.json"
                self.assertTrue(sync_file.is_file())
                sync_doc = json.loads(sync_file.read_text(encoding="utf-8"))
                self.assertEqual(sync_doc["cid"], "conv_group_00001")
                self.assertEqual(sync_doc["status"], "done")
                self.assertEqual(set(sync_doc.keys()), studio_ipc.CHAT_SYNC_ALLOWED_KEYS)

                # Clear chat_sync before testing readonly turn
                sync_file.unlink()
                with mock.patch.object(bridge_mod, "_acquire_session", return_value=(fake_sess_ro, False)):
                    bridge_mod.run_agy(
                        READONLY_UID,
                        "readonly question",
                        user_role="readonly",
                        user_id=READONLY_UID,
                        override_cid="conv_ro_00000001",
                    )
                self.assertEqual(len(buf._turns), 0, "TG readonly turn MUST NOT write to _studio_ipc_buffer")
                self.assertFalse(sync_file.exists(), "TG readonly turn MUST NOT write chat_sync")


class TestPBC3ChatSyncAndEventHubIsolation(_PhaseBStudioBase):
    """PB-C3: internal/observer/scheduled exclusion, atomic 0600 chat_sync, strict EventHub whitelist."""

    async def test_pb_c3_internal_turns_excluded_atomic_0600_and_event_hub_whitelist(self) -> None:
        # (1) Internal / observer-sandbox / scheduled / delegation turns NEVER write buffer or chat_sync
        buf = studio_ipc.TurnEventBuffer()
        sync_file = self.bus_dir / "chat_sync" / f"{TEST_BOT_HANDLE}.json"
        if sync_file.exists():
            sync_file.unlink()

        excluded_cases = [
            {"scope_key": "bus:job-1234", "prompt": "delegated task", "cid": "conv_valid_0001", "workdir": str(self.tmp)},
            {"scope_key": str(ADMIN_UID_A), "prompt": "[ACB_SCHEDULED_TASK id=s1] run", "cid": "conv_valid_0001", "workdir": str(self.tmp)},
            {"scope_key": str(ADMIN_UID_A), "prompt": "[ACB_TEAM_DELEGATION job=j1] run", "cid": "conv_valid_0001", "workdir": str(self.tmp)},
            {"scope_key": str(ADMIN_UID_A), "prompt": "normal", "cid": "conv_internal_01", "workdir": str(self.tmp)},
            {"scope_key": str(ADMIN_UID_A), "prompt": "normal", "cid": "conv_pure_llm_01", "workdir": str(self.tmp)},
            {"scope_key": str(ADMIN_UID_A), "prompt": "normal", "cid": "conv_valid_0001", "workdir": str(self.tmp / "observer-sandbox")},
        ]
        (self.tmp / "observer-sandbox").mkdir(exist_ok=True)
        with (
            mock.patch.object(bot_bus, "BUS_DIR", str(self.bus_dir)),
            mock.patch.object(bridge_mod, "_studio_ipc_buffer", buf),
            mock.patch.object(bridge_mod, "META_FILE", str(self.meta_file)),
            mock.patch.object(bridge_mod, "SUMMARIES_DB", str(self.tmp / "none.sqlite")),
            mock.patch.object(bridge_mod, "ALLOWED", {ADMIN_UID_A}),
            mock.patch.object(bridge_mod, "ADMIN_USERS", {ADMIN_UID_A}),
            mock.patch.object(bridge_mod, "save_state"),
            mock.patch.object(bridge_mod, "LiveDraftStreamer", _StubLiveDraftStreamer),
            mock.patch.object(bridge_mod, "send", return_value=1),
            mock.patch.object(bridge_mod, "send_rich", return_value=(1, "ok")),
            mock.patch.object(bridge_mod, "push_step_images"),
            mock.patch.object(bridge_mod, "_maybe_post_turn_auto_compact"),
            mock.patch.object(bridge_mod, "_compute_workspace_diff_and_footer", return_value=("", None)),
            mock.patch.object(bridge_mod, "get_turn_details", return_value=([], [], 0)),
            mock.patch.object(bridge_mod, "_current_bot_handle", return_value=TEST_BOT_HANDLE),
        ):
            for case in excluded_cases:
                fs = _ScriptedFakeSession(
                    [{"event": "result", "status": "SUCCESS", "conversation_id": case["cid"], "response": "ok"}],
                    cid=case["cid"],
                )
                with mock.patch.object(bridge_mod, "_acquire_session", return_value=(fs, False)):
                    bridge_mod.run_agy(
                        ADMIN_UID_A,
                        case["prompt"],
                        scope_key=case["scope_key"],
                        user_role="admin",
                        user_id=ADMIN_UID_A,
                        override_cid=case["cid"],
                        override_workdir=case["workdir"],
                    )
        self.assertEqual(len(buf._turns), 0, "Internal/scheduled/delegation turns MUST NOT enter IPC buffer")
        self.assertFalse(sync_file.exists(), "Internal/scheduled/delegation turns MUST NOT write chat_sync")

        # (2) write_chat_sync_atomic enforces 0700 dir, 0600 file, strict whitelist keys
        written = studio_ipc.write_chat_sync_atomic(
            self.bus_dir,
            TEST_BOT_HANDLE,
            cid="conv_valid_0001",
            source="tg",
            status="running",
        )
        self.assertIsNotNone(written)
        assert written is not None
        self.assertEqual(stat.S_IMODE(written.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(written.stat().st_mode), 0o600)
        doc = json.loads(written.read_text(encoding="utf-8"))
        self.assertEqual(set(doc.keys()), studio_ipc.CHAT_SYNC_ALLOWED_KEYS)

        # (3) Start watcher and subscribe as readonly on GET /api/events
        hub = self.app[EVENT_HUB_KEY]
        hub.watcher_interval = 0.04
        hub._last_fp = None
        hub.start_watcher()

        _, sid_ro, _ = await self._login("ro_user", PASS_RO)
        resp_ev = await self.client.get(
            "/api/events",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_ro}"},
        )
        self.assertEqual(resp_ev.status, 200)
        init_evs = await _read_sse_events(resp_ev, max_events=1, timeout=1.0)
        self.assertEqual(init_evs[0]["event"], "connected")

        # Wait for initial watcher snapshot
        deadline = time.monotonic() + 1.0
        while hub._last_fp is None and time.monotonic() < deadline:
            await asyncio.sleep(0.02)

        # Write polluted chat_sync file with forbidden keys, host path, and secrets
        fake_ghp = "ghp_" + "LeakedSecretToken123456"
        fake_sk = "sk-" + "proj-LeakedSecretKey1234567890"
        fake_host_path = "/" + "home" + "/alice/private/secret.env"
        polluted_doc = {
            "bot": TEST_BOT_HANDLE,
            "cid": "conv_valid_0001",
            "source": "tg",
            "status": "done",
            "updated_at": round(time.time(), 3),
            "seq": 999,
            "chat_id": GROUP_CHAT_ID,
            "thread_id": 77,
            "turn_id": "tg-aaaaaaaaaaaaaaaa",
            "owner_user_id": ADMIN_UID_A,
            "user_id": ADMIN_UID_A,
            "prompt": f"prompt {fake_ghp} {fake_host_path}",
            "response": f"resp {fake_sk}",
            "content": "secret content",
            "thinking": "secret thinking",
        }
        written.write_text(json.dumps(polluted_doc), encoding="utf-8")

        evs = await _read_sse_events(resp_ev, max_events=3, timeout=1.2)
        sess_evs = [e for e in evs if e["event"] == "session_updated"]
        self.assertTrue(sess_evs, f"Expected session_updated event for readonly subscriber, got: {evs}")
        ev_data = sess_evs[-1]["data"]
        assert isinstance(ev_data, dict)
        allowed_event_keys = {"cid", "bot", "source", "status", "busy", "updated_at", "ts"}
        self.assertTrue(set(ev_data.keys()).issubset(allowed_event_keys), f"Unexpected keys: {ev_data.keys()}")
        self.assertEqual(ev_data["cid"], "conv_valid_0001")
        self.assertEqual(ev_data["status"], "done")
        self.assertIs(ev_data["busy"], False)
        self.assertLessEqual(int(sess_evs[-1]["raw_len"]), HUB_MAX_SSE_BYTES)
        ev_serialized = json.dumps(ev_data)
        for bad_tok in (fake_ghp, fake_sk, fake_host_path, "tg-aaaaaaaaaaaaaaaa", str(GROUP_CHAT_ID)):
            self.assertNotIn(bad_tok, ev_serialized)

        # Polluted chat_sync pointing to internal/scheduled cid -> 0 session_updated events
        for blocked_cid in ("conv_internal_01", "conv_sched_00001"):
            written.write_text(
                json.dumps({"bot": TEST_BOT_HANDLE, "cid": blocked_cid, "source": "tg", "status": "running", "seq": 1001}),
                encoding="utf-8",
            )
            await asyncio.sleep(0.12)
        blocked_evs = await _read_sse_events(resp_ev, max_events=2, timeout=0.25)
        self.assertEqual([e for e in blocked_evs if e["event"] == "session_updated"], [])

        # Direct EventHub.publish defense-in-depth strips new forbidden keys
        hub.publish(
            "session_updated",
            {
                "cid": "conv_valid_0001",
                "turn_id": "tg-1111222233334444",
                "owner_user_id": ADMIN_UID_A,
                "user_id": ADMIN_UID_A,
                "prompt": "raw prompt",
                "response": "raw response",
                "content": "raw content",
                "thinking": "raw thinking",
            },
        )
        direct_evs = await _read_sse_events(resp_ev, max_events=2, timeout=0.8)
        resp_ev.close()
        self.assertTrue(direct_evs)
        ddata = direct_evs[-1]["data"]
        assert isinstance(ddata, dict)
        for fk in ("turn_id", "owner_user_id", "user_id", "prompt", "response", "content", "thinking"):
            self.assertNotIn(fk, ddata)


class TestPBC4SingleWriterMirrorFaultToleranceAndDmAlignment(unittest.TestCase):
    """PB-C4: non-fatal TG mirror failure, single-writer 409 session_busy, safe DM alignment & warm recycle."""

    def test_pb_c4_mirror_exception_nonfatal_single_writer_409_and_dm_alignment(self) -> None:
        with tempfile.TemporaryDirectory(prefix="agy_pbc4_") as td:
            bus_dir = Path(td) / "bus"
            bus_dir.mkdir(parents=True)
            buf = studio_ipc.TurnEventBuffer()

            # (1) TG mirror throws on both prompt & result -> Web turn still finishes, lease released, chat_sync=done
            emitted: list[tuple[str, dict]] = []
            fs = _ScriptedFakeSession(
                [
                    {"event": "init", "conversation_id": "conv_web_sync_01"},
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "agent_response",
                            "state": "ACTIVE",
                            "step_index": 1,
                            "text_delta": "hello from web",
                        },
                    },
                    {
                        "event": "result",
                        "status": "SUCCESS",
                        "conversation_id": "conv_web_sync_01",
                        "response": "hello from web",
                    },
                ],
                cid=None,
            )

            # Seed an idle stale DM warm session holding old cid
            dm_skey = bridge_mod.scope_key_for(ADMIN_UID_A, None)
            stale_warm = _ScriptedFakeSession([], cid="conv_old_dm_0001")
            orig_pool = dict(bridge_mod._session_pool)
            orig_scopes = json.loads(json.dumps(bridge_mod.state.get("scopes") or {}))
            closed_sessions: list[object] = []

            try:
                bridge_mod._session_pool[dm_skey] = stale_warm
                with (
                    mock.patch.object(bot_bus, "BUS_DIR", str(bus_dir)),
                    mock.patch.object(bridge_mod, "_studio_ipc_buffer", buf),
                    mock.patch.object(bridge_mod, "ALLOWED", {ADMIN_UID_A}),
                    mock.patch.object(bridge_mod, "ADMIN_USERS", {ADMIN_UID_A}),
                    mock.patch.object(bridge_mod, "save_state"),
                    mock.patch.object(bridge_mod, "_acquire_session", return_value=(fs, False)),
                    mock.patch.object(bridge_mod, "send", side_effect=RuntimeError("TG 429 rate limit")),
                    mock.patch.object(bridge_mod, "send_rich", side_effect=TimeoutError("TG 500 timeout")),
                    mock.patch.object(bridge_mod, "close_session_async", side_effect=lambda s, force=False: closed_sessions.append(s)),
                    mock.patch.object(bridge_mod, "_current_bot_handle", return_value=TEST_BOT_HANDLE),
                ):
                    bridge_mod.run_agy(
                        0,
                        "sync web prompt",
                        scope_key=f"web:{ADMIN_UID_A}:turn-1",
                        user_role="admin",
                        user_id=ADMIN_UID_A,
                        event_sink=lambda t, p: emitted.append((t, p)),
                        web_turn_id="turn-0000111122223333",
                        sync_tg=True,
                    )

                ev_types = [t for t, _ in emitted]
                self.assertIn("text_delta", ev_types)
                self.assertIn("done", ev_types)
                self.assertFalse(studio_ipc.is_conversation_locked(bus_dir, "conv_web_sync_01"))

                sync_doc = json.loads((bus_dir / "chat_sync" / f"{TEST_BOT_HANDLE}.json").read_text(encoding="utf-8"))
                self.assertEqual(sync_doc["cid"], "conv_web_sync_01")
                self.assertEqual(sync_doc["source"], "web")
                self.assertEqual(sync_doc["status"], "done")

                # (3a) Idle stale DM warm session was popped & closed, and DM conversation_id aligned
                self.assertEqual(bridge_mod.state["scopes"][dm_skey]["conversation_id"], "conv_web_sync_01")
                self.assertNotIn(dm_skey, bridge_mod._session_pool)
                self.assertIn(stale_warm, closed_sessions)

                # (3b) If DM scope IS actively running a TG turn, warm session MUST NOT be popped or killed
                active_tg_warm = _ScriptedFakeSession([], cid="conv_running_tg_1")
                bridge_mod._session_pool[dm_skey] = active_tg_warm
                closed_sessions.clear()
                with (
                    mock.patch.object(bridge_mod, "ALLOWED", {ADMIN_UID_A}),
                    mock.patch.object(bridge_mod, "ADMIN_USERS", {ADMIN_UID_A}),
                    mock.patch.object(bridge_mod, "save_state"),
                    mock.patch.object(bridge_mod, "turn_running", True),
                    mock.patch.object(bridge_mod, "turn_running_scope", dm_skey),
                    mock.patch.object(bridge_mod, "close_session_async", side_effect=lambda s, force=False: closed_sessions.append(s)),
                ):
                    bridge_mod._align_dm_scope_after_web_turn(ADMIN_UID_A, "conv_web_sync_02")
                self.assertIs(bridge_mod._session_pool.get(dm_skey), active_tg_warm)
                self.assertEqual(len(closed_sessions), 0)

                # (2) Concurrent Web send targeting a cid with active TG turn -> deterministic 409 session_busy
                with (
                    mock.patch.object(bot_bus, "BUS_DIR", str(bus_dir)),
                    mock.patch.object(bridge_mod, "_studio_ipc_buffer", buf),
                    mock.patch.object(bridge_mod, "turn_running", True),
                    mock.patch.object(bridge_mod, "turn_running_cid", "conv_busy_tg_001"),
                ):
                    sc_409, body_409 = bridge_mod._studio_ipc_enqueue_turn(
                        {"user_id": ADMIN_UID_A, "prompt": "concurrent write", "cid": "conv_busy_tg_001", "sync_tg": True}
                    )
                self.assertEqual(sc_409, 409)
                self.assertEqual(body_409.get("code"), "session_busy")
            finally:
                bridge_mod._session_pool.clear()
                bridge_mod._session_pool.update(orig_pool)
                bridge_mod.state["scopes"] = orig_scopes


class TestPBC5TgStreamRevocationConcurrencyAndRedaction(_PhaseBStudioBase):
    """PB-C5: tg-* live revocation <= 0.8s zero leak, mixed turn-*/tg-* caps 429, cross-chunk redaction & <=16KiB."""

    async def test_pb_c5_tg_stream_revocation_concurrency_caps_and_cross_chunk_redaction(self) -> None:
        _, sid_a, csrf_a = await self._login("admin_a", PASS_ADMIN_A)

        # (3) Cross-chunk secret redaction & <= 16 KiB frame cap on tg-* stream
        tg_red = "tg-abcdef0123456789"
        self.ipc_buf.create_turn(
            tg_red,
            owner_user_id=ADMIN_UID_A,
            bot_handle=TEST_BOT_HANDLE,
            cid="conv_valid_0001",
            source="tg",
        )
        part1 = "secret is ghp_"
        part2 = "SplitTokenSecret99887766 end"
        self.ipc_buf.append(tg_red, "text_delta", {"delta": part1, "step_index": 1})
        self.ipc_buf.append(tg_red, "text_delta", {"delta": part2, "step_index": 1})
        self.ipc_buf.append(tg_red, "done", {"conversation_id": "conv_valid_0001", "response": "X" * 24000, "status": "SUCCESS"})

        resp_red = await self.client.get(
            f"/api/chat/stream?turn_id={tg_red}&bot={TEST_BOT_HANDLE}",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
        )
        self.assertEqual(resp_red.status, 200)
        red_evs = await _read_sse_events(resp_red, max_events=10, timeout=2.0)
        resp_red.close()
        combined = "".join(str(e["data"].get("delta", "")) for e in red_evs if e["event"] == "text_delta" and isinstance(e["data"], dict))
        self.assertNotIn("SplitTokenSecret99887766", combined)
        self.assertIn("[REDACTED]", combined)
        for ev in red_evs:
            self.assertLessEqual(int(ev["raw_len"]), CHAT_MAX_SSE_BYTES)

        # (2) Mixed turn-* and tg-* concurrency cap: > 4 per session -> 429, 0 slot leak after close
        chat_svc = self.app[CHAT_SERVICE_KEY]
        open_resps: list[aiohttp.ClientResponse] = []
        created_tids: list[str] = []
        try:
            # 2 web turns + 2 tg turns = 4 slots filled
            for idx in range(2):
                r_send = await self.client.post(
                    "/api/chat/send",
                    headers=self._write_headers(sid_a, csrf_a),
                    json={"prompt": f"web turn {idx}"},
                )
                self.assertEqual(r_send.status, 202)
                w_tid = (await r_send.json())["turn_id"]
                created_tids.append(w_tid)
                self.ipc_buf.append(w_tid, "turn_start", {"turn_id": w_tid})
                rs = await self.client.get(
                    f"/api/chat/stream?turn_id={w_tid}&bot={TEST_BOT_HANDLE}",
                    headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
                )
                self.assertEqual(rs.status, 200)
                open_resps.append(rs)

            for idx in range(2):
                t_tid = f"tg-111122223333000{idx}"
                created_tids.append(t_tid)
                self.ipc_buf.create_turn(t_tid, owner_user_id=ADMIN_UID_A, bot_handle=TEST_BOT_HANDLE, cid="conv_valid_0001", source="tg")
                self.ipc_buf.append(t_tid, "turn_start", {"turn_id": t_tid})
                rs = await self.client.get(
                    f"/api/chat/stream?turn_id={t_tid}&bot={TEST_BOT_HANDLE}",
                    headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
                )
                self.assertEqual(rs.status, 200)
                open_resps.append(rs)

            # 5th stream (tg-*) MUST be rejected with 429
            tg_5 = "tg-1111222233330009"
            self.ipc_buf.create_turn(tg_5, owner_user_id=ADMIN_UID_A, bot_handle=TEST_BOT_HANDLE, cid="conv_valid_0001", source="tg")
            r_429 = await self.client.get(
                f"/api/chat/stream?turn_id={tg_5}&bot={TEST_BOT_HANDLE}",
                headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
            )
            self.assertEqual(r_429.status, 429)
        finally:
            for tid in created_tids:
                self.ipc_buf.append(tid, "done", {"status": "SUCCESS"})
            for r in open_resps:
                r.close()
            await asyncio.sleep(0.15)
        self.assertEqual(len(chat_svc._active_streams), 0)

        # (1) Real-time revocation (logout) while subscribed to tg-* stream + /api/events
        # -> closes within <= 0.8s with auth_error and 0 post-revocation data frames leaked
        tg_rev = "tg-9999888877776666"
        self.ipc_buf.create_turn(tg_rev, owner_user_id=ADMIN_UID_A, bot_handle=TEST_BOT_HANDLE, cid="conv_valid_0001", source="tg")
        self.ipc_buf.append(tg_rev, "turn_start", {"turn_id": tg_rev})

        resp_tg = await self.client.get(
            f"/api/chat/stream?turn_id={tg_rev}&bot={TEST_BOT_HANDLE}",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
        )
        self.assertEqual(resp_tg.status, 200)
        first_tg = await _read_sse_events(resp_tg, max_events=1, timeout=1.0)
        self.assertEqual(first_tg[0]["event"], "turn_start")

        resp_ev = await self.client.get(
            "/api/events",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a}"},
        )
        self.assertEqual(resp_ev.status, 200)
        first_ev = await _read_sse_events(resp_ev, max_events=1, timeout=1.0)
        self.assertEqual(first_ev[0]["event"], "connected")

        t0 = time.monotonic()
        r_out = await self.client.post(
            "/api/auth/logout",
            headers=self._write_headers(sid_a, csrf_a),
            json={},
        )
        self.assertEqual(r_out.status, 200)

        # Immediately emit post-revocation data into both tg-* buffer and EventHub
        self.ipc_buf.append(tg_rev, "text_delta", {"delta": "POST_REVOKE_TG_LEAK"})
        self.app[EVENT_HUB_KEY].publish("session_updated", {"cid": "conv_valid_0001", "status": "POST_REVOKE_EV_LEAK"})

        tail_tg = await _read_sse_events(resp_tg, max_events=5, timeout=1.2)
        tail_ev = await _read_sse_events(resp_ev, max_events=5, timeout=1.2)
        elapsed = time.monotonic() - t0
        resp_tg.close()
        resp_ev.close()

        self.assertLessEqual(elapsed, 0.85, f"Revocation teardown exceeded budget: {elapsed:.3f}s")
        self.assertTrue(any(e["event"] == "auth_error" for e in tail_tg), f"Expected auth_error on tg stream: {tail_tg}")
        self.assertTrue(any(e["event"] == "auth_error" for e in tail_ev), f"Expected auth_error on /api/events: {tail_ev}")
        self.assertFalse(any(e["event"] == "text_delta" for e in tail_tg), f"Leaked tg data after logout: {tail_tg}")
        self.assertFalse(any(e["event"] == "session_updated" for e in tail_ev), f"Leaked event after logout: {tail_ev}")

        # Also verify live RBAC admin -> readonly downgrade disconnects tg-* stream with 0 leaked frames
        _, sid_a2, _ = await self._login("admin_a", PASS_ADMIN_A)
        tg_deg = "tg-5555444433332222"
        self.ipc_buf.create_turn(tg_deg, owner_user_id=ADMIN_UID_A, bot_handle=TEST_BOT_HANDLE, cid="conv_valid_0001", source="tg")
        self.ipc_buf.append(tg_deg, "turn_start", {"turn_id": tg_deg})

        resp_deg = await self.client.get(
            f"/api/chat/stream?turn_id={tg_deg}&bot={TEST_BOT_HANDLE}",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_a2}"},
        )
        self.assertEqual(resp_deg.status, 200)
        _ = await _read_sse_events(resp_deg, max_events=1, timeout=1.0)

        # Downgrade admin_a in live .env to readonly
        _write_env(
            self.env_file,
            [
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_TEST}",
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID_A},{ADMIN_UID_B},{READONLY_UID}",
                f"AGY_TG_ADMIN_USERS={ADMIN_UID_B}",
                f"AGY_TG_READONLY_USERS={ADMIN_UID_A},{READONLY_UID}",
            ],
        )
        await asyncio.sleep(0.18)
        self.ipc_buf.append(tg_deg, "text_delta", {"delta": "POST_DOWNGRADE_LEAK"})
        tail_deg = await _read_sse_events(resp_deg, max_events=5, timeout=1.0)
        resp_deg.close()
        self.assertTrue(any(e["event"] == "auth_error" for e in tail_deg), f"Expected auth_error on downgrade: {tail_deg}")
        self.assertFalse(any(e["event"] == "text_delta" for e in tail_deg), f"Leaked frame after downgrade: {tail_deg}")


class TestPBC6FrontendSyncRaceAndDedup(unittest.TestCase):
    """PB-C6: Frontend static invariants + Node.js race/dedup state-machine verification."""

    def test_pb_c6_frontend_workspace_sync_guards_and_contracts(self) -> None:
        types_src = (REPO_ROOT / "webui" / "src" / "types.ts").read_text(encoding="utf-8")
        api_src = (REPO_ROOT / "webui" / "src" / "api.ts").read_text(encoding="utf-8")
        app_src = (REPO_ROOT / "webui" / "src" / "App.tsx").read_text(encoding="utf-8")
        ws_src = (REPO_ROOT / "webui" / "src" / "components" / "WorkspaceView.tsx").read_text(encoding="utf-8")

        # 1. Types & API client wiring
        self.assertIn('"session_updated"', types_src)
        self.assertIn("sync_tg?: boolean;", types_src)
        self.assertIn("ActiveSessionTurnResponse", types_src)
        self.assertIn('bindType("session_updated")', api_src)
        self.assertIn("export function fetchActiveSessionTurn", api_src)
        self.assertIn("/active-turn", api_src)

        # 2. App.tsx forwards monotonic sessionSyncEvent on session_updated & resync_required
        self.assertIn('ev.type === "session_updated"', app_src)
        self.assertIn("sessionSyncEvent={sessionSyncEvent}", app_src)

        # 3. WorkspaceView.tsx guards:
        # - Admin-only syncTg toggle default true, persisted in localStorage, invisible for readonly
        self.assertIn("SYNC_TG_STORAGE_KEY", ws_src)
        self.assertIn("localStorage.getItem(SYNC_TG_STORAGE_KEY)", ws_src)
        self.assertIn("localStorage.setItem(SYNC_TG_STORAGE_KEY", ws_src)
        self.assertIn("sync_tg: !isReadonly && syncTg", ws_src)
        self.assertIn("{!isReadonly && (", ws_src)
        self.assertIn("同步到 TG", ws_src)

        # - Readonly never probes active-turn or mounts /api/chat/stream
        self.assertIn("if (isReadonly || !cid || streamingRef.current) return;", ws_src)
        self.assertIn("if (!isReadonly && !streamingRef.current)", ws_src)

        # - Monotonic genRef + activeCidRef + streamingRef guards in loadSessionHistory,
        #   probeAndAttachActiveTurn, handleSend & attachStream
        self.assertIn(
            "genRef.current !== reqGen || activeCidRef.current !== cid || (!beforeCursor && streamingRef.current)",
            ws_src,
        )
        self.assertIn("genRef.current += 1", ws_src)
        self.assertRegex(
            ws_src,
            r"const handleSend = async \(\) => \{[\s\S]*?genRef\.current \+= 1;\s*const sendGen = genRef\.current;[\s\S]*?attachStream\(res\.turn_id,\s*res\.bot \|\| selectedBot,\s*sendGen,\s*\"local\"\);",
        )
        self.assertRegex(
            ws_src,
            r"const probeAndAttachActiveTurn = useCallback\([\s\S]*?if \(!res\.active \|\| !res\.turn_id\)[\s\S]*?genRef\.current \+= 1;\s*const attachGen = genRef\.current;[\s\S]*?attachStream\(res\.turn_id,\s*res\.bot \|\| botHint \|\| selectedBot,\s*attachGen,\s*\"remote\"\);",
        )
        self.assertIn("TG 实时同步中", ws_src)

        # 4. Run Node.js deterministic simulation of race & deduplication invariants
        node_script = r"""
const assert = require("assert");

// Simulate WorkspaceView monotonic generation + dedup controller
function createController({ isReadonly }) {
  let gen = 0;
  let activeCid = null;
  let streaming = false;
  let streamingSource = null;
  let activeTurnId = null;
  let messages = [];
  let activeTurnCalls = 0;
  let streamMounts = [];

  function selectSession(cid) {
    if (streaming && streamingSource === "local") return;
    gen += 1;
    streaming = false;
    streamingSource = null;
    activeTurnId = null;
    activeCid = cid;
    return gen;
  }

  function newChat() {
    if (streaming && streamingSource === "local") return;
    gen += 1;
    streaming = false;
    streamingSource = null;
    activeTurnId = null;
    activeCid = null;
    messages = [];
    return gen;
  }

  function applyHistoryResult(cid, expectedGen, msgs, beforeCursor = null) {
    if (gen !== expectedGen || activeCid !== cid || (!beforeCursor && streaming)) return false;
    if (beforeCursor) {
      messages = [...msgs, ...messages];
    } else {
      messages = [...msgs];
    }
    return true;
  }

  function onSessionUpdated(ev, mockActiveTurn) {
    if (!activeCid || ev.cid !== activeCid) return;
    if (ev.status === "running") {
      if (isReadonly || streaming) return;
      const reqGen = gen;
      activeTurnCalls += 1;
      const res = mockActiveTurn();
      if (gen !== reqGen || activeCid !== ev.cid || streaming) return;
      if (!res.active || !res.turn_id || activeTurnId === res.turn_id) return;
      gen += 1;
      const attachGen = gen;
      streaming = true;
      streamingSource = "remote";
      activeTurnId = res.turn_id;
      const aId = `remote-a-${res.turn_id}`;
      messages = messages.filter((m) => m.id !== aId);
      messages.push({ id: aId, role: "assistant", content: "" });
      streamMounts.push({ turnId: res.turn_id, streamGen: attachGen, mode: "remote" });
    } else if (ev.status === "done") {
      if (!streaming || streamingSource === "remote") {
        streaming = false;
        streamingSource = null;
        activeTurnId = null;
      }
    }
  }

  return {
    selectSession,
    newChat,
    applyHistoryResult,
    onSessionUpdated,
    startLocalTurn(cid) {
      gen += 1;
      const sendGen = gen;
      activeCid = cid;
      streaming = true;
      streamingSource = "local";
      activeTurnId = "turn-local1";
      messages = [
        ...messages,
        { id: "u-1", role: "user", content: "hi" },
        { id: "a-1", role: "assistant", content: "" },
      ];
      streamMounts.push({ turnId: "turn-local1", streamGen: sendGen, mode: "local" });
      return sendGen;
    },
    state: () => ({ gen, activeCid, streaming, streamingSource, activeTurnId, messages, activeTurnCalls, streamMounts }),
  };
}

// Case 1: readonly receiving running -> 0 active-turn calls, 0 stream mounts
const ro = createController({ isReadonly: true });
ro.selectSession("conv_01");
ro.onSessionUpdated({ cid: "conv_01", status: "running" }, () => ({ active: true, turn_id: "tg-1111222233334444" }));
assert.strictEqual(ro.state().activeTurnCalls, 0);
assert.strictEqual(ro.state().streamMounts.length, 0);

// Case 2: admin local Web turn receiving echoed running -> 0 active-turn calls, 0 duplicate bubbles
const admLocal = createController({ isReadonly: false });
admLocal.startLocalTurn("conv_01");
admLocal.onSessionUpdated({ cid: "conv_01", status: "running" }, () => ({ active: true, turn_id: "turn-local1" }));
assert.strictEqual(admLocal.state().activeTurnCalls, 0);
assert.strictEqual(admLocal.state().messages.length, 2);

// Case 3: admin receiving duplicate running -> mounted ONCE; stale history from old cid dropped after switch/newChat
const adm = createController({ isReadonly: false });
const g1 = adm.selectSession("conv_01");
adm.onSessionUpdated({ cid: "conv_01", status: "running" }, () => ({ active: true, turn_id: "tg-aaaa1111bbbb2222" }));
adm.onSessionUpdated({ cid: "conv_01", status: "running" }, () => ({ active: true, turn_id: "tg-aaaa1111bbbb2222" }));
assert.strictEqual(adm.state().streamMounts.length, 1);
assert.strictEqual(adm.state().streamMounts[0].streamGen, adm.state().gen);
adm.newChat();
const appliedStale = adm.applyHistoryResult("conv_01", g1, [{ id: "old", role: "user", content: "stale" }]);
assert.strictEqual(appliedStale, false);
assert.strictEqual(adm.state().messages.length, 0);

// Case 4: in-flight loadSessionHistory resolving AFTER probeAndAttachActiveTurn MUST NOT overwrite remote stream bubble
const raceRemote = createController({ isReadonly: false });
const histGenRemote = raceRemote.selectSession("conv_race_remote");
raceRemote.onSessionUpdated({ cid: "conv_race_remote", status: "running" }, () => ({
  active: true,
  turn_id: "tg-cccc3333dddd4444",
}));
assert.strictEqual(raceRemote.state().gen, histGenRemote + 1);
assert.strictEqual(raceRemote.state().streamMounts[0].streamGen, histGenRemote + 1);
const overwrittenByOldGen = raceRemote.applyHistoryResult("conv_race_remote", histGenRemote, [
  { id: "h-old", role: "user", content: "stale history snapshot" },
]);
assert.strictEqual(overwrittenByOldGen, false);
// Defense-in-depth: even with matching gen, full history overwrite is blocked while streaming=true
const overwrittenWhileStreaming = raceRemote.applyHistoryResult("conv_race_remote", raceRemote.state().gen, [
  { id: "h-samegen", role: "user", content: "must not wipe stream" },
]);
assert.strictEqual(overwrittenWhileStreaming, false);
assert.deepStrictEqual(
  raceRemote.state().messages.map((m) => m.id),
  ["remote-a-tg-cccc3333dddd4444"],
);
// Pagination (beforeCursor truthy) with matching gen still prepends without wiping the active stream bubble
const prependedOlder = raceRemote.applyHistoryResult(
  "conv_race_remote",
  raceRemote.state().gen,
  [{ id: "h-page1", role: "user", content: "earlier message" }],
  10,
);
assert.strictEqual(prependedOlder, true);
assert.deepStrictEqual(
  raceRemote.state().messages.map((m) => m.id),
  ["h-page1", "remote-a-tg-cccc3333dddd4444"],
);

// Case 5: in-flight loadSessionHistory resolving AFTER handleSend MUST NOT overwrite local stream bubbles
const raceLocal = createController({ isReadonly: false });
const histGenLocal = raceLocal.selectSession("conv_race_local");
const sendGen = raceLocal.startLocalTurn("conv_race_local");
assert.strictEqual(sendGen, histGenLocal + 1);
assert.strictEqual(raceLocal.state().streamMounts[0].streamGen, sendGen);
const overwrittenLocal = raceLocal.applyHistoryResult("conv_race_local", histGenLocal, [
  { id: "h-old-local", role: "user", content: "stale history snapshot" },
]);
assert.strictEqual(overwrittenLocal, false);
assert.deepStrictEqual(
  raceLocal.state().messages.map((m) => m.id),
  ["u-1", "a-1"],
);
console.log("NODE_SIM_OK");
"""
        proc = subprocess.run(
            ["node", "-e", node_script],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, f"Node sim failed: {proc.stderr}")
        self.assertIn("NODE_SIM_OK", proc.stdout)


class TestPBC7IpcActiveAuthAndTurnLifecycleCleanup(_PhaseBStudioBase):
    """PB-C7: /ipc/chat/active transport fail-closed 403 + run_agy all exit paths clean up tg-* & chat_sync."""

    def test_pb_c7_ipc_active_transport_guards_and_run_agy_all_exit_cleanup(self) -> None:
        # (1) /ipc/chat/active transport & user_id fail-closed 403
        # Wrong token
        sc, _, raw = _uds_http_request(
            self.ipc_srv.sock_path,
            "GET",
            f"/ipc/chat/active?cid=conv_valid_0001&user_id={ADMIN_UID_A}",
            headers={"X-Bridge-IPC-Token": "wrong_token"},
        )
        self.assertEqual(sc, 403)
        self.assertEqual(json.loads(raw).get("source"), "bridge_ipc")

        # Spoofed proxy headers
        for hdr in ("X-Forwarded-For", "CF-Connecting-IP", "X-Real-IP"):
            sc_h, _, _ = _uds_http_request(
                self.ipc_srv.sock_path,
                "GET",
                f"/ipc/chat/active?cid=conv_valid_0001&user_id={ADMIN_UID_A}",
                headers={"X-Bridge-IPC-Token": self.ipc_srv.token, hdr: "203.0.113.10"},
            )
            self.assertEqual(sc_h, 403, f"Expected 403 for spoofed header {hdr}")

        # Mismatched SO_PEERCRED UID
        self.peer_uid_box[0] = os.getuid() + 999
        try:
            sc_p, _, _ = _uds_http_request(
                self.ipc_srv.sock_path,
                "GET",
                f"/ipc/chat/active?cid=conv_valid_0001&user_id={ADMIN_UID_A}",
                headers={"X-Bridge-IPC-Token": self.ipc_srv.token},
            )
            self.assertEqual(sc_p, 403)
        finally:
            self.peer_uid_box[0] = os.getuid()

        # Invalid user_id
        for bad_uid in ("0", "-5", "notanint", "true", ""):
            sc_u, _, _ = _uds_http_request(
                self.ipc_srv.sock_path,
                "GET",
                f"/ipc/chat/active?cid=conv_valid_0001&user_id={bad_uid}",
                headers={"X-Bridge-IPC-Token": self.ipc_srv.token},
            )
            self.assertEqual(sc_u, 403, f"Expected 403 for invalid user_id={bad_uid!r}")

        # (2) run_agy ALL exit paths for TG DM admin turn:
        #     (a) coalesced_final_delivered early return
        #     (b) mid-turn exception
        #     (c) EOF / cancelled (result is None)
        buf = studio_ipc.TurnEventBuffer()
        sync_file = self.bus_dir / "chat_sync" / f"{TEST_BOT_HANDLE}.json"

        class _CoalesceStreamer(_StubLiveDraftStreamer):
            def finalize_step(self, *args, **kwargs):
                return (9001, "<b>done</b>")

        with (
            mock.patch.object(bot_bus, "BUS_DIR", str(self.bus_dir)),
            mock.patch.object(bridge_mod, "_studio_ipc_buffer", buf),
            mock.patch.object(bridge_mod, "ALLOWED", {ADMIN_UID_A}),
            mock.patch.object(bridge_mod, "ADMIN_USERS", {ADMIN_UID_A}),
            mock.patch.object(bridge_mod, "save_state"),
            mock.patch.object(bridge_mod, "LiveDraftStreamer", _CoalesceStreamer),
            mock.patch.object(bridge_mod, "send", return_value=1),
            mock.patch.object(bridge_mod, "send_rich", return_value=(1, "ok")),
            mock.patch.object(bridge_mod, "push_step_images"),
            mock.patch.object(bridge_mod, "_maybe_post_turn_auto_compact"),
            mock.patch.object(bridge_mod, "_record_and_relay_bot_group_msg"),
            mock.patch.object(bridge_mod, "_compute_workspace_diff_and_footer", return_value=("", None)),
            mock.patch.object(bridge_mod, "get_turn_details", return_value=([], [], 0)),
            mock.patch.object(bridge_mod, "_current_bot_handle", return_value=TEST_BOT_HANDLE),
        ):
            # (a) Coalesced early return
            fs_coal = _ScriptedFakeSession(
                [
                    {"event": "init", "conversation_id": "conv_coal_000001"},
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "agent_response",
                            "state": "DONE",
                            "step_index": 1,
                            "text_delta": "coalesced answer",
                        },
                    },
                    {
                        "event": "result",
                        "status": "SUCCESS",
                        "conversation_id": "conv_coal_000001",
                        "response": "coalesced answer",
                    },
                ],
                cid="conv_coal_000001",
            )
            with mock.patch.object(bridge_mod, "_acquire_session", return_value=(fs_coal, False)):
                bridge_mod.run_agy(
                    ADMIN_UID_A,
                    "coalesce test",
                    user_role="admin",
                    user_id=ADMIN_UID_A,
                    override_cid="conv_coal_000001",
                )
            coal_tids = [t for t in buf._turns if studio_ipc.is_valid_tg_turn_id(t)]
            self.assertEqual(len(coal_tids), 1)
            coal_info = buf.get_turn_info(coal_tids[0])
            assert coal_info is not None
            self.assertTrue(coal_info["finished"])
            self.assertEqual(coal_info["status"], "done")
            sync_coal = json.loads(sync_file.read_text(encoding="utf-8"))
            self.assertEqual(sync_coal["status"], "done")
            self.assertFalse(studio_ipc.is_conversation_locked(self.bus_dir, "conv_coal_000001"))

            # (b) Mid-turn exception -> finally closes tg-* with error & chat_sync=error
            fs_exc = _ScriptedFakeSession(
                [],
                cid="conv_exc_0000001",
                raise_on_next=RuntimeError("boom mid-turn"),
            )
            with mock.patch.object(bridge_mod, "_acquire_session", return_value=(fs_exc, False)):
                with self.assertRaises(RuntimeError):
                    bridge_mod.run_agy(
                        ADMIN_UID_A,
                        "exception test",
                        user_role="admin",
                        user_id=ADMIN_UID_A,
                        override_cid="conv_exc_0000001",
                    )
            exc_tids = [t for t in buf._turns if t not in coal_tids]
            self.assertEqual(len(exc_tids), 1)
            exc_info = buf.get_turn_info(exc_tids[0])
            assert exc_info is not None
            self.assertTrue(exc_info["finished"])
            self.assertEqual(exc_info["status"], "error")
            sync_exc = json.loads(sync_file.read_text(encoding="utf-8"))
            self.assertEqual(sync_exc["cid"], "conv_exc_0000001")
            self.assertEqual(sync_exc["status"], "error")
            self.assertFalse(studio_ipc.is_conversation_locked(self.bus_dir, "conv_exc_0000001"))

            # (c) Interrupted EOF (returncode=-15, result=None) -> tg-* aborted & chat_sync=aborted
            fs_eof = _ScriptedFakeSession(
                [{"event": "__eof__"}],
                cid="conv_eof_0000001",
                returncode=-15,
            )
            with mock.patch.object(bridge_mod, "_acquire_session", return_value=(fs_eof, False)):
                bridge_mod.run_agy(
                    ADMIN_UID_A,
                    "eof cancel test",
                    user_role="admin",
                    user_id=ADMIN_UID_A,
                    override_cid="conv_eof_0000001",
                )
            eof_tids = [t for t in buf._turns if t not in coal_tids and t not in exc_tids]
            self.assertEqual(len(eof_tids), 1)
            eof_info = buf.get_turn_info(eof_tids[0])
            assert eof_info is not None
            self.assertTrue(eof_info["finished"])
            self.assertEqual(eof_info["status"], "aborted")
            sync_eof = json.loads(sync_file.read_text(encoding="utf-8"))
            self.assertEqual(sync_eof["cid"], "conv_eof_0000001")
            self.assertEqual(sync_eof["status"], "aborted")
            self.assertFalse(studio_ipc.is_conversation_locked(self.bus_dir, "conv_eof_0000001"))


class TestPBC8IsolationAndHygiene(unittest.TestCase):
    """PB-C8: Protected files 0 diff, webui/dist & node_modules untracked, no hardcoded personal paths."""

    def test_pb_c8_protected_files_untracked_dist_and_no_real_browser(self) -> None:
        protected = (
            ".agents/skills/google-profile/scripts/google_browser.py",
            ".agents/skills/live-browser/scripts/static/index.html",
        )
        diff_proc = subprocess.run(
            ["git", "diff", "--name-only", "HEAD", "--", *protected],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(diff_proc.returncode, 0)
        self.assertEqual(diff_proc.stdout.strip(), "", f"Protected files modified: {diff_proc.stdout}")

        tracked_proc = subprocess.run(
            ["git", "ls-files", "webui/dist", "webui/node_modules"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(tracked_proc.returncode, 0)
        self.assertEqual(tracked_proc.stdout.strip(), "", f"Build artifacts tracked in git: {tracked_proc.stdout}")

        # Verify no hardcoded user home path in modified Phase B source files
        home_re = re.compile(r"/" + r"home" + r"/[a-zA-Z0-9_-]+/")
        for rel in (
            "bridge/studio_ipc.py",
            "studio/event_hub.py",
            "studio/chat_service.py",
            "studio/server.py",
            "webui/src/types.ts",
            "webui/src/api.ts",
            "webui/src/App.tsx",
            "webui/src/components/WorkspaceView.tsx",
        ):
            txt = (REPO_ROOT / rel).read_text(encoding="utf-8")
            self.assertIsNone(home_re.search(txt), f"Hardcoded home path found in {rel}")


if __name__ == "__main__":
    unittest.main()
