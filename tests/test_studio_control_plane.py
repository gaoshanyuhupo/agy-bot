#!/usr/bin/env python3
"""Phase A M2 Contract Unit & Integration Tests (`PA-C1`..`PA-C7`).

Runs completely isolated in temporary directories with real in-process AF_UNIX
`StudioIPCServer` and aiohttp `TestClient` (zero real browsers, zero systemd
mutations, zero host state changes).
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
import scheduler  # noqa: E402
import studio_ipc  # noqa: E402
from studio.auth import (  # noqa: E402
    SESSION_COOKIE_NAME,
    StudioAuthManager,
    hash_password_scrypt,
    save_users_file_atomic,
)
from studio.data_sources import MAX_MESSAGE_BYTES, StudioDataSources, redact_job_detail_text  # noqa: E402
from studio.event_hub import MAX_SSE_EVENT_BYTES  # noqa: E402
from studio.server import (  # noqa: E402
    CSP_HEADER_PASSWORD,
    EVENT_HUB_KEY,
    create_app,
)

BOT_TOKEN_TEST = "123456789:EXAMPLE_M2_TEST_TOKEN_MAIN_0001"
ADMIN_UID = 111111111
READONLY_UID = 222222222
DENIED_UID = 333333333
TEST_BOT_ONLINE = "example_bot_online"
TEST_BOT_OFFLINE = "example_bot_offline"
TEST_PASS_ADMIN = "EXAMPLE_ADMIN_PASS_01"
TEST_PASS_RO = "EXAMPLE_RO_PASS_01"
TEST_PASS_FORCE = "EXAMPLE_FORCE_PASS_01"


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
            # Server may reject early (e.g. 403 on bad header) and close before draining body;
            # still attempt to read the HTTP response if the socket was established.
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
    """Read structured SSE events from an open aiohttp response until EOF, max_events, or timeout."""
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
                events.append({"event": cur_event, "id": cur_id, "data": parsed, "raw_len": len(raw_data.encode("utf-8"))})
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


class _ControlPlaneBaseTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="agy_m2_test_")
        self.tmp = Path(self._td.name)
        self.config_dir = self.tmp / "studio-config"
        self.bridge_dir = self.tmp / "bridge-env"
        self.bus_dir = self.tmp / "bot_bus"
        self.projects_dir = self.tmp / "projects"
        self.allowed_proj_dir = self.tmp / "repos" / "safe-proj"
        self.schedules_file = self.tmp / "scheduled_tasks.json"
        self.audit_log = self.config_dir / "audit.jsonl"

        self.config_dir.mkdir(parents=True)
        self.bridge_dir.mkdir(parents=True)
        (self.bus_dir / "jobs").mkdir(parents=True)
        (self.bus_dir / "inbox").mkdir(parents=True)
        self.projects_dir.mkdir(parents=True)
        self.allowed_proj_dir.mkdir(parents=True)

        # Seed whitelisted project definition
        (self.projects_dir / "safe-proj.json").write_text(
            json.dumps({
                "id": "safe-proj",
                "name": "Safe Project",
                "projectResources": {
                    "resources": [{"folderUri": f"file://{self.allowed_proj_dir}"}]
                },
            }),
            encoding="utf-8",
        )

        # Seed `.env` with ADMIN_UID (admin) and READONLY_UID (readonly)
        self.env_file = self.bridge_dir / ".env"
        _write_env(
            self.env_file,
            [
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_TEST}",
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                f"AGY_TG_READONLY_USERS={READONLY_UID}",
            ],
        )

        # Seed users.json
        now_i = int(time.time())
        users_map = {
            "admin_user": {
                "username": "admin_user",
                "password_hash": hash_password_scrypt(TEST_PASS_ADMIN),
                "role": "admin",
                "bot": "main",
                "user_id": ADMIN_UID,
                "enabled": True,
                "must_change_password": False,
                "password_version": 1,
                "created_at": now_i,
                "updated_at": now_i,
            },
            "ro_user": {
                "username": "ro_user",
                "password_hash": hash_password_scrypt(TEST_PASS_RO),
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
                "password_hash": hash_password_scrypt(TEST_PASS_FORCE),
                "role": "admin",
                "bot": "main",
                "user_id": ADMIN_UID,
                "enabled": True,
                "must_change_password": True,
                "password_version": 1,
                "created_at": now_i,
                "updated_at": now_i,
            },
        }
        save_users_file_atomic(self.config_dir / "users.json", users_map)

        # Seed roster: one online bot, one offline bot
        now = time.time()
        (self.bus_dir / "roster.json").write_text(
            json.dumps({
                "version": 1,
                "bots": {
                    TEST_BOT_ONLINE: {
                        "handle": TEST_BOT_ONLINE,
                        "display_name": "Online Worker",
                        "role": "worker",
                        "pid": os.getpid(),
                        "last_seen": now,
                        "busy": False,
                        "active_model": "gemini-3.8-flash",
                        "default_project": "safe-proj",
                    },
                    TEST_BOT_OFFLINE: {
                        "handle": TEST_BOT_OFFLINE,
                        "display_name": "Offline Worker",
                        "role": "worker",
                        "pid": os.getpid(),
                        "last_seen": now - 3600,
                        "busy": False,
                    },
                },
            }),
            encoding="utf-8",
        )

        self.schedules_file.write_text(
            json.dumps({"version": 1, "tasks": {}}),
            encoding="utf-8",
        )

        self.auth = StudioAuthManager(
            config_dir=self.config_dir,
            bridge_dir=self.bridge_dir,
            auth_mode="password",
        )
        self.sources = StudioDataSources(
            bus_dir=self.bus_dir,
            schedules_file=self.schedules_file,
            projects_dir=self.projects_dir,
            cost_ledger_file=self.tmp / "cost_ledger.json",
            cost_config_file=self.tmp / "cost_config.json",
            quota_cache_file=self.tmp / "quota.json",
            brain_root=self.tmp / "brain",
            summaries_db=self.tmp / "summaries.db",
            meta_file=self.tmp / "meta.json",
        )
        self.app = create_app(
            auth_mgr=self.auth,
            data_sources=self.sources,
            revocation_check_interval=0.1,
            audit_log_path=self.audit_log,
            sse_keepalive_interval=5.0,
            event_hub_max_events=16,
            event_watcher_interval=0.0,
        )
        self.server = TestServer(self.app)
        self.client = TestClient(self.server, cookie_jar=aiohttp.DummyCookieJar())
        await self.client.start_server()
        self._ipc_servers: list[studio_ipc.StudioIPCServer] = []

    async def asyncTearDown(self) -> None:
        for srv in self._ipc_servers:
            srv.stop()
        await self.client.close()
        self._td.cleanup()

    def _origin(self) -> str:
        return f"http://{self.server.host}:{self.server.port}"

    async def _login(self, username: str, password: str) -> tuple[dict, str, str]:
        resp = await self.client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
            headers={"Origin": self._origin(), "Content-Type": "application/json"},
        )
        self.assertEqual(resp.status, 200, await resp.text())
        data = await resp.json()
        sid = resp.cookies[SESSION_COOKIE_NAME].value
        return data, sid, str(data["csrf_token"])

    def _write_headers(self, sid: str, csrf: str, *, origin: str | None = None, content_type: str = "application/json") -> dict[str, str]:
        hdrs = {
            "Cookie": f"{SESSION_COOKIE_NAME}={sid}",
            "X-Studio-CSRF": csrf,
            "Content-Type": content_type,
        }
        if origin is not None:
            hdrs["Origin"] = origin
        else:
            hdrs["Origin"] = self._origin()
        return hdrs

    def _read_audit_entries(self) -> list[dict]:
        if not self.audit_log.is_file():
            return []
        out: list[dict] = []
        for ln in self.audit_log.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                out.append(json.loads(ln))
        return out


class TestPAC1BridgeIPCControlPlane(_ControlPlaneBaseTest):
    """PA-C1: Bridge IPC `/ipc/job/cancel` & `/ipc/schedule/run` security & precision."""

    async def test_pa_c1_ipc_job_cancel_and_schedule_run_auth_and_rce_ban(self) -> None:
        canceled_jobs: list[tuple[str, int]] = []
        ran_schedules: list[tuple[str, int]] = []

        # Create isolated TaskManager & BusDir for direct Bridge function testing
        tm = scheduler.TaskManager(
            filepath=str(self.schedules_file),
            lockpath=str(self.tmp / "sched.lock"),
        )
        safe_task = tm.create_task(
            name="Safe Reminder",
            schedule_expr="0 9 * * *",
            task_type="reminder",
            payload={"prompt": "Check release notes"},
            custom_id="sched-safe-1",
        )
        script_task = tm.create_task(
            name="CLI Script",
            schedule_expr="0 9 * * *",
            task_type="script",
            payload={"script": "echo EXAMPLE_SECRET_SHELL_CMD"},
            custom_id="sched-script-1",
        )
        precheck_task = tm.create_task(
            name="CLI Precheck Agent",
            schedule_expr="0 9 * * *",
            task_type="agent",
            payload={"prompt": "Inspect status"},
            precheck_cmd="echo EXAMPLE_PRECHECK_CMD",
            custom_id="sched-precheck-1",
        )
        self.assertEqual(safe_task["id"], "sched-safe-1")
        self.assertEqual(script_task["id"], "sched-script-1")
        self.assertEqual(precheck_task["id"], "sched-precheck-1")

        # Seed a running job in bus_dir
        job_fp = self.bus_dir / "jobs" / "job-run-01.json"
        job_fp.write_text(
            json.dumps({
                "job_id": "job-run-01",
                "target_bot": TEST_BOT_ONLINE,
                "from_bot": "studio",
                "status": "running",
                "prompt": "Run diagnostics",
                "created_at": time.time(),
            }),
            encoding="utf-8",
        )

        fake_q = bridge_mod._JobQueue(use_global_queue_file=False)

        with (
            mock.patch.object(scheduler, "task_mgr", tm),
            mock.patch.object(bot_bus, "BUS_DIR", str(self.bus_dir)),
            mock.patch.object(bot_bus, "JOBS_DIR", str(self.bus_dir / "jobs")),
            mock.patch.object(bot_bus, "INBOX_DIR", str(self.bus_dir / "inbox")),
            mock.patch.object(bot_bus, "LOCK_FILE", str(self.bus_dir / "bus.lock")),
            mock.patch.object(bridge_mod, "job_q", fake_q),
            mock.patch.object(bridge_mod, "ALLOWED", {ADMIN_UID}),
            mock.patch.object(bridge_mod, "PRIMARY_CHAT_ID", ADMIN_UID),
            mock.patch.object(bridge_mod, "_current_bot_handle", return_value=TEST_BOT_ONLINE),
        ):
            def _cancel_cb(jid: str, uid: int) -> tuple[int, dict]:
                canceled_jobs.append((jid, uid))
                return bridge_mod._studio_ipc_cancel_job(jid, uid)

            def _run_cb(sid_arg: str, uid: int) -> tuple[int, dict]:
                ran_schedules.append((sid_arg, uid))
                return bridge_mod._studio_ipc_run_schedule(sid_arg, uid)

            srv = studio_ipc.StudioIPCServer(
                bus_dir=self.bus_dir,
                bot_handle=TEST_BOT_ONLINE,
                resolve_role_fn=lambda uid: "admin" if uid == ADMIN_UID else ("readonly" if uid == READONLY_UID else "denied"),
                get_meta_fn=lambda: {"handle": TEST_BOT_ONLINE},
                enqueue_turn_fn=lambda _r: (202, {"ok": True}),
                abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
                cancel_job_fn=_cancel_cb,
                run_schedule_fn=_run_cb,
            )
            srv.start()
            self._ipc_servers.append(srv)

            # 1. Proxy forwarding header rejected unconditionally -> 403
            sc, _, _ = _uds_http_request(
                srv.sock_path,
                "POST",
                "/ipc/job/cancel",
                headers={
                    "X-Bridge-IPC-Token": srv.token,
                    "X-Forwarded-For": "127.0.0.1",
                    "Content-Type": "application/json",
                },
                body=json.dumps({"job_id": "job-run-01", "user_id": ADMIN_UID}).encode("utf-8"),
            )
            self.assertEqual(sc, 403)

            # 2. Spoofed role="admin" for readonly UID rejected -> 403
            sc, _, _ = _uds_http_request(
                srv.sock_path,
                "POST",
                "/ipc/schedule/run",
                headers={"X-Bridge-IPC-Token": srv.token, "Content-Type": "application/json"},
                body=json.dumps({"schedule_id": "sched-safe-1", "user_id": READONLY_UID, "role": "admin"}).encode("utf-8"),
            )
            self.assertEqual(sc, 403)

            # 3. Path traversal IDs rejected -> 400
            sc, _, _ = _uds_http_request(
                srv.sock_path,
                "POST",
                "/ipc/job/cancel",
                headers={"X-Bridge-IPC-Token": srv.token, "Content-Type": "application/json"},
                body=json.dumps({"job_id": "../evil", "user_id": ADMIN_UID}).encode("utf-8"),
            )
            self.assertEqual(sc, 400)

            # 4. Bridge-side precision: when an unrelated Telegram turn is running,
            #    canceling `job-run-01` MUST NOT flip `cancel_requested` for the TG turn!
            with bridge_mod.session_lock:
                orig_tr = bridge_mod.turn_running
                orig_scope = bridge_mod.turn_running_scope
                orig_active = getattr(bridge_mod, "_active_bus_job_id", None)
                orig_cr = bridge_mod.cancel_requested
                bridge_mod.turn_running = True
                bridge_mod.turn_running_scope = "tg:111111111"
                bridge_mod._active_bus_job_id = None
                bridge_mod.cancel_requested = False
            try:
                sc, _, raw = _uds_http_request(
                    srv.sock_path,
                    "POST",
                    "/ipc/job/cancel",
                    headers={"X-Bridge-IPC-Token": srv.token, "Content-Type": "application/json"},
                    body=json.dumps({"job_id": "job-run-01", "user_id": ADMIN_UID}).encode("utf-8"),
                )
                self.assertEqual(sc, 200)
                self.assertFalse(bridge_mod.cancel_requested, "Must NEVER interrupt unrelated Telegram turn")

                # Now simulate `job-run-01` actually running on this worker -> MUST set cancel_requested
                with bridge_mod.session_lock:
                    bridge_mod.turn_running = True
                    bridge_mod.turn_running_scope = "bus:job-run-01"
                    bridge_mod._active_bus_job_id = "job-run-01"
                    bridge_mod.cancel_requested = False
                sc2, _, raw2 = _uds_http_request(
                    srv.sock_path,
                    "POST",
                    "/ipc/job/cancel",
                    headers={"X-Bridge-IPC-Token": srv.token, "Content-Type": "application/json"},
                    body=json.dumps({"job_id": "job-run-01", "user_id": ADMIN_UID}).encode("utf-8"),
                )
                self.assertEqual(sc2, 200)
                resp2 = json.loads(raw2.decode("utf-8"))
                self.assertTrue(resp2["was_running"])
                self.assertTrue(bridge_mod.cancel_requested)
            finally:
                with bridge_mod.session_lock:
                    bridge_mod.turn_running = orig_tr
                    bridge_mod.turn_running_scope = orig_scope
                    bridge_mod._active_bus_job_id = orig_active
                    bridge_mod.cancel_requested = orig_cr

            # 5. Bridge-side Defense-in-Depth RCE ban on `/ipc/schedule/run`:
            #    BOTH `script` AND `precheck_cmd` tasks MUST return 403 and enqueue 0 items!
            for bad_sid in ("sched-script-1", "sched-precheck-1"):
                sc_bad, _, raw_bad = _uds_http_request(
                    srv.sock_path,
                    "POST",
                    "/ipc/schedule/run",
                    headers={"X-Bridge-IPC-Token": srv.token, "Content-Type": "application/json"},
                    body=json.dumps({"schedule_id": bad_sid, "user_id": ADMIN_UID}).encode("utf-8"),
                )
                self.assertEqual(sc_bad, 403, f"Bridge IPC must block {bad_sid}: {raw_bad!r}")
            self.assertEqual(fake_q.qsize(), 0)

            # 6. Safe reminder schedule runs via IPC -> 202 and enqueues 1 item
            sc_ok, _, raw_ok = _uds_http_request(
                srv.sock_path,
                "POST",
                "/ipc/schedule/run",
                headers={"X-Bridge-IPC-Token": srv.token, "Content-Type": "application/json"},
                body=json.dumps({"schedule_id": "sched-safe-1", "user_id": ADMIN_UID}).encode("utf-8"),
            )
            self.assertEqual(sc_ok, 202, raw_ok)
            self.assertEqual(fake_q.qsize(), 1)


class TestPAC2WriteGateAndAudit(_ControlPlaneBaseTest):
    """PA-C2: Four-layer write gate, <=32 KiB fixed/chunked cap, non-dict 400, 0600 JSONL audit."""

    async def test_pa_c2_four_layer_write_gate_all_m2_endpoints(self) -> None:
        _, sid_admin, csrf_admin = await self._login("admin_user", TEST_PASS_ADMIN)
        _, sid_ro, csrf_ro = await self._login("ro_user", TEST_PASS_RO)
        _, sid_force, csrf_force = await self._login("force_user", TEST_PASS_FORCE)

        endpoints = [
            ("POST", "/api/jobs/dispatch", {"bot": TEST_BOT_ONLINE, "prompt": "hi"}),
            ("POST", "/api/jobs/job-missing/cancel", {}),
            ("POST", "/api/jobs/job-missing/retry", {}),
            ("POST", "/api/schedules", {"name": "n", "task_type": "reminder", "schedule_expr": "0 9 * * *", "prompt": "p"}),
            ("PATCH", "/api/schedules/sched-missing", {"enabled": False}),
            ("DELETE", "/api/schedules/sched-missing", {}),
            ("POST", "/api/schedules/sched-missing/run", {}),
        ]

        for method, path, payload in endpoints:
            body_bytes = json.dumps(payload).encode("utf-8")

            # Gate 1: Missing Origin -> 403
            r_no_orig = await self.client.request(
                method,
                path,
                data=body_bytes,
                headers={
                    "Cookie": f"{SESSION_COOKIE_NAME}={sid_admin}",
                    "X-Studio-CSRF": csrf_admin,
                    "Content-Type": "application/json",
                },
            )
            self.assertEqual(r_no_orig.status, 403, f"{method} {path} missing Origin")
            self.assertEqual(r_no_orig.headers.get("Content-Security-Policy"), CSP_HEADER_PASSWORD)
            self.assertEqual(r_no_orig.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertIn("no-store", r_no_orig.headers.get("Cache-Control", ""))

            # Gate 1b: Cross-Origin -> 403
            r_bad_orig = await self.client.request(
                method,
                path,
                data=body_bytes,
                headers=self._write_headers(sid_admin, csrf_admin, origin="https://evil.example.org"),
            )
            self.assertEqual(r_bad_orig.status, 403, f"{method} {path} cross Origin")

            # Gate 2: Simple request Content-Type: text/plain -> 415
            r_ct = await self.client.request(
                method,
                path,
                data=body_bytes,
                headers=self._write_headers(sid_admin, csrf_admin, content_type="text/plain"),
            )
            self.assertEqual(r_ct.status, 415, f"{method} {path} text/plain")

            # Gate 3a: No cookie -> 401
            r_nocookie = await self.client.request(
                method,
                path,
                data=body_bytes,
                headers={"Origin": self._origin(), "Content-Type": "application/json"},
            )
            self.assertEqual(r_nocookie.status, 401, f"{method} {path} no cookie")

            # Gate 3b: must_change_password=True -> 403
            r_mcp = await self.client.request(
                method,
                path,
                data=body_bytes,
                headers=self._write_headers(sid_force, csrf_force),
            )
            self.assertEqual(r_mcp.status, 403, f"{method} {path} must_change_password")

            # Gate 4a: Missing/wrong CSRF -> 403
            r_csrf = await self.client.request(
                method,
                path,
                data=body_bytes,
                headers=self._write_headers(sid_admin, "wrong-csrf-token"),
            )
            self.assertEqual(r_csrf.status, 403, f"{method} {path} bad CSRF")

            # Gate 4b: Readonly user -> 403
            r_ro = await self.client.request(
                method,
                path,
                data=body_bytes,
                headers=self._write_headers(sid_ro, csrf_ro),
            )
            self.assertEqual(r_ro.status, 403, f"{method} {path} readonly")

        # Audit file exists with 0600 permissions and logged every denial without leaking cookies/CSRF
        self.assertTrue(self.audit_log.is_file())
        mode = stat.S_IMODE(self.audit_log.stat().st_mode)
        self.assertEqual(mode, 0o600)
        raw_audit = self.audit_log.read_text(encoding="utf-8")
        self.assertNotIn(sid_admin, raw_audit)
        self.assertNotIn(csrf_admin, raw_audit)
        self.assertNotIn(TEST_PASS_ADMIN, raw_audit)
        entries = self._read_audit_entries()
        self.assertGreaterEqual(len(entries), len(endpoints) * 7)

    async def test_pa_c2_bounded_body_32kib_fixed_and_chunked_and_non_dict(self) -> None:
        _, sid, csrf = await self._login("admin_user", TEST_PASS_ADMIN)
        hdrs = self._write_headers(sid, csrf)

        # Fixed-length > 32 KiB -> 413
        oversized = json.dumps({"bot": TEST_BOT_ONLINE, "prompt": "A" * (34 * 1024)}).encode("utf-8")
        r_fix = await self.client.post("/api/jobs/dispatch", data=oversized, headers=hdrs)
        self.assertEqual(r_fix.status, 413)

        r_fix_sched = await self.client.post("/api/schedules", data=oversized, headers=hdrs)
        self.assertEqual(r_fix_sched.status, 413)

        # Chunked transfer encoding > 32 KiB (no Content-Length) -> 413
        async def _chunk_gen():
            yield b'{"bot":"' + TEST_BOT_ONLINE.encode("ascii") + b'","prompt":"'
            for _ in range(10):
                yield b"B" * 4096
            yield b'"}'

        r_chunked = await self.client.post(
            "/api/jobs/dispatch",
            data=_chunk_gen(),
            headers=hdrs,
            chunked=True,
        )
        self.assertEqual(r_chunked.status, 413)

        # Non-dict JSON (`[]`, `"hello"`) & invalid JSON -> 400
        for bad_raw in (b"[]", b'"hello"', b"123", b"{not-json"):
            r_bad = await self.client.post("/api/jobs/dispatch", data=bad_raw, headers=hdrs)
            self.assertEqual(r_bad.status, 400)
            r_bad_s = await self.client.post("/api/schedules", data=bad_raw, headers=hdrs)
            self.assertEqual(r_bad_s.status, 400)

        outcomes = {e["outcome"] for e in self._read_audit_entries()}
        self.assertIn("denied_payload_too_large", outcomes)
        self.assertIn("denied_invalid_json", outcomes)


class TestPAC3RedactionAndBounds(_ControlPlaneBaseTest):
    """PA-C3: Job detail redaction/32 KiB cap, CLI script hiding, SSE payload redaction/16 KiB cap."""

    async def test_pa_c3_job_detail_redaction_truncation_and_path_traversal(self) -> None:
        _, sid_ro, _ = await self._login("ro_user", TEST_PASS_RO)
        cookie_hdr = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_ro}"}

        # Path traversal & invalid IDs -> 400
        for bad_id in ("..%2F..%2Fetc%2Fpasswd", "job..evil", "bad$id", "a"):
            r = await self.client.get(f"/api/jobs/{bad_id}", headers=cookie_hdr)
            self.assertEqual(r.status, 400, f"bad_id={bad_id}")

        # Missing valid job -> 404
        r_404 = await self.client.get("/api/jobs/job-does-not-exist", headers=cookie_hdr)
        self.assertEqual(r_404.status, 404)

        # Seed job with synthetic secrets, host path, ipc_sock, and >32 KiB fields
        syn_ghp = "ghp_" + "ExampleSecret0123456789ABCDEF"
        syn_pem = ("-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5 + "\n"
                   + "MIIE_EXAMPLE_KEY_BODY\n"
                   + "-" * 5 + "END RSA PRIVATE KEY" + "-" * 5)
        syn_home = "/" + "home" + "/alice-dev/secret-repo/file.py"
        syn_sock = "/" + "tmp" + "/bot_bus/ipc/worker.sock"
        huge_body = ("Hello " + syn_ghp + " " + syn_home + " " + syn_sock + "\n") + ("X" * (40 * 1024))

        (self.bus_dir / "jobs" / "job-detail-1.json").write_text(
            json.dumps({
                "job_id": "job-detail-1",
                "group_id": "batch-1",
                "label": f"Inspect {syn_ghp}",
                "from_bot": "studio",
                "target_bot": TEST_BOT_ONLINE,
                "status": "done",
                "workdir": syn_home,
                "ipc_sock": syn_sock,
                "origin_chat_id": -1001234567890,
                "prompt": huge_body,
                "result_text": f"Result {syn_pem}\n" + ("Y" * (38 * 1024)),
                "error": f"Failed at {syn_home} token={syn_ghp}",
                "created_at": time.time() - 10,
                "started_at": time.time() - 8,
                "finished_at": time.time() - 1,
            }),
            encoding="utf-8",
        )

        r_ok = await self.client.get("/api/jobs/job-detail-1", headers=cookie_hdr)
        self.assertEqual(r_ok.status, 200)
        body = await r_ok.json()
        job = body["job"]

        # Forbidden host fields absent
        for forbidden_k in ("workdir", "ipc_sock", "origin_chat_id", "worker_pid"):
            self.assertNotIn(forbidden_k, job)

        raw_txt = json.dumps(body)
        for leak in (syn_ghp, "MIIE_EXAMPLE_KEY_BODY", syn_home, syn_sock):
            self.assertNotIn(leak, raw_txt)

        # Single-field <= 32 KiB cap enforced + truncated marker
        self.assertLessEqual(len(job["prompt"].encode("utf-8")), MAX_MESSAGE_BYTES)
        self.assertLessEqual(len(job["result"].encode("utf-8")), MAX_MESSAGE_BYTES)
        self.assertLessEqual(len(job["error"].encode("utf-8")), MAX_MESSAGE_BYTES)
        self.assertTrue(job["truncated"])
        self.assertIn("prompt", job["truncated_fields"])
        self.assertIn("result", job["truncated_fields"])

    async def test_pa_c3_schedules_hide_cli_script_and_events_redaction_16kib(self) -> None:
        tm = scheduler.TaskManager(
            filepath=str(self.schedules_file),
            lockpath=str(self.tmp / "sched.lock"),
        )
        tm.create_task(
            name="Nightly Backup",
            schedule_expr="0 3 * * *",
            task_type="script",
            payload={"script": "python3 /opt/secret/backup.py --secret SUPER_HIDDEN_SCRIPT_CMD"},
            custom_id="sched-cli-script",
        )
        tm.create_task(
            name="Precheck Watcher",
            schedule_expr="*/10 * * * *",
            task_type="agent",
            payload={"prompt": "Check diff"},
            precheck_cmd="curl -s https://example.com/probe # SUPER_HIDDEN_PRECHECK_CMD",
            custom_id="sched-cli-precheck",
        )

        _, sid_ro, _ = await self._login("ro_user", TEST_PASS_RO)
        r = await self.client.get("/api/schedules", headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_ro}"})
        self.assertEqual(r.status, 200)
        raw_txt = await r.text()
        self.assertNotIn("SUPER_HIDDEN_SCRIPT_CMD", raw_txt)
        self.assertNotIn("SUPER_HIDDEN_PRECHECK_CMD", raw_txt)
        data = json.loads(raw_txt)
        by_id = {s["id"]: s for s in data["schedules"]}
        self.assertTrue(by_id["sched-cli-script"]["read_only_cli"])
        self.assertTrue(by_id["sched-cli-precheck"]["read_only_cli"])
        self.assertEqual(by_id["sched-cli-script"]["prompt"], "")
        self.assertEqual(by_id["sched-cli-precheck"]["prompt"], "")

        # EventHub redaction + forbidden key stripping + 16 KiB frame cap
        hub = self.app[EVENT_HUB_KEY]
        syn_sk = "sk-" + "ExampleKey0123456789ABCDEFGH"
        seq = hub.publish(
            "job_updated",
            {
                "action": "test",
                "ipc_sock": "/tmp/hidden.sock",
                "script": "rm -rf /tmp/x",
                "precheck_cmd": "whoami",
                "message": f"leak {syn_sk} " + ("Z" * (24 * 1024)),
            },
        )
        ev_item = [e for e in hub._events if e[0] == seq][0]
        self.assertNotIn("ipc_sock", ev_item[2])
        self.assertNotIn("script", ev_item[2])
        self.assertNotIn("precheck_cmd", ev_item[2])
        self.assertNotIn(syn_sk, json.dumps(ev_item[2]))
        frame = hub._format_sse_frame(ev_item[1], ev_item[2], seq=ev_item[0])
        self.assertLessEqual(len(frame), MAX_SSE_EVENT_BYTES)
        self.assertIn(b'"truncated":true', frame)


class TestPAC4GlobalSSEEvents(_ControlPlaneBaseTest):
    """PA-C4: `/api/events` zero-TOCTOU concurrency, <=0.8s revocation 0-leak, replay & resync."""

    async def test_pa_c4_events_concurrent_8_requests_zero_toctou_and_cleanup(self) -> None:
        _, sid_admin, _ = await self._login("admin_user", TEST_PASS_ADMIN)
        _, sid_ro, _ = await self._login("ro_user", TEST_PASS_RO)
        _, sid_force, _ = await self._login("force_user", TEST_PASS_FORCE)

        # must_change_password=True -> 403
        r_mcp = await self.client.get(
            "/api/events", headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_force}"}
        )
        self.assertEqual(r_mcp.status, 403)

        # Readonly user CAN subscribe -> 200 SSE
        r_ro = await self.client.get(
            "/api/events", headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_ro}"}
        )
        self.assertEqual(r_ro.status, 200)
        self.assertIn("text/event-stream", r_ro.headers.get("Content-Type", ""))
        self.assertEqual(r_ro.headers.get("Content-Security-Policy"), CSP_HEADER_PASSWORD)
        self.assertEqual(r_ro.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("no-store", r_ro.headers.get("Cache-Control", ""))
        r_ro.close()
        await asyncio.sleep(0.05)

        # 8 concurrent connections from same session -> strictly 4x200 + 4x429
        cookie_hdr = {"Cookie": f"{SESSION_COOKIE_NAME}={sid_admin}"}
        resps = await asyncio.gather(
            *(self.client.get("/api/events", headers=cookie_hdr) for _ in range(8))
        )
        statuses = sorted(r.status for r in resps)
        self.assertEqual(statuses, [200, 200, 200, 200, 429, 429, 429, 429])

        # Verify connected event on the 4 open streams, then close them all cleanly
        open_resps = [r for r in resps if r.status == 200]
        for r in open_resps:
            evs = await _read_sse_events(r, max_events=1, timeout=1.0)
            self.assertEqual(len(evs), 1)
            self.assertEqual(evs[0]["event"], "connected")
            r.close()
        for r in resps:
            r.release()

        # Wait briefly for server-side handlers to observe disconnect / wake & clean up
        hub = self.app[EVENT_HUB_KEY]
        hub.publish("job_updated", {"action": "cleanup_probe"})
        deadline = time.monotonic() + 1.5
        while hub._active_streams and time.monotonic() < deadline:
            hub.publish("job_updated", {"action": "cleanup_probe"})
            await asyncio.sleep(0.05)
        self.assertEqual(len(hub._active_streams), 0, "Zero leaked SSE slots after disconnect")

    async def test_pa_c4_events_revocation_logout_downgrade_and_handshake_zero_leak(self) -> None:
        hub = self.app[EVENT_HUB_KEY]

        # 1. Mid-stream logout -> auth_error + EOF within <= 0.8s, 0 frames leaked after logout
        _, sid1, csrf1 = await self._login("admin_user", TEST_PASS_ADMIN)
        resp1 = await self.client.get(
            "/api/events", headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid1}"}
        )
        self.assertEqual(resp1.status, 200)
        init_evs = await _read_sse_events(resp1, max_events=1, timeout=1.0)
        self.assertEqual(init_evs[0]["event"], "connected")

        t0 = time.monotonic()
        r_out = await self.client.post(
            "/api/auth/logout",
            headers=self._write_headers(sid1, csrf1),
            data="{}",
        )
        self.assertEqual(r_out.status, 200)
        # Immediately publish a sensitive-marker event AFTER logout -> MUST NOT reach revoked client
        hub.publish("job_updated", {"action": "POST_LOGOUT_MUST_NOT_LEAK"})
        tail_evs = await _read_sse_events(resp1, max_events=10, timeout=1.2)
        elapsed = time.monotonic() - t0
        self.assertLessEqual(elapsed, 0.85, f"Logout teardown took {elapsed:.3f}s (>0.8s)")
        self.assertTrue(any(e["event"] == "auth_error" for e in tail_evs), tail_evs)
        self.assertNotIn("POST_LOGOUT_MUST_NOT_LEAK", json.dumps(tail_evs))
        resp1.close()

        # 2. Mid-stream live RBAC downgrade (`admin` -> `readonly`) -> auth_error + EOF <= 0.8s, 0 post-downgrade frames
        _, sid2, _ = await self._login("admin_user", TEST_PASS_ADMIN)
        resp2 = await self.client.get(
            "/api/events", headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid2}"}
        )
        self.assertEqual(resp2.status, 200)
        init_evs2 = await _read_sse_events(resp2, max_events=1, timeout=1.0)
        self.assertEqual(init_evs2[0]["event"], "connected")

        t_dg = time.monotonic()
        _write_env(
            self.env_file,
            [
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_TEST}",
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                f"AGY_TG_ADMIN_USERS={DENIED_UID}",
                f"AGY_TG_READONLY_USERS={ADMIN_UID},{READONLY_UID}",
            ],
        )
        hub.publish("job_updated", {"action": "POST_DOWNGRADE_MUST_NOT_LEAK"})
        tail_evs2 = await _read_sse_events(resp2, max_events=10, timeout=1.2)
        elapsed_dg = time.monotonic() - t_dg
        self.assertLessEqual(elapsed_dg, 0.85, f"Downgrade teardown took {elapsed_dg:.3f}s")
        self.assertTrue(any(e["event"] == "auth_error" for e in tail_evs2), tail_evs2)
        self.assertNotIn("POST_DOWNGRADE_MUST_NOT_LEAK", json.dumps(tail_evs2))
        resp2.close()

        # Restore admin env
        _write_env(
            self.env_file,
            [
                f"AGY_TG_BOT_TOKEN={BOT_TOKEN_TEST}",
                f"AGY_TG_ALLOWED_CHATS={ADMIN_UID},{READONLY_UID}",
                f"AGY_TG_ADMIN_USERS={ADMIN_UID}",
                f"AGY_TG_READONLY_USERS={READONLY_UID}",
            ],
        )

        # 3. Handshake-phase revocation (revoked BEFORE prepare) -> 403, 0 frames, 0 leaked slots
        _, sid3, _ = await self._login("admin_user", TEST_PASS_ADMIN)
        orig_auth_sh = self.auth.authenticate_session_hash
        call_count = 0

        async def _revoke_mid_handshake(sh: str, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                # Simulate revocation right between initial auth & pre-prepare check
                await self.auth.destroy_session(sh)
            return await orig_auth_sh(sh, **kwargs)

        with mock.patch.object(self.auth, "authenticate_session_hash", side_effect=_revoke_mid_handshake):
            r_hs = await self.client.get(
                "/api/events", headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid3}"}
            )
            self.assertEqual(r_hs.status, 403)
            self.assertIn("application/json", r_hs.headers.get("Content-Type", ""))
        self.assertEqual(len(hub._active_streams), 0)

    async def test_pa_c4_events_last_event_id_replay_and_resync_required(self) -> None:
        hub = self.app[EVENT_HUB_KEY]
        _, sid, _ = await self._login("admin_user", TEST_PASS_ADMIN)

        s1 = hub.publish("job_updated", {"action": "ev1"})
        s2 = hub.publish("schedule_updated", {"action": "ev2"})
        s3 = hub.publish("bots_updated", {"action": "ev3"})

        # Reconnect with Last-Event-ID=s1 -> replays s2 and s3 strictly in order
        r_rep = await self.client.get(
            "/api/events",
            headers={
                "Cookie": f"{SESSION_COOKIE_NAME}={sid}",
                "Last-Event-ID": str(s1),
            },
        )
        self.assertEqual(r_rep.status, 200)
        replayed = await _read_sse_events(r_rep, max_events=2, timeout=1.0)
        self.assertEqual(len(replayed), 2)
        self.assertEqual(replayed[0]["event"], "schedule_updated")
        self.assertEqual(replayed[0]["id"], str(s2))
        self.assertEqual(replayed[1]["event"], "bots_updated")
        self.assertEqual(replayed[1]["id"], str(s3))
        r_rep.close()

        # Overflow ring buffer (max_events=16) by publishing 25 more events
        for i in range(25):
            hub.publish("job_updated", {"action": f"bulk_{i}"})

        # Reconnect with stale Last-Event-ID=s1 -> MUST receive `resync_required`
        r_ovf = await self.client.get(
            "/api/events",
            headers={
                "Cookie": f"{SESSION_COOKIE_NAME}={sid}",
                "Last-Event-ID": str(s1),
            },
        )
        self.assertEqual(r_ovf.status, 200)
        ovf_evs = await _read_sse_events(r_ovf, max_events=1, timeout=1.0)
        self.assertEqual(len(ovf_evs), 1)
        self.assertEqual(ovf_evs[0]["event"], "resync_required")
        self.assertEqual(ovf_evs[0]["data"]["reason"], "buffer_overflow")  # type: ignore[index]
        r_ovf.close()


class TestPAC6JobsAndSchedulesControlPlane(_ControlPlaneBaseTest):
    """PA-C6: Jobs roster/fanout/cancel/retry & Schedules RCE ban/min-interval/CLI readonly."""

    async def test_pa_c6_jobs_dispatch_cancel_idempotency_and_retry(self) -> None:
        _, sid, csrf = await self._login("admin_user", TEST_PASS_ADMIN)
        hdrs = self._write_headers(sid, csrf)

        # 1. Unknown bot -> 400; offline bot -> 409
        r_unk = await self.client.post(
            "/api/jobs/dispatch",
            json={"bot": "nonexistent_bot", "prompt": "do work"},
            headers=hdrs,
        )
        self.assertEqual(r_unk.status, 400)

        r_off = await self.client.post(
            "/api/jobs/dispatch",
            json={"bot": TEST_BOT_OFFLINE, "prompt": "do work"},
            headers=hdrs,
        )
        self.assertEqual(r_off.status, 409)

        # 2. Fan-out > 6 -> 400; fan-out == 0 -> 400
        r_empty = await self.client.post(
            "/api/jobs/dispatch", json={"assignments": []}, headers=hdrs
        )
        self.assertEqual(r_empty.status, 400)

        r_too_many = await self.client.post(
            "/api/jobs/dispatch",
            json={
                "assignments": [
                    {"bot": TEST_BOT_ONLINE, "prompt": f"task {i}"} for i in range(7)
                ]
            },
            headers=hdrs,
        )
        self.assertEqual(r_too_many.status, 400)

        # 3. Single prompt > 16 KiB -> 400
        r_big_prompt = await self.client.post(
            "/api/jobs/dispatch",
            json={"bot": TEST_BOT_ONLINE, "prompt": "P" * (17 * 1024)},
            headers=hdrs,
        )
        self.assertEqual(r_big_prompt.status, 400)

        # 4. Forbidden fields (`workdir`, `target_chat_id`, `chat_id`, `thread_id`, `role`, `reply_to`) -> 400
        for bad_field in ("workdir", "target_chat_id", "chat_id", "thread_id", "role", "reply_to"):
            r_forb = await self.client.post(
                "/api/jobs/dispatch",
                json={"bot": TEST_BOT_ONLINE, "prompt": "hi", bad_field: "evil"},
                headers=hdrs,
            )
            self.assertEqual(r_forb.status, 400, f"Must reject {bad_field}")

        # 5. Unknown project -> 400; whitelisted project -> 202 (server maps workdir)
        r_bad_proj = await self.client.post(
            "/api/jobs/dispatch",
            json={"bot": TEST_BOT_ONLINE, "prompt": "hi", "project": "unlisted-project"},
            headers=hdrs,
        )
        self.assertEqual(r_bad_proj.status, 400)

        # Subscribe to SSE to verify `job_updated` event is emitted
        sse_r = await self.client.get(
            "/api/events", headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid}"}
        )
        await _read_sse_events(sse_r, max_events=1, timeout=1.0)

        r_ok = await self.client.post(
            "/api/jobs/dispatch",
            json={
                "bot": TEST_BOT_ONLINE,
                "prompt": "Verify unit tests",
                "label": "CI Check",
                "project": "safe-proj",
            },
            headers=hdrs,
        )
        self.assertEqual(r_ok.status, 202, await r_ok.text())
        disp = await r_ok.json()
        self.assertEqual(len(disp["jobs"]), 1)
        jid1 = disp["jobs"][0]["job_id"]

        # Verify on-disk job has server-mapped workdir and inbox packet exists
        disk_job = json.loads((self.bus_dir / "jobs" / f"{jid1}.json").read_text(encoding="utf-8"))
        self.assertEqual(disk_job["workdir"], str(self.allowed_proj_dir.resolve()))
        inbox_files = list((self.bus_dir / "inbox" / TEST_BOT_ONLINE).glob("*.json"))
        self.assertEqual(len(inbox_files), 1)

        evs = await _read_sse_events(sse_r, max_events=1, timeout=1.0)
        self.assertEqual(evs[0]["event"], "job_updated")
        sse_r.close()

        # 6. Retry queued job -> strictly 409 Conflict
        r_retry_q = await self.client.post(f"/api/jobs/{jid1}/retry", data="{}", headers=hdrs)
        self.assertEqual(r_retry_q.status, 409)

        # 7. Cancel queued job -> 200 cancelled; second cancel -> idempotent 200 already_terminal
        r_can1 = await self.client.post(f"/api/jobs/{jid1}/cancel", data="{}", headers=hdrs)
        self.assertEqual(r_can1.status, 200)
        d_can1 = await r_can1.json()
        self.assertEqual(d_can1["status"], "cancelled")
        self.assertFalse(d_can1["already_terminal"])

        r_can2 = await self.client.post(f"/api/jobs/{jid1}/cancel", data="{}", headers=hdrs)
        self.assertEqual(r_can2.status, 200)
        d_can2 = await r_can2.json()
        self.assertTrue(d_can2["already_terminal"])
        self.assertEqual(d_can2["status"], "cancelled")

        # 8. Retry terminal job -> 202 with brand-new job_id
        r_retry_ok = await self.client.post(f"/api/jobs/{jid1}/retry", data="{}", headers=hdrs)
        self.assertEqual(r_retry_ok.status, 202, await r_retry_ok.text())
        d_retry = await r_retry_ok.json()
        self.assertEqual(d_retry["retried_from"], jid1)
        self.assertNotEqual(d_retry["job_id"], jid1)

        # 9. Running job: retry -> 409; cancel -> calls target bot UDS `/ipc/job/cancel`
        ipc_cancel_hits: list[str] = []
        srv = studio_ipc.StudioIPCServer(
            bus_dir=self.bus_dir,
            bot_handle=TEST_BOT_ONLINE,
            resolve_role_fn=lambda uid: "admin" if uid == ADMIN_UID else "readonly",
            get_meta_fn=lambda: {"handle": TEST_BOT_ONLINE},
            enqueue_turn_fn=lambda _r: (202, {"ok": True}),
            abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
            cancel_job_fn=lambda jid, _uid: (
                ipc_cancel_hits.append(jid) or (200, {"ok": True, "cancelled": True, "was_running": True, "status": "cancelling"})
            ),
        )
        srv.start()
        self._ipc_servers.append(srv)

        (self.bus_dir / "jobs" / "job-running-99.json").write_text(
            json.dumps({
                "job_id": "job-running-99",
                "target_bot": TEST_BOT_ONLINE,
                "from_bot": "studio",
                "status": "running",
                "prompt": "Long running task",
                "created_at": time.time(),
            }),
            encoding="utf-8",
        )
        r_retry_run = await self.client.post("/api/jobs/job-running-99/retry", data="{}", headers=hdrs)
        self.assertEqual(r_retry_run.status, 409)

        r_can_run = await self.client.post("/api/jobs/job-running-99/cancel", data="{}", headers=hdrs)
        self.assertEqual(r_can_run.status, 200, await r_can_run.text())
        d_can_run = await r_can_run.json()
        self.assertTrue(d_can_run["via_ipc"])
        self.assertEqual(ipc_cancel_hits, ["job-running-99"])

    async def test_pa_c6_schedules_rce_ban_min_interval_and_cli_readonly(self) -> None:
        _, sid, csrf = await self._login("admin_user", TEST_PASS_ADMIN)
        hdrs = self._write_headers(sid, csrf)

        # 1. RCE Absolute Ban on POST /api/schedules -> 403
        for rce_payload in (
            {"name": "bad1", "task_type": "script", "schedule_expr": "0 9 * * *", "prompt": "echo 1"},
            {"name": "bad2", "task_type": "prompt", "schedule_expr": "0 9 * * *", "prompt": "hi", "precheck_cmd": "id"},
            {"name": "bad3", "task_type": "prompt", "schedule_expr": "0 9 * * *", "prompt": "hi", "command": "ls"},
            {"name": "bad4", "task_type": "prompt", "schedule_expr": "0 9 * * *", "prompt": "hi", "script": "uname"},
        ):
            r = await self.client.post("/api/schedules", json=rce_payload, headers=hdrs)
            self.assertEqual(r.status, 403, f"Must 403 on {rce_payload}")

        # 2. Forbidden route/host fields -> 400
        for bad_f in ("workdir", "target_chat_id", "chat_id", "thread_id"):
            r = await self.client.post(
                "/api/schedules",
                json={
                    "name": "bad-field",
                    "task_type": "prompt",
                    "schedule_expr": "0 9 * * *",
                    "prompt": "hi",
                    bad_f: "evil",
                },
                headers=hdrs,
            )
            self.assertEqual(r.status, 400, f"Must 400 on {bad_f}")

        # 3. <300s cron or invalid cron -> 400
        for bad_cron in (
            "* * * * *",
            "*/1 * * * *",
            "*/2 * * * *",
            "*/4 * * * *",
            "0,10,20,30,40,45,46 * * * *",
            "in 2m",
            "not-a-cron",
        ):
            r = await self.client.post(
                "/api/schedules",
                json={
                    "name": "fast",
                    "task_type": "reminder",
                    "schedule_expr": bad_cron,
                    "prompt": "ping",
                },
                headers=hdrs,
            )
            self.assertEqual(r.status, 400, f"Must reject {bad_cron!r}")

        # 4. Unknown project -> 400
        r_bad_p = await self.client.post(
            "/api/schedules",
            json={
                "name": "bad-proj",
                "task_type": "prompt",
                "schedule_expr": "*/5 * * * *",
                "prompt": "check",
                "project": "no-such-proj",
            },
            headers=hdrs,
        )
        self.assertEqual(r_bad_p.status, 400)

        # 5. Valid create (`prompt` & `reminder`) -> 201, file mode 0600, SSE emitted
        r_create = await self.client.post(
            "/api/schedules",
            json={
                "name": "Safe 5min Check",
                "task_type": "prompt",
                "schedule_expr": "*/5 * * * *",
                "prompt": "Summarize workspace status",
                "project": "safe-proj",
            },
            headers=hdrs,
        )
        self.assertEqual(r_create.status, 201, await r_create.text())
        created = (await r_create.json())["schedule"]
        safe_id = created["id"]
        self.assertFalse(created["read_only_cli"])
        self.assertEqual(stat.S_IMODE(self.schedules_file.stat().st_mode), 0o600)

        # Patch safe schedule -> 200; attempt injecting script/precheck_cmd via PATCH -> 403
        r_patch_ok = await self.client.patch(
            f"/api/schedules/{safe_id}",
            json={"name": "Safe 10min Check", "schedule_expr": "*/10 * * * *", "enabled": False},
            headers=hdrs,
        )
        self.assertEqual(r_patch_ok.status, 200)
        self.assertFalse((await r_patch_ok.json())["schedule"]["enabled"])

        r_patch_rce = await self.client.patch(
            f"/api/schedules/{safe_id}",
            json={"task_type": "script"},
            headers=hdrs,
        )
        self.assertEqual(r_patch_rce.status, 403)

        r_patch_pre = await self.client.patch(
            f"/api/schedules/{safe_id}",
            json={"precheck_cmd": "whoami"},
            headers=hdrs,
        )
        self.assertEqual(r_patch_pre.status, 403)

        # Run safe schedule via UDS IPC -> 202
        ipc_run_hits: list[str] = []
        srv = studio_ipc.StudioIPCServer(
            bus_dir=self.bus_dir,
            bot_handle=TEST_BOT_ONLINE,
            resolve_role_fn=lambda uid: "admin" if uid == ADMIN_UID else "readonly",
            get_meta_fn=lambda: {"handle": TEST_BOT_ONLINE},
            enqueue_turn_fn=lambda _r: (202, {"ok": True}),
            abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
            run_schedule_fn=lambda sid_arg, _uid: (
                ipc_run_hits.append(sid_arg) or (202, {"ok": True, "queued": True, "schedule_id": sid_arg})
            ),
        )
        srv.start()
        self._ipc_servers.append(srv)

        r_run_ok = await self.client.post(f"/api/schedules/{safe_id}/run", data="{}", headers=hdrs)
        self.assertEqual(r_run_ok.status, 202, await r_run_ok.text())
        self.assertEqual(ipc_run_hits, [safe_id])

        # Delete safe schedule -> 200
        r_del_ok = await self.client.delete(f"/api/schedules/{safe_id}", data="{}", headers=hdrs)
        self.assertEqual(r_del_ok.status, 200)

        # 6. Existing CLI `script` & `precheck_cmd` tasks:
        #    ONLY `PATCH {"enabled": false}` allowed (200); re-enable/edit/delete/run ALL -> 403!
        tm = scheduler.TaskManager(
            filepath=str(self.schedules_file),
            lockpath=str(self.schedules_file.parent / f".{self.schedules_file.name}.lock"),
        )
        tm.create_task(
            name="Legacy Script",
            schedule_expr="0 4 * * *",
            task_type="script",
            payload={"script": "echo cli_only_cmd"},
            custom_id="cli-script-1",
        )
        tm.create_task(
            name="Legacy Precheck",
            schedule_expr="0 5 * * *",
            task_type="agent",
            payload={"prompt": "Check"},
            precheck_cmd="echo precheck_only_cmd",
            custom_id="cli-precheck-1",
        )

        for cli_id in ("cli-script-1", "cli-precheck-1"):
            # Edit name -> 403
            r_ed = await self.client.patch(
                f"/api/schedules/{cli_id}", json={"name": "tampered"}, headers=hdrs
            )
            self.assertEqual(r_ed.status, 403, f"edit {cli_id}")

            # Disable + extra field -> 403
            r_mix = await self.client.patch(
                f"/api/schedules/{cli_id}",
                json={"enabled": False, "name": "tampered"},
                headers=hdrs,
            )
            self.assertEqual(r_mix.status, 403, f"mixed disable {cli_id}")

            # Emergency disable ONLY `{"enabled": false}` -> 200
            r_dis = await self.client.patch(
                f"/api/schedules/{cli_id}", json={"enabled": False}, headers=hdrs
            )
            self.assertEqual(r_dis.status, 200, f"emergency disable {cli_id}")
            self.assertFalse((await r_dis.json())["schedule"]["enabled"])

            # Re-enable `{"enabled": true}` -> 403
            r_en = await self.client.patch(
                f"/api/schedules/{cli_id}", json={"enabled": True}, headers=hdrs
            )
            self.assertEqual(r_en.status, 403, f"re-enable {cli_id}")

            # Delete -> 403
            r_dl = await self.client.delete(
                f"/api/schedules/{cli_id}", data="{}", headers=hdrs
            )
            self.assertEqual(r_dl.status, 403, f"delete {cli_id}")

            # Run -> 403 (blocked at Studio layer before IPC!)
            r_rn = await self.client.post(
                f"/api/schedules/{cli_id}/run", data="{}", headers=hdrs
            )
            self.assertEqual(r_rn.status, 403, f"run {cli_id}")

        self.assertEqual(ipc_run_hits, [safe_id], "IPC run_schedule must NEVER be called for CLI script/precheck tasks")


class TestM2Round2BlockersAndHardenings(_ControlPlaneBaseTest):
    """M2 Round 2 regression tests for BLOCK-1..BLOCK-4 + P2 flock delete guard & close_task drain."""

    def _read_audit_entries(self) -> list[dict[str, object]]:
        if not self.audit_log.is_file():
            return []
        entries: list[dict[str, object]] = []
        for line in self.audit_log.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
        return entries

    async def test_block1_validate_cron_min_interval_deterministic_structural_checks(self) -> None:
        tz, _ = scheduler.get_scheduler_tz("Asia/Shanghai")
        bypass_exprs = [
            "0,59 0,23 1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31 * *",
            "0,5,10,15,20,25,30,35,40,45,50,59 0,2,4,6,8,10,11 * * *",
            "0,5,10,15,20,25,30,35,40,45,50,59 0,2,4,6,8,10,12,14,16,18,20,23 * * *",
        ]
        for expr in bypass_exprs:
            with self.assertRaises(ValueError, msg=f"Must reject 60s bypass cron: {expr}"):
                scheduler.validate_cron_min_interval(expr, tz)

        # Multi-hour min_secs > 3600 checks (same-day adjacent hours & cross-midnight)
        with self.assertRaises(ValueError):
            scheduler.validate_cron_min_interval("0,50 10,12 * * *", tz, min_secs=7200)
        with self.assertRaises(ValueError):
            scheduler.validate_cron_min_interval("0,50 1,23 * * *", tz, min_secs=7200)

        # Valid expressions must still pass
        for valid_expr in (
            "*/5 * * * *",
            "0 9 * * *",
            "0,59 0,23 2,4,6,8,10,12,14,16,18,20,22,24,26,28,30 * *",
        ):
            first_dt = scheduler.validate_cron_min_interval(valid_expr, tz)
            self.assertIsNotNone(first_dt, valid_expr)

        # HTTP API verification: all 3 bypass crons -> 400; valid crons -> 201
        _, sid, csrf = await self._login("admin_user", TEST_PASS_ADMIN)
        hdrs = self._write_headers(sid, csrf)
        for idx, expr in enumerate(bypass_exprs):
            r_bad = await self.client.post(
                "/api/schedules",
                json={
                    "name": f"Bypass Cron {idx}",
                    "task_type": "prompt",
                    "schedule_expr": expr,
                    "prompt": "Check",
                },
                headers=hdrs,
            )
            self.assertEqual(r_bad.status, 400, f"API must return 400 for {expr}: {await r_bad.text()}")

        for idx, ok_expr in enumerate(("*/5 * * * *", "0 9 * * *")):
            r_ok = await self.client.post(
                "/api/schedules",
                json={
                    "name": f"Valid Cron {idx}",
                    "task_type": "prompt",
                    "schedule_expr": ok_expr,
                    "prompt": "Check",
                },
                headers=hdrs,
            )
            self.assertEqual(r_ok.status, 201, f"API must return 201 for {ok_expr}: {await r_ok.text()}")

    async def test_block2_recursive_fail_closed_and_strict_string_types(self) -> None:
        _, sid, csrf = await self._login("admin_user", TEST_PASS_ADMIN)
        hdrs = self._write_headers(sid, csrf)

        def _nest(depth: int, leaf: dict[str, object]) -> dict[str, object]:
            cur: dict[str, object] = dict(leaf)
            for i in range(depth):
                cur = {f"lv{i}": cur}
            return cur

        # 1. 8-layer & 40-layer nested `model` smuggling `precheck_cmd` to POST /api/schedules -> 403 + audit
        for depth in (8, 40):
            r_sched = await self.client.post(
                "/api/schedules",
                json={
                    "name": f"Nested RCE {depth}",
                    "task_type": "prompt",
                    "schedule_expr": "*/5 * * * *",
                    "prompt": "Check",
                    "model": _nest(depth, {"precheck_cmd": "id"}),
                },
                headers=hdrs,
            )
            self.assertEqual(r_sched.status, 403, f"depth={depth}: {await r_sched.text()}")

        # 2. 8-layer & 40-layer nested `model` smuggling `workdir` to POST /api/jobs/dispatch -> 400 + audit
        for depth in (8, 40):
            r_job = await self.client.post(
                "/api/jobs/dispatch",
                json={
                    "bot": TEST_BOT_ONLINE,
                    "prompt": "Check",
                    "model": _nest(depth, {"workdir": "/tmp"}),
                },
                headers=hdrs,
            )
            self.assertEqual(r_job.status, 400, f"depth={depth}: {await r_job.text()}")

        # 3. Non-string `model`, `effort`, `bot` rejected with 400 + audit
        non_str_job_payloads = [
            {"bot": TEST_BOT_ONLINE, "prompt": "p", "model": 123},
            {"bot": TEST_BOT_ONLINE, "prompt": "p", "model": {"nested": "ok"}},
            {"bot": TEST_BOT_ONLINE, "prompt": "p", "effort": 0},
            {"bot": TEST_BOT_ONLINE, "prompt": "p", "effort": ["high"]},
            {"bot": 12345, "prompt": "p"},
        ]
        for payload in non_str_job_payloads:
            r = await self.client.post("/api/jobs/dispatch", json=payload, headers=hdrs)
            self.assertEqual(r.status, 400, f"dispatch non-str {payload}: {await r.text()}")

        non_str_sched_payloads = [
            {"name": "S1", "task_type": "prompt", "schedule_expr": "*/5 * * * *", "prompt": "p", "model": 123},
            {"name": "S2", "task_type": "prompt", "schedule_expr": "*/5 * * * *", "prompt": "p", "model": {"a": 1}},
            {"name": "S3", "task_type": "prompt", "schedule_expr": "*/5 * * * *", "prompt": "p", "bot": ["bot1"]},
            {"name": "S4", "task_type": "prompt", "schedule_expr": "*/5 * * * *", "prompt": "p", "bot": False},
        ]
        for payload in non_str_sched_payloads:
            r = await self.client.post("/api/schedules", json=payload, headers=hdrs)
            self.assertEqual(r.status, 400, f"create schedule non-str {payload}: {await r.text()}")

        # Create a valid schedule to test POST /api/schedules/{id}/run with non-string `bot`
        r_ok = await self.client.post(
            "/api/schedules",
            json={
                "name": "Run Type Check",
                "task_type": "prompt",
                "schedule_expr": "*/10 * * * *",
                "prompt": "Check",
            },
            headers=hdrs,
        )
        self.assertEqual(r_ok.status, 201)
        sid_sched = (await r_ok.json())["schedule"]["id"]

        for bad_bot in (123, {"a": 1}, ["x"], True):
            r_run = await self.client.post(
                f"/api/schedules/{sid_sched}/run",
                json={"bot": bad_bot},
                headers=hdrs,
            )
            self.assertEqual(r_run.status, 400, f"run schedule non-str bot={bad_bot!r}: {await r_run.text()}")

        audits = self._read_audit_entries()
        outcomes = [str(a.get("outcome") or "") for a in audits]
        self.assertIn("denied_forbidden_rce:precheck_cmd", outcomes)
        self.assertIn("denied_forbidden_rce:max_depth_exceeded", outcomes)
        self.assertIn("denied_forbidden_field:workdir", outcomes)
        self.assertIn("denied_forbidden_field:max_depth_exceeded", outcomes)
        self.assertIn("denied_invalid_model", outcomes)
        self.assertIn("denied_invalid_effort", outcomes)
        self.assertIn("denied_invalid_bot", outcomes)

    async def test_block3_extended_host_path_redaction_in_job_detail_and_events(self) -> None:
        sensitive_paths = [
            "~/.gemini/antigravity/secret.json",
            "/tmp/agy_secret_dump.txt",
            "/var/lib/postgresql/data/pg_hba.conf",
            "/opt/internal/deploy.sh",
            "/run/app/sock.pid",
            r"C:\Users\alice\secret.txt",
        ]
        safe_route = "/api/jobs/job-123"
        combined_text = (
            f"Inspect {sensitive_paths[0]} and {sensitive_paths[1]} "
            f"with db={sensitive_paths[2]}, script={sensitive_paths[3]}, "
            f"pidfile={sensitive_paths[4]}, win={sensitive_paths[5]}; "
            f"keep route {safe_route} intact."
        )
        job_id = "job-block3-paths"
        (self.bus_dir / "jobs" / f"{job_id}.json").write_text(
            json.dumps({
                "job_id": job_id,
                "group_id": "grp-block3",
                "label": f"Check {sensitive_paths[1]} on {safe_route}",
                "from_bot": "studio",
                "target_bot": TEST_BOT_ONLINE,
                "status": "done",
                "prompt": combined_text,
                "result_summary": combined_text,
                "error": f"failed reading {sensitive_paths[5]} via {safe_route}",
                "created_at": time.time(),
            }),
            encoding="utf-8",
        )

        _, sid_ro, _ = await self._login("ro_user", TEST_PASS_RO)
        r_det = await self.client.get(
            f"/api/jobs/{job_id}",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_ro}"},
        )
        self.assertEqual(r_det.status, 200)
        det_raw = await r_det.text()
        for sp in sensitive_paths:
            self.assertNotIn(sp, det_raw, f"GET /api/jobs/{{id}} leaked host path: {sp}")
        self.assertNotIn("secret.txt", det_raw)
        self.assertNotIn("pg_hba.conf", det_raw)
        self.assertNotIn("deploy.sh", det_raw)
        self.assertNotIn("sock.pid", det_raw)
        self.assertNotIn("agy_secret_dump.txt", det_raw)
        self.assertIn(safe_route, det_raw, "Web route /api/jobs/job-123 must be preserved")

        # Verify /api/events SSE redacts all sensitive paths while preserving /api/jobs/job-123
        hub = self.app[EVENT_HUB_KEY]
        resp_sse = await self.client.get(
            "/api/events",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid_ro}"},
        )
        self.assertEqual(resp_sse.status, 200)
        init_evs = await _read_sse_events(resp_sse, max_events=1, timeout=1.0)
        self.assertEqual(init_evs[0]["event"], "connected")

        hub.publish(
            "job_updated",
            {
                "action": "path_probe",
                "summary": combined_text,
                "route": safe_route,
            },
        )
        evs = await _read_sse_events(resp_sse, max_events=1, timeout=1.0)
        resp_sse.close()
        self.assertEqual(len(evs), 1)
        ev_raw = json.dumps(evs[0]["data"], ensure_ascii=False)
        for sp in sensitive_paths:
            self.assertNotIn(sp, ev_raw, f"/api/events leaked host path: {sp}")
        self.assertNotIn("secret.txt", ev_raw)
        self.assertNotIn("pg_hba.conf", ev_raw)
        self.assertNotIn("deploy.sh", ev_raw)
        self.assertNotIn("sock.pid", ev_raw)
        self.assertNotIn("agy_secret_dump.txt", ev_raw)
        self.assertIn(safe_route, ev_raw, "Web route /api/jobs/job-123 must be preserved in SSE")

        # BLOCK-3R: Markdown inline-code backtick paths & .sock branches redacted, safe route preserved
        md_sample = (
            "See `/tmp/secret.txt` and `~/.gemini/creds.json` "
            "plus sock=/run/app/bot.sock and foo=worker.sock; "
            f"keep {safe_route} and `{safe_route}` intact."
        )
        redacted_md, _ = redact_job_detail_text(md_sample)
        self.assertIn("`[REDACTED]`", redacted_md)
        self.assertIn("See `[REDACTED]` and `[REDACTED]`", redacted_md)
        self.assertIn("sock=[REDACTED] and foo=[REDACTED]", redacted_md)
        for leaked in ("/tmp/secret.txt", "secret.txt", "~/.gemini/creds.json", "creds.json", "/run/app/bot.sock", "bot.sock", "worker.sock"):
            self.assertNotIn(leaked, redacted_md)
        self.assertIn(f"keep {safe_route} and `{safe_route}` intact.", redacted_md)

        # BLOCK-3R: Linear-time anti-ReDoS check on 32 KiB repeated delimiter inputs (< 0.2s each)
        for bad_sample in (
            "(" * (32 * 1024),
            "=" * (32 * 1024),
            ":" * (32 * 1024),
            "`" * (32 * 1024),
            "(a" * (16 * 1024),
        ):
            t0 = time.perf_counter()
            out_txt, _ = redact_job_detail_text(bad_sample)
            elapsed = time.perf_counter() - t0
            self.assertLess(
                elapsed,
                0.2,
                f"ReDoS regression: 32 KiB delimiter sample took {elapsed:.3f}s (>= 0.2s)",
            )
            self.assertEqual(len(out_txt), len(bad_sample))

    async def test_block4_event_hub_watcher_survives_corrupt_roster_and_recovers(self) -> None:
        hub = self.app[EVENT_HUB_KEY]
        hub.watcher_interval = 0.05
        hub._last_fp = None
        hub.start_watcher()
        self.assertIsNotNone(hub._watcher_task)

        _, sid, _ = await self._login("ro_user", TEST_PASS_RO)
        resp = await self.client.get(
            "/api/events",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid}"},
        )
        self.assertEqual(resp.status, 200)
        init_evs = await _read_sse_events(resp, max_events=1, timeout=1.0)
        self.assertEqual(init_evs[0]["event"], "connected")

        # Wait for initial fingerprint snapshot
        deadline = time.monotonic() + 1.0
        while hub._last_fp is None and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        self.assertIsNotNone(hub._last_fp)

        # Write corrupt roster.json with non-integer pid -> watcher logs warning & stays alive
        roster_path = self.bus_dir / "roster.json"
        with self.assertLogs("agy-studio.events", level="WARNING") as cm:
            roster_path.write_text(
                json.dumps({
                    "version": 1,
                    "bots": {
                        TEST_BOT_ONLINE: {
                            "handle": TEST_BOT_ONLINE,
                            "pid": "not-an-integer",
                            "last_seen": time.time(),
                        }
                    },
                }),
                encoding="utf-8",
            )
            await asyncio.sleep(0.18)

        self.assertTrue(
            any("EventHub watcher" in msg for msg in cm.output),
            f"Expected watcher warning log, got: {cm.output}",
        )
        self.assertIsNotNone(hub._watcher_task)
        assert hub._watcher_task is not None
        self.assertFalse(hub._watcher_task.done(), "Watcher task MUST remain alive after corrupt roster.json")

        # Restore valid roster.json -> watcher detects change and pushes bots_updated
        now = time.time()
        roster_path.write_text(
            json.dumps({
                "version": 1,
                "bots": {
                    TEST_BOT_ONLINE: {
                        "handle": TEST_BOT_ONLINE,
                        "display_name": "Recovered Worker",
                        "role": "worker",
                        "pid": os.getpid(),
                        "last_seen": now,
                        "busy": True,
                        "active_model": "gemini-3.8-flash",
                        "default_project": "safe-proj",
                    }
                },
            }),
            encoding="utf-8",
        )
        recovered_evs = await _read_sse_events(resp, max_events=5, timeout=1.0)
        resp.close()
        bots_evs = [e for e in recovered_evs if e["event"] == "bots_updated"]
        self.assertTrue(bots_evs, f"Expected bots_updated after roster recovery, got: {recovered_evs}")
        self.assertEqual(bots_evs[-1]["data"].get("source"), "watcher")  # type: ignore[union-attr]
        self.assertEqual(bots_evs[-1]["data"].get("busy"), 1)  # type: ignore[union-attr]

    async def test_p2_delete_schedule_flock_guard_and_sse_close_task_awaited(self) -> None:
        _, sid, csrf = await self._login("admin_user", TEST_PASS_ADMIN)
        hdrs = self._write_headers(sid, csrf)

        # P2-1: Create safe schedule, then simulate TOCTOU replacement with script task before delete_task runs
        r_create = await self.client.post(
            "/api/schedules",
            json={
                "name": "Race Target",
                "task_type": "prompt",
                "schedule_expr": "*/10 * * * *",
                "prompt": "Normal prompt",
            },
            headers=hdrs,
        )
        self.assertEqual(r_create.status, 201)
        race_id = (await r_create.json())["schedule"]["id"]

        tm = scheduler.TaskManager(
            filepath=str(self.schedules_file),
            lockpath=str(self.schedules_file.parent / f".{self.schedules_file.name}.lock"),
        )
        orig_get_task = scheduler.TaskManager.get_task

        def _swap_to_script_after_read(self_tm: scheduler.TaskManager, tid: str):
            res = orig_get_task(self_tm, tid)
            if tid == race_id and isinstance(res, dict):
                # Concurrently mutate on disk to a CLI script task after initial read
                def _mutate_to_script(t: dict[str, object]) -> None:
                    t["task_type"] = "script"
                    t["payload"] = {"script": "echo cli_only"}

                self_tm.update_task(tid, _mutate_to_script)
            return res

        with mock.patch.object(scheduler.TaskManager, "get_task", _swap_to_script_after_read):
            r_del = await self.client.delete(
                f"/api/schedules/{race_id}", data="{}", headers=hdrs
            )
            self.assertEqual(r_del.status, 403, await r_del.text())

        # Verify task survived on disk (was NOT deleted under flock!)
        surviving = tm.get_task(race_id)
        self.assertIsNotNone(surviving)
        assert surviving is not None
        self.assertEqual(surviving.get("task_type"), "script")

        # P2-2: Verify `_on_auth_revoked` tracks `close_task` on active stream entry and `finally:` awaits it
        hub = self.app[EVENT_HUB_KEY]
        resp = await self.client.get(
            "/api/events",
            headers={"Cookie": f"{SESSION_COOKIE_NAME}={sid}"},
        )
        self.assertEqual(resp.status, 200)
        init_evs = await _read_sse_events(resp, max_events=1, timeout=1.0)
        self.assertEqual(init_evs[0]["event"], "connected")

        tracked_entries = list(hub._active_streams.values())
        self.assertEqual(len(tracked_entries), 1)
        entry_ref = tracked_entries[0]

        r_out = await self.client.post(
            "/api/auth/logout",
            headers=hdrs,
            data="{}",
        )
        self.assertEqual(r_out.status, 200)
        tail = await _read_sse_events(resp, max_events=5, timeout=1.2)
        resp.close()
        self.assertTrue(any(e["event"] == "auth_error" for e in tail), tail)
        self.assertIsNotNone(entry_ref.get("close_task"))
        assert entry_ref["close_task"] is not None
        self.assertTrue(entry_ref["close_task"].done())


class TestPAC5AndC7FrontendAndProtectedHygiene(unittest.TestCase):
    """PA-C5 & PA-C7: Zero dangerouslySetInnerHTML, zero new npm deps, 0 protected file edits."""

    def test_pa_c5_c7_frontend_safety_and_protected_files(self) -> None:
        src_root = REPO_ROOT / "webui" / "src"
        self.assertTrue(src_root.is_dir())
        forbidden_re = re.compile(r"\b(?:dangerouslySetInnerHTML|innerHTML|outerHTML)\b")
        block_comment_re = re.compile(r"/\*[\s\S]*?\*/")
        line_comment_re = re.compile(r"//[^\n]*")
        for fp in sorted(src_root.rglob("*.ts*")):
            txt = fp.read_text(encoding="utf-8")
            code_only = line_comment_re.sub("", block_comment_re.sub("", txt))
            self.assertIsNone(
                forbidden_re.search(code_only),
                f"Forbidden raw HTML sink found in {fp.relative_to(REPO_ROOT)}",
            )

        # Verify zero new npm dependencies added in package.json
        pkg = json.loads((REPO_ROOT / "webui" / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(set((pkg.get("dependencies") or {}).keys()), {"lucide-react", "react", "react-dom"})

        # Verify protected files have zero modifications relative to HEAD
        # (skip during export_public pre-commit verification when synced files are not yet committed;
        # post-commit verification & CI always run with AGY_EXPORT_PUBLIC_VERIFY unset).
        if os.environ.get("AGY_EXPORT_PUBLIC_VERIFY") != "1":
            protected = [
                ".agents/skills/google-profile/scripts/google_browser.py",
                ".agents/skills/live-browser/scripts/static/index.html",
            ]
            res = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "diff", "--name-only", "HEAD", "--", *protected],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(res.stdout.strip(), "", f"Protected files modified: {res.stdout!r}")


if __name__ == "__main__":
    unittest.main()
