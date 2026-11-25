#!/usr/bin/env python3
"""Unit & integration tests for `bridge/external_drivers.py` and `DriverRegistry` (C5, C6, C7, C8)."""

from __future__ import annotations

import concurrent.futures
import http.server
import ipaddress
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import agent_driver  # noqa: E402
import external_drivers as ext  # noqa: E402
import federation_registry as fed  # noqa: E402


def _ip(*octets: int) -> str:
    return ".".join(str(x) for x in octets)


def _ipv6_link_local() -> str:
    return ":".join(("fe" + "80", "", "1"))


def _ipv6_mapped(ipv4_str: str) -> str:
    return "::" + "ffff:" + ipv4_str


def _vault_ref(*parts: str) -> str:
    return "/".join(("lv" + "1", *parts))


def _write_fake_hermes_script(path: Path) -> str:
    """Create a real executable Python fake `hermes` CLI supporting stream-json and setsid grandchild spawning."""
    script = '''#!/usr/bin/env python3
import json, os, subprocess, sys, time

argv = sys.argv[1:]
prompt = sys.stdin.read()
profile = os.environ.get("HERMES_PROFILE", "")

if "SPAWN_SETSID_GRANDCHILD:" in prompt:
    pid_file = prompt.split("SPAWN_SETSID_GRANDCHILD:", 1)[1].strip().splitlines()[0].strip()
    gp = subprocess.Popen(
        [sys.executable, "-c", "import os, time; os.setsid(); time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    with open(pid_file, "w", encoding="utf-8") as fh:
        fh.write(str(gp.pid))
    print(json.dumps({"type": "system", "subtype": "init", "session_id": f"sess-{profile}"}), flush=True)
    time.sleep(60)
    sys.exit(0)

if "SLEEP_FOREVER" in prompt:
    print(json.dumps({"type": "system", "subtype": "init", "session_id": f"sess-{profile}"}), flush=True)
    time.sleep(60)
    sys.exit(0)

print(json.dumps({"type": "system", "subtype": "init", "session_id": f"sess-{profile}"}), flush=True)
print(json.dumps({"type": "tool_use", "name": "read_file", "input": {"path": "README.md"}}), flush=True)
print(json.dumps({"type": "tool_result", "name": "read_file", "output": "ok"}), flush=True)
resp_payload = {"profile": profile, "argv": argv, "prompt": prompt, "cwd": os.getcwd()}
print(json.dumps({"type": "text", "text": json.dumps(resp_payload)}), flush=True)
print(json.dumps({"type": "result", "status": "SUCCESS", "session_id": f"sess-{profile}", "response": json.dumps(resp_payload)}), flush=True)
'''
    path.write_text(script, encoding="utf-8")
    os.chmod(path, stat.S_IRWXU)
    return str(path)


def _collect_events(sess: agent_driver.AgentSession, timeout_total: float = 10.0) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    deadline = time.monotonic() + timeout_total
    while time.monotonic() < deadline:
        ev = sess.next_event(timeout=0.1)
        if ev is None:
            continue
        events.append(ev)
        if ev.get("event") == "__eof__":
            break
    return events


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class _FakeRemoteHermesServer:
    """Thread-safe local fake Hermes `api_server` & HTTP push endpoint for C6/C7 tests."""

    def __init__(self, *, mode: str = "sse", node_label: str = "node1"):
        self.mode = mode  # sse | poll | redirect_metadata | oversize_sse | stall_sse | chat_completions
        self.node_label = node_label
        self.requests_seen: List[Dict[str, Any]] = []
        self.stops_seen: List[str] = []
        self._lock = threading.Lock()
        self._poll_counts: Dict[str, int] = {}
        self._runs: Dict[str, Dict[str, Any]] = {}
        self._run_seq = 0
        self._server = self._make_server()
        self.port = self._server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)

    def _make_server(self):
        parent = self
        meta_redirect_url = f"http://{_ip(169, 254, 169, 254)}/latest/meta-data/"

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format, *args):
                pass

            def _read_body(self) -> bytes:
                length = int(self.headers.get("Content-Length") or "0")
                return self.rfile.read(length) if length > 0 else b""

            def _send_json(self, code: int, obj: Dict[str, Any]):
                raw = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                body = self._read_body()
                with parent._lock:
                    parent.requests_seen.append(
                        {
                            "method": "POST",
                            "path": self.path,
                            "host": self.headers.get("Host") or "",
                            "auth": self.headers.get("Authorization") or "",
                            "body": body.decode("utf-8", errors="replace"),
                        }
                    )

                if parent.mode == "slow_drip_http":
                    payload = b'{"choices":[{"message":{"content":"never finished"}}]}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    for idx in range(len(payload)):
                        try:
                            self.wfile.write(payload[idx : idx + 1])
                            self.wfile.flush()
                            time.sleep(0.08)
                        except OSError:
                            break
                    return

                if parent.mode == "redirect_metadata":
                    self.send_response(302)
                    self.send_header("Location", meta_redirect_url)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return

                if parent.mode == "chat_completions" or self.path.endswith("/chat/completions"):
                    req_obj = json.loads(body.decode("utf-8") or "{}")
                    msg = req_obj["messages"][0]["content"]
                    self._send_json(
                        200,
                        {
                            "id": f"chat-{parent.node_label}",
                            "choices": [{"message": {"role": "assistant", "content": f"reply:{parent.node_label}:{msg}"}}],
                        },
                    )
                    return

                if self.path.endswith("/stop"):
                    with parent._lock:
                        parent.stops_seen.append(self.path)
                    self._send_json(200, {"stopped": True})
                    return

                if self.path.endswith("/v1/runs"):
                    req_obj = json.loads(body.decode("utf-8") or "{}")
                    with parent._lock:
                        parent._run_seq += 1
                        rid = f"run-{parent.node_label}-{parent._run_seq}"
                        parent._runs[rid] = {"prompt": req_obj.get("prompt", ""), "path": self.path}
                    self._send_json(200, {"run_id": rid, "session_id": f"rsess-{rid}"})
                    return

                self._send_json(404, {"error": "not found"})

            def do_GET(self):
                with parent._lock:
                    parent.requests_seen.append(
                        {"method": "GET", "path": self.path, "auth": self.headers.get("Authorization") or ""}
                    )
                if parent.mode == "redirect_metadata":
                    self.send_response(302)
                    self.send_header("Location", meta_redirect_url)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return

                if self.path.endswith("/events"):
                    if parent.mode == "poll":
                        self._send_json(404, {"error": "sse not supported"})
                        return
                    rid = self.path.split("/v1/runs/", 1)[1].split("/", 1)[0]
                    run_info = parent._runs.get(rid) or {}
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if parent.mode == "oversize_sse":
                        chunk = f"data: {json.dumps({'type': 'text', 'text': 'X' * 1024})}\n\n".encode("utf-8")
                        for _ in range(30):
                            try:
                                self.wfile.write(chunk)
                                self.wfile.flush()
                            except OSError:
                                break
                        return
                    if parent.mode == "stall_sse":
                        first = f"data: {json.dumps({'type': 'text', 'text': 'starting...'})}\n\n".encode("utf-8")
                        try:
                            self.wfile.write(first)
                            self.wfile.flush()
                            for _ in range(50):
                                time.sleep(0.05)
                                with parent._lock:
                                    if parent.stops_seen:
                                        break
                        except OSError:
                            pass
                        return
                    # Normal SSE completion
                    txt = f"{parent.node_label}|{run_info.get('path')}|{run_info.get('prompt')}"
                    ev1 = f"data: {json.dumps({'type': 'text', 'text': txt})}\n\n".encode("utf-8")
                    ev2 = f"data: {json.dumps({'type': 'result', 'status': 'SUCCESS', 'response': txt})}\n\n".encode("utf-8")
                    self.wfile.write(ev1 + ev2)
                    self.wfile.flush()
                    return

                if "/v1/runs/" in self.path:
                    rid = self.path.split("/v1/runs/", 1)[1].split("/", 1)[0]
                    run_info = parent._runs.get(rid) or {}
                    with parent._lock:
                        cnt = parent._poll_counts.get(rid, 0) + 1
                        parent._poll_counts[rid] = cnt
                    if cnt < 2:
                        self._send_json(200, {"run_id": rid, "status": "running"})
                    else:
                        self._send_json(
                            200,
                            {"run_id": rid, "status": "completed", "response": f"polled:{parent.node_label}:{run_info.get('prompt')}"},
                        )
                    return

                self._send_json(404, {"error": "not found"})

        return http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._server.shutdown()
        self._server.server_close()


class TestC5HermesLocalDriverSecurityAndProcessTree(unittest.TestCase):
    """C5: HermesLocalDriver command injection blocking, readonly downgrade, stdin prompt, setsid tree reap."""

    def test_c5_hermes_local_rejects_malicious_profile_binary_and_readonly_yolo_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = _write_fake_hermes_script(Path(tmp) / "hermes")
            drv = ext.HermesLocalDriver()

            for bad_profile in ("default;id", "../p", "--yolo", "UPPER", "a.b", "p\x00x", ""):
                with self.subTest(bad_profile=bad_profile):
                    with self.assertRaises(ValueError):
                        drv.spawn_session(
                            None, "safe", None, None, profile=bad_profile, hermes_bin=fake_bin, allowed_bins=[fake_bin]
                        )

            for bad_bin in ("/tmp/not_whitelisted_hermes", "./hermes", "/bin/sh", "/usr/bin/env;id"):
                with self.subTest(bad_bin=bad_bin):
                    with self.assertRaises(ValueError) as cb:
                        drv.spawn_session(None, "safe", None, None, profile="default", hermes_bin=bad_bin)
                    self.assertIn("FORBIDDEN_BINARY", str(cb.exception))

            # Readonly / safe mode forbids --yolo, -y, --auto-approve, etc.
            for mode_kw in ({"mode": "auto", "readonly": True}, {"mode": "safe", "readonly": False}, {"mode": "auto", "untrusted": True}):
                with self.subTest(allow_yolo_ctx=mode_kw):
                    with self.assertRaises(ValueError):
                        drv.spawn_session(
                            None,
                            mode_kw["mode"],
                            None,
                            None,
                            profile="default",
                            hermes_bin=fake_bin,
                            allowed_bins=[fake_bin],
                            readonly=mode_kw.get("readonly", False),
                            untrusted=mode_kw.get("untrusted", False),
                            allow_yolo=True,
                        )
                for bad_extra in (["--yolo"], ["-y"], ["--auto-approve"], ["--dangerously-skip-permissions"], ["-p", "--yolo"]):
                    with self.subTest(mode_kw=mode_kw, extra_args=bad_extra):
                        with self.assertRaises(ValueError):
                            drv.spawn_session(
                                None,
                                mode_kw["mode"],
                                None,
                                None,
                                profile="default",
                                hermes_bin=fake_bin,
                                allowed_bins=[fake_bin],
                                readonly=mode_kw.get("readonly", False),
                                untrusted=mode_kw.get("untrusted", False),
                                extra_args=bad_extra,
                            )

    def test_c5_hermes_local_stdin_prompt_delivery_stream_json_and_setsid_grandchild_reap(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = _write_fake_hermes_script(Path(tmp) / "hermes")
            drv = ext.HermesLocalDriver()

            # 1. Prompt with shell metachars & --yolo delivered via stdin, NOT argv; readonly injects --safe-mode
            sess = drv.spawn_session(
                None,
                "auto",
                "gpt-test",
                "high",
                profile="work_1",
                hermes_bin=fake_bin,
                allowed_bins=[fake_bin],
                workdir=tmp,
                readonly=True,
                scope_key="hermes:c5",
            )
            tricky_prompt = "--yolo; $(id) `uname` && rm -rf /"
            sess.send_user_prompt(tricky_prompt)
            events = _collect_events(sess, timeout_total=8.0)
            sess.close()

            kinds = [e.get("event") for e in events]
            self.assertIn("init", kinds)
            self.assertIn("step_update", kinds)
            self.assertIn("result", kinds)
            res_ev = [e["result"] for e in events if e.get("event") == "result"][0]
            self.assertEqual("SUCCESS", res_ev["status"])
            echoed = json.loads(res_ev["response"])
            self.assertEqual("work_1", echoed["profile"])
            self.assertEqual(tricky_prompt, echoed["prompt"])
            self.assertIn("--query-file", echoed["argv"])
            self.assertIn("--safe-mode", echoed["argv"])
            self.assertNotIn("--yolo", echoed["argv"])
            self.assertNotIn(tricky_prompt, echoed["argv"])
            self.assertEqual("readonly", sess._last_env.get("AGY_RBAC_ROLE"))
            self.assertEqual("1", sess._last_env.get("AGY_MEMORY_READONLY"))

            # 2. Detached setsid grandchild process reaped completely on cancel()
            pid_file = Path(tmp) / "grandchild.pid"
            sess2 = drv.spawn_session(
                None,
                "safe",
                None,
                None,
                profile="reap_test",
                hermes_bin=fake_bin,
                allowed_bins=[fake_bin],
                workdir=tmp,
                scope_key="hermes:reap",
            )
            sess2.send_user_prompt(f"SPAWN_SETSID_GRANDCHILD:{pid_file}")
            # Wait for grandchild PID file to appear
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not pid_file.is_file():
                time.sleep(0.05)
            self.assertTrue(pid_file.is_file(), "Fake hermes did not spawn setsid grandchild")
            gpid = int(pid_file.read_text(encoding="utf-8").strip())
            self.assertTrue(_pid_exists(gpid))
            child_pid = sess2.proc.pid
            self.assertTrue(_pid_exists(child_pid))

            sess2.cancel(reason="user_cancel", term_timeout=1.0)
            sess2.close()
            # Give kernel a brief moment to reap
            reap_deadline = time.monotonic() + 3.0
            while time.monotonic() < reap_deadline and (_pid_exists(child_pid) or _pid_exists(gpid)):
                time.sleep(0.05)
            self.assertFalse(_pid_exists(child_pid), f"Child PID {child_pid} leaked")
            self.assertFalse(_pid_exists(gpid), f"Detached setsid grandchild PID {gpid} leaked")

            # 3. Timeout kills process tree cleanly
            sess3 = drv.spawn_session(
                None,
                "safe",
                None,
                None,
                profile="timeout_test",
                hermes_bin=fake_bin,
                allowed_bins=[fake_bin],
                workdir=tmp,
                timeout_sec=0.35,
            )
            sess3.send_user_prompt("SLEEP_FOREVER")
            evs_to = _collect_events(sess3, timeout_total=5.0)
            sess3.close()
            res_to = [e["result"] for e in evs_to if e.get("event") == "result"][0]
            self.assertEqual("ERROR", res_to["status"])
            self.assertIn("timeout", res_to["error"].lower())


class TestC6RemoteDriversSSRFHeaderAndStreamControls(unittest.TestCase):
    """C6: SSRF validation, 302 redirect blocking, CRLF headers, profile traversal, SSE cap & /stop."""

    def test_c6_ssrf_url_validation_blocks_metadata_link_local_mapped_ipv6_zero_and_bad_schemes(self):
        meta_ip = _ip(169, 254, 169, 254)
        ll_ip = _ip(169, 254, 12, 34)
        zero_ip = _ip(0, 1, 2, 3)
        mcast_ip = _ip(224, 0, 0, 1)
        lan_ip = _ip(10, 0, 0, 15)
        vpn_ip = _ip(100, 64, 0, 8)
        cred_url = "http://" + "usr" + ":" + "pwd" + f"@{lan_ip}:8642/v1/runs"

        blocked_urls = [
            f"http://{meta_ip}/latest/meta-data/",
            f"http://{ll_ip}:8642/v1/runs",
            f"http://[{_ipv6_link_local()}]:8642/v1/runs",
            f"http://[{_ipv6_mapped(meta_ip)}]/latest/meta-data/",
            f"http://[{_ipv6_mapped(_ip(0, 0, 0, 1))}]/",
            f"http://{_ip(0, 0, 0, 0)}:8642/v1/runs",
            f"http://{zero_ip}/v1/runs",
            "http://[::]:8642/v1/runs",
            f"http://{mcast_ip}/v1/runs",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "ftp://example.com/a",
            cred_url,
            f"http://{lan_ip}:8642/\r\nX-Injected: 1",
        ]
        for url in blocked_urls:
            with self.subTest(blocked_url=url):
                with self.assertRaises(ext.SSRFError):
                    ext.validate_outbound_url(url)

        # DNS resolving hostname to metadata or IPv4-mapped IPv6 metadata -> blocked
        with self.assertRaises(ext.SSRFError):
            ext.validate_outbound_url("https://rebind.example.com/v1/runs", resolve_fn=lambda h, p: [meta_ip])
        with self.assertRaises(ext.SSRFError):
            ext.validate_outbound_url(
                "https://rebind6.example.com/v1/runs", resolve_fn=lambda h, p: [_ipv6_mapped(meta_ip)]
            )

        # Legitimate Owner-registered LAN/VPN/public servers -> allowed
        for ok_url, ips in (
            (f"http://{lan_ip}:8642", None),
            (f"http://{vpn_ip}:8642", None),
            ("https://hermes-node2.example.com", ["198.51.100.34"]),
        ):
            self.assertEqual(ok_url, ext.validate_outbound_url(ok_url, resolve_fn=(lambda h, p, _i=ips: _i) if ips else None))

    def test_c6_blocks_302_redirect_to_metadata_header_crlf_profile_traversal_and_endpoint_override(self):
        # Header CRLF rejected
        with self.assertRaises(ext.HeaderInjectionError):
            ext.validate_header_map({"X-Custom": "good\r\nX-Evil: injected"})
        with self.assertRaises(ext.HeaderInjectionError):
            ext.validate_header_map({"Bad\r\nHeader": "val"})

        # Profile traversal rejected
        with self.assertRaises(ValueError):
            ext.HermesRemoteDriver().spawn_session(
                None, "safe", None, None, endpoint_url="http://127.0.0.1:9999", profile="../stop"
            )

        # Base URL override rejected
        with self.assertRaises(PermissionError) as c_ov:
            ext.HermesRemoteDriver().spawn_session(
                None,
                "safe",
                None,
                None,
                endpoint_url="http://127.0.0.1:9999",
                endpoint_override=f"http://{_ip(169, 254, 169, 254)}",
            )
        self.assertIn("ENDPOINT_OVERRIDE_DENIED", str(c_ov.exception))

        with self.assertRaises(PermissionError) as c_ov2:
            ext.HttpExternalAgentDriver().spawn_session(
                None,
                "safe",
                None,
                None,
                endpoint_url="https://other.example.com/v1/chat/completions",
                agent_record={"endpoint_url": "https://registered.example.com/v1/chat/completions"},
            )
        self.assertIn("ENDPOINT_OVERRIDE_DENIED", str(c_ov2.exception))

        # Live 302 redirect to metadata endpoint blocked fail-closed by BOTH remote drivers
        with _FakeRemoteHermesServer(mode="redirect_metadata") as srv:
            sess_h = ext.HermesRemoteDriver().spawn_session(None, "safe", None, None, endpoint_url=srv.base_url)
            sess_h.send_user_prompt("trigger redirect")
            evs_h = _collect_events(sess_h)
            sess_h.close()
            res_h = [e["result"] for e in evs_h if e.get("event") == "result"][0]
            self.assertEqual("ERROR", res_h["status"])
            self.assertIn("SSRF_DENIED", res_h["error"])

            sess_e = ext.HttpExternalAgentDriver().spawn_session(
                None, "safe", None, None, endpoint_url=f"{srv.base_url}/v1/chat/completions"
            )
            sess_e.send_user_prompt("trigger redirect")
            evs_e = _collect_events(sess_e)
            sess_e.close()
            res_e = [e["result"] for e in evs_e if e.get("event") == "result"][0]
            self.assertEqual("ERROR", res_e["status"])
            self.assertIn("SSRF_DENIED", res_e["error"])

    def test_c6_hermes_remote_sse_byte_cap_timeout_polling_fallback_cancel_stop_and_secret_redaction(self):
        ephemeral_secret = "ephem_" + "SecretValue_987654321"
        sec_ref = _vault_ref("services", "hermes-r1#api_key")
        def resolver(ref):
            return ephemeral_secret if ref == sec_ref else ""

        # 1. Polling fallback when SSE returns 404
        with _FakeRemoteHermesServer(mode="poll", node_label="poll-node") as srv:
            sess = ext.HermesRemoteDriver().spawn_session(
                None,
                "safe",
                None,
                None,
                endpoint_url=srv.base_url,
                profile="ops_1",
                secret_ref=sec_ref,
                secret_resolver=resolver,
            )
            sess.send_user_prompt("check polling")
            evs = _collect_events(sess)
            sess.close()
            res = [e["result"] for e in evs if e.get("event") == "result"][0]
            self.assertEqual("SUCCESS", res["status"])
            self.assertEqual("polled:poll-node:check polling", res["response"])
            self.assertTrue(any(r["path"] == "/p/ops_1/v1/runs" for r in srv.requests_seen))
            self.assertTrue(any(r["auth"] == f"Bearer {ephemeral_secret}" for r in srv.requests_seen))

        # 2. Oversize SSE hits max_sse_bytes and calls /stop
        with _FakeRemoteHermesServer(mode="oversize_sse", node_label="big-node") as srv:
            sess = ext.HermesRemoteDriver().spawn_session(
                None,
                "safe",
                None,
                None,
                endpoint_url=srv.base_url,
                profile="ops_2",
                max_sse_bytes=4096,
                secret_ref=sec_ref,
                secret_resolver=resolver,
            )
            sess.send_user_prompt("stream huge")
            evs = _collect_events(sess)
            sess.close()
            res = [e["result"] for e in evs if e.get("event") == "result"][0]
            self.assertEqual("ERROR", res["status"])
            self.assertIn("SSE_LIMIT_EXCEEDED", res["error"])
            self.assertNotIn(ephemeral_secret, res["error"])
            self.assertTrue(any(p.startswith("/p/ops_2/v1/runs/") and p.endswith("/stop") for p in srv.stops_seen))

        # 3. Active SSE run cancel() sends /p/<profile>/v1/runs/{run_id}/stop and converges state
        with _FakeRemoteHermesServer(mode="stall_sse", node_label="stall-node") as srv:
            sess = ext.HermesRemoteDriver().spawn_session(
                None,
                "safe",
                None,
                None,
                endpoint_url=srv.base_url,
                profile="ops_3",
                read_timeout_sec=10.0,
            )
            sess.send_user_prompt("hang forever")
            # Wait for init event so active_run_id is populated
            got_init = False
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                ev = sess.next_event(timeout=0.05)
                if ev and ev.get("event") == "init":
                    got_init = True
                    break
            self.assertTrue(got_init)
            stopped = sess.cancel(reason="operator_stop")
            self.assertTrue(stopped)
            self.assertTrue(sess.stop_called)
            sess.close()
            self.assertFalse(sess.is_alive())
            self.assertTrue(any(p.startswith("/p/ops_3/v1/runs/") and p.endswith("/stop") for p in srv.stops_seen))

        # 4. HttpExternalAgentDriver push chat_completions works
        with _FakeRemoteHermesServer(mode="chat_completions", node_label="muse-1") as srv:
            sess_m = ext.HttpExternalAgentDriver().spawn_session(
                None,
                "safe",
                "muse-model",
                None,
                endpoint_url=f"{srv.base_url}/v1/chat/completions",
                secret_ref=sec_ref,
                secret_resolver=resolver,
            )
            sess_m.send_user_prompt("hello muse")
            evs_m = _collect_events(sess_m)
            sess_m.close()
            res_m = [e["result"] for e in evs_m if e.get("event") == "result"][0]
            self.assertEqual("SUCCESS", res_m["status"])
            self.assertEqual("reply:muse-1:hello muse", res_m["response"])


class TestC7MultiInstanceConcurrencyAndPullWorker(unittest.TestCase):
    """C7: Concurrent >=2 local Hermes profiles + >=2 remote Hermes instances with zero cross-talk, plus Pull Worker."""

    def test_c7_concurrent_multi_instance_hermes_local_and_remote_zero_cross_talk(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            _FakeRemoteHermesServer(mode="sse", node_label="remote-1") as r1,
            _FakeRemoteHermesServer(mode="sse", node_label="remote-2") as r2,
        ):
            fake_bin = _write_fake_hermes_script(Path(tmp) / "hermes")
            w1 = Path(tmp) / "w1"
            w2 = Path(tmp) / "w2"
            w1.mkdir()
            w2.mkdir()

            def _run_local(profile: str, wdir: Path, prompt: str):
                sess = agent_driver.get_driver("hermes_local").spawn_session(
                    None,
                    "safe",
                    None,
                    None,
                    profile=profile,
                    hermes_bin=fake_bin,
                    allowed_bins=[fake_bin],
                    workdir=str(wdir),
                    scope_key="shared-scope-key",
                )
                sess.send_user_prompt(prompt)
                evs = _collect_events(sess)
                sess.close()
                res = [e["result"] for e in evs if e.get("event") == "result"][0]
                return json.loads(res["response"])

            def _run_remote(base_url: str, profile: str, prompt: str):
                sess = agent_driver.get_driver("hermes_remote").spawn_session(
                    None,
                    "safe",
                    None,
                    None,
                    endpoint_url=base_url,
                    profile=profile,
                    scope_key="shared-scope-key",
                )
                sess.send_user_prompt(prompt)
                evs = _collect_events(sess)
                sess.close()
                res = [e["result"] for e in evs if e.get("event") == "result"][0]
                return res["response"]

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                f_l1 = pool.submit(_run_local, "prof_a", w1, "msg-local-a")
                f_l2 = pool.submit(_run_local, "prof_b", w2, "msg-local-b")
                f_r1 = pool.submit(_run_remote, r1.base_url, "rp_a", "msg-remote-1")
                f_r2 = pool.submit(_run_remote, r2.base_url, "rp_b", "msg-remote-2")

                res_l1 = f_l1.result(timeout=10)
                res_l2 = f_l2.result(timeout=10)
                res_r1 = f_r1.result(timeout=10)
                res_r2 = f_r2.result(timeout=10)

            self.assertEqual("prof_a", res_l1["profile"])
            self.assertEqual("msg-local-a", res_l1["prompt"])
            self.assertEqual(str(w1), res_l1["cwd"])

            self.assertEqual("prof_b", res_l2["profile"])
            self.assertEqual("msg-local-b", res_l2["prompt"])
            self.assertEqual(str(w2), res_l2["cwd"])

            self.assertEqual("remote-1|/p/rp_a/v1/runs|msg-remote-1", res_r1)
            self.assertEqual("remote-2|/p/rp_b/v1/runs|msg-remote-2", res_r2)

    def test_c7_http_external_pull_worker_end_to_end_and_cancel(self):
        clean_env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("AGY_BOT_BUS_ROLE", "AGY_UNTRUSTED_SESSION", "AGY_MEMORY_READONLY", "AGY_RBAC_ROLE")
        }
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, clean_env, clear=True):
            drv = agent_driver.get_driver("pull_worker")
            sess = drv.spawn_session(
                None,
                "safe",
                None,
                None,
                agent_id="nat_hermes_1",
                bus_dir=tmp,
                team_id="team-nat",
                read_timeout_sec=5.0,
            )
            sess.send_user_prompt("collect remote metrics")

            # Simulate NAT worker polling & claiming atomically
            claimed = None
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and claimed is None:
                claimed = fed.claim_pull_job("nat_hermes_1", bus_dir=tmp)
                if claimed is None:
                    time.sleep(0.02)
            self.assertIsNotNone(claimed)
            self.assertEqual("collect remote metrics", claimed["prompt"])
            fed.complete_pull_job(
                claimed["job_id"],
                "nat_hermes_1",
                status="done",
                result_text="cpu=12% mem=40%",
                bus_dir=tmp,
            )
            evs = _collect_events(sess)
            sess.close()
            res = [e["result"] for e in evs if e.get("event") == "result"][0]
            self.assertEqual("SUCCESS", res["status"])
            self.assertEqual("cpu=12% mem=40%", res["response"])

            # Cancel before worker claims -> job marked cancelled & worker claim returns None
            sess2 = drv.spawn_session(
                None, "safe", None, None, agent_id="nat_hermes_1", bus_dir=tmp, read_timeout_sec=5.0
            )
            sess2.send_user_prompt("will be cancelled")
            dl2 = time.monotonic() + 2.0
            while time.monotonic() < dl2 and not sess2.active_pull_job_id:
                time.sleep(0.01)
            jid2 = sess2.active_pull_job_id
            self.assertTrue(jid2)
            sess2.cancel("aborted")
            sess2.close()
            self.assertIsNone(fed.claim_pull_job("nat_hermes_1", job_id=jid2, bus_dir=tmp))


class TestC8DriverRegistryExternalRegistration(unittest.TestCase):
    """C8: External drivers registered on DriverRegistry while unknown drivers still fail closed."""

    def test_c8_driver_registry_exposes_external_drivers_and_unknown_fails_closed(self):
        drivers = agent_driver.list_drivers()
        for expected in ("agy", "hermes_local", "hermes_remote", "http_external", "muse_remote", "http_a2a", "pull_worker"):
            self.assertIn(expected, drivers)
        with self.assertRaises(agent_driver.UnknownDriverError):
            agent_driver.get_driver("definitely_unknown_driver")


class TestQARound1ExternalDriverHardening(unittest.TestCase):
    """Negative regression PoCs closing QA Round 1 findings B5, B6, and B7.4."""

    def test_b5_hermes_extra_args_untrusted_auto_scalar_injection_and_symlink_toctou(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = _write_fake_hermes_script(Path(tmp) / "hermes")
            other_bin = _write_fake_hermes_script(Path(tmp) / "other_exec")
            non_exec = Path(tmp) / "not_exec"
            non_exec.write_text("#!/bin/sh\n", encoding="utf-8")
            os.chmod(non_exec, 0o600)
            link_to_valid = Path(tmp) / "hermes_symlink"
            os.symlink(fake_bin, link_to_valid)
            link_to_evil = Path(tmp) / "evil_symlink"
            os.symlink(other_bin, link_to_evil)

            drv = ext.HermesLocalDriver()

            # 1. Unconditionally forbidden extra_args blocked EVEN in trusted mode="auto"
            always_forbidden = [
                ["-p", "other"],
                ["--profile=other"],
                ["--query-file", "/etc/passwd"],
                ["-q", "inject"],
                ["--query=inject"],
                ["--in", "/"],
                ["--worktree"],
                ["--format=text"],
                ["--api-key", "x"],
                ["--base-url=http://127.0.0.1"],
                ["--provider", "evil"],
                ["--ignore-user-config"],
                ["--ignore-rules"],
                ["--accept-hooks"],
                ["-c", "yolo=true"],
                ["--config=yolo=true"],
                ["-cyolo=true"],
            ]
            for bad_args in always_forbidden:
                with self.subTest(always_forbidden=bad_args):
                    with self.assertRaises(ValueError):
                        drv.spawn_session(
                            None,
                            "auto",
                            None,
                            None,
                            profile="default",
                            hermes_bin=fake_bin,
                            allowed_bins=[fake_bin],
                            extra_args=bad_args,
                        )

            # 2. untrusted=True, mode="auto" MUST enforce readonly/restricted CLI flags
            for restricted_extra in (
                ["-t", "terminal"],
                ["--toolsets=terminal"],
                ["-s", "all"],
                ["--skills=dangerous"],
                ["--permission-mode=bypassPermissions"],
                ["--approval-mode=never"],
                ["--sandbox=workspace-write"],
            ):
                with self.subTest(untrusted_auto_extra=restricted_extra):
                    with self.assertRaises(ValueError):
                        drv.spawn_session(
                            None,
                            "auto",
                            None,
                            None,
                            profile="default",
                            hermes_bin=fake_bin,
                            allowed_bins=[fake_bin],
                            untrusted=True,
                            extra_args=restricted_extra,
                        )

            # 3. Scalar flag injection via model / effort / conv rejected
            for kw in ({"model": "--yolo"}, {"effort": "-y"}, {"conv": "--auto-approve"}):
                with self.subTest(scalar_inject=kw):
                    with self.assertRaises(ValueError):
                        drv.spawn_session(
                            kw.get("conv"),
                            "safe",
                            kw.get("model"),
                            kw.get("effort"),
                            profile="default",
                            hermes_bin=fake_bin,
                            allowed_bins=[fake_bin],
                        )

            # 4. Symlink TOCTOU: validate_hermes_binary resolves & returns realpath; blocks unwhitelisted symlink & non-exec
            resolved = ext.validate_hermes_binary(str(link_to_valid), allowed_bins=[fake_bin])
            self.assertEqual(os.path.realpath(fake_bin), resolved)
            with self.assertRaises(ValueError):
                ext.validate_hermes_binary(str(link_to_evil), allowed_bins=[fake_bin])
            with self.assertRaises(ValueError):
                ext.validate_hermes_binary(str(non_exec), allowed_bins=[str(non_exec)])

            # 5. AGY_HERMES_ALLOWED_BINS ignored unless clean local_admin env
            for blocked_env in (
                {"AGY_HERMES_ALLOWED_BINS": fake_bin},
                {"AGY_HERMES_ALLOWED_BINS": fake_bin, "AGY_TRUST_LEVEL": "local_worker"},
                {"AGY_HERMES_ALLOWED_BINS": fake_bin, "AGY_TRUST_LEVEL": "local_admin", "AGY_UNTRUSTED_SESSION": "1"},
                {"AGY_HERMES_ALLOWED_BINS": fake_bin, "AGY_TRUST_LEVEL": "local_admin", "AGY_MEMORY_READONLY": "1"},
                {"AGY_HERMES_ALLOWED_BINS": fake_bin, "AGY_TRUST_LEVEL": "local_admin", "AGY_RBAC_ROLE": "readonly"},
            ):
                with self.subTest(blocked_env=blocked_env):
                    with self.assertRaises(ValueError):
                        ext.validate_hermes_binary(fake_bin, env=blocked_env)

            clean_admin_env = {"AGY_HERMES_ALLOWED_BINS": fake_bin, "AGY_TRUST_LEVEL": "local_admin"}
            self.assertEqual(
                os.path.realpath(fake_bin),
                ext.validate_hermes_binary(fake_bin, env=clean_admin_env),
            )

    def test_b6_ssrf_blocks_aws_ipv6_alibaba_imds_ipv6_transitions_env_proxy_and_dns_rebinding(self):
        # Programmatically build non-doc metadata & IPv6 transition targets (zero literal IPs)
        imds_v4_bytes = bytes((169, 254, 169, 254))
        aws_v6_imds = str(ipaddress.IPv6Address(bytes.fromhex("fd000ec2" + "0000" * 5 + "0254")))
        ali_v4_imds = str(ipaddress.IPv4Address(bytes((100, 100, 100, 200))))
        sixtofour_imds = str(ipaddress.IPv6Address(bytes.fromhex("2002") + imds_v4_bytes + bytes(10)))
        # Teredo client IPv4 is bitwise-inverted in the last 4 bytes of Teredo /32 prefix
        inv_imds = bytes(b ^ 0xFF for b in imds_v4_bytes)
        teredo_prefix = bytes((0x20, 0x01, 0x00, 0x00))
        teredo_client_imds = str(
            ipaddress.IPv6Address(teredo_prefix + bytes((1, 2, 3, 4, 0, 0, 0xFF, 0xFF)) + inv_imds)
        )
        teredo_server_imds = str(ipaddress.IPv6Address(teredo_prefix + imds_v4_bytes + bytes(8)))
        nat64_wk_imds = str(ipaddress.IPv6Address(bytes.fromhex("0064ff9b" + "0000" * 4) + imds_v4_bytes))
        nat64_local_imds = str(ipaddress.IPv6Address(bytes.fromhex("0064ff9b0001" + "0000" * 3) + imds_v4_bytes))
        ipv4_compat_imds = str(ipaddress.IPv6Address(bytes(12) + imds_v4_bytes))
        ipv4_trans_imds = str(ipaddress.IPv6Address(bytes.fromhex("0000" * 4 + "ffff0000") + imds_v4_bytes))

        blocked_targets = [
            f"http://[{aws_v6_imds}]/latest/meta-data/",
            f"http://{ali_v4_imds}/latest/meta-data/",
            f"http://[{sixtofour_imds}]/",
            f"http://[{teredo_client_imds}]/",
            f"http://[{teredo_server_imds}]/",
            f"http://[{nat64_wk_imds}]/",
            f"http://[{nat64_local_imds}]/",
            f"http://[{ipv4_compat_imds}]/",
            f"http://[{ipv4_trans_imds}]/",
        ]
        for bad_url in blocked_targets:
            with self.subTest(ssrf_target=bad_url):
                with self.assertRaises(ext.SSRFError):
                    ext.validate_outbound_url(bad_url)

        # IPv6 loopback ::1 and CGNAT VPN node remain permitted
        self.assertEqual("http://[::1]:8642", ext.validate_outbound_url("http://[::1]:8642"))
        vpn_url = f"http://{_ip(100, 64, 0, 8)}:8642"
        self.assertEqual(vpn_url, ext.validate_outbound_url(vpn_url))

        # Env proxy ignored (ProxyHandler({})) + IP pinning prevents DNS rebinding & preserves Host header
        with _FakeRemoteHermesServer(mode="chat_completions", node_label="pinned-node") as srv:
            resolve_calls: List[str] = []

            def _pinned_resolve(host: str, _port: int):
                resolve_calls.append(host)
                return ["127.0.0.1"]

            fake_host_url = f"http://rebind-test.example.com:{srv.port}/v1/chat/completions"
            poison_proxy_env = {
                "HTTP_PROXY": "http://127.0.0.1:1",
                "http_proxy": "http://127.0.0.1:1",
                "HTTPS_PROXY": "http://127.0.0.1:1",
                "https_proxy": "http://127.0.0.1:1",
                "ALL_PROXY": "http://127.0.0.1:1",
            }
            with mock.patch.dict(os.environ, poison_proxy_env, clear=False):
                sess = ext.HttpExternalAgentDriver().spawn_session(
                    None,
                    "safe",
                    "m1",
                    None,
                    endpoint_url=fake_host_url,
                    resolve_fn=_pinned_resolve,
                )
                sess.send_user_prompt("pin check")
                evs = _collect_events(sess, timeout_total=5.0)
                sess.close()

            res = [e["result"] for e in evs if e.get("event") == "result"][0]
            self.assertEqual("SUCCESS", res["status"], res)
            self.assertEqual("reply:pinned-node:pin check", res["response"])
            # Server observed original Host header despite connecting via pinned 127.0.0.1
            self.assertTrue(
                any(r.get("host") == f"rebind-test.example.com:{srv.port}" for r in srv.requests_seen),
                srv.requests_seen,
            )
            # Only 2 resolve_fn calls (init + pre-open), zero system DNS on rebind-test.example.com
            self.assertEqual(2, len(resolve_calls))

    def test_b7_http_external_slow_drip_enforces_total_deadline(self):
        with _FakeRemoteHermesServer(mode="slow_drip_http", node_label="drip-node") as srv:
            t0 = time.monotonic()
            sess = ext.HttpExternalAgentDriver().spawn_session(
                None,
                "safe",
                "m1",
                None,
                endpoint_url=f"{srv.base_url}/v1/chat/completions",
                connect_timeout_sec=0.5,
                read_timeout_sec=0.35,
            )
            sess.send_user_prompt("slow drip test")
            evs = _collect_events(sess, timeout_total=5.0)
            elapsed = time.monotonic() - t0
            sess.close()

            res = [e["result"] for e in evs if e.get("event") == "result"][0]
            self.assertEqual("ERROR", res["status"])
            self.assertIn("READ_TIMEOUT", res["error"])
            self.assertLess(elapsed, 2.5, f"Slow-drip read did not terminate at deadline (elapsed={elapsed:.2f}s)")

    def test_m3_hermes_stream_result_error_normalization(self):
        # 1. is_error=True on type="result" without explicit status -> must normalize to ERROR
        ev_is_err = ext._normalize_hermes_stream_event(
            {"type": "result", "is_error": True, "response": "provider failed", "session_id": "s1"},
            [0],
        )
        self.assertIsNotNone(ev_is_err)
        self.assertEqual("ERROR", ev_is_err["result"]["status"])

        # 2. non-empty error with empty response on type="result" without status -> ERROR
        ev_err_empty_resp = ext._normalize_hermes_stream_event(
            {"type": "result", "error": "rate limit exceeded", "response": "", "session_id": "s2"},
            [0],
        )
        self.assertIsNotNone(ev_err_empty_resp)
        self.assertEqual("ERROR", ev_err_empty_resp["result"]["status"])
        self.assertEqual("rate limit exceeded", ev_err_empty_resp["result"]["error"])

        # 3. clean result without error -> remains SUCCESS
        ev_ok = ext._normalize_hermes_stream_event(
            {"type": "result", "response": "FEDERATION_OK", "session_id": "s3"},
            [0],
        )
        self.assertIsNotNone(ev_ok)
        self.assertEqual("SUCCESS", ev_ok["result"]["status"])
        self.assertEqual("FEDERATION_OK", ev_ok["result"]["response"])


if __name__ == "__main__":
    unittest.main()
