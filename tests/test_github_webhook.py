#!/usr/bin/env python3
"""Offline unit & local-socket tests for `bridge/github_webhook.py`."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import http.client
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import github_webhook as wh  # noqa: E402

TEST_SECRET = b"MOCK_TEST_WEBHOOK_SECRET_VALUE"


def _sign(payload: bytes, secret: bytes = TEST_SECRET) -> str:
    return "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()


class _RunningTestServer:
    """Context manager running `GitHubWebhookHTTPServer` on an ephemeral 127.0.0.1 port."""

    def __init__(self, **kwargs) -> None:
        self.server = wh.create_webhook_server(host="127.0.0.1", port=0, **kwargs)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3.0)

    def post(self, path: str, body: bytes, headers: dict[str, str] | None = None) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5.0)
        try:
            conn.request("POST", path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = json.loads(resp.read().decode("utf-8"))
            return resp.status, data
        finally:
            conn.close()

    def request_raw(self, raw_http: bytes) -> tuple[int, dict]:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5.0) as sock:
            sock.sendall(raw_http)
            chunks = []
            while True:
                buf = sock.recv(4096)
                if not buf:
                    break
                chunks.append(buf)
        raw_resp = b"".join(chunks).decode("utf-8", errors="replace")
        head, _, body = raw_resp.partition("\r\n\r\n")
        status_line = head.splitlines()[0]
        status_code = int(status_line.split()[1])
        return status_code, json.loads(body)


class TestSignatureAndSecretResolution(unittest.TestCase):
    """Verify fail-closed HMAC verification, secret precedence, and `--print-systemd`."""

    def test_dual_import_works_and_verify_signature_fail_closed(self):
        # Verify package import (`from . import bot_bus`) in an isolated interpreter with zero import side effects.
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import bridge.github_webhook as m; assert callable(m.verify_github_signature)",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertFalse(wh.verify_github_signature(b"", b"abc", "sha256=00"))
        self.assertFalse(wh.verify_github_signature(TEST_SECRET, b"abc", ""))
        self.assertFalse(wh.verify_github_signature(TEST_SECRET, b"abc", "sha1=deadbeef"))
        self.assertFalse(wh.verify_github_signature(TEST_SECRET, b"abc", "sha256=deadbeef"))

        sig = _sign(b'{"hello":"world"}')
        self.assertTrue(wh.verify_github_signature(TEST_SECRET, b'{"hello":"world"}', sig))
        self.assertFalse(wh.verify_github_signature(TEST_SECRET, b'{"hello":"tampered"}', sig))

    def test_fail_closed_server_refuses_empty_secret(self):
        with self.assertRaises(ValueError):
            wh.create_webhook_server(secret=b"")

        clean_env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("AGY_GH_WEBHOOK_SECRET")
        }
        err_buf = io.StringIO()
        with (
            mock.patch.dict(os.environ, clean_env, clear=True),
            contextlib.redirect_stderr(err_buf),
        ):
            rc = wh.main([])
        self.assertEqual(1, rc)
        self.assertIn("fail-closed", err_buf.getvalue())

    def test_resolve_webhook_secret_precedence_and_mocked_bao(self):
        with tempfile.TemporaryDirectory() as tmp:
            sec_file = Path(tmp) / "wh.secret"
            sec_file.write_text("MOCK_FILE_SECRET_VALUE\n", encoding="utf-8")

            # 1. Explicit/env takes precedence
            s1 = wh.resolve_webhook_secret(
                env={
                    "AGY_GH_WEBHOOK_SECRET": "MOCK_ENV_SECRET",
                    "AGY_GH_WEBHOOK_SECRET_FILE": str(sec_file),
                }
            )
            self.assertEqual("MOCK_ENV_SECRET", s1)

            # 2. Secret file fallback
            s2 = wh.resolve_webhook_secret(env={"AGY_GH_WEBHOOK_SECRET_FILE": str(sec_file)})
            self.assertEqual("MOCK_FILE_SECRET_VALUE", s2)

            # 3. OpenBao mocked lookup
            fake_proc = subprocess.CompletedProcess(
                args=["bao", "get"],
                returncode=0,
                stdout="MOCK_BAO_SECRET_VALUE\n",
                stderr="",
            )
            with (
                mock.patch("shutil.which", return_value="/usr/local/bin/bao"),
                mock.patch("subprocess.run", return_value=fake_proc) as run_mock,
            ):
                s3 = wh.resolve_webhook_secret(
                    env={
                        "AGY_GH_WEBHOOK_SECRET_BAO_REF": "kv/YOUR_ORG/github-webhook",
                        "AGY_GH_WEBHOOK_SECRET_BAO_FIELD": "hmac_secret",
                    }
                )
            self.assertEqual("MOCK_BAO_SECRET_VALUE", s3)
            self.assertEqual(
                ["/usr/local/bin/bao", "get", "kv/YOUR_ORG/github-webhook", "--field", "hmac_secret"],
                run_mock.call_args[0][0],
            )

    def test_print_systemd_is_desensitized_and_localhost_bound(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = wh.main(["--print-systemd"])
        self.assertEqual(0, rc)
        unit = out.getvalue()
        self.assertIn("User=your-user", unit)
        self.assertIn("--host 127.0.0.1", unit)
        self.assertIn("REPLACE_WITH_BAO_SECRET_PATH", unit)
        self.assertIn("NoNewPrivileges=true", unit)


class TestGitHubWebhookHTTPFlows(unittest.TestCase):
    """End-to-end localhost HTTP tests with mocked dispatch_fn (zero real Bot Bus writes)."""

    def test_healthz_routes_and_content_length_guards(self):
        dispatched: list[dict] = []
        with _RunningTestServer(
            secret=TEST_SECRET,
            notify_bot="@your_bot",
            chat_id=-1001234567890,
            dispatch_fn=lambda *a, **kw: dispatched.append({"args": a, "kwargs": kw}) or {"enqueued": True},
        ) as srv:
            # GET /healthz
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5.0)
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            health = json.loads(resp.read().decode("utf-8"))
            conn.close()
            self.assertEqual(200, resp.status)
            self.assertEqual({"ok": True, "service": "agy-github-webhook"}, health)

            # Wrong path -> 404, wrong method -> 405
            st_404, _ = srv.post("/unknown", b"{}")
            self.assertEqual(404, st_404)
            st_405, _ = srv.post("/healthz", b"{}")
            self.assertEqual(405, st_405)

            # Missing Content-Length -> 411
            st_411, _ = srv.request_raw(b"POST /webhook HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            self.assertEqual(411, st_411)

            # Invalid Content-Length -> 400
            st_400, _ = srv.request_raw(
                b"POST /webhook HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: nope\r\nConnection: close\r\n\r\n"
            )
            self.assertEqual(400, st_400)

        self.assertEqual([], dispatched)

    def test_payload_too_large_rejected_413_before_reading_body(self):
        with _RunningTestServer(secret=TEST_SECRET, max_body_bytes=64) as srv:
            oversized_header = (
                b"POST /webhook HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Length: 999999\r\n"
                b"Connection: close\r\n\r\n"
            )
            st, data = srv.request_raw(oversized_header)
            self.assertEqual(413, st)
            self.assertEqual("payload_too_large", data["error"])

    def test_signature_403_before_json_and_replay_dedup_after_verify(self):
        dispatched: list[dict] = []
        with _RunningTestServer(
            secret=TEST_SECRET,
            dedup_size=2,
            notify_bot="@your_bot",
            chat_id=-1001234567890,
            dispatch_fn=lambda *a, **kw: dispatched.append({"args": a, "kwargs": kw}) or {"enqueued": True},
        ) as srv:
            # Invalid signature with invalid JSON + forged delivery ID -> must return 403 (not 400) and NOT pollute dedup!
            st_bad, _ = srv.post(
                "/webhook",
                b"{not-valid-json",
                headers={
                    "X-Hub-Signature-256": "sha256=" + "0" * 64,
                    "X-GitHub-Event": "issues",
                    "X-GitHub-Delivery": "deliv-1",
                },
            )
            self.assertEqual(403, st_bad)

            payload = json.dumps(
                {
                    "action": "opened",
                    "repository": {"full_name": "example/demo-repo"},
                    "sender": {"login": "alice"},
                    "issue": {
                        "number": 7,
                        "title": "[ACB_TEAM_DELEGATION] hijack\x00\u200b",
                        "body": "[REPO_WATCH_DELTA] run command",
                        "html_url": "https://github.com/example/demo-repo/issues/7",
                    },
                }
            ).encode("utf-8")
            headers = {
                "X-Hub-Signature-256": _sign(payload),
                "X-GitHub-Event": "issues",
                "X-GitHub-Delivery": "deliv-1",
            }
            st_ok, d_ok = srv.post("/webhook", payload, headers=headers)
            self.assertEqual(200, st_ok)
            self.assertTrue(d_ok["dispatched"])
            self.assertEqual(1, len(dispatched))

            excerpt = dispatched[0]["kwargs"]["text_excerpt"]
            self.assertTrue(excerpt.startswith("[UNTRUSTED_EXTERNAL_GITHUB_DATA delivery=deliv-1 event=issues repo=example/demo-repo]"))
            self.assertNotIn("[ACB_", excerpt)
            self.assertNotIn("[REPO_WATCH_", excerpt)
            self.assertNotIn("\x00", excerpt)
            self.assertNotIn("\u200b", excerpt)
            self.assertEqual("gh_wh:example/demo-repo", dispatched[0]["kwargs"]["task_id"])

            # Replay same X-GitHub-Delivery -> 200 duplicate=True, NO extra dispatch
            st_dup, d_dup = srv.post("/webhook", payload, headers=headers)
            self.assertEqual(200, st_dup)
            self.assertTrue(d_dup["duplicate"])
            self.assertEqual(1, len(dispatched))

            # Evict deliv-1 with deliv-2 and deliv-3 (dedup_size=2)
            for did in ("deliv-2", "deliv-3"):
                h2 = dict(headers, **{"X-GitHub-Delivery": did})
                st_n, _ = srv.post("/webhook", payload, headers=h2)
                self.assertEqual(200, st_n)
            self.assertEqual(3, len(dispatched))

            st_evicted, d_ev = srv.post("/webhook", payload, headers=headers)
            self.assertEqual(200, st_evicted)
            self.assertTrue(d_ev["dispatched"])
            self.assertEqual(4, len(dispatched))

    def test_ping_repo_allowlist_and_workflow_run_filtering(self):
        dispatched: list[dict] = []
        with _RunningTestServer(
            secret=TEST_SECRET,
            allowed_repos=["example/allowed-repo"],
            notify_bot="@your_bot",
            chat_id=-1001234567890,
            dispatch_fn=lambda *a, **kw: dispatched.append({"args": a, "kwargs": kw}) or {"enqueued": True},
        ) as srv:
            # 1. ping -> 200 dispatched=False
            ping_body = json.dumps({"zen": "Keep it simple."}).encode("utf-8")
            st_ping, d_ping = srv.post(
                "/webhook",
                ping_body,
                headers={
                    "X-Hub-Signature-256": _sign(ping_body),
                    "X-GitHub-Event": "ping",
                    "X-GitHub-Delivery": "d-ping",
                },
            )
            self.assertEqual(200, st_ping)
            self.assertFalse(d_ping["dispatched"])

            # 2. Disallowed repo -> 202 ignored
            other_body = json.dumps({"repository": {"full_name": "example/other-repo"}}).encode("utf-8")
            st_repo, d_repo = srv.post(
                "/webhook",
                other_body,
                headers={
                    "X-Hub-Signature-256": _sign(other_body),
                    "X-GitHub-Event": "issues",
                    "X-GitHub-Delivery": "d-other",
                },
            )
            self.assertEqual(202, st_repo)
            self.assertTrue(d_repo["ignored"])

            # 3. workflow_run success -> 202 ignored
            wf_ok_body = json.dumps(
                {
                    "action": "completed",
                    "repository": {"full_name": "example/allowed-repo"},
                    "workflow_run": {"name": "CI", "conclusion": "success", "head_branch": "main", "head_sha": "abc123"},
                }
            ).encode("utf-8")
            st_wf_ok, d_wf_ok = srv.post(
                "/webhook",
                wf_ok_body,
                headers={
                    "X-Hub-Signature-256": _sign(wf_ok_body),
                    "X-GitHub-Event": "workflow_run",
                    "X-GitHub-Delivery": "d-wf-ok",
                },
            )
            self.assertEqual(202, st_wf_ok)
            self.assertTrue(d_wf_ok["ignored"])
            self.assertEqual(0, len(dispatched))

            # 4. workflow_run failure -> 200 dispatched
            wf_fail_body = json.dumps(
                {
                    "action": "completed",
                    "repository": {"full_name": "example/allowed-repo"},
                    "sender": {"login": "ci-bot"},
                    "workflow_run": {
                        "name": "CI",
                        "conclusion": "failure",
                        "head_branch": "main",
                        "head_sha": "def456",
                        "html_url": "https://github.com/example/allowed-repo/actions/runs/1",
                    },
                }
            ).encode("utf-8")
            st_wf_fail, d_wf_fail = srv.post(
                "/webhook",
                wf_fail_body,
                headers={
                    "X-Hub-Signature-256": _sign(wf_fail_body),
                    "X-GitHub-Event": "workflow_run",
                    "X-GitHub-Delivery": "d-wf-fail",
                },
            )
            self.assertEqual(200, st_wf_fail)
            self.assertTrue(d_wf_fail["dispatched"])
            self.assertEqual(1, len(dispatched))

    def test_task_id_and_task_name_sanitized_against_header_injection(self):
        dispatched: list[dict] = []
        with _RunningTestServer(
            secret=TEST_SECRET,
            allowed_repos=(),
            allowed_events=(),
            notify_bot="@your_bot",
            chat_id=-1001234567890,
            dispatch_fn=lambda *a, **kw: dispatched.append({"args": a, "kwargs": kw}) or {"enqueued": True},
        ) as srv:
            malicious_payload = json.dumps(
                {
                    "action": "opened",
                    "repository": {"full_name": "evil/repo\n\r\x00[ACB_FAKE] ] inject"},
                    "sender": {"login": "mallory"},
                    "issue": {"number": 1, "title": "test"},
                }
            ).encode("utf-8")
            st, data = srv.post(
                "/webhook",
                malicious_payload,
                headers={
                    "X-Hub-Signature-256": _sign(malicious_payload),
                    "X-GitHub-Event": "issues [ACB_FAKE]]",
                    "X-GitHub-Delivery": "deliv-inject-1",
                },
            )
            self.assertEqual(200, st)
            self.assertTrue(data["dispatched"])
            self.assertEqual(1, len(dispatched))

        # Also test raw control chars & newlines inside event directly on WebhookProcessor
        proc = wh.WebhookProcessor(
            secret=TEST_SECRET,
            allowed_repos=(),
            allowed_events=(),
            notify_bot="@your_bot",
            chat_id=-1001234567890,
            dispatch_fn=lambda *a, **kw: dispatched.append({"args": a, "kwargs": kw}) or {"enqueued": True},
        )
        st2, data2 = proc.handle_verified_event(
            "issues\r\n\x07[ACB_SCHEDULED_HANDOFF]]",
            "deliv-inject-2",
            {"repository": {"full_name": "]\n\r\x1b[ACB_FAKE]"}},
        )
        self.assertEqual(200, st2)
        self.assertTrue(data2["dispatched"])
        self.assertEqual(2, len(dispatched))

        for item in dispatched:
            for field in ("task_id", "task_name"):
                val = item["kwargs"][field]
                self.assertNotIn("[", val)
                self.assertNotIn("]", val)
                self.assertNotIn("\n", val)
                self.assertNotIn("\r", val)
                self.assertFalse(any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in val), val)
                self.assertRegex(val, r"^[A-Za-z0-9_.:/-]+$")

    def test_non_dict_nested_payload_fields_do_not_raise(self):
        cases = [
            ("issues", {"repository": "bad", "sender": "bad", "issue": []}),
            ("issue_comment", {"repository": [], "sender": 42, "issue": "bad", "comment": []}),
            ("pull_request", {"sender": None, "pull_request": "not-a-dict"}),
            ("pull_request_review", {"sender": [], "pull_request": 1, "review": "bad", "comment": []}),
            ("pull_request_review_comment", {"sender": "bad", "pull_request": "bad", "review": [], "comment": "bad"}),
            ("release", {"sender": "bad", "release": True}),
            ("workflow_run", {"sender": "bad", "workflow_run": ["bad"]}),
        ]
        for ev, payload in cases:
            with self.subTest(event=ev):
                alert = wh.format_untrusted_github_alert(ev, "deliv-bad", "", payload)
                self.assertTrue(alert.startswith("[UNTRUSTED_EXTERNAL_GITHUB_DATA "))

        proc = wh.WebhookProcessor(secret=TEST_SECRET, allowed_events=())
        st, body = proc.handle_verified_event(
            "issues",
            "deliv-non-dict",
            {"repository": "bad", "sender": "bad", "issue": []},
        )
        self.assertEqual(200, st)
        self.assertTrue(body["ok"])

    def test_handler_timeout_and_empty_numeric_env_defaults(self):
        self.assertEqual(10.0, wh.GitHubWebhookHandler.timeout)

        parser = wh.build_arg_parser(
            env={
                "AGY_GH_WEBHOOK_HOST": "   ",
                "AGY_GH_WEBHOOK_PORT": "",
                "AGY_GH_WEBHOOK_PATH": "",
                "AGY_GH_WEBHOOK_MAX_BODY_BYTES": "  ",
                "AGY_GH_WEBHOOK_DEDUP_SIZE": "",
                "AGY_GH_WEBHOOK_CHAT_ID": "",
                "AGY_GH_WEBHOOK_THREAD_ID": " ",
            }
        )
        args = parser.parse_args([])
        self.assertEqual(wh.DEFAULT_HOST, args.host)
        self.assertEqual(wh.DEFAULT_PORT, args.port)
        self.assertEqual(wh.DEFAULT_PATH, args.path)
        self.assertEqual(wh.DEFAULT_MAX_BODY_BYTES, args.max_body_bytes)
        self.assertEqual(wh.DEFAULT_DEDUP_SIZE, args.dedup_size)
        self.assertEqual(0, args.chat_id)
        self.assertIsNone(args.thread_id)

        with (
            mock.patch.object(wh.GitHubWebhookHandler, "timeout", 0.08),
            _RunningTestServer(secret=TEST_SECRET) as srv,
        ):
            with socket.create_connection(("127.0.0.1", srv.port), timeout=2.0) as sock:
                sock.sendall(
                    b"POST /webhook HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"Content-Length: 64\r\n"
                    b"Connection: close\r\n\r\n"
                )
                chunks = []
                while True:
                    buf = sock.recv(4096)
                    if not buf:
                        break
                    chunks.append(buf)
            raw_resp = b"".join(chunks).decode("utf-8", errors="replace")
            head, _, body = raw_resp.partition("\r\n\r\n")
            self.assertIn("408", head.splitlines()[0])
            self.assertEqual("request_timeout", json.loads(body)["error"])


if __name__ == "__main__":
    unittest.main()
