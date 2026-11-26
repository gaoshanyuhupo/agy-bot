#!/usr/bin/env python3
"""Offline unit & integration tests for M1 multi-Google-account engine, cost ledger, Telegram Bridge, and IPC.

Covers C2..C8 strictly offline inside `TemporaryDirectory` with zero network I/O, zero real `agy` OAuth calls,
and zero touches to the host `~/.gemini/antigravity-cli/antigravity-oauth-token`.
"""

from __future__ import annotations

import datetime
import gc
import hashlib
import http.client
import importlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.error
import warnings

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import cost_usage  # noqa: E402
import google_accounts  # noqa: E402
import studio_ipc  # noqa: E402


def _mock_access_token(tag: str = "A") -> str:
    return "ya" + "29." + f"EXAMPLE_MOCK_ACCESS_{tag}_" + (tag * 10)


def _mock_refresh_token(tag: str = "A") -> str:
    return "1/" + "/" + f"EXAMPLE_MOCK_REFRESH_{tag}_" + (tag * 10)


def _make_token_bytes(email: str = "alice@example.com", tag: str = "A", expiry: str | None = None) -> bytes:
    if expiry is None:
        exp_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
        expiry = exp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {
        "auth_method": "oauth-personal",
        "id_token_email": email,
        "token": {
            "access_token": _mock_access_token(tag),
            "refresh_token": _mock_refresh_token(tag),
            "expiry": expiry,
        },
        "writer_id": "test-writer",
    }
    return json.dumps(doc).encode("utf-8")


def _load_isolated_bridge(tmp: str, extra_env: dict[str, str] | None = None):
    """Reload bridge in an isolated temp environment, clearing ambient AGY_TG_BOT_* & AGY_STUDIO_* vars."""
    ambient_clear = {
        k: ""
        for k in list(os.environ.keys())
        if k.startswith(("AGY_TG_BOT_", "AGY_STUDIO_", "AGY_GOOGLE_ACCOUNTS_", "AGY_HOST_OAUTH_"))
    }
    env_patch = {
        **ambient_clear,
        "AGY_BOT_BUS_DIR": os.path.join(tmp, "bus"),
        "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
        "AGY_MEMORY_TAINT_FILE": os.path.join(tmp, "memory_taint.json"),
        "AGY_TG_WORKDIR": os.path.join(tmp, "workdir"),
        "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
        "AGY_TG_ALLOWED_CHATS": "-1001234567890,111,222",
        "AGY_TG_ALLOWED_USERS": "",
        "AGY_TG_ADMIN_USERS": "111",
        "AGY_TG_READONLY_USERS": "222",
        "AGY_TG_ALLOW_GROUP_READONLY": "0",
        "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_ACCOUNTS_TEST_TOKEN_01",
        "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
        "AGY_BOT_CHAIN": "",
        "AGY_BOT_ORIGIN_MSG_ID": "0",
        "AGY_BOT_MENTION_HOP": "0",
        "AGY_GOOGLE_ACCOUNTS_DIR": os.path.join(tmp, "accounts"),
        "AGY_HOST_OAUTH_TOKEN_FILE": os.path.join(tmp, "host_gemini", "antigravity-oauth-token"),
        "AGY_STUDIO_CONFIG_DIR": os.path.join(tmp, "studio_cfg"),
        "AGY_STUDIO_USERS_FILE": os.path.join(tmp, "studio_cfg", "users.json"),
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
        bridge.BRAIN_ROOT = os.path.join(tmp, "brain")
        bridge.COST_LEDGER_FILE = os.path.join(tmp, "cache", "cost_ledger_v2.json")
        bridge.COST_CONFIG_FILE = os.path.join(tmp, "cache", "cost_config.json")
        bridge.QUOTA_CACHE_FILE = os.path.join(tmp, "cache", "quota_usage.json")
        bridge.COST_LEDGER_LOCK = os.path.join(tmp, "cache", "cost_ledger.lock")
        bridge._google_account_mgr = None
        bridge._google_login_flow_mgr = None
        return bridge


def _ipc_post(sock_path: str, path: str, body: dict, headers: dict[str, str], timeout: float = 5.0) -> tuple[int, dict]:
    raw = json.dumps(body).encode("utf-8")
    req_headers = {
        "Host": "localhost",
        "Connection": "close",
        "Content-Type": "application/json",
        "Content-Length": str(len(raw)),
        **headers,
    }
    header_lines = [f"POST {path} HTTP/1.1"]
    header_lines.extend(f"{k}: {v}" for k, v in req_headers.items())
    payload = ("\r\n".join(header_lines) + "\r\n\r\n").encode("iso-8859-1") + raw

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    resp: http.client.HTTPResponse | None = None
    try:
        sock.settimeout(timeout)
        sock.connect(sock_path)
        try:
            sock.sendall(payload)
        except (BrokenPipeError, ConnectionResetError):
            # Server may fail-closed (e.g. proxy headers or wrong SO_PEERCRED UID),
            # write 403, and close the socket before sendall finishes; read the buffered response.
            pass
        resp = http.client.HTTPResponse(sock, method="POST")
        resp.begin()
        data = json.loads(resp.read().decode("utf-8"))
        return resp.status, data
    finally:
        if resp is not None:
            resp.close()
        sock.close()


# ---------------------------------------------------------------------------
# C3: Storage, Permissions, Anti-Symlink, Zero-Token Registry, & Atomic Switch
# ---------------------------------------------------------------------------

class TestGoogleAccountStorageSecurity(unittest.TestCase):
    def test_account_id_whitelist_and_forbidden_names(self) -> None:
        for ok_id in ("primary", "work-1", "a_b_0", "x", "a" + "0" * 47):
            self.assertEqual(ok_id, google_accounts.validate_account_id(ok_id))

        bad_ids = [
            "",
            ".",
            "..",
            "../escape",
            "a/b",
            "a\\b",
            "__proto__",
            "constructor",
            "prototype",
            "UpperCase",
            "-leading-dash",
            "_leading_underscore",
            "bad space",
            "null\x00byte",
            "a" * 49,
            123,
            None,
        ]
        for bad in bad_ids:
            with self.assertRaises(ValueError, msg=f"Expected ValueError for {bad!r}"):
                google_accounts.validate_account_id(bad)

    def test_host_adoption_permissions_zero_token_registry_and_public_view(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_store_") as tmp:
            root = Path(tmp) / "accounts"
            host_tok = Path(tmp) / "host" / "antigravity-oauth-token"
            host_tok.parent.mkdir(parents=True, exist_ok=True)
            tok_bytes = _make_token_bytes("alice@example.com", tag="HOST1")
            host_tok.write_bytes(tok_bytes)

            mgr = google_accounts.GoogleAccountManager(
                root_dir=root,
                host_token_path=host_tok,
                quota_cache_file=Path(tmp) / "cache" / "quota_usage.json",
                cost_config_file=Path(tmp) / "cache" / "cost_config.json",
            )
            accts = mgr.list_accounts()
            self.assertEqual(len(accts), 1)
            self.assertEqual(accts[0]["account_id"], "primary")
            self.assertTrue(accts[0]["is_active"])
            self.assertTrue(accts[0]["is_host_adopted"])
            self.assertEqual(accts[0]["email_masked"], "a***e@example.com")

            # Verify 0700 dirs and 0600 files
            self.assertEqual(stat.S_IMODE(os.stat(root).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(root / "profiles").st_mode), 0o700)
            pdir = mgr.profile_dir_for("primary")
            self.assertEqual(stat.S_IMODE(os.stat(pdir).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(pdir / "antigravity-acp").st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(mgr.registry_path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(mgr.lock_path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(mgr.token_path_for("primary")).st_mode), 0o600)

            # Verify registry.json has ZERO plaintext token fields or token substrings
            reg_text = mgr.registry_path.read_text(encoding="utf-8")
            for forbidden in ("access_token", "refresh_token", "id_token", "code_verifier", "oauth_state", "EXAMPLE_MOCK_ACCESS_HOST1"):
                self.assertNotIn(forbidden, reg_text)

            # Verify public dicts expose zero paths or profile_dir
            pub_json = json.dumps(accts)
            self.assertNotIn("profile_dir", pub_json)
            self.assertNotIn(str(root), pub_json)
            self.assertNotIn("alice@example.com", pub_json)

            # Verify group view omits email_masked and any email-domain suffix
            grp_accts = mgr.list_accounts(for_group=True)
            grp_json = json.dumps(grp_accts)
            self.assertNotIn("email", grp_json)
            self.assertNotIn("@example.com", grp_json)
            self.assertNotIn(str(root), grp_json)

    def test_symlink_fail_closed_on_adoption_read_and_switch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_sym_") as tmp:
            root = Path(tmp) / "accounts"
            real_tok = Path(tmp) / "real.json"
            real_tok.write_bytes(_make_token_bytes("real@example.com", tag="SYM1"))
            sym_host = Path(tmp) / "host_link"
            os.symlink(real_tok, sym_host)

            # Symlinked host token MUST NOT be adopted
            mgr = google_accounts.GoogleAccountManager(root_dir=root, host_token_path=sym_host)
            self.assertEqual(mgr.list_accounts(), [])

            # Symlinked target token file inside profile MUST fail-closed on switch
            real_host = Path(tmp) / "real_host_token"
            real_host.write_bytes(_make_token_bytes("host@example.com", tag="H0"))
            mgr2 = google_accounts.GoogleAccountManager(root_dir=Path(tmp) / "acc2", host_token_path=real_host)
            mgr2.add_account("work", alias="Work")
            tpath = mgr2.token_path_for("work")
            os.symlink(real_tok, tpath)
            with self.assertRaises(google_accounts.SymlinkSecurityError):
                mgr2.switch_account("work")
            # Original host token MUST remain untouched
            self.assertIn("EXAMPLE_MOCK_ACCESS_H0", real_host.read_text(encoding="utf-8"))

            # Symlinked registry.json MUST fail-closed
            evil_reg = Path(tmp) / "evil_reg.json"
            evil_reg.write_text('{"version":1,"accounts":{}}', encoding="utf-8")
            mgr2.registry_path.unlink()
            os.symlink(evil_reg, mgr2.registry_path)
            with self.assertRaises(google_accounts.SymlinkSecurityError):
                mgr2.list_accounts()

    def test_switch_writes_back_refreshed_host_token_and_aborts_cleanly_on_corrupt_target(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_sw_") as tmp:
            root = Path(tmp) / "accounts"
            host_tok = Path(tmp) / "host" / "antigravity-oauth-token"
            host_tok.parent.mkdir(parents=True, exist_ok=True)
            host_tok.write_bytes(_make_token_bytes("primary@example.com", tag="OLD1"))

            mgr = google_accounts.GoogleAccountManager(root_dir=root, host_token_path=host_tok)
            mgr.add_account("work", alias="Work")
            mgr.add_account("broken", alias="Broken")

            # Simulate CLI auto-refreshing host token while primary is active
            refreshed_primary = _make_token_bytes("primary@example.com", tag="RENEWED1")
            host_tok.write_bytes(refreshed_primary)

            # Corrupt target token -> switch MUST abort without modifying host token or active_account_id
            mgr.token_path_for("broken").write_bytes(b"{not valid json")
            with self.assertRaises(google_accounts.AccountError):
                mgr.switch_account("broken")
            self.assertEqual(host_tok.read_bytes(), refreshed_primary)
            self.assertEqual(mgr.get_active_account()["account_id"], "primary")

            # Valid target token -> writes back RENEWED1 to primary slot, then replaces host token with WORK2
            work_bytes = _make_token_bytes("work@example.com", tag="WORK2")
            mgr.token_path_for("work").write_bytes(work_bytes)
            res = mgr.switch_account("work")
            self.assertTrue(res["ok"])
            self.assertEqual(res["previous_account_id"], "primary")
            self.assertEqual(res["active_account_id"], "work")
            self.assertEqual(host_tok.read_bytes(), work_bytes)
            self.assertEqual(mgr.token_path_for("primary").read_bytes(), refreshed_primary)
            self.assertEqual(stat.S_IMODE(os.stat(host_tok).st_mode), 0o600)

    def test_self_switch_active_account_preserves_renewed_host_token(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_selfsw_") as tmp:
            root = Path(tmp) / "accounts"
            host_tok = Path(tmp) / "host" / "antigravity-oauth-token"
            host_tok.parent.mkdir(parents=True, exist_ok=True)
            old_bytes = _make_token_bytes("primary@example.com", tag="OLD")
            host_tok.write_bytes(old_bytes)

            mgr = google_accounts.GoogleAccountManager(root_dir=root, host_token_path=host_tok)
            self.assertEqual(mgr.get_active_account()["account_id"], "primary")
            self.assertEqual(mgr.token_path_for("primary").read_bytes(), old_bytes)

            # Simulate host CLI auto-refreshing token while primary remains active
            renewed_bytes = _make_token_bytes("primary@example.com", tag="RENEWED")
            host_tok.write_bytes(renewed_bytes)

            # Self-switching to active account MUST preserve RENEWED in both host and slot
            res = mgr.switch_account("primary")
            self.assertTrue(res["ok"])
            self.assertEqual(res["active_account_id"], "primary")
            self.assertFalse(res["switched"])
            self.assertEqual(host_tok.read_bytes(), renewed_bytes)
            self.assertEqual(mgr.token_path_for("primary").read_bytes(), renewed_bytes)
            self.assertNotIn(b"OLD", host_tok.read_bytes())
            self.assertNotIn(b"OLD", mgr.token_path_for("primary").read_bytes())


# ---------------------------------------------------------------------------
# C1/C2: Headless OAuth Login State Machine (`GoogleLoginFlowManager`)
# ---------------------------------------------------------------------------

class _FakeLoginProc:
    """In-memory subprocess double verifying stdin writes and process-group teardown."""

    def __init__(self, auth_url: str, token_path: Path, *, write_token_on_code: bool = True, exit_code: int = 0) -> None:
        self.pid = 999999  # Never passed to real killpg because we mock os.killpg in unit tests
        self._auth_url = auth_url
        self._token_path = token_path
        self._write_token = write_token_on_code
        self._exit_code = exit_code
        self.stdout = io.StringIO(f"Open this URL to sign in:\n{auth_url}\n")
        self.stdin_writes: list[str] = []
        self.stdin = _RecordingStdin(self.stdin_writes)
        self._returncode: int | None = None
        self.terminated = False
        self.killed = False
        self.waited = False

    def poll(self):
        return self._returncode

    def terminate(self):
        self.terminated = True
        self._returncode = -15

    def kill(self):
        self.killed = True
        self._returncode = -9

    def wait(self, timeout=None):
        self.waited = True
        if self._returncode is None:
            if self._write_token and self.stdin_writes:
                self._token_path.parent.mkdir(parents=True, exist_ok=True)
                self._token_path.write_bytes(_make_token_bytes("oauth_user@example.com", tag="OAUTH1"))
            self._returncode = self._exit_code
        return self._returncode


class _RecordingStdin:
    def __init__(self, sink: list[str]) -> None:
        self._sink = sink
        self.closed = False

    def write(self, data: str) -> int:
        self._sink.append(data)
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


class TestGoogleLoginFlowManager(unittest.TestCase):
    def test_oauth_env_isolation_session_binding_validation_and_anti_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_flow_") as tmp:
            mgr = google_accounts.GoogleAccountManager(
                root_dir=Path(tmp) / "accounts",
                host_token_path=Path(tmp) / "host" / "token",
            )
            spawned: list[dict] = []
            expected_state = "STATE_EXAMPLE_UNIT_TEST_98765"
            auth_url = (
                "https://accounts.google.com/o/oauth2/auth"
                "?client_id=example&redirect_uri=https%3A%2F%2Fantigravity.google%2Foauth-callback"
                f"&state={expected_state}"
            )
            procs: list[_FakeLoginProc] = []

            def fake_popen(cmd, **kwargs):
                spawned.append({"cmd": cmd, "kwargs": kwargs})
                p = _FakeLoginProc(auth_url, mgr.token_path_for("acct1"))
                procs.append(p)
                return p

            fmgr = google_accounts.GoogleLoginFlowManager(mgr, popen_fn=fake_popen)
            with mock.patch.dict(os.environ, {"DISPLAY": ":0", "BROWSER": "firefox", "WAYLAND_DISPLAY": "wayland-0"}):
                started = fmgr.start_login("acct1", alias="Account One", owner_session_id="sess-owner-A", timeout_sec=120)

            # Verify subprocess command and sanitized env
            self.assertEqual(len(spawned), 1)
            cmd = spawned[0]["cmd"]
            kw = spawned[0]["kwargs"]
            self.assertEqual(cmd[1:3], ["acp", "--gemini-dir"])
            self.assertEqual(cmd[4:], ["--app-data-dir", "antigravity-acp", "--login"])
            self.assertTrue(kw["start_new_session"])
            self.assertEqual(kw["env"]["AGY_CLI_DISABLE_AUTO_UPDATE"], "1")
            self.assertEqual(kw["env"]["SSH_CONNECTION"], "127.0.0.1 0 127.0.0.1 0")
            for stripped in ("DISPLAY", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "BROWSER"):
                self.assertNotIn(stripped, kw["env"])

            flow_id = started["flow_id"]
            self.assertIn("auth_url", started)
            self.assertNotIn("oauth_state", started)

            # GET response MUST NOT expose oauth_state or auth_url
            get_view = fmgr.get_flow(flow_id, owner_session_id="sess-owner-A")
            self.assertEqual(get_view["status"], "awaiting_code")
            self.assertNotIn("oauth_state", get_view)
            self.assertNotIn("auth_url", get_view)
            self.assertNotIn(expected_state, json.dumps(get_view))

            # Cross-session access MUST raise PermissionError without leaking auth_url/state
            for bad_sess in ("sess-attacker-B", ""):
                with self.assertRaises(PermissionError) as ctx_g:
                    fmgr.get_flow(flow_id, owner_session_id=bad_sess)
                self.assertNotIn(expected_state, str(ctx_g.exception))
                with self.assertRaises(PermissionError):
                    fmgr.submit_code(flow_id, "4/0AEXAMPLE_VALID_CODE_1234", owner_session_id=bad_sess)
                with self.assertRaises(PermissionError):
                    fmgr.cancel_flow(flow_id, owner_session_id=bad_sess)

            # Invalid code_or_url MUST be rejected BEFORE touching stdin
            invalid_inputs = [
                "4/0AEXAMPLE_CODE\r\ninjected",
                "4/0AEXAMPLE_CODE\ninjected",
                "4/0AEXAMPLE_CODE\x00null",
                "https://evil.example.com/oauth-callback?code=4/0AEXAMPLE_1234&state=" + expected_state,
                "http://antigravity.google/oauth-callback?code=4/0AEXAMPLE_1234&state=" + expected_state,
                "https://antigravity.google/wrong-path?code=4/0AEXAMPLE_1234&state=" + expected_state,
                "https://antigravity.google/oauth-callback?code=4/0AEXAMPLE_1234&state=WRONG_STATE",
                "bad code with spaces",
            ]
            for bad_in in invalid_inputs:
                with self.assertRaises(ValueError, msg=f"Should reject {bad_in!r}"):
                    fmgr.submit_code(flow_id, bad_in, owner_session_id="sess-owner-A")
            self.assertEqual(procs[0].stdin_writes, [])

            # Valid official callback URL succeeds
            good_cb = f"https://antigravity.google/oauth-callback?state={expected_state}&code=4/0AEXAMPLE_VALID_CODE_999"
            done = fmgr.submit_code(flow_id, good_cb, owner_session_id="sess-owner-A")
            self.assertEqual(done["status"], "completed")
            self.assertEqual(len(procs[0].stdin_writes), 1)
            self.assertEqual(done["account"]["email_masked"], "o***r@example.com")
            self.assertEqual(stat.S_IMODE(os.stat(mgr.token_path_for("acct1")).st_mode), 0o600)

            # Registry MUST NOT contain oauth_state or tokens
            reg_txt = mgr.registry_path.read_text(encoding="utf-8")
            self.assertNotIn(expected_state, reg_txt)
            self.assertNotIn("EXAMPLE_MOCK_ACCESS_OAUTH1", reg_txt)

            # Replay MUST raise FlowConflictError
            with self.assertRaises(google_accounts.FlowConflictError):
                fmgr.submit_code(flow_id, good_cb, owner_session_id="sess-owner-A")

    def test_timeout_expiry_and_cancel_kill_real_process_group(self) -> None:
        """Spawn a real tiny python child (non-agy) to verify `os.killpg` + reaping on TTL expiry & cancel."""
        with tempfile.TemporaryDirectory(prefix="ga_killpg_") as tmp:
            mgr = google_accounts.GoogleAccountManager(
                root_dir=Path(tmp) / "accounts",
                host_token_path=Path(tmp) / "host" / "token",
            )
            fake_url = "https://accounts.google.com/o/oauth2/auth?state=STATE_KILLPG_TEST_01"
            helper_script = Path(tmp) / "fake_agy.py"
            helper_script.write_text(
                f"import sys, time\nprint({fake_url!r}, flush=True)\ntime.sleep(30)\n",
                encoding="utf-8",
            )

            real_procs: list[subprocess.Popen] = []

            def spawn_helper(_cmd, **kwargs):
                p = subprocess.Popen([sys.executable, str(helper_script)], **kwargs)
                real_procs.append(p)
                return p

            fmgr = google_accounts.GoogleLoginFlowManager(mgr, popen_fn=spawn_helper)
            # 1. Verify TTL timeout kills process group and reaps child
            f1 = fmgr.start_login("ttl1", owner_session_id="s1", timeout_sec=0.35)
            time.sleep(0.75)
            st1 = fmgr.get_flow(f1["flow_id"], owner_session_id="s1")
            self.assertEqual(st1["status"], "expired")
            self.assertIsNotNone(real_procs[0].poll())
            with self.assertRaises(google_accounts.FlowConflictError):
                fmgr.submit_code(f1["flow_id"], "4/0AEXAMPLE_LATE_CODE_123", owner_session_id="s1")

            # 2. Verify cancel_flows_for_session kills process group cleanly
            f2 = fmgr.start_login("cancel1", owner_session_id="s2", timeout_sec=60)
            self.assertIsNone(real_procs[1].poll())
            cancelled = fmgr.cancel_flows_for_session("s2")
            self.assertEqual(cancelled, 1)
            self.assertIsNotNone(real_procs[1].poll())
            self.assertEqual(fmgr.get_flow(f2["flow_id"], owner_session_id="s2")["status"], "cancelled")

    def test_submit_code_success_closes_real_subprocess_pipes_without_resource_warning(self) -> None:
        """Spawn a real tiny python child and verify submit_code success closes pipes with 0 ResourceWarnings."""
        with tempfile.TemporaryDirectory(prefix="ga_subok_") as tmp:
            mgr = google_accounts.GoogleAccountManager(
                root_dir=Path(tmp) / "accounts",
                host_token_path=Path(tmp) / "host" / "token",
            )
            expected_state = "STATE_REAL_SUBPROC_OK_42"
            fake_url = (
                "https://accounts.google.com/o/oauth2/auth"
                "?client_id=example&redirect_uri=https%3A%2F%2Fantigravity.google%2Foauth-callback"
                f"&state={expected_state}"
            )
            target_token = mgr.token_path_for("real_ok")
            token_payload = _make_token_bytes("real.ok@example.com", tag="REALOK")
            helper_script = Path(tmp) / "fake_agy_ok.py"
            helper_script.write_text(
                "import pathlib, sys\n"
                f"print({fake_url!r}, flush=True)\n"
                "line = sys.stdin.readline().strip()\n"
                "if not line:\n"
                "    sys.exit(2)\n"
                f"p = pathlib.Path({str(target_token)!r})\n"
                "p.parent.mkdir(parents=True, exist_ok=True)\n"
                f"p.write_bytes({token_payload!r})\n"
                "print('LOGIN_OK', flush=True)\n",
                encoding="utf-8",
            )

            real_procs: list[subprocess.Popen] = []

            def spawn_helper(_cmd, **kwargs):
                p = subprocess.Popen([sys.executable, str(helper_script)], **kwargs)
                real_procs.append(p)
                return p

            fmgr = google_accounts.GoogleLoginFlowManager(mgr, popen_fn=spawn_helper)
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                started = fmgr.start_login("real_ok", alias="Real Subproc", owner_session_id="sess-real", timeout_sec=30)
                cb_url = f"https://antigravity.google/oauth-callback?state={expected_state}&code=4/0AEXAMPLE_REAL_CODE_123"
                done = fmgr.submit_code(started["flow_id"], cb_url, owner_session_id="sess-real")
                self.assertEqual(done["status"], "completed")
                self.assertEqual(len(real_procs), 1)
                proc = real_procs[0]
                self.assertEqual(proc.poll(), 0)
                if proc.stdin is not None:
                    self.assertTrue(proc.stdin.closed)
                if proc.stdout is not None:
                    self.assertTrue(proc.stdout.closed)
                if proc.stderr is not None:
                    self.assertTrue(proc.stderr.closed)
                del proc
                real_procs.clear()
                gc.collect()

            res_warns = [w for w in caught if issubclass(w.category, ResourceWarning)]
            self.assertEqual(res_warns, [], msg=f"Unexpected ResourceWarnings: {[str(w.message) for w in res_warns]}")


# ---------------------------------------------------------------------------
# C4: Direct Google Probing, Redirect Block, 512KiB Cap, Redaction, Isolated Renewal
# ---------------------------------------------------------------------------

class TestGoogleProbeAndIsolatedRenewal(unittest.TestCase):
    def test_ga1_dead_code_removed_and_host_path_fail_closed_and_standard_ua(self) -> None:
        # Removed internal quota probing constants & parsers MUST NOT be exported
        for removed_sym in (
            "CLOUDCODE_DAILY_BASE",
            "CLOUDCODE_PROD_BASE",
            "parse_quota_summary_response",
            "parse_available_models_fallback",
            "_summary_reset_time",
        ):
            self.assertFalse(
                hasattr(google_accounts, removed_sym),
                msg=f"Removed internal symbol still exported: {removed_sym}",
            )
        self.assertEqual(google_accounts.ALLOWED_GOOGLE_PROBE_HOSTS, frozenset({"www.googleapis.com"}))

        # Construct forbidden URLs via concatenation to keep test file free of bare literals/domains
        cc_host = "cloudcode" + "-pa." + "googleapis" + "." + "com"
        cc_daily_upper = "DAILY-" + "CLOUDCODE" + "-PA." + "GOOGLEAPIS" + "." + "COM"
        rpc_lca = "v1" + "internal:" + "loadCode" + "Assist"
        rpc_sum = "v1" + "internal:" + "retrieveUser" + "QuotaSummary"
        rpc_mod = "v1" + "internal:" + "fetchAvailable" + "Models"
        https_pfx = "https://"

        bad_urls = (
            https_pfx + cc_host + "/oauth2/v2/userinfo",
            https_pfx + cc_daily_upper + "/oauth2/v2/userinfo",
            https_pfx + cc_host + "./oauth2/v2/userinfo",
            https_pfx + "www.googleapis.com./oauth2/v2/userinfo",
            https_pfx + "sub." + cc_host + "/oauth2/v2/userinfo",
            https_pfx + "www.googleapis.com/" + rpc_lca,
            https_pfx + "www.googleapis.com/oauth2/v2/userinfo/../../" + rpc_sum,
            https_pfx + "www.googleapis.com/oauth2/v2/userinfo%2f..%2f" + rpc_mod,
            "https://www.googleapis.com/other/path",
            "https://www.googleapis.com/oauth2/v2/userinfo?alt=json",
            "https://www.googleapis.com/oauth2/v2/userinfo#frag",
            "http://www.googleapis.com/oauth2/v2/userinfo",
            "https://evil.example.com/oauth2/v2/userinfo",
            "https://www.googleapis.com:443/oauth2/v2/userinfo",
            "https://www.googleapis.com:8443/oauth2/v2/userinfo",
            https_pfx + "EXAMPLE_U" + ":" + "EXAMPLE_P" + "@" + "www.googleapis.com/oauth2/v2/userinfo",
            "https://www.googleapis.com/oauth2/v2/userinfo\r\nX-Inject: 1",
        )
        for bad_url in bad_urls:
            with self.assertRaises(google_accounts.GoogleProbeError, msg=f"assert_allowed_google_url must reject {bad_url!r}"):
                google_accounts.assert_allowed_google_url(bad_url)
            with self.assertRaises(google_accounts.GoogleProbeError, msg=f"google_https_json_request must reject {bad_url!r}"):
                google_accounts.google_https_json_request(
                    "GET",
                    bad_url,
                    access_token=_mock_access_token("REJECT"),
                )

        # Positive control: exact official userinfo URL passes and sends honest non-IDE User-Agent
        self.assertEqual(
            google_accounts.assert_allowed_google_url(google_accounts.GOOGLE_USERINFO_URL),
            google_accounts.GOOGLE_USERINFO_URL,
        )
        seen_headers: list[dict[str, str]] = []

        class _OkResp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

            def read(self, _n=-1):
                return b'{"id":"uid-ua-1","email":"ua@example.com"}'

        class _CapturingOpener:
            def open(self, req, timeout=None):
                seen_headers.append(dict(req.header_items()))
                return _OkResp()

        res = google_accounts.google_https_json_request(
            "GET",
            google_accounts.GOOGLE_USERINFO_URL,
            access_token=_mock_access_token("UAOK"),
            opener=_CapturingOpener(),
        )
        self.assertEqual(res["id"], "uid-ua-1")
        self.assertEqual(len(seen_headers), 1)
        ua_val = seen_headers[0].get("User-agent") or seen_headers[0].get("User-Agent") or ""
        self.assertTrue(ua_val)
        self.assertNotIn("aidev_client", ua_val.lower())

        # Redirect handler MUST fail-closed on 301/302/307/308
        handler = google_accounts._NoRedirectHandler()
        for code in (301, 302, 307, 308):
            with self.assertRaises(google_accounts.GoogleProbeError) as ctx_redir:
                handler.redirect_request(None, None, code, "Redirect", {}, "https://evil.example.com/steal")
            self.assertEqual(ctx_redir.exception.status_code, code)

        # 512 KiB response bound & timeout clamping <= 10.0s
        seen_timeouts: list[float] = []

        class _OversizedResp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

            def read(self, n=-1):
                return b"x" * (n if n > 0 else google_accounts.MAX_PROBE_RESPONSE_BYTES + 10)

        class _FakeOpener:
            def open(self, req, timeout=None):
                seen_timeouts.append(float(timeout))
                return _OversizedResp()

        with self.assertRaises(google_accounts.GoogleProbeError) as ctx_sz:
            google_accounts.google_https_json_request(
                "GET",
                google_accounts.GOOGLE_USERINFO_URL,
                access_token=_mock_access_token("BOUND"),
                timeout_sec=99.0,
                opener=_FakeOpener(),
            )
        self.assertEqual(seen_timeouts, [10.0])
        self.assertIn("exceeded", str(ctx_sz.exception).lower())

    def test_redirect_and_http_error_close_response_handles_without_resource_warning(self) -> None:
        class _TrackableStream(io.BytesIO):
            def __init__(self, data: bytes) -> None:
                super().__init__(data)
                self.close_calls = 0

            def close(self) -> None:
                self.close_calls += 1
                super().close()

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)

            # 1. _NoRedirectHandler.redirect_request MUST close fp before raising for 301/302/307/308
            handler = google_accounts._NoRedirectHandler()
            for code in (301, 302, 307, 308):
                redir_fp = _TrackableStream(b"redirect body")
                with self.assertRaises(google_accounts.GoogleProbeError) as ctx_redir:
                    handler.redirect_request(None, redir_fp, code, "Redirect", {}, "https://evil.example.com/steal")
                self.assertEqual(ctx_redir.exception.status_code, code)
                self.assertTrue(redir_fp.closed)
                self.assertGreaterEqual(redir_fp.close_calls, 1)

            # 2. HTTPError (401 and 301/302/307/308) MUST close exc/fp in finally with 0 ResourceWarnings
            for status_code, body in ((401, b'{"error":"expired"}'), (301, b"moved"), (302, b"found"), (307, b"temp"), (308, b"perm")):
                err_fp = _TrackableStream(body)

                class _ErrOpener:
                    def open(self, req, timeout=None, _code=status_code, _fp=err_fp):
                        raise urllib.error.HTTPError(
                            req.full_url,
                            _code,
                            "Error",
                            {},
                            _fp,
                        )

                with self.assertRaises(google_accounts.GoogleProbeError) as ctx_err:
                    google_accounts.google_https_json_request(
                        "GET",
                        google_accounts.GOOGLE_USERINFO_URL,
                        access_token=_mock_access_token("ERRCLOSE"),
                        opener=_ErrOpener(),
                    )
                self.assertEqual(ctx_err.exception.status_code, status_code)
                self.assertTrue(err_fp.closed, msg=f"HTTPError fp not closed for HTTP {status_code}")
                self.assertGreaterEqual(err_fp.close_calls, 1)

            gc.collect()

        res_warns = [w for w in caught if issubclass(w.category, ResourceWarning)]
        self.assertEqual(res_warns, [], msg=f"Unexpected ResourceWarnings: {[str(w.message) for w in res_warns]}")

    def test_secret_redaction_covers_all_token_formats(self) -> None:
        tok_a = _mock_access_token("REDACT")
        tok_r = _mock_refresh_token("REDACT")
        fake_jwt = "eyJ" + "EXAMPLEHEADER01" + "." + "EXAMPLEPAYLOAD02" + "." + "EXAMPLESIG03"
        raw = (
            f"Authorization: Bearer {tok_a} | raw={tok_a} | ref={tok_r} | "
            f'json={{"access_token":"{tok_a}","refresh_token":"{tok_r}","id_token":"{fake_jwt}"}}'
        )
        redacted = google_accounts.redact_secrets(raw)
        self.assertNotIn(tok_a, redacted)
        self.assertNotIn(tok_r, redacted)
        self.assertNotIn(fake_jwt, redacted)
        self.assertIn("[REDACTED", redacted)

    def test_401_triggers_isolated_acp_initialize_and_userinfo_only_without_touching_host_token(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_probe_") as tmp:
            root = Path(tmp) / "accounts"
            host_tok = Path(tmp) / "host" / "antigravity-oauth-token"
            host_tok.parent.mkdir(parents=True, exist_ok=True)
            host_original = _make_token_bytes("host_only@example.com", tag="HOSTORIG")
            host_tok.write_bytes(host_original)

            quota_cache = Path(tmp) / "cache" / "quota_usage.json"
            quota_cache.parent.mkdir(parents=True, exist_ok=True)
            quota_sentinel = '{"source":"official_usage","groups":[{"name":"Gemini","buckets":[]}]}\n'
            quota_cache.write_text(quota_sentinel, encoding="utf-8")

            calls: list[tuple[str, str, str]] = []
            acp_spawns: list[dict] = []

            def fake_http(method, url, *, access_token, json_body=None, timeout_sec=10.0):
                calls.append((method, url, access_token))
                google_accounts.assert_allowed_google_url(url)
                if access_token == _mock_access_token("STALE"):
                    raise google_accounts.GoogleProbeError("HTTP 401: expired", status_code=401)
                if url == google_accounts.GOOGLE_USERINFO_URL:
                    return {"id": "google-uid-new-1", "email": "new.user@example.com"}
                raise AssertionError(f"Unexpected outbound URL: {url}")

            class _FakeAcpInitProc:
                pid = 888888

                def __init__(self, target_token_path: Path):
                    self._tpath = target_token_path
                    self.stdin_writes: list[str] = []
                    self.stdin = _RecordingStdin(self.stdin_writes)
                    self.stdout = io.StringIO('{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":1}}\n')
                    self.stderr = io.StringIO("")
                    self._rc = None

                def poll(self):
                    return self._rc

                def terminate(self):
                    self._rc = 0

                def kill(self):
                    self._rc = -9

                def wait(self, timeout=None):
                    self._tpath.write_bytes(_make_token_bytes("new.user@example.com", tag="FRESH"))
                    self._rc = 0
                    return 0

            mgr = google_accounts.GoogleAccountManager(
                root_dir=root,
                host_token_path=host_tok,
                quota_cache_file=quota_cache,
                http_request_fn=fake_http,
                auto_adopt_host=False,
            )
            mgr.add_account("acct_new", alias="New Account")
            mgr.token_path_for("acct_new").write_bytes(_make_token_bytes("new.user@example.com", tag="STALE"))

            def fake_popen(cmd, **kwargs):
                acp_spawns.append({"cmd": cmd, "kwargs": kwargs})
                return _FakeAcpInitProc(mgr.token_path_for("acct_new"))

            mgr._popen_fn = fake_popen
            with mock.patch("os.killpg"):
                refreshed = mgr.refresh_account("acct_new")

            # Strictly userinfo-only outbound calls (GA2)
            self.assertEqual(len(calls), 2)
            self.assertLessEqual({u for _, u, _ in calls}, {google_accounts.GOOGLE_USERINFO_URL})
            self.assertEqual(len(acp_spawns), 1)
            self.assertEqual(acp_spawns[0]["cmd"][1:3], ["acp", "--gemini-dir"])
            self.assertEqual(acp_spawns[0]["cmd"][3], str(mgr.profile_dir_for("acct_new")))
            self.assertEqual(acp_spawns[0]["kwargs"]["env"]["AGY_CLI_DISABLE_AUTO_UPDATE"], "1")

            # New account defaults to unknown plan with zero fabricated quota (GA5)
            self.assertEqual(refreshed["plan_tier"], "unknown")
            self.assertEqual(refreshed["plan_label"], "Unknown")
            self.assertEqual(refreshed["email_masked"], "n***r@example.com")
            self.assertFalse(refreshed["quota_summary"]["has_quota"])
            for pct_key in ("gemini_5h_pct", "gemini_weekly_pct", "claude_gpt_5h_pct", "claude_gpt_weekly_pct"):
                self.assertIsNone(refreshed["quota_summary"][pct_key])
            # Host token & official /usage quota_cache_file MUST remain completely untouched!
            self.assertEqual(host_tok.read_bytes(), host_original)
            self.assertEqual(quota_cache.read_text(encoding="utf-8"), quota_sentinel)

    def test_ga2_login_auto_probe_and_refresh_all_emit_userinfo_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_ga2_") as tmp:
            root = Path(tmp) / "accounts"
            called_urls: list[str] = []

            def fake_http(method, url, *, access_token, json_body=None, timeout_sec=10.0):
                called_urls.append(url)
                google_accounts.assert_allowed_google_url(url)
                return {"id": "uid-login-auto-1", "email": "auto.user@example.com"}

            mgr = google_accounts.GoogleAccountManager(
                root_dir=root,
                host_token_path=Path(tmp) / "host" / "token",
                http_request_fn=fake_http,
                auto_adopt_host=False,
            )
            expected_state = "STATE_GA2_AUTO_PROBE_001"
            auth_url = (
                "https://accounts.google.com/o/oauth2/auth"
                "?client_id=example&redirect_uri=https%3A%2F%2Fantigravity.google%2Foauth-callback"
                f"&state={expected_state}"
            )

            def fake_popen(_cmd, **_kwargs):
                return _FakeLoginProc(auth_url, mgr.token_path_for("auto1"))

            fmgr = google_accounts.GoogleLoginFlowManager(
                mgr,
                popen_fn=fake_popen,
                auto_probe_on_login=True,
            )
            started = fmgr.start_login("auto1", alias="Auto One", owner_session_id="sess-ga2")
            cb = f"https://antigravity.google/oauth-callback?state={expected_state}&code=4/0AEXAMPLE_GA2_CODE_123"
            done = fmgr.submit_code(started["flow_id"], cb, owner_session_id="sess-ga2")
            self.assertEqual(done["status"], "completed")
            self.assertEqual(done["account"]["plan_tier"], "unknown")
            self.assertFalse(done["account"]["quota_summary"]["has_quota"])
            self.assertLessEqual(set(called_urls), {google_accounts.GOOGLE_USERINFO_URL})
            self.assertEqual(len(called_urls), 1)

            # refresh_all_accounts also emits strictly userinfo only
            res_all = mgr.refresh_all_accounts()
            self.assertTrue(res_all["ok"])
            self.assertEqual(len(res_all["refreshed"]), 1)
            self.assertLessEqual(set(called_urls), {google_accounts.GOOGLE_USERINFO_URL})
            self.assertEqual(len(called_urls), 2)


# ---------------------------------------------------------------------------
# C6: Fingerprint Deduplication, Multi-Plan Pools, Recommendation, & Cost Compat
# ---------------------------------------------------------------------------

class TestMultiPlanDedupAndCostLedgerCompat(unittest.TestCase):
    def test_ga5_fingerprint_dedup_legacy_registry_compat_and_refresh_preserves_legacy_plan(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_dedup_") as tmp:
            root = Path(tmp) / "accounts"
            quota_cache = Path(tmp) / "cache" / "quota_usage.json"
            quota_cache.parent.mkdir(parents=True, exist_ok=True)
            quota_sentinel = '{"source":"official_usage","groups":[]}\n'
            quota_cache.write_text(quota_sentinel, encoding="utf-8")

            called_urls: list[str] = []
            token_to_profile = {
                _mock_access_token("U1"): ("uid-shared-001", "shared@example.com"),
                _mock_access_token("U1DUP"): ("uid-shared-001", "shared@example.com"),
                _mock_access_token("P2"): ("uid-pro-002", "pro2@example.com"),
                _mock_access_token("F3"): ("uid-free-003", "free3@example.com"),
            }

            def fake_http(_method, url, *, access_token, json_body=None, timeout_sec=10.0):
                called_urls.append(url)
                google_accounts.assert_allowed_google_url(url)
                uid, em = token_to_profile[access_token]
                return {"id": uid, "email": em}

            def _legacy_quota(gem_rem: float, claude_rem: float) -> dict:
                return {
                    "fetched_at_epoch": 1700000000.0,
                    "fetched_at_iso": "2026-11-21T00:00:00Z",
                    "description": "",
                    "groups": [
                        {
                            "name": "Gemini Models",
                            "buckets": [
                                {
                                    "id": "gemini-weekly",
                                    "name": "Weekly",
                                    "window": "weekly",
                                    "remaining_fraction": gem_rem,
                                    "reset_time": "2026-11-27T23:00:00Z",
                                }
                            ],
                        },
                        {
                            "name": "Claude and GPT models",
                            "buckets": [
                                {
                                    "id": "3p-weekly",
                                    "name": "Weekly",
                                    "window": "weekly",
                                    "remaining_fraction": claude_rem,
                                    "reset_time": "2026-11-27T23:00:00Z",
                                }
                            ],
                        },
                    ],
                }

            mgr = google_accounts.GoogleAccountManager(
                root_dir=root,
                host_token_path=Path(tmp) / "host" / "token",
                quota_cache_file=quota_cache,
                http_request_fn=fake_http,
                auto_adopt_host=False,
            )

            # Seed legacy registry.json containing historical plan_tier/quota, quota=None, and missing quota key
            for aid, tag, em in (
                ("ultra_main", "U1", "shared@example.com"),
                ("ultra_dup", "U1DUP", "shared@example.com"),
                ("pro_work", "P2", "pro2@example.com"),
                ("free_alt", "F3", "free3@example.com"),
            ):
                mgr.add_account(aid, alias=aid)
                mgr.token_path_for(aid).write_bytes(_make_token_bytes(em, tag=tag))

            with mgr._exclusive_lock():
                reg = mgr._load_registry_locked()
                reg["active_account_id"] = "ultra_main"
                reg["accounts"]["ultra_main"].update({
                    "plan_tier": "ultra",
                    "plan_label": "Google AI Ultra",
                    "quota": _legacy_quota(0.20, 0.03),
                    "status": "ready",
                })
                reg["accounts"]["ultra_dup"].update({
                    "plan_tier": "ultra",
                    "plan_label": "Google AI Ultra",
                    "quota": _legacy_quota(0.20, 0.03),
                    "status": "ready",
                })
                reg["accounts"]["pro_work"].update({
                    "plan_tier": "pro",
                    "plan_label": "Google AI Pro",
                    "quota": _legacy_quota(0.90, 0.80),
                    "status": "ready",
                })
                reg["accounts"]["free_alt"].update({
                    "plan_tier": "free",
                    "plan_label": "Free",
                    "quota": None,
                    "status": "ready",
                })
                # Also add a legacy slot missing the `quota` key altogether
                reg["accounts"]["legacy_nokey"] = {
                    "account_id": "legacy_nokey",
                    "alias": "Legacy NoKey",
                    "plan_tier": "enterprise",
                    "plan_label": "Enterprise",
                    "status": "ready",
                }
                mgr._save_registry_locked(reg)

            # Refresh identity for the 4 tokenized accounts: ONLY userinfo is called, legacy plan/quota preserved!
            for aid in ("ultra_main", "ultra_dup", "pro_work", "free_alt"):
                mgr.refresh_account(aid)

            self.assertLessEqual(set(called_urls), {google_accounts.GOOGLE_USERINFO_URL})
            self.assertEqual(len(called_urls), 4)
            # quota_cache_file MUST NOT be overwritten by refresh_account
            self.assertEqual(quota_cache.read_text(encoding="utf-8"), quota_sentinel)

            accts = {a["account_id"]: a for a in mgr.list_accounts()}
            self.assertEqual(mgr.get_account("ultra_main")["plan_tier"], "ultra")
            self.assertEqual(mgr.get_account("ultra_main")["plan_label"], "Google AI Ultra")
            self.assertEqual(mgr.get_account("legacy_nokey")["plan_tier"], "enterprise")
            self.assertFalse(mgr.get_account("legacy_nokey")["quota_summary"]["has_quota"])
            self.assertFalse(mgr.get_account("free_alt")["quota_summary"]["has_quota"])
            self.assertEqual(mgr.get_active_account_context(), ("ultra_main", "ultra"))

            expected_fp = hashlib.sha256(b"google-account\x00uid-shared-001").hexdigest()
            self.assertEqual(accts["ultra_main"]["credential_fingerprint"], expected_fp)
            self.assertEqual(accts["ultra_dup"]["credential_fingerprint"], expected_fp)
            # Exactly one of the two shared-UID slots is marked duplicate
            dup_flags = [accts["ultra_main"]["is_duplicate"], accts["ultra_dup"]["is_duplicate"]]
            self.assertEqual(sorted(dup_flags), [False, True])

            summary = mgr.summarize_plan_quotas()
            self.assertEqual(summary["total_slots"], 5)
            self.assertEqual(summary["total_unique_accounts"], 4)
            self.assertEqual(summary["duplicate_slot_count"], 1)
            tiers = {t["plan_tier"]: t for t in summary["tiers"]}
            self.assertEqual(tiers["ultra"]["unique_accounts"], 1)
            self.assertEqual(tiers["ultra"]["duplicate_slots"], 1)
            # Ultra Gemini pool must NOT be double-counted (0.20, not 0.40)
            self.assertAlmostEqual(tiers["ultra"]["pools"]["gemini_weekly"]["total_remaining_fraction"], 0.2, places=3)

            # Recommend claude_gpt: ultra_main is exhausted (3% <= 5%), so pro_work (80%) wins!
            rec_cg = mgr.recommend_account("claude_gpt")
            self.assertEqual(rec_cg["recommended"]["account_id"], "pro_work")

            # Recommend gemini: pro_work (90%) beats ultra_main (20%)
            rec_gem = mgr.recommend_account("gemini")
            self.assertEqual(rec_gem["recommended"]["account_id"], "pro_work")

            # GA7: format_multi_plan_summary with no quota data uses honest degraded copy, never "待刷新配额"
            rendered_summary = cost_usage.format_multi_plan_summary(summary)
            self.assertIn("仅身份同步（配额请看 /usage）", rendered_summary)
            self.assertNotIn("待刷新配额", rendered_summary)

    def test_cost_ledger_v2_and_cost_config_backward_compatibility(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_cost_") as tmp:
            brain_root = Path(tmp) / "brain"
            ledger_file = Path(tmp) / "cache" / "cost_ledger_v2.json"
            lock_file = Path(tmp) / "cache" / "cost.lock"
            cfg_file = Path(tmp) / "cache" / "cost_config.json"
            ledger_file.parent.mkdir(parents=True, exist_ok=True)

            # 1. Seed legacy cost_ledger_v2.json WITHOUT account_id / plan_tier
            ledger_file.write_text(
                json.dumps({
                    "version": 1,
                    "conversations": {
                        "legacy-conv-001": {
                            "mtime_ns": 1,
                            "size": 100,
                            "project_id": "default-cli-project",
                            "is_observer": False,
                            "is_scheduled": False,
                            "hours": {"2026-11-21T10": {"gemini-3.8-flash": [1000, 500, 200, 1, 0.01, 0.02]}},
                        }
                    },
                }),
                encoding="utf-8",
            )
            # Add a new live transcript under active account "pro_work" / "pro"
            tpath = brain_root / "new-conv-002" / ".system_generated" / "logs" / "transcript.jsonl"
            tpath.parent.mkdir(parents=True, exist_ok=True)
            tpath.write_text(
                json.dumps({
                    "type": "PLANNER_RESPONSE",
                    "model": "claude-opus-5-5",
                    "input_tokens": 2000,
                    "cache_read_tokens": 1000,
                    "output_tokens": 500,
                    "created_at": "2026-11-22T03:00:00Z",
                    "step_index": 1,
                }) + "\n",
                encoding="utf-8",
            )

            records = cost_usage.collect_cost_hourly_buckets(
                brain_root=str(brain_root),
                cost_ledger_file=str(ledger_file),
                cost_ledger_lock=str(lock_file),
                meta_map={},
                mem_cache={},
                cache_lock=threading.Lock(),
                active_account_id="pro_work",
                active_plan_tier="pro",
            )
            by_acct = cost_usage.aggregate_by_account(records)
            self.assertIn("unassigned", by_acct)
            self.assertEqual(by_acct["unassigned"]["plan_tier"], "unknown")
            self.assertIn("pro_work", by_acct)
            self.assertEqual(by_acct["pro_work"]["plan_tier"], "pro")

            by_plan = cost_usage.aggregate_by_plan(records)
            self.assertIn("unknown", by_plan)
            self.assertIn("pro", by_plan)

            # Legacy render_cost_panel must work seamlessly with both 12-tuple and 14-tuple records
            html_14, _kb = cost_usage.render_cost_panel(
                view="overview",
                scope="all",
                cur_proj="default-cli-project",
                proj_name="default",
                records=records,
                cost_tz_name="Asia/Shanghai",
                cost_config_file=str(cfg_file),
            )
            self.assertIn("/cost", html_14)

            # 2. Legacy cost_config.json WITHOUT account_weekly_resets + per-account override
            cfg_file.write_text(
                json.dumps({
                    "weekly_reset_utc_weekday": 4,
                    "weekly_reset_utc_hour": 23,
                    "weekly_reset_utc_minute": 0,
                }),
                encoding="utf-8",
            )
            self.assertEqual(cost_usage.load_weekly_reset_utc(str(cfg_file)), (4, 23, 0))
            self.assertEqual(cost_usage.load_weekly_reset_utc(str(cfg_file), account_id="pro_work"), (4, 23, 0))

            cost_usage.save_weekly_reset_utc(str(cfg_file), 1, 14, 30, account_id="pro_work")
            self.assertEqual(cost_usage.load_weekly_reset_utc(str(cfg_file), account_id="pro_work"), (1, 14, 30))
            # Global top-level default anchor MUST remain preserved
            self.assertEqual(cost_usage.load_weekly_reset_utc(str(cfg_file)), (4, 23, 0))


# ---------------------------------------------------------------------------
# C5: Telegram Group Redaction & Mutation Blocking + IPC `/ipc/accounts/recycle`
# ---------------------------------------------------------------------------

class TestBridgeAccountsAndStudioIPC(unittest.TestCase):
    def test_telegram_group_redaction_and_mutation_rejection_vs_admin_dm_switch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_bridge_") as tmp:
            bridge = _load_isolated_bridge(tmp)
            bridge.BOT_META.update({"bot_id": 100, "handle": "example_bot", "resolved": True})

            # Seed two accounts
            host_tok = Path(bridge.HOST_OAUTH_TOKEN_FILE)
            host_tok.parent.mkdir(parents=True, exist_ok=True)
            host_tok.write_bytes(_make_token_bytes("secret.owner@example.com", tag="B1"))

            mgr = bridge._get_google_account_manager()
            mgr.add_account("work", alias="work.alias@example.org")
            mgr.token_path_for("work").write_bytes(_make_token_bytes("work.person@example.org", tag="B2"))

            sent: list[str] = []
            cb_answers: list[dict] = []

            with (
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append(txt) or 1),
                mock.patch.object(bridge, "tg", side_effect=lambda method, **kw: cb_answers.append({"method": method, **kw}) or None),
            ):
                # 1. Group chat /accounts is strictly read-only & redacted (no email, no email-domain suffix, no paths)
                bridge.handle_message({
                    "chat": {"id": -1001234567890, "type": "supergroup"},
                    "from": {"id": 111},
                    "text": "/accounts",
                })
                self.assertEqual(len(sent), 1)
                grp_view = sent[-1]
                self.assertNotIn("secret.owner@example.com", grp_view)
                self.assertNotIn("@example.com", grp_view)
                self.assertNotIn("@example.org", grp_view)
                self.assertNotIn(str(tmp), grp_view)

                # 2. Group chat /usage is also strictly redacted
                with mock.patch.object(
                    bridge,
                    "fetch_plan_quota_data",
                    return_value=({"fetched_at_epoch": time.time(), "groups": []}, False, ""),
                ):
                    usage_txt, _kb = bridge.build_usage_panel(force_live=False, chat_id=-1001234567890)
                self.assertNotIn("@example.com", usage_txt)
                self.assertNotIn("@example.org", usage_txt)
                self.assertNotIn(str(tmp), usage_txt)

                # 3. Group chat mutating subcommands MUST be rejected (even for admin uid 111!)
                for mut_cmd in (
                    "/accounts add acct2",
                    "/accounts login work",
                    "/accounts code gflow_1 4/0AEXAMPLE_1234",
                    "/accounts cancel gflow_1",
                    "/accounts switch work",
                    "/accounts refresh work",
                    "/accounts logout work",
                    "/accounts delete work",
                ):
                    sent.clear()
                    bridge.handle_message({
                        "chat": {"id": -1001234567890, "type": "supergroup"},
                        "from": {"id": 111},
                        "text": mut_cmd,
                    })
                    self.assertEqual(len(sent), 1, msg=f"No reply for {mut_cmd}")
                    self.assertIn("仅限管理员私聊", sent[0], msg=f"Mutation not blocked in group: {mut_cmd}")
                # Active account MUST still be primary
                self.assertEqual(mgr.get_active_account()["account_id"], "primary")

                # 4. Forged inline callback in group chat MUST be rejected
                cb_answers.clear()
                bridge.handle_callback({
                    "id": "cb-group-forged",
                    "from": {"id": 111},
                    "message": {"chat": {"id": -1001234567890}, "message_id": 55},
                    "data": "accounts:switch:work",
                })
                self.assertTrue(any("仅限管理员私聊" in str(a.get("text", "")) for a in cb_answers))
                self.assertEqual(mgr.get_active_account()["account_id"], "primary")

                # 5. Admin DM switch succeeds, recycles idle warm session, and marks running session dirty without force-kill
                idle_sess = mock.MagicMock()
                running_sess = mock.MagicMock()
                with bridge.session_lock:
                    bridge._session_pool.clear()
                    bridge.session_dirty_scopes.clear()
                    bridge._session_pool["idle_scope"] = idle_sess
                    bridge._session_pool["busy_scope"] = running_sess
                    bridge.turn_running = True
                    bridge.turn_running_scope = "busy_scope"

                sent.clear()
                closed_sync: list[tuple] = []
                with mock.patch.object(bridge, "close_session_async", side_effect=lambda s, force=False: closed_sync.append((s, force))):
                    bridge.handle_message({
                        "chat": {"id": 111, "type": "private"},
                        "from": {"id": 111},
                        "text": "/accounts switch work",
                    })
                self.assertEqual(mgr.get_active_account()["account_id"], "work")
                self.assertEqual(closed_sync, [(idle_sess, False)])
                with bridge.session_lock:
                    self.assertNotIn("idle_scope", bridge._session_pool)
                    self.assertIn("busy_scope", bridge._session_pool)
                    self.assertIn("busy_scope", bridge.session_dirty_scopes)
                    bridge.turn_running = False
                    bridge.turn_running_scope = None
                    bridge._session_pool.clear()
                    bridge.session_dirty_scopes.clear()
                running_sess.close.assert_not_called()

    def test_ipc_accounts_recycle_rbac_users_json_forbidden_keys_and_no_kill_inflight(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_ipc_") as tmp:
            bridge = _load_isolated_bridge(tmp)
            users_path = Path(bridge.STUDIO_USERS_FILE)
            users_path.parent.mkdir(parents=True, exist_ok=True)
            users_path.write_text(
                json.dumps({
                    "version": 1,
                    "users": {
                        "admin_u": {"username": "admin_u", "user_id": 111, "role": "admin", "disabled": False},
                        "guest_u": {"username": "guest_u", "user_id": 222, "role": "readonly", "disabled": False},
                    },
                }),
                encoding="utf-8",
            )

            peer_uid_box = [os.getuid()]
            srv = studio_ipc.StudioIPCServer(
                bus_dir=Path(tmp) / "bus",
                bot_handle="example_bot",
                resolve_role_fn=bridge._studio_ipc_resolve_role,
                get_meta_fn=lambda: {"handle": "example_bot"},
                enqueue_turn_fn=lambda _r: (200, {"ok": True}),
                abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
                recycle_accounts_fn=bridge._studio_ipc_recycle_accounts,
                peer_uid_fn=lambda _conn: peer_uid_box[0],
            )
            sock_path = str(srv.start())
            try:
                auth_hdr = {"X-Bridge-IPC-Token": srv.token}

                # 1. Wrong token -> 403
                sc, _ = _ipc_post(sock_path, "/ipc/accounts/recycle", {"user_id": 111}, {"X-Bridge-IPC-Token": "wrong"})
                self.assertEqual(sc, 403)

                # 2. Proxy forwarding headers -> 403
                for proxy_hdr in ("X-Forwarded-For", "CF-Connecting-IP", "X-Real-IP"):
                    sc, _ = _ipc_post(
                        sock_path,
                        "/ipc/accounts/recycle",
                        {"user_id": 111},
                        {**auth_hdr, proxy_hdr: "127.0.0.1"},
                    )
                    self.assertEqual(sc, 403, msg=f"Header {proxy_hdr} must be rejected")

                # 3. Wrong SO_PEERCRED UID -> 403
                peer_uid_box[0] = os.getuid() + 1
                sc, _ = _ipc_post(sock_path, "/ipc/accounts/recycle", {"user_id": 111}, auth_hdr)
                self.assertEqual(sc, 403)
                peer_uid_box[0] = os.getuid()

                # 4. Readonly user spoofing `role: "admin"` -> 403
                sc, _ = _ipc_post(
                    sock_path,
                    "/ipc/accounts/recycle",
                    {"user_id": 222, "role": "admin"},
                    auth_hdr,
                )
                self.assertEqual(sc, 403)

                # 5. Forbidden & unknown keys -> 400
                for bad_payload in (
                    {"user_id": 111, "cmd": "id"},
                    {"user_id": 111, "shell": "/bin/sh"},
                    {"user_id": 111, "workdir": "/tmp"},
                    {"user_id": 111, "token_path": "/tmp/tok"},
                    {"user_id": 111, "reload_file": "/tmp/r"},
                    {"user_id": 111, "role": "admin"},
                    {"user_id": 111, "unknown_extra": 1},
                    {"user_id": 111, "account_id": "../evil"},
                ):
                    sc, _ = _ipc_post(sock_path, "/ipc/accounts/recycle", bad_payload, auth_hdr)
                    self.assertEqual(sc, 400, msg=f"Payload {bad_payload!r} must return 400")

                # 6. Valid admin call recycles idle session & marks running session dirty (never kills active turn)
                idle_sess = mock.MagicMock()
                active_sess = mock.MagicMock()
                closed_sync: list[tuple] = []
                with bridge.session_lock:
                    bridge._session_pool.clear()
                    bridge.session_dirty_scopes.clear()
                    bridge._session_pool["s_idle"] = idle_sess
                    bridge._session_pool["s_busy"] = active_sess
                    bridge.turn_running = True
                    bridge.turn_running_scope = "s_busy"

                with mock.patch.object(bridge, "close_session_async", side_effect=lambda s, force=False: closed_sync.append((s, force))):
                    sc, body = _ipc_post(
                        sock_path,
                        "/ipc/accounts/recycle",
                        {"user_id": 111, "account_id": "work", "reason": "studio_switch"},
                        auth_hdr,
                    )
                self.assertEqual(sc, 200)
                self.assertTrue(body["ok"])
                self.assertEqual(body["recycled_idle"], 1)
                self.assertEqual(body["deferred_running"], 1)
                self.assertEqual(closed_sync, [(idle_sess, False)])
                active_sess.close.assert_not_called()
                with bridge.session_lock:
                    self.assertIn("s_busy", bridge.session_dirty_scopes)
                    bridge.turn_running = False
                    bridge.turn_running_scope = None
                    bridge._session_pool.clear()
                    bridge.session_dirty_scopes.clear()

                # 7. Live RBAC revocation in users.json immediately rejects previously-admin uid 111 with 403!
                users_path.write_text(
                    json.dumps({
                        "version": 1,
                        "users": {
                            "admin_u": {"username": "admin_u", "user_id": 111, "role": "readonly", "enabled": True},
                        },
                    }),
                    encoding="utf-8",
                )
                sc, _ = _ipc_post(sock_path, "/ipc/accounts/recycle", {"user_id": 111, "account_id": "work"}, auth_hdr)
                self.assertEqual(sc, 403)
            finally:
                srv.stop()

    def test_studio_users_json_enabled_schema_disabled_and_corrupt_fail_closed(self) -> None:
        try:
            from studio import auth as studio_auth  # noqa: E402
        except ModuleNotFoundError as exc:
            if exc.name != "aiohttp":
                raise
            import types

            fake_aiohttp = types.ModuleType("aiohttp")
            fake_web = types.ModuleType("aiohttp.web")
            fake_web.middleware = lambda fn: fn
            fake_aiohttp.web = fake_web
            with mock.patch.dict(sys.modules, {"aiohttp": fake_aiohttp, "aiohttp.web": fake_web}):
                sys.modules.pop("studio.auth", None)
                from studio import auth as studio_auth  # noqa: E402
                sys.modules.pop("studio.auth", None)

        with tempfile.TemporaryDirectory(prefix="ga_users_rbac_") as tmp:
            bridge = _load_isolated_bridge(tmp)
            users_path = Path(bridge.STUDIO_USERS_FILE)
            users_path.parent.mkdir(parents=True, exist_ok=True)

            srv = studio_ipc.StudioIPCServer(
                bus_dir=Path(tmp) / "bus",
                bot_handle="example_bot",
                resolve_role_fn=bridge._studio_ipc_resolve_role,
                get_meta_fn=lambda: {"handle": "example_bot"},
                enqueue_turn_fn=lambda _r: (200, {"ok": True}),
                abort_turn_fn=lambda _t, _u: (200, {"ok": True}),
                recycle_accounts_fn=bridge._studio_ipc_recycle_accounts,
                peer_uid_fn=lambda _conn: os.getuid(),
            )
            sock_path = str(srv.start())
            try:
                auth_hdr = {"X-Bridge-IPC-Token": srv.token}

                # 1. Real schema enabled=True -> admin allowed (200)
                users_path.write_text(
                    json.dumps({
                        "version": 1,
                        "users": {
                            "admin_u": {"username": "admin_u", "user_id": 111, "role": "admin", "enabled": True},
                        },
                    }),
                    encoding="utf-8",
                )
                self.assertEqual(bridge._resolve_studio_users_json_role(111), "admin")
                sc, body = _ipc_post(sock_path, "/ipc/accounts/recycle", {"user_id": 111}, auth_hdr)
                self.assertEqual(sc, 200)
                self.assertTrue(body["ok"])

                # 2. enabled=False -> immediately denied (403)
                users_path.write_text(
                    json.dumps({
                        "version": 1,
                        "users": {
                            "admin_u": {"username": "admin_u", "user_id": 111, "role": "admin", "enabled": False},
                        },
                    }),
                    encoding="utf-8",
                )
                self.assertEqual(bridge._resolve_studio_users_json_role(111), "denied")
                sc, _ = _ipc_post(sock_path, "/ipc/accounts/recycle", {"user_id": 111}, auth_hdr)
                self.assertEqual(sc, 403)

                # 3. Corrupt non-boolean enabled="false" -> whole-store fail-closed denied (403)
                users_path.write_text(
                    json.dumps({
                        "version": 1,
                        "users": {
                            "admin_u": {"username": "admin_u", "user_id": 111, "role": "admin", "enabled": "false"},
                        },
                    }),
                    encoding="utf-8",
                )
                self.assertEqual(bridge._resolve_studio_users_json_role(111), "denied")
                sc, _ = _ipc_post(sock_path, "/ipc/accounts/recycle", {"user_id": 111}, auth_hdr)
                self.assertEqual(sc, 403)

                # 4. Corrupt non-boolean enabled on sibling record also fail-closes entire store
                users_path.write_text(
                    json.dumps({
                        "version": 1,
                        "users": {
                            "admin_u": {"username": "admin_u", "user_id": 111, "role": "admin", "enabled": True},
                            "corrupt_u": {"username": "corrupt_u", "user_id": 222, "role": "readonly", "enabled": "true"},
                        },
                    }),
                    encoding="utf-8",
                )
                self.assertEqual(bridge._resolve_studio_users_json_role(111), "denied")
                sc, _ = _ipc_post(sock_path, "/ipc/accounts/recycle", {"user_id": 111}, auth_hdr)
                self.assertEqual(sc, 403)

                # 5. Real studio.auth.save_users_file_atomic() disabled admin record -> denied & 403
                pw_hash = studio_auth.hash_password_scrypt("ExampleStrong#2026")
                now_ts = int(time.time())
                real_disabled_rec = {
                    "username": "admin_real",
                    "password_hash": pw_hash,
                    "role": "admin",
                    "bot": "main",
                    "user_id": 111,
                    "enabled": False,
                    "must_change_password": False,
                    "password_version": 1,
                    "created_at": now_ts,
                    "updated_at": now_ts,
                }
                studio_auth.save_users_file_atomic(users_path, {"admin_real": real_disabled_rec})
                valid_store, loaded = studio_auth.load_users_file(users_path)
                self.assertTrue(valid_store)
                self.assertFalse(loaded["admin_real"]["enabled"])
                self.assertEqual(bridge._resolve_studio_users_json_role(111), "denied")
                sc, _ = _ipc_post(sock_path, "/ipc/accounts/recycle", {"user_id": 111}, auth_hdr)
                self.assertEqual(sc, 403)
            finally:
                srv.stop()

    def test_group_usage_and_accounts_error_echoes_fully_redacted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_grp_err_") as tmp:
            bridge = _load_isolated_bridge(tmp)
            dom = "gmail" + "." + "com"
            secret_email = "secret.user@" + dom
            secret_domain = "@" + dom
            host_path = "/home/" + "alice/.gemini/antigravity-cli/antigravity-oauth-token"
            tok_access = _mock_access_token("GRPERR")
            tok_refresh = _mock_refresh_token("GRPERR")
            qa_err = (
                f"probe failed for {secret_email} at {host_path} "
                f"with Authorization: Bearer {tok_access} raw={tok_access} ref={tok_refresh}"
            )

            def _assert_zero_leak(rendered: str, label: str) -> None:
                self.assertNotIn(secret_email, rendered, msg=f"{label}: leaked email")
                self.assertNotIn(secret_domain, rendered, msg=f"{label}: leaked email-domain suffix")
                self.assertNotIn("/home/", rendered, msg=f"{label}: leaked host path")
                self.assertNotIn(".gemini", rendered, msg=f"{label}: leaked .gemini path")
                self.assertNotIn(tok_access, rendered, msg=f"{label}: leaked access token")
                self.assertNotIn(tok_refresh, rendered, msg=f"{label}: leaked refresh token")
                self.assertNotIn("ya" + "29.", rendered, msg=f"{label}: leaked ya29 prefix")
                self.assertNotIn("1/" + "/", rendered, msg=f"{label}: leaked refresh prefix")

            # 1. render_usage_panel(..., redact_for_group=True)
            panel_html, _kb = cost_usage.render_usage_panel(
                None,
                False,
                qa_err,
                redact_for_group=True,
            )
            _assert_zero_leak(panel_html, "render_usage_panel(group)")

            # 2. Group cmd_usage exception echo
            sent: list[str] = []
            done_ev = threading.Event()

            def _fake_send(cid, txt, **kw):
                sent.append(txt)
                if "查询总套餐配额失败" in txt:
                    done_ev.set()
                return len(sent)

            with (
                mock.patch.object(bridge, "send", side_effect=_fake_send),
                mock.patch.object(bridge, "build_usage_panel", side_effect=RuntimeError(qa_err)),
            ):
                bridge.cmd_usage(-1001234567890)
                self.assertTrue(done_ev.wait(timeout=3.0), msg="cmd_usage background thread did not send error")
            usage_err_msgs = [m for m in sent if "查询总套餐配额失败" in m]
            self.assertEqual(len(usage_err_msgs), 1)
            _assert_zero_leak(usage_err_msgs[0], "cmd_usage(group)")

            # 3. Group cmd_accounts exception inside build_accounts_panel is caught and fully redacted
            sent.clear()
            with (
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append(txt) or 1),
                mock.patch.object(bridge, "build_accounts_panel", side_effect=RuntimeError(qa_err)),
            ):
                bridge.cmd_accounts(-1001234567890, "", from_user={"id": 111})
            self.assertEqual(len(sent), 1)
            self.assertIn("账号操作失败", sent[0])
            _assert_zero_leak(sent[0], "cmd_accounts(group)")

    def test_ga2_ga3_ga7_telegram_dm_accounts_refresh_honest_copy_and_official_usage_cli(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ga_tg_honest_") as tmp:
            bridge = _load_isolated_bridge(tmp)
            bridge.BOT_META.update({"bot_id": 100, "handle": "example_bot", "resolved": True})

            host_tok = Path(bridge.HOST_OAUTH_TOKEN_FILE)
            host_tok.parent.mkdir(parents=True, exist_ok=True)
            host_tok.write_bytes(_make_token_bytes("dm.owner@example.com", tag="DM1"))

            called_urls: list[str] = []

            def fake_http(_method, url, *, access_token, json_body=None, timeout_sec=10.0):
                called_urls.append(url)
                google_accounts.assert_allowed_google_url(url)
                return {"id": "uid-dm-001", "email": "dm.owner@example.com"}

            mgr = bridge._get_google_account_manager()
            mgr._http_request_fn = fake_http

            sent: list[str] = []
            tg_calls: list[dict] = []

            with (
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append(txt) or 1),
                mock.patch.object(bridge, "tg", side_effect=lambda method, **kw: tg_calls.append({"method": method, **kw}) or None),
            ):
                # 1. Admin DM /accounts panel shows honest degraded copy and never "待刷新配额"
                bridge.handle_message({
                    "chat": {"id": 111, "type": "private"},
                    "from": {"id": 111},
                    "text": "/accounts",
                })
                self.assertEqual(len(sent), 1)
                self.assertIn("已停用非官方内部配额探测", sent[0])
                self.assertIn("/usage", sent[0])
                self.assertNotIn("待刷新配额", sent[0])

                # 2. Admin DM /accounts refresh hits userinfo ONLY and displays honest copy
                sent.clear()
                bridge.handle_message({
                    "chat": {"id": 111, "type": "private"},
                    "from": {"id": 111},
                    "text": "/accounts refresh",
                })
                self.assertGreaterEqual(len(sent), 2)
                combined_refresh = "\n".join(sent)
                self.assertIn("已停用非官方内部配额探测", combined_refresh)
                self.assertIn("/usage", combined_refresh)
                self.assertNotIn("待刷新配额", combined_refresh)
                self.assertLessEqual(set(called_urls), {google_accounts.GOOGLE_USERINFO_URL})
                self.assertEqual(len(called_urls), 1)

                # 3. Admin DM callback `accounts:refresh:all` hits userinfo ONLY and displays honest copy
                tg_calls.clear()
                bridge.handle_callback({
                    "id": "cb-dm-refresh-all",
                    "from": {"id": 111},
                    "message": {"chat": {"id": 111}, "message_id": 77},
                    "data": "accounts:refresh:all",
                })
                self.assertLessEqual(set(called_urls), {google_accounts.GOOGLE_USERINFO_URL})
                self.assertEqual(len(called_urls), 2)
                self.assertTrue(
                    any("同步账号身份" in str(c.get("text", "")) for c in tg_calls if c.get("method") == "answerCallbackQuery")
                )
                edited = [c.get("text", "") for c in tg_calls if c.get("method") == "editMessageText"]
                self.assertEqual(len(edited), 1)
                self.assertIn("已停用非官方内部配额探测", edited[0])
                self.assertNotIn("待刷新配额", edited[0])

            # 4. GA3: bridge.fetch_plan_quota_data still invokes official `agy -p /usage --output-format json`
            recorded_cmds: list[list[str]] = []

            def _fake_run_group(cmd, **kwargs):
                recorded_cmds.append(list(cmd))
                out = json.dumps({
                    "command": {
                        "data": {
                            "description": "Official CLI",
                            "groups": [
                                {
                                    "name": "Gemini Models",
                                    "buckets": [{"id": "gemini-weekly", "window": "weekly", "remaining_fraction": 0.9}],
                                }
                            ],
                        }
                    }
                })
                return 0, out, ""

            with mock.patch.object(bridge, "_run_subprocess_group", side_effect=_fake_run_group):
                snap, is_fallback, err_str = bridge.fetch_plan_quota_data(force_live=True)
            self.assertEqual(len(recorded_cmds), 1)
            self.assertEqual(recorded_cmds[0][1:5], ["-p", "/usage", "--output-format", "json"])
            self.assertIsNotNone(snap)
            self.assertFalse(is_fallback)
            self.assertEqual(err_str, "")


if __name__ == "__main__":
    unittest.main()
