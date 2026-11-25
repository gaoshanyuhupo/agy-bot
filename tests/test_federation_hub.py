#!/usr/bin/env python3
"""Comprehensive M2 security & integration tests for Federation Hub, Host Server Bridge,
Stdio MCP Adapter, Capabilities Enforcement, Pull Worker Sync, and Outbound Dispatcher (M2-C1..M2-C8)."""

from __future__ import annotations

import base64
import concurrent.futures
import http.client
import importlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import bot_bus  # noqa: E402
import external_drivers as ext  # noqa: E402
import federation_hub as hub  # noqa: E402
import federation_mcp_stdio as stdio_mcp  # noqa: E402
import federation_registry as fed  # noqa: E402

_SCRUB_ENV_KEYS = (
    "AGY_UNTRUSTED_SESSION",
    "AGY_MEMORY_READONLY",
    "AGY_TRUST_LEVEL",
    "AGY_MAX_RUNTIME_MODE",
    "AGY_RBAC_ROLE",
    "AGY_BOT_TEAM_ID",
    "AGY_AGENT_ORIGIN",
    "AGY_BOT_BUS_ROLE",
    "AGY_BOT_CHAIN",
    "AGY_BOT_CHAIN_ID",
    "AGY_BOT_SCOPE_KEY",
    "AGY_BOT_CHAT_ID",
    "AGY_BOT_THREAD_ID",
    "AGY_BOT_ORIGIN_MSG_ID",
    "AGY_BOT_MENTION_HOP",
    "AGY_FEDERATION_TOKEN",
    "AGY_FEDERATION_HUB_HOST",
    "AGY_FEDERATION_HUB_PORT",
    "AGY_FEDERATION_HUB_ALLOW_NON_LOOPBACK",
    "AGY_FEDERATION_ALLOW_REMOTE_HUB",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
)


def _clean_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    base = {k: v for k, v in os.environ.items() if k not in _SCRUB_ENV_KEYS}
    if extra:
        base.update(extra)
    return base


def _ip(*octets: int) -> str:
    return ".".join(str(x) for x in octets)


def _write_fake_hermes_script(path: Path) -> str:
    script = '''#!/usr/bin/env python3
import json, os, sys, time

argv = sys.argv[1:]
prompt = sys.stdin.read()
profile = os.environ.get("HERMES_PROFILE", "")

if "SLEEP_LONG" in prompt:
    print(json.dumps({"type": "system", "subtype": "init", "session_id": f"sess-{profile}"}), flush=True)
    time.sleep(30)
    sys.exit(0)

print(json.dumps({"type": "system", "subtype": "init", "session_id": f"sess-{profile}"}), flush=True)
out = {
    "profile": profile,
    "argv": argv,
    "prompt": prompt,
    "trust_level": os.environ.get("AGY_TRUST_LEVEL", ""),
    "untrusted": os.environ.get("AGY_UNTRUSTED_SESSION", ""),
    "rbac": os.environ.get("AGY_RBAC_ROLE", ""),
}
print(json.dumps({"type": "result", "status": "SUCCESS", "session_id": f"sess-{profile}", "response": json.dumps(out)}), flush=True)
'''
    path.write_text(script, encoding="utf-8")
    os.chmod(path, stat.S_IRWXU)
    return str(path)


class _RunningHub:
    """Context manager launching a real `FederationHubServer` bound to `127.0.0.1:0`."""

    def __init__(self, **kwargs: Any):
        kwargs.setdefault("host", "127.0.0.1")
        kwargs.setdefault("port", 0)
        self.server = hub.FederationHubServer(**kwargs)
        self.port = self.server.bound_port
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.02},
            daemon=True,
        )

    def __enter__(self) -> "_RunningHub":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.server.close_hub()
        self.thread.join(timeout=2.0)

    def request(
        self,
        method: str,
        path: str,
        *,
        token: Optional[str] = None,
        body: Any = None,
        raw_body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        sign_replay: bool = False,
        conn: Optional[http.client.HTTPConnection] = None,
    ) -> Tuple[int, Dict[str, str], Dict[str, Any]]:
        own_conn = conn is None
        c = conn or http.client.HTTPConnection("127.0.0.1", self.port, timeout=5.0)
        try:
            hdrs: Dict[str, str] = {}
            if raw_body is not None:
                payload_bytes = raw_body
            elif body is not None:
                payload_bytes = json.dumps(body).encode("utf-8")
                hdrs["Content-Type"] = "application/json"
            else:
                payload_bytes = b""
                if method.upper() in ("POST", "PUT", "PATCH"):
                    hdrs["Content-Type"] = "application/json"
            if token:
                hdrs["Authorization"] = f"Bearer {token}"
                if sign_replay:
                    hdrs.update(hub.build_replay_headers(token, method, path, payload_bytes))
            if headers:
                hdrs.update(headers)
            c.request(method, path, body=payload_bytes, headers=hdrs)
            resp = c.getresponse()
            resp_raw = resp.read()
            resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
            try:
                parsed = json.loads(resp_raw.decode("utf-8")) if resp_raw else {}
            except Exception:
                parsed = {"raw": resp_raw.decode("utf-8", errors="replace")}
            return resp.status, resp_hdrs, parsed
        finally:
            if own_conn:
                c.close()


# ==============================================================================
# M2-C1: Real-time zero-cache auth, <1s revocation, replay, DoS, stdio, Basic auth
# ==============================================================================
class TestM2C1AuthReplayDoSAndStdio(unittest.TestCase):
    def test_revoke_takes_effect_immediately_subsecond(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent("ext_a", kind="hermes_remote", endpoint_url="https://a.example.com", owner_auth=owner, bus_dir=tmp)
            fed.register_agent("ext_b", kind="hermes_remote", endpoint_url="https://b.example.com", owner_auth=owner, bus_dir=tmp)
            fed.register_agent("ext_c", kind="hermes_remote", endpoint_url="https://c.example.com", owner_auth=owner, bus_dir=tmp)
            tok_a = fed.mint_agent_token("ext_a", owner_auth=owner, bus_dir=tmp)["token"]
            tok_b = fed.mint_agent_token("ext_b", owner_auth=owner, bus_dir=tmp)["token"]
            tok_c = fed.mint_agent_token("ext_c", owner_auth=owner, bus_dir=tmp)["token"]

            with _RunningHub(bus_dir=tmp) as rh:
                # 1. Persistent HTTP/1.1 keep-alive connection: revoke_agent_token -> immediate 401
                conn = http.client.HTTPConnection("127.0.0.1", rh.port, timeout=5.0)
                try:
                    st1, _, _ = rh.request("GET", "/hub/v1/me", token=tok_a, conn=conn)
                    self.assertEqual(200, st1)
                    t0 = time.monotonic()
                    fed.revoke_agent_token("ext_a", owner_auth=owner, bus_dir=tmp)
                    st2, _, _ = rh.request("GET", "/hub/v1/me", token=tok_a, conn=conn)
                    elapsed = time.monotonic() - t0
                    self.assertEqual(401, st2)
                    self.assertLess(elapsed, 1.0)
                finally:
                    conn.close()

                # 2. revoke_agent -> immediate 401 across concurrent threads
                st_b1, _, _ = rh.request("GET", "/hub/v1/me", token=tok_b)
                self.assertEqual(200, st_b1)
                t1 = time.monotonic()
                fed.revoke_agent("ext_b", owner_auth=owner, bus_dir=tmp)
                with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                    codes = list(pool.map(lambda _: rh.request("GET", "/hub/v1/me", token=tok_b)[0], range(6)))
                self.assertTrue(all(c == 401 for c in codes), codes)
                self.assertLess(time.monotonic() - t1, 1.0)

                # 3. update_agent(enabled=False) -> immediate 401 on same keep-alive connection
                conn_c = http.client.HTTPConnection("127.0.0.1", rh.port, timeout=5.0)
                try:
                    self.assertEqual(200, rh.request("GET", "/hub/v1/me", token=tok_c, conn=conn_c)[0])
                    fed.update_agent("ext_c", enabled=False, owner_auth=owner, bus_dir=tmp)
                    self.assertEqual(401, rh.request("GET", "/hub/v1/me", token=tok_c, conn=conn_c)[0])
                finally:
                    conn_c.close()

    def test_replay_nonce_timestamp_and_bounded_cache(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent("rep_agent", kind="hermes_remote", endpoint_url="https://r.example.com", owner_auth=owner, bus_dir=tmp)
            tok = fed.mint_agent_token("rep_agent", owner_auth=owner, bus_dir=tmp)["token"]

            with _RunningHub(bus_dir=tmp, require_replay_headers=True, replay_window_sec=300.0, nonce_cache_max=5) as rh:
                # Missing replay headers when required -> 401
                st_miss, _, body_miss = rh.request("GET", "/hub/v1/me", token=tok)
                self.assertEqual(401, st_miss)
                self.assertEqual("REPLAY_HEADERS_INCOMPLETE", body_miss.get("error"))

                # Valid signed request -> 200
                fixed_hdrs = hub.build_replay_headers(tok, "GET", "/hub/v1/me", b"", nonce="nonce-unique-1")
                st_ok, _, _ = rh.request("GET", "/hub/v1/me", token=tok, headers=fixed_hdrs)
                self.assertEqual(200, st_ok)

                # Exact same nonce replayed -> 401
                st_dup, _, body_dup = rh.request("GET", "/hub/v1/me", token=tok, headers=fixed_hdrs)
                self.assertEqual(401, st_dup)
                self.assertEqual("REPLAY_NONCE_REUSED", body_dup.get("error"))

                # Expired timestamp (>300s old) -> 401
                old_hdrs = hub.build_replay_headers(tok, "GET", "/hub/v1/me", b"", timestamp=int(time.time()) - 400, nonce="nonce-old-1")
                st_old, _, body_old = rh.request("GET", "/hub/v1/me", token=tok, headers=old_hdrs)
                self.assertEqual(401, st_old)
                self.assertEqual("REPLAY_TIMESTAMP_EXPIRED", body_old.get("error"))

                # Tampered signature -> 401
                bad_hdrs = dict(hub.build_replay_headers(tok, "GET", "/hub/v1/me", b"", nonce="nonce-tamper-1"))
                bad_hdrs["X-Agy-Signature"] = "0" * 64
                st_sig, _, body_sig = rh.request("GET", "/hub/v1/me", token=tok, headers=bad_hdrs)
                self.assertEqual(401, st_sig)
                self.assertEqual("REPLAY_SIGNATURE_INVALID", body_sig.get("error"))

                # Bounded Nonce cache enforces max_entries=5 (zero OOM)
                for idx in range(12):
                    hdr_i = hub.build_replay_headers(tok, "GET", "/hub/v1/me", b"", nonce=f"nonce-cap-{idx}")
                    self.assertEqual(200, rh.request("GET", "/hub/v1/me", token=tok, headers=hdr_i)[0])
                self.assertLessEqual(len(rh.server.nonce_cache), 5)

    def test_body_limit_413_rate_limit_429_and_query_token_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent("dos_agent", kind="hermes_remote", endpoint_url="https://d.example.com", owner_auth=owner, bus_dir=tmp)
            tok = fed.mint_agent_token("dos_agent", owner_auth=owner, bus_dir=tmp)["token"]

            with _RunningHub(bus_dir=tmp, max_body_bytes=512, rate_limit_max_requests=3, rate_limit_window_sec=60.0) as rh:
                # 1. URL query string credentials rejected (400) and never echoed
                for qk in ("token", "access_token", "api_key"):
                    st_q, _, body_q = rh.request("GET", f"/hub/v1/me?{qk}={tok}")
                    self.assertEqual(400, st_q)
                    self.assertEqual("QUERY_TOKEN_FORBIDDEN", body_q.get("error"))
                    self.assertNotIn(tok, json.dumps(body_q))

                # 2. Request body > max_body_bytes -> 413
                big_payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "pad": "A" * 1024}).encode("utf-8")
                st_413, _, body_413 = rh.request(
                    "POST",
                    "/hub/mcp",
                    token=tok,
                    raw_body=big_payload,
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(413, st_413)
                self.assertEqual("PAYLOAD_TOO_LARGE", body_413.get("error"))

                # 3. Rate limit > 3 requests in window -> 429 + Retry-After header
                for _ in range(3):
                    self.assertEqual(200, rh.request("GET", "/hub/v1/me", token=tok)[0])
                st_429, hdrs_429, body_429 = rh.request("GET", "/hub/v1/me", token=tok)
                self.assertEqual(429, st_429)
                self.assertEqual("RATE_LIMIT_EXCEEDED", body_429.get("error"))
                self.assertIn("retry-after", hdrs_429)
                self.assertGreaterEqual(int(hdrs_429["retry-after"]), 1)

    def test_stdio_adapter_no_argv_token_no_proxy_loopback_only(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent("stdio_hermes", kind="hermes_local", profile="p1", owner_auth=owner, bus_dir=tmp)
            tok = fed.mint_agent_token("stdio_hermes", owner_auth=owner, bus_dir=tmp)["token"]

            # 1. CLI argv plaintext token flags MUST fail fast
            for bad_argv in (
                ["--token", tok],
                [f"--token={tok}"],
                ["-t", tok],
                ["--api-key", tok],
                [tok],
            ):
                with self.subTest(bad_argv=bad_argv[0][:10]):
                    with self.assertRaises(ValueError) as ce:
                        stdio_mcp.reject_cli_token_args(bad_argv)
                    self.assertIn("CLI_TOKEN_FORBIDDEN", str(ce.exception))
                    rc = stdio_mcp.main(bad_argv)
                    self.assertNotEqual(0, rc)

            # 2. Non-loopback Hub URL rejected by default, allowed with AGY_FEDERATION_ALLOW_REMOTE_HUB=1
            with self.assertRaises(ValueError) as cr:
                stdio_mcp.validate_hub_url("https://hub.example.com/hub/mcp", env={})
            self.assertIn("REMOTE_HUB_DENIED", str(cr.exception))
            self.assertEqual(
                "https://hub.example.com/hub/mcp",
                stdio_mcp.validate_hub_url("https://hub.example.com/hub/mcp", env={"AGY_FEDERATION_ALLOW_REMOTE_HUB": "1"}),
            )

            # 3. World-readable token-file rejected; chmod 600 token-file accepted
            tf = Path(tmp) / "agent_cred"
            tf.write_text(tok + "\n", encoding="utf-8")
            os.chmod(tf, 0o644)
            with self.assertRaises(PermissionError):
                stdio_mcp.load_federation_token(token_file=str(tf))
            os.chmod(tf, 0o600)
            self.assertEqual(tok, stdio_mcp.load_federation_token(token_file=str(tf)))

            # 4. Proxy bypass: works even with poisoned dead HTTP_PROXY/HTTPS_PROXY + signs replay headers
            with _RunningHub(bus_dir=tmp, require_replay_headers=True) as rh:
                poisoned_env = _clean_env(
                    {
                        "AGY_BOT_BUS_DIR": tmp,
                        "HTTP_PROXY": "http://127.0.0.1:1",
                        "HTTPS_PROXY": "http://127.0.0.1:1",
                        "AGY_FEDERATION_TOKEN": tok,
                    }
                )
                with mock.patch.dict(os.environ, poisoned_env, clear=True):
                    adapter = stdio_mcp.FederationMCPStdioAdapter(
                        hub_url=f"http://127.0.0.1:{rh.port}/hub/mcp",
                        token=stdio_mcp.load_federation_token(),
                    )
                    in_stream = io.StringIO(
                        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
                        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}) + "\n"
                    )
                    out_stream = io.StringIO()
                    self.assertEqual(0, adapter.serve_streams(in_stream, out_stream))
                    lines = [json.loads(ln) for ln in out_stream.getvalue().splitlines() if ln.strip()]
                    self.assertEqual(2, len(lines))
                    self.assertEqual("agy-federation-hub", lines[0]["result"]["serverInfo"]["name"])
                    self.assertEqual({}, lines[1]["result"])

    def test_inline_basic_auth_trailing_padding_rejected(self):
        b64_one_pad = base64.b64encode(b"abcdefgh").decode("ascii")  # 12 chars ending with '='
        b64_two_pad = base64.b64encode(b"user:pass1").decode("ascii")  # 16 chars ending with '=='
        self.assertTrue(b64_one_pad.endswith("="))
        self.assertTrue(b64_two_pad.endswith("=="))
        for raw_note in ("header Bas" + f"ic {b64_one_pad}", "header Bas" + f"ic {b64_two_pad}"):
            with self.assertRaises(ValueError) as ctx:
                fed.reject_plaintext_secrets({"note": raw_note}, path="metadata")
            self.assertIn("PLAINTEXT_SECRET_REJECTED", str(ctx.exception))
        # Benign prose still allowed
        fed.reject_plaintext_secrets({"note": "uses basic configuration overview"}, path="metadata")


# ==============================================================================
# M2-C2: Host Server Bridge 4-tuple eligibility + Lock 1
# ==============================================================================
class TestM2C2HostBridgeEligibilityAndLock1(unittest.TestCase):
    def _seed_host_admin_agent(self, tmp: str, owner: fed.OwnerAuth) -> str:
        fed.register_agent(
            "host_peer",
            kind="hermes_remote",
            endpoint_url="https://hp.example.com",
            trust_level="remote_trusted",
            capabilities={"coordinator_peer": True, "host_server_invoke": True, "can_dispatch": True},
            owner_auth=owner,
            bus_dir=tmp,
        )
        return fed.mint_agent_token("host_peer", owner_auth=owner, bus_dir=tmp)["token"]

    def test_host_tools_require_all_four_eligibility_conditions(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            cases = [
                ("missing_host_invoke", {"coordinator_peer": True, "host_server_invoke": False, "can_dispatch": True}, "remote_trusted", True),
                ("missing_coord_peer", {"coordinator_peer": False, "host_server_invoke": True, "can_dispatch": True}, "remote_trusted", True),
                ("untrusted_level", {"coordinator_peer": True, "host_server_invoke": True, "can_dispatch": True}, "remote_untrusted", True),
                ("readonly_level", {"coordinator_peer": True, "host_server_invoke": True, "can_dispatch": True}, "readonly_guest", True),
                ("disabled_agent", {"coordinator_peer": True, "host_server_invoke": True, "can_dispatch": True}, "local_worker", False),
            ]
            toks: Dict[str, str] = {}
            for aid, caps, trust, enabled in cases:
                fed.register_agent(
                    aid,
                    kind="hermes_remote",
                    endpoint_url=f"https://{aid}.example.com",
                    trust_level=trust,
                    capabilities=caps,
                    enabled=True,
                    owner_auth=owner,
                    bus_dir=tmp,
                )
                toks[aid] = fed.mint_agent_token(aid, owner_auth=owner, bus_dir=tmp)["token"]
                if not enabled:
                    fed.update_agent(aid, enabled=False, owner_auth=owner, bus_dir=tmp)

            ok_tok = self._seed_host_admin_agent(tmp, owner)
            safe_file = Path(tmp) / "hello.txt"
            safe_file.write_text("hi", encoding="utf-8")

            with _RunningHub(bus_dir=tmp, repo_root=tmp, home_dir=tmp) as rh:
                for aid, _caps, _trust, enabled in cases:
                    expected_code = 403 if enabled else 401
                    st_rest, _, _ = rh.request(
                        "POST",
                        "/hub/v1/host/files",
                        token=toks[aid],
                        body={"action": "stat", "path": str(safe_file)},
                    )
                    self.assertEqual(expected_code, st_rest, f"{aid} REST should be {expected_code}")
                    st_mcp, _, _ = rh.request(
                        "POST",
                        "/hub/mcp",
                        token=toks[aid],
                        body={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {"name": "host_files", "arguments": {"action": "stat", "path": str(safe_file)}},
                        },
                    )
                    self.assertEqual(expected_code, st_mcp, f"{aid} MCP should be {expected_code}")

                # All 4 conditions satisfied -> 200
                st_ok, _, body_ok = rh.request(
                    "POST",
                    "/hub/v1/host/files",
                    token=ok_tok,
                    body={"action": "read", "path": str(safe_file)},
                )
                self.assertEqual(200, st_ok)
                self.assertEqual("hi", body_ok["content"])

    def test_host_files_lock1_blocks_direct_traversal_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            tok = self._seed_host_admin_agent(tmp, owner)
            repo_dir = Path(tmp) / "repo"
            (repo_dir / "hooks").mkdir(parents=True)
            (repo_dir / "hooks" / "guard.py").write_text("# guard", encoding="utf-8")
            (repo_dir / ".agents" / "rules").mkdir(parents=True)
            (repo_dir / ".agents" / "rules" / "policy.md").write_text("# policy", encoding="utf-8")
            (repo_dir / "AGENTS.md").write_text("# agents", encoding="utf-8")
            (Path(tmp) / "team_config.json").write_text("{}", encoding="utf-8")

            # Symlinks pointing into Lock 1 directories/files
            sym_fed = Path(tmp) / "innocent_link"
            sym_fed.symlink_to(fed.federation_dir(tmp))
            sym_agents = Path(tmp) / "readme_copy.txt"
            sym_agents.symlink_to(fed.agents_file_path(tmp))

            blocked_targets = [
                fed.agents_file_path(tmp),
                str(Path(tmp) / "team_config.json"),
                str(repo_dir / "hooks" / "guard.py"),
                str(repo_dir / ".agents" / "rules" / "policy.md"),
                str(repo_dir / "AGENTS.md"),
                str(repo_dir / "sub" / ".." / ".." / "federation" / "agents.json"),
                str(sym_fed / "agents.json"),
                str(sym_fed / "new_evil.json"),
                str(sym_agents),
            ]
            with _RunningHub(bus_dir=tmp, repo_root=str(repo_dir), home_dir=tmp) as rh:
                for p in blocked_targets:
                    for act in ("read", "write"):
                        with self.subTest(path=p, action=act):
                            payload: Dict[str, Any] = {"action": act, "path": p}
                            if act == "write":
                                payload["content"] = "{}"
                            st, _, body = rh.request("POST", "/hub/v1/host/files", token=tok, body=payload)
                            self.assertEqual(403, st, body)
                            self.assertEqual("HOST_LOCK1_DENIED", body.get("error"))

    def test_host_exec_lock1_blocks_shell_chaining_env_expand_and_interpreters(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            tok = self._seed_host_admin_agent(tmp, owner)
            with _RunningHub(bus_dir=tmp, repo_root=tmp, home_dir=tmp) as rh:
                forbidden_cmds = [
                    {"command": "echo hi; id"},
                    {"command": "echo hi && whoami"},
                    {"command": "echo hi || whoami"},
                    {"command": "ls | cat"},
                    {"command": "echo $(whoami)"},
                    {"command": "echo `whoami`"},
                    {"command": "echo $HOME"},
                    {"command": "echo ${PATH}"},
                    {"command": "ls > /tmp/out.txt"},
                    {"argv": ["sh", "-c", "id"]},
                    {"argv": ["bash", "-c", "id"]},
                    {"argv": ["python3", "-c", "print(1)"]},
                    {"argv": ["perl", "-e", "print 1"]},
                    {"argv": ["node", "-e", "console.log(1)"]},
                    {"argv": ["env", "sh", "-c", "id"]},
                    {"argv": ["git", "-c", "core.sshCommand=id", "status"]},
                    {"argv": ["git", "config", "--list"]},
                    {"argv": ["cat", fed.agents_file_path(tmp)]},
                ]
                for payload in forbidden_cmds:
                    with self.subTest(payload=payload):
                        st, _, body = rh.request("POST", "/hub/v1/host/exec", token=tok, body=payload)
                        self.assertEqual(403, st, body)
                        self.assertEqual("HOST_LOCK1_DENIED", body.get("error"))

                # Safe allowlisted read-only command succeeds
                st_ok, _, body_ok = rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["echo", "safe_ping"]})
                self.assertEqual(200, st_ok)
                self.assertIn("safe_ping", body_ok["stdout"])


# ==============================================================================
# M2-C3: Lock 2 Vault/Credentials + Lock 3 Protected Assets & Safe Reload
# ==============================================================================
class TestM2C3Lock2AndLock3(unittest.TestCase):
    def _setup(self, tmp: str):
        owner = fed.make_owner_auth("owner")
        fed.register_agent(
            "host_peer",
            kind="hermes_remote",
            endpoint_url="https://hp.example.com",
            trust_level="remote_trusted",
            capabilities={"coordinator_peer": True, "host_server_invoke": True, "can_dispatch": True},
            owner_auth=owner,
            bus_dir=tmp,
        )
        tok = fed.mint_agent_token("host_peer", owner_auth=owner, bus_dir=tmp)["token"]
        return owner, tok

    def test_host_lock2_blocks_bao_vault_env_token_ssh_and_proc_environ(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            _owner, tok = self._setup(tmp)
            home_dir = Path(tmp) / "fake_home"
            (home_dir / ".ssh").mkdir(parents=True)
            (home_dir / ".ssh" / "id_ed25519").write_text("dummy", encoding="utf-8")
            (home_dir / ".config" / "agy-tg-bridge").mkdir(parents=True)
            (home_dir / ".config" / "agy-tg-bridge" / "bot.env").write_text("X=1", encoding="utf-8")
            (home_dir / ".hermes").mkdir(parents=True)
            (home_dir / ".hermes" / ".env").write_text("Y=2", encoding="utf-8")
            (Path(tmp) / "prod.token").write_text("tok", encoding="utf-8")
            (Path(tmp) / "cert.pem").write_text("pem", encoding="utf-8")
            (Path(tmp) / "priv.key").write_text("key", encoding="utf-8")

            with _RunningHub(bus_dir=tmp, repo_root=tmp, home_dir=str(home_dir)) as rh:
                # Lock 2 commands
                for cmd_payload in (
                    {"argv": ["bao", "status"]},
                    {"argv": ["vault", "status"]},
                    {"argv": ["env", "bao", "status"]},
                    {"argv": ["cat", "/proc/self/environ"]},
                    {"argv": ["cat", f"/proc/{os.getpid()}/environ"]},
                    {"argv": ["cat", str(home_dir / ".hermes" / ".env")]},
                ):
                    with self.subTest(cmd=cmd_payload):
                        st, _, body = rh.request("POST", "/hub/v1/host/exec", token=tok, body=cmd_payload)
                        self.assertEqual(403, st, body)
                        self.assertEqual("HOST_LOCK2_DENIED", body.get("error"))

                # Lock 2 files
                for fp in (
                    str(home_dir / ".ssh" / "id_ed25519"),
                    str(home_dir / ".config" / "agy-tg-bridge" / "bot.env"),
                    str(home_dir / ".hermes" / ".env"),
                    str(Path(tmp) / "prod.token"),
                    str(Path(tmp) / "cert.pem"),
                    str(Path(tmp) / "priv.key"),
                    "/proc/self/environ",
                    f"/proc/{os.getpid()}/environ",
                ):
                    with self.subTest(file=fp):
                        st, _, body = rh.request("POST", "/hub/v1/host/files", token=tok, body={"action": "read", "path": fp})
                        self.assertEqual(403, st, body)
                        self.assertEqual("HOST_LOCK2_DENIED", body.get("error"))

    def test_host_exec_strips_sensitive_env_vars_in_child_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_vault = "hvs." + "StrippedVault123456"
            fake_gh = "ghp_" + "StrippedGh1234567890abcd"
            fake_sk = "sk-" + "StrippedOpenAI1234567890"
            fake_tg = "12345678" + ":" + ("t" * 35)
            env_with_secrets = _clean_env(
                {
                    "AGY_BOT_BUS_DIR": tmp,
                    "VAULT_TOKEN": fake_vault,
                    "BAO_TOKEN": fake_vault,
                    "GH_TOKEN": fake_gh,
                    "GITHUB_TOKEN": fake_gh,
                    "TG_BOT_TOKEN": fake_tg,
                    "OPENAI_API_KEY": fake_sk,
                    "MY_CUSTOM_SECRET": "must-not-appear",
                    "SAFE_PUBLIC_MARKER": "visible-ok-value",
                }
            )
            with mock.patch.dict(os.environ, env_with_secrets, clear=True):
                _owner, tok = self._setup(tmp)
                with _RunningHub(bus_dir=tmp, repo_root=tmp, home_dir=tmp) as rh:
                    st, _, body = rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["env"]})
                    self.assertEqual(200, st, body)
                    out = body["stdout"]
                    self.assertIn("SAFE_PUBLIC_MARKER=visible-ok-value", out)
                    for forbidden in (
                        "VAULT_TOKEN",
                        "BAO_TOKEN",
                        "GH_TOKEN",
                        "GITHUB_TOKEN",
                        "TG_BOT_TOKEN",
                        "OPENAI_API_KEY",
                        "MY_CUSTOM_SECRET",
                        fake_vault,
                        fake_gh,
                        fake_sk,
                        "must-not-appear",
                    ):
                        self.assertNotIn(forbidden, out)

    def test_host_lock3_blocks_protected_files_and_fisherwseven_profile(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            _owner, tok = self._setup(tmp)
            home_dir = Path(tmp) / "fake_home"
            repo_dir = Path(tmp) / "repo"
            gb = repo_dir / ".agents" / "skills" / "google-profile" / "scripts" / "google_browser.py"
            gb.parent.mkdir(parents=True)
            gb.write_text("# protected", encoding="utf-8")
            idx = repo_dir / ".agents" / "skills" / "live-browser" / "scripts" / "static" / "index.html"
            idx.parent.mkdir(parents=True)
            idx.write_text("<html></html>", encoding="utf-8")
            prof = home_dir / ".local" / "share" / "camoufox-profiles" / "fisherwseven"
            prof.mkdir(parents=True)
            (prof / "prefs.js").write_text("// prefs", encoding="utf-8")
            cache_prof = home_dir / ".cache" / "camoufox-profiles" / "fisherwseven"
            cache_prof.parent.mkdir(parents=True)
            cache_prof.symlink_to(prof)
            sym_escape = Path(tmp) / "my_browser_link"
            sym_escape.symlink_to(prof)
            unit_file = repo_dir / "systemd" / "agy-tg-bridge.service"
            unit_file.parent.mkdir(parents=True)
            unit_file.write_text("[Unit]\n", encoding="utf-8")

            with _RunningHub(bus_dir=tmp, repo_root=str(repo_dir), home_dir=str(home_dir)) as rh:
                for target in (
                    str(gb),
                    str(idx),
                    str(prof / "prefs.js"),
                    str(cache_prof / "prefs.js"),
                    str(sym_escape / "prefs.js"),
                    str(unit_file),
                ):
                    with self.subTest(lock3_path=target):
                        st, _, body = rh.request("POST", "/hub/v1/host/files", token=tok, body={"action": "read", "path": target})
                        self.assertEqual(403, st, body)
                        self.assertEqual("HOST_LOCK3_DENIED", body.get("error"))
                        st_e, _, body_e = rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["cat", target]})
                        self.assertEqual(403, st_e, body_e)
                        self.assertEqual("HOST_LOCK3_DENIED", body_e.get("error"))

    def test_host_services_readonly_and_sentinel_only_forbids_bridge_restart(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            _owner, tok = self._setup(tmp)
            sentinel_dir = Path(tmp) / "sentinels"
            with _RunningHub(bus_dir=tmp, repo_root=tmp, home_dir=tmp, reload_sentinel_dir=str(sentinel_dir)) as rh:
                # Mutating actions strictly forbidden with HOST_LOCK3_DENIED
                for bad_act in ("restart", "stop", "start", "edit", "daemon-reload", "kill"):
                    st, _, body = rh.request(
                        "POST",
                        "/hub/v1/host/services",
                        token=tok,
                        body={"action": bad_act, "service": "agy-tg-bridge.service"},
                    )
                    self.assertEqual(403, st, body)
                    self.assertEqual("HOST_LOCK3_DENIED", body.get("error"))

                # Non-whitelisted unit name or injection rejected (400)
                for bad_svc in ("sshd.service", "agy-tg-bridge;id", "../etc/passwd", "nginx.service"):
                    st_u, _, _ = rh.request(
                        "POST",
                        "/hub/v1/host/services",
                        token=tok,
                        body={"action": "status", "service": bad_svc},
                    )
                    self.assertEqual(400, st_u)

                # Direct systemctl via host_exec blocked by Lock 3
                st_sx, _, body_sx = rh.request(
                    "POST",
                    "/hub/v1/host/exec",
                    token=tok,
                    body={"argv": ["systemctl", "restart", "agy-tg-bridge"]},
                )
                self.assertEqual(403, st_sx)
                self.assertEqual("HOST_LOCK3_DENIED", body_sx.get("error"))

                # Safe reload uses sentinel file ONLY (never calls systemctl restart)
                with mock.patch.object(hub.subprocess, "run") as m_run:
                    st_rel, _, body_rel = rh.request(
                        "POST",
                        "/hub/v1/host/services",
                        token=tok,
                        body={"action": "reload", "service": "agy-tg-bridge.service"},
                    )
                    self.assertEqual(200, st_rel, body_rel)
                    self.assertEqual("sentinel", body_rel["method"])
                    self.assertTrue((sentinel_dir / "agy_bridge_reload").is_file())
                    m_run.assert_not_called()

                # Reload on non-bridge service denied
                st_r2, _, body_r2 = rh.request(
                    "POST",
                    "/hub/v1/host/services",
                    token=tok,
                    body={"action": "reload", "service": "agy-live-browser.service"},
                )
                self.assertEqual(403, st_r2)
                self.assertEqual("HOST_LOCK3_DENIED", body_r2.get("error"))

                # Read-only status uses shell=False without mutation
                fake_proc = mock.Mock(returncode=0, stdout="active (running)\n", stderr="")
                with mock.patch.object(hub.subprocess, "run", return_value=fake_proc) as m_run:
                    st_st, _, body_st = rh.request(
                        "POST",
                        "/hub/v1/host/services",
                        token=tok,
                        body={"action": "status", "service": "agy-tg-bridge"},
                    )
                    self.assertEqual(200, st_st)
                    self.assertIn("active", body_st["stdout"])
                    self.assertFalse(m_run.call_args.kwargs.get("shell", False))


# ==============================================================================
# M2-C4: capabilities (can_dispatch / can_receive / allowed_teams) + legacy compat
# ==============================================================================
class TestM2C4CapabilitiesConsistency(unittest.TestCase):
    def test_can_dispatch_false_blocked_across_mcp_rest_and_bus(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            # Even with coordinator_peer=True and leader_agent_id, explicit can_dispatch=False MUST block everywhere
            fed.register_agent(
                "no_disp_lead",
                kind="hermes_remote",
                endpoint_url="https://nd.example.com",
                capabilities={"coordinator_peer": True, "can_dispatch": False},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.register_agent("worker_a", kind="hermes_local", profile="wa", owner_auth=owner, bus_dir=tmp)
            fed.create_team("team-alpha", leader_agent_id="no_disp_lead", members=["no_disp_lead", "worker_a"], owner_auth=owner, bus_dir=tmp)
            tok = fed.mint_agent_token("no_disp_lead", owner_auth=owner, bus_dir=tmp)["token"]

            # 1. Direct bot_bus denied
            with hub._with_bot_bus_dir(tmp):
                with self.assertRaises(PermissionError) as cb:
                    bot_bus.dispatch_assignments(
                        "no_disp_lead",
                        [{"bot": "worker_a", "prompt": "blocked"}],
                        team_id="team-alpha",
                        auth_token=tok,
                    )
                self.assertIn("can_dispatch=False", str(cb.exception))

            with _RunningHub(bus_dir=tmp) as rh:
                # 2. REST /hub/v1/dispatch denied (403)
                st_r, _, _ = rh.request(
                    "POST",
                    "/hub/v1/dispatch",
                    token=tok,
                    body={"bot": "worker_a", "prompt": "blocked", "team_id": "team-alpha"},
                )
                self.assertEqual(403, st_r)

                # 3. Hub MCP tools/list omits team_dispatch and direct tools/call denied (403 / -32003)
                st_l, _, body_l = rh.request("POST", "/hub/mcp", token=tok, body={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                self.assertEqual(200, st_l)
                names = {t["name"] for t in body_l["result"]["tools"]}
                self.assertNotIn("team_dispatch", names)
                self.assertNotIn("team_job", names)

                st_c, _, body_c = rh.request(
                    "POST",
                    "/hub/mcp",
                    token=tok,
                    body={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "team_dispatch", "arguments": {"bot": "worker_a", "prompt": "hi"}},
                    },
                )
                self.assertEqual(403, st_c)
                self.assertEqual(-32003, body_c["error"]["code"])

            # 4. Local stdio bot_bus_mcp also omits & blocks team_dispatch
            env_mcp = _clean_env(
                {
                    "AGY_BOT_BUS_DIR": tmp,
                    "AGY_BOT_BUS_ENABLE": "1",
                    "AGY_BOT_BUS_ROLE": "coordinator",
                    "AGY_BOT_HANDLE": "no_disp_lead",
                    "AGY_FEDERATION_TOKEN": tok,
                }
            )
            with mock.patch.dict(os.environ, env_mcp, clear=True):
                import bot_bus_mcp  # noqa: E402
                importlib.reload(bot_bus)
                importlib.reload(bot_bus_mcp)
                self.assertEqual("worker", bot_bus_mcp._bus_role())
                with self.assertRaises(PermissionError):
                    bot_bus_mcp._handle_team_dispatch({"bot": "worker_a", "prompt": "blocked", "team_id": "team-alpha"})

    def test_can_receive_false_target_rejected_zero_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent(
                "lead_a",
                kind="hermes_remote",
                endpoint_url="https://la.example.com",
                capabilities={"can_dispatch": True},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.register_agent(
                "no_recv_target",
                kind="http_a2a",
                transport="pull_worker",
                capabilities={"can_receive": False},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.create_team("team-alpha", leader_agent_id="lead_a", members=["lead_a", "no_recv_target"], owner_auth=owner, bus_dir=tmp)
            tok = fed.mint_agent_token("lead_a", owner_auth=owner, bus_dir=tmp)["token"]

            with _RunningHub(bus_dir=tmp) as rh:
                st, _, body = rh.request(
                    "POST",
                    "/hub/v1/dispatch",
                    token=tok,
                    body={"bot": "no_recv_target", "prompt": "should fail", "team_id": "team-alpha"},
                )
                self.assertEqual(403, st, body)

            # PullWorkerQueue direct enqueue also rejects can_receive=False
            q = fed.PullWorkerQueue(tmp)
            with self.assertRaises(PermissionError):
                q.enqueue("no_recv_target", "direct pull fail", team_id="team-alpha", owner_auth=owner)

            # Zero job files, zero inbox packets, zero pull_queue job files created
            jobs_dir = Path(tmp) / "jobs"
            inbox_dir = Path(tmp) / "inbox" / "no_recv_target"
            pull_dir = Path(fed.pull_queue_dir(tmp))
            self.assertEqual([], list(jobs_dir.glob("*.json")) if jobs_dir.is_dir() else [])
            self.assertEqual([], list(inbox_dir.glob("*.json")) if inbox_dir.is_dir() else [])
            self.assertEqual([], list(pull_dir.glob("*.json")) if pull_dir.is_dir() else [])

    def test_allowed_teams_enforced_even_for_coordinator_peer(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent(
                "clamped_peer",
                kind="hermes_remote",
                endpoint_url="https://cp.example.com",
                capabilities={"coordinator_peer": True, "can_dispatch": True, "allowed_teams": ["team-alpha"]},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.register_agent("worker_a", kind="hermes_local", profile="wa", owner_auth=owner, bus_dir=tmp)
            fed.register_agent("worker_b", kind="hermes_local", profile="wb", owner_auth=owner, bus_dir=tmp)
            fed.create_team("team-alpha", leader_agent_id="clamped_peer", members=["clamped_peer", "worker_a"], owner_auth=owner, bus_dir=tmp)
            fed.create_team("team-beta", leader_agent_id="clamped_peer", members=["clamped_peer", "worker_b"], owner_auth=owner, bus_dir=tmp)
            tok = fed.mint_agent_token("clamped_peer", owner_auth=owner, bus_dir=tmp)["token"]

            with _RunningHub(bus_dir=tmp) as rh:
                # Visible teams strictly clamped to ["team-alpha"]
                st_t, _, body_t = rh.request("GET", "/hub/v1/teams", token=tok)
                self.assertEqual(200, st_t)
                self.assertEqual(["team-alpha"], [t["team_id"] for t in body_t["teams"]])

                # Dispatch to team-alpha -> ALLOWED
                st_a, _, _ = rh.request(
                    "POST",
                    "/hub/v1/dispatch",
                    token=tok,
                    body={"bot": "worker_a", "prompt": "alpha ok", "team_id": "team-alpha"},
                )
                self.assertEqual(200, st_a)

                # Dispatch to team-beta (even though coordinator_peer=True AND leader_agent_id of team-beta!) -> DENIED
                st_b, _, body_b = rh.request(
                    "POST",
                    "/hub/v1/dispatch",
                    token=tok,
                    body={"bot": "worker_b", "prompt": "beta denied", "team_id": "team-beta"},
                )
                self.assertEqual(403, st_b, body_b)

    def test_legacy_non_federated_dispatch_backward_compatible(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            with hub._with_bot_bus_dir(tmp):
                bot_bus.update_bot_config("legacy_coord", role="coordinator")
                bot_bus.update_bot_config("legacy_worker", role="worker")
                bot_bus.heartbeat_bot({"handle": "legacy_coord", "pid": os.getpid(), "role": "coordinator"})
                bot_bus.heartbeat_bot({"handle": "legacy_worker", "pid": os.getpid(), "role": "worker"})
                self.assertFalse(os.path.exists(fed.federation_dir(tmp)))

                res = bot_bus.dispatch_assignments("legacy_coord", [{"bot": "legacy_worker", "prompt": "legacy work"}])
                self.assertEqual(1, len(res["jobs"]))
                self.assertFalse(os.path.exists(fed.federation_dir(tmp)))


# ==============================================================================
# M2-C5: Pull Worker cross-agent 403, concurrent claim-once, 409, bot_bus sync
# ==============================================================================
class TestM2C5PullWorkerEndpointsAndSync(unittest.TestCase):
    def _seed_pull_setup(self, tmp: str):
        owner = fed.make_owner_auth("owner")
        fed.register_agent(
            "coord_lead",
            kind="hermes_remote",
            endpoint_url="https://cl.example.com",
            capabilities={"coordinator_peer": True, "can_dispatch": True},
            owner_auth=owner,
            bus_dir=tmp,
        )
        fed.register_agent("pull_w1", kind="http_a2a", transport="pull_worker", owner_auth=owner, bus_dir=tmp)
        fed.register_agent("pull_w2", kind="http_a2a", transport="pull_worker", owner_auth=owner, bus_dir=tmp)
        fed.create_team("team-nat", leader_agent_id="coord_lead", members=["coord_lead", "pull_w1", "pull_w2"], owner_auth=owner, bus_dir=tmp)
        t_lead = fed.mint_agent_token("coord_lead", owner_auth=owner, bus_dir=tmp)["token"]
        t_w1 = fed.mint_agent_token("pull_w1", owner_auth=owner, bus_dir=tmp)["token"]
        t_w2 = fed.mint_agent_token("pull_w2", owner_auth=owner, bus_dir=tmp)["token"]
        return owner, t_lead, t_w1, t_w2

    def test_pull_worker_cross_agent_inbox_claim_result_403(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner, _t_lead, t_w1, t_w2 = self._seed_pull_setup(tmp)
            q = fed.PullWorkerQueue(tmp)
            job = q.enqueue("pull_w1", "secret pull job", team_id="team-nat", owner_auth=owner)
            jid = job["job_id"]

            with _RunningHub(bus_dir=tmp) as rh:
                # w2 reading w1's inbox -> 403
                self.assertEqual(403, rh.request("GET", "/hub/v1/agents/pull_w1/inbox", token=t_w2)[0])
                # w2 claiming w1's job -> 403
                self.assertEqual(403, rh.request("POST", f"/hub/v1/jobs/{jid}/claim", token=t_w2, body={})[0])
                # w1 claims legitimately -> 200
                self.assertEqual(200, rh.request("POST", f"/hub/v1/jobs/{jid}/claim", token=t_w1, body={})[0])
                # w2 submitting result for w1's job -> 403
                self.assertEqual(
                    403,
                    rh.request("POST", f"/hub/v1/jobs/{jid}/result", token=t_w2, body={"status": "done", "result_text": "hijack"})[0],
                )

    def test_pull_worker_concurrent_claim_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner, _t_lead, t_w1, _t_w2 = self._seed_pull_setup(tmp)
            q = fed.PullWorkerQueue(tmp)
            jid = q.enqueue("pull_w1", "race me", team_id="team-nat", owner_auth=owner)["job_id"]

            with _RunningHub(bus_dir=tmp) as rh:
                def _try_claim(_idx: int) -> int:
                    return rh.request("POST", f"/hub/v1/jobs/{jid}/claim", token=t_w1, body={})[0]

                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                    codes = list(pool.map(_try_claim, range(10)))
                self.assertEqual(1, codes.count(200), f"Expected exactly 1 200 winner, got {codes}")
                self.assertEqual(9, codes.count(409), f"Expected 9 409 conflicts, got {codes}")

    def test_pull_worker_cancelled_unclaimed_and_duplicate_result_409(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner, _t_lead, t_w1, _t_w2 = self._seed_pull_setup(tmp)
            q = fed.PullWorkerQueue(tmp)
            j_unclaimed = q.enqueue("pull_w1", "unclaimed task", team_id="team-nat", owner_auth=owner)["job_id"]
            j_cancelled = q.enqueue("pull_w1", "cancelled task", team_id="team-nat", owner_auth=owner)["job_id"]
            q.cancel(j_cancelled, owner_auth=owner)

            with _RunningHub(bus_dir=tmp) as rh:
                # 1. Invalid status -> 400
                self.assertEqual(
                    400,
                    rh.request("POST", f"/hub/v1/jobs/{j_unclaimed}/result", token=t_w1, body={"status": "running"})[0],
                )
                # 2. Unclaimed result -> 409
                self.assertEqual(
                    409,
                    rh.request("POST", f"/hub/v1/jobs/{j_unclaimed}/result", token=t_w1, body={"status": "done", "result_text": "early"})[0],
                )
                # 3. Cancelled job claim & result -> 409
                self.assertEqual(409, rh.request("POST", f"/hub/v1/jobs/{j_cancelled}/claim", token=t_w1, body={})[0])
                self.assertEqual(
                    409,
                    rh.request("POST", f"/hub/v1/jobs/{j_cancelled}/result", token=t_w1, body={"status": "done"})[0],
                )
                # 4. Claim -> complete -> duplicate result -> 409
                self.assertEqual(200, rh.request("POST", f"/hub/v1/jobs/{j_unclaimed}/claim", token=t_w1, body={})[0])
                self.assertEqual(
                    200,
                    rh.request("POST", f"/hub/v1/jobs/{j_unclaimed}/result", token=t_w1, body={"status": "done", "result_text": "ok"})[0],
                )
                self.assertEqual(
                    409,
                    rh.request("POST", f"/hub/v1/jobs/{j_unclaimed}/result", token=t_w1, body={"status": "done", "result_text": "dup"})[0],
                )

    def test_pull_worker_result_syncs_bot_bus_finish_and_batch_done(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            _owner, t_lead, t_w1, _t_w2 = self._seed_pull_setup(tmp)
            disp = hub.ExternalWorkerDispatcher(bus_dir=tmp)

            with _RunningHub(bus_dir=tmp) as rh:
                # Leader dispatches async job to pull_w1
                st_d, _, body_d = rh.request(
                    "POST",
                    "/hub/v1/dispatch",
                    token=t_lead,
                    body={"bot": "pull_w1", "prompt": "run nat audit", "team_id": "team-nat", "wait": False},
                )
                self.assertEqual(200, st_d, body_d)
                jid = body_d["jobs"][0]["job_id"]

                # Outbound dispatcher bridges bot_bus job -> PullWorkerQueue
                stats = disp.poll_once()
                self.assertEqual(1, stats["bridged_pull"])

                # Worker sees job in inbox, claims it, submits result
                st_i, _, body_i = rh.request("GET", "/hub/v1/agents/pull_w1/inbox", token=t_w1)
                self.assertEqual(200, st_i)
                self.assertEqual([jid], [j["job_id"] for j in body_i["jobs"]])

                self.assertEqual(200, rh.request("POST", f"/hub/v1/jobs/{jid}/claim", token=t_w1, body={})[0])
                st_res, _, body_res = rh.request(
                    "POST",
                    f"/hub/v1/jobs/{jid}/result",
                    token=t_w1,
                    body={"status": "done", "result_text": "nat audit clean"},
                )
                self.assertEqual(200, st_res, body_res)
                self.assertTrue(body_res["bus_synced"])

                # bot_bus job converged to done + batch_notified=True + exactly 1 batch_done packet
                with hub._with_bot_bus_dir(tmp):
                    bus_job = bot_bus.get_job(jid)
                    self.assertEqual("done", bus_job["status"])
                    self.assertEqual("nat audit clean", bus_job["result_text"])
                    self.assertTrue(bus_job["batch_notified"])
                    pkts = bot_bus.pop_inbox_packets("coord_lead")
                    batch_pkts = [p for p in pkts if p.get("type") == "batch_done"]
                    self.assertEqual(1, len(batch_pkts))
                    self.assertEqual([jid], batch_pkts[0]["job_ids"])


# ==============================================================================
# M2-C6: Hermes re-entry guard, Outbound Dispatcher, cancel prop, non-agy batch_done
# ==============================================================================
class TestM2C6OutboundDispatcherAndHermesReentry(unittest.TestCase):
    def test_hermes_local_send_user_prompt_blocks_concurrent_reentry(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = _write_fake_hermes_script(Path(tmp) / "hermes")
            drv = ext.HermesLocalDriver()
            sess = drv.spawn_session(
                None,
                "safe",
                None,
                None,
                profile="reentry_p",
                hermes_bin=fake_bin,
                allowed_bins=[fake_bin],
                workdir=tmp,
                scope_key="hermes:reentry",
            )
            try:
                sess.send_user_prompt("SLEEP_LONG")
                first_proc = sess.proc
                self.assertIsNotNone(first_proc)

                # Concurrent second call while turn is active MUST fail immediately with RuntimeError
                with self.assertRaises(RuntimeError) as cr:
                    sess.send_user_prompt("second overlapping turn")
                self.assertIn("active turn", str(cr.exception))
                # Original subprocess untouched
                self.assertIs(first_proc, sess.proc)
            finally:
                sess.close()

    def test_outbound_dispatcher_skips_agy_local_and_disabled_or_no_receive(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent("agy_worker", kind="agy_local", owner_auth=owner, bus_dir=tmp)
            fed.register_agent("ext_disabled", kind="hermes_local", profile="p1", enabled=False, owner_auth=owner, bus_dir=tmp)
            fed.register_agent("ext_no_recv", kind="hermes_local", profile="p2", capabilities={"can_receive": False}, owner_auth=owner, bus_dir=tmp)

            # Seed queued jobs directly in bot_bus for all three
            with hub._with_bot_bus_dir(tmp):
                bot_bus.dispatch_jobs_in_dir(
                    tmp,
                    "owner_coord",
                    [
                        {"bot": "agy_worker", "prompt": "local agy task"},
                        {"bot": "ext_disabled", "prompt": "disabled task"},
                        {"bot": "ext_no_recv", "prompt": "no receive task"},
                    ],
                )
                disp = hub.ExternalWorkerDispatcher(bus_dir=tmp)
                stats = disp.poll_once()
                self.assertEqual(0, stats["dispatched"])
                self.assertEqual(0, stats["bridged_pull"])
                # All three jobs remain untouched ("queued")
                for j in bot_bus.list_jobs(limit=10):
                    self.assertEqual("queued", j["status"])

    def test_outbound_dispatcher_monotonic_trust_and_cancel_propagation(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            fake_bin = _write_fake_hermes_script(Path(tmp) / "hermes")
            owner = fed.make_owner_auth("owner")
            fed.register_agent(
                "lead_local",
                kind="agy_local",
                capabilities={"coordinator_peer": True, "can_dispatch": True},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.register_agent(
                "hermes_w1",
                kind="hermes_local",
                profile="w1",
                trust_level="local_worker",
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.create_team("team-dev", leader_agent_id="lead_local", members=["lead_local", "hermes_w1"], owner_auth=owner, bus_dir=tmp)

            disp = hub.ExternalWorkerDispatcher(
                bus_dir=tmp,
                driver_kwargs_factory=lambda _ag, _job: {
                    "hermes_bin": fake_bin,
                    "allowed_bins": [fake_bin],
                    "allow_yolo": True,
                    "workdir": tmp,
                },
            )
            try:
                # 1. Tainted/untrusted job MUST downgrade to safe mode & NEVER pass --yolo
                with hub._with_bot_bus_dir(tmp):
                    res1 = bot_bus.dispatch_assignments(
                        "lead_local",
                        [{"bot": "hermes_w1", "prompt": "inspect untrusted", "mode": "auto", "untrusted": True}],
                        team_id="team-dev",
                    )
                jid1 = res1["jobs"][0]["job_id"]
                disp.poll_once()
                deadline = time.monotonic() + 8.0
                j1 = None
                while time.monotonic() < deadline:
                    with hub._with_bot_bus_dir(tmp):
                        j1 = bot_bus.get_job(jid1)
                    if j1 and j1["status"] in bot_bus.TERMINAL_STATUSES:
                        break
                    time.sleep(0.05)
                self.assertEqual("done", j1["status"], j1)
                echoed = json.loads(j1["result_text"])
                self.assertIn("--safe-mode", echoed["argv"])
                self.assertNotIn("--yolo", echoed["argv"])
                self.assertEqual("1", echoed["untrusted"])

                # 2. Cancel propagation terminates running Hermes subprocess and converges to cancelled
                with hub._with_bot_bus_dir(tmp):
                    res2 = bot_bus.dispatch_assignments(
                        "lead_local",
                        [{"bot": "hermes_w1", "prompt": "SLEEP_LONG cancel test"}],
                        team_id="team-dev",
                    )
                jid2 = res2["jobs"][0]["job_id"]
                disp.poll_once()
                t_start = time.monotonic()
                while time.monotonic() - t_start < 5.0:
                    with hub._with_bot_bus_dir(tmp):
                        cur2 = bot_bus.get_job(jid2) or {}
                    if cur2.get("status") == "running":
                        break
                    time.sleep(0.05)
                with hub._with_bot_bus_dir(tmp):
                    bot_bus.cancel_job(jid2, requester_bot="lead_local", reason="abort_now")
                t_end = time.monotonic()
                j2 = None
                while time.monotonic() - t_end < 6.0:
                    with hub._with_bot_bus_dir(tmp):
                        j2 = bot_bus.get_job(jid2)
                    if j2 and j2.get("status") in bot_bus.TERMINAL_STATUSES:
                        break
                    time.sleep(0.05)
                self.assertEqual("cancelled", j2["status"], j2)
            finally:
                disp.stop()

    def test_non_agy_leader_receives_batch_done_wakeup(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            fake_bin = _write_fake_hermes_script(Path(tmp) / "hermes")
            owner = fed.make_owner_auth("owner")
            fed.register_agent(
                "hermes_leader",
                kind="hermes_remote",
                endpoint_url="https://hl.example.com",
                trust_level="remote_trusted",
                capabilities={"can_dispatch": True},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.register_agent("hermes_worker", kind="hermes_local", profile="hw", owner_auth=owner, bus_dir=tmp)
            fed.create_team("team-ext", leader_agent_id="hermes_leader", members=["hermes_leader", "hermes_worker"], owner_auth=owner, bus_dir=tmp)
            tok_leader = fed.mint_agent_token("hermes_leader", owner_auth=owner, bus_dir=tmp)["token"]

            delivered_events: List[Dict[str, Any]] = []
            disp = hub.ExternalWorkerDispatcher(
                bus_dir=tmp,
                driver_kwargs_factory=lambda _ag, _job: {
                    "hermes_bin": fake_bin,
                    "allowed_bins": [fake_bin],
                    "workdir": tmp,
                },
                batch_done_callback=lambda aid, ev, _ag: delivered_events.append({"agent_id": aid, "event": ev}),
            )

            with _RunningHub(bus_dir=tmp) as rh:
                # Non-agy leader dispatches async job (wake_on_async=True)
                st_d, _, body_d = rh.request(
                    "POST",
                    "/hub/v1/dispatch",
                    token=tok_leader,
                    body={"bot": "hermes_worker", "prompt": "do ext task", "team_id": "team-ext", "wait": False},
                )
                self.assertEqual(200, st_d, body_d)
                jid = body_d["jobs"][0]["job_id"]

                # Poll to dispatch worker, wait for completion, then poll to deliver batch_done wakeup
                disp.poll_once()
                deadline = time.monotonic() + 8.0
                while time.monotonic() < deadline:
                    with hub._with_bot_bus_dir(tmp):
                        if (bot_bus.get_job(jid) or {}).get("status") == "done":
                            break
                    time.sleep(0.05)

                stats2 = disp.poll_once()
                self.assertEqual(1, stats2["batch_done"])
                self.assertEqual(1, len(delivered_events))
                ev = delivered_events[0]["event"]
                self.assertEqual("batch_done", ev["type"])
                self.assertEqual([jid], ev["job_ids"])
                self.assertTrue(ev["tainted"])  # remote leader origin preserves tainted flag
                self.assertEqual(1, len(ev["jobs"]))

                # Also visible on non-agy leader's /hub/v1/agents/{id}/inbox without Telegram Bridge
                st_in, _, body_in = rh.request("GET", "/hub/v1/agents/hermes_leader/inbox", token=tok_leader)
                self.assertEqual(200, st_in)
                self.assertEqual(1, len(body_in["events"]))
                self.assertEqual([jid], body_in["events"][0]["job_ids"])
                self.assertTrue(body_in["events"][0]["tainted"])
            disp.stop()


# ==============================================================================
# M2-C7: Loopback default, CSRF/Host/Content-Type/Headers, MCP dynamic, host_invoke_agent
# ==============================================================================
class TestM2C7BindCSRFMCPAndHostInvoke(unittest.TestCase):
    def test_hub_defaults_loopback_and_rejects_unconfirmed_non_loopback(self):
        self.assertEqual("127.0.0.1", hub.DEFAULT_HUB_HOST)
        self.assertEqual(18799, hub.DEFAULT_HUB_PORT)
        non_loopback = _ip(0, 0, 0, 0)
        lan_ip = _ip(10, 0, 0, 5)
        for bad_host in (non_loopback, lan_ip, "::"):
            with self.assertRaises(ValueError) as ce:
                hub.validate_bind_host(bad_host, env={})
            self.assertIn("NON_LOOPBACK_BIND_DENIED", str(ce.exception))
        # Explicit opt-in allows non-loopback
        self.assertEqual(
            non_loopback,
            hub.validate_bind_host(non_loopback, env={"AGY_FEDERATION_HUB_ALLOW_NON_LOOPBACK": "1"}),
        )

    def test_csrf_origin_host_content_type_and_security_headers(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent("web_peer", kind="hermes_remote", endpoint_url="https://wp.example.com", owner_auth=owner, bus_dir=tmp)
            tok = fed.mint_agent_token("web_peer", owner_auth=owner, bus_dir=tmp)["token"]

            with _RunningHub(bus_dir=tmp) as rh:
                # 1. Health endpoint minimal & carries mandatory security headers
                st_h, hdrs_h, body_h = rh.request("GET", "/hub/v1/health")
                self.assertEqual(200, st_h)
                self.assertEqual({"ok": True, "service": "agy-federation-hub"}, body_h)
                self.assertEqual("no-store", hdrs_h.get("cache-control"))
                self.assertEqual("no-referrer", hdrs_h.get("referrer-policy"))
                self.assertEqual("nosniff", hdrs_h.get("x-content-type-options"))

                # 2. Cross-origin Origin header rejected (403)
                st_o, hdrs_o, body_o = rh.request(
                    "GET",
                    "/hub/v1/me",
                    token=tok,
                    headers={"Origin": "https://evil.example.org"},
                )
                self.assertEqual(403, st_o)
                self.assertEqual("ORIGIN_FORBIDDEN", body_o.get("error"))
                self.assertEqual("no-store", hdrs_o.get("cache-control"))

                # 3. DNS rebinding Host header rejected (403)
                st_host, _, body_host = rh.request(
                    "GET",
                    "/hub/v1/me",
                    token=tok,
                    headers={"Host": "rebind.example.org:18799"},
                )
                self.assertEqual(403, st_host)
                self.assertEqual("INVALID_HOST_HEADER", body_host.get("error"))

                # 4. Non-JSON Content-Type on POST rejected (415)
                st_ct, _, body_ct = rh.request(
                    "POST",
                    "/hub/mcp",
                    token=tok,
                    raw_body=b"plain=text",
                    headers={"Content-Type": "text/plain"},
                )
                self.assertEqual(415, st_ct)
                self.assertEqual("UNSUPPORTED_MEDIA_TYPE", body_ct.get("error"))

                # 5. Loopback Origin + application/json; charset=utf-8 accepted
                st_ok, _, _ = rh.request(
                    "POST",
                    "/hub/mcp",
                    token=tok,
                    raw_body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                    headers={
                        "Origin": "http://127.0.0.1:18799",
                        "Content-Type": "application/json; charset=utf-8",
                    },
                )
                self.assertEqual(200, st_ok)

    def test_mcp_tools_list_dynamic_and_direct_call_denied(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent("ro_guest", kind="mcp_inbound_only", trust_level="readonly_guest", owner_auth=owner, bus_dir=tmp)
            fed.register_agent(
                "team_lead",
                kind="hermes_remote",
                endpoint_url="https://tl.example.com",
                trust_level="remote_trusted",
                capabilities={"can_dispatch": True},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.register_agent(
                "full_peer",
                kind="hermes_remote",
                endpoint_url="https://fp.example.com",
                trust_level="remote_trusted",
                capabilities={"coordinator_peer": True, "host_server_invoke": True, "can_dispatch": True},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.create_team("team-alpha", leader_agent_id="team_lead", members=["team_lead"], owner_auth=owner, bus_dir=tmp)
            t_ro = fed.mint_agent_token("ro_guest", owner_auth=owner, bus_dir=tmp)["token"]
            t_lead = fed.mint_agent_token("team_lead", owner_auth=owner, bus_dir=tmp)["token"]
            t_full = fed.mint_agent_token("full_peer", owner_auth=owner, bus_dir=tmp)["token"]

            with _RunningHub(bus_dir=tmp) as rh:
                def _list(tok: str) -> set[str]:
                    st, _, b = rh.request("POST", "/hub/mcp", token=tok, body={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                    self.assertEqual(200, st)
                    return {t["name"] for t in b["result"]["tools"]}

                ro_tools = _list(t_ro)
                self.assertEqual({"team_roster", "team_list"}, ro_tools)

                lead_tools = _list(t_lead)
                self.assertIn("team_dispatch", lead_tools)
                self.assertNotIn("host_exec", lead_tools)

                full_tools = _list(t_full)
                self.assertTrue({"host_exec", "host_files", "host_services", "host_invoke_agent"}.issubset(full_tools))

                # Forged direct call to unauthorized tool -> 403 + JSON-RPC -32003
                st_forged, _, b_forged = rh.request(
                    "POST",
                    "/hub/mcp",
                    token=t_lead,
                    body={
                        "jsonrpc": "2.0",
                        "id": 9,
                        "method": "tools/call",
                        "params": {"name": "host_exec", "arguments": {"argv": ["whoami"]}},
                    },
                )
                self.assertEqual(403, st_forged)
                self.assertEqual(-32003, b_forged["error"]["code"])

    def test_host_invoke_agent_cannot_spoof_sender_or_escalate_trust(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent(
                "host_invoker",
                kind="hermes_local",
                profile="hi",
                trust_level="local_worker",
                capabilities={"coordinator_peer": True, "host_server_invoke": True, "can_dispatch": True},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.register_agent("worker_target", kind="hermes_local", profile="wt", owner_auth=owner, bus_dir=tmp)
            fed.create_team("team-ops", leader_agent_id="host_invoker", members=["host_invoker", "worker_target"], owner_auth=owner, bus_dir=tmp)
            tok = fed.mint_agent_token("host_invoker", owner_auth=owner, bus_dir=tmp)["token"]

            with _RunningHub(bus_dir=tmp, repo_root=tmp, home_dir=tmp) as rh:
                # 1. Spoofing from_bot -> 403 SENDER_SPOOF_DENIED
                st_sp, _, body_sp = rh.request(
                    "POST",
                    "/hub/v1/host/invoke_agent",
                    token=tok,
                    body={
                        "agent_id": "worker_target",
                        "from_bot": "owner_admin",
                        "prompt": "spoofed",
                        "team_id": "team-ops",
                    },
                )
                self.assertEqual(403, st_sp)
                self.assertEqual("SENDER_SPOOF_DENIED", body_sp.get("error"))

                # 2. Attempting trust_level="local_admin" from local_worker caller -> monotonically clamped to local_worker
                st_ok, _, body_ok = rh.request(
                    "POST",
                    "/hub/v1/host/invoke_agent",
                    token=tok,
                    body={
                        "agent_id": "worker_target",
                        "prompt": "legit check",
                        "team_id": "team-ops",
                        "trust_level": "local_admin",
                    },
                )
                self.assertEqual(200, st_ok, body_ok)
                dispatched = body_ok["dispatched_jobs"][0]
                self.assertEqual("host_invoker", dispatched["from_bot"])
                self.assertLessEqual(
                    bot_bus.TRUST_ORDER[dispatched["trust_level"]],
                    bot_bus.TRUST_ORDER["local_worker"],
                )


# ==============================================================================
# M2-C8: audit.jsonl permissions/flock/redaction + systemd unit hardening
# ==============================================================================
class TestM2C8AuditLogAndSystemdUnit(unittest.TestCase):
    def test_audit_jsonl_permissions_flock_completeness_and_redaction(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent(
                "audit_peer",
                kind="hermes_remote",
                endpoint_url="https://ap.example.com",
                trust_level="remote_trusted",
                capabilities={"coordinator_peer": True, "host_server_invoke": True, "can_dispatch": True},
                owner_auth=owner,
                bus_dir=tmp,
            )
            tok = fed.mint_agent_token("audit_peer", owner_auth=owner, bus_dir=tmp)["token"]
            fake_sk = "sk-" + "AuditSecretLeakTest1234567890"
            fake_ghp = "ghp_" + "AuditGhLeak1234567890abcdef"

            with _RunningHub(bus_dir=tmp, repo_root=tmp, home_dir=tmp) as rh:
                # 1. Invalid auth event + allowed host_exec with secret in args + denied Lock 2 event
                rh.request("GET", "/hub/v1/me", token=tok + "bad")
                rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["echo", fake_sk, fake_ghp]})
                rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["bao", "status"]})

                # 2. Concurrent audit writes under flock produce valid single-line JSONL records
                def _hit(idx: int):
                    return rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["echo", f"n-{idx}"]})[0]

                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    codes = list(pool.map(_hit, range(16)))
                self.assertTrue(all(c == 200 for c in codes), codes)

            audit_path = Path(fed.federation_dir(tmp)) / "audit.jsonl"
            self.assertTrue(audit_path.is_file())
            self.assertEqual(0o700, stat.S_IMODE(os.stat(fed.federation_dir(tmp)).st_mode))
            self.assertEqual(0o600, stat.S_IMODE(os.stat(audit_path).st_mode))

            raw_text = audit_path.read_text(encoding="utf-8")
            self.assertNotIn(tok, raw_text)
            self.assertNotIn(fake_sk, raw_text)
            self.assertNotIn(fake_ghp, raw_text)

            records = [json.loads(line) for line in raw_text.splitlines() if line.strip()]
            self.assertGreaterEqual(len(records), 19)
            events = {r["event"] for r in records}
            reasons = {r["reason"] for r in records}
            self.assertIn("auth_failed", events)
            self.assertIn("host_bridge", events)
            self.assertIn("HOST_LOCK2_DENIED", reasons)

    def test_systemd_unit_no_plaintext_secrets_and_loopback_default(self):
        candidates = (
            REPO_ROOT / "systemd" / "agy-federation-hub.service",
            REPO_ROOT / "systemd" / "examples" / "agy-federation-hub.service.example",
        )
        unit_path = next((p for p in candidates if p.is_file()), None)
        self.assertIsNotNone(unit_path, f"Missing systemd unit in {[str(p) for p in candidates]}")
        assert unit_path is not None
        text = unit_path.read_text(encoding="utf-8")
        self.assertIn("AGY_FEDERATION_HUB_HOST=127.0.0.1", text)
        self.assertIn("AGY_FEDERATION_HUB_PORT=18799", text)
        self.assertIn("UMask=0077", text)
        self.assertNotIn("AGY_FEDERATION_HUB_ALLOW_NON_LOOPBACK=1", text)
        self.assertNotIn("AGY_FEDERATION_TOKEN=", text)
        self.assertNotIn("agy_fed_", text)
        self.assertNotIn("EnvironmentFile=", text)
        fed.reject_plaintext_secrets({"unit": text}, path="systemd_unit")


# ==============================================================================
# QA Round 1 Blocking Regressions (M2-B1..M2-B8 + 2 Hardening Items)
# ==============================================================================
class TestM2Round1SecurityRegressions(unittest.TestCase):
    def _seed_host_peer(self, tmp: str) -> Tuple[fed.OwnerAuth, str]:
        owner = fed.make_owner_auth("owner")
        fed.register_agent(
            "host_peer",
            kind="hermes_remote",
            endpoint_url="https://hp.example.com",
            trust_level="remote_trusted",
            capabilities={"coordinator_peer": True, "host_server_invoke": True, "can_dispatch": True},
            owner_auth=owner,
            bus_dir=tmp,
        )
        tok = fed.mint_agent_token("host_peer", owner_auth=owner, bus_dir=tmp)["token"]
        return owner, tok

    def test_m2_b1_host_exec_blocks_rg_grep_recursive_attached_flags_and_dir_targets(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            _owner, tok = self._seed_host_peer(tmp)
            repo_dir = Path(tmp) / "repo"
            safe_sub = repo_dir / "safe_sub"
            safe_sub.mkdir(parents=True)
            (repo_dir / "AGENTS.md").write_text("SECRET_GOVERNANCE_MARKER\n", encoding="utf-8")
            (repo_dir / "hooks").mkdir(parents=True)
            (repo_dir / "hooks" / "g.py").write_text("# hook\n", encoding="utf-8")
            safe_file = safe_sub / "hello.txt"
            safe_file.write_text("alpha\nbeta hello\ngamma\n", encoding="utf-8")

            with _RunningHub(bus_dir=tmp, repo_root=str(repo_dir), home_dir=tmp) as rh:
                blocked_execs = [
                    {"argv": ["rg", "SECRET", str(repo_dir)]},
                    {"argv": ["grep", "-rn", "SECRET", "."]},
                    {"argv": ["grep", "-R", "SECRET", "."]},
                    {"argv": ["grep", "--recursive", "SECRET", "."]},
                    {"argv": ["grep", "-f.env", "pat", str(safe_file)]},
                    {"argv": ["grep", "-fAGENTS.md", str(safe_file)]},
                    {"argv": ["grep", "-f", "AGENTS.md", str(safe_file)]},
                    {"argv": ["grep", "--file=AGENTS.md", str(safe_file)]},
                    {"argv": ["grep", "-d", "recurse", "SECRET", "."]},
                    {"argv": ["grep", "SECRET", str(repo_dir)]},
                    {"argv": ["grep", "hello", str(safe_sub)]},
                    {"argv": ["ls", "-R", str(repo_dir)]},
                    {"argv": ["ls", "-laR", str(safe_sub)]},
                    {"argv": ["ls", "-L", str(safe_sub)]},
                    {"argv": ["du", "-L", str(safe_sub)]},
                    {"argv": ["du", "-s", str(repo_dir)]},
                    {"argv": ["wc", "--files0-from=AGENTS.md"]},
                    {"argv": ["file", "-f.env", str(safe_file)]},
                    {"argv": ["file", "-m/etc/passwd", str(safe_file)]},
                    {"argv": ["tail", "-f", str(safe_file)]},
                    {"argv": ["stat", "-L", str(safe_file)]},
                    {"argv": ["touch", "bridge/federation_hub.py"]},
                    {"argv": ["mkdir", "-p", ".git/hooks/evil"]},
                ]
                for payload in blocked_execs:
                    with self.subTest(payload=payload):
                        st, _, body = rh.request("POST", "/hub/v1/host/exec", token=tok, body=payload)
                        self.assertEqual(403, st, body)
                        self.assertIn(body.get("error"), ("HOST_LOCK1_DENIED", "HOST_LOCK2_DENIED", "HOST_LOCK3_DENIED"))

                # Safe allowlisted non-recursive commands succeed
                st_g, _, b_g = rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["grep", "-n", "hello", str(safe_file)]})
                self.assertEqual(200, st_g, b_g)
                self.assertIn("2:beta hello", b_g["stdout"])

                st_ls, _, _ = rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["ls", "-la", str(safe_sub)]})
                self.assertEqual(200, st_ls)

                st_du, _, _ = rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["du", "-s", str(safe_sub)]})
                self.assertEqual(200, st_du)

                st_hd, _, b_hd = rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["head", "-n", "1", str(safe_file)]})
                self.assertEqual(200, st_hd)
                self.assertEqual("alpha\n", b_hd["stdout"])

                st_t, _, _ = rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["touch", str(safe_sub / "touched.txt")]})
                self.assertEqual(200, st_t)
                self.assertTrue((safe_sub / "touched.txt").is_file())

    def test_m2_b2_host_exec_git_strict_readonly_metadata_allowlist(self):
        import subprocess as sp

        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            _owner, tok = self._seed_host_peer(tmp)
            repo_dir = Path(tmp) / "gitrepo"
            repo_dir.mkdir()
            sp.run(["git", "init", "-q"], cwd=str(repo_dir), check=True)
            sp.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo_dir), check=True)
            sp.run(["git", "config", "user.name", "Test"], cwd=str(repo_dir), check=True)
            (repo_dir / "AGENTS.md").write_text("SECRET_IN_GIT\n", encoding="utf-8")
            (repo_dir / "note.txt").write_text("hello\n", encoding="utf-8")
            sp.run(["git", "add", "AGENTS.md", "note.txt"], cwd=str(repo_dir), check=True)
            sp.run(["git", "commit", "-q", "-m", "init"], cwd=str(repo_dir), check=True)
            (repo_dir / "note.txt").write_text("hello world\n", encoding="utf-8")

            with _RunningHub(bus_dir=tmp, repo_root=str(repo_dir), home_dir=tmp) as rh:
                blocked_git = [
                    ["git", "show", "HEAD:AGENTS.md"],
                    ["git", "grep", "SECRET_IN_GIT"],
                    ["git", "log", "-p"],
                    ["git", "log", "--patch"],
                    ["git", "log", "-S", "SECRET"],
                    ["git", "log", "-G", "SECRET"],
                    ["git", "archive", "HEAD"],
                    ["git", "cat-file", "-p", "HEAD:AGENTS.md"],
                    ["git", "blame", "AGENTS.md"],
                    ["git", "format-patch", "-1"],
                    ["git", "diff"],
                    ["git", "diff", "-p"],
                    ["git", "diff", "--no-index", "--stat", "note.txt", "AGENTS.md"],
                    ["git", "branch", "new_evil_branch"],
                    ["git", "branch", "-D", "master"],
                    ["git", "-C", str(repo_dir), "status"],
                    ["git", "--git-dir=.git", "status"],
                    ["git", "-c", "core.pager=id", "status"],
                ]
                for argv in blocked_git:
                    with self.subTest(git_argv=argv):
                        st, _, body = rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": argv, "workdir": str(repo_dir)})
                        self.assertEqual(403, st, body)
                        self.assertEqual("HOST_LOCK1_DENIED", body.get("error"))

                # Safe read-only metadata git commands succeed
                allowed_git = [
                    ["git", "status", "-s"],
                    ["git", "branch", "--list"],
                    ["git", "rev-parse", "--short", "HEAD"],
                    ["git", "log", "--oneline", "-n", "2"],
                    ["git", "diff", "--stat"],
                ]
                for argv in allowed_git:
                    with self.subTest(allowed_git=argv):
                        st, _, body = rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": argv, "workdir": str(repo_dir)})
                        self.assertEqual(200, st, body)
                        self.assertEqual(0, body["exit_code"], body)
                        self.assertNotIn("SECRET_IN_GIT", body["stdout"])

    def test_m2_b3_lock2_blocks_proc_pid_task_tid_environ_and_all_env_variants(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            _owner, tok = self._seed_host_peer(tmp)
            pid = os.getpid()
            tid = threading.get_native_id() if hasattr(threading, "get_native_id") else pid
            arb_dir = Path(tmp) / "any_dir"
            arb_dir.mkdir()
            env_variants = [
                arb_dir / "prod.env",
                arb_dir / "bot.env",
                arb_dir / "secrets.env",
                arb_dir / "prod.env.bak",
                arb_dir / ".env",
                arb_dir / ".env.local",
            ]
            for ef in env_variants:
                ef.write_text("SECRET=1\n", encoding="utf-8")

            proc_targets = [
                f"/proc/{pid}/task/{tid}/environ",
                f"/proc/{pid}/mem",
                f"/proc/{pid}/cmdline",
                "/proc/self/fd/0",
                f"/proc/{pid}/root/etc/passwd",
                "/proc/thread-self/environ",
            ]

            with _RunningHub(bus_dir=tmp, repo_root=tmp, home_dir=tmp) as rh:
                for p in proc_targets + [str(f) for f in env_variants]:
                    with self.subTest(lock2_target=p):
                        st_f, _, b_f = rh.request("POST", "/hub/v1/host/files", token=tok, body={"action": "read", "path": p})
                        self.assertEqual(403, st_f, b_f)
                        self.assertEqual("HOST_LOCK2_DENIED", b_f.get("error"))
                        st_e, _, b_e = rh.request("POST", "/hub/v1/host/exec", token=tok, body={"argv": ["cat", p]})
                        self.assertEqual(403, st_e, b_e)
                        self.assertEqual("HOST_LOCK2_DENIED", b_e.get("error"))

                # Non-sensitive global /proc/uptime remains readable
                if os.path.isfile("/proc/uptime"):
                    st_up, _, b_up = rh.request("POST", "/hub/v1/host/files", token=tok, body={"action": "read", "path": "/proc/uptime"})
                    self.assertEqual(200, st_up, b_up)

    def test_m2_b4_lock1_blocks_write_to_core_code_git_hooks_live_runtime_and_shell_rc(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            _owner, tok = self._seed_host_peer(tmp)
            home_dir = Path(tmp) / "fake_home"
            repo_dir = Path(tmp) / "repo"
            (repo_dir / "bridge").mkdir(parents=True)
            (repo_dir / "scripts").mkdir(parents=True)
            (repo_dir / ".git" / "hooks").mkdir(parents=True)
            (repo_dir / "systemd").mkdir(parents=True)
            (home_dir / "agy-tg-bridge").mkdir(parents=True)
            (home_dir / ".local" / "bin").mkdir(parents=True)
            (home_dir / ".gemini").mkdir(parents=True)
            (home_dir / ".config" / "systemd" / "user").mkdir(parents=True)

            orig_hub = "# original federation_hub\n"
            (repo_dir / "bridge" / "federation_hub.py").write_text(orig_hub, encoding="utf-8")
            (repo_dir / "bridge" / "memory_guard.py").write_text("# guard\n", encoding="utf-8")
            (repo_dir / "README.md").write_text("# readme\n", encoding="utf-8")
            (repo_dir / ".git" / "config").write_text("[core]\n", encoding="utf-8")
            (home_dir / ".bashrc").write_text("# bashrc\n", encoding="utf-8")

            sym_git = Path(tmp) / "git_symlink"
            sym_git.symlink_to(repo_dir / ".git")

            write_blocked_targets = [
                "bridge/federation_hub.py",
                "bridge/federation_registry.py",
                "bridge/federation_mcp_stdio.py",
                "bridge/bot_bus.py",
                "bridge/bot_bus_mcp.py",
                "bridge/agent_driver.py",
                "bridge/external_drivers.py",
                "bridge/memory_guard.py",
                "bridge/bridge.py",
                "scripts/verify_gate.py",
                "scripts/sync_live.py",
                "scripts/export_public.py",
                ".git/hooks/pre-commit",
                ".git/hooks/post-checkout",
                ".git/config",
                str(sym_git / "hooks" / "post-checkout"),
                "systemd/agy-federation-hub.service",
                str(home_dir / "agy-tg-bridge" / "bridge.py"),
                "~/.bashrc",
                "~/.profile",
                "~/.bash_profile",
                "~/.zshrc",
                "~/.zprofile",
                "~/.local/bin/evil_cmd",
                "~/.gemini/settings.json",
                "~/.config/systemd/user/evil.service",
                "/etc/systemd/system/evil.service",
            ]

            with _RunningHub(bus_dir=tmp, repo_root=str(repo_dir), home_dir=str(home_dir)) as rh:
                for target in write_blocked_targets:
                    with self.subTest(write_target=target):
                        st, _, body = rh.request(
                            "POST",
                            "/hub/v1/host/files",
                            token=tok,
                            body={"action": "write", "path": target, "content": "# PWNED\n"},
                        )
                        self.assertEqual(403, st, body)
                        self.assertEqual("HOST_LOCK1_DENIED", body.get("error"))

                # Zero disk mutations verified
                self.assertEqual(orig_hub, (repo_dir / "bridge" / "federation_hub.py").read_text(encoding="utf-8"))
                self.assertFalse((repo_dir / ".git" / "hooks" / "pre-commit").exists())
                self.assertFalse((repo_dir / ".git" / "hooks" / "post-checkout").exists())
                self.assertEqual("# bashrc\n", (home_dir / ".bashrc").read_text(encoding="utf-8"))

                # Read on non-sensitive repo files remains allowed, while memory_guard.py stays read+write denied
                st_rd, _, b_rd = rh.request("POST", "/hub/v1/host/files", token=tok, body={"action": "read", "path": "README.md"})
                self.assertEqual(200, st_rd, b_rd)
                self.assertIn("# readme", b_rd["content"])

                st_mg, _, b_mg = rh.request("POST", "/hub/v1/host/files", token=tok, body={"action": "read", "path": "bridge/memory_guard.py"})
                self.assertEqual(403, st_mg, b_mg)
                self.assertEqual("HOST_LOCK1_DENIED", b_mg.get("error"))

    def test_m2_b5_chunked_negative_size_query_token_variants_and_0640_token_file(self):
        import socket as sock_mod

        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            _owner, tok = self._seed_host_peer(tmp)
            fake_sk = "sk-" + "QuerySecretLeakTest12345678"

            # 1. Token file permissions: 0640 / 0604 / 0602 / 0660 MUST be rejected; 0600 / 0400 accepted
            tf = Path(tmp) / "tok_perm"
            tf.write_text(tok + "\n", encoding="utf-8")
            for bad_mode in (0o640, 0o604, 0o602, 0o660, 0o644):
                os.chmod(tf, bad_mode)
                with self.subTest(mode=oct(bad_mode)):
                    with self.assertRaises(PermissionError):
                        stdio_mcp.load_federation_token(token_file=str(tf))
            for good_mode in (0o600, 0o400):
                os.chmod(tf, good_mode)
                self.assertEqual(tok, stdio_mcp.load_federation_token(token_file=str(tf)))
            os.chmod(tf, 0o600)

            with _RunningHub(bus_dir=tmp, max_body_bytes=256) as rh:
                # 2. Query credential key variants & raw secret values in arbitrary query params -> 400 zero echo
                query_cases = [
                    f"/hub/v1/me?api-key={tok}",
                    f"/hub/v1/me?x-api-key={tok}",
                    f"/hub/v1/me?auth-token={tok}",
                    f"/hub/v1/me?bearer-token={tok}",
                    f"/hub/v1/me?x={tok}",
                    f"/hub/v1/me?note={fake_sk}",
                ]
                for qpath in query_cases:
                    with self.subTest(query=qpath[:28]):
                        st_q, _, body_q = rh.request("GET", qpath)
                        self.assertEqual(400, st_q, body_q)
                        self.assertEqual("QUERY_TOKEN_FORBIDDEN", body_q.get("error"))
                        self.assertNotIn(tok, json.dumps(body_q))
                        self.assertNotIn(fake_sk, json.dumps(body_q))

                # 3. Malformed / negative / oversized chunked Transfer-Encoding
                def _raw_chunked(chunk_payload: bytes) -> Tuple[int, str]:
                    req = (
                        b"POST /hub/mcp HTTP/1.1\r\n"
                        + f"Host: 127.0.0.1:{rh.port}\r\n".encode("ascii")
                        + f"Authorization: Bearer {tok}\r\n".encode("ascii")
                        + b"Content-Type: application/json\r\n"
                        + b"Transfer-Encoding: chunked\r\n"
                        + b"Connection: close\r\n\r\n"
                        + chunk_payload
                    )
                    with sock_mod.create_connection(("127.0.0.1", rh.port), timeout=3.0) as s:
                        s.sendall(req)
                        chunks_out = []
                        while True:
                            part = s.recv(4096)
                            if not part:
                                break
                            chunks_out.append(part)
                    raw_resp = b"".join(chunks_out).decode("utf-8", errors="replace")
                    status_line = raw_resp.splitlines()[0] if raw_resp else ""
                    code = int(status_line.split()[1]) if len(status_line.split()) >= 2 else 0
                    return code, raw_resp

                for bad_chunk in (
                    b"-1\r\n" + b"A" * 512 + b"\r\n0\r\n\r\n",
                    b"+10\r\n" + b"A" * 16 + b"\r\n0\r\n\r\n",
                    b"zzzz\r\n0\r\n\r\n",
                    b"5\r\nabcdeXX0\r\n\r\n",  # missing CRLF
                ):
                    code_b, raw_b = _raw_chunked(bad_chunk)
                    self.assertEqual(400, code_b, raw_b)
                    self.assertIn("INVALID_CHUNKED_BODY", raw_b)

                # Oversized chunked payload > max_body_bytes(256) -> 413
                big_chunk = f"{512:x}\r\n".encode("ascii") + (b"B" * 512) + b"\r\n0\r\n\r\n"
                code_413, raw_413 = _raw_chunked(big_chunk)
                self.assertEqual(413, code_413, raw_413)
                self.assertIn("PAYLOAD_TOO_LARGE", raw_413)

                # Valid small chunked JSON-RPC ping -> 200
                ok_json = b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
                ok_chunk = f"{len(ok_json):x}\r\n".encode("ascii") + ok_json + b"\r\n0\r\n\r\n"
                code_200, raw_200 = _raw_chunked(ok_chunk)
                self.assertEqual(200, code_200, raw_200)

    def test_m2_b6_allowed_teams_broadcast_nonexistent_team_and_ambiguous_omitted_team_id(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent(
                "clamped_peer",
                kind="hermes_remote",
                endpoint_url="https://cp.example.com",
                capabilities={"coordinator_peer": True, "can_dispatch": True, "allowed_teams": ["team-alpha"]},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.register_agent(
                "ghost_peer",
                kind="hermes_remote",
                endpoint_url="https://gp.example.com",
                capabilities={"coordinator_peer": True, "can_dispatch": True, "allowed_teams": ["team-ghost"]},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.register_agent(
                "multi_peer",
                kind="hermes_remote",
                endpoint_url="https://mp.example.com",
                capabilities={"coordinator_peer": True, "can_dispatch": True, "allowed_teams": ["team-alpha", "team-beta"]},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.register_agent("worker_a", kind="hermes_local", profile="wa", owner_auth=owner, bus_dir=tmp)
            fed.register_agent("worker_b", kind="hermes_local", profile="wb", owner_auth=owner, bus_dir=tmp)
            fed.register_agent("shared_w", kind="hermes_local", profile="sw", owner_auth=owner, bus_dir=tmp)
            fed.create_team("team-alpha", leader_agent_id="clamped_peer", members=["clamped_peer", "multi_peer", "worker_a", "shared_w"], owner_auth=owner, bus_dir=tmp)
            fed.create_team("team-beta", leader_agent_id="clamped_peer", members=["clamped_peer", "multi_peer", "worker_b", "shared_w"], owner_auth=owner, bus_dir=tmp)

            t_clamped = fed.mint_agent_token("clamped_peer", owner_auth=owner, bus_dir=tmp)["token"]
            t_ghost = fed.mint_agent_token("ghost_peer", owner_auth=owner, bus_dir=tmp)["token"]
            t_multi = fed.mint_agent_token("multi_peer", owner_auth=owner, bus_dir=tmp)["token"]

            with _RunningHub(bus_dir=tmp) as rh:
                # 1. clamped_peer team_broadcast to team-beta -> 403; omitted team_id -> 403; team-alpha -> 200
                st_b1, _, b_b1 = rh.request(
                    "POST",
                    "/hub/mcp",
                    token=t_clamped,
                    body={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "team_broadcast", "arguments": {"team_id": "team-beta", "chat_id": -1001, "message": "cross"}},
                    },
                )
                self.assertEqual(403, st_b1, b_b1)

                st_b2, _, b_b2 = rh.request(
                    "POST",
                    "/hub/mcp",
                    token=t_clamped,
                    body={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "team_broadcast", "arguments": {"chat_id": -1001, "message": "omitted"}},
                    },
                )
                self.assertEqual(403, st_b2, b_b2)

                st_b3, _, b_b3 = rh.request(
                    "POST",
                    "/hub/mcp",
                    token=t_clamped,
                    body={
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "team_broadcast", "arguments": {"team_id": "team-alpha", "chat_id": -1001, "message": "ok"}},
                    },
                )
                self.assertEqual(200, st_b3, b_b3)

                # 2. ghost_peer with non-existent allowed_team fails closed (403), never falls through to has_global_coord
                st_g, _, b_g = rh.request(
                    "POST",
                    "/hub/v1/dispatch",
                    token=t_ghost,
                    body={"bot": "worker_b", "prompt": "ghost bypass", "team_id": "team-ghost"},
                )
                self.assertEqual(403, st_g, b_g)

                # 3. multi_peer dispatching to shared_w omitting team_id MUST fail closed (never unscoped team_id="")
                st_amb, _, b_amb = rh.request(
                    "POST",
                    "/hub/v1/dispatch",
                    token=t_multi,
                    body={"bot": "shared_w", "prompt": "ambiguous"},
                )
                self.assertEqual(403, st_amb, b_amb)

                # 4. multi_peer dispatching to worker_a (uniquely in team-alpha) omitting team_id auto-backfills team-alpha
                st_uniq, _, b_uniq = rh.request(
                    "POST",
                    "/hub/v1/dispatch",
                    token=t_multi,
                    body={"bot": "worker_a", "prompt": "unique team"},
                )
                self.assertEqual(200, st_uniq, b_uniq)
                self.assertEqual("team-alpha", b_uniq["jobs"][0]["team_id"])

    def test_m2_b7_audit_logger_redacts_secrets_in_dict_keys_and_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger = hub.AuditLogger(tmp)
            fake_fed = "agy_fed_" + "DictKeyLeakSecret1234567890"
            fake_sk = "sk-" + "DictKeySkLeak1234567890abcd"
            logger.record(
                "custom_event",
                actor_id="tester",
                action="audit_test",
                outcome="allowed",
                detail={
                    f"header_{fake_fed}": "val_ok",
                    "nested": {f"k_{fake_sk}": f"v_{fake_fed}"},
                },
                extra_secrets=[fake_fed],
            )
            raw = Path(logger.log_path).read_text(encoding="utf-8")
            self.assertNotIn(fake_fed, raw)
            self.assertNotIn(fake_sk, raw)
            parsed = json.loads(raw.strip())
            self.assertEqual("custom_event", parsed["event"])
            self.assertIn("header_[REDACTED]", parsed["detail"])
            self.assertIn("k_[REDACTED]", parsed["detail"]["nested"])

    def test_m2_b8_cancel_claimed_pull_job_converges_bot_bus_and_emits_unique_batch_done(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent(
                "coord_lead",
                kind="hermes_remote",
                endpoint_url="https://cl.example.com",
                capabilities={"coordinator_peer": True, "can_dispatch": True},
                owner_auth=owner,
                bus_dir=tmp,
            )
            fed.register_agent("pull_w1", kind="http_a2a", transport="pull_worker", owner_auth=owner, bus_dir=tmp)
            fed.create_team("team-nat", leader_agent_id="coord_lead", members=["coord_lead", "pull_w1"], owner_auth=owner, bus_dir=tmp)
            t_lead = fed.mint_agent_token("coord_lead", owner_auth=owner, bus_dir=tmp)["token"]
            t_w1 = fed.mint_agent_token("pull_w1", owner_auth=owner, bus_dir=tmp)["token"]
            disp = hub.ExternalWorkerDispatcher(bus_dir=tmp)

            with _RunningHub(bus_dir=tmp) as rh:
                # Path A: Cancel claimed Pull job via Hub REST /cancel
                st_d1, _, b_d1 = rh.request(
                    "POST",
                    "/hub/v1/dispatch",
                    token=t_lead,
                    body={"bot": "pull_w1", "prompt": "pull task A", "team_id": "team-nat", "wait": False},
                )
                self.assertEqual(200, st_d1, b_d1)
                jid1 = b_d1["jobs"][0]["job_id"]
                self.assertEqual(1, disp.poll_once()["bridged_pull"])
                self.assertEqual(200, rh.request("POST", f"/hub/v1/jobs/{jid1}/claim", token=t_w1, body={})[0])

                with hub._with_bot_bus_dir(tmp):
                    self.assertEqual("running", bot_bus.get_job(jid1)["status"])

                st_c1, _, b_c1 = rh.request(
                    "POST",
                    f"/hub/v1/jobs/{jid1}/cancel",
                    token=t_lead,
                    body={"reason": "abort_claimed_pull"},
                )
                self.assertEqual(200, st_c1, b_c1)
                self.assertEqual("cancelled", b_c1["cancelled"]["status"])

                # bot_bus converged atomically & emitted exactly 1 batch_done
                with hub._with_bot_bus_dir(tmp):
                    j1 = bot_bus.get_job(jid1)
                    self.assertEqual("cancelled", j1["status"])
                    self.assertEqual("CANCELLED_BY_COORDINATOR", j1["error_code"])
                    self.assertTrue(j1["batch_notified"])
                    pkts1 = [p for p in bot_bus.pop_inbox_packets("coord_lead") if p.get("type") == "batch_done"]
                    self.assertEqual(1, len(pkts1))
                    self.assertEqual([jid1], pkts1[0]["job_ids"])

                # Subsequent poll_once must NOT duplicate batch_done; late worker result -> 409
                disp.poll_once()
                with hub._with_bot_bus_dir(tmp):
                    self.assertEqual([], [p for p in bot_bus.pop_inbox_packets("coord_lead") if p.get("type") == "batch_done"])
                self.assertEqual(
                    409,
                    rh.request("POST", f"/hub/v1/jobs/{jid1}/result", token=t_w1, body={"status": "done", "result_text": "late"})[0],
                )

                # Path B: Cancel directly via bot_bus.cancel_job + dispatcher._sync_pull_cancellations
                st_d2, _, b_d2 = rh.request(
                    "POST",
                    "/hub/v1/dispatch",
                    token=t_lead,
                    body={"bot": "pull_w1", "prompt": "pull task B", "team_id": "team-nat", "wait": False},
                )
                self.assertEqual(200, st_d2, b_d2)
                jid2 = b_d2["jobs"][0]["job_id"]
                self.assertEqual(1, disp.poll_once()["bridged_pull"])
                self.assertEqual(200, rh.request("POST", f"/hub/v1/jobs/{jid2}/claim", token=t_w1, body={})[0])

                with hub._with_bot_bus_dir(tmp):
                    bot_bus.cancel_job(jid2, requester_bot="coord_lead", reason="bus_direct_cancel", auth_token=t_lead)
                    self.assertEqual("running", bot_bus.get_job(jid2)["status"])

                stats_sync = disp.poll_once()
                self.assertEqual(1, stats_sync["pull_cancelled"])
                with hub._with_bot_bus_dir(tmp):
                    j2 = bot_bus.get_job(jid2)
                    self.assertEqual("cancelled", j2["status"])
                    self.assertTrue(j2["batch_notified"])
                    pkts2 = [p for p in bot_bus.pop_inbox_packets("coord_lead") if p.get("type") == "batch_done"]
                    self.assertEqual(1, len(pkts2))
                    self.assertEqual([jid2], pkts2[0]["job_ids"])

    def test_hardening_rate_limit_precedes_nonce_cache_and_hermes_post_popen_cancel_race(self):
        # 1. Rate-limited flooder MUST NOT evict legitimate agent's nonce from bounded cache
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            owner = fed.make_owner_auth("owner")
            fed.register_agent("good_agent", kind="hermes_remote", endpoint_url="https://g.example.com", owner_auth=owner, bus_dir=tmp)
            fed.register_agent("flood_agent", kind="hermes_remote", endpoint_url="https://f.example.com", owner_auth=owner, bus_dir=tmp)
            t_good = fed.mint_agent_token("good_agent", owner_auth=owner, bus_dir=tmp)["token"]
            t_flood = fed.mint_agent_token("flood_agent", owner_auth=owner, bus_dir=tmp)["token"]

            with _RunningHub(
                bus_dir=tmp,
                require_replay_headers=True,
                nonce_cache_max=2,
                rate_limit_max_requests=1,
                rate_limit_window_sec=60.0,
            ) as rh:
                hdr_good = hub.build_replay_headers(t_good, "GET", "/hub/v1/me", b"", nonce="good-nonce-1")
                self.assertEqual(200, rh.request("GET", "/hub/v1/me", token=t_good, headers=hdr_good)[0])

                # Flood agent uses its 1 allowed request, then floods 5 more -> all 429, never touches nonce_cache
                hdr_f0 = hub.build_replay_headers(t_flood, "GET", "/hub/v1/me", b"", nonce="flood-0")
                self.assertEqual(200, rh.request("GET", "/hub/v1/me", token=t_flood, headers=hdr_f0)[0])
                for i in range(1, 6):
                    hdr_fi = hub.build_replay_headers(t_flood, "GET", "/hub/v1/me", b"", nonce=f"flood-{i}")
                    self.assertEqual(429, rh.request("GET", "/hub/v1/me", token=t_flood, headers=hdr_fi)[0])

                # Good agent's nonce MUST still be in cache (replay rejected, wait: rate limit is 1/60s so verify directly)
                self.assertFalse(rh.server.nonce_cache.check_and_record("good_agent", "good-nonce-1"))

        # 2. HermesLocalSession post-Popen cancel race kills newly spawned child & clears _turn_active
        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = _write_fake_hermes_script(Path(tmp) / "hermes")
            drv = ext.HermesLocalDriver()
            sess = drv.spawn_session(
                None,
                "safe",
                None,
                None,
                profile="race_p",
                hermes_bin=fake_bin,
                allowed_bins=[fake_bin],
                workdir=tmp,
                scope_key="hermes:race",
            )
            real_popen = ext.subprocess.Popen

            def _racing_popen(*args, **kwargs):
                p = real_popen(*args, **kwargs)
                # Simulate cancel() arriving right before send_user_prompt re-acquires self._lock
                sess.cancel(reason="race_cancelled")
                return p

            try:
                with mock.patch.object(ext.subprocess, "Popen", side_effect=_racing_popen):
                    sess.send_user_prompt("SLEEP_LONG")
                self.assertFalse(sess._turn_active)
                self.assertIsNotNone(sess.proc)
                self.assertIsNotNone(sess.proc.poll())
            finally:
                sess.close()

    def test_m2_r2_date_ss_hostname_ps_and_all_exec_bins_strict_arg_allowlists(self):
        """Regression for QA Round 2 P0-1 (`M2-B1-R2`) & P0-2 (`M2-B3-R2`) + all 27 allowlisted bins."""
        import subprocess
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, _clean_env({"AGY_BOT_BUS_DIR": tmp}), clear=True):
            _owner, tok = self._seed_host_peer(tmp)
            repo_dir = Path(tmp) / "repo"
            repo_dir.mkdir(parents=True, exist_ok=True)
            env_secret = "PROD_DB_PASS=" + "Round2EnvSecret999"
            gov_secret = "TOP_SECRET_GOVERNANCE_" + "12345"
            (repo_dir / ".env").write_text(env_secret + "\n", encoding="utf-8")
            (repo_dir / "AGENTS.md").write_text(gov_secret + "\n", encoding="utf-8")

            # Spawn isolated same-UID child process carrying mock sensitive env vars
            probe_marker = "".join(["Probe", "Env", "Marker", "987654321"])
            child_env = dict(os.environ)
            child_env["DATABASE_URL"] = f"postgres://tester:{probe_marker}@198.51.100.10:5432/demo"
            child = subprocess.Popen(["sleep", "20"], env=child_env)
            try:
                with _RunningHub(bus_dir=tmp, repo_root=str(repo_dir)) as rh:
                    # 1. P0-1 (M2-B1-R2): attached/file-reading flags on date / ss / hostname MUST return 403 & zero leak
                    blocked_file_argvs = [
                        ["date", "-f.env"],
                        ["date", "-fAGENTS.md"],
                        ["date", "-f", ".env"],
                        ["date", "--file=.env"],
                        ["date", "-r.env"],
                        ["date", "-r", "AGENTS.md"],
                        ["date", "-s", "2020-01-01"],
                        ["ss", "-F.env"],
                        ["ss", "-FAGENTS.md"],
                        ["ss", "-F", ".env"],
                        ["ss", "--filter=.env"],
                        ["ss", "-D", "dump.out"],
                        ["ss", "-K"],
                        ["hostname", "-F.env"],
                        ["hostname", "-F", ".env"],
                        ["hostname", "--file=.env"],
                        ["hostname", "evil-host"],
                        ["whoami", "extra"],
                        ["pwd", "/etc"],
                        ["uname", "-a", "extra"],
                        ["uptime", "--evil"],
                        ["free", "-s", "1"],
                        ["which", "/bin/sh"],
                        ["printenv", "-x"],
                    ]
                    for argv in blocked_file_argvs:
                        with self.subTest(blocked_argv=argv):
                            st, _, body = rh.request(
                                "POST",
                                "/hub/v1/host/exec",
                                token=tok,
                                body={"argv": argv, "workdir": str(repo_dir)},
                            )
                            self.assertEqual(403, st, f"{argv} -> {body}")
                            raw = json.dumps(body)
                            self.assertNotIn(env_secret, raw)
                            self.assertNotIn(gov_secret, raw)

                    # 2. P0-2 (M2-B3-R2): BSD `e` and mixed POSIX/BSD `-ex`/`-e -x` on `ps` MUST return 403 & zero environ leak
                    blocked_ps_argvs = [
                        ["ps", "eww", str(child.pid)],
                        ["ps", "auxeww"],
                        ["ps", "ef"],
                        ["ps", "ef", "-p", str(child.pid)],
                        ["ps", "e"],
                        ["ps", "xe"],
                        ["ps", "-e", "eww"],
                        ["ps", "-e", "aux"],
                        ["ps", "-ex"],
                        ["ps", "-eax"],
                        ["ps", "-e", "-x"],
                        ["ps", "-o", "pid,environ"],
                    ]
                    for argv in blocked_ps_argvs:
                        with self.subTest(blocked_ps=argv):
                            st, _, body = rh.request(
                                "POST",
                                "/hub/v1/host/exec",
                                token=tok,
                                body={"argv": argv, "workdir": str(repo_dir)},
                            )
                            self.assertEqual(403, st, f"{argv} -> {body}")
                            self.assertNotIn(probe_marker, json.dumps(body))

                    # 3. Safe read-only invocations MUST succeed with 200 and zero leaked env secrets
                    allowed_argvs = [
                        ["date", "-u"],
                        ["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"],
                        ["date", "--iso-8601=seconds"],
                        ["ss", "-tuln"],
                        ["hostname", "-s"],
                        ["ps", "-ef"],
                        ["ps", "aux"],
                        ["ps", "-p", str(child.pid), "-o", "pid,comm,args"],
                        ["ps", "-e", "--no-headers", "-o", "pid,comm"],
                        ["uname", "-s"],
                        ["pwd", "-P"],
                        ["whoami"],
                        ["id", "-u"],
                        ["uptime", "-p"],
                        ["free", "-m"],
                        ["df", "-h", str(repo_dir)],
                        ["which", "ls"],
                    ]
                    for argv in allowed_argvs:
                        with self.subTest(allowed_argv=argv):
                            st, _, body = rh.request(
                                "POST",
                                "/hub/v1/host/exec",
                                token=tok,
                                body={"argv": argv, "workdir": str(repo_dir)},
                            )
                            self.assertEqual(200, st, f"{argv} -> {body}")
                            self.assertEqual(0, body.get("exit_code"), f"{argv} -> {body}")
                            self.assertNotIn(probe_marker, json.dumps(body))
            finally:
                child.terminate()
                try:
                    child.wait(timeout=3.0)
                except Exception:
                    child.kill()


class TestWithBotBusDirBindingIsolation(unittest.TestCase):
    """Regression tests for B1 & B2 on `federation_hub._with_bot_bus_dir`."""

    def _load_fresh_bus_at(self, initial_dir: str, mod_name: str):
        spec = importlib.util.spec_from_file_location(mod_name, str(BRIDGE_DIR / "bot_bus.py"))
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        with mock.patch.dict(os.environ, {"AGY_BOT_BUS_DIR": initial_dir}, clear=False):
            spec.loader.exec_module(mod)
        return mod

    def test_b1_with_bot_bus_dir_target_equals_initial_overrides_env_and_restores(self):
        with tempfile.TemporaryDirectory() as d_init, tempfile.TemporaryDirectory() as d_env:
            fresh_bus = self._load_fresh_bus_at(d_init, "bot_bus_hub_b1")
            with (
                mock.patch.object(hub, "bot_bus", fresh_bus),
                mock.patch.dict(os.environ, {"AGY_BOT_BUS_DIR": d_env}, clear=False),
            ):
                # Outer env override points at d_env
                self.assertEqual(d_env, fresh_bus._effective_bus_dir())
                self.assertEqual(os.path.join(d_env, "team_config.json"), fresh_bus._config_file())

                # Inner _with_bot_bus_dir(d_init) MUST bind all paths & writes to d_init despite target == _INITIAL_BUS_DIR
                with hub._with_bot_bus_dir(d_init):
                    self.assertEqual(d_init, fresh_bus._effective_bus_dir())
                    self.assertEqual(os.path.join(d_init, "team_config.json"), fresh_bus._config_file())
                    self.assertEqual(os.path.join(d_init, "bus.lock"), fresh_bus._lock_file())
                    self.assertEqual(os.path.join(d_init, "roster.json"), fresh_bus._roster_file())
                    fresh_bus.update_bot_config("b1_worker", role="worker", specialty="dev")
                    fresh_bus.heartbeat_bot(
                        {"handle": "b1_worker", "pid": os.getpid(), "role": "worker", "busy": False}
                    )

                # Exit restores resolution back to d_env
                self.assertEqual(d_env, fresh_bus._effective_bus_dir())
                self.assertEqual(os.path.join(d_env, "team_config.json"), fresh_bus._config_file())
                self.assertEqual(os.path.join(d_env, "bus.lock"), fresh_bus._lock_file())
                self.assertEqual(os.path.join(d_env, "roster.json"), fresh_bus._roster_file())

            # All disk writes landed in d_init, zero files created in d_env
            self.assertTrue((Path(d_init) / "team_config.json").is_file())
            self.assertTrue((Path(d_init) / "bus.lock").is_file())
            self.assertTrue((Path(d_init) / "roster.json").is_file())
            self.assertIn("b1_worker", json.loads((Path(d_init) / "team_config.json").read_text(encoding="utf-8"))["bots"])
            self.assertEqual([], list(Path(d_env).iterdir()))

    def test_b2_with_bot_bus_dir_overrides_single_constant_patch_and_restores(self):
        with (
            tempfile.TemporaryDirectory() as target,
            tempfile.TemporaryDirectory() as custom_dir,
            tempfile.TemporaryDirectory() as nested_dir,
        ):
            fresh_bus = self._load_fresh_bus_at(target, "bot_bus_hub_b2")
            custom_cfg = os.path.join(custom_dir, "custom_team_config.json")

            with (
                mock.patch.object(hub, "bot_bus", fresh_bus),
                mock.patch.object(fresh_bus, "CONFIG_FILE", custom_cfg),
            ):
                self.assertEqual(target, fresh_bus.BUS_DIR)
                self.assertEqual(custom_cfg, fresh_bus._config_file())
                self.assertEqual(os.path.join(target, "bus.lock"), fresh_bus._lock_file())

                with hub._with_bot_bus_dir(target):
                    self.assertEqual(os.path.join(target, "team_config.json"), fresh_bus._config_file())
                    self.assertEqual(os.path.join(target, "bus.lock"), fresh_bus._lock_file())
                    self.assertEqual(os.path.join(target, "team_config.json"), fresh_bus.CONFIG_FILE)
                    fresh_bus.update_bot_config("b2_coord", role="coordinator")

                    # Nested _with_bot_bus_dir switches cleanly and restores outer target
                    with hub._with_bot_bus_dir(nested_dir):
                        self.assertEqual(nested_dir, fresh_bus._effective_bus_dir())
                        self.assertEqual(os.path.join(nested_dir, "team_config.json"), fresh_bus._config_file())
                        fresh_bus.update_bot_config("b2_nested", role="worker")

                    self.assertEqual(target, fresh_bus._effective_bus_dir())
                    self.assertEqual(os.path.join(target, "team_config.json"), fresh_bus._config_file())

                # Exit restores single-constant CONFIG_FILE patch
                self.assertEqual(custom_cfg, fresh_bus.CONFIG_FILE)
                self.assertEqual(custom_cfg, fresh_bus._config_file())

                # Blank bus_dir rejected fail-closed
                with self.assertRaises(ValueError):
                    with hub._with_bot_bus_dir("   "):
                        pass

            self.assertFalse(os.path.exists(custom_cfg))
            self.assertIn("b2_coord", json.loads((Path(target) / "team_config.json").read_text(encoding="utf-8"))["bots"])
            self.assertIn("b2_nested", json.loads((Path(nested_dir) / "team_config.json").read_text(encoding="utf-8"))["bots"])


if __name__ == "__main__":
    unittest.main()
