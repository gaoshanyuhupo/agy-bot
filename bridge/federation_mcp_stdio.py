#!/usr/bin/env python3
"""Lightweight stdio MCP adapter bridging local external agents (e.g. Hermes) to Federation Hub.

Security invariants (`M2-C1`):
- Strictly FORBIDS passing plaintext tokens on CLI argv (`--token`, `-t`, `--api-key`,
  `--bearer`, `--secret`, `--auth-token`, or raw `agy_fed_*` literals).
- Loads credentials exclusively from `AGY_FEDERATION_TOKEN` env var or `--token-file`
  (rejecting world-readable token files on POSIX).
- Defaults strictly to loopback Hub URL (`http://127.0.0.1:18799/hub/mcp`) and refuses
  non-loopback URLs unless `AGY_FEDERATION_ALLOW_REMOTE_HUB=1`.
- Always bypasses `HTTP_PROXY`/`HTTPS_PROXY` via `urllib.request.ProxyHandler({})`.
- Automatically signs every request with `Authorization: Bearer ...` and anti-replay
  headers (`X-Agy-Timestamp`, `X-Agy-Nonce`, `X-Agy-Signature`).
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from typing import Any, Dict, Mapping, Optional, Sequence
import urllib.error
import urllib.request
from urllib.parse import urlsplit

if __package__:
    from . import federation_hub  # type: ignore
    from . import federation_registry  # type: ignore
else:
    _THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    if _THIS_DIR not in sys.path:
        sys.path.insert(0, _THIS_DIR)
    import federation_hub  # type: ignore
    import federation_registry  # type: ignore

DEFAULT_HUB_MCP_URL = f"http://{federation_hub.DEFAULT_HUB_HOST}:{federation_hub.DEFAULT_HUB_PORT}/hub/mcp"

_FORBIDDEN_CLI_FLAGS = frozenset(
    {
        "--token",
        "-t",
        "--api-key",
        "--apikey",
        "--bearer",
        "--secret",
        "--auth-token",
        "--access-token",
    }
)


def reject_cli_token_args(argv: Sequence[str]) -> None:
    """Fail-fast if any CLI argument attempts to pass a plaintext token or secret flag."""
    for raw in argv:
        tok = str(raw or "").strip()
        low = tok.lower()
        flag, _eq, _val = low.partition("=")
        if low in _FORBIDDEN_CLI_FLAGS or flag in _FORBIDDEN_CLI_FLAGS:
            raise ValueError(
                "CLI_TOKEN_FORBIDDEN: plaintext token CLI flags are strictly forbidden; "
                "use AGY_FEDERATION_TOKEN env var or --token-file"
            )
        if federation_registry.TOKEN_PREFIX in tok:
            raise ValueError(
                "CLI_TOKEN_FORBIDDEN: raw federation token detected in CLI argv; "
                "use AGY_FEDERATION_TOKEN env var or --token-file"
            )


def validate_hub_url(
    url: str,
    *,
    allow_remote: Optional[bool] = None,
    env: Optional[Mapping[str, str]] = None,
) -> str:
    """Validate Hub MCP URL (loopback-only unless `AGY_FEDERATION_ALLOW_REMOTE_HUB=1`)."""
    raw = str(url or "").strip()
    if not raw or any(ch in raw for ch in ("\r", "\n", "\x00")):
        raise ValueError("INVALID_HUB_URL: empty or contains forbidden control characters")
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"INVALID_HUB_URL: unsupported scheme {parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError("INVALID_HUB_URL: missing hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("INVALID_HUB_URL: embedded credentials in URL are forbidden")
    if allow_remote is None:
        e = os.environ if env is None else env
        allow_remote = str(e.get("AGY_FEDERATION_ALLOW_REMOTE_HUB") or "").strip() == "1"
    if not federation_hub.is_loopback_host(parsed.hostname) and not bool(allow_remote):
        raise ValueError(
            f"REMOTE_HUB_DENIED: refusing non-loopback Hub URL host {parsed.hostname!r} "
            "without AGY_FEDERATION_ALLOW_REMOTE_HUB=1"
        )
    return raw


def load_federation_token(
    *,
    token_file: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> str:
    """Load federation bearer token from `--token-file` (non-world-readable) or `AGY_FEDERATION_TOKEN`."""
    if token_file:
        tf = os.path.abspath(os.path.expanduser(str(token_file).strip()))
        if not os.path.isfile(tf):
            raise ValueError(f"TOKEN_FILE_NOT_FOUND: {tf}")
        st = os.stat(tf)
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            raise PermissionError(
                f"INSECURE_TOKEN_FILE: token file {tf!r} has group/other permissions ({oct(mode)}); owner-only chmod 600 required"
            )
        with open(tf, "r", encoding="utf-8") as fh:
            tok = fh.read().strip()
        if not tok:
            raise ValueError("TOKEN_EMPTY: token file is empty")
        return tok

    e = os.environ if env is None else env
    tok = str(e.get("AGY_FEDERATION_TOKEN") or "").strip()
    if not tok:
        raise ValueError("TOKEN_MISSING: set AGY_FEDERATION_TOKEN or pass --token-file")
    return tok


class FederationMCPStdioAdapter:
    """Forwards JSON-RPC 2.0 MCP messages over direct (proxy-bypassed) HTTP POST to Hub."""

    def __init__(
        self,
        *,
        hub_url: str,
        token: str,
        timeout_sec: float = 30.0,
        allow_remote: Optional[bool] = None,
        env: Optional[Mapping[str, str]] = None,
    ):
        self.hub_url = validate_hub_url(hub_url, allow_remote=allow_remote, env=env)
        if not token or not str(token).strip():
            raise ValueError("TOKEN_MISSING: non-empty federation token required")
        self._token = str(token).strip()
        self.timeout_sec = max(1.0, float(timeout_sec or 30.0))
        # Always bypass HTTP_PROXY / HTTPS_PROXY so local Hub traffic never leaks through a proxy
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def forward_request(self, req_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        body = json.dumps(req_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        path_only = urlsplit(self.hub_url).path or "/hub/mcp"
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {self._token}",
        }
        headers.update(
            federation_hub.build_replay_headers(
                self._token,
                "POST",
                path_only,
                body,
            )
        )
        req = urllib.request.Request(self.hub_url, data=body, headers=headers, method="POST")
        req_id = req_obj.get("id")
        try:
            with self._opener.open(req, timeout=self.timeout_sec) as resp:
                raw = resp.read()
                if resp.status == 202 or req_id is None:
                    return None
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                err_raw = exc.read().decode("utf-8", errors="replace")
                parsed = json.loads(err_raw)
                if isinstance(parsed, dict) and "jsonrpc" in parsed:
                    return parsed
                msg = str(parsed.get("message") or parsed.get("error") or err_raw) if isinstance(parsed, dict) else err_raw
            except Exception:
                msg = str(exc)
            safe_msg = federation_registry.redact_secrets(msg, extra_secrets=[self._token])
            if req_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32000, "message": f"HTTP {exc.code}: {safe_msg}"},
            }
        except Exception as exc:
            safe_msg = federation_registry.redact_secrets(str(exc), extra_secrets=[self._token])
            if req_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32000, "message": safe_msg},
            }

    def serve_streams(self, stdin_stream, stdout_stream) -> int:
        for raw_line in stdin_stream:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if not isinstance(msg, dict):
                continue
            reply = self.forward_request(msg)
            if reply is not None:
                stdout_stream.write(json.dumps(reply, ensure_ascii=False, separators=(",", ":")) + "\n")
                stdout_stream.flush()
        return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="AGY Federation Hub stdio MCP adapter")
    p.add_argument(
        "--hub-url",
        default=None,
        help=f"Federation Hub MCP URL (default: {DEFAULT_HUB_MCP_URL})",
    )
    p.add_argument(
        "--token-file",
        default=None,
        help="Path to chmod-600 file containing the agent federation token (or use AGY_FEDERATION_TOKEN env)",
    )
    p.add_argument("--timeout", type=float, default=30.0, help="HTTP request timeout in seconds")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        reject_cli_token_args(raw_argv)
        args = build_arg_parser().parse_args(raw_argv)
        hub_url = args.hub_url or os.environ.get("AGY_FEDERATION_HUB_URL") or DEFAULT_HUB_MCP_URL
        token = load_federation_token(token_file=args.token_file)
        adapter = FederationMCPStdioAdapter(hub_url=hub_url, token=token, timeout_sec=args.timeout)
        return adapter.serve_streams(sys.stdin, sys.stdout)
    except Exception as exc:
        safe_err = federation_registry.redact_secrets(str(exc))
        sys.stderr.write(f"federation_mcp_stdio error: {safe_err}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
