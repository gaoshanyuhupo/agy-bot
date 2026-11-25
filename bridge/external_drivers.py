#!/usr/bin/env python3
"""Pluggable External Agent Drivers for Hermes (local & remote) and HTTP/A2A/Pull Workers.

Flat standalone module (no top-level `import bridge`) registered into
`bridge/agent_driver.py`'s `DriverRegistry`:
- `hermes_local`  -> `HermesLocalDriver` / `HermesLocalSession`
- `hermes_remote` -> `HermesRemoteDriver` / `HermesRemoteSession`
- `http_external` (aliases `muse_remote`, `http_a2a`, `pull_worker`)
                  -> `HttpExternalAgentDriver` / `HttpExternalAgentSession`

Security invariants enforced fail-closed (C2, C5, C6, C7):
- `HermesLocalDriver`: zero `shell=True`, strict `profile` regex + binary whitelist,
  prompt delivered exclusively over `stdin` (`--query-file -`), shared
  `build_session_security_context()` + `enforce_readonly_cli_args()` + `build_base_session_env()`,
  readonly/safe mode blocks `--yolo`/`-y`/`--auto-approve` & mutating flags, and
  `cancel`/`timeout`/`close` reaps entire process tree (including `setsid` grandchildren)
  via `_kill_process_tree(..., expected_root_starttime=...)`.
- `HermesRemoteDriver` & `HttpExternalAgentDriver`: strict `validate_outbound_url` SSRF
  guard (`http`/`https` only; blocks IPv4 link-local/cloud-metadata, IPv6 link-local,
  IPv4 zero-network, unspecified, multicast, and IPv4-mapped IPv6 equivalents), HTTP auto-redirects
  disabled fail-closed, Owner-bound immutable base URL, profile traversal rejection,
  CRLF header injection rejection, connect/read timeouts, bounded response/SSE byte caps,
  ephemeral OpenBao `secret_ref` resolution with zero persistence/echo, and remote `/stop`
  cancellation convergence.
"""

from __future__ import annotations

import collections
import dataclasses
import http.client
import ipaddress
import json
import os
import queue
import re
import socket
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union
import urllib.error
import urllib.request
from urllib.parse import urlsplit

if __package__:
    from . import agent_driver  # type: ignore
    from . import federation_registry  # type: ignore
else:
    import agent_driver  # type: ignore
    import federation_registry  # type: ignore


class SSRFError(ValueError):
    """Raised fail-closed when an outbound URL, resolved IP, or redirect violates SSRF policy."""


class HeaderInjectionError(ValueError):
    """Raised fail-closed when an outbound HTTP header contains CRLF or invalid characters."""


DEFAULT_HERMES_ALLOWED_BINS: Tuple[str, ...] = (
    os.path.join(os.path.expanduser("~"), ".local", "bin", "hermes"),
    "/usr/local/bin/hermes",
    "/usr/bin/hermes",
)

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")

_HERMES_EXTRA_ARGS_ALWAYS_FORBIDDEN = frozenset(
    {
        "-p",
        "--profile",
        "--query-file",
        "-q",
        "--query",
        "--in",
        "--worktree",
        "--format",
        "--api-key",
        "--base-url",
        "--provider",
        "--ignore-user-config",
        "--ignore-rules",
        "--accept-hooks",
        "-c",
        "--config",
    }
)

_HERMES_READONLY_FORBIDDEN_FLAGS = frozenset(
    {
        "--yolo",
        "-y",
        "--auto-approve",
        "--dangerously-skip-permissions",
        "--allow-dangerously-skip-permissions",
        "--dangerously-bypass-approvals-and-sandbox",
        "--dangerously-allow-all",
        "--full-auto",
        "--accept-edits",
        "--ignore-rules",
        "--accept-hooks",
        "--api-key",
        "--base-url",
        "-t",
        "--toolsets",
        "-s",
        "--skills",
        "--permission-mode",
    }
)

# Cloud metadata & IPv6 transition prefixes constructed programmatically (zero literal IPs)
_AWS_IPV6_IMDS = ipaddress.IPv6Address(bytes.fromhex("fd000ec2" + "0000" * 5 + "0254"))
_ALIBABA_IPV4_IMDS = ipaddress.IPv4Address(bytes((100, 100, 100, 200)))
_NAT64_WELL_KNOWN_NET = ipaddress.IPv6Network(
    (ipaddress.IPv6Address(bytes.fromhex("0064ff9b" + "0000" * 6)), 96)
)
_NAT64_LOCAL_NET = ipaddress.IPv6Network(
    (ipaddress.IPv6Address(bytes.fromhex("0064ff9b0001" + "0000" * 5)), 48)
)
_IPV4_TRANSLATED_NET = ipaddress.IPv6Network(
    (ipaddress.IPv6Address(bytes.fromhex("0000" * 4 + "ffff0000" + "0000" * 2)), 96)
)
_IPV4_COMPAT_NET = ipaddress.IPv6Network((ipaddress.IPv6Address(bytes(16)), 96))

DEFAULT_CONNECT_TIMEOUT_SEC = 10.0
DEFAULT_READ_TIMEOUT_SEC = 60.0
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_SSE_BYTES = 8 * 1024 * 1024

HERMES_LOCAL_CAPABILITIES = agent_driver.DriverCapabilities(
    engine_name="hermes_local",
    supports_compact=False,
    supports_resume=True,
    supports_stream_json=True,
    supports_permission_modes=True,
    supports_native_tools=True,
)
HERMES_REMOTE_CAPABILITIES = agent_driver.DriverCapabilities(
    engine_name="hermes_remote",
    supports_compact=False,
    supports_resume=True,
    supports_stream_json=True,
    supports_permission_modes=True,
    supports_native_tools=True,
)
HTTP_EXTERNAL_CAPABILITIES = agent_driver.DriverCapabilities(
    engine_name="http_external",
    supports_compact=False,
    supports_resume=False,
    supports_stream_json=True,
    supports_permission_modes=True,
    supports_native_tools=True,
)


# ---------------------------------------------------------------- Security & Validation Helpers
def _env_allows_hermes_bin_override(env: Optional[Mapping[str, str]] = None) -> bool:
    """Permit `AGY_HERMES_ALLOWED_BINS` ONLY in clean `local_admin` environments (B5)."""
    e = os.environ if env is None else env
    if str(e.get("AGY_UNTRUSTED_SESSION") or "").strip() == "1":
        return False
    if str(e.get("AGY_MEMORY_READONLY") or "").strip() == "1":
        return False
    if str(e.get("AGY_RBAC_ROLE") or "").strip().lower() == "readonly":
        return False
    trust = str(e.get("AGY_TRUST_LEVEL") or "").strip().lower()
    if trust != "local_admin":
        return False
    return True


def validate_hermes_binary(
    binary_path: Optional[str],
    *,
    allowed_bins: Optional[Sequence[str]] = None,
    env: Optional[Mapping[str, str]] = None,
) -> str:
    """Validate that `binary_path` resolves to a whitelisted executable regular file and return `realpath` (B5)."""
    raw = str(binary_path or DEFAULT_HERMES_ALLOWED_BINS[0]).strip()
    if not raw:
        raise ValueError("FORBIDDEN_BINARY: hermes binary path cannot be empty")
    if any(ch in raw for ch in ("\x00", "\r", "\n", ";", "|", "&", "$", "`", " ")):
        raise ValueError(f"FORBIDDEN_BINARY: unsafe characters in binary path: {raw!r}")
    if not os.path.isabs(raw):
        raise ValueError(f"FORBIDDEN_BINARY: binary path must be absolute: {raw!r}")

    e = os.environ if env is None else env
    whitelist_raw: List[str] = list(DEFAULT_HERMES_ALLOWED_BINS)
    if _env_allows_hermes_bin_override(e):
        env_extra = str(e.get("AGY_HERMES_ALLOWED_BINS") or "").strip()
        if env_extra:
            for item in env_extra.split(":"):
                if item.strip():
                    whitelist_raw.append(item.strip())
    if allowed_bins:
        whitelist_raw.extend(str(x).strip() for x in allowed_bins if str(x).strip())

    allowed_resolved = {os.path.realpath(os.path.abspath(p)) for p in whitelist_raw if os.path.isabs(p)}
    cand_abs = os.path.abspath(raw)
    cand_real = os.path.realpath(cand_abs)
    if cand_real not in allowed_resolved:
        raise ValueError(f"FORBIDDEN_BINARY: executable {raw!r} is not in the Hermes binary whitelist")
    if not os.path.isfile(cand_real) or os.path.islink(cand_real) or not os.access(cand_real, os.X_OK):
        raise ValueError(
            f"FORBIDDEN_BINARY: resolved executable {cand_real!r} must be a non-symlink executable regular file"
        )
    return cand_real


def validate_header_map(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Validate HTTP header names and values against CRLF/null injection (C6)."""
    if not headers:
        return {}
    if not isinstance(headers, dict):
        raise HeaderInjectionError("HEADER_INJECTION_DENIED: headers must be a dict")
    clean: Dict[str, str] = {}
    for k, v in headers.items():
        ks = str(k)
        vs = str(v)
        if any(ch in ks for ch in ("\r", "\n", "\x00")) or not _HEADER_NAME_RE.fullmatch(ks):
            raise HeaderInjectionError(f"HEADER_INJECTION_DENIED: invalid header name {ks!r}")
        if any(ch in vs for ch in ("\r", "\n", "\x00")):
            raise HeaderInjectionError(f"HEADER_INJECTION_DENIED: CRLF/control char rejected in header {ks!r}")
        clean[ks] = vs
    return clean


def _is_forbidden_ssrf_ip(ip_obj: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
    """Check whether `ip_obj` (or any embedded IPv4 transition target) falls in blocked SSRF ranges (B6)."""
    if isinstance(ip_obj, ipaddress.IPv4Address):
        if ip_obj.is_link_local:
            return True, f"link_local_or_metadata ({ip_obj})"
        if ip_obj == _ALIBABA_IPV4_IMDS:
            return True, f"cloud_metadata_alibaba ({ip_obj})"
        if ip_obj.packed[0] == 0:
            return True, f"zero_network ({ip_obj})"
        if ip_obj.is_multicast:
            return True, f"multicast ({ip_obj})"
        if ip_obj.is_unspecified:
            return True, f"unspecified ({ip_obj})"
        return False, ""

    # IPv6 direct checks
    if ip_obj == _AWS_IPV6_IMDS:
        return True, f"aws_ipv6_imds ({ip_obj})"
    if ip_obj.is_link_local:
        return True, f"ipv6_link_local ({ip_obj})"
    if ip_obj.is_unspecified:
        return True, f"ipv6_unspecified ({ip_obj})"
    if ip_obj.is_multicast:
        return True, f"ipv6_multicast ({ip_obj})"

    # Recursively inspect embedded IPv4 addresses across all IPv6 transition/translation mechanisms
    embedded_v4: List[Tuple[str, ipaddress.IPv4Address]] = []
    if ip_obj.ipv4_mapped is not None:
        embedded_v4.append(("ipv4_mapped", ip_obj.ipv4_mapped))
    if ip_obj.sixtofour is not None:
        embedded_v4.append(("sixtofour", ip_obj.sixtofour))
    if ip_obj.teredo is not None:
        teredo_server, teredo_client = ip_obj.teredo
        embedded_v4.append(("teredo_server", teredo_server))
        embedded_v4.append(("teredo_client", teredo_client))
    if ip_obj in _NAT64_WELL_KNOWN_NET:
        embedded_v4.append(("nat64_well_known", ipaddress.IPv4Address(ip_obj.packed[12:16])))
    if ip_obj in _NAT64_LOCAL_NET:
        embedded_v4.append(("nat64_local", ipaddress.IPv4Address(ip_obj.packed[12:16])))
    if ip_obj in _IPV4_TRANSLATED_NET:
        embedded_v4.append(("ipv4_translated", ipaddress.IPv4Address(ip_obj.packed[12:16])))
    if ip_obj in _IPV4_COMPAT_NET and int(ip_obj) > 1:
        embedded_v4.append(("ipv4_compatible", ipaddress.IPv4Address(ip_obj.packed[12:16])))

    for kind_lbl, v4_addr in embedded_v4:
        blocked, reason = _is_forbidden_ssrf_ip(v4_addr)
        if blocked:
            return True, f"{kind_lbl}:{reason}"
    return False, ""


def resolve_and_validate_outbound_url(
    url: str,
    *,
    resolve_fn: Optional[Callable[[str, int], Sequence[str]]] = None,
) -> Tuple[str, List[str]]:
    """Strict outbound SSRF URL & DNS validator returning `(clean_url, pinned_ips)` for IP pinning (B6).

    - Allows ONLY `http://` and `https://` schemes (blocks `file://`, `gopher://`, etc.).
    - Rejects CRLF, null bytes, embedded credentials, and empty hostnames.
    - Resolves hostname (or parses IP literal) and checks EVERY IP + IPv6 transition targets against
      blocked metadata/link-local/zero-network/multicast ranges.
    - Returns validated canonical IP strings so callers can pin TCP connections without a second DNS query.
    """
    if not isinstance(url, str) or not url.strip():
        raise SSRFError("SSRF_DENIED: empty outbound URL")
    clean = url.strip()
    if any(ch in clean for ch in ("\r", "\n", "\x00")):
        raise SSRFError("SSRF_DENIED: control/CRLF character in outbound URL")

    parsed = urlsplit(clean)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise SSRFError(f"SSRF_DENIED: forbidden URL scheme {scheme!r} (only http/https permitted)")
    if parsed.username is not None or parsed.password is not None:
        raise SSRFError("SSRF_DENIED: embedded URL credentials are forbidden")
    host = parsed.hostname
    if not host:
        raise SSRFError("SSRF_DENIED: missing hostname in outbound URL")
    port = parsed.port or (443 if scheme == "https" else 80)

    resolved_ips: List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = []
    try:
        resolved_ips.append(ipaddress.ip_address(host))
    except ValueError:
        try:
            if resolve_fn is not None:
                raw_ips = list(resolve_fn(host, port))
            else:
                infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                raw_ips = [str(info[4][0]) for info in infos if info and info[4]]
        except Exception as exc:
            raise SSRFError(f"SSRF_DENIED: DNS resolution failed for host {host!r}: {exc}") from exc
        if not raw_ips:
            raise SSRFError(f"SSRF_DENIED: DNS returned no IP addresses for host {host!r}")
        for raw_ip in raw_ips:
            ip_clean = str(raw_ip).split("%", 1)[0].strip()
            try:
                resolved_ips.append(ipaddress.ip_address(ip_clean))
            except ValueError as exc:
                raise SSRFError(f"SSRF_DENIED: invalid resolved IP {raw_ip!r} for host {host!r}") from exc

    pinned: List[str] = []
    seen_ip: set[str] = set()
    for ip_obj in resolved_ips:
        blocked, reason = _is_forbidden_ssrf_ip(ip_obj)
        if blocked:
            raise SSRFError(f"SSRF_DENIED: target {host!r} resolved to blocked address ({reason})")
        s_ip = str(ip_obj)
        if s_ip not in seen_ip:
            seen_ip.add(s_ip)
            pinned.append(s_ip)

    return clean, pinned


def validate_outbound_url(
    url: str,
    *,
    resolve_fn: Optional[Callable[[str, int], Sequence[str]]] = None,
) -> str:
    """Strict outbound SSRF URL & DNS-resolved IP validator (C6). Returns normalized URL."""
    clean, _pinned = resolve_and_validate_outbound_url(url, resolve_fn=resolve_fn)
    return clean


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail-closed redirect handler that blocks ALL 3xx redirects (prevents 302 -> metadata SSRF)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        safe_loc = str(newurl or "").split("?", 1)[0][:120]
        raise SSRFError(
            f"SSRF_DENIED: automatic HTTP redirect blocked (status={code}, location={safe_loc!r})"
        )


def _connect_pinned_ips(
    pinned_ips: Sequence[str],
    port: int,
    timeout: Optional[float],
    source_address: Optional[Tuple[str, int]] = None,
) -> socket.socket:
    """Connect TCP strictly to pre-validated numeric `pinned_ips` using `AI_NUMERICHOST` (zero DNS TOCTOU)."""
    last_err: Optional[Exception] = None
    for ip_str in pinned_ips:
        try:
            infos = socket.getaddrinfo(ip_str, port, 0, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST)
        except OSError as exc:
            last_err = exc
            continue
        for family, socktype, proto, _canon, sockaddr in infos:
            sock: Optional[socket.socket] = None
            try:
                sock = socket.socket(family, socktype, proto)
                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT and timeout is not None:
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sockaddr)
                return sock
            except OSError as exc:
                last_err = exc
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
    if last_err is not None:
        raise last_err
    raise OSError("No pinned IP addresses available for outbound connection")


def _make_pinned_http_conn_cls(pinned_ips: Tuple[str, ...]):
    class _PinnedHTTPConnection(http.client.HTTPConnection):
        def connect(self):
            # Connect directly to validated numeric IP while preserving `self.host` for the `Host` header.
            self.sock = _connect_pinned_ips(pinned_ips, self.port, self.timeout, self.source_address)

    return _PinnedHTTPConnection


def _make_pinned_https_conn_cls(pinned_ips: Tuple[str, ...]):
    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            # Connect directly to validated numeric IP; TLS SNI & cert verification still use original `self.host`.
            raw_sock = _connect_pinned_ips(pinned_ips, self.port, self.timeout, self.source_address)
            try:
                self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
            except Exception:
                try:
                    raw_sock.close()
                except OSError:
                    pass
                raise

    return _PinnedHTTPSConnection


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, pinned_ips: Sequence[str]):
        super().__init__()
        self._conn_cls = _make_pinned_http_conn_cls(tuple(pinned_ips))

    def http_open(self, req):
        return self.do_open(self._conn_cls, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pinned_ips: Sequence[str], context=None):
        super().__init__(context=context)
        self._conn_cls = _make_pinned_https_conn_cls(tuple(pinned_ips))

    def https_open(self, req):
        return self.do_open(self._conn_cls, req, context=self._context)


def _build_hardened_opener(pinned_ips: Optional[Sequence[str]] = None) -> urllib.request.OpenerDirector:
    """Build hardened urllib opener: zero env proxies (`ProxyHandler({})`), zero redirects, and IP pinning (B6)."""
    handlers: List[Any] = [
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    ]
    if pinned_ips:
        handlers.append(_PinnedHTTPHandler(pinned_ips))
        handlers.append(_PinnedHTTPSHandler(pinned_ips))
    return urllib.request.build_opener(*handlers)


def resolve_secret_ref(
    secret_ref: str,
    *,
    secret_resolver: Optional[Callable[[str], str]] = None,
) -> str:
    """Resolve an OpenBao `secret_ref` ephemerally in-memory (zero disk writes, zero logging)."""
    clean_ref = federation_registry.validate_secret_ref(secret_ref)
    if not clean_ref:
        return ""
    if secret_resolver is not None:
        val = str(secret_resolver(clean_ref) or "")
        return val.strip()

    path_part, _, field_part = clean_ref.partition("#")
    cmd = ["bao", "get", path_part]
    if field_part:
        cmd += ["--field", field_part]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=5.0,
        shell=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"OpenBao secret resolution failed for ref {clean_ref!r} (exit={proc.returncode})")
    return (proc.stdout or "").strip()


def _extract_response_socket(stream) -> Any:
    raw_fp = getattr(stream, "fp", None)
    raw_obj = getattr(raw_fp, "raw", None)
    sock = getattr(raw_obj, "_sock", None)
    if sock is not None:
        return sock
    return getattr(raw_fp, "_sock", None)


def _read_bounded_bytes(
    stream,
    max_bytes: int,
    *,
    cancel_event: Optional[threading.Event] = None,
    deadline: Optional[float] = None,
) -> bytes:
    """Read from an HTTP response stream enforcing a hard byte ceiling and monotonic total deadline (B7.4)."""
    chunks: List[bytes] = []
    total = 0
    cap = max(1, int(max_bytes))
    sock_obj = _extract_response_socket(stream)
    read_fn = getattr(stream, "read1", None) or stream.read
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise RuntimeError("CANCELLED: outbound HTTP read aborted")
        if deadline is not None:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise TimeoutError("READ_TIMEOUT: outbound HTTP read exceeded total deadline")
            if sock_obj is not None:
                try:
                    sock_obj.settimeout(max(0.05, min(0.25, rem)))
                except Exception:
                    pass
        try:
            chunk = read_fn(min(16384, cap - total + 1))
        except (socket.timeout, TimeoutError):
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("READ_TIMEOUT: outbound HTTP read exceeded total deadline")
            continue
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise ValueError(f"RESPONSE_LIMIT_EXCEEDED: response exceeded max_response_bytes ({cap})")
        chunks.append(chunk)
    return b"".join(chunks)


def _sanitize_error_message(exc: Exception, secrets_to_scrub: Sequence[str] = ()) -> str:
    return federation_registry.redact_secrets(str(exc), extra_secrets=secrets_to_scrub)


def _normalize_hermes_stream_event(raw_ev: Dict[str, Any], step_counter: List[int]) -> Optional[Dict[str, Any]]:
    """Translate Hermes `stream-json` JSONL events into normalized `AgentSession` events."""
    if not isinstance(raw_ev, dict):
        return None
    # Pass through already-normalized AgentSession events
    if raw_ev.get("event") in ("init", "step_update", "result", "__eof__"):
        return raw_ev

    ev_type = str(raw_ev.get("type") or raw_ev.get("event") or "").strip().lower()
    if ev_type in ("system", "init", "session_init"):
        cid = str(
            raw_ev.get("session_id")
            or raw_ev.get("conversation_id")
            or raw_ev.get("run_id")
            or ""
        ).strip()
        if cid or raw_ev.get("subtype") == "init" or ev_type != "system":
            return {"event": "init", "conversation_id": cid}
        return None

    if ev_type in ("text", "delta", "text_delta", "assistant", "message"):
        text = str(
            raw_ev.get("text_delta")
            or raw_ev.get("delta")
            or raw_ev.get("text")
            or raw_ev.get("content")
            or ""
        )
        if not text:
            return None
        step_counter[0] += 1
        return {
            "event": "step_update",
            "step_update": {
                "step_type": "agent_response",
                "state": "DONE" if ev_type in ("assistant", "message") else "ACTIVE",
                "step_index": step_counter[0],
                "text_delta": text,
            },
        }

    if ev_type in ("tool_use", "tool_call", "tool_start"):
        step_counter[0] += 1
        return {
            "event": "step_update",
            "step_update": {
                "step_type": "tool",
                "state": "ACTIVE",
                "step_index": step_counter[0],
                "tool_name": str(raw_ev.get("name") or raw_ev.get("tool_name") or "tool"),
                "tool_info": raw_ev.get("input") if isinstance(raw_ev.get("input"), dict) else {"raw": raw_ev.get("input")},
            },
        }

    if ev_type in ("tool_result", "tool_end"):
        step_counter[0] += 1
        out_val = raw_ev.get("output") if "output" in raw_ev else raw_ev.get("result")
        return {
            "event": "step_update",
            "step_update": {
                "step_type": "tool",
                "state": "DONE",
                "step_index": step_counter[0],
                "tool_name": str(raw_ev.get("name") or raw_ev.get("tool_name") or "tool"),
                "tool_info": {"output": out_val},
            },
        }

    if ev_type in ("result", "done", "completed", "error", "failed", "cancelled"):
        resp_text = str(raw_ev.get("response") or raw_ev.get("result") or raw_ev.get("text") or "")
        err_text = str(raw_ev.get("error") or "")
        is_error_flag = raw_ev.get("is_error") is True
        explicit_status = str(raw_ev.get("status") or "").strip().upper()
        if is_error_flag or (err_text.strip() and not resp_text.strip()):
            status = "ERROR"
        else:
            raw_status = explicit_status or ("ERROR" if ev_type in ("error", "failed", "cancelled") else "SUCCESS")
            if raw_status in ("DONE", "COMPLETED", "OK", "SUCCESS"):
                status = "SUCCESS"
            elif raw_status in ("CANCELLED", "CANCELED", "ERROR", "FAILED"):
                status = "ERROR"
            else:
                status = raw_status or "SUCCESS"
        return {
            "event": "result",
            "result": {
                "status": status,
                "conversation_id": str(raw_ev.get("session_id") or raw_ev.get("conversation_id") or ""),
                "response": resp_text,
                "error": err_text,
                "usage": raw_ev.get("usage") if isinstance(raw_ev.get("usage"), dict) else {},
                "finished_reason": str(raw_ev.get("finished_reason") or ev_type),
            },
        }

    return None


# ---------------------------------------------------------------- HermesLocalDriver (C5, C7)
class HermesLocalSession(agent_driver.AgentSession):
    """Hardened local Hermes CLI session (`hermes -p <profile> chat --query-file - --oneshot --format stream-json`)."""

    driver_name: str = "hermes_local"
    capabilities: agent_driver.DriverCapabilities = HERMES_LOCAL_CAPABILITIES

    def __init__(
        self,
        conv: Optional[str],
        mode: Optional[str],
        model: Optional[str],
        effort: Optional[str],
        *,
        profile: str = "default",
        hermes_bin: Optional[str] = None,
        allowed_bins: Optional[Sequence[str]] = None,
        extra_args: Optional[Sequence[str]] = None,
        allow_yolo: bool = False,
        timeout_sec: Optional[float] = None,
        project: Optional[str] = None,
        workdir: Optional[str] = None,
        scope_key: Optional[str] = None,
        readonly: bool = False,
        untrusted: bool = False,
        is_worktree: bool = False,
        trust_level: Optional[str] = None,
        team_id: str = "",
        agent_origin: Optional[str] = None,
        turn_taint_only: bool = False,
        host=None,
    ):
        self.profile = federation_registry.validate_profile_name(profile)
        self.hermes_bin = validate_hermes_binary(hermes_bin, allowed_bins=allowed_bins)
        self.extra_args = [str(a) for a in (extra_args or ())]
        self.allow_yolo = bool(allow_yolo)
        self.timeout_sec = float(timeout_sec) if timeout_sec and float(timeout_sec) > 0 else None
        self.team_id = agent_driver.validate_team_id(team_id)

        sec_ctx = self._init_common_state(
            conv,
            mode,
            model,
            effort,
            project=project,
            workdir=workdir,
            scope_key=scope_key,
            readonly=readonly,
            untrusted=untrusted,
            is_worktree=is_worktree,
            trust_level=trust_level,
            agent_origin=agent_origin or "local_bus",
            turn_taint_only=turn_taint_only,
            driver_name="hermes_local",
            capabilities=HERMES_LOCAL_CAPABILITIES,
            host=host,
        )
        # Ensure team_id is propagated onto security_context
        if self.team_id and sec_ctx.team_id != self.team_id:
            self.security_context = agent_driver.build_session_security_context(
                mode,
                scope_key=self.scope_key,
                readonly=readonly,
                untrusted=untrusted,
                trust_level=trust_level,
                team_id=self.team_id,
                agent_origin=agent_origin or "local_bus",
                turn_taint_only=turn_taint_only,
                host=host,
            )

        self.event_q: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self.stderr_tail: "collections.deque[str]" = collections.deque(maxlen=80)
        self.proc: Optional[subprocess.Popen] = None
        self._proc_starttime: Optional[str] = None
        self._lock = threading.Lock()
        self._closed = False
        self._turn_active = False
        self._cancelled = False
        self._cancel_reason = ""
        self._eof_emitted = False
        self._result_emitted = False
        self._last_cmd: List[str] = []
        self._last_env: Dict[str, str] = {}
        self._stdout_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._timeout_timer: Optional[threading.Timer] = None
        self._exit_code: Optional[int] = None

        # Pre-validate command assembly immediately so invalid flags/profile fail fast on spawn
        self._build_command()

    @property
    def exit_code(self) -> Optional[int]:
        if self.proc is not None and self.proc.poll() is not None:
            self._exit_code = self.proc.returncode
        return self._exit_code

    def is_alive(self) -> bool:
        return not self._closed

    def _validate_hermes_args(self, cmd: List[str]) -> List[str]:
        """Enforce unconditional extra_args deny-list, safe scalar values, and readonly/untrusted downgrade (B5)."""
        sec = self.security_context
        # 1. Validate model / effort / conv scalars cannot inject CLI flags
        for field_name, field_val in (("model", self.model), ("effort", self.effort), ("conv", self.cid)):
            if field_val is not None and str(field_val).strip():
                s_val = str(field_val).strip()
                if s_val.startswith("-") or any(ch in s_val for ch in ("\x00", "\r", "\n")):
                    raise ValueError(f"FORBIDDEN_CLI_FLAG: invalid {field_name} value {field_val!r}")

        # 2. Unconditionally forbid override/escape flags in extra_args across ALL modes
        for tok in self.extra_args:
            raw_tok = str(tok or "").strip()
            low = raw_tok.lower()
            flag, _eq, _val = low.partition("=")
            if (
                low in _HERMES_EXTRA_ARGS_ALWAYS_FORBIDDEN
                or flag in _HERMES_EXTRA_ARGS_ALWAYS_FORBIDDEN
                or (
                    len(flag) > 2
                    and not flag.startswith("--")
                    and flag.startswith(("-p", "-q", "-c"))
                )
            ):
                raise ValueError(
                    f"FORBIDDEN_CLI_FLAG: extra_args flag {tok!r} is unconditionally forbidden for HermesLocalSession"
                )

        restricted = (
            sec.readonly
            or sec.effective_mode == "safe"
            or (not sec.allow_skip_permissions)
            or sec.untrusted
            or sec.trust_level in ("remote_untrusted", "readonly_guest")
        )
        if restricted:
            if self.allow_yolo:
                raise ValueError(
                    "FORBIDDEN_CLI_FLAG: --yolo/allow_yolo is strictly forbidden in readonly/safe/untrusted Hermes session"
                )
            for tok in list(self.extra_args) + list(cmd[1:]):
                low = str(tok or "").strip().lower()
                flag, _eq, _val = low.partition("=")
                if (
                    low in _HERMES_READONLY_FORBIDDEN_FLAGS
                    or flag in _HERMES_READONLY_FORBIDDEN_FLAGS
                    or (
                        len(flag) > 2
                        and not flag.startswith("--")
                        and flag.startswith(("-t", "-s", "-y", "-a"))
                    )
                ):
                    raise ValueError(
                        f"FORBIDDEN_CLI_FLAG: forbidden Hermes flag {tok!r} in readonly/safe/untrusted session"
                    )
            enforced_sec = dataclasses.replace(
                sec,
                readonly=True,
                allow_skip_permissions=False,
                effective_mode="safe",
            )
            if self.extra_args:
                agent_driver.enforce_readonly_cli_args(["hermes", *self.extra_args], enforced_sec)
            return agent_driver.enforce_readonly_cli_args(cmd, enforced_sec)
        return agent_driver.enforce_readonly_cli_args(cmd, sec)

    def _build_command(self) -> List[str]:
        sec = self.security_context
        cmd: List[str] = [
            self.hermes_bin,
            "-p",
            self.profile,
            "chat",
            "--query-file",
            "-",
            "--oneshot",
            "--format",
            "stream-json",
        ]
        restricted = (
            sec.readonly
            or sec.effective_mode == "safe"
            or (not sec.allow_skip_permissions)
            or sec.untrusted
            or sec.trust_level in ("remote_untrusted", "readonly_guest")
        )
        if restricted:
            cmd.append("--safe-mode")
        elif self.allow_yolo and sec.allow_skip_permissions and not sec.untrusted:
            cmd.append("--yolo")
        if self.model:
            cmd += ["-m", str(self.model)]
        if self.effort:
            cmd += ["--reasoning", str(self.effort)]
        if self.workdir:
            cmd += ["--in", str(self.workdir)]
        if self.cid:
            cmd += ["--resume", str(self.cid)]
        if self.extra_args:
            cmd.extend(self.extra_args)
        return self._validate_hermes_args(cmd)

    def _emit_eof(self) -> None:
        with self._lock:
            if not self._eof_emitted:
                self._eof_emitted = True
                self.event_q.put({"event": "__eof__"})

    def _emit_terminal_error_once(self, error_msg: str, reason: str) -> None:
        with self._lock:
            if not self._result_emitted:
                self._result_emitted = True
                self.event_q.put(
                    {
                        "event": "result",
                        "result": {
                            "status": "ERROR",
                            "conversation_id": self.cid or "",
                            "response": "",
                            "error": error_msg,
                            "finished_reason": reason,
                        },
                    }
                )

    def send_user_prompt(self, prompt: str, raw_slash: bool = False) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("HermesLocalSession is closed")
            if self._turn_active or (self.proc is not None and self.proc.poll() is None):
                raise RuntimeError("HermesLocalSession already has an active turn")
            self._turn_active = True
            self._eof_emitted = False
            self._result_emitted = False
            self._cancelled = False
            self._cancel_reason = ""

        try:
            cmd = self._build_command()
            env = agent_driver.build_base_session_env(
                self.security_context,
                scope_key=self.scope_key,
                host=self._host,
            )
            env["HERMES_PROFILE"] = self.profile
            self._last_cmd = list(cmd)
            self._last_env = dict(env)

            proc = subprocess.Popen(
                cmd,
                cwd=self.workdir,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
                start_new_session=True,
                shell=False,
            )
            proc_st = (
                agent_driver._read_proc_starttime(proc.pid) if proc.pid is not None else None
            )
            cancelled_during_spawn = False
            cancel_reason = ""
            with self._lock:
                self.proc = proc
                self._proc_starttime = proc_st
                if self._cancelled or self._closed:
                    cancelled_during_spawn = True
                    cancel_reason = self._cancel_reason or ("closed" if self._closed else "cancelled")
            if cancelled_during_spawn:
                if proc.pid is not None:
                    agent_driver._kill_process_tree(
                        proc.pid,
                        term_timeout=1.0,
                        proc=proc,
                        expected_root_starttime=proc_st,
                    )
                for _stream in (proc.stdin, proc.stdout, proc.stderr):
                    if _stream is not None:
                        try:
                            _stream.close()
                        except Exception:
                            pass
                with self._lock:
                    if self.proc is proc:
                        self._exit_code = proc.returncode
                        self._turn_active = False
                self._emit_terminal_error_once(cancel_reason, cancel_reason)
                self._emit_eof()
                return
            self.last_used = time.time()
        except Exception:
            with self._lock:
                self._turn_active = False
            raise

        # Deliver prompt exclusively via stdin (--query-file -) so zero shell/argv injection is possible
        try:
            if proc.stdin is not None:
                proc.stdin.write(str(prompt or ""))
                proc.stdin.flush()
                proc.stdin.close()
        except OSError:
            pass

        if self.timeout_sec is not None:
            timer = threading.Timer(self.timeout_sec, self.cancel, kwargs={"reason": "timeout"})
            timer.daemon = True
            self._timeout_timer = timer
            timer.start()

        self._stdout_thread = threading.Thread(target=self._drain_stdout, args=(proc,), daemon=True)
        self._stderr_thread = threading.Thread(target=self._drain_stderr, args=(proc,), daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

    def _drain_stdout(self, proc: subprocess.Popen) -> None:
        step_counter = [0]
        collected_text: List[str] = []
        stream = proc.stdout
        try:
            if stream is not None:
                for raw_line in stream:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        parsed = json.loads(line)
                    except Exception:
                        continue
                    norm = _normalize_hermes_stream_event(parsed, step_counter)
                    if not norm:
                        continue
                    if norm.get("event") == "init":
                        cid = norm.get("conversation_id")
                        if cid:
                            self.cid = cid
                    elif norm.get("event") == "step_update":
                        su = norm.get("step_update") or {}
                        if su.get("step_type") == "agent_response" and su.get("text_delta"):
                            collected_text.append(str(su["text_delta"]))
                    elif norm.get("event") == "result":
                        with self._lock:
                            self._result_emitted = True
                        r = norm.get("result") or {}
                        if r.get("conversation_id"):
                            self.cid = r["conversation_id"]
                    self.event_q.put(norm)
        except Exception:
            pass
        finally:
            if stream is not None:
                try:
                    if not getattr(stream, "closed", False):
                        stream.close()
                except Exception:
                    pass
            if self._timeout_timer is not None:
                try:
                    self._timeout_timer.cancel()
                except Exception:
                    pass
            try:
                proc.wait(timeout=2.0)
            except Exception:
                pass
            self._exit_code = proc.returncode
            with self._lock:
                if self.proc is proc:
                    self._turn_active = False
                already_res = self._result_emitted
                was_cancelled = self._cancelled
                c_reason = self._cancel_reason or "cancelled"
            if not already_res:
                if was_cancelled:
                    self._emit_terminal_error_once(c_reason, c_reason)
                elif proc.returncode == 0:
                    with self._lock:
                        self._result_emitted = True
                    self.event_q.put(
                        {
                            "event": "result",
                            "result": {
                                "status": "SUCCESS",
                                "conversation_id": self.cid or "",
                                "response": "".join(collected_text),
                                "error": "",
                                "finished_reason": "eof",
                            },
                        }
                    )
                else:
                    self._emit_terminal_error_once(
                        f"hermes exited with code {proc.returncode}: {self.get_stderr_text()[:400]}",
                        "exit_error",
                    )
            self._emit_eof()

    def _drain_stderr(self, proc: subprocess.Popen) -> None:
        stream = proc.stderr
        try:
            if stream is not None:
                for line in stream:
                    self.stderr_tail.append(line)
        except Exception:
            pass
        finally:
            if stream is not None:
                try:
                    if not getattr(stream, "closed", False):
                        stream.close()
                except Exception:
                    pass

    def next_event(self, timeout: float = 0.25) -> Optional[Dict[str, Any]]:
        if self._pushback:
            return self._pushback.popleft()
        try:
            return self.event_q.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_stderr_text(self) -> str:
        return "".join(self.stderr_tail)[-1200:]

    def cancel(self, reason: str = "cancelled", *, term_timeout: float = 1.5) -> None:
        with self._lock:
            self._cancelled = True
            if not self._cancel_reason:
                self._cancel_reason = str(reason or "cancelled")
            c_reason = self._cancel_reason
            proc = self.proc
            proc_st = self._proc_starttime
        if self._timeout_timer is not None:
            try:
                self._timeout_timer.cancel()
            except Exception:
                pass
        if proc is not None and proc.poll() is None and proc.pid is not None:
            agent_driver._kill_process_tree(
                proc.pid,
                term_timeout=term_timeout,
                proc=proc,
                expected_root_starttime=proc_st,
            )
            self._exit_code = proc.returncode
        with self._lock:
            if self.proc is proc and (proc is None or proc.poll() is not None):
                self._turn_active = False
        self._emit_terminal_error_once(c_reason, c_reason)
        self._emit_eof()

    def close(self, force: bool = False, term_timeout: Optional[float] = None) -> None:
        t_out = (1.0 if force else 2.0) if term_timeout is None else float(term_timeout)
        self.cancel(reason="closed", term_timeout=t_out)
        with self._lock:
            self._closed = True
        for th in (self._stdout_thread, self._stderr_thread):
            if th is not None and th.is_alive() and th is not threading.current_thread():
                try:
                    th.join(timeout=0.5)
                except Exception:
                    pass


class HermesLocalDriver(agent_driver.AgentDriver):
    """Pluggable driver for local Hermes CLI instances (`hermes -p <profile> chat`)."""

    name: str = "hermes_local"
    capabilities: agent_driver.DriverCapabilities = HERMES_LOCAL_CAPABILITIES

    def spawn_session(
        self,
        conv,
        mode,
        model,
        effort,
        *,
        project=None,
        workdir=None,
        scope_key=None,
        readonly=False,
        untrusted=False,
        is_worktree=False,
        trust_level=None,
        team_id: str = "",
        agent_origin=None,
        turn_taint_only=False,
        profile: str = "default",
        hermes_bin: Optional[str] = None,
        allowed_bins: Optional[Sequence[str]] = None,
        extra_args: Optional[Sequence[str]] = None,
        allow_yolo: bool = False,
        timeout_sec: Optional[float] = None,
    ) -> HermesLocalSession:
        return HermesLocalSession(
            conv,
            mode,
            model,
            effort,
            profile=profile,
            hermes_bin=hermes_bin,
            allowed_bins=allowed_bins,
            extra_args=extra_args,
            allow_yolo=allow_yolo,
            timeout_sec=timeout_sec,
            project=project,
            workdir=workdir,
            scope_key=scope_key,
            readonly=readonly,
            untrusted=untrusted,
            is_worktree=is_worktree,
            trust_level=trust_level,
            team_id=team_id,
            agent_origin=agent_origin,
            turn_taint_only=turn_taint_only,
        )


# ---------------------------------------------------------------- HermesRemoteDriver (C6, C7)
class HermesRemoteSession(agent_driver.AgentSession):
    """Hardened remote Hermes `api_server` session supporting `/v1/runs`, SSE, polling fallback, and `/stop`."""

    driver_name: str = "hermes_remote"
    capabilities: agent_driver.DriverCapabilities = HERMES_REMOTE_CAPABILITIES

    def __init__(
        self,
        conv: Optional[str],
        mode: Optional[str],
        model: Optional[str],
        effort: Optional[str],
        *,
        endpoint_url: str,
        profile: str = "",
        secret_ref: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
        connect_timeout_sec: float = DEFAULT_CONNECT_TIMEOUT_SEC,
        read_timeout_sec: float = DEFAULT_READ_TIMEOUT_SEC,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_sse_bytes: int = DEFAULT_MAX_SSE_BYTES,
        secret_resolver: Optional[Callable[[str], str]] = None,
        resolve_fn: Optional[Callable[[str, int], Sequence[str]]] = None,
        agent_record: Optional[Dict[str, Any]] = None,
        endpoint_override: Optional[str] = None,
        owner_auth: Any = None,
        auth_token: Optional[str] = None,
        project: Optional[str] = None,
        workdir: Optional[str] = None,
        scope_key: Optional[str] = None,
        readonly: bool = False,
        untrusted: bool = False,
        is_worktree: bool = False,
        trust_level: Optional[str] = None,
        agent_origin: Optional[str] = None,
        turn_taint_only: bool = False,
        host=None,
    ):
        if endpoint_override is not None and str(endpoint_override).strip():
            raise PermissionError(
                "ENDPOINT_OVERRIDE_DENIED: caller cannot override Owner-registered base endpoint_url"
            )
        bound_url = endpoint_url
        if isinstance(agent_record, dict):
            reg_url = str(agent_record.get("endpoint_url") or "").strip()
            if bound_url and reg_url and bound_url.rstrip("/") != reg_url.rstrip("/"):
                raise PermissionError(
                    "ENDPOINT_OVERRIDE_DENIED: endpoint_url does not match Owner-registered agent record"
                )
            bound_url = reg_url or bound_url
            if not profile and agent_record.get("profile"):
                profile = str(agent_record["profile"])
            if not secret_ref and agent_record.get("secret_ref"):
                secret_ref = str(agent_record["secret_ref"])

        self._resolve_fn = resolve_fn
        self._secret_resolver = secret_resolver
        self.endpoint_url = validate_outbound_url(bound_url, resolve_fn=resolve_fn).rstrip("/")
        self.profile = federation_registry.validate_profile_name(profile, allow_empty=True)
        self.secret_ref = federation_registry.validate_secret_ref(secret_ref)
        self.extra_headers = validate_header_map(extra_headers)
        self.connect_timeout_sec = max(0.1, float(connect_timeout_sec or DEFAULT_CONNECT_TIMEOUT_SEC))
        self.read_timeout_sec = max(0.2, float(read_timeout_sec or DEFAULT_READ_TIMEOUT_SEC))
        self.max_response_bytes = max(1024, int(max_response_bytes or DEFAULT_MAX_RESPONSE_BYTES))
        self.max_sse_bytes = max(1024, int(max_sse_bytes or DEFAULT_MAX_SSE_BYTES))

        self._init_common_state(
            conv,
            mode,
            model,
            effort,
            project=project,
            workdir=workdir,
            scope_key=scope_key,
            readonly=readonly,
            untrusted=untrusted,
            is_worktree=is_worktree,
            trust_level=trust_level,
            agent_origin=agent_origin or "local_bus",
            turn_taint_only=turn_taint_only,
            driver_name="hermes_remote",
            capabilities=HERMES_REMOTE_CAPABILITIES,
            host=host,
        )

        self.event_q: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._lock = threading.Lock()
        self._closed = False
        self._cancel_event = threading.Event()
        self._active_run_id: str = ""
        self._active_resp = None
        self._worker_thread: Optional[threading.Thread] = None
        self._eof_emitted = False
        self._result_emitted = False
        self._last_error = ""
        self.stop_called = False

    def _api_prefix(self) -> str:
        if self.profile:
            return f"{self.endpoint_url}/p/{self.profile}/v1/runs"
        return f"{self.endpoint_url}/v1/runs"

    def _build_request_headers(self, *, accept: str = "application/json") -> Tuple[Dict[str, str], List[str]]:
        headers = dict(self.extra_headers)
        headers["Accept"] = accept
        secrets_used: List[str] = []
        if self.secret_ref:
            tok = resolve_secret_ref(self.secret_ref, secret_resolver=self._secret_resolver)
            if tok:
                secrets_used.append(tok)
                headers["Authorization"] = f"Bearer {tok}"
        return validate_header_map(headers), secrets_used

    def _open_url(
        self,
        url: str,
        *,
        method: str = "GET",
        body_bytes: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ):
        validated_url, pinned_ips = resolve_and_validate_outbound_url(url, resolve_fn=self._resolve_fn)
        clean_headers = validate_header_map(headers or {})
        req = urllib.request.Request(validated_url, data=body_bytes, headers=clean_headers, method=method)
        opener = _build_hardened_opener(pinned_ips=pinned_ips)
        return opener.open(req, timeout=timeout or self.connect_timeout_sec)

    def is_alive(self) -> bool:
        return not self._closed

    def _emit_eof(self) -> None:
        with self._lock:
            if not self._eof_emitted:
                self._eof_emitted = True
                self.event_q.put({"event": "__eof__"})

    def _emit_result_once(self, result_dict: Dict[str, Any]) -> None:
        with self._lock:
            if not self._result_emitted:
                self._result_emitted = True
                self.event_q.put({"event": "result", "result": result_dict})

    def send_user_prompt(self, prompt: str, raw_slash: bool = False) -> None:
        if self._closed:
            raise RuntimeError("HermesRemoteSession is closed")
        with self._lock:
            self._cancel_event.clear()
            self._eof_emitted = False
            self._result_emitted = False
            self._active_run_id = ""
            self.stop_called = False
        self.last_used = time.time()
        th = threading.Thread(target=self._run_turn, args=(str(prompt or ""),), daemon=True)
        self._worker_thread = th
        th.start()

    def _send_remote_stop(self, run_id: str) -> bool:
        if not run_id:
            return False
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", run_id) or ".." in run_id:
            return False
        stop_url = f"{self._api_prefix()}/{run_id}/stop"
        try:
            headers, _secs = self._build_request_headers()
            headers["Content-Type"] = "application/json"
            resp = self._open_url(
                stop_url,
                method="POST",
                body_bytes=b"{}",
                headers=headers,
                timeout=min(5.0, self.connect_timeout_sec),
            )
            try:
                _read_bounded_bytes(resp, min(65536, self.max_response_bytes))
            finally:
                resp.close()
            self.stop_called = True
            return True
        except Exception:
            return False

    def _run_turn(self, prompt: str) -> None:
        secrets_used: List[str] = []
        step_counter = [0]
        collected_text: List[str] = []
        deadline = time.monotonic() + self.read_timeout_sec
        try:
            headers, secrets_used = self._build_request_headers(accept="application/json")
            headers["Content-Type"] = "application/json"
            payload: Dict[str, Any] = {
                "prompt": prompt,
                "mode": self.security_context.effective_mode,
                "readonly": self.security_context.readonly,
            }
            if self.model:
                payload["model"] = self.model
            if self.effort:
                payload["reasoning"] = self.effort
            if self.cid:
                payload["session_id"] = self.cid
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

            resp = self._open_url(
                self._api_prefix(),
                method="POST",
                body_bytes=body,
                headers=headers,
                timeout=self.connect_timeout_sec,
            )
            try:
                raw_data = _read_bounded_bytes(
                    resp,
                    self.max_response_bytes,
                    cancel_event=self._cancel_event,
                    deadline=deadline,
                )
            finally:
                resp.close()

            start_obj = json.loads(raw_data.decode("utf-8", errors="replace"))
            run_id = str(start_obj.get("run_id") or start_obj.get("id") or "").strip()
            if not run_id or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", run_id) or ".." in run_id:
                raise ValueError("Invalid run_id returned by remote Hermes server")
            with self._lock:
                self._active_run_id = run_id
            sess_id = str(start_obj.get("session_id") or start_obj.get("conversation_id") or run_id)
            self.cid = sess_id
            self.event_q.put({"event": "init", "conversation_id": sess_id})

            # Stream SSE events with fallback to polling on 404/405/501
            events_url = f"{self._api_prefix()}/{run_id}/events"
            sse_supported = True
            try:
                sse_headers, sse_secs = self._build_request_headers(accept="text/event-stream")
                secrets_used.extend(sse_secs)
                sse_resp = self._open_url(
                    events_url,
                    method="GET",
                    headers=sse_headers,
                    timeout=min(self.connect_timeout_sec, max(0.2, deadline - time.monotonic())),
                )
                with self._lock:
                    self._active_resp = sse_resp
                try:
                    self._consume_sse_stream(sse_resp, run_id, deadline, step_counter, collected_text)
                finally:
                    with self._lock:
                        self._active_resp = None
                    try:
                        sse_resp.close()
                    except Exception:
                        pass
            except urllib.error.HTTPError as http_err:
                code = http_err.code
                try:
                    http_err.close()
                except Exception:
                    pass
                if code in (404, 405, 501):
                    sse_supported = False
                else:
                    raise

            if not sse_supported:
                self._poll_run_until_done(run_id, deadline, collected_text, secrets_used)

            if self._cancel_event.is_set():
                self._emit_result_once(
                    {
                        "status": "ERROR",
                        "conversation_id": self.cid or "",
                        "response": "".join(collected_text),
                        "error": "cancelled",
                        "finished_reason": "cancelled",
                    }
                )
            else:
                self._emit_result_once(
                    {
                        "status": "SUCCESS",
                        "conversation_id": self.cid or "",
                        "response": "".join(collected_text),
                        "error": "",
                        "finished_reason": "completed",
                    }
                )
        except Exception as exc:
            safe_err = _sanitize_error_message(exc, secrets_used)
            self._last_error = safe_err
            self._emit_result_once(
                {
                    "status": "ERROR",
                    "conversation_id": self.cid or "",
                    "response": "".join(collected_text),
                    "error": safe_err,
                    "finished_reason": "error",
                }
            )
        finally:
            self._emit_eof()

    def _consume_sse_stream(
        self,
        resp,
        run_id: str,
        deadline: float,
        step_counter: List[int],
        collected_text: List[str],
    ) -> None:
        total_bytes = 0
        sock_obj = _extract_response_socket(resp)
        read_fn = getattr(resp, "read1", None) or resp.read
        buf = bytearray()

        def _process_line(raw_line: bytes) -> bool:
            """Return True if SSE stream reached terminal event or [DONE]."""
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line or line.startswith(":") or not line.startswith("data:"):
                return False
            data_str = line[5:].strip()
            if data_str == "[DONE]":
                return True
            try:
                parsed = json.loads(data_str)
            except Exception:
                return False
            norm = _normalize_hermes_stream_event(parsed, step_counter)
            if not norm:
                return False
            if norm.get("event") == "step_update":
                su = norm.get("step_update") or {}
                if su.get("step_type") == "agent_response" and su.get("text_delta"):
                    collected_text.append(str(su["text_delta"]))
                self.event_q.put(norm)
            elif norm.get("event") == "result":
                r = norm.get("result") or {}
                if not r.get("response") and collected_text:
                    r["response"] = "".join(collected_text)
                self._emit_result_once(r)
                return True
            else:
                self.event_q.put(norm)
            return False

        while True:
            if self._cancel_event.is_set():
                self._send_remote_stop(run_id)
                return
            rem = deadline - time.monotonic()
            if rem <= 0:
                self._send_remote_stop(run_id)
                raise TimeoutError(f"SSE_TIMEOUT: remote Hermes stream exceeded {self.read_timeout_sec}s")
            if sock_obj is not None:
                try:
                    sock_obj.settimeout(max(0.05, min(0.25, rem)))
                except Exception:
                    pass
            try:
                chunk = read_fn(4096)
            except (socket.timeout, TimeoutError):
                continue
            if not chunk:
                if buf:
                    _process_line(bytes(buf))
                break
            total_bytes += len(chunk)
            if total_bytes > self.max_sse_bytes:
                self._send_remote_stop(run_id)
                raise ValueError(
                    f"SSE_LIMIT_EXCEEDED: remote SSE stream exceeded max_sse_bytes ({self.max_sse_bytes})"
                )
            buf.extend(chunk)
            while True:
                nl_idx = buf.find(b"\n")
                if nl_idx < 0:
                    break
                line_bytes = bytes(buf[: nl_idx + 1])
                del buf[: nl_idx + 1]
                if _process_line(line_bytes):
                    return

    def _poll_run_until_done(
        self,
        run_id: str,
        deadline: float,
        collected_text: List[str],
        secrets_used: List[str],
    ) -> None:
        status_url = f"{self._api_prefix()}/{run_id}"
        while True:
            if self._cancel_event.is_set():
                self._send_remote_stop(run_id)
                return
            rem = deadline - time.monotonic()
            if rem <= 0:
                self._send_remote_stop(run_id)
                raise TimeoutError(f"POLL_TIMEOUT: remote Hermes run exceeded {self.read_timeout_sec}s")
            headers, poll_secs = self._build_request_headers(accept="application/json")
            secrets_used.extend(poll_secs)
            resp = self._open_url(
                status_url,
                method="GET",
                headers=headers,
                timeout=min(self.connect_timeout_sec, rem),
            )
            try:
                raw = _read_bounded_bytes(
                    resp,
                    self.max_response_bytes,
                    cancel_event=self._cancel_event,
                    deadline=deadline,
                )
            finally:
                resp.close()
            obj = json.loads(raw.decode("utf-8", errors="replace"))
            st = str(obj.get("status") or "").strip().lower()
            if st in ("done", "completed", "success"):
                txt = str(obj.get("response") or obj.get("result") or obj.get("output") or "")
                if txt:
                    collected_text.append(txt)
                    self.event_q.put(
                        {
                            "event": "step_update",
                            "step_update": {
                                "step_type": "agent_response",
                                "state": "DONE",
                                "step_index": 1,
                                "text_delta": txt,
                            },
                        }
                    )
                self._emit_result_once(
                    {
                        "status": "SUCCESS",
                        "conversation_id": self.cid or "",
                        "response": "".join(collected_text),
                        "error": "",
                        "usage": obj.get("usage") if isinstance(obj.get("usage"), dict) else {},
                        "finished_reason": st,
                    }
                )
                return
            if st in ("error", "failed", "cancelled", "canceled"):
                self._emit_result_once(
                    {
                        "status": "ERROR",
                        "conversation_id": self.cid or "",
                        "response": "".join(collected_text),
                        "error": str(obj.get("error") or st),
                        "finished_reason": st,
                    }
                )
                return
            time.sleep(min(0.1, max(0.01, rem)))

    def next_event(self, timeout: float = 0.25) -> Optional[Dict[str, Any]]:
        if self._pushback:
            return self._pushback.popleft()
        try:
            return self.event_q.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_stderr_text(self) -> str:
        return self._last_error

    def cancel(self, reason: str = "cancelled") -> bool:
        self._cancel_event.set()
        with self._lock:
            run_id = self._active_run_id
            resp = self._active_resp
        stopped = self._send_remote_stop(run_id) if run_id else False
        if resp is not None:
            try:
                resp.close()
            except Exception:
                pass
        self._emit_result_once(
            {
                "status": "ERROR",
                "conversation_id": self.cid or "",
                "response": "",
                "error": str(reason or "cancelled"),
                "finished_reason": "cancelled",
            }
        )
        self._emit_eof()
        return stopped

    def close(self, force: bool = False, term_timeout: Optional[float] = None) -> None:
        self.cancel(reason="closed")
        with self._lock:
            self._closed = True
        if self._worker_thread is not None and self._worker_thread.is_alive() and self._worker_thread is not threading.current_thread():
            try:
                self._worker_thread.join(timeout=1.0)
            except Exception:
                pass


class HermesRemoteDriver(agent_driver.AgentDriver):
    """Pluggable driver for remote Hermes `api_server` instances."""

    name: str = "hermes_remote"
    capabilities: agent_driver.DriverCapabilities = HERMES_REMOTE_CAPABILITIES

    def spawn_session(
        self,
        conv,
        mode,
        model,
        effort,
        *,
        endpoint_url: str = "",
        profile: str = "",
        secret_ref: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
        connect_timeout_sec: float = DEFAULT_CONNECT_TIMEOUT_SEC,
        read_timeout_sec: float = DEFAULT_READ_TIMEOUT_SEC,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_sse_bytes: int = DEFAULT_MAX_SSE_BYTES,
        secret_resolver: Optional[Callable[[str], str]] = None,
        resolve_fn: Optional[Callable[[str, int], Sequence[str]]] = None,
        agent_record: Optional[Dict[str, Any]] = None,
        endpoint_override: Optional[str] = None,
        owner_auth: Any = None,
        auth_token: Optional[str] = None,
        project=None,
        workdir=None,
        scope_key=None,
        readonly=False,
        untrusted=False,
        is_worktree=False,
        trust_level=None,
        agent_origin=None,
        turn_taint_only=False,
    ) -> HermesRemoteSession:
        return HermesRemoteSession(
            conv,
            mode,
            model,
            effort,
            endpoint_url=endpoint_url,
            profile=profile,
            secret_ref=secret_ref,
            extra_headers=extra_headers,
            connect_timeout_sec=connect_timeout_sec,
            read_timeout_sec=read_timeout_sec,
            max_response_bytes=max_response_bytes,
            max_sse_bytes=max_sse_bytes,
            secret_resolver=secret_resolver,
            resolve_fn=resolve_fn,
            agent_record=agent_record,
            endpoint_override=endpoint_override,
            owner_auth=owner_auth,
            auth_token=auth_token,
            project=project,
            workdir=workdir,
            scope_key=scope_key,
            readonly=readonly,
            untrusted=untrusted,
            is_worktree=is_worktree,
            trust_level=trust_level,
            agent_origin=agent_origin,
            turn_taint_only=turn_taint_only,
        )


# ---------------------------------------------------------------- HttpExternalAgentDriver (Push + Pull Worker)
class HttpExternalAgentSession(agent_driver.AgentSession):
    """Generic external agent session supporting hardened HTTP Push (OpenAI/A2A/Muse) & NAT Pull Worker queue."""

    driver_name: str = "http_external"
    capabilities: agent_driver.DriverCapabilities = HTTP_EXTERNAL_CAPABILITIES

    def __init__(
        self,
        conv: Optional[str],
        mode: Optional[str],
        model: Optional[str],
        effort: Optional[str],
        *,
        transport: str = "http_push",
        endpoint_url: str = "",
        api_style: str = "chat_completions",  # chat_completions | responses | a2a
        agent_id: str = "",
        bus_dir: Optional[str] = None,
        team_id: str = "",
        from_agent_id: str = "",
        secret_ref: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
        connect_timeout_sec: float = DEFAULT_CONNECT_TIMEOUT_SEC,
        read_timeout_sec: float = DEFAULT_READ_TIMEOUT_SEC,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        secret_resolver: Optional[Callable[[str], str]] = None,
        resolve_fn: Optional[Callable[[str, int], Sequence[str]]] = None,
        agent_record: Optional[Dict[str, Any]] = None,
        endpoint_override: Optional[str] = None,
        owner_auth: Any = None,
        auth_token: Optional[str] = None,
        project: Optional[str] = None,
        workdir: Optional[str] = None,
        scope_key: Optional[str] = None,
        readonly: bool = False,
        untrusted: bool = False,
        is_worktree: bool = False,
        trust_level: Optional[str] = None,
        agent_origin: Optional[str] = None,
        turn_taint_only: bool = False,
        host=None,
    ):
        if endpoint_override is not None and str(endpoint_override).strip():
            raise PermissionError(
                "ENDPOINT_OVERRIDE_DENIED: caller cannot override Owner-registered base endpoint_url"
            )
        if isinstance(agent_record, dict):
            reg_url = str(agent_record.get("endpoint_url") or "").strip()
            if endpoint_url and reg_url and endpoint_url.rstrip("/") != reg_url.rstrip("/"):
                raise PermissionError(
                    "ENDPOINT_OVERRIDE_DENIED: endpoint_url does not match Owner-registered agent record"
                )
            endpoint_url = reg_url or endpoint_url
            if not agent_id and agent_record.get("agent_id"):
                agent_id = str(agent_record["agent_id"])
            if not secret_ref and agent_record.get("secret_ref"):
                secret_ref = str(agent_record["secret_ref"])
            if agent_record.get("transport") == "pull_worker":
                transport = "pull_worker"

        self.transport = str(transport or "http_push").strip().lower()
        if self.transport not in ("http_push", "pull_worker"):
            raise ValueError(f"Unsupported HttpExternalAgentSession transport: {self.transport!r}")

        self._resolve_fn = resolve_fn
        self._secret_resolver = secret_resolver
        self.api_style = str(api_style or "chat_completions").strip().lower()
        self.secret_ref = federation_registry.validate_secret_ref(secret_ref)
        self.extra_headers = validate_header_map(extra_headers)
        self.connect_timeout_sec = max(0.1, float(connect_timeout_sec or DEFAULT_CONNECT_TIMEOUT_SEC))
        self.read_timeout_sec = max(0.2, float(read_timeout_sec or DEFAULT_READ_TIMEOUT_SEC))
        self.max_response_bytes = max(1024, int(max_response_bytes or DEFAULT_MAX_RESPONSE_BYTES))
        self.bus_dir = bus_dir
        self.team_id = federation_registry.validate_team_id(team_id, allow_empty=True)
        self.from_agent_id = federation_registry.validate_agent_id(from_agent_id) if from_agent_id else ""
        self._owner_auth = owner_auth
        self._auth_token = auth_token

        if self.transport == "http_push":
            self.endpoint_url = validate_outbound_url(endpoint_url, resolve_fn=resolve_fn)
            self.agent_id = federation_registry.validate_agent_id(agent_id) if agent_id else ""
        else:
            self.endpoint_url = ""
            self.agent_id = federation_registry.validate_agent_id(agent_id)

        self._init_common_state(
            conv,
            mode,
            model,
            effort,
            project=project,
            workdir=workdir,
            scope_key=scope_key,
            readonly=readonly,
            untrusted=untrusted,
            is_worktree=is_worktree,
            trust_level=trust_level,
            agent_origin=agent_origin or "local_bus",
            turn_taint_only=turn_taint_only,
            driver_name="http_external",
            capabilities=HTTP_EXTERNAL_CAPABILITIES,
            host=host,
        )

        self.event_q: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._lock = threading.Lock()
        self._closed = False
        self._cancel_event = threading.Event()
        self._eof_emitted = False
        self._result_emitted = False
        self._last_error = ""
        self._active_pull_job_id = ""
        self._worker_thread: Optional[threading.Thread] = None

    @property
    def active_pull_job_id(self) -> str:
        with self._lock:
            return self._active_pull_job_id

    def is_alive(self) -> bool:
        return not self._closed

    def _emit_eof(self) -> None:
        with self._lock:
            if not self._eof_emitted:
                self._eof_emitted = True
                self.event_q.put({"event": "__eof__"})

    def _emit_result_once(self, result_dict: Dict[str, Any]) -> None:
        with self._lock:
            if not self._result_emitted:
                self._result_emitted = True
                self.event_q.put({"event": "result", "result": result_dict})

    def send_user_prompt(self, prompt: str, raw_slash: bool = False) -> None:
        if self._closed:
            raise RuntimeError("HttpExternalAgentSession is closed")
        with self._lock:
            self._cancel_event.clear()
            self._eof_emitted = False
            self._result_emitted = False
            self._active_pull_job_id = ""
        self.last_used = time.time()
        target = self._run_pull_turn if self.transport == "pull_worker" else self._run_http_push_turn
        th = threading.Thread(target=target, args=(str(prompt or ""),), daemon=True)
        self._worker_thread = th
        th.start()

    def _run_http_push_turn(self, prompt: str) -> None:
        secrets_used: List[str] = []
        try:
            validated_url, pinned_ips = resolve_and_validate_outbound_url(
                self.endpoint_url,
                resolve_fn=self._resolve_fn,
            )
            headers = dict(self.extra_headers)
            headers["Content-Type"] = "application/json"
            headers["Accept"] = "application/json"
            if self.secret_ref:
                tok = resolve_secret_ref(self.secret_ref, secret_resolver=self._secret_resolver)
                if tok:
                    secrets_used.append(tok)
                    headers["Authorization"] = f"Bearer {tok}"
            clean_headers = validate_header_map(headers)

            if self.api_style == "responses":
                payload: Dict[str, Any] = {
                    "model": self.model or "default",
                    "input": prompt,
                }
            elif self.api_style == "a2a":
                payload = {
                    "prompt": prompt,
                    "model": self.model or "",
                    "mode": self.security_context.effective_mode,
                    "readonly": self.security_context.readonly,
                }
            else:
                payload = {
                    "model": self.model or "default",
                    "messages": [{"role": "user", "content": prompt}],
                }
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(validated_url, data=body, headers=clean_headers, method="POST")
            opener = _build_hardened_opener(pinned_ips=pinned_ips)
            resp = opener.open(req, timeout=self.connect_timeout_sec)
            deadline = time.monotonic() + self.read_timeout_sec
            try:
                raw = _read_bounded_bytes(
                    resp,
                    self.max_response_bytes,
                    cancel_event=self._cancel_event,
                    deadline=deadline,
                )
            finally:
                resp.close()

            obj = json.loads(raw.decode("utf-8", errors="replace"))
            text = _extract_http_external_text(obj)
            conv_id = str(obj.get("id") or obj.get("conversation_id") or self.cid or "")
            if conv_id:
                self.cid = conv_id
                self.event_q.put({"event": "init", "conversation_id": conv_id})
            if text:
                self.event_q.put(
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "agent_response",
                            "state": "DONE",
                            "step_index": 1,
                            "text_delta": text,
                        },
                    }
                )
            self._emit_result_once(
                {
                    "status": "SUCCESS",
                    "conversation_id": self.cid or "",
                    "response": text,
                    "error": "",
                    "usage": obj.get("usage") if isinstance(obj.get("usage"), dict) else {},
                    "finished_reason": "completed",
                }
            )
        except Exception as exc:
            safe_err = _sanitize_error_message(exc, secrets_used)
            self._last_error = safe_err
            self._emit_result_once(
                {
                    "status": "ERROR",
                    "conversation_id": self.cid or "",
                    "response": "",
                    "error": safe_err,
                    "finished_reason": "error",
                }
            )
        finally:
            self._emit_eof()

    def _run_pull_turn(self, prompt: str) -> None:
        q = federation_registry.PullWorkerQueue(self.bus_dir)
        deadline = time.monotonic() + self.read_timeout_sec
        try:
            job = q.enqueue(
                self.agent_id,
                prompt,
                team_id=self.team_id,
                from_agent_id=self.from_agent_id,
                metadata={
                    "mode": self.security_context.effective_mode,
                    "readonly": self.security_context.readonly,
                },
                owner_auth=self._owner_auth,
                auth_token=self._auth_token,
            )
            jid = job["job_id"]
            with self._lock:
                self._active_pull_job_id = jid
            self.cid = jid
            self.event_q.put({"event": "init", "conversation_id": jid})

            while True:
                if self._cancel_event.is_set():
                    q.cancel(
                        jid,
                        reason="cancelled",
                        requester_agent_id=self.from_agent_id,
                        team_id=self.team_id,
                        owner_auth=self._owner_auth,
                        auth_token=self._auth_token,
                    )
                    self._emit_result_once(
                        {
                            "status": "ERROR",
                            "conversation_id": jid,
                            "response": "",
                            "error": "cancelled",
                            "finished_reason": "cancelled",
                        }
                    )
                    return
                cur = q.get(jid)
                if cur is None:
                    raise RuntimeError(f"Pull job {jid!r} disappeared")
                st = cur.get("status")
                if st == "done":
                    txt = str(cur.get("result_text") or "")
                    if txt:
                        self.event_q.put(
                            {
                                "event": "step_update",
                                "step_update": {
                                    "step_type": "agent_response",
                                    "state": "DONE",
                                    "step_index": 1,
                                    "text_delta": txt,
                                },
                            }
                        )
                    self._emit_result_once(
                        {
                            "status": "SUCCESS",
                            "conversation_id": jid,
                            "response": txt,
                            "error": "",
                            "finished_reason": "completed",
                        }
                    )
                    return
                if st in ("error", "cancelled"):
                    self._emit_result_once(
                        {
                            "status": "ERROR",
                            "conversation_id": jid,
                            "response": str(cur.get("result_text") or ""),
                            "error": str(cur.get("error") or st),
                            "finished_reason": str(st),
                        }
                    )
                    return
                rem = deadline - time.monotonic()
                if rem <= 0:
                    q.cancel(
                        jid,
                        reason="timeout",
                        requester_agent_id=self.from_agent_id,
                        team_id=self.team_id,
                        owner_auth=self._owner_auth,
                        auth_token=self._auth_token,
                    )
                    raise TimeoutError(f"PULL_WORKER_TIMEOUT: pull job {jid!r} timed out after {self.read_timeout_sec}s")
                time.sleep(min(0.05, rem))
        except Exception as exc:
            safe_err = _sanitize_error_message(exc)
            self._last_error = safe_err
            self._emit_result_once(
                {
                    "status": "ERROR",
                    "conversation_id": self.cid or "",
                    "response": "",
                    "error": safe_err,
                    "finished_reason": "error",
                }
            )
        finally:
            self._emit_eof()

    def next_event(self, timeout: float = 0.25) -> Optional[Dict[str, Any]]:
        if self._pushback:
            return self._pushback.popleft()
        try:
            return self.event_q.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_stderr_text(self) -> str:
        return self._last_error

    def cancel(self, reason: str = "cancelled") -> None:
        self._cancel_event.set()
        with self._lock:
            jid = self._active_pull_job_id
        if self.transport == "pull_worker" and jid:
            try:
                federation_registry.PullWorkerQueue(self.bus_dir).cancel(
                    jid,
                    reason=reason,
                    requester_agent_id=self.from_agent_id,
                    team_id=self.team_id,
                    owner_auth=self._owner_auth,
                    auth_token=self._auth_token,
                )
            except Exception:
                pass
        self._emit_result_once(
            {
                "status": "ERROR",
                "conversation_id": self.cid or "",
                "response": "",
                "error": str(reason or "cancelled"),
                "finished_reason": "cancelled",
            }
        )
        self._emit_eof()

    def close(self, force: bool = False, term_timeout: Optional[float] = None) -> None:
        self.cancel(reason="closed")
        with self._lock:
            self._closed = True
        if self._worker_thread is not None and self._worker_thread.is_alive() and self._worker_thread is not threading.current_thread():
            try:
                self._worker_thread.join(timeout=1.0)
            except Exception:
                pass


def _extract_http_external_text(obj: Any) -> str:
    if not isinstance(obj, dict):
        return ""
    if isinstance(obj.get("output_text"), str) and obj["output_text"]:
        return obj["output_text"]
    choices = obj.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            msg = first.get("message")
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                return msg["content"]
            if isinstance(first.get("text"), str):
                return first["text"]
    output = obj.get("output")
    if isinstance(output, list):
        parts: List[str] = []
        for item in output:
            if not isinstance(item, dict):
                continue
            for c in item.get("content") or []:
                if isinstance(c, dict) and isinstance(c.get("text"), str):
                    parts.append(c["text"])
        if parts:
            return "".join(parts)
    for k in ("response", "result", "text", "content"):
        v = obj.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


class HttpExternalAgentDriver(agent_driver.AgentDriver):
    """Pluggable driver for Muse / OpenAI-compatible HTTP / A2A / NAT Pull Worker agents."""

    name: str = "http_external"
    capabilities: agent_driver.DriverCapabilities = HTTP_EXTERNAL_CAPABILITIES

    def __init__(self, *, name: str = "http_external", default_transport: str = "http_push"):
        self.name = name
        self._default_transport = default_transport

    def spawn_session(
        self,
        conv,
        mode,
        model,
        effort,
        *,
        transport: Optional[str] = None,
        endpoint_url: str = "",
        api_style: str = "chat_completions",
        agent_id: str = "",
        bus_dir: Optional[str] = None,
        team_id: str = "",
        from_agent_id: str = "",
        secret_ref: str = "",
        extra_headers: Optional[Dict[str, str]] = None,
        connect_timeout_sec: float = DEFAULT_CONNECT_TIMEOUT_SEC,
        read_timeout_sec: float = DEFAULT_READ_TIMEOUT_SEC,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        secret_resolver: Optional[Callable[[str], str]] = None,
        resolve_fn: Optional[Callable[[str, int], Sequence[str]]] = None,
        agent_record: Optional[Dict[str, Any]] = None,
        endpoint_override: Optional[str] = None,
        owner_auth: Any = None,
        auth_token: Optional[str] = None,
        project=None,
        workdir=None,
        scope_key=None,
        readonly=False,
        untrusted=False,
        is_worktree=False,
        trust_level=None,
        agent_origin=None,
        turn_taint_only=False,
    ) -> HttpExternalAgentSession:
        eff_transport = transport or self._default_transport
        return HttpExternalAgentSession(
            conv,
            mode,
            model,
            effort,
            transport=eff_transport,
            endpoint_url=endpoint_url,
            api_style=api_style,
            agent_id=agent_id,
            bus_dir=bus_dir,
            team_id=team_id,
            from_agent_id=from_agent_id,
            secret_ref=secret_ref,
            extra_headers=extra_headers,
            connect_timeout_sec=connect_timeout_sec,
            read_timeout_sec=read_timeout_sec,
            max_response_bytes=max_response_bytes,
            secret_resolver=secret_resolver,
            resolve_fn=resolve_fn,
            agent_record=agent_record,
            endpoint_override=endpoint_override,
            owner_auth=owner_auth,
            auth_token=auth_token,
            project=project,
            workdir=workdir,
            scope_key=scope_key,
            readonly=readonly,
            untrusted=untrusted,
            is_worktree=is_worktree,
            trust_level=trust_level,
            agent_origin=agent_origin,
            turn_taint_only=turn_taint_only,
        )


def register_external_drivers(registry: Optional[agent_driver.DriverRegistry] = None) -> List[str]:
    """Register `hermes_local`, `hermes_remote`, and `http_external` (+ aliases) on `registry`."""
    reg = registry if registry is not None else agent_driver.default_registry
    entries: Tuple[Tuple[str, agent_driver.AgentDriver], ...] = (
        ("hermes_local", HermesLocalDriver()),
        ("hermes_remote", HermesRemoteDriver()),
        ("http_external", HttpExternalAgentDriver(name="http_external", default_transport="http_push")),
        ("muse_remote", HttpExternalAgentDriver(name="muse_remote", default_transport="http_push")),
        ("http_a2a", HttpExternalAgentDriver(name="http_a2a", default_transport="http_push")),
        ("pull_worker", HttpExternalAgentDriver(name="pull_worker", default_transport="pull_worker")),
    )
    registered: List[str] = []
    for name, drv in entries:
        reg.register_driver(name, drv, overwrite=True)
        registered.append(name)
    return registered
