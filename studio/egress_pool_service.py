#!/usr/bin/env python3
"""AGY Studio — Egress Proxy Pool Service (OpenBao KV v2 + Manual SOCKS5 + Safe Health Probe + Pluggable Draw).

Security & operational guarantees:
- Zero plaintext credentials in responses, error messages, logs, or audit trails.
- All OpenBao KV v2 operations (LIST / GET / merge-POST / tombstone) execute over async HTTP
  reusing `OpenBaoSecretBackend` (zero `subprocess` calls to `bao set`).
- Mount & path prefix are strictly environment-driven (`AGY_EGRESS_VAULT_MOUNT`,
  `AGY_EGRESS_VAULT_PREFIX`, optional `AGY_EGRESS_VAULT_REF_PREFIX`) with generic defaults
  and zero host-private path literals.
- Built-in health-check probe strictly targets fixed server-side allowlisted public probe(s)
  (rejects user-supplied probe URLs to prevent SSRF; blocks link-local/metadata and sensitive
  loopback ports).
- Concurrency limits (`draw` <= 1, `verify` <= 3 + per-node mutex) with async job status tracking
  and process-group (`start_new_session=True`, `SIGTERM` -> `SIGKILL` `os.killpg`) cleanup wired
  into `app.on_cleanup`.
- All write endpoints enforce the full four-layer Studio write gate and append to an anti-symlink
  `0600` JSONL audit log.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
import datetime
import fcntl
import inspect
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import struct
import time
from typing import Any, Awaitable, Callable
from urllib.parse import unquote, urlsplit

import aiohttp
from aiohttp import web

from .auth import StudioAuthManager, studio_auth_error
from .chat_service import (
    MAX_PROMPT_BODY_BYTES,
    _extract_media_type,
    _read_bounded_json_body,
)
from .control_plane import _find_forbidden_key_recursive
from .data_sources import _SENSITIVE_HOST_PATH_RE, _sanitize_slug, redact_secrets_only
from .secrets_config_service import (
    DEFAULT_KV_MOUNT,
    OpenBaoSecretBackend,
    SecretStoreError,
    SecretsConfigService,
    _validate_kv_mount,
    _validate_kv_path,
)

log = logging.getLogger("agy-studio.egress_pool")

DEFAULT_EGRESS_VAULT_PREFIX = "egress"
DEFAULT_PROBE_URL = "https://cloudflare.com/cdn-cgi/trace"

_ALLOWED_SCHEMES = frozenset({"socks5", "socks5h", "http", "https"})
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_USERINFO_IN_URL_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s@]+@)")

_SENSITIVE_LOOPBACK_PORTS = frozenset(
    {22, 23, 25, 53, 80, 443, 3306, 5432, 6379, 8200, 8201, 18795, 18796, 37701}
)
_FORBIDDEN_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "instance-data",
    }
)

_FORBIDDEN_WRITE_KEYS = frozenset(
    {
        "role",
        "user_id",
        "cmd",
        "command",
        "shell",
        "script",
        "env",
        "probe_url",
        "target_url",
        "cli",
        "cli_path",
    }
)
_ALLOWED_CREATE_KEYS = frozenset(
    {"name", "slug", "proxy_url", "url", "scheme", "host", "port", "username", "password", "note"}
)
_ALLOWED_VERIFY_KEYS = frozenset({"force"})
_ALLOWED_DRAW_KEYS = frozenset({"country", "want", "max_tries"})
_ALLOWED_PRUNE_KEYS = frozenset({"dry_run"})

_MAX_JOBS_HISTORY = 128
_VAULT_IO_TIMEOUT_SEC = 8.0
_MAX_VAULT_RESP_BYTES = 256 * 1024
_DEFAULT_PROBE_TIMEOUT_SEC = 12.0
_DEFAULT_CLI_DRAW_TIMEOUT_SEC = 120.0
_DEFAULT_CLI_VERIFY_TIMEOUT_SEC = 35.0
_DEFAULT_CLI_PRUNE_TIMEOUT_SEC = 60.0
_MAX_VERIFY_CONCURRENCY = 3


def _utc_iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scrub_egress_text(raw: Any, max_len: int = 240) -> str:
    """Scrub URL userinfo, credentials, control chars, and host paths before returning/auditing."""
    text = str(raw or "")
    if not text:
        return ""
    text = _USERINFO_IN_URL_RE.sub(r"\1***@", text)
    text = redact_secrets_only(text)
    text = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", text)
    text = _CTRL_RE.sub(" ", text)
    return " ".join(text.split())[:max_len]


def _actor_label(sess: dict[str, Any] | None) -> str:
    if not sess:
        return "anonymous"
    uname = str(sess.get("username") or "").strip()
    if uname:
        return _sanitize_slug(uname, max_len=64) or "user"
    bot = _sanitize_slug(sess.get("bot") or "studio", max_len=32) or "studio"
    uid = int(sess.get("user_id") or 0)
    return f"{bot}:#{uid}"


def _ensure_secure_dir(path: Path) -> None:
    if path.is_symlink():
        raise PermissionError("Refusing symlink directory")
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


class _EgressAuditLogger:
    """Anti-symlink `0600` append-only JSONL audit logger for egress pool mutations."""

    def __init__(self, audit_path: Path) -> None:
        self.audit_path = Path(audit_path)

    def record(
        self,
        *,
        action: str,
        ok: bool,
        sess: dict[str, Any] | None = None,
        node: str = "",
        job_id: str = "",
        error: str = "",
    ) -> None:
        rec = {
            "ts": _utc_iso_now(),
            "actor": _actor_label(sess),
            "role": str((sess or {}).get("role") or "anonymous"),
            "action": str(action)[:64],
            "node": _sanitize_slug(node, max_len=64) if node else "",
            "job_id": _sanitize_slug(job_id, max_len=64) if job_id else "",
            "ok": bool(ok),
            "error": _scrub_egress_text(error) if error else "",
        }
        line = (json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            _ensure_secure_dir(self.audit_path.parent)
            if self.audit_path.is_symlink():
                raise PermissionError("Refusing to append audit log to symlink")
            flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(self.audit_path), flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    os.write(fd, line)
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        except Exception as exc:
            log.warning("Egress pool audit write failed: %s", type(exc).__name__)


def validate_egress_slug(raw: Any, *, require_custom_prefix: bool = False) -> str:
    """Validate egress node name/slug strictly (blocks traversal, flag injection, shell metachars)."""
    if not isinstance(raw, str):
        raise ValueError("节点名称必须为字符串")
    s = raw.strip().lower()
    if not s or ".." in s or "/" in s or "\\" in s or s.startswith("-") or _CTRL_RE.search(s):
        raise ValueError("节点名称格式非法，禁止路径穿越、连字符前缀或控制字符")
    if require_custom_prefix and not s.startswith("custom-"):
        s = f"custom-{s}"
    if not _SLUG_RE.fullmatch(s):
        raise ValueError("节点名称仅允许小写字母、数字、下划线与连字符（1-48 字符）")
    return s


def _validate_port(raw: Any) -> int:
    if isinstance(raw, bool) or raw is None:
        raise ValueError("端口必须为 1..65535 整数")
    if isinstance(raw, str):
        s = raw.strip()
        if not s or not s.isascii() or not s.isdigit():
            raise ValueError("端口必须为 1..65535 整数")
        val = int(s)
    elif isinstance(raw, int):
        val = raw
    else:
        raise ValueError("端口必须为 1..65535 整数")
    if not (1 <= val <= 65535):
        raise ValueError("端口超出有效范围（1..65535）")
    return val


_HEX_LABEL_RE = re.compile(r"^0[xX][0-9A-Fa-f]+$")


def _is_forbidden_agy_binary(path: Path) -> bool:
    """Fail-closed check blocking direct or symlinked `agy` CLI executables."""
    if path.name.strip().lower() == "agy":
        return True
    try:
        resolved = path.resolve(strict=False)
        if resolved.name.strip().lower() == "agy":
            return True
    except OSError:
        return True
    return False


def is_forbidden_proxy_target(host: str, port: int) -> tuple[bool, str]:
    """Reject cloud metadata, link-local, unspecified/multicast, and sensitive local loopback ports."""
    clean_host = host.strip().lower().rstrip(".").strip("[]")
    if not clean_host:
        return True, "代理主机名不能为空"
    if "%" in clean_host:
        return True, "代理主机名禁止包含区域标识符"
    if clean_host in _FORBIDDEN_METADATA_HOSTS or clean_host.endswith(".internal"):
        return True, "禁止指向内网元数据或受限主机"
    if clean_host == "localhost":
        if port in _SENSITIVE_LOOPBACK_PORTS:
            return True, "禁止指向本机敏感服务端口"
        return False, ""
    try:
        ip_obj = ipaddress.ip_address(clean_host)
    except ValueError:
        return False, ""
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [ip_obj]
    if isinstance(ip_obj, ipaddress.IPv6Address):
        if ip_obj.ipv4_mapped is not None:
            candidates.append(ip_obj.ipv4_mapped)
        if ip_obj.sixtofour is not None:
            candidates.append(ip_obj.sixtofour)
    for cand in candidates:
        if cand.is_link_local or cand.is_unspecified or cand.is_multicast:
            return True, "禁止指向链路本地（含云元数据）、未指定或多播地址"
        if cand.is_loopback and port in _SENSITIVE_LOOPBACK_PORTS:
            return True, "禁止指向本机敏感回环服务端口"
        # Block cloud IPv6 IMDS prefix (ULA ec2 metadata block) without embedding IPv6 literals
        if isinstance(cand, ipaddress.IPv6Address) and cand.packed[:4] == bytes.fromhex("fd000ec2"):
            return True, "禁止指向云元数据地址"
    return False, ""


def _validate_host(raw: Any) -> str:
    if not isinstance(raw, str):
        raise ValueError("代理主机名必须为字符串")
    s = raw.strip().strip("[]")
    if not s or len(s) > 253 or any(ch.isspace() for ch in s) or _CTRL_RE.search(s):
        raise ValueError("代理主机名包含非法字符或超长")
    if "/" in s or "@" in s or "?" in s or "#" in s or "%" in s:
        raise ValueError("代理主机名格式非法")
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        pass
    # Reject non-standard numeric/obfuscated IPv4 literals (decimal int, octal, hex, shorthand)
    s_no_dot = s.rstrip(".")
    if not s_no_dot:
        raise ValueError("代理主机名格式非法")
    try:
        socket.inet_aton(s_no_dot)
    except OSError:
        pass
    else:
        raise ValueError("禁止使用非标准数值、缩写或进制混淆 IP 地址")
    labels = s_no_dot.split(".")
    for lbl in labels:
        if not lbl or lbl.isdigit() or _HEX_LABEL_RE.fullmatch(lbl):
            raise ValueError("代理主机名禁止包含纯数字、八进制或十六进制混淆标签")
    if not _HOSTNAME_RE.fullmatch(s):
        raise ValueError("代理主机名格式非法")
    return s.lower()


def _format_server_url(scheme: str, host: str, port: int) -> str:
    host_fmt = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{host_fmt}:{port}"


def parse_manual_egress_input(body: dict[str, Any]) -> dict[str, Any]:
    """Parse structured fields or single-line `proxy_url` into a validated Vault node payload."""
    raw_url = body.get("proxy_url") if body.get("proxy_url") is not None else body.get("url")
    scheme = ""
    host = ""
    port = 0
    username = ""
    password = ""

    if raw_url is not None and str(raw_url).strip():
        if not isinstance(raw_url, str):
            raise ValueError("proxy_url 必须为字符串")
        url_str = raw_url.strip()
        if len(url_str) > 1024 or _CTRL_RE.search(url_str) or any(ch.isspace() for ch in url_str):
            raise ValueError("proxy_url 包含非法空白或控制字符")
        if "://" not in url_str:
            raise ValueError("proxy_url 必须包含协议头（如 socks5h://host:1080）")
        sp = urlsplit(url_str)
        scheme = (sp.scheme or "").lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise ValueError(f"不支持的代理协议 {scheme!r}，仅允许: {', '.join(sorted(_ALLOWED_SCHEMES))}")
        if sp.path not in ("", "/") or sp.query or sp.fragment:
            raise ValueError("代理 URL 不允许包含路径、查询参数或锚点")
        host = _validate_host(sp.hostname or "")
        try:
            parsed_port = sp.port
        except ValueError as exc:
            raise ValueError("代理端口无效") from exc
        if parsed_port is None:
            raise ValueError("代理 URL 必须显式指定端口")
        port = _validate_port(parsed_port)
        if sp.username is not None:
            username = unquote(sp.username)
        if sp.password is not None:
            password = unquote(sp.password)
    else:
        raw_scheme = body.get("scheme")
        scheme = str(raw_scheme if raw_scheme is not None else "socks5h").strip().lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise ValueError(f"不支持的代理协议 {scheme!r}，仅允许: {', '.join(sorted(_ALLOWED_SCHEMES))}")
        host = _validate_host(body.get("host"))
        port = _validate_port(body.get("port"))
        if body.get("username") is not None:
            if not isinstance(body["username"], str):
                raise ValueError("username 必须为字符串")
            username = body["username"]
        if body.get("password") is not None:
            if not isinstance(body["password"], str):
                raise ValueError("password 必须为字符串")
            password = body["password"]

    if len(username) > 256 or len(password) > 512 or _CTRL_RE.search(username) or _CTRL_RE.search(password):
        raise ValueError("代理账密长度超限或包含控制字符")

    forbidden, forb_reason = is_forbidden_proxy_target(host, port)
    if forbidden:
        raise ValueError(forb_reason)

    raw_name = body.get("name") if body.get("name") is not None else body.get("slug")
    if raw_name is not None and str(raw_name).strip():
        slug = validate_egress_slug(str(raw_name), require_custom_prefix=True)
    else:
        host_token = re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-")[:20] or "node"
        slug = validate_egress_slug(f"custom-{host_token}-{port}-{secrets.token_hex(2)}", require_custom_prefix=True)

    raw_note = body.get("note")
    note = ""
    if raw_note is not None:
        if not isinstance(raw_note, str):
            raise ValueError("note 必须为字符串")
        note = _scrub_egress_text(raw_note, max_len=160)

    server = _format_server_url(scheme, host, port)
    now_iso = _utc_iso_now()
    vault_data: dict[str, Any] = {
        "server": server,
        "host": host,
        "port": str(port),
        "username": username,
        "password": password,
        "scheme": scheme,
        "provider": "custom",
        "tag": slug,
        "exit_ip": "",
        "country": "",
        "region": "",
        "city": "",
        "isp": "",
        "asn": "",
        "ptr": "",
        "mbps": "",
        "latency_ms": "",
        "status": "unverified",
        "drawn_at": now_iso,
        "verified_at": "",
        "note": note,
    }
    return {"slug": slug, "vault_data": vault_data}


def sanitize_egress_node(slug: str, raw: dict[str, Any], *, ref: str) -> dict[str, Any] | None:
    """Return strictly credential-free public metadata for a Vault egress node (None if tombstoned)."""
    if not isinstance(raw, dict):
        return None
    status = str(raw.get("status") or "unverified").strip()
    if status.lower() == "removed":
        return None

    scheme = str(raw.get("scheme") or "").strip().lower()
    host = str(raw.get("host") or "").strip()
    port_str = str(raw.get("port") or "").strip()
    raw_server = str(raw.get("server") or "").strip()

    has_url_auth = False
    if raw_server and "://" in raw_server:
        try:
            sp = urlsplit(raw_server)
            if not scheme and sp.scheme:
                scheme = sp.scheme.lower()
            if not host and sp.hostname:
                host = sp.hostname
            if not port_str and sp.port:
                port_str = str(sp.port)
            if sp.username or sp.password:
                has_url_auth = True
        except Exception:
            pass

    if scheme not in _ALLOWED_SCHEMES:
        scheme = "socks5h"

    clean_server = ""
    if host and port_str.isdigit():
        clean_server = _format_server_url(scheme, host, int(port_str))
    elif host:
        host_fmt = f"[{host}]" if ":" in host and not host.startswith("[") else host
        clean_server = f"{scheme}://{host_fmt}"

    has_auth = bool(
        has_url_auth
        or (raw.get("username") is not None and str(raw.get("username")) != "")
        or (raw.get("password") is not None and str(raw.get("password")) != "")
    )
    if clean_server and has_auth and "://" in clean_server:
        sch, rest = clean_server.split("://", 1)
        display = f"{sch}://***@{rest}"
    else:
        display = clean_server or f"vault:{ref}"

    provider = _sanitize_slug(raw.get("provider") or ("custom" if slug.startswith("custom-") else "pool"), max_len=32) or "pool"

    def _safe_meta(val: Any, max_len: int = 96) -> str:
        if val is None:
            return ""
        return _scrub_egress_text(val, max_len=max_len)

    return {
        "name": slug,
        "slug": slug,
        "ref": ref,
        "scheme": scheme,
        "host": host,
        "port": int(port_str) if port_str.isdigit() else None,
        "server": clean_server,
        "display": display,
        "has_auth": has_auth,
        "provider": provider,
        "tag": _safe_meta(raw.get("tag") or slug, max_len=64),
        "exit_ip": _safe_meta(raw.get("exit_ip"), max_len=64),
        "country": _safe_meta(raw.get("country"), max_len=16),
        "region": _safe_meta(raw.get("region"), max_len=64),
        "city": _safe_meta(raw.get("city"), max_len=64),
        "isp": _safe_meta(raw.get("isp"), max_len=96),
        "asn": _safe_meta(raw.get("asn"), max_len=48),
        "ptr": _safe_meta(raw.get("ptr"), max_len=128),
        "mbps": _safe_meta(raw.get("mbps"), max_len=32),
        "latency_ms": _safe_meta(raw.get("latency_ms"), max_len=32),
        "status": _safe_meta(status, max_len=64) or "unverified",
        "drawn_at": _safe_meta(raw.get("drawn_at"), max_len=48),
        "verified_at": _safe_meta(raw.get("verified_at"), max_len=48),
        "note": _safe_meta(raw.get("note"), max_len=160),
        "deletable": bool(slug.startswith("custom-") or provider == "custom"),
    }


def _parse_probe_body(body_text: str) -> dict[str, str]:
    """Parse either Cloudflare `cdn-cgi/trace` key=value lines or JSON IP-info response."""
    text = (body_text or "").strip()
    if not text:
        return {}
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except Exception:
            obj = {}
        if isinstance(obj, dict):
            return {
                "exit_ip": str(obj.get("ip") or obj.get("query") or "").strip(),
                "country": str(obj.get("country") or obj.get("countryCode") or "").strip(),
                "region": str(obj.get("region") or obj.get("regionName") or "").strip(),
                "city": str(obj.get("city") or "").strip(),
                "isp": str(obj.get("isp") or obj.get("org") or "").strip(),
                "asn": str(obj.get("asn") or obj.get("as") or "").strip(),
                "ptr": str(obj.get("ptr") or obj.get("hostname") or "").strip(),
            }
    kv: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            kv[k.strip().lower()] = v.strip()
    return {
        "exit_ip": kv.get("ip", ""),
        "country": kv.get("loc", ""),
        "region": kv.get("colo", ""),
        "city": "",
        "isp": "",
        "asn": "",
        "ptr": "",
    }


async def _probe_via_proxy_async(
    *,
    scheme: str,
    host: str,
    port: int,
    username: str = "",
    password: str = "",
    probe_url: str = DEFAULT_PROBE_URL,
    timeout_sec: float = _DEFAULT_PROBE_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Perform a pure-Python async SOCKS5/HTTP proxy health probe against a fixed allowlisted HTTPS URL.

    Never invokes shell commands and never exposes proxy credentials in process argv/env.
    """
    sp = urlsplit(probe_url)
    target_host = sp.hostname or ""
    target_port = sp.port or (443 if sp.scheme == "https" else 80)
    target_path = sp.path or "/"
    if sp.query:
        target_path = f"{target_path}?{sp.query}"
    if not target_host or sp.scheme not in ("http", "https"):
        raise ValueError("Invalid server-side probe URL")

    clean_host = _validate_host(host)
    clean_port = _validate_port(port)
    forb, forb_reason = is_forbidden_proxy_target(clean_host, clean_port)
    if forb:
        raise ValueError(forb_reason)

    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(clean_host, clean_port, type=socket.SOCK_STREAM),
        timeout=timeout_sec,
    )
    if not infos:
        raise RuntimeError("代理主机 DNS 解析无结果")
    resolved_ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip_str = str(sockaddr[0]).split("%", 1)[0]
        ip_forb, ip_reason = is_forbidden_proxy_target(ip_str, clean_port)
        if ip_forb:
            raise ValueError(f"代理目标解析到受限地址（{ip_reason}）")
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)
    if not resolved_ips:
        raise RuntimeError("代理主机未解析到有效 IP 地址")
    pinned_ip = resolved_ips[0]

    t0 = time.monotonic()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(pinned_ip, clean_port),
        timeout=timeout_sec,
    )
    try:
        if scheme in ("socks5", "socks5h"):
            has_auth = bool(username or password)
            if has_auth:
                writer.write(b"\x05\x02\x00\x02")
            else:
                writer.write(b"\x05\x01\x00")
            await writer.drain()
            ver_method = await asyncio.wait_for(reader.readexactly(2), timeout=timeout_sec)
            if ver_method[0] != 5:
                raise RuntimeError("Invalid SOCKS5 greeting response")
            method = ver_method[1]
            if method == 0xFF:
                raise RuntimeError("SOCKS5 server rejected authentication methods")
            if method == 0x02:
                u_bytes = username.encode("utf-8")
                p_bytes = password.encode("utf-8")
                if len(u_bytes) > 255 or len(p_bytes) > 255:
                    raise RuntimeError("SOCKS5 credential exceeds 255 bytes")
                writer.write(bytes([1, len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes)
                await writer.drain()
                auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout_sec)
                if auth_resp[1] != 0:
                    raise RuntimeError("SOCKS5 authentication failed")
            elif method != 0x00:
                raise RuntimeError(f"Unsupported SOCKS5 auth method {method}")

            host_bytes = target_host.encode("ascii")
            req_pkt = (
                b"\x05\x01\x00\x03"
                + bytes([len(host_bytes)])
                + host_bytes
                + struct.pack("!H", target_port)
            )
            writer.write(req_pkt)
            await writer.drain()
            hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout_sec)
            if hdr[0] != 5 or hdr[1] != 0:
                raise RuntimeError(f"SOCKS5 CONNECT failed (rep={hdr[1]})")
            atyp = hdr[3]
            if atyp == 1:
                await asyncio.wait_for(reader.readexactly(6), timeout=timeout_sec)
            elif atyp == 3:
                alen = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout_sec))[0]
                await asyncio.wait_for(reader.readexactly(alen + 2), timeout=timeout_sec)
            elif atyp == 4:
                await asyncio.wait_for(reader.readexactly(18), timeout=timeout_sec)
            else:
                raise RuntimeError("Unsupported SOCKS5 address type")
        else:
            # HTTP / HTTPS proxy CONNECT tunnel
            import base64

            headers = [
                f"CONNECT {target_host}:{target_port} HTTP/1.1",
                f"Host: {target_host}:{target_port}",
            ]
            if username or password:
                b64 = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
                headers.append(f"Proxy-Authorization: Basic {b64}")
            headers.append("\r\n")
            writer.write("\r\n".join(headers).encode("ascii"))
            await writer.drain()
            resp_hdr = b""
            while b"\r\n\r\n" not in resp_hdr and len(resp_hdr) < 8192:
                chunk = await asyncio.wait_for(reader.read(1024), timeout=timeout_sec)
                if not chunk:
                    break
                resp_hdr += chunk
            first_line = resp_hdr.split(b"\r\n", 1)[0].decode("ascii", errors="ignore")
            if " 200" not in first_line:
                raise RuntimeError(f"HTTP proxy CONNECT rejected ({first_line[:48]})")

        if sp.scheme == "https":
            ssl_ctx = ssl.create_default_context()
            await asyncio.wait_for(
                writer.start_tls(ssl_ctx, server_hostname=target_host),
                timeout=timeout_sec,
            )

        http_req = (
            f"GET {target_path} HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"User-Agent: agy-studio-egress-probe/1.0\r\n"
            f"Accept: application/json, text/plain\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(http_req)
        await writer.drain()

        raw_chunks: list[bytes] = []
        total_read = 0
        while total_read < 32768:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout_sec)
            if not chunk:
                break
            raw_chunks.append(chunk)
            total_read += len(chunk)
        raw_resp = b"".join(raw_chunks)
        latency_ms = int(round((time.monotonic() - t0) * 1000))
        if b"\r\n\r\n" not in raw_resp:
            raise RuntimeError("Malformed HTTP probe response")
        head_b, body_b = raw_resp.split(b"\r\n\r\n", 1)
        status_line = head_b.split(b"\r\n", 1)[0].decode("ascii", errors="ignore")
        parts = status_line.split()
        code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        if not (200 <= code < 300):
            raise RuntimeError(f"Probe HTTP {code}")
        parsed = _parse_probe_body(body_b.decode("utf-8", errors="ignore"))
        parsed["latency_ms"] = str(latency_ms)
        return parsed
    finally:
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass


class OpenBaoEgressVaultClient:
    """Async HTTP KV v2 client for egress nodes reusing `OpenBaoSecretBackend` auth."""

    def __init__(
        self,
        secrets_config: SecretsConfigService,
        *,
        kv_mount: str | None = None,
        vault_prefix: str | None = None,
        ref_prefix: str | None = None,
    ) -> None:
        self._secrets_config = secrets_config
        self._backend = OpenBaoSecretBackend(secrets_config)
        self._kv_mount_override = (kv_mount or "").strip()
        self._prefix_override = (vault_prefix or "").strip()
        self._ref_prefix_override = (ref_prefix or "").strip()

    def resolve_coordinates(self) -> dict[str, Any]:
        rt = self._secrets_config.resolve_openbao_runtime()
        raw_mount = (
            self._kv_mount_override
            or os.environ.get("AGY_EGRESS_VAULT_MOUNT", "").strip()
            or str(rt.get("kv_mount") or DEFAULT_KV_MOUNT)
        )
        ok_m, kv_mount, _ = _validate_kv_mount(raw_mount)
        if not ok_m:
            kv_mount = DEFAULT_KV_MOUNT

        raw_prefix = (
            self._prefix_override
            or os.environ.get("AGY_EGRESS_VAULT_PREFIX", "").strip()
            or DEFAULT_EGRESS_VAULT_PREFIX
        )
        ok_p, prefix, _ = _validate_kv_path(raw_prefix)
        if not ok_p:
            prefix = DEFAULT_EGRESS_VAULT_PREFIX

        raw_ref_prefix = (
            self._ref_prefix_override
            or os.environ.get("AGY_EGRESS_VAULT_REF_PREFIX", "").strip()
            or prefix
        )
        ok_rp, ref_prefix, _ = _validate_kv_path(raw_ref_prefix)
        if not ok_rp:
            ref_prefix = prefix

        return {
            "rt": rt,
            "ready": bool(rt.get("enabled") and rt.get("addr") and rt.get("credential_configured")),
            "addr": str(rt.get("addr") or ""),
            "kv_mount": kv_mount,
            "prefix": prefix,
            "ref_prefix": ref_prefix,
        }

    def is_ready(self) -> bool:
        return bool(self.resolve_coordinates()["ready"])

    def format_ref(self, slug: str) -> str:
        coords = self.resolve_coordinates()
        return f"{coords['ref_prefix']}/{slug}"

    async def list_keys(self) -> list[str]:
        coords = self.resolve_coordinates()
        if not coords["ready"]:
            return []
        url = f"{coords['addr']}/v1/{coords['kv_mount']}/metadata/{coords['prefix']}?list=true"
        timeout = aiohttp.ClientTimeout(total=_VAULT_IO_TIMEOUT_SEC, connect=3.0)
        async with aiohttp.ClientSession(timeout=timeout) as cli:
            token = await self._backend._resolve_client_token(cli, coords["rt"])
            if not token:
                raise SecretStoreError("OpenBao 缺少有效认证凭据")
            async with cli.get(
                url,
                headers={"X-Vault-Token": token, "Accept": "application/json"},
                allow_redirects=False,
            ) as resp:
                raw = await resp.content.read(_MAX_VAULT_RESP_BYTES + 1)
                if resp.status == 404:
                    return []
                if resp.status != 200 or len(raw) > _MAX_VAULT_RESP_BYTES:
                    raise SecretStoreError(f"OpenBao LIST 失败（HTTP {resp.status}）")
                parsed = json.loads(raw.decode("utf-8", errors="ignore"))
                keys = ((parsed.get("data") or {}) if isinstance(parsed, dict) else {}).get("keys")
                if not isinstance(keys, list):
                    return []
                out: list[str] = []
                for k in keys:
                    if isinstance(k, str):
                        ks = k.strip()
                        if ks and not ks.endswith("/") and "/" not in ks and ".." not in ks:
                            out.append(ks)
                return sorted(set(out))

    async def get_node(self, slug: str) -> dict[str, Any] | None:
        clean_slug = validate_egress_slug(slug, require_custom_prefix=False)
        coords = self.resolve_coordinates()
        if not coords["ready"]:
            return None
        url = f"{coords['addr']}/v1/{coords['kv_mount']}/data/{coords['prefix']}/{clean_slug}"
        timeout = aiohttp.ClientTimeout(total=_VAULT_IO_TIMEOUT_SEC, connect=3.0)
        async with aiohttp.ClientSession(timeout=timeout) as cli:
            token = await self._backend._resolve_client_token(cli, coords["rt"])
            if not token:
                raise SecretStoreError("OpenBao 缺少有效认证凭据")
            async with cli.get(
                url,
                headers={"X-Vault-Token": token, "Accept": "application/json"},
                allow_redirects=False,
            ) as resp:
                raw = await resp.content.read(_MAX_VAULT_RESP_BYTES + 1)
                if resp.status == 404:
                    return None
                if resp.status != 200 or len(raw) > _MAX_VAULT_RESP_BYTES:
                    raise SecretStoreError(f"OpenBao GET 失败（HTTP {resp.status}）")
                parsed = json.loads(raw.decode("utf-8", errors="ignore"))
                inner = ((parsed.get("data") or {}).get("data")) if isinstance(parsed, dict) else None
                return dict(inner) if isinstance(inner, dict) else None

    async def put_node(self, slug: str, data: dict[str, Any], *, merge: bool = False) -> dict[str, Any]:
        clean_slug = validate_egress_slug(slug, require_custom_prefix=False)
        coords = self.resolve_coordinates()
        if not coords["ready"]:
            raise SecretStoreError("OpenBao 未启用或未配置有效凭据")
        merged = dict(data)
        if merge:
            existing = await self.get_node(clean_slug)
            if isinstance(existing, dict):
                base = dict(existing)
                base.update(merged)
                merged = base
        url = f"{coords['addr']}/v1/{coords['kv_mount']}/data/{coords['prefix']}/{clean_slug}"
        timeout = aiohttp.ClientTimeout(total=_VAULT_IO_TIMEOUT_SEC, connect=3.0)
        async with aiohttp.ClientSession(timeout=timeout) as cli:
            token = await self._backend._resolve_client_token(cli, coords["rt"])
            if not token:
                raise SecretStoreError("OpenBao 缺少有效认证凭据")
            async with cli.post(
                url,
                json={"data": merged},
                headers={"X-Vault-Token": token, "Accept": "application/json"},
                allow_redirects=False,
            ) as resp:
                await resp.content.read(4096)
                if 300 <= resp.status < 400:
                    raise SecretStoreError(f"OpenBao 写入返回重定向（HTTP {resp.status}），已拒绝")
                if resp.status not in (200, 204):
                    raise SecretStoreError(f"OpenBao 写入失败（HTTP {resp.status}）")
        return merged

    async def tombstone_node(self, slug: str) -> None:
        clean_slug = validate_egress_slug(slug, require_custom_prefix=False)
        existing = await self.get_node(clean_slug)
        tombstone = dict(existing) if isinstance(existing, dict) else {"tag": clean_slug, "provider": "custom"}
        tombstone["status"] = "removed"
        tombstone["username"] = ""
        tombstone["password"] = ""
        tombstone["removed_at"] = _utc_iso_now()
        await self.put_node(clean_slug, tombstone, merge=False)


class StudioEgressPoolService:
    """Studio backend service and REST handlers for egress proxy pool management."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        secrets_config: SecretsConfigService,
        *,
        vault_client: Any | None = None,
        audit_log_path: str | Path | None = None,
        pool_cli_path: str | None = None,
        pool_python_path: str | None = None,
        probe_fn: Callable[..., Awaitable[dict[str, Any]]] | None = None,
        subprocess_exec: Callable[..., Awaitable[Any]] | None = None,
        in_use_checker: Callable[[str, str], Awaitable[bool] | bool] | None = None,
        cli_draw_timeout: float = _DEFAULT_CLI_DRAW_TIMEOUT_SEC,
        cli_verify_timeout: float = _DEFAULT_CLI_VERIFY_TIMEOUT_SEC,
        cli_prune_timeout: float = _DEFAULT_CLI_PRUNE_TIMEOUT_SEC,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.secrets_config = secrets_config
        self.vault = vault_client or OpenBaoEgressVaultClient(secrets_config)
        self._pool_cli_override = pool_cli_path
        self._pool_python_override = pool_python_path
        self._probe_fn = probe_fn
        self._subprocess_exec = subprocess_exec or asyncio.create_subprocess_exec
        self._in_use_checker = in_use_checker
        self._cli_draw_timeout = float(cli_draw_timeout)
        self._cli_verify_timeout = float(cli_verify_timeout)
        self._cli_prune_timeout = float(cli_prune_timeout)

        default_audit = Path(
            os.environ.get(
                "AGY_STUDIO_EGRESS_AUDIT_LOG",
                str(self.auth_mgr.config_dir / "egress_pool_audit.jsonl"),
            )
        )
        self.audit = _EgressAuditLogger(Path(audit_log_path) if audit_log_path is not None else default_audit)

        # Bounded async jobs & concurrency guards (BM4)
        self._jobs: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._bg_tasks: set[asyncio.Task[Any]] = set()
        self._active_procs: set[Any] = set()
        self._draw_active: bool = False
        self._prune_active: bool = False
        self._verify_sem = asyncio.Semaphore(_MAX_VERIFY_CONCURRENCY)
        self._verify_inflight: int = 0
        self._verifying_nodes: set[str] = set()

    def set_in_use_checker(self, checker: Callable[[str, str], Awaitable[bool] | bool] | None) -> None:
        self._in_use_checker = checker

    # ------------------------------------------------------------------ Pluggable CLI Discovery
    def _resolve_pool_cli(self) -> list[str] | None:
        raw_cli = (
            self._pool_cli_override
            if self._pool_cli_override is not None
            else os.environ.get("AGY_EGRESS_POOL_CLI", "")
        ).strip()
        if not raw_cli:
            return None
        cli_path = Path(raw_cli).expanduser()
        if _is_forbidden_agy_binary(cli_path):
            return None
        if not cli_path.is_file():
            return None
        if cli_path.suffix == ".py":
            py_bin = (
                self._pool_python_override
                if self._pool_python_override is not None
                else os.environ.get("AGY_EGRESS_POOL_PYTHON", "")
            ).strip()
            if py_bin:
                py_p = Path(py_bin).expanduser()
                if _is_forbidden_agy_binary(py_p):
                    return None
                if not (py_p.is_file() and os.access(py_p, os.X_OK)):
                    return None
                return [str(py_p), str(cli_path)]
            return ["python3", str(cli_path)]
        if not os.access(cli_path, os.X_OK):
            return None
        return [str(cli_path)]

    def is_draw_supported(self) -> bool:
        return self._resolve_pool_cli() is not None

    def _resolve_probe_url(self) -> str:
        raw = os.environ.get("AGY_EGRESS_PROBE_URL", "").strip()
        if raw and raw.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            return raw
        return DEFAULT_PROBE_URL

    # ------------------------------------------------------------------ Subprocess & Cleanup (BM4)
    @staticmethod
    async def _terminate_proc_group(proc: Any) -> None:
        if proc is None or getattr(proc, "returncode", None) is not None:
            return
        pid = getattr(proc, "pid", None)
        if isinstance(pid, int) and pid > 0:
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                return
            except Exception:
                try:
                    proc.terminate()
                except Exception:
                    pass
        else:
            try:
                proc.terminate()
            except Exception:
                pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
            return
        except Exception:
            pass
        if isinstance(pid, int) and pid > 0:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                return
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        else:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        except Exception:
            pass

    async def _run_pool_cli(self, args: list[str], *, timeout_sec: float) -> tuple[int, str, str]:
        base = self._resolve_pool_cli()
        if not base:
            raise RuntimeError("未配置住宅 IP 池适配器（AGY_EGRESS_POOL_CLI）")
        proc = await self._subprocess_exec(
            *base,
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        self._active_procs.add(proc)
        try:
            out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            rc = int(proc.returncode if proc.returncode is not None else 0)
            return (
                rc,
                _scrub_egress_text(out_b.decode("utf-8", errors="ignore"), max_len=1200),
                _scrub_egress_text(err_b.decode("utf-8", errors="ignore"), max_len=600),
            )
        except asyncio.TimeoutError:
            await self._terminate_proc_group(proc)
            raise TimeoutError(f"出口池任务超时（>{timeout_sec:.0f}s）")
        except asyncio.CancelledError:
            await self._terminate_proc_group(proc)
            raise
        finally:
            self._active_procs.discard(proc)

    async def close_all(self) -> None:
        """Cancel background jobs and terminate/reap all active CLI process groups (0 orphans)."""
        for task in list(self._bg_tasks):
            if not task.done():
                task.cancel()
        for proc in list(self._active_procs):
            await self._terminate_proc_group(proc)
        if self._bg_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*list(self._bg_tasks), return_exceptions=True),
                    timeout=3.0,
                )
            except Exception:
                pass
        self._bg_tasks.clear()
        self._active_procs.clear()
        self._draw_active = False
        self._prune_active = False
        self._verifying_nodes.clear()
        self._verify_inflight = 0

    # ------------------------------------------------------------------ Job Tracking
    def _create_job(self, kind: str, target: str = "") -> dict[str, Any]:
        jid = f"egj_{secrets.token_hex(6)}"
        job = {
            "job_id": jid,
            "kind": kind,
            "target": _sanitize_slug(target, max_len=64) if target else "",
            "status": "queued",
            "created_at": _utc_iso_now(),
            "finished_at": "",
            "result": None,
            "error": "",
        }
        self._jobs[jid] = job
        while len(self._jobs) > _MAX_JOBS_HISTORY:
            self._jobs.popitem(last=False)
        return job

    def _track_task(self, coro: Awaitable[Any]) -> asyncio.Task[Any]:
        task = asyncio.create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)
        return task

    # ------------------------------------------------------------------ Four-Layer Write Gate (BM1)
    async def _enforce_write_gate(
        self,
        request: web.Request,
        *,
        action: str,
        node: str = "",
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        # Gate 1a: Origin required & strictly same-origin
        ok_orig, err_orig = self.auth_mgr.check_same_origin(request, require_origin=True)
        if not ok_orig:
            self.audit.record(action=action, ok=False, node=node, error="denied_origin")
            return False, None, studio_auth_error(err_orig, status=403)

        # Gate 1b: Sec-Fetch-Site validation
        sfs = (request.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sfs and sfs not in ("same-origin", "none"):
            self.audit.record(action=action, ok=False, node=node, error="denied_sec_fetch_site")
            return False, None, studio_auth_error("Sec-Fetch-Site 跨站写请求已拦截", status=403)

        # Gate 2: Non-simple Content-Type: application/json
        if _extract_media_type(request) != "application/json":
            self.audit.record(action=action, ok=False, node=node, error="denied_content_type")
            return False, None, studio_auth_error("写接口仅接受 Content-Type: application/json", status=415)

        # Gate 3: Authenticated session + !must_change_password
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            self.audit.record(action=action, ok=False, node=node, error=f"denied_auth:{status_code}")
            return False, None, studio_auth_error(err_auth, status=status_code)

        # Gate 4a: Constant-time X-Studio-CSRF check
        ok_csrf, err_csrf = self.auth_mgr.check_csrf(request, sess)
        if not ok_csrf:
            self.audit.record(action=action, ok=False, sess=sess, node=node, error="denied_csrf")
            return False, None, studio_auth_error(err_csrf, status=403)

        # Gate 4b: Live RBAC role == admin
        if sess.get("role") != "admin":
            self.audit.record(action=action, ok=False, sess=sess, node=node, error="denied_rbac")
            return False, None, studio_auth_error("只读权限（readonly）禁止执行写操作", status=403)

        return True, sess, None

    async def _parse_write_body(
        self,
        request: web.Request,
        *,
        sess: dict[str, Any],
        action: str,
        allowed_keys: frozenset[str],
        allow_empty: bool,
        node: str = "",
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request,
            max_bytes=MAX_PROMPT_BODY_BYTES,
            allow_empty=allow_empty,
        )
        if not ok_body or body is None:
            self.audit.record(action=action, ok=False, sess=sess, node=node, error=body_outcome)
            return False, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_WRITE_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action=action,
                ok=False,
                sess=sess,
                node=node,
                error=f"denied_forbidden_field:{bad_forb}",
            )
            return False, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止传入受限字段: {bad_forb}"},
                status=400,
            )

        unknown = set(body.keys()) - allowed_keys
        if unknown:
            self.audit.record(action=action, ok=False, sess=sess, node=node, error="denied_unknown_field")
            return False, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": f"存在未允许的字段: {sorted(unknown)[0]}"},
                status=400,
            )

        return True, body, None

    # ------------------------------------------------------------------ Public Service Helpers
    async def list_nodes(self) -> dict[str, Any]:
        vault_ready = bool(self.vault.is_ready())
        nodes: list[dict[str, Any]] = []
        vault_error = ""
        if vault_ready:
            try:
                keys = await self.vault.list_keys()
                # Bounded parallel GETs (concurrency <= 6)
                sem = asyncio.Semaphore(6)

                async def _fetch_one(slug: str) -> dict[str, Any] | None:
                    async with sem:
                        raw = await self.vault.get_node(slug)
                        if not isinstance(raw, dict):
                            return None
                        return sanitize_egress_node(slug, raw, ref=self.vault.format_ref(slug))

                fetched = await asyncio.gather(*(_fetch_one(k) for k in keys), return_exceptions=True)
                for item in fetched:
                    if isinstance(item, dict):
                        nodes.append(item)
            except Exception as exc:
                vault_error = _scrub_egress_text(exc)
        nodes.sort(key=lambda n: (0 if n.get("status") == "clean" else 1, n.get("name") or ""))
        return {
            "ok": True,
            "vault_ready": vault_ready,
            "vault_error": vault_error,
            "draw_supported": self.is_draw_supported(),
            "prune_supported": self.is_draw_supported(),
            "draw_running": self._draw_active,
            "verify_running": len(self._verifying_nodes),
            "nodes": nodes,
            "total": len(nodes),
        }

    async def resolve_node_ref(self, slug_or_ref: str) -> tuple[str, str] | None:
        """Resolve a node slug or Vault ref to `(slug, canonical_ref)` if active (non-removed)."""
        raw = str(slug_or_ref or "").strip()
        if not raw:
            return None
        slug = raw.rsplit("/", 1)[-1]
        try:
            clean_slug = validate_egress_slug(slug, require_custom_prefix=False)
        except ValueError:
            return None
        if not self.vault.is_ready():
            return None
        node = await self.vault.get_node(clean_slug)
        if not isinstance(node, dict):
            return None
        if str(node.get("status") or "").strip().lower() == "removed":
            return None
        return clean_slug, self.vault.format_ref(clean_slug)

    # ------------------------------------------------------------------ REST Handlers
    async def handle_list_nodes(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        data = await self.list_nodes()
        data["can_edit"] = sess.get("role") == "admin"
        return web.json_response(data)

    async def handle_create_node(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="egress_create")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="egress_create",
            allowed_keys=_ALLOWED_CREATE_KEYS,
            allow_empty=False,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        try:
            parsed = parse_manual_egress_input(body)
        except ValueError as exc:
            err_msg = _scrub_egress_text(exc)
            self.audit.record(action="egress_create", ok=False, sess=sess, error=err_msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": err_msg}, status=400)

        slug = parsed["slug"]
        vault_data = parsed["vault_data"]
        if not self.vault.is_ready():
            self.audit.record(action="egress_create", ok=False, sess=sess, node=slug, error="vault_unready")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "OpenBao 未就绪，无法安全保存出口节点凭据"},
                status=503,
            )

        try:
            await self.vault.put_node(slug, vault_data, merge=False)
        except Exception as exc:
            err_msg = _scrub_egress_text(exc)
            self.audit.record(action="egress_create", ok=False, sess=sess, node=slug, error=err_msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": err_msg}, status=502)

        sanitized = sanitize_egress_node(slug, vault_data, ref=self.vault.format_ref(slug))
        self.audit.record(action="egress_create", ok=True, sess=sess, node=slug)
        return web.json_response({"ok": True, "node": sanitized}, status=201)

    async def handle_delete_node(self, request: web.Request) -> web.Response:
        raw_name = request.match_info.get("name") or ""
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="egress_delete", node=raw_name
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, _body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="egress_delete",
            allowed_keys=frozenset(),
            allow_empty=True,
            node=raw_name,
        )
        if not ok_body:
            assert body_resp is not None
            return body_resp

        try:
            slug = validate_egress_slug(raw_name, require_custom_prefix=False)
        except ValueError as exc:
            self.audit.record(action="egress_delete", ok=False, sess=sess, node=raw_name, error=str(exc))
            return web.json_response({"ok": False, "source": "studio_api", "error": str(exc)}, status=400)

        if not self.vault.is_ready():
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "OpenBao 未就绪"},
                status=503,
            )

        existing = await self.vault.get_node(slug)
        if not isinstance(existing, dict) or str(existing.get("status") or "").lower() == "removed":
            return web.json_response({"ok": False, "source": "studio_api", "error": "出口节点不存在"}, status=404)

        provider = str(existing.get("provider") or "").strip().lower()
        if not (slug.startswith("custom-") or provider == "custom"):
            self.audit.record(action="egress_delete", ok=False, sess=sess, node=slug, error="not_custom_node")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "仅允许删除手工录入的 custom-* 出口节点"},
                status=400,
            )

        ref = self.vault.format_ref(slug)
        if self._in_use_checker is not None:
            used_res = self._in_use_checker(slug, ref)
            if inspect.isawaitable(used_res):
                used_res = await used_res
            if used_res:
                self.audit.record(action="egress_delete", ok=False, sess=sess, node=slug, error="in_use")
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "该出口节点正被活跃浏览器会话使用，请先停止浏览器"},
                    status=409,
                )

        if slug in self._verifying_nodes:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "该出口节点正在测活中，请稍后再删除"},
                status=409,
            )

        try:
            await self.vault.tombstone_node(slug)
        except Exception as exc:
            err_msg = _scrub_egress_text(exc)
            self.audit.record(action="egress_delete", ok=False, sess=sess, node=slug, error=err_msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": err_msg}, status=502)

        self.audit.record(action="egress_delete", ok=True, sess=sess, node=slug)
        return web.json_response({"ok": True, "deleted": slug})

    async def handle_verify_node(self, request: web.Request) -> web.Response:
        raw_name = request.match_info.get("name") or ""
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="egress_verify", node=raw_name
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, _body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="egress_verify",
            allowed_keys=_ALLOWED_VERIFY_KEYS,
            allow_empty=True,
            node=raw_name,
        )
        if not ok_body:
            assert body_resp is not None
            return body_resp

        try:
            slug = validate_egress_slug(raw_name, require_custom_prefix=False)
        except ValueError as exc:
            return web.json_response({"ok": False, "source": "studio_api", "error": str(exc)}, status=400)

        if not self.vault.is_ready():
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "OpenBao 未就绪"},
                status=503,
            )

        node_raw = await self.vault.get_node(slug)
        if not isinstance(node_raw, dict) or str(node_raw.get("status") or "").lower() == "removed":
            return web.json_response({"ok": False, "source": "studio_api", "error": "出口节点不存在"}, status=404)

        # Anti-SSRF pre-flight check before launching verify job
        host = str(node_raw.get("host") or "").strip()
        port_s = str(node_raw.get("port") or "").strip()
        if (not host or not port_s) and node_raw.get("server"):
            sp = urlsplit(str(node_raw["server"]))
            host = host or (sp.hostname or "")
            port_s = port_s or (str(sp.port) if sp.port else "")
        try:
            clean_host = _validate_host(host)
            clean_port = _validate_port(port_s)
        except ValueError as exc:
            return web.json_response({"ok": False, "source": "studio_api", "error": str(exc)}, status=400)
        forb, forb_msg = is_forbidden_proxy_target(clean_host, clean_port)
        if forb:
            self.audit.record(action="egress_verify", ok=False, sess=sess, node=slug, error="ssrf_blocked")
            return web.json_response({"ok": False, "source": "studio_api", "error": forb_msg}, status=400)

        if slug in self._verifying_nodes:
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "verify_already_running",
                    "error": f"节点 {slug} 正在测活中，请勿重复触发",
                },
                status=409,
            )
        if self._verify_inflight >= _MAX_VERIFY_CONCURRENCY:
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "verify_rate_limited",
                    "error": f"并发测活已达上限（{_MAX_VERIFY_CONCURRENCY}），请稍候重试",
                },
                status=429,
            )

        self._verifying_nodes.add(slug)
        self._verify_inflight += 1
        job = self._create_job("verify", target=slug)
        self.audit.record(action="egress_verify", ok=True, sess=sess, node=slug, job_id=job["job_id"])

        async def _run_verify() -> None:
            try:
                async with self._verify_sem:
                    job["status"] = "running"
                    provider = str(node_raw.get("provider") or "").strip().lower()
                    is_pool_managed = (
                        bool(node_raw.get("proxy_client_id"))
                        or slug.startswith("urn-")
                        or provider == "urnetwork"
                    )
                    if is_pool_managed and self.is_draw_supported() and self._probe_fn is None:
                        rc, out_txt, err_txt = await self._run_pool_cli(
                            ["verify", slug],
                            timeout_sec=self._cli_verify_timeout,
                        )
                        refreshed = await self.vault.get_node(slug)
                        sanitized = (
                            sanitize_egress_node(slug, refreshed, ref=self.vault.format_ref(slug))
                            if isinstance(refreshed, dict)
                            else None
                        )
                        if rc == 0:
                            job["status"] = "done"
                            job["result"] = {"node": sanitized, "output": out_txt[:400]}
                        else:
                            job["status"] = "failed"
                            job["error"] = err_txt or out_txt or f"CLI verify exited {rc}"
                            job["result"] = {"node": sanitized}
                    else:
                        scheme = str(node_raw.get("scheme") or "socks5h").strip().lower()
                        if scheme not in _ALLOWED_SCHEMES:
                            scheme = "socks5h"
                        username = str(node_raw.get("username") or "")
                        password = str(node_raw.get("password") or "")
                        probe_url = self._resolve_probe_url()
                        probe_callable = self._probe_fn or _probe_via_proxy_async
                        try:
                            meta = await probe_callable(
                                scheme=scheme,
                                host=clean_host,
                                port=clean_port,
                                username=username,
                                password=password,
                                probe_url=probe_url,
                                timeout_sec=_DEFAULT_PROBE_TIMEOUT_SEC,
                            )
                            update_fields = {
                                "exit_ip": str(meta.get("exit_ip") or ""),
                                "country": str(meta.get("country") or ""),
                                "region": str(meta.get("region") or ""),
                                "city": str(meta.get("city") or ""),
                                "isp": str(meta.get("isp") or ""),
                                "asn": str(meta.get("asn") or ""),
                                "ptr": str(meta.get("ptr") or ""),
                                "latency_ms": str(meta.get("latency_ms") or ""),
                                "status": "clean",
                                "verified_at": _utc_iso_now(),
                            }
                            merged = await self.vault.put_node(slug, update_fields, merge=True)
                            job["status"] = "done"
                            job["result"] = {
                                "node": sanitize_egress_node(slug, merged, ref=self.vault.format_ref(slug))
                            }
                        except Exception as exc:
                            reason = _scrub_egress_text(type(exc).__name__ + ": " + str(exc), max_len=64)
                            dead_update = {
                                "status": f"dead:{reason[:48]}",
                                "verified_at": _utc_iso_now(),
                            }
                            try:
                                merged = await self.vault.put_node(slug, dead_update, merge=True)
                                san = sanitize_egress_node(slug, merged, ref=self.vault.format_ref(slug))
                            except Exception:
                                san = None
                            job["status"] = "failed"
                            job["error"] = _scrub_egress_text(exc)
                            job["result"] = {"node": san}
            except asyncio.CancelledError:
                job["status"] = "failed"
                job["error"] = "cancelled"
                raise
            except Exception as exc:
                job["status"] = "failed"
                job["error"] = _scrub_egress_text(exc)
            finally:
                job["finished_at"] = _utc_iso_now()
                self._verifying_nodes.discard(slug)
                self._verify_inflight = max(0, self._verify_inflight - 1)

        self._track_task(_run_verify())
        return web.json_response({"ok": True, "job": dict(job)}, status=202)

    async def handle_draw(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="egress_draw")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="egress_draw",
            allowed_keys=_ALLOWED_DRAW_KEYS,
            allow_empty=True,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        if not self.is_draw_supported():
            self.audit.record(action="egress_draw", ok=False, sess=sess, error="draw_not_configured")
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "draw_supported": False,
                    "error": "未配置住宅 IP 池适配器（AGY_EGRESS_POOL_CLI），仅支持手工录入 SOCKS5 与内置测活",
                },
                status=501,
            )

        raw_country = str(body.get("country") or "US").strip().upper()
        if not _COUNTRY_RE.fullmatch(raw_country):
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "country 必须为两位 ISO 国家代码（如 US、JP、GB）"},
                status=400,
            )
        try:
            raw_want = body.get("want", 1)
            raw_tries = body.get("max_tries", 12)
            if isinstance(raw_want, bool) or isinstance(raw_tries, bool):
                raise ValueError("want/max_tries 不能为布尔值")
            want = int(raw_want)
            max_tries = int(raw_tries)
            if not (1 <= want <= 5) or not (1 <= max_tries <= 50):
                raise ValueError("want 须在 1..5，max_tries 须在 1..50")
        except (TypeError, ValueError) as exc:
            return web.json_response({"ok": False, "source": "studio_api", "error": str(exc)}, status=400)

        if self._draw_active:
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "draw_busy",
                    "error": "已有住宅 IP 抽取任务正在运行（全局并发上限为 1），请等待完成",
                },
                status=429,
            )

        self._draw_active = True
        job = self._create_job("draw", target=raw_country)
        self.audit.record(action="egress_draw", ok=True, sess=sess, node=raw_country, job_id=job["job_id"])

        async def _run_draw() -> None:
            try:
                job["status"] = "running"
                rc, out_txt, err_txt = await self._run_pool_cli(
                    [
                        "draw",
                        "--country",
                        raw_country,
                        "--want",
                        str(want),
                        "--max-tries",
                        str(max_tries),
                    ],
                    timeout_sec=self._cli_draw_timeout,
                )
                if rc == 0:
                    job["status"] = "done"
                    job["result"] = {"country": raw_country, "want": want, "output": out_txt[:600]}
                else:
                    job["status"] = "failed"
                    job["error"] = err_txt or out_txt or f"draw exited {rc}"
            except asyncio.CancelledError:
                job["status"] = "failed"
                job["error"] = "cancelled"
                raise
            except Exception as exc:
                job["status"] = "failed"
                job["error"] = _scrub_egress_text(exc)
            finally:
                job["finished_at"] = _utc_iso_now()
                self._draw_active = False

        self._track_task(_run_draw())
        return web.json_response({"ok": True, "job": dict(job)}, status=202)

    async def handle_prune(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="egress_prune")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="egress_prune",
            allowed_keys=_ALLOWED_PRUNE_KEYS,
            allow_empty=True,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        if not self.is_draw_supported():
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "draw_supported": False,
                    "error": "未配置住宅 IP 池适配器（AGY_EGRESS_POOL_CLI）",
                },
                status=501,
            )

        if self._prune_active:
            return web.json_response(
                {"ok": False, "source": "studio_api", "code": "prune_busy", "error": "已有清理任务在运行"},
                status=429,
            )

        self._prune_active = True
        job = self._create_job("prune", target="pool")
        self.audit.record(action="egress_prune", ok=True, sess=sess, job_id=job["job_id"])

        async def _run_prune() -> None:
            try:
                job["status"] = "running"
                args = ["prune"]
                if body.get("dry_run") is True:
                    args.append("--dry-run")
                rc, out_txt, err_txt = await self._run_pool_cli(
                    args,
                    timeout_sec=self._cli_prune_timeout,
                )
                if rc == 0:
                    job["status"] = "done"
                    job["result"] = {"output": out_txt[:600]}
                else:
                    job["status"] = "failed"
                    job["error"] = err_txt or out_txt or f"prune exited {rc}"
            except asyncio.CancelledError:
                job["status"] = "failed"
                job["error"] = "cancelled"
                raise
            except Exception as exc:
                job["status"] = "failed"
                job["error"] = _scrub_egress_text(exc)
            finally:
                job["finished_at"] = _utc_iso_now()
                self._prune_active = False

        self._track_task(_run_prune())
        return web.json_response({"ok": True, "job": dict(job)}, status=202)

    async def handle_list_jobs(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        jobs = list(reversed(list(self._jobs.values())))[:30]
        return web.json_response({"ok": True, "jobs": jobs})

    async def handle_get_job(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        jid = str(request.match_info.get("job_id") or "").strip()
        job = self._jobs.get(jid)
        if not job:
            return web.json_response({"ok": False, "source": "studio_api", "error": "任务不存在"}, status=404)
        return web.json_response({"ok": True, "job": dict(job)})
