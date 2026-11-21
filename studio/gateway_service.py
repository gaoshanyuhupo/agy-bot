#!/usr/bin/env python3
"""AGY Studio — External Model Gateways CRUD & Bounded `/probe` Service.

Security invariants (C1–C4):
- C1 (Auth / RBAC / 4-layer write gate & GET redaction):
  - All mutating endpoints (`POST/PUT/PATCH/DELETE` + `/probe`) enforce:
    1. Strict Same-Origin (`Origin` required & matched) + `Sec-Fetch-Site` check -> 403
    2. `Content-Type: application/json` -> 415
    3. Authenticated session + live RBAC + `must_change_password=False` -> 401/403
    4. `X-Studio-CSRF` + `role == "admin"` -> 403
    + bounded JSON body reading (`<= 32 KiB`) & `0600` JSONL audit logging.
  - `GET /api/gateways` NEVER echoes plaintext `api_key`, `api_key_cmd`, host absolute
    paths, or sensitive `extra_headers` values (`Authorization`, `X-API-Key`, `Cookie`,
    `Proxy-Authorization`, or any key containing `token|secret|key|auth|passwd|password|credential`).
- C2 (Anti-RCE & Dangerous Field Rejection):
  - Strict input field whitelist; `api_key_cmd`, `api_key_file`, `secret_ref`, and
    invalid gateway IDs (`../x`, `__proto__`, `constructor`, whitespace/control chars)
    return `400` and are never persisted.
  - Pre-existing host `api_key_cmd` entries are surfaced read-only (`read_only_cmd: true`)
    and cannot be overwritten, deleted, or command-executed via Web API (`403`).
- C3 (SSRF / DoS / Secret-Safe `/probe`):
  - Validates `base_url` (and resolves DNS before probing) to block cloud metadata IPs
    (AWS/ECS IMDS, IPv6 EC2 metadata, GCP metadata hostnames, IPv4/IPv6 link-local ranges,
    unspecified addresses, Alibaba metadata), non-HTTP(S) schemes, embedded `user:pass@`,
    redirects (`allow_redirects=False`), while allowing legitimate local loopback
    (`127.0.0.1` / `localhost` / `::1`) for Ollama/vLLM.
  - Bounded timeout (`<= 8s`) and bounded response body (`<= 512 KiB`).
  - Redacts Bearer/API keys from upstream error text and server logs.
- C4 (`SecretStore` + Zero Plaintext `api_key` in `gateways.json`):
  - Stores API keys in `SecretStore` (OpenBao KV v2 -> `local_0600` fallback) and writes
    ONLY non-sensitive metadata + `secret_ref` into `gateways.json` (`0700` dir, `0600` file,
    `O_NOFOLLOW`, `flock` atomic replace).
"""

from __future__ import annotations

import asyncio
import fcntl
import fnmatch
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import tempfile
import time
from typing import Any, Sequence
from urllib.parse import urlsplit

import aiohttp
from aiohttp import abc as aiohttp_abc, web

from .auth import StudioAuthManager, studio_auth_error
from .chat_service import (
    StudioAuditLogger,
    _extract_media_type,
    _read_bounded_json_body,
)
from .data_sources import redact_secrets_only
from .secrets_config_service import (
    SecretsConfigService,
    _ensure_secure_parent_dir,
    _mask_secret_hint,
    _read_regular_json_no_symlink,
    _validate_gateway_secret_id,
)

log = logging.getLogger("agy-studio.gateways")

MAX_GATEWAYS_COUNT = 64
MAX_PROBE_BODY_BYTES = 512 * 1024  # 512 KiB strict cap
PROBE_TOTAL_TIMEOUT_SEC = 6.5  # <= 8s
PROBE_CONNECT_TIMEOUT_SEC = 3.0
PROBE_READ_TIMEOUT_SEC = 5.0
MAX_EXTRA_HEADERS = 24
MAX_PATTERNS_PER_LIST = 128
MAX_STATIC_MODELS = 256
MAX_BASE_URL_LEN = 512

_CTRL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
_HEADER_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_NUMERIC_IP_LABEL_RE = re.compile(r"^(?:[0-9]+|0[xX][0-9a-fA-F]+|0[oO][0-7]+)$")
_CANONICAL_IPV4_OCTET_RE = re.compile(r"^(?:0|[1-9][0-9]{0,2})$")
_SENSITIVE_HEADER_EXACT = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "cookie",
        "set-cookie",
        "x-auth-token",
    }
)
_SENSITIVE_HEADER_TOKENS = ("token", "secret", "key", "auth", "passwd", "password", "credential")

_VALID_DIALECTS = frozenset(
    {
        "cpa",
        "openai_strict",
        "zhipu",
        "ark",
        "deepseek",
        "litellm",
        "new_api",
        "openrouter",
        "openai_2api",
    }
)
_VALID_EFFORT_MODES = frozenset({"body", "model_paren", "none"})
_VALID_MAX_TOKENS_FIELDS = frozenset({"max_completion_tokens", "max_tokens", "omit"})
_VALID_CREDENTIAL_MODES = frozenset({"api_key", "api_key_env", "none"})

_DIALECT_DEFAULTS: dict[str, dict[str, Any]] = {
    "cpa": {
        "supports_reasoning_effort": True,
        "effort_mode": "body",
        "flatten_system_content": False,
        "strip_stream_options": False,
        "max_tokens_field": "max_completion_tokens",
        "max_tokens_cap": None,
        "adaptive_400_fallback": True,
    },
    "openai_strict": {
        "supports_reasoning_effort": False,
        "effort_mode": "none",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 16384,
        "adaptive_400_fallback": True,
    },
    "zhipu": {
        "supports_reasoning_effort": False,
        "effort_mode": "none",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 16384,
        "adaptive_400_fallback": True,
    },
    "ark": {
        "supports_reasoning_effort": True,
        "effort_mode": "body",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 16384,
        "adaptive_400_fallback": True,
    },
    "deepseek": {
        "supports_reasoning_effort": False,
        "effort_mode": "none",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 8192,
        "adaptive_400_fallback": True,
    },
    "litellm": {
        "supports_reasoning_effort": True,
        "effort_mode": "body",
        "flatten_system_content": False,
        "strip_stream_options": False,
        "max_tokens_field": "max_completion_tokens",
        "max_tokens_cap": None,
        "adaptive_400_fallback": True,
    },
    "new_api": {
        "supports_reasoning_effort": True,
        "effort_mode": "body",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 16384,
        "adaptive_400_fallback": True,
    },
    "openrouter": {
        "supports_reasoning_effort": True,
        "effort_mode": "body",
        "flatten_system_content": False,
        "strip_stream_options": False,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": None,
        "adaptive_400_fallback": True,
    },
    "openai_2api": {
        "supports_reasoning_effort": True,
        "effort_mode": "model_paren",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 16384,
        "adaptive_400_fallback": True,
    },
}

_FORBIDDEN_CLIENT_FIELDS = frozenset(
    {
        "api_key_cmd",
        "api_key_file",
        "secret_ref",
        "cmd",
        "command",
        "shell",
        "script",
    }
)

_ALLOWED_MUTATION_FIELDS = frozenset(
    {
        "id",
        "name",
        "base_url",
        "dialect",
        "enabled",
        "credential_kind",
        "api_key",
        "api_key_env",
        "clear_api_key",
        "preferred_secret_backend",
        "include_models",
        "exclude_models",
        "models",
        "supports_reasoning_effort",
        "effort_mode",
        "flatten_system_content",
        "strip_stream_options",
        "max_tokens_field",
        "max_tokens_cap",
        "adaptive_400_fallback",
        "timeout_s",
        "extra_headers",
    }
)

_ALLOWED_PROBE_FIELDS = frozenset(
    {
        "gateway_id",
        "id",
        "base_url",
        "dialect",
        "credential_kind",
        "api_key",
        "api_key_env",
        "include_models",
        "exclude_models",
        "models",
        "extra_headers",
    }
)

_AWS_IMDS_V4 = ".".join(("169", "254", "169", "254"))
_AWS_ECS_V4 = ".".join(("169", "254", "170", "2"))
_ALI_META_V4 = ".".join(("100", "100", "100", "200"))
_AWS_EC2_V6_HOST = ":".join(("fd00", "ec2", "", "254"))
_AWS_EC2_V6_CIDR = ":".join(("fd00", "ec2", "", "")) + "/32"
_LINK_LOCAL_V4_CIDR = ".".join(("169", "254", "0", "0")) + "/16"
_LINK_LOCAL_V6_CIDR = "fe80::/10"

_BLOCKED_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "instance-data",
        "instance-data.ec2.internal",
        _AWS_IMDS_V4,
        _AWS_ECS_V4,
        _ALI_META_V4,
        _AWS_EC2_V6_HOST,
    }
)
_AWS_EC2_IPV6_NET = ipaddress.ip_network(_AWS_EC2_V6_CIDR)
_ALIBABA_META_IP = ipaddress.ip_address(_ALI_META_V4)
_LINK_LOCAL_V4_NET = ipaddress.ip_network(_LINK_LOCAL_V4_CIDR)
_LINK_LOCAL_V6_NET = ipaddress.ip_network(_LINK_LOCAL_V6_CIDR)

_BEARER_RE = re.compile(r"(?i)(bearer\s+)[^\s\"'`,;]+")
_SK_TOKEN_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_HVS_TOKEN_RE = re.compile(r"\bhvs\.[A-Za-z0-9_.-]{8,}\b")
_KV_SECRET_RE = re.compile(r"(?i)((?:api[_-]?key|x-api-key|authorization|token)\s*[:=]\s*)[^\s\"'`,;]+")


def is_sensitive_header_key(key: str) -> bool:
    low = (key or "").strip().lower()
    if not low:
        return False
    if low in _SENSITIVE_HEADER_EXACT:
        return True
    return any(tok in low for tok in _SENSITIVE_HEADER_TOKENS)


def sanitize_extra_headers_for_response(headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(headers, dict):
        return out
    for raw_k, raw_v in headers.items():
        k = str(raw_k or "").strip()
        if not k:
            continue
        v = "" if raw_v is None else str(raw_v)
        out[k] = "[REDACTED]" if is_sensitive_header_key(k) else v
    return out


def _is_blocked_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """Return `(blocked, reason)` for SSRF IP checks while allowing loopback (`127.0.0.1` / `::1`)."""
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return _is_blocked_ip(ip_obj.ipv4_mapped)
    if ip_obj.is_loopback:
        return False, ""
    if ip_obj.is_unspecified:
        return True, "禁止访问未指定地址（0.0.0.0 / ::）"
    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in _LINK_LOCAL_V4_NET:
        return True, "禁止访问链路本地或云元数据地址（IPv4 link-local）"
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in _LINK_LOCAL_V6_NET:
        return True, "禁止访问 IPv6 链路本地地址（fe80::/10）"
    if ip_obj.is_link_local:
        return True, "禁止访问链路本地地址"
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in _AWS_EC2_IPV6_NET:
        return True, "禁止访问云元数据 IPv6 地址"
    if ip_obj == _ALIBABA_META_IP:
        return True, "禁止访问云元数据地址"
    if ip_obj.is_multicast:
        return True, "禁止访问组播地址"
    return False, ""


def _looks_like_obfuscated_numeric_ip(hostname: str) -> bool:
    """Detect decimal/hex/octal/shorthand IPv4 obfuscation while sparing canonical IPv4 & domains.

    Catches:
    - C-style leading-zero octal octets (e.g. `0251.0376.0251.0376`, `0177.0.0.1`)
    - Hex/Python-octal/mixed-radix octets (`0x`/`0X`/`0o`/`0O` in any combination)
    - Non-standard 1/2/3-part shorthand numeric IPv4 (single integer, 2-part, or 3-part dotted)
    - Out-of-range 4-part numeric IPv4 labels (octet > 255)

    Returns `False` for canonical 4-octet decimal IPv4 (such as loopback or standard dotted-quad
    literals, which are validated by `ipaddress.ip_address` + `_is_blocked_ip`) and normal domains.
    """
    host = (hostname or "").strip().rstrip(".")
    if not host:
        return False
    labels = host.split(".")
    if not (1 <= len(labels) <= 4):
        return False
    for lbl in labels:
        if not lbl or not _NUMERIC_IP_LABEL_RE.fullmatch(lbl):
            return False
    # 1, 2, or 3 all-numeric labels are non-standard shorthand IPv4 representations.
    if len(labels) < 4:
        return True
    # 4 all-numeric labels: allow only canonical decimal octets (0..255 with no leading zeros/prefixes).
    for lbl in labels:
        if not _CANONICAL_IPV4_OCTET_RE.fullmatch(lbl) or int(lbl) > 255:
            return True
    return False


def _normalized_url_origin(raw_url: Any) -> tuple[str, str, int] | None:
    """Return canonical `(scheme, hostname, effective_port)` for an HTTP(S) URL."""
    if not isinstance(raw_url, str):
        return None
    s = raw_url.strip()
    if not s:
        return None
    try:
        parsed = urlsplit(s)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return None
        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
        if not hostname:
            return None
        port = parsed.port
    except ValueError:
        return None
    try:
        hostname = ipaddress.ip_address(hostname).compressed
    except ValueError:
        pass
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    return (scheme, hostname, effective_port)


def _is_same_origin_url(url_a: Any, url_b: Any) -> bool:
    """Strict origin comparison (`scheme`, `hostname`, `effective_port`); fail-closed on invalid URLs."""
    orig_a = _normalized_url_origin(url_a)
    orig_b = _normalized_url_origin(url_b)
    return orig_a is not None and orig_b is not None and orig_a == orig_b


class _PinnedResolver(aiohttp_abc.AbstractResolver):
    """Single-target fail-closed aiohttp resolver pinned to pre-validated DNS records.

    Eliminates DNS rebinding TOCTOU between `_dns_check_for_probe()` and `ClientSession.get()`
    while preserving normal TLS SNI and `Host` headers.
    """

    def __init__(
        self,
        target_host: str,
        target_port: int,
        records: Sequence[dict[str, Any]],
    ) -> None:
        self._target_host = (target_host or "").strip().lower().rstrip(".")
        self._target_port = int(target_port)
        self._records = [dict(r) for r in records]

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: int = socket.AF_INET,
    ) -> list[dict[str, Any]]:
        norm_host = (host or "").strip().lower().rstrip(".")
        if not self._target_host or norm_host != self._target_host:
            raise OSError(f"Pinned resolver rejected unexpected host: {host!r}")
        if port and int(port) != self._target_port:
            raise OSError(f"Pinned resolver rejected unexpected port: {port!r}")
        matched: list[dict[str, Any]] = []
        for rec in self._records:
            rec_family = int(rec.get("family", socket.AF_INET))
            if family and family != socket.AF_UNSPEC and rec_family != family:
                continue
            matched.append(
                {
                    "hostname": host,
                    "host": str(rec["host"]),
                    "port": int(port or rec.get("port") or self._target_port),
                    "family": rec_family,
                    "proto": int(rec.get("proto", socket.IPPROTO_TCP)),
                    "flags": int(rec.get("flags", socket.AI_NUMERICHOST | socket.AI_NUMERICSERV)),
                }
            )
        if not matched:
            raise OSError(f"Pinned resolver has no matching records for {host!r}")
        return matched

    async def close(self) -> None:
        return None


def validate_gateway_base_url(raw: Any) -> tuple[bool, str, str]:
    """Strictly validate gateway `base_url` against SSRF, scheme abuse, and embedded credentials."""
    if not isinstance(raw, str):
        return False, "", "Base URL 必须为字符串"
    s = raw.strip()
    if not s:
        return False, "", "Base URL 不能为空"
    if len(s) > MAX_BASE_URL_LEN:
        return False, "", f"Base URL 长度不能超过 {MAX_BASE_URL_LEN} 字符"
    if _CTRL_CHARS_RE.search(s) or any(ch.isspace() for ch in s):
        return False, "", "Base URL 包含非法空白或控制字符"

    try:
        parsed = urlsplit(s)
    except ValueError:
        return False, "", "Base URL 格式无效"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, "", "Base URL 仅允许 http:// 或 https:// 协议"
    if parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
        return False, "", "Base URL 禁止内嵌用户名或密码（user:pass@）"
    if parsed.query or parsed.fragment:
        return False, "", "Base URL 禁止包含查询参数或锚点"

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return False, "", "Base URL 缺少有效主机名"
    host_clean = hostname.rstrip(".")
    if not host_clean:
        return False, "", "Base URL 主机名无效"

    if host_clean in _BLOCKED_METADATA_HOSTS or host_clean.endswith(".metadata.google.internal"):
        return False, "", "安全策略禁止访问云元数据地址"

    try:
        port = parsed.port
    except ValueError:
        return False, "", "Base URL 端口无效"
    if port is not None and not (1 <= port <= 65535):
        return False, "", "Base URL 端口超出范围（1-65535）"

    # Reject obfuscated numeric IPv4 (octal/hex/mixed-radix/shorthand) before IP literal parsing
    if _looks_like_obfuscated_numeric_ip(host_clean):
        return False, "", "禁止使用非标准数字/十六进制/八进制 IP 地址"

    # IP literal validation (blocks metadata / link-local / 0.0.0.0; allows 127.0.0.1 / ::1)
    try:
        ip_obj = ipaddress.ip_address(host_clean)
    except ValueError:
        if ":" in host_clean:
            return False, "", "Base URL 包含无效 IPv6 地址"
    else:
        blocked, reason = _is_blocked_ip(ip_obj)
        if blocked:
            return False, "", reason

    clean_path = (parsed.path or "").rstrip("/")
    if ".." in clean_path.split("/"):
        return False, "", "Base URL 路径禁止包含 .."

    normalized = f"{scheme}://{parsed.netloc}{clean_path}"
    return True, normalized, ""


def _build_upstream_models_url(base_url: str) -> str:
    clean = (base_url or "").strip().rstrip("/")
    parsed = urlsplit(clean)
    if (parsed.path or "").strip("/"):
        return f"{clean}/models"
    return f"{clean}/v1/models"


def _model_matches_filters(
    model_id: str,
    include_patterns: Sequence[str] = (),
    exclude_patterns: Sequence[str] = (),
) -> bool:
    mid = (model_id or "").strip()
    if not mid:
        return False
    if include_patterns and not any(fnmatch.fnmatchcase(mid, pat) for pat in include_patterns):
        return False
    if exclude_patterns and any(fnmatch.fnmatchcase(mid, pat) for pat in exclude_patterns):
        return False
    return True


def _redact_probe_text(text: str, secret_values: Sequence[str] = (), max_len: int = 240) -> str:
    s = str(text or "")
    for sec in secret_values:
        tok = str(sec or "").strip()
        if len(tok) >= 4:
            s = s.replace(tok, "[REDACTED]")
    s = _BEARER_RE.sub(r"\1[REDACTED]", s)
    s = _SK_TOKEN_RE.sub("[REDACTED]", s)
    s = _HVS_TOKEN_RE.sub("[REDACTED]", s)
    s = _KV_SECRET_RE.sub(r"\1[REDACTED]", s)
    s = redact_secrets_only(s, max_len=max_len)
    return s.strip()


def _normalize_string_list(
    raw: Any,
    *,
    field_name: str,
    max_items: int,
) -> tuple[bool, list[str], str]:
    if raw is None:
        return True, [], ""
    if isinstance(raw, str):
        items = [x.strip() for x in re.split(r"[,\n]+", raw) if x.strip()]
    elif isinstance(raw, list):
        items = []
        for x in raw:
            if not isinstance(x, str):
                return False, [], f"{field_name} 元素必须为字符串"
            s = x.strip()
            if s:
                items.append(s)
    else:
        return False, [], f"{field_name} 必须为字符串数组"
    if len(items) > max_items:
        return False, [], f"{field_name} 数量不能超过 {max_items}"
    dedup: list[str] = []
    seen: set[str] = set()
    for item in items:
        if len(item) > 160 or _CTRL_CHARS_RE.search(item):
            return False, [], f"{field_name} 包含非法控制字符或超长项"
        if item not in seen:
            seen.add(item)
            dedup.append(item)
    return True, dedup, ""


def _validate_extra_headers_input(
    raw: Any,
    *,
    existing_headers: dict[str, str] | None = None,
) -> tuple[bool, dict[str, str], str]:
    if raw is None:
        return True, {}, ""
    pairs: list[tuple[str, str]] = []
    if isinstance(raw, dict):
        for k, v in raw.items():
            if not isinstance(k, str) or not isinstance(v, str):
                return False, {}, "extra_headers 键值必须为字符串"
            pairs.append((k, v))
    elif isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                return False, {}, "extra_headers 列表项必须为对象"
            k = item.get("key")
            v = item.get("value")
            if not isinstance(k, str) or not isinstance(v, str):
                return False, {}, "extra_headers 键值必须为字符串"
            pairs.append((k, v))
    else:
        return False, {}, "extra_headers 必须为对象或键值数组"

    if len(pairs) > MAX_EXTRA_HEADERS:
        return False, {}, f"extra_headers 数量不能超过 {MAX_EXTRA_HEADERS}"

    existing = existing_headers or {}
    existing_ci = {k.lower(): v for k, v in existing.items()}
    out: dict[str, str] = {}
    for raw_k, raw_v in pairs:
        k = raw_k.strip()
        v = raw_v.strip()
        if not k and not v:
            continue
        if not _HEADER_KEY_RE.fullmatch(k) or _CTRL_CHARS_RE.search(k):
            return False, {}, f"自定义请求头名称无效：{k[:32]}"
        if len(v) > 1024 or _CTRL_CHARS_RE.search(v):
            return False, {}, f"自定义请求头 {k} 值包含非法控制字符或超长"
        # Preserve existing sensitive header if client echoed back `[REDACTED]`
        if v == "[REDACTED]" and is_sensitive_header_key(k):
            prev = existing_ci.get(k.lower())
            if prev is not None:
                out[k] = prev
            continue
        out[k] = v
    return True, out, ""


def _parse_raw_gateways_list(data: Any) -> list[dict[str, Any]]:
    """Parse all 4 legacy/canonical `gateways.json` layouts while preserving unknown host fields."""
    if data is None:
        return []
    out: list[dict[str, Any]] = []
    if isinstance(data, dict) and isinstance(data.get("gateways"), list):
        for item in data["gateways"]:
            if isinstance(item, dict) and item.get("id"):
                out.append(dict(item))
        return out
    if isinstance(data, dict) and isinstance(data.get("gateways"), dict):
        for gid, item in data["gateways"].items():
            if isinstance(item, dict):
                cp = dict(item)
                cp.setdefault("id", str(gid))
                out.append(cp)
        return out
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("id"):
                out.append(dict(item))
        return out
    if isinstance(data, dict):
        if "base_url" in data or "id" in data:
            if data.get("id"):
                out.append(dict(data))
            return out
        for gid, item in data.items():
            if isinstance(item, dict):
                cp = dict(item)
                cp.setdefault("id", str(gid))
                out.append(cp)
        return out
    return out


def _is_readonly_cmd_entry(entry: dict[str, Any]) -> bool:
    cmd = entry.get("api_key_cmd")
    if cmd is None:
        return False
    if isinstance(cmd, str):
        return bool(cmd.strip())
    if isinstance(cmd, (list, tuple)):
        return any(str(x).strip() for x in cmd)
    return True


def _sanitize_secret_ref_summary(ref: Any) -> dict[str, Any] | None:
    """Return strictly non-secret, path-free metadata for UI display (zero host filesystem paths)."""
    if not isinstance(ref, dict):
        return None
    backend = str(ref.get("backend") or "").strip().lower()
    if backend == "openbao":
        return {
            "backend": "openbao",
            "kv_mount": str(ref.get("kv_mount") or ""),
            "path": str(ref.get("path") or ""),
            "version": ref.get("version") if isinstance(ref.get("version"), int) else None,
        }
    if backend == "local_0600":
        return {
            "backend": "local_0600",
            "slot": str(ref.get("slot") or ""),
        }
    if backend == "security_card":
        return {"backend": "security_card", "status": "reserved"}
    return None


def _sanitize_gateway_for_response(entry: dict[str, Any]) -> dict[str, Any]:
    """Build strictly sanitized gateway representation for GET/POST/PUT/PATCH responses."""
    gw_id = str(entry.get("id") or "").strip().lower()
    dialect = str(entry.get("dialect") or "openai_strict").strip().lower()
    if dialect not in _VALID_DIALECTS:
        dialect = "openai_strict"
    preset = _DIALECT_DEFAULTS[dialect]

    read_only_cmd = _is_readonly_cmd_entry(entry)
    api_key_env = str(entry.get("api_key_env") or "").strip()
    secret_ref = entry.get("secret_ref") if isinstance(entry.get("secret_ref"), dict) else None
    legacy_plain = str(entry.get("api_key") or "").strip()
    stored_hint = str(entry.get("api_key_hint") or "").strip()

    if read_only_cmd:
        credential_kind = "server_cmd_readonly"
        secret_backend = "host_cmd_readonly"
        has_api_key = True
        api_key_hint = "宿主机命令托管（只读）"
    elif secret_ref and str(secret_ref.get("backend") or "").strip().lower() in (
        "openbao",
        "local_0600",
        "security_card",
    ):
        credential_kind = "api_key"
        secret_backend = str(secret_ref.get("backend")).strip().lower()
        has_api_key = True
        api_key_hint = _mask_secret_hint(stored_hint) if stored_hint else "已托管加密"
    elif api_key_env:
        credential_kind = "api_key_env"
        secret_backend = "env"
        has_api_key = True
        api_key_hint = f"env:{api_key_env}"
    elif legacy_plain:
        credential_kind = "api_key"
        secret_backend = "legacy_plaintext"
        has_api_key = True
        api_key_hint = _mask_secret_hint(legacy_plain)
    else:
        credential_kind = "none"
        secret_backend = "none"
        has_api_key = False
        api_key_hint = ""

    raw_cap = entry.get("max_tokens_cap", preset["max_tokens_cap"])
    max_tokens_cap: int | None = None
    if isinstance(raw_cap, int) and not isinstance(raw_cap, bool) and raw_cap > 0:
        max_tokens_cap = raw_cap

    timeout_raw = entry.get("timeout_s", 300.0)
    try:
        timeout_s = max(5.0, min(1800.0, float(timeout_raw if timeout_raw is not None else 300.0)))
    except (TypeError, ValueError):
        timeout_s = 300.0

    def _str_list(val: Any) -> list[str]:
        if isinstance(val, list):
            return [str(x).strip() for x in val if str(x).strip()]
        if isinstance(val, str):
            return [x.strip() for x in val.split(",") if x.strip()]
        return []

    return {
        "id": gw_id,
        "name": str(entry.get("name") or gw_id).strip() or gw_id,
        "base_url": str(entry.get("base_url") or "").strip().rstrip("/"),
        "dialect": dialect,
        "enabled": bool(entry.get("enabled", True)),
        "credential_kind": credential_kind,
        "secret_backend": secret_backend,
        "has_api_key": has_api_key,
        "api_key_hint": api_key_hint,
        "api_key_env": api_key_env if not read_only_cmd else "",
        "read_only_cmd": read_only_cmd,
        "secret_ref_summary": _sanitize_secret_ref_summary(secret_ref) if not read_only_cmd else None,
        "include_models": _str_list(entry.get("include_models")),
        "exclude_models": _str_list(entry.get("exclude_models")),
        "models": _str_list(entry.get("models")),
        "supports_reasoning_effort": bool(
            entry.get("supports_reasoning_effort", preset["supports_reasoning_effort"])
        ),
        "effort_mode": str(entry.get("effort_mode") or preset["effort_mode"]),
        "flatten_system_content": bool(
            entry.get("flatten_system_content", preset["flatten_system_content"])
        ),
        "strip_stream_options": bool(
            entry.get("strip_stream_options", preset["strip_stream_options"])
        ),
        "max_tokens_field": str(entry.get("max_tokens_field") or preset["max_tokens_field"]),
        "max_tokens_cap": max_tokens_cap,
        "adaptive_400_fallback": bool(
            entry.get("adaptive_400_fallback", preset["adaptive_400_fallback"])
        ),
        "timeout_s": timeout_s,
        "extra_headers": sanitize_extra_headers_for_response(entry.get("extra_headers")),
        "updated_at": entry.get("updated_at") if isinstance(entry.get("updated_at"), (int, float)) else None,
    }


class GatewayService:
    """Manages `gateways.json` CRUD, SecretStore integration, and SSRF-safe `/probe`."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        secrets_config: SecretsConfigService,
        audit: StudioAuditLogger,
        *,
        gateways_path: Path | None = None,
        event_hub: Any | None = None,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.secrets_config = secrets_config
        self.audit = audit
        self.event_hub = event_hub
        env_gw = os.environ.get("AGY_TG_GATEWAYS_FILE", "").strip()
        default_gw = Path.home() / ".config" / "agy-tg-bridge" / "gateways.json"
        self.gateways_path = Path(gateways_path) if gateways_path else Path(env_gw or str(default_gw))

    # ---------------------------------------------------------------- Storage (`0700` / `0600` + `flock`)
    def _read_raw_entries(self) -> list[dict[str, Any]]:
        data = _read_regular_json_no_symlink(self.gateways_path, max_bytes=512 * 1024)
        if data is None:
            # Handle legacy JSON array root safely (still refusing symlinks)
            try:
                if self.gateways_path.is_symlink() or not self.gateways_path.exists():
                    return []
                flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
                fd = os.open(str(self.gateways_path), flags)
                try:
                    raw = os.read(fd, 512 * 1024 + 1)
                    if len(raw) > 512 * 1024:
                        return []
                    parsed = json.loads(raw.decode("utf-8"))
                    return _parse_raw_gateways_list(parsed)
                finally:
                    os.close(fd)
            except Exception:
                return []
        return _parse_raw_gateways_list(data)

    def _mutate_gateways_atomic(self, mutator: Any) -> Any:
        parent = _ensure_secure_parent_dir(self.gateways_path)
        if self.gateways_path.is_symlink():
            raise OSError("Refusing symlink gateways.json")

        lock_path = parent / f".{self.gateways_path.name}.lock"
        if lock_path.is_symlink():
            raise OSError("Refusing symlink gateways lock file")

        lock_flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            lock_flags |= os.O_NOFOLLOW
        lock_fd = os.open(str(lock_path), lock_flags, 0o600)
        try:
            try:
                os.chmod(lock_path, 0o600)
            except OSError:
                pass
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                if self.gateways_path.is_symlink():
                    raise OSError("Refusing to overwrite symlink gateways.json")
                entries = self._read_raw_entries()
                result = mutator(entries)
                doc = {
                    "version": 1,
                    "updated_at": int(time.time()),
                    "gateways": entries,
                }
                serialized = (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
                fd, tmp_name = tempfile.mkstemp(
                    prefix=f".{self.gateways_path.name}.tmp.",
                    dir=str(parent),
                )
                try:
                    os.fchmod(fd, 0o600)
                    os.write(fd, serialized)
                    os.fsync(fd)
                except Exception:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    try:
                        os.unlink(tmp_name)
                    except OSError:
                        pass
                    raise
                os.close(fd)
                os.replace(tmp_name, str(self.gateways_path))
                try:
                    os.chmod(self.gateways_path, 0o600)
                except OSError:
                    pass
                return result
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    # ---------------------------------------------------------------- 4-Layer Write Gate + Sec-Fetch-Site
    async def _enforce_write_gate(
        self,
        request: web.Request,
        *,
        action: str,
        target_id: str = "gateways",
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        client_ip = self.auth_mgr.extract_client_ip(request)

        # Gate 1a: Strict Same-Origin
        ok_orig, err_orig = self.auth_mgr.check_same_origin(request, require_origin=True)
        if not ok_orig:
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_origin",
                client_ip=client_ip,
                target_id=target_id,
            )
            return False, None, studio_auth_error(err_orig, status=403)

        # Gate 1b: Sec-Fetch-Site validation when header is sent by browser / client
        sfs = (request.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sfs and sfs not in ("same-origin", "none"):
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_sec_fetch_site",
                client_ip=client_ip,
                target_id=target_id,
            )
            return False, None, studio_auth_error(
                "Sec-Fetch-Site 跨站写请求已拦截",
                status=403,
            )

        # Gate 2: Non-simple Content-Type
        media_type = _extract_media_type(request)
        if media_type != "application/json":
            self.audit.record(
                action=action,
                status_code=415,
                outcome="denied_content_type",
                client_ip=client_ip,
                target_id=target_id,
            )
            return False, None, studio_auth_error(
                "写接口仅接受 Content-Type: application/json",
                status=415,
            )

        # Gate 3: Authenticated session + live RBAC + must_change_password=False
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            self.audit.record(
                action=action,
                status_code=status_code,
                outcome="denied_auth",
                client_ip=client_ip,
                target_id=target_id,
            )
            return False, None, studio_auth_error(err_auth, status=status_code)

        # Gate 4a: CSRF token verification
        ok_csrf, err_csrf = self.auth_mgr.check_csrf(request, sess)
        if not ok_csrf:
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_csrf",
                client_ip=client_ip,
                target_id=target_id,
                sess=sess,
            )
            return False, None, studio_auth_error(err_csrf, status=403)

        # Gate 4b: Live RBAC admin role
        if sess.get("role") != "admin":
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_rbac",
                client_ip=client_ip,
                target_id=target_id,
                sess=sess,
            )
            return False, None, studio_auth_error(
                "只读权限（readonly）禁止修改或探测外部模型中转站",
                status=403,
            )

        return True, sess, None

    # ---------------------------------------------------------------- Validation Helpers
    def _check_body_whitelist(
        self,
        body: dict[str, Any],
        *,
        allowed_fields: frozenset[str],
    ) -> tuple[bool, str]:
        for k in body.keys():
            if k in _FORBIDDEN_CLIENT_FIELDS:
                if k == "api_key_cmd":
                    return False, "安全策略禁止通过 Web API 注入或修改 api_key_cmd 字段"
                if k == "api_key_file":
                    return False, "安全策略禁止通过 Web API 指定宿主机 api_key_file 路径"
                if k == "secret_ref":
                    return False, "禁止客户端直接伪造 secret_ref 字段"
                return False, f"安全策略禁止传入危险字段：{k}"
            if k not in allowed_fields:
                return False, f"包含未允许的请求字段：{str(k)[:48]}"
        return True, ""

    def _validate_mutation_fields(
        self,
        body: dict[str, Any],
        *,
        is_create: bool,
        existing: dict[str, Any] | None = None,
    ) -> tuple[bool, dict[str, Any], str]:
        base = dict(existing or {})

        # Name
        if is_create or "name" in body:
            raw_name = body.get("name", base.get("name", ""))
            if not isinstance(raw_name, str) or not raw_name.strip():
                return False, {}, "显示名称不能为空"
            name = raw_name.strip()
            if len(name) > 80 or _CTRL_CHARS_RE.search(name):
                return False, {}, "显示名称包含非法控制字符或超过 80 字符"
        else:
            name = str(base.get("name") or base.get("id") or "").strip()

        # Base URL
        if is_create or "base_url" in body:
            ok_u, norm_url, err_u = validate_gateway_base_url(body.get("base_url"))
            if not ok_u:
                return False, {}, err_u
        else:
            ok_u, norm_url, err_u = validate_gateway_base_url(base.get("base_url"))
            if not ok_u:
                return False, {}, err_u

        # Dialect
        raw_dialect = body.get("dialect", base.get("dialect", "openai_strict"))
        if not isinstance(raw_dialect, str) or raw_dialect.strip().lower() not in _VALID_DIALECTS:
            return False, {}, "不支持的方言预设（dialect）"
        dialect = raw_dialect.strip().lower()
        preset = _DIALECT_DEFAULTS[dialect]

        # Enabled
        raw_enabled = body.get("enabled", base.get("enabled", True))
        if not isinstance(raw_enabled, bool):
            return False, {}, "enabled 必须为布尔值"
        enabled = raw_enabled

        # Model lists
        ok_inc, inc_models, err_inc = _normalize_string_list(
            body.get("include_models", base.get("include_models")),
            field_name="include_models",
            max_items=MAX_PATTERNS_PER_LIST,
        )
        if not ok_inc:
            return False, {}, err_inc

        ok_exc, exc_models, err_exc = _normalize_string_list(
            body.get("exclude_models", base.get("exclude_models")),
            field_name="exclude_models",
            max_items=MAX_PATTERNS_PER_LIST,
        )
        if not ok_exc:
            return False, {}, err_exc

        ok_mod, static_models, err_mod = _normalize_string_list(
            body.get("models", base.get("models")),
            field_name="models",
            max_items=MAX_STATIC_MODELS,
        )
        if not ok_mod:
            return False, {}, err_mod

        # Protocol options
        def _bool_opt(key: str, default_val: bool) -> tuple[bool, bool, str]:
            val = body.get(key, base.get(key, default_val))
            if not isinstance(val, bool):
                return False, default_val, f"{key} 必须为布尔值"
            return True, val, ""

        ok_b, supports_effort, err_b = _bool_opt(
            "supports_reasoning_effort", preset["supports_reasoning_effort"]
        )
        if not ok_b:
            return False, {}, err_b
        ok_b, flatten_sys, err_b = _bool_opt(
            "flatten_system_content", preset["flatten_system_content"]
        )
        if not ok_b:
            return False, {}, err_b
        ok_b, strip_stream, err_b = _bool_opt(
            "strip_stream_options", preset["strip_stream_options"]
        )
        if not ok_b:
            return False, {}, err_b
        ok_b, adaptive_400, err_b = _bool_opt(
            "adaptive_400_fallback", preset["adaptive_400_fallback"]
        )
        if not ok_b:
            return False, {}, err_b

        effort_mode = str(body.get("effort_mode", base.get("effort_mode", preset["effort_mode"]))).strip().lower()
        if effort_mode not in _VALID_EFFORT_MODES:
            return False, {}, "effort_mode 仅限 body / model_paren / none"

        max_tokens_field = str(
            body.get("max_tokens_field", base.get("max_tokens_field", preset["max_tokens_field"]))
        ).strip()
        if max_tokens_field not in _VALID_MAX_TOKENS_FIELDS:
            return False, {}, "max_tokens_field 仅限 max_completion_tokens / max_tokens / omit"

        raw_cap = body.get("max_tokens_cap", base.get("max_tokens_cap", preset["max_tokens_cap"]))
        max_tokens_cap: int | None
        if raw_cap in (None, "", 0):
            max_tokens_cap = None
        elif isinstance(raw_cap, int) and not isinstance(raw_cap, bool) and 1 <= raw_cap <= 2_000_000:
            max_tokens_cap = raw_cap
        else:
            return False, {}, "max_tokens_cap 须为空（不限）或正整数"

        raw_timeout = body.get("timeout_s", base.get("timeout_s", 300.0))
        if isinstance(raw_timeout, bool) or not isinstance(raw_timeout, (int, float)):
            return False, {}, "timeout_s 必须为数字"
        timeout_s = float(raw_timeout)
        if not (5.0 <= timeout_s <= 1800.0):
            return False, {}, "timeout_s 须在 5 ~ 1800 秒之间"

        # Extra headers
        if "extra_headers" in body:
            ok_h, extra_headers, err_h = _validate_extra_headers_input(
                body.get("extra_headers"),
                existing_headers=base.get("extra_headers")
                if isinstance(base.get("extra_headers"), dict)
                else {},
            )
            if not ok_h:
                return False, {}, err_h
        else:
            extra_headers = (
                dict(base.get("extra_headers"))
                if isinstance(base.get("extra_headers"), dict)
                else {}
            )

        # Credential mode & inputs
        raw_cred_kind = body.get("credential_kind")
        if raw_cred_kind is not None:
            if not isinstance(raw_cred_kind, str) or raw_cred_kind.strip().lower() not in _VALID_CREDENTIAL_MODES:
                return False, {}, "credential_kind 仅限 api_key / api_key_env / none"
            cred_kind = raw_cred_kind.strip().lower()
        elif "api_key" in body and body.get("api_key"):
            cred_kind = "api_key"
        elif "api_key_env" in body and body.get("api_key_env"):
            cred_kind = "api_key_env"
        elif base.get("secret_ref") or base.get("api_key"):
            cred_kind = "api_key"
        elif base.get("api_key_env"):
            cred_kind = "api_key_env"
        else:
            cred_kind = "none"

        raw_api_key = body.get("api_key")
        new_api_key = ""
        if raw_api_key is not None:
            if not isinstance(raw_api_key, str):
                return False, {}, "api_key 必须为字符串"
            new_api_key = raw_api_key.strip()
            if len(new_api_key) > 1024 or _CTRL_CHARS_RE.search(new_api_key):
                return False, {}, "api_key 包含非法控制字符或超过长度限制"

        api_key_env = ""
        if cred_kind == "api_key_env":
            raw_env = body.get("api_key_env", base.get("api_key_env", ""))
            if not isinstance(raw_env, str) or not _ENV_NAME_RE.fullmatch(raw_env.strip()):
                return False, {}, "环境变量名（api_key_env）须匹配 ^[A-Z_][A-Z0-9_]{0,63}$"
            api_key_env = raw_env.strip()

        preferred_backend = body.get("preferred_secret_backend")
        if preferred_backend is not None:
            if not isinstance(preferred_backend, str) or preferred_backend.strip().lower() not in (
                "",
                "openbao",
                "local_0600",
                "security_card",
            ):
                return False, {}, "不支持的密钥托管后端"
            preferred_backend = preferred_backend.strip().lower() or None

        return (
            True,
            {
                "name": name,
                "base_url": norm_url,
                "dialect": dialect,
                "enabled": enabled,
                "include_models": inc_models,
                "exclude_models": exc_models,
                "models": static_models,
                "supports_reasoning_effort": supports_effort,
                "effort_mode": effort_mode,
                "flatten_system_content": flatten_sys,
                "strip_stream_options": strip_stream,
                "max_tokens_field": max_tokens_field,
                "max_tokens_cap": max_tokens_cap,
                "adaptive_400_fallback": adaptive_400,
                "timeout_s": timeout_s,
                "extra_headers": extra_headers,
                "credential_kind": cred_kind,
                "new_api_key": new_api_key,
                "api_key_env": api_key_env,
                "clear_api_key": bool(body.get("clear_api_key", False)),
                "preferred_secret_backend": preferred_backend,
            },
            "",
        )

    async def _dns_check_for_probe(self, base_url: str) -> tuple[bool, str, list[dict[str, Any]]]:
        """Resolve and validate target IPs prior to probing; return pinned records to stop TOCTOU."""
        parsed = urlsplit(base_url)
        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
        if not hostname:
            return False, "无效的目标主机名", []
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        numeric_flags = socket.AI_NUMERICHOST | socket.AI_NUMERICSERV

        if hostname == "localhost":
            return (
                True,
                "",
                [
                    {
                        "hostname": hostname,
                        "host": "127.0.0.1",
                        "port": port,
                        "family": socket.AF_INET,
                        "proto": socket.IPPROTO_TCP,
                        "flags": numeric_flags,
                    },
                    {
                        "hostname": hostname,
                        "host": "::1",
                        "port": port,
                        "family": socket.AF_INET6,
                        "proto": socket.IPPROTO_TCP,
                        "flags": numeric_flags,
                    },
                ],
            )

        if _looks_like_obfuscated_numeric_ip(hostname):
            return False, "禁止使用非标准数字/十六进制/八进制 IP 地址", []

        try:
            ip_obj = ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            blocked, reason = _is_blocked_ip(ip_obj)
            if blocked:
                return False, reason, []
            family = socket.AF_INET6 if isinstance(ip_obj, ipaddress.IPv6Address) else socket.AF_INET
            return (
                True,
                "",
                [
                    {
                        "hostname": hostname,
                        "host": ip_obj.compressed,
                        "port": port,
                        "family": family,
                        "proto": socket.IPPROTO_TCP,
                        "flags": numeric_flags,
                    }
                ],
            )

        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM),
                timeout=2.5,
            )
        except TimeoutError:
            return False, "上游域名 DNS 解析超时", []
        except OSError:
            return False, "上游域名 DNS 解析失败", []

        if not infos:
            return False, "上游域名未返回有效 IP 地址", []

        records: list[dict[str, Any]] = []
        seen: set[tuple[int, str, int]] = set()
        for family, _stype, proto, _canon, sockaddr in infos:
            if family not in (socket.AF_INET, socket.AF_INET6):
                continue
            raw_ip = str(sockaddr[0])
            ip_for_check = raw_ip.split("%", 1)[0]
            try:
                ip_obj = ipaddress.ip_address(ip_for_check)
            except ValueError:
                continue
            blocked, reason = _is_blocked_ip(ip_obj)
            if blocked:
                return False, f"DNS 解析结果被安全策略拦截：{reason}", []
            resolved_port = int(sockaddr[1]) if len(sockaddr) >= 2 and sockaddr[1] else port
            key = (int(family), ip_obj.compressed, resolved_port)
            if key in seen:
                continue
            seen.add(key)
            records.append(
                {
                    "hostname": hostname,
                    "host": ip_obj.compressed,
                    "port": resolved_port,
                    "family": int(family),
                    "proto": int(proto or socket.IPPROTO_TCP),
                    "flags": numeric_flags,
                }
            )

        if not records:
            return False, "上游域名未返回有效 IP 地址", []
        return True, "", records

    # ---------------------------------------------------------------- Handlers
    async def handle_list_gateways(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        is_admin = sess.get("role") == "admin"
        raw_entries = self._read_raw_entries()
        items = [_sanitize_gateway_for_response(e) for e in raw_entries]
        return web.json_response(
            {
                "ok": True,
                "can_edit": is_admin,
                "total": len(items),
                "gateways": items,
                "secret_store": self.secrets_config.secret_store.describe_status(),
            }
        )

    async def handle_create_gateway(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request,
            action="gateways.create",
        )
        if not ok_gate or not sess:
            return err_resp or studio_auth_error("写操作被拒绝", status=403)

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_status, body_outcome, body_err = await _read_bounded_json_body(
            request,
            allow_empty=False,
        )
        if not ok_body or body is None:
            self.audit.record(
                action="gateways.create",
                status_code=body_status,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id="gateways",
                sess=sess,
            )
            return studio_auth_error(body_err, status=body_status)

        ok_wl, err_wl = self._check_body_whitelist(body, allowed_fields=_ALLOWED_MUTATION_FIELDS)
        if not ok_wl:
            self.audit.record(
                action="gateways.create",
                status_code=400,
                outcome="denied_forbidden_field",
                client_ip=client_ip,
                target_id="gateways",
                sess=sess,
            )
            return web.json_response({"ok": False, "source": "studio_api", "error": err_wl}, status=400)

        ok_id, gw_id, err_id = _validate_gateway_secret_id(body.get("id"))
        if not ok_id:
            self.audit.record(
                action="gateways.create",
                status_code=400,
                outcome="denied_invalid_id",
                client_ip=client_ip,
                target_id="gateways",
                sess=sess,
            )
            return web.json_response({"ok": False, "source": "studio_api", "error": err_id}, status=400)

        ok_v, parsed, err_v = self._validate_mutation_fields(body, is_create=True)
        if not ok_v:
            self.audit.record(
                action="gateways.create",
                status_code=400,
                outcome="denied_validation",
                client_ip=client_ip,
                target_id=gw_id,
                sess=sess,
            )
            return web.json_response({"ok": False, "source": "studio_api", "error": err_v}, status=400)

        # Pre-check duplicates & capacity before storing secret
        existing_entries = self._read_raw_entries()
        if any(str(e.get("id") or "").strip().lower() == gw_id for e in existing_entries):
            self.audit.record(
                action="gateways.create",
                status_code=409,
                outcome="denied_duplicate",
                client_ip=client_ip,
                target_id=gw_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"站点 ID「{gw_id}」已存在"},
                status=409,
            )
        if len(existing_entries) >= MAX_GATEWAYS_COUNT:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"外部中转站数量已达上限（{MAX_GATEWAYS_COUNT}）"},
                status=400,
            )

        secret_ref: dict[str, Any] | None = None
        secret_backend = "none"
        fallback_used = False
        api_key_hint = ""
        if parsed["credential_kind"] == "api_key":
            if not parsed["new_api_key"]:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "请输入 API Key，或切换为环境变量模式"},
                    status=400,
                )
            try:
                secret_ref, secret_backend, fallback_used = (
                    await self.secrets_config.secret_store.store_gateway_secret(
                        gw_id,
                        parsed["new_api_key"],
                        preferred_backend=parsed["preferred_secret_backend"],
                    )
                )
                api_key_hint = _mask_secret_hint(parsed["new_api_key"])
            except ValueError as exc:
                return web.json_response({"ok": False, "source": "studio_api", "error": str(exc)}, status=400)
            except OSError as exc:
                log.warning("SecretStore write failed for gateway %s: %s", gw_id, type(exc).__name__)
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "密钥存储失败（文件权限或符号链接受限）"},
                    status=500,
                )

        now_ts = int(time.time())
        new_entry = self._build_persisted_entry(
            gw_id=gw_id,
            parsed=parsed,
            secret_ref=secret_ref,
            api_key_hint=api_key_hint,
            now_ts=now_ts,
        )

        class _DuplicateError(Exception):
            pass

        def _insert(entries: list[dict[str, Any]]) -> dict[str, Any]:
            if any(str(e.get("id") or "").strip().lower() == gw_id for e in entries):
                raise _DuplicateError()
            entries.append(new_entry)
            return new_entry

        try:
            saved = self._mutate_gateways_atomic(_insert)
        except _DuplicateError:
            if secret_ref:
                await self.secrets_config.secret_store.delete_gateway_secret(secret_ref)
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"站点 ID「{gw_id}」已存在"},
                status=409,
            )
        except OSError as exc:
            if secret_ref:
                await self.secrets_config.secret_store.delete_gateway_secret(secret_ref)
            log.warning("Failed to persist gateways.json on create: %s", type(exc).__name__)
            self.audit.record(
                action="gateways.create",
                status_code=500,
                outcome="io_error",
                client_ip=client_ip,
                target_id=gw_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "写入 gateways.json 失败（权限或路径受限）"},
                status=500,
            )

        self.audit.record(
            action="gateways.create",
            status_code=201,
            outcome=f"ok_{secret_backend}",
            client_ip=client_ip,
            target_id=gw_id,
            sess=sess,
        )
        if self.event_hub is not None:
            self.event_hub.publish(
                "gateways_updated",
                {"gateway_id": gw_id, "action": "created", "source": "studio"},
            )
        return web.json_response(
            {
                "ok": True,
                "gateway": _sanitize_gateway_for_response(saved),
                "secret_backend": secret_backend,
                "fallback_used": fallback_used,
            },
            status=201,
        )

    async def handle_update_gateway(self, request: web.Request) -> web.Response:
        return await self._handle_upsert_existing(request, partial=(request.method == "PATCH"))

    async def _handle_upsert_existing(self, request: web.Request, *, partial: bool) -> web.Response:
        raw_id = request.match_info.get("gateway_id", "")
        action = "gateways.patch" if partial else "gateways.update"
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request,
            action=action,
            target_id=raw_id or "gateways",
        )
        if not ok_gate or not sess:
            return err_resp or studio_auth_error("写操作被拒绝", status=403)

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_id, gw_id, err_id = _validate_gateway_secret_id(raw_id)
        if not ok_id:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_invalid_id",
                client_ip=client_ip,
                target_id=str(raw_id)[:64],
                sess=sess,
            )
            return web.json_response({"ok": False, "source": "studio_api", "error": err_id}, status=400)

        ok_body, body, body_status, body_outcome, body_err = await _read_bounded_json_body(
            request,
            allow_empty=False,
        )
        if not ok_body or body is None:
            self.audit.record(
                action=action,
                status_code=body_status,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=gw_id,
                sess=sess,
            )
            return studio_auth_error(body_err, status=body_status)

        ok_wl, err_wl = self._check_body_whitelist(body, allowed_fields=_ALLOWED_MUTATION_FIELDS)
        if not ok_wl:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_forbidden_field",
                client_ip=client_ip,
                target_id=gw_id,
                sess=sess,
            )
            return web.json_response({"ok": False, "source": "studio_api", "error": err_wl}, status=400)

        if "id" in body and body.get("id") != gw_id:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "编辑网关时不可修改站点 ID"},
                status=400,
            )

        existing_entries = self._read_raw_entries()
        existing = next(
            (e for e in existing_entries if str(e.get("id") or "").strip().lower() == gw_id),
            None,
        )
        if existing is None:
            self.audit.record(
                action=action,
                status_code=404,
                outcome="not_found",
                client_ip=client_ip,
                target_id=gw_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"中转站「{gw_id}」不存在"},
                status=404,
            )

        if _is_readonly_cmd_entry(existing):
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_readonly_cmd",
                client_ip=client_ip,
                target_id=gw_id,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": "安全策略禁止通过 Web API 修改或覆盖含宿主机 api_key_cmd 的只读网关",
                },
                status=403,
            )

        ok_v, parsed, err_v = self._validate_mutation_fields(
            body,
            is_create=(not partial),
            existing=existing,
        )
        if not ok_v:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_validation",
                client_ip=client_ip,
                target_id=gw_id,
                sess=sess,
            )
            return web.json_response({"ok": False, "source": "studio_api", "error": err_v}, status=400)

        old_ref = existing.get("secret_ref") if isinstance(existing.get("secret_ref"), dict) else None
        secret_ref = dict(old_ref) if old_ref else None
        api_key_hint = str(existing.get("api_key_hint") or "").strip()
        secret_backend = str((secret_ref or {}).get("backend") or ("env" if parsed["credential_kind"] == "api_key_env" else "none"))
        fallback_used = False
        ref_to_delete_after: dict[str, Any] | None = None

        if parsed["credential_kind"] == "api_key":
            if parsed["clear_api_key"]:
                ref_to_delete_after = old_ref
                secret_ref = None
                api_key_hint = ""
                secret_backend = "none"
            elif parsed["new_api_key"]:
                try:
                    new_ref, secret_backend, fallback_used = (
                        await self.secrets_config.secret_store.store_gateway_secret(
                            gw_id,
                            parsed["new_api_key"],
                            preferred_backend=parsed["preferred_secret_backend"],
                        )
                    )
                    if old_ref and old_ref.get("backend") != new_ref.get("backend"):
                        ref_to_delete_after = old_ref
                    secret_ref = new_ref
                    api_key_hint = _mask_secret_hint(parsed["new_api_key"])
                except ValueError as exc:
                    return web.json_response({"ok": False, "source": "studio_api", "error": str(exc)}, status=400)
                except OSError as exc:
                    log.warning("SecretStore update failed for gateway %s: %s", gw_id, type(exc).__name__)
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "密钥存储失败（文件权限或符号链接受限）"},
                        status=500,
                    )
            elif not secret_ref and str(existing.get("api_key") or "").strip():
                # Migrate legacy plaintext api_key out of gateways.json into SecretStore
                legacy_key = str(existing.get("api_key") or "").strip()
                try:
                    new_ref, secret_backend, fallback_used = (
                        await self.secrets_config.secret_store.store_gateway_secret(
                            gw_id,
                            legacy_key,
                            preferred_backend=parsed["preferred_secret_backend"],
                        )
                    )
                    secret_ref = new_ref
                    api_key_hint = _mask_secret_hint(legacy_key)
                except Exception as exc:
                    log.warning("Legacy key migration failed for %s: %s", gw_id, type(exc).__name__)
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "旧版密钥迁移至 SecretStore 失败"},
                        status=500,
                    )
            elif not secret_ref:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "请输入 API Key，或切换为环境变量模式"},
                    status=400,
                )
        else:
            # Switched to api_key_env or none -> schedule cleanup of old managed secret
            if old_ref:
                ref_to_delete_after = old_ref
            secret_ref = None
            api_key_hint = ""
            secret_backend = "env" if parsed["credential_kind"] == "api_key_env" else "none"

        now_ts = int(time.time())
        updated_entry = self._build_persisted_entry(
            gw_id=gw_id,
            parsed=parsed,
            secret_ref=secret_ref,
            api_key_hint=api_key_hint,
            now_ts=now_ts,
        )

        class _NotFoundError(Exception):
            pass

        class _ReadOnlyCmdRace(Exception):
            pass

        def _replace(entries: list[dict[str, Any]]) -> dict[str, Any]:
            for idx, item in enumerate(entries):
                if str(item.get("id") or "").strip().lower() == gw_id:
                    if _is_readonly_cmd_entry(item):
                        raise _ReadOnlyCmdRace()
                    entries[idx] = updated_entry
                    return updated_entry
            raise _NotFoundError()

        try:
            saved = self._mutate_gateways_atomic(_replace)
        except _ReadOnlyCmdRace:
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": "安全策略禁止通过 Web API 修改或覆盖含宿主机 api_key_cmd 的只读网关",
                },
                status=403,
            )
        except _NotFoundError:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"中转站「{gw_id}」不存在"},
                status=404,
            )
        except OSError as exc:
            log.warning("Failed to persist gateways.json on update: %s", type(exc).__name__)
            self.audit.record(
                action=action,
                status_code=500,
                outcome="io_error",
                client_ip=client_ip,
                target_id=gw_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "写入 gateways.json 失败（权限或路径受限）"},
                status=500,
            )

        if ref_to_delete_after:
            await self.secrets_config.secret_store.delete_gateway_secret(ref_to_delete_after)

        self.audit.record(
            action=action,
            status_code=200,
            outcome=f"ok_{secret_backend}",
            client_ip=client_ip,
            target_id=gw_id,
            sess=sess,
        )
        if self.event_hub is not None:
            self.event_hub.publish(
                "gateways_updated",
                {"gateway_id": gw_id, "action": "updated", "source": "studio"},
            )
        return web.json_response(
            {
                "ok": True,
                "gateway": _sanitize_gateway_for_response(saved),
                "secret_backend": secret_backend,
                "fallback_used": fallback_used,
            }
        )

    async def handle_delete_gateway(self, request: web.Request) -> web.Response:
        raw_id = request.match_info.get("gateway_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request,
            action="gateways.delete",
            target_id=raw_id or "gateways",
        )
        if not ok_gate or not sess:
            return err_resp or studio_auth_error("删除操作被拒绝", status=403)

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_id, gw_id, err_id = _validate_gateway_secret_id(raw_id)
        if not ok_id:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_id}, status=400)

        class _NotFoundError(Exception):
            pass

        class _ReadOnlyCmdRace(Exception):
            pass

        def _remove(entries: list[dict[str, Any]]) -> dict[str, Any]:
            for idx, item in enumerate(entries):
                if str(item.get("id") or "").strip().lower() == gw_id:
                    if _is_readonly_cmd_entry(item):
                        raise _ReadOnlyCmdRace()
                    return entries.pop(idx)
            raise _NotFoundError()

        try:
            removed = self._mutate_gateways_atomic(_remove)
        except _ReadOnlyCmdRace:
            self.audit.record(
                action="gateways.delete",
                status_code=403,
                outcome="denied_readonly_cmd",
                client_ip=client_ip,
                target_id=gw_id,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": "安全策略禁止通过 Web API 删除含宿主机 api_key_cmd 的只读网关",
                },
                status=403,
            )
        except _NotFoundError:
            self.audit.record(
                action="gateways.delete",
                status_code=404,
                outcome="not_found",
                client_ip=client_ip,
                target_id=gw_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"中转站「{gw_id}」不存在"},
                status=404,
            )
        except OSError as exc:
            log.warning("Failed to delete gateway %s: %s", gw_id, type(exc).__name__)
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "更新 gateways.json 失败"},
                status=500,
            )

        old_ref = removed.get("secret_ref") if isinstance(removed.get("secret_ref"), dict) else None
        secret_deleted = False
        if old_ref:
            secret_deleted = await self.secrets_config.secret_store.delete_gateway_secret(old_ref)

        self.audit.record(
            action="gateways.delete",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=gw_id,
            sess=sess,
        )
        if self.event_hub is not None:
            self.event_hub.publish(
                "gateways_updated",
                {"gateway_id": gw_id, "action": "deleted", "source": "studio"},
            )
        return web.json_response(
            {
                "ok": True,
                "deleted": True,
                "id": gw_id,
                "secret_deleted": secret_deleted,
            }
        )

    async def handle_probe_gateway(self, request: web.Request) -> web.Response:
        route_gw_id = request.match_info.get("gateway_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request,
            action="gateways.probe",
            target_id=route_gw_id or "probe",
        )
        if not ok_gate or not sess:
            return err_resp or studio_auth_error("探测请求被拒绝", status=403)

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_status, body_outcome, body_err = await _read_bounded_json_body(
            request,
            allow_empty=bool(route_gw_id),
        )
        if not ok_body or body is None:
            self.audit.record(
                action="gateways.probe",
                status_code=body_status,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=route_gw_id or "probe",
                sess=sess,
            )
            return studio_auth_error(body_err, status=body_status)

        ok_wl, err_wl = self._check_body_whitelist(body, allowed_fields=_ALLOWED_PROBE_FIELDS)
        if not ok_wl:
            self.audit.record(
                action="gateways.probe",
                status_code=400,
                outcome="denied_forbidden_field",
                client_ip=client_ip,
                target_id=route_gw_id or "probe",
                sess=sess,
            )
            return web.json_response({"ok": False, "source": "studio_api", "error": err_wl}, status=400)

        target_id = route_gw_id or str(body.get("gateway_id") or body.get("id") or "").strip()
        existing: dict[str, Any] | None = None
        if target_id:
            ok_id, norm_id, err_id = _validate_gateway_secret_id(target_id)
            if not ok_id:
                return web.json_response({"ok": False, "source": "studio_api", "error": err_id}, status=400)
            target_id = norm_id
            existing = next(
                (e for e in self._read_raw_entries() if str(e.get("id") or "").strip().lower() == target_id),
                None,
            )
            if route_gw_id and existing is None:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"中转站「{target_id}」不存在"},
                    status=404,
                )

        if existing is not None and _is_readonly_cmd_entry(existing) and not body.get("api_key"):
            self.audit.record(
                action="gateways.probe",
                status_code=403,
                outcome="denied_readonly_cmd_probe",
                client_ip=client_ip,
                target_id=target_id,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": "该网关使用宿主机 api_key_cmd 凭证（只读），Web 探测禁止执行宿主机命令",
                },
                status=403,
            )

        raw_url = body.get("base_url") if body.get("base_url") is not None else (existing or {}).get("base_url")
        ok_u, norm_url, err_u = validate_gateway_base_url(raw_url)
        if not ok_u:
            self.audit.record(
                action="gateways.probe",
                status_code=400,
                outcome="denied_ssrf_url",
                client_ip=client_ip,
                target_id=target_id or "probe",
                sess=sess,
            )
            return web.json_response({"ok": False, "source": "studio_api", "error": err_u}, status=400)

        same_origin_as_existing = (
            existing is not None and _is_same_origin_url(norm_url, existing.get("base_url"))
        )

        if existing is not None and _is_readonly_cmd_entry(existing) and not same_origin_as_existing:
            self.audit.record(
                action="gateways.probe",
                status_code=403,
                outcome="denied_readonly_cmd_cross_origin_probe",
                client_ip=client_ip,
                target_id=target_id,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": "该网关使用宿主机 api_key_cmd 凭证（只读），禁止跨源探测",
                },
                status=403,
            )

        ok_dns, err_dns, dns_records = await self._dns_check_for_probe(norm_url)
        if not ok_dns:
            self.audit.record(
                action="gateways.probe",
                status_code=400,
                outcome="denied_ssrf_dns",
                client_ip=client_ip,
                target_id=target_id or "probe",
                sess=sess,
            )
            return web.json_response({"ok": False, "source": "studio_api", "error": err_dns}, status=400)

        ok_inc, inc_models, err_inc = _normalize_string_list(
            body.get("include_models", (existing or {}).get("include_models")),
            field_name="include_models",
            max_items=MAX_PATTERNS_PER_LIST,
        )
        if not ok_inc:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_inc}, status=400)

        ok_exc, exc_models, err_exc = _normalize_string_list(
            body.get("exclude_models", (existing or {}).get("exclude_models")),
            field_name="exclude_models",
            max_items=MAX_PATTERNS_PER_LIST,
        )
        if not ok_exc:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_exc}, status=400)

        ok_mod, static_models, err_mod = _normalize_string_list(
            body.get("models", (existing or {}).get("models")),
            field_name="models",
            max_items=MAX_STATIC_MODELS,
        )
        if not ok_mod:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_mod}, status=400)

        # Only inherit or backfill `[REDACTED]` extra_headers when probing the exact same origin
        raw_extra_headers = (
            body.get("extra_headers")
            if "extra_headers" in body
            else ((existing or {}).get("extra_headers") if same_origin_as_existing else None)
        )
        inherited_existing_headers = (
            (existing or {}).get("extra_headers")
            if same_origin_as_existing and isinstance((existing or {}).get("extra_headers"), dict)
            else {}
        )
        ok_h, extra_headers, err_h = _validate_extra_headers_input(
            raw_extra_headers,
            existing_headers=inherited_existing_headers,
        )
        if not ok_h:
            return web.json_response({"ok": False, "source": "studio_api", "error": err_h}, status=400)

        # Resolve API key for probe (never logged or echoed; NEVER inherit across origins)
        probe_api_key = ""
        cred_kind = str(body.get("credential_kind") or "").strip().lower()
        if isinstance(body.get("api_key"), str) and body["api_key"].strip():
            probe_api_key = body["api_key"].strip()
        elif cred_kind == "api_key_env" or (
            isinstance(body.get("api_key_env"), str) and body["api_key_env"].strip()
        ):
            env_name = str(
                body.get("api_key_env")
                or ((existing or {}).get("api_key_env") if same_origin_as_existing else "")
                or ""
            ).strip()
            if env_name and not _ENV_NAME_RE.fullmatch(env_name):
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "无效的环境变量名（api_key_env）"},
                    status=400,
                )
            if env_name:
                probe_api_key = os.environ.get(env_name, "").strip()
        elif existing is not None and same_origin_as_existing and cred_kind != "none":
            if isinstance(existing.get("secret_ref"), dict):
                probe_api_key = await self.secrets_config.secret_store.resolve_gateway_secret(
                    existing["secret_ref"]
                )
            elif isinstance(existing.get("api_key_env"), str) and existing["api_key_env"].strip():
                probe_api_key = os.environ.get(existing["api_key_env"].strip(), "").strip()
            elif isinstance(existing.get("api_key"), str) and existing["api_key"].strip():
                probe_api_key = existing["api_key"].strip()

        secrets_to_scrub: list[str] = []
        if probe_api_key:
            secrets_to_scrub.append(probe_api_key)
        for hk, hv in extra_headers.items():
            if is_sensitive_header_key(hk) and hv:
                secrets_to_scrub.append(hv)

        endpoint = _build_upstream_models_url(norm_url)
        req_headers = {"Accept": "application/json", **extra_headers}
        if probe_api_key:
            req_headers["Authorization"] = f"Bearer {probe_api_key}"

        t0 = time.monotonic()
        reachable = False
        probe_ok = False
        http_status: int | None = None
        truncated = False
        discovered: list[str] = []
        message = ""

        parsed_norm = urlsplit(norm_url)
        pinned_host = (parsed_norm.hostname or "").strip().lower().rstrip(".")
        pinned_port = parsed_norm.port or (443 if parsed_norm.scheme == "https" else 80)
        pinned_resolver = _PinnedResolver(pinned_host, pinned_port, dns_records)
        connector = aiohttp.TCPConnector(resolver=pinned_resolver, use_dns_cache=False)

        timeout = aiohttp.ClientTimeout(
            total=PROBE_TOTAL_TIMEOUT_SEC,
            connect=PROBE_CONNECT_TIMEOUT_SEC,
            sock_read=PROBE_READ_TIMEOUT_SEC,
        )
        try:
            async with aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                connector_owner=False,
            ) as cli:
                async with cli.get(
                    endpoint,
                    headers=req_headers,
                    allow_redirects=False,
                ) as resp:
                    http_status = resp.status
                    chunks: list[bytes] = []
                    total_read = 0
                    while total_read <= MAX_PROBE_BODY_BYTES:
                        chunk = await resp.content.read(min(16384, MAX_PROBE_BODY_BYTES + 1 - total_read))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        total_read += len(chunk)
                    raw_bytes = b"".join(chunks)
                    if len(raw_bytes) > MAX_PROBE_BODY_BYTES:
                        raw_bytes = raw_bytes[:MAX_PROBE_BODY_BYTES]
                        truncated = True

                    if 300 <= resp.status < 400:
                        reachable = False
                        probe_ok = False
                        message = f"上游返回重定向（HTTP {resp.status}），出于安全策略已拒绝跟随"
                    elif resp.status == 200:
                        reachable = True
                        try:
                            payload = json.loads(raw_bytes.decode("utf-8", errors="replace"))
                        except Exception:
                            probe_ok = False
                            message = (
                                "上游响应体超过 512 KiB 截断后无法解析为完整 JSON"
                                if truncated
                                else "上游返回 HTTP 200 但响应不是有效 JSON"
                            )
                        else:
                            entries_list: list[Any] = []
                            if isinstance(payload, dict):
                                if isinstance(payload.get("data"), list):
                                    entries_list = payload["data"]
                                elif isinstance(payload.get("models"), list):
                                    entries_list = payload["models"]
                            elif isinstance(payload, list):
                                entries_list = payload
                            seen_m: set[str] = set()
                            for ent in entries_list:
                                mid = ""
                                if isinstance(ent, dict) and ent.get("id"):
                                    mid = str(ent["id"]).strip()
                                elif isinstance(ent, str) and ent.strip():
                                    mid = ent.strip()
                                if mid and mid not in seen_m and not _CTRL_CHARS_RE.search(mid):
                                    seen_m.add(mid)
                                    discovered.append(mid)
                            probe_ok = True
                            message = (
                                f"连通成功（HTTP 200），发现 {len(discovered)} 个上游模型"
                                + ("（响应体已按 512 KiB 上限截断）" if truncated else "")
                            )
                    else:
                        reachable = True
                        probe_ok = False
                        raw_err = raw_bytes.decode("utf-8", errors="replace")
                        safe_detail = _redact_probe_text(raw_err, secrets_to_scrub, max_len=180)
                        if safe_detail:
                            message = f"上游返回 HTTP {resp.status}：{safe_detail}"
                        else:
                            message = f"上游返回异常状态码 HTTP {resp.status}"
        except TimeoutError:
            reachable = False
            probe_ok = False
            message = f"上游连接超时（> {PROBE_TOTAL_TIMEOUT_SEC:.1f}s）"
        except aiohttp.ClientSSLError:
            reachable = False
            probe_ok = False
            message = "上游 TLS 证书校验失败"
        except aiohttp.ClientError as exc:
            reachable = False
            probe_ok = False
            log.warning("Gateway probe client error for %s: %s", target_id or "draft", type(exc).__name__)
            message = f"无法连接上游端点（{type(exc).__name__}）"
        except Exception as exc:
            reachable = False
            probe_ok = False
            log.warning("Gateway probe unexpected error for %s: %s", target_id or "draft", type(exc).__name__)
            message = "上游连通性探测失败"
        finally:
            await connector.close()

        latency_ms = max(1, int(round((time.monotonic() - t0) * 1000)))
        merged_pool: list[str] = []
        seen_pool: set[str] = set()
        for m in [*discovered, *static_models]:
            if m not in seen_pool:
                seen_pool.add(m)
                merged_pool.append(m)
        exposed = [m for m in merged_pool if _model_matches_filters(m, inc_models, exc_models)]

        self.audit.record(
            action="gateways.probe",
            status_code=200,
            outcome="ok" if probe_ok else f"probe_failed_{http_status or 'net'}",
            client_ip=client_ip,
            target_id=target_id or "draft",
            sess=sess,
        )
        return web.json_response(
            {
                "ok": probe_ok,
                "reachable": reachable,
                "http_status": http_status,
                "latency_ms": latency_ms,
                "endpoint": endpoint,
                "truncated": truncated,
                "discovered_models": discovered,
                "discovered_count": len(discovered),
                "exposed_models": exposed,
                "exposed_count": len(exposed),
                "message": _redact_probe_text(message, secrets_to_scrub, max_len=280),
            }
        )

    @staticmethod
    def _build_persisted_entry(
        *,
        gw_id: str,
        parsed: dict[str, Any],
        secret_ref: dict[str, Any] | None,
        api_key_hint: str,
        now_ts: int,
    ) -> dict[str, Any]:
        """Construct clean `gateways.json` object with STRICTLY ZERO plaintext `api_key`."""
        entry: dict[str, Any] = {
            "id": gw_id,
            "name": parsed["name"],
            "base_url": parsed["base_url"],
            "dialect": parsed["dialect"],
            "enabled": parsed["enabled"],
            "supports_reasoning_effort": parsed["supports_reasoning_effort"],
            "effort_mode": parsed["effort_mode"],
            "flatten_system_content": parsed["flatten_system_content"],
            "strip_stream_options": parsed["strip_stream_options"],
            "max_tokens_field": parsed["max_tokens_field"],
            "max_tokens_cap": parsed["max_tokens_cap"],
            "adaptive_400_fallback": parsed["adaptive_400_fallback"],
            "timeout_s": parsed["timeout_s"],
            "updated_at": now_ts,
        }
        if parsed["include_models"]:
            entry["include_models"] = parsed["include_models"]
        if parsed["exclude_models"]:
            entry["exclude_models"] = parsed["exclude_models"]
        if parsed["models"]:
            entry["models"] = parsed["models"]
        if parsed["extra_headers"]:
            entry["extra_headers"] = parsed["extra_headers"]

        if secret_ref is not None:
            entry["secret_ref"] = secret_ref
            if api_key_hint:
                entry["api_key_hint"] = api_key_hint
        elif parsed["credential_kind"] == "api_key_env" and parsed["api_key_env"]:
            entry["api_key_env"] = parsed["api_key_env"]

        return entry
