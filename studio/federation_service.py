#!/usr/bin/env python3
"""AGY Studio — External Agent Bidirectional Federation Control Plane Service & REST API.

Wraps `bridge/federation_registry.py` with:
- Strict 4-layer Studio Admin write gate (`Origin` + `Sec-Fetch-Site` -> 403,
  `Content-Type: application/json` -> 415, live auth + `!must_change_password` -> 401/403,
  `X-Studio-CSRF` + `role == "admin"` -> 403).
- Server-only `OwnerAuth` construction AFTER all 4 write gates pass; explicit rejection
  of client-injected privilege/token/secret fields (`400`).
- One-time bearer token delivery (`Cache-Control: no-store, max-age=0` + `Pragma: no-cache`)
  and zero leakage across GET endpoints, Studio audit logs, access logs, and SSE events.
- Immediate Kill-Switch (`POST /api/federation/agents/{agent_id}/revoke`).
- Multi-team dynamic leader assignment across any registered agent without silent privilege
  escalation (returns explicit `leader_can_dispatch` and `warnings`).
- Anti-SSRF loopback-only Hub health probe (`allow_redirects=False`, timeout <= 3s,
  ignores all client query/body parameters).
- Anti-symlink / anti-traversal fail-closed Admin reader for `<BUS_DIR>/federation/audit.jsonl`.
"""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Sequence
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BRIDGE_SRC_DIR = _REPO_ROOT / "bridge"
if str(_BRIDGE_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_BRIDGE_SRC_DIR))

import bot_bus  # noqa: E402
import federation_registry  # noqa: E402

from .auth import StudioAuthManager, studio_auth_error
from .chat_service import (
    MAX_PROMPT_BODY_BYTES,
    StudioAuditLogger,
    _extract_media_type,
    _read_bounded_json_body,
)
from .data_sources import (
    StudioDataSources,
    _SENSITIVE_HOST_PATH_RE,
    _sanitize_slug,
    redact_secrets_only,
)
from .event_hub import StudioEventHub

log = logging.getLogger("agy-studio.federation")

DEFAULT_HUB_HOST = "127.0.0.1"
DEFAULT_HUB_PORT = 18799
MAX_HEALTH_TIMEOUT_SEC = 3.0
DEFAULT_HEALTH_TIMEOUT_SEC = 2.5
MAX_AUDIT_LIMIT = 200
DEFAULT_AUDIT_LIMIT = 50
MAX_AUDIT_READ_BYTES = 2 * 1024 * 1024  # 2 MiB tail cap
DEFAULT_TIMELINE_LIMIT = 50
MAX_TIMELINE_LIMIT = 200
MAX_WORKBENCH_JSON_BYTES = 1 * 1024 * 1024  # 1 MiB per JSON file cap
MAX_WORKBENCH_SCAN_FILES = 500
MAX_DISPATCH_PROMPT_CHARS = 65536
MAX_DISPATCH_TIMEOUT_SEC = 3600.0
WORKBENCH_ONLINE_WINDOW_SEC = 300.0
WORKBENCH_STALE_WINDOW_SEC = 3600.0
PRESENCE_FUTURE_SKEW_SEC = 60.0
PRESENCE_VALID_ACTIONS = frozenset({"peek", "inbox", "claim", "result", "events_ack", "mcp"})

_FED_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])agy_fed_[A-Za-z0-9._-]{12,}")
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_STRICT_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$")
_STRICT_PORT_RE = re.compile(r"^[1-9][0-9]{0,4}$")
_TERMINAL_JOB_STATUSES = frozenset({"done", "error", "cancelled", "failed"})
_DIR_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_OPEN_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)

# Keys that clients must NEVER inject in any federation request payload
_FORBIDDEN_CLIENT_INJECTION_KEYS = frozenset(
    {
        "owner_auth",
        "is_owner",
        "role",
        "token_records",
        "token_hash",
        "salt",
        "token_id",
        "revoked_at",
        "actor_id",
        "agent_origin",
        "is_registered_agent",
        "trust_override",
        "cmd",
        "command",
        "shell",
        "script",
        "workdir",
        "target_chat_id",
    }
    | set(federation_registry.FORBIDDEN_SECRET_KEYS)
)

# Keys stripped from any sanitized response / audit output
_OUTPUT_FORBIDDEN_KEYS = frozenset(
    {
        "token_records",
        "token_hash",
        "salt",
        "raw_token",
        "plaintext_token",
        "bearer_token",
        "api_key",
        "apikey",
        "api_token",
        "access_token",
        "auth_token",
        "refresh_token",
        "password",
        "passwd",
        "pwd",
        "secret",
        "secret_key",
        "client_secret",
        "private_key",
        "authorization",
        "credential",
        "credentials",
        "bot_token",
        "x_api_key",
        "x-api-key",
    }
)

_ALLOWED_CREATE_AGENT_KEYS = frozenset(
    {
        "agent_id",
        "display_name",
        "kind",
        "driver",
        "profile",
        "endpoint_url",
        "secret_ref",
        "transport",
        "capabilities",
        "trust_level",
        "enabled",
        "metadata",
        "overwrite",
        "mint_token",
        "token_label",
    }
)

_ALLOWED_PATCH_AGENT_KEYS = frozenset(
    {
        "display_name",
        "kind",
        "driver",
        "profile",
        "endpoint_url",
        "secret_ref",
        "transport",
        "capabilities",
        "trust_level",
        "enabled",
        "revoked",
        "metadata",
    }
)

_ALLOWED_CAPABILITY_KEYS = frozenset(
    {
        "coordinator_peer",
        "host_server_invoke",
        "allowed_teams",
        "can_dispatch",
        "can_receive",
    }
)

_ALLOWED_MINT_TOKEN_KEYS = frozenset({"label", "scope"})
_ALLOWED_ROTATE_TOKEN_KEYS = frozenset({"label", "revoke_existing", "scope"})

_ALLOWED_CREATE_TEAM_KEYS = frozenset(
    {
        "team_id",
        "display_name",
        "leader_agent_id",
        "co_leaders",
        "members",
        "metadata",
        "overwrite",
    }
)

_ALLOWED_PATCH_TEAM_KEYS = frozenset(
    {
        "display_name",
        "leader_agent_id",
        "co_leaders",
        "members",
        "metadata",
    }
)

_ALLOWED_SET_LEADER_KEYS = frozenset({"leader_agent_id", "co_leaders"})
_ALLOWED_WORKBENCH_DISPATCH_KEYS = frozenset({"prompt", "label", "timeout_s"})
_ALLOWED_WORKBENCH_CANCEL_KEYS = frozenset({"reason"})

THREE_HARD_LOCKS_SUMMARY: list[dict[str, str]] = [
    {
        "id": "lock_1_no_shell_bypass",
        "title": "硬锁 1：禁止 Shell / 解释器与任意文件篡改",
        "detail": (
            "host_exec 仅放行只读白名单命令与严格参数白名单，永久禁止 sh/bash/python/rm/sudo/curl "
            "等解释器与写命令，禁止通过文件接口越权修改受保护路径。"
        ),
    },
    {
        "id": "lock_2_no_secret_extraction",
        "title": "硬锁 2：禁止 OpenBao / 凭据提取",
        "detail": (
            "永久禁止调用 bao/vault、读取 .env/tokens/OpenBao 配置或返回明文密钥；"
            "所有出站凭据仅以 OpenBao secret_ref 方式在服务端临时注入。"
        ),
    },
    {
        "id": "lock_3_no_self_escalation",
        "title": "硬锁 3：禁止自我提权与宿主机服务篡改",
        "detail": (
            "永久禁止外部 Agent（含 coordinator_peer）修改 agents.json/teams.json、签发/轮换 Token "
            "或调用 systemctl/service；所有权限变更仅限人类 Owner 通过 4 层写门禁执行。"
        ),
    },
]

_NO_STORE_TOKEN_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
}


def _utc_iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _api_error(message: str, *, status: int = 400, code: str = "") -> web.Response:
    payload: dict[str, Any] = {
        "ok": False,
        "source": "studio_api",
        "error": redact_secrets_only(str(message or "请求无效")),
    }
    if code:
        payload["code"] = code
    return web.json_response(payload, status=status)


def _find_forbidden_client_key(obj: Any, *, path: str = "body", _depth: int = 0) -> str | None:
    if _depth > 12:
        return f"{path} (nesting too deep)"
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k)
            kn = ks.strip().lower().replace("-", "_")
            if kn in _FORBIDDEN_CLIENT_INJECTION_KEYS or ks.strip().lower() in _FORBIDDEN_CLIENT_INJECTION_KEYS:
                return f"{path}.{ks}"
            nested = _find_forbidden_client_key(v, path=f"{path}.{ks}", _depth=_depth + 1)
            if nested:
                return nested
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            nested = _find_forbidden_client_key(item, path=f"{path}[{idx}]", _depth=_depth + 1)
            if nested:
                return nested
    return None


def _sanitize_public_value(val: Any, *, scrub_host_paths: bool = False, _depth: int = 0) -> Any:
    """Defense-in-depth recursive sanitizer stripping forbidden secret keys and token patterns."""
    if _depth > 12:
        return None
    if val is None or isinstance(val, (bool, int, float)):
        return val
    if isinstance(val, str):
        s = redact_secrets_only(val)
        s = _FED_TOKEN_RE.sub("[REDACTED]", s)
        s = federation_registry.redact_secrets(s)
        if scrub_host_paths and s:
            s = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", s)
        return s
    if isinstance(val, dict):
        out: dict[str, Any] = {}
        for k, v in val.items():
            ks = str(k)
            kl = ks.strip().lower()
            kl_norm = kl.replace("-", "_")
            if (
                kl in _OUTPUT_FORBIDDEN_KEYS
                or kl_norm in _OUTPUT_FORBIDDEN_KEYS
                or kl == "token"
                or kl_norm == "token"
            ):
                continue
            out[ks] = _sanitize_public_value(v, scrub_host_paths=scrub_host_paths, _depth=_depth + 1)
        return out
    if isinstance(val, (list, tuple)):
        return [
            _sanitize_public_value(item, scrub_host_paths=scrub_host_paths, _depth=_depth + 1)
            for item in val
        ]
    s = redact_secrets_only(str(val))
    s = _FED_TOKEN_RE.sub("[REDACTED]", s)
    if scrub_host_paths and s:
        s = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", s)
    return s


def _sanitize_agent_record(agent: dict[str, Any], *, viewer_role: str = "") -> dict[str, Any]:
    """Sanitize a registered agent record while keeping validated `secret_ref` intact for admin only.

    - `admin` viewers receive the validated OpenBao mount ref (`<mount>/<namespace>/<item>[#<field>]`)
      so WebUI edit round-trips preserve `secret_ref` without `[REDACTED]` corruption (M3-B1).
    - Non-admin (`readonly`) viewers never see internal OpenBao paths (`secret_ref=""`) and
      only observe the boolean indicator `has_secret_ref`.
    """
    clean = _sanitize_public_value(agent)
    if not isinstance(clean, dict):
        clean = {}
    raw_ref = str((agent or {}).get("secret_ref") or "").strip()
    has_ref = bool(raw_ref)
    clean["has_secret_ref"] = has_ref
    if (
        viewer_role == "admin"
        and has_ref
        and federation_registry.SECRET_REF_RE.fullmatch(raw_ref)
        and not _FED_TOKEN_RE.search(raw_ref)
    ):
        clean["secret_ref"] = raw_ref
    else:
        clean["secret_ref"] = ""
    return clean


def _validate_strict_bool(
    body: dict[str, Any],
    key: str,
    *,
    default: bool | None = None,
) -> tuple[bool, bool | None, str]:
    """Require an explicit JSON boolean (`True`/`False`) when `key` is present and not None."""
    if key not in body or body[key] is None:
        return True, default, ""
    val = body[key]
    if not isinstance(val, bool):
        return False, None, f"字段 {key} 必须为严格布尔值 (true/false)"
    return True, val, ""


def _validate_strict_str_list(
    body: dict[str, Any],
    key: str,
) -> tuple[bool, list[str] | None, str]:
    """Require a JSON array of strings (`list[str]`) when `key` is present and not None."""
    if key not in body or body[key] is None:
        return True, None, ""
    val = body[key]
    if not isinstance(val, list) or not all(isinstance(item, str) for item in val):
        return False, None, f"字段 {key} 必须为字符串数组 (list[str])"
    return True, val, ""


def _validate_strict_token_scope(body: dict[str, Any]) -> tuple[bool, str, str]:
    """Require exact string `'full'` or `'peek'` whenever `'scope'` key is present in body."""
    if "scope" not in body:
        return True, federation_registry.TOKEN_SCOPE_FULL, ""
    val = body["scope"]
    if type(val) is not str or val not in federation_registry.VALID_TOKEN_SCOPES:
        return False, "", "字段 scope 必须为精确字符串 'full' 或 'peek'"
    return True, val, ""


def _validate_optional_dict(
    body: dict[str, Any],
    key: str,
) -> tuple[bool, dict[str, Any] | None, str]:
    """Require a JSON object (`dict`) when `key` is present and not None."""
    if key not in body or body[key] is None:
        return True, None, ""
    val = body[key]
    if not isinstance(val, dict):
        return False, None, f"字段 {key} 必须为 JSON 对象"
    return True, val, ""


def _validate_loopback_hub_target(raw_host: str, raw_port: Any) -> tuple[bool, str, int, str]:
    """Strictly validate server-configured Hub target as literal loopback IP + valid port."""
    host_str = str(raw_host or "").strip()
    if host_str.startswith("[") and host_str.endswith("]"):
        host_str = host_str[1:-1]
    if not host_str:
        return False, "", 0, "empty_hub_host"
    try:
        ip_obj = ipaddress.ip_address(host_str)
    except ValueError:
        return False, "", 0, "non_literal_loopback_host"
    if not ip_obj.is_loopback:
        return False, "", 0, "non_loopback_host"
    # Restrict strictly to canonical loopback addresses (127.0.0.1 or ::1)
    if str(ip_obj) not in ("127.0.0.1", "::1"):
        return False, "", 0, "non_canonical_loopback_host"
    try:
        port = int(raw_port)
    except (TypeError, ValueError):
        return False, "", 0, "invalid_hub_port"
    if not (1 <= port <= 65535):
        return False, "", 0, "out_of_range_hub_port"
    fmt_host = f"[{ip_obj}]" if ip_obj.version == 6 else str(ip_obj)
    return True, fmt_host, port, ""


def _validate_hub_public_url(raw_url: Any) -> str:
    """Strictly validate optional `AGY_FEDERATION_HUB_PUBLIC_URL` (Fail-Closed -> '').

    Allows ONLY:
    - `https://<host>[:port][/]` (excluding link-local/unspecified/multicast IPs)
    - `http://(127.0.0.1|localhost|[::1])[:port][/]` (strict canonical loopback only)

    Rejects non-loopback `http://`, userinfo (`@`), query (`?`), fragment (`#`),
    non-empty paths (anything other than `` or `/`), whitespace/control chars,
    empty ports (`:`), non-canonical loopback (`127.0.0.2`), `javascript:`, `file:`, etc.
    Returns canonical base URL with trailing slash stripped, or `""` when invalid/unset.
    """
    if not isinstance(raw_url, str) or not raw_url:
        return ""
    if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in raw_url):
        return ""
    if any(ch in raw_url for ch in ("?", "#", "@", "\\", "%")):
        return ""
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return ""
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("https", "http"):
        return ""
    if parsed.path not in ("", "/"):
        return ""
    if parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None:
        return ""
    netloc = parsed.netloc
    if not netloc:
        return ""

    port_val: int | None = None
    if netloc.startswith("["):
        end_idx = netloc.find("]")
        if end_idx <= 1:
            return ""
        host_raw = netloc[1:end_idx]
        rest = netloc[end_idx + 1 :]
        if rest:
            if not rest.startswith(":"):
                return ""
            port_str = rest[1:]
            if not _STRICT_PORT_RE.fullmatch(port_str):
                return ""
            port_val = int(port_str)
            if not (1 <= port_val <= 65535):
                return ""
    else:
        if ":" in netloc:
            parts = netloc.split(":")
            if len(parts) != 2:
                return ""
            host_raw, port_str = parts
            if not _STRICT_PORT_RE.fullmatch(port_str):
                return ""
            port_val = int(port_str)
            if not (1 <= port_val <= 65535):
                return ""
        else:
            host_raw = netloc

    if not host_raw:
        return ""
    host_low = host_raw.lower()

    try:
        parsed_port = parsed.port
    except ValueError:
        return ""
    if port_val is not None and parsed_port != port_val:
        return ""

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return ""

    if scheme == "http":
        # Strict canonical loopback only: 127.0.0.1, localhost, or [::1]
        if netloc.startswith("["):
            if host_low != "::1" or hostname != "::1":
                return ""
        elif host_low not in ("127.0.0.1", "localhost"):
            return ""
        fmt_host = "[::1]" if hostname == "::1" else hostname
        return f"http://{fmt_host}:{port_val}" if port_val is not None else f"http://{fmt_host}"

    # scheme == "https"
    if netloc.startswith("["):
        try:
            ip_obj = ipaddress.ip_address(host_raw)
        except ValueError:
            return ""
        if (
            ip_obj.version != 6
            or ip_obj.ipv4_mapped is not None
            or ip_obj.is_link_local
            or ip_obj.is_unspecified
            or ip_obj.is_multicast
        ):
            return ""
        if ip_obj.is_loopback and host_low != "::1":
            return ""
        fmt_host = f"[{ip_obj}]"
        return f"https://{fmt_host}:{port_val}" if port_val is not None else f"https://{fmt_host}"

    # Check if IPv4 literal
    try:
        ip_obj = ipaddress.ip_address(host_raw)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if ip_obj.version != 4 or ip_obj.is_link_local or ip_obj.is_unspecified or ip_obj.is_multicast:
            return ""
        if str(ip_obj) != host_raw:
            return ""
        if ip_obj.is_loopback and str(ip_obj) != "127.0.0.1":
            return ""
        fmt_host = str(ip_obj)
    else:
        if host_low == "localhost":
            fmt_host = "localhost"
        else:
            if len(host_low) > 253 or host_low.startswith(".") or host_low.endswith(".") or ".." in host_low:
                return ""
            labels = host_low.split(".")
            if len(labels) < 2 or not all(_DOMAIN_LABEL_RE.fullmatch(lbl) for lbl in labels):
                return ""
            if not _STRICT_TLD_RE.fullmatch(labels[-1]):
                return ""
            fmt_host = host_low

    return f"https://{fmt_host}:{port_val}" if port_val is not None else f"https://{fmt_host}"


def _validate_workbench_job_id(raw_job_id: Any) -> str:
    """Strictly validate a workbench job_id (supports both pull_queue and bot_bus IDs, blocks traversal)."""
    if not isinstance(raw_job_id, str) or not raw_job_id:
        raise ValueError("job_id 不能为空")
    if (
        ".." in raw_job_id
        or "/" in raw_job_id
        or "\\" in raw_job_id
        or "\x00" in raw_job_id
        or raw_job_id in (".", "..")
    ):
        raise ValueError(f"非法 job_id（含路径穿越字符）: {raw_job_id!r}")
    if not bot_bus.JOB_ID_RE.fullmatch(raw_job_id):
        raise ValueError(f"非法 job_id 格式: {raw_job_id!r}")
    return raw_job_id


def _open_dir_chain_no_symlink(base_dir: str, rel_parts: Sequence[str]) -> tuple[bool, int | None, str]:
    """Traverse `rel_parts` under `base_dir` step-by-step with `O_DIRECTORY | O_NOFOLLOW`.

    Returns `(True, None, "")` when any directory along the chain does not exist (zero disk side effects).
    Returns `(False, None, reason)` if any component is a symlink or non-directory.
    Caller MUST close the returned fd when not None.
    """
    try:
        base_fd = os.open(str(base_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except FileNotFoundError:
        return True, None, ""
    except OSError:
        return False, None, "SECURITY_SYMLINK_REJECTED: unable to open bus directory safely"

    cur_fd = base_fd
    try:
        for part in rel_parts:
            if not part or part in (".", "..") or "/" in part or "\\" in part or "\x00" in part:
                os.close(cur_fd)
                return False, None, f"SECURITY_SYMLINK_REJECTED: invalid directory component {part!r}"
            try:
                st = os.lstat(part, dir_fd=cur_fd)
            except FileNotFoundError:
                os.close(cur_fd)
                return True, None, ""
            except OSError:
                os.close(cur_fd)
                return False, None, f"SECURITY_SYMLINK_REJECTED: unable to inspect {part!r}"

            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                os.close(cur_fd)
                return False, None, f"SECURITY_SYMLINK_REJECTED: {part!r} is a symlink or non-directory"

            try:
                next_fd = os.open(part, _DIR_OPEN_FLAGS, dir_fd=cur_fd)
            except FileNotFoundError:
                os.close(cur_fd)
                return True, None, ""
            except OSError:
                os.close(cur_fd)
                return False, None, f"SECURITY_SYMLINK_REJECTED: refused to open {part!r} safely"

            os.close(cur_fd)
            cur_fd = next_fd
            fst = os.fstat(cur_fd)
            if not stat.S_ISDIR(fst.st_mode):
                os.close(cur_fd)
                return False, None, f"SECURITY_SYMLINK_REJECTED: {part!r} is not a directory"
        return True, cur_fd, ""
    except Exception:
        try:
            os.close(cur_fd)
        except OSError:
            pass
        return False, None, "SECURITY_SYMLINK_REJECTED: directory traversal failed"


def _assert_dir_not_symlink(base_dir: str, rel_parts: Sequence[str]) -> tuple[bool, str]:
    """Verify every existing directory along `base_dir/rel_parts` is a real directory (not a symlink)."""
    ok_dir, dir_fd, dir_err = _open_dir_chain_no_symlink(base_dir, rel_parts)
    if dir_fd is not None:
        os.close(dir_fd)
    if not ok_dir:
        return False, dir_err
    return True, ""


def _assert_file_not_symlink(
    base_dir: str,
    rel_dir_parts: Sequence[str],
    filename: str,
) -> tuple[bool, str]:
    """Verify `base_dir/rel_dir_parts/filename` (if present) is a regular file and not a symlink."""
    if not filename or filename in (".", "..") or "/" in filename or "\\" in filename or "\x00" in filename:
        return False, f"SECURITY_SYMLINK_REJECTED: invalid filename {filename!r}"
    ok_dir, dir_fd, dir_err = _open_dir_chain_no_symlink(base_dir, rel_dir_parts)
    if not ok_dir:
        return False, dir_err
    if dir_fd is None:
        return True, ""
    try:
        try:
            st = os.lstat(filename, dir_fd=dir_fd)
        except FileNotFoundError:
            return True, ""
        except OSError:
            return False, f"SECURITY_SYMLINK_REJECTED: unable to inspect {filename!r}"
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return False, f"SECURITY_SYMLINK_REJECTED: {filename!r} is a symlink or non-regular file"
        return True, ""
    finally:
        os.close(dir_fd)


def _read_json_file_in_dirfd(
    dir_fd: int,
    filename: str,
    *,
    max_bytes: int = MAX_WORKBENCH_JSON_BYTES,
) -> tuple[bool, dict[str, Any] | None, str]:
    """Open and parse a single JSON regular file inside `dir_fd` with `lstat` + `O_NOFOLLOW`."""
    try:
        st = os.lstat(filename, dir_fd=dir_fd)
    except FileNotFoundError:
        return True, None, ""
    except OSError:
        return False, None, f"SECURITY_SYMLINK_REJECTED: unable to inspect {filename!r}"

    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        return False, None, f"SECURITY_SYMLINK_REJECTED: {filename!r} is a symlink or non-regular file"

    try:
        fd = os.open(filename, _FILE_OPEN_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        return True, None, ""
    except OSError:
        return False, None, f"SECURITY_SYMLINK_REJECTED: refused to open {filename!r} safely"

    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            return False, None, f"SECURITY_SYMLINK_REJECTED: {filename!r} is not a regular file"
        chunks: list[bytes] = []
        remaining = max_bytes
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)

    try:
        obj = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return True, None, ""
    return True, obj if isinstance(obj, dict) else None, ""


def _read_single_json_no_symlink(
    bus_dir: str,
    rel_parts: Sequence[str],
    filename: str,
) -> tuple[bool, dict[str, Any] | None, str]:
    ok_dir, dir_fd, dir_err = _open_dir_chain_no_symlink(bus_dir, rel_parts)
    if not ok_dir:
        return False, None, dir_err
    if dir_fd is None:
        return True, None, ""
    try:
        return _read_json_file_in_dirfd(dir_fd, filename)
    finally:
        os.close(dir_fd)


def _scan_json_dir_no_symlink(
    bus_dir: str,
    rel_parts: Sequence[str],
    *,
    max_files: int = MAX_WORKBENCH_SCAN_FILES,
) -> tuple[bool, list[dict[str, Any]], str]:
    """Safely scan `*.json` files in `bus_dir/rel_parts` using `O_DIRECTORY | O_NOFOLLOW`."""
    ok_dir, dir_fd, dir_err = _open_dir_chain_no_symlink(bus_dir, rel_parts)
    if not ok_dir:
        return False, [], dir_err
    if dir_fd is None:
        return True, [], ""
    records: list[dict[str, Any]] = []
    try:
        try:
            names = sorted(
                fn for fn in os.listdir(dir_fd) if fn.endswith(".json") and not fn.endswith(".tmp")
            )
        except OSError:
            return False, [], "SECURITY_SYMLINK_REJECTED: unable to list directory safely"
        for fn in names[:max_files]:
            ok_f, obj, err_f = _read_json_file_in_dirfd(dir_fd, fn)
            if not ok_f:
                return False, [], err_f
            if isinstance(obj, dict):
                records.append(obj)
        return True, records, ""
    finally:
        os.close(dir_fd)


def _read_agents_map_no_symlink(bus_dir: str) -> tuple[bool, dict[str, dict[str, Any]], str]:
    """Read and sanitize `<bus_dir>/federation/agents.json` with zero symlinks and zero disk creation."""
    ok_f, data, err_f = _read_single_json_no_symlink(bus_dir, ("federation",), "agents.json")
    if not ok_f:
        return False, {}, err_f
    if not isinstance(data, dict) or not isinstance(data.get("agents"), dict):
        return True, {}, ""
    out: dict[str, dict[str, Any]] = {}
    for aid, rec in data["agents"].items():
        if isinstance(aid, str) and isinstance(rec, dict):
            out[aid] = federation_registry.sanitize_agent_record(rec)
    return True, out, ""


def _read_roster_last_seen_no_symlink(bus_dir: str) -> dict[str, float]:
    """Read optional `roster.json` `last_seen` timestamps safely (fail-open to empty on missing)."""
    ok_f, data, _ = _read_single_json_no_symlink(bus_dir, (), "roster.json")
    if not ok_f or not isinstance(data, dict):
        return {}
    bots = data.get("bots")
    if not isinstance(bots, dict):
        return {}
    out: dict[str, float] = {}
    for handle, entry in bots.items():
        if isinstance(handle, str) and isinstance(entry, dict):
            ts = entry.get("last_seen")
            if isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts > 0:
                out[handle.strip().lower()] = float(ts)
    return out


def _sanitize_presence_ts(val: Any, *, max_ts: float) -> float | None:
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        fval = float(val)
        if math.isfinite(fval) and 0.0 < fval <= max_ts:
            return fval
    return None


def _read_presence_map_no_symlink(
    bus_dir: str,
    *,
    now_ts: float | None = None,
) -> tuple[bool, dict[str, dict[str, Any]], str]:
    """Read and sanitize `<bus_dir>/federation/presence.json` strictly read-only with anti-symlink checks.

    - Missing `<bus_dir>`, `federation/`, or `presence.json` returns `(True, {}, "")` with zero disk creation.
    - Symlink or non-regular `presence.json` (or symlink `federation/`) fails closed with `SECURITY_SYMLINK_REJECTED`.
    - Files exceeding `MAX_WORKBENCH_JSON_BYTES` (1 MiB) or malformed JSON are skipped safely.
    - Validates finite positive timestamps `<= now_ts + 60s`, strict action allowlist, and ignores unknown keys.
    """
    ok_dir, dir_fd, dir_err = _open_dir_chain_no_symlink(bus_dir, ("federation",))
    if not ok_dir:
        return False, {}, dir_err
    if dir_fd is None:
        return True, {}, ""
    try:
        try:
            st = os.lstat("presence.json", dir_fd=dir_fd)
        except FileNotFoundError:
            return True, {}, ""
        except OSError:
            return False, {}, "SECURITY_SYMLINK_REJECTED: unable to inspect 'presence.json'"

        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return False, {}, "SECURITY_SYMLINK_REJECTED: 'presence.json' is a symlink or non-regular file"

        try:
            fd = os.open("presence.json", _FILE_OPEN_FLAGS, dir_fd=dir_fd)
        except FileNotFoundError:
            return True, {}, ""
        except OSError:
            return False, {}, "SECURITY_SYMLINK_REJECTED: refused to open 'presence.json' safely"

        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode):
                return False, {}, "SECURITY_SYMLINK_REJECTED: 'presence.json' is not a regular file"
            if fst.st_size > MAX_WORKBENCH_JSON_BYTES:
                return True, {}, ""
            chunks: list[bytes] = []
            remaining = MAX_WORKBENCH_JSON_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > MAX_WORKBENCH_JSON_BYTES:
                return True, {}, ""
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)

    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return True, {}, ""
    if not isinstance(data, dict):
        return True, {}, ""

    eff_now = time.time() if now_ts is None else float(now_ts)
    max_allowed_ts = eff_now + PRESENCE_FUTURE_SKEW_SEC
    out: dict[str, dict[str, Any]] = {}
    for raw_aid, raw_entry in data.items():
        if not isinstance(raw_aid, str) or not isinstance(raw_entry, dict):
            continue
        try:
            aid = federation_registry.validate_agent_id(raw_aid)
        except ValueError:
            continue
        last_seen_at = _sanitize_presence_ts(raw_entry.get("last_seen_at"), max_ts=max_allowed_ts)
        last_peek_at = _sanitize_presence_ts(raw_entry.get("last_peek_at"), max_ts=max_allowed_ts)
        ts_candidates = [t for t in (last_seen_at, last_peek_at) if t is not None]
        if not ts_candidates:
            continue
        raw_act = raw_entry.get("last_action")
        clean_act = (
            raw_act.strip().lower()
            if isinstance(raw_act, str) and raw_act.strip().lower() in PRESENCE_VALID_ACTIONS
            else ""
        )
        out[aid] = {
            "last_seen_at": last_seen_at,
            "last_peek_at": last_peek_at,
            "last_heartbeat_at": max(ts_candidates),
            "last_action": clean_act,
        }
    return True, out, ""


def _classify_workbench_agent(agent: dict[str, Any]) -> tuple[str, str, bool, str]:
    """Return `(adapter_type, dispatch_mode, can_dispatch, disabled_reason)` for a federated agent."""
    kind = str(agent.get("kind") or "").strip().lower()
    driver = str(agent.get("driver") or "").strip().lower()
    transport = str(agent.get("transport") or "").strip().lower()
    is_pull = transport == "pull_worker" or driver == "pull_worker" or kind == "pull_worker"

    if is_pull:
        adapter_type = "pull_worker"
        dispatch_mode = "pull"
    elif kind == "agy_local":
        adapter_type = "agy_local"
        dispatch_mode = "local_only"
    elif kind == "mcp_inbound_only":
        adapter_type = "mcp_inbound_only"
        dispatch_mode = "inbound_only"
    elif kind in ("hermes_local", "hermes_remote", "muse_remote", "http_a2a"):
        adapter_type = kind
        dispatch_mode = "push"
    else:
        adapter_type = kind or "external"
        dispatch_mode = "push"

    if kind == "agy_local":
        return adapter_type, dispatch_mode, False, "本机 AGY Bot 请在主工作台对话"
    if kind == "mcp_inbound_only":
        return adapter_type, dispatch_mode, False, "仅入站 MCP 节点不支持主动派单"
    if bool(agent.get("revoked", False)):
        return adapter_type, dispatch_mode, False, "节点已被吊销"
    if not bool(agent.get("enabled", True)):
        return adapter_type, dispatch_mode, False, "节点已停用"
    caps = agent.get("capabilities") or {}
    if not bool(caps.get("can_receive", True)):
        return adapter_type, dispatch_mode, False, "节点未开启接收派工权限 (can_receive=false)"
    return adapter_type, dispatch_mode, True, ""


def _safe_float_ts(val: Any) -> float:
    if isinstance(val, (int, float)) and not isinstance(val, bool) and math.isfinite(val) and val > 0:
        return float(val)
    return 0.0


def _compute_runtime_status(
    agent: dict[str, Any],
    *,
    last_live_ts: float,
    has_active_execution: bool,
    now_ts: float,
) -> str:
    if bool(agent.get("revoked", False)):
        return "revoked"
    if not bool(agent.get("enabled", True)):
        return "disabled"
    if has_active_execution:
        return "online"
    if last_live_ts > 0:
        age = max(0.0, now_ts - last_live_ts)
        if age <= WORKBENCH_ONLINE_WINDOW_SEC:
            return "online"
        if age <= WORKBENCH_STALE_WINDOW_SEC:
            return "stale"
    return "offline"


def _detect_job_source(pull_job: dict[str, Any] | None, bus_job: dict[str, Any] | None) -> str:
    p_meta = (pull_job or {}).get("metadata") if isinstance((pull_job or {}).get("metadata"), dict) else {}
    p_src = str(p_meta.get("source") or "").strip().lower()
    p_from = str((pull_job or {}).get("from_agent_id") or p_meta.get("from_actor") or "").strip().lower()
    b_from = str((bus_job or {}).get("from_bot") or "").strip().lower()
    b_orig = str((bus_job or {}).get("agent_origin") or "").strip().lower()
    b_chat = (bus_job or {}).get("origin_chat_id")
    has_tg_chat = isinstance(b_chat, int) and not isinstance(b_chat, bool) and b_chat != 0

    if p_src == "studio" or p_from.startswith("studio:") or p_from == "studio" or b_from == "studio" or b_from.startswith("studio:"):
        return "studio"
    if p_src == "telegram" or has_tg_chat or b_orig.startswith("local_tg"):
        return "telegram"
    if bus_job is not None:
        return "bus"
    return "pull"


def _status_priority(status: str) -> int:
    st = str(status or "").strip().lower()
    if st in _TERMINAL_JOB_STATUSES:
        return 3
    if st in ("running", "claimed"):
        return 2
    if st == "queued":
        return 1
    return 0


def _terminal_status_priority(status: str) -> int:
    st = str(status or "").strip().lower()
    if st == "done":
        return 3
    if st in ("error", "failed"):
        return 2
    if st == "cancelled":
        return 1
    return 0


def _merge_single_timeline_job(
    jid: str,
    pull_job: dict[str, Any] | None,
    bus_job: dict[str, Any] | None,
    *,
    is_admin: bool,
    now_ts: float,
) -> dict[str, Any]:
    """Merge and deeply redact a single job across PullWorkerQueue and bot_bus."""
    p_st = str((pull_job or {}).get("status") or "").strip().lower()
    b_st = str((bus_job or {}).get("status") or "").strip().lower()
    if b_st == "failed":
        b_st = "error"

    p_fin = _safe_float_ts((pull_job or {}).get("finished_at"))
    b_fin = _safe_float_ts((bus_job or {}).get("finished_at"))
    p_claim = _safe_float_ts((pull_job or {}).get("claimed_at"))
    b_start = _safe_float_ts((bus_job or {}).get("started_at"))
    p_created = _safe_float_ts((pull_job or {}).get("created_at"))
    b_created = _safe_float_ts((bus_job or {}).get("created_at"))

    # Pick winning status: terminal priority, then newer finished_at/claimed_at/started_at
    if pull_job is not None and bus_job is None:
        win_src = "pull"
        status = p_st or "queued"
    elif bus_job is not None and pull_job is None:
        win_src = "bus"
        status = b_st or "queued"
    else:
        p_rank = _status_priority(p_st)
        b_rank = _status_priority(b_st)
        if p_rank > b_rank:
            win_src = "pull"
            status = p_st
        elif b_rank > p_rank:
            win_src = "bus"
            status = b_st
        elif p_rank == 3:
            # Both terminal: semantic priority first (done > error > cancelled),
            # then newer finished_at only when both sides share the same terminal class.
            p_term_prio = _terminal_status_priority(p_st)
            b_term_prio = _terminal_status_priority(b_st)
            if p_term_prio > b_term_prio:
                win_src = "pull"
            elif b_term_prio > p_term_prio:
                win_src = "bus"
            elif p_fin != b_fin:
                win_src = "pull" if p_fin > b_fin else "bus"
            else:
                win_src = "pull"
            status = p_st if win_src == "pull" else b_st
        else:
            p_prog = max(p_claim, p_created)
            b_prog = max(b_start, b_created)
            win_src = "pull" if p_prog >= b_prog else "bus"
            status = p_st if win_src == "pull" else b_st

    primary = pull_job if win_src == "pull" else bus_job
    secondary = bus_job if win_src == "pull" else pull_job

    p_meta = (pull_job or {}).get("metadata") if isinstance((pull_job or {}).get("metadata"), dict) else {}

    prompt = str((pull_job or {}).get("prompt") or (bus_job or {}).get("prompt") or "")
    result_text = str(
        (primary or {}).get("result_text")
        or (primary or {}).get("result")
        or (secondary or {}).get("result_text")
        or (secondary or {}).get("result")
        or ""
    )
    error_text = str((primary or {}).get("error") or (secondary or {}).get("error") or "")
    cancel_reason = str(
        (primary or {}).get("cancel_reason") or (secondary or {}).get("cancel_reason") or ""
    )
    label = str((bus_job or {}).get("label") or p_meta.get("label") or "")
    from_actor = str(
        (bus_job or {}).get("from_bot")
        or (pull_job or {}).get("from_agent_id")
        or p_meta.get("from_actor")
        or ""
    )
    team_id = str((pull_job or {}).get("team_id") or (bus_job or {}).get("team_id") or "")
    group_id = str((bus_job or {}).get("group_id") or p_meta.get("group_id") or "")

    created_candidates = [t for t in (p_created, b_created) if t > 0]
    created_at = min(created_candidates) if created_candidates else 0.0
    started_candidates = [t for t in (p_claim, b_start) if t > 0]
    started_at = min(started_candidates) if started_candidates else None
    finished_candidates = [t for t in (p_fin, b_fin) if t > 0]
    finished_at = max(finished_candidates) if finished_candidates else None

    is_terminal = status in _TERMINAL_JOB_STATUSES
    elapsed_s: float | None = None
    if is_terminal and finished_at is not None:
        base_t = started_at if started_at is not None else created_at
        if base_t > 0:
            elapsed_s = round(max(0.0, finished_at - base_t), 2)
    elif not is_terminal and created_at > 0:
        elapsed_s = round(max(0.0, now_ts - created_at), 2)

    stores: list[str] = []
    if pull_job is not None:
        stores.append("pull")
    if bus_job is not None:
        stores.append("bus")

    source = _detect_job_source(pull_job, bus_job)
    raw_item: dict[str, Any] = {
        "job_id": jid,
        "status": status,
        "source": source,
        "stores": stores,
        "bridged": (len(stores) > 1) or bool(p_meta.get("bridged_from_bot_bus")),
        "label": label[:120],
        "from_actor": from_actor[:80],
        "team_id": team_id[:64],
        "group_id": group_id[:64],
        "prompt": prompt,
        "result_text": result_text,
        "error": error_text,
        "cancel_reason": cancel_reason,
        "created_at": created_at if created_at > 0 else None,
        "started_at": started_at,
        "claimed_at": p_claim if p_claim > 0 else None,
        "finished_at": finished_at,
        "elapsed_s": elapsed_s,
        "is_active": not is_terminal,
        "can_cancel": bool(is_admin and not is_terminal),
    }
    return _sanitize_public_value(raw_item, scrub_host_paths=True)


def _sanitize_leader_event_summary(ev: dict[str, Any]) -> dict[str, Any]:
    """Extract ONLY strict safe summary fields from a leader_event (never leak raw payloads/secrets)."""
    eid = str(ev.get("event_id") or "")[:128]
    ev_type = str(ev.get("type") or ev.get("event") or "event")[:48]
    created_at = _safe_float_ts(ev.get("created_at"))
    group_id = str(ev.get("group_id") or "")[:64]
    team_id = str(ev.get("team_id") or "")[:64]

    raw_jids = ev.get("job_ids")
    job_ids: list[str] = []
    if isinstance(raw_jids, list):
        for item in raw_jids[:50]:
            if isinstance(item, str) and item.strip():
                job_ids.append(item.strip()[:128])
    elif isinstance(ev.get("job_id"), str) and str(ev.get("job_id")).strip():
        job_ids.append(str(ev.get("job_id")).strip()[:128])

    raw_jobs = ev.get("jobs")
    jobs_count = len(raw_jobs) if isinstance(raw_jobs, list) else len(job_ids)
    status_counts: dict[str, int] = {}
    if isinstance(raw_jobs, list):
        for j in raw_jobs[:50]:
            if isinstance(j, dict):
                st = str(j.get("status") or "unknown").strip().lower()[:24] or "unknown"
                status_counts[st] = status_counts.get(st, 0) + 1

    if status_counts:
        if len(status_counts) == 1:
            derived_status = next(iter(status_counts.keys()))
        elif "error" in status_counts or "failed" in status_counts:
            derived_status = "partial_error"
        else:
            derived_status = "mixed"
    else:
        derived_status = str(ev.get("status") or "pending").strip().lower()[:24] or "pending"

    summary: dict[str, Any] = {
        "event_id": eid,
        "type": ev_type,
        "created_at": created_at if created_at > 0 else None,
        "group_id": group_id,
        "team_id": team_id,
        "job_ids": job_ids,
        "jobs_count": jobs_count,
        "status": derived_status,
        "status_counts": status_counts,
        "tainted": bool(ev.get("tainted", False)),
    }
    return _sanitize_public_value(summary, scrub_host_paths=True)


def _read_federation_audit_no_symlink(
    bus_dir: str,
    *,
    limit: int,
    offset: int,
    actor_filter: str = "",
    event_filter: str = "",
) -> tuple[bool, dict[str, Any], str]:
    """Fail-closed anti-symlink reader for `<BUS_DIR>/federation/audit.jsonl`.

    Verifies neither `<BUS_DIR>/federation` nor `audit.jsonl` is a symlink or escapes
    the federation directory, opens with `O_NOFOLLOW`, and sanitizes every returned field.
    """
    bus_path = Path(bus_dir)
    fed_dir = bus_path / "federation"

    # Open federation directory via O_DIRECTORY | O_NOFOLLOW to close dir-swap TOCTOU window
    try:
        fed_st = os.lstat(fed_dir)
    except FileNotFoundError:
        return True, {"entries": [], "total": 0, "limit": limit, "offset": offset}, ""
    except OSError:
        return False, {}, "SECURITY_AUDIT_UNAVAILABLE: unable to inspect federation directory"

    if stat.S_ISLNK(fed_st.st_mode) or not stat.S_ISDIR(fed_st.st_mode):
        return False, {}, "SECURITY_SYMLINK_REJECTED: federation directory is a symlink or non-directory"

    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        dir_fd = os.open(str(fed_dir), dir_flags)
    except FileNotFoundError:
        return True, {"entries": [], "total": 0, "limit": limit, "offset": offset}, ""
    except OSError:
        return False, {}, "SECURITY_SYMLINK_REJECTED: refused to open federation directory safely"

    try:
        d_st = os.fstat(dir_fd)
        if not stat.S_ISDIR(d_st.st_mode):
            return False, {}, "SECURITY_SYMLINK_REJECTED: federation path is not a directory"

        try:
            file_st = os.lstat("audit.jsonl", dir_fd=dir_fd)
        except FileNotFoundError:
            return True, {"entries": [], "total": 0, "limit": limit, "offset": offset}, ""
        except OSError:
            return False, {}, "SECURITY_AUDIT_UNAVAILABLE: unable to inspect audit.jsonl"

        if stat.S_ISLNK(file_st.st_mode) or not stat.S_ISREG(file_st.st_mode):
            return False, {}, "SECURITY_SYMLINK_REJECTED: audit.jsonl is a symlink or non-regular file"

        file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open("audit.jsonl", file_flags, dir_fd=dir_fd)
        except FileNotFoundError:
            return True, {"entries": [], "total": 0, "limit": limit, "offset": offset}, ""
        except OSError:
            return False, {}, "SECURITY_SYMLINK_REJECTED: refused to open audit.jsonl safely"

        try:
            f_st = os.fstat(fd)
            if not stat.S_ISREG(f_st.st_mode):
                return False, {}, "SECURITY_SYMLINK_REJECTED: audit.jsonl is not a regular file"
            # Read bounded tail up to MAX_AUDIT_READ_BYTES
            size = f_st.st_size
            if size > MAX_AUDIT_READ_BYTES:
                os.lseek(fd, size - MAX_AUDIT_READ_BYTES, os.SEEK_SET)
                raw_bytes = os.read(fd, MAX_AUDIT_READ_BYTES)
                # Drop potentially split first line
                nl_pos = raw_bytes.find(b"\n")
                if nl_pos >= 0:
                    raw_bytes = raw_bytes[nl_pos + 1 :]
            else:
                chunks: list[bytes] = []
                remaining = MAX_AUDIT_READ_BYTES
                while remaining > 0:
                    chunk = os.read(fd, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw_bytes = b"".join(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)

    parsed_entries: list[dict[str, Any]] = []
    actor_f = actor_filter.strip().lower()
    event_f = event_filter.strip().lower()
    for raw_line in raw_bytes.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        if actor_f and str(obj.get("actor_id") or "").strip().lower() != actor_f:
            continue
        if event_f and str(obj.get("event") or "").strip().lower() != event_f:
            continue
        sanitized_obj = _sanitize_public_value(obj, scrub_host_paths=True)
        if isinstance(sanitized_obj, dict):
            parsed_entries.append(sanitized_obj)

    # Newest first
    parsed_entries.reverse()
    total = len(parsed_entries)
    page = parsed_entries[offset : offset + limit]
    return (
        True,
        {
            "entries": page,
            "total": total,
            "limit": limit,
            "offset": offset,
        },
        "",
    )


class StudioFederationService:
    """Studio backend service and aiohttp REST handlers for External Agent Bidirectional Federation."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        data_sources: StudioDataSources,
        audit: StudioAuditLogger,
        event_hub: StudioEventHub | None = None,
        *,
        hub_host: str | None = None,
        hub_port: int | None = None,
        hub_public_url: str | None = None,
        health_timeout_sec: float = DEFAULT_HEALTH_TIMEOUT_SEC,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.audit = audit
        self.event_hub = event_hub
        self._hub_host_override = hub_host
        self._hub_port_override = hub_port
        self._hub_public_url_override = hub_public_url
        self.health_timeout_sec = max(0.2, min(float(health_timeout_sec), MAX_HEALTH_TIMEOUT_SEC))

    @property
    def bus_dir(self) -> str:
        return str(self.data_sources.bus_dir)

    def _effective_hub_host_port(self) -> tuple[str, Any]:
        host = (
            self._hub_host_override
            if self._hub_host_override is not None
            else os.environ.get("AGY_FEDERATION_HUB_HOST", DEFAULT_HUB_HOST)
        )
        port = (
            self._hub_port_override
            if self._hub_port_override is not None
            else os.environ.get("AGY_FEDERATION_HUB_PORT", str(DEFAULT_HUB_PORT))
        )
        return str(host).strip(), port

    def _build_hub_config(self) -> dict[str, Any]:
        raw_host, raw_port = self._effective_hub_host_port()
        ok_cfg, fmt_host, port, _ = _validate_loopback_hub_target(raw_host, raw_port)
        loopback_mcp_url = f"http://{fmt_host}:{port}/hub/mcp" if ok_cfg else ""
        raw_public = (
            self._hub_public_url_override
            if self._hub_public_url_override is not None
            else os.environ.get("AGY_FEDERATION_HUB_PUBLIC_URL", "")
        )
        public_url = _validate_hub_public_url(raw_public)
        mcp_url = f"{public_url}/hub/mcp" if public_url else loopback_mcp_url
        return {
            "loopback_valid": ok_cfg,
            "host": fmt_host if ok_cfg else "invalid",
            "port": port if ok_cfg else 0,
            "public_url": public_url,
            "loopback_mcp_url": loopback_mcp_url,
            "mcp_url": mcp_url,
        }

    def _make_studio_owner_auth(self, sess: dict[str, Any]) -> federation_registry.OwnerAuth:
        actor = str(sess.get("username") or sess.get("user_id") or "admin").strip()
        actor_slug = _sanitize_slug(actor, max_len=64) or "admin"
        return federation_registry.make_owner_auth(actor_id=f"studio:{actor_slug}")

    def _publish_federation_updated(
        self,
        *,
        action: str,
        agent_id: str = "",
        team_id: str = "",
    ) -> None:
        if self.event_hub is None:
            return
        payload: dict[str, Any] = {
            "action": str(action)[:48],
            "source": "studio",
            "ts": round(time.time(), 3),
        }
        if agent_id:
            payload["agent_id"] = _sanitize_slug(agent_id, max_len=64)
        if team_id:
            payload["team_id"] = _sanitize_slug(team_id, max_len=64)
        self.event_hub.publish("federation_updated", payload)

    def _annotate_team_warnings(self, team: dict[str, Any]) -> tuple[dict[str, Any], bool | None, list[str]]:
        """Inspect team leader `can_dispatch` without mutating any agent record."""
        clean_team = _sanitize_public_value(team)
        if not isinstance(clean_team, dict):
            clean_team = {}
        leader_id = str(clean_team.get("leader_agent_id") or "").strip()
        warnings: list[str] = []
        leader_can_dispatch: bool | None = None
        if leader_id:
            try:
                leader_rec = federation_registry.get_agent(leader_id, bus_dir=self.bus_dir)
            except Exception:
                leader_rec = None
            if isinstance(leader_rec, dict):
                if bool(leader_rec.get("revoked", False)):
                    leader_can_dispatch = False
                    warnings.append(f"负责人 {leader_id} 已被吊销，无法执行派工。")
                else:
                    caps = leader_rec.get("capabilities") or {}
                    can_disp = bool(caps.get("can_dispatch", False))
                    leader_can_dispatch = can_disp
                    if not can_disp:
                        warnings.append(
                            f"负责人 {leader_id} 当前 can_dispatch=false，不会静默提权；如需允许其派工请由 Owner 显式开启 can_dispatch。"
                        )
            else:
                legacy_ids: set[str] = set()
                try:
                    lcfg = federation_registry._load_legacy_team_config(self.bus_dir)
                    for k in (lcfg.get("bots") or {}).keys():
                        legacy_ids.add(str(k).lstrip("@").strip().lower())
                except Exception:
                    pass
                try:
                    lros = federation_registry._load_legacy_roster(self.bus_dir)
                    for k in (lros.get("bots") or {}).keys():
                        legacy_ids.add(str(k).lstrip("@").strip().lower())
                except Exception:
                    pass
                if leader_id.lstrip("@").strip().lower() in legacy_ids:
                    leader_can_dispatch = True
                else:
                    leader_can_dispatch = False
                    warnings.append(f"负责人 {leader_id} 不在已注册 Agent 名册中或已被删除，无法执行派工。")
        clean_team["leader_can_dispatch"] = leader_can_dispatch
        clean_team["warnings"] = warnings
        return clean_team, leader_can_dispatch, warnings

    # ------------------------------------------------------------------ 4-Layer Admin Write Gate (M3-C1)
    async def _enforce_write_gate(
        self,
        request: web.Request,
        *,
        action: str,
        target_id: str = "",
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        client_ip = self.auth_mgr.extract_client_ip(request)
        safe_tid = _sanitize_slug(target_id, max_len=64) if target_id else ""

        # Gate 1a: Strict Same-Origin (Origin required)
        ok_orig, err_orig = self.auth_mgr.check_same_origin(request, require_origin=True)
        if not ok_orig:
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_origin",
                client_ip=client_ip,
                target_id=safe_tid,
            )
            return False, None, studio_auth_error(err_orig, status=403)

        # Gate 1b: Sec-Fetch-Site must be same-origin / none when present
        sfs = (request.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sfs and sfs not in ("same-origin", "none"):
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_sec_fetch_site",
                client_ip=client_ip,
                target_id=safe_tid,
            )
            return False, None, studio_auth_error("Sec-Fetch-Site 跨站写请求已拦截", status=403)

        # Gate 2: Non-simple Content-Type: application/json
        if _extract_media_type(request) != "application/json":
            self.audit.record(
                action=action,
                status_code=415,
                outcome="denied_content_type",
                client_ip=client_ip,
                target_id=safe_tid,
            )
            return False, None, studio_auth_error("写接口仅接受 Content-Type: application/json", status=415)

        # Gate 3: Authenticated session + !must_change_password
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            self.audit.record(
                action=action,
                status_code=status_code,
                outcome=f"denied_auth_{status_code}",
                client_ip=client_ip,
                target_id=safe_tid,
            )
            return False, None, studio_auth_error(err_auth, status=status_code)

        # Gate 4a: Constant-time X-Studio-CSRF validation
        ok_csrf, err_csrf = self.auth_mgr.check_csrf(request, sess)
        if not ok_csrf:
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_csrf",
                client_ip=client_ip,
                target_id=safe_tid,
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
                target_id=safe_tid,
                sess=sess,
            )
            return False, None, studio_auth_error("只读权限（readonly）禁止执行写操作", status=403)

        return True, sess, None

    async def _parse_validated_body(
        self,
        request: web.Request,
        *,
        sess: dict[str, Any],
        action: str,
        allowed_keys: frozenset[str],
        allow_empty: bool = False,
        target_id: str = "",
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        client_ip = self.auth_mgr.extract_client_ip(request)
        safe_tid = _sanitize_slug(target_id, max_len=64) if target_id else ""

        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request,
            max_bytes=MAX_PROMPT_BODY_BYTES,
            allow_empty=allow_empty,
        )
        if not ok_body or body is None:
            self.audit.record(
                action=action,
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
            )
            return False, None, _api_error(body_err, status=body_sc)

        bad_key = _find_forbidden_client_key(body)
        if bad_key:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_forbidden_field",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
            )
            return (
                False,
                None,
                _api_error(
                    f"PLAINTEXT_SECRET_REJECTED: 禁止提交受限或明文凭据字段 ({bad_key})",
                    status=400,
                    code="PLAINTEXT_SECRET_REJECTED",
                ),
            )

        unknown = sorted(set(body.keys()) - allowed_keys)
        if unknown:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
            )
            return (
                False,
                None,
                _api_error(f"请求包含未允许的字段: {', '.join(unknown)}", status=400, code="UNKNOWN_FIELD"),
            )

        try:
            federation_registry.reject_plaintext_secrets(body, path="payload")
        except ValueError as exc:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_plaintext_secret",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
            )
            return False, None, _api_error(str(exc), status=400, code="PLAINTEXT_SECRET_REJECTED")

        if "capabilities" in body and body["capabilities"] is not None:
            caps = body["capabilities"]
            if not isinstance(caps, dict):
                return False, None, _api_error("capabilities 必须为 JSON 对象", status=400)
            unk_caps = sorted(set(caps.keys()) - _ALLOWED_CAPABILITY_KEYS)
            if unk_caps:
                return (
                    False,
                    None,
                    _api_error(f"capabilities 包含未允许的字段: {', '.join(unk_caps)}", status=400),
                )
            for cap_bool_key in ("coordinator_peer", "host_server_invoke", "can_dispatch", "can_receive"):
                ok_cb, _cb_val, cb_err = _validate_strict_bool(caps, cap_bool_key)
                if not ok_cb:
                    return False, None, _api_error(f"capabilities.{cb_err}", status=400)
            ok_at, _at_val, at_err = _validate_strict_str_list(caps, "allowed_teams")
            if not ok_at:
                return False, None, _api_error(f"capabilities.{at_err}", status=400)

        return True, body, None

    # ------------------------------------------------------------------ Loopback Hub Health Probe (M3-C4)
    async def probe_hub_health(self) -> dict[str, Any]:
        """Strictly loopback-bound Hub health probe (`allow_redirects=False`, timeout <= 3s).

        Completely ignores any client query/body parameters and environment HTTP proxies.
        """
        raw_host, raw_port = self._effective_hub_host_port()
        ok_cfg, fmt_host, port, cfg_err = _validate_loopback_hub_target(raw_host, raw_port)
        checked_at = _utc_iso_now()
        if not ok_cfg:
            return {
                "ok": True,
                "reachable": False,
                "status": "misconfigured",
                "reason": cfg_err,
                "service": "agy-federation-hub",
                "latency_ms": None,
                "checked_at": checked_at,
            }

        url = f"http://{fmt_host}:{port}/hub/v1/health"
        timeout = aiohttp.ClientTimeout(total=self.health_timeout_sec)
        t0 = time.monotonic()
        try:
            async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as client:
                async with client.get(url, allow_redirects=False) as resp:
                    latency_ms = round((time.monotonic() - t0) * 1000.0, 1)
                    if 300 <= resp.status < 400:
                        return {
                            "ok": True,
                            "reachable": False,
                            "status": "redirect_blocked",
                            "service": "agy-federation-hub",
                            "latency_ms": latency_ms,
                            "checked_at": checked_at,
                        }
                    if resp.status != 200:
                        return {
                            "ok": True,
                            "reachable": False,
                            "status": "unhealthy",
                            "http_status": resp.status,
                            "service": "agy-federation-hub",
                            "latency_ms": latency_ms,
                            "checked_at": checked_at,
                        }
                    raw_body = await resp.content.read(8192)
                    try:
                        data = json.loads(raw_body.decode("utf-8", errors="replace"))
                    except Exception:
                        data = None
                    if not isinstance(data, dict) or data.get("ok") is not True:
                        return {
                            "ok": True,
                            "reachable": False,
                            "status": "invalid_response",
                            "service": "agy-federation-hub",
                            "latency_ms": latency_ms,
                            "checked_at": checked_at,
                        }
                    svc = _sanitize_slug(str(data.get("service") or "agy-federation-hub"), max_len=64) or "agy-federation-hub"
                    return {
                        "ok": True,
                        "reachable": True,
                        "status": "healthy",
                        "service": svc,
                        "latency_ms": latency_ms,
                        "checked_at": checked_at,
                    }
        except asyncio.TimeoutError:
            return {
                "ok": True,
                "reachable": False,
                "status": "timeout",
                "service": "agy-federation-hub",
                "latency_ms": round((time.monotonic() - t0) * 1000.0, 1),
                "checked_at": checked_at,
            }
        except Exception:
            return {
                "ok": True,
                "reachable": False,
                "status": "unreachable",
                "service": "agy-federation-hub",
                "latency_ms": round((time.monotonic() - t0) * 1000.0, 1),
                "checked_at": checked_at,
            }

    # ------------------------------------------------------------------ Read Endpoints
    async def handle_get_overview(self, request: web.Request) -> web.Response:
        ok, sess, err, sc = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=sc)

        agents_raw = await asyncio.to_thread(
            federation_registry.list_agents,
            bus_dir=self.bus_dir,
            include_disabled=True,
            include_revoked=True,
        )
        teams_raw = await asyncio.to_thread(
            federation_registry.list_teams,
            bus_dir=self.bus_dir,
        )
        hub_health = await self.probe_hub_health()

        viewer_role = str(sess.get("role") or "")
        agents = [_sanitize_agent_record(a, viewer_role=viewer_role) for a in agents_raw]
        teams = [self._annotate_team_warnings(t)[0] for t in teams_raw]

        hub_config = self._build_hub_config()

        counts = {
            "agents_total": len(agents),
            "agents_enabled": sum(1 for a in agents if a.get("enabled") and not a.get("revoked")),
            "agents_revoked": sum(1 for a in agents if a.get("revoked")),
            "agents_coordinator_peer": sum(
                1 for a in agents if not a.get("revoked") and bool((a.get("capabilities") or {}).get("coordinator_peer"))
            ),
            "agents_host_invoke": sum(
                1 for a in agents if not a.get("revoked") and bool((a.get("capabilities") or {}).get("host_server_invoke"))
            ),
            "teams_total": len(teams),
        }

        return web.json_response(
            {
                "ok": True,
                "can_edit": sess.get("role") == "admin",
                "agents": agents,
                "teams": teams,
                "counts": counts,
                "hub_health": hub_health,
                "hub_config": hub_config,
                "hard_locks": THREE_HARD_LOCKS_SUMMARY,
                "updated_at": _utc_iso_now(),
            }
        )

    async def handle_get_health(self, request: web.Request) -> web.Response:
        ok, sess, err, sc = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=sc)
        # Explicitly ignores all request.query / body parameters (M3-C4 anti-SSRF)
        health = await self.probe_hub_health()
        return web.json_response(health)

    async def handle_list_agents(self, request: web.Request) -> web.Response:
        ok, sess, err, sc = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=sc)
        agents_raw = await asyncio.to_thread(
            federation_registry.list_agents,
            bus_dir=self.bus_dir,
            include_disabled=True,
            include_revoked=True,
        )
        viewer_role = str(sess.get("role") or "")
        agents = [_sanitize_agent_record(a, viewer_role=viewer_role) for a in agents_raw]
        return web.json_response(
            {
                "ok": True,
                "can_edit": sess.get("role") == "admin",
                "total": len(agents),
                "agents": agents,
            }
        )

    async def handle_get_agent(self, request: web.Request) -> web.Response:
        ok, sess, err, sc = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=sc)
        raw_aid = request.match_info.get("agent_id", "")
        try:
            aid = federation_registry.validate_agent_id(raw_aid)
        except ValueError as exc:
            return _api_error(str(exc), status=400)
        rec = await asyncio.to_thread(federation_registry.get_agent, aid, bus_dir=self.bus_dir)
        if rec is None:
            return _api_error(f"未找到 Agent: {aid}", status=404)
        viewer_role = str(sess.get("role") or "")
        return web.json_response(
            {
                "ok": True,
                "can_edit": sess.get("role") == "admin",
                "agent": _sanitize_agent_record(rec, viewer_role=viewer_role),
            }
        )

    async def handle_list_teams(self, request: web.Request) -> web.Response:
        ok, sess, err, sc = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=sc)
        teams_raw = await asyncio.to_thread(federation_registry.list_teams, bus_dir=self.bus_dir)
        teams = [self._annotate_team_warnings(t)[0] for t in teams_raw]
        return web.json_response(
            {
                "ok": True,
                "can_edit": sess.get("role") == "admin",
                "total": len(teams),
                "teams": teams,
            }
        )

    async def handle_get_audit(self, request: web.Request) -> web.Response:
        ok, sess, err, sc = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=sc)
        if sess.get("role") != "admin":
            return studio_auth_error("仅管理员（admin）可查看联邦审计日志", status=403)

        raw_limit = request.query.get("limit", str(DEFAULT_AUDIT_LIMIT)).strip()
        raw_offset = request.query.get("offset", "0").strip()
        try:
            limit = int(raw_limit)
        except ValueError:
            return _api_error("limit 必须为正整数", status=400)
        if limit < 1:
            return _api_error("limit 必须 >= 1", status=400)
        limit = min(limit, MAX_AUDIT_LIMIT)

        try:
            offset = int(raw_offset)
        except ValueError:
            return _api_error("offset 必须为非负整数", status=400)
        if offset < 0:
            return _api_error("offset 必须 >= 0", status=400)

        actor_filter = (request.query.get("actor_id") or "").strip()[:64]
        event_filter = (request.query.get("event") or "").strip()[:64]

        ok_read, data, read_err = await asyncio.to_thread(
            _read_federation_audit_no_symlink,
            self.bus_dir,
            limit=limit,
            offset=offset,
            actor_filter=actor_filter,
            event_filter=event_filter,
        )
        if not ok_read:
            return _api_error(read_err, status=403, code="SECURITY_SYMLINK_REJECTED")
        return web.json_response({"ok": True, **data})

    # ------------------------------------------------------------------ Agent Write Endpoints
    @staticmethod
    def _normalize_kind_driver_transport(body: dict[str, Any]) -> tuple[str, str, str]:
        raw_kind = str(body.get("kind") or "").strip().lower()
        raw_driver = str(body.get("driver") or "").strip().lower()
        raw_transport = str(body.get("transport") or "").strip().lower()
        if raw_kind == "pull_worker":
            raw_kind = "http_a2a"
            if not raw_driver:
                raw_driver = "pull_worker"
            if not raw_transport:
                raw_transport = "pull_worker"
        return raw_kind, raw_driver, raw_transport

    async def handle_create_agent(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="federation.agent.create")
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        ok_body, body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.agent.create",
            allowed_keys=_ALLOWED_CREATE_AGENT_KEYS,
            allow_empty=False,
        )
        if not ok_body or body is None:
            return body_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        raw_aid = body.get("agent_id")
        try:
            aid = federation_registry.validate_agent_id(raw_aid)
        except ValueError as exc:
            self.audit.record(
                action="federation.agent.create",
                status_code=400,
                outcome="invalid_agent_id",
                client_ip=client_ip,
                sess=sess,
            )
            return _api_error(str(exc), status=400)

        norm_kind, norm_driver, norm_transport = self._normalize_kind_driver_transport(body)
        ok_mt, mint_token_val, err_mt = _validate_strict_bool(body, "mint_token", default=False)
        if not ok_mt:
            return _api_error(err_mt, status=400)
        ok_en, enabled_val, err_en = _validate_strict_bool(body, "enabled", default=True)
        if not ok_en:
            return _api_error(err_en, status=400)
        ok_ow, overwrite_val, err_ow = _validate_strict_bool(body, "overwrite", default=False)
        if not ok_ow:
            return _api_error(err_ow, status=400)
        ok_md, metadata_val, err_md = _validate_optional_dict(body, "metadata")
        if not ok_md:
            return _api_error(err_md, status=400)
        mint_token = bool(mint_token_val)
        token_label = str(body.get("token_label") or "studio-initial").strip()[:80]

        try:
            owner_auth = self._make_studio_owner_auth(sess)
            agent = await asyncio.to_thread(
                federation_registry.register_agent,
                aid,
                kind=norm_kind,
                owner_auth=owner_auth,
                display_name=str(body.get("display_name") or ""),
                driver=norm_driver,
                profile=str(body.get("profile") or ""),
                endpoint_url=str(body.get("endpoint_url") or ""),
                secret_ref=str(body.get("secret_ref") or ""),
                transport=norm_transport,
                capabilities=body.get("capabilities"),
                trust_level=body.get("trust_level"),
                enabled=bool(enabled_val),
                metadata=metadata_val,
                overwrite=bool(overwrite_val),
                bus_dir=self.bus_dir,
            )
            minted: dict[str, Any] | None = None
            if mint_token:
                minted = await asyncio.to_thread(
                    federation_registry.mint_agent_token,
                    aid,
                    owner_auth=owner_auth,
                    label=token_label,
                    bus_dir=self.bus_dir,
                )
                refreshed = await asyncio.to_thread(federation_registry.get_agent, aid, bus_dir=self.bus_dir)
                if refreshed is not None:
                    agent = refreshed
        except PermissionError as exc:
            self.audit.record(
                action="federation.agent.create",
                status_code=403,
                outcome="denied_owner_auth",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            msg = str(exc)
            sc = 409 if "already registered" in msg.lower() else 400
            self.audit.record(
                action="federation.agent.create",
                status_code=sc,
                outcome="invalid_request",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(msg, status=sc)

        self.audit.record(
            action="federation.agent.create",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=aid,
            sess=sess,
        )
        self._publish_federation_updated(action="agent_created", agent_id=aid)

        resp_payload: dict[str, Any] = {
            "ok": True,
            "agent": _sanitize_agent_record(agent, viewer_role="admin"),
        }
        headers: dict[str, str] = {}
        if minted is not None:
            resp_payload["token"] = minted["token"]
            resp_payload["token_id"] = minted["token_id"]
            resp_payload["token_created_at"] = minted["created_at"]
            headers = dict(_NO_STORE_TOKEN_HEADERS)
        return web.json_response(resp_payload, headers=headers)

    async def handle_patch_agent(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("agent_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="federation.agent.update", target_id=raw_aid
        )
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        try:
            aid = federation_registry.validate_agent_id(raw_aid)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        ok_body, body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.agent.update",
            allowed_keys=_ALLOWED_PATCH_AGENT_KEYS,
            allow_empty=False,
            target_id=aid,
        )
        if not ok_body or body is None:
            return body_resp  # type: ignore[return-value]

        for bool_k in ("enabled", "revoked"):
            ok_b, _b_val, err_b = _validate_strict_bool(body, bool_k)
            if not ok_b:
                return _api_error(err_b, status=400)
        ok_md, _md_val, err_md = _validate_optional_dict(body, "metadata")
        if not ok_md:
            return _api_error(err_md, status=400)

        updates = dict(body)
        if "kind" in updates:
            raw_kind = str(updates.get("kind") or "").strip().lower()
            if raw_kind == "pull_worker":
                updates["kind"] = "http_a2a"
                updates.setdefault("driver", "pull_worker")
                updates.setdefault("transport", "pull_worker")
            elif raw_kind in federation_registry.VALID_AGENT_KINDS:
                existing = await asyncio.to_thread(federation_registry.get_agent, aid, bus_dir=self.bus_dir)
                if isinstance(existing, dict) and (
                    existing.get("kind") != raw_kind
                    or existing.get("driver") == "pull_worker"
                    or existing.get("transport") == "pull_worker"
                ):
                    def_driver, def_transport = federation_registry._default_driver_and_transport(raw_kind)
                    if "driver" not in body or not str(body.get("driver") or "").strip():
                        updates["driver"] = def_driver
                    if "transport" not in body or not str(body.get("transport") or "").strip():
                        updates["transport"] = def_transport

        try:
            owner_auth = self._make_studio_owner_auth(sess)
            updated = await asyncio.to_thread(
                federation_registry.update_agent,
                aid,
                owner_auth=owner_auth,
                bus_dir=self.bus_dir,
                **updates,
            )
        except PermissionError as exc:
            self.audit.record(
                action="federation.agent.update",
                status_code=403,
                outcome="denied_owner_auth",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            msg = str(exc)
            sc = 404 if "unknown agent_id" in msg.lower() else 400
            self.audit.record(
                action="federation.agent.update",
                status_code=sc,
                outcome="invalid_request",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(msg, status=sc)

        self.audit.record(
            action="federation.agent.update",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=aid,
            sess=sess,
        )
        self._publish_federation_updated(action="agent_updated", agent_id=aid)
        return web.json_response({"ok": True, "agent": _sanitize_agent_record(updated, viewer_role="admin")})

    async def handle_delete_agent(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("agent_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="federation.agent.delete", target_id=raw_aid
        )
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        try:
            aid = federation_registry.validate_agent_id(raw_aid)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        ok_body, _body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.agent.delete",
            allowed_keys=frozenset(),
            allow_empty=True,
            target_id=aid,
        )
        if not ok_body:
            return body_resp  # type: ignore[return-value]

        try:
            owner_auth = self._make_studio_owner_auth(sess)
            deleted = await asyncio.to_thread(
                federation_registry.delete_agent,
                aid,
                owner_auth=owner_auth,
                bus_dir=self.bus_dir,
            )
        except PermissionError as exc:
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        if not deleted:
            self.audit.record(
                action="federation.agent.delete",
                status_code=404,
                outcome="not_found",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(f"未找到 Agent: {aid}", status=404)

        self.audit.record(
            action="federation.agent.delete",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=aid,
            sess=sess,
        )
        self._publish_federation_updated(action="agent_deleted", agent_id=aid)
        return web.json_response({"ok": True, "deleted": True, "agent_id": aid})

    async def handle_mint_token(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("agent_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="federation.agent.token_mint", target_id=raw_aid
        )
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        try:
            aid = federation_registry.validate_agent_id(raw_aid)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        ok_body, body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.agent.token_mint",
            allowed_keys=_ALLOWED_MINT_TOKEN_KEYS,
            allow_empty=True,
            target_id=aid,
        )
        if not ok_body or body is None:
            return body_resp  # type: ignore[return-value]

        ok_scope, scope_val, err_scope = _validate_strict_token_scope(body)
        if not ok_scope:
            self.audit.record(
                action="federation.agent.token_mint",
                status_code=400,
                outcome="invalid_scope",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(err_scope, status=400, code="INVALID_TOKEN_SCOPE")

        label = str(body.get("label") or "studio").strip()[:80]
        try:
            owner_auth = self._make_studio_owner_auth(sess)
            minted = await asyncio.to_thread(
                federation_registry.mint_agent_token,
                aid,
                owner_auth=owner_auth,
                label=label,
                scope=scope_val,
                bus_dir=self.bus_dir,
            )
            agent = await asyncio.to_thread(federation_registry.get_agent, aid, bus_dir=self.bus_dir)
        except PermissionError as exc:
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            msg = str(exc)
            sc = 404 if "unknown agent_id" in msg.lower() else 400
            self.audit.record(
                action="federation.agent.token_mint",
                status_code=sc,
                outcome="invalid_request",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(msg, status=sc)

        self.audit.record(
            action="federation.agent.token_mint",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=aid,
            sess=sess,
        )
        self._publish_federation_updated(action="token_minted", agent_id=aid)
        return web.json_response(
            {
                "ok": True,
                "agent_id": aid,
                "token_id": minted["token_id"],
                "token": minted["token"],
                "scope": minted["scope"],
                "created_at": minted["created_at"],
                "agent": _sanitize_agent_record(agent, viewer_role="admin") if agent is not None else None,
            },
            headers=_NO_STORE_TOKEN_HEADERS,
        )

    async def handle_rotate_token(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("agent_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="federation.agent.token_rotate", target_id=raw_aid
        )
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        try:
            aid = federation_registry.validate_agent_id(raw_aid)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        ok_body, body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.agent.token_rotate",
            allowed_keys=_ALLOWED_ROTATE_TOKEN_KEYS,
            allow_empty=True,
            target_id=aid,
        )
        if not ok_body or body is None:
            return body_resp  # type: ignore[return-value]

        ok_scope, scope_val, err_scope = _validate_strict_token_scope(body)
        if not ok_scope:
            self.audit.record(
                action="federation.agent.token_rotate",
                status_code=400,
                outcome="invalid_scope",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(err_scope, status=400, code="INVALID_TOKEN_SCOPE")

        label = str(body.get("label") or "studio-rotated").strip()[:80]
        ok_re, revoke_existing_val, err_re = _validate_strict_bool(body, "revoke_existing", default=True)
        if not ok_re:
            return _api_error(err_re, status=400)
        revoke_existing = bool(revoke_existing_val)
        try:
            owner_auth = self._make_studio_owner_auth(sess)
            rotated = await asyncio.to_thread(
                federation_registry.rotate_agent_token,
                aid,
                owner_auth=owner_auth,
                revoke_existing=revoke_existing,
                label=label,
                scope=scope_val,
                bus_dir=self.bus_dir,
            )
            agent = await asyncio.to_thread(federation_registry.get_agent, aid, bus_dir=self.bus_dir)
        except PermissionError as exc:
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            msg = str(exc)
            sc = 404 if "unknown agent_id" in msg.lower() else 400
            self.audit.record(
                action="federation.agent.token_rotate",
                status_code=sc,
                outcome="invalid_request",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(msg, status=sc)

        self.audit.record(
            action="federation.agent.token_rotate",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=aid,
            sess=sess,
        )
        self._publish_federation_updated(action="token_rotated", agent_id=aid)
        return web.json_response(
            {
                "ok": True,
                "agent_id": aid,
                "token_id": rotated["token_id"],
                "token": rotated["token"],
                "scope": rotated["scope"],
                "revoked_previous": rotated["revoked_previous"],
                "created_at": rotated["created_at"],
                "agent": _sanitize_agent_record(agent, viewer_role="admin") if agent is not None else None,
            },
            headers=_NO_STORE_TOKEN_HEADERS,
        )

    async def handle_revoke_agent(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("agent_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="federation.agent.revoke", target_id=raw_aid
        )
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        try:
            aid = federation_registry.validate_agent_id(raw_aid)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        ok_body, _body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.agent.revoke",
            allowed_keys=frozenset(),
            allow_empty=True,
            target_id=aid,
        )
        if not ok_body:
            return body_resp  # type: ignore[return-value]

        try:
            owner_auth = self._make_studio_owner_auth(sess)
            revoked = await asyncio.to_thread(
                federation_registry.revoke_agent,
                aid,
                owner_auth=owner_auth,
                bus_dir=self.bus_dir,
            )
        except PermissionError as exc:
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            msg = str(exc)
            sc = 404 if "unknown agent_id" in msg.lower() else 400
            self.audit.record(
                action="federation.agent.revoke",
                status_code=sc,
                outcome="invalid_request",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(msg, status=sc)

        self.audit.record(
            action="federation.agent.revoke",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=aid,
            sess=sess,
        )
        self._publish_federation_updated(action="agent_revoked", agent_id=aid)
        return web.json_response({"ok": True, "agent": _sanitize_agent_record(revoked, viewer_role="admin")})

    # ------------------------------------------------------------------ Team Write Endpoints (M3-C3)
    async def handle_create_team(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="federation.team.create")
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        ok_body, body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.team.create",
            allowed_keys=_ALLOWED_CREATE_TEAM_KEYS,
            allow_empty=False,
        )
        if not ok_body or body is None:
            return body_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        try:
            tid = federation_registry.validate_team_id(body.get("team_id"))
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        ok_cl, co_leaders_val, err_cl = _validate_strict_str_list(body, "co_leaders")
        if not ok_cl:
            return _api_error(err_cl, status=400)
        ok_mb, members_val, err_mb = _validate_strict_str_list(body, "members")
        if not ok_mb:
            return _api_error(err_mb, status=400)
        ok_md, metadata_val, err_md = _validate_optional_dict(body, "metadata")
        if not ok_md:
            return _api_error(err_md, status=400)
        ok_ow, overwrite_val, err_ow = _validate_strict_bool(body, "overwrite", default=False)
        if not ok_ow:
            return _api_error(err_ow, status=400)

        try:
            owner_auth = self._make_studio_owner_auth(sess)
            team = await asyncio.to_thread(
                federation_registry.create_team,
                tid,
                owner_auth=owner_auth,
                display_name=str(body.get("display_name") or ""),
                leader_agent_id=str(body.get("leader_agent_id") or ""),
                co_leaders=co_leaders_val,
                members=members_val,
                metadata=metadata_val,
                require_registered=True,
                overwrite=bool(overwrite_val),
                bus_dir=self.bus_dir,
            )
        except PermissionError as exc:
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            msg = str(exc)
            sc = 409 if "already exists" in msg.lower() else 400
            self.audit.record(
                action="federation.team.create",
                status_code=sc,
                outcome="invalid_request",
                client_ip=client_ip,
                target_id=tid,
                sess=sess,
            )
            return _api_error(msg, status=sc)

        annotated, leader_can_dispatch, warnings = self._annotate_team_warnings(team)
        self.audit.record(
            action="federation.team.create",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=tid,
            sess=sess,
        )
        self._publish_federation_updated(action="team_created", team_id=tid)
        return web.json_response(
            {
                "ok": True,
                "team": annotated,
                "leader_can_dispatch": leader_can_dispatch,
                "warnings": warnings,
            }
        )

    async def handle_patch_team(self, request: web.Request) -> web.Response:
        raw_tid = request.match_info.get("team_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="federation.team.update", target_id=raw_tid
        )
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        try:
            tid = federation_registry.validate_team_id(raw_tid)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        ok_body, body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.team.update",
            allowed_keys=_ALLOWED_PATCH_TEAM_KEYS,
            allow_empty=False,
            target_id=tid,
        )
        if not ok_body or body is None:
            return body_resp  # type: ignore[return-value]

        ok_cl, co_leaders_val, err_cl = _validate_strict_str_list(body, "co_leaders")
        if not ok_cl:
            return _api_error(err_cl, status=400)
        ok_mb, members_val, err_mb = _validate_strict_str_list(body, "members")
        if not ok_mb:
            return _api_error(err_mb, status=400)
        ok_md, metadata_val, err_md = _validate_optional_dict(body, "metadata")
        if not ok_md:
            return _api_error(err_md, status=400)

        try:
            owner_auth = self._make_studio_owner_auth(sess)
            team = await asyncio.to_thread(
                federation_registry.update_team,
                tid,
                owner_auth=owner_auth,
                display_name=body.get("display_name") if "display_name" in body else None,
                leader_agent_id=body.get("leader_agent_id") if "leader_agent_id" in body else None,
                co_leaders=co_leaders_val if "co_leaders" in body else None,
                members=members_val if "members" in body else None,
                metadata=metadata_val if "metadata" in body else None,
                require_registered=True,
                bus_dir=self.bus_dir,
            )
        except PermissionError as exc:
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            msg = str(exc)
            sc = 404 if "unknown team_id" in msg.lower() else 400
            self.audit.record(
                action="federation.team.update",
                status_code=sc,
                outcome="invalid_request",
                client_ip=client_ip,
                target_id=tid,
                sess=sess,
            )
            return _api_error(msg, status=sc)

        annotated, leader_can_dispatch, warnings = self._annotate_team_warnings(team)
        self.audit.record(
            action="federation.team.update",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=tid,
            sess=sess,
        )
        self._publish_federation_updated(action="team_updated", team_id=tid)
        return web.json_response(
            {
                "ok": True,
                "team": annotated,
                "leader_can_dispatch": leader_can_dispatch,
                "warnings": warnings,
            }
        )

    async def handle_set_team_leader(self, request: web.Request) -> web.Response:
        raw_tid = request.match_info.get("team_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="federation.team.set_leader", target_id=raw_tid
        )
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        try:
            tid = federation_registry.validate_team_id(raw_tid)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        ok_body, body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.team.set_leader",
            allowed_keys=_ALLOWED_SET_LEADER_KEYS,
            allow_empty=False,
            target_id=tid,
        )
        if not ok_body or body is None:
            return body_resp  # type: ignore[return-value]

        raw_leader = body.get("leader_agent_id")
        try:
            leader_id = federation_registry.validate_agent_id(raw_leader)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        ok_cl, co_leaders_val, err_cl = _validate_strict_str_list(body, "co_leaders")
        if not ok_cl:
            return _api_error(err_cl, status=400)

        try:
            owner_auth = self._make_studio_owner_auth(sess)
            team = await asyncio.to_thread(
                federation_registry.set_team_leader,
                tid,
                leader_id,
                owner_auth=owner_auth,
                co_leaders=co_leaders_val if "co_leaders" in body else None,
                require_registered=True,
                bus_dir=self.bus_dir,
            )
        except PermissionError as exc:
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            msg = str(exc)
            sc = 404 if "unknown team_id" in msg.lower() else 400
            self.audit.record(
                action="federation.team.set_leader",
                status_code=sc,
                outcome="invalid_request",
                client_ip=client_ip,
                target_id=tid,
                sess=sess,
            )
            return _api_error(msg, status=sc)

        annotated, leader_can_dispatch, warnings = self._annotate_team_warnings(team)
        self.audit.record(
            action="federation.team.set_leader",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=tid,
            sess=sess,
        )
        self._publish_federation_updated(action="team_leader_updated", team_id=tid)
        return web.json_response(
            {
                "ok": True,
                "team": annotated,
                "leader_can_dispatch": leader_can_dispatch,
                "warnings": warnings,
            }
        )

    async def handle_delete_team(self, request: web.Request) -> web.Response:
        raw_tid = request.match_info.get("team_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="federation.team.delete", target_id=raw_tid
        )
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        try:
            tid = federation_registry.validate_team_id(raw_tid)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        ok_body, _body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.team.delete",
            allowed_keys=frozenset(),
            allow_empty=True,
            target_id=tid,
        )
        if not ok_body:
            return body_resp  # type: ignore[return-value]

        try:
            owner_auth = self._make_studio_owner_auth(sess)
            deleted = await asyncio.to_thread(
                federation_registry.delete_team,
                tid,
                owner_auth=owner_auth,
                bus_dir=self.bus_dir,
            )
        except PermissionError as exc:
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        if not deleted:
            self.audit.record(
                action="federation.team.delete",
                status_code=404,
                outcome="not_found",
                client_ip=client_ip,
                target_id=tid,
                sess=sess,
            )
            return _api_error(f"未找到团队: {tid}", status=404)

        self.audit.record(
            action="federation.team.delete",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=tid,
            sess=sess,
        )
        self._publish_federation_updated(action="team_deleted", team_id=tid)
        return web.json_response({"ok": True, "deleted": True, "team_id": tid})

    # ------------------------------------------------------------------ Federation Workbench Endpoints
    def _build_workbench_snapshot_sync(self, *, viewer_role: str) -> tuple[bool, dict[str, Any], str]:
        """Pure read-only, zero-side-effect anti-symlink workbench snapshot builder."""
        # Verify federation, pull_queue, leader_events, and jobs dirs have no symlinks
        ok_ag, agents_map, err_ag = _read_agents_map_no_symlink(self.bus_dir)
        if not ok_ag:
            return False, {}, err_ag

        ok_pq, pull_jobs, err_pq = _scan_json_dir_no_symlink(self.bus_dir, ("federation", "pull_queue"))
        if not ok_pq:
            return False, {}, err_pq

        ok_le_root, le_root_fd, err_le_root = _open_dir_chain_no_symlink(
            self.bus_dir, ("federation", "leader_events")
        )
        if not ok_le_root:
            return False, {}, err_le_root
        if le_root_fd is not None:
            os.close(le_root_fd)

        ok_bj, bus_jobs, err_bj = _scan_json_dir_no_symlink(self.bus_dir, ("jobs",))
        if not ok_bj:
            return False, {}, err_bj

        now_ts = time.time()
        ok_pr, presence_map, err_pr = _read_presence_map_no_symlink(self.bus_dir, now_ts=now_ts)
        if not ok_pr:
            return False, {}, err_pr

        roster_last_seen = _read_roster_last_seen_no_symlink(self.bus_dir)

        pull_by_agent: dict[str, list[dict[str, Any]]] = {}
        for pj in pull_jobs:
            t_aid = str(pj.get("target_agent_id") or "").strip().lower()
            if t_aid:
                pull_by_agent.setdefault(t_aid, []).append(pj)

        bus_by_agent: dict[str, list[dict[str, Any]]] = {}
        for bj in bus_jobs:
            t_bot = str(bj.get("target_bot") or "").strip().lower()
            if t_bot:
                bus_by_agent.setdefault(t_bot, []).append(bj)

        workbench_agents: list[dict[str, Any]] = []
        for aid in sorted(agents_map.keys()):
            raw_ag = agents_map[aid]
            kind = str(raw_ag.get("kind") or "").strip().lower()
            if kind == "agy_local":
                continue

            ok_ev, ev_list, err_ev = _scan_json_dir_no_symlink(
                self.bus_dir, ("federation", "leader_events", aid)
            )
            if not ok_ev:
                return False, {}, err_ev

            ag_pull = pull_by_agent.get(aid, [])
            ag_bus = bus_by_agent.get(aid, [])

            pq_counts = {"queued": 0, "claimed": 0, "done": 0, "error": 0, "cancelled": 0, "total": 0}
            live_timestamps: list[float] = []
            activity_timestamps: list[float] = []
            has_active_exec = False

            for pj in ag_pull:
                st = str(pj.get("status") or "queued").strip().lower()
                if st in pq_counts:
                    pq_counts[st] += 1
                pq_counts["total"] += 1
                if st == "claimed":
                    has_active_exec = True
                for t_val in (
                    _safe_float_ts(pj.get("claimed_at")),
                    _safe_float_ts(pj.get("finished_at")),
                ):
                    if t_val > 0:
                        live_timestamps.append(t_val)
                        activity_timestamps.append(t_val)
                c_ts = _safe_float_ts(pj.get("created_at"))
                if c_ts > 0:
                    activity_timestamps.append(c_ts)

            bj_counts = {"queued": 0, "running": 0, "done": 0, "error": 0, "cancelled": 0, "total": 0}
            for bj in ag_bus:
                st = str(bj.get("status") or "queued").strip().lower()
                if st == "failed":
                    st = "error"
                if st in bj_counts:
                    bj_counts[st] += 1
                bj_counts["total"] += 1
                if st == "running":
                    has_active_exec = True
                for t_val in (
                    _safe_float_ts(bj.get("started_at")),
                    _safe_float_ts(bj.get("finished_at")),
                ):
                    if t_val > 0:
                        live_timestamps.append(t_val)
                        activity_timestamps.append(t_val)
                c_ts = _safe_float_ts(bj.get("created_at"))
                if c_ts > 0:
                    activity_timestamps.append(c_ts)

            for ev in ev_list:
                e_ts = _safe_float_ts(ev.get("created_at"))
                if e_ts > 0:
                    activity_timestamps.append(e_ts)

            if aid in roster_last_seen:
                live_timestamps.append(roster_last_seen[aid])
                activity_timestamps.append(roster_last_seen[aid])

            last_heartbeat_at: float | None = None
            last_heartbeat_action = ""
            pres = presence_map.get(aid)
            if isinstance(pres, dict):
                for p_ts in (pres.get("last_seen_at"), pres.get("last_peek_at")):
                    if isinstance(p_ts, float) and p_ts > 0:
                        live_timestamps.append(p_ts)
                        activity_timestamps.append(p_ts)
                p_hb = pres.get("last_heartbeat_at")
                if isinstance(p_hb, float) and p_hb > 0:
                    last_heartbeat_at = p_hb
                    last_heartbeat_action = str(pres.get("last_action") or "")

            ag_meta = raw_ag.get("metadata") if isinstance(raw_ag.get("metadata"), dict) else {}
            for meta_ts_key in ("last_seen", "last_heartbeat_at"):
                m_ts = _safe_float_ts(raw_ag.get(meta_ts_key)) or _safe_float_ts(ag_meta.get(meta_ts_key))
                if m_ts > 0:
                    live_timestamps.append(m_ts)
                    activity_timestamps.append(m_ts)

            last_live_ts = max(live_timestamps) if live_timestamps else 0.0
            last_activity_at = max(activity_timestamps) if activity_timestamps else None

            adapter_type, dispatch_mode, target_can_dispatch, disabled_reason = _classify_workbench_agent(raw_ag)
            runtime_status = _compute_runtime_status(
                raw_ag,
                last_live_ts=last_live_ts,
                has_active_execution=has_active_exec,
                now_ts=now_ts,
            )

            clean_ag = _sanitize_agent_record(raw_ag, viewer_role=viewer_role)
            clean_ag = _sanitize_public_value(clean_ag, scrub_host_paths=True)
            # Re-apply validated admin-only secret_ref after deep scrub
            raw_ref = str(raw_ag.get("secret_ref") or "").strip()
            if (
                viewer_role == "admin"
                and raw_ref
                and federation_registry.SECRET_REF_RE.fullmatch(raw_ref)
                and not _FED_TOKEN_RE.search(raw_ref)
            ):
                clean_ag["secret_ref"] = raw_ref
            else:
                clean_ag["secret_ref"] = ""
            clean_ag["has_secret_ref"] = bool(raw_ref)

            clean_ag["runtime_status"] = runtime_status
            clean_ag["adapter_type"] = adapter_type
            clean_ag["dispatch_mode"] = dispatch_mode
            clean_ag["can_dispatch"] = target_can_dispatch
            clean_ag["dispatch_disabled_reason"] = disabled_reason
            clean_ag["pull_queue_counts"] = pq_counts
            clean_ag["bus_job_counts"] = bj_counts
            clean_ag["leader_events_count"] = len(ev_list)
            clean_ag["last_activity_at"] = last_activity_at
            clean_ag["last_heartbeat_at"] = last_heartbeat_at
            clean_ag["last_heartbeat_action"] = last_heartbeat_action
            workbench_agents.append(clean_ag)

        return (
            True,
            {
                "agents": workbench_agents,
                "hub_config": self._build_hub_config(),
                "can_edit": viewer_role == "admin",
                "role": viewer_role or "readonly",
                "updated_at": _utc_iso_now(),
            },
            "",
        )

    def _build_agent_timeline_sync(
        self,
        aid: str,
        *,
        limit: int,
        viewer_role: str,
    ) -> tuple[bool, int, dict[str, Any], str]:
        """Pure read-only, zero-side-effect anti-symlink agent timeline & telemetry builder."""
        ok_ag, agents_map, err_ag = _read_agents_map_no_symlink(self.bus_dir)
        if not ok_ag:
            return False, 403, {}, err_ag

        ok_pq, pull_jobs, err_pq = _scan_json_dir_no_symlink(self.bus_dir, ("federation", "pull_queue"))
        if not ok_pq:
            return False, 403, {}, err_pq

        ok_le_root, le_root_fd, err_le_root = _open_dir_chain_no_symlink(
            self.bus_dir, ("federation", "leader_events")
        )
        if not ok_le_root:
            return False, 403, {}, err_le_root
        if le_root_fd is not None:
            os.close(le_root_fd)

        ok_ev, ev_list, err_ev = _scan_json_dir_no_symlink(
            self.bus_dir, ("federation", "leader_events", aid)
        )
        if not ok_ev:
            return False, 403, {}, err_ev

        ok_bj, bus_jobs, err_bj = _scan_json_dir_no_symlink(self.bus_dir, ("jobs",))
        if not ok_bj:
            return False, 403, {}, err_bj

        now_ts = time.time()
        ok_pr, presence_map, err_pr = _read_presence_map_no_symlink(self.bus_dir, now_ts=now_ts)
        if not ok_pr:
            return False, 403, {}, err_pr

        raw_ag = agents_map.get(aid)
        if not isinstance(raw_ag, dict):
            return False, 404, {}, f"未找到外部 Agent: {aid}"

        is_admin = viewer_role == "admin"

        pull_by_jid: dict[str, dict[str, Any]] = {}
        pq_counts = {"queued": 0, "claimed": 0, "done": 0, "error": 0, "cancelled": 0, "total": 0}
        live_ts_list: list[float] = []
        act_ts_list: list[float] = []
        has_active_exec = False

        for pj in pull_jobs:
            if str(pj.get("target_agent_id") or "").strip().lower() != aid:
                continue
            jid = str(pj.get("job_id") or "").strip()
            if not jid:
                continue
            pull_by_jid[jid] = pj
            st = str(pj.get("status") or "queued").strip().lower()
            if st in pq_counts:
                pq_counts[st] += 1
            pq_counts["total"] += 1
            if st == "claimed":
                has_active_exec = True
            for tv in (_safe_float_ts(pj.get("claimed_at")), _safe_float_ts(pj.get("finished_at"))):
                if tv > 0:
                    live_ts_list.append(tv)
                    act_ts_list.append(tv)
            ct = _safe_float_ts(pj.get("created_at"))
            if ct > 0:
                act_ts_list.append(ct)

        bus_by_jid: dict[str, dict[str, Any]] = {}
        bj_counts = {"queued": 0, "running": 0, "done": 0, "error": 0, "cancelled": 0, "total": 0}
        for bj in bus_jobs:
            if str(bj.get("target_bot") or "").strip().lower() != aid:
                continue
            jid = str(bj.get("job_id") or "").strip()
            if not jid:
                continue
            bus_by_jid[jid] = bj
            st = str(bj.get("status") or "queued").strip().lower()
            if st == "failed":
                st = "error"
            if st in bj_counts:
                bj_counts[st] += 1
            bj_counts["total"] += 1
            if st == "running":
                has_active_exec = True
            for tv in (_safe_float_ts(bj.get("started_at")), _safe_float_ts(bj.get("finished_at"))):
                if tv > 0:
                    live_ts_list.append(tv)
                    act_ts_list.append(tv)
            ct = _safe_float_ts(bj.get("created_at"))
            if ct > 0:
                act_ts_list.append(ct)

        all_jids = sorted(set(pull_by_jid.keys()) | set(bus_by_jid.keys()))
        merged_items: list[dict[str, Any]] = [
            _merge_single_timeline_job(
                jid,
                pull_by_jid.get(jid),
                bus_by_jid.get(jid),
                is_admin=is_admin,
                now_ts=now_ts,
            )
            for jid in all_jids
        ]
        # Take the most recent `limit` unique jobs, ordered chronologically (oldest -> newest)
        merged_items.sort(
            key=lambda it: (float(it.get("created_at") or 0.0), str(it.get("job_id") or "")),
            reverse=True,
        )
        total_jobs = len(merged_items)
        page_items = list(reversed(merged_items[:limit]))

        # Active pull_inbox summary (FIFO oldest first)
        pull_inbox: list[dict[str, Any]] = []
        for jid, pj in pull_by_jid.items():
            st = str(pj.get("status") or "queued").strip().lower()
            if st in ("queued", "claimed") and not pj.get("cancelled"):
                p_meta = pj.get("metadata") if isinstance(pj.get("metadata"), dict) else {}
                pull_inbox.append(
                    _sanitize_public_value(
                        {
                            "job_id": jid,
                            "status": st,
                            "source": _detect_job_source(pj, bus_by_jid.get(jid)),
                            "label": str(p_meta.get("label") or "")[:120],
                            "prompt_preview": str(pj.get("prompt") or "")[:200],
                            "created_at": _safe_float_ts(pj.get("created_at")) or None,
                            "claimed_at": _safe_float_ts(pj.get("claimed_at")) or None,
                            "can_cancel": is_admin,
                        },
                        scrub_host_paths=True,
                    )
                )
        pull_inbox.sort(key=lambda it: (float(it.get("created_at") or 0.0), str(it.get("job_id") or "")))

        leader_events: list[dict[str, Any]] = []
        for ev in ev_list:
            e_ts = _safe_float_ts(ev.get("created_at"))
            if e_ts > 0:
                act_ts_list.append(e_ts)
            leader_events.append(_sanitize_leader_event_summary(ev))
        leader_events.sort(
            key=lambda it: (float(it.get("created_at") or 0.0), str(it.get("event_id") or "")),
            reverse=True,
        )

        roster_last_seen = _read_roster_last_seen_no_symlink(self.bus_dir)
        if aid in roster_last_seen:
            live_ts_list.append(roster_last_seen[aid])
            act_ts_list.append(roster_last_seen[aid])

        last_heartbeat_at: float | None = None
        last_heartbeat_action = ""
        pres = presence_map.get(aid)
        if isinstance(pres, dict):
            for p_ts in (pres.get("last_seen_at"), pres.get("last_peek_at")):
                if isinstance(p_ts, float) and p_ts > 0:
                    live_ts_list.append(p_ts)
                    act_ts_list.append(p_ts)
            p_hb = pres.get("last_heartbeat_at")
            if isinstance(p_hb, float) and p_hb > 0:
                last_heartbeat_at = p_hb
                last_heartbeat_action = str(pres.get("last_action") or "")

        ag_meta = raw_ag.get("metadata") if isinstance(raw_ag.get("metadata"), dict) else {}
        for meta_ts_key in ("last_seen", "last_heartbeat_at"):
            m_ts = _safe_float_ts(raw_ag.get(meta_ts_key)) or _safe_float_ts(ag_meta.get(meta_ts_key))
            if m_ts > 0:
                live_ts_list.append(m_ts)
                act_ts_list.append(m_ts)

        adapter_type, dispatch_mode, target_can_dispatch, disabled_reason = _classify_workbench_agent(raw_ag)
        runtime_status = _compute_runtime_status(
            raw_ag,
            last_live_ts=max(live_ts_list) if live_ts_list else 0.0,
            has_active_execution=has_active_exec,
            now_ts=now_ts,
        )
        clean_ag = _sanitize_public_value(_sanitize_agent_record(raw_ag, viewer_role=viewer_role), scrub_host_paths=True)
        raw_ref = str(raw_ag.get("secret_ref") or "").strip()
        if (
            is_admin
            and raw_ref
            and federation_registry.SECRET_REF_RE.fullmatch(raw_ref)
            and not _FED_TOKEN_RE.search(raw_ref)
        ):
            clean_ag["secret_ref"] = raw_ref
        else:
            clean_ag["secret_ref"] = ""
        clean_ag["has_secret_ref"] = bool(raw_ref)
        clean_ag["runtime_status"] = runtime_status
        clean_ag["adapter_type"] = adapter_type
        clean_ag["dispatch_mode"] = dispatch_mode
        clean_ag["can_dispatch"] = target_can_dispatch
        clean_ag["dispatch_disabled_reason"] = disabled_reason
        clean_ag["pull_queue_counts"] = pq_counts
        clean_ag["bus_job_counts"] = bj_counts
        clean_ag["leader_events_count"] = len(leader_events)
        clean_ag["last_activity_at"] = max(act_ts_list) if act_ts_list else None
        clean_ag["last_heartbeat_at"] = last_heartbeat_at
        clean_ag["last_heartbeat_action"] = last_heartbeat_action

        has_active_jobs = any(bool(it.get("is_active")) for it in merged_items)
        return (
            True,
            200,
            {
                "ok": True,
                "agent": clean_ag,
                "timeline": page_items,
                "total": total_jobs,
                "limit": limit,
                "has_active_jobs": has_active_jobs,
                "pull_inbox": pull_inbox,
                "leader_events": leader_events[:50],
                "can_edit": is_admin,
                "role": viewer_role or "readonly",
                "updated_at": _utc_iso_now(),
            },
            "",
        )

    async def handle_get_workbench(self, request: web.Request) -> web.Response:
        ok, sess, err, sc = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=sc)

        viewer_role = str(sess.get("role") or "readonly")
        ok_snap, snap, snap_err = await asyncio.to_thread(
            self._build_workbench_snapshot_sync,
            viewer_role=viewer_role,
        )
        if not ok_snap:
            return _api_error(snap_err, status=403, code="SECURITY_SYMLINK_REJECTED")
        return web.json_response(
            {"ok": True, **snap},
            headers={"Cache-Control": "no-store, max-age=0"},
        )

    async def handle_get_workbench_timeline(self, request: web.Request) -> web.Response:
        ok, sess, err, sc = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=sc)

        raw_aid = request.match_info.get("agent_id", "")
        try:
            aid = federation_registry.validate_agent_id(raw_aid)
        except ValueError as exc:
            return _api_error(str(exc), status=400)

        raw_limit = request.query.get("limit", str(DEFAULT_TIMELINE_LIMIT)).strip()
        try:
            limit = int(raw_limit)
        except ValueError:
            return _api_error("limit 必须为正整数", status=400)
        if limit < 1:
            return _api_error("limit 必须 >= 1", status=400)
        limit = min(limit, MAX_TIMELINE_LIMIT)

        viewer_role = str(sess.get("role") or "readonly")
        ok_tl, tl_sc, payload, tl_err = await asyncio.to_thread(
            self._build_agent_timeline_sync,
            aid,
            limit=limit,
            viewer_role=viewer_role,
        )
        if not ok_tl:
            code = "SECURITY_SYMLINK_REJECTED" if tl_sc == 403 else ("AGENT_NOT_FOUND" if tl_sc == 404 else "")
            return _api_error(tl_err, status=tl_sc, code=code)
        return web.json_response(
            payload,
            headers={"Cache-Control": "no-store, max-age=0"},
        )

    async def handle_workbench_dispatch(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("agent_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="federation.workbench.dispatch", target_id=raw_aid
        )
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        try:
            aid = federation_registry.validate_agent_id(raw_aid)
        except ValueError as exc:
            self.audit.record(
                action="federation.workbench.dispatch",
                status_code=400,
                outcome="invalid_agent_id",
                client_ip=client_ip,
                sess=sess,
            )
            return _api_error(str(exc), status=400)

        ok_body, body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.workbench.dispatch",
            allowed_keys=_ALLOWED_WORKBENCH_DISPATCH_KEYS,
            allow_empty=False,
            target_id=aid,
        )
        if not ok_body or body is None:
            return body_resp  # type: ignore[return-value]

        raw_prompt = body.get("prompt")
        if type(raw_prompt) is not str or not raw_prompt.strip():
            self.audit.record(
                action="federation.workbench.dispatch",
                status_code=400,
                outcome="invalid_prompt",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error("prompt 必须为非空字符串", status=400)
        clean_prompt = raw_prompt.strip()
        if len(clean_prompt) > MAX_DISPATCH_PROMPT_CHARS:
            self.audit.record(
                action="federation.workbench.dispatch",
                status_code=400,
                outcome="prompt_too_long",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(f"prompt 长度超出上限 ({MAX_DISPATCH_PROMPT_CHARS})", status=400)

        clean_label = ""
        if "label" in body and body["label"] is not None:
            raw_label = body["label"]
            if type(raw_label) is not str:
                self.audit.record(
                    action="federation.workbench.dispatch",
                    status_code=400,
                    outcome="invalid_label",
                    client_ip=client_ip,
                    target_id=aid,
                    sess=sess,
                )
                return _api_error("label 必须为字符串", status=400)
            clean_label = raw_label.strip()[:120]

        timeout_s: float | None = None
        if "timeout_s" in body and body["timeout_s"] is not None:
            raw_to = body["timeout_s"]
            if isinstance(raw_to, bool) or not isinstance(raw_to, (int, float)) or not math.isfinite(raw_to):
                self.audit.record(
                    action="federation.workbench.dispatch",
                    status_code=400,
                    outcome="invalid_timeout",
                    client_ip=client_ip,
                    target_id=aid,
                    sess=sess,
                )
                return _api_error("timeout_s 必须为有效数值", status=400)
            if raw_to < 1 or raw_to > MAX_DISPATCH_TIMEOUT_SEC:
                self.audit.record(
                    action="federation.workbench.dispatch",
                    status_code=400,
                    outcome="invalid_timeout",
                    client_ip=client_ip,
                    target_id=aid,
                    sess=sess,
                )
                return _api_error(f"timeout_s 必须在 1..{int(MAX_DISPATCH_TIMEOUT_SEC)} 秒范围内", status=400)
            timeout_s = float(raw_to)

        # Anti-symlink check on federation/agents.json before inspecting target
        ok_ag, agents_map, err_ag = await asyncio.to_thread(_read_agents_map_no_symlink, self.bus_dir)
        if not ok_ag:
            self.audit.record(
                action="federation.workbench.dispatch",
                status_code=403,
                outcome="denied_symlink",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(err_ag, status=403, code="SECURITY_SYMLINK_REJECTED")

        agent = agents_map.get(aid)
        if not isinstance(agent, dict):
            self.audit.record(
                action="federation.workbench.dispatch",
                status_code=404,
                outcome="agent_not_found",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(f"未找到外部 Agent: {aid}", status=404, code="AGENT_NOT_FOUND")

        _adapter_type, dispatch_mode, can_disp, disabled_reason = _classify_workbench_agent(agent)
        if not can_disp:
            kind_low = str(agent.get("kind") or "").strip().lower()
            sc = 400 if kind_low in ("agy_local", "mcp_inbound_only") else 403
            self.audit.record(
                action="federation.workbench.dispatch",
                status_code=sc,
                outcome="denied_target_ineligible",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(disabled_reason or "目标节点不可派单", status=sc, code="TARGET_INELIGIBLE")

        actor_name = str(sess.get("username") or sess.get("user_id") or "admin").strip()
        actor_slug = _sanitize_slug(actor_name, max_len=64) or "admin"

        def _do_dispatch() -> tuple[bool, int, dict[str, Any], str]:
            if dispatch_mode == "pull":
                ok_pq, pq_err = _assert_file_not_symlink(self.bus_dir, ("federation", "pull_queue"), ".lock")
                if not ok_pq:
                    return False, 403, {}, pq_err

                owner_auth = self._make_studio_owner_auth(sess)
                meta: dict[str, Any] = {
                    "source": "studio",
                    "from_actor": f"studio:{actor_slug}",
                }
                if clean_label:
                    meta["label"] = clean_label
                if timeout_s is not None:
                    meta["timeout_s"] = timeout_s
                rec = federation_registry.PullWorkerQueue(self.bus_dir).enqueue(
                    aid,
                    clean_prompt,
                    from_agent_id="",
                    metadata=meta,
                    owner_auth=owner_auth,
                    env={},
                )
                merged = _merge_single_timeline_job(
                    str(rec["job_id"]),
                    rec,
                    None,
                    is_admin=True,
                    now_ts=time.time(),
                )
                return True, 200, merged, ""

            # Push external agent (hermes_local / hermes_remote / muse_remote / http_a2a)
            for dir_parts in (("jobs",), ("inbox",), ("inbox", aid)):
                ok_d, d_err = _assert_dir_not_symlink(self.bus_dir, dir_parts)
                if not ok_d:
                    return False, 403, {}, d_err
            for file_dir_parts, fname in ((("inbox",), ".last_pkt_ns"), ((), "bus.lock")):
                ok_f, f_err = _assert_file_not_symlink(self.bus_dir, file_dir_parts, fname)
                if not ok_f:
                    return False, 403, {}, f_err

            assignment: dict[str, Any] = {
                "bot": aid,
                "prompt": clean_prompt,
                "label": clean_label or clean_prompt[:64],
            }
            dispatched = bot_bus.dispatch_jobs_in_dir(
                self.bus_dir,
                from_bot="studio",
                assignments=[assignment],
            )
            jobs_created = dispatched.get("jobs") or []
            if not jobs_created or not isinstance(jobs_created[0], dict):
                return False, 500, {}, "派单落盘失败"
            bjob = jobs_created[0]
            merged = _merge_single_timeline_job(
                str(bjob["job_id"]),
                None,
                bjob,
                is_admin=True,
                now_ts=time.time(),
            )
            return True, 200, merged, ""

        try:
            ok_disp, disp_sc, job_item, disp_err = await asyncio.to_thread(_do_dispatch)
        except PermissionError as exc:
            self.audit.record(
                action="federation.workbench.dispatch",
                status_code=403,
                outcome="denied_owner_auth",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            self.audit.record(
                action="federation.workbench.dispatch",
                status_code=400,
                outcome="invalid_request",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(str(exc), status=400)

        if not ok_disp:
            self.audit.record(
                action="federation.workbench.dispatch",
                status_code=disp_sc,
                outcome="denied_symlink" if disp_sc == 403 else "dispatch_failed",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            code = "SECURITY_SYMLINK_REJECTED" if disp_sc == 403 else ""
            return _api_error(disp_err, status=disp_sc, code=code)

        self.audit.record(
            action="federation.workbench.dispatch",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=aid,
            sess=sess,
        )
        self._publish_federation_updated(action="workbench_dispatch", agent_id=aid)
        return web.json_response(
            {
                "ok": True,
                "agent_id": aid,
                "dispatch_mode": dispatch_mode,
                "job": job_item,
            },
            headers={"Cache-Control": "no-store, max-age=0"},
        )

    async def handle_workbench_cancel(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("agent_id", "")
        raw_jid = request.match_info.get("job_id", "")
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="federation.workbench.cancel", target_id=raw_aid
        )
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        client_ip = self.auth_mgr.extract_client_ip(request)
        try:
            aid = federation_registry.validate_agent_id(raw_aid)
        except ValueError as exc:
            self.audit.record(
                action="federation.workbench.cancel",
                status_code=400,
                outcome="invalid_agent_id",
                client_ip=client_ip,
                sess=sess,
            )
            return _api_error(str(exc), status=400)

        try:
            jid = _validate_workbench_job_id(raw_jid)
        except ValueError as exc:
            self.audit.record(
                action="federation.workbench.cancel",
                status_code=400,
                outcome="invalid_job_id",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(str(exc), status=400)

        ok_body, body, body_resp = await self._parse_validated_body(
            request,
            sess=sess,
            action="federation.workbench.cancel",
            allowed_keys=_ALLOWED_WORKBENCH_CANCEL_KEYS,
            allow_empty=True,
            target_id=aid,
        )
        if not ok_body or body is None:
            return body_resp  # type: ignore[return-value]

        clean_reason = "cancelled_by_studio"
        if "reason" in body and body["reason"] is not None:
            raw_reason = body["reason"]
            if type(raw_reason) is not str:
                self.audit.record(
                    action="federation.workbench.cancel",
                    status_code=400,
                    outcome="invalid_reason",
                    client_ip=client_ip,
                    target_id=aid,
                    sess=sess,
                )
                return _api_error("reason 必须为字符串", status=400)
            if raw_reason.strip():
                clean_reason = raw_reason.strip()[:200]

        def _do_cancel() -> tuple[bool, int, dict[str, Any], str]:
            pull_job: dict[str, Any] | None = None
            is_pull_id = bool(federation_registry.PULL_JOB_ID_RE.fullmatch(jid))
            if is_pull_id:
                ok_pj, pj_obj, err_pj = _read_single_json_no_symlink(
                    self.bus_dir, ("federation", "pull_queue"), f"{jid}.json"
                )
                if not ok_pj:
                    return False, 403, {}, err_pj
                pull_job = pj_obj

            ok_bj, bj_obj, err_bj = _read_single_json_no_symlink(
                self.bus_dir, ("jobs",), f"{jid}.json"
            )
            if not ok_bj:
                return False, 403, {}, err_bj
            bus_job = bj_obj

            if pull_job is None and bus_job is None:
                return False, 404, {}, f"未找到任务: {jid}"

            # Enforce strict ownership against `aid`
            if pull_job is not None and str(pull_job.get("target_agent_id") or "").strip().lower() != aid:
                return False, 404, {}, f"任务 {jid} 不属于 Agent {aid}"
            if bus_job is not None and str(bus_job.get("target_bot") or "").strip().lower() != aid:
                return False, 404, {}, f"任务 {jid} 不属于 Agent {aid}"

            p_st = str((pull_job or {}).get("status") or "").strip().lower()
            b_st = str((bus_job or {}).get("status") or "").strip().lower()
            p_term = pull_job is None or p_st in _TERMINAL_JOB_STATUSES
            b_term = bus_job is None or b_st in _TERMINAL_JOB_STATUSES

            # Preserve completed (`done`/`error`) terminal results idempotently
            either_completed = (p_st in ("done", "error")) or (b_st in ("done", "error", "failed"))
            if (p_term and b_term) or either_completed:
                merged = _merge_single_timeline_job(
                    jid,
                    pull_job,
                    bus_job,
                    is_admin=True,
                    now_ts=time.time(),
                )
                return (
                    True,
                    200,
                    {
                        "ok": True,
                        "agent_id": aid,
                        "job_id": jid,
                        "status": merged["status"],
                        "already_terminal": True,
                        "cancelled": False,
                        "job": merged,
                    },
                    "",
                )

            updated_pull = pull_job
            updated_bus = bus_job
            did_cancel = False

            # Pre-validate all write-path directories & lock files before mutating either store
            if pull_job is not None and not p_term:
                ok_pq, pq_err = _assert_file_not_symlink(self.bus_dir, ("federation", "pull_queue"), ".lock")
                if not ok_pq:
                    return False, 403, {}, pq_err

            if bus_job is not None and not b_term:
                bus_dir_checks: list[tuple[str, ...]] = [("jobs",), ("inbox",), ("inbox", aid)]
                from_bot_norm = bot_bus.normalize_handle(str(bus_job.get("from_bot") or ""))
                if (
                    from_bot_norm
                    and from_bot_norm != aid
                    and from_bot_norm not in (".", "..")
                    and "/" not in from_bot_norm
                    and "\\" not in from_bot_norm
                    and "\x00" not in from_bot_norm
                ):
                    bus_dir_checks.append(("inbox", from_bot_norm))
                for dir_parts in bus_dir_checks:
                    ok_d, d_err = _assert_dir_not_symlink(self.bus_dir, dir_parts)
                    if not ok_d:
                        return False, 403, {}, d_err
                for file_dir_parts, fname in ((("inbox",), ".last_pkt_ns"), ((), "bus.lock")):
                    ok_f, f_err = _assert_file_not_symlink(self.bus_dir, file_dir_parts, fname)
                    if not ok_f:
                        return False, 403, {}, f_err

            if pull_job is not None and not p_term:
                owner_auth = self._make_studio_owner_auth(sess)
                res_p = federation_registry.PullWorkerQueue(self.bus_dir).cancel(
                    jid,
                    reason=clean_reason,
                    owner_auth=owner_auth,
                    env={},
                )
                if isinstance(res_p, dict):
                    updated_pull = res_p
                    res_p_st = str(res_p.get("status") or "").strip().lower()
                    if res_p_st in ("done", "error", "failed"):
                        # Worker already completed the job before cancel took effect;
                        # skip bot_bus.cancel_job_in_dir() and return preserved terminal state.
                        merged = _merge_single_timeline_job(
                            jid,
                            updated_pull,
                            updated_bus,
                            is_admin=True,
                            now_ts=time.time(),
                        )
                        return (
                            True,
                            200,
                            {
                                "ok": True,
                                "agent_id": aid,
                                "job_id": jid,
                                "status": merged["status"],
                                "already_terminal": True,
                                "cancelled": False,
                                "job": merged,
                            },
                            "",
                        )
                    if res_p_st == "cancelled":
                        did_cancel = True

            if bus_job is not None and not b_term:
                res_b, was_term = bot_bus.cancel_job_in_dir(
                    self.bus_dir,
                    jid,
                    reason=clean_reason,
                )
                if isinstance(res_b, dict):
                    updated_bus = res_b
                    if not was_term:
                        did_cancel = True

            merged = _merge_single_timeline_job(
                jid,
                updated_pull,
                updated_bus,
                is_admin=True,
                now_ts=time.time(),
            )
            return (
                True,
                200,
                {
                    "ok": True,
                    "agent_id": aid,
                    "job_id": jid,
                    "status": merged["status"],
                    "already_terminal": not did_cancel and merged["status"] in _TERMINAL_JOB_STATUSES,
                    "cancelled": did_cancel,
                    "job": merged,
                },
                "",
            )

        try:
            ok_c, c_sc, payload, c_err = await asyncio.to_thread(_do_cancel)
        except PermissionError as exc:
            self.audit.record(
                action="federation.workbench.cancel",
                status_code=403,
                outcome="denied_owner_auth",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return studio_auth_error(str(exc), status=403)
        except ValueError as exc:
            self.audit.record(
                action="federation.workbench.cancel",
                status_code=400,
                outcome="invalid_request",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            return _api_error(str(exc), status=400)

        if not ok_c:
            self.audit.record(
                action="federation.workbench.cancel",
                status_code=c_sc,
                outcome="denied_symlink" if c_sc == 403 else "cancel_failed",
                client_ip=client_ip,
                target_id=aid,
                sess=sess,
            )
            code = "SECURITY_SYMLINK_REJECTED" if c_sc == 403 else ("JOB_NOT_FOUND" if c_sc == 404 else "")
            return _api_error(c_err, status=c_sc, code=code)

        self.audit.record(
            action="federation.workbench.cancel",
            status_code=200,
            outcome="ok",
            client_ip=client_ip,
            target_id=aid,
            sess=sess,
        )
        self._publish_federation_updated(action="workbench_cancel", agent_id=aid)
        return web.json_response(payload, headers={"Cache-Control": "no-store, max-age=0"})
