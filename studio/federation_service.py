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
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any

import aiohttp
from aiohttp import web

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BRIDGE_SRC_DIR = _REPO_ROOT / "bridge"
if str(_BRIDGE_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_BRIDGE_SRC_DIR))

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

_FED_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])agy_fed_[A-Za-z0-9._-]{12,}")

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
        health_timeout_sec: float = DEFAULT_HEALTH_TIMEOUT_SEC,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.audit = audit
        self.event_hub = event_hub
        self._hub_host_override = hub_host
        self._hub_port_override = hub_port
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

        raw_host, raw_port = self._effective_hub_host_port()
        ok_cfg, fmt_host, port, _ = _validate_loopback_hub_target(raw_host, raw_port)

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
                "hub_config": {
                    "loopback_valid": ok_cfg,
                    "host": fmt_host if ok_cfg else "invalid",
                    "port": port if ok_cfg else 0,
                    "mcp_url": f"http://{fmt_host}:{port}/hub/mcp" if ok_cfg else "",
                },
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
