#!/usr/bin/env python3
"""AGY Studio Phase B M1 — Bot Team Control Plane (Config, Skills/MCP View & Safe Hot-Reload).

Security Invariants (`PB-C3`):
- Zero `subprocess`, zero `os.system`, zero `systemctl`, zero direct `/tmp` writes on Studio side.
- Strict handle validation (`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`) preventing path traversal/injection.
- Strictly allowlisted MCP metadata (`{name, transport, enabled}` ONLY — zero `env`, `headers`,
  `command`, `args`, `url`, `lv1/...`, tokens, or host paths) and Skills metadata
  (`{name, scope, description (<=160)}` ONLY — zero host paths).
- All mutations enforce the four-layer write gate (`Origin` -> 403, `Content-Type` -> 415,
  cookie + live RBAC + `must_change_password=False` -> 401/403, `X-Studio-CSRF` + `admin` -> 403),
  recursive forbidden-field scanning, 15s per-bot reload cooldown (`429` + `Retry-After`),
  and `0600` append-only JSONL audit logging on every branch.
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
import re
import time
from typing import Any

import aiohttp
from aiohttp import web

from .auth import StudioAuthManager, studio_auth_error
from .chat_service import (
    MAX_PROMPT_BODY_BYTES,
    StudioAuditLogger,
    _extract_media_type,
    _read_bounded_json_body,
)
from .control_plane import _find_forbidden_key_recursive
from .data_sources import (
    MAX_MODEL_SLUG_LEN,
    StudioDataSources,
    _SENSITIVE_HOST_PATH_RE,
    _sanitize_slug,
    redact_secrets_only,
)
from .event_hub import StudioEventHub

log = logging.getLogger("agy-studio.bot_control")

DEFAULT_RELOAD_COOLDOWN_SEC = 15.0
MAX_PROFILE_BODY_BYTES = 128 * 1024
MAX_PROFILE_DOC_BYTES = 24 * 1024

_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SKILL_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_FORBIDDEN_SKILL_SLUGS = frozenset({".", "..", "__proto__", "constructor", "prototype"})
_ALLOWED_PROFILE_DOCS = frozenset({"SOUL.md", "RULES.md", "MEMORY.md"})
_VALID_SKILL_POLICY_MODES = frozenset({"allowlist", "all"})
_VALID_MODEL_MODES = frozenset({"default", "follow", "custom"})
_VALID_EFFORTS = frozenset({"", "low", "medium", "high", "xhigh", "max"})
_PRIVATE_GET_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
}

_ALLOWED_PROFILE_PUT_KEYS = frozenset({
    "expected_rev",
    "doc",
    "content",
    "docs",
    "skills_policy",
    "specialty",
})
_ALLOWED_SKILL_PUT_KEYS = frozenset({
    "expected_rev",
    "content",
})
_ALLOWED_SKILL_DELETE_KEYS = frozenset({
    "expected_rev",
})
_FORBIDDEN_PROFILE_KEYS = frozenset({
    "workdir",
    "default_workdir",
    "ipc_sock",
    "role",
    "path",
    "reload_file",
    "env",
    "headers",
    "command",
    "cmd",
    "args",
    "url",
    "shell",
    "script",
    "token",
    "secret",
    "password",
    "pid",
    "allowed_chats",
    "mirror_chat_id",
    "mirror_thread_id",
    "chat_id",
    "thread_id",
})

_ALLOWED_CONFIG_PATCH_KEYS = frozenset({
    "model_mode",
    "model",
    "default_effort",
    "default_project",
})
_FORBIDDEN_CONFIG_KEYS = frozenset({
    "workdir",
    "default_workdir",
    "ipc_sock",
    "env",
    "headers",
    "command",
    "args",
    "url",
    "role",
    "reload_file",
    "allowed_chats",
    "mirror_chat_id",
    "mirror_thread_id",
    "chat_id",
    "thread_id",
    "token",
    "secret",
    "password",
    "pid",
})
_FORBIDDEN_RELOAD_KEYS = frozenset({
    "reload_file",
    "cmd",
    "command",
    "shell",
    "script",
    "workdir",
    "ipc_sock",
    "env",
    "role",
    "pid",
})


def _redact_bot_text(raw: Any, max_len: int = 160) -> str:
    text = redact_secrets_only(raw)
    if text:
        text = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", text)
    text = " ".join(text.split())
    if max_len > 0 and len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def _normalize_strict_handle(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if s.startswith("@"):
        s = s[1:]
    if not s or "/" in s or "\\" in s or ".." in s or "%" in s or "\x00" in s:
        return None
    if not _HANDLE_RE.fullmatch(s):
        return None
    return s.lower()


def _sanitize_mcp_list(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw[:64]:
        if not isinstance(item, dict):
            continue
        name = _sanitize_slug(item.get("name"), max_len=64)
        if not name:
            continue
        tr = str(item.get("transport") or "unknown").strip().lower()
        if tr not in ("stdio", "http", "sse", "streamable-http", "unknown"):
            tr = "unknown"
        out.append({
            "name": name,
            "transport": tr,
            "enabled": bool(item.get("enabled", True)),
        })
    return out


def _sanitize_skills_list(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for item in raw[:120]:
        if not isinstance(item, dict):
            continue
        name = _sanitize_slug(item.get("name"), max_len=64)
        if not name:
            continue
        scope = _sanitize_slug(item.get("scope") or "workspace", max_len=24) or "workspace"
        desc = _redact_bot_text(item.get("description") or "", max_len=160)
        out.append({
            "name": name,
            "scope": scope,
            "description": desc,
        })
    return out


class StudioBotControlService:
    """Bot Team Control Plane API handlers (config read/write + safe hot-reload)."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        data_sources: StudioDataSources,
        event_hub: StudioEventHub,
        audit: StudioAuditLogger,
        *,
        reload_cooldown_sec: float = DEFAULT_RELOAD_COOLDOWN_SEC,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.event_hub = event_hub
        self.audit = audit
        self.reload_cooldown_sec = max(0.0, float(reload_cooldown_sec))
        self._reload_cooldowns: dict[str, float] = {}
        self._reload_in_flight: set[str] = set()

    def _ipc_dir(self) -> Path:
        return (self.data_sources.bus_dir / "ipc").resolve()

    def _resolve_bot_ipc(self, handle: str) -> tuple[Path, str] | None:
        ipc_dir = self._ipc_dir()
        if not ipc_dir.is_dir():
            return None
        sock_p = (ipc_dir / f"{handle}.sock").resolve()
        tok_p = (ipc_dir / f"{handle}.token").resolve()
        try:
            sock_p.relative_to(ipc_dir)
            tok_p.relative_to(ipc_dir)
        except ValueError:
            return None
        if not sock_p.exists() or not tok_p.is_file():
            return None
        try:
            token = tok_p.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        return (sock_p, token) if token else None

    def _find_roster_bot(self, handle: str) -> dict[str, Any] | None:
        bots_info = self.data_sources.get_bots()
        for b in bots_info.get("bots") or []:
            if str(b.get("handle") or "").strip().lower() == handle:
                return b
        return None

    async def _ipc_request_json(
        self,
        *,
        sock_path: Path,
        token: str,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        timeout_sec: float = 20.0,
    ) -> tuple[int, dict[str, Any]]:
        connector = aiohttp.UnixConnector(path=str(sock_path))
        headers = {"X-Bridge-IPC-Token": token}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        try:
            async with aiohttp.ClientSession(connector=connector) as cli:
                async with cli.request(
                    method,
                    f"http://localhost{path}",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=timeout_sec),
                ) as resp:
                    raw = await resp.text()
                    try:
                        data = json.loads(raw) if raw else {}
                    except Exception:
                        data = {"ok": False, "error": f"Bridge IPC HTTP {resp.status}"}
                    if not isinstance(data, dict):
                        data = {"ok": False, "error": f"Bridge IPC HTTP {resp.status}"}
                    return resp.status, data
        except Exception as exc:
            log.warning("BotControl Bridge IPC %s %s failed: %s", method, path, type(exc).__name__)
            return 502, {"ok": False, "source": "upstream", "error": "Bridge IPC 服务暂不可达"}

    async def _enforce_write_gate(
        self,
        request: web.Request,
        *,
        action: str,
        target_id: str = "",
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

        # Gate 1b: Sec-Fetch-Site validation when header is sent by browser
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

        # Gate 4a: CSRF verification
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
                "只读权限（readonly）禁止执行写操作",
                status=403,
            )

        return True, sess, None

    def _sanitize_config_response(
        self,
        *,
        handle: str,
        raw: dict[str, Any],
        ipc_online: bool,
        can_edit: bool,
    ) -> dict[str, Any]:
        models_out = [
            {
                "id": _sanitize_slug(m.get("id"), max_len=MAX_MODEL_SLUG_LEN),
                "label": _redact_bot_text(m.get("label") or m.get("id") or "", max_len=160),
            }
            for m in (raw.get("models") or [])[:120]
            if isinstance(m, dict) and m.get("id")
        ]
        if isinstance(raw.get("projects"), list) and raw.get("projects"):
            projects_out = [
                {
                    "id": _sanitize_slug(p.get("id"), max_len=64),
                    "name": _redact_bot_text(p.get("name") or p.get("id") or "", max_len=80),
                }
                for p in raw["projects"][:64]
                if isinstance(p, dict) and p.get("id")
            ]
        else:
            projects_out = [
                {"id": p["id"], "name": p["name"]}
                for p in self.data_sources.get_allowed_projects()
            ]
        efforts_raw = raw.get("efforts")
        efforts_out = (
            [str(e).strip().lower() for e in efforts_raw if str(e).strip().lower() in _VALID_EFFORTS and str(e).strip()]
            if isinstance(efforts_raw, list) and efforts_raw
            else ["low", "medium", "high", "xhigh", "max"]
        )
        mode_val = str(raw.get("model_mode") or "default").strip().lower()
        if mode_val not in _VALID_MODEL_MODES:
            mode_val = "default"
        eff_val = str(raw.get("default_effort") or "").strip().lower()
        if eff_val not in _VALID_EFFORTS:
            eff_val = ""

        # Strict whitelist output — NEVER includes workdir, pid, ipc_sock, allowed_chats, env, headers, command, args, url
        return {
            "ok": True,
            "ipc_online": ipc_online,
            "can_edit": can_edit and ipc_online,
            "handle": handle,
            "display_name": _redact_bot_text(raw.get("display_name") or handle, max_len=64),
            "role": _sanitize_slug(raw.get("role") or "worker", max_len=24),
            "specialty": _redact_bot_text(raw.get("specialty") or "", max_len=160),
            "model_mode": mode_val,
            "configured_model": _sanitize_slug(raw.get("configured_model") or "", max_len=MAX_MODEL_SLUG_LEN),
            "effective_model": _sanitize_slug(raw.get("effective_model") or raw.get("active_model") or "default", max_len=MAX_MODEL_SLUG_LEN),
            "dm_model": _sanitize_slug(raw.get("dm_model") or "", max_len=MAX_MODEL_SLUG_LEN),
            "env_default_model": _sanitize_slug(raw.get("env_default_model") or "", max_len=MAX_MODEL_SLUG_LEN),
            "default_effort": eff_val,
            "default_project": _sanitize_slug(raw.get("default_project") or "", max_len=64),
            "efforts": efforts_out,
            "models": models_out,
            "projects": projects_out,
            "skills": _sanitize_skills_list(raw.get("skills")),
            "mcp_servers": _sanitize_mcp_list(raw.get("mcp_servers")),
            "busy": bool(raw.get("busy", False)),
            "queue_depth": int(raw.get("queue_depth") or 0),
        }

    # ------------------------------------------------------------------ GET /api/bots/{handle}/config
    async def handle_get_bot_config(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)

        handle = _normalize_strict_handle(request.match_info.get("handle") or "")
        if not handle:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 Bot handle 格式"},
                status=400,
            )

        roster_bot = self._find_roster_bot(handle)
        ipc_ep = self._resolve_bot_ipc(handle)
        if roster_bot is None and ipc_ep is None:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的 Bot 节点"},
                status=404,
            )

        can_edit = sess.get("role") == "admin"
        if ipc_ep is not None:
            sock_p, tok = ipc_ep
            sc, data = await self._ipc_request_json(
                sock_path=sock_p,
                token=tok,
                method="GET",
                path="/ipc/bot/config",
            )
            if sc == 200 and data.get("ok"):
                return web.json_response(
                    self._sanitize_config_response(
                        handle=handle,
                        raw=data,
                        ipc_online=True,
                        can_edit=can_edit,
                    )
                )

        # Offline fallback: read-only roster view
        fallback = dict(roster_bot or {})
        return web.json_response(
            self._sanitize_config_response(
                handle=handle,
                raw=fallback,
                ipc_online=False,
                can_edit=False,
            )
        )

    # ------------------------------------------------------------------ PATCH /api/bots/{handle}/config
    async def handle_patch_bot_config(self, request: web.Request) -> web.Response:
        raw_h = request.match_info.get("handle") or ""
        handle = _normalize_strict_handle(raw_h)
        safe_tid = handle or _sanitize_slug(raw_h, max_len=64)

        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="bot.config.patch", target_id=safe_tid
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        if not handle:
            self.audit.record(
                action="bot.config.patch",
                status_code=400,
                outcome="denied_invalid_handle",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 Bot handle 格式"},
                status=400,
            )

        roster_bot = self._find_roster_bot(handle)
        ipc_ep = self._resolve_bot_ipc(handle)
        if roster_bot is None and ipc_ep is None:
            self.audit.record(
                action="bot.config.patch",
                status_code=404,
                outcome="denied_unknown_bot",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的 Bot 节点"},
                status=404,
            )

        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action="bot.config.patch",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_CONFIG_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action="bot.config.patch",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        extra_keys = set(body.keys()) - _ALLOWED_CONFIG_PATCH_KEYS
        if extra_keys:
            self.audit.record(
                action="bot.config.patch",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "存在未允许的配置字段"},
                status=400,
            )

        if not body:
            self.audit.record(
                action="bot.config.patch",
                status_code=400,
                outcome="denied_empty_patch",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "至少需要提供一个可更新配置字段"},
                status=400,
            )

        ipc_payload: dict[str, Any] = {
            "user_id": int(sess["user_id"]),
            "actor_username": str(sess.get("username") or "")[:64],
        }

        if "model_mode" in body or "model" in body:
            if "model_mode" not in body:
                self.audit.record(
                    action="bot.config.patch",
                    status_code=400,
                    outcome="denied_missing_model_mode",
                    client_ip=client_ip,
                    target_id=handle,
                    sess=sess,
                    bot_override=handle,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "修改模型时必须显式提供 model_mode"},
                    status=400,
                )
            raw_mode = body.get("model_mode")
            if not isinstance(raw_mode, str) or raw_mode.strip().lower() not in _VALID_MODEL_MODES:
                self.audit.record(
                    action="bot.config.patch",
                    status_code=400,
                    outcome="denied_invalid_model_mode",
                    client_ip=client_ip,
                    target_id=handle,
                    sess=sess,
                    bot_override=handle,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "model_mode 仅允许 default / follow / custom"},
                    status=400,
                )
            norm_mode = raw_mode.strip().lower()
            ipc_payload["model_mode"] = norm_mode
            if norm_mode == "custom":
                raw_m = body.get("model")
                clean_m = raw_m.strip() if isinstance(raw_m, str) else ""
                if (
                    not clean_m
                    or len(clean_m) > MAX_MODEL_SLUG_LEN
                    or ".." in clean_m
                    or clean_m.startswith(("/", "~"))
                    or any(ord(ch) < 32 or ord(ch) == 127 for ch in clean_m)
                ):
                    self.audit.record(
                        action="bot.config.patch",
                        status_code=400,
                        outcome="denied_invalid_model",
                        client_ip=client_ip,
                        target_id=handle,
                        sess=sess,
                        bot_override=handle,
                    )
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "custom 模式必须提供有效的模型 slug"},
                        status=400,
                    )
                ipc_payload["model"] = clean_m
            else:
                if body.get("model") not in (None, ""):
                    self.audit.record(
                        action="bot.config.patch",
                        status_code=400,
                        outcome="denied_model_with_non_custom",
                        client_ip=client_ip,
                        target_id=handle,
                        sess=sess,
                        bot_override=handle,
                    )
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "非 custom 模式不允许指定 model"},
                        status=400,
                    )

        if "default_effort" in body:
            raw_ef = body.get("default_effort")
            norm_ef = "" if raw_ef is None else (raw_ef.strip().lower() if isinstance(raw_ef, str) else None)
            if norm_ef is None or norm_ef not in _VALID_EFFORTS:
                self.audit.record(
                    action="bot.config.patch",
                    status_code=400,
                    outcome="denied_invalid_effort",
                    client_ip=client_ip,
                    target_id=handle,
                    sess=sess,
                    bot_override=handle,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "default_effort 仅允许空值或 low/medium/high/xhigh/max"},
                    status=400,
                )
            ipc_payload["default_effort"] = norm_ef

        if "default_project" in body:
            raw_p = body.get("default_project")
            if raw_p is None or (isinstance(raw_p, str) and raw_p.strip() == ""):
                ipc_payload["default_project"] = ""
            elif isinstance(raw_p, str):
                proj = self.data_sources.resolve_allowed_project(raw_p.strip())
                if not proj:
                    self.audit.record(
                        action="bot.config.patch",
                        status_code=400,
                        outcome="denied_invalid_project",
                        client_ip=client_ip,
                        target_id=handle,
                        sess=sess,
                        bot_override=handle,
                    )
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "default_project 不在项目白名单内"},
                        status=400,
                    )
                ipc_payload["default_project"] = proj["id"]
            else:
                self.audit.record(
                    action="bot.config.patch",
                    status_code=400,
                    outcome="denied_invalid_project",
                    client_ip=client_ip,
                    target_id=handle,
                    sess=sess,
                    bot_override=handle,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "default_project 必须为字符串"},
                    status=400,
                )

        if ipc_ep is None:
            self.audit.record(
                action="bot.config.patch",
                status_code=503,
                outcome="error_ipc_offline",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "upstream", "error": "目标 Bot Bridge IPC 离线，无法更新配置"},
                status=503,
            )

        sock_p, tok = ipc_ep
        sc, data = await self._ipc_request_json(
            sock_path=sock_p,
            token=tok,
            method="POST",
            path="/ipc/bot/config",
            payload=ipc_payload,
        )
        if sc >= 400 or not data.get("ok"):
            self.audit.record(
                action="bot.config.patch",
                status_code=sc,
                outcome="error_ipc" if sc >= 500 else "denied_ipc",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "upstream",
                    "error": _redact_bot_text(data.get("error") or "更新 Bot 配置失败", max_len=200),
                },
                status=sc,
            )

        self.audit.record(
            action="bot.config.patch",
            status_code=200,
            outcome="allowed",
            client_ip=client_ip,
            target_id=handle,
            sess=sess,
            bot_override=handle,
        )
        self.event_hub.publish(
            "bots_updated",
            {"handle": handle, "action": "config_updated", "source": "studio"},
        )
        return web.json_response(
            self._sanitize_config_response(
                handle=handle,
                raw=data,
                ipc_online=True,
                can_edit=True,
            )
        )

    # ------------------------------------------------------------------ POST /api/bots/{handle}/reload
    async def handle_reload_bot(self, request: web.Request) -> web.Response:
        raw_h = request.match_info.get("handle") or ""
        handle = _normalize_strict_handle(raw_h)
        safe_tid = handle or _sanitize_slug(raw_h, max_len=64)

        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="bot.reload", target_id=safe_tid
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        if not handle:
            self.audit.record(
                action="bot.reload",
                status_code=400,
                outcome="denied_invalid_handle",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 Bot handle 格式"},
                status=400,
            )

        roster_bot = self._find_roster_bot(handle)
        ipc_ep = self._resolve_bot_ipc(handle)
        if roster_bot is None and ipc_ep is None:
            self.audit.record(
                action="bot.reload",
                status_code=404,
                outcome="denied_unknown_bot",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的 Bot 节点"},
                status=404,
            )

        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=True
        )
        if not ok_body or body is None:
            self.audit.record(
                action="bot.reload",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_RELOAD_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action="bot.reload",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        if body:
            self.audit.record(
                action="bot.reload",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "热重载接口不接受额外参数"},
                status=400,
            )

        # 15s per-bot cooldown debounce + in-flight single-flight guard (prevents concurrent TOCTOU)
        now_m = time.monotonic()
        last_ts = self._reload_cooldowns.get(handle)
        in_cooldown = last_ts is not None and (now_m - last_ts) < self.reload_cooldown_sec
        if in_cooldown or handle in self._reload_in_flight:
            if in_cooldown and last_ts is not None:
                retry_after = max(1, int(math.ceil(self.reload_cooldown_sec - (now_m - last_ts))))
            else:
                retry_after = max(1, int(math.ceil(self.reload_cooldown_sec or 1.0)))
            self.audit.record(
                action="bot.reload",
                status_code=429,
                outcome="denied_cooldown",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": f"热重载冷却中，请 {retry_after} 秒后再试",
                    "retry_after": retry_after,
                },
                status=429,
                headers={"Retry-After": str(retry_after)},
            )

        if ipc_ep is None:
            self.audit.record(
                action="bot.reload",
                status_code=503,
                outcome="error_ipc_offline",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "upstream", "error": "目标 Bot Bridge IPC 离线，无法执行热重载"},
                status=503,
            )

        sock_p, tok = ipc_ep
        self._reload_in_flight.add(handle)
        try:
            sc, data = await self._ipc_request_json(
                sock_path=sock_p,
                token=tok,
                method="POST",
                path="/ipc/bot/reload",
                payload={
                    "user_id": int(sess["user_id"]),
                    "actor_username": str(sess.get("username") or "")[:64],
                },
            )
            if sc < 400 and data.get("ok"):
                self._reload_cooldowns[handle] = time.monotonic()
        finally:
            self._reload_in_flight.discard(handle)

        if sc >= 400 or not data.get("ok"):
            outcome = "self_check_failed" if sc == 422 else ("denied_ipc" if sc < 500 else "error_ipc")
            self.audit.record(
                action="bot.reload",
                status_code=sc,
                outcome=outcome,
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "upstream",
                    "code": _sanitize_slug(data.get("code") or "", max_len=32) or None,
                    "error": _redact_bot_text(data.get("error") or "触发热重载失败", max_len=240),
                },
                status=sc,
            )

        self.audit.record(
            action="bot.reload",
            status_code=202,
            outcome="allowed",
            client_ip=client_ip,
            target_id=handle,
            sess=sess,
            bot_override=handle,
        )
        self.event_hub.publish(
            "bots_updated",
            {"handle": handle, "action": "reload_scheduled", "source": "studio"},
        )
        return web.json_response(
            {
                "ok": True,
                "bot": handle,
                "scheduled": True,
                "self_check": "passed",
                "cooldown_sec": int(self.reload_cooldown_sec),
            },
            status=202,
        )

    @staticmethod
    def _validate_skill_slug(raw: Any) -> str | None:
        if not isinstance(raw, str):
            return None
        s = raw.strip()
        if (
            not s
            or s in _FORBIDDEN_SKILL_SLUGS
            or "/" in s
            or "\\" in s
            or ".." in s
            or "\x00" in s
            or not _SKILL_SLUG_RE.fullmatch(s)
        ):
            return None
        return s

    @staticmethod
    def _parse_expected_rev(raw: Any) -> int | None:
        if isinstance(raw, bool) or not isinstance(raw, int):
            return None
        return raw if raw >= 0 else None

    @staticmethod
    def _sanitize_skill_entry(item: Any, *, include_owner: bool = False, include_enabled: bool = False) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None
        slug = _sanitize_slug(item.get("slug") or item.get("name"), max_len=64)
        if not slug:
            return None
        out: dict[str, Any] = {
            "slug": slug,
            "name": _sanitize_slug(item.get("name") or slug, max_len=64) or slug,
            "scope": _sanitize_slug(item.get("scope") or "bot", max_len=24) or "bot",
            "description": _redact_bot_text(item.get("description") or "", max_len=160),
            "size_bytes": max(0, int(item.get("size_bytes") or 0)),
            "updated_at": max(0, int(item.get("updated_at") or 0)),
        }
        if include_owner and item.get("owner"):
            out["owner"] = _sanitize_slug(item.get("owner"), max_len=64)
        if include_enabled:
            out["enabled"] = bool(item.get("enabled", False))
        return out

    def _sanitize_profile_response(
        self,
        *,
        handle: str,
        raw: dict[str, Any],
        ipc_online: bool,
        can_edit: bool,
    ) -> dict[str, Any]:
        raw_docs = raw.get("docs") if isinstance(raw.get("docs"), dict) else {}
        docs_out: dict[str, str] = {}
        doc_bytes: dict[str, int] = {}
        for dname in ("SOUL.md", "RULES.md", "MEMORY.md"):
            val = raw_docs.get(dname)
            txt = val if isinstance(val, str) else ""
            if len(txt.encode("utf-8")) > MAX_PROFILE_DOC_BYTES + 1024:
                txt = txt[:MAX_PROFILE_DOC_BYTES]
            docs_out[dname] = txt
            doc_bytes[dname] = len(txt.encode("utf-8"))

        raw_pol = raw.get("skills_policy") if isinstance(raw.get("skills_policy"), dict) else {}
        pmode = str(raw_pol.get("mode") or "allowlist").strip().lower()
        if pmode not in _VALID_SKILL_POLICY_MODES:
            pmode = "allowlist"
        raw_en = raw_pol.get("enabled_catalog_skills")
        en_list = sorted(
            {
                s
                for s in (raw_en if isinstance(raw_en, list) else [])[:200]
                if isinstance(s, str) and self._validate_skill_slug(s)
            }
        )

        own_skills = [
            e
            for e in (
                self._sanitize_skill_entry(it, include_owner=True)
                for it in (raw.get("own_skills") or [])[:200]
            )
            if e is not None
        ]
        catalog_skills = [
            e
            for e in (
                self._sanitize_skill_entry(it, include_enabled=True)
                for it in (raw.get("catalog_skills") or [])[:200]
            )
            if e is not None
        ]
        team_skills = [
            e
            for e in (
                self._sanitize_skill_entry(it, include_owner=True)
                for it in (raw.get("team_skills") or [])[:200]
            )
            if e is not None
        ]
        effective_skills = [
            e
            for e in (
                self._sanitize_skill_entry(it, include_owner=True)
                for it in (raw.get("effective_skills") or [])[:200]
            )
            if e is not None
        ]

        raw_ms = raw.get("memory_stats") if isinstance(raw.get("memory_stats"), dict) else {}
        mem_stats: dict[str, Any] = {
            "memory_project": _sanitize_slug(raw_ms.get("memory_project") or f"bot-{handle}", max_len=80) or f"bot-{handle}",
            "memory_scope": _sanitize_slug(raw_ms.get("memory_scope") or "isolated", max_len=24) or "isolated",
            "observations_count": max(0, int(raw_ms.get("observations_count") or 0)),
            "summaries_count": max(0, int(raw_ms.get("summaries_count") or 0)),
            "instincts_count": max(0, int(raw_ms.get("instincts_count") or 0)),
            "active_instincts_preview": _redact_bot_text(raw_ms.get("active_instincts_preview") or "", max_len=2000),
        }
        if isinstance(raw_ms.get("team_memory"), list):
            tm_out = []
            for row in raw_ms["team_memory"][:64]:
                if not isinstance(row, dict):
                    continue
                tm_out.append({
                    "handle": _sanitize_slug(row.get("handle") or "", max_len=64),
                    "project": _sanitize_slug(row.get("project") or "", max_len=80),
                    "observations_count": max(0, int(row.get("observations_count") or 0)),
                    "summaries_count": max(0, int(row.get("summaries_count") or 0)),
                    "instincts_count": max(0, int(row.get("instincts_count") or 0)),
                })
            mem_stats["team_memory"] = tm_out
            mem_stats["total_observations"] = max(0, int(raw_ms.get("total_observations") or 0))
            mem_stats["total_summaries"] = max(0, int(raw_ms.get("total_summaries") or 0))
            mem_stats["total_instincts"] = max(0, int(raw_ms.get("total_instincts") or 0))

        role_val = _sanitize_slug(raw.get("role") or "worker", max_len=24) or "worker"
        return {
            "ok": True,
            "ipc_online": ipc_online,
            "can_edit": can_edit and ipc_online,
            "handle": handle,
            "role": role_val,
            "rev": max(0, int(raw.get("rev") or 0)),
            "max_doc_bytes": MAX_PROFILE_DOC_BYTES,
            "specialty": _redact_bot_text(raw.get("specialty") or "", max_len=160),
            "memory_project": _sanitize_slug(raw.get("memory_project") or f"bot-{handle}", max_len=80) or f"bot-{handle}",
            "memory_scope": _sanitize_slug(raw.get("memory_scope") or ("coordinator_all" if role_val == "coordinator" else "isolated"), max_len=24),
            "updated_at": max(0, int(raw.get("updated_at") or 0)),
            "updated_by": _redact_bot_text(raw.get("updated_by") or "", max_len=64),
            "docs": docs_out,
            "doc_bytes": doc_bytes,
            "skills_policy": {"mode": pmode, "enabled_catalog_skills": en_list},
            "own_skills": own_skills,
            "catalog_skills": catalog_skills,
            "team_skills": team_skills,
            "effective_skills": effective_skills,
            "memory_stats": mem_stats,
        }

    # ------------------------------------------------------------------ GET /api/bots/{handle}/profile
    async def handle_get_bot_profile(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)

        handle = _normalize_strict_handle(request.match_info.get("handle") or "")
        if not handle:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 Bot handle 格式"},
                status=400,
                headers=_PRIVATE_GET_HEADERS,
            )

        roster_bot = self._find_roster_bot(handle)
        ipc_ep = self._resolve_bot_ipc(handle)
        if roster_bot is None and ipc_ep is None:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的 Bot 节点"},
                status=404,
                headers=_PRIVATE_GET_HEADERS,
            )

        can_edit = sess.get("role") == "admin"
        if ipc_ep is not None:
            sock_p, tok = ipc_ep
            sc, data = await self._ipc_request_json(
                sock_path=sock_p,
                token=tok,
                method="GET",
                path="/ipc/bot/profile",
            )
            if sc == 200 and data.get("ok"):
                return web.json_response(
                    self._sanitize_profile_response(
                        handle=handle,
                        raw=data,
                        ipc_online=True,
                        can_edit=can_edit,
                    ),
                    headers=_PRIVATE_GET_HEADERS,
                )

        fallback = dict(roster_bot or {})
        return web.json_response(
            self._sanitize_profile_response(
                handle=handle,
                raw=fallback,
                ipc_online=False,
                can_edit=False,
            ),
            headers=_PRIVATE_GET_HEADERS,
        )

    # ------------------------------------------------------------------ PUT /api/bots/{handle}/profile
    async def handle_put_bot_profile(self, request: web.Request) -> web.Response:
        raw_h = request.match_info.get("handle") or ""
        handle = _normalize_strict_handle(raw_h)
        safe_tid = handle or _sanitize_slug(raw_h, max_len=64)

        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="bot.profile.put", target_id=safe_tid
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        if not handle:
            self.audit.record(
                action="bot.profile.put",
                status_code=400,
                outcome="denied_invalid_handle",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 Bot handle 格式"},
                status=400,
            )

        roster_bot = self._find_roster_bot(handle)
        ipc_ep = self._resolve_bot_ipc(handle)
        if roster_bot is None and ipc_ep is None:
            self.audit.record(
                action="bot.profile.put",
                status_code=404,
                outcome="denied_unknown_bot",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的 Bot 节点"},
                status=404,
            )

        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROFILE_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action="bot.profile.put",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_PROFILE_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action="bot.profile.put",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        extra_keys = set(body.keys()) - _ALLOWED_PROFILE_PUT_KEYS
        if extra_keys:
            self.audit.record(
                action="bot.profile.put",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "存在未允许的 Profile 字段"},
                status=400,
            )

        exp_rev = self._parse_expected_rev(body.get("expected_rev"))
        if exp_rev is None:
            self.audit.record(
                action="bot.profile.put",
                status_code=400,
                outcome="denied_missing_expected_rev",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "缺少有效的整数 expected_rev 乐观锁版本号"},
                status=400,
            )

        ipc_payload: dict[str, Any] = {
            "user_id": int(sess["user_id"]),
            "actor_username": str(sess.get("username") or "")[:64],
            "expected_rev": exp_rev,
        }

        if "doc" in body or "content" in body:
            doc_val = body.get("doc")
            content_val = body.get("content")
            if not isinstance(doc_val, str) or doc_val not in _ALLOWED_PROFILE_DOCS:
                self.audit.record(
                    action="bot.profile.put",
                    status_code=400,
                    outcome="denied_invalid_doc",
                    client_ip=client_ip,
                    target_id=handle,
                    sess=sess,
                    bot_override=handle,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "doc 仅允许 SOUL.md / RULES.md / MEMORY.md"},
                    status=400,
                )
            if not isinstance(content_val, str) or "\x00" in content_val:
                self.audit.record(
                    action="bot.profile.put",
                    status_code=400,
                    outcome="denied_invalid_content",
                    client_ip=client_ip,
                    target_id=handle,
                    sess=sess,
                    bot_override=handle,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "文档内容必须为不含 NUL 字节的合法 UTF-8 字符串"},
                    status=400,
                )
            if len(content_val.encode("utf-8")) > MAX_PROFILE_DOC_BYTES:
                self.audit.record(
                    action="bot.profile.put",
                    status_code=413,
                    outcome="denied_doc_too_large",
                    client_ip=client_ip,
                    target_id=handle,
                    sess=sess,
                    bot_override=handle,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "单文档超过 24 KiB UTF-8 上限"},
                    status=413,
                )
            ipc_payload["doc"] = doc_val
            ipc_payload["content"] = content_val

        if "docs" in body:
            raw_docs = body.get("docs")
            if not isinstance(raw_docs, dict):
                self.audit.record(
                    action="bot.profile.put",
                    status_code=400,
                    outcome="denied_invalid_docs",
                    client_ip=client_ip,
                    target_id=handle,
                    sess=sess,
                    bot_override=handle,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "docs 必须为对象映射"},
                    status=400,
                )
            clean_docs: dict[str, str] = {}
            for dk, dv in raw_docs.items():
                if dk not in _ALLOWED_PROFILE_DOCS or not isinstance(dv, str) or "\x00" in dv:
                    self.audit.record(
                        action="bot.profile.put",
                        status_code=400,
                        outcome="denied_invalid_doc",
                        client_ip=client_ip,
                        target_id=handle,
                        sess=sess,
                        bot_override=handle,
                    )
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "docs 包含非法键名或内容"},
                        status=400,
                    )
                if len(dv.encode("utf-8")) > MAX_PROFILE_DOC_BYTES:
                    self.audit.record(
                        action="bot.profile.put",
                        status_code=413,
                        outcome="denied_doc_too_large",
                        client_ip=client_ip,
                        target_id=handle,
                        sess=sess,
                        bot_override=handle,
                    )
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "单文档超过 24 KiB UTF-8 上限"},
                        status=413,
                    )
                clean_docs[dk] = dv
            ipc_payload["docs"] = clean_docs

        if "skills_policy" in body:
            sp = body.get("skills_policy")
            if not isinstance(sp, dict):
                self.audit.record(
                    action="bot.profile.put",
                    status_code=400,
                    outcome="denied_invalid_skills_policy",
                    client_ip=client_ip,
                    target_id=handle,
                    sess=sess,
                    bot_override=handle,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "skills_policy 必须为对象"},
                    status=400,
                )
            ipc_payload["skills_policy"] = sp

        if "specialty" in body:
            spec = body.get("specialty")
            if not isinstance(spec, str) or "\x00" in spec or len(spec.encode("utf-8")) > 1024:
                self.audit.record(
                    action="bot.profile.put",
                    status_code=400,
                    outcome="denied_invalid_specialty",
                    client_ip=client_ip,
                    target_id=handle,
                    sess=sess,
                    bot_override=handle,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "specialty 格式或长度无效"},
                    status=400,
                )
            ipc_payload["specialty"] = spec

        if ipc_ep is None:
            self.audit.record(
                action="bot.profile.put",
                status_code=503,
                outcome="error_ipc_offline",
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "upstream", "error": "目标 Bot Bridge IPC 离线，无法保存 Profile"},
                status=503,
            )

        sock_p, tok = ipc_ep
        sc, data = await self._ipc_request_json(
            sock_path=sock_p,
            token=tok,
            method="POST",
            path="/ipc/bot/profile",
            payload=ipc_payload,
        )
        if sc >= 400 or not data.get("ok"):
            outcome = "conflict_rev" if sc == 409 else ("error_ipc" if sc >= 500 else "denied_ipc")
            self.audit.record(
                action="bot.profile.put",
                status_code=sc,
                outcome=outcome,
                client_ip=client_ip,
                target_id=handle,
                sess=sess,
                bot_override=handle,
            )
            err_body: dict[str, Any] = {
                "ok": False,
                "source": "upstream",
                "error": _redact_bot_text(data.get("error") or "保存 Profile 失败", max_len=200),
            }
            if data.get("code"):
                err_body["code"] = _sanitize_slug(data.get("code"), max_len=32)
            if isinstance(data.get("current_rev"), int):
                err_body["current_rev"] = int(data["current_rev"])
            return web.json_response(err_body, status=sc)

        self.audit.record(
            action="bot.profile.put",
            status_code=200,
            outcome="allowed",
            client_ip=client_ip,
            target_id=handle,
            sess=sess,
            bot_override=handle,
        )
        self.event_hub.publish(
            "bots_updated",
            {"handle": handle, "action": "profile_updated", "source": "studio"},
        )
        return web.json_response(
            self._sanitize_profile_response(
                handle=handle,
                raw=data,
                ipc_online=True,
                can_edit=True,
            ),
            headers=_PRIVATE_GET_HEADERS,
        )

    # ------------------------------------------------------------------ GET /api/bots/{handle}/skills/{slug}
    async def handle_get_bot_skill(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)

        handle = _normalize_strict_handle(request.match_info.get("handle") or "")
        slug = self._validate_skill_slug(request.match_info.get("slug") or "")
        if not handle or not slug:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 Bot handle 或 skill slug 格式"},
                status=400,
                headers=_PRIVATE_GET_HEADERS,
            )

        roster_bot = self._find_roster_bot(handle)
        ipc_ep = self._resolve_bot_ipc(handle)
        if roster_bot is None and ipc_ep is None:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的 Bot 节点"},
                status=404,
                headers=_PRIVATE_GET_HEADERS,
            )
        if ipc_ep is None:
            return web.json_response(
                {"ok": False, "source": "upstream", "error": "目标 Bot Bridge IPC 离线"},
                status=503,
                headers=_PRIVATE_GET_HEADERS,
            )

        sock_p, tok = ipc_ep
        sc, data = await self._ipc_request_json(
            sock_path=sock_p,
            token=tok,
            method="GET",
            path=f"/ipc/bot/skills?slug={slug}",
        )
        if sc >= 400 or not data.get("ok"):
            return web.json_response(
                {
                    "ok": False,
                    "source": "upstream",
                    "error": _redact_bot_text(data.get("error") or "读取 Skill 失败", max_len=200),
                },
                status=sc,
                headers=_PRIVATE_GET_HEADERS,
            )

        content = data.get("content") if isinstance(data.get("content"), str) else ""
        return web.json_response(
            {
                "ok": True,
                "handle": handle,
                "slug": slug,
                "rev": max(0, int(data.get("rev") or 0)),
                "name": _sanitize_slug(data.get("name") or slug, max_len=64) or slug,
                "description": _redact_bot_text(data.get("description") or "", max_len=160),
                "content": content,
                "size_bytes": len(content.encode("utf-8")),
                "max_doc_bytes": MAX_PROFILE_DOC_BYTES,
                "can_edit": sess.get("role") == "admin",
            },
            headers=_PRIVATE_GET_HEADERS,
        )

    # ------------------------------------------------------------------ PUT /api/bots/{handle}/skills/{slug}
    async def handle_put_bot_skill(self, request: web.Request) -> web.Response:
        raw_h = request.match_info.get("handle") or ""
        raw_slug = request.match_info.get("slug") or ""
        handle = _normalize_strict_handle(raw_h)
        slug = self._validate_skill_slug(raw_slug)
        safe_tid = f"{handle or _sanitize_slug(raw_h, max_len=32)}:{slug or _sanitize_slug(raw_slug, max_len=32)}"

        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="bot.skill.put", target_id=safe_tid
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        if not handle or not slug:
            self.audit.record(
                action="bot.skill.put",
                status_code=400,
                outcome="denied_invalid_handle_or_slug",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 Bot handle 或 skill slug 格式"},
                status=400,
            )

        roster_bot = self._find_roster_bot(handle)
        ipc_ep = self._resolve_bot_ipc(handle)
        if roster_bot is None and ipc_ep is None:
            self.audit.record(
                action="bot.skill.put",
                status_code=404,
                outcome="denied_unknown_bot",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的 Bot 节点"},
                status=404,
            )

        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROFILE_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action="bot.skill.put",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_PROFILE_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action="bot.skill.put",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        extra_keys = set(body.keys()) - _ALLOWED_SKILL_PUT_KEYS
        if extra_keys:
            self.audit.record(
                action="bot.skill.put",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "存在未允许的 Skill 字段"},
                status=400,
            )

        exp_rev = self._parse_expected_rev(body.get("expected_rev"))
        content = body.get("content")
        if exp_rev is None:
            self.audit.record(
                action="bot.skill.put",
                status_code=400,
                outcome="denied_missing_expected_rev",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "缺少有效的整数 expected_rev 乐观锁版本号"},
                status=400,
            )
        if not isinstance(content, str) or "\x00" in content:
            self.audit.record(
                action="bot.skill.put",
                status_code=400,
                outcome="denied_invalid_content",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "SKILL.md 内容必须为不含 NUL 字节的合法字符串"},
                status=400,
            )
        if len(content.encode("utf-8")) > MAX_PROFILE_DOC_BYTES:
            self.audit.record(
                action="bot.skill.put",
                status_code=413,
                outcome="denied_doc_too_large",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "SKILL.md 超过 24 KiB UTF-8 上限"},
                status=413,
            )

        if ipc_ep is None:
            self.audit.record(
                action="bot.skill.put",
                status_code=503,
                outcome="error_ipc_offline",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "upstream", "error": "目标 Bot Bridge IPC 离线，无法保存 Skill"},
                status=503,
            )

        sock_p, tok = ipc_ep
        sc, data = await self._ipc_request_json(
            sock_path=sock_p,
            token=tok,
            method="POST",
            path="/ipc/bot/skills",
            payload={
                "user_id": int(sess["user_id"]),
                "actor_username": str(sess.get("username") or "")[:64],
                "slug": slug,
                "content": content,
                "expected_rev": exp_rev,
            },
        )
        if sc >= 400 or not data.get("ok"):
            outcome = "conflict_rev" if sc == 409 else ("error_ipc" if sc >= 500 else "denied_ipc")
            self.audit.record(
                action="bot.skill.put",
                status_code=sc,
                outcome=outcome,
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            err_body: dict[str, Any] = {
                "ok": False,
                "source": "upstream",
                "error": _redact_bot_text(data.get("error") or "保存 Skill 失败", max_len=200),
            }
            if data.get("code"):
                err_body["code"] = _sanitize_slug(data.get("code"), max_len=32)
            if isinstance(data.get("current_rev"), int):
                err_body["current_rev"] = int(data["current_rev"])
            return web.json_response(err_body, status=sc)

        self.audit.record(
            action="bot.skill.put",
            status_code=200,
            outcome="allowed",
            client_ip=client_ip,
            target_id=safe_tid,
            sess=sess,
            bot_override=handle,
        )
        self.event_hub.publish(
            "bots_updated",
            {"handle": handle, "action": "skill_updated", "slug": slug, "source": "studio"},
        )
        saved_content = data.get("content") if isinstance(data.get("content"), str) else content
        return web.json_response(
            {
                "ok": True,
                "handle": handle,
                "slug": slug,
                "rev": max(0, int(data.get("rev") or 0)),
                "name": _sanitize_slug(data.get("name") or slug, max_len=64) or slug,
                "description": _redact_bot_text(data.get("description") or "", max_len=160),
                "content": saved_content,
                "size_bytes": len(saved_content.encode("utf-8")),
                "max_doc_bytes": MAX_PROFILE_DOC_BYTES,
                "can_edit": True,
            },
            headers=_PRIVATE_GET_HEADERS,
        )

    # ------------------------------------------------------------------ DELETE /api/bots/{handle}/skills/{slug}
    async def handle_delete_bot_skill(self, request: web.Request) -> web.Response:
        raw_h = request.match_info.get("handle") or ""
        raw_slug = request.match_info.get("slug") or ""
        handle = _normalize_strict_handle(raw_h)
        slug = self._validate_skill_slug(raw_slug)
        safe_tid = f"{handle or _sanitize_slug(raw_h, max_len=32)}:{slug or _sanitize_slug(raw_slug, max_len=32)}"

        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="bot.skill.delete", target_id=safe_tid
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        if not handle or not slug:
            self.audit.record(
                action="bot.skill.delete",
                status_code=400,
                outcome="denied_invalid_handle_or_slug",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 Bot handle 或 skill slug 格式"},
                status=400,
            )

        roster_bot = self._find_roster_bot(handle)
        ipc_ep = self._resolve_bot_ipc(handle)
        if roster_bot is None and ipc_ep is None:
            self.audit.record(
                action="bot.skill.delete",
                status_code=404,
                outcome="denied_unknown_bot",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的 Bot 节点"},
                status=404,
            )

        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action="bot.skill.delete",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_PROFILE_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action="bot.skill.delete",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        extra_keys = set(body.keys()) - _ALLOWED_SKILL_DELETE_KEYS
        if extra_keys:
            self.audit.record(
                action="bot.skill.delete",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "存在未允许的删除参数"},
                status=400,
            )

        exp_rev = self._parse_expected_rev(body.get("expected_rev"))
        if exp_rev is None:
            self.audit.record(
                action="bot.skill.delete",
                status_code=400,
                outcome="denied_missing_expected_rev",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "缺少有效的整数 expected_rev 乐观锁版本号"},
                status=400,
            )

        if ipc_ep is None:
            self.audit.record(
                action="bot.skill.delete",
                status_code=503,
                outcome="error_ipc_offline",
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            return web.json_response(
                {"ok": False, "source": "upstream", "error": "目标 Bot Bridge IPC 离线，无法删除 Skill"},
                status=503,
            )

        sock_p, tok = ipc_ep
        sc, data = await self._ipc_request_json(
            sock_path=sock_p,
            token=tok,
            method="DELETE",
            path="/ipc/bot/skills",
            payload={
                "user_id": int(sess["user_id"]),
                "actor_username": str(sess.get("username") or "")[:64],
                "slug": slug,
                "expected_rev": exp_rev,
            },
        )
        if sc >= 400 or not data.get("ok"):
            outcome = "conflict_rev" if sc == 409 else ("error_ipc" if sc >= 500 else "denied_ipc")
            self.audit.record(
                action="bot.skill.delete",
                status_code=sc,
                outcome=outcome,
                client_ip=client_ip,
                target_id=safe_tid,
                sess=sess,
                bot_override=handle,
            )
            err_body: dict[str, Any] = {
                "ok": False,
                "source": "upstream",
                "error": _redact_bot_text(data.get("error") or "删除 Skill 失败", max_len=200),
            }
            if data.get("code"):
                err_body["code"] = _sanitize_slug(data.get("code"), max_len=32)
            if isinstance(data.get("current_rev"), int):
                err_body["current_rev"] = int(data["current_rev"])
            return web.json_response(err_body, status=sc)

        self.audit.record(
            action="bot.skill.delete",
            status_code=200,
            outcome="allowed",
            client_ip=client_ip,
            target_id=safe_tid,
            sess=sess,
            bot_override=handle,
        )
        self.event_hub.publish(
            "bots_updated",
            {"handle": handle, "action": "skill_deleted", "slug": slug, "source": "studio"},
        )
        return web.json_response(
            {
                "ok": True,
                "deleted": True,
                "handle": handle,
                "slug": slug,
                "rev": max(0, int(data.get("rev") or 0)),
            },
            headers=_PRIVATE_GET_HEADERS,
        )
