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

_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_VALID_MODEL_MODES = frozenset({"default", "follow", "custom"})
_VALID_EFFORTS = frozenset({"", "low", "medium", "high", "xhigh", "max"})

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
