#!/usr/bin/env python3
"""AGY Studio Phase A M2 — Safe Control Plane APIs for Jobs & Schedules.

Enforces the exact four-layer write gate across all mutating endpoints:
  1. Strict Same-Origin (`Origin` required & matched) -> 403
  2. Non-simple request `Content-Type: application/json` -> 415
  3. Cookie + live RBAC + `must_change_password=False` -> 401/403
  4. `X-Studio-CSRF` + `role == "admin"` -> 403
Plus bounded JSON body reading (`<= 32 KiB`, both fixed-length & chunked -> 413)
and append-only `0600` JSONL audit logging on EVERY allow/deny/error branch
(strictly zero secrets, prompts, scripts, cookies, or CSRF tokens logged).

RCE Absolute Ban (`PA-C6`):
- `task_type == "script"` and any `precheck_cmd` / `script` / `command` / `cmd` / `shell`
  field are strictly forbidden (403) across create, patch, and run.
- Existing CLI-created `script` or `precheck_cmd` tasks are read-only (`read_only_cli: true`),
  never expose command text, allow ONLY emergency disable (`PATCH {"enabled": false}`),
  and return 403 on re-enable, edit, delete, or run.
"""

from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path
import sys
from typing import Any

import aiohttp
from aiohttp import web

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BRIDGE_SRC_DIR = _REPO_ROOT / "bridge"
if str(_BRIDGE_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_BRIDGE_SRC_DIR))

import bot_bus  # noqa: E402
import scheduler  # noqa: E402
import studio_ipc  # noqa: E402

from .auth import StudioAuthManager, studio_auth_error, upstream_error
from .chat_service import (
    MAX_PROMPT_BODY_BYTES,
    StudioAuditLogger,
    _extract_media_type,
    _read_bounded_json_body,
)
from .data_sources import (
    StudioDataSources,
    _sanitize_slug,
    is_read_only_cli_schedule,
    redact_secrets_only,
)
from .event_hub import StudioEventHub

log = logging.getLogger("agy-studio.control_plane")

MAX_JOB_PROMPT_BYTES = 16 * 1024
MAX_SCHEDULE_PROMPT_BYTES = 16 * 1024
MAX_STUDIO_DISPATCH_FANOUT = 6
MIN_CRON_INTERVAL_SECS = 300

_VALID_EFFORTS = frozenset({"low", "medium", "high", "xhigh", "max"})
_ALLOWED_JOB_ASSIGNMENT_KEYS = frozenset({"bot", "prompt", "label", "project", "model", "effort"})
_FORBIDDEN_JOB_KEYS = frozenset({
    "workdir",
    "target_chat_id",
    "chat_id",
    "thread_id",
    "target_thread_id",
    "role",
    "reply_to",
    "origin_chat_id",
    "origin_thread_id",
    "origin_msg_id",
    "ipc_sock",
})

_ALLOWED_SCHEDULE_TASK_TYPES = frozenset({"prompt", "reminder"})
_ALLOWED_SCHEDULE_CREATE_KEYS = frozenset({
    "name",
    "schedule_expr",
    "task_type",
    "prompt",
    "project",
    "model",
    "enabled",
    "silent_if_empty",
    "bot",
})
_ALLOWED_SCHEDULE_PATCH_KEYS = frozenset({
    "name",
    "schedule_expr",
    "task_type",
    "prompt",
    "project",
    "model",
    "enabled",
    "silent_if_empty",
})
_FORBIDDEN_SCHEDULE_RCE_KEYS = frozenset({
    "precheck_cmd",
    "script",
    "command",
    "cmd",
    "shell",
})
_FORBIDDEN_SCHEDULE_ROUTE_KEYS = frozenset({
    "workdir",
    "target_chat_id",
    "chat_id",
    "thread_id",
    "target_thread_id",
    "role",
    "reply_to",
    "delivery",
    "handoff_bot",
    "ipc_sock",
})


_MAX_FORBIDDEN_SCAN_DEPTH = 16


def _find_forbidden_key_recursive(obj: Any, forbidden: frozenset[str], *, depth: int = 0) -> str | None:
    if depth > _MAX_FORBIDDEN_SCAN_DEPTH:
        return "max_depth_exceeded"
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).strip().lower()
            if kl in forbidden:
                return kl
            found = _find_forbidden_key_recursive(v, forbidden, depth=depth + 1)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_forbidden_key_recursive(item, forbidden, depth=depth + 1)
            if found:
                return found
    return None


class StudioControlPlane:
    """Control plane handlers for Jobs R/W and Schedules Safe R/W."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        data_sources: StudioDataSources,
        event_hub: StudioEventHub,
        audit: StudioAuditLogger,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.event_hub = event_hub
        self.audit = audit

    # ------------------------------------------------------------------ Shared Helpers
    def _ipc_dir(self) -> Path:
        return (self.data_sources.bus_dir / "ipc").resolve()

    def _resolve_ipc_endpoint(self, requested_bot: str | None = None) -> tuple[str, Path, str] | None:
        ipc_dir = self._ipc_dir()
        if not ipc_dir.is_dir():
            return None

        candidates: list[str] = []
        if requested_bot:
            clean = _sanitize_slug(str(requested_bot).lstrip("@").lower(), max_len=64)
            if clean:
                candidates.append(clean)
        else:
            bots_info = self.data_sources.get_bots()
            for b in bots_info.get("bots") or []:
                h = str(b.get("handle") or "").strip().lower()
                if h and b.get("online"):
                    candidates.append(h)
            try:
                for p in sorted(ipc_dir.glob("*.sock")):
                    if p.stem not in candidates:
                        candidates.append(p.stem)
            except OSError:
                pass

        for handle in candidates:
            safe_h = handle.lstrip("@").lower()
            if not safe_h or "/" in safe_h or ".." in safe_h:
                continue
            sock_p = (ipc_dir / f"{safe_h}.sock").resolve()
            tok_p = (ipc_dir / f"{safe_h}.token").resolve()
            try:
                sock_p.relative_to(ipc_dir)
                tok_p.relative_to(ipc_dir)
            except ValueError:
                continue
            if not sock_p.exists() or not tok_p.is_file():
                continue
            try:
                token = tok_p.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if token:
                return safe_h, sock_p, token
        return None

    async def _ipc_request_json(
        self,
        *,
        sock_path: Path,
        token: str,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        timeout_sec: float = 10.0,
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
            log.warning("ControlPlane Bridge IPC %s %s failed: %s", method, path, type(exc).__name__)
            return 502, {"ok": False, "source": "upstream", "error": "Bridge IPC 服务暂不可达"}

    def _task_manager(self) -> scheduler.TaskManager:
        sf = self.data_sources.schedules_file
        lock_path = sf.parent / f".{sf.name}.lock"
        return scheduler.TaskManager(filepath=str(sf), lockpath=str(lock_path))

    async def _enforce_write_gate(
        self,
        request: web.Request,
        *,
        action: str,
        target_id: str = "",
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        client_ip = self.auth_mgr.extract_client_ip(request)

        # Gate 1: Strict Same-Origin (`Origin` required & matched)
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

        # Gate 2: Non-simple request Content-Type enforcement (`application/json` only -> 415)
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

        # Gate 3: Authenticated session cookie + live RBAC + `must_change_password=False`
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

        # Gate 4b: Live RBAC admin role requirement
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

    def _validate_schedule_expr(self, expr: Any) -> tuple[bool, str, str, str | None, datetime.datetime | None]:
        """Validate schedule_expr syntax and >= 300s interval floor.

        Returns `(ok, err_msg, sched_type, cron_expr, next_run_dt)`.
        """
        if not isinstance(expr, str) or not expr.strip():
            return False, "计划表达式 schedule_expr 不能为空", "", None, None
        clean = expr.strip()
        if len(clean) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in clean):
            return False, "计划表达式格式无效", "", None, None

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        tz, _ = scheduler.get_scheduler_tz(self.data_sources.cost_tz_name)

        rel_dt = scheduler.parse_relative_time(clean, from_dt_utc=now_utc)
        if rel_dt is not None:
            gap = (rel_dt - now_utc).total_seconds()
            if gap < MIN_CRON_INTERVAL_SECS:
                return (
                    False,
                    f"定时触发间隔过短 ({int(gap)}秒)，最小间隔限制为 {MIN_CRON_INTERVAL_SECS // 60} 分钟",
                    "",
                    None,
                    None,
                )
            return True, "", "once", None, rel_dt

        try:
            first_dt = scheduler.validate_cron_min_interval(
                clean, tz, min_secs=MIN_CRON_INTERVAL_SECS, from_dt=now_utc
            )
        except Exception as exc:
            return False, str(exc), "", None, None
        return True, "", "cron", clean, first_dt

    # ------------------------------------------------------------------ A. Jobs APIs
    async def handle_get_job_detail(self, request: web.Request) -> web.Response:
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            return studio_auth_error(err_auth, status=status_code)
        job_id = str(request.match_info.get("job_id") or "").strip()
        sc, payload = self.data_sources.get_job_detail(job_id)
        return web.json_response(payload, status=sc)

    async def handle_dispatch_jobs(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="jobs.dispatch")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action="jobs.dispatch",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        # Reject forbidden fields anywhere in payload
        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_JOB_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action="jobs.dispatch",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        # Normalize single vs batch format under strict field whitelist
        if "assignments" in body:
            extra_top = set(body.keys()) - {"assignments"}
            if extra_top:
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_unknown_field",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "存在未允许的顶层字段"},
                    status=400,
                )
            raw_assignments = body.get("assignments")
            if not isinstance(raw_assignments, list):
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_invalid_assignments",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "assignments 必须为数组"},
                    status=400,
                )
        else:
            extra_top = set(body.keys()) - _ALLOWED_JOB_ASSIGNMENT_KEYS
            if extra_top:
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_unknown_field",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "存在未允许的请求字段"},
                    status=400,
                )
            raw_assignments = [body]

        if len(raw_assignments) == 0 or len(raw_assignments) > MAX_STUDIO_DISPATCH_FANOUT:
            self.audit.record(
                action="jobs.dispatch",
                status_code=400,
                outcome="denied_fanout_limit",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": f"批量派工数量必须在 1 到 {MAX_STUDIO_DISPATCH_FANOUT} 之间",
                },
                status=400,
            )

        # Snapshot live roster
        bots_data = self.data_sources.get_bots()
        roster_by_handle = {
            str(b.get("handle") or "").strip().lower(): b
            for b in (bots_data.get("bots") or [])
            if b.get("handle")
        }

        validated_specs: list[dict[str, Any]] = []
        for idx, item in enumerate(raw_assignments):
            if not isinstance(item, dict):
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_invalid_assignment",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"第 {idx + 1} 条派工必须为 JSON 对象"},
                    status=400,
                )
            extra_keys = set(item.keys()) - _ALLOWED_JOB_ASSIGNMENT_KEYS
            if extra_keys:
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_unknown_field",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"第 {idx + 1} 条派工包含未允许字段"},
                    status=400,
                )

            raw_bot = item.get("bot")
            if not isinstance(raw_bot, str) or not raw_bot.strip():
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_missing_bot",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"第 {idx + 1} 条派工缺少目标 bot"},
                    status=400,
                )
            norm_bot = bot_bus.normalize_handle(raw_bot)
            bot_entry = roster_by_handle.get(norm_bot)
            if bot_entry is None:
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_unknown_bot",
                    client_ip=client_ip,
                    sess=sess,
                    bot_override=norm_bot,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"目标 Bot 不在 live roster 中: {norm_bot}"},
                    status=400,
                )
            if not bot_entry.get("online"):
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=409,
                    outcome="denied_bot_offline",
                    client_ip=client_ip,
                    sess=sess,
                    bot_override=norm_bot,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"目标 Bot 当前离线，无法派发: {norm_bot}"},
                    status=409,
                )

            prompt = item.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_empty_prompt",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"第 {idx + 1} 条派工 prompt 不能为空"},
                    status=400,
                )
            if len(prompt.encode("utf-8")) > MAX_JOB_PROMPT_BYTES:
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_prompt_too_large",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"第 {idx + 1} 条派工 prompt 超过 16 KiB 上限"},
                    status=400,
                )

            raw_label = item.get("label")
            if raw_label is not None and not isinstance(raw_label, str):
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_invalid_label",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "label 必须为字符串"},
                    status=400,
                )
            clean_label = str(raw_label or "").strip()[:120]

            raw_proj = item.get("project")
            mapped_project = ""
            mapped_workdir = ""
            if raw_proj is not None:
                if not isinstance(raw_proj, str):
                    self.audit.record(
                        action="jobs.dispatch",
                        status_code=400,
                        outcome="denied_invalid_project",
                        client_ip=client_ip,
                        sess=sess,
                    )
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "project 必须为字符串"},
                        status=400,
                    )
                if raw_proj.strip() != "":
                    resolved_proj = self.data_sources.resolve_allowed_project(raw_proj)
                    if resolved_proj is None:
                        self.audit.record(
                            action="jobs.dispatch",
                            status_code=400,
                            outcome="denied_invalid_project",
                            client_ip=client_ip,
                            sess=sess,
                        )
                        return web.json_response(
                            {"ok": False, "source": "studio_api", "error": "指定的 project 不在允许白名单中"},
                            status=400,
                        )
                    mapped_project = resolved_proj["id"]
                    mapped_workdir = resolved_proj["workdir"]

            raw_effort_val = item.get("effort")
            if raw_effort_val is not None and not isinstance(raw_effort_val, str):
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_invalid_effort",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "effort 必须为字符串"},
                    status=400,
                )
            raw_effort = (raw_effort_val or "").strip().lower()
            if raw_effort and raw_effort not in _VALID_EFFORTS:
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_invalid_effort",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "无效的 effort 参数"},
                    status=400,
                )

            raw_model_val = item.get("model")
            if raw_model_val is not None and not isinstance(raw_model_val, str):
                self.audit.record(
                    action="jobs.dispatch",
                    status_code=400,
                    outcome="denied_invalid_model",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "model 必须为字符串"},
                    status=400,
                )
            raw_model = (raw_model_val or "").strip()
            clean_model = _sanitize_slug(raw_model, max_len=96) if raw_model else ""

            validated_specs.append({
                "bot": norm_bot,
                "prompt": prompt.strip(),
                "label": clean_label,
                "project": mapped_project,
                "workdir": mapped_workdir,
                "model": clean_model,
                "effort": raw_effort,
            })

        try:
            dispatched = bot_bus.dispatch_jobs_in_dir(
                str(self.data_sources.bus_dir),
                "studio",
                validated_specs,
                max_fanout=MAX_STUDIO_DISPATCH_FANOUT,
            )
        except Exception as exc:
            self.audit.record(
                action="jobs.dispatch",
                status_code=500,
                outcome=f"error_{type(exc).__name__}",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "派工入队失败"},
                status=500,
            )

        created_jobs = dispatched.get("jobs") or []
        job_ids = [str(j.get("job_id") or "") for j in created_jobs]
        group_id = str(dispatched.get("group_id") or "")

        self.event_hub.publish(
            "job_updated",
            {
                "action": "dispatch",
                "group_id": group_id,
                "job_ids": job_ids,
                "count": len(job_ids),
            },
        )
        self.audit.record(
            action="jobs.dispatch",
            status_code=202,
            outcome="allowed",
            client_ip=client_ip,
            target_id=job_ids[0] if len(job_ids) == 1 else group_id,
            sess=sess,
            bot_override=validated_specs[0]["bot"] if len(validated_specs) == 1 else "",
        )

        safe_jobs = [
            {
                "job_id": _sanitize_slug(j.get("job_id"), max_len=64),
                "group_id": _sanitize_slug(j.get("group_id"), max_len=64),
                "label": redact_secrets_only(j.get("label") or "", max_len=120),
                "from_bot": _sanitize_slug(j.get("from_bot"), max_len=64),
                "target_bot": _sanitize_slug(j.get("target_bot"), max_len=64),
                "status": "queued",
                "project": _sanitize_slug(j.get("project"), max_len=64),
                "model": _sanitize_slug(j.get("model"), max_len=64),
                "effort": _sanitize_slug(j.get("effort"), max_len=32),
                "created_at": float(j.get("created_at") or 0.0),
            }
            for j in created_jobs
        ]
        return web.json_response(
            {"ok": True, "group_id": group_id, "jobs": safe_jobs},
            status=202,
        )

    async def handle_cancel_job(self, request: web.Request) -> web.Response:
        job_id = str(request.match_info.get("job_id") or "").strip()
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="jobs.cancel", target_id=job_id
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, _body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=True
        )
        if not ok_body:
            self.audit.record(
                action="jobs.cancel",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        if not studio_ipc.is_valid_entity_id(job_id):
            self.audit.record(
                action="jobs.cancel",
                status_code=400,
                outcome="denied_invalid_job_id",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 job_id 格式"},
                status=400,
            )

        jobs_root = (self.data_sources.bus_dir / "jobs").resolve()
        candidate = (jobs_root / f"{job_id}.json").resolve()
        try:
            candidate.relative_to(jobs_root)
        except ValueError:
            self.audit.record(
                action="jobs.cancel",
                status_code=400,
                outcome="denied_invalid_job_id",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 job_id 路径"},
                status=400,
            )

        updated_job, already_terminal = bot_bus.cancel_job_in_dir(
            str(self.data_sources.bus_dir),
            job_id,
            reason="cancelled_by_studio",
        )
        if updated_job is None:
            self.audit.record(
                action="jobs.cancel",
                status_code=404,
                outcome="denied_not_found",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "派工单不存在"},
                status=404,
            )

        cur_status = str(updated_job.get("status") or "unknown").lower()
        target_bot = str(updated_job.get("target_bot") or "").strip().lower()

        if already_terminal:
            self.audit.record(
                action="jobs.cancel",
                status_code=200,
                outcome="allowed_already_terminal",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
                bot_override=target_bot,
            )
            return web.json_response(
                {
                    "ok": True,
                    "job_id": job_id,
                    "already_terminal": True,
                    "status": cur_status,
                },
                status=200,
            )

        if cur_status == "cancelled":
            self.event_hub.publish(
                "job_updated",
                {"action": "cancel", "job_id": job_id, "status": "cancelled"},
            )
            self.audit.record(
                action="jobs.cancel",
                status_code=200,
                outcome="allowed_queued_cancelled",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
                bot_override=target_bot,
            )
            return web.json_response(
                {
                    "ok": True,
                    "job_id": job_id,
                    "already_terminal": False,
                    "cancelled": True,
                    "status": "cancelled",
                },
                status=200,
            )

        # Running job -> notify owning Bridge via UDS POST /ipc/job/cancel
        resolved = self._resolve_ipc_endpoint(target_bot)
        if resolved is None:
            self.audit.record(
                action="jobs.cancel",
                status_code=503,
                outcome="upstream_unavailable",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
                bot_override=target_bot,
            )
            return upstream_error("目标 Bot 的 Bridge IPC 服务暂不可达", status=503)

        bot_handle, sock_path, ipc_token = resolved
        sc, resp_data = await self._ipc_request_json(
            sock_path=sock_path,
            token=ipc_token,
            method="POST",
            path="/ipc/job/cancel",
            payload={"job_id": job_id, "user_id": int(sess["user_id"])},
            timeout_sec=10.0,
        )
        self.audit.record(
            action="jobs.cancel",
            status_code=sc,
            outcome="allowed_running_ipc" if sc < 400 else f"denied_ipc_{sc}",
            client_ip=client_ip,
            target_id=job_id,
            sess=sess,
            bot_override=bot_handle,
        )
        if sc >= 400:
            safe_err = redact_secrets_only(resp_data.get("error") or f"Bridge IPC HTTP {sc}", max_len=200)
            return web.json_response(
                {"ok": False, "source": "upstream", "error": safe_err},
                status=sc,
            )

        final_st = _sanitize_slug(resp_data.get("status") or "cancelling", max_len=32)
        self.event_hub.publish(
            "job_updated",
            {"action": "cancel", "job_id": job_id, "status": final_st},
        )
        return web.json_response(
            {
                "ok": True,
                "job_id": job_id,
                "already_terminal": bool(resp_data.get("already_terminal", False)),
                "cancelled": bool(resp_data.get("cancelled", True)),
                "status": final_st,
                "via_ipc": True,
            },
            status=200,
        )

    async def handle_retry_job(self, request: web.Request) -> web.Response:
        job_id = str(request.match_info.get("job_id") or "").strip()
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="jobs.retry", target_id=job_id
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=True
        )
        if not ok_body or body is None:
            self.audit.record(
                action="jobs.retry",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_JOB_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action="jobs.retry",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        if body:
            self.audit.record(
                action="jobs.retry",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "重试接口不接受额外字段"},
                status=400,
            )

        if not studio_ipc.is_valid_entity_id(job_id):
            self.audit.record(
                action="jobs.retry",
                status_code=400,
                outcome="denied_invalid_job_id",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 job_id 格式"},
                status=400,
            )

        jobs_root = (self.data_sources.bus_dir / "jobs").resolve()
        candidate = (jobs_root / f"{job_id}.json").resolve()
        try:
            candidate.relative_to(jobs_root)
        except ValueError:
            self.audit.record(
                action="jobs.retry",
                status_code=400,
                outcome="denied_invalid_job_id",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 job_id 路径"},
                status=400,
            )

        if not candidate.is_file():
            self.audit.record(
                action="jobs.retry",
                status_code=404,
                outcome="denied_not_found",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "派工单不存在"},
                status=404,
            )

        try:
            orig = json.loads(candidate.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            orig = None
        if not isinstance(orig, dict):
            self.audit.record(
                action="jobs.retry",
                status_code=404,
                outcome="denied_corrupt_job",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "派工单记录损坏"},
                status=404,
            )

        cur_status = str(orig.get("status") or "").lower()
        if cur_status in ("queued", "running"):
            self.audit.record(
                action="jobs.retry",
                status_code=409,
                outcome="denied_conflict_active",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "排队中或运行中的任务不可重试"},
                status=409,
            )

        target_bot = bot_bus.normalize_handle(str(orig.get("target_bot") or ""))
        bots_data = self.data_sources.get_bots()
        roster_by_handle = {
            str(b.get("handle") or "").strip().lower(): b
            for b in (bots_data.get("bots") or [])
            if b.get("handle")
        }
        bot_entry = roster_by_handle.get(target_bot)
        if bot_entry is None:
            self.audit.record(
                action="jobs.retry",
                status_code=400,
                outcome="denied_unknown_bot",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
                bot_override=target_bot,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"目标 Bot 不在 live roster 中: {target_bot}"},
                status=400,
            )
        if not bot_entry.get("online"):
            self.audit.record(
                action="jobs.retry",
                status_code=409,
                outcome="denied_bot_offline",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
                bot_override=target_bot,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"目标 Bot 当前离线，无法重试: {target_bot}"},
                status=409,
            )

        orig_prompt = str(orig.get("prompt") or "").strip()
        if not orig_prompt or len(orig_prompt.encode("utf-8")) > MAX_JOB_PROMPT_BYTES:
            self.audit.record(
                action="jobs.retry",
                status_code=400,
                outcome="denied_invalid_orig_prompt",
                client_ip=client_ip,
                target_id=job_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "原任务 prompt 为空或超过 16 KiB 上限"},
                status=400,
            )

        # Re-validate project against server-side whitelist (never reuse untrusted raw workdir)
        mapped_project = ""
        mapped_workdir = ""
        orig_proj = str(orig.get("project") or "").strip()
        if orig_proj:
            resolved_proj = self.data_sources.resolve_allowed_project(orig_proj)
            if resolved_proj is not None:
                mapped_project = resolved_proj["id"]
                mapped_workdir = resolved_proj["workdir"]

        orig_effort = str(orig.get("effort") or "").strip().lower()
        if orig_effort not in _VALID_EFFORTS:
            orig_effort = ""
        orig_model = _sanitize_slug(orig.get("model") or "", max_len=96) if orig.get("model") else ""
        orig_label = str(orig.get("label") or f"retry:{job_id}").strip()[:120]

        dispatched = bot_bus.dispatch_jobs_in_dir(
            str(self.data_sources.bus_dir),
            "studio",
            [
                {
                    "bot": target_bot,
                    "prompt": orig_prompt,
                    "label": orig_label,
                    "project": mapped_project,
                    "workdir": mapped_workdir,
                    "model": orig_model,
                    "effort": orig_effort,
                }
            ],
            max_fanout=1,
        )
        new_job = (dispatched.get("jobs") or [{}])[0]
        new_job_id = str(new_job.get("job_id") or "")

        self.event_hub.publish(
            "job_updated",
            {
                "action": "retry",
                "job_id": new_job_id,
                "retried_from": job_id,
                "status": "queued",
            },
        )
        self.audit.record(
            action="jobs.retry",
            status_code=202,
            outcome="allowed",
            client_ip=client_ip,
            target_id=new_job_id,
            sess=sess,
            bot_override=target_bot,
        )
        return web.json_response(
            {
                "ok": True,
                "retried_from": job_id,
                "job_id": new_job_id,
                "job": {
                    "job_id": new_job_id,
                    "group_id": str(new_job.get("group_id") or ""),
                    "label": redact_secrets_only(new_job.get("label") or "", max_len=120),
                    "from_bot": str(new_job.get("from_bot") or "studio"),
                    "target_bot": target_bot,
                    "status": "queued",
                    "project": mapped_project,
                    "model": orig_model,
                    "effort": orig_effort,
                    "created_at": float(new_job.get("created_at") or 0.0),
                },
            },
            status=202,
        )

    # ------------------------------------------------------------------ B. Schedules Safe R/W APIs
    async def handle_create_schedule(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="schedules.create"
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action="schedules.create",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        # PA-C6 RCE Absolute Ban: check script & precheck_cmd/shell keys FIRST -> 403
        bad_rce = _find_forbidden_key_recursive(body, _FORBIDDEN_SCHEDULE_RCE_KEYS)
        raw_ttype = str(body.get("task_type") or "").strip().lower()
        if bad_rce is not None or raw_ttype == "script":
            self.audit.record(
                action="schedules.create",
                status_code=403,
                outcome=f"denied_forbidden_rce:{bad_rce or 'script'}",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": "安全策略禁止通过 WebUI 创建 script 或包含 precheck_cmd/shell 命令的定时任务",
                },
                status=403,
            )

        bad_route = _find_forbidden_key_recursive(body, _FORBIDDEN_SCHEDULE_ROUTE_KEYS)
        if bad_route is not None:
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_route}",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_route}"},
                status=400,
            )

        extra_keys = set(body.keys()) - _ALLOWED_SCHEDULE_CREATE_KEYS
        if extra_keys:
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "请求包含未允许字段"},
                status=400,
            )

        if raw_ttype not in _ALLOWED_SCHEDULE_TASK_TYPES:
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome="denied_invalid_task_type",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "task_type 仅支持 prompt 或 reminder"},
                status=400,
            )

        raw_name = body.get("name")
        if not isinstance(raw_name, str) or not raw_name.strip():
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome="denied_missing_name",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "任务名称 name 不能为空"},
                status=400,
            )
        clean_name = raw_name.strip()[:120]

        ok_sched, err_sched, _sched_type, _cron_expr, _first_dt = self._validate_schedule_expr(
            body.get("schedule_expr")
        )
        if not ok_sched:
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome="denied_invalid_schedule",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": err_sched},
                status=400,
            )

        raw_prompt = body.get("prompt")
        if not isinstance(raw_prompt, str) or not raw_prompt.strip():
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome="denied_empty_prompt",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "任务内容 prompt 不能为空"},
                status=400,
            )
        if len(raw_prompt.encode("utf-8")) > MAX_SCHEDULE_PROMPT_BYTES:
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome="denied_prompt_too_large",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "prompt 超过 16 KiB 上限"},
                status=400,
            )

        mapped_project = ""
        mapped_workdir: str | None = None
        raw_proj = body.get("project")
        if raw_proj is not None:
            if not isinstance(raw_proj, str):
                self.audit.record(
                    action="schedules.create",
                    status_code=400,
                    outcome="denied_invalid_project",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "project 必须为字符串"},
                    status=400,
                )
            if raw_proj.strip() != "":
                resolved_proj = self.data_sources.resolve_allowed_project(raw_proj)
                if resolved_proj is None:
                    self.audit.record(
                        action="schedules.create",
                        status_code=400,
                        outcome="denied_invalid_project",
                        client_ip=client_ip,
                        sess=sess,
                    )
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "指定的 project 不在允许白名单中"},
                        status=400,
                    )
                mapped_project = resolved_proj["id"]
                mapped_workdir = resolved_proj["workdir"] or None

        enabled_val = body.get("enabled", True)
        if not isinstance(enabled_val, bool):
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome="denied_invalid_enabled",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "enabled 必须为布尔值"},
                status=400,
            )

        silent_val = body.get("silent_if_empty")
        if silent_val is not None and not isinstance(silent_val, bool):
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome="denied_invalid_silent",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "silent_if_empty 必须为布尔值"},
                status=400,
            )

        raw_model_val = body.get("model")
        if raw_model_val is not None and not isinstance(raw_model_val, str):
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome="denied_invalid_model",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "model 必须为字符串"},
                status=400,
            )
        raw_model = (raw_model_val or "").strip()
        clean_model = (
            _sanitize_slug(raw_model, max_len=96)
            if raw_model
            else ("gemini-3.8-flash-low" if raw_ttype == "prompt" else "")
        )

        raw_bot_val = body.get("bot")
        if raw_bot_val is not None and not isinstance(raw_bot_val, str):
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome="denied_invalid_bot",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "bot 必须为字符串"},
                status=400,
            )
        raw_bot = (raw_bot_val or "").strip()
        clean_bot = bot_bus.normalize_handle(raw_bot) if raw_bot else None

        tm = self._task_manager()
        try:
            created = tm.create_task(
                name=clean_name,
                schedule_expr=str(body["schedule_expr"]).strip(),
                task_type=raw_ttype,
                payload={"prompt": raw_prompt.strip()},
                target_chat_id=None,
                target_thread_id=None,
                model=clean_model,
                project=mapped_project,
                workdir=mapped_workdir,
                silent_if_empty=silent_val,
                bot_instance_id=clean_bot,
                precheck_cmd=None,
                enabled=enabled_val,
            )
        except ValueError as exc:
            self.audit.record(
                action="schedules.create",
                status_code=400,
                outcome="denied_scheduler_validation",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": str(exc)},
                status=400,
            )

        tid = str(created.get("id") or "")
        safe_item = self.data_sources.format_schedule_item(created)
        self.event_hub.publish(
            "schedule_updated",
            {"action": "create", "schedule_id": tid, "enabled": bool(created.get("enabled"))},
        )
        self.audit.record(
            action="schedules.create",
            status_code=201,
            outcome="allowed",
            client_ip=client_ip,
            target_id=tid,
            sess=sess,
        )
        return web.json_response({"ok": True, "schedule": safe_item}, status=201)

    async def handle_patch_schedule(self, request: web.Request) -> web.Response:
        schedule_id = str(request.match_info.get("schedule_id") or "").strip()
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="schedules.patch", target_id=schedule_id
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action="schedules.patch",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        if not studio_ipc.is_valid_entity_id(schedule_id):
            self.audit.record(
                action="schedules.patch",
                status_code=400,
                outcome="denied_invalid_schedule_id",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 schedule_id 格式"},
                status=400,
            )

        # PA-C6 RCE ban: reject script/precheck_cmd anywhere in patch body -> 403
        bad_rce = _find_forbidden_key_recursive(body, _FORBIDDEN_SCHEDULE_RCE_KEYS)
        raw_ttype = str(body.get("task_type") or "").strip().lower() if "task_type" in body else ""
        if bad_rce is not None or raw_ttype == "script":
            self.audit.record(
                action="schedules.patch",
                status_code=403,
                outcome=f"denied_forbidden_rce:{bad_rce or 'script'}",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": "安全策略禁止通过 WebUI 写入 script 或 precheck_cmd/shell 字段",
                },
                status=403,
            )

        bad_route = _find_forbidden_key_recursive(body, _FORBIDDEN_SCHEDULE_ROUTE_KEYS)
        if bad_route is not None:
            self.audit.record(
                action="schedules.patch",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_route}",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_route}"},
                status=400,
            )

        tm = self._task_manager()
        existing = tm.get_task(schedule_id)
        if not isinstance(existing, dict):
            self.audit.record(
                action="schedules.patch",
                status_code=404,
                outcome="denied_not_found",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "定时任务不存在"},
                status=404,
            )

        # PA-C6 CLI script/precheck task: STRICTLY emergency disable `{"enabled": false}` ONLY!
        if is_read_only_cli_schedule(existing):
            if set(body.keys()) != {"enabled"} or body.get("enabled") is not False:
                self.audit.record(
                    action="schedules.patch",
                    status_code=403,
                    outcome="denied_cli_script_readonly",
                    client_ip=client_ip,
                    target_id=schedule_id,
                    sess=sess,
                )
                return web.json_response(
                    {
                        "ok": False,
                        "source": "studio_api",
                        "error": "CLI 创建的脚本/预检任务在 WebUI 中仅允许紧急停用（enabled=false），禁止启用或修改",
                    },
                    status=403,
                )

            def _disable_only(t: dict[str, Any]) -> None:
                if not is_read_only_cli_schedule(t):
                    return
                t["enabled"] = False

            updated = tm.update_task(schedule_id, _disable_only)
            if updated is None:
                self.audit.record(
                    action="schedules.patch",
                    status_code=404,
                    outcome="denied_not_found",
                    client_ip=client_ip,
                    target_id=schedule_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "定时任务不存在"},
                    status=404,
                )
            safe_item = self.data_sources.format_schedule_item(updated)
            self.event_hub.publish(
                "schedule_updated",
                {"action": "disable", "schedule_id": schedule_id, "enabled": False},
            )
            self.audit.record(
                action="schedules.patch",
                status_code=200,
                outcome="allowed_emergency_disable",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response({"ok": True, "schedule": safe_item}, status=200)

        # Regular (non-CLI-script) schedule patch validation
        if not body:
            self.audit.record(
                action="schedules.patch",
                status_code=400,
                outcome="denied_empty_patch",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "至少提供一个待更新字段"},
                status=400,
            )

        extra_keys = set(body.keys()) - _ALLOWED_SCHEDULE_PATCH_KEYS
        if extra_keys:
            self.audit.record(
                action="schedules.patch",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "请求包含未允许字段"},
                status=400,
            )

        parsed_updates: dict[str, Any] = {}
        if "name" in body:
            if not isinstance(body["name"], str) or not body["name"].strip():
                self.audit.record(
                    action="schedules.patch",
                    status_code=400,
                    outcome="denied_invalid_name",
                    client_ip=client_ip,
                    target_id=schedule_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "任务名称 name 不能为空"},
                    status=400,
                )
            parsed_updates["name"] = body["name"].strip()[:120]

        if "task_type" in body:
            if raw_ttype not in _ALLOWED_SCHEDULE_TASK_TYPES:
                self.audit.record(
                    action="schedules.patch",
                    status_code=400,
                    outcome="denied_invalid_task_type",
                    client_ip=client_ip,
                    target_id=schedule_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "task_type 仅支持 prompt 或 reminder"},
                    status=400,
                )
            parsed_updates["task_type"] = raw_ttype

        if "schedule_expr" in body:
            ok_s, err_s, stype, cexpr, next_dt = self._validate_schedule_expr(body["schedule_expr"])
            if not ok_s:
                self.audit.record(
                    action="schedules.patch",
                    status_code=400,
                    outcome="denied_invalid_schedule",
                    client_ip=client_ip,
                    target_id=schedule_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": err_s},
                    status=400,
                )
            parsed_updates["schedule_expr"] = str(body["schedule_expr"]).strip()
            parsed_updates["schedule_type"] = stype
            parsed_updates["cron_expr"] = cexpr
            parsed_updates["next_run_at"] = scheduler.format_iso_utc(next_dt)

        if "prompt" in body:
            rp = body["prompt"]
            if not isinstance(rp, str) or not rp.strip():
                self.audit.record(
                    action="schedules.patch",
                    status_code=400,
                    outcome="denied_empty_prompt",
                    client_ip=client_ip,
                    target_id=schedule_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "prompt 不能为空"},
                    status=400,
                )
            if len(rp.encode("utf-8")) > MAX_SCHEDULE_PROMPT_BYTES:
                self.audit.record(
                    action="schedules.patch",
                    status_code=400,
                    outcome="denied_prompt_too_large",
                    client_ip=client_ip,
                    target_id=schedule_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "prompt 超过 16 KiB 上限"},
                    status=400,
                )
            parsed_updates["prompt"] = rp.strip()

        if "project" in body:
            rpj = body["project"]
            if rpj is None:
                parsed_updates["project"] = ""
                parsed_updates["workdir"] = None
            elif not isinstance(rpj, str):
                self.audit.record(
                    action="schedules.patch",
                    status_code=400,
                    outcome="denied_invalid_project",
                    client_ip=client_ip,
                    target_id=schedule_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "project 必须为字符串"},
                    status=400,
                )
            elif rpj.strip() == "":
                parsed_updates["project"] = ""
                parsed_updates["workdir"] = None
            else:
                resolved_proj = self.data_sources.resolve_allowed_project(rpj)
                if resolved_proj is None:
                    self.audit.record(
                        action="schedules.patch",
                        status_code=400,
                        outcome="denied_invalid_project",
                        client_ip=client_ip,
                        target_id=schedule_id,
                        sess=sess,
                    )
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "指定的 project 不在允许白名单中"},
                        status=400,
                    )
                parsed_updates["project"] = resolved_proj["id"]
                parsed_updates["workdir"] = resolved_proj["workdir"] or None

        if "model" in body:
            rm = body["model"]
            if rm is not None and not isinstance(rm, str):
                self.audit.record(
                    action="schedules.patch",
                    status_code=400,
                    outcome="denied_invalid_model",
                    client_ip=client_ip,
                    target_id=schedule_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "model 必须为字符串"},
                    status=400,
                )
            parsed_updates["model"] = _sanitize_slug(rm or "", max_len=96) if (rm and rm.strip()) else ""

        if "enabled" in body:
            if not isinstance(body["enabled"], bool):
                self.audit.record(
                    action="schedules.patch",
                    status_code=400,
                    outcome="denied_invalid_enabled",
                    client_ip=client_ip,
                    target_id=schedule_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "enabled 必须为布尔值"},
                    status=400,
                )
            parsed_updates["enabled"] = body["enabled"]

        if "silent_if_empty" in body:
            if not isinstance(body["silent_if_empty"], bool):
                self.audit.record(
                    action="schedules.patch",
                    status_code=400,
                    outcome="denied_invalid_silent",
                    client_ip=client_ip,
                    target_id=schedule_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "silent_if_empty 必须为布尔值"},
                    status=400,
                )
            parsed_updates["silent_if_empty"] = body["silent_if_empty"]

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        tz, _ = scheduler.get_scheduler_tz(self.data_sources.cost_tz_name)

        class _CliReadOnlyRace(Exception):
            pass

        def _apply_patch(t: dict[str, Any]) -> None:
            # Re-verify under exclusive flock against concurrent replacement by a script task
            if is_read_only_cli_schedule(t):
                raise _CliReadOnlyRace()
            if "name" in parsed_updates:
                t["name"] = parsed_updates["name"]
            if "task_type" in parsed_updates:
                t["task_type"] = parsed_updates["task_type"]
            if "schedule_expr" in parsed_updates:
                t["schedule_expr"] = parsed_updates["schedule_expr"]
                t["schedule_type"] = parsed_updates["schedule_type"]
                t["cron_expr"] = parsed_updates["cron_expr"]
                t.setdefault("state", {})["next_run_at"] = parsed_updates["next_run_at"]
            if "prompt" in parsed_updates:
                t.setdefault("payload", {})["prompt"] = parsed_updates["prompt"]
            if "project" in parsed_updates:
                ex = t.setdefault("execution", {})
                ex["project"] = parsed_updates["project"]
                ex["workdir"] = parsed_updates["workdir"]
            if "model" in parsed_updates:
                t.setdefault("execution", {})["model"] = parsed_updates["model"]
            if "silent_if_empty" in parsed_updates:
                t.setdefault("delivery", {})["silent_if_empty"] = parsed_updates["silent_if_empty"]
            if "enabled" in parsed_updates:
                t["enabled"] = parsed_updates["enabled"]
                if t["enabled"] and "next_run_at" not in parsed_updates:
                    if t.get("schedule_type") == "cron" and t.get("cron_expr"):
                        n_dt = scheduler.next_cron_occurrence(t["cron_expr"], now_utc, tz)
                        t.setdefault("state", {})["next_run_at"] = scheduler.format_iso_utc(n_dt)

        try:
            updated = tm.update_task(schedule_id, _apply_patch)
        except _CliReadOnlyRace:
            self.audit.record(
                action="schedules.patch",
                status_code=403,
                outcome="denied_cli_script_readonly",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "CLI 脚本任务禁止修改"},
                status=403,
            )

        if updated is None:
            self.audit.record(
                action="schedules.patch",
                status_code=404,
                outcome="denied_not_found",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "定时任务不存在"},
                status=404,
            )

        safe_item = self.data_sources.format_schedule_item(updated)
        self.event_hub.publish(
            "schedule_updated",
            {"action": "patch", "schedule_id": schedule_id, "enabled": bool(updated.get("enabled"))},
        )
        self.audit.record(
            action="schedules.patch",
            status_code=200,
            outcome="allowed",
            client_ip=client_ip,
            target_id=schedule_id,
            sess=sess,
        )
        return web.json_response({"ok": True, "schedule": safe_item}, status=200)

    async def handle_delete_schedule(self, request: web.Request) -> web.Response:
        schedule_id = str(request.match_info.get("schedule_id") or "").strip()
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="schedules.delete", target_id=schedule_id
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, _body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=True
        )
        if not ok_body:
            self.audit.record(
                action="schedules.delete",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        if not studio_ipc.is_valid_entity_id(schedule_id):
            self.audit.record(
                action="schedules.delete",
                status_code=400,
                outcome="denied_invalid_schedule_id",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 schedule_id 格式"},
                status=400,
            )

        tm = self._task_manager()
        existing = tm.get_task(schedule_id)
        if not isinstance(existing, dict):
            self.audit.record(
                action="schedules.delete",
                status_code=404,
                outcome="denied_not_found",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "定时任务不存在"},
                status=404,
            )

        if is_read_only_cli_schedule(existing):
            self.audit.record(
                action="schedules.delete",
                status_code=403,
                outcome="denied_cli_script_delete",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": "安全策略禁止通过 WebUI 删除 CLI 脚本或含 precheck_cmd 的定时任务",
                },
                status=403,
            )

        class _CliReadOnlyDeleteRace(Exception):
            pass

        def _guard_delete(t: dict[str, Any]) -> None:
            # Re-verify under exclusive flock against concurrent replacement by a script/precheck task
            if is_read_only_cli_schedule(t):
                raise _CliReadOnlyDeleteRace()

        try:
            deleted = tm.delete_task(schedule_id, guard=_guard_delete)
        except _CliReadOnlyDeleteRace:
            self.audit.record(
                action="schedules.delete",
                status_code=403,
                outcome="denied_cli_script_delete",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": "安全策略禁止通过 WebUI 删除 CLI 脚本或含 precheck_cmd 的定时任务",
                },
                status=403,
            )
        if not deleted:
            self.audit.record(
                action="schedules.delete",
                status_code=404,
                outcome="denied_not_found",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "定时任务不存在"},
                status=404,
            )

        self.event_hub.publish(
            "schedule_updated",
            {"action": "delete", "schedule_id": schedule_id},
        )
        self.audit.record(
            action="schedules.delete",
            status_code=200,
            outcome="allowed",
            client_ip=client_ip,
            target_id=schedule_id,
            sess=sess,
        )
        return web.json_response({"ok": True, "deleted": True, "id": schedule_id}, status=200)

    async def handle_run_schedule(self, request: web.Request) -> web.Response:
        schedule_id = str(request.match_info.get("schedule_id") or "").strip()
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="schedules.run", target_id=schedule_id
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=True
        )
        if not ok_body or body is None:
            self.audit.record(
                action="schedules.run",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_rce = _find_forbidden_key_recursive(body, _FORBIDDEN_SCHEDULE_RCE_KEYS)
        if bad_rce is not None:
            self.audit.record(
                action="schedules.run",
                status_code=403,
                outcome=f"denied_forbidden_rce:{bad_rce}",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "禁止传入脚本或预检命令字段"},
                status=403,
            )

        bad_route = _find_forbidden_key_recursive(body, _FORBIDDEN_SCHEDULE_ROUTE_KEYS)
        if bad_route is not None:
            self.audit.record(
                action="schedules.run",
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_route}",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_route}"},
                status=400,
            )

        if set(body.keys()) - {"bot"}:
            self.audit.record(
                action="schedules.run",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "请求包含未允许字段"},
                status=400,
            )

        raw_req_bot = body.get("bot")
        if raw_req_bot is not None and not isinstance(raw_req_bot, str):
            self.audit.record(
                action="schedules.run",
                status_code=400,
                outcome="denied_invalid_bot",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "bot 必须为字符串"},
                status=400,
            )

        if not studio_ipc.is_valid_entity_id(schedule_id):
            self.audit.record(
                action="schedules.run",
                status_code=400,
                outcome="denied_invalid_schedule_id",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 schedule_id 格式"},
                status=400,
            )

        tm = self._task_manager()
        existing = tm.get_task(schedule_id)
        if not isinstance(existing, dict):
            self.audit.record(
                action="schedules.run",
                status_code=404,
                outcome="denied_not_found",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "定时任务不存在"},
                status=404,
            )

        # Defense #1 (Studio side): strictly block script / precheck_cmd tasks -> 403
        if is_read_only_cli_schedule(existing):
            self.audit.record(
                action="schedules.run",
                status_code=403,
                outcome="denied_cli_script_run",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": "安全策略禁止通过 WebUI 触发 script 或含 precheck_cmd 的定时任务",
                },
                status=403,
            )

        req_bot = (
            (raw_req_bot or "").strip()
            or str(existing.get("bot") or existing.get("bot_instance_id") or "").strip()
        ) or None
        resolved = self._resolve_ipc_endpoint(req_bot)
        if resolved is None:
            resolved = self._resolve_ipc_endpoint(None)
        if resolved is None:
            self.audit.record(
                action="schedules.run",
                status_code=503,
                outcome="upstream_unavailable",
                client_ip=client_ip,
                target_id=schedule_id,
                sess=sess,
            )
            return upstream_error("Bridge IPC 服务未就绪或离线", status=503)

        bot_handle, sock_path, ipc_token = resolved
        sc, resp_data = await self._ipc_request_json(
            sock_path=sock_path,
            token=ipc_token,
            method="POST",
            path="/ipc/schedule/run",
            payload={"schedule_id": schedule_id, "user_id": int(sess["user_id"])},
            timeout_sec=10.0,
        )
        self.audit.record(
            action="schedules.run",
            status_code=sc,
            outcome="allowed" if sc < 400 else f"denied_ipc_{sc}",
            client_ip=client_ip,
            target_id=schedule_id,
            sess=sess,
            bot_override=bot_handle,
        )
        if sc >= 400:
            safe_err = redact_secrets_only(resp_data.get("error") or f"Bridge IPC HTTP {sc}", max_len=200)
            return web.json_response(
                {"ok": False, "source": "upstream", "error": safe_err},
                status=sc,
            )

        self.event_hub.publish(
            "schedule_updated",
            {"action": "run", "schedule_id": schedule_id, "bot": bot_handle},
        )
        return web.json_response(
            {
                "ok": True,
                "queued": bool(resp_data.get("queued", True)),
                "schedule_id": schedule_id,
                "bot": bot_handle,
            },
            status=sc,
        )
