#!/usr/bin/env python3
"""AGY Studio Phase A — Single-Writer IPC Chat Service, Audit Logging & Revocation-Safe SSE.

Strictly NEVER spawns `agy` subprocesses or writes `transcript.jsonl`.
All chat execution and cancellation is proxied over per-bot Unix Domain Sockets
(`BUS_DIR/ipc/<handle>.sock`) to the owning `bridge.py` single-writer daemon.
"""

from __future__ import annotations

import asyncio
from collections import OrderedDict
import datetime
import fcntl
import json
import logging
import os
from pathlib import Path
import time
from typing import Any
import urllib.parse

import aiohttp
from aiohttp import web

from .auth import StudioAuthManager, studio_auth_error, upstream_error
from .data_sources import (
    StreamRedactor,
    StudioDataSources,
    _sanitize_slug,
    redact_secrets_only,
    truncate_utf8_bytes,
)
import studio_ipc

log = logging.getLogger("agy-studio.chat")

MAX_PROMPT_BODY_BYTES = 32 * 1024
MAX_SSE_EVENT_BYTES = 16 * 1024
MAX_STREAMS_PER_SESSION = 4
MAX_STREAMS_GLOBAL = 32
DEFAULT_KEEPALIVE_SEC = 15.0
MAX_TURN_OWNERS = 512

_VALID_EFFORTS = frozenset({"low", "medium", "high", "xhigh", "max"})
_VALID_EXECUTION_MODES = frozenset({"queue", "interrupt"})
INTERRUPT_WAIT_TIMEOUT_SEC = 2.5


def _utc_iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_media_type(request: web.Request) -> str:
    raw = request.headers.get("Content-Type")
    if not raw or not isinstance(raw, str):
        return ""
    return raw.split(";", 1)[0].strip().lower()


def _reject_non_finite_json(token: str) -> Any:
    raise ValueError(f"Non-finite JSON constant not allowed: {token}")


async def _read_bounded_json_body(
    request: web.Request,
    *,
    max_bytes: int = MAX_PROMPT_BODY_BYTES,
    allow_empty: bool = False,
) -> tuple[bool, dict[str, Any] | None, int, str, str]:
    """Read and parse a JSON object request body strictly bounded to `max_bytes`.

    Checks `Content-Length` upfront AND streams at most `max_bytes + 1` bytes so
    chunked transfer encoding cannot bypass the size cap.
    Returns `(ok, body_dict, status_code, audit_outcome, error_message)`.
    """
    cl_raw = request.headers.get("Content-Length")
    if cl_raw is not None:
        try:
            cl_val = int(cl_raw.strip())
        except ValueError:
            return False, None, 400, "denied_invalid_content_length", "无效的 Content-Length 请求头"
        if cl_val < 0:
            return False, None, 400, "denied_invalid_content_length", "无效的 Content-Length 请求头"
        if cl_val > max_bytes:
            return False, None, 413, "denied_payload_too_large", "请求体超过 32 KiB 上限"

    chunks: list[bytes] = []
    total = 0
    limit_probe = max_bytes + 1
    try:
        while True:
            remaining = limit_probe - total
            if remaining <= 0:
                return False, None, 413, "denied_payload_too_large", "请求体超过 32 KiB 上限"
            chunk = await request.content.read(min(8192, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                return False, None, 413, "denied_payload_too_large", "请求体超过 32 KiB 上限"
    except Exception:
        return False, None, 400, "denied_invalid_json", "请求体读取失败"

    raw_body = b"".join(chunks)
    if len(raw_body) > max_bytes:
        return False, None, 413, "denied_payload_too_large", "请求体超过 32 KiB 上限"

    if allow_empty and not raw_body.strip():
        return True, {}, 200, "ok", ""

    try:
        body = json.loads(raw_body.decode("utf-8"), parse_constant=_reject_non_finite_json)
    except Exception:
        return False, None, 400, "denied_invalid_json", "请求体必须为有效 JSON"

    if not isinstance(body, dict):
        return False, None, 400, "denied_invalid_json", "请求体必须为 JSON 对象"

    return True, body, 200, "ok", ""


class StudioAuditLogger:
    """Append-only `0600` JSONL audit logger for all Studio mutating endpoints (zero secret logging)."""

    def __init__(self, audit_path: Path) -> None:
        self.audit_path = Path(audit_path)

    def record(
        self,
        *,
        action: str,
        status_code: int,
        outcome: str,
        client_ip: str,
        target_id: str = "",
        sess: dict[str, Any] | None = None,
        bot_override: str = "",
    ) -> None:
        rec = {
            "ts_utc": _utc_iso_now(),
            "actor_username": str((sess or {}).get("username") or ""),
            "bot": str(bot_override or (sess or {}).get("bot") or ""),
            "user_id": int((sess or {}).get("user_id") or 0) if sess else 0,
            "role": str((sess or {}).get("role") or "anonymous"),
            "action": str(action),
            "target_id": str(target_id or "")[:128],
            "status_code": int(status_code),
            "outcome": str(outcome),
            "client_ip": str(client_ip or "unknown")[:64],
        }
        line = (json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.audit_path.parent, 0o700)
            except OSError:
                pass
            fd = os.open(str(self.audit_path), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
            try:
                try:
                    os.chmod(self.audit_path, 0o600)
                except OSError:
                    pass
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    os.write(fd, line)
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        except OSError as exc:
            log.warning("Audit log write failed: %s", type(exc).__name__)


class StudioChatService:
    """Handles chat send/abort/stream/models/sessions endpoints over Bridge UDS IPC."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        data_sources: StudioDataSources,
        *,
        audit_log_path: Path | None = None,
        attachment_service: Any | None = None,
        revocation_check_interval: float = 1.5,
        keepalive_interval: float = DEFAULT_KEEPALIVE_SEC,
        max_streams_per_session: int = MAX_STREAMS_PER_SESSION,
        max_streams_global: int = MAX_STREAMS_GLOBAL,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.attachment_service = attachment_service
        default_audit = Path(
            os.environ.get("AGY_STUDIO_AUDIT_LOG", str(self.auth_mgr.config_dir / "audit.jsonl"))
        )
        self.audit = StudioAuditLogger(audit_log_path or default_audit)
        self.revocation_check_interval = max(0.05, float(revocation_check_interval))
        self.keepalive_interval = max(0.5, float(keepalive_interval))
        self.max_streams_per_session = max(1, int(max_streams_per_session))
        self.max_streams_global = max(1, int(max_streams_global))

        self._turn_owners: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._active_streams: dict[int, dict[str, Any]] = {}
        self.auth_mgr.add_revoke_listener(self._on_auth_revoked)

    # ------------------------------------------------------------------ Bridge UDS Discovery
    def _ipc_dir(self) -> Path:
        return (self.data_sources.bus_dir / "ipc").resolve()

    def _iter_ipc_endpoints(self, requested_bot: str | None = None) -> list[tuple[str, Path, str]]:
        """Enumerate valid `(bot_handle, sock_path, ipc_token)` endpoints strictly inside `BUS_DIR/ipc/`."""
        ipc_dir = self._ipc_dir()
        if not ipc_dir.is_dir():
            return []

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

        found: list[tuple[str, Path, str]] = []
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
                found.append((safe_h, sock_p, token))
        return found

    def _resolve_ipc_endpoint(self, requested_bot: str | None = None) -> tuple[str, Path, str] | None:
        """Resolve `(bot_handle, sock_path, ipc_token)` strictly inside `BUS_DIR/ipc/`."""
        eps = self._iter_ipc_endpoints(requested_bot)
        return eps[0] if eps else None

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
            log.warning("Bridge IPC %s %s failed: %s", method, path, type(exc).__name__)
            return 502, {"ok": False, "source": "upstream", "error": "Bridge IPC 服务暂不可达"}

    # ------------------------------------------------------------------ Turn Ownership Registry
    def _record_turn_owner(
        self,
        turn_id: str,
        *,
        sess: dict[str, Any],
        target_bot: str,
        cid: str | None = None,
    ) -> None:
        self._turn_owners[turn_id] = {
            "bot": str(sess["bot"]),
            "user_id": int(sess["user_id"]),
            "username_key": str(sess.get("username_key") or ""),
            "target_bot": str(target_bot),
            "cid": cid,
            "created_at": time.time(),
        }
        self._turn_owners.move_to_end(turn_id)
        while len(self._turn_owners) > MAX_TURN_OWNERS:
            self._turn_owners.popitem(last=False)

    def _is_turn_owner(self, owner: dict[str, Any], sess: dict[str, Any]) -> bool:
        if owner.get("bot") != str(sess["bot"]):
            return False
        if int(owner.get("user_id") or 0) != int(sess["user_id"]):
            return False
        o_ukey = str(owner.get("username_key") or "")
        s_ukey = str(sess.get("username_key") or "")
        if o_ukey and s_ukey and o_ukey != s_ukey:
            return False
        return True

    # ------------------------------------------------------------------ Four-Layer Write Gate
    async def _enforce_write_gate(
        self,
        request: web.Request,
        *,
        action: str,
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
            )
            return False, None, studio_auth_error(err_orig, status=403)

        # Gate 2: Non-simple request Content-Type enforcement (`application/json` only -> else 415)
        media_type = _extract_media_type(request)
        if media_type != "application/json":
            self.audit.record(
                action=action,
                status_code=415,
                outcome="denied_content_type",
                client_ip=client_ip,
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
                sess=sess,
            )
            return False, None, studio_auth_error(
                "只读权限（readonly）禁止执行写操作",
                status=403,
            )

        return True, sess, None

    # ------------------------------------------------------------------ Read APIs: Sessions & Models
    async def handle_get_sessions(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        try:
            limit = int(request.query.get("limit", "30"))
        except ValueError:
            limit = 30
        bot_q = request.query.get("bot")
        source_q = request.query.get("source")
        q_val = request.query.get("q")
        data = self.data_sources.get_sessions(limit=limit, bot=bot_q, source=source_q, q=q_val)
        return web.json_response(data)

    async def handle_get_session_messages(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        cid = str(request.match_info.get("cid") or "").strip()
        try:
            limit = int(request.query.get("limit", "40"))
        except ValueError:
            limit = 40
        before_raw = request.query.get("before")
        before_val: int | None = None
        if before_raw is not None and before_raw.strip():
            try:
                before_val = int(before_raw.strip())
            except ValueError:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "无效的 before 分页游标"},
                    status=400,
                )
        sc, payload = self.data_sources.get_session_messages(cid, limit=limit, before=before_val)
        return web.json_response(payload, status=sc)

    async def handle_get_session_active_turn(self, request: web.Request) -> web.Response:
        # Strictly admin-only + must_change_password=False; fail closed before any IPC call
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        if sess.get("role") != "admin":
            return studio_auth_error("只读权限（readonly）不可查询活跃实时轮次", status=403)

        cid = str(request.match_info.get("cid") or "").strip()
        ok_cid, err_cid, sc_cid = studio_ipc.validate_resume_cid(
            cid,
            summaries_db=self.data_sources.summaries_db,
            meta_file=self.data_sources.meta_file,
        )
        if not ok_cid:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": err_cid},
                status=sc_cid,
            )

        req_bot = str(request.query.get("bot") or "").strip() or None
        endpoints = self._iter_ipc_endpoints(req_bot)
        uid = int(sess["user_id"])
        qs = urllib.parse.urlencode({"cid": cid, "user_id": str(uid)})

        for bot_handle, sock_path, ipc_token in endpoints:
            sc, data = await self._ipc_request_json(
                sock_path=sock_path,
                token=ipc_token,
                method="GET",
                path=f"/ipc/chat/active?{qs}",
                timeout_sec=5.0,
            )
            if sc == 200 and data.get("ok") and data.get("active"):
                turn_id = str(data.get("turn_id") or "").strip()
                if not turn_id:
                    continue
                preview = redact_secrets_only(str(data.get("prompt_preview") or ""), max_len=240)
                return web.json_response(
                    {
                        "ok": True,
                        "active": True,
                        "bot": bot_handle,
                        "cid": str(data.get("cid") or cid),
                        "turn_id": turn_id,
                        "source": _sanitize_slug(str(data.get("source") or "tg"), max_len=16) or "tg",
                        "status": _sanitize_slug(str(data.get("status") or "running"), max_len=24) or "running",
                        "prompt_preview": preview,
                    }
                )

        return web.json_response({"ok": True, "active": False, "cid": cid})

    async def handle_get_models(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)

        req_bot = request.query.get("bot")
        resolved = self._resolve_ipc_endpoint(req_bot)
        if resolved is not None:
            bot_handle, sock_path, token = resolved
            sc, meta = await self._ipc_request_json(
                sock_path=sock_path,
                token=token,
                method="GET",
                path="/ipc/meta",
                timeout_sec=5.0,
            )
            if sc == 200 and meta.get("ok"):
                return web.json_response({
                    "ok": True,
                    "bot": _sanitize_slug(meta.get("handle") or bot_handle, max_len=64),
                    "active_model": _sanitize_slug(meta.get("active_model") or "", max_len=96),
                    "default_project": _sanitize_slug(meta.get("default_project") or "", max_len=64),
                    "efforts": list(meta.get("efforts") or ["low", "medium", "high", "xhigh", "max"]),
                    "models": [
                        {
                            "id": _sanitize_slug(m.get("id") or "", max_len=128),
                            "label": redact_secrets_only(m.get("label") or m.get("id") or "", max_len=128),
                        }
                        for m in (meta.get("models") or [])
                        if isinstance(m, dict) and m.get("id")
                    ],
                    "projects": [
                        {
                            "id": _sanitize_slug(p.get("id") or "", max_len=64),
                            "name": redact_secrets_only(p.get("name") or p.get("id") or "", max_len=80),
                        }
                        for p in (meta.get("projects") or [])
                        if isinstance(p, dict) and p.get("id")
                    ],
                    "ipc_online": True,
                })

        # Fallback read-only catalog from roster when IPC is not online
        bots_data = self.data_sources.get_bots()
        fallback_models: list[dict[str, str]] = []
        seen_m: set[str] = set()
        for b in bots_data.get("bots") or []:
            em = str(b.get("effective_model") or "").strip()
            if em and em not in seen_m:
                seen_m.add(em)
                fallback_models.append({"id": em, "label": em})
        fallback_projects = [
            {"id": p["id"], "name": p["name"]}
            for p in self.data_sources.get_allowed_projects()
        ]
        return web.json_response({
            "ok": True,
            "bot": _sanitize_slug(req_bot or "", max_len=64),
            "active_model": fallback_models[0]["id"] if fallback_models else "",
            "default_project": fallback_projects[0]["id"] if fallback_projects else "",
            "efforts": ["low", "medium", "high", "xhigh", "max"],
            "models": fallback_models,
            "projects": fallback_projects,
            "ipc_online": False,
        })

    # ------------------------------------------------------------------ Write APIs: Send & Abort
    async def handle_chat_send(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="chat.send")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)

        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES
        )
        if not ok_body or body is None:
            self.audit.record(
                action="chat.send",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        raw_prompt = body.get("prompt")
        if raw_prompt is None:
            raw_prompt = ""
        if not isinstance(raw_prompt, str):
            self.audit.record(
                action="chat.send",
                status_code=400,
                outcome="denied_invalid_prompt",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "prompt 必须为字符串"},
                status=400,
            )
        if len(raw_prompt.encode("utf-8")) > MAX_PROMPT_BODY_BYTES:
            self.audit.record(
                action="chat.send",
                status_code=413,
                outcome="denied_payload_too_large",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "prompt 超过 32 KiB 上限"},
                status=413,
            )

        raw_attachments = body.get("attachments")
        raw_context_files = body.get("context_files")
        project_raw = str(body.get("project") or "").strip() or None

        resolved_atts: list[dict[str, Any]] = []
        resolved_ctx: list[dict[str, str]] = []
        if raw_attachments is not None or raw_context_files is not None:
            if self.attachment_service is None:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "附件服务未启用"},
                    status=503,
                )
            ok_att, resolved_atts, sc_att, err_att = self.attachment_service.resolve_attachments(
                raw_attachments
            )
            if not ok_att:
                self.audit.record(
                    action="chat.send",
                    status_code=sc_att,
                    outcome="denied_invalid_attachments",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": err_att},
                    status=sc_att,
                )
            ok_ctx, resolved_ctx, sc_ctx, err_ctx = self.attachment_service.resolve_context_files(
                raw_context_files, project_raw
            )
            if not ok_ctx:
                self.audit.record(
                    action="chat.send",
                    status_code=sc_ctx,
                    outcome="denied_invalid_context_files",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": err_ctx},
                    status=sc_ctx,
                )

        if not raw_prompt.strip() and not resolved_atts and not resolved_ctx:
            self.audit.record(
                action="chat.send",
                status_code=400,
                outcome="denied_empty_prompt",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "消息内容不能为空"},
                status=400,
            )

        if resolved_atts or resolved_ctx:
            assert self.attachment_service is not None
            display_prompt, prompt = self.attachment_service.build_prompt_with_attachments(
                raw_prompt,
                resolved_atts,
                resolved_ctx,
                max_bytes=MAX_PROMPT_BODY_BYTES,
            )
            public_atts = self.attachment_service.strip_internal_paths(resolved_atts)
            ctx_rel_list = [c["rel_path"] for c in resolved_ctx]
        else:
            display_prompt = raw_prompt
            prompt = raw_prompt
            public_atts = []
            ctx_rel_list = []

        effort_raw = str(body.get("effort") or "").strip().lower()
        if effort_raw and effort_raw not in _VALID_EFFORTS:
            self.audit.record(
                action="chat.send",
                status_code=400,
                outcome="denied_invalid_effort",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "无效的思考强度参数"},
                status=400,
            )

        sync_tg = False
        if "sync_tg" in body:
            raw_sync_tg = body.get("sync_tg")
            if not isinstance(raw_sync_tg, bool):
                self.audit.record(
                    action="chat.send",
                    status_code=400,
                    outcome="denied_invalid_sync_tg",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "sync_tg 必须为布尔值（true/false）"},
                    status=400,
                )
            sync_tg = raw_sync_tg

        raw_exec_mode = body.get("execution_mode", "queue")
        if raw_exec_mode is None:
            execution_mode = "queue"
        elif (
            not isinstance(raw_exec_mode, str)
            or raw_exec_mode.strip().lower() not in _VALID_EXECUTION_MODES
        ):
            self.audit.record(
                action="chat.send",
                status_code=400,
                outcome="denied_invalid_execution_mode",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "execution_mode 必须为 queue 或 interrupt"},
                status=400,
            )
        else:
            execution_mode = raw_exec_mode.strip().lower()

        req_bot = str(body.get("bot") or "").strip() or None
        resolved = self._resolve_ipc_endpoint(req_bot)
        if resolved is None:
            self.audit.record(
                action="chat.send",
                status_code=503,
                outcome="upstream_unavailable",
                client_ip=client_ip,
                sess=sess,
                bot_override=req_bot or "",
            )
            return upstream_error("目标 Bot 的 Bridge IPC 服务未就绪或离线", status=503)

        bot_handle, sock_path, ipc_token = resolved
        cid_val = str(body.get("cid") or "").strip() or None
        uid_int = int(sess["user_id"])
        interrupted_turn_id: str | None = None
        interrupt_deadline = time.monotonic() + INTERRUPT_WAIT_TIMEOUT_SEC

        if execution_mode == "interrupt":
            abort_target_tid: str | None = None
            if cid_val:
                qs_active = urllib.parse.urlencode({"cid": cid_val, "user_id": str(uid_int)})
                sc_act, act_data = await self._ipc_request_json(
                    sock_path=sock_path,
                    token=ipc_token,
                    method="GET",
                    path=f"/ipc/chat/active?{qs_active}",
                    timeout_sec=3.0,
                )
                if sc_act == 200 and act_data.get("ok") and act_data.get("active"):
                    cand_tid = str(act_data.get("turn_id") or "").strip()
                    if cand_tid:
                        owner = self._turn_owners.get(cand_tid)
                        if owner is not None and not self._is_turn_owner(owner, sess):
                            self.audit.record(
                                action="chat.send",
                                status_code=403,
                                outcome="denied_cross_tenant",
                                client_ip=client_ip,
                                target_id=cand_tid,
                                sess=sess,
                                bot_override=bot_handle,
                            )
                            return studio_auth_error("无权中止其他账号的对话轮次", status=403)
                        abort_target_tid = cand_tid
            else:
                sc_meta, meta_data = await self._ipc_request_json(
                    sock_path=sock_path,
                    token=ipc_token,
                    method="GET",
                    path="/ipc/meta",
                    timeout_sec=3.0,
                )
                if sc_meta == 200 and meta_data.get("ok") and meta_data.get("busy"):
                    cand_tid = str(meta_data.get("active_turn_id") or "").strip()
                    if cand_tid:
                        owner = self._turn_owners.get(cand_tid)
                        if owner is not None and self._is_turn_owner(owner, sess):
                            abort_target_tid = cand_tid
                            meta_cid = str(meta_data.get("active_cid") or "").strip()
                            if meta_cid and not cid_val:
                                cid_val = meta_cid

            if abort_target_tid:
                sc_ab, ab_data = await self._ipc_request_json(
                    sock_path=sock_path,
                    token=ipc_token,
                    method="POST",
                    path="/ipc/chat/abort",
                    payload={"turn_id": abort_target_tid, "user_id": uid_int},
                    timeout_sec=5.0,
                )
                self.audit.record(
                    action="chat.interrupt_abort",
                    status_code=sc_ab,
                    outcome="allowed" if sc_ab < 400 else f"denied_ipc_{sc_ab}",
                    client_ip=client_ip,
                    target_id=abort_target_tid,
                    sess=sess,
                    bot_override=bot_handle,
                )
                if sc_ab == 403:
                    safe_ab_err = redact_secrets_only(ab_data.get("error") or "无权中止当前轮次", max_len=200)
                    return studio_auth_error(safe_ab_err, status=403)
                if sc_ab < 400 and ab_data.get("ok") and ab_data.get("aborted"):
                    interrupted_turn_id = abort_target_tid
                    # Wait briefly (<= 2.5s) for the interrupted turn to release its conversation lease.
                    while time.monotonic() < interrupt_deadline:
                        if cid_val:
                            qs_poll = urllib.parse.urlencode({"cid": cid_val, "user_id": str(uid_int)})
                            sc_p, p_data = await self._ipc_request_json(
                                sock_path=sock_path,
                                token=ipc_token,
                                method="GET",
                                path=f"/ipc/chat/active?{qs_poll}",
                                timeout_sec=2.0,
                            )
                            if sc_p == 200 and p_data.get("ok") and not p_data.get("active"):
                                break
                        else:
                            sc_p, p_data = await self._ipc_request_json(
                                sock_path=sock_path,
                                token=ipc_token,
                                method="GET",
                                path="/ipc/meta",
                                timeout_sec=2.0,
                            )
                            if sc_p == 200 and p_data.get("ok") and (
                                not p_data.get("busy")
                                or str(p_data.get("active_turn_id") or "") != abort_target_tid
                            ):
                                break
                        await asyncio.sleep(0.15)

        ipc_payload: dict[str, Any] = {
            "user_id": uid_int,
            "actor_username": str(sess.get("username") or ""),
            "prompt": prompt,
            "cid": cid_val,
            "project": project_raw,
            "model": str(body.get("model") or "").strip() or None,
            "effort": effort_raw or None,
            "sync_tg": sync_tg,
            "priority": "urgent" if execution_mode == "interrupt" else "normal",
            "interrupt_current": execution_mode == "interrupt",
        }
        sc, resp_data = await self._ipc_request_json(
            sock_path=sock_path,
            token=ipc_token,
            method="POST",
            path="/ipc/chat/send",
            payload=ipc_payload,
            timeout_sec=15.0,
        )

        # In preview compatibility mode (old Bridge without native interrupt_current), a brief
        # conv_lease release race can still return 409 session_busy right after /ipc/chat/abort.
        while (
            execution_mode == "interrupt"
            and sc == 409
            and resp_data.get("code") == "session_busy"
            and time.monotonic() < interrupt_deadline
        ):
            await asyncio.sleep(0.15)
            sc, resp_data = await self._ipc_request_json(
                sock_path=sock_path,
                token=ipc_token,
                method="POST",
                path="/ipc/chat/send",
                payload=ipc_payload,
                timeout_sec=15.0,
            )

        if not interrupted_turn_id and resp_data.get("interrupted_turn_id"):
            interrupted_turn_id = str(resp_data.get("interrupted_turn_id"))

        turn_id = str(resp_data.get("turn_id") or "")
        if sc in (200, 202) and resp_data.get("ok") and turn_id:
            self._record_turn_owner(turn_id, sess=sess, target_bot=bot_handle, cid=cid_val)
            self.audit.record(
                action="chat.send",
                status_code=sc,
                outcome="allowed_interrupt" if execution_mode == "interrupt" else "allowed",
                client_ip=client_ip,
                target_id=turn_id,
                sess=sess,
                bot_override=bot_handle,
            )
            resp_out: dict[str, Any] = {
                "ok": True,
                "turn_id": turn_id,
                "bot": bot_handle,
                "cid": resp_data.get("cid") or cid_val,
                "status": str(resp_data.get("status") or "queued"),
                "display_prompt": display_prompt,
                "execution_mode": execution_mode,
                "interrupted_turn_id": interrupted_turn_id,
            }
            if public_atts:
                resp_out["attachments"] = public_atts
            if ctx_rel_list:
                resp_out["context_files"] = ctx_rel_list
            return web.json_response(resp_out, status=sc)

        self.audit.record(
            action="chat.send",
            status_code=sc,
            outcome=f"denied_ipc_{sc}",
            client_ip=client_ip,
            target_id=cid_val or "",
            sess=sess,
            bot_override=bot_handle,
        )
        safe_err = redact_secrets_only(resp_data.get("error") or f"Bridge IPC HTTP {sc}", max_len=200)
        out_err: dict[str, Any] = {"ok": False, "source": "upstream", "error": safe_err}
        if resp_data.get("code"):
            out_err["code"] = _sanitize_slug(resp_data["code"], max_len=48)
        return web.json_response(out_err, status=sc)

    async def handle_chat_abort(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="chat.abort")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES
        )
        if not ok_body or body is None:
            self.audit.record(
                action="chat.abort",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        turn_id = str(body.get("turn_id") or "").strip()
        if not turn_id:
            self.audit.record(
                action="chat.abort",
                status_code=400,
                outcome="denied_missing_turn_id",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "缺少 turn_id"},
                status=400,
            )

        owner = self._turn_owners.get(turn_id)
        if owner is not None and not self._is_turn_owner(owner, sess):
            self.audit.record(
                action="chat.abort",
                status_code=403,
                outcome="denied_cross_tenant",
                client_ip=client_ip,
                target_id=turn_id,
                sess=sess,
            )
            return studio_auth_error("无权中止其他账号的对话轮次", status=403)

        target_bot = (owner or {}).get("target_bot") or str(body.get("bot") or "").strip() or None
        resolved = self._resolve_ipc_endpoint(target_bot)
        if resolved is None:
            self.audit.record(
                action="chat.abort",
                status_code=503,
                outcome="upstream_unavailable",
                client_ip=client_ip,
                target_id=turn_id,
                sess=sess,
            )
            return upstream_error("Bridge IPC 服务暂不可达", status=503)

        bot_handle, sock_path, ipc_token = resolved
        sc, resp_data = await self._ipc_request_json(
            sock_path=sock_path,
            token=ipc_token,
            method="POST",
            path="/ipc/chat/abort",
            payload={"turn_id": turn_id, "user_id": int(sess["user_id"])},
            timeout_sec=10.0,
        )
        self.audit.record(
            action="chat.abort",
            status_code=sc,
            outcome="allowed" if sc < 400 else f"denied_ipc_{sc}",
            client_ip=client_ip,
            target_id=turn_id,
            sess=sess,
            bot_override=bot_handle,
        )
        if sc >= 400:
            safe_err = redact_secrets_only(resp_data.get("error") or f"Bridge IPC HTTP {sc}", max_len=200)
            return web.json_response({"ok": False, "source": "upstream", "error": safe_err}, status=sc)
        return web.json_response(
            {
                "ok": True,
                "turn_id": turn_id,
                "aborted": bool(resp_data.get("aborted")),
                "bot": bot_handle,
            },
            status=sc,
        )

    # ------------------------------------------------------------------ SSE Teardown & Revocation
    @staticmethod
    async def _close_upstream_stream(entry: dict[str, Any]) -> None:
        up_resp: aiohttp.ClientResponse | None = entry.get("upstream_resp")
        up_cli: aiohttp.ClientSession | None = entry.get("upstream_cli")
        reader_task: asyncio.Task[Any] | None = entry.get("reader_task")
        if reader_task is not None and not reader_task.done():
            reader_task.cancel()
        if up_resp is not None:
            try:
                up_resp.close()
            except Exception:
                pass
        if up_cli is not None and not up_cli.closed:
            try:
                await asyncio.wait_for(up_cli.close(), timeout=0.4)
            except Exception:
                pass

    @staticmethod
    async def _close_downstream_sse_bounded(
        entry: dict[str, Any],
        *,
        error_reason: str | None = None,
        timeout_sec: float = 0.8,
    ) -> None:
        resp: web.StreamResponse | None = entry.get("stream_resp")
        if resp is None:
            return
        if entry.get("downstream_closing"):
            return
        entry["downstream_closing"] = True
        if error_reason:
            frame = (
                "event: auth_error\n"
                f"data: {json.dumps({'source': 'studio_auth', 'error': error_reason}, ensure_ascii=False)}\n\n"
            ).encode("utf-8")
            try:
                await asyncio.wait_for(resp.write(frame), timeout=min(0.35, timeout_sec))
            except Exception:
                pass
        try:
            await asyncio.wait_for(resp.write_eof(), timeout=min(0.45, timeout_sec))
        except Exception:
            try:
                req = entry.get("request")
                transport = getattr(req, "transport", None) if req is not None else None
                if transport is not None and not transport.is_closing():
                    transport.close()
            except Exception:
                pass

    async def _terminate_stream_entry(
        self,
        entry: dict[str, Any],
        *,
        error_reason: str = "访问权限已被撤销",
        await_downstream: bool = True,
    ) -> None:
        if entry.get("closing"):
            return
        # 1. Synchronously block all further data frame writes & record close_reason before any await
        entry["closing"] = True
        entry["close_reason"] = error_reason
        # 2. Sever upstream UDS connection FIRST before touching downstream
        await self._close_upstream_stream(entry)
        # 3. Emit terminal auth_error and close downstream within <= 0.8s
        if await_downstream:
            await self._close_downstream_sse_bounded(
                entry, error_reason=error_reason, timeout_sec=0.8
            )
        elif not entry.get("downstream_closing") and entry.get("downstream_close_task") is None:
            entry["downstream_close_task"] = asyncio.create_task(
                self._close_downstream_sse_bounded(
                    entry, error_reason=error_reason, timeout_sec=0.8
                )
            )

    async def _on_auth_revoked(
        self,
        session_hash: str | None,
        bot: str | None,
        user_id: int | None,
        *,
        username_key: str | None = None,
        exclude_session_hash: str | None = None,
    ) -> None:
        if username_key:
            targets = [
                e for e in list(self._active_streams.values())
                if e.get("username_key") == username_key
                and e.get("session_hash") != exclude_session_hash
                and not e.get("closing")
            ]
        elif session_hash:
            targets = [
                e for e in list(self._active_streams.values())
                if e.get("session_hash") == session_hash and not e.get("closing")
            ]
        elif bot and user_id is not None:
            targets = [
                e for e in list(self._active_streams.values())
                if e.get("bot") == bot and e.get("user_id") == user_id and not e.get("closing")
            ]
        else:
            targets = []

        if not targets:
            return

        # 1. Synchronously mark closing & close_reason before any await
        for e in targets:
            e["closing"] = True
            e["close_reason"] = "访问权限已被撤销"

        # 2. Sever all upstream UDS connections first in parallel
        await asyncio.gather(
            *(self._close_upstream_stream(e) for e in targets),
            return_exceptions=True,
        )

        # 3. Close downstream SSE responses with bounded <= 0.8s timeout
        for e in targets:
            if not e.get("downstream_closing") and e.get("downstream_close_task") is None:
                e["downstream_close_task"] = asyncio.create_task(
                    self._close_downstream_sse_bounded(
                        e,
                        error_reason=e.get("close_reason") or "访问权限已被撤销",
                        timeout_sec=0.8,
                    )
                )

    async def close_all(self) -> None:
        entries = list(self._active_streams.values())
        for e in entries:
            e["closing"] = True
            e["close_reason"] = "服务正在关闭"
        await asyncio.gather(*(self._close_upstream_stream(e) for e in entries), return_exceptions=True)
        await asyncio.gather(
            *(self._close_downstream_sse_bounded(e, error_reason="服务正在关闭", timeout_sec=0.8) for e in entries),
            return_exceptions=True,
        )
        self._active_streams.clear()

    # ------------------------------------------------------------------ SSE Formatting & Redaction
    @staticmethod
    def _format_sse_frame(event_name: str, data: dict[str, Any], seq: int | None = None) -> bytes:
        raw_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        encoded_json = raw_json.encode("utf-8")
        if len(encoded_json) > MAX_SSE_EVENT_BYTES - 128:
            # Hard-cap every SSE frame <= 16 KiB
            compact: dict[str, Any] = {"truncated": True}
            for k in ("turn_id", "conversation_id", "status", "step_index", "tool_name", "reason", "code"):
                if k in data:
                    compact[k] = data[k]
            for text_k in ("delta", "response", "partial_text", "error", "message"):
                if text_k in data and isinstance(data[text_k], str):
                    clipped, _ = truncate_utf8_bytes(data[text_k], MAX_SSE_EVENT_BYTES - 512)
                    compact[text_k] = clipped
            raw_json = json.dumps(compact, ensure_ascii=False, separators=(",", ":"))

        lines: list[str] = []
        if seq is not None and seq > 0:
            lines.append(f"id: {seq}")
        lines.append(f"event: {event_name}")
        lines.append(f"data: {raw_json}")
        return ("\n".join(lines) + "\n\n").encode("utf-8")

    # ------------------------------------------------------------------ GET /api/chat/stream
    async def handle_chat_stream(self, request: web.Request) -> web.StreamResponse:
        # 1. Authenticate session cookie + live RBAC + must_change_password=False
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            return studio_auth_error(err_auth, status=status_code)
        if sess.get("role") != "admin":
            return studio_auth_error("只读权限（readonly）不可订阅实时对话流", status=403)

        turn_id = str(request.query.get("turn_id") or "").strip()
        if not turn_id:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "缺少 turn_id 参数"},
                status=400,
            )

        # 2. Strict tenant ownership enforcement
        owner = self._turn_owners.get(turn_id)
        req_bot = str(request.query.get("bot") or "").strip() or None
        if owner is not None:
            if not self._is_turn_owner(owner, sess):
                return studio_auth_error("无权订阅其他用户的对话流", status=403)
            target_bot: str | None = owner.get("target_bot") or req_bot
        elif studio_ipc.is_valid_tg_turn_id(turn_id):
            # Allow `tg-<16hex>` live DM turns only when pointing to a valid online IPC endpoint;
            # Bridge `/ipc/chat/stream` strictly re-verifies live admin RBAC and `owner_user_id == sess["user_id"]`.
            if self._resolve_ipc_endpoint(req_bot) is None:
                return studio_auth_error("未找到对应的对话流或目标 Bot 离线", status=403)
            target_bot = req_bot
        else:
            return studio_auth_error("未找到对应的对话流或无权访问", status=403)

        # 3. Concurrency limits (per-session <= 4, global <= 32 -> 429) with atomic synchronous reservation
        session_hash = str(sess["session_hash"])
        if len(self._active_streams) >= self.max_streams_global:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "全局实时流并发数已达上限"},
                status=429,
            )
        per_sess_cnt = sum(1 for e in self._active_streams.values() if e.get("session_hash") == session_hash)
        if per_sess_cnt >= self.max_streams_per_session:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "当前会话实时流并发数已达上限"},
                status=429,
            )

        # Register placeholder BEFORE any `await` to eliminate TOCTOU concurrency bypass & track in-flight revocation
        entry: dict[str, Any] = {
            "request": request,
            "stream_resp": None,
            "upstream_resp": None,
            "upstream_cli": None,
            "session_hash": session_hash,
            "username_key": sess.get("username_key"),
            "bot": str(sess["bot"]),
            "user_id": int(sess["user_id"]),
            "turn_id": turn_id,
            "closing": False,
            "close_reason": None,
            "downstream_closing": False,
            "downstream_close_task": None,
            "reader_task": None,
        }
        entry_key = id(entry)
        self._active_streams[entry_key] = entry

        try:
            # 4. Resolve upstream Bridge UDS endpoint
            resolved = self._resolve_ipc_endpoint(target_bot)
            if resolved is None:
                return upstream_error("Bridge IPC 服务暂不可达", status=503)
            _bot_handle, sock_path, ipc_token = resolved

            # 5. Parse Last-Event-ID / after_seq
            raw_after = request.query.get("after_seq")
            if raw_after is None or not raw_after.strip():
                raw_after = request.headers.get("Last-Event-ID", "0")
            try:
                after_seq = max(0, int(str(raw_after).strip()))
            except ValueError:
                after_seq = 0

            # 6. Connect upstream UDS stream BEFORE preparing downstream SSE
            up_connector = aiohttp.UnixConnector(path=str(sock_path))
            up_cli = aiohttp.ClientSession(connector=up_connector)
            entry["upstream_cli"] = up_cli
            try:
                up_resp = await up_cli.get(
                    "http://localhost/ipc/chat/stream",
                    params={
                        "turn_id": turn_id,
                        "after_seq": str(after_seq),
                        "user_id": str(int(sess["user_id"])),
                    },
                    headers={"X-Bridge-IPC-Token": ipc_token},
                    timeout=aiohttp.ClientTimeout(total=None, sock_connect=5.0, sock_read=None),
                )
            except Exception:
                if entry.get("closing"):
                    return studio_auth_error("访问权限已被撤销", status=403)
                return upstream_error("连接 Bridge IPC 对话流失败", status=502)

            entry["upstream_resp"] = up_resp

            # Abort immediately with 403 (0 frames written) if revoked during upstream handshake
            if entry.get("closing"):
                return studio_auth_error("访问权限已被撤销", status=403)

            if up_resp.status >= 400:
                try:
                    err_payload = await up_resp.json()
                except Exception:
                    err_payload = {"ok": False, "error": f"Bridge IPC HTTP {up_resp.status}"}
                st = up_resp.status
                return web.json_response(
                    {
                        "ok": False,
                        "source": "upstream",
                        "error": redact_secrets_only(err_payload.get("error") or f"HTTP {st}", max_len=200),
                    },
                    status=st,
                )

            # Re-verify live admin auth before committing 200 SSE headers (0 frames on downgrade/revocation)
            ok_pre, live_pre, err_pre, _sc_pre = await self.auth_mgr.authenticate_session_hash(session_hash)
            if entry.get("closing") or not ok_pre or not live_pre or live_pre.get("role") != "admin":
                reason = (
                    "权限已降级为只读（readonly），实时对话流已断开"
                    if (ok_pre and live_pre and live_pre.get("role") != "admin")
                    else ("password_change_required" if err_pre == "password_change_required" else "访问权限已被撤销")
                )
                return studio_auth_error(reason, status=403)

            # 7. Prepare downstream SSE StreamResponse (set security headers BEFORE prepare!)
            csp_val = (
                "default-src 'self'; script-src 'self' https://telegram.org; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                "font-src 'self' data:; connect-src 'self' ws: wss:; "
                "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
                if self.auth_mgr.auth_mode == "legacy"
                else "default-src 'self'; script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
                "font-src 'self' data:; connect-src 'self' ws: wss:; "
                "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
            )
            sse_resp = web.StreamResponse(
                status=200,
                headers={
                    "Content-Type": "text/event-stream; charset=utf-8",
                    "Cache-Control": "no-store, max-age=0",
                    "X-Accel-Buffering": "no",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                    "Content-Security-Policy": csp_val,
                },
            )
            await sse_resp.prepare(request)
            entry["stream_resp"] = sse_resp

            if entry.get("closing"):
                await self._close_downstream_sse_bounded(
                    entry,
                    error_reason=entry.get("close_reason") or "访问权限已被撤销",
                    timeout_sec=0.8,
                )
                return sse_resp

            text_redactor = StreamRedactor(window_size=256)
            think_redactor = StreamRedactor(window_size=256)
            last_write_ts = time.monotonic()

            async def _verify_live_admin() -> bool:
                if entry.get("closing"):
                    return False
                ok_live, live_sess, err_live, _sc = await self.auth_mgr.authenticate_session_hash(session_hash)
                if not ok_live or not live_sess:
                    reason = "password_change_required" if err_live == "password_change_required" else "访问权限已被撤销"
                    await self._terminate_stream_entry(entry, error_reason=reason, await_downstream=True)
                    return False
                if live_sess.get("role") != "admin":
                    await self._terminate_stream_entry(
                        entry,
                        error_reason="权限已降级为只读（readonly），实时对话流已断开",
                        await_downstream=True,
                    )
                    return False
                return True

            async def _safe_write_frame(frame: bytes) -> bool:
                nonlocal last_write_ts
                if entry.get("closing"):
                    return False
                if not await _verify_live_admin():
                    return False
                if entry.get("closing"):
                    return False
                try:
                    await sse_resp.write(frame)
                    last_write_ts = time.monotonic()
                    return True
                except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError, OSError):
                    entry["closing"] = True
                    return False

            async def _flush_redactors(seq_hint: int | None) -> bool:
                flushed_think = think_redactor.flush()
                if flushed_think:
                    ok_w = await _safe_write_frame(
                        self._format_sse_frame("thinking", {"delta": flushed_think}, seq=None)
                    )
                    if not ok_w:
                        return False
                flushed_text = text_redactor.flush()
                if flushed_text:
                    ok_w = await _safe_write_frame(
                        self._format_sse_frame("text_delta", {"delta": flushed_text}, seq=None)
                    )
                    if not ok_w:
                        return False
                return True

            async def _pump_upstream() -> None:
                try:
                    async for raw_line in up_resp.content:
                        if entry.get("closing"):
                            return
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if not line:
                            continue
                        try:
                            ev_obj = json.loads(line)
                        except Exception:
                            continue
                        if not isinstance(ev_obj, dict):
                            continue

                        ev_name = str(ev_obj.get("event") or "message")
                        seq_val = ev_obj.get("seq")
                        seq_int = int(seq_val) if isinstance(seq_val, int) and seq_val > 0 else None
                        data = ev_obj.get("data") if isinstance(ev_obj.get("data"), dict) else {}

                        if ev_name == "text_delta":
                            safe_delta = text_redactor.feed(data.get("delta") or "")
                            if safe_delta:
                                if not await _safe_write_frame(
                                    self._format_sse_frame(
                                        "text_delta",
                                        {"delta": safe_delta, "step_index": data.get("step_index", 0)},
                                        seq=seq_int,
                                    )
                                ):
                                    return
                            continue

                        if ev_name == "thinking":
                            safe_th = think_redactor.feed(data.get("delta") or "")
                            if safe_th:
                                if not await _safe_write_frame(
                                    self._format_sse_frame(
                                        "thinking",
                                        {"delta": safe_th, "step_index": data.get("step_index", 0)},
                                        seq=seq_int,
                                    )
                                ):
                                    return
                            continue

                        if ev_name in ("done", "aborted", "error", "tool_use", "tool_result", "resync_required"):
                            if not await _flush_redactors(seq_int):
                                return

                        sanitized_data = self._sanitize_event_payload(ev_name, data)
                        if not await _safe_write_frame(
                            self._format_sse_frame(ev_name, sanitized_data, seq=seq_int)
                        ):
                            return
                        if ev_name in ("done", "aborted", "error", "resync_required"):
                            return
                except asyncio.CancelledError:
                    return
                except Exception:
                    return

            async def _watchdog_and_keepalive() -> None:
                nonlocal last_write_ts
                sleep_step = min(self.revocation_check_interval, self.keepalive_interval)
                while not entry.get("closing"):
                    await asyncio.sleep(sleep_step)
                    if entry.get("closing"):
                        return
                    if not await _verify_live_admin():
                        return
                    if (time.monotonic() - last_write_ts) >= self.keepalive_interval:
                        if not await _safe_write_frame(b": keepalive\n\n"):
                            return

            reader_task = asyncio.create_task(_pump_upstream())
            entry["reader_task"] = reader_task
            watchdog_task = asyncio.create_task(_watchdog_and_keepalive())

            done, pending = await asyncio.wait(
                [reader_task, watchdog_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for t in done:
                try:
                    t.result()
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass
            return sse_resp
        finally:
            self._active_streams.pop(entry_key, None)
            entry["closing"] = True
            await self._close_upstream_stream(entry)
            close_task = entry.get("downstream_close_task")
            if close_task is not None and not close_task.done():
                try:
                    await asyncio.wait_for(close_task, timeout=0.9)
                except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                    pass
            if entry.get("stream_resp") is not None and not entry.get("downstream_closing"):
                await self._close_downstream_sse_bounded(
                    entry,
                    error_reason=entry.get("close_reason"),
                    timeout_sec=0.8,
                )

    @staticmethod
    def _sanitize_event_payload(ev_name: str, data: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in data.items():
            if isinstance(v, str):
                out[k] = redact_secrets_only(v)
            elif isinstance(v, (int, float, bool)) or v is None:
                out[k] = v
            elif isinstance(v, dict):
                try:
                    s = json.dumps(v, ensure_ascii=False)
                    out[k] = json.loads(redact_secrets_only(s))
                except Exception:
                    out[k] = {}
            elif isinstance(v, list):
                try:
                    s = json.dumps(v, ensure_ascii=False)
                    out[k] = json.loads(redact_secrets_only(s))
                except Exception:
                    out[k] = []
        return out
