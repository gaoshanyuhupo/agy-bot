#!/usr/bin/env python3
"""AGY Studio Milestone 2 — Multi-Google-Account Management Service & REST API.

Wraps `bridge/google_accounts.py` (`GoogleAccountManager` & `GoogleLoginFlowManager`)
with Studio-side async execution, strict four-layer write gates, per-session OAuth
ownership isolation, anti-symlink `0600` JSONL audit logging, Bridge UDS IPC worker
recycling, and SSE `accounts_updated` broadcasts.

Security invariants (C1 / C2 / C5 / C6):
- Every write/login endpoint enforces the full four-layer Studio write gate:
  1. Strict Same-Origin (`Origin` required + `Sec-Fetch-Site` check) -> 403
  2. `Content-Type: application/json` -> 415 and bounded body <= 32 KiB -> 413
  3. Live session auth + `must_change_password=False` -> 401 / 403
  4. Constant-time `X-Studio-CSRF` + live RBAC `role == "admin"` -> 403
- `GET /api/google-accounts/login/{flow_id}` requires authenticated `admin` (`!must_change_password`)
  plus constant-time `owner_session_id == sess["session_hash"]` verification (cross-session -> 403)
  and NEVER exposes `oauth_state`, `auth_url`, or `profile_dir`.
- Public account views and audit logs NEVER expose raw emails, OAuth tokens, `code_verifier`,
  `oauth_state`, OAuth `code`/`auth_url`, `profile_dir`, or host absolute paths.
- Session logout, RBAC revocation, and `app.on_cleanup` automatically cancel and reap active
  `agy acp --login` process groups (0 orphan subprocesses).
"""

from __future__ import annotations

import asyncio
import datetime
import fcntl
import inspect
import json
import logging
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Awaitable, Callable

import aiohttp
from aiohttp import web

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BRIDGE_SRC_DIR = _REPO_ROOT / "bridge"
if str(_BRIDGE_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_BRIDGE_SRC_DIR))

import cost_usage  # noqa: E402
import google_accounts  # noqa: E402
from google_accounts import (  # noqa: E402
    AccountError,
    FlowConflictError,
    FlowNotFoundError,
    GoogleAccountManager,
    GoogleLoginFlowManager,
    GoogleProbeError,
    SymlinkSecurityError,
    _assert_no_symlink_chain,
    _ensure_secure_dir,
    sanitize_alias,
    scrub_paths_for_public,
    to_public_dict,
    validate_account_id,
)

from .auth import StudioAuthManager, studio_auth_error
from .chat_service import (
    MAX_PROMPT_BODY_BYTES,
    _extract_media_type,
    _read_bounded_json_body,
)
from .control_plane import _find_forbidden_key_recursive
from .data_sources import StudioDataSources, _read_json_ro, _sanitize_slug
from .event_hub import StudioEventHub

log = logging.getLogger("agy-studio.google_accounts")

_OAUTH_URL_OR_QS_RE = re.compile(
    r"https?://(?:accounts\.google\.com|antigravity\.google)[^\s\"'<>]*",
    re.IGNORECASE,
)
_OAUTH_PARAM_RE = re.compile(
    r"(?i)\b(code|state|code_verifier|code_challenge|access_token|refresh_token|id_token)\s*=\s*[^\s&\"'<>]+"
)
_EMAIL_PLAIN_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_FORBIDDEN_MUTATION_KEYS = frozenset({
    "role",
    "user_id",
    "profile_dir",
    "host_token_path",
    "root_dir",
    "token_path",
    "access_token",
    "refresh_token",
    "id_token",
    "code_verifier",
    "oauth_state",
    "owner_session_id",
    "cmd",
    "command",
    "shell",
    "script",
    "env",
    "ipc_sock",
})

_ALLOWED_ADD_KEYS = frozenset({"account_id", "alias"})
_ALLOWED_PATCH_KEYS = frozenset({
    "alias",
    "weekly_reset_utc_weekday",
    "weekly_reset_utc_hour",
    "weekly_reset_utc_minute",
})
_ALLOWED_LOGIN_START_KEYS = frozenset({"alias", "timeout_sec"})
_ALLOWED_LOGIN_SUBMIT_KEYS = frozenset({"code_or_url", "code", "callback_url"})

_PUBLIC_FORBIDDEN_KEYS = frozenset({
    "email",
    "access_token",
    "refresh_token",
    "id_token",
    "code_verifier",
    "oauth_state",
    "profile_dir",
    "token_path",
    "host_token_path",
    "owner_session_id",
    "google_user_id",
})


def _utc_iso_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sanitize_audit_error(raw: Any, max_len: int = 240) -> str:
    """Scrub tokens, OAuth callback codes/states, URLs, emails, and host paths before auditing."""
    if not raw:
        return ""
    s = scrub_paths_for_public(str(raw))
    s = _OAUTH_URL_OR_QS_RE.sub("[oauth-url-redacted]", s)
    s = _OAUTH_PARAM_RE.sub(r"\1=[REDACTED]", s)
    s = _EMAIL_PLAIN_RE.sub("[email-redacted]", s)
    s = " ".join(s.split())
    return s[:max_len]


def _strip_forbidden_public_keys(obj: Any, *, depth: int = 0) -> Any:
    """Defense-in-depth recursive sanitizer ensuring forbidden secret/path keys never leave the API."""
    if depth > 12:
        return None
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if str(k).strip().lower() in _PUBLIC_FORBIDDEN_KEYS:
                continue
            out[k] = _strip_forbidden_public_keys(v, depth=depth + 1)
        return out
    if isinstance(obj, list):
        return [_strip_forbidden_public_keys(item, depth=depth + 1) for item in obj]
    if isinstance(obj, str):
        return scrub_paths_for_public(obj)
    return obj


def _actor_label(sess: dict[str, Any] | None) -> str:
    if not sess:
        return "anonymous"
    uname = str(sess.get("username") or "").strip()
    if uname:
        return _sanitize_slug(uname, max_len=64) or "user"
    bot = _sanitize_slug(sess.get("bot") or "studio", max_len=32) or "studio"
    uid = int(sess.get("user_id") or 0)
    return f"{bot}:#{uid}"


class _AccountsAuditLogger:
    """Anti-symlink `0600` append-only JSONL audit logger for Google account operations."""

    def __init__(self, audit_path: Path) -> None:
        self.audit_path = Path(audit_path)

    def record(
        self,
        *,
        action: str,
        ok: bool,
        sess: dict[str, Any] | None = None,
        account_id: str = "",
        flow_id: str = "",
        error: str = "",
    ) -> None:
        rec = {
            "ts": _utc_iso_now(),
            "actor": _actor_label(sess),
            "role": str((sess or {}).get("role") or "anonymous"),
            "action": str(action)[:64],
            "account_id": _sanitize_slug(account_id, max_len=64) if account_id else "",
            "flow_id": _sanitize_slug(flow_id, max_len=64) if flow_id else "",
            "ok": bool(ok),
            "error": _sanitize_audit_error(error) if error else "",
        }
        line = (json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            _ensure_secure_dir(self.audit_path.parent, enforce_mode=True)
            _assert_no_symlink_chain(self.audit_path)
            if self.audit_path.is_symlink():
                raise SymlinkSecurityError("Refusing to append audit log to symlink")
            flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(self.audit_path), flags, 0o600)
            try:
                os.chmod(self.audit_path, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    os.write(fd, line)
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        except Exception as exc:
            log.warning("Google accounts audit write failed: %s", type(exc).__name__)


class StudioGoogleAccountsService:
    """Studio backend service and aiohttp REST handlers for multi-Google-account management."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        data_sources: StudioDataSources,
        event_hub: StudioEventHub | None = None,
        *,
        root_dir: str | Path | None = None,
        host_token_path: str | Path | None = None,
        audit_log_path: str | Path | None = None,
        recycle_callback: Callable[..., Awaitable[dict[str, Any]] | dict[str, Any]] | None = None,
        account_manager: GoogleAccountManager | None = None,
        login_flow_manager: GoogleLoginFlowManager | None = None,
        http_request_fn: Callable[..., dict[str, Any]] | None = None,
        popen_fn: Callable[..., Any] | None = None,
        auto_adopt_host: bool = True,
        auto_probe_on_login: bool = True,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.event_hub = event_hub
        self._recycle_callback = recycle_callback

        if account_manager is not None:
            self.account_manager = account_manager
        else:
            eff_root = root_dir if root_dir is not None else getattr(data_sources, "google_accounts_dir", None)
            isolated_ds = bool(getattr(data_sources, "_isolated_mode", False))
            eff_auto_adopt = bool(auto_adopt_host) and (
                host_token_path is not None or (not isolated_ds and root_dir is None)
            )
            eff_host_tok = (
                host_token_path
                if host_token_path is not None
                else (
                    (Path(eff_root) / ".no-host-token")
                    if (isolated_ds or root_dir is not None)
                    else None
                )
            )
            self.account_manager = GoogleAccountManager(
                root_dir=eff_root,
                host_token_path=eff_host_tok,
                quota_cache_file=data_sources.quota_cache_file,
                cost_config_file=data_sources.cost_config_file,
                http_request_fn=http_request_fn,
                popen_fn=popen_fn,
                auto_adopt_host=eff_auto_adopt,
            )

        if login_flow_manager is not None:
            self.login_flows = login_flow_manager
        else:
            self.login_flows = GoogleLoginFlowManager(
                self.account_manager,
                popen_fn=popen_fn,
                auto_probe_on_login=auto_probe_on_login,
            )

        default_audit = Path(
            os.environ.get(
                "AGY_STUDIO_GOOGLE_ACCOUNTS_AUDIT_LOG",
                str(self.auth_mgr.config_dir / "google_accounts_audit.jsonl"),
            )
        )
        self.audit = _AccountsAuditLogger(Path(audit_log_path) if audit_log_path is not None else default_audit)
        # Map session_hash -> identity tuple for identity-level RBAC revocation cleanup
        self._session_identities: dict[str, dict[str, Any]] = {}
        self.auth_mgr.add_revoke_listener(self._on_auth_revoked)

    # ------------------------------------------------------------------ Lifecycle & Revocation
    def on_session_logout(self, session_hash: str) -> int:
        """Cancel and reap all active OAuth flows belonging to a logged-out session."""
        if not isinstance(session_hash, str) or not session_hash:
            return 0
        self._session_identities.pop(session_hash, None)
        return self.login_flows.cancel_flows_for_session(session_hash)

    def on_server_cleanup(self) -> int:
        """Terminate and reap all tracked OAuth subprocesses on server shutdown."""
        self._session_identities.clear()
        return self.login_flows.cleanup_all_flows()

    async def close_all(self) -> int:
        """Async cleanup hook invoked from `app.on_cleanup`."""
        return await asyncio.to_thread(self.on_server_cleanup)

    async def _on_auth_revoked(
        self,
        session_hash: str | None,
        bot: str | None,
        user_id: int | None,
        *,
        username_key: str | None = None,
        exclude_session_hash: str | None = None,
    ) -> None:
        if session_hash:
            await asyncio.to_thread(self.on_session_logout, session_hash)
            return

        targets: list[str] = []
        for sh, ident in list(self._session_identities.items()):
            if exclude_session_hash and sh == exclude_session_hash:
                continue
            matched = False
            if username_key and ident.get("username_key") == username_key:
                matched = True
            elif bot is not None and user_id is not None and ident.get("bot") == bot and ident.get("user_id") == user_id:
                matched = True
            if matched:
                targets.append(sh)
        for sh in targets:
            await asyncio.to_thread(self.on_session_logout, sh)

    # ------------------------------------------------------------------ Audit & SSE Helpers
    def _publish_accounts_updated(
        self,
        *,
        action: str,
        account_id: str = "",
        active_account_id: str | None = None,
    ) -> None:
        if self.event_hub is None:
            return
        payload: dict[str, Any] = {
            "action": str(action)[:48],
            "source": "studio",
            "ts": round(time.time(), 3),
        }
        if account_id:
            payload["account_id"] = _sanitize_slug(account_id, max_len=64)
        if active_account_id is not None:
            payload["active_account_id"] = _sanitize_slug(active_account_id, max_len=64) if active_account_id else None
        self.event_hub.publish("accounts_updated", payload)

    def _load_account_weekly_resets(self) -> dict[str, dict[str, int]]:
        cfg = _read_json_ro(self.data_sources.cost_config_file, {})
        if not isinstance(cfg, dict):
            return {}
        raw_map = cfg.get("account_weekly_resets")
        if not isinstance(raw_map, dict):
            return {}
        out: dict[str, dict[str, int]] = {}
        for aid, rec in raw_map.items():
            if not isinstance(rec, dict):
                continue
            if "weekly_reset_utc_weekday" not in rec or "weekly_reset_utc_hour" not in rec:
                continue
            try:
                wd = int(rec["weekly_reset_utc_weekday"]) % 7
                hr = int(rec["weekly_reset_utc_hour"]) % 24
                mn = int(rec.get("weekly_reset_utc_minute", 0)) % 60
                out[str(aid)] = {"weekday": wd, "hour": hr, "minute": mn}
            except (TypeError, ValueError):
                continue
        return out

    # ------------------------------------------------------------------ Public Snapshot (C1/C6)
    def list_snapshot(self, *, can_edit: bool = False) -> dict[str, Any]:
        """Return strictly desensitized accounts, multi-plan pool summary, and recommendations."""
        accounts = self.account_manager.list_accounts(for_group=False)
        resets_map = self._load_account_weekly_resets()
        enriched: list[dict[str, Any]] = []
        for acct in accounts:
            item = dict(acct)
            aid = str(item.get("account_id") or "")
            if aid in resets_map:
                item["weekly_reset_utc"] = resets_map[aid]
            else:
                item["weekly_reset_utc"] = None
            enriched.append(item)

        by_plan = self.account_manager.summarize_plan_quotas(for_group=False)
        rec_cg = self.account_manager.recommend_account("claude_gpt", for_group=False)
        rec_gem = self.account_manager.recommend_account("gemini", for_group=False)

        snap = {
            "ok": True,
            "active_account_id": by_plan.get("active_account_id"),
            "accounts": enriched,
            "by_plan": by_plan,
            "recommendation": {
                "claude_gpt": rec_cg,
                "gemini": rec_gem,
            },
            "quota_probe_disabled": True,
            "quota_probe_notice": (
                "已停用非官方内部配额 API 探测以防 Google 账号风控；"
                "刷新操作仅通过官方 Google userinfo 同步账号身份，查看当前激活账号配额请使用官方 agy /usage。"
            ),
            "can_edit": bool(can_edit),
            "updated_at": _utc_iso_now(),
        }
        return _strip_forbidden_public_keys(snap)

    # ------------------------------------------------------------------ Bridge UDS IPC Recycle (C5)
    def _iter_bridge_ipc_endpoints(self) -> list[tuple[str, Path, str]]:
        ipc_dir = (self.data_sources.bus_dir / "ipc").resolve()
        if not ipc_dir.is_dir():
            return []
        found: list[tuple[str, Path, str]] = []
        try:
            sock_files = sorted(ipc_dir.glob("*.sock"))
        except OSError:
            return []
        for sock_raw in sock_files:
            handle = sock_raw.stem.strip().lower()
            if not handle or "/" in handle or ".." in handle:
                continue
            sock_p = sock_raw.resolve()
            tok_p = (ipc_dir / f"{handle}.token").resolve()
            try:
                sock_p.relative_to(ipc_dir)
                tok_p.relative_to(ipc_dir)
            except ValueError:
                continue
            if not sock_p.exists() or not tok_p.is_file():
                continue
            try:
                tok = tok_p.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if tok:
                found.append((handle, sock_p, tok))
        return found

    async def _recycle_bridges_after_switch(
        self,
        *,
        account_id: str,
        sess: dict[str, Any],
        reason: str = "studio_activate",
    ) -> list[dict[str, Any]]:
        if self._recycle_callback is not None:
            try:
                res = self._recycle_callback(account_id=account_id, sess=sess, reason=reason)
                if inspect.isawaitable(res):
                    res = await res
                if isinstance(res, list):
                    return res
                if isinstance(res, dict):
                    return [res]
                return [{"handle": "callback", "ok": True}]
            except Exception as exc:
                log.warning("Google accounts recycle_callback failed: %s", type(exc).__name__)
                return [{"handle": "callback", "ok": False, "error": _sanitize_audit_error(exc)}]

        endpoints = self._iter_bridge_ipc_endpoints()
        results: list[dict[str, Any]] = []
        payload = {
            "user_id": int(sess["user_id"]),
            "actor_username": str(sess.get("username") or "")[:64],
            "account_id": account_id,
            "reason": reason,
        }
        for handle, sock_p, tok in endpoints:
            connector = aiohttp.UnixConnector(path=str(sock_p))
            try:
                async with aiohttp.ClientSession(connector=connector) as cli:
                    async with cli.post(
                        "http://localhost/ipc/accounts/recycle",
                        headers={
                            "X-Bridge-IPC-Token": tok,
                            "Content-Type": "application/json",
                        },
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=5.0),
                    ) as resp:
                        raw_txt = await resp.text()
                        try:
                            data = json.loads(raw_txt) if raw_txt else {}
                        except Exception:
                            data = {}
                        ok_ipc = resp.status == 200 and bool(isinstance(data, dict) and data.get("ok"))
                        entry: dict[str, Any] = {
                            "handle": _sanitize_slug(handle, max_len=64),
                            "ok": ok_ipc,
                            "status": resp.status,
                        }
                        if isinstance(data, dict) and "recycled" in data:
                            entry["recycled"] = bool(data.get("recycled"))
                        if not ok_ipc:
                            entry["error"] = _sanitize_audit_error(
                                (data.get("error") if isinstance(data, dict) else "") or f"HTTP {resp.status}"
                            )
                        results.append(entry)
            except Exception as exc:
                log.info("Bridge IPC recycle skipped for %s (offline): %s", handle, type(exc).__name__)
                results.append({
                    "handle": _sanitize_slug(handle, max_len=64),
                    "ok": False,
                    "status": "offline",
                    "error": "Bridge IPC offline",
                })
        return results

    # ------------------------------------------------------------------ Four-Layer Write Gate (C1)
    async def _enforce_write_gate(
        self,
        request: web.Request,
        *,
        action: str,
        account_id: str = "",
        flow_id: str = "",
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        # Gate 1a: Origin required & strictly same-origin
        ok_orig, err_orig = self.auth_mgr.check_same_origin(request, require_origin=True)
        if not ok_orig:
            self.audit.record(
                action=action,
                ok=False,
                account_id=account_id,
                flow_id=flow_id,
                error="denied_origin",
            )
            return False, None, studio_auth_error(err_orig, status=403)

        # Gate 1b: Sec-Fetch-Site validation
        sfs = (request.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sfs and sfs not in ("same-origin", "none"):
            self.audit.record(
                action=action,
                ok=False,
                account_id=account_id,
                flow_id=flow_id,
                error="denied_sec_fetch_site",
            )
            return False, None, studio_auth_error("Sec-Fetch-Site 跨站写请求已拦截", status=403)

        # Gate 2: Non-simple Content-Type: application/json
        if _extract_media_type(request) != "application/json":
            self.audit.record(
                action=action,
                ok=False,
                account_id=account_id,
                flow_id=flow_id,
                error="denied_content_type",
            )
            return False, None, studio_auth_error(
                "写接口仅接受 Content-Type: application/json",
                status=415,
            )

        # Gate 3: Authenticated session + !must_change_password
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            self.audit.record(
                action=action,
                ok=False,
                account_id=account_id,
                flow_id=flow_id,
                error=f"denied_auth:{status_code}",
            )
            return False, None, studio_auth_error(err_auth, status=status_code)

        # Gate 4a: Constant-time X-Studio-CSRF check
        ok_csrf, err_csrf = self.auth_mgr.check_csrf(request, sess)
        if not ok_csrf:
            self.audit.record(
                action=action,
                ok=False,
                sess=sess,
                account_id=account_id,
                flow_id=flow_id,
                error="denied_csrf",
            )
            return False, None, studio_auth_error(err_csrf, status=403)

        # Gate 4b: Live RBAC role == admin
        if sess.get("role") != "admin":
            self.audit.record(
                action=action,
                ok=False,
                sess=sess,
                account_id=account_id,
                flow_id=flow_id,
                error="denied_rbac",
            )
            return False, None, studio_auth_error(
                "只读权限（readonly）禁止执行写操作",
                status=403,
            )

        return True, sess, None

    async def _parse_write_body(
        self,
        request: web.Request,
        *,
        sess: dict[str, Any],
        action: str,
        allowed_keys: frozenset[str],
        allow_empty: bool,
        account_id: str = "",
        flow_id: str = "",
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request,
            max_bytes=MAX_PROMPT_BODY_BYTES,
            allow_empty=allow_empty,
        )
        if not ok_body or body is None:
            self.audit.record(
                action=action,
                ok=False,
                sess=sess,
                account_id=account_id,
                flow_id=flow_id,
                error=body_outcome,
            )
            return False, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_MUTATION_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action=action,
                ok=False,
                sess=sess,
                account_id=account_id,
                flow_id=flow_id,
                error=f"denied_forbidden_field:{bad_forb}",
            )
            return False, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止传入受限字段: {bad_forb}"},
                status=400,
            )

        unknown = set(body.keys()) - allowed_keys
        if unknown:
            self.audit.record(
                action=action,
                ok=False,
                sess=sess,
                account_id=account_id,
                flow_id=flow_id,
                error="denied_unknown_field",
            )
            return False, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": f"存在未允许的字段: {sorted(unknown)[0]}"},
                status=400,
            )

        return True, body, None

    # ------------------------------------------------------------------ REST Handlers

    # GET /api/google-accounts
    async def handle_list_accounts(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        can_edit = sess.get("role") == "admin"
        snap = await asyncio.to_thread(self.list_snapshot, can_edit=can_edit)
        return web.json_response(snap)

    # POST /api/google-accounts
    async def handle_add_account(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="add")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="add",
            allowed_keys=_ALLOWED_ADD_KEYS,
            allow_empty=False,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        raw_aid = body.get("account_id")
        try:
            aid = validate_account_id(raw_aid)
        except ValueError as exc:
            self.audit.record(action="add", ok=False, sess=sess, error=str(exc))
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "account_id 格式非法，仅允许 ^[a-z0-9][a-z0-9_-]{0,47}$"},
                status=400,
            )

        raw_alias = body.get("alias")
        if raw_alias is not None and not isinstance(raw_alias, str):
            self.audit.record(action="add", ok=False, sess=sess, account_id=aid, error="invalid_alias_type")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "alias 必须为字符串"},
                status=400,
            )

        try:
            acct = await asyncio.to_thread(self.account_manager.add_account, aid, raw_alias)
        except SymlinkSecurityError as exc:
            self.audit.record(action="add", ok=False, sess=sess, account_id=aid, error=str(exc))
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": scrub_paths_for_public(str(exc))},
                status=403,
            )
        except AccountError as exc:
            msg = scrub_paths_for_public(str(exc))
            sc = 409 if "already exists" in msg.lower() else 400
            self.audit.record(action="add", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=sc)

        self.audit.record(action="add", ok=True, sess=sess, account_id=aid)
        self._publish_accounts_updated(action="add", account_id=aid)
        snap = await asyncio.to_thread(self.list_snapshot, can_edit=True)
        return web.json_response(
            _strip_forbidden_public_keys({
                "ok": True,
                "account": acct,
                "snapshot": snap,
            }),
            status=201,
        )

    # PATCH /api/google-accounts/{account_id}
    async def handle_update_account(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("account_id") or ""
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="update", account_id=raw_aid
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        try:
            aid = validate_account_id(raw_aid)
        except ValueError as exc:
            self.audit.record(action="update", ok=False, sess=sess, error=str(exc))
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 account_id 格式"},
                status=400,
            )

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="update",
            allowed_keys=_ALLOWED_PATCH_KEYS,
            allow_empty=False,
            account_id=aid,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        if not body:
            self.audit.record(action="update", ok=False, sess=sess, account_id=aid, error="empty_patch")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "至少提供一个可更新字段"},
                status=400,
            )

        new_alias: str | None = None
        if "alias" in body:
            raw_alias = body.get("alias")
            if not isinstance(raw_alias, str) or not raw_alias.strip():
                self.audit.record(action="update", ok=False, sess=sess, account_id=aid, error="invalid_alias")
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "alias 必须为非空字符串"},
                    status=400,
                )
            new_alias = sanitize_alias(raw_alias, aid)

        has_reset_patch = any(
            k in body for k in ("weekly_reset_utc_weekday", "weekly_reset_utc_hour", "weekly_reset_utc_minute")
        )
        wd_val: int | None = None
        hr_val: int | None = None
        mn_val: int | None = None
        if has_reset_patch:
            def _parse_int_range(key: str, lo: int, hi: int) -> tuple[bool, int | None]:
                if key not in body or body[key] is None:
                    return True, None
                v = body[key]
                if isinstance(v, bool) or not isinstance(v, int):
                    return False, None
                if v < lo or v > hi:
                    return False, None
                return True, v

            ok_wd, wd_val = _parse_int_range("weekly_reset_utc_weekday", 0, 6)
            ok_hr, hr_val = _parse_int_range("weekly_reset_utc_hour", 0, 23)
            ok_mn, mn_val = _parse_int_range("weekly_reset_utc_minute", 0, 59)
            if not (ok_wd and ok_hr and ok_mn):
                self.audit.record(action="update", ok=False, sess=sess, account_id=aid, error="invalid_weekly_reset")
                return web.json_response(
                    {
                        "ok": False,
                        "source": "studio_api",
                        "error": "每周重置锚点参数非法（weekday: 0..6, hour: 0..23, minute: 0..59）",
                    },
                    status=400,
                )

        def _apply_update() -> dict[str, Any]:
            with self.account_manager._exclusive_lock():
                reg = self.account_manager._load_registry_locked()
                accounts = reg.get("accounts") or {}
                if aid not in accounts:
                    raise KeyError(f"Account '{aid}' not found")
                rec = accounts[aid]
                if new_alias is not None:
                    rec["alias"] = new_alias
                    rec["updated_at"] = _utc_iso_now()
                    self.account_manager._save_registry_locked(reg)
                dup_map = self.account_manager._compute_duplicates(reg)
                pub = to_public_dict(
                    rec,
                    active_account_id=reg.get("active_account_id"),
                    is_duplicate=(aid in dup_map),
                    duplicate_of=dup_map.get(aid),
                )

            if has_reset_patch:
                cur_wd, cur_hr, cur_mn = cost_usage.load_weekly_reset_utc(
                    str(self.data_sources.cost_config_file),
                    account_id=aid,
                )
                eff_wd = cur_wd if wd_val is None else wd_val
                eff_hr = cur_hr if hr_val is None else hr_val
                eff_mn = cur_mn if mn_val is None else mn_val
                cost_usage.save_weekly_reset_utc(
                    str(self.data_sources.cost_config_file),
                    eff_wd,
                    eff_hr,
                    eff_mn,
                    account_id=aid,
                )
                pub["weekly_reset_utc"] = {"weekday": eff_wd, "hour": eff_hr, "minute": eff_mn}
            else:
                resets = self._load_account_weekly_resets()
                pub["weekly_reset_utc"] = resets.get(aid)
            return pub

        try:
            pub_acct = await asyncio.to_thread(_apply_update)
        except KeyError:
            self.audit.record(action="update", ok=False, sess=sess, account_id=aid, error="not_found")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"账号 '{aid}' 不存在"},
                status=404,
            )
        except Exception as exc:
            msg = scrub_paths_for_public(str(exc))
            self.audit.record(action="update", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=400)

        self.audit.record(action="update", ok=True, sess=sess, account_id=aid)
        self._publish_accounts_updated(action="update", account_id=aid)
        snap = await asyncio.to_thread(self.list_snapshot, can_edit=True)
        return web.json_response(
            _strip_forbidden_public_keys({
                "ok": True,
                "account": pub_acct,
                "snapshot": snap,
            })
        )

    # DELETE /api/google-accounts/{account_id}
    async def handle_delete_account(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("account_id") or ""
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="delete", account_id=raw_aid
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        try:
            aid = validate_account_id(raw_aid)
        except ValueError as exc:
            self.audit.record(action="delete", ok=False, sess=sess, error=str(exc))
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 account_id 格式"},
                status=400,
            )

        ok_body, _body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="delete",
            allowed_keys=frozenset(),
            allow_empty=True,
            account_id=aid,
        )
        if not ok_body:
            assert body_resp is not None
            return body_resp

        await asyncio.to_thread(self.login_flows.cancel_flows_for_account, aid)
        try:
            res = await asyncio.to_thread(self.account_manager.delete_account, aid)
        except SymlinkSecurityError as exc:
            msg = scrub_paths_for_public(str(exc))
            self.audit.record(action="delete", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=403)
        except AccountError as exc:
            msg = scrub_paths_for_public(str(exc))
            sc = 404 if "not found" in msg.lower() else 400
            self.audit.record(action="delete", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=sc)

        self.audit.record(action="delete", ok=True, sess=sess, account_id=aid)
        self._publish_accounts_updated(action="delete", account_id=aid)
        snap = await asyncio.to_thread(self.list_snapshot, can_edit=True)
        return web.json_response(
            _strip_forbidden_public_keys({
                "ok": True,
                "account_id": aid,
                "was_active": bool(res.get("was_active", False)),
                "snapshot": snap,
            })
        )

    # POST /api/google-accounts/{account_id}/login/start
    async def handle_start_login(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("account_id") or ""
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="login_start", account_id=raw_aid
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        try:
            aid = validate_account_id(raw_aid)
        except ValueError as exc:
            self.audit.record(action="login_start", ok=False, sess=sess, error=str(exc))
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 account_id 格式"},
                status=400,
            )

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="login_start",
            allowed_keys=_ALLOWED_LOGIN_START_KEYS,
            allow_empty=True,
            account_id=aid,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        raw_alias = body.get("alias")
        if raw_alias is not None and not isinstance(raw_alias, str):
            self.audit.record(action="login_start", ok=False, sess=sess, account_id=aid, error="invalid_alias")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "alias 必须为字符串"},
                status=400,
            )

        timeout_sec = google_accounts.DEFAULT_LOGIN_TIMEOUT_SEC
        if "timeout_sec" in body and body["timeout_sec"] is not None:
            raw_t = body["timeout_sec"]
            if isinstance(raw_t, bool) or not isinstance(raw_t, (int, float)) or raw_t <= 0:
                self.audit.record(action="login_start", ok=False, sess=sess, account_id=aid, error="invalid_timeout")
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "timeout_sec 必须为正数"},
                    status=400,
                )
            timeout_sec = min(float(raw_t), google_accounts.MAX_LOGIN_TIMEOUT_SEC)

        session_hash = str(sess["session_hash"])
        self._session_identities[session_hash] = {
            "bot": str(sess.get("bot") or ""),
            "user_id": int(sess.get("user_id") or 0),
            "username_key": str(sess.get("username") or "").strip().lower(),
        }

        try:
            flow = await asyncio.to_thread(
                self.login_flows.start_login,
                aid,
                alias=raw_alias,
                owner_session_id=session_hash,
                timeout_sec=timeout_sec,
            )
        except SymlinkSecurityError as exc:
            msg = scrub_paths_for_public(str(exc))
            self.audit.record(action="login_start", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=403)
        except Exception as exc:
            msg = _sanitize_audit_error(exc)
            self.audit.record(action="login_start", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": msg or "启动无头 OAuth 登录失败"},
                status=500,
            )

        fid = str(flow.get("flow_id") or "")
        self.audit.record(action="login_start", ok=True, sess=sess, account_id=aid, flow_id=fid)
        return web.json_response(
            _strip_forbidden_public_keys({
                "ok": True,
                "flow": flow,
            }),
            status=201,
        )

    # GET /api/google-accounts/login/{flow_id}
    async def handle_get_login_status(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        if sess.get("role") != "admin":
            return studio_auth_error("只读权限（readonly）禁止查看 OAuth 登录流状态", status=403)

        flow_id = str(request.match_info.get("flow_id") or "").strip()
        try:
            flow = await asyncio.to_thread(
                self.login_flows.get_flow,
                flow_id,
                str(sess["session_hash"]),
            )
        except PermissionError:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "跨会话访问 OAuth 登录流已被拒绝"},
                status=403,
            )
        except FlowNotFoundError:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的 OAuth 登录流"},
                status=404,
            )

        # Defense-in-depth: GET status NEVER contains oauth_state, auth_url, or profile_dir
        safe_flow = dict(flow)
        safe_flow.pop("oauth_state", None)
        safe_flow.pop("auth_url", None)
        safe_flow.pop("profile_dir", None)
        return web.json_response(_strip_forbidden_public_keys({"ok": True, "flow": safe_flow}))

    # POST /api/google-accounts/login/{flow_id}/submit
    async def handle_submit_login(self, request: web.Request) -> web.Response:
        flow_id = str(request.match_info.get("flow_id") or "").strip()
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="login_submit", flow_id=flow_id
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="login_submit",
            allowed_keys=_ALLOWED_LOGIN_SUBMIT_KEYS,
            allow_empty=False,
            flow_id=flow_id,
        )
        if not ok_body or body is None:
            assert body_resp is not None
            return body_resp

        raw_code = body.get("code_or_url")
        if raw_code is None:
            raw_code = body.get("callback_url")
        if raw_code is None:
            raw_code = body.get("code")
        if not isinstance(raw_code, str) or not raw_code.strip():
            self.audit.record(action="login_submit", ok=False, sess=sess, flow_id=flow_id, error="missing_code_or_url")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "请提供 OAuth 授权码或官方回调链接"},
                status=400,
            )

        try:
            flow = await asyncio.to_thread(
                self.login_flows.submit_code,
                flow_id,
                raw_code,
                str(sess["session_hash"]),
            )
        except PermissionError:
            self.audit.record(action="login_submit", ok=False, sess=sess, flow_id=flow_id, error="cross_session_denied")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "跨会话提交 OAuth 授权码已被拒绝"},
                status=403,
            )
        except FlowNotFoundError:
            self.audit.record(action="login_submit", ok=False, sess=sess, flow_id=flow_id, error="flow_not_found")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的 OAuth 登录流"},
                status=404,
            )
        except FlowConflictError as exc:
            msg = _sanitize_audit_error(exc)
            self.audit.record(action="login_submit", ok=False, sess=sess, flow_id=flow_id, error=msg)
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": msg or "OAuth 登录流已结束或已提交"},
                status=409,
            )
        except ValueError as exc:
            msg = _sanitize_audit_error(exc)
            self.audit.record(action="login_submit", ok=False, sess=sess, flow_id=flow_id, error=msg)
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": msg or "授权码或回调链接校验失败"},
                status=400,
            )
        except SymlinkSecurityError as exc:
            msg = _sanitize_audit_error(exc)
            self.audit.record(action="login_submit", ok=False, sess=sess, flow_id=flow_id, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=403)
        except Exception as exc:
            msg = _sanitize_audit_error(exc)
            self.audit.record(action="login_submit", ok=False, sess=sess, flow_id=flow_id, error=msg)
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": msg or "OAuth 登录完成失败"},
                status=500,
            )

        aid = str(flow.get("account_id") or "")
        self.audit.record(action="login_submit", ok=True, sess=sess, account_id=aid, flow_id=flow_id)
        self._publish_accounts_updated(action="login_completed", account_id=aid)
        snap = await asyncio.to_thread(self.list_snapshot, can_edit=True)
        return web.json_response(
            _strip_forbidden_public_keys({
                "ok": True,
                "flow": flow,
                "snapshot": snap,
            })
        )

    # POST /api/google-accounts/login/{flow_id}/cancel
    async def handle_cancel_login(self, request: web.Request) -> web.Response:
        flow_id = str(request.match_info.get("flow_id") or "").strip()
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="login_cancel", flow_id=flow_id
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, _body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="login_cancel",
            allowed_keys=frozenset(),
            allow_empty=True,
            flow_id=flow_id,
        )
        if not ok_body:
            assert body_resp is not None
            return body_resp

        try:
            flow = await asyncio.to_thread(
                self.login_flows.cancel_flow,
                flow_id,
                str(sess["session_hash"]),
            )
        except PermissionError:
            self.audit.record(action="login_cancel", ok=False, sess=sess, flow_id=flow_id, error="cross_session_denied")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "跨会话取消 OAuth 登录流已被拒绝"},
                status=403,
            )
        except FlowNotFoundError:
            self.audit.record(action="login_cancel", ok=False, sess=sess, flow_id=flow_id, error="flow_not_found")
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的 OAuth 登录流"},
                status=404,
            )

        aid = str(flow.get("account_id") or "")
        self.audit.record(action="login_cancel", ok=True, sess=sess, account_id=aid, flow_id=flow_id)
        return web.json_response(_strip_forbidden_public_keys({"ok": True, "flow": flow}))

    # POST /api/google-accounts/{account_id}/logout
    async def handle_logout_account(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("account_id") or ""
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="logout", account_id=raw_aid
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        try:
            aid = validate_account_id(raw_aid)
        except ValueError as exc:
            self.audit.record(action="logout", ok=False, sess=sess, error=str(exc))
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 account_id 格式"},
                status=400,
            )

        ok_body, _body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="logout",
            allowed_keys=frozenset(),
            allow_empty=True,
            account_id=aid,
        )
        if not ok_body:
            assert body_resp is not None
            return body_resp

        await asyncio.to_thread(self.login_flows.cancel_flows_for_account, aid)
        try:
            res = await asyncio.to_thread(self.account_manager.logout_account, aid)
        except SymlinkSecurityError as exc:
            msg = scrub_paths_for_public(str(exc))
            self.audit.record(action="logout", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=403)
        except AccountError as exc:
            msg = scrub_paths_for_public(str(exc))
            sc = 404 if "not found" in msg.lower() else 400
            self.audit.record(action="logout", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=sc)

        self.audit.record(action="logout", ok=True, sess=sess, account_id=aid)
        self._publish_accounts_updated(action="logout", account_id=aid)
        snap = await asyncio.to_thread(self.list_snapshot, can_edit=True)
        return web.json_response(
            _strip_forbidden_public_keys({
                "ok": True,
                "account": res.get("account"),
                "was_active": bool(res.get("was_active", False)),
                "snapshot": snap,
            })
        )

    # POST /api/google-accounts/{account_id}/activate
    async def handle_activate_account(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("account_id") or ""
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="activate", account_id=raw_aid
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        try:
            aid = validate_account_id(raw_aid)
        except ValueError as exc:
            self.audit.record(action="activate", ok=False, sess=sess, error=str(exc))
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 account_id 格式"},
                status=400,
            )

        ok_body, _body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="activate",
            allowed_keys=frozenset(),
            allow_empty=True,
            account_id=aid,
        )
        if not ok_body:
            assert body_resp is not None
            return body_resp

        try:
            sw = await asyncio.to_thread(self.account_manager.switch_account, aid)
        except SymlinkSecurityError as exc:
            msg = scrub_paths_for_public(str(exc))
            self.audit.record(action="activate", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=403)
        except AccountError as exc:
            msg = scrub_paths_for_public(str(exc))
            sc = 404 if "not found" in msg.lower() else 400
            self.audit.record(action="activate", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=sc)

        recycle_results = await self._recycle_bridges_after_switch(
            account_id=aid,
            sess=sess,
            reason="studio_activate",
        )

        self.audit.record(action="activate", ok=True, sess=sess, account_id=aid)
        self._publish_accounts_updated(action="activate", account_id=aid, active_account_id=aid)
        snap = await asyncio.to_thread(self.list_snapshot, can_edit=True)
        return web.json_response(
            _strip_forbidden_public_keys({
                "ok": True,
                "previous_account_id": sw.get("previous_account_id"),
                "active_account_id": aid,
                "switched": bool(sw.get("switched", False)),
                "account": sw.get("account"),
                "recycle_results": recycle_results,
                "snapshot": snap,
            })
        )

    # POST /api/google-accounts/{account_id}/refresh-quota
    async def handle_refresh_account(self, request: web.Request) -> web.Response:
        raw_aid = request.match_info.get("account_id") or ""
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="refresh", account_id=raw_aid
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        try:
            aid = validate_account_id(raw_aid)
        except ValueError as exc:
            self.audit.record(action="refresh", ok=False, sess=sess, error=str(exc))
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 account_id 格式"},
                status=400,
            )

        ok_body, _body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="refresh",
            allowed_keys=frozenset(),
            allow_empty=True,
            account_id=aid,
        )
        if not ok_body:
            assert body_resp is not None
            return body_resp

        try:
            acct = await asyncio.to_thread(self.account_manager.refresh_account, aid)
        except SymlinkSecurityError as exc:
            msg = scrub_paths_for_public(str(exc))
            self.audit.record(action="refresh", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=403)
        except AccountError as exc:
            msg = scrub_paths_for_public(str(exc))
            sc = 404 if "no target" in msg.lower() or "not found" in msg.lower() else 400
            self.audit.record(action="refresh", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response({"ok": False, "source": "studio_api", "error": msg}, status=sc)
        except GoogleProbeError as exc:
            msg = _sanitize_audit_error(exc)
            self.audit.record(action="refresh", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response(
                {"ok": False, "source": "upstream", "error": msg or "Google 身份同步失败"},
                status=502,
            )
        except Exception as exc:
            msg = _sanitize_audit_error(exc)
            self.audit.record(action="refresh", ok=False, sess=sess, account_id=aid, error=msg)
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": msg or "同步账号身份失败"},
                status=500,
            )

        self.audit.record(action="refresh", ok=True, sess=sess, account_id=aid)
        self._publish_accounts_updated(action="refresh", account_id=aid)
        snap = await asyncio.to_thread(self.list_snapshot, can_edit=True)
        return web.json_response(
            _strip_forbidden_public_keys({
                "ok": True,
                "account": acct,
                "snapshot": snap,
            })
        )

    # POST /api/google-accounts/refresh-all
    async def handle_refresh_all(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action="refresh_all")
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        ok_body, _body, body_resp = await self._parse_write_body(
            request,
            sess=sess,
            action="refresh_all",
            allowed_keys=frozenset(),
            allow_empty=True,
        )
        if not ok_body:
            assert body_resp is not None
            return body_resp

        try:
            res = await asyncio.to_thread(self.account_manager.refresh_all_accounts)
        except Exception as exc:
            msg = _sanitize_audit_error(exc)
            self.audit.record(action="refresh_all", ok=False, sess=sess, error=msg)
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": msg or "批量同步账号身份失败"},
                status=500,
            )

        errs = res.get("errors") if isinstance(res.get("errors"), dict) else {}
        self.audit.record(
            action="refresh_all",
            ok=(len(errs) == 0),
            sess=sess,
            error=("; ".join(f"{k}:{v}" for k, v in errs.items()) if errs else ""),
        )
        self._publish_accounts_updated(action="refresh_all")
        snap = await asyncio.to_thread(self.list_snapshot, can_edit=True)
        return web.json_response(
            _strip_forbidden_public_keys({
                "ok": True,
                "all_succeeded": len(errs) == 0,
                "refreshed": res.get("refreshed") or [],
                "errors": errs,
                "snapshot": snap,
            })
        )


GoogleAccountsService = StudioGoogleAccountsService
