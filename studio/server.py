#!/usr/bin/env python3
"""AGY Studio WebUI Phase 1 MVP — Main aiohttp Sidecar Server.

Serves:
- Zero-data SPA shell (`webui/dist/`)
- Password-mode authentication (`/api/auth/login`, `/api/auth/change-password`, `/api/auth/me`,
  `/api/auth/logout`) or legacy dual-track auth (`/internal/magic-link`, `/api/auth/telegram`,
  `/api/auth/redeem`) strictly isolated by `AGY_STUDIO_AUTH_MODE`
- Strictly read-only Phase 1 observability APIs (`/api/overview`, `/api/bots`, `/api/jobs`,
  `/api/schedules`, `/api/costs`, `/api/browser/status`)
- Same-origin authenticated Live-Browser WS & transfer proxy (`/ws/browser`,
  `/api/browser/upload`, `/api/browser/download/{download_id}`)
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import aiohttp
from aiohttp import web, web_log

from .attachment_service import StudioAttachmentService
from .attention_service import StudioAttentionService
from .auth import StudioAuthManager, studio_auth_error
from .bot_control import StudioBotControlService
from .browser_proxy import BrowserProxy, HTTP_SESSION_KEY
from .chat_service import StudioChatService
from .control_plane import StudioControlPlane
from .data_sources import StudioDataSources
from .event_hub import StudioEventHub
from .gateway_service import GatewayService
from .room_service import StudioRoomService
from .secrets_config_service import SecretsConfigService
from .workbench_state_service import WorkbenchStateService
from .workspace_files import StudioWorkspaceFilesService

AUTH_MGR_KEY: web.AppKey[StudioAuthManager] = web.AppKey("auth_mgr", StudioAuthManager)
DATA_SOURCES_KEY: web.AppKey[StudioDataSources] = web.AppKey("data_sources", StudioDataSources)
BROWSER_PROXY_KEY: web.AppKey[BrowserProxy] = web.AppKey("browser_proxy", BrowserProxy)
CHAT_SERVICE_KEY: web.AppKey[StudioChatService] = web.AppKey("chat_service", StudioChatService)
ATTACHMENT_SERVICE_KEY: web.AppKey[StudioAttachmentService] = web.AppKey(
    "attachment_service", StudioAttachmentService
)
EVENT_HUB_KEY: web.AppKey[StudioEventHub] = web.AppKey("event_hub", StudioEventHub)
CONTROL_PLANE_KEY: web.AppKey[StudioControlPlane] = web.AppKey("control_plane", StudioControlPlane)
WORKSPACE_FILES_KEY: web.AppKey[StudioWorkspaceFilesService] = web.AppKey("workspace_files", StudioWorkspaceFilesService)
BOT_CONTROL_KEY: web.AppKey[StudioBotControlService] = web.AppKey("bot_control", StudioBotControlService)
ROOM_SERVICE_KEY: web.AppKey[StudioRoomService] = web.AppKey("room_service", StudioRoomService)
ATTENTION_SERVICE_KEY: web.AppKey[StudioAttentionService] = web.AppKey("attention_service", StudioAttentionService)
SECRETS_CONFIG_KEY: web.AppKey[SecretsConfigService] = web.AppKey("secrets_config", SecretsConfigService)
GATEWAY_SERVICE_KEY: web.AppKey[GatewayService] = web.AppKey("gateway_service", GatewayService)
WORKBENCH_STATE_KEY: web.AppKey[WorkbenchStateService] = web.AppKey(
    "workbench_state", WorkbenchStateService
)
STATIC_DIST_KEY: web.AppKey[Path] = web.AppKey("static_dist_dir", Path)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("agy-studio")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STATIC_DIST_DIR = REPO_ROOT / "webui" / "dist"


class SanitizedAccessLogger(web_log.AccessLogger):
    """Strict minimal aiohttp AccessLogger: logs ONLY IP, time, query-stripped request line, status, size, duration.

    Explicitly omits `%{Referer}i`, `%{User-Agent}i`, all request headers, and all query parameters so
    credentials can NEVER enter server access logs via query strings or `Referer` headers.
    """

    LOG_FORMAT = '%a %t "%r" %s %b %Tf'

    def __init__(self, logger: logging.Logger, log_format: str = LOG_FORMAT) -> None:
        # Always enforce the minimal sanitized format even when AppRunner passes aiohttp's default format
        super().__init__(logger, log_format=self.LOG_FORMAT)

    @staticmethod
    def sanitize_target(path: str, path_qs: str) -> str:
        clean_path = (path or "").split("?", 1)[0]
        if clean_path:
            return clean_path
        return (path_qs or "/").split("?", 1)[0] or "/"

    def _format_r(self, request: Any, response: Any, time: float) -> str:  # noqa: A002
        if request is None:
            return "-"
        method = str(getattr(request, "method", "GET") or "GET")
        raw_path_qs = str(getattr(request, "path_qs", "") or "")
        safe_path = self.sanitize_target(str(getattr(request, "path", "") or ""), raw_path_qs)
        ver = getattr(request, "version", None)
        if ver is not None:
            return f"{method} {safe_path} HTTP/{ver.major}.{ver.minor}"
        return f"{method} {safe_path} HTTP/1.1"

    def _format_line(self, request: Any, response: Any, time: float) -> list[tuple[Any, Any]]:  # noqa: A002
        items = list(super()._format_line(request, response, time))
        if request is None:
            return items
        raw_path_qs = str(getattr(request, "path_qs", "") or "")
        if "?" not in raw_path_qs:
            return items
        safe_path = self.sanitize_target(str(getattr(request, "path", "") or ""), raw_path_qs)
        sanitized: list[tuple[Any, Any]] = []
        for key, val in items:
            if isinstance(val, str) and raw_path_qs in val:
                val = val.replace(raw_path_qs, safe_path)
            sanitized.append((key, val))
        return sanitized


CSP_HEADER_PASSWORD = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "object-src 'none'"
)

CSP_HEADER_LEGACY = (
    "default-src 'self'; "
    "script-src 'self' https://telegram.org; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "object-src 'none'"
)

CSP_HEADER = CSP_HEADER_PASSWORD


async def security_headers_middleware(
    request: web.Request,
    handler: Any,
) -> web.StreamResponse:
    try:
        resp = await handler(request)
    except web.HTTPException as exc:
        resp = exc
    auth = request.app.get(AUTH_MGR_KEY)
    csp_value = (
        CSP_HEADER_LEGACY
        if (auth is not None and auth.auth_mode == "legacy")
        else CSP_HEADER_PASSWORD
    )
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    resp.headers.setdefault("Content-Security-Policy", csp_value)
    if request.path.startswith(("/api/", "/auth/", "/internal/")):
        if request.method == "GET" and request.path.startswith("/api/chat/attachments/"):
            resp.headers.setdefault("Cache-Control", "private, max-age=3600")
        else:
            resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp


def _safe_static_file(dist_dir: Path, rel_path: str) -> Path | None:
    try:
        root = dist_dir.resolve()
        candidate = (root / rel_path.lstrip("/")).resolve()
        candidate.relative_to(root)
    except Exception:
        return None
    return candidate if candidate.is_file() else None


def _session_payload(auth: StudioAuthManager, sess: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": True,
        "authenticated": True,
        "auth_mode": auth.auth_mode,
        "bot": sess["bot"],
        "user_id": sess["user_id"],
        "role": sess["role"],
        "user": sess["user"],
        "auth_track": sess["auth_track"],
        "must_change_password": bool(sess.get("must_change_password", False)),
        "csrf_token": sess["csrf_token"],
    }
    if sess.get("username"):
        payload["username"] = sess["username"]
    return payload


def create_app(
    *,
    auth_mgr: StudioAuthManager | None = None,
    data_sources: StudioDataSources | None = None,
    static_dist_dir: Path | None = None,
    revocation_check_interval: float = 1.5,
    audit_log_path: Path | None = None,
    sse_keepalive_interval: float = 15.0,
    event_hub_max_events: int = 256,
    event_watcher_interval: float = 0.5,
    workbench_state_path: Path | None = None,
) -> web.Application:
    public_url = os.environ.get("AGY_STUDIO_PUBLIC_URL", "").strip()
    auth = auth_mgr or StudioAuthManager(public_url=public_url)
    sources = data_sources or StudioDataSources()
    proxy = BrowserProxy(auth, sources, revocation_check_interval=revocation_check_interval)
    chat_service = StudioChatService(
        auth,
        sources,
        audit_log_path=audit_log_path,
        revocation_check_interval=revocation_check_interval,
        keepalive_interval=sse_keepalive_interval,
    )
    attachment_service = StudioAttachmentService(
        auth,
        sources,
        chat_service.audit,
    )
    chat_service.attachment_service = attachment_service
    event_hub = StudioEventHub(
        auth,
        sources,
        max_events=event_hub_max_events,
        revocation_check_interval=revocation_check_interval,
        keepalive_interval=sse_keepalive_interval,
        watcher_interval=event_watcher_interval,
    )
    control_plane = StudioControlPlane(
        auth,
        sources,
        event_hub,
        chat_service.audit,
    )
    workspace_files = StudioWorkspaceFilesService(
        auth,
        sources,
        event_hub,
        chat_service.audit,
    )
    bot_control = StudioBotControlService(
        auth,
        sources,
        event_hub,
        chat_service.audit,
    )
    room_service = StudioRoomService(
        auth,
        sources,
        event_hub,
        chat_service.audit,
        attachment_service=attachment_service,
    )
    attention_service = StudioAttentionService(
        auth,
        sources,
        event_hub,
        chat_service.audit,
    )
    secrets_config = SecretsConfigService(
        auth,
        chat_service.audit,
    )
    gateway_service = GatewayService(
        auth,
        secrets_config,
        chat_service.audit,
        event_hub=event_hub,
    )
    workbench_state = WorkbenchStateService(
        auth,
        chat_service.audit,
        event_hub=event_hub,
        state_path=workbench_state_path,
    )
    dist_dir = static_dist_dir or Path(
        os.environ.get("AGY_STUDIO_DIST_DIR", str(DEFAULT_STATIC_DIST_DIR))
    )

    app = web.Application(
        middlewares=[web.middleware(security_headers_middleware)],
        client_max_size=28 * 1024 * 1024,
    )
    app[AUTH_MGR_KEY] = auth
    app[DATA_SOURCES_KEY] = sources
    app[BROWSER_PROXY_KEY] = proxy
    app[CHAT_SERVICE_KEY] = chat_service
    app[ATTACHMENT_SERVICE_KEY] = attachment_service
    app[EVENT_HUB_KEY] = event_hub
    app[CONTROL_PLANE_KEY] = control_plane
    app[WORKSPACE_FILES_KEY] = workspace_files
    app[BOT_CONTROL_KEY] = bot_control
    app[ROOM_SERVICE_KEY] = room_service
    app[ATTENTION_SERVICE_KEY] = attention_service
    app[SECRETS_CONFIG_KEY] = secrets_config
    app[GATEWAY_SERVICE_KEY] = gateway_service
    app[WORKBENCH_STATE_KEY] = workbench_state
    app[STATIC_DIST_KEY] = dist_dir

    async def _on_startup(application: web.Application) -> None:
        application[HTTP_SESSION_KEY] = aiohttp.ClientSession()
        event_hub.start_watcher()

    async def _on_cleanup(application: web.Application) -> None:
        await room_service.close_all()
        await event_hub.close_all()
        await chat_service.close_all()
        await proxy.close_all()
        sess = application.get(HTTP_SESSION_KEY)
        if sess is not None and not sess.closed:
            await sess.close()

    app.on_startup.append(_on_startup)
    app.on_cleanup.append(_on_cleanup)

    # ---------------------------------------------------------------- Health
    async def handle_healthz(_request: web.Request) -> web.Response:
        return web.json_response({"ok": True, "service": "agy-studio", "readonly_mvp": True})

    # ---------------------------------------------------------------- Password Mode: Login & Change Password
    async def handle_auth_login(request: web.Request) -> web.Response:
        if auth.auth_mode != "password":
            return studio_auth_error("当前为 legacy 双轨模式，账号密码登录未启用", status=403)
        ok_orig, err_orig = auth.check_same_origin(request, require_origin=True)
        if not ok_orig:
            return studio_auth_error(err_orig, status=403)
        try:
            body = await request.json()
        except Exception:
            return studio_auth_error("请求体必须为有效 JSON", status=400)
        if not isinstance(body, dict):
            return studio_auth_error("请求体必须为 JSON 对象", status=400)

        client_ip = auth.extract_client_ip(request)
        ok, raw_sid, sess, err, status_code, retry_after = await auth.authenticate_password(
            body.get("username"),
            body.get("password"),
            client_ip=client_ip,
        )
        if not ok or not sess:
            if status_code == 429:
                return studio_auth_error(
                    err,
                    status=429,
                    extra={"retry_after": retry_after},
                    headers={"Retry-After": str(retry_after)},
                )
            return studio_auth_error(err, status=status_code)

        resp = web.json_response(_session_payload(auth, sess))
        auth.set_session_cookie(resp, request, raw_sid)
        return resp

    async def handle_auth_change_password(request: web.Request) -> web.Response:
        if auth.auth_mode != "password":
            return studio_auth_error("当前为 legacy 双轨模式，修改密码接口未启用", status=403)
        ok_orig, err_orig = auth.check_same_origin(request, require_origin=True)
        if not ok_orig:
            return studio_auth_error(err_orig, status=403)
        ok_auth, sess, err_auth, status_code = await auth.authenticate_request(
            request, allow_password_change_only=True
        )
        if not ok_auth or not sess:
            return studio_auth_error(err_auth, status=status_code)
        ok_csrf, err_csrf = auth.check_csrf(request, sess)
        if not ok_csrf:
            return studio_auth_error(err_csrf, status=403)
        try:
            body = await request.json()
        except Exception:
            return studio_auth_error("请求体必须为有效 JSON", status=400)
        if not isinstance(body, dict):
            return studio_auth_error("请求体必须为 JSON 对象", status=400)

        client_ip = auth.extract_client_ip(request)
        ok, new_raw_sid, new_sess, err, sc, retry_after = await auth.change_password(
            sess,
            body.get("current_password"),
            body.get("new_password"),
            client_ip=client_ip,
        )
        if not ok or not new_sess:
            if sc == 429:
                return studio_auth_error(
                    err,
                    status=429,
                    extra={"retry_after": retry_after},
                    headers={"Retry-After": str(retry_after)},
                )
            return studio_auth_error(err, status=sc)

        resp = web.json_response(_session_payload(auth, new_sess))
        auth.set_session_cookie(resp, request, new_raw_sid)
        return resp

    # ---------------------------------------------------------------- Legacy Internal Magic Link Issue
    async def handle_internal_magic_link(request: web.Request) -> web.Response:
        ok_loop, err_loop = auth.verify_internal_loopback(request)
        if not ok_loop:
            return studio_auth_error(err_loop, status=403)
        if auth.auth_mode != "legacy":
            return studio_auth_error(
                "当前 WebUI 已切换为账号密码登录模式，一次性魔法链接已停用，请直接使用账号密码登录",
                status=403,
            )
        try:
            body = await request.json()
        except Exception:
            return studio_auth_error("请求体必须为有效 JSON", status=400)
        if not isinstance(body, dict):
            return studio_auth_error("请求体必须为 JSON 对象", status=400)
        fallback_base = f"{request.scheme}://{request.host}" if request.host else ""
        ok, payload, err = auth.issue_magic_link(
            body.get("bot"),
            body.get("user_id"),
            fallback_base_url=fallback_base,
        )
        if not ok or not payload:
            return studio_auth_error(err, status=403)
        return web.json_response(payload)

    # ---------------------------------------------------------------- Legacy Track A: Telegram Mini App Auth
    async def handle_auth_telegram(request: web.Request) -> web.Response:
        if auth.auth_mode != "legacy":
            return studio_auth_error("当前已启用账号密码登录模式，Telegram Mini App 登录已停用", status=403)
        ok_orig, err_orig = auth.check_same_origin(request, require_origin=True)
        if not ok_orig:
            return studio_auth_error(err_orig, status=403)
        try:
            body = await request.json()
        except Exception:
            return studio_auth_error("请求体必须为有效 JSON", status=400)
        if not isinstance(body, dict):
            return studio_auth_error("请求体必须为 JSON 对象", status=400)
        init_data = str(body.get("initData") or "")
        ok, raw_sid, sess, err = auth.authenticate_telegram_init_data(init_data)
        if not ok or not sess:
            return studio_auth_error(err, status=403)
        resp = web.json_response(_session_payload(auth, sess))
        auth.set_session_cookie(resp, request, raw_sid)
        return resp

    # ---------------------------------------------------------------- Legacy Track B: Magic Link Redeem
    async def handle_auth_redeem(request: web.Request) -> web.Response:
        if auth.auth_mode != "legacy":
            return studio_auth_error("当前已启用账号密码登录模式，一次性魔法链接已停用", status=403)
        ok_orig, err_orig = auth.check_same_origin(request, require_origin=True)
        if not ok_orig:
            return studio_auth_error(err_orig, status=403)
        try:
            body = await request.json()
        except Exception:
            return studio_auth_error("请求体必须为有效 JSON", status=400)
        if not isinstance(body, dict):
            return studio_auth_error("请求体必须为 JSON 对象", status=400)
        token = str(body.get("token") or "")
        ok, raw_sid, sess, err = auth.redeem_magic_token(token)
        if not ok or not sess:
            return studio_auth_error(err, status=403)
        resp = web.json_response(_session_payload(auth, sess))
        auth.set_session_cookie(resp, request, raw_sid)
        return resp

    # ---------------------------------------------------------------- Session Introspection & Logout
    async def handle_auth_me(request: web.Request) -> web.Response:
        ok, sess, err, status_code = await auth.authenticate_request(
            request, allow_password_change_only=True
        )
        if not ok or not sess:
            return studio_auth_error(err, status=status_code, extra={"auth_mode": auth.auth_mode})
        return web.json_response(_session_payload(auth, sess))

    async def handle_auth_logout(request: web.Request) -> web.Response:
        ok_orig, err_orig = auth.check_same_origin(request, require_origin=True)
        if not ok_orig:
            return studio_auth_error(err_orig, status=403)
        ok, sess, err, status_code = await auth.authenticate_request(
            request, allow_password_change_only=True
        )
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        ok_csrf, err_csrf = auth.check_csrf(request, sess)
        if not ok_csrf:
            return studio_auth_error(err_csrf, status=403)
        await auth.destroy_session(sess["session_hash"])
        resp = web.json_response({"ok": True, "authenticated": False})
        auth.clear_session_cookie(resp, request)
        return resp

    # ---------------------------------------------------------------- Phase 1 Read-Only APIs (strictly gated by must_change_password)
    async def handle_api_overview(request: web.Request) -> web.Response:
        ok, sess, err, status_code = await auth.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        data = await sources.get_overview(session=sess, http_session=request.app[HTTP_SESSION_KEY])
        return web.json_response(data)

    async def handle_api_bots(request: web.Request) -> web.Response:
        ok, sess, err, status_code = await auth.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        return web.json_response(sources.get_bots())

    async def handle_api_jobs(request: web.Request) -> web.Response:
        ok, sess, err, status_code = await auth.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        try:
            limit = int(request.query.get("limit", "30"))
        except ValueError:
            limit = 30
        status_q = request.query.get("status")
        bot_q = request.query.get("bot")
        return web.json_response(sources.get_jobs(limit=limit, status=status_q, bot=bot_q))

    async def handle_api_schedules(request: web.Request) -> web.Response:
        ok, sess, err, status_code = await auth.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        return web.json_response(sources.get_schedules())

    async def handle_api_costs(request: web.Request) -> web.Response:
        ok, sess, err, status_code = await auth.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        scope = request.query.get("scope", "all")
        return web.json_response(sources.get_costs(scope=scope))

    async def handle_api_browser_status(request: web.Request) -> web.Response:
        ok, sess, err, status_code = await auth.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        data = await sources.get_browser_status(
            bot_key=str(sess["bot"]),
            user_id=int(sess["user_id"]),
            http_session=request.app[HTTP_SESSION_KEY],
        )
        return web.json_response(data)

    async def handle_api_not_found(_request: web.Request) -> web.Response:
        return web.json_response(
            {"ok": False, "source": "studio_api", "error": "Endpoint not found or disabled in Phase 1 read-only MVP"},
            status=404,
        )

    # ---------------------------------------------------------------- Static SPA Shell (Zero Data)
    def _serve_spa_index() -> web.StreamResponse:
        idx = dist_dir / "index.html"
        if idx.is_file():
            return web.FileResponse(idx, headers={"Cache-Control": "no-store, max-age=0"})
        return web.Response(
            text=(
                "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'/>"
                "<title>AGY Studio</title></head><body>"
                "<h1>AGY Studio WebUI</h1><p>Frontend assets not built yet. Run npm run build in webui/.</p>"
                "</body></html>"
            ),
            content_type="text/html",
            headers={"Cache-Control": "no-store, max-age=0"},
        )

    async def handle_spa_shell(_request: web.Request) -> web.StreamResponse:
        # Strictly zero business data; `/auth/magic#t=...` never sends or consumes tokens on GET
        return _serve_spa_index()

    async def handle_static_asset(request: web.Request) -> web.StreamResponse:
        rel = request.match_info.get("asset_path", "")
        target = _safe_static_file(dist_dir / "assets", rel)
        if not target:
            raise web.HTTPNotFound(text="Not Found")
        immutable_max_age = 365 * 86400
        return web.FileResponse(target, headers={"Cache-Control": f"public, max-age={immutable_max_age}, immutable"})

    # Register routes
    app.router.add_get("/healthz", handle_healthz)
    app.router.add_post("/internal/magic-link", handle_internal_magic_link)

    app.router.add_post("/api/auth/login", handle_auth_login)
    app.router.add_post("/api/auth/change-password", handle_auth_change_password)
    app.router.add_post("/api/auth/telegram", handle_auth_telegram)
    app.router.add_post("/api/auth/redeem", handle_auth_redeem)
    app.router.add_get("/api/auth/me", handle_auth_me)
    app.router.add_post("/api/auth/logout", handle_auth_logout)

    app.router.add_get("/api/overview", handle_api_overview)
    app.router.add_get("/api/bots", handle_api_bots)
    app.router.add_get("/api/jobs", handle_api_jobs)
    app.router.add_get("/api/schedules", handle_api_schedules)
    app.router.add_get("/api/costs", handle_api_costs)
    app.router.add_get("/api/browser/status", handle_api_browser_status)

    # Phase A M1: Single-Writer Chat, Sessions & Models APIs
    app.router.add_get("/api/sessions", chat_service.handle_get_sessions)
    app.router.add_get("/api/sessions/{cid}/messages", chat_service.handle_get_session_messages)
    app.router.add_get("/api/sessions/{cid}/active-turn", chat_service.handle_get_session_active_turn)
    app.router.add_get("/api/models", chat_service.handle_get_models)
    app.router.add_post("/api/chat/attachments", attachment_service.handle_upload)
    app.router.add_get("/api/chat/attachments/{att_id}", attachment_service.handle_get_attachment)
    app.router.add_post("/api/chat/send", chat_service.handle_chat_send)
    app.router.add_post("/api/chat/abort", chat_service.handle_chat_abort)
    app.router.add_get("/api/chat/stream", chat_service.handle_chat_stream)

    # Phase A M2: Jobs Control Plane, Safe Schedules R/W & Global Real-Time SSE
    app.router.add_post("/api/jobs/dispatch", control_plane.handle_dispatch_jobs)
    app.router.add_get("/api/jobs/{job_id}", control_plane.handle_get_job_detail)
    app.router.add_post("/api/jobs/{job_id}/cancel", control_plane.handle_cancel_job)
    app.router.add_post("/api/jobs/{job_id}/retry", control_plane.handle_retry_job)

    app.router.add_post("/api/schedules", control_plane.handle_create_schedule)
    app.router.add_patch("/api/schedules/{schedule_id}", control_plane.handle_patch_schedule)
    app.router.add_delete("/api/schedules/{schedule_id}", control_plane.handle_delete_schedule)
    app.router.add_post("/api/schedules/{schedule_id}/run", control_plane.handle_run_schedule)

    app.router.add_get("/api/events", event_hub.handle_events)

    # Phase B M1: Sandboxed Workspace Files, Git Diff & Single-Writer Undo/Redo
    app.router.add_get("/api/projects", workspace_files.handle_get_projects)
    app.router.add_get("/api/files/tree", workspace_files.handle_get_tree)
    app.router.add_get("/api/files/content", workspace_files.handle_get_content)
    app.router.add_get("/api/files/diff", workspace_files.handle_get_diff)
    app.router.add_get("/api/undo/checkpoints", workspace_files.handle_get_undo_checkpoints)
    app.router.add_post("/api/undo/apply", workspace_files.handle_apply_undo)
    app.router.add_post("/api/undo/redo", workspace_files.handle_apply_redo)

    # Phase B M1: Bot Team Control Plane (Config, Skills/MCP View & Safe Hot-Reload)
    app.router.add_get("/api/bots/{handle}/config", bot_control.handle_get_bot_config)
    app.router.add_patch("/api/bots/{handle}/config", bot_control.handle_patch_bot_config)
    app.router.add_post("/api/bots/{handle}/reload", bot_control.handle_reload_bot)

    # Phase B M2: Web Multi-Bot Chat Rooms & Unified Attention Queue
    app.router.add_get("/api/rooms", room_service.handle_get_rooms)
    app.router.add_post("/api/rooms", room_service.handle_create_room)
    app.router.add_get("/api/rooms/{room_id}/messages", room_service.handle_get_room_messages)
    app.router.add_post("/api/rooms/{room_id}/messages", room_service.handle_post_room_message)
    app.router.add_get("/api/rooms/{room_id}/activity", room_service.handle_get_room_activity)

    app.router.add_get("/api/attention", attention_service.handle_get_attention)
    app.router.add_post("/api/attention", attention_service.handle_create_attention)
    app.router.add_post("/api/attention/{item_id}/decide", attention_service.handle_decide_attention)

    # Secrets Config (OpenBao auto-detect/config & reserved Security Card foundation)
    app.router.add_get("/api/secrets/openbao", secrets_config.handle_get_openbao)
    app.router.add_put("/api/secrets/openbao", secrets_config.handle_put_openbao)
    app.router.add_post("/api/secrets/openbao/test", secrets_config.handle_test_openbao)

    # External Model Gateways CRUD & Bounded /probe (SecretStore-backed)
    app.router.add_get("/api/gateways", gateway_service.handle_list_gateways)
    app.router.add_post("/api/gateways", gateway_service.handle_create_gateway)
    app.router.add_post("/api/gateways/probe", gateway_service.handle_probe_gateway)
    app.router.add_put("/api/gateways/{gateway_id}", gateway_service.handle_update_gateway)
    app.router.add_patch("/api/gateways/{gateway_id}", gateway_service.handle_update_gateway)
    app.router.add_delete("/api/gateways/{gateway_id}", gateway_service.handle_delete_gateway)
    app.router.add_post("/api/gateways/{gateway_id}/probe", gateway_service.handle_probe_gateway)

    # Workbench Sidebar State Server Sync (9 semantic fields; optimistic concurrency)
    app.router.add_get("/api/workbench/state", workbench_state.handle_get_state)
    app.router.add_put("/api/workbench/state", workbench_state.handle_put_state)

    app.router.add_get("/ws/browser", proxy.handle_ws_browser)
    app.router.add_post("/api/browser/upload", proxy.handle_upload)
    app.router.add_get("/api/browser/download/{download_id}", proxy.handle_download)

    # Catch-all for unknown /api/* paths so they never return SPA HTML
    app.router.add_route("*", "/api/{tail:.*}", handle_api_not_found)

    # Zero-data SPA routes
    app.router.add_get("/assets/{asset_path:.*}", handle_static_asset)
    app.router.add_get("/", handle_spa_shell)
    app.router.add_get("/auth/magic", handle_spa_shell)
    for spa_route in (
        "/workspace",
        "/overview",
        "/bots",
        "/models",
        "/openbao",
        "/security-card",
        "/jobs",
        "/schedules",
        "/costs",
        "/browser",
        "/rooms",
        "/attention",
        "/files",
    ):
        app.router.add_get(spa_route, handle_spa_shell)

    return app


def main() -> None:
    host = os.environ.get("AGY_STUDIO_HOST", "127.0.0.1").strip() or "127.0.0.1"
    try:
        port = int(os.environ.get("AGY_STUDIO_PORT", "18796"))
    except ValueError:
        port = 18796
    app = create_app()
    log.info(
        "Starting AGY Studio sidecar on http://%s:%d (auth_mode=%s)",
        host,
        port,
        app[AUTH_MGR_KEY].auth_mode,
    )
    web.run_app(
        app,
        host=host,
        port=port,
        print=None,
        access_log_class=SanitizedAccessLogger,
        access_log_format=SanitizedAccessLogger.LOG_FORMAT,
    )


if __name__ == "__main__":
    main()
