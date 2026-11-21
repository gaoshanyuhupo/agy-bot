#!/usr/bin/env python3
"""AGY Studio Phase B M2 — Unified Approval Center / Attention Queue (`PB-C5`).

Security & Atomicity Guarantees:
- Persistent approval cards stored under `BUS_DIR/studio_approvals/` (`0700` dir,
  `0600` files, `approvals.lock` cross-process `fcntl.flock` + atomic temp-file write).
- Strict `item_id` validation (`^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$`) blocking path traversal.
- Read-only Live-Browser takeover aggregation in `GET /api/attention`: reuses
  `data_sources.get_browser_status()` per `(sess["bot"], sess["user_id"])` and synthesizes
  a pinned `kind: "browser_takeover"` read-only card ONLY when
  `reachable && running && !session_restricted && (takeover || takeover_reason)`.
  NEVER mutates `live-browser` or clears ownerless `wait-human` pause state.
- Atomic CAS decision (`POST /api/attention/{item_id}/decide`) with four-layer Admin write gate,
  synchronous in-flight deduplication set + cross-process `fcntl.flock(approvals.lock)`,
  guaranteeing that 10 concurrent `asyncio.gather` requests yield EXACTLY 1 `200 OK`
  (and 1 downstream `/ipc/attention/notify`) and 9 `409 Conflict` responses.
- Injectable `clock_fn` for deterministic expiration testing (expired items return `409`
  with 0 downstream notifications).
- `0600` append-only `StudioAuditLogger` entries on every allow/deny/conflict/expired branch
  (zero plaintext secrets, CSRF tokens, or raw prompts).
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import time
from typing import Any, Callable, Iterator
import uuid

import aiohttp
from aiohttp import web

from .auth import StudioAuthManager, studio_auth_error
from .browser_proxy import HTTP_SESSION_KEY
from .chat_service import (
    MAX_PROMPT_BODY_BYTES,
    StudioAuditLogger,
    _extract_media_type,
    _read_bounded_json_body,
)
from .control_plane import _find_forbidden_key_recursive
from .data_sources import (
    StudioDataSources,
    _SENSITIVE_HOST_PATH_RE,
    _sanitize_slug,
    redact_secrets_only,
    redact_sensitive_text,
    truncate_utf8_bytes,
)
from .event_hub import StudioEventHub
import studio_ipc

log = logging.getLogger("agy-studio.attention")

ITEM_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$")
MAX_SUMMARY_BYTES = 4 * 1024
MAX_TITLE_CHARS = 160
MAX_NOTE_BYTES = 2 * 1024
MAX_APPROVAL_CARDS = 200
DEFAULT_TTL_SEC = 900.0
MIN_TTL_SEC = 1.0
MAX_TTL_SEC = 86400.0

BROWSER_TAKEOVER_ITEM_ID = "browser-takeover-live"

_VALID_KINDS = frozenset({"plan", "action", "undo_force"})
_VALID_RISK_LEVELS = frozenset({"medium", "high"})
_VALID_STATUSES = frozenset({"pending", "approved", "rejected", "expired"})
_VALID_DECISIONS = frozenset({"approved", "rejected"})

_ALLOWED_CREATE_KEYS = frozenset({
    "item_id",
    "kind",
    "risk_level",
    "title",
    "summary",
    "bot",
    "cid",
    "project_id",
    "room_id",
    "ttl_sec",
    "expires_at",
})
_ALLOWED_DECIDE_KEYS = frozenset({"decision", "note"})
_FORBIDDEN_ATTENTION_KEYS = frozenset({
    "chat_id",
    "target_chat_id",
    "thread_id",
    "target_thread_id",
    "role",
    "workdir",
    "ipc_sock",
    "script",
    "precheck_cmd",
    "reload_file",
    "command",
    "cmd",
    "shell",
})


def is_valid_attention_id(raw: Any) -> bool:
    if not isinstance(raw, str):
        return False
    if ".." in raw or "/" in raw or "\\" in raw or "\x00" in raw or "%" in raw:
        return False
    return bool(ITEM_ID_RE.fullmatch(raw))


def _sanitize_attention_text(raw: Any, *, max_bytes: int = MAX_SUMMARY_BYTES) -> str:
    text = redact_secrets_only(raw)
    if text:
        text = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", text)
    clipped, _ = truncate_utf8_bytes(text, max_bytes)
    return clipped


def _finite_float_or_none(val: Any) -> float | None:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        return None
    fval = float(val)
    return fval if math.isfinite(fval) else None


def _atomic_write_json_0600(target_path: Path, payload: dict[str, Any]) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(target_path.parent, 0o700)
    except OSError:
        pass
    raw = (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")
    tmp_path = target_path.parent / f".{target_path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}"
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, target_path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _read_json_dict(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


class StudioAttentionService:
    """Unified Attention Queue & atomic CAS approval engine."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        data_sources: StudioDataSources,
        event_hub: StudioEventHub,
        audit: StudioAuditLogger,
        *,
        clock_fn: Callable[[], float] | None = None,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.event_hub = event_hub
        self.audit = audit
        self.clock_fn: Callable[[], float] = clock_fn or time.time
        # Synchronous in-flight guard eliminates intra-process async TOCTOU races
        self._deciding_ids: set[str] = set()

    def _approvals_dir(self) -> Path:
        d = (self.data_sources.bus_dir / "studio_approvals").resolve()
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        return d

    def _card_path(self, item_id: str) -> Path:
        root = self._approvals_dir()
        cand = (root / f"{item_id}.json").resolve()
        cand.relative_to(root)
        return cand

    @contextmanager
    def _approvals_lock(self) -> Iterator[None]:
        adir = self._approvals_dir()
        lock_p = adir / "approvals.lock"
        fd = os.open(str(lock_p), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                os.chmod(lock_p, 0o600)
            except OSError:
                pass
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _normalize_card(self, raw: dict[str, Any], *, now: float) -> tuple[dict[str, Any], bool]:
        """Return `(sanitized_card, status_changed_to_expired)`."""
        status = str(raw.get("status") or "pending").strip().lower()
        if status not in _VALID_STATUSES:
            status = "pending"
        expires_val = _finite_float_or_none(raw.get("expires_at"))
        created_val = _finite_float_or_none(raw.get("created_at"))
        if created_val is None:
            created_val = now
        decided_val = _finite_float_or_none(raw.get("decided_at"))
        expired_now = False
        if (
            status == "pending"
            and expires_val is not None
            and expires_val > 0
            and now >= expires_val
        ):
            status = "expired"
            expired_now = True

        kind = str(raw.get("kind") or "action").strip().lower()
        if kind not in _VALID_KINDS:
            kind = "action"
        risk = str(raw.get("risk_level") or "medium").strip().lower()
        if risk not in _VALID_RISK_LEVELS:
            risk = "medium"

        card = {
            "item_id": str(raw.get("item_id") or ""),
            "kind": kind,
            "risk_level": risk,
            "status": status,
            "readonly_signal": False,
            "title": _sanitize_attention_text(raw.get("title") or kind, max_bytes=MAX_TITLE_CHARS * 3)[:MAX_TITLE_CHARS],
            "summary": _sanitize_attention_text(raw.get("summary") or "", max_bytes=MAX_SUMMARY_BYTES),
            "bot": _sanitize_slug(raw.get("bot") or "", max_len=64),
            "cid": str(raw.get("cid") or "") if studio_ipc.is_valid_cid(raw.get("cid")) else "",
            "project_id": _sanitize_slug(raw.get("project_id") or "", max_len=64),
            "room_id": _sanitize_slug(raw.get("room_id") or "", max_len=32),
            "created_at": created_val,
            "expires_at": expires_val,
            "decided_at": decided_val,
            "decided_by": _sanitize_slug(raw.get("decided_by") or "", max_len=64) or None,
            "decision_note": _sanitize_attention_text(raw.get("decision_note") or "", max_bytes=MAX_NOTE_BYTES),
        }
        return card, expired_now

    def _list_cards_locked(self, *, now: float) -> list[dict[str, Any]]:
        adir = self._approvals_dir()
        cards: list[dict[str, Any]] = []
        try:
            for ent in os.scandir(adir):
                if not ent.is_file() or not ent.name.endswith(".json") or ent.name.endswith(".tmp"):
                    continue
                if ent.name.startswith("."):
                    continue
                stem = ent.name[:-5]
                if not is_valid_attention_id(stem):
                    continue
                raw = _read_json_dict(Path(ent.path))
                if raw is None:
                    continue
                raw.setdefault("item_id", stem)
                card, expired_now = self._normalize_card(raw, now=now)
                if expired_now:
                    try:
                        _atomic_write_json_0600(Path(ent.path), card)
                    except OSError:
                        pass
                cards.append(card)
        except OSError:
            pass
        cards.sort(key=lambda c: (0 if c["status"] == "pending" else 1, -float(c["created_at"])))
        return cards

    def _prune_old_cards_locked(self, cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(cards) < MAX_APPROVAL_CARDS:
            return list(cards)
        resolved = [c for c in cards if c["status"] != "pending"]
        resolved.sort(key=lambda c: float(c.get("created_at") or 0.0))
        excess = len(cards) - MAX_APPROVAL_CARDS + 1
        removed_ids: set[str] = set()
        for c in resolved[:excess]:
            try:
                self._card_path(c["item_id"]).unlink(missing_ok=True)
                removed_ids.add(c["item_id"])
            except OSError:
                pass
        return [c for c in cards if c["item_id"] not in removed_ids]

    # ------------------------------------------------------------------ Four-Layer Write Gate
    async def _enforce_write_gate(
        self,
        request: web.Request,
        *,
        action: str,
        target_id: str = "",
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        client_ip = self.auth_mgr.extract_client_ip(request)

        # Gate 1: Strict Same-Origin
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

        # Gate 3: Session cookie + live RBAC + must_change_password=False
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

        # Gate 4a: CSRF
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

        # Gate 4b: Admin live RBAC
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
                "只读权限（readonly）禁止执行审批写操作",
                status=403,
            )

        return True, sess, None

    # ------------------------------------------------------------------ Bridge IPC Notification
    def _resolve_bot_ipc(self, bot_handle: str | None) -> tuple[str, Path, str] | None:
        ipc_dir = (self.data_sources.bus_dir / "ipc").resolve()
        if not ipc_dir.is_dir():
            return None
        candidates: list[str] = []
        if bot_handle:
            clean = _sanitize_slug(bot_handle.lstrip("@").lower(), max_len=64)
            if clean:
                candidates.append(clean)
        else:
            for b in self.data_sources.get_bots().get("bots") or []:
                h = str(b.get("handle") or "").strip().lower()
                if h and b.get("online"):
                    candidates.append(h)
        for h in candidates:
            if not h or "/" in h or ".." in h:
                continue
            sock_p = (ipc_dir / f"{h}.sock").resolve()
            tok_p = (ipc_dir / f"{h}.token").resolve()
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
                return h, sock_p, token
        return None

    async def _notify_bridge_decision(
        self,
        *,
        card: dict[str, Any],
        decision: str,
        note: str,
        sess: dict[str, Any],
    ) -> dict[str, Any]:
        resolved = self._resolve_bot_ipc(card.get("bot") or None)
        if resolved is None:
            return {"notified": False, "reason": "ipc_offline"}
        bot_handle, sock_p, token = resolved
        connector = aiohttp.UnixConnector(path=str(sock_p))
        payload = {
            "user_id": int(sess["user_id"]),
            "actor_username": str(sess.get("username") or "")[:64],
            "item_id": card["item_id"],
            "kind": card["kind"],
            "decision": decision,
            "note": note,
        }
        try:
            async with aiohttp.ClientSession(connector=connector) as cli:
                async with cli.post(
                    "http://localhost/ipc/attention/notify",
                    headers={
                        "X-Bridge-IPC-Token": token,
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10.0),
                ) as resp:
                    raw = await resp.text()
                    try:
                        data = json.loads(raw) if raw else {}
                    except Exception:
                        data = {}
                    return {
                        "notified": resp.status < 400 and bool(data.get("ok", True)),
                        "bot": bot_handle,
                        "status": resp.status,
                    }
        except Exception as exc:
            log.warning("Attention IPC notify to @%s failed: %s", bot_handle, type(exc).__name__)
            return {"notified": False, "bot": bot_handle, "reason": "ipc_error"}

    # ------------------------------------------------------------------ HTTP Handlers
    async def handle_get_attention(self, request: web.Request) -> web.Response:
        ok, sess, err, sc = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=sc)

        status_filter = str(request.query.get("status") or "all").strip().lower()
        now = float(self.clock_fn())

        with self._approvals_lock():
            cards = self._list_cards_locked(now=now)

        # Read-only Live-Browser takeover aggregation (zero mutation, zero touch on live-browser state)
        browser_card: dict[str, Any] | None = None
        http_session = request.app.get(HTTP_SESSION_KEY)
        if http_session is not None:
            b_st = await self.data_sources.get_browser_status(
                bot_key=str(sess["bot"]),
                user_id=int(sess["user_id"]),
                http_session=http_session,
            )
            if (
                b_st.get("reachable")
                and b_st.get("running")
                and not b_st.get("session_restricted")
                and (b_st.get("takeover") or b_st.get("takeover_reason"))
            ):
                safe_origin = str(b_st.get("url") or "")
                safe_title = redact_sensitive_text(b_st.get("title") or "", max_len=120)
                safe_reason = redact_sensitive_text(
                    b_st.get("takeover_reason") or "浏览器当前处于人工接管/等待人类操作状态",
                    max_len=160,
                )
                browser_card = {
                    "item_id": BROWSER_TAKEOVER_ITEM_ID,
                    "kind": "browser_takeover",
                    "risk_level": "high",
                    "status": "pending",
                    "readonly_signal": True,
                    "title": "实时浏览器等待人工接管",
                    "summary": safe_reason,
                    "origin": safe_origin,
                    "page_title": safe_title,
                    "takeover_reason": safe_reason,
                    "bot": _sanitize_slug(sess.get("bot") or "", max_len=64),
                    "cid": "",
                    "project_id": "",
                    "room_id": "",
                    "created_at": round(now, 3),
                    "expires_at": None,
                    "decided_at": None,
                    "decided_by": None,
                    "decision_note": "",
                }

        all_items: list[dict[str, Any]] = []
        if browser_card is not None:
            all_items.append(browser_card)
        all_items.extend(cards)

        pending_count = sum(1 for c in all_items if c["status"] == "pending")
        if status_filter == "pending":
            filtered = [c for c in all_items if c["status"] == "pending"]
        elif status_filter == "resolved":
            filtered = [c for c in all_items if c["status"] != "pending"]
        else:
            filtered = all_items

        return web.json_response(
            {
                "ok": True,
                "total": len(filtered),
                "pending_count": pending_count,
                "has_browser_takeover": browser_card is not None,
                "items": filtered,
            }
        )

    async def handle_create_attention(self, request: web.Request) -> web.Response:
        action = "attention_create"
        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action=action)
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        ok_b, body, sc_b, out_b, err_b = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES
        )
        if not ok_b or body is None:
            self.audit.record(
                action=action, status_code=sc_b, outcome=out_b, client_ip=client_ip, sess=sess
            )
            return web.json_response({"ok": False, "source": "studio_api", "error": err_b}, status=sc_b)

        bad_key = _find_forbidden_key_recursive(body, _FORBIDDEN_ATTENTION_KEYS)
        if bad_key is not None:
            self.audit.record(
                action=action, status_code=400, outcome="denied_forbidden_field", client_ip=client_ip, sess=sess
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止传入受限字段: {bad_key}"},
                status=400,
            )

        unknown = set(body.keys()) - _ALLOWED_CREATE_KEYS
        if unknown:
            self.audit.record(
                action=action, status_code=400, outcome="denied_unknown_field", client_ip=client_ip, sess=sess
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"不支持的字段: {sorted(unknown)[0]}"},
                status=400,
            )

        raw_id = body.get("item_id")
        if raw_id is not None and str(raw_id).strip() != "":
            item_id = str(raw_id).strip()
            if not is_valid_attention_id(item_id) or item_id == BROWSER_TAKEOVER_ITEM_ID:
                self.audit.record(
                    action=action, status_code=400, outcome="denied_invalid_id", client_ip=client_ip, sess=sess
                )
                return web.json_response(
                    {
                        "ok": False,
                        "source": "studio_api",
                        "error": "item_id 须匹配 ^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$",
                    },
                    status=400,
                )
        else:
            item_id = f"att-{uuid.uuid4().hex[:12]}"

        kind = str(body.get("kind") or "action").strip().lower()
        if kind not in _VALID_KINDS:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_invalid_kind",
                client_ip=client_ip,
                target_id=item_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "kind 必须为 plan / action / undo_force"},
                status=400,
            )

        risk_level = str(body.get("risk_level") or "medium").strip().lower()
        if risk_level not in _VALID_RISK_LEVELS:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_invalid_risk",
                client_ip=client_ip,
                target_id=item_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "risk_level 必须为 medium / high"},
                status=400,
            )

        raw_summary = body.get("summary")
        if not isinstance(raw_summary, str) or not raw_summary.strip():
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_empty_summary",
                client_ip=client_ip,
                target_id=item_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "summary 不能为空"},
                status=400,
            )

        now = float(self.clock_fn())
        expires_at: float
        if "expires_at" in body and body.get("expires_at") is not None:
            raw_exp = body.get("expires_at")
            if (
                isinstance(raw_exp, bool)
                or not isinstance(raw_exp, (int, float))
                or not math.isfinite(float(raw_exp))
                or float(raw_exp) <= 0
            ):
                self.audit.record(
                    action=action,
                    status_code=400,
                    outcome="denied_invalid_expires_at",
                    client_ip=client_ip,
                    target_id=item_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "expires_at 必须为正有限数字时间戳"},
                    status=400,
                )
            expires_at = float(raw_exp)
        else:
            raw_ttl = body.get("ttl_sec", DEFAULT_TTL_SEC)
            if (
                isinstance(raw_ttl, bool)
                or not isinstance(raw_ttl, (int, float))
                or not math.isfinite(float(raw_ttl))
                or float(raw_ttl) <= 0
            ):
                self.audit.record(
                    action=action,
                    status_code=400,
                    outcome="denied_invalid_ttl",
                    client_ip=client_ip,
                    target_id=item_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "ttl_sec 必须为正有限数字"},
                    status=400,
                )
            ttl = max(MIN_TTL_SEC, min(MAX_TTL_SEC, float(raw_ttl)))
            expires_at = now + ttl
            if not math.isfinite(expires_at):
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "expires_at 计算结果非法"},
                    status=400,
                )

        raw_cid = str(body.get("cid") or "").strip()
        cid_val = raw_cid if studio_ipc.is_valid_cid(raw_cid) else ""
        title_clean = _sanitize_attention_text(body.get("title") or f"待审批：{kind}", max_bytes=MAX_TITLE_CHARS * 3)[
            :MAX_TITLE_CHARS
        ]
        summary_clean = _sanitize_attention_text(raw_summary, max_bytes=MAX_SUMMARY_BYTES)

        card = {
            "item_id": item_id,
            "kind": kind,
            "risk_level": risk_level,
            "status": "pending",
            "readonly_signal": False,
            "title": title_clean,
            "summary": summary_clean,
            "bot": _sanitize_slug(body.get("bot") or "", max_len=64),
            "cid": cid_val,
            "project_id": _sanitize_slug(body.get("project_id") or "", max_len=64),
            "room_id": _sanitize_slug(body.get("room_id") or "", max_len=32),
            "created_at": round(now, 3),
            "expires_at": round(expires_at, 3),
            "decided_at": None,
            "decided_by": None,
            "decision_note": "",
        }

        with self._approvals_lock():
            cp = self._card_path(item_id)
            if cp.is_file():
                self.audit.record(
                    action=action,
                    status_code=409,
                    outcome="conflict_exists",
                    client_ip=client_ip,
                    target_id=item_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "审批项 ID 已存在"},
                    status=409,
                )
            existing = self._list_cards_locked(now=now)
            remaining = self._prune_old_cards_locked(existing)
            if len(remaining) >= MAX_APPROVAL_CARDS:
                self.audit.record(
                    action=action,
                    status_code=429,
                    outcome="denied_card_limit",
                    client_ip=client_ip,
                    target_id=item_id,
                    sess=sess,
                )
                return web.json_response(
                    {
                        "ok": False,
                        "source": "studio_api",
                        "code": "approval_queue_full",
                        "error": f"待审批卡片数量已达上限（{MAX_APPROVAL_CARDS}），请先处理现有待审批项",
                    },
                    status=429,
                )
            _atomic_write_json_0600(cp, card)
            pending_count = sum(1 for c in remaining if c["status"] == "pending") + 1

        self.event_hub.publish(
            "attention_updated",
            {
                "action": "created",
                "item_id": item_id,
                "kind": kind,
                "status": "pending",
                "pending_count": pending_count,
            },
        )
        self.audit.record(
            action=action,
            status_code=201,
            outcome="ok",
            client_ip=client_ip,
            target_id=item_id,
            sess=sess,
        )
        return web.json_response({"ok": True, "item": card}, status=201)

    async def handle_decide_attention(self, request: web.Request) -> web.Response:
        action = "attention_decide"
        client_ip = self.auth_mgr.extract_client_ip(request)
        raw_id = str(request.match_info.get("item_id") or "").strip()

        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action=action, target_id=raw_id[:64]
        )
        if not ok_gate or not sess:
            return err_resp  # type: ignore[return-value]

        if not is_valid_attention_id(raw_id):
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_invalid_id",
                client_ip=client_ip,
                target_id=raw_id[:64],
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 item_id 格式"},
                status=400,
            )

        if raw_id == BROWSER_TAKEOVER_ITEM_ID:
            self.audit.record(
                action=action,
                status_code=409,
                outcome="denied_readonly_signal",
                client_ip=client_ip,
                target_id=raw_id,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "readonly_signal",
                    "error": "实时浏览器接管卡片为只读聚合信号，请前往实时浏览器面板操作",
                },
                status=409,
            )

        ok_b, body, sc_b, out_b, err_b = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES
        )
        if not ok_b or body is None:
            self.audit.record(
                action=action,
                status_code=sc_b,
                outcome=out_b,
                client_ip=client_ip,
                target_id=raw_id,
                sess=sess,
            )
            return web.json_response({"ok": False, "source": "studio_api", "error": err_b}, status=sc_b)

        bad_key = _find_forbidden_key_recursive(body, _FORBIDDEN_ATTENTION_KEYS)
        if bad_key is not None:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_forbidden_field",
                client_ip=client_ip,
                target_id=raw_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止传入受限字段: {bad_key}"},
                status=400,
            )

        unknown = set(body.keys()) - _ALLOWED_DECIDE_KEYS
        if unknown:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id=raw_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"不支持的字段: {sorted(unknown)[0]}"},
                status=400,
            )

        decision = str(body.get("decision") or "").strip().lower()
        if decision not in _VALID_DECISIONS:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_invalid_decision",
                client_ip=client_ip,
                target_id=raw_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "decision 必须为 approved 或 rejected"},
                status=400,
            )

        note_clean = _sanitize_attention_text(body.get("note") or "", max_bytes=MAX_NOTE_BYTES)

        # Atomic synchronous in-flight check BEFORE any await (eliminates async gather TOCTOU)
        if raw_id in self._deciding_ids:
            self.audit.record(
                action=action,
                status_code=409,
                outcome="conflict_in_flight",
                client_ip=client_ip,
                target_id=raw_id,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "already_decided",
                    "error": "该审批项正在处理或已完成决议（409 Conflict）",
                },
                status=409,
            )

        self._deciding_ids.add(raw_id)
        try:
            now = float(self.clock_fn())
            actor = str(sess.get("username") or f"uid:{sess['user_id']}")
            decided_card: dict[str, Any] | None = None
            conflict_code = ""
            conflict_msg = ""
            pending_count = 0

            # Cross-process atomic CAS under fcntl.flock(approvals.lock) with ZERO awaits inside
            with self._approvals_lock():
                cp = self._card_path(raw_id)
                raw_card = _read_json_dict(cp)
                if raw_card is None:
                    self.audit.record(
                        action=action,
                        status_code=404,
                        outcome="not_found",
                        client_ip=client_ip,
                        target_id=raw_id,
                        sess=sess,
                    )
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "审批项不存在"},
                        status=404,
                    )

                raw_card.setdefault("item_id", raw_id)
                card, expired_now = self._normalize_card(raw_card, now=now)
                if expired_now:
                    _atomic_write_json_0600(cp, card)
                    conflict_code = "expired"
                    conflict_msg = "该审批项已过期，无法执行决议（409 Conflict）"
                elif card["status"] == "expired":
                    conflict_code = "expired"
                    conflict_msg = "该审批项已过期，无法执行决议（409 Conflict）"
                elif card["status"] != "pending":
                    conflict_code = "already_decided"
                    conflict_msg = f"该审批项已完成决议（{card['status']}），禁止重复提交（409 Conflict）"
                else:
                    card["status"] = decision
                    card["decided_at"] = round(now, 3)
                    card["decided_by"] = _sanitize_slug(actor, max_len=64)
                    card["decision_note"] = note_clean
                    _atomic_write_json_0600(cp, card)
                    decided_card = card
                pending_count = sum(1 for c in self._list_cards_locked(now=now) if c["status"] == "pending")

            if conflict_code:
                outcome_name = "conflict_expired" if conflict_code == "expired" else "conflict_already_decided"
                if conflict_code == "expired":
                    self.event_hub.publish(
                        "attention_updated",
                        {
                            "action": "expired",
                            "item_id": raw_id,
                            "status": "expired",
                            "pending_count": pending_count,
                        },
                    )
                self.audit.record(
                    action=action,
                    status_code=409,
                    outcome=outcome_name,
                    client_ip=client_ip,
                    target_id=raw_id,
                    sess=sess,
                )
                return web.json_response(
                    {
                        "ok": False,
                        "source": "studio_api",
                        "code": conflict_code,
                        "error": conflict_msg,
                    },
                    status=409,
                )

            assert decided_card is not None
            notify_res = await self._notify_bridge_decision(
                card=decided_card,
                decision=decision,
                note=note_clean,
                sess=sess,
            )
            self.event_hub.publish(
                "attention_updated",
                {
                    "action": "decided",
                    "item_id": raw_id,
                    "kind": decided_card["kind"],
                    "status": decision,
                    "decision": decision,
                    "pending_count": pending_count,
                },
            )
            self.audit.record(
                action=action,
                status_code=200,
                outcome=f"ok_{decision}",
                client_ip=client_ip,
                target_id=raw_id,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": True,
                    "item": decided_card,
                    "decision": decision,
                    "notify": notify_res,
                }
            )
        finally:
            self._deciding_ids.discard(raw_id)
