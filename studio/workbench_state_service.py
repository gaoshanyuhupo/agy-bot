#!/usr/bin/env python3
"""AGY Studio — Server-Side Workbench Sidebar State Sync Service (C1 / C5 / C6).

Persists ONLY the 9 semantic sidebar fields of `WorkbenchSidebarState` to
`~/.config/agy-tg-bridge/studio_workbench_state.json` (0700 dir, 0600 file,
`O_NOFOLLOW` symlink refusal, `flock` atomic read-modify-write):

  1. customProjects       (list <= 64, strictly logical metadata {id, name, createdAt?}; ZERO host paths)
  2. projectRenames       (dict <= 128)
  3. hiddenProjectIds     (list <= 128)
  4. hiddenSessionCids    (list <= 500)
  5. pinnedSessionCids    (list <= 200)
  6. archivedSessionCids  (list <= 500)
  7. unreadSessionCids    (list <= 500)
  8. sessionRenames       (dict <= 500)
  9. showArchived         (bool)

Pure viewport layout fields (`paneCount`, `layoutMode`, `panes`) are explicitly
rejected here and remain per-device in browser `localStorage`.

Routes:
- `GET /api/workbench/state` — authenticated (`admin` & `readonly`), returns
  `{ok, version, updated_at, state, can_edit}`
- `PUT /api/workbench/state` — 4-layer write gate (`Origin` + `Sec-Fetch-Site` +
  `Content-Type: application/json` + cookie/live RBAC + `X-Studio-CSRF` + `admin`),
  128 KiB body cap, strict whitelist/quota/anti-prototype-pollution validation,
  optimistic concurrency (`expected_version` / `version` -> `409 Conflict` with
  latest server snapshot), audit log, and `workbench_state_updated` SSE broadcast.
"""

from __future__ import annotations

import fcntl
import json
import logging
import math
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any

from aiohttp import web

from .auth import StudioAuthManager, studio_auth_error
from .chat_service import (
    StudioAuditLogger,
    _extract_media_type,
    _read_bounded_json_body,
)
from .event_hub import StudioEventHub

log = logging.getLogger("agy-studio.workbench_state")

MAX_WORKBENCH_BODY_BYTES = 128 * 1024

MAX_CUSTOM_PROJECTS = 64
MAX_PROJECT_RENAMES = 128
MAX_HIDDEN_PROJECT_IDS = 128
MAX_HIDDEN_SESSION_CIDS = 500
MAX_PINNED_SESSION_CIDS = 200
MAX_ARCHIVED_SESSION_CIDS = 500
MAX_UNREAD_SESSION_CIDS = 500
MAX_SESSION_RENAMES = 500
MAX_PROJECT_NAME_LEN = 64
MAX_SESSION_TITLE_LEN = 120

_SHORT_SLUG_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_CUSTOM_PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SESSION_CID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_CTRL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

_FORBIDDEN_PROTO_KEYS = frozenset({"__proto__", "prototype", "constructor"})
_RESERVED_PROJECT_IDS = frozenset({"__tmp_projects__", "__unassigned__", "__other__"})
_FORBIDDEN_PATH_FIELDS = frozenset({
    "workdir",
    "path",
    "dir",
    "directory",
    "cwd",
    "root",
    "folderuri",
    "folder_uri",
    "file",
    "filepath",
    "file_path",
})
_ALLOWED_TOP_KEYS = frozenset({"state", "expected_version", "version"})
_ALLOWED_STATE_KEYS = frozenset({
    "customProjects",
    "projectRenames",
    "hiddenProjectIds",
    "hiddenSessionCids",
    "pinnedSessionCids",
    "archivedSessionCids",
    "unreadSessionCids",
    "sessionRenames",
    "showArchived",
})
_ALLOWED_CUSTOM_PROJECT_KEYS = frozenset({"id", "name", "createdAt"})


def empty_workbench_sidebar_state() -> dict[str, Any]:
    return {
        "customProjects": [],
        "projectRenames": {},
        "hiddenProjectIds": [],
        "hiddenSessionCids": [],
        "pinnedSessionCids": [],
        "archivedSessionCids": [],
        "unreadSessionCids": [],
        "sessionRenames": {},
        "showArchived": False,
    }


def _find_proto_key_recursive(obj: Any, *, depth: int = 0) -> str | None:
    if depth > 12:
        return "max_depth_exceeded"
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k)
            if ks in _FORBIDDEN_PROTO_KEYS or ks.lower() in _FORBIDDEN_PROTO_KEYS:
                return ks
            found = _find_proto_key_recursive(v, depth=depth + 1)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_proto_key_recursive(item, depth=depth + 1)
            if found is not None:
                return found
    return None


def _ensure_secure_parent_dir(file_path: Path) -> Path:
    parent = file_path.parent
    if parent.is_symlink():
        raise OSError("Refusing symlink workbench state directory")
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise OSError("Refusing symlink workbench state directory")
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass
    return parent


def _read_regular_json_no_symlink(path: Path, *, max_bytes: int = MAX_WORKBENCH_BODY_BYTES * 2) -> dict[str, Any] | None:
    try:
        if path.is_symlink() or path.parent.is_symlink() or not path.exists():
            return None
        flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
        fd = os.open(str(path), flags)
        try:
            chunks: list[bytes] = []
            total = 0
            while total <= max_bytes:
                chunk = os.read(fd, min(16384, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            raw = b"".join(chunks)
            if len(raw) > max_bytes:
                return None
            parsed = json.loads(raw.decode("utf-8"))
            return parsed if isinstance(parsed, dict) else None
        finally:
            os.close(fd)
    except Exception:
        return None


def validate_workbench_sidebar_state(raw: Any) -> tuple[bool, dict[str, Any], str]:
    """Strictly validate & canonicalize `WorkbenchSidebarState` (9 whitelisted fields)."""
    if not isinstance(raw, dict):
        return False, {}, "state 必须为 JSON 对象"

    bad_proto = _find_proto_key_recursive(raw)
    if bad_proto is not None:
        return False, {}, f"禁止传入非法原型键：{bad_proto}"

    for key in raw.keys():
        ks = str(key)
        if ks not in _ALLOWED_STATE_KEYS:
            return False, {}, f"工作台状态包含未允许的字段：{ks[:48]}"

    out = empty_workbench_sidebar_state()

    # 1. customProjects (logical metadata ONLY; strictly zero host path fields)
    if "customProjects" in raw:
        cp_raw = raw["customProjects"]
        if not isinstance(cp_raw, list):
            return False, {}, "customProjects 必须为数组"
        if len(cp_raw) > MAX_CUSTOM_PROJECTS:
            return False, {}, f"customProjects 数量超过上限（最多 {MAX_CUSTOM_PROJECTS} 项）"
        seen_ids: set[str] = set()
        clean_cp: list[dict[str, Any]] = []
        for idx, item in enumerate(cp_raw):
            if not isinstance(item, dict):
                return False, {}, f"customProjects[{idx}] 必须为对象"
            for ik in item.keys():
                iks = str(ik)
                if iks.lower() in _FORBIDDEN_PATH_FIELDS:
                    return False, {}, f"customProjects 禁止携带宿主机路径字段：{iks}"
                if iks not in _ALLOWED_CUSTOM_PROJECT_KEYS:
                    return False, {}, f"customProjects 包含未允许字段：{iks[:48]}"
            pid_raw = item.get("id")
            if not isinstance(pid_raw, str):
                return False, {}, f"customProjects[{idx}].id 必须为字符串"
            pid = pid_raw.strip()
            if (
                not pid
                or ".." in pid
                or "/" in pid
                or "\\" in pid
                or _CTRL_CHARS_RE.search(pid)
                or pid in _RESERVED_PROJECT_IDS
                or not _CUSTOM_PROJECT_ID_RE.fullmatch(pid)
            ):
                return False, {}, f"customProjects[{idx}].id 格式非法"
            if pid.lower() in seen_ids:
                return False, {}, f"customProjects 存在重复的项目 ID：{pid}"
            seen_ids.add(pid.lower())

            pname_raw = item.get("name")
            if not isinstance(pname_raw, str):
                return False, {}, f"customProjects[{idx}].name 必须为字符串"
            pname = pname_raw.strip()
            if not pname or len(pname) > MAX_PROJECT_NAME_LEN or _CTRL_CHARS_RE.search(pname):
                return False, {}, f"customProjects[{idx}].name 为空、超长或含非法控制字符"

            entry: dict[str, Any] = {"id": pid, "name": pname}
            if "createdAt" in item and item["createdAt"] is not None:
                cat = item["createdAt"]
                if isinstance(cat, bool) or not isinstance(cat, (int, float)) or not math.isfinite(cat) or cat <= 0:
                    return False, {}, f"customProjects[{idx}].createdAt 必须为正数时间戳"
                entry["createdAt"] = int(cat) if isinstance(cat, int) else float(cat)
            clean_cp.append(entry)
        out["customProjects"] = clean_cp

    # 2. projectRenames
    if "projectRenames" in raw:
        pr_raw = raw["projectRenames"]
        if not isinstance(pr_raw, dict):
            return False, {}, "projectRenames 必须为对象"
        if len(pr_raw) > MAX_PROJECT_RENAMES:
            return False, {}, f"projectRenames 条目超过上限（最多 {MAX_PROJECT_RENAMES} 项）"
        clean_pr: dict[str, str] = {}
        for k, v in pr_raw.items():
            if not isinstance(k, str) or not isinstance(v, str):
                return False, {}, "projectRenames 键值必须为字符串"
            ck = k.strip()
            cv = v.strip()
            if not ck or ".." in ck or not _SHORT_SLUG_RE.fullmatch(ck):
                return False, {}, "projectRenames 包含非法项目标识键"
            if not cv or len(cv) > MAX_PROJECT_NAME_LEN or _CTRL_CHARS_RE.search(cv):
                return False, {}, "projectRenames 值不能为空、超长或含控制字符"
            clean_pr[ck] = cv
        out["projectRenames"] = clean_pr

    # 3. hiddenProjectIds
    if "hiddenProjectIds" in raw:
        hp_raw = raw["hiddenProjectIds"]
        if not isinstance(hp_raw, list):
            return False, {}, "hiddenProjectIds 必须为数组"
        if len(hp_raw) > MAX_HIDDEN_PROJECT_IDS:
            return False, {}, f"hiddenProjectIds 数量超过上限（最多 {MAX_HIDDEN_PROJECT_IDS} 项）"
        clean_hp: list[str] = []
        seen_hp: set[str] = set()
        for item in hp_raw:
            if not isinstance(item, str):
                return False, {}, "hiddenProjectIds 元素必须为字符串"
            s = item.strip()
            if not s or ".." in s or not _SHORT_SLUG_RE.fullmatch(s):
                return False, {}, "hiddenProjectIds 包含非法项目标识"
            if s not in seen_hp:
                seen_hp.add(s)
                clean_hp.append(s)
        out["hiddenProjectIds"] = clean_hp

    # 4-7. Session CID arrays
    for field_name, cap in (
        ("hiddenSessionCids", MAX_HIDDEN_SESSION_CIDS),
        ("pinnedSessionCids", MAX_PINNED_SESSION_CIDS),
        ("archivedSessionCids", MAX_ARCHIVED_SESSION_CIDS),
        ("unreadSessionCids", MAX_UNREAD_SESSION_CIDS),
    ):
        if field_name not in raw:
            continue
        arr_raw = raw[field_name]
        if not isinstance(arr_raw, list):
            return False, {}, f"{field_name} 必须为数组"
        if len(arr_raw) > cap:
            return False, {}, f"{field_name} 数量超过上限（最多 {cap} 项）"
        clean_arr: list[str] = []
        seen_arr: set[str] = set()
        for item in arr_raw:
            if not isinstance(item, str):
                return False, {}, f"{field_name} 元素必须为字符串"
            s = item.strip()
            if not s or ".." in s or not _SESSION_CID_RE.fullmatch(s):
                return False, {}, f"{field_name} 包含非法会话 ID"
            if s not in seen_arr:
                seen_arr.add(s)
                clean_arr.append(s)
        out[field_name] = clean_arr

    # 8. sessionRenames
    if "sessionRenames" in raw:
        sr_raw = raw["sessionRenames"]
        if not isinstance(sr_raw, dict):
            return False, {}, "sessionRenames 必须为对象"
        if len(sr_raw) > MAX_SESSION_RENAMES:
            return False, {}, f"sessionRenames 条目超过上限（最多 {MAX_SESSION_RENAMES} 项）"
        clean_sr: dict[str, str] = {}
        for k, v in sr_raw.items():
            if not isinstance(k, str) or not isinstance(v, str):
                return False, {}, "sessionRenames 键值必须为字符串"
            ck = k.strip()
            cv = v.strip()
            if not ck or ".." in ck or not _SESSION_CID_RE.fullmatch(ck):
                return False, {}, "sessionRenames 包含非法会话 ID 键"
            if not cv or len(cv) > MAX_SESSION_TITLE_LEN or _CTRL_CHARS_RE.search(cv):
                return False, {}, "sessionRenames 标题不能为空、超长或含控制字符"
            clean_sr[ck] = cv
        out["sessionRenames"] = clean_sr

    # 9. showArchived
    if "showArchived" in raw:
        sa_raw = raw["showArchived"]
        if not isinstance(sa_raw, bool):
            return False, {}, "showArchived 必须为布尔值"
        out["showArchived"] = sa_raw

    return True, out, ""


def _sanitize_stored_doc(raw: dict[str, Any] | None) -> tuple[int, int | None, dict[str, Any]]:
    """Safely normalize an on-disk workbench state file without trusting malformed contents."""
    if not isinstance(raw, dict):
        return 0, None, empty_workbench_sidebar_state()
    raw_ver = raw.get("version", 0)
    version = raw_ver if isinstance(raw_ver, int) and not isinstance(raw_ver, bool) and raw_ver >= 0 else 0
    raw_upd = raw.get("updated_at")
    updated_at = raw_upd if isinstance(raw_upd, int) and not isinstance(raw_upd, bool) and raw_upd > 0 else None
    raw_state = raw.get("state")
    ok, clean_state, _ = validate_workbench_sidebar_state(raw_state if isinstance(raw_state, dict) else {})
    if not ok:
        clean_state = empty_workbench_sidebar_state()
    return version, updated_at, clean_state


class WorkbenchStateService:
    """Server-side sync & optimistic-concurrency persistence for WorkbenchSidebarState."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        audit: StudioAuditLogger,
        *,
        event_hub: StudioEventHub | None = None,
        state_path: Path | None = None,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.audit = audit
        self.event_hub = event_hub
        env_path = os.environ.get("AGY_STUDIO_WORKBENCH_STATE_FILE", "").strip()
        default_path = Path.home() / ".config" / "agy-tg-bridge" / "studio_workbench_state.json"
        self.state_path = Path(state_path) if state_path else Path(env_path or str(default_path))

    # ---------------------------------------------------------------- Storage
    def read_state_snapshot(self) -> tuple[int, int | None, dict[str, Any]]:
        doc = _read_regular_json_no_symlink(self.state_path)
        return _sanitize_stored_doc(doc)

    def _save_state_atomic(
        self,
        new_state: dict[str, Any],
        *,
        expected_version: int | None,
    ) -> tuple[bool, int, int | None, dict[str, Any]]:
        """Atomically persist `new_state` under `flock(LOCK_EX)` with optimistic concurrency check.

        Returns `(saved_ok, version, updated_at, canonical_state)`.
        When `saved_ok` is False, a version conflict occurred and the latest server snapshot is returned.
        """
        parent = _ensure_secure_parent_dir(self.state_path)
        if self.state_path.is_symlink():
            raise OSError("Refusing symlink studio_workbench_state.json")

        lock_path = parent / f".{self.state_path.name}.lock"
        if lock_path.is_symlink():
            raise OSError("Refusing symlink workbench state lock file")

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
                if self.state_path.is_symlink():
                    raise OSError("Refusing to overwrite symlink studio_workbench_state.json")

                cur_ver, cur_upd, cur_state = self.read_state_snapshot()
                if expected_version is not None and expected_version != cur_ver:
                    return False, cur_ver, cur_upd, cur_state

                next_ver = cur_ver + 1
                now_ts = int(time.time())
                doc = {
                    "version": next_ver,
                    "updated_at": now_ts,
                    "state": new_state,
                }
                serialized = (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
                fd, tmp_name = tempfile.mkstemp(
                    prefix=f".{self.state_path.name}.tmp.",
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
                os.replace(tmp_name, str(self.state_path))
                try:
                    os.chmod(self.state_path, 0o600)
                except OSError:
                    pass
                return True, next_ver, now_ts, new_state
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)

    # ---------------------------------------------------------------- 4-Layer Write Gate
    async def _enforce_write_gate(
        self,
        request: web.Request,
        *,
        action: str = "workbench.state.put",
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
                target_id="workbench_state",
            )
            return False, None, studio_auth_error(err_orig, status=403)

        # Gate 1b: Sec-Fetch-Site validation when sent by browser
        sfs = (request.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sfs and sfs not in ("same-origin", "none"):
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_sec_fetch_site",
                client_ip=client_ip,
                target_id="workbench_state",
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
                target_id="workbench_state",
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
                target_id="workbench_state",
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
                target_id="workbench_state",
                sess=sess,
            )
            return False, None, studio_auth_error(err_csrf, status=403)

        # Gate 4b: Live RBAC admin role (readonly MUST fail-closed 403)
        if sess.get("role") != "admin":
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_rbac",
                client_ip=client_ip,
                target_id="workbench_state",
                sess=sess,
            )
            return False, None, studio_auth_error(
                "只读权限（readonly）禁止修改工作台侧栏状态",
                status=403,
            )

        return True, sess, None

    # ---------------------------------------------------------------- HTTP Handlers
    async def handle_get_state(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)

        version, updated_at, state = self.read_state_snapshot()
        return web.json_response(
            {
                "ok": True,
                "version": version,
                "updated_at": updated_at,
                "state": state,
                "can_edit": sess.get("role") == "admin",
            }
        )

    async def handle_put_state(self, request: web.Request) -> web.Response:
        ok_gate, sess, err_resp = await self._enforce_write_gate(
            request, action="workbench.state.put"
        )
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request,
            max_bytes=MAX_WORKBENCH_BODY_BYTES,
            allow_empty=False,
        )
        if not ok_body or body is None:
            self.audit.record(
                action="workbench.state.put",
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                target_id="workbench_state",
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_proto = _find_proto_key_recursive(body)
        if bad_proto is not None:
            self.audit.record(
                action="workbench.state.put",
                status_code=400,
                outcome="denied_proto_key",
                client_ip=client_ip,
                target_id="workbench_state",
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止传入非法原型键：{bad_proto}"},
                status=400,
            )

        extra_top = set(body.keys()) - _ALLOWED_TOP_KEYS
        if extra_top:
            self.audit.record(
                action="workbench.state.put",
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                target_id="workbench_state",
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"存在未允许的顶层字段：{sorted(extra_top)[0]}"},
                status=400,
            )

        if "state" not in body:
            self.audit.record(
                action="workbench.state.put",
                status_code=400,
                outcome="denied_missing_state",
                client_ip=client_ip,
                target_id="workbench_state",
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "请求体必须包含 state 对象"},
                status=400,
            )

        expected_version: int | None = None
        has_exp = "expected_version" in body and body["expected_version"] is not None
        has_ver = "version" in body and body["version"] is not None
        if has_exp:
            ev = body["expected_version"]
            if isinstance(ev, bool) or not isinstance(ev, int) or ev < 0:
                self.audit.record(
                    action="workbench.state.put",
                    status_code=400,
                    outcome="denied_invalid_version",
                    client_ip=client_ip,
                    target_id="workbench_state",
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "expected_version 必须为非负整数"},
                    status=400,
                )
            expected_version = ev
        if has_ver:
            vv = body["version"]
            if isinstance(vv, bool) or not isinstance(vv, int) or vv < 0:
                self.audit.record(
                    action="workbench.state.put",
                    status_code=400,
                    outcome="denied_invalid_version",
                    client_ip=client_ip,
                    target_id="workbench_state",
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "version 必须为非负整数"},
                    status=400,
                )
            if expected_version is not None and expected_version != vv:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "expected_version 与 version 不一致"},
                    status=400,
                )
            expected_version = vv

        ok_state, clean_state, err_state = validate_workbench_sidebar_state(body.get("state"))
        if not ok_state:
            self.audit.record(
                action="workbench.state.put",
                status_code=400,
                outcome="denied_validation",
                client_ip=client_ip,
                target_id="workbench_state",
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": err_state},
                status=400,
            )

        try:
            saved_ok, final_ver, final_upd, final_state = self._save_state_atomic(
                clean_state,
                expected_version=expected_version,
            )
        except OSError as exc:
            log.warning("Failed to persist studio_workbench_state.json: %s", type(exc).__name__)
            self.audit.record(
                action="workbench.state.put",
                status_code=500,
                outcome="io_error",
                client_ip=client_ip,
                target_id="workbench_state",
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "写入工作台状态失败（权限或路径受限）"},
                status=500,
            )

        if not saved_ok:
            self.audit.record(
                action="workbench.state.put",
                status_code=409,
                outcome="conflict_version",
                client_ip=client_ip,
                target_id="workbench_state",
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "code": "version_conflict",
                    "error": "工作台状态已被其他终端更新，已返回服务端最新版本快照",
                    "version": final_ver,
                    "updated_at": final_upd,
                    "state": final_state,
                },
                status=409,
            )

        self.audit.record(
            action="workbench.state.put",
            status_code=200,
            outcome="allowed",
            client_ip=client_ip,
            target_id="workbench_state",
            sess=sess,
        )
        if self.event_hub is not None:
            self.event_hub.publish(
                "workbench_state_updated",
                {
                    "version": final_ver,
                    "updated_at": final_upd,
                    "source": "studio",
                },
            )

        return web.json_response(
            {
                "ok": True,
                "version": final_ver,
                "updated_at": final_upd,
                "state": final_state,
                "can_edit": True,
            }
        )
