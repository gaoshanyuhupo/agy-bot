#!/usr/bin/env python3
"""AGY Studio Phase B M1 — Sandboxed Workspace Files, Git Diff & Single-Writer Undo/Redo Proxy.

Security Invariants (`PB-C1`, `PB-C2`):
- Strictly project-whitelist scoped (`data_sources.resolve_allowed_project(project_id)`).
  Client-supplied `workdir` / `root` / `cwd` are unconditionally rejected (400), and
  `GET /api/projects` returns ONLY `{id, name, is_git}` (zero host paths).
- Component-by-component symlink (including dangling symlink) rejection +
  `target.resolve().is_relative_to(root.resolve())` containment + `O_NOFOLLOW` open.
- Strict sensitive-file blacklist hidden from directory trees and blocked (403) on
  file preview and Git diff.
- `git` invocations strictly use `asyncio.create_subprocess_exec` (`shell=False`,
  `GIT_TERMINAL_PROMPT=0`, timeout <= 5s) with `--no-ext-diff`, `--no-textconv`,
  `--no-color`, `-- <rel_path>`.
- Studio NEVER writes workspace files or `acb_undo` directly; all Undo/Redo list and
  apply operations proxy over authenticated Bridge UDS IPC with the four-layer write
  gate and `0600` append-only JSONL audit logging.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any
import urllib.parse

import aiohttp
from aiohttp import web

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BRIDGE_SRC_DIR = _REPO_ROOT / "bridge"
if str(_BRIDGE_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_BRIDGE_SRC_DIR))

import studio_ipc  # noqa: E402

from .auth import StudioAuthManager, studio_auth_error  # noqa: E402
from .chat_service import (  # noqa: E402
    MAX_PROMPT_BODY_BYTES,
    StudioAuditLogger,
    _extract_media_type,
    _read_bounded_json_body,
)
from .control_plane import _find_forbidden_key_recursive  # noqa: E402
from .data_sources import (  # noqa: E402
    StudioDataSources,
    _SENSITIVE_HOST_PATH_RE,
    _sanitize_slug,
    redact_secrets_only,
    truncate_utf8_bytes,
)
from .event_hub import StudioEventHub  # noqa: E402

log = logging.getLogger("agy-studio.workspace_files")

MAX_TREE_ENTRIES = 400
MAX_TREE_DEPTH = 2
MAX_FILE_READ_BYTES = 256 * 1024
MAX_CONTENT_RESPONSE_BYTES = 64 * 1024
MAX_CONTENT_LINES = 1500
MAX_DIFF_BYTES = 256 * 1024
GIT_TIMEOUT_SEC = 5.0

_HEAVY_SKIP_DIRS = frozenset({
    "node_modules",
    "__pycache__",
    "dist",
    "venv",
    ".venv",
    ".worktrees",
    ".rollback",
    ".git",
})

_SENSITIVE_EXACT_NAMES = frozenset({
    ".env",
    ".envrc",
    "users.json",
    "auth_users.json",
    "sessions.json",
    ".bao_credentials.json",
    "auth.json",
    "credentials.json",
    "audit.jsonl",
    "mcp_config.json",
})

_SENSITIVE_SUFFIXES = (
    ".token",
    ".secret",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".db",
    ".db-wal",
    ".db-shm",
    ".db-journal",
    ".sqlite",
    ".sqlite3",
    ".sock",
)

_SENSITIVE_SUBSTRINGS = (
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".sqlite",
)

_FORBIDDEN_QUERY_PARAMS = frozenset({"workdir", "root", "cwd", "dir_abs", "abs_path"})
_ALLOWED_DIFF_SCOPES = frozenset({"all", "staged", "unstaged"})

_FORBIDDEN_UNDO_KEYS = frozenset({
    "workdir",
    "changes",
    "sha1",
    "pre_sha1",
    "post_sha1",
    "role",
    "ipc_sock",
    "path",
    "files",
})
_ALLOWED_UNDO_MUTATION_KEYS = frozenset({"entry_id", "bot", "cid", "project_id", "force"})

_DIFF_HEADER_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")
_SYMLINK_DIFF_MODE_LINES = frozenset({
    "new file mode 120000",
    "old mode 120000",
    "new mode 120000",
    "deleted file mode 120000",
})

_EXT_LANG_MAP = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".js": "javascript",
    ".jsx": "jsx",
    ".json": "json",
    ".md": "markdown",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".toml": "toml",
    ".sh": "bash",
    ".css": "css",
    ".html": "html",
    ".sql": "sql",
    ".go": "go",
    ".rs": "rust",
    ".txt": "text",
}


def redact_workspace_text(raw: Any) -> str:
    """Redact credentials, Vault paths, and sensitive host paths from workspace output."""
    text = redact_secrets_only(raw)
    if text:
        text = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", text)
    return text


def is_sensitive_name(name: str) -> bool:
    """Return True if a single path component is a protected/sensitive filename or directory."""
    low = str(name or "").strip().lower()
    if not low:
        return False
    if low == ".git" or low == ".env" or low.startswith(".env."):
        return True
    if low in _SENSITIVE_EXACT_NAMES:
        return True
    if any(low.endswith(suf) for suf in _SENSITIVE_SUFFIXES):
        return True
    if any(sub in low for sub in _SENSITIVE_SUBSTRINGS):
        return True
    return False


def is_sensitive_rel_path(rel_path: str) -> bool:
    """Return True if any segment of a relative POSIX path matches the sensitive blacklist."""
    norm = str(rel_path or "").replace("\\", "/").strip("/")
    if not norm:
        return False
    for part in norm.split("/"):
        if is_sensitive_name(part):
            return True
    return False


def _resolve_sandboxed_path(
    root: Path,
    raw_rel: str,
    *,
    allow_root: bool = False,
) -> tuple[bool, Path | None, str, int, str]:
    """Validate and resolve `raw_rel` strictly inside `root` with zero symlink traversal."""
    try:
        root_real = root.resolve(strict=True)
    except OSError:
        return False, None, "", 404, "项目工作区目录不可访问"
    if not root_real.is_dir():
        return False, None, "", 404, "项目工作区目录不存在"

    rel_s = str(raw_rel or "").strip()
    if rel_s in ("", "."):
        if allow_root:
            return True, root_real, "", 200, ""
        return False, None, "", 400, "文件路径不能为空"

    if "\x00" in rel_s or "\\" in rel_s or os.path.isabs(rel_s):
        return False, None, "", 400, "非法路径格式"
    if rel_s.startswith(("/", "-")):
        return False, None, "", 400, "路径不允许以 / 或 - 开头"

    raw_trimmed = rel_s.rstrip("/") if allow_root else rel_s
    parts = raw_trimmed.split("/")
    if not parts:
        return False, None, "", 400, "非法路径格式"
    if parts[0].startswith("-") or ":" in parts[0]:
        return False, None, "", 400, "非法路径前缀"

    for part in parts:
        if not part or part in (".", ".."):
            return False, None, "", 400, "禁止路径遍历或空路径段"
        if any(ord(c) < 32 or ord(c) == 127 for c in part):
            return False, None, "", 400, "路径包含非法控制字符"

    # Check sensitive blacklist on every path component BEFORE touching filesystem
    norm_rel = "/".join(parts)
    if is_sensitive_rel_path(norm_rel):
        return False, None, "", 403, "禁止访问敏感文件或受保护目录"

    # Component-by-component symlink check (catches both live and dangling symlinks)
    cur = root_real
    for part in parts:
        cur = cur / part
        if os.path.islink(cur):
            return False, None, "", 403, "禁止访问符号链接路径"

    try:
        target_real = cur.resolve(strict=False)
    except OSError:
        return False, None, "", 400, "无法解析目标路径"

    if not target_real.is_relative_to(root_real):
        return False, None, "", 403, "路径越界，已拒绝访问"
    if not allow_root and target_real == root_real:
        return False, None, "", 400, "目标路径不能为项目根目录"

    return True, target_real, norm_rel, 200, ""


def _filter_sensitive_unified_diff(raw_diff: str) -> str:
    """Drop any `diff --git a/... b/...` section touching a sensitive, unsafe, or symlink (mode 120000) path."""
    if not raw_diff:
        return ""
    lines = raw_diff.splitlines(keepends=True)
    out_sections: list[str] = []
    cur_buf: list[str] = []
    cur_blocked = False
    in_header = False

    def _flush() -> None:
        if cur_buf and not cur_blocked:
            out_sections.append("".join(cur_buf))

    for ln in lines:
        if ln.startswith("diff --git "):
            _flush()
            cur_buf = [ln]
            in_header = True
            m = _DIFF_HEADER_RE.match(ln.rstrip("\r\n"))
            if not m:
                cur_blocked = True
            else:
                a_p, b_p = m.group(1), m.group(2)
                cur_blocked = (
                    is_sensitive_rel_path(a_p)
                    or is_sensitive_rel_path(b_p)
                    or ".." in a_p.split("/")
                    or ".." in b_p.split("/")
                    or a_p.startswith("/")
                    or b_p.startswith("/")
                )
        else:
            if in_header:
                if ln.startswith("@@ "):
                    in_header = False
                elif not cur_blocked:
                    stripped = ln.rstrip("\r\n")
                    if stripped in _SYMLINK_DIFF_MODE_LINES or (
                        stripped.startswith("index ") and stripped.endswith(" 120000")
                    ):
                        cur_blocked = True
            cur_buf.append(ln)
    _flush()
    return "".join(out_sections)


class StudioWorkspaceFilesService:
    """Read-only sandboxed workspace explorer + Git diff + single-writer Undo/Redo IPC proxy."""

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

    # ------------------------------------------------------------------ Shared IPC & Gate Helpers
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
        extra_headers: dict[str, str] | None = None,
        timeout_sec: float = 10.0,
    ) -> tuple[int, dict[str, Any]]:
        connector = aiohttp.UnixConnector(path=str(sock_path))
        headers = {"X-Bridge-IPC-Token": token}
        if extra_headers:
            headers.update(extra_headers)
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
            log.warning("WorkspaceFiles Bridge IPC %s %s failed: %s", method, path, type(exc).__name__)
            return 502, {"ok": False, "source": "upstream", "error": "Bridge IPC 服务暂不可达"}

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

        # Gate 2: Non-simple Content-Type (`application/json` -> else 415)
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

        # Gate 4b: Live RBAC admin requirement
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

    def _reject_forbidden_query_params(self, request: web.Request) -> web.Response | None:
        for k in request.query.keys():
            if k.strip().lower() in _FORBIDDEN_QUERY_PARAMS:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"禁止传入受限查询参数: {k}"},
                    status=400,
                )
        return None

    def _resolve_project_root(self, request: web.Request) -> tuple[dict[str, str] | None, Path | None, web.Response | None]:
        forb = self._reject_forbidden_query_params(request)
        if forb is not None:
            return None, None, forb
        raw_pid = (request.query.get("project_id") or request.query.get("project") or "").strip()
        if not raw_pid:
            return None, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": "缺少 project_id 参数"},
                status=400,
            )
        if "\x00" in raw_pid or "/" in raw_pid or "\\" in raw_pid or ".." in raw_pid or raw_pid.startswith("-"):
            return None, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的 project_id 参数"},
                status=400,
            )
        proj = self.data_sources.resolve_allowed_project(raw_pid)
        if not proj or not proj.get("workdir"):
            return None, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": "未找到对应的白名单项目"},
                status=404,
            )
        root = Path(proj["workdir"])
        if not root.is_dir():
            return None, None, web.json_response(
                {"ok": False, "source": "studio_api", "error": "项目工作区目录不可访问"},
                status=404,
            )
        return proj, root, None

    # ------------------------------------------------------------------ GET /api/projects
    async def handle_get_projects(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        projects_out: list[dict[str, Any]] = []
        for p in self.data_sources.get_allowed_projects():
            wdir = p.get("workdir") or ""
            is_git = bool(wdir and (Path(wdir) / ".git").exists())
            # Strictly `{id, name, is_git}` ONLY — NEVER return `workdir`
            projects_out.append({
                "id": p["id"],
                "name": p["name"],
                "is_git": is_git,
            })
        return web.json_response({"ok": True, "projects": projects_out})

    # ------------------------------------------------------------------ GET /api/files/tree
    async def handle_get_tree(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        proj, root, err_resp = self._resolve_project_root(request)
        if err_resp is not None or proj is None or root is None:
            assert err_resp is not None
            return err_resp

        raw_dir = request.query.get("dir", "")
        ok_p, target_dir, norm_dir, sc_p, err_p = _resolve_sandboxed_path(
            root, raw_dir, allow_root=True
        )
        if not ok_p or target_dir is None:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": err_p},
                status=sc_p,
            )
        if not target_dir.is_dir():
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "目标目录不存在"},
                status=404,
            )

        try:
            depth = int(request.query.get("depth", "2"))
        except ValueError:
            depth = 2
        depth = max(1, min(MAX_TREE_DEPTH, depth))

        root_real = root.resolve()
        counter = [0]
        truncated = [False]

        def _scan_dir(cur_dir: Path, cur_rel: str, rem_depth: int) -> list[dict[str, Any]]:
            nodes: list[dict[str, Any]] = []
            try:
                raw_entries = list(os.scandir(cur_dir))
            except OSError:
                return nodes

            # Sort dirs first, then files alphabetically
            def _sort_key(e: os.DirEntry[str]) -> tuple[int, str]:
                try:
                    is_d = e.is_dir(follow_symlinks=False)
                except OSError:
                    is_d = False
                return (0 if is_d else 1, e.name.lower())

            raw_entries.sort(key=_sort_key)

            for ent in raw_entries:
                if counter[0] >= MAX_TREE_ENTRIES:
                    truncated[0] = True
                    break
                name = ent.name
                try:
                    if ent.is_symlink():
                        continue
                    is_dir = ent.is_dir(follow_symlinks=False)
                    is_file = ent.is_file(follow_symlinks=False)
                except OSError:
                    continue
                if not is_dir and not is_file:
                    continue
                if is_dir and name in _HEAVY_SKIP_DIRS:
                    continue
                child_rel = f"{cur_rel}/{name}" if cur_rel else name
                if is_sensitive_name(name) or is_sensitive_rel_path(child_rel):
                    continue
                child_path = Path(ent.path)
                try:
                    if not child_path.resolve().is_relative_to(root_real):
                        continue
                except OSError:
                    continue

                counter[0] += 1
                if is_dir:
                    node: dict[str, Any] = {
                        "name": redact_workspace_text(name),
                        "path": redact_workspace_text(child_rel),
                        "type": "dir",
                        "size": None,
                    }
                    if rem_depth > 1:
                        children = _scan_dir(child_path, child_rel, rem_depth - 1)
                        node["children"] = children
                        node["has_children"] = len(children) > 0
                    else:
                        # Lightweight probe for whether directory has visible non-sensitive entries
                        has_vis = False
                        try:
                            for sub in os.scandir(child_path):
                                if sub.is_symlink():
                                    continue
                                if sub.is_dir(follow_symlinks=False) and sub.name in _HEAVY_SKIP_DIRS:
                                    continue
                                if is_sensitive_name(sub.name):
                                    continue
                                has_vis = True
                                break
                        except OSError:
                            pass
                        node["has_children"] = has_vis
                    nodes.append(node)
                else:
                    try:
                        fsize = int(ent.stat(follow_symlinks=False).st_size)
                    except OSError:
                        fsize = 0
                    nodes.append({
                        "name": redact_workspace_text(name),
                        "path": redact_workspace_text(child_rel),
                        "type": "file",
                        "size": fsize,
                    })
            return nodes

        entries = _scan_dir(target_dir, norm_dir, depth)
        return web.json_response({
            "ok": True,
            "project_id": proj["id"],
            "dir": redact_workspace_text(norm_dir),
            "truncated": truncated[0],
            "total": counter[0],
            "entries": entries,
        })

    # ------------------------------------------------------------------ GET /api/files/content
    async def handle_get_content(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        proj, root, err_resp = self._resolve_project_root(request)
        if err_resp is not None or proj is None or root is None:
            assert err_resp is not None
            return err_resp

        raw_path = request.query.get("path", "")
        ok_p, target_file, norm_rel, sc_p, err_p = _resolve_sandboxed_path(
            root, raw_path, allow_root=False
        )
        if not ok_p or target_file is None:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": err_p},
                status=sc_p,
            )

        if os.path.islink(target_file):
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "禁止访问符号链接路径"},
                status=403,
            )
        if not target_file.exists():
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "文件不存在"},
                status=404,
            )
        if not target_file.is_file():
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "目标路径不是普通文件"},
                status=400,
            )

        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(str(target_file), flags)
        except OSError:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "禁止访问符号链接或不可读文件"},
                status=403,
            )

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                os.close(fd)
                fd = -1
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "目标路径不是普通文件"},
                    status=400,
                )
            file_size = int(st.st_size)
            fh = os.fdopen(fd, "rb")
            fd = -1
            with fh:
                raw_bytes = fh.read(MAX_FILE_READ_BYTES + 1)
        except OSError:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "读取文件内容失败"},
                status=500,
            )

        truncated = len(raw_bytes) > MAX_FILE_READ_BYTES
        if truncated:
            raw_bytes = raw_bytes[:MAX_FILE_READ_BYTES]

        # Detect binary via NUL byte presence -> return zero raw bytes
        if b"\x00" in raw_bytes:
            return web.json_response({
                "ok": True,
                "project_id": proj["id"],
                "path": redact_workspace_text(norm_rel),
                "is_binary": True,
                "size": file_size,
                "language": "binary",
                "content": "",
                "lines": 0,
                "truncated": False,
            })

        decoded = raw_bytes.decode("utf-8", errors="replace")
        all_lines = decoded.splitlines()
        if len(all_lines) > MAX_CONTENT_LINES:
            decoded = "\n".join(all_lines[:MAX_CONTENT_LINES])
            truncated = True

        redacted = redact_workspace_text(decoded)
        bounded_text, byte_trunc = truncate_utf8_bytes(redacted, MAX_CONTENT_RESPONSE_BYTES)
        if byte_trunc:
            truncated = True

        line_count = len(bounded_text.splitlines()) if bounded_text else 0
        ext = Path(norm_rel).suffix.lower()
        return web.json_response({
            "ok": True,
            "project_id": proj["id"],
            "path": redact_workspace_text(norm_rel),
            "is_binary": False,
            "size": file_size,
            "language": _EXT_LANG_MAP.get(ext, "text"),
            "content": bounded_text,
            "lines": line_count,
            "truncated": truncated,
        })

    # ------------------------------------------------------------------ GET /api/files/diff
    @staticmethod
    async def _run_git(root: Path, args: list[str], *, timeout: float = GIT_TIMEOUT_SEC) -> tuple[int, str, str]:
        safe_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_PAGER": "cat",
            "LC_ALL": "C",
        }
        proc = await asyncio.create_subprocess_exec(
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.quotePath=false",
            "-C",
            str(root),
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=safe_env,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:
                pass
            return 124, "", "git command timed out"
        return (
            int(proc.returncode or 0),
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
        )

    async def handle_get_diff(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        proj, root, err_resp = self._resolve_project_root(request)
        if err_resp is not None or proj is None or root is None:
            assert err_resp is not None
            return err_resp

        # Reject arbitrary `ref` arguments (especially option injection like `-p` / `--output=...`)
        raw_ref = request.query.get("ref")
        if raw_ref is not None and raw_ref.strip() != "":
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "不支持自定义 ref 参数，请使用 scope=all|staged|unstaged"},
                status=400,
            )

        scope = (request.query.get("scope") or "all").strip().lower()
        if scope not in _ALLOWED_DIFF_SCOPES:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "scope 仅允许 all / staged / unstaged"},
                status=400,
            )

        raw_path = (request.query.get("path") or "").strip()
        norm_rel = ""
        if raw_path:
            ok_p, _target, norm_rel, sc_p, err_p = _resolve_sandboxed_path(
                root, raw_path, allow_root=False
            )
            if not ok_p:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": err_p},
                    status=sc_p,
                )

        if not (root / ".git").exists():
            return web.json_response({
                "ok": True,
                "project_id": proj["id"],
                "is_git": False,
                "scope": scope,
                "path": redact_workspace_text(norm_rel),
                "files": [],
                "diff": "",
                "truncated": False,
            })

        # 1. Changed file list via `git status --porcelain=v1 -uall --`
        st_args = ["status", "--porcelain=v1", "-uall", "--"]
        if norm_rel:
            st_args.append(norm_rel)
        rc_st, out_st, _err_st = await self._run_git(root, st_args)
        changed_files: list[dict[str, str]] = []
        if rc_st == 0 and out_st:
            for raw_ln in out_st.splitlines():
                if len(raw_ln) < 4:
                    continue
                xy = raw_ln[:2]
                fp_part = raw_ln[3:].strip()
                if " -> " in fp_part:
                    fp_part = fp_part.split(" -> ", 1)[1].strip()
                fp_part = fp_part.strip('"')
                if not fp_part or is_sensitive_rel_path(fp_part):
                    continue
                if os.path.islink(root / fp_part):
                    continue
                # Scope filter on file listing
                staged_flag = xy[0] not in (" ", "?")
                unstaged_flag = xy[1] != " "
                if scope == "staged" and not staged_flag:
                    continue
                if scope == "unstaged" and not unstaged_flag:
                    continue
                changed_files.append({
                    "path": redact_workspace_text(fp_part),
                    "status": xy.strip() or "M",
                    "staged": "true" if staged_flag else "false",
                })
                if len(changed_files) >= 300:
                    break

        # 2. Unified diff via mandatory safe git flags
        base_diff_args = ["diff", "--no-ext-diff", "--no-textconv", "--no-color"]
        raw_diff = ""
        if scope == "staged":
            cmd = [*base_diff_args, "--cached", "--"]
            if norm_rel:
                cmd.append(norm_rel)
            rc_d, out_d, err_d = await self._run_git(root, cmd)
            if rc_d == 124:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "Git Diff 执行超时"},
                    status=504,
                )
            if rc_d not in (0, 1):
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"Git Diff 执行失败: {redact_workspace_text(err_d)[:160]}"},
                    status=500,
                )
            raw_diff = out_d
        elif scope == "unstaged":
            cmd = [*base_diff_args, "--"]
            if norm_rel:
                cmd.append(norm_rel)
            rc_d, out_d, err_d = await self._run_git(root, cmd)
            if rc_d == 124:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "Git Diff 执行超时"},
                    status=504,
                )
            if rc_d not in (0, 1):
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": f"Git Diff 执行失败: {redact_workspace_text(err_d)[:160]}"},
                    status=500,
                )
            raw_diff = out_d
        else:
            rc_head, _, _ = await self._run_git(root, ["rev-parse", "--verify", "HEAD"])
            if rc_head == 0:
                cmd = [*base_diff_args, "HEAD", "--"]
                if norm_rel:
                    cmd.append(norm_rel)
                rc_d, out_d, err_d = await self._run_git(root, cmd)
                if rc_d == 124:
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": "Git Diff 执行超时"},
                        status=504,
                    )
                if rc_d not in (0, 1):
                    return web.json_response(
                        {"ok": False, "source": "studio_api", "error": f"Git Diff 执行失败: {redact_workspace_text(err_d)[:160]}"},
                        status=500,
                    )
                raw_diff = out_d
            else:
                # Repository has no HEAD commit yet: combine staged + unstaged
                cmd_s = [*base_diff_args, "--cached", "--", *([norm_rel] if norm_rel else [])]
                cmd_u = [*base_diff_args, "--", *([norm_rel] if norm_rel else [])]
                _rc1, out1, _ = await self._run_git(root, cmd_s)
                _rc2, out2, _ = await self._run_git(root, cmd_u)
                raw_diff = "\n".join(part for part in (out1.strip("\n"), out2.strip("\n")) if part)

        filtered_diff = _filter_sensitive_unified_diff(raw_diff)
        redacted_diff = redact_workspace_text(filtered_diff)
        bounded_diff, truncated = truncate_utf8_bytes(redacted_diff, MAX_DIFF_BYTES)

        return web.json_response({
            "ok": True,
            "project_id": proj["id"],
            "is_git": True,
            "scope": scope,
            "path": redact_workspace_text(norm_rel),
            "files": changed_files,
            "diff": bounded_diff,
            "truncated": truncated,
        })

    # ------------------------------------------------------------------ GET /api/undo/checkpoints
    async def handle_get_undo_checkpoints(self, request: web.Request) -> web.Response:
        ok, sess, err, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok or not sess:
            return studio_auth_error(err, status=status_code)
        if sess.get("role") != "admin":
            return studio_auth_error("只读权限（readonly）不可访问撤销检查点", status=403)
        forb = self._reject_forbidden_query_params(request)
        if forb is not None:
            return forb

        cid = (request.query.get("cid") or "").strip()
        if cid and not studio_ipc.is_valid_cid(cid):
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "无效的会话 ID 格式"},
                status=400,
            )
        pid = (request.query.get("project_id") or "").strip()
        if pid:
            proj = self.data_sources.resolve_allowed_project(pid)
            if not proj:
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "未找到对应的白名单项目"},
                    status=404,
                )
            pid = proj["id"]

        req_bot = (request.query.get("bot") or "").strip() or None
        ep = self._resolve_ipc_endpoint(req_bot)
        if ep is None:
            return web.json_response({
                "ok": True,
                "ipc_online": False,
                "bot": _sanitize_slug(req_bot or "", max_len=64),
                "undo_stack": [],
                "redo_stack": [],
            })

        bot_h, sock_p, tok = ep
        q_params: dict[str, str] = {}
        if cid:
            q_params["cid"] = cid
        if pid:
            q_params["project_id"] = pid
        qs = f"?{urllib.parse.urlencode(q_params)}" if q_params else ""

        sc, data = await self._ipc_request_json(
            sock_path=sock_p,
            token=tok,
            method="GET",
            path=f"/ipc/undo/list{qs}",
            extra_headers={"X-Bridge-User-Id": str(sess["user_id"])},
        )
        if sc >= 400 or not data.get("ok"):
            return web.json_response(
                {
                    "ok": False,
                    "source": "upstream",
                    "error": redact_workspace_text(data.get("error") or "获取撤销检查点失败"),
                },
                status=sc,
            )

        def _clean_stack(items: Any) -> list[dict[str, Any]]:
            out: list[dict[str, Any]] = []
            if not isinstance(items, list):
                return out
            for it in items[:30]:
                if not isinstance(it, dict):
                    continue
                changes = []
                for ch in (it.get("changes") or [])[:50]:
                    if isinstance(ch, dict):
                        changes.append({
                            "path": redact_workspace_text(ch.get("path") or ""),
                            "action": _sanitize_slug(ch.get("action") or "modified", max_len=24),
                        })
                # Explicitly omit `workdir`
                out.append({
                    "entry_id": _sanitize_slug(it.get("entry_id") or "", max_len=64),
                    "ts": int(it.get("ts") or 0),
                    "cid": str(it.get("cid") or ""),
                    "project_id": _sanitize_slug(it.get("project_id") or "", max_len=64),
                    "prompt": redact_workspace_text(it.get("prompt") or "")[:120],
                    "truncated": bool(it.get("truncated", False)),
                    "changes_count": int(it.get("changes_count") or len(changes)),
                    "changes": changes,
                    "is_top": bool(it.get("is_top", False)),
                })
            return out

        return web.json_response({
            "ok": True,
            "ipc_online": True,
            "bot": bot_h,
            "undo_stack": _clean_stack(data.get("undo_stack")),
            "redo_stack": _clean_stack(data.get("redo_stack")),
        })

    # ------------------------------------------------------------------ POST /api/undo/apply & /api/undo/redo
    async def _handle_undo_mutation(self, request: web.Request, *, reverse: bool) -> web.Response:
        action_name = "undo.redo" if reverse else "undo.apply"
        ipc_path = "/ipc/undo/redo" if reverse else "/ipc/undo/apply"

        ok_gate, sess, err_resp = await self._enforce_write_gate(request, action=action_name)
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        client_ip = self.auth_mgr.extract_client_ip(request)
        ok_body, body, body_sc, body_outcome, body_err = await _read_bounded_json_body(
            request, max_bytes=MAX_PROMPT_BODY_BYTES, allow_empty=False
        )
        if not ok_body or body is None:
            self.audit.record(
                action=action_name,
                status_code=body_sc,
                outcome=body_outcome,
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": body_err},
                status=body_sc,
            )

        bad_forb = _find_forbidden_key_recursive(body, _FORBIDDEN_UNDO_KEYS)
        if bad_forb is not None:
            self.audit.record(
                action=action_name,
                status_code=400,
                outcome=f"denied_forbidden_field:{bad_forb}",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": f"禁止客户端传入受限字段: {bad_forb}"},
                status=400,
            )

        extra_keys = set(body.keys()) - _ALLOWED_UNDO_MUTATION_KEYS
        if extra_keys:
            self.audit.record(
                action=action_name,
                status_code=400,
                outcome="denied_unknown_field",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "存在未允许的请求字段"},
                status=400,
            )

        entry_id = str(body.get("entry_id") or "").strip()
        if not studio_ipc.is_valid_undo_entry_id(entry_id):
            self.audit.record(
                action=action_name,
                status_code=400,
                outcome="denied_invalid_entry_id",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "无效的检查点 entry_id"},
                status=400,
            )

        raw_cid = body.get("cid")
        cid_val: str | None = None
        if raw_cid is not None and str(raw_cid).strip() != "":
            cid_s = str(raw_cid).strip()
            if not studio_ipc.is_valid_cid(cid_s):
                self.audit.record(
                    action=action_name,
                    status_code=400,
                    outcome="denied_invalid_cid",
                    client_ip=client_ip,
                    target_id=entry_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "无效的会话 ID 格式"},
                    status=400,
                )
            cid_val = cid_s

        raw_pid = body.get("project_id")
        pid_val: str | None = None
        if raw_pid is not None and str(raw_pid).strip() != "":
            proj = self.data_sources.resolve_allowed_project(str(raw_pid).strip())
            if not proj:
                self.audit.record(
                    action=action_name,
                    status_code=404,
                    outcome="denied_unknown_project",
                    client_ip=client_ip,
                    target_id=entry_id,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "未找到对应的白名单项目"},
                    status=404,
                )
            pid_val = proj["id"]

        raw_force = body.get("force", False)
        if not isinstance(raw_force, bool):
            self.audit.record(
                action=action_name,
                status_code=400,
                outcome="denied_invalid_force",
                client_ip=client_ip,
                target_id=entry_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "force 必须为布尔值"},
                status=400,
            )

        req_bot = str(body.get("bot") or "").strip() or None
        ep = self._resolve_ipc_endpoint(req_bot)
        if ep is None:
            self.audit.record(
                action=action_name,
                status_code=503,
                outcome="error_ipc_offline",
                client_ip=client_ip,
                target_id=entry_id,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "upstream", "error": "目标 Bot Bridge IPC 离线，无法执行撤销/重做"},
                status=503,
            )

        bot_h, sock_p, tok = ep
        ipc_payload = {
            "user_id": int(sess["user_id"]),
            "actor_username": str(sess.get("username") or "")[:64],
            "entry_id": entry_id,
            "cid": cid_val,
            "project_id": pid_val,
            "force": raw_force,
        }
        sc, data = await self._ipc_request_json(
            sock_path=sock_p,
            token=tok,
            method="POST",
            path=ipc_path,
            payload=ipc_payload,
        )

        if sc >= 400 or not data.get("ok"):
            err_code = _sanitize_slug(data.get("code") or "", max_len=32)
            outcome = f"denied_{err_code}" if err_code else ("conflict" if sc == 409 else "error_ipc")
            self.audit.record(
                action=action_name,
                status_code=sc,
                outcome=outcome,
                client_ip=client_ip,
                target_id=entry_id,
                sess=sess,
                bot_override=bot_h,
            )
            err_payload: dict[str, Any] = {
                "ok": False,
                "source": "upstream",
                "error": redact_workspace_text(data.get("error") or "执行撤销/重做失败"),
            }
            if err_code:
                err_payload["code"] = err_code
            if isinstance(data.get("conflicts"), list):
                err_payload["conflicts"] = [
                    redact_workspace_text(c)[:160] for c in data["conflicts"][:10]
                ]
            return web.json_response(err_payload, status=sc)

        self.audit.record(
            action=action_name,
            status_code=200,
            outcome="allowed_force" if raw_force else "allowed",
            client_ip=client_ip,
            target_id=entry_id,
            sess=sess,
            bot_override=bot_h,
        )
        applied_clean = [
            {
                "action": _sanitize_slug(a.get("action") or "", max_len=24),
                "path": redact_workspace_text(a.get("path") or ""),
            }
            for a in (data.get("applied") or [])[:50]
            if isinstance(a, dict)
        ]
        return web.json_response({
            "ok": True,
            "action": "redo" if reverse else "undo",
            "bot": bot_h,
            "entry_id": entry_id,
            "cid": str(data.get("cid") or ""),
            "project_id": _sanitize_slug(data.get("project_id") or "", max_len=64),
            "applied": applied_clean,
            "remaining_undo": int(data.get("remaining_undo") or 0),
            "remaining_redo": int(data.get("remaining_redo") or 0),
        })

    async def handle_apply_undo(self, request: web.Request) -> web.Response:
        return await self._handle_undo_mutation(request, reverse=False)

    async def handle_apply_redo(self, request: web.Request) -> web.Response:
        return await self._handle_undo_mutation(request, reverse=True)
