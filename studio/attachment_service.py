#!/usr/bin/env python3
"""AGY Studio — Controlled Multimodal Attachment Upload, Safe Preview & Workspace Context Resolution.

Security invariants:
- Never trusts client-supplied absolute host paths (prevents LFI).
- Uploaded files are stored under `<UPLOAD_ROOT>/web/` (`0700` dir, `0600` files, `O_NOFOLLOW`,
  random server-generated filenames `web_<ts_ms>_<hex>.<ext>`) and indexed solely by opaque
  `att_<ts_ms>_<hex>` IDs.
- Strict extension whitelist aligned with `agy` CLI capabilities (`read_file` native image/PDF/
  audio/video/text + code/document/archive) with per-category byte ceilings.
- Explicitly rejects `.svg`/`.svgz` (prevents Stored XSS) and verifies raster image magic headers
  before permitting `Content-Disposition: inline`.
- `GET /api/chat/attachments/{att_id}` requires authentication, enforces
  `X-Content-Type-Options: nosniff` + `Cache-Control: private, max-age=3600`, serves `inline`
  ONLY for verified safe bitmaps (`png/jpg/jpeg/webp/gif`), and `attachment` for all other types.
- Workspace `@` context files are resolved exclusively inside server-whitelisted project roots
  via `_resolve_sandboxed_path()` (blocks `..`, absolute paths, symlinks, `.git`, `.env`, keys).
- Prompt injection builders include server paths ONLY for downstream Bridge IPC / `agy` CLI turns;
  historical display parsers strip host paths before returning to WebUI / `readonly` views.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import logging
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import secrets
import time
from typing import TYPE_CHECKING, Any, Iterator
import urllib.parse

from aiohttp import web

from .auth import StudioAuthManager, studio_auth_error
from .data_sources import (
    StudioDataSources,
    _sanitize_slug,
    extract_message_attachments,
    truncate_utf8_bytes,
)
from .workspace_files import _resolve_sandboxed_path

if TYPE_CHECKING:
    from .chat_service import StudioAuditLogger

log = logging.getLogger("agy-studio.attachments")


def _extract_media_type(request: web.Request) -> str:
    raw = request.headers.get("Content-Type")
    if not raw or not isinstance(raw, str):
        return ""
    return raw.split(";", 1)[0].strip().lower()

ATTACHMENT_ID_RE = re.compile(r"^att_[0-9]{10,16}_[a-f0-9]{12}$")

MAX_ATTACHMENTS_PER_MSG = 6
MAX_CONTEXT_FILES_PER_MSG = 10

ATTACHMENT_TTL_SEC = 7 * 86400
MAX_TOTAL_UPLOAD_BYTES = 512 * 1024 * 1024
MAX_INDEX_ENTRIES = 500

IMAGE_MAX_BYTES = 15 * 1024 * 1024
DOC_MAX_BYTES = 20 * 1024 * 1024
CODE_MAX_BYTES = 5 * 1024 * 1024
MEDIA_MAX_BYTES = 25 * 1024 * 1024
ARCHIVE_MAX_BYTES = 25 * 1024 * 1024

_FORBIDDEN_EXTENSIONS = frozenset({"svg", "svgz"})

# ext -> (kind, canonical_mime, max_bytes, allow_inline)
_EXT_RULES: dict[str, tuple[str, str, int, bool]] = {
    # Images (<= 15 MiB, inline safe raster only)
    "png": ("image", "image/png", IMAGE_MAX_BYTES, True),
    "jpg": ("image", "image/jpeg", IMAGE_MAX_BYTES, True),
    "jpeg": ("image", "image/jpeg", IMAGE_MAX_BYTES, True),
    "webp": ("image", "image/webp", IMAGE_MAX_BYTES, True),
    "gif": ("image", "image/gif", IMAGE_MAX_BYTES, True),
    # Documents & PDF (<= 20 MiB)
    "pdf": ("pdf", "application/pdf", DOC_MAX_BYTES, False),
    "txt": ("document", "text/plain; charset=utf-8", DOC_MAX_BYTES, False),
    "md": ("document", "text/plain; charset=utf-8", DOC_MAX_BYTES, False),
    "csv": ("document", "text/csv; charset=utf-8", DOC_MAX_BYTES, False),
    "json": ("document", "application/json", DOC_MAX_BYTES, False),
    "yaml": ("document", "text/plain; charset=utf-8", DOC_MAX_BYTES, False),
    "yml": ("document", "text/plain; charset=utf-8", DOC_MAX_BYTES, False),
    "xml": ("document", "application/octet-stream", DOC_MAX_BYTES, False),
    "toml": ("document", "text/plain; charset=utf-8", DOC_MAX_BYTES, False),
    "log": ("document", "text/plain; charset=utf-8", DOC_MAX_BYTES, False),
    "docx": (
        "document",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        DOC_MAX_BYTES,
        False,
    ),
    "xlsx": (
        "document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        DOC_MAX_BYTES,
        False,
    ),
    # Code & Text (<= 5 MiB; served as attachment/plain text to avoid script execution)
    "py": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "ts": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "tsx": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "js": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "jsx": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "go": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "rs": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "sh": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "sql": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "html": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "css": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "c": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "cpp": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "h": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "java": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "diff": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "patch": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "ini": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    "conf": ("code", "text/plain; charset=utf-8", CODE_MAX_BYTES, False),
    # Audio & Video (<= 25 MiB)
    "mp3": ("audio", "audio/mpeg", MEDIA_MAX_BYTES, False),
    "wav": ("audio", "audio/wav", MEDIA_MAX_BYTES, False),
    "ogg": ("audio", "audio/ogg", MEDIA_MAX_BYTES, False),
    "m4a": ("audio", "audio/mp4", MEDIA_MAX_BYTES, False),
    "flac": ("audio", "audio/flac", MEDIA_MAX_BYTES, False),
    "mp4": ("video", "video/mp4", MEDIA_MAX_BYTES, False),
    "webm": ("video", "video/webm", MEDIA_MAX_BYTES, False),
    "mov": ("video", "video/quicktime", MEDIA_MAX_BYTES, False),
    # Archives (<= 25 MiB)
    "zip": ("archive", "application/zip", ARCHIVE_MAX_BYTES, False),
    "gz": ("archive", "application/gzip", ARCHIVE_MAX_BYTES, False),
    "tgz": ("archive", "application/gzip", ARCHIVE_MAX_BYTES, False),
    "tar.gz": ("archive", "application/gzip", ARCHIVE_MAX_BYTES, False),
}

_KIND_LABELS: dict[str, str] = {
    "image": "图片",
    "pdf": "PDF",
    "document": "文档",
    "code": "代码",
    "audio": "音频",
    "video": "视频",
    "archive": "压缩包",
}

_ATT_BLOCK_HEADER = "[已附加文件]"
_CTX_BLOCK_HEADER = "[已引用工作区文件]"


def is_valid_attachment_id(raw: Any) -> bool:
    return isinstance(raw, str) and bool(ATTACHMENT_ID_RE.fullmatch(raw.strip()))


def format_size_human(size_bytes: int) -> str:
    n = max(0, int(size_bytes))
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def _sanitize_display_filename(raw_name: Any) -> str:
    text = str(raw_name or "").strip()
    if not text:
        return "attachment"
    # Strip both POSIX and Windows directory prefixes
    text = PurePosixPath(text).name
    text = PureWindowsPath(text).name
    text = re.sub(r"[\x00-\x1f\x7f\r\n]+", "_", text).strip()
    text = text.replace("..", "_")
    if not text or text in (".", ".."):
        return "attachment"
    if len(text) > 160:
        stem, dot, ext = text.rpartition(".")
        if dot and len(ext) <= 12:
            text = stem[: 159 - len(ext)] + "." + ext
        else:
            text = text[:160]
    return text


def _extract_extension(filename: str) -> str:
    low = filename.strip().lower()
    if low.endswith(".tar.gz"):
        return "tar.gz"
    if "." not in low:
        return ""
    return low.rsplit(".", 1)[1].strip()


def _verify_image_magic(ext: str, head: bytes) -> bool:
    if not head:
        return False
    # Explicitly reject XML/HTML/SVG payloads disguised as images
    lead = head.lstrip()[:64].lower()
    if lead.startswith((b"<svg", b"<?xml", b"<html", b"<!doctype", b"<script")):
        return False
    if ext == "png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in ("jpg", "jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if ext == "gif":
        return head.startswith((b"GIF87a", b"GIF89a"))
    if ext == "webp":
        return len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    return False


def _public_attachment_view(rec: dict[str, Any]) -> dict[str, Any]:
    att_id = str(rec.get("id") or "")
    size = max(0, int(rec.get("size") or 0))
    return {
        "id": att_id,
        "name": str(rec.get("orig_name") or rec.get("name") or "attachment"),
        "kind": str(rec.get("kind") or "document"),
        "mime": str(rec.get("mime") or "application/octet-stream"),
        "size": size,
        "size_label": format_size_human(size),
        "preview_url": f"/api/chat/attachments/{att_id}",
    }


def _ascii_fallback_filename(name: str, ext: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    if not clean:
        clean = f"attachment.{ext}" if ext else "attachment"
    return clean[:120]


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
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
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


def default_prompt_for_attachments(
    resolved_attachments: list[dict[str, Any]],
    resolved_context_files: list[dict[str, str]],
) -> str:
    has_att = bool(resolved_attachments)
    has_ctx = bool(resolved_context_files)
    has_img = any(str(a.get("kind") or "") == "image" for a in resolved_attachments)
    if has_att and has_ctx:
        return "请查看并分析我附加的文件与引用的工作区文件"
    if has_att:
        return "请查看并分析我附加的图片/文件" if has_img else "请查看并分析我附加的文件"
    if has_ctx:
        return "请查看并分析我引用的工作区文件"
    return ""


def build_attachment_prompt_block(
    resolved_attachments: list[dict[str, Any]],
    resolved_context_files: list[dict[str, str]],
) -> str:
    """Build the standardized CLI-readable attachment & workspace reference block."""
    sections: list[str] = []
    if resolved_attachments:
        lines = [_ATT_BLOCK_HEADER]
        for att in resolved_attachments:
            kind = str(att.get("kind") or "document")
            att_id = str(att.get("id") or "")
            name = str(att.get("name") or "attachment")
            size_lbl = format_size_human(int(att.get("size") or 0))
            abs_p = str(att.get("abs_path") or "")
            lines.append(f"- [{kind}|{att_id}|{size_lbl}] {name} (文件位置: {abs_p})")
        lines.append(
            "提示：以上文件已由系统落盘，请直接使用 read_file 工具读取图片/PDF/音视频/文本文件内容进行分析。"
        )
        sections.append("\n".join(lines))

    if resolved_context_files:
        lines = [_CTX_BLOCK_HEADER]
        for cf in resolved_context_files:
            rel = str(cf.get("rel_path") or "")
            pid = str(cf.get("project_id") or "")
            abs_p = str(cf.get("abs_path") or "")
            proj_part = f"项目: {pid}, " if pid else ""
            lines.append(f"- @{rel} ({proj_part}文件位置: {abs_p})")
        lines.append("提示：请结合以上工作区文件进行分析与回答。")
        sections.append("\n".join(lines))

    return "\n\n".join(sections)


def build_prompt_with_attachments(
    user_prompt: str,
    resolved_attachments: list[dict[str, Any]],
    resolved_context_files: list[dict[str, str]],
    *,
    max_bytes: int = 32 * 1024,
) -> tuple[str, str]:
    """Return `(display_prompt, cli_prompt)` strictly bounded to `max_bytes` UTF-8 bytes."""
    display_prompt = user_prompt.strip()
    if not display_prompt:
        display_prompt = default_prompt_for_attachments(resolved_attachments, resolved_context_files)

    block = build_attachment_prompt_block(resolved_attachments, resolved_context_files)
    if not block:
        bounded, _ = truncate_utf8_bytes(display_prompt, max_bytes)
        return bounded, bounded

    block_bytes = len(block.encode("utf-8"))
    sep = "\n\n"
    budget_for_text = max(256, max_bytes - block_bytes - len(sep))
    bounded_text, _ = truncate_utf8_bytes(display_prompt, budget_for_text)
    cli_prompt = f"{bounded_text}{sep}{block}"
    if len(cli_prompt.encode("utf-8")) > max_bytes:
        cli_prompt, _ = truncate_utf8_bytes(cli_prompt, max_bytes)
    return display_prompt, cli_prompt


class StudioAttachmentService:
    """Controlled multimodal upload, safe preview & workspace `@` context file resolver."""

    def __init__(
        self,
        auth_mgr: StudioAuthManager,
        data_sources: StudioDataSources,
        audit: StudioAuditLogger,
        *,
        upload_dir: Path | None = None,
        ttl_sec: float = ATTACHMENT_TTL_SEC,
        max_total_bytes: int = MAX_TOTAL_UPLOAD_BYTES,
    ) -> None:
        self.auth_mgr = auth_mgr
        self.data_sources = data_sources
        self.audit = audit
        if upload_dir is not None:
            self._custom_upload_dir: Path | None = Path(upload_dir)
        else:
            env_dir = os.environ.get("AGY_STUDIO_UPLOAD_DIR", "").strip()
            if env_dir:
                self._custom_upload_dir = Path(env_dir)
            else:
                workdir = os.environ.get("AGY_TG_WORKDIR", "").strip() or str(
                    Path.home() / "agy-workspace"
                )
                self._custom_upload_dir = Path(workdir) / "uploads" / "web"
        self.ttl_sec = max(60.0, float(ttl_sec))
        self.max_total_bytes = max(1024 * 1024, int(max_total_bytes))

    def _ensure_upload_dir(self) -> Path:
        assert self._custom_upload_dir is not None
        base = self._custom_upload_dir
        if os.path.islink(base):
            raise OSError("Upload directory must not be a symlink")
        base.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(base, 0o700)
        except OSError:
            pass
        real = base.resolve(strict=True)
        if not real.is_dir():
            raise OSError("Upload directory is not accessible")
        return real

    def _index_path(self, udir: Path) -> Path:
        return udir / ".index.json"

    @contextmanager
    def _index_lock(self, udir: Path) -> Iterator[None]:
        lock_p = udir / ".index.lock"
        if os.path.islink(lock_p):
            raise OSError("Index lock must not be a symlink")
        fd = os.open(str(lock_p), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
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

    def _read_index_locked(self, udir: Path) -> dict[str, dict[str, Any]]:
        idx_p = self._index_path(udir)
        if not idx_p.is_file() or os.path.islink(idx_p):
            return {}
        try:
            raw = json.loads(idx_p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return {}
        items = raw.get("items") if isinstance(raw, dict) else None
        if not isinstance(items, dict):
            return {}
        out: dict[str, dict[str, Any]] = {}
        for k, v in items.items():
            if is_valid_attachment_id(k) and isinstance(v, dict):
                out[k] = v
        return out

    def _safe_stored_path(self, udir: Path, stored_name: str) -> Path | None:
        if (
            not stored_name
            or "/" in stored_name
            or "\\" in stored_name
            or ".." in stored_name
            or "\x00" in stored_name
            or stored_name.startswith(".")
        ):
            return None
        cand = udir / stored_name
        if os.path.islink(cand):
            return None
        try:
            resolved = cand.resolve(strict=False)
        except OSError:
            return None
        if not resolved.is_relative_to(udir) or resolved == udir:
            return None
        return resolved

    def _prune_locked(
        self,
        udir: Path,
        items: dict[str, dict[str, Any]],
        *,
        now: float,
    ) -> dict[str, dict[str, Any]]:
        cutoff = now - self.ttl_sec
        kept: dict[str, dict[str, Any]] = {}
        to_unlink: list[str] = []

        for att_id, rec in items.items():
            created_at = float(rec.get("created_at") or 0.0)
            stored_name = str(rec.get("stored_name") or "")
            p = self._safe_stored_path(udir, stored_name)
            if created_at < cutoff or p is None or not p.is_file():
                if stored_name:
                    to_unlink.append(stored_name)
                continue
            kept[att_id] = rec

        # Enforce total entries and total disk bytes cap (oldest first)
        ordered = sorted(kept.items(), key=lambda kv: float(kv[1].get("created_at") or 0.0))
        total_bytes = sum(max(0, int(r.get("size") or 0)) for _, r in ordered)
        while len(ordered) > MAX_INDEX_ENTRIES or (
            total_bytes > self.max_total_bytes and len(ordered) > 1
        ):
            old_id, old_rec = ordered.pop(0)
            kept.pop(old_id, None)
            total_bytes -= max(0, int(old_rec.get("size") or 0))
            old_stored = str(old_rec.get("stored_name") or "")
            if old_stored:
                to_unlink.append(old_stored)

        for fname in to_unlink:
            p = self._safe_stored_path(udir, fname)
            if p is not None:
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass

        return kept

    # ------------------------------------------------------------------ Write Gate (multipart)
    async def _enforce_upload_gate(
        self,
        request: web.Request,
    ) -> tuple[bool, dict[str, Any] | None, web.Response | None]:
        action = "chat.attachment_upload"
        client_ip = self.auth_mgr.extract_client_ip(request)

        # Gate 1: Strict Same-Origin
        ok_orig, err_orig = self.auth_mgr.check_same_origin(request, require_origin=True)
        if not ok_orig:
            self.audit.record(
                action=action, status_code=403, outcome="denied_origin", client_ip=client_ip
            )
            return False, None, studio_auth_error(err_orig, status=403)

        # Gate 2: multipart/form-data Content-Type
        media_type = _extract_media_type(request)
        if media_type != "multipart/form-data":
            self.audit.record(
                action=action, status_code=415, outcome="denied_content_type", client_ip=client_ip
            )
            return (
                False,
                None,
                studio_auth_error("上传接口仅接受 Content-Type: multipart/form-data", status=415),
            )

        # Gate 3: Authenticated session + live RBAC + must_change_password=False
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            self.audit.record(
                action=action, status_code=status_code, outcome="denied_auth", client_ip=client_ip
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
                sess=sess,
            )
            return False, None, studio_auth_error(err_csrf, status=403)

        # Gate 4b: Live RBAC admin only
        if sess.get("role") != "admin":
            self.audit.record(
                action=action,
                status_code=403,
                outcome="denied_rbac",
                client_ip=client_ip,
                sess=sess,
            )
            return False, None, studio_auth_error("只读权限（readonly）禁止上传附件", status=403)

        return True, sess, None

    # ------------------------------------------------------------------ POST /api/chat/attachments
    async def handle_upload(self, request: web.Request) -> web.Response:
        action = "chat.attachment_upload"
        client_ip = self.auth_mgr.extract_client_ip(request)

        ok_gate, sess, err_resp = await self._enforce_upload_gate(request)
        if not ok_gate or not sess:
            assert err_resp is not None
            return err_resp

        try:
            udir = self._ensure_upload_dir()
        except OSError:
            self.audit.record(
                action=action,
                status_code=500,
                outcome="error_storage",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "附件存储目录不可用"},
                status=500,
            )

        try:
            reader = await request.multipart()
        except Exception:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_invalid_multipart",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "无法解析 multipart/form-data 请求体"},
                status=400,
            )

        file_part = None
        try:
            while True:
                part = await reader.next()
                if part is None:
                    break
                if part.name == "file" or part.filename:
                    file_part = part
                    break
        except Exception:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_invalid_multipart",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "上传数据流损坏"},
                status=400,
            )

        if file_part is None:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_missing_file",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "缺少上传文件字段（file）"},
                status=400,
            )

        orig_name = _sanitize_display_filename(file_part.filename)
        ext = _extract_extension(orig_name)
        if ext in _FORBIDDEN_EXTENSIONS:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_svg",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": "禁止上传 SVG 文件（防范内联脚本 XSS 风险），请转换为 PNG/JPG/WebP",
                },
                status=400,
            )

        rule = _EXT_RULES.get(ext)
        if rule is None:
            self.audit.record(
                action=action,
                status_code=400,
                outcome="denied_unsupported_type",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {
                    "ok": False,
                    "source": "studio_api",
                    "error": f"不支持的文件类型（.{ext or '无扩展名'}），支持图片/PDF/文档/代码/音视频/压缩包",
                },
                status=400,
            )

        kind, canonical_mime, max_bytes, _allow_inline = rule

        ts_ms = int(time.time() * 1000)
        rand_hex = secrets.token_hex(6)
        att_id = f"att_{ts_ms}_{rand_hex}"
        stored_name = f"web_{ts_ms}_{rand_hex}.{ext}"
        tmp_path = udir / f".upload.{os.getpid()}.{rand_hex}.tmp"
        final_path = udir / stored_name

        total_written = 0
        head_buf = bytearray()
        too_large = False
        try:
            fd = os.open(
                str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            try:
                with os.fdopen(fd, "wb") as fh:
                    while True:
                        chunk = await file_part.read_chunk(65536)
                        if not chunk:
                            break
                        if len(head_buf) < 64:
                            head_buf.extend(chunk[: 64 - len(head_buf)])
                        total_written += len(chunk)
                        if total_written > max_bytes:
                            too_large = True
                            break
                        fh.write(chunk)
                    if not too_large:
                        fh.flush()
                        os.fsync(fh.fileno())
            except Exception:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass
                raise

            if too_large:
                tmp_path.unlink(missing_ok=True)
                limit_mb = max_bytes // (1024 * 1024)
                self.audit.record(
                    action=action,
                    status_code=413,
                    outcome="denied_too_large",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {
                        "ok": False,
                        "source": "studio_api",
                        "error": f"{_KIND_LABELS.get(kind, '该类')}文件超过 {limit_mb} MiB 上限",
                    },
                    status=413,
                )

            if total_written <= 0:
                tmp_path.unlink(missing_ok=True)
                self.audit.record(
                    action=action,
                    status_code=400,
                    outcome="denied_empty_file",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {"ok": False, "source": "studio_api", "error": "禁止上传空文件（0 字节）"},
                    status=400,
                )

            if kind == "image" and not _verify_image_magic(ext, bytes(head_buf)):
                tmp_path.unlink(missing_ok=True)
                self.audit.record(
                    action=action,
                    status_code=400,
                    outcome="denied_invalid_image_magic",
                    client_ip=client_ip,
                    sess=sess,
                )
                return web.json_response(
                    {
                        "ok": False,
                        "source": "studio_api",
                        "error": "图片文件内容校验失败，请上传有效的 PNG/JPG/WebP/GIF 位图",
                    },
                    status=400,
                )

            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, final_path)
        except web.HTTPRequestEntityTooLarge:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            self.audit.record(
                action=action,
                status_code=413,
                outcome="denied_too_large",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "上传文件体积超过服务端上限"},
                status=413,
            )
        except Exception as exc:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
            log.warning("Attachment write failed: %s", type(exc).__name__)
            self.audit.record(
                action=action,
                status_code=500,
                outcome="error_write",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "保存上传文件失败"},
                status=500,
            )

        now = time.time()
        record: dict[str, Any] = {
            "id": att_id,
            "stored_name": stored_name,
            "orig_name": orig_name,
            "kind": kind,
            "ext": ext,
            "mime": canonical_mime,
            "size": total_written,
            "created_at": round(now, 3),
            "owner_user_id": int(sess["user_id"]),
            "owner_username": str(sess.get("username") or "")[:64],
        }
        try:
            with self._index_lock(udir):
                items = self._read_index_locked(udir)
                items[att_id] = record
                items = self._prune_locked(udir, items, now=now)
                _atomic_write_json_0600(
                    self._index_path(udir),
                    {"version": 1, "items": items},
                )
        except Exception as exc:
            try:
                final_path.unlink(missing_ok=True)
            except OSError:
                pass
            log.warning("Attachment index update failed: %s", type(exc).__name__)
            self.audit.record(
                action=action,
                status_code=500,
                outcome="error_index",
                client_ip=client_ip,
                sess=sess,
            )
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "写入附件索引失败"},
                status=500,
            )

        self.audit.record(
            action=action,
            status_code=201,
            outcome="ok",
            client_ip=client_ip,
            target_id=att_id,
            sess=sess,
        )
        return web.json_response(
            {"ok": True, "attachment": _public_attachment_view(record)},
            status=201,
        )

    # ------------------------------------------------------------------ GET /api/chat/attachments/{att_id}
    async def handle_get_attachment(self, request: web.Request) -> web.StreamResponse:
        ok_auth, sess, err_auth, status_code = await self.auth_mgr.authenticate_request(request)
        if not ok_auth or not sess:
            return studio_auth_error(err_auth, status=status_code)

        att_id = str(request.match_info.get("att_id") or "").strip()
        if not is_valid_attachment_id(att_id):
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "非法的附件标识"},
                status=400,
            )

        try:
            udir = self._ensure_upload_dir()
            with self._index_lock(udir):
                items = self._read_index_locked(udir)
                rec = items.get(att_id)
        except OSError:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "附件存储不可访问"},
                status=500,
            )

        if not isinstance(rec, dict):
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "附件不存在或已过期清理"},
                status=404,
            )

        stored_name = str(rec.get("stored_name") or "")
        ext = str(rec.get("ext") or "").lower()
        rule = _EXT_RULES.get(ext)
        if rule is None:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "附件类型不受支持"},
                status=404,
            )

        target_path = self._safe_stored_path(udir, stored_name)
        if target_path is None or not target_path.is_file():
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "附件文件不存在或已清理"},
                status=404,
            )

        try:
            fd = os.open(str(target_path), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                with os.fdopen(fd, "rb") as fh:
                    body = fh.read()
            except Exception:
                raise
        except OSError:
            return web.json_response(
                {"ok": False, "source": "studio_api", "error": "读取附件失败"},
                status=404,
            )

        kind, canonical_mime, _max_b, allow_inline = rule
        force_dl = request.query.get("download") in ("1", "true", "yes")
        can_inline = (
            allow_inline
            and kind == "image"
            and not force_dl
            and _verify_image_magic(ext, body[:64])
        )
        disp_type = "inline" if can_inline else "attachment"
        orig_name = _sanitize_display_filename(rec.get("orig_name") or stored_name)
        ascii_fb = _ascii_fallback_filename(orig_name, ext)
        utf8_quoted = urllib.parse.quote(orig_name, safe="")
        headers = {
            "Content-Type": canonical_mime,
            "Content-Disposition": f'{disp_type}; filename="{ascii_fb}"; filename*=UTF-8\'\'{utf8_quoted}',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, max-age=3600",
        }
        return web.Response(body=body, status=200, headers=headers)

    # ------------------------------------------------------------------ Server-Side Resolution Helpers
    def resolve_attachments(
        self,
        raw_ids: Any,
    ) -> tuple[bool, list[dict[str, Any]], int, str]:
        """Resolve client-supplied `att_id` list to verified server records (including `abs_path`)."""
        if raw_ids is None:
            return True, [], 200, ""
        if not isinstance(raw_ids, list):
            return False, [], 400, "attachments 必须为附件 ID 字符串数组"
        if len(raw_ids) > MAX_ATTACHMENTS_PER_MSG:
            return False, [], 400, f"单条消息最多附加 {MAX_ATTACHMENTS_PER_MSG} 个文件"
        if not raw_ids:
            return True, [], 200, ""

        dedup_ids: list[str] = []
        seen: set[str] = set()
        for item in raw_ids:
            if not isinstance(item, str) or not is_valid_attachment_id(item):
                return False, [], 400, "包含非法的附件 ID"
            aid = item.strip()
            if aid not in seen:
                seen.add(aid)
                dedup_ids.append(aid)

        try:
            udir = self._ensure_upload_dir()
            with self._index_lock(udir):
                items = self._read_index_locked(udir)
        except OSError:
            return False, [], 500, "附件存储目录不可用"

        resolved: list[dict[str, Any]] = []
        for aid in dedup_ids:
            rec = items.get(aid)
            if not isinstance(rec, dict):
                return False, [], 404, f"附件不存在或已过期：{aid}"
            stored_name = str(rec.get("stored_name") or "")
            target_path = self._safe_stored_path(udir, stored_name)
            if target_path is None or not target_path.is_file():
                return False, [], 404, f"附件文件已失效：{aid}"
            pub = _public_attachment_view(rec)
            pub["abs_path"] = str(target_path)
            resolved.append(pub)

        return True, resolved, 200, ""

    def resolve_context_files(
        self,
        raw_files: Any,
        project_id: str | None,
    ) -> tuple[bool, list[dict[str, str]], int, str]:
        """Validate `@` workspace context files strictly inside an allowed project root."""
        if raw_files is None:
            return True, [], 200, ""
        if not isinstance(raw_files, list):
            return False, [], 400, "context_files 必须为项目内相对路径数组"
        if len(raw_files) > MAX_CONTEXT_FILES_PER_MSG:
            return False, [], 400, f"单条消息最多引用 {MAX_CONTEXT_FILES_PER_MSG} 个工作区文件"
        if not raw_files:
            return True, [], 200, ""

        proj: dict[str, str] | None = None
        if project_id and str(project_id).strip():
            proj = self.data_sources.resolve_allowed_project(str(project_id).strip())
            if proj is None:
                return False, [], 400, "引用的项目不在服务端白名单内"
        else:
            allowed = self.data_sources.get_allowed_projects()
            if allowed:
                proj = allowed[0]
        if proj is None or not proj.get("workdir"):
            return False, [], 400, "引用工作区文件前请先选择有效的允许项目"

        root = Path(proj["workdir"])
        resolved: list[dict[str, str]] = []
        seen: set[str] = set()
        for raw_rel in raw_files:
            if not isinstance(raw_rel, str):
                return False, [], 400, "context_files 元素必须为字符串"
            rel_clean = raw_rel.strip().lstrip("@")
            ok_p, target_real, norm_rel, sc_p, err_p = _resolve_sandboxed_path(
                root, rel_clean, allow_root=False
            )
            if not ok_p or target_real is None:
                return False, [], sc_p, f"工作区文件引用被拒绝（{rel_clean[:64]}）：{err_p}"
            if not target_real.is_file():
                return False, [], 404, f"工作区文件不存在：{norm_rel}"
            if norm_rel in seen:
                continue
            seen.add(norm_rel)
            resolved.append(
                {
                    "rel_path": norm_rel,
                    "abs_path": str(target_real),
                    "project_id": _sanitize_slug(proj.get("id") or "", max_len=64),
                }
            )

        return True, resolved, 200, ""

    @staticmethod
    def build_attachment_prompt_block(
        resolved_attachments: list[dict[str, Any]],
        resolved_context_files: list[dict[str, str]],
    ) -> str:
        return build_attachment_prompt_block(resolved_attachments, resolved_context_files)

    @staticmethod
    def build_prompt_with_attachments(
        user_prompt: str,
        resolved_attachments: list[dict[str, Any]],
        resolved_context_files: list[dict[str, str]],
        *,
        max_bytes: int = 32 * 1024,
    ) -> tuple[str, str]:
        return build_prompt_with_attachments(
            user_prompt,
            resolved_attachments,
            resolved_context_files,
            max_bytes=max_bytes,
        )

    @staticmethod
    def strip_internal_paths(resolved_attachments: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return strictly public attachment dicts without `abs_path`."""
        return [
            {
                "id": str(a.get("id") or ""),
                "name": str(a.get("name") or "attachment"),
                "kind": str(a.get("kind") or "document"),
                "mime": str(a.get("mime") or "application/octet-stream"),
                "size": int(a.get("size") or 0),
                "size_label": str(a.get("size_label") or format_size_human(int(a.get("size") or 0))),
                "preview_url": str(a.get("preview_url") or ""),
            }
            for a in resolved_attachments
        ]
