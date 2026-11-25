#!/usr/bin/env python3
"""Strictly read-only data aggregation layer for AGY Studio Phase 1 MVP.

Reuses pure helpers from `bridge/bot_bus.py`, `bridge/scheduler.py`, and
`bridge/cost_usage.py` WITHOUT performing any writes, creating state files,
or exposing tokens, `.env` values, chat IDs, or private credentials.
"""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from typing import Any
import urllib.parse

import aiohttp

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BRIDGE_SRC_DIR = _REPO_ROOT / "bridge"
if str(_BRIDGE_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_BRIDGE_SRC_DIR))

import bot_bus  # noqa: E402
import cost_usage  # noqa: E402
import google_accounts  # noqa: E402
import scheduler  # noqa: E402
import studio_ipc  # noqa: E402

_URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Arbitrary POSIX absolute paths (any multi-segment `/a/b...`, known root segments, or `~/...`)
# AND Windows absolute paths (`C:\...`, `D:/...`), never matching URL `//` or slash commands like `/webui`.
_ABS_PATH_RE = re.compile(
    r"(?:(?<=^)|(?<=[\s(\[\{\"'=:;,]))"
    r"(?:"
    r"/(?!/)[A-Za-z0-9._-]+(?:/[^\s,'\"`<>)\]}]+)+"
    r"|/(?:home|Users|etc|var|tmp|root|opt|srv|proc|run|mnt|media|data|private|secrets)(?=/|$|[\s,'\"`<>)\]}])"
    r"|~(?:/[^\s,'\"`<>)\]}]+)+"
    r"|[A-Za-z]:(?:\\|/)[^\s,'\"`<>)\]}]+"
    r")"
)
_TG_AND_LONG_ID_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:-100\d{8,13}|-\d{9,13}|\d{8,15})(?![A-Za-z0-9_.-])"
)

_PEM_DASH = "-" * 5
_PEM_TYPE_WORDS = r"(?:[A-Z0-9-]{1,24}[ \t]+){0,4}"
_PEM_BEGIN_RE = re.compile(rf"{_PEM_DASH}BEGIN[ \t]+{_PEM_TYPE_WORDS}PRIVATE[ \t]+KEY{_PEM_DASH}")
_PEM_END_RE = re.compile(rf"{_PEM_DASH}END[ \t]+{_PEM_TYPE_WORDS}PRIVATE[ \t]+KEY{_PEM_DASH}")
_PEM_BLOCK_RE = re.compile(
    rf"{_PEM_DASH}BEGIN[ \t]+{_PEM_TYPE_WORDS}PRIVATE[ \t]+KEY{_PEM_DASH}[\s\S]*?{_PEM_DASH}END[ \t]+{_PEM_TYPE_WORDS}PRIVATE[ \t]+KEY{_PEM_DASH}"
)
_PEM_REMNANT_RE = re.compile(
    rf"{_PEM_DASH}(?:BEGIN|END)[ \t]+{_PEM_TYPE_WORDS}PRIVATE[ \t]+KEY{_PEM_DASH}[^\r\n]*"
)

_COOKIE_LINE_RE = re.compile(r"(?im)^(?:set-)?cookie\s*:\s*[^\r\n]+")
_COOKIE_INLINE_RE = re.compile(r"(?i)\b(?:set-)?cookie\s*:\s*[^\r\n]+")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}\b")
_QUOTED_CRED_RE = re.compile(
    r"""(?i)(?<![A-Za-z0-9_.-])(?:"|')?[A-Za-z0-9_.-]{0,40}(?:token|apikey|api_key|key|secret|password|passwd|pwd|cookie|session|authorization|auth|sig|signature|credential)(?:"|')?\s*[:=]\s*(?:"(?:[^"\\]|\\.)+"|'(?:[^'\\]|\\.)+')"""
)
_UNQUOTED_CRED_RE = re.compile(
    r"""(?i)(?<![A-Za-z0-9_.-])(?:"|')?\b[A-Za-z0-9_.-]{0,40}(?:token|apikey|api_key|key|secret|password|passwd|pwd|cookie|session|authorization|auth|sig|signature|credential)\b(?:"|')?\s*[:=]\s*[^\s,;\"'`&)\]}]+"""
)

# Unclosed sensitive structure prefixes for StreamRedactor cross-chunk hold & bounded swallowing
_UNCLOSED_HEADER_RE = re.compile(
    r"(?i)(?:\b(?:set-)?cookie[ \t]*:|\bauthorization[ \t]*:|\bagy_studio_session[ \t]*=)[^\r\n]*$"
)
_UNCLOSED_QUOTED_CRED_RE = re.compile(
    r"""(?i)(?<![A-Za-z0-9_.-])(?:"|')?[A-Za-z0-9_.-]{0,40}"""
    r"""(?:token|apikey|api_key|key|secret|password|passwd|pwd|cookie|session|authorization|auth|sig|signature|credential)"""
    r"""(?:"|')?[ \t]*[:=][ \t]*(?:(?P<dq>")(?:[^"\\]|\\[\s\S])*\\?|(?P<sq>')(?:[^'\\]|\\[\s\S])*\\?)$"""
)
_UNCLOSED_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*){0,2}$"
)
_NON_BASE64URL_RE = re.compile(r"[^A-Za-z0-9_.-]")
_TOKEN_BOUNDARY_RE = re.compile(r"""[\s,;\"'`&)\]}]""")

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    _PEM_BLOCK_RE,
    _PEM_REMNANT_RE,
    _COOKIE_LINE_RE,
    _COOKIE_INLINE_RE,
    re.compile(r"(?i)\bagy_studio_session\s*=\s*[^\s;,\"'`)\]}]+"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{8,}\b"),
    re.compile(r"(?<![A-Za-z0-9_.-])\d{8,11}:[A-Za-z0-9_-]{24,45}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{16,}\b"),
    re.compile(r"\bsk-(?:proj-|ant-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:cfut|cfsd|cfat|ibk|ibssh|alt)_[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?<![A-Za-z0-9])agy_fed_[A-Za-z0-9._-]{12,}"),
    re.compile(r"\bhvs\.[A-Za-z0-9_-]{10,}\b"),
    _JWT_RE,
    re.compile(r"\b(?:lv[12]|kv/data|secret/data)/[A-Za-z0-9_./*-]+\b"),
    re.compile(r"(?i)\b(?:bearer|basic)\s+[^\s,;\"'`)\]}]+"),
    re.compile(r"(?i)\btoken\s+[A-Za-z0-9_.~+/=-]{6,}"),
    # Quoted JSON / dict credentials: "token": "...", "api_key": "...", "secret": "...", "password": "...", "authorization": "..."
    # Negative lookbehind + bounded prefix `{0,40}` eliminates O(N^2) backtracking on long alphanumeric runs.
    _QUOTED_CRED_RE,
    # Unquoted key=value / key: value credentials
    _UNQUOTED_CRED_RE,
)

MAX_MESSAGE_BYTES = 32 * 1024
MAX_TRANSCRIPT_SCAN_BYTES = 8 * 1024 * 1024
_TRANSCRIPT_CHUNK_BYTES = 64 * 1024
MAX_MODEL_SLUG_LEN = 160

_SAFE_SLUG_RE = re.compile(r"[^A-Za-z0-9._:@/-]+")
_SLUG_CTRL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]+")
_CONTROLLED_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,47}$")
_ALLOWED_JOB_STATUSES = frozenset({"queued", "running", "done", "error", "failed", "cancelled", "unknown"})
_ALLOWED_BOT_ROLES = frozenset({"coordinator", "peer", "worker"})
_SENSITIVE_HOST_PATH_RE = re.compile(
    r"(?:(?<=^)|(?<=[\s(\[\{\"'`=:;,+\-]))"
    r"(?:(?i:file):///(?:home|Users|root|etc|var|tmp|opt|srv|proc|run|mnt|media|data|private|secrets)/[^\s,'\"`<>)\]}]+"
    r"|/(?:home|Users|root|etc|var|tmp|opt|srv|proc|run|mnt|media|data|private|secrets)/[^\s,'\"`<>)\]}]+"
    r"|~/[^\s,'\"`<>)\]}]+"
    r"|[A-Za-z]:[\\/][^\s,'\"`<>)\]}]+"
    r"|[^\s(\[\{\"'`=:;,<>)\]}+\-]+\.sock\b)"
)


def is_read_only_cli_schedule(task: dict[str, Any] | None) -> bool:
    """Return True if a schedule uses `script` or any `precheck_cmd`/shell field (read-only/CLI-managed)."""
    if not isinstance(task, dict):
        return False
    ttype = str(task.get("task_type") or "").strip().lower()
    if ttype == "script":
        return True
    if str(task.get("precheck_cmd") or "").strip():
        return True
    payload = task.get("payload")
    if isinstance(payload, dict):
        for key in ("precheck_cmd", "script", "command", "cmd", "shell"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return True
            if val is not None and not isinstance(val, str) and bool(val):
                return True
    return False


def redact_job_detail_text(raw: Any, max_bytes: int = MAX_MESSAGE_BYTES) -> tuple[str, bool]:
    """Redact credentials, host home paths, and IPC socket paths, then bound UTF-8 byte length."""
    text = redact_secrets_only(raw)
    if text:
        text = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", text)
    return truncate_utf8_bytes(text, max_bytes)


def _redact_url_path_segments(path: str) -> str:
    """Redact any embedded secrets, percent-encoded emails, or numeric IDs inside URL path segments."""
    if not path:
        return ""
    out_segs: list[str] = []
    for seg in path.split("/"):
        if not seg:
            out_segs.append("")
            continue
        decoded = urllib.parse.unquote(seg)
        clean_dec = decoded
        for pat in _SECRET_PATTERNS:
            clean_dec = pat.sub("[REDACTED]", clean_dec)
        clean_dec = _EMAIL_RE.sub("[REDACTED]", clean_dec)
        clean_dec = _TG_AND_LONG_ID_RE.sub("[REDACTED]", clean_dec)
        if clean_dec != decoded:
            out_segs.append("[REDACTED]")
        else:
            clean_raw = seg
            for pat in _SECRET_PATTERNS:
                clean_raw = pat.sub("[REDACTED]", clean_raw)
            clean_raw = _EMAIL_RE.sub("[REDACTED]", clean_raw)
            clean_raw = _TG_AND_LONG_ID_RE.sub("[REDACTED]", clean_raw)
            out_segs.append(clean_raw)
    return "/".join(out_segs)


def sanitize_url_origin(raw: Any, max_len: int = 200) -> str:
    """Return STRICTLY `scheme://host[:port]` (zero path, query, fragment, or userinfo)."""
    text = str(raw or "").strip()
    if not text:
        return ""
    try:
        sp = urllib.parse.urlsplit(text)
    except Exception:
        return ""
    scheme = (sp.scheme or "").lower()
    if scheme not in ("http", "https"):
        if scheme == "about":
            return f"about:{(sp.path or 'blank')[:32]}"
        return ""
    host = (sp.hostname or "").lower()
    if not host:
        return ""
    try:
        port = sp.port
    except ValueError:
        return ""
    if port is not None and not (1 <= port <= 65535):
        return ""
    default_port = 443 if scheme == "https" else 80
    host_fmt = f"[{host}]" if ":" in host else host
    port_part = "" if (port is None or port == default_port) else f":{port}"
    out = f"{scheme}://{host_fmt}{port_part}"
    if len(out) > max_len:
        out = out[: max_len - 1] + "…"
    return out


def sanitize_url_origin_path(raw: Any, max_len: int = 200) -> str:
    """Return ONLY `scheme://host[:port]/path`, stripping userinfo, query, fragment, and path PII."""
    origin = sanitize_url_origin(raw, max_len=max_len)
    if not origin or origin.startswith("about:"):
        return origin
    try:
        sp = urllib.parse.urlsplit(str(raw or "").strip())
    except Exception:
        return origin
    safe_path = _redact_url_path_segments(sp.path or "")
    out = f"{origin}{safe_path}"
    if len(out) > max_len:
        out = out[: max_len - 1] + "…"
    return out


def _sanitize_controlled_label(raw: Any, *, fallback: str = "unknown") -> str:
    """Enforce strict controlled-label whitelist regex + redaction check (never passes free text)."""
    if not isinstance(raw, str):
        return fallback
    text = raw.strip()
    if not text:
        return fallback
    if not _CONTROLLED_LABEL_RE.fullmatch(text):
        return fallback
    red = redact_sensitive_text(text, max_len=64)
    if red != text or "[REDACTED]" in red:
        return fallback
    return text


def _normalize_iso_utc(raw: Any) -> tuple[datetime.datetime | None, str | None]:
    """Strictly parse and return `(dt_utc, canonical_iso_utc_str)` or `(None, None)`."""
    if not isinstance(raw, str) or not raw.strip():
        return None, None
    dt = scheduler.parse_iso_utc(raw.strip())
    if dt is None:
        return None, None
    return dt, scheduler.format_iso_utc(dt)


def _sanitize_slug(raw: Any, max_len: int = 64) -> str:
    """Whitelist-sanitize an identifier/slug (never allowing absolute paths, traversal, or secrets).

    Supports long external model refs (e.g. `gw:<id>:<org/model-name:variant>`, up to `max_len=160`)
    without truncating or corrupting trailing characters, while rejecting control chars, `..`,
    host paths, and credentials.
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    text = _SLUG_CTRL_CHARS_RE.sub("", text).strip()
    if not text:
        return ""
    if text.startswith(("/", "~")):
        text = Path(text).name
    if ".." in text:
        return "[REDACTED]"
    red_secrets = redact_secrets_only(text)
    if "[REDACTED]" in red_secrets:
        return "[REDACTED]"
    if _EMAIL_RE.search(text) or _SENSITIVE_HOST_PATH_RE.search(text):
        return "[REDACTED]"
    if not text.startswith("gw:") and _ABS_PATH_RE.search(text):
        return "[REDACTED]"
    if not text.startswith("gw:") and _TG_AND_LONG_ID_RE.search(text):
        return "[REDACTED]"
    return _SAFE_SLUG_RE.sub("_", text)[:max_len]


def _classify_error_code(raw_error: Any) -> str:
    """Map raw error text into a coarse non-sensitive enum code (never returning raw trace/text)."""
    txt = str(raw_error or "").strip().lower()
    if not txt:
        return ""
    if "timeout" in txt or "timed out" in txt or "超时" in txt:
        return "timeout"
    if "cancel" in txt or "取消" in txt:
        return "cancelled"
    if "permission" in txt or "forbidden" in txt or "unauth" in txt or "403" in txt or "401" in txt:
        return "auth_error"
    if "rate" in txt or "429" in txt or "quota" in txt:
        return "rate_limited"
    return "execution_error"


def redact_secrets_only(raw: Any, max_len: int | None = None) -> str:
    """Redact credentials, tokens, PEM private keys, and session cookies while preserving normal code/markdown."""
    text = str(raw if raw is not None else "")
    if not text:
        return ""
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    if max_len is not None and max_len > 0 and len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def truncate_utf8_bytes(text: str, max_bytes: int) -> tuple[str, bool]:
    """Truncate `text` to at most `max_bytes` UTF-8 bytes without splitting multi-byte chars."""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text, False
    cut = raw[:max_bytes]
    return cut.decode("utf-8", errors="ignore"), True


_ATT_BLOCK_HEADER = "[已附加文件]"
_CTX_BLOCK_HEADER = "[已引用工作区文件]"
_ATT_LINE_RE = re.compile(
    r"^-\s*\[(?P<kind>[a-z]+)\|(?P<id>att_[0-9]{10,16}_[a-f0-9]{12})(?:\|(?P<size>[^\]]+))?\]\s+"
    r"(?P<name>(?:(?!文件位置:).)+?)(?:\s*\((?:项目:\s*[^,)]+,\s*)?文件位置:\s*.+\))?\s*$"
)
_CTX_LINE_RE = re.compile(
    r"^-\s*@(?P<rel>(?:(?!文件位置:).)+?)(?:\s*\((?:项目:\s*[^,)]+,\s*)?文件位置:\s*.+\))?\s*$"
)
_HOST_LOC_TAIL_RE = re.compile(r"\s*\(?(?:项目:.*?)?文件位置:.*$")
_ATT_HINT_PREFIXES = (
    "提示：以上文件已由系统落盘",
    "提示：请结合以上工作区文件",
)
_ALLOWED_ATTACHMENT_KINDS = frozenset(
    {"image", "pdf", "document", "code", "audio", "video", "archive"}
)


def extract_message_attachments(
    raw_text: str,
) -> tuple[str, list[dict[str, Any]], list[str]]:
    """Parse structured `[已附加文件]` / `[已引用工作区文件]` blocks and strip all host paths."""
    text = str(raw_text or "")
    if _ATT_BLOCK_HEADER not in text and _CTX_BLOCK_HEADER not in text:
        return text, [], []

    lines = text.splitlines()
    out_lines: list[str] = []
    attachments: list[dict[str, Any]] = []
    context_files: list[str] = []
    seen_att_ids: set[str] = set()
    seen_ctx: set[str] = set()
    mode: str | None = None

    for ln in lines:
        stripped = ln.strip()
        if stripped == _ATT_BLOCK_HEADER:
            mode = "att"
            continue
        if stripped == _CTX_BLOCK_HEADER:
            mode = "ctx"
            continue

        if mode == "att":
            if not stripped:
                mode = None
                continue
            if any(stripped.startswith(p) for p in _ATT_HINT_PREFIXES):
                continue
            m = _ATT_LINE_RE.match(stripped)
            if m:
                att_id = m.group("id")
                if att_id not in seen_att_ids and len(attachments) < 6:
                    seen_att_ids.add(att_id)
                    kind = m.group("kind").strip().lower()
                    if kind not in _ALLOWED_ATTACHMENT_KINDS:
                        kind = "document"
                    raw_name = Path(m.group("name").strip().replace("\\", "/")).name or "attachment"
                    attachments.append(
                        {
                            "id": att_id,
                            "name": re.sub(r"[\x00-\x1f\x7f\r\n]+", "_", raw_name)[:160],
                            "kind": kind,
                            "size_label": (m.group("size") or "").strip()[:32],
                            "preview_url": f"/api/chat/attachments/{att_id}",
                        }
                    )
                continue
            if "文件位置:" in ln:
                cleaned_ln = _HOST_LOC_TAIL_RE.sub("", ln).rstrip()
                cleaned_ln = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", cleaned_ln)
                if cleaned_ln.strip():
                    out_lines.append(cleaned_ln)
                continue
            ln = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", ln)
            mode = None

        if mode == "ctx":
            if not stripped:
                mode = None
                continue
            if any(stripped.startswith(p) for p in _ATT_HINT_PREFIXES):
                continue
            m = _CTX_LINE_RE.match(stripped)
            if m:
                rel = m.group("rel").strip()
                if (
                    rel
                    and not rel.startswith("/")
                    and ".." not in rel.split("/")
                    and rel not in seen_ctx
                    and len(context_files) < 10
                ):
                    seen_ctx.add(rel)
                    context_files.append(rel)
                continue
            if "文件位置:" in ln:
                cleaned_ln = _HOST_LOC_TAIL_RE.sub("", ln).rstrip()
                cleaned_ln = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", cleaned_ln)
                if cleaned_ln.strip():
                    out_lines.append(cleaned_ln)
                continue
            ln = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", ln)
            mode = None

        out_lines.append(ln)

    clean_text = "\n".join(out_lines).strip()
    return clean_text, attachments, context_files


_JOB_ID_IN_TEXT_RE = re.compile(r"\b(job-[a-zA-Z0-9_-]{4,24})\b")
_STAGE_ACK_RE = re.compile(
    r"(?:收到来自|我开始处理|开始处理|已接单|已收到派单|收到派单|开始执行)",
    re.IGNORECASE,
)
_STAGE_DELIVERY_RE = re.compile(
    r"(?:已验收通过|验收通过|已验收|已完成|任务完成|已交付|交付完成|上线预览|最终交付|本轮.*完成)",
    re.IGNORECASE,
)
_STAGE_DISPATCH_RE = re.compile(
    r"(?:已立刻排入|已排入|已派单|已派给|已分派|派单给|排入.{0,16}队列|单号\s*[`「【(（]?\s*job-)",
    re.IGNORECASE,
)
_STAGE_ERROR_RE = re.compile(
    r"(?:执行失败|任务失败|处理失败|已取消|异常中断|执行超时|❌)",
    re.IGNORECASE,
)
_TOOL_PROGRESS_RE = re.compile(r"(?i)^(?:running\s+tool|tool)\s*[:：]\s*([A-Za-z0-9_.:/-]{1,48})")


def classify_room_message_stage(sender_type: str, sender_role: str, text: str) -> str:
    """Classify a bot group/room message into a lightweight stage tag for UI pipeline badges."""
    if sender_type != "bot":
        return ""
    sample = str(text or "").strip()[:600]
    if not sample:
        return "reply"
    # Check ack first because worker ack messages contain the word "派单"
    if _STAGE_ACK_RE.search(sample):
        return "ack"
    if _STAGE_ERROR_RE.search(sample):
        return "error"
    if _STAGE_DELIVERY_RE.search(sample):
        return "delivery"
    if _STAGE_DISPATCH_RE.search(sample):
        return "dispatch"
    if sender_role == "coordinator" and _JOB_ID_IN_TEXT_RE.search(sample):
        return "dispatch"
    return "reply"


def extract_job_id_from_text(text: str) -> str:
    """Extract the first sanitized `job-...` identifier referenced in message text, if any."""
    m = _JOB_ID_IN_TEXT_RE.search(str(text or "")[:800])
    if not m:
        return ""
    return _sanitize_slug(m.group(1), max_len=32)


def format_job_progress_label(raw_progress: Any, *, fallback: str = "") -> str:
    """Format raw job progress into a strictly sanitized, human-readable short stage label."""
    txt = str(raw_progress or "").strip()
    if not txt:
        return fallback
    m_tool = _TOOL_PROGRESS_RE.match(txt)
    if m_tool:
        tname = _sanitize_slug(m_tool.group(1), max_len=40)
        return f"正在调用工具 · {tname}" if tname else "正在调用工具"
    low = txt.lower()
    if "think" in low or "思考" in low:
        return "正在思考推理"
    if "queue" in low or "排队" in low:
        return "排队等待执行"
    clean = redact_sensitive_text(txt, max_len=64)
    if clean:
        clean = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", clean)
    return clean or fallback


def map_group_history_entry_to_room_message(
    entry: dict[str, Any],
    *,
    room_id: str = "lobby",
    max_content_bytes: int = 16 * 1024,
) -> dict[str, Any]:
    """Map a `group_history/<chat_id>.json` ledger entry to a sanitized `RoomMessageItem` (zero raw IDs)."""
    seq = max(0, int(entry.get("seq") or 0))
    ts_raw = entry.get("ts")
    try:
        ts_val = round(float(ts_raw or 0.0), 3)
    except (TypeError, ValueError):
        ts_val = 0.0

    is_bot = bool(entry.get("is_bot"))
    sender_type = "bot" if is_bot else "human"
    raw_sender = entry.get("sender_handle") or ("bot" if is_bot else "user")
    sender = _sanitize_slug(raw_sender, max_len=64) or sender_type

    raw_role = str(entry.get("sender_role") or "").strip().lower()
    if is_bot:
        sender_role = raw_role if raw_role in _ALLOWED_BOT_ROLES else "bot"
    else:
        sender_role = "human"

    src_raw = str(entry.get("source") or "").strip().lower()
    source = "web" if src_raw == "web" else "tg"

    raw_full = entry.get("full_text")
    if isinstance(raw_full, str) and raw_full.strip():
        raw_text = raw_full
    else:
        raw_text = str(entry.get("text_excerpt") or "")

    stripped_text, parsed_atts, parsed_ctx = extract_message_attachments(raw_text)
    clean_text = studio_ipc.neutralize_control_tags(stripped_text)
    clean_text = redact_secrets_only(clean_text)
    if clean_text:
        clean_text = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", clean_text)
    clean_content, trunc_now = truncate_utf8_bytes(clean_text, max_content_bytes)

    raw_mentions = bot_bus.extract_at_mentions(clean_content)
    mentions = [_sanitize_slug(m, max_len=64).lower() for m in raw_mentions[:4] if _sanitize_slug(m, max_len=64)]
    stage_tag = classify_room_message_stage(sender_type, sender_role, clean_content)
    job_id_ref = extract_job_id_from_text(clean_content) if is_bot else ""

    out_msg: dict[str, Any] = {
        "seq": seq,
        "msg_id": f"tg-{seq}",
        "room_id": room_id,
        "ts": ts_val,
        "sender_type": sender_type,
        "sender": sender,
        "sender_role": sender_role,
        "source": source,
        "content": clean_content,
        "truncated": bool(entry.get("truncated")) or bool(trunc_now),
        "mentions": mentions,
        "chain_id": "",
        "hop": 0,
        "status": "done",
        "blocked_reason": "",
    }
    if stage_tag:
        out_msg["stage_tag"] = stage_tag
    if job_id_ref:
        out_msg["job_id"] = job_id_ref
    if parsed_atts:
        out_msg["attachments"] = parsed_atts
    if parsed_ctx:
        out_msg["context_files"] = parsed_ctx
    return out_msg


class StreamRedactor:
    """Cross-chunk streaming credential redactor with >=256-char sliding tail window,
    convergent cut-boundary stabilization, unclosed-prefix holding, and bounded swallow states."""

    def __init__(self, *, window_size: int = 256, max_hold: int = 4096) -> None:
        self.window_size = max(256, int(window_size))
        self.max_hold = max(self.window_size * 2, int(max_hold))
        self._buf: str = ""
        self._in_pem: bool = False
        self._swallow_mode: str | None = None
        self._swallow_quote: str = ""
        self._swallow_escape: bool = False

    @staticmethod
    def _find_unclosed_prefix(buf: str) -> tuple[int, str, str] | None:
        """Return `(start_idx, swallow_mode, quote_char)` for the earliest unclosed sensitive prefix."""
        best: tuple[int, str, str] | None = None

        last_nl = buf.rfind("\n")
        m_hdr = _UNCLOSED_HEADER_RE.search(buf, last_nl + 1)
        if m_hdr is not None:
            best = (m_hdr.start(), "line", "")

        m_q = _UNCLOSED_QUOTED_CRED_RE.search(buf)
        if m_q is not None:
            q_char = '"' if m_q.group("dq") else "'"
            if best is None or m_q.start() < best[0]:
                best = (m_q.start(), "quote", q_char)

        m_jwt = _UNCLOSED_JWT_RE.search(buf)
        if m_jwt is not None:
            if best is None or m_jwt.start() < best[0]:
                best = (m_jwt.start(), "base64url", "")

        return best

    @staticmethod
    def _swallow_mode_for_pattern(pat: re.Pattern[str]) -> str | None:
        if pat is _QUOTED_CRED_RE:
            return None
        if pat is _COOKIE_LINE_RE or pat is _COOKIE_INLINE_RE:
            return "line"
        if pat is _JWT_RE:
            return "base64url"
        return "token"

    def _enter_swallow(self, mode: str, quote_char: str = "", tail_buf: str = "") -> None:
        self._swallow_mode = mode
        if mode == "quote":
            self._swallow_quote = quote_char
            bs = 0
            for ch in reversed(tail_buf):
                if ch == "\\":
                    bs += 1
                else:
                    break
            self._swallow_escape = (bs % 2) == 1
        else:
            self._swallow_quote = ""
            self._swallow_escape = False

    def feed(self, chunk: Any) -> str:
        if chunk is None:
            return ""
        s = str(chunk)
        if not s:
            return ""
        self._buf += s
        out_parts: list[str] = []

        while self._buf:
            if self._in_pem:
                m_end = _PEM_END_RE.search(self._buf)
                if m_end is not None:
                    self._buf = self._buf[m_end.end():]
                    self._in_pem = False
                    continue
                # Discard swallowed PEM body except a small tail to catch a split END marker
                if len(self._buf) > 128:
                    self._buf = self._buf[-128:]
                break

            if self._swallow_mode is not None:
                mode = self._swallow_mode
                if mode == "line":
                    nl = self._buf.find("\n")
                    if nl == -1:
                        self._buf = ""
                        break
                    keep = nl - 1 if (nl > 0 and self._buf[nl - 1] == "\r") else nl
                    self._buf = self._buf[keep:]
                    self._swallow_mode = None
                    continue
                if mode == "quote":
                    found_close = -1
                    for idx, ch in enumerate(self._buf):
                        if self._swallow_escape:
                            self._swallow_escape = False
                            continue
                        if ch == "\\":
                            self._swallow_escape = True
                            continue
                        if ch == self._swallow_quote:
                            found_close = idx
                            break
                    if found_close == -1:
                        self._buf = ""
                        break
                    self._buf = self._buf[found_close + 1:]
                    self._swallow_mode = None
                    self._swallow_quote = ""
                    self._swallow_escape = False
                    continue
                if mode == "base64url":
                    m_nb = _NON_BASE64URL_RE.search(self._buf)
                    if m_nb is None:
                        self._buf = ""
                        break
                    self._buf = self._buf[m_nb.start():]
                    self._swallow_mode = None
                    continue
                # mode == "token"
                m_tb = _TOKEN_BOUNDARY_RE.search(self._buf)
                if m_tb is None:
                    self._buf = ""
                    break
                self._buf = self._buf[m_tb.start():]
                self._swallow_mode = None
                continue

            m_begin = _PEM_BEGIN_RE.search(self._buf)
            if m_begin is not None:
                prefix = self._buf[: m_begin.start()]
                if prefix:
                    out_parts.append(redact_secrets_only(prefix))
                out_parts.append("[REDACTED]")
                self._buf = self._buf[m_begin.end():]
                self._in_pem = True
                continue

            if len(self._buf) <= self.window_size:
                break

            unclosed = self._find_unclosed_prefix(self._buf)
            cut = len(self._buf) - self.window_size
            if unclosed is not None:
                u_start, u_mode, u_quote = unclosed
                if cut > u_start:
                    if u_start == 0:
                        if len(self._buf) < self.max_hold:
                            break
                        out_parts.append("[REDACTED]")
                        self._enter_swallow(u_mode, u_quote, self._buf)
                        self._buf = ""
                        break
                    cut = u_start

            hold_for_tail = False
            tail_swallow: tuple[int, str, str] | None = None
            changed = True
            while changed:
                changed = False
                for pat in _SECRET_PATTERNS:
                    for m in pat.finditer(self._buf):
                        if m.start() < cut <= m.end():
                            if m.end() >= len(self._buf) - 1:
                                if len(self._buf) < self.max_hold:
                                    hold_for_tail = True
                                    break
                                sw_mode = (
                                    self._swallow_mode_for_pattern(pat)
                                    if m.end() == len(self._buf)
                                    else None
                                )
                                if sw_mode is not None:
                                    if tail_swallow is None or m.start() < tail_swallow[0]:
                                        tail_swallow = (m.start(), sw_mode, "")
                                    hold_for_tail = True
                                    break
                            if m.end() > cut:
                                cut = m.end()
                                changed = True
                                break
                    if hold_for_tail or changed:
                        break
                if not hold_for_tail and unclosed is not None and cut > unclosed[0]:
                    if len(self._buf) < self.max_hold:
                        hold_for_tail = True
                    else:
                        u_start, u_mode, u_quote = unclosed
                        if tail_swallow is None or u_start < tail_swallow[0]:
                            tail_swallow = (u_start, u_mode, u_quote)
                        hold_for_tail = True
                    break

            if tail_swallow is not None:
                if unclosed is not None and unclosed[0] < tail_swallow[0]:
                    tail_swallow = unclosed
                sw_start, sw_mode, sw_quote = tail_swallow
                if sw_start > 0:
                    out_parts.append(redact_secrets_only(self._buf[:sw_start]))
                out_parts.append("[REDACTED]")
                self._enter_swallow(sw_mode, sw_quote, self._buf)
                self._buf = ""
                break

            if hold_for_tail:
                break

            emit_raw = self._buf[:cut]
            self._buf = self._buf[cut:]
            out_parts.append(redact_secrets_only(emit_raw))

        return "".join(out_parts)

    def flush(self) -> str:
        if self._in_pem:
            self._buf = ""
            self._in_pem = False
            return ""
        if self._swallow_mode is not None:
            self._buf = ""
            self._swallow_mode = None
            self._swallow_quote = ""
            self._swallow_escape = False
            return ""
        if not self._buf:
            return ""
        m_unclosed_q = _UNCLOSED_QUOTED_CRED_RE.search(self._buf)
        if m_unclosed_q is not None:
            u_start = m_unclosed_q.start()
            prefix = redact_secrets_only(self._buf[:u_start]) if u_start > 0 else ""
            self._buf = ""
            return prefix + "[REDACTED]"
        rem = redact_secrets_only(self._buf)
        self._buf = ""
        return rem


def redact_sensitive_text(raw: Any, max_len: int = 120) -> str:
    """Deeply redact secrets, credentials, emails, absolute paths, TG/long IDs, and URL queries/fragments."""
    text = str(raw or "").strip()
    if not text:
        return ""
    # 1. Strip URL query, fragment, and embedded credentials first
    text = _URL_IN_TEXT_RE.sub(lambda m: sanitize_url_origin_path(m.group(0)) or "[REDACTED]", text)
    # 2. Redact credentials, tokens, Vault paths, and key/value secrets
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    # 3. Redact emails
    text = _EMAIL_RE.sub("[REDACTED]", text)
    # 4. Redact absolute filesystem paths
    text = _ABS_PATH_RE.sub("[REDACTED]", text)
    # 5. Redact Telegram-shaped negative IDs and standalone 8-15 digit IDs
    text = _TG_AND_LONG_ID_RE.sub("[REDACTED]", text)
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def _read_json_ro(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return default


class StudioDataSources:
    """Read-only aggregator over Bot Bus, Scheduler, Cost Ledger, and Live-Browser status."""

    def __init__(
        self,
        *,
        bus_dir: Path | None = None,
        schedules_file: Path | None = None,
        cost_ledger_file: Path | None = None,
        cost_config_file: Path | None = None,
        quota_cache_file: Path | None = None,
        cost_tz_name: str | None = None,
        live_browser_url: str | None = None,
        live_browser_config_dir: Path | None = None,
        brain_root: Path | None = None,
        summaries_db: Path | None = None,
        meta_file: Path | None = None,
        projects_dir: Path | None = None,
        google_accounts_dir: Path | None = None,
        account_manager: Any | None = None,
    ) -> None:
        home = Path.home()
        agy_root = home / ".gemini" / "antigravity-cli"
        cache_root = agy_root / "cache"
        self.bus_dir = bus_dir or Path(
            os.environ.get("AGY_BOT_BUS_DIR", "").strip() or str(cache_root / "bot_bus")
        )
        self.schedules_file = schedules_file or Path(
            os.environ.get("AGY_STUDIO_SCHEDULES_FILE", str(cache_root / "scheduled_tasks.json"))
        )
        self.cost_ledger_file = cost_ledger_file or Path(
            os.environ.get("AGY_STUDIO_COST_LEDGER", str(cache_root / "cost_ledger_v2.json"))
        )
        self.cost_config_file = cost_config_file or Path(
            os.environ.get("AGY_STUDIO_COST_CONFIG", str(cache_root / "cost_config.json"))
        )
        self.quota_cache_file = quota_cache_file or Path(
            os.environ.get("AGY_STUDIO_QUOTA_CACHE", str(cache_root / "quota_usage.json"))
        )
        self.brain_root = brain_root or Path(
            os.environ.get("AGY_STUDIO_BRAIN_ROOT", str(agy_root / "brain"))
        )
        self.summaries_db = summaries_db or Path(
            os.environ.get("AGY_STUDIO_SUMMARIES_DB", str(agy_root / "conversation_summaries.db"))
        )
        self.meta_file = meta_file or Path(
            os.environ.get("AGY_STUDIO_META_FILE", str(cache_root / "conversation_metadata.json"))
        )
        self.projects_dir = projects_dir or Path(
            os.environ.get("AGY_PROJECTS_DIR", str(home / ".gemini" / "config" / "projects"))
        )
        env_accts_dir = os.environ.get("AGY_GOOGLE_ACCOUNTS_DIR", "").strip()
        self._isolated_mode = any(
            p is not None
            for p in (bus_dir, schedules_file, cost_ledger_file, cost_config_file, quota_cache_file, brain_root)
        )
        if google_accounts_dir is not None:
            self.google_accounts_dir = google_accounts_dir
        elif env_accts_dir:
            self.google_accounts_dir = Path(env_accts_dir)
        elif self._isolated_mode:
            self.google_accounts_dir = self.cost_config_file.parent / "accounts"
        else:
            self.google_accounts_dir = agy_root / "accounts"
        self.account_manager = account_manager
        self.cost_tz_name = cost_tz_name or os.environ.get("AGY_TG_COST_TZ", "Asia/Shanghai")
        self.live_browser_url = (
            live_browser_url or os.environ.get("AGY_LIVE_BROWSER_URL", "http://127.0.0.1:18795")
        ).strip().rstrip("/")
        self.live_browser_config_dir = live_browser_config_dir or Path(
            os.environ.get("AGY_LIVE_BROWSER_CONFIG_DIR", str(home / ".config/agy-live-browser"))
        )

    def read_live_browser_token(self) -> str:
        tok_path = self.live_browser_config_dir / "local.token"
        if not tok_path.is_file():
            return ""
        try:
            return tok_path.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    # ------------------------------------------------------------------ TG Mirror Binding (Internal Only)
    def resolve_tg_mirror(self) -> dict[str, Any]:
        """Resolve server-side TG mirror binding (`AGY_STUDIO_MIRROR_CHAT_ID` env -> `team_config.json`).

        INTERNAL ONLY: callers MUST NEVER expose raw `chat_id` or `thread_id` in HTTP/SSE payloads.
        """
        raw_env = os.environ.get("AGY_STUDIO_MIRROR_CHAT_ID", "").strip()
        if raw_env:
            if raw_env.lower() in ("0", "off", "false", "none", "disabled"):
                return {"bound": False, "chat_id": 0, "thread_id": None, "source": "env_disabled"}
            try:
                env_cid = int(raw_env)
            except ValueError:
                return {"bound": False, "chat_id": 0, "thread_id": None, "source": "invalid"}
            if env_cid >= 0:
                return {"bound": False, "chat_id": 0, "thread_id": None, "source": "invalid"}
            raw_tid = os.environ.get("AGY_STUDIO_MIRROR_THREAD_ID", "").strip()
            env_tid = bot_bus._norm_tid(raw_tid) if raw_tid else None
            return {"bound": True, "chat_id": env_cid, "thread_id": env_tid, "source": "env"}

        cfg_raw = _read_json_ro(self.bus_dir / "team_config.json", {})
        tm = cfg_raw.get("mirror") if isinstance(cfg_raw, dict) and isinstance(cfg_raw.get("mirror"), dict) else {}
        raw_cid = tm.get("chat_id")
        if isinstance(raw_cid, bool):
            cid = 0
        else:
            try:
                cid = int(raw_cid or 0)
            except (TypeError, ValueError):
                cid = 0
        if cid >= 0:
            return {"bound": False, "chat_id": 0, "thread_id": None, "source": "none"}
        tid = bot_bus._norm_tid(tm.get("thread_id"))
        return {"bound": True, "chat_id": cid, "thread_id": tid, "source": "team_config"}

    def read_tg_mirror_history(
        self,
        chat_id: int,
        thread_id: int | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Read-only view of `BUS_DIR/group_history/<chat_id>.json` filtered strictly by `thread_id`."""
        cid = int(chat_id or 0)
        if cid >= 0:
            return [], 0
        norm_tid = bot_bus._norm_tid(thread_id)
        hist_path = self.bus_dir / "group_history" / f"{cid}.json"
        doc = _read_json_ro(hist_path, {})
        if not isinstance(doc, dict):
            return [], 0
        raw_entries = doc.get("entries")
        if not isinstance(raw_entries, list):
            return [], 0
        filtered: list[dict[str, Any]] = []
        max_seq = 0
        for e in raw_entries:
            if not isinstance(e, dict):
                continue
            if bot_bus._norm_tid(e.get("thread_id")) != norm_tid:
                continue
            seq_val = int(e.get("seq") or 0)
            if seq_val > max_seq:
                max_seq = seq_val
            filtered.append(e)
        filtered.sort(key=lambda x: int(x.get("seq") or 0))
        return filtered, max_seq

    # ------------------------------------------------------------------ Bots (Read-Only)
    def get_bots(self) -> dict[str, Any]:
        roster_raw = _read_json_ro(self.bus_dir / "roster.json", {"bots": {}})
        cfg_raw = _read_json_ro(self.bus_dir / "team_config.json", {"bots": {}})
        r_bots = roster_raw.get("bots") if isinstance(roster_raw, dict) else {}
        c_bots = cfg_raw.get("bots") if isinstance(cfg_raw, dict) else {}
        if not isinstance(r_bots, dict):
            r_bots = {}
        if not isinstance(c_bots, dict):
            c_bots = {}

        now = time.time()
        handles = sorted(set(r_bots.keys()) | set(c_bots.keys()))
        items: list[dict[str, Any]] = []
        for h in handles:
            merged = bot_bus._merge_bot_view(h, r_bots.get(h), c_bots.get(h), now)
            role_val = str(merged.get("role") or "worker").lower()
            if role_val not in _ALLOWED_BOT_ROLES:
                role_val = "worker"
            # Strict whitelist: never expose raw chat IDs, host PIDs, raw paths, or unsanitized text
            items.append({
                "handle": _sanitize_slug(merged.get("handle"), max_len=64),
                "display_name": redact_sensitive_text(merged.get("display_name"), max_len=64),
                "role": role_val,
                "online": bool(merged["online"]),
                "busy": bool(merged["busy"]),
                "current_job": _sanitize_slug(merged.get("current_job"), max_len=64) if merged.get("current_job") else None,
                "queue_depth": int(merged["queue_depth"] or 0),
                "specialty": redact_sensitive_text(merged.get("specialty"), max_len=100),
                "model_mode": _sanitize_slug(merged.get("model_mode"), max_len=32),
                "effective_model": _sanitize_slug(merged.get("effective_model") or merged.get("active_model") or "default", max_len=MAX_MODEL_SLUG_LEN),
                "active_model": _sanitize_slug(merged.get("active_model") or "", max_len=MAX_MODEL_SLUG_LEN),
                "default_effort": _sanitize_slug(merged.get("default_effort") or "", max_len=16),
                "default_project": _sanitize_slug(merged.get("default_project") or "", max_len=64),
                "last_seen": float(merged["last_seen"] or 0.0),
            })

        role_order = {"coordinator": 0, "peer": 1, "worker": 2}
        items.sort(key=lambda b: (0 if b["online"] else 1, role_order.get(b["role"], 9), b["handle"]))
        online_count = sum(1 for b in items if b["online"])
        busy_count = sum(1 for b in items if b["busy"])
        return {
            "ok": True,
            "readonly": True,
            "total": len(items),
            "online": online_count,
            "busy": busy_count,
            "bots": items,
        }

    # ------------------------------------------------------------------ Jobs (Read-Only)
    def get_jobs(
        self,
        *,
        limit: int = 30,
        status: str | None = None,
        bot: str | None = None,
    ) -> dict[str, Any]:
        jobs_dir = self.bus_dir / "jobs"
        norm_bot = bot_bus.normalize_handle(bot or "") if bot else ""
        clean_status = (status or "").strip().lower()
        safe_limit = max(1, min(100, int(limit or 30)))

        raw_jobs: list[dict[str, Any]] = []
        if jobs_dir.is_dir():
            try:
                for entry in jobs_dir.iterdir():
                    if not entry.is_file() or not entry.name.endswith(".json") or entry.name.endswith(".tmp"):
                        continue
                    data = _read_json_ro(entry, None)
                    if not isinstance(data, dict):
                        continue
                    if clean_status and str(data.get("status") or "").lower() != clean_status:
                        continue
                    if norm_bot and norm_bot not in (data.get("target_bot"), data.get("from_bot")):
                        continue
                    raw_jobs.append(data)
            except OSError:
                pass

        raw_jobs.sort(key=lambda j: float(j.get("created_at") or 0.0), reverse=True)
        counts: dict[str, int] = {"queued": 0, "running": 0, "done": 0, "error": 0, "cancelled": 0}
        for j in raw_jobs:
            st = str(j.get("status") or "unknown").lower()
            if st in counts:
                counts[st] += 1

        items: list[dict[str, Any]] = []
        for j in raw_jobs[:safe_limit]:
            created = float(j.get("created_at") or 0.0)
            started = float(j.get("started_at") or 0.0)
            finished = float(j.get("finished_at") or 0.0)
            dur = None
            if started > 0 and finished >= started:
                dur = round(finished - started, 1)
            elif started > 0 and str(j.get("status")) == "running":
                dur = round(max(0.0, time.time() - started), 1)
            st_enum = str(j.get("status") or "unknown").lower()
            if st_enum not in _ALLOWED_JOB_STATUSES:
                st_enum = "unknown"
            # Strict whitelist telemetry: NEVER return raw prompt, result_summary, stack traces, or raw URLs
            items.append({
                "job_id": _sanitize_slug(j.get("job_id"), max_len=64),
                "group_id": _sanitize_slug(j.get("group_id"), max_len=64),
                "label": redact_sensitive_text(j.get("label"), max_len=80),
                "from_bot": _sanitize_slug(j.get("from_bot"), max_len=64),
                "target_bot": _sanitize_slug(j.get("target_bot"), max_len=64),
                "status": st_enum,
                "project": _sanitize_slug(j.get("project"), max_len=64),
                "model": _sanitize_slug(j.get("model"), max_len=MAX_MODEL_SLUG_LEN),
                "effort": _sanitize_slug(j.get("effort"), max_len=32),
                "created_at": created,
                "started_at": started or None,
                "finished_at": finished or None,
                "duration_sec": dur,
                "has_summary": bool(j.get("result_summary") or j.get("summary")),
                "has_error": bool(j.get("error")),
                "error_code": _classify_error_code(j.get("error")),
            })

        return {
            "ok": True,
            "readonly": True,
            "total": len(raw_jobs),
            "counts": counts,
            "jobs": items,
        }

    def read_chat_sync_states(self, *, max_running_age_sec: float = 600.0) -> dict[str, dict[str, Any]]:
        """Read-only sanitized per-bot `chat_sync/*.json` runtime status (never exposes cid or chat IDs)."""
        sync_dir = self.bus_dir / "chat_sync"
        out: dict[str, dict[str, Any]] = {}
        if not sync_dir.is_dir():
            return out
        now = time.time()
        try:
            for ent in os.scandir(sync_dir):
                name = ent.name
                if name.startswith(".") or not name.endswith(".json") or name.endswith(".tmp"):
                    continue
                try:
                    st = ent.stat()
                    if not ent.is_file() or st.st_size > 16384:
                        continue
                    doc = _read_json_ro(Path(ent.path), None)
                except OSError:
                    continue
                if not isinstance(doc, dict):
                    continue
                handle = _sanitize_slug(doc.get("bot") or Path(name).stem, max_len=64).lower()
                if not handle:
                    continue
                status_raw = str(doc.get("status") or "").strip().lower()
                if status_raw not in ("running", "done", "aborted", "error"):
                    continue
                src_raw = str(doc.get("source") or "tg").strip().lower()
                source = "web" if src_raw == "web" else "tg"
                try:
                    updated_at = float(doc.get("updated_at") or 0.0)
                except (TypeError, ValueError):
                    updated_at = 0.0
                if updated_at <= 0.0:
                    updated_at = float(st.st_mtime)
                is_running = status_raw == "running" and (now - updated_at) <= max_running_age_sec
                out[handle] = {
                    "bot": handle,
                    "status": "running" if is_running else status_raw,
                    "running": is_running,
                    "source": source,
                    "updated_at": round(updated_at, 3),
                }
        except OSError:
            pass
        return out

    def get_jobs_activity(self, *, limit: int = 12) -> list[dict[str, Any]]:
        """Read-only sanitized recent jobs with live progress label for room activity pipeline."""
        jobs_dir = self.bus_dir / "jobs"
        safe_limit = max(1, min(32, int(limit or 12)))
        raw_jobs: list[dict[str, Any]] = []
        if jobs_dir.is_dir():
            try:
                for entry in jobs_dir.iterdir():
                    if not entry.is_file() or not entry.name.endswith(".json") or entry.name.endswith(".tmp"):
                        continue
                    data = _read_json_ro(entry, None)
                    if isinstance(data, dict):
                        raw_jobs.append(data)
            except OSError:
                pass

        # Prioritize active (running/queued) jobs first, then newest by created_at
        status_rank = {"running": 0, "queued": 1}
        raw_jobs.sort(
            key=lambda j: (
                status_rank.get(str(j.get("status") or "").lower(), 2),
                -float(j.get("created_at") or 0.0),
            )
        )
        now = time.time()
        items: list[dict[str, Any]] = []
        for j in raw_jobs[:safe_limit]:
            created = float(j.get("created_at") or 0.0)
            started = float(j.get("started_at") or 0.0)
            finished = float(j.get("finished_at") or 0.0)
            raw_st = str(j.get("status") or "unknown").strip().lower()
            if raw_st == "error":
                st_norm = "failed"
            elif raw_st in ("queued", "running", "done", "failed", "cancelled"):
                st_norm = raw_st
            else:
                st_norm = "failed" if j.get("error") else "done"
            dur: float | None = None
            if started > 0 and finished >= started:
                dur = round(finished - started, 1)
            elif started > 0 and st_norm == "running":
                dur = round(max(0.0, now - started), 1)
            progress_lbl = (
                format_job_progress_label(j.get("progress"), fallback="正在处理派单")
                if st_norm == "running"
                else ("排队等待执行" if st_norm == "queued" else "")
            )
            items.append({
                "job_id": _sanitize_slug(j.get("job_id"), max_len=64),
                "group_id": _sanitize_slug(j.get("group_id"), max_len=64),
                "bot": _sanitize_slug(j.get("target_bot"), max_len=64),
                "from_bot": _sanitize_slug(j.get("from_bot"), max_len=64),
                "label": redact_sensitive_text(j.get("label"), max_len=80),
                "status": st_norm,
                "progress": progress_lbl,
                "created_at": round(created, 3) if created > 0 else 0.0,
                "started_at": round(started, 3) if started > 0 else None,
                "finished_at": round(finished, 3) if finished > 0 else None,
                "duration_s": dur,
            })
        return items

    def get_allowed_projects(self) -> list[dict[str, str]]:
        """Read server-side project whitelist from `projects_dir` (internal: includes `workdir`)."""
        items: list[dict[str, str]] = []
        seen_ids: set[str] = set()
        if not self.projects_dir.is_dir():
            return items
        try:
            entries = sorted(self.projects_dir.iterdir(), key=lambda p: p.name)
        except OSError:
            return items
        for entry in entries:
            if not entry.is_file() or not entry.name.endswith(".json"):
                continue
            data = _read_json_ro(entry, None)
            if not isinstance(data, dict):
                continue
            pid = str(data.get("id") or entry.stem).strip()
            if not pid or pid in seen_ids:
                continue
            seen_ids.add(pid)
            name = str(data.get("name") or pid).strip()
            wdir = ""
            pres = data.get("projectResources")
            res_list = pres.get("resources") if isinstance(pres, dict) else None
            if isinstance(res_list, list):
                for r in res_list:
                    if not isinstance(r, dict):
                        continue
                    furi = str(
                        r.get("folderUri")
                        or (r.get("gitFolder") or {}).get("folderUri")
                        or ""
                    )
                    if furi.startswith("file://") and not wdir:
                        cand = os.path.realpath(furi[len("file://") :])
                        if os.path.isdir(cand):
                            wdir = cand
            if not wdir and isinstance(data.get("workdir"), str) and data["workdir"].strip():
                cand = os.path.realpath(data["workdir"].strip())
                if os.path.isdir(cand):
                    wdir = cand
            items.append({
                "id": _sanitize_slug(pid, max_len=64),
                "name": redact_secrets_only(name, max_len=80),
                "workdir": wdir,
            })
        return items

    def resolve_allowed_project(self, raw_project: str) -> dict[str, str] | None:
        """Resolve `raw_project` strictly against the server-side project whitelist."""
        q = str(raw_project or "").strip()
        if not q:
            return None
        q_low = q.lower()
        for proj in self.get_allowed_projects():
            if proj["id"] == q or proj["id"].lower() == q_low or proj["name"].lower() == q_low:
                return proj
        return None

    def get_job_detail(self, job_id: str) -> tuple[int, dict[str, Any]]:
        """Read a single job file with strict ID validation, secret/path redaction, and <=32 KiB per-field cap."""
        if not studio_ipc.is_valid_entity_id(job_id):
            return 400, {"ok": False, "source": "studio_api", "error": "非法的 job_id 格式"}
        jobs_root = (self.bus_dir / "jobs").resolve()
        candidate = (jobs_root / f"{job_id}.json").resolve()
        try:
            candidate.relative_to(jobs_root)
        except ValueError:
            return 400, {"ok": False, "source": "studio_api", "error": "非法的 job_id 路径"}
        if not candidate.is_file():
            return 404, {"ok": False, "source": "studio_api", "error": "派工单不存在"}
        j = _read_json_ro(candidate, None)
        if not isinstance(j, dict):
            return 404, {"ok": False, "source": "studio_api", "error": "派工单记录损坏"}

        created = float(j.get("created_at") or 0.0)
        started = float(j.get("started_at") or 0.0)
        finished = float(j.get("finished_at") or 0.0)
        dur = None
        if started > 0 and finished >= started:
            dur = round(finished - started, 1)
        elif started > 0 and str(j.get("status")) == "running":
            dur = round(max(0.0, time.time() - started), 1)
        st_enum = str(j.get("status") or "unknown").lower()
        if st_enum not in _ALLOWED_JOB_STATUSES:
            st_enum = "unknown"

        label_text, trunc_label = redact_job_detail_text(j.get("label") or "", max_bytes=MAX_MESSAGE_BYTES)
        prompt_text, trunc_prompt = redact_job_detail_text(j.get("prompt") or "", max_bytes=MAX_MESSAGE_BYTES)
        raw_res = j.get("result_text") or j.get("result_summary") or j.get("summary") or ""
        result_text, trunc_result = redact_job_detail_text(raw_res, max_bytes=MAX_MESSAGE_BYTES)
        error_text, trunc_error = redact_job_detail_text(j.get("error") or "", max_bytes=MAX_MESSAGE_BYTES)
        progress_text, _ = redact_job_detail_text(j.get("progress") or "", max_bytes=4096)

        trunc_fields: list[str] = []
        if trunc_label:
            trunc_fields.append("label")
        if trunc_prompt:
            trunc_fields.append("prompt")
        if trunc_result:
            trunc_fields.append("result")
        if trunc_error:
            trunc_fields.append("error")

        return 200, {
            "ok": True,
            "job": {
                "job_id": _sanitize_slug(j.get("job_id") or job_id, max_len=64),
                "group_id": _sanitize_slug(j.get("group_id"), max_len=64),
                "label": label_text,
                "from_bot": _sanitize_slug(j.get("from_bot"), max_len=64),
                "target_bot": _sanitize_slug(j.get("target_bot"), max_len=64),
                "status": st_enum,
                "project": _sanitize_slug(j.get("project"), max_len=64),
                "model": _sanitize_slug(j.get("model"), max_len=MAX_MODEL_SLUG_LEN),
                "effort": _sanitize_slug(j.get("effort"), max_len=32),
                "created_at": created,
                "started_at": started or None,
                "finished_at": finished or None,
                "duration_sec": dur,
                "cancel_requested": bool(j.get("cancel_requested")),
                "progress": progress_text,
                "prompt": prompt_text,
                "result": result_text,
                "error": error_text,
                "error_code": _classify_error_code(j.get("error")),
                "truncated": bool(trunc_fields),
                "truncated_fields": trunc_fields,
            },
        }

    # ------------------------------------------------------------------ Schedules (Read-Only)
    def format_schedule_item(
        self,
        t: dict[str, Any],
        *,
        now_utc: datetime.datetime | None = None,
        tz: Any | None = None,
    ) -> dict[str, Any]:
        """Strictly sanitize a single schedule record; NEVER exposes CLI script/precheck command text."""
        now_utc = now_utc or datetime.datetime.now(datetime.timezone.utc)
        if tz is None:
            tz, _ = scheduler.get_scheduler_tz(self.cost_tz_name)
        st = t.get("state") if isinstance(t.get("state"), dict) else {}
        ex = t.get("execution") if isinstance(t.get("execution"), dict) else {}
        deliv = t.get("delivery") if isinstance(t.get("delivery"), dict) else {}
        payload = t.get("payload") if isinstance(t.get("payload"), dict) else {}
        nxt_dt, nxt_iso = _normalize_iso_utc(st.get("next_run_at"))
        last_dt, last_iso = _normalize_iso_utc(st.get("last_run_at"))
        ro_cli = is_read_only_cli_schedule(t)
        ttype = _sanitize_slug(t.get("task_type"), max_len=48)

        # Only expose redacted prompt for WebUI-managed safe types (`prompt`/`reminder`) when NOT read_only_cli
        safe_prompt = ""
        if not ro_cli and ttype in ("prompt", "reminder"):
            safe_prompt, _ = redact_job_detail_text(
                payload.get("prompt") or payload.get("message") or "",
                max_bytes=16 * 1024,
            )

        return {
            "id": _sanitize_slug(t.get("id"), max_len=64),
            "name": redact_sensitive_text(t.get("name"), max_len=80),
            "enabled": bool(t.get("enabled", True)),
            "read_only_cli": ro_cli,
            "schedule_type": _sanitize_slug(t.get("schedule_type"), max_len=32),
            "schedule_expr": redact_sensitive_text(t.get("schedule_expr"), max_len=64),
            "task_type": ttype,
            "model": _sanitize_controlled_label(ex.get("model"), fallback="unknown") if ex.get("model") else "",
            "project": _sanitize_slug(ex.get("project"), max_len=64),
            "bot": _sanitize_slug(t.get("bot") or t.get("bot_instance_id") or "", max_len=64),
            "silent_if_empty": bool(deliv.get("silent_if_empty", True)),
            "prompt": safe_prompt,
            "next_run_at": nxt_iso,
            "next_run_local": nxt_dt.astimezone(tz).strftime("%Y-%m-%d %H:%M") if nxt_dt else None,
            "countdown": scheduler.format_countdown(nxt_dt, now_utc),
            "last_run_at": last_iso,
            "last_run_local": last_dt.astimezone(tz).strftime("%m-%d %H:%M") if last_dt else None,
            "last_status": _sanitize_slug(st.get("last_status") or "pending", max_len=32),
            "run_count": int(st.get("run_count") or 0),
            "has_last_error": bool(st.get("last_error")),
            "last_error_code": _classify_error_code(st.get("last_error")),
        }

    def get_schedules(self) -> dict[str, Any]:
        raw = _read_json_ro(self.schedules_file, {"version": 1, "tasks": {}})
        tasks_map = raw.get("tasks") if isinstance(raw, dict) else {}
        if not isinstance(tasks_map, dict):
            tasks_map = {}

        now_utc = datetime.datetime.now(datetime.timezone.utc)
        tz, tz_lbl = scheduler.get_scheduler_tz(self.cost_tz_name)
        items: list[dict[str, Any]] = []
        for t in tasks_map.values():
            if not isinstance(t, dict):
                continue
            items.append(self.format_schedule_item(t, now_utc=now_utc, tz=tz))

        items.sort(key=lambda x: (not x["enabled"], x["next_run_at"] or "9999"))
        active = sum(1 for x in items if x["enabled"])
        return {
            "ok": True,
            "readonly": True,
            "tz_label": tz_lbl,
            "total": len(items),
            "active": active,
            "paused": len(items) - active,
            "schedules": items,
        }

    # ------------------------------------------------------------------ Costs & Quota (Read-Only)
    def _read_accounts_quota_ro(self) -> tuple[dict[str, Any], dict[str, str]]:
        """Read strictly desensitized multi-plan quota summary and alias map without creating files."""
        empty_summary: dict[str, Any] = {
            "active_account_id": None,
            "total_unique_accounts": 0,
            "total_slots": 0,
            "duplicate_slot_count": 0,
            "for_group": False,
            "tiers": [],
        }
        alias_map: dict[str, str] = {}
        mgr = self.account_manager
        try:
            if mgr is not None and getattr(mgr, "registry_path", None) is not None and mgr.registry_path.is_file():
                summary = mgr.summarize_plan_quotas(for_group=False)
                for acct in mgr.list_accounts(for_group=False):
                    aid = str(acct.get("account_id") or "")
                    if aid:
                        alias_map[aid] = str(acct.get("alias") or aid)
                return summary, alias_map

            reg_path = self.google_accounts_dir / "registry.json"
            if reg_path.is_file() and not reg_path.is_symlink():
                ro_mgr = google_accounts.GoogleAccountManager(
                    root_dir=self.google_accounts_dir,
                    auto_adopt_host=False,
                )
                summary = ro_mgr.summarize_plan_quotas(for_group=False)
                for acct in ro_mgr.list_accounts(for_group=False):
                    aid = str(acct.get("account_id") or "")
                    if aid:
                        alias_map[aid] = str(acct.get("alias") or aid)
                return summary, alias_map
        except Exception:
            pass
        return empty_summary, alias_map

    def get_costs(
        self,
        *,
        scope: str = "all",
        account_id: str | None = None,
        plan_tier: str | None = None,
    ) -> dict[str, Any]:
        if scope not in ("all", "agent", "sched"):
            scope = "all"

        clean_aid: str | None = None
        if isinstance(account_id, str):
            raw_aid = account_id.strip()
            if raw_aid and raw_aid.lower() != "all":
                clean_aid = _sanitize_slug(raw_aid, max_len=64) or None

        clean_tier: str | None = None
        if isinstance(plan_tier, str):
            raw_tier = plan_tier.strip().lower()
            if raw_tier and raw_tier != "all":
                clean_tier = _sanitize_controlled_label(raw_tier, fallback="unknown").lower()

        tz, tz_lbl = cost_usage.get_cost_tz(self.cost_tz_name)
        now_local = datetime.datetime.now(tz)
        now_utc = now_local.astimezone(datetime.timezone.utc)
        today_start = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start_utc, _week_end_utc, week_start_loc, week_end_loc, week_rem_str = (
            cost_usage.get_weekly_quota_bounds(
                now_utc,
                tz,
                str(self.cost_config_file),
                account_id=clean_aid,
            )
        )
        d7_start = today_start - datetime.timedelta(days=6)
        d14_start = today_start - datetime.timedelta(days=13)
        d30_start = today_start - datetime.timedelta(days=29)
        month_prefix = now_local.strftime("%Y-%m")
        today_ymd = now_local.strftime("%Y-%m-%d")

        ledger = _read_json_ro(self.cost_ledger_file, {"conversations": {}})
        convs = ledger.get("conversations") if isinstance(ledger, dict) else {}
        if not isinstance(convs, dict):
            convs = {}

        agg_today = cost_usage.new_cost_agg()
        agg_week = cost_usage.new_cost_agg()
        agg_d7 = cost_usage.new_cost_agg()
        agg_d30 = cost_usage.new_cost_agg()
        agg_month = cost_usage.new_cost_agg()
        by_day: dict[str, dict[str, Any]] = {}
        by_model_week: dict[str, dict[str, Any]] = {}
        by_model_month: dict[str, dict[str, Any]] = {}
        by_account_month_raw: dict[str, dict[str, Any]] = {}
        by_account_tier: dict[str, str] = {}
        by_plan_month_raw: dict[str, dict[str, Any]] = {}
        by_plan_accounts: dict[str, set[str]] = {}

        for entry in convs.values():
            if not isinstance(entry, dict):
                continue
            is_obs = bool(entry.get("is_observer", False))
            is_sched = bool(entry.get("is_scheduled", False))
            if scope == "agent" and (is_obs or is_sched):
                continue
            if scope == "sched" and not is_sched:
                continue
            entry_acct = _sanitize_slug(entry.get("account_id") or "", max_len=64) or "unassigned"
            entry_tier = _sanitize_controlled_label(
                str(entry.get("plan_tier") or "unknown").strip().lower(),
                fallback="unknown",
            ).lower()
            if clean_aid is not None and entry_acct != clean_aid:
                continue
            if clean_tier is not None and entry_tier != clean_tier:
                continue

            hours = entry.get("hours")
            if not isinstance(hours, dict):
                continue
            for hour_utc, fam_map in hours.items():
                try:
                    dt_h = datetime.datetime.strptime(hour_utc, "%Y-%m-%dT%H").replace(
                        tzinfo=datetime.timezone.utc
                    )
                except Exception:
                    continue
                if not isinstance(fam_map, dict):
                    continue
                dt_loc = dt_h.astimezone(tz)
                ymd = dt_loc.strftime("%Y-%m-%d")
                for fam, vals in fam_map.items():
                    if not isinstance(vals, (list, tuple)) or len(vals) < 6:
                        continue
                    inp, ca, out, calls = int(vals[0]), int(vals[1]), int(vals[2]), int(vals[3])
                    cost_u, nocache_u = float(vals[4]), float(vals[5])
                    if ymd == today_ymd:
                        cost_usage.add_cost_agg(agg_today, inp, ca, out, calls, cost_u, nocache_u)
                    if dt_h >= week_start_utc:
                        cost_usage.add_cost_agg(agg_week, inp, ca, out, calls, cost_u, nocache_u)
                        cost_usage.add_cost_agg(
                            by_model_week.setdefault(fam, cost_usage.new_cost_agg()),
                            inp, ca, out, calls, cost_u, nocache_u,
                        )
                    if dt_loc >= d7_start:
                        cost_usage.add_cost_agg(agg_d7, inp, ca, out, calls, cost_u, nocache_u)
                    if dt_loc >= d14_start:
                        cost_usage.add_cost_agg(
                            by_day.setdefault(ymd, cost_usage.new_cost_agg()),
                            inp, ca, out, calls, cost_u, nocache_u,
                        )
                    if dt_loc >= d30_start:
                        cost_usage.add_cost_agg(agg_d30, inp, ca, out, calls, cost_u, nocache_u)
                    if ymd.startswith(month_prefix):
                        cost_usage.add_cost_agg(agg_month, inp, ca, out, calls, cost_u, nocache_u)
                        cost_usage.add_cost_agg(
                            by_model_month.setdefault(fam, cost_usage.new_cost_agg()),
                            inp, ca, out, calls, cost_u, nocache_u,
                        )
                        cost_usage.add_cost_agg(
                            by_account_month_raw.setdefault(entry_acct, cost_usage.new_cost_agg()),
                            inp, ca, out, calls, cost_u, nocache_u,
                        )
                        if by_account_tier.get(entry_acct, "unknown") == "unknown" and entry_tier != "unknown":
                            by_account_tier[entry_acct] = entry_tier
                        else:
                            by_account_tier.setdefault(entry_acct, entry_tier)
                        cost_usage.add_cost_agg(
                            by_plan_month_raw.setdefault(entry_tier, cost_usage.new_cost_agg()),
                            inp, ca, out, calls, cost_u, nocache_u,
                        )
                        by_plan_accounts.setdefault(entry_tier, set()).add(entry_acct)

        def _pack_agg(agg: dict[str, Any]) -> dict[str, Any]:
            tot_tok, cache_pct, _bar, saved, save_pct = cost_usage.agg_metrics(agg)
            return {
                "input_tokens": int(agg["inp"]),
                "cache_read_tokens": int(agg["ca"]),
                "output_tokens": int(agg["out"]),
                "total_tokens": int(tot_tok),
                "calls": int(agg["calls"]),
                "cache_hit_pct": round(cache_pct, 1),
                "cost_usd": round(float(agg["cost"]), 4),
                "nocache_usd": round(float(agg["nocache"]), 4),
                "saved_usd": round(float(saved), 4),
                "save_pct": round(float(save_pct), 1),
            }

        daily_14d: list[dict[str, Any]] = []
        for offset in range(13, -1, -1):
            d_dt = today_start - datetime.timedelta(days=offset)
            ymd = d_dt.strftime("%Y-%m-%d")
            dagg = by_day.get(ymd) or cost_usage.new_cost_agg()
            daily_14d.append({"date": ymd, "label": d_dt.strftime("%m-%d"), **_pack_agg(dagg)})

        def _pack_models(mdict: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
            normalized: dict[str, dict[str, Any]] = {}
            for raw_fam, magg in mdict.items():
                safe_fam = _sanitize_controlled_label(raw_fam, fallback="unknown")
                bucket = normalized.setdefault(safe_fam, cost_usage.new_cost_agg())
                cost_usage.add_cost_agg(
                    bucket,
                    int(magg["inp"]),
                    int(magg["ca"]),
                    int(magg["out"]),
                    int(magg["calls"]),
                    float(magg["cost"]),
                    float(magg["nocache"]),
                )
            rows = []
            for fam, magg in sorted(normalized.items(), key=lambda kv: -kv[1]["cost"]):
                label = cost_usage.MODEL_FAMILY_LABELS.get(fam, fam)
                rows.append({
                    "family": fam,
                    "label": label,
                    **_pack_agg(magg),
                })
            return rows

        accounts_quota, acct_alias_map = self._read_accounts_quota_ro()

        by_account_month: list[dict[str, Any]] = []
        for aid, aagg in sorted(by_account_month_raw.items(), key=lambda kv: (-kv[1]["cost"], kv[0])):
            tier_k = by_account_tier.get(aid, "unknown")
            by_account_month.append({
                "account_id": aid,
                "alias": acct_alias_map.get(aid, "未归属 (历史)" if aid == "unassigned" else aid),
                "plan_tier": tier_k,
                "plan_label": google_accounts.PLAN_TIER_LABELS.get(tier_k, "Unknown"),
                **_pack_agg(aagg),
            })

        by_plan_month: list[dict[str, Any]] = []
        for tier_k, pagg in sorted(
            by_plan_month_raw.items(),
            key=lambda kv: (-kv[1]["cost"], -google_accounts.PLAN_TIER_PRIORITY.get(kv[0], 0), kv[0]),
        ):
            accts_sorted = sorted(by_plan_accounts.get(tier_k, set()))
            by_plan_month.append({
                "plan_tier": tier_k,
                "plan_label": google_accounts.PLAN_TIER_LABELS.get(tier_k, "Unknown"),
                "accounts": accts_sorted,
                "account_count": len(accts_sorted),
                **_pack_agg(pagg),
            })

        quota_snap = cost_usage.load_cached_plan_quota(str(self.quota_cache_file))
        quota_groups: list[dict[str, Any]] = []
        if isinstance(quota_snap, dict):
            for grp in quota_snap.get("groups") or []:
                if not isinstance(grp, dict):
                    continue
                buckets_out = []
                for b in grp.get("buckets") or []:
                    if not isinstance(b, dict):
                        continue
                    rem_frac = max(0.0, min(1.0, float(b.get("remaining_fraction", 0.0))))
                    rst_utc = cost_usage.parse_iso_z(b.get("reset_time"))
                    raw_bname = b.get("name") if b.get("name") is not None else b.get("window")
                    buckets_out.append({
                        "name": _sanitize_controlled_label(raw_bname, fallback="unknown"),
                        "window": _sanitize_controlled_label(b.get("window"), fallback="unknown"),
                        "remaining_pct": round(rem_frac * 100.0, 1),
                        "reset_countdown": cost_usage.fmt_quota_countdown(rst_utc, now_utc),
                    })
                quota_groups.append({
                    "name": _sanitize_controlled_label(grp.get("name"), fallback="unknown"),
                    "buckets": buckets_out,
                })

        return {
            "ok": True,
            "readonly": True,
            "scope": scope,
            "tz_label": tz_lbl,
            "week_window": {
                "start_local": week_start_loc.strftime("%m-%d %H:%M"),
                "end_local": week_end_loc.strftime("%m-%d %H:%M"),
                "remaining": week_rem_str,
            },
            "today": _pack_agg(agg_today),
            "week": _pack_agg(agg_week),
            "month": _pack_agg(agg_month),
            "d7": _pack_agg(agg_d7),
            "d30": _pack_agg(agg_d30),
            "daily_14d": daily_14d,
            "by_model_week": _pack_models(by_model_week),
            "by_model_month": _pack_models(by_model_month),
            "by_account_month": by_account_month,
            "by_plan_month": by_plan_month,
            "accounts_quota": accounts_quota,
            "filter": {
                "account_id": clean_aid,
                "plan_tier": clean_tier,
            },
            "quota_groups": quota_groups,
        }

    # ------------------------------------------------------------------ Browser Status (Read-Only)
    async def get_browser_status(
        self,
        *,
        bot_key: str,
        user_id: int,
        http_session: aiohttp.ClientSession,
    ) -> dict[str, Any]:
        token = self.read_live_browser_token()
        if not token:
            return {
                "ok": True,
                "readonly": True,
                "reachable": False,
                "running": False,
                "engine_mode": "offline",
                "source": "upstream",
                "error": "Live-Browser 本地令牌未初始化",
            }
        url = f"{self.live_browser_url}/internal/status"
        params = {
            "source": "tg_cmd",
            "chat_scope": "private",
            "bot": bot_key,
            "user_id": str(user_id),
        }
        try:
            async with http_session.get(
                url,
                headers={"X-Live-Token": token},
                params=params,
                timeout=aiohttp.ClientTimeout(total=3.0),
            ) as resp:
                if resp.status >= 400:
                    return {
                        "ok": True,
                        "readonly": True,
                        "reachable": False,
                        "running": False,
                        "engine_mode": "error",
                        "source": "upstream",
                        "error": f"Live-Browser HTTP {resp.status}",
                    }
                data = await resp.json()
        except Exception:
            return {
                "ok": True,
                "readonly": True,
                "reachable": False,
                "running": False,
                "engine_mode": "offline",
                "source": "upstream",
                "error": "Live-Browser 服务暂不可达",
            }

        restricted = bool(data.get("session_restricted"))
        is_running = bool(data.get("running")) and not restricted
        # REST status exposes ONLY origin (`scheme://host[:port]`, zero path/query/fragment/userinfo)
        # to eliminate percent-encoded PII leakage via path segments; full navigation remains in owner WS channel.
        safe_url = sanitize_url_origin(data.get("url")) if is_running else ""
        safe_title = redact_sensitive_text(data.get("title"), max_len=120) if is_running else ""
        return {
            "ok": True,
            "readonly": True,
            "reachable": True,
            "running": is_running,
            "session_restricted": restricted,
            "engine_mode": _sanitize_slug(data.get("engine_mode") or "idle", max_len=32),
            "profile": None if restricted else (_sanitize_slug(data.get("profile"), max_len=64) if data.get("profile") else None),
            "pinned": False if restricted else bool(data.get("pinned")),
            "egress": "" if restricted else _sanitize_slug(data.get("egress") or "direct", max_len=32),
            "os": "" if restricted else _sanitize_slug(data.get("os") or "", max_len=32),
            "takeover": False if restricted else bool(data.get("takeover")),
            "takeover_reason": "" if restricted else redact_sensitive_text(data.get("takeover_reason") or "", max_len=160),
            "ai_busy": False if restricted else bool(data.get("ai_busy")),
            "url": safe_url,
            "title": safe_title,
            "vw": int(data.get("vw") or 1280),
            "vh": int(data.get("vh") or 800),
            "quality_preset": _sanitize_slug(data.get("quality_preset") or "balanced", max_len=32),
            "viewers": int(data.get("viewers") or 0),
            "tabs_count": 0 if restricted else len(data.get("tabs") or []),
        }

    # ------------------------------------------------------------------ Overview (Read-Only)
    async def get_overview(
        self,
        *,
        session: dict[str, Any],
        http_session: aiohttp.ClientSession,
    ) -> dict[str, Any]:
        bots = self.get_bots()
        jobs = self.get_jobs(limit=10)
        schedules = self.get_schedules()
        costs = self.get_costs(scope="all")
        browser = await self.get_browser_status(
            bot_key=str(session["bot"]),
            user_id=int(session["user_id"]),
            http_session=http_session,
        )
        return {
            "ok": True,
            "readonly": True,
            "generated_at": int(time.time()),
            "viewer": {
                "bot": session["bot"],
                "user_id": session["user_id"],
                "role": session["role"],
                "auth_track": session["auth_track"],
            },
            "summary": {
                "bots_total": bots["total"],
                "bots_online": bots["online"],
                "bots_busy": bots["busy"],
                "jobs_total": jobs["total"],
                "jobs_running": jobs["counts"]["running"],
                "jobs_queued": jobs["counts"]["queued"],
                "jobs_error": jobs["counts"]["error"],
                "schedules_total": schedules["total"],
                "schedules_active": schedules["active"],
                "today_cost_usd": costs["today"]["cost_usd"],
                "today_tokens": costs["today"]["total_tokens"],
                "today_cache_hit_pct": costs["today"]["cache_hit_pct"],
                "week_cost_usd": costs["week"]["cost_usd"],
                "week_saved_usd": costs["week"]["saved_usd"],
                "month_cost_usd": costs["month"]["cost_usd"],
            },
            "browser": browser,
            "recent_jobs": jobs["jobs"][:5],
        }

    # ------------------------------------------------------------------ Sessions & Bounded Transcript Replay (Read-Only)
    def get_sessions(
        self,
        *,
        limit: int | None = 30,
        bot: str | None = None,
        source: str | None = None,
        q: str | None = None,
    ) -> dict[str, Any]:
        safe_limit = max(1, min(100, 30 if limit is None else int(limit)))
        q_low = (q or "").strip().lower()
        src_filter = (source or "all").strip().lower()
        bot_filter = bot_bus.normalize_handle(bot or "") if bot else ""

        raw_rows: dict[str, dict[str, Any]] = {}

        if self.summaries_db.is_file():
            try:
                conn = sqlite3.connect(f"file:{self.summaries_db}?mode=ro", uri=True, timeout=2.0)
                try:
                    rows = conn.execute(
                        "SELECT last_modified_time, conversation_id, preview, workspace_uris, project_id, agent_name "
                        "FROM conversation_summaries ORDER BY last_modified_time DESC LIMIT 300"
                    ).fetchall()
                finally:
                    conn.close()
                for upd, cid, preview, ws_raw, pid, agent_name in rows:
                    cid_s = str(cid or "").strip()
                    if not studio_ipc.is_valid_cid(cid_s):
                        continue
                    if studio_ipc.is_excluded_session_meta(
                        {"workspace_uris": ws_raw, "agent_name": agent_name}
                    ):
                        continue
                    prev_s = str(preview or "")
                    if "[ACB_SCHEDULED_TASK" in prev_s or "[ACB_TEAM_DELEGATION" in prev_s:
                        continue
                    raw_rows[cid_s] = {
                        "cid": cid_s,
                        "updated_at": str(upd or ""),
                        "preview": prev_s,
                        "project_id": _sanitize_slug(pid or "", max_len=64),
                        "source": "tg" if "[TG" in prev_s else "session",
                        "bot": "",
                    }
            except Exception:
                pass

        if self.meta_file.is_file():
            meta_doc = _read_json_ro(self.meta_file, {})
            convs = meta_doc.get("conversations") if isinstance(meta_doc, dict) else {}
            if isinstance(convs, dict):
                for cid_k, entry in convs.items():
                    cid_s = str(cid_k or "").strip()
                    if not studio_ipc.is_valid_cid(cid_s) or not isinstance(entry, dict):
                        continue
                    if studio_ipc.is_excluded_session_meta(entry):
                        raw_rows.pop(cid_s, None)
                        continue
                    s = entry.get("summary") if isinstance(entry.get("summary"), dict) else {}
                    prev_s = str(s.get("Preview") or "")
                    if "[ACB_SCHEDULED_TASK" in prev_s or "[ACB_TEAM_DELEGATION" in prev_s:
                        continue
                    if cid_s not in raw_rows:
                        raw_rows[cid_s] = {
                            "cid": cid_s,
                            "updated_at": str(s.get("UpdatedAt") or ""),
                            "preview": prev_s,
                            "project_id": _sanitize_slug(s.get("ProjectID") or "", max_len=64),
                            "source": str(entry.get("source") or "session"),
                            "bot": _sanitize_slug(entry.get("bot") or "", max_len=64),
                        }

        wt_by_cid: dict[str, dict[str, Any]] = {}
        try:
            reg_wts = bot_bus.load_studio_worktrees(str(self.bus_dir))
            for wt_id, wt_meta in reg_wts.items():
                if not isinstance(wt_meta, dict) or not wt_meta.get("active"):
                    continue
                wt_cid = str(wt_meta.get("cid") or "").strip()
                if not wt_cid:
                    continue
                pid_wt = str(wt_meta.get("project_id") or "").strip()
                # Verify worktree directory still exists (non-symlink) if project is whitelisted
                if pid_wt:
                    proj_wt = self.resolve_allowed_project(pid_wt)
                    if proj_wt and proj_wt.get("workdir"):
                        ok_d, _p, _sc, _e = bot_bus.resolve_studio_worktree_dir(proj_wt["workdir"], wt_id)
                        if not ok_d:
                            continue
                wt_by_cid[wt_cid] = bot_bus.sanitize_studio_worktree_meta(wt_meta)
        except Exception:
            pass

        items: list[dict[str, Any]] = []
        for row in raw_rows.values():
            clean_preview = redact_secrets_only(row.get("preview") or "", max_len=160).strip()
            title = clean_preview.splitlines()[0][:80] if clean_preview else row["cid"][:12]
            item_src = str(row.get("source") or "session").lower()
            item_bot = str(row.get("bot") or "")
            if src_filter not in ("", "all") and item_src != src_filter:
                continue
            if bot_filter and item_bot and bot_bus.normalize_handle(item_bot) != bot_filter:
                continue
            if q_low and (q_low not in clean_preview.lower() and q_low not in row["cid"].lower() and q_low not in row["project_id"].lower()):
                continue
            sess_item: dict[str, Any] = {
                "cid": row["cid"],
                "title": title,
                "preview": clean_preview,
                "updated_at": str(row.get("updated_at") or ""),
                "project_id": row["project_id"],
                "source": item_src,
                "bot": item_bot,
                "busy": studio_ipc.is_conversation_locked(self.bus_dir, row["cid"]),
            }
            bound_wt = wt_by_cid.get(row["cid"])
            if bound_wt is not None:
                sess_item["worktree"] = bound_wt
                if not sess_item["project_id"] and bound_wt.get("project_id"):
                    sess_item["project_id"] = str(bound_wt["project_id"])
            items.append(sess_item)

        items.sort(key=lambda x: x["updated_at"], reverse=True)
        return {
            "ok": True,
            "total": len(items),
            "sessions": items[:safe_limit],
        }

    def get_session_messages(
        self,
        cid: str,
        *,
        limit: int | None = 40,
        before: int | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Read paginated transcript messages via bounded reverse seek (NEVER full-file readlines)."""
        ok_cid, err_cid, sc_cid = studio_ipc.validate_resume_cid(
            cid,
            summaries_db=self.summaries_db,
            meta_file=self.meta_file,
        )
        if not ok_cid:
            return sc_cid, {"ok": False, "error": err_cid, "source": "studio_api"}

        safe_limit = max(1, min(100, 40 if limit is None else int(limit)))
        tpath = (self.brain_root / cid / ".system_generated" / "logs" / "transcript.jsonl").resolve()
        try:
            tpath.relative_to(self.brain_root.resolve())
        except ValueError:
            return 400, {"ok": False, "error": "非法会话路径", "source": "studio_api"}

        if not tpath.is_file():
            return 404, {"ok": False, "error": "会话记录不存在", "source": "studio_api"}

        file_size = tpath.stat().st_size
        end_pos = file_size if (before is None or before <= 0 or before > file_size) else int(before)

        collected: list[tuple[int, dict[str, Any]]] = []
        scanned_bytes = 0
        pos = end_pos
        carry = b""

        with open(tpath, "rb") as fh:
            while pos > 0 and len(collected) < safe_limit and scanned_bytes < MAX_TRANSCRIPT_SCAN_BYTES:
                read_size = min(_TRANSCRIPT_CHUNK_BYTES, pos)
                pos -= read_size
                fh.seek(pos)
                block = fh.read(read_size)
                scanned_bytes += len(block)
                buf = block + carry
                lines = buf.split(b"\n")
                if pos > 0:
                    carry = lines[0]
                    lines = lines[1:]
                else:
                    carry = b""

                # Compute exact byte start offsets for each line in reverse order
                cursor_off = pos + len(carry) + (1 if pos > 0 else 0)
                line_spans: list[tuple[int, bytes]] = []
                for ln in lines:
                    line_spans.append((cursor_off, ln))
                    cursor_off += len(ln) + 1

                for line_off, raw_ln in reversed(line_spans):
                    if not raw_ln.strip():
                        continue
                    try:
                        obj = json.loads(raw_ln.decode("utf-8", errors="replace"))
                    except Exception:
                        continue
                    if not isinstance(obj, dict):
                        continue
                    msg = self._parse_transcript_message(obj, line_off)
                    if msg is not None:
                        collected.append((line_off, msg))
                        if len(collected) >= safe_limit:
                            break

        collected.reverse()
        messages = [m for _off, m in collected]
        oldest_off = collected[0][0] if collected else 0
        has_more = bool(collected and oldest_off > 0)
        return 200, {
            "ok": True,
            "cid": cid,
            "messages": messages,
            "has_more": has_more,
            "next_before": oldest_off if has_more else None,
            "total_returned": len(messages),
        }

    @staticmethod
    def _parse_transcript_message(obj: dict[str, Any], byte_offset: int) -> dict[str, Any] | None:
        step_type = str(obj.get("type") or "")
        if step_type == "USER_INPUT":
            raw_content = str(obj.get("content") or "")
            stripped_content, parsed_atts, parsed_ctx = extract_message_attachments(raw_content)
            redacted = redact_secrets_only(stripped_content)
            if (
                parsed_atts
                or parsed_ctx
                or _ATT_BLOCK_HEADER in raw_content
                or _CTX_BLOCK_HEADER in raw_content
            ):
                redacted = _SENSITIVE_HOST_PATH_RE.sub("[REDACTED]", redacted)
            content, truncated = truncate_utf8_bytes(redacted, MAX_MESSAGE_BYTES)
            out_u: dict[str, Any] = {
                "id": f"step-{obj.get('step_index', byte_offset)}",
                "role": "user",
                "content": content,
                "truncated": truncated,
                "created_at": str(obj.get("created_at") or ""),
                "byte_offset": byte_offset,
            }
            if parsed_atts:
                out_u["attachments"] = parsed_atts
            if parsed_ctx:
                out_u["context_files"] = parsed_ctx
            return out_u
        if step_type == "PLANNER_RESPONSE":
            raw_content = str(obj.get("content") or "")
            raw_thinking = str(obj.get("thinking") or "")
            raw_tools = obj.get("tool_calls") if isinstance(obj.get("tool_calls"), list) else []
            if not raw_content.strip() and not raw_thinking.strip() and not raw_tools:
                return None
            red_content = redact_secrets_only(raw_content)
            content, truncated_c = truncate_utf8_bytes(red_content, MAX_MESSAGE_BYTES)
            red_thinking = redact_secrets_only(raw_thinking)
            thinking, truncated_t = truncate_utf8_bytes(red_thinking, MAX_MESSAGE_BYTES)
            safe_tools: list[dict[str, Any]] = []
            for tc in raw_tools[:20]:
                if not isinstance(tc, dict):
                    continue
                tname = _sanitize_slug(tc.get("name") or tc.get("tool_name") or "tool", max_len=64)
                safe_tools.append({"name": tname})
            return {
                "id": f"step-{obj.get('step_index', byte_offset)}",
                "role": "assistant",
                "content": content,
                "thinking": thinking,
                "tool_calls": safe_tools,
                "status": _sanitize_slug(obj.get("status") or "DONE", max_len=24),
                "truncated": bool(truncated_c or truncated_t),
                "created_at": str(obj.get("created_at") or ""),
                "byte_offset": byte_offset,
            }
        return None
