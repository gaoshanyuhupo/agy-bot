#!/usr/bin/env python3
"""Single-Writer Unix Domain Socket IPC server for Bridge <-> AGY Studio.

Provides zero-dependency stdlib HTTP/1.1-over-UDS IPC with:
- Strict directory (`0700`) and socket/token (`0600`) permissions
- Kernel `SO_PEERCRED` UID verification (`peer_uid == os.getuid()`)
- Constant-time `X-Bridge-IPC-Token` verification (256-bit atomic token file)
- Unconditional rejection of proxy forwarding headers (`X-Forwarded-For`,
  `CF-Connecting-IP`, `X-Real-IP`)
- Zero trust in caller-supplied `role` fields: Bridge always recomputes live RBAC
- Cross-process `fcntl.flock` conversation leases (`BUS_DIR/conv_locks/<sha256(cid)>.lock`)
- Bounded per-bot turn event ring buffer (<= 32 turns; <= 512 events & <= 2 MiB per turn)
"""

from __future__ import annotations

import collections
import fcntl
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import sqlite3
import struct
import threading
import time
from typing import Any, Callable, Iterator
import urllib.parse

CID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
TG_TURN_ID_RE = re.compile(r"^tg-[a-f0-9]{16}$")
ENTITY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$")
MAX_PROMPT_BYTES = 32 * 1024
MAX_TG_GROUP_CONTENT_BYTES = 16 * 1024
MAX_IPC_BODY_BYTES = 128 * 1024

DEFAULT_MAX_TURNS = 32
DEFAULT_MAX_EVENTS_PER_TURN = 512
DEFAULT_MAX_BYTES_PER_TURN = 2 * 1024 * 1024

_FORBIDDEN_PROXY_HEADERS = frozenset({"x-forwarded-for", "cf-connecting-ip", "x-real-ip"})
_TERMINAL_EVENTS = frozenset({"done", "aborted", "error"})
CHAT_SYNC_ALLOWED_KEYS = frozenset({"bot", "cid", "source", "status", "updated_at", "seq"})
_CHAT_SYNC_SOURCES = frozenset({"web", "tg"})
_CHAT_SYNC_STATUSES = frozenset({"running", "done", "aborted", "error"})
_UNTRUSTED_CLIENT_SEND_KEYS = ("role", "chat_id", "target_chat_id", "thread_id", "target_thread_id")
_FORBIDDEN_UNDO_IPC_KEYS = frozenset({
    "workdir",
    "changes",
    "sha1",
    "pre_sha1",
    "post_sha1",
    "ipc_sock",
    "path",
    "files",
})
_FORBIDDEN_BOT_CONFIG_IPC_KEYS = frozenset({
    "workdir",
    "default_workdir",
    "ipc_sock",
    "env",
    "headers",
    "command",
    "args",
    "url",
    "reload_file",
    "allowed_chats",
    "mirror_chat_id",
    "mirror_thread_id",
    "token",
    "secret",
    "password",
})
_FORBIDDEN_BOT_PROFILE_IPC_KEYS = frozenset({
    "workdir",
    "default_workdir",
    "ipc_sock",
    "role",
    "path",
    "reload_file",
    "env",
    "headers",
    "command",
    "cmd",
    "args",
    "url",
    "shell",
    "script",
    "token",
    "secret",
    "password",
    "pid",
    "allowed_chats",
    "mirror_chat_id",
    "mirror_thread_id",
    "chat_id",
    "thread_id",
})
_BOT_SKILL_SLUG_IPC_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_FORBIDDEN_BOT_SKILL_SLUGS = frozenset({".", "..", "__proto__", "constructor", "prototype"})
_FORBIDDEN_RELOAD_IPC_KEYS = frozenset({
    "reload_file",
    "cmd",
    "command",
    "shell",
    "script",
    "workdir",
    "ipc_sock",
    "env",
})
_FORBIDDEN_ROOM_IPC_KEYS = frozenset({
    "workdir",
    "ipc_sock",
    "script",
    "precheck_cmd",
    "reload_file",
    "command",
    "cmd",
    "shell",
})
_FORBIDDEN_ATTENTION_IPC_KEYS = frozenset({
    "workdir",
    "ipc_sock",
    "script",
    "precheck_cmd",
    "reload_file",
    "command",
    "cmd",
    "shell",
})
_FORBIDDEN_TG_GROUP_IPC_KEYS = frozenset({
    "role",
    "chat_id",
    "target_chat_id",
    "thread_id",
    "target_thread_id",
    "mirror_chat_id",
    "mirror_thread_id",
    "scope_key",
    "workdir",
    "ipc_sock",
    "script",
    "precheck_cmd",
    "reload_file",
    "command",
    "cmd",
    "shell",
})
_ALLOWED_TG_GROUP_IPC_KEYS = frozenset({
    "user_id",
    "actor_username",
    "content",
    "project",
    "mirror_human_to_tg",
    "origin_msg_id",
    "priority",
    "interrupt_current",
})
_FORBIDDEN_ACCOUNT_RECYCLE_IPC_KEYS = frozenset({
    "role",
    "cmd",
    "command",
    "shell",
    "script",
    "workdir",
    "ipc_sock",
    "token_path",
    "reload_file",
    "env",
    "profile_dir",
    "host_token_path",
    "access_token",
    "refresh_token",
    "id_token",
    "oauth_state",
    "code",
})
_ALLOWED_ACCOUNT_RECYCLE_IPC_KEYS = frozenset({
    "user_id",
    "actor_username",
    "account_id",
    "reason",
})
_ACCOUNT_ID_IPC_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
_FORBIDDEN_ACCOUNT_ID_IPC_NAMES = frozenset({".", "..", "__proto__", "constructor", "prototype"})
_VALID_IPC_PRIORITIES = frozenset({"normal", "urgent"})
UNDO_ENTRY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
WORKTREE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$")
SHA1_HEX_RE = re.compile(r"^[0-9a-f]{40}$")
ROOM_ID_IPC_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")
ATTENTION_ID_IPC_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$")
_FORBIDDEN_CHAT_SEND_IPC_KEYS = frozenset({
    "workdir",
    "cwd",
    "worktree_path",
    "root",
    "dir_abs",
    "abs_path",
    "ipc_sock",
})
_FORBIDDEN_WORKTREE_CLEANUP_IPC_KEYS = frozenset({
    "workdir",
    "cwd",
    "worktree_path",
    "root",
    "path",
    "repo_root",
    "branch",
    "ipc_sock",
    "role",
    "cmd",
    "command",
    "shell",
    "script",
})
_ALLOWED_WORKTREE_CLEANUP_IPC_KEYS = frozenset({
    "user_id",
    "actor_username",
    "worktree_id",
    "project_id",
    "force",
})
_IPC_INVISIBLE_FORMAT_RE = re.compile(r"[\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_IPC_FULLWIDTH_TAG_TRANS = str.maketrans(
    {
        "\uff3b": "[",  # ［
        "\uff3d": "]",  # ］
        "\u3010": "[",  # 【
        "\u3011": "]",  # 】
        "\uff0f": "/",  # ／
        "\uff3f": "_",  # ＿
        "\uff0d": "-",  # －
        **{chr(c): chr(c - 0xFEE0) for c in range(0xFF10, 0xFF1A)},  # ０-９
        **{chr(c): chr(c - 0xFEE0) for c in range(0xFF21, 0xFF3B)},  # Ａ-Ｚ
        **{chr(c): chr(c - 0xFEE0) for c in range(0xFF41, 0xFF5B)},  # ａ-ｚ
    }
)
_IPC_FORGED_TAG_RE = re.compile(
    r"\[(?=\s*/?\s*(?:ACB_|REPO_WATCH_|BENCHMARK_|UNTRUSTED_|SILENT\b|NO_HANDOFF_|AGY_MEMORY_READONLY))",
    re.IGNORECASE,
)
_IPC_ROOM_ENVELOPE_HEADER_RE = re.compile(r"^\[UNTRUSTED_WEB_ROOM_MESSAGE [^\[\]\r\n]+\]$")
_IPC_ROOM_ENVELOPE_FOOTER = "[/UNTRUSTED_WEB_ROOM_MESSAGE]"


def neutralize_control_tags(raw: Any) -> str:
    """Strip invisible format chars, normalize fullwidth tag chars, and neutralize forged bracket tags to a fixed point."""
    if raw is None:
        return ""
    text = str(raw)
    for _ in range(8):
        nxt = _IPC_INVISIBLE_FORMAT_RE.sub("", text)
        nxt = nxt.translate(_IPC_FULLWIDTH_TAG_TRANS)
        nxt = _IPC_FORGED_TAG_RE.sub("(", nxt)
        if nxt == text:
            break
        text = nxt
    return text


def _neutralize_room_ipc_prompt(prompt: str) -> str:
    """Neutralize all forged tags inside a room turn prompt while preserving a valid outer Studio untrusted envelope."""
    lines = str(prompt or "").splitlines()
    if (
        len(lines) >= 2
        and _IPC_ROOM_ENVELOPE_HEADER_RE.fullmatch(lines[0].strip())
        and lines[-1].strip() == _IPC_ROOM_ENVELOPE_FOOTER
    ):
        clean_header = _IPC_INVISIBLE_FORMAT_RE.sub("", lines[0].strip()).translate(_IPC_FULLWIDTH_TAG_TRANS)
        if _IPC_ROOM_ENVELOPE_HEADER_RE.fullmatch(clean_header):
            inner = "\n".join(lines[1:-1])
            return f"{clean_header}\n{neutralize_control_tags(inner)}\n{_IPC_ROOM_ENVELOPE_FOOTER}"
    return neutralize_control_tags(prompt)


def is_valid_room_id(raw: Any) -> bool:
    if not isinstance(raw, str):
        return False
    if ".." in raw or "/" in raw or "\\" in raw or "\x00" in raw:
        return False
    return bool(ROOM_ID_IPC_RE.fullmatch(raw))


def is_valid_attention_id(raw: Any) -> bool:
    if not isinstance(raw, str):
        return False
    if ".." in raw or "/" in raw or "\\" in raw or "\x00" in raw:
        return False
    return bool(ATTENTION_ID_IPC_RE.fullmatch(raw))


def is_valid_undo_entry_id(raw: Any) -> bool:
    """Strictly validate an undo/redo checkpoint entry_id."""
    if not isinstance(raw, str):
        return False
    return bool(UNDO_ENTRY_ID_RE.fullmatch(raw))


def is_valid_worktree_id(raw: Any) -> bool:
    """Strictly validate a worktree slug (`^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$`)."""
    if not isinstance(raw, str):
        return False
    if ".." in raw or "/" in raw or "\\" in raw or "\x00" in raw:
        return False
    return bool(WORKTREE_ID_RE.fullmatch(raw))


def is_valid_sha1_hex(raw: Any) -> bool:
    """Strictly validate a 40-char lowercase hexadecimal SHA-1 digest."""
    if not isinstance(raw, str):
        return False
    return bool(SHA1_HEX_RE.fullmatch(raw))


def _find_forbidden_ipc_key(obj: Any, forbidden: frozenset[str], *, depth: int = 0) -> str | None:
    if depth > 16:
        return "max_depth_exceeded"
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).strip().lower()
            if kl in forbidden:
                return kl
            found = _find_forbidden_ipc_key(v, forbidden, depth=depth + 1)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_forbidden_ipc_key(item, forbidden, depth=depth + 1)
            if found:
                return found
    return None

_chat_sync_seq_lock = threading.Lock()
_chat_sync_seq = 0


def normalize_ipc_handle(raw: str) -> str:
    """Normalize a bot handle into a safe filename slug for IPC socket/token files."""
    s = str(raw or "").strip().lstrip("@").lower()
    s = re.sub(r"[^a-z0-9_.-]+", "_", s)
    return s[:64] or "bridge"


def is_valid_cid(raw: Any) -> bool:
    """Strictly validate a conversation ID (`^[A-Za-z0-9_-]{8,64}$`)."""
    if not isinstance(raw, str):
        return False
    return bool(CID_RE.fullmatch(raw))


def is_valid_tg_turn_id(raw: Any) -> bool:
    """Strictly validate a Telegram DM live-stream turn ID (`^tg-[a-f0-9]{16}$`)."""
    if not isinstance(raw, str):
        return False
    return bool(TG_TURN_ID_RE.fullmatch(raw))


def write_chat_sync_atomic(
    bus_dir: str | Path,
    bot_handle: str,
    *,
    cid: str,
    source: str,
    status: str,
) -> Path | None:
    """Atomically write a strictly allowlisted `BUS_DIR/chat_sync/<handle>.json` signal file.

    Directory is enforced to `0700` and file is written via tmp + `fsync` + `0600` + `os.replace`.
    Only allowlisted metadata keys (`bot`, `cid`, `source`, `status`, `updated_at`, `seq`) are ever written.
    """
    global _chat_sync_seq
    if not is_valid_cid(cid):
        return None
    src = str(source or "").strip().lower()
    if src not in _CHAT_SYNC_SOURCES:
        return None
    st = str(status or "").strip().lower()
    if st not in _CHAT_SYNC_STATUSES:
        return None

    handle = normalize_ipc_handle(bot_handle)
    with _chat_sync_seq_lock:
        _chat_sync_seq += 1
        seq_val = _chat_sync_seq

    payload = {
        "bot": handle,
        "cid": str(cid),
        "source": src,
        "status": st,
        "updated_at": round(time.time(), 3),
        "seq": seq_val,
    }
    raw_bytes = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")

    sync_dir = Path(bus_dir) / "chat_sync"
    sync_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(sync_dir, 0o700)

    target_path = sync_dir / f"{handle}.json"
    tmp_path = sync_dir / f".{handle}.json.tmp.{os.getpid()}.{secrets.token_hex(6)}"
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw_bytes)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, target_path)
        return target_path
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def is_valid_entity_id(raw: Any) -> bool:
    """Strictly validate a job/schedule ID (no path traversal, no slashes, 2..64 safe chars)."""
    if not isinstance(raw, str):
        return False
    if ".." in raw or "/" in raw or "\\" in raw:
        return False
    return bool(ENTITY_ID_RE.fullmatch(raw))


def parse_strict_user_id(raw: Any) -> int | None:
    """Parse a positive integer user_id strictly (rejecting bool, float, or non-digits)."""
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw > 0 else None
    if isinstance(raw, str):
        s = raw.strip()
        if s.isascii() and s.isdigit():
            val = int(s)
            return val if val > 0 else None
    return None


def is_excluded_session_meta(meta: dict[str, Any] | None) -> bool:
    """Return True if session metadata indicates an internal/observer/pure-llm session."""
    if not isinstance(meta, dict):
        return False
    agent_name = str(meta.get("agent_name") or "").strip().lower()
    if agent_name == "pure-llm":
        return True
    ws_raw = meta.get("workspace_uris")
    if isinstance(ws_raw, list):
        ws_str = " ".join(str(x) for x in ws_raw)
    else:
        ws_str = str(ws_raw or "")
    if "observer-sandbox" in ws_str.lower():
        return True
    if meta.get("Internal") or meta.get("is_internal"):
        return True
    summary = meta.get("summary")
    if isinstance(summary, dict):
        if summary.get("Internal") or summary.get("is_internal"):
            return True
        sum_uris = summary.get("WorkspaceURIs")
        if isinstance(sum_uris, list) and any("observer-sandbox" in str(u).lower() for u in sum_uris):
            return True
    return False


def validate_resume_cid(
    raw_cid: Any,
    *,
    summaries_db: str | Path | None = None,
    meta_file: str | Path | None = None,
) -> tuple[bool, str, int]:
    """Validate `/resume` cid syntax and reject internal/excluded sessions.

    Returns `(ok, error_message, http_status)`.
    """
    if not is_valid_cid(raw_cid):
        return False, "无效的会话 ID 格式（须匹配 ^[A-Za-z0-9_-]{8,64}$）", 400
    cid = str(raw_cid)

    if summaries_db and os.path.isfile(str(summaries_db)):
        try:
            conn = sqlite3.connect(f"file:{summaries_db}?mode=ro", uri=True, timeout=2.0)
            try:
                row = conn.execute(
                    "SELECT workspace_uris, agent_name FROM conversation_summaries WHERE conversation_id = ?",
                    (cid,),
                ).fetchone()
            finally:
                conn.close()
            if row is not None:
                ws_raw, agent_name = row[0], row[1]
                if is_excluded_session_meta({"workspace_uris": ws_raw, "agent_name": agent_name}):
                    return False, "禁止恢复内部或受限会话", 403
        except Exception:
            pass

    if meta_file and os.path.isfile(str(meta_file)):
        try:
            with open(str(meta_file), "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
            convs = data.get("conversations") if isinstance(data, dict) else {}
            if isinstance(convs, dict) and cid in convs:
                entry = convs.get(cid)
                if is_excluded_session_meta(entry):
                    return False, "禁止恢复内部或受限会话", 403
        except Exception:
            pass

    return True, "", 200


# ---------------------------------------------------------------------------
# Cross-process conversation lease (`BUS_DIR/conv_locks/<sha256(cid)>.lock`)
# ---------------------------------------------------------------------------


def conv_lock_path(bus_dir: str | Path, cid: str) -> Path:
    digest = hashlib.sha256(cid.encode("utf-8")).hexdigest()
    return Path(bus_dir) / "conv_locks" / f"{digest}.lock"


def is_conversation_locked(bus_dir: str | Path, cid: str) -> bool:
    """Non-blocking probe checking whether another process holds the flock for `cid`."""
    if not is_valid_cid(cid):
        return False
    lp = conv_lock_path(bus_dir, cid)
    if not lp.is_file():
        return False
    fd = -1
    try:
        fd = os.open(str(lp), os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except BlockingIOError:
        return True
    except OSError:
        return False
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


class ConversationLease:
    """Non-blocking advisory `fcntl.flock` lease guaranteeing single-writer per `cid`."""

    def __init__(self, bus_dir: str | Path, cid: str, fd: int, lock_file: Path) -> None:
        self.bus_dir = Path(bus_dir)
        self.cid = cid
        self._fd: int | None = fd
        self.lock_file = lock_file
        self._lock = threading.Lock()

    @classmethod
    def try_acquire(cls, bus_dir: str | Path, cid: str) -> ConversationLease | None:
        if not is_valid_cid(cid):
            return None
        locks_dir = Path(bus_dir) / "conv_locks"
        locks_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(locks_dir, 0o700)
        except OSError:
            pass
        lp = conv_lock_path(bus_dir, cid)
        fd = os.open(str(lp), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                os.chmod(lp, 0o600)
            except OSError:
                pass
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                os.ftruncate(fd, 0)
                os.write(fd, f"{os.getpid()} {int(time.time())}\n".encode("ascii"))
            except OSError:
                pass
            return cls(bus_dir, cid, fd, lp)
        except BlockingIOError:
            os.close(fd)
            return None
        except Exception:
            os.close(fd)
            raise

    def release(self) -> None:
        with self._lock:
            if self._fd is None:
                return
            fd = self._fd
            self._fd = None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def __enter__(self) -> ConversationLease:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.release()


# ---------------------------------------------------------------------------
# Bounded Per-Bot Turn Event Ring Buffer
# ---------------------------------------------------------------------------


class _TurnRecord:
    __slots__ = (
        "turn_id",
        "owner_user_id",
        "actor_username",
        "bot_handle",
        "scope_key",
        "cid",
        "source",
        "prompt_preview",
        "status",
        "created_at",
        "finished_at",
        "events",
        "total_bytes",
        "next_seq",
        "dropped_before_seq",
        "finished",
        "aborted",
        "max_events",
        "max_bytes",
    )

    def __init__(
        self,
        turn_id: str,
        *,
        owner_user_id: int,
        actor_username: str,
        bot_handle: str,
        scope_key: str,
        cid: str | None,
        source: str,
        prompt_preview: str,
        max_events: int,
        max_bytes: int,
    ) -> None:
        self.turn_id = turn_id
        self.owner_user_id = int(owner_user_id)
        self.actor_username = str(actor_username or "")
        self.bot_handle = str(bot_handle or "")
        self.scope_key = str(scope_key or "")
        self.cid = cid
        src_clean = str(source or "web").strip().lower()
        self.source = "tg" if src_clean == "tg" else "web"
        self.prompt_preview = " ".join(str(prompt_preview or "").split())[:240]
        self.status = "queued"
        self.created_at = time.time()
        self.finished_at: float | None = None
        self.events: collections.deque[tuple[int, str, dict[str, Any], int]] = collections.deque()
        self.total_bytes = 0
        self.next_seq = 1
        self.dropped_before_seq = 0
        self.finished = False
        self.aborted = False
        self.max_events = max(1, int(max_events))
        self.max_bytes = max(1024, int(max_bytes))


class TurnEventBuffer:
    """Thread-safe bounded turn event buffer (<=32 turns; <=512 events & <=2MiB per turn)."""

    def __init__(
        self,
        *,
        max_turns: int = DEFAULT_MAX_TURNS,
        max_events_per_turn: int = DEFAULT_MAX_EVENTS_PER_TURN,
        max_bytes_per_turn: int = DEFAULT_MAX_BYTES_PER_TURN,
    ) -> None:
        self.max_turns = max(1, int(max_turns))
        self.max_events_per_turn = max(1, int(max_events_per_turn))
        self.max_bytes_per_turn = max(1024, int(max_bytes_per_turn))
        self._cond = threading.Condition()
        self._turns: collections.OrderedDict[str, _TurnRecord] = collections.OrderedDict()

    def create_turn(
        self,
        turn_id: str,
        *,
        owner_user_id: int,
        actor_username: str = "",
        bot_handle: str = "",
        scope_key: str = "",
        cid: str | None = None,
        source: str = "web",
        prompt_preview: str = "",
    ) -> _TurnRecord:
        with self._cond:
            rec = _TurnRecord(
                turn_id,
                owner_user_id=owner_user_id,
                actor_username=actor_username,
                bot_handle=bot_handle,
                scope_key=scope_key,
                cid=cid,
                source=source,
                prompt_preview=prompt_preview,
                max_events=self.max_events_per_turn,
                max_bytes=self.max_bytes_per_turn,
            )
            self._turns[turn_id] = rec
            self._evict_turns_locked()
            self._cond.notify_all()
            return rec

    def _evict_turns_locked(self) -> None:
        while len(self._turns) > self.max_turns:
            evicted = False
            for tid, rec in list(self._turns.items()):
                if rec.finished:
                    self._turns.pop(tid, None)
                    evicted = True
                    break
            if not evicted:
                self._turns.popitem(last=False)

    def get_turn_info(self, turn_id: str) -> dict[str, Any] | None:
        with self._cond:
            rec = self._turns.get(turn_id)
            if rec is None:
                return None
            return {
                "turn_id": rec.turn_id,
                "owner_user_id": rec.owner_user_id,
                "actor_username": rec.actor_username,
                "bot_handle": rec.bot_handle,
                "scope_key": rec.scope_key,
                "cid": rec.cid,
                "source": rec.source,
                "prompt_preview": rec.prompt_preview,
                "status": rec.status,
                "finished": rec.finished,
                "aborted": rec.aborted,
                "next_seq": rec.next_seq,
                "dropped_before_seq": rec.dropped_before_seq,
                "buffered_events": len(rec.events),
                "buffered_bytes": rec.total_bytes,
            }

    def set_cid(self, turn_id: str, cid: str) -> None:
        with self._cond:
            rec = self._turns.get(turn_id)
            if rec is not None and cid:
                rec.cid = cid

    def mark_aborted(self, turn_id: str) -> bool:
        with self._cond:
            rec = self._turns.get(turn_id)
            if rec is None:
                return False
            rec.aborted = True
            self._cond.notify_all()
            return True

    def find_active_turn_for_cid(self, cid: str) -> str | None:
        if not cid:
            return None
        with self._cond:
            for tid, rec in self._turns.items():
                if not rec.finished and rec.cid == cid:
                    return tid
            return None

    def find_active_turn_for_cid_and_owner(
        self,
        cid: str,
        owner_user_id: int,
    ) -> dict[str, Any] | None:
        """Find the active unfinished turn matching both `cid` and `owner_user_id`."""
        if not cid:
            return None
        uid = parse_strict_user_id(owner_user_id)
        if uid is None:
            return None
        with self._cond:
            for rec in reversed(list(self._turns.values())):
                if not rec.finished and rec.cid == cid and rec.owner_user_id == uid:
                    return {
                        "turn_id": rec.turn_id,
                        "cid": rec.cid,
                        "source": rec.source,
                        "status": rec.status,
                        "prompt_preview": rec.prompt_preview,
                        "bot_handle": rec.bot_handle,
                    }
            return None

    def append(self, turn_id: str, event_type: str, payload: dict[str, Any] | None = None) -> int:
        data = dict(payload) if isinstance(payload, dict) else {}
        if event_type == "init" and data.get("conversation_id"):
            cid_val = str(data["conversation_id"])
        else:
            cid_val = None
        encoded_len = len(
            json.dumps({"event": event_type, "data": data}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        with self._cond:
            rec = self._turns.get(turn_id)
            if rec is None:
                return 0
            if cid_val:
                rec.cid = cid_val
            if event_type == "turn_start":
                rec.status = "running"
            elif event_type in _TERMINAL_EVENTS:
                rec.status = event_type
                rec.finished = True
                rec.finished_at = time.time()

            seq = rec.next_seq
            rec.next_seq += 1
            rec.events.append((seq, event_type, data, encoded_len))
            rec.total_bytes += encoded_len

            while len(rec.events) > rec.max_events or (
                len(rec.events) > 1 and rec.total_bytes > rec.max_bytes
            ):
                old_seq, _old_ev, _old_data, old_len = rec.events.popleft()
                rec.total_bytes = max(0, rec.total_bytes - old_len)
                rec.dropped_before_seq = max(rec.dropped_before_seq, old_seq)

            self._cond.notify_all()
            return seq

    def finish(self, turn_id: str, status: str = "done") -> None:
        with self._cond:
            rec = self._turns.get(turn_id)
            if rec is None:
                return
            rec.status = status
            rec.finished = True
            if rec.finished_at is None:
                rec.finished_at = time.time()
            self._cond.notify_all()

    def iter_events(
        self,
        turn_id: str,
        *,
        after_seq: int = 0,
        should_stop: Callable[[], bool] | None = None,
        wait_slice_sec: float = 0.5,
    ) -> Iterator[dict[str, Any]]:
        """Yield buffered and live events for `turn_id` starting strictly after `after_seq`."""
        cursor = max(0, int(after_seq))
        while True:
            if should_stop is not None and should_stop():
                return
            batch: list[dict[str, Any]] = []
            resync_ev: dict[str, Any] | None = None
            is_done = False

            with self._cond:
                rec = self._turns.get(turn_id)
                if rec is None:
                    yield {
                        "seq": cursor,
                        "event": "resync_required",
                        "data": {"turn_id": turn_id, "reason": "turn_evicted"},
                    }
                    return

                earliest_seq = rec.events[0][0] if rec.events else rec.next_seq
                if rec.dropped_before_seq > 0 and cursor < rec.dropped_before_seq:
                    resync_ev = {
                        "seq": rec.next_seq - 1,
                        "event": "resync_required",
                        "data": {
                            "turn_id": turn_id,
                            "conversation_id": rec.cid,
                            "reason": "buffer_overflow",
                            "dropped_before_seq": rec.dropped_before_seq,
                            "earliest_available_seq": earliest_seq,
                        },
                    }
                else:
                    for seq, ev_type, ev_data, _sz in rec.events:
                        if seq > cursor:
                            batch.append({"seq": seq, "event": ev_type, "data": ev_data})
                    if batch:
                        cursor = batch[-1]["seq"]
                    is_done = rec.finished and (cursor >= rec.next_seq - 1)
                    if not batch and not is_done:
                        self._cond.wait(timeout=wait_slice_sec)

            if resync_ev is not None:
                yield resync_ev
                return
            for item in batch:
                yield item
                if item["event"] in _TERMINAL_EVENTS:
                    return
            if is_done:
                return


# ---------------------------------------------------------------------------
# Unix Domain Socket HTTP/1.1 Server
# ---------------------------------------------------------------------------


def _write_token_atomic(token_path: Path, token: str) -> None:
    token_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(token_path.parent, 0o700)
    tmp_path = token_path.parent / f".{token_path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}"
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, token_path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def get_socket_peer_uid(conn: socket.socket) -> int | None:
    """Return kernel `SO_PEERCRED` peer UID for a Unix domain socket connection."""
    so_peercred = getattr(socket, "SO_PEERCRED", 17)
    try:
        creds = conn.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", creds)
        return int(uid)
    except OSError:
        return None


class _ThreadingUnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True
    block_on_close = False

    def __init__(self, server_address: str, handler_cls: type[http.server.BaseHTTPRequestHandler], ipc_owner: StudioIPCServer) -> None:
        self.ipc_owner = ipc_owner
        super().__init__(server_address, handler_cls)


class _StudioIPCHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def address_string(self) -> str:
        return "unix"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Never log headers, query strings, or tokens to stderr.
        return

    @property
    def ipc(self) -> StudioIPCServer:
        return self.server.ipc_owner  # type: ignore[attr-defined]

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)
        self.wfile.flush()
        self.close_connection = True

    def _authenticate_transport(self) -> tuple[bool, str]:
        # 1. Kernel SO_PEERCRED UID check
        peer_uid = self.ipc._get_peer_uid(self.connection)
        if peer_uid is None or peer_uid != os.getuid():
            return False, "IPC 对端 UID 校验失败"

        # 2. Reject any proxy forwarding headers unconditionally
        for hdr_name in self.headers.keys():
            if hdr_name.strip().lower() in _FORBIDDEN_PROXY_HEADERS:
                return False, "IPC 拒绝携带代理转发头的请求"

        # 3. Constant-time per-bot 256-bit IPC token check
        provided = (self.headers.get("X-Bridge-IPC-Token") or "").strip()
        if not provided or not hmac.compare_digest(provided, self.ipc.token):
            return False, "IPC 鉴权令牌无效"

        return True, ""

    def _read_json_body(self) -> tuple[bool, dict[str, Any] | None, str, int]:
        raw_cl = self.headers.get("Content-Length")
        if raw_cl is None:
            return False, None, "缺少 Content-Length", 400
        try:
            cl = int(raw_cl)
        except ValueError:
            return False, None, "无效的 Content-Length", 400
        if cl < 0 or cl > MAX_IPC_BODY_BYTES:
            return False, None, "IPC 请求体超过上限", 413
        body_bytes = self.rfile.read(cl) if cl > 0 else b"{}"
        try:
            data = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            return False, None, "IPC 请求体必须为有效 JSON", 400
        if not isinstance(data, dict):
            return False, None, "IPC 请求体必须为 JSON 对象", 400
        return True, data, "", 200

    def _authorize_admin_user(self, raw_user_id: Any) -> tuple[bool, int | None, str]:
        uid = parse_strict_user_id(raw_user_id)
        if uid is None:
            return False, None, "缺少有效的正整数 user_id"
        # Strictly ignore any caller-supplied `role` field; always recompute live RBAC on Bridge side.
        live_role = str(self.ipc.resolve_role_fn(uid) or "denied").strip().lower()
        if live_role != "admin":
            return False, uid, "非管理员权限，Bridge IPC 已拒绝写操作"
        return True, uid, ""

    def do_GET(self) -> None:  # noqa: N802
        ok, err = self._authenticate_transport()
        if not ok:
            self._send_json(403, {"ok": False, "error": err, "source": "bridge_ipc"})
            return

        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)

        if path == "/ipc/meta":
            try:
                meta = self.ipc.get_meta_fn()
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"meta failed: {type(exc).__name__}"})
                return
            self._send_json(200, {"ok": True, **(meta if isinstance(meta, dict) else {})})
            return

        if path == "/ipc/bot/config":
            if self.ipc.get_bot_config_fn is None:
                self._send_json(501, {"ok": False, "error": "bot_config 未启用"})
                return
            try:
                cfg_payload = self.ipc.get_bot_config_fn()
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"bot_config failed: {type(exc).__name__}"})
                return
            self._send_json(200, {"ok": True, **(cfg_payload if isinstance(cfg_payload, dict) else {})})
            return

        if path == "/ipc/bot/profile":
            if self.ipc.get_bot_profile_fn is None:
                self._send_json(501, {"ok": False, "error": "bot_profile 未启用"})
                return
            try:
                prof_payload = self.ipc.get_bot_profile_fn()
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"bot_profile failed: {type(exc).__name__}"})
                return
            self._send_json(200, {"ok": True, **(prof_payload if isinstance(prof_payload, dict) else {})})
            return

        if path == "/ipc/bot/skills":
            raw_slug = ((qs.get("slug") or [""])[0]).strip()
            if raw_slug:
                if (
                    raw_slug in _FORBIDDEN_BOT_SKILL_SLUGS
                    or not _BOT_SKILL_SLUG_IPC_RE.fullmatch(raw_slug)
                ):
                    self._send_json(400, {"ok": False, "error": "非法的 skill slug 格式"})
                    return
                if self.ipc.get_bot_skill_fn is None:
                    self._send_json(501, {"ok": False, "error": "bot_skill 读取未启用"})
                    return
                try:
                    sc_sk, resp_sk = self.ipc.get_bot_skill_fn(raw_slug)
                except Exception as exc:
                    self._send_json(500, {"ok": False, "error": f"bot_skill failed: {type(exc).__name__}"})
                    return
                self._send_json(int(sc_sk), resp_sk)
                return
            if self.ipc.get_bot_profile_fn is None:
                self._send_json(501, {"ok": False, "error": "bot_skills 未启用"})
                return
            try:
                prof_payload = self.ipc.get_bot_profile_fn()
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"bot_skills failed: {type(exc).__name__}"})
                return
            self._send_json(
                200,
                {
                    "ok": True,
                    "rev": prof_payload.get("rev", 1),
                    "skills_policy": prof_payload.get("skills_policy", {}),
                    "own_skills": prof_payload.get("own_skills", []),
                    "catalog_skills": prof_payload.get("catalog_skills", []),
                    "team_skills": prof_payload.get("team_skills", []),
                    "effective_skills": prof_payload.get("effective_skills", []),
                },
            )
            return

        if path == "/ipc/undo/list":
            raw_uid = (qs.get("user_id") or [self.headers.get("X-Bridge-User-Id") or ""])[0]
            ok_u, uid, err_u = self._authorize_admin_user(raw_uid)
            if not ok_u or uid is None:
                self._send_json(403, {"ok": False, "error": err_u, "source": "bridge_ipc"})
                return
            if self.ipc.list_undo_fn is None:
                self._send_json(501, {"ok": False, "error": "undo_list 未启用"})
                return
            raw_cid = ((qs.get("cid") or [""])[0]).strip()
            cid_arg: str | None = None
            if raw_cid:
                if not is_valid_cid(raw_cid):
                    self._send_json(400, {"ok": False, "error": "无效的会话 ID 格式"})
                    return
                cid_arg = raw_cid
            raw_pid = ((qs.get("project_id") or [""])[0]).strip()[:128] or None
            raw_wt = ((qs.get("worktree_id") or [""])[0]).strip()
            wt_arg: str | None = None
            if raw_wt:
                if not is_valid_worktree_id(raw_wt):
                    self._send_json(400, {"ok": False, "error": "非法的 worktree_id 格式"})
                    return
                wt_arg = raw_wt
            try:
                if wt_arg is not None:
                    try:
                        sc_u, resp_u = self.ipc.list_undo_fn(uid, cid_arg, raw_pid, worktree_id=wt_arg)  # type: ignore[call-arg]
                    except TypeError:
                        sc_u, resp_u = self.ipc.list_undo_fn(uid, cid_arg, raw_pid)
                else:
                    sc_u, resp_u = self.ipc.list_undo_fn(uid, cid_arg, raw_pid)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"undo_list failed: {type(exc).__name__}"})
                return
            self._send_json(int(sc_u), resp_u)
            return

        if path == "/ipc/undo/diff":
            raw_uid = (qs.get("user_id") or [self.headers.get("X-Bridge-User-Id") or ""])[0]
            ok_u, uid, err_u = self._authorize_admin_user(raw_uid)
            if not ok_u or uid is None:
                self._send_json(403, {"ok": False, "error": err_u, "source": "bridge_ipc"})
                return
            if self.ipc.diff_undo_fn is None:
                self._send_json(501, {"ok": False, "error": "undo_diff 未启用"})
                return
            entry_id = ((qs.get("entry_id") or [""])[0]).strip()
            if not is_valid_undo_entry_id(entry_id):
                self._send_json(400, {"ok": False, "error": "无效的检查点 entry_id"})
                return
            raw_cid = ((qs.get("cid") or [""])[0]).strip()
            cid_arg_d: str | None = None
            if raw_cid:
                if not is_valid_cid(raw_cid):
                    self._send_json(400, {"ok": False, "error": "无效的会话 ID 格式"})
                    return
                cid_arg_d = raw_cid
            raw_pid_d = ((qs.get("project_id") or [""])[0]).strip()[:128] or None
            try:
                sc_d, resp_d = self.ipc.diff_undo_fn(uid, entry_id, cid_arg_d, raw_pid_d)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"undo_diff failed: {type(exc).__name__}"})
                return
            self._send_json(int(sc_d), resp_d)
            return

        if path == "/ipc/chat/active":
            raw_uid = (qs.get("user_id") or [self.headers.get("X-Bridge-User-Id") or ""])[0]
            ok_u, uid, err_u = self._authorize_admin_user(raw_uid)
            if not ok_u or uid is None:
                self._send_json(403, {"ok": False, "error": err_u, "source": "bridge_ipc"})
                return

            raw_cid = ((qs.get("cid") or [""])[0]).strip()
            ok_cid, err_cid, sc_cid = validate_resume_cid(
                raw_cid,
                summaries_db=self.ipc.summaries_db,
                meta_file=self.ipc.meta_file,
            )
            if not ok_cid:
                self._send_json(sc_cid, {"ok": False, "error": err_cid})
                return

            active = self.ipc.buffer.find_active_turn_for_cid_and_owner(raw_cid, uid)
            if active is None:
                self._send_json(200, {"ok": True, "active": False, "cid": raw_cid})
                return

            self._send_json(
                200,
                {
                    "ok": True,
                    "active": True,
                    "turn_id": active["turn_id"],
                    "cid": active["cid"] or raw_cid,
                    "source": active["source"],
                    "status": active["status"],
                    "prompt_preview": active["prompt_preview"],
                },
            )
            return

        if path == "/ipc/chat/stream":
            raw_uid = (qs.get("user_id") or [self.headers.get("X-Bridge-User-Id") or ""])[0]
            ok_u, uid, err_u = self._authorize_admin_user(raw_uid)
            if not ok_u or uid is None:
                self._send_json(403, {"ok": False, "error": err_u, "source": "bridge_ipc"})
                return

            turn_id = ((qs.get("turn_id") or [""])[0]).strip()
            if not turn_id:
                self._send_json(400, {"ok": False, "error": "缺少 turn_id"})
                return

            info = self.ipc.buffer.get_turn_info(turn_id)
            if info is None:
                self._send_json(404, {"ok": False, "error": "未找到对应的对话轮次"})
                return
            if int(info["owner_user_id"]) != uid:
                self._send_json(403, {"ok": False, "error": "无权订阅其他用户的对话流"})
                return

            raw_after = ((qs.get("after_seq") or ["0"])[0]).strip()
            try:
                after_seq = max(0, int(raw_after))
            except ValueError:
                after_seq = 0

            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

            try:
                for ev in self.ipc.buffer.iter_events(
                    turn_id,
                    after_seq=after_seq,
                    should_stop=lambda: self.ipc._stopping.is_set(),
                    wait_slice_sec=0.35,
                ):
                    line = (json.dumps(ev, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
                    chunk_hdr = f"{len(line):x}\r\n".encode("ascii")
                    self.wfile.write(chunk_hdr + line + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            return

        self._send_json(404, {"ok": False, "error": "IPC endpoint not found"})

    def do_POST(self) -> None:  # noqa: N802
        ok, err = self._authenticate_transport()
        if not ok:
            self._send_json(403, {"ok": False, "error": err, "source": "bridge_ipc"})
            return

        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        ok_body, body, err_body, sc_body = self._read_json_body()
        if not ok_body or body is None:
            self._send_json(sc_body, {"ok": False, "error": err_body})
            return

        # Recompute live admin RBAC from user_id BEFORE inspecting forbidden keys so
        # readonly callers attempting spoofed `role:"admin"` always receive 403.
        ok_u, uid, err_u = self._authorize_admin_user(body.get("user_id"))
        if not ok_u or uid is None:
            self._send_json(403, {"ok": False, "error": err_u, "source": "bridge_ipc"})
            return

        if path == "/ipc/accounts/recycle":
            bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_ACCOUNT_RECYCLE_IPC_KEYS)
            if bad_k is not None:
                self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
                return
            unknown = set(body.keys()) - _ALLOWED_ACCOUNT_RECYCLE_IPC_KEYS
            if unknown:
                self._send_json(400, {"ok": False, "error": f"不支持的字段: {sorted(unknown)[0]}"})
                return
            raw_aid = body.get("account_id")
            account_id: str | None = None
            if raw_aid is not None and str(raw_aid).strip() != "":
                if not isinstance(raw_aid, str):
                    self._send_json(400, {"ok": False, "error": "account_id 必须为字符串"})
                    return
                aid_s = raw_aid.strip()
                if aid_s in _FORBIDDEN_ACCOUNT_ID_IPC_NAMES or not _ACCOUNT_ID_IPC_RE.fullmatch(aid_s):
                    self._send_json(400, {"ok": False, "error": "非法的 account_id 格式"})
                    return
                account_id = aid_s
            raw_reason = body.get("reason", "account_switch")
            if raw_reason is None:
                reason_val = "account_switch"
            elif not isinstance(raw_reason, str):
                self._send_json(400, {"ok": False, "error": "reason 必须为字符串"})
                return
            else:
                reason_val = re.sub(r"[\x00-\x1f\x7f\r\n]+", " ", raw_reason).strip()[:128] or "account_switch"
            raw_actor = re.sub(r"[\x00-\x1f\x7f\r\n]+", " ", str(body.get("actor_username") or "")).strip()
            safe_actor = neutralize_control_tags(raw_actor)[:64]
            if self.ipc.recycle_accounts_fn is None:
                self._send_json(501, {"ok": False, "error": "accounts_recycle 未启用"})
                return
            req_acc = {
                "user_id": uid,
                "actor_username": safe_actor,
                "account_id": account_id,
                "reason": reason_val,
            }
            try:
                status_code, resp_payload = self.ipc.recycle_accounts_fn(req_acc)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"accounts_recycle failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path == "/ipc/tg_group/send":
            # Strictly reject ANY client-supplied role/chat_id/thread_id/mirror_*/scope_key/shell keys recursively
            bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_TG_GROUP_IPC_KEYS)
            if bad_k is not None:
                self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
                return
            unknown = set(body.keys()) - _ALLOWED_TG_GROUP_IPC_KEYS
            if unknown:
                self._send_json(400, {"ok": False, "error": f"不支持的字段: {sorted(unknown)[0]}"})
                return
            content = body.get("content")
            if not isinstance(content, str) or not content.strip():
                self._send_json(400, {"ok": False, "error": "content 不能为空"})
                return
            if len(content.encode("utf-8")) > MAX_TG_GROUP_CONTENT_BYTES:
                self._send_json(413, {"ok": False, "error": "content 超过 16 KiB 上限"})
                return
            mirror_human = body.get("mirror_human_to_tg", True)
            if not isinstance(mirror_human, bool):
                self._send_json(400, {"ok": False, "error": "mirror_human_to_tg 必须为布尔值"})
                return
            raw_origin_mid = body.get("origin_msg_id", 0)
            if isinstance(raw_origin_mid, bool) or not isinstance(raw_origin_mid, int) or raw_origin_mid < 0:
                self._send_json(400, {"ok": False, "error": "origin_msg_id 必须为非负整数"})
                return
            raw_priority = body.get("priority", "normal")
            if raw_priority is None:
                priority_val = "normal"
            elif not isinstance(raw_priority, str) or raw_priority.strip().lower() not in _VALID_IPC_PRIORITIES:
                self._send_json(400, {"ok": False, "error": "priority 必须为 normal 或 urgent"})
                return
            else:
                priority_val = raw_priority.strip().lower()
            raw_interrupt = body.get("interrupt_current", False)
            if not isinstance(raw_interrupt, bool):
                self._send_json(400, {"ok": False, "error": "interrupt_current 必须为布尔值"})
                return
            safe_content = neutralize_control_tags(content).strip()
            if not safe_content:
                self._send_json(400, {"ok": False, "error": "content 不能为空"})
                return
            raw_actor = re.sub(r"[\x00-\x1f\x7f\r\n]+", " ", str(body.get("actor_username") or "")).strip()
            safe_actor = neutralize_control_tags(raw_actor)[:64]
            if self.ipc.tg_group_send_fn is None:
                self._send_json(501, {"ok": False, "error": "tg_group_send 未启用"})
                return
            req_tg = {
                "user_id": uid,
                "actor_username": safe_actor,
                "content": safe_content,
                "project": str(body.get("project") or "").strip()[:128] or None,
                "mirror_human_to_tg": mirror_human,
                "origin_msg_id": int(raw_origin_mid),
                "priority": priority_val,
                "interrupt_current": raw_interrupt,
            }
            try:
                status_code, resp_payload = self.ipc.tg_group_send_fn(req_tg)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"tg_group_send failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        # Strip any caller-supplied untrusted routing/role fields so downstream handlers can never trust them
        for bad_k in _UNTRUSTED_CLIENT_SEND_KEYS:
            body.pop(bad_k, None)

        if path == "/ipc/chat/send":
            bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_CHAT_SEND_IPC_KEYS)
            if bad_k is not None:
                self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
                return
            prompt = body.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                self._send_json(400, {"ok": False, "error": "prompt 不能为空"})
                return
            if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
                self._send_json(413, {"ok": False, "error": "prompt 超过 32 KiB 上限"})
                return

            worktree = False
            if "worktree" in body:
                raw_wt = body.get("worktree")
                if not isinstance(raw_wt, bool):
                    self._send_json(400, {"ok": False, "error": "worktree 必须为布尔值（true/false）"})
                    return
                worktree = raw_wt

            sync_tg = False
            if "sync_tg" in body:
                raw_sync = body.get("sync_tg")
                if not isinstance(raw_sync, bool):
                    self._send_json(400, {"ok": False, "error": "sync_tg 必须为布尔值（true/false）"})
                    return
                sync_tg = raw_sync

            raw_priority = body.get("priority", "normal")
            if raw_priority is None:
                priority_val = "normal"
            elif not isinstance(raw_priority, str) or raw_priority.strip().lower() not in _VALID_IPC_PRIORITIES:
                self._send_json(400, {"ok": False, "error": "priority 必须为 normal 或 urgent"})
                return
            else:
                priority_val = raw_priority.strip().lower()

            interrupt_current = False
            if "interrupt_current" in body:
                raw_ic = body.get("interrupt_current")
                if not isinstance(raw_ic, bool):
                    self._send_json(400, {"ok": False, "error": "interrupt_current 必须为布尔值（true/false）"})
                    return
                interrupt_current = raw_ic

            raw_cid = body.get("cid")
            cid: str | None = None
            if raw_cid is not None and str(raw_cid).strip() != "":
                cid_str = str(raw_cid).strip()
                ok_cid, err_cid, sc_cid = validate_resume_cid(
                    cid_str,
                    summaries_db=self.ipc.summaries_db,
                    meta_file=self.ipc.meta_file,
                )
                if not ok_cid:
                    self._send_json(sc_cid, {"ok": False, "error": err_cid})
                    return
                cid = cid_str

            req = {
                "user_id": uid,
                "actor_username": str(body.get("actor_username") or "")[:64],
                "prompt": prompt,
                "cid": cid,
                "project": str(body.get("project") or "").strip()[:128] or None,
                "model": str(body.get("model") or "").strip()[:160] or None,
                "effort": str(body.get("effort") or "").strip().lower()[:16] or None,
                "sync_tg": sync_tg,
                "worktree": worktree,
                "priority": priority_val,
                "interrupt_current": interrupt_current,
            }
            try:
                status_code, resp_payload = self.ipc.enqueue_turn_fn(req)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"enqueue failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path == "/ipc/worktrees/cleanup":
            bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_WORKTREE_CLEANUP_IPC_KEYS)
            if bad_k is not None:
                self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
                return
            unknown = set(body.keys()) - _ALLOWED_WORKTREE_CLEANUP_IPC_KEYS
            if unknown:
                self._send_json(400, {"ok": False, "error": f"不支持的字段: {sorted(unknown)[0]}"})
                return
            wt_id = str(body.get("worktree_id") or "").strip()
            if not is_valid_worktree_id(wt_id):
                self._send_json(400, {"ok": False, "error": "非法的 worktree_id 格式"})
                return
            pid_wt = str(body.get("project_id") or "").strip()
            if not pid_wt or "/" in pid_wt or "\\" in pid_wt or ".." in pid_wt or "\x00" in pid_wt:
                self._send_json(400, {"ok": False, "error": "非法的 project_id 参数"})
                return
            raw_force_wt = body.get("force", False)
            if not isinstance(raw_force_wt, bool):
                self._send_json(400, {"ok": False, "error": "force 必须为布尔值"})
                return
            if self.ipc.cleanup_worktree_fn is None:
                self._send_json(501, {"ok": False, "error": "worktree_cleanup 未启用"})
                return
            req_wt = {
                "user_id": uid,
                "actor_username": str(body.get("actor_username") or "")[:64],
                "worktree_id": wt_id,
                "project_id": pid_wt[:128],
                "force": raw_force_wt,
            }
            try:
                status_code, resp_payload = self.ipc.cleanup_worktree_fn(req_wt)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"worktree_cleanup failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path == "/ipc/chat/abort":
            turn_id = str(body.get("turn_id") or "").strip()
            if not turn_id:
                self._send_json(400, {"ok": False, "error": "缺少 turn_id"})
                return
            info = self.ipc.buffer.get_turn_info(turn_id)
            if info is None:
                self._send_json(404, {"ok": False, "error": "未找到对应的对话轮次"})
                return
            if int(info["owner_user_id"]) != uid:
                self._send_json(403, {"ok": False, "error": "无权中止其他用户的对话轮次"})
                return
            try:
                status_code, resp_payload = self.ipc.abort_turn_fn(turn_id, uid)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"abort failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path == "/ipc/job/cancel":
            job_id = str(body.get("job_id") or "").strip()
            if not is_valid_entity_id(job_id):
                self._send_json(400, {"ok": False, "error": "非法的 job_id 格式"})
                return
            if self.ipc.cancel_job_fn is None:
                self._send_json(501, {"ok": False, "error": "cancel_job 未启用"})
                return
            try:
                status_code, resp_payload = self.ipc.cancel_job_fn(job_id, uid)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"cancel_job failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path == "/ipc/schedule/run":
            schedule_id = str(body.get("schedule_id") or "").strip()
            if not is_valid_entity_id(schedule_id):
                self._send_json(400, {"ok": False, "error": "非法的 schedule_id 格式"})
                return
            if self.ipc.run_schedule_fn is None:
                self._send_json(501, {"ok": False, "error": "run_schedule 未启用"})
                return
            try:
                status_code, resp_payload = self.ipc.run_schedule_fn(schedule_id, uid)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"run_schedule failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path in ("/ipc/undo/apply", "/ipc/undo/redo"):
            bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_UNDO_IPC_KEYS)
            if bad_k is not None:
                self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
                return
            entry_id = str(body.get("entry_id") or "").strip()
            if not is_valid_undo_entry_id(entry_id):
                self._send_json(400, {"ok": False, "error": "无效的检查点 entry_id"})
                return
            raw_cid = body.get("cid")
            cid_val: str | None = None
            if raw_cid is not None and str(raw_cid).strip() != "":
                cid_s = str(raw_cid).strip()
                if not is_valid_cid(cid_s):
                    self._send_json(400, {"ok": False, "error": "无效的会话 ID 格式"})
                    return
                cid_val = cid_s
            raw_force = body.get("force", False)
            if not isinstance(raw_force, bool):
                self._send_json(400, {"ok": False, "error": "force 必须为布尔值"})
                return
            raw_pid = body.get("project_id")
            pid_val = str(raw_pid).strip()[:128] if raw_pid is not None and str(raw_pid).strip() else None
            fn = self.ipc.apply_undo_fn if path == "/ipc/undo/apply" else self.ipc.apply_redo_fn
            if fn is None:
                self._send_json(501, {"ok": False, "error": "undo/redo 未启用"})
                return
            req_undo = {
                "user_id": uid,
                "actor_username": str(body.get("actor_username") or "")[:64],
                "entry_id": entry_id,
                "cid": cid_val,
                "project_id": pid_val,
                "force": raw_force,
            }
            try:
                status_code, resp_payload = fn(req_undo)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"undo failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path == "/ipc/bot/config":
            bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_BOT_CONFIG_IPC_KEYS)
            if bad_k is not None:
                self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
                return
            if self.ipc.update_bot_config_fn is None:
                self._send_json(501, {"ok": False, "error": "bot_config 写接口未启用"})
                return
            req_cfg = dict(body)
            req_cfg["user_id"] = uid
            req_cfg["actor_username"] = str(body.get("actor_username") or "")[:64]
            try:
                status_code, resp_payload = self.ipc.update_bot_config_fn(req_cfg)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"bot_config update failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path == "/ipc/bot/profile":
            bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_BOT_PROFILE_IPC_KEYS)
            if bad_k is not None:
                self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
                return
            if self.ipc.update_bot_profile_fn is None:
                self._send_json(501, {"ok": False, "error": "bot_profile 写接口未启用"})
                return
            req_prof = dict(body)
            req_prof["user_id"] = uid
            req_prof["actor_username"] = str(body.get("actor_username") or "")[:64]
            try:
                status_code, resp_payload = self.ipc.update_bot_profile_fn(req_prof)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"bot_profile update failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path == "/ipc/bot/skills":
            bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_BOT_PROFILE_IPC_KEYS)
            if bad_k is not None:
                self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
                return
            raw_slug = body.get("slug")
            if (
                not isinstance(raw_slug, str)
                or raw_slug in _FORBIDDEN_BOT_SKILL_SLUGS
                or not _BOT_SKILL_SLUG_IPC_RE.fullmatch(raw_slug)
            ):
                self._send_json(400, {"ok": False, "error": "非法的 skill slug 格式"})
                return
            if self.ipc.put_bot_skill_fn is None:
                self._send_json(501, {"ok": False, "error": "bot_skill 写接口未启用"})
                return
            req_sk = dict(body)
            req_sk["user_id"] = uid
            req_sk["actor_username"] = str(body.get("actor_username") or "")[:64]
            try:
                status_code, resp_payload = self.ipc.put_bot_skill_fn(req_sk)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"bot_skill save failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path == "/ipc/bot/skills/delete":
            self._handle_delete_bot_skill(body, uid)
            return

        if path == "/ipc/bot/reload":
            bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_RELOAD_IPC_KEYS)
            if bad_k is not None:
                self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
                return
            extra_keys = set(body.keys()) - {"user_id", "actor_username"}
            if extra_keys:
                self._send_json(400, {"ok": False, "error": "热重载接口不接受额外参数"})
                return
            if self.ipc.reload_bot_fn is None:
                self._send_json(501, {"ok": False, "error": "bot_reload 未启用"})
                return
            try:
                status_code, resp_payload = self.ipc.reload_bot_fn(uid)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"bot_reload failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path == "/ipc/room/turn":
            bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_ROOM_IPC_KEYS)
            if bad_k is not None:
                self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
                return
            room_id = str(body.get("room_id") or "").strip().lower()
            if not is_valid_room_id(room_id):
                self._send_json(400, {"ok": False, "error": "非法的 room_id 格式"})
                return
            prompt = body.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                self._send_json(400, {"ok": False, "error": "prompt 不能为空"})
                return
            if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
                self._send_json(413, {"ok": False, "error": "prompt 超过 32 KiB 上限"})
                return
            raw_hop = body.get("hop", 0)
            if isinstance(raw_hop, bool) or not isinstance(raw_hop, int) or raw_hop < 0 or raw_hop > 2:
                self._send_json(400, {"ok": False, "error": "非法的 hop 值（须为 0..2 整数）"})
                return
            raw_room_prio = body.get("priority", "normal")
            if raw_room_prio is None:
                room_priority = "normal"
            elif not isinstance(raw_room_prio, str) or raw_room_prio.strip().lower() not in _VALID_IPC_PRIORITIES:
                self._send_json(400, {"ok": False, "error": "priority 必须为 normal 或 urgent"})
                return
            else:
                room_priority = raw_room_prio.strip().lower()
            raw_room_ic = body.get("interrupt_current", False)
            if not isinstance(raw_room_ic, bool):
                self._send_json(400, {"ok": False, "error": "interrupt_current 必须为布尔值"})
                return
            if self.ipc.room_turn_fn is None:
                self._send_json(501, {"ok": False, "error": "room_turn 未启用"})
                return
            # Defense-in-depth neutralization of forged control tags on Bridge side
            safe_prompt = _neutralize_room_ipc_prompt(prompt)
            req_room = {
                "user_id": uid,
                "actor_username": str(body.get("actor_username") or "")[:64],
                "room_id": room_id,
                "prompt": safe_prompt,
                "chain_id": str(body.get("chain_id") or "").strip()[:64],
                "hop": int(raw_hop),
                "project": str(body.get("project") or "").strip()[:128] or None,
                "priority": room_priority,
                "interrupt_current": raw_room_ic,
            }
            try:
                status_code, resp_payload = self.ipc.room_turn_fn(req_room)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"room_turn failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        if path == "/ipc/attention/notify":
            bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_ATTENTION_IPC_KEYS)
            if bad_k is not None:
                self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
                return
            item_id = str(body.get("item_id") or "").strip()
            if not is_valid_attention_id(item_id):
                self._send_json(400, {"ok": False, "error": "非法的 item_id 格式"})
                return
            decision = str(body.get("decision") or "").strip().lower()
            if decision not in ("approved", "rejected"):
                self._send_json(400, {"ok": False, "error": "decision 必须为 approved 或 rejected"})
                return
            kind = str(body.get("kind") or "action").strip().lower()
            if kind not in ("plan", "action", "undo_force"):
                self._send_json(400, {"ok": False, "error": "非法的 kind 类型"})
                return
            note = str(body.get("note") or "")
            if len(note.encode("utf-8")) > 2048:
                self._send_json(413, {"ok": False, "error": "note 超过 2 KiB 上限"})
                return
            if self.ipc.attention_notify_fn is None:
                self._send_json(501, {"ok": False, "error": "attention_notify 未启用"})
                return
            req_att = {
                "user_id": uid,
                "actor_username": str(body.get("actor_username") or "")[:64],
                "item_id": item_id,
                "kind": kind,
                "decision": decision,
                "note": neutralize_control_tags(note),
            }
            try:
                status_code, resp_payload = self.ipc.attention_notify_fn(req_att)
            except Exception as exc:
                self._send_json(500, {"ok": False, "error": f"attention_notify failed: {type(exc).__name__}"})
                return
            self._send_json(int(status_code), resp_payload)
            return

        self._send_json(404, {"ok": False, "error": "IPC endpoint not found"})

    def _handle_delete_bot_skill(self, body: dict[str, Any], uid: int) -> None:
        bad_k = _find_forbidden_ipc_key(body, _FORBIDDEN_BOT_PROFILE_IPC_KEYS)
        if bad_k is not None:
            self._send_json(400, {"ok": False, "error": f"禁止传入受限字段: {bad_k}"})
            return
        raw_slug = body.get("slug")
        if (
            not isinstance(raw_slug, str)
            or raw_slug in _FORBIDDEN_BOT_SKILL_SLUGS
            or not _BOT_SKILL_SLUG_IPC_RE.fullmatch(raw_slug)
        ):
            self._send_json(400, {"ok": False, "error": "非法的 skill slug 格式"})
            return
        if self.ipc.delete_bot_skill_fn is None:
            self._send_json(501, {"ok": False, "error": "bot_skill 删除接口未启用"})
            return
        req_del = {
            "user_id": uid,
            "actor_username": str(body.get("actor_username") or "")[:64],
            "slug": raw_slug,
            "expected_rev": body.get("expected_rev"),
        }
        try:
            status_code, resp_payload = self.ipc.delete_bot_skill_fn(req_del)
        except Exception as exc:
            self._send_json(500, {"ok": False, "error": f"bot_skill delete failed: {type(exc).__name__}"})
            return
        self._send_json(int(status_code), resp_payload)

    def do_DELETE(self) -> None:  # noqa: N802
        ok, err = self._authenticate_transport()
        if not ok:
            self._send_json(403, {"ok": False, "error": err, "source": "bridge_ipc"})
            return

        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path

        ok_body, body, err_body, sc_body = self._read_json_body()
        if not ok_body or body is None:
            self._send_json(sc_body, {"ok": False, "error": err_body})
            return

        ok_u, uid, err_u = self._authorize_admin_user(body.get("user_id"))
        if not ok_u or uid is None:
            self._send_json(403, {"ok": False, "error": err_u, "source": "bridge_ipc"})
            return

        for bad_k in _UNTRUSTED_CLIENT_SEND_KEYS:
            body.pop(bad_k, None)

        if path == "/ipc/bot/skills":
            self._handle_delete_bot_skill(body, uid)
            return

        self._send_json(404, {"ok": False, "error": "IPC endpoint not found"})


class StudioIPCServer:
    """Lifecycle wrapper for per-bot UDS IPC server + bounded event buffer."""

    def __init__(
        self,
        *,
        bus_dir: str | Path,
        bot_handle: str,
        resolve_role_fn: Callable[[int], str],
        get_meta_fn: Callable[[], dict[str, Any]],
        enqueue_turn_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]],
        abort_turn_fn: Callable[[str, int], tuple[int, dict[str, Any]]],
        cancel_job_fn: Callable[[str, int], tuple[int, dict[str, Any]]] | None = None,
        run_schedule_fn: Callable[[str, int], tuple[int, dict[str, Any]]] | None = None,
        list_undo_fn: Callable[..., tuple[int, dict[str, Any]]] | None = None,
        diff_undo_fn: Callable[[int, str, str | None, str | None], tuple[int, dict[str, Any]]] | None = None,
        apply_undo_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] | None = None,
        apply_redo_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] | None = None,
        cleanup_worktree_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] | None = None,
        get_bot_config_fn: Callable[[], dict[str, Any]] | None = None,
        update_bot_config_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] | None = None,
        reload_bot_fn: Callable[[int], tuple[int, dict[str, Any]]] | None = None,
        get_bot_profile_fn: Callable[[], dict[str, Any]] | None = None,
        update_bot_profile_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] | None = None,
        get_bot_skill_fn: Callable[[str], tuple[int, dict[str, Any]]] | None = None,
        put_bot_skill_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] | None = None,
        delete_bot_skill_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] | None = None,
        room_turn_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] | None = None,
        attention_notify_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] | None = None,
        tg_group_send_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] | None = None,
        recycle_accounts_fn: Callable[[dict[str, Any]], tuple[int, dict[str, Any]]] | None = None,
        buffer: TurnEventBuffer | None = None,
        summaries_db: str | Path | None = None,
        meta_file: str | Path | None = None,
        peer_uid_fn: Callable[[socket.socket], int | None] | None = None,
    ) -> None:
        self.bus_dir = Path(bus_dir)
        self.bot_handle = normalize_ipc_handle(bot_handle)
        self.ipc_dir = self.bus_dir / "ipc"
        self.sock_path = self.ipc_dir / f"{self.bot_handle}.sock"
        self.token_path = self.ipc_dir / f"{self.bot_handle}.token"
        self.token = secrets.token_hex(32)  # 256-bit random token per boot

        self.resolve_role_fn = resolve_role_fn
        self.get_meta_fn = get_meta_fn
        self.enqueue_turn_fn = enqueue_turn_fn
        self.abort_turn_fn = abort_turn_fn
        self.cancel_job_fn = cancel_job_fn
        self.run_schedule_fn = run_schedule_fn
        self.list_undo_fn = list_undo_fn
        self.diff_undo_fn = diff_undo_fn
        self.apply_undo_fn = apply_undo_fn
        self.apply_redo_fn = apply_redo_fn
        self.cleanup_worktree_fn = cleanup_worktree_fn
        self.get_bot_config_fn = get_bot_config_fn
        self.update_bot_config_fn = update_bot_config_fn
        self.reload_bot_fn = reload_bot_fn
        self.get_bot_profile_fn = get_bot_profile_fn
        self.update_bot_profile_fn = update_bot_profile_fn
        self.get_bot_skill_fn = get_bot_skill_fn
        self.put_bot_skill_fn = put_bot_skill_fn
        self.delete_bot_skill_fn = delete_bot_skill_fn
        self.room_turn_fn = room_turn_fn
        self.attention_notify_fn = attention_notify_fn
        self.tg_group_send_fn = tg_group_send_fn
        self.recycle_accounts_fn = recycle_accounts_fn
        self.buffer = buffer or TurnEventBuffer()
        self.summaries_db = summaries_db
        self.meta_file = meta_file
        self._get_peer_uid = peer_uid_fn or get_socket_peer_uid

        self._stopping = threading.Event()
        self._server: _ThreadingUnixHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> Path:
        self.ipc_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.ipc_dir, 0o700)
        _write_token_atomic(self.token_path, self.token)

        if self.sock_path.exists() or self.sock_path.is_symlink():
            try:
                self.sock_path.unlink()
            except OSError:
                pass

        old_umask = os.umask(0o177)
        try:
            self._server = _ThreadingUnixHTTPServer(str(self.sock_path), _StudioIPCHandler, self)
        finally:
            os.umask(old_umask)
        os.chmod(self.sock_path, 0o600)

        self._stopping.clear()
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.2},
            name=f"studio-ipc-{self.bot_handle}",
            daemon=True,
        )
        self._thread.start()
        return self.sock_path

    def stop(self) -> None:
        self._stopping.set()
        srv = self._server
        self._server = None
        if srv is not None:
            try:
                srv.shutdown()
            except Exception:
                pass
            try:
                srv.server_close()
            except Exception:
                pass
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None
        for p in (self.sock_path, self.token_path):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
