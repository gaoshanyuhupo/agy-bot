#!/usr/bin/env python3
"""Zero-trust authentication, session, CSRF, Origin & live RBAC for AGY Studio.

Auth modes (`AGY_STUDIO_AUTH_MODE`, default `'password'`):
- `'password'` (default):
  - Username + scrypt password authentication (`POST /api/auth/login`) backed by an external
    `0600` `users.json` store (fail-closed when missing/corrupt; zero hardcoded credentials).
  - Password change (`POST /api/auth/change-password`) with strict policy, Same-Origin + CSRF,
    session rotation, and immediate eviction of sibling sessions & active WebSockets.
  - Mandatory `must_change_password=True` server-side hard gate across all business APIs and WS.
  - Effective role is strictly `min(user.role, env_live_role)` recomputed live on every request,
    every WebSocket frame, and watchdog heartbeat.
  - Constant-time anti-enumeration verification + bounded-memory rate limiting before scrypt.
  - Legacy `/api/auth/telegram`, `/api/auth/redeem`, and `/internal/magic-link` return HTTP 403.
- `'legacy'`:
  - Preserves dual-track Telegram Mini App HMAC (`POST /api/auth/telegram`) + 60s single-use
    Magic Link (`POST /internal/magic-link` -> `POST /api/auth/redeem`) with zero cross-track
    fallback. Password endpoints return HTTP 403.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from collections import OrderedDict, deque
from contextlib import contextmanager
import fcntl
import getpass
import hashlib
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import sys
import time
from typing import Any, Awaitable, Callable, Iterator
import urllib.parse
import weakref

from aiohttp import web

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BRIDGE_SRC_DIR = _REPO_ROOT / "bridge"
if str(_BRIDGE_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_BRIDGE_SRC_DIR))

import access_control  # noqa: E402

SESSION_COOKIE_NAME = "agy_studio_session"
DEFAULT_SESSION_TTL_SEC = 12 * 3600
DEFAULT_MAGIC_TTL_SEC = 60.0
DEFAULT_TG_INIT_MAX_AGE_SEC = 3600
MAX_PENDING_MAGIC_TOKENS = 256
MAX_ACTIVE_SESSIONS = 128

VALID_AUTH_MODES = ("password", "legacy")
DEFAULT_AUTH_MODE = "password"

SCRYPT_N = 16384  # 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_SALT_LEN = 16
SCRYPT_MAXMEM = 64 * 1024 * 1024

MAX_USERNAME_LEN = 64
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 128
MAX_PASSWORD_BYTES = 256

DEFAULT_IP_MAX_FAILURES = 10
DEFAULT_IP_WINDOW_SEC = 300.0
DEFAULT_MAX_IP_BUCKETS = 1024
DEFAULT_USER_MAX_FAILURES = 8
DEFAULT_USER_WINDOW_SEC = 300.0
DEFAULT_MAX_USER_BUCKETS = 1024
DEFAULT_GLOBAL_MAX_FAILURES = 60
DEFAULT_GLOBAL_WINDOW_SEC = 60.0

_DUMMY_SCRYPT_SALT = b"agy_studio_dummy"
_DUMMY_SCRYPT_DK = hashlib.scrypt(
    b"DUMMY_CONSTANT_TIME_SENTINEL",
    salt=_DUMMY_SCRYPT_SALT,
    n=SCRYPT_N,
    r=SCRYPT_R,
    p=SCRYPT_P,
    dklen=SCRYPT_DKLEN,
    maxmem=SCRYPT_MAXMEM,
)

_IGNORED_ENV_SUFFIXES = (
    ".bak",
    ".tmp",
    ".example",
    ".sample",
    ".orig",
    ".old",
    ".swp",
    ".dist",
    ".disabled",
)
_IGNORED_ENV_KEYS = frozenset(s.lstrip(".") for s in _IGNORED_ENV_SUFFIXES)
_ENV_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_USERNAME_SAFE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")


def parse_strict_int(raw: Any) -> int | None:
    """Parse an integer strictly (rejecting bool, float, None, or non-ASCII numeric strings)."""
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return None
        digits = s[1:] if s.startswith("-") else s
        if not digits or not digits.isascii() or not digits.isdigit():
            return None
        try:
            return int(s)
        except (TypeError, ValueError):
            return None
    return None


def intersect_roles(user_role: str, env_role: str) -> str:
    """Least-privilege intersection of `users.json` role and `.env*` live RBAC role."""
    if user_role not in ("admin", "readonly") or env_role not in ("admin", "readonly"):
        return "denied"
    if user_role == "admin" and env_role == "admin":
        return "admin"
    return "readonly"


def hash_password_scrypt(password: str) -> str:
    """Hash a password with stdlib `hashlib.scrypt` and a fresh 16-byte random salt."""
    salt = secrets.token_bytes(SCRYPT_SALT_LEN)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    dk_b64 = base64.b64encode(dk).decode("ascii")
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt_b64}${dk_b64}"


def _parse_scrypt_hash(stored_hash: Any) -> tuple[int, int, int, bytes, bytes] | None:
    """Parse and strictly validate a `scrypt$N$r$p$<salt_b64>$<dk_b64>` string."""
    if not isinstance(stored_hash, str):
        return None
    parts = stored_hash.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return None
    n = parse_strict_int(parts[1])
    r = parse_strict_int(parts[2])
    p = parse_strict_int(parts[3])
    if n is None or r is None or p is None:
        return None
    # n must be a power of 2 in a safe bounded range
    if n < 1024 or n > 65536 or (n & (n - 1)) != 0:
        return None
    if not (1 <= r <= 32) or not (1 <= p <= 8):
        return None
    # Guard scrypt memory usage (~128 * n * r * p)
    if 128 * n * r * p > SCRYPT_MAXMEM:
        return None
    try:
        salt = base64.b64decode(parts[4].encode("ascii"), validate=True)
        dk = base64.b64decode(parts[5].encode("ascii"), validate=True)
    except Exception:
        return None
    if not (8 <= len(salt) <= 64) or not (16 <= len(dk) <= 64):
        return None
    return n, r, p, salt, dk


def is_valid_scrypt_hash(stored_hash: Any) -> bool:
    return _parse_scrypt_hash(stored_hash) is not None


def run_dummy_scrypt(password: str) -> bool:
    """Execute constant-parameter dummy scrypt work to prevent account-enumeration timing leaks."""
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=_DUMMY_SCRYPT_SALT,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    hmac.compare_digest(derived, _DUMMY_SCRYPT_DK)
    return False


def verify_scrypt_hash(password: str, stored_hash: Any) -> bool:
    """Verify `password` against a stored scrypt hash in constant time (runs dummy scrypt if malformed)."""
    parsed = _parse_scrypt_hash(stored_hash)
    if parsed is None:
        return run_dummy_scrypt(password)
    n, r, p, salt, dk = parsed
    try:
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(dk),
            maxmem=SCRYPT_MAXMEM,
        )
    except Exception:
        return run_dummy_scrypt(password)
    return hmac.compare_digest(derived, dk)


def validate_username_input(raw: Any) -> tuple[bool, str, str, str]:
    """Validate login username input; returns `(ok, display_name, norm_key, error)`."""
    if not isinstance(raw, str):
        return False, "", "", "用户名格式无效"
    if len(raw) > MAX_USERNAME_LEN * 2:
        return False, "", "", f"用户名长度不得超过 {MAX_USERNAME_LEN} 个字符"
    text = raw.strip()
    if not text:
        return False, "", "", "请输入用户名"
    if len(text) > MAX_USERNAME_LEN:
        return False, "", "", f"用户名长度不得超过 {MAX_USERNAME_LEN} 个字符"
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return False, "", "", "用户名包含非法控制字符"
    return True, text, text.lower(), ""


def validate_new_password(
    new_password: Any,
    *,
    current_password: str | None = None,
    username: str | None = None,
) -> tuple[bool, str]:
    """Enforce C5 password complexity policy."""
    if not isinstance(new_password, str) or not new_password:
        return False, "新密码不能为空"
    if len(new_password) < MIN_PASSWORD_LEN or len(new_password) > MAX_PASSWORD_LEN:
        return False, f"新密码长度须在 {MIN_PASSWORD_LEN} 到 {MAX_PASSWORD_LEN} 个字符之间"
    if len(new_password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False, f"新密码 UTF-8 字节长度不得超过 {MAX_PASSWORD_BYTES} 字节"
    if not new_password.strip():
        return False, "新密码不能为纯空白字符"
    if current_password is not None and new_password == current_password:
        return False, "新密码不得与当前密码相同"
    if username is not None:
        norm_user = username.strip().lower()
        if norm_user and (new_password.lower() == norm_user or new_password.strip().lower() == norm_user):
            return False, "新密码不得与用户名相同"
    return True, ""


def _validate_user_record(rec: Any) -> dict[str, Any] | None:
    """Strictly validate a single user record from `users.json` (returns None on any corruption)."""
    if not isinstance(rec, dict):
        return None
    raw_username = rec.get("username")
    if not isinstance(raw_username, str):
        return None
    username = raw_username.strip()
    if not username or len(username) > MAX_USERNAME_LEN:
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in username):
        return None

    pw_hash = rec.get("password_hash")
    if not is_valid_scrypt_hash(pw_hash):
        return None

    role = rec.get("role")
    if not isinstance(role, str) or role not in ("admin", "readonly"):
        return None

    bot = rec.get("bot")
    if not isinstance(bot, str):
        return None
    bot = bot.strip()
    if not bot or not _ENV_KEY_RE.match(bot):
        return None

    user_id = rec.get("user_id")
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        return None

    enabled = rec.get("enabled")
    if not isinstance(enabled, bool):
        return None

    must_change = rec.get("must_change_password")
    if not isinstance(must_change, bool):
        return None

    pw_ver = rec.get("password_version")
    if isinstance(pw_ver, bool) or not isinstance(pw_ver, int) or pw_ver < 1:
        return None

    created_at = rec.get("created_at")
    updated_at = rec.get("updated_at")
    if (
        isinstance(created_at, bool)
        or not isinstance(created_at, (int, float))
        or not math.isfinite(created_at)
        or isinstance(updated_at, bool)
        or not isinstance(updated_at, (int, float))
        or not math.isfinite(updated_at)
    ):
        return None

    return {
        "username": username,
        "password_hash": pw_hash,
        "role": role,
        "bot": bot,
        "user_id": user_id,
        "enabled": enabled,
        "must_change_password": must_change,
        "password_version": pw_ver,
        "created_at": int(created_at),
        "updated_at": int(updated_at),
    }


def load_users_file(path: Path) -> tuple[bool, dict[str, dict[str, Any]]]:
    """Load and validate `users.json` strictly fail-closed.

    Returns `(store_valid, users_by_norm_key)`.
    If the file is missing, unreadable, empty, invalid JSON, structurally malformed, or
    contains any corrupt/invalid user entry, returns `(False, {})` (whole-store fail-closed).
    """
    if not path.is_file():
        return False, {}
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError:
        return False, {}
    if not raw_text.strip():
        return False, {}
    try:
        doc = json.loads(raw_text)
    except Exception:
        return False, {}
    if not isinstance(doc, dict):
        return False, {}
    raw_users = doc.get("users")
    if not isinstance(raw_users, dict):
        return False, {}

    normalized: dict[str, dict[str, Any]] = {}
    seen_keys: set[str] = set()
    for raw_key, raw_rec in raw_users.items():
        if not isinstance(raw_key, str) or not raw_key.strip():
            return False, {}
        k_norm = raw_key.strip().lower()
        if k_norm in seen_keys:
            # Ambiguous duplicate case-folded keys -> fail-closed for the whole store
            return False, {}
        seen_keys.add(k_norm)
        valid_rec = _validate_user_record(raw_rec)
        if valid_rec is None:
            return False, {}
        if valid_rec["username"].lower() != k_norm:
            return False, {}
        normalized[k_norm] = valid_rec
    return True, normalized


@contextmanager
def _users_file_lock(users_file: Path) -> Iterator[None]:
    """Acquire an advisory flock guarding read-modify-write mutations to `users.json`."""
    users_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(users_file.parent, 0o700)
    except OSError:
        pass
    lock_path = users_file.parent / f".{users_file.name}.lock"
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            os.chmod(lock_path, 0o600)
        except OSError:
            pass
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def save_users_file_atomic(path: Path, users_by_key: dict[str, dict[str, Any]]) -> None:
    """Atomically persist `users.json` with `0700` dir perms and `0600` file perms."""
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)

    payload = {
        "version": 1,
        "users": {k: users_by_key[k] for k in sorted(users_by_key)},
    }
    encoded = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

    tmp_name = f".{path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}"
    tmp_path = path.parent / tmp_name
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


class LoginRateLimiter:
    """Bounded-memory sliding-window rate limiter across IP, normalized username, and global buckets."""

    def __init__(
        self,
        *,
        now_fn: Callable[[], float] | None = None,
        ip_max_failures: int = DEFAULT_IP_MAX_FAILURES,
        ip_window_sec: float = DEFAULT_IP_WINDOW_SEC,
        max_ip_buckets: int = DEFAULT_MAX_IP_BUCKETS,
        user_max_failures: int = DEFAULT_USER_MAX_FAILURES,
        user_window_sec: float = DEFAULT_USER_WINDOW_SEC,
        max_user_buckets: int = DEFAULT_MAX_USER_BUCKETS,
        global_max_failures: int = DEFAULT_GLOBAL_MAX_FAILURES,
        global_window_sec: float = DEFAULT_GLOBAL_WINDOW_SEC,
    ) -> None:
        self._now = now_fn or time.time
        self.ip_max_failures = max(1, int(ip_max_failures))
        self.ip_window_sec = max(1.0, float(ip_window_sec))
        self.max_ip_buckets = max(1, int(max_ip_buckets))

        self.user_max_failures = max(1, int(user_max_failures))
        self.user_window_sec = max(1.0, float(user_window_sec))
        self.max_user_buckets = max(1, int(max_user_buckets))

        self.global_max_failures = max(1, int(global_max_failures))
        self.global_window_sec = max(1.0, float(global_window_sec))

        self._ip_buckets: OrderedDict[str, deque[float]] = OrderedDict()
        self._user_buckets: OrderedDict[str, deque[float]] = OrderedDict()
        self._global_failures: deque[float] = deque(maxlen=self.global_max_failures + 16)

    @staticmethod
    def _prune_deque(dq: deque[float], cutoff: float) -> None:
        while dq and dq[0] <= cutoff:
            dq.popleft()

    def _prune_bucket_map(
        self,
        buckets: OrderedDict[str, deque[float]],
        now: float,
        window_sec: float,
    ) -> None:
        cutoff = now - window_sec
        expired_keys: list[str] = []
        for key, dq in buckets.items():
            self._prune_deque(dq, cutoff)
            if not dq:
                expired_keys.append(key)
        for key in expired_keys:
            buckets.pop(key, None)

    def _record_in_map(
        self,
        buckets: OrderedDict[str, deque[float]],
        key: str,
        now: float,
        window_sec: float,
        max_buckets: int,
        max_failures: int,
    ) -> None:
        if not key:
            return
        dq = buckets.get(key)
        if dq is not None:
            self._prune_deque(dq, now - window_sec)
            dq.append(now)
            buckets.move_to_end(key)
            return
        if len(buckets) >= max_buckets:
            self._prune_bucket_map(buckets, now, window_sec)
            while len(buckets) >= max_buckets:
                buckets.popitem(last=False)
        buckets[key] = deque([now], maxlen=max_failures + 16)

    def check(self, client_ip: str, norm_username: str) -> tuple[bool, int]:
        """Check whether a login/password-change attempt is permitted before entering scrypt."""
        now = self._now()
        retry_after = 0

        # 1. Global failure bucket
        self._prune_deque(self._global_failures, now - self.global_window_sec)
        if len(self._global_failures) >= self.global_max_failures:
            wait = math.ceil((self._global_failures[0] + self.global_window_sec) - now)
            retry_after = max(retry_after, max(1, wait))

        # 2. Client IP bucket
        if client_ip:
            ip_dq = self._ip_buckets.get(client_ip)
            if ip_dq is not None:
                self._prune_deque(ip_dq, now - self.ip_window_sec)
                if not ip_dq:
                    self._ip_buckets.pop(client_ip, None)
                elif len(ip_dq) >= self.ip_max_failures:
                    wait = math.ceil((ip_dq[0] + self.ip_window_sec) - now)
                    retry_after = max(retry_after, max(1, wait))

        # 3. Normalized username bucket
        if norm_username:
            u_dq = self._user_buckets.get(norm_username)
            if u_dq is not None:
                self._prune_deque(u_dq, now - self.user_window_sec)
                if not u_dq:
                    self._user_buckets.pop(norm_username, None)
                elif len(u_dq) >= self.user_max_failures:
                    wait = math.ceil((u_dq[0] + self.user_window_sec) - now)
                    retry_after = max(retry_after, max(1, wait))

        if retry_after > 0:
            return False, retry_after
        return True, 0

    def record_failure(self, client_ip: str, norm_username: str) -> None:
        now = self._now()
        self._prune_deque(self._global_failures, now - self.global_window_sec)
        self._global_failures.append(now)
        self._record_in_map(
            self._ip_buckets,
            client_ip,
            now,
            self.ip_window_sec,
            self.max_ip_buckets,
            self.ip_max_failures,
        )
        self._record_in_map(
            self._user_buckets,
            norm_username,
            now,
            self.user_window_sec,
            self.max_user_buckets,
            self.user_max_failures,
        )

    def clear_username(self, norm_username: str) -> None:
        if norm_username:
            self._user_buckets.pop(norm_username, None)


def _parse_user_roles_map(raw: str | None) -> dict[int, str]:
    out: dict[int, str] = {}
    if not raw:
        return out
    text = str(raw).strip()
    if not text:
        return out
    if text.startswith("{"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                for k, v in obj.items():
                    uid = parse_strict_int(str(k).strip())
                    role = str(v or "").strip().lower()
                    if uid is not None and role in ("admin", "readonly", "denied"):
                        out[uid] = role
                return out
        except Exception:
            pass
    for item in text.replace(" ", ",").split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        uid_s, role_s = item.split(":", 1)
        uid = parse_strict_int(uid_s.strip())
        role = role_s.strip().lower()
        if uid is not None and role in ("admin", "readonly", "denied"):
            out[uid] = role
    return out


def discover_bridge_env_files(bridge_dir: Path) -> dict[str, Path]:
    """Discover `.env` (`main`) and `.env.<key>` runtime files under `bridge_dir`."""
    found: dict[str, Path] = {}
    if not bridge_dir.is_dir():
        return found
    main_env = bridge_dir / ".env"
    if main_env.is_file():
        found["main"] = main_env
    try:
        entries = sorted(bridge_dir.iterdir(), key=lambda p: p.name)
    except OSError:
        return found
    for entry in entries:
        if not entry.is_file():
            continue
        name = entry.name
        if not name.startswith(".env.") or name == ".env":
            continue
        low = name.lower()
        if any(low.endswith(sfx) for sfx in _IGNORED_ENV_SUFFIXES):
            continue
        key = name[5:]
        if not key or "." in key or key.lower() in _IGNORED_ENV_KEYS:
            continue
        if not _ENV_KEY_RE.match(key):
            continue
        found[key] = entry
    return found


def _resolve_bot_roles_from_env(env_map: dict[str, str], bot_allowed: set[int]) -> dict[int, str]:
    """Resolve per-user RBAC role matching `bridge/access_control.py` and `live_browser_server.py`."""
    allowed_users = access_control.parse_uid_set(env_map.get("AGY_TG_ALLOWED_USERS"))
    admin_users = access_control.parse_uid_set(env_map.get("AGY_TG_ADMIN_USERS"))
    readonly_users = access_control.parse_uid_set(env_map.get("AGY_TG_READONLY_USERS"))
    explicit_roles = _parse_user_roles_map(env_map.get("AGY_TG_USER_ROLES"))

    for uid, role in explicit_roles.items():
        if role == "admin":
            admin_users.add(uid)
            readonly_users.discard(uid)
        elif role == "readonly":
            readonly_users.add(uid)
            admin_users.discard(uid)
            allowed_users.discard(uid)

    effective_admins = admin_users if admin_users else allowed_users
    roles: dict[int, str] = {}
    for cid in bot_allowed:
        if cid <= 0:
            continue
        if explicit_roles.get(cid) == "denied":
            roles[cid] = "denied"
            continue
        if effective_admins:
            if cid in effective_admins:
                roles[cid] = "admin"
            elif cid in readonly_users:
                roles[cid] = "readonly"
            elif admin_users and allowed_users and cid in allowed_users:
                roles[cid] = "readonly"
            else:
                roles[cid] = "denied"
        else:
            if cid in readonly_users:
                roles[cid] = "readonly"
            else:
                roles[cid] = "admin"
    return roles


def load_bot_auth_context(
    bridge_dir: Path,
) -> tuple[dict[str, str], dict[str, set[int]], dict[str, dict[int, str]]]:
    """Freshly parse `.env*` files to return `(bots_by_key, allowed_by_bot, bot_roles)`."""
    bots_by_key: dict[str, str] = {}
    allowed_by_bot: dict[str, set[int]] = {}
    bot_roles: dict[str, dict[int, str]] = {}

    for key, path in discover_bridge_env_files(bridge_dir).items():
        if not path.is_file():
            continue
        env_map: dict[str, str] = {}
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env_map[k.strip()] = v.strip().strip("'\"")
        token = env_map.get("AGY_TG_BOT_TOKEN", "")
        if not (token and ":" in token):
            continue
        bot_allowed = access_control.parse_uid_set(env_map.get("AGY_TG_ALLOWED_CHATS"))
        bots_by_key[key] = token
        allowed_by_bot[key] = bot_allowed
        bot_roles[key] = _resolve_bot_roles_from_env(env_map, bot_allowed)

    return bots_by_key, allowed_by_bot, bot_roles


_STRICT_ORIGIN_RE = re.compile(
    r"^(?P<scheme>https?)://"
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)"
    r"(?::(?P<port>[0-9]{1,5}))?$",
    re.IGNORECASE,
)


def normalize_origin(raw: str | None) -> str:
    """Normalize an HTTP Origin header or base URL into strict `scheme://host[:port]` (empty if invalid).

    Strictly rejects any path (including `/`), params, query/fragment (including bare `?` or `#`),
    empty port (trailing `:`), userinfo, whitespace/control characters, or out-of-range/non-numeric ports.
    """
    if not raw or not isinstance(raw, str):
        return ""
    text = raw.strip()
    if not text or text.lower() == "null":
        return ""
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return ""
    m = _STRICT_ORIGIN_RE.fullmatch(text)
    if not m:
        return ""
    try:
        parsed = urllib.parse.urlparse(text)
    except Exception:
        return ""
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return ""
    if parsed.path or parsed.params or parsed.query or parsed.fragment:
        return ""
    if parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
        return ""
    raw_host = m.group("host")
    port_str = m.group("port")
    if port_str is not None and port_str.startswith("0"):
        return ""
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    if raw_host.startswith("["):
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return ""
    else:
        if ".." in host or any(
            not lbl or lbl.startswith("-") or lbl.endswith("-") for lbl in host.split(".")
        ):
            return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port is not None and not (1 <= port <= 65535):
        return ""
    default_port = 443 if scheme == "https" else 80
    host_fmt = f"[{host}]" if ":" in host else host
    if port is None or port == default_port:
        return f"{scheme}://{host_fmt}"
    return f"{scheme}://{host_fmt}:{port}"


def _sha256_hex(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


def studio_auth_error(
    error: str,
    *,
    status: int = 403,
    extra: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> web.Response:
    """Return a standardized Studio-side authentication/authorization error response."""
    body: dict[str, Any] = {"ok": False, "source": "studio_auth", "error": error}
    if extra:
        body.update(extra)
    resp_headers = {"Cache-Control": "no-store, max-age=0"}
    if headers:
        resp_headers.update(headers)
    return web.json_response(body, status=status, headers=resp_headers)


def upstream_error(error: str, *, status: int = 502) -> web.Response:
    """Return a standardized upstream (live-browser / target) error response."""
    return web.json_response(
        {"ok": False, "source": "upstream", "error": error},
        status=status,
        headers={"Cache-Control": "no-store, max-age=0"},
    )


class StudioAuthManager:
    """Manages password/legacy auth modes, sessions, CSRF, Origin, rate limiting, and live RBAC."""

    def __init__(
        self,
        *,
        config_dir: Path | None = None,
        bridge_dir: Path | None = None,
        users_file: Path | None = None,
        auth_mode: str | None = None,
        public_url: str = "",
        allowed_origins: str | list[str] | tuple[str, ...] | set[str] | None = None,
        session_ttl_sec: float = DEFAULT_SESSION_TTL_SEC,
        magic_ttl_sec: float = DEFAULT_MAGIC_TTL_SEC,
        tg_init_max_age_sec: int = DEFAULT_TG_INIT_MAX_AGE_SEC,
        now_fn: Callable[[], float] | None = None,
        scrypt_concurrency: int = 4,
        ip_max_failures: int = DEFAULT_IP_MAX_FAILURES,
        ip_window_sec: float = DEFAULT_IP_WINDOW_SEC,
        max_ip_buckets: int = DEFAULT_MAX_IP_BUCKETS,
        user_max_failures: int = DEFAULT_USER_MAX_FAILURES,
        user_window_sec: float = DEFAULT_USER_WINDOW_SEC,
        max_user_buckets: int = DEFAULT_MAX_USER_BUCKETS,
        global_max_failures: int = DEFAULT_GLOBAL_MAX_FAILURES,
        global_window_sec: float = DEFAULT_GLOBAL_WINDOW_SEC,
    ) -> None:
        if auth_mode is None:
            env_mode = os.environ.get("AGY_STUDIO_AUTH_MODE")
            if env_mode is None or not env_mode.strip():
                norm_mode = DEFAULT_AUTH_MODE
            else:
                norm_mode = env_mode.strip().lower()
        else:
            if not isinstance(auth_mode, str):
                raise ValueError(f"Invalid AGY_STUDIO_AUTH_MODE {auth_mode!r}: must be 'password' or 'legacy'")
            norm_mode = auth_mode.strip().lower()
        if norm_mode not in VALID_AUTH_MODES:
            raise ValueError(
                f"Invalid AGY_STUDIO_AUTH_MODE {norm_mode!r}: must be one of {VALID_AUTH_MODES}"
            )
        self.auth_mode: str = norm_mode

        self.config_dir = config_dir or Path(
            os.environ.get("AGY_STUDIO_CONFIG_DIR", str(Path.home() / ".config/agy-studio"))
        )
        self.bridge_dir = bridge_dir or Path(
            os.environ.get("AGY_TG_BRIDGE_DIR", str(Path.home() / "agy-tg-bridge"))
        )
        self.users_file = Path(users_file) if users_file is not None else (self.config_dir / "users.json")

        raw_public = (public_url or "").strip()
        if raw_public:
            # Allow a single trailing slash on base URL only if there is no path/query/fragment
            cand_pub = (
                raw_public[:-1]
                if raw_public.endswith("/") and not raw_public.endswith("://") and raw_public.count("/") == 3
                else raw_public
            )
            norm_pub = normalize_origin(cand_pub)
            if not norm_pub or not norm_pub.startswith("https://"):
                raise ValueError(
                    f"Invalid AGY_STUDIO_PUBLIC_URL {raw_public!r}: public mode requires a valid https:// origin"
                )
            self.public_url = norm_pub
        else:
            self.public_url = ""

        raw_extra = (
            os.environ.get("AGY_STUDIO_ALLOWED_ORIGINS", "")
            if allowed_origins is None
            else allowed_origins
        )
        extra_items = raw_extra.split(",") if isinstance(raw_extra, str) else list(raw_extra)
        validated_extras: list[str] = []
        for item in extra_items:
            s_item = str(item or "").strip()
            if not s_item:
                continue
            norm_item = normalize_origin(s_item)
            if not norm_item:
                raise ValueError(f"Invalid origin in AGY_STUDIO_ALLOWED_ORIGINS: {s_item!r}")
            if self.public_url and not norm_item.startswith("https://"):
                raise ValueError(
                    f"Public mode requires https:// in AGY_STUDIO_ALLOWED_ORIGINS, got {s_item!r}"
                )
            validated_extras.append(norm_item)
        self.extra_allowed_origins: frozenset[str] = frozenset(validated_extras)
        self.session_ttl_sec = float(session_ttl_sec)
        self.magic_ttl_sec = float(magic_ttl_sec)
        self.tg_init_max_age_sec = int(tg_init_max_age_sec)
        self._now = now_fn or time.time
        self._scrypt_concurrency = max(1, int(scrypt_concurrency))
        self._scrypt_sems: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Semaphore] = (
            weakref.WeakKeyDictionary()
        )

        self.rate_limiter = LoginRateLimiter(
            now_fn=self._now,
            ip_max_failures=ip_max_failures,
            ip_window_sec=ip_window_sec,
            max_ip_buckets=max_ip_buckets,
            user_max_failures=user_max_failures,
            user_window_sec=user_window_sec,
            max_user_buckets=max_user_buckets,
            global_max_failures=global_max_failures,
            global_window_sec=global_window_sec,
        )

        self.local_token_file = self.config_dir / "local.token"
        self.local_token = self._ensure_local_token()

        # Keyed strictly by SHA-256 hash (plaintext tokens/session IDs never persisted in memory)
        self._magic_tokens: dict[str, dict[str, Any]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._revoke_listeners: list[Callable[..., Awaitable[None]]] = []

    def _get_scrypt_semaphore(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        sem = self._scrypt_sems.get(loop)
        if sem is None:
            sem = asyncio.Semaphore(self._scrypt_concurrency)
            self._scrypt_sems[loop] = sem
        return sem

    async def _run_scrypt_bounded(self, fn: Callable[..., Any], *args: Any) -> Any:
        sem = self._get_scrypt_semaphore()
        async with sem:
            return await asyncio.to_thread(fn, *args)

    def _ensure_local_token(self) -> str:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.config_dir, 0o700)
        except OSError:
            pass
        if self.local_token_file.is_file():
            tok = self.local_token_file.read_text(encoding="utf-8").strip()
            if tok:
                try:
                    os.chmod(self.local_token_file, 0o600)
                except OSError:
                    pass
                return tok
        tok = secrets.token_urlsafe(32)
        tmp = self.local_token_file.with_suffix(".tmp")
        tmp.write_text(tok + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.local_token_file)
        return tok

    def add_revoke_listener(
        self,
        cb: Callable[..., Awaitable[None]],
    ) -> None:
        self._revoke_listeners.append(cb)

    async def _notify_revoke(
        self,
        *,
        session_hash: str | None = None,
        bot: str | None = None,
        user_id: int | None = None,
        username_key: str | None = None,
        exclude_session_hash: str | None = None,
    ) -> None:
        for cb in list(self._revoke_listeners):
            try:
                if username_key is not None or exclude_session_hash is not None:
                    await cb(
                        session_hash,
                        bot,
                        user_id,
                        username_key=username_key,
                        exclude_session_hash=exclude_session_hash,
                    )
                else:
                    await cb(session_hash, bot, user_id)
            except Exception:
                pass

    def extract_client_ip(self, request: web.Request) -> str:
        """Extract client IP safely, trusting CF-Connecting-IP ONLY in public mode from loopback."""
        peer = (request.remote or "").strip()
        if self.public_url and peer in ("127.0.0.1", "::1"):
            cf_ip = (request.headers.get("CF-Connecting-IP") or "").strip()
            if cf_ip:
                try:
                    return str(ipaddress.ip_address(cf_ip))
                except ValueError:
                    pass
        return peer or "unknown"

    def resolve_live_role(self, bot_key: str, user_id: int) -> str:
        """Recompute live RBAC role from `.env*` (`'admin'`, `'readonly'`, or `'denied'`)."""
        clean_bot = str(bot_key or "").strip()
        if not clean_bot or not isinstance(user_id, int) or isinstance(user_id, bool) or user_id <= 0:
            return "denied"
        bots, allowed_by_bot, bot_roles = load_bot_auth_context(self.bridge_dir)
        if clean_bot not in bots:
            return "denied"
        if user_id not in allowed_by_bot.get(clean_bot, set()):
            return "denied"
        role = (bot_roles.get(clean_bot) or {}).get(user_id, "denied")
        return role if role in ("admin", "readonly") else "denied"

    def verify_internal_loopback(self, request: web.Request) -> tuple[bool, str]:
        """Verify strictly local loopback call without proxy headers + valid internal token."""
        peer = (request.remote or "").strip()
        if peer not in ("127.0.0.1", "::1"):
            return False, "内部接口仅允许本机回环地址访问"
        if "X-Forwarded-For" in request.headers or "CF-Connecting-IP" in request.headers:
            return False, "内部接口拒绝携带代理转发头的请求"
        tok = request.headers.get("X-Studio-Internal-Token", "")
        if not self.local_token or not tok or not hmac.compare_digest(tok, self.local_token):
            return False, "内部鉴权令牌无效"
        return True, ""

    def _prune_expired(self, now: float) -> None:
        for h, entry in list(self._magic_tokens.items()):
            if now > float(entry.get("expires_at", 0.0)):
                self._magic_tokens.pop(h, None)
        for sh, sess in list(self._sessions.items()):
            if now > float(sess.get("expires_at", 0.0)):
                self._sessions.pop(sh, None)

    def issue_magic_link(
        self,
        bot_key: Any,
        raw_user_id: Any,
        *,
        fallback_base_url: str = "",
    ) -> tuple[bool, dict[str, Any] | None, str]:
        """Issue a 60s single-use desktop magic link after live RBAC verification (legacy mode only)."""
        if self.auth_mode != "legacy":
            return (
                False,
                None,
                "当前 WebUI 已切换为账号密码登录模式，一次性魔法链接已停用，请直接使用账号密码登录",
            )
        clean_bot = str(bot_key or "").strip()
        uid = parse_strict_int(raw_user_id)
        if not clean_bot or uid is None or uid <= 0:
            return False, None, "缺少有效的 bot 或正整数 user_id"

        role = self.resolve_live_role(clean_bot, uid)
        if role not in ("admin", "readonly"):
            return False, None, f"账号 {uid} 在机器人 {clean_bot} 上无有效授权"

        now = self._now()
        self._prune_expired(now)
        if len(self._magic_tokens) >= MAX_PENDING_MAGIC_TOKENS:
            oldest_key = min(self._magic_tokens, key=lambda k: self._magic_tokens[k]["created_at"])
            self._magic_tokens.pop(oldest_key, None)

        raw_token = secrets.token_urlsafe(32)
        token_hash = _sha256_hex(raw_token)
        expires_at = now + self.magic_ttl_sec
        self._magic_tokens[token_hash] = {
            "bot": clean_bot,
            "user_id": uid,
            "created_at": now,
            "expires_at": expires_at,
        }

        base = (self.public_url or fallback_base_url or "http://127.0.0.1:18796").strip().rstrip("/")
        magic_url = f"{base}/auth/magic#t={urllib.parse.quote(raw_token, safe='')}"
        return True, {
            "ok": True,
            "url": magic_url,
            "bot": clean_bot,
            "user_id": uid,
            "role": role,
            "ttl_seconds": int(self.magic_ttl_sec),
            "expires_at": int(expires_at),
        }, ""

    def _create_session(
        self,
        *,
        bot: str,
        user_id: int,
        role: str,
        auth_track: str,
        user_meta: dict[str, Any] | None = None,
        username: str = "",
        username_key: str = "",
        password_version: int = 0,
        must_change_password: bool = False,
    ) -> tuple[str, dict[str, Any]]:
        now = self._now()
        self._prune_expired(now)
        if len(self._sessions) >= MAX_ACTIVE_SESSIONS:
            oldest_key = min(self._sessions, key=lambda k: self._sessions[k]["last_seen"])
            self._sessions.pop(oldest_key, None)

        raw_sid = secrets.token_urlsafe(32)
        sid_hash = _sha256_hex(raw_sid)
        csrf_token = secrets.token_urlsafe(24)
        safe_user: dict[str, Any] = {"id": user_id}
        if isinstance(user_meta, dict):
            for k in ("first_name", "last_name", "username"):
                val = user_meta.get(k)
                if isinstance(val, str) and val.strip():
                    safe_user[k] = val.strip()[:64]
        if username:
            safe_user["username"] = username[:64]
        rec: dict[str, Any] = {
            "session_hash": sid_hash,
            "bot": bot,
            "user_id": user_id,
            "role": role,
            "auth_track": auth_track,
            "csrf_token": csrf_token,
            "user": safe_user,
            "created_at": now,
            "last_seen": now,
            "expires_at": now + self.session_ttl_sec,
            "must_change_password": bool(must_change_password),
        }
        if username:
            rec["username"] = username
            rec["username_key"] = username_key or username.strip().lower()
            rec["password_version"] = int(password_version)
        self._sessions[sid_hash] = rec
        return raw_sid, dict(rec)

    def redeem_magic_token(self, raw_token: str) -> tuple[bool, str, dict[str, Any] | None, str]:
        """Track B redemption: atomically consume a single-use magic token and create a session (legacy mode only)."""
        if self.auth_mode != "legacy":
            return False, "", None, "当前已启用账号密码登录模式，一次性魔法链接已停用"
        tok = str(raw_token or "").strip()
        if not tok or len(tok) < 16 or len(tok) > 256:
            return False, "", None, "一次性登录令牌格式无效"

        now = self._now()
        token_hash = _sha256_hex(tok)
        entry = self._magic_tokens.pop(token_hash, None)
        if entry is None:
            return False, "", None, "一次性登录链接无效或已被使用，请重新发送 /webui 获取"
        if now > float(entry.get("expires_at", 0.0)):
            return False, "", None, "一次性登录链接已过期（60 秒有效），请重新发送 /webui 获取"

        bot = str(entry["bot"])
        uid = int(entry["user_id"])
        live_role = self.resolve_live_role(bot, uid)
        if live_role not in ("admin", "readonly"):
            return False, "", None, f"账号 {uid} 已不在机器人 {bot} 的授权白名单中"

        raw_sid, sess = self._create_session(
            bot=bot,
            user_id=uid,
            role=live_role,
            auth_track="magic_link",
        )
        return True, raw_sid, sess, ""

    def authenticate_telegram_init_data(
        self,
        init_data: str,
    ) -> tuple[bool, str, dict[str, Any] | None, str]:
        """Track A authentication: validate Telegram WebApp initData HMAC-SHA256 & live RBAC (legacy mode only)."""
        if self.auth_mode != "legacy":
            return False, "", None, "当前已启用账号密码登录模式，Telegram Mini App 登录已停用"
        raw = str(init_data or "").strip()
        if not raw:
            return False, "", None, "缺少 Telegram Mini App 身份签名（initData）"
        try:
            pairs = urllib.parse.parse_qsl(raw, keep_blank_values=True)
        except Exception:
            return False, "", None, "initData 格式无效"

        params = dict(pairs)
        received_hash = params.get("hash", "")
        auth_date_str = params.get("auth_date", "")
        if not received_hash or not auth_date_str.isdigit():
            return False, "", None, "缺少签名哈希或有效时间戳"

        auth_date = int(auth_date_str)
        now = self._now()
        if abs(now - auth_date) > self.tg_init_max_age_sec:
            return False, "", None, "Telegram 身份签名已过期，请关闭面板重新打开"

        data_check_string = "\n".join(
            f"{k}={v}" for k, v in sorted((k, v) for k, v in pairs if k != "hash")
        )
        bots, allowed_by_bot, bot_roles = load_bot_auth_context(self.bridge_dir)
        matched_bot: str | None = None
        for bot_key, token in bots.items():
            secret_key = hmac.new(b"WebAppData", token.encode("utf-8"), hashlib.sha256).digest()
            expected = hmac.new(
                secret_key, data_check_string.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            if hmac.compare_digest(expected, received_hash):
                matched_bot = bot_key
                break
        if not matched_bot:
            return False, "", None, "Telegram 机器人签名校验不通过"

        try:
            user_obj = json.loads(params.get("user", "{}"))
            uid = parse_strict_int(user_obj.get("id") if isinstance(user_obj, dict) else None)
        except Exception:
            return False, "", None, "无法解析 Telegram 用户身份"
        if uid is None or uid <= 0:
            return False, "", None, "无效的 Telegram 用户 ID"

        if uid not in allowed_by_bot.get(matched_bot, set()):
            return False, "", None, f"账号 {uid} 不在机器人 {matched_bot} 的授权白名单中"

        live_role = (bot_roles.get(matched_bot) or {}).get(uid, "denied")
        if live_role not in ("admin", "readonly"):
            return False, "", None, f"账号 {uid} 在机器人 {matched_bot} 上无有效访问角色"

        raw_sid, sess = self._create_session(
            bot=matched_bot,
            user_id=uid,
            role=live_role,
            auth_track="telegram",
            user_meta=user_obj if isinstance(user_obj, dict) else None,
        )
        return True, raw_sid, sess, ""

    async def authenticate_password(
        self,
        raw_username: Any,
        raw_password: Any,
        *,
        client_ip: str,
    ) -> tuple[bool, str, dict[str, Any] | None, str, int, int]:
        """Password-mode authentication with anti-enumeration constant-time scrypt & bounded rate limiting."""
        if self.auth_mode != "password":
            return False, "", None, "当前为 legacy 双轨模式，账号密码登录未启用", 403, 0

        ok_u, _display_u, norm_u, err_u = validate_username_input(raw_username)
        if not ok_u:
            return False, "", None, err_u, 400, 0

        if not isinstance(raw_password, str) or not raw_password:
            return False, "", None, "请输入密码", 400, 0
        if len(raw_password) > MAX_PASSWORD_LEN:
            return False, "", None, f"密码长度不得超过 {MAX_PASSWORD_LEN} 个字符", 400, 0
        if len(raw_password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            return False, "", None, f"密码长度不得超过 {MAX_PASSWORD_BYTES} 字节", 400, 0

        allowed, retry_after = self.rate_limiter.check(client_ip, norm_u)
        if not allowed:
            return False, "", None, "尝试次数过多，请稍后再试", 429, retry_after

        store_ok, users_map = load_users_file(self.users_file)
        user_rec = users_map.get(norm_u) if store_ok else None

        # Constant-time scrypt execution regardless of account existence / status / corruption
        if user_rec is not None:
            pw_ok = await self._run_scrypt_bounded(
                verify_scrypt_hash, raw_password, user_rec["password_hash"]
            )
        else:
            await self._run_scrypt_bounded(run_dummy_scrypt, raw_password)
            pw_ok = False

        if not store_ok or user_rec is None or not user_rec["enabled"] or not pw_ok:
            self.rate_limiter.record_failure(client_ip, norm_u)
            return False, "", None, "账号或密码错误", 401, 0

        # Re-read users.json synchronously after scrypt to eliminate TOCTOU across concurrent password rotation/disable
        store_ok2, users_map2 = load_users_file(self.users_file)
        cur_rec = users_map2.get(norm_u) if store_ok2 else None
        if (
            not store_ok2
            or cur_rec is None
            or not cur_rec["enabled"]
            or int(cur_rec["password_version"]) != int(user_rec["password_version"])
            or not hmac.compare_digest(str(cur_rec["password_hash"]), str(user_rec["password_hash"]))
        ):
            self.rate_limiter.record_failure(client_ip, norm_u)
            return False, "", None, "账号或密码错误", 401, 0

        env_role = self.resolve_live_role(cur_rec["bot"], cur_rec["user_id"])
        eff_role = intersect_roles(cur_rec["role"], env_role)
        if eff_role not in ("admin", "readonly"):
            self.rate_limiter.record_failure(client_ip, norm_u)
            return False, "", None, "账号或密码错误", 401, 0

        self.rate_limiter.clear_username(norm_u)
        raw_sid, sess = self._create_session(
            bot=cur_rec["bot"],
            user_id=cur_rec["user_id"],
            role=eff_role,
            auth_track="password",
            user_meta={"username": cur_rec["username"]},
            username=cur_rec["username"],
            username_key=norm_u,
            password_version=cur_rec["password_version"],
            must_change_password=cur_rec["must_change_password"],
        )
        # Opportunistically prune only stale-version/stale-binding sessions for this username
        # (never touches sibling sessions already on the current or newer password_version).
        await self._evict_stale_username_sessions(
            norm_u,
            expected_password_version=int(cur_rec["password_version"]),
            expected_bot=str(cur_rec["bot"]),
            expected_user_id=int(cur_rec["user_id"]),
        )
        return True, raw_sid, sess, "", 200, 0

    async def change_password(
        self,
        session: dict[str, Any],
        current_password: Any,
        new_password: Any,
        *,
        client_ip: str,
    ) -> tuple[bool, str, dict[str, Any] | None, str, int, int]:
        """Verify current password, enforce policy, atomically rotate scrypt hash, evict siblings & rotate session."""
        if self.auth_mode != "password":
            return False, "", None, "当前为 legacy 双轨模式，修改密码接口未启用", 403, 0
        if session.get("auth_track") != "password":
            return False, "", None, "当前会话不支持修改密码", 403, 0

        uname_key = str(session.get("username_key") or "").strip().lower()
        uname_display = str(session.get("username") or uname_key)
        caller_sh = str(session.get("session_hash") or "") or None
        if not uname_key:
            return False, "", None, "会话缺少有效账号标识", 403, 0

        if not isinstance(current_password, str) or not current_password:
            return False, "", None, "请输入当前密码", 400, 0
        if len(current_password) > MAX_PASSWORD_LEN:
            return False, "", None, f"当前密码长度不得超过 {MAX_PASSWORD_LEN} 个字符", 400, 0
        if len(current_password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            return False, "", None, f"当前密码长度不得超过 {MAX_PASSWORD_BYTES} 字节", 400, 0

        allowed, retry_after = self.rate_limiter.check(client_ip, uname_key)
        if not allowed:
            return False, "", None, "尝试次数过多，请稍后再试", 429, retry_after

        ok_policy, err_policy = validate_new_password(
            new_password,
            current_password=current_password,
            username=uname_display,
        )
        if not ok_policy:
            return False, "", None, err_policy, 400, 0

        # Freshly load user before verifying current password
        store_ok, users_map = load_users_file(self.users_file)
        user_rec = users_map.get(uname_key) if store_ok else None
        if not store_ok or user_rec is None or not user_rec["enabled"]:
            await self._evict_username_sessions(uname_key)
            return False, "", None, "访问权限已被撤销，会话已立即吊销", 403, 0

        env_role = self.resolve_live_role(user_rec["bot"], user_rec["user_id"])
        eff_role = intersect_roles(user_rec["role"], env_role)
        if eff_role not in ("admin", "readonly"):
            await self._evict_username_sessions(uname_key, bot=user_rec["bot"], user_id=user_rec["user_id"])
            return False, "", None, "访问权限已被撤销，会话已立即吊销", 403, 0

        if (
            user_rec["password_version"] != session.get("password_version")
            or user_rec["bot"] != session.get("bot")
            or user_rec["user_id"] != int(session.get("user_id", 0))
        ):
            await self._evict_stale_username_sessions(
                uname_key,
                expected_password_version=int(user_rec["password_version"]),
                expected_bot=str(user_rec["bot"]),
                expected_user_id=int(user_rec["user_id"]),
                force_session_hash=caller_sh,
            )
            return False, "", None, "访问权限已被撤销，会话已立即吊销", 403, 0

        pw_ok = await self._run_scrypt_bounded(
            verify_scrypt_hash, current_password, user_rec["password_hash"]
        )
        if not pw_ok:
            self.rate_limiter.record_failure(client_ip, uname_key)
            return False, "", None, "当前密码错误", 401, 0

        new_hash = await self._run_scrypt_bounded(hash_password_scrypt, new_password)
        now = self._now()

        # Atomic locked read-modify-write on users.json
        revoke_mode = ""  # "", "account", "rbac", "stale"
        revoke_bot: str | None = None
        revoke_uid: int | None = None
        expected_ver = 0
        expected_bot = ""
        expected_uid = 0
        new_version = 0
        eff_role2 = "denied"
        cur_rec: dict[str, Any] | None = None
        with _users_file_lock(self.users_file):
            store_ok2, users_map2 = load_users_file(self.users_file)
            cur_rec = users_map2.get(uname_key) if store_ok2 else None
            if not store_ok2 or cur_rec is None or not cur_rec["enabled"]:
                revoke_mode = "account"
            else:
                env_role2 = self.resolve_live_role(cur_rec["bot"], cur_rec["user_id"])
                eff_role2 = intersect_roles(cur_rec["role"], env_role2)
                if eff_role2 not in ("admin", "readonly"):
                    revoke_mode = "rbac"
                    revoke_bot = str(cur_rec["bot"])
                    revoke_uid = int(cur_rec["user_id"])
                elif (
                    cur_rec["password_version"] != session.get("password_version")
                    or cur_rec["bot"] != session.get("bot")
                    or cur_rec["user_id"] != int(session.get("user_id", 0))
                ):
                    revoke_mode = "stale"
                    expected_ver = int(cur_rec["password_version"])
                    expected_bot = str(cur_rec["bot"])
                    expected_uid = int(cur_rec["user_id"])
                else:
                    new_version = int(cur_rec["password_version"]) + 1
                    cur_rec["password_hash"] = new_hash
                    cur_rec["must_change_password"] = False
                    cur_rec["password_version"] = new_version
                    cur_rec["updated_at"] = int(now)
                    users_map2[uname_key] = cur_rec
                    save_users_file_atomic(self.users_file, users_map2)

        if revoke_mode == "account":
            await self._evict_username_sessions(uname_key)
            return False, "", None, "访问权限已被撤销，会话已立即吊销", 403, 0
        if revoke_mode == "rbac":
            await self._evict_username_sessions(uname_key, bot=revoke_bot, user_id=revoke_uid)
            return False, "", None, "访问权限已被撤销，会话已立即吊销", 403, 0
        if revoke_mode == "stale":
            await self._evict_stale_username_sessions(
                uname_key,
                expected_password_version=expected_ver,
                expected_bot=expected_bot,
                expected_user_id=expected_uid,
                force_session_hash=caller_sh,
            )
            return False, "", None, "访问权限已被撤销，会话已立即吊销", 403, 0

        assert cur_rec is not None
        # Evict ALL pre-rotation sessions (caller's old session + all sibling sessions) for this account
        for sh, rec in list(self._sessions.items()):
            if rec.get("username_key") == uname_key and rec.get("password_version") != new_version:
                self._sessions.pop(sh, None)
        if caller_sh:
            self._sessions.pop(caller_sh, None)

        self.rate_limiter.clear_username(uname_key)
        new_raw_sid, new_sess = self._create_session(
            bot=cur_rec["bot"],
            user_id=cur_rec["user_id"],
            role=eff_role2,
            auth_track="password",
            user_meta={"username": cur_rec["username"]},
            username=cur_rec["username"],
            username_key=uname_key,
            password_version=new_version,
            must_change_password=False,
        )
        # Immediately close all sibling WS AND caller's old WS (excluding the brand-new session_hash)
        await self._notify_revoke(
            username_key=uname_key,
            exclude_session_hash=new_sess["session_hash"],
        )
        return True, new_raw_sid, new_sess, "", 200, 0

    async def _evict_username_sessions(
        self,
        username_key: str,
        *,
        bot: str | None = None,
        user_id: int | None = None,
    ) -> None:
        for sh, rec in list(self._sessions.items()):
            if rec.get("username_key") == username_key or (
                bot is not None and user_id is not None and rec.get("bot") == bot and rec.get("user_id") == user_id
            ):
                self._sessions.pop(sh, None)
        await self._notify_revoke(username_key=username_key)
        if bot is not None and user_id is not None:
            await self._notify_revoke(session_hash=None, bot=bot, user_id=user_id)

    async def _evict_stale_username_sessions(
        self,
        username_key: str,
        *,
        expected_password_version: int,
        expected_bot: str,
        expected_user_id: int,
        force_session_hash: str | None = None,
    ) -> None:
        """Evict ONLY stale sessions for `username_key` whose version is strictly older or binding mismatches.

        Monotonicity invariant: unless explicitly named by `force_session_hash`, sessions with
        `rec_pv > expected_password_version` are NEVER evicted, and sessions matching
        `(expected_password_version, expected_bot, expected_user_id)` and their WebSockets remain untouched.
        """
        stale_hashes: list[str] = []
        for sh, rec in list(self._sessions.items()):
            if rec.get("username_key") != username_key:
                continue
            if force_session_hash is not None and sh == force_session_hash:
                is_stale = True
            else:
                rec_pv = parse_strict_int(rec.get("password_version"))
                if rec_pv is None or rec_pv < expected_password_version:
                    is_stale = True
                elif rec_pv > expected_password_version:
                    is_stale = False
                else:
                    is_stale = (
                        rec.get("bot") != expected_bot
                        or parse_strict_int(rec.get("user_id")) != expected_user_id
                    )
            if is_stale:
                self._sessions.pop(sh, None)
                stale_hashes.append(sh)
        if force_session_hash and force_session_hash not in stale_hashes:
            self._sessions.pop(force_session_hash, None)
            stale_hashes.append(force_session_hash)
        for sh in stale_hashes:
            await self._notify_revoke(session_hash=sh)

    async def authenticate_session_hash(
        self,
        session_hash: str,
        *,
        allow_password_change_only: bool = False,
    ) -> tuple[bool, dict[str, Any] | None, str, int]:
        """Re-verify an active session hash against expiry, live `users.json` state, and `.env*` RBAC."""
        sess = self._sessions.get(session_hash)
        if not sess:
            return False, None, "会话未登录或已失效", 401
        now = self._now()
        if now > float(sess.get("expires_at", 0.0)):
            self._sessions.pop(session_hash, None)
            # Single-session expiry: revoke ONLY this session_hash (never kill sibling cookies)
            await self._notify_revoke(session_hash=session_hash)
            return False, None, "会话已过期，请重新登录", 401

        track = str(sess.get("auth_track") or "")
        if self.auth_mode == "password":
            if track != "password":
                self._sessions.pop(session_hash, None)
                await self._notify_revoke(session_hash=session_hash)
                return False, None, "当前已切换账号密码登录模式，旧会话已失效", 403

            uname_key = str(sess.get("username_key") or "").strip().lower()
            store_ok, users_map = load_users_file(self.users_file)
            user_rec = users_map.get(uname_key) if (store_ok and uname_key) else None
            if not store_ok or user_rec is None or not user_rec["enabled"]:
                self._sessions.pop(session_hash, None)
                if uname_key:
                    await self._evict_username_sessions(uname_key)
                else:
                    await self._notify_revoke(session_hash=session_hash)
                return False, None, "访问权限已被撤销，会话已立即吊销", 403

            env_role = self.resolve_live_role(user_rec["bot"], user_rec["user_id"])
            eff_role = intersect_roles(user_rec["role"], env_role)
            if eff_role not in ("admin", "readonly"):
                rev_bot = str(user_rec["bot"])
                rev_uid = int(user_rec["user_id"])
                self._sessions.pop(session_hash, None)
                await self._evict_username_sessions(uname_key, bot=rev_bot, user_id=rev_uid)
                return False, None, "访问权限已被撤销，会话已立即吊销", 403

            if (
                user_rec["password_version"] != sess.get("password_version")
                or user_rec["bot"] != sess.get("bot")
                or user_rec["user_id"] != int(sess.get("user_id", 0))
            ):
                await self._evict_stale_username_sessions(
                    uname_key,
                    expected_password_version=int(user_rec["password_version"]),
                    expected_bot=str(user_rec["bot"]),
                    expected_user_id=int(user_rec["user_id"]),
                    force_session_hash=session_hash,
                )
                return False, None, "访问权限已被撤销，会话已立即吊销", 403

            sess["role"] = eff_role
            sess["username"] = user_rec["username"]
            sess["must_change_password"] = bool(user_rec["must_change_password"])
            sess["last_seen"] = now

            if sess["must_change_password"] and not allow_password_change_only:
                return False, None, "password_change_required", 403
            return True, dict(sess), "", 200

        # Legacy mode (`telegram` / `magic_link`)
        if track == "password":
            self._sessions.pop(session_hash, None)
            await self._notify_revoke(session_hash=session_hash)
            return False, None, "当前为 legacy 双轨模式，账号密码会话已失效", 403

        live_role = self.resolve_live_role(sess["bot"], int(sess["user_id"]))
        if live_role not in ("admin", "readonly"):
            rev_bot = str(sess["bot"])
            rev_uid = int(sess["user_id"])
            # Identity-level RBAC revocation: evict ALL sessions and sockets for `(bot, user_id)`
            for sh, rec in list(self._sessions.items()):
                if rec.get("bot") == rev_bot and rec.get("user_id") == rev_uid:
                    self._sessions.pop(sh, None)
            await self._notify_revoke(session_hash=None, bot=rev_bot, user_id=rev_uid)
            return False, None, "访问权限已被撤销，会话已立即吊销", 403

        sess["role"] = live_role
        sess["last_seen"] = now
        return True, dict(sess), "", 200

    async def authenticate_request(
        self,
        request: web.Request,
        *,
        allow_password_change_only: bool = False,
    ) -> tuple[bool, dict[str, Any] | None, str, int]:
        """Authenticate an incoming HTTP/WS request via HttpOnly session cookie + fresh RBAC."""
        raw_sid = request.cookies.get(SESSION_COOKIE_NAME, "").strip()
        if not raw_sid:
            msg = (
                "未登录，请使用账号密码登录"
                if self.auth_mode == "password"
                else "未登录，请通过 Telegram Mini App 或 /webui 一次性链接登录"
            )
            return False, None, msg, 401
        return await self.authenticate_session_hash(
            _sha256_hex(raw_sid),
            allow_password_change_only=allow_password_change_only,
        )

    async def destroy_session(self, session_hash: str) -> None:
        sess = self._sessions.pop(session_hash, None)
        if sess:
            # Single-session logout: revoke ONLY this session_hash (never kill sibling independent sessions)
            await self._notify_revoke(session_hash=session_hash)

    def expected_origins(self, request: web.Request) -> set[str]:
        origins: set[str] = set(self.extra_allowed_origins)
        if self.public_url:
            # Public mode: strictly allow ONLY the configured public_url origin (+ explicit AGY_STUDIO_ALLOWED_ORIGINS).
            # Never expand allowed origins from X-Forwarded-Host, X-Forwarded-Proto, or backend request.scheme.
            op = normalize_origin(self.public_url)
            if op:
                origins.add(op)
            return origins
        # Pure local dev/test mode (public_url empty): allow exact request.scheme://request.host only.
        # Never trust X-Forwarded-Host / X-Forwarded-Proto.
        req_host = (request.host or "").strip()
        if req_host:
            o = normalize_origin(f"{request.scheme}://{req_host}")
            if o:
                origins.add(o)
        return origins

    def check_same_origin(self, request: web.Request, *, require_origin: bool = True) -> tuple[bool, str]:
        raw_origin = request.headers.get("Origin", "").strip()
        if not raw_origin:
            if require_origin:
                return False, "缺少 Origin 请求头，已拒绝潜在跨站请求"
            return True, ""
        norm = normalize_origin(raw_origin)
        if not norm:
            return False, "Origin 请求头格式无效"
        allowed = self.expected_origins(request)
        if norm not in allowed:
            return False, "跨站 Origin 已拦截"
        return True, ""

    def check_csrf(self, request: web.Request, session: dict[str, Any]) -> tuple[bool, str]:
        provided = request.headers.get("X-Studio-CSRF", "").strip()
        expected = str(session.get("csrf_token") or "")
        if not provided or not expected or not hmac.compare_digest(provided, expected):
            return False, "缺少或无效的 X-Studio-CSRF 会话令牌"
        return True, ""

    def is_secure_cookie(self, request: web.Request) -> bool:
        if self.public_url:
            # Public mode is strictly HTTPS-only (validated in __init__); Cookie MUST ALWAYS be Secure.
            return True
        # Explicit local dev mode (public_url empty): depend solely on direct request.secure,
        # NEVER on X-Forwarded-Proto or CF-Visitor headers.
        return bool(request.secure)

    def set_session_cookie(self, response: web.StreamResponse, request: web.Request, raw_sid: str) -> None:
        response.set_cookie(
            SESSION_COOKIE_NAME,
            raw_sid,
            max_age=int(self.session_ttl_sec),
            httponly=True,
            samesite="Lax",
            secure=self.is_secure_cookie(request),
            path="/",
        )

    def clear_session_cookie(self, response: web.StreamResponse, request: web.Request) -> None:
        response.del_cookie(
            SESSION_COOKIE_NAME,
            path="/",
            httponly=True,
            samesite="Lax",
            secure=self.is_secure_cookie(request),
        )


# ----------------------------------------------------------------------------
# Operator User Store CLI (`python3 -m studio.auth ...`)
# Strictly forbids plaintext `--password` argv flags (supports stdin/env/TTY).
# ----------------------------------------------------------------------------


def _resolve_cli_users_file(args: argparse.Namespace) -> Path:
    if getattr(args, "users_file", None):
        return Path(args.users_file).expanduser()
    cfg_dir = (
        Path(args.config_dir).expanduser()
        if getattr(args, "config_dir", None)
        else Path(os.environ.get("AGY_STUDIO_CONFIG_DIR", str(Path.home() / ".config/agy-studio")))
    )
    return cfg_dir / "users.json"


def _read_cli_password(args: argparse.Namespace) -> str:
    if getattr(args, "password_stdin", False):
        raw = sys.stdin.read()
        return raw.rstrip("\r\n")
    env_var = getattr(args, "password_env", None)
    if env_var:
        val = os.environ.get(str(env_var), "")
        if not val:
            raise ValueError(f"Environment variable {env_var!r} is empty or unset")
        return val
    pw1 = getpass.getpass("Password: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        raise ValueError("Passwords do not match")
    return pw1


def _load_existing_for_mutation(users_file: Path) -> dict[str, dict[str, Any]]:
    if not users_file.exists():
        return {}
    ok, users_map = load_users_file(users_file)
    if not ok:
        raise ValueError(f"Existing users file {users_file} is corrupt; refusing to overwrite automatically")
    return users_map


def _cmd_set_user(args: argparse.Namespace) -> int:
    ok_u, display_u, norm_u, err_u = validate_username_input(args.username)
    if not ok_u or not _USERNAME_SAFE_RE.match(display_u):
        sys.stderr.write(f"Invalid username: {err_u or 'must match [A-Za-z0-9][A-Za-z0-9._@-]{0,63}'}\n")
        return 2
    bot = str(args.bot or "").strip()
    if not bot or not _ENV_KEY_RE.match(bot):
        sys.stderr.write("Invalid --bot key\n")
        return 2
    uid = parse_strict_int(args.user_id)
    if uid is None or uid <= 0:
        sys.stderr.write("Invalid --user-id (must be positive integer)\n")
        return 2
    role = str(args.role or "readonly").strip().lower()
    if role not in ("admin", "readonly"):
        sys.stderr.write("Invalid --role (must be 'admin' or 'readonly')\n")
        return 2

    try:
        pw = _read_cli_password(args)
    except Exception as exc:
        sys.stderr.write(f"Failed to read password: {exc}\n")
        return 2

    ok_pw, err_pw = validate_new_password(pw, username=display_u)
    if not ok_pw:
        sys.stderr.write(f"Password policy error: {err_pw}\n")
        return 2

    users_file = _resolve_cli_users_file(args)
    pw_hash = hash_password_scrypt(pw)
    now_ts = int(time.time())

    with _users_file_lock(users_file):
        try:
            users_map = _load_existing_for_mutation(users_file)
        except ValueError as exc:
            sys.stderr.write(f"{exc}\n")
            return 1
        prev = users_map.get(norm_u)
        prev_ver = int(prev["password_version"]) if prev else 0
        created_ts = int(prev["created_at"]) if prev else now_ts
        users_map[norm_u] = {
            "username": display_u,
            "password_hash": pw_hash,
            "role": role,
            "bot": bot,
            "user_id": uid,
            "enabled": not bool(args.disabled),
            "must_change_password": bool(args.must_change_password),
            "password_version": prev_ver + 1,
            "created_at": created_ts,
            "updated_at": now_ts,
        }
        save_users_file_atomic(users_file, users_map)

    action = "Updated" if prev else "Created"
    print(
        f"{action} user '{display_u}' (role={role}, bot={bot}, user_id={uid}, "
        f"enabled={not bool(args.disabled)}, must_change_password={bool(args.must_change_password)}, "
        f"password_version={prev_ver + 1})"
    )
    return 0


def _cmd_list_users(args: argparse.Namespace) -> int:
    users_file = _resolve_cli_users_file(args)
    if not users_file.is_file():
        if args.json:
            print(json.dumps({"ok": True, "users": []}, ensure_ascii=False))
        else:
            print("(no users configured)")
        return 0
    ok, users_map = load_users_file(users_file)
    if not ok:
        sys.stderr.write(f"Users file {users_file} is unreadable or corrupt\n")
        return 1
    safe_rows = [
        {
            "username": rec["username"],
            "role": rec["role"],
            "bot": rec["bot"],
            "user_id": rec["user_id"],
            "enabled": rec["enabled"],
            "must_change_password": rec["must_change_password"],
            "password_version": rec["password_version"],
            "created_at": rec["created_at"],
            "updated_at": rec["updated_at"],
        }
        for _k, rec in sorted(users_map.items())
    ]
    if args.json:
        print(json.dumps({"ok": True, "users": safe_rows}, ensure_ascii=False, indent=2))
        return 0
    if not safe_rows:
        print("(no users configured)")
        return 0
    for row in safe_rows:
        print(
            f"{row['username']}\trole={row['role']}\tbot={row['bot']}\tuid={row['user_id']}\t"
            f"enabled={row['enabled']}\tmust_change={row['must_change_password']}\tver={row['password_version']}"
        )
    return 0


def _cmd_toggle_user(args: argparse.Namespace, *, enabled: bool) -> int:
    ok_u, _disp, norm_u, err_u = validate_username_input(args.username)
    if not ok_u:
        sys.stderr.write(f"Invalid username: {err_u}\n")
        return 2
    users_file = _resolve_cli_users_file(args)
    with _users_file_lock(users_file):
        try:
            users_map = _load_existing_for_mutation(users_file)
        except ValueError as exc:
            sys.stderr.write(f"{exc}\n")
            return 1
        rec = users_map.get(norm_u)
        if rec is None:
            sys.stderr.write(f"User '{args.username}' not found\n")
            return 1
        rec["enabled"] = enabled
        if not enabled:
            rec["password_version"] = int(rec["password_version"]) + 1
        rec["updated_at"] = int(time.time())
        users_map[norm_u] = rec
        save_users_file_atomic(users_file, users_map)
    state = "enabled" if enabled else "disabled"
    print(f"User '{rec['username']}' {state} (password_version={rec['password_version']})")
    return 0


def _cmd_delete_user(args: argparse.Namespace) -> int:
    ok_u, _disp, norm_u, err_u = validate_username_input(args.username)
    if not ok_u:
        sys.stderr.write(f"Invalid username: {err_u}\n")
        return 2
    users_file = _resolve_cli_users_file(args)
    with _users_file_lock(users_file):
        try:
            users_map = _load_existing_for_mutation(users_file)
        except ValueError as exc:
            sys.stderr.write(f"{exc}\n")
            return 1
        rec = users_map.pop(norm_u, None)
        if rec is None:
            sys.stderr.write(f"User '{args.username}' not found\n")
            return 1
        save_users_file_atomic(users_file, users_map)
    print(f"Deleted user '{rec['username']}'")
    return 0


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m studio.auth",
        description="AGY Studio password account store administrator CLI (no plaintext --password flag)",
        allow_abbrev=False,
    )
    common = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    common.add_argument("--config-dir", default=None, help="Override AGY_STUDIO_CONFIG_DIR")
    common.add_argument("--users-file", default=None, help="Explicit path to users.json")

    sub = parser.add_subparsers(dest="command", required=True)

    p_set = sub.add_parser(
        "set-user",
        parents=[common],
        help="Create or update a Studio user",
        allow_abbrev=False,
    )
    p_set.add_argument("--username", required=True, help="Username (case-insensitive index, display preserved)")
    p_set.add_argument("--bot", required=True, help="Bound Telegram bridge bot key (e.g. main, sg)")
    p_set.add_argument("--user-id", required=True, type=int, help="Bound Telegram positive user_id")
    p_set.add_argument("--role", choices=("admin", "readonly"), default="readonly", help="Max role for this user")
    p_set.add_argument("--disabled", action="store_true", help="Create/update user in disabled state")
    mcp_grp = p_set.add_mutually_exclusive_group()
    mcp_grp.add_argument(
        "--must-change-password",
        dest="must_change_password",
        action="store_true",
        default=True,
        help="Require password change on next login (default)",
    )
    mcp_grp.add_argument(
        "--no-must-change-password",
        dest="must_change_password",
        action="store_false",
        help="Do not force password change on next login",
    )
    pw_grp = p_set.add_mutually_exclusive_group()
    pw_grp.add_argument("--password-stdin", action="store_true", help="Read password from stdin")
    pw_grp.add_argument("--password-env", default=None, help="Read password from named environment variable")

    p_list = sub.add_parser(
        "list-users",
        parents=[common],
        help="List configured users (never prints hashes)",
        allow_abbrev=False,
    )
    p_list.add_argument("--json", action="store_true", help="Output JSON")

    p_dis = sub.add_parser(
        "disable-user",
        parents=[common],
        help="Disable a user and bump password_version",
        allow_abbrev=False,
    )
    p_dis.add_argument("--username", required=True)

    p_en = sub.add_parser(
        "enable-user",
        parents=[common],
        help="Enable a disabled user",
        allow_abbrev=False,
    )
    p_en.add_argument("--username", required=True)

    p_del = sub.add_parser(
        "delete-user",
        parents=[common],
        help="Delete a user",
        allow_abbrev=False,
    )
    p_del.add_argument("--username", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(argv)
    if args.command == "set-user":
        return _cmd_set_user(args)
    if args.command == "list-users":
        return _cmd_list_users(args)
    if args.command == "disable-user":
        return _cmd_toggle_user(args, enabled=False)
    if args.command == "enable-user":
        return _cmd_toggle_user(args, enabled=True)
    if args.command == "delete-user":
        return _cmd_delete_user(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
