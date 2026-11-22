#!/usr/bin/env python3
"""Multi-Google-Account OAuth login, isolated profile storage, quota probing, and multi-plan aggregation.

Shared core module for both Telegram Bridge (M1) and AGY Studio (M2).

Security invariants:
- Strict `account_id` whitelist (`^[a-z0-9][a-z0-9_-]{0,47}$`) rejecting traversal & prototype-pollution names.
- Isolated per-account storage under `<accounts_root>/profiles/<sha256(account_id)>/antigravity-acp/antigravity-oauth-token`.
- Directories enforced to `0700`, files enforced to `0600`, anti-symlink (`is_symlink` + `O_NOFOLLOW`) fail-closed.
- Atomic writes via same-directory `O_CREAT|O_EXCL` (`0600`) temp file + `fsync` + `os.replace`.
- Zero plaintext tokens/OAuth secrets in `registry.json`, public dicts, GET responses, or logs.
- Headless OAuth login via `agy acp --gemini-dir <dir> --app-data-dir antigravity-acp --login` with
  `start_new_session=True`, `AGY_CLI_DISABLE_AUTO_UPDATE=1`, `SSH_CONNECTION="127.0.0.1 0 127.0.0.1 0"`,
  stripped GUI/keyring env vars, constant-time `owner_session_id` + `oauth_state` validation,
  TTL expiry + anti-replay, and `os.killpg` teardown.
- Direct HTTPS probing strictly restricted to hardcoded Google official hosts, `HTTPRedirectHandler` blocking all
  3xx redirects fail-closed, `timeout <= 10.0s`, and bounded `<= 512 KiB` reads.
- Credential-fingerprint (`sha256(b"google-account\\x00" + userinfo_id)`) deduplication across multi-plan quota pools.
"""

from __future__ import annotations

from contextlib import contextmanager
import datetime
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Iterator
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Constants & Strict Allowlists
# ---------------------------------------------------------------------------

ACCOUNT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
FORBIDDEN_ACCOUNT_IDS = frozenset({".", "..", "__proto__", "constructor", "prototype"})

OAUTH_CODE_RE = re.compile(r"^[A-Za-z0-9/_.~+=-]{8,512}$")
GOOGLE_AUTH_URL_RE = re.compile(re.escape("https://accounts.google.com/o/oauth2/auth?") + r"[^\s\"'<>]+")

GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
CLOUDCODE_DAILY_BASE = "https://daily-cloudcode-pa.googleapis.com"
CLOUDCODE_PROD_BASE = "https://cloudcode-pa.googleapis.com"

ALLOWED_GOOGLE_PROBE_HOSTS = frozenset({
    "www.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
})

ALLOWED_OAUTH_CALLBACK_HOST = "antigravity.google"
ALLOWED_OAUTH_CALLBACK_PATH = "/oauth-callback"

MAX_PROBE_TIMEOUT_SEC = 10.0
MAX_PROBE_RESPONSE_BYTES = 512 * 1024  # 512 KiB hard bound
DEFAULT_LOGIN_TIMEOUT_SEC = 300.0
MAX_LOGIN_TIMEOUT_SEC = 300.0
DEFAULT_URL_WAIT_TIMEOUT_SEC = 15.0
DEFAULT_SUBMIT_WAIT_TIMEOUT_SEC = 30.0
DEFAULT_REFRESH_SUBPROC_TIMEOUT_SEC = 15.0

SUMMARY_WINDOW_MINS = {
    "5h": 5 * 60,
    "weekly": 7 * 24 * 60,
}

PLAN_TIER_LABELS = {
    "ultra": "Google AI Ultra",
    "pro": "Google AI Pro",
    "enterprise": "Enterprise",
    "free": "Free",
    "unknown": "Unknown",
}

PLAN_TIER_PRIORITY = {
    "ultra": 4,
    "pro": 3,
    "enterprise": 2,
    "free": 1,
    "unknown": 0,
}

_FORBIDDEN_REGISTRY_SECRET_KEYS = frozenset({
    "access_token",
    "refresh_token",
    "id_token",
    "code_verifier",
    "oauth_state",
    "token",
    "client_secret",
    "password",
    "secret",
})

_STRIPPED_SUBPROCESS_ENV_KEYS = (
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
    "BROWSER",
    "OPENAI_BASE_URL",
    "OPENAI_API_KEY",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
)

# Secret redaction regexes
_REDACT_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{4,}")
_REDACT_YA29_RE = re.compile(r"\bya29\.[A-Za-z0-9._~+/-]{4,}")
_REDACT_REFRESH_1_RE = re.compile(r"(?<![A-Za-z0-9_])1//[A-Za-z0-9._~+/-]{4,}")
_REDACT_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")
_REDACT_KV_SECRET_RE = re.compile(
    r"""(?i)(["']?(?:access_token|refresh_token|id_token|code_verifier|oauth_state|client_secret|authorization)["']?\s*[:=]\s*)(["'][^"'\r\n]*["']|[^\s,;}\]]+)"""
)
_EMAIL_IN_TEXT_RE = re.compile(r"(?<![A-Za-z0-9._%*+-])[A-Za-z0-9._%*+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_AT_DOMAIN_RE = re.compile(r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_ABS_HOME_PATH_RE = re.compile(r"(?:/home/[A-Za-z0-9._-]+(?:/[^\s\"'<>]*)?|/Users/[A-Za-z0-9._-]+(?:/[^\s\"'<>]*)?|~/[^\s\"'<>]*)")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class AccountError(ValueError):
    """Base error for Google account storage/validation failures."""


class SymlinkSecurityError(AccountError):
    """Raised fail-closed whenever a symlink is encountered on a managed or host credential path."""


class FlowNotFoundError(KeyError):
    """Raised when an OAuth login flow ID does not exist."""


class FlowConflictError(RuntimeError):
    """Raised when attempting to replay or act on an already submitted/finished/expired flow."""


class GoogleProbeError(RuntimeError):
    """Raised when a direct Google HTTPS probe fails or is blocked fail-closed."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(redact_secrets(str(message)))
        self.status_code = status_code


# ---------------------------------------------------------------------------
# Sanitization, Validation, & Fingerprinting Helpers
# ---------------------------------------------------------------------------

def redact_secrets(text: Any) -> str:
    """Scrub OAuth tokens, Bearer headers, JWTs, refresh tokens, and sensitive KV values."""
    if text is None:
        return ""
    s = str(text)
    s = _REDACT_BEARER_RE.sub("Bearer [REDACTED]", s)
    s = _REDACT_YA29_RE.sub("[REDACTED_TOKEN]", s)
    s = _REDACT_REFRESH_1_RE.sub("[REDACTED_REFRESH]", s)
    s = _REDACT_JWT_RE.sub("[REDACTED_JWT]", s)
    s = _REDACT_KV_SECRET_RE.sub(r"\1[REDACTED]", s)
    return s


def scrub_paths_for_public(text: Any) -> str:
    """Remove local home-directory paths and secrets from user-facing messages."""
    s = redact_secrets(text)
    s = _ABS_HOME_PATH_RE.sub("[path-redacted]", s)
    return s


def scrub_error_for_public(text: Any, *, redact_for_group: bool = False) -> str:
    """Scrub tokens and local paths from error text; also strip emails and domain suffixes for group chats."""
    s = scrub_paths_for_public(text)
    if redact_for_group:
        s = _EMAIL_IN_TEXT_RE.sub("[redacted]", s)
        s = _AT_DOMAIN_RE.sub("", s)
    return s.strip()


def validate_account_id(raw: Any) -> str:
    """Strictly validate `account_id` against `^[a-z0-9][a-z0-9_-]{0,47}$` and forbidden names."""
    if not isinstance(raw, str):
        raise ValueError("account_id must be a string")
    if "\x00" in raw or "/" in raw or "\\" in raw:
        raise ValueError("account_id contains forbidden path characters")
    if raw in FORBIDDEN_ACCOUNT_IDS:
        raise ValueError(f"account_id '{raw}' is reserved/forbidden")
    if not ACCOUNT_ID_RE.fullmatch(raw):
        raise ValueError("account_id must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    return raw


def sanitize_alias(raw: Any, fallback: str) -> str:
    """Clean a display alias into a safe single-line string (<= 64 chars)."""
    s = re.sub(r"[\x00-\x1f\x7f\r\n]+", " ", str(raw or "")).strip()
    if not s:
        return fallback
    return s[:64]


def compute_credential_fingerprint(userinfo_id: str) -> str:
    """Compute canonical T3-compatible SHA-256 fingerprint for a Google account ID."""
    uid = str(userinfo_id or "").strip()
    if not uid:
        raise ValueError("userinfo_id must be non-empty")
    return hashlib.sha256(b"google-account\x00" + uid.encode("utf-8")).hexdigest()


def mask_email(email: Any) -> str:
    """Mask an email for admin DM / Studio display (e.g. `a***e@example.com`)."""
    raw = str(email or "").strip()
    if not raw or "@" not in raw:
        return ""
    local, domain = raw.rsplit("@", 1)
    local = local.strip()
    domain = domain.strip()
    if not local or not domain:
        return ""
    if len(local) <= 1:
        masked_local = "***"
    elif len(local) == 2:
        masked_local = f"{local[0]}***"
    else:
        masked_local = f"{local[0]}***{local[-1]}"
    return f"{masked_local}@{domain}"


def _scrub_group_label(text: Any, fallback: str = "") -> str:
    """Ensure no email address or email-domain suffix survives in a group-chat label."""
    s = str(text or "").strip()
    s = _EMAIL_IN_TEXT_RE.sub("[redacted]", s)
    s = _AT_DOMAIN_RE.sub("", s)
    s = _ABS_HOME_PATH_RE.sub("", s).strip()
    return s or fallback


def classify_plan_tier(paid_tier: Any = None, current_tier: Any = None) -> tuple[str, str]:
    """Classify Google Antigravity tier metadata into canonical `(plan_tier, plan_label)`."""
    def _extract_tokens(val: Any) -> list[str]:
        toks: list[str] = []
        if isinstance(val, dict):
            for k in ("id", "name", "tierId", "displayName", "slug"):
                v = val.get(k)
                if isinstance(v, str) and v.strip():
                    toks.append(v.strip().lower())
        elif isinstance(val, str) and val.strip():
            toks.append(val.strip().lower())
        return toks

    paid_toks = _extract_tokens(paid_tier)
    cur_toks = _extract_tokens(current_tier)

    for group in (paid_toks, cur_toks):
        joined = " ".join(group)
        if not joined:
            continue
        if "ultra" in joined:
            return "ultra", PLAN_TIER_LABELS["ultra"]
        if "pro" in joined:
            return "pro", PLAN_TIER_LABELS["pro"]
        if any(k in joined for k in ("enterprise", "business", "standard-tier", "workspace", "gcp")):
            return "enterprise", PLAN_TIER_LABELS["enterprise"]
        if "free" in joined:
            return "free", PLAN_TIER_LABELS["free"]
    return "unknown", PLAN_TIER_LABELS["unknown"]


def antigravity_user_agent() -> str:
    """Return T3-aligned Antigravity client User-Agent string."""
    plat = sys.platform
    if plat.startswith("linux"):
        os_type = "linux"
    elif plat == "darwin":
        os_type = "darwin"
    elif plat.startswith("win"):
        os_type = "win32"
    else:
        os_type = plat
    mach = (platform.machine() or "x64").lower()
    if mach in ("x86_64", "amd64"):
        arch = "x64"
    elif mach in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        arch = mach
    cl_ver = f"{963137}{146}"
    return f"antigravity/hub/2.24.0 (aidev_client; os_type={os_type}; arch={arch}; cl={cl_ver})"


def _parse_iso_utc(ts_str: Any) -> datetime.datetime | None:
    if not ts_str or not isinstance(ts_str, str):
        return None
    s = ts_str.strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)
    except Exception:
        return None


def _iso_utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_quota_summary(quota: dict[str, Any] | None) -> dict[str, Any]:
    """Build compact, group-safe quota summary (percentages and reset_at only)."""
    if not isinstance(quota, dict):
        return {
            "has_quota": False,
            "fetched_at_iso": "",
            "gemini_5h_pct": None,
            "gemini_5h_reset_at": None,
            "gemini_weekly_pct": None,
            "gemini_weekly_reset_at": None,
            "claude_gpt_5h_pct": None,
            "claude_gpt_5h_reset_at": None,
            "claude_gpt_weekly_pct": None,
            "claude_gpt_weekly_reset_at": None,
            "groups": [],
        }

    out: dict[str, Any] = {
        "has_quota": False,
        "fetched_at_iso": str(quota.get("fetched_at_iso") or ""),
        "gemini_5h_pct": None,
        "gemini_5h_reset_at": None,
        "gemini_weekly_pct": None,
        "gemini_weekly_reset_at": None,
        "claude_gpt_5h_pct": None,
        "claude_gpt_5h_reset_at": None,
        "claude_gpt_weekly_pct": None,
        "claude_gpt_weekly_reset_at": None,
        "groups": [],
    }
    raw_groups = quota.get("groups")
    if isinstance(raw_groups, list):
        safe_groups: list[dict[str, Any]] = []
        for grp in raw_groups:
            if not isinstance(grp, dict):
                continue
            gname = str(grp.get("name") or "").strip()
            gl = gname.lower()
            safe_buckets: list[dict[str, Any]] = []
            for b in (grp.get("buckets") or []):
                if not isinstance(b, dict):
                    continue
                try:
                    rem_frac = float(b.get("remaining_fraction", 0.0))
                except (TypeError, ValueError):
                    continue
                if not math.isfinite(rem_frac):
                    continue
                rem_frac = max(0.0, min(1.0, rem_frac))
                rem_pct = round(rem_frac * 100.0, 1)
                win = str(b.get("window") or "").strip().lower()
                bname = str(b.get("name") or "").strip()
                reset_time = str(b.get("reset_time") or "").strip() or None
                safe_buckets.append({
                    "id": str(b.get("id") or ""),
                    "name": bname,
                    "window": win,
                    "remaining_fraction": rem_frac,
                    "remaining_pct": rem_pct,
                    "reset_time": reset_time,
                })
                out["has_quota"] = True
                if "gemini" in gl:
                    if win == "5h" or "hour" in bname.lower():
                        if out["gemini_5h_pct"] is None or rem_pct < out["gemini_5h_pct"]:
                            out["gemini_5h_pct"] = rem_pct
                            out["gemini_5h_reset_at"] = reset_time
                    elif win == "weekly" or "weekly" in bname.lower():
                        if out["gemini_weekly_pct"] is None or rem_pct < out["gemini_weekly_pct"]:
                            out["gemini_weekly_pct"] = rem_pct
                            out["gemini_weekly_reset_at"] = reset_time
                    elif out["gemini_weekly_pct"] is None:
                        out["gemini_weekly_pct"] = rem_pct
                        out["gemini_weekly_reset_at"] = reset_time
                elif "claude" in gl or "gpt" in gl:
                    if win == "5h" or "hour" in bname.lower():
                        if out["claude_gpt_5h_pct"] is None or rem_pct < out["claude_gpt_5h_pct"]:
                            out["claude_gpt_5h_pct"] = rem_pct
                            out["claude_gpt_5h_reset_at"] = reset_time
                    elif win == "weekly" or "weekly" in bname.lower():
                        if out["claude_gpt_weekly_pct"] is None or rem_pct < out["claude_gpt_weekly_pct"]:
                            out["claude_gpt_weekly_pct"] = rem_pct
                            out["claude_gpt_weekly_reset_at"] = reset_time
                    elif out["claude_gpt_weekly_pct"] is None:
                        out["claude_gpt_weekly_pct"] = rem_pct
                        out["claude_gpt_weekly_reset_at"] = reset_time
            if safe_buckets:
                safe_groups.append({"name": gname, "buckets": safe_buckets})
        out["groups"] = safe_groups
    return out


def sanitize_account_for_group(acct: dict[str, Any]) -> dict[str, Any]:
    """Return a strictly redacted account view for Telegram group chats.

    Omits raw email, masked email, any email-domain suffix, `profile_dir`, and all local paths.
    Retains only `account_id`, scrubbed `alias`, `plan_tier`, `plan_label`, `is_active`,
    duplicate metadata, `status`, and quota percentages/reset times.
    """
    account_id = str(acct.get("account_id") or "")
    alias = _scrub_group_label(acct.get("alias") or account_id, fallback=account_id)
    plan_tier = str(acct.get("plan_tier") or "unknown")
    plan_label = str(acct.get("plan_label") or PLAN_TIER_LABELS.get(plan_tier, "Unknown"))
    quota_summary = acct.get("quota_summary")
    if not isinstance(quota_summary, dict):
        quota_summary = _extract_quota_summary(acct.get("quota"))
    return {
        "account_id": account_id,
        "alias": alias,
        "plan_tier": plan_tier,
        "plan_label": plan_label,
        "is_active": bool(acct.get("is_active", False)),
        "is_duplicate": bool(acct.get("is_duplicate", False)),
        "duplicate_of": acct.get("duplicate_of") or None,
        "status": str(acct.get("status") or "unknown"),
        "quota_summary": quota_summary,
    }


def to_public_dict(
    acct: dict[str, Any],
    *,
    active_account_id: str | None = None,
    is_duplicate: bool = False,
    duplicate_of: str | None = None,
    for_group: bool = False,
) -> dict[str, Any]:
    """Serialize an account record into a public-safe dictionary (never exposing tokens or paths)."""
    account_id = str(acct.get("account_id") or "")
    plan_tier = str(acct.get("plan_tier") or "unknown")
    plan_label = str(acct.get("plan_label") or PLAN_TIER_LABELS.get(plan_tier, "Unknown"))
    is_active = bool(acct.get("is_active", False)) if active_account_id is None else (account_id == active_account_id)
    quota_summary = _extract_quota_summary(acct.get("quota"))
    base: dict[str, Any] = {
        "account_id": account_id,
        "alias": sanitize_alias(acct.get("alias"), account_id),
        "plan_tier": plan_tier,
        "plan_label": plan_label,
        "is_active": is_active,
        "is_duplicate": bool(is_duplicate or acct.get("is_duplicate", False)),
        "duplicate_of": duplicate_of if duplicate_of is not None else (acct.get("duplicate_of") or None),
        "status": str(acct.get("status") or "pending_login"),
        "quota_summary": quota_summary,
    }
    if for_group:
        return sanitize_account_for_group(base)

    base.update({
        "email_masked": mask_email(acct.get("email") or ""),
        "auth_method": str(acct.get("auth_method") or "oauth-personal"),
        "is_host_adopted": bool(acct.get("is_host_adopted", False)),
        "credential_fingerprint": str(acct.get("credential_fingerprint") or ""),
        "paid_tier_id": str(acct.get("paid_tier_id") or ""),
        "current_tier_id": str(acct.get("current_tier_id") or ""),
        "last_checked_at": str(acct.get("last_checked_at") or ""),
        "last_error": scrub_paths_for_public(acct.get("last_error") or ""),
        "created_at": str(acct.get("created_at") or ""),
        "updated_at": str(acct.get("updated_at") or ""),
    })
    return base


# ---------------------------------------------------------------------------
# Filesystem Security Primitives (Anti-Symlink + 0700/0600 + Atomic Writes)
# ---------------------------------------------------------------------------

def _assert_no_symlink_chain(path: Path, stop_at: Path | None = None) -> None:
    """Fail-closed if `path` or any managed parent up to `stop_at` is a symlink."""
    cur = path
    stop_norm = os.path.abspath(str(stop_at)) if stop_at is not None else None
    visited = 0
    while visited < 64:
        visited += 1
        if cur.is_symlink():
            raise SymlinkSecurityError("Refusing to traverse or touch symlinked credential path")
        if stop_norm is not None and os.path.abspath(str(cur)) == stop_norm:
            break
        parent = cur.parent
        if parent == cur:
            break
        if stop_norm is None:
            # Check immediate path + its direct parent only when no root boundary is specified
            if parent.is_symlink():
                raise SymlinkSecurityError("Refusing to traverse symlinked parent directory")
            break
        cur = parent


def _ensure_secure_dir(dir_path: Path, *, boundary: Path | None = None, enforce_mode: bool = True) -> None:
    """Create directory chain securely (0700) without traversing symlinks."""
    if boundary is not None:
        if boundary.is_symlink():
            raise SymlinkSecurityError("Managed root directory must not be a symlink")
        if not boundary.exists():
            boundary.mkdir(parents=True, exist_ok=True)
        if enforce_mode:
            os.chmod(boundary, 0o700)
        rel = os.path.relpath(os.path.abspath(str(dir_path)), os.path.abspath(str(boundary)))
        if rel == ".." or rel.startswith(".." + os.sep):
            raise AccountError("Managed path escapes root directory")
        cur = boundary
        if rel != ".":
            for part in Path(rel).parts:
                cur = cur / part
                if cur.is_symlink():
                    raise SymlinkSecurityError("Refusing to traverse symlinked directory")
                if not cur.exists():
                    cur.mkdir(mode=0o700)
                if enforce_mode:
                    os.chmod(cur, 0o700)
    else:
        _assert_no_symlink_chain(dir_path)
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
        if enforce_mode:
            os.chmod(dir_path, 0o700)


def _read_bytes_nofollow(path: Path, *, boundary: Path | None = None, max_bytes: int = 2 * 1024 * 1024) -> bytes:
    """Read file bytes strictly with `O_NOFOLLOW` and anti-symlink parent validation."""
    _assert_no_symlink_chain(path, stop_at=boundary)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        if getattr(exc, "errno", None) == 40:  # ELOOP on symlink
            raise SymlinkSecurityError("Refusing to read symlinked file") from exc
        raise
    try:
        st = os.fstat(fd)
        if not os.path.isfile(str(path)) or (st.st_mode & 0o170000) != 0o100000:
            raise AccountError("Credential path must be a regular file")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            data = fh.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise AccountError("Credential file exceeds maximum allowed size")
        return data
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _write_bytes_atomic_0600(
    target_path: Path,
    payload: bytes,
    *,
    boundary: Path | None = None,
    enforce_parent_0700: bool = True,
) -> None:
    """Atomically write bytes with `O_CREAT|O_EXCL|O_NOFOLLOW` `0600` temp file + `fsync` + `os.replace`."""
    _ensure_secure_dir(target_path.parent, boundary=boundary, enforce_mode=enforce_parent_0700)
    _assert_no_symlink_chain(target_path, stop_at=boundary)
    if target_path.is_symlink():
        raise SymlinkSecurityError("Refusing to overwrite symlinked file")

    tmp_path = target_path.parent / f".{target_path.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_path), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fd = -1
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        if target_path.is_symlink():
            raise SymlinkSecurityError("Target became a symlink before atomic replace")
        os.replace(tmp_path, target_path)
        os.chmod(target_path, 0o600)
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _assert_no_secret_keys_recursive(obj: Any, *, depth: int = 0) -> None:
    if depth > 16:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).strip().lower()
            if kl in _FORBIDDEN_REGISTRY_SECRET_KEYS:
                raise AccountError(f"Refusing to persist forbidden secret key in registry: {kl}")
            _assert_no_secret_keys_recursive(v, depth=depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _assert_no_secret_keys_recursive(item, depth=depth + 1)


def parse_oauth_token_bytes(raw: bytes) -> dict[str, Any]:
    """Parse and validate an `antigravity-oauth-token` JSON blob."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise AccountError("Invalid OAuth token JSON") from exc
    if not isinstance(doc, dict):
        raise AccountError("OAuth token file must be a JSON object")
    tok = doc.get("token")
    if not isinstance(tok, dict):
        raise AccountError("OAuth token file missing 'token' object")
    access_token = tok.get("access_token")
    if not isinstance(access_token, str) or not access_token.strip():
        raise AccountError("OAuth token file missing non-empty access_token")
    return doc


def is_token_expiring(token_doc: dict[str, Any], *, skew_sec: float = 60.0) -> bool:
    """Return True if the CLI token has an `expiry` timestamp within `skew_sec` of now."""
    tok = token_doc.get("token") if isinstance(token_doc, dict) else None
    if not isinstance(tok, dict):
        return True
    expiry = tok.get("expiry")
    if not expiry:
        return False
    exp_dt = _parse_iso_utc(expiry)
    if exp_dt is None:
        return False
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    return exp_dt.timestamp() <= (now_utc.timestamp() + skew_sec)


# ---------------------------------------------------------------------------
# Subprocess Helpers (Headless ACP Env & Process-Group Teardown)
# ---------------------------------------------------------------------------

def build_isolated_acp_env(base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Build headless environment for `agy acp` bypassing OS keyring and auto-updater."""
    env = dict(os.environ if base_env is None else base_env)
    for k in _STRIPPED_SUBPROCESS_ENV_KEYS:
        env.pop(k, None)
    env["SSH_CONNECTION"] = "127.0.0.1 0 127.0.0.1 0"
    env["AGY_CLI_DISABLE_AUTO_UPDATE"] = "1"
    env["AGY_INTERNAL_OBSERVER"] = "1"
    return env


def _close_proc_pipes(proc: Any) -> None:
    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(proc, stream_name, None)
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass


def terminate_process_group(proc: Any, *, grace_sec: float = 1.0) -> None:
    """Cleanly terminate a subprocess's entire process group (`SIGTERM` -> `SIGKILL`) and reap it."""
    if proc is None:
        return
    try:
        if proc.poll() is not None:
            try:
                proc.wait(timeout=0.5)
            except Exception:
                pass
            _close_proc_pipes(proc)
            return
    except Exception:
        pass

    pid = getattr(proc, "pid", None)
    pgid = None
    if isinstance(pid, int) and pid > 0:
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = pid

    if pgid is not None and pgid > 0:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            try:
                proc.terminate()
            except Exception:
                pass
    else:
        try:
            proc.terminate()
        except Exception:
            pass

    try:
        proc.wait(timeout=max(0.05, float(grace_sec)))
        _close_proc_pipes(proc)
        return
    except Exception:
        pass

    if pgid is not None and pgid > 0:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            try:
                proc.kill()
            except Exception:
                pass
    else:
        try:
            proc.kill()
        except Exception:
            pass

    try:
        proc.wait(timeout=2.0)
    except Exception:
        pass
    _close_proc_pipes(proc)


# ---------------------------------------------------------------------------
# Direct Google HTTPS Client (No Redirects, Hard Host Whitelist, <=10s, <=512KiB)
# ---------------------------------------------------------------------------

def assert_allowed_google_url(url: str) -> str:
    """Strictly verify URL uses HTTPS against the hardcoded Google official host whitelist."""
    if not isinstance(url, str) or not url.strip():
        raise GoogleProbeError("Empty probe URL rejected")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in url):
        raise GoogleProbeError("Control characters in probe URL rejected")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise GoogleProbeError("Only HTTPS Google probe URLs are allowed")
    if parsed.username or parsed.password:
        raise GoogleProbeError("Embedded credentials in URL are forbidden")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_GOOGLE_PROBE_HOSTS:
        raise GoogleProbeError(f"Host not in hardcoded Google allowlist: {host}")
    if parsed.port is not None:
        raise GoogleProbeError("Custom ports are forbidden on Google probe URLs")
    return url


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Fail-closed redirect handler rejecting all HTTP 3xx responses."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        if fp is not None:
            try:
                fp.close()
            except Exception:
                pass
        raise GoogleProbeError(
            f"HTTP {code} redirect blocked (fail-closed)",
            status_code=int(code) if isinstance(code, int) else 302,
        )


def google_https_json_request(
    method: str,
    url: str,
    *,
    access_token: str,
    json_body: dict[str, Any] | None = None,
    timeout_sec: float = MAX_PROBE_TIMEOUT_SEC,
    max_bytes: int = MAX_PROBE_RESPONSE_BYTES,
    opener: urllib.request.OpenerDirector | None = None,
) -> dict[str, Any]:
    """Perform a direct, no-redirect, bounded-size HTTPS JSON request to an official Google endpoint."""
    safe_url = assert_allowed_google_url(url)
    eff_timeout = min(max(0.1, float(timeout_sec)), MAX_PROBE_TIMEOUT_SEC)
    eff_max_bytes = min(max(1024, int(max_bytes)), MAX_PROBE_RESPONSE_BYTES)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "User-Agent": antigravity_user_agent(),
    }
    data_bytes: bytes | None = None
    if json_body is not None:
        data_bytes = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(safe_url, data=data_bytes, headers=headers, method=method.upper())
    eff_opener = opener if opener is not None else urllib.request.build_opener(_NoRedirectHandler())
    try:
        with eff_opener.open(req, timeout=eff_timeout) as resp:
            status = int(getattr(resp, "status", 200) or 200)
            if 300 <= status < 400:
                raise GoogleProbeError(f"HTTP {status} redirect blocked (fail-closed)", status_code=status)
            raw = resp.read(eff_max_bytes + 1)
            if len(raw) > eff_max_bytes:
                raise GoogleProbeError(
                    f"Google API response exceeded {eff_max_bytes} byte limit",
                    status_code=status,
                )
    except GoogleProbeError:
        raise
    except urllib.error.HTTPError as exc:
        code = int(getattr(exc, "code", 0) or 0)
        fp_err = getattr(exc, "fp", None)
        try:
            if 300 <= code < 400:
                raise GoogleProbeError(f"HTTP {code} redirect blocked (fail-closed)", status_code=code) from exc
            snippet = ""
            try:
                body_err = exc.read(512)
                if body_err:
                    snippet = redact_secrets(body_err.decode("utf-8", errors="replace"))[:160]
            except Exception:
                pass
            detail = f"HTTP {code}" + (f": {snippet}" if snippet else "")
            raise GoogleProbeError(detail, status_code=code) from exc
        finally:
            try:
                exc.close()
            except Exception:
                pass
            if fp_err is not None and not getattr(fp_err, "closed", False):
                try:
                    fp_err.close()
                except Exception:
                    pass
    except Exception as exc:
        raise GoogleProbeError(f"Probe transport error ({type(exc).__name__}): {redact_secrets(exc)}") from exc

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise GoogleProbeError("Invalid JSON response from Google API") from exc
    if not isinstance(parsed, dict):
        raise GoogleProbeError("Unexpected non-object JSON response from Google API")
    return parsed


# ---------------------------------------------------------------------------
# Quota Parsing (T3 Code `antigravityUsageLimits.ts` Parity + Bridge Format)
# ---------------------------------------------------------------------------

def _summary_reset_time(bucket: dict[str, Any], window_duration_mins: int | None, requested_at_ms: float) -> str | None:
    """Suppress rolling full-window reset times on untouched buckets (T3 Code parity)."""
    rem = bucket.get("remainingFraction")
    desc = bucket.get("description")
    reset_time = bucket.get("resetTime")
    if not isinstance(reset_time, str) or not reset_time.strip():
        return None
    if rem == 1 and desc is None and window_duration_mins is not None:
        dt = _parse_iso_utc(reset_time)
        if dt is not None:
            reset_ms = dt.timestamp() * 1000.0
            if abs(reset_ms - requested_at_ms - (window_duration_mins * 60_000.0)) <= 60_000.0:
                return None
    return reset_time.strip()


def parse_quota_summary_response(response: dict[str, Any], *, requested_at_ms: float | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse `v1internal:retrieveUserQuotaSummary` into `(groups, windows)`."""
    req_ms = time.time() * 1000.0 if requested_at_ms is None else float(requested_at_ms)
    raw_groups = response.get("groups")
    if isinstance(raw_groups, list) and any(isinstance(g, dict) and g.get("buckets") for g in raw_groups):
        iter_groups = raw_groups
    else:
        iter_groups = [{"displayName": "", "buckets": response.get("buckets") or []}]

    windows_by_id: dict[str, dict[str, Any]] = {}
    groups_map: dict[str, dict[str, Any]] = {}

    for grp in iter_groups:
        if not isinstance(grp, dict):
            continue
        g_display = str(grp.get("displayName") or "").strip()
        for bucket in (grp.get("buckets") or []):
            if not isinstance(bucket, dict) or bucket.get("disabled"):
                continue
            bid = str(bucket.get("bucketId") or "").strip()
            if not bid:
                continue
            raw_rem = bucket.get("remainingFraction")
            if raw_rem is None:
                continue
            try:
                rem_frac = float(raw_rem)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(rem_frac):
                continue
            rem_frac = max(0.0, min(1.0, rem_frac))

            if bid.startswith("gemini-argon-"):
                family = g_display or "Gemini Argon"
                group_key = "Gemini Models"
            elif bid.startswith("gemini-carbon-"):
                family = g_display or "Gemini Carbon"
                group_key = "Gemini Models"
            elif bid.startswith("gemini-"):
                family = "Gemini"
                group_key = "Gemini Models"
            elif bid.startswith("3p-"):
                family = "Claude & GPT (shared)"
                group_key = "Claude and GPT models"
            else:
                family = g_display or bid
                group_key = g_display or ("Claude and GPT models" if ("claude" in family.lower() or "gpt" in family.lower()) else "Gemini Models")

            win_raw = str(bucket.get("window") or "").strip().lower()
            is_weekly = win_raw == "weekly"
            is_5h = win_raw == "5h"
            win_mins = SUMMARY_WINDOW_MINS.get(win_raw)
            reset_iso = _summary_reset_time(bucket, win_mins, req_ms)
            b_disp = str(bucket.get("displayName") or "").strip()
            label = f"{family} · {'Weekly' if is_weekly else '5-hour' if is_5h else (b_disp or 'Quota')}"
            win_entry: dict[str, Any] = {
                "id": bid,
                "label": label,
                "kind": "weekly" if is_weekly else ("session" if is_5h else "other"),
                "used_percent": round((1.0 - rem_frac) * 100.0, 2),
                "remaining_fraction": rem_frac,
            }
            if reset_iso:
                win_entry["resets_at"] = reset_iso
            if win_mins is not None:
                win_entry["window_duration_mins"] = win_mins
            windows_by_id[bid] = win_entry

            g_obj = groups_map.setdefault(group_key, {"name": group_key, "description": "", "buckets": []})
            g_obj["buckets"].append({
                "id": bid,
                "name": b_disp or ("Weekly" if is_weekly else ("5-hour" if is_5h else bid)),
                "window": win_raw or ("weekly" if is_weekly else ("5h" if is_5h else "other")),
                "remaining_fraction": rem_frac,
                "reset_time": reset_iso or "",
            })

    return list(groups_map.values()), list(windows_by_id.values())


def parse_available_models_fallback(response: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Parse `v1internal:fetchAvailableModels` fallback quota payload into `(groups, windows)`."""
    models = response.get("models")
    if not isinstance(models, dict):
        return [], []
    windows_by_id: dict[str, dict[str, Any]] = {}
    for model_id, model_obj in models.items():
        if not isinstance(model_obj, dict):
            continue
        mid = str(model_id or "").lower()
        provider = str(model_obj.get("modelProvider") or "")
        if provider == "MODEL_PROVIDER_GOOGLE" or mid.startswith("gemini-"):
            family = "Gemini"
        elif provider == "MODEL_PROVIDER_ANTHROPIC" or mid.startswith("claude-"):
            family = "Claude"
        elif provider == "MODEL_PROVIDER_OPENAI" or mid.startswith("gpt-"):
            family = "GPT"
        else:
            continue
        for suffix, q_key in (("quota", "quotaInfo"), ("weekly", "weeklyQuotaInfo")):
            q_obj = model_obj.get(q_key)
            if not isinstance(q_obj, dict):
                continue
            raw_rem = q_obj.get("remainingFraction")
            if raw_rem is None:
                continue
            try:
                rem_frac = float(raw_rem)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(rem_frac):
                continue
            rem_frac = max(0.0, min(1.0, rem_frac))
            wid = f"{family.lower()}-{suffix}"
            used_pct = round((1.0 - rem_frac) * 100.0, 2)
            prev = windows_by_id.get(wid)
            if prev is None or used_pct > prev["used_percent"]:
                entry: dict[str, Any] = {
                    "id": wid,
                    "label": f"{family} · {'Weekly' if suffix == 'weekly' else 'Reported quota'}",
                    "kind": "weekly" if suffix == "weekly" else "other",
                    "used_percent": used_pct,
                    "remaining_fraction": rem_frac,
                    "family": family,
                }
                rst = str(q_obj.get("resetTime") or "").strip()
                if rst:
                    entry["resets_at"] = rst
                if suffix == "weekly":
                    entry["window_duration_mins"] = 7 * 24 * 60
                windows_by_id[wid] = entry

    groups_map: dict[str, dict[str, Any]] = {}
    for w in windows_by_id.values():
        fam = w.get("family") or ""
        g_key = "Gemini Models" if fam == "Gemini" else "Claude and GPT models"
        g_obj = groups_map.setdefault(g_key, {"name": g_key, "description": "", "buckets": []})
        g_obj["buckets"].append({
            "id": w["id"],
            "name": w["label"],
            "window": "weekly" if w["kind"] == "weekly" else "5h",
            "remaining_fraction": w["remaining_fraction"],
            "reset_time": w.get("resets_at") or "",
        })
    clean_windows = [{k: v for k, v in w.items() if k != "family"} for w in windows_by_id.values()]
    return list(groups_map.values()), clean_windows


# ---------------------------------------------------------------------------
# Core Account Manager (`GoogleAccountManager`)
# ---------------------------------------------------------------------------

class GoogleAccountManager:
    """Manages isolated Google OAuth profiles, host token switching, probing, and plan aggregation."""

    def __init__(
        self,
        *,
        root_dir: str | Path | None = None,
        host_token_path: str | Path | None = None,
        quota_cache_file: str | Path | None = None,
        cost_config_file: str | Path | None = None,
        agy_bin: str | None = None,
        http_request_fn: Callable[..., dict[str, Any]] | None = None,
        popen_fn: Callable[..., Any] | None = None,
        auto_adopt_host: bool = True,
    ) -> None:
        home = Path.home()
        env_root = os.environ.get("AGY_GOOGLE_ACCOUNTS_DIR", "").strip()
        env_host = os.environ.get("AGY_HOST_OAUTH_TOKEN_FILE", "").strip()
        self.root_dir = Path(root_dir) if root_dir is not None else Path(
            env_root or (home / ".gemini" / "antigravity-cli" / "accounts")
        )
        self.profiles_dir = self.root_dir / "profiles"
        self.registry_path = self.root_dir / "registry.json"
        self.lock_path = self.root_dir / ".lock"
        self.host_token_path = Path(host_token_path) if host_token_path is not None else Path(
            env_host or (home / ".gemini" / "antigravity-cli" / "antigravity-oauth-token")
        )
        self.quota_cache_file = Path(quota_cache_file) if quota_cache_file is not None else None
        self.cost_config_file = Path(cost_config_file) if cost_config_file is not None else None
        self.agy_bin = agy_bin or os.environ.get("AGY_TG_AGY_BIN") or str(home / ".local" / "bin" / "agy")
        self._http_request_fn = http_request_fn or google_https_json_request
        self._popen_fn = popen_fn or subprocess.Popen
        self._thread_lock = threading.RLock()
        self._auto_adopt_host = bool(auto_adopt_host)

        if self._auto_adopt_host:
            self._ensure_initialized_with_host_adoption()

    # -- Path Helpers -------------------------------------------------------

    def profile_dir_for(self, account_id: str) -> Path:
        aid = validate_account_id(account_id)
        digest = hashlib.sha256(aid.encode("utf-8")).hexdigest()
        pdir = self.profiles_dir / digest
        rel = os.path.relpath(os.path.abspath(str(pdir)), os.path.abspath(str(self.profiles_dir)))
        if rel == ".." or rel.startswith(".." + os.sep):
            raise AccountError("Profile directory escaped managed profiles root")
        return pdir

    def token_path_for(self, account_id: str) -> Path:
        return self.profile_dir_for(account_id) / "antigravity-acp" / "antigravity-oauth-token"

    # -- Cross-Process Locking & Registry I/O -------------------------------

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        with self._thread_lock:
            _ensure_secure_dir(self.root_dir, boundary=self.root_dir, enforce_mode=True)
            _ensure_secure_dir(self.profiles_dir, boundary=self.root_dir, enforce_mode=True)
            _assert_no_symlink_chain(self.lock_path, stop_at=self.root_dir)
            flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(self.lock_path), flags, 0o600)
            try:
                os.chmod(self.lock_path, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _default_registry(self) -> dict[str, Any]:
        return {
            "version": 1,
            "active_account_id": None,
            "updated_at": _iso_utc_now(),
            "accounts": {},
        }

    def _load_registry_locked(self) -> dict[str, Any]:
        if not self.registry_path.exists() and not self.registry_path.is_symlink():
            return self._default_registry()
        raw = _read_bytes_nofollow(self.registry_path, boundary=self.root_dir)
        try:
            doc = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise AccountError("Corrupt accounts registry.json") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("accounts"), dict):
            raise AccountError("Malformed accounts registry.json")
        return doc

    def _save_registry_locked(self, reg: dict[str, Any]) -> None:
        reg["version"] = 1
        reg["updated_at"] = _iso_utc_now()
        _assert_no_secret_keys_recursive(reg)
        payload = (json.dumps(reg, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        _write_bytes_atomic_0600(
            self.registry_path,
            payload,
            boundary=self.root_dir,
            enforce_parent_0700=True,
        )

    def _ensure_initialized_with_host_adoption(self) -> None:
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            if reg.get("accounts"):
                return
            # First-time adoption if host_token_path exists, is NOT a symlink, and is valid token JSON
            if self.host_token_path.is_symlink() or not self.host_token_path.exists():
                return
            try:
                raw_host = _read_bytes_nofollow(self.host_token_path)
                tok_doc = parse_oauth_token_bytes(raw_host)
            except Exception:
                return
            primary_id = "primary"
            tpath = self.token_path_for(primary_id)
            _write_bytes_atomic_0600(tpath, raw_host, boundary=self.root_dir, enforce_parent_0700=True)
            now_iso = _iso_utc_now()
            reg["accounts"][primary_id] = {
                "account_id": primary_id,
                "alias": "Primary",
                "is_host_adopted": True,
                "auth_method": str(tok_doc.get("auth_method") or "oauth-personal"),
                "email": str(tok_doc.get("id_token_email") or "").strip(),
                "google_user_id": "",
                "credential_fingerprint": "",
                "plan_tier": "unknown",
                "plan_label": PLAN_TIER_LABELS["unknown"],
                "paid_tier_id": "",
                "current_tier_id": "",
                "quota": None,
                "status": "ready",
                "last_error": "",
                "last_checked_at": "",
                "created_at": now_iso,
                "updated_at": now_iso,
            }
            reg["active_account_id"] = primary_id
            self._save_registry_locked(reg)

    # -- Duplicate Detection & Public Listing -------------------------------

    def _compute_duplicates(self, reg: dict[str, Any]) -> dict[str, str]:
        """Return `{duplicate_account_id: canonical_account_id}` for slots sharing a fingerprint."""
        active_id = reg.get("active_account_id")
        accounts = reg.get("accounts") or {}
        # Prefer active account as canonical, then sorted order for determinism
        ordered_ids = sorted(accounts.keys(), key=lambda aid: (0 if aid == active_id else 1, aid))
        seen_fp: dict[str, str] = {}
        dup_map: dict[str, str] = {}
        for aid in ordered_ids:
            rec = accounts[aid]
            fp = str(rec.get("credential_fingerprint") or "").strip()
            if not fp:
                continue
            if fp in seen_fp:
                dup_map[aid] = seen_fp[fp]
            else:
                seen_fp[fp] = aid
        return dup_map

    def list_accounts(self, *, for_group: bool = False) -> list[dict[str, Any]]:
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            active_id = reg.get("active_account_id")
            dup_map = self._compute_duplicates(reg)
            accounts = reg.get("accounts") or {}
            ordered_ids = sorted(accounts.keys(), key=lambda aid: (0 if aid == active_id else 1, aid))
            return [
                to_public_dict(
                    accounts[aid],
                    active_account_id=active_id,
                    is_duplicate=(aid in dup_map),
                    duplicate_of=dup_map.get(aid),
                    for_group=for_group,
                )
                for aid in ordered_ids
            ]

    def get_account(self, account_id: str, *, for_group: bool = False) -> dict[str, Any] | None:
        aid = validate_account_id(account_id)
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            rec = (reg.get("accounts") or {}).get(aid)
            if rec is None:
                return None
            dup_map = self._compute_duplicates(reg)
            return to_public_dict(
                rec,
                active_account_id=reg.get("active_account_id"),
                is_duplicate=(aid in dup_map),
                duplicate_of=dup_map.get(aid),
                for_group=for_group,
            )

    def get_active_account(self, *, for_group: bool = False) -> dict[str, Any] | None:
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            aid = reg.get("active_account_id")
            if not aid or aid not in (reg.get("accounts") or {}):
                return None
            dup_map = self._compute_duplicates(reg)
            return to_public_dict(
                reg["accounts"][aid],
                active_account_id=aid,
                is_duplicate=(aid in dup_map),
                duplicate_of=dup_map.get(aid),
                for_group=for_group,
            )

    def get_active_account_context(self) -> tuple[str, str]:
        """Return `(active_account_id, plan_tier)` for cost ledger tagging without side effects."""
        try:
            with self._exclusive_lock():
                reg = self._load_registry_locked()
                aid = reg.get("active_account_id")
                if not aid or aid not in (reg.get("accounts") or {}):
                    return "unassigned", "unknown"
                rec = reg["accounts"][aid]
                return str(aid), str(rec.get("plan_tier") or "unknown")
        except Exception:
            return "unassigned", "unknown"

    # -- Account Lifecycle Mutations ----------------------------------------

    def add_account(self, account_id: str, alias: str | None = None) -> dict[str, Any]:
        aid = validate_account_id(account_id)
        clean_alias = sanitize_alias(alias, aid)
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            accounts = reg.setdefault("accounts", {})
            if aid in accounts:
                raise AccountError(f"Account '{aid}' already exists")
            _ensure_secure_dir(self.profile_dir_for(aid) / "antigravity-acp", boundary=self.root_dir, enforce_mode=True)
            now_iso = _iso_utc_now()
            accounts[aid] = {
                "account_id": aid,
                "alias": clean_alias,
                "is_host_adopted": False,
                "auth_method": "oauth-personal",
                "email": "",
                "google_user_id": "",
                "credential_fingerprint": "",
                "plan_tier": "unknown",
                "plan_label": PLAN_TIER_LABELS["unknown"],
                "paid_tier_id": "",
                "current_tier_id": "",
                "quota": None,
                "status": "pending_login",
                "last_error": "",
                "last_checked_at": "",
                "created_at": now_iso,
                "updated_at": now_iso,
            }
            self._save_registry_locked(reg)
            return to_public_dict(accounts[aid], active_account_id=reg.get("active_account_id"))

    def register_logged_in_account(
        self,
        account_id: str,
        *,
        alias: str | None = None,
        token_doc: dict[str, Any],
    ) -> dict[str, Any]:
        """Register or update an account after a verified OAuth token file is written."""
        aid = validate_account_id(account_id)
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            accounts = reg.setdefault("accounts", {})
            now_iso = _iso_utc_now()
            existing = accounts.get(aid) or {}
            clean_alias = sanitize_alias(alias or existing.get("alias"), aid)
            email = str(token_doc.get("id_token_email") or existing.get("email") or "").strip()
            auth_method = str(token_doc.get("auth_method") or existing.get("auth_method") or "oauth-personal").strip()
            accounts[aid] = {
                "account_id": aid,
                "alias": clean_alias,
                "is_host_adopted": bool(existing.get("is_host_adopted", False)),
                "auth_method": auth_method or "oauth-personal",
                "email": email,
                "google_user_id": str(existing.get("google_user_id") or ""),
                "credential_fingerprint": str(existing.get("credential_fingerprint") or ""),
                "plan_tier": str(existing.get("plan_tier") or "unknown"),
                "plan_label": str(existing.get("plan_label") or PLAN_TIER_LABELS["unknown"]),
                "paid_tier_id": str(existing.get("paid_tier_id") or ""),
                "current_tier_id": str(existing.get("current_tier_id") or ""),
                "quota": existing.get("quota"),
                "status": "ready",
                "last_error": "",
                "last_checked_at": str(existing.get("last_checked_at") or ""),
                "created_at": str(existing.get("created_at") or now_iso),
                "updated_at": now_iso,
            }
            if not reg.get("active_account_id") and not self.host_token_path.exists():
                reg["active_account_id"] = aid
            self._save_registry_locked(reg)
            dup_map = self._compute_duplicates(reg)
            return to_public_dict(
                accounts[aid],
                active_account_id=reg.get("active_account_id"),
                is_duplicate=(aid in dup_map),
                duplicate_of=dup_map.get(aid),
            )

    def _sync_quota_and_cost_caches(self, account_id: str, rec: dict[str, Any]) -> None:
        """Atomically mirror active account quota & weekly reset into Bridge cache files if configured."""
        quota = rec.get("quota")
        if self.quota_cache_file is not None and isinstance(quota, dict) and quota.get("groups"):
            snap = {
                "fetched_at_epoch": float(quota.get("fetched_at_epoch") or time.time()),
                "fetched_at_iso": str(quota.get("fetched_at_iso") or _iso_utc_now()),
                "description": str(quota.get("description") or ""),
                "groups": quota.get("groups") or [],
                "account_id": account_id,
                "plan_tier": str(rec.get("plan_tier") or "unknown"),
            }
            payload = (json.dumps(snap, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            try:
                _write_bytes_atomic_0600(self.quota_cache_file, payload, enforce_parent_0700=False)
            except Exception:
                pass

        if self.cost_config_file is not None and isinstance(quota, dict):
            wk = quota.get("weekly_reset_utc")
            if isinstance(wk, dict) and "weekday" in wk and "hour" in wk:
                try:
                    try:
                        import cost_usage  # type: ignore[import-not-found]
                    except ImportError:
                        from bridge import cost_usage
                    cost_usage.save_weekly_reset_utc(
                        str(self.cost_config_file),
                        int(wk["weekday"]),
                        int(wk["hour"]),
                        int(wk.get("minute", 0)),
                        account_id=account_id,
                    )
                except Exception:
                    pass

    def switch_account(self, account_id: str) -> dict[str, Any]:
        """Atomically switch active Google account under `fcntl.flock`.

        1. Validate target `account_id`, anti-symlink check, and verify target token JSON BEFORE any mutation.
        2. Write back current host token atomically to the previously active slot (preserving CLI auto-refresh).
        3. Atomically replace host token file (`0600`) with target account's token.
        4. Persist updated `active_account_id` in `registry.json` and sync quota/cost caches.
        """
        aid = validate_account_id(account_id)
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            accounts = reg.get("accounts") or {}
            if aid not in accounts:
                raise AccountError(f"Account '{aid}' not found")

            target_tpath = self.token_path_for(aid)
            if target_tpath.is_symlink():
                raise SymlinkSecurityError("Target account token path is a symlink")
            if not target_tpath.exists():
                raise AccountError(f"Account '{aid}' has no OAuth token; please login first")
            target_raw = _read_bytes_nofollow(target_tpath, boundary=self.root_dir)
            parse_oauth_token_bytes(target_raw)

            # Fail-closed if host token path or its direct parent is a symlink
            _assert_no_symlink_chain(self.host_token_path)

            prev_id = reg.get("active_account_id")
            if prev_id and prev_id in accounts and self.host_token_path.exists():
                try:
                    host_raw = _read_bytes_nofollow(self.host_token_path)
                    parse_oauth_token_bytes(host_raw)
                except SymlinkSecurityError:
                    raise
                except Exception:
                    host_raw = None
                if host_raw is not None:
                    prev_tpath = self.token_path_for(prev_id)
                    _write_bytes_atomic_0600(prev_tpath, host_raw, boundary=self.root_dir, enforce_parent_0700=True)
                    if prev_id == aid:
                        target_raw = host_raw

            # Atomically replace host token file with target account's token
            _write_bytes_atomic_0600(self.host_token_path, target_raw, enforce_parent_0700=False)

            reg["active_account_id"] = aid
            accounts[aid]["status"] = "ready"
            accounts[aid]["updated_at"] = _iso_utc_now()
            self._save_registry_locked(reg)
            self._sync_quota_and_cost_caches(aid, accounts[aid])

            dup_map = self._compute_duplicates(reg)
            return {
                "ok": True,
                "previous_account_id": prev_id,
                "active_account_id": aid,
                "switched": prev_id != aid,
                "account": to_public_dict(
                    accounts[aid],
                    active_account_id=aid,
                    is_duplicate=(aid in dup_map),
                    duplicate_of=dup_map.get(aid),
                ),
            }

    def logout_account(self, account_id: str) -> dict[str, Any]:
        """Remove an account's isolated OAuth token and mark it logged out."""
        aid = validate_account_id(account_id)
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            accounts = reg.get("accounts") or {}
            if aid not in accounts:
                raise AccountError(f"Account '{aid}' not found")
            tpath = self.token_path_for(aid)
            _assert_no_symlink_chain(tpath, stop_at=self.root_dir)
            if tpath.exists():
                tpath.unlink()
            was_active = reg.get("active_account_id") == aid
            if was_active:
                reg["active_account_id"] = None
            accounts[aid]["status"] = "logged_out"
            accounts[aid]["quota"] = None
            accounts[aid]["updated_at"] = _iso_utc_now()
            self._save_registry_locked(reg)
            return {
                "ok": True,
                "account_id": aid,
                "was_active": was_active,
                "account": to_public_dict(accounts[aid], active_account_id=reg.get("active_account_id")),
            }

    def delete_account(self, account_id: str) -> dict[str, Any]:
        """Remove an account slot and its isolated profile directory under `fcntl.flock`."""
        aid = validate_account_id(account_id)
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            accounts = reg.get("accounts") or {}
            if aid not in accounts:
                raise AccountError(f"Account '{aid}' not found")
            pdir = self.profile_dir_for(aid)
            _assert_no_symlink_chain(pdir, stop_at=self.root_dir)
            if pdir.exists():
                shutil.rmtree(pdir)
            was_active = reg.get("active_account_id") == aid
            if was_active:
                reg["active_account_id"] = None
            accounts.pop(aid, None)
            self._save_registry_locked(reg)
            return {
                "ok": True,
                "account_id": aid,
                "was_active": was_active,
            }

    # -- Isolated Zero-Token Token Renewal ----------------------------------

    def refresh_token_isolated(self, account_id: str, *, timeout_sec: float = DEFAULT_REFRESH_SUBPROC_TIMEOUT_SEC) -> dict[str, Any]:
        """Renew an expired isolated profile token via headless `agy acp` JSON-RPC `initialize` (0 LLM tokens).

        Never touches host `~/.gemini/antigravity-cli/`.
        """
        aid = validate_account_id(account_id)
        pdir = self.profile_dir_for(aid)
        tpath = self.token_path_for(aid)
        _assert_no_symlink_chain(tpath, stop_at=self.root_dir)
        _ensure_secure_dir(pdir / "antigravity-acp", boundary=self.root_dir, enforce_mode=True)

        cmd = [
            self.agy_bin,
            "acp",
            "--gemini-dir",
            str(pdir),
            "--app-data-dir",
            "antigravity-acp",
        ]
        env = build_isolated_acp_env()
        proc = self._popen_fn(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env=env,
            text=True,
            bufsize=1,
        )
        init_req = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": 1, "clientCapabilities": {}},
        }, separators=(",", ":")) + "\n"

        deadline = time.monotonic() + min(max(0.5, float(timeout_sec)), 30.0)
        try:
            if proc.stdin is not None:
                proc.stdin.write(init_req)
                proc.stdin.flush()
            # Read response line with bounded deadline in helper thread so blocking readline cannot hang
            resp_box: list[str] = []

            def _reader() -> None:
                try:
                    if proc.stdout is None:
                        return
                    for line in proc.stdout:
                        s = line.strip()
                        if not s:
                            continue
                        resp_box.append(s)
                        if '"id":1' in s or '"id": 1' in s:
                            break
                except Exception:
                    pass

            rt = threading.Thread(target=_reader, daemon=True)
            rt.start()
            remaining = max(0.05, deadline - time.monotonic())
            rt.join(timeout=remaining)
        finally:
            terminate_process_group(proc, grace_sec=0.5)

        if not tpath.exists():
            raise GoogleProbeError("Isolated token refresh did not leave a readable token file")
        raw = _read_bytes_nofollow(tpath, boundary=self.root_dir)
        os.chmod(tpath, 0o600)
        return parse_oauth_token_bytes(raw)

    # -- Direct Google Metadata & Quota Probing -----------------------------

    def _probe_endpoints_for_token(
        self,
        access_token: str,
        auth_method: str,
        *,
        timeout_sec: float = MAX_PROBE_TIMEOUT_SEC,
    ) -> dict[str, Any]:
        userinfo = self._http_request_fn(
            "GET",
            GOOGLE_USERINFO_URL,
            access_token=access_token,
            timeout_sec=timeout_sec,
        )
        google_uid = str(userinfo.get("id") or "").strip()
        email = str(userinfo.get("email") or "").strip()
        fingerprint = compute_credential_fingerprint(google_uid) if google_uid else ""

        endpoints = (
            [CLOUDCODE_PROD_BASE, CLOUDCODE_DAILY_BASE]
            if auth_method == "oauth-business"
            else [CLOUDCODE_DAILY_BASE, CLOUDCODE_PROD_BASE]
        )

        # 1. loadCodeAssist for tier classification & optional project_id
        paid_tier = None
        current_tier = None
        project_id = None
        for base in endpoints:
            try:
                lca = self._http_request_fn(
                    "POST",
                    f"{base}/v1internal:loadCodeAssist",
                    access_token=access_token,
                    json_body={"metadata": {"ideType": "ANTIGRAVITY"}},
                    timeout_sec=timeout_sec,
                )
                paid_tier = lca.get("paidTier")
                current_tier = lca.get("currentTier")
                proj = lca.get("cloudaicompanionProject")
                if isinstance(proj, str) and proj.strip():
                    project_id = proj.strip()
                break
            except GoogleProbeError as exc:
                if exc.status_code == 401:
                    raise
                continue

        plan_tier, plan_label = classify_plan_tier(paid_tier, current_tier)

        def _tier_id_str(val: Any) -> str:
            if isinstance(val, dict):
                return str(val.get("id") or val.get("name") or "").strip()
            return str(val or "").strip()

        # 2. retrieveUserQuotaSummary across primary/backup endpoints (first host wins per bucketId)
        merged_groups: dict[str, dict[str, Any]] = {}
        merged_windows: dict[str, dict[str, Any]] = {}
        seen_bucket_ids: set[str] = set()
        quota_body = {"project": project_id} if project_id else {}

        for base in endpoints:
            req_ms = time.time() * 1000.0
            try:
                summary_resp = self._http_request_fn(
                    "POST",
                    f"{base}/v1internal:retrieveUserQuotaSummary",
                    access_token=access_token,
                    json_body=quota_body,
                    timeout_sec=timeout_sec,
                )
            except GoogleProbeError as exc:
                if exc.status_code == 401:
                    raise
                continue
            grps, wins = parse_quota_summary_response(summary_resp, requested_at_ms=req_ms)
            for w in wins:
                if w["id"] not in merged_windows:
                    merged_windows[w["id"]] = w
            for g in grps:
                g_out = merged_groups.setdefault(g["name"], {"name": g["name"], "description": g.get("description") or "", "buckets": []})
                for b in g.get("buckets") or []:
                    if b["id"] not in seen_bucket_ids:
                        seen_bucket_ids.add(b["id"])
                        g_out["buckets"].append(b)

        # 3. Fallback to fetchAvailableModels if summary returned empty
        if not merged_windows:
            for base in endpoints:
                try:
                    models_resp = self._http_request_fn(
                        "POST",
                        f"{base}/v1internal:fetchAvailableModels",
                        access_token=access_token,
                        json_body=quota_body,
                        timeout_sec=timeout_sec,
                    )
                except GoogleProbeError as exc:
                    if exc.status_code == 401:
                        raise
                    continue
                grps, wins = parse_available_models_fallback(models_resp)
                for w in wins:
                    if w["id"] not in merged_windows:
                        merged_windows[w["id"]] = w
                for g in grps:
                    g_out = merged_groups.setdefault(g["name"], {"name": g["name"], "description": "", "buckets": []})
                    for b in g.get("buckets") or []:
                        if b["id"] not in seen_bucket_ids:
                            seen_bucket_ids.add(b["id"])
                            g_out["buckets"].append(b)

        groups_list = [g for g in merged_groups.values() if g.get("buckets")]
        windows_list = list(merged_windows.values())

        # Extract weekly reset UTC anchor from Gemini weekly bucket if available
        weekly_reset_utc = None
        for g in groups_list:
            for b in g.get("buckets") or []:
                if b.get("id") == "gemini-weekly" or ("gemini" in (g.get("name") or "").lower() and b.get("window") == "weekly"):
                    rst_dt = _parse_iso_utc(b.get("reset_time"))
                    if rst_dt is not None:
                        weekly_reset_utc = {
                            "weekday": rst_dt.weekday(),
                            "hour": rst_dt.hour,
                            "minute": rst_dt.minute,
                        }
                    break
            if weekly_reset_utc is not None:
                break

        now_epoch = time.time()
        quota_obj = {
            "fetched_at_epoch": now_epoch,
            "fetched_at_iso": _iso_utc_now(),
            "description": "",
            "groups": groups_list,
            "windows": windows_list,
            "weekly_reset_utc": weekly_reset_utc,
        }

        return {
            "google_user_id": google_uid,
            "email": email,
            "credential_fingerprint": fingerprint,
            "plan_tier": plan_tier,
            "plan_label": plan_label,
            "paid_tier_id": _tier_id_str(paid_tier),
            "current_tier_id": _tier_id_str(current_tier),
            "quota": quota_obj,
        }

    def refresh_account(self, account_id: str | None = None, *, timeout_sec: float = MAX_PROBE_TIMEOUT_SEC) -> dict[str, Any]:
        """Refresh userinfo, plan tier, and quota for `account_id` (defaults to active account)."""
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            aid = validate_account_id(account_id) if account_id is not None else reg.get("active_account_id")
            if not aid or aid not in (reg.get("accounts") or {}):
                raise AccountError("No target or active account found to refresh")
            rec = reg["accounts"][aid]
            auth_method = str(rec.get("auth_method") or "oauth-personal")
            tpath = self.token_path_for(aid)
            if not tpath.exists():
                raise AccountError(f"Account '{aid}' has no OAuth token; please login first")
            raw_tok = _read_bytes_nofollow(tpath, boundary=self.root_dir)
            tok_doc = parse_oauth_token_bytes(raw_tok)

        # Perform network/refresh I/O outside registry lock so concurrent readers aren't stalled
        if is_token_expiring(tok_doc):
            tok_doc = self.refresh_token_isolated(aid)

        access_token = str(tok_doc["token"]["access_token"])
        try:
            probe_data = self._probe_endpoints_for_token(access_token, auth_method, timeout_sec=timeout_sec)
        except GoogleProbeError as exc:
            if exc.status_code == 401:
                tok_doc = self.refresh_token_isolated(aid)
                access_token = str(tok_doc["token"]["access_token"])
                probe_data = self._probe_endpoints_for_token(access_token, auth_method, timeout_sec=timeout_sec)
            else:
                with self._exclusive_lock():
                    reg = self._load_registry_locked()
                    if aid in (reg.get("accounts") or {}):
                        reg["accounts"][aid]["last_error"] = scrub_paths_for_public(str(exc))[:240]
                        reg["accounts"][aid]["last_checked_at"] = _iso_utc_now()
                        self._save_registry_locked(reg)
                raise

        with self._exclusive_lock():
            reg = self._load_registry_locked()
            accounts = reg.get("accounts") or {}
            if aid not in accounts:
                raise AccountError(f"Account '{aid}' was deleted during refresh")
            rec = accounts[aid]
            now_iso = _iso_utc_now()
            if probe_data.get("email"):
                rec["email"] = probe_data["email"]
            if probe_data.get("google_user_id"):
                rec["google_user_id"] = probe_data["google_user_id"]
            if probe_data.get("credential_fingerprint"):
                rec["credential_fingerprint"] = probe_data["credential_fingerprint"]
            rec["plan_tier"] = probe_data["plan_tier"]
            rec["plan_label"] = probe_data["plan_label"]
            rec["paid_tier_id"] = probe_data["paid_tier_id"]
            rec["current_tier_id"] = probe_data["current_tier_id"]
            rec["quota"] = probe_data["quota"]
            rec["status"] = "ready"
            rec["last_error"] = ""
            rec["last_checked_at"] = now_iso
            rec["updated_at"] = now_iso
            self._save_registry_locked(reg)
            if reg.get("active_account_id") == aid:
                self._sync_quota_and_cost_caches(aid, rec)
            dup_map = self._compute_duplicates(reg)
            return to_public_dict(
                rec,
                active_account_id=reg.get("active_account_id"),
                is_duplicate=(aid in dup_map),
                duplicate_of=dup_map.get(aid),
            )

    def refresh_all_accounts(self, *, timeout_sec: float = MAX_PROBE_TIMEOUT_SEC) -> dict[str, Any]:
        """Refresh all logged-in accounts and return updated summaries + per-account errors."""
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            candidate_ids = [
                aid for aid, rec in (reg.get("accounts") or {}).items()
                if self.token_path_for(aid).exists() and rec.get("status") != "logged_out"
            ]
        refreshed: list[dict[str, Any]] = []
        errors: dict[str, str] = {}
        for aid in candidate_ids:
            try:
                refreshed.append(self.refresh_account(aid, timeout_sec=timeout_sec))
            except Exception as exc:
                errors[aid] = scrub_paths_for_public(str(exc))[:200]
        return {
            "ok": len(errors) == 0,
            "refreshed": refreshed,
            "errors": errors,
            "summary": self.summarize_plan_quotas(),
        }

    # -- Multi-Plan Deduplicated Aggregation & Recommendation (C6) ----------

    def summarize_plan_quotas(self, *, for_group: bool = False) -> dict[str, Any]:
        """Aggregate multi-plan quota pools deduplicated strictly by `credential_fingerprint`."""
        with self._exclusive_lock():
            reg = self._load_registry_locked()
            active_id = reg.get("active_account_id")
            dup_map = self._compute_duplicates(reg)
            accounts = reg.get("accounts") or {}
            ordered_ids = sorted(accounts.keys(), key=lambda aid: (0 if aid == active_id else 1, aid))

            tiers: dict[str, dict[str, Any]] = {}
            seen_keys: set[str] = set()
            total_unique = 0
            total_slots = 0
            duplicate_slot_count = 0

            pool_keys = ("gemini_5h", "gemini_weekly", "claude_gpt_5h", "claude_gpt_weekly")

            for aid in ordered_ids:
                rec = accounts[aid]
                total_slots += 1
                plan_tier = str(rec.get("plan_tier") or "unknown")
                plan_label = str(rec.get("plan_label") or PLAN_TIER_LABELS.get(plan_tier, "Unknown"))
                tier_entry = tiers.setdefault(plan_tier, {
                    "plan_tier": plan_tier,
                    "plan_label": plan_label,
                    "unique_accounts": 0,
                    "slot_count": 0,
                    "duplicate_slots": 0,
                    "account_ids": [],
                    "pools": {
                        pk: {
                            "accounts_with_data": 0,
                            "total_remaining_fraction": 0.0,
                            "avg_remaining_pct": None,
                            "max_remaining_pct": None,
                            "exhausted_count": 0,
                            "earliest_reset_at": None,
                        }
                        for pk in pool_keys
                    },
                })
                tier_entry["slot_count"] += 1
                tier_entry["account_ids"].append(aid)

                fp = str(rec.get("credential_fingerprint") or "").strip()
                dedup_key = f"fp:{fp}" if fp else f"slot:{aid}"
                if aid in dup_map or dedup_key in seen_keys:
                    tier_entry["duplicate_slots"] += 1
                    duplicate_slot_count += 1
                    continue
                seen_keys.add(dedup_key)
                tier_entry["unique_accounts"] += 1
                total_unique += 1

                qs = _extract_quota_summary(rec.get("quota"))
                for pk in pool_keys:
                    pct_val = qs.get(f"{pk}_pct")
                    rst_val = qs.get(f"{pk}_reset_at")
                    if pct_val is None:
                        continue
                    pool = tier_entry["pools"][pk]
                    frac = max(0.0, min(1.0, float(pct_val) / 100.0))
                    pool["accounts_with_data"] += 1
                    pool["total_remaining_fraction"] = round(pool["total_remaining_fraction"] + frac, 4)
                    if pool["max_remaining_pct"] is None or pct_val > pool["max_remaining_pct"]:
                        pool["max_remaining_pct"] = round(float(pct_val), 1)
                    if pct_val <= 5.0:
                        pool["exhausted_count"] += 1
                    if rst_val:
                        cur_rst = pool["earliest_reset_at"]
                        if cur_rst is None:
                            pool["earliest_reset_at"] = rst_val
                        else:
                            dt_new = _parse_iso_utc(rst_val)
                            dt_old = _parse_iso_utc(cur_rst)
                            if dt_new is not None and (dt_old is None or dt_new < dt_old):
                                pool["earliest_reset_at"] = rst_val

            for tier_entry in tiers.values():
                for pool in tier_entry["pools"].values():
                    cnt = pool["accounts_with_data"]
                    if cnt > 0:
                        pool["avg_remaining_pct"] = round((pool["total_remaining_fraction"] / cnt) * 100.0, 1)

            ordered_tiers = sorted(
                tiers.values(),
                key=lambda t: (-PLAN_TIER_PRIORITY.get(t["plan_tier"], 0), t["plan_tier"]),
            )
            return {
                "active_account_id": active_id,
                "total_unique_accounts": total_unique,
                "total_slots": total_slots,
                "duplicate_slot_count": duplicate_slot_count,
                "for_group": bool(for_group),
                "tiers": ordered_tiers,
            }

    def recommend_account(self, model_group: str = "claude_gpt", *, for_group: bool = False) -> dict[str, Any]:
        """Recommend the best non-exhausted account for `model_group` (`claude_gpt` or `gemini`)."""
        mg = str(model_group or "claude_gpt").strip().lower()
        if mg not in ("claude_gpt", "gemini"):
            raise ValueError("model_group must be 'claude_gpt' or 'gemini'")

        with self._exclusive_lock():
            reg = self._load_registry_locked()
            active_id = reg.get("active_account_id")
            dup_map = self._compute_duplicates(reg)
            accounts = reg.get("accounts") or {}

            candidates: list[tuple[tuple[float, int, int, str], dict[str, Any], float]] = []
            seen_fps: set[str] = set()
            ordered_ids = sorted(accounts.keys(), key=lambda aid: (0 if aid == active_id else 1, aid))

            for aid in ordered_ids:
                rec = accounts[aid]
                if rec.get("status") != "ready":
                    continue
                fp = str(rec.get("credential_fingerprint") or "").strip()
                if aid in dup_map or (fp and fp in seen_fps):
                    continue
                if fp:
                    seen_fps.add(fp)
                qs = _extract_quota_summary(rec.get("quota"))
                if mg == "gemini":
                    p5 = qs.get("gemini_5h_pct")
                    pw = qs.get("gemini_weekly_pct")
                else:
                    p5 = qs.get("claude_gpt_5h_pct")
                    pw = qs.get("claude_gpt_weekly_pct")
                vals = [v for v in (p5, pw) if v is not None]
                if not vals:
                    continue
                eff_pct = min(vals)
                if eff_pct <= 5.0:
                    continue
                tier_prio = PLAN_TIER_PRIORITY.get(str(rec.get("plan_tier") or "unknown"), 0)
                is_active_bonus = 1 if aid == active_id else 0
                pub = to_public_dict(
                    rec,
                    active_account_id=active_id,
                    is_duplicate=False,
                    duplicate_of=None,
                    for_group=for_group,
                )
                candidates.append(((eff_pct, tier_prio, is_active_bonus, aid), pub, eff_pct))

            candidates.sort(key=lambda item: (-item[0][0], -item[0][1], -item[0][2], item[0][3]))
            if not candidates:
                return {
                    "model_group": mg,
                    "recommended": None,
                    "reason": f"No non-exhausted account available for {mg}",
                    "candidates": [],
                }
            best_pub = candidates[0][1]
            best_pct = candidates[0][2]
            return {
                "model_group": mg,
                "recommended": best_pub,
                "reason": f"Selected {best_pub['account_id']} ({best_pub['plan_label']}, min remaining {best_pct:.1f}%)",
                "candidates": [c[1] for c in candidates],
            }


# ---------------------------------------------------------------------------
# Headless OAuth Login State Machine (`GoogleLoginFlowManager`)
# ---------------------------------------------------------------------------

class _LoginFlowState:
    __slots__ = (
        "flow_id",
        "account_id",
        "alias",
        "owner_session_id",
        "oauth_state",
        "auth_url",
        "proc",
        "status",
        "created_at",
        "expires_at",
        "error",
        "account",
        "timer",
    )

    def __init__(
        self,
        *,
        flow_id: str,
        account_id: str,
        alias: str,
        owner_session_id: str,
        oauth_state: str,
        auth_url: str,
        proc: Any,
        created_at: float,
        expires_at: float,
    ) -> None:
        self.flow_id = flow_id
        self.account_id = account_id
        self.alias = alias
        self.owner_session_id = owner_session_id
        self.oauth_state = oauth_state
        self.auth_url = auth_url
        self.proc = proc
        self.status = "awaiting_code"
        self.created_at = created_at
        self.expires_at = expires_at
        self.error = ""
        self.account: dict[str, Any] | None = None
        self.timer: threading.Timer | None = None


def validate_oauth_code_or_callback_url(raw_input: Any, expected_state: str) -> str:
    """Strictly validate user-pasted OAuth authorization code or official callback URL.

    Raises `ValueError` on any control characters, non-official callback host/path,
    OAuth `state` mismatch, or malformed code. Never passes untrusted data to stdin.
    """
    if not isinstance(raw_input, str):
        raise ValueError("code_or_url must be a string")
    if not raw_input or len(raw_input) > 4096:
        raise ValueError("code_or_url is empty or exceeds maximum length")
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in raw_input):
        raise ValueError("Control characters are forbidden in OAuth code/URL")

    cleaned = raw_input.strip()
    if not cleaned:
        raise ValueError("code_or_url cannot be blank")

    lower = cleaned.lower()
    is_url_like = ("://" in cleaned) or lower.startswith(("http:", "https:", "javascript:", "data:", "file:"))
    if is_url_like:
        parsed = urllib.parse.urlsplit(cleaned)
        if parsed.scheme != "https":
            raise ValueError("Callback URL must use https scheme")
        if parsed.username or parsed.password:
            raise ValueError("Callback URL must not contain credentials")
        if (parsed.hostname or "").lower() != ALLOWED_OAUTH_CALLBACK_HOST or parsed.port is not None:
            raise ValueError(f"Callback URL host must be {ALLOWED_OAUTH_CALLBACK_HOST}")
        if parsed.path != ALLOWED_OAUTH_CALLBACK_PATH:
            raise ValueError(f"Callback URL path must be {ALLOWED_OAUTH_CALLBACK_PATH}")
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        states = qs.get("state") or []
        codes = qs.get("code") or []
        if len(states) != 1 or len(codes) != 1:
            raise ValueError("Callback URL must contain single 'code' and 'state' query parameters")
        if not expected_state or not hmac.compare_digest(states[0], expected_state):
            raise ValueError("OAuth state mismatch")
        code_val = codes[0]
        if not OAUTH_CODE_RE.fullmatch(code_val):
            raise ValueError("Invalid OAuth authorization code format in callback URL")
        return cleaned

    if any(ch.isspace() for ch in cleaned):
        raise ValueError("OAuth code must not contain whitespace")
    if not OAUTH_CODE_RE.fullmatch(cleaned):
        raise ValueError("Invalid OAuth authorization code format")
    return cleaned


class GoogleLoginFlowManager:
    """Manages headless `agy acp --login` PKCE OAuth flows with session ownership, TTL, and killpg cleanup."""

    def __init__(
        self,
        account_manager: GoogleAccountManager,
        *,
        popen_fn: Callable[..., Any] | None = None,
        url_wait_timeout_sec: float = DEFAULT_URL_WAIT_TIMEOUT_SEC,
        submit_wait_timeout_sec: float = DEFAULT_SUBMIT_WAIT_TIMEOUT_SEC,
        auto_probe_on_login: bool = False,
    ) -> None:
        self.account_manager = account_manager
        self._popen_fn = popen_fn or account_manager._popen_fn
        self._url_wait_timeout_sec = float(url_wait_timeout_sec)
        self._submit_wait_timeout_sec = float(submit_wait_timeout_sec)
        self._auto_probe_on_login = bool(auto_probe_on_login)
        self._lock = threading.RLock()
        self._flows: dict[str, _LoginFlowState] = {}

    def _assert_owner(self, flow: _LoginFlowState, owner_session_id: Any) -> None:
        if not isinstance(owner_session_id, str):
            raise PermissionError("Cross-session access to OAuth flow denied")
        if not hmac.compare_digest(flow.owner_session_id, owner_session_id):
            raise PermissionError("Cross-session access to OAuth flow denied")

    def _public_flow_dict(self, flow: _LoginFlowState, *, include_auth_url: bool = False) -> dict[str, Any]:
        """Serialize flow state; NEVER exposes `oauth_state` and omits `auth_url` from GET views."""
        out: dict[str, Any] = {
            "flow_id": flow.flow_id,
            "account_id": flow.account_id,
            "alias": flow.alias,
            "status": flow.status,
            "created_at": round(flow.created_at, 3),
            "expires_at": round(flow.expires_at, 3),
            "error": scrub_paths_for_public(flow.error),
            "account": flow.account,
        }
        if include_auth_url and flow.status == "awaiting_code":
            out["auth_url"] = flow.auth_url
        return out

    def _expire_flow_by_id(self, flow_id: str) -> None:
        proc_to_kill = None
        with self._lock:
            flow = self._flows.get(flow_id)
            if flow is None or flow.status != "awaiting_code":
                return
            flow.status = "expired"
            flow.error = "OAuth login flow timed out"
            proc_to_kill = flow.proc
            flow.proc = None
            if flow.timer is not None:
                flow.timer.cancel()
                flow.timer = None
        if proc_to_kill is not None:
            terminate_process_group(proc_to_kill)

    def _check_expiry_locked(self, flow: _LoginFlowState) -> Any | None:
        if flow.status == "awaiting_code" and time.monotonic() >= flow.expires_at:
            flow.status = "expired"
            flow.error = "OAuth login flow timed out"
            if flow.timer is not None:
                flow.timer.cancel()
                flow.timer = None
            proc = flow.proc
            flow.proc = None
            return proc
        return None

    def _read_auth_url_from_proc(self, proc: Any, timeout_sec: float) -> tuple[str, str]:
        """Read subprocess stdout until a valid Google OAuth URL with `state` is emitted."""
        result_box: dict[str, str] = {}
        err_lines: list[str] = []

        def _reader() -> None:
            try:
                if proc.stdout is None:
                    return
                for raw_line in proc.stdout:
                    line = raw_line.strip()
                    if not line:
                        continue
                    m = GOOGLE_AUTH_URL_RE.search(line)
                    if m:
                        cand_url = m.group(0)
                        parsed = urllib.parse.urlsplit(cand_url)
                        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
                        states = qs.get("state") or []
                        if parsed.scheme == "https" and (parsed.hostname or "").lower() == "accounts.google.com" and len(states) == 1 and states[0].strip():
                            result_box["auth_url"] = cand_url
                            result_box["oauth_state"] = states[0].strip()
                            return
                    if len(err_lines) < 8:
                        err_lines.append(redact_secrets(line)[:160])
            except Exception as exc:
                err_lines.append(f"read error: {type(exc).__name__}")

        rt = threading.Thread(target=_reader, daemon=True)
        rt.start()
        rt.join(timeout=max(0.2, float(timeout_sec)))
        if "auth_url" not in result_box or "oauth_state" not in result_box:
            detail = " | ".join(err_lines[-3:]) if err_lines else "timed out waiting for Google OAuth URL"
            raise RuntimeError(f"Failed to obtain Google OAuth URL: {redact_secrets(detail)}")
        return result_box["auth_url"], result_box["oauth_state"]

    def start_login(
        self,
        account_id: str,
        alias: str | None = None,
        owner_session_id: str = "",
        timeout_sec: float = DEFAULT_LOGIN_TIMEOUT_SEC,
    ) -> dict[str, Any]:
        """Start an isolated headless `agy acp --login` flow bound to `owner_session_id`."""
        aid = validate_account_id(account_id)
        if not isinstance(owner_session_id, str):
            raise ValueError("owner_session_id must be a string")
        clean_alias = sanitize_alias(alias, aid)
        eff_timeout = min(max(0.2, float(timeout_sec)), MAX_LOGIN_TIMEOUT_SEC)

        # Ensure isolated profile directory exists and is 0700 (anti-symlink checked)
        with self.account_manager._exclusive_lock():
            reg = self.account_manager._load_registry_locked()
            existing = (reg.get("accounts") or {}).get(aid)
            if existing and not alias:
                clean_alias = sanitize_alias(existing.get("alias"), aid)
            pdir = self.account_manager.profile_dir_for(aid)
            _ensure_secure_dir(pdir / "antigravity-acp", boundary=self.account_manager.root_dir, enforce_mode=True)

        # Cancel any prior active flow for the same account_id before starting a fresh one
        self.cancel_flows_for_account(aid)

        cmd = [
            self.account_manager.agy_bin,
            "acp",
            "--gemini-dir",
            str(pdir),
            "--app-data-dir",
            "antigravity-acp",
            "--login",
        ]
        env = build_isolated_acp_env()
        proc = self._popen_fn(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=env,
            text=True,
            bufsize=1,
        )

        try:
            auth_url, oauth_state = self._read_auth_url_from_proc(proc, timeout_sec=min(self._url_wait_timeout_sec, eff_timeout))
        except Exception:
            terminate_process_group(proc)
            raise

        now_mono = time.monotonic()
        flow_id = f"gflow_{secrets.token_hex(12)}"
        flow = _LoginFlowState(
            flow_id=flow_id,
            account_id=aid,
            alias=clean_alias,
            owner_session_id=owner_session_id,
            oauth_state=oauth_state,
            auth_url=auth_url,
            proc=proc,
            created_at=now_mono,
            expires_at=now_mono + eff_timeout,
        )
        timer = threading.Timer(eff_timeout, self._expire_flow_by_id, args=(flow_id,))
        timer.daemon = True
        flow.timer = timer

        with self._lock:
            self._flows[flow_id] = flow
            timer.start()
            return self._public_flow_dict(flow, include_auth_url=True)

    def get_flow(self, flow_id: str, owner_session_id: str) -> dict[str, Any]:
        """Get flow status for the owning session (omits `oauth_state` and `auth_url`)."""
        proc_to_kill = None
        with self._lock:
            flow = self._flows.get(str(flow_id or ""))
            if flow is None:
                raise FlowNotFoundError(f"Unknown login flow: {flow_id}")
            self._assert_owner(flow, owner_session_id)
            proc_to_kill = self._check_expiry_locked(flow)
            resp = self._public_flow_dict(flow, include_auth_url=False)
        if proc_to_kill is not None:
            terminate_process_group(proc_to_kill)
        return resp

    def submit_code(self, flow_id: str, code_or_url: str, owner_session_id: str) -> dict[str, Any]:
        """Validate and submit an OAuth code or official callback URL to the running login flow."""
        proc_to_kill = None
        with self._lock:
            flow = self._flows.get(str(flow_id or ""))
            if flow is None:
                raise FlowNotFoundError(f"Unknown login flow: {flow_id}")
            self._assert_owner(flow, owner_session_id)
            proc_to_kill = self._check_expiry_locked(flow)
            if proc_to_kill is None and flow.status != "awaiting_code":
                raise FlowConflictError(f"OAuth login flow is no longer active (status={flow.status})")
            if proc_to_kill is None:
                # Validate BEFORE mutating state or touching stdin!
                validated_input = validate_oauth_code_or_callback_url(code_or_url, flow.oauth_state)
                flow.status = "submitting"
                if flow.timer is not None:
                    flow.timer.cancel()
                    flow.timer = None
                proc = flow.proc
                aid = flow.account_id
                alias = flow.alias
            else:
                validated_input = ""
                proc = None
                aid = flow.account_id
                alias = flow.alias

        if proc_to_kill is not None:
            terminate_process_group(proc_to_kill)
            raise FlowConflictError("OAuth login flow has expired")

        try:
            if proc is None or proc.stdin is None:
                raise RuntimeError("OAuth subprocess stdin unavailable")
            proc.stdin.write(validated_input + "\n")
            proc.stdin.flush()
            try:
                proc.stdin.close()
            except Exception:
                pass

            try:
                rc = proc.wait(timeout=self._submit_wait_timeout_sec)
            except subprocess.TimeoutExpired as exc:
                terminate_process_group(proc)
                raise RuntimeError("OAuth login subprocess timed out after code submission") from exc
            finally:
                if proc is not None and proc.poll() is not None:
                    _close_proc_pipes(proc)

            if rc != 0:
                raise RuntimeError(f"OAuth login subprocess exited with code {rc}")

            tpath = self.account_manager.token_path_for(aid)
            if tpath.is_symlink():
                raise SymlinkSecurityError("OAuth login produced a symlinked token file")
            if not tpath.exists():
                raise RuntimeError("OAuth login completed without writing token file")
            raw_tok = _read_bytes_nofollow(tpath, boundary=self.account_manager.root_dir)
            os.chmod(tpath, 0o600)
            tok_doc = parse_oauth_token_bytes(raw_tok)
            pub_acct = self.account_manager.register_logged_in_account(aid, alias=alias, token_doc=tok_doc)

            if self._auto_probe_on_login:
                try:
                    pub_acct = self.account_manager.refresh_account(aid)
                except Exception:
                    pass

            with self._lock:
                flow.status = "completed"
                flow.account = pub_acct
                flow.proc = None
                flow.oauth_state = ""
                flow.auth_url = ""
                return self._public_flow_dict(flow, include_auth_url=False)
        except Exception as exc:
            terminate_process_group(proc)
            with self._lock:
                flow.status = "failed"
                flow.error = scrub_paths_for_public(str(exc))[:240]
                flow.proc = None
                flow.oauth_state = ""
                flow.auth_url = ""
            raise
        finally:
            if proc is not None:
                _close_proc_pipes(proc)

    def cancel_flow(self, flow_id: str, owner_session_id: str) -> dict[str, Any]:
        """Cancel an active flow owned by `owner_session_id` and terminate its process group."""
        proc_to_kill = None
        with self._lock:
            flow = self._flows.get(str(flow_id or ""))
            if flow is None:
                raise FlowNotFoundError(f"Unknown login flow: {flow_id}")
            self._assert_owner(flow, owner_session_id)
            if flow.timer is not None:
                flow.timer.cancel()
                flow.timer = None
            proc_to_kill = flow.proc
            flow.proc = None
            if flow.status in ("awaiting_code", "submitting"):
                flow.status = "cancelled"
            flow.oauth_state = ""
            flow.auth_url = ""
            resp = self._public_flow_dict(flow, include_auth_url=False)
        if proc_to_kill is not None:
            terminate_process_group(proc_to_kill)
        return resp

    def cancel_flows_for_session(self, owner_session_id: str) -> int:
        """Cancel and reap all active flows belonging to `owner_session_id`."""
        if not isinstance(owner_session_id, str):
            return 0
        procs: list[Any] = []
        cancelled = 0
        with self._lock:
            for flow in self._flows.values():
                if hmac.compare_digest(flow.owner_session_id, owner_session_id):
                    if flow.timer is not None:
                        flow.timer.cancel()
                        flow.timer = None
                    if flow.proc is not None:
                        procs.append(flow.proc)
                        flow.proc = None
                    if flow.status in ("awaiting_code", "submitting"):
                        flow.status = "cancelled"
                        cancelled += 1
                    flow.oauth_state = ""
                    flow.auth_url = ""
        for p in procs:
            terminate_process_group(p)
        return cancelled

    def cancel_flows_for_account(self, account_id: str) -> int:
        """Cancel and reap all active flows targeting `account_id`."""
        aid = validate_account_id(account_id)
        procs: list[Any] = []
        cancelled = 0
        with self._lock:
            for flow in self._flows.values():
                if flow.account_id == aid:
                    if flow.timer is not None:
                        flow.timer.cancel()
                        flow.timer = None
                    if flow.proc is not None:
                        procs.append(flow.proc)
                        flow.proc = None
                    if flow.status in ("awaiting_code", "submitting"):
                        flow.status = "cancelled"
                        cancelled += 1
                    flow.oauth_state = ""
                    flow.auth_url = ""
        for p in procs:
            terminate_process_group(p)
        return cancelled

    def cleanup_all_flows(self) -> int:
        """Terminate and reap all tracked OAuth subprocesses (called on shutdown/hot-reload)."""
        procs: list[Any] = []
        cancelled = 0
        with self._lock:
            for flow in self._flows.values():
                if flow.timer is not None:
                    flow.timer.cancel()
                    flow.timer = None
                if flow.proc is not None:
                    procs.append(flow.proc)
                    flow.proc = None
                if flow.status in ("awaiting_code", "submitting"):
                    flow.status = "cancelled"
                    cancelled += 1
                flow.oauth_state = ""
                flow.auth_url = ""
        for p in procs:
            terminate_process_group(p)
        return cancelled
