#!/usr/bin/env python3
"""Generic Host Telegram <-> Federation PullWorkerQueue Bridge Daemon.

Pure Python standard-library daemon bridging Telegram Bot API (long polling) to
registered `pull_worker` external agents in `federation_registry.PullWorkerQueue`.
Supports both legacy single-bot env mode (`F1..F8`) and single-process multi-bot
config file mode (`AGY_FED_TG_BOTS_CONFIG=/path/to/fed_bots.json`, `M1..M4`).

Security & reliability invariants (F1..F8, M1..M4):
- Secret hygiene (F1, M2): Resolves `AGY_FED_TG_TOKEN_SECRET_REF` / `token_secret_ref`
  ephemerally in memory via `external_drivers.resolve_secret_ref` (fail-closed on invalid
  ref / failure / empty value; never falls back to `AGY_FED_TG_BOT_TOKEN` when a secret
  ref is configured or in multi-bot config mode). A process-wide thread-safe token
  redaction registry (`SecretRedactionRegistry`) registers every loaded bot's raw and
  URL-encoded tokens across `RedactingLogFilter`, `scrub_secrets`, and `scrub_metadata`.
- Multi-bot config hardening (M1): Opens `AGY_FED_TG_BOTS_CONFIG` with `O_NOFOLLOW |
  O_NONBLOCK | O_CLOEXEC` and verifies via `os.fstat(fd)` that it is a regular file with
  `mode & 0o077 == 0` (anti-TOCTOU). Rejects forbidden plaintext secret keys, enforces
  global uniqueness (`name`, `agent_id`, `token_secret_ref`, `state_dir`, `bot_id`),
  strict integer lists (`type(x) is int`), non-empty `owner_users`, and non-downgrading
  union `effective_denied_chats = defaults.denied_chats | bot.denied_chats | env_denied_chats`.
- Owner RBAC & `DENIED_CHATS` precedence (F2): `owner_users` must be a non-empty set of
  positive integers (fail-closed at startup). Non-owners, missing `from`, and
  `sender_chat` / anonymous-admin messages are silently dropped without calling
  `make_owner_auth()` or `PullWorkerQueue`.
- Bot-loop immunity & group trigger gating (F3): Any message with `from.is_bot == True` is
  unconditionally silently dropped. In authorized groups, triggers only on exact
  `@<bot_username>` mention, reply to this bot, or explicit slash commands.
- State file hardening (F4): State directories `0700`, files `0600` (`bindings.json`,
  `offset.json`, `bridge.lock`, `state.lock`, `supervisor.lock`), symlink/`O_NOFOLLOW`
  fail-closed guards, atomic `flock` + temp-file + `os.replace` writes.
- Target agent & env fail-closed (F5): Strict `validate_agent_id` plus real-time
  `federation_registry.get_agent` eligibility checks at startup and before every `enqueue`.
- Concurrency, fault isolation, dual locks & graceful reload (F6, F7, M2, M3): Per-bot
  isolated worker threads, `TelegramClient`s, state directories, and job tables with
  bounded backoff on errors; dual exclusive locks (`supervisor.lock` + per-bot
  `bridge.lock` with `FD_CLOEXEC`) with zero-leak rollback on conflict; graceful shutdown
  on `SIGTERM`/`SIGINT`/`SIGHUP`/reload sentinel (`/tmp/agy_fed_tg_reload`) with atomic
  offset flush and explicit lock fd close before `os.execv`.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import dataclasses
import errno
import fcntl
import html as html_mod
import json
import logging
import os
import re
import signal
import stat
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple

if __package__:
    from . import external_drivers  # type: ignore
    from . import federation_registry  # type: ignore
else:
    _THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    if _THIS_DIR not in sys.path:
        sys.path.insert(0, _THIS_DIR)
    import external_drivers  # type: ignore
    import federation_registry  # type: ignore


DEFAULT_API_BASE_URL = "https://api.telegram.org"
DEFAULT_JOB_TIMEOUT_SEC = 300.0
DEFAULT_POLL_TIMEOUT_SEC = 25
DEFAULT_CONTEXT_TURNS = 8
DEFAULT_COMMAND_ALIASES = ("ask", "f01")
DEFAULT_MULTI_BOT_COMMAND_ALIASES = ("ask",)
DEFAULT_UNIFIED_RELOAD_SENTINEL = "/tmp/agy_fed_tg_reload"
DEFAULT_JOB_POLL_INTERVAL_SEC = 0.35
DEFAULT_TYPING_REFRESH_SEC = 4.5
DEFAULT_BACKOFF_BASE_SEC = 0.5
DEFAULT_BACKOFF_MAX_SEC = 10.0
MAX_TELEGRAM_CHUNK_LEN = 4000
MAX_HTTP_ERROR_BODY_BYTES = 65536
MAX_CONTEXT_CHARS = 3600
MAX_BOTS_CONFIG_BYTES = 2 * 1024 * 1024

_TG_BOT_URL_TOKEN_RE = re.compile(r"bot\d+(?::|%3[Aa])[A-Za-z0-9_-]{8,}")
_POSITIVE_INT_RE = re.compile(r"^\d+$")
_SIGNED_INT_RE = re.compile(r"^-?\d+$")
_ALIAS_NAME_RE = re.compile(r"^[a-z0-9_]{1,32}$")
_BOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SLASH_CMD_RE = re.compile(r"^/([A-Za-z0-9_]+)(?:@([A-Za-z0-9_]+))?(?:\s+(.*))?$", re.DOTALL)

_MANAGEMENT_COMMANDS = frozenset({"start", "help", "status", "cancel", "clear"})
_BIND_COMMANDS = frozenset({"bindgroup", "unbindgroup"})
_ALLOWED_SECRET_REF_KEYS = frozenset({"token_secret_ref", "secret_ref"})


class TelegramAPIError(RuntimeError):
    """Sanitized Telegram Bot API error (never carries raw bot tokens)."""

    def __init__(self, message: str, *, status_code: int = 0, description: str = "", method: str = ""):
        super().__init__(message)
        self.status_code = int(status_code)
        self.description = str(description or message)
        self.method = str(method or "")


class TargetAgentUnavailableError(RuntimeError):
    """Raised fail-closed when the target federation agent is missing, disabled, revoked, or incompatible."""


class InstanceLockError(RuntimeError):
    """Raised fail-closed when another instance already holds `bridge.lock` or `supervisor.lock`."""


# ---------------------------------------------------------------------------
# Process-Wide Thread-Safe Secret Scrubbing Registry (F1, M2)
# ---------------------------------------------------------------------------
class SecretRedactionRegistry:
    """Thread-safe registry holding all loaded bot tokens (raw + URL-encoded forms)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tokens: Set[str] = set()

    @staticmethod
    def expand_variants(token: Any) -> Tuple[str, ...]:
        raw = str(token or "").strip()
        if not raw:
            return ()
        variants: List[str] = [raw]
        quoted = urllib.parse.quote(raw, safe="")
        if quoted and quoted not in variants:
            variants.append(quoted)
        quoted_plus = urllib.parse.quote_plus(raw)
        if quoted_plus and quoted_plus not in variants:
            variants.append(quoted_plus)
        quoted_lower = re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), quoted)
        if quoted_lower and quoted_lower not in variants:
            variants.append(quoted_lower)
        return tuple(variants)

    def register(self, token: Any) -> None:
        variants = self.expand_variants(token)
        if not variants:
            return
        with self._lock:
            self._tokens.update(variants)

    def register_many(self, tokens: Sequence[Any]) -> None:
        to_add: List[str] = []
        for tok in tokens:
            to_add.extend(self.expand_variants(tok))
        if not to_add:
            return
        with self._lock:
            self._tokens.update(to_add)

    def snapshot(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._tokens, key=len, reverse=True))

    def clear(self) -> None:
        with self._lock:
            self._tokens.clear()


_GLOBAL_SECRET_REGISTRY = SecretRedactionRegistry()


def register_redacted_token(token: str) -> None:
    """Register a bot token (raw + URL-encoded) in the process-wide redaction registry."""
    _GLOBAL_SECRET_REGISTRY.register(token)


def register_redacted_tokens(tokens: Sequence[str]) -> None:
    """Register multiple bot tokens in the process-wide redaction registry."""
    _GLOBAL_SECRET_REGISTRY.register_many(tokens)


def get_registered_redacted_tokens() -> Tuple[str, ...]:
    """Return an immutable snapshot of all registered redaction token variants."""
    return _GLOBAL_SECRET_REGISTRY.snapshot()


def clear_registered_redacted_tokens() -> None:
    """Clear the process-wide redaction registry (intended for isolated test cleanup)."""
    _GLOBAL_SECRET_REGISTRY.clear()


def scrub_secrets(
    text: Any,
    *,
    bot_token: str = "",
    extra_secrets: Sequence[str] = (),
    include_registry: bool = True,
) -> str:
    """Scrub bot tokens (all registered + explicit, raw + URL-encoded), Telegram URLs, and generic secrets."""
    secret_set: Set[str] = set()
    if bot_token:
        secret_set.update(SecretRedactionRegistry.expand_variants(bot_token))
    for item in extra_secrets:
        if item:
            secret_set.update(SecretRedactionRegistry.expand_variants(item))
    if include_registry:
        secret_set.update(_GLOBAL_SECRET_REGISTRY.snapshot())
    secrets_list = sorted(secret_set, key=len, reverse=True)
    out = federation_registry.redact_secrets(str(text or ""), extra_secrets=secrets_list)
    out = _TG_BOT_URL_TOKEN_RE.sub("bot[REDACTED]", out)
    return out


def scrub_metadata(
    obj: Any,
    *,
    bot_token: str = "",
    extra_secrets: Sequence[str] = (),
    _depth: int = 0,
) -> Any:
    """Recursively scrub secret patterns from metadata dicts/lists before queuing."""
    if _depth > 10:
        return "[TRUNCATED]"
    if obj is None or isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, str):
        return scrub_secrets(obj, bot_token=bot_token, extra_secrets=extra_secrets)
    if isinstance(obj, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in obj.items():
            key_str = str(k)
            key_norm = key_str.strip().lower().replace("-", "_")
            if key_norm in federation_registry.FORBIDDEN_SECRET_KEYS or key_str.strip().lower() in federation_registry.FORBIDDEN_SECRET_KEYS:
                continue
            safe_key = scrub_secrets(key_str, bot_token=bot_token, extra_secrets=extra_secrets)
            cleaned[safe_key] = scrub_metadata(
                v,
                bot_token=bot_token,
                extra_secrets=extra_secrets,
                _depth=_depth + 1,
            )
        return cleaned
    if isinstance(obj, (list, tuple)):
        return [
            scrub_metadata(
                item,
                bot_token=bot_token,
                extra_secrets=extra_secrets,
                _depth=_depth + 1,
            )
            for item in obj
        ]
    return scrub_secrets(str(obj), bot_token=bot_token, extra_secrets=extra_secrets)


class RedactingLogFilter(logging.Filter):
    """Thread-safe logging filter guaranteeing zero cross-bot token / secret leakage."""

    def __init__(
        self,
        bot_token: str = "",
        *,
        bot_tokens: Sequence[str] = (),
        registry: Optional[SecretRedactionRegistry] = None,
    ):
        super().__init__()
        self._lock = threading.RLock()
        self._local_tokens: Set[str] = set()
        self._registry = registry if registry is not None else _GLOBAL_SECRET_REGISTRY
        if bot_token:
            self.add_bot_token(bot_token)
        if bot_tokens:
            self.add_bot_tokens(bot_tokens)

    def set_bot_token(self, token: str) -> None:
        self.add_bot_token(token)

    def add_bot_token(self, token: str) -> None:
        variants = SecretRedactionRegistry.expand_variants(token)
        if not variants:
            return
        with self._lock:
            self._local_tokens.update(variants)
        self._registry.register(token)

    def add_bot_tokens(self, tokens: Sequence[str]) -> None:
        for tok in tokens:
            self.add_bot_token(tok)

    def _all_tokens(self) -> Tuple[str, ...]:
        with self._lock:
            combined = set(self._local_tokens)
        combined.update(self._registry.snapshot())
        return tuple(sorted(combined, key=len, reverse=True))

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            extra = self._all_tokens()
            rendered = record.getMessage()
            record.msg = scrub_secrets(rendered, extra_secrets=extra, include_registry=False)
            record.args = ()
            if record.exc_info:
                try:
                    formatted_exc = "".join(traceback.format_exception(*record.exc_info))
                    record.exc_text = scrub_secrets(formatted_exc, extra_secrets=extra, include_registry=False)
                except Exception:
                    record.exc_text = "[EXCEPTION_REDACTED]"
                record.exc_info = None
            elif record.exc_text:
                record.exc_text = scrub_secrets(record.exc_text, extra_secrets=extra, include_registry=False)
            if record.stack_info:
                record.stack_info = scrub_secrets(record.stack_info, extra_secrets=extra, include_registry=False)
        except Exception:
            record.msg = "[LOG_REDACTION_ERROR]"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True


# ---------------------------------------------------------------------------
# Strict Environment Configuration (F1, F2, F5)
# ---------------------------------------------------------------------------
def _parse_int_set(raw: Optional[str], *, var_name: str, positive_only: bool = False, required: bool = False) -> FrozenSet[int]:
    val = str(raw or "").strip()
    if not val:
        if required:
            raise ValueError(f"{var_name} is required and must contain at least one integer ID")
        return frozenset()
    pattern = _POSITIVE_INT_RE if positive_only else _SIGNED_INT_RE
    parsed: Set[int] = set()
    for part in val.split(","):
        tok = part.strip()
        if not tok:
            raise ValueError(f"{var_name} contains an empty entry in {val!r}")
        if not pattern.fullmatch(tok):
            raise ValueError(f"{var_name} contains invalid integer value: {tok!r}")
        num = int(tok)
        if positive_only and num <= 0:
            raise ValueError(f"{var_name} must contain positive integer IDs, got {num}")
        parsed.add(num)
    if required and not parsed:
        raise ValueError(f"{var_name} must contain at least one integer ID")
    return frozenset(parsed)


def _parse_command_aliases(raw: Optional[str]) -> FrozenSet[str]:
    text = str(raw if raw is not None else ",".join(DEFAULT_COMMAND_ALIASES)).strip()
    aliases: Set[str] = {"ask"}
    if not text:
        return frozenset(aliases)
    for part in text.split(","):
        tok = part.strip().lstrip("/").lower()
        if not tok:
            continue
        if not _ALIAS_NAME_RE.fullmatch(tok):
            raise ValueError(f"Invalid command alias in AGY_FED_TG_COMMAND_ALIASES: {tok!r}")
        if tok in _MANAGEMENT_COMMANDS or tok in _BIND_COMMANDS:
            continue
        aliases.add(tok)
    return frozenset(aliases)


def _parse_positive_float(raw: Optional[str], default: float, *, var_name: str) -> float:
    text = str(raw if raw is not None else "").strip()
    if not text:
        return float(default)
    try:
        val = float(text)
    except ValueError as exc:
        raise ValueError(f"{var_name} must be a positive number, got {text!r}") from exc
    if val <= 0:
        raise ValueError(f"{var_name} must be > 0, got {val}")
    return val


def _parse_nonneg_int(raw: Optional[str], default: int, *, var_name: str, minimum: int = 0) -> int:
    text = str(raw if raw is not None else "").strip()
    if not text:
        return int(default)
    if not _SIGNED_INT_RE.fullmatch(text):
        raise ValueError(f"{var_name} must be an integer, got {text!r}")
    val = int(text)
    if val < minimum:
        raise ValueError(f"{var_name} must be >= {minimum}, got {val}")
    return val


def resolve_bot_token(
    env: Mapping[str, str],
    *,
    secret_resolver: Optional[Callable[[str], str]] = None,
) -> str:
    """Resolve Telegram bot token with fail-closed OpenBao secret_ref precedence (F1).

    If `AGY_FED_TG_TOKEN_SECRET_REF` is non-empty:
    - Validates it via `federation_registry.validate_secret_ref`.
    - Resolves ephemerally via `external_drivers.resolve_secret_ref`.
    - Fails closed on any validation error, resolver failure, or empty result
      (NEVER silently falls back to `AGY_FED_TG_BOT_TOKEN`).
    Only when `AGY_FED_TG_TOKEN_SECRET_REF` is unset/empty is `AGY_FED_TG_BOT_TOKEN` used.
    """
    raw_ref = str(env.get("AGY_FED_TG_TOKEN_SECRET_REF") or "").strip()
    if raw_ref:
        clean_ref = federation_registry.validate_secret_ref(raw_ref)
        try:
            resolved = external_drivers.resolve_secret_ref(clean_ref, secret_resolver=secret_resolver)
        except Exception as exc:
            safe_err = scrub_secrets(str(exc))
            raise RuntimeError(f"SECRET_REF_RESOLUTION_FAILED: {safe_err}") from None
        token = str(resolved or "").strip()
        if not token:
            raise RuntimeError(
                f"SECRET_REF_EMPTY: secret_ref {clean_ref!r} resolved to an empty value"
            )
        if any(ch in token for ch in ("\r", "\n", "\x00", " ")):
            raise ValueError("Resolved bot token contains invalid whitespace or control characters")
        return token

    fallback = str(env.get("AGY_FED_TG_BOT_TOKEN") or "").strip()
    if not fallback:
        raise ValueError(
            "Missing bot token: configure AGY_FED_TG_TOKEN_SECRET_REF (recommended) or AGY_FED_TG_BOT_TOKEN"
        )
    if any(ch in fallback for ch in ("\r", "\n", "\x00", " ")):
        raise ValueError("AGY_FED_TG_BOT_TOKEN contains invalid whitespace or control characters")
    return fallback


@dataclasses.dataclass(frozen=True)
class BridgeConfig:
    """Validated runtime configuration for `FederationTelegramBridge`."""

    agent_id: str
    bot_token: str = dataclasses.field(repr=False)
    owner_users: FrozenSet[int]
    allowed_chats: FrozenSet[int] = frozenset()
    denied_chats: FrozenSet[int] = frozenset()
    state_dir: str = ""
    reload_sentinel: str = ""
    bus_dir: Optional[str] = None
    job_timeout_sec: float = DEFAULT_JOB_TIMEOUT_SEC
    poll_timeout_sec: int = DEFAULT_POLL_TIMEOUT_SEC
    context_turns: int = DEFAULT_CONTEXT_TURNS
    command_aliases: FrozenSet[str] = frozenset(DEFAULT_COMMAND_ALIASES)
    job_poll_interval_sec: float = DEFAULT_JOB_POLL_INTERVAL_SEC
    typing_refresh_sec: float = DEFAULT_TYPING_REFRESH_SEC
    api_base_url: str = DEFAULT_API_BASE_URL
    bot_name: str = ""


@dataclasses.dataclass(frozen=True)
class MultiBotConfig:
    """Validated single-process multi-bot configuration loaded from `AGY_FED_TG_BOTS_CONFIG` (M1)."""

    config_path: str
    state_root_dir: str
    reload_sentinel: str
    bots: Tuple[BridgeConfig, ...]


def load_config(
    env: Optional[Mapping[str, str]] = None,
    *,
    secret_resolver: Optional[Callable[[str], str]] = None,
) -> BridgeConfig:
    """Load and strictly validate all `AGY_FED_TG_*` environment settings (fail-closed)."""
    src = os.environ if env is None else env
    raw_agent_id = str(src.get("AGY_FED_TG_AGENT_ID") or "").strip()
    agent_id = federation_registry.validate_agent_id(raw_agent_id)

    owner_users = _parse_int_set(
        src.get("AGY_FED_TG_OWNER_USERS"),
        var_name="AGY_FED_TG_OWNER_USERS",
        positive_only=True,
        required=True,
    )
    allowed_chats = _parse_int_set(
        src.get("AGY_FED_TG_ALLOWED_CHATS"),
        var_name="AGY_FED_TG_ALLOWED_CHATS",
        positive_only=False,
        required=False,
    )
    denied_chats = _parse_int_set(
        src.get("AGY_FED_TG_DENIED_CHATS"),
        var_name="AGY_FED_TG_DENIED_CHATS",
        positive_only=False,
        required=False,
    )

    bot_token = resolve_bot_token(src, secret_resolver=secret_resolver)
    register_redacted_token(bot_token)

    raw_state_dir = str(src.get("AGY_FED_TG_STATE_DIR") or "").strip()
    if raw_state_dir:
        state_dir = os.path.abspath(os.path.expanduser(raw_state_dir))
    else:
        state_dir = os.path.abspath(
            os.path.join(os.path.expanduser("~"), ".config", "agy-tg-bridge", "fed_tg", agent_id)
        )

    raw_sentinel = str(
        src.get("AGY_FED_TG_RELOAD_SENTINEL") or src.get("AGY_FED_TG_RELOAD_FLAG") or ""
    ).strip()
    reload_sentinel = raw_sentinel or f"/tmp/agy_fed_tg_{agent_id}_reload"

    raw_bus_dir = str(src.get("AGY_FED_TG_BUS_DIR") or src.get("AGY_BOT_BUS_DIR") or "").strip()
    bus_dir = os.path.abspath(os.path.expanduser(raw_bus_dir)) if raw_bus_dir else None

    job_timeout_sec = _parse_positive_float(
        src.get("AGY_FED_TG_JOB_TIMEOUT_SEC"),
        DEFAULT_JOB_TIMEOUT_SEC,
        var_name="AGY_FED_TG_JOB_TIMEOUT_SEC",
    )
    poll_timeout_sec = _parse_nonneg_int(
        src.get("AGY_FED_TG_POLL_TIMEOUT_SEC"),
        DEFAULT_POLL_TIMEOUT_SEC,
        var_name="AGY_FED_TG_POLL_TIMEOUT_SEC",
        minimum=1,
    )
    context_turns = _parse_nonneg_int(
        src.get("AGY_FED_TG_CONTEXT_TURNS"),
        DEFAULT_CONTEXT_TURNS,
        var_name="AGY_FED_TG_CONTEXT_TURNS",
        minimum=0,
    )
    command_aliases = _parse_command_aliases(src.get("AGY_FED_TG_COMMAND_ALIASES"))
    job_poll_interval_sec = _parse_positive_float(
        src.get("AGY_FED_TG_JOB_POLL_INTERVAL_SEC"),
        DEFAULT_JOB_POLL_INTERVAL_SEC,
        var_name="AGY_FED_TG_JOB_POLL_INTERVAL_SEC",
    )
    typing_refresh_sec = _parse_positive_float(
        src.get("AGY_FED_TG_TYPING_REFRESH_SEC"),
        DEFAULT_TYPING_REFRESH_SEC,
        var_name="AGY_FED_TG_TYPING_REFRESH_SEC",
    )
    api_base_url = str(src.get("AGY_FED_TG_API_BASE_URL") or DEFAULT_API_BASE_URL).strip().rstrip("/")

    return BridgeConfig(
        agent_id=agent_id,
        bot_token=bot_token,
        owner_users=owner_users,
        allowed_chats=allowed_chats,
        denied_chats=denied_chats,
        state_dir=state_dir,
        reload_sentinel=reload_sentinel,
        bus_dir=bus_dir,
        job_timeout_sec=job_timeout_sec,
        poll_timeout_sec=poll_timeout_sec,
        context_turns=context_turns,
        command_aliases=command_aliases,
        job_poll_interval_sec=job_poll_interval_sec,
        typing_refresh_sec=typing_refresh_sec,
        api_base_url=api_base_url or DEFAULT_API_BASE_URL,
        bot_name=agent_id,
    )


# ---------------------------------------------------------------------------
# Strict Multi-Bot Config File Loader (M1)
# ---------------------------------------------------------------------------
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _read_secure_config_text(config_path: str) -> Tuple[str, str]:
    """Open `fed_bots.json` with `O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC` and validate `fstat` (M1)."""
    raw = str(config_path or "").strip()
    if not raw:
        raise ValueError("AGY_FED_TG_BOTS_CONFIG path must be non-empty")
    abs_path = os.path.abspath(os.path.expanduser(raw))
    _assert_not_symlink(abs_path)
    try:
        fd = os.open(abs_path, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PermissionError(
                f"SYMLINK_REJECTED: O_NOFOLLOW blocked symlink {os.path.basename(abs_path)!r}"
            ) from None
        if exc.errno == errno.EISDIR:
            raise PermissionError(
                f"UNSAFE_CONFIG_FILE: {os.path.basename(abs_path)!r} is a directory"
            ) from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(
                f"UNSAFE_CONFIG_FILE: {os.path.basename(abs_path)!r} is not a regular file"
            )
        mode = stat.S_IMODE(st.st_mode)
        if (mode & 0o077) != 0:
            raise PermissionError(
                f"UNSAFE_CONFIG_PERMISSIONS: {os.path.basename(abs_path)!r} has mode {oct(mode)}; "
                "expected 0600 or stricter (mode & 0o077 == 0)"
            )
        if st.st_size > MAX_BOTS_CONFIG_BYTES:
            raise ValueError(f"Config file exceeds maximum size ({MAX_BOTS_CONFIG_BYTES} bytes)")
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    with os.fdopen(fd, "r", encoding="utf-8") as fh:
        return abs_path, fh.read()


def _reject_forbidden_secret_keys(obj: Any, *, path_prefix: str = "$") -> None:
    """Recursively fail-closed if any JSON object key is a forbidden plaintext secret field (M1)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_str = str(k)
            key_low = key_str.strip().lower()
            key_norm = key_low.replace("-", "_")
            if key_norm not in _ALLOWED_SECRET_REF_KEYS:
                if (
                    key_norm in federation_registry.FORBIDDEN_SECRET_KEYS
                    or key_low in federation_registry.FORBIDDEN_SECRET_KEYS
                    or key_norm.endswith(("_token", "_secret", "_password", "_api_key", "_apikey"))
                ):
                    raise ValueError(
                        f"FORBIDDEN_SECRET_KEY: plaintext secret field {key_str!r} at {path_prefix} "
                        "is forbidden in bots config; use token_secret_ref"
                    )
            _reject_forbidden_secret_keys(v, path_prefix=f"{path_prefix}.{key_str}")
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _reject_forbidden_secret_keys(item, path_prefix=f"{path_prefix}[{idx}]")


def _parse_strict_json_int_list(
    raw: Any,
    *,
    field_name: str,
    positive_only: bool = False,
) -> FrozenSet[int]:
    if not isinstance(raw, list):
        raise ValueError(f"{field_name} must be a JSON list of integers")
    parsed: Set[int] = set()
    for item in raw:
        if type(item) is not int:
            raise ValueError(
                f"{field_name} must contain only integers (got {type(item).__name__})"
            )
        if positive_only and item <= 0:
            raise ValueError(f"{field_name} must contain only positive integers (got {item})")
        parsed.add(item)
    return frozenset(parsed)


def _parse_strict_json_aliases(raw: Any, *, field_name: str) -> FrozenSet[str]:
    if not isinstance(raw, list):
        raise ValueError(f"{field_name} must be a JSON list of command alias strings")
    aliases: Set[str] = {"ask"}
    for item in raw:
        if not isinstance(item, str):
            raise ValueError(f"{field_name} must contain only strings (got {type(item).__name__})")
        tok = item.strip().lstrip("/").lower()
        if not tok:
            raise ValueError(f"{field_name} contains an empty command alias")
        if not _ALIAS_NAME_RE.fullmatch(tok):
            raise ValueError(f"Invalid command alias in {field_name}: {tok!r}")
        if tok in _MANAGEMENT_COMMANDS or tok in _BIND_COMMANDS:
            continue
        aliases.add(tok)
    return frozenset(aliases)


def _parse_strict_json_positive_float(raw: Any, default: float, *, field_name: str) -> float:
    if raw is None:
        return float(default)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise ValueError(f"{field_name} must be a positive number (got {type(raw).__name__})")
    val = float(raw)
    if val <= 0:
        raise ValueError(f"{field_name} must be > 0, got {val}")
    return val


def _parse_strict_json_int(raw: Any, default: int, *, field_name: str, minimum: int = 0) -> int:
    if raw is None:
        return int(default)
    if type(raw) is not int:
        raise ValueError(f"{field_name} must be an integer (got {type(raw).__name__})")
    if raw < minimum:
        raise ValueError(f"{field_name} must be >= {minimum}, got {raw}")
    return raw


def _resolve_required_secret_ref(
    raw_ref: Any,
    *,
    field_name: str,
    secret_resolver: Optional[Callable[[str], str]] = None,
) -> str:
    """Strictly validate and resolve an OpenBao `token_secret_ref` (zero env plaintext fallback)."""
    if not isinstance(raw_ref, str) or not raw_ref.strip():
        raise ValueError(
            f"{field_name} is required in multi-bot config mode (env plaintext token fallback is forbidden)"
        )
    clean_ref = federation_registry.validate_secret_ref(raw_ref.strip())
    try:
        resolved = external_drivers.resolve_secret_ref(clean_ref, secret_resolver=secret_resolver)
    except Exception as exc:
        safe_err = scrub_secrets(str(exc))
        raise RuntimeError(f"SECRET_REF_RESOLUTION_FAILED: {safe_err}") from None
    token = str(resolved or "").strip()
    if not token:
        raise RuntimeError(
            f"SECRET_REF_EMPTY: secret_ref {clean_ref!r} resolved to an empty value"
        )
    if any(ch in token for ch in ("\r", "\n", "\x00", " ")):
        raise ValueError("Resolved bot token contains invalid whitespace or control characters")
    register_redacted_token(token)
    return token


def load_multi_bot_config(
    config_path: Optional[str] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
    secret_resolver: Optional[Callable[[str], str]] = None,
) -> MultiBotConfig:
    """Load and strictly validate single-process multi-bot JSON configuration (`fed_bots.json`, M1)."""
    src = os.environ if env is None else env
    raw_cfg_path = (
        str(config_path).strip()
        if config_path is not None
        else str(src.get("AGY_FED_TG_BOTS_CONFIG") or "").strip()
    )
    abs_cfg_path, raw_text = _read_secure_config_text(raw_cfg_path)

    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"Invalid JSON in bots config: {scrub_secrets(exc)}") from None

    if not isinstance(data, dict):
        raise ValueError("Bots config root must be a JSON object")

    _reject_forbidden_secret_keys(data)

    raw_defaults = data.get("defaults", {})
    if raw_defaults is None:
        raw_defaults = {}
    if not isinstance(raw_defaults, dict):
        raise ValueError("defaults must be a JSON object")

    env_denied_chats = _parse_int_set(
        src.get("AGY_FED_TG_DENIED_CHATS"),
        var_name="AGY_FED_TG_DENIED_CHATS",
        positive_only=False,
        required=False,
    )

    if "owner_users" in raw_defaults:
        defaults_owner_users = _parse_strict_json_int_list(
            raw_defaults["owner_users"],
            field_name="defaults.owner_users",
            positive_only=True,
        )
    else:
        defaults_owner_users = _parse_int_set(
            src.get("AGY_FED_TG_OWNER_USERS"),
            var_name="AGY_FED_TG_OWNER_USERS",
            positive_only=True,
            required=False,
        )

    defaults_allowed_chats = (
        _parse_strict_json_int_list(
            raw_defaults["allowed_chats"],
            field_name="defaults.allowed_chats",
            positive_only=False,
        )
        if "allowed_chats" in raw_defaults
        else frozenset()
    )
    defaults_denied_chats = (
        _parse_strict_json_int_list(
            raw_defaults["denied_chats"],
            field_name="defaults.denied_chats",
            positive_only=False,
        )
        if "denied_chats" in raw_defaults
        else frozenset()
    )

    defaults_job_timeout = _parse_strict_json_positive_float(
        raw_defaults.get("job_timeout_sec"),
        DEFAULT_JOB_TIMEOUT_SEC,
        field_name="defaults.job_timeout_sec",
    )
    defaults_poll_timeout = _parse_strict_json_int(
        raw_defaults.get("poll_timeout_sec"),
        DEFAULT_POLL_TIMEOUT_SEC,
        field_name="defaults.poll_timeout_sec",
        minimum=1,
    )
    defaults_context_turns = _parse_strict_json_int(
        raw_defaults.get("context_turns"),
        DEFAULT_CONTEXT_TURNS,
        field_name="defaults.context_turns",
        minimum=0,
    )
    defaults_job_poll_interval = _parse_strict_json_positive_float(
        raw_defaults.get("job_poll_interval_sec"),
        DEFAULT_JOB_POLL_INTERVAL_SEC,
        field_name="defaults.job_poll_interval_sec",
    )
    defaults_typing_refresh = _parse_strict_json_positive_float(
        raw_defaults.get("typing_refresh_sec"),
        DEFAULT_TYPING_REFRESH_SEC,
        field_name="defaults.typing_refresh_sec",
    )
    defaults_aliases = (
        _parse_strict_json_aliases(
            raw_defaults["command_aliases"],
            field_name="defaults.command_aliases",
        )
        if "command_aliases" in raw_defaults
        else frozenset(DEFAULT_MULTI_BOT_COMMAND_ALIASES)
    )

    raw_state_root = raw_defaults.get("state_root_dir")
    if raw_state_root is not None:
        if not isinstance(raw_state_root, str) or not raw_state_root.strip():
            raise ValueError("defaults.state_root_dir must be a non-empty string")
        state_root_dir = os.path.abspath(os.path.expanduser(raw_state_root.strip()))
    else:
        env_state_root = str(src.get("AGY_FED_TG_STATE_ROOT_DIR") or "").strip()
        if env_state_root:
            state_root_dir = os.path.abspath(os.path.expanduser(env_state_root))
        else:
            state_root_dir = os.path.abspath(
                os.path.join(os.path.expanduser("~"), ".config", "agy-tg-bridge", "fed_tg")
            )

    raw_defaults_bus = raw_defaults.get("bus_dir")
    if raw_defaults_bus is not None and not isinstance(raw_defaults_bus, str):
        raise ValueError("defaults.bus_dir must be a string")
    raw_bus_dir = str(
        raw_defaults_bus
        if (isinstance(raw_defaults_bus, str) and raw_defaults_bus.strip())
        else (src.get("AGY_FED_TG_BUS_DIR") or src.get("AGY_BOT_BUS_DIR") or "")
    ).strip()
    defaults_bus_dir = os.path.abspath(os.path.expanduser(raw_bus_dir)) if raw_bus_dir else None

    raw_defaults_api = raw_defaults.get("api_base_url")
    if raw_defaults_api is not None and not isinstance(raw_defaults_api, str):
        raise ValueError("defaults.api_base_url must be a string")
    defaults_api_base = (
        str(raw_defaults_api or src.get("AGY_FED_TG_API_BASE_URL") or DEFAULT_API_BASE_URL)
        .strip()
        .rstrip("/")
        or DEFAULT_API_BASE_URL
    )

    raw_defaults_sentinel = raw_defaults.get("reload_sentinel")
    if raw_defaults_sentinel is not None and not isinstance(raw_defaults_sentinel, str):
        raise ValueError("defaults.reload_sentinel must be a string")
    reload_sentinel = (
        str(
            src.get("AGY_FED_TG_RELOAD_FLAG")
            or src.get("AGY_FED_TG_RELOAD_SENTINEL")
            or raw_defaults_sentinel
            or DEFAULT_UNIFIED_RELOAD_SENTINEL
        ).strip()
        or DEFAULT_UNIFIED_RELOAD_SENTINEL
    )

    raw_bots = data.get("bots")
    if not isinstance(raw_bots, list) or not raw_bots:
        raise ValueError("bots must be a non-empty JSON list")

    # Pass 1: Strict schema, merge, and static uniqueness validation (fail-closed before resolving secrets)
    seen_names: Set[str] = set()
    seen_agent_ids: Set[str] = set()
    seen_secret_refs: Set[str] = set()
    seen_state_dirs: Set[str] = set()
    norm_root = os.path.normpath(state_root_dir)
    staged_specs: List[Dict[str, Any]] = []

    for idx, entry in enumerate(raw_bots):
        if not isinstance(entry, dict):
            raise ValueError(f"bots[{idx}] must be a JSON object")

        enabled = entry.get("enabled", True)
        if type(enabled) is not bool:
            raise ValueError(f"bots[{idx}].enabled must be a boolean")

        raw_name = entry.get("name")
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError(f"bots[{idx}].name must be a non-empty string")
        bot_name = raw_name.strip()
        if not _BOT_NAME_RE.fullmatch(bot_name):
            raise ValueError(f"bots[{idx}].name has invalid format: {bot_name!r}")
        norm_name = bot_name.lower()
        if norm_name in seen_names:
            raise ValueError(f"DUPLICATE_BOT_NAME: duplicate bot name {bot_name!r} (case-insensitive)")
        seen_names.add(norm_name)

        agent_id = federation_registry.validate_agent_id(entry.get("agent_id"))
        if agent_id in seen_agent_ids:
            raise ValueError(f"DUPLICATE_AGENT_ID: duplicate agent_id {agent_id!r}")
        seen_agent_ids.add(agent_id)

        if not enabled:
            if "token_secret_ref" in entry and entry["token_secret_ref"] is not None:
                if not isinstance(entry["token_secret_ref"], str) or not entry["token_secret_ref"].strip():
                    raise ValueError(f"bots[{idx}].token_secret_ref must be a non-empty string")
                federation_registry.validate_secret_ref(entry["token_secret_ref"].strip())
            continue

        raw_ref = entry.get("token_secret_ref")
        if not isinstance(raw_ref, str) or not raw_ref.strip():
            raise ValueError(
                f"bots[{idx}] ({bot_name}) is missing required token_secret_ref "
                "(env plaintext token fallback is forbidden)"
            )
        clean_ref = federation_registry.validate_secret_ref(raw_ref.strip())
        if clean_ref in seen_secret_refs:
            raise ValueError(f"DUPLICATE_SECRET_REF: duplicate token_secret_ref {clean_ref!r}")
        seen_secret_refs.add(clean_ref)

        if "state_dir" in entry and entry["state_dir"] is not None:
            if not isinstance(entry["state_dir"], str) or not entry["state_dir"].strip():
                raise ValueError(f"bots[{idx}].state_dir must be a non-empty string")
            bot_state_dir = os.path.abspath(os.path.expanduser(entry["state_dir"].strip()))
        else:
            bot_state_dir = os.path.abspath(os.path.join(state_root_dir, agent_id))
        norm_state_dir = os.path.normpath(bot_state_dir)
        if norm_state_dir == norm_root:
            raise ValueError(f"bots[{idx}].state_dir cannot equal state_root_dir")
        if norm_state_dir in seen_state_dirs:
            raise ValueError(f"DUPLICATE_STATE_DIR: duplicate state_dir {bot_state_dir!r}")
        seen_state_dirs.add(norm_state_dir)

        if "owner_users" in entry:
            effective_owners = _parse_strict_json_int_list(
                entry["owner_users"],
                field_name=f"bots[{idx}].owner_users",
                positive_only=True,
            )
        else:
            effective_owners = defaults_owner_users
        if not effective_owners:
            raise ValueError(
                f"bots[{idx}] ({bot_name}) has empty effective owner_users; "
                "at least one positive integer owner ID is required"
            )

        bot_allowed = (
            _parse_strict_json_int_list(
                entry["allowed_chats"],
                field_name=f"bots[{idx}].allowed_chats",
                positive_only=False,
            )
            if "allowed_chats" in entry
            else frozenset()
        )
        effective_allowed = defaults_allowed_chats | bot_allowed

        bot_denied = (
            _parse_strict_json_int_list(
                entry["denied_chats"],
                field_name=f"bots[{idx}].denied_chats",
                positive_only=False,
            )
            if "denied_chats" in entry
            else frozenset()
        )
        # Non-downgrading mandatory union (M1)
        effective_denied = defaults_denied_chats | bot_denied | env_denied_chats

        bot_aliases = (
            _parse_strict_json_aliases(
                entry["command_aliases"],
                field_name=f"bots[{idx}].command_aliases",
            )
            if "command_aliases" in entry
            else defaults_aliases
        )

        bot_job_timeout = _parse_strict_json_positive_float(
            entry.get("job_timeout_sec"),
            defaults_job_timeout,
            field_name=f"bots[{idx}].job_timeout_sec",
        )
        bot_poll_timeout = _parse_strict_json_int(
            entry.get("poll_timeout_sec"),
            defaults_poll_timeout,
            field_name=f"bots[{idx}].poll_timeout_sec",
            minimum=1,
        )
        bot_context_turns = _parse_strict_json_int(
            entry.get("context_turns"),
            defaults_context_turns,
            field_name=f"bots[{idx}].context_turns",
            minimum=0,
        )
        bot_job_poll_interval = _parse_strict_json_positive_float(
            entry.get("job_poll_interval_sec"),
            defaults_job_poll_interval,
            field_name=f"bots[{idx}].job_poll_interval_sec",
        )
        bot_typing_refresh = _parse_strict_json_positive_float(
            entry.get("typing_refresh_sec"),
            defaults_typing_refresh,
            field_name=f"bots[{idx}].typing_refresh_sec",
        )

        raw_bot_bus = entry.get("bus_dir")
        if raw_bot_bus is not None and not isinstance(raw_bot_bus, str):
            raise ValueError(f"bots[{idx}].bus_dir must be a string")
        bot_bus_dir = (
            os.path.abspath(os.path.expanduser(raw_bot_bus.strip()))
            if isinstance(raw_bot_bus, str) and raw_bot_bus.strip()
            else defaults_bus_dir
        )

        raw_bot_api = entry.get("api_base_url")
        if raw_bot_api is not None and not isinstance(raw_bot_api, str):
            raise ValueError(f"bots[{idx}].api_base_url must be a string")
        bot_api_base = (
            str(raw_bot_api).strip().rstrip("/")
            if isinstance(raw_bot_api, str) and raw_bot_api.strip()
            else defaults_api_base
        )

        staged_specs.append(
            {
                "idx": idx,
                "bot_name": bot_name,
                "agent_id": agent_id,
                "secret_ref": clean_ref,
                "owner_users": effective_owners,
                "allowed_chats": effective_allowed,
                "denied_chats": effective_denied,
                "state_dir": bot_state_dir,
                "bus_dir": bot_bus_dir,
                "job_timeout_sec": bot_job_timeout,
                "poll_timeout_sec": bot_poll_timeout,
                "context_turns": bot_context_turns,
                "command_aliases": bot_aliases,
                "job_poll_interval_sec": bot_job_poll_interval,
                "typing_refresh_sec": bot_typing_refresh,
                "api_base_url": bot_api_base,
            }
        )

    if not staged_specs:
        raise ValueError("bots config must contain at least one enabled bot")

    # Pass 2: Resolve all token_secret_refs ephemerally & register into process-wide redaction registry
    resolved_tokens_seen: Set[str] = set()
    bot_configs: List[BridgeConfig] = []
    for spec in staged_specs:
        tok = _resolve_required_secret_ref(
            spec["secret_ref"],
            field_name=f"bots[{spec['idx']}].token_secret_ref",
            secret_resolver=secret_resolver,
        )
        if tok in resolved_tokens_seen:
            raise ValueError("DUPLICATE_BOT_TOKEN: multiple enabled bots resolved to the same bot token")
        resolved_tokens_seen.add(tok)
        bot_configs.append(
            BridgeConfig(
                agent_id=spec["agent_id"],
                bot_token=tok,
                owner_users=spec["owner_users"],
                allowed_chats=spec["allowed_chats"],
                denied_chats=spec["denied_chats"],
                state_dir=spec["state_dir"],
                reload_sentinel="",  # Unified sentinel owned by MultiBotSupervisor
                bus_dir=spec["bus_dir"],
                job_timeout_sec=spec["job_timeout_sec"],
                poll_timeout_sec=spec["poll_timeout_sec"],
                context_turns=spec["context_turns"],
                command_aliases=spec["command_aliases"],
                job_poll_interval_sec=spec["job_poll_interval_sec"],
                typing_refresh_sec=spec["typing_refresh_sec"],
                api_base_url=spec["api_base_url"],
                bot_name=spec["bot_name"],
            )
        )

    return MultiBotConfig(
        config_path=abs_cfg_path,
        state_root_dir=state_root_dir,
        reload_sentinel=reload_sentinel,
        bots=tuple(bot_configs),
    )


# ---------------------------------------------------------------------------
# Hardened State Storage, Symlink Guard & Exclusive Instance Lock (F4, F6, F7, M3)
# ---------------------------------------------------------------------------


def _assert_not_symlink(path: str) -> None:
    if os.path.lexists(path) and os.path.islink(path):
        raise PermissionError(f"SYMLINK_REJECTED: refusing to access symlink {os.path.basename(path)!r}")


def _ensure_secure_dir(path: str) -> None:
    _assert_not_symlink(path)
    if not os.path.exists(path):
        os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise PermissionError(f"SYMLINK_REJECTED: state directory {os.path.basename(path)!r} is not a real directory")
    os.chmod(path, 0o700)


def _open_regular_nofollow(path: str, flags: int, mode: int = 0o600) -> int:
    _assert_not_symlink(path)
    try:
        fd = os.open(path, flags | _O_NOFOLLOW | _O_CLOEXEC, mode)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PermissionError(
                f"SYMLINK_REJECTED: O_NOFOLLOW blocked symlink {os.path.basename(path)!r}"
            ) from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"UNSAFE_STATE_FILE: {os.path.basename(path)!r} is not a regular file")
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return fd


class InstanceLock:
    """Exclusive non-blocking process lock (`bridge.lock` or `supervisor.lock`, F4, F6, M3)."""

    def __init__(self, state_dir: str, *, lock_filename: str = "bridge.lock"):
        self.state_dir = state_dir
        self.lock_filename = str(lock_filename or "bridge.lock")
        self.lock_path = os.path.join(state_dir, self.lock_filename)
        self._fd: Optional[int] = None

    @property
    def fd(self) -> Optional[int]:
        return self._fd

    def acquire(self) -> None:
        if self._fd is not None:
            return
        _ensure_secure_dir(self.state_dir)
        fd = _open_regular_nofollow(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            # Explicitly enforce FD_CLOEXEC so execv never leaks lock descriptors (M3)
            cur_fd_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            fcntl.fcntl(fd, fcntl.F_SETFD, cur_fd_flags | fcntl.FD_CLOEXEC)
            os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as exc:
                if isinstance(exc, BlockingIOError) or exc.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                    raise InstanceLockError(
                        f"INSTANCE_LOCKED: another federation_tg_bridge instance already holds {self.lock_filename}"
                    ) from None
                raise
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, f"{os.getpid()}\n".encode("ascii"))
            self._fd = fd
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def release(self) -> None:
        fd = self._fd
        self._fd = None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            try:
                os.close(fd)
            except OSError:
                pass


class BridgeStateStore:
    """Hardened, symlink-proof, flock-serialized persistence for `bindings.json` and `offset.json`."""

    def __init__(self, state_dir: str, *, denied_chats: FrozenSet[int] = frozenset()):
        self.state_dir = state_dir
        self.denied_chats = frozenset(denied_chats)
        self.bindings_path = os.path.join(state_dir, "bindings.json")
        self.offset_path = os.path.join(state_dir, "offset.json")
        self.state_lock_path = os.path.join(state_dir, "state.lock")
        self._thread_lock = threading.Lock()

    @contextlib.contextmanager
    def _state_lock(self):
        with self._thread_lock:
            _ensure_secure_dir(self.state_dir)
            fd = _open_regular_nofollow(self.state_lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def _read_json_nofollow(self, path: str, default: Any) -> Any:
        _assert_not_symlink(self.state_dir)
        _assert_not_symlink(path)
        if not os.path.lexists(path):
            return default
        fd = _open_regular_nofollow(path, os.O_RDONLY, 0o600)
        try:
            with os.fdopen(fd, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return default

    def _atomic_write_json_nofollow(self, path: str, payload: Any) -> None:
        _ensure_secure_dir(self.state_dir)
        _assert_not_symlink(path)
        tmp_path = f"{path}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
                fh.flush()
                os.fsync(fh.fileno())
            _assert_not_symlink(path)
            os.replace(tmp_path, path)
            vfd = _open_regular_nofollow(path, os.O_RDONLY, 0o600)
            try:
                os.fchmod(vfd, 0o600)
            finally:
                os.close(vfd)
        except Exception:
            try:
                if os.path.lexists(tmp_path) and not os.path.islink(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _sanitize_bound_chats(self, raw_data: Any) -> Set[int]:
        if not isinstance(raw_data, dict):
            return set()
        raw_list = raw_data.get("bound_chats")
        if not isinstance(raw_list, list):
            return set()
        clean: Set[int] = set()
        for item in raw_list:
            # Strictly reject bool (subclass of int), strings, floats, None, and positive IDs
            if type(item) is not int:
                continue
            if item >= 0:
                continue
            if item in self.denied_chats:
                continue
            clean.add(item)
        return clean

    def load_bound_chats(self) -> Set[int]:
        """Load bound group chat IDs fail-closed (symlink raises PermissionError; corrupt JSON -> empty set)."""
        _assert_not_symlink(self.state_dir)
        _assert_not_symlink(self.bindings_path)
        if not os.path.lexists(self.bindings_path):
            return set()
        with self._state_lock():
            data = self._read_json_nofollow(self.bindings_path, None)
            return self._sanitize_bound_chats(data)

    def bind_group(self, chat_id: int) -> bool:
        """Atomically bind a negative group/supergroup chat_id under flock. Returns True if newly added."""
        if type(chat_id) is not int or chat_id >= 0:
            raise ValueError("Only negative group/supergroup chat IDs can be bound")
        if chat_id in self.denied_chats:
            raise PermissionError("DENIED_CHAT: cannot bind a chat in AGY_FED_TG_DENIED_CHATS")
        with self._state_lock():
            data = self._read_json_nofollow(self.bindings_path, None)
            chats = self._sanitize_bound_chats(data)
            added = chat_id not in chats
            chats.add(chat_id)
            payload = {
                "version": 1,
                "bound_chats": sorted(chats),
                "updated_at": time.time(),
            }
            self._atomic_write_json_nofollow(self.bindings_path, payload)
            return added

    def unbind_group(self, chat_id: int) -> bool:
        """Atomically unbind a group chat_id under flock. Returns True if removed."""
        if type(chat_id) is not int or chat_id >= 0:
            raise ValueError("Only negative group/supergroup chat IDs can be unbound")
        if chat_id in self.denied_chats:
            raise PermissionError("DENIED_CHAT: cannot modify bindings for a denied chat")
        with self._state_lock():
            data = self._read_json_nofollow(self.bindings_path, None)
            chats = self._sanitize_bound_chats(data)
            existed = chat_id in chats
            chats.discard(chat_id)
            payload = {
                "version": 1,
                "bound_chats": sorted(chats),
                "updated_at": time.time(),
            }
            self._atomic_write_json_nofollow(self.bindings_path, payload)
            return existed

    def load_offset(self) -> int:
        """Load last processed Telegram `update_id` fail-closed (symlink raises PermissionError)."""
        _assert_not_symlink(self.state_dir)
        _assert_not_symlink(self.offset_path)
        if not os.path.lexists(self.offset_path):
            return 0
        with self._state_lock():
            data = self._read_json_nofollow(self.offset_path, None)
            if not isinstance(data, dict):
                return 0
            val = data.get("last_update_id")
            if type(val) is int and val >= 0:
                return val
            return 0

    def save_offset(self, update_id: int) -> None:
        """Atomically persist monotonic `last_update_id` under flock (`0600`, symlink-proof)."""
        if type(update_id) is not int or update_id < 0:
            raise ValueError(f"Invalid update_id: {update_id!r}")
        with self._state_lock():
            prev = 0
            existing = self._read_json_nofollow(self.offset_path, None)
            if isinstance(existing, dict) and type(existing.get("last_update_id")) is int:
                prev = max(0, existing["last_update_id"])
            final_id = max(prev, update_id)
            payload = {
                "version": 1,
                "last_update_id": final_id,
                "updated_at": time.time(),
            }
            self._atomic_write_json_nofollow(self.offset_path, payload)


# ---------------------------------------------------------------------------
# Telegram Text Chunking (F7)
# ---------------------------------------------------------------------------
def split_text_for_telegram(
    text: str,
    *,
    max_len: int = MAX_TELEGRAM_CHUNK_LEN,
    html_aware: bool = True,
) -> List[str]:
    """Split text into lossless chunks where both raw and HTML-escaped lengths are `<= max_len`.

    Guarantees `"".join(chunks) == text` so zero characters are truncated or dropped.
    """
    cap = max(32, int(max_len))
    src = str(text or "")
    if not src:
        return [""]

    def _fits(piece: str) -> bool:
        if len(piece) > cap:
            return False
        if html_aware and len(html_mod.escape(piece)) > cap:
            return False
        return True

    if _fits(src):
        return [src]

    chunks: List[str] = []
    pos = 0
    n = len(src)
    while pos < n:
        # Upper bound by raw character count
        hi = min(n, pos + cap)
        if not _fits(src[pos:hi]):
            # Binary search largest fitting prefix
            lo = pos + 1
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if _fits(src[pos:mid]):
                    lo = mid
                else:
                    hi = mid - 1
            best_end = lo
        else:
            best_end = hi

        if best_end < n:
            # Prefer clean boundary inside the latter half of the chunk
            window_start = pos + max(1, (best_end - pos) // 2)
            split_at = -1
            for sep in ("\n\n", "\n", " "):
                idx = src.rfind(sep, window_start, best_end)
                if idx != -1:
                    split_at = idx + len(sep)
                    break
            if split_at > pos and _fits(src[pos:split_at]):
                best_end = split_at

        if best_end <= pos:
            best_end = pos + 1
        chunks.append(src[pos:best_end])
        pos = best_end

    return chunks


# ---------------------------------------------------------------------------
# Pure-Stdlib Telegram Bot API Client (F1, F7)
# ---------------------------------------------------------------------------
class TelegramClient:
    """Minimal standard-library Telegram Bot API JSON client with strict token scrubbing."""

    def __init__(
        self,
        bot_token: str,
        *,
        api_base_url: str = DEFAULT_API_BASE_URL,
        urlopen_fn: Optional[Callable[..., Any]] = None,
    ):
        self._bot_token = str(bot_token or "").strip()
        if not self._bot_token:
            raise ValueError("TelegramClient requires a non-empty bot_token")
        register_redacted_token(self._bot_token)
        self.api_base_url = str(api_base_url or DEFAULT_API_BASE_URL).strip().rstrip("/")
        self._urlopen = urlopen_fn or urllib.request.urlopen

    def __repr__(self) -> str:
        return f"<TelegramClient api_base_url={self.api_base_url!r}>"

    def _endpoint(self, method: str) -> str:
        return f"{self.api_base_url}/bot{self._bot_token}/{method}"

    def call(
        self,
        method: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        timeout: float = 30.0,
    ) -> Any:
        url = self._endpoint(method)
        body = json.dumps(payload or {}, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with self._urlopen(req, timeout=timeout) as resp:
                raw_bytes = resp.read()
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read(MAX_HTTP_ERROR_BODY_BYTES).decode("utf-8", errors="replace")
            except Exception:
                err_body = ""
            finally:
                try:
                    exc.close()
                except Exception:
                    pass
            desc = ""
            if err_body:
                try:
                    parsed_err = json.loads(err_body)
                    if isinstance(parsed_err, dict):
                        desc = str(parsed_err.get("description") or "")
                except Exception:
                    desc = err_body[:400]
            if not desc:
                desc = str(exc)
            safe_desc = scrub_secrets(desc, bot_token=self._bot_token)
            raise TelegramAPIError(
                f"Telegram API {method} failed (HTTP {exc.code}): {safe_desc}",
                status_code=int(getattr(exc, "code", 0) or 0),
                description=safe_desc,
                method=method,
            ) from None
        except Exception as exc:
            safe_msg = scrub_secrets(str(exc), bot_token=self._bot_token)
            raise TelegramAPIError(
                f"Telegram API {method} network error: {safe_msg}",
                status_code=0,
                description=safe_msg,
                method=method,
            ) from None

        try:
            parsed = json.loads(raw_bytes.decode("utf-8", errors="replace"))
        except Exception as exc:
            safe_msg = scrub_secrets(str(exc), bot_token=self._bot_token)
            raise TelegramAPIError(
                f"Telegram API {method} invalid JSON response: {safe_msg}",
                status_code=0,
                description=safe_msg,
                method=method,
            ) from None

        if not isinstance(parsed, dict) or not parsed.get("ok"):
            code = int(parsed.get("error_code") or 0) if isinstance(parsed, dict) else 0
            raw_desc = str(parsed.get("description") or "unknown Telegram API error") if isinstance(parsed, dict) else "invalid response"
            safe_desc = scrub_secrets(raw_desc, bot_token=self._bot_token)
            raise TelegramAPIError(
                f"Telegram API {method} returned ok=false (code={code}): {safe_desc}",
                status_code=code,
                description=safe_desc,
                method=method,
            )
        return parsed.get("result")

    def get_me(self) -> Dict[str, Any]:
        res = self.call("getMe", {}, timeout=15.0)
        if not isinstance(res, dict):
            raise TelegramAPIError("Telegram getMe returned non-dict result", method="getMe")
        return res

    def get_updates(
        self,
        *,
        offset: Optional[int] = None,
        timeout: int = DEFAULT_POLL_TIMEOUT_SEC,
        allowed_updates: Sequence[str] = ("message",),
    ) -> List[Dict[str, Any]]:
        payload: Dict[str, Any] = {
            "timeout": int(timeout),
            "allowed_updates": list(allowed_updates),
        }
        if offset is not None and offset > 0:
            payload["offset"] = int(offset)
        res = self.call("getUpdates", payload, timeout=float(timeout) + 10.0)
        return list(res) if isinstance(res, list) else []

    def send_chat_action(self, chat_id: int, action: str = "typing") -> bool:
        try:
            self.call("sendChatAction", {"chat_id": int(chat_id), "action": str(action)}, timeout=10.0)
            return True
        except TelegramAPIError:
            return False

    def send_message(
        self,
        chat_id: int,
        text: str,
        *,
        parse_mode: Optional[str] = None,
        reply_to_message_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"chat_id": int(chat_id), "text": str(text)}
        if parse_mode:
            payload["parse_mode"] = str(parse_mode)
        if reply_to_message_id is not None:
            payload["reply_to_message_id"] = int(reply_to_message_id)
        res = self.call("sendMessage", payload, timeout=20.0)
        return res if isinstance(res, dict) else {}

    def edit_message_text(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        *,
        parse_mode: Optional[str] = None,
    ) -> Any:
        payload: Dict[str, Any] = {
            "chat_id": int(chat_id),
            "message_id": int(message_id),
            "text": str(text),
        }
        if parse_mode:
            payload["parse_mode"] = str(parse_mode)
        return self.call("editMessageText", payload, timeout=20.0)


# ---------------------------------------------------------------------------
# Target Agent Validation (F5)
# ---------------------------------------------------------------------------
def validate_target_agent(agent_id: str, *, bus_dir: Optional[str] = None) -> Dict[str, Any]:
    """Verify target agent is registered, enabled, non-revoked, can_receive=True, transport=='pull_worker'."""
    aid = federation_registry.validate_agent_id(agent_id)
    rec = federation_registry.get_agent(aid, bus_dir=bus_dir)
    if not isinstance(rec, dict):
        raise TargetAgentUnavailableError(f"target agent {aid!r} is not registered")
    if rec.get("revoked"):
        raise TargetAgentUnavailableError(f"target agent {aid!r} is revoked")
    if not rec.get("enabled", False):
        raise TargetAgentUnavailableError(f"target agent {aid!r} is disabled")
    caps = rec.get("capabilities") if isinstance(rec.get("capabilities"), dict) else {}
    if not bool(caps.get("can_receive", False)):
        raise TargetAgentUnavailableError(f"target agent {aid!r} has capabilities.can_receive=False")
    transport = str(rec.get("transport") or "").strip().lower()
    if transport != "pull_worker":
        raise TargetAgentUnavailableError(
            f"target agent {aid!r} has transport {transport!r} (expected 'pull_worker')"
        )
    return rec


# ---------------------------------------------------------------------------
# Active Chat Job Tracking & Main Bridge Engine
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class ActiveChatJob:
    chat_id: int
    owner_user_id: int
    job_id: str = ""
    placeholder_msg_id: Optional[int] = None
    started_mono: float = 0.0
    cancel_requested: bool = False
    cancel_event: threading.Event = dataclasses.field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = None


def _is_html_parse_400(exc: TelegramAPIError) -> bool:
    if exc.status_code != 400:
        return False
    desc = exc.description.lower()
    return (
        "can't parse entities" in desc
        or "parse entities" in desc
        or "unsupported start tag" in desc
        or "unexpected end tag" in desc
        or "unclosed" in desc
    )


def _is_not_modified_400(exc: TelegramAPIError) -> bool:
    return exc.status_code == 400 and "message is not modified" in exc.description.lower()


def _parse_slash_command(text: str) -> Optional[Tuple[str, str, str]]:
    """Parse `/cmd[@username] [args]`. Returns `(cmd_lower, target_bot_lower, args)` or None."""
    stripped = str(text or "").strip()
    if not stripped.startswith("/"):
        return None
    m = _SLASH_CMD_RE.match(stripped)
    if not m:
        return None
    cmd = m.group(1).lower()
    target_bot = (m.group(2) or "").lower()
    args = (m.group(3) or "").strip()
    return cmd, target_bot, args


def _match_exact_bot_mention(text: str, bot_username: str) -> Tuple[bool, str]:
    """Return `(matched, text_without_mention)` for exact `@<bot_username>` (boundary-safe, case-insensitive)."""
    uname = str(bot_username or "").strip().lstrip("@")
    if not uname:
        return False, str(text or "").strip()
    pat = re.compile(rf"(?<![A-Za-z0-9_])@{re.escape(uname)}(?![A-Za-z0-9_])", re.IGNORECASE)
    if not pat.search(text):
        return False, str(text or "").strip()
    cleaned = pat.sub("", text).strip()
    return True, cleaned


class FederationTelegramBridge:
    """Host Telegram <-> Federation `PullWorkerQueue` daemon controller."""

    def __init__(
        self,
        config: BridgeConfig,
        *,
        client: Optional[TelegramClient] = None,
        queue: Optional[federation_registry.PullWorkerQueue] = None,
        state_store: Optional[BridgeStateStore] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep_fn: Optional[Callable[[float], None]] = None,
        env: Optional[Dict[str, str]] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.config = config
        register_redacted_token(config.bot_token)
        self.client = client or TelegramClient(config.bot_token, api_base_url=config.api_base_url)
        self.queue = queue or federation_registry.PullWorkerQueue(config.bus_dir)
        self.state = state_store or BridgeStateStore(
            config.state_dir,
            denied_chats=config.denied_chats,
        )
        self.instance_lock = InstanceLock(config.state_dir, lock_filename="bridge.lock")
        self._clock = clock
        self._sleep_fn = sleep_fn
        self._env = env

        logger_suffix = config.bot_name or config.agent_id
        self.logger = logger or logging.getLogger(f"agy.fed_tg.{logger_suffix}")
        self._redact_filter = RedactingLogFilter(config.bot_token)
        if not any(isinstance(f, RedactingLogFilter) for f in self.logger.filters):
            self.logger.addFilter(self._redact_filter)
        else:
            for flt in self.logger.filters:
                if isinstance(flt, RedactingLogFilter):
                    flt.add_bot_token(config.bot_token)

        self.bot_id: Optional[int] = None
        self.bot_username: str = ""
        self._last_update_id: int = 0
        self._stop_event = threading.Event()
        self._reload_requested = False

        self._jobs_lock = threading.Lock()
        self._active_jobs: Dict[int, ActiveChatJob] = {}
        self._ctx_lock = threading.Lock()
        self._chat_context: Dict[int, "collections.deque[Tuple[str, str]]"] = {}

    def _scrub(self, text: Any) -> str:
        return scrub_secrets(text, bot_token=self.config.bot_token)

    def _make_owner_auth(self, owner_uid: int) -> federation_registry.OwnerAuth:
        return federation_registry.make_owner_auth(f"tg_owner_{owner_uid}", env=self._env)

    # ---------------------------------------------------------------- Lifecycle
    def startup(self) -> Dict[str, Any]:
        """Acquire exclusive lock, verify clean env, target agent, offset, and `getMe`."""
        self.instance_lock.acquire()
        try:
            # Verify process environment is clean (F5)
            federation_registry.make_owner_auth("tg_bridge_startup", env=self._env)
            # Verify target agent is registered & eligible (F5)
            validate_target_agent(self.config.agent_id, bus_dir=self.config.bus_dir)
            # Load persisted offset & validate bindings file isn't a symlink (F4, F7)
            self._last_update_id = self.state.load_offset()
            self.state.load_bound_chats()
            me = self.client.get_me()
            raw_id = me.get("id")
            if type(raw_id) is not int:
                raise TelegramAPIError("Telegram getMe returned invalid bot id", method="getMe")
            self.bot_id = raw_id
            self.bot_username = str(me.get("username") or "").strip().lstrip("@")
            self.logger.info(
                "Started federation_tg_bridge for agent_id=%s bot_id=%s",
                self.config.agent_id,
                self.bot_id,
            )
            return me
        except Exception:
            self.instance_lock.release()
            raise

    def request_stop(self) -> None:
        self._stop_event.set()

    def check_reload_sentinel(self) -> bool:
        """Check and consume reload sentinel file if present. Returns True when reload triggered."""
        sentinel = self.config.reload_sentinel
        if not sentinel or not os.path.lexists(sentinel):
            return False
        try:
            os.unlink(sentinel)
        except OSError:
            pass
        self._reload_requested = True
        self._stop_event.set()
        self.logger.info("Reload sentinel consumed; initiating graceful shutdown")
        return True

    def wait_for_active_jobs(self, timeout: float = 5.0) -> None:
        deadline = self._clock() + max(0.0, float(timeout))
        with self._jobs_lock:
            threads = [job.thread for job in self._active_jobs.values() if job.thread is not None]
        for th in threads:
            rem = max(0.0, deadline - self._clock())
            th.join(timeout=rem)

    def flush_offset(self) -> None:
        """Atomically persist the latest in-memory `update_id` to `offset.json` if advanced."""
        if type(self._last_update_id) is int and self._last_update_id > 0:
            self.state.save_offset(self._last_update_id)

    def shutdown(self, *, join_timeout: float = 5.0, grace_timeout: float = 0.0) -> None:
        self._stop_event.set()
        try:
            grace = max(0.0, float(grace_timeout))
            if grace > 0.0:
                self.wait_for_active_jobs(timeout=min(grace, max(0.0, float(join_timeout))))
            with self._jobs_lock:
                active_list = list(self._active_jobs.values())
            for job in active_list:
                job.cancel_event.set()
            self.wait_for_active_jobs(timeout=join_timeout)
            try:
                self.flush_offset()
            except Exception as exc:
                self.logger.warning("Failed to flush offset during shutdown: %s", self._scrub(exc))
        finally:
            self.instance_lock.release()

    def poll_once(self) -> int:
        """Execute a single `getUpdates` poll cycle and dispatch all new updates."""
        if self.check_reload_sentinel():
            return 0
        if self._stop_event.is_set():
            return 0
        offset_arg = (self._last_update_id + 1) if self._last_update_id > 0 else None
        updates = self.client.get_updates(
            offset=offset_arg,
            timeout=self.config.poll_timeout_sec,
            allowed_updates=("message",),
        )
        processed = 0
        for upd in updates:
            if self._stop_event.is_set():
                break
            if not isinstance(upd, dict):
                continue
            try:
                if self.handle_update(upd):
                    processed += 1
            except Exception as exc:
                self.logger.error("Unhandled error dispatching update: %s", self._scrub(exc))
        return processed

    def run(self, *, install_signals: bool = True, max_loops: Optional[int] = None) -> None:
        """Run the main long-polling daemon loop until `SIGTERM`/`SIGINT`/`SIGHUP`/reload sentinel."""
        prev_sigterm = None
        prev_sigint = None
        prev_sighup = None
        has_sighup = hasattr(signal, "SIGHUP")
        if install_signals and threading.current_thread() is threading.main_thread():
            def _handle_stop_sig(_signum, _frame):
                self._stop_event.set()

            def _handle_reload_sig(_signum, _frame):
                self._reload_requested = True
                self._stop_event.set()

            prev_sigterm = signal.signal(signal.SIGTERM, _handle_stop_sig)
            prev_sigint = signal.signal(signal.SIGINT, _handle_stop_sig)
            if has_sighup:
                prev_sighup = signal.signal(signal.SIGHUP, _handle_reload_sig)

        self.startup()
        loops = 0
        try:
            while not self._stop_event.is_set():
                if self.check_reload_sentinel():
                    break
                if max_loops is not None and loops >= max_loops:
                    break
                loops += 1
                try:
                    self.poll_once()
                except TelegramAPIError as exc:
                    self.logger.warning("Telegram poll error: %s", self._scrub(exc))
                    self._wait_interval(min(2.0, self.config.job_poll_interval_sec))
                except Exception as exc:
                    self.logger.error("Unexpected poll loop error: %s", self._scrub(exc))
                    self._wait_interval(min(2.0, self.config.job_poll_interval_sec))
        finally:
            self.shutdown()
            if install_signals and threading.current_thread() is threading.main_thread():
                if prev_sigterm is not None:
                    signal.signal(signal.SIGTERM, prev_sigterm)
                if prev_sigint is not None:
                    signal.signal(signal.SIGINT, prev_sigint)
                if has_sighup and prev_sighup is not None:
                    signal.signal(signal.SIGHUP, prev_sighup)

    def _wait_interval(self, seconds: float) -> None:
        if self._sleep_fn is not None:
            self._sleep_fn(seconds)
        else:
            self._stop_event.wait(timeout=seconds)

    # ---------------------------------------------------------------- Delivery Helpers (F7)
    def _send_resilient(
        self,
        chat_id: int,
        *,
        html_text: str,
        plain_text: str,
        reply_to_message_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        try:
            return self.client.send_message(
                chat_id,
                html_text,
                parse_mode="HTML",
                reply_to_message_id=reply_to_message_id,
            )
        except TelegramAPIError as exc:
            if _is_html_parse_400(exc):
                return self.client.send_message(
                    chat_id,
                    plain_text,
                    parse_mode=None,
                    reply_to_message_id=reply_to_message_id,
                )
            raise

    def _edit_resilient(
        self,
        chat_id: int,
        message_id: int,
        *,
        html_text: str,
        plain_text: str,
    ) -> None:
        try:
            self.client.edit_message_text(chat_id, message_id, html_text, parse_mode="HTML")
        except TelegramAPIError as exc:
            if _is_not_modified_400(exc):
                return
            if _is_html_parse_400(exc):
                try:
                    self.client.edit_message_text(chat_id, message_id, plain_text, parse_mode=None)
                except TelegramAPIError as retry_exc:
                    if _is_not_modified_400(retry_exc):
                        return
                    raise
                return
            raise

    def _deliver_text(
        self,
        chat_id: int,
        raw_text: str,
        *,
        placeholder_msg_id: Optional[int] = None,
    ) -> None:
        safe_text = self._scrub(raw_text)
        chunks = split_text_for_telegram(safe_text, max_len=MAX_TELEGRAM_CHUNK_LEN, html_aware=True)
        for idx, chunk in enumerate(chunks):
            escaped = html_mod.escape(chunk)
            if idx == 0 and placeholder_msg_id is not None:
                self._edit_resilient(
                    chat_id,
                    placeholder_msg_id,
                    html_text=escaped,
                    plain_text=chunk,
                )
            else:
                self._send_resilient(
                    chat_id,
                    html_text=escaped,
                    plain_text=chunk,
                )

    def _send_notice(self, chat_id: int, text: str) -> None:
        safe = self._scrub(text)
        try:
            self._send_resilient(chat_id, html_text=html_mod.escape(safe), plain_text=safe)
        except TelegramAPIError as exc:
            self.logger.warning("Failed to send notice to chat %s: %s", chat_id, self._scrub(exc))

    # ---------------------------------------------------------------- Context Buffer
    def _record_context(self, chat_id: int, speaker: str, text: str) -> None:
        turns = self.config.context_turns
        if turns <= 0:
            return
        clean = self._scrub(text).strip()
        if not clean:
            return
        max_items = max(2, turns * 2)
        with self._ctx_lock:
            buf = self._chat_context.get(chat_id)
            if buf is None or buf.maxlen != max_items:
                buf = collections.deque(maxlen=max_items)
                self._chat_context[chat_id] = buf
            buf.append((speaker, clean[:1200]))

    def _build_prompt_with_context(self, chat_id: int, user_prompt: str) -> str:
        clean_prompt = self._scrub(user_prompt).strip()
        if self.config.context_turns <= 0:
            return clean_prompt
        with self._ctx_lock:
            entries = list(self._chat_context.get(chat_id) or ())
        if not entries:
            return clean_prompt
        lines: List[str] = []
        used = 0
        for speaker, content in entries:
            line = f"{speaker}: {content}"
            if used + len(line) + 1 > MAX_CONTEXT_CHARS:
                break
            lines.append(line)
            used += len(line) + 1
        if not lines:
            return clean_prompt
        history_block = "\n".join(lines)
        return f"[Recent Chat Context]\n{history_block}\n\n[Current Request]\n{clean_prompt}"

    # ---------------------------------------------------------------- Update Dispatch (F2, F3, F4, F5, F6, F7)
    def _is_chat_authorized(self, chat_id: int, chat_type: str, owner_uid: int) -> bool:
        # DENIED_CHATS always wins unconditionally (F2)
        if chat_id in self.config.denied_chats:
            return False
        if chat_type == "private":
            return chat_id == owner_uid or chat_id in self.config.allowed_chats
        if chat_type in ("group", "supergroup"):
            if chat_id in self.config.allowed_chats:
                return True
            try:
                bound = self.state.load_bound_chats()
            except PermissionError as exc:
                self.logger.error("State file symlink rejected while checking bindings: %s", self._scrub(exc))
                return False
            return chat_id in bound
        return False

    def handle_update(self, update: Dict[str, Any]) -> bool:
        """Process a single Telegram update dict. Returns True if accepted & dispatched."""
        if not isinstance(update, dict):
            return False

        raw_uid = update.get("update_id")
        if type(raw_uid) is int:
            if raw_uid <= self._last_update_id:
                return False
            self._last_update_id = raw_uid
            self.state.save_offset(raw_uid)

        message = update.get("message")
        if not isinstance(message, dict):
            return False

        # F2: Reject anonymous admin / channel sender_chat messages silently
        if message.get("sender_chat"):
            return False

        from_user = message.get("from")
        if not isinstance(from_user, dict):
            return False

        # F3: Unconditional bot-loop immunity (even if id appears in OWNER_USERS)
        if from_user.get("is_bot") is True or bool(from_user.get("is_bot")):
            return False

        uid = from_user.get("id")
        if type(uid) is not int:
            return False

        # F2: Strict Owner RBAC — non-owners silently dropped (0 replies, 0 make_owner_auth, 0 enqueue)
        if uid not in self.config.owner_users:
            return False

        chat = message.get("chat")
        if not isinstance(chat, dict):
            return False
        chat_id = chat.get("id")
        if type(chat_id) is not int:
            return False
        chat_type = str(chat.get("type") or "").strip().lower()

        # F2: DENIED_CHATS absolute precedence over ALLOWED_CHATS, DM, and bindings.json
        if chat_id in self.config.denied_chats:
            return False

        raw_text = message.get("text")
        if not isinstance(raw_text, str):
            raw_text = message.get("caption") if isinstance(message.get("caption"), str) else ""
        text = raw_text.strip()
        if not text:
            return False

        parsed_cmd = _parse_slash_command(text)
        if parsed_cmd is not None:
            cmd_name, target_bot, cmd_args = parsed_cmd
            if target_bot and (not self.bot_username or target_bot != self.bot_username.lower()):
                return False

            if cmd_name in _BIND_COMMANDS:
                return self._handle_bind_command(cmd_name, chat_id, chat_type)

        # Check chat authorization before executing any other command or prompt
        if not self._is_chat_authorized(chat_id, chat_type, uid):
            return False

        # Handle management commands
        if parsed_cmd is not None:
            cmd_name, _target_bot, cmd_args = parsed_cmd
            if cmd_name in ("start", "help"):
                self._handle_help(chat_id)
                return True
            if cmd_name == "status":
                self._handle_status(chat_id, chat_type)
                return True
            if cmd_name == "clear":
                with self._ctx_lock:
                    self._chat_context.pop(chat_id, None)
                self._send_notice(chat_id, "🧹 已清空当前会话上下文缓存。")
                return True
            if cmd_name == "cancel":
                self._handle_cancel(chat_id, uid)
                return True
            if cmd_name in self.config.command_aliases:
                if not cmd_args:
                    self._send_notice(chat_id, f"用法：/{cmd_name} <任务内容>")
                    return True
                self._dispatch_prompt(chat_id, chat_type, uid, cmd_args)
                return True
            # Unknown slash command: polite notice in DM, silent ignore in groups
            if chat_type == "private":
                self._send_notice(chat_id, "未知命令，发送 /help 查看支持的指令。")
                return True
            return False

        # Non-command message: DM triggers directly; group requires exact bot mention or reply to this bot (F3)
        if chat_type == "private":
            self._dispatch_prompt(chat_id, chat_type, uid, text)
            return True

        if chat_type in ("group", "supergroup"):
            reply = message.get("reply_to_message")
            is_reply_to_me = (
                isinstance(reply, dict)
                and isinstance(reply.get("from"), dict)
                and self.bot_id is not None
                and reply["from"].get("id") == self.bot_id
            )
            mentioned, stripped_text = _match_exact_bot_mention(text, self.bot_username)
            if not is_reply_to_me and not mentioned:
                # Plain group chatter: cache bounded human context, do not reply or enqueue
                self._record_context(chat_id, "owner", text)
                return False
            prompt_text = stripped_text if mentioned else text
            if not prompt_text:
                self._send_notice(chat_id, "请在提及后附带需要远端 Agent 处理的内容。")
                return True
            self._dispatch_prompt(chat_id, chat_type, uid, prompt_text)
            return True

        return False

    # ---------------------------------------------------------------- Command Handlers
    def _handle_bind_command(self, cmd_name: str, chat_id: int, chat_type: str) -> bool:
        if chat_type not in ("group", "supergroup") or chat_id >= 0:
            self._send_notice(chat_id, "⚠️ /bindgroup 与 /unbindgroup 仅允许在普通群或超级群中使用。")
            return False
        if chat_id in self.config.denied_chats:
            return False
        try:
            if cmd_name == "bindgroup":
                added = self.state.bind_group(chat_id)
                msg = (
                    "✅ 已将当前群聊绑定至本联邦桥接守护。"
                    if added
                    else "ℹ️ 当前群聊已在绑定列表中。"
                )
            else:
                removed = self.state.unbind_group(chat_id)
                msg = (
                    "✅ 已解除当前群聊的动态绑定。"
                    if removed
                    else "ℹ️ 当前群聊未在动态绑定列表中。"
                )
        except PermissionError as exc:
            self.logger.error("Bind command rejected: %s", self._scrub(exc))
            self._send_notice(chat_id, "🔒 状态文件安全校验未通过，操作已拒绝。")
            return False
        except Exception as exc:
            self.logger.error("Bind command failed: %s", self._scrub(exc))
            self._send_notice(chat_id, "⚠️ 群聊绑定状态更新失败，请检查守护日志。")
            return False
        self._send_notice(chat_id, msg)
        return True

    def _handle_help(self, chat_id: int) -> None:
        aliases_str = ", ".join(f"/{a}" for a in sorted(self.config.command_aliases))
        lines = [
            f"🤖 Federation Telegram Bridge ({self.config.agent_id})",
            "支持指令（仅 Owner 有效）：",
            "• /status - 查看目标 Agent 注册与当前会话任务状态",
            "• /cancel - 取消当前会话正在执行的任务",
            "• /clear - 清空当前会话滚动上下文",
            "• /bindgroup / /unbindgroup - 绑定或解绑当前群聊",
            f"• {aliases_str} <内容> - 显式派发任务到目标 Agent",
        ]
        self._send_notice(chat_id, "\n".join(lines))

    def _handle_status(self, chat_id: int, chat_type: str) -> None:
        rec = federation_registry.get_agent(self.config.agent_id, bus_dir=self.config.bus_dir)
        if not isinstance(rec, dict):
            agent_state = "未注册 (unregistered)"
        else:
            caps = rec.get("capabilities") if isinstance(rec.get("capabilities"), dict) else {}
            enabled = bool(rec.get("enabled", False))
            revoked = bool(rec.get("revoked", False))
            can_recv = bool(caps.get("can_receive", False))
            transport = str(rec.get("transport") or "unknown")
            online_label = "可用" if (enabled and not revoked and can_recv and transport == "pull_worker") else "不可用"
            agent_state = (
                f"{online_label} (enabled={enabled}, revoked={revoked}, "
                f"transport={transport}, can_receive={can_recv})"
            )

        with self._jobs_lock:
            active = self._active_jobs.get(chat_id)
            total_active = len(self._active_jobs)

        if active is not None:
            elapsed = max(0.0, self._clock() - active.started_mono)
            job_line = f"运行中 (job_id={active.job_id or 'pending'}, elapsed={elapsed:.1f}s)"
        else:
            job_line = "空闲"

        if chat_type == "private":
            bind_line = "Owner 私聊 (DM)"
        elif chat_id in self.config.allowed_chats:
            bind_line = "静态白名单群聊"
        else:
            bind_line = "动态绑定群聊 (/bindgroup)"

        lines = [
            f"📊 Agent: {self.config.agent_id}",
            f"状态: {agent_state}",
            f"当前会话: {bind_line}",
            f"当前任务: {job_line} (全局在途: {total_active})",
        ]
        self._send_notice(chat_id, "\n".join(lines))

    def _handle_cancel(self, chat_id: int, owner_uid: int) -> None:
        with self._jobs_lock:
            active = self._active_jobs.get(chat_id)
            if active is None:
                jid = None
            else:
                active.cancel_requested = True
                active.cancel_event.set()
                jid = active.job_id

        if active is None:
            self._send_notice(chat_id, "ℹ️ 当前会话没有正在执行的任务。")
            return

        try:
            owner_auth = self._make_owner_auth(owner_uid)
        except PermissionError as exc:
            self.logger.warning("Cancel blocked by tainted env: %s", self._scrub(exc))
            self._send_notice(chat_id, "🔒 当前运行环境受限，无法执行取消操作。")
            return

        if jid:
            try:
                self.queue.cancel(
                    jid,
                    reason="cancelled_by_owner",
                    owner_auth=owner_auth,
                    env=self._env,
                )
            except Exception as exc:
                self.logger.warning("Queue cancel failed for %s: %s", jid, self._scrub(exc))
                self._send_notice(chat_id, "⚠️ 取消队列任务时发生错误，请稍后重试。")
                return
        self._send_notice(chat_id, f"🛑 已请求取消当前会话任务 ({jid or 'pending'})。")

    # ---------------------------------------------------------------- Prompt Dispatch & Worker Waiter (F5, F6, F7)
    def _dispatch_prompt(self, chat_id: int, chat_type: str, owner_uid: int, prompt_text: str) -> None:
        # F5: Real-time target agent check BEFORE enqueue
        try:
            validate_target_agent(self.config.agent_id, bus_dir=self.config.bus_dir)
        except TargetAgentUnavailableError as exc:
            self.logger.warning("Target agent unavailable before enqueue: %s", self._scrub(exc))
            self._send_notice(
                chat_id,
                f"⚠️ 目标 Agent ({self.config.agent_id}) 当前不可用（未注册、已禁用/撤权或传输模式不兼容），已拒绝入队。",
            )
            return

        # F5: OwnerAuth check BEFORE enqueue (blocks tainted/readonly/worker env)
        try:
            owner_auth = self._make_owner_auth(owner_uid)
        except PermissionError as exc:
            self.logger.warning("Enqueue blocked by tainted env: %s", self._scrub(exc))
            self._send_notice(chat_id, "🔒 当前进程环境处于受限/污点状态，已拒绝派发任务。")
            return

        # F6: Per-chat concurrency guard (deterministic busy rejection; never overwrites active job)
        active = ActiveChatJob(
            chat_id=chat_id,
            owner_user_id=owner_uid,
            started_mono=self._clock(),
        )
        busy = False
        with self._jobs_lock:
            if chat_id in self._active_jobs:
                busy = True
            else:
                self._active_jobs[chat_id] = active
        if busy:
            self._send_notice(chat_id, "⏳ 当前会话已有任务正在处理，请等待完成或发送 /cancel 取消。")
            return

        placeholder_msg_id: Optional[int] = None
        try:
            self.client.send_chat_action(chat_id, "typing")
            ph_res = self._send_resilient(
                chat_id,
                html_text=html_mod.escape(f"⏳ 已提交给 {self.config.agent_id}，等待远端 Worker 处理…"),
                plain_text=f"⏳ 已提交给 {self.config.agent_id}，等待远端 Worker 处理…",
            )
            if isinstance(ph_res, dict) and type(ph_res.get("message_id")) is int:
                placeholder_msg_id = ph_res["message_id"]

            full_prompt = self._build_prompt_with_context(chat_id, prompt_text)
            safe_meta = scrub_metadata(
                {
                    "source": "federation_tg_bridge",
                    "agent_id": self.config.agent_id,
                    "chat_id": chat_id,
                    "chat_type": chat_type,
                    "owner_user_id": owner_uid,
                },
                bot_token=self.config.bot_token,
            )
            job_rec = self.queue.enqueue(
                self.config.agent_id,
                full_prompt,
                metadata=safe_meta,
                owner_auth=owner_auth,
                env=self._env,
            )
            jid = str(job_rec["job_id"])
            with self._jobs_lock:
                active.job_id = jid
                active.placeholder_msg_id = placeholder_msg_id
                already_cancelled = active.cancel_requested

            self._record_context(chat_id, "owner", prompt_text)

            if already_cancelled:
                self.queue.cancel(
                    jid,
                    reason="cancelled_by_owner",
                    owner_auth=owner_auth,
                    env=self._env,
                )
                with self._jobs_lock:
                    if self._active_jobs.get(chat_id) is active:
                        self._active_jobs.pop(chat_id, None)
                self._deliver_text(chat_id, "🛑 任务已取消。", placeholder_msg_id=placeholder_msg_id)
                return

            worker = threading.Thread(
                target=self._wait_for_job,
                args=(active, owner_auth),
                name=f"fed-tg-job-{jid}",
                daemon=True,
            )
            with self._jobs_lock:
                active.thread = worker
            worker.start()
        except PermissionError as exc:
            with self._jobs_lock:
                if self._active_jobs.get(chat_id) is active:
                    self._active_jobs.pop(chat_id, None)
            self.logger.warning("Enqueue rejected with PermissionError: %s", self._scrub(exc))
            self._deliver_text(
                chat_id,
                "🔒 权限或环境校验未通过，任务已拒绝入队。",
                placeholder_msg_id=placeholder_msg_id,
            )
        except Exception as exc:
            with self._jobs_lock:
                if self._active_jobs.get(chat_id) is active:
                    self._active_jobs.pop(chat_id, None)
            self.logger.error("Failed to enqueue job: %s", self._scrub(exc))
            self._deliver_text(
                chat_id,
                "⚠️ 任务入队失败，请稍后重试或检查守护日志。",
                placeholder_msg_id=placeholder_msg_id,
            )

    def _wait_for_job(
        self,
        active: ActiveChatJob,
        owner_auth: federation_registry.OwnerAuth,
    ) -> None:
        started = active.started_mono
        last_typing = started
        try:
            while True:
                job = self.queue.get(active.job_id)
                if not isinstance(job, dict):
                    self._deliver_text(
                        active.chat_id,
                        "⚠️ 任务状态记录缺失，请重试。",
                        placeholder_msg_id=active.placeholder_msg_id,
                    )
                    return

                status = str(job.get("status") or "").strip().lower()
                if status == "done":
                    result_text = str(job.get("result_text") or "").strip() or "(远端 Agent 返回了空内容)"
                    safe_result = self._scrub(result_text)
                    self._record_context(active.chat_id, self.config.agent_id, safe_result)
                    self._deliver_text(
                        active.chat_id,
                        safe_result,
                        placeholder_msg_id=active.placeholder_msg_id,
                    )
                    return

                if status == "error":
                    err_text = self._scrub(str(job.get("error") or "远端 Agent 执行失败"))
                    self._deliver_text(
                        active.chat_id,
                        f"❌ 执行失败：{err_text}",
                        placeholder_msg_id=active.placeholder_msg_id,
                    )
                    return

                if status == "cancelled" or job.get("cancelled"):
                    reason = self._scrub(str(job.get("cancel_reason") or "cancelled"))
                    if reason == "timeout":
                        msg = "⏱ 任务执行超时，已自动取消排队/在途作业。"
                    else:
                        msg = f"🛑 任务已取消 ({reason})。"
                    self._deliver_text(
                        active.chat_id,
                        msg,
                        placeholder_msg_id=active.placeholder_msg_id,
                    )
                    return

                if active.cancel_event.is_set():
                    try:
                        self.queue.cancel(
                            active.job_id,
                            reason="cancelled_by_owner" if active.cancel_requested else "bridge_shutdown",
                            owner_auth=owner_auth,
                            env=self._env,
                        )
                    except Exception as exc:
                        self.logger.warning("Cancel on stop failed for %s: %s", active.job_id, self._scrub(exc))
                    self._deliver_text(
                        active.chat_id,
                        "🛑 任务已取消。",
                        placeholder_msg_id=active.placeholder_msg_id,
                    )
                    return

                now = self._clock()
                if (now - started) >= self.config.job_timeout_sec:
                    try:
                        self.queue.cancel(
                            active.job_id,
                            reason="timeout",
                            owner_auth=owner_auth,
                            env=self._env,
                        )
                    except Exception as exc:
                        self.logger.error("Timeout cancel failed for %s: %s", active.job_id, self._scrub(exc))
                    self._deliver_text(
                        active.chat_id,
                        "⏱ 任务执行超时，已自动取消排队/在途作业。",
                        placeholder_msg_id=active.placeholder_msg_id,
                    )
                    return

                if (now - last_typing) >= self.config.typing_refresh_sec:
                    self.client.send_chat_action(active.chat_id, "typing")
                    last_typing = now

                if self._sleep_fn is not None:
                    self._sleep_fn(self.config.job_poll_interval_sec)
                else:
                    active.cancel_event.wait(timeout=self.config.job_poll_interval_sec)
        except Exception as exc:
            self.logger.error("Job waiter error for %s: %s", active.job_id, self._scrub(exc))
            try:
                self._deliver_text(
                    active.chat_id,
                    "⚠️ 等待任务结果时发生异常，请查看守护日志。",
                    placeholder_msg_id=active.placeholder_msg_id,
                )
            except Exception:
                pass
        finally:
            with self._jobs_lock:
                if self._active_jobs.get(active.chat_id) is active:
                    self._active_jobs.pop(active.chat_id, None)


# ---------------------------------------------------------------------------
# Single-Process Multi-Bot Supervisor (M2, M3)
# ---------------------------------------------------------------------------
class MultiBotSupervisor:
    """Supervises multiple isolated `FederationTelegramBridge` bots inside one process.

    Guarantees:
    - Process-wide token redaction across all managed bots before any network/log activity (M2).
    - Dual exclusive locking: `<state_root_dir>/supervisor.lock` + per-bot `<state_dir>/bridge.lock`
      with zero-leak rollback on any lock/startup/duplicate-`bot_id` conflict (M1, M3).
    - Fault-isolated per-bot polling threads with bounded exponential backoff (M2).
    - Unified `SIGTERM`/`SIGINT`/`SIGHUP` & reload-sentinel graceful shutdown, atomic offset
      flushing, and explicit lock fd closing before `os.execv` (M3).
    """

    def __init__(
        self,
        config: MultiBotConfig,
        *,
        client_factory: Optional[Callable[[BridgeConfig], Any]] = None,
        queue_factory: Optional[Callable[[BridgeConfig], Any]] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep_fn: Optional[Callable[[float], None]] = None,
        env: Optional[Dict[str, str]] = None,
        logger: Optional[logging.Logger] = None,
        monitor_interval_sec: float = 0.2,
        backoff_base_sec: float = DEFAULT_BACKOFF_BASE_SEC,
        backoff_max_sec: float = DEFAULT_BACKOFF_MAX_SEC,
        shutdown_grace_sec: float = 1.0,
    ):
        self.config = config
        self._clock = clock
        self._sleep_fn = sleep_fn
        self._env = env
        self._monitor_interval_sec = max(0.01, float(monitor_interval_sec))
        self._backoff_base_sec = max(0.01, float(backoff_base_sec))
        self._backoff_max_sec = max(self._backoff_base_sec, float(backoff_max_sec))
        self._shutdown_grace_sec = max(0.0, float(shutdown_grace_sec))

        # Register ALL loaded bot tokens globally before any bot initializes (M2)
        all_tokens = [b.bot_token for b in config.bots]
        register_redacted_tokens(all_tokens)

        self.logger = logger or logging.getLogger("agy.fed_tg.supervisor")
        if not any(isinstance(f, RedactingLogFilter) for f in self.logger.filters):
            self.logger.addFilter(RedactingLogFilter(bot_tokens=all_tokens))
        else:
            for flt in self.logger.filters:
                if isinstance(flt, RedactingLogFilter):
                    flt.add_bot_tokens(all_tokens)

        self.supervisor_lock = InstanceLock(config.state_root_dir, lock_filename="supervisor.lock")
        self._stop_event = threading.Event()
        self._reload_requested = False

        self.bridges: Dict[str, FederationTelegramBridge] = {}
        self._bridge_list: List[FederationTelegramBridge] = []
        self._worker_threads: Dict[str, threading.Thread] = {}

        for bcfg in config.bots:
            key = bcfg.bot_name or bcfg.agent_id
            client = client_factory(bcfg) if client_factory is not None else None
            queue = queue_factory(bcfg) if queue_factory is not None else None
            bot_logger = logging.getLogger(f"agy.fed_tg.{key}")
            if not any(isinstance(f, RedactingLogFilter) for f in bot_logger.filters):
                bot_logger.addFilter(RedactingLogFilter(bot_tokens=all_tokens))
            br = FederationTelegramBridge(
                bcfg,
                client=client,
                queue=queue,
                clock=clock,
                sleep_fn=sleep_fn,
                env=env,
                logger=bot_logger,
            )
            self.bridges[key] = br
            self._bridge_list.append(br)

    @property
    def reload_requested(self) -> bool:
        return self._reload_requested

    def held_lock_fds(self) -> List[int]:
        """Return all currently open lock file descriptors held by supervisor and child bots."""
        fds: List[int] = []
        if self.supervisor_lock.fd is not None:
            fds.append(self.supervisor_lock.fd)
        for br in self._bridge_list:
            if br.instance_lock.fd is not None:
                fds.append(br.instance_lock.fd)
        return fds

    def request_stop(self, *, reload: bool = False) -> None:
        if reload:
            self._reload_requested = True
        self._stop_event.set()
        for br in self._bridge_list:
            br.request_stop()

    def check_reload_sentinel(self) -> bool:
        """Check and consume unified reload sentinel file. Returns True if reload triggered."""
        sentinel = self.config.reload_sentinel
        if not sentinel or not os.path.lexists(sentinel):
            return False
        try:
            os.unlink(sentinel)
        except OSError:
            pass
        self._reload_requested = True
        self.request_stop(reload=True)
        self.logger.info("Unified reload sentinel consumed; initiating graceful multi-bot shutdown")
        return True

    def startup(self) -> Dict[str, Dict[str, Any]]:
        """Acquire `supervisor.lock`, start each bot (acquiring `bridge.lock`), and deduplicate `bot_id`."""
        self.supervisor_lock.acquire()
        started: List[FederationTelegramBridge] = []
        identities: Dict[str, Dict[str, Any]] = {}
        seen_bot_ids: Dict[int, str] = {}
        try:
            federation_registry.make_owner_auth("tg_supervisor_startup", env=self._env)
            for br in self._bridge_list:
                key = br.config.bot_name or br.config.agent_id
                me = br.startup()
                started.append(br)
                assert br.bot_id is not None
                if br.bot_id in seen_bot_ids:
                    raise ValueError(
                        f"DUPLICATE_BOT_ID: bot_id={br.bot_id} returned for both "
                        f"{seen_bot_ids[br.bot_id]!r} and {key!r}"
                    )
                seen_bot_ids[br.bot_id] = key
                identities[key] = me
            self.logger.info(
                "MultiBotSupervisor started %d bot(s): %s",
                len(started),
                ", ".join(identities.keys()),
            )
            return identities
        except Exception:
            for br in reversed(started):
                try:
                    br.shutdown(join_timeout=1.0, grace_timeout=0.0)
                except Exception:
                    br.instance_lock.release()
            self.supervisor_lock.release()
            raise

    def _wait_worker_backoff(self, bridge: FederationTelegramBridge, seconds: float) -> None:
        if self._sleep_fn is not None:
            self._sleep_fn(seconds)
            return
        deadline = time.monotonic() + max(0.0, seconds)
        while not self._stop_event.is_set() and not bridge._stop_event.is_set():
            rem = deadline - time.monotonic()
            if rem <= 0:
                break
            self._stop_event.wait(timeout=min(0.1, rem))

    def _bot_worker_loop(
        self,
        bridge: FederationTelegramBridge,
        *,
        max_loops: Optional[int] = None,
    ) -> None:
        key = bridge.config.bot_name or bridge.config.agent_id
        consecutive_errors = 0
        loops = 0
        while not self._stop_event.is_set() and not bridge._stop_event.is_set():
            if max_loops is not None and loops >= max_loops:
                break
            loops += 1
            try:
                bridge.poll_once()
                consecutive_errors = 0
            except TelegramAPIError as exc:
                consecutive_errors += 1
                delay = min(self._backoff_max_sec, self._backoff_base_sec * (2 ** min(consecutive_errors - 1, 5)))
                bridge.logger.warning(
                    "Bot %s Telegram poll error (attempt=%d, backoff=%.2fs): %s",
                    key,
                    consecutive_errors,
                    delay,
                    bridge._scrub(exc),
                )
                self._wait_worker_backoff(bridge, delay)
            except Exception as exc:
                consecutive_errors += 1
                delay = min(self._backoff_max_sec, self._backoff_base_sec * (2 ** min(consecutive_errors - 1, 5)))
                bridge.logger.error(
                    "Bot %s unexpected poll error (attempt=%d, backoff=%.2fs): %s",
                    key,
                    consecutive_errors,
                    delay,
                    bridge._scrub(exc),
                )
                self._wait_worker_backoff(bridge, delay)

    def shutdown(self, *, join_timeout: float = 5.0) -> None:
        """Stop all bot polling threads, finish/cancel active jobs, flush offsets, and close all lock fds."""
        self.request_stop()
        try:
            deadline = self._clock() + max(0.0, float(join_timeout))
            for th in list(self._worker_threads.values()):
                if th.is_alive():
                    rem = max(0.0, deadline - self._clock())
                    th.join(timeout=rem)
            self._worker_threads.clear()

            per_bot_grace = min(self._shutdown_grace_sec, max(0.0, float(join_timeout) / 2.0))
            for br in reversed(self._bridge_list):
                try:
                    rem_join = max(0.5, deadline - self._clock())
                    br.shutdown(join_timeout=rem_join, grace_timeout=per_bot_grace)
                except Exception as exc:
                    self.logger.error(
                        "Error shutting down bot %s: %s",
                        br.config.bot_name or br.config.agent_id,
                        scrub_secrets(exc),
                    )
                    br.instance_lock.release()
        finally:
            for br in self._bridge_list:
                br.instance_lock.release()
            self.supervisor_lock.release()

    def run(self, *, install_signals: bool = True, max_loops: Optional[int] = None) -> None:
        """Start all bots in isolated threads and supervise until signal or reload sentinel."""
        prev_sigterm = None
        prev_sigint = None
        prev_sighup = None
        has_sighup = hasattr(signal, "SIGHUP")
        if install_signals and threading.current_thread() is threading.main_thread():
            def _handle_stop_sig(_signum, _frame):
                self.request_stop(reload=False)

            def _handle_reload_sig(_signum, _frame):
                self.request_stop(reload=True)

            prev_sigterm = signal.signal(signal.SIGTERM, _handle_stop_sig)
            prev_sigint = signal.signal(signal.SIGINT, _handle_stop_sig)
            if has_sighup:
                prev_sighup = signal.signal(signal.SIGHUP, _handle_reload_sig)

        self.startup()
        try:
            if not self.check_reload_sentinel() and not self._stop_event.is_set():
                for br in self._bridge_list:
                    key = br.config.bot_name or br.config.agent_id
                    th = threading.Thread(
                        target=self._bot_worker_loop,
                        args=(br,),
                        kwargs={"max_loops": max_loops},
                        name=f"fed-tg-bot-{key}",
                        daemon=True,
                    )
                    self._worker_threads[key] = th
                    th.start()

                while not self._stop_event.is_set():
                    if self.check_reload_sentinel():
                        break
                    if self._worker_threads and not any(t.is_alive() for t in self._worker_threads.values()):
                        break
                    self._stop_event.wait(timeout=self._monitor_interval_sec)
        finally:
            self.shutdown()
            if install_signals and threading.current_thread() is threading.main_thread():
                if prev_sigterm is not None:
                    signal.signal(signal.SIGTERM, prev_sigterm)
                if prev_sigint is not None:
                    signal.signal(signal.SIGINT, prev_sigint)
                if has_sighup and prev_sighup is not None:
                    signal.signal(signal.SIGHUP, prev_sighup)


# ---------------------------------------------------------------------------
# CLI Entrypoint (Single-Bot Env Mode + Multi-Bot Config Mode)
# ---------------------------------------------------------------------------
def _configure_logging(
    bot_token: str = "",
    *,
    bot_tokens: Sequence[str] = (),
) -> logging.Logger:
    tokens_to_add = [tok for tok in (bot_token, *bot_tokens) if tok]
    if tokens_to_add:
        register_redacted_tokens(tokens_to_add)
    logger = logging.getLogger("agy.fed_tg")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        handler.addFilter(RedactingLogFilter(bot_tokens=tokens_to_add))
        logger.addHandler(handler)
    else:
        for h in logger.handlers:
            has_filter = False
            for flt in h.filters:
                if isinstance(flt, RedactingLogFilter):
                    flt.add_bot_tokens(tokens_to_add)
                    has_filter = True
            if not has_filter:
                h.addFilter(RedactingLogFilter(bot_tokens=tokens_to_add))
    return logger


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Generic Telegram <-> Federation PullWorkerQueue Bridge Daemon")
    p.add_argument("--self-check", action="store_true", help="Verify module imports and exit 0")
    return p


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
    secret_resolver: Optional[Callable[[str], str]] = None,
    execv_fn: Optional[Callable[[str, List[str]], Any]] = None,
    client_factory: Optional[Callable[[BridgeConfig], Any]] = None,
    max_loops: Optional[int] = None,
    install_signals: bool = True,
) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.self_check:
        print("ok")
        return 0

    src_env = os.environ if env is None else env
    bots_config_path = str(src_env.get("AGY_FED_TG_BOTS_CONFIG") or "").strip()

    if bots_config_path:
        # Single-process multi-bot config file mode (M1..M4)
        try:
            multi_cfg = load_multi_bot_config(
                bots_config_path,
                env=src_env,
                secret_resolver=secret_resolver,
            )
        except Exception as exc:
            sys.stderr.write(f"[FATAL] Multi-bot configuration error: {scrub_secrets(exc)}\n")
            return 2

        logger = _configure_logging(bot_tokens=[b.bot_token for b in multi_cfg.bots])
        supervisor = MultiBotSupervisor(
            multi_cfg,
            client_factory=client_factory,
            env=dict(src_env) if env is not None else None,
            logger=logger,
        )
        try:
            supervisor.run(install_signals=install_signals, max_loops=max_loops)
        except (InstanceLockError, TargetAgentUnavailableError, PermissionError, ValueError, RuntimeError, OSError) as exc:
            logger.error("Multi-bot supervisor failed closed: %s", scrub_secrets(exc))
            return 1

        if supervisor.reload_requested:
            # Ensure every lock fd is explicitly closed before execv (M3)
            if supervisor.held_lock_fds():
                supervisor.shutdown()
            # Fail-closed validation of reloaded config before re-exec (M3)
            try:
                load_multi_bot_config(
                    bots_config_path,
                    env=src_env,
                    secret_resolver=secret_resolver,
                )
            except Exception as exc:
                logger.error("Reload aborted — invalid multi-bot configuration: %s", scrub_secrets(exc))
                return 2
            reexec_args = [
                sys.executable,
                os.path.abspath(__file__),
                *(list(argv) if argv is not None else sys.argv[1:]),
            ]
            (execv_fn or os.execv)(sys.executable, reexec_args)
        return 0

    # Legacy single-bot environment mode (100% backwards-compatible F1..F8)
    try:
        cfg = load_config(env=src_env, secret_resolver=secret_resolver)
    except Exception as exc:
        sys.stderr.write(f"[FATAL] Configuration error: {scrub_secrets(exc)}\n")
        return 2

    logger = _configure_logging(cfg.bot_token)
    client = client_factory(cfg) if client_factory is not None else None
    bridge = FederationTelegramBridge(
        cfg,
        client=client,
        env=dict(src_env) if env is not None else None,
        logger=logger,
    )
    try:
        bridge.run(install_signals=install_signals, max_loops=max_loops)
    except (InstanceLockError, TargetAgentUnavailableError, PermissionError, ValueError, RuntimeError, OSError) as exc:
        logger.error("Bridge startup/runtime failed closed: %s", scrub_secrets(exc, bot_token=cfg.bot_token))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
