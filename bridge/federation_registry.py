#!/usr/bin/env python3
"""Server-authoritative External Agent Federation Registry, Multi-Team RBAC & Pull Worker Queue.

Flat standalone module (no top-level `import bridge`) shared by `bot_bus.py`,
`bot_bus_mcp.py`, `external_drivers.py`, and future M2 Inbound Hub.

Security invariants (C1, C2, C3, C4, C7, C8):
- Storage layout: `<BUS_DIR>/federation/` (`0700`), `agents.json` / `teams.json` (`0600`),
  `pull_queue/` (`0700`), `pull_queue/<job_id>.json` (`0600`), guarded by `fcntl.flock`
  and temp-file `os.replace` atomic writes.
- Owner-only mutations: EVERY write operation requires verified Owner authorization
  (`OwnerAuth(is_owner=True, ...)` in a clean local owner context). Workers, registered
  external agents (even with `coordinator_peer=True`), untrusted/readonly/tainted contexts,
  and unauthenticated callers ALWAYS fail closed with `PermissionError("PRIVILEGE_ESCALATION_DENIED: ...")`
  leaving disk files completely untouched.
- Zero plaintext secrets: Rejects raw secret fields (`api_key`, `token`, `password`, `secret`,
  `authorization`, etc.) and raw secret value patterns (`sk-`, `ghp_`, `hvs.`, `AIza`, `Bearer `,
  etc.); only OpenBao `secret_ref` mount paths are accepted. Agent inbound tokens
  are stored strictly as salted HMAC-SHA256 digests and verified via `hmac.compare_digest`.
- Strict identifier validation: `agent_id`, `team_id`, `profile`, `job_id` reject traversal
  chars (`..`, `/`, `\\`, `\x00`), dots, uppercase, and overlong inputs with `ValueError`.
- Backward compatibility: Read paths never create `<BUS_DIR>/federation/` on disk when absent;
  legacy 4-Bot `default` team deployments work with zero regressions.
"""

from __future__ import annotations

import contextlib
import copy
import dataclasses
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

try:
    if __package__:
        from . import memory_guard as _memory_guard  # type: ignore
    else:
        import memory_guard as _memory_guard  # type: ignore
except ImportError:
    _memory_guard = None  # type: ignore

HOME = os.path.expanduser("~")
DEFAULT_BUS_DIR = os.path.join(HOME, ".gemini", "antigravity-cli", "cache", "bot_bus")

AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TEAM_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
PROFILE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
PULL_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,95}$")
_OPENBAO_MOUNTS = ("lv" + "1", "lv" + "2")
SECRET_REF_RE = re.compile(
    r"^(?:" + "|".join(_OPENBAO_MOUNTS) + r")/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+(?:#[A-Za-z0-9._-]+)?$"
)
TOKEN_PREFIX = "agy_fed_"

VALID_AGENT_KINDS = frozenset(
    {
        "agy_local",
        "hermes_local",
        "hermes_remote",
        "muse_remote",
        "http_a2a",
        "mcp_inbound_only",
    }
)
VALID_TRANSPORTS = frozenset(
    {
        "local_cli",
        "hermes_api",
        "http_push",
        "pull_worker",
        "mcp_inbound",
    }
)
VALID_DRIVERS = frozenset(
    {
        "agy",
        "hermes_local",
        "hermes_remote",
        "http_external",
        "muse_remote",
        "http_a2a",
        "pull_worker",
        "mcp_inbound_only",
    }
)
TRUST_ORDER: Dict[str, int] = {
    "local_admin": 4,
    "local_worker": 3,
    "remote_trusted": 2,
    "remote_untrusted": 1,
    "readonly_guest": 0,
}

FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "api_token",
        "token",
        "access_token",
        "auth_token",
        "bearer_token",
        "refresh_token",
        "password",
        "passwd",
        "pwd",
        "secret",
        "secret_key",
        "client_secret",
        "private_key",
        "authorization",
        "raw_token",
        "plaintext_token",
        "credential",
        "credentials",
        "bot_token",
        "x-api-key",
        "x_api_key",
    }
)

_PLAINTEXT_SECRET_VALUE_RES: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("openai_or_sk_key", re.compile(r"(?<![A-Za-z0-9-])sk-[A-Za-z0-9_-]{12,}")),
    ("github_token", re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,})\b")),
    ("vault_token", re.compile(r"(?<![A-Za-z0-9])hvs\.[A-Za-z0-9_-]{12,}\b")),
    ("google_api_key", re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{20,}\b")),
    ("slack_token", re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{12,}\b")),
    ("telegram_bot_token", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{25,}\b")),
    ("federation_token", re.compile(r"(?<![A-Za-z0-9])agy_fed_[A-Za-z0-9._-]{12,}")),
    ("auth_header_scheme", re.compile(r"(?i)^\s*(?:bearer|basic)\s+\S+")),
    ("inline_bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    (
        "inline_basic_auth",
        re.compile(
            r"\b[Bb][Aa][Ss][Ii][Cc]\s+"
            r"(?=(?:[A-Za-z0-9+/=]*[0-9+/=]|[A-Za-z0-9+/=]+[A-Z][A-Za-z0-9+/=]*))"
            r"[A-Za-z0-9+/=]{12,}(?![A-Za-z0-9+/=])"
        ),
    ),
    ("inline_auth_header", re.compile(r"(?i)\bauthorization\s*[:=]\s*(?:bearer|basic)\s+\S+")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)

_PULL_TERMINAL_STATUSES = frozenset({"done", "error", "cancelled"})


def _resolve_bus_dir(bus_dir: Optional[str] = None) -> str:
    if bus_dir and str(bus_dir).strip():
        return os.path.abspath(os.path.expanduser(str(bus_dir).strip()))
    env_dir = os.environ.get("AGY_BOT_BUS_DIR", "").strip()
    if env_dir:
        return os.path.abspath(os.path.expanduser(env_dir))
    return os.path.abspath(DEFAULT_BUS_DIR)


def federation_dir(bus_dir: Optional[str] = None) -> str:
    return os.path.join(_resolve_bus_dir(bus_dir), "federation")


def agents_file_path(bus_dir: Optional[str] = None) -> str:
    return os.path.join(federation_dir(bus_dir), "agents.json")


def teams_file_path(bus_dir: Optional[str] = None) -> str:
    return os.path.join(federation_dir(bus_dir), "teams.json")


def lock_file_path(bus_dir: Optional[str] = None) -> str:
    return os.path.join(federation_dir(bus_dir), "federation.lock")


def pull_queue_dir(bus_dir: Optional[str] = None) -> str:
    return os.path.join(federation_dir(bus_dir), "pull_queue")


def has_federation_state(bus_dir: Optional[str] = None) -> bool:
    """Return True iff `agents.json` or `teams.json` exists under `<BUS_DIR>/federation/`."""
    return os.path.isfile(agents_file_path(bus_dir)) or os.path.isfile(teams_file_path(bus_dir))


def _is_external_origin(origin: Any) -> bool:
    orig = str(origin or "").strip().lower()
    if not orig:
        return False
    if _memory_guard is not None:
        try:
            return bool(_memory_guard.is_external_agent_origin(orig))
        except Exception:
            pass
    return orig.startswith("remote") or orig not in (
        "local_bus",
        "local_tg",
        "local_web",
        "local_tg_fast",
        "local_owner",
    )


# ---------------------------------------------------------------- Identifier & Secret Validators
def validate_agent_id(agent_id: Any) -> str:
    """Strictly validate `agent_id` (`^[a-z0-9][a-z0-9_-]{0,63}$`, no traversal/dots/uppercase)."""
    if not isinstance(agent_id, str) or not agent_id:
        raise ValueError(f"Invalid agent_id: {agent_id!r}")
    if "." in agent_id or "/" in agent_id or "\\" in agent_id or "\x00" in agent_id or ".." in agent_id:
        raise ValueError(f"Unsafe agent_id rejected: {agent_id!r}")
    if not AGENT_ID_RE.fullmatch(agent_id):
        raise ValueError(
            f"Invalid agent_id format: {agent_id!r} (expected ^[a-z0-9][a-z0-9_-]{{0,63}}$)"
        )
    return agent_id


def validate_team_id(team_id: Any, *, allow_empty: bool = False) -> str:
    """Strictly validate `team_id` (`^[a-z0-9][a-z0-9_-]{1,63}$`, no traversal/dots/uppercase)."""
    if allow_empty and (team_id is None or team_id == ""):
        return ""
    if not isinstance(team_id, str) or not team_id:
        raise ValueError(f"Invalid team_id: {team_id!r}")
    if "." in team_id or "/" in team_id or "\\" in team_id or "\x00" in team_id or ".." in team_id:
        raise ValueError(f"Unsafe team_id rejected: {team_id!r}")
    if not TEAM_ID_RE.fullmatch(team_id):
        raise ValueError(
            f"Invalid team_id format: {team_id!r} (expected ^[a-z0-9][a-z0-9_-]{{1,63}}$)"
        )
    return team_id


def validate_profile_name(profile: Any, *, allow_empty: bool = False) -> str:
    """Strictly validate Hermes/agent profile name (`^[a-z0-9][a-z0-9_-]{0,63}$`)."""
    if allow_empty and (profile is None or profile == ""):
        return ""
    if not isinstance(profile, str) or not profile:
        raise ValueError(f"Invalid profile name: {profile!r}")
    if "." in profile or "/" in profile or "\\" in profile or "\x00" in profile or ".." in profile:
        raise ValueError(f"Unsafe profile name rejected: {profile!r}")
    if not PROFILE_NAME_RE.fullmatch(profile):
        raise ValueError(
            f"Invalid profile name format: {profile!r} (expected ^[a-z0-9][a-z0-9_-]{{0,63}}$)"
        )
    return profile


def validate_pull_job_id(job_id: Any) -> str:
    """Strictly validate Pull Worker `job_id` against traversal and unsafe characters."""
    if not isinstance(job_id, str) or not job_id:
        raise ValueError(f"Invalid pull job_id: {job_id!r}")
    if "." in job_id or "/" in job_id or "\\" in job_id or "\x00" in job_id or ".." in job_id:
        raise ValueError(f"Unsafe pull job_id rejected: {job_id!r}")
    if not PULL_JOB_ID_RE.fullmatch(job_id):
        raise ValueError(f"Invalid pull job_id format: {job_id!r}")
    return job_id


def validate_secret_ref(secret_ref: Any) -> str:
    """Validate an OpenBao `secret_ref` (`<mount>/<namespace>/<item>[#<field>]`); reject plaintext secrets."""
    if secret_ref is None or secret_ref == "":
        return ""
    if not isinstance(secret_ref, str):
        raise ValueError(f"Invalid secret_ref type: {type(secret_ref).__name__}")
    val = secret_ref.strip()
    if not val:
        return ""
    for rule, pat in _PLAINTEXT_SECRET_VALUE_RES:
        if pat.search(val):
            raise ValueError(
                f"PLAINTEXT_SECRET_REJECTED: secret_ref appears to contain a plaintext secret ({rule}); pass an OpenBao secret_ref path"
            )
    if ".." in val or "\r" in val or "\n" in val or "\x00" in val or " " in val:
        raise ValueError("Invalid secret_ref: contains forbidden path traversal or control characters")
    if not SECRET_REF_RE.fullmatch(val):
        raise ValueError(
            "Invalid secret_ref format: must be an OpenBao mount reference '<mount>/<namespace>/<item>[#<field>]'"
        )
    return val


def validate_endpoint_url_format(url: Any) -> str:
    """Syntactically validate an optional registered endpoint URL (http/https only, no userinfo, no CRLF)."""
    if url is None or url == "":
        return ""
    if not isinstance(url, str):
        raise ValueError(f"Invalid endpoint_url type: {type(url).__name__}")
    val = url.strip()
    if not val:
        return ""
    if any(ch in val for ch in ("\r", "\n", "\x00")):
        raise ValueError("Invalid endpoint_url: control/CRLF characters are forbidden")
    parsed = urlsplit(val)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Invalid endpoint_url scheme: {parsed.scheme!r} (only http/https allowed)")
    if not parsed.hostname:
        raise ValueError("Invalid endpoint_url: missing hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "PLAINTEXT_SECRET_REJECTED: endpoint_url must not embed credentials (use OpenBao secret_ref)"
        )
    for rule, pat in _PLAINTEXT_SECRET_VALUE_RES:
        if pat.search(val):
            raise ValueError(f"PLAINTEXT_SECRET_REJECTED: endpoint_url contains secret-like value ({rule})")
    return val


def reject_plaintext_secrets(obj: Any, *, path: str = "payload", _depth: int = 0) -> None:
    """Recursively reject raw secret field names and secret-like string values (C2)."""
    if _depth > 12:
        raise ValueError(f"Payload nesting too deep at {path}")
    if obj is None or isinstance(obj, (bool, int, float)):
        return
    if isinstance(obj, str):
        for rule, pat in _PLAINTEXT_SECRET_VALUE_RES:
            if pat.search(obj):
                raise ValueError(
                    f"PLAINTEXT_SECRET_REJECTED: field {path!r} contains plaintext secret pattern ({rule}); use OpenBao secret_ref"
                )
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            key_str = str(k)
            key_norm = key_str.strip().lower().replace("-", "_")
            if key_norm in FORBIDDEN_SECRET_KEYS or key_str.strip().lower() in FORBIDDEN_SECRET_KEYS:
                raise ValueError(
                    f"PLAINTEXT_SECRET_REJECTED: forbidden plaintext credential field {path}.{key_str!r}; use OpenBao 'secret_ref'"
                )
            reject_plaintext_secrets(v, path=f"{path}.{key_str}", _depth=_depth + 1)
        return
    if isinstance(obj, (list, tuple)):
        for idx, item in enumerate(obj):
            reject_plaintext_secrets(item, path=f"{path}[{idx}]", _depth=_depth + 1)
        return


def redact_secrets(text: str, extra_secrets: Sequence[str] = ()) -> str:
    """Scrub federation tokens, Authorization headers, and known secret strings from text."""
    out = str(text or "")
    for sec in extra_secrets:
        if sec and len(sec) >= 4:
            out = out.replace(sec, "[REDACTED]")
    out = re.sub(r"(?i)(authorization\s*[:=]\s*)(?:bearer|basic)\s+\S+", r"\1[REDACTED]", out)
    out = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}", r"\1 [REDACTED]", out)
    for _rule, pat in _PLAINTEXT_SECRET_VALUE_RES:
        out = pat.sub("[REDACTED]", out)
    return out


# ---------------------------------------------------------------- Owner-Only Write Auth (C1)
@dataclasses.dataclass(frozen=True)
class OwnerAuth:
    """Explicit Owner authorization token object required for every registry write API."""

    actor_id: str = "owner"
    is_owner: bool = False
    role: str = ""
    trust_level: str = ""
    agent_origin: str = ""
    untrusted: bool = False
    readonly: bool = False
    tainted: bool = False
    is_registered_agent: bool = False


def make_owner_auth(
    actor_id: str = "owner",
    *,
    env: Optional[Dict[str, str]] = None,
) -> OwnerAuth:
    """Construct an `OwnerAuth` context after verifying process env is not untrusted/readonly/external."""
    e = os.environ if env is None else env
    _check_env_clean_for_owner(e, action="make_owner_auth")
    clean_actor = str(actor_id or "owner").strip() or "owner"
    return OwnerAuth(
        actor_id=clean_actor,
        is_owner=True,
        role="owner",
        trust_level="local_admin",
        agent_origin="local_owner",
        untrusted=False,
        readonly=False,
        tainted=False,
        is_registered_agent=False,
    )


def _check_env_clean_for_owner(env: Dict[str, str], *, action: str) -> None:
    if str(env.get("AGY_UNTRUSTED_SESSION") or "").strip() == "1":
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: untrusted session cannot perform {action}"
        )
    if str(env.get("AGY_MEMORY_READONLY") or "").strip() == "1":
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: memory-readonly/tainted session cannot perform {action}"
        )
    if str(env.get("AGY_RBAC_ROLE") or "").strip().lower() == "readonly":
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: readonly RBAC session cannot perform {action}"
        )
    origin = str(env.get("AGY_AGENT_ORIGIN") or "").strip().lower()
    if origin and _is_external_origin(origin):
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: external origin {origin!r} cannot perform {action}"
        )
    trust = str(env.get("AGY_TRUST_LEVEL") or "").strip().lower()
    if trust and trust not in ("local_admin",):
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: non-owner trust_level {trust!r} cannot perform {action}"
        )
    bus_role = str(env.get("AGY_BOT_BUS_ROLE") or "").strip().lower()
    if bus_role in ("worker", "peer", "coordinator_peer"):
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: bus role {bus_role!r} cannot perform owner action {action}"
        )


def assert_owner_auth(
    owner_auth: Any,
    *,
    action: str,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> OwnerAuth:
    """Fail-closed owner authorization gate for all federation registry mutations (C1).

    Rejects:
    - `None` or non-Owner contexts (`is_owner is not True`)
    - Workers, peers, `coordinator_peer`, registered external agents, or tainted/readonly callers
    - Processes running with untrusted/readonly/external/worker environment markers
    """
    if owner_auth is None:
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: missing owner authorization for {action}"
        )

    if isinstance(owner_auth, OwnerAuth):
        ctx = owner_auth
    elif isinstance(owner_auth, dict):
        ctx = OwnerAuth(
            actor_id=str(owner_auth.get("actor_id") or "").strip(),
            is_owner=owner_auth.get("is_owner") is True,
            role=str(owner_auth.get("role") or "").strip().lower(),
            trust_level=str(owner_auth.get("trust_level") or "").strip().lower(),
            agent_origin=str(owner_auth.get("agent_origin") or "").strip().lower(),
            untrusted=bool(owner_auth.get("untrusted", False)),
            readonly=bool(owner_auth.get("readonly", False)),
            tainted=bool(owner_auth.get("tainted", False)),
            is_registered_agent=bool(owner_auth.get("is_registered_agent", False)),
        )
    else:
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: invalid owner_auth type {type(owner_auth).__name__} for {action}"
        )

    if ctx.is_owner is not True:
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: non-owner caller ({ctx.actor_id or 'anonymous'}, role={ctx.role or 'none'}) denied for {action}"
        )
    if ctx.untrusted or ctx.readonly or ctx.tainted or ctx.is_registered_agent:
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: restricted/agent caller denied for {action}"
        )
    role_low = str(ctx.role or "").strip().lower()
    if role_low not in ("", "owner", "local_owner"):
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: role {role_low!r} is not Owner and cannot perform {action}"
        )
    trust_low = str(ctx.trust_level or "").strip().lower()
    if trust_low and trust_low != "local_admin":
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: trust_level {trust_low!r} cannot perform {action}"
        )
    origin_low = str(ctx.agent_origin or "").strip().lower()
    if origin_low and _is_external_origin(origin_low):
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: external origin {origin_low!r} cannot perform {action}"
        )

    e = os.environ if env is None else env
    _check_env_clean_for_owner(e, action=action)

    # Even if an external/federation agent (including a coordinator_peer) tries to pass is_owner=True
    # with its agent_id as actor_id, reject if actor_id matches any registered agent in agents.json.
    actor_norm = str(ctx.actor_id or "").strip().lower()
    if actor_norm and os.path.isfile(agents_file_path(bus_dir)):
        agents_data = _read_json(agents_file_path(bus_dir), {"agents": {}})
        agents_map = agents_data.get("agents") if isinstance(agents_data, dict) else {}
        if isinstance(agents_map, dict) and actor_norm in agents_map:
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: registered agent {actor_norm!r} (even coordinator_peer) cannot perform owner mutation {action}"
            )

    return ctx


# ---------------------------------------------------------------- Atomic Storage & Flock Helpers
def _ensure_secure_dir(path: str) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _read_json(path: str, default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return copy.deepcopy(default) if default is not None else {}


def _atomic_write_json(path: str, payload: Any) -> None:
    parent = os.path.dirname(path)
    _ensure_secure_dir(parent)
    tmp = f"{path}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass
        raise


@contextlib.contextmanager
def _registry_lock(bus_dir: Optional[str] = None, *, shared: bool = False):
    fdir = federation_dir(bus_dir)
    _ensure_secure_dir(fdir)
    lpath = lock_file_path(bus_dir)
    fd = os.open(lpath, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.chmod(lpath, 0o600)
        with os.fdopen(fd, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    except Exception:
        raise


def _load_agents_unlocked(bus_dir: Optional[str] = None) -> Dict[str, Any]:
    path = agents_file_path(bus_dir)
    if not os.path.isfile(path):
        return {"version": 1, "agents": {}}
    data = _read_json(path, {"version": 1, "agents": {}})
    if not isinstance(data, dict) or not isinstance(data.get("agents"), dict):
        return {"version": 1, "agents": {}}
    return data


def _load_teams_unlocked(bus_dir: Optional[str] = None) -> Dict[str, Any]:
    path = teams_file_path(bus_dir)
    if not os.path.isfile(path):
        return {"version": 1, "teams": {}}
    data = _read_json(path, {"version": 1, "teams": {}})
    if not isinstance(data, dict) or not isinstance(data.get("teams"), dict):
        return {"version": 1, "teams": {}}
    return data


def _load_legacy_team_config(bus_dir: Optional[str] = None) -> Dict[str, Any]:
    cfg_path = os.path.join(_resolve_bus_dir(bus_dir), "team_config.json")
    if not os.path.isfile(cfg_path):
        return {"version": 1, "bots": {}}
    data = _read_json(cfg_path, {"version": 1, "bots": {}})
    if not isinstance(data, dict) or not isinstance(data.get("bots"), dict):
        return {"version": 1, "bots": {}}
    return data


def _load_legacy_roster(bus_dir: Optional[str] = None) -> Dict[str, Any]:
    r_path = os.path.join(_resolve_bus_dir(bus_dir), "roster.json")
    if not os.path.isfile(r_path):
        return {"version": 1, "bots": {}}
    data = _read_json(r_path, {"version": 1, "bots": {}})
    if not isinstance(data, dict) or not isinstance(data.get("bots"), dict):
        return {"version": 1, "bots": {}}
    return data


# ---------------------------------------------------------------- Sanitization & Token Hashing
def _hash_token(salt_hex: str, raw_token: str) -> str:
    return hmac.new(
        bytes.fromhex(salt_hex),
        raw_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def sanitize_agent_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deep copy of an agent record with all token hashes, salts, and secrets stripped."""
    if not isinstance(rec, dict):
        return {}
    out = copy.deepcopy(rec)
    raw_tokens = out.pop("token_records", None)
    active_count = 0
    if isinstance(raw_tokens, list):
        for tr in raw_tokens:
            if isinstance(tr, dict) and tr.get("revoked_at") is None:
                active_count += 1
    for secret_k in list(out.keys()):
        if secret_k.lower() in FORBIDDEN_SECRET_KEYS or secret_k in ("salt", "token_hash", "token_records"):
            out.pop(secret_k, None)
    out["active_token_count"] = active_count
    out["has_active_token"] = active_count > 0
    return out


def _normalize_capabilities(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    src = dict(raw or {})
    reject_plaintext_secrets(src, path="capabilities")
    raw_teams = src.get("allowed_teams") or []
    if not isinstance(raw_teams, (list, tuple, set)):
        raise ValueError("capabilities.allowed_teams must be a list of team_id strings")
    allowed_teams: List[str] = []
    seen: set[str] = set()
    for tid in raw_teams:
        clean_tid = validate_team_id(tid)
        if clean_tid not in seen:
            seen.add(clean_tid)
            allowed_teams.append(clean_tid)
    coord_peer = bool(src.get("coordinator_peer", False))
    if "can_dispatch" in src and src.get("can_dispatch") is not None:
        can_dispatch = bool(src.get("can_dispatch"))
    else:
        can_dispatch = coord_peer
    return {
        "coordinator_peer": coord_peer,
        "host_server_invoke": bool(src.get("host_server_invoke", False)),
        "allowed_teams": allowed_teams,
        "can_dispatch": can_dispatch,
        "can_receive": bool(src.get("can_receive", True)),
    }


def _default_driver_and_transport(kind: str) -> Tuple[str, str]:
    mapping = {
        "agy_local": ("agy", "local_cli"),
        "hermes_local": ("hermes_local", "local_cli"),
        "hermes_remote": ("hermes_remote", "hermes_api"),
        "muse_remote": ("http_external", "http_push"),
        "http_a2a": ("http_external", "http_push"),
        "mcp_inbound_only": ("mcp_inbound_only", "mcp_inbound"),
    }
    return mapping[kind]


def _normalize_trust_level(trust_level: Optional[str], *, kind: str) -> str:
    if trust_level is None or str(trust_level).strip() == "":
        return "local_worker" if kind == "agy_local" else "remote_trusted"
    norm = str(trust_level).strip().lower()
    if norm not in TRUST_ORDER:
        raise ValueError(f"Invalid trust_level: {trust_level!r} (allowed: {sorted(TRUST_ORDER)})")
    return norm


# ---------------------------------------------------------------- Agent CRUD & Token Lifecycle
def register_agent(
    agent_id: str,
    *,
    kind: str,
    owner_auth: Any,
    display_name: str = "",
    driver: str = "",
    profile: str = "",
    endpoint_url: str = "",
    secret_ref: str = "",
    transport: str = "",
    capabilities: Optional[Dict[str, Any]] = None,
    trust_level: Optional[str] = None,
    enabled: bool = True,
    metadata: Optional[Dict[str, Any]] = None,
    overwrite: bool = False,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    **extra_kwargs: Any,
) -> Dict[str, Any]:
    """Register an external or local federated Agent (Owner-only, zero plaintext secrets)."""
    assert_owner_auth(owner_auth, action="register_agent", bus_dir=bus_dir, env=env)
    if extra_kwargs:
        reject_plaintext_secrets(extra_kwargs, path="register_agent")
        raise ValueError(f"Unexpected keyword argument(s): {sorted(extra_kwargs.keys())}")

    aid = validate_agent_id(agent_id)
    norm_kind = str(kind or "").strip().lower()
    if norm_kind not in VALID_AGENT_KINDS:
        raise ValueError(f"Invalid agent kind: {kind!r} (allowed: {sorted(VALID_AGENT_KINDS)})")

    default_drv, default_tr = _default_driver_and_transport(norm_kind)
    norm_driver = str(driver or default_drv).strip().lower()
    if norm_driver not in VALID_DRIVERS:
        raise ValueError(f"Invalid driver: {driver!r} (allowed: {sorted(VALID_DRIVERS)})")
    norm_transport = str(transport or default_tr).strip().lower()
    if norm_transport not in VALID_TRANSPORTS:
        raise ValueError(f"Invalid transport: {transport!r} (allowed: {sorted(VALID_TRANSPORTS)})")

    clean_profile = validate_profile_name(profile, allow_empty=(norm_kind != "hermes_local"))
    clean_url = validate_endpoint_url_format(endpoint_url)
    clean_secret_ref = validate_secret_ref(secret_ref)
    clean_caps = _normalize_capabilities(capabilities)
    clean_trust = _normalize_trust_level(trust_level, kind=norm_kind)
    clean_meta = copy.deepcopy(metadata) if isinstance(metadata, dict) else {}
    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("metadata must be a dict")
    reject_plaintext_secrets(clean_meta, path="metadata")
    clean_display = str(display_name or aid).strip()[:120]
    reject_plaintext_secrets(clean_display, path="display_name")

    now = time.time()
    with _registry_lock(bus_dir):
        data = _load_agents_unlocked(bus_dir)
        agents = data.setdefault("agents", {})
        if aid in agents and not overwrite:
            raise ValueError(f"Agent already registered: {aid!r} (pass overwrite=True to replace)")
        prev_tokens = list(agents[aid].get("token_records") or []) if (aid in agents and overwrite) else []
        created_at = float(agents[aid].get("created_at") or now) if (aid in agents and overwrite) else now
        record = {
            "agent_id": aid,
            "display_name": clean_display,
            "kind": norm_kind,
            "driver": norm_driver,
            "profile": clean_profile,
            "endpoint_url": clean_url,
            "secret_ref": clean_secret_ref,
            "transport": norm_transport,
            "capabilities": clean_caps,
            "trust_level": clean_trust,
            "enabled": bool(enabled),
            "revoked": False,
            "token_records": prev_tokens,
            "metadata": clean_meta,
            "created_at": created_at,
            "updated_at": now,
        }
        agents[aid] = record
        _atomic_write_json(agents_file_path(bus_dir), data)
        return sanitize_agent_record(record)


def update_agent(
    agent_id: str,
    *,
    owner_auth: Any,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    **updates: Any,
) -> Dict[str, Any]:
    """Update fields on a registered agent (Owner-only, zero plaintext secrets)."""
    assert_owner_auth(owner_auth, action="update_agent", bus_dir=bus_dir, env=env)
    reject_plaintext_secrets(updates, path="update_agent")
    aid = validate_agent_id(agent_id)

    allowed_fields = frozenset(
        {
            "display_name",
            "kind",
            "driver",
            "profile",
            "endpoint_url",
            "secret_ref",
            "transport",
            "capabilities",
            "trust_level",
            "enabled",
            "revoked",
            "metadata",
        }
    )
    unknown = set(updates.keys()) - allowed_fields
    if unknown:
        raise ValueError(f"Unsupported update_agent field(s): {sorted(unknown)}")

    with _registry_lock(bus_dir):
        data = _load_agents_unlocked(bus_dir)
        agents = data.setdefault("agents", {})
        if aid not in agents:
            raise ValueError(f"Unknown agent_id: {aid!r}")
        rec = copy.deepcopy(agents[aid])
        if "display_name" in updates:
            rec["display_name"] = str(updates["display_name"] or aid).strip()[:120]
        if "kind" in updates:
            nk = str(updates["kind"] or "").strip().lower()
            if nk not in VALID_AGENT_KINDS:
                raise ValueError(f"Invalid agent kind: {updates['kind']!r}")
            rec["kind"] = nk
        if "driver" in updates:
            nd = str(updates["driver"] or "").strip().lower()
            if nd not in VALID_DRIVERS:
                raise ValueError(f"Invalid driver: {updates['driver']!r}")
            rec["driver"] = nd
        if "transport" in updates:
            nt = str(updates["transport"] or "").strip().lower()
            if nt not in VALID_TRANSPORTS:
                raise ValueError(f"Invalid transport: {updates['transport']!r}")
            rec["transport"] = nt
        if "profile" in updates:
            rec["profile"] = validate_profile_name(
                updates["profile"], allow_empty=(rec["kind"] != "hermes_local")
            )
        if "endpoint_url" in updates:
            rec["endpoint_url"] = validate_endpoint_url_format(updates["endpoint_url"])
        if "secret_ref" in updates:
            rec["secret_ref"] = validate_secret_ref(updates["secret_ref"])
        if "capabilities" in updates:
            merged_caps = dict(rec.get("capabilities") or {})
            if not isinstance(updates["capabilities"], dict):
                raise ValueError("capabilities must be a dict")
            merged_caps.update(updates["capabilities"])
            rec["capabilities"] = _normalize_capabilities(merged_caps)
        if "trust_level" in updates:
            rec["trust_level"] = _normalize_trust_level(updates["trust_level"], kind=rec["kind"])
        if "enabled" in updates:
            rec["enabled"] = bool(updates["enabled"])
        if "revoked" in updates:
            rec["revoked"] = bool(updates["revoked"])
            if rec["revoked"]:
                rec["enabled"] = False
        if "metadata" in updates:
            if not isinstance(updates["metadata"], dict):
                raise ValueError("metadata must be a dict")
            reject_plaintext_secrets(updates["metadata"], path="metadata")
            rec["metadata"] = copy.deepcopy(updates["metadata"])
        if rec.get("kind") == "hermes_local":
            rec["profile"] = validate_profile_name(rec.get("profile"), allow_empty=False)
        rec["updated_at"] = time.time()
        agents[aid] = rec
        _atomic_write_json(agents_file_path(bus_dir), data)
        return sanitize_agent_record(rec)


def delete_agent(
    agent_id: str,
    *,
    owner_auth: Any,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> bool:
    """Remove an agent from the registry (Owner-only)."""
    assert_owner_auth(owner_auth, action="delete_agent", bus_dir=bus_dir, env=env)
    aid = validate_agent_id(agent_id)
    with _registry_lock(bus_dir):
        data = _load_agents_unlocked(bus_dir)
        agents = data.setdefault("agents", {})
        if aid not in agents:
            return False
        agents.pop(aid, None)
        _atomic_write_json(agents_file_path(bus_dir), data)
        return True


def get_agent(agent_id: str, *, bus_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return sanitized agent view (no tokens/hashes), or None if absent. Never creates files."""
    aid = validate_agent_id(agent_id)
    if not os.path.isfile(agents_file_path(bus_dir)):
        return None
    with _registry_lock(bus_dir, shared=True):
        data = _load_agents_unlocked(bus_dir)
        rec = (data.get("agents") or {}).get(aid)
        return sanitize_agent_record(rec) if isinstance(rec, dict) else None


def list_agents(
    *,
    bus_dir: Optional[str] = None,
    include_disabled: bool = True,
    include_revoked: bool = False,
) -> List[Dict[str, Any]]:
    """Return sanitized list of registered federation agents. Never creates files."""
    if not os.path.isfile(agents_file_path(bus_dir)):
        return []
    with _registry_lock(bus_dir, shared=True):
        data = _load_agents_unlocked(bus_dir)
        out: List[Dict[str, Any]] = []
        for aid in sorted((data.get("agents") or {}).keys()):
            rec = data["agents"][aid]
            if not isinstance(rec, dict):
                continue
            if not include_revoked and rec.get("revoked"):
                continue
            if not include_disabled and not rec.get("enabled", True):
                continue
            out.append(sanitize_agent_record(rec))
        return out


def mint_agent_token(
    agent_id: str,
    *,
    owner_auth: Any,
    label: str = "",
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Mint a high-entropy bearer token for `agent_id`, storing ONLY salted HMAC-SHA256 hash."""
    assert_owner_auth(owner_auth, action="mint_agent_token", bus_dir=bus_dir, env=env)
    aid = validate_agent_id(agent_id)
    clean_label = str(label or "").strip()[:80]
    reject_plaintext_secrets(clean_label, path="label")

    token_id = f"tok_{uuid.uuid4().hex[:12]}"
    secret_part = secrets.token_urlsafe(32)
    raw_token = f"{TOKEN_PREFIX}{aid}.{token_id}.{secret_part}"
    salt_hex = secrets.token_hex(16)
    token_hash = _hash_token(salt_hex, raw_token)
    now = time.time()

    with _registry_lock(bus_dir):
        data = _load_agents_unlocked(bus_dir)
        agents = data.setdefault("agents", {})
        rec = agents.get(aid)
        if not isinstance(rec, dict):
            raise ValueError(f"Unknown agent_id: {aid!r}")
        if rec.get("revoked"):
            raise ValueError(f"Cannot mint token for revoked agent: {aid!r}")
        records = list(rec.get("token_records") or [])
        records.append(
            {
                "token_id": token_id,
                "salt": salt_hex,
                "token_hash": token_hash,
                "label": clean_label,
                "created_at": now,
                "revoked_at": None,
            }
        )
        rec["token_records"] = records
        rec["updated_at"] = now
        agents[aid] = rec
        _atomic_write_json(agents_file_path(bus_dir), data)

    return {
        "agent_id": aid,
        "token_id": token_id,
        "token": raw_token,
        "created_at": now,
    }


def rotate_agent_token(
    agent_id: str,
    *,
    owner_auth: Any,
    revoke_existing: bool = True,
    label: str = "rotated",
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Atomically revoke existing tokens (when `revoke_existing=True`) and mint a replacement token."""
    assert_owner_auth(owner_auth, action="rotate_agent_token", bus_dir=bus_dir, env=env)
    aid = validate_agent_id(agent_id)
    clean_label = str(label or "rotated").strip()[:80]
    reject_plaintext_secrets(clean_label, path="label")

    token_id = f"tok_{uuid.uuid4().hex[:12]}"
    secret_part = secrets.token_urlsafe(32)
    raw_token = f"{TOKEN_PREFIX}{aid}.{token_id}.{secret_part}"
    salt_hex = secrets.token_hex(16)
    token_hash = _hash_token(salt_hex, raw_token)
    now = time.time()
    revoked_count = 0

    with _registry_lock(bus_dir):
        data = _load_agents_unlocked(bus_dir)
        agents = data.setdefault("agents", {})
        rec = agents.get(aid)
        if not isinstance(rec, dict):
            raise ValueError(f"Unknown agent_id: {aid!r}")
        if rec.get("revoked"):
            raise ValueError(f"Cannot rotate token for revoked agent: {aid!r}")
        records = list(rec.get("token_records") or [])
        if revoke_existing:
            for tr in records:
                if isinstance(tr, dict) and tr.get("revoked_at") is None:
                    tr["revoked_at"] = now
                    revoked_count += 1
        records.append(
            {
                "token_id": token_id,
                "salt": salt_hex,
                "token_hash": token_hash,
                "label": clean_label,
                "created_at": now,
                "revoked_at": None,
            }
        )
        rec["token_records"] = records
        rec["updated_at"] = now
        agents[aid] = rec
        _atomic_write_json(agents_file_path(bus_dir), data)

    return {
        "agent_id": aid,
        "token_id": token_id,
        "token": raw_token,
        "revoked_previous": revoked_count,
        "created_at": now,
    }


def revoke_agent_token(
    agent_id: str,
    *,
    owner_auth: Any,
    token_id: Optional[str] = None,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> int:
    """Atomically revoke one `token_id` or all active tokens for `agent_id`. Returns count revoked."""
    assert_owner_auth(owner_auth, action="revoke_agent_token", bus_dir=bus_dir, env=env)
    aid = validate_agent_id(agent_id)
    now = time.time()
    revoked = 0

    with _registry_lock(bus_dir):
        data = _load_agents_unlocked(bus_dir)
        agents = data.setdefault("agents", {})
        rec = agents.get(aid)
        if not isinstance(rec, dict):
            raise ValueError(f"Unknown agent_id: {aid!r}")
        for tr in rec.get("token_records") or []:
            if not isinstance(tr, dict) or tr.get("revoked_at") is not None:
                continue
            if token_id is None or tr.get("token_id") == token_id:
                tr["revoked_at"] = now
                revoked += 1
        rec["updated_at"] = now
        agents[aid] = rec
        _atomic_write_json(agents_file_path(bus_dir), data)
    return revoked


def revoke_agent(
    agent_id: str,
    *,
    owner_auth: Any,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Atomically revoke an agent (`revoked=True`, `enabled=False`) and all its tokens."""
    assert_owner_auth(owner_auth, action="revoke_agent", bus_dir=bus_dir, env=env)
    aid = validate_agent_id(agent_id)
    now = time.time()
    with _registry_lock(bus_dir):
        data = _load_agents_unlocked(bus_dir)
        agents = data.setdefault("agents", {})
        rec = agents.get(aid)
        if not isinstance(rec, dict):
            raise ValueError(f"Unknown agent_id: {aid!r}")
        rec["revoked"] = True
        rec["enabled"] = False
        for tr in rec.get("token_records") or []:
            if isinstance(tr, dict) and tr.get("revoked_at") is None:
                tr["revoked_at"] = now
        rec["updated_at"] = now
        agents[aid] = rec
        _atomic_write_json(agents_file_path(bus_dir), data)
        return sanitize_agent_record(rec)


def verify_agent_token(
    raw_token: Any,
    *,
    agent_id: Optional[str] = None,
    bus_dir: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Verify a bearer token against salted HMAC-SHA256 digests under `flock`.

    Returns sanitized agent view on success, or `None` on invalid/revoked/disabled token.
    Never logs or echoes `raw_token`.
    """
    if not isinstance(raw_token, str) or not raw_token.startswith(TOKEN_PREFIX):
        return None
    if any(ch in raw_token for ch in ("\r", "\n", "\x00", " ")):
        return None
    rest = raw_token[len(TOKEN_PREFIX) :]
    parts = rest.split(".", 2)
    if len(parts) != 3:
        return None
    tok_agent_id, tok_id, _secret = parts
    try:
        tok_agent_id = validate_agent_id(tok_agent_id)
    except ValueError:
        return None
    if agent_id is not None:
        try:
            expected_aid = validate_agent_id(agent_id)
        except ValueError:
            return None
        if tok_agent_id != expected_aid:
            return None

    if not os.path.isfile(agents_file_path(bus_dir)):
        return None

    with _registry_lock(bus_dir, shared=True):
        data = _load_agents_unlocked(bus_dir)
        rec = (data.get("agents") or {}).get(tok_agent_id)
        if not isinstance(rec, dict):
            return None
        if rec.get("revoked") or not rec.get("enabled", True):
            return None
        for tr in rec.get("token_records") or []:
            if not isinstance(tr, dict):
                continue
            if tr.get("revoked_at") is not None:
                continue
            if tr.get("token_id") != tok_id:
                continue
            salt_hex = str(tr.get("salt") or "")
            stored_hash = str(tr.get("token_hash") or "")
            if not salt_hex or not stored_hash:
                continue
            try:
                computed = _hash_token(salt_hex, raw_token)
            except ValueError:
                continue
            if hmac.compare_digest(computed, stored_hash):
                return sanitize_agent_record(rec)
    return None


# ---------------------------------------------------------------- Multi-Team CRUD (C1, C3)
def _known_valid_agent_ids_unlocked(bus_dir: Optional[str] = None) -> set[str]:
    known: set[str] = set()
    agents_data = _load_agents_unlocked(bus_dir)
    for aid, rec in (agents_data.get("agents") or {}).items():
        if isinstance(rec, dict) and not rec.get("revoked"):
            known.add(aid)
    legacy_cfg = _load_legacy_team_config(bus_dir)
    for h in (legacy_cfg.get("bots") or {}).keys():
        known.add(str(h).strip().lower())
    legacy_roster = _load_legacy_roster(bus_dir)
    for h in (legacy_roster.get("bots") or {}).keys():
        known.add(str(h).strip().lower())
    return known


def create_team(
    team_id: str,
    *,
    owner_auth: Any,
    display_name: str = "",
    leader_agent_id: str = "",
    co_leaders: Optional[Sequence[str]] = None,
    members: Optional[Sequence[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    require_registered: bool = True,
    overwrite: bool = False,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Create a named team with an arbitrary Owner-selected `leader_agent_id` (Owner-only)."""
    assert_owner_auth(owner_auth, action="create_team", bus_dir=bus_dir, env=env)
    tid = validate_team_id(team_id)
    clean_display = str(display_name or tid).strip()[:120]
    reject_plaintext_secrets(clean_display, path="display_name")
    clean_meta = copy.deepcopy(metadata) if isinstance(metadata, dict) else {}
    if metadata is not None and not isinstance(metadata, dict):
        raise ValueError("metadata must be a dict")
    reject_plaintext_secrets(clean_meta, path="metadata")

    clean_leader = validate_agent_id(leader_agent_id) if leader_agent_id else ""
    clean_co: List[str] = []
    for cl in co_leaders or ():
        cid = validate_agent_id(cl)
        if cid != clean_leader and cid not in clean_co:
            clean_co.append(cid)

    clean_members: List[str] = []
    for m in members or ():
        mid = validate_agent_id(m)
        if mid not in clean_members:
            clean_members.append(mid)
    for required_m in ([clean_leader] if clean_leader else []) + clean_co:
        if required_m not in clean_members:
            clean_members.append(required_m)

    now = time.time()
    with _registry_lock(bus_dir):
        if require_registered:
            known = _known_valid_agent_ids_unlocked(bus_dir)
            for aid in ([clean_leader] if clean_leader else []) + clean_co + clean_members:
                if aid not in known:
                    raise ValueError(
                        f"Agent {aid!r} is not registered or is revoked; register it before assigning to team {tid!r}"
                    )
        data = _load_teams_unlocked(bus_dir)
        teams = data.setdefault("teams", {})
        if tid in teams and not overwrite:
            raise ValueError(f"Team already exists: {tid!r}")
        created_at = float(teams[tid].get("created_at") or now) if (tid in teams and overwrite) else now
        team = {
            "team_id": tid,
            "display_name": clean_display,
            "leader_agent_id": clean_leader,
            "co_leaders": clean_co,
            "members": clean_members,
            "metadata": clean_meta,
            "created_at": created_at,
            "updated_at": now,
        }
        teams[tid] = team
        _atomic_write_json(teams_file_path(bus_dir), data)
        return copy.deepcopy(team)


def update_team(
    team_id: str,
    *,
    owner_auth: Any,
    display_name: Optional[str] = None,
    leader_agent_id: Optional[str] = None,
    co_leaders: Optional[Sequence[str]] = None,
    members: Optional[Sequence[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    require_registered: bool = True,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Update team settings (Owner-only)."""
    assert_owner_auth(owner_auth, action="update_team", bus_dir=bus_dir, env=env)
    tid = validate_team_id(team_id)
    if metadata is not None:
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be a dict")
        reject_plaintext_secrets(metadata, path="metadata")
    if display_name is not None:
        reject_plaintext_secrets(display_name, path="display_name")

    with _registry_lock(bus_dir):
        data = _load_teams_unlocked(bus_dir)
        teams = data.setdefault("teams", {})
        if tid not in teams:
            raise ValueError(f"Unknown team_id: {tid!r}")
        team = copy.deepcopy(teams[tid])
        if display_name is not None:
            team["display_name"] = str(display_name or tid).strip()[:120]
        if leader_agent_id is not None:
            team["leader_agent_id"] = validate_agent_id(leader_agent_id) if leader_agent_id else ""
        if co_leaders is not None:
            new_co: List[str] = []
            for cl in co_leaders:
                cid = validate_agent_id(cl)
                if cid != team["leader_agent_id"] and cid not in new_co:
                    new_co.append(cid)
            team["co_leaders"] = new_co
        if members is not None:
            new_members: List[str] = []
            for m in members:
                mid = validate_agent_id(m)
                if mid not in new_members:
                    new_members.append(mid)
            team["members"] = new_members
        for req_m in ([team["leader_agent_id"]] if team["leader_agent_id"] else []) + list(team["co_leaders"]):
            if req_m not in team["members"]:
                team["members"].append(req_m)
        if metadata is not None:
            team["metadata"] = copy.deepcopy(metadata)
        if require_registered:
            known = _known_valid_agent_ids_unlocked(bus_dir)
            for aid in ([team["leader_agent_id"]] if team["leader_agent_id"] else []) + list(team["co_leaders"]) + list(team["members"]):
                if aid not in known:
                    raise ValueError(f"Agent {aid!r} is not registered or is revoked")
        team["updated_at"] = time.time()
        teams[tid] = team
        _atomic_write_json(teams_file_path(bus_dir), data)
        return copy.deepcopy(team)


def set_team_leader(
    team_id: str,
    leader_agent_id: str,
    *,
    owner_auth: Any,
    co_leaders: Optional[Sequence[str]] = None,
    require_registered: bool = True,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Designate ANY registered agent (local/remote Hermes, Muse, or agy bot) as `leader_agent_id` (Owner-only)."""
    assert_owner_auth(owner_auth, action="set_team_leader", bus_dir=bus_dir, env=env)
    return update_team(
        team_id,
        owner_auth=owner_auth,
        leader_agent_id=validate_agent_id(leader_agent_id),
        co_leaders=co_leaders,
        require_registered=require_registered,
        bus_dir=bus_dir,
        env=env,
    )


def add_team_member(
    team_id: str,
    agent_id: str,
    *,
    owner_auth: Any,
    require_registered: bool = True,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Add an agent to a team (Owner-only)."""
    assert_owner_auth(owner_auth, action="add_team_member", bus_dir=bus_dir, env=env)
    tid = validate_team_id(team_id)
    aid = validate_agent_id(agent_id)
    with _registry_lock(bus_dir):
        if require_registered:
            known = _known_valid_agent_ids_unlocked(bus_dir)
            if aid not in known:
                raise ValueError(f"Agent {aid!r} is not registered or is revoked")
        data = _load_teams_unlocked(bus_dir)
        teams = data.setdefault("teams", {})
        if tid not in teams:
            raise ValueError(f"Unknown team_id: {tid!r}")
        team = copy.deepcopy(teams[tid])
        if aid not in team["members"]:
            team["members"].append(aid)
        team["updated_at"] = time.time()
        teams[tid] = team
        _atomic_write_json(teams_file_path(bus_dir), data)
        return copy.deepcopy(team)


def remove_team_member(
    team_id: str,
    agent_id: str,
    *,
    owner_auth: Any,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Remove an agent from a team (also strips co-leader/leader if removed; Owner-only)."""
    assert_owner_auth(owner_auth, action="remove_team_member", bus_dir=bus_dir, env=env)
    tid = validate_team_id(team_id)
    aid = validate_agent_id(agent_id)
    with _registry_lock(bus_dir):
        data = _load_teams_unlocked(bus_dir)
        teams = data.setdefault("teams", {})
        if tid not in teams:
            raise ValueError(f"Unknown team_id: {tid!r}")
        team = copy.deepcopy(teams[tid])
        team["members"] = [m for m in team.get("members") or [] if m != aid]
        team["co_leaders"] = [c for c in team.get("co_leaders") or [] if c != aid]
        if team.get("leader_agent_id") == aid:
            team["leader_agent_id"] = ""
        team["updated_at"] = time.time()
        teams[tid] = team
        _atomic_write_json(teams_file_path(bus_dir), data)
        return copy.deepcopy(team)


def delete_team(
    team_id: str,
    *,
    owner_auth: Any,
    bus_dir: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> bool:
    """Delete a team definition (Owner-only)."""
    assert_owner_auth(owner_auth, action="delete_team", bus_dir=bus_dir, env=env)
    tid = validate_team_id(team_id)
    with _registry_lock(bus_dir):
        data = _load_teams_unlocked(bus_dir)
        teams = data.setdefault("teams", {})
        if tid not in teams:
            return False
        teams.pop(tid, None)
        _atomic_write_json(teams_file_path(bus_dir), data)
        return True


def get_team(team_id: str, *, bus_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
    tid = validate_team_id(team_id)
    if not os.path.isfile(teams_file_path(bus_dir)):
        return None
    with _registry_lock(bus_dir, shared=True):
        data = _load_teams_unlocked(bus_dir)
        team = (data.get("teams") or {}).get(tid)
        return copy.deepcopy(team) if isinstance(team, dict) else None


def list_teams(*, bus_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    if not os.path.isfile(teams_file_path(bus_dir)):
        return []
    with _registry_lock(bus_dir, shared=True):
        data = _load_teams_unlocked(bus_dir)
        teams = data.get("teams") or {}
        return [copy.deepcopy(teams[tid]) for tid in sorted(teams.keys()) if isinstance(teams[tid], dict)]


# ---------------------------------------------------------------- Server-Side Authority Resolution (C3, C4)
def resolve_actor_authority(
    actor_id: str,
    *,
    bus_dir: Optional[str] = None,
    auth_token: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Resolve authoritative server-side privileges for `actor_id` from `federation` + `team_config.json`.

    Never trusts forged process environment variables (`AGY_BOT_BUS_ROLE=coordinator`,
    `AGY_TRUST_LEVEL=local_admin`) when server-side config/registry does not grant authority.
    Never creates `<BUS_DIR>/federation/` when absent (C8 backward compatibility).
    """
    raw_actor = str(actor_id or "").strip().lstrip("@").lower()
    if not raw_actor:
        return {
            "actor_id": "",
            "authorized": False,
            "reason": "missing_actor_id",
            "is_coordinator_peer": False,
            "is_legacy_coordinator": False,
            "is_legacy_peer": False,
            "host_server_invoke": False,
            "led_teams": [],
            "member_teams": [],
            "agent": None,
            "token_verified": False,
            "federation_active": has_federation_state(bus_dir),
        }

    fed_active = has_federation_state(bus_dir)
    agents_map: Dict[str, Any] = {}
    teams_map: Dict[str, Any] = {}
    if fed_active:
        with _registry_lock(bus_dir, shared=True):
            agents_map = dict((_load_agents_unlocked(bus_dir).get("agents") or {}))
            teams_map = dict((_load_teams_unlocked(bus_dir).get("teams") or {}))

    legacy_cfg = _load_legacy_team_config(bus_dir)
    legacy_bots = legacy_cfg.get("bots") or {}
    legacy_entry = legacy_bots.get(raw_actor) if isinstance(legacy_bots, dict) else None
    legacy_role = str((legacy_entry or {}).get("role") or "").strip().lower() if isinstance(legacy_entry, dict) else ""

    token_verified = False
    verified_agent: Optional[Dict[str, Any]] = None
    if auth_token is not None:
        verified_agent = verify_agent_token(auth_token, agent_id=raw_actor, bus_dir=bus_dir)
        if verified_agent is None:
            return {
                "actor_id": raw_actor,
                "authorized": False,
                "reason": "invalid_or_revoked_token",
                "is_coordinator_peer": False,
                "is_legacy_coordinator": False,
                "is_legacy_peer": False,
                "host_server_invoke": False,
                "led_teams": [],
                "member_teams": [],
                "agent": None,
                "token_verified": False,
                "federation_active": fed_active,
            }
        token_verified = True

    raw_agent = agents_map.get(raw_actor) if isinstance(agents_map, dict) else None
    sanitized_agent = verified_agent or (sanitize_agent_record(raw_agent) if isinstance(raw_agent, dict) else None)

    if isinstance(raw_agent, dict):
        if raw_agent.get("revoked") or not raw_agent.get("enabled", True):
            return {
                "actor_id": raw_actor,
                "authorized": False,
                "reason": "agent_revoked_or_disabled",
                "is_coordinator_peer": False,
                "is_legacy_coordinator": False,
                "is_legacy_peer": False,
                "host_server_invoke": False,
                "led_teams": [],
                "member_teams": [],
                "agent": sanitized_agent,
                "token_verified": token_verified,
                "federation_active": fed_active,
            }

    led_teams: List[str] = []
    member_teams: List[str] = []
    for tid, team in sorted(teams_map.items()):
        if not isinstance(team, dict):
            continue
        leader = str(team.get("leader_agent_id") or "")
        co_leaders = list(team.get("co_leaders") or [])
        members = list(team.get("members") or [])
        if raw_actor == leader or raw_actor in co_leaders:
            led_teams.append(tid)
            member_teams.append(tid)
        elif raw_actor in members:
            member_teams.append(tid)

    caps = (sanitized_agent or {}).get("capabilities") or {}
    is_coord_peer = bool(caps.get("coordinator_peer")) if sanitized_agent else False
    host_invoke = bool(caps.get("host_server_invoke")) if sanitized_agent else False
    allowed_teams = list(caps.get("allowed_teams") or []) if sanitized_agent else []
    can_dispatch = bool(caps.get("can_dispatch", False)) if sanitized_agent else False
    can_receive = bool(caps.get("can_receive", True)) if sanitized_agent else True

    # Legacy host coordinator in team_config.json retains global coordinator authority
    # unless explicitly registered in agents.json with coordinator_peer=False and scoped to teams.
    is_legacy_coord = (legacy_role == "coordinator") and (sanitized_agent is None or is_coord_peer)
    is_legacy_peer = (legacy_role == "peer") and (sanitized_agent is None)
    if sanitized_agent is None:
        can_dispatch = bool(is_legacy_coord or is_legacy_peer or (not fed_active and not legacy_bots))

    effective_led_teams = (
        [tid for tid in led_teams if tid in allowed_teams] if allowed_teams else list(led_teams)
    )
    effective_member_teams = (
        [tid for tid in member_teams if tid in allowed_teams] if allowed_teams else list(member_teams)
    )

    known_actor = (sanitized_agent is not None) or (legacy_entry is not None)
    return {
        "actor_id": raw_actor,
        "authorized": known_actor or (not fed_active and not legacy_bots),
        "reason": "" if known_actor else ("legacy_empty_config" if (not fed_active and not legacy_bots) else "unknown_actor"),
        "is_coordinator_peer": is_coord_peer,
        "is_legacy_coordinator": is_legacy_coord,
        "is_legacy_peer": is_legacy_peer,
        "legacy_role": legacy_role,
        "host_server_invoke": host_invoke,
        "can_dispatch": can_dispatch,
        "can_receive": can_receive,
        "allowed_teams": allowed_teams,
        "led_teams": effective_led_teams,
        "raw_led_teams": led_teams,
        "member_teams": effective_member_teams,
        "agent": sanitized_agent,
        "token_verified": token_verified,
        "federation_active": fed_active,
        "has_legacy_bots": bool(legacy_bots),
    }


def authorize_team_action(
    actor_id: str,
    action: str,
    *,
    team_id: str = "",
    target_agent_id: str = "",
    job: Optional[Dict[str, Any]] = None,
    bus_dir: Optional[str] = None,
    auth_token: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Enforce multi-team & global coordinator_peer isolation fail-closed (C3, C4).

    Raises `PermissionError("PRIVILEGE_ESCALATION_DENIED: ...")` on any cross-team
    or unauthorized privilege escalation attempt.
    """
    clean_team = validate_team_id(team_id, allow_empty=True)
    clean_target = validate_agent_id(target_agent_id) if target_agent_id else ""

    auth = resolve_actor_authority(actor_id, bus_dir=bus_dir, auth_token=auth_token, env=env)
    fed_active = bool(auth.get("federation_active"))

    # If auth_token was supplied and failed, or agent is revoked/disabled -> ALWAYS deny immediately.
    if not auth.get("authorized"):
        reason = auth.get("reason") or "unauthorized"
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: actor {actor_id!r} denied for {action} ({reason})"
        )

    # B4: Registered external/non-agy_local agents MUST present a verified federation token
    # on all server-side authorization paths (never allow auth_token=None bypass).
    agent = auth.get("agent")
    if isinstance(agent, dict) and agent.get("kind") != "agy_local":
        if not auth.get("token_verified"):
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: external agent {auth['actor_id']!r} "
                f"(kind={agent.get('kind')!r}) requires valid auth_token for {action}"
            )

    # Check if caller has global coordinator privileges (Owner-granted coordinator_peer or legacy coordinator).
    has_global_coord = bool(auth["is_coordinator_peer"] or auth["is_legacy_coordinator"])

    # If no federation state exists at all (legacy 4-Bot deployment), preserve backward compatibility.
    if not fed_active:
        return auth

    teams_map = {t["team_id"]: t for t in list_teams(bus_dir=bus_dir)}
    act = str(action or "").strip().lower()
    allowed_teams = set(auth.get("allowed_teams") or [])
    can_dispatch = bool(auth.get("can_dispatch", False))

    # M2-C4: Enforce capabilities.can_dispatch on registered agents across all mutating orchestration actions.
    if isinstance(agent, dict) and act in ("dispatch", "cancel", "retry", "cleanup_worktree", "broadcast"):
        if not can_dispatch:
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: agent {auth['actor_id']!r} has capabilities.can_dispatch=False and cannot perform {act}"
            )

    # M2-C4: Enforce target capabilities.can_receive=True (and enabled/not-revoked) on dispatch.
    if act == "dispatch" and clean_target:
        target_rec = get_agent(clean_target, bus_dir=bus_dir)
        if isinstance(target_rec, dict):
            if target_rec.get("revoked") or not target_rec.get("enabled", True):
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: target agent {clean_target!r} is disabled or revoked"
                )
            if not bool((target_rec.get("capabilities") or {}).get("can_receive", True)):
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: target agent {clean_target!r} has capabilities.can_receive=False"
                )

    # M2-C4 / M2-B6: Enforce capabilities.allowed_teams intersection clamp EVEN for coordinator_peer=True or leader_agent_id.
    if allowed_teams:
        if act in ("dispatch", "broadcast"):
            if clean_team:
                if clean_team not in allowed_teams:
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: team {clean_team!r} is outside capabilities.allowed_teams={sorted(allowed_teams)} for {auth['actor_id']!r}"
                    )
                team_obj = teams_map.get(clean_team)
                if team_obj is None:
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: team {clean_team!r} not found"
                    )
                if clean_target and clean_target not in (team_obj.get("members") or []):
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: target {clean_target!r} is not a member of allowed team {clean_team!r}"
                    )
            else:
                if not clean_target:
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: team_id required when capabilities.allowed_teams={sorted(allowed_teams)} is set for {auth['actor_id']!r}"
                    )
                matching_allowed = [
                    tid
                    for tid in sorted(allowed_teams)
                    if clean_target in ((teams_map.get(tid) or {}).get("members") or [])
                ]
                if not matching_allowed:
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: target {clean_target!r} is not in any team within capabilities.allowed_teams={sorted(allowed_teams)}"
                    )
                if len(matching_allowed) > 1:
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: explicit team_id required because target {clean_target!r} belongs to multiple allowed_teams={matching_allowed}"
                    )
        elif act in ("cancel", "retry", "status", "cleanup_worktree"):
            if isinstance(job, dict):
                job_team = validate_team_id(job.get("team_id") or "", allow_empty=True)
                if clean_team and clean_team != job_team:
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: team_id mismatch with target job "
                        f"(requested={clean_team!r}, job_team={job_team!r})"
                    )
                eff_team_chk = job_team
            else:
                eff_team_chk = clean_team
            if not eff_team_chk or eff_team_chk not in allowed_teams:
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: team {eff_team_chk!r} is outside capabilities.allowed_teams={sorted(allowed_teams)} for {auth['actor_id']!r}"
                )
            if teams_map.get(eff_team_chk) is None:
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: team {eff_team_chk!r} not found"
                )

    # Global active coordinator_peer (or legacy host coordinator) may coordinate across allowed teams.
    if has_global_coord:
        return auth

    led_teams = set(auth.get("led_teams") or [])

    if act in ("dispatch", "broadcast"):
        if not led_teams:
            # Check legacy peer only when no teams restrict this actor and target isn't in a team
            if auth.get("is_legacy_peer") and not clean_team and not teams_map:
                return auth
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: actor {auth['actor_id']!r} is neither a global coordinator_peer nor leader of any team for {act}"
            )
        # Resolve target team
        if clean_team:
            if clean_team not in led_teams:
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: actor {auth['actor_id']!r} is not leader of team {clean_team!r} (led_teams={sorted(led_teams)})"
                )
            team_obj = teams_map.get(clean_team)
            if team_obj is None:
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: team {clean_team!r} not found"
                )
            if clean_target and clean_target not in (team_obj.get("members") or []):
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: target {clean_target!r} is not a member of team {clean_team!r}"
                )
            return auth
        # No explicit team_id supplied: only allow if target is a member of a team led by actor
        if clean_target:
            matching_led = [
                tid
                for tid in sorted(led_teams)
                if clean_target in ((teams_map.get(tid) or {}).get("members") or [])
            ]
            if not matching_led:
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: cross-team dispatch denied; target {clean_target!r} is not a member of any team led by {auth['actor_id']!r}"
                )
            return auth
        raise PermissionError(
            f"PRIVILEGE_ESCALATION_DENIED: team_id required for team-scoped leader {auth['actor_id']!r}"
        )

    if act in ("cancel", "retry", "status", "cleanup_worktree"):
        if isinstance(job, dict):
            job_team = validate_team_id(job.get("team_id") or "", allow_empty=True)
            if clean_team and clean_team != job_team:
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: team_id mismatch with target job "
                    f"(requested={clean_team!r}, job_team={job_team!r})"
                )
            eff_team = job_team
        else:
            eff_team = clean_team
        if not eff_team:
            # Non-global team leader cannot touch default/unscoped jobs unless they originated it and are not scoped solely to another team
            if isinstance(job, dict) and job.get("from_bot") == auth["actor_id"] and not teams_map:
                return auth
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: actor {auth['actor_id']!r} lacks global coordinator_peer for unscoped job {act}"
            )
        if eff_team not in led_teams:
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: cross-team {act} denied for actor {auth['actor_id']!r} on team {eff_team!r} (led_teams={sorted(led_teams)})"
            )
        return auth

    if act == "list":
        return auth

    raise PermissionError(f"PRIVILEGE_ESCALATION_DENIED: unsupported team action {action!r}")


def list_effective_roster(
    *,
    bus_dir: Optional[str] = None,
    include_offline: bool = True,
) -> List[Dict[str, Any]]:
    """Return sanitized federation agent summaries suitable for `team_roster` (zero tokens/hashes)."""
    if not os.path.isfile(agents_file_path(bus_dir)):
        return []
    agents = list_agents(bus_dir=bus_dir, include_disabled=include_offline, include_revoked=False)
    teams = list_teams(bus_dir=bus_dir)
    led_by: Dict[str, List[str]] = {}
    member_of: Dict[str, List[str]] = {}
    for t in teams:
        tid = t["team_id"]
        if t.get("leader_agent_id"):
            led_by.setdefault(t["leader_agent_id"], []).append(tid)
        for cl in t.get("co_leaders") or []:
            led_by.setdefault(cl, []).append(tid)
        for m in t.get("members") or []:
            member_of.setdefault(m, []).append(tid)

    roster_items: List[Dict[str, Any]] = []
    for ag in agents:
        aid = ag["agent_id"]
        caps = ag.get("capabilities") or {}
        is_enabled = bool(ag.get("enabled", True)) and not bool(ag.get("revoked", False))
        if not include_offline and not is_enabled:
            continue
        role = "coordinator" if caps.get("coordinator_peer") else ("peer" if led_by.get(aid) else "worker")
        roster_items.append(
            {
                "handle": aid,
                "agent_id": aid,
                "display_name": ag.get("display_name") or aid,
                "kind": ag.get("kind"),
                "driver": ag.get("driver"),
                "transport": ag.get("transport"),
                "profile": ag.get("profile") or "",
                "role": role,
                "federated": True,
                "online": is_enabled,
                "busy": False,
                "trust_level": ag.get("trust_level") or "remote_trusted",
                "coordinator_peer": bool(caps.get("coordinator_peer")),
                "host_server_invoke": bool(caps.get("host_server_invoke")),
                "can_dispatch": bool(caps.get("can_dispatch", False)),
                "can_receive": bool(caps.get("can_receive", True)),
                "allowed_teams": list(caps.get("allowed_teams") or []),
                "led_teams": sorted(set(led_by.get(aid) or [])),
                "teams": sorted(set(member_of.get(aid) or [])),
                "has_active_token": bool(ag.get("has_active_token")),
                "specialty": str((ag.get("metadata") or {}).get("specialty") or ag.get("kind") or ""),
            }
        )
    return roster_items


# ---------------------------------------------------------------- NAT-Friendly Pull Worker Queue (C7)
class PullWorkerQueue:
    """`flock`-serialized atomic job queue for NAT/firewalled external Pull Workers (`C7`).

    Storage: `<BUS_DIR>/federation/pull_queue/` (`0700`), job files `<job_id>.json` (`0600`).
    Guarantees:
    - Strict `target_agent_id` enforcement (an agent can never claim another agent's job).
    - Claim-once atomicity across concurrent threads/processes via `fcntl.flock(LOCK_EX)`.
    - Cancelled or already-claimed jobs are strictly rejected and never executed twice.
    """

    def __init__(self, bus_dir: Optional[str] = None):
        self.bus_dir = _resolve_bus_dir(bus_dir)

    @property
    def queue_dir(self) -> str:
        return pull_queue_dir(self.bus_dir)

    @property
    def lock_path(self) -> str:
        return os.path.join(self.queue_dir, "pull_queue.lock")

    def _job_file(self, job_id: str) -> str:
        clean_id = validate_pull_job_id(job_id)
        qroot = os.path.realpath(self.queue_dir)
        cand = os.path.join(self.queue_dir, f"{clean_id}.json")
        if not os.path.realpath(cand).startswith(qroot + os.sep):
            raise ValueError(f"Pull job path escapes pull_queue: {job_id!r}")
        return cand

    @contextlib.contextmanager
    def _lock(self):
        _ensure_secure_dir(federation_dir(self.bus_dir))
        _ensure_secure_dir(self.queue_dir)
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        os.chmod(self.lock_path, 0o600)
        with os.fdopen(fd, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    def _check_tainted_env(self, env: Optional[Dict[str, str]], *, action: str) -> Dict[str, str]:
        e = dict(os.environ) if env is None else dict(env)
        if (
            str(e.get("AGY_UNTRUSTED_SESSION") or "").strip() == "1"
            or str(e.get("AGY_MEMORY_READONLY") or "").strip() == "1"
            or str(e.get("AGY_RBAC_ROLE") or "").strip().lower() == "readonly"
        ):
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: untrusted/readonly session cannot {action} pull_queue jobs"
            )
        return e

    def _authorize_worker_agent(
        self,
        aid: str,
        *,
        auth_token: Optional[str],
        action: str,
    ) -> None:
        raw_rec: Optional[Dict[str, Any]] = None
        if os.path.isfile(agents_file_path(self.bus_dir)):
            with _registry_lock(self.bus_dir, shared=True):
                data = _load_agents_unlocked(self.bus_dir)
                cand = (data.get("agents") or {}).get(aid)
                if isinstance(cand, dict):
                    raw_rec = cand

        if isinstance(raw_rec, dict):
            if raw_rec.get("revoked") or not raw_rec.get("enabled", True):
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: agent {aid!r} is revoked or disabled for pull_queue {action}"
                )
            requires_token = (raw_rec.get("kind") != "agy_local") or bool(raw_rec.get("token_records"))
            if requires_token:
                if not auth_token:
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: auth_token is required for agent {aid!r} on pull_queue {action}"
                    )
                if verify_agent_token(auth_token, agent_id=aid, bus_dir=self.bus_dir) is None:
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: invalid or revoked agent token for pull_queue {action}"
                    )
                return

        if auth_token is not None:
            if verify_agent_token(auth_token, agent_id=aid, bus_dir=self.bus_dir) is None:
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: invalid or revoked agent token for pull_queue {action}"
                )

    def _authorize_dispatcher(
        self,
        *,
        action: str,
        caller_agent_id: str = "",
        target_agent_id: str = "",
        team_id: str = "",
        job: Optional[Dict[str, Any]] = None,
        owner_auth: Any = None,
        auth_token: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        e = self._check_tainted_env(env, action=action)
        fed_active = has_federation_state(self.bus_dir)

        if owner_auth is not None:
            assert_owner_auth(owner_auth, action=f"pull_queue.{action}", bus_dir=self.bus_dir, env=e)
            return

        if caller_agent_id:
            if fed_active:
                authorize_team_action(
                    caller_agent_id,
                    "dispatch" if action == "enqueue" else "cancel",
                    team_id=team_id,
                    target_agent_id=target_agent_id,
                    job=job,
                    bus_dir=self.bus_dir,
                    auth_token=auth_token,
                    env=e,
                )
                return
            auth = resolve_actor_authority(
                caller_agent_id,
                bus_dir=self.bus_dir,
                auth_token=auth_token,
                env=e,
            )
            if not auth.get("authorized"):
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: caller {caller_agent_id!r} denied for pull_queue {action}"
                )
            if auth.get("has_legacy_bots") and auth.get("legacy_role") == "worker":
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: worker {caller_agent_id!r} cannot {action} pull_queue jobs"
                )
            return

        bus_role = str(e.get("AGY_BOT_BUS_ROLE") or "").strip().lower()
        if bus_role == "worker":
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: worker session cannot {action} pull_queue jobs"
            )
        if fed_active:
            raise PermissionError(
                f"PRIVILEGE_ESCALATION_DENIED: pull_queue {action} requires owner_auth or authorized caller when federation is active"
            )

    def enqueue(
        self,
        target_agent_id: str,
        prompt: str,
        *,
        job_id: Optional[str] = None,
        team_id: str = "",
        from_agent_id: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        owner_auth: Any = None,
        auth_token: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        target = validate_agent_id(target_agent_id)
        clean_team = validate_team_id(team_id, allow_empty=True)
        clean_from = validate_agent_id(from_agent_id) if from_agent_id else ""
        self._authorize_dispatcher(
            action="enqueue",
            caller_agent_id=clean_from,
            target_agent_id=target,
            team_id=clean_team,
            owner_auth=owner_auth,
            auth_token=auth_token,
            env=env,
        )
        if has_federation_state(self.bus_dir):
            target_rec = get_agent(target, bus_dir=self.bus_dir)
            if isinstance(target_rec, dict):
                if target_rec.get("revoked") or not target_rec.get("enabled", True):
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: target agent {target!r} is disabled or revoked"
                    )
                if not bool((target_rec.get("capabilities") or {}).get("can_receive", True)):
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: target agent {target!r} has capabilities.can_receive=False"
                    )
        clean_prompt = str(prompt or "").strip()
        if not clean_prompt:
            raise ValueError("Pull job prompt cannot be empty")
        clean_meta = copy.deepcopy(metadata) if isinstance(metadata, dict) else {}
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata must be a dict")
        reject_plaintext_secrets(clean_meta, path="pull_job.metadata")

        jid = validate_pull_job_id(job_id) if job_id else f"pull-{uuid.uuid4().hex[:12]}"
        now = time.time()
        record = {
            "job_id": jid,
            "target_agent_id": target,
            "from_agent_id": clean_from,
            "team_id": clean_team,
            "prompt": clean_prompt,
            "metadata": clean_meta,
            "status": "queued",
            "claimed_by": "",
            "claimed_at": 0.0,
            "cancelled": False,
            "cancel_reason": "",
            "result_text": "",
            "error": "",
            "created_at": now,
            "finished_at": 0.0,
        }
        with self._lock():
            fp = self._job_file(jid)
            if os.path.exists(fp):
                raise ValueError(f"Pull job_id already exists: {jid!r}")
            _atomic_write_json(fp, record)
        return copy.deepcopy(record)

    def claim(
        self,
        agent_id: str,
        *,
        job_id: Optional[str] = None,
        auth_token: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        aid = validate_agent_id(agent_id)
        self._authorize_worker_agent(aid, auth_token=auth_token, action="claim")

        with self._lock():
            if job_id is not None:
                fp = self._job_file(job_id)
                if not os.path.isfile(fp):
                    return None
                job = _read_json(fp, None)
                if not isinstance(job, dict):
                    return None
                if job.get("target_agent_id") != aid:
                    raise PermissionError(
                        f"PRIVILEGE_ESCALATION_DENIED: pull job {job_id!r} belongs to {job.get('target_agent_id')!r}, not {aid!r}"
                    )
                if job.get("cancelled") or job.get("status") != "queued":
                    return None
                job["status"] = "claimed"
                job["claimed_by"] = aid
                job["claimed_at"] = time.time()
                _atomic_write_json(fp, job)
                return copy.deepcopy(job)

            # FIFO scan for next queued job belonging to `aid`
            candidates: List[Tuple[float, str, str, Dict[str, Any]]] = []
            try:
                names = sorted(
                    fn for fn in os.listdir(self.queue_dir) if fn.endswith(".json") and not fn.endswith(".tmp")
                )
            except OSError:
                return None
            for fn in names:
                fp = os.path.join(self.queue_dir, fn)
                job = _read_json(fp, None)
                if not isinstance(job, dict):
                    continue
                if job.get("target_agent_id") != aid:
                    continue
                if job.get("cancelled") or job.get("status") != "queued":
                    continue
                candidates.append((float(job.get("created_at") or 0.0), fn, fp, job))
            if not candidates:
                return None
            candidates.sort(key=lambda item: (item[0], item[1]))
            _, _, fp, job = candidates[0]
            job["status"] = "claimed"
            job["claimed_by"] = aid
            job["claimed_at"] = time.time()
            _atomic_write_json(fp, job)
            return copy.deepcopy(job)

    def complete(
        self,
        job_id: str,
        agent_id: str,
        *,
        status: str = "done",
        result_text: str = "",
        error: str = "",
        auth_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        aid = validate_agent_id(agent_id)
        if status not in ("done", "error"):
            raise ValueError(f"Invalid completion status: {status!r}")
        self._authorize_worker_agent(aid, auth_token=auth_token, action="complete")
        with self._lock():
            fp = self._job_file(job_id)
            job = _read_json(fp, None)
            if not isinstance(job, dict):
                raise ValueError(f"Pull job not found: {job_id!r}")
            if job.get("target_agent_id") != aid:
                raise PermissionError(
                    f"PRIVILEGE_ESCALATION_DENIED: agent {aid!r} does not own pull job {job_id!r}"
                )
            if job.get("status") in _PULL_TERMINAL_STATUSES or job.get("cancelled"):
                raise ValueError(f"JOB_ALREADY_TERMINAL: pull job {job_id!r} is already terminal ({job.get('status')})")
            if job.get("claimed_by") != aid or job.get("status") != "claimed":
                raise ValueError(f"JOB_NOT_CLAIMED: pull job {job_id!r} is not currently claimed by {aid!r}")
            job["status"] = status
            job["result_text"] = str(result_text or "")
            job["error"] = str(error or "")
            job["finished_at"] = time.time()
            _atomic_write_json(fp, job)
            return copy.deepcopy(job)

    def list_jobs(
        self,
        agent_id: str,
        *,
        status: Optional[str] = "queued",
        auth_token: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        aid = validate_agent_id(agent_id)
        self._authorize_worker_agent(aid, auth_token=auth_token, action="inbox")
        if not os.path.isdir(self.queue_dir):
            return []
        out: List[Dict[str, Any]] = []
        with self._lock():
            try:
                names = sorted(
                    fn for fn in os.listdir(self.queue_dir) if fn.endswith(".json") and not fn.endswith(".tmp")
                )
            except OSError:
                return []
            for fn in names:
                job = _read_json(os.path.join(self.queue_dir, fn), None)
                if not isinstance(job, dict):
                    continue
                if job.get("target_agent_id") != aid:
                    continue
                if status is not None and job.get("status") != status:
                    continue
                if status == "queued" and job.get("cancelled"):
                    continue
                out.append(copy.deepcopy(job))
        out.sort(key=lambda j: (float(j.get("created_at") or 0.0), str(j.get("job_id") or "")))
        return out

    def cancel(
        self,
        job_id: str,
        *,
        reason: str = "cancelled",
        requester_agent_id: str = "",
        team_id: str = "",
        owner_auth: Any = None,
        auth_token: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        clean_req = validate_agent_id(requester_agent_id) if requester_agent_id else ""
        clean_team = validate_team_id(team_id, allow_empty=True)
        # Validate environment & pre-auth before opening queue file
        self._check_tainted_env(env, action="cancel")
        with self._lock():
            fp = self._job_file(job_id)
            if not os.path.isfile(fp):
                self._authorize_dispatcher(
                    action="cancel",
                    caller_agent_id=clean_req,
                    team_id=clean_team,
                    owner_auth=owner_auth,
                    auth_token=auth_token,
                    env=env,
                )
                return None
            job = _read_json(fp, None)
            if not isinstance(job, dict):
                return None
            self._authorize_dispatcher(
                action="cancel",
                caller_agent_id=clean_req,
                team_id=clean_team,
                job=job,
                owner_auth=owner_auth,
                auth_token=auth_token,
                env=env,
            )
            if job.get("status") in _PULL_TERMINAL_STATUSES:
                return copy.deepcopy(job)
            job["cancelled"] = True
            job["cancel_reason"] = str(reason or "cancelled")
            job["status"] = "cancelled"
            job["error"] = str(reason or "cancelled")
            job["finished_at"] = time.time()
            _atomic_write_json(fp, job)
            return copy.deepcopy(job)

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        clean_id = validate_pull_job_id(job_id)
        if not os.path.isdir(self.queue_dir):
            return None
        fp = self._job_file(clean_id)
        if not os.path.isfile(fp):
            return None
        with self._lock():
            job = _read_json(fp, None)
            return copy.deepcopy(job) if isinstance(job, dict) else None


def enqueue_pull_job(
    target_agent_id: str,
    prompt: str,
    *,
    job_id: Optional[str] = None,
    team_id: str = "",
    from_agent_id: str = "",
    metadata: Optional[Dict[str, Any]] = None,
    owner_auth: Any = None,
    auth_token: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    bus_dir: Optional[str] = None,
) -> Dict[str, Any]:
    return PullWorkerQueue(bus_dir).enqueue(
        target_agent_id,
        prompt,
        job_id=job_id,
        team_id=team_id,
        from_agent_id=from_agent_id,
        metadata=metadata,
        owner_auth=owner_auth,
        auth_token=auth_token,
        env=env,
    )


def claim_pull_job(
    agent_id: str,
    *,
    job_id: Optional[str] = None,
    auth_token: Optional[str] = None,
    bus_dir: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    return PullWorkerQueue(bus_dir).claim(agent_id, job_id=job_id, auth_token=auth_token)


def complete_pull_job(
    job_id: str,
    agent_id: str,
    *,
    status: str = "done",
    result_text: str = "",
    error: str = "",
    auth_token: Optional[str] = None,
    bus_dir: Optional[str] = None,
) -> Dict[str, Any]:
    return PullWorkerQueue(bus_dir).complete(
        job_id,
        agent_id,
        status=status,
        result_text=result_text,
        error=error,
        auth_token=auth_token,
    )


def cancel_pull_job(
    job_id: str,
    *,
    reason: str = "cancelled",
    requester_agent_id: str = "",
    team_id: str = "",
    owner_auth: Any = None,
    auth_token: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    bus_dir: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    return PullWorkerQueue(bus_dir).cancel(
        job_id,
        reason=reason,
        requester_agent_id=requester_agent_id,
        team_id=team_id,
        owner_auth=owner_auth,
        auth_token=auth_token,
        env=env,
    )


def get_pull_job(job_id: str, *, bus_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
    return PullWorkerQueue(bus_dir).get(job_id)
