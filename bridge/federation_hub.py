#!/usr/bin/env python3
"""External Agent Federation Inbound Hub, Host Server Bridge, and Outbound Worker Dispatcher.

Pure Python standard-library HTTP/1.1 `ThreadingHTTPServer` implementing:
- Loopback-by-default binding (`127.0.0.1:18799`), fail-fast non-loopback guard,
  security headers, CSRF/DNS-Rebinding protection (`Origin`/`Host`/`Content-Type`),
  1 MiB request body ceiling (`413`), per-agent sliding window rate limiting (`429`),
  and URL query credential rejection (`400`).
- Zero-cache real-time Bearer token authentication via `federation_registry` +
  HMAC-SHA256 anti-replay signatures (`X-Agy-Timestamp`, `X-Agy-Nonce`, `X-Agy-Signature`)
  with a bounded thread-safe TTL Nonce cache.
- MCP Streamable HTTP (`POST /hub/mcp`) with dynamic per-caller `tools/list` and
  server-side secondary enforcement on `tools/call`.
- Owner-authorized Host Server Bridge (`host_exec`, `host_files`, `host_services`,
  `host_invoke_agent`) guarded by strict 4-tuple eligibility and 3 anti-self-escalation locks.
- REST / A2A + NAT Pull Worker API (`/hub/v1/...`) synced with `PullWorkerQueue` & `bot_bus`.
- `flock`-serialized, secret-redacted structured audit log (`<BUS_DIR>/federation/audit.jsonl`, `0600`).
- Outbound `ExternalWorkerDispatcher` for non-`agy_local` agents and non-`agy` leader `batch_done` wakeups.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import copy
import fcntl
import hashlib
import hmac
import http.server
import ipaddress
import json
import math
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

if __package__:
    from . import agent_driver  # type: ignore
    from . import bot_bus  # type: ignore
    from . import external_drivers  # type: ignore
    from . import federation_registry  # type: ignore
    from . import memory_guard  # type: ignore
else:
    _THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    if _THIS_DIR not in sys.path:
        sys.path.insert(0, _THIS_DIR)
    import agent_driver  # type: ignore
    import bot_bus  # type: ignore
    import external_drivers  # type: ignore
    import federation_registry  # type: ignore
    import memory_guard  # type: ignore

DEFAULT_HUB_HOST = "127.0.0.1"
DEFAULT_HUB_PORT = 18799
DEFAULT_MAX_BODY_BYTES = 1024 * 1024  # 1 MiB
DEFAULT_RATE_LIMIT_MAX_REQUESTS = 120
DEFAULT_RATE_LIMIT_WINDOW_SEC = 60.0
DEFAULT_REPLAY_WINDOW_SEC = 300.0
DEFAULT_NONCE_CACHE_MAX = 10000
DEFAULT_HOST_EXEC_TIMEOUT_SEC = 30.0
MAX_HOST_EXEC_TIMEOUT_SEC = 120.0
MAX_HOST_EXEC_OUTPUT_BYTES = 65536
MAX_HOST_FILE_READ_BYTES = 262144

_FORBIDDEN_QUERY_CRED_KEYS = frozenset(
    {
        "token",
        "access_token",
        "api_key",
        "apikey",
        "x_api_key",
        "api_token",
        "auth_token",
        "bearer_token",
        "refresh_token",
        "bearer",
        "secret",
        "secret_key",
        "authorization",
        "password",
        "passwd",
        "credential",
        "credentials",
        "bot_token",
    }
)

_HOST_ELIGIBLE_TRUST_LEVELS = frozenset({"local_admin", "local_worker", "remote_trusted"})

_ALLOWED_EXEC_BINS = frozenset(
    {
        "ls",
        "cat",
        "head",
        "tail",
        "grep",
        "wc",
        "stat",
        "file",
        "pwd",
        "id",
        "whoami",
        "uname",
        "uptime",
        "df",
        "free",
        "ps",
        "ss",
        "hostname",
        "date",
        "du",
        "which",
        "printenv",
        "env",
        "git",
        "echo",
        "mkdir",
        "touch",
    }
)

_FORBIDDEN_LOCK1_BINS = frozenset(
    {
        "sh",
        "bash",
        "dash",
        "zsh",
        "ksh",
        "csh",
        "tcsh",
        "fish",
        "python",
        "python2",
        "python3",
        "perl",
        "ruby",
        "node",
        "nodejs",
        "php",
        "awk",
        "gawk",
        "mawk",
        "nawk",
        "lua",
        "xargs",
        "find",
        "sed",
        "ln",
        "cp",
        "mv",
        "rm",
        "chmod",
        "chown",
        "chgrp",
        "dd",
        "sudo",
        "su",
        "doas",
        "pkexec",
        "curl",
        "wget",
        "nc",
        "ncat",
        "socat",
        "ssh",
        "scp",
        "rsync",
        "tar",
        "zip",
        "unzip",
        "tee",
        "exec",
        "eval",
        "source",
    }
)

_FORBIDDEN_LOCK2_BINS = frozenset({"bao", "vault"})
_FORBIDDEN_LOCK3_BINS = frozenset({"systemctl", "service", "journalctl"})

_GIT_ALLOWED_SUBCOMMANDS = frozenset(
    {
        "status",
        "branch",
        "rev-parse",
        "describe",
        "log",
        "diff",
    }
)

_GIT_STATUS_ALLOWED_FLAGS = frozenset(
    {
        "-s",
        "--short",
        "-b",
        "--branch",
        "--porcelain",
        "--porcelain=v1",
        "--porcelain=v2",
        "-u",
        "--untracked-files",
        "--untracked-files=no",
        "--untracked-files=normal",
        "--untracked-files=all",
        "--ignored=no",
        "-z",
        "--show-stash",
        "--ahead-behind",
        "--no-ahead-behind",
        "--no-renames",
    }
)

_GIT_BRANCH_ALLOWED_FLAGS = frozenset(
    {
        "--list",
        "-a",
        "--all",
        "-r",
        "--remotes",
        "-v",
        "-vv",
        "--verbose",
        "--show-current",
        "--no-color",
        "--color=never",
        "--merged",
        "--no-merged",
    }
)

_GIT_REV_PARSE_ALLOWED_FLAGS = frozenset(
    {
        "--short",
        "--abbrev-ref",
        "--show-toplevel",
        "--is-inside-work-tree",
        "--is-bare-repository",
        "--show-prefix",
        "--verify",
        "--symbolic-full-name",
    }
)

_GIT_DESCRIBE_ALLOWED_FLAGS = frozenset(
    {
        "--tags",
        "--always",
        "--dirty",
        "--long",
        "--exact-match",
        "--all",
    }
)

_GIT_LOG_ALLOWED_BOOL_FLAGS = frozenset(
    {
        "--oneline",
        "--stat",
        "--numstat",
        "--shortstat",
        "--name-only",
        "--name-status",
        "--summary",
        "--no-merges",
        "--merges",
        "--decorate",
        "--no-decorate",
        "--graph",
        "--abbrev-commit",
        "--first-parent",
        "--reverse",
        "--no-patch",
        "-s",
    }
)

_GIT_LOG_ALLOWED_NUM_FLAGS = frozenset({"-n", "--max-count"})
_GIT_LOG_ALLOWED_DATE_FLAGS = frozenset({"--since", "--until", "--after", "--before"})

_GIT_DIFF_SUMMARY_FLAGS = frozenset(
    {
        "--stat",
        "--numstat",
        "--shortstat",
        "--name-only",
        "--name-status",
        "--summary",
    }
)
_GIT_DIFF_EXTRA_FLAGS = frozenset(
    {
        "--cached",
        "--staged",
        "--no-renames",
        "--find-renames",
        "--relative",
        "--dirstat",
    }
)

_GREP_ALLOWED_BOOL_FLAGS = frozenset(
    {
        "-i",
        "-n",
        "-c",
        "-l",
        "-v",
        "-w",
        "-x",
        "-F",
        "-E",
        "-H",
        "-h",
        "-o",
        "-q",
        "-s",
        "--ignore-case",
        "--line-number",
        "--count",
        "--files-with-matches",
        "--invert-match",
        "--word-regexp",
        "--line-regexp",
        "--fixed-strings",
        "--extended-regexp",
        "--with-filename",
        "--no-filename",
        "--only-matching",
        "--quiet",
        "--silent",
        "--no-messages",
    }
)
_GREP_ALLOWED_NUM_FLAGS = frozenset(
    {
        "-A",
        "-B",
        "-C",
        "-m",
        "--after-context",
        "--before-context",
        "--context",
        "--max-count",
    }
)
_GREP_ALLOWED_NUM_LONG_FLAGS = frozenset(
    {
        "--after-context",
        "--before-context",
        "--context",
        "--max-count",
    }
)

_LS_ALLOWED_SHORT_CHARS = frozenset("aAl1hdFStrucisngopQ")
_LS_ALLOWED_LONG_FLAGS = frozenset(
    {
        "--all",
        "--almost-all",
        "--human-readable",
        "--directory",
        "--classify",
        "--reverse",
        "--full-time",
        "--numeric-uid-gid",
        "--size",
        "--inode",
        "--color=never",
        "--color=auto",
        "--time-style=iso",
        "--time-style=long-iso",
        "--time-style=full-iso",
    }
)

_DU_ALLOWED_SHORT_CHARS = frozenset("shkmbacx0")
_DU_ALLOWED_LONG_FLAGS = frozenset(
    {
        "--summarize",
        "--human-readable",
        "--bytes",
        "--all",
        "--total",
        "--one-file-system",
        "--apparent-size",
    }
)

_CAT_ALLOWED_SHORT_CHARS = frozenset("nbsETvAet")
_CAT_ALLOWED_LONG_FLAGS = frozenset(
    {
        "--number",
        "--number-nonblank",
        "--squeeze-blank",
        "--show-ends",
        "--show-tabs",
        "--show-nonprinting",
        "--show-all",
    }
)

_HEAD_TAIL_BOOL_FLAGS = frozenset({"-q", "-v", "--quiet", "--silent", "--verbose"})
_HEAD_TAIL_NUM_FLAGS = frozenset({"-n", "-c", "--lines", "--bytes"})
_HEAD_TAIL_NUM_RE = re.compile(r"^[+-]?\d+$")

_WC_ALLOWED_SHORT_CHARS = frozenset("lwcmL")
_WC_ALLOWED_LONG_FLAGS = frozenset(
    {
        "--lines",
        "--words",
        "--bytes",
        "--chars",
        "--max-line-length",
    }
)

_FILE_ALLOWED_FLAGS = frozenset(
    {
        "-b",
        "--brief",
        "-i",
        "--mime",
        "--mime-type",
        "--mime-encoding",
        "-h",
        "--no-dereference",
    }
)

_STAT_ALLOWED_BOOL_FLAGS = frozenset({"-t", "--terse"})
_STAT_ALLOWED_FMT_FLAGS = frozenset({"-c", "--format"})

_TOUCH_ALLOWED_FLAGS = frozenset({"-c", "--no-create", "-a", "-m"})
_MKDIR_ALLOWED_FLAGS = frozenset({"-p", "--parents", "-v", "--verbose"})

_DATE_ALLOWED_BOOL_FLAGS = frozenset(
    {
        "-u",
        "--utc",
        "--universal",
        "-R",
        "--rfc-email",
        "--rfc-2822",
        "-I",
        "--iso-8601",
    }
)
_DATE_ALLOWED_ISO_SPEC = frozenset({"date", "hours", "minutes", "seconds", "ns"})
_DATE_ALLOWED_RFC3339_SPEC = frozenset({"date", "seconds", "ns"})
_DATE_FORMAT_RE = re.compile(r"^\+[A-Za-z0-9_.:/% T\-]{1,64}$")

_SS_ALLOWED_SHORT_CHARS = frozenset("tulnpa46HsomiwxSe")
_SS_ALLOWED_LONG_FLAGS = frozenset(
    {
        "--tcp",
        "--udp",
        "--listening",
        "--numeric",
        "--processes",
        "--all",
        "--ipv4",
        "--ipv6",
        "--no-header",
        "--summary",
        "--options",
        "--memory",
        "--info",
        "--raw",
        "--unix",
        "--sctp",
        "--extended",
        "--resolve",
    }
)

_HOSTNAME_ALLOWED_FLAGS = frozenset(
    {
        "-f",
        "-s",
        "-i",
        "-I",
        "-d",
        "-a",
        "--fqdn",
        "--long",
        "--short",
        "--ip-address",
        "--all-ip-addresses",
        "--domain",
        "--alias",
    }
)

_PS_ALLOWED_BSD_TOKENS = frozenset(
    {
        "aux",
        "ax",
        "a",
        "u",
        "x",
        "w",
        "ww",
        "axw",
        "axww",
        "auxw",
        "auxww",
    }
)
_PS_ALLOWED_POSIX_BOOL_FLAGS = frozenset(
    {
        "-e",
        "-f",
        "-F",
        "-ef",
        "-eF",
        "-efw",
        "-efww",
        "-ew",
        "-eww",
        "-A",
        "-Af",
        "-H",
        "-T",
        "-L",
        "-l",
        "-w",
        "-ww",
        "--no-headers",
        "--headers",
        "--forest",
    }
)
_PS_POSIX_E_FLAGS = frozenset({"-e", "-ef", "-eF", "-efw", "-efww", "-ew", "-eww"})
_PS_ALLOWED_FORMAT_COLS = frozenset(
    {
        "pid",
        "ppid",
        "pgid",
        "sid",
        "uid",
        "euid",
        "user",
        "gid",
        "group",
        "stat",
        "state",
        "s",
        "pri",
        "ni",
        "pcpu",
        "%cpu",
        "pmem",
        "%mem",
        "vsz",
        "rss",
        "tty",
        "tname",
        "start",
        "stime",
        "lstart",
        "bsdstart",
        "etime",
        "etimes",
        "time",
        "cputime",
        "comm",
        "ucmd",
        "cmd",
        "args",
        "command",
        "cgroup",
        "nlwp",
        "thcount",
        "psr",
        "wchan",
    }
)
_PS_PID_LIST_RE = re.compile(r"^\d+(?:,\d+)*$")
_PS_USER_LIST_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*$")
_PS_COMM_LIST_RE = re.compile(r"^[A-Za-z0-9_.+-]+(?:,[A-Za-z0-9_.+-]+)*$")
_PS_COL_HEADER_RE = re.compile(r"^[A-Za-z0-9_%-]{0,32}$")

_PWD_ALLOWED_FLAGS = frozenset({"-L", "-P", "--logical", "--physical"})
_ID_ALLOWED_FLAGS = frozenset({"-u", "-g", "-G", "-n", "-r", "-un", "-gn", "-Gn", "--user", "--group", "--groups", "--name", "--real"})
_UNAME_ALLOWED_SHORT_CHARS = frozenset("asnrvmpo")
_UNAME_ALLOWED_LONG_FLAGS = frozenset(
    {
        "--all",
        "--kernel-name",
        "--nodename",
        "--kernel-release",
        "--kernel-version",
        "--machine",
        "--processor",
        "--hardware-platform",
        "--operating-system",
    }
)
_UPTIME_ALLOWED_FLAGS = frozenset({"-p", "-s", "--pretty", "--since"})
_DF_ALLOWED_SHORT_CHARS = frozenset("hkmTPial")
_DF_ALLOWED_LONG_FLAGS = frozenset(
    {
        "--human-readable",
        "--print-type",
        "--portability",
        "--inodes",
        "--all",
        "--local",
        "--total",
    }
)
_FREE_ALLOWED_SHORT_CHARS = frozenset("bkmghtwl")
_FREE_ALLOWED_LONG_FLAGS = frozenset(
    {
        "--bytes",
        "--kibi",
        "--mebi",
        "--gibi",
        "--human",
        "--total",
        "--wide",
        "--lohi",
        "--si",
    }
)
_BARE_IDENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_BARE_CMD_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")
_ENV_VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_CHUNK_SIZE_RE = re.compile(rb"^[0-9a-fA-F]{1,16}$")

_SHELL_META_SUBSTRINGS: Tuple[str, ...] = (
    ";",
    "&&",
    "||",
    "|",
    "`",
    "$(",
    "${",
    ">",
    "<",
    "\n",
    "\r",
    "\x00",
)
_ENV_EXPAND_RE = re.compile(r"\$(?:[A-Za-z_?@*#0-9]|\{|\()")

_SENSITIVE_ENV_EXACT = frozenset(
    {
        "VAULT_TOKEN",
        "BAO_TOKEN",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "TG_BOT_TOKEN",
        "TELEGRAM_BOT_TOKEN",
        "AGY_FEDERATION_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "CF_API_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "DATABASE_URL",
        "ANTIGRAVITY_SOURCE_METADATA",
    }
)
_SENSITIVE_ENV_RE = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|COOKIE|CREDENTIAL|AUTH)",
    re.IGNORECASE,
)

_UNIT_NAME_RE = re.compile(r"^(?:agy|hermes)-[a-z0-9_.-]{1,48}(?:\.service)?$")
_PROC_PROCESS_RE = re.compile(r"^/proc/(?:self|thread-self|\d+)(?:/.*)?$")
_LOCK2_SECRET_SUFFIXES: Tuple[str, ...] = (".env", ".token", ".pem", ".key", ".p12", ".pfx")
_LOCK2_SECRET_BASENAMES = frozenset(
    {".bao_credentials.json", "auth.json", "credentials.json", "oauth_creds.json"}
)

_LOCK1_WRITE_PROTECTED_REPO_FILES: Tuple[str, ...] = (
    "bridge/federation_hub.py",
    "bridge/federation_registry.py",
    "bridge/federation_mcp_stdio.py",
    "bridge/bot_bus.py",
    "bridge/bot_bus_mcp.py",
    "bridge/agent_driver.py",
    "bridge/external_drivers.py",
    "bridge/memory_guard.py",
    "bridge/bridge.py",
    "scripts/verify_gate.py",
    "scripts/sync_live.py",
    "scripts/export_public.py",
)

_LOCK1_WRITE_PROTECTED_HOME_FILES: Tuple[str, ...] = (
    ".bashrc",
    ".profile",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
)

_PROTECTED_CODE_REL_PATHS: Tuple[str, ...] = (
    ".agents/skills/google-profile/scripts/google_browser.py",
    ".agents/skills/live-browser/scripts/static/index.html",
)

_RELOAD_SENTINEL_MAP: Dict[str, str] = {
    "agy-tg-bridge": "agy_bridge_reload",
    "agy-tg-bridge.service": "agy_bridge_reload",
    "agy-tg-bridge-sg": "agy_bridge_sg_reload",
    "agy-tg-bridge-sg.service": "agy_bridge_sg_reload",
    "agy-tg-bridge-jeff": "agy_bridge_jeff_reload",
    "agy-tg-bridge-jeff.service": "agy_bridge_jeff_reload",
    "agy-tg-bridge-sgcli": "agy_bridge_sgcli_reload",
    "agy-tg-bridge-sgcli.service": "agy_bridge_sgcli_reload",
}

_BOT_BUS_BIND_LOCK = threading.RLock()


class HubError(Exception):
    """Structured HTTP / JSON-RPC error raised inside the Federation Hub."""

    def __init__(
        self,
        http_status: int,
        error_code: str,
        message: str,
        *,
        rpc_code: int = -32000,
        headers: Optional[Dict[str, str]] = None,
    ):
        super().__init__(message)
        self.http_status = int(http_status)
        self.error_code = str(error_code)
        self.message = str(message)
        self.rpc_code = int(rpc_code)
        self.headers = dict(headers or {})


# ---------------------------------------------------------------- Helpers: Loopback, Bus Binding, Replay, Rate Limit
def is_loopback_host(host: Optional[str]) -> bool:
    """Return True strictly for `localhost`, `127.0.0.0/8`, or `::1`."""
    raw = str(host or "").strip().lower()
    if not raw:
        return False
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if raw == "localhost":
        return True
    try:
        ip_obj = ipaddress.ip_address(raw)
        return bool(ip_obj.is_loopback)
    except ValueError:
        return False


def validate_bind_host(
    host: str,
    *,
    allow_non_loopback: Optional[bool] = None,
    env: Optional[Mapping[str, str]] = None,
) -> str:
    """Fail-fast unless `host` is loopback or `AGY_FEDERATION_HUB_ALLOW_NON_LOOPBACK=1`."""
    clean = str(host or "").strip() or DEFAULT_HUB_HOST
    if allow_non_loopback is None:
        e = os.environ if env is None else env
        allow_non_loopback = str(e.get("AGY_FEDERATION_HUB_ALLOW_NON_LOOPBACK") or "").strip() == "1"
    if not is_loopback_host(clean) and not bool(allow_non_loopback):
        raise ValueError(
            f"NON_LOOPBACK_BIND_DENIED: refusing to bind Federation Hub to {clean!r} "
            "without AGY_FEDERATION_HUB_ALLOW_NON_LOOPBACK=1"
        )
    return clean


def _extract_host_without_port(host_header: str) -> str:
    raw = str(host_header or "").strip()
    if not raw or any(ch in raw for ch in ("\r", "\n", "\x00", " ", "/", "@")):
        return ""
    if raw.startswith("["):
        end = raw.find("]")
        if end < 0:
            return ""
        inner = raw[1:end]
        rest = raw[end + 1 :]
        if rest and not (rest.startswith(":") and rest[1:].isdigit()):
            return ""
        return inner.lower()
    if raw.count(":") == 1:
        h, p = raw.split(":", 1)
        if not p.isdigit():
            return ""
        return h.lower()
    if ":" in raw:
        return ""
    return raw.lower()


@contextlib.contextmanager
def _with_bot_bus_dir(bus_dir: str):
    """Thread-safe binding of `bot_bus` module-level paths to `bus_dir`."""
    target = os.path.abspath(os.path.expanduser(bus_dir))
    with _BOT_BUS_BIND_LOCK:
        prev_bus = bot_bus.BUS_DIR
        if os.path.abspath(prev_bus) == target:
            yield
            return
        saved = {
            "BUS_DIR": bot_bus.BUS_DIR,
            "JOBS_DIR": bot_bus.JOBS_DIR,
            "INBOX_DIR": bot_bus.INBOX_DIR,
            "GROUP_HISTORY_DIR": bot_bus.GROUP_HISTORY_DIR,
            "LOCK_FILE": bot_bus.LOCK_FILE,
            "CONFIG_FILE": bot_bus.CONFIG_FILE,
            "ROSTER_FILE": bot_bus.ROSTER_FILE,
            "THREADS_FILE": bot_bus.THREADS_FILE,
            "LOOP_GUARD_FILE": bot_bus.LOOP_GUARD_FILE,
            "MENTION_CHAINS_FILE": bot_bus.MENTION_CHAINS_FILE,
            "ORIGIN_CTX_FILE": bot_bus.ORIGIN_CTX_FILE,
            "DISPATCH_WINDOW_FILE": bot_bus.DISPATCH_WINDOW_FILE,
        }
        try:
            bot_bus.BUS_DIR = target
            bot_bus.JOBS_DIR = os.path.join(target, "jobs")
            bot_bus.INBOX_DIR = os.path.join(target, "inbox")
            bot_bus.GROUP_HISTORY_DIR = os.path.join(target, "group_history")
            bot_bus.LOCK_FILE = os.path.join(target, "bus.lock")
            bot_bus.CONFIG_FILE = os.path.join(target, "team_config.json")
            bot_bus.ROSTER_FILE = os.path.join(target, "roster.json")
            bot_bus.THREADS_FILE = os.path.join(target, "threads.json")
            bot_bus.LOOP_GUARD_FILE = os.path.join(target, "loop_guard.json")
            bot_bus.MENTION_CHAINS_FILE = os.path.join(target, "mention_chains.json")
            bot_bus.ORIGIN_CTX_FILE = os.path.join(target, "origin_context.json")
            bot_bus.DISPATCH_WINDOW_FILE = os.path.join(target, "dispatch_window.json")
            yield
        finally:
            for k, v in saved.items():
                setattr(bot_bus, k, v)


def compute_replay_signature(
    raw_token: str,
    timestamp: str,
    nonce: str,
    method: str,
    path: str,
    body: bytes,
) -> str:
    """Compute canonical `HMAC-SHA256(token, f'{ts}.{nonce}.{METHOD}.{path}.{sha256(body)}')`."""
    path_only = urlsplit(str(path or "/")).path or "/"
    body_hash = hashlib.sha256(body if isinstance(body, (bytes, bytearray)) else b"").hexdigest()
    canonical = f"{timestamp}.{nonce}.{str(method or 'GET').upper()}.{path_only}.{body_hash}"
    return hmac.new(
        str(raw_token).encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def build_replay_headers(
    raw_token: str,
    method: str,
    path: str,
    body: bytes = b"",
    *,
    timestamp: Optional[int] = None,
    nonce: Optional[str] = None,
) -> Dict[str, str]:
    """Build signed anti-replay headers for Federation Hub requests."""
    ts_str = str(int(time.time()) if timestamp is None else int(timestamp))
    nonce_str = str(nonce) if nonce is not None else secrets.token_urlsafe(18)
    sig = compute_replay_signature(raw_token, ts_str, nonce_str, method, path, body)
    return {
        "X-Agy-Timestamp": ts_str,
        "X-Agy-Nonce": nonce_str,
        "X-Agy-Signature": sig,
    }


class BoundedNonceCache:
    """Thread-safe TTL + capacity-bounded replay Nonce deduplication cache."""

    def __init__(self, *, ttl_sec: float = DEFAULT_REPLAY_WINDOW_SEC, max_entries: int = DEFAULT_NONCE_CACHE_MAX):
        self.ttl_sec = max(1.0, float(ttl_sec))
        self.max_entries = max(1, int(max_entries))
        self._lock = threading.Lock()
        self._entries: "collections.OrderedDict[Tuple[str, str], float]" = collections.OrderedDict()

    def check_and_record(self, agent_id: str, nonce: str, *, now: Optional[float] = None) -> bool:
        """Return True and record if `(agent_id, nonce)` is fresh; False on replay."""
        ts = time.time() if now is None else float(now)
        key = (str(agent_id), str(nonce))
        with self._lock:
            # Evict expired entries from the oldest side
            cutoff = ts - self.ttl_sec
            while self._entries:
                oldest_k, oldest_ts = next(iter(self._entries.items()))
                if oldest_ts < cutoff:
                    self._entries.popitem(last=False)
                else:
                    break
            if key in self._entries:
                return False
            while len(self._entries) >= self.max_entries:
                self._entries.popitem(last=False)
            self._entries[key] = ts
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class SlidingWindowRateLimiter:
    """Thread-safe per-key sliding-window rate limiter returning `(allowed, retry_after_sec)`."""

    def __init__(self, *, max_requests: int = DEFAULT_RATE_LIMIT_MAX_REQUESTS, window_sec: float = DEFAULT_RATE_LIMIT_WINDOW_SEC):
        self.max_requests = max(1, int(max_requests))
        self.window_sec = max(1.0, float(window_sec))
        self._lock = threading.Lock()
        self._buckets: Dict[str, collections.deque[float]] = {}

    def allow(self, key: str, *, now: Optional[float] = None) -> Tuple[bool, int]:
        ts = time.monotonic() if now is None else float(now)
        cutoff = ts - self.window_sec
        with self._lock:
            dq = self._buckets.get(key)
            if dq is None:
                dq = collections.deque()
                self._buckets[key] = dq
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= self.max_requests:
                wait_sec = max(1, int(math.ceil(dq[0] + self.window_sec - ts)))
                return False, wait_sec
            dq.append(ts)
            return True, 0


# ---------------------------------------------------------------- Structured Audit Logger (M2-C8)
class AuditLogger:
    """`flock`-serialized, `0600` secret-redacted JSONL audit logger under `<BUS_DIR>/federation/audit.jsonl`."""

    def __init__(self, bus_dir: Optional[str] = None):
        self.bus_dir = federation_registry._resolve_bus_dir(bus_dir)

    @property
    def log_path(self) -> str:
        return os.path.join(federation_registry.federation_dir(self.bus_dir), "audit.jsonl")

    @property
    def lock_path(self) -> str:
        return os.path.join(federation_registry.federation_dir(self.bus_dir), "audit.lock")

    @staticmethod
    def _sanitize_value(val: Any, extra_secrets: Sequence[str], _depth: int = 0) -> Any:
        if _depth > 8:
            return "[TRUNCATED]"
        if val is None or isinstance(val, (bool, int, float)):
            return val
        if isinstance(val, str):
            return federation_registry.redact_secrets(val, extra_secrets=extra_secrets)[:2000]
        if isinstance(val, dict):
            return {
                federation_registry.redact_secrets(str(k), extra_secrets=extra_secrets)[:200]: AuditLogger._sanitize_value(
                    v, extra_secrets, _depth + 1
                )
                for k, v in val.items()
            }
        if isinstance(val, (list, tuple)):
            return [AuditLogger._sanitize_value(item, extra_secrets, _depth + 1) for item in val[:50]]
        return federation_registry.redact_secrets(str(val), extra_secrets=extra_secrets)[:1000]

    def record(
        self,
        event_type: str,
        *,
        actor_id: str = "",
        action: str = "",
        outcome: str = "",
        http_status: int = 0,
        reason: str = "",
        detail: Optional[Dict[str, Any]] = None,
        extra_secrets: Sequence[str] = (),
    ) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "ts": round(time.time(), 6),
            "event": str(event_type or "hub_event"),
            "actor_id": str(actor_id or ""),
            "action": str(action or ""),
            "outcome": str(outcome or ""),
            "http_status": int(http_status or 0),
            "reason": str(reason or ""),
            "detail": detail if isinstance(detail, dict) else {},
        }
        sanitized = self._sanitize_value(entry, extra_secrets)
        fdir = federation_registry.federation_dir(self.bus_dir)
        federation_registry._ensure_secure_dir(fdir)
        lock_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        os.chmod(self.lock_path, 0o600)
        serialized = json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"))
        for sec in extra_secrets:
            if sec and len(sec) >= 4:
                serialized = serialized.replace(sec, "[REDACTED]")
                esc_sec = json.dumps(sec, ensure_ascii=False)[1:-1]
                if esc_sec and esc_sec != sec:
                    serialized = serialized.replace(esc_sec, "[REDACTED]")
        serialized = re.sub(r"(?<![A-Za-z0-9])agy_fed_[A-Za-z0-9._-]{12,}", "[REDACTED]", serialized)
        line = serialized + "\n"
        with os.fdopen(lock_fd, "a+", encoding="utf-8") as lf:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
            try:
                log_fd = os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                os.chmod(self.log_path, 0o600)
                with os.fdopen(log_fd, "a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
            finally:
                fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
        return sanitized


# ---------------------------------------------------------------- Host Server Bridge & Three Hard Locks (M2-C2, M2-C3)
def check_host_server_eligibility(auth: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify strict 4-tuple eligibility for Host Server Bridge tools (`M2-C2`)."""
    if not isinstance(auth, dict) or not auth.get("authorized") or not auth.get("token_verified"):
        return False, "caller is not an active verified agent"
    agent = auth.get("agent")
    if not isinstance(agent, dict):
        return False, "missing registered agent record"
    if agent.get("revoked") or not agent.get("enabled", True):
        return False, "agent is revoked or disabled"
    caps = agent.get("capabilities") or {}
    if caps.get("host_server_invoke") is not True:
        return False, "capabilities.host_server_invoke must be True"
    if caps.get("coordinator_peer") is not True:
        return False, "capabilities.coordinator_peer must be True"
    trust = str(agent.get("trust_level") or "").strip().lower()
    if trust not in _HOST_ELIGIBLE_TRUST_LEVELS:
        return False, f"trust_level {trust!r} is not eligible for host server invoke"
    return True, ""


def _path_is_equal_or_under(candidate: str, root: str) -> bool:
    if not candidate or not root:
        return False
    c = os.path.normpath(candidate)
    r = os.path.normpath(root)
    return c == r or c.startswith(r + os.sep)


def _expand_and_resolve_path(raw_path: str, *, base_dir: Optional[str] = None, home_dir: Optional[str] = None) -> Tuple[str, str]:
    """Return `(abs_path, real_path)` resolving symlinks even when the leaf does not yet exist."""
    raw = str(raw_path or "")
    if not raw or "\x00" in raw:
        raise HubError(400, "INVALID_PATH", "Path must be a non-empty string without null bytes", rpc_code=-32602)
    eff_home = os.path.abspath(home_dir) if home_dir else os.path.expanduser("~")
    if raw == "~":
        expanded = eff_home
    elif raw.startswith("~/"):
        expanded = os.path.join(eff_home, raw[2:])
    else:
        expanded = os.path.expanduser(raw)
    if not os.path.isabs(expanded):
        anchor = os.path.abspath(base_dir) if base_dir else os.getcwd()
        expanded = os.path.join(anchor, expanded)
    abs_p = os.path.abspath(expanded)
    real_p = os.path.realpath(abs_p)
    return abs_p, real_p


def _collect_lock_roots(
    *,
    bus_dir: str,
    repo_root: str,
    home_dir: Optional[str] = None,
) -> Dict[str, set[str]]:
    """Collect canonical Lock 1/2/3 directories and files (both read+write and write-only)."""
    eff_home = os.path.abspath(home_dir) if home_dir else os.path.expanduser("~")
    eff_home_real = os.path.realpath(eff_home)
    fed_dir_abs = os.path.abspath(federation_registry.federation_dir(bus_dir))
    fed_dir_real = os.path.realpath(fed_dir_abs)
    default_fed_dir = os.path.abspath(
        os.path.join(eff_home, ".gemini", "antigravity-cli", "cache", "bot_bus", "federation")
    )
    team_cfg_abs = os.path.abspath(os.path.join(bus_dir, "team_config.json"))
    team_cfg_real = os.path.realpath(team_cfg_abs)
    default_team_cfg = os.path.abspath(
        os.path.join(eff_home, ".gemini", "antigravity-cli", "cache", "bot_bus", "team_config.json")
    )
    repo_abs = os.path.abspath(repo_root)
    repo_real = os.path.realpath(repo_abs)

    lock1_dirs = {
        fed_dir_abs,
        fed_dir_real,
        default_fed_dir,
        os.path.join(repo_abs, "hooks"),
        os.path.join(repo_real, "hooks"),
        os.path.join(repo_abs, ".agents", "rules"),
        os.path.join(repo_real, ".agents", "rules"),
        os.path.join(eff_home, ".gemini", "config", "hooks"),
        os.path.join(eff_home_real, ".gemini", "config", "hooks"),
        os.path.join(eff_home, "agy-workspace", ".agents", "rules"),
    }
    lock1_files = {
        team_cfg_abs,
        team_cfg_real,
        default_team_cfg,
        os.path.join(repo_abs, "AGENTS.md"),
        os.path.join(repo_real, "AGENTS.md"),
        os.path.join(eff_home, "agy-workspace", "AGENTS.md"),
        os.path.join(eff_home, ".gemini", "config", "hooks.json"),
        os.path.join(eff_home_real, ".gemini", "config", "hooks.json"),
        os.path.join(repo_abs, "bridge", "memory_guard.py"),
        os.path.join(repo_real, "bridge", "memory_guard.py"),
    }

    lock1_write_dirs = {
        os.path.join(repo_abs, "systemd"),
        os.path.join(repo_real, "systemd"),
        os.path.join(repo_abs, ".git"),
        os.path.join(repo_real, ".git"),
        os.path.join(eff_home, "agy-tg-bridge"),
        os.path.realpath(os.path.join(eff_home, "agy-tg-bridge")),
        os.path.join(eff_home_real, "agy-tg-bridge"),
        os.path.join(eff_home, ".local", "bin"),
        os.path.realpath(os.path.join(eff_home, ".local", "bin")),
        os.path.join(eff_home_real, ".local", "bin"),
        os.path.join(eff_home, ".gemini"),
        os.path.realpath(os.path.join(eff_home, ".gemini")),
        os.path.join(eff_home_real, ".gemini"),
        os.path.join(eff_home, ".config", "systemd"),
        os.path.realpath(os.path.join(eff_home, ".config", "systemd")),
        os.path.join(eff_home_real, ".config", "systemd"),
        "/etc/systemd",
    }
    lock1_write_files: set[str] = set()
    repo_bases = {repo_abs, repo_real, os.path.join(eff_home, "agy-cli-bot"), os.path.join(eff_home_real, "agy-cli-bot")}
    for rb in repo_bases:
        for rel_f in _LOCK1_WRITE_PROTECTED_REPO_FILES:
            lock1_write_files.add(os.path.abspath(os.path.join(rb, rel_f)))
            lock1_write_files.add(os.path.realpath(os.path.join(rb, rel_f)))
    for hb in {eff_home, eff_home_real}:
        for hf in _LOCK1_WRITE_PROTECTED_HOME_FILES:
            lock1_write_files.add(os.path.abspath(os.path.join(hb, hf)))
            lock1_write_files.add(os.path.realpath(os.path.join(hb, hf)))

    lock2_dirs = {
        os.path.join(eff_home, ".ssh"),
        os.path.realpath(os.path.join(eff_home, ".ssh")),
        os.path.join(eff_home_real, ".ssh"),
        os.path.join(eff_home, ".config", "agy-tg-bridge"),
        os.path.realpath(os.path.join(eff_home, ".config", "agy-tg-bridge")),
        os.path.join(eff_home_real, ".config", "agy-tg-bridge"),
        os.path.join(eff_home, ".config", "openbao"),
        os.path.realpath(os.path.join(eff_home, ".config", "openbao")),
        os.path.join(eff_home_real, ".config", "openbao"),
    }

    lock3_files: set[str] = set()
    for rel_pf in _PROTECTED_CODE_REL_PATHS:
        lock3_files.add(os.path.abspath(os.path.join(repo_abs, rel_pf)))
        lock3_files.add(os.path.realpath(os.path.join(repo_abs, rel_pf)))
        lock3_files.add(os.path.abspath(os.path.join(eff_home, "agy-workspace", rel_pf)))
        lock3_files.add(os.path.realpath(os.path.join(eff_home, "agy-workspace", rel_pf)))
    lock3_dirs = {
        os.path.abspath(os.path.join(eff_home, ".local", "share", "camoufox-profiles", "fisherwseven")),
        os.path.realpath(os.path.join(eff_home, ".local", "share", "camoufox-profiles", "fisherwseven")),
        os.path.abspath(os.path.join(eff_home, ".cache", "camoufox-profiles", "fisherwseven")),
        os.path.realpath(os.path.join(eff_home, ".cache", "camoufox-profiles", "fisherwseven")),
        "/etc/systemd/system",
        os.path.join(repo_abs, "systemd"),
        os.path.join(repo_real, "systemd"),
        os.path.join(eff_home, ".config", "systemd"),
    }
    return {
        "lock1_dirs": lock1_dirs,
        "lock1_files": lock1_files,
        "lock1_write_dirs": lock1_write_dirs,
        "lock1_write_files": lock1_write_files,
        "lock2_dirs": lock2_dirs,
        "lock3_dirs": lock3_dirs,
        "lock3_files": lock3_files,
    }


def _check_dir_not_containing_protected_subtree(
    abs_p: str,
    real_p: str,
    *,
    bus_dir: str,
    repo_root: str,
    home_dir: Optional[str] = None,
) -> None:
    """Reject directory targets that are ancestors of any Lock 1/2/3 protected root (`M2-B1`)."""
    roots = _collect_lock_roots(bus_dir=bus_dir, repo_root=repo_root, home_dir=home_dir)
    candidates = [abs_p] if abs_p == real_p else [abs_p, real_p]
    lock1_roots = roots["lock1_dirs"] | roots["lock1_files"]
    lock2_roots = roots["lock2_dirs"] | {"/proc"}
    lock3_roots = roots["lock3_dirs"] | roots["lock3_files"]
    for cand in candidates:
        for r in lock1_roots:
            if _path_is_equal_or_under(r, cand):
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    "HOST_LOCK1_DENIED: directory target contains protected Lock 1 subtree",
                    rpc_code=-32003,
                )
        for r in lock2_roots:
            if _path_is_equal_or_under(r, cand):
                raise HubError(
                    403,
                    "HOST_LOCK2_DENIED",
                    "HOST_LOCK2_DENIED: directory target contains protected Lock 2 subtree",
                    rpc_code=-32003,
                )
        for r in lock3_roots:
            if _path_is_equal_or_under(r, cand):
                raise HubError(
                    403,
                    "HOST_LOCK3_DENIED",
                    "HOST_LOCK3_DENIED: directory target contains protected Lock 3 subtree",
                    rpc_code=-32003,
                )


def _check_path_against_locks(
    raw_path: str,
    *,
    bus_dir: str,
    repo_root: str,
    home_dir: Optional[str] = None,
    base_dir: Optional[str] = None,
    write: bool = False,
) -> Tuple[str, str]:
    """Validate `raw_path` (both pre-symlink `abspath` and post-symlink `realpath`) against Locks 1, 2, 3."""
    eff_home = os.path.abspath(home_dir) if home_dir else os.path.expanduser("~")
    abs_p, real_p = _expand_and_resolve_path(raw_path, base_dir=base_dir, home_dir=eff_home)
    candidates = [abs_p] if abs_p == real_p else [abs_p, real_p]

    roots = _collect_lock_roots(bus_dir=bus_dir, repo_root=repo_root, home_dir=eff_home)
    lock1_dirs = roots["lock1_dirs"]
    lock1_files = roots["lock1_files"]
    lock1_write_dirs = roots["lock1_write_dirs"]
    lock1_write_files = roots["lock1_write_files"]
    lock2_dirs = roots["lock2_dirs"]
    lock3_files = roots["lock3_files"]
    lock3_dirs = roots["lock3_dirs"]

    # --- Lock 1: Federation registry, team_config.json, hooks, .agents/rules, AGENTS.md, memory_guard.py
    #             (+ M2-B4 core security/runtime/shell persistence paths on write)
    for cand in candidates:
        c_posix = cand.replace("\\", "/")
        c_low = c_posix.lower()
        base = os.path.basename(cand)
        for d in lock1_dirs:
            if _path_is_equal_or_under(cand, d):
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: governance/federation path access forbidden ({base})",
                    rpc_code=-32003,
                )
        if cand in lock1_files or base in ("AGENTS.md", "team_config.json", "memory_guard.py"):
            raise HubError(
                403,
                "HOST_LOCK1_DENIED",
                f"HOST_LOCK1_DENIED: protected governance file access forbidden ({base})",
                rpc_code=-32003,
            )
        if "/.agents/rules/" in c_low or c_low.endswith("/.agents/rules"):
            raise HubError(
                403,
                "HOST_LOCK1_DENIED",
                "HOST_LOCK1_DENIED: .agents/rules path access forbidden",
                rpc_code=-32003,
            )
        if write:
            for d in lock1_write_dirs:
                if _path_is_equal_or_under(cand, d):
                    raise HubError(
                        403,
                        "HOST_LOCK1_DENIED",
                        f"HOST_LOCK1_DENIED: write to protected core/runtime/persistence directory forbidden ({base})",
                        rpc_code=-32003,
                    )
            if cand in lock1_write_files:
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: write to protected core/persistence file forbidden ({base})",
                    rpc_code=-32003,
                )
            if "/.git/" in c_low or c_low.endswith("/.git"):
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    "HOST_LOCK1_DENIED: write inside .git directory is strictly forbidden",
                    rpc_code=-32003,
                )

    # --- Lock 2: Vault / Secrets / *.env* / *.token / *.pem / *.key / ~/.ssh / /proc/<pid>/* (M2-B3)
    for cand in candidates:
        c_posix = cand.replace("\\", "/")
        c_low = c_posix.lower()
        base = os.path.basename(cand)
        base_low = base.lower()
        if _PROC_PROCESS_RE.fullmatch(c_posix):
            raise HubError(
                403,
                "HOST_LOCK2_DENIED",
                "HOST_LOCK2_DENIED: per-process /proc access is strictly forbidden",
                rpc_code=-32003,
            )
        if (
            base_low == ".env"
            or base_low.startswith(".env.")
            or ".env." in base_low
            or any(base_low.endswith(suf) for suf in _LOCK2_SECRET_SUFFIXES)
            or base_low in _LOCK2_SECRET_BASENAMES
        ):
            raise HubError(
                403,
                "HOST_LOCK2_DENIED",
                f"HOST_LOCK2_DENIED: secret/credential file access forbidden ({base})",
                rpc_code=-32003,
            )
        if "/.ssh/" in c_low or c_low.endswith("/.ssh"):
            raise HubError(
                403,
                "HOST_LOCK2_DENIED",
                "HOST_LOCK2_DENIED: SSH credential directory access forbidden",
                rpc_code=-32003,
            )
        for d in lock2_dirs:
            if _path_is_equal_or_under(cand, d):
                raise HubError(
                    403,
                    "HOST_LOCK2_DENIED",
                    f"HOST_LOCK2_DENIED: credential directory access forbidden ({base})",
                    rpc_code=-32003,
                )

    # --- Lock 3: Protected code files, primary fisherwseven Camoufox profile, systemd units
    for cand in candidates:
        c_posix = cand.replace("\\", "/")
        c_low = c_posix.lower()
        base = os.path.basename(cand)
        if (
            cand in lock3_files
            or c_low.endswith("/google-profile/scripts/google_browser.py")
            or c_low.endswith("/live-browser/scripts/static/index.html")
        ):
            raise HubError(
                403,
                "HOST_LOCK3_DENIED",
                f"HOST_LOCK3_DENIED: protected host code file access forbidden ({base})",
                rpc_code=-32003,
            )
        if "/camoufox-profiles/fisherwseven/" in c_low or c_low.endswith("/camoufox-profiles/fisherwseven"):
            raise HubError(
                403,
                "HOST_LOCK3_DENIED",
                "HOST_LOCK3_DENIED: primary host-pinned fisherwseven browser profile access forbidden",
                rpc_code=-32003,
            )
        for d in lock3_dirs:
            if _path_is_equal_or_under(cand, d):
                raise HubError(
                    403,
                    "HOST_LOCK3_DENIED",
                    f"HOST_LOCK3_DENIED: protected host asset/systemd path access forbidden ({base})",
                    rpc_code=-32003,
                )

    # Fallback check against memory_guard protected governance paths (mapped to Lock 1)
    for cand in candidates:
        try:
            is_prot, lbl = memory_guard._is_protected_guard_path(cand)
            if is_prot:
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: guarded governance path ({lbl}) access forbidden",
                    rpc_code=-32003,
                )
        except HubError:
            raise
        except Exception:
            pass

    return abs_p, real_p


def build_sanitized_exec_env(base_env: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """Return a child environment with all sensitive tokens, keys, passwords, and vault vars stripped."""
    src = os.environ if base_env is None else base_env
    clean: Dict[str, str] = {}
    for k, v in src.items():
        ku = str(k).upper()
        if ku in _SENSITIVE_ENV_EXACT or _SENSITIVE_ENV_RE.search(ku):
            continue
        clean[str(k)] = str(v)
    return clean


def _validate_git_args(
    args: Sequence[str],
    *,
    eff_workdir: str,
    bus_dir: str,
    repo_root: str,
    home_dir: Optional[str],
) -> None:
    """Strict read-only metadata subcommand & flag allowlist for `git` (`M2-B2`)."""
    if not args:
        raise HubError(
            403,
            "HOST_LOCK1_DENIED",
            "HOST_LOCK1_DENIED: git requires an allowlisted read-only metadata subcommand",
            rpc_code=-32003,
        )
    if args[0].startswith("-"):
        raise HubError(
            403,
            "HOST_LOCK1_DENIED",
            f"HOST_LOCK1_DENIED: pre-subcommand git flag {args[0]!r} is forbidden",
            rpc_code=-32003,
        )
    subcmd = args[0].strip().lower()
    if subcmd not in _GIT_ALLOWED_SUBCOMMANDS:
        raise HubError(
            403,
            "HOST_LOCK1_DENIED",
            f"HOST_LOCK1_DENIED: git subcommand {subcmd!r} is not in read-only metadata allowlist",
            rpc_code=-32003,
        )

    def _check_git_pos(tok: str) -> None:
        if ":" in tok:
            raise HubError(
                403,
                "HOST_LOCK1_DENIED",
                f"HOST_LOCK1_DENIED: git object/content spec {tok!r} is forbidden",
                rpc_code=-32003,
            )
        _check_path_against_locks(
            tok,
            bus_dir=bus_dir,
            repo_root=repo_root,
            home_dir=home_dir,
            base_dir=eff_workdir,
            write=False,
        )

    sub_args = list(args[1:])
    if subcmd == "status":
        end_opts = False
        for a in sub_args:
            if not end_opts and a == "--":
                end_opts = True
                continue
            if not end_opts and a.startswith("-"):
                if a not in _GIT_STATUS_ALLOWED_FLAGS:
                    raise HubError(
                        403,
                        "HOST_LOCK1_DENIED",
                        f"HOST_LOCK1_DENIED: forbidden git status flag {a!r}",
                        rpc_code=-32003,
                    )
            else:
                _check_git_pos(a)
        return

    if subcmd == "branch":
        has_list = False
        pos_args: List[str] = []
        end_opts = False
        for a in sub_args:
            if not end_opts and a == "--":
                end_opts = True
                continue
            if not end_opts and a.startswith("-"):
                if a not in _GIT_BRANCH_ALLOWED_FLAGS:
                    raise HubError(
                        403,
                        "HOST_LOCK1_DENIED",
                        f"HOST_LOCK1_DENIED: forbidden git branch flag {a!r}",
                        rpc_code=-32003,
                    )
                if a == "--list":
                    has_list = True
            else:
                pos_args.append(a)
        if pos_args and not has_list:
            raise HubError(
                403,
                "HOST_LOCK1_DENIED",
                "HOST_LOCK1_DENIED: creating/modifying git branches is forbidden (use --list for read-only inspection)",
                rpc_code=-32003,
            )
        for p in pos_args:
            _check_git_pos(p)
        return

    if subcmd == "rev-parse":
        for a in sub_args:
            if a.startswith("-"):
                if a in _GIT_REV_PARSE_ALLOWED_FLAGS or re.fullmatch(r"--short=\d+", a):
                    continue
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: forbidden git rev-parse flag {a!r}",
                    rpc_code=-32003,
                )
            if ":" in a or ".." in a or not re.fullmatch(r"[A-Za-z0-9_./@^~-]+", a):
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: forbidden git rev-parse ref {a!r}",
                    rpc_code=-32003,
                )
            _check_git_pos(a)
        return

    if subcmd == "describe":
        for a in sub_args:
            if a.startswith("-"):
                if a in _GIT_DESCRIBE_ALLOWED_FLAGS or re.fullmatch(r"--abbrev=\d+", a):
                    continue
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: forbidden git describe flag {a!r}",
                    rpc_code=-32003,
                )
            _check_git_pos(a)
        return

    if subcmd == "log":
        i = 0
        end_opts = False
        while i < len(sub_args):
            a = sub_args[i]
            if not end_opts and a == "--":
                end_opts = True
                i += 1
                continue
            if not end_opts and a.startswith("-"):
                if a in _GIT_LOG_ALLOWED_BOOL_FLAGS:
                    i += 1
                    continue
                if a in _GIT_LOG_ALLOWED_NUM_FLAGS:
                    if i + 1 >= len(sub_args) or not sub_args[i + 1].isdigit():
                        raise HubError(
                            403,
                            "HOST_LOCK1_DENIED",
                            f"HOST_LOCK1_DENIED: git log {a!r} requires a non-negative integer",
                            rpc_code=-32003,
                        )
                    i += 2
                    continue
                if a.startswith("-n") and len(a) > 2 and a[2:].isdigit():
                    i += 1
                    continue
                if a.startswith("--max-count=") and a.split("=", 1)[1].isdigit():
                    i += 1
                    continue
                if a in _GIT_LOG_ALLOWED_DATE_FLAGS:
                    if i + 1 >= len(sub_args) or sub_args[i + 1].startswith("-"):
                        raise HubError(
                            403,
                            "HOST_LOCK1_DENIED",
                            f"HOST_LOCK1_DENIED: invalid git log date option {a!r}",
                            rpc_code=-32003,
                        )
                    i += 2
                    continue
                if "=" in a:
                    fl, val = a.split("=", 1)
                    if fl in _GIT_LOG_ALLOWED_DATE_FLAGS and val and not val.startswith("-"):
                        i += 1
                        continue
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: forbidden git log flag {a!r}",
                    rpc_code=-32003,
                )
            _check_git_pos(a)
            i += 1
        return

    if subcmd == "diff":
        has_summary = False
        end_opts = False
        for a in sub_args:
            if not end_opts and a == "--":
                end_opts = True
                continue
            if not end_opts and a.startswith("-"):
                if a in _GIT_DIFF_SUMMARY_FLAGS:
                    has_summary = True
                    continue
                if a in _GIT_DIFF_EXTRA_FLAGS:
                    continue
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: forbidden git diff flag {a!r}",
                    rpc_code=-32003,
                )
            _check_git_pos(a)
        if not has_summary:
            raise HubError(
                403,
                "HOST_LOCK1_DENIED",
                "HOST_LOCK1_DENIED: git diff requires a summary-only flag (--stat/--numstat/--shortstat/--name-only/--name-status/--summary)",
                rpc_code=-32003,
            )
        return


def _validate_command_specific_args(
    exe_base: str,
    args: Sequence[str],
    *,
    eff_workdir: str,
    bus_dir: str,
    repo_root: str,
    home_dir: Optional[str],
) -> None:
    """Enforce strict per-command flag whitelists and path lock checks (`M2-B1`, `M2-B2`, `M2-B4`)."""
    if exe_base == "git":
        _validate_git_args(args, eff_workdir=eff_workdir, bus_dir=bus_dir, repo_root=repo_root, home_dir=home_dir)
        return

    if exe_base == "grep":
        i = 0
        end_opts = False
        pattern_seen = False
        file_args: List[str] = []
        while i < len(args):
            a = args[i]
            if not end_opts and a == "--":
                end_opts = True
                i += 1
                continue
            if not end_opts and a.startswith("-") and a != "-":
                if a in _GREP_ALLOWED_BOOL_FLAGS:
                    i += 1
                    continue
                if a in _GREP_ALLOWED_NUM_FLAGS:
                    if i + 1 >= len(args) or not args[i + 1].isdigit():
                        raise HubError(
                            403,
                            "HOST_LOCK1_DENIED",
                            f"HOST_LOCK1_DENIED: grep option {a!r} requires a non-negative integer",
                            rpc_code=-32003,
                        )
                    i += 2
                    continue
                if "=" in a:
                    fl, val = a.split("=", 1)
                    if fl in _GREP_ALLOWED_NUM_LONG_FLAGS and val.isdigit():
                        i += 1
                        continue
                    raise HubError(
                        403,
                        "HOST_LOCK1_DENIED",
                        f"HOST_LOCK1_DENIED: forbidden grep option {a!r}",
                        rpc_code=-32003,
                    )
                if a in ("-e", "--regexp"):
                    if i + 1 >= len(args):
                        raise HubError(400, "INVALID_EXEC_ARGS", f"Missing pattern for grep {a!r}", rpc_code=-32602)
                    pattern_seen = True
                    i += 2
                    continue
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: forbidden/combined grep flag {a!r}",
                    rpc_code=-32003,
                )
            if not pattern_seen:
                pattern_seen = True
                i += 1
                continue
            file_args.append(a)
            i += 1
        for fp in file_args:
            if fp == "-":
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    "HOST_LOCK1_DENIED: grep '-' file target is forbidden",
                    rpc_code=-32003,
                )
            abs_p, real_p = _check_path_against_locks(
                fp,
                bus_dir=bus_dir,
                repo_root=repo_root,
                home_dir=home_dir,
                base_dir=eff_workdir,
                write=False,
            )
            if os.path.isdir(abs_p) or os.path.isdir(real_p):
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: grep directory target is forbidden ({fp})",
                    rpc_code=-32003,
                )
            _check_dir_not_containing_protected_subtree(
                abs_p,
                real_p,
                bus_dir=bus_dir,
                repo_root=repo_root,
                home_dir=home_dir,
            )
        return

    if exe_base == "ls":
        end_opts = False
        targets: List[str] = []
        for a in args:
            if not end_opts and a == "--":
                end_opts = True
                continue
            if not end_opts and a.startswith("-") and a != "-":
                if a.startswith("--"):
                    if a not in _LS_ALLOWED_LONG_FLAGS:
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden ls flag {a!r}", rpc_code=-32003)
                else:
                    chars = a[1:]
                    if not chars or any(ch not in _LS_ALLOWED_SHORT_CHARS for ch in chars):
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden ls flag {a!r}", rpc_code=-32003)
            else:
                targets.append(a)
        for tgt in (targets or [eff_workdir]):
            _check_path_against_locks(tgt, bus_dir=bus_dir, repo_root=repo_root, home_dir=home_dir, base_dir=eff_workdir, write=False)
        return

    if exe_base == "du":
        i = 0
        end_opts = False
        targets = []
        while i < len(args):
            a = args[i]
            if not end_opts and a == "--":
                end_opts = True
                i += 1
                continue
            if not end_opts and a.startswith("-") and a != "-":
                if a in ("-d", "--max-depth"):
                    if i + 1 >= len(args) or not args[i + 1].isdigit():
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: du {a!r} requires a non-negative integer", rpc_code=-32003)
                    i += 2
                    continue
                if a.startswith("--max-depth=") and a.split("=", 1)[1].isdigit():
                    i += 1
                    continue
                if a.startswith("--"):
                    if a not in _DU_ALLOWED_LONG_FLAGS:
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden du flag {a!r}", rpc_code=-32003)
                    i += 1
                    continue
                chars = a[1:]
                if not chars or any(ch not in _DU_ALLOWED_SHORT_CHARS for ch in chars):
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden du flag {a!r}", rpc_code=-32003)
                i += 1
                continue
            targets.append(a)
            i += 1
        for tgt in (targets or [eff_workdir]):
            abs_p, real_p = _check_path_against_locks(
                tgt,
                bus_dir=bus_dir,
                repo_root=repo_root,
                home_dir=home_dir,
                base_dir=eff_workdir,
                write=False,
            )
            _check_dir_not_containing_protected_subtree(
                abs_p,
                real_p,
                bus_dir=bus_dir,
                repo_root=repo_root,
                home_dir=home_dir,
            )
        return

    if exe_base == "cat":
        end_opts = False
        for a in args:
            if not end_opts and a == "--":
                end_opts = True
                continue
            if not end_opts and a.startswith("-") and a != "-":
                if a.startswith("--"):
                    if a not in _CAT_ALLOWED_LONG_FLAGS:
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden cat flag {a!r}", rpc_code=-32003)
                else:
                    chars = a[1:]
                    if not chars or any(ch not in _CAT_ALLOWED_SHORT_CHARS for ch in chars):
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden cat flag {a!r}", rpc_code=-32003)
            elif a != "-":
                _check_path_against_locks(a, bus_dir=bus_dir, repo_root=repo_root, home_dir=home_dir, base_dir=eff_workdir, write=False)
        return

    if exe_base in ("head", "tail"):
        i = 0
        end_opts = False
        while i < len(args):
            a = args[i]
            if not end_opts and a == "--":
                end_opts = True
                i += 1
                continue
            if not end_opts and a.startswith("-") and a != "-":
                if a in _HEAD_TAIL_BOOL_FLAGS:
                    i += 1
                    continue
                if a in _HEAD_TAIL_NUM_FLAGS:
                    if i + 1 >= len(args) or not _HEAD_TAIL_NUM_RE.fullmatch(args[i + 1]):
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: {exe_base} {a!r} requires numeric arg", rpc_code=-32003)
                    i += 2
                    continue
                if "=" in a:
                    fl, val = a.split("=", 1)
                    if fl in ("--lines", "--bytes") and _HEAD_TAIL_NUM_RE.fullmatch(val):
                        i += 1
                        continue
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden {exe_base} flag {a!r}", rpc_code=-32003)
                if len(a) > 2 and a[:2] in ("-n", "-c") and _HEAD_TAIL_NUM_RE.fullmatch(a[2:]):
                    i += 1
                    continue
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden {exe_base} flag {a!r}", rpc_code=-32003)
            if a != "-":
                _check_path_against_locks(a, bus_dir=bus_dir, repo_root=repo_root, home_dir=home_dir, base_dir=eff_workdir, write=False)
            i += 1
        return

    if exe_base == "wc":
        end_opts = False
        for a in args:
            if not end_opts and a == "--":
                end_opts = True
                continue
            if not end_opts and a.startswith("-") and a != "-":
                if a.startswith("--"):
                    if a not in _WC_ALLOWED_LONG_FLAGS:
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden wc flag {a!r}", rpc_code=-32003)
                else:
                    chars = a[1:]
                    if not chars or any(ch not in _WC_ALLOWED_SHORT_CHARS for ch in chars):
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden wc flag {a!r}", rpc_code=-32003)
            elif a != "-":
                _check_path_against_locks(a, bus_dir=bus_dir, repo_root=repo_root, home_dir=home_dir, base_dir=eff_workdir, write=False)
        return

    if exe_base == "file":
        end_opts = False
        for a in args:
            if not end_opts and a == "--":
                end_opts = True
                continue
            if not end_opts and a.startswith("-") and a != "-":
                if a not in _FILE_ALLOWED_FLAGS:
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden file flag {a!r}", rpc_code=-32003)
            elif a != "-":
                _check_path_against_locks(a, bus_dir=bus_dir, repo_root=repo_root, home_dir=home_dir, base_dir=eff_workdir, write=False)
        return

    if exe_base == "stat":
        i = 0
        end_opts = False
        while i < len(args):
            a = args[i]
            if not end_opts and a == "--":
                end_opts = True
                i += 1
                continue
            if not end_opts and a.startswith("-") and a != "-":
                if a in _STAT_ALLOWED_BOOL_FLAGS:
                    i += 1
                    continue
                if a in _STAT_ALLOWED_FMT_FLAGS:
                    if i + 1 >= len(args):
                        raise HubError(400, "INVALID_EXEC_ARGS", f"Missing format for stat {a!r}", rpc_code=-32602)
                    i += 2
                    continue
                if a.startswith("--format="):
                    i += 1
                    continue
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden stat flag {a!r}", rpc_code=-32003)
            _check_path_against_locks(a, bus_dir=bus_dir, repo_root=repo_root, home_dir=home_dir, base_dir=eff_workdir, write=False)
            i += 1
        return

    if exe_base in ("touch", "mkdir"):
        allowed_fl = _TOUCH_ALLOWED_FLAGS if exe_base == "touch" else _MKDIR_ALLOWED_FLAGS
        end_opts = False
        for a in args:
            if not end_opts and a == "--":
                end_opts = True
                continue
            if not end_opts and a.startswith("-") and a != "-":
                if a not in allowed_fl:
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden {exe_base} flag {a!r}", rpc_code=-32003)
            else:
                abs_p, real_p = _check_path_against_locks(
                    a,
                    bus_dir=bus_dir,
                    repo_root=repo_root,
                    home_dir=home_dir,
                    base_dir=eff_workdir,
                    write=True,
                )
                for p_parent in {os.path.dirname(abs_p), os.path.dirname(real_p)}:
                    if p_parent:
                        _check_path_against_locks(
                            p_parent,
                            bus_dir=bus_dir,
                            repo_root=repo_root,
                            home_dir=home_dir,
                            write=True,
                        )
        return

    if exe_base == "date":
        i = 0
        while i < len(args):
            a = args[i]
            if a in _DATE_ALLOWED_BOOL_FLAGS:
                i += 1
                continue
            if a.startswith("--iso-8601="):
                spec = a.split("=", 1)[1]
                if spec in _DATE_ALLOWED_ISO_SPEC:
                    i += 1
                    continue
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden date option {a!r}", rpc_code=-32003)
            if a == "--rfc-3339":
                if i + 1 >= len(args) or args[i + 1] not in _DATE_ALLOWED_RFC3339_SPEC:
                    raise HubError(403, "HOST_LOCK1_DENIED", "HOST_LOCK1_DENIED: invalid date --rfc-3339 value", rpc_code=-32003)
                i += 2
                continue
            if a.startswith("--rfc-3339="):
                spec = a.split("=", 1)[1]
                if spec in _DATE_ALLOWED_RFC3339_SPEC:
                    i += 1
                    continue
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden date option {a!r}", rpc_code=-32003)
            if _DATE_FORMAT_RE.fullmatch(a):
                i += 1
                continue
            raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden date argument {a!r}", rpc_code=-32003)
        return

    if exe_base == "ss":
        for a in args:
            if a.startswith("--"):
                if a not in _SS_ALLOWED_LONG_FLAGS:
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden ss flag {a!r}", rpc_code=-32003)
            elif a.startswith("-") and len(a) > 1:
                chars = a[1:]
                if any(ch not in _SS_ALLOWED_SHORT_CHARS for ch in chars):
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden ss flag {a!r}", rpc_code=-32003)
            else:
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden ss argument {a!r}", rpc_code=-32003)
        return

    if exe_base == "hostname":
        for a in args:
            if a not in _HOSTNAME_ALLOWED_FLAGS:
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden hostname argument {a!r}", rpc_code=-32003)
        return

    if exe_base == "ps":
        def _validate_ps_format_cols(spec: str) -> None:
            cols = [c.strip() for c in spec.split(",")]
            if not cols or any(not c for c in cols):
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: invalid ps format spec {spec!r}", rpc_code=-32003)
            for c in cols:
                if "=" in c:
                    col_name, header = c.split("=", 1)
                    if not _PS_COL_HEADER_RE.fullmatch(header):
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: invalid ps column header in {c!r}", rpc_code=-32003)
                else:
                    col_name = c
                if col_name.lower() not in _PS_ALLOWED_FORMAT_COLS:
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden ps format column {col_name!r}", rpc_code=-32003)

        saw_bsd = False
        saw_posix_e = False
        i = 0
        while i < len(args):
            a = args[i]
            if not a.startswith("-"):
                if "e" in a.lower():
                    raise HubError(
                        403,
                        "HOST_LOCK2_DENIED",
                        f"HOST_LOCK2_DENIED: ps BSD environment-inspection option {a!r} is strictly forbidden",
                        rpc_code=-32003,
                    )
                if a not in _PS_ALLOWED_BSD_TOKENS:
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden ps argument {a!r}", rpc_code=-32003)
                saw_bsd = True
                i += 1
                continue
            if a in _PS_ALLOWED_POSIX_BOOL_FLAGS:
                if a in _PS_POSIX_E_FLAGS:
                    saw_posix_e = True
                i += 1
                continue
            if a in ("-p", "--pid"):
                if i + 1 >= len(args) or not _PS_PID_LIST_RE.fullmatch(args[i + 1]):
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: ps {a!r} requires numeric PID list", rpc_code=-32003)
                i += 2
                continue
            if a.startswith("--pid=") and _PS_PID_LIST_RE.fullmatch(a.split("=", 1)[1]):
                i += 1
                continue
            if a in ("-o", "--format"):
                if i + 1 >= len(args):
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: ps {a!r} requires format columns", rpc_code=-32003)
                _validate_ps_format_cols(args[i + 1])
                i += 2
                continue
            if a.startswith("--format="):
                _validate_ps_format_cols(a.split("=", 1)[1])
                i += 1
                continue
            if a in ("-u", "-U", "--user"):
                if i + 1 >= len(args) or not _PS_USER_LIST_RE.fullmatch(args[i + 1]):
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: ps {a!r} requires safe user list", rpc_code=-32003)
                i += 2
                continue
            if a.startswith("--user=") and _PS_USER_LIST_RE.fullmatch(a.split("=", 1)[1]):
                i += 1
                continue
            if a == "-C":
                if i + 1 >= len(args) or not _PS_COMM_LIST_RE.fullmatch(args[i + 1]):
                    raise HubError(403, "HOST_LOCK1_DENIED", "HOST_LOCK1_DENIED: ps -C requires safe command list", rpc_code=-32003)
                i += 2
                continue
            # Reject any unrecognized flag (notably -ex / -eax / -x which trigger procps BSD-mode environ leak!)
            if "e" in a.lower() and ("x" in a.lower() or "a" in a.lower()):
                raise HubError(
                    403,
                    "HOST_LOCK2_DENIED",
                    f"HOST_LOCK2_DENIED: mixed POSIX/BSD ps flag {a!r} can expose process environ and is forbidden",
                    rpc_code=-32003,
                )
            raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden ps flag {a!r}", rpc_code=-32003)
        if saw_bsd and saw_posix_e:
            raise HubError(
                403,
                "HOST_LOCK2_DENIED",
                "HOST_LOCK2_DENIED: mixing ps -e with BSD flags is forbidden",
                rpc_code=-32003,
            )
        return

    if exe_base == "pwd":
        for a in args:
            if a not in _PWD_ALLOWED_FLAGS:
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden pwd argument {a!r}", rpc_code=-32003)
        return

    if exe_base == "whoami":
        if args:
            raise HubError(403, "HOST_LOCK1_DENIED", "HOST_LOCK1_DENIED: whoami takes no arguments", rpc_code=-32003)
        return

    if exe_base == "id":
        pos_count = 0
        for a in args:
            if a.startswith("-"):
                if a not in _ID_ALLOWED_FLAGS:
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden id flag {a!r}", rpc_code=-32003)
            else:
                pos_count += 1
                if pos_count > 1 or not _BARE_IDENT_RE.fullmatch(a):
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden id argument {a!r}", rpc_code=-32003)
        return

    if exe_base == "uname":
        for a in args:
            if a.startswith("--"):
                if a not in _UNAME_ALLOWED_LONG_FLAGS:
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden uname flag {a!r}", rpc_code=-32003)
            elif a.startswith("-") and len(a) > 1:
                if any(ch not in _UNAME_ALLOWED_SHORT_CHARS for ch in a[1:]):
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden uname flag {a!r}", rpc_code=-32003)
            else:
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden uname argument {a!r}", rpc_code=-32003)
        return

    if exe_base == "uptime":
        for a in args:
            if a not in _UPTIME_ALLOWED_FLAGS:
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden uptime argument {a!r}", rpc_code=-32003)
        return

    if exe_base == "df":
        end_opts = False
        for a in args:
            if not end_opts and a == "--":
                end_opts = True
                continue
            if not end_opts and a.startswith("-") and a != "-":
                if a.startswith("--"):
                    if a not in _DF_ALLOWED_LONG_FLAGS:
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden df flag {a!r}", rpc_code=-32003)
                else:
                    if len(a) < 2 or any(ch not in _DF_ALLOWED_SHORT_CHARS for ch in a[1:]):
                        raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden df flag {a!r}", rpc_code=-32003)
            else:
                _check_path_against_locks(a, bus_dir=bus_dir, repo_root=repo_root, home_dir=home_dir, base_dir=eff_workdir, write=False)
        return

    if exe_base == "free":
        for a in args:
            if a.startswith("--"):
                if a not in _FREE_ALLOWED_LONG_FLAGS:
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden free flag {a!r}", rpc_code=-32003)
            elif a.startswith("-") and len(a) > 1:
                if any(ch not in _FREE_ALLOWED_SHORT_CHARS for ch in a[1:]):
                    raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden free flag {a!r}", rpc_code=-32003)
            else:
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden free argument {a!r}", rpc_code=-32003)
        return

    if exe_base == "which":
        for a in args:
            if a == "-a":
                continue
            if a.startswith("-") or not _BARE_CMD_RE.fullmatch(a):
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden which argument {a!r}", rpc_code=-32003)
        return

    if exe_base == "printenv":
        for a in args:
            if a in ("-0", "--null"):
                continue
            if a.startswith("-") or not _ENV_VAR_NAME_RE.fullmatch(a):
                raise HubError(403, "HOST_LOCK1_DENIED", f"HOST_LOCK1_DENIED: forbidden printenv argument {a!r}", rpc_code=-32003)
            if _SENSITIVE_ENV_RE.search(a) or a.upper() in _SENSITIVE_ENV_EXACT:
                raise HubError(
                    403,
                    "HOST_LOCK2_DENIED",
                    f"HOST_LOCK2_DENIED: reading sensitive env variable {a!r} is forbidden",
                    rpc_code=-32003,
                )
        return

    if exe_base == "env":
        if args:
            raise HubError(
                403,
                "HOST_LOCK1_DENIED",
                "HOST_LOCK1_DENIED: `env` with arguments is forbidden (only 0-arg sanitized env inspection allowed)",
                rpc_code=-32003,
            )
        return

    if exe_base == "echo":
        return

    # Fail-closed catch-all: no allowlisted binary may bypass per-command argument validation.
    raise HubError(
        403,
        "HOST_LOCK1_DENIED",
        f"HOST_LOCK1_DENIED: no argument allowlist policy defined for {exe_base!r}",
        rpc_code=-32003,
    )


def _validate_host_exec_argv(
    *,
    argv: Optional[Sequence[Any]] = None,
    command: Optional[str] = None,
    workdir: Optional[str] = None,
    bus_dir: str,
    repo_root: str,
    home_dir: Optional[str] = None,
) -> Tuple[List[str], str]:
    """Validate `host_exec` argv/command against shell injection, interpreters, and Locks 1/2/3."""
    if argv is not None:
        if not isinstance(argv, (list, tuple)) or not argv:
            raise HubError(400, "INVALID_EXEC_ARGV", "`argv` must be a non-empty list of strings", rpc_code=-32602)
        tokens = [str(x) for x in argv]
    elif command is not None and str(command).strip():
        raw_cmd = str(command)
        for meta in _SHELL_META_SUBSTRINGS:
            if meta in raw_cmd:
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: shell metacharacter {meta!r} is forbidden in host_exec",
                    rpc_code=-32003,
                )
        if _ENV_EXPAND_RE.search(raw_cmd):
            raise HubError(
                403,
                "HOST_LOCK1_DENIED",
                "HOST_LOCK1_DENIED: shell variable expansion is forbidden in host_exec",
                rpc_code=-32003,
            )
        try:
            tokens = shlex.split(raw_cmd, posix=True)
        except ValueError as exc:
            raise HubError(400, "INVALID_EXEC_COMMAND", f"Command parse error: {exc}", rpc_code=-32602) from exc
        if not tokens:
            raise HubError(400, "INVALID_EXEC_COMMAND", "Command cannot be empty", rpc_code=-32602)
    else:
        raise HubError(400, "INVALID_EXEC_ARGS", "Provide `argv` or `command`", rpc_code=-32602)

    for tok in tokens:
        for meta in _SHELL_META_SUBSTRINGS:
            if meta in tok:
                raise HubError(
                    403,
                    "HOST_LOCK1_DENIED",
                    f"HOST_LOCK1_DENIED: shell metacharacter {meta!r} is forbidden in host_exec token",
                    rpc_code=-32003,
                )
        if _ENV_EXPAND_RE.search(tok):
            raise HubError(
                403,
                "HOST_LOCK1_DENIED",
                "HOST_LOCK1_DENIED: shell variable expansion is forbidden in host_exec token",
                rpc_code=-32003,
            )

    exe_raw = tokens[0].strip()
    if not exe_raw:
        raise HubError(400, "INVALID_EXEC_ARGS", "Executable cannot be empty", rpc_code=-32602)
    exe_base = os.path.basename(exe_raw).lower()

    if exe_base in _FORBIDDEN_LOCK2_BINS:
        raise HubError(
            403,
            "HOST_LOCK2_DENIED",
            f"HOST_LOCK2_DENIED: Vault/OpenBao CLI {exe_base!r} is strictly forbidden",
            rpc_code=-32003,
        )
    if exe_base in _FORBIDDEN_LOCK3_BINS:
        raise HubError(
            403,
            "HOST_LOCK3_DENIED",
            f"HOST_LOCK3_DENIED: direct {exe_base!r} execution is forbidden; use host_services",
            rpc_code=-32003,
        )
    if exe_base in _FORBIDDEN_LOCK1_BINS or exe_base.startswith("python3.") or exe_base.startswith("python2."):
        raise HubError(
            403,
            "HOST_LOCK1_DENIED",
            f"HOST_LOCK1_DENIED: shell/interpreter/mutating command {exe_base!r} is forbidden",
            rpc_code=-32003,
        )
    if exe_base not in _ALLOWED_EXEC_BINS:
        raise HubError(
            403,
            "HOST_LOCK1_DENIED",
            f"HOST_LOCK1_DENIED: executable {exe_base!r} is not in the host_exec allowlist",
            rpc_code=-32003,
        )

    # Check resolved binary realpath to defeat symlinks like `/tmp/ls -> /bin/sh` or `-> bao`
    resolved_exe = exe_raw if ("/" in exe_raw) else (shutil.which(exe_raw) or "")
    if resolved_exe:
        real_exe_base = os.path.basename(os.path.realpath(resolved_exe)).lower()
        if real_exe_base in _FORBIDDEN_LOCK2_BINS:
            raise HubError(403, "HOST_LOCK2_DENIED", "HOST_LOCK2_DENIED: symlinked vault binary forbidden", rpc_code=-32003)
        if real_exe_base in _FORBIDDEN_LOCK3_BINS:
            raise HubError(403, "HOST_LOCK3_DENIED", "HOST_LOCK3_DENIED: symlinked service binary forbidden", rpc_code=-32003)
        if real_exe_base in _FORBIDDEN_LOCK1_BINS or real_exe_base.startswith("python3."):
            raise HubError(403, "HOST_LOCK1_DENIED", "HOST_LOCK1_DENIED: symlinked forbidden interpreter", rpc_code=-32003)
        if "/" in exe_raw:
            _check_path_against_locks(exe_raw, bus_dir=bus_dir, repo_root=repo_root, home_dir=home_dir)

    # Special command hardening: `env` only permitted with 0 args
    if exe_base == "env" and len(tokens) > 1:
        for arg in tokens[1:]:
            ab = os.path.basename(arg).lower()
            if ab in _FORBIDDEN_LOCK2_BINS:
                raise HubError(
                    403,
                    "HOST_LOCK2_DENIED",
                    "HOST_LOCK2_DENIED: invoking vault/bao via env is forbidden",
                    rpc_code=-32003,
                )
        raise HubError(
            403,
            "HOST_LOCK1_DENIED",
            "HOST_LOCK1_DENIED: `env` with arguments is forbidden (only 0-arg sanitized env inspection allowed)",
            rpc_code=-32003,
        )

    if exe_base == "printenv":
        for arg in tokens[1:]:
            if not arg.startswith("-") and (_SENSITIVE_ENV_RE.search(arg) or arg.upper() in _SENSITIVE_ENV_EXACT):
                raise HubError(
                    403,
                    "HOST_LOCK2_DENIED",
                    f"HOST_LOCK2_DENIED: reading sensitive env variable {arg!r} is forbidden",
                    rpc_code=-32003,
                )

    # Validate workdir against Locks 1/2/3 BEFORE command-specific path resolution
    eff_workdir = os.path.abspath(os.path.expanduser(workdir)) if workdir else os.path.abspath(repo_root)
    _check_path_against_locks(
        eff_workdir,
        bus_dir=bus_dir,
        repo_root=repo_root,
        home_dir=home_dir,
        write=(exe_base in ("touch", "mkdir")),
    )
    if not os.path.isdir(eff_workdir):
        raise HubError(400, "INVALID_WORKDIR", f"Workdir does not exist: {eff_workdir}", rpc_code=-32602)

    # Strict per-command flag whitelists & path validation (M2-B1, M2-B2, M2-B4)
    _validate_command_specific_args(
        exe_base,
        tokens[1:],
        eff_workdir=eff_workdir,
        bus_dir=bus_dir,
        repo_root=repo_root,
        home_dir=home_dir,
    )

    # Defense-in-depth: validate every non-flag argument (and flag=value payload) against Locks 1/2/3
    is_write_cmd = exe_base in ("touch", "mkdir")
    for arg in tokens[1:]:
        if not arg:
            continue
        candidates_to_check: List[str] = []
        if "=" in arg:
            _k, v = arg.split("=", 1)
            if v:
                candidates_to_check.append(v)
        if not arg.startswith("-") or "/" in arg or "\\" in arg:
            candidates_to_check.append(arg)
        for cand_arg in candidates_to_check:
            _check_path_against_locks(
                cand_arg,
                bus_dir=bus_dir,
                repo_root=repo_root,
                home_dir=home_dir,
                base_dir=eff_workdir,
                write=is_write_cmd,
            )

    return tokens, eff_workdir


class HostServerBridge:
    """Owner-authorized Host Server Bridge shared by MCP `tools/call` and REST `/hub/v1/host/*`."""

    def __init__(
        self,
        *,
        bus_dir: str,
        repo_root: str,
        home_dir: Optional[str] = None,
        reload_sentinel_dir: str = "/tmp",
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.bus_dir = federation_registry._resolve_bus_dir(bus_dir)
        self.repo_root = os.path.abspath(repo_root)
        self.home_dir = os.path.abspath(home_dir) if home_dir else os.path.expanduser("~")
        self.reload_sentinel_dir = os.path.abspath(reload_sentinel_dir)
        self.audit = audit_logger or AuditLogger(self.bus_dir)

    def _require_eligible(self, auth: Dict[str, Any], action: str, raw_token: str = "") -> Dict[str, Any]:
        ok, reason = check_host_server_eligibility(auth)
        if not ok:
            self.audit.record(
                "host_bridge",
                actor_id=str(auth.get("actor_id") or ""),
                action=action,
                outcome="denied",
                http_status=403,
                reason="HOST_INVOKE_FORBIDDEN",
                detail={"why": reason},
                extra_secrets=([raw_token] if raw_token else ()),
            )
            raise HubError(
                403,
                "HOST_INVOKE_FORBIDDEN",
                f"HOST_INVOKE_FORBIDDEN: {reason}",
                rpc_code=-32003,
            )
        return auth["agent"]

    def host_files(
        self,
        auth: Dict[str, Any],
        args: Dict[str, Any],
        *,
        raw_token: str = "",
    ) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        extra_sec = [raw_token] if raw_token else []
        self._require_eligible(auth, "host_files", raw_token=raw_token)
        action = str(args.get("action") or "").strip().lower()
        if action not in ("read", "list", "stat", "write"):
            raise HubError(400, "INVALID_ACTION", f"Invalid host_files action: {action!r}", rpc_code=-32602)
        raw_path = str(args.get("path") or "").strip()
        if not raw_path:
            raise HubError(400, "INVALID_PATH", "`path` is required", rpc_code=-32602)
        try:
            _abs_p, real_p = _check_path_against_locks(
                raw_path,
                bus_dir=self.bus_dir,
                repo_root=self.repo_root,
                home_dir=self.home_dir,
                base_dir=self.repo_root,
                write=(action == "write"),
            )
        except HubError as exc:
            self.audit.record(
                "host_bridge",
                actor_id=actor,
                action=f"host_files.{action}",
                outcome="denied",
                http_status=exc.http_status,
                reason=exc.error_code,
                detail={"path": raw_path},
                extra_secrets=extra_sec,
            )
            raise

        if action == "stat":
            if not os.path.exists(real_p):
                res = {"ok": True, "action": "stat", "path": real_p, "exists": False}
            else:
                st = os.stat(real_p)
                res = {
                    "ok": True,
                    "action": "stat",
                    "path": real_p,
                    "exists": True,
                    "is_file": os.path.isfile(real_p),
                    "is_dir": os.path.isdir(real_p),
                    "size": st.st_size,
                    "mode": oct(st.st_mode & 0o777),
                    "mtime": st.st_mtime,
                }
        elif action == "list":
            if not os.path.isdir(real_p):
                raise HubError(404, "NOT_FOUND", f"Directory not found: {real_p}", rpc_code=-32004)
            entries: List[Dict[str, Any]] = []
            for name in sorted(os.listdir(real_p))[:500]:
                child = os.path.join(real_p, name)
                entries.append(
                    {
                        "name": name,
                        "is_dir": os.path.isdir(child),
                        "is_file": os.path.isfile(child),
                    }
                )
            res = {"ok": True, "action": "list", "path": real_p, "entries": entries}
        elif action == "read":
            if not os.path.isfile(real_p):
                raise HubError(404, "NOT_FOUND", f"File not found: {real_p}", rpc_code=-32004)
            max_bytes = max(1, min(MAX_HOST_FILE_READ_BYTES, int(args.get("max_bytes") or 65536)))
            with open(real_p, "rb") as fh:
                raw_bytes = fh.read(max_bytes + 1)
            truncated = len(raw_bytes) > max_bytes
            text = federation_registry.redact_secrets(
                raw_bytes[:max_bytes].decode("utf-8", errors="replace"),
                extra_secrets=extra_sec,
            )
            res = {
                "ok": True,
                "action": "read",
                "path": real_p,
                "content": text,
                "truncated": truncated,
            }
        else:  # write
            if "content" not in args or not isinstance(args.get("content"), str):
                raise HubError(400, "INVALID_CONTENT", "`content` string is required for write", rpc_code=-32602)
            content = args["content"]
            parent = os.path.dirname(real_p)
            _check_path_against_locks(
                parent,
                bus_dir=self.bus_dir,
                repo_root=self.repo_root,
                home_dir=self.home_dir,
                write=True,
            )
            os.makedirs(parent, exist_ok=True)
            tmp = f"{real_p}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
            os.replace(tmp, real_p)
            res = {"ok": True, "action": "write", "path": real_p, "bytes_written": len(content.encode("utf-8"))}

        self.audit.record(
            "host_bridge",
            actor_id=actor,
            action=f"host_files.{action}",
            outcome="allowed",
            http_status=200,
            detail={"path": real_p},
            extra_secrets=extra_sec,
        )
        return res

    def host_exec(
        self,
        auth: Dict[str, Any],
        args: Dict[str, Any],
        *,
        raw_token: str = "",
    ) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        extra_sec = [raw_token] if raw_token else []
        self._require_eligible(auth, "host_exec", raw_token=raw_token)
        try:
            tokens, eff_workdir = _validate_host_exec_argv(
                argv=args.get("argv"),
                command=args.get("command"),
                workdir=args.get("workdir"),
                bus_dir=self.bus_dir,
                repo_root=self.repo_root,
                home_dir=self.home_dir,
            )
        except HubError as exc:
            self.audit.record(
                "host_bridge",
                actor_id=actor,
                action="host_exec",
                outcome="denied",
                http_status=exc.http_status,
                reason=exc.error_code,
                detail={"command": args.get("command") or args.get("argv")},
                extra_secrets=extra_sec,
            )
            raise

        timeout_sec = max(
            1.0,
            min(
                MAX_HOST_EXEC_TIMEOUT_SEC,
                float(args.get("timeout_sec") or DEFAULT_HOST_EXEC_TIMEOUT_SEC),
            ),
        )
        child_env = build_sanitized_exec_env()
        proc: Optional[subprocess.Popen] = None
        proc_st: Optional[str] = None
        timed_out = False
        try:
            proc = subprocess.Popen(
                tokens,
                cwd=eff_workdir,
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
            )
            proc_st = agent_driver._read_proc_starttime(proc.pid) if proc.pid is not None else None
            try:
                out_b, err_b = proc.communicate(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                timed_out = True
                if proc.pid is not None:
                    agent_driver._kill_process_tree(
                        proc.pid,
                        term_timeout=1.0,
                        proc=proc,
                        expected_root_starttime=proc_st,
                    )
                out_b, err_b = proc.communicate(timeout=2.0)
        except FileNotFoundError as exc:
            raise HubError(400, "EXEC_NOT_FOUND", f"Command not found: {tokens[0]!r}", rpc_code=-32602) from exc

        stdout_txt = federation_registry.redact_secrets(
            (out_b or b"")[:MAX_HOST_EXEC_OUTPUT_BYTES].decode("utf-8", errors="replace"),
            extra_secrets=extra_sec,
        )
        stderr_txt = federation_registry.redact_secrets(
            (err_b or b"")[:MAX_HOST_EXEC_OUTPUT_BYTES].decode("utf-8", errors="replace"),
            extra_secrets=extra_sec,
        )
        rc = proc.returncode if proc is not None else -1
        self.audit.record(
            "host_bridge",
            actor_id=actor,
            action="host_exec",
            outcome="allowed",
            http_status=200,
            detail={"argv": tokens, "workdir": eff_workdir, "exit_code": rc, "timed_out": timed_out},
            extra_secrets=extra_sec,
        )
        return {
            "ok": (rc == 0 and not timed_out),
            "exit_code": rc,
            "timed_out": timed_out,
            "stdout": stdout_txt,
            "stderr": stderr_txt,
            "workdir": eff_workdir,
        }

    def host_services(
        self,
        auth: Dict[str, Any],
        args: Dict[str, Any],
        *,
        raw_token: str = "",
    ) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        extra_sec = [raw_token] if raw_token else []
        self._require_eligible(auth, "host_services", raw_token=raw_token)
        action = str(args.get("action") or "").strip().lower()
        service = str(args.get("service") or "").strip()

        if action not in ("status", "list", "logs", "reload"):
            self.audit.record(
                "host_bridge",
                actor_id=actor,
                action=f"host_services.{action}",
                outcome="denied",
                http_status=403,
                reason="HOST_LOCK3_DENIED",
                detail={"service": service},
                extra_secrets=extra_sec,
            )
            raise HubError(
                403,
                "HOST_LOCK3_DENIED",
                f"HOST_LOCK3_DENIED: mutating service action {action!r} is strictly forbidden (only status/list/logs/reload allowed)",
                rpc_code=-32003,
            )

        if action != "list":
            if (
                not service
                or ".." in service
                or "/" in service
                or "\\" in service
                or any(ch in service for ch in _SHELL_META_SUBSTRINGS)
                or not _UNIT_NAME_RE.fullmatch(service)
            ):
                self.audit.record(
                    "host_bridge",
                    actor_id=actor,
                    action=f"host_services.{action}",
                    outcome="denied",
                    http_status=400,
                    reason="INVALID_SERVICE_UNIT",
                    detail={"service": service},
                    extra_secrets=extra_sec,
                )
                raise HubError(
                    400,
                    "INVALID_SERVICE_UNIT",
                    f"Invalid or non-whitelisted service unit name: {service!r}",
                    rpc_code=-32602,
                )

        if action == "reload":
            sentinel_name = _RELOAD_SENTINEL_MAP.get(service)
            if not sentinel_name:
                self.audit.record(
                    "host_bridge",
                    actor_id=actor,
                    action="host_services.reload",
                    outcome="denied",
                    http_status=403,
                    reason="HOST_LOCK3_DENIED",
                    detail={"service": service},
                    extra_secrets=extra_sec,
                )
                raise HubError(
                    403,
                    "HOST_LOCK3_DENIED",
                    f"HOST_LOCK3_DENIED: reload is only permitted via safe bridge reload sentinels, not {service!r}",
                    rpc_code=-32003,
                )
            os.makedirs(self.reload_sentinel_dir, exist_ok=True)
            sentinel_path = os.path.join(self.reload_sentinel_dir, sentinel_name)
            with open(sentinel_path, "a", encoding="utf-8"):
                os.utime(sentinel_path, None)
            self.audit.record(
                "host_bridge",
                actor_id=actor,
                action="host_services.reload",
                outcome="allowed",
                http_status=200,
                detail={"service": service, "sentinel": sentinel_path},
                extra_secrets=extra_sec,
            )
            return {
                "ok": True,
                "action": "reload",
                "service": service,
                "method": "sentinel",
                "sentinel": sentinel_path,
            }

        child_env = build_sanitized_exec_env()
        if action == "list":
            cmd = ["systemctl", "list-units", "--type=service", "--no-pager", "--plain", "agy-*", "hermes-*"]
        elif action == "status":
            unit = service if service.endswith(".service") else f"{service}.service"
            cmd = ["systemctl", "status", "--no-pager", "-n", "10", unit]
        else:  # logs
            unit = service if service.endswith(".service") else f"{service}.service"
            lines = max(1, min(200, int(args.get("lines") or 50)))
            cmd = ["journalctl", "-u", unit, "-n", str(lines), "--no-pager"]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10.0,
            env=child_env,
            shell=False,
            check=False,
        )
        stdout_txt = federation_registry.redact_secrets(
            (proc.stdout or "")[:MAX_HOST_EXEC_OUTPUT_BYTES],
            extra_secrets=extra_sec,
        )
        stderr_txt = federation_registry.redact_secrets(
            (proc.stderr or "")[:MAX_HOST_EXEC_OUTPUT_BYTES],
            extra_secrets=extra_sec,
        )
        self.audit.record(
            "host_bridge",
            actor_id=actor,
            action=f"host_services.{action}",
            outcome="allowed",
            http_status=200,
            detail={"service": service, "exit_code": proc.returncode},
            extra_secrets=extra_sec,
        )
        return {
            "ok": True,
            "action": action,
            "service": service,
            "exit_code": proc.returncode,
            "stdout": stdout_txt,
            "stderr": stderr_txt,
        }

    def host_invoke_agent(
        self,
        auth: Dict[str, Any],
        args: Dict[str, Any],
        *,
        raw_token: str = "",
    ) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        extra_sec = [raw_token] if raw_token else []
        agent = self._require_eligible(auth, "host_invoke_agent", raw_token=raw_token)

        # Anti-spoofing: reject forged sender fields
        for spoof_key in ("from_bot", "from_agent_id", "sender"):
            raw_spoof = str(args.get(spoof_key) or "").strip().lstrip("@").lower()
            if raw_spoof and raw_spoof != actor:
                self.audit.record(
                    "host_bridge",
                    actor_id=actor,
                    action="host_invoke_agent",
                    outcome="denied",
                    http_status=403,
                    reason="SENDER_SPOOF_DENIED",
                    detail={"spoofed_field": spoof_key, "spoofed_value": raw_spoof},
                    extra_secrets=extra_sec,
                )
                raise HubError(
                    403,
                    "SENDER_SPOOF_DENIED",
                    f"SENDER_SPOOF_DENIED: caller {actor!r} cannot spoof {spoof_key}={raw_spoof!r}",
                    rpc_code=-32003,
                )

        target_id = str(args.get("agent_id") or args.get("bot") or "").strip()
        prompt = str(args.get("prompt") or "").strip()
        if not target_id or not prompt:
            raise HubError(400, "INVALID_ARGS", "`agent_id` and `prompt` are required", rpc_code=-32602)

        caller_trust = bot_bus._normalize_trust_level(agent.get("trust_level"), default="remote_trusted")
        req_trust = str(args.get("trust_level") or "").strip()
        eff_trust = bot_bus._min_trust_level(caller_trust, req_trust) if req_trust else caller_trust
        # Guarantee monotonic trust ceiling <= caller_trust
        eff_origin = (
            "local_bus"
            if agent.get("kind") in ("agy_local", "hermes_local")
            else f"remote_{agent.get('kind') or 'hub'}"
        )
        team_id = str(args.get("team_id") or "").strip()
        mode = str(args.get("mode") or "").strip()
        wait = bool(args.get("wait", False))
        timeout_sec = max(1.0, min(600.0, float(args.get("timeout_sec") or 60.0)))

        spec: Dict[str, Any] = {
            "bot": target_id,
            "prompt": prompt,
            "trust_level": eff_trust,
            "agent_origin": eff_origin,
        }
        if mode:
            spec["mode"] = mode
        if args.get("label"):
            spec["label"] = str(args["label"])[:120]
        if args.get("workdir"):
            _check_path_against_locks(
                str(args["workdir"]),
                bus_dir=self.bus_dir,
                repo_root=self.repo_root,
                home_dir=self.home_dir,
            )
            spec["workdir"] = str(args["workdir"])

        try:
            with _with_bot_bus_dir(self.bus_dir):
                created = bot_bus.dispatch_assignments(
                    actor,
                    [spec],
                    team_id=team_id,
                    agent_origin=eff_origin,
                    parent_agent_origin=eff_origin,
                    parent_trust_level=caller_trust,
                    trust_level=eff_trust,
                    wake_on_async=not wait,
                    auth_token=raw_token,
                )
        except PermissionError as exc:
            self.audit.record(
                "host_bridge",
                actor_id=actor,
                action="host_invoke_agent",
                outcome="denied",
                http_status=403,
                reason="PRIVILEGE_ESCALATION_DENIED",
                detail={"target": target_id, "team_id": team_id},
                extra_secrets=extra_sec,
            )
            raise HubError(403, "PRIVILEGE_ESCALATION_DENIED", str(exc), rpc_code=-32003) from exc
        except ValueError as exc:
            raise HubError(400, "INVALID_DISPATCH", str(exc), rpc_code=-32602) from exc

        jobs = created["jobs"]
        self.audit.record(
            "host_bridge",
            actor_id=actor,
            action="host_invoke_agent",
            outcome="allowed",
            http_status=200,
            detail={
                "target": target_id,
                "team_id": jobs[0].get("team_id") if jobs else team_id,
                "job_id": jobs[0].get("job_id") if jobs else "",
                "trust_level": jobs[0].get("trust_level") if jobs else eff_trust,
            },
            extra_secrets=extra_sec,
        )
        if not wait:
            return {
                "ok": True,
                "mode": "async",
                "group_id": created["group_id"],
                "jobs": [bot_bus.summarize_job_brief(j) for j in jobs],
                "dispatched_jobs": jobs,
            }

        with _with_bot_bus_dir(self.bus_dir):
            settled, all_done = bot_bus.wait_for_jobs([j["job_id"] for j in jobs], timeout_sec=timeout_sec)
        return {
            "ok": all_done,
            "mode": "sync",
            "group_id": created["group_id"],
            "all_settled": all_done,
            "results": [bot_bus.summarize_job_brief(j) for j in settled],
        }


# ---------------------------------------------------------------- Leader Wakeup Store (Non-agy batch_done)
def _leader_events_dir(bus_dir: str, agent_id: str) -> str:
    aid = federation_registry.validate_agent_id(agent_id)
    return os.path.join(federation_registry.federation_dir(bus_dir), "leader_events", aid)


def store_leader_event(bus_dir: str, agent_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
    """Durably persist a non-`agy` leader event (e.g. `batch_done`) with `0700`/`0600` permissions."""
    ed = _leader_events_dir(bus_dir, agent_id)
    federation_registry._ensure_secure_dir(federation_registry.federation_dir(bus_dir))
    federation_registry._ensure_secure_dir(os.path.dirname(ed))
    federation_registry._ensure_secure_dir(ed)
    eid = str(event.get("event_id") or f"ev-{uuid.uuid4().hex[:12]}")
    rec = copy.deepcopy(event)
    rec["event_id"] = eid
    rec.setdefault("created_at", time.time())
    fp = os.path.join(ed, f"{time.time_ns():020d}_{eid}.json")
    federation_registry._atomic_write_json(fp, rec)
    return rec


def list_leader_events(bus_dir: str, agent_id: str) -> List[Dict[str, Any]]:
    ed = _leader_events_dir(bus_dir, agent_id)
    if not os.path.isdir(ed):
        return []
    out: List[Dict[str, Any]] = []
    try:
        names = sorted(fn for fn in os.listdir(ed) if fn.endswith(".json") and not fn.endswith(".tmp"))
    except OSError:
        return []
    for fn in names:
        data = federation_registry._read_json(os.path.join(ed, fn), None)
        if isinstance(data, dict):
            out.append(data)
    return out


# ---------------------------------------------------------------- Outbound External Worker Dispatcher (M2-C6)
class ExternalWorkerDispatcher:
    """Outbound worker loop driving non-`agy_local` agents & non-`agy` leader `batch_done` wakeups."""

    def __init__(
        self,
        bus_dir: Optional[str] = None,
        *,
        poll_interval: float = 0.2,
        driver_registry: Optional[agent_driver.DriverRegistry] = None,
        driver_kwargs_factory: Optional[Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]] = None,
        batch_done_callback: Optional[Callable[[str, Dict[str, Any], Dict[str, Any]], None]] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.bus_dir = federation_registry._resolve_bus_dir(bus_dir)
        self.poll_interval = max(0.02, float(poll_interval or 0.2))
        self.driver_registry = driver_registry if driver_registry is not None else agent_driver.DriverRegistry(register_builtin=True)
        external_drivers.register_external_drivers(self.driver_registry)
        self.driver_kwargs_factory = driver_kwargs_factory
        self.batch_done_callback = batch_done_callback
        self.audit = audit_logger or AuditLogger(self.bus_dir)

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._active_jobs: Dict[str, threading.Thread] = {}
        self._bridged_pull_jobs: set[str] = set()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run_loop, name="agy-fed-dispatcher", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        th = self._thread
        if th is not None and th.is_alive() and th is not threading.current_thread():
            th.join(timeout=timeout)
        with self._lock:
            workers = list(self._active_jobs.values())
        for w in workers:
            if w.is_alive() and w is not threading.current_thread():
                w.join(timeout=min(timeout, 2.0))

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.poll_once()
            except Exception:
                pass
            self._stop_event.wait(self.poll_interval)

    def _is_eligible_outbound_worker(self, agent: Dict[str, Any]) -> bool:
        if not isinstance(agent, dict):
            return False
        if agent.get("kind") in ("agy_local", "mcp_inbound_only"):
            return False
        if agent.get("revoked") or not agent.get("enabled", True):
            return False
        caps = agent.get("capabilities") or {}
        if not bool(caps.get("can_receive", True)):
            return False
        return True

    def _pop_non_agy_leader_batch_done(self, agent: Dict[str, Any]) -> int:
        aid = str(agent.get("agent_id") or "")
        if not aid or agent.get("kind") == "agy_local":
            return 0
        if agent.get("revoked") or not agent.get("enabled", True):
            return 0
        bot_inbox = os.path.join(self.bus_dir, "inbox", aid)
        if not os.path.isdir(bot_inbox):
            return 0

        popped_pkts: List[Dict[str, Any]] = []
        with _with_bot_bus_dir(self.bus_dir):
            with bot_bus._bus_lock():
                try:
                    names = sorted(
                        (fn for fn in os.listdir(bot_inbox) if fn.endswith(".json") and not fn.endswith(".tmp")),
                        key=bot_bus._inbox_sort_key,
                    )
                except OSError:
                    return 0
                for fn in names:
                    fp = os.path.join(bot_inbox, fn)
                    pkt = bot_bus._read_json(fp, None)
                    if not isinstance(pkt, dict) or pkt.get("type") != "batch_done":
                        continue
                    try:
                        os.remove(fp)
                    except OSError:
                        pass
                    popped_pkts.append(pkt)

        delivered = 0
        for pkt in popped_pkts:
            job_ids = list(pkt.get("job_ids") or [])
            summaries: List[Dict[str, Any]] = []
            any_tainted = bool(pkt.get("tainted", False))
            with _with_bot_bus_dir(self.bus_dir):
                for jid in job_ids:
                    j = bot_bus.get_job(jid)
                    if isinstance(j, dict):
                        if j.get("tainted") or j.get("untrusted"):
                            any_tainted = True
                        summaries.append(bot_bus.summarize_job_brief(j))
                bot_bus.mark_batch_wakeup_acked(job_ids)
            enriched = {
                "type": "batch_done",
                "group_id": pkt.get("group_id") or "",
                "team_id": pkt.get("team_id") or "",
                "job_ids": job_ids,
                "jobs": summaries,
                "tainted": any_tainted,
                "agent_origin": pkt.get("agent_origin") or "local_bus",
                "trust_level": pkt.get("trust_level") or "remote_trusted",
                "created_at": float(pkt.get("created_at") or time.time()),
            }
            stored = store_leader_event(self.bus_dir, aid, enriched)
            if callable(self.batch_done_callback):
                try:
                    self.batch_done_callback(aid, stored, agent)
                except Exception:
                    pass
            self.audit.record(
                "batch_done_delivered",
                actor_id=aid,
                action="leader_wakeup",
                outcome="delivered",
                detail={"group_id": stored.get("group_id"), "job_ids": job_ids, "tainted": any_tainted},
            )
            delivered += 1
        return delivered

    def _sync_pull_cancellations(self, pull_q: federation_registry.PullWorkerQueue) -> int:
        cancelled_cnt = 0
        with _with_bot_bus_dir(self.bus_dir):
            all_jobs = bot_bus.list_jobs(limit=bot_bus.JOB_RETENTION_LIMIT)
        owner_ctx = federation_registry.OwnerAuth(
            actor_id="federation_dispatcher",
            is_owner=True,
            role="owner",
            trust_level="local_admin",
            agent_origin="local_owner",
        )
        for job in all_jobs:
            jid = str(job.get("job_id") or "")
            if not jid:
                continue
            if not (job.get("cancel_requested") or job.get("status") == "cancelled"):
                continue
            pjob = pull_q.get(jid)
            if not isinstance(pjob, dict):
                continue
            cancel_reason = str(job.get("cancel_reason") or "cancelled_by_coordinator")
            pull_is_cancelled = pjob.get("status") == "cancelled"
            if pjob.get("status") not in ("done", "error", "cancelled"):
                try:
                    res_p = pull_q.cancel(
                        jid,
                        reason=cancel_reason,
                        owner_auth=owner_ctx,
                        env={},
                    )
                    if isinstance(res_p, dict) and res_p.get("status") == "cancelled":
                        pull_is_cancelled = True
                        cancelled_cnt += 1
                except Exception:
                    pass
            # M2-B8: Atomically converge running/queued bot_bus job to cancelled & emit batch_done once
            if pull_is_cancelled and job.get("status") in ("queued", "running"):
                with _with_bot_bus_dir(self.bus_dir):
                    cur_bus = bot_bus.get_job(jid)
                    if isinstance(cur_bus, dict) and cur_bus.get("status") in ("queued", "running"):
                        bot_bus.finish_job(
                            jid,
                            status="cancelled",
                            error=cancel_reason,
                            error_code="CANCELLED_BY_COORDINATOR",
                        )
        return cancelled_cnt

    def poll_once(self) -> Dict[str, int]:
        """Execute one deterministic poll cycle across external agents and non-`agy` leaders."""
        stats = {"dispatched": 0, "bridged_pull": 0, "pull_cancelled": 0, "batch_done": 0}
        if not federation_registry.has_federation_state(self.bus_dir):
            return stats

        agents = federation_registry.list_agents(
            bus_dir=self.bus_dir,
            include_disabled=True,
            include_revoked=True,
        )
        eligible_by_id: Dict[str, Dict[str, Any]] = {}
        for ag in agents:
            aid = str(ag.get("agent_id") or "")
            if not aid:
                continue
            if ag.get("kind") != "agy_local":
                stats["batch_done"] += self._pop_non_agy_leader_batch_done(ag)
            if self._is_eligible_outbound_worker(ag):
                eligible_by_id[aid] = ag

        pull_q = federation_registry.PullWorkerQueue(self.bus_dir)
        stats["pull_cancelled"] += self._sync_pull_cancellations(pull_q)

        if not eligible_by_id:
            return stats

        with _with_bot_bus_dir(self.bus_dir):
            queued_jobs = bot_bus.list_jobs(limit=bot_bus.JOB_RETENTION_LIMIT, status="queued")

        # Clean finished worker threads
        with self._lock:
            done_ids = [jid for jid, th in self._active_jobs.items() if not th.is_alive()]
            for jid in done_ids:
                self._active_jobs.pop(jid, None)

        for job in reversed(queued_jobs):  # FIFO oldest first
            jid = str(job.get("job_id") or "")
            target_id = str(job.get("target_bot") or "")
            if not jid or target_id not in eligible_by_id:
                continue
            agent = eligible_by_id[target_id]
            transport = str(agent.get("transport") or "").strip().lower()
            driver_name = str(agent.get("driver") or "").strip().lower()

            if transport == "pull_worker" or driver_name == "pull_worker":
                if pull_q.get(jid) is not None:
                    continue
                if job.get("cancel_requested"):
                    continue
                owner_ctx = federation_registry.OwnerAuth(
                    actor_id="federation_dispatcher",
                    is_owner=True,
                    role="owner",
                    trust_level="local_admin",
                    agent_origin="local_owner",
                )
                try:
                    pull_q.enqueue(
                        target_id,
                        str(job.get("prompt") or ""),
                        job_id=jid,
                        team_id=str(job.get("team_id") or ""),
                        from_agent_id=str(job.get("from_bot") or ""),
                        metadata={
                            "bridged_from_bot_bus": True,
                            "group_id": str(job.get("group_id") or ""),
                            "trust_level": str(job.get("trust_level") or "remote_trusted"),
                            "tainted": bool(job.get("tainted") or job.get("untrusted")),
                        },
                        owner_auth=owner_ctx,
                        env={},
                    )
                    self._bridged_pull_jobs.add(jid)
                    stats["bridged_pull"] += 1
                except Exception:
                    pass
                continue

            with self._lock:
                if jid in self._active_jobs:
                    continue
            with _with_bot_bus_dir(self.bus_dir):
                claimed = bot_bus.claim_job(jid, target_id, os.getpid())
            if claimed is None:
                continue
            th = threading.Thread(
                target=self._execute_external_job,
                args=(claimed, copy.deepcopy(agent)),
                name=f"fed-job-{jid}",
                daemon=True,
            )
            with self._lock:
                self._active_jobs[jid] = th
            th.start()
            stats["dispatched"] += 1

        return stats

    def _execute_external_job(self, job: Dict[str, Any], agent: Dict[str, Any]) -> None:
        jid = str(job.get("job_id") or "")
        agent_id = str(agent.get("agent_id") or "")
        driver_name = str(agent.get("driver") or agent.get("kind") or "").strip().lower()
        sess: Optional[agent_driver.AgentSession] = None
        cancelled = False
        cancel_reason = ""
        result_status = "ERROR"
        result_text = ""
        result_error = ""
        worker_cid = ""
        usage: Dict[str, Any] = {}
        collected_chunks: List[str] = []

        try:
            # Strict monotonic trust & security clamping (M2-C6)
            job_trust = agent_driver.normalize_trust_level(job.get("trust_level"), default="remote_untrusted")
            ag_trust = agent_driver.normalize_trust_level(agent.get("trust_level"), default="remote_trusted")
            eff_trust = agent_driver.min_trust_level(job_trust, ag_trust)
            eff_readonly = bool(job.get("readonly")) or (eff_trust == "readonly_guest")
            eff_untrusted = (
                bool(job.get("untrusted"))
                or bool(job.get("tainted"))
                or eff_readonly
                or (agent_driver.TRUST_ORDER[eff_trust] <= agent_driver.TRUST_ORDER["remote_untrusted"])
            )
            raw_mode = str(job.get("mode") or "").strip().lower()
            max_mode = str(job.get("max_runtime_mode") or "").strip().lower()
            if eff_readonly or eff_untrusted or max_mode == "safe" or raw_mode == "safe":
                eff_mode = "safe"
            else:
                eff_mode = raw_mode or "safe"

            drv = self.driver_registry.get_driver(driver_name)
            spawn_kw: Dict[str, Any] = {
                "workdir": str(job.get("workdir") or "").strip() or os.getcwd(),
                "scope_key": f"fed:{agent_id}:{jid}",
                "readonly": eff_readonly,
                "untrusted": eff_untrusted,
                "trust_level": eff_trust,
                "agent_origin": str(job.get("agent_origin") or "local_bus"),
            }
            if driver_name == "hermes_local":
                spawn_kw["profile"] = str(agent.get("profile") or "default")
                spawn_kw["team_id"] = str(job.get("team_id") or "")
                spawn_kw["allow_yolo"] = False
                max_rt = float(job.get("max_runtime_sec") or 0.0)
                if max_rt > 0:
                    spawn_kw["timeout_sec"] = max_rt
            elif driver_name == "hermes_remote":
                spawn_kw["endpoint_url"] = str(agent.get("endpoint_url") or "")
                spawn_kw["profile"] = str(agent.get("profile") or "")
                spawn_kw["secret_ref"] = str(agent.get("secret_ref") or "")
                spawn_kw["agent_record"] = agent
            else:
                spawn_kw["endpoint_url"] = str(agent.get("endpoint_url") or "")
                spawn_kw["transport"] = str(agent.get("transport") or "http_push")
                spawn_kw["agent_id"] = agent_id
                spawn_kw["bus_dir"] = self.bus_dir
                spawn_kw["team_id"] = str(job.get("team_id") or "")
                spawn_kw["from_agent_id"] = str(job.get("from_bot") or "")
                spawn_kw["secret_ref"] = str(agent.get("secret_ref") or "")
                spawn_kw["agent_record"] = agent

            if callable(self.driver_kwargs_factory):
                extra_kw = self.driver_kwargs_factory(agent, job)
                if isinstance(extra_kw, dict):
                    # Never allow factory override to turn on allow_yolo when restricted
                    if eff_readonly or eff_untrusted or eff_mode == "safe":
                        extra_kw = dict(extra_kw)
                        extra_kw.pop("allow_yolo", None)
                    spawn_kw.update(extra_kw)

            sess = drv.spawn_session(
                str(job.get("resume_cid") or "") or None,
                eff_mode,
                str(job.get("model") or "") or None,
                str(job.get("effort") or "") or None,
                **spawn_kw,
            )
            sess.send_user_prompt(str(job.get("prompt") or ""))

            while True:
                with _with_bot_bus_dir(self.bus_dir):
                    if bot_bus.is_job_cancelled(jid):
                        cancelled = True
                        cur_j = bot_bus.get_job(jid) or {}
                        cancel_reason = str(cur_j.get("cancel_reason") or "cancelled_by_coordinator")
                        sess.cancel(reason=cancel_reason)
                        break
                if self._stop_event.is_set():
                    cancelled = True
                    cancel_reason = "dispatcher_stopped"
                    sess.cancel(reason=cancel_reason)
                    break
                ev = sess.next_event(timeout=0.1)
                if ev is None:
                    continue
                ev_type = ev.get("event")
                if ev_type == "init":
                    cid = str(ev.get("conversation_id") or "")
                    if cid:
                        worker_cid = cid
                elif ev_type == "step_update":
                    su = ev.get("step_update") or {}
                    if su.get("step_type") == "agent_response" and su.get("text_delta"):
                        collected_chunks.append(str(su["text_delta"]))
                elif ev_type == "result":
                    res_obj = ev.get("result") or {}
                    result_status = str(res_obj.get("status") or "SUCCESS").upper()
                    result_text = str(res_obj.get("response") or "") or "".join(collected_chunks)
                    result_error = str(res_obj.get("error") or "")
                    if res_obj.get("conversation_id"):
                        worker_cid = str(res_obj["conversation_id"])
                    if isinstance(res_obj.get("usage"), dict):
                        usage = dict(res_obj["usage"])
                elif ev_type == "__eof__":
                    break
        except Exception as exc:
            result_status = "ERROR"
            result_error = federation_registry.redact_secrets(str(exc))
        finally:
            if sess is not None:
                try:
                    sess.close()
                except Exception:
                    pass

        # Exactly-once terminal finish_job convergence
        with _with_bot_bus_dir(self.bus_dir):
            cur = bot_bus.get_job(jid)
            if isinstance(cur, dict) and cur.get("status") not in bot_bus.TERMINAL_STATUSES:
                if cancelled or cur.get("cancel_requested"):
                    bot_bus.finish_job(
                        jid,
                        status="cancelled",
                        error=cancel_reason or str(cur.get("cancel_reason") or "cancelled_by_coordinator"),
                        error_code="CANCELLED_BY_COORDINATOR",
                        worker_cid=worker_cid,
                    )
                elif result_status == "SUCCESS":
                    bot_bus.finish_job(
                        jid,
                        status="done",
                        result_text=result_text or "".join(collected_chunks),
                        worker_cid=worker_cid,
                        usage=usage or None,
                    )
                else:
                    bot_bus.finish_job(
                        jid,
                        status="error",
                        result_text=result_text or "".join(collected_chunks),
                        error=result_error or "external agent execution failed",
                        error_code="AGENT_EXEC_ERROR",
                        worker_cid=worker_cid,
                        usage=usage or None,
                    )


# ---------------------------------------------------------------- Hub Core Business Logic (MCP + REST)
def _is_global_coord(auth: Dict[str, Any]) -> bool:
    return bool(auth.get("is_coordinator_peer") or auth.get("is_legacy_coordinator"))


def _can_orchestrate(auth: Dict[str, Any]) -> bool:
    agent = auth.get("agent")
    if isinstance(agent, dict):
        trust = str(agent.get("trust_level") or "").strip().lower()
        if trust in ("readonly_guest", "remote_untrusted"):
            return False
    if not auth.get("can_dispatch"):
        return False
    return bool(auth.get("is_coordinator_peer") or auth.get("led_teams"))


def _filter_teams_for_auth(teams: List[Dict[str, Any]], auth: Dict[str, Any]) -> List[Dict[str, Any]]:
    allowed_cap = set(auth.get("allowed_teams") or [])
    if _is_global_coord(auth):
        if not allowed_cap:
            return teams
        return [t for t in teams if isinstance(t, dict) and t.get("team_id") in allowed_cap]
    visible = set(auth.get("led_teams") or []) | set(auth.get("member_teams") or [])
    if allowed_cap:
        visible &= allowed_cap
    return [t for t in teams if isinstance(t, dict) and t.get("team_id") in visible]


def _filter_jobs_for_auth(jobs: List[Dict[str, Any]], auth: Dict[str, Any]) -> List[Dict[str, Any]]:
    me = str(auth.get("actor_id") or "")
    allowed_cap = set(auth.get("allowed_teams") or [])
    if _is_global_coord(auth):
        if not allowed_cap:
            return jobs
        return [j for j in jobs if isinstance(j, dict) and str(j.get("team_id") or "").strip() in allowed_cap]
    led = set(auth.get("led_teams") or [])
    out: List[Dict[str, Any]] = []
    for j in jobs:
        if not isinstance(j, dict):
            continue
        jt = str(j.get("team_id") or "").strip()
        if allowed_cap and jt not in allowed_cap:
            continue
        if (jt and jt in led) or j.get("from_bot") == me or j.get("target_bot") == me:
            out.append(j)
    return out


def _permitted_mcp_tools(auth: Dict[str, Any]) -> List[str]:
    if not auth.get("authorized") or not auth.get("token_verified"):
        return []
    agent = auth.get("agent")
    if not isinstance(agent, dict) or agent.get("revoked") or not agent.get("enabled", True):
        return []
    trust = str(agent.get("trust_level") or "").strip().lower()
    tools: List[str] = ["team_roster", "team_list"]
    if trust != "readonly_guest":
        tools.append("group_say")
    if _can_orchestrate(auth):
        tools.extend(["team_dispatch", "team_job", "team_broadcast"])
    host_ok, _ = check_host_server_eligibility(auth)
    if host_ok:
        tools.extend(["host_exec", "host_files", "host_services", "host_invoke_agent"])
    return tools


_ALL_MCP_TOOL_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "team_roster": {
        "name": "team_roster",
        "description": "List team-scoped federation roster entries and recent scoped jobs.",
        "inputSchema": {
            "type": "object",
            "properties": {"include_offline": {"type": "boolean"}},
        },
    },
    "team_list": {
        "name": "team_list",
        "description": "List teams visible to the authenticated agent.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    "group_say": {
        "name": "group_say",
        "description": "Post a short group collaboration update as the authenticated agent.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "chat_id": {"type": "integer"},
                "thread_id": {"type": "integer"},
            },
            "required": ["message"],
        },
    },
    "team_dispatch": {
        "name": "team_dispatch",
        "description": "Dispatch one or more tasks to teammates within authorized teams.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bot": {"type": "string"},
                "prompt": {"type": "string"},
                "assignments": {"type": "array", "items": {"type": "object"}},
                "team_id": {"type": "string"},
                "mode": {"type": "string"},
                "wait": {"type": "boolean"},
            },
        },
    },
    "team_job": {
        "name": "team_job",
        "description": "List, inspect, or cancel team-scoped jobs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["list", "status", "cancel"]},
                "job_id": {"type": "string"},
                "limit": {"type": "integer"},
                "reason": {"type": "string"},
            },
            "required": ["action"],
        },
    },
    "team_broadcast": {
        "name": "team_broadcast",
        "description": "Broadcast a plain status notice to a permitted team chat.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "bot": {"type": "string"},
                "chat_id": {"type": "integer"},
                "thread_id": {"type": "integer"},
                "team_id": {"type": "string"},
            },
            "required": ["message"],
        },
    },
    "host_exec": {
        "name": "host_exec",
        "description": "Execute an allowlisted host command (shell=False, 3-lock guarded).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "argv": {"type": "array", "items": {"type": "string"}},
                "command": {"type": "string"},
                "workdir": {"type": "string"},
                "timeout_sec": {"type": "number"},
            },
        },
    },
    "host_files": {
        "name": "host_files",
        "description": "Read, list, stat, or write host files (3-lock guarded).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["read", "list", "stat", "write"]},
                "path": {"type": "string"},
                "content": {"type": "string"},
                "max_bytes": {"type": "integer"},
            },
            "required": ["action", "path"],
        },
    },
    "host_services": {
        "name": "host_services",
        "description": "Inspect agy/hermes systemd services or trigger safe sentinel reload.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["status", "list", "logs", "reload"]},
                "service": {"type": "string"},
                "lines": {"type": "integer"},
            },
            "required": ["action"],
        },
    },
    "host_invoke_agent": {
        "name": "host_invoke_agent",
        "description": "Invoke another agent via Bot Bus with non-spoofable sender and monotonic trust.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string"},
                "prompt": {"type": "string"},
                "team_id": {"type": "string"},
                "mode": {"type": "string"},
                "wait": {"type": "boolean"},
                "timeout_sec": {"type": "number"},
            },
            "required": ["agent_id", "prompt"],
        },
    },
}


# ---------------------------------------------------------------- HTTP Server & Request Handler
class FederationHubServer(http.server.ThreadingHTTPServer):
    """Hardened local/federated Inbound Hub HTTP server."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        *,
        host: Optional[str] = None,
        port: Optional[int] = None,
        bus_dir: Optional[str] = None,
        repo_root: Optional[str] = None,
        home_dir: Optional[str] = None,
        reload_sentinel_dir: str = "/tmp",
        allow_non_loopback: Optional[bool] = None,
        allowed_origins: Optional[Sequence[str]] = None,
        allowed_hosts: Optional[Sequence[str]] = None,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        rate_limit_max_requests: int = DEFAULT_RATE_LIMIT_MAX_REQUESTS,
        rate_limit_window_sec: float = DEFAULT_RATE_LIMIT_WINDOW_SEC,
        require_replay_headers: bool = False,
        replay_window_sec: float = DEFAULT_REPLAY_WINDOW_SEC,
        nonce_cache_max: int = DEFAULT_NONCE_CACHE_MAX,
        start_dispatcher: bool = False,
        dispatcher_poll_interval: float = 0.2,
        env: Optional[Mapping[str, str]] = None,
    ):
        e = os.environ if env is None else env
        eff_host = host if host is not None else (str(e.get("AGY_FEDERATION_HUB_HOST") or "").strip() or DEFAULT_HUB_HOST)
        eff_port = int(port if port is not None else (str(e.get("AGY_FEDERATION_HUB_PORT") or "").strip() or DEFAULT_HUB_PORT))
        validate_bind_host(eff_host, allow_non_loopback=allow_non_loopback, env=e)

        self.bind_host = eff_host
        self.bus_dir = federation_registry._resolve_bus_dir(bus_dir)
        self.repo_root = os.path.abspath(
            repo_root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        self.home_dir = os.path.abspath(home_dir) if home_dir else os.path.expanduser("~")
        self.max_body_bytes = max(128, int(max_body_bytes or DEFAULT_MAX_BODY_BYTES))
        self.require_replay_headers = bool(require_replay_headers)
        self.replay_window_sec = max(1.0, float(replay_window_sec or DEFAULT_REPLAY_WINDOW_SEC))

        raw_origins = list(allowed_origins or ())
        env_origins = str(e.get("AGY_FEDERATION_HUB_ALLOWED_ORIGINS") or "").strip()
        if env_origins:
            raw_origins.extend(x.strip() for x in env_origins.split(",") if x.strip())
        self.allowed_origins = {o.rstrip("/").lower() for o in raw_origins if o}

        self.allowed_hosts = {"127.0.0.1", "localhost", "::1"}
        clean_bind = eff_host.strip("[]").lower()
        if clean_bind and clean_bind not in ("0.0.0.0", "::"):
            self.allowed_hosts.add(clean_bind)
        if allowed_hosts:
            self.allowed_hosts.update(h.strip("[]").lower() for h in allowed_hosts if h.strip())
        env_hosts = str(e.get("AGY_FEDERATION_HUB_ALLOWED_HOSTS") or "").strip()
        if env_hosts:
            self.allowed_hosts.update(h.strip("[]").lower() for h in env_hosts.split(",") if h.strip())

        self.nonce_cache = BoundedNonceCache(ttl_sec=self.replay_window_sec, max_entries=nonce_cache_max)
        self.rate_limiter = SlidingWindowRateLimiter(
            max_requests=rate_limit_max_requests,
            window_sec=rate_limit_window_sec,
        )
        self.audit = AuditLogger(self.bus_dir)
        self.host_bridge = HostServerBridge(
            bus_dir=self.bus_dir,
            repo_root=self.repo_root,
            home_dir=self.home_dir,
            reload_sentinel_dir=reload_sentinel_dir,
            audit_logger=self.audit,
        )
        self.dispatcher: Optional[ExternalWorkerDispatcher] = None
        if start_dispatcher:
            self.dispatcher = ExternalWorkerDispatcher(
                bus_dir=self.bus_dir,
                poll_interval=dispatcher_poll_interval,
                audit_logger=self.audit,
            )

        super().__init__((eff_host, eff_port), _FederationHubHandler)
        self.bound_port = int(self.server_address[1])

    def start_background_dispatcher(self) -> None:
        if self.dispatcher is not None:
            self.dispatcher.start()

    def stop_background_dispatcher(self) -> None:
        if self.dispatcher is not None:
            self.dispatcher.stop()

    def close_hub(self) -> None:
        self.stop_background_dispatcher()
        try:
            self.shutdown()
        except Exception:
            pass
        try:
            self.server_close()
        except Exception:
            pass

    # --- Domain action helpers shared by REST & MCP
    def op_me(self, auth: Dict[str, Any]) -> Dict[str, Any]:
        host_ok, _ = check_host_server_eligibility(auth)
        return {
            "ok": True,
            "agent": auth.get("agent"),
            "actor_id": auth.get("actor_id"),
            "is_coordinator_peer": bool(auth.get("is_coordinator_peer")),
            "can_dispatch": bool(auth.get("can_dispatch")),
            "can_receive": bool(auth.get("can_receive")),
            "allowed_teams": list(auth.get("allowed_teams") or []),
            "led_teams": list(auth.get("led_teams") or []),
            "member_teams": list(auth.get("member_teams") or []),
            "host_server_eligible": host_ok,
            "permitted_tools": _permitted_mcp_tools(auth),
        }

    def op_teams(self, auth: Dict[str, Any]) -> Dict[str, Any]:
        teams = federation_registry.list_teams(bus_dir=self.bus_dir)
        return {"ok": True, "teams": _filter_teams_for_auth(teams, auth)}

    def op_roster(self, auth: Dict[str, Any], *, include_offline: bool = True) -> Dict[str, Any]:
        teams = _filter_teams_for_auth(federation_registry.list_teams(bus_dir=self.bus_dir), auth)
        with _with_bot_bus_dir(self.bus_dir):
            full_roster = bot_bus.list_roster(include_offline=include_offline)
            raw_jobs = bot_bus.list_jobs(limit=bot_bus.JOB_RETENTION_LIMIT)

        # Scope roster strictly to visible team members + self unless unscoped global coordinator
        allowed_cap = set(auth.get("allowed_teams") or [])
        if _is_global_coord(auth) and not allowed_cap:
            scoped_roster = full_roster
        else:
            visible_members = {str(auth.get("actor_id") or "")}
            for t in teams:
                visible_members.update(t.get("members") or [])
                if t.get("leader_agent_id"):
                    visible_members.add(t["leader_agent_id"])
                visible_members.update(t.get("co_leaders") or [])
            scoped_roster = [r for r in full_roster if str(r.get("handle") or "") in visible_members]

        scoped_jobs = [bot_bus.summarize_job_brief(j) for j in _filter_jobs_for_auth(raw_jobs, auth)[:10]]
        return {
            "ok": True,
            "self_agent": auth.get("actor_id"),
            "roster": scoped_roster,
            "teams": teams,
            "recent_jobs": scoped_jobs,
        }

    def op_dispatch(self, auth: Dict[str, Any], body: Dict[str, Any], *, raw_token: str) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        extra_sec = [raw_token] if raw_token else []
        if not _can_orchestrate(auth):
            self.audit.record(
                "dispatch",
                actor_id=actor,
                action="dispatch",
                outcome="denied",
                http_status=403,
                reason="PRIVILEGE_ESCALATION_DENIED",
                extra_secrets=extra_sec,
            )
            raise HubError(
                403,
                "PRIVILEGE_ESCALATION_DENIED",
                f"PRIVILEGE_ESCALATION_DENIED: actor {actor!r} lacks dispatch authority",
                rpc_code=-32003,
            )

        agent = auth.get("agent") or {}
        caller_trust = bot_bus._normalize_trust_level(agent.get("trust_level"), default="remote_trusted")
        eff_origin = (
            "local_bus"
            if agent.get("kind") in ("agy_local", "hermes_local")
            else f"remote_{agent.get('kind') or 'hub'}"
        )
        team_id = str(body.get("team_id") or "").strip()
        wait = bool(body.get("wait", False))
        raw_assignments = body.get("assignments")
        assignments: List[Dict[str, Any]] = []
        if isinstance(raw_assignments, list) and raw_assignments:
            for item in raw_assignments:
                if not isinstance(item, dict):
                    raise HubError(400, "INVALID_ASSIGNMENT", "Each assignment must be a JSON object", rpc_code=-32602)
                ent = dict(item)
                if "agent_id" in ent and not ent.get("bot"):
                    ent["bot"] = ent["agent_id"]
                assignments.append(ent)
        else:
            bot_target = str(body.get("bot") or body.get("agent_id") or "").strip()
            prompt = str(body.get("prompt") or "").strip()
            if not bot_target or not prompt:
                raise HubError(400, "INVALID_DISPATCH", "Provide `assignments` or both `bot`/`agent_id` and `prompt`", rpc_code=-32602)
            ent = {
                "bot": bot_target,
                "prompt": prompt,
                "label": str(body.get("label") or "")[:120],
                "mode": str(body.get("mode") or ""),
                "workdir": str(body.get("workdir") or ""),
                "model": str(body.get("model") or ""),
                "effort": str(body.get("effort") or ""),
            }
            assignments.append(ent)

        try:
            with _with_bot_bus_dir(self.bus_dir):
                created = bot_bus.dispatch_assignments(
                    actor,
                    assignments,
                    team_id=team_id,
                    agent_origin=eff_origin,
                    parent_agent_origin=eff_origin,
                    parent_trust_level=caller_trust,
                    wake_on_async=not wait,
                    auth_token=raw_token,
                )
        except PermissionError as exc:
            self.audit.record(
                "dispatch",
                actor_id=actor,
                action="dispatch",
                outcome="denied",
                http_status=403,
                reason="PRIVILEGE_ESCALATION_DENIED",
                detail={"team_id": team_id, "error": str(exc)},
                extra_secrets=extra_sec,
            )
            raise HubError(403, "PRIVILEGE_ESCALATION_DENIED", str(exc), rpc_code=-32003) from exc
        except ValueError as exc:
            raise HubError(400, "INVALID_DISPATCH", str(exc), rpc_code=-32602) from exc

        job_ids = [j["job_id"] for j in created["jobs"]]
        self.audit.record(
            "dispatch",
            actor_id=actor,
            action="dispatch",
            outcome="allowed",
            http_status=200,
            detail={"group_id": created["group_id"], "job_ids": job_ids, "team_id": team_id},
            extra_secrets=extra_sec,
        )
        return {
            "ok": True,
            "group_id": created["group_id"],
            "jobs": [bot_bus.summarize_job_brief(j) for j in created["jobs"]],
        }

    def op_jobs_list(self, auth: Dict[str, Any], *, limit: int = 20) -> Dict[str, Any]:
        lim = max(1, min(100, int(limit or 20)))
        with _with_bot_bus_dir(self.bus_dir):
            raw_jobs = bot_bus.list_jobs(limit=bot_bus.JOB_RETENTION_LIMIT)
        scoped = _filter_jobs_for_auth(raw_jobs, auth)[:lim]
        return {"ok": True, "jobs": [bot_bus.summarize_job_brief(j) for j in scoped]}

    def op_job_status(self, auth: Dict[str, Any], job_id: str, *, raw_token: str) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        try:
            clean_jid = bot_bus.validate_job_id(job_id)
        except ValueError as exc:
            raise HubError(400, "INVALID_JOB_ID", str(exc), rpc_code=-32602) from exc
        with _with_bot_bus_dir(self.bus_dir):
            raw_job = bot_bus.get_job(clean_jid)
            if raw_job is None:
                raise HubError(404, "JOB_NOT_FOUND", f"Job not found: {clean_jid}", rpc_code=-32004)
            # Allow target/sender within allowed_teams OR authorize_team_action("status")
            allowed_cap = set(auth.get("allowed_teams") or [])
            j_team = str(raw_job.get("team_id") or "").strip()
            is_participant = raw_job.get("from_bot") == actor or raw_job.get("target_bot") == actor
            if is_participant and (not allowed_cap or j_team in allowed_cap):
                return {"ok": True, "job": bot_bus.summarize_job_brief(raw_job)}
            try:
                job = bot_bus.get_job(clean_jid, requester_bot=actor, auth_token=raw_token)
            except PermissionError as exc:
                raise HubError(403, "PRIVILEGE_ESCALATION_DENIED", str(exc), rpc_code=-32003) from exc
        return {"ok": True, "job": bot_bus.summarize_job_brief(job or raw_job)}

    def op_job_cancel(self, auth: Dict[str, Any], job_id: str, reason: str, *, raw_token: str) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        extra_sec = [raw_token] if raw_token else []
        try:
            clean_jid = bot_bus.validate_job_id(job_id)
        except ValueError as exc:
            raise HubError(400, "INVALID_JOB_ID", str(exc), rpc_code=-32602) from exc
        try:
            with _with_bot_bus_dir(self.bus_dir):
                job = bot_bus.cancel_job(
                    clean_jid,
                    requester_bot=actor,
                    reason=str(reason or "cancelled_by_coordinator"),
                    auth_token=raw_token,
                )
        except PermissionError as exc:
            self.audit.record(
                "job_cancel",
                actor_id=actor,
                action="cancel",
                outcome="denied",
                http_status=403,
                reason="PRIVILEGE_ESCALATION_DENIED",
                detail={"job_id": clean_jid},
                extra_secrets=extra_sec,
            )
            raise HubError(403, "PRIVILEGE_ESCALATION_DENIED", str(exc), rpc_code=-32003) from exc
        if job is None:
            # Also check PullWorkerQueue-only jobs
            pull_q = federation_registry.PullWorkerQueue(self.bus_dir)
            pjob = pull_q.get(clean_jid)
            if pjob is None:
                raise HubError(404, "JOB_NOT_FOUND", f"Job not found: {clean_jid}", rpc_code=-32004)
            try:
                cancelled_p = pull_q.cancel(
                    clean_jid,
                    reason=str(reason or "cancelled_by_coordinator"),
                    requester_agent_id=actor,
                    auth_token=raw_token,
                    env={},
                )
            except PermissionError as exc:
                raise HubError(403, "PRIVILEGE_ESCALATION_DENIED", str(exc), rpc_code=-32003) from exc
            self.audit.record(
                "job_cancel",
                actor_id=actor,
                action="cancel",
                outcome="allowed",
                http_status=200,
                detail={"job_id": clean_jid, "pull_only": True},
                extra_secrets=extra_sec,
            )
            return {"ok": True, "cancelled": cancelled_p}

        # Synchronize cancellation to PullWorkerQueue if bridged & converge bot_bus atomically (M2-B8)
        pull_q = federation_registry.PullWorkerQueue(self.bus_dir)
        if pull_q.get(clean_jid) is not None:
            cancel_reason = str(reason or "cancelled_by_coordinator")
            cancelled_pull = None
            try:
                cancelled_pull = pull_q.cancel(
                    clean_jid,
                    reason=cancel_reason,
                    requester_agent_id=actor,
                    auth_token=raw_token,
                    env={},
                )
            except Exception:
                cancelled_pull = None
            if isinstance(cancelled_pull, dict) and cancelled_pull.get("status") == "cancelled":
                with _with_bot_bus_dir(self.bus_dir):
                    cur_bus = bot_bus.get_job(clean_jid)
                    if isinstance(cur_bus, dict) and cur_bus.get("status") in ("queued", "running"):
                        finished = bot_bus.finish_job(
                            clean_jid,
                            status="cancelled",
                            error=cancel_reason,
                            error_code="CANCELLED_BY_COORDINATOR",
                        )
                        if isinstance(finished, dict):
                            job = finished

        self.audit.record(
            "job_cancel",
            actor_id=actor,
            action="cancel",
            outcome="allowed",
            http_status=200,
            detail={"job_id": clean_jid},
            extra_secrets=extra_sec,
        )
        return {"ok": True, "cancelled": bot_bus.summarize_job_brief(job)}

    def op_broadcast(self, auth: Dict[str, Any], args: Dict[str, Any], *, raw_token: str) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        extra_sec = [raw_token] if raw_token else []
        if not _can_orchestrate(auth):
            raise HubError(403, "PRIVILEGE_ESCALATION_DENIED", "Actor lacks broadcast authority", rpc_code=-32003)
        msg = str(args.get("message") or "").strip()
        if not msg:
            raise HubError(400, "INVALID_MESSAGE", "`message` cannot be empty", rpc_code=-32602)
        target_bot = str(args.get("bot") or actor).strip().lstrip("@").lower()
        team_id = str(args.get("team_id") or "").strip()
        try:
            federation_registry.authorize_team_action(
                actor,
                "broadcast",
                team_id=team_id,
                target_agent_id=(target_bot if target_bot != actor else ""),
                bus_dir=self.bus_dir,
                auth_token=raw_token,
                env={},
            )
        except PermissionError as exc:
            raise HubError(403, "PRIVILEGE_ESCALATION_DENIED", str(exc), rpc_code=-32003) from exc
        chat_id = int(args.get("chat_id") or 0)
        thread_id = args.get("thread_id")
        if not chat_id:
            raise HubError(400, "INVALID_CHAT_ID", "`chat_id` is required for broadcast", rpc_code=-32602)
        with _with_bot_bus_dir(self.bus_dir):
            bot_bus.enqueue_broadcast(target_bot, chat_id, msg, thread_id=thread_id, from_bot=actor)
        self.audit.record(
            "broadcast",
            actor_id=actor,
            action="team_broadcast",
            outcome="allowed",
            http_status=200,
            detail={"bot": target_bot, "chat_id": chat_id},
            extra_secrets=extra_sec,
        )
        return {"ok": True, "bot": target_bot, "chat_id": chat_id, "thread_id": thread_id}

    def op_group_say(self, auth: Dict[str, Any], args: Dict[str, Any], *, raw_token: str) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        agent = auth.get("agent") or {}
        if str(agent.get("trust_level") or "").strip().lower() == "readonly_guest":
            raise HubError(403, "PRIVILEGE_ESCALATION_DENIED", "readonly_guest cannot use group_say", rpc_code=-32003)
        msg = str(args.get("message") or "").strip()
        if not msg:
            raise HubError(400, "INVALID_MESSAGE", "`message` cannot be empty", rpc_code=-32602)
        chat_id = int(args.get("chat_id") or 0)
        if chat_id >= 0:
            raise HubError(400, "INVALID_CHAT_ID", "group_say requires negative group `chat_id`", rpc_code=-32602)
        thread_id = args.get("thread_id")
        with _with_bot_bus_dir(self.bus_dir):
            bot_bus.enqueue_group_say(actor, chat_id, msg, thread_id=thread_id)
        return {"ok": True, "bot": actor, "chat_id": chat_id, "thread_id": thread_id}

    def op_pull_inbox(self, auth: Dict[str, Any], path_agent_id: str, *, raw_token: str) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        extra_sec = [raw_token] if raw_token else []
        try:
            target_aid = federation_registry.validate_agent_id(path_agent_id)
        except ValueError as exc:
            raise HubError(400, "INVALID_AGENT_ID", str(exc), rpc_code=-32602) from exc
        if actor != target_aid:
            self.audit.record(
                "pull_inbox",
                actor_id=actor,
                action="inbox",
                outcome="denied",
                http_status=403,
                reason="CROSS_AGENT_FORBIDDEN",
                detail={"target_agent_id": target_aid},
                extra_secrets=extra_sec,
            )
            raise HubError(
                403,
                "CROSS_AGENT_FORBIDDEN",
                f"CROSS_AGENT_FORBIDDEN: agent {actor!r} cannot read inbox of {target_aid!r}",
                rpc_code=-32003,
            )
        pull_q = federation_registry.PullWorkerQueue(self.bus_dir)
        try:
            jobs = pull_q.list_jobs(target_aid, status="queued", auth_token=raw_token)
        except PermissionError as exc:
            raise HubError(403, "PRIVILEGE_ESCALATION_DENIED", str(exc), rpc_code=-32003) from exc
        events = list_leader_events(self.bus_dir, target_aid)
        return {"ok": True, "agent_id": target_aid, "jobs": jobs, "events": events}

    def op_pull_claim(self, auth: Dict[str, Any], job_id: Optional[str], *, raw_token: str) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        extra_sec = [raw_token] if raw_token else []
        pull_q = federation_registry.PullWorkerQueue(self.bus_dir)

        clean_jid: Optional[str] = None
        if job_id is not None and str(job_id).strip() and str(job_id).strip().lower() != "next":
            try:
                clean_jid = federation_registry.validate_pull_job_id(str(job_id).strip())
            except ValueError as exc:
                raise HubError(400, "INVALID_JOB_ID", str(exc), rpc_code=-32602) from exc
            existing = pull_q.get(clean_jid)
            if existing is None:
                raise HubError(404, "JOB_NOT_FOUND", f"Pull job not found: {clean_jid}", rpc_code=-32004)
            if existing.get("target_agent_id") != actor:
                self.audit.record(
                    "pull_claim",
                    actor_id=actor,
                    action="claim",
                    outcome="denied",
                    http_status=403,
                    reason="CROSS_AGENT_FORBIDDEN",
                    detail={"job_id": clean_jid, "owner": existing.get("target_agent_id")},
                    extra_secrets=extra_sec,
                )
                raise HubError(
                    403,
                    "CROSS_AGENT_FORBIDDEN",
                    f"CROSS_AGENT_FORBIDDEN: pull job {clean_jid!r} does not belong to {actor!r}",
                    rpc_code=-32003,
                )

        try:
            claimed = pull_q.claim(actor, job_id=clean_jid, auth_token=raw_token)
        except PermissionError as exc:
            self.audit.record(
                "pull_claim",
                actor_id=actor,
                action="claim",
                outcome="denied",
                http_status=403,
                reason="CROSS_AGENT_FORBIDDEN",
                detail={"job_id": clean_jid or ""},
                extra_secrets=extra_sec,
            )
            raise HubError(403, "CROSS_AGENT_FORBIDDEN", str(exc), rpc_code=-32003) from exc

        if claimed is None:
            if clean_jid is not None:
                self.audit.record(
                    "pull_claim",
                    actor_id=actor,
                    action="claim",
                    outcome="conflict",
                    http_status=409,
                    reason="JOB_NOT_CLAIMABLE",
                    detail={"job_id": clean_jid},
                    extra_secrets=extra_sec,
                )
                raise HubError(
                    409,
                    "JOB_NOT_CLAIMABLE",
                    f"Pull job {clean_jid!r} is already claimed, terminal, or cancelled",
                    rpc_code=-32009,
                )
            return {"ok": True, "job": None}

        # Sync running status to bot_bus if a matching bot_bus job exists
        claimed_jid = str(claimed["job_id"])
        with _with_bot_bus_dir(self.bus_dir):
            bus_job = bot_bus.get_job(claimed_jid)
            if isinstance(bus_job, dict) and bus_job.get("status") == "queued":
                bot_bus.claim_job(claimed_jid, actor, os.getpid())

        self.audit.record(
            "pull_claim",
            actor_id=actor,
            action="claim",
            outcome="allowed",
            http_status=200,
            detail={"job_id": claimed_jid},
            extra_secrets=extra_sec,
        )
        return {"ok": True, "job": claimed}

    def op_pull_result(
        self,
        auth: Dict[str, Any],
        job_id: str,
        body: Dict[str, Any],
        *,
        raw_token: str,
    ) -> Dict[str, Any]:
        actor = str(auth.get("actor_id") or "")
        extra_sec = [raw_token] if raw_token else []
        try:
            clean_jid = federation_registry.validate_pull_job_id(job_id)
        except ValueError as exc:
            raise HubError(400, "INVALID_JOB_ID", str(exc), rpc_code=-32602) from exc

        status = str(body.get("status") or "").strip().lower()
        if status not in ("done", "error"):
            raise HubError(400, "INVALID_STATUS", "`status` must be 'done' or 'error'", rpc_code=-32602)
        result_text = str(body.get("result_text") or "")
        error_text = str(body.get("error") or "")

        pull_q = federation_registry.PullWorkerQueue(self.bus_dir)
        existing = pull_q.get(clean_jid)
        if existing is None:
            raise HubError(404, "JOB_NOT_FOUND", f"Pull job not found: {clean_jid}", rpc_code=-32004)
        if existing.get("target_agent_id") != actor:
            self.audit.record(
                "pull_result",
                actor_id=actor,
                action="result",
                outcome="denied",
                http_status=403,
                reason="CROSS_AGENT_FORBIDDEN",
                detail={"job_id": clean_jid},
                extra_secrets=extra_sec,
            )
            raise HubError(
                403,
                "CROSS_AGENT_FORBIDDEN",
                f"CROSS_AGENT_FORBIDDEN: agent {actor!r} cannot submit result for {clean_jid!r}",
                rpc_code=-32003,
            )

        try:
            completed = pull_q.complete(
                clean_jid,
                actor,
                status=status,
                result_text=result_text,
                error=error_text,
                auth_token=raw_token,
            )
        except PermissionError as exc:
            self.audit.record(
                "pull_result",
                actor_id=actor,
                action="result",
                outcome="denied",
                http_status=403,
                reason="CROSS_AGENT_FORBIDDEN",
                detail={"job_id": clean_jid},
                extra_secrets=extra_sec,
            )
            raise HubError(403, "CROSS_AGENT_FORBIDDEN", str(exc), rpc_code=-32003) from exc
        except ValueError as exc:
            msg = str(exc)
            if "JOB_ALREADY_TERMINAL" in msg or "JOB_NOT_CLAIMED" in msg or "already terminal" in msg:
                self.audit.record(
                    "pull_result",
                    actor_id=actor,
                    action="result",
                    outcome="conflict",
                    http_status=409,
                    reason="JOB_STATE_CONFLICT",
                    detail={"job_id": clean_jid, "detail": msg},
                    extra_secrets=extra_sec,
                )
                raise HubError(409, "JOB_STATE_CONFLICT", msg, rpc_code=-32009) from exc
            raise HubError(400, "INVALID_RESULT", msg, rpc_code=-32602) from exc

        # Synchronize terminal completion to bot_bus (and emit batch_done once)
        bus_synced = False
        with _with_bot_bus_dir(self.bus_dir):
            bus_job = bot_bus.get_job(clean_jid)
            if isinstance(bus_job, dict) and bus_job.get("status") not in bot_bus.TERMINAL_STATUSES:
                bot_bus.finish_job(
                    clean_jid,
                    status=status,
                    result_text=result_text,
                    error=error_text,
                    error_code=("OK" if status == "done" else "AGENT_EXEC_ERROR"),
                )
                bus_synced = True

        self.audit.record(
            "pull_result",
            actor_id=actor,
            action="result",
            outcome="allowed",
            http_status=200,
            detail={"job_id": clean_jid, "status": status, "bus_synced": bus_synced},
            extra_secrets=extra_sec,
        )
        return {"ok": True, "job": completed, "bus_synced": bus_synced}

    def op_mcp(self, auth: Dict[str, Any], payload: Dict[str, Any], *, raw_token: str) -> Tuple[int, Dict[str, Any]]:
        if not isinstance(payload, dict):
            return 400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid JSON-RPC request"}}
        req_id = payload.get("id")
        method = str(payload.get("method") or "").strip()
        params = payload.get("params") if isinstance(payload.get("params"), dict) else {}

        if method == "initialize":
            proto = str(params.get("protocolVersion") or "2024-11-05")
            return 200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": proto,
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "agy-federation-hub", "version": "1.0.0"},
                },
            }

        if method in ("notifications/initialized", "notifications/cancelled"):
            return 202, {"ok": True}

        if method == "ping":
            return 200, {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            allowed = _permitted_mcp_tools(auth)
            schemas = [_ALL_MCP_TOOL_SCHEMAS[name] for name in allowed if name in _ALL_MCP_TOOL_SCHEMAS]
            return 200, {"jsonrpc": "2.0", "id": req_id, "result": {"tools": schemas}}

        if method == "tools/call":
            tname = str(params.get("name") or "").strip()
            targs = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            allowed = set(_permitted_mcp_tools(auth))
            if tname not in _ALL_MCP_TOOL_SCHEMAS:
                return 404, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Unknown tool: {tname}"},
                }
            if tname not in allowed:
                self.audit.record(
                    "mcp_tools_call",
                    actor_id=str(auth.get("actor_id") or ""),
                    action=tname,
                    outcome="denied",
                    http_status=403,
                    reason="TOOL_FORBIDDEN",
                    extra_secrets=([raw_token] if raw_token else ()),
                )
                return 403, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": f"FORBIDDEN: tool {tname!r} is not permitted for agent {auth.get('actor_id')!r}",
                        "data": {"code": "TOOL_FORBIDDEN"},
                    },
                }

            try:
                if tname == "team_roster":
                    res = self.op_roster(auth, include_offline=bool(targs.get("include_offline", True)))
                elif tname == "team_list":
                    res = self.op_teams(auth)
                elif tname == "group_say":
                    res = self.op_group_say(auth, targs, raw_token=raw_token)
                elif tname == "team_dispatch":
                    res = self.op_dispatch(auth, targs, raw_token=raw_token)
                elif tname == "team_job":
                    act = str(targs.get("action") or "").strip().lower()
                    if act == "list":
                        res = self.op_jobs_list(auth, limit=int(targs.get("limit") or 20))
                    elif act == "status":
                        res = self.op_job_status(auth, str(targs.get("job_id") or ""), raw_token=raw_token)
                    elif act == "cancel":
                        res = self.op_job_cancel(
                            auth,
                            str(targs.get("job_id") or ""),
                            str(targs.get("reason") or "cancelled_by_coordinator"),
                            raw_token=raw_token,
                        )
                    else:
                        raise HubError(400, "INVALID_ACTION", f"Unsupported team_job action: {act!r}", rpc_code=-32602)
                elif tname == "team_broadcast":
                    res = self.op_broadcast(auth, targs, raw_token=raw_token)
                elif tname == "host_exec":
                    res = self.host_bridge.host_exec(auth, targs, raw_token=raw_token)
                elif tname == "host_files":
                    res = self.host_bridge.host_files(auth, targs, raw_token=raw_token)
                elif tname == "host_services":
                    res = self.host_bridge.host_services(auth, targs, raw_token=raw_token)
                elif tname == "host_invoke_agent":
                    res = self.host_bridge.host_invoke_agent(auth, targs, raw_token=raw_token)
                else:
                    raise HubError(404, "UNKNOWN_TOOL", f"Unknown tool: {tname}", rpc_code=-32602)
            except HubError as exc:
                safe_msg = federation_registry.redact_secrets(
                    exc.message,
                    extra_secrets=([raw_token] if raw_token else ()),
                )
                return exc.http_status, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": exc.rpc_code,
                        "message": safe_msg,
                        "data": {"code": exc.error_code},
                    },
                }

            return 200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False)}],
                    "isError": False,
                    "structuredContent": res,
                },
            }

        return 404, {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


class _FederationHubHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: FederationHubServer

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress default stderr request logging so tokens/query strings can never leak to stderr.
        return

    def _send_json(
        self,
        status: int,
        payload: Dict[str, Any],
        *,
        extra_headers: Optional[Dict[str, str]] = None,
        close_conn: bool = False,
        extra_secrets: Sequence[str] = (),
    ) -> None:
        raw_text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if extra_secrets:
            raw_text = federation_registry.redact_secrets(raw_text, extra_secrets=extra_secrets)
        body = raw_text.encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(str(k), str(v))
        if close_conn:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _check_query_tokens(self, query_str: str) -> None:
        if not query_str:
            return
        pairs = parse_qsl(query_str, keep_blank_values=True)
        for k, v in pairs:
            k_norm = k.strip().lower().replace("-", "_")
            has_secret_val = False
            if v:
                if federation_registry.TOKEN_PREFIX in v:
                    has_secret_val = True
                else:
                    for _rule, pat in federation_registry._PLAINTEXT_SECRET_VALUE_RES:
                        if pat.search(v):
                            has_secret_val = True
                            break
            if k_norm in _FORBIDDEN_QUERY_CRED_KEYS or has_secret_val:
                self.server.audit.record(
                    "auth_rejected",
                    action=self.command,
                    outcome="denied",
                    http_status=400,
                    reason="QUERY_TOKEN_FORBIDDEN",
                    detail={"query_key": k_norm},
                    extra_secrets=([v] if v else ()),
                )
                raise HubError(
                    400,
                    "QUERY_TOKEN_FORBIDDEN",
                    "Credentials must be passed in Authorization header, never in URL query string",
                )

    def _check_host_and_origin(self) -> None:
        raw_host = self.headers.get("Host") or ""
        parsed_host = _extract_host_without_port(raw_host)
        if not parsed_host or parsed_host not in self.server.allowed_hosts:
            self.server.audit.record(
                "csrf_host_rejected",
                action=self.command,
                outcome="denied",
                http_status=403,
                reason="INVALID_HOST_HEADER",
                detail={"host": raw_host[:120]},
            )
            raise HubError(403, "INVALID_HOST_HEADER", "Host header rejected (DNS rebinding guard)")

        raw_origin = (self.headers.get("Origin") or "").strip()
        if raw_origin:
            norm_origin = raw_origin.rstrip("/").lower()
            parsed_o = urlsplit(raw_origin)
            o_ok = False
            if norm_origin in self.server.allowed_origins:
                o_ok = True
            elif parsed_o.scheme.lower() in ("http", "https") and is_loopback_host(parsed_o.hostname):
                o_ok = True
            if not o_ok:
                self.server.audit.record(
                    "csrf_origin_rejected",
                    action=self.command,
                    outcome="denied",
                    http_status=403,
                    reason="ORIGIN_FORBIDDEN",
                    detail={"origin": raw_origin[:120]},
                )
                raise HubError(403, "ORIGIN_FORBIDDEN", "Cross-origin request rejected")

    def _read_request_body(self) -> bytes:
        method = self.command.upper()
        if method in ("POST", "PUT", "PATCH"):
            raw_ct = (self.headers.get("Content-Type") or "").strip()
            media_type = raw_ct.split(";", 1)[0].strip().lower()
            if media_type != "application/json":
                raise HubError(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be application/json",
                )

        max_bytes = self.server.max_body_bytes
        te = (self.headers.get("Transfer-Encoding") or "").strip().lower()
        if "chunked" in te:
            chunks: List[bytes] = []
            total = 0
            while True:
                size_line = self.rfile.readline(128)
                if not size_line or not size_line.endswith(b"\n"):
                    raise HubError(
                        400,
                        "INVALID_CHUNKED_BODY",
                        "Malformed or truncated chunk size line",
                        headers={"Connection": "close"},
                    )
                size_token = size_line.strip().split(b";", 1)[0].strip()
                if not _CHUNK_SIZE_RE.fullmatch(size_token):
                    raise HubError(
                        400,
                        "INVALID_CHUNKED_BODY",
                        "Invalid hex chunk size",
                        headers={"Connection": "close"},
                    )
                chunk_size = int(size_token, 16)
                if chunk_size < 0:
                    raise HubError(
                        400,
                        "INVALID_CHUNKED_BODY",
                        "Negative chunk size rejected",
                        headers={"Connection": "close"},
                    )
                if chunk_size == 0:
                    for _ in range(64):
                        trailer = self.rfile.readline(4096)
                        if not trailer or trailer in (b"\r\n", b"\n"):
                            break
                    break
                if total + chunk_size > max_bytes:
                    raise HubError(
                        413,
                        "PAYLOAD_TOO_LARGE",
                        f"Request body exceeds maximum size of {max_bytes} bytes",
                        headers={"Connection": "close"},
                    )
                total += chunk_size
                data = self.rfile.read(chunk_size)
                if len(data) != chunk_size:
                    raise HubError(
                        400,
                        "INVALID_CHUNKED_BODY",
                        "Truncated chunk payload",
                        headers={"Connection": "close"},
                    )
                crlf = self.rfile.read(2)
                if crlf != b"\r\n":
                    raise HubError(
                        400,
                        "INVALID_CHUNKED_BODY",
                        "Missing CRLF terminator after chunk payload",
                        headers={"Connection": "close"},
                    )
                chunks.append(data)
            return b"".join(chunks)

        raw_cl = self.headers.get("Content-Length")
        if raw_cl is None:
            return b""
        try:
            cl = int(raw_cl.strip())
        except ValueError as exc:
            raise HubError(400, "INVALID_CONTENT_LENGTH", "Invalid Content-Length header") from exc
        if cl < 0:
            raise HubError(400, "INVALID_CONTENT_LENGTH", "Negative Content-Length header")
        if cl > max_bytes:
            raise HubError(
                413,
                "PAYLOAD_TOO_LARGE",
                f"Request body exceeds maximum size of {max_bytes} bytes",
                headers={"Connection": "close"},
            )
        if cl == 0:
            return b""
        body = self.rfile.read(cl)
        if len(body) > max_bytes:
            raise HubError(
                413,
                "PAYLOAD_TOO_LARGE",
                f"Request body exceeds maximum size of {max_bytes} bytes",
                headers={"Connection": "close"},
            )
        return body

    def _authenticate(self, path_only: str, raw_body: bytes) -> Tuple[Dict[str, Any], str]:
        auth_hdr = (self.headers.get("Authorization") or "").strip()
        if not auth_hdr:
            self.server.audit.record(
                "auth_failed",
                action=f"{self.command} {path_only}",
                outcome="denied",
                http_status=401,
                reason="MISSING_AUTHORIZATION",
            )
            raise HubError(401, "UNAUTHORIZED", "Missing Authorization Bearer token")

        parts = auth_hdr.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            self.server.audit.record(
                "auth_failed",
                action=f"{self.command} {path_only}",
                outcome="denied",
                http_status=401,
                reason="INVALID_AUTH_SCHEME",
                extra_secrets=[auth_hdr],
            )
            raise HubError(401, "UNAUTHORIZED", "Authorization header must use Bearer scheme")

        raw_token = parts[1].strip()
        # Zero-cache real-time disk verification on EVERY request (including keep-alive)
        verified_agent = federation_registry.verify_agent_token(raw_token, bus_dir=self.server.bus_dir)
        if verified_agent is None:
            self.server.audit.record(
                "auth_failed",
                action=f"{self.command} {path_only}",
                outcome="denied",
                http_status=401,
                reason="INVALID_OR_REVOKED_TOKEN",
                extra_secrets=[raw_token],
            )
            raise HubError(401, "UNAUTHORIZED", "Invalid, expired, or revoked federation token")

        aid = str(verified_agent["agent_id"])
        auth = federation_registry.resolve_actor_authority(
            aid,
            bus_dir=self.server.bus_dir,
            auth_token=raw_token,
            env={},
        )
        if not auth.get("authorized") or not auth.get("token_verified"):
            self.server.audit.record(
                "auth_failed",
                actor_id=aid,
                action=f"{self.command} {path_only}",
                outcome="denied",
                http_status=401,
                reason=str(auth.get("reason") or "UNAUTHORIZED"),
                extra_secrets=[raw_token],
            )
            raise HubError(401, "UNAUTHORIZED", "Agent is disabled, revoked, or unauthorized")

        # Per-agent sliding-window rate limit BEFORE recording into shared Nonce cache
        # so a flooding agent cannot evict legitimate agents' replay nonces.
        allowed, retry_after = self.server.rate_limiter.allow(aid)
        if not allowed:
            self.server.audit.record(
                "rate_limited",
                actor_id=aid,
                action=f"{self.command} {path_only}",
                outcome="denied",
                http_status=429,
                reason="RATE_LIMIT_EXCEEDED",
                detail={"retry_after": retry_after},
                extra_secrets=[raw_token],
            )
            raise HubError(
                429,
                "RATE_LIMIT_EXCEEDED",
                "Rate limit exceeded",
                headers={"Retry-After": str(retry_after)},
            )

        # Anti-replay header verification
        ts_hdr = self.headers.get("X-Agy-Timestamp")
        nonce_hdr = self.headers.get("X-Agy-Nonce")
        sig_hdr = self.headers.get("X-Agy-Signature")
        any_replay = any(h is not None for h in (ts_hdr, nonce_hdr, sig_hdr))
        if self.server.require_replay_headers or any_replay:
            if not ts_hdr or not nonce_hdr or not sig_hdr:
                self.server.audit.record(
                    "replay_rejected",
                    actor_id=aid,
                    action=f"{self.command} {path_only}",
                    outcome="denied",
                    http_status=401,
                    reason="REPLAY_HEADERS_INCOMPLETE",
                    extra_secrets=[raw_token],
                )
                raise HubError(401, "REPLAY_HEADERS_INCOMPLETE", "All X-Agy-Timestamp/Nonce/Signature headers are required")
            ts_str = ts_hdr.strip()
            nonce_str = nonce_hdr.strip()
            sig_str = sig_hdr.strip()
            try:
                ts_val = float(ts_str)
                if not math.isfinite(ts_val):
                    raise ValueError("non-finite timestamp")
            except ValueError as exc:
                self.server.audit.record(
                    "replay_rejected",
                    actor_id=aid,
                    action=f"{self.command} {path_only}",
                    outcome="denied",
                    http_status=401,
                    reason="REPLAY_TIMESTAMP_INVALID",
                    extra_secrets=[raw_token],
                )
                raise HubError(401, "REPLAY_TIMESTAMP_INVALID", "Invalid X-Agy-Timestamp header") from exc
            if abs(time.time() - ts_val) > self.server.replay_window_sec:
                self.server.audit.record(
                    "replay_rejected",
                    actor_id=aid,
                    action=f"{self.command} {path_only}",
                    outcome="denied",
                    http_status=401,
                    reason="REPLAY_TIMESTAMP_EXPIRED",
                    extra_secrets=[raw_token],
                )
                raise HubError(401, "REPLAY_TIMESTAMP_EXPIRED", "Request timestamp outside allowed replay window")
            if not (1 <= len(nonce_str) <= 128) or any(ch.isspace() or ord(ch) < 32 for ch in nonce_str):
                raise HubError(401, "REPLAY_NONCE_INVALID", "Invalid X-Agy-Nonce header")

            expected_sig = compute_replay_signature(
                raw_token,
                ts_str,
                nonce_str,
                self.command,
                path_only,
                raw_body,
            )
            if not hmac.compare_digest(sig_str.lower(), expected_sig.lower()):
                self.server.audit.record(
                    "replay_rejected",
                    actor_id=aid,
                    action=f"{self.command} {path_only}",
                    outcome="denied",
                    http_status=401,
                    reason="REPLAY_SIGNATURE_INVALID",
                    extra_secrets=[raw_token],
                )
                raise HubError(401, "REPLAY_SIGNATURE_INVALID", "Invalid X-Agy-Signature")
            if not self.server.nonce_cache.check_and_record(aid, nonce_str):
                self.server.audit.record(
                    "replay_rejected",
                    actor_id=aid,
                    action=f"{self.command} {path_only}",
                    outcome="denied",
                    http_status=401,
                    reason="REPLAY_NONCE_REUSED",
                    extra_secrets=[raw_token],
                )
                raise HubError(401, "REPLAY_NONCE_REUSED", "Duplicate X-Agy-Nonce replay detected")

        return auth, raw_token

    def _parse_json_body(self, raw_body: bytes) -> Dict[str, Any]:
        if not raw_body:
            return {}
        try:
            parsed = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            raise HubError(400, "INVALID_JSON", f"Invalid JSON body: {exc}") from exc
        if not isinstance(parsed, dict):
            raise HubError(400, "INVALID_JSON", "JSON request body must be an object")
        return parsed

    def _dispatch_request(self) -> None:
        raw_token = ""
        try:
            split = urlsplit(self.path)
            path_only = split.path or "/"
            self._check_query_tokens(split.query)
            self._check_host_and_origin()
            raw_body = self._read_request_body()

            if self.command == "GET" and path_only == "/hub/v1/health":
                self._send_json(200, {"ok": True, "service": "agy-federation-hub"})
                return

            auth, raw_token = self._authenticate(path_only, raw_body)

            if self.command == "POST" and path_only == "/hub/mcp":
                body = self._parse_json_body(raw_body)
                code, resp = self.server.op_mcp(auth, body, raw_token=raw_token)
                self._send_json(code, resp, extra_secrets=([raw_token] if raw_token else ()))
                return

            if self.command == "GET":
                if path_only == "/hub/v1/me":
                    self._send_json(200, self.server.op_me(auth), extra_secrets=[raw_token])
                    return
                if path_only == "/hub/v1/teams":
                    self._send_json(200, self.server.op_teams(auth), extra_secrets=[raw_token])
                    return
                if path_only == "/hub/v1/roster":
                    qdict = dict(parse_qsl(split.query))
                    inc_off = str(qdict.get("include_offline", "true")).lower() not in ("0", "false", "no")
                    self._send_json(200, self.server.op_roster(auth, include_offline=inc_off), extra_secrets=[raw_token])
                    return
                if path_only == "/hub/v1/jobs":
                    qdict = dict(parse_qsl(split.query))
                    lim = int(qdict.get("limit") or 20) if str(qdict.get("limit") or "").isdigit() else 20
                    self._send_json(200, self.server.op_jobs_list(auth, limit=lim), extra_secrets=[raw_token])
                    return
                m_job = re.fullmatch(r"/hub/v1/jobs/([^/]+)", path_only)
                if m_job:
                    jid = unquote(m_job.group(1))
                    self._send_json(200, self.server.op_job_status(auth, jid, raw_token=raw_token), extra_secrets=[raw_token])
                    return
                m_inbox = re.fullmatch(r"/hub/v1/agents/([^/]+)/inbox", path_only)
                if m_inbox:
                    aid = unquote(m_inbox.group(1))
                    self._send_json(200, self.server.op_pull_inbox(auth, aid, raw_token=raw_token), extra_secrets=[raw_token])
                    return

            if self.command == "POST":
                body = self._parse_json_body(raw_body)
                if path_only == "/hub/v1/dispatch":
                    self._send_json(200, self.server.op_dispatch(auth, body, raw_token=raw_token), extra_secrets=[raw_token])
                    return
                if path_only == "/hub/v1/jobs/claim":
                    jid = body.get("job_id")
                    self._send_json(200, self.server.op_pull_claim(auth, jid, raw_token=raw_token), extra_secrets=[raw_token])
                    return
                m_cancel = re.fullmatch(r"/hub/v1/jobs/([^/]+)/cancel", path_only)
                if m_cancel:
                    jid = unquote(m_cancel.group(1))
                    self._send_json(
                        200,
                        self.server.op_job_cancel(auth, jid, str(body.get("reason") or "cancelled_by_coordinator"), raw_token=raw_token),
                        extra_secrets=[raw_token],
                    )
                    return
                m_claim = re.fullmatch(r"/hub/v1/jobs/([^/]+)/claim", path_only)
                if m_claim:
                    jid = unquote(m_claim.group(1))
                    self._send_json(200, self.server.op_pull_claim(auth, jid, raw_token=raw_token), extra_secrets=[raw_token])
                    return
                m_res = re.fullmatch(r"/hub/v1/jobs/([^/]+)/result", path_only)
                if m_res:
                    jid = unquote(m_res.group(1))
                    self._send_json(200, self.server.op_pull_result(auth, jid, body, raw_token=raw_token), extra_secrets=[raw_token])
                    return
                if path_only == "/hub/v1/host/exec":
                    self._send_json(200, self.server.host_bridge.host_exec(auth, body, raw_token=raw_token), extra_secrets=[raw_token])
                    return
                if path_only == "/hub/v1/host/files":
                    self._send_json(200, self.server.host_bridge.host_files(auth, body, raw_token=raw_token), extra_secrets=[raw_token])
                    return
                if path_only == "/hub/v1/host/services":
                    self._send_json(200, self.server.host_bridge.host_services(auth, body, raw_token=raw_token), extra_secrets=[raw_token])
                    return
                if path_only == "/hub/v1/host/invoke_agent":
                    self._send_json(200, self.server.host_bridge.host_invoke_agent(auth, body, raw_token=raw_token), extra_secrets=[raw_token])
                    return

            raise HubError(404, "NOT_FOUND", f"Endpoint not found: {self.command} {path_only}")
        except HubError as exc:
            close_conn = exc.http_status == 413 or exc.headers.get("Connection", "").lower() == "close"
            extra_h = {k: v for k, v in exc.headers.items() if k.lower() != "connection"}
            self._send_json(
                exc.http_status,
                {"ok": False, "error": exc.error_code, "message": exc.message},
                extra_headers=extra_h,
                close_conn=close_conn,
                extra_secrets=([raw_token] if raw_token else ()),
            )
        except Exception as exc:
            safe_err = federation_registry.redact_secrets(
                str(exc),
                extra_secrets=([raw_token] if raw_token else ()),
            )
            self._send_json(
                500,
                {"ok": False, "error": "INTERNAL_ERROR", "message": safe_err},
                extra_secrets=([raw_token] if raw_token else ()),
            )

    def do_GET(self) -> None:
        self._dispatch_request()

    def do_POST(self) -> None:
        self._dispatch_request()

    def do_PUT(self) -> None:
        self._dispatch_request()

    def do_PATCH(self) -> None:
        self._dispatch_request()

    def do_DELETE(self) -> None:
        self._dispatch_request()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="AGY External Agent Federation Inbound Hub & Outbound Dispatcher")
    parser.add_argument("--host", default=None, help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default: 18799)")
    parser.add_argument("--bus-dir", default=None, help="Override AGY_BOT_BUS_DIR")
    parser.add_argument("--no-dispatcher", action="store_true", help="Disable background ExternalWorkerDispatcher")
    parser.add_argument("--require-replay", action="store_true", help="Require anti-replay headers on every request")
    args = parser.parse_args(argv)

    server = FederationHubServer(
        host=args.host,
        port=args.port,
        bus_dir=args.bus_dir,
        require_replay_headers=bool(args.require_replay or os.environ.get("AGY_FEDERATION_HUB_REQUIRE_REPLAY") == "1"),
        start_dispatcher=not args.no_dispatcher,
    )

    def _on_signal(_signum: int, _frame: Any) -> None:
        threading.Thread(target=server.close_hub, daemon=True).start()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _on_signal)
        except Exception:
            pass

    server.start_background_dispatcher()
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.close_hub()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
