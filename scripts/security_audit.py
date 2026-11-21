#!/usr/bin/env python3
"""Strict desensitization and secret audit gate for `agy-bot`.

Zero-leak design: this script contains ONLY generic structural rules (zero hardcoded
personal IDs, domains, handles, or credentials) plus optional local blocklist support
loaded at runtime from outside the repository (`--blocklist-file` or
`~/.config/agy-audit-blocklist.txt`).

Audits working-tree files and (optionally) full Git commit history across:
- KEY: raw API keys, bot tokens, OAuth/PATs, masked secret prefixes (`••••`), private keys,
  high-entropy credential assignments, Authorization headers, and Vault secret references.
- API / URL: credentialed URLs, query-string tokens, webhooks, Cloudflare NS servers,
  non-allowlisted external endpoints, and bare non-public domains.
- ID: contextual IDs (`CHAT_ID`, `USER_ID`, `ZONE_ID`, `ACCOUNT_ID`, ...), Telegram
  negative group/supergroup IDs, standalone long numeric IDs, 32-char hex IDs, and UUIDs.
- PII / PATH / INFRA: non-example emails, non-decorator `@handles`, hardcoded `/home/<user>`
  or `User=<user>` paths, non-local IPv4/IPv6 addresses, and runtime secret artifacts.
"""

from __future__ import annotations

import argparse
from bisect import bisect_right
import dataclasses
import ipaddress
import json
from json.decoder import scanstring as _json_scanstring
import math
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Set, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOCAL_BLOCKLIST = Path.home() / ".config" / "agy-audit-blocklist.txt"

SKIP_DIRS: Set[str] = {
    ".git",
    ".worktrees",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "backups",
    "state",
    ".pytest_cache",
    ".ruff_cache",
}

BINARY_SUFFIXES: Set[str] = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".sqlite",
}

# Host-private operator tooling / skills that must never appear in the public repo.
HOST_PRIVATE_EXACT: Set[str] = {
    ".agents/rules/google-profile.md",
    "bin/bao",
    "bin/gh-bao",
    "bin/wrangler-bao",
    "scripts/export_public.py",
    "scripts/howtofix_daily_checkin.py",
    "scripts/sync_live.py",
    "tests/test_export_public.py",
}

HOST_PRIVATE_PREFIXES: Tuple[str, ...] = (
    ".agents/skills/cloud-mail/",
    ".agents/skills/cloudflare/",
    ".agents/skills/dnshe/",
    ".agents/skills/github/",
    ".agents/skills/google-profile/",
    ".agents/skills/instabox/",
    ".agents/skills/openbao/",
    ".agents/skills/evolved-camoufox-google-playwright/",
    ".agents/skills/evolved-cloudflare-wrangler-ops/",
    ".agents/skills/evolved-howtofix-cli-automation/",
    ".agents/skills/evolved-openbao-secret-ops/",
    "systemd/user/",
)

FORBIDDEN_RUNTIME_NAMES: Set[str] = {
    ".env",
    ".bao_credentials.json",
    "auth.json",
    "credentials.json",
    "claude-mem-recent.md",
    "ecc-active-instincts.md",
}

FORBIDDEN_RUNTIME_SUFFIXES: Tuple[str, ...] = (
    ".token",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
)

PLACEHOLDER_MARKERS: Tuple[str, ...] = (
    "REPLACE_WITH",
    "YOUR_",
    "YOUR-",
    "EXAMPLE",
    "PLACEHOLDER",
    "DUMMY",
    "MOCK_",
    "CHANGEME",
    "CHANGE_ME",
    "INSERT_",
    "<RETRIEVE",
    "REDACTED",
)

SAFE_EXAMPLE_IDS: Set[str] = {
    "0",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "987654321",
    "111111111",
    "-123456789",
    "-1001234567890",
}

SAFE_EMAIL_LOCALS: Set[str] = {
    "ghp_xxxx",
}

SAFE_EMAIL_DOMAINS: Set[str] = {
    "example.com",
    "example.org",
    "example.net",
    "yourdomain.com",
    "your-domain.com",
    "users.noreply.github.com",
    "localhost",
    "placeholder.local",
}

SAFE_PUBLIC_HOSTS: Set[str] = {
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "api.telegram.org",
    "core.telegram.org",
    "telegram.org",
    "web.telegram.org",
    "t.me",
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "nodejs.org",
    "docs.python.org",
    "developer.mozilla.org",
    "www.w3.org",
    "w3.org",
    "example.com",
    "example.org",
    "example.net",
    "yourdomain.com",
    "your-domain.com",
    "altare.sh",
    "api.altare.sh",
    "altare.gg",
    "developers.cloudflare.com",
    "api.cloudflare.com",
    "cloudflare.com",
    "modelcontextprotocol.io",
    "accounts.google.com",
    "myaccount.google.com",
    "mail.google.com",
    "support.google.com",
    "www.google.com",
    "aistudio.google.com",
    "ai.google.dev",
    "linux.do",
    "x.com",
    "vercel.com",
    "anthropic.com",
    "openai.com",
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "antigravity-cli-auto-updater-974169037036.us-central1.run.app",
    "pypi.python.org",
    "systemd.io",
    "aibigbigworld.com",
    "www.aibigbigworld.com",
}

# Verified funding metadata hosts permitted ONLY inside validated npm `package-lock.json` `funding` fields
SAFE_LOCKFILE_FUNDING_HOSTS: Set[str] = {
    "opencollective" + ".com",
    "tidelift" + ".com",
}

# Exact official vendor documentation URL prefixes permitted ONLY in built `webui/dist/assets/*.js`
DIST_JS_DOC_URL_PREFIXES: Tuple[str, ...] = (
    "https://" + "react" + ".dev/errors/",
    "https://" + "react" + ".dev/link/",
)
# Exact vendor license URL permitted ONLY inside a CSS license block comment in `webui/dist/assets/*.css`
DIST_CSS_LICENSE_URL: str = "https://" + "tailwindcss" + ".com"

SAFE_PUBLIC_HOST_SUFFIXES: Tuple[str, ...] = (
    ".example.com",
    ".example.org",
    ".example.net",
    ".yourdomain.com",
    ".your-domain.com",
    ".w3.org",
    ".github.com",
    ".telegram.org",
)

SAFE_AT_TOKENS: Set[str] = {
    "@abstractmethod",
    "@app",
    "@asynccontextmanager",
    "@bot",
    "@bot1",
    "@bot2",
    "@bot_one",
    "@bot_two",
    "@bota",
    "@botb",
    "@charset",
    "@classmethod",
    "@click",
    "@contextlib",
    "@contextmanager",
    "@daily",
    "@dataclass",
    "@dataclasses",
    "@example",
    "@example_bot",
    "@example_main_bot",
    "@font-face",
    "@foo_bot",
    "@handle",
    "@handles",
    "@hourly",
    "@import",
    "@keyframes",
    "@layer",
    "@lru_cache",
    "@media",
    "@mentioned",
    "@mentions",
    "@midnight",
    "@modelcontextprotocol",
    "@monthly",
    "@my_handle",
    "@param",
    "@playwright",
    "@property",
    "@pytest",
    "@returns",
    "@router",
    "@staticmethod",
    "@supports",
    "@username",
    "@validator",
    "@weekly",
    "@worker",
    "@your_bot",
    "@your_bot_1",
    "@your_bot_2",
    "@yourbot",
}


@dataclasses.dataclass(frozen=True)
class Finding:
    """Represents a single desensitization or secret audit hit."""

    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM"
    category: str  # "KEY" | "API" | "URL" | "ID" | "PII" | "PATH" | "INFRA" | "FILE" | "HISTORY"
    rule: str
    path: str
    line: int
    masked_match: str
    detail: str
    commit: Optional[str] = None

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def is_host_private(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    if norm in HOST_PRIVATE_EXACT:
        return True
    if norm.startswith("systemd/") and not norm.startswith("systemd/examples/"):
        return True
    return any(norm.startswith(p) for p in HOST_PRIVATE_PREFIXES)


def _mask_value(val: str) -> str:
    s = val.strip()
    if len(s) <= 8:
        return s[:2] + "••••" if len(s) > 2 else "••••"
    if len(s) <= 14:
        return f"{s[:3]}••••{s[-3:]}"
    return f"{s[:6]}••••{s[-4:]}"


def _has_placeholder(val: str) -> bool:
    upper = val.upper()
    if any(m in upper for m in PLACEHOLDER_MARKERS):
        return True
    if re.fullmatch(r"[xX*•._-]{6,}", val.strip()):
        return True
    if val.strip().startswith(("<", "${", "$")):
        return True
    return False


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = float(len(s))
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_safe_public_host(host: str) -> bool:
    h = host.strip().lower().rstrip(".")
    if ":" in h and not h.startswith("["):
        h = h.split(":", 1)[0]
    h = h.strip("[]")
    if h in SAFE_PUBLIC_HOSTS:
        return True
    return any(h.endswith(suf) for suf in SAFE_PUBLIC_HOST_SUFFIXES)


def _line_col(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def load_local_blocklist(path: Optional[Path] = None) -> List[Tuple[str, re.Pattern[str]]]:
    """Load optional out-of-repo custom blocklist patterns (one literal or `regex:...` per line)."""
    target = path or (
        Path(os.environ["AGY_AUDIT_BLOCKLIST_FILE"])
        if os.environ.get("AGY_AUDIT_BLOCKLIST_FILE")
        else DEFAULT_LOCAL_BLOCKLIST
    )
    rules: List[Tuple[str, re.Pattern[str]]] = []
    if not target or not target.is_file():
        return rules
    for raw in target.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("regex:"):
            pat = line[6:].strip()
            rules.append((f"local_blocklist:{pat[:24]}", re.compile(pat, re.IGNORECASE)))
        else:
            rules.append((f"local_blocklist:{line[:24]}", re.compile(re.escape(line), re.IGNORECASE)))
    return rules


# ---------------------------------------------------------------------------
# Generic structural audit rules (no personal/operator literals embedded)
# ---------------------------------------------------------------------------

RAW_SECRET_RULES: Tuple[Tuple[str, str, str, re.Pattern[str]], ...] = (
    ("CRITICAL", "KEY", "private_key_pem", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("CRITICAL", "KEY", "github_pat", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{12,}\b")),
    ("CRITICAL", "KEY", "tg_bot_token", re.compile(r"\b\d{8,11}:[A-Za-z0-9_-]{30,42}\b")),
    ("CRITICAL", "KEY", "google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")),
    ("CRITICAL", "KEY", "aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16}\b")),
    ("CRITICAL", "KEY", "openai_anthropic_sk", re.compile(r"\bsk-(?:proj-|ant-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b")),
    ("CRITICAL", "KEY", "cloudflare_api_token", re.compile(r"\b(?:cfut|cfsd|cfat)_[A-Za-z0-9_-]{10,}\b")),
    ("CRITICAL", "KEY", "altare_key", re.compile(r"\balt_[A-Za-z0-9_-]{14,}\b")),
    (
        "CRITICAL",
        "KEY",
        "resend_key",
        re.compile(r"\bre_(?=[A-Za-z0-9_-]*(?:\d|[A-Z]))[A-Za-z0-9_-]{14,}\b"),
    ),
    ("CRITICAL", "KEY", "instabox_key", re.compile(r"\b(?:ibk|ibssh)_[A-Za-z0-9_-]{8,}\b")),
    ("CRITICAL", "KEY", "vault_hvs_token", re.compile(r"\bhvs\.[A-Za-z0-9_-]{12,}\b")),
    ("CRITICAL", "KEY", "slack_stripe_token", re.compile(r"\b(?:xox[baprs]-[0-9A-Za-z-]{10,}|(?:rk|pk|whsec)_(?:live|test)_[0-9A-Za-z]{12,})\b")),
    ("CRITICAL", "KEY", "cf_tunnel_eyJ", re.compile(r"\beyJhIjoi[A-Za-z0-9+/=_-]{16,}")),
    ("HIGH", "KEY", "jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b")),
    ("HIGH", "KEY", "pk_prefixed_key", re.compile(r"\bpk-[A-Za-z0-9_-]{12,}\b(?![•*])")),
    ("CRITICAL", "URL", "url_embedded_credentials", re.compile(r"https?://[^/\s:@\"'<>]+:[^/\s@\"'<>]+@[A-Za-z0-9.-]+")),
    ("CRITICAL", "API", "telegram_api_literal_token", re.compile(r"https?://api\.telegram\.org/bot\d+:[A-Za-z0-9_-]+")),
    (
        "CRITICAL",
        "API",
        "webhook_secret_url",
        re.compile(
            r"https?://(?:discord\.com/api/webhooks|hooks\.slack\.com/services|oapi\.dingtalk\.com/robot|qyapi\.weixin\.qq\.com/cgi-bin/webhook)/[^\s\"'<>]+"
        ),
    ),
    (
        "CRITICAL",
        "URL",
        "url_query_secret",
        re.compile(
            r"https?://[^\s\"'<>]+\?[A-Za-z0-9_.-]*(?:key|token|secret|auth|sig|signature|password|apikey|access_token)=[^&\s\"'<>]+",
            re.IGNORECASE,
        ),
    ),
    (
        "CRITICAL",
        "KEY",
        "auth_header_literal",
        re.compile(r"""(?i)\bauthorization\b["']?\s*[:=]\s*["'](?:bearer|basic|token)\s+([A-Za-z0-9_.~+/=-]{14,})["']"""),
    ),
)

CREDENTIAL_ASSIGN_RE = re.compile(
    r"""(?i)\b([A-Z0-9_]*(?:API_KEY|APIKEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET|WEBHOOK_SECRET|SIGNING_SECRET|AUTH_TOKEN|BOT_TOKEN|TUNNEL_TOKEN|PASSCODE))["']?\s*[:=]\s*(?:["']([^"'\s\n]{14,})["']|([A-Za-z0-9_./+=-]{14,}))"""
)

MASKED_KEY_RE = re.compile(
    r"""(?<![A-Za-z0-9_])(?:(?:(?:ghp|gho|ghu|ghs|ghr|github_pat|cfut|cfsd|cfat|ibk|ibssh|alt|re)_|(?:sk|pk)-|hvs\.|AIza)[A-Za-z0-9_-]{0,16}(?:•{2,}|\*{3,})[A-Za-z0-9_-]*|[A-Za-z0-9_.-]{3,}(?:•{3,}|\*{4,})[A-Za-z0-9_.-]{2,})(?![A-Za-z0-9_])"""
)

STRICT_EXPOSURE_RULES: Tuple[Tuple[str, str, str, re.Pattern[str]], ...] = (
    ("HIGH", "INFRA", "vault_secret_path", re.compile(r"\b(?:lv[12]|kv/data|secret/data)/[A-Za-z0-9_./*-]+\b")),
    ("HIGH", "INFRA", "vault_card_identifier", re.compile(r"\b[a-z][a-z0-9]*-lv\d+-card\d+\b", re.IGNORECASE)),
    (
        "HIGH",
        "API",
        "custom_device_header",
        re.compile(r"\bX-[A-Za-z0-9-]*Device(?:-[A-Za-z0-9-]+)?\b"),
    ),
    (
        "HIGH",
        "URL",
        "cloudflare_nameserver",
        re.compile(r"\b[a-z0-9-]+\.ns\.cloudflare\.com\b", re.IGNORECASE),
    ),
    (
        "HIGH",
        "ID",
        "telegram_group_or_channel_id",
        re.compile(r"(?<![A-Za-z0-9_.-])-(?:100\d{8,12}|\d{9,13})(?![A-Za-z0-9_.-])"),
    ),
    (
        "HIGH",
        "ID",
        "contextual_sensitive_id",
        re.compile(
            r"""(?i)\b(?:ALLOWED_CHATS|TG_ALLOWED_CHATS|CHAT_ID|TG_CHAT_ID|USER_ID|OWNER_ID|ADMIN_ID|GROUP_ID|CHANNEL_ID|ACCOUNT_ID|ZONE_ID|TEAM_ID|CLIENT_ID)["']?\s*[:=]\s*["']?(-?\d{6,16}|[a-fA-F0-9]{24,64})\b"""
        ),
    ),
    (
        "MEDIUM",
        "ID",
        "standalone_long_numeric_id",
        re.compile(r"(?<![A-Za-z0-9_.-])-?\d{8,15}(?![A-Za-z0-9_.-])"),
    ),
    (
        "HIGH",
        "ID",
        "hex_32_identifier",
        re.compile(r"(?<![A-Fa-f0-9])(?=[a-f0-9]*[a-f])(?=[a-f0-9]*[0-9])[a-f0-9]{32}(?![A-Fa-f0-9])"),
    ),
    (
        "MEDIUM",
        "ID",
        "uuid_identifier",
        re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    ),
    (
        "HIGH",
        "PATH",
        "hardcoded_home_path",
        re.compile(r"/(?:home|Users)/(?!your-user\b|YOUR_USER\b|<user>|\$USER\b|\$\{USER\}|altare\b)[A-Za-z0-9._-]+"),
    ),
    (
        "HIGH",
        "PATH",
        "hardcoded_systemd_user",
        re.compile(r"\bUser=(?!your-user\b|YOUR_USER\b|<user>)[A-Za-z0-9._-]+\b"),
    ),
)

EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
AT_HANDLE_RE = re.compile(r"(?<![A-Za-z0-9_./+\\-])(@[A-Za-z][A-Za-z0-9_-]{2,})\b(?!\.[A-Za-z0-9]{1,6}\b)")
URL_RE = re.compile(r"\b(?:https?|wss?)://([A-Za-z0-9][A-Za-z0-9_.:@%-]*)(?:/[^\s\"'<>)\]}]*)?", re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(
    r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:xyz|net|org|com|cd)|api\.[a-z0-9-]+\.sh)\b",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"(?<![\dv.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
IPV6_RE = re.compile(
    r"(?<![A-Fa-f0-9:\[])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4})(?![A-Fa-f0-9:.])"
)


def _scan_raw_secrets(text: str, rel_path: str, commit: Optional[str] = None) -> List[Finding]:
    findings: List[Finding] = []
    for severity, cat, rule, rx in RAW_SECRET_RULES:
        for m in rx.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            if _has_placeholder(val):
                continue
            if rule == "tg_bot_token" and val.startswith(("123456789:", "000000000:")):
                continue
            if rule == "pk_prefixed_key" and val.lower().startswith("pk-your"):
                continue
            findings.append(
                Finding(
                    severity=severity,
                    category=cat,
                    rule=rule,
                    path=rel_path,
                    line=_line_col(text, m.start()),
                    masked_match=_mask_value(val),
                    detail=f"Matched raw secret pattern `{rule}`",
                    commit=commit,
                )
            )

    for m in CREDENTIAL_ASSIGN_RE.finditer(text):
        var_name = m.group(1)
        is_quoted = m.group(2) is not None
        val = m.group(2) if is_quoted else m.group(3)
        if _has_placeholder(val):
            continue
        if any(tok in val for tok in ("os.environ", "os.getenv", "getenv(", "subprocess", "bao get", "example.com")):
            continue
        if val.startswith(("/", "~", "./", "http://127.0.0.1", "http://localhost")):
            continue
        if not is_quoted and ("." in val or val.isupper() or val.islower()):
            continue
        entropy = _shannon_entropy(val)
        has_digits = any(c.isdigit() for c in val)
        has_upper = any(c.isupper() for c in val)
        has_lower = any(c.islower() for c in val)
        classes = int(has_digits) + int(has_upper) + int(has_lower)
        if entropy >= 3.2 and (classes >= 2 or (is_quoted and len(val) >= 24)):
            findings.append(
                Finding(
                    severity="CRITICAL",
                    category="KEY",
                    rule="high_entropy_credential_assignment",
                    path=rel_path,
                    line=_line_col(text, m.start()),
                    masked_match=f"{var_name}={_mask_value(val)}",
                    detail=f"High-entropy literal ({entropy:.2f} bits/char) assigned to `{var_name}`",
                    commit=commit,
                )
            )
    return findings


_NPM_SCOPED_PKG_RE = re.compile(r"^@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$")
_NPM_DEP_SECTIONS = frozenset(
    {"dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "peerDependenciesMeta"}
)
_JSON_WS_RE = re.compile(r"[ \t\r\n]*")
_JSON_NUM_RE = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_TS_IMPORT_SCOPE_RE = re.compile(
    r"""(?:^|[\n;])[ \t]*import\s+(?:type\s+)?(?:[^"'`\n;]*?\s+from\s+)?(["'])(@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*)(?:/[A-Za-z0-9._-]+)*\1""",
    re.MULTILINE,
)
_JS_REGEX_PREV_KEYWORDS = frozenset(
    {"return", "case", "throw", "in", "of", "typeof", "void", "delete", "new", "else", "do", "yield", "await"}
)
_JS_REGEX_PREV_PUNCT = frozenset("=(,:?!&|{;[~^+-*%<>")


def _is_dist_js_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/")
    return norm.startswith("webui/dist/assets/") and norm.endswith(".js")


def _is_dist_css_path(rel_path: str) -> bool:
    norm = rel_path.replace("\\", "/")
    return norm.startswith("webui/dist/assets/") and norm.endswith(".css")


def _span_contains(sorted_spans: Sequence[Tuple[int, int]], start: int, end: int) -> bool:
    """Return True if `[start, end)` lies strictly inside one of the disjoint sorted spans."""
    if not sorted_spans:
        return False
    idx = bisect_right(sorted_spans, (start, 1 << 60)) - 1
    if idx < 0:
        return False
    s, e = sorted_spans[idx]
    return s <= start and end <= e


def _span_overlaps(sorted_spans: Sequence[Tuple[int, int]], start: int, end: int) -> bool:
    """Return True if `[start, end)` overlaps any span in the disjoint sorted span list."""
    if not sorted_spans:
        return False
    idx = bisect_right(sorted_spans, (start, 1 << 60)) - 1
    if idx >= 0:
        s, e = sorted_spans[idx]
        if s < end and start < e:
            return True
    nxt = idx + 1
    if 0 <= nxt < len(sorted_spans):
        s, e = sorted_spans[nxt]
        if s < end and start < e:
            return True
    return False


def _parse_json_with_spans(text: str) -> Optional[Any]:
    """Strict JSON parser returning an AST with exact character spans `(start, end)` for strings/objects/arrays."""
    n = len(text)
    pos = _JSON_WS_RE.match(text, 0).end()  # type: ignore[union-attr]

    def _skip_ws(i: int) -> int:
        m = _JSON_WS_RE.match(text, i)
        return m.end() if m else i

    def _parse_value(i: int) -> Tuple[Any, int]:
        if i >= n:
            raise ValueError("unexpected EOF")
        ch = text[i]
        if ch == '"':
            val, end = _json_scanstring(text, i + 1)
            return ("str", val, i, end), end
        if ch == "{":
            j = _skip_ws(i + 1)
            entries: List[Tuple[str, int, int, Any]] = []
            if j < n and text[j] == "}":
                return ("obj", entries, i, j + 1), j + 1
            while True:
                if j >= n or text[j] != '"':
                    raise ValueError("expected string key")
                k_start = j
                k_str, k_end = _json_scanstring(text, j + 1)
                j = _skip_ws(k_end)
                if j >= n or text[j] != ":":
                    raise ValueError("expected :")
                j = _skip_ws(j + 1)
                val_node, j = _parse_value(j)
                entries.append((k_str, k_start, k_end, val_node))
                j = _skip_ws(j)
                if j >= n:
                    raise ValueError("unterminated object")
                if text[j] == ",":
                    j = _skip_ws(j + 1)
                    continue
                if text[j] == "}":
                    return ("obj", entries, i, j + 1), j + 1
                raise ValueError("expected , or }")
        if ch == "[":
            j = _skip_ws(i + 1)
            items: List[Any] = []
            if j < n and text[j] == "]":
                return ("arr", items, i, j + 1), j + 1
            while True:
                val_node, j = _parse_value(j)
                items.append(val_node)
                j = _skip_ws(j)
                if j >= n:
                    raise ValueError("unterminated array")
                if text[j] == ",":
                    j = _skip_ws(j + 1)
                    continue
                if text[j] == "]":
                    return ("arr", items, i, j + 1), j + 1
                raise ValueError("expected , or ]")
        if text.startswith("true", i):
            return ("prim", True, i, i + 4), i + 4
        if text.startswith("false", i):
            return ("prim", False, i, i + 5), i + 5
        if text.startswith("null", i):
            return ("prim", None, i, i + 4), i + 4
        m_num = _JSON_NUM_RE.match(text, i)
        if m_num:
            return ("prim", m_num.group(0), i, m_num.end()), m_num.end()
        raise ValueError(f"unexpected token at {i}")

    try:
        root, end_pos = _parse_value(pos)
        end_pos = _skip_ws(end_pos)
        if end_pos != n:
            return None
        return root
    except Exception:
        return None


def _load_declared_webui_scoped_packages() -> Set[str]:
    """Load declared scoped npm dependency names from `webui/package.json`."""
    pkg_json = REPO_ROOT / "webui" / "package.json"
    out: Set[str] = set()
    if not pkg_json.is_file():
        return out
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return out
    if not isinstance(data, dict):
        return out
    for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        sec_obj = data.get(sec)
        if isinstance(sec_obj, dict):
            for k in sec_obj:
                if isinstance(k, str) and _NPM_SCOPED_PKG_RE.fullmatch(k):
                    out.add(k)
    return out


def _extract_package_json_dep_spans(text: str) -> List[Tuple[int, int]]:
    """Return exact JSON key spans for verified scoped npm dependency keys in `webui/package.json`."""
    ast = _parse_json_with_spans(text)
    if not ast or ast[0] != "obj":
        return []
    spans: List[Tuple[int, int]] = []
    for key, _ks, _ke, val in ast[1]:
        if key not in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            continue
        if val[0] != "obj":
            continue
        for dep_key, dks, dke, _dval in val[1]:
            if _NPM_SCOPED_PKG_RE.fullmatch(dep_key):
                spans.append((dks, dke))
    spans.sort()
    return spans


def _extract_lockfile_verified_spans(text: str) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """Parse `webui/package-lock.json` and return `(npm_dep_key_spans, verified_funding_url_spans)`.

    - `npm_dep_key_spans`: ONLY real dependency keys inside valid `packages` entries (NEVER arbitrary string values,
      descriptions, authors, or non-dependency fields).
    - `verified_funding_url_spans`: ONLY `"funding"` URL string spans inside package entries that have BOTH
      `resolved` starting with `https://registry.npmjs.org/` AND `integrity` starting with `sha512-`.
    """
    ast = _parse_json_with_spans(text)
    if not ast or ast[0] != "obj":
        return [], []

    packages_node = None
    for key, _ks, _ke, val in ast[1]:
        if key == "packages" and val[0] == "obj":
            packages_node = val
            break
    if packages_node is None:
        return [], []

    dep_spans: List[Tuple[int, int]] = []
    funding_spans: List[Tuple[int, int]] = []

    def _collect_funding(node: Any) -> None:
        kind = node[0]
        if kind == "str":
            funding_spans.append((node[2], node[3]))
        elif kind == "obj":
            for fk, _fks, _fke, fvn in node[1]:
                if fk == "url" and fvn[0] == "str":
                    funding_spans.append((fvn[2], fvn[3]))
        elif kind == "arr":
            for item in node[1]:
                _collect_funding(item)

    # First pass: gather verified package names from lockfile entries with authentic npm registry metadata
    verified_pkg_names: Set[str] = _load_declared_webui_scoped_packages()
    for pkg_path, _pks, _pke, pkg_val in packages_node[1]:
        if pkg_val[0] != "obj":
            continue
        fmap = {k: v for k, _ks, _ke, v in pkg_val[1]}
        res_node = fmap.get("resolved")
        int_node = fmap.get("integrity")
        res_str = res_node[1] if (res_node and res_node[0] == "str") else ""
        int_str = int_node[1] if (int_node and int_node[0] == "str") else ""
        has_strict_reg = res_str.startswith("https://registry.npmjs.org/") and int_str.startswith("sha512-")
        has_bundled_meta = (
            (not res_str)
            and ("version" in fmap)
            and any(flag in fmap for flag in ("optional", "dev", "devOptional", "peer", "inBundle"))
        )
        if has_strict_reg or has_bundled_meta:
            if "node_modules/" in pkg_path:
                tail = pkg_path.rsplit("node_modules/", 1)[1]
                if _NPM_SCOPED_PKG_RE.fullmatch(tail):
                    verified_pkg_names.add(tail)

    # Second pass: emit exact spans ONLY for authentic dependency keys and verified funding fields
    for pkg_path, pks, pke, pkg_val in packages_node[1]:
        if pkg_val[0] != "obj":
            continue
        fmap = {k: v for k, _ks, _ke, v in pkg_val[1]}
        res_node = fmap.get("resolved")
        int_node = fmap.get("integrity")
        res_str = res_node[1] if (res_node and res_node[0] == "str") else ""
        int_str = int_node[1] if (int_node and int_node[0] == "str") else ""
        has_strict_reg = res_str.startswith("https://registry.npmjs.org/") and int_str.startswith("sha512-")
        has_bundled_meta = (
            (not res_str)
            and ("version" in fmap)
            and any(flag in fmap for flag in ("optional", "dev", "devOptional", "peer", "inBundle"))
        )
        is_root_pkg = pkg_path == ""

        if is_root_pkg or has_strict_reg or has_bundled_meta:
            if "node_modules/" in pkg_path:
                tail = pkg_path.rsplit("node_modules/", 1)[1]
                if _NPM_SCOPED_PKG_RE.fullmatch(tail) and tail in verified_pkg_names:
                    dep_spans.append((pks, pke))
            for sec in _NPM_DEP_SECTIONS:
                sec_node = fmap.get(sec)
                if not sec_node or sec_node[0] != "obj":
                    continue
                for dk, dks, dke, _dv in sec_node[1]:
                    if not _NPM_SCOPED_PKG_RE.fullmatch(dk):
                        continue
                    # For root package, require exact declared/verified package; for registry-verified packages,
                    # allow verified packages plus optional/peer metadata entries.
                    if dk in verified_pkg_names or (
                        has_strict_reg and sec in ("optionalDependencies", "peerDependencies", "peerDependenciesMeta")
                    ):
                        dep_spans.append((dks, dke))
            if has_strict_reg and "bundleDependencies" in fmap:
                bnode = fmap["bundleDependencies"]
                if bnode[0] == "arr":
                    for item in bnode[1]:
                        if item[0] == "str" and _NPM_SCOPED_PKG_RE.fullmatch(item[1]) and item[1] in verified_pkg_names:
                            dep_spans.append((item[2], item[3]))

        # Funding URLs allowed ONLY on strictly registry-verified packages (resolved + sha512 integrity)
        if has_strict_reg and "funding" in fmap:
            _collect_funding(fmap["funding"])

    dep_spans.sort()
    funding_spans.sort()
    return dep_spans, funding_spans


def _lex_js_spans(text: str) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]], List[Tuple[int, int]]]:
    """Lex JS/TS source into disjoint sorted `(string_spans, block_comment_spans, line_comment_spans)`.

    Properly distinguishes string literals, template literals, block/line comments, and regex literals
    so quotes inside regexes or comments never desynchronize string detection.
    """
    string_spans: List[Tuple[int, int]] = []
    block_comment_spans: List[Tuple[int, int]] = []
    line_comment_spans: List[Tuple[int, int]] = []
    n = len(text)
    i = 0
    prev_non_ws = ""
    prev_ident = ""

    while i < n:
        ch = text[i]
        if ch in " \t\r\n":
            i += 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = text[i + 1]
            if nxt == "*":
                end = text.find("*/", i + 2)
                end_pos = (end + 2) if end != -1 else n
                block_comment_spans.append((i, end_pos))
                i = end_pos
                continue
            if nxt == "/":
                end = text.find("\n", i + 2)
                end_pos = end if end != -1 else n
                line_comment_spans.append((i, end_pos))
                i = end_pos
                continue
            # Possible regex literal if preceded by operator/punctuation/regex-allowing keyword
            if (not prev_non_ws) or (prev_non_ws in _JS_REGEX_PREV_PUNCT) or (prev_ident in _JS_REGEX_PREV_KEYWORDS):
                j = i + 1
                in_class = False
                valid_rx = False
                while j < n:
                    rc = text[j]
                    if rc == "\n" or rc == "\r":
                        break
                    if rc == "\\":
                        j += 2
                        continue
                    if rc == "[":
                        in_class = True
                    elif rc == "]" and in_class:
                        in_class = False
                    elif rc == "/" and not in_class:
                        j += 1
                        while j < n and text[j].isalpha():
                            j += 1
                        valid_rx = True
                        break
                    j += 1
                if valid_rx:
                    prev_non_ws = "/"
                    prev_ident = ""
                    i = j
                    continue
        if ch in ('"', "'", "`"):
            quote = ch
            j = i + 1
            while j < n:
                sc = text[j]
                if sc == "\\":
                    j += 2
                    continue
                if sc == quote:
                    j += 1
                    break
                j += 1
            string_spans.append((i, j))
            prev_non_ws = quote
            prev_ident = ""
            i = j
            continue
        if ch.isalpha() or ch in ("_", "$"):
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in ("_", "$")):
                j += 1
            prev_ident = text[i:j]
            prev_non_ws = text[j - 1]
            i = j
            continue
        prev_non_ws = ch
        prev_ident = ""
        i += 1

    return string_spans, block_comment_spans, line_comment_spans


def _lex_css_spans(text: str) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """Lex CSS into disjoint sorted `(string_spans, block_comment_spans)`."""
    string_spans: List[Tuple[int, int]] = []
    block_comment_spans: List[Tuple[int, int]] = []
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            end_pos = (end + 2) if end != -1 else n
            block_comment_spans.append((i, end_pos))
            i = end_pos
            continue
        if ch in ('"', "'"):
            quote = ch
            j = i + 1
            while j < n:
                sc = text[j]
                if sc == "\\":
                    j += 2
                    continue
                if sc == quote:
                    j += 1
                    break
                j += 1
            string_spans.append((i, j))
            i = j
            continue
        i += 1
    return string_spans, block_comment_spans


def _extract_ts_import_scope_spans(text: str, allowed_scoped_pkgs: Set[str]) -> List[Tuple[int, int]]:
    """Return exact spans of declared scoped npm packages inside static ES `import` statements (excluding comments)."""
    if not allowed_scoped_pkgs:
        return []
    _str_spans, blk_spans, line_spans = _lex_js_spans(text)
    spans: List[Tuple[int, int]] = []
    for m in _TS_IMPORT_SCOPE_RE.finditer(text):
        pkg = m.group(2)
        if pkg not in allowed_scoped_pkgs:
            continue
        imp_pos = text.find("import", m.start(), m.end())
        if imp_pos < 0:
            continue
        if _span_overlaps(blk_spans, imp_pos, imp_pos + 6) or _span_overlaps(line_spans, imp_pos, imp_pos + 6):
            continue
        spans.append((m.start(2), m.end(2)))
    spans.sort()
    return spans


def _is_css_hex_color_context(text: str, hash_idx: int, end: int) -> bool:
    """Verify `#RRGGBBAA` sits in a real CSS property value (not a comment or arbitrary identifier)."""
    if hash_idx <= 0 or text[hash_idx] != "#":
        return False
    prev_i = hash_idx - 1
    while prev_i >= 0 and text[prev_i] in " \t\r\n":
        prev_i -= 1
    if prev_i < 0 or text[prev_i] not in ":,({":
        # Also allow space-separated shorthand property values like `border: 1px solid #RRGGBBAA;`
        if not (hash_idx > 0 and text[hash_idx - 1] in " \t"):
            return False
    if end < len(text) and text[end] not in ";},) \t\r\n":
        return False
    return True


def _is_js_bitmask_literal(
    text: str,
    start: int,
    end: int,
    val_str: str,
    *,
    string_spans: Sequence[Tuple[int, int]],
    block_comment_spans: Sequence[Tuple[int, int]],
    line_comment_spans: Sequence[Tuple[int, int]],
) -> bool:
    """Return True ONLY for verified non-string 31-bit JS bitmask/lane constants in built dist JS bundles.

    NEVER exempts numbers inside quoted strings/template literals/comments,
    Telegram supergroup IDs (`-100...`), arbitrary user/chat numeric IDs, or values outside signed 32-bit range.
    """
    # Hard guard: NEVER exempt anything inside strings or comments, or adjacent to quotes
    if (
        _span_overlaps(string_spans, start, end)
        or _span_overlaps(block_comment_spans, start, end)
        or _span_overlaps(line_comment_spans, start, end)
    ):
        return False
    if start > 0 and text[start - 1] in ('"', "'", "`"):
        return False
    if end < len(text) and text[end] in ('"', "'", "`"):
        return False

    # Require valid JS numeric expression delimiters before & after
    if start > 0 and text[start - 1] not in " \t\r\n=:,(&|^~!<>{;+?*/[":
        return False
    if end < len(text) and text[end] not in " \t\r\n;,)}:&|^?=!<>+-*/]":
        return False

    try:
        n = int(val_str)
    except ValueError:
        return False
    # Telegram supergroup IDs (-100...) and 12+ digit IDs are outside signed 32-bit range
    if n < -(1 << 31) or n > (1 << 31):
        return False
    # Exact power-of-2, Mersenne mask ((1<<k)-1), or bitwise-not power-of-2 (~(1<<k) = -(1<<k)-1)
    if n > 0 and ((n & (n - 1)) == 0 or (n & (n + 1)) == 0):
        return True
    if n < 0:
        inv = -n - 1
        if inv > 0 and (inv & (inv - 1)) == 0:
            return True
    # Syntactically adjacent to JS bitwise operators (&, |, &=, |=, ^, ^=, ~)
    prev_slice = text[max(0, start - 3) : start]
    next_slice = text[end : min(len(text), end + 2)]
    if prev_slice.endswith(("&", "|", "^", "~", "&=", "|=", "^=")):
        return True
    if next_slice.startswith(("&", "|", "^")):
        return True
    # Bitmask comparison or ternary branch inside a bitwise expression, strictly low-12-bit aligned
    if (abs(n) & 0xFFF) == 0:
        window = text[max(0, start - 28) : min(len(text), end + 12)]
        if any(op in window for op in ("&=", "|=", "&", "|")):
            return True
    return False


def _scan_strict_exposures(
    text: str,
    rel_path: str,
    *,
    commit: Optional[str] = None,
    extra_rules: Sequence[Tuple[str, re.Pattern[str]]] = (),
) -> List[Finding]:
    findings: List[Finding] = []
    norm_rel = rel_path.replace("\\", "/")
    is_pkg_json = norm_rel == "webui/package.json"
    is_lockfile = norm_rel == "webui/package-lock.json"
    is_webui_ts = norm_rel in {"webui/vite.config.ts", "webui/vite.config.js"} or (
        norm_rel.startswith("webui/src/") and norm_rel.endswith((".ts", ".tsx"))
    )
    is_dist_js = _is_dist_js_path(norm_rel)
    is_dist_css = _is_dist_css_path(norm_rel)

    # Pre-compute exact syntax-verified exemption spans for WebUI files ONLY
    npm_scope_spans: List[Tuple[int, int]] = []
    funding_url_spans: List[Tuple[int, int]] = []
    js_string_spans: List[Tuple[int, int]] = []
    js_block_comment_spans: List[Tuple[int, int]] = []
    js_line_comment_spans: List[Tuple[int, int]] = []
    css_string_spans: List[Tuple[int, int]] = []
    css_block_comment_spans: List[Tuple[int, int]] = []

    if is_pkg_json:
        npm_scope_spans = _extract_package_json_dep_spans(text)
    elif is_lockfile:
        npm_scope_spans, funding_url_spans = _extract_lockfile_verified_spans(text)
    elif is_webui_ts:
        npm_scope_spans = _extract_ts_import_scope_spans(text, _load_declared_webui_scoped_packages())
    elif is_dist_js:
        js_string_spans, js_block_comment_spans, js_line_comment_spans = _lex_js_spans(text)
    elif is_dist_css:
        css_string_spans, css_block_comment_spans = _lex_css_spans(text)

    for m in MASKED_KEY_RE.finditer(text):
        val = m.group(0)
        findings.append(
            Finding(
                severity="HIGH",
                category="KEY",
                rule="masked_secret_fragment",
                path=rel_path,
                line=_line_col(text, m.start()),
                masked_match=val,
                detail="Masked/truncated credential prefix/suffix still leaks key format & characters",
                commit=commit,
            )
        )

    for severity, cat, rule, rx in STRICT_EXPOSURE_RULES:
        for m in rx.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            if val in SAFE_EXAMPLE_IDS or _has_placeholder(val):
                continue
            if rule == "uuid_identifier" and val.lower() in {
                "00000000-0000-0000-0000-000000000000",
                "12345678-1234-1234-1234-123456789012",
            }:
                continue
            if rule in ("contextual_sensitive_id", "standalone_long_numeric_id"):
                digits_only = val.lstrip("-")
                if len(set(digits_only)) == 1 or re.fullmatch(r"10{6,}", digits_only):
                    continue
                if rule == "standalone_long_numeric_id" and re.match(
                    r"\+[A-Za-z0-9._-]+@users\.noreply\.github\.com\b",
                    text[m.end() :],
                    re.IGNORECASE,
                ):
                    continue
                if (
                    rule == "standalone_long_numeric_id"
                    and is_dist_css
                    and len(val) == 8
                    and not val.startswith("-")
                    and not _span_overlaps(css_string_spans, m.start(), m.end())
                    and not _span_overlaps(css_block_comment_spans, m.start(), m.end())
                    and m.start() > 0
                    and text[m.start() - 1] == "#"
                    and _is_css_hex_color_context(text, m.start() - 1, m.end())
                ):
                    # CSS 8-digit #RRGGBBAA hex color literal inside real CSS property value
                    continue
            if (
                rule in ("standalone_long_numeric_id", "telegram_group_or_channel_id")
                and is_dist_js
                and _is_js_bitmask_literal(
                    text,
                    m.start(),
                    m.end(),
                    val,
                    string_spans=js_string_spans,
                    block_comment_spans=js_block_comment_spans,
                    line_comment_spans=js_line_comment_spans,
                )
            ):
                continue
            findings.append(
                Finding(
                    severity=severity,
                    category=cat,
                    rule=rule,
                    path=rel_path,
                    line=_line_col(text, m.start()),
                    masked_match=_mask_value(val) if len(val) > 18 else val,
                    detail=f"Strict rule `{rule}` triggered",
                    commit=commit,
                )
            )

    email_spans: List[Tuple[int, int]] = []
    for m in EMAIL_RE.finditer(text):
        email_spans.append((m.start(), m.end()))
        local_part = m.group(1).lower()
        domain = m.group(2).lower()
        if local_part in SAFE_EMAIL_LOCALS or domain in SAFE_EMAIL_DOMAINS or domain.endswith(".example.com"):
            continue
        findings.append(
            Finding(
                severity="HIGH",
                category="PII",
                rule="personal_or_real_email",
                path=rel_path,
                line=_line_col(text, m.start()),
                masked_match=_mask_value(m.group(0)),
                detail=f"Non-example email domain `{domain}`",
                commit=commit,
            )
        )

    for m in AT_HANDLE_RE.finditer(text):
        pos = m.start(1)
        end_pos = m.end(1)
        if any(s <= pos < e for s, e in email_spans):
            continue
        handle = m.group(1)
        if handle.lower() in SAFE_AT_TOKENS:
            continue
        # Verified npm scoped package ONLY in exact JSON dep keys or static TS/Vite `import` specifiers
        if npm_scope_spans and _span_contains(npm_scope_spans, pos, end_pos):
            continue
        # License tag permitted ONLY inside actual block comments in built dist JS/CSS
        if (is_dist_js or is_dist_css) and handle == ("@" + "license"):
            c_spans = js_block_comment_spans if is_dist_js else css_block_comment_spans
            if _span_contains(c_spans, pos, end_pos):
                continue
        # React/ES6 built JS runtime symbols (double-at iterator & stack frame sentinel)
        if is_dist_js and handle == ("@" + "iterator") and pos > 0 and text[pos - 1] == "@":
            continue
        if is_dist_js and handle == ("@" + "unknown") and text[pos : pos + 12] == ("@" + "unknown:0:0"):
            continue
        findings.append(
            Finding(
                severity="HIGH",
                category="PII",
                rule="unallowlisted_handle",
                path=rel_path,
                line=_line_col(text, pos),
                masked_match=handle,
                detail="Handle/mention `@...` not in generic placeholder/decorator allowlist",
                commit=commit,
            )
        )

    url_spans: List[Tuple[int, int]] = []
    for m in URL_RE.finditer(text):
        url_spans.append((m.start(), m.end()))
        full_url = m.group(0)
        host_port = m.group(1)
        if "@" in host_port:
            host_port = host_port.rsplit("@", 1)[1]
        if _has_placeholder(host_port) or "{" in host_port or "%" in host_port:
            continue
        host_only = host_port.strip().lower().rstrip(".").split(":", 1)[0].strip("[]")
        # Verified npm lockfile funding URLs ONLY inside validated `funding` field of registry-verified packages
        if (
            is_lockfile
            and host_only in SAFE_LOCKFILE_FUNDING_HOSTS
            and _span_contains(funding_url_spans, m.start(), m.end())
        ):
            continue
        # Official React error/link doc URLs ONLY in built `webui/dist/assets/*.js`
        if is_dist_js and full_url.startswith(DIST_JS_DOC_URL_PREFIXES):
            continue
        # Official Tailwind license URL ONLY inside CSS block comment in `webui/dist/assets/*.css`
        if (
            is_dist_css
            and full_url == DIST_CSS_LICENSE_URL
            and _span_contains(css_block_comment_spans, m.start(), m.end())
        ):
            continue
        if not _is_safe_public_host(host_port):
            findings.append(
                Finding(
                    severity="MEDIUM",
                    category="URL",
                    rule="unallowlisted_external_url",
                    path=rel_path,
                    line=_line_col(text, m.start()),
                    masked_match=host_port,
                    detail=f"External URL host `{host_port}` requires desensitization review or explicit allowlisting",
                    commit=commit,
                )
            )

    for m in BARE_DOMAIN_RE.finditer(text):
        pos = m.start(1)
        end_pos = m.end(1)
        if any(s <= pos < e for s, e in url_spans) or any(s <= pos < e for s, e in email_spans):
            continue
        dom = m.group(1).lower()
        if (
            is_lockfile
            and dom in SAFE_LOCKFILE_FUNDING_HOSTS
            and _span_contains(funding_url_spans, pos, end_pos)
        ):
            continue
        if _is_safe_public_host(dom) or _has_placeholder(dom):
            continue
        findings.append(
            Finding(
                severity="MEDIUM",
                category="URL",
                rule="unallowlisted_bare_domain",
                path=rel_path,
                line=_line_col(text, pos),
                masked_match=_mask_value(dom),
                detail=f"Bare domain `{dom}` outside safe vendor allowlist",
                commit=commit,
            )
        )

    for m in IPV4_RE.finditer(text):
        ip_str = m.group(0)
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip_str in {"0.0.0.0", "127.0.0.1", "255.255.255.255"}:
            continue
        if any(
            ip_obj in ipaddress.ip_network(cidr)
            for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8")
        ):
            continue
        findings.append(
            Finding(
                severity="MEDIUM",
                category="INFRA",
                rule="non_doc_ipv4",
                path=rel_path,
                line=_line_col(text, m.start()),
                masked_match=ip_str,
                detail="Non-loopback/non-RFC5737 IPv4 address exposed",
                commit=commit,
            )
        )

    for m in IPV6_RE.finditer(text):
        ip_str = m.group(0)
        if "::" not in ip_str and ip_str.count(":") < 7:
            continue
        if sum(1 for g in ip_str.split(":") if g) < 2 or len(ip_str) < 7:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        mapped = getattr(ip_obj, "ipv4_mapped", None)
        if ip_obj.version != 6 or ip_obj.is_loopback or ip_obj.is_unspecified or (mapped and mapped.is_loopback):
            continue
        findings.append(
            Finding(
                severity="MEDIUM",
                category="INFRA",
                rule="non_loopback_ipv6",
                path=rel_path,
                line=_line_col(text, m.start()),
                masked_match=_mask_value(ip_str),
                detail="Non-loopback IPv6 address exposed",
                commit=commit,
            )
        )

    for rule_name, rx in extra_rules:
        for m in rx.finditer(text):
            findings.append(
                Finding(
                    severity="HIGH",
                    category="PII",
                    rule=rule_name,
                    path=rel_path,
                    line=_line_col(text, m.start()),
                    masked_match=_mask_value(m.group(0)),
                    detail="Matched operator-supplied local blocklist entry",
                    commit=commit,
                )
            )

    return findings


def scan_text(
    text: str,
    rel_path: str,
    *,
    strict: bool = True,
    commit: Optional[str] = None,
    extra_rules: Sequence[Tuple[str, re.Pattern[str]]] = (),
) -> List[Finding]:
    """Scan a text string and return desensitization findings."""
    findings = _scan_raw_secrets(text, rel_path, commit=commit)
    if strict:
        findings.extend(_scan_strict_exposures(text, rel_path, commit=commit, extra_rules=extra_rules))
    return findings


def _is_forbidden_secret_filename(name: str) -> bool:
    return name in FORBIDDEN_RUNTIME_NAMES or (name.startswith(".env.") and name != ".env.example")


def _is_forbidden_artifact_suffix(name: str) -> bool:
    return any(name.endswith(suf) for suf in FORBIDDEN_RUNTIME_SUFFIXES) or ".bak-" in name


def is_forbidden_runtime_file(rel_path: str) -> bool:
    """Return True if basename matches a forbidden runtime secret or artifact file."""
    name = Path(rel_path).name
    return _is_forbidden_secret_filename(name) or _is_forbidden_artifact_suffix(name)


def _check_forbidden_file(rel_path: str, mode: str) -> List[Finding]:
    name = Path(rel_path).name
    if _is_forbidden_secret_filename(name):
        return [
            Finding(
                severity="CRITICAL",
                category="FILE",
                rule="forbidden_runtime_secret_file",
                path=rel_path,
                line=0,
                masked_match=name,
                detail="Runtime secret/state `.env` or credential file must never be published",
            )
        ]
    if _is_forbidden_artifact_suffix(name):
        return [
            Finding(
                severity="CRITICAL",
                category="FILE",
                rule="forbidden_artifact_suffix",
                path=rel_path,
                line=0,
                masked_match=name,
                detail="Database, token, key, or backup artifact present in repo tree",
            )
        ]
    if mode == "public-release" and is_host_private(rel_path):
        return [
            Finding(
                severity="HIGH",
                category="FILE",
                rule="host_private_file_remaining",
                path=rel_path,
                line=0,
                masked_match=rel_path,
                detail="Host-private script/skill/doc still present pending strip-or-template decision",
            )
        ]
    return []


def _iter_repo_files(repo_root: Path, exclude_paths: Optional[Sequence[str]] = None) -> Iterable[Path]:
    excluded = {p.replace("\\", "/").strip("/") for p in (exclude_paths or ())}
    for root, dirs, files in os.walk(repo_root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        rpath = Path(root)
        for fn in sorted(files):
            fp = rpath / fn
            rel = str(fp.relative_to(repo_root)).replace("\\", "/")
            if any(rel == ex or rel.startswith(ex + "/") for ex in excluded):
                continue
            yield fp


def scan_repository(
    repo_root: Path,
    *,
    mode: str = "secret-guard",
    exclude_paths: Optional[Sequence[str]] = None,
    extra_rules: Sequence[Tuple[str, re.Pattern[str]]] = (),
) -> Tuple[int, List[Finding]]:
    """Audit files under `repo_root` according to `mode`.

    Modes:
    - `secret-guard`: raw secrets forbidden everywhere; strict rules enforced on all core open-source files.
    - `core-public`: strict full rules enforced exclusively across core open-source files.
    - `public-release`: strict full rules + private-file check enforced across 100% of files.
    """
    if mode not in {"secret-guard", "core-public", "public-release"}:
        raise ValueError(f"Unsupported mode: {mode}")

    scanned = 0
    findings: List[Finding] = []
    for fp in _iter_repo_files(repo_root, exclude_paths=exclude_paths):
        rel = str(fp.relative_to(repo_root)).replace("\\", "/")
        private_file = is_host_private(rel)
        if mode == "core-public" and private_file:
            continue

        file_findings = _check_forbidden_file(rel, mode=mode)
        findings.extend(file_findings)
        if fp.suffix.lower() in BINARY_SUFFIXES or any(fp.name.endswith(s) for s in FORBIDDEN_RUNTIME_SUFFIXES):
            continue

        scanned += 1
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        use_strict = mode == "public-release" or (not private_file)
        findings.extend(scan_text(text, rel, strict=use_strict, extra_rules=extra_rules))

    return scanned, findings


def scan_git_history(
    repo_root: Path,
    *,
    strict: bool = True,
    extra_rules: Sequence[Tuple[str, re.Pattern[str]]] = (),
) -> Tuple[int, List[Finding]]:
    """Scan all commits reachable from any branch/tag in Git history for leaked secrets or PII."""
    try:
        rev_res = subprocess.run(
            ["git", "-C", str(repo_root), "rev-list", "--all"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        return 0, [
            Finding(
                severity="HIGH",
                category="HISTORY",
                rule="git_rev_list_failed",
                path=".git",
                line=0,
                masked_match="rev-list",
                detail=exc.stderr.strip() or "Failed to enumerate git commits",
            )
        ]

    commits = [c.strip() for c in rev_res.stdout.splitlines() if c.strip()]
    findings: List[Finding] = []
    for sha in commits:
        show_res = subprocess.run(
            ["git", "-C", str(repo_root), "show", "--format=medium", "--no-color", sha],
            capture_output=True,
            text=True,
            errors="ignore",
        )
        if show_res.returncode != 0:
            continue
        current_file = "<commit-message>"
        added_lines_by_file: dict[str, List[str]] = {current_file: []}
        for raw_line in show_res.stdout.splitlines():
            if raw_line.startswith("+++ b/"):
                current_file = raw_line[6:]
                added_lines_by_file.setdefault(current_file, [])
            elif raw_line.startswith("+") and not raw_line.startswith("+++"):
                added_lines_by_file.setdefault(current_file, []).append(raw_line[1:])
            elif current_file == "<commit-message>" and not raw_line.startswith(("diff ", "--- ", "index ", "@@ ")):
                added_lines_by_file[current_file].append(raw_line)

        for fpath, lines in added_lines_by_file.items():
            if not lines:
                continue
            chunk = "\n".join(lines)
            for hit in scan_text(chunk, fpath, strict=strict, commit=sha[:8], extra_rules=extra_rules):
                findings.append(dataclasses.replace(hit, category="HISTORY"))

    return len(commits), findings


def _format_report(
    mode: str,
    scanned_files: int,
    findings: Sequence[Finding],
    scanned_commits: int = 0,
    history_findings: Sequence[Finding] = (),
) -> str:
    all_hits = list(findings) + list(history_findings)
    if not all_hits:
        extra = f", {scanned_commits} commits clean" if scanned_commits else ""
        return f"[OK] Desensitization audit ({mode}) passed: 0 hits across {scanned_files} files{extra}."

    lines = [
        f"[FAIL] Desensitization audit ({mode}) found {len(all_hits)} hit(s) "
        f"({len(findings)} workspace across {scanned_files} files"
        + (f", {len(history_findings)} git-history across {scanned_commits} commits" if scanned_commits else "")
        + "):"
    ]
    by_cat: dict[str, int] = {}
    for item in all_hits:
        by_cat[item.category] = by_cat.get(item.category, 0) + 1
    summary_parts = ", ".join(f"{k}={v}" for k, v in sorted(by_cat.items()))
    lines.append(f"  Summary by category: {summary_parts}")

    for item in all_hits:
        loc = f"{item.path}:{item.line}" if item.line else item.path
        c_prefix = f"@{item.commit} " if item.commit else ""
        lines.append(
            f"  - [{item.severity}][{item.category}/{item.rule}] {c_prefix}{loc} -> {item.masked_match}"
        )
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Strict desensitization and secret scanner")
    parser.add_argument(
        "--mode",
        choices=("secret-guard", "core-public", "public-release"),
        default="secret-guard",
        help="Audit strictness scope (default: secret-guard)",
    )
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="Repository root to scan")
    parser.add_argument("--check-history", action="store_true", help="Also scan all reachable Git history")
    parser.add_argument("--blocklist-file", type=Path, default=None, help="Optional local private-term blocklist file")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    args = parser.parse_args(argv)

    extra_rules = load_local_blocklist(args.blocklist_file)
    scanned_files, findings = scan_repository(
        args.root.resolve(),
        mode=args.mode,
        extra_rules=extra_rules,
    )
    scanned_commits = 0
    history_findings: List[Finding] = []
    if args.check_history:
        scanned_commits, history_findings = scan_git_history(
            args.root.resolve(),
            strict=(args.mode != "secret-guard"),
            extra_rules=extra_rules,
        )

    if args.json:
        payload = {
            "mode": args.mode,
            "scanned_files": scanned_files,
            "scanned_commits": scanned_commits,
            "findings": [f.to_dict() for f in findings],
            "history_findings": [f.to_dict() for f in history_findings],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(_format_report(args.mode, scanned_files, findings, scanned_commits, history_findings))

    return 1 if (findings or history_findings) else 0


if __name__ == "__main__":
    sys.exit(main())
