#!/usr/bin/env python3
"""Model candidate chain resolution & pre-output failover classification engine."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Union

TRANSIENT_ERR_MARKERS = (
    "oauth2:",
    "internal_failure",
    "token refresh",
    "error getting token source",
    "not logged into antigravity",
    "context summarization: request failed",
    "checkpoint_empty_summary",
    "502 bad gateway",
    "bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
    "gateway timeout",
    "status 502",
    "status 503",
    "status 504",
    "http 502",
    "http 503",
    "http 504",
    "code = unavailable",
    "connection reset by peer",
    "connection refused",
    "connection timed out",
    "read timed out",
    "remote end closed connection",
    "broken pipe",
    "tls handshake timeout",
    "unexpected eof",
    "upstream error",
)

FAILOVER_QUOTA_OR_MODEL_MARKERS = (
    "quota",
    "exhausted",
    "resource_exhausted",
    "insufficient_quota",
    "exceeded your current quota",
    "billing_hard_limit_reached",
    "429",
    "too many requests",
    "rate limit",
    "ratelimit",
    "rate_limit_exceeded",
    "insufficient",
    "payment required",
    "http 402",
    "status 402",
    "error 402",
    "invalid_api_key",
    "incorrect api key",
    "authentication_error",
    "no available channel",
    "overloaded",
    "capacity",
    "503",
    "unavailable",
    "model_not_found",
    "model not found",
    "does not exist",
    "unknown model",
    "unsupported model",
    "deadline exceeded",
    "timed out",
    "timeout",
)


def is_transient_agy_error(err_text: Optional[str]) -> bool:
    """Return True if `err_text` indicates a transient auth/network/summarization error."""
    if not err_text:
        return False
    low = str(err_text).lower()
    return any(m in low for m in TRANSIENT_ERR_MARKERS)


def is_summarization_error(err_text: Optional[str]) -> bool:
    """Return True if `err_text` indicates a pre-invocation context summarization failure."""
    if not err_text:
        return False
    low = str(err_text).lower()
    return ("context summarization" in low) or ("checkpoint_empty_summary" in low)


def is_quota_or_model_error(err_text: Optional[str]) -> bool:
    """Return True if `err_text` indicates quota exhaustion, rate limiting, overload, or unavailable model."""
    if not err_text:
        return False
    low = str(err_text).lower()
    return any(m in low for m in FAILOVER_QUOTA_OR_MODEL_MARKERS)


def is_failover_eligible_error(err_text: Optional[str]) -> bool:
    """Return True when a pre-output failure may safely trigger fallback to the next candidate model.

    Covers quota exhaustion (`quota`, `exhausted`, `resource_exhausted`, `429`, `rate limit`,
    `insufficient`), model unavailability/overload (`overloaded`, `503`, `unavailable`,
    `model_not_found`), timeout/auth pre-invocation failures, and `is_transient_agy_error`.
    """
    if not err_text:
        return False
    return is_quota_or_model_error(err_text) or is_transient_agy_error(err_text)


def parse_fallback_models(raw: Optional[Union[str, Sequence[str]]]) -> List[str]:
    """Parse comma/whitespace-separated or sequence fallback models into a deduplicated ordered list."""
    if raw is None:
        return []
    if isinstance(raw, str):
        tokens: Iterable[str] = raw.replace(";", ",").replace(" ", ",").split(",")
    else:
        tokens = [str(x) for x in raw]

    out: List[str] = []
    seen = set()
    for tok in tokens:
        m = tok.strip()
        if not m or m.lower() in ("off", "none", "null", "default", "disable", "disabled"):
            continue
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def resolve_model_chain(
    primary_model: Optional[str],
    *,
    scope_fallback: Optional[Union[str, Sequence[str]]] = None,
    env_fallback: Optional[Union[str, Sequence[str]]] = "",
    bot_default_model: Optional[str] = None,
) -> List[Optional[str]]:
    """Build the ordered candidate model chain `[primary, fallback1, fallback2, ...]`.

    Semantics for `scope_fallback`:
    - `None`: inherit `env_fallback` (`AGY_TG_FALLBACK_MODELS`).
    - `[]` (empty list): explicitly disabled (`off`) for this scope -> `[effective_primary]`.
    - non-empty list/str: use per-scope override list.
    """
    eff_primary = (primary_model or "").strip() or (bot_default_model or "").strip() or None
    chain: List[Optional[str]] = [eff_primary]

    if scope_fallback is not None:
        fallbacks = parse_fallback_models(scope_fallback)
    else:
        fallbacks = parse_fallback_models(env_fallback)

    for fb in fallbacks:
        if fb != eff_primary and fb not in chain:
            chain.append(fb)
    return chain


def can_switch_model_safely(delivered_steps: int, attempt_tools: int) -> bool:
    """Ironclad safety invariant: model failover is ONLY allowed before first output and before any tool run."""
    return int(delivered_steps) == 0 and int(attempt_tools) == 0


def describe_fallback_config(
    scope_fallback: Optional[Union[str, Sequence[str]]],
    env_fallback: Optional[Union[str, Sequence[str]]],
) -> str:
    """Return a concise human-readable description of active fallback configuration."""
    if scope_fallback is not None:
        parsed = parse_fallback_models(scope_fallback)
        if not parsed:
            return "off (作用域已禁用)"
        return " → ".join(parsed) + " (作用域覆盖)"
    env_parsed = parse_fallback_models(env_fallback)
    if not env_parsed:
        return "off (未配置)"
    return " → ".join(env_parsed) + " (环境变量)"


def format_failover_exhausted_error(
    attempted_models: Sequence[Optional[str]],
    last_error: str,
) -> str:
    """Format a clear terminal error when all primary + fallback candidate models failed."""
    labels = [str(m or "(default)") for m in attempted_models]
    chain_str = " → ".join(labels) if labels else "(default)"
    err_snip = (last_error or "(no details)").strip()
    if len(attempted_models) > 1:
        return f"⚠️ 主模型与全部备用模型均调用失败（已尝试：{chain_str}）：\n{err_snip}"
    return f"⚠️ agy ERROR: {err_snip}"
