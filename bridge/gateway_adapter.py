#!/usr/bin/env python3
"""Multi-gateway OpenAI-compatible adapter & per-route loopback proxy for `agy`.

Zero-side-effect module on import: does not create runtime files, open listening
sockets, or import `bridge.py`.

Supports:
1. Embedded in-process loopback HTTP server (`GatewayAdapterServer`) bound to
   `127.0.0.1:0` for `bridge/bridge.py`, issuing isolated per-route tokens:
   `http://127.0.0.1:<port>/g/<route_token>/v1`
2. Standalone CLI server (`python3 bridge/gateway_adapter.py serve ...`)
3. Multi-dialect request normalization (`cpa`, `openai_strict`, `zhipu`, `ark`,
   `deepseek`, `litellm`, `new_api`, `openrouter`, `openai_2api`)
4. Adaptive HTTP 400 fallback (pre-first-byte quirk detection & transparent retry)
5. HTTP JSON -> SSE conversion and SSE `tool_calls` / `finish_reason` repair
"""

from __future__ import annotations

import argparse
from collections import OrderedDict
import copy
import dataclasses
import fnmatch
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import math
import os
from pathlib import Path
import queue
import re
import secrets
import shlex
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlparse

import requests

logger = logging.getLogger("agy.gateway_adapter")

VALID_EFFORT_MODES = ("body", "model_paren", "none")
VALID_MAX_TOKENS_FIELDS = ("max_completion_tokens", "max_tokens", "omit")
VALID_EFFORTS = ("low", "medium", "high", "xhigh", "max")
LOCAL_PROXY_API_KEY = "agy-local-proxy-token"

# Known Google Antigravity native model prefixes (used when live `agy models` list is unavailable)
NATIVE_GOOGLE_PREFIXES: Tuple[str, ...] = (
    "gemini-",
    "claude-opus-5-5",
    "claude-sonnet-5-5",
    "gpt-oss-120b",
)

DIALECT_PRESETS: Dict[str, Dict[str, Any]] = {
    "cpa": {
        "supports_reasoning_effort": True,
        "effort_mode": "body",
        "flatten_system_content": False,
        "strip_stream_options": False,
        "max_tokens_field": "max_completion_tokens",
        "max_tokens_cap": None,
        "adaptive_400_fallback": True,
    },
    "openai_strict": {
        "supports_reasoning_effort": False,
        "effort_mode": "none",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 16384,
        "adaptive_400_fallback": True,
    },
    "zhipu": {
        "supports_reasoning_effort": False,
        "effort_mode": "none",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 16384,
        "adaptive_400_fallback": True,
    },
    "ark": {
        "supports_reasoning_effort": True,
        "effort_mode": "body",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 16384,
        "adaptive_400_fallback": True,
    },
    "deepseek": {
        "supports_reasoning_effort": False,
        "effort_mode": "none",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 8192,
        "adaptive_400_fallback": True,
    },
    "litellm": {
        "supports_reasoning_effort": True,
        "effort_mode": "body",
        "flatten_system_content": False,
        "strip_stream_options": False,
        "max_tokens_field": "max_completion_tokens",
        "max_tokens_cap": None,
        "adaptive_400_fallback": True,
    },
    "new_api": {
        "supports_reasoning_effort": True,
        "effort_mode": "body",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 16384,
        "adaptive_400_fallback": True,
    },
    "openrouter": {
        "supports_reasoning_effort": True,
        "effort_mode": "body",
        "flatten_system_content": False,
        "strip_stream_options": False,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": None,
        "adaptive_400_fallback": True,
    },
    "openai_2api": {
        "supports_reasoning_effort": True,
        "effort_mode": "model_paren",
        "flatten_system_content": True,
        "strip_stream_options": True,
        "max_tokens_field": "max_tokens",
        "max_tokens_cap": 16384,
        "adaptive_400_fallback": True,
    },
}

_GW_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


@dataclasses.dataclass
class GatewayConfig:
    """Normalized configuration for a single OpenAI-compatible upstream gateway."""

    id: str
    name: str
    base_url: str
    dialect: str = "openai_strict"
    api_key: str = ""
    api_key_env: str = ""
    api_key_cmd: Any = None
    enabled: bool = True
    include_models: Tuple[str, ...] = ()
    exclude_models: Tuple[str, ...] = ()
    max_tokens_cap: Optional[int] = 16384
    supports_reasoning_effort: bool = False
    effort_mode: str = "none"
    flatten_system_content: bool = True
    strip_stream_options: bool = True
    max_tokens_field: str = "max_tokens"
    adaptive_400_fallback: bool = True
    models: Tuple[str, ...] = ()
    extra_headers: Dict[str, str] = dataclasses.field(default_factory=dict)
    timeout_s: float = 300.0

    def fingerprint(self) -> str:
        """Return a stable non-secret fingerprint for session invalidation checks."""
        payload = {
            "id": self.id,
            "base_url": self.base_url,
            "dialect": self.dialect,
            "enabled": self.enabled,
            "max_tokens_cap": self.max_tokens_cap,
            "supports_reasoning_effort": self.supports_reasoning_effort,
            "effort_mode": self.effort_mode,
            "flatten_system_content": self.flatten_system_content,
            "strip_stream_options": self.strip_stream_options,
            "max_tokens_field": self.max_tokens_field,
        }
        return hashlib.sha1(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:12]

    def __repr__(self) -> str:
        return (
            f"GatewayConfig(id={self.id!r}, name={self.name!r}, "
            f"base_url={self.base_url!r}, dialect={self.dialect!r}, enabled={self.enabled!r})"
        )


@dataclasses.dataclass(frozen=True)
class ModelResolution:
    """Resolved execution target for a user/scope model selection."""

    kind: str  # "native" | "gateway"
    raw_model: Optional[str]
    gateway_id: Optional[str] = None
    upstream_model: Optional[str] = None
    gateway: Optional[GatewayConfig] = None

    @property
    def is_gateway(self) -> bool:
        return self.kind == "gateway" and self.gateway is not None and bool(self.upstream_model)


@dataclasses.dataclass(frozen=True)
class RouteInfo:
    """Registered per-route loopback endpoint bound to `(gateway_id, upstream_model, effort)`."""

    token: str
    url: str
    local_api_key: str
    gateway_id: str
    upstream_model: str
    effort: Optional[str] = None


def _as_str_tuple(raw: Any) -> Tuple[str, ...]:
    if not raw:
        return ()
    if isinstance(raw, str):
        items = [x.strip() for x in raw.split(",") if x.strip()]
    elif isinstance(raw, (list, tuple)):
        items = [str(x).strip() for x in raw if str(x).strip()]
    else:
        return ()
    return tuple(items)


def _as_bool(val: Any, default: bool) -> bool:
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return default


def default_gateways_file_path() -> Path:
    return Path.home() / ".config" / "agy-tg-bridge" / "gateways.json"


def _normalize_gateway_entry(raw: Dict[str, Any], fallback_id: str = "") -> GatewayConfig:
    if not isinstance(raw, dict):
        raise ValueError("Gateway entry must be a JSON object")
    gw_id = str(raw.get("id") or fallback_id or "").strip().lower()
    if not gw_id:
        raise ValueError("Gateway entry missing required 'id'")
    if ":" in gw_id or "/" in gw_id or not _GW_ID_RE.match(gw_id):
        raise ValueError(f"Invalid gateway id {gw_id!r}; expected [a-z0-9][a-z0-9_-]{{0,31}}")

    base_url = str(raw.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        raise ValueError(f"Gateway {gw_id!r} missing required 'base_url'")
    parsed_url = urlparse(base_url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
        raise ValueError(f"Gateway {gw_id!r} has invalid base_url (expected http/https URL)")

    dialect = str(raw.get("dialect") or "openai_strict").strip().lower()
    if dialect not in DIALECT_PRESETS:
        raise ValueError(f"Gateway {gw_id!r} uses unknown dialect {dialect!r}")
    preset = DIALECT_PRESETS[dialect]

    supports_effort = _as_bool(raw.get("supports_reasoning_effort"), preset["supports_reasoning_effort"])
    effort_mode = str(raw.get("effort_mode") or preset["effort_mode"]).strip().lower()
    if effort_mode not in VALID_EFFORT_MODES:
        raise ValueError(f"Gateway {gw_id!r} has invalid effort_mode {effort_mode!r}")

    max_tokens_field = str(raw.get("max_tokens_field") or preset["max_tokens_field"]).strip()
    if max_tokens_field not in VALID_MAX_TOKENS_FIELDS:
        raise ValueError(f"Gateway {gw_id!r} has invalid max_tokens_field {max_tokens_field!r}")

    raw_cap = raw.get("max_tokens_cap", preset["max_tokens_cap"])
    max_tokens_cap: Optional[int]
    if raw_cap in (None, "", 0, "0"):
        max_tokens_cap = None
    else:
        max_tokens_cap = int(raw_cap)
        if max_tokens_cap <= 0:
            max_tokens_cap = None

    extra_headers_raw = raw.get("extra_headers") or {}
    extra_headers: Dict[str, str] = {}
    if isinstance(extra_headers_raw, dict):
        for hk, hv in extra_headers_raw.items():
            if hk and hv is not None:
                extra_headers[str(hk)] = str(hv)

    timeout_raw = raw.get("timeout_s", 300.0)
    timeout_s = max(5.0, float(timeout_raw if timeout_raw is not None else 300.0))

    return GatewayConfig(
        id=gw_id,
        name=str(raw.get("name") or gw_id).strip() or gw_id,
        base_url=base_url,
        dialect=dialect,
        api_key=str(raw.get("api_key") or "").strip(),
        api_key_env=str(raw.get("api_key_env") or "").strip(),
        api_key_cmd=raw.get("api_key_cmd"),
        enabled=_as_bool(raw.get("enabled"), True),
        include_models=_as_str_tuple(raw.get("include_models")),
        exclude_models=_as_str_tuple(raw.get("exclude_models")),
        max_tokens_cap=max_tokens_cap,
        supports_reasoning_effort=supports_effort,
        effort_mode=effort_mode,
        flatten_system_content=_as_bool(raw.get("flatten_system_content"), preset["flatten_system_content"]),
        strip_stream_options=_as_bool(raw.get("strip_stream_options"), preset["strip_stream_options"]),
        max_tokens_field=max_tokens_field,
        adaptive_400_fallback=_as_bool(raw.get("adaptive_400_fallback"), preset["adaptive_400_fallback"]),
        models=_as_str_tuple(raw.get("models")),
        extra_headers=extra_headers,
        timeout_s=timeout_s,
    )


def parse_gateways_payload(data: Any) -> Dict[str, GatewayConfig]:
    """Parse parsed JSON (`list` or `{"gateways": ...}` or `{"id": {...}}`) into ordered `{id: GatewayConfig}`."""
    out: Dict[str, GatewayConfig] = {}
    if data is None:
        return out
    if isinstance(data, dict) and isinstance(data.get("gateways"), list):
        items: Sequence[Any] = data["gateways"]
        for item in items:
            cfg = _normalize_gateway_entry(item)
            out[cfg.id] = cfg
        return out
    if isinstance(data, dict) and isinstance(data.get("gateways"), dict):
        for gid, item in data["gateways"].items():
            cfg = _normalize_gateway_entry(item, fallback_id=str(gid))
            out[cfg.id] = cfg
        return out
    if isinstance(data, list):
        for item in data:
            cfg = _normalize_gateway_entry(item)
            out[cfg.id] = cfg
        return out
    if isinstance(data, dict):
        if "base_url" in data or "id" in data:
            cfg = _normalize_gateway_entry(data)
            out[cfg.id] = cfg
            return out
        for gid, item in data.items():
            cfg = _normalize_gateway_entry(item, fallback_id=str(gid))
            out[cfg.id] = cfg
        return out
    raise ValueError("Gateways configuration must be a JSON object or array")


def validate_gateways_config(
    *,
    gateways_file: Optional[str] = None,
    gateways_json: Optional[str] = None,
) -> Tuple[bool, Dict[str, GatewayConfig], List[str], Optional[str]]:
    """Validate gateway config without raising or leaking secret values.

    Returns `(ok, gateways_map, errors, source_desc)`.
    """
    env_json = (gateways_json if gateways_json is not None else os.environ.get("AGY_TG_GATEWAYS_JSON", "")).strip()
    explicit_file = (
        gateways_file if gateways_file is not None else os.environ.get("AGY_TG_GATEWAYS_FILE", "")
    ).strip()

    errors: List[str] = []
    parsed_map: Dict[str, GatewayConfig] = {}
    source_desc: Optional[str] = None

    if explicit_file:
        p = Path(os.path.expandvars(os.path.expanduser(explicit_file)))
        source_desc = str(p)
        if not p.is_file():
            errors.append(f"gateways file not found: {p}")
        else:
            try:
                raw_obj = json.loads(p.read_text(encoding="utf-8"))
                parsed_map.update(parse_gateways_payload(raw_obj))
            except Exception as exc:
                errors.append(f"invalid gateways file ({p}): {type(exc).__name__}: {exc}")

    if env_json:
        source_desc = "AGY_TG_GATEWAYS_JSON" if not source_desc else f"{source_desc} + AGY_TG_GATEWAYS_JSON"
        try:
            raw_obj = json.loads(env_json)
            parsed_map.update(parse_gateways_payload(raw_obj))
        except Exception as exc:
            errors.append(f"invalid AGY_TG_GATEWAYS_JSON: {type(exc).__name__}: {exc}")

    if not explicit_file and not env_json:
        default_p = default_gateways_file_path()
        if default_p.is_file():
            source_desc = str(default_p)
            try:
                raw_obj = json.loads(default_p.read_text(encoding="utf-8"))
                parsed_map.update(parse_gateways_payload(raw_obj))
            except Exception as exc:
                errors.append(f"invalid gateways file ({default_p}): {type(exc).__name__}: {exc}")

    return (len(errors) == 0), parsed_map, errors, source_desc


def load_gateways_config(
    *,
    gateways_file: Optional[str] = None,
    gateways_json: Optional[str] = None,
) -> Dict[str, GatewayConfig]:
    """Load configured gateways safely; returns `{}` on missing/invalid config."""
    ok, parsed, errors, _src = validate_gateways_config(
        gateways_file=gateways_file,
        gateways_json=gateways_json,
    )
    if not ok and errors:
        logger.warning("Gateway configuration validation errors: %s", "; ".join(errors))
    return parsed


def build_upstream_url(base_url: str, subpath: str) -> str:
    """Join `base_url` with OpenAI-compatible endpoint `subpath` without forcing duplicate `/v1`."""
    clean_base = (base_url or "").strip().rstrip("/")
    sub = "/" + (subpath or "").lstrip("/")
    parsed = urlparse(clean_base)
    if parsed.path.strip("/"):
        return clean_base + sub
    return clean_base + "/v1" + sub


def model_matches_filters(
    model_id: str,
    include_patterns: Sequence[str] = (),
    exclude_patterns: Sequence[str] = (),
) -> bool:
    """Return True if `model_id` satisfies optional include/exclude glob patterns."""
    mid = (model_id or "").strip()
    if not mid:
        return False
    if include_patterns:
        if not any(fnmatch.fnmatchcase(mid, pat) for pat in include_patterns):
            return False
    if exclude_patterns:
        if any(fnmatch.fnmatchcase(mid, pat) for pat in exclude_patterns):
            return False
    return True


def is_native_google_slug(model_id: Optional[str], native_models: Sequence[Tuple[str, str]] = ()) -> bool:
    """Return True if `model_id` is `None` or identifies a native Google Antigravity model."""
    if not model_id:
        return True
    mid = str(model_id).strip()
    if not mid or mid.lower() in ("default", "none", "reset", "clear"):
        return True
    if mid.startswith("gw:"):
        return False
    if native_models:
        native_slugs = {slug for slug, _ in native_models}
        if mid in native_slugs:
            return True
    if "/" in mid:
        return False
    low = mid.lower()
    return any(low.startswith(pref) for pref in NATIVE_GOOGLE_PREFIXES)


def parse_gateway_model_ref(raw_model: Optional[str]) -> Optional[Tuple[str, str]]:
    """Parse explicit `gw:<gateway_id>:<upstream_model>` ref into `(gateway_id, upstream_model)`."""
    if not raw_model:
        return None
    s = str(raw_model).strip()
    if not s.startswith("gw:"):
        return None
    rest = s[3:]
    if ":" not in rest:
        return None
    gw_id, upstream = rest.split(":", 1)
    gw_id = gw_id.strip().lower()
    upstream = upstream.strip()
    if not gw_id or not upstream:
        return None
    return gw_id, upstream


def format_gateway_model_ref(gateway_id: str, upstream_model: str) -> str:
    """Format an explicit unambiguous gateway model reference `gw:<gateway_id>:<upstream_model>`."""
    return f"gw:{gateway_id.strip().lower()}:{upstream_model.strip()}"


def resolve_model_target(
    model_id: Optional[str],
    *,
    gateways: Dict[str, GatewayConfig],
    native_models: Sequence[Tuple[str, str]] = (),
    gateway_catalogs: Optional[Dict[str, Sequence[str]]] = None,
) -> ModelResolution:
    """Resolve `model_id` into either Google native execution or a specific gateway + upstream model.

    Handles model names containing `/` (e.g. `team/gpt-6.1-sol`) without naive `split('/', 1)`.
    """
    raw = (model_id or "").strip() or None
    if not raw or raw.lower() in ("default", "none", "reset", "clear"):
        return ModelResolution(kind="native", raw_model=None, upstream_model=None)

    enabled_gws = {gid: gw for gid, gw in (gateways or {}).items() if gw.enabled}

    explicit = parse_gateway_model_ref(raw)
    if explicit is not None:
        gid, upstream = explicit
        gw = enabled_gws.get(gid) or gateways.get(gid)
        if gw is not None and gw.enabled:
            return ModelResolution(
                kind="gateway",
                raw_model=raw,
                gateway_id=gw.id,
                upstream_model=upstream,
                gateway=gw,
            )
        return ModelResolution(kind="native", raw_model=raw, upstream_model=upstream)

    if is_native_google_slug(raw, native_models=native_models):
        return ModelResolution(kind="native", raw_model=raw, upstream_model=raw)

    if not enabled_gws:
        return ModelResolution(kind="native", raw_model=raw, upstream_model=raw)

    catalogs = gateway_catalogs or {}

    # 1. Exact match in probed or static gateway model catalogs (respecting filters)
    catalog_matches: List[GatewayConfig] = []
    for gid, gw in enabled_gws.items():
        known = list(catalogs.get(gid) or ()) + [m for m in gw.models if m not in (catalogs.get(gid) or ())]
        filtered = [m for m in known if model_matches_filters(m, gw.include_models, gw.exclude_models)]
        if raw in filtered:
            catalog_matches.append(gw)
    if len(catalog_matches) == 1:
        gw = catalog_matches[0]
        return ModelResolution(
            kind="gateway",
            raw_model=raw,
            gateway_id=gw.id,
            upstream_model=raw,
            gateway=gw,
        )
    if len(catalog_matches) > 1:
        gw = catalog_matches[0]
        return ModelResolution(
            kind="gateway",
            raw_model=raw,
            gateway_id=gw.id,
            upstream_model=raw,
            gateway=gw,
        )

    # 2. Specific include_models glob match (excluding broad `*`)
    include_matches: List[GatewayConfig] = []
    for gw in enabled_gws.values():
        specific_inc = [p for p in gw.include_models if p not in ("*", "*/*")]
        if specific_inc and model_matches_filters(raw, specific_inc, gw.exclude_models):
            include_matches.append(gw)
    if len(include_matches) == 1:
        gw = include_matches[0]
        return ModelResolution(
            kind="gateway",
            raw_model=raw,
            gateway_id=gw.id,
            upstream_model=raw,
            gateway=gw,
        )

    # 3. Fallback when catalog is empty/offline and non-Google slug satisfies gateway filters
    non_excluded = [
        gw for gw in enabled_gws.values()
        if model_matches_filters(raw, gw.include_models, gw.exclude_models)
    ]
    if len(non_excluded) == 1:
        gw = non_excluded[0]
        return ModelResolution(
            kind="gateway",
            raw_model=raw,
            gateway_id=gw.id,
            upstream_model=raw,
            gateway=gw,
        )

    return ModelResolution(kind="native", raw_model=raw, upstream_model=raw)


def _flatten_content_parts(content: Any) -> Any:
    if not isinstance(content, list):
        return content
    text_parts: List[str] = []
    for part in content:
        if isinstance(part, str):
            text_parts.append(part)
        elif isinstance(part, dict):
            ptype = part.get("type")
            if ptype == "text" or ("text" in part and ptype is None):
                text_parts.append(str(part.get("text") or ""))
            else:
                # Non-text part (e.g. image_url): preserve original list untouched
                return content
        else:
            return content
    return "\n".join(text_parts)


def transform_chat_request(
    payload: Dict[str, Any],
    gateway: GatewayConfig,
    *,
    upstream_model: Optional[str] = None,
    effort: Optional[str] = None,
    quirks: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Normalize an OpenAI `/chat/completions` JSON request body according to dialect & quirks."""
    out = copy.deepcopy(payload) if isinstance(payload, dict) else {}
    q = quirks or {}

    flatten_sys = bool(q.get("flatten_system_content", gateway.flatten_system_content))
    strip_stream_opts = bool(q.get("strip_stream_options", gateway.strip_stream_options))
    max_tokens_field = str(q.get("max_tokens_field", gateway.max_tokens_field))
    max_tokens_cap = q.get("max_tokens_cap", gateway.max_tokens_cap)
    supports_effort = bool(q.get("supports_reasoning_effort", gateway.supports_reasoning_effort))
    effort_mode = str(q.get("effort_mode", gateway.effort_mode))

    target_model = (upstream_model or str(out.get("model") or "")).strip()
    eff = (effort or "").strip().lower() or None

    if eff and supports_effort and effort_mode != "none":
        if effort_mode == "body":
            if "reasoning_effort" not in out:
                out["reasoning_effort"] = eff
        elif effort_mode == "model_paren":
            out.pop("reasoning_effort", None)
            if target_model and not target_model.endswith(f"({eff})"):
                target_model = f"{target_model}({eff})"
    else:
        if not supports_effort or effort_mode == "none":
            out.pop("reasoning_effort", None)

    if target_model:
        out["model"] = target_model

    if flatten_sys and isinstance(out.get("messages"), list):
        for msg in out["messages"]:
            if not isinstance(msg, dict):
                continue
            if msg.get("role") in ("system", "developer") and isinstance(msg.get("content"), list):
                msg["content"] = _flatten_content_parts(msg["content"])

    if strip_stream_opts:
        out.pop("stream_options", None)

    raw_max = out.get("max_completion_tokens")
    if raw_max is None:
        raw_max = out.get("max_tokens")
    out.pop("max_completion_tokens", None)
    out.pop("max_tokens", None)

    if raw_max is not None and max_tokens_field != "omit":
        if not isinstance(raw_max, bool) and (not isinstance(raw_max, float) or math.isfinite(raw_max)):
            try:
                tok_val: Optional[int] = int(raw_max)
            except (TypeError, ValueError, OverflowError):
                tok_val = None
            if tok_val is not None:
                if (
                    max_tokens_cap is not None
                    and not isinstance(max_tokens_cap, bool)
                    and (not isinstance(max_tokens_cap, float) or math.isfinite(max_tokens_cap))
                ):
                    try:
                        cap_val = int(max_tokens_cap)
                        if cap_val > 0:
                            tok_val = min(tok_val, cap_val)
                    except (TypeError, ValueError, OverflowError):
                        pass
                if max_tokens_field == "max_completion_tokens":
                    out["max_completion_tokens"] = tok_val
                elif max_tokens_field == "max_tokens":
                    out["max_tokens"] = tok_val

    return out


def infer_quirk_from_400(
    error_text: str,
    current_payload: Dict[str, Any],
    current_quirks: Dict[str, Any],
    gateway: GatewayConfig,
) -> Optional[Dict[str, Any]]:
    """Inspect an upstream HTTP 400 body and return updated quirk overrides if recoverable."""
    low = (error_text or "").lower()
    if not low:
        return None

    updated = dict(current_quirks)
    changed = False

    # 1. System / message content must be a string
    if (
        "must be a string" in low
        or "expected a string" in low
        or ("messages[" in low and "content" in low and "string" in low)
    ) and not updated.get("flatten_system_content", gateway.flatten_system_content):
        updated["flatten_system_content"] = True
        changed = True

    # 2. stream_options rejected
    if "stream_options" in low and (
        "unknown" in low
        or "extra inputs" in low
        or "not permitted" in low
        or "unrecognized" in low
        or "unsupported" in low
        or "invalid" in low
    ):
        if not updated.get("strip_stream_options", gateway.strip_stream_options):
            updated["strip_stream_options"] = True
            changed = True

    # 3. max_completion_tokens unknown / unsupported -> rewrite to max_tokens (or omit)
    if "max_completion_tokens" in low and (
        "unknown" in low
        or "extra inputs" in low
        or "not permitted" in low
        or "unrecognized" in low
        or "unsupported" in low
    ):
        cur_field = updated.get("max_tokens_field", gateway.max_tokens_field)
        if cur_field == "max_completion_tokens":
            updated["max_tokens_field"] = "max_tokens"
            changed = True
        elif cur_field != "omit":
            updated["max_tokens_field"] = "omit"
            changed = True

    # 4. max_tokens / max_completion_tokens out of range / too large
    if ("max_tokens" in low or "max_completion_tokens" in low) and (
        "too large" in low
        or "exceed" in low
        or "less than or equal" in low
        or "must be <=" in low
        or "must be at most" in low
        or "maximum" in low
        or "range" in low
        or "<=" in low
        or "invalid max_tokens" in low
    ):
        cur_val = current_payload.get("max_completion_tokens") or current_payload.get("max_tokens")
        parsed_limit: Optional[int] = None
        for pat in (
            r"<=\s*(\d+)",
            r"\[\s*1\s*,\s*(\d+)\s*\]",
            r"at most\s*(\d+)",
            r"maximum(?:\s+(?:is|of|:))?\s*(\d+)",
            r"max(?:imum)?\s*[:=]\s*(\d+)",
        ):
            m = re.search(pat, low)
            if m:
                try:
                    cand = int(m.group(1))
                    if 64 <= cand <= 1_000_000:
                        parsed_limit = cand
                        break
                except ValueError:
                    pass
        if parsed_limit is None:
            if isinstance(cur_val, int) and cur_val > 8192:
                parsed_limit = 8192
            elif isinstance(cur_val, int) and cur_val > 4096:
                parsed_limit = 4096
            else:
                parsed_limit = 4096
        prev_cap = updated.get("max_tokens_cap", gateway.max_tokens_cap)
        prev_int = int(prev_cap) if prev_cap is not None else None
        if prev_int is None or parsed_limit < prev_int:
            next_cap = parsed_limit
        elif parsed_limit > 1024:
            next_cap = max(1024, parsed_limit // 2)
        else:
            next_cap = prev_int
        if prev_int is None or next_cap < prev_int:
            updated["max_tokens_cap"] = next_cap
            changed = True

    # 5. reasoning_effort rejected
    if "reasoning_effort" in low and (
        "unknown" in low
        or "extra inputs" in low
        or "not permitted" in low
        or "unrecognized" in low
        or "unsupported" in low
    ):
        if updated.get("supports_reasoning_effort", gateway.supports_reasoning_effort):
            updated["supports_reasoning_effort"] = False
            updated["effort_mode"] = "none"
            changed = True

    return updated if changed else None


def _normalize_tool_calls_list(
    tool_calls: List[Any],
    *,
    seen_ids: Optional[Dict[str, int]] = None,
    next_idx_box: Optional[List[int]] = None,
    last_idx_box: Optional[List[int]] = None,
) -> List[Any]:
    out: List[Any] = []
    for pos, tc in enumerate(tool_calls):
        if not isinstance(tc, dict):
            out.append(tc)
            continue
        item = dict(tc)
        if "index" not in item or item["index"] is None:
            if seen_ids is not None and next_idx_box is not None and last_idx_box is not None:
                tc_id = item.get("id")
                if isinstance(tc_id, str) and tc_id:
                    if tc_id in seen_ids:
                        assigned = seen_ids[tc_id]
                    else:
                        assigned = next_idx_box[0]
                        seen_ids[tc_id] = assigned
                        next_idx_box[0] += 1
                    last_idx_box[0] = assigned
                    item["index"] = assigned
                else:
                    if last_idx_box[0] >= 0 and pos == 0:
                        item["index"] = last_idx_box[0]
                    else:
                        assigned = max(pos, next_idx_box[0])
                        last_idx_box[0] = assigned
                        item["index"] = assigned
            else:
                item["index"] = pos
        else:
            try:
                idx_int = int(item["index"])
                if seen_ids is not None and next_idx_box is not None and last_idx_box is not None:
                    tc_id = item.get("id")
                    if isinstance(tc_id, str) and tc_id:
                        seen_ids[tc_id] = idx_int
                    last_idx_box[0] = idx_int
                    if idx_int >= next_idx_box[0]:
                        next_idx_box[0] = idx_int + 1
            except (TypeError, ValueError, OverflowError):
                pass
        out.append(item)
    return out


def normalize_completion_json(data: Dict[str, Any]) -> Dict[str, Any]:
    """Fix non-streaming OpenAI chat completion JSON (`tool_calls` + `finish_reason == 'stop'`)."""
    if not isinstance(data, dict):
        return data
    out = copy.deepcopy(data)
    choices = out.get("choices")
    if not isinstance(choices, list):
        return out
    for ch in choices:
        if not isinstance(ch, dict):
            continue
        msg = ch.get("message")
        if isinstance(msg, dict) and isinstance(msg.get("tool_calls"), list) and msg["tool_calls"]:
            msg["tool_calls"] = _normalize_tool_calls_list(msg["tool_calls"])
            if ch.get("finish_reason") == "stop":
                ch["finish_reason"] = "tool_calls"
    return out


def json_completion_to_sse_chunks(data: Dict[str, Any]) -> List[bytes]:
    """Convert a non-streaming OpenAI JSON chat completion into compliant SSE `data:` frames."""
    norm = normalize_completion_json(data)
    cid = norm.get("id") or f"chatcmpl-{secrets.token_hex(8)}"
    created = norm.get("created") or int(time.time())
    model = norm.get("model") or "unknown"
    choices = norm.get("choices") or []
    usage = norm.get("usage")

    frames: List[bytes] = []

    def _emit(obj: Dict[str, Any]) -> None:
        frames.append(f"data: {json.dumps(obj, ensure_ascii=False)}\n\n".encode("utf-8"))

    for pos, ch in enumerate(choices):
        if not isinstance(ch, dict):
            continue
        c_idx = ch.get("index", pos)
        msg = ch.get("message") or {}
        role = msg.get("role") or "assistant"
        _emit(
            {
                "id": cid,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": c_idx, "delta": {"role": role}, "finish_reason": None}],
            }
        )
        reasoning = msg.get("reasoning_content")
        if reasoning is None:
            reasoning = msg.get("reasoning")
        if isinstance(reasoning, str) and reasoning:
            _emit(
                {
                    "id": cid,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": c_idx, "delta": {"reasoning_content": reasoning}, "finish_reason": None}],
                }
            )
        content = msg.get("content")
        if isinstance(content, str) and content:
            _emit(
                {
                    "id": cid,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": c_idx, "delta": {"content": content}, "finish_reason": None}],
                }
            )
        tcalls = msg.get("tool_calls")
        if isinstance(tcalls, list) and tcalls:
            norm_tcs = _normalize_tool_calls_list(tcalls)
            _emit(
                {
                    "id": cid,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": c_idx, "delta": {"tool_calls": norm_tcs}, "finish_reason": None}],
                }
            )
        finish_reason = ch.get("finish_reason") or ("tool_calls" if tcalls else "stop")
        _emit(
            {
                "id": cid,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": c_idx, "delta": {}, "finish_reason": finish_reason}],
            }
        )

    if usage is not None:
        _emit(
            {
                "id": cid,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [],
                "usage": usage,
            }
        )

    frames.append(b"data: [DONE]\n\n")
    return frames


class SSEStreamNormalizer:
    """Stateful line-by-line OpenAI SSE chunk normalizer."""

    def __init__(self) -> None:
        self._saw_tool_calls: Dict[int, bool] = {}
        self._seen_tc_ids: Dict[int, Dict[str, int]] = {}
        self._next_tc_idx: Dict[int, List[int]] = {}
        self._last_tc_idx: Dict[int, List[int]] = {}
        self.saw_done: bool = False
        self.saw_error: bool = False

    def process_line(self, raw_line: str) -> Optional[bytes]:
        line = raw_line.rstrip("\r\n")
        if not line:
            return None
        if line.startswith(":"):
            return (line + "\n\n").encode("utf-8")
        if not line.startswith("data:"):
            return None

        payload_str = line[5:].strip()
        if not payload_str:
            return None
        if payload_str == "[DONE]":
            self.saw_done = True
            return b"data: [DONE]\n\n"

        try:
            chunk = json.loads(payload_str)
        except Exception:
            return (line + "\n\n").encode("utf-8")

        if not isinstance(chunk, dict):
            return (line + "\n\n").encode("utf-8")

        if chunk.get("error") and not chunk.get("choices"):
            self.saw_error = True
            return f"data: UPSTREAM_ERROR {json.dumps(chunk, ensure_ascii=False)}\n\n".encode("utf-8")

        choices = chunk.get("choices")
        if isinstance(choices, list):
            for pos, ch in enumerate(choices):
                if not isinstance(ch, dict):
                    continue
                raw_c_idx = ch.get("index")
                if (
                    raw_c_idx is not None
                    and not isinstance(raw_c_idx, bool)
                    and (not isinstance(raw_c_idx, float) or math.isfinite(raw_c_idx))
                ):
                    try:
                        c_idx = int(raw_c_idx)
                    except (TypeError, ValueError, OverflowError):
                        c_idx = pos
                else:
                    c_idx = pos
                delta = ch.get("delta")
                if isinstance(delta, dict) and isinstance(delta.get("tool_calls"), list) and delta["tool_calls"]:
                    self._saw_tool_calls[c_idx] = True
                    seen_ids = self._seen_tc_ids.setdefault(c_idx, {})
                    next_box = self._next_tc_idx.setdefault(c_idx, [0])
                    last_box = self._last_tc_idx.setdefault(c_idx, [-1])
                    delta["tool_calls"] = _normalize_tool_calls_list(
                        delta["tool_calls"],
                        seen_ids=seen_ids,
                        next_idx_box=next_box,
                        last_idx_box=last_box,
                    )
                if ch.get("finish_reason") == "stop" and self._saw_tool_calls.get(c_idx):
                    ch["finish_reason"] = "tool_calls"

        return f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode("utf-8")

    def finalize(self) -> Optional[bytes]:
        if not self.saw_done and not self.saw_error:
            self.saw_done = True
            return b"data: [DONE]\n\n"
        return None


def _build_api_key_cmd_env() -> Dict[str, str]:
    """Build subprocess environment with user-local bin directories prepended to PATH."""
    env = dict(os.environ)
    raw_path = env.get("PATH", "")
    parts = [p for p in raw_path.split(os.pathsep) if p] if raw_path else []
    extra_dirs = [str(Path.home() / ".local" / "bin"), str(Path.home() / "bin")]
    prepended = [d for d in extra_dirs if d not in parts]
    if prepended:
        env["PATH"] = os.pathsep.join(prepended + parts)
    return env


def _gateway_runtime_fingerprint(gateway: GatewayConfig) -> str:
    """Hash gateway endpoint, dialect, and auth source metadata (never plaintext secrets)."""
    payload = {
        "id": gateway.id,
        "base_url": gateway.base_url,
        "dialect": gateway.dialect,
        "api_key_env": gateway.api_key_env,
        "api_key_cmd": gateway.api_key_cmd,
        "api_key_sha": hashlib.sha256(gateway.api_key.encode("utf-8")).hexdigest() if gateway.api_key else "",
        "effort_mode": gateway.effort_mode,
        "flatten_system_content": gateway.flatten_system_content,
        "strip_stream_options": gateway.strip_stream_options,
        "max_tokens_field": gateway.max_tokens_field,
        "max_tokens_cap": gateway.max_tokens_cap,
        "supports_reasoning_effort": gateway.supports_reasoning_effort,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


class GatewayRuntimeState:
    """Thread-safe secret cache, learned quirk table, and model catalog cache."""

    def __init__(self, *, catalog_ttl_s: float = 90.0, key_ttl_s: float = 300.0) -> None:
        self._lock = threading.Lock()
        self._key_cache: Dict[str, Tuple[float, str]] = {}
        self._quirks: Dict[str, Dict[str, Any]] = {}
        self._catalog_cache: Dict[str, Tuple[float, List[str]]] = {}
        self._config_hashes: Dict[str, str] = {}
        self.catalog_ttl_s = catalog_ttl_s
        self.key_ttl_s = key_ttl_s

    def _ensure_gateway_fresh_locked(self, gateway: GatewayConfig) -> str:
        cfg_hash = _gateway_runtime_fingerprint(gateway)
        prev_hash = self._config_hashes.get(gateway.id)
        if prev_hash is not None and prev_hash != cfg_hash:
            self._quirks.pop(gateway.id, None)
            self._key_cache.pop(gateway.id, None)
            self._catalog_cache.pop(gateway.id, None)
        self._config_hashes[gateway.id] = cfg_hash
        return cfg_hash

    def sync_gateways(self, gateways: Dict[str, GatewayConfig]) -> None:
        """Invalidate cached quirks, keys, and catalogs for changed or removed gateways."""
        gws = gateways or {}
        with self._lock:
            for gid in list(self._config_hashes.keys()):
                if gid not in gws:
                    self._config_hashes.pop(gid, None)
                    self._quirks.pop(gid, None)
                    self._key_cache.pop(gid, None)
                    self._catalog_cache.pop(gid, None)
            for gw in gws.values():
                self._ensure_gateway_fresh_locked(gw)

    def get_quirks(self, gateway: Union[GatewayConfig, str]) -> Dict[str, Any]:
        with self._lock:
            if isinstance(gateway, GatewayConfig):
                self._ensure_gateway_fresh_locked(gateway)
                gid = gateway.id
            else:
                gid = gateway
            return dict(self._quirks.get(gid) or {})

    def update_quirks(self, gateway: Union[GatewayConfig, str], new_quirks: Dict[str, Any]) -> None:
        with self._lock:
            if isinstance(gateway, GatewayConfig):
                self._ensure_gateway_fresh_locked(gateway)
                gid = gateway.id
            else:
                gid = gateway
            cur = dict(self._quirks.get(gid) or {})
            cur.update(new_quirks)
            self._quirks[gid] = cur

    def clear_key_cache(self, gateway_id: Optional[str] = None) -> None:
        with self._lock:
            if gateway_id is None:
                self._key_cache.clear()
            else:
                self._key_cache.pop(gateway_id, None)

    def resolve_api_key(self, gateway: GatewayConfig) -> str:
        now = time.time()
        with self._lock:
            cfg_hash = self._ensure_gateway_fresh_locked(gateway)
            if gateway.api_key:
                return gateway.api_key
            if gateway.api_key_env:
                env_val = os.environ.get(gateway.api_key_env, "").strip()
                if env_val:
                    return env_val
            cmd = gateway.api_key_cmd
            if not cmd:
                return ""
            cached = self._key_cache.get(gateway.id)
            if cached and (now - cached[0]) < self.key_ttl_s and cached[1]:
                return cached[1]

        secret_val = ""
        cmd_env = _build_api_key_cmd_env()
        try:
            if isinstance(cmd, (list, tuple)):
                argv = [str(x) for x in cmd if str(x)]
                res = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False, env=cmd_env)
            else:
                cmd_str = str(cmd).strip()
                has_shell_ops = any(tok in cmd_str for tok in ("|", "&&", "||", ";", ">", "<", "$(", "`"))
                if has_shell_ops:
                    res = subprocess.run(
                        cmd_str, shell=True, capture_output=True, text=True, timeout=10, check=False, env=cmd_env
                    )
                else:
                    res = subprocess.run(
                        shlex.split(cmd_str), capture_output=True, text=True, timeout=10, check=False, env=cmd_env
                    )
            if res.returncode == 0:
                secret_val = (res.stdout or "").strip()
                if not secret_val:
                    logger.warning("api_key_cmd for gateway %s returned empty key", gateway.id)
            else:
                logger.warning("api_key_cmd for gateway %s exited rc=%d", gateway.id, res.returncode)
        except Exception as exc:
            logger.warning("Failed to resolve api_key_cmd for gateway %s: %s", gateway.id, type(exc).__name__)
            return ""

        if secret_val:
            with self._lock:
                if self._config_hashes.get(gateway.id) == cfg_hash:
                    self._key_cache[gateway.id] = (now, secret_val)
        return secret_val

    def list_gateway_models(
        self,
        gateway: GatewayConfig,
        *,
        force_refresh: bool = False,
        timeout_s: float = 4.0,
        http_get: Optional[Callable[..., Any]] = None,
    ) -> List[str]:
        if not gateway.enabled:
            return []
        now = time.time()
        with self._lock:
            self._ensure_gateway_fresh_locked(gateway)
            cached = self._catalog_cache.get(gateway.id)
            if not force_refresh and cached and (now - cached[0]) < self.catalog_ttl_s:
                return list(cached[1])

        raw_ids: List[str] = []
        url = build_upstream_url(gateway.base_url, "/models")
        headers = {"Accept": "application/json", **gateway.extra_headers}
        api_key = self.resolve_api_key(gateway)
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        getter = http_get or requests.get
        try:
            resp = getter(url, headers=headers, timeout=timeout_s)
            status_code = getattr(resp, "status_code", 0)
            if status_code == 200:
                payload = resp.json()
                entries: List[Any] = []
                if isinstance(payload, dict):
                    if isinstance(payload.get("data"), list):
                        entries = payload["data"]
                    elif isinstance(payload.get("models"), list):
                        entries = payload["models"]
                elif isinstance(payload, list):
                    entries = payload
                for ent in entries:
                    if isinstance(ent, dict) and ent.get("id"):
                        raw_ids.append(str(ent["id"]).strip())
                    elif isinstance(ent, str) and ent.strip():
                        raw_ids.append(ent.strip())
            else:
                logger.warning("Gateway %s /models probe returned HTTP %s", gateway.id, status_code)
        except Exception as exc:
            logger.warning("Gateway %s /models probe failed (%s)", gateway.id, type(exc).__name__)
            with self._lock:
                if cached:
                    return list(cached[1])

        for static_m in gateway.models:
            if static_m not in raw_ids:
                raw_ids.append(static_m)

        filtered: List[str] = []
        seen = set()
        for mid in raw_ids:
            if mid not in seen and model_matches_filters(mid, gateway.include_models, gateway.exclude_models):
                seen.add(mid)
                filtered.append(mid)

        with self._lock:
            self._catalog_cache[gateway.id] = (now, list(filtered))
        return filtered


class _AdapterHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


class GatewayAdapterServer:
    """In-process or standalone OpenAI-compatible multi-gateway loopback adapter."""

    def __init__(
        self,
        gateways: Optional[Dict[str, GatewayConfig]] = None,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        runtime_state: Optional[GatewayRuntimeState] = None,
        default_gateway_id: Optional[str] = None,
        default_effort: Optional[str] = None,
        max_routes: int = 512,
        preheader_keepalive_after_s: float = 30.0,
        preheader_keepalive_interval_s: float = 15.0,
    ) -> None:
        self.host = host
        self.requested_port = int(port)
        self.runtime = runtime_state or GatewayRuntimeState()
        self.default_gateway_id = default_gateway_id
        self.default_effort = default_effort
        self.max_routes = max(1, int(max_routes))

        env_after = os.environ.get("AGY_GATEWAY_PREHEADER_KEEPALIVE_AFTER_S", "").strip()
        env_interval = os.environ.get("AGY_GATEWAY_PREHEADER_KEEPALIVE_INTERVAL_S", "").strip()
        if env_after and preheader_keepalive_after_s == 30.0:
            try:
                preheader_keepalive_after_s = float(env_after)
            except ValueError:
                pass
        if env_interval and preheader_keepalive_interval_s == 15.0:
            try:
                preheader_keepalive_interval_s = float(env_interval)
            except ValueError:
                pass
        self.preheader_keepalive_after_s = max(0.0, float(preheader_keepalive_after_s))
        self.preheader_keepalive_interval_s = max(0.01, float(preheader_keepalive_interval_s))

        self._lock = threading.Lock()
        self._gateways: Dict[str, GatewayConfig] = dict(gateways or {})
        self.runtime.sync_gateways(self._gateways)
        self._routes_by_token: "OrderedDict[str, RouteInfo]" = OrderedDict()
        self._token_by_key: Dict[Tuple[str, str, str], str] = {}
        self._httpd: Optional[_AdapterHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def port(self) -> int:
        if self._httpd is not None:
            return int(self._httpd.server_address[1])
        return self.requested_port

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def is_running(self) -> bool:
        return self._httpd is not None and self._thread is not None and self._thread.is_alive()

    def update_gateways(self, gateways: Dict[str, GatewayConfig]) -> None:
        gws = dict(gateways or {})
        with self._lock:
            self._gateways = gws
        self.runtime.sync_gateways(gws)

    def get_gateway(self, gateway_id: str) -> Optional[GatewayConfig]:
        with self._lock:
            return self._gateways.get(gateway_id)

    def register_route(
        self,
        gateway_id: str,
        upstream_model: str,
        effort: Optional[str] = None,
        *,
        force_new: bool = False,
    ) -> RouteInfo:
        if not self.is_running():
            self.start()
        gid = gateway_id.strip().lower()
        umodel = upstream_model.strip()
        eff = (effort or "").strip().lower() or None
        key = (gid, umodel, eff or "")
        with self._lock:
            if gid not in self._gateways:
                raise KeyError(f"Unknown gateway id: {gid}")
            if not force_new:
                existing_tok = self._token_by_key.get(key)
                if existing_tok and existing_tok in self._routes_by_token:
                    self._routes_by_token.move_to_end(existing_tok)
                    return self._routes_by_token[existing_tok]
            token = secrets.token_urlsafe(18)
            route = RouteInfo(
                token=token,
                url=f"http://{self.host}:{self.port}/g/{token}/v1",
                local_api_key=LOCAL_PROXY_API_KEY,
                gateway_id=gid,
                upstream_model=umodel,
                effort=eff,
            )
            self._routes_by_token[token] = route
            self._routes_by_token.move_to_end(token)
            self._token_by_key[key] = token
            while len(self._routes_by_token) > self.max_routes:
                evicted_tok, evicted_route = self._routes_by_token.popitem(last=False)
                evicted_key = (evicted_route.gateway_id, evicted_route.upstream_model, evicted_route.effort or "")
                if self._token_by_key.get(evicted_key) == evicted_tok:
                    self._token_by_key.pop(evicted_key, None)
            return route

    def get_route(self, token: str) -> Optional[RouteInfo]:
        with self._lock:
            route = self._routes_by_token.get(token)
            if route is not None:
                self._routes_by_token.move_to_end(token)
            return route

    def start(self) -> int:
        with self._lock:
            if self._httpd is not None:
                return int(self._httpd.server_address[1])
            adapter = self

            class _Handler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                    return

                def _safe_write(self, data: bytes, *, flush: bool = True) -> bool:
                    try:
                        self.wfile.write(data)
                        if flush:
                            self.wfile.flush()
                        return True
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        return False

                def _safe_flush(self) -> bool:
                    try:
                        self.wfile.flush()
                        return True
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        return False

                def _send_raw(self, code: int, content_type: str, raw: bytes) -> bool:
                    try:
                        self.send_response(code)
                        self.send_header("Content-Type", content_type)
                        self.send_header("Content-Length", str(len(raw)))
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(raw)
                        self.wfile.flush()
                        return True
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        return False

                def _send_json(self, code: int, obj: Any) -> None:
                    raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                    self._send_raw(code, "application/json; charset=utf-8", raw)

                def _send_sse_headers(self) -> bool:
                    try:
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                        self.send_header("Cache-Control", "no-cache")
                        self.send_header("X-Accel-Buffering", "no")
                        self.send_header("Connection", "close")
                        self.end_headers()
                        return True
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        return False

                def _send_sse_error(self, message: str, code: Any = 502) -> bool:
                    err_obj = {
                        "error": {
                            "message": message,
                            "type": "upstream_error",
                            "code": code,
                        }
                    }
                    # Prefix with UPSTREAM_ERROR so strict OpenAI SSE clients (including `agy`,
                    # which ignores top-level `error` keys in JSON SSE chunks) fail fast with
                    # the upstream status/message instead of treating the stream as empty output.
                    frame = f"data: UPSTREAM_ERROR {json.dumps(err_obj, ensure_ascii=False)}\n\n".encode("utf-8")
                    if not self._safe_write(frame, flush=False):
                        return False
                    return self._safe_write(b"data: [DONE]\n\n", flush=True)

                def _read_body(self) -> bytes:
                    try:
                        clen = int(self.headers.get("Content-Length") or "0")
                    except ValueError:
                        clen = 0
                    if clen <= 0:
                        return b""
                    return self.rfile.read(clen)

                def _resolve_request_target(
                    self,
                ) -> Tuple[Optional[GatewayConfig], Optional[RouteInfo], str, Optional[str]]:
                    path = urlparse(self.path).path
                    if path.startswith("/g/"):
                        parts = path.split("/", 4)
                        # /g/<token>/v1/<subpath>
                        if len(parts) < 4:
                            return None, None, "", "invalid route path"
                        tok = parts[2]
                        route = adapter.get_route(tok)
                        if route is None:
                            return None, None, "", "unknown route token"
                        gw = adapter.get_gateway(route.gateway_id)
                        if gw is None or not gw.enabled:
                            return None, route, "", "gateway disabled or missing"
                        rest = "/" + (parts[4] if len(parts) >= 5 else "")
                        if parts[3] != "v1":
                            rest = "/" + "/".join(parts[3:])
                        return gw, route, rest, None

                    # Direct /v1/... mode (CLI `serve`)
                    if path == "/health" or path == "/healthz":
                        return None, None, "__health__", None

                    gw = None
                    if adapter.default_gateway_id:
                        gw = adapter.get_gateway(adapter.default_gateway_id)
                    else:
                        with adapter._lock:
                            enabled = [g for g in adapter._gateways.values() if g.enabled]
                            if len(enabled) == 1:
                                gw = enabled[0]
                    if gw is None or not gw.enabled:
                        return None, None, "", "no active default gateway"
                    sub = path[3:] if path.startswith("/v1/") else ("/" if path == "/v1" else path)
                    return gw, None, sub, None

                def do_GET(self) -> None:  # noqa: N802
                    gw, route, sub, err = self._resolve_request_target()
                    if sub == "__health__":
                        self._send_json(200, {"status": "ok"})
                        return
                    if err or gw is None:
                        self._send_json(404, {"error": {"message": err or "not found"}})
                        return

                    if sub.rstrip("/") == "/models":
                        ids = adapter.runtime.list_gateway_models(gw)
                        if route and route.upstream_model and route.upstream_model not in ids:
                            ids = [route.upstream_model] + ids
                        data_items = [
                            {"id": mid, "object": "model", "owned_by": gw.id}
                            for mid in ids
                        ]
                        self._send_json(200, {"object": "list", "data": data_items})
                        return

                    target_url = build_upstream_url(gw.base_url, sub)
                    headers = {"Accept": "application/json", **gw.extra_headers}
                    api_key = adapter.runtime.resolve_api_key(gw)
                    if api_key:
                        headers["Authorization"] = f"Bearer {api_key}"
                    try:
                        resp = requests.get(target_url, headers=headers, timeout=min(30.0, gw.timeout_s))
                        raw = resp.content
                        ctype = resp.headers.get("Content-Type", "application/json")
                        self._send_raw(resp.status_code, ctype, raw)
                    except Exception as exc:
                        self._send_json(502, {"error": {"message": f"upstream GET error: {type(exc).__name__}"}})

                @staticmethod
                def _close_resp_quiet(r: Any) -> None:
                    if r is not None:
                        try:
                            r.close()
                        except Exception:
                            pass

                @staticmethod
                def _extract_error_message(raw_bytes: bytes, status_code: int) -> str:
                    err_text = raw_bytes.decode("utf-8", errors="replace").strip()
                    if err_text:
                        try:
                            parsed = json.loads(err_text)
                            if isinstance(parsed, dict):
                                err_obj = parsed.get("error")
                                if isinstance(err_obj, dict) and err_obj.get("message"):
                                    return str(err_obj["message"])
                                if parsed.get("message"):
                                    return str(parsed["message"])
                        except Exception:
                            pass
                        return err_text[:500]
                    return f"upstream returned HTTP {status_code}"

                def _perform_chat_attempts(
                    self,
                    gw: GatewayConfig,
                    target_url: str,
                    req_json: Dict[str, Any],
                    headers: Dict[str, str],
                    route_model: Optional[str],
                    route_effort: Optional[str],
                    cancel_ev: Optional[threading.Event] = None,
                ) -> Dict[str, Any]:
                    quirks = adapter.runtime.get_quirks(gw)
                    resp = None
                    last_err_text = ""
                    try:
                        for attempt in range(3):
                            if cancel_ev is not None and cancel_ev.is_set():
                                return {"kind": "cancelled", "resp": None, "exc": None, "status": 0, "ctype": "", "body": b""}
                            fwd_json = transform_chat_request(
                                req_json,
                                gw,
                                upstream_model=route_model,
                                effort=route_effort,
                                quirks=quirks,
                            )
                            try:
                                resp = requests.post(
                                    target_url,
                                    json=fwd_json,
                                    headers=headers,
                                    stream=True,
                                    timeout=gw.timeout_s,
                                )
                            except Exception as exc:
                                return {"kind": "conn_error", "resp": None, "exc": exc, "status": 502, "ctype": "", "body": b""}

                            if cancel_ev is not None and cancel_ev.is_set():
                                self._close_resp_quiet(resp)
                                resp = None
                                return {"kind": "cancelled", "resp": None, "exc": None, "status": 0, "ctype": "", "body": b""}

                            if resp.status_code == 400 and gw.adaptive_400_fallback and attempt < 2:
                                err_ctype = resp.headers.get("Content-Type", "application/json")
                                try:
                                    err_bytes = resp.raw.read(65536) if hasattr(resp, "raw") and resp.raw else resp.content[:65536]
                                    last_err_text = (
                                        err_bytes.decode("utf-8", errors="replace")
                                        if isinstance(err_bytes, bytes)
                                        else str(err_bytes)
                                    )
                                except Exception:
                                    last_err_text = ""
                                finally:
                                    self._close_resp_quiet(resp)
                                    resp = None
                                new_quirks = infer_quirk_from_400(last_err_text, fwd_json, quirks, gw)
                                if new_quirks is not None:
                                    adapter.runtime.update_quirks(gw, new_quirks)
                                    quirks = new_quirks
                                    logger.info("Gateway %s adapted quirk on 400 retry %d", gw.id, attempt + 1)
                                    continue
                                return {
                                    "kind": "buffered_400",
                                    "resp": None,
                                    "exc": None,
                                    "status": 400,
                                    "ctype": err_ctype,
                                    "body": last_err_text.encode("utf-8"),
                                }
                            break

                        if resp is None:
                            return {"kind": "no_response", "resp": None, "exc": None, "status": 502, "ctype": "", "body": b""}
                        ctype_low = (resp.headers.get("Content-Type") or "").lower()
                        if resp.status_code != 200 or "text/event-stream" not in ctype_low:
                            try:
                                _ = resp.content
                            except Exception as exc:
                                return {"kind": "conn_error", "resp": None, "exc": exc, "status": 502, "ctype": "", "body": b""}
                        res = {"kind": "response", "resp": resp, "exc": None, "status": resp.status_code, "ctype": "", "body": b""}
                        resp = None
                        return res
                    finally:
                        self._close_resp_quiet(resp)

                def _stream_sse_with_keepalive(
                    self,
                    resp: Any,
                    norm: SSEStreamNormalizer,
                    cancel_ev: Optional[threading.Event],
                    req_started_at: float,
                    keepalive_active: bool,
                ) -> None:
                    line_q: "queue.Queue[Tuple[str, Any]]" = queue.Queue(maxsize=256)
                    effective_cancel = cancel_ev if cancel_ev is not None else threading.Event()

                    def _put_item(item: Tuple[str, Any]) -> bool:
                        while not effective_cancel.is_set():
                            try:
                                line_q.put(item, timeout=0.2)
                                return True
                            except queue.Full:
                                continue
                        return False

                    def _reader() -> None:
                        terminal_sent = False
                        try:
                            for raw_line in resp.iter_lines(chunk_size=None, decode_unicode=False):
                                if effective_cancel.is_set():
                                    return
                                if raw_line is None:
                                    continue
                                if not _put_item(("line", raw_line)):
                                    return
                            terminal_sent = True
                            _put_item(("eof", None))
                        except Exception as exc:
                            logger.warning("Gateway SSE reader failed: %s", type(exc).__name__)
                            terminal_sent = True
                            _put_item(("err", exc))
                        finally:
                            if not terminal_sent and not effective_cancel.is_set():
                                _put_item(("err", RuntimeError("sse reader terminated unexpectedly")))

                    threading.Thread(target=_reader, daemon=True, name="agy-gw-sse-reader").start()
                    last_activity_at = time.monotonic() if keepalive_active else req_started_at
                    try:
                        while True:
                            if effective_cancel.is_set():
                                return
                            if keepalive_active:
                                wait_s = adapter.preheader_keepalive_interval_s
                            else:
                                elapsed = max(0.0, time.monotonic() - last_activity_at)
                                wait_s = max(0.01, adapter.preheader_keepalive_after_s - elapsed)
                            try:
                                kind, payload = line_q.get(timeout=wait_s)
                            except queue.Empty:
                                if not self._safe_write(b": keepalive\n\n", flush=True):
                                    effective_cancel.set()
                                    self._close_resp_quiet(resp)
                                    return
                                keepalive_active = True
                                last_activity_at = time.monotonic()
                                continue

                            if kind == "eof":
                                tail = norm.finalize()
                                if tail:
                                    if not self._safe_write(tail, flush=True):
                                        effective_cancel.set()
                                return
                            if kind == "err":
                                if not norm.saw_done:
                                    self._send_sse_error(f"upstream stream error: {type(payload).__name__}", code=502)
                                return
                            if kind == "line":
                                raw_line = payload
                                line_str = (
                                    bytes(raw_line).decode("utf-8", errors="replace")
                                    if isinstance(raw_line, (bytes, bytearray))
                                    else str(raw_line)
                                )
                                frame = norm.process_line(line_str)
                                if frame:
                                    if not self._safe_write(frame, flush=True):
                                        effective_cancel.set()
                                        self._close_resp_quiet(resp)
                                        return
                                    last_activity_at = time.monotonic()
                    finally:
                        if cancel_ev is None:
                            effective_cancel.set()

                def _write_chat_outcome(
                    self,
                    outcome: Dict[str, Any],
                    client_wants_stream: bool,
                    sse_headers_sent: bool,
                    cancel_ev: Optional[threading.Event] = None,
                    *,
                    req_started_at: Optional[float] = None,
                    keepalive_active: bool = False,
                ) -> None:
                    kind = outcome.get("kind")
                    resp = outcome.get("resp")
                    try:
                        if kind == "cancelled":
                            return
                        if kind == "conn_error":
                            msg = f"upstream connection failed: {type(outcome.get('exc')).__name__}"
                            if sse_headers_sent:
                                self._send_sse_error(msg, code=502)
                            else:
                                self._send_json(502, {"error": {"message": msg}})
                            return
                        if kind == "buffered_400":
                            buf_body = outcome.get("body") or b""
                            if sse_headers_sent:
                                msg = self._extract_error_message(buf_body, 400)
                                self._send_sse_error(msg, code=400)
                            else:
                                self._send_raw(400, outcome.get("ctype") or "application/json", buf_body)
                            return
                        if kind == "no_response" or resp is None:
                            msg = "upstream returned no response"
                            if sse_headers_sent:
                                self._send_sse_error(msg, code=502)
                            else:
                                self._send_json(502, {"error": {"message": msg}})
                            return

                        if resp.status_code != 200:
                            err_raw = resp.content[:262144]
                            if sse_headers_sent:
                                msg = self._extract_error_message(err_raw, resp.status_code)
                                self._send_sse_error(msg, code=resp.status_code)
                            else:
                                self._send_raw(
                                    resp.status_code,
                                    resp.headers.get("Content-Type", "application/json"),
                                    err_raw,
                                )
                            return

                        ctype = (resp.headers.get("Content-Type") or "").lower()
                        if "text/event-stream" in ctype:
                            if not sse_headers_sent:
                                if not self._send_sse_headers():
                                    if cancel_ev is not None:
                                        cancel_ev.set()
                                    return
                            norm = SSEStreamNormalizer()
                            if client_wants_stream and adapter.preheader_keepalive_after_s > 0:
                                self._stream_sse_with_keepalive(
                                    resp,
                                    norm,
                                    cancel_ev,
                                    req_started_at if req_started_at is not None else time.monotonic(),
                                    keepalive_active,
                                )
                                return
                            for raw_line in resp.iter_lines(chunk_size=None, decode_unicode=False):
                                if cancel_ev is not None and cancel_ev.is_set():
                                    return
                                if raw_line is None:
                                    continue
                                line_str = (
                                    bytes(raw_line).decode("utf-8", errors="replace")
                                    if isinstance(raw_line, (bytes, bytearray))
                                    else str(raw_line)
                                )
                                frame = norm.process_line(line_str)
                                if frame:
                                    if not self._safe_write(frame, flush=True):
                                        if cancel_ev is not None:
                                            cancel_ev.set()
                                        return
                            tail = norm.finalize()
                            if tail:
                                if not self._safe_write(tail, flush=True) and cancel_ev is not None:
                                    cancel_ev.set()
                            return

                        # Non-streaming JSON response
                        body_bytes = resp.content
                        try:
                            parsed_resp = json.loads(body_bytes.decode("utf-8"))
                        except Exception:
                            if sse_headers_sent:
                                self._send_sse_error("upstream returned non-JSON response", code=502)
                            else:
                                self._send_raw(
                                    200,
                                    resp.headers.get("Content-Type", "application/json"),
                                    body_bytes,
                                )
                            return

                        if (client_wants_stream or sse_headers_sent) and isinstance(parsed_resp, dict):
                            frames = json_completion_to_sse_chunks(parsed_resp)
                            if not sse_headers_sent:
                                if not self._send_sse_headers():
                                    if cancel_ev is not None:
                                        cancel_ev.set()
                                    return
                            for frame in frames:
                                if not self._safe_write(frame, flush=False):
                                    if cancel_ev is not None:
                                        cancel_ev.set()
                                    return
                            if not self._safe_flush() and cancel_ev is not None:
                                cancel_ev.set()
                            return

                        norm_json = normalize_completion_json(parsed_resp) if isinstance(parsed_resp, dict) else parsed_resp
                        out_raw = json.dumps(norm_json, ensure_ascii=False).encode("utf-8")
                        self._send_raw(200, "application/json; charset=utf-8", out_raw)
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        if cancel_ev is not None:
                            cancel_ev.set()
                    finally:
                        self._close_resp_quiet(resp)

                def do_POST(self) -> None:  # noqa: N802
                    gw, route, sub, err = self._resolve_request_target()
                    if err or gw is None:
                        self._send_json(404, {"error": {"message": err or "not found"}})
                        return

                    raw_body = self._read_body()
                    if sub.rstrip("/") != "/chat/completions":
                        target_url = build_upstream_url(gw.base_url, sub)
                        headers = {
                            "Content-Type": self.headers.get("Content-Type", "application/json"),
                            **gw.extra_headers,
                        }
                        api_key = adapter.runtime.resolve_api_key(gw)
                        if api_key:
                            headers["Authorization"] = f"Bearer {api_key}"
                        try:
                            resp = requests.post(target_url, data=raw_body, headers=headers, timeout=gw.timeout_s)
                            out_bytes = resp.content
                            self._send_raw(
                                resp.status_code,
                                resp.headers.get("Content-Type", "application/json"),
                                out_bytes,
                            )
                        except Exception as exc:
                            self._send_json(502, {"error": {"message": f"upstream POST error: {type(exc).__name__}"}})
                        return

                    try:
                        req_json = json.loads(raw_body.decode("utf-8")) if raw_body else {}
                    except Exception:
                        self._send_json(400, {"error": {"message": "invalid JSON request body"}})
                        return
                    if not isinstance(req_json, dict):
                        self._send_json(400, {"error": {"message": "JSON request body must be an object"}})
                        return

                    client_wants_stream = bool(req_json.get("stream"))
                    route_model = route.upstream_model if route else None
                    route_effort = route.effort if route else adapter.default_effort
                    target_url = build_upstream_url(gw.base_url, "/chat/completions")

                    headers = {
                        "Content-Type": "application/json",
                        "Accept": "text/event-stream, application/json",
                        **gw.extra_headers,
                    }
                    api_key = adapter.runtime.resolve_api_key(gw)
                    if api_key:
                        headers["Authorization"] = f"Bearer {api_key}"

                    if not client_wants_stream or adapter.preheader_keepalive_after_s <= 0:
                        outcome = self._perform_chat_attempts(
                            gw, target_url, req_json, headers, route_model, route_effort
                        )
                        self._write_chat_outcome(outcome, client_wants_stream, sse_headers_sent=False)
                        return

                    done_ev = threading.Event()
                    cancel_ev = threading.Event()
                    outcome_lock = threading.Lock()
                    req_started_at = time.monotonic()
                    shared_outcome: Dict[str, Any] = {
                        "kind": None,
                        "resp": None,
                        "exc": None,
                        "status": 0,
                        "ctype": "",
                        "body": b"",
                    }

                    def _worker() -> None:
                        res: Dict[str, Any] = {
                            "kind": "conn_error",
                            "resp": None,
                            "exc": RuntimeError("worker terminated unexpectedly"),
                            "status": 502,
                            "ctype": "",
                            "body": b"",
                        }
                        try:
                            try:
                                res = self._perform_chat_attempts(
                                    gw,
                                    target_url,
                                    req_json,
                                    headers,
                                    route_model,
                                    route_effort,
                                    cancel_ev=cancel_ev,
                                )
                            except Exception as exc:
                                logger.warning(
                                    "Gateway %s upstream worker failed: %s",
                                    gw.id,
                                    type(exc).__name__,
                                )
                                res = {
                                    "kind": "conn_error",
                                    "resp": None,
                                    "exc": exc,
                                    "status": 502,
                                    "ctype": "",
                                    "body": b"",
                                }
                            with outcome_lock:
                                if cancel_ev.is_set():
                                    self._close_resp_quiet(res.get("resp") if isinstance(res, dict) else None)
                                    if isinstance(res, dict):
                                        res["resp"] = None
                                    shared_outcome["kind"] = "cancelled"
                                elif isinstance(res, dict):
                                    shared_outcome.update(res)
                                else:
                                    shared_outcome.update(
                                        {
                                            "kind": "conn_error",
                                            "resp": None,
                                            "exc": TypeError("unexpected worker outcome"),
                                            "status": 502,
                                            "ctype": "",
                                            "body": b"",
                                        }
                                    )
                        except Exception as exc:
                            logger.warning(
                                "Gateway %s worker publish failed: %s",
                                gw.id,
                                type(exc).__name__,
                            )
                            self._close_resp_quiet(res.get("resp") if isinstance(res, dict) else None)
                            with outcome_lock:
                                if cancel_ev.is_set():
                                    shared_outcome["kind"] = "cancelled"
                                else:
                                    shared_outcome.update(
                                        {
                                            "kind": "conn_error",
                                            "resp": None,
                                            "exc": exc,
                                            "status": 502,
                                            "ctype": "",
                                            "body": b"",
                                        }
                                    )
                        finally:
                            done_ev.set()

                    threading.Thread(target=_worker, daemon=True, name="agy-gw-upstream").start()

                    sse_headers_sent = False
                    try:
                        if not done_ev.wait(timeout=adapter.preheader_keepalive_after_s):
                            if not self._send_sse_headers():
                                cancel_ev.set()
                                return
                            sse_headers_sent = True
                            if not self._safe_write(b": keepalive\n\n", flush=True):
                                cancel_ev.set()
                                return
                            while not done_ev.wait(timeout=adapter.preheader_keepalive_interval_s):
                                if not self._safe_write(b": keepalive\n\n", flush=True):
                                    cancel_ev.set()
                                    return

                        with outcome_lock:
                            outcome = dict(shared_outcome)
                            shared_outcome["resp"] = None
                        self._write_chat_outcome(
                            outcome,
                            client_wants_stream,
                            sse_headers_sent=sse_headers_sent,
                            cancel_ev=cancel_ev,
                            req_started_at=req_started_at,
                            keepalive_active=sse_headers_sent,
                        )
                    finally:
                        cancel_ev.set()
                        with outcome_lock:
                            leftover_resp = shared_outcome.get("resp")
                            shared_outcome["resp"] = None
                        self._close_resp_quiet(leftover_resp)

            self._httpd = _AdapterHTTPServer((self.host, self.requested_port), _Handler)
            self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True, name="agy-gateway-adapter")
            self._thread.start()
            return self.port

    def stop(self) -> None:
        with self._lock:
            httpd = self._httpd
            th = self._thread
            self._httpd = None
            self._thread = None
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception:
                pass
            try:
                httpd.server_close()
            except Exception:
                pass
        if th is not None and th.is_alive():
            th.join(timeout=2.0)


def _cli_serve(args: argparse.Namespace) -> int:
    gateways = load_gateways_config(gateways_file=args.config)
    if not gateways:
        print("No gateways configured.", file=sys.stderr)
        return 1
    default_gid = args.gateway
    if default_gid and default_gid not in gateways:
        print(f"Gateway not found: {default_gid}", file=sys.stderr)
        return 1
    srv = GatewayAdapterServer(
        gateways,
        host=args.host,
        port=args.port,
        default_gateway_id=default_gid,
        default_effort=args.effort,
    )
    bound_port = srv.start()
    print(f"Gateway adapter listening on http://{args.host}:{bound_port}/v1 (gateways={','.join(gateways)})", flush=True)
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        srv.stop()
        return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Multi-gateway OpenAI-compatible adapter for agy")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("serve", help="Run standalone loopback gateway adapter")
    sp.add_argument("--config", default=None, help="Path to gateways.json")
    sp.add_argument("--gateway", default=None, help="Default gateway ID for /v1/* requests")
    sp.add_argument("--effort", default=None, help="Default reasoning effort for /v1/* requests")
    sp.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    sp.add_argument("--port", type=int, default=0, help="Bind port (default: 0 ephemeral)")
    args = parser.parse_args(argv)
    if args.cmd == "serve":
        return _cli_serve(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
