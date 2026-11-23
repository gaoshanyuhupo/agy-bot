#!/usr/bin/env python3
"""Fail-Closed Per-Bot Isolation Stdio JSON-RPC Proxy for `claude-mem` MCP Server.

Wraps the upstream `claude-mem` `mcp-server.cjs` stdio server and enforces strict
per-bot memory boundaries before forwarding any `tools/call` request:

- Explicit policy coverage for ALL 19 `claude-mem` MCP tools:
  * Scoped read/search: `search`, `dumb_search`, `timeline`, `session_start_context`,
    `get_tool_uses`, `work_state_read`
  * ID-scoped fetch (anti-IDOR SQLite RO verification): `get_observations`, `timeline` (`anchor`)
  * Scoped write: `save_memory`, `important_workflow`, `work_state_write`
  * Smart code tools (path boundary checked): `smart_search`, `smart_unfold`, `smart_outline`
  * Corpus tools (6): `build_corpus`, `list_corpora`, `prime_corpus`, `query_corpus`,
    `rebuild_corpus`, `reprime_corpus`
  * Unknown tools: fail-closed DENY for Workers.
- Worker (`AGY_BOT_BUS_ROLE != "coordinator"`):
  * Missing/invalid `AGY_BOT_HANDLE` -> fail-closed DENY on all tool calls.
  * Forces `project = bot-<handle>` and strips forged multi-project keys (`projects`, etc.).
  * `get_observations(ids=...)` (handling mixed int/str IDs) & `timeline(anchor=...)` verify
    ownership via read-only SQLite against `claude-mem.db`; unreadable DB -> fail-closed DENY;
    cross-bot IDs are stripped/rejected (if zero owned IDs remain, short-circuit without calling upstream).
  * Cross-bot `*_corpus` and unauthorized `smart_*` paths are denied.
- Coordinator (`AGY_BOT_BUS_ROLE == "coordinator"`):
  * Full read visibility across all `bot-*` and shared projects.
  * Write tools default `project` to `bot-<handle>` when omitted.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
from typing import Any, Mapping

try:
    import bot_profiles
except ImportError:
    _THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    if _THIS_DIR not in sys.path:
        sys.path.insert(0, _THIS_DIR)
    import bot_profiles  # type: ignore

SCOPED_READ_TOOLS: frozenset[str] = frozenset(
    {
        "search",
        "dumb_search",
        "timeline",
        "session_start_context",
        "get_tool_uses",
        "work_state_read",
    }
)
SCOPED_WRITE_TOOLS: frozenset[str] = frozenset(
    {
        "save_memory",
        "important_workflow",
        "work_state_write",
    }
)
# Upstream `mcp-server.cjs` declares strict `additionalProperties: false` without a `project` key
# on these tools; worker isolation for `work_state_*` is enforced via per-bot sentinel `cwd`.
NO_PROJECT_ARG_TOOLS: frozenset[str] = frozenset(
    {
        "work_state_read",
        "work_state_write",
        "important_workflow",
    }
)
ID_FETCH_TOOLS: frozenset[str] = frozenset({"get_observations"})
SMART_CODE_TOOLS: frozenset[str] = frozenset(
    {"smart_search", "smart_unfold", "smart_outline"}
)
CORPUS_TOOLS: frozenset[str] = frozenset(
    {
        "build_corpus",
        "list_corpora",
        "prime_corpus",
        "query_corpus",
        "rebuild_corpus",
        "reprime_corpus",
    }
)
ALL_KNOWN_TOOLS: frozenset[str] = (
    SCOPED_READ_TOOLS
    | SCOPED_WRITE_TOOLS
    | ID_FETCH_TOOLS
    | SMART_CODE_TOOLS
    | CORPUS_TOOLS
)

_FORGED_PROJECT_KEYS: tuple[str, ...] = (
    "projects",
    "project_filter",
    "projectFilter",
    "all_projects",
    "allProjects",
    "projectId",
    "project_id",
    "projectIds",
    "project_ids",
)
_SMART_PATH_KEYS: tuple[str, ...] = (
    "path",
    "file",
    "file_path",
    "filePath",
    "dir",
    "directory",
    "root",
    "target",
    "cwd",
    "paths",
    "files",
)
_SKILL_SEG_RE = re.compile(r"(?:^|/)\.agents/skills/([^/]+)(?:/|$)")
_SKILLS_ROOT_RE = re.compile(r"(?:^|/)\.agents/skills/?$")
_BRIDGE_CFG_RE = re.compile(r"(?:^|/)\.config/agy-tg-bridge(?:/(.*))?$")
_CLAUDE_MEM_DIR_RE = re.compile(r"(?i)(?:^|/)\.claude-mem(?:/|$)")
_CORPUS_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,80}$")


def _parse_int_id(val: Any) -> int | None:
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if val > 0 else None
    if isinstance(val, str):
        s = val.strip()
        if s.isascii() and s.isdigit():
            n = int(s)
            return n if n > 0 else None
    return None


def _parse_ids_arg(raw_ids: Any) -> tuple[list[int], bool]:
    """Parse mixed int/str `ids` argument; returns `(valid_positive_ints, had_any_input)`."""
    if raw_ids is None:
        return [], False
    if isinstance(raw_ids, (int, str)) and not isinstance(raw_ids, bool):
        parsed = _parse_int_id(raw_ids)
        return ([parsed] if parsed is not None else []), True
    if isinstance(raw_ids, list):
        out: list[int] = []
        seen: set[int] = set()
        for item in raw_ids:
            p = _parse_int_id(item)
            if p is not None and p not in seen:
                seen.add(p)
                out.append(p)
        return out, len(raw_ids) > 0
    return [], True


def _query_owned_observation_ids(
    db_path: Path,
    ids: list[int],
    expected_project: str,
) -> tuple[bool, list[int], str]:
    """Query read-only SQLite to filter `ids` strictly to those owned by `expected_project`.

    Returns `(db_ok, owned_ids, err_msg)`.
    """
    if not db_path.is_file():
        return False, [], "claude-mem database unavailable (fail-closed)"
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2.0)
        try:
            if not ids:
                return True, [], ""
            placeholders = ",".join("?" for _ in ids)
            rows = conn.execute(
                f"SELECT id FROM observations WHERE project = ? AND id IN ({placeholders})",
                [expected_project, *ids],
            ).fetchall()
            owned_set = {int(r[0]) for r in rows}
            owned_ordered = [i for i in ids if i in owned_set]
            return True, owned_ordered, ""
        finally:
            conn.close()
    except Exception as exc:
        return False, [], f"claude-mem database read failed ({type(exc).__name__})"


def _check_observation_anchor_owner(
    db_path: Path,
    anchor_id: int,
    expected_project: str,
) -> tuple[bool, bool, str]:
    """Return `(db_ok, is_owned, err_msg)` for a single observation anchor ID."""
    if not db_path.is_file():
        return False, False, "claude-mem database unavailable (fail-closed)"
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=2.0)
        try:
            row = conn.execute(
                "SELECT project FROM observations WHERE id = ?",
                (anchor_id,),
            ).fetchone()
            if row is None:
                return True, False, "anchor observation not found"
            return True, str(row[0] or "").strip() == expected_project, ""
        finally:
            conn.close()
    except Exception as exc:
        return False, False, f"claude-mem database read failed ({type(exc).__name__})"


def _is_worker_forbidden_path(
    raw_path: str,
    *,
    my_handle: str,
    profiles_dir: Path,
    db_path: Path,
    cwd: str = "",
) -> tuple[bool, str]:
    s = str(raw_path or "").strip()
    if not s:
        return False, ""
    expanded = os.path.expandvars(os.path.expanduser(s))
    if not os.path.isabs(expanded) and cwd:
        expanded_abs = os.path.join(cwd, expanded)
    else:
        expanded_abs = expanded
    norm_str = os.path.normpath(expanded_abs).replace("\\", "/")
    try:
        res_str = str(Path(expanded_abs).resolve(strict=False)).replace("\\", "/")
    except Exception:
        res_str = norm_str

    p_root = str(profiles_dir.resolve(strict=False)).replace("\\", "/").rstrip("/")
    p_root_norm = os.path.normpath(str(profiles_dir)).replace("\\", "/").rstrip("/")
    db_norm = os.path.normpath(str(db_path)).replace("\\", "/")
    db_res = str(db_path.resolve(strict=False)).replace("\\", "/")
    db_dir_norm = os.path.normpath(str(db_path.parent)).replace("\\", "/").rstrip("/")
    db_dir_res = str(db_path.parent.resolve(strict=False)).replace("\\", "/").rstrip("/")
    cwd_norm = os.path.normpath(cwd).replace("\\", "/").rstrip("/") if cwd else ""
    cwd_res = str(Path(cwd).resolve(strict=False)).replace("\\", "/").rstrip("/") if cwd else ""

    mode, allowed = bot_profiles.get_worker_allowed_catalog_slugs(
        my_handle, profiles_dir=profiles_dir
    )

    for cand in (norm_str, res_str):
        low = cand.lower()

        # 1. Direct .claude-mem directory & DB access
        if _CLAUDE_MEM_DIR_RE.search(cand):
            return True, "direct .claude-mem directory access is forbidden for worker"
        for db_cand in (db_norm, db_res):
            if (
                cand == db_cand
                or cand.startswith(db_cand + "-")
                or cand.startswith(db_cand + ".")
            ):
                return True, "direct claude-mem database access is forbidden for worker"
        for db_dir in (db_dir_norm, db_dir_res):
            if not db_dir:
                continue
            if Path(db_dir).name.lower() in (".claude-mem", "claude-mem"):
                if cand == db_dir or cand.startswith(db_dir + "/"):
                    return True, "direct claude-mem directory access is forbidden for worker"
            else:
                is_cwd_or_anc = bool(
                    (cwd_norm and (cwd_norm == db_dir or cwd_norm.startswith(db_dir + "/")))
                    or (cwd_res and (cwd_res == db_dir or cwd_res.startswith(db_dir + "/")))
                )
                if not is_cwd_or_anc and cand == db_dir:
                    return True, "direct claude-mem database directory access is forbidden for worker"

        # 2. Protected bridge config parent & cross-bot profile directory access
        m_cfg = _BRIDGE_CFG_RE.search(cand)
        if m_cfg:
            sub = (m_cfg.group(1) or "").strip("/").lower()
            own_sub = f"bots/{my_handle}"
            if sub != own_sub and not sub.startswith(own_sub + "/"):
                return True, "accessing protected bridge config directory is forbidden for worker"

        for root_cand in (p_root, p_root_norm):
            if cand == root_cand:
                return True, "listing all bot profiles root is forbidden for worker"
            if cand.startswith(root_cand + "/"):
                rest = cand[len(root_cand) + 1 :]
                target_bot = rest.split("/", 1)[0].lower()
                if target_bot and target_bot != my_handle:
                    return True, f"cross-bot profile path forbidden for worker (@{target_bot})"
            parent_p = Path(root_cand).parent
            if parent_p.name == "agy-tg-bridge":
                parent_str = str(parent_p).replace("\\", "/").rstrip("/")
                own_prefix = f"{root_cand}/{my_handle}".lower()
                if cand == parent_str or (
                    cand.startswith(parent_str + "/")
                    and low != own_prefix
                    and not low.startswith(own_prefix + "/")
                ):
                    return True, "accessing protected bridge parent directory is forbidden for worker"

        # 3. `.agents/skills` root & unauthorized catalog skill path
        if mode != "all":
            if _SKILLS_ROOT_RE.search(cand):
                return True, "scanning .agents/skills root is forbidden for worker under allowlist policy"
            m = _SKILL_SEG_RE.search(cand)
            if m:
                slug = m.group(1)
                if slug not in allowed:
                    return True, f"unauthorized catalog skill path for worker: {slug}"

    return False, ""


def _tool_result(text: str, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": text}],
        "isError": bool(is_error),
    }


def evaluate_mcp_tool_call(
    tool_name: str,
    arguments: Any,
    *,
    env: Mapping[str, str] | None = None,
    db_path: str | Path | None = None,
    profiles_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Evaluate a `claude-mem` MCP `tools/call` invocation under per-bot isolation policy.

    Returns a decision dict:
    - `{"action": "forward", "arguments": <sanitized_args>}`
    - `{"action": "short_circuit", "result": <mcp_tool_result>}` (deny or empty safe result)
    """
    eff_env = env if env is not None else os.environ
    tname = str(tool_name or "").strip()
    args = dict(arguments) if isinstance(arguments, dict) else {}

    raw_handle = str(eff_env.get("AGY_BOT_HANDLE") or "").strip()
    handle = bot_profiles.normalize_bot_handle(raw_handle)
    role = str(eff_env.get("AGY_BOT_BUS_ROLE") or "worker").strip().lower()
    is_coordinator = role == "coordinator"

    eff_db = bot_profiles.resolve_claude_mem_db(
        db_path if db_path is not None else eff_env.get("CLAUDE_MEM_DB_PATH")
    )
    eff_profiles = bot_profiles.resolve_profiles_dir(
        profiles_dir if profiles_dir is not None else eff_env.get("AGY_BOT_PROFILES_DIR")
    )

    # Fail-closed when AGY_BOT_HANDLE is missing or invalid
    if not handle:
        return {
            "action": "short_circuit",
            "result": _tool_result(
                "[claude-mem-proxy] Access denied (fail-closed): missing or invalid AGY_BOT_HANDLE.",
                is_error=True,
            ),
        }

    expected_project = f"bot-{handle}"

    # Coordinator: full read visibility across all bots & shared projects; default writes to own project
    if is_coordinator:
        if tname in NO_PROJECT_ARG_TOOLS:
            args.pop("project", None)
            for fk in _FORGED_PROJECT_KEYS:
                args.pop(fk, None)
        elif tname in SCOPED_WRITE_TOOLS:
            raw_proj = str(args.get("project") or "").strip()
            if not raw_proj:
                args["project"] = expected_project
        return {"action": "forward", "arguments": args}

    # Worker: unknown tools fail-closed
    if tname not in ALL_KNOWN_TOOLS:
        return {
            "action": "short_circuit",
            "result": _tool_result(
                f"[claude-mem-proxy] Access denied (fail-closed): unknown tool '{tname}' is not permitted for worker.",
                is_error=True,
            ),
        }

    # Worker: Corpus tools
    if tname in CORPUS_TOOLS:
        if tname == "list_corpora":
            return {
                "action": "short_circuit",
                "result": _tool_result(
                    "[claude-mem-proxy] Access denied: cross-bot corpus listing is restricted for worker.",
                    is_error=True,
                ),
            }
        corpus_inputs: list[Any] = []
        if "name" in args and args.get("name") is not None:
            corpus_inputs.append(args.get("name"))
        if "corpus" in args and args.get("corpus") is not None:
            corpus_inputs.append(args.get("corpus"))
        if not corpus_inputs:
            return {
                "action": "short_circuit",
                "result": _tool_result(
                    f"[claude-mem-proxy] Access denied: worker @{handle} must specify a valid corpus name prefixed with '{expected_project}'.",
                    is_error=True,
                ),
            }
        for raw_cname in corpus_inputs:
            if not isinstance(raw_cname, str) or "\x00" in raw_cname or "/" in raw_cname or "\\" in raw_cname or ".." in raw_cname:
                return {
                    "action": "short_circuit",
                    "result": _tool_result(
                        f"[claude-mem-proxy] Access denied: invalid corpus name format for worker @{handle}.",
                        is_error=True,
                    ),
                }
            cname = raw_cname.lower()
            if not _CORPUS_NAME_RE.fullmatch(cname) or not (
                cname == expected_project or cname.startswith(expected_project + "-")
            ):
                return {
                    "action": "short_circuit",
                    "result": _tool_result(
                        f"[claude-mem-proxy] Access denied: worker @{handle} may only access corpus matching '^[a-z0-9][a-z0-9_-]{{0,80}}$' and prefixed with '{expected_project}'.",
                        is_error=True,
                    ),
                }
        args["project"] = expected_project
        for fk in _FORGED_PROJECT_KEYS:
            args.pop(fk, None)
        return {"action": "forward", "arguments": args}

    # Worker: Smart code tools (enforce path boundaries)
    if tname in SMART_CODE_TOOLS:
        found_explicit_path = False
        for pk in _SMART_PATH_KEYS:
            val = args.get(pk)
            candidates = val if isinstance(val, list) else ([val] if isinstance(val, str) else [])
            for p_cand in candidates:
                if not isinstance(p_cand, str) or not p_cand.strip():
                    continue
                found_explicit_path = True
                forb, reason = _is_worker_forbidden_path(
                    p_cand,
                    my_handle=handle,
                    profiles_dir=eff_profiles,
                    db_path=eff_db,
                )
                if forb:
                    return {
                        "action": "short_circuit",
                        "result": _tool_result(
                            f"[claude-mem-proxy] Access denied ({tname}): {reason}",
                            is_error=True,
                        ),
                    }
        if tname == "smart_search" and not found_explicit_path:
            return {
                "action": "short_circuit",
                "result": _tool_result(
                    "[claude-mem-proxy] Access denied (smart_search): worker must provide an explicit allowed path parameter.",
                    is_error=True,
                ),
            }
        return {"action": "forward", "arguments": args}

    # Worker: `get_observations(ids=...)` anti-IDOR SQLite RO verification
    if tname == "get_observations":
        parsed_ids, had_input = _parse_ids_arg(args.get("ids"))
        if not had_input or not parsed_ids:
            return {
                "action": "short_circuit",
                "result": _tool_result(
                    json.dumps({"observations": [], "filtered": True}, ensure_ascii=False),
                    is_error=False,
                ),
            }
        db_ok, owned_ids, db_err = _query_owned_observation_ids(
            eff_db, parsed_ids, expected_project
        )
        if not db_ok:
            return {
                "action": "short_circuit",
                "result": _tool_result(
                    f"[claude-mem-proxy] Access denied (fail-closed): {db_err}",
                    is_error=True,
                ),
            }
        if not owned_ids:
            return {
                "action": "short_circuit",
                "result": _tool_result(
                    json.dumps(
                        {
                            "observations": [],
                            "filtered_out_cross_bot": len(parsed_ids),
                            "project": expected_project,
                        },
                        ensure_ascii=False,
                    ),
                    is_error=False,
                ),
            }
        args["ids"] = owned_ids
        args["project"] = expected_project
        for fk in _FORGED_PROJECT_KEYS:
            args.pop(fk, None)
        return {"action": "forward", "arguments": args}

    # Worker: `timeline` (verify anchor ownership if provided + force project)
    if tname == "timeline":
        if "anchor" in args and args.get("anchor") not in (None, ""):
            anchor_id = _parse_int_id(args.get("anchor"))
            if anchor_id is None:
                return {
                    "action": "short_circuit",
                    "result": _tool_result(
                        "[claude-mem-proxy] Access denied: invalid timeline anchor ID.",
                        is_error=True,
                    ),
                }
            db_ok, is_owned, db_err = _check_observation_anchor_owner(
                eff_db, anchor_id, expected_project
            )
            if not db_ok:
                return {
                    "action": "short_circuit",
                    "result": _tool_result(
                        f"[claude-mem-proxy] Access denied (fail-closed): {db_err}",
                        is_error=True,
                    ),
                }
            if not is_owned:
                return {
                    "action": "short_circuit",
                    "result": _tool_result(
                        f"[claude-mem-proxy] Access denied: timeline anchor {anchor_id} does not belong to {expected_project}.",
                        is_error=True,
                    ),
                }
            args["anchor"] = anchor_id

        args["project"] = expected_project
        for fk in _FORGED_PROJECT_KEYS:
            args.pop(fk, None)
        return {"action": "forward", "arguments": args}

    # Worker: All other scoped read & write tools
    if tname in SCOPED_READ_TOOLS or tname in SCOPED_WRITE_TOOLS:
        if tname in NO_PROJECT_ARG_TOOLS:
            args.pop("project", None)
        else:
            args["project"] = expected_project
        for fk in _FORGED_PROJECT_KEYS:
            args.pop(fk, None)
        return {"action": "forward", "arguments": args}

    # Defensive fallback (unreachable)
    return {
        "action": "short_circuit",
        "result": _tool_result(
            f"[claude-mem-proxy] Access denied (fail-closed): unhandled tool '{tname}'.",
            is_error=True,
        ),
    }


# ---------------------------------------------------------------------------
# Stdio JSON-RPC Transport (Dual NDJSON & Content-Length framing support)
# ---------------------------------------------------------------------------


def _read_jsonrpc_message(stream: Any) -> tuple[dict[str, Any] | None, str]:
    """Read one JSON-RPC message from a binary stream, supporting NDJSON and Content-Length."""
    while True:
        line = stream.readline()
        if not line:
            return None, "ndjson"
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith(b"content-length:"):
            try:
                content_len = int(stripped.split(b":", 1)[1].strip())
            except ValueError:
                continue
            # Consume remaining headers until empty line
            while True:
                hdr = stream.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            if content_len <= 0:
                continue
            body = stream.read(content_len)
            if not body:
                return None, "lsp"
            try:
                msg = json.loads(body.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict):
                return msg, "lsp"
            continue
        try:
            msg = json.loads(stripped.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict):
            return msg, "ndjson"


def _write_jsonrpc_message(stream: Any, msg: dict[str, Any], *, framing: str = "ndjson") -> None:
    raw = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if framing == "lsp":
        header = f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii")
        stream.write(header + raw)
    else:
        stream.write(raw + b"\n")
    stream.flush()


def _resolve_upstream_cmd() -> list[str]:
    override = os.environ.get("CLAUDE_MEM_UPSTREAM_CMD", "").strip()
    if override:
        try:
            parsed = json.loads(override)
            if isinstance(parsed, list) and all(isinstance(x, str) for x in parsed) and parsed:
                return parsed
        except json.JSONDecodeError:
            pass
    bun_bin = os.environ.get("AGY_BUN_BIN", str(Path.home() / ".bun" / "bin" / "bun"))
    mcp_cjs = os.environ.get(
        "CLAUDE_MEM_MCP_CJS",
        str(
            Path.home()
            / ".claude"
            / "plugins"
            / "marketplaces"
            / "thedotmack"
            / "plugin"
            / "scripts"
            / "mcp-server.cjs"
        ),
    )
    return [bun_bin, mcp_cjs]


def _has_git_ancestor(path: Path) -> bool:
    cur = path.resolve(strict=False)
    for anc in (cur, *cur.parents):
        if (anc / ".git").exists():
            return True
    return False


def _resolve_worker_sentinel_cwd(
    env: Mapping[str, str] | None = None,
    *,
    profiles_dir: str | Path | None = None,
) -> Path | None:
    """Resolve and create a non-git per-bot sentinel `cwd` for Worker upstream `mcp-server.cjs`.

    Isolates `work_state_read` / `work_state_write` (which derive project name from `process.cwd()`).
    Falls back to `<tempdir>/agy-mem-cwd-<uid>/<handle>/bot-<handle>` (`0700`) if the profiles dir
    resides inside a git repository.
    """
    eff_env = env if env is not None else os.environ
    raw_handle = str(eff_env.get("AGY_BOT_HANDLE") or "").strip()
    handle = bot_profiles.normalize_bot_handle(raw_handle)
    role = str(eff_env.get("AGY_BOT_BUS_ROLE") or "worker").strip().lower()
    if not handle or role == "coordinator":
        return None

    eff_profiles = bot_profiles.resolve_profiles_dir(
        profiles_dir if profiles_dir is not None else eff_env.get("AGY_BOT_PROFILES_DIR")
    )
    try:
        sentinel = bot_profiles.ensure_mem_cwd_sentinel(handle, profiles_dir=eff_profiles)
        if not _has_git_ancestor(sentinel):
            return sentinel
    except Exception:
        pass

    uid = os.getuid() if hasattr(os, "getuid") else 0
    fb_root = Path(tempfile.gettempdir()) / f"agy-mem-cwd-{uid}"
    fb_bot = fb_root / handle
    fb_sentinel = fb_bot / f"bot-{handle}"
    for d in (fb_root, fb_bot, fb_sentinel):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
    return fb_sentinel


def run_proxy() -> int:
    upstream_cmd = _resolve_upstream_cmd()
    stdout_lock = threading.Lock()
    client_framing = ["ndjson"]
    upstream_proc: list[subprocess.Popen[bytes] | None] = [None]
    pump_thread: list[threading.Thread | None] = [None]
    stopping = threading.Event()

    def _emit_to_client(msg: dict[str, Any]) -> None:
        with stdout_lock:
            try:
                _write_jsonrpc_message(sys.stdout.buffer, msg, framing=client_framing[0])
            except (BrokenPipeError, OSError):
                stopping.set()

    def _pump_upstream_stdout(proc: subprocess.Popen[bytes]) -> None:
        assert proc.stdout is not None
        try:
            while not stopping.is_set():
                msg, _fr = _read_jsonrpc_message(proc.stdout)
                if msg is None:
                    break
                _emit_to_client(msg)
        finally:
            stopping.set()

    def _ensure_upstream() -> subprocess.Popen[bytes]:
        if upstream_proc[0] is not None and upstream_proc[0].poll() is None:
            return upstream_proc[0]
        sentinel_cwd = _resolve_worker_sentinel_cwd()
        popen_kwargs: dict[str, Any] = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": sys.stderr,
        }
        if sentinel_cwd is not None:
            popen_kwargs["cwd"] = str(sentinel_cwd)
        proc = subprocess.Popen(upstream_cmd, **popen_kwargs)
        upstream_proc[0] = proc
        t = threading.Thread(target=_pump_upstream_stdout, args=(proc,), daemon=True)
        pump_thread[0] = t
        t.start()
        return proc

    def _handle_signal(_signum: int, _frame: Any) -> None:
        stopping.set()
        proc = upstream_proc[0]
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    try:
        while not stopping.is_set():
            msg, framing = _read_jsonrpc_message(sys.stdin.buffer)
            if msg is None:
                break
            client_framing[0] = framing
            method = str(msg.get("method") or "")
            req_id = msg.get("id")

            if method == "tools/call":
                params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
                tool_name = str(params.get("name") or "")
                tool_args = params.get("arguments")
                decision = evaluate_mcp_tool_call(tool_name, tool_args)
                if decision["action"] == "short_circuit":
                    if req_id is not None:
                        _emit_to_client(
                            {
                                "jsonrpc": "2.0",
                                "id": req_id,
                                "result": decision["result"],
                            }
                        )
                    continue
                new_params = dict(params)
                new_params["arguments"] = decision["arguments"]
                msg = dict(msg)
                msg["params"] = new_params

            try:
                proc = _ensure_upstream()
                assert proc.stdin is not None
                _write_jsonrpc_message(proc.stdin, msg, framing="ndjson")
            except Exception as exc:
                if req_id is not None:
                    _emit_to_client(
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": _tool_result(
                                f"[claude-mem-proxy] Upstream MCP unavailable: {type(exc).__name__}",
                                is_error=True,
                            ),
                        }
                    )
    finally:
        proc = upstream_proc[0]
        if proc is not None:
            try:
                if proc.stdin:
                    proc.stdin.close()
            except OSError:
                pass
            pt = pump_thread[0]
            if pt is not None and pt.is_alive():
                pt.join(timeout=3.0)
            stopping.set()
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except OSError:
                        pass
        else:
            stopping.set()
    return 0


if __name__ == "__main__":
    sys.exit(run_proxy())
