#!/usr/bin/env python3
"""Per-Bot Mechanical Isolation `PreToolUse` Guardrail for Antigravity CLI.

Runs on BOTH clean (non-tainted) AND tainted sessions whenever `AGY_BOT_HANDLE` is set:
- Standalone manual CLI (no `AGY_BOT_HANDLE` in env): immediately passes with empty stdout `""` + exit 0.
- Coordinator (`AGY_BOT_BUS_ROLE == "coordinator"`): permits read-only inspection across all
  `bots/**` and `.agents/skills/**` (passes with empty stdout `""` + exit 0).
- Worker (`AGY_BOT_HANDLE` set and `AGY_BOT_BUS_ROLE != "coordinator"`):
  1. Denies reading, listing, searching, or modifying any sibling bot's profile directory
     (`<AGY_BOT_PROFILES_DIR>/<other_handle>/**` or enumerating `<AGY_BOT_PROFILES_DIR>` root),
     defending against `../`, symlinks, `~`/`$HOME`/`$AGY_BOT_PROFILES_DIR`, and shell commands.
  2. Denies direct access/copy/query to `~/.claude-mem/claude-mem.db*` (including `-wal`/`-shm`
     and `CLAUDE_MEM_DB_PATH`) via file tools or shell commands (`sqlite3`, `python`, `cat`, etc.).
  3. Denies reading or modifying unauthorized catalog skills under `.agents/skills/<slug>/**`
     when `<slug>` is not enabled in the worker's `profile.json` `skills_policy`
     (without false-blocking generic repository commands like `git`, `unittest`, or `verify_gate.py`).

CRITICAL OUTPUT CONTRACT:
- Deny: `{"decision": "deny", "reason": "[bot-isolation-guard] ..."}` + exit 0.
- Pass: strictly EMPTY stdout (`""`) + exit 0 (NEVER `{}` and NEVER `{"decision": "allow"}`).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping


def _load_bridge_modules():
    candidates = [
        Path(__file__).resolve().parents[1] / "bridge",
        Path(os.environ.get("AGY_BRIDGE_DIR", str(Path.home() / "agy-tg-bridge"))),
    ]
    for cand in candidates:
        if (cand / "bot_profiles.py").is_file() or (cand / "memory_guard.py").is_file():
            if str(cand) not in sys.path:
                sys.path.insert(0, str(cand))
            break
    bp = None
    mg = None
    try:
        import bot_profiles as _bp  # type: ignore

        bp = _bp
    except Exception:
        bp = None
    try:
        import memory_guard as _mg  # type: ignore

        mg = _mg
    except Exception:
        mg = None
    return bp, mg


_BOT_PROFILES, _MEMORY_GUARD = _load_bridge_modules()

_PATH_ARG_KEYS: tuple[str, ...] = (
    "Path",
    "TargetFile",
    "target_file",
    "path",
    "file_path",
    "FilePath",
    "DestinationPath",
    "destination",
    "DirectoryPath",
    "SearchPath",
    "SearchDirectory",
    "directory",
    "dir",
    "root",
    "AbsolutePath",
    "TargetDirectory",
)

_SKILL_SEG_RE = re.compile(r"(?:^|/)\.agents/skills/([^/\s'\"`;&|]+)(?:/|$)")
_SKILLS_ROOT_RE = re.compile(r"(?:^|/)\.agents/skills/?$")
_BOTS_SEG_RE = re.compile(r"(?:^|/)\.config/agy-tg-bridge/bots(?:/([^/\s'\"`;&|]+))?(?:/|$)")
_BRIDGE_CFG_RE = re.compile(r"(?:^|/)\.config/agy-tg-bridge(?:/(.*))?$")
_CLAUDE_MEM_DIR_RE = re.compile(r"(?i)(?:^|/)\.claude-mem(?:/|$)")
_CLAUDE_MEM_DB_RE = re.compile(r"(?i)(?:^|/)claude-mem\.db(?:-wal|-shm)?(?:$|[/'\"\s;&|])")
_HOME_VAR_RE = re.compile(r"\$\{HOME\}|\$HOME(?=/|$)")
_PROFILES_VAR_RE = re.compile(r"\$\{AGY_BOT_PROFILES_DIR\}|\$AGY_BOT_PROFILES_DIR(?=/|$)")
_DB_VAR_RE = re.compile(r"\$\{CLAUDE_MEM_DB_PATH\}|\$CLAUDE_MEM_DB_PATH(?=/|$)")
_DATA_DIR_VAR_RE = re.compile(r"\$\{CLAUDE_MEM_DATA_DIR\}|\$CLAUDE_MEM_DATA_DIR(?=/|$)")
_BUS_DIR_VAR_RE = re.compile(r"\$\{AGY_BOT_BUS_DIR\}|\$AGY_BOT_BUS_DIR(?=/|$)")
_FEDERATION_PATH_RE = re.compile(
    r"(?i)(?:^|/)bot_bus/federation(?:/|$)|(?:^|/)federation/(?:agents\.json|teams\.json|federation\.lock|pull_queue)(?:/|$)"
)
_FEDERATION_CMD_RE = re.compile(
    r"(?i)(?:bot_bus/federation(?:/|$|[\s'\"`;&|<>()])|(?<![A-Za-z0-9_.-])federation/(?:agents\.json|teams\.json|federation\.lock|pull_queue)(?:/|$|[\s'\"`;&|<>()]))"
)

_WRITE_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "write_file",
        "edit_file",
        "replace_file_content",
        "multi_replace_file_content",
        "write_to_file",
        "create_file",
        "delete_file",
        "remove_file",
        "move_file",
        "rename_file",
        "apply_patch",
    }
)

_SHELL_MUTATOR_BINS: frozenset[str] = frozenset(
    {
        "tee",
        "sed",
        "perl",
        "python",
        "python2",
        "python3",
        "node",
        "nodejs",
        "bun",
        "deno",
        "ruby",
        "php",
        "awk",
        "gawk",
        "mawk",
        "ed",
        "ex",
        "vi",
        "vim",
        "nvim",
        "nano",
        "mv",
        "cp",
        "rm",
        "unlink",
        "ln",
        "chmod",
        "chown",
        "chgrp",
        "touch",
        "truncate",
        "dd",
        "install",
        "mkdir",
        "rmdir",
        "rsync",
        "tar",
        "unzip",
        "patch",
        "sponge",
        "sqlite3",
        "xargs",
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
    }
)
_SHELL_WRITE_REDIR_RE = re.compile(r"(?:>>|&>|<>|(?<![0-9&])>(?!&[12](?:\s|$))|[0-9]+>(?!&[12](?:\s|$)))")


def _effective_home(env: Mapping[str, str]) -> str:
    val = str(env.get("HOME") or "").strip()
    return os.path.normpath(val) if val else os.path.normpath(str(Path.home()))


def _resolve_profiles_root(env: Mapping[str, str]) -> Path:
    raw = str(env.get("AGY_BOT_PROFILES_DIR") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path(_effective_home(env)) / ".config" / "agy-tg-bridge" / "bots"


def _resolve_db_path(env: Mapping[str, str]) -> Path:
    raw = str(env.get("CLAUDE_MEM_DB_PATH") or "").strip()
    if raw:
        return Path(raw).expanduser()
    data_dir = str(env.get("CLAUDE_MEM_DATA_DIR") or "").strip()
    if data_dir:
        return Path(data_dir).expanduser() / "claude-mem.db"
    return Path(_effective_home(env)) / ".claude-mem" / "claude-mem.db"


def _resolve_bus_dir(env: Mapping[str, str]) -> Path:
    raw = str(env.get("AGY_BOT_BUS_DIR") or "").strip()
    if raw:
        return Path(raw).expanduser()
    return Path(_effective_home(env)) / ".gemini" / "antigravity-cli" / "cache" / "bot_bus"


def _normalize_handle(raw: str) -> str | None:
    if _BOT_PROFILES is not None:
        return _BOT_PROFILES.normalize_bot_handle(raw)
    s = str(raw or "").strip().lstrip("@").lower()
    if not s or "/" in s or "\\" in s or ".." in s or "\x00" in s:
        return None
    if re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", s):
        return s
    return None


def _get_worker_skill_policy(handle: str, profiles_root: Path) -> tuple[str, set[str]]:
    if _BOT_PROFILES is not None:
        return _BOT_PROFILES.get_worker_allowed_catalog_slugs(handle, profiles_dir=profiles_root)
    pjson = profiles_root / handle / "profile.json"
    if not pjson.is_file():
        return "allowlist", set()
    try:
        data = json.loads(pjson.read_text(encoding="utf-8", errors="replace"))
        pol = data.get("skills_policy") if isinstance(data, dict) else {}
        mode = str((pol or {}).get("mode") or "allowlist").strip().lower()
        en = (pol or {}).get("enabled_catalog_skills") or []
        return mode, {str(x) for x in en if isinstance(x, str)}
    except Exception:
        return "allowlist", set()


def _expand_path_candidates(
    raw_token: str,
    *,
    cwd: str,
    env: Mapping[str, str],
    profiles_root: Path,
    db_path: Path,
    bus_dir: Path | None = None,
) -> tuple[str, str]:
    eff_home = _effective_home(env)
    eff_bus = bus_dir if bus_dir is not None else _resolve_bus_dir(env)
    s = str(raw_token or "").strip().strip("'\"")
    if not s:
        return "", ""
    # Strip shell prefix chars like leading at-sign file syntax or file:// URI
    if s.startswith("file://"):
        s = s[7:]
    if s.startswith("@") and len(s) > 1 and ("/" in s or "." in s):
        s = s[1:]
    s = _HOME_VAR_RE.sub(eff_home, s)
    s = _PROFILES_VAR_RE.sub(str(profiles_root), s)
    s = _DB_VAR_RE.sub(str(db_path), s)
    s = _DATA_DIR_VAR_RE.sub(str(db_path.parent), s)
    s = _BUS_DIR_VAR_RE.sub(str(eff_bus), s)
    if s == "~":
        s = eff_home
    elif s.startswith("~/"):
        s = eff_home + s[1:]
    if not os.path.isabs(s) and cwd:
        s = os.path.join(cwd, s)
    norm_p = os.path.normpath(s).replace("\\", "/")
    try:
        res_p = str(Path(norm_p).resolve(strict=False)).replace("\\", "/")
    except Exception:
        res_p = norm_p
    return norm_p, res_p


def _is_federation_registry_path(
    raw_path: str,
    norm_p: str,
    res_p: str,
    *,
    env: Mapping[str, str],
    bus_dir: Path,
) -> bool:
    """Return True if path targets `<BUS_DIR>/federation` or any federation registry/queue file (B3)."""
    eff_home = _effective_home(env)
    fed_roots: list[str] = []
    for base_fed in (
        bus_dir / "federation",
        Path(eff_home) / ".gemini" / "antigravity-cli" / "cache" / "bot_bus" / "federation",
    ):
        rn = os.path.normpath(str(base_fed)).replace("\\", "/").rstrip("/")
        if rn:
            fed_roots.append(rn)
        try:
            rr = str(base_fed.resolve(strict=False)).replace("\\", "/").rstrip("/")
            if rr and rr not in fed_roots:
                fed_roots.append(rr)
        except Exception:
            pass

    raw_clean = str(raw_path or "").strip().strip("'\"").replace("\\", "/")
    if raw_clean.startswith("./"):
        raw_clean = raw_clean[2:]
    extra_cands = [raw_clean, norm_p, res_p]
    if norm_p:
        try:
            rp = os.path.realpath(norm_p).replace("\\", "/")
            if rp not in extra_cands:
                extra_cands.append(rp)
        except Exception:
            pass

    for cand in extra_cands:
        if not cand:
            continue
        if _FEDERATION_PATH_RE.search(cand):
            return True
        for root_s in fed_roots:
            if cand == root_s or cand.startswith(root_s + "/"):
                return True
    return False


def _check_single_path(
    raw_path: str,
    *,
    my_handle: str,
    cwd: str,
    env: Mapping[str, str],
    profiles_root: Path,
    db_path: Path,
    skill_policy: tuple[str, set[str]],
    is_write: bool = False,
    bus_dir: Path | None = None,
) -> tuple[bool, str]:
    if not raw_path or not str(raw_path).strip():
        return False, ""
    eff_bus = bus_dir if bus_dir is not None else _resolve_bus_dir(env)
    norm_p, res_p = _expand_path_candidates(
        raw_path,
        cwd=cwd,
        env=env,
        profiles_root=profiles_root,
        db_path=db_path,
        bus_dir=eff_bus,
    )
    if _is_federation_registry_path(raw_path, norm_p, res_p, env=env, bus_dir=eff_bus):
        return (
            True,
            "direct access to federation registry (<BUS_DIR>/federation) is forbidden for bot sessions; Owner-only",
        )
    p_root_norm = os.path.normpath(str(profiles_root)).replace("\\", "/").rstrip("/")
    p_root_res = str(profiles_root.resolve(strict=False)).replace("\\", "/").rstrip("/")
    p_parent_norm = os.path.normpath(str(profiles_root.parent)).replace("\\", "/").rstrip("/")
    p_parent_res = str(profiles_root.parent.resolve(strict=False)).replace("\\", "/").rstrip("/")
    protect_p_parent = profiles_root.parent.name == "agy-tg-bridge"
    bots_subdir = profiles_root.name.lower() or "bots"

    db_norm = os.path.normpath(str(db_path)).replace("\\", "/")
    db_res = str(db_path.resolve(strict=False)).replace("\\", "/")
    db_dir_norm = os.path.normpath(str(db_path.parent)).replace("\\", "/").rstrip("/")
    db_dir_res = str(db_path.parent.resolve(strict=False)).replace("\\", "/").rstrip("/")
    db_dir_is_mem = db_path.parent.name.lower() in (".claude-mem", "claude-mem")

    cwd_norm = os.path.normpath(cwd).replace("\\", "/").rstrip("/") if cwd else ""
    try:
        cwd_res = str(Path(cwd).resolve(strict=False)).replace("\\", "/").rstrip("/") if cwd else ""
    except Exception:
        cwd_res = cwd_norm

    policy_mode, allowed_catalog = skill_policy
    write_deny_reason = (
        "direct writes to bot profile directory are forbidden for worker; "
        "use Studio/Bridge Single-Writer"
    )

    for cand in (norm_p, res_p):
        if not cand:
            continue
        low = cand.lower()

        # 1. Direct claude-mem directory and claude-mem.db* access
        for db_cand in (db_norm, db_res):
            if (
                cand == db_cand
                or cand.startswith(db_cand + "-")
                or cand.startswith(db_cand + ".")
            ):
                return True, "direct access to claude-mem.db is forbidden for worker; use claude-mem MCP"
        if "/.claude-mem/claude-mem.db" in low or _CLAUDE_MEM_DB_RE.search(low):
            return True, "direct access to claude-mem.db is forbidden for worker; use claude-mem MCP"
        if _CLAUDE_MEM_DIR_RE.search(cand):
            return True, "direct access to ~/.claude-mem directory is forbidden for worker; use claude-mem MCP"
        for db_dir in (db_dir_norm, db_dir_res):
            if not db_dir:
                continue
            if db_dir_is_mem:
                if cand == db_dir or cand.startswith(db_dir + "/"):
                    return True, "direct access to claude-mem data directory is forbidden for worker; use claude-mem MCP"
            elif cand == db_dir:
                is_cwd_or_ancestor = any(
                    cw and (cw == db_dir or cw.startswith(db_dir + "/"))
                    for cw in (cwd_norm, cwd_res)
                )
                if not is_cwd_or_ancestor:
                    return True, "direct access to claude-mem data directory is forbidden for worker; use claude-mem MCP"

        # 2. Cross-bot profile directory, bridge config parent dir, and worker self-write isolation
        for root_c in (p_root_norm, p_root_res):
            if cand == root_c:
                if is_write:
                    return True, write_deny_reason
                return True, f"accessing shared bots profile root is forbidden for worker @{my_handle}"
            if cand.startswith(root_c + "/"):
                if is_write:
                    return True, write_deny_reason
                rest = cand[len(root_c) + 1 :]
                target_bot = rest.split("/", 1)[0].lower()
                if target_bot and target_bot != my_handle:
                    return True, f"cross-bot profile access denied: worker @{my_handle} cannot access @{target_bot}"

        if protect_p_parent:
            allowed_sub_prefix = f"{bots_subdir}/{my_handle}"
            for p_root_parent in (p_parent_norm, p_parent_res):
                if not p_root_parent:
                    continue
                if cand == p_root_parent:
                    if is_write:
                        return True, write_deny_reason
                    return True, f"accessing bridge config root is forbidden for worker @{my_handle}"
                if cand.startswith(p_root_parent + "/"):
                    if is_write:
                        return True, write_deny_reason
                    sub_low = cand[len(p_root_parent) + 1 :].lower()
                    if not (
                        sub_low == allowed_sub_prefix
                        or sub_low.startswith(allowed_sub_prefix + "/")
                    ):
                        return True, f"accessing bridge config path outside own bot profile is forbidden for worker @{my_handle}"

        m_cfg = _BRIDGE_CFG_RE.search(cand)
        if m_cfg:
            if is_write:
                return True, write_deny_reason
            sub_low = (m_cfg.group(1) or "").strip("/").lower()
            allowed_cfg_prefix = f"bots/{my_handle}"
            if not (
                sub_low == allowed_cfg_prefix
                or sub_low.startswith(allowed_cfg_prefix + "/")
            ):
                return True, f"accessing .config/agy-tg-bridge outside own bot profile is forbidden for worker @{my_handle}"

        m_bots = _BOTS_SEG_RE.search(cand)
        if m_bots:
            if is_write:
                return True, write_deny_reason
            target_bot = (m_bots.group(1) or "").lower()
            if not target_bot or target_bot != my_handle:
                return True, f"cross-bot profile access denied for worker @{my_handle}"

        # 3. Unauthorized catalog `.agents/skills` root or `.agents/skills/<slug>/**` access
        if policy_mode != "all" and _SKILLS_ROOT_RE.search(cand):
            return True, f"enumerating or searching .agents/skills root is forbidden for worker @{my_handle}"
        m_skill = _SKILL_SEG_RE.search(cand)
        if m_skill:
            slug = m_skill.group(1)
            if policy_mode != "all" and slug not in allowed_catalog:
                return True, f"unauthorized catalog skill access denied for worker @{my_handle}: {slug}"

    return False, ""


def _shell_command_may_write(cmd: str) -> bool:
    """Return True if a shell command uses output redirection or invokes a mutating binary."""
    if not cmd:
        return False
    if _SHELL_WRITE_REDIR_RE.search(cmd):
        return True

    if _MEMORY_GUARD is not None:
        try:
            raw_segs = _MEMORY_GUARD._split_shell_segments(cmd)
        except Exception:
            raw_segs = re.split(r"(?:&&|\|\||[;\n|])", cmd)
    else:
        raw_segs = re.split(r"(?:&&|\|\||[;\n|])", cmd)

    # Also split subshell / command substitution boundaries so `$(python3 ...)` is inspected
    segs: list[str] = []
    for seg in raw_segs:
        for sub in re.split(r"(?:\$\(|`|(?<!\\)[()])", seg):
            s = sub.strip()
            if s:
                segs.append(s)

    wrapper_bins = {
        "env",
        "sudo",
        "doas",
        "command",
        "builtin",
        "exec",
        "nohup",
        "nice",
        "ionice",
        "timeout",
        "time",
        "stdbuf",
        "flock",
    }

    for seg in segs:
        if _MEMORY_GUARD is not None:
            try:
                toks = _MEMORY_GUARD._tokenize_segment(seg)
            except Exception:
                toks = seg.split()
        else:
            toks = seg.split()

        idx = 0
        while idx < len(toks):
            tok = toks[idx].strip().strip("'\"")
            if not tok:
                idx += 1
                continue
            # Skip leading KEY=VAL env assignments
            if "=" in tok and not tok.startswith("-") and not tok.startswith("/"):
                idx += 1
                continue
            base = os.path.basename(tok).lower()
            if base in wrapper_bins:
                idx += 1
                while idx < len(toks):
                    nxt = toks[idx].strip().strip("'\"")
                    if not nxt:
                        idx += 1
                        continue
                    if nxt.startswith("-") or ("=" in nxt and not nxt.startswith("/")):
                        idx += 1
                        continue
                    if base in ("timeout", "nice") and re.fullmatch(r"[0-9]+(?:\.[0-9]+)?[smhd]?", nxt):
                        idx += 1
                        continue
                    break
                continue
            if base in _SHELL_MUTATOR_BINS:
                return True
            if base == "find" and any(
                t in ("-delete", "-exec", "-execdir", "-ok", "-okdir") for t in toks[idx + 1 :]
            ):
                return True
            break
    return False


def _extract_shell_candidate_tokens(cmd: str) -> list[str]:
    """Extract shell argument tokens, redirection targets, and inline path literals."""
    tokens: list[str] = []
    if not cmd:
        return tokens
    if _MEMORY_GUARD is not None:
        try:
            segs = _MEMORY_GUARD._split_shell_segments(cmd)
        except Exception:
            segs = [cmd]
        for seg in segs:
            out_r, in_r = _MEMORY_GUARD._extract_shell_redirections(seg)
            tokens.extend(out_r)
            tokens.extend(in_r)
            toks = _MEMORY_GUARD._tokenize_segment(seg)
            tokens.extend(toks)
            for t in toks:
                if "=" in t and not t.startswith("-"):
                    tokens.append(t.split("=", 1)[1])
    else:
        tokens.extend(re.findall(r"[^\s'\"`;&|<>()]+", cmd))

    # Also catch quoted path substrings inside inline python/awk/sqlite3 scripts
    inline_hits = re.findall(
        r"(?:(?:\$\{?(?:HOME|AGY_BOT_PROFILES_DIR|CLAUDE_MEM_DB_PATH|CLAUDE_MEM_DATA_DIR|AGY_BOT_BUS_DIR)\}?)|(?:~|/|\.\./)[^\s'\"`;&|<>(),\]]+)[^\s'\"`;&|<>(),\]]*",
        cmd,
    )
    tokens.extend(inline_hits)
    # Catch relative `.agents/skills`, `.claude-mem`, `.config/agy-tg-bridge`, `bots/<handle>`, `bot_bus/federation`, `federation/*`, or DB references inside inline scripts
    rel_hits = re.findall(
        r"(?:\.agents/skills(?:/[^\s'\"`;&|<>(),\]]*)?|\.claude-mem(?:/[^\s'\"`;&|<>(),\]]*)?|\.config/agy-tg-bridge(?:/[^\s'\"`;&|<>(),\]]*)?|bots/[a-zA-Z0-9_.-]+(?:/[^\s'\"`;&|<>(),\]]*)?|bot_bus/federation(?:/[^\s'\"`;&|<>(),\]]*)?|federation/(?:agents\.json|teams\.json|federation\.lock|pull_queue(?:/[^\s'\"`;&|<>(),\]]*)?)|claude-mem\.db(?:-wal|-shm)?)",
        cmd,
    )
    tokens.extend(rel_hits)
    return tokens


def evaluate_bot_isolation_tool_call(
    tool_name: str,
    tool_args: Mapping[str, Any],
    *,
    cwd: str = "",
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Evaluate a `PreToolUse` tool call for per-bot isolation boundaries."""
    eff_env = env if env is not None else os.environ
    raw_handle = str(eff_env.get("AGY_BOT_HANDLE") or "").strip()
    if not raw_handle:
        return {"blocked": False, "reason": ""}

    my_handle = _normalize_handle(raw_handle)
    if not my_handle:
        return {
            "blocked": True,
            "reason": "[bot-isolation-guard] Fail-closed: invalid AGY_BOT_HANDLE format",
        }

    role = str(eff_env.get("AGY_BOT_BUS_ROLE") or "worker").strip().lower()
    profiles_root = _resolve_profiles_root(eff_env)
    db_path = _resolve_db_path(eff_env)
    bus_dir = _resolve_bus_dir(eff_env)
    skill_policy = _get_worker_skill_policy(my_handle, profiles_root) if role != "coordinator" else ("all", set())

    tname = str(tool_name or "").strip()
    args = dict(tool_args) if isinstance(tool_args, Mapping) else {}

    # 1. File / directory tools
    path_candidates: list[str] = []
    for key in _PATH_ARG_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            path_candidates.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    path_candidates.append(item)

    # Also check nested `Files` or `paths` arrays if present
    for list_key in ("Paths", "paths", "Files", "files"):
        val = args.get(list_key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.strip():
                    path_candidates.append(item)

    fed_deny_msg = (
        "[bot-isolation-guard] direct access to federation registry (<BUS_DIR>/federation) "
        "is forbidden for bot sessions; Owner-only"
    )
    if role == "coordinator":
        # Coordinator retains full bots/** and skills access, but STILL cannot read/tamper <BUS_DIR>/federation/ (B3).
        for cand in path_candidates:
            norm_p, res_p = _expand_path_candidates(
                cand,
                cwd=cwd,
                env=eff_env,
                profiles_root=profiles_root,
                db_path=db_path,
                bus_dir=bus_dir,
            )
            if _is_federation_registry_path(cand, norm_p, res_p, env=eff_env, bus_dir=bus_dir):
                return {"blocked": True, "reason": fed_deny_msg}
        if tname == "run_command":
            cmd = str(args.get("CommandLine") or args.get("command") or args.get("cmd") or "")
            if cmd.strip():
                if _FEDERATION_CMD_RE.search(cmd) or (
                    "AGY_BOT_BUS_DIR" in cmd and "federation" in cmd.lower()
                ):
                    return {"blocked": True, "reason": fed_deny_msg}
                for tok in _extract_shell_candidate_tokens(cmd):
                    if not tok or tok.startswith("-"):
                        continue
                    norm_p, res_p = _expand_path_candidates(
                        tok,
                        cwd=cwd,
                        env=eff_env,
                        profiles_root=profiles_root,
                        db_path=db_path,
                        bus_dir=bus_dir,
                    )
                    if _is_federation_registry_path(tok, norm_p, res_p, env=eff_env, bus_dir=bus_dir):
                        return {"blocked": True, "reason": fed_deny_msg}
        return {"blocked": False, "reason": ""}

    is_write_tool = tname.lower() in _WRITE_TOOL_NAMES
    for cand in path_candidates:
        blocked, reason = _check_single_path(
            cand,
            my_handle=my_handle,
            cwd=cwd,
            env=eff_env,
            profiles_root=profiles_root,
            db_path=db_path,
            skill_policy=skill_policy,
            is_write=is_write_tool,
            bus_dir=bus_dir,
        )
        if blocked:
            return {"blocked": True, "reason": f"[bot-isolation-guard] {reason}"}

    # 2. Shell command inspection (`run_command`)
    if tname == "run_command":
        cmd = str(args.get("CommandLine") or args.get("command") or args.get("cmd") or "")
        if cmd.strip():
            if _FEDERATION_CMD_RE.search(cmd) or (
                "AGY_BOT_BUS_DIR" in cmd and "federation" in cmd.lower()
            ):
                return {"blocked": True, "reason": fed_deny_msg}
            if _CLAUDE_MEM_DB_RE.search(cmd):
                return {
                    "blocked": True,
                    "reason": "[bot-isolation-guard] direct access to claude-mem.db is forbidden for worker; use claude-mem MCP",
                }
            # Direct check for env var referencing claude-mem DB or data dir
            if "CLAUDE_MEM_DB_PATH" in cmd or "CLAUDE_MEM_DATA_DIR" in cmd:
                return {
                    "blocked": True,
                    "reason": "[bot-isolation-guard] direct access to CLAUDE_MEM_DB_PATH/CLAUDE_MEM_DATA_DIR is forbidden for worker",
                }
            shell_is_write = _shell_command_may_write(cmd)
            for tok in _extract_shell_candidate_tokens(cmd):
                if not tok or tok.startswith("-"):
                    continue
                blocked, reason = _check_single_path(
                    tok,
                    my_handle=my_handle,
                    cwd=cwd,
                    env=eff_env,
                    profiles_root=profiles_root,
                    db_path=db_path,
                    skill_policy=skill_policy,
                    is_write=shell_is_write,
                    bus_dir=bus_dir,
                )
                if blocked:
                    return {"blocked": True, "reason": f"[bot-isolation-guard] {reason}"}

    return {"blocked": False, "reason": ""}


def _emit_deny(reason: str) -> int:
    clean = str(reason or "").strip() or "[bot-isolation-guard] Blocked cross-bot tool call"
    print(json.dumps({"decision": "deny", "reason": clean}, ensure_ascii=False))
    return 0


def _emit_pass() -> int:
    # Strictly empty stdout + exit 0 (never `{}` and never `{"decision": "allow"}`)
    return 0


def main() -> int:
    raw_handle = os.environ.get("AGY_BOT_HANDLE", "").strip()
    if not raw_handle:
        return _emit_pass()

    role = os.environ.get("AGY_BOT_BUS_ROLE", "worker").strip().lower()

    try:
        raw_stdin = sys.stdin.read()
        if not raw_stdin.strip():
            if role == "coordinator":
                return _emit_pass()
            return _emit_deny(
                "[bot-isolation-guard] Fail-closed: empty PreToolUse payload in worker session"
            )
        payload = json.loads(raw_stdin)
        if not isinstance(payload, dict):
            return _emit_deny(
                "[bot-isolation-guard] Fail-closed: malformed PreToolUse payload in worker session"
            )
        tool_call = payload.get("toolCall")
        if not isinstance(tool_call, dict):
            tool_call = payload.get("tool_call")
        if not isinstance(tool_call, dict):
            return _emit_deny(
                "[bot-isolation-guard] Fail-closed: missing toolCall object in worker session"
            )
        tool_name = str(
            tool_call.get("name") or payload.get("toolName") or payload.get("tool_name") or ""
        ).strip()
        raw_args = tool_call.get("args")
        if not isinstance(raw_args, dict):
            raw_args = tool_call.get("arguments")
        tool_args = raw_args if isinstance(raw_args, dict) else {}
        cwd = str(payload.get("cwd") or "")

        result = evaluate_bot_isolation_tool_call(
            tool_name,
            tool_args,
            cwd=cwd,
            env=os.environ,
        )
        if result.get("blocked"):
            return _emit_deny(str(result.get("reason") or ""))
        return _emit_pass()
    except Exception as exc:
        return _emit_deny(
            f"[bot-isolation-guard] Fail-closed internal error in worker session: {type(exc).__name__}"
        )


if __name__ == "__main__":
    sys.exit(main())
