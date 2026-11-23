"""Pluggable Agent Driver abstraction, registry, common security boundary, and `AgyDriver` / `AgySession`.

Architecture & Future Multi-Engine Onboarding (ACP / Claude Code / Codex CLI)
=============================================================================
This flat module decouples `bridge/bridge.py` from any single CLI backend while
enforcing shared security and isolation invariants at the `AgentSession` base layer:

1. **Normalized Stream Event Contract**:
   Every `AgentSession` emits normalized event dicts from `next_event(timeout)`:
   - `{"event": "init", "conversation_id": "<cid>"}`
   - `{"event": "step_update", "step_update": {"step_type": "tool", "state": "ACTIVE"|"DONE", "step_index": int, "tool_name": str, "tool_info": dict, "duration_seconds": float?}}`
   - `{"event": "step_update", "step_update": {"step_type": "agent_response", "state": "ACTIVE"|"DONE", "step_index": int, "text_delta": str, "thinking_delta": str?}}`
   - `{"event": "step_update", "step_update": {"step_type": "checkpoint", "state": "ACTIVE"|"DONE", "step_index": int, "duration_seconds": float?}}`
   - `{"event": "result", "result": {"status": "SUCCESS"|"ERROR"|"WAITING", "conversation_id": str?, "response": str?, "error": str?, "usage": dict?, "denied_actions": list?, "finished_reason": str?}}`
   - `{"event": "__eof__"}`

2. **Onboarding a New Backend Driver (e.g., ACP / Claude Code / Codex CLI)**:
   - Declare a `DriverCapabilities(engine_name="claude_code", supports_compact=..., ...)`
     so `bridge.py` knows whether `/compact`, session resume, or native tools apply.
   - Subclass `AgentSession` and call `self._init_common_state(...)` in `__init__` so
     readonly/untrusted downgrade, `AGY_RBAC_ROLE="readonly"`, untrusted observer/memory
     env flags, bot isolation env, and cross-driver `matches()` checks are inherited
     automatically instead of re-implemented per driver.
   - Use `build_base_session_env(self.security_context, scope_key=self.scope_key)` and
     `enforce_readonly_cli_args(cmd, self.security_context)` before spawning subprocesses.
   - Translate engine-native JSONL/JSON-RPC/ACP notifications (e.g. Claude Code
     `stream-json` `assistant`/`content_block_delta`/`tool_use`/`result`, Codex CLI
     `item.started`/`item.completed`/`turn.completed`, or ACP `session/update`) into the
     normalized event dicts above inside the driver's reader loop.
   - Subclass `AgentDriver` implementing `spawn_session(...)` and register it via:
     `agent_driver.register_driver("claude_code", ClaudeCodeDriver())`, then select it
     via `AGY_AGENT_DRIVER=claude_code` or explicit `driver="claude_code"` parameter.
   - Unknown driver names ALWAYS fail closed with `UnknownDriverError` (never silently
     falling back to `"agy"`).

Standalone-capable flat module (no top-level `import bridge`). When wired into
`bridge/bridge.py`, call `bind_host(bridge_module)` so dynamic config and
callbacks resolve at call time without circular imports.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import collections
import dataclasses
import json
import os
import queue
import signal
import subprocess
import threading
import time
from typing import Any, Dict, FrozenSet, List, Optional, Sequence

_host = None


def bind_host(host):
    """Bind the runtime bridge host module (or namespace) for lazy attribute resolution."""
    global _host
    _host = host
    return host


def _resolve_host(host=None):
    return host if host is not None else _host


def _host_attr(name: str, default: Any = None, *, host=None) -> Any:
    h = _resolve_host(host)
    if h is None:
        return default
    return getattr(h, name, default)


def _host_log(msg: str, *, host=None) -> None:
    fn = _host_attr("log", None, host=host)
    if callable(fn):
        fn(msg)


# ---------------------------------------------------------------- Process Tree Safe Termination
def _read_proc_stat_info(pid, proc_root="/proc"):
    """Read `(state, starttime)` from `/proc/<pid>/stat` using `rfind(')')` (safe for spaces/parens in comm)."""
    stat_path = os.path.join(proc_root, str(pid), "stat")
    try:
        with open(stat_path, "r", encoding="utf-8", errors="ignore") as fh:
            raw = fh.read()
    except OSError:
        return None, None
    idx = raw.rfind(")")
    if idx < 0:
        return None, None
    rest = raw[idx + 2:].split()
    if len(rest) <= 19:
        return None, None
    return rest[0], rest[19]


def _read_proc_starttime(pid, proc_root="/proc"):
    """Return process `starttime` (post-comm index 19) from `/proc/<pid>/stat`, or None."""
    _state, starttime = _read_proc_stat_info(pid, proc_root=proc_root)
    return starttime


def _read_proc_euid(pid, proc_root="/proc"):
    """Return effective UID from `/proc/<pid>/status` (`Uid:` line), or None on failure."""
    status_path = os.path.join(proc_root, str(pid), "status")
    try:
        with open(status_path, "r", encoding="utf-8", errors="ignore") as fh:
            raw = fh.read()
    except OSError:
        return None
    for line in raw.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            try:
                if len(parts) >= 3:
                    return int(parts[2])
                if len(parts) == 2:
                    return int(parts[1])
            except ValueError:
                return None
            return None
    return None


def _list_proc_children(pid, proc_root="/proc"):
    """Return direct child PIDs from `/proc/<pid>/task/*/children`."""
    task_dir = os.path.join(proc_root, str(pid), "task")
    children = []
    try:
        tids = os.listdir(task_dir)
    except OSError:
        return children
    for tid in tids:
        cpath = os.path.join(task_dir, tid, "children")
        try:
            with open(cpath, "r", encoding="utf-8", errors="ignore") as fh:
                data = fh.read().strip()
        except OSError:
            continue
        if not data:
            continue
        for tok in data.split():
            try:
                cpid = int(tok)
                if cpid > 1:
                    children.append(cpid)
            except ValueError:
                continue
    return children


def _collect_descendant_pids(root_pid, proc_root="/proc"):
    """Recursively collect all descendant PIDs of `root_pid` (excluding `root_pid` itself)."""
    descendants = []
    visited = {root_pid}
    dq = collections.deque([root_pid])
    while dq:
        cur = dq.popleft()
        for cpid in _list_proc_children(cur, proc_root=proc_root):
            if cpid <= 1 or cpid in visited:
                continue
            visited.add(cpid)
            descendants.append(cpid)
            dq.append(cpid)
    return descendants


def _kill_process_tree(root_pid, term_timeout=2.0, proc_root="/proc", proc=None, expected_root_starttime=None):
    """Safely terminate and kill `root_pid` and all verified descendants (including detached setsid subtrees).

    Fail-closed guards before both SIGTERM and SIGKILL:
    1. Permanently excludes PID <= 1, self PID, and any process sharing our own PGID.
    2. Requires `/proc/<pid>/status` effective UID == `os.geteuid()`.
    3. Verifies `/proc/<pid>/stat` `starttime` (parsed via `rfind(')')`) for `root_pid` upfront (when provided)
       and for every target before SIGTERM/SIGKILL to prevent PID reuse.
    4. Only uses `os.killpg(root_pgid, ...)` when `root_pgid == root_pid` and `root_pgid != my_pgid`.
    """
    try:
        root_pid = int(root_pid)
    except (TypeError, ValueError):
        return
    my_pid = os.getpid()
    my_pgid = os.getpgrp()
    my_euid = os.geteuid()
    if root_pid <= 1 or root_pid == my_pid:
        return

    def _validate_target(pid, expected_starttime=None):
        if pid <= 1 or pid == my_pid:
            return False, None, None
        try:
            pgid = os.getpgid(pid)
        except OSError:
            return False, None, None
        if pgid <= 1 or pgid == my_pgid:
            return False, None, None
        euid = _read_proc_euid(pid, proc_root=proc_root)
        if euid is None or euid != my_euid:
            return False, None, None
        state, st = _read_proc_stat_info(pid, proc_root=proc_root)
        if st is None or state in ("Z", "X"):
            return False, None, None
        if expected_starttime is not None and str(st) != str(expected_starttime):
            return False, None, None
        return True, st, pgid

    # Fail-closed upfront check on `root_pid` (UID, PGID, state, and optional expected starttime).
    root_ok, root_st, root_pgid = _validate_target(root_pid, expected_starttime=expected_root_starttime)
    if not root_ok:
        if proc is not None:
            try:
                proc.poll()
            except Exception:
                pass
        return

    # Snapshot full descendant tree BEFORE killing root so detached setsid children are captured before reparenting.
    targets = {root_pid: (root_st, root_pgid)}
    descendants = _collect_descendant_pids(root_pid, proc_root=proc_root)
    for pid in descendants:
        ok, st, pgid = _validate_target(pid)
        if ok:
            targets[pid] = (st, pgid)

    can_killpg = root_pgid == root_pid and root_pgid > 1 and root_pgid != my_pgid
    killpg_term_sent = False
    if can_killpg:
        r_ok, _rst, cur_rpgid = _validate_target(root_pid, expected_starttime=root_st)
        if r_ok and cur_rpgid == root_pid:
            try:
                os.killpg(root_pgid, signal.SIGTERM)
                killpg_term_sent = True
            except OSError:
                pass

    for pid, (st, _orig_pgid) in list(targets.items()):
        ok, _cur_st, cur_pgid = _validate_target(pid, expected_starttime=st)
        if not ok:
            continue
        if pid == root_pid and killpg_term_sent and cur_pgid == root_pgid:
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass

    wait_budget = max(0.0, float(term_timeout or 0.0))
    deadline = time.monotonic() + wait_budget
    while True:
        if proc is not None:
            try:
                proc.poll()
            except Exception:
                pass
        alive = []
        for pid, (st, _orig_pgid) in list(targets.items()):
            ok, _cur_st, cur_pgid = _validate_target(pid, expected_starttime=st)
            if ok:
                alive.append((pid, st, cur_pgid))
        if not alive:
            return
        rem = deadline - time.monotonic()
        if rem <= 0:
            break
        time.sleep(min(0.05, rem))

    killpg_kill_sent = False
    if can_killpg:
        root_ok_kill, _rst, cur_rpgid = _validate_target(root_pid, expected_starttime=root_st)
        if root_ok_kill and cur_rpgid == root_pid:
            try:
                os.killpg(root_pgid, signal.SIGKILL)
                killpg_kill_sent = True
            except OSError:
                pass

    for pid, (st, _orig_pgid) in list(targets.items()):
        ok, _cur_st, cur_pgid = _validate_target(pid, expected_starttime=st)
        if not ok:
            continue
        if pid == root_pid and killpg_kill_sent and cur_pgid == root_pgid:
            continue
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    if proc is not None:
        try:
            if proc.poll() is None:
                proc.wait(timeout=1.0)
        except Exception:
            pass


# ---------------------------------------------------------------- Driver Capabilities & Security Boundary
SIGNAL_TERMINATION_EXIT_CODES = frozenset({-15, 143, -2, 130})

_READONLY_FORBIDDEN_CLI_FLAGS = frozenset(
    {
        "--dangerously-skip-permissions",
        "--allow-dangerously-skip-permissions",
        "--dangerously-bypass-approvals-and-sandbox",
        "--yolo",
        "-y",
        "--full-auto",
        "--auto-approve",
    }
)

_READONLY_FORBIDDEN_CLI_KV_FLAGS: Dict[str, FrozenSet[str]] = {
    "--approval-mode": frozenset({"yolo", "never", "auto_edit", "auto-edit", "full-auto"}),
    "--permission-mode": frozenset({"bypasspermissions", "dontask", "acceptedits"}),
    "--ask-for-approval": frozenset({"never"}),
    "-a": frozenset({"never"}),
    "--sandbox": frozenset({"danger-full-access"}),
}


class UnknownDriverError(ValueError):
    """Raised fail-closed when a requested agent driver is not registered."""


@dataclasses.dataclass(frozen=True)
class DriverCapabilities:
    """Declarative feature capability matrix for a pluggable Agent Driver."""

    engine_name: str
    supports_compact: bool = False
    supports_resume: bool = True
    supports_stream_json: bool = True
    supports_permission_modes: bool = True
    supports_native_tools: bool = True


AGY_CAPABILITIES = DriverCapabilities(
    engine_name="agy",
    supports_compact=True,
    supports_resume=True,
    supports_stream_json=True,
    supports_permission_modes=True,
    supports_native_tools=True,
)


@dataclasses.dataclass(frozen=True)
class SessionSecurityContext:
    """Immutable security boundary enforced across ALL AgentSession implementations."""

    readonly: bool
    untrusted: bool
    effective_mode: str
    bus_enable: bool
    bus_role: str
    rbac_role: str
    allow_skip_permissions: bool


def build_session_security_context(
    mode: Optional[str],
    *,
    scope_key: str,
    readonly: bool = False,
    untrusted: bool = False,
    bus_role: Optional[str] = None,
    bus_enable: Optional[bool] = None,
    host=None,
) -> SessionSecurityContext:
    """Compute canonical fail-closed security context shared by every Agent Driver.

    Invariants (never overridable by driver subclasses):
    - `readonly=True` ALWAYS forces `effective_mode="safe"`, `allow_skip_permissions=False`,
      `bus_enable=False`, `rbac_role="readonly"`, and `untrusted=True`.
    - `untrusted=True` ALWAYS marks the session untrusted so observer/readonly memory env vars
      are injected.
    """
    ro = bool(readonly)
    untr = bool(untrusted) or ro
    eff_mode = "safe" if ro else mode
    allow_skip = (eff_mode == "auto") and (not ro)

    if bus_role is not None:
        eff_bus_role = str(bus_role)
    else:
        role_fn = _host_attr("_current_bot_role", None, host=host)
        eff_bus_role = str(role_fn()) if callable(role_fn) else "peer"

    if ro:
        eff_bus_enable = False
    elif bus_enable is not None:
        eff_bus_enable = bool(bus_enable)
    else:
        bus_fn = _host_attr("_desired_bus_enable", None, host=host)
        eff_bus_enable = bool(bus_fn(scope_key)) if callable(bus_fn) else False

    return SessionSecurityContext(
        readonly=ro,
        untrusted=untr,
        effective_mode=eff_mode if eff_mode is not None else "safe",
        bus_enable=eff_bus_enable,
        bus_role=eff_bus_role,
        rbac_role="readonly" if ro else "admin",
        allow_skip_permissions=allow_skip,
    )


def enforce_readonly_cli_args(cmd: Sequence[str], sec_ctx: SessionSecurityContext) -> List[str]:
    """Fail-closed guard ensuring readonly sessions NEVER receive auto-approval CLI flags."""
    args = list(cmd)
    if not sec_ctx.readonly:
        return args
    n = len(args)
    for i, tok in enumerate(args):
        low = str(tok or "").strip().lower()
        if not low:
            continue
        if low in _READONLY_FORBIDDEN_CLI_FLAGS:
            raise ValueError(f"Forbidden permission-bypass CLI flag in readonly session: {tok!r}")
        flag, eq, val = low.partition("=")
        if eq:
            flag_s = flag.strip()
            val_s = val.strip()
            if flag_s in _READONLY_FORBIDDEN_CLI_FLAGS:
                raise ValueError(f"Forbidden permission-bypass CLI flag in readonly session: {tok!r}")
            forbidden_vals = _READONLY_FORBIDDEN_CLI_KV_FLAGS.get(flag_s)
            if forbidden_vals is not None and val_s in forbidden_vals:
                raise ValueError(f"Forbidden permission-bypass CLI flag in readonly session: {tok!r}")
        else:
            forbidden_vals = _READONLY_FORBIDDEN_CLI_KV_FLAGS.get(low)
            if forbidden_vals is not None and i + 1 < n:
                next_tok = args[i + 1]
                next_low = str(next_tok or "").strip().lower()
                if next_low in forbidden_vals:
                    raise ValueError(
                        f"Forbidden permission-bypass CLI flag in readonly session: {tok!r} {next_tok!r}"
                    )
    return args


def build_base_session_env(
    sec_ctx: SessionSecurityContext,
    *,
    scope_key: str,
    base_env: Optional[Dict[str, str]] = None,
    exec_plan: Optional[Dict[str, Any]] = None,
    apply_agy_auto_update: bool = False,
    host=None,
) -> Dict[str, str]:
    """Build hardened child-process environment shared by all Agent Drivers.

    Security-critical variables (`AGY_CLI_DISABLE_AUTO_UPDATE`, bot isolation env,
    `AGY_BOT_BUS_ENABLE`, `AGY_RBAC_ROLE`, and untrusted readonly-memory flags) are
    applied AFTER `exec_plan` so gateway/model overrides can never weaken isolation.
    """
    env = dict(os.environ if base_env is None else base_env)

    if exec_plan is not None:
        apply_exec = _host_attr("_apply_exec_env", None, host=host)
        if callable(apply_exec):
            apply_exec(env, exec_plan)

    if apply_agy_auto_update:
        apply_upd = _host_attr("_apply_agy_auto_update_env", None, host=host)
        if callable(apply_upd):
            apply_upd(env)

    home = _host_attr("HOME", os.path.expanduser("~"), host=host)
    env["PATH"] = os.path.join(home, ".local/bin") + ":" + env.get("PATH", "")
    env.setdefault("HOME", home)

    outbox = _host_attr("BOT_OUTBOX_DIR", None, host=host)
    if outbox:
        env["AGY_OUTBOX_DIR"] = str(outbox)

    parse_sk = _host_attr("parse_scope_key", None, host=host)
    if callable(parse_sk):
        origin_chat, origin_tid = parse_sk(scope_key)
    else:
        origin_chat, origin_tid = 0, None

    env["AGY_BOT_BUS_ENABLE"] = "1" if sec_ctx.bus_enable else "0"

    inject_iso = _host_attr("_inject_bot_isolation_env", None, host=host)
    handle_fn = _host_attr("_current_bot_handle", None, host=host)
    if callable(inject_iso):
        bot_handle = handle_fn() if callable(handle_fn) else ""
        inject_iso(env, handle=bot_handle, role=sec_ctx.bus_role)

    bot_inst_id = _host_attr("BOT_INSTANCE_ID", None, host=host)
    if bot_inst_id is not None:
        env["AGY_BOT_INSTANCE_ID"] = str(bot_inst_id)
    env["AGY_BOT_SCOPE_KEY"] = str(scope_key)
    env["AGY_BOT_CHAT_ID"] = str(origin_chat or 0)
    env["AGY_BOT_THREAD_ID"] = str(origin_tid) if origin_tid is not None else ""
    env["AGY_BOT_CHAIN"] = ""
    env["AGY_BOT_MENTION_HOP"] = "0"
    env["AGY_RBAC_ROLE"] = sec_ctx.rbac_role

    if sec_ctx.untrusted:
        env["AGY_INTERNAL_OBSERVER"] = "1"
        env["AGY_UNTRUSTED_SESSION"] = "1"
        env["AGY_MEMORY_READONLY"] = "1"

    return env


# ---------------------------------------------------------------- Abstract Session & Protocol Helpers
class AgentSession(ABC):
    """Abstract persistent session protocol shared by `AgySession` and future pluggable drivers."""

    driver_name: str = "generic"
    capabilities: DriverCapabilities = DriverCapabilities(engine_name="generic")

    def _init_common_state(
        self,
        conv: Optional[str],
        mode: Optional[str],
        model: Optional[str],
        effort: Optional[str],
        *,
        project: Optional[str] = None,
        workdir: Optional[str] = None,
        scope_key: Optional[str] = None,
        readonly: bool = False,
        untrusted: bool = False,
        is_worktree: bool = False,
        driver_name: Optional[str] = None,
        capabilities: Optional[DriverCapabilities] = None,
        exec_signature: Any = None,
        host=None,
    ) -> SessionSecurityContext:
        self._host = host
        if driver_name is not None:
            self.driver_name = str(driver_name).strip().lower()
        if capabilities is not None:
            self.capabilities = capabilities

        primary_sk = _host_attr("PRIMARY_SCOPE_KEY", "default", host=host)
        default_wdir = _host_attr("WORKDIR", os.getcwd(), host=host)
        self.scope_key = scope_key or primary_sk

        sec_ctx = build_session_security_context(
            mode,
            scope_key=self.scope_key,
            readonly=readonly,
            untrusted=untrusted,
            host=host,
        )
        self.security_context = sec_ctx
        self.cid = conv
        self.readonly = sec_ctx.readonly
        self.untrusted = sec_ctx.untrusted
        self.mode = "safe" if self.readonly else mode
        self.model = model
        self.effort = effort
        self.project = project
        self.workdir = workdir or default_wdir
        self.is_worktree = bool(is_worktree)
        self.bus_role = sec_ctx.bus_role
        self.bus_enable = sec_ctx.bus_enable
        self.spawned_at = time.time()
        self.last_used = self.spawned_at
        self._pushback = collections.deque()

        if exec_signature is not None:
            self._exec_signature = exec_signature
        else:
            sig_fn = _host_attr("_compute_exec_signature", None, host=host)
            self._exec_signature = sig_fn(model, effort) if callable(sig_fn) else ("native", model or "", effort or "")
        return sec_ctx

    @property
    def exit_code(self) -> Optional[int]:
        """Return process/session exit code if terminated, else None."""
        return None

    def was_terminated_by_signal(self) -> bool:
        """Return True if the session exited due to SIGTERM/SIGINT."""
        return self.exit_code in SIGNAL_TERMINATION_EXIT_CODES

    @abstractmethod
    def is_alive(self) -> bool:
        """Return True if the underlying session can still accept prompts and produce events."""

    def matches(
        self,
        conv,
        mode,
        model,
        effort,
        project=None,
        workdir=None,
        readonly=False,
        untrusted=False,
        is_worktree=False,
        driver_name=None,
    ) -> bool:
        """Strict warm-session reuse predicate covering liveness, driver identity, trust boundary, and context."""
        if not self.is_alive():
            return False
        if driver_name is not None and (
            str(getattr(self, "driver_name", "agy")).strip().lower() != str(driver_name).strip().lower()
        ):
            return False
        if getattr(self, "readonly", False) != bool(readonly):
            return False
        if getattr(self, "untrusted", False) != (bool(untrusted) or bool(readonly)):
            return False
        if bool(getattr(self, "is_worktree", False)) != bool(is_worktree):
            return False

        h = _resolve_host(getattr(self, "_host", None))
        eff_mode = "safe" if self.readonly else mode

        desired_bus_fn = getattr(h, "_desired_bus_enable", None) if h is not None else None
        if self.readonly:
            expected_bus = False
        elif callable(desired_bus_fn):
            expected_bus = bool(desired_bus_fn(self.scope_key))
        else:
            expected_bus = bool(getattr(self, "bus_enable", False))
        if getattr(self, "bus_enable", False) != expected_bus:
            return False

        role_fn = getattr(h, "_current_bot_role", None) if h is not None else None
        if callable(role_fn):
            if getattr(self, "bus_role", None) != role_fn():
                return False

        if self.mode != eff_mode or self.model != model or self.effort != effort:
            return False

        sig_fn = getattr(h, "_compute_exec_signature", None) if h is not None else None
        if callable(sig_fn):
            if getattr(self, "_exec_signature", None) != sig_fn(model, effort):
                return False

        default_wdir = getattr(h, "WORKDIR", self.workdir) if h is not None else self.workdir
        if self.project != project or self.workdir != (workdir or default_wdir):
            return False
        return self.cid == conv

    @abstractmethod
    def send_user_prompt(self, prompt: str, raw_slash: bool = False) -> None:
        """Deliver a user turn prompt to the running session."""

    @abstractmethod
    def next_event(self, timeout: float = 0.25) -> Optional[Dict[str, Any]]:
        """Return next normalized event dict, or None on timeout."""

    def peek_immediate_result(self, timeout: float = 0.065):
        """Wait up to 65ms after `agent_response` DONE to see if `result` follows immediately.

        Returns `(result_dict, None)` if turn finished, or `(None, reason)` if intermediate step.
        """
        deadline = time.time() + timeout
        while True:
            rem = max(0.0, deadline - time.time())
            ev = self.next_event(timeout=rem)
            if ev is None:
                return None, "waiting"
            kind = ev.get("event")
            if kind == "result":
                return (ev.get("result") or ev), None
            if kind == "init":
                continue
            self._pushback.append(ev)
            return None, "more_steps"

    def get_stderr_text(self) -> str:
        """Return diagnostic stderr tail for error reporting."""
        return ""

    @abstractmethod
    def close(self, force: bool = False, term_timeout: Optional[float] = None) -> None:
        """Terminate and release all resources held by this session."""


def get_session_exit_code(sess: Any) -> Optional[int]:
    """Protocol-safe exit code accessor (prefers `sess.exit_code`; legacy mock fallback)."""
    if sess is None:
        return None
    if hasattr(sess, "exit_code"):
        return sess.exit_code
    proc = getattr(sess, "proc", None)
    return getattr(proc, "returncode", None) if proc is not None else None


def session_was_terminated_by_signal(sess: Any) -> bool:
    """Protocol-safe signal-termination check (prefers `sess.was_terminated_by_signal()`)."""
    if sess is None:
        return False
    fn = getattr(sess, "was_terminated_by_signal", None)
    if callable(fn):
        return bool(fn())
    return get_session_exit_code(sess) in SIGNAL_TERMINATION_EXIT_CODES


# ---------------------------------------------------------------- Built-in AgySession Implementation
class AgySession(AgentSession):
    """Manages a warm persistent `agy --input-format stream-json --output-format stream-json` process
    with non-blocking stdout event queue for instant cancellation & 60ms result lookahead.
    """

    driver_name: str = "agy"
    capabilities: DriverCapabilities = AGY_CAPABILITIES
    _eof_fallback_lock = threading.Lock()

    def __init__(
        self,
        conv,
        mode,
        model,
        effort,
        project=None,
        workdir=None,
        scope_key=None,
        readonly=False,
        untrusted=False,
        is_worktree=False,
        *,
        host=None,
    ):
        h = _resolve_host(host)
        resolve_exec = getattr(h, "_resolve_exec_target", None) if h is not None else None
        if callable(resolve_exec):
            exec_plan = resolve_exec(model, effort)
        else:
            exec_plan = {
                "kind": "native",
                "cli_model": model,
                "cli_effort": effort,
                "env_set": {},
                "gateway_id": None,
                "upstream_model": None,
                "effort": effort,
                "signature": ("native", model or "", effort or ""),
            }

        sec_ctx = self._init_common_state(
            conv,
            mode,
            model,
            effort,
            project=project,
            workdir=workdir,
            scope_key=scope_key,
            readonly=readonly,
            untrusted=untrusted,
            is_worktree=is_worktree,
            driver_name="agy",
            capabilities=AGY_CAPABILITIES,
            exec_signature=exec_plan["signature"],
            host=host,
        )
        self.stderr_tail = collections.deque(maxlen=80)
        self.event_q = queue.Queue()
        self.eof_reached = False

        self._route_kind = exec_plan["kind"]
        self._gateway_id = exec_plan["gateway_id"]
        self._upstream_model = exec_plan["upstream_model"]
        cli_model = exec_plan["cli_model"]
        cli_effort = exec_plan["cli_effort"]

        agy_bin = _host_attr("AGY_BIN", os.path.join(os.path.expanduser("~"), ".local/bin/agy"), host=h)
        print_timeout = _host_attr("PRINT_TIMEOUT", "30m", host=h)

        cmd = [
            agy_bin,
            "--input-format", "stream-json",
            "--output-format", "stream-json",
            "--print-timeout", print_timeout,
        ]
        if sec_ctx.allow_skip_permissions:
            cmd.append("--dangerously-skip-permissions")
        if self.project and not self.is_worktree:
            cmd += ["--project", self.project]
        if cli_model:
            cmd += ["--model", cli_model]
        if cli_effort:
            cmd += ["--effort", cli_effort]
        if conv:
            cmd += ["--conversation", conv]
        cmd += ["-p", ""]
        cmd = enforce_readonly_cli_args(cmd, sec_ctx)

        env = build_base_session_env(
            sec_ctx,
            scope_key=self.scope_key,
            exec_plan=exec_plan,
            apply_agy_auto_update=True,
            host=h,
        )

        _host_log(
            "Spawning persistent AgySession (conv=%s, project=%s, cwd=%s, model=%s, effort=%s, route=%s, mode=%s, bus=%s, ro=%s, untrusted=%s)"
            % (
                (conv or "new")[:8],
                self.project or "default",
                self.workdir,
                model or "default",
                effort or "default",
                f"gw:{self._gateway_id}" if self._gateway_id else "native",
                self.mode,
                self.bus_enable,
                self.readonly,
                self.untrusted,
            ),
            host=h,
        )
        self._close_lock = threading.Lock()
        self._closed = False
        self._eof_lock = threading.Lock()
        self._eof_emitted = False

        subproc_mod = getattr(h, "subprocess", subprocess) if h is not None else subprocess
        thread_mod = getattr(h, "threading", threading) if h is not None else threading
        self.proc = subproc_mod.Popen(
            cmd,
            cwd=self.workdir,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=env,
            start_new_session=True,
        )
        _pid = getattr(self.proc, "pid", None)
        read_st = getattr(h, "_read_proc_starttime", _read_proc_starttime) if h is not None else _read_proc_starttime
        self._proc_starttime = read_st(_pid) if _pid is not None else None
        self._stdout_thread = thread_mod.Thread(target=self._drain_stdout, daemon=True)
        self._stderr_thread = thread_mod.Thread(target=self._drain_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

    @property
    def exit_code(self) -> Optional[int]:
        return self.proc.returncode if self.proc is not None else None

    def _signal_eof(self):
        self.eof_reached = True
        eof_lock = getattr(self, "_eof_lock", None) or AgySession._eof_fallback_lock
        with eof_lock:
            if not getattr(self, "_eof_emitted", False):
                self._eof_emitted = True
                self.event_q.put({"event": "__eof__"})

    def _drain_stdout(self):
        p = self.proc
        stream = p.stdout if p is not None else None
        try:
            if stream is not None:
                for raw in stream:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        ev = json.loads(raw)
                    except Exception:
                        continue
                    if ev.get("event") == "init":
                        cid = ev.get("conversation_id")
                        if cid:
                            self.cid = cid
                    self.event_q.put(ev)
        except Exception:
            pass
        finally:
            if stream is not None:
                try:
                    if not getattr(stream, "closed", False):
                        stream.close()
                except Exception:
                    pass
            self._signal_eof()

    def _drain_stderr(self):
        p = self.proc
        stream = p.stderr if p is not None else None
        try:
            if stream is not None:
                for line in stream:
                    self.stderr_tail.append(line)
        except Exception:
            pass
        finally:
            if stream is not None:
                try:
                    if not getattr(stream, "closed", False):
                        stream.close()
                except Exception:
                    pass

    def next_event(self, timeout=0.25):
        """Return next parsed event dict, or None on timeout (never blocks cancellation)."""
        if self._pushback:
            return self._pushback.popleft()
        try:
            return self.event_q.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_stderr_text(self):
        return "".join(self.stderr_tail)[-1200:]

    def is_alive(self):
        return self.proc is not None and self.proc.poll() is None and not self.eof_reached

    def send_user_prompt(self, prompt, raw_slash=False):
        # Give freshly spawned `agy` ~200ms to finish OAuth file load (`server_oauth.go`) before first RPC
        since_spawn = time.time() - self.spawned_at
        if since_spawn < 0.22:
            time.sleep(0.22 - since_spawn)
        if raw_slash:
            safe_prompt = prompt
        else:
            safe_prompt = (" " + prompt) if prompt.lstrip().startswith("/") else prompt
        payload = json.dumps({"event": "user", "message": {"content": safe_prompt}}, ensure_ascii=False)
        self.proc.stdin.write(payload + "\n")
        self.proc.stdin.flush()
        self.last_used = time.time()

    def close(self, force=False, term_timeout=None):
        p = self.proc
        if p is None:
            return
        lock = getattr(self, "_close_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._close_lock = lock
        h = _resolve_host(getattr(self, "_host", None))
        kill_tree = getattr(h, "_kill_process_tree", _kill_process_tree) if h is not None else _kill_process_tree
        with lock:
            if getattr(self, "_closed", False):
                return
            try:
                try:
                    if p.stdin and not p.stdin.closed:
                        p.stdin.close()
                except Exception:
                    pass
                exited_cleanly = False
                if not force:
                    try:
                        p.wait(timeout=1.5)
                        exited_cleanly = True
                    except Exception:
                        exited_cleanly = False
                if p.poll() is None and (force or not exited_cleanly):
                    t_out = (1.5 if force else 2.0) if term_timeout is None else float(term_timeout)
                    _pid = getattr(p, "pid", None)
                    if _pid is not None:
                        kill_tree(
                            _pid,
                            term_timeout=t_out,
                            proc=p,
                            expected_root_starttime=getattr(self, "_proc_starttime", None),
                        )
                    else:
                        try:
                            p.terminate()
                        except Exception:
                            pass
                    try:
                        if p.poll() is None:
                            p.wait(timeout=1.0)
                    except Exception:
                        pass
            finally:
                stdout_th = getattr(self, "_stdout_thread", None)
                stderr_th = getattr(self, "_stderr_thread", None)
                for th in (stdout_th, stderr_th):
                    if th is not None and th.is_alive() and th is not threading.current_thread():
                        try:
                            th.join(timeout=0.5)
                        except Exception:
                            pass
                if p.stdin is not None:
                    try:
                        if not getattr(p.stdin, "closed", False):
                            p.stdin.close()
                    except Exception:
                        pass
                if p.stdout is not None and (stdout_th is None or not stdout_th.is_alive()):
                    try:
                        if not getattr(p.stdout, "closed", False):
                            p.stdout.close()
                    except Exception:
                        pass
                if p.stderr is not None and (stderr_th is None or not stderr_th.is_alive()):
                    try:
                        if not getattr(p.stderr, "closed", False):
                            p.stderr.close()
                    except Exception:
                        pass
                if stdout_th is not None and stdout_th.is_alive():
                    self._signal_eof()
                self._closed = True


# ---------------------------------------------------------------- AgentDriver ABC & Registry
class AgentDriver(ABC):
    """Pluggable Agent Driver interface responsible for spawning `AgentSession` instances."""

    name: str = ""
    capabilities: DriverCapabilities = DriverCapabilities(engine_name="generic")

    @abstractmethod
    def spawn_session(
        self,
        conv,
        mode,
        model,
        effort,
        *,
        project=None,
        workdir=None,
        scope_key=None,
        readonly=False,
        untrusted=False,
        is_worktree=False,
    ) -> AgentSession:
        """Spawn a new persistent `AgentSession` adhering to `SessionSecurityContext` invariants."""


class AgyDriver(AgentDriver):
    """Default built-in driver for Antigravity CLI (`agy`).

    Resolves `host.AgySession` dynamically so existing unit tests that monkeypatch
    `mock.patch.object(bridge, "AgySession", ...)` continue to intercept session spawns.
    """

    name: str = "agy"
    capabilities: DriverCapabilities = AGY_CAPABILITIES

    def spawn_session(
        self,
        conv,
        mode,
        model,
        effort,
        *,
        project=None,
        workdir=None,
        scope_key=None,
        readonly=False,
        untrusted=False,
        is_worktree=False,
    ):
        h = _resolve_host()
        session_cls = getattr(h, "AgySession", AgySession) if h is not None else AgySession
        sess_kw = {
            "project": project,
            "workdir": workdir,
            "scope_key": scope_key,
            "readonly": readonly,
            "untrusted": untrusted,
        }
        if is_worktree:
            sess_kw["is_worktree"] = True
        return session_cls(conv, mode, model, effort, **sess_kw)


class DriverRegistry:
    """Thread-safe, fail-closed registry of pluggable `AgentDriver` backends."""

    def __init__(self, *, register_builtin: bool = True):
        self._lock = threading.Lock()
        self._drivers: Dict[str, AgentDriver] = {}
        if register_builtin:
            self._drivers["agy"] = AgyDriver()

    @staticmethod
    def _normalize_name(name: Any) -> str:
        norm = str(name or "").strip().lower()
        if not norm:
            raise ValueError("Driver name must be a non-empty string")
        return norm

    def register_driver(self, name: str, driver: AgentDriver, *, overwrite: bool = False) -> AgentDriver:
        norm = self._normalize_name(name)
        if not isinstance(driver, AgentDriver) and not callable(getattr(driver, "spawn_session", None)):
            raise TypeError(f"driver must be an AgentDriver instance (got {type(driver).__name__})")
        with self._lock:
            if not overwrite and norm in self._drivers:
                raise ValueError(f"Agent driver already registered: {norm!r}")
            self._drivers[norm] = driver
        return driver

    def unregister_driver(self, name: str) -> Optional[AgentDriver]:
        norm = self._normalize_name(name)
        with self._lock:
            return self._drivers.pop(norm, None)

    def resolve_driver_name(self, explicit_name: Optional[str] = None) -> str:
        if explicit_name is not None:
            if not isinstance(explicit_name, str) or not explicit_name.strip():
                raise UnknownDriverError(
                    f"Invalid explicit agent driver name: {explicit_name!r} (must be a non-empty string)"
                )
            return explicit_name.strip().lower()
        raw_env = os.environ.get("AGY_AGENT_DRIVER")
        if raw_env is None or raw_env == "":
            return "agy"
        env_name = raw_env.strip().lower()
        if not env_name:
            raise UnknownDriverError(
                f"Invalid AGY_AGENT_DRIVER environment value: {raw_env!r} (whitespace-only)"
            )
        return env_name

    def get_driver(self, name: Optional[str] = None) -> AgentDriver:
        resolved = self.resolve_driver_name(name)
        with self._lock:
            drv = self._drivers.get(resolved)
            registered = sorted(self._drivers.keys())
        if drv is None:
            raise UnknownDriverError(
                f"Unknown agent driver {resolved!r}; registered drivers: {', '.join(registered) or '(none)'}"
            )
        return drv

    def list_drivers(self) -> List[str]:
        with self._lock:
            return sorted(self._drivers.keys())


default_registry = DriverRegistry(register_builtin=True)


def register_driver(name: str, driver: AgentDriver, *, overwrite: bool = False) -> AgentDriver:
    return default_registry.register_driver(name, driver, overwrite=overwrite)


def unregister_driver(name: str) -> Optional[AgentDriver]:
    return default_registry.unregister_driver(name)


def resolve_driver_name(explicit_name: Optional[str] = None) -> str:
    return default_registry.resolve_driver_name(explicit_name)


def get_driver(name: Optional[str] = None) -> AgentDriver:
    return default_registry.get_driver(name)


def list_drivers() -> List[str]:
    return default_registry.list_drivers()


# ---------------------------------------------------------------- Session Pool & Lifecycle Helpers
def close_session_async(sess, force=False):
    if sess is None:
        return
    threading.Thread(target=sess.close, kwargs={"force": force}, daemon=True).start()


def invalidate_session(reason="", force=False, scope_key=None, *, host=None):
    """Recycle warm session(s) immediately if idle, or mark dirty to recycle right after active turn."""
    h = _resolve_host(host)
    if h is None:
        return
    to_close = []
    with h.session_lock:
        targets = [scope_key] if scope_key is not None else list(h._session_pool.keys())
        for sk in targets:
            if h.turn_running and h.turn_running_scope == sk and not force:
                h.session_dirty_scopes.add(sk)
                _host_log(
                    "Marked active session dirty (%s · scope=%s); will recycle after current turn" % (reason, sk),
                    host=h,
                )
            elif sk in h._session_pool:
                sess = h._session_pool.pop(sk, None)
                h.session_dirty_scopes.discard(sk)
                if sess is not None:
                    to_close.append(sess)
                    _host_log("Closing warm session (%s · scope=%s)" % (reason, sk), host=h)
    close_async = getattr(h, "close_session_async", close_session_async)
    for sess in to_close:
        close_async(sess, force=force)


def close_all_sessions_sync(*, host=None):
    h = _resolve_host(host)
    if h is None:
        return
    with h.session_lock:
        to_close = list(h._session_pool.values())
        h._session_pool.clear()
        h.session_dirty_scopes.clear()
    for sess in to_close:
        sess.close(force=False)


def idle_session_reaper(*, host=None):
    h = _resolve_host(host)
    if h is None:
        return
    while not getattr(h, "shutting_down", False):
        time.sleep(30)
        ttl = getattr(h, "IDLE_SESSION_TTL", 2700)
        if ttl <= 0:
            continue
        now = time.time()
        to_close = []
        with h.session_lock:
            for sk in list(h._session_pool.keys()):
                if h.turn_running and h.turn_running_scope == sk:
                    continue
                sess = h._session_pool.get(sk)
                if sess is not None and (now - sess.last_used) > ttl:
                    h._session_pool.pop(sk, None)
                    to_close.append(sess)
                    _host_log(
                        "Idle session TTL (%ds) reached for scope=%s; closing warm agy process" % (ttl, sk),
                        host=h,
                    )
        for sess in to_close:
            sess.close(force=False)


def _acquire_session(
    scope_key,
    conv,
    mode,
    model,
    effort,
    project,
    workdir,
    force_new=False,
    readonly=False,
    untrusted=False,
    is_worktree=False,
    *,
    driver=None,
    registry: Optional[DriverRegistry] = None,
    host=None,
):
    """Acquire a matching warm `AgentSession` from `host._session_pool`, or spawn via `DriverRegistry`."""
    h = _resolve_host(host)
    reg = registry if registry is not None else default_registry
    # Fail-closed BEFORE touching the warm session pool if an unknown driver name is requested.
    target_driver = reg.get_driver(driver)
    target_driver_name = getattr(target_driver, "name", None) or reg.resolve_driver_name(driver)

    primary_sk = getattr(h, "PRIMARY_SCOPE_KEY", "default") if h is not None else "default"
    skey = scope_key or primary_sk
    max_warm = getattr(h, "MAX_WARM_SESSIONS", 4) if h is not None else 4
    to_close = []
    same_conv_to_close = []

    if h is not None:
        with h.session_lock:
            existing = h._session_pool.get(skey)
            matches_kw = {"readonly": readonly, "untrusted": untrusted}
            if is_worktree:
                matches_kw["is_worktree"] = True
            same_driver = (
                existing is not None
                and str(getattr(existing, "driver_name", "agy")).strip().lower()
                == str(target_driver_name).strip().lower()
            )
            if same_driver and isinstance(existing, AgentSession):
                matches_kw["driver_name"] = target_driver_name
            if not force_new and same_driver and existing.matches(
                conv, mode, model, effort, project, workdir, **matches_kw
            ):
                return existing, True
            if existing is not None:
                h._session_pool.pop(skey, None)
                if conv and existing.cid == conv:
                    same_conv_to_close.append(existing)
                else:
                    to_close.append(existing)
            if conv:
                for k, s in list(h._session_pool.items()):
                    if k != skey and s.cid == conv and not (h.turn_running and h.turn_running_scope == k):
                        h._session_pool.pop(k, None)
                        same_conv_to_close.append(s)
                        _host_log(
                            "Evicting duplicate warm session holding conv=%s from scope=%s" % (conv[:8], k),
                            host=h,
                        )
            while len(h._session_pool) >= max_warm:
                candidates = [
                    (s.last_used, k, s)
                    for k, s in h._session_pool.items()
                    if not (h.turn_running and k == h.turn_running_scope)
                ]
                if not candidates:
                    break
                candidates.sort(key=lambda x: x[0])
                _, evict_k, evict_s = candidates[0]
                h._session_pool.pop(evict_k, None)
                to_close.append(evict_s)
                _host_log("Warm session pool cap (%d) reached; evicting LRU scope=%s" % (max_warm, evict_k), host=h)

    # Synchronously close any evicted warm session holding the SAME conv BEFORE spawning the new process
    # so zero concurrent writers can exist for the same conversation_id.
    for old_same in same_conv_to_close:
        try:
            old_same.close(force=False)
        except Exception:
            pass

    sess = target_driver.spawn_session(
        conv,
        mode,
        model,
        effort,
        project=project,
        workdir=workdir,
        scope_key=skey,
        readonly=readonly,
        untrusted=untrusted,
        is_worktree=is_worktree,
    )
    if h is not None:
        with h.session_lock:
            prev_raced = h._session_pool.get(skey)
            if prev_raced is not None and prev_raced is not sess:
                to_close.append(prev_raced)
            h._session_pool[skey] = sess
        close_async = getattr(h, "close_session_async", close_session_async)
    else:
        close_async = close_session_async
    for old in to_close:
        close_async(old, force=False)
    return sess, False
