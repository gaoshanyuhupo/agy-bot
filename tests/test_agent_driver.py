#!/usr/bin/env python3
"""Unit & integration tests for `bridge/agent_driver.py` pluggable Driver contract (C2, C3)."""

from __future__ import annotations

import ast
import collections
import importlib
import os
import queue
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import agent_driver  # noqa: E402


def _load_isolated_bridge(tmp: str):
    env_patch = {
        "AGY_BOT_BUS_DIR": os.path.join(tmp, "bus"),
        "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
        "AGY_TG_QUEUE_FILE": os.path.join(tmp, "state.json.queue.json"),
        "AGY_MEMORY_TAINT_FILE": os.path.join(tmp, "memory_taint.json"),
        "AGY_TG_WORKDIR": os.path.join(tmp, "workdir"),
        "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
        "AGY_TG_ALLOWED_CHATS": "111,-1001234567890",
        "AGY_TG_ALLOWED_USERS": "",
        "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_AGENT_DRIVER_TEST_TOKEN_01",
        "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
        "AGY_STUDIO_IPC_DISABLE": "1",
        "AGY_TG_BOT_MODEL": "",
        "AGY_TG_BOT_EFFORT": "",
        "AGY_MODEL": "",
        "AGY_EFFORT": "",
        "AGY_AGENT_DRIVER": "",
    }
    with mock.patch.dict(os.environ, env_patch, clear=False):
        import bot_bus  # noqa: E402
        import bridge  # noqa: E402

        importlib.reload(bot_bus)
        importlib.reload(bridge)
        os.makedirs(bridge.WORKDIR, exist_ok=True)
        os.makedirs(bridge.UPLOADDIR, exist_ok=True)
        return bridge


class _FakeSession(agent_driver.AgentSession):
    """Pure in-memory AgentSession (no `.proc`, no external CLI binary) for C3 verification."""

    def __init__(
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
        driver_name="fake",
        capabilities=None,
        turn_scripts=None,
        exit_code_on_close=0,
    ):
        caps = capabilities or agent_driver.DriverCapabilities(
            engine_name=driver_name,
            supports_compact=False,
            supports_resume=True,
            supports_stream_json=True,
            supports_permission_modes=True,
            supports_native_tools=True,
        )
        self._init_common_state(
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
            driver_name=driver_name,
            capabilities=caps,
        )
        self._scripts = collections.deque(turn_scripts or [])
        self._q: queue.Queue = queue.Queue()
        self._alive = True
        self._exit_code = None
        self._exit_code_on_close = exit_code_on_close
        self.prompts_received: list[tuple[str, bool]] = []
        self.close_calls: list[bool] = []
        self.stderr_text = ""

    @property
    def exit_code(self):
        return self._exit_code

    def is_alive(self) -> bool:
        return self._alive

    def send_user_prompt(self, prompt: str, raw_slash: bool = False) -> None:
        self.prompts_received.append((prompt, raw_slash))
        self.last_used = time.time()
        script = self._scripts.popleft() if self._scripts else []
        for ev in script:
            if ev.get("event") == "__set_exit__":
                self._exit_code = ev.get("code")
                self._alive = False
                continue
            if ev.get("event") == "__sleep__":
                time.sleep(float(ev.get("sec", 0.01)))
                continue
            self._q.put(ev)

    def next_event(self, timeout: float = 0.25):
        if self._pushback:
            return self._pushback.popleft()
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_stderr_text(self) -> str:
        return self.stderr_text

    def close(self, force: bool = False, term_timeout=None) -> None:
        self.close_calls.append(bool(force))
        self._alive = False
        if self._exit_code is None:
            self._exit_code = -15 if force else self._exit_code_on_close
        self._q.put({"event": "__eof__"})


class _FakeDriver(agent_driver.AgentDriver):
    """Pure in-memory pluggable AgentDriver for end-to-end bridge tests."""

    def __init__(self, name="fake", *, supports_compact=False, script_factory=None):
        self.name = name
        self.capabilities = agent_driver.DriverCapabilities(
            engine_name=name,
            supports_compact=supports_compact,
            supports_resume=True,
            supports_stream_json=True,
            supports_permission_modes=True,
            supports_native_tools=True,
        )
        self._script_factory = script_factory
        self.spawned: list[_FakeSession] = []

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
        scripts = self._script_factory() if callable(self._script_factory) else []
        sess = _FakeSession(
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
            driver_name=self.name,
            capabilities=self.capabilities,
            turn_scripts=scripts,
        )
        self.spawned.append(sess)
        return sess


class TestAgentDriverSecurityBoundary(unittest.TestCase):
    """C2: Shared security invariants enforced at `AgentSession` / `SessionSecurityContext` layer."""

    def test_readonly_forces_safe_downgrade_and_env_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            sec_ro = agent_driver.build_session_security_context(
                "auto", scope_key="111", readonly=True, untrusted=False, host=bridge
            )
            self.assertTrue(sec_ro.readonly)
            self.assertTrue(sec_ro.untrusted)
            self.assertEqual(sec_ro.effective_mode, "safe")
            self.assertFalse(sec_ro.allow_skip_permissions)
            self.assertFalse(sec_ro.bus_enable)
            self.assertEqual(sec_ro.rbac_role, "readonly")

            env = agent_driver.build_base_session_env(
                sec_ro, scope_key="111", base_env={"PATH": "/usr/bin"}, apply_agy_auto_update=True, host=bridge
            )
            self.assertEqual(env.get("AGY_RBAC_ROLE"), "readonly")
            self.assertEqual(env.get("AGY_BOT_BUS_ENABLE"), "0")
            self.assertEqual(env.get("AGY_INTERNAL_OBSERVER"), "1")
            self.assertEqual(env.get("AGY_UNTRUSTED_SESSION"), "1")
            self.assertEqual(env.get("AGY_MEMORY_READONLY"), "1")
            self.assertEqual(env.get("AGY_CLI_DISABLE_AUTO_UPDATE"), "1")
            self.assertIn("AGY_BOT_HANDLE", env)

            # Readonly CLI arg guard fails closed on ALL single-token and two-token multi-engine bypass PoCs
            bypass_pocs = [
                # 13 QA Round 1 multi-engine PoCs
                ["claude", "--dangerously-skip-permissions"],
                ["claude", "--allow-dangerously-skip-permissions"],
                ["claude", "--permission-mode", "bypassPermissions"],
                ["claude", "--permission-mode=bypassPermissions"],
                ["claude", "--permission-mode", "dontAsk"],
                ["claude", "--permission-mode", "acceptEdits"],
                ["codex", "--dangerously-bypass-approvals-and-sandbox"],
                ["codex", "--full-auto"],
                ["codex", "--ask-for-approval", "never"],
                ["codex", "-a", "never"],
                ["codex", "--sandbox", "danger-full-access"],
                ["gemini", "--approval-mode", "yolo"],
                ["gemini", "--approval-mode", "auto_edit"],
                # Additional single-token, `=`, and case-insensitive variants
                ["gemini", "--yolo"],
                ["gemini", "-y"],
                ["gemini", "--yolo=true"],
                ["gemini", "-y=1"],
                ["gemini", "--approval-mode=yolo"],
                ["gemini", "--approval-mode=never"],
                ["gemini", "--approval-mode=auto-edit"],
                ["gemini", "--approval-mode", "full-auto"],
                ["gemini", "--Approval-Mode=YOLO"],
                ["claude", "--dangerously-skip-permissions=true"],
                ["claude", "--allow-dangerously-skip-permissions=1"],
                ["claude", "--permission-mode=dontask"],
                ["claude", "--permission-mode=acceptedits"],
                ["claude", "--PERMISSION-MODE", "BYPASSPERMISSIONS"],
                ["codex", "--dangerously-bypass-approvals-and-sandbox=true"],
                ["codex", "--full-auto=yes"],
                ["codex", "--ask-for-approval=never"],
                ["codex", "-a=never"],
                ["codex", "--sandbox=danger-full-access"],
                ["cli", "--auto-approve"],
                ["cli", "--auto-approve=true"],
            ]
            for bad_cmd in bypass_pocs:
                with self.subTest(bad_cmd=bad_cmd):
                    with self.assertRaises(ValueError):
                        agent_driver.enforce_readonly_cli_args(bad_cmd, sec_ro)

            # Safe readonly flags pass cleanly
            for ok_cmd in (
                ["cli", "--model", "m1"],
                ["codex", "--sandbox", "read-only"],
                ["codex", "--sandbox=read-only"],
                ["gemini", "--approval-mode", "suggest"],
                ["gemini", "--approval-mode=suggest"],
                ["claude", "--permission-mode", "plan"],
                ["claude", "--permission-mode=plan"],
                ["codex", "-a", "on-request"],
            ):
                with self.subTest(ok_cmd=ok_cmd):
                    self.assertEqual(agent_driver.enforce_readonly_cli_args(ok_cmd, sec_ro), ok_cmd)

    def test_untrusted_admin_session_still_injects_observer_and_readonly_memory_envs(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            sec_untr = agent_driver.build_session_security_context(
                "auto", scope_key="111", readonly=False, untrusted=True, host=bridge
            )
            self.assertFalse(sec_untr.readonly)
            self.assertTrue(sec_untr.untrusted)
            self.assertEqual(sec_untr.rbac_role, "admin")

            env = agent_driver.build_base_session_env(
                sec_untr, scope_key="111", base_env={"PATH": "/usr/bin"}, host=bridge
            )
            self.assertEqual(env.get("AGY_INTERNAL_OBSERVER"), "1")
            self.assertEqual(env.get("AGY_UNTRUSTED_SESSION"), "1")
            self.assertEqual(env.get("AGY_MEMORY_READONLY"), "1")

    def test_matches_rejects_cross_driver_and_trust_boundary_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            sess = _FakeSession(
                "cid-1",
                "auto",
                "m1",
                "high",
                project="proj-a",
                workdir=bridge.WORKDIR,
                scope_key="111",
                readonly=False,
                untrusted=False,
                is_worktree=False,
                driver_name="Fake_CLI",
            )
            self.assertEqual(sess.driver_name, "fake_cli")
            # Exact match succeeds (including case/whitespace normalization on driver_name)
            self.assertTrue(
                sess.matches(
                    "cid-1", "auto", "m1", "high", "proj-a", bridge.WORKDIR,
                    readonly=False, untrusted=False, is_worktree=False, driver_name="fake_cli",
                )
            )
            self.assertTrue(
                sess.matches(
                    "cid-1", "auto", "m1", "high", "proj-a", bridge.WORKDIR,
                    readonly=False, untrusted=False, is_worktree=False, driver_name="  FAKE_CLI  ",
                )
            )
            # Any single dimension mismatch MUST return False
            self.assertFalse(sess.matches("cid-1", "auto", "m1", "high", "proj-a", bridge.WORKDIR, driver_name="agy"))
            self.assertFalse(sess.matches("cid-1", "auto", "m1", "high", "proj-a", bridge.WORKDIR, readonly=True))
            self.assertFalse(sess.matches("cid-1", "auto", "m1", "high", "proj-a", bridge.WORKDIR, untrusted=True))
            self.assertFalse(sess.matches("cid-1", "auto", "m1", "high", "proj-a", bridge.WORKDIR, is_worktree=True))
            self.assertFalse(sess.matches("cid-1", "safe", "m1", "high", "proj-a", bridge.WORKDIR))
            self.assertFalse(sess.matches("cid-1", "auto", "m2", "high", "proj-a", bridge.WORKDIR))
            self.assertFalse(sess.matches("cid-1", "auto", "m1", "low", "proj-a", bridge.WORKDIR))
            self.assertFalse(sess.matches("cid-1", "auto", "m1", "high", "proj-b", bridge.WORKDIR))
            self.assertFalse(sess.matches("cid-1", "auto", "m1", "high", "proj-a", "/other"))
            self.assertFalse(sess.matches("cid-2", "auto", "m1", "high", "proj-a", bridge.WORKDIR))

            # Closed session never matches
            sess.close()
            self.assertFalse(sess.matches("cid-1", "auto", "m1", "high", "proj-a", bridge.WORKDIR))

    def test_kill_process_tree_fail_closed_guards_preserved(self):
        # PID <= 1, self PID, or mismatched starttime must never invoke os.kill / os.killpg
        with (
            mock.patch("os.kill") as m_kill,
            mock.patch("os.killpg") as m_killpg,
        ):
            agent_driver._kill_process_tree(0)
            agent_driver._kill_process_tree(1)
            agent_driver._kill_process_tree(os.getpid())
            m_kill.assert_not_called()
            m_killpg.assert_not_called()

        # Synthetic /proc with parens in comm + starttime mismatch must fail closed
        with tempfile.TemporaryDirectory() as proc_root:
            pid_dir = Path(proc_root) / "99999"
            pid_dir.mkdir()
            (pid_dir / "stat").write_text(
                "99999 (my (weird) proc) S 1 99999 99999 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 123456 0 0\n",
                encoding="utf-8",
            )
            (pid_dir / "status").write_text(
                f"Name:\tweird\nUid:\t{os.geteuid()}\t{os.geteuid()}\t{os.geteuid()}\t{os.geteuid()}\n",
                encoding="utf-8",
            )
            state, st = agent_driver._read_proc_stat_info(99999, proc_root=proc_root)
            self.assertEqual(state, "S")
            self.assertEqual(st, "123456")
            self.assertEqual(agent_driver._read_proc_starttime(99999, proc_root=proc_root), "123456")

            with (
                mock.patch("os.getpgid", return_value=99999),
                mock.patch("os.kill") as m_kill,
                mock.patch("os.killpg") as m_killpg,
            ):
                agent_driver._kill_process_tree(
                    99999, proc_root=proc_root, expected_root_starttime="999999"
                )
                m_kill.assert_not_called()
                m_killpg.assert_not_called()


class TestPluggableDriverRegistryAndEndToEnd(unittest.TestCase):
    """C3: Registry fail-closed, zero `sess.proc` in `bridge.py`, FakeDriver E2E & compact degradation."""

    def test_registry_fail_closed_and_agy_driver_respects_bridge_monkeypatch(self):
        reg = agent_driver.DriverRegistry()
        self.assertIn("agy", reg.list_drivers())
        self.assertEqual(reg.get_driver("agy").name, "agy")

        # Unknown driver MUST fail closed (no silent fallback to agy)
        with self.assertRaises(agent_driver.UnknownDriverError):
            reg.get_driver("nonexistent_engine")
        with mock.patch.dict(os.environ, {"AGY_AGENT_DRIVER": "unknown_cli_v99"}):
            with self.assertRaises(agent_driver.UnknownDriverError):
                reg.get_driver()

        # Explicit empty/whitespace driver name and whitespace-only AGY_AGENT_DRIVER MUST fail closed
        with self.assertRaises(agent_driver.UnknownDriverError):
            reg.get_driver("")
        with self.assertRaises(agent_driver.UnknownDriverError):
            reg.get_driver("   ")
        with mock.patch.dict(os.environ, {"AGY_AGENT_DRIVER": "   "}):
            with self.assertRaises(agent_driver.UnknownDriverError):
                reg.get_driver()
        with mock.patch.dict(os.environ, {"AGY_AGENT_DRIVER": "\t"}):
            with self.assertRaises(agent_driver.UnknownDriverError):
                reg.get_driver()
        with mock.patch.dict(os.environ, {"AGY_AGENT_DRIVER": "agy"}):
            with self.assertRaises(agent_driver.UnknownDriverError):
                reg.get_driver("")

        # Duplicate registration without overwrite raises ValueError
        drv = _FakeDriver("mock_cli")
        reg.register_driver("mock_cli", drv)
        with self.assertRaises(ValueError):
            reg.register_driver("mock_cli", drv)
        self.assertEqual(reg.get_driver("mock_cli"), drv)
        reg.unregister_driver("mock_cli")
        with self.assertRaises(agent_driver.UnknownDriverError):
            reg.get_driver("mock_cli")

        # AgyDriver dynamically respects `mock.patch.object(bridge, "AgySession", ...)`
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            # `_acquire_session(..., driver="")` MUST fail closed even when AGY_AGENT_DRIVER is valid
            with mock.patch.dict(os.environ, {"AGY_AGENT_DRIVER": "agy"}):
                with self.assertRaises(agent_driver.UnknownDriverError):
                    bridge._acquire_session("111", "cid-x", "auto", "m1", "low", None, tmp, driver="")
            captured = []

            class _PatchedAgySession:
                def __init__(self, conv, mode, model, effort, **kw):
                    captured.append((conv, mode, model, effort, kw))
                    self.cid = conv
                    self.last_used = time.time()

                def matches(self, *a, **kw):
                    return False

                def close(self, force=False):
                    pass

            with mock.patch.object(bridge, "AgySession", _PatchedAgySession):
                sess, reused = bridge._acquire_session("111", "cid-x", "auto", "m1", "low", None, tmp)
                self.assertFalse(reused)
                self.assertIsInstance(sess, _PatchedAgySession)
                self.assertEqual(len(captured), 1)
                self.assertEqual(captured[0][0], "cid-x")

    def test_zero_direct_sess_proc_access_in_bridge_py(self):
        src = (BRIDGE_DIR / "bridge.py").read_text(encoding="utf-8")
        tree = ast.parse(src, filename="bridge/bridge.py")
        violations = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "proc"
                and isinstance(node.value, ast.Name)
                and node.value.id == "sess"
            ):
                violations.append(node.lineno)
        self.assertEqual(violations, [], f"Found direct sess.proc accesses in bridge.py lines: {violations}")

    def test_fake_driver_full_lifecycle_warm_reuse_signal_cancel_and_compact_degradation(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            cid = "fake_conv_0001_abcd"

            # Turn 1 script: init -> tool ACTIVE/DONE -> agent_response stream -> result SUCCESS
            # Turn 2 script (same warm session!): agent_response stream -> result SUCCESS
            # Turn 3 script (signal interrupt, exit_code=-15, no result): EOF without result
            turn_scripts = [
                [
                    {"event": "init", "conversation_id": cid},
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "tool",
                            "state": "ACTIVE",
                            "step_index": 1,
                            "tool_name": "run_command",
                            "tool_info": {"command": "echo hi"},
                        },
                    },
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "tool",
                            "state": "DONE",
                            "step_index": 1,
                            "tool_name": "run_command",
                            "tool_info": {"output": "hi"},
                            "duration_seconds": 0.12,
                        },
                    },
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "agent_response",
                            "state": "ACTIVE",
                            "step_index": 2,
                            "text_delta": "Hello ",
                        },
                    },
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "agent_response",
                            "state": "DONE",
                            "step_index": 2,
                            "text_delta": "from FakeDriver!",
                        },
                    },
                    {
                        "event": "result",
                        "result": {
                            "status": "SUCCESS",
                            "conversation_id": cid,
                            "response": "Hello from FakeDriver!",
                            "usage": {"total_tokens": 42},
                        },
                    },
                ],
                [
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "agent_response",
                            "state": "DONE",
                            "step_index": 3,
                            "text_delta": "Warm reuse works!",
                        },
                    },
                    {
                        "event": "result",
                        "result": {
                            "status": "SUCCESS",
                            "conversation_id": cid,
                            "response": "Warm reuse works!",
                            "usage": {"total_tokens": 18},
                        },
                    },
                ],
                [
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "agent_response",
                            "state": "ACTIVE",
                            "step_index": 4,
                            "text_delta": "Partial before signal...",
                        },
                    },
                    {"event": "__set_exit__", "code": -15},
                    {"event": "__eof__"},
                ],
            ]
            drv = _FakeDriver("fake_mem", supports_compact=False, script_factory=lambda: list(turn_scripts))
            agent_driver.register_driver("fake_mem", drv, overwrite=True)
            try:
                events_t1: list[tuple[str, dict]] = []
                events_t2: list[tuple[str, dict]] = []
                events_t3: list[tuple[str, dict]] = []

                with mock.patch.dict(os.environ, {"AGY_AGENT_DRIVER": "fake_mem"}):
                    # Turn 1: cold spawn
                    bridge.run_agy(
                        0,
                        "first prompt",
                        scope_key="web:111:fake",
                        user_role="admin",
                        user_id=111,
                        event_sink=lambda t, p: events_t1.append((t, p)),
                        web_turn_id="turn-fake-1",
                    )
                    self.assertEqual(len(drv.spawned), 1)
                    sess1 = drv.spawned[0]
                    self.assertFalse(hasattr(sess1, "proc"))
                    ev_types_1 = [t for t, _ in events_t1]
                    self.assertIn("init", ev_types_1)
                    self.assertIn("tool_use", ev_types_1)
                    self.assertIn("tool_result", ev_types_1)
                    self.assertIn("text_delta", ev_types_1)
                    self.assertIn("done", ev_types_1)
                    done_ev_1 = [p for t, p in events_t1 if t == "done"][-1]
                    self.assertEqual(done_ev_1["response"], "Hello from FakeDriver!")

                    # Turn 2: warm reuse via matches() -> still only 1 spawned session!
                    bridge.run_agy(
                        0,
                        "second prompt",
                        scope_key="web:111:fake",
                        user_role="admin",
                        user_id=111,
                        override_cid=cid,
                        event_sink=lambda t, p: events_t2.append((t, p)),
                        web_turn_id="turn-fake-2",
                    )
                    self.assertEqual(len(drv.spawned), 1, "Expected warm FakeSession reuse on turn 2")
                    done_ev_2 = [p for t, p in events_t2 if t == "done"][-1]
                    self.assertEqual(done_ev_2["response"], "Warm reuse works!")

                    # Compact on supports_compact=False driver -> graceful degradation, warm session kept alive!
                    ok_c, _dur_c, err_c = bridge._execute_compact_on_session(
                        "web:111:fake", cid, "auto", None, None, None, bridge.WORKDIR
                    )
                    self.assertFalse(ok_c)
                    self.assertIn("does not support /compact", err_c)
                    self.assertTrue(sess1.is_alive(), "Warm session must NOT be killed on unsupported /compact")
                    self.assertEqual(len(sess1.prompts_received), 2, "Must not send /compact to unsupported driver")

                    # Turn 3: signal termination (exit_code=-15, no .proc!) -> aborted event via protocol method
                    bridge.run_agy(
                        0,
                        "third prompt interrupted",
                        scope_key="web:111:fake",
                        user_role="admin",
                        user_id=111,
                        override_cid=cid,
                        event_sink=lambda t, p: events_t3.append((t, p)),
                        web_turn_id="turn-fake-3",
                    )
                    aborted_evs = [p for t, p in events_t3 if t == "aborted"]
                    self.assertTrue(aborted_evs, f"Expected aborted event on exit_code=-15, got {events_t3}")
                    self.assertEqual(aborted_evs[-1]["reason"], "interrupted")

                    # Close cleanup
                    sess1.close(force=True)
                    self.assertFalse(sess1.is_alive())
                    self.assertTrue(sess1.close_calls)
            finally:
                agent_driver.unregister_driver("fake_mem")
                bridge.close_all_sessions_sync()

    def test_compact_precheck_zero_spawn_preserves_warm_session_and_skips_auto_compact(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            cid = "fake_compact_precheck_0001"
            skey = "web:111:compact_guard"
            drv = _FakeDriver("fake_no_compact", supports_compact=False)
            agent_driver.register_driver("fake_no_compact", drv, overwrite=True)
            try:
                with mock.patch.dict(os.environ, {"AGY_AGENT_DRIVER": "fake_no_compact"}):
                    # Case A (Cold pool): supports_compact=False -> unsupported with 0 spawns
                    ok_a, _dur_a, err_a = bridge._execute_compact_on_session(
                        skey, cid, "auto", None, None, None, bridge.WORKDIR
                    )
                    self.assertFalse(ok_a)
                    self.assertIn("does not support /compact", err_a)
                    self.assertEqual(len(drv.spawned), 0, "Cold pool must NOT spawn on unsupported /compact")

                    # Case B (Warm pool with param diff): warm session alive with model="m1", effort="high",
                    # calling _execute_compact_on_session with model=None, effort=None MUST NOT kill or respawn it
                    s_warm, reused = bridge._acquire_session(
                        skey, cid, "auto", "m1", "high", None, bridge.WORKDIR
                    )
                    self.assertFalse(reused)
                    self.assertEqual(len(drv.spawned), 1)
                    self.assertTrue(s_warm.is_alive())

                    ok_b, _dur_b, err_b = bridge._execute_compact_on_session(
                        skey, cid, "auto", None, None, None, bridge.WORKDIR
                    )
                    self.assertFalse(ok_b)
                    self.assertIn("does not support /compact", err_b)
                    self.assertTrue(s_warm.is_alive(), "Warm session MUST remain alive despite param diff")
                    self.assertEqual(len(drv.spawned), 1, "Must NOT respawn on unsupported /compact")
                    self.assertEqual(s_warm.close_calls, [])

                    # Case C (Auto-compact entry): _maybe_post_turn_auto_compact silently skips without
                    # creating LiveDraftStreamer or incrementing _auto_compact_fail_streak
                    bridge._auto_compact_fail_streak.pop(cid, None)
                    with (
                        mock.patch.object(
                            bridge,
                            "should_auto_compact",
                            return_value=(True, {"raw_ctx_tokens": 999999, "total_lines": 100}),
                        ),
                        mock.patch.object(bridge, "LiveDraftStreamer") as m_streamer,
                    ):
                        bridge._maybe_post_turn_auto_compact(
                            111, cid, "auto", "m1", "high", None, bridge.WORKDIR, scope_key=skey
                        )
                        m_streamer.assert_not_called()
                        self.assertEqual(
                            bridge._auto_compact_fail_streak.get(cid, 0),
                            0,
                            "Unsupported driver must NOT increment _auto_compact_fail_streak",
                        )
                        self.assertEqual(len(drv.spawned), 1)
                        self.assertTrue(s_warm.is_alive())

                    # Pre-turn guard inside run_agy also skips without calling _execute_compact_on_session
                    drv._script_factory = lambda: [
                        [
                            {
                                "event": "result",
                                "result": {
                                    "status": "SUCCESS",
                                    "conversation_id": cid,
                                    "response": "pre-turn skip ok",
                                },
                            }
                        ]
                    ]
                    s_warm._scripts.append(
                        [
                            {
                                "event": "result",
                                "result": {
                                    "status": "SUCCESS",
                                    "conversation_id": cid,
                                    "response": "pre-turn skip ok",
                                },
                            }
                        ]
                    )
                    events_pre: list[tuple[str, dict]] = []
                    with (
                        mock.patch.object(
                            bridge,
                            "should_auto_compact",
                            return_value=(True, {"raw_ctx_tokens": 999999, "total_lines": 100}),
                        ),
                        mock.patch.object(bridge, "_execute_compact_on_session") as m_exec_compact,
                    ):
                        bridge.run_agy(
                            0,
                            "hello",
                            scope_key=skey,
                            user_role="admin",
                            user_id=111,
                            override_cid=cid,
                            override_model="m1",
                            override_effort="high",
                            event_sink=lambda t, p: events_pre.append((t, p)),
                            web_turn_id="turn-pre-skip",
                        )
                        m_exec_compact.assert_not_called()
                        self.assertTrue(any(t == "done" for t, _ in events_pre))
            finally:
                agent_driver.unregister_driver("fake_no_compact")
                bridge.close_all_sessions_sync()


if __name__ == "__main__":
    unittest.main()
