#!/usr/bin/env python3
"""Offline unit & integration tests for Bridge Anti-Hang hardening (C1–C8):

- C1: Descendant process tree cleanup (`_kill_process_tree`) + pipe EOF & zero ResourceWarning
- C2: Anti-mis-kill guards (PID 1/self/own-PGID, cross-UID, PID-reuse starttime check, spaces/parens comm)
- C3: Dual-layer watchdog config boundaries & active multi-step turn anti-false-positive
- C4: Dual-layer watchdog timeout recovery, strict no-failover, RBAC retry button & group redaction
- C5: Same-scope preemption 4 negative security guardrails
- C6: Same-scope admin preemption, M2/M3 double-send race, turn generation isolation
- C7: Cancel button RBAC closure, `/cancel` + `action:cancel` fail-closed, `/status` DM scope redaction, Draft UX
- C8: Isolated env loader & core-public desensitization compliance
"""

from __future__ import annotations

import collections
import gc
import importlib
import json
import os
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import warnings
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

# Dynamically assembled synthetic IDs & credentials (RFC2606 / desensitization-safe)
ADMIN_UID = 810_000 + 11
READONLY_UID = ADMIN_UID + 1
DENIED_UID = ADMIN_UID + 2
GROUP_CHAT_ID = -(100_000_000_0000 + 7319)
OTHER_GROUP_CHAT_ID = GROUP_CHAT_ID - 1
TOPIC_A = 41
TOPIC_B = TOPIC_A + 1
SYNTH_TOKEN = f"{ADMIN_UID}:EXAMPLE_" + "ANTI_HANG_TEST_TOKEN_01"
SYNTH_EMAIL = "tester" + "@example.invalid"


def _load_isolated_bridge(tmp: str, extra_env: dict[str, str] | None = None):
    """Reload `access_control`, `bot_bus`, and `bridge` with every ambient `AGY_*` var explicitly isolated."""
    env_patch = {
        "AGY_BOT_BUS_DIR": os.path.join(tmp, "bus"),
        "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
        "AGY_TG_QUEUE_FILE": os.path.join(tmp, "state.json.queue.json"),
        "AGY_TG_QUEUE_TTL_SEC": "3600",
        "AGY_MEMORY_TAINT_FILE": os.path.join(tmp, "memory_taint.json"),
        "AGY_TG_WORKDIR": os.path.join(tmp, "workdir"),
        "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
        "AGY_TG_ALLOWED_CHATS": f"{GROUP_CHAT_ID},{OTHER_GROUP_CHAT_ID},{ADMIN_UID}",
        "AGY_TG_ALLOWED_USERS": "",
        "AGY_TG_ADMIN_USERS": str(ADMIN_UID),
        "AGY_TG_READONLY_USERS": str(READONLY_UID),
        "AGY_TG_ALLOW_GROUP_READONLY": "0",
        "AGY_TG_BOT_TOKEN": SYNTH_TOKEN,
        "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
        "AGY_TG_BOT_MODEL": "",
        "AGY_TG_BOT_EFFORT": "",
        "AGY_TG_BOT_ROLE": "",
        "AGY_TG_BOT_PROJECT": "",
        "AGY_TG_FALLBACK_MODELS": "",
        "AGY_TG_BUS_CHAT_MODE": "",
        "AGY_BUS_CHAT_MODE": "conversational",
        "AGY_BUS_FAST_CHAT": "1",
        "AGY_BG_WAIT_TIMEOUT": "300",
        "AGY_TURN_SILENCE_TIMEOUT": "420",
        "AGY_PREEMPT_WAITING_BG": "1",
        "AGY_PREEMPT_BG_GRACE_SEC": "5",
        "AGY_BOT_CHAIN": "",
        "AGY_BOT_ORIGIN_MSG_ID": "0",
        "AGY_BOT_MENTION_HOP": "0",
    }
    if extra_env:
        env_patch.update(extra_env)
    with mock.patch.dict(os.environ, env_patch, clear=False):
        import access_control  # noqa: E402
        import bot_bus  # noqa: E402
        import bridge  # noqa: E402

        importlib.reload(access_control)
        importlib.reload(bot_bus)
        importlib.reload(bridge)
        os.makedirs(bridge.WORKDIR, exist_ok=True)
        os.makedirs(bridge.UPLOADDIR, exist_ok=True)
        bridge.BOT_META.update({"bot_id": 1001, "handle": "test_anti_hang_bot", "resolved": True})
        return bridge


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _make_stat_line(pid: int, comm: str, state: str, starttime: str) -> str:
    """Build a valid Linux `/proc/<pid>/stat` line where index 19 after `') '` is `starttime`."""
    # Fields after ') ': state(0), ppid(1)..itrealvalue(18), starttime(19), vsize(20), rss(21)
    fields = [state] + ["0"] * 18 + [str(starttime), "4096", "128"]
    return f"{pid} ({comm}) " + " ".join(fields) + "\n"


def _write_fake_proc_entry(
    proc_root: Path,
    pid: int,
    *,
    comm: str = "worker",
    state: str = "S",
    starttime: str = "100001",
    euid: int | None = None,
    children: list[int] | None = None,
):
    pdir = proc_root / str(pid)
    tdir = pdir / "task" / str(pid)
    tdir.mkdir(parents=True, exist_ok=True)
    (pdir / "stat").write_text(_make_stat_line(pid, comm, state, starttime), encoding="utf-8")
    uid_val = os.geteuid() if euid is None else euid
    (pdir / "status").write_text(
        f"Name:\t{comm}\nUid:\t{uid_val}\t{uid_val}\t{uid_val}\t{uid_val}\n",
        encoding="utf-8",
    )
    (tdir / "children").write_text(" ".join(str(c) for c in (children or [])), encoding="utf-8")


class _FakeAgySession:
    """Deterministic fake `AgySession` for watchdog & preemption tests."""

    def __init__(self, events=None, *, cid="conv-test-001", stderr_text="", block_until_closed=False):
        self.cid = cid
        self.last_used = time.time()
        self.eof_reached = False
        self.close_calls: list[bool] = []
        self._stderr_text = stderr_text
        self._pushback = collections.deque()
        self._event_q: queue.Queue = queue.Queue()
        self._block_until_closed = block_until_closed
        self.proc = mock.Mock()
        self.proc.returncode = None
        self.proc.poll.return_value = None
        for ev in (events or []):
            self._event_q.put(ev)

    def send_user_prompt(self, prompt, raw_slash=False):
        self.last_prompt = prompt

    def push_event(self, ev):
        self._event_q.put(ev)

    def next_event(self, timeout=0.25):
        if self._pushback:
            return self._pushback.popleft()
        try:
            item = self._event_q.get(timeout=min(timeout, 0.05))
        except queue.Empty:
            return None
        if isinstance(item, tuple) and item[0] == "__SLEEP__":
            time.sleep(item[1])
            return None
        return item

    def peek_immediate_result(self, timeout=0.065):
        ev = self.next_event(timeout=min(timeout, 0.02))
        if ev is None:
            return None, "waiting"
        if ev.get("event") == "result":
            return (ev.get("result") or ev), None
        self._pushback.append(ev)
        return None, "more_steps"

    def get_stderr_text(self):
        return self._stderr_text

    def is_alive(self):
        return not self.eof_reached

    def close(self, force=False, term_timeout=None):
        self.close_calls.append(bool(force))
        self.eof_reached = True
        self.proc.returncode = -9 if force else 0
        self.proc.poll.return_value = self.proc.returncode
        self._event_q.put({"event": "__eof__"})


class TestC1ProcessTreeAndPipeEOF(unittest.TestCase):
    """C1: Real child + detached SIGTERM-ignoring grandchild holding stdout; zero ResourceWarning."""

    def test_close_force_kills_detached_sigterm_ignoring_grandchild_and_delivers_eof_zero_warnings(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)

            grandchild_script = (
                "import signal, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "time.sleep(60)"
            )
            child_script = (
                "import json, subprocess, sys, time; "
                f"gc = subprocess.Popen([sys.executable, '-c', {grandchild_script!r}], "
                "start_new_session=True, stdin=subprocess.DEVNULL, stdout=sys.stdout, stderr=sys.stderr, close_fds=False); "
                "print(json.dumps({'event': 'init', 'conversation_id': 'conv-tree', 'gc_pid': gc.pid}), flush=True); "
                "time.sleep(60)"
            )

            with warnings.catch_warnings():
                warnings.simplefilter("error", ResourceWarning)

                sess = bridge.AgySession.__new__(bridge.AgySession)
                sess.cid = None
                sess.event_q = queue.Queue()
                sess._pushback = collections.deque()
                sess.stderr_tail = collections.deque(maxlen=200)
                sess.eof_reached = False
                sess._close_lock = threading.Lock()
                sess._closed = False
                sess.proc = subprocess.Popen(
                    [sys.executable, "-c", child_script],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    start_new_session=True,
                )
                sess._stdout_thread = threading.Thread(target=sess._drain_stdout, daemon=True)
                sess._stderr_thread = threading.Thread(target=sess._drain_stderr, daemon=True)
                sess._stdout_thread.start()
                sess._stderr_thread.start()

                gc_pid = None
                child_pid = sess.proc.pid
                try:
                    init_ev = sess.next_event(timeout=5.0)
                    self.assertIsNotNone(init_ev, "Expected init event with grandchild PID")
                    gc_pid = int(init_ev["gc_pid"])
                    self.assertTrue(_pid_exists(child_pid))
                    self.assertTrue(_pid_exists(gc_pid))
                    # Confirm grandchild truly detached into its own session/PGID
                    self.assertNotEqual(os.getpgid(child_pid), os.getpgid(gc_pid))

                    sess.close(force=True, term_timeout=0.25)

                    # Both child and detached SIGTERM-ignoring grandchild must be dead
                    deadline = time.monotonic() + 2.0
                    while time.monotonic() < deadline and (_pid_exists(child_pid) or _pid_exists(gc_pid)):
                        time.sleep(0.05)
                    self.assertFalse(_pid_exists(child_pid), f"Child {child_pid} still alive")
                    self.assertFalse(_pid_exists(gc_pid), f"Detached grandchild {gc_pid} still alive")

                    # Drain queue and confirm __eof__ was delivered
                    eof_seen = False
                    for _ in range(10):
                        ev = sess.next_event(timeout=0.2)
                        if ev and ev.get("event") == "__eof__":
                            eof_seen = True
                            break
                    self.assertTrue(eof_seen, "Expected {'event': '__eof__'} after close(force=True)")
                    self.assertTrue(sess.eof_reached)
                    self.assertTrue(sess.proc.stdin.closed)
                    self.assertTrue(sess.proc.stdout.closed)
                    self.assertTrue(sess.proc.stderr.closed)
                finally:
                    if gc_pid and _pid_exists(gc_pid):
                        try:
                            os.kill(gc_pid, signal.SIGKILL)
                        except OSError:
                            pass
                    sess.close(force=True, term_timeout=0.1)
                    sess.proc = None
                    gc.collect()

    def test_close_graceful_force_false_closes_pipes_zero_resource_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            quick_script = (
                "import json, sys; "
                "print(json.dumps({'event': 'init', 'conversation_id': 'conv-clean'}), flush=True); "
                "sys.stdin.read()"
            )
            with warnings.catch_warnings():
                warnings.simplefilter("error", ResourceWarning)

                sess = bridge.AgySession.__new__(bridge.AgySession)
                sess.cid = None
                sess.event_q = queue.Queue()
                sess._pushback = collections.deque()
                sess.stderr_tail = collections.deque(maxlen=200)
                sess.eof_reached = False
                sess._close_lock = threading.Lock()
                sess._closed = False
                sess.proc = subprocess.Popen(
                    [sys.executable, "-c", quick_script],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    start_new_session=True,
                )
                sess._stdout_thread = threading.Thread(target=sess._drain_stdout, daemon=True)
                sess._stderr_thread = threading.Thread(target=sess._drain_stderr, daemon=True)
                sess._stdout_thread.start()
                sess._stderr_thread.start()

                init_ev = sess.next_event(timeout=5.0)
                self.assertEqual("conv-clean", (init_ev or {}).get("conversation_id"))

                sess.close(force=False)
                self.assertTrue(sess.proc.stdin.closed)
                self.assertTrue(sess.proc.stdout.closed)
                self.assertTrue(sess.proc.stderr.closed)
                eof_ev = sess.next_event(timeout=1.0)
                self.assertEqual({"event": "__eof__"}, eof_ev)
                sess.proc = None
                gc.collect()

    def test_close_does_not_deadlock_when_double_fork_orphan_holds_stdout(self):
        """P0 C1: Double-forked orphan reparented to PID 1 holding stdout must not deadlock close()."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            # Parent spawns an intermediate child that setsid()+forks an orphan holding stdout/stderr,
            # writes orphan PID back via pipe, and immediately exits so orphan is reparented to PID 1.
            orphan_parent_script = (
                "import json, os, sys, time\n"
                "r_fd, w_fd = os.pipe()\n"
                "mid = os.fork()\n"
                "if mid == 0:\n"
                "    os.close(r_fd)\n"
                "    os.setsid()\n"
                "    orphan = os.fork()\n"
                "    if orphan == 0:\n"
                "        os.close(w_fd)\n"
                "        time.sleep(60)\n"
                "        os._exit(0)\n"
                "    os.write(w_fd, str(orphan).encode())\n"
                "    os.close(w_fd)\n"
                "    os._exit(0)\n"
                "os.close(w_fd)\n"
                "os.waitpid(mid, 0)\n"
                "orphan_pid = int(os.read(r_fd, 64).decode().strip())\n"
                "os.close(r_fd)\n"
                "print(json.dumps({'event': 'init', 'conversation_id': 'conv-orphan', 'orphan_pid': orphan_pid}), flush=True)\n"
                "if sys.argv[1] == 'exit_on_stdin':\n"
                "    sys.stdin.read()\n"
                "else:\n"
                "    time.sleep(60)\n"
            )

            for force_flag, mode_arg in ((True, "sleep"), (False, "exit_on_stdin")):
                with self.subTest(force=force_flag):
                    with warnings.catch_warnings():
                        warnings.simplefilter("error", ResourceWarning)

                        sess = bridge.AgySession.__new__(bridge.AgySession)
                        sess.cid = None
                        sess.event_q = queue.Queue()
                        sess._pushback = collections.deque()
                        sess.stderr_tail = collections.deque(maxlen=200)
                        sess.eof_reached = False
                        sess._close_lock = threading.Lock()
                        sess._closed = False
                        sess._eof_lock = threading.Lock()
                        sess._eof_emitted = False
                        sess.proc = subprocess.Popen(
                            [sys.executable, "-c", orphan_parent_script, mode_arg],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            bufsize=1,
                            start_new_session=True,
                        )
                        sess._proc_starttime = bridge._read_proc_starttime(sess.proc.pid)
                        sess._stdout_thread = threading.Thread(target=sess._drain_stdout, daemon=True)
                        sess._stderr_thread = threading.Thread(target=sess._drain_stderr, daemon=True)
                        sess._stdout_thread.start()
                        sess._stderr_thread.start()

                        orphan_pid = None
                        try:
                            init_ev = sess.next_event(timeout=5.0)
                            self.assertIsNotNone(init_ev, f"Expected init event for force={force_flag}")
                            orphan_pid = int(init_ev["orphan_pid"])
                            self.assertTrue(_pid_exists(orphan_pid))

                            t0 = time.monotonic()
                            sess.close(force=force_flag, term_timeout=0.2)
                            elapsed = time.monotonic() - t0
                            self.assertLess(
                                elapsed,
                                2.5,
                                f"close(force={force_flag}) deadlocked or exceeded bounded return ({elapsed:.2f}s)",
                            )
                            self.assertTrue(sess.eof_reached)
                            self.assertTrue(
                                sess._stdout_thread.is_alive(),
                                "Expected _stdout_thread still alive while reparented orphan holds stdout",
                            )
                            eof_ev = sess.next_event(timeout=0.5)
                            self.assertEqual({"event": "__eof__"}, eof_ev)
                            self.assertTrue(sess.proc.stdin.closed)
                        finally:
                            if orphan_pid and _pid_exists(orphan_pid):
                                try:
                                    os.kill(orphan_pid, signal.SIGKILL)
                                except OSError:
                                    pass
                            sess._stdout_thread.join(timeout=2.0)
                            sess._stderr_thread.join(timeout=2.0)
                            self.assertFalse(sess._stdout_thread.is_alive())
                            self.assertFalse(sess._stderr_thread.is_alive())
                            self.assertTrue(sess.proc.stdout.closed)
                            self.assertTrue(sess.proc.stderr.closed)
                            # No duplicate __eof__ emitted when reader thread exits later
                            self.assertIsNone(sess.next_event(timeout=0.05))
                            sess.proc = None
                            gc.collect()


class TestC2KillProcessTreeSafetyGuards(unittest.TestCase):
    """C2: Anti-mis-kill guards & PID reuse protection via `/proc` parsing."""

    def test_parse_proc_stat_with_spaces_and_parens_in_comm(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            fake_proc = Path(tmp) / "fake_proc"
            _write_fake_proc_entry(
                fake_proc,
                42001,
                comm="foo ) bar (baz)",
                state="S",
                starttime="987654321",
            )
            state, st = bridge._read_proc_stat_info(42001, proc_root=str(fake_proc))
            self.assertEqual("S", state)
            self.assertEqual("987654321", st)
            self.assertEqual("987654321", bridge._read_proc_starttime(42001, proc_root=str(fake_proc)))

    def test_excludes_dangerous_targets_and_blocks_pid_reuse_before_sigkill(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            fake_proc = Path(tmp) / "fake_proc"
            my_pid = os.getpid()
            my_pgid = os.getpgrp()
            my_euid = os.geteuid()

            root_pid = 51000
            valid_detached = 51001
            other_uid_pid = 51002
            same_pgid_pid = 51003
            reused_pid = 51004

            _write_fake_proc_entry(
                fake_proc,
                root_pid,
                comm="agy ) root",
                starttime="10010",
                euid=my_euid,
                children=[1, my_pid, valid_detached, other_uid_pid, same_pgid_pid, reused_pid],
            )
            _write_fake_proc_entry(fake_proc, 1, comm="systemd", starttime="1", euid=0)
            _write_fake_proc_entry(fake_proc, my_pid, comm="python3", starttime="500", euid=my_euid)
            _write_fake_proc_entry(fake_proc, valid_detached, comm="sub (worker) 1", starttime="10011", euid=my_euid)
            _write_fake_proc_entry(fake_proc, other_uid_pid, comm="other", starttime="10012", euid=my_euid + 1)
            _write_fake_proc_entry(fake_proc, same_pgid_pid, comm="peer", starttime="10013", euid=my_euid)
            _write_fake_proc_entry(fake_proc, reused_pid, comm="reuse_me", starttime="10014", euid=my_euid)

            pgid_map = {
                1: 1,
                my_pid: my_pgid,
                root_pid: root_pid,
                valid_detached: valid_detached,
                other_uid_pid: other_uid_pid,
                same_pgid_pid: my_pgid,
                reused_pid: reused_pid,
            }
            kill_calls: list[tuple[int, int]] = []
            killpg_calls: list[tuple[int, int]] = []

            def fake_getpgid(pid):
                if pid not in pgid_map:
                    raise ProcessLookupError(pid)
                return pgid_map[pid]

            def fake_kill(pid, sig):
                kill_calls.append((pid, sig))
                # Simulate PID reuse right after SIGTERM on `reused_pid`
                if pid == reused_pid and sig == signal.SIGTERM:
                    _write_fake_proc_entry(
                        fake_proc, reused_pid, comm="unrelated_new_proc", starttime="99999", euid=my_euid
                    )

            def fake_killpg(pgid, sig):
                killpg_calls.append((pgid, sig))

            with (
                mock.patch.object(os, "getpgid", side_effect=fake_getpgid),
                mock.patch.object(os, "kill", side_effect=fake_kill),
                mock.patch.object(os, "killpg", side_effect=fake_killpg),
            ):
                bridge._kill_process_tree(root_pid, term_timeout=0.05, proc_root=str(fake_proc))

            targeted_pids = {pid for pid, _ in kill_calls} | {pgid for pgid, _ in killpg_calls}
            for forbidden in (1, my_pid, my_pgid, other_uid_pid, same_pgid_pid):
                self.assertNotIn(forbidden, targeted_pids, f"Forbidden target {forbidden} must never be signalled")

            self.assertIn((root_pid, signal.SIGTERM), killpg_calls)
            self.assertIn((root_pid, signal.SIGKILL), killpg_calls)
            self.assertIn((valid_detached, signal.SIGTERM), kill_calls)
            self.assertIn((valid_detached, signal.SIGKILL), kill_calls)
            # Reused PID may get initial SIGTERM before reuse, MUST NOT receive SIGKILL after starttime changed
            self.assertIn((reused_pid, signal.SIGTERM), kill_calls)
            self.assertNotIn((reused_pid, signal.SIGKILL), kill_calls)

    def test_close_force_idempotent_and_skips_kill_on_already_exited_proc(self):
        """P1 C2: Calling close(force=True) twice invokes _kill_process_tree once with expected_root_starttime;
        already-exited procs never trigger _kill_process_tree.
        """
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            real_kill = bridge._kill_process_tree

            with warnings.catch_warnings():
                warnings.simplefilter("error", ResourceWarning)

                # Part 1: Live process closed twice -> _kill_process_tree called exactly once with starttime
                sess = bridge.AgySession.__new__(bridge.AgySession)
                sess.cid = None
                sess.event_q = queue.Queue()
                sess._pushback = collections.deque()
                sess.stderr_tail = collections.deque(maxlen=200)
                sess.eof_reached = False
                sess._close_lock = threading.Lock()
                sess._closed = False
                sess._eof_lock = threading.Lock()
                sess._eof_emitted = False
                sess.proc = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    start_new_session=True,
                )
                expected_st = bridge._read_proc_starttime(sess.proc.pid)
                self.assertIsNotNone(expected_st)
                sess._proc_starttime = expected_st
                sess._stdout_thread = threading.Thread(target=sess._drain_stdout, daemon=True)
                sess._stderr_thread = threading.Thread(target=sess._drain_stderr, daemon=True)
                sess._stdout_thread.start()
                sess._stderr_thread.start()

                kill_invocations = []

                def spy_kill(*args, **kwargs):
                    kill_invocations.append((args, kwargs))
                    return real_kill(*args, **kwargs)

                try:
                    with mock.patch.object(bridge, "_kill_process_tree", side_effect=spy_kill):
                        sess.close(force=True, term_timeout=0.2)
                        sess.close(force=True, term_timeout=0.2)

                    self.assertEqual(1, len(kill_invocations))
                    self.assertEqual(expected_st, kill_invocations[0][1].get("expected_root_starttime"))
                finally:
                    sess.proc = None
                    gc.collect()

                # Part 2: Already-reaped process (poll() is not None) -> zero _kill_process_tree calls
                sess2 = bridge.AgySession.__new__(bridge.AgySession)
                sess2.cid = None
                sess2.event_q = queue.Queue()
                sess2._pushback = collections.deque()
                sess2.stderr_tail = collections.deque(maxlen=200)
                sess2.eof_reached = False
                sess2._close_lock = threading.Lock()
                sess2._closed = False
                sess2._eof_lock = threading.Lock()
                sess2._eof_emitted = False
                sess2.proc = subprocess.Popen(
                    [sys.executable, "-c", "pass"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    start_new_session=True,
                )
                sess2._proc_starttime = bridge._read_proc_starttime(sess2.proc.pid)
                sess2._stdout_thread = threading.Thread(target=sess2._drain_stdout, daemon=True)
                sess2._stderr_thread = threading.Thread(target=sess2._drain_stderr, daemon=True)
                sess2._stdout_thread.start()
                sess2._stderr_thread.start()
                sess2.proc.wait(timeout=3.0)
                self.assertIsNotNone(sess2.proc.poll())

                kill_mock = mock.Mock()
                try:
                    with mock.patch.object(bridge, "_kill_process_tree", kill_mock):
                        sess2.close(force=True, term_timeout=0.2)
                    self.assertEqual(0, kill_mock.call_count)
                finally:
                    sess2.proc = None
                    gc.collect()

    def test_kill_process_tree_rejects_root_starttime_mismatch_and_non_leader_killpg(self):
        """P1 C2: _kill_process_tree aborts on root starttime mismatch and never calls killpg if root_pgid != root_pid."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            fake_proc = Path(tmp) / "fake_proc"
            my_euid = os.geteuid()
            my_pgid = os.getpgrp()

            # Case 1: root_pid starttime mismatch -> zero kill/killpg calls (even with children present)
            root_mismatch = 52000
            child_of_mismatch = 52001
            _write_fake_proc_entry(
                fake_proc,
                root_mismatch,
                comm="reused_root",
                starttime="10010",
                euid=my_euid,
                children=[child_of_mismatch],
            )
            _write_fake_proc_entry(
                fake_proc,
                child_of_mismatch,
                comm="reused_child",
                starttime="10011",
                euid=my_euid,
            )

            # Case 2: root_pid is NOT its own PGID leader (root_pgid != root_pid and != my_pgid) -> zero killpg
            root_non_leader = 52010
            shared_pgid = 52999 if 52999 != my_pgid else 52998
            _write_fake_proc_entry(
                fake_proc,
                root_non_leader,
                comm="non_leader",
                starttime="20020",
                euid=my_euid,
            )

            pgid_map = {
                root_mismatch: root_mismatch,
                child_of_mismatch: child_of_mismatch,
                root_non_leader: shared_pgid,
            }
            kill_calls: list[tuple[int, int]] = []
            killpg_calls: list[tuple[int, int]] = []

            def fake_getpgid(pid):
                if pid not in pgid_map:
                    raise ProcessLookupError(pid)
                return pgid_map[pid]

            with (
                mock.patch.object(os, "getpgid", side_effect=fake_getpgid),
                mock.patch.object(os, "kill", side_effect=lambda p, s: kill_calls.append((p, s))),
                mock.patch.object(os, "killpg", side_effect=lambda g, s: killpg_calls.append((g, s))),
            ):
                bridge._kill_process_tree(
                    root_mismatch,
                    term_timeout=0.05,
                    proc_root=str(fake_proc),
                    expected_root_starttime="99999",
                )
                self.assertEqual([], kill_calls, "Mismatched root starttime must produce zero os.kill calls")
                self.assertEqual([], killpg_calls, "Mismatched root starttime must produce zero os.killpg calls")

                bridge._kill_process_tree(
                    root_non_leader,
                    term_timeout=0.05,
                    proc_root=str(fake_proc),
                    expected_root_starttime="20020",
                )
                self.assertEqual([], killpg_calls, "Non-leader root_pgid != root_pid must NEVER call os.killpg")
                self.assertIn((root_non_leader, signal.SIGTERM), kill_calls)
                self.assertIn((root_non_leader, signal.SIGKILL), kill_calls)


class TestC3WatchdogConfigAndNoFalsePositive(unittest.TestCase):
    """C3: Config boundary parsing & active multi-step turn anti-false-positive."""

    def test_watchdog_env_parsing_defaults_zero_and_invalid_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            b_def = _load_isolated_bridge(tmp)
            self.assertEqual(300.0, b_def.BG_WAIT_TIMEOUT)
            self.assertEqual(420.0, b_def.TURN_SILENCE_TIMEOUT)
            self.assertTrue(b_def.PREEMPT_WAITING_BG)
            self.assertEqual(5.0, b_def.PREEMPT_BG_GRACE_SEC)

            b_zero = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_BG_WAIT_TIMEOUT": "0",
                    "AGY_TURN_SILENCE_TIMEOUT": "0",
                    "AGY_PREEMPT_WAITING_BG": "off",
                    "AGY_PREEMPT_BG_GRACE_SEC": "0",
                },
            )
            self.assertEqual(0.0, b_zero.BG_WAIT_TIMEOUT)
            self.assertEqual(0.0, b_zero.TURN_SILENCE_TIMEOUT)
            self.assertFalse(b_zero.PREEMPT_WAITING_BG)
            self.assertEqual(0.0, b_zero.PREEMPT_BG_GRACE_SEC)

            b_bad = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_BG_WAIT_TIMEOUT": "not_a_number",
                    "AGY_TURN_SILENCE_TIMEOUT": "-15",
                    "AGY_PREEMPT_WAITING_BG": "false",
                    "AGY_PREEMPT_BG_GRACE_SEC": "nan",
                },
            )
            self.assertEqual(300.0, b_bad.BG_WAIT_TIMEOUT)
            self.assertEqual(420.0, b_bad.TURN_SILENCE_TIMEOUT)
            self.assertFalse(b_bad.PREEMPT_WAITING_BG)
            self.assertEqual(5.0, b_bad.PREEMPT_BG_GRACE_SEC)

    def test_active_multistep_turn_exceeding_silence_timeout_succeeds_and_clears_waiting_bg(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_BG_WAIT_TIMEOUT": "0.25",
                    "AGY_TURN_SILENCE_TIMEOUT": "0.25",
                },
            )
            # Active steps spaced by 0.11s -> total > 0.44s (> 0.25s timeout), must succeed without false positive!
            events = [
                {"event": "init", "conversation_id": "conv-active-1"},
                ("__SLEEP__", 0.11),
                {"event": "step_update", "step_update": {"step_type": "agent_response", "state": "ACTIVE", "step_index": 1, "text_delta": "Step 1 milestone"}},
                {"event": "step_update", "step_update": {"step_type": "agent_response", "state": "DONE", "step_index": 1}},
                # Now in waiting_bg! Next step_update arrives at +0.11s (< 0.25s) and must clear waiting_bg
                ("__SLEEP__", 0.11),
                {"event": "step_update", "step_update": {"step_type": "tool", "state": "ACTIVE", "step_index": 2, "tool_name": "run_cmd", "tool_info": {}}},
                ("__SLEEP__", 0.11),
                {"event": "step_update", "step_update": {"step_type": "tool", "state": "DONE", "step_index": 2, "tool_name": "run_cmd", "duration_seconds": 0.1}},
                ("__SLEEP__", 0.11),
                {"event": "result", "result": {"status": "SUCCESS", "conversation_id": "conv-active-1", "response": "All done!"}},
            ]
            fake_sess = _FakeAgySession(events, cid="conv-active-1")
            sent_msgs = []
            web_events = []

            with (
                mock.patch.object(bridge, "_acquire_session", return_value=(fake_sess, False)),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_msgs.append((a, kw)) or 101),
                mock.patch.object(bridge, "send_rich", side_effect=lambda *a, **kw: sent_msgs.append((a, kw)) or (102, "ok")),
                mock.patch.object(bridge, "push_step_images", return_value=None),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact", return_value=None),
            ):
                bridge.run_agy(
                    ADMIN_UID,
                    "long active task",
                    user_role="admin",
                    user_id=ADMIN_UID,
                    event_sink=lambda t, p: web_events.append((t, p)),
                )

            self.assertEqual([], fake_sess.close_calls)
            self.assertFalse(bridge.turn_running)
            self.assertFalse(bridge.turn_waiting_bg)
            self.assertIsNone(bridge.turn_waiting_bg_since)
            self.assertTrue(any(ev_t == "done" and pl.get("status") == "SUCCESS" for ev_t, pl in web_events))

    def test_empty_polls_and_push_step_images_never_refresh_last_activity_at(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_BG_WAIT_TIMEOUT": "0",
                    "AGY_TURN_SILENCE_TIMEOUT": "5",
                },
            )
            fake_sess = _FakeAgySession([], cid="conv-silent-1")
            img_scans = []
            sent_msgs = []
            # Controlled clock: advances 2.5s per idle poll so push_step_images fires >=2 times before 5s silence triggers
            clock = [1000.0]

            def fake_next_event(timeout=0.25):
                clock[0] += 2.5
                return None

            fake_sess.next_event = fake_next_event

            with (
                mock.patch.object(bridge.time, "time", side_effect=lambda: clock[0]),
                mock.patch.object(bridge, "_acquire_session", return_value=(fake_sess, False)),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_msgs.append((a, kw)) or 201),
                mock.patch.object(bridge, "push_step_images", side_effect=lambda *a, **kw: img_scans.append(1)),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
            ):
                bridge.run_agy(ADMIN_UID, "silent hang", user_role="admin", user_id=ADMIN_UID)

            self.assertGreaterEqual(len(img_scans), 2, "push_step_images must have run during idle polls")
            self.assertEqual([True], fake_sess.close_calls)
            self.assertTrue(any("静默超时" in str(a[1]) for a, _kw in sent_msgs))


class TestC4WatchdogTimeoutRecoveryNoFailover(unittest.TestCase):
    """C4: Dual-layer timeout recovery, no failover, RBAC retry button & group desensitization."""

    def test_bg_wait_timeout_aborts_without_failover_releases_lease_and_gives_admin_retry_button(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_BG_WAIT_TIMEOUT": "0.16",
                    "AGY_TURN_SILENCE_TIMEOUT": "60",
                    "AGY_TG_FALLBACK_MODELS": "fallback-m1,fallback-m2",
                },
            )
            events = [
                {"event": "init", "conversation_id": "conv-bg-hang"},
                {"event": "step_update", "step_update": {"step_type": "agent_response", "state": "ACTIVE", "step_index": 1, "text_delta": "Starting bg work"}},
                {"event": "step_update", "step_update": {"step_type": "agent_response", "state": "DONE", "step_index": 1}},
            ]
            fake_sess = _FakeAgySession(events, cid="conv-bg-hang")
            acq_calls = []
            sent_calls = []
            fake_lease = mock.Mock()

            with (
                mock.patch.object(bridge, "_acquire_session", side_effect=lambda *a, **kw: (acq_calls.append((a, kw)) or (fake_sess, False))),
                mock.patch.object(bridge.studio_ipc.ConversationLease, "try_acquire", return_value=fake_lease),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_calls.append((a, kw)) or 301),
                mock.patch.object(bridge, "send_rich", side_effect=lambda *a, **kw: (302, "ok")),
                mock.patch.object(bridge, "push_step_images", return_value=None),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
            ):
                bridge.run_agy(ADMIN_UID, "run bg wait", user_role="admin", user_id=ADMIN_UID)

            self.assertEqual(1, len(acq_calls), "Watchdog timeout must NEVER trigger retry or model failover")
            self.assertEqual([True], fake_sess.close_calls)
            self.assertFalse(bridge.turn_running)
            self.assertFalse(bridge.turn_waiting_bg)
            self.assertIsNone(bridge.turn_waiting_bg_since)
            fake_lease.release.assert_called_once()

            sc = bridge.get_scope_state(str(ADMIN_UID))
            self.assertEqual("TIMEOUT", (sc.get("last_turn") or {}).get("status"))

            timeout_msgs = [(a, kw) for a, kw in sent_calls if "后台等待超时" in str(a[1])]
            self.assertEqual(1, len(timeout_msgs))
            _args, kw = timeout_msgs[0]
            self.assertNotIn("agy produced no result", str(_args[1]))
            rm = kw.get("reply_markup")
            self.assertIsInstance(rm, dict)
            self.assertIn("action:retry", json.dumps(rm))

    def test_turn_silence_timeout_zero_steps_no_failover_and_group_readonly_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_BG_WAIT_TIMEOUT": "0",
                    "AGY_TURN_SILENCE_TIMEOUT": "0.16",
                    "AGY_TG_FALLBACK_MODELS": "fallback-m1,fallback-m2",
                },
            )
            secret_stderr = f"FATAL stderr path={tmp}/private.key email={SYNTH_EMAIL} quota exceeded"
            fake_sess = _FakeAgySession([], cid=None, stderr_text=secret_stderr)
            acq_calls = []
            sent_calls = []

            with (
                mock.patch.object(bridge, "_acquire_session", side_effect=lambda *a, **kw: (acq_calls.append((a, kw)) or (fake_sess, False))),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_calls.append((a, kw)) or 401),
                mock.patch.object(bridge, "push_step_images", return_value=None),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
            ):
                bridge.run_agy(GROUP_CHAT_ID, "hello from readonly", user_role="readonly", user_id=READONLY_UID)

            # Even with 0 delivered_steps and 0 tools, watchdog MUST NOT fall into failover
            self.assertEqual(1, len(acq_calls))
            self.assertEqual([True], fake_sess.close_calls)
            self.assertFalse(bridge.turn_running)

            timeout_msgs = [(a, kw) for a, kw in sent_calls if "静默超时" in str(a[1])]
            self.assertEqual(1, len(timeout_msgs))
            msg_text = str(timeout_msgs[0][0][1])
            msg_kw = timeout_msgs[0][1]
            self.assertIsNone(msg_kw.get("reply_markup"), "Readonly user must NEVER get retry button")
            self.assertNotIn(tmp, msg_text)
            self.assertNotIn(SYNTH_EMAIL, msg_text)
            self.assertNotIn("FATAL stderr", msg_text)
            self.assertNotIn("agy produced no result", msg_text)

    def test_dm_readonly_watchdog_notice_omits_retry_button_copy(self):
        """P2: DM watchdog timeout notice only mentions retry button when `wd_kb is not None`."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_BG_WAIT_TIMEOUT": "0",
                    "AGY_TURN_SILENCE_TIMEOUT": "0.14",
                },
            )
            fake_sess = _FakeAgySession([], cid=None)
            sent_calls = []

            with (
                mock.patch.object(bridge, "_acquire_session", return_value=(fake_sess, False)),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_calls.append((a, kw)) or 402),
                mock.patch.object(bridge, "push_step_images", return_value=None),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
            ):
                bridge.run_agy(READONLY_UID, "readonly dm hang", user_role="readonly", user_id=READONLY_UID)

            timeout_msgs = [(a, kw) for a, kw in sent_calls if "静默超时" in str(a[1])]
            self.assertEqual(1, len(timeout_msgs))
            msg_text = str(timeout_msgs[0][0][1])
            self.assertIsNone(timeout_msgs[0][1].get("reply_markup"))
            self.assertNotIn("或点击下方按钮重试上一轮", msg_text)


class TestC5PreemptionNegativeGuardrails(unittest.TestCase):
    """C5: All 4 negative guardrails must strictly reject preemption."""

    def test_four_negative_guardrails_reject_preemption(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_PREEMPT_BG_GRACE_SEC": "5", "AGY_BUS_FAST_CHAT": "0"})
            active_scope = f"{GROUP_CHAT_ID}:{TOPIC_A}"
            orig_sess = _FakeAgySession([], cid="conv-active")

            def _seed_state(*, waiting_bg=True, waited_sec=30.0):
                with bridge.session_lock:
                    bridge.turn_running = True
                    bridge.turn_running_scope = active_scope
                    bridge.turn_running_chat = GROUP_CHAT_ID
                    bridge.turn_gen = 7
                    bridge.turn_waiting_bg = waiting_bg
                    bridge.turn_waiting_bg_since = (time.time() - waited_sec) if waiting_bg else None
                    bridge.turn_preempted_gen = None
                    bridge.cancel_requested = False
                    bridge._session_pool[active_scope] = orig_sess

            def _assert_rejected(desc, call_fn):
                close_mock = mock.Mock()
                with (
                    mock.patch.object(bridge, "close_session_async", close_mock),
                    mock.patch.object(bridge, "send", return_value=501),
                ):
                    call_fn()
                self.assertFalse(bridge.cancel_requested, desc)
                self.assertIsNone(bridge.turn_preempted_gen, desc)
                self.assertEqual(0, close_mock.call_count, desc)
                self.assertIs(orig_sess, bridge._session_pool.get(active_scope), desc)
                item = bridge.job_q.get()
                bridge.job_q.task_done()
                payload = item[3]
                prompt_val = payload[1]["prompt"] if isinstance(payload, tuple) else payload
                self.assertNotIn("[BRIDGE_NOTICE]", prompt_val, desc)

            # 1. Readonly user (same scope, waiting_bg past grace) -> MUST reject
            _seed_state(waiting_bg=True, waited_sec=30.0)
            _assert_rejected(
                "readonly same scope",
                lambda: bridge.enqueue(GROUP_CHAT_ID, "guest msg", thread_id=TOPIC_A, user_role="readonly", user_id=READONLY_UID),
            )

            # 2a. Admin cross-scope: DM while group active -> MUST reject
            _seed_state(waiting_bg=True, waited_sec=30.0)
            _assert_rejected(
                "admin DM vs group",
                lambda: bridge.enqueue(ADMIN_UID, "dm msg", user_role="admin", user_id=ADMIN_UID),
            )

            # 2b. Admin cross-scope: Topic B while Topic A active -> MUST reject
            _seed_state(waiting_bg=True, waited_sec=30.0)
            _assert_rejected(
                "admin topic B vs topic A",
                lambda: bridge.enqueue(GROUP_CHAT_ID, "topic b msg", thread_id=TOPIC_B, user_role="admin", user_id=ADMIN_UID),
            )

            # 3. Same scope admin while actively executing (turn_waiting_bg is False) -> MUST reject
            _seed_state(waiting_bg=False, waited_sec=0.0)
            _assert_rejected(
                "same scope active not waiting_bg",
                lambda: bridge.enqueue(GROUP_CHAT_ID, "active msg", thread_id=TOPIC_A, user_role="admin", user_id=ADMIN_UID),
            )

            # 4a. Same scope admin within grace period (< 5s) -> MUST reject
            _seed_state(waiting_bg=True, waited_sec=1.0)
            _assert_rejected(
                "within grace period",
                lambda: bridge.enqueue(GROUP_CHAT_ID, "too early", thread_id=TOPIC_A, user_role="admin", user_id=ADMIN_UID),
            )

            # 4b. Same scope admin when AGY_PREEMPT_WAITING_BG=0 -> MUST reject
            bridge.PREEMPT_WAITING_BG = False
            _seed_state(waiting_bg=True, waited_sec=30.0)
            _assert_rejected(
                "preempt flag disabled",
                lambda: bridge.enqueue(GROUP_CHAT_ID, "disabled preempt", thread_id=TOPIC_A, user_role="admin", user_id=ADMIN_UID),
            )

    def test_allow_preempt_false_and_internal_bus_wakes_reject_preemption(self):
        """P1 C5/C6: allow_preempt=False and Bot Bus wakes (group_mention / scheduled_handoff) never preempt waiting_bg."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_PREEMPT_BG_GRACE_SEC": "5", "AGY_BUS_FAST_CHAT": "0"})
            active_scope = f"{GROUP_CHAT_ID}:{TOPIC_A}"
            orig_sess = _FakeAgySession([], cid="conv-bus-active")

            def _seed_waiting():
                with bridge.session_lock:
                    bridge.turn_running = True
                    bridge.turn_running_scope = active_scope
                    bridge.turn_running_chat = GROUP_CHAT_ID
                    bridge.turn_gen = 11
                    bridge.turn_waiting_bg = True
                    bridge.turn_waiting_bg_since = time.time() - 45.0
                    bridge.turn_preempted_gen = None
                    bridge.cancel_requested = False
                    bridge._session_pool[active_scope] = orig_sess

            def _verify_no_preempt(label, trigger_fn):
                _seed_waiting()
                close_mock = mock.Mock()
                with (
                    mock.patch.object(bridge, "close_session_async", close_mock),
                    mock.patch.object(bridge, "send", return_value=509),
                ):
                    trigger_fn()
                self.assertEqual(0, close_mock.call_count, label)
                self.assertIsNone(bridge.turn_preempted_gen, label)
                self.assertTrue(bridge.turn_waiting_bg, label)
                self.assertIs(orig_sess, bridge._session_pool.get(active_scope), label)
                item = bridge.job_q.get()
                bridge.job_q.task_done()
                payload = item[3]
                prompt_val = payload[1]["prompt"] if isinstance(payload, tuple) else payload
                self.assertNotIn("[BRIDGE_NOTICE]", prompt_val, label)

            # 1. Explicit allow_preempt=False with same scope + admin + waiting_bg past grace
            _verify_no_preempt(
                "direct allow_preempt=False",
                lambda: bridge.enqueue(
                    GROUP_CHAT_ID,
                    "internal wake",
                    thread_id=TOPIC_A,
                    user_role="admin",
                    user_id=ADMIN_UID,
                    allow_preempt=False,
                ),
            )

            # 2. Bot Bus `group_mention` packet
            _verify_no_preempt(
                "bot bus group_mention",
                lambda: bridge._handle_bot_bus_packet(
                    {
                        "type": "group_mention",
                        "chat_id": GROUP_CHAT_ID,
                        "thread_id": TOPIC_A,
                        "from_bot": "peer_bot",
                        "hop": 1,
                        "msg_id": 9001,
                        "text_excerpt": "please check status",
                    }
                ),
            )

            # 3. Bot Bus `scheduled_handoff` packet
            _verify_no_preempt(
                "bot bus scheduled_handoff",
                lambda: bridge._handle_bot_bus_packet(
                    {
                        "type": "scheduled_handoff",
                        "chat_id": GROUP_CHAT_ID,
                        "thread_id": TOPIC_A,
                        "from_bot": "scheduler_bot",
                        "task_id": "t-1",
                        "task_name": "nightly_check",
                        "msg_id": 9002,
                        "text_excerpt": "cron summary",
                    }
                ),
            )


class TestC6SameScopePreemptionAndRace(unittest.TestCase):
    """C6: Same-scope admin preemption, M2/M3 double-send race, silent Turn A exit, gen isolation."""

    def test_preempt_waiting_bg_double_send_m2_m3_and_silent_turn_a_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(
                tmp,
                extra_env={"AGY_PREEMPT_BG_GRACE_SEC": "1", "AGY_BUS_FAST_CHAT": "0"},
            )
            skey = str(ADMIN_UID)
            turn_a_events = [
                {"event": "init", "conversation_id": "conv-preempt-1"},
                {"event": "step_update", "step_update": {"step_type": "agent_response", "state": "ACTIVE", "step_index": 1, "text_delta": "Milestone sent"}},
                {"event": "step_update", "step_update": {"step_type": "agent_response", "state": "DONE", "step_index": 1}},
            ]
            sess_a = _FakeAgySession(turn_a_events, cid="conv-preempt-1")
            sent_messages = []
            close_async_calls = []

            def fake_acquire(sk, *a, **kw):
                with bridge.session_lock:
                    bridge._session_pool[sk] = sess_a
                return sess_a, False

            def fake_close_async(sess, force=False):
                close_async_calls.append((sess, force))
                sess.close(force=force)

            with (
                mock.patch.object(bridge, "_acquire_session", side_effect=fake_acquire),
                mock.patch.object(bridge, "close_session_async", side_effect=fake_close_async),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_messages.append((a, kw)) or 601),
                mock.patch.object(bridge, "send_rich", side_effect=lambda *a, **kw: (602, "ok")),
                mock.patch.object(bridge, "push_step_images", return_value=None),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
            ):
                t_a = threading.Thread(
                    target=bridge.run_agy,
                    args=(ADMIN_UID, "Turn A prompt"),
                    kwargs={"user_role": "admin", "user_id": ADMIN_UID},
                    daemon=True,
                )
                t_a.start()

                # Wait until Turn A enters waiting_bg
                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline:
                    with bridge.session_lock:
                        if bridge.turn_waiting_bg:
                            bridge.turn_waiting_bg_since = time.time() - 10.0
                            break
                    time.sleep(0.02)
                self.assertTrue(bridge.turn_waiting_bg, "Turn A should enter waiting_bg")

                # Rapid double-send M2 and M3 while Turn A is still unwinding
                bridge.enqueue(ADMIN_UID, "M2 urgent", user_role="admin", user_id=ADMIN_UID)
                bridge.enqueue(ADMIN_UID, "M3 follow-up", user_role="admin", user_id=ADMIN_UID)

                t_a.join(timeout=3.0)
                self.assertFalse(t_a.is_alive(), "Turn A must exit cleanly after preemption")

            # Only M2 triggered preemption once
            self.assertEqual(1, len(close_async_calls))
            self.assertEqual((sess_a, True), close_async_calls[0])

            # Turn A exited cleanly without polluting global cancel_requested or leaving stale gen state
            self.assertFalse(bridge.turn_running)
            self.assertFalse(bridge.turn_waiting_bg)
            self.assertIsNone(bridge.turn_waiting_bg_since)
            self.assertIsNone(bridge.turn_preempted_gen)
            self.assertFalse(bridge.cancel_requested)

            # Turn A MUST NOT send error or cancelled messages
            all_texts = [str(a[1]) for a, _kw in sent_messages]
            for txt in all_texts:
                self.assertNotIn("agy produced no result", txt)
                self.assertNotIn("Task cancelled", txt)

            # Verify queued items: M2 has [BRIDGE_NOTICE], M3 does NOT
            item_m2 = bridge.job_q.get()
            bridge.job_q.task_done()
            item_m3 = bridge.job_q.get()
            bridge.job_q.task_done()
            p_m2 = item_m2[3][1]["prompt"] if isinstance(item_m2[3], tuple) else item_m2[3]
            p_m3 = item_m3[3][1]["prompt"] if isinstance(item_m3[3], tuple) else item_m3[3]
            self.assertIn("[BRIDGE_NOTICE]", p_m2)
            self.assertIn("M2 urgent", p_m2)
            self.assertNotIn("[BRIDGE_NOTICE]", p_m3)
            self.assertEqual("M3 follow-up", p_m3)

            # M2 notice was NOT a "queued" notice
            self.assertTrue(any("已切换处理你的新消息" in t for t in all_texts))
            self.assertEqual("PREEMPTED", (bridge.get_scope_state(skey).get("last_turn") or {}).get("status"))

    def test_preempted_turn_a_with_interrupted_result_is_silent_and_m2_succeeds(self):
        """P1 C6: Real `agy` emitting interrupted `result` on SIGTERM during preemption must stay silent,
        record last_turn=PREEMPTED, emit Web aborted(preempted), and allow M2 to run to SUCCESS.
        """
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(
                tmp,
                extra_env={"AGY_PREEMPT_BG_GRACE_SEC": "1", "AGY_BUS_FAST_CHAT": "0"},
            )
            skey = str(ADMIN_UID)

            class _InterruptedOnCloseSession(_FakeAgySession):
                def close(self, force=False, term_timeout=None):
                    self.close_calls.append(bool(force))
                    if not self.eof_reached:
                        # Simulate real `agy` catching SIGTERM and emitting an interrupted ERROR result before EOF
                        self._event_q.put(
                            {
                                "event": "result",
                                "result": {
                                    "status": "ERROR",
                                    "finished_reason": "interrupted",
                                    "conversation_id": self.cid,
                                },
                            }
                        )
                        self.eof_reached = True
                        self.proc.returncode = -15
                        self.proc.poll.return_value = -15
                        self._event_q.put({"event": "__eof__"})

            sess_a = _InterruptedOnCloseSession(
                [
                    {"event": "init", "conversation_id": "conv-preempt-int"},
                    {"event": "step_update", "step_update": {"step_type": "agent_response", "state": "ACTIVE", "step_index": 1, "text_delta": "Started bg"}},
                    {"event": "step_update", "step_update": {"step_type": "agent_response", "state": "DONE", "step_index": 1}},
                ],
                cid="conv-preempt-int",
            )
            sess_m2 = _FakeAgySession(
                [
                    {"event": "init", "conversation_id": "conv-preempt-int"},
                    {"event": "step_update", "step_update": {"step_type": "agent_response", "state": "ACTIVE", "step_index": 1, "text_delta": "M2 done"}},
                    {"event": "step_update", "step_update": {"step_type": "agent_response", "state": "DONE", "step_index": 1}},
                    {"event": "result", "result": {"status": "SUCCESS", "conversation_id": "conv-preempt-int", "response": "M2 done"}},
                ],
                cid="conv-preempt-int",
            )

            sent_messages = []
            web_events_a = []
            web_events_m2 = []
            acq_seq = [sess_a, sess_m2]

            def fake_acquire(sk, *a, **kw):
                s = acq_seq.pop(0)
                with bridge.session_lock:
                    bridge._session_pool[sk] = s
                return s, False

            def fake_close_async(sess, force=False):
                sess.close(force=force)

            with (
                mock.patch.object(bridge, "_acquire_session", side_effect=fake_acquire),
                mock.patch.object(bridge, "close_session_async", side_effect=fake_close_async),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_messages.append((a, kw)) or 611),
                mock.patch.object(bridge, "send_rich", side_effect=lambda *a, **kw: (612, "ok")),
                mock.patch.object(bridge, "push_step_images", return_value=None),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact", return_value=None),
            ):
                t_a = threading.Thread(
                    target=bridge.run_agy,
                    args=(ADMIN_UID, "Turn A bg"),
                    kwargs={
                        "user_role": "admin",
                        "user_id": ADMIN_UID,
                        "event_sink": lambda t, p: web_events_a.append((t, p)),
                    },
                    daemon=True,
                )
                t_a.start()

                deadline = time.monotonic() + 3.0
                while time.monotonic() < deadline:
                    with bridge.session_lock:
                        if bridge.turn_waiting_bg:
                            bridge.turn_waiting_bg_since = time.time() - 10.0
                            break
                    time.sleep(0.02)
                self.assertTrue(bridge.turn_waiting_bg)

                bridge.enqueue(ADMIN_UID, "M2 urgent after interrupted", user_role="admin", user_id=ADMIN_UID)
                t_a.join(timeout=3.0)
                self.assertFalse(t_a.is_alive())

                # Verify Turn A stayed completely silent and recorded PREEMPTED
                self.assertEqual("PREEMPTED", (bridge.get_scope_state(skey).get("last_turn") or {}).get("status"))
                self.assertFalse(bridge.cancel_requested)
                self.assertTrue(
                    any(t == "aborted" and p.get("reason") == "preempted" for t, p in web_events_a),
                    f"Expected Web aborted(preempted), got {web_events_a}",
                )
                for a, _kw in sent_messages:
                    txt = str(a[1])
                    self.assertNotIn("Task cancelled", txt)
                    self.assertNotIn("🛑", txt)
                    self.assertNotIn("⚠️", txt)

                # Now run dequeued M2 and assert it succeeds cleanly
                item_m2 = bridge.job_q.get()
                bridge.job_q.task_done()
                m2_payload = item_m2[3]
                m2_prompt = m2_payload[1]["prompt"] if isinstance(m2_payload, tuple) else m2_payload
                self.assertIn("[BRIDGE_NOTICE]", m2_prompt)

                bridge.run_agy(
                    ADMIN_UID,
                    m2_prompt,
                    user_role="admin",
                    user_id=ADMIN_UID,
                    event_sink=lambda t, p: web_events_m2.append((t, p)),
                )
                self.assertEqual("SUCCESS", (bridge.get_scope_state(skey).get("last_turn") or {}).get("status"))
                self.assertTrue(any(t == "done" and p.get("status") == "SUCCESS" for t, p in web_events_m2))

    def test_preempt_enqueues_m2_before_sending_switch_notice(self):
        """P2: Preemption path puts M2 into job_q BEFORE invoking network send()."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_PREEMPT_BG_GRACE_SEC": "1", "AGY_BUS_FAST_CHAT": "0"})
            skey = str(ADMIN_UID)
            sess_a = _FakeAgySession([], cid="conv-order")
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_scope = skey
                bridge.turn_running_chat = ADMIN_UID
                bridge.turn_gen = 5
                bridge.turn_waiting_bg = True
                bridge.turn_waiting_bg_since = time.time() - 12.0
                bridge.turn_preempted_gen = None
                bridge._session_pool[skey] = sess_a

            qsize_during_send = []

            def spy_send(*a, **kw):
                qsize_during_send.append(bridge.job_q.qsize())
                return 620

            with (
                mock.patch.object(bridge, "close_session_async", return_value=None),
                mock.patch.object(bridge, "send", side_effect=spy_send),
            ):
                bridge.enqueue(ADMIN_UID, "M2 priority", user_role="admin", user_id=ADMIN_UID)

            self.assertEqual([1], qsize_during_send, "M2 must already be in job_q before send() executes")
            item = bridge.job_q.get()
            bridge.job_q.task_done()
            p_m2 = item[3][1]["prompt"] if isinstance(item[3], tuple) else item[3]
            self.assertIn("M2 priority", p_m2)


class TestC7CancelRbacStatusRedactionAndDraftUx(unittest.TestCase):
    """C7: Busy cancel button RBAC, fail-closed cancel handlers, `/status` redaction, LiveDraftStreamer UX."""

    def test_busy_queue_notice_cancel_button_rbac_in_conversational_and_status_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_scope = str(ADMIN_UID)
                bridge.turn_running_chat = ADMIN_UID
                bridge.turn_waiting_bg = False

            for mode in ("conversational", "status"):
                bridge.BUS_CHAT_MODE = mode
                sent = []
                with mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent.append((a, kw)) or 701):
                    bridge.enqueue(ADMIN_UID, f"admin-{mode}", user_role="admin", user_id=ADMIN_UID)
                    bridge.enqueue(GROUP_CHAT_ID, f"ro-{mode}", user_role="readonly", user_id=READONLY_UID)

                self.assertEqual(2, len(sent))
                admin_rm = sent[0][1].get("reply_markup")
                ro_rm = sent[1][1].get("reply_markup")
                self.assertIsInstance(admin_rm, dict, f"Admin must get cancel keyboard in mode={mode}")
                self.assertIn("action:cancel", json.dumps(admin_rm))
                self.assertIsNone(ro_rm, f"Readonly must NEVER get cancel keyboard in mode={mode}")

                # Drain queue
                while not bridge.job_q.empty():
                    bridge.job_q.get()
                    bridge.job_q.task_done()

    def test_action_cancel_callback_and_slash_cancel_rbac_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_scope = str(GROUP_CHAT_ID)
                bridge.turn_running_chat = GROUP_CHAT_ID
                bridge.cancel_requested = False

            cb_answers = []
            sent_texts = []
            cancel_mock = mock.Mock()

            with (
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: cb_answers.append((m, kw))),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_texts.append(a[1]) or 702),
                mock.patch.object(bridge, "cancel_current_task", cancel_mock),
            ):
                # Forged action:cancel from readonly and denied users
                for uid in (READONLY_UID, DENIED_UID):
                    bridge.handle_callback(
                        {
                            "id": f"cb-{uid}",
                            "from": {"id": uid},
                            "message": {"chat": {"id": GROUP_CHAT_ID}, "message_id": 88},
                            "data": "action:cancel",
                        }
                    )
                self.assertEqual(0, cancel_mock.call_count)
                self.assertFalse(bridge.cancel_requested)
                self.assertEqual(2, len(cb_answers))
                self.assertTrue(all(kw.get("show_alert") is True for _m, kw in cb_answers))

                # Forged /cancel and /stop from readonly and denied users
                for uid in (READONLY_UID, DENIED_UID):
                    bridge.handle_message(
                        {
                            "chat": {"id": GROUP_CHAT_ID, "type": "supergroup"},
                            "from": {"id": uid},
                            "message_id": 89,
                            "text": "/cancel",
                        }
                    )
                self.assertEqual(0, cancel_mock.call_count)
                self.assertFalse(bridge.cancel_requested)

                # Authorized admin callback succeeds
                bridge.handle_callback(
                    {
                        "id": "cb-admin",
                        "from": {"id": ADMIN_UID},
                        "message": {"chat": {"id": GROUP_CHAT_ID}, "message_id": 90},
                        "data": "action:cancel",
                    }
                )
                self.assertEqual(1, cancel_mock.call_count)

    def test_cmd_status_redacts_private_dm_scope_in_group_and_displays_waiting_bg(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_scope = str(ADMIN_UID)
                bridge.turn_running_chat = ADMIN_UID
                bridge.turn_waiting_bg = True
                bridge.turn_waiting_bg_since = time.time() - 37.0

            sent = []
            with mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent.append((a, kw)) or 801):
                bridge.cmd_status(GROUP_CHAT_ID)
                bridge.cmd_status(ADMIN_UID)

            group_status = str(sent[0][0][1])
            dm_status = str(sent[1][0][1])

            self.assertIn("其他私聊任务（已隔离上下文）", group_status)
            self.assertIn("waiting_bg", group_status)
            self.assertNotIn(str(ADMIN_UID), group_status, "Group /status must NEVER expose private DM chat_id")

            self.assertIn("waiting_bg", dm_status)
            self.assertIn("37s", dm_status)

    def test_live_draft_streamer_clears_waiting_bg_on_thinking_and_text_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            streamer = bridge.LiveDraftStreamer(ADMIN_UID, time.time(), enabled=False)
            streamer.start_next_segment(0)
            self.assertTrue(streamer.waiting_bg)

            with streamer.lock:
                _did, payload = streamer._build_status_payload_locked()
            self.assertIn("等待后台任务响应", payload)
            self.assertIn("打断", payload)
            self.assertIn("/cancel", payload)

            streamer.on_thinking("inspecting next result")
            self.assertFalse(streamer.waiting_bg)

            streamer.start_next_segment(1)
            self.assertTrue(streamer.waiting_bg)
            streamer.on_text_delta("Resumed output text")
            self.assertFalse(streamer.waiting_bg)


class TestUrgentPreemptionAndDequeueRace(unittest.TestCase):
    """Explicit urgent preemption (`/urgent`, `! <msg>`, `action:preempt:<qid>`) & enqueue<->cancel/urgent race (C1-C7)."""

    def test_c1_rbac_fail_closed_urgent_bang_and_preempt_card_zero_mutation(self):
        """C1: readonly/denied users blocked on /urgent, ! <msg>, mentions & forged callbacks; 0 state mutation."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge.BOT_META.update({"bot_id": 1001, "handle": "example_main_bot", "resolved": True})
            skey = str(GROUP_CHAT_ID)
            active_sess = _FakeAgySession([], cid="conv-c1-active")
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_scope = skey
                bridge.turn_running_chat = GROUP_CHAT_ID
                bridge.turn_gen = 15
                bridge.turn_waiting_bg = False
                bridge.turn_preempted_gen = None
                bridge.cancel_requested = False
                bridge._session_pool[skey] = active_sess

            existing_qid = bridge.job_q.put((GROUP_CHAT_ID, None, skey, "existing queued"))
            sent_calls = []
            cb_answers = []
            close_mock = mock.Mock()

            with (
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_calls.append((a, kw)) or 901),
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: cb_answers.append((m, kw))),
                mock.patch.object(bridge, "close_session_async", close_mock),
            ):
                for uid, expect_reply in ((READONLY_UID, True), (DENIED_UID, False)):
                    for text in (
                        "/urgent 新任务",
                        "! 新任务",
                        "/urgent@example_main_bot 新任务",
                        "@example_main_bot /urgent 新任务",
                        "@example_main_bot ! 新任务",
                    ):
                        sent_calls.clear()
                        bridge.handle_message({
                            "chat": {"id": GROUP_CHAT_ID, "type": "supergroup"},
                            "from": {"id": uid},
                            "message_id": 201,
                            "text": text,
                        })
                        if expect_reply:
                            self.assertTrue(
                                any("权限不足" in str(a[1]) for a, _kw in sent_calls),
                                f"readonly {text!r} must receive RBAC denial, got {sent_calls}",
                            )
                        else:
                            self.assertEqual([], sent_calls, f"denied {text!r} must be silently rejected")

                    # Forged callbacks action:preempt:<qid> & action:cancel
                    for cb_data in (f"action:preempt:{existing_qid}", "action:cancel"):
                        cb_answers.clear()
                        bridge.handle_callback({
                            "id": f"cb-{uid}-{cb_data}",
                            "from": {"id": uid},
                            "message": {"chat": {"id": GROUP_CHAT_ID}, "message_id": 202},
                            "data": cb_data,
                        })
                        self.assertEqual(1, len(cb_answers))
                        self.assertTrue(cb_answers[0][1].get("show_alert") is True)
                        if uid == READONLY_UID:
                            self.assertIn("权限不足", cb_answers[0][1].get("text", ""))
                        else:
                            self.assertEqual("Unauthorized", cb_answers[0][1].get("text", ""))

                # Readonly queued card MUST NOT include action:preempt or action:cancel buttons
                sent_calls.clear()
                bridge.enqueue(GROUP_CHAT_ID, "ro queued q", user_role="readonly", user_id=READONLY_UID)
                self.assertEqual(1, len(sent_calls))
                self.assertIsNone(sent_calls[0][1].get("reply_markup"))

            # Zero mutation to active session, turn flags, or original queue head
            self.assertEqual(0, close_mock.call_count)
            self.assertIsNone(bridge.turn_preempted_gen)
            self.assertFalse(bridge.cancel_requested)
            self.assertIs(active_sess, bridge._session_pool.get(skey))
            self.assertEqual(2, bridge.job_q.qsize())
            first_item = bridge.job_q.get()
            bridge.job_q.task_done()
            self.assertEqual("existing queued", first_item[3])

    def test_c2_prefix_mention_parsing_group_isolation_and_punctuation_guards(self):
        """C2: Pure punctuation / no-space / empty /urgent / @bot_two ignored; @example_main_bot stripped cleanly."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge.BOT_META.update({"bot_id": 1001, "handle": "example_main_bot", "resolved": True})

            normal_enqueued = []
            urgent_enqueued = []
            sent_texts = []

            with (
                mock.patch.object(bridge, "enqueue", side_effect=lambda *a, **kw: normal_enqueued.append((a, kw))),
                mock.patch.object(bridge, "enqueue_urgent", side_effect=lambda *a, **kw: urgent_enqueued.append((a, kw))),
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent_texts.append(txt) or 911),
            ):
                # 1a. Pure punctuation or missing space after ! -> normal text, NOT urgent
                for plain_txt in ("!", "!!!", "!?", "!   ", "!无空格"):
                    normal_enqueued.clear()
                    urgent_enqueued.clear()
                    bridge.handle_message({
                        "chat": {"id": GROUP_CHAT_ID, "type": "supergroup"},
                        "from": {"id": ADMIN_UID},
                        "message_id": 301,
                        "text": plain_txt,
                    })
                    self.assertEqual([], urgent_enqueued, f"{plain_txt!r} must NOT trigger urgent")
                    self.assertEqual(1, len(normal_enqueued), f"{plain_txt!r} must route to normal enqueue")

                # 1b. Empty /urgent -> usage hint only, zero enqueue, zero interrupt
                normal_enqueued.clear()
                urgent_enqueued.clear()
                sent_texts.clear()
                for empty_cmd in ("/urgent", "/urgent   ", "/urgent@example_main_bot", "@example_main_bot /urgent"):
                    sent_texts.clear()
                    bridge.handle_message({
                        "chat": {"id": GROUP_CHAT_ID, "type": "supergroup"},
                        "from": {"id": ADMIN_UID},
                        "message_id": 302,
                        "text": empty_cmd,
                    })
                    self.assertEqual([], urgent_enqueued, empty_cmd)
                    self.assertEqual([], normal_enqueued, empty_cmd)
                    self.assertTrue(any("/urgent" in t for t in sent_texts), f"Expected usage hint for {empty_cmd!r}")

                # 2. Group messages targeting @bot_two -> completely ignored
                for other_txt in (
                    "/urgent@bot_two 任务",
                    "@bot_two /urgent 任务",
                    "@bot_two ! 任务",
                ):
                    normal_enqueued.clear()
                    urgent_enqueued.clear()
                    sent_texts.clear()
                    bridge.handle_message({
                        "chat": {"id": GROUP_CHAT_ID, "type": "supergroup"},
                        "from": {"id": ADMIN_UID},
                        "message_id": 303,
                        "text": other_txt,
                    })
                    self.assertEqual([], urgent_enqueued, other_txt)
                    self.assertEqual([], normal_enqueued, other_txt)
                    self.assertEqual([], sent_texts, other_txt)

                # 3. Group messages targeting @example_main_bot -> stripped cleanly to body "紧急修bug"
                for my_txt in (
                    "/urgent@example_main_bot 紧急修bug",
                    "@example_main_bot /urgent 紧急修bug",
                    "@example_main_bot ! 紧急修bug",
                    "! 紧急修bug",
                ):
                    normal_enqueued.clear()
                    urgent_enqueued.clear()
                    bridge.handle_message({
                        "chat": {"id": GROUP_CHAT_ID, "type": "supergroup"},
                        "from": {"id": ADMIN_UID},
                        "message_id": 304,
                        "text": my_txt,
                    })
                    self.assertEqual([], normal_enqueued, my_txt)
                    self.assertEqual(1, len(urgent_enqueued), my_txt)
                    self.assertEqual("紧急修bug", urgent_enqueued[0][0][1], my_txt)

                # 4. `/urgent` and `! ` with `reply_to_message` preserve quoted reply context
                for reply_cmd, expected_body in (
                    ("/urgent 马上核查这段报错", "马上核查这段报错"),
                    ("! 立刻修复这个引用问题", "立刻修复这个引用问题"),
                ):
                    normal_enqueued.clear()
                    urgent_enqueued.clear()
                    bridge.handle_message({
                        "chat": {"id": GROUP_CHAT_ID, "type": "supergroup"},
                        "from": {"id": ADMIN_UID},
                        "message_id": 305,
                        "text": reply_cmd,
                        "reply_to_message": {
                            "message_id": 299,
                            "from": {"first_name": "Alice", "username": "alice_dev"},
                            "text": "Traceback: KeyError('session_id')",
                        },
                    })
                    self.assertEqual([], normal_enqueued, reply_cmd)
                    self.assertEqual(1, len(urgent_enqueued), reply_cmd)
                    prompt_passed = urgent_enqueued[0][0][1]
                    self.assertIn("Traceback: KeyError('session_id')", prompt_passed, reply_cmd)
                    self.assertIn(expected_body, prompt_passed, reply_cmd)

    def test_c3_active_non_waiting_bg_preemption_order_preservation_and_idle_path(self):
        """C3: Preempt active non-waiting_bg turn, kill AgySession, preserve [M_urgent, Q1, Q2], and handle idle."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge.RELOAD_TRIGGER = os.path.join(tmp, "no_reload.flag")
            skey = str(ADMIN_UID)

            # Active session stuck mid-tool (turn_waiting_bg=False!) until force-closed
            m_old_started = threading.Event()
            sess_old = _FakeAgySession(
                [
                    {"event": "init", "conversation_id": "conv-c3-active"},
                    {"event": "step_update", "step_update": {"step_type": "tool", "state": "ACTIVE", "step_index": 1, "tool_name": "run_command", "tool_info": {}}},
                ],
                cid="conv-c3-active",
            )
            executed_order = []
            all_done = threading.Event()
            close_async_calls = []

            def make_quick_sess(label):
                return _FakeAgySession(
                    [
                        {"event": "init", "conversation_id": "conv-c3-active"},
                        {"event": "result", "result": {"status": "SUCCESS", "conversation_id": "conv-c3-active", "response": f"ok:{label}"}},
                    ],
                    cid="conv-c3-active",
                )

            def fake_acquire(sk, *a, **kw):
                # First call is M_old; subsequent calls are M_urgent, Q1, Q2
                if not m_old_started.is_set():
                    with bridge.session_lock:
                        bridge._session_pool[sk] = sess_old
                    m_old_started.set()
                    return sess_old, False
                s = make_quick_sess(len(executed_order))
                with bridge.session_lock:
                    bridge._session_pool[sk] = s
                return s, False

            orig_run_agy = bridge.run_agy

            def spy_run_agy(chat_id, prompt, **kw):
                executed_order.append(prompt)
                try:
                    return orig_run_agy(chat_id, prompt, **kw)
                finally:
                    if prompt == "Q2":
                        all_done.set()

            def fake_close_async(sess, force=False):
                close_async_calls.append((sess, force))
                sess.close(force=force)

            sent_msgs = []
            with (
                mock.patch.object(bridge, "_acquire_session", side_effect=fake_acquire),
                mock.patch.object(bridge, "close_session_async", side_effect=fake_close_async),
                mock.patch.object(bridge, "run_agy", side_effect=spy_run_agy),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_msgs.append(str(a[1])) or 921),
                mock.patch.object(bridge, "send_rich", return_value=(922, "ok")),
                mock.patch.object(bridge, "push_step_images", return_value=None),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact", return_value=None),
                mock.patch.object(bridge, "perform_hot_reload", return_value=True),
            ):
                t_worker = threading.Thread(target=bridge.worker, daemon=True)
                t_worker.start()

                bridge.job_q.put((ADMIN_UID, None, skey, "M_old"))
                self.assertTrue(m_old_started.wait(timeout=3.0))
                # Confirm M_old is actively running with turn_waiting_bg == False
                self.assertTrue(bridge.turn_running)
                self.assertFalse(bridge.turn_waiting_bg)

                # Queue normal Q1 and Q2 behind M_old
                bridge.job_q.put((ADMIN_UID, None, skey, "Q1"))
                bridge.job_q.put((ADMIN_UID, None, skey, "Q2"))

                # Send explicit urgent preemption while M_old is non-waiting_bg!
                bridge.enqueue_urgent(ADMIN_UID, "M_urgent", user_role="admin", user_id=ADMIN_UID)

                self.assertTrue(all_done.wait(timeout=5.0), f"Expected Q2 done; executed={executed_order}")

                # Verify idle /urgent executes cleanly with zero spurious interrupt message
                sent_msgs.clear()
                idle_done = threading.Event()
                orig_spy = spy_run_agy

                def idle_wrapper(chat_id, prompt, **kw):
                    res = orig_spy(chat_id, prompt, **kw)
                    if prompt == "M_idle":
                        idle_done.set()
                    return res

                with mock.patch.object(bridge, "run_agy", side_effect=idle_wrapper):
                    bridge.enqueue_urgent(ADMIN_UID, "M_idle", user_role="admin", user_id=ADMIN_UID)
                    self.assertTrue(idle_done.wait(timeout=3.0))

                bridge.job_q.put((ADMIN_UID, None, skey, "__RELOAD__"))
                t_worker.join(timeout=3.0)

            self.assertEqual(["M_old", "M_urgent", "Q1", "Q2", "M_idle"], executed_order)
            self.assertIn((sess_old, True), close_async_calls)
            self.assertFalse(any("已中断当前任务" in m for m in sent_msgs), f"Idle urgent must not claim interrupt: {sent_msgs}")

    def test_c4_cross_scope_isolation_never_kills_other_group_topic_bus_or_web(self):
        """C4: Urgent in scope_B never kills scope_A (other group / topic / bus / web); queues at front with notice."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            scope_b = f"{GROUP_CHAT_ID}:{TOPIC_B}"

            for active_scope, label in (
                (str(OTHER_GROUP_CHAT_ID), "other_group"),
                (f"{GROUP_CHAT_ID}:{TOPIC_A}", "other_topic"),
                ("bus:job-9981", "bus_job"),
                (f"web:{ADMIN_UID}:conv-web-1", "web_studio"),
            ):
                with self.subTest(active_scope=label):
                    sess_a = _FakeAgySession([], cid=f"conv-{label}")
                    with bridge.session_lock:
                        bridge.turn_running = True
                        bridge.turn_running_scope = active_scope
                        bridge.turn_running_chat = OTHER_GROUP_CHAT_ID
                        bridge.turn_gen = 21
                        bridge.turn_waiting_bg = False
                        bridge.turn_preempted_gen = None
                        bridge.cancel_requested = False
                        bridge._session_pool[active_scope] = sess_a

                    # Pre-populate a normal queued item so we verify put_front places urgent ahead of it
                    bridge.job_q.put((GROUP_CHAT_ID, TOPIC_B, scope_b, "normal_b1"))

                    sent_msgs = []
                    close_mock = mock.Mock()
                    with (
                        mock.patch.object(bridge, "close_session_async", close_mock),
                        mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_msgs.append(str(a[1])) or 931),
                    ):
                        bridge.enqueue_urgent(
                            GROUP_CHAT_ID,
                            f"urgent_for_{label}",
                            thread_id=TOPIC_B,
                            scope_key=scope_b,
                            user_role="admin",
                            user_id=ADMIN_UID,
                        )

                    self.assertEqual(0, close_mock.call_count, f"{label} must never be killed")
                    self.assertIsNone(bridge.turn_preempted_gen, f"{label} turn_preempted_gen must remain untouched")
                    self.assertFalse(bridge.cancel_requested, f"{label} cancel_requested must remain False")
                    self.assertIs(sess_a, bridge._session_pool.get(active_scope))
                    self.assertTrue(
                        any("其他会话正在占用" in m and "未中断其他会话" in m for m in sent_msgs),
                        f"Expected clear cross-scope notice for {label}, got {sent_msgs}",
                    )

                    # Urgent item must be at queue head ahead of normal_b1
                    it1 = bridge.job_q.get()
                    bridge.job_q.task_done()
                    it2 = bridge.job_q.get()
                    bridge.job_q.task_done()
                    p1 = it1[3][1]["prompt"] if isinstance(it1[3], tuple) else it1[3]
                    self.assertEqual(f"urgent_for_{label}", p1)
                    self.assertEqual("normal_b1", it2[3])

    def test_c5_preempt_card_scope_check_stale_qid_double_click_len_and_429_cooldown(self):
        """C5: action:preempt:<qid> cross-scope guard, stale/dispatched guard, concurrent double-click, <=64B, 429 safe."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            scope_a = f"{GROUP_CHAT_ID}:{TOPIC_A}"
            scope_b = f"{GROUP_CHAT_ID}:{TOPIC_B}"

            sess_a = _FakeAgySession([], cid="conv-c5-a")
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_scope = scope_a
                bridge.turn_running_chat = GROUP_CHAT_ID
                bridge.turn_gen = 30
                bridge.turn_waiting_bg = False
                bridge.turn_preempted_gen = None
                bridge.cancel_requested = False
                bridge._session_pool[scope_a] = sess_a

            # Queue items via enqueue() and verify callback_data <= 64 bytes
            enq_cards = []
            with mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: enq_cards.append((a, kw)) or 940):
                qid_a1 = bridge.enqueue(GROUP_CHAT_ID, "A1", thread_id=TOPIC_A, user_role="admin", user_id=ADMIN_UID)
                qid_b1 = bridge.enqueue(GROUP_CHAT_ID, "B1", thread_id=TOPIC_B, user_role="admin", user_id=ADMIN_UID)
                qid_a2 = bridge.enqueue(GROUP_CHAT_ID, "A2", thread_id=TOPIC_A, user_role="admin", user_id=ADMIN_UID)

            self.assertEqual(3, len(enq_cards))
            for qid_val, (_a, kw) in zip((qid_a1, qid_b1, qid_a2), enq_cards):
                kb = kw.get("reply_markup")
                self.assertIsInstance(kb, dict)
                preempt_cb = kb["inline_keyboard"][0][0]["callback_data"]
                self.assertEqual(f"action:preempt:{qid_val}", preempt_cb)
                self.assertLessEqual(len(preempt_cb.encode("utf-8")), 64)

            # 1. Cross-scope forgery: scope_a clicks qid_b1 -> rejected, 0 kills
            close_mock = mock.Mock()
            cb_answers = []
            with (
                mock.patch.object(bridge, "close_session_async", close_mock),
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: cb_answers.append((m, kw))),
                mock.patch.object(bridge, "send", return_value=941),
            ):
                bridge.handle_callback({
                    "id": "cb-xscope",
                    "from": {"id": ADMIN_UID},
                    "message": {
                        "chat": {"id": GROUP_CHAT_ID, "is_forum": True},
                        "message_thread_id": TOPIC_A,
                        "is_topic_message": True,
                        "message_id": 500,
                    },
                    "data": f"action:preempt:{qid_b1}",
                })
            self.assertEqual(0, close_mock.call_count)
            self.assertIsNone(bridge.turn_preempted_gen)
            self.assertTrue(any("已过期" in kw.get("text", "") for m, kw in cb_answers if m == "answerCallbackQuery"))

            # 2. Stale / already-dispatched / nonexistent qid -> 0 kills (never kills running target itself!)
            popped_qid, _popped_item = bridge.job_q.get_entry()  # pops qid_a1 into _dispatched
            self.assertEqual(qid_a1, popped_qid)
            with (
                mock.patch.object(bridge, "close_session_async", close_mock),
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: cb_answers.append((m, kw))),
                mock.patch.object(bridge, "send", return_value=942),
            ):
                for bad_qid in (qid_a1, "000000000000"):
                    bridge.handle_callback({
                        "id": f"cb-stale-{bad_qid}",
                        "from": {"id": ADMIN_UID},
                        "message": {
                            "chat": {"id": GROUP_CHAT_ID, "is_forum": True},
                            "message_thread_id": TOPIC_A,
                            "is_topic_message": True,
                            "message_id": 501,
                        },
                        "data": f"action:preempt:{bad_qid}",
                    })
            self.assertEqual(0, close_mock.call_count)
            self.assertIsNone(bridge.turn_preempted_gen)
            bridge.job_q.task_done(popped_qid)

            # 3. Concurrent double-click on valid qid_a2 -> at most 1 interrupt, 0 duplicates, 0 lost items
            barrier = threading.Barrier(2)
            double_close = []
            double_answers = []

            def click_worker(idx):
                barrier.wait(timeout=3.0)
                bridge.handle_callback({
                    "id": f"cb-dbl-{idx}",
                    "from": {"id": ADMIN_UID},
                    "message": {
                        "chat": {"id": GROUP_CHAT_ID, "is_forum": True},
                        "message_thread_id": TOPIC_A,
                        "is_topic_message": True,
                        "message_id": 502,
                    },
                    "data": f"action:preempt:{qid_a2}",
                })

            with (
                mock.patch.object(bridge, "close_session_async", side_effect=lambda s, force=False: double_close.append((s, force))),
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: double_answers.append((m, kw))),
                mock.patch.object(bridge, "send", return_value=943),
            ):
                t1 = threading.Thread(target=click_worker, args=(1,))
                t2 = threading.Thread(target=click_worker, args=(2,))
                t1.start()
                t2.start()
                t1.join(timeout=3.0)
                t2.join(timeout=3.0)

            self.assertEqual(1, len(double_close), "Concurrent double-click must trigger at most one kill")
            self.assertEqual(2, bridge.job_q.qsize(), "Queue must retain both qid_a2 and qid_b1 with 0 dupes/loss")
            q_first_id, _ = bridge.job_q.get_entry()
            bridge.job_q.task_done(q_first_id)
            q_second_id, _ = bridge.job_q.get_entry()
            bridge.job_q.task_done(q_second_id)
            self.assertEqual([qid_a2, qid_b1], [q_first_id, q_second_id])

            # 4. 429 FloodWait cooldown -> zero outbound HTTP posts on enqueue card & preempt callback
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_scope = scope_a
                bridge.turn_gen = 31
                bridge.turn_preempted_gen = None
                bridge._session_pool[scope_a] = _FakeAgySession([], cid="conv-c5-429")
            bridge._tg_record_flood_wait(60, chat_id=GROUP_CHAT_ID, method="sendMessage")
            try:
                post_mock = mock.Mock()
                with (
                    mock.patch.object(bridge.http_session, "post", post_mock),
                    mock.patch.object(bridge, "close_session_async", return_value=None),
                ):
                    qid_429 = bridge.enqueue(GROUP_CHAT_ID, "A429", thread_id=TOPIC_A, user_role="admin", user_id=ADMIN_UID)
                    bridge.handle_callback({
                        "id": "cb-429",
                        "from": {"id": ADMIN_UID},
                        "message": {
                            "chat": {"id": GROUP_CHAT_ID, "is_forum": True},
                            "message_thread_id": TOPIC_A,
                            "is_topic_message": True,
                            "message_id": 503,
                        },
                        "data": f"action:preempt:{qid_429}",
                    })
                self.assertEqual(0, post_mock.call_count, "429 cooldown must short-circuit all outbound Telegram HTTP calls")
                self.assertEqual(31, bridge.turn_preempted_gen, "Preemption state transition must still succeed during 429 cooldown")
            finally:
                bridge._tg_clear_flood_wait()

    def test_c6_enqueue_cancel_and_urgent_dequeue_window_race_and_lock_stress(self):
        """C6: Deterministic dequeue->run_agy window interception for /cancel & /urgent + multi-thread deadlock stress."""
        with tempfile.TemporaryDirectory() as tmp:
            # Part 1: Deterministic barrier between job_q.get_entry() and worker() claiming session_lock -> /cancel
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge.RELOAD_TRIGGER = os.path.join(tmp, "no_reload_c6a.flag")
            skey = str(ADMIN_UID)

            m1_popped = threading.Event()
            release_worker = threading.Event()
            run_agy_called = []
            sent_cancel = []
            orig_get_entry = bridge.job_q.get_entry

            def gated_get_entry():
                qid, item = orig_get_entry()
                if item[3] == "M1_cancel_window":
                    m1_popped.set()
                    release_worker.wait(timeout=5.0)
                return qid, item

            with (
                mock.patch.object(bridge.job_q, "get_entry", side_effect=gated_get_entry),
                mock.patch.object(bridge, "run_agy", side_effect=lambda *a, **kw: run_agy_called.append(a[1])),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_cancel.append(str(a[1])) or 951),
                mock.patch.object(bridge, "perform_hot_reload", return_value=True),
            ):
                tw = threading.Thread(target=bridge.worker, daemon=True)
                tw.start()
                bridge.job_q.put((ADMIN_UID, None, skey, "M1_cancel_window"))
                self.assertTrue(m1_popped.wait(timeout=3.0), "Worker should have popped M1 into _dispatched")
                self.assertFalse(bridge.turn_running, "M1 must be in pre-session_lock window")

                # Fire /cancel right in the empty window!
                bridge.cancel_current_task(ADMIN_UID, scope_key=skey)
                release_worker.set()

                # Terminate worker cleanly
                bridge.job_q.put((ADMIN_UID, None, skey, "__RELOAD__"))
                tw.join(timeout=3.0)
                self.assertFalse(tw.is_alive())

            self.assertEqual([], run_agy_called, "M1 caught in dequeue window must NEVER start run_agy/AgySession")
            self.assertTrue(any("已终止当前任务" in m for m in sent_cancel), f"Expected cancel ack, got {sent_cancel}")
            self.assertFalse(bridge.turn_running)

        with tempfile.TemporaryDirectory() as tmp:
            # Part 2: Deterministic barrier in dequeue window -> /urgent M2 intercepts M1 and runs M2 immediately
            bridge2 = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge2.RELOAD_TRIGGER = os.path.join(tmp, "no_reload_c6b.flag")
            skey = str(ADMIN_UID)

            m1_popped = threading.Event()
            release_worker = threading.Event()
            m2_done = threading.Event()
            executed = []
            orig_get_entry2 = bridge2.job_q.get_entry

            def gated_get_entry2():
                qid, item = orig_get_entry2()
                if item[3] == "M1_urgent_window":
                    m1_popped.set()
                    release_worker.wait(timeout=5.0)
                return qid, item

            def fake_run2(chat_id, prompt, **kw):
                executed.append(prompt)
                if prompt == "M2_urgent":
                    m2_done.set()

            with (
                mock.patch.object(bridge2.job_q, "get_entry", side_effect=gated_get_entry2),
                mock.patch.object(bridge2, "run_agy", side_effect=fake_run2),
                mock.patch.object(bridge2, "send", return_value=952),
                mock.patch.object(bridge2, "perform_hot_reload", return_value=True),
            ):
                tw2 = threading.Thread(target=bridge2.worker, daemon=True)
                tw2.start()
                bridge2.job_q.put((ADMIN_UID, None, skey, "M1_urgent_window"))
                self.assertTrue(m1_popped.wait(timeout=3.0))

                bridge2.enqueue_urgent(ADMIN_UID, "M2_urgent", user_role="admin", user_id=ADMIN_UID)
                release_worker.set()
                self.assertTrue(m2_done.wait(timeout=3.0), f"M2_urgent should execute immediately; executed={executed}")

                bridge2.job_q.put((ADMIN_UID, None, skey, "__RELOAD__"))
                tw2.join(timeout=3.0)
                self.assertFalse(tw2.is_alive())

            self.assertEqual(["M2_urgent"], executed, "M1 must be skipped and M2_urgent run immediately")

        with tempfile.TemporaryDirectory() as tmp:
            # Part 3: Pre-acquire window inside run_agy (after worker claims turn_gen, before _acquire_session)
            bridge3 = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge3.RELOAD_TRIGGER = os.path.join(tmp, "no_reload_c6c.flag")
            skey = str(ADMIN_UID)

            in_setup = threading.Event()
            release_setup = threading.Event()
            acq_mock = mock.Mock()

            def gated_snapshot(**kw):
                in_setup.set()
                release_setup.wait(timeout=5.0)
                return {}

            with (
                mock.patch.object(bridge3, "snapshot_workspace_files", side_effect=gated_snapshot),
                mock.patch.object(bridge3, "_acquire_session", acq_mock),
                mock.patch.object(bridge3, "send", return_value=953),
                mock.patch.object(bridge3, "tg", return_value=None),
                mock.patch.object(bridge3, "perform_hot_reload", return_value=True),
            ):
                tw3 = threading.Thread(target=bridge3.worker, daemon=True)
                tw3.start()
                bridge3.job_q.put((ADMIN_UID, None, skey, "M1_pre_acquire"))
                self.assertTrue(in_setup.wait(timeout=3.0))

                bridge3.cancel_current_task(ADMIN_UID, scope_key=skey)
                release_setup.set()

                bridge3.job_q.put((ADMIN_UID, None, skey, "__RELOAD__"))
                tw3.join(timeout=3.0)
                self.assertFalse(tw3.is_alive())

            self.assertEqual(0, acq_mock.call_count, "Cancelled pre-claimed turn must abort before _acquire_session")
            self.assertFalse(bridge3.turn_running)

        with tempfile.TemporaryDirectory() as tmp:
            # Part 4: Multi-threaded concurrency stress (worker + cancel + urgent + promote_to_front) -> 0 deadlocks
            bridge4 = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge4.RELOAD_TRIGGER = os.path.join(tmp, "no_reload_c6d.flag")
            skey = str(ADMIN_UID)
            errors = []

            def fast_run(chat_id, prompt, **kw):
                time.sleep(0.002)

            with (
                mock.patch.object(bridge4, "run_agy", side_effect=fast_run),
                mock.patch.object(bridge4, "close_session_async", return_value=None),
                mock.patch.object(bridge4, "send", return_value=954),
                mock.patch.object(bridge4, "tg", return_value=None),
                mock.patch.object(bridge4, "perform_hot_reload", return_value=True),
            ):
                tw4 = threading.Thread(target=bridge4.worker, daemon=True)
                tw4.start()

                def stress_actor(actor_id):
                    try:
                        for i in range(20):
                            qid = bridge4.enqueue(ADMIN_UID, f"s-{actor_id}-{i}", user_role="admin", user_id=ADMIN_UID)
                            if i % 3 == 0:
                                bridge4.job_q.promote_to_front(qid, skey)
                            elif i % 3 == 1:
                                bridge4.enqueue_urgent(ADMIN_UID, f"u-{actor_id}-{i}", user_role="admin", user_id=ADMIN_UID)
                            else:
                                bridge4.cancel_current_task(ADMIN_UID, scope_key=skey)
                    except Exception as exc:
                        errors.append(exc)

                actors = [threading.Thread(target=stress_actor, args=(k,)) for k in range(4)]
                for t in actors:
                    t.start()
                for t in actors:
                    t.join(timeout=8.0)
                    self.assertFalse(t.is_alive(), "Deadlock detected in stress actor thread")

                bridge4.job_q.clear_all()
                bridge4.job_q.put((ADMIN_UID, None, skey, "__RELOAD__"))
                tw4.join(timeout=5.0)
                self.assertFalse(tw4.is_alive(), "Deadlock detected in worker thread")
                self.assertEqual([], errors)

    def test_c7_command_registration_worker_menu_hiding_and_help_docs(self):
        """C7: /urgent registered in _KNOWN_BRIDGE_COMMANDS, DM & group menus, /help; worker keeps group menu deleted."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            self.assertIn("/urgent", bridge._KNOWN_BRIDGE_COMMANDS)
            self.assertIn("urgent", [c["command"] for c in bridge._PRIVATE_COMMANDS])
            self.assertIn("urgent", [c["command"] for c in bridge._GROUP_TEAM_COMMANDS])

            fake_ok = mock.MagicMock()
            fake_ok.status_code = 200
            fake_ok.json.return_value = {"ok": True, "result": True}

            # Coordinator with groups enabled -> registers _GROUP_TEAM_COMMANDS (including urgent)
            tg_calls_coord = []
            with (
                mock.patch.object(bridge, "_current_bot_role", return_value="coordinator"),
                mock.patch.object(bridge, "_is_groups_enabled", return_value=True),
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: tg_calls_coord.append((m, kw)) or fake_ok),
            ):
                self.assertTrue(bridge.register_bot_commands(force=True))
            grp_set = [kw for m, kw in tg_calls_coord if m == "setMyCommands" and kw.get("scope") == {"type": "all_group_chats"}]
            self.assertEqual(1, len(grp_set))
            self.assertIn("urgent", [c["command"] for c in grp_set[0]["commands"]])

            # Worker with groups enabled -> calls deleteMyCommands on all_group_chats (menu stays hidden!)
            tg_calls_worker = []
            with (
                mock.patch.object(bridge, "_current_bot_role", return_value="worker"),
                mock.patch.object(bridge, "_is_groups_enabled", return_value=True),
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: tg_calls_worker.append((m, kw)) or fake_ok),
            ):
                self.assertTrue(bridge.register_bot_commands(force=True))
            grp_del = [kw for m, kw in tg_calls_worker if m == "deleteMyCommands" and kw.get("scope") == {"type": "all_group_chats"}]
            self.assertEqual(1, len(grp_del))
            grp_set_w = [kw for m, kw in tg_calls_worker if m == "setMyCommands" and kw.get("scope") == {"type": "all_group_chats"}]
            self.assertEqual([], grp_set_w)

            # DM and Group /help both document /urgent and !
            help_outputs = []
            with mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: help_outputs.append((cid, txt)) or 961):
                bridge.handle_message({"chat": {"id": ADMIN_UID, "type": "private"}, "from": {"id": ADMIN_UID}, "message_id": 1, "text": "/help"})
                bridge.handle_message({"chat": {"id": GROUP_CHAT_ID, "type": "supergroup"}, "from": {"id": ADMIN_UID}, "message_id": 2, "text": "/help"})
            self.assertEqual(2, len(help_outputs))
            dm_help, grp_help = help_outputs[0][1], help_outputs[1][1]
            self.assertIn("/urgent", dm_help)
            self.assertIn("!", dm_help)
            self.assertIn("/urgent", grp_help)
            self.assertIn("!", grp_help)

    def test_c3_c6_studio_ipc_interrupt_idle_no_self_suicide_and_active_preemption(self):
        """Blocker #1 regression: Web Studio tg_group_send, room_turn, and enqueue_turn interrupt_current=True."""
        # --- Part A: _studio_ipc_tg_group_send idle + worker races into Step W1 -> NO self-suicide ---
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge.RELOAD_TRIGGER = os.path.join(tmp, "no_reload_b1a.flag")
            skey = bridge.scope_key_for(GROUP_CHAT_ID, TOPIC_A)

            worker_in_step_w1 = threading.Event()
            release_run = threading.Event()
            done_ev = threading.Event()
            prompts_sent = []
            close_calls = []

            def fake_acquire(sk, *a, **kw):
                sess = _FakeAgySession(
                    [
                        {"event": "init", "conversation_id": "conv-b1-tg-idle"},
                        {"event": "result", "result": {"status": "SUCCESS", "conversation_id": "conv-b1-tg-idle", "response": "tg-idle-ok"}},
                    ],
                    cid="conv-b1-tg-idle",
                )
                orig_send_prompt = sess.send_user_prompt

                def spy_prompt(p, raw_slash=False):
                    prompts_sent.append(p)
                    orig_send_prompt(p, raw_slash=raw_slash)
                    done_ev.set()

                sess.send_user_prompt = spy_prompt
                with bridge.session_lock:
                    bridge._session_pool[sk] = sess
                return sess, False

            orig_put_front_preempt = bridge.job_q.put_front_and_mark_dispatched_preempt

            def racing_put_front_preempt(item, scope_key, **kw):
                qid, marked = orig_put_front_preempt(item, scope_key, **kw)
                # Force deterministic race: wait until worker() has ALREADY popped `qid` and entered Step W1!
                self.assertTrue(worker_in_step_w1.wait(timeout=3.0), "worker must claim new_qid in Step W1 first")
                return qid, marked

            def gated_snapshot(**kw):
                worker_in_step_w1.set()
                release_run.wait(timeout=3.0)
                return {}

            with (
                mock.patch.object(bridge, "_resolve_studio_mirror_target", return_value=(GROUP_CHAT_ID, TOPIC_A)),
                mock.patch.object(bridge.job_q, "put_front_and_mark_dispatched_preempt", side_effect=racing_put_front_preempt),
                mock.patch.object(bridge, "snapshot_workspace_files", side_effect=gated_snapshot),
                mock.patch.object(bridge, "_acquire_session", side_effect=fake_acquire),
                mock.patch.object(bridge, "close_session_async", side_effect=lambda s, force=False: close_calls.append((s, force))),
                mock.patch.object(bridge, "send", return_value=701),
                mock.patch.object(bridge, "send_rich", return_value=(702, "ok")),
                mock.patch.object(bridge, "push_step_images", return_value=None),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact", return_value=None),
                mock.patch.object(bridge, "perform_hot_reload", return_value=True),
            ):
                tw = threading.Thread(target=bridge.worker, daemon=True)
                tw.start()
                try:
                    sc, body = bridge._studio_ipc_tg_group_send({
                        "user_id": ADMIN_UID,
                        "actor_username": "admin",
                        "content": "idle_web_tg_urgent",
                        "priority": "urgent",
                        "interrupt_current": True,
                        "mirror_human_to_tg": False,
                    })
                    release_run.set()
                    self.assertEqual(202, sc)
                    self.assertTrue(body["ok"])
                    self.assertFalse(body["interrupted_current"], "Idle interrupt_current must NOT self-preempt")
                    self.assertTrue(done_ev.wait(timeout=3.0), "New tg_group_send message must execute instead of self-suiciding")
                    self.assertEqual([], close_calls)
                    self.assertTrue(any("idle_web_tg_urgent" in p for p in prompts_sent), f"prompts={prompts_sent}")
                finally:
                    bridge.job_q.put((GROUP_CHAT_ID, TOPIC_A, skey, "__RELOAD__"))
                    tw.join(timeout=3.0)
                    self.assertFalse(tw.is_alive())

        # --- Part B: _studio_ipc_tg_group_send with active old turn in same scope -> interrupts old & runs new ---
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge.RELOAD_TRIGGER = os.path.join(tmp, "no_reload_b1b.flag")
            skey = bridge.scope_key_for(GROUP_CHAT_ID, TOPIC_A)

            old_started = threading.Event()
            new_done = threading.Event()
            sess_old = _FakeAgySession(
                [
                    {"event": "init", "conversation_id": "conv-b1-tg-old"},
                    {"event": "step_update", "step_update": {"step_type": "tool", "state": "ACTIVE", "step_index": 1, "tool_name": "run_command", "tool_info": {}}},
                ],
                cid="conv-b1-tg-old",
            )
            executed_prompts = []
            close_calls = []

            def fake_acquire_b(sk, *a, **kw):
                if not old_started.is_set():
                    with bridge.session_lock:
                        bridge._session_pool[sk] = sess_old
                    old_started.set()
                    return sess_old, False
                s_new = _FakeAgySession(
                    [
                        {"event": "init", "conversation_id": "conv-b1-tg-old"},
                        {"event": "result", "result": {"status": "SUCCESS", "conversation_id": "conv-b1-tg-old", "response": "new-done"}},
                    ],
                    cid="conv-b1-tg-old",
                )
                with bridge.session_lock:
                    bridge._session_pool[sk] = s_new
                return s_new, False

            orig_run = bridge.run_agy

            def spy_run(chat_id, prompt, **kw):
                executed_prompts.append(prompt)
                try:
                    return orig_run(chat_id, prompt, **kw)
                finally:
                    if prompt == "active_web_tg_urgent":
                        new_done.set()

            def fake_close_async(sess, force=False):
                close_calls.append((sess, force))
                sess.close(force=force)

            with (
                mock.patch.object(bridge, "_resolve_studio_mirror_target", return_value=(GROUP_CHAT_ID, TOPIC_A)),
                mock.patch.object(bridge, "_acquire_session", side_effect=fake_acquire_b),
                mock.patch.object(bridge, "close_session_async", side_effect=fake_close_async),
                mock.patch.object(bridge, "run_agy", side_effect=spy_run),
                mock.patch.object(bridge, "send", return_value=703),
                mock.patch.object(bridge, "send_rich", return_value=(704, "ok")),
                mock.patch.object(bridge, "push_step_images", return_value=None),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact", return_value=None),
                mock.patch.object(bridge, "perform_hot_reload", return_value=True),
            ):
                tw = threading.Thread(target=bridge.worker, daemon=True)
                tw.start()
                try:
                    bridge.job_q.put((GROUP_CHAT_ID, TOPIC_A, skey, "old_tg_turn"))
                    self.assertTrue(old_started.wait(timeout=3.0))
                    sc, body = bridge._studio_ipc_tg_group_send({
                        "user_id": ADMIN_UID,
                        "actor_username": "admin",
                        "content": "active_web_tg_urgent",
                        "priority": "urgent",
                        "interrupt_current": True,
                        "mirror_human_to_tg": False,
                    })
                    self.assertEqual(202, sc)
                    self.assertTrue(body["interrupted_current"], "Must interrupt active same-scope turn")
                    self.assertTrue(new_done.wait(timeout=4.0), f"executed={executed_prompts}")
                    self.assertIn((sess_old, True), close_calls)
                    self.assertEqual(["old_tg_turn", "active_web_tg_urgent"], executed_prompts)
                finally:
                    bridge.job_q.put((GROUP_CHAT_ID, TOPIC_A, skey, "__RELOAD__"))
                    tw.join(timeout=3.0)
                    self.assertFalse(tw.is_alive())

        # --- Part C: _studio_ipc_room_turn idle race (NO self-suicide) + active room turn preemption ---
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge.RELOAD_TRIGGER = os.path.join(tmp, "no_reload_b1c.flag")
            room_scope = "room:demo_room"

            worker_claimed = threading.Event()
            release_room = threading.Event()
            close_calls = []

            def fake_acquire_room_idle(sk, *a, **kw):
                s = _FakeAgySession(
                    [
                        {"event": "init", "conversation_id": "conv-room-idle"},
                        {"event": "result", "result": {"status": "SUCCESS", "conversation_id": "conv-room-idle", "response": "room-idle-ok"}},
                    ],
                    cid="conv-room-idle",
                )
                with bridge.session_lock:
                    bridge._session_pool[sk] = s
                return s, False

            orig_pfp = bridge.job_q.put_front_and_mark_dispatched_preempt

            def racing_room_pfp(item, scope_key, **kw):
                qid, marked = orig_pfp(item, scope_key, **kw)
                self.assertTrue(worker_claimed.wait(timeout=3.0), "worker must claim room qid in Step W1 first")
                release_room.set()
                return qid, marked

            def gated_room_snapshot(**kw):
                worker_claimed.set()
                release_room.wait(timeout=3.0)
                return {}

            with (
                mock.patch.object(bridge.job_q, "put_front_and_mark_dispatched_preempt", side_effect=racing_room_pfp),
                mock.patch.object(bridge, "snapshot_workspace_files", side_effect=gated_room_snapshot),
                mock.patch.object(bridge, "_acquire_session", side_effect=fake_acquire_room_idle),
                mock.patch.object(bridge, "close_session_async", side_effect=lambda s, force=False: close_calls.append((s, force))),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact", return_value=None),
                mock.patch.object(bridge, "perform_hot_reload", return_value=True),
            ):
                tw = threading.Thread(target=bridge.worker, daemon=True)
                tw.start()
                try:
                    sc, body = bridge._studio_ipc_room_turn({
                        "user_id": ADMIN_UID,
                        "actor_username": "admin",
                        "room_id": "demo_room",
                        "prompt": "idle_room_urgent",
                        "priority": "urgent",
                        "interrupt_current": True,
                    })
                    self.assertEqual(200, sc, body)
                    self.assertEqual("done", body["status"])
                    self.assertEqual("room-idle-ok", body["reply"])
                    self.assertFalse(body["interrupted_current"], "Idle room interrupt_current must NOT self-preempt")
                    self.assertEqual([], close_calls)
                finally:
                    bridge.job_q.put((0, None, room_scope, "__RELOAD__"))
                    tw.join(timeout=3.0)
                    self.assertFalse(tw.is_alive())

        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge.RELOAD_TRIGGER = os.path.join(tmp, "no_reload_b1c2.flag")
            room_scope = "room:demo_room"

            old_room_started = threading.Event()
            sess_room_old = _FakeAgySession(
                [
                    {"event": "init", "conversation_id": "conv-room-active"},
                    {"event": "step_update", "step_update": {"step_type": "tool", "state": "ACTIVE", "step_index": 1, "tool_name": "run_command", "tool_info": {}}},
                ],
                cid="conv-room-active",
            )
            close_calls = []
            old_result_holder = {}

            def fake_acquire_room_active(sk, *a, **kw):
                if not old_room_started.is_set():
                    with bridge.session_lock:
                        bridge._session_pool[sk] = sess_room_old
                    old_room_started.set()
                    return sess_room_old, False
                s_new = _FakeAgySession(
                    [
                        {"event": "init", "conversation_id": "conv-room-active"},
                        {"event": "result", "result": {"status": "SUCCESS", "conversation_id": "conv-room-active", "response": "room-urgent-ok"}},
                    ],
                    cid="conv-room-active",
                )
                with bridge.session_lock:
                    bridge._session_pool[sk] = s_new
                return s_new, False

            def fake_close_room(sess, force=False):
                close_calls.append((sess, force))
                sess.close(force=force)

            with (
                mock.patch.object(bridge, "_acquire_session", side_effect=fake_acquire_room_active),
                mock.patch.object(bridge, "close_session_async", side_effect=fake_close_room),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact", return_value=None),
                mock.patch.object(bridge, "perform_hot_reload", return_value=True),
            ):
                tw = threading.Thread(target=bridge.worker, daemon=True)
                tw.start()
                try:
                    def run_old_room():
                        old_result_holder["res"] = bridge._studio_ipc_room_turn({
                            "user_id": ADMIN_UID,
                            "actor_username": "admin",
                            "room_id": "demo_room",
                            "prompt": "old_room_turn",
                        })

                    t_old = threading.Thread(target=run_old_room, daemon=True)
                    t_old.start()
                    self.assertTrue(old_room_started.wait(timeout=3.0))

                    sc_new, body_new = bridge._studio_ipc_room_turn({
                        "user_id": ADMIN_UID,
                        "actor_username": "admin",
                        "room_id": "demo_room",
                        "prompt": "urgent_room_turn",
                        "priority": "urgent",
                        "interrupt_current": True,
                    })
                    t_old.join(timeout=4.0)
                    self.assertFalse(t_old.is_alive())
                    self.assertEqual(200, sc_new, body_new)
                    self.assertEqual("room-urgent-ok", body_new["reply"])
                    self.assertTrue(body_new["interrupted_current"], "Active same-room turn must be interrupted")
                    self.assertIn((sess_room_old, True), close_calls)
                    self.assertEqual(500, old_result_holder["res"][0])
                finally:
                    bridge.job_q.put((0, None, room_scope, "__RELOAD__"))
                    tw.join(timeout=3.0)
                    self.assertFalse(tw.is_alive())

        # --- Part D: _studio_ipc_enqueue_turn guard never cancels newly enqueued web turn ---
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            cid = "conv_b1_web_0001"
            old_tid = "turn-old-0001"
            bridge._studio_ipc_buffer.create_turn(
                old_tid,
                owner_user_id=ADMIN_UID,
                actor_username="admin",
                bot_handle="test_anti_hang_bot",
                scope_key=f"web:{ADMIN_UID}:{cid}",
                cid=cid,
                source="web",
                prompt_preview="old",
            )
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_cid = cid
                bridge.turn_running_web_id = old_tid
                bridge.turn_running_scope = f"web:{ADMIN_UID}:{cid}"
                bridge.turn_running_qid = "old-qid-0001"
                bridge.cancel_requested = False

            orig_pf = bridge.job_q.put_front

            def simulate_worker_switched_to_new_turn(item, **kw):
                new_qid = orig_pf(item, **kw)
                new_web_req = item[3][1]
                # Simulate old turn finishing and worker claiming new_qid before _studio_ipc_enqueue_turn takes session_lock
                with bridge.session_lock:
                    bridge.turn_running = True
                    bridge.turn_running_qid = new_qid
                    bridge.turn_running_web_id = new_web_req["turn_id"]
                    bridge.turn_running_cid = cid
                return new_qid

            with mock.patch.object(bridge.job_q, "put_front", side_effect=simulate_worker_switched_to_new_turn):
                sc_e, body_e = bridge._studio_ipc_enqueue_turn({
                    "user_id": ADMIN_UID,
                    "actor_username": "admin",
                    "prompt": "new_web_turn",
                    "cid": cid,
                    "priority": "urgent",
                    "interrupt_current": True,
                })
            self.assertEqual(202, sc_e, body_e)
            self.assertFalse(bridge.cancel_requested, "Must NOT set cancel_requested on newly claimed web turn")
            self.assertIsNone(body_e.get("interrupted_turn_id"))

    def test_c3_c6_run_agy_send_user_prompt_broken_pipe_under_preempt_and_cancel(self):
        """Blocker #2 regression: send_user_prompt() BrokenPipeError under preempt/cancel exits cleanly without raising."""
        for trigger_kind in ("preempt", "cancel"):
            for is_web in (False, True):
                for reused_warm in (False, True):
                    with self.subTest(trigger=trigger_kind, is_web=is_web, reused_warm=reused_warm):
                        with tempfile.TemporaryDirectory() as tmp:
                            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
                            skey = f"web:{ADMIN_UID}:conv-b2" if is_web else str(ADMIN_UID)
                            sent_msgs = []
                            web_events = []

                            sess = _FakeAgySession([], cid="conv-b2")

                            def broken_send_prompt(prompt, raw_slash=False):
                                with bridge.session_lock:
                                    if trigger_kind == "preempt":
                                        bridge.turn_preempted_gen = bridge.turn_gen
                                    else:
                                        bridge.cancel_requested = True
                                raise BrokenPipeError("stdin closed by force-kill")

                            sess.send_user_prompt = broken_send_prompt
                            acq_mock = mock.Mock(return_value=(sess, reused_warm))

                            with (
                                mock.patch.object(bridge, "_acquire_session", acq_mock),
                                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_msgs.append(str(a[1])) or 711),
                                mock.patch.object(bridge, "send_rich", return_value=(712, "ok")),
                                mock.patch.object(bridge, "push_step_images", return_value=None),
                                mock.patch.object(bridge, "tg", return_value=None),
                                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
                                mock.patch.object(bridge, "_maybe_post_turn_auto_compact", return_value=None),
                            ):
                                # Must NOT raise BrokenPipeError
                                bridge.run_agy(
                                    0 if is_web else ADMIN_UID,
                                    "hello_b2",
                                    scope_key=skey,
                                    user_role="admin",
                                    user_id=ADMIN_UID,
                                    event_sink=(lambda et, ep: web_events.append((et, ep))) if is_web else None,
                                    web_turn_id="turn-b2-1" if is_web else None,
                                )

                            self.assertEqual(1, acq_mock.call_count, "Must break cleanly without retrying after preempt/cancel")
                            self.assertFalse(any("bridge error" in m for m in sent_msgs), f"Must not emit bridge error: {sent_msgs}")
                            sc = bridge.get_scope_state(skey)
                            expected_status = "PREEMPTED" if trigger_kind == "preempt" else "CANCELLED"
                            self.assertEqual(expected_status, (sc.get("last_turn") or {}).get("status"))
                            if is_web:
                                ev_types = [et for et, _ in web_events]
                                self.assertIn("aborted", ev_types)
                                self.assertNotIn("error", ev_types)
                                aborted_payload = [ep for et, ep in web_events if et == "aborted"][-1]
                                expected_reason = "preempted" if trigger_kind == "preempt" else "cancelled"
                                self.assertEqual(expected_reason, aborted_payload.get("reason"))

    def test_c6_bus_job_cancel_after_worker_preclaim_skips_popen_and_finishes_cancelled(self):
        """Blocker #3 regression: worker Step W1 pre-claim -> /cancel during _execute_bus_job prep -> 0 Popen & cancelled."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_BUS_FAST_CHAT": "0"})
            bridge.RELOAD_TRIGGER = os.path.join(tmp, "no_reload_b3.flag")
            job_id = "job-b3-cancel01"
            bridge.bot_bus._ensure_dirs()
            bridge.bot_bus._atomic_write_json(
                bridge.bot_bus._job_path(job_id),
                {
                    "job_id": job_id,
                    "group_id": "grp-b3",
                    "from_bot": "coordinator_bot",
                    "target_bot": "test_anti_hang_bot",
                    "label": "B3 cancel prep test",
                    "prompt": "do work",
                    "workdir": bridge.WORKDIR,
                    "notify_group": False,
                    "status": "queued",
                    "cancel_requested": False,
                    "cancel_reason": "",
                    "group_delivered": False,
                    "created_at": time.time(),
                    "started_at": 0.0,
                    "finished_at": 0.0,
                    "worker_pid": 0,
                    "worker_cid": "",
                    "progress": "",
                    "result_text": "",
                    "error": "",
                    "artifacts": [],
                    "usage": {},
                },
            )

            prep_entered = threading.Event()
            cancel_applied = threading.Event()
            popen_mock = mock.Mock()

            def gated_snapshot(**kw):
                prep_entered.set()
                cancel_applied.wait(timeout=5.0)
                return {}

            with (
                mock.patch.object(bridge, "snapshot_workspace_files", side_effect=gated_snapshot),
                mock.patch.object(bridge.subprocess, "Popen", popen_mock),
                mock.patch.object(bridge, "send", return_value=721),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "tg_send_in_route", return_value=None),
                mock.patch.object(bridge, "perform_hot_reload", return_value=True),
            ):
                tw = threading.Thread(target=bridge.worker, daemon=True)
                tw.start()
                try:
                    bridge.job_q.put((ADMIN_UID, None, f"bus:{job_id}", ("__BUS_JOB__", job_id)))
                    self.assertTrue(prep_entered.wait(timeout=3.0), "_execute_bus_job should reach prep phase")
                    # Confirm worker() Step W1 pre-claimed the bus job
                    self.assertTrue(bridge.turn_running)
                    self.assertEqual(f"bus:{job_id}", bridge.turn_running_scope)

                    # Admin fires /cancel during _execute_bus_job preparation (before Popen)
                    bridge.cancel_current_task(ADMIN_UID, scope_key=str(ADMIN_UID))
                    self.assertTrue(bridge.cancel_requested)
                    cancel_applied.set()

                    # Terminate worker cleanly after bus job finishes
                    bridge.job_q.put((ADMIN_UID, None, str(ADMIN_UID), "__RELOAD__"))
                    tw.join(timeout=4.0)
                    self.assertFalse(tw.is_alive())
                finally:
                    cancel_applied.set()

            self.assertEqual(0, popen_mock.call_count, "Cancelled pre-claimed bus job must NEVER call subprocess.Popen")
            final_job = bridge.bot_bus.get_job(job_id)
            self.assertIsNotNone(final_job)
            self.assertEqual("cancelled", final_job["status"], f"Bus job must finish as cancelled, got: {final_job}")
            self.assertEqual("cancelled_local", final_job["error"])
            self.assertFalse(bridge.turn_running)
            self.assertFalse(bridge.cancel_requested)
            self.assertIsNone(bridge._active_bus_job_id)


if __name__ == "__main__":
    unittest.main()
