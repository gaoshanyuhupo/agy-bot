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


if __name__ == "__main__":
    unittest.main()
