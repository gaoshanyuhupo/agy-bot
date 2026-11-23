#!/usr/bin/env python3
"""Contract tests for P1 modularization of `bridge/bridge.py` into 4 flat sibling modules (C1, C4-C7)."""

from __future__ import annotations

import ast
import importlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
SCRIPTS_DIR = REPO_ROOT / "scripts"
for p in (BRIDGE_DIR, SCRIPTS_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

NEW_FLAT_MODULES = (
    "job_queue.py",
    "agent_driver.py",
    "live_streamer.py",
    "studio_ipc_handlers.py",
)

EXPECTED_23_IPC_HANDLERS = (
    "_studio_ipc_resolve_role",
    "_studio_ipc_get_meta",
    "_studio_ipc_enqueue_turn",
    "_studio_ipc_abort_turn",
    "_studio_ipc_cancel_job",
    "_studio_ipc_run_schedule",
    "_studio_ipc_list_undo",
    "_studio_ipc_get_undo_diff",
    "_studio_ipc_apply_undo",
    "_studio_ipc_apply_redo",
    "_studio_ipc_cleanup_worktree",
    "_studio_ipc_get_bot_config",
    "_studio_ipc_update_bot_config",
    "_studio_ipc_reload_bot",
    "_studio_ipc_get_bot_profile",
    "_studio_ipc_update_bot_profile",
    "_studio_ipc_get_bot_skill",
    "_studio_ipc_put_bot_skill",
    "_studio_ipc_delete_bot_skill",
    "_studio_ipc_room_turn",
    "_studio_ipc_attention_notify",
    "_studio_ipc_tg_group_send",
    "_studio_ipc_recycle_accounts",
)


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
        "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_MODULARIZATION_TEST_TOKEN_01",
        "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
        "AGY_STUDIO_IPC_DISABLE": "1",
    }
    with mock.patch.dict(os.environ, env_patch, clear=False):
        import bot_bus  # noqa: E402
        import bridge  # noqa: E402

        importlib.reload(bot_bus)
        importlib.reload(bridge)
        os.makedirs(bridge.WORKDIR, exist_ok=True)
        os.makedirs(bridge.UPLOADDIR, exist_ok=True)
        return bridge


class TestFlatLayoutAndCircularImportGuard(unittest.TestCase):
    """C1: Strictly flat `bridge/*.py`, zero `import bridge`, standalone importability & single source of truth."""

    def test_flat_layout_no_init_py_and_no_subpackages(self):
        self.assertFalse((BRIDGE_DIR / "__init__.py").exists(), "bridge/__init__.py MUST NOT exist")
        subdirs = [
            p.name for p in BRIDGE_DIR.iterdir() if p.is_dir() and p.name != "__pycache__"
        ]
        self.assertEqual(subdirs, [], f"Unexpected subdirectories under bridge/: {subdirs}")
        for fname in NEW_FLAT_MODULES:
            self.assertTrue((BRIDGE_DIR / fname).is_file(), f"Missing flat module bridge/{fname}")

    def test_zero_bridge_imports_in_new_modules_ast(self):
        for fname in NEW_FLAT_MODULES:
            src = (BRIDGE_DIR / fname).read_text(encoding="utf-8")
            tree = ast.parse(src, filename=f"bridge/{fname}")
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotEqual(
                            alias.name,
                            "bridge",
                            f"{fname}:L{node.lineno} forbidden `import bridge`",
                        )
                        self.assertFalse(
                            alias.name.startswith("bridge.bridge"),
                            f"{fname}:L{node.lineno} forbidden `{alias.name}`",
                        )
                elif isinstance(node, ast.ImportFrom):
                    if node.module == "bridge":
                        imported = [a.name for a in node.names]
                        self.assertNotIn(
                            "bridge",
                            imported,
                            f"{fname}:L{node.lineno} forbidden `from bridge import bridge`",
                        )

    def test_standalone_import_and_instantiation_in_fresh_subprocess(self):
        code = (
            "import sys, tempfile, os; "
            f"sys.path.insert(0, {str(BRIDGE_DIR)!r}); "
            "import job_queue, agent_driver, live_streamer, studio_ipc_handlers; "
            "assert 'bridge' not in sys.modules; "
            "td = tempfile.mkdtemp(); "
            "q = job_queue._JobQueue(persist_path=os.path.join(td, 'q.json')); "
            "q.put((1, None, '1', 'hello')); "
            "assert q.qsize() == 1; "
            "reg = agent_driver.DriverRegistry(); "
            "assert 'agy' in reg.list_drivers(); "
            "s = live_streamer.LiveDraftStreamer(12345, 0.0, enabled=False); "
            "assert s.use_draft_api is True; "
            "noop = live_streamer._NoOpStreamer(cid='c1'); "
            "assert noop.finalize_step('x') == (None, None); "
            "print('STANDALONE_OK')"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        self.assertIn("STANDALONE_OK", proc.stdout)

    def test_self_check_and_single_source_of_truth_exports(self):
        proc = subprocess.run(
            [sys.executable, str(BRIDGE_DIR / "bridge.py"), "--self-check"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        report = json.loads(proc.stdout.strip())
        self.assertEqual(report.get("status"), "ok")

        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            import agent_driver  # noqa: E402
            import job_queue  # noqa: E402
            import live_streamer  # noqa: E402
            import studio_ipc_handlers  # noqa: E402

            # Identity re-exports
            self.assertIs(bridge._JobQueue, job_queue._JobQueue)
            self.assertIs(bridge.PersistentJobQueue, job_queue.PersistentJobQueue)
            self.assertIs(bridge.restore_persisted_queue, job_queue.restore_persisted_queue)
            self.assertIs(bridge.AgySession, agent_driver.AgySession)
            self.assertIs(bridge._kill_process_tree, agent_driver._kill_process_tree)
            self.assertIs(bridge._read_proc_starttime, agent_driver._read_proc_starttime)
            self.assertIs(bridge._read_proc_stat_info, agent_driver._read_proc_stat_info)
            self.assertIs(bridge._acquire_session, agent_driver._acquire_session)
            self.assertIs(bridge.LiveDraftStreamer, live_streamer.LiveDraftStreamer)
            self.assertIs(bridge._NoOpStreamer, live_streamer._NoOpStreamer)
            self.assertIs(bridge.alloc_draft_pair, live_streamer.alloc_draft_pair)
            self.assertIs(bridge._start_studio_ipc, studio_ipc_handlers._start_studio_ipc)
            self.assertIs(bridge._stop_studio_ipc, studio_ipc_handlers._stop_studio_ipc)
            self.assertIs(bridge._undo_apply_lock, studio_ipc_handlers._undo_apply_lock)
            self.assertIs(bridge._studio_attention_receipts, studio_ipc_handlers._studio_attention_receipts)

            # All 23 Studio IPC handlers re-exported identically
            for hname in EXPECTED_23_IPC_HANDLERS:
                self.assertTrue(hasattr(bridge, hname), f"bridge missing {hname}")
                self.assertIs(
                    getattr(bridge, hname),
                    getattr(studio_ipc_handlers, hname),
                    f"Re-export mismatch for {hname}",
                )

            # Single source of truth for global mutable state (no duplicate pool/lock/queue)
            self.assertFalse(hasattr(agent_driver, "_session_pool"))
            self.assertFalse(hasattr(agent_driver, "session_lock"))
            self.assertFalse(hasattr(job_queue, "job_q"))
            self.assertFalse(hasattr(studio_ipc_handlers, "_studio_ipc_server"))


class TestStandaloneQueuePreemptAndCancelWindow(unittest.TestCase):
    """C4: Standalone `_JobQueue` atomic persistence, dequeue->run_agy preempt/cancel window, and restore."""

    def test_dispatched_preempt_and_cancel_flags_and_disk_restore(self):
        import job_queue  # noqa: E402

        with tempfile.TemporaryDirectory() as tmp:
            qfile = os.path.join(tmp, "queue.json")
            q = job_queue._JobQueue(persist_path=qfile)
            q1 = q.put((100, None, "100", "first"))
            q.put((100, None, "100", "second"))

            got_qid, got_item = q.get_entry()
            self.assertEqual(got_qid, q1)
            self.assertEqual(got_item[3], "first")

            # Urgent preempt marks currently dispatched same-scope item in dequeue->run_agy window
            urgent_qid, marked = q.put_front_and_mark_dispatched_preempt((100, None, "100", "urgent"), "100")
            self.assertEqual(marked, 1)
            self.assertEqual(q.consume_dispatched_cancel(q1), "preempt")
            self.assertIsNone(q.consume_dispatched_cancel(q1))

            # Cancel scope removes pending items and flags dispatched item as "cancel"
            removed, marked_cancel = q.cancel_scope_and_mark_dispatched("100")
            self.assertEqual(removed, 2)  # urgent + second
            self.assertEqual(marked_cancel, 1)
            self.assertEqual(q.consume_dispatched_cancel(q1), "cancel")
            self.assertNotEqual(urgent_qid, q1)

            # Fresh queue restores remaining dispatched item from disk
            q2 = job_queue._JobQueue(persist_path=qfile)
            summary = q2.restore_from_disk(ttl_sec=3600)
            self.assertEqual(summary["restored"], 1)
            self.assertEqual(q2.get()[3], "first")


class TestLiveStreamerResilienceAndConcurrency(unittest.TestCase):
    """C5: `LiveDraftStreamer` io_lock finalize guard, 429 backoff, and editMessageText fallback."""

    def test_io_lock_prevents_late_draft_racing_finalize_and_handles_429_and_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            streamer = bridge.LiveDraftStreamer(111, time.time() - 5.0, enabled=False)
            self.assertTrue(streamer.use_draft_api)

            # 1. Concurrent _push_draft vs finalize_step strictly serialized by io_lock
            entered_http = threading.Event()
            release_http = threading.Event()
            timeline: list[str] = []

            class _FakeResp:
                def __init__(self, status_code, payload):
                    self.status_code = status_code
                    self._payload = payload
                    self.headers = {}

                def json(self):
                    return dict(self._payload)

            def _blocking_tg_route(method, chat_id, **kw):
                timeline.append(f"push_start:{method}")
                entered_http.set()
                release_http.wait(timeout=3.0)
                timeline.append(f"push_end:{method}")
                return _FakeResp(200, {"ok": True, "result": True})

            def _fake_send_rich(*a, **kw):
                timeline.append("finalize_send_rich")
                return 777, "<b>final</b>"

            with (
                mock.patch.object(bridge, "tg_send_in_route", side_effect=_blocking_tg_route),
                mock.patch.object(bridge, "send_rich", side_effect=_fake_send_rich),
                mock.patch.object(bridge, "_tg_flood_remaining", return_value=0.0),
            ):
                th = threading.Thread(target=streamer._push_draft, args=(streamer.status_draft_id, "<b>hi</b>"))
                th.start()
                self.assertTrue(entered_http.wait(timeout=2.0))

                fin_done = threading.Event()

                def _run_finalize():
                    streamer.finalize_step("final answer")
                    fin_done.set()

                th_fin = threading.Thread(target=_run_finalize)
                th_fin.start()
                time.sleep(0.05)
                self.assertFalse(fin_done.is_set(), "finalize_step must wait for in-flight io_lock")
                release_http.set()
                th.join(timeout=2.0)
                th_fin.join(timeout=2.0)
                self.assertTrue(fin_done.is_set())
                self.assertEqual(
                    timeline,
                    ["push_start:sendMessageDraft", "push_end:sendMessageDraft", "finalize_send_rich"],
                )

            # 2. 429 on sendMessageDraft sets flood_until without switching away from draft API
            streamer2 = bridge.LiveDraftStreamer(111, time.time() - 5.0, enabled=False)
            resp_429 = _FakeResp(429, {"ok": False, "parameters": {"retry_after": 7}})
            with (
                mock.patch.object(bridge, "tg_send_in_route", return_value=resp_429),
                mock.patch.object(bridge, "_tg_record_flood_wait") as m_rec,
                mock.patch.object(bridge, "_tg_flood_remaining", return_value=0.0),
            ):
                before_t = time.time()
                streamer2._push_draft(streamer2.status_draft_id, "<b>test</b>")
                self.assertTrue(streamer2.use_draft_api)
                self.assertGreaterEqual(streamer2.flood_until, before_t + 7.0)
                m_rec.assert_called_once()

            # 3. Non-429 error on sendMessageDraft falls back cleanly to sendMessage / editMessageText via bridge.tg
            streamer3 = bridge.LiveDraftStreamer(111, time.time() - 5.0, enabled=False)
            calls: list[str] = []

            def _route_fallback(method, chat_id, **kw):
                calls.append(method)
                if method == "sendMessageDraft":
                    return _FakeResp(400, {"ok": False, "description": "Bad Request: method not available"})
                return _FakeResp(200, {"ok": True, "result": {"message_id": 901}})

            with (
                mock.patch.object(bridge, "tg_send_in_route", side_effect=_route_fallback),
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: calls.append(m) or _FakeResp(200, {"ok": True})),
                mock.patch.object(bridge, "_tg_flood_remaining", return_value=0.0),
            ):
                streamer3._push_draft(streamer3.status_draft_id, "<b>hello</b>")
                self.assertFalse(streamer3.use_draft_api)
                self.assertEqual(streamer3.fallback_msg_id, 901)
                # Subsequent push edits via bridge.tg("editMessageText", ...)
                streamer3._push_draft(streamer3.status_draft_id, "<b>hello 2</b>")
                self.assertEqual(calls, ["sendMessageDraft", "sendMessage", "editMessageText"])


class TestLockHierarchyAndRegistrationCompleteness(unittest.TestCase):
    """C6 & C7: AST lock-ordering across all split modules + deployment/CI/public-export registration."""

    def test_ast_lock_hierarchy_across_bridge_and_all_four_modules(self):
        git_call_names = {
            "_run_git",
            "prepare_job_worktree",
            "finalize_job_worktree",
            "cleanup_job_worktree",
            "prepare_studio_worktree",
            "inspect_studio_worktree",
            "cleanup_studio_worktree",
        }

        def _lock_name(ctx_expr: ast.AST) -> str | None:
            if isinstance(ctx_expr, ast.Name) and ctx_expr.id in ("state_lock", "session_lock"):
                return ctx_expr.id
            if isinstance(ctx_expr, ast.Attribute):
                if ctx_expr.attr in ("state_lock", "session_lock"):
                    return ctx_expr.attr
                if ctx_expr.attr == "_cond":
                    return "job_q._cond"
            return None

        violations: list[str] = []
        for fname in ("bridge.py",) + NEW_FLAT_MODULES:
            src = (BRIDGE_DIR / fname).read_text(encoding="utf-8")
            tree = ast.parse(src, filename=f"bridge/{fname}")

            def _walk(node: ast.AST, active_locks: list[str], func_name: str, _fn: str = fname) -> None:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for stmt in node.body:
                        _walk(stmt, [], node.name, _fn)
                    return
                if isinstance(node, ast.With):
                    added: list[str] = []
                    for item in node.items:
                        lname = _lock_name(item.context_expr)
                        if lname:
                            if lname == "session_lock" and "state_lock" in active_locks:
                                violations.append(f"{_fn}:{func_name}:L{node.lineno} state_lock->session_lock")
                            if (lname == "session_lock" and "job_q._cond" in active_locks) or (
                                lname == "job_q._cond" and "session_lock" in active_locks
                            ):
                                violations.append(f"{_fn}:{func_name}:L{node.lineno} job_q._cond<->session_lock")
                            added.append(lname)
                    next_locks = active_locks + added
                    for stmt in node.body:
                        _walk(stmt, next_locks, func_name, _fn)
                    return
                if isinstance(node, ast.Call) and ("state_lock" in active_locks or "session_lock" in active_locks):
                    callee = ""
                    if isinstance(node.func, ast.Name):
                        callee = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        callee = node.func.attr
                    if callee in git_call_names:
                        violations.append(f"{_fn}:{func_name}:L{node.lineno} {callee} under {active_locks}")
                for child in ast.iter_child_nodes(node):
                    _walk(child, active_locks, func_name, _fn)

            _walk(tree, [], "<module>")

        self.assertEqual(violations, [], f"Lock ordering / git-under-lock violations: {violations}")

    def test_start_studio_ipc_wires_all_23_callbacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            captured_kwargs = {}

            class _FakeServer:
                sock_path = "/tmp/fake.sock"

                def __init__(self, **kw):
                    captured_kwargs.update(kw)

                def start(self):
                    pass

                def stop(self):
                    pass

            with (
                mock.patch.dict(os.environ, {"AGY_STUDIO_IPC_DISABLE": "0"}),
                mock.patch.object(bridge.studio_ipc, "StudioIPCServer", _FakeServer),
            ):
                bridge._studio_ipc_server = None
                srv = bridge._start_studio_ipc()
                self.assertIsNotNone(srv)
                self.assertIs(bridge._studio_ipc_server, srv)
                expected_kw_keys = {
                    "resolve_role_fn",
                    "get_meta_fn",
                    "enqueue_turn_fn",
                    "abort_turn_fn",
                    "cancel_job_fn",
                    "run_schedule_fn",
                    "list_undo_fn",
                    "diff_undo_fn",
                    "apply_undo_fn",
                    "apply_redo_fn",
                    "cleanup_worktree_fn",
                    "get_bot_config_fn",
                    "update_bot_config_fn",
                    "reload_bot_fn",
                    "get_bot_profile_fn",
                    "update_bot_profile_fn",
                    "get_bot_skill_fn",
                    "put_bot_skill_fn",
                    "delete_bot_skill_fn",
                    "room_turn_fn",
                    "attention_notify_fn",
                    "tg_group_send_fn",
                    "recycle_accounts_fn",
                }
                self.assertEqual(len(expected_kw_keys), 23)
                for k in expected_kw_keys:
                    self.assertIn(k, captured_kwargs, f"Missing StudioIPCServer callback {k}")
                    self.assertTrue(callable(captured_kwargs[k]), f"Callback {k} not callable")
                bridge._stop_studio_ipc()
                self.assertIsNone(bridge._studio_ipc_server)

    def test_registration_in_cli_verify_gate_and_private_sync_scripts(self):
        import cli as bridge_cli  # noqa: E402
        import verify_gate  # noqa: E402

        for fname in NEW_FLAT_MODULES:
            self.assertIn(fname, bridge_cli.RUNTIME_BRIDGE_FILES)

        self.assertIn("tests/test_agent_driver.py", verify_gate.BRIDGE_TEST_FILES)
        self.assertIn("tests/test_bridge_modularization.py", verify_gate.BRIDGE_TEST_FILES)

        if (SCRIPTS_DIR / "sync_live.py").is_file():
            import sync_live  # noqa: E402

            mapped_rels = {rel for rel, _live, _kind, _dep in sync_live.MAPPINGS}
            for fname in NEW_FLAT_MODULES:
                self.assertIn(f"bridge/{fname}", mapped_rels)

        if (SCRIPTS_DIR / "export_public.py").is_file():
            import export_public  # noqa: E402

            for fname in NEW_FLAT_MODULES:
                self.assertTrue(export_public.is_public_core(f"bridge/{fname}"))
            self.assertIn("tests/test_agent_driver.py", export_public.CORE_SYNC_EXACT)
            self.assertIn("tests/test_bridge_modularization.py", export_public.CORE_SYNC_EXACT)


if __name__ == "__main__":
    unittest.main()
