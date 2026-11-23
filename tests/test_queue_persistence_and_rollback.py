#!/usr/bin/env python3
"""Offline unit & integration tests for Queue Restart Persistence & Hot-Reload Auto-Rollback."""

from __future__ import annotations

import importlib
import json
import os
import shutil
import stat
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


def _load_isolated_bridge(tmp: str, extra_env: dict[str, str] | None = None):
    env_patch = {
        "AGY_BOT_BUS_DIR": os.path.join(tmp, "bus"),
        "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
        "AGY_TG_QUEUE_FILE": os.path.join(tmp, "state.json.queue.json"),
        "AGY_TG_QUEUE_TTL_SEC": "3600",
        "AGY_TG_ROLLBACK_DIR": os.path.join(tmp, "rollback_lkg"),
        "AGY_TG_RELOAD_BREADCRUMB": os.path.join(tmp, "reload_pending.json"),
        "AGY_TG_MAX_ROLLBACK_ATTEMPTS": "2",
        "AGY_MEMORY_TAINT_FILE": os.path.join(tmp, "memory_taint.json"),
        "AGY_TG_WORKDIR": os.path.join(tmp, "workdir"),
        "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
        "AGY_TG_ALLOWED_CHATS": "-1001234567890,111",
        "AGY_TG_ALLOWED_USERS": "",
        "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_QUEUE_ROLLBACK_TOKEN_01",
        "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
        "AGY_BOT_CHAIN": "",
        "AGY_BOT_ORIGIN_MSG_ID": "0",
        "AGY_BOT_MENTION_HOP": "0",
    }
    if extra_env:
        env_patch.update(extra_env)
    with mock.patch.dict(os.environ, env_patch, clear=False):
        import bot_bus  # noqa: E402
        import bridge  # noqa: E402

        importlib.reload(bot_bus)
        importlib.reload(bridge)
        os.makedirs(bridge.WORKDIR, exist_ok=True)
        os.makedirs(bridge.UPLOADDIR, exist_ok=True)
        return bridge, bot_bus


class TestQueueRestartPersistence(unittest.TestCase):
    """Verify atomic _JobQueue persistence, sentinel filtering, TTL, in-flight dedup, and FIFO restore."""

    def test_persists_all_item_types_filters_reload_and_tracks_dispatched(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _bot_bus = _load_isolated_bridge(tmp)
            qfile = Path(bridge.QUEUE_FILE)

            bridge.job_q.put((111, None, "111", "plain string prompt"))
            bridge.job_q.put((111, None, "111", "__RELOAD__"))  # must NEVER be persisted
            bridge.job_q.put(
                (
                    -1001234567890,
                    42,
                    "-1001234567890:42",
                    (
                        "__CHAT_TURN__",
                        {
                            "prompt": "hello topic",
                            "origin_msg_id": 900,
                            "mention_hop": 2,
                            "chain_id": "ch-1",
                            "user_role": "readonly",
                            "user_id": 222,
                        },
                    ),
                )
            )
            bridge.job_q.put((111, None, "111", ("__COMPACT__", "focus on tests")))
            bridge.job_q.put((111, None, "111", ("__SCHEDULED__", {"id": "t-1", "task_type": "script"})))
            bridge.job_q.put((111, None, "bus:job-9", ("__BUS_JOB__", "job-9")))

            self.assertTrue(qfile.is_file())
            self.assertEqual(0o600, stat.S_IMODE(qfile.stat().st_mode))
            raw = json.loads(qfile.read_text(encoding="utf-8"))
            kinds = [r["kind"] for r in raw["items"]]
            self.assertEqual(["text", "chat_turn", "compact", "scheduled", "bus_job"], kinds)
            self.assertFalse(any(r.get("payload") == "__RELOAD__" for r in raw["items"]))

            # Pop 1st item -> marked dispatched on disk until task_done()
            first = bridge.job_q.get()
            self.assertEqual("plain string prompt", first[3])
            raw_mid = json.loads(qfile.read_text(encoding="utf-8"))
            self.assertEqual("dispatched", raw_mid["items"][0]["status"])

            # Pop control sentinel -> not marked dispatched
            sec = bridge.job_q.get()
            self.assertEqual("__RELOAD__", sec[3])
            bridge.job_q.task_done()  # finishes 1st real item

            raw_after = json.loads(qfile.read_text(encoding="utf-8"))
            self.assertEqual(4, len(raw_after["items"]))
            self.assertTrue(all(r["status"] == "pending" for r in raw_after["items"]))

    def test_restore_persisted_queue_ttl_inflight_dedup_bus_check_and_route_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, bot_bus = _load_isolated_bridge(tmp)
            qfile = Path(bridge.QUEUE_FILE)

            # Seed two bus jobs: one still queued (valid), one done (should be dropped)
            bot_bus.heartbeat_bot({"handle": "worker", "pid": os.getpid(), "role": "worker"})
            res_disp = bot_bus.dispatch_assignments(
                "main",
                [
                    {"bot": "worker", "prompt": "queued bus work", "label": "q1"},
                    {"bot": "worker", "prompt": "finished bus work", "label": "d1"},
                ],
            )
            j_queued, j_done = res_disp["jobs"]
            bot_bus.claim_job(j_done["job_id"], "worker", 123)
            bot_bus.finish_job(j_done["job_id"], status="done", result_text="ok")

            now = time.time()
            seed_items = [
                {
                    "qid": "expired-1",
                    "enqueued_at": now - 7200,  # > 3600s TTL -> drop
                    "status": "pending",
                    "chat_id": 111,
                    "thread_id": None,
                    "scope_key": "111",
                    "kind": "text",
                    "payload": "stale prompt",
                },
                {
                    "qid": "disp-inflight",
                    "enqueued_at": now - 10,
                    "status": "dispatched",
                    "chat_id": 111,
                    "thread_id": None,
                    "scope_key": "111",
                    "kind": "chat_turn",
                    "payload": {
                        "prompt": "already in flight",
                        "origin_msg_id": 55,
                        "mention_hop": 0,
                        "chain_id": "",
                        "user_role": "admin",
                        "user_id": 111,
                    },
                },
                {
                    "qid": "keep-chat-1",
                    "enqueued_at": now - 5,
                    "status": "pending",
                    "chat_id": 111,
                    "thread_id": None,
                    "scope_key": "111",
                    "kind": "chat_turn",
                    "payload": {
                        "prompt": "follow-up 1",
                        "origin_msg_id": 56,
                        "mention_hop": 1,
                        "chain_id": "c-56",
                        "user_role": "readonly",
                        "user_id": 222,
                    },
                },
                {
                    "qid": "keep-chat-2",
                    "enqueued_at": now - 4,
                    "status": "pending",
                    "chat_id": -1001234567890,
                    "thread_id": 77,
                    "scope_key": "-1001234567890:77",
                    "kind": "compact",
                    "payload": "compact note",
                },
                {
                    "qid": "bus-done",
                    "enqueued_at": now - 3,
                    "status": "pending",
                    "chat_id": 111,
                    "thread_id": None,
                    "scope_key": f"bus:{j_done['job_id']}",
                    "kind": "bus_job",
                    "payload": j_done["job_id"],
                },
                {
                    "qid": "bus-queued",
                    "enqueued_at": now - 2,
                    "status": "pending",
                    "chat_id": 111,
                    "thread_id": None,
                    "scope_key": f"bus:{j_queued['job_id']}",
                    "kind": "bus_job",
                    "payload": j_queued["job_id"],
                },
            ]
            qfile.write_text(json.dumps({"version": 1, "items": seed_items}), encoding="utf-8")

            # Simulate restart into fresh bridge instance
            bridge2, _ = _load_isolated_bridge(tmp)
            sent_notices = []
            with mock.patch.object(
                bridge2,
                "send",
                side_effect=lambda cid, txt, **kw: sent_notices.append((cid, kw.get("thread_id"), txt)) or 1,
            ):
                summary = bridge2.restore_persisted_queue(
                    recovered_in_flight=[("111", "already in flight")],
                    notify=True,
                )

            self.assertEqual(3, summary["restored"])
            self.assertEqual(1, summary["dropped_expired"])
            self.assertEqual(1, summary["dropped_dedup"])
            self.assertEqual(1, summary["dropped_invalid"])

            # Verify FIFO order & full field preservation
            it1 = bridge2.job_q.get()
            it2 = bridge2.job_q.get()
            it3 = bridge2.job_q.get()
            self.assertEqual("chat_turn", "chat_turn")
            self.assertEqual("__CHAT_TURN__", it1[3][0])
            self.assertEqual("follow-up 1", it1[3][1]["prompt"])
            self.assertEqual(56, it1[3][1]["origin_msg_id"])
            self.assertEqual("readonly", it1[3][1]["user_role"])
            self.assertEqual(222, it1[3][1]["user_id"])
            self.assertEqual((-1001234567890, 77, "-1001234567890:77", ("__COMPACT__", "compact note")), it2)
            self.assertEqual(("__BUS_JOB__", j_queued["job_id"]), it3[3])

            # One concise summary per affected route (111 and -1001234567890:77)
            routes_notified = {(c, t) for c, t, _ in sent_notices}
            self.assertEqual({(111, None), (-1001234567890, 77)}, routes_notified)

    def test_restore_dedups_readonly_chat_turn_against_exec_skey(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _bot_bus = _load_isolated_bridge(tmp)
            qfile = Path(bridge.QUEUE_FILE)
            now = time.time()
            seed_items = [
                {
                    "qid": "ro-disp-1",
                    "enqueued_at": now - 10,
                    "status": "dispatched",
                    "chat_id": -1001234567890,
                    "thread_id": 42,
                    "scope_key": "-1001234567890:42",
                    "kind": "chat_turn",
                    "payload": {
                        "prompt": "readonly inflight query",
                        "origin_msg_id": 101,
                        "mention_hop": 0,
                        "chain_id": "",
                        "user_role": "readonly",
                        "user_id": 222,
                    },
                },
                {
                    "qid": "ro-disp-guest",
                    "enqueued_at": now - 9,
                    "status": "dispatched",
                    "chat_id": 111,
                    "thread_id": None,
                    "scope_key": "111",
                    "kind": "chat_turn",
                    "payload": {
                        "prompt": "guest inflight query",
                        "origin_msg_id": 102,
                        "mention_hop": 0,
                        "chain_id": "",
                        "user_role": "readonly",
                        "user_id": None,
                    },
                },
                {
                    "qid": "ro-pending-2",
                    "enqueued_at": now - 5,
                    "status": "pending",
                    "chat_id": -1001234567890,
                    "thread_id": 42,
                    "scope_key": "-1001234567890:42",
                    "kind": "chat_turn",
                    "payload": {
                        "prompt": "readonly pending query",
                        "origin_msg_id": 103,
                        "mention_hop": 0,
                        "chain_id": "",
                        "user_role": "readonly",
                        "user_id": 222,
                    },
                },
            ]
            qfile.write_text(json.dumps({"version": 1, "items": seed_items}), encoding="utf-8")

            bridge2, _ = _load_isolated_bridge(tmp)
            with mock.patch.object(bridge2, "send", return_value=1):
                summary = bridge2.restore_persisted_queue(
                    recovered_in_flight=[
                        ("-1001234567890:42:ro:222", "readonly inflight query"),
                        ("111:ro:guest", "guest inflight query"),
                    ],
                    notify=False,
                )

            self.assertEqual(2, summary["dropped_dedup"])
            self.assertEqual(1, summary["restored"])
            kept = bridge2.job_q.get()
            self.assertEqual("readonly pending query", kept[3][1]["prompt"])

    def test_put_front_and_promote_to_front_persist_order_across_crash_restart(self):
        """C7: put_front and promote_to_front atomically persist (0o600) and restore exact head order."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _ = _load_isolated_bridge(tmp)
            qfile = Path(bridge.QUEUE_FILE)

            # Part 1: put(Q1), put(Q2), put_front(U1) -> crash reload -> [U1, Q1, Q2]
            qid_q1 = bridge.job_q.put((111, None, "111", "Q1"))
            qid_q2 = bridge.job_q.put((111, None, "111", "Q2"))
            qid_u1 = bridge.job_q.put_front((111, None, "111", "U1"))
            self.assertTrue(qid_q1 and qid_q2 and qid_u1)
            self.assertEqual(0o600, stat.S_IMODE(qfile.stat().st_mode))

            bridge_reloaded, _ = _load_isolated_bridge(tmp)
            summary1 = bridge_reloaded.restore_persisted_queue(notify=False)
            self.assertEqual(3, summary1["restored"])
            got1 = [bridge_reloaded.job_q.get()[3] for _ in range(3)]
            for _ in range(3):
                bridge_reloaded.job_q.task_done()
            self.assertEqual(["U1", "Q1", "Q2"], got1)

            # Part 2: put(Q1), put(Q2), promote_to_front(Q2, scope) -> crash reload -> [Q2, Q1]
            bridge_p2, _ = _load_isolated_bridge(tmp)
            p2_q1 = bridge_p2.job_q.put((111, None, "111", "Q1"))
            p2_q2 = bridge_p2.job_q.put((111, None, "111", "Q2"))
            # Cross-scope promote must fail closed without changing order
            self.assertFalse(bridge_p2.job_q.promote_to_front(p2_q2, "-1001234567890"))
            # Matching-scope promote succeeds and persists atomically
            self.assertTrue(bridge_p2.job_q.promote_to_front(p2_q2, "111"))
            self.assertEqual(0o600, stat.S_IMODE(qfile.stat().st_mode))
            self.assertNotEqual(p2_q1, p2_q2)

            bridge_p2_reloaded, _ = _load_isolated_bridge(tmp)
            summary2 = bridge_p2_reloaded.restore_persisted_queue(notify=False)
            self.assertEqual(2, summary2["restored"])
            got2 = [bridge_p2_reloaded.job_q.get()[3] for _ in range(2)]
            for _ in range(2):
                bridge_p2_reloaded.job_q.task_done()
            self.assertEqual(["Q2", "Q1"], got2)


class TestHotReloadSelfCheckAndAutoRollback(unittest.TestCase):
    """Verify `--self-check`, pre-exec abort, LKG startup rollback, and sync_live deploy/rollback."""

    def test_self_check_flag_succeeds_without_acquiring_lock_or_mutating_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock_dir = Path(tmp) / "locks"
            state_file = Path(tmp) / "state.json"
            env = {
                **os.environ,
                "AGY_TG_LOCK_DIR": str(lock_dir),
                "AGY_TG_STATE_FILE": str(state_file),
                "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_SELF_CHECK_TOKEN_01",
                "AGY_TG_ALLOWED_CHATS": "111",
                "AGY_TG_ENV_FILE": os.path.join(tmp, "none.env"),
            }
            proc = subprocess.run(
                [sys.executable, str(BRIDGE_DIR / "bridge.py"), "--self-check"],
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(0, proc.returncode, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual("ok", report["status"])
            self.assertFalse(lock_dir.exists() and any(lock_dir.iterdir()))
            self.assertFalse(state_file.exists())

    def test_perform_hot_reload_aborts_on_syntax_error_and_preserves_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _ = _load_isolated_bridge(tmp)
            fake_runtime = Path(tmp) / "runtime_bridge"
            fake_runtime.mkdir()
            # Copy real bridge runtime files to isolated runtime dir
            for pyf in BRIDGE_DIR.glob("*.py"):
                shutil.copy2(pyf, fake_runtime / pyf.name)
            # Corrupt bridge.py syntax on disk
            (fake_runtime / "bridge.py").write_text("def broken(:\n    pass\n", encoding="utf-8")

            reload_flag = Path(tmp) / "reload.flag"
            reload_flag.touch()
            bridge.BRIDGE_RUNTIME_DIR = str(fake_runtime)
            bridge.RELOAD_TRIGGER = str(reload_flag)

            warm_sess = mock.MagicMock()
            with bridge.session_lock:
                bridge._session_pool["111"] = warm_sess

            alerts = []
            with (
                mock.patch.object(bridge.os, "execv") as m_execv,
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: alerts.append(txt) or 1),
            ):
                ok = bridge.perform_hot_reload(notify_chat_id=111)

            self.assertFalse(ok)
            m_execv.assert_not_called()
            warm_sess.close.assert_not_called()
            self.assertFalse(reload_flag.exists(), "RELOAD_TRIGGER must be cleared to prevent spin")
            self.assertTrue(any("前置自检失败" in a for a in alerts))

    def test_startup_crash_triggers_lkg_auto_rollback_and_respects_attempt_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _ = _load_isolated_bridge(tmp)
            fake_runtime = Path(tmp) / "runtime_bridge"
            fake_runtime.mkdir()
            (fake_runtime / "bridge.py").write_text("# broken new version\nVERSION = 'bad'\n", encoding="utf-8")
            lkg_dir = Path(tmp) / "rollback_lkg"
            lkg_dir.mkdir()
            (lkg_dir / "bridge.py").write_text("# stable LKG version\nVERSION = 'good'\n", encoding="utf-8")

            bridge.BRIDGE_RUNTIME_DIR = str(fake_runtime)
            bridge.ROLLBACK_DIR = str(lkg_dir)
            bridge._write_reload_breadcrumb(
                {
                    "attempt": 1,
                    "ts": time.time(),
                    "lkg_dir": str(lkg_dir),
                    "notify_chat_id": 111,
                    "notify_thread_id": None,
                    "rollback_attempted": False,
                    "rollback_count": 0,
                    "seen_in_main": False,
                }
            )

            alerts = []
            with (
                mock.patch.object(bridge, "_acquire_instance_lock"),
                mock.patch.object(bridge.signal, "signal"),
                mock.patch.object(bridge, "_init_bot_identity", side_effect=RuntimeError("boom_in_startup")),
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: alerts.append(txt) or 1),
                mock.patch.object(bridge.os, "execv", side_effect=SystemExit(99)) as m_execv,
            ):
                with self.assertRaises(SystemExit) as cm:
                    bridge.main()
                self.assertEqual(99, cm.exception.code)

            m_execv.assert_called_once()
            # Runtime bridge.py must now be restored to LKG stable content
            self.assertIn("VERSION = 'good'", (fake_runtime / "bridge.py").read_text(encoding="utf-8"))
            self.assertTrue(any("已自动回滚至上一稳定版本" in a for a in alerts))

            # Breadcrumb now marks rollback_attempted=True; second failure must NOT loop forever!
            crumb_after = bridge._read_reload_breadcrumb()
            self.assertTrue(crumb_after["rollback_attempted"])
            self.assertEqual(1, crumb_after["rollback_count"])
            with self.assertRaises(RuntimeError):
                bridge._perform_lkg_rollback(crumb_after, "second_failure")

    def test_sync_live_deploy_backup_lkg_auto_rollback_and_manual_rollback(self):
        if not (SCRIPTS_DIR / "sync_live.py").is_file():
            self.skipTest("scripts/sync_live.py is private-only and absent in public export")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_repo = root / "repo"
            fake_home = root / "home"
            live_bridge = fake_home / "agy-tg-bridge"
            backup_root = fake_home / ".gemini/antigravity-cli/cache/deploy_backups"
            live_bridge.mkdir(parents=True)

            # Seed fake repo with minimal valid files matching subset of MAPPINGS
            (fake_repo / "bridge").mkdir(parents=True)
            for fname in ("bridge.py", "memory_guard.py", "formatting.py", "access_control.py", "model_failover.py", "cost_usage.py", "scheduler.py", "bot_bus.py", "bot_bus_mcp.py", "github_webhook.py", "gateway_adapter.py", "studio_ipc.py", "google_accounts.py", "bot_profiles.py", "claude_mem_mcp_proxy.py"):
                shutil.copy2(BRIDGE_DIR / fname, fake_repo / "bridge" / fname)

            # Seed pre-existing live files (version v1)
            for fname in ("bridge.py", "memory_guard.py"):
                (live_bridge / fname).write_text(f"# LIVE_V1_{fname}\nVERSION = 'v1'\n", encoding="utf-8")

            env_patch = {
                "AGY_LIVE_HOME": str(fake_home),
                "AGY_DEPLOY_BACKUP_DIR": str(backup_root),
                "AGY_DEPLOY_BACKUP_KEEP": "5",
            }
            with mock.patch.dict(os.environ, env_patch, clear=False):
                import sync_live  # noqa: E402

                importlib.reload(sync_live)
                sync_live.REPO_ROOT = fake_repo
                sync_live.HOME = fake_home
                sync_live.MAPPINGS = [
                    ("bridge/bridge.py", live_bridge / "bridge.py", "file", True),
                    ("bridge/memory_guard.py", live_bridge / "memory_guard.py", "file", True),
                    ("bridge/formatting.py", live_bridge / "formatting.py", "file", True),
                    ("bridge/access_control.py", live_bridge / "access_control.py", "file", True),
                    ("bridge/model_failover.py", live_bridge / "model_failover.py", "file", True),
                    ("bridge/cost_usage.py", live_bridge / "cost_usage.py", "file", True),
                    ("bridge/scheduler.py", live_bridge / "scheduler.py", "file", True),
                    ("bridge/bot_bus.py", live_bridge / "bot_bus.py", "file", True),
                    ("bridge/bot_bus_mcp.py", live_bridge / "bot_bus_mcp.py", "file", True),
                    ("bridge/github_webhook.py", live_bridge / "github_webhook.py", "file", True),
                    ("bridge/gateway_adapter.py", live_bridge / "gateway_adapter.py", "file", True),
                    ("bridge/studio_ipc.py", live_bridge / "studio_ipc.py", "file", True),
                    ("bridge/google_accounts.py", live_bridge / "google_accounts.py", "file", True),
                    ("bridge/bot_profiles.py", live_bridge / "bot_profiles.py", "file", True),
                    ("bridge/claude_mem_mcp_proxy.py", live_bridge / "claude_mem_mcp_proxy.py", "file", True),
                ]

                # 1. Pre-deploy py_compile failure aborts before modifying live
                (fake_repo / "bridge" / "formatting.py").write_text("def bad(:\n", encoding="utf-8")
                ns = type("Args", (), {"systemd": False, "reload_bridges": False, "no_reload": True, "verify": False, "verify_timeout": 5})()
                with mock.patch.object(sync_live, "audit_secrets", return_value=0):
                    rc_bad = sync_live.cmd_deploy(ns)
                self.assertEqual(1, rc_bad)
                self.assertIn("LIVE_V1_bridge.py", (live_bridge / "bridge.py").read_text(encoding="utf-8"))

                # Restore valid formatting.py, test successful non-blocking deploy + LKG + snapshot
                shutil.copy2(BRIDGE_DIR / "formatting.py", fake_repo / "bridge" / "formatting.py")
                with (
                    mock.patch.object(sync_live, "audit_secrets", return_value=0),
                    mock.patch.object(sync_live, "_touch_reload_sentinels") as m_touch,
                ):
                    ns.no_reload = False
                    rc_ok = sync_live.cmd_deploy(ns)
                self.assertEqual(0, rc_ok)
                m_touch.assert_called_once()
                # Pre-deploy LKG must still contain V1!
                self.assertIn("LIVE_V1_bridge.py", (live_bridge / ".rollback/lkg/bridge.py").read_text(encoding="utf-8"))
                snaps = sorted(backup_root.iterdir())
                self.assertEqual(1, len(snaps))

                # 2. Post-deploy --self-check failure automatically rolls back live files in-place!
                (fake_repo / "bridge" / "memory_guard.py").write_text(
                    (BRIDGE_DIR / "memory_guard.py").read_text(encoding="utf-8") + "\nraise RuntimeError('import_fail')\n",
                    encoding="utf-8",
                )
                with (
                    mock.patch.object(sync_live, "audit_secrets", return_value=0),
                    mock.patch.object(sync_live, "_touch_reload_sentinels") as m_touch2,
                ):
                    ns.no_reload = True
                    rc_fail = sync_live.cmd_deploy(ns)
                self.assertEqual(1, rc_fail)
                m_touch2.assert_not_called()
                # Live memory_guard.py must have been restored to the valid pre-deploy version (not the crashing import_fail one!)
                self.assertNotIn("import_fail", (live_bridge / "memory_guard.py").read_text(encoding="utf-8"))

                # 3. Manual rollback restores V1 from first snapshot
                rb_args = type("RbArgs", (), {"list": False, "to": snaps[0].name, "no_reload": True})()
                rc_rb = sync_live.cmd_rollback(rb_args)
                self.assertEqual(0, rc_rb)
                self.assertIn("LIVE_V1_bridge.py", (live_bridge / "bridge.py").read_text(encoding="utf-8"))

    def test_worker_continues_consuming_after_failed_reload_self_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _ = _load_isolated_bridge(tmp)
            bridge.RELOAD_TRIGGER = os.path.join(tmp, "nonexistent_reload.flag")

            consumed_prompts = []
            second_done = threading.Event()

            def _fake_run_agy(chat_id, prompt, **kw):
                consumed_prompts.append((chat_id, prompt))
                if prompt == "after failed reload":
                    second_done.set()

            def _fake_reload(**kw):
                # First call fails pre-exec self-check (returns False); second exits test worker cleanly
                return len(consumed_prompts) > 0

            with (
                mock.patch.object(bridge, "perform_hot_reload", side_effect=_fake_reload),
                mock.patch.object(bridge, "run_agy", side_effect=_fake_run_agy),
            ):
                t = threading.Thread(target=bridge.worker, daemon=True)
                t.start()

                bridge.job_q.put((111, None, "111", "__RELOAD__"))
                bridge.job_q.put((111, None, "111", "after failed reload"))
                self.assertTrue(second_done.wait(timeout=3.0), "Worker thread exited instead of continuing after failed reload")

                # Cleanly terminate the test worker thread
                bridge.job_q.put((111, None, "111", "__RELOAD__"))
                t.join(timeout=3.0)

            self.assertEqual([(111, "after failed reload")], consumed_prompts)
            self.assertFalse(t.is_alive())

    def test_c9b_sync_live_dual_hooks_canary_zero_write_abort_auto_rollback_and_verify_hooks(self):
        """C9b: Pre-deploy canary aborts with 0 bytes written; post-deploy failure auto-rollbacks; verify-hooks is read-only."""
        if not (SCRIPTS_DIR / "sync_live.py").is_file():
            self.skipTest("scripts/sync_live.py is private-only and absent in public export")
        with tempfile.TemporaryDirectory(prefix="sync_live_c9b_") as tmp:
            root = Path(tmp)
            fake_repo = root / "repo"
            fake_home = root / "home"
            live_hooks_dir = fake_home / ".gemini/config/hooks"
            live_bridge_dir = fake_home / "agy-tg-bridge"
            backup_root = fake_home / ".gemini/antigravity-cli/cache/deploy_backups"
            live_hooks_dir.mkdir(parents=True)
            live_bridge_dir.mkdir(parents=True)
            (fake_repo / "hooks").mkdir(parents=True)
            (fake_repo / "bridge").mkdir(parents=True)

            # Seed repo candidate hooks + memory_guard
            shutil.copy2(REPO_ROOT / "hooks/hooks.json", fake_repo / "hooks/hooks.json")
            shutil.copy2(REPO_ROOT / "hooks/taint_outbound_guard.py", fake_repo / "hooks/taint_outbound_guard.py")
            shutil.copy2(BRIDGE_DIR / "memory_guard.py", fake_repo / "bridge/memory_guard.py")

            # Seed pre-existing live hooks (V1)
            live_hooks_json = fake_home / ".gemini/config/hooks.json"
            live_guard_py = live_hooks_dir / "taint_outbound_guard.py"
            v1_hooks_content = json.dumps({"taint-outbound-guard": {"enabled": False, "PreToolUse": []}}, indent=2) + "\n"
            v1_guard_content = "# LIVE_V1_GUARD\nprint('')\n"
            live_hooks_json.write_text(v1_hooks_content, encoding="utf-8")
            live_guard_py.write_text(v1_guard_content, encoding="utf-8")

            env_patch = {
                "AGY_LIVE_HOME": str(fake_home),
                "AGY_DEPLOY_BACKUP_DIR": str(backup_root),
                "AGY_DEPLOY_BACKUP_KEEP": "5",
            }
            with mock.patch.dict(os.environ, env_patch, clear=False):
                import sync_live  # noqa: E402

                importlib.reload(sync_live)
                sync_live.REPO_ROOT = fake_repo
                sync_live.HOME = fake_home
                sync_live.MAPPINGS = [
                    ("hooks/hooks.json", live_hooks_json, "file", True),
                    ("hooks/taint_outbound_guard.py", live_guard_py, "file", True),
                    ("bridge/memory_guard.py", live_bridge_dir / "memory_guard.py", "file", True),
                ]

                ns = type(
                    "Args",
                    (),
                    {"systemd": False, "reload_bridges": False, "no_reload": True, "verify": False, "verify_timeout": 5},
                )()

                # 1. Pre-deploy isolated canary FAILS -> exit != 0, 0 bytes written to ~/.gemini/config/
                pre_fail_res = {"status": "fail", "ok": False, "summary": "candidate emitted {}"}
                with (
                    mock.patch.object(sync_live, "audit_secrets", return_value=0),
                    mock.patch.object(sync_live, "_run_hooks_canary", return_value=pre_fail_res) as m_canary,
                ):
                    rc_pre = sync_live.cmd_deploy(ns)
                self.assertEqual(1, rc_pre)
                m_canary.assert_called_once()
                self.assertFalse(m_canary.call_args.kwargs["live_mode"])
                # Strictly 0 bytes written to live ~/.gemini/config/
                self.assertEqual(v1_hooks_content, live_hooks_json.read_text(encoding="utf-8"))
                self.assertEqual(v1_guard_content, live_guard_py.read_text(encoding="utf-8"))
                self.assertFalse((live_bridge_dir / "memory_guard.py").exists())

                # 2. Pre-deploy passes, Post-deploy live canary FAILS -> auto-rollback restores V1 completely!
                canary_seq = [
                    {"status": "pass", "ok": True, "summary": "pre ok"},
                    {"status": "fail", "ok": False, "summary": "live hooks broken"},
                ]
                with (
                    mock.patch.object(sync_live, "audit_secrets", return_value=0),
                    mock.patch.object(sync_live, "_run_hooks_canary", side_effect=canary_seq) as m_canary2,
                    mock.patch.object(sync_live, "_touch_reload_sentinels") as m_touch,
                ):
                    rc_post = sync_live.cmd_deploy(ns)
                self.assertEqual(1, rc_post)
                self.assertEqual(2, m_canary2.call_count)
                self.assertFalse(m_canary2.call_args_list[0].kwargs["live_mode"])
                self.assertTrue(m_canary2.call_args_list[1].kwargs["live_mode"])
                m_touch.assert_not_called()
                # Restored to exact V1 contents & newly deployed bridge/memory_guard.py removed!
                self.assertEqual(v1_hooks_content, live_hooks_json.read_text(encoding="utf-8"))
                self.assertEqual(v1_guard_content, live_guard_py.read_text(encoding="utf-8"))
                self.assertFalse((live_bridge_dir / "memory_guard.py").exists())

                # 3. `verify-hooks` (both --candidate and default live mode) is strictly read-only & reports disabled state
                disabled_live_res = {
                    "status": "disabled",
                    "ok": True,
                    "mode": "live",
                    "guard_enabled": False,
                    "hooks_json": str(live_hooks_json),
                    "agy_version": "1.5.14",
                    "summary": "[DISABLED] taint-outbound-guard.enabled=false",
                    "cases": [{"name": "tainted_blocked_deny", "status": "disabled", "duration_s": 0.0}],
                }
                vh_live_args = type("VH", (), {"candidate": False, "require_enabled": False, "agy_bin": None, "json": True})()
                import io as _io
                import contextlib as _ctx
                buf = _io.StringIO()
                with (
                    mock.patch.object(sync_live, "_run_hooks_canary", return_value=disabled_live_res),
                    _ctx.redirect_stdout(buf),
                ):
                    rc_vh = sync_live.cmd_verify_hooks(vh_live_args)
                self.assertEqual(0, rc_vh)
                parsed_vh = json.loads(buf.getvalue())
                self.assertEqual("disabled", parsed_vh["status"])
                self.assertFalse(parsed_vh["guard_enabled"])
                # Zero writes to live hooks.json
                self.assertEqual(v1_hooks_content, live_hooks_json.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
