#!/usr/bin/env python3
"""Offline unit tests for `bridge/scheduler.py`:
- Cron expression & macro/alias parsing
- `MIN_CRON_INTERVAL_SECS` safety floor validation
- English & Chinese relative timer parsing + `split_schedule_and_body` flags
- Atomic `TaskManager` CRUD, bot ownership isolation, due-task advancement & completion tracking
- Timezone resolution & countdown formatting
"""

from __future__ import annotations

import datetime
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))

import scheduler  # noqa: E402


class TestCronParsingAndSafetyFloor(unittest.TestCase):
    """Verify cron field parsing, aliases, macros, next occurrence, and 5-min safety floor."""

    def test_cron_fields_aliases_macros_and_errors(self):
        mins, hrs, doms, months, dows, dom_res, dow_res = scheduler.parse_cron_expression(
            "0,30 9-17/2 1,15 jan-mar mon-fri"
        )
        self.assertEqual({0, 30}, mins)
        self.assertEqual({9, 11, 13, 15, 17}, hrs)
        self.assertEqual({1, 15}, doms)
        self.assertEqual({1, 2, 3}, months)
        self.assertEqual({1, 2, 3, 4, 5}, dows)
        self.assertTrue(dom_res)
        self.assertTrue(dow_res)

        # Sunday=7 normalizes to 0; wrap-around DOW fri-mon includes 5,6,0,1
        _, _, _, _, dows_wrap, _, _ = scheduler.parse_cron_expression("0 8 * * fri-mon")
        self.assertEqual({5, 6, 0, 1}, dows_wrap)
        _, _, _, _, dows_sun7, _, _ = scheduler.parse_cron_expression("0 8 * * 7")
        self.assertEqual({0}, dows_sun7)

        # Macros expand properly
        m_daily = scheduler.parse_cron_expression("@daily")
        self.assertEqual(({0}, {0}), (m_daily[0], m_daily[1]))
        m_hourly = scheduler.parse_cron_expression("@HOURLY")
        self.assertEqual(({0}, set(range(24))), (m_hourly[0], m_hourly[1]))

        # Invalid expressions raise ValueError
        for bad in ("* * *", "60 0 * * *", "0 24 * * *", "*/0 * * * *", "0 0 * 13 *", "0 0 * * 1-2-3"):
            with self.subTest(expr=bad):
                with self.assertRaises(ValueError):
                    scheduler.parse_cron_expression(bad)

    def test_min_cron_interval_floor_and_next_occurrence(self):
        tz_utc = datetime.timezone.utc
        probe = datetime.datetime(2026, 3, 1, 10, 0, 0, tzinfo=tz_utc)

        # Sub-5-minute intervals must be rejected
        for too_fast in ("* * * * *", "*/2 * * * *", "*/4 * * * *"):
            with self.subTest(expr=too_fast):
                with self.assertRaises(ValueError):
                    scheduler.validate_cron_min_interval(too_fast, tz_utc, from_dt=probe)

        # Exactly 5-minute interval passes
        nxt = scheduler.validate_cron_min_interval("*/5 * * * *", tz_utc, from_dt=probe)
        self.assertEqual(datetime.datetime(2026, 3, 1, 10, 5, 0, tzinfo=tz_utc), nxt)

        # Local timezone offset check (Asia/Shanghai = UTC+8): 09:00 local == 01:00 UTC
        tz_sh, lbl_sh = scheduler.get_scheduler_tz("Asia/Shanghai")
        self.assertEqual("UTC+8", lbl_sh)
        from_utc = datetime.datetime(2026, 3, 1, 0, 30, 0, tzinfo=tz_utc)  # 08:30 local
        nxt_sh = scheduler.next_cron_occurrence("0 9 * * *", from_utc, tz_sh)
        self.assertEqual(datetime.datetime(2026, 3, 1, 1, 0, 0, tzinfo=tz_utc), nxt_sh)

        # Leap year Feb 29 schedules resolve cleanly
        from_leap = datetime.datetime(2026, 3, 1, 0, 0, 0, tzinfo=tz_utc)
        nxt_leap = scheduler.next_cron_occurrence("15 12 29 2 *", from_leap, tz_utc)
        self.assertEqual(datetime.datetime(2028, 2, 29, 12, 15, 0, tzinfo=tz_utc), nxt_leap)


class TestRelativeTimersAndCommandSplit(unittest.TestCase):
    """Verify English/Chinese relative time parsing and `split_schedule_and_body`."""

    def test_parse_relative_time_english_and_chinese(self):
        base = datetime.datetime(2026, 5, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        cases = {
            "in 30m": datetime.timedelta(minutes=30),
            "in 1h 30m": datetime.timedelta(hours=1, minutes=30),
            "in 2d": datetime.timedelta(days=2),
            "in 15": datetime.timedelta(minutes=15),
            "10分钟": datetime.timedelta(minutes=10),
            "45秒": datetime.timedelta(seconds=45),
            "1小时30分": datetime.timedelta(hours=1, minutes=30),
            "2天": datetime.timedelta(days=2),
        }
        for raw, delta in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(base + delta, scheduler.parse_relative_time(raw, from_dt_utc=base))

        for bad in ("", "0m", "in 0s", "30", "0 9 * * *", "hello world"):
            with self.subTest(bad=bad):
                self.assertIsNone(scheduler.parse_relative_time(bad, from_dt_utc=base))

    def test_split_schedule_and_body_with_flags(self):
        sched, body, opts = scheduler.split_schedule_and_body("--loud -m gemini-2.5-pro --timeout 120 in 30m check logs")
        self.assertEqual("in 30m", sched)
        self.assertEqual("check logs", body)
        self.assertEqual({"silent_if_empty": False, "model": "gemini-2.5-pro", "timeout_secs": 120}, opts)

        sched2, body2, opts2 = scheduler.split_schedule_and_body("--silent */10 * * * * run audit")
        self.assertEqual("*/10 * * * *", sched2)
        self.assertEqual("run audit", body2)
        self.assertEqual({"silent_if_empty": True}, opts2)

        sched3, body3, opts3 = scheduler.split_schedule_and_body("@daily daily digest")
        self.assertEqual("@daily", sched3)
        self.assertEqual("daily digest", body3)
        self.assertEqual({}, opts3)

        with self.assertRaises(ValueError):
            scheduler.split_schedule_and_body("not-a-valid-schedule")


class TestTaskManagerAtomicCRUDAndDispatch(unittest.TestCase):
    """Verify flock-backed TaskManager CRUD, ownership isolation, due triggering & countdowns."""

    def test_crud_toggle_due_dispatch_and_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = scheduler.TaskManager(
                filepath=os.path.join(tmp, "scheduled_tasks.json"),
                lockpath=os.path.join(tmp, "scheduled_tasks.lock"),
            )

            # Create one-shot and recurring cron tasks owned by distinct bot instances
            t_once = mgr.create_task(
                name="OneShot",
                schedule_expr="in 10m",
                task_type="agent",
                payload={"prompt": "ping"},
                target_chat_id=-1001234567890,
                custom_id="task-once-1",
                bot_instance_id="bot-a",
            )
            t_cron = mgr.create_task(
                name="HourlyCheck",
                schedule_expr="0 * * * *",
                task_type="cost_report",
                payload={},
                target_chat_id=-1001234567890,
                custom_id="task-cron-1",
                bot_instance_id="bot-b",
            )
            self.assertEqual("once", t_once["schedule_type"])
            self.assertFalse(t_once["delivery"]["silent_if_empty"])
            self.assertEqual("cron", t_cron["schedule_type"])
            self.assertFalse(t_cron["delivery"]["silent_if_empty"])

            # Ownership filtering
            self.assertEqual(["task-once-1"], [t["id"] for t in mgr.list_tasks(bot_instance_id="bot-a")])
            self.assertEqual(["task-cron-1"], [t["id"] for t in mgr.list_tasks(bot_instance_id="bot-b")])
            self.assertEqual(2, len(mgr.list_tasks()))

            # Toggle enabled & silent flags
            self.assertFalse(mgr.toggle_task("task-once-1", enable=False))
            self.assertTrue(mgr.toggle_task("task-once-1", enable=True))
            self.assertTrue(mgr.toggle_silent("task-cron-1"))

            # Trigger due tasks in the future: once becomes disabled, cron advances next_run_at
            future_utc = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
            due_a = mgr.get_due_tasks(now_utc=future_utc, bot_instance_id="bot-a")
            self.assertEqual(["task-once-1"], [t["id"] for t in due_a])
            after_once = mgr.get_task("task-once-1")
            self.assertFalse(after_once["enabled"])
            self.assertIsNone(after_once["state"]["next_run_at"])

            due_b = mgr.get_due_tasks(now_utc=future_utc, bot_instance_id="bot-b")
            self.assertEqual(["task-cron-1"], [t["id"] for t in due_b])
            after_cron = mgr.get_task("task-cron-1")
            self.assertTrue(after_cron["enabled"])
            nxt_cron = scheduler.parse_iso_utc(after_cron["state"]["next_run_at"])
            self.assertIsNotNone(nxt_cron)
            self.assertGreater(nxt_cron, future_utc)

            # Record completion updates counters & error state
            mgr.record_completion("task-cron-1", "success", last_snippet="ok report")
            done_cron = mgr.get_task("task-cron-1")
            self.assertEqual(1, done_cron["state"]["run_count"])
            self.assertEqual("success", done_cron["state"]["last_status"])
            self.assertEqual("ok report", done_cron["state"]["last_output_snippet"])

            mgr.record_completion("task-once-1", "failed", error="timeout")
            fail_once = mgr.get_task("task-once-1")
            self.assertEqual("failed", fail_once["state"]["last_status"])
            self.assertEqual("timeout", fail_once["state"]["last_error"])

            # Delete task
            self.assertTrue(mgr.delete_task("task-once-1"))
            self.assertFalse(mgr.delete_task("task-once-1"))
            self.assertIsNone(mgr.get_task("task-once-1"))

    def test_countdown_and_tz_formatting(self):
        base = datetime.datetime(2026, 5, 1, 10, 0, 0, tzinfo=datetime.timezone.utc)
        self.assertEqual("无计划", scheduler.format_countdown(None, base))
        self.assertEqual("即将触发", scheduler.format_countdown(base, base))
        self.assertEqual("剩 45s", scheduler.format_countdown(base + datetime.timedelta(seconds=45), base))
        self.assertEqual("剩 12m", scheduler.format_countdown(base + datetime.timedelta(minutes=12), base))
        self.assertEqual("剩 2h5m", scheduler.format_countdown(base + datetime.timedelta(hours=2, minutes=5), base))
        self.assertEqual("剩 3天1h", scheduler.format_countdown(base + datetime.timedelta(days=3, hours=1), base))

        with mock.patch.dict(os.environ, {"AGY_TG_COST_TZ": "UTC"}, clear=False):
            tz, lbl = scheduler.get_scheduler_tz()
            self.assertEqual("UTC", lbl)
            self.assertIsNotNone(tz)

    def test_precheck_cmd_and_handoff_bot_persistence_and_detail_panel(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = scheduler.TaskManager(
                filepath=os.path.join(tmp, "scheduled_tasks.json"),
                lockpath=os.path.join(tmp, "scheduled_tasks.lock"),
            )
            t = mgr.create_task(
                name="RepoWatch",
                schedule_expr="0 * * * *",
                task_type="agent",
                payload={"prompt": "Inspect repo changes"},
                target_chat_id=-1001234567890,
                custom_id="task-watch-1",
                precheck_cmd="  python3 scripts/repo_watch.py --repo example/demo-repo  ",
                handoff_bot="  @Bot_One ",
            )
            self.assertEqual(
                "python3 scripts/repo_watch.py --repo example/demo-repo",
                t["payload"]["precheck_cmd"],
            )
            self.assertEqual("bot_one", t["delivery"]["handoff_bot"])

            # Empty/whitespace optional args omit fields cleanly
            t_plain = mgr.create_task(
                name="PlainTask",
                schedule_expr="in 5m",
                task_type="agent",
                payload={"prompt": "hi"},
                custom_id="task-plain-1",
                precheck_cmd="   ",
                handoff_bot=" @ ",
            )
            self.assertNotIn("precheck_cmd", t_plain["payload"])
            self.assertNotIn("handoff_bot", t_plain["delivery"])

            detail_html = scheduler.format_task_detail(t)
            self.assertIn("@bot_one", detail_html)
            self.assertIn("repo_watch.py --repo example/demo-repo", detail_html)

            with mock.patch.object(scheduler, "task_mgr", mgr):
                panel_html, _ = scheduler.build_schedule_panel(view="detail", selected_task_id="task-watch-1")
            self.assertIn("协同接力", panel_html)
            self.assertIn("@bot_one", panel_html)
            self.assertIn("预检命令", panel_html)


if __name__ == "__main__":
    unittest.main()
