#!/usr/bin/env python3
"""Unit tests for Coordinator Bot Bus role separation and non-blocking async dispatch."""

from __future__ import annotations

import importlib
import json
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


class TestBotBusTeamWorkflow(unittest.TestCase):
    """Verify non-blocking coordinator dispatch defaults, role config, and worker envelope."""

    def _load_isolated_bus(self, bus_dir: str):
        env_patch = {
            "AGY_BOT_BUS_DIR": bus_dir,
            "AGY_BOT_BUS_ENABLE": "1",
            "AGY_BOT_BUS_ROLE": "coordinator",
            "AGY_BOT_HANDLE": "bot_one",
            "AGY_BOT_CHAT_ID": "123456789",
            "AGY_BOT_SCOPE_KEY": "dm:123456789",
            "AGY_BOT_CHAIN": "",
            "AGY_BOT_ORIGIN_MSG_ID": "0",
            "AGY_BOT_MENTION_HOP": "0",
        }
        with mock.patch.dict(os.environ, env_patch, clear=False):
            import bot_bus  # noqa: E402
            import bot_bus_mcp  # noqa: E402

            importlib.reload(bot_bus)
            importlib.reload(bot_bus_mcp)
            return bot_bus, bot_bus_mcp

    def test_team_dispatch_defaults_to_non_blocking_async(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, bot_bus_mcp = self._load_isolated_bus(tmp)
            bot_bus.update_bot_config("bot_one", role="coordinator", specialty="orchestrator")
            bot_bus.update_bot_config("bot_two", role="worker", specialty="developer")
            bot_bus.heartbeat_bot(
                {"handle": "bot_one", "pid": os.getpid(), "role": "coordinator", "busy": False}
            )
            bot_bus.heartbeat_bot(
                {"handle": "bot_two", "pid": os.getpid(), "role": "worker", "busy": False}
            )

            with mock.patch.dict(
                os.environ,
                {
                    "AGY_BOT_BUS_ENABLE": "1",
                    "AGY_BOT_BUS_ROLE": "coordinator",
                    "AGY_BOT_HANDLE": "bot_one",
                    "AGY_BOT_CHAT_ID": "123456789",
                    "AGY_BOT_SCOPE_KEY": "dm:123456789",
                    "AGY_BOT_CHAIN": "",
                    "AGY_BOT_ORIGIN_MSG_ID": "0",
                    "AGY_BOT_MENTION_HOP": "0",
                },
                clear=False,
            ):
                res = bot_bus_mcp._handle_team_dispatch(
                    {"bot": "@bot_two", "prompt": "Implement and publish release"}
                )
            self.assertFalse(res.get("isError"), res)
            payload = json.loads(res["content"][0]["text"])
            self.assertEqual("async", payload["mode"])
            self.assertEqual(1, len(payload["dispatched"]))
            job = bot_bus.get_job(payload["dispatched"][0]["job_id"])
            self.assertIsNotNone(job)
            self.assertTrue(job["wake_on_async"])
            self.assertEqual("queued", job["status"])

    def test_tool_schema_and_instructions_reflect_async_role_division(self):
        with tempfile.TemporaryDirectory() as tmp:
            _bot_bus, bot_bus_mcp = self._load_isolated_bus(tmp)
            with mock.patch.dict(
                os.environ,
                {"AGY_BOT_BUS_ENABLE": "1", "AGY_BOT_BUS_ROLE": "coordinator"},
                clear=False,
            ):
                schemas = {t["name"]: t for t in bot_bus_mcp._tool_schemas()}
            wait_desc = schemas["team_dispatch"]["inputSchema"]["properties"]["wait"]["description"]
            self.assertIn("default false", wait_desc.lower())

            instr = bot_bus_mcp.COORDINATOR_INSTRUCTIONS.lower()
            self.assertIn("wait=false", instr)
            self.assertIn("developer", instr)
            self.assertIn("tester", instr)
            self.assertIn("issues", instr)
            self.assertIn("prs", instr)

    def test_format_worker_envelope_supports_specialty_and_backward_compat(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = self._load_isolated_bus(tmp)
            job = {
                "job_id": "job-test1",
                "from_bot": "bot_one",
                "target_bot": "bot_two",
                "label": "test-task",
                "prompt": "Run checks",
            }
            plain = bot_bus.format_worker_envelope(job, "/home/your-user/agy-workspace", "/tmp/out")
            self.assertNotIn("职责分工：", plain)
            self.assertIn("Run checks", plain)

            with_spec = bot_bus.format_worker_envelope(
                job,
                "/home/your-user/agy-workspace",
                "/tmp/out",
                worker_specialty="coding and release",
            )
            self.assertIn("职责分工：coding and release", with_spec)

    def test_update_bot_config_and_role_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = self._load_isolated_bus(tmp)
            bot_bus.update_bot_config("bot_one", role="coordinator", specialty="dispatch only")
            bot_bus.update_bot_config("bot_two", role="worker", specialty="code and release")
            cfg1 = bot_bus.resolve_bot_config("bot_one")
            cfg2 = bot_bus.resolve_bot_config("bot_two")
            self.assertEqual("coordinator", cfg1["role"])
            self.assertEqual("dispatch only", cfg1["specialty"])
            self.assertEqual("worker", cfg2["role"])
            self.assertEqual("code and release", cfg2["specialty"])


if __name__ == "__main__":
    unittest.main()
