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

    def test_three_state_model_mode_resolution_and_legacy_compat(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = self._load_isolated_bus(tmp)

            # 1. Missing entry -> default mode -> falls back to env_model
            cfg_missing = bot_bus.resolve_bot_config("bot_two", env_model="team/gpt-6.1-sol")
            self.assertEqual(bot_bus.MODEL_MODE_DEFAULT, cfg_missing["model_mode"])
            self.assertEqual("", cfg_missing["configured_model"])
            self.assertEqual("team/gpt-6.1-sol", cfg_missing["env_default_model"])
            self.assertEqual("team/gpt-6.1-sol", cfg_missing["default_model"])

            # 2. Legacy team_config.json without model_mode:
            #    None -> default; "" -> follow; non-empty -> custom
            legacy_cfg = {
                "version": 1,
                "bots": {
                    "bot_none": {"role": "worker", "default_model": None},
                    "bot_follow": {"role": "worker", "default_model": ""},
                    "bot_custom": {"role": "worker", "default_model": "gemini-3.8-flash-low"},
                },
            }
            bot_bus._atomic_write_json(bot_bus.CONFIG_FILE, legacy_cfg)

            c_none = bot_bus.resolve_bot_config("bot_none", env_model="team/gpt-6.1-sol")
            self.assertEqual(bot_bus.MODEL_MODE_DEFAULT, c_none["model_mode"])
            self.assertEqual("team/gpt-6.1-sol", c_none["default_model"])

            c_follow = bot_bus.resolve_bot_config("bot_follow", env_model="team/gpt-6.1-sol")
            self.assertEqual(bot_bus.MODEL_MODE_FOLLOW, c_follow["model_mode"])
            self.assertEqual("", c_follow["configured_model"])
            self.assertEqual("", c_follow["default_model"])

            c_custom = bot_bus.resolve_bot_config("bot_custom", env_model="team/gpt-6.1-sol")
            self.assertEqual(bot_bus.MODEL_MODE_CUSTOM, c_custom["model_mode"])
            self.assertEqual("gemini-3.8-flash-low", c_custom["configured_model"])
            self.assertEqual("gemini-3.8-flash-low", c_custom["default_model"])

            # 3. Explicit set_bot_model_config persists model_mode + model_updated_at
            rec_f = bot_bus.set_bot_model_config("bot_two", bot_bus.MODEL_MODE_FOLLOW)
            self.assertEqual(bot_bus.MODEL_MODE_FOLLOW, rec_f["model_mode"])
            self.assertGreater(rec_f["model_updated_at"], 0)
            res_f = bot_bus.resolve_bot_config("bot_two", env_model="team/gpt-6.1-sol")
            self.assertEqual(bot_bus.MODEL_MODE_FOLLOW, res_f["model_mode"])
            self.assertEqual("", res_f["default_model"])

            rec_c = bot_bus.set_bot_model_config("bot_two", bot_bus.MODEL_MODE_CUSTOM, "claude-opus-5-5-high")
            self.assertEqual(bot_bus.MODEL_MODE_CUSTOM, rec_c["model_mode"])
            res_c = bot_bus.resolve_bot_config("bot_two", env_model="team/gpt-6.1-sol")
            self.assertEqual(bot_bus.MODEL_MODE_CUSTOM, res_c["model_mode"])
            self.assertEqual("claude-opus-5-5-high", res_c["configured_model"])
            self.assertEqual("claude-opus-5-5-high", res_c["default_model"])

            rec_d = bot_bus.set_bot_model_config("bot_two", bot_bus.MODEL_MODE_DEFAULT)
            self.assertEqual(bot_bus.MODEL_MODE_DEFAULT, rec_d["model_mode"])
            self.assertIsNone(rec_d["default_model"])
            res_d = bot_bus.resolve_bot_config("bot_two", env_model="team/gpt-6.1-sol")
            self.assertEqual(bot_bus.MODEL_MODE_DEFAULT, res_d["model_mode"])
            self.assertEqual("team/gpt-6.1-sol", res_d["default_model"])

            # 4. promote_sole_coordinator remains compatible and sets worker custom model
            bot_bus.promote_sole_coordinator("bot_one", worker_default_model="gemini-3.8-flash-low")
            res_w = bot_bus.resolve_bot_config("bot_two", env_model="team/gpt-6.1-sol")
            self.assertEqual("worker", res_w["role"])
            self.assertEqual(bot_bus.MODEL_MODE_CUSTOM, res_w["model_mode"])
            self.assertEqual("gemini-3.8-flash-low", res_w["default_model"])

    def test_merge_bot_view_distinguishes_modes_and_sync_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = self._load_isolated_bus(tmp)
            bot_bus.heartbeat_bot(
                {
                    "handle": "bot_two",
                    "pid": os.getpid(),
                    "role": "worker",
                    "dm_model": "claude-opus-5-5-high",
                    "env_default_model": "team/gpt-6.1-sol",
                    "active_model": "claude-opus-5-5-high",
                }
            )
            bot_bus.heartbeat_bot(
                {
                    "handle": "bot_one",
                    "pid": os.getpid(),
                    "role": "coordinator",
                    "dm_model": "gemini-4-neon-high",
                    "env_default_model": "",
                    "active_model": "gemini-4-neon-high",
                }
            )

            # Default mode: must NOT blindly copy active_model into default_model
            roster = {b["handle"]: b for b in bot_bus.list_roster(include_offline=True)}
            self.assertEqual(bot_bus.MODEL_MODE_DEFAULT, roster["bot_two"]["model_mode"])
            self.assertEqual("team/gpt-6.1-sol", roster["bot_two"]["effective_model"])
            self.assertEqual("team/gpt-6.1-sol", roster["bot_two"]["default_model"])
            self.assertEqual("claude-opus-5-5-high", roster["bot_two"]["dm_model"])

            self.assertEqual(bot_bus.MODEL_MODE_DEFAULT, roster["bot_one"]["model_mode"])
            self.assertEqual("", roster["bot_one"]["effective_model"])
            self.assertEqual("", roster["bot_one"]["default_model"])

            # Follow mode: dynamically tracks heartbeat dm_model, and falls back to env_default_model when DM is empty
            bot_bus.set_bot_model_config("bot_two", bot_bus.MODEL_MODE_FOLLOW)
            roster = {b["handle"]: b for b in bot_bus.list_roster(include_offline=True)}
            self.assertEqual(bot_bus.MODEL_MODE_FOLLOW, roster["bot_two"]["model_mode"])
            self.assertEqual("claude-opus-5-5-high", roster["bot_two"]["effective_model"])
            self.assertEqual("claude-opus-5-5-high", roster["bot_two"]["default_model"])

            bot_bus.heartbeat_bot(
                {
                    "handle": "bot_two",
                    "pid": os.getpid(),
                    "role": "worker",
                    "dm_model": "",
                    "env_default_model": "team/gpt-6.1-sol",
                    "active_model": "team/gpt-6.1-sol",
                }
            )
            roster = {b["handle"]: b for b in bot_bus.list_roster(include_offline=True)}
            self.assertEqual("team/gpt-6.1-sol", roster["bot_two"]["effective_model"])
            self.assertEqual("team/gpt-6.1-sol", roster["bot_two"]["default_model"])

            # Custom mode
            bot_bus.set_bot_model_config("bot_two", bot_bus.MODEL_MODE_CUSTOM, "gemini-3.8-flash-low")
            roster = {b["handle"]: b for b in bot_bus.list_roster(include_offline=True)}
            self.assertEqual(bot_bus.MODEL_MODE_CUSTOM, roster["bot_two"]["model_mode"])
            self.assertEqual("gemini-3.8-flash-low", roster["bot_two"]["configured_model"])
            self.assertEqual("gemini-3.8-flash-low", roster["bot_two"]["effective_model"])
            self.assertEqual("gemini-3.8-flash-low", roster["bot_two"]["default_model"])

            # notify_bot_model_sync delivers sync_group_model packet cleanly
            bot_bus.notify_bot_model_sync(
                "bot_two",
                model_mode=bot_bus.MODEL_MODE_FOLLOW,
                from_bot="bot_one",
                chat_id=-1001234567890,
            )
            pkts = bot_bus.pop_inbox_packets("bot_two")
            self.assertEqual(1, len(pkts))
            self.assertEqual("sync_group_model", pkts[0]["type"])
            self.assertEqual(bot_bus.MODEL_MODE_FOLLOW, pkts[0]["model_mode"])
            self.assertEqual(-1001234567890, pkts[0]["chat_id"])


if __name__ == "__main__":
    unittest.main()
