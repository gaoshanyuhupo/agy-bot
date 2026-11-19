#!/usr/bin/env python3
"""Regression tests for Layer 1/2/3 group-chat Bot Bus collaboration."""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
if str(BRIDGE_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_DIR))


class TestGroupChatBus(unittest.TestCase):
    """Verify worker group speech, shared ledger, cross-process mention loop guard, and routing."""

    def _load_bus(self, bus_dir: str, extra_env: dict[str, str] | None = None):
        env_patch = {
            "AGY_BOT_BUS_DIR": bus_dir,
            "AGY_BOT_BUS_ENABLE": "1",
            "AGY_BOT_BUS_ROLE": "coordinator",
            "AGY_BOT_HANDLE": "bot_one",
            "AGY_BOT_CHAT_ID": "-1001234567890",
            "AGY_BOT_SCOPE_KEY": "-1001234567890",
            "AGY_BOT_CHAIN": "",
            "AGY_BOT_ORIGIN_MSG_ID": "0",
            "AGY_BOT_MENTION_HOP": "0",
        }
        if extra_env:
            env_patch.update(extra_env)
        with mock.patch.dict(os.environ, env_patch, clear=False):
            import bot_bus  # noqa: E402
            import bot_bus_mcp  # noqa: E402

            importlib.reload(bot_bus)
            importlib.reload(bot_bus_mcp)
            return bot_bus, bot_bus_mcp

    def _load_bridge(self, tmp: str, extra_env: dict[str, str] | None = None):
        env_patch = {
            "AGY_BOT_BUS_DIR": tmp,
            "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
            "AGY_TG_WORKDIR": tmp,
            "AGY_TG_ALLOWED_CHATS": "-1001234567890",
            "AGY_TG_BOT_TOKEN": "1234567890:EXAMPLE_TOKEN_FOR_TEST_ONLY",
            "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
            "AGY_BOT_CHAIN": "",
            "AGY_BOT_ORIGIN_MSG_ID": "0",
            "AGY_BOT_MENTION_HOP": "0",
        }
        if extra_env:
            env_patch.update(extra_env)
        with mock.patch.dict(os.environ, env_patch, clear=False):
            import bridge  # noqa: E402

            importlib.reload(bridge)
            return bridge

    def test_worker_mcp_role_restricts_tools_and_group_say_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, bot_bus_mcp = self._load_bus(
                tmp,
                {
                    "AGY_BOT_BUS_ENABLE": "1",
                    "AGY_BOT_BUS_ROLE": "worker",
                    "AGY_BOT_HANDLE": "bot_two",
                    "AGY_BOT_CHAT_ID": "-1001234567890",
                    "AGY_BOT_SCOPE_KEY": "-1001234567890",
                },
            )
            env_worker = {
                "AGY_BOT_BUS_ENABLE": "1",
                "AGY_BOT_BUS_ROLE": "worker",
                "AGY_BOT_HANDLE": "bot_two",
                "AGY_BOT_CHAT_ID": "-1001234567890",
                "AGY_BOT_SCOPE_KEY": "-1001234567890",
            }
            with mock.patch.dict(os.environ, env_worker, clear=False):
                schemas = {t["name"]: t for t in bot_bus_mcp._tool_schemas()}
                self.assertEqual({"team_roster", "group_say"}, set(schemas.keys()))
                self.assertNotIn("team_dispatch", schemas)
                self.assertNotIn("team_job", schemas)

                # Direct call to forbidden dispatch tool must be rejected
                captured: list[dict] = []
                with mock.patch.object(bot_bus_mcp, "_reply_ok", side_effect=lambda _id, r: captured.append(r)):
                    bot_bus_mcp._handle_request(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {"name": "team_dispatch", "arguments": {"bot": "@bot_one", "prompt": "hi"}},
                        }
                    )
                self.assertTrue(captured and captured[0].get("isError"))

                res = bot_bus_mcp._handle_group_say({"message": "进度更新：正在跑测试"})
                self.assertFalse(res.get("isError"), res)
                pkts = bot_bus.pop_inbox_packets("bot_two")
                self.assertEqual(1, len(pkts))
                self.assertEqual("group_say", pkts[0]["type"])
                self.assertEqual(-1001234567890, pkts[0]["chat_id"])
                self.assertEqual("bot_two", pkts[0]["from_bot"])

            # DM chat_id (>0) cannot use group_say
            with mock.patch.dict(
                os.environ,
                {**env_worker, "AGY_BOT_CHAT_ID": "123456789", "AGY_BOT_SCOPE_KEY": "123456789"},
                clear=False,
            ):
                dm_res = bot_bus_mcp._handle_group_say({"message": "hello"})
                self.assertTrue(dm_res.get("isError"))

    def test_extract_at_mentions_ignores_code_emails_and_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = self._load_bus(tmp)
            text = (
                "Check `@foo_bot` and ``@foo_bot`` and ``inline `code` @example_bot`` and ```\n@example_bot\n``` "
                "and user@example.com and https://example.com/@bota; please ask @bot_one and @bot_two!"
            )
            self.assertEqual(["bot_one", "bot_two"], bot_bus.extract_at_mentions(text))

    def test_shared_group_history_dedup_isolation_and_unseen_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = self._load_bus(tmp)
            # DM chat_id (>0) must never enter group ledger
            self.assertIsNone(
                bot_bus.record_group_message(
                    123456789, msg_id=1, sender_handle="alice", is_bot=False, text="private secret"
                )
            )

            # Same human message received by two bots deduplicates by msg_id
            r1 = bot_bus.record_group_message(
                -1001234567890, msg_id=101, sender_handle="alice", is_bot=False, text="大家好，开始讨论方案"
            )
            r2 = bot_bus.record_group_message(
                -1001234567890, msg_id=101, sender_handle="alice", is_bot=False, text="大家好，开始讨论方案"
            )
            self.assertIsNotNone(r1)
            self.assertIsNone(r2)

            bot_bus.record_group_message(
                -1001234567890, msg_id=102, sender_handle="bot_one", sender_role="coordinator", is_bot=True, text="我先拆解任务"
            )
            # Separate Topic thread_id=42 must remain isolated from main thread_id=None
            bot_bus.record_group_message(
                -1001234567890, msg_id=103, thread_id=42, sender_handle="alice", is_bot=False, text="另一个话题"
            )

            unseen_main = bot_bus.get_unseen_group_history(-1001234567890, "bot_two", thread_id=None, advance_cursor=True)
            self.assertEqual(2, len(unseen_main))
            self.assertEqual([], bot_bus.get_unseen_group_history(-1001234567890, "bot_two", thread_id=None, advance_cursor=True))

            # New message arrives -> bot_two sees only the new one
            bot_bus.record_group_message(
                -1001234567890, msg_id=104, sender_handle="alice", is_bot=False, text="@bot_two 你怎么看？"
            )
            env_prompt = bot_bus.format_worker_envelope(
                {
                    "job_id": "job-abc",
                    "from_bot": "bot_one",
                    "target_bot": "bot_two",
                    "label": "review",
                    "prompt": "给出意见",
                    "origin_chat_id": -1001234567890,
                    "origin_msg_id": 999,
                },
                "/tmp/work",
                "/tmp/out",
            )
            self.assertIn("你怎么看", env_prompt)
            self.assertNotIn("另一个话题", env_prompt)
            self.assertNotIn("我先拆解任务", env_prompt)

    def test_cross_process_mention_relay_and_hop_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = self._load_bus(tmp)
            bot_bus.heartbeat_bot(
                {"handle": "bot_one", "pid": os.getpid(), "role": "coordinator", "allowed_chats": [-1001234567890]}
            )
            bot_bus.heartbeat_bot(
                {"handle": "bot_two", "pid": os.getpid(), "role": "worker", "allowed_chats": [-1001234567890]}
            )

            # Without a human anchor, bot->bot mention relay must be blocked
            no_anchor = bot_bus.relay_group_mentions(
                "bot_one", -1001234567890, "ping @bot_two", msg_id=201, source_hop=0
            )
            self.assertEqual([], no_anchor["relayed"])
            self.assertEqual("no_active_human_anchor", no_anchor["blocked_reason"])

            # Anchor by human message (msg_id=200)
            bot_bus.mark_human_group_activity(-1001234567890, msg_id=200)
            hop1 = bot_bus.relay_group_mentions(
                "bot_one", -1001234567890, "请 @bot_two 跟进一下", msg_id=202, source_hop=0, max_hops=2
            )
            self.assertEqual(["bot_two"], hop1["relayed"])
            pkts_two = bot_bus.pop_inbox_packets("bot_two")
            self.assertEqual(1, len(pkts_two))
            self.assertEqual("group_mention", pkts_two[0]["type"])
            self.assertEqual(1, pkts_two[0]["hop"])

            # Simulate separate process reload; hop 2 allowed, hop 3 blocked
            bot_bus_proc2, _ = self._load_bus(tmp, {"AGY_BOT_HANDLE": "bot_two"})
            hop2 = bot_bus_proc2.relay_group_mentions(
                "bot_two", -1001234567890, "我好了 @bot_one 请查收", msg_id=203, source_hop=1, max_hops=2
            )
            self.assertEqual(["bot_one"], hop2["relayed"])
            pkts_one = bot_bus_proc2.pop_inbox_packets("bot_one")
            self.assertEqual(2, pkts_one[0]["hop"])

            hop3 = bot_bus_proc2.relay_group_mentions(
                "bot_one", -1001234567890, "收到 @bot_two 辛苦", msg_id=204, source_hop=2, max_hops=2
            )
            self.assertEqual([], hop3["relayed"])
            self.assertIn("max_hops_reached", hop3["blocked_reason"])

    def test_bridge_long_message_mention_and_fast_chat_classifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_patch = {
                "AGY_BOT_BUS_DIR": tmp,
                "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
                "AGY_TG_WORKDIR": tmp,
                "AGY_TG_ALLOWED_CHATS": "-1001234567890",
                "AGY_TG_BOT_TOKEN": "1234567890:EXAMPLE_TOKEN_FOR_TEST_ONLY",
                "AGY_BOT_CHAIN": "",
            }
            with mock.patch.dict(os.environ, env_patch, clear=False):
                import bridge  # noqa: E402

                importlib.reload(bridge)
                bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})
                long_prefix = "@bot_one " + ("请帮我处理这个长上下文问题，" * 25)
                msg_long = {
                    "chat": {"id": -1001234567890},
                    "text": f"{long_prefix} 以及最后点名 @bot_two 一起看一下",
                }
                self.assertFalse(bridge._should_ignore_group_message(msg_long))

                msg_backtick = {
                    "chat": {"id": -1001234567890},
                    "text": "@bot_one 请把示例里的 `@bot_two` 删掉",
                }
                self.assertTrue(bridge._should_ignore_group_message(msg_backtick))

                # Fast-chat classifier accepts short Q&A and rejects code-edit/heavy tasks
                self.assertTrue(bridge._is_fast_chat_candidate("现在进度怎么样？"))
                self.assertFalse(bridge._is_fast_chat_candidate("请帮我修改 bridge.py 并运行测试"))
                self.assertFalse(bridge._is_fast_chat_candidate("/status"))
                self.assertFalse(bridge._is_fast_chat_candidate("进度?", has_media=True))

    @staticmethod
    def _fake_tg_resp(status_code: int, payload: dict):
        return types.SimpleNamespace(
            status_code=status_code,
            text=json.dumps(payload, ensure_ascii=False),
            json=lambda: payload,
        )

    def test_reply_to_message_id_400_retry_logging_and_non_400_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(tmp)

            # 1. HTTP 400 reply-not-found logs error, strips reply_to_message_id, and retries once
            calls_400: list[dict] = []
            logs_400: list[str] = []
            resps_400 = [
                self._fake_tg_resp(400, {"ok": False, "description": "Bad Request: message to be replied not found"}),
                self._fake_tg_resp(200, {"ok": True, "result": {"message_id": 777}}),
            ]
            with (
                mock.patch.object(bridge, "tg", side_effect=lambda method, **kw: calls_400.append({"method": method, **kw}) or resps_400.pop(0)),
                mock.patch.object(bridge, "log", side_effect=logs_400.append),
            ):
                r = bridge.tg_send_in_route("sendMessage", -1001234567890, text="hi", reply_to_message_id=999)
            self.assertEqual(200, r.status_code)
            self.assertEqual(2, len(calls_400))
            self.assertEqual(999, calls_400[0].get("reply_to_message_id"))
            self.assertNotIn("reply_to_message_id", calls_400[1])
            self.assertTrue(any("reply_to_message_id=999" in m for m in logs_400))

            # 2. HTTP 400 non-reply error (HTML parse entities) must NOT strip reply_to_message_id,
            #    and send() plain-text fallback preserves reply_to_message_id
            calls_html: list[dict] = []
            resps_html = [
                self._fake_tg_resp(400, {"ok": False, "description": "Bad Request: can't parse entities"}),
                self._fake_tg_resp(200, {"ok": True, "result": {"message_id": 778}}),
            ]
            with (
                mock.patch.object(bridge, "tg", side_effect=lambda method, **kw: calls_html.append(kw) or resps_html.pop(0)),
                mock.patch.object(bridge, "log"),
            ):
                mid = bridge.send(-1001234567890, "<b>broken", parse_mode="HTML", reply_to_message_id=999)
            self.assertEqual(778, mid)
            self.assertEqual(2, len(calls_html))
            self.assertEqual(999, calls_html[0].get("reply_to_message_id"))
            self.assertEqual(999, calls_html[1].get("reply_to_message_id"))

            # 3. Non-400 errors (500 / 403) must NOT strip reply_to_message_id or mask status
            calls_500: list[dict] = []
            logs_500: list[str] = []
            with (
                mock.patch.object(
                    bridge,
                    "tg",
                    side_effect=lambda method, **kw: calls_500.append(kw) or self._fake_tg_resp(500, {"ok": False, "description": "Internal Server Error"}),
                ),
                mock.patch.object(bridge, "log", side_effect=logs_500.append),
            ):
                r500 = bridge.tg_send_in_route("sendMessage", -1001234567890, text="hi", reply_to_message_id=999)
            self.assertEqual(500, r500.status_code)
            self.assertEqual(1, len(calls_500))
            self.assertEqual(999, calls_500[0].get("reply_to_message_id"))
            self.assertTrue(any("500" in m for m in logs_500))

            # 4. send_rich() attaches reply_to_message_id only on the first chunk
            rich_calls: list[dict] = []
            with mock.patch.object(
                bridge,
                "tg_send_in_route",
                side_effect=lambda method, chat_id, **kw: rich_calls.append(kw) or self._fake_tg_resp(200, {"ok": True, "result": {"message_id": 800 + len(rich_calls)}}),
            ):
                long_md = ("段落内容 " * 520) + "\n\n" + ("第二段内容 " * 520)
                bridge.send_rich(-1001234567890, long_md, header_html="<b>Header</b>\n\n", reply_to_message_id=555)
            self.assertGreaterEqual(len(rich_calls), 2)
            self.assertEqual(555, rich_calls[0].get("reply_to_message_id"))
            for later in rich_calls[1:]:
                self.assertIsNone(later.get("reply_to_message_id"))

    def test_dm_rejection_and_worker_cannot_spoof_or_broadcast(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, bot_bus_mcp = self._load_bus(
                tmp,
                {
                    "AGY_BOT_BUS_ROLE": "worker",
                    "AGY_BOT_HANDLE": "bot_two",
                    "AGY_BOT_CHAT_ID": "-1001234567890",
                    "AGY_BOT_SCOPE_KEY": "-1001234567890",
                },
            )
            # DM chat_id (>= 0) strictly rejected across ledger / anchor / relay / group_say
            for dm_cid in (0, 123456789):
                self.assertIsNone(
                    bot_bus.record_group_message(dm_cid, msg_id=10, sender_handle="alice", is_bot=False, text="secret")
                )
                self.assertEqual([], bot_bus.get_unseen_group_history(dm_cid, "bot_two"))
                self.assertIsNone(bot_bus.mark_human_group_activity(dm_cid, msg_id=10))
                relay = bot_bus.relay_group_mentions("bot_one", dm_cid, "ping @bot_two", msg_id=11)
                self.assertEqual([], relay["relayed"])
                self.assertEqual("not_group_chat", relay["blocked_reason"])
                with self.assertRaises(ValueError):
                    bot_bus.enqueue_group_say("bot_two", dm_cid, "leak")
            hist_dir = os.path.join(tmp, "group_history")
            self.assertTrue(not os.path.exists(hist_dir) or os.listdir(hist_dir) == [])

            # Worker blocked on all coordinator tools at both tools/list and tools/call
            env_worker = {
                "AGY_BOT_BUS_ENABLE": "1",
                "AGY_BOT_BUS_ROLE": "worker",
                "AGY_BOT_HANDLE": "bot_two",
                "AGY_BOT_CHAT_ID": "-1001234567890",
                "AGY_BOT_SCOPE_KEY": "-1001234567890",
            }
            with mock.patch.dict(os.environ, env_worker, clear=False):
                listed = {t["name"] for t in bot_bus_mcp._tool_schemas()}
                self.assertEqual({"team_roster", "group_say"}, listed)
                for forbidden in ("team_dispatch", "team_job", "team_broadcast"):
                    captured: list[dict] = []
                    with mock.patch.object(bot_bus_mcp, "_reply_ok", side_effect=lambda _id, r: captured.append(r)):
                        bot_bus_mcp._handle_request(
                            {
                                "jsonrpc": "2.0",
                                "id": 9,
                                "method": "tools/call",
                                "params": {"name": forbidden, "arguments": {"message": "x", "bot": "@bot_one", "action": "list"}},
                            }
                        )
                    self.assertTrue(captured and captured[0].get("isError"), forbidden)

                # Even if caller passes spoofed bot/chat_id args, group_say pins sender & bound group
                res = bot_bus_mcp._handle_group_say({"message": "进度更新", "bot": "@bot_one", "chat_id": -123456789})
                self.assertFalse(res.get("isError"), res)
                pkts = bot_bus.pop_inbox_packets("bot_two")
                self.assertEqual(1, len(pkts))
                self.assertEqual("bot_two", pkts[0]["from_bot"])
                self.assertEqual(-1001234567890, pkts[0]["chat_id"])

    def test_origin_context_dynamic_refresh_and_notify_group_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, bot_bus_mcp = self._load_bus(
                tmp,
                {
                    "AGY_BOT_BUS_ROLE": "coordinator",
                    "AGY_BOT_HANDLE": "bot_one",
                    "AGY_BOT_CHAT_ID": "-1001234567890",
                    "AGY_BOT_THREAD_ID": "",
                    "AGY_BOT_SCOPE_KEY": "-1001234567890:42",
                    "AGY_BOT_ORIGIN_MSG_ID": "100",
                    "AGY_BOT_CHAIN": "",
                },
            )
            bot_bus.heartbeat_bot({"handle": "bot_one", "pid": os.getpid(), "role": "coordinator"})
            bot_bus.heartbeat_bot({"handle": "bot_two", "pid": os.getpid(), "role": "worker"})

            # Simulate warm AgySession receiving a newer message on topic 42
            bot_bus.set_origin_context(
                "-1001234567890:42",
                bot_handle="bot_one",
                chat_id=-1001234567890,
                thread_id=42,
                msg_id=555,
                mention_hop=1,
                chain_id="hc-555",
            )
            env_coord = {
                "AGY_BOT_BUS_ENABLE": "1",
                "AGY_BOT_BUS_ROLE": "coordinator",
                "AGY_BOT_HANDLE": "bot_one",
                "AGY_BOT_CHAT_ID": "-1001234567890",
                "AGY_BOT_THREAD_ID": "",
                "AGY_BOT_SCOPE_KEY": "-1001234567890:42",
                "AGY_BOT_ORIGIN_MSG_ID": "100",
                "AGY_BOT_CHAIN": "",
            }
            with mock.patch.dict(os.environ, env_coord, clear=False):
                ctx = bot_bus_mcp._origin_context()
                self.assertEqual(555, ctx["origin_msg_id"])
                self.assertEqual(42, ctx["origin_thread_id"])
                self.assertEqual(-1001234567890, ctx["origin_chat_id"])

                # Default notify_group=True in group chat; explicit notify_group=False respected in job record
                r_def = bot_bus_mcp._handle_team_dispatch({"bot": "@bot_two", "prompt": "check logs"})
                self.assertFalse(r_def.get("isError"), r_def)
                jid_def = json.loads(r_def["content"][0]["text"])["dispatched"][0]["job_id"]
                job_def = bot_bus.get_job(jid_def)
                self.assertTrue(job_def["notify_group"])
                self.assertEqual(555, job_def["origin_msg_id"])

                r_quiet = bot_bus_mcp._handle_team_dispatch({"bot": "@bot_two", "prompt": "silent check", "notify_group": False})
                self.assertFalse(r_quiet.get("isError"), r_quiet)
                jid_quiet = json.loads(r_quiet["content"][0]["text"])["dispatched"][0]["job_id"]
                self.assertFalse(bot_bus.get_job(jid_quiet)["notify_group"])

    def test_human_msg_id_idempotency_mention_caps_and_punctuation_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = self._load_bus(tmp)
            for h in ("bot_one", "bot_two", "bota", "botb", "foo_bot", "example_bot"):
                bot_bus.heartbeat_bot(
                    {"handle": h, "pid": os.getpid(), "role": "worker", "allowed_chats": [-1001234567890]}
                )

            cid_1 = bot_bus.mark_human_group_activity(-1001234567890, msg_id=300)
            r1 = bot_bus.relay_group_mentions("bot_one", -1001234567890, "先看 @bot_two", msg_id=301, source_hop=0)
            self.assertEqual(["bot_two"], r1["relayed"])

            # Second bot observing the same human msg_id=300 must not reset chain_id or relays count
            cid_2 = bot_bus.mark_human_group_activity(-1001234567890, msg_id=300)
            self.assertEqual(cid_1, cid_2)
            # 4 more targets in one message -> MENTION_CHAIN_MAX_RELAYS=4 allows 3 more (1+3=4) and blocks the 4th
            r2 = bot_bus.relay_group_mentions(
                "bot_one",
                -1001234567890,
                "请问 @bota，@botb、@foo_bot 和 @example_bot。",
                msg_id=302,
                source_hop=0,
            )
            self.assertEqual(["bota", "botb", "foo_bot"], r2["relayed"])
            self.assertEqual("chain_relay_cap_reached", r2["blocked_reason"])

            # loop_guard_allow blocks after max_events within window
            for _ in range(3):
                self.assertTrue(bot_bus.loop_guard_allow("mention:-1001234567890", max_events=3, window_sec=60.0))
            self.assertFalse(bot_bus.loop_guard_allow("mention:-1001234567890", max_events=3, window_sec=60.0))

            # Punctuation, case folding, URLs, emails, fenced & inline code
            mentions = bot_bus.extract_at_mentions(
                "请问@Bot_One，然后问@Bot_Two！参见 https://example.com/@bota 和 user@example.com 以及 `@foo_bot` 和 ```py\n@example_bot\n```。"
            )
            self.assertEqual(["bot_one", "bot_two"], mentions)

    def test_should_ignore_group_message_slash_commands_and_worker_bare_messages(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(tmp)
            bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_one", "pid": os.getpid(), "role": "coordinator", "allowed_chats": [-1001234567890]}
            )
            bridge.bot_bus.update_bot_config("bot_two", role="worker")

            # Targeted slash command routing
            self.assertTrue(bridge._should_ignore_group_message({"chat": {"id": -1001234567890}, "text": "/status@bot_one"}))
            self.assertFalse(bridge._should_ignore_group_message({"chat": {"id": -1001234567890}, "text": "/status@bot_two"}))
            # Bare /delegate @bot_two should be ignored by worker so only coordinator handles it
            self.assertTrue(bridge._should_ignore_group_message({"chat": {"id": -1001234567890}, "text": "/delegate @bot_two check tests"}))
            # Bare message without @bot_two is ignored by worker when coordinator is online
            self.assertTrue(bridge._should_ignore_group_message({"chat": {"id": -1001234567890}, "text": "大家好"}))
            # Long message (>250 chars) ending with @bot_two wakes bot_two
            long_msg = ("讨论上下文信息 " * 40) + " 最后麻烦 @bot_two 看下"
            self.assertGreater(len(long_msg), 250)
            self.assertFalse(bridge._should_ignore_group_message({"chat": {"id": -1001234567890}, "text": long_msg}))

    def test_busy_fast_chat_isolation_semaphore_and_readonly_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(tmp)
            bridge.BOT_META.update({"bot_id": 111, "handle": "bot_one", "resolved": True})

            # Classifier boundary checks
            self.assertTrue(bridge._is_fast_chat_candidate("收到，请问这个大概多久？"))
            self.assertTrue(bridge._is_fast_chat_candidate("@bot_one 辛苦了", is_mention=True))
            self.assertFalse(bridge._is_fast_chat_candidate("请 refactor 这个模块"))
            self.assertFalse(bridge._is_fast_chat_candidate("a" * 321, is_mention=True))
            self.assertFalse(bridge._is_fast_chat_candidate("/help"))
            self.assertFalse(bridge._is_fast_chat_candidate("进度如何？", has_media=True))

            # Simulate an active foreground worker turn
            sentinel_sess = object()
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_scope = "-1001234567890"
                bridge.cancel_requested = False
                bridge._session_pool["-1001234567890"] = sentinel_sess
            with bridge.state_lock:
                sc = bridge._ensure_scope_locked("-1001234567890")
                sc["undo_stack"] = ["snap-1"]

            in_fast_ev = threading.Event()
            release_fast_ev = threading.Event()
            captured_cmds: list[list[str]] = []
            captured_envs: list[dict] = []
            sent_replies: list[tuple] = []

            def fake_subproc(cmd, cwd, timeout_s, env=None, shell=False):
                captured_cmds.append(list(cmd))
                captured_envs.append(dict(env or {}))
                in_fast_ev.set()
                release_fast_ev.wait(timeout=5.0)
                return 0, json.dumps({"response": "当前正在处理后台任务，很快好。"}), ""

            with (
                mock.patch.object(bridge, "_run_subprocess_group", side_effect=fake_subproc),
                mock.patch.object(
                    bridge,
                    "send_rich",
                    side_effect=lambda cid, txt, **kw: sent_replies.append((cid, txt, kw)) or (456, txt),
                ),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: 457),
                mock.patch.object(bridge, "save_state", side_effect=AssertionError("fast reply must not call save_state")),
            ):
                bridge.enqueue(-1001234567890, "现在进度怎么样？", origin_msg_id=321, raw_text="现在进度怎么样？")
                self.assertTrue(in_fast_ev.wait(timeout=3.0), "fast reply thread did not start")

                # While fast reply semaphore is held, a 2nd fast-chat candidate must fall back to job_q
                q_before = bridge.job_q.qsize()
                bridge.enqueue(-1001234567890, "还需要多久？", origin_msg_id=322, raw_text="还需要多久？")
                self.assertEqual(q_before + 1, bridge.job_q.qsize())

                release_fast_ev.set()
                # Wait for semaphore release by acquiring & releasing
                acquired = bridge._fast_chat_sem.acquire(timeout=3.0)
                self.assertTrue(acquired)
                bridge._fast_chat_sem.release()

            self.assertEqual(1, len(captured_cmds))
            self.assertNotIn("--dangerously-skip-permissions", captured_cmds[0])
            self.assertIn("--disable-slash-commands", captured_cmds[0])
            self.assertEqual("0", captured_envs[0].get("AGY_BOT_BUS_ENABLE"))
            self.assertEqual("1", captured_envs[0].get("AGY_INTERNAL_OBSERVER"))
            self.assertEqual(1, len(sent_replies))
            self.assertEqual(321, sent_replies[0][2].get("reply_to_message_id"))

            # Main worker state/session/undo remained completely untouched
            with bridge.session_lock:
                self.assertTrue(bridge.turn_running)
                self.assertEqual("-1001234567890", bridge.turn_running_scope)
                self.assertFalse(bridge.cancel_requested)
                self.assertIs(sentinel_sess, bridge._session_pool.get("-1001234567890"))
            self.assertEqual(["snap-1"], bridge.get_scope_value("-1001234567890", "undo_stack"))

            # Exception inside fast reply still releases _fast_chat_sem cleanly
            with (
                mock.patch.object(bridge, "_run_subprocess_group", side_effect=RuntimeError("boom")),
                mock.patch.object(bridge, "send", return_value=458),
            ):
                self.assertTrue(bridge._fast_chat_sem.acquire(blocking=False))
                bridge._run_fast_group_reply(-1001234567890, "进度？", origin_msg_id=323)
                self.assertTrue(bridge._fast_chat_sem.acquire(blocking=False))
                bridge._fast_chat_sem.release()

    def test_concurrent_flock_group_history_writes_and_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = self._load_bus(tmp)
            errors: list[Exception] = []

            def writer(tid_idx: int):
                try:
                    for i in range(10):
                        # Intentional overlapping msg_ids across threads 0..1 to exercise dedup under flock
                        mid = (i + 1) if tid_idx < 2 else (100 * tid_idx + i + 1)
                        bot_bus.record_group_message(
                            -1001234567890,
                            msg_id=mid,
                            sender_handle=f"user{tid_idx}",
                            is_bot=False,
                            text=f"msg {tid_idx}-{i}",
                        )
                        if i % 3 == 0:
                            bot_bus.get_unseen_group_history(-1001234567890, f"reader_{tid_idx % 2}", advance_cursor=True)
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=writer, args=(k,)) for k in range(5)]
            for th in threads:
                th.start()
            for th in threads:
                th.join(timeout=10.0)

            self.assertEqual([], errors)
            hist_path = os.path.join(tmp, "group_history", "-1001234567890.json")
            with open(hist_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            entries = data["entries"]
            # Threads 0 & 1 share msg_ids 1..10 (10 unique), threads 2..4 add 30 unique = 40 total (at GROUP_HISTORY_LIMIT)
            self.assertEqual(40, len(entries))
            seqs = [e["seq"] for e in entries]
            self.assertEqual(sorted(seqs), seqs)
            self.assertEqual(len(set(seqs)), len(seqs))

    def test_shared_ledger_excludes_self_bot_messages_and_advances_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = self._load_bus(tmp)
            bot_bus.record_group_message(
                -1001234567890, msg_id=10, sender_handle="alice", is_bot=False, text="人类需求"
            )
            bot_bus.record_group_message(
                -1001234567890, msg_id=11, sender_handle="bot_one", sender_role="coordinator", is_bot=True, text="bot_one 自己的回复"
            )
            bot_bus.record_group_message(
                -1001234567890, msg_id=12, sender_handle="bot_two", sender_role="worker", is_bot=True, text="bot_two 的协作回复"
            )

            # bot_one sees human + bot_two, never its own message
            unseen_one = bot_bus.get_unseen_group_history(-1001234567890, "bot_one", advance_cursor=True)
            self.assertEqual([10, 12], [e["msg_id"] for e in unseen_one])

            # If only bot_one speaks next, unseen for bot_one is [] AND cursor still advances to seq=4
            bot_bus.record_group_message(
                -1001234567890, msg_id=13, sender_handle="bot_one", sender_role="coordinator", is_bot=True, text="bot_one 自言自语"
            )
            self.assertEqual([], bot_bus.get_unseen_group_history(-1001234567890, "bot_one", advance_cursor=True))
            # Verify cursor advanced to seq 4 so a later bot_two message only returns seq 5
            bot_bus.record_group_message(
                -1001234567890, msg_id=14, sender_handle="bot_two", sender_role="worker", is_bot=True, text="bot_two 新消息"
            )
            unseen_one_next = bot_bus.get_unseen_group_history(-1001234567890, "bot_one", advance_cursor=True)
            self.assertEqual([14], [e["msg_id"] for e in unseen_one_next])

            # Meanwhile bot_two sees bot_one's messages (10, 11, 13) and not its own (12, 14)
            unseen_two = bot_bus.get_unseen_group_history(-1001234567890, "bot_two", advance_cursor=True)
            self.assertEqual([10, 11, 13], [e["msg_id"] for e in unseen_two])

    def test_execute_bus_job_strictly_respects_notify_group_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(tmp)
            bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_one", "pid": os.getpid(), "role": "coordinator", "allowed_chats": [-1001234567890]}
            )
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_two", "pid": os.getpid(), "role": "worker", "allowed_chats": [-1001234567890]}
            )
            bridge.bot_bus.update_bot_config(
                "bot_two", role="worker", mirror_chat_id=-1001234567890, mirror_thread_id=42
            )

            class _FakeProc:
                def __init__(self):
                    self.pid = 99999
                    self.returncode = 0
                    self.stdout = iter(
                        [
                            json.dumps(
                                {
                                    "event": "result",
                                    "result": {
                                        "status": "SUCCESS",
                                        "conversation_id": "conv-silent-1",
                                        "response": "silent job ok",
                                    },
                                }
                            )
                            + "\n"
                        ]
                    )
                    self.stderr = iter([])

                def wait(self, timeout=None):
                    return 0

            for chat_mode in ("conversational", "card"):
                res = bridge.bot_bus.dispatch_assignments(
                    "bot_one",
                    [{"bot": "bot_two", "prompt": "run silent check", "label": "silent-qa", "notify_group": False}],
                    origin_scope_key="-1001234567890:42",
                    origin_chat_id=-1001234567890,
                    origin_thread_id=42,
                    origin_msg_id=888,
                    default_notify_group=True,
                )
                jid = res["jobs"][0]["job_id"]
                tg_calls: list[tuple] = []
                rich_calls: list[tuple] = []

                with (
                    mock.patch.object(bridge, "BUS_CHAT_MODE", chat_mode),
                    mock.patch.object(bridge.subprocess, "Popen", return_value=_FakeProc()),
                    mock.patch.object(
                        bridge, "tg_send_in_route", side_effect=lambda *a, **kw: tg_calls.append((a, kw)) or None
                    ),
                    mock.patch.object(
                        bridge, "send_rich", side_effect=lambda *a, **kw: rich_calls.append((a, kw)) or (999, "x")
                    ),
                    mock.patch.object(bridge, "send_file", side_effect=AssertionError("must not send files silently")),
                ):
                    bridge._execute_bus_job(jid)

                self.assertEqual([], tg_calls, f"mode={chat_mode} leaked tg_send_in_route")
                self.assertEqual([], rich_calls, f"mode={chat_mode} leaked send_rich")
                job_after = bridge.bot_bus.get_job(jid)
                self.assertEqual("done", job_after["status"])
                self.assertEqual("silent job ok", job_after["result_text"])
                self.assertFalse(job_after.get("group_delivered"))

    def test_origin_context_per_bot_isolation_and_warm_mention_hop_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, bot_bus_mcp = self._load_bus(tmp)
            bot_bus.heartbeat_bot(
                {"handle": "bot_one", "pid": os.getpid(), "role": "coordinator", "allowed_chats": [-1001234567890]}
            )
            bot_bus.heartbeat_bot(
                {"handle": "bot_two", "pid": os.getpid(), "role": "worker", "allowed_chats": [-1001234567890]}
            )
            chain_id = bot_bus.mark_human_group_activity(-1001234567890, thread_id=42, msg_id=700)

            # Concurrent bots in the exact same group/topic do not overwrite each other
            bot_bus.set_origin_context(
                "-1001234567890:42",
                bot_handle="bot_one",
                chat_id=-1001234567890,
                thread_id=42,
                msg_id=701,
                mention_hop=0,
                chain_id=chain_id,
            )
            bot_bus.set_origin_context(
                "-1001234567890:42",
                bot_handle="bot_two",
                chat_id=-1001234567890,
                thread_id=42,
                msg_id=702,
                mention_hop=2,
                chain_id=chain_id,
            )

            env_one = {
                "AGY_BOT_BUS_ENABLE": "1",
                "AGY_BOT_BUS_ROLE": "coordinator",
                "AGY_BOT_HANDLE": "bot_one",
                "AGY_BOT_CHAT_ID": "-1001234567890",
                "AGY_BOT_THREAD_ID": "42",
                "AGY_BOT_SCOPE_KEY": "-1001234567890:42",
                "AGY_BOT_ORIGIN_MSG_ID": "100",
                "AGY_BOT_MENTION_HOP": "0",
            }
            env_two_warm = {
                **env_one,
                "AGY_BOT_BUS_ROLE": "worker",
                "AGY_BOT_HANDLE": "bot_two",
                "AGY_BOT_MENTION_HOP": "0",  # frozen spawn-time env on warm AgySession!
            }
            with mock.patch.dict(os.environ, env_one, clear=False):
                ctx_one = bot_bus_mcp._origin_context()
                self.assertEqual(701, ctx_one["origin_msg_id"])
                self.assertEqual(0, ctx_one["mention_hop"])

            with mock.patch.dict(os.environ, env_two_warm, clear=False):
                ctx_two = bot_bus_mcp._origin_context()
                self.assertEqual(702, ctx_two["origin_msg_id"])
                self.assertEqual(2, ctx_two["mention_hop"])
                self.assertEqual(chain_id, ctx_two["chain_id"])

                res = bot_bus_mcp._handle_group_say({"message": "接力回复 @bot_one"})
                self.assertFalse(res.get("isError"), res)
                pkts = bot_bus.pop_inbox_packets("bot_one")  # not delivered yet; check bot_two's outbox
                self.assertEqual([], pkts)
                say_pkts = bot_bus.pop_inbox_packets("bot_two")
                self.assertEqual(1, len(say_pkts))
                self.assertEqual(2, say_pkts[0]["source_hop"])

                relay = bot_bus.relay_group_mentions(
                    "bot_two",
                    -1001234567890,
                    say_pkts[0]["message"],
                    thread_id=42,
                    msg_id=703,
                    source_hop=say_pkts[0]["source_hop"],
                    max_hops=2,
                )
                self.assertEqual([], relay["relayed"])
                self.assertIn("max_hops_reached", relay["blocked_reason"])

            # Resetting mention_hop=0 in origin_context overrides non-zero env var back to 0
            bot_bus.set_origin_context(
                "-1001234567890:42",
                bot_handle="bot_two",
                chat_id=-1001234567890,
                thread_id=42,
                msg_id=705,
                mention_hop=0,
                chain_id=chain_id,
            )
            with mock.patch.dict(os.environ, {**env_two_warm, "AGY_BOT_MENTION_HOP": "2"}, clear=False):
                self.assertEqual(0, bot_bus_mcp._origin_context()["mention_hop"])

    def test_send_failure_does_not_record_ledger_or_relay_mentions(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(tmp)
            bridge.BOT_META.update({"bot_id": 111, "handle": "bot_one", "resolved": True})
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_one", "pid": os.getpid(), "role": "coordinator", "allowed_chats": [-1001234567890]}
            )
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_two", "pid": os.getpid(), "role": "worker", "allowed_chats": [-1001234567890]}
            )
            bridge.bot_bus.mark_human_group_activity(-1001234567890, msg_id=900)

            with (
                mock.patch.object(bridge, "_run_subprocess_group", return_value=(0, json.dumps({"response": "请 @bot_two 看下"}), "")),
                mock.patch.object(bridge, "send_rich", return_value=(None, None)),
            ):
                self.assertTrue(bridge._fast_chat_sem.acquire(blocking=False))
                bridge._run_fast_group_reply(-1001234567890, "进度？", origin_msg_id=900)

            self.assertEqual([], bridge.bot_bus.get_unseen_group_history(-1001234567890, "bot_two"))
            self.assertEqual([], bridge.bot_bus.pop_inbox_packets("bot_two"))

            # Direct call with msg_id=0 is also ignored defensively
            bridge._record_and_relay_bot_group_msg(-1001234567890, 0, None, "hello @bot_two")
            self.assertEqual([], bridge.bot_bus.get_unseen_group_history(-1001234567890, "bot_two"))
            self.assertEqual([], bridge.bot_bus.pop_inbox_packets("bot_two"))

    def test_dm_busy_task_redaction_and_batch_done_group_delivered(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(tmp)
            bridge.BOT_META.update({"bot_id": 111, "handle": "bot_one", "resolved": True})
            bridge.bot_bus.heartbeat_bot({"handle": "bot_one", "pid": os.getpid(), "role": "coordinator"})
            bridge.bot_bus.heartbeat_bot({"handle": "bot_two", "pid": os.getpid(), "role": "worker"})

            # 1. Interactive DM scope must be redacted
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_scope = "987654321"
                bridge.turn_running_chat = 987654321
                bridge._active_bus_job_id = None
            busy, desc, _ = bridge._describe_active_busy_task()
            self.assertTrue(busy)
            self.assertNotIn("987654321", desc)
            self.assertIn("私聊", desc)

            # 2. Bus job originating from DM must redact both chat_id and private label
            res = bridge.bot_bus.dispatch_assignments(
                "bot_one",
                [{"bot": "bot_two", "prompt": "secret dm task", "label": "机密私聊标题"}],
                origin_scope_key="987654321",
                origin_chat_id=987654321,
                default_notify_group=False,
            )
            jid = res["jobs"][0]["job_id"]
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_scope = f"bus:{jid}"
                bridge.turn_running_chat = 987654321
                bridge._active_bus_job_id = jid
            busy2, desc2, _ = bridge._describe_active_busy_task()
            self.assertTrue(busy2)
            self.assertNotIn("987654321", desc2)
            self.assertNotIn("机密私聊标题", desc2)
            self.assertIn("私聊", desc2)
            with bridge.session_lock:
                bridge.turn_running = False
                bridge.turn_running_scope = None
                bridge.turn_running_chat = None
                bridge._active_bus_job_id = None

            # 3. summarize_job_brief exposes group_delivered
            bridge.bot_bus.update_job(jid, group_delivered=True)
            finished = bridge.bot_bus.finish_job(jid, status="done", result_text="done")
            brief = bridge.bot_bus.summarize_job_brief(finished)
            self.assertTrue(brief["group_delivered"])

    def test_album_real_msg_id_out_of_order_anchor_fast_reply_ctx_and_400_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(tmp)
            bridge.BOT_META.update({"bot_id": 111, "handle": "bot_one", "resolved": True})

            # 1. Out-of-order lagging human message must not regress human_msg_id anchor
            c_new = bridge.bot_bus.mark_human_group_activity(-1001234567890, msg_id=500)
            c_old = bridge.bot_bus.mark_human_group_activity(-1001234567890, msg_id=450)
            self.assertEqual(c_new, c_old)

            # 2. _flush_album passes real first_msg_id instead of 0
            bridge.ALLOWED_USERS = set()
            bridge._note_poll_album_batch(
                [
                    {
                        "message": {
                            "message_id": 612,
                            "chat": {"id": -1001234567890},
                            "from": {"id": 42, "username": "alice", "is_bot": False},
                            "media_group_id": "mg-1",
                            "photo": [{"file_id": "f1"}],
                            "caption": "看看这两张图",
                        }
                    },
                    {
                        "message": {
                            "message_id": 613,
                            "chat": {"id": -1001234567890},
                            "from": {"id": 42, "username": "alice", "is_bot": False},
                            "media_group_id": "mg-1",
                            "photo": [{"file_id": "f2"}],
                        }
                    },
                ]
            )
            akey = "-1001234567890:mg-1"
            with bridge._album_lock:
                bridge._album_buffers[akey]["batch_pending"] = 0
                bridge._album_buffers[akey]["items"] = [{"dest": "/tmp/a.jpg", "rel": "a.jpg"}]
                bridge._album_buffers[akey]["captions"] = ["看看这两张图"]

            enq_calls: list[dict] = []
            with (
                mock.patch.object(bridge, "send", return_value=700),
                mock.patch.object(bridge, "enqueue", side_effect=lambda *a, **kw: enq_calls.append(kw)),
            ):
                bridge._flush_album(akey)
            self.assertEqual(1, len(enq_calls))
            self.assertEqual(612, enq_calls[0]["origin_msg_id"])
            unseen_album = bridge.bot_bus.get_unseen_group_history(-1001234567890, "bot_two")
            self.assertEqual([612], [e["msg_id"] for e in unseen_album])

            # 3. Fast reply preserves reply context and uses scope workdir
            scope_dir = os.path.join(tmp, "custom_scope_dir")
            os.makedirs(scope_dir, exist_ok=True)
            with bridge.state_lock:
                sc = bridge._ensure_scope_locked("-1001234567890")
                sc["workdir"] = scope_dir
            with bridge.session_lock:
                bridge.turn_running = True
                bridge.turn_running_scope = "-1001234567890"
            captured_fast: list[tuple] = []

            def fake_fast_subproc(cmd, cwd, timeout_s, env=None, shell=False):
                captured_fast.append((cmd, cwd))
                return 0, json.dumps({"response": "快答收到"}), ""

            with (
                mock.patch.object(bridge, "_run_subprocess_group", side_effect=fake_fast_subproc),
                mock.patch.object(bridge, "send_rich", return_value=(701, "ok")),
            ):
                bridge.enqueue(
                    -1001234567890,
                    "[引用回复自 alice]:\n> 上文内容\n\n现在进度如何？",
                    origin_msg_id=620,
                    raw_text="现在进度如何？",
                )
                self.assertTrue(bridge._fast_chat_sem.acquire(timeout=3.0))
                bridge._fast_chat_sem.release()
            with bridge.session_lock:
                bridge.turn_running = False
                bridge.turn_running_scope = None

            self.assertEqual(1, len(captured_fast))
            self.assertEqual(os.path.realpath(scope_dir), captured_fast[0][1])
            self.assertIn("[引用回复自 alice]:", captured_fast[0][0][-1])

            # 4. tg_send_in_route 400 "reply message not found" strips reply_to_message_id and retries
            calls_rmnf: list[dict] = []
            resps_rmnf = [
                self._fake_tg_resp(400, {"ok": False, "description": "Bad Request: reply message not found"}),
                self._fake_tg_resp(200, {"ok": True, "result": {"message_id": 779}}),
            ]
            with (
                mock.patch.object(bridge, "tg", side_effect=lambda method, **kw: calls_rmnf.append(kw) or resps_rmnf.pop(0)),
                mock.patch.object(bridge, "log"),
            ):
                r_rmnf = bridge.tg_send_in_route("sendMessage", -1001234567890, text="hi", reply_to_message_id=999)
            self.assertEqual(200, r_rmnf.status_code)
            self.assertEqual(2, len(calls_rmnf))
            self.assertNotIn("reply_to_message_id", calls_rmnf[1])

    def test_scheduled_handoff_bus_self_guard_overnight_and_rate_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            bot_bus, _ = self._load_bus(tmp)
            bot_bus.heartbeat_bot(
                {"handle": "bot_one", "pid": os.getpid(), "role": "coordinator", "allowed_chats": [-1001234567890]}
            )
            bot_bus.heartbeat_bot(
                {"handle": "bot_two", "pid": os.getpid(), "role": "worker", "allowed_chats": [-1001234567890]}
            )

            # 1. Self-handoff blocked (explicit handle and role alias)
            self_res = bot_bus.enqueue_scheduled_handoff(
                "bot_one", "@bot_one", chat_id=-1001234567890, task_id="t-self", task_name="Self"
            )
            self.assertFalse(self_res["enqueued"])
            self.assertEqual("self_handoff", self_res["reason"])

            self_role = bot_bus.enqueue_scheduled_handoff(
                "bot_one", "coordinator", chat_id=-1001234567890, task_id="t-self2", task_name="SelfRole"
            )
            self.assertFalse(self_role["enqueued"])
            self.assertEqual("self_handoff", self_role["reason"])

            # 2. Overnight handoff succeeds with zero human activity anchor
            res1 = bot_bus.enqueue_scheduled_handoff(
                "bot_two",
                "@bot_one",
                chat_id=-1001234567890,
                thread_id=12,
                msg_id=501,
                task_id="t-watch",
                task_name="HourlyWatch",
                text_excerpt="New Issue #1",
            )
            self.assertTrue(res1["enqueued"], res1)
            res2 = bot_bus.enqueue_scheduled_handoff(
                "bot_two",
                "coordinator",
                chat_id=-1001234567890,
                thread_id=12,
                msg_id=502,
                task_id="t-watch",
                task_name="HourlyWatch",
                text_excerpt="New PR #2",
            )
            self.assertTrue(res2["enqueued"], res2)

            # 3. Third handoff for same (task_id, to_bot) within 300s is rate-limited
            res3 = bot_bus.enqueue_scheduled_handoff(
                "bot_two",
                "@bot_one",
                chat_id=-1001234567890,
                thread_id=12,
                msg_id=503,
                task_id="t-watch",
                task_name="HourlyWatch",
                text_excerpt="Spam",
            )
            self.assertFalse(res3["enqueued"])
            self.assertEqual("rate_limited", res3["reason"])

            pkts = bot_bus.pop_inbox_packets("bot_one")
            self.assertEqual(2, len(pkts))
            self.assertEqual("scheduled_handoff", pkts[0]["type"])
            self.assertEqual(12, pkts[0]["thread_id"])
            self.assertEqual("t-watch", pkts[0]["task_id"])

    def test_bridge_scheduled_precheck_no_handoff_and_receiver_lane(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(
                tmp,
                {"AGY_BOT_HANDLE": "bot_two", "AGY_BOT_BUS_ROLE": "worker"},
            )
            bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_one", "pid": os.getpid(), "role": "coordinator", "allowed_chats": [-1001234567890]}
            )
            bridge.bot_bus.heartbeat_bot(
                {"handle": "bot_two", "pid": os.getpid(), "role": "worker", "allowed_chats": [-1001234567890]}
            )

            mgr = bridge.scheduler.TaskManager(
                filepath=os.path.join(tmp, "scheduled_tasks.json"),
                lockpath=os.path.join(tmp, "scheduled_tasks.lock"),
            )
            task_agent = mgr.create_task(
                name="RepoWatch",
                schedule_expr="0 * * * *",
                task_type="agent",
                payload={"prompt": "Check repo", "precheck_cmd": "python3 scripts/repo_watch.py --repo example/demo-repo"},
                target_chat_id=-1001234567890,
                custom_id="task-watch-agent",
                handoff_bot="@bot_one",
            )

            # 1. Precheck [SILENT] skips AGY_BIN completely
            subproc_calls = []
            with (
                mock.patch.object(bridge.scheduler, "task_mgr", mgr),
                mock.patch.object(
                    bridge,
                    "_run_subprocess_group",
                    side_effect=lambda cmd, **kw: subproc_calls.append((cmd, kw)) or (0, "[SILENT]\n", ""),
                ),
                mock.patch.object(bridge, "send_rich") as send_rich_mock,
            ):
                bridge.execute_scheduled_task(task_agent)
            self.assertEqual(1, len(subproc_calls))
            self.assertTrue(subproc_calls[0][1]["shell"])
            send_rich_mock.assert_not_called()
            self.assertEqual("[SILENT] via precheck", mgr.get_task("task-watch-agent")["state"]["last_output_snippet"])
            self.assertEqual([], bridge.bot_bus.pop_inbox_packets("bot_one"))

            # 2. Precheck delta + [NO_HANDOFF] strips marker, sends group msg, writes ledger, does NOT wake bot_one
            subproc_calls.clear()
            sent_texts = []

            def fake_subproc_no_handoff(cmd, **kw):
                subproc_calls.append(cmd)
                if kw.get("shell"):
                    return 0, "[REPO_WATCH_DELTA repo=example/demo-repo tier=info]\n[NO_HANDOFF_RECOMMENDED]\n- Stars: 1->2", ""
                return 0, json.dumps({"response": "[NO_HANDOFF]\n⭐ Star +1 (1 -> 2)"}), ""

            with (
                mock.patch.object(bridge.scheduler, "task_mgr", mgr),
                mock.patch.object(bridge, "_run_subprocess_group", side_effect=fake_subproc_no_handoff),
                mock.patch.object(
                    bridge,
                    "send_rich",
                    side_effect=lambda cid, txt, **kw: sent_texts.append(txt) or (801, "html"),
                ),
            ):
                bridge.execute_scheduled_task(task_agent)
            self.assertEqual(2, len(subproc_calls))
            prompt_idx = subproc_calls[1].index("-p") + 1
            self.assertIn("[预检脚本检测到变更增量", subproc_calls[1][prompt_idx])
            self.assertEqual(["⭐ Star +1 (1 -> 2)"], sent_texts)
            self.assertNotIn("[NO_HANDOFF]", sent_texts[0])
            self.assertEqual([], bridge.bot_bus.pop_inbox_packets("bot_one"))
            ledger_1 = bridge.bot_bus.get_unseen_group_history(-1001234567890, "bot_one", advance_cursor=True)
            self.assertEqual([801], [e["msg_id"] for e in ledger_1])

            # 3. Precheck failure (rc != 0) injects error into AGY_BIN + actionable reply wakes bot_one
            subproc_calls.clear()

            def fake_subproc_actionable(cmd, **kw):
                subproc_calls.append(cmd)
                if kw.get("shell"):
                    return 2, "", "rate limit hit"
                return 0, json.dumps({"response": "发现新 Issue #5 需要评估"}), ""

            with (
                mock.patch.object(bridge.scheduler, "task_mgr", mgr),
                mock.patch.object(bridge, "_run_subprocess_group", side_effect=fake_subproc_actionable),
                mock.patch.object(bridge, "send_rich", return_value=(802, "html")),
            ):
                bridge.execute_scheduled_task(task_agent)
            prompt_idx3 = subproc_calls[1].index("-p") + 1
            self.assertIn("[预检脚本执行异常 rc=2]\nrate limit hit", subproc_calls[1][prompt_idx3])
            ho_pkts = bridge.bot_bus.pop_inbox_packets("bot_one")
            self.assertEqual(1, len(ho_pkts))
            self.assertEqual("scheduled_handoff", ho_pkts[0]["type"])
            self.assertEqual(802, ho_pkts[0]["msg_id"])

            # 4. Script task with dict-returning send() writes ledger and triggers scheduled_handoff
            task_script = mgr.create_task(
                name="ScriptWatch",
                schedule_expr="0 * * * *",
                task_type="script",
                payload={"script": "echo delta"},
                target_chat_id=-1001234567890,
                custom_id="task-watch-script",
                handoff_bot="@bot_one",
            )
            with (
                mock.patch.object(bridge.scheduler, "task_mgr", mgr),
                mock.patch.object(bridge, "_run_subprocess_group", return_value=(0, "PR #9 opened", "")),
                mock.patch.object(bridge, "send", return_value={"ok": True, "result": {"message_id": 803}}),
            ):
                bridge.execute_scheduled_task(task_script)
            ho_pkts_script = bridge.bot_bus.pop_inbox_packets("bot_one")
            self.assertEqual(1, len(ho_pkts_script))
            self.assertEqual(803, ho_pkts_script[0]["msg_id"])

            # 5. Receiving scheduled_handoff on coordinator routes to main job_q (NOT fast_chat) even when busy
            bridge_coord = self._load_bridge(
                tmp,
                {"AGY_BOT_HANDLE": "bot_one", "AGY_BOT_BUS_ROLE": "coordinator"},
            )
            bridge_coord.BOT_META.update({"bot_id": 111, "handle": "bot_one", "resolved": True})
            with bridge_coord.session_lock:
                bridge_coord.turn_running = True
                bridge_coord.turn_running_scope = "-1001234567890"
            try:
                with (
                    mock.patch.object(bridge_coord, "_run_fast_group_reply") as fast_mock,
                    mock.patch.object(bridge_coord, "send", return_value=804),
                ):
                    bridge_coord._handle_bot_bus_packet(ho_pkts_script[0])
                fast_mock.assert_not_called()
                self.assertEqual(1, bridge_coord.job_q.qsize())
                queued_item = bridge_coord.job_q.get()
                self.assertEqual(-1001234567890, queued_item[0])
                self.assertEqual("__CHAT_TURN__", queued_item[3][0])
                self.assertIn("[ACB_SCHEDULED_HANDOFF from=@bot_two", queued_item[3][1]["prompt"])
                bridge_coord.job_q.task_done()
            finally:
                with bridge_coord.session_lock:
                    bridge_coord.turn_running = False
                    bridge_coord.turn_running_scope = None


class TestModelSelectionAndFollowSync(unittest.TestCase):
    """Verify DM `/ model` normalization, group `/model` & `/team` full catalog UI, and live DM follow sync."""

    def _load_bridge(self, tmp: str, extra_env: dict[str, str] | None = None):
        env_patch = {
            "AGY_BOT_BUS_DIR": tmp,
            "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
            "AGY_TG_WORKDIR": tmp,
            "AGY_TG_ALLOWED_CHATS": "111,-1001234567890",
            "AGY_TG_ALLOWED_USERS": "",
            "AGY_TG_ADMIN_USERS": "",
            "AGY_TG_READONLY_USERS": "",
            "AGY_TG_BOT_TOKEN": "1234567890:EXAMPLE_TOKEN_FOR_TEST_ONLY",
            "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
            "AGY_TG_BOT_MODEL": "",
            "AGY_TG_FALLBACK_MODELS": "",
            "AGY_TG_GATEWAYS_FILE": os.path.join(tmp, "nonexistent_gw.json"),
            "AGY_TG_GATEWAYS_JSON": "",
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
            return bridge

    def test_dm_slash_normalization_resilient_panel_and_command_scope_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(
                tmp,
                {
                    "AGY_BOT_BUS_ROLE": "worker",
                    "AGY_TG_BOT_MODEL": "team/gpt-6.1-sol",
                },
            )
            bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})
            sample_models = [
                ("gemini-4-neon-high", "Gemini 4 Neon (High)"),
                ("claude-opus-5-5-high", "Claude Opus 5.5 (High)"),
            ]

            # 1. `/ model`, `/Model`, `@bot_two /model`, `@bot_two / model` all pop the model keyboard in DM
            for raw_text in ("/ model", "/Model", "/  Model", "@bot_two /model", "@bot_two / model"):
                sent = []
                with (
                    mock.patch.object(bridge, "agy_models", return_value=sample_models),
                    mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent.append((a, kw)) or 101),
                ):
                    bridge.handle_message(
                        {
                            "chat": {"id": 111, "type": "private"},
                            "from": {"id": 111, "username": "username"},
                            "message_id": 10,
                            "text": raw_text,
                        }
                    )
                self.assertEqual(1, len(sent), f"Failed for input {raw_text!r}")
                self.assertIn("reply_markup", sent[0][1])
                kb = sent[0][1]["reply_markup"]["inline_keyboard"]
                self.assertTrue(len(kb) >= 3)
                self.assertIn("Models", sent[0][0][1])

            # 2. Non-command paths & other-bot mentions do NOT trigger cmd_model or unknown bridge command
            for non_cmd in ("/ etc/hosts", "/", "@bot_two /etc/hosts", "@bot_one /model"):
                sent = []
                enqueued = []
                with (
                    mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent.append(a[1]) or 102),
                    mock.patch.object(bridge, "enqueue", side_effect=lambda *a, **kw: enqueued.append(a[1])),
                ):
                    bridge.handle_message(
                        {
                            "chat": {"id": 111, "type": "private"},
                            "from": {"id": 111, "username": "username"},
                            "message_id": 11,
                            "text": non_cmd,
                        }
                    )
                self.assertEqual([], sent, f"Unexpected bridge reply for {non_cmd!r}: {sent}")
                self.assertEqual(1, len(enqueued), f"Expected normal chat enqueue for {non_cmd!r}")

            # 3. Even when agy_models() throws during cold/network error, cmd_model still sends a valid keyboard
            sent_err = []
            with (
                mock.patch.object(bridge, "agy_models", side_effect=RuntimeError("cli timeout")),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent_err.append((a, kw)) or 103),
            ):
                bridge.cmd_model(111, "")
            self.assertEqual(1, len(sent_err))
            self.assertIn("inline_keyboard", sent_err[0][1]["reply_markup"])
            self.assertEqual("model:default", sent_err[0][1]["reply_markup"]["inline_keyboard"][-1][0]["callback_data"])

            # 4. register_bot_commands cleans positive DM chat_ids too (not only negative group chat_ids)
            tg_calls = []
            fake_ok = mock.MagicMock(status_code=200, json=lambda: {"ok": True})
            with mock.patch.object(bridge, "tg", side_effect=lambda method, **kw: tg_calls.append((method, kw)) or fake_ok):
                bridge.register_bot_commands(force=True)
            deleted_scopes = [kw.get("scope") for m, kw in tg_calls if m == "deleteMyCommands"]
            self.assertIn({"type": "chat", "chat_id": 111}, deleted_scopes)
            self.assertIn({"type": "chat_administrators", "chat_id": 111}, deleted_scopes)
            self.assertIn({"type": "chat", "chat_id": -1001234567890}, deleted_scopes)

    def test_group_model_panel_has_default_follow_and_full_models_while_dm_stays_compat(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(tmp, {"AGY_TG_BOT_MODEL": "team/gpt-6.1-sol"})
            bridge.BOT_META.update({"bot_id": 111, "handle": "bot_one", "resolved": True})

            # `model` must be present in _GROUP_TEAM_COMMANDS
            grp_cmd_names = [c["command"] for c in bridge._GROUP_TEAM_COMMANDS]
            self.assertIn("model", grp_cmd_names)

            catalog = [
                (f"vendor/very-long-model-slug-entry-number-{i:02d}", f"[GW] Model {i:02d}")
                for i in range(15)
            ]

            # DM keyboard default preserves 12 rows (10 models + pagination + single reset row)
            kb_dm = bridge.make_model_keyboard(catalog[0][0], page=0, page_size=10, models=catalog)
            self.assertEqual(12, len(kb_dm["inline_keyboard"]))
            self.assertEqual(1, len(kb_dm["inline_keyboard"][-1]))
            self.assertEqual("model:default", kb_dm["inline_keyboard"][-1][0]["callback_data"])

            # Group panel includes side-by-side [Default, Follow DM] + paginated models
            bridge.update_scope_state("-1001234567890", model=bridge.MODEL_FOLLOW_DM)
            bridge.update_scope_state("111", model="claude-opus-5-5-high")
            text_grp, kb_grp = bridge._render_model_panel("-1001234567890", page=0, page_size=10, models=catalog)
            self.assertIn("跟随私聊", text_grp)
            self.assertIn("claude-opus-5-5-high", text_grp)
            self.assertNotIn(bridge.MODEL_FOLLOW_DM, text_grp)

            action_row = kb_grp["inline_keyboard"][-1]
            self.assertEqual(2, len(action_row))
            self.assertEqual("model:default", action_row[0]["callback_data"])
            self.assertEqual("model:follow", action_row[1]["callback_data"])
            self.assertTrue(action_row[1]["text"].startswith("✓ "))

            # Group `/model 追随` and `model:default` callback update scope & bot_bus
            with (
                mock.patch.object(bridge, "agy_models", return_value=catalog),
                mock.patch.object(bridge, "send", return_value=1),
                mock.patch.object(bridge, "tg", return_value=mock.MagicMock(status_code=200, json=lambda: {"ok": True})),
            ):
                bridge.cmd_model(-1001234567890, "default")
                self.assertIsNone(bridge.get_scope_value("-1001234567890", "model"))
                self.assertEqual(
                    bridge.bot_bus.MODEL_MODE_DEFAULT,
                    bridge.bot_bus.resolve_bot_config("bot_one", env_model="team/gpt-6.1-sol")["model_mode"],
                )

                bridge.cmd_model(-1001234567890, "追随")
                self.assertEqual(bridge.MODEL_FOLLOW_DM, bridge.get_scope_value("-1001234567890", "model"))
                self.assertEqual(
                    bridge.bot_bus.MODEL_MODE_FOLLOW,
                    bridge.bot_bus.resolve_bot_config("bot_one", env_model="team/gpt-6.1-sol")["model_mode"],
                )

                # Topic scope /model change stays isolated to that Topic and does NOT overwrite bot_bus
                bridge.cmd_model(-1001234567890, "gemini-4-neon-high", thread_id=42)
                self.assertEqual("gemini-4-neon-high", bridge.get_scope_value("-1001234567890:42", "model"))
                self.assertEqual(
                    bridge.bot_bus.MODEL_MODE_FOLLOW,
                    bridge.bot_bus.resolve_bot_config("bot_one", env_model="team/gpt-6.1-sol")["model_mode"],
                )

    def test_team_model_subpanel_pagination_64b_callbacks_and_cold_restart_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(tmp, {"AGY_BOT_BUS_ROLE": "coordinator"})
            bridge.BOT_META.update({"bot_id": 111, "handle": "bot_one", "resolved": True})

            long_handle = "very_long_worker_bot_handle_for_callback_length_test_bot"
            bridge.bot_bus.heartbeat_bot(
                {
                    "handle": long_handle,
                    "pid": os.getpid(),
                    "role": "worker",
                    "dm_model": "claude-opus-5-5-high",
                    "env_default_model": "team/gpt-6.1-sol",
                    "active_model": "claude-opus-5-5-high",
                }
            )
            bridge.bot_bus.heartbeat_bot(
                {
                    "handle": "bot_one",
                    "pid": os.getpid(),
                    "role": "coordinator",
                    "dm_model": "gemini-4-neon-high",
                    "env_default_model": "",
                    "active_model": "gemini-4-neon-high",
                }
            )

            long_models = [
                (f"gw:openrouter:very-long-org-prefix/model-identifier-variant-{i:02d}-thinking", f"[OR] Model {i:02d}")
                for i in range(15)
            ]

            with mock.patch.object(bridge, "agy_models", return_value=long_models):
                team_text, team_kb = bridge.build_team_panel()
                self.assertIn("默认 (team/gpt-6.1-sol)", team_text)
                for row in team_kb["inline_keyboard"]:
                    for btn in row:
                        self.assertLessEqual(len(btn["callback_data"].encode("utf-8")), 64)

                # Find model button for long_handle
                model_cbs = [
                    btn["callback_data"]
                    for row in team_kb["inline_keyboard"]
                    for btn in row
                    if btn["callback_data"].startswith("team:model:")
                ]
                self.assertTrue(len(model_cbs) >= 2)
                btok = bridge._team_bot_token(long_handle)
                open_cb = f"team:model:{btok}"
                self.assertIn(open_cb, model_cbs)

                # Open sub-panel page 0 & page 1 and verify ALL callback_data <= 64 bytes
                sub_text, sub_kb = bridge.build_team_model_panel(long_handle, page=0, page_size=10, models=long_models)
                self.assertIn("⚙️ 默认", sub_text)
                for row in sub_kb["inline_keyboard"]:
                    for btn in row:
                        self.assertLessEqual(len(btn["callback_data"].encode("utf-8")), 64)

                all_sub_cbs = [btn["callback_data"] for row in sub_kb["inline_keyboard"] for btn in row]
                self.assertIn(f"team:tmp:{btok}:1", all_sub_cbs)
                self.assertIn(f"team:tmd:{btok}", all_sub_cbs)
                self.assertIn(f"team:tmf:{btok}", all_sub_cbs)
                self.assertIn("team:refresh", all_sub_cbs)

                # Simulate cold restart (clear in-memory callback token maps)
                target_model_cb = sub_kb["inline_keyboard"][0][0]["callback_data"]
                bridge._TEAM_BOT_CB_MAP.clear()
                bridge._MODEL_CB_MAP.clear()

                edited = []
                fake_ok = mock.MagicMock(status_code=200, json=lambda: {"ok": True})
                with mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: edited.append((m, kw)) or fake_ok):
                    # Select custom long gateway model after cold restart
                    bridge.handle_callback(
                        {
                            "id": "cb-tm-1",
                            "from": {"id": 111},
                            "message": {"chat": {"id": -1001234567890}, "message_id": 88},
                            "data": target_model_cb,
                        }
                    )
                    cfg_after = bridge.bot_bus.resolve_bot_config(long_handle, env_model="team/gpt-6.1-sol")
                    self.assertEqual(bridge.bot_bus.MODEL_MODE_CUSTOM, cfg_after["model_mode"])
                    self.assertEqual(long_models[0][0], cfg_after["configured_model"])

                    # Select follow via sub-panel callback -> dispatches sync_group_model packet
                    bridge.handle_callback(
                        {
                            "id": "cb-tm-2",
                            "from": {"id": 111},
                            "message": {"chat": {"id": -1001234567890}, "message_id": 88},
                            "data": f"team:tmf:{btok}",
                        }
                    )
                    cfg_follow = bridge.bot_bus.resolve_bot_config(long_handle, env_model="team/gpt-6.1-sol")
                    self.assertEqual(bridge.bot_bus.MODEL_MODE_FOLLOW, cfg_follow["model_mode"])
                    pkts = bridge.bot_bus.pop_inbox_packets(long_handle)
                    self.assertEqual(2, len(pkts))
                    self.assertEqual("sync_group_model", pkts[-1]["type"])
                    self.assertEqual(bridge.bot_bus.MODEL_MODE_FOLLOW, pkts[-1]["model_mode"])

                    # Select default via sub-panel callback
                    bridge.handle_callback(
                        {
                            "id": "cb-tm-3",
                            "from": {"id": 111},
                            "message": {"chat": {"id": -1001234567890}, "message_id": 88},
                            "data": f"team:tmd:{btok}",
                        }
                    )
                    cfg_def = bridge.bot_bus.resolve_bot_config(long_handle, env_model="team/gpt-6.1-sol")
                    self.assertEqual(bridge.bot_bus.MODEL_MODE_DEFAULT, cfg_def["model_mode"])

                # cmd_team model supports default/默认, follow/追随, and fuzzy suffix slug
                with mock.patch.object(bridge, "send", return_value=1):
                    bridge.cmd_team(-1001234567890, f"model @{long_handle} 追随")
                    self.assertEqual(
                        bridge.bot_bus.MODEL_MODE_FOLLOW,
                        bridge.bot_bus.resolve_bot_config(long_handle)["model_mode"],
                    )
                    bridge.cmd_team(-1001234567890, f"model @{long_handle} model-identifier-variant-03-thinking")
                    self.assertEqual(
                        long_models[3][0],
                        bridge.bot_bus.resolve_bot_config(long_handle)["configured_model"],
                    )
                    bridge.cmd_team(-1001234567890, f"model @{long_handle} 默认")
                    self.assertEqual(
                        bridge.bot_bus.MODEL_MODE_DEFAULT,
                        bridge.bot_bus.resolve_bot_config(long_handle)["model_mode"],
                    )

    def test_follow_dm_live_sync_across_all_exec_paths_warm_sessions_and_bus_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(
                tmp,
                {
                    "AGY_BOT_BUS_ROLE": "worker",
                    "AGY_TG_BOT_MODEL": "team/gpt-6.1-sol",
                },
            )
            bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})

            # Seed DM model first, then verify new group scope does NOT freeze DM model when config is default
            bridge.update_scope_state("111", model="gemini-4-neon-high")
            grp_sc = bridge.get_scope_state("-1001234567890")
            self.assertIsNone(grp_sc["model"])
            self.assertEqual("team/gpt-6.1-sol", bridge._resolve_effective_model("-1001234567890"))

            # Pre-seed a warm AgySession on group scope to verify invalidation on sync & DM change
            warm_grp_1 = mock.MagicMock()
            warm_grp_1.is_alive.return_value = True
            with bridge.session_lock:
                bridge._session_pool["-1001234567890"] = warm_grp_1

            # 1. Cross-bot sync_group_model(follow) updates group scope, evicts warm session, persists state & heartbeat
            bridge.bot_bus.set_bot_model_config("bot_two", bridge.bot_bus.MODEL_MODE_FOLLOW)
            bridge._handle_bot_bus_packet(
                {
                    "type": "sync_group_model",
                    "from_bot": "bot_one",
                    "target_bot": "bot_two",
                    "model_mode": bridge.bot_bus.MODEL_MODE_FOLLOW,
                    "model": "",
                    "chat_id": -1001234567890,
                    "thread_id": None,
                }
            )
            self.assertEqual(bridge.MODEL_FOLLOW_DM, bridge.get_scope_value("-1001234567890", "model"))
            self.assertNotIn("-1001234567890", bridge._session_pool)
            self.assertEqual("gemini-4-neon-high", bridge._resolve_effective_model("-1001234567890"))

            # New topic scope created under group inherits parent group's MODEL_FOLLOW_DM
            self.assertEqual(bridge.MODEL_FOLLOW_DM, bridge.get_scope_value("-1001234567890:99", "model"))

            # 2. Switch DM model to claude-opus-5-5-high -> evicts following group warm session & updates ALL paths!
            warm_grp_2 = mock.MagicMock()
            warm_grp_2.is_alive.return_value = True
            with bridge.session_lock:
                bridge._session_pool["-1001234567890"] = warm_grp_2

            with mock.patch.object(bridge, "send", return_value=1):
                bridge.cmd_model(111, "claude-opus-5-5-high")

            self.assertNotIn("-1001234567890", bridge._session_pool)
            self.assertEqual("claude-opus-5-5-high", bridge._resolve_effective_model("-1001234567890"))
            self.assertEqual("claude-opus-5-5-high", bridge._resolve_effective_model("-1001234567890:99"))

            # Heartbeat & roster view immediately reflect the new DM model
            roster_map = {b["handle"]: b for b in bridge.bot_bus.list_roster(include_offline=True)}
            self.assertEqual("claude-opus-5-5-high", roster_map["bot_two"]["dm_model"])
            self.assertEqual("claude-opus-5-5-high", roster_map["bot_two"]["effective_model"])

            # 2a. cmd_status shows Follow DM + claude-opus-5-5-high (never raw sentinel)
            status_msgs = []
            with mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: status_msgs.append(a[1]) or 1):
                bridge.cmd_status(-1001234567890)
            self.assertTrue(status_msgs)
            self.assertIn("跟随私聊", status_msgs[0])
            self.assertIn("claude-opus-5-5-high", status_msgs[0])
            self.assertNotIn(bridge.MODEL_FOLLOW_DM, status_msgs[0])

            # 2b. run_compact receives claude-opus-5-5-high
            bridge.update_scope_state("-1001234567890", conversation_id="conv-follow-1")
            compact_models = []
            with (
                mock.patch.object(
                    bridge,
                    "_execute_compact_on_session",
                    side_effect=lambda skey, conv, mode, mdl, *a, **kw: compact_models.append(mdl) or (True, 0.2, ""),
                ),
                mock.patch.object(bridge, "send", return_value=1),
                mock.patch.object(bridge, "tg", return_value=None),
            ):
                bridge.run_compact(-1001234567890)
            self.assertEqual(["claude-opus-5-5-high"], compact_models)

            # 2c. _run_fast_group_reply passes --model claude-opus-5-5-high
            fast_cmds = []
            bridge._fast_chat_sem.acquire()
            with (
                mock.patch.object(
                    bridge,
                    "_run_subprocess_group",
                    side_effect=lambda cmd, **kw: fast_cmds.append(list(cmd)) or (0, '{"response":"ok"}', ""),
                ),
                mock.patch.object(bridge, "send_rich", return_value=(55, "ok")),
                mock.patch.object(bridge, "_record_and_relay_bot_group_msg"),
            ):
                bridge._run_fast_group_reply(-1001234567890, "进度如何？")
            self.assertEqual(1, len(fast_cmds))
            self.assertIn("--model", fast_cmds[0])
            self.assertEqual("claude-opus-5-5-high", fast_cmds[0][fast_cmds[0].index("--model") + 1])

            # 2d. run_agy passes --model claude-opus-5-5-high (never __follow_dm__)
            run_agy_cmds = []

            class _FakePopen:
                def __init__(self, cmd, **kwargs):
                    run_agy_cmds.append(list(cmd))
                    self.pid = 7777
                    self.returncode = 0
                    self.stdin = mock.MagicMock()
                    self.stdin.closed = False
                    self.stdout = iter(
                        [
                            '{"event":"init","conversation_id":"conv-follow-1"}\n',
                            '{"event":"result","result":{"status":"SUCCESS","response":"done","conversation_id":"conv-follow-1"}}\n',
                        ]
                    )
                    self.stderr = iter([])

                def poll(self):
                    return 0

                def wait(self, timeout=None):
                    return 0

            with (
                mock.patch.object(bridge.subprocess, "Popen", side_effect=_FakePopen),
                mock.patch.object(bridge, "send_rich", return_value=(56, "done")),
                mock.patch.object(bridge, "send", return_value=1),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "_record_and_relay_bot_group_msg"),
            ):
                bridge.run_agy(-1001234567890, "hello group")
            self.assertEqual(1, len(run_agy_cmds))
            self.assertIn("--model", run_agy_cmds[0])
            self.assertEqual("claude-opus-5-5-high", run_agy_cmds[0][run_agy_cmds[0].index("--model") + 1])

            # 2e. _execute_bus_job without job["model"] uses DM effective model when follow, and ENV_BOT_MODEL when default
            def _run_one_bus_job(label: str):
                res = bridge.bot_bus.dispatch_assignments(
                    "bot_one",
                    [{"bot": "bot_two", "prompt": "check", "label": label}],
                    origin_chat_id=-1001234567890,
                    origin_scope_key="-1001234567890",
                )
                jid = res["jobs"][0]["job_id"]
                seen_models = []

                def _fake_exec_target(mdl, eff):
                    seen_models.append(mdl)
                    return {
                        "kind": "native",
                        "cli_model": mdl,
                        "cli_effort": eff,
                        "env_set": {},
                        "signature": ("native", mdl or "", eff or ""),
                    }

                class _JobPopen:
                    def __init__(self, cmd, **kwargs):
                        self.pid = 7778
                        self.returncode = 0
                        self.stdout = iter(
                            [
                                '{"event":"result","result":{"status":"SUCCESS","response":"job ok","conversation_id":"conv-job-1"}}\n'
                            ]
                        )
                        self.stderr = iter([])

                    def wait(self, timeout=None):
                        return 0

                with (
                    mock.patch.object(bridge, "_resolve_exec_target", side_effect=_fake_exec_target),
                    mock.patch.object(bridge.subprocess, "Popen", side_effect=_JobPopen),
                    mock.patch.object(bridge, "tg_send_in_route", return_value=None),
                    mock.patch.object(bridge, "send_rich", return_value=(57, "job ok")),
                ):
                    bridge._execute_bus_job(jid)
                return seen_models

            # While in follow mode -> job runs on DM model claude-opus-5-5-high
            self.assertEqual(["claude-opus-5-5-high"], _run_one_bus_job("follow-check"))

            # 3. Switch back to default via sync_group_model -> falls back to ENV_BOT_MODEL (team/gpt-6.1-sol)
            bridge.bot_bus.set_bot_model_config("bot_two", bridge.bot_bus.MODEL_MODE_DEFAULT)
            bridge._handle_bot_bus_packet(
                {
                    "type": "sync_group_model",
                    "from_bot": "bot_one",
                    "target_bot": "bot_two",
                    "model_mode": bridge.bot_bus.MODEL_MODE_DEFAULT,
                    "model": "",
                    "chat_id": -1001234567890,
                    "thread_id": None,
                }
            )
            self.assertIsNone(bridge.get_scope_value("-1001234567890", "model"))
            self.assertEqual("team/gpt-6.1-sol", bridge._resolve_effective_model("-1001234567890"))
            self.assertEqual(["team/gpt-6.1-sol"], _run_one_bus_job("default-check"))

    def test_stale_sync_group_model_rejection_and_mixed_ms_ns_safety(self):
        """Stale rev, untagged delayed, and mixed ms/ns sync packets must NOT clobber newer model/scope/warm session (QA-01/02)."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(
                tmp,
                {
                    "AGY_BOT_BUS_ROLE": "worker",
                    "AGY_TG_BOT_MODEL": "team/gpt-6.1-sol",
                },
            )
            bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})

            # Remote setter initially queues OLD (rev=1)
            rec_old = bridge.bot_bus.set_bot_model_and_notify(
                "bot_two",
                bridge.bot_bus.MODEL_MODE_CUSTOM,
                "model-old",
                from_bot="bot_one",
                chat_id=-1001234567890,
                thread_id=42,
                notify_target=True,
            )
            self.assertEqual(1, rec_old["model_rev"])
            stale_pkts = bridge.bot_bus.pop_inbox_packets("bot_two")
            self.assertEqual(1, len(stale_pkts))
            stale_rev_pkt = stale_pkts[0]
            self.assertEqual(1, stale_rev_pkt["model_rev"])

            # Local group /model switches to NEW (bumps rev=2, updates scope & heartbeat)
            with mock.patch.object(bridge, "send", return_value=1):
                bridge.cmd_model(-1001234567890, "model-new")
                # Isolate topic 42 with its own override
                bridge.cmd_model(-1001234567890, "model-topic-42", thread_id=42)

            self.assertEqual(2, bridge.bot_bus.resolve_bot_config("bot_two")["model_rev"])
            self.assertEqual("model-new", bridge.get_scope_value("-1001234567890", "model"))
            self.assertEqual("model-topic-42", bridge.get_scope_value("-1001234567890:42", "model"))

            # Seed an active warm session for NEW on the main group scope
            warm_new = mock.MagicMock()
            warm_new.is_alive.return_value = True
            with bridge.session_lock:
                bridge._session_pool["-1001234567890"] = warm_new

            def _assert_all_stay_new():
                cfg = bridge.bot_bus.resolve_bot_config("bot_two", env_model="team/gpt-6.1-sol")
                self.assertEqual(bridge.bot_bus.MODEL_MODE_CUSTOM, cfg["model_mode"])
                self.assertEqual("model-new", cfg["configured_model"])
                self.assertEqual(2, cfg["model_rev"])
                self.assertEqual("model-new", bridge.get_scope_value("-1001234567890", "model"))
                self.assertEqual("model-new", bridge._resolve_effective_model("-1001234567890"))
                self.assertEqual("model-topic-42", bridge.get_scope_value("-1001234567890:42", "model"))
                self.assertIs(warm_new, bridge._session_pool.get("-1001234567890"))
                roster = {b["handle"]: b for b in bridge.bot_bus.list_roster(include_offline=True)}
                self.assertEqual("model-new", roster["bot_two"]["configured_model"])
                self.assertEqual("model-new", roster["bot_two"]["effective_model"])
                self.assertEqual(2, roster["bot_two"]["model_rev"])

            # (a) Stale pkt_rev < auth_rev after local /model NEW
            bridge._handle_bot_bus_packet(stale_rev_pkt)
            _assert_all_stay_new()

            # (b) Untagged delayed packet created_at=1 vs authoritative NEW
            bridge._handle_bot_bus_packet(
                {
                    "type": "sync_group_model",
                    "from_bot": "bot_one",
                    "target_bot": "bot_two",
                    "model_mode": bridge.bot_bus.MODEL_MODE_CUSTOM,
                    "model": "model-stale-untagged",
                    "chat_id": -1001234567890,
                    "thread_id": 42,
                    "created_at": 1,
                }
            )
            _assert_all_stay_new()

            # (c) Legacy 13-digit ms stale packet arriving AFTER NEW
            bot_inbox = os.path.join(bridge.bot_bus.INBOX_DIR, "bot_two")
            os.makedirs(bot_inbox, mode=0o700, exist_ok=True)
            legacy_sec = int(time.time()) - 600
            legacy_ms = legacy_sec * 1000
            bridge.bot_bus._atomic_write_json(
                os.path.join(bot_inbox, f"{legacy_ms}_deadbeef.json"),
                {
                    "type": "sync_group_model",
                    "from_bot": "bot_one",
                    "target_bot": "bot_two",
                    "model_mode": bridge.bot_bus.MODEL_MODE_CUSTOM,
                    "model": "model-legacy-ms-stale",
                    "chat_id": -1001234567890,
                    "thread_id": 42,
                    "created_at": legacy_sec,
                },
            )
            for pkt in bridge.bot_bus.pop_inbox_packets("bot_two"):
                bridge._handle_bot_bus_packet(pkt)
            _assert_all_stay_new()

            # (d) Mixed legacy ms OLD + fresh ns NEWEST (rev=3) popped together converge to NEWEST
            bridge.bot_bus._atomic_write_json(
                os.path.join(bot_inbox, f"{legacy_ms}_ffffffff.json"),
                {
                    "type": "sync_group_model",
                    "from_bot": "bot_one",
                    "target_bot": "bot_two",
                    "model_mode": bridge.bot_bus.MODEL_MODE_CUSTOM,
                    "model": "model-legacy-ms-old",
                    "chat_id": -1001234567890,
                    "thread_id": None,
                    "created_at": legacy_sec,
                },
            )
            rec_newest = bridge.bot_bus.set_bot_model_and_notify(
                "bot_two",
                bridge.bot_bus.MODEL_MODE_CUSTOM,
                "model-newest",
                from_bot="bot_one",
                chat_id=-1001234567890,
                thread_id=None,
                notify_target=True,
            )
            self.assertEqual(3, rec_newest["model_rev"])
            mixed_pkts = bridge.bot_bus.pop_inbox_packets("bot_two")
            self.assertEqual(2, len(mixed_pkts))
            self.assertEqual("model-legacy-ms-old", mixed_pkts[0]["model"])
            self.assertEqual("model-newest", mixed_pkts[1]["model"])
            for pkt in mixed_pkts:
                bridge._handle_bot_bus_packet(pkt)
            self.assertEqual("model-newest", bridge.get_scope_value("-1001234567890", "model"))
            self.assertEqual("model-newest", bridge._resolve_effective_model("-1001234567890"))
            self.assertEqual("model-topic-42", bridge.get_scope_value("-1001234567890:42", "model"))
            self.assertNotIn("-1001234567890", bridge._session_pool)

        # (e) Pure synthetic compat: untagged packet applies cleanly when neither auth_rev nor auth_upd exists
        with tempfile.TemporaryDirectory() as tmp_syn:
            bridge_syn = self._load_bridge(tmp_syn, {"AGY_TG_BOT_ROLE": "worker"})
            bridge_syn.BOT_META.update({"bot_id": 223, "handle": "bot_fresh", "resolved": True})
            bridge_syn._handle_bot_bus_packet(
                {
                    "type": "sync_group_model",
                    "from_bot": "bot_one",
                    "target_bot": "bot_fresh",
                    "model_mode": bridge_syn.bot_bus.MODEL_MODE_CUSTOM,
                    "model": "synthetic-model",
                    "chat_id": -1001234567890,
                    "thread_id": None,
                }
            )
            self.assertEqual("synthetic-model", bridge_syn.get_scope_value("-1001234567890", "model"))

    def test_register_bot_commands_scope_cleanup_gate_and_retry(self):
        """Failed DM/group chat cleanup prevents caching & retries; inapplicable private chat_administrators does not (QA-03)."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(tmp, {"AGY_TG_BOT_ROLE": "worker"})
            bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})
            bridge._LAST_REGISTERED_CMD_ROLE = None

            resp_ok = mock.MagicMock(status_code=200, json=lambda: {"ok": True})
            resp_400 = mock.MagicMock(status_code=400, json=lambda: {"ok": False, "error_code": 400})

            # 1. Positive DM `chat` deleteMyCommands returns HTTP 400 -> returns False, does NOT cache, retries on force=False
            calls_1 = []

            def _tg_fail_dm_chat(method, **kw):
                calls_1.append((method, kw.get("scope")))
                if method == "deleteMyCommands" and kw.get("scope") == {"type": "chat", "chat_id": 111}:
                    return resp_400
                return resp_ok

            with mock.patch.object(bridge, "tg", side_effect=_tg_fail_dm_chat):
                self.assertFalse(bridge.register_bot_commands(force=True))
                self.assertIsNone(bridge._LAST_REGISTERED_CMD_ROLE)
                prev_len = len(calls_1)
                self.assertFalse(bridge.register_bot_commands(force=False))
                self.assertGreater(len(calls_1), prev_len)

            # 2. Private `chat_administrators` returning HTTP 400 is best-effort and MUST allow caching
            calls_2 = []

            def _tg_fail_private_admin_only(method, **kw):
                calls_2.append((method, kw.get("scope")))
                if method == "deleteMyCommands" and kw.get("scope") == {"type": "chat_administrators", "chat_id": 111}:
                    return resp_400
                return resp_ok

            with mock.patch.object(bridge, "tg", side_effect=_tg_fail_private_admin_only):
                self.assertTrue(bridge.register_bot_commands(force=False))
                self.assertEqual("worker", bridge._LAST_REGISTERED_CMD_ROLE)
                self.assertIn(("deleteMyCommands", {"type": "chat_administrators", "chat_id": 111}), calls_2)
                cached_len = len(calls_2)
                self.assertTrue(bridge.register_bot_commands(force=False))
                self.assertEqual(cached_len, len(calls_2))

            # 3. Negative group `chat_administrators` returning HTTP 400 MUST block caching
            bridge._LAST_REGISTERED_CMD_ROLE = None

            def _tg_fail_group_admin(method, **kw):
                if method == "deleteMyCommands" and kw.get("scope") == {
                    "type": "chat_administrators",
                    "chat_id": -1001234567890,
                }:
                    return resp_400
                return resp_ok

            with mock.patch.object(bridge, "tg", side_effect=_tg_fail_group_admin):
                self.assertFalse(bridge.register_bot_commands(force=True))
                self.assertIsNone(bridge._LAST_REGISTERED_CMD_ROLE)

    def test_receiver_vs_local_setter_toctou_race_and_equal_rev_mismatch(self):
        """Full-module Event-driven receiver-vs-setter TOCTOU tests + equal-rev stale notify rejection (QA-02)."""
        chat_id = -1001234567890
        sk = str(chat_id)
        topic_sk = f"{sk}:42"

        for kind in ("local_scope_setter", "self_team_setter"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                bridge = self._load_bridge(
                    tmp,
                    {
                        "AGY_TG_BOT_ROLE": "worker",
                        "AGY_TG_BOT_MODEL": "team/gpt-6.1-sol",
                    },
                )
                bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})
                bus = bridge.bot_bus

                # Remote setter queues STALE at rev=1
                rec1 = bus.set_bot_model_and_notify(
                    "bot_two",
                    bus.MODEL_MODE_CUSTOM,
                    "STALE",
                    from_bot="bot_one",
                    chat_id=chat_id,
                    notify_target=True,
                )
                self.assertEqual(1, rec1["model_rev"])
                (packet,) = bus.pop_inbox_packets("bot_two")
                bridge.update_scope_state(sk, model="STALE")
                bridge.update_scope_state(topic_sk, model="TOPIC")

                original_cfg = bridge._current_bot_cfg
                captured = threading.Event()
                resume = threading.Event()
                errors = []

                def paused_cfg():
                    val = original_cfg()
                    if threading.current_thread().name == "bus-receiver" and not captured.is_set():
                        captured.set()
                        if not resume.wait(5):
                            raise TimeoutError("receiver pause timed out")
                    return val

                def run_receiver():
                    try:
                        bridge._handle_bot_bus_packet(packet)
                    except BaseException as exc:  # pragma: no cover - surfaced via assertEqual
                        errors.append(repr(exc))

                with mock.patch.object(bridge, "_current_bot_cfg", side_effect=paused_cfg):
                    rx_thread = threading.Thread(target=run_receiver, name="bus-receiver")
                    rx_thread.start()
                    self.assertTrue(captured.wait(5), "receiver did not reach _current_bot_cfg pause")

                    # Concurrently update model on main thread; MUST NOT deadlock `_current_bot_cfg`
                    if kind == "local_scope_setter":
                        bridge._apply_scope_model_change(sk, "NEW")
                    else:
                        bridge._set_team_bot_model("bot_two", bus.MODEL_MODE_CUSTOM, "NEW", chat_id=chat_id)

                    mid_cfg = original_cfg()
                    self.assertEqual("NEW", mid_cfg["configured_model"])
                    self.assertEqual(2, mid_cfg["model_rev"])
                    self.assertEqual("NEW", bridge.get_scope_value(sk, "model"))

                    resume.set()
                    rx_thread.join(5)
                    self.assertFalse(rx_thread.is_alive(), "receiver thread deadlocked")
                    self.assertEqual([], errors)

                final_cfg = original_cfg()
                roster = {b["handle"]: b for b in bus.list_roster(include_offline=True)}
                pending = bus.pop_inbox_packets("bot_two")
                self.assertEqual("NEW", final_cfg["configured_model"])
                self.assertEqual(2, final_cfg["model_rev"])
                self.assertEqual("NEW", bridge.get_scope_value(sk, "model"))
                self.assertEqual("NEW", bridge._resolve_effective_model(sk))
                self.assertEqual("TOPIC", bridge.get_scope_value(topic_sk, "model"))
                self.assertEqual("NEW", roster["bot_two"]["effective_model"])
                self.assertEqual(2, roster["bot_two"]["model_rev"])
                self.assertEqual(0, len(pending))

                # Equal-rev mismatched `notify_bot_model_sync(model="STALE")` while config already holds NEW (rev=2)
                warm_new = mock.MagicMock()
                warm_new.is_alive.return_value = True
                with bridge.session_lock:
                    bridge._session_pool[sk] = warm_new

                bus.notify_bot_model_sync(
                    "bot_two",
                    model_mode=bus.MODEL_MODE_CUSTOM,
                    model="STALE",
                    from_bot="bot_one",
                    chat_id=chat_id,
                )
                (eq_rev_pkt,) = bus.pop_inbox_packets("bot_two")
                self.assertEqual(2, eq_rev_pkt["model_rev"])
                self.assertEqual("STALE", eq_rev_pkt["model"])

                bridge._handle_bot_bus_packet(eq_rev_pkt)
                self.assertEqual("NEW", bridge.get_scope_value(sk, "model"))
                self.assertEqual("NEW", bridge._resolve_effective_model(sk))
                self.assertEqual("TOPIC", bridge.get_scope_value(topic_sk, "model"))
                self.assertIs(warm_new, bridge._session_pool.get(sk))

    def test_register_bot_commands_forced_refresh_failure_invalidates_cached_role(self):
        """A failed forced refresh clears prior cached role so the next non-forced call retries and recovers (QA-03)."""
        with tempfile.TemporaryDirectory() as tmp:
            bridge = self._load_bridge(tmp, {"AGY_TG_BOT_ROLE": "worker"})
            bridge.BOT_META.update({"bot_id": 222, "handle": "bot_two", "resolved": True})
            bridge._LAST_REGISTERED_CMD_ROLE = None

            resp_ok = mock.MagicMock(status_code=200, json=lambda: {"ok": True})
            resp_400 = mock.MagicMock(status_code=400, json=lambda: {"ok": False, "error_code": 400})

            # 1. Initial forced registration succeeds and caches `worker`
            with mock.patch.object(bridge, "tg", return_value=resp_ok):
                self.assertTrue(bridge.register_bot_commands(force=True))
            self.assertEqual("worker", bridge._LAST_REGISTERED_CMD_ROLE)

            # 2. Subsequent forced refresh fails on DM chat deleteMyCommands HTTP 400 -> returns False & clears cache
            calls_fail = []

            def _tg_dm_400(method, **kw):
                calls_fail.append((method, kw.get("scope")))
                if method == "deleteMyCommands" and kw.get("scope") == {"type": "chat", "chat_id": 111}:
                    return resp_400
                return resp_ok

            with mock.patch.object(bridge, "tg", side_effect=_tg_dm_400):
                self.assertFalse(bridge.register_bot_commands(force=True))
                self.assertIsNone(bridge._LAST_REGISTERED_CMD_ROLE)
                after_forced = len(calls_fail)
                # Next non-forced call MUST actually retry Telegram APIs
                self.assertFalse(bridge.register_bot_commands(force=False))
                self.assertGreater(len(calls_fail), after_forced)
                self.assertIsNone(bridge._LAST_REGISTERED_CMD_ROLE)

            # 3. Once DM chat succeeds (even if private chat_administrators returns HTTP 400), force=False recovers
            calls_recover = []

            def _tg_recover_private_admin_400(method, **kw):
                calls_recover.append((method, kw.get("scope")))
                if method == "deleteMyCommands" and kw.get("scope") == {"type": "chat_administrators", "chat_id": 111}:
                    return resp_400
                return resp_ok

            with mock.patch.object(bridge, "tg", side_effect=_tg_recover_private_admin_400):
                self.assertTrue(bridge.register_bot_commands(force=False))
                self.assertGreater(len(calls_recover), 0)
                self.assertEqual("worker", bridge._LAST_REGISTERED_CMD_ROLE)

            # 4. Exception during forced refresh also clears cached role so next non-forced call retries
            with mock.patch.object(bridge, "tg", side_effect=RuntimeError("transient network drop")):
                self.assertFalse(bridge.register_bot_commands(force=True))
                self.assertIsNone(bridge._LAST_REGISTERED_CMD_ROLE)

            calls_after_exc = []
            with mock.patch.object(
                bridge, "tg", side_effect=lambda method, **kw: calls_after_exc.append(method) or resp_ok
            ):
                self.assertTrue(bridge.register_bot_commands(force=False))
                self.assertGreater(len(calls_after_exc), 0)
                self.assertEqual("worker", bridge._LAST_REGISTERED_CMD_ROLE)


if __name__ == "__main__":
    unittest.main()
