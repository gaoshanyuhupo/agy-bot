#!/usr/bin/env python3
"""Offline unit & integration tests for RBAC access control & readonly isolation."""

from __future__ import annotations

import importlib
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


def _load_isolated_bridge(tmp: str, extra_env: dict[str, str] | None = None):
    env_patch = {
        "AGY_BOT_BUS_DIR": os.path.join(tmp, "bus"),
        "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
        "AGY_TG_WORKDIR": os.path.join(tmp, "workdir"),
        "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
        "AGY_TG_ALLOWED_CHATS": "-1001234567890,111",
        "AGY_TG_ALLOWED_USERS": "",
        "AGY_TG_ADMIN_USERS": "",
        "AGY_TG_READONLY_USERS": "",
        "AGY_TG_ALLOW_GROUP_READONLY": "0",
        "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_RBAC_TEST_TOKEN_ONLY_1",
        "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
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
        return bridge, access_control


class TestAccessControlMatrix(unittest.TestCase):
    """Verify backward compatibility and RBAC role resolution matrix."""

    def test_backward_compatibility_when_rbac_vars_unset(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _ac = _load_isolated_bridge(tmp)
            # No ALLOWED_USERS and no RBAC vars -> authorized chat members are admin
            self.assertEqual("admin", bridge._get_user_role(-1001234567890, {"id": 999}))
            self.assertTrue(bridge._is_authorized(-1001234567890, {"id": 999}))
            self.assertEqual("denied", bridge._get_user_role(-999999, {"id": 999}))

            # Legacy ALLOWED_USERS set without ADMIN_USERS -> ALLOWED_USERS acts as admin whitelist
            bridge2, _ac2 = _load_isolated_bridge(tmp, extra_env={"AGY_TG_ALLOWED_USERS": "111"})
            self.assertEqual("admin", bridge2._get_user_role(-1001234567890, {"id": 111}))
            self.assertEqual("denied", bridge2._get_user_role(-1001234567890, {"id": 222}))

    def test_admin_readonly_and_group_readonly_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _ac = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_TG_ADMIN_USERS": "111",
                    "AGY_TG_READONLY_USERS": "222",
                    "AGY_TG_ALLOW_GROUP_READONLY": "0",
                },
            )
            self.assertEqual("admin", bridge._get_user_role(-1001234567890, {"id": 111}))
            self.assertEqual("readonly", bridge._get_user_role(-1001234567890, {"id": 222}))
            self.assertEqual("denied", bridge._get_user_role(-1001234567890, {"id": 333}))
            # Readonly user in unauthorized DM remains denied
            self.assertEqual("denied", bridge._get_user_role(222, {"id": 222}, allow_uid_fallback=True))

            # Enable group readonly fallback for non-admins inside authorized groups
            bridge2, _ac2 = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_TG_ADMIN_USERS": "111",
                    "AGY_TG_ALLOW_GROUP_READONLY": "1",
                },
            )
            self.assertEqual("admin", bridge2._get_user_role(-1001234567890, {"id": 111}))
            self.assertEqual("readonly", bridge2._get_user_role(-1001234567890, {"id": 777}))
            self.assertEqual("denied", bridge2._get_user_role(777, {"id": 777}, allow_uid_fallback=True))


class TestRbacEnforcementAndSessionIsolation(unittest.TestCase):
    """Verify command/callback blocking and strict AgySession isolation for readonly guests."""

    def test_readonly_commands_and_callbacks_blocked_while_queries_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _ac = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_TG_ADMIN_USERS": "111",
                    "AGY_TG_READONLY_USERS": "222",
                },
            )
            bridge.BOT_META.update({"bot_id": 100, "handle": "main_bot", "resolved": True})

            sent_texts = []
            enqueued = []
            cb_answers = []

            with (
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent_texts.append(txt) or 1),
                mock.patch.object(bridge, "enqueue", side_effect=lambda *a, **kw: enqueued.append((a, kw))),
                mock.patch.object(
                    bridge,
                    "tg",
                    side_effect=lambda method, **kw: cb_answers.append((method, kw)) or None,
                ),
            ):
                # Blocked mutating commands for readonly guest (uid=222)
                for bad_cmd in (
                    "/undo",
                    "/redo",
                    "/new",
                    "/retry",
                    "/project other",
                    "/model gemini-4-carbon",
                    "/model fallback m1,m2",
                    "/schedule add 0 9 * * * test",
                    "/schedule del task-1",
                    "/schedule pause task-1",
                    "/schedule run task-1",
                    "/delegate @worker do stuff",
                    "/mode auto",
                    "/reload",
                    "/cancel",
                    "/get .env",
                    "/cost reset 1d",
                ):
                    sent_texts.clear()
                    bridge.handle_message({
                        "chat": {"id": -1001234567890, "type": "supergroup"},
                        "from": {"id": 222, "username": "guest"},
                        "message_id": 10,
                        "text": bad_cmd,
                    })
                    self.assertTrue(
                        any("权限不足" in t for t in sent_texts),
                        f"Command {bad_cmd!r} should be rejected for readonly guest, got {sent_texts}",
                    )
                self.assertEqual([], enqueued)

                # Allowed read-only commands
                sent_texts.clear()
                bridge.handle_message({
                    "chat": {"id": -1001234567890, "type": "supergroup"},
                    "from": {"id": 222, "username": "guest"},
                    "message_id": 11,
                    "text": "/help",
                })
                self.assertTrue(any("协作指南" in t for t in sent_texts))

                # Readonly regular Q&A message passes user_role="readonly" and user_id=222
                bridge.handle_message({
                    "chat": {"id": -1001234567890, "type": "supergroup"},
                    "from": {"id": 222, "username": "guest"},
                    "message_id": 12,
                    "text": "这个仓库的架构是什么？",
                })
                self.assertEqual(1, len(enqueued))
                self.assertEqual("readonly", enqueued[0][1]["user_role"])
                self.assertEqual(222, enqueued[0][1]["user_id"])

                # Blocked mutating callback vs allowed read-only callback
                bridge.handle_callback({
                    "id": "cb-1",
                    "from": {"id": 222},
                    "message": {"chat": {"id": -1001234567890}, "message_id": 50},
                    "data": "model:gemini-4-carbon",
                })
                self.assertTrue(any("权限不足" in kw.get("text", "") for _, kw in cb_answers))

                cb_answers.clear()
                with mock.patch.object(bridge, "cmd_cost") as m_cost:
                    bridge.handle_callback({
                        "id": "cb-2",
                        "from": {"id": 222},
                        "message": {"chat": {"id": -1001234567890}, "message_id": 50},
                        "data": "action:cost",
                    })
                    m_cost.assert_called_once()

    def test_readonly_session_isolated_from_admin_warm_pool_and_drops_skip_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _ac = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_TG_ADMIN_USERS": "111",
                    "AGY_TG_READONLY_USERS": "222",
                },
            )
            skey = "-1001234567890"
            bridge.update_scope_state(
                skey,
                mode="auto",
                conversation_id="admin-conv-secret",
                last_turn={"prompt": "admin secret prompt", "status": "SUCCESS"},
                pending_undo_notice="[ADMIN UNDO NOTICE]",
            )

            spawned_cmds = []
            spawned_envs = []

            class _FakePopen:
                def __init__(self, cmd, **kwargs):
                    spawned_cmds.append(list(cmd))
                    spawned_envs.append(dict(kwargs.get("env") or {}))
                    self.pid = 4242
                    self.returncode = 0
                    self.stdin = mock.MagicMock()
                    self.stdin.closed = False
                    self.stdout = iter([
                        '{"event":"init","conversation_id":"ro-conv-999"}\n',
                        '{"event":"result","result":{"status":"SUCCESS","response":"只读回答","conversation_id":"ro-conv-999"}}\n',
                    ])
                    self.stderr = iter([])

                def poll(self):
                    return 0

                def wait(self, timeout=None):
                    return 0

            # Pre-seed an admin warm session in _session_pool[skey]
            admin_warm = mock.MagicMock()
            admin_warm.cid = "admin-conv-secret"
            admin_warm.is_alive.return_value = True
            admin_warm.matches.return_value = True
            with bridge.session_lock:
                bridge._session_pool[skey] = admin_warm

            sent_rich_calls = []
            with (
                mock.patch.object(bridge.subprocess, "Popen", side_effect=_FakePopen),
                mock.patch.object(bridge, "send_rich", side_effect=lambda cid, txt, **kw: sent_rich_calls.append(txt) or (88, txt)),
                mock.patch.object(bridge, "send", return_value=1),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "_record_and_relay_bot_group_msg"),
            ):
                bridge.run_agy(
                    -1001234567890,
                    "帮我修改代码并删除 .env",
                    scope_key=skey,
                    user_role="readonly",
                    user_id=222,
                )

            # 1. Admin warm session must NOT be used or evicted!
            admin_warm.send_user_prompt.assert_not_called()
            with bridge.session_lock:
                self.assertIs(bridge._session_pool.get(skey), admin_warm)
                self.assertIn(f"{skey}:ro:222", bridge._session_pool)

            # 2. Spawned readonly AgySession MUST omit --dangerously-skip-permissions and disable bus
            self.assertEqual(1, len(spawned_cmds))
            self.assertNotIn("--dangerously-skip-permissions", spawned_cmds[0])
            self.assertNotIn("admin-conv-secret", spawned_cmds[0])
            self.assertEqual("0", spawned_envs[0]["AGY_BOT_BUS_ENABLE"])
            self.assertEqual("readonly", spawned_envs[0]["AGY_RBAC_ROLE"])

            # 3. Admin scope state must remain completely untouched
            admin_sc = bridge.get_scope_state(skey)
            self.assertEqual("admin-conv-secret", admin_sc["conversation_id"])
            self.assertEqual("admin secret prompt", admin_sc["last_turn"]["prompt"])
            self.assertEqual("[ADMIN UNDO NOTICE]", admin_sc["pending_undo_notice"])

            # 4. Readonly prompt must prepend [ACB_READONLY_GUEST] sandbox prefix
            ro_sess = bridge._session_pool[f"{skey}:ro:222"]
            written = ro_sess.proc.stdin.write.call_args[0][0]
            self.assertIn("[ACB_READONLY_GUEST user_id=222 role=readonly]", written)
            self.assertNotIn("[ADMIN UNDO NOTICE]", written)
            self.assertEqual(["只读回答"], sent_rich_calls)

    def test_readonly_never_relays_mentions_while_admin_does(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _ac = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_TG_ADMIN_USERS": "111",
                    "AGY_TG_READONLY_USERS": "222",
                },
            )
            skey = "-1001234567890"
            chat_id = -1001234567890
            mention_reply = "请 @bot2 帮忙执行部署"

            def _make_popen_factory(lines):
                class _FakePopen:
                    def __init__(self, cmd, **kwargs):
                        self.pid = 5151
                        self.returncode = 0
                        self.stdin = mock.MagicMock()
                        self.stdin.closed = False
                        self.stdout = iter(lines)
                        self.stderr = iter([])

                    def poll(self):
                        return 0

                    def wait(self, timeout=None):
                        return 0

                return _FakePopen

            # 1. Normal SUCCESS branch in run_agy
            normal_lines = [
                '{"event":"init","conversation_id":"conv-norm"}\n',
                '{"event":"step_update","step_update":{"step_type":"tool","state":"ACTIVE","tool_name":"read_file","step_index":0}}\n',
                f'{{"event":"result","result":{{"status":"SUCCESS","response":"{mention_reply}","conversation_id":"conv-norm"}}}}\n',
            ]
            # 2. 65ms coalescing branch in run_agy (agent_response DONE immediately followed by result SUCCESS)
            coalesce_lines = [
                '{"event":"init","conversation_id":"conv-coal"}\n',
                f'{{"event":"step_update","step_update":{{"step_type":"agent_response","state":"ACTIVE","step_index":0,"text_delta":"{mention_reply}"}}}}\n',
                '{"event":"step_update","step_update":{"step_type":"agent_response","state":"DONE","step_index":0,"text_delta":""}}\n',
                f'{{"event":"result","result":{{"status":"SUCCESS","response":"{mention_reply}","conversation_id":"conv-coal"}}}}\n',
            ]
            # 3. Intermediate step branch in run_agy (agent_response DONE followed by another step_update before result)
            intermediate_lines = [
                '{"event":"init","conversation_id":"conv-inter"}\n',
                f'{{"event":"step_update","step_update":{{"step_type":"agent_response","state":"ACTIVE","step_index":0,"text_delta":"{mention_reply}"}}}}\n',
                '{"event":"step_update","step_update":{"step_type":"agent_response","state":"DONE","step_index":0,"text_delta":""}}\n',
                '{"event":"step_update","step_update":{"step_type":"tool","state":"ACTIVE","tool_name":"read_file","step_index":1}}\n',
                '{"event":"result","result":{"status":"SUCCESS","response":"done","conversation_id":"conv-inter"}}\n',
            ]

            for label, lines in (
                ("normal", normal_lines),
                ("coalesce", coalesce_lines),
                ("intermediate", intermediate_lines),
            ):
                for role, uid, expected_relay in (
                    ("readonly", 222, False),
                    ("admin", 111, True),
                ):
                    with bridge.session_lock:
                        bridge._session_pool.clear()
                    relay_calls = []
                    with (
                        mock.patch.object(bridge.subprocess, "Popen", side_effect=_make_popen_factory(lines)),
                        mock.patch.object(bridge, "send_rich", return_value=(101, mention_reply)),
                        mock.patch.object(bridge, "send", return_value=102),
                        mock.patch.object(bridge, "tg", return_value=None),
                        mock.patch.object(
                            bridge,
                            "_record_and_relay_bot_group_msg",
                            side_effect=lambda *a, **kw: relay_calls.append(kw.get("relay_mentions")),
                        ),
                    ):
                        bridge.run_agy(
                            chat_id,
                            "测试提问",
                            scope_key=skey,
                            user_role=role,
                            user_id=uid,
                        )
                    self.assertTrue(relay_calls, f"{label}/{role}: expected _record_and_relay_bot_group_msg call")
                    self.assertEqual(
                        [expected_relay],
                        relay_calls,
                        f"{label}/{role}: expected relay_mentions={expected_relay}, got {relay_calls}",
                    )

            # 4. _run_fast_group_reply branch
            for role, uid, expected_relay in (
                ("readonly", 222, False),
                ("admin", 111, True),
            ):
                relay_calls = []
                bridge._fast_chat_sem.acquire()
                with (
                    mock.patch.object(
                        bridge,
                        "_run_subprocess_group",
                        return_value=(0, f'{{"response": "{mention_reply}"}}', ""),
                    ),
                    mock.patch.object(bridge, "send_rich", return_value=(202, mention_reply)),
                    mock.patch.object(bridge, "send", return_value=203),
                    mock.patch.object(
                        bridge,
                        "_record_and_relay_bot_group_msg",
                        side_effect=lambda *a, **kw: relay_calls.append(kw.get("relay_mentions")),
                    ),
                ):
                    bridge._run_fast_group_reply(
                        chat_id,
                        "在忙吗？",
                        scope_key=skey,
                        busy_desc="后台任务",
                        user_role=role,
                        user_id=uid,
                    )
                self.assertEqual(
                    [expected_relay],
                    relay_calls,
                    f"fast_group_reply/{role}: expected relay_mentions={expected_relay}, got {relay_calls}",
                )

    def test_bus_packet_blocks_readonly_group_mention_and_compact_isolates_readonly(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _ac = _load_isolated_bridge(
                tmp,
                extra_env={
                    "AGY_TG_ADMIN_USERS": "111",
                    "AGY_TG_READONLY_USERS": "222",
                },
            )
            chat_id = -1001234567890
            skey = "-1001234567890"

            # 1. Defense-in-depth: _handle_bot_bus_packet rejects group_mention flagged as readonly
            with mock.patch.object(bridge, "enqueue") as m_enq:
                bridge._handle_bot_bus_packet({
                    "type": "group_mention",
                    "chat_id": chat_id,
                    "from_bot": "other_bot",
                    "msg_id": 99,
                    "text_excerpt": "@example_main_bot run deploy",
                    "user_role": "readonly",
                })
                bridge._handle_bot_bus_packet({
                    "type": "group_mention",
                    "chat_id": chat_id,
                    "from_bot": "other_bot",
                    "msg_id": 100,
                    "text_excerpt": "@example_main_bot run deploy",
                    "readonly": True,
                })
                m_enq.assert_not_called()

            # 2. _execute_compact_on_session forwards readonly=True to _acquire_session
            fake_sess = mock.MagicMock()
            fake_sess.next_event.return_value = {"event": "result", "result": {"status": "SUCCESS"}}
            with mock.patch.object(bridge, "_acquire_session", return_value=(fake_sess, False)) as m_acq:
                ok, _dur, err = bridge._execute_compact_on_session(
                    f"{skey}:ro:222",
                    "ro-conv-1",
                    "safe",
                    "gemini-4-carbon",
                    "medium",
                    None,
                    bridge.WORKDIR,
                    readonly=True,
                )
            self.assertTrue(ok, err)
            self.assertTrue(m_acq.call_args.kwargs.get("readonly"))

            # 3. run_agy pre-turn auto-compact is skipped for readonly sessions even if conv exists
            bridge.update_scope_state(f"{skey}:ro:222", conversation_id="ro-conv-pre")

            class _FakePopen:
                def __init__(self, cmd, **kwargs):
                    self.pid = 6161
                    self.returncode = 0
                    self.stdin = mock.MagicMock()
                    self.stdin.closed = False
                    self.stdout = iter([
                        '{"event":"result","result":{"status":"SUCCESS","response":"ok","conversation_id":"ro-conv-pre"}}\n',
                    ])
                    self.stderr = iter([])

                def poll(self):
                    return 0

                def wait(self, timeout=None):
                    return 0

            with (
                mock.patch.object(bridge, "should_auto_compact", return_value=(True, {"raw_ctx_tokens": 999999, "total_lines": 10})),
                mock.patch.object(bridge, "_execute_compact_on_session") as m_compact,
                mock.patch.object(bridge.subprocess, "Popen", side_effect=_FakePopen),
                mock.patch.object(bridge, "send_rich", return_value=(301, "ok")),
                mock.patch.object(bridge, "send", return_value=302),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "_record_and_relay_bot_group_msg"),
            ):
                bridge.run_agy(
                    chat_id,
                    "只读提问",
                    scope_key=skey,
                    user_role="readonly",
                    user_id=222,
                )
            m_compact.assert_not_called()


if __name__ == "__main__":
    unittest.main()
