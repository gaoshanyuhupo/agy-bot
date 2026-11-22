#!/usr/bin/env python3
"""Offline unit tests for on-demand group access (`/group`), env gating, and unjoined-group command cleanup."""

from __future__ import annotations

import importlib
import os
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

ADMIN_UID = 700_000_000 + 101
GUEST_UID = ADMIN_UID + 1
GROUP_A = -(100_000_000_0000 + 4201)
GROUP_B = GROUP_A - 1


def _load_isolated_bridge(tmp: str, extra_env: dict[str, str] | None = None):
    env_patch = {
        "AGY_BOT_BUS_DIR": os.path.join(tmp, "bus"),
        "AGY_TG_STATE_FILE": os.path.join(tmp, "state.json"),
        "AGY_MEMORY_TAINT_FILE": os.path.join(tmp, "memory_taint.json"),
        "AGY_TG_WORKDIR": os.path.join(tmp, "workdir"),
        "AGY_TG_LOCK_DIR": os.path.join(tmp, "locks"),
        "AGY_TG_ALLOWED_CHATS": str(ADMIN_UID),
        "AGY_TG_GROUP_CHATS": str(GROUP_A),
        "AGY_TG_ALLOW_GROUPS": "0",
        "AGY_TG_ALLOWED_USERS": str(ADMIN_UID),
        "AGY_TG_ADMIN_USERS": str(ADMIN_UID),
        "AGY_TG_READONLY_USERS": str(GUEST_UID),
        "AGY_TG_ALLOW_GROUP_READONLY": "0",
        "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_GROUP_TOGGLE_TEST_TOKEN_01",
        "AGY_TG_ENV_FILE": os.path.join(tmp, "nonexistent.env"),
        "AGY_TG_BOT_ROLE": "worker",
        "AGY_TG_BOT_MODEL": "",
        "AGY_TG_BOT_EFFORT": "",
        "AGY_TG_BOT_PROJECT": "",
        "AGY_TG_FALLBACK_MODELS": "",
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
        bridge.BOT_META.update({"bot_id": 123456789, "handle": "standalone_test_bot", "resolved": True})
        return bridge


class TestOnDemandGroupAccess(unittest.TestCase):
    def test_dm_only_default_blocks_group_messages_and_callbacks_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            self.assertFalse(bridge._is_groups_enabled())
            self.assertEqual({ADMIN_UID}, bridge.ALLOWED)
            self.assertEqual({GROUP_A}, bridge._configured_group_chats())
            self.assertEqual("admin", bridge._get_user_role(ADMIN_UID, {"id": ADMIN_UID}))
            self.assertEqual("denied", bridge._get_user_role(GROUP_A, {"id": ADMIN_UID}))

            enqueued = []
            tg_calls = []
            with (
                mock.patch.object(bridge, "enqueue", side_effect=lambda *a, **kw: enqueued.append((a, kw))),
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: tg_calls.append((m, kw)) or None),
            ):
                # Group message from admin MUST be rejected while groups are off
                bridge.handle_message({
                    "chat": {"id": GROUP_A, "type": "supergroup"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 10,
                    "text": "hello group",
                })
                self.assertEqual([], enqueued)

                # Group inline callback from admin MUST also be rejected (no uid fallback bypass in groups!)
                bridge.handle_callback({
                    "id": "cb-group-denied",
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message": {"chat": {"id": GROUP_A, "type": "supergroup"}, "message_id": 11},
                    "data": "action:status",
                })
                self.assertTrue(
                    any(m == "answerCallbackQuery" and kw.get("text") == "Unauthorized" for m, kw in tg_calls),
                    f"Expected Unauthorized callback answer, got {tg_calls}",
                )

    def test_dm_group_on_off_persists_across_reload_and_evicts_group_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            sent = []
            evicted = []
            with (
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append((cid, txt)) or 1),
                mock.patch.object(bridge, "register_bot_commands_async"),
                mock.patch.object(bridge, "invalidate_session", side_effect=lambda reason, **kw: evicted.append((reason, kw))),
            ):
                # 1. Admin turns on groups from DM -> activates standby GROUP_A
                bridge.handle_message({
                    "chat": {"id": ADMIN_UID, "type": "private"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 20,
                    "text": "/group on",
                })
                self.assertTrue(bridge._is_groups_enabled())
                self.assertEqual({ADMIN_UID, GROUP_A}, bridge.ALLOWED)
                self.assertEqual("admin", bridge._get_user_role(GROUP_A, {"id": ADMIN_UID}))

                # 2. Reload bridge from same STATE_FILE -> runtime toggle persists!
            bridge = _load_isolated_bridge(tmp)
            self.assertTrue(bridge._is_groups_enabled())
            self.assertEqual({ADMIN_UID, GROUP_A}, bridge.ALLOWED)

            with (
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append((cid, txt)) or 1),
                mock.patch.object(bridge, "tg", return_value=mock.MagicMock(status_code=200, json=lambda: {"ok": True})),
                mock.patch.object(bridge, "register_bot_commands_async"),
                mock.patch.object(bridge, "invalidate_session", side_effect=lambda reason, **kw: evicted.append((reason, kw))),
            ):
                # 3. Admin adds GROUP_B via `/group on <id>` and rejects positive IDs
                sent.clear()
                bridge.handle_message({
                    "chat": {"id": ADMIN_UID, "type": "private"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 21,
                    "text": f"/group on {GUEST_UID}",
                })
                self.assertNotIn(GUEST_UID, bridge.ALLOWED)
                self.assertTrue(any("负整数" in txt for _, txt in sent))

                bridge.handle_message({
                    "chat": {"id": ADMIN_UID, "type": "private"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 22,
                    "text": f"/group on {GROUP_B}",
                })
                self.assertEqual({ADMIN_UID, GROUP_A, GROUP_B}, bridge.ALLOWED)

                # 3b. Remove runtime GROUP_B cleanly
                bridge.handle_message({
                    "chat": {"id": ADMIN_UID, "type": "private"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 220,
                    "text": f"/group remove {GROUP_B}",
                })
                self.assertEqual({ADMIN_UID, GROUP_A}, bridge.ALLOWED)

                # 4. Plant warm sessions (DM + Group) and turn off groups -> evicts group only
                bridge._session_pool[str(ADMIN_UID)] = mock.MagicMock()
                bridge._session_pool[str(GROUP_A)] = mock.MagicMock()
                bridge.handle_message({
                    "chat": {"id": ADMIN_UID, "type": "private"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 23,
                    "text": "/group off",
                })
                self.assertFalse(bridge._is_groups_enabled())
                self.assertEqual({ADMIN_UID}, bridge.ALLOWED)
                self.assertEqual([("cmd_group_off", {"scope_key": str(GROUP_A)})], evicted)

                # 4b. DM inline callback `group:on` -> enables again; `group:reset` -> returns to env default (off)
                bridge.handle_callback({
                    "id": "cb-dm-on",
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message": {"chat": {"id": ADMIN_UID, "type": "private"}, "message_id": 24},
                    "data": "group:on",
                })
                self.assertTrue(bridge._is_groups_enabled())
                self.assertEqual({ADMIN_UID, GROUP_A}, bridge.ALLOWED)

                bridge.handle_callback({
                    "id": "cb-dm-reset",
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message": {"chat": {"id": ADMIN_UID, "type": "private"}, "message_id": 25},
                    "data": "group:reset",
                })
                self.assertFalse(bridge._is_groups_enabled())
                self.assertEqual({ADMIN_UID}, bridge.ALLOWED)

            # 5. Reload after off/reset -> still DM-only
            bridge_off = _load_isolated_bridge(tmp)
            self.assertFalse(bridge_off._is_groups_enabled())
            self.assertEqual({ADMIN_UID}, bridge_off.ALLOWED)

    def test_group_mutations_blocked_in_group_chat_and_for_readonly_users(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(
                tmp,
                extra_env={"AGY_TG_ALLOW_GROUPS": "1"},
            )
            sent = []
            tg_calls = []
            with (
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append((cid, txt)) or 1),
                mock.patch.object(bridge, "tg", side_effect=lambda m, **kw: tg_calls.append((m, kw)) or None),
                mock.patch.object(bridge, "register_bot_commands_async"),
            ):
                # Admin trying `/group off` inside group chat MUST be blocked (DM-only mutation)
                bridge.handle_message({
                    "chat": {"id": GROUP_A, "type": "supergroup"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 30,
                    "text": "/group off",
                })
                self.assertTrue(bridge._is_groups_enabled())
                self.assertTrue(any("仅限管理员私聊" in txt for _, txt in sent))

                # Readonly guest trying `/group` in group MUST be denied by RBAC
                sent.clear()
                bridge.handle_message({
                    "chat": {"id": GROUP_A, "type": "supergroup"},
                    "from": {"id": GUEST_UID, "username": "guest"},
                    "message_id": 31,
                    "text": "/group off",
                })
                self.assertTrue(bridge._is_groups_enabled())
                self.assertTrue(any("权限不足" in txt for _, txt in sent))

                # Callback `group:off` inside group chat MUST be denied
                bridge.handle_callback({
                    "id": "cb-grp-mut",
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message": {"chat": {"id": GROUP_A, "type": "supergroup"}, "message_id": 32},
                    "data": "group:off",
                })
                self.assertTrue(bridge._is_groups_enabled())
                self.assertTrue(
                    any(m == "answerCallbackQuery" and "仅限管理员私聊" in str(kw.get("text", "")) for m, kw in tg_calls)
                )

    def test_register_bot_commands_skips_unjoined_group_chat_not_found_and_backs_off_429(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(
                tmp,
                extra_env={"AGY_TG_ALLOW_GROUPS": "1", "AGY_TG_BOT_ROLE": "worker"},
            )
            bridge._LAST_REGISTERED_CMD_ROLE = None
            bridge._LAST_REGISTERED_CMD_GROUPS = None

            resp_ok = mock.MagicMock(status_code=200, json=lambda: {"ok": True})
            resp_chat_not_found = mock.MagicMock(
                status_code=400,
                json=lambda: {"ok": False, "error_code": 400, "description": "Bad Request: chat not found"},
            )
            resp_429 = mock.MagicMock(
                status_code=429,
                json=lambda: {"ok": False, "error_code": 429, "parameters": {"retry_after": 180}},
            )

            # 1. Explicit `chat not found` on negative group ID does NOT block command registration or cause retry storms
            calls = []

            def _tg_unjoined(method, **kw):
                calls.append((method, kw.get("scope")))
                sc = kw.get("scope") or {}
                if method == "deleteMyCommands" and sc.get("chat_id") == GROUP_A:
                    return resp_chat_not_found
                return resp_ok

            with mock.patch.object(bridge, "tg", side_effect=_tg_unjoined):
                self.assertTrue(bridge.register_bot_commands(force=True))
                self.assertEqual("worker", bridge._LAST_REGISTERED_CMD_ROLE)
                self.assertTrue(bridge._LAST_REGISTERED_CMD_GROUPS)
                # Should not call chat_administrators after `chat` already reported chat not found
                self.assertNotIn(("deleteMyCommands", {"type": "chat_administrators", "chat_id": GROUP_A}), calls)

            # 2. HTTP 429 records retry_after backoff into `_cmd_reg_next_retry_ts`
            before = time.time()
            with mock.patch.object(bridge, "tg", return_value=resp_429):
                self.assertFalse(bridge.register_bot_commands(force=True))
                self.assertGreaterEqual(bridge._cmd_reg_next_retry_ts, before + 180)

    def test_dm_only_mode_omits_group_ids_from_command_cleanup_and_clears_all_group_chats(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(
                tmp,
                extra_env={"AGY_TG_ALLOW_GROUPS": "0", "AGY_TG_BOT_ROLE": "coordinator"},
            )
            resp_ok = mock.MagicMock(status_code=200, json=lambda: {"ok": True})
            calls = []

            def _tg_rec(method, **kw):
                calls.append((method, kw.get("scope")))
                return resp_ok

            with mock.patch.object(bridge, "tg", side_effect=_tg_rec):
                self.assertTrue(bridge.register_bot_commands(force=True))
            # Never touches unjoined/disabled GROUP_A and deletes `all_group_chats` even for coordinator
            self.assertFalse(any((sc or {}).get("chat_id") == GROUP_A for _, sc in calls))
            self.assertIn(("deleteMyCommands", {"type": "all_group_chats"}), calls)
            self.assertNotIn(("setMyCommands", {"type": "all_group_chats"}), calls)

    def test_group_remove_evicts_only_removed_group_and_topic_sessions(self):
        group_c = GROUP_B - 1
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_TG_ALLOW_GROUPS": "1"})
            sent = []
            evicted = []
            with (
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append((cid, txt)) or 1),
                mock.patch.object(bridge, "register_bot_commands_async"),
                mock.patch.object(bridge, "invalidate_session", side_effect=lambda reason, **kw: evicted.append((reason, kw))),
            ):
                # Add runtime GROUP_B and group_c while GROUP_A (env) is also active
                bridge.handle_message({
                    "chat": {"id": ADMIN_UID, "type": "private"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 40,
                    "text": f"/group on {GROUP_B} {group_c}",
                })
                self.assertEqual({ADMIN_UID, GROUP_A, GROUP_B, group_c}, bridge.ALLOWED)

                # Plant warm sessions across DM, GROUP_A (+topic), GROUP_B (+topic +ro), and group_c
                bridge._session_pool[str(ADMIN_UID)] = mock.MagicMock()
                bridge._session_pool[str(GROUP_A)] = mock.MagicMock()
                bridge._session_pool[f"{GROUP_A}:55"] = mock.MagicMock()
                bridge._session_pool[str(GROUP_B)] = mock.MagicMock()
                bridge._session_pool[f"{GROUP_B}:12"] = mock.MagicMock()
                bridge._session_pool[f"{GROUP_B}:ro:{GUEST_UID}"] = mock.MagicMock()
                bridge._session_pool[str(group_c)] = mock.MagicMock()

                # Remove GROUP_B -> groups remain enabled, ONLY GROUP_B + its topic/ro scopes are evicted
                evicted.clear()
                bridge.handle_message({
                    "chat": {"id": ADMIN_UID, "type": "private"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 41,
                    "text": f"/group remove {GROUP_B}",
                })
                self.assertTrue(bridge._is_groups_enabled())
                self.assertEqual({ADMIN_UID, GROUP_A, group_c}, bridge.ALLOWED)
                evicted_scopes = {kw.get("scope_key") for reason, kw in evicted if reason == "cmd_group_remove"}
                self.assertEqual(
                    {str(GROUP_B), f"{GROUP_B}:12", f"{GROUP_B}:ro:{GUEST_UID}"},
                    evicted_scopes,
                )
                self.assertEqual(3, len(evicted))

    def test_flush_album_drops_buffered_album_after_group_off_or_group_remove(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"AGY_TG_ALLOW_GROUPS": "1"})
            sent = []
            enqueued = []
            recorded = []
            with (
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent.append((cid, txt)) or 1),
                mock.patch.object(bridge, "enqueue", side_effect=lambda *a, **kw: enqueued.append((a, kw))),
                mock.patch.object(bridge, "register_bot_commands_async"),
                mock.patch.object(bridge.bot_bus, "record_group_message", side_effect=lambda *a, **kw: recorded.append((a, kw))),
            ):
                # 1. Add runtime GROUP_B alongside GROUP_A, buffer albums in both
                bridge.handle_message({
                    "chat": {"id": ADMIN_UID, "type": "private"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 50,
                    "text": f"/group on {GROUP_B}",
                })
                akey_b = f"{GROUP_B}:mg-b"
                akey_a = f"{GROUP_A}:mg-a"
                with bridge._album_lock:
                    bridge._album_buffers[akey_b] = {
                        "chat_id": GROUP_B,
                        "thread_id": None,
                        "scope_key": str(GROUP_B),
                        "first_msg_id": 501,
                        "sender_handle": "admin",
                        "batch_pending": 0,
                        "downloading": 0,
                        "items": [{"dest": "/tmp/img_b.jpg", "meta": "photo"}],
                        "captions": ["album b"],
                        "reply_ctxs": [],
                        "errors": [],
                        "timer": None,
                    }
                    bridge._album_buffers[akey_a] = {
                        "chat_id": GROUP_A,
                        "thread_id": None,
                        "scope_key": str(GROUP_A),
                        "first_msg_id": 502,
                        "sender_handle": "admin",
                        "batch_pending": 0,
                        "downloading": 0,
                        "items": [{"dest": "/tmp/img_a.jpg", "meta": "photo"}],
                        "captions": ["album a"],
                        "reply_ctxs": [],
                        "errors": [],
                        "timer": None,
                    }

                # Remove GROUP_B before its debounce timer fires -> GROUP_B album MUST be dropped
                bridge.handle_message({
                    "chat": {"id": ADMIN_UID, "type": "private"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 51,
                    "text": f"/group remove {GROUP_B}",
                })
                sent.clear()
                enqueued.clear()
                recorded.clear()

                bridge._flush_album(akey_b)
                self.assertEqual([], sent)
                self.assertEqual([], enqueued)
                self.assertEqual([], recorded)
                self.assertNotIn(akey_b, bridge._album_buffers)

                # Still-authorized GROUP_A album flushes normally
                bridge._flush_album(akey_a)
                self.assertEqual(1, len(enqueued))
                self.assertEqual(1, len(recorded))

                # 2. Buffer another GROUP_A album, then execute `/group off` before flush -> MUST drop
                akey_a2 = f"{GROUP_A}:mg-a2"
                with bridge._album_lock:
                    bridge._album_buffers[akey_a2] = {
                        "chat_id": GROUP_A,
                        "thread_id": None,
                        "scope_key": str(GROUP_A),
                        "first_msg_id": 503,
                        "sender_handle": "admin",
                        "batch_pending": 0,
                        "downloading": 0,
                        "items": [],
                        "captions": [],
                        "reply_ctxs": [],
                        "errors": ["download timeout"],
                        "timer": None,
                    }
                bridge.handle_message({
                    "chat": {"id": ADMIN_UID, "type": "private"},
                    "from": {"id": ADMIN_UID, "username": "admin"},
                    "message_id": 52,
                    "text": "/group off",
                })
                sent.clear()
                enqueued.clear()
                recorded.clear()

                bridge._flush_album(akey_a2)
                self.assertEqual([], sent)
                self.assertEqual([], enqueued)
                self.assertEqual([], recorded)
                self.assertNotIn(akey_a2, bridge._album_buffers)


if __name__ == "__main__":
    unittest.main()
