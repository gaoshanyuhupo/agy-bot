#!/usr/bin/env python3
"""Offline unit & security tests for `bridge/federation_tg_bridge.py` (F1..F8 + M1..M4).

Zero real network, Telegram, or OpenBao calls: all HTTP traffic, OpenBao secret
resolution, filesystem state, and monotonic clocks are isolated in temporary
directories with deterministic mocks.
"""

from __future__ import annotations

import fcntl
import html as html_mod
import io
import json
import logging
import os
import signal
import stat
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "bridge"
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (str(BRIDGE_DIR), str(SCRIPTS_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import bot_bus  # noqa: E402
import federation_registry  # noqa: E402
import federation_tg_bridge as ftb  # noqa: E402

# Safe synthetic identifiers matching `scripts/security_audit.py` SAFE_EXAMPLE_IDS & SAFE_AT_TOKENS
OWNER_UID = 123456789
OTHER_UID = 987654321
BOT_UID = 111111111
GROUP_ALLOWED = -1001234567890
GROUP_DENIED = -123456789
GROUP_DYNAMIC = -1001234567890
BOT_USERNAME = "your_bot"
OTHER_BOT_USERNAME = "your_bot_2"
EXAMPLE_AGENT_ID = "worker_pull_01"
EXAMPLE_SECRET_REF = "lv" + "1/services/example-bot#token"


def _make_fake_token(prefix: str = "123456789") -> str:
    return f"{prefix}:{'MOCK_TOKEN_'}{'a' * 22}"


def _make_other_token() -> str:
    return f"{'987654321'}:{'MOCK_OTHER_'}{'b' * 22}"


class MockTelegramTransport:
    """In-memory mock Telegram Bot API client recording every call."""

    def __init__(self, *, bot_id: int = BOT_UID, bot_username: str = BOT_USERNAME):
        self.bot_id = bot_id
        self.bot_username = bot_username
        self.calls: List[Tuple[str, Dict[str, Any]]] = []
        self._lock = threading.Lock()
        self._msg_seq = 100
        self.pending_updates: List[List[Dict[str, Any]]] = []
        self.fail_html_once_send = False
        self.fail_html_once_edit = False
        self.fail_not_modified_edit = False
        self.fail_reply_not_found_once_send: Optional[str] = None
        self.fail_edit_missing_once: Optional[str] = None
        self.send_error_queue: List[Exception] = []
        self.edit_error_queue: List[Exception] = []

    def _record(self, method: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self.calls.append((method, dict(payload)))

    def get_calls(self, method: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if method is None:
                return [dict(p) for _, p in self.calls]
            return [dict(p) for m, p in self.calls if m == method]

    def get_me(self) -> Dict[str, Any]:
        self._record("getMe", {})
        return {"id": self.bot_id, "is_bot": True, "username": self.bot_username}

    def get_updates(
        self,
        *,
        offset: Optional[int] = None,
        timeout: int = 25,
        allowed_updates=("message",),
    ) -> List[Dict[str, Any]]:
        self._record("getUpdates", {"offset": offset, "timeout": timeout, "allowed_updates": list(allowed_updates)})
        with self._lock:
            if self.pending_updates:
                return self.pending_updates.pop(0)
        return []

    def send_chat_action(
        self,
        chat_id: int,
        action: str = "typing",
        *,
        message_thread_id: Optional[int] = None,
    ) -> bool:
        rec: Dict[str, Any] = {"chat_id": chat_id, "action": action}
        if message_thread_id is not None:
            rec["message_thread_id"] = message_thread_id
        self._record("sendChatAction", rec)
        return True

    def send_message(
        self,
        chat_id: int,
        text: str,
        *,
        parse_mode: Optional[str] = None,
        reply_to_message_id: Optional[int] = None,
        message_thread_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        rec: Dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "reply_to_message_id": reply_to_message_id,
        }
        if message_thread_id is not None:
            rec["message_thread_id"] = message_thread_id
        self._record("sendMessage", rec)
        if self.send_error_queue:
            raise self.send_error_queue.pop(0)
        if reply_to_message_id is not None and self.fail_reply_not_found_once_send:
            desc = self.fail_reply_not_found_once_send
            self.fail_reply_not_found_once_send = None
            raise ftb.TelegramAPIError(
                f"Telegram API sendMessage failed (HTTP 400): {desc}",
                status_code=400,
                description=desc,
                method="sendMessage",
            )
        if parse_mode == "HTML" and self.fail_html_once_send:
            self.fail_html_once_send = False
            raise ftb.TelegramAPIError(
                "Telegram API sendMessage failed (HTTP 400): Bad Request: can't parse entities",
                status_code=400,
                description="Bad Request: can't parse entities",
                method="sendMessage",
            )
        with self._lock:
            self._msg_seq += 1
            mid = self._msg_seq
        return {"message_id": mid, "chat": {"id": chat_id}, "text": text}

    def edit_message_text(
        self,
        chat_id: int,
        message_id: int,
        text: str,
        *,
        parse_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._record(
            "editMessageText",
            {
                "chat_id": chat_id,
                "message_id": message_id,
                "text": text,
                "parse_mode": parse_mode,
            },
        )
        if self.edit_error_queue:
            raise self.edit_error_queue.pop(0)
        if self.fail_edit_missing_once:
            desc = self.fail_edit_missing_once
            self.fail_edit_missing_once = None
            raise ftb.TelegramAPIError(
                f"Telegram API editMessageText failed (HTTP 400): {desc}",
                status_code=400,
                description=desc,
                method="editMessageText",
            )
        if self.fail_not_modified_edit:
            self.fail_not_modified_edit = False
            raise ftb.TelegramAPIError(
                "Telegram API editMessageText failed (HTTP 400): Bad Request: message is not modified",
                status_code=400,
                description="Bad Request: message is not modified",
                method="editMessageText",
            )
        if parse_mode == "HTML" and self.fail_html_once_edit:
            self.fail_html_once_edit = False
            raise ftb.TelegramAPIError(
                "Telegram API editMessageText failed (HTTP 400): Bad Request: can't parse entities",
                status_code=400,
                description="Bad Request: can't parse entities",
                method="editMessageText",
            )
        return {"message_id": message_id, "chat": {"id": chat_id}, "text": text}


def _make_update(
    update_id: int,
    *,
    chat_id: int = OWNER_UID,
    chat_type: str = "private",
    from_user: Optional[Dict[str, Any]] = None,
    include_from: bool = True,
    sender_chat: Optional[Dict[str, Any]] = None,
    text: str = "hello",
    reply_to_message: Optional[Dict[str, Any]] = None,
    message_id: Optional[int] = None,
    is_forum: Optional[bool] = None,
    is_topic_message: Optional[bool] = None,
    message_thread_id: Any = None,
    date: Optional[int] = None,
) -> Dict[str, Any]:
    chat_obj: Dict[str, Any] = {"id": chat_id, "type": chat_type}
    if is_forum is not None:
        chat_obj["is_forum"] = is_forum
    msg: Dict[str, Any] = {
        "message_id": message_id if message_id is not None else update_id * 10,
        "chat": chat_obj,
        "text": text,
    }
    if is_topic_message is not None:
        msg["is_topic_message"] = is_topic_message
    if message_thread_id is not None:
        msg["message_thread_id"] = message_thread_id
    if date is not None:
        msg["date"] = date
    if include_from:
        msg["from"] = (
            from_user
            if from_user is not None
            else {"id": OWNER_UID, "is_bot": False, "username": "owner_user"}
        )
    if sender_chat is not None:
        msg["sender_chat"] = sender_chat
    if reply_to_message is not None:
        msg["reply_to_message"] = reply_to_message
    return {"update_id": update_id, "message": msg}


def _register_pull_agent(
    bus_dir: str,
    agent_id: str = EXAMPLE_AGENT_ID,
    *,
    enabled: bool = True,
    transport: str = "pull_worker",
    can_receive: bool = True,
) -> Tuple[Dict[str, Any], str]:
    owner_auth = federation_registry.make_owner_auth("test_owner", env={})
    rec = federation_registry.register_agent(
        agent_id,
        kind="muse_remote",
        driver="pull_worker",
        transport=transport,
        capabilities={"can_receive": can_receive, "can_dispatch": False},
        enabled=enabled,
        overwrite=True,
        owner_auth=owner_auth,
        bus_dir=bus_dir,
        env={},
    )
    tok = federation_registry.mint_agent_token(
        agent_id,
        label="test_pull_worker",
        owner_auth=owner_auth,
        bus_dir=bus_dir,
        env={},
    )
    return rec, tok["token"]


def _count_pull_queue_jobs(bus_dir: str) -> int:
    qdir = federation_registry.pull_queue_dir(bus_dir)
    if not os.path.isdir(qdir):
        return 0
    return len([f for f in os.listdir(qdir) if f.endswith(".json") and not f.endswith(".tmp")])


class _BridgeTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="fed_tg_bridge_test_")
        self.root = Path(self._tmp.name)
        self.bus_dir = str(self.root / "bus")
        self.state_dir = str(self.root / "state")
        self.sentinel = str(self.root / "reload.sentinel")
        self.token = _make_fake_token()
        self.clean_env: Dict[str, str] = {}
        _, self.worker_token = _register_pull_agent(self.bus_dir, EXAMPLE_AGENT_ID)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _build_bridge(
        self,
        *,
        allowed_chats: Tuple[int, ...] = (),
        denied_chats: Tuple[int, ...] = (),
        owner_users: Tuple[int, ...] = (OWNER_UID,),
        job_timeout_sec: float = 300.0,
        job_poll_interval_sec: float = 0.01,
        clock=None,
        sleep_fn=None,
        env: Optional[Dict[str, str]] = None,
    ) -> Tuple[ftb.FederationTelegramBridge, MockTelegramTransport]:
        cfg = ftb.BridgeConfig(
            agent_id=EXAMPLE_AGENT_ID,
            bot_token=self.token,
            owner_users=frozenset(owner_users),
            allowed_chats=frozenset(allowed_chats),
            denied_chats=frozenset(denied_chats),
            state_dir=self.state_dir,
            reload_sentinel=self.sentinel,
            bus_dir=self.bus_dir,
            job_timeout_sec=job_timeout_sec,
            job_poll_interval_sec=job_poll_interval_sec,
            typing_refresh_sec=4.5,
        )
        client = MockTelegramTransport()
        bridge = ftb.FederationTelegramBridge(
            cfg,
            client=client,
            clock=clock or time.monotonic,
            sleep_fn=sleep_fn,
            env=self.clean_env if env is None else env,
        )
        return bridge, client


# ===========================================================================
# F1: Secret Resolution & Zero-Leak Scrubbing
# ===========================================================================
class TestF1SecretResolutionAndScrubbing(_BridgeTestBase):
    def test_f1_secret_ref_fail_closed_and_no_silent_fallback(self) -> None:
        fallback_token = _make_fake_token()

        # 1) Plaintext token passed in SECRET_REF -> fail closed even if BOT_TOKEN exists
        for bad_ref in (fallback_token, "lv" + "1/../evil#token", "invalid/mount/item#token"):
            env = {
                "AGY_FED_TG_AGENT_ID": EXAMPLE_AGENT_ID,
                "AGY_FED_TG_OWNER_USERS": str(OWNER_UID),
                "AGY_FED_TG_TOKEN_SECRET_REF": bad_ref,
                "AGY_FED_TG_BOT_TOKEN": fallback_token,
            }
            with self.assertRaises(ValueError):
                ftb.load_config(env)

        # 2) Valid ref but resolver raises -> fail closed (NEVER falls back to BOT_TOKEN)
        env_valid_ref = {
            "AGY_FED_TG_AGENT_ID": EXAMPLE_AGENT_ID,
            "AGY_FED_TG_OWNER_USERS": str(OWNER_UID),
            "AGY_FED_TG_TOKEN_SECRET_REF": EXAMPLE_SECRET_REF,
            "AGY_FED_TG_BOT_TOKEN": fallback_token,
        }
        with self.assertRaises(RuntimeError):
            ftb.load_config(env_valid_ref, secret_resolver=lambda _r: (_ for _ in ()).throw(RuntimeError("vault down")))

        # 3) Valid ref but resolver returns empty/whitespace -> fail closed
        with self.assertRaises(RuntimeError):
            ftb.load_config(env_valid_ref, secret_resolver=lambda _r: "   ")

        # 4) Valid ref resolves cleanly
        cfg = ftb.load_config(env_valid_ref, secret_resolver=lambda _r: fallback_token)
        self.assertEqual(cfg.bot_token, fallback_token)
        self.assertNotIn(fallback_token, repr(cfg))

        # 5) Only when SECRET_REF is empty/unset is BOT_TOKEN fallback allowed
        env_fallback_only = {
            "AGY_FED_TG_AGENT_ID": EXAMPLE_AGENT_ID,
            "AGY_FED_TG_OWNER_USERS": str(OWNER_UID),
            "AGY_FED_TG_TOKEN_SECRET_REF": "",
            "AGY_FED_TG_BOT_TOKEN": fallback_token,
        }
        cfg2 = ftb.load_config(env_fallback_only)
        self.assertEqual(cfg2.bot_token, fallback_token)

    def test_f1_urllib_error_logs_replies_and_metadata_zero_token_leak(self) -> None:
        raw_token = _make_fake_token()
        other_token = _make_other_token()
        leaked_url = "https://api.telegram.org/" + "bot" + raw_token + "/sendMessage"
        other_url = "https://api.telegram.org/" + "bot" + other_token + "/getMe"

        # 1) URLError carrying raw token URL -> TelegramAPIError must scrub completely
        def _boom_url(_req, timeout=30.0):
            raise urllib.error.URLError(f"connection refused to {leaked_url} and {other_url}")

        client_err = ftb.TelegramClient(raw_token, urlopen_fn=_boom_url)
        self.assertNotIn(raw_token, repr(client_err))
        with self.assertRaises(ftb.TelegramAPIError) as ctx:
            client_err.send_message(OWNER_UID, "hi")
        self.assertNotIn(raw_token, str(ctx.exception))
        self.assertNotIn(other_token, str(ctx.exception))
        self.assertIn("[REDACTED]", str(ctx.exception))

        # 2) HTTPError carrying token in body -> scrubbed
        def _boom_http(req, timeout=30.0):
            body = json.dumps({"ok": False, "description": f"Bad call {leaked_url}"}).encode("utf-8")
            raise urllib.error.HTTPError(req.full_url, 500, "Server Error", hdrs={}, fp=io.BytesIO(body))

        client_http = ftb.TelegramClient(raw_token, urlopen_fn=_boom_http)
        with self.assertRaises(ftb.TelegramAPIError) as ctx2:
            client_http.send_message(OWNER_UID, "hi")
        self.assertNotIn(raw_token, str(ctx2.exception))

        # 3) Log redaction filter strips token from emitted records
        buf = io.StringIO()
        test_logger = logging.getLogger("test.f1.redaction")
        test_logger.handlers.clear()
        test_logger.propagate = False
        handler = logging.StreamHandler(buf)
        handler.addFilter(ftb.RedactingLogFilter(raw_token))
        test_logger.addHandler(handler)
        test_logger.error("Failed calling %s with %s", leaked_url, other_url)
        logged = buf.getvalue()
        self.assertNotIn(raw_token, logged)
        self.assertNotIn(other_token, logged)
        self.assertIn("[REDACTED]", logged)

        # 4) Worker reply & metadata scrubbing + zero token persistence on disk
        bridge, mock_client = self._build_bridge()
        bridge.startup()
        try:
            meta = ftb.scrub_metadata(
                {"note": f"url={leaked_url}", "bot_token": raw_token, "nested": [other_url]},
                bot_token=raw_token,
            )
            self.assertNotIn("bot_token", meta)
            self.assertNotIn(raw_token, json.dumps(meta))
            self.assertNotIn(other_token, json.dumps(meta))

            bridge.handle_update(
                _make_update(1, chat_id=OWNER_UID, text=f"check secrets {raw_token} {other_url}")
            )
            claimed = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(claimed)
            # Bridge scrubbed prompt and metadata before PullWorkerQueue.enqueue
            self.assertNotIn(raw_token, claimed["prompt"])
            self.assertNotIn(other_token, claimed["prompt"])
            self.assertNotIn(raw_token, json.dumps(claimed["metadata"]))
            self.assertNotIn(other_token, json.dumps(claimed["metadata"]))

            bridge.queue.complete(
                claimed["job_id"],
                EXAMPLE_AGENT_ID,
                status="done",
                result_text=f"Leaked: {raw_token} and {other_url}",
                auth_token=self.worker_token,
            )
            bridge.wait_for_active_jobs(timeout=3.0)
            edits = mock_client.get_calls("editMessageText")
            self.assertTrue(edits)
            final_text = edits[-1]["text"]
            self.assertNotIn(raw_token, final_text)
            self.assertNotIn(other_token, final_text)
            self.assertIn("[REDACTED]", final_text)

            # Verify zero token written anywhere in bridge state_dir
            for cur, _, files in os.walk(self.state_dir):
                for fn in files:
                    fp = os.path.join(cur, fn)
                    data = Path(fp).read_text(encoding="utf-8", errors="ignore")
                    self.assertNotIn(raw_token, data, f"Raw token leaked to disk: {fp}")
        finally:
            bridge.shutdown()


# ===========================================================================
# F2: Owner RBAC, OwnerAuth & DENIED_CHATS Precedence
# ===========================================================================
class TestF2OwnerRBACAndDeniedChats(_BridgeTestBase):
    def test_f2_owner_users_env_fail_closed(self) -> None:
        for bad_owners in ("", "   ", "abc", f"{OWNER_UID},not_an_int", f"{OWNER_UID}, ", "-123456789"):
            env = {
                "AGY_FED_TG_AGENT_ID": EXAMPLE_AGENT_ID,
                "AGY_FED_TG_OWNER_USERS": bad_owners,
                "AGY_FED_TG_BOT_TOKEN": self.token,
            }
            with self.assertRaises(ValueError, msg=f"Expected ValueError for OWNER_USERS={bad_owners!r}"):
                ftb.load_config(env)

    def test_f2_non_owner_missing_from_and_sender_chat_silently_dropped(self) -> None:
        bridge, client = self._build_bridge(allowed_chats=(GROUP_ALLOWED,))
        bridge.startup()
        try:
            with mock.patch.object(
                federation_registry, "make_owner_auth", wraps=federation_registry.make_owner_auth
            ) as spy_auth:
                # Non-owner prompt, /cancel, /bindgroup
                for idx, txt in enumerate(("hello", "/cancel", "/bindgroup", "/status"), start=1):
                    res = bridge.handle_update(
                        _make_update(
                            idx,
                            chat_id=GROUP_ALLOWED,
                            chat_type="supergroup",
                            from_user={"id": OTHER_UID, "is_bot": False},
                            text=txt,
                        )
                    )
                    self.assertFalse(res)

                # Missing `from`
                self.assertFalse(
                    bridge.handle_update(
                        _make_update(10, chat_id=GROUP_ALLOWED, chat_type="supergroup", include_from=False, text="/cancel")
                    )
                )

                # Anonymous admin (`sender_chat` present even if `from.id` matches OWNER_UID)
                self.assertFalse(
                    bridge.handle_update(
                        _make_update(
                            11,
                            chat_id=GROUP_ALLOWED,
                            chat_type="supergroup",
                            from_user={"id": OWNER_UID, "is_bot": False},
                            sender_chat={"id": GROUP_ALLOWED, "type": "supergroup"},
                            text="/bindgroup",
                        )
                    )
                )

                self.assertEqual(spy_auth.call_count, 0)
                self.assertEqual(client.get_calls("sendMessage"), [])
                self.assertEqual(client.get_calls("editMessageText"), [])
                self.assertEqual(_count_pull_queue_jobs(self.bus_dir), 0)
        finally:
            bridge.shutdown()

    def test_f2_denied_chats_overrides_allowed_and_persisted_bindings(self) -> None:
        # Manually pre-write GROUP_DENIED into bindings.json on disk
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        bindings_file = Path(self.state_dir) / "bindings.json"
        bindings_file.write_text(
            json.dumps({"version": 1, "bound_chats": [GROUP_DENIED, GROUP_ALLOWED]}),
            encoding="utf-8",
        )
        os.chmod(bindings_file, 0o600)
        before_bytes = bindings_file.read_bytes()

        # GROUP_DENIED is in BOTH ALLOWED_CHATS and DENIED_CHATS and bindings.json
        bridge, client = self._build_bridge(
            allowed_chats=(GROUP_DENIED, GROUP_ALLOWED),
            denied_chats=(GROUP_DENIED,),
        )
        bridge.startup()
        try:
            with mock.patch.object(
                federation_registry, "make_owner_auth", wraps=federation_registry.make_owner_auth
            ) as spy_auth:
                self.assertFalse(
                    bridge.handle_update(
                        _make_update(
                            1,
                            chat_id=GROUP_DENIED,
                            chat_type="supergroup",
                            text=f"@{BOT_USERNAME} run task",
                        )
                    )
                )
                self.assertFalse(
                    bridge.handle_update(
                        _make_update(
                            2,
                            chat_id=GROUP_DENIED,
                            chat_type="supergroup",
                            text="/bindgroup",
                        )
                    )
                )
                self.assertEqual(spy_auth.call_count, 0)
                self.assertEqual(client.get_calls("sendMessage"), [])
                self.assertEqual(_count_pull_queue_jobs(self.bus_dir), 0)
                self.assertEqual(bindings_file.read_bytes(), before_bytes)
        finally:
            bridge.shutdown()


# ===========================================================================
# F3: Bot-Loop Immunity & Group Trigger Gating
# ===========================================================================
class TestF3BotLoopImmunityAndGroupGating(_BridgeTestBase):
    def test_f3_is_bot_unconditionally_silently_dropped(self) -> None:
        # Even if BOT_UID is misconfigured into OWNER_USERS and replies to this bot in an allowed group
        bridge, client = self._build_bridge(
            owner_users=(OWNER_UID, BOT_UID),
            allowed_chats=(GROUP_ALLOWED,),
        )
        bridge.startup()
        try:
            upd = _make_update(
                1,
                chat_id=GROUP_ALLOWED,
                chat_type="supergroup",
                from_user={"id": BOT_UID, "is_bot": True, "username": OTHER_BOT_USERNAME},
                text=f"@{BOT_USERNAME} ping loop",
                reply_to_message={"message_id": 5, "from": {"id": BOT_UID, "is_bot": True}},
            )
            self.assertFalse(bridge.handle_update(upd))
            self.assertEqual(client.get_calls("sendMessage"), [])
            self.assertEqual(_count_pull_queue_jobs(self.bus_dir), 0)
        finally:
            bridge.shutdown()

    def test_f3_group_trigger_gating_exact_mention_reply_and_commands(self) -> None:
        bridge, client = self._build_bridge(allowed_chats=(GROUP_ALLOWED,))
        bridge.startup()
        try:
            # 1) Plain chatter in authorized group -> ignored
            self.assertFalse(
                bridge.handle_update(
                    _make_update(1, chat_id=GROUP_ALLOWED, chat_type="supergroup", text="just chatting here")
                )
            )
            # 2) Prefix-collision mention (@your_bot_2 instead of @your_bot) -> ignored
            self.assertFalse(
                bridge.handle_update(
                    _make_update(
                        2,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        text=f"@{OTHER_BOT_USERNAME} please do something",
                    )
                )
            )
            # 3) Command addressed to another bot -> ignored
            self.assertFalse(
                bridge.handle_update(
                    _make_update(
                        3,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        text=f"/f01@{OTHER_BOT_USERNAME} ignore me",
                    )
                )
            )
            self.assertEqual(client.get_calls("sendMessage"), [])
            self.assertEqual(_count_pull_queue_jobs(self.bus_dir), 0)

            # 4) Exact case-insensitive mention -> triggers & enqueues
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        4,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        text=f"Hi @{BOT_USERNAME.upper()} summarize status",
                    )
                )
            )
            job1 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job1)
            self.assertIn("summarize status", job1["prompt"])
            bridge.queue.complete(job1["job_id"], EXAMPLE_AGENT_ID, result_text="ok1", auth_token=self.worker_token)
            bridge.wait_for_active_jobs(timeout=3.0)

            # 5) Reply to this bot -> triggers
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        5,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        text="follow up question",
                        reply_to_message={"message_id": 10, "from": {"id": BOT_UID, "is_bot": True}},
                    )
                )
            )
            job2 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job2)
            bridge.queue.complete(job2["job_id"], EXAMPLE_AGENT_ID, result_text="ok2", auth_token=self.worker_token)
            bridge.wait_for_active_jobs(timeout=3.0)

            # 6) Explicit /f01 command -> triggers
            self.assertTrue(
                bridge.handle_update(
                    _make_update(6, chat_id=GROUP_ALLOWED, chat_type="supergroup", text="/f01 run check")
                )
            )
            job3 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job3)
            bridge.queue.complete(job3["job_id"], EXAMPLE_AGENT_ID, result_text="ok3", auth_token=self.worker_token)
            bridge.wait_for_active_jobs(timeout=3.0)
        finally:
            bridge.shutdown()


# ===========================================================================
# F4: /bindgroup & State File Security (Symlink / 0600 / Corrupt JSON)
# ===========================================================================
class TestF4BindGroupAndStateFileSecurity(_BridgeTestBase):
    def test_f4_bindgroup_rejects_private_channel_denied_and_non_owner(self) -> None:
        bridge, _client = self._build_bridge(denied_chats=(GROUP_DENIED,))
        bridge.startup()
        try:
            bindings_path = Path(self.state_dir) / "bindings.json"
            self.assertFalse(bindings_path.exists())

            # Private chat
            self.assertFalse(
                bridge.handle_update(_make_update(1, chat_id=OWNER_UID, chat_type="private", text="/bindgroup"))
            )
            # Channel
            self.assertFalse(
                bridge.handle_update(_make_update(2, chat_id=GROUP_DYNAMIC, chat_type="channel", text="/bindgroup"))
            )
            # Denied group
            self.assertFalse(
                bridge.handle_update(_make_update(3, chat_id=GROUP_DENIED, chat_type="supergroup", text="/bindgroup"))
            )
            # Non-owner in valid supergroup
            self.assertFalse(
                bridge.handle_update(
                    _make_update(
                        4,
                        chat_id=GROUP_DYNAMIC,
                        chat_type="supergroup",
                        from_user={"id": OTHER_UID, "is_bot": False},
                        text="/bindgroup",
                    )
                )
            )
            self.assertFalse(bindings_path.exists())

            # Legitimate owner /bindgroup in supergroup -> atomic 0600 write & 0700 dir
            self.assertTrue(
                bridge.handle_update(_make_update(5, chat_id=GROUP_DYNAMIC, chat_type="supergroup", text="/bindgroup"))
            )
            self.assertTrue(bindings_path.is_file())
            self.assertEqual(stat.S_IMODE(os.stat(self.state_dir).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(bindings_path).st_mode), 0o600)
            self.assertEqual(bridge.state.load_bound_chats(), {GROUP_DYNAMIC})

            # /unbindgroup removes it atomically
            self.assertTrue(
                bridge.handle_update(_make_update(6, chat_id=GROUP_DYNAMIC, chat_type="supergroup", text="/unbindgroup"))
            )
            self.assertEqual(bridge.state.load_bound_chats(), set())
        finally:
            bridge.shutdown()

    def test_f4_symlink_defense_for_bindings_offset_and_lock(self) -> None:
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        decoy = self.root / "decoy_secret.txt"
        decoy_content = "DECOY_ORIGINAL_CONTENT_DO_NOT_TOUCH"
        decoy.write_text(decoy_content, encoding="utf-8")

        # 1) bindings.json symlink -> read & write both fail closed, decoy untouched
        b_link = Path(self.state_dir) / "bindings.json"
        os.symlink(decoy, b_link)
        store = ftb.BridgeStateStore(self.state_dir, denied_chats=frozenset({GROUP_DENIED}))
        with self.assertRaises(PermissionError):
            store.load_bound_chats()
        with self.assertRaises(PermissionError):
            store.bind_group(GROUP_DYNAMIC)
        self.assertEqual(decoy.read_text(encoding="utf-8"), decoy_content)
        b_link.unlink()

        # 2) offset.json symlink -> read & write both fail closed, decoy untouched
        o_link = Path(self.state_dir) / "offset.json"
        os.symlink(decoy, o_link)
        with self.assertRaises(PermissionError):
            store.load_offset()
        with self.assertRaises(PermissionError):
            store.save_offset(42)
        self.assertEqual(decoy.read_text(encoding="utf-8"), decoy_content)
        o_link.unlink()

        # 3) bridge.lock symlink -> acquire fails closed, decoy untouched
        l_link = Path(self.state_dir) / "bridge.lock"
        os.symlink(decoy, l_link)
        lock = ftb.InstanceLock(self.state_dir)
        with self.assertRaises(PermissionError):
            lock.acquire()
        self.assertEqual(decoy.read_text(encoding="utf-8"), decoy_content)
        l_link.unlink()

    def test_f4_corrupt_or_tampered_bindings_file_sanitized_fail_closed(self) -> None:
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        b_path = Path(self.state_dir) / "bindings.json"
        store = ftb.BridgeStateStore(self.state_dir, denied_chats=frozenset({GROUP_DENIED}))

        # Corrupt JSON -> empty set fail-closed
        b_path.write_text("{corrupt json", encoding="utf-8")
        self.assertEqual(store.load_bound_chats(), set())

        # Mixed non-int / bool / positive / DENIED_CHATS -> only valid non-denied negative ints survive
        b_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "bound_chats": [True, False, "bad", None, 1.5, OWNER_UID, GROUP_DENIED, GROUP_DYNAMIC],
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(store.load_bound_chats(), {GROUP_DYNAMIC})


# ===========================================================================
# F5: Target Agent & Env Fail-Closed (Startup + Per-Enqueue)
# ===========================================================================
class TestF5TargetAgentAndTaintedEnv(_BridgeTestBase):
    def test_f5_invalid_agent_id_rejected_at_config_load(self) -> None:
        for bad_id in ("../evil", "Muse-F01", "bad/id", ""):
            env = {
                "AGY_FED_TG_AGENT_ID": bad_id,
                "AGY_FED_TG_OWNER_USERS": str(OWNER_UID),
                "AGY_FED_TG_BOT_TOKEN": self.token,
            }
            with self.assertRaises(ValueError):
                ftb.load_config(env)

    def test_f5_startup_and_runtime_agent_mutation_fail_closed(self) -> None:
        owner_auth = federation_registry.make_owner_auth("test_owner", env={})

        # 1) Unregistered agent fails startup
        cfg_missing = ftb.BridgeConfig(
            agent_id="missing_agent",
            bot_token=self.token,
            owner_users=frozenset({OWNER_UID}),
            state_dir=self.state_dir,
            reload_sentinel=self.sentinel,
            bus_dir=self.bus_dir,
        )
        b_missing = ftb.FederationTelegramBridge(cfg_missing, client=MockTelegramTransport(), env={})
        with self.assertRaises(ftb.TargetAgentUnavailableError):
            b_missing.startup()

        # 2) Valid at startup, then mutated at runtime -> per-enqueue check blocks every case
        bridge, client = self._build_bridge()
        bridge.startup()
        try:
            mutations = [
                lambda: federation_registry.update_agent(
                    EXAMPLE_AGENT_ID, enabled=False, owner_auth=owner_auth, bus_dir=self.bus_dir, env={}
                ),
                lambda: federation_registry.update_agent(
                    EXAMPLE_AGENT_ID,
                    enabled=True,
                    capabilities={"can_receive": False},
                    owner_auth=owner_auth,
                    bus_dir=self.bus_dir,
                    env={},
                ),
                lambda: federation_registry.update_agent(
                    EXAMPLE_AGENT_ID,
                    capabilities={"can_receive": True},
                    transport="http_push",
                    owner_auth=owner_auth,
                    bus_dir=self.bus_dir,
                    env={},
                ),
                lambda: federation_registry.revoke_agent(
                    EXAMPLE_AGENT_ID, owner_auth=owner_auth, bus_dir=self.bus_dir, env={}
                ),
            ]
            for idx, mutate in enumerate(mutations, start=1):
                mutate()
                bridge.handle_update(_make_update(idx, chat_id=OWNER_UID, text=f"job attempt {idx}"))
                self.assertEqual(_count_pull_queue_jobs(self.bus_dir), 0)
            # Owner received safe notices without internal bus path or tokens
            sent = client.get_calls("sendMessage")
            self.assertEqual(len(sent), len(mutations))
            for call in sent:
                self.assertNotIn(self.bus_dir, call["text"])
                self.assertNotIn(self.token, call["text"])
        finally:
            bridge.shutdown()

    def test_f5_tainted_env_blocks_make_owner_auth_and_enqueue(self) -> None:
        tainted_envs = (
            {"AGY_UNTRUSTED_SESSION": "1"},
            {"AGY_MEMORY_READONLY": "1"},
            {"AGY_BOT_BUS_ROLE": "worker"},
        )
        for idx, tenv in enumerate(tainted_envs, start=1):
            # Startup itself fails closed with PermissionError
            b_start, _ = self._build_bridge(env=tenv)
            with self.assertRaises(PermissionError):
                b_start.startup()

            # Runtime taint also blocks per-enqueue with 0 files in pull_queue/
            b_run, client = self._build_bridge(env={})
            b_run.startup()
            try:
                b_run._env = dict(tenv)
                with self.assertRaises(PermissionError):
                    b_run._make_owner_auth(OWNER_UID)
                b_run.handle_update(_make_update(idx, chat_id=OWNER_UID, text="tainted task"))
                self.assertEqual(_count_pull_queue_jobs(self.bus_dir), 0)
                self.assertTrue(client.get_calls("sendMessage"))
            finally:
                b_run.shutdown()


# ===========================================================================
# F6: Concurrency, Cross-Chat /cancel, Timeout Orphan Cleanup & Exclusive flock
# ===========================================================================
class TestF6ConcurrencyCancelTimeoutAndLock(_BridgeTestBase):
    def test_f6_same_chat_busy_and_cross_chat_cancel_isolation(self) -> None:
        bridge, client = self._build_bridge(allowed_chats=(GROUP_ALLOWED,))
        bridge.startup()
        try:
            # C1 (Owner DM) dispatches jid1
            bridge.handle_update(_make_update(1, chat_id=OWNER_UID, chat_type="private", text="first job"))
            with bridge._jobs_lock:
                jid1 = bridge._active_jobs[OWNER_UID].job_id
            self.assertTrue(jid1)

            # Second prompt in C1 while jid1 active -> deterministic busy notice, jid1 preserved
            bridge.handle_update(_make_update(2, chat_id=OWNER_UID, chat_type="private", text="second job"))
            with bridge._jobs_lock:
                self.assertEqual(bridge._active_jobs[OWNER_UID].job_id, jid1)
            self.assertEqual(_count_pull_queue_jobs(self.bus_dir), 1)

            # C2 (GROUP_ALLOWED) sends /cancel -> MUST NOT cancel C1's jid1
            bridge.handle_update(_make_update(3, chat_id=GROUP_ALLOWED, chat_type="supergroup", text="/cancel"))
            rec_after_c2_cancel = bridge.queue.get(jid1)
            self.assertIsNotNone(rec_after_c2_cancel)
            self.assertEqual(rec_after_c2_cancel["status"], "queued")
            self.assertFalse(rec_after_c2_cancel["cancelled"])

            # Now complete jid1 and verify delivery
            claimed = bridge.queue.claim(EXAMPLE_AGENT_ID, job_id=jid1, auth_token=self.worker_token)
            self.assertIsNotNone(claimed)
            bridge.queue.complete(jid1, EXAMPLE_AGENT_ID, result_text="done C1", auth_token=self.worker_token)
            bridge.wait_for_active_jobs(timeout=3.0)
            edits = client.get_calls("editMessageText")
            self.assertTrue(any("done C1" in c["text"] for c in edits))
        finally:
            bridge.shutdown()

    def test_f6_timeout_cancels_orphan_job_with_deterministic_monotonic_clock(self) -> None:
        # Fixed positive monotonic baseline (never negative even on fresh CI runners)
        now_box = [1000.0]

        def fake_clock() -> float:
            return now_box[0]

        def fake_sleep(_sec: float) -> None:
            now_box[0] += 120.0

        bridge, client = self._build_bridge(
            job_timeout_sec=300.0,
            job_poll_interval_sec=0.01,
            clock=fake_clock,
            sleep_fn=fake_sleep,
        )
        bridge.startup()
        try:
            bridge.handle_update(_make_update(1, chat_id=OWNER_UID, text="never completes"))
            bridge.wait_for_active_jobs(timeout=3.0)

            # Find the single job on disk and assert cancelled with reason="timeout" (zero orphans)
            qdir = Path(federation_registry.pull_queue_dir(self.bus_dir))
            job_files = [p for p in qdir.glob("*.json") if not p.name.endswith(".tmp")]
            self.assertEqual(len(job_files), 1)
            job_data = json.loads(job_files[0].read_text(encoding="utf-8"))
            self.assertEqual(job_data["status"], "cancelled")
            self.assertTrue(job_data["cancelled"])
            self.assertEqual(job_data["cancel_reason"], "timeout")

            # Placeholder updated with timeout notice
            edits = client.get_calls("editMessageText")
            self.assertTrue(edits)
            self.assertIn("超时", edits[-1]["text"])
        finally:
            bridge.shutdown()

    def test_f6_exclusive_flock_blocks_second_instance(self) -> None:
        bridge1, _ = self._build_bridge()
        bridge2, _ = self._build_bridge()
        bridge1.startup()
        try:
            with self.assertRaises(ftb.InstanceLockError):
                bridge2.startup()
        finally:
            bridge1.shutdown()

        # After bridge1 releases lock, bridge2 can cleanly acquire
        bridge2.startup()
        bridge2.shutdown()


# ===========================================================================
# F7: Delivery Resilience (>4000 Chunking, 400 Fallback, Offset Anti-Replay & Reload)
# ===========================================================================
class TestF7DeliveryResilienceOffsetAndReload(_BridgeTestBase):
    def test_f7_long_reply_chunking_html_escaping_and_zero_truncation(self) -> None:
        bridge, client = self._build_bridge()
        bridge.startup()
        try:
            payload = ("Line with <script>&\"chars\" and text " * 280).strip()
            self.assertGreater(len(payload), 9500)

            bridge.handle_update(_make_update(1, chat_id=OWNER_UID, text="long output"))
            claimed = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(claimed)
            bridge.queue.complete(claimed["job_id"], EXAMPLE_AGENT_ID, result_text=payload, auth_token=self.worker_token)
            bridge.wait_for_active_jobs(timeout=3.0)

            edits = client.get_calls("editMessageText")
            # Filter out the initial placeholder sendMessage
            sends = client.get_calls("sendMessage")[1:]
            self.assertEqual(len(edits), 1)
            self.assertGreaterEqual(len(sends), 2)

            delivered_html_parts = [edits[0]["text"]] + [c["text"] for c in sends]
            for part in delivered_html_parts:
                self.assertLessEqual(len(part), ftb.MAX_TELEGRAM_CHUNK_LEN)
                self.assertNotIn("<script>", part)

            reconstructed = html_mod.unescape("".join(delivered_html_parts))
            self.assertEqual(reconstructed, payload)
        finally:
            bridge.shutdown()

    def test_f7_http_400_parse_fallback_and_message_not_modified_idempotent(self) -> None:
        bridge, client = self._build_bridge()
        bridge.startup()
        try:
            # 1) editMessageText 400 parse entities -> retries without parse_mode
            client.fail_html_once_edit = True
            bridge._deliver_text(OWNER_UID, "<b>raw html</b>", placeholder_msg_id=101)
            edit_calls = client.get_calls("editMessageText")
            self.assertEqual(len(edit_calls), 2)
            self.assertEqual(edit_calls[0]["parse_mode"], "HTML")
            self.assertIsNone(edit_calls[1]["parse_mode"])
            self.assertEqual(edit_calls[1]["text"], "<b>raw html</b>")

            # 2) sendMessage 400 parse entities -> retries without parse_mode
            client.fail_html_once_send = True
            bridge._deliver_text(OWNER_UID, "plain fallback text")
            send_calls = client.get_calls("sendMessage")
            self.assertEqual(len(send_calls), 2)
            self.assertEqual(send_calls[0]["parse_mode"], "HTML")
            self.assertIsNone(send_calls[1]["parse_mode"])

            # 3) editMessageText 400 "message is not modified" -> ignored without crash
            client.fail_not_modified_edit = True
            bridge._deliver_text(OWNER_UID, "same content", placeholder_msg_id=101)
        finally:
            bridge.shutdown()

    def test_f7_offset_anti_replay_and_reload_sentinel_graceful_exit(self) -> None:
        bridge1, client1 = self._build_bridge()
        client1.pending_updates.append([_make_update(50, chat_id=OWNER_UID, text="first run")])
        bridge1.startup()
        try:
            bridge1.poll_once()
            job1 = bridge1.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job1)
            bridge1.queue.complete(job1["job_id"], EXAMPLE_AGENT_ID, result_text="done 50", auth_token=self.worker_token)
            bridge1.wait_for_active_jobs(timeout=3.0)
        finally:
            bridge1.shutdown()

        offset_file = Path(self.state_dir) / "offset.json"
        self.assertEqual(stat.S_IMODE(os.stat(offset_file).st_mode), 0o600)
        self.assertEqual(json.loads(offset_file.read_text(encoding="utf-8"))["last_update_id"], 50)

        # Restart process: getUpdates starts at 51; replayed update_id=50 is skipped, 51 processed
        bridge2, client2 = self._build_bridge()
        client2.pending_updates.append(
            [
                _make_update(50, chat_id=OWNER_UID, text="replayed 50"),
                _make_update(51, chat_id=OWNER_UID, text="fresh 51"),
            ]
        )
        bridge2.startup()
        try:
            processed = bridge2.poll_once()
            self.assertEqual(processed, 1)
            upd_calls = client2.get_calls("getUpdates")
            self.assertEqual(upd_calls[0]["offset"], 51)
            job2 = bridge2.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job2)
            self.assertIn("fresh 51", job2["prompt"])
            bridge2.queue.complete(job2["job_id"], EXAMPLE_AGENT_ID, result_text="done 51", auth_token=self.worker_token)
            bridge2.wait_for_active_jobs(timeout=3.0)
        finally:
            bridge2.shutdown()

        # Reload sentinel triggers graceful stop, consumes sentinel, preserves valid state files
        Path(self.sentinel).write_text("reload\n", encoding="utf-8")
        bridge3, _client3 = self._build_bridge()
        bridge3.run(install_signals=False, max_loops=5)
        self.assertTrue(bridge3._reload_requested)
        self.assertFalse(Path(self.sentinel).exists())
        self.assertEqual(json.loads(offset_file.read_text(encoding="utf-8"))["last_update_id"], 51)

        # SIGTERM / stop_event graceful exit leaves state files valid and intact
        bridge4, client4 = self._build_bridge()
        orig_get_updates = client4.get_updates

        def _updates_then_stop(**kwargs):
            bridge4.request_stop()
            return orig_get_updates(**kwargs)

        client4.get_updates = _updates_then_stop  # type: ignore[assignment]
        bridge4.run(install_signals=True, max_loops=5)
        self.assertEqual(json.loads(offset_file.read_text(encoding="utf-8"))["last_update_id"], 51)

    def test_f7_commands_help_status_clear_ask_and_flat_cli_self_check(self) -> None:
        bridge, client = self._build_bridge()
        bridge.startup()
        try:
            self.assertTrue(bridge.handle_update(_make_update(1, chat_id=OWNER_UID, text="/start")))
            self.assertTrue(bridge.handle_update(_make_update(2, chat_id=OWNER_UID, text="/help")))
            self.assertTrue(bridge.handle_update(_make_update(3, chat_id=OWNER_UID, text="/status")))
            self.assertTrue(bridge.handle_update(_make_update(4, chat_id=OWNER_UID, text="/clear")))
            sent = client.get_calls("sendMessage")
            self.assertEqual(len(sent), 4)
            self.assertIn(EXAMPLE_AGENT_ID, sent[2]["text"])
            self.assertNotIn(self.bus_dir, sent[2]["text"])

            self.assertTrue(bridge.handle_update(_make_update(5, chat_id=OWNER_UID, text="/ask hello ask")))
            job = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job)
            self.assertIn("hello ask", job["prompt"])
            bridge.queue.complete(job["job_id"], EXAMPLE_AGENT_ID, result_text="ask ok", auth_token=self.worker_token)
            bridge.wait_for_active_jobs(timeout=3.0)
        finally:
            bridge.shutdown()

        # Verify flat script execution works directly with system python
        import subprocess

        proc = subprocess.run(
            [sys.executable, str(REPO_ROOT / "bridge" / "federation_tg_bridge.py"), "--self-check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "ok")


# ===========================================================================
# F8: Gate Registration & Dual-Repo Desensitization Sanity
# ===========================================================================
class TestF8GateRegistrationAndSanity(unittest.TestCase):
    def test_f8_registered_in_verify_gate_and_export_public(self) -> None:
        import verify_gate  # noqa: E402

        self.assertIn("tests/test_federation_tg_bridge.py", verify_gate.BRIDGE_TEST_FILES)
        self.assertIn("tests/test_federation_tg_bridge.py", verify_gate.SECURITY_TEST_FILES)

        export_pub_path = REPO_ROOT / "scripts" / "export_public.py"
        if export_pub_path.is_file():
            import export_public  # noqa: E402

            self.assertIn("tests/test_federation_tg_bridge.py", export_public.CORE_SYNC_EXACT)
            self.assertTrue(export_public.is_public_core("bridge/federation_tg_bridge.py"))
            self.assertTrue(export_public.is_public_core("tests/test_federation_tg_bridge.py"))
            self.assertFalse(export_public.is_public_core("fed_bots.json"))
            self.assertFalse(export_public.is_public_core("systemd/agy-tg-bridge-fed.service"))

        sec_audit_path = REPO_ROOT / "scripts" / "security_audit.py"
        if sec_audit_path.is_file():
            import security_audit  # noqa: E402

            self.assertIn("fed_bots.json", security_audit.FORBIDDEN_RUNTIME_NAMES)
            self.assertTrue(security_audit.is_forbidden_runtime_file("fed_bots.json"))
            self.assertTrue(security_audit.is_forbidden_runtime_file("subdir/fed_bots.json"))

        sync_live_path = REPO_ROOT / "scripts" / "sync_live.py"
        if sync_live_path.is_file():
            import sync_live  # noqa: E402

            mapped_rels = {rel for rel, *_rest in sync_live.MAPPINGS}
            self.assertIn("bridge/federation_tg_bridge.py", mapped_rels)
            self.assertIn("systemd/agy-tg-bridge-fed.service", mapped_rels)
            self.assertNotIn("systemd/agy-tg-bridge-f01.service", mapped_rels)
            self.assertIn("fed_bots.json", sync_live.SKIP_NAMES)
            self.assertIn(".env.fed", sync_live.SKIP_NAMES)
            self.assertIn("agy-tg-bridge-fed.service", sync_live.SERVICES)
            self.assertNotIn("agy-tg-bridge-f01.service", sync_live.SERVICES)


# ===========================================================================
# Multi-Bot Helpers (M1..M4)
# ===========================================================================
BOT_A_UID = 111111111
BOT_B_UID = 222222222
BOT_A_AGENT = "worker-alpha"
BOT_B_AGENT = "worker-beta"
BOT_A_SECRET_REF = "lv" + "1/services/example-bot-a#token"
BOT_B_SECRET_REF = "lv" + "1/services/example-bot-b#token"
GROUP_SECOND = -55001


def _make_bot_a_token() -> str:
    return f"{'123456789'}:{'MOCK_ALPHA_'}{'a' * 22}"


def _make_bot_b_token() -> str:
    return f"{'987654321'}:{'MOCK_BETA_'}{'b' * 22}"


def _write_secure_json(path: Path, payload: Any, mode: int = 0o600) -> Path:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.chmod(path, mode)
    return path


class _MultiBotTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="fed_tg_multi_test_")
        self.root = Path(self._tmp.name)
        self.bus_dir = str(self.root / "bus")
        self.state_root = str(self.root / "fed_state")
        self.sentinel = str(self.root / "agy_fed_tg_reload")
        self.config_path = self.root / "fed_bots.json"
        self.token_a = _make_bot_a_token()
        self.token_b = _make_bot_b_token()
        _, self.worker_tok_a = _register_pull_agent(self.bus_dir, BOT_A_AGENT)
        _, self.worker_tok_b = _register_pull_agent(self.bus_dir, BOT_B_AGENT)
        self.secret_map = {
            BOT_A_SECRET_REF: self.token_a,
            BOT_B_SECRET_REF: self.token_b,
        }

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _resolve_secret(self, ref: str) -> str:
        if ref not in self.secret_map:
            raise RuntimeError(f"Secret not found: {ref}")
        return self.secret_map[ref]

    def _base_config_dict(self) -> Dict[str, Any]:
        return {
            "defaults": {
                "owner_users": [OWNER_UID],
                "denied_chats": [GROUP_DENIED],
                "job_timeout_sec": 300,
                "poll_timeout_sec": 1,
                "context_turns": 8,
                "job_poll_interval_sec": 0.01,
                "state_root_dir": self.state_root,
                "bus_dir": self.bus_dir,
                "reload_sentinel": self.sentinel,
                "command_aliases": ["ask"],
            },
            "bots": [
                {
                    "name": "bot_alpha",
                    "agent_id": BOT_A_AGENT,
                    "enabled": True,
                    "token_secret_ref": BOT_A_SECRET_REF,
                    "allowed_chats": [GROUP_ALLOWED],
                    "denied_chats": [],
                    "command_aliases": ["ask", "alpha"],
                },
                {
                    "name": "bot_beta",
                    "agent_id": BOT_B_AGENT,
                    "enabled": True,
                    "token_secret_ref": BOT_B_SECRET_REF,
                    "allowed_chats": [GROUP_ALLOWED],
                    "denied_chats": [],
                    "command_aliases": ["ask", "beta"],
                },
            ],
        }


# ===========================================================================
# M1: fed_bots.json File Security, Schema Uniqueness & Non-Downgrading Merge
# ===========================================================================
class TestM1MultiBotConfigSecurityAndMerge(_MultiBotTestBase):
    def test_m1_file_security_symlink_dir_fifo_and_wide_permissions_fail_closed(self) -> None:
        real_cfg = _write_secure_json(self.root / "real_cfg.json", self._base_config_dict(), mode=0o600)

        # 1) Symlink rejected via O_NOFOLLOW
        sym_cfg = self.root / "sym_cfg.json"
        os.symlink(real_cfg, sym_cfg)
        with self.assertRaises(PermissionError):
            ftb.load_multi_bot_config(str(sym_cfg), env={}, secret_resolver=self._resolve_secret)

        # 2) Directory rejected via fstat S_ISREG
        dir_cfg = self.root / "dir_cfg"
        dir_cfg.mkdir(mode=0o700)
        with self.assertRaises(PermissionError):
            ftb.load_multi_bot_config(str(dir_cfg), env={}, secret_resolver=self._resolve_secret)

        # 3) FIFO rejected via O_NONBLOCK + fstat S_ISREG (must not block)
        fifo_cfg = self.root / "fifo_cfg"
        os.mkfifo(fifo_cfg, 0o600)
        with self.assertRaises(PermissionError):
            ftb.load_multi_bot_config(str(fifo_cfg), env={}, secret_resolver=self._resolve_secret)

        # 4) Wide permissions (0644, 0640, 0604) rejected via fstat mode & 0o077 != 0
        for bad_mode in (0o644, 0o640, 0o604, 0o660):
            os.chmod(real_cfg, bad_mode)
            with self.assertRaises(PermissionError, msg=f"Expected PermissionError for mode {oct(bad_mode)}"):
                ftb.load_multi_bot_config(str(real_cfg), env={}, secret_resolver=self._resolve_secret)

        # 5) 0600 regular file succeeds
        os.chmod(real_cfg, 0o600)
        loaded = ftb.load_multi_bot_config(str(real_cfg), env={}, secret_resolver=self._resolve_secret)
        self.assertEqual(len(loaded.bots), 2)

    def test_m1_corrupt_json_non_object_empty_or_all_disabled_bots_fail_closed(self) -> None:
        # 1) Corrupt JSON
        self.config_path.write_text("{broken json", encoding="utf-8")
        os.chmod(self.config_path, 0o600)
        with self.assertRaises(ValueError):
            ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        # 2) Non-object roots
        for bad_root in (["list"], "string", 42, None):
            _write_secure_json(self.config_path, bad_root, mode=0o600)
            with self.assertRaises(ValueError):
                ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        # 3) Missing bots, empty bots, non-list bots
        for bad_payload in (
            {"defaults": {"owner_users": [OWNER_UID]}},
            {"defaults": {"owner_users": [OWNER_UID]}, "bots": []},
            {"defaults": {"owner_users": [OWNER_UID]}, "bots": "not-a-list"},
        ):
            _write_secure_json(self.config_path, bad_payload, mode=0o600)
            with self.assertRaises(ValueError):
                ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        # 4) All bots disabled
        all_off = self._base_config_dict()
        for b in all_off["bots"]:
            b["enabled"] = False
        _write_secure_json(self.config_path, all_off, mode=0o600)
        with self.assertRaises(ValueError):
            ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        # 5) Invalid agent_id & non-bool enabled
        bad_aid = self._base_config_dict()
        bad_aid["bots"][0]["agent_id"] = "../evil"
        _write_secure_json(self.config_path, bad_aid, mode=0o600)
        with self.assertRaises(ValueError):
            ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        bad_en = self._base_config_dict()
        bad_en["bots"][0]["enabled"] = "true"
        _write_secure_json(self.config_path, bad_en, mode=0o600)
        with self.assertRaises(ValueError):
            ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

    def test_m1_global_uniqueness_static_keys_and_runtime_bot_id(self) -> None:
        # 1) Duplicate name (case-insensitive)
        dup_name = self._base_config_dict()
        dup_name["bots"][1]["name"] = "BOT_ALPHA"
        _write_secure_json(self.config_path, dup_name, mode=0o600)
        with self.assertRaises(ValueError):
            ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        # 2) Duplicate agent_id
        dup_aid = self._base_config_dict()
        dup_aid["bots"][1]["agent_id"] = BOT_A_AGENT
        _write_secure_json(self.config_path, dup_aid, mode=0o600)
        with self.assertRaises(ValueError):
            ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        # 3) Duplicate token_secret_ref
        dup_ref = self._base_config_dict()
        dup_ref["bots"][1]["token_secret_ref"] = BOT_A_SECRET_REF
        _write_secure_json(self.config_path, dup_ref, mode=0o600)
        with self.assertRaises(ValueError):
            ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        # 4) Duplicate state_dir
        dup_dir = self._base_config_dict()
        shared_dir = str(self.root / "shared_bot_state")
        dup_dir["bots"][0]["state_dir"] = shared_dir
        dup_dir["bots"][1]["state_dir"] = shared_dir
        _write_secure_json(self.config_path, dup_dir, mode=0o600)
        with self.assertRaises(ValueError):
            ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        # 5) Duplicate bot_id returned by getMe() -> fail closed + full lock rollback
        _write_secure_json(self.config_path, self._base_config_dict(), mode=0o600)
        mcfg = ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        def _same_bot_id_factory(_bcfg: ftb.BridgeConfig) -> MockTelegramTransport:
            return MockTelegramTransport(bot_id=BOT_A_UID, bot_username="your_bot_1")

        sup = ftb.MultiBotSupervisor(mcfg, client_factory=_same_bot_id_factory, env={})
        with self.assertRaises(ValueError):
            sup.startup()
        self.assertEqual(sup.held_lock_fds(), [])
        # Verify supervisor.lock and bot A bridge.lock were released cleanly
        probe_sup = ftb.InstanceLock(self.state_root, lock_filename="supervisor.lock")
        probe_sup.acquire()
        probe_sup.release()
        probe_a = ftb.InstanceLock(os.path.join(self.state_root, BOT_A_AGENT))
        probe_a.acquire()
        probe_a.release()

    def test_m1_denied_chats_union_strict_int_types_and_nonempty_owner_users(self) -> None:
        # 1) bot.denied_chats = [] MUST NOT clear defaults.denied_chats or env AGY_FED_TG_DENIED_CHATS
        cfg_data = self._base_config_dict()
        cfg_data["defaults"]["denied_chats"] = [GROUP_ALLOWED]
        cfg_data["bots"][0]["denied_chats"] = []
        cfg_data["bots"][1]["denied_chats"] = [GROUP_SECOND]
        _write_secure_json(self.config_path, cfg_data, mode=0o600)

        mcfg = ftb.load_multi_bot_config(
            str(self.config_path),
            env={"AGY_FED_TG_DENIED_CHATS": str(GROUP_DENIED)},
            secret_resolver=self._resolve_secret,
        )
        self.assertEqual(mcfg.bots[0].denied_chats, frozenset({GROUP_ALLOWED, GROUP_DENIED}))
        self.assertEqual(mcfg.bots[1].denied_chats, frozenset({GROUP_ALLOWED, GROUP_DENIED, GROUP_SECOND}))

        # 2) bool / str / negative owner IDs rejected in owner_users & denied_chats
        bad_id_cases = [
            ("defaults", "owner_users", [True]),
            ("defaults", "owner_users", [OWNER_UID, False]),
            ("defaults", "owner_users", [str(OWNER_UID)]),
            ("defaults", "owner_users", [-123456789]),
            ("defaults", "denied_chats", [True]),
            ("defaults", "denied_chats", [str(GROUP_DENIED)]),
            ("bot0", "owner_users", []),
            ("bot0", "owner_users", [False]),
            ("bot0", "denied_chats", ["bad"]),
            ("defaults", "owner_users", []),
        ]
        for scope, field, bad_val in bad_id_cases:
            d = self._base_config_dict()
            if scope == "defaults":
                d["defaults"][field] = bad_val
            else:
                d["bots"][0][field] = bad_val
            _write_secure_json(self.config_path, d, mode=0o600)
            with self.assertRaises(ValueError, msg=f"Expected ValueError for {scope}.{field}={bad_val!r}"):
                ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

    def test_m1_forbidden_secret_keys_and_no_env_token_fallback(self) -> None:
        # 1) Plaintext secret fields anywhere in config rejected
        for forbidden_key in ("bot_token", "token", "api_key", "password", "secret", "auth_token"):
            d = self._base_config_dict()
            d["bots"][0][forbidden_key] = self.token_a
            _write_secure_json(self.config_path, d, mode=0o600)
            with self.assertRaises(ValueError, msg=f"Expected rejection for key {forbidden_key!r}"):
                ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        # 2) Missing token_secret_ref fails closed EVEN when AGY_FED_TG_BOT_TOKEN is in env
        d_missing = self._base_config_dict()
        del d_missing["bots"][0]["token_secret_ref"]
        _write_secure_json(self.config_path, d_missing, mode=0o600)
        with self.assertRaises(ValueError):
            ftb.load_multi_bot_config(
                str(self.config_path),
                env={"AGY_FED_TG_BOT_TOKEN": self.token_a},
                secret_resolver=self._resolve_secret,
            )

        # 3) Secret resolver failure / empty result fails closed EVEN when AGY_FED_TG_BOT_TOKEN is in env
        _write_secure_json(self.config_path, self._base_config_dict(), mode=0o600)
        with self.assertRaises(RuntimeError):
            ftb.load_multi_bot_config(
                str(self.config_path),
                env={"AGY_FED_TG_BOT_TOKEN": self.token_a},
                secret_resolver=lambda _r: (_ for _ in ()).throw(RuntimeError("vault unavailable")),
            )
        with self.assertRaises(RuntimeError):
            ftb.load_multi_bot_config(
                str(self.config_path),
                env={"AGY_FED_TG_BOT_TOKEN": self.token_a},
                secret_resolver=lambda _r: "   ",
            )


# ===========================================================================
# M2: Multi-Bot Fault Isolation & Cross-Bot Credential / State Zero Leakage
# ===========================================================================
class TestM2MultiBotFaultIsolationAndRedaction(_MultiBotTestBase):
    def test_m2_bot_a_poll_and_handler_errors_do_not_disrupt_bot_b(self) -> None:
        _write_secure_json(self.config_path, self._base_config_dict(), mode=0o600)
        mcfg = ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        client_a = MockTelegramTransport(bot_id=BOT_A_UID, bot_username="your_bot_1")
        client_b = MockTelegramTransport(bot_id=BOT_B_UID, bot_username="your_bot_2")

        bot_a_attempts = {"count": 0}
        bot_b_done = threading.Event()

        def _failing_a_get_updates(**_kwargs):
            bot_a_attempts["count"] += 1
            if bot_a_attempts["count"] == 1:
                raise RuntimeError(f"Bot A crash leaking {self.token_b}")
            if bot_a_attempts["count"] == 2:
                raise ftb.TelegramAPIError("HTTP 500 server error", status_code=500, method="getUpdates")
            if bot_a_attempts["count"] == 3:
                raise TimeoutError("network timeout")
            return []

        client_a.get_updates = _failing_a_get_updates  # type: ignore[assignment]
        client_b.pending_updates.append([_make_update(101, chat_id=OWNER_UID, text="bot b task")])

        def _factory(bcfg: ftb.BridgeConfig) -> MockTelegramTransport:
            return client_a if bcfg.agent_id == BOT_A_AGENT else client_b

        sup = ftb.MultiBotSupervisor(
            mcfg,
            client_factory=_factory,
            env={},
            monitor_interval_sec=0.02,
            backoff_base_sec=0.01,
            backoff_max_sec=0.02,
        )

        # Background thread acts as pull worker for Bot B while supervisor runs
        def _worker_b() -> None:
            q = federation_registry.PullWorkerQueue(self.bus_dir)
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                claimed = q.claim(BOT_B_AGENT, auth_token=self.worker_tok_b)
                if claimed:
                    q.complete(
                        claimed["job_id"],
                        BOT_B_AGENT,
                        status="done",
                        result_text="bot_b_delivered_ok",
                        auth_token=self.worker_tok_b,
                    )
                    bot_b_done.set()
                    return
                time.sleep(0.01)

        worker_th = threading.Thread(target=_worker_b, daemon=True)
        worker_th.start()

        sup_th = threading.Thread(target=sup.run, kwargs={"install_signals": False, "max_loops": 6}, daemon=True)
        sup_th.start()
        self.assertTrue(bot_b_done.wait(timeout=5.0), "Bot B failed to process job while Bot A was crashing")

        # Wait until Bot B delivers editMessageText and Bot A attempted retries
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            edits_b = client_b.get_calls("editMessageText")
            if any("bot_b_delivered_ok" in c["text"] for c in edits_b) and bot_a_attempts["count"] >= 4:
                break
            time.sleep(0.02)

        sup.request_stop()
        sup_th.join(timeout=5.0)
        worker_th.join(timeout=2.0)

        self.assertGreaterEqual(bot_a_attempts["count"], 4)
        edits_b = client_b.get_calls("editMessageText")
        self.assertTrue(any("bot_b_delivered_ok" in c["text"] for c in edits_b))

    def test_m2_cross_bot_token_zero_leakage_logs_exceptions_replies_and_metadata(self) -> None:
        _write_secure_json(self.config_path, self._base_config_dict(), mode=0o600)
        mcfg = ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        encoded_b = urllib.parse.quote(self.token_b, safe="")
        bot_b_url = "https://api.telegram.org/" + "bot" + self.token_b + "/getUpdates"

        # 1) Shared RedactingLogFilter scrubs Bot B's raw, URL-encoded, and URL token in Bot A's logs & exc_info
        log_buf = io.StringIO()
        logger_a = logging.getLogger("test.m2.bot_alpha")
        logger_a.handlers.clear()
        logger_a.propagate = False
        handler = logging.StreamHandler(log_buf)
        handler.addFilter(ftb.RedactingLogFilter(bot_token=self.token_a))
        logger_a.addHandler(handler)

        logger_a.error("Bot A saw %s and %s and %s", self.token_b, encoded_b, bot_b_url)
        try:
            raise RuntimeError(f"Unhandled leak raw={self.token_b} enc={encoded_b} url={bot_b_url}")
        except RuntimeError:
            logger_a.exception("Bot A traceback")

        emitted_log = log_buf.getvalue()
        self.assertNotIn(self.token_a, emitted_log)
        self.assertNotIn(self.token_b, emitted_log)
        self.assertNotIn(encoded_b, emitted_log)
        self.assertIn("[REDACTED]", emitted_log)

        # 2) Bot A TelegramClient error containing Bot B's raw + URL-encoded token -> scrubbed
        def _boom_cross(_req, timeout=30.0):
            raise urllib.error.URLError(f"proxy error raw={self.token_b} enc={encoded_b} url={bot_b_url}")

        tg_a = ftb.TelegramClient(self.token_a, urlopen_fn=_boom_cross)
        with self.assertRaises(ftb.TelegramAPIError) as exc_ctx:
            tg_a.send_message(OWNER_UID, "ping")
        self.assertNotIn(self.token_b, str(exc_ctx.exception))
        self.assertNotIn(encoded_b, str(exc_ctx.exception))
        self.assertIn("[REDACTED]", str(exc_ctx.exception))

        # 3) scrub_metadata & Bot A worker reply scrub Bot B's raw + URL-encoded token
        cleaned_meta = ftb.scrub_metadata(
            {"ref": self.token_b, "enc": encoded_b, "url": bot_b_url, "bot_token": self.token_b},
            bot_token=self.token_a,
        )
        self.assertNotIn("bot_token", cleaned_meta)
        meta_dump = json.dumps(cleaned_meta)
        self.assertNotIn(self.token_b, meta_dump)
        self.assertNotIn(encoded_b, meta_dump)

        client_a = MockTelegramTransport(bot_id=BOT_A_UID, bot_username="your_bot_1")
        client_b = MockTelegramTransport(bot_id=BOT_B_UID, bot_username="your_bot_2")
        sup = ftb.MultiBotSupervisor(
            mcfg,
            client_factory=lambda b: client_a if b.agent_id == BOT_A_AGENT else client_b,
            env={},
        )
        sup.startup()
        try:
            br_a = sup.bridges["bot_alpha"]
            br_a.handle_update(
                _make_update(1, chat_id=OWNER_UID, text=f"echo {self.token_b} {encoded_b} {bot_b_url}")
            )
            claimed = br_a.queue.claim(BOT_A_AGENT, auth_token=self.worker_tok_a)
            self.assertIsNotNone(claimed)
            self.assertNotIn(self.token_b, claimed["prompt"])
            self.assertNotIn(encoded_b, claimed["prompt"])
            br_a.queue.complete(
                claimed["job_id"],
                BOT_A_AGENT,
                status="done",
                result_text=f"Reply containing {self.token_b} and {encoded_b} and {bot_b_url}",
                auth_token=self.worker_tok_a,
            )
            br_a.wait_for_active_jobs(timeout=3.0)
            edits_a = client_a.get_calls("editMessageText")
            self.assertTrue(edits_a)
            self.assertNotIn(self.token_b, edits_a[-1]["text"])
            self.assertNotIn(encoded_b, edits_a[-1]["text"])
            self.assertIn("[REDACTED]", edits_a[-1]["text"])
        finally:
            sup.shutdown()

    def test_m2_shared_group_commands_bindings_and_offsets_strictly_isolated(self) -> None:
        _write_secure_json(self.config_path, self._base_config_dict(), mode=0o600)
        mcfg = ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)
        client_a = MockTelegramTransport(bot_id=BOT_A_UID, bot_username="your_bot_1")
        client_b = MockTelegramTransport(bot_id=BOT_B_UID, bot_username="your_bot_2")
        sup = ftb.MultiBotSupervisor(
            mcfg,
            client_factory=lambda b: client_a if b.agent_id == BOT_A_AGENT else client_b,
            env={},
        )
        sup.startup()
        try:
            br_a = sup.bridges["bot_alpha"]
            br_b = sup.bridges["bot_beta"]

            # Bot B starts a job and builds context in GROUP_ALLOWED at update_id=10
            br_b.handle_update(
                _make_update(10, chat_id=GROUP_ALLOWED, chat_type="supergroup", text="/beta keep running")
            )
            with br_b._jobs_lock:
                jid_b = br_b._active_jobs[GROUP_ALLOWED].job_id
            self.assertTrue(jid_b)
            self.assertEqual(br_b.state.load_offset(), 10)

            # Bot A executes /cancel, /clear, /bindgroup in GROUP_SECOND, and advances offset to 99
            br_a.handle_update(_make_update(97, chat_id=GROUP_ALLOWED, chat_type="supergroup", text="/cancel"))
            br_a.handle_update(_make_update(98, chat_id=GROUP_ALLOWED, chat_type="supergroup", text="/clear"))
            br_a.handle_update(_make_update(99, chat_id=GROUP_SECOND, chat_type="supergroup", text="/bindgroup"))

            # Verify zero side effects on Bot B
            rec_b = br_b.queue.get(jid_b)
            self.assertIsNotNone(rec_b)
            self.assertEqual(rec_b["status"], "queued")
            self.assertFalse(rec_b["cancelled"])
            with br_b._ctx_lock:
                self.assertIn(GROUP_ALLOWED, br_b._chat_context)
            self.assertEqual(br_a.state.load_bound_chats(), {GROUP_SECOND})
            self.assertEqual(br_b.state.load_bound_chats(), set())
            self.assertEqual(br_a.state.load_offset(), 99)
            self.assertEqual(br_b.state.load_offset(), 10)
        finally:
            sup.shutdown()


# ===========================================================================
# M3: Dual Exclusive Locks, Graceful Shutdown & Unified Hot Reload
# ===========================================================================
class TestM3DualLocksGracefulShutdownAndReload(_MultiBotTestBase):
    def test_m3_dual_lock_matrix_cloexec_and_zero_leak_rollback(self) -> None:
        _write_secure_json(self.config_path, self._base_config_dict(), mode=0o600)
        mcfg = ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        def _client_factory(bcfg: ftb.BridgeConfig) -> MockTelegramTransport:
            if bcfg.agent_id == BOT_A_AGENT:
                return MockTelegramTransport(bot_id=BOT_A_UID, bot_username="your_bot_1")
            return MockTelegramTransport(bot_id=BOT_B_UID, bot_username="your_bot_2")

        # 1) Supervisor 1 holds supervisor.lock + both bridge.locks (0600 + FD_CLOEXEC)
        sup1 = ftb.MultiBotSupervisor(mcfg, client_factory=_client_factory, env={})
        sup1.startup()
        try:
            fds = sup1.held_lock_fds()
            self.assertEqual(len(fds), 3)
            for fd in fds:
                fd_flags = fcntl.fcntl(fd, fcntl.F_GETFD)
                self.assertTrue(fd_flags & fcntl.FD_CLOEXEC, "Lock fd missing FD_CLOEXEC")
            sup_lock_path = Path(self.state_root) / "supervisor.lock"
            self.assertEqual(stat.S_IMODE(os.stat(sup_lock_path).st_mode), 0o600)

            # Second multi-bot supervisor -> immediately fails on supervisor.lock
            sup2 = ftb.MultiBotSupervisor(mcfg, client_factory=_client_factory, env={})
            with self.assertRaises(ftb.InstanceLockError):
                sup2.startup()
            self.assertEqual(sup2.held_lock_fds(), [])

            # Reverse: single-bot process trying to claim managed bot_alpha -> fails on bridge.lock
            single_a = ftb.FederationTelegramBridge(
                mcfg.bots[0],
                client=MockTelegramTransport(bot_id=BOT_A_UID, bot_username="your_bot_1"),
                env={},
            )
            with self.assertRaises(ftb.InstanceLockError):
                single_a.startup()
            self.assertIsNone(single_a.instance_lock.fd)
        finally:
            sup1.shutdown()
        self.assertEqual(sup1.held_lock_fds(), [])

        # 2) Single-bot process holds Bot B's bridge.lock -> MultiBotSupervisor fails AND rolls back Bot A + supervisor.lock
        single_b = ftb.FederationTelegramBridge(
            mcfg.bots[1],
            client=MockTelegramTransport(bot_id=BOT_B_UID, bot_username="your_bot_2"),
            env={},
        )
        single_b.startup()
        try:
            sup3 = ftb.MultiBotSupervisor(mcfg, client_factory=_client_factory, env={})
            with self.assertRaises(ftb.InstanceLockError):
                sup3.startup()
            # Zero fd leak: supervisor.lock AND Bot A bridge.lock were released cleanly
            self.assertEqual(sup3.held_lock_fds(), [])
            probe_sup = ftb.InstanceLock(self.state_root, lock_filename="supervisor.lock")
            probe_sup.acquire()
            probe_sup.release()
            probe_a = ftb.InstanceLock(os.path.join(self.state_root, BOT_A_AGENT))
            probe_a.acquire()
            probe_a.release()
        finally:
            single_b.shutdown()

    def test_m3_unified_reload_sentinel_flushes_offsets_and_closes_all_locks_before_execv(self) -> None:
        _write_secure_json(self.config_path, self._base_config_dict(), mode=0o600)
        client_a = MockTelegramTransport(bot_id=BOT_A_UID, bot_username="your_bot_1")
        client_b = MockTelegramTransport(bot_id=BOT_B_UID, bot_username="your_bot_2")

        # Queue one update on Bot A (spawns an active job) and one update on Bot B;
        # trigger reload sentinel deterministically once both bots have processed their
        # first update (evidenced by polling with offset=202 and offset=306).
        sync_state = {"a_done": False, "b_done": False, "reload_sent": False}
        sync_lock = threading.Lock()
        orig_a_updates = client_a.get_updates
        orig_b_updates = client_b.get_updates

        def _maybe_trigger_reload() -> None:
            with sync_lock:
                if sync_state["a_done"] and sync_state["b_done"] and not sync_state["reload_sent"]:
                    sync_state["reload_sent"] = True
                    Path(self.sentinel).write_text("reload\n", encoding="utf-8")

        def _a_updates_track(**kwargs):
            if kwargs.get("offset") == 202:
                with sync_lock:
                    sync_state["a_done"] = True
                _maybe_trigger_reload()
            return orig_a_updates(**kwargs)

        def _b_updates_track(**kwargs):
            if kwargs.get("offset") == 306:
                with sync_lock:
                    sync_state["b_done"] = True
                _maybe_trigger_reload()
            return orig_b_updates(**kwargs)

        client_a.pending_updates.append([_make_update(201, chat_id=OWNER_UID, text="in-flight job a")])
        client_b.pending_updates.append([_make_update(305, chat_id=OWNER_UID, text="/status")])
        client_a.get_updates = _a_updates_track  # type: ignore[assignment]
        client_b.get_updates = _b_updates_track  # type: ignore[assignment]

        execv_calls: List[Tuple[str, List[str]]] = []
        locks_free_at_execv = {"ok": False}

        def _fake_execv(exe: str, argv: List[str]) -> None:
            # Verify ALL lock fds (supervisor.lock + both bridge.locks) are already released before os.execv
            l_sup = ftb.InstanceLock(self.state_root, lock_filename="supervisor.lock")
            l_a = ftb.InstanceLock(os.path.join(self.state_root, BOT_A_AGENT))
            l_b = ftb.InstanceLock(os.path.join(self.state_root, BOT_B_AGENT))
            try:
                l_sup.acquire()
                l_a.acquire()
                l_b.acquire()
                locks_free_at_execv["ok"] = True
            finally:
                l_b.release()
                l_a.release()
                l_sup.release()
            execv_calls.append((exe, list(argv)))

        env = {
            "AGY_FED_TG_BOTS_CONFIG": str(self.config_path),
            "AGY_FED_TG_RELOAD_FLAG": self.sentinel,
        }
        rc = ftb.main(
            [],
            env=env,
            secret_resolver=self._resolve_secret,
            execv_fn=_fake_execv,
            client_factory=lambda b: client_a if b.agent_id == BOT_A_AGENT else client_b,
            max_loops=None,
            install_signals=False,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(len(execv_calls), 1)
        self.assertTrue(locks_free_at_execv["ok"], "Locks were still held when execv was invoked")
        self.assertFalse(Path(self.sentinel).exists(), "Reload sentinel was not removed")

        # Offsets for BOTH bots atomically persisted with 0600 permissions
        off_a = Path(self.state_root) / BOT_A_AGENT / "offset.json"
        off_b = Path(self.state_root) / BOT_B_AGENT / "offset.json"
        self.assertEqual(stat.S_IMODE(os.stat(off_a).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(off_b).st_mode), 0o600)
        self.assertEqual(json.loads(off_a.read_text(encoding="utf-8"))["last_update_id"], 201)
        self.assertEqual(json.loads(off_b.read_text(encoding="utf-8"))["last_update_id"], 305)

        # In-flight job on Bot A was cleanly cancelled during graceful shutdown (zero stuck queued jobs)
        qdir = Path(federation_registry.pull_queue_dir(self.bus_dir))
        job_files = [p for p in qdir.glob("*.json") if not p.name.endswith(".tmp")]
        self.assertEqual(len(job_files), 1)
        jdata = json.loads(job_files[0].read_text(encoding="utf-8"))
        self.assertEqual(jdata["status"], "cancelled")
        self.assertTrue(jdata["cancelled"])

    def test_m3_sighup_and_sigterm_lifecycle_behavior(self) -> None:
        _write_secure_json(self.config_path, self._base_config_dict(), mode=0o600)
        mcfg = ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        # SIGHUP sets reload_requested=True and exits cleanly with all locks released
        if hasattr(signal, "SIGHUP"):
            client_a = MockTelegramTransport(bot_id=BOT_A_UID, bot_username="your_bot_1")
            client_b = MockTelegramTransport(bot_id=BOT_B_UID, bot_username="your_bot_2")
            fired = {"sent": False}

            def _trigger_sighup(**_kwargs):
                if not fired["sent"]:
                    fired["sent"] = True
                    os.kill(os.getpid(), signal.SIGHUP)
                return []

            client_a.get_updates = _trigger_sighup  # type: ignore[assignment]
            sup_hup = ftb.MultiBotSupervisor(
                mcfg,
                client_factory=lambda b: client_a if b.agent_id == BOT_A_AGENT else client_b,
                env={},
                monitor_interval_sec=0.02,
            )
            sup_hup.run(install_signals=True)
            self.assertTrue(sup_hup.reload_requested)
            self.assertEqual(sup_hup.held_lock_fds(), [])

        # SIGTERM exits cleanly with reload_requested=False and all locks released
        client_a2 = MockTelegramTransport(bot_id=BOT_A_UID, bot_username="your_bot_1")
        client_b2 = MockTelegramTransport(bot_id=BOT_B_UID, bot_username="your_bot_2")
        fired2 = {"sent": False}

        def _trigger_sigterm(**_kwargs):
            if not fired2["sent"]:
                fired2["sent"] = True
                os.kill(os.getpid(), signal.SIGTERM)
            return []

        client_a2.get_updates = _trigger_sigterm  # type: ignore[assignment]
        sup_term = ftb.MultiBotSupervisor(
            mcfg,
            client_factory=lambda b: client_a2 if b.agent_id == BOT_A_AGENT else client_b2,
            env={},
            monitor_interval_sec=0.02,
        )
        sup_term.run(install_signals=True)
        self.assertFalse(sup_term.reload_requested)
        self.assertEqual(sup_term.held_lock_fds(), [])

    def test_m3_reload_with_corrupted_or_insecure_config_fails_closed(self) -> None:
        scenarios = ("corrupt_json", "wide_mode_0644", "duplicate_agent_id", "missing_secret_ref_with_env_token")
        for idx, scenario in enumerate(scenarios, start=1):
            _write_secure_json(self.config_path, self._base_config_dict(), mode=0o600)
            client_a = MockTelegramTransport(bot_id=BOT_A_UID, bot_username="your_bot_1")
            client_b = MockTelegramTransport(bot_id=BOT_B_UID, bot_username="your_bot_2")
            sentinel_i = str(self.root / f"reload_{idx}")
            corrupted = {"done": False}

            def _corrupt_and_reload(**_kwargs):
                if not corrupted["done"]:
                    corrupted["done"] = True
                    if scenario == "corrupt_json":
                        self.config_path.write_text("{corrupt", encoding="utf-8")
                    elif scenario == "wide_mode_0644":
                        os.chmod(self.config_path, 0o644)
                    elif scenario == "duplicate_agent_id":
                        bad = self._base_config_dict()
                        bad["bots"][1]["agent_id"] = BOT_A_AGENT
                        _write_secure_json(self.config_path, bad, mode=0o600)
                    elif scenario == "missing_secret_ref_with_env_token":
                        bad = self._base_config_dict()
                        del bad["bots"][0]["token_secret_ref"]
                        _write_secure_json(self.config_path, bad, mode=0o600)
                    Path(sentinel_i).write_text("reload\n", encoding="utf-8")
                return []

            client_a.get_updates = _corrupt_and_reload  # type: ignore[assignment]
            execv_called: List[Any] = []
            env = {
                "AGY_FED_TG_BOTS_CONFIG": str(self.config_path),
                "AGY_FED_TG_RELOAD_FLAG": sentinel_i,
                "AGY_FED_TG_BOT_TOKEN": self.token_a,  # Must NEVER be used as fallback
            }
            rc = ftb.main(
                [],
                env=env,
                secret_resolver=self._resolve_secret,
                execv_fn=lambda exe, argv: execv_called.append((exe, argv)),
                client_factory=lambda b: client_a if b.agent_id == BOT_A_AGENT else client_b,
                install_signals=False,
            )
            self.assertEqual(rc, 2, f"Expected fail-closed exit code 2 for scenario {scenario}")
            self.assertEqual(execv_called, [], f"execv must not be invoked on broken config ({scenario})")
            # Locks must be released cleanly
            probe = ftb.InstanceLock(self.state_root, lock_filename="supervisor.lock")
            probe.acquire()
            probe.release()


# ===========================================================================
# M4: Single-Bot Backward Compatibility, Unified Service Unit & Tooling Alignment
# ===========================================================================
class TestM4BackwardCompatServiceUnitAndTooling(_BridgeTestBase):
    def test_m4_single_bot_env_mode_backward_compatible_when_bots_config_unset(self) -> None:
        client = MockTelegramTransport()
        client.pending_updates.append([_make_update(77, chat_id=OWNER_UID, text="/status")])
        env = {
            "AGY_FED_TG_AGENT_ID": EXAMPLE_AGENT_ID,
            "AGY_FED_TG_OWNER_USERS": str(OWNER_UID),
            "AGY_FED_TG_TOKEN_SECRET_REF": EXAMPLE_SECRET_REF,
            "AGY_FED_TG_STATE_DIR": self.state_dir,
            "AGY_FED_TG_BUS_DIR": self.bus_dir,
            "AGY_FED_TG_RELOAD_SENTINEL": self.sentinel,
            "AGY_FED_TG_POLL_TIMEOUT_SEC": "1",
        }
        rc = ftb.main(
            [],
            env=env,
            secret_resolver=lambda _r: self.token,
            client_factory=lambda _cfg: client,
            max_loops=1,
            install_signals=False,
        )
        self.assertEqual(rc, 0)
        sent = client.get_calls("sendMessage")
        self.assertEqual(len(sent), 1)
        self.assertIn(EXAMPLE_AGENT_ID, sent[0]["text"])

    def test_m4_unified_systemd_unit_gitignore_and_sync_live_alignment(self) -> None:
        legacy_unit = REPO_ROOT / "systemd" / "agy-tg-bridge-f01.service"
        unified_unit = REPO_ROOT / "systemd" / "agy-tg-bridge-fed.service"
        self.assertFalse(legacy_unit.exists(), "Legacy f01 systemd unit must be removed")
        if unified_unit.is_file():
            content = unified_unit.read_text(encoding="utf-8")
            for required_line in (
                "After=network-online.target agy-federation-hub.service",
                "Wants=network-online.target agy-federation-hub.service",
                "UMask=0077",
                "NoNewPrivileges=true",
                "Environment=AGY_FED_TG_BOTS_CONFIG=",
                "/agy-tg-bridge/fed_bots.json",
                "Environment=AGY_FED_TG_RELOAD_FLAG=/tmp/agy_fed_tg_reload",
                "ExecStart=/usr/bin/python3 ",
                "/agy-tg-bridge/federation_tg_bridge.py",
            ):
                self.assertIn(required_line, content)
            self.assertNotIn("agy_fed_tg_f01_reload", content)

        gitignore_path = REPO_ROOT / ".gitignore"
        if gitignore_path.is_file():
            gi_text = gitignore_path.read_text(encoding="utf-8")
            self.assertIn("fed_bots.json", gi_text)
            self.assertIn(".env.fed", gi_text)

        sync_live_path = REPO_ROOT / "scripts" / "sync_live.py"
        if sync_live_path.is_file():
            sl_text = sync_live_path.read_text(encoding="utf-8")
            self.assertNotIn("agy_fed_tg_f01_reload", sl_text)
            self.assertNotIn("_touch_fed_tg_reload_sentinels", sl_text)
            self.assertIn("/tmp/agy_fed_tg_reload", sl_text)

            import importlib.util

            spec = importlib.util.spec_from_file_location("_test_sync_live_mod", str(sync_live_path))
            self.assertIsNotNone(spec)
            assert spec is not None and spec.loader is not None
            sl_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(sl_mod)
            self.assertEqual(sl_mod._FED_TG_RELOAD_SENTINELS, ("/tmp/agy_fed_tg_reload",))
            self.assertFalse(hasattr(sl_mod, "_touch_fed_tg_reload_sentinels"))

            tmp_bridge_flag = self.root / "bridge_reload"
            tmp_fed_flag = self.root / "fed_reload"
            with (
                mock.patch.object(sl_mod, "_BRIDGE_RELOAD_SENTINELS", (str(tmp_bridge_flag),)),
                mock.patch.object(sl_mod, "_FED_TG_RELOAD_SENTINELS", (str(tmp_fed_flag),)),
            ):
                # Default zero-arg call preserves bridge-only behavior
                sl_mod._touch_reload_sentinels()
                self.assertTrue(tmp_bridge_flag.exists())
                self.assertFalse(tmp_fed_flag.exists())
                tmp_bridge_flag.unlink()

                # Fed-only call writes only unified federation sentinel
                sl_mod._touch_reload_sentinels(include_bridges=False, include_fed_tg=True)
                self.assertFalse(tmp_bridge_flag.exists())
                self.assertTrue(tmp_fed_flag.exists())
                tmp_fed_flag.unlink()

                # Combined call writes both
                sl_mod._touch_reload_sentinels(include_bridges=True, include_fed_tg=True)
                self.assertTrue(tmp_bridge_flag.exists())
                self.assertTrue(tmp_fed_flag.exists())


# ===========================================================================
# G1: RBAC / Tenant / DM Isolation for Shared Group Bus
# ===========================================================================
class TestG1GroupBusRBACAndDMIsolation(_BridgeTestBase):
    def test_g1_unauthorized_denied_bot_anon_bindgroup_and_dm_never_touch_bot_bus(self) -> None:
        # Use multi-bot config to also exercise defaults | bot | env denied_chats union
        cfg_path = self.root / "g1_bots.json"
        state_root = str(self.root / "g1_state")
        env_denied_chat = -55002
        bot_denied_chat = -55003
        unbound_chat = -55004
        cfg_payload = {
            "defaults": {
                "owner_users": [OWNER_UID],
                "denied_chats": [GROUP_DENIED],
                "state_root_dir": state_root,
                "bus_dir": self.bus_dir,
                "job_poll_interval_sec": 0.01,
            },
            "bots": [
                {
                    "name": "bot_g1",
                    "agent_id": EXAMPLE_AGENT_ID,
                    "enabled": True,
                    "token_secret_ref": EXAMPLE_SECRET_REF,
                    "allowed_chats": [GROUP_ALLOWED],
                    "denied_chats": [bot_denied_chat],
                }
            ],
        }
        _write_secure_json(cfg_path, cfg_payload, mode=0o600)
        mcfg = ftb.load_multi_bot_config(
            str(cfg_path),
            env={"AGY_FED_TG_DENIED_CHATS": str(env_denied_chat)},
            secret_resolver=lambda _r: self.token,
        )
        client = MockTelegramTransport(bot_id=BOT_UID, bot_username=BOT_USERNAME)
        bridge = ftb.FederationTelegramBridge(mcfg.bots[0], client=client, env={})
        bridge.startup()
        try:
            with (
                mock.patch.object(
                    bot_bus, "record_group_message", wraps=bot_bus.record_group_message
                ) as spy_rec,
                mock.patch.object(
                    bot_bus, "format_unseen_group_history", wraps=bot_bus.format_unseen_group_history
                ) as spy_fmt,
            ):
                # 1) Non-owner in authorized group
                self.assertFalse(
                    bridge.handle_update(
                        _make_update(
                            1,
                            chat_id=GROUP_ALLOWED,
                            chat_type="supergroup",
                            from_user={"id": OTHER_UID, "is_bot": False, "username": "intruder"},
                            text=f"@{BOT_USERNAME} leak context",
                        )
                    )
                )
                # 2a) Anonymous admin (sender_chat)
                self.assertFalse(
                    bridge.handle_update(
                        _make_update(
                            2,
                            chat_id=GROUP_ALLOWED,
                            chat_type="supergroup",
                            from_user={"id": OWNER_UID, "is_bot": False, "username": "owner_user"},
                            sender_chat={"id": GROUP_ALLOWED, "type": "supergroup"},
                            text="anon admin chatter",
                        )
                    )
                )
                # 2b) from.is_bot=True (even with OWNER_UID)
                self.assertFalse(
                    bridge.handle_update(
                        _make_update(
                            3,
                            chat_id=GROUP_ALLOWED,
                            chat_type="supergroup",
                            from_user={"id": OWNER_UID, "is_bot": True, "username": OTHER_BOT_USERNAME},
                            text="bot chatter",
                        )
                    )
                )
                # 3) Denied chats across defaults | bot | env union
                for idx, denied_cid in enumerate((GROUP_DENIED, bot_denied_chat, env_denied_chat), start=4):
                    self.assertFalse(
                        bridge.handle_update(
                            _make_update(
                                idx,
                                chat_id=denied_cid,
                                chat_type="supergroup",
                                text=f"@{BOT_USERNAME} denied group msg",
                            )
                        )
                    )
                # 4) Unauthorized / unbound group: plain message + /bindgroup (only updates bindings.json)
                self.assertFalse(
                    bridge.handle_update(
                        _make_update(
                            10,
                            chat_id=unbound_chat,
                            chat_type="supergroup",
                            text="plain message in unbound group",
                        )
                    )
                )
                self.assertTrue(
                    bridge.handle_update(
                        _make_update(
                            11,
                            chat_id=unbound_chat,
                            chat_type="supergroup",
                            text="/bindgroup",
                        )
                    )
                )
                self.assertIn(unbound_chat, bridge.state.load_bound_chats())

                # 5) Owner DM (chat_id > 0): normal turns + /clear never touch bot_bus; keeps local _chat_context
                self.assertTrue(bridge.handle_update(_make_update(12, chat_id=OWNER_UID, text="dm turn one")))
                job1 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
                self.assertIsNotNone(job1)
                bridge.queue.complete(
                    job1["job_id"], EXAMPLE_AGENT_ID, result_text="dm reply one", auth_token=self.worker_token
                )
                bridge.wait_for_active_jobs(timeout=3.0)

                self.assertTrue(bridge.handle_update(_make_update(13, chat_id=OWNER_UID, text="dm turn two")))
                job2 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
                self.assertIsNotNone(job2)
                self.assertIn("[Recent Chat Context]", job2["prompt"])
                self.assertIn("dm turn one", job2["prompt"])
                self.assertIn("dm reply one", job2["prompt"])
                bridge.queue.complete(
                    job2["job_id"], EXAMPLE_AGENT_ID, result_text="dm reply two", auth_token=self.worker_token
                )
                bridge.wait_for_active_jobs(timeout=3.0)

                self.assertTrue(bridge.handle_update(_make_update(14, chat_id=OWNER_UID, text="/clear")))
                with bridge._ctx_lock:
                    self.assertNotIn(OWNER_UID, bridge._chat_context)

                # Zero calls to bot_bus across all 5 cases
                self.assertEqual(spy_rec.call_count, 0)
                self.assertEqual(spy_fmt.call_count, 0)
                gh_dir = Path(self.bus_dir) / "group_history"
                for cid in (GROUP_ALLOWED, GROUP_DENIED, bot_denied_chat, env_denied_chat, unbound_chat, OWNER_UID):
                    self.assertFalse((gh_dir / f"{cid}.json").exists())
        finally:
            bridge.shutdown()


# ===========================================================================
# G2: Cross-Bot Interop, ContextVar bus_dir Concurrency Isolation & Scrubbing
# ===========================================================================
class TestG2CrossBotSharingBusDirIsolationAndRedaction(_MultiBotTestBase):
    def test_g2_concurrent_bus_dir_isolation_shared_interop_and_full_token_scrubbing(self) -> None:
        orig_global_bus_dir = bot_bus.BUS_DIR
        dir_a = str(self.root / "bus_a")
        dir_b = str(self.root / "bus_b")
        dir_shared = str(self.root / "bus_shared")

        _, worker_tok_a_iso = _register_pull_agent(dir_a, BOT_A_AGENT)
        _, worker_tok_b_iso = _register_pull_agent(dir_b, BOT_B_AGENT)
        _, worker_tok_shared = _register_pull_agent(dir_shared, EXAMPLE_AGENT_ID)

        enc_a = urllib.parse.quote(self.token_a, safe="")
        enc_b = urllib.parse.quote(self.token_b, safe="")
        enc_b_lower = enc_b.replace("%3A", "%3a")

        # Part 1: MultiBotSupervisor concurrent dual threads with isolated bus_dir (dir_a vs dir_b)
        iso_cfg = self._base_config_dict()
        iso_cfg["bots"][0]["bus_dir"] = dir_a
        iso_cfg["bots"][1]["bus_dir"] = dir_b
        _write_secure_json(self.config_path, iso_cfg, mode=0o600)
        mcfg = ftb.load_multi_bot_config(str(self.config_path), env={}, secret_resolver=self._resolve_secret)

        client_a = MockTelegramTransport(bot_id=BOT_A_UID, bot_username="your_bot_1")
        client_b = MockTelegramTransport(bot_id=BOT_B_UID, bot_username="your_bot_2")
        sup = ftb.MultiBotSupervisor(
            mcfg,
            client_factory=lambda b: client_a if b.agent_id == BOT_A_AGENT else client_b,
            env={},
        )
        sup.startup()
        try:
            br_a = sup.bridges["bot_alpha"]
            br_b = sup.bridges["bot_beta"]
            barrier = threading.Barrier(2)
            errors: List[Exception] = []

            def _run_bot(br, wtok, agent_id, tag, uname, base_uid):
                try:
                    barrier.wait(timeout=3.0)
                    # Plain human chatter with both raw and URL-encoded tokens
                    br.handle_update(
                        _make_update(
                            base_uid,
                            chat_id=GROUP_ALLOWED,
                            chat_type="supergroup",
                            message_id=base_uid * 10,
                            text=f"{tag}_chatter raw={self.token_a} other={self.token_b} enc={enc_b} low={enc_b_lower}",
                        )
                    )
                    # Trigger task
                    br.handle_update(
                        _make_update(
                            base_uid + 1,
                            chat_id=GROUP_ALLOWED,
                            chat_type="supergroup",
                            message_id=(base_uid + 1) * 10,
                            text=f"@{uname} {tag}_task {enc_a}",
                        )
                    )
                    claimed = br.queue.claim(agent_id, auth_token=wtok)
                    assert claimed is not None
                    for leak in (self.token_a, self.token_b, enc_a, enc_b, enc_b_lower):
                        assert leak not in claimed["prompt"], f"Token leaked into prompt: {leak}"
                    br.queue.complete(
                        claimed["job_id"],
                        agent_id,
                        status="done",
                        result_text=f"{tag}_reply {self.token_a} {self.token_b} {enc_a} {enc_b} {enc_b_lower}",
                        auth_token=wtok,
                    )
                    br.wait_for_active_jobs(timeout=3.0)
                except Exception as exc:
                    errors.append(exc)

            th_a = threading.Thread(
                target=_run_bot, args=(br_a, worker_tok_a_iso, BOT_A_AGENT, "ONLY_A", "your_bot_1", 10)
            )
            th_b = threading.Thread(
                target=_run_bot, args=(br_b, worker_tok_b_iso, BOT_B_AGENT, "ONLY_B", "your_bot_2", 30)
            )
            th_a.start()
            th_b.start()
            th_a.join(timeout=5.0)
            th_b.join(timeout=5.0)
            self.assertEqual(errors, [])

            # Verify global bot_bus.BUS_DIR untouched
            self.assertEqual(bot_bus.BUS_DIR, orig_global_bus_dir)

            # Verify strict dir_a vs dir_b isolation and zero token leakage in disk JSON
            gh_a_path = Path(dir_a) / "group_history" / f"{GROUP_ALLOWED}.json"
            gh_b_path = Path(dir_b) / "group_history" / f"{GROUP_ALLOWED}.json"
            self.assertTrue(gh_a_path.is_file())
            self.assertTrue(gh_b_path.is_file())

            raw_a = gh_a_path.read_text(encoding="utf-8")
            raw_b = gh_b_path.read_text(encoding="utf-8")
            self.assertIn("ONLY_A_chatter", raw_a)
            self.assertIn("ONLY_A_reply", raw_a)
            self.assertNotIn("ONLY_B", raw_a)
            self.assertIn("ONLY_B_chatter", raw_b)
            self.assertIn("ONLY_B_reply", raw_b)
            self.assertNotIn("ONLY_A", raw_b)
            for disk_json in (raw_a, raw_b):
                for leak in (self.token_a, self.token_b, enc_a, enc_b, enc_b_lower):
                    self.assertNotIn(leak, disk_json)
        finally:
            sup.shutdown()

        # Part 2: Shared dir_shared bidirectional interop (local bot <-> federation bot)
        shared_cfg = ftb.BridgeConfig(
            agent_id=EXAMPLE_AGENT_ID,
            bot_token=self.token_a,
            owner_users=frozenset({OWNER_UID}),
            allowed_chats=frozenset({GROUP_ALLOWED}),
            state_dir=str(self.root / "shared_state"),
            reload_sentinel=str(self.root / "shared_reload"),
            bus_dir=dir_shared,
            job_poll_interval_sec=0.01,
        )
        shared_client = MockTelegramTransport(bot_id=BOT_UID, bot_username=BOT_USERNAME)
        shared_bridge = ftb.FederationTelegramBridge(shared_cfg, client=shared_client, env={})
        shared_bridge.startup()
        try:
            # Local coordinator bot writes a message to shared bus (even containing raw/encoded token)
            with bot_bus.bind_bus_dir(dir_shared):
                bot_bus.record_group_message(
                    GROUP_ALLOWED,
                    msg_id=5001,
                    thread_id=None,
                    sender_handle=OTHER_BOT_USERNAME,
                    sender_role="coordinator",
                    is_bot=True,
                    text=f"Local bot handoff notes with secret {self.token_b} and {enc_b}",
                    source="tg",
                )

            # Federation bot receives Owner mention in same group
            self.assertTrue(
                shared_bridge.handle_update(
                    _make_update(
                        1,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        message_id=5002,
                        text=f"@{BOT_USERNAME} continue from local bot",
                    )
                )
            )
            claimed = shared_bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=worker_tok_shared)
            self.assertIsNotNone(claimed)
            self.assertIn("Local bot handoff notes", claimed["prompt"])
            self.assertIn(f"@{OTHER_BOT_USERNAME}(coordinator)", claimed["prompt"])
            for leak in (self.token_a, self.token_b, enc_a, enc_b, enc_b_lower):
                self.assertNotIn(leak, claimed["prompt"])

            # Remote agent finishes with a reply containing secret tokens
            shared_bridge.queue.complete(
                claimed["job_id"],
                EXAMPLE_AGENT_ID,
                status="done",
                result_text=f"Fed reply for local bot {self.token_a} {self.token_b} {enc_a} {enc_b}",
                auth_token=worker_tok_shared,
            )
            shared_bridge.wait_for_active_jobs(timeout=3.0)

            edits = shared_client.get_calls("editMessageText")
            self.assertEqual(len(edits), 1)
            delivered_mid = edits[0]["message_id"]

            # Inspect disk JSON: text_excerpt & full_text scrubbed, metadata fields exact
            gh_shared = Path(dir_shared) / "group_history" / f"{GROUP_ALLOWED}.json"
            data = json.loads(gh_shared.read_text(encoding="utf-8"))
            bot_entries = [e for e in data["entries"] if e.get("msg_id") == delivered_mid]
            self.assertEqual(len(bot_entries), 1)
            entry = bot_entries[0]
            self.assertTrue(entry["is_bot"])
            self.assertEqual(entry["sender_role"], "worker")
            self.assertEqual(entry["sender_handle"], BOT_USERNAME)
            for field in ("text_excerpt", "full_text"):
                for leak in (self.token_a, self.token_b, enc_a, enc_b, enc_b_lower):
                    self.assertNotIn(leak, entry[field])

            # Local bot reads federation bot's reply from shared bus
            with bot_bus.bind_bus_dir(dir_shared):
                seen_by_local = bot_bus.format_unseen_group_history(
                    GROUP_ALLOWED,
                    OTHER_BOT_USERNAME,
                    thread_id=None,
                    advance_cursor=True,
                )
            self.assertIn(f"@{BOT_USERNAME}(worker)", seen_by_local)
            self.assertIn("Fed reply for local bot", seen_by_local)
            for leak in (self.token_a, self.token_b, enc_a, enc_b, enc_b_lower):
                self.assertNotIn(leak, seen_by_local)
            self.assertEqual(bot_bus.BUS_DIR, orig_global_bus_dir)
        finally:
            shared_bridge.shutdown()


# ===========================================================================
# G3: Dedup, Cursor Transaction Timing, /clear Isolation & I/O Degradation
# ===========================================================================
class TestG3DeduplicationCursorTxClearAndIODegradation(_BridgeTestBase):
    def test_g3_dedup_no_double_injection_and_no_self_echo(self) -> None:
        bridge, _client = self._build_bridge(allowed_chats=(GROUP_ALLOWED,))
        bridge.startup()
        try:
            # Plain human chatter + another bot's message
            self.assertFalse(
                bridge.handle_update(
                    _make_update(
                        1,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        message_id=101,
                        text="plain human context alpha",
                    )
                )
            )
            with bot_bus.bind_bus_dir(self.bus_dir):
                bot_bus.record_group_message(
                    GROUP_ALLOWED,
                    msg_id=102,
                    sender_handle="peer_bot",
                    sender_role="coordinator",
                    is_bot=True,
                    text="peer bot context beta",
                )

            # Owner triggers task 1 via exact mention
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        2,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        message_id=103,
                        text=f"@{BOT_USERNAME} unique_trigger_gamma",
                    )
                )
            )
            job1 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job1)
            # Contains unseen bus history, NOT double-injected _chat_context, trigger msg NOT duplicated
            self.assertIn("plain human context alpha", job1["prompt"])
            self.assertIn("peer bot context beta", job1["prompt"])
            self.assertNotIn("[Recent Chat Context]", job1["prompt"])
            self.assertEqual(job1["prompt"].count("unique_trigger_gamma"), 1)

            # Complete job1 -> bot writes is_bot=True reply to bus
            bridge.queue.complete(
                job1["job_id"],
                EXAMPLE_AGENT_ID,
                result_text="self_bot_reply_delta",
                auth_token=self.worker_token,
            )
            bridge.wait_for_active_jobs(timeout=3.0)

            # Next turn: bot must NOT echo its own previous is_bot=True reply
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        3,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        message_id=104,
                        text=f"@{BOT_USERNAME} second_trigger_epsilon",
                    )
                )
            )
            job2 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job2)
            self.assertNotIn("self_bot_reply_delta", job2["prompt"])
            self.assertNotIn("[Recent Chat Context]", job2["prompt"])
            self.assertEqual(job2["prompt"].count("second_trigger_epsilon"), 1)
            bridge.queue.complete(
                job2["job_id"], EXAMPLE_AGENT_ID, result_text="done2", auth_token=self.worker_token
            )
            bridge.wait_for_active_jobs(timeout=3.0)
        finally:
            bridge.shutdown()

    def test_g3_cursor_not_advanced_on_disabled_agent_or_busy_rejection(self) -> None:
        owner_auth = federation_registry.make_owner_auth("test_owner", env={})
        bridge, _client = self._build_bridge(allowed_chats=(GROUP_ALLOWED,))
        bridge.startup()
        try:
            # (a) Unseen history present, agent disabled -> rejected without advancing cursor
            with bot_bus.bind_bus_dir(self.bus_dir):
                bot_bus.record_group_message(
                    GROUP_ALLOWED,
                    msg_id=201,
                    sender_handle="peer_bot",
                    sender_role="coordinator",
                    is_bot=True,
                    text="must_survive_disabled_check",
                )
            federation_registry.update_agent(
                EXAMPLE_AGENT_ID, enabled=False, owner_auth=owner_auth, bus_dir=self.bus_dir, env={}
            )
            bridge.handle_update(
                _make_update(
                    1,
                    chat_id=GROUP_ALLOWED,
                    chat_type="supergroup",
                    message_id=202,
                    text=f"@{BOT_USERNAME} blocked while disabled",
                )
            )
            self.assertEqual(_count_pull_queue_jobs(self.bus_dir), 0)

            # Re-enable agent -> subsequent request STILL reads unseen history!
            federation_registry.update_agent(
                EXAMPLE_AGENT_ID, enabled=True, owner_auth=owner_auth, bus_dir=self.bus_dir, env={}
            )
            bridge.handle_update(
                _make_update(
                    2,
                    chat_id=GROUP_ALLOWED,
                    chat_type="supergroup",
                    message_id=203,
                    text=f"@{BOT_USERNAME} task after reenable",
                )
            )
            job1 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job1)
            self.assertIn("must_survive_disabled_check", job1["prompt"])

            # (b) While job1 is active (busy), new unseen message arrives and a busy trigger is rejected
            with bot_bus.bind_bus_dir(self.bus_dir):
                bot_bus.record_group_message(
                    GROUP_ALLOWED,
                    msg_id=204,
                    sender_handle="peer_bot",
                    sender_role="coordinator",
                    is_bot=True,
                    text="must_survive_busy_rejection",
                )
            bridge.handle_update(
                _make_update(
                    3,
                    chat_id=GROUP_ALLOWED,
                    chat_type="supergroup",
                    message_id=205,
                    text=f"@{BOT_USERNAME} rejected because busy",
                )
            )
            # Complete job1, then send a normal trigger -> must still read msg 204!
            bridge.queue.complete(
                job1["job_id"], EXAMPLE_AGENT_ID, result_text="done1", auth_token=self.worker_token
            )
            bridge.wait_for_active_jobs(timeout=3.0)

            bridge.handle_update(
                _make_update(
                    4,
                    chat_id=GROUP_ALLOWED,
                    chat_type="supergroup",
                    message_id=206,
                    text=f"@{BOT_USERNAME} task after busy cleared",
                )
            )
            job2 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job2)
            self.assertIn("must_survive_busy_rejection", job2["prompt"])
            bridge.queue.complete(
                job2["job_id"], EXAMPLE_AGENT_ID, result_text="done2", auth_token=self.worker_token
            )
            bridge.wait_for_active_jobs(timeout=3.0)
        finally:
            bridge.shutdown()

    def test_g3_clear_in_topic_100_isolates_topic_200_and_other_bots(self) -> None:
        bridge, _client = self._build_bridge(allowed_chats=(GROUP_ALLOWED,))
        bridge.startup()
        try:
            # Populate Topic 100 and Topic 200 in bot_bus + local _chat_context
            self.assertFalse(
                bridge.handle_update(
                    _make_update(
                        1,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        is_forum=True,
                        is_topic_message=True,
                        message_thread_id=100,
                        message_id=301,
                        text="topic100_old_msg",
                    )
                )
            )
            self.assertFalse(
                bridge.handle_update(
                    _make_update(
                        2,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        is_forum=True,
                        is_topic_message=True,
                        message_thread_id=200,
                        message_id=302,
                        text="topic200_old_msg",
                    )
                )
            )

            # Execute /clear in Topic 100
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        3,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        is_forum=True,
                        is_topic_message=True,
                        message_thread_id=100,
                        message_id=303,
                        text="/clear",
                    )
                )
            )

            # Local _chat_context cleared ONLY for Topic 100, intact for Topic 200
            with bridge._ctx_lock:
                self.assertNotIn((GROUP_ALLOWED, 100), bridge._chat_context)
                self.assertIn((GROUP_ALLOWED, 200), bridge._chat_context)

            # Trigger in Topic 100 -> must NOT see topic100_old_msg
            bridge.handle_update(
                _make_update(
                    4,
                    chat_id=GROUP_ALLOWED,
                    chat_type="supergroup",
                    is_forum=True,
                    is_topic_message=True,
                    message_thread_id=100,
                    message_id=304,
                    text=f"@{BOT_USERNAME} fresh_t100",
                )
            )
            job_t100 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job_t100)
            self.assertNotIn("topic100_old_msg", job_t100["prompt"])
            bridge.queue.complete(
                job_t100["job_id"], EXAMPLE_AGENT_ID, result_text="ok100", auth_token=self.worker_token
            )
            bridge.wait_for_active_jobs(timeout=3.0)

            # Trigger in Topic 200 -> MUST still see topic200_old_msg
            bridge.handle_update(
                _make_update(
                    5,
                    chat_id=GROUP_ALLOWED,
                    chat_type="supergroup",
                    is_forum=True,
                    is_topic_message=True,
                    message_thread_id=200,
                    message_id=305,
                    text=f"@{BOT_USERNAME} fresh_t200",
                )
            )
            job_t200 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(job_t200)
            self.assertIn("topic200_old_msg", job_t200["prompt"])
            bridge.queue.complete(
                job_t200["job_id"], EXAMPLE_AGENT_ID, result_text="ok200", auth_token=self.worker_token
            )
            bridge.wait_for_active_jobs(timeout=3.0)

            # Another bot's cursor in Topic 100 is unaffected and still sees topic100_old_msg
            with bot_bus.bind_bus_dir(self.bus_dir):
                other_unseen = bot_bus.format_unseen_group_history(
                    GROUP_ALLOWED, "other_peer_bot", thread_id=100, advance_cursor=False
                )
            self.assertIn("topic100_old_msg", other_unseen)
        finally:
            bridge.shutdown()

    def test_g3_bot_bus_io_error_degrades_gracefully_with_scrubbed_warning(self) -> None:
        log_buf = io.StringIO()
        test_logger = logging.getLogger("test.g3.io_degrade")
        test_logger.handlers.clear()
        test_logger.filters.clear()
        test_logger.propagate = False
        test_logger.setLevel(logging.WARNING)
        handler = logging.StreamHandler(log_buf)
        test_logger.addHandler(handler)

        cfg = ftb.BridgeConfig(
            agent_id=EXAMPLE_AGENT_ID,
            bot_token=self.token,
            owner_users=frozenset({OWNER_UID}),
            allowed_chats=frozenset({GROUP_ALLOWED}),
            state_dir=self.state_dir,
            reload_sentinel=self.sentinel,
            bus_dir=self.bus_dir,
            job_poll_interval_sec=0.01,
        )
        client = MockTelegramTransport(bot_id=BOT_UID, bot_username=BOT_USERNAME)
        bridge = ftb.FederationTelegramBridge(cfg, client=client, env={}, logger=test_logger)
        bridge.startup()
        encoded_tok = urllib.parse.quote(self.token, safe="")
        try:
            boom = OSError(f"disk full token={self.token} enc={encoded_tok}")
            with (
                mock.patch.object(bot_bus, "record_group_message", side_effect=boom),
                mock.patch.object(bot_bus, "format_unseen_group_history", side_effect=boom),
            ):
                self.assertTrue(
                    bridge.handle_update(
                        _make_update(
                            1,
                            chat_id=GROUP_ALLOWED,
                            chat_type="supergroup",
                            message_id=401,
                            text=f"@{BOT_USERNAME} proceed despite disk full",
                        )
                    )
                )
                claimed = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
                self.assertIsNotNone(claimed)
                self.assertIn("proceed despite disk full", claimed["prompt"])
                bridge.queue.complete(
                    claimed["job_id"],
                    EXAMPLE_AGENT_ID,
                    result_text="delivered despite bus io error",
                    auth_token=self.worker_token,
                )
                bridge.wait_for_active_jobs(timeout=3.0)

            edits = client.get_calls("editMessageText")
            self.assertEqual(len(edits), 1)
            self.assertIn("delivered despite bus io error", edits[0]["text"])
            logs = log_buf.getvalue()
            self.assertIn("disk full", logs)
            self.assertIn("[REDACTED]", logs)
            self.assertNotIn(self.token, logs)
            self.assertNotIn(encoded_tok, logs)
        finally:
            bridge.shutdown()

    def test_g3_cursor_not_advanced_on_enqueue_failure_or_cancel_and_advances_on_retry(self) -> None:
        bridge, client = self._build_bridge(allowed_chats=(GROUP_ALLOWED,))
        bridge.startup()
        try:
            bot_handle = bridge._bus_bot_handle()

            def _read_cursor() -> int:
                with bot_bus.bind_bus_dir(self.bus_dir):
                    hist_path = Path(bot_bus._group_history_path(GROUP_ALLOWED))
                    ckey = bot_bus._cursor_key(bot_handle, None)
                if not hist_path.is_file():
                    return 0
                data = json.loads(hist_path.read_text(encoding="utf-8"))
                cursors = data.get("cursors") or {}
                return int(cursors.get(ckey) or 0)

            # (a) queue.enqueue raises PermissionError -> cursor MUST NOT advance
            with bot_bus.bind_bus_dir(self.bus_dir):
                bot_bus.record_group_message(
                    GROUP_ALLOWED,
                    msg_id=501,
                    sender_handle="peer_bot",
                    sender_role="coordinator",
                    is_bot=True,
                    text="must_survive_permission_error",
                )
            self.assertEqual(_read_cursor(), 0)
            with mock.patch.object(
                bridge.queue, "enqueue", side_effect=PermissionError("toctou_revoked_env")
            ):
                bridge.handle_update(
                    _make_update(
                        1,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        message_id=502,
                        text=f"@{BOT_USERNAME} trigger perm fail",
                    )
                )
            self.assertEqual(_count_pull_queue_jobs(self.bus_dir), 0)
            self.assertEqual(_read_cursor(), 0)
            with bot_bus.bind_bus_dir(self.bus_dir):
                unseen_after_perm = bot_bus.format_unseen_group_history(
                    GROUP_ALLOWED, bot_handle, advance_cursor=False
                )
            self.assertIn("must_survive_permission_error", unseen_after_perm)

            # (b) queue.enqueue raises RuntimeError -> cursor MUST NOT advance
            with bot_bus.bind_bus_dir(self.bus_dir):
                bot_bus.record_group_message(
                    GROUP_ALLOWED,
                    msg_id=503,
                    sender_handle="peer_bot",
                    sender_role="coordinator",
                    is_bot=True,
                    text="must_survive_runtime_error",
                )
            with mock.patch.object(
                bridge.queue, "enqueue", side_effect=RuntimeError("disk_write_failure")
            ):
                bridge.handle_update(
                    _make_update(
                        2,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        message_id=504,
                        text=f"@{BOT_USERNAME} trigger runtime fail",
                    )
                )
            self.assertEqual(_count_pull_queue_jobs(self.bus_dir), 0)
            self.assertEqual(_read_cursor(), 0)

            # (c) already_cancelled right after enqueue -> cursor MUST NOT advance
            with bot_bus.bind_bus_dir(self.bus_dir):
                bot_bus.record_group_message(
                    GROUP_ALLOWED,
                    msg_id=505,
                    sender_handle="peer_bot",
                    sender_role="coordinator",
                    is_bot=True,
                    text="must_survive_early_cancel",
                )
            orig_enqueue = bridge.queue.enqueue

            def _enqueue_then_cancel(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                rec = orig_enqueue(*args, **kwargs)
                with bridge._jobs_lock:
                    act = bridge._active_jobs.get(GROUP_ALLOWED)
                    if act is not None:
                        act.cancel_requested = True
                return rec

            with mock.patch.object(bridge.queue, "enqueue", side_effect=_enqueue_then_cancel):
                bridge.handle_update(
                    _make_update(
                        3,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        message_id=506,
                        text=f"@{BOT_USERNAME} trigger cancelled mid enqueue",
                    )
                )
            self.assertEqual(_read_cursor(), 0)
            edits_cancel = client.get_calls("editMessageText")
            self.assertTrue(any("已取消" in c["text"] for c in edits_cancel))

            # (d) Subsequent retry succeeds -> reads ALL preserved unseen context and commits cursor
            bridge.handle_update(
                _make_update(
                    4,
                    chat_id=GROUP_ALLOWED,
                    chat_type="supergroup",
                    message_id=507,
                    text=f"@{BOT_USERNAME} retry after enqueue failures",
                )
            )
            claimed = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(claimed)
            self.assertIn("must_survive_permission_error", claimed["prompt"])
            self.assertIn("must_survive_runtime_error", claimed["prompt"])
            self.assertIn("must_survive_early_cancel", claimed["prompt"])
            self.assertIn("retry after enqueue failures", claimed["prompt"])
            self.assertGreater(_read_cursor(), 0)
            with bot_bus.bind_bus_dir(self.bus_dir):
                unseen_after_retry = bot_bus.format_unseen_group_history(
                    GROUP_ALLOWED, bot_handle, advance_cursor=False
                )
            self.assertEqual(unseen_after_retry, "")

            bridge.queue.complete(
                claimed["job_id"],
                EXAMPLE_AGENT_ID,
                result_text="retry_succeeded_ok",
                auth_token=self.worker_token,
            )
            bridge.wait_for_active_jobs(timeout=3.0)
            edits_ok = client.get_calls("editMessageText")
            self.assertTrue(any("retry_succeeded_ok" in c["text"] for c in edits_ok))

            # (e) Post-enqueue cursor commit I/O error degrades gracefully without breaking job wait/delivery
            with bot_bus.bind_bus_dir(self.bus_dir):
                bot_bus.record_group_message(
                    GROUP_ALLOWED,
                    msg_id=508,
                    sender_handle="peer_bot",
                    sender_role="coordinator",
                    is_bot=True,
                    text="post_enqueue_commit_err_context",
                )
            real_fmt = bot_bus.format_unseen_group_history

            def _fail_only_on_commit(*args: Any, **kwargs: Any) -> str:
                if kwargs.get("advance_cursor", True):
                    raise OSError(f"commit disk err {self.token}")
                return real_fmt(*args, **kwargs)

            with mock.patch.object(bot_bus, "format_unseen_group_history", side_effect=_fail_only_on_commit):
                bridge.handle_update(
                    _make_update(
                        5,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        message_id=509,
                        text=f"@{BOT_USERNAME} commit io error should not break delivery",
                    )
                )
            claimed2 = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(claimed2)
            self.assertIn("post_enqueue_commit_err_context", claimed2["prompt"])
            bridge.queue.complete(
                claimed2["job_id"],
                EXAMPLE_AGENT_ID,
                result_text="delivered_despite_cursor_commit_err",
                auth_token=self.worker_token,
            )
            bridge.wait_for_active_jobs(timeout=3.0)
            edits_final = client.get_calls("editMessageText")
            self.assertTrue(any("delivered_despite_cursor_commit_err" in c["text"] for c in edits_final))
        finally:
            bridge.shutdown()


# ===========================================================================
# G4: Forum Topic Normalization & Concurrent Multi-Topic Isolation
# ===========================================================================
class TestG4ForumTopicNormalizationAndIsolation(_BridgeTestBase):
    def test_g4_invalid_and_non_forum_thread_ids_normalized_and_http_payload_exact(self) -> None:
        # 1) Direct TelegramClient HTTP payload verification
        captured: List[Tuple[str, Dict[str, Any]]] = []

        class _FakeResp:
            def __init__(self, body: Dict[str, Any]):
                self._raw = json.dumps(body).encode("utf-8")

            def read(self) -> bytes:
                return self._raw

            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

        def _fake_urlopen(req, timeout=30.0):
            method = req.full_url.rsplit("/", 1)[-1]
            payload = json.loads(req.data.decode("utf-8"))
            captured.append((method, payload))
            if method == "sendChatAction":
                return _FakeResp({"ok": True, "result": True})
            return _FakeResp({"ok": True, "result": {"message_id": 777}})

        tg = ftb.TelegramClient(self.token, urlopen_fn=_fake_urlopen)
        for bad_tid in (None, 1, 0, -5, True, "42"):
            tg.send_chat_action(GROUP_ALLOWED, "typing", message_thread_id=bad_tid)  # type: ignore[arg-type]
            tg.send_message(GROUP_ALLOWED, "hi", message_thread_id=bad_tid)  # type: ignore[arg-type]
        for _method, payload in captured:
            self.assertNotIn("message_thread_id", payload)

        captured.clear()
        tg.send_chat_action(GROUP_ALLOWED, "typing", message_thread_id=101)
        tg.send_message(GROUP_ALLOWED, "in topic", reply_to_message_id=55, message_thread_id=101)
        tg.edit_message_text(GROUP_ALLOWED, 777, "edited")
        self.assertEqual(captured[0][0], "sendChatAction")
        self.assertEqual(captured[0][1].get("message_thread_id"), 101)
        self.assertEqual(captured[1][0], "sendMessage")
        self.assertEqual(captured[1][1].get("message_thread_id"), 101)
        self.assertEqual(captured[1][1].get("reply_to_message_id"), 55)
        self.assertEqual(captured[2][0], "editMessageText")
        self.assertNotIn("message_thread_id", captured[2][1])

        # 2) Bridge end-to-end normalization for all invalid Forum / non-Forum thread_id inputs
        bridge, client = self._build_bridge(allowed_chats=(GROUP_ALLOWED,))
        bridge.startup()
        try:
            cases = [
                (True, True, 1),
                (True, True, 0),
                (True, True, -5),
                (True, True, True),
                (True, True, "42"),
                (False, False, 77),
            ]
            for idx, (is_forum, is_topic, raw_tid) in enumerate(cases, start=1):
                before_actions = len(client.get_calls("sendChatAction"))
                before_sends = len(client.get_calls("sendMessage"))
                self.assertTrue(
                    bridge.handle_update(
                        _make_update(
                            idx,
                            chat_id=GROUP_ALLOWED,
                            chat_type="supergroup",
                            is_forum=is_forum,
                            is_topic_message=is_topic,
                            message_thread_id=raw_tid,
                            message_id=500 + idx,
                            text=f"@{BOT_USERNAME} check case {idx}",
                        )
                    )
                )
                job = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
                self.assertIsNotNone(job)
                self.assertIsNone(job["metadata"]["thread_id"])
                new_actions = client.get_calls("sendChatAction")[before_actions:]
                new_sends = client.get_calls("sendMessage")[before_sends:]
                for call in new_actions + new_sends:
                    self.assertNotIn("message_thread_id", call)
                bridge.queue.complete(
                    job["job_id"], EXAMPLE_AGENT_ID, result_text=f"ok {idx}", auth_token=self.worker_token
                )
                bridge.wait_for_active_jobs(timeout=3.0)
        finally:
            bridge.shutdown()

    def test_g4_concurrent_topics_101_and_202_isolated_jobs_status_clear_cancel(self) -> None:
        bridge, client = self._build_bridge(allowed_chats=(GROUP_ALLOWED,))
        bridge.startup()
        try:
            # Start Topic 101 and Topic 202 jobs concurrently -> neither reports busy!
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        1,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        is_forum=True,
                        is_topic_message=True,
                        message_thread_id=101,
                        message_id=601,
                        text=f"@{BOT_USERNAME} work in topic 101",
                    )
                )
            )
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        2,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        is_forum=True,
                        is_topic_message=True,
                        message_thread_id=202,
                        message_id=602,
                        text=f"@{BOT_USERNAME} work in topic 202",
                    )
                )
            )
            with bridge._jobs_lock:
                self.assertIn((GROUP_ALLOWED, 101), bridge._active_jobs)
                self.assertIn((GROUP_ALLOWED, 202), bridge._active_jobs)
                jid_101 = bridge._active_jobs[(GROUP_ALLOWED, 101)].job_id
                jid_202 = bridge._active_jobs[(GROUP_ALLOWED, 202)].job_id
            self.assertNotEqual(jid_101, jid_202)
            self.assertEqual(bridge.queue.get(jid_101)["metadata"]["thread_id"], 101)
            self.assertEqual(bridge.queue.get(jid_202)["metadata"]["thread_id"], 202)

            actions = client.get_calls("sendChatAction")
            self.assertEqual([a.get("message_thread_id") for a in actions[:2]], [101, 202])
            sends = client.get_calls("sendMessage")
            self.assertEqual([s.get("message_thread_id") for s in sends[:2]], [101, 202])

            # /status in Topic 101 reports Topic 101 job & replies inside Topic 101
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        3,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        is_forum=True,
                        is_topic_message=True,
                        message_thread_id=101,
                        message_id=603,
                        text="/status",
                    )
                )
            )
            status_call = client.get_calls("sendMessage")[-1]
            self.assertEqual(status_call.get("message_thread_id"), 101)
            self.assertEqual(status_call.get("reply_to_message_id"), 603)
            self.assertIn(jid_101, status_call["text"])

            # /clear in Topic 101 clears only Topic 101 context; Topic 202 intact
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        4,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        is_forum=True,
                        is_topic_message=True,
                        message_thread_id=101,
                        message_id=604,
                        text="/clear",
                    )
                )
            )
            with bridge._ctx_lock:
                self.assertNotIn((GROUP_ALLOWED, 101), bridge._chat_context)
                self.assertIn((GROUP_ALLOWED, 202), bridge._chat_context)

            # /cancel in Topic 101 cancels ONLY jid_101; jid_202 remains active and completes!
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        5,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        is_forum=True,
                        is_topic_message=True,
                        message_thread_id=101,
                        message_id=605,
                        text="/cancel",
                    )
                )
            )
            self.assertEqual(bridge.queue.get(jid_101)["status"], "cancelled")
            self.assertEqual(bridge.queue.get(jid_202)["status"], "queued")

            claimed_202 = bridge.queue.claim(EXAMPLE_AGENT_ID, job_id=jid_202, auth_token=self.worker_token)
            self.assertIsNotNone(claimed_202)
            bridge.queue.complete(
                jid_202, EXAMPLE_AGENT_ID, result_text="topic 202 completed", auth_token=self.worker_token
            )
            bridge.wait_for_active_jobs(timeout=3.0)
            edits = client.get_calls("editMessageText")
            self.assertTrue(any("topic 202 completed" in e["text"] for e in edits))
            for e in edits:
                self.assertNotIn("message_thread_id", e)
        finally:
            bridge.shutdown()


# ===========================================================================
# G5: Group reply_to_message_id & 400 Deleted-Message Fallback Resilience
# ===========================================================================
class TestG5GroupReplyToAnd400FallbackResilience(_BridgeTestBase):
    def test_g5_reply_to_400_and_html_400_orthogonal_fallback_preserves_thread_id(self) -> None:
        bridge, client = self._build_bridge(allowed_chats=(GROUP_ALLOWED,))
        bridge.startup()
        try:
            # 1) Combined 400: reply-not-found -> HTML parse entities -> plain succeeds, thread_id=101 preserved
            client.fail_reply_not_found_once_send = "Bad Request: message to be replied not found"
            client.fail_html_once_send = True
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        1,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        is_forum=True,
                        is_topic_message=True,
                        message_thread_id=101,
                        message_id=701,
                        text="/status",
                    )
                )
            )
            sends = client.get_calls("sendMessage")
            self.assertEqual(len(sends), 3)
            self.assertEqual(sends[0]["reply_to_message_id"], 701)
            self.assertEqual(sends[0]["parse_mode"], "HTML")
            self.assertEqual(sends[0].get("message_thread_id"), 101)
            self.assertIsNone(sends[1]["reply_to_message_id"])
            self.assertEqual(sends[1]["parse_mode"], "HTML")
            self.assertEqual(sends[1].get("message_thread_id"), 101)
            self.assertIsNone(sends[2]["reply_to_message_id"])
            self.assertIsNone(sends[2]["parse_mode"])
            self.assertEqual(sends[2].get("message_thread_id"), 101)

            # 2) Alternate phrasing ("replied message not found") + reverse order (HTML 400 first, then reply 400)
            base_n = len(client.get_calls("sendMessage"))
            client.send_error_queue.extend(
                [
                    ftb.TelegramAPIError(
                        "HTTP 400: Bad Request: can't parse entities",
                        status_code=400,
                        description="Bad Request: can't parse entities",
                        method="sendMessage",
                    ),
                    ftb.TelegramAPIError(
                        "HTTP 400: Bad Request: replied message not found",
                        status_code=400,
                        description="Bad Request: replied message not found",
                        method="sendMessage",
                    ),
                ]
            )
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        2,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        is_forum=True,
                        is_topic_message=True,
                        message_thread_id=101,
                        message_id=702,
                        text="/help",
                    )
                )
            )
            sends2 = client.get_calls("sendMessage")[base_n:]
            self.assertEqual(len(sends2), 3)
            self.assertEqual(sends2[0]["reply_to_message_id"], 702)
            self.assertEqual(sends2[0]["parse_mode"], "HTML")
            self.assertEqual(sends2[1]["reply_to_message_id"], 702)
            self.assertIsNone(sends2[1]["parse_mode"])
            self.assertIsNone(sends2[2]["reply_to_message_id"])
            self.assertIsNone(sends2[2]["parse_mode"])
            self.assertEqual(sends2[2].get("message_thread_id"), 101)

            # 3) Bounded retry: persistent 400 errors never infinite-loop
            client.send_error_queue.extend(
                [
                    ftb.TelegramAPIError("400", status_code=400, description="Bad Request: message to be replied not found"),
                    ftb.TelegramAPIError("400", status_code=400, description="Bad Request: message to be replied not found"),
                ]
            )
            with self.assertRaises(ftb.TelegramAPIError):
                bridge._send_resilient(
                    GROUP_ALLOWED,
                    html_text="x",
                    plain_text="x",
                    reply_to_message_id=703,
                    message_thread_id=101,
                )
        finally:
            bridge.shutdown()

    def test_g5_placeholder_deleted_fallback_records_real_msg_id_and_total_failure_skips_bus(self) -> None:
        bridge, client = self._build_bridge(allowed_chats=(GROUP_ALLOWED,))
        bridge.startup()
        try:
            # Case A: "message to edit not found" -> fallback _send_resilient in Topic 101 & bus records NEW msg_id
            for idx, err_desc in enumerate(
                ("Bad Request: message to edit not found", "Bad Request: MESSAGE_ID_INVALID"), start=1
            ):
                base_sends = len(client.get_calls("sendMessage"))
                self.assertTrue(
                    bridge.handle_update(
                        _make_update(
                            idx,
                            chat_id=GROUP_ALLOWED,
                            chat_type="supergroup",
                            is_forum=True,
                            is_topic_message=True,
                            message_thread_id=101,
                            message_id=800 + idx,
                            text=f"@{BOT_USERNAME} placeholder deleted test {idx}",
                        )
                    )
                )
                ph_call = client.get_calls("sendMessage")[base_sends]
                self.assertEqual(ph_call["reply_to_message_id"], 800 + idx)
                self.assertEqual(ph_call.get("message_thread_id"), 101)

                claimed = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
                self.assertIsNotNone(claimed)
                client.fail_edit_missing_once = err_desc
                bridge.queue.complete(
                    claimed["job_id"],
                    EXAMPLE_AGENT_ID,
                    result_text=f"fallback_delivered_{idx}",
                    auth_token=self.worker_token,
                )
                bridge.wait_for_active_jobs(timeout=3.0)

                sends_after = client.get_calls("sendMessage")[base_sends:]
                # Placeholder send + fallback final send
                self.assertEqual(len(sends_after), 2)
                fallback_send = sends_after[1]
                self.assertEqual(fallback_send.get("message_thread_id"), 101)
                self.assertEqual(fallback_send.get("reply_to_message_id"), 800 + idx)
                self.assertIn(f"fallback_delivered_{idx}", fallback_send["text"])

                # Verify bot_bus recorded the fallback message's real message_id (NOT the deleted placeholder id)
                gh_file = Path(self.bus_dir) / "group_history" / f"{GROUP_ALLOWED}.json"
                data = json.loads(gh_file.read_text(encoding="utf-8"))
                matched = [
                    e
                    for e in data["entries"]
                    if e.get("is_bot") and f"fallback_delivered_{idx}" in e.get("text_excerpt", "")
                ]
                self.assertEqual(len(matched), 1)
                self.assertEqual(matched[0]["thread_id"], 101)
                self.assertEqual(matched[0]["sender_role"], "worker")
                # Placeholder was msg_seq-1, fallback send was msg_seq
                self.assertEqual(matched[0]["msg_id"], client._msg_seq)

            # Case B: Total Telegram delivery failure -> MUST NOT record bot reply in bot_bus
            self.assertTrue(
                bridge.handle_update(
                    _make_update(
                        10,
                        chat_id=GROUP_ALLOWED,
                        chat_type="supergroup",
                        is_forum=True,
                        is_topic_message=True,
                        message_thread_id=101,
                        message_id=810,
                        text=f"@{BOT_USERNAME} total delivery failure test",
                    )
                )
            )
            claimed_fail = bridge.queue.claim(EXAMPLE_AGENT_ID, auth_token=self.worker_token)
            self.assertIsNotNone(claimed_fail)
            # Fail initial edit + fallback send + error notice edit/send
            client.edit_error_queue.extend(
                [
                    ftb.TelegramAPIError("HTTP 500", status_code=500, description="Internal error", method="editMessageText"),
                    ftb.TelegramAPIError("HTTP 500", status_code=500, description="Internal error", method="editMessageText"),
                ]
            )
            bridge.queue.complete(
                claimed_fail["job_id"],
                EXAMPLE_AGENT_ID,
                result_text="never_delivered_to_tg_secret_marker",
                auth_token=self.worker_token,
            )
            bridge.wait_for_active_jobs(timeout=3.0)

            gh_file = Path(self.bus_dir) / "group_history" / f"{GROUP_ALLOWED}.json"
            data = json.loads(gh_file.read_text(encoding="utf-8"))
            self.assertFalse(
                any("never_delivered_to_tg_secret_marker" in e.get("text_excerpt", "") for e in data["entries"])
            )
        finally:
            bridge.shutdown()


if __name__ == "__main__":
    unittest.main()
