#!/usr/bin/env python3
"""Offline unit & integration tests for model failover (`bridge/model_failover.py` + `bridge/bridge.py`)."""

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
        "AGY_TG_ALLOWED_CHATS": "-1001234567890",
        "AGY_TG_ALLOWED_USERS": "",
        "AGY_TG_ADMIN_USERS": "",
        "AGY_TG_READONLY_USERS": "",
        "AGY_TG_ALLOW_GROUP_READONLY": "0",
        "AGY_TG_FALLBACK_MODELS": "",
        "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_FAILOVER_TEST_TOKEN_01",
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
        import model_failover  # noqa: E402

        importlib.reload(model_failover)
        importlib.reload(bot_bus)
        importlib.reload(bridge)
        os.makedirs(bridge.WORKDIR, exist_ok=True)
        os.makedirs(bridge.UPLOADDIR, exist_ok=True)
        return bridge, model_failover


class _FakeSession:
    """Minimal AgySession double emitting predetermined stream-json event sequences."""

    def __init__(self, events, *, returncode=0, stderr_text="", model=None, cid=None):
        self._events = list(events)
        self.cid = cid
        self.model = model
        self.last_used = 0.0
        self._stderr_text = stderr_text
        self.proc = mock.MagicMock()
        self.proc.returncode = returncode
        self.sent_prompts = []

    def send_user_prompt(self, prompt, raw_slash=False):
        self.sent_prompts.append(prompt)

    def next_event(self, timeout=0.25):
        if self._events:
            return self._events.pop(0)
        return {"event": "__eof__"}

    def peek_immediate_result(self, timeout=0.065):
        if self._events and self._events[0].get("event") == "result":
            ev = self._events.pop(0)
            return (ev.get("result") or ev), None
        return None, "more_steps"

    def get_stderr_text(self):
        return self._stderr_text

    def is_alive(self):
        return True

    def close(self, force=False):
        pass


class TestModelFailoverHelpers(unittest.TestCase):
    """Pure unit tests for `bridge/model_failover.py`."""

    def test_chain_resolution_and_deduplication(self):
        import model_failover  # noqa: E402

        chain = model_failover.resolve_model_chain(
            "gemini-4-hydrogen",
            scope_fallback=None,
            env_fallback="gemini-4-hydrogen, gemini-3.8-flash-high, claude-sonnet-5-5, gemini-3.8-flash-high",
        )
        self.assertEqual(["gemini-4-hydrogen", "gemini-3.8-flash-high", "claude-sonnet-5-5"], chain)

        # Explicit scope off overrides env fallback
        chain_off = model_failover.resolve_model_chain(
            "gemini-4-hydrogen",
            scope_fallback=[],
            env_fallback="gemini-3.8-flash-high",
        )
        self.assertEqual(["gemini-4-hydrogen"], chain_off)

        # Scope override replaces env fallback
        chain_override = model_failover.resolve_model_chain(
            None,
            scope_fallback=["claude-sonnet-5-5", "gpt-oss-120b"],
            env_fallback="gemini-3.8-flash-high",
        )
        self.assertEqual([None, "claude-sonnet-5-5", "gpt-oss-120b"], chain_override)

    def test_error_classification_and_safety_guard(self):
        import model_failover  # noqa: E402

        for err in (
            "HTTP 429: RESOURCE_EXHAUSTED",
            "Quota exceeded for model",
            "Rate limit reached, please retry",
            "Insufficient quota remaining",
            "Model overloaded right now",
            "503 Service Unavailable",
            "code = UNAVAILABLE",
            "model_not_found: bad slug",
            "oauth2: token refresh failed",
        ):
            self.assertTrue(model_failover.is_failover_eligible_error(err), f"Expected eligible: {err}")

        self.assertFalse(model_failover.is_failover_eligible_error("SyntaxError in user prompt"))
        self.assertFalse(model_failover.is_failover_eligible_error(""))

        self.assertTrue(model_failover.can_switch_model_safely(delivered_steps=0, attempt_tools=0))
        self.assertFalse(model_failover.can_switch_model_safely(delivered_steps=1, attempt_tools=0))
        self.assertFalse(model_failover.can_switch_model_safely(delivered_steps=0, attempt_tools=1))


class TestModelFailoverIntegration(unittest.TestCase):
    """Integration tests for `bridge.run_agy()` failover and `/model fallback` config."""

    def test_failover_before_output_switches_model_and_annotates_footer(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _mf = _load_isolated_bridge(
                tmp,
                extra_env={"AGY_TG_FALLBACK_MODELS": "gemini-3.8-flash-high,claude-sonnet-5-5"},
            )
            skey = "-1001234567890"
            bridge.update_scope_state(skey, model="gemini-4-hydrogen")

            acquired_models = []
            status_overrides = []
            sent_rich_calls = []

            sess_fail_1 = _FakeSession(
                [
                    {"event": "init", "conversation_id": "conv-failed-1"},
                    {"event": "result", "result": {"status": "ERROR", "error": "429 RESOURCE_EXHAUSTED: quota exceeded"}},
                ],
                model="gemini-4-hydrogen",
                cid="conv-failed-1",
            )
            sess_ok_2 = _FakeSession(
                [
                    {"event": "init", "conversation_id": "conv-ok-2"},
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "agent_response",
                            "state": "DONE",
                            "step_index": 0,
                            "text_delta": "备用模型已接管并完成回答。",
                        },
                    },
                    {"event": "result", "result": {"status": "SUCCESS", "conversation_id": "conv-ok-2", "usage": {"total_tokens": 2500}}},
                ],
                model="gemini-3.8-flash-high",
                cid="conv-ok-2",
            )

            def fake_acquire(scope_key, conv, mode, model, effort, project, workdir, force_new=False, readonly=False):
                acquired_models.append(model)
                if model == "gemini-4-hydrogen":
                    return sess_fail_1, False
                return sess_ok_2, False

            orig_set_override = bridge.LiveDraftStreamer.set_status_override

            def spy_set_override(self_st, tpl):
                if tpl:
                    status_overrides.append(tpl)
                return orig_set_override(self_st, tpl)

            def fake_send_rich(chat_id, text, header_html=None, footer_str=None, reply_markup=None, thread_id=None, reply_to_message_id=None):
                sent_rich_calls.append({"text": text, "footer": footer_str})
                return 901, text

            with (
                mock.patch.object(bridge, "_acquire_session", side_effect=fake_acquire),
                mock.patch.object(bridge.LiveDraftStreamer, "set_status_override", spy_set_override),
                mock.patch.object(bridge, "send_rich", side_effect=fake_send_rich),
                mock.patch.object(bridge, "send", return_value=1),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "_record_and_relay_bot_group_msg"),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact"),
            ):
                bridge.run_agy(-1001234567890, "hello world", scope_key=skey)

            self.assertEqual(["gemini-4-hydrogen", "gemini-3.8-flash-high"], acquired_models)
            self.assertTrue(
                any("主模型受限，自动切换备用模型 (gemini-3.8-flash-high)" in s for s in status_overrides),
                f"Missing failover DraftStreamer notice in {status_overrides}",
            )
            self.assertEqual(1, len(sent_rich_calls))
            self.assertIn("备用模型已接管并完成回答。", sent_rich_calls[0]["text"])
            self.assertIn("gemini-3.8-flash-high", sent_rich_calls[0]["footer"])
            self.assertIn("备用切换←gemini-4-hydrogen", sent_rich_calls[0]["footer"])
            # Scope's configured primary model must NOT be permanently overwritten
            self.assertEqual("gemini-4-hydrogen", bridge.get_scope_value(skey, "model"))
            self.assertEqual("conv-ok-2", bridge.get_scope_value(skey, "conversation_id"))

    def test_strictly_forbids_failover_after_tool_or_delivered_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _mf = _load_isolated_bridge(
                tmp,
                extra_env={"AGY_TG_FALLBACK_MODELS": "gemini-3.8-flash-high"},
            )
            skey = "-1001234567890"
            bridge.update_scope_state(skey, model="gemini-4-hydrogen")

            # Case 1: tool executed before 429 error -> MUST NOT failover
            acquired_1 = []
            sent_errors_1 = []
            sess_after_tool = _FakeSession(
                [
                    {"event": "init", "conversation_id": "conv-tool"},
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "tool",
                            "state": "ACTIVE",
                            "step_index": 0,
                            "tool_name": "run_command",
                            "tool_info": {"parameters": {"CommandLine": "echo hi"}},
                        },
                    },
                    {"event": "result", "result": {"status": "ERROR", "error": "429 RESOURCE_EXHAUSTED"}},
                ],
                cid="conv-tool",
            )

            with (
                mock.patch.object(
                    bridge,
                    "_acquire_session",
                    side_effect=lambda *a, **kw: (acquired_1.append(a[3]) or sess_after_tool, False),
                ),
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent_errors_1.append(txt) or 1),
                mock.patch.object(bridge, "send_rich", return_value=(1, "ok")),
                mock.patch.object(bridge, "tg", return_value=None),
            ):
                bridge.run_agy(-1001234567890, "run tool", scope_key=skey)

            self.assertEqual(["gemini-4-hydrogen"], acquired_1)
            self.assertTrue(any("429 RESOURCE_EXHAUSTED" in e for e in sent_errors_1))

            # Case 2: intermediate step delivered before 429 error -> MUST NOT failover
            acquired_2 = []
            sent_errors_2 = []
            sess_after_output = _FakeSession(
                [
                    {"event": "init", "conversation_id": "conv-out"},
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "agent_response",
                            "state": "DONE",
                            "step_index": 0,
                            "text_delta": "Partial intermediate step",
                        },
                    },
                    {"event": "result", "result": {"status": "ERROR", "error": "429 quota exhausted"}},
                ],
                cid="conv-out",
            )

            with (
                mock.patch.object(
                    bridge,
                    "_acquire_session",
                    side_effect=lambda *a, **kw: (acquired_2.append(a[3]) or sess_after_output, False),
                ),
                mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent_errors_2.append(txt) or 1),
                mock.patch.object(bridge, "send_rich", return_value=(55, "html")),
                mock.patch.object(bridge, "tg", return_value=None),
                mock.patch.object(bridge, "_record_and_relay_bot_group_msg"),
            ):
                bridge.run_agy(-1001234567890, "stream first", scope_key=skey)

            self.assertEqual(["gemini-4-hydrogen"], acquired_2)
            self.assertTrue(any("429 quota exhausted" in e for e in sent_errors_2))

    def test_all_candidates_exhausted_reports_chain_and_cmd_model_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge, _mf = _load_isolated_bridge(tmp)
            skey = "-1001234567890"
            sent_msgs = []

            with mock.patch.object(bridge, "send", side_effect=lambda cid, txt, **kw: sent_msgs.append(txt) or 1):
                bridge.cmd_model(-1001234567890, "fallback gemini-3.8-flash-high, claude-sonnet-5-5", scope_key=skey)
                self.assertEqual(
                    ["gemini-3.8-flash-high", "claude-sonnet-5-5"],
                    bridge.get_scope_value(skey, "fallback_models"),
                )

                bridge.update_scope_state(skey, model="gemini-4-hydrogen")
                acquired = []

                def always_fail(*a, **kw):
                    m = a[3]
                    acquired.append(m)
                    return _FakeSession(
                        [{"event": "result", "result": {"status": "ERROR", "error": f"503 unavailable on {m}"}}],
                        model=m,
                    ), False

                with (
                    mock.patch.object(bridge, "_acquire_session", side_effect=always_fail),
                    mock.patch.object(bridge, "tg", return_value=None),
                ):
                    bridge.run_agy(-1001234567890, "fail all", scope_key=skey)

                self.assertEqual(["gemini-4-hydrogen", "gemini-3.8-flash-high", "claude-sonnet-5-5"], acquired)
                self.assertTrue(any("主模型与全部备用模型均调用失败" in msg for msg in sent_msgs))

                # Disable fallback via /model fallback off
                bridge.cmd_model(-1001234567890, "fallback off", scope_key=skey)
                self.assertEqual([], bridge.get_scope_value(skey, "fallback_models"))

                # Reset to env default via /model fallback default
                bridge.cmd_model(-1001234567890, "fallback default", scope_key=skey)
                self.assertIsNone(bridge.get_scope_value(skey, "fallback_models"))


if __name__ == "__main__":
    unittest.main()
