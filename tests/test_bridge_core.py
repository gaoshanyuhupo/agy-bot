#!/usr/bin/env python3
"""Offline unit tests for core `bridge/bridge.py` subsystems:
- Markdown-to-Telegram-HTML conversion & chunk splitting (`md_to_html`, `split_markdown`)
- Telegram HTTP 429 backoff/retry & timeout handling (`_tg_retry_after`, `tg`)
- Media album debounce batching & flush (`_note_poll_album_batch`, `_handle_album_item`, `_flush_album`)
- Content-addressed `/undo` & `/redo` workspace snapshots, conflict guards, and replay
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import threading
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
        "AGY_TG_BOT_TOKEN": "123456789:EXAMPLE_CORE_TEST_TOKEN_ONLY_01",
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
        bridge.ACB_UNDO_DIR = os.path.join(tmp, "acb_undo")
        bridge.ACB_UNDO_BLOBS_DIR = os.path.join(bridge.ACB_UNDO_DIR, "blobs")
        os.makedirs(bridge.ACB_UNDO_BLOBS_DIR, exist_ok=True)
        bridge._UNDO_STAT_CACHE.clear()
        return bridge


class TestMarkdownAndChunking(unittest.TestCase):
    """Verify Telegram HTML formatting, escaping, unclosed fences, and chunk splitting."""

    def test_md_to_html_code_inline_links_escaping_and_unclosed_fence(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)

            self.assertEqual("", bridge.md_to_html(""))

            sample = (
                "# Title with **bold**\n"
                "Inline `a < b & **raw**` and **bold** _italic_ ~~old~~\n"
                "Link [Docs](https://example.com/docs?x=1) and [Local](file:///tmp/a.txt)\n"
                "![diagram](https://example.com/arch.png)\n"
                "> quoted line\n"
                "```python\n"
                "if x < 10 and y > 0:\n"
                "    print('hi')\n"
                "```"
            )
            html = bridge.md_to_html(sample)
            self.assertIn("<b>Title with bold</b>", html)
            self.assertIn("<code>a &lt; b &amp; **raw**</code>", html)
            self.assertIn("<b>bold</b>", html)
            self.assertIn("<i>italic</i>", html)
            self.assertIn("<s>old</s>", html)
            self.assertIn('<a href="https://example.com/docs?x=1">Docs</a>', html)
            self.assertIn("<code>Local</code>", html)
            self.assertIn("🖼 <code>diagram</code>", html)
            self.assertIn("<blockquote>quoted line</blockquote>", html)
            self.assertIn('<pre><code class="language-python">', html)
            self.assertIn("if x &lt; 10 and y &gt; 0:", html)

            unclosed = bridge.md_to_html("```bash\necho unclosed & raw")
            self.assertEqual('<pre><code class="language-bash">echo unclosed &amp; raw</code></pre>', unclosed)

    def test_split_markdown_reopens_fenced_code_blocks_across_chunks(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            lines = ["```python"] + [f"line_{i} = '{'x' * 30}'" for i in range(25)] + ["```"]
            text = "\n".join(lines)
            chunks = bridge.split_markdown(text, max_len=240)
            self.assertGreater(len(chunks), 2)
            for idx, chunk in enumerate(chunks[:-1]):
                self.assertTrue(chunk.endswith("```"), f"Chunk {idx} must close open fence: {chunk[-20:]!r}")
            for idx, chunk in enumerate(chunks[1:], start=1):
                self.assertTrue(chunk.startswith("```python"), f"Chunk {idx} must reopen fence: {chunk[:30]!r}")
            # Every chunk must render into balanced HTML tags
            for chunk in chunks:
                rendered = bridge.md_to_html(chunk)
                self.assertEqual(rendered.count("<pre>"), rendered.count("</pre>"))
                self.assertEqual(rendered.count("<code"), rendered.count("</code>"))


class TestTelegram429Retry(unittest.TestCase):
    """Verify `_tg_retry_after()` extraction and `tg()` retry/cap/timeout behavior."""

    def test_tg_retry_after_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)

            class _FakeResp:
                def __init__(self, status_code, data):
                    self.status_code = status_code
                    self._data = data

                def json(self):
                    if isinstance(self._data, Exception):
                        raise self._data
                    return self._data

            self.assertIsNone(bridge._tg_retry_after(None))
            self.assertIsNone(bridge._tg_retry_after(_FakeResp(200, {"ok": True})))
            self.assertEqual(7, bridge._tg_retry_after(_FakeResp(429, {"parameters": {"retry_after": 7}})))
            self.assertEqual(1, bridge._tg_retry_after(_FakeResp(429, {"parameters": {"retry_after": 0}})))
            self.assertEqual(2, bridge._tg_retry_after(_FakeResp(429, ValueError("bad json"))))

    def test_tg_retries_on_429_and_respects_max_wait_and_retry_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)

            class _FakeResp:
                def __init__(self, status_code, body):
                    self.status_code = status_code
                    self._body = body

                def json(self):
                    return self._body

            # Case 1: 429 (retry_after=3) followed by 200 OK
            r429 = _FakeResp(429, {"ok": False, "parameters": {"retry_after": 3}})
            r200 = _FakeResp(200, {"ok": True, "result": {"message_id": 42}})
            with (
                mock.patch.object(bridge.http_session, "post", side_effect=[r429, r200]) as m_post,
                mock.patch.object(bridge, "_sleep_wait_429", return_value=True) as m_sleep,
            ):
                res = bridge.tg("sendMessage", _max_429_wait=12, chat_id=-1001234567890, text="hi")
            self.assertIs(res, r200)
            self.assertEqual(2, m_post.call_count)
            m_sleep.assert_called_once_with(3.25)

            # Case 2: retry_after exceeds _max_429_wait -> gives up without sleeping
            r429_long = _FakeResp(429, {"ok": False, "parameters": {"retry_after": 30}})
            with (
                mock.patch.object(bridge.http_session, "post", return_value=r429_long) as m_post,
                mock.patch.object(bridge, "_sleep_wait_429", return_value=True) as m_sleep,
            ):
                res_cap = bridge.tg("sendMessage", _max_429_wait=10, chat_id=-1001234567890, text="hi")
            self.assertIs(res_cap, r429_long)
            self.assertEqual(1, m_post.call_count)
            m_sleep.assert_not_called()

            # Case 3: Persistent 429 caps at max 2 retries (3 total attempts)
            r429_short = _FakeResp(429, {"ok": False, "parameters": {"retry_after": 1}})
            with (
                mock.patch.object(bridge.http_session, "post", return_value=r429_short) as m_post,
                mock.patch.object(bridge, "_sleep_wait_429", return_value=True) as m_sleep,
            ):
                res_max = bridge.tg("sendMessage", _max_429_wait=12, chat_id=-1001234567890, text="hi")
            self.assertIs(res_max, r429_short)
            self.assertEqual(3, m_post.call_count)
            self.assertEqual(2, m_sleep.call_count)

            # Case 4: Network exception returns None cleanly
            with mock.patch.object(bridge.http_session, "post", side_effect=TimeoutError("read timed out")):
                self.assertIsNone(bridge.tg("getMe"))


class TestAlbumDebounceAndBatching(unittest.TestCase):
    """Verify album batch pre-registration, debounce timer merging, and enqueue submission."""

    def test_album_batch_debounces_and_flushes_single_combined_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            bridge.ALBUM_DEBOUNCE_SECONDS = 0.05

            chat_id = -1001234567890
            thread_id = 77
            skey = bridge.scope_key_for(chat_id, thread_id)
            mg_id = "album_9988"

            msg1 = {
                "message_id": 101,
                "chat": {"id": chat_id, "type": "supergroup", "is_forum": True},
                "message_thread_id": thread_id,
                "is_topic_message": True,
                "media_group_id": mg_id,
                "from": {"id": 123456, "username": "alice", "is_bot": False},
                "caption": "Please inspect both screenshots",
                "photo": [{"file_id": "f_small", "width": 90, "height": 90}, {"file_id": "f_1", "width": 800, "height": 600}],
            }
            msg2 = {
                "message_id": 102,
                "chat": {"id": chat_id, "type": "supergroup", "is_forum": True},
                "message_thread_id": thread_id,
                "is_topic_message": True,
                "media_group_id": mg_id,
                "from": {"id": 123456, "username": "alice", "is_bot": False},
                "document": {"file_id": "f_2", "file_name": "report.pdf", "mime_type": "application/pdf", "file_size": 1024},
            }

            flushed_event = threading.Event()
            enqueued: list[tuple] = []
            sent: list[tuple] = []

            def fake_tg_download(file_id, dest):
                Path(dest).write_bytes(f"data:{file_id}".encode("utf-8"))

            def fake_enqueue(*args, **kwargs):
                enqueued.append((args, kwargs))
                flushed_event.set()

            with (
                mock.patch.object(bridge, "tg_download", side_effect=fake_tg_download),
                mock.patch.object(bridge, "send", side_effect=lambda *a, **kw: sent.append((a, kw))),
                mock.patch.object(bridge, "enqueue", side_effect=fake_enqueue),
            ):
                bridge._note_poll_album_batch([{"message": msg1}, {"message": msg2}])
                akey = f"{skey}:{mg_id}"
                self.assertEqual(2, bridge._album_buffers[akey]["batch_pending"])

                bridge._handle_album_item(msg1, chat_id, thread_id, skey, mg_id)
                # While msg2 is still pending in batch_pending, timer must NOT have fired or flushed
                self.assertFalse(flushed_event.is_set())
                self.assertEqual(1, bridge._album_buffers[akey]["batch_pending"])

                bridge._handle_album_item(msg2, chat_id, thread_id, skey, mg_id)
                self.assertTrue(flushed_event.wait(timeout=3.0), "Album flush timer did not fire")

            bridge._cancel_all_album_timers()
            self.assertEqual(1, len(enqueued))
            args, kwargs = enqueued[0]
            self.assertEqual(chat_id, args[0])
            prompt = args[1]
            self.assertIn("Please inspect both screenshots", prompt)
            self.assertIn("Album with 2 files saved at:", prompt)
            self.assertIn("report.pdf", prompt)
            self.assertTrue(kwargs["has_media"])
            self.assertEqual(101, kwargs["origin_msg_id"])
            self.assertTrue(any("2 个文件" in str(a[1]) for a, _kw in sent))

    def test_album_flush_reports_error_when_all_downloads_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            chat_id = -1001234567890
            skey = bridge.scope_key_for(chat_id, None)
            akey = f"{skey}:album_fail"
            bridge._album_buffers[akey] = {
                "chat_id": chat_id,
                "thread_id": None,
                "scope_key": skey,
                "first_msg_id": 55,
                "sender_handle": "alice",
                "batch_pending": 0,
                "downloading": 0,
                "items": [],
                "captions": [],
                "reply_ctxs": [],
                "errors": ["File over 20MB"],
                "timer": None,
            }
            sent: list[str] = []
            with (
                mock.patch.object(bridge, "send", side_effect=lambda _cid, txt, **_kw: sent.append(txt)),
                mock.patch.object(bridge, "enqueue", side_effect=AssertionError("must not enqueue empty album")),
            ):
                bridge._flush_album(akey)
            self.assertEqual(1, len(sent))
            self.assertIn("下载失败", sent[0])
            self.assertIn("20MB", sent[0])


class TestUndoRedoCheckpoints(unittest.TestCase):
    """Verify content-addressed snapshot creation, rollback, conflict guard, and redo."""

    def test_snapshot_undo_conflict_force_and_redo_cycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            wdir = Path(bridge.WORKDIR)
            chat_id = -1001234567890
            skey = bridge.scope_key_for(chat_id, None)

            # Initial workspace files before turn
            keep_mod = wdir / "mod.txt"
            keep_mod.write_text("before-mod\n", encoding="utf-8")
            keep_del = wdir / "deleted.txt"
            keep_del.write_text("before-del\n", encoding="utf-8")

            pre = bridge.snapshot_undo_manifest(str(wdir))

            # Turn mutations: create, modify, delete
            created_f = wdir / "nested" / "created.txt"
            created_f.parent.mkdir(parents=True, exist_ok=True)
            created_f.write_text("new-content\n", encoding="utf-8")
            keep_mod.write_text("after-mod\n", encoding="utf-8")
            keep_del.unlink()

            changed = bridge.finalize_turn_undo(skey, str(wdir), pre, "edit 3 files", "conv-1")
            self.assertEqual(3, changed)
            self.assertEqual(1, len(bridge.get_scope_value(skey, "undo_stack")))

            sent_msgs: list[str] = []
            with mock.patch.object(bridge, "send", side_effect=lambda _cid, txt, **_kw: sent_msgs.append(txt)):
                # Preview does not mutate disk or pop stack
                bridge.cmd_undo(chat_id, "preview", scope_key=skey)
                self.assertEqual(1, len(bridge.get_scope_value(skey, "undo_stack")))
                self.assertIn("涉及文件（3 个）", sent_msgs[-1])

                # Simulate external modification conflict on mod.txt
                keep_mod.write_text("external-edit\n", encoding="utf-8")
                bridge.cmd_undo(chat_id, "", scope_key=skey)
                self.assertIn("安全拦截", sent_msgs[-1])
                self.assertEqual("external-edit\n", keep_mod.read_text(encoding="utf-8"))
                self.assertTrue(created_f.is_file())

                # Force undo rolls back all 3 files and populates redo_stack + pending_undo_notice
                bridge.cmd_undo(chat_id, "force", scope_key=skey)
                self.assertIn("已撤销工作区文件改动", sent_msgs[-1])
                self.assertFalse(created_f.exists())
                self.assertEqual("before-mod\n", keep_mod.read_text(encoding="utf-8"))
                self.assertEqual("before-del\n", keep_del.read_text(encoding="utf-8"))
                self.assertEqual(0, len(bridge.get_scope_value(skey, "undo_stack")))
                self.assertEqual(1, len(bridge.get_scope_value(skey, "redo_stack")))
                self.assertTrue(bridge.get_scope_value(skey, "pending_undo_notice"))

                # Redo replays turn mutations and restores undo_stack
                bridge.cmd_redo(chat_id, scope_key=skey)
                self.assertIn("已恢复被撤销的改动", sent_msgs[-1])
                self.assertEqual("new-content\n", created_f.read_text(encoding="utf-8"))
                self.assertEqual("after-mod\n", keep_mod.read_text(encoding="utf-8"))
                self.assertFalse(keep_del.exists())
                self.assertEqual(1, len(bridge.get_scope_value(skey, "undo_stack")))
                self.assertEqual(0, len(bridge.get_scope_value(skey, "redo_stack")))
                self.assertIsNone(bridge.get_scope_value(skey, "pending_undo_notice"))


class TestAutoCompactAndUsageQuietSelfHeal(unittest.TestCase):
    """Verify silent auto-compact streak gating and calm usage fallback footer."""

    def test_auto_compact_transient_failures_are_silent_until_streak_and_danger_zone(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            chat_id = 123456789
            conv = "conv-auto-compact-streak-001"
            skey = bridge.scope_key_for(chat_id, None)
            danger_floor = bridge.AGY_HARD_COMPACT_CEILING - bridge._AUTO_COMPACT_DANGER_BUFFER

            sent_calls: list[tuple] = []

            class _DummyStreamer:
                def __init__(self, *args, **kwargs):
                    pass

                def set_status_override(self, _text):
                    pass

                def start(self):
                    pass

                def stop(self):
                    pass

            def _fake_tg_send(*args, **kwargs):
                sent_calls.append((args, kwargs))

            stats_high = {"exists": True, "raw_ctx_tokens": danger_floor + 5000, "total_lines": 120}
            stats_safe = {"exists": True, "raw_ctx_tokens": danger_floor - 5000, "total_lines": 120}

            with (
                mock.patch.object(bridge, "LiveDraftStreamer", _DummyStreamer),
                mock.patch.object(bridge, "tg_send_in_route", side_effect=_fake_tg_send),
                mock.patch.object(bridge, "_execute_compact_on_session", return_value=(False, 1.1, "502 bad gateway")),
            ):
                # 1st & 2nd failures: completely silent even at high context
                with mock.patch.object(bridge, "should_auto_compact", return_value=(True, stats_high)):
                    bridge._maybe_post_turn_auto_compact(chat_id, conv, "auto", "m", "high", scope_key=skey)
                    bridge._maybe_post_turn_auto_compact(chat_id, conv, "auto", "m", "high", scope_key=skey)
                self.assertEqual([], sent_calls)
                self.assertEqual(2, bridge._auto_compact_fail_streak.get(conv))

                # 3rd failure below danger floor: still silent
                with mock.patch.object(bridge, "should_auto_compact", return_value=(True, stats_safe)):
                    bridge._maybe_post_turn_auto_compact(chat_id, conv, "auto", "m", "high", scope_key=skey)
                self.assertEqual([], sent_calls)
                self.assertEqual(3, bridge._auto_compact_fail_streak.get(conv))

                # Subsequent failure at/above danger floor (>= 3 streak): sends calm reminder without ⚠️
                with mock.patch.object(bridge, "should_auto_compact", return_value=(True, stats_high)):
                    bridge._maybe_post_turn_auto_compact(chat_id, conv, "auto", "m", "high", scope_key=skey)
                self.assertEqual(1, len(sent_calls))
                warn_text = sent_calls[-1][1]["text"]
                self.assertNotIn("⚠️", warn_text)
                self.assertIn("/new", warn_text)
                self.assertIn("/compact", warn_text)

            # Successful compact clears streak and posts normal completion notice
            with (
                mock.patch.object(bridge, "LiveDraftStreamer", _DummyStreamer),
                mock.patch.object(bridge, "tg_send_in_route", side_effect=_fake_tg_send),
                mock.patch.object(bridge, "should_auto_compact", return_value=(True, stats_high)),
                mock.patch.object(bridge, "_execute_compact_on_session", return_value=(True, 0.9, "")),
                mock.patch.object(
                    bridge,
                    "get_context_stats",
                    return_value={"just_compacted": True, "ctx_tokens": 14000},
                ),
            ):
                bridge._maybe_post_turn_auto_compact(chat_id, conv, "auto", "m", "high", scope_key=skey)
            self.assertNotIn(conv, bridge._auto_compact_fail_streak)
            self.assertEqual(2, len(sent_calls))
            self.assertIn("上下文已自动精简压缩", sent_calls[-1][1]["text"])

            # Next single failure after reset is silent again
            with (
                mock.patch.object(bridge, "LiveDraftStreamer", _DummyStreamer),
                mock.patch.object(bridge, "tg_send_in_route", side_effect=_fake_tg_send),
                mock.patch.object(bridge, "should_auto_compact", return_value=(True, stats_high)),
                mock.patch.object(bridge, "_execute_compact_on_session", return_value=(False, 1.0, "timeout")),
            ):
                bridge._maybe_post_turn_auto_compact(chat_id, conv, "auto", "m", "high", scope_key=skey)
            self.assertEqual(2, len(sent_calls))
            self.assertEqual(1, bridge._auto_compact_fail_streak.get(conv))

    def test_build_usage_panel_fallback_footer_is_calm_without_warning_icon(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            snap = {
                "fetched_at_epoch": 1700000000.0,
                "groups": [
                    {
                        "name": "Gemini",
                        "buckets": [
                            {
                                "name": "5h",
                                "window": "5h",
                                "remaining_fraction": 0.95,
                                "reset_time": "2026-11-18T12:00:00Z",
                            }
                        ],
                    }
                ],
            }
            with mock.patch.object(bridge, "fetch_plan_quota_data", return_value=(snap, True, "read timeout")):
                text, _kb = bridge.build_usage_panel(force_live=True)
            footer = text.splitlines()[-1]
            self.assertNotIn("⚠️", footer)
            self.assertNotIn("⚠️", text)
            self.assertIn("🕒 缓存快照于", footer)
            self.assertIn("后续自动刷新", footer)

            with mock.patch.object(bridge, "fetch_plan_quota_data", return_value=(None, False, "connect error")):
                err_text, _kb2 = bridge.build_usage_panel(force_live=True)
            self.assertIn("⚠️", err_text)
            self.assertIn("暂无法获取云端总套餐实时配额", err_text)


class TestRecoveredAttemptErrorHandling(unittest.TestCase):
    """Verify strict detection of recovered `API error (attempt N):` turns in Bus & interactive modes."""

    @staticmethod
    def _write_transcript(brain_root: Path, cid: str, entries: list[dict]) -> Path:
        tpath = brain_root / cid / ".system_generated" / "logs" / "transcript.jsonl"
        tpath.parent.mkdir(parents=True, exist_ok=True)
        tpath.write_text(
            "\n".join(json.dumps(item, ensure_ascii=False) for item in entries) + "\n",
            encoding="utf-8",
        )
        return tpath

    def test_is_recovered_attempt_error_strict_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp)
            brain_root = Path(tmp) / "brain"
            bridge.BRAIN_ROOT = str(brain_root)
            err_msg = "API error (attempt 1): request failed: net/http: timeout awaiting response headers"

            # (a) Valid recovery: ERROR_MESSAGE followed by tool cycle + terminal PLANNER_RESPONSE
            self._write_transcript(
                brain_root,
                "cid-ok",
                [
                    {"type": "USER_INPUT", "status": "DONE", "content": "check"},
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "tool_calls": [{"name": "read_file"}]},
                    {"type": "GENERIC", "status": "DONE", "content": "file body"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "All checks passed."},
                ],
            )
            self.assertTrue(bridge._is_recovered_attempt_error("cid-ok", 0, err_msg))

            # (b1) ERROR_MESSAGE is the last step -> False
            self._write_transcript(
                brain_root,
                "cid-last-err",
                [
                    {"type": "USER_INPUT", "status": "DONE", "content": "check"},
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                ],
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-last-err", 0, err_msg))

            # (b2) PLANNER_RESPONSE followed by another ERROR_MESSAGE -> False
            self._write_transcript(
                brain_root,
                "cid-trailing-err",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Partial reply"},
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                ],
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-trailing-err", 0, err_msg))

            # (b3) Terminal PLANNER_RESPONSE with empty/whitespace content -> False
            self._write_transcript(
                brain_root,
                "cid-empty-content",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "   \n"},
                ],
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-empty-content", 0, err_msg))

            # (b4) Terminal PLANNER_RESPONSE still has pending tool_calls -> False
            self._write_transcript(
                brain_root,
                "cid-has-tools",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                    {
                        "type": "PLANNER_RESPONSE",
                        "status": "DONE",
                        "content": "Calling tool...",
                        "tool_calls": [{"name": "run_command"}],
                    },
                ],
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-has-tools", 0, err_msg))

            # (b5) Non-attempt error message -> False
            self.assertFalse(bridge._is_recovered_attempt_error("cid-ok", 0, "HTTP 500 Internal Server Error"))
            self.assertFalse(bridge._is_recovered_attempt_error("cid-ok", 0, "status=ERROR"))

            # (b6) ERROR_MESSAGE only existed BEFORE start_line without matching text -> False
            self._write_transcript(
                brain_root,
                "cid-prior-err",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Previous turn done"},
                    {"type": "USER_INPUT", "status": "DONE", "content": "Next turn"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Next turn done"},
                ],
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-prior-err", 2, err_msg))

            # (d1) Historical ERROR_MESSAGE using real agy `error` field matches raw_err + clean current turn -> True
            err_503 = (
                "API error (attempt 1): UNAVAILABLE (code 503): "
                "No capacity available for model gemini-4-hydrogen-xhigh on the server"
            )
            self._write_transcript(
                brain_root,
                "cid-hist-error-field",
                [
                    {"type": "USER_INPUT", "status": "DONE", "content": "old turn"},
                    {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "old reply"},
                    {"type": "USER_INPUT", "status": "DONE", "content": "new turn"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "new reply"},
                ],
            )
            self.assertTrue(bridge._is_recovered_attempt_error("cid-hist-error-field", 3, err_503))

            # (d2) Historical ERROR_MESSAGE using `content` field matches raw_err + clean current turn -> True
            self._write_transcript(
                brain_root,
                "cid-hist-content-field",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE", "content": err_503},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "old reply"},
                    {"type": "USER_INPUT", "status": "DONE", "content": "new turn"},
                    {"type": "GENERIC", "status": "ERROR", "content": "tool exit 1"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "new reply after tool err"},
                ],
            )
            self.assertTrue(bridge._is_recovered_attempt_error("cid-hist-content-field", 2, err_503))

            # (d3) NEGATIVE: Historical error A, but current turn returns DIFFERENT error B -> False
            err_other = "API error (attempt 1): INTERNAL (code 500): different backend error"
            self.assertFalse(bridge._is_recovered_attempt_error("cid-hist-error-field", 3, err_other))

            # (d4) NEGATIVE: Historical error A matches, but current turn ends with tool-only DONE -> False
            self._write_transcript(
                brain_root,
                "cid-hist-tool-only",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "old reply"},
                    {"type": "USER_INPUT", "status": "DONE", "content": "new turn"},
                    {
                        "type": "PLANNER_RESPONSE",
                        "status": "DONE",
                        "content": "",
                        "tool_calls": [{"name": "run_command"}],
                    },
                ],
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-hist-tool-only", 2, err_503))

            # (d5) NEGATIVE: Historical error A matches, but current turn is RUNNING -> False
            self._write_transcript(
                brain_root,
                "cid-hist-running",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                    {"type": "USER_INPUT", "status": "DONE", "content": "new turn"},
                    {"type": "PLANNER_RESPONSE", "status": "RUNNING", "content": "partial"},
                ],
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-hist-running", 1, err_503))

            # (d6) NEGATIVE: Missing or corrupted transcript JSON -> fail-closed False
            self.assertFalse(bridge._is_recovered_attempt_error("cid-nonexistent", 0, err_503))
            corrupt_path = brain_root / "cid-corrupt-cur" / ".system_generated/logs/transcript.jsonl"
            corrupt_path.parent.mkdir(parents=True, exist_ok=True)
            corrupt_path.write_text(
                json.dumps({"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503})
                + "\n{broken json\n",
                encoding="utf-8",
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-corrupt-cur", 1, err_503))

            corrupt_prior = brain_root / "cid-corrupt-prior" / ".system_generated/logs/transcript.jsonl"
            corrupt_prior.parent.mkdir(parents=True, exist_ok=True)
            corrupt_prior.write_text(
                "{broken prior\n"
                + json.dumps({"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503})
                + "\n"
                + json.dumps({"type": "USER_INPUT", "status": "DONE", "content": "new"})
                + "\n"
                + json.dumps({"type": "PLANNER_RESPONSE", "status": "DONE", "content": "done"})
                + "\n",
                encoding="utf-8",
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-corrupt-prior", 2, err_503))

            # (e1) /compact (require_checkpoint=True): historical error + new CHECKPOINT DONE -> True
            self._write_transcript(
                brain_root,
                "cid-compact-hist-ok",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                    {"type": "CHECKPOINT", "status": "DONE", "content": "old ckpt"},
                    {"type": "USER_INPUT", "status": "DONE", "content": "/compact"},
                    {"type": "CHECKPOINT", "status": "DONE", "content": "new ckpt"},
                ],
            )
            self.assertTrue(
                bridge._is_recovered_attempt_error("cid-compact-hist-ok", 2, err_503, require_checkpoint=True)
            )

            # (e2) /compact: same-turn transient ERROR_MESSAGE followed by new CHECKPOINT DONE -> True
            self._write_transcript(
                brain_root,
                "cid-compact-sameturn-ok",
                [
                    {"type": "USER_INPUT", "status": "DONE", "content": "/compact"},
                    {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                    {"type": "CHECKPOINT", "status": "DONE", "content": "recovered ckpt"},
                ],
            )
            self.assertTrue(
                bridge._is_recovered_attempt_error("cid-compact-sameturn-ok", 0, err_503, require_checkpoint=True)
            )

            # (e3) NEGATIVE /compact: old CHECKPOINT before start_line, NO new CHECKPOINT in [start_line:] -> False
            self._write_transcript(
                brain_root,
                "cid-compact-old-ckpt-only",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                    {"type": "CHECKPOINT", "status": "DONE", "content": "old ckpt"},
                    {"type": "USER_INPUT", "status": "DONE", "content": "/compact"},
                ],
            )
            self.assertFalse(
                bridge._is_recovered_attempt_error("cid-compact-old-ckpt-only", 2, err_503, require_checkpoint=True)
            )

            # (e4) NEGATIVE /compact: only PLANNER_RESPONSE DONE, no CHECKPOINT DONE -> False
            self._write_transcript(
                brain_root,
                "cid-compact-chat-only",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                    {"type": "USER_INPUT", "status": "DONE", "content": "/compact"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Not a checkpoint"},
                ],
            )
            self.assertFalse(
                bridge._is_recovered_attempt_error("cid-compact-chat-only", 1, err_503, require_checkpoint=True)
            )

            # (e5) NEGATIVE /compact: CHECKPOINT not DONE or followed by ERROR_MESSAGE -> False
            self._write_transcript(
                brain_root,
                "cid-compact-running",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                    {"type": "USER_INPUT", "status": "DONE", "content": "/compact"},
                    {"type": "CHECKPOINT", "status": "RUNNING", "content": "half"},
                ],
            )
            self.assertFalse(
                bridge._is_recovered_attempt_error("cid-compact-running", 1, err_503, require_checkpoint=True)
            )
            self._write_transcript(
                brain_root,
                "cid-compact-trailing-err",
                [
                    {"type": "USER_INPUT", "status": "DONE", "content": "/compact"},
                    {"type": "CHECKPOINT", "status": "DONE", "content": "ok"},
                    {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                ],
            )
            self.assertFalse(
                bridge._is_recovered_attempt_error("cid-compact-trailing-err", 0, err_503, require_checkpoint=True)
            )

            # (b7) Non-DONE terminal PLANNER_RESPONSE -> False
            self._write_transcript(
                brain_root,
                "cid-running",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                    {"type": "PLANNER_RESPONSE", "status": "RUNNING", "content": "Still streaming"},
                ],
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-running", 0, err_msg))

            # (c1) Intermediate GENERIC(ERROR) (e.g. failed tool call) recovered by final DONE PLANNER_RESPONSE -> True
            self._write_transcript(
                brain_root,
                "cid-generic-err-recovered",
                [
                    {"type": "USER_INPUT", "status": "DONE", "content": "run check"},
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "tool_calls": [{"name": "run_command"}]},
                    {"type": "GENERIC", "status": "ERROR", "content": "command exited 1"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Handled tool failure and completed."},
                ],
            )
            self.assertTrue(bridge._is_recovered_attempt_error("cid-generic-err-recovered", 0, err_msg))

            # (c2) Trailing GENERIC(ERROR) with no closing DONE PLANNER_RESPONSE -> False
            self._write_transcript(
                brain_root,
                "cid-generic-err-trailing",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                    {"type": "GENERIC", "status": "ERROR", "content": "command exited 1"},
                ],
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-generic-err-trailing", 0, err_msg))

            # (c3) Unclosed intermediate GENERIC(RUNNING) before terminal PLANNER_RESPONSE -> False
            self._write_transcript(
                brain_root,
                "cid-generic-running",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                    {"type": "GENERIC", "status": "RUNNING", "content": "still running"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Finished"},
                ],
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-generic-running", 0, err_msg))

            # (c4) Non-GENERIC intermediate ERROR (PLANNER_RESPONSE status=ERROR) -> False
            self._write_transcript(
                brain_root,
                "cid-planner-err-mid",
                [
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                    {"type": "PLANNER_RESPONSE", "status": "ERROR", "content": "aborted"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Finished"},
                ],
            )
            self.assertFalse(bridge._is_recovered_attempt_error("cid-planner-err-mid", 0, err_msg))

    def test_execute_bus_job_recovers_false_error_and_preserves_true_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"HOME": tmp})
            brain_root = Path(tmp) / "brain"
            bridge.BRAIN_ROOT = str(brain_root)
            cid = "conv-bus-recover-001"
            # Pre-existing turn (2 lines) before agy runs
            prior_entries = [
                {"type": "USER_INPUT", "status": "DONE", "content": "old turn"},
                {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "old answer"},
            ]
            self._write_transcript(brain_root, cid, prior_entries)

            job_payload = {
                "job_id": "job-recover-1",
                "from_bot": "sgaeget_bot",
                "to_bot": "jeff_ha_bot",
                "prompt": "verify gateway",
                "label": "Recover check",
                "resume_cid": cid,
                "notify_group": False,
            }
            stream_events = [
                json.dumps({"event": "init", "conversation_id": cid}) + "\n",
                json.dumps({"event": "step_update", "step_update": {"step_type": "agent_response", "step_index": 1, "state": "DONE", "text_delta": "Final verified report."}}) + "\n",
                json.dumps({
                    "event": "result",
                    "result": {
                        "conversation_id": cid,
                        "status": "ERROR",
                        "error": "API error (attempt 1): request failed: net/http: timeout awaiting response headers",
                        "response": "Final verified report.",
                    },
                }) + "\n",
            ]

            class _FakeProc:
                def __init__(self, lines, turn_entries, rc=0):
                    self.pid = 99999
                    self.stdout = iter(lines)
                    self.stderr = iter([])
                    self.returncode = rc
                    TestRecoveredAttemptErrorHandling._write_transcript(
                        brain_root, cid, prior_entries + turn_entries
                    )

                def wait(self, timeout=None):
                    return self.returncode

            recovered_turn = [
                {"type": "USER_INPUT", "status": "DONE", "content": "new turn"},
                {"type": "ERROR_MESSAGE", "status": "DONE"},
                {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Final verified report."},
            ]
            finished: list[tuple] = []
            with (
                mock.patch.object(bridge.bot_bus, "claim_job", return_value=job_payload),
                mock.patch.object(bridge.bot_bus, "is_job_cancelled", return_value=False),
                mock.patch.object(
                    bridge.bot_bus,
                    "finish_job",
                    side_effect=lambda jid, **kw: finished.append((jid, kw)),
                ),
                mock.patch.object(bridge, "_publish_bot_heartbeat"),
                mock.patch.object(
                    bridge.subprocess,
                    "Popen",
                    side_effect=lambda *a, **kw: _FakeProc(stream_events, recovered_turn, rc=0),
                ),
            ):
                bridge._execute_bus_job("job-recover-1")

            self.assertEqual(1, len(finished))
            self.assertEqual("done", finished[0][1]["status"])
            self.assertEqual("", finished[0][1]["error"])
            self.assertEqual("Final verified report.", finished[0][1]["result_text"])

            # Negative case: transcript ends with ERROR_MESSAGE -> stays status="error"
            self._write_transcript(brain_root, cid, prior_entries)
            unrecovered_turn = [
                {"type": "USER_INPUT", "status": "DONE", "content": "new turn"},
                {"type": "ERROR_MESSAGE", "status": "DONE"},
            ]
            finished.clear()
            with (
                mock.patch.object(bridge.bot_bus, "claim_job", return_value=job_payload),
                mock.patch.object(bridge.bot_bus, "is_job_cancelled", return_value=False),
                mock.patch.object(
                    bridge.bot_bus,
                    "finish_job",
                    side_effect=lambda jid, **kw: finished.append((jid, kw)),
                ),
                mock.patch.object(bridge, "_publish_bot_heartbeat"),
                mock.patch.object(
                    bridge.subprocess,
                    "Popen",
                    side_effect=lambda *a, **kw: _FakeProc(stream_events, unrecovered_turn, rc=0),
                ),
            ):
                bridge._execute_bus_job("job-recover-1")

            self.assertEqual(1, len(finished))
            self.assertEqual("error", finished[0][1]["status"])
            self.assertIn("API error (attempt 1)", finished[0][1]["error"])

    def test_interactive_run_agy_coalesces_recovered_attempt_error_without_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"HOME": tmp})
            brain_root = Path(tmp) / "brain"
            bridge.BRAIN_ROOT = str(brain_root)
            cid = "conv-interactive-recover-001"
            self._write_transcript(
                brain_root,
                cid,
                [
                    {"type": "USER_INPUT", "status": "DONE", "content": "hello"},
                    {"type": "ERROR_MESSAGE", "status": "DONE"},
                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Recovered interactive answer."},
                ],
            )

            events = iter(
                [
                    {"event": "init", "conversation_id": cid},
                    {
                        "event": "step_update",
                        "step_update": {
                            "step_type": "agent_response",
                            "step_index": 1,
                            "state": "DONE",
                            "text_delta": "Recovered interactive answer.",
                        },
                    },
                ]
            )

            class _FakeSession:
                cid = None
                proc = type("P", (), {"returncode": 0})()

                def send_user_prompt(self, _prompt):
                    return None

                def next_event(self, timeout=0.25):
                    return next(events, {"event": "__eof__"})

                def peek_immediate_result(self, timeout=0.065):
                    return (
                        {
                            "conversation_id": cid,
                            "status": "ERROR",
                            "error": "API error (attempt 1): request failed: net/http: timeout awaiting response headers",
                            "response": "",
                        },
                        [],
                    )

                def get_stderr_text(self):
                    return ""

            finalized: list[tuple] = []
            sent_plain: list[str] = []

            class _FakeStreamer:
                status_override = None

                def __init__(self, *args, **kwargs):
                    self.start_line = 0

                def start(self):
                    pass

                def stop(self):
                    pass

                def set_cid(self, _c):
                    pass

                def set_status_override(self, _v):
                    pass

                def on_thinking(self, _t):
                    pass

                def on_text_delta(self, _t):
                    pass

                def finalize_step(self, text, **kwargs):
                    finalized.append((text, kwargs))
                    return (101, f"<p>{text}</p>")

            chat_id = -1001234567890
            with (
                mock.patch.object(bridge, "_acquire_session", return_value=(_FakeSession(), False)),
                mock.patch.object(bridge, "LiveDraftStreamer", _FakeStreamer),
                mock.patch.object(bridge, "send", side_effect=lambda _c, txt, **_kw: sent_plain.append(txt)),
                mock.patch.object(bridge, "push_step_images"),
                mock.patch.object(bridge, "_record_and_relay_bot_group_msg"),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact"),
            ):
                bridge.run_agy(chat_id, "hello", scope_key=bridge.scope_key_for(chat_id, None))

            self.assertEqual(1, len(finalized))
            self.assertEqual("Recovered interactive answer.", finalized[0][0])
            self.assertIsNotNone(finalized[0][1].get("footer_str"))
            self.assertEqual([], [m for m in sent_plain if "⚠️ agy" in m])

    def test_interactive_run_agy_stale_historical_error_coalesce_postloop_and_mismatch_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"HOME": tmp})
            brain_root = Path(tmp) / "brain"
            bridge.BRAIN_ROOT = str(brain_root)
            err_503 = (
                "API error (attempt 1): UNAVAILABLE (code 503): "
                "No capacity available for model gemini-4-hydrogen-xhigh on the server"
            )
            err_other = "API error (attempt 1): INTERNAL (code 500): brand new failure"
            chat_id = -1001234567890
            skey = bridge.scope_key_for(chat_id, None)

            prior_entries = [
                {"type": "USER_INPUT", "status": "DONE", "content": "earlier turn"},
                {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "earlier answer"},
            ]

            class _FakeStreamer:
                status_override = None

                def __init__(self, *args, **kwargs):
                    self.start_line = kwargs.get("start_line", 0)

                def start(self):
                    pass

                def stop(self):
                    pass

                def set_cid(self, _c):
                    pass

                def set_status_override(self, _v):
                    pass

                def on_thinking(self, _t):
                    pass

                def on_text_delta(self, _t):
                    pass

                def start_next_segment(self, sl):
                    self.start_line = sl

                def finalize_step(self, text, **kwargs):
                    finalized.append((text, kwargs))
                    return (202, f"<p>{text}</p>")

            # (1) imm_res coalescing with stale historical error (0 new ERROR_MESSAGE)
            cid_imm = "conv-stale-imm-001"
            self._write_transcript(brain_root, cid_imm, prior_entries)
            bridge.update_scope_state(skey, conversation_id=cid_imm)

            class _ImmStaleSession:
                cid = cid_imm
                proc = type("P", (), {"returncode": 0})()

                def __init__(self):
                    self._events = iter(
                        [
                            {"event": "init", "conversation_id": cid_imm},
                            {
                                "event": "step_update",
                                "step_update": {
                                    "step_type": "agent_response",
                                    "step_index": 2,
                                    "state": "DONE",
                                    "text_delta": "Clean resumed answer.",
                                },
                            },
                        ]
                    )

                def send_user_prompt(self, _prompt):
                    TestRecoveredAttemptErrorHandling._write_transcript(
                        brain_root,
                        cid_imm,
                        prior_entries
                        + [
                            {"type": "USER_INPUT", "status": "DONE", "content": "follow up"},
                            {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Clean resumed answer."},
                        ],
                    )

                def next_event(self, timeout=0.25):
                    return next(self._events, {"event": "__eof__"})

                def peek_immediate_result(self, timeout=0.065):
                    return (
                        {"conversation_id": cid_imm, "status": "ERROR", "error": err_503, "response": ""},
                        [],
                    )

                def get_stderr_text(self):
                    return ""

            finalized: list[tuple] = []
            sent_plain: list[tuple] = []
            with (
                mock.patch.object(bridge, "_acquire_session", return_value=(_ImmStaleSession(), True)),
                mock.patch.object(bridge, "LiveDraftStreamer", _FakeStreamer),
                mock.patch.object(bridge, "send", side_effect=lambda _c, txt, **kw: sent_plain.append((txt, kw))),
                mock.patch.object(bridge, "push_step_images"),
                mock.patch.object(bridge, "_record_and_relay_bot_group_msg"),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact"),
            ):
                bridge.run_agy(chat_id, "follow up", scope_key=skey)

            self.assertEqual(1, len(finalized))
            self.assertEqual("Clean resumed answer.", finalized[0][0])
            self.assertIsNotNone(finalized[0][1].get("footer_str"))
            self.assertEqual([], sent_plain)

            # (2) Post-loop path (imm_res misses 65ms window, result arrives as next event)
            cid_post = "conv-stale-post-002"
            self._write_transcript(brain_root, cid_post, prior_entries)
            bridge.update_scope_state(skey, conversation_id=cid_post)

            class _PostLoopStaleSession:
                cid = cid_post
                proc = type("P", (), {"returncode": 0})()

                def __init__(self):
                    self._events = iter(
                        [
                            {"event": "init", "conversation_id": cid_post},
                            {
                                "event": "step_update",
                                "step_update": {
                                    "step_type": "agent_response",
                                    "step_index": 2,
                                    "state": "DONE",
                                    "text_delta": "Delayed result answer.",
                                },
                            },
                            {
                                "event": "result",
                                "result": {
                                    "conversation_id": cid_post,
                                    "status": "ERROR",
                                    "error": err_503,
                                    "response": "",
                                },
                            },
                        ]
                    )

                def send_user_prompt(self, _prompt):
                    TestRecoveredAttemptErrorHandling._write_transcript(
                        brain_root,
                        cid_post,
                        prior_entries
                        + [
                            {"type": "USER_INPUT", "status": "DONE", "content": "follow up 2"},
                            {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Delayed result answer."},
                        ],
                    )

                def next_event(self, timeout=0.25):
                    return next(self._events, {"event": "__eof__"})

                def peek_immediate_result(self, timeout=0.065):
                    return None, "timeout"

                def get_stderr_text(self):
                    return ""

            finalized.clear()
            sent_plain.clear()
            tg_edits: list[tuple] = []

            class _OkResp:
                status_code = 200
                text = '{"ok":true}'

                @staticmethod
                def json():
                    return {"ok": True, "result": {"message_id": 202}}

            with (
                mock.patch.object(bridge, "_acquire_session", return_value=(_PostLoopStaleSession(), True)),
                mock.patch.object(bridge, "LiveDraftStreamer", _FakeStreamer),
                mock.patch.object(bridge, "send", side_effect=lambda _c, txt, **kw: sent_plain.append((txt, kw))),
                mock.patch.object(
                    bridge,
                    "tg",
                    side_effect=lambda method, **kw: (tg_edits.append((method, kw)) or _OkResp()),
                ),
                mock.patch.object(bridge, "push_step_images"),
                mock.patch.object(bridge, "_record_and_relay_bot_group_msg"),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact"),
            ):
                bridge.run_agy(chat_id, "follow up 2", scope_key=skey)

            self.assertEqual(1, len(finalized))
            self.assertEqual([], sent_plain)
            self.assertEqual(1, len([m for m, _kw in tg_edits if m == "editMessageText"]))
            self.assertEqual([], [m for m, _kw in tg_edits if m == "sendMessage"])

            # (3) NEGATIVE: mismatched new error B must NOT be swallowed
            cid_mis = "conv-stale-mismatch-003"
            self._write_transcript(brain_root, cid_mis, prior_entries)
            bridge.update_scope_state(skey, conversation_id=cid_mis)

            class _MismatchSession(_ImmStaleSession):
                cid = cid_mis

                def __init__(self):
                    self._events = iter(
                        [
                            {"event": "init", "conversation_id": cid_mis},
                            {
                                "event": "step_update",
                                "step_update": {
                                    "step_type": "agent_response",
                                    "step_index": 2,
                                    "state": "DONE",
                                    "text_delta": "Partial text",
                                },
                            },
                        ]
                    )

                def send_user_prompt(self, _prompt):
                    TestRecoveredAttemptErrorHandling._write_transcript(
                        brain_root,
                        cid_mis,
                        prior_entries
                        + [
                            {"type": "USER_INPUT", "status": "DONE", "content": "follow up 3"},
                            {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Partial text"},
                        ],
                    )

                def peek_immediate_result(self, timeout=0.065):
                    return (
                        {"conversation_id": cid_mis, "status": "ERROR", "error": err_other, "response": ""},
                        [],
                    )

            finalized.clear()
            sent_plain.clear()
            with (
                mock.patch.object(bridge, "_acquire_session", return_value=(_MismatchSession(), True)),
                mock.patch.object(bridge, "LiveDraftStreamer", _FakeStreamer),
                mock.patch.object(bridge, "send", side_effect=lambda _c, txt, **kw: sent_plain.append((txt, kw))),
                mock.patch.object(bridge, "push_step_images"),
                mock.patch.object(bridge, "_record_and_relay_bot_group_msg"),
                mock.patch.object(bridge, "_maybe_post_turn_auto_compact"),
            ):
                bridge.run_agy(chat_id, "follow up 3", scope_key=skey)

            self.assertTrue(any("⚠️ agy ERROR" in txt and err_other in txt for txt, _kw in sent_plain))

    def test_execute_bus_job_stale_historical_error_and_mismatch_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"HOME": tmp})
            brain_root = Path(tmp) / "brain"
            bridge.BRAIN_ROOT = str(brain_root)
            cid = "conv-bus-stale-001"
            err_503 = (
                "API error (attempt 1): UNAVAILABLE (code 503): "
                "No capacity available for model gemini-4-hydrogen-xhigh on the server"
            )
            err_other = "API error (attempt 1): INTERNAL (code 500): different bus error"
            prior_entries = [
                {"type": "USER_INPUT", "status": "DONE", "content": "prior task"},
                {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "prior done"},
            ]
            clean_turn = [
                {"type": "USER_INPUT", "status": "DONE", "content": "continued task"},
                {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "Bus resumed cleanly."},
            ]

            job_payload = {
                "job_id": "job-stale-1",
                "from_bot": "sgaeget_bot",
                "to_bot": "agycli_main_bot",
                "prompt": "continue",
                "label": "Stale error bus check",
                "resume_cid": cid,
                "notify_group": False,
            }

            class _FakeProc:
                def __init__(self, lines, turn_entries, rc=0):
                    self.pid = 99998
                    self.stdout = iter(lines)
                    self.stderr = iter([])
                    self.returncode = rc
                    TestRecoveredAttemptErrorHandling._write_transcript(
                        brain_root, cid, prior_entries + turn_entries
                    )

                def wait(self, timeout=None):
                    return self.returncode

            # Positive: historical err_503 matches, even when result response is empty (falls back to transcript)
            self._write_transcript(brain_root, cid, prior_entries)
            stream_events_ok = [
                json.dumps({"event": "init", "conversation_id": cid}) + "\n",
                json.dumps({
                    "event": "result",
                    "result": {"conversation_id": cid, "status": "ERROR", "error": err_503, "response": ""},
                }) + "\n",
            ]
            finished: list[tuple] = []
            with (
                mock.patch.object(bridge.bot_bus, "claim_job", return_value=job_payload),
                mock.patch.object(bridge.bot_bus, "is_job_cancelled", return_value=False),
                mock.patch.object(bridge.bot_bus, "finish_job", side_effect=lambda jid, **kw: finished.append((jid, kw))),
                mock.patch.object(bridge, "_publish_bot_heartbeat"),
                mock.patch.object(
                    bridge.subprocess,
                    "Popen",
                    side_effect=lambda *a, **kw: _FakeProc(stream_events_ok, clean_turn, rc=0),
                ),
            ):
                bridge._execute_bus_job("job-stale-1")

            self.assertEqual(1, len(finished))
            self.assertEqual("done", finished[0][1]["status"])
            self.assertEqual("", finished[0][1]["error"])
            self.assertEqual("Bus resumed cleanly.", finished[0][1]["result_text"])

            # Negative: different error B must stay status="error"
            self._write_transcript(brain_root, cid, prior_entries)
            stream_events_mismatch = [
                json.dumps({"event": "init", "conversation_id": cid}) + "\n",
                json.dumps({
                    "event": "result",
                    "result": {"conversation_id": cid, "status": "ERROR", "error": err_other, "response": "Bus resumed cleanly."},
                }) + "\n",
            ]
            finished.clear()
            with (
                mock.patch.object(bridge.bot_bus, "claim_job", return_value=job_payload),
                mock.patch.object(bridge.bot_bus, "is_job_cancelled", return_value=False),
                mock.patch.object(bridge.bot_bus, "finish_job", side_effect=lambda jid, **kw: finished.append((jid, kw))),
                mock.patch.object(bridge, "_publish_bot_heartbeat"),
                mock.patch.object(
                    bridge.subprocess,
                    "Popen",
                    side_effect=lambda *a, **kw: _FakeProc(stream_events_mismatch, clean_turn, rc=0),
                ),
            ):
                bridge._execute_bus_job("job-stale-1")

            self.assertEqual(1, len(finished))
            self.assertEqual("error", finished[0][1]["status"])
            self.assertIn("different bus error", finished[0][1]["error"])

    def test_execute_compact_on_session_recovery_retry_and_fail_closed_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            bridge = _load_isolated_bridge(tmp, extra_env={"HOME": tmp})
            brain_root = Path(tmp) / "brain"
            bridge.BRAIN_ROOT = str(brain_root)
            err_503 = (
                "API error (attempt 1): UNAVAILABLE (code 503): "
                "No capacity available for model gemini-4-hydrogen-xhigh on the server"
            )
            skey = "-1001234567890"

            class _CompactFakeSess:
                def __init__(self, events, on_send=None, stderr_text=""):
                    self._events = list(events)
                    self._on_send = on_send
                    self._stderr_text = stderr_text
                    self.last_used = 0.0

                def send_user_prompt(self, _prompt, raw_slash=False):
                    if self._on_send:
                        self._on_send()

                def next_event(self, timeout=0.25):
                    if self._events:
                        return self._events.pop(0)
                    return {"event": "__eof__"}

                def get_stderr_text(self):
                    return self._stderr_text

            # (1) Positive: stale historical 503 + newly appended CHECKPOINT DONE -> True, no compact_error invalidation
            cid_ok = "conv-compact-stale-ok"
            prior_hist = [
                {"type": "USER_INPUT", "status": "DONE", "content": "work"},
                {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                {"type": "CHECKPOINT", "status": "DONE", "content": "old ckpt"},
            ]
            self._write_transcript(brain_root, cid_ok, prior_hist)
            acq_calls: list[bool] = []
            inv_reasons: list[str] = []

            def _append_new_ckpt():
                self._write_transcript(
                    brain_root,
                    cid_ok,
                    prior_hist
                    + [
                        {"type": "USER_INPUT", "status": "DONE", "content": "/compact"},
                        {"type": "CHECKPOINT", "status": "DONE", "content": "fresh ckpt"},
                    ],
                )

            sess_ok = _CompactFakeSess(
                [{"event": "result", "result": {"conversation_id": cid_ok, "status": "ERROR", "error": err_503}}],
                on_send=_append_new_ckpt,
            )
            with (
                mock.patch.object(
                    bridge,
                    "_acquire_session",
                    side_effect=lambda *a, **kw: (acq_calls.append(kw.get("force_new", False)) or sess_ok, True),
                ),
                mock.patch.object(
                    bridge,
                    "invalidate_session",
                    side_effect=lambda reason, **kw: inv_reasons.append(reason),
                ),
                mock.patch.object(bridge, "_sleep_interruptible", return_value=True),
            ):
                ok, _dur, err = bridge._execute_compact_on_session(
                    skey, cid_ok, "auto", "m", "high", None, bridge.WORKDIR
                )
            self.assertTrue(ok)
            self.assertEqual("", err)
            self.assertEqual([False], acq_calls)
            self.assertEqual([], inv_reasons)
            self.assertEqual(5, bridge._last_compacted_line.get(cid_ok))

            # (2) Positive transient 503 retry: attempt 1 fails with NO new CHECKPOINT -> retries attempt 2,
            #     re-captures compact_start_line, writes CHECKPOINT DONE, and normalizes leaked attempt-1 error
            cid_retry = "conv-compact-retry-503"
            base_lines = [{"type": "USER_INPUT", "status": "DONE", "content": "long chat"}]
            self._write_transcript(brain_root, cid_retry, base_lines)
            attempt_n = [0]
            inv_reasons.clear()

            def _acq_retry(*a, **kw):
                attempt_n[0] += 1
                if attempt_n[0] == 1:
                    return (
                        _CompactFakeSess(
                            [{"event": "result", "result": {"conversation_id": cid_retry, "status": "ERROR", "error": err_503}}],
                            on_send=lambda: self._write_transcript(
                                brain_root,
                                cid_retry,
                                base_lines
                                + [
                                    {"type": "USER_INPUT", "status": "DONE", "content": "/compact"},
                                    {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                                ],
                            ),
                        ),
                        True,
                    )
                return (
                    _CompactFakeSess(
                        [{"event": "result", "result": {"conversation_id": cid_retry, "status": "ERROR", "error": err_503}}],
                        on_send=lambda: self._write_transcript(
                            brain_root,
                            cid_retry,
                            base_lines
                            + [
                                {"type": "USER_INPUT", "status": "DONE", "content": "/compact"},
                                {"type": "ERROR_MESSAGE", "status": "DONE", "error": err_503},
                                {"type": "USER_INPUT", "status": "DONE", "content": "/compact"},
                                {"type": "CHECKPOINT", "status": "DONE", "content": "retry ckpt"},
                            ],
                        ),
                    ),
                    False,
                )

            with (
                mock.patch.object(bridge, "_acquire_session", side_effect=_acq_retry),
                mock.patch.object(
                    bridge,
                    "invalidate_session",
                    side_effect=lambda reason, **kw: inv_reasons.append(reason),
                ),
                mock.patch.object(bridge, "_sleep_interruptible", return_value=True),
            ):
                ok2, _dur2, err2 = bridge._execute_compact_on_session(
                    skey, cid_retry, "auto", "m", "high", None, bridge.WORKDIR
                )
            self.assertTrue(ok2)
            self.assertEqual("", err2)
            self.assertEqual(2, attempt_n[0])
            self.assertEqual(["compact_error"], inv_reasons)
            self.assertEqual(5, bridge._last_compacted_line.get(cid_retry))

            # (3) Negative: old CHECKPOINT exists before start_line, NO new CHECKPOINT appended -> False
            cid_no_new = "conv-compact-old-only"
            self._write_transcript(brain_root, cid_no_new, prior_hist)
            inv_reasons.clear()
            with (
                mock.patch.object(
                    bridge,
                    "_acquire_session",
                    side_effect=lambda *a, **kw: (
                        _CompactFakeSess(
                            [{"event": "result", "result": {"conversation_id": cid_no_new, "status": "ERROR", "error": err_503}}],
                            on_send=lambda: self._write_transcript(
                                brain_root,
                                cid_no_new,
                                prior_hist + [{"type": "USER_INPUT", "status": "DONE", "content": "/compact"}],
                            ),
                        ),
                        False,
                    ),
                ),
                mock.patch.object(
                    bridge,
                    "invalidate_session",
                    side_effect=lambda reason, **kw: inv_reasons.append(reason),
                ),
                mock.patch.object(bridge, "_sleep_interruptible", return_value=True),
            ):
                ok3, _dur3, err3 = bridge._execute_compact_on_session(
                    skey, cid_no_new, "auto", "m", "high", None, bridge.WORKDIR
                )
            self.assertFalse(ok3)
            self.assertIn("code 503", err3)
            self.assertEqual(["compact_error", "compact_error"], inv_reasons)

            # (4) Negative: only PLANNER_RESPONSE DONE (no CHECKPOINT) -> False
            cid_chat = "conv-compact-chat-reply"
            self._write_transcript(brain_root, cid_chat, prior_hist)
            with (
                mock.patch.object(
                    bridge,
                    "_acquire_session",
                    side_effect=lambda *a, **kw: (
                        _CompactFakeSess(
                            [{"event": "result", "result": {"conversation_id": cid_chat, "status": "ERROR", "error": err_503}}],
                            on_send=lambda: self._write_transcript(
                                brain_root,
                                cid_chat,
                                prior_hist
                                + [
                                    {"type": "USER_INPUT", "status": "DONE", "content": "/compact"},
                                    {"type": "PLANNER_RESPONSE", "status": "DONE", "content": "just chatting"},
                                ],
                            ),
                        ),
                        False,
                    ),
                ),
                mock.patch.object(bridge, "invalidate_session"),
                mock.patch.object(bridge, "_sleep_interruptible", return_value=True),
            ):
                ok4, _dur4, _err4 = bridge._execute_compact_on_session(
                    skey, cid_chat, "auto", "m", "high", None, bridge.WORKDIR
                )
            self.assertFalse(ok4)

            # (5) Negative: EOF (res is None) and cancel_requested -> False (fail-closed)
            cid_eof = "conv-compact-eof"
            self._write_transcript(
                brain_root,
                cid_eof,
                prior_hist + [{"type": "CHECKPOINT", "status": "DONE", "content": "already there"}],
            )
            with (
                mock.patch.object(
                    bridge,
                    "_acquire_session",
                    side_effect=lambda *a, **kw: (_CompactFakeSess([{"event": "__eof__"}], stderr_text="eof"), False),
                ),
                mock.patch.object(bridge, "invalidate_session"),
                mock.patch.object(bridge, "_sleep_interruptible", return_value=True),
            ):
                ok_eof, _dur_e, _err_e = bridge._execute_compact_on_session(
                    skey, cid_eof, "auto", "m", "high", None, bridge.WORKDIR
                )
            self.assertFalse(ok_eof)

            def _trigger_cancel():
                bridge.cancel_requested = True

            bridge.cancel_requested = False
            try:
                with (
                    mock.patch.object(
                        bridge,
                        "_acquire_session",
                        return_value=(
                            _CompactFakeSess(
                                [{"event": "result", "result": {"conversation_id": cid_ok, "status": "ERROR", "error": err_503}}],
                                on_send=_trigger_cancel,
                            ),
                            False,
                        ),
                    ),
                    mock.patch.object(bridge, "invalidate_session"),
                ):
                    ok_cancel, _dur_c, err_cancel = bridge._execute_compact_on_session(
                        skey, cid_ok, "auto", "m", "high", None, bridge.WORKDIR
                    )
                self.assertFalse(ok_cancel)
                self.assertEqual("cancelled", err_cancel)
            finally:
                bridge.cancel_requested = False


if __name__ == "__main__":
    unittest.main()
