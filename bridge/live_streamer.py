"""Real-time Telegram draft streaming (`LiveDraftStreamer`), draft ID allocation, and `_NoOpStreamer`.

Standalone-capable flat module (no top-level `import bridge`). When wired into
`bridge/bridge.py`, call `bind_host(bridge_module)` so Telegram API helpers,
transcript accessors, and formatting callbacks resolve lazily at call time
(preserving full compatibility with `mock.patch.object(bridge, "tg", ...)`).
"""

from __future__ import annotations

import html as html_mod
import itertools
import json
import os
import re
import threading
import time

try:
    import formatting as _default_formatting
except ImportError:
    from bridge import formatting as _default_formatting  # type: ignore[no-redef]

_host = None


def bind_host(host):
    """Bind the runtime bridge host module (or namespace) for lazy attribute resolution."""
    global _host
    _host = host
    return host


def _resolve_host(host=None):
    return host if host is not None else _host


def _host_attr(name, default=None, *, host=None):
    h = _resolve_host(host)
    if h is None:
        return default
    return getattr(h, name, default)


def _default_normalize_thread_id(tid):
    if tid is None or isinstance(tid, bool):
        return None
    try:
        iv = int(tid)
    except (TypeError, ValueError):
        return None
    return iv if iv > 0 else None


# Monotonic non-zero draft_id generator (1 .. 2_000_000_000)
_draft_id_lock = threading.Lock()
_draft_id_seq = itertools.count(int(time.time() * 10) % 1_500_000_000 + 100)


def alloc_draft_pair():
    """Allocate two consecutive non-zero draft IDs: (status_draft_id, text_draft_id)."""
    with _draft_id_lock:
        d1 = (next(_draft_id_seq) % 2_000_000_000) or 1
        d2 = (next(_draft_id_seq) % 2_000_000_000) or 2
        return d1, d2


class LiveDraftStreamer:
    """Streams instant native `sendMessageDraft` updates (with automatic fallback to editMessageText).
    - t=0.00s: immediately pops up Telegram native "Thinking…" placeholder + Stop button
    - Event-driven (<50ms) live updates on every thought block, tool start, and tool finish
    - Smooth ~4.5 fps (0.22s) non-blocking animated text streaming during `agent_response`
    """

    def __init__(self, chat_id, started, cid=None, start_line=0, enabled=True, thread_id=None, *, host=None):
        self._host = host
        h = self._get_host()
        norm_tid_fn = _host_attr("_normalize_thread_id", _default_normalize_thread_id, host=h)
        brain_root = _host_attr(
            "BRAIN_ROOT",
            os.path.join(os.path.expanduser("~"), ".gemini/antigravity-cli/brain"),
            host=h,
        )
        alloc_fn = _host_attr("alloc_draft_pair", alloc_draft_pair, host=h)

        self.chat_id = chat_id
        self.thread_id = norm_tid_fn(thread_id)
        self.started = started
        self.cid = cid
        self.tpath = os.path.join(brain_root, cid, ".system_generated/logs/transcript.jsonl") if cid else None
        self.start_line = start_line
        self.enabled = enabled

        self.use_draft_api = bool(chat_id and int(chat_id) > 0)  # Native draft API works in private chats / DM topics
        self.status_draft_id, self.text_draft_id = alloc_fn()
        self.fallback_msg_id = None

        self.lock = threading.Lock()
        self.io_lock = threading.Lock()  # Held during HTTP call so finalize never races a late draft
        self.wakeup = threading.Event()
        self.stop_ev = threading.Event()

        self.paused = False
        self.waiting_bg = False
        self.delay_until = 0.0
        self.flood_until = 0.0
        self._fb_min_gap = 3.2
        self._fb_429_logged_at = 0.0
        self.phase = "status"          # "status" | "text"
        self.active_tool = None
        self.tool_history = []         # [(label, dur_str, out_snippet)]
        self.total_tools = 0
        self.latest_thought = ""
        self.stream_text = ""
        self.status_override = None

        self.last_sent_key = None
        self.last_push_at = 0.0
        self.urgent = True             # Push immediately at t=0.00s!
        self._thread = None

    def _get_host(self):
        return self._host if self._host is not None else _host

    def _log(self, msg):
        fn = _host_attr("log", None, host=self._get_host())
        if callable(fn):
            fn(msg)

    def _tg(self, method, **kwargs):
        fn = _host_attr("tg", None, host=self._get_host())
        if callable(fn):
            return fn(method, **kwargs)
        return None

    def _tg_send_in_route(self, method, chat_id, *, thread_id=None, **kwargs):
        fn = _host_attr("tg_send_in_route", None, host=self._get_host())
        if callable(fn):
            return fn(method, chat_id, thread_id=thread_id, **kwargs)
        return self._tg(method, chat_id=chat_id, **kwargs)

    def _tg_flood_remaining(self, chat_id):
        fn = _host_attr("_tg_flood_remaining", None, host=self._get_host())
        return float(fn(chat_id)) if callable(fn) else 0.0

    def _tg_is_429(self, resp):
        fn = _host_attr("_tg_is_429", None, host=self._get_host())
        if callable(fn):
            return bool(fn(resp))
        return getattr(resp, "status_code", None) == 429

    def _tg_retry_after(self, resp):
        fn = _host_attr("_tg_retry_after", None, host=self._get_host())
        if callable(fn):
            return fn(resp)
        return None

    def _tg_record_flood_wait(self, wait_s, *, chat_id=None, method="", resp=None):
        fn = _host_attr("_tg_record_flood_wait", None, host=self._get_host())
        if callable(fn):
            fn(wait_s, chat_id=chat_id, method=method, resp=resp)

    def _tg_json(self, resp):
        fn = _host_attr("_tg_json", None, host=self._get_host())
        if callable(fn):
            return fn(resp)
        if resp is None:
            return {}
        try:
            data = resp.json()
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _tg_ok(self, resp):
        fn = _host_attr("_tg_ok", None, host=self._get_host())
        if callable(fn):
            return bool(fn(resp))
        return bool(self._tg_json(resp).get("ok"))

    def _extract_msg_id(self, resp):
        fn = _host_attr("_extract_msg_id", None, host=self._get_host())
        if callable(fn):
            return fn(resp)
        j = self._tg_json(resp)
        if j.get("ok") and isinstance(j.get("result"), dict):
            return j["result"].get("message_id")
        return None

    def _sanitize_tg_log_text(self, text):
        fn = _host_attr("_sanitize_tg_log_text", None, host=self._get_host())
        return fn(text) if callable(fn) else str(text or "")[:160]

    def _fast_timeout(self):
        return _host_attr("FAST_TIMEOUT", (3.5, 6.0), host=self._get_host())

    def start(self):
        if not self.enabled:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def set_cid(self, cid):
        if not cid:
            return
        h = self._get_host()
        brain_root = _host_attr(
            "BRAIN_ROOT",
            os.path.join(os.path.expanduser("~"), ".gemini/antigravity-cli/brain"),
            host=h,
        )
        get_lines = _host_attr("get_transcript_line_count", None, host=h)
        with self.lock:
            if self.cid == cid and self.tpath:
                return
            self.cid = cid
            self.tpath = os.path.join(brain_root, cid, ".system_generated/logs/transcript.jsonl")
            self.start_line = get_lines(cid) if callable(get_lines) else 0

    def _refresh_thought_locked(self):
        if not self.tpath or not os.path.exists(self.tpath):
            return
        extract_fn = _host_attr(
            "extract_live_thought_snippet",
            _default_formatting.extract_live_thought_snippet,
            host=self._get_host(),
        )
        try:
            with open(self.tpath) as f:
                lines = f.readlines()[self.start_line:]
            for line in reversed(lines):
                obj = json.loads(line)
                th = obj.get("thinking")
                if th:
                    snip = extract_fn(th)
                    if snip and snip != self.latest_thought:
                        self.latest_thought = snip
                    break
        except Exception:
            pass

    def set_status_override(self, template_html):
        """Set or clear a custom status title template (may include `{elapsed}`)."""
        with self.lock:
            self.status_override = template_html
            self.phase = "status"
            self.paused = False
            self.delay_until = 0.0
            self.urgent = True
        self.wakeup.set()

    def on_thinking(self, text):
        if not text:
            return
        extract_fn = _host_attr(
            "extract_live_thought_snippet",
            _default_formatting.extract_live_thought_snippet,
            host=self._get_host(),
        )
        with self.lock:
            self.waiting_bg = False
            snip = extract_fn(text)
            if snip:
                self.latest_thought = snip
                self.urgent = True
        self.wakeup.set()

    def on_tool_start(self, tool_name, tool_info):
        fmt_tool = _host_attr("format_tool_label", lambda n, _i: str(n or "tool"), host=self._get_host())
        label = fmt_tool(tool_name, tool_info)
        with self.lock:
            # Immediately pull the fresh thinking block that agy flushed right before tool start!
            self._refresh_thought_locked()
            self.paused = False
            self.waiting_bg = False
            self.delay_until = 0.0
            self.phase = "status"
            self.active_tool = label
            self.total_tools += 1
            self.urgent = True
        self.wakeup.set()

    def on_tool_done(self, tool_name, tool_info, duration_seconds=None):
        h = self._get_host()
        fmt_tool = _host_attr("format_tool_label", lambda n, _i: str(n or "tool"), host=h)
        sum_out = _host_attr("summarize_tool_output", lambda _i: "", host=h)
        label = fmt_tool(tool_name, tool_info)
        dur_str = f"{duration_seconds:.1f}s" if duration_seconds is not None else ""
        out_snip = sum_out(tool_info)
        with self.lock:
            self.tool_history.append((label, dur_str, out_snip))
            if len(self.tool_history) > 7:
                self.tool_history = self.tool_history[-7:]
            if self.active_tool == label:
                self.active_tool = None
            self.urgent = True
        self.wakeup.set()

    def on_text_delta(self, accumulated_text):
        if not accumulated_text or not accumulated_text.strip():
            return
        with self.lock:
            was_status = (self.phase != "text")
            self.paused = False
            self.waiting_bg = False
            self.delay_until = 0.0
            self.phase = "text"
            self.stream_text = accumulated_text
            if was_status:
                self.urgent = True
        self.wakeup.set()

    def pause_for_finalize(self):
        """Synchronously pause streaming and wait for any in-flight draft HTTP call to finish."""
        with self.lock:
            self.paused = True
        with self.io_lock:
            pass

    def finalize_step(self, final_text, header_html=None, footer_str=None, reply_markup=None):
        """Deliver permanent step message cleanly, replacing the live draft without losing output."""
        self.pause_for_finalize()
        old_fb_mid = self.fallback_msg_id
        self.fallback_msg_id = None

        h = self._get_host()
        split_md = _host_attr("split_markdown", _default_formatting.split_markdown, host=h)
        md_html = _host_attr("md_to_html", _default_formatting.md_to_html, host=h)
        fast_timeout = self._fast_timeout()

        # In fallback mode (e.g. group chat), edit single-chunk message in place to save group quota
        if not self.use_draft_api and old_fb_mid is not None:
            chunks = split_md(final_text, max_len=3000)
            footer_html = ("\n\n" + html_mod.escape(footer_str)) if footer_str else ""
            if len(chunks) == 1:
                full_html = (header_html or "") + md_html(chunks[0]) + footer_html
                if full_html and len(full_html) <= 4050:
                    kw = {
                        "chat_id": self.chat_id,
                        "message_id": old_fb_mid,
                        "text": full_html,
                        "parse_mode": "HTML",
                        "link_preview_options": {"is_disabled": True},
                    }
                    if reply_markup:
                        kw["reply_markup"] = reply_markup
                    r = self._tg("editMessageText", _max_429_wait=65, **kw)
                    if self._tg_ok(r):
                        return old_fb_mid, full_html

        # Deliver permanent response FIRST (with 429 wait + multi-chunk pacing + rescue) BEFORE deleting fallback bubble!
        send_rich_fn = _host_attr("send_rich", None, host=h)
        if callable(send_rich_fn):
            last_mid, last_html = send_rich_fn(
                self.chat_id, final_text, header_html=header_html,
                footer_str=footer_str, reply_markup=reply_markup, thread_id=self.thread_id,
            )
        else:
            last_mid, last_html = None, None

        if old_fb_mid is not None:
            if last_mid is not None:
                self._tg(
                    "deleteMessage",
                    _timeout=fast_timeout,
                    _retry_429=False,
                    chat_id=self.chat_id,
                    message_id=old_fb_mid,
                )
            else:
                snippet = html_mod.escape(final_text[:2800]) + ("\n..." if len(final_text) > 2800 else "")
                notice = (
                    "⚠️ <b>最终消息送达受阻，已保存并尝试文件补发，以下为预览：</b>\n\n"
                    f"{snippet}"
                )
                self._tg(
                    "editMessageText",
                    _max_429_wait=20,
                    chat_id=self.chat_id,
                    message_id=old_fb_mid,
                    text=notice[:4090],
                    parse_mode="HTML",
                    link_preview_options={"is_disabled": True},
                )

        return last_mid, last_html

    def start_next_segment(self, new_start_line):
        """Prepare a fresh draft pair if the turn continues after an intermediate response."""
        alloc_fn = _host_attr("alloc_draft_pair", alloc_draft_pair, host=self._get_host())
        d1, d2 = alloc_fn()
        with self.lock:
            self.status_draft_id = d1
            self.text_draft_id = d2
            self.fallback_msg_id = None
            self.phase = "status"
            self.stream_text = ""
            self.tool_history = []
            self.active_tool = None
            self.latest_thought = ""
            self.start_line = new_start_line
            self.last_sent_key = None
            self.waiting_bg = True
            self.paused = False
            # Small 0.5s grace so normal turns never flash after intermediate check
            self.delay_until = time.time() + 0.5
        self.wakeup.set()

    def stop(self):
        self.stop_ev.set()
        with self.lock:
            self.paused = True
            fb_mid = self.fallback_msg_id
            self.fallback_msg_id = None
        self.wakeup.set()
        with self.io_lock:
            pass
        if fb_mid is not None:
            self._tg(
                "deleteMessage",
                _timeout=self._fast_timeout(),
                _retry_429=False,
                chat_id=self.chat_id,
                message_id=fb_mid,
            )

    def _build_status_payload_locked(self):
        elapsed = int(time.time() - self.started)
        self._refresh_thought_locked()

        # At t < 2s before any thoughts/tools arrive, empty string triggers Telegram native "Thinking…" shimmer!
        if (
            self.use_draft_api
            and elapsed < 2
            and not self.status_override
            and not self.latest_thought
            and not self.tool_history
            and not self.active_tool
            and not self.waiting_bg
        ):
            return self.status_draft_id, ""

        if self.status_override:
            title = self.status_override.replace("{elapsed}", str(elapsed))
        elif self.waiting_bg and not self.active_tool and not self.latest_thought and not self.tool_history:
            title = f"⏳ <b>等待后台任务响应 ({elapsed}s)...</b>\n<i>可直接发消息打断，或发送 /cancel 终止</i>"
        elif self.total_tools > 0:
            title = f"⚡ <b>思考与执行中 ({elapsed}s · 第 {self.total_tools} 步)...</b>"
        else:
            title = f"🧠 <b>正在深度思考 ({elapsed}s)...</b>"

        lines = [title]
        if self.latest_thought:
            lines.append(f"\n<blockquote>💭 <i>{html_mod.escape(self.latest_thought)}</i></blockquote>")

        tool_lines = []
        for label, dur, out_snip in self.tool_history[-5:]:
            tag = f" <code>[{dur}]</code>" if dur else ""
            extra = f"\n   ↳ <i>{html_mod.escape(out_snip)}</i>" if out_snip else ""
            tool_lines.append(f"• ✓ <code>{html_mod.escape(label)}</code>{tag}{extra}")
        if self.active_tool:
            tool_lines.append(f"• ⚙️ <code>{html_mod.escape(self.active_tool)}</code> <i>(执行中...)</i>")

        if tool_lines:
            lines.append("\n" + "\n".join(tool_lines))

        return self.status_draft_id, "\n".join(lines)[:3950]

    def _build_text_payload_locked(self):
        md_html = _host_attr("md_to_html", _default_formatting.md_to_html, host=self._get_host())
        raw = self.stream_text.strip()
        snippet = raw if len(raw) <= 3400 else ("…\n" + raw[-3400:])
        if snippet.count("```") % 2 == 1:
            snippet += "\n```"
        rendered = md_html(snippet)
        html = rendered + " ▍"
        if len(html) > 4000:
            html = html_mod.escape(raw[-3800:]) + " ▍"
        return self.text_draft_id, html

    def _push_draft(self, draft_id, html_text):
        fast_timeout = self._fast_timeout()
        with self.io_lock:
            with self.lock:
                if self.paused or self.stop_ev.is_set():
                    return
            rem_shared = self._tg_flood_remaining(self.chat_id)
            if rem_shared > 0:
                with self.lock:
                    self.flood_until = max(self.flood_until, time.time() + rem_shared)
                self.last_push_at = time.time()
                return

            if self.use_draft_api:
                params = {
                    "draft_id": draft_id,
                    "text": html_text,
                    "can_stop": True,
                    "keep_on_stop": True,
                }
                if html_text:
                    params["parse_mode"] = "HTML"
                r = self._tg_send_in_route(
                    "sendMessageDraft",
                    self.chat_id,
                    thread_id=self.thread_id,
                    _timeout=fast_timeout,
                    _retry_429=False,
                    **params,
                )
                if r is None:
                    rem_after = self._tg_flood_remaining(self.chat_id)
                    if rem_after > 0:
                        with self.lock:
                            self.flood_until = max(self.flood_until, time.time() + rem_after)
                        self.last_push_at = time.time()
                        return
                elif self._tg_is_429(r):
                    wait_s = self._tg_retry_after(r) or 2
                    self._tg_record_flood_wait(wait_s, chat_id=self.chat_id, method="sendMessageDraft", resp=r)
                    with self.lock:
                        self.flood_until = max(self.flood_until, time.time() + float(wait_s) + 0.5)
                    self.last_push_at = time.time()
                    return
                else:
                    j = self._tg_json(r)
                    if j.get("ok"):
                        self.last_push_at = time.time()
                        return
                    desc = str(j.get("description", ""))
                    # If malformed partial HTML entity, retry plain text draft once
                    if html_text and ("parse entities" in desc or "can't find end" in desc):
                        plain = re.sub(r"<[^>]+>", "", html_mod.unescape(html_text))[:3950]
                        r2 = self._tg_send_in_route(
                            "sendMessageDraft",
                            self.chat_id,
                            thread_id=self.thread_id,
                            _timeout=fast_timeout,
                            _retry_429=False,
                            draft_id=draft_id,
                            text=plain,
                            can_stop=True,
                            keep_on_stop=True,
                        )
                        if self._tg_is_429(r2):
                            wait_s = self._tg_retry_after(r2) or 2
                            self._tg_record_flood_wait(wait_s, chat_id=self.chat_id, method="sendMessageDraft", resp=r2)
                            with self.lock:
                                self.flood_until = max(self.flood_until, time.time() + float(wait_s) + 0.5)
                            self.last_push_at = time.time()
                            return
                        if self._tg_ok(r2):
                            self.last_push_at = time.time()
                            return
                        if self._tg_flood_remaining(self.chat_id) > 0:
                            rem_after = self._tg_flood_remaining(self.chat_id)
                            with self.lock:
                                self.flood_until = max(self.flood_until, time.time() + rem_after)
                            self.last_push_at = time.time()
                            return
                    # Otherwise fallback cleanly to editMessageText mode
                    self._log(
                        "sendMessageDraft returned %s; switching to editMessageText fallback"
                        % self._sanitize_tg_log_text(desc)
                    )
                    self.use_draft_api = False

            # Fallback path (e.g. group chats / topics)
            if self._tg_flood_remaining(self.chat_id) > 0:
                rem_after = self._tg_flood_remaining(self.chat_id)
                with self.lock:
                    self.flood_until = max(self.flood_until, time.time() + rem_after)
                self.last_push_at = time.time()
                return
            fb_text = html_text or "🧠 <b>正在思考中...</b>"
            use_parse_html = True
            for _fb_try in range(2):
                kw_fb = {"text": fb_text, "link_preview_options": {"is_disabled": True}}
                if use_parse_html:
                    kw_fb["parse_mode"] = "HTML"
                if self.fallback_msg_id is None:
                    r = self._tg_send_in_route(
                        "sendMessage",
                        self.chat_id,
                        thread_id=self.thread_id,
                        _timeout=fast_timeout,
                        _retry_429=False,
                        **kw_fb,
                    )
                    mid = self._extract_msg_id(r)
                    if mid:
                        with self.lock:
                            if self.paused or self.stop_ev.is_set():
                                self._tg(
                                    "deleteMessage",
                                    _timeout=fast_timeout,
                                    _retry_429=False,
                                    chat_id=self.chat_id,
                                    message_id=mid,
                                )
                                return
                            self.fallback_msg_id = mid
                        self.last_push_at = time.time()
                        return
                else:
                    r = self._tg(
                        "editMessageText",
                        _timeout=fast_timeout,
                        _retry_429=False,
                        chat_id=self.chat_id,
                        message_id=self.fallback_msg_id,
                        **kw_fb,
                    )
                    if self._tg_ok(r):
                        self.last_push_at = time.time()
                        return

                if self._tg_is_429(r):
                    wait_s = self._tg_retry_after(r) or 5
                    self._tg_record_flood_wait(
                        wait_s,
                        chat_id=self.chat_id,
                        method="sendMessage" if self.fallback_msg_id is None else "editMessageText",
                        resp=r,
                    )
                    with self.lock:
                        self._fb_min_gap = min(8.0, self._fb_min_gap + 1.2)
                        self.flood_until = max(self.flood_until, time.time() + float(wait_s) + 1.0)
                        gap_now = self._fb_min_gap
                    if (time.time() - self._fb_429_logged_at) > 10.0:
                        self._fb_429_logged_at = time.time()
                        self._log(
                            "DraftStreamer fallback hit 429 (retry_after=%ss); backing off (gap=%.1fs)"
                            % (wait_s, gap_now)
                        )
                    self.last_push_at = time.time()
                    return
                if r is None and self._tg_flood_remaining(self.chat_id) > 0:
                    rem_after = self._tg_flood_remaining(self.chat_id)
                    with self.lock:
                        self.flood_until = max(self.flood_until, time.time() + rem_after)
                    self.last_push_at = time.time()
                    return

                desc = str(self._tg_json(r).get("description", ""))
                low_desc = desc.lower()
                if "message is not modified" in low_desc:
                    self.last_push_at = time.time()
                    return
                if use_parse_html and ("parse entities" in low_desc or "can't find end" in low_desc):
                    fb_text = re.sub(r"<[^>]+>", "", html_mod.unescape(fb_text))[:3950] or "Thinking..."
                    use_parse_html = False
                    continue
                if "message to edit not found" in low_desc:
                    with self.lock:
                        self.fallback_msg_id = None
                break
            self.last_push_at = time.time()

    def _loop(self):
        while not self.stop_ev.is_set():
            with self.lock:
                now = time.time()
                is_paused = self.paused
                rem_shared = self._tg_flood_remaining(self.chat_id)
                rem_delay = max(0.0, max(self.delay_until, self.flood_until) - now, rem_shared)
                is_text = (self.phase == "text")
                is_urgent = self.urgent
            if is_paused:
                self.wakeup.wait(timeout=1.0)
            elif rem_delay > 0:
                self.stop_ev.wait(timeout=min(1.0, rem_delay))
            else:
                wait_s = 0.0 if is_urgent else (0.22 if is_text else 1.2)
                if wait_s > 0:
                    self.wakeup.wait(timeout=wait_s)
            self.wakeup.clear()

            if self.stop_ev.is_set():
                break

            now = time.time()
            with self.lock:
                if (
                    self.paused
                    or now < max(self.delay_until, self.flood_until)
                    or self._tg_flood_remaining(self.chat_id) > 0
                ):
                    continue
                if self.use_draft_api:
                    min_gap = 0.20 if self.phase == "text" else (0.12 if self.urgent else 1.1)
                else:
                    min_gap = max(3.2, self._fb_min_gap)
                since = now - self.last_push_at
                sleep_rem = max(0.0, min_gap - since)

            if sleep_rem > 0:
                self.stop_ev.wait(timeout=sleep_rem)
                if self.stop_ev.is_set():
                    break

            with self.lock:
                if (
                    self.paused
                    or self.stop_ev.is_set()
                    or time.time() < max(self.delay_until, self.flood_until)
                    or self._tg_flood_remaining(self.chat_id) > 0
                ):
                    continue
                self.urgent = False
                if self.phase == "text":
                    did, payload = self._build_text_payload_locked()
                else:
                    did, payload = self._build_status_payload_locked()

                # Keep draft alive every 12s even if text didn't change (draft expires at 30s)
                key = (did, payload)
                if key == self.last_sent_key and (time.time() - self.last_push_at) < 12.0:
                    continue
                self.last_sent_key = key

            self._push_draft(did, payload)


class _NoOpStreamer:
    """Zero-Telegram stub streamer used when `run_agy` executes a Web Studio IPC turn."""

    def __init__(self, cid=None, start_line=0):
        self.cid = cid
        self.start_line = start_line
        self.status_override = None

    def start(self):
        return

    def stop(self):
        return

    def set_cid(self, cid):
        if cid:
            self.cid = cid

    def set_status_override(self, template_html):
        self.status_override = template_html

    def on_thinking(self, text):
        return

    def on_tool_start(self, tool_name, tool_info):
        return

    def on_tool_done(self, tool_name, tool_info, duration_seconds=None):
        return

    def on_text_delta(self, text):
        return

    def finalize_step(self, *args, **kwargs):
        return (None, None)

    def start_next_segment(self, start_line=0):
        self.start_line = start_line
