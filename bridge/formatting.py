#!/usr/bin/env python3
"""Pure Telegram HTML / Markdown formatting and live-stream snippet helpers."""

from __future__ import annotations

import html as html_mod
import os
import re


def format_inline_markdown(text):
    """Format markdown text (outside code blocks) into Telegram HTML."""
    esc = html_mod.escape(text)

    code_tokens = []

    def save_code(m):
        code_tokens.append(m.group(1))
        return f"\x00CODE{len(code_tokens)-1}\x00"

    esc = re.sub(r"`([^`\n]+)`", save_code, esc)
    esc = re.sub(r"\*\*([^*\n]+)\*\*", r"<b>\1</b>", esc)
    esc = re.sub(r"__([^_\n]+)__", r"<b>\1</b>", esc)
    esc = re.sub(r"~~([^~\n]+)~~", r"<s>\1</s>", esc)
    esc = re.sub(r"(?<!\w)\*([^*\n]+)\*(?!\w)", r"<i>\1</i>", esc)
    esc = re.sub(r"(?<!\w)_([^_\n]+)_(?!\w)", r"<i>\1</i>", esc)
    esc = re.sub(
        r"^(#{1,6})\s+(.+)$",
        lambda m: f"<b>{re.sub(r'</?b>', '', m.group(2))}</b>",
        esc,
        flags=re.MULTILINE,
    )

    # Markdown images: ![alt](path) -> 🖼 <code>alt</code>
    esc = re.sub(
        r"!\[([^\]]*)\]\(([^)\s]+)\)",
        lambda m: f"🖼 <code>{m.group(1) or os.path.basename(m.group(2))}</code>",
        esc,
    )
    # Local file:// links -> <code>label</code>
    esc = re.sub(r"\[([^\]]+)\]\(file://[^)\s]+\)", r"<code>\1</code>", esc)
    # Web/Telegram links
    esc = re.sub(r"\[([^\]]+)\]\(((?:https?|tg)://[^)\s]+)\)", r'<a href="\2">\1</a>', esc)

    def replace_quote(m):
        q = m.group(0).replace("&gt; ", "").replace("&gt;", "").strip("\n")
        return f"<blockquote>{q}</blockquote>"

    esc = re.sub(r"(?:^&gt; .*(?:\n|$))+", replace_quote, esc, flags=re.MULTILINE)

    for idx, code_content in enumerate(code_tokens):
        esc = esc.replace(f"\x00CODE{idx}\x00", f"<code>{code_content}</code>")

    return esc


def md_to_html(text):
    """Convert full markdown to Telegram HTML, preserving language in code blocks."""
    if not text:
        return ""

    code_block_pattern = re.compile(r"```([a-zA-Z0-9_\-\+]*)\n?(.*?)```", re.DOTALL)
    parts = []
    last_idx = 0
    for m in code_block_pattern.finditer(text):
        if m.start() > last_idx:
            parts.append(("text", text[last_idx:m.start()]))
        parts.append(("code", (m.group(1).strip(), m.group(2))))
        last_idx = m.end()

    if last_idx < len(text):
        rem = text[last_idx:]
        if rem.startswith("```"):
            first_nl = rem.find("\n")
            if first_nl != -1:
                lang = rem[3:first_nl].strip()
                parts.append(("code", (lang, rem[first_nl + 1:])))
            else:
                parts.append(("code", ("", rem[3:])))
        else:
            parts.append(("text", rem))

    out = []
    for kind, content in parts:
        if kind == "code":
            lang, code = content
            esc_code = html_mod.escape(code.strip("\r\n"))
            if lang:
                out.append(f'<pre><code class="language-{html_mod.escape(lang)}">{esc_code}</code></pre>')
            else:
                out.append(f"<pre><code>{esc_code}</code></pre>")
        else:
            out.append(format_inline_markdown(content))

    return "".join(out)


def split_markdown(text, max_len=3200):
    """Split long markdown text cleanly at line or code boundaries."""
    if len(text) <= max_len:
        return [text]

    lines = text.split("\n")
    chunks = []
    current_chunk = []
    current_len = 0
    in_code_block = False
    code_fence = ""

    for line in lines:
        line_len = len(line) + 1
        m = re.match(r"^(```+)(\w*)", line)

        if current_len + line_len > max_len and current_chunk:
            if in_code_block:
                current_chunk.append("```")
                chunks.append("\n".join(current_chunk))
                current_chunk = [f"```{code_fence}", line]
                current_len = len(current_chunk[0]) + 1 + line_len
            else:
                chunks.append("\n".join(current_chunk))
                current_chunk = [line]
                current_len = line_len
        else:
            current_chunk.append(line)
            current_len += line_len

        if m:
            if not in_code_block:
                in_code_block = True
                code_fence = m.group(2)
            else:
                in_code_block = False
                code_fence = ""

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    return chunks


def format_tool_label(tool_name, tool_info):
    """Format tool execution into a clear, informative label for live streaming."""
    if not tool_name:
        return ""
    params = (tool_info or {}).get("parameters") or {}
    if tool_name == "run_command":
        summary = params.get("toolSummary")
        cmd = params.get("CommandLine", "").strip().split("\n")[0]
        if summary and cmd:
            return f"sh: {summary[:24]} ({cmd[:28]})"
        elif summary:
            return f"sh: {summary[:40]}"
        return f"sh: {cmd[:42]}" if cmd else "sh"
    elif tool_name in ("read_file", "view_file"):
        path = params.get("Path") or params.get("AbsolutePath") or ""
        return f"read: {os.path.basename(path)[:32]}" if path else "read"
    elif tool_name in ("edit_file", "replace_file_content", "multi_replace_file_content"):
        path = params.get("Path") or params.get("TargetFile") or ""
        return f"edit: {os.path.basename(path)[:32]}" if path else "edit"
    elif tool_name in ("write_file", "write_to_file"):
        path = params.get("Path") or params.get("TargetFile") or ""
        return f"write: {os.path.basename(path)[:32]}" if path else "write"
    elif tool_name == "search_web":
        q = params.get("query", "")
        return f"search: {q[:32]}" if q else "search"
    elif tool_name == "invoke_subagent":
        role = params.get("Role") or params.get("TypeName") or "agent"
        return f"agent: {role[:30]}"
    elif tool_name == "call_mcp_tool":
        srv = params.get("ServerName", "")
        tname = params.get("ToolName", "")
        return f"mcp: {srv}.{tname}"[:36] if srv else f"mcp: {tname[:30]}"
    elif tool_name == "context_compaction":
        return "🧹 自动压缩上下文 (Context Compaction)"
    return tool_name[:30]


def summarize_tool_output(tool_info):
    """Extract a crisp 1-line outcome snippet from completed tool_info if available."""
    out = (tool_info or {}).get("output")
    if not isinstance(out, str) or not out.strip():
        return ""
    idx = out.find("Command output:\n")
    if idx != -1:
        body = out[idx + len("Command output:\n"):].strip()
    else:
        body = out.strip()
    for line in body.splitlines():
        s = line.strip()
        if s and not s.startswith("Created At:") and not s.startswith("Completed At:"):
            return s[:48] + ("…" if len(s) > 48 else "")
    return ""


def format_usage_suffix(dur, total_tokens, model=None, effort=None, fallback_from=None):
    """Format compact turn execution footer (model, effort, duration, tokens, optional failover tag)."""
    parts = []
    eff_model = model or "gemini-3.8-flash-high"
    if effort:
        eff_effort = effort
    else:
        for lvl in ("xhigh", "high", "medium", "low"):
            if eff_model.endswith("-" + lvl):
                eff_effort = lvl
                break
        else:
            eff_effort = "default"

    if fallback_from is not None and fallback_from != model:
        orig_lbl = fallback_from or "default"
        parts.append(f"🤖 {eff_model} (🔁 备用切换←{orig_lbl})")
    else:
        parts.append(f"🤖 {eff_model}")
    parts.append(f"🧠 {eff_effort}")

    if dur is not None:
        try:
            parts.append(f"⏱ {float(dur) / 60.0:.2f} min")
        except Exception:
            parts.append(f"⏱ {dur} min")

    if total_tokens is not None:
        try:
            m = float(total_tokens) / 1_000_000.0
            if m < 0.001:
                tok_str = f"{m:.4f}".rstrip("0").rstrip(".") + " m"
            elif m < 0.1:
                tok_str = f"{m:.3f}".rstrip("0").rstrip(".") + " m"
            else:
                tok_str = f"{m:.2f}".rstrip("0").rstrip(".") + " m"
            parts.append(tok_str)
        except Exception:
            parts.append(f"{total_tokens} m")

    return " · ".join(parts)


def format_tokens_k(tokens):
    """Format token counts cleanly in compact `k` units."""
    if tokens is None:
        return "0k"
    if tokens >= 1000:
        val = tokens / 1000.0
        return f"{val:.1f}k" if val < 100 else f"{int(round(val))}k"
    return str(int(tokens))


def build_thinking_header(thinkings, tool_calls):
    """Build a collapsible Telegram blockquote (<blockquote expandable>) safely within 3800 chars."""
    open_tag = "<blockquote expandable>"
    close_tag = "</blockquote>\n\n"
    max_inner = 3800 - len(open_tag) - len(close_tag)

    thinking_block = ""
    if thinkings:
        joined_thinking = "\n\n".join(t.strip() for t in thinkings if t and t.strip())
        if len(joined_thinking) > 1600:
            joined_thinking = joined_thinking[:1600] + "... (truncated)"
        while joined_thinking and len(html_mod.escape(joined_thinking)) > 2000:
            joined_thinking = joined_thinking[:max(100, int(len(joined_thinking) * 0.75))] + "... (truncated)"
        if joined_thinking:
            thinking_block = "💭 <b>思考过程 (Thinking Process):</b>\n" + html_mod.escape(joined_thinking)

    blocks = [thinking_block] if thinking_block else []
    used_len = len(thinking_block)

    if tool_calls:
        tool_hdr = f"🛠 <b>工具调用 (Tool Calls - {len(tool_calls)}):</b>"
        sep = 2 if blocks else 0
        if used_len + sep + len(tool_hdr) + 64 <= max_inner:
            tool_lines = [tool_hdr]
            used_len += sep + len(tool_hdr)
            cap = min(len(tool_calls), 25)
            shown = 0
            for tc in tool_calls[:cap]:
                name = tc.get("name", "tool")
                args = tc.get("args") or {}
                label = format_tool_label(name, {"parameters": args})
                line = f"• <code>{html_mod.escape(name)}</code> ({html_mod.escape(label)})"
                more_note = f"\n• <i>... +{len(tool_calls) - (shown + 1)} more</i>"
                reserve = len(more_note) if (shown + 1) < len(tool_calls) else 0
                if used_len + 1 + len(line) + reserve > max_inner:
                    break
                tool_lines.append(line)
                used_len += 1 + len(line)
                shown += 1
            if shown < len(tool_calls):
                tool_lines.append(f"• <i>... +{len(tool_calls) - shown} more</i>")
            blocks.append("\n".join(tool_lines))

    if not blocks:
        return ""
    return open_tag + "\n\n".join(blocks) + close_tag


def extract_live_thought_snippet(raw_thought, max_chars=360):
    """Extract the latest reasoning lines (up to ~4 lines / 360 chars) for live streaming preview."""
    if not raw_thought:
        return ""
    cleaned_lines = []
    for line in raw_thought.strip().splitlines():
        s = re.sub(r"^[#>*\s]+", "", line).strip()
        if s:
            cleaned_lines.append(s)
    if not cleaned_lines:
        return ""
    tail = "\n".join(cleaned_lines[-4:])
    if len(tail) > max_chars:
        tail = "…" + tail[-max_chars:]
    return tail
