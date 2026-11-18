#!/usr/bin/env python3
"""Antigravity Python SDK Telegram Bridge.

Runs side-by-side with any existing CLI bridge.
Uses google-antigravity SDK with native Go localharness runtime.
"""
import asyncio
import html as html_mod
import json
import logging
import os
import re
import signal
import sys
import time
from typing import Dict, List, Optional

import aiohttp
from google.antigravity import Agent, LocalAgentConfig, CapabilitiesConfig, types
from google.antigravity.hooks import policy

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("agy-sdk-bridge")

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.isfile(ENV_PATH):
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

BOT_TOKEN = os.environ.get("AGY_SDK_BOT_TOKEN", "").strip()
ALLOWED_RAW = os.environ.get("AGY_SDK_ALLOWED_CHATS", "").strip()
ALLOWED_CHATS = {int(x) for x in ALLOWED_RAW.split(",") if x.strip().isdigit()}
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
MODEL_TARGET = os.environ.get("AGY_SDK_MODEL", "").strip() or "gemini-2.5-flash"
WORKDIR = os.path.realpath(os.environ.get("AGY_SDK_WORKDIR", os.path.expanduser("~/agy-workspace")))
STATE_FILE = os.path.join(os.path.expanduser("~"), ".agy-sdk-bridge-state.json")

TG_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

# -----------------------------------------------------------------------------
# State Management
# -----------------------------------------------------------------------------
chat_sessions: Dict[int, Optional[str]] = {}

def load_state():
    global chat_sessions
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                chat_sessions = {int(k): v for k, v in data.get("sessions", {}).items()}
                logger.info(f"Loaded sessions for {len(chat_sessions)} chats.")
        except Exception as e:
            logger.warning(f"Failed to load state: {e}")

def save_state():
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"sessions": {str(k): v for k, v in chat_sessions.items()}}, f, indent=2)
    except Exception as e:
        logger.warning(f"Failed to save state: {e}")

def update_env_file(key: str, val: str):
    lines = []
    found = False
    if os.path.isfile(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            lines = f.readlines()
    new_lines = []
    for line in lines:
        if line.strip().startswith(f"{key}=") or line.strip() == key:
            new_lines.append(f"{key}={val}\n")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"{key}={val}\n")
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

# -----------------------------------------------------------------------------
# Telegram HTML Formatting Utilities
# -----------------------------------------------------------------------------
def format_inline_markdown(text: str) -> str:
    esc = html_mod.escape(text)
    code_tokens = []

    def save_code(m):
        code_tokens.append(m.group(1))
        return f"\x00CODE{len(code_tokens)-1}\x00"

    esc = re.sub(r"`([^`\n]+)`", save_code, esc)
    esc = re.sub(r"^(#{1,6})\s+(.+)$", r"<b>\2</b>", esc, flags=re.MULTILINE)
    esc = re.sub(r"\*\*([^*\n]+)\*\*", r"<b>\1</b>", esc)
    esc = re.sub(r"__([^_\n]+)__", r"<b>\1</b>", esc)
    esc = re.sub(r"~~([^~\n]+)~~", r"<s>\1</s>", esc)
    esc = re.sub(r"(?<!\w)\*([^*\n]+)\*(?!\w)", r"<i>\1</i>", esc)
    esc = re.sub(r"(?<!\w)_([^_\n]+)_(?!\w)", r"<i>\1</i>", esc)
    esc = re.sub(r"\[([^\]]+)\]\(((?:https?|tg)://[^)\s]+)\)", r'<a href="\2">\1</a>', esc)

    for idx, code_content in enumerate(code_tokens):
        esc = esc.replace(f"\x00CODE{idx}\x00", f"<code>{code_content}</code>")

    return esc

def md_to_html(text: str) -> str:
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
                out.append(f'<pre><code>{esc_code}</code></pre>')
        else:
            out.append(format_inline_markdown(content))

    return "".join(out)

# -----------------------------------------------------------------------------
# Telegram API Client
# -----------------------------------------------------------------------------
class TelegramClient:
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session

    async def api_call(self, method: str, json_data: dict) -> Optional[dict]:
        url = f"{TG_API}/{method}"
        try:
            async with self.session.post(url, json=json_data, timeout=aiohttp.ClientTimeout(total=60)) as resp:
                data = await resp.json()
                if not data.get("ok"):
                    logger.warning(f"Telegram API {method} error: {data}")
                return data
        except Exception as e:
            logger.error(f"Telegram HTTP request error ({method}): {e}")
            return None

    async def send_message(self, chat_id: int, text: str, parse_mode: Optional[str] = "HTML", reply_to: Optional[int] = None) -> Optional[int]:
        payload = {"chat_id": chat_id, "text": text}
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if reply_to:
            payload["reply_to_message_id"] = reply_to
        data = await self.api_call("sendMessage", payload)
        if data and data.get("ok"):
            return data["result"]["message_id"]
        # Fallback to plain text if HTML parsing failed
        if parse_mode == "HTML":
            payload.pop("parse_mode")
            data = await self.api_call("sendMessage", payload)
            if data and data.get("ok"):
                return data["result"]["message_id"]
        return None

    async def edit_message(self, chat_id: int, message_id: int, text: str, parse_mode: Optional[str] = "HTML") -> bool:
        payload = {"chat_id": chat_id, "message_id": message_id, "text": text}
        if parse_mode:
            payload["parse_mode"] = parse_mode
        data = await self.api_call("editMessageText", payload)
        if data and data.get("ok"):
            return True
        if parse_mode == "HTML":
            payload.pop("parse_mode")
            data = await self.api_call("editMessageText", payload)
            return bool(data and data.get("ok"))
        return False

# -----------------------------------------------------------------------------
# Agent Task Execution
# -----------------------------------------------------------------------------
async def execute_agent_task(tg: TelegramClient, chat_id: int, prompt: str, reply_to_id: Optional[int]):
    if not GEMINI_API_KEY:
        await tg.send_message(
            chat_id,
            "⚠️ <b>未配置 GEMINI_API_KEY</b>\n\n"
            "Antigravity Python SDK 启动需要 Gemini API 密钥。\n"
            "请在 <code>agy-sdk-bridge/.env</code> 中填入 <code>GEMINI_API_KEY=AIza...</code> 后重试。",
            reply_to=reply_to_id,
        )
        return

    os.makedirs(WORKDIR, exist_ok=True)
    conv_id = chat_sessions.get(chat_id)

    status_msg_id = await tg.send_message(
        chat_id,
        "⚡ <b>Antigravity SDK 正在初始化...</b>",
        reply_to=reply_to_id,
    )
    if not status_msg_id:
        return

    config_kwargs = {
        "api_key": GEMINI_API_KEY,
        "workspaces": [WORKDIR],
        "capabilities": CapabilitiesConfig(),
        "policies": [policy.allow_all()],
    }
    if MODEL_TARGET:
        config_kwargs["model"] = MODEL_TARGET
    if conv_id:
        config_kwargs["conversation_id"] = conv_id

    config = LocalAgentConfig(**config_kwargs)

    thoughts: List[str] = []
    tool_events: List[str] = []
    output_text: List[str] = []
    last_update_time = time.time()
    update_interval = 1.3

    try:
        async with Agent(config) as agent:
            # Update session ID if new
            new_cid = agent.conversation_id
            if new_cid and new_cid != conv_id:
                chat_sessions[chat_id] = new_cid
                save_state()

            await tg.edit_message(
                chat_id,
                status_msg_id,
                f"⚡ <b>Antigravity SDK 思考中...</b>\n会话: <code>{new_cid[:8] if new_cid else 'new'}...</code>",
            )

            response = await agent.chat(prompt)

            async for chunk in response.chunks:
                now = time.time()
                if isinstance(chunk, types.Thought):
                    thoughts.append(chunk.text)
                elif isinstance(chunk, types.ToolCall):
                    tool_desc = f"⚙️ <code>{chunk.name}</code>"
                    if chunk.name == "run_command" and isinstance(chunk.args, dict):
                        cmd = chunk.args.get("CommandLine", "")[:50]
                        tool_desc = f"⚙️ <code>bash: {html_mod.escape(cmd)}</code>"
                    tool_events.append(tool_desc)
                elif isinstance(chunk, types.ToolResult):
                    # Tool executed
                    pass
                elif isinstance(chunk, types.Text):
                    output_text.append(chunk.text)

                # Periodic update to Telegram
                if now - last_update_time >= update_interval:
                    last_update_time = now
                    preview_parts = ["⚡ <b>Antigravity SDK 处理中...</b>"]
                    if tool_events:
                        preview_parts.append(tool_events[-1])
                    if output_text:
                        recent_text = "".join(output_text)[-200:].strip()
                        if recent_text:
                            preview_parts.append(f"\n{html_mod.escape(recent_text)}...")
                    elif thoughts:
                        recent_thought = "".join(thoughts)[-150:].strip()
                        if recent_thought:
                            preview_parts.append(f"\n💭 <i>{html_mod.escape(recent_thought)}...</i>")

                    await tg.edit_message(chat_id, status_msg_id, "\n".join(preview_parts))

            # Final response construction
            final_body = "".join(output_text).strip()
            final_html_body = md_to_html(final_body) if final_body else "<i>(任务执行完成，无文本输出)</i>"

            # Construct header with expandable thinking & tools
            header_parts = []
            if thoughts or tool_events:
                full_thoughts = "".join(thoughts).strip()
                thought_block = f"💭 思考:\n{html_mod.escape(full_thoughts[:800])}" if full_thoughts else ""
                tools_block = "\n".join(tool_events[-10:]) if tool_events else ""
                combined_meta = f"{thought_block}\n\n{tools_block}".strip()
                if combined_meta:
                    header_parts.append(f"<blockquote expandable><b>🧠 思考与调用过程:</b>\n{combined_meta}</blockquote>\n\n")

            full_final_msg = "".join(header_parts) + final_html_body

            # Telegram limit check (4096 chars)
            if len(full_final_msg) <= 4000:
                await tg.edit_message(chat_id, status_msg_id, full_final_msg)
            else:
                # If too long, edit first message with header and prefix, then send remainder
                await tg.edit_message(chat_id, status_msg_id, full_final_msg[:3800] + "...")
                remaining = full_final_msg[3800:]
                while remaining:
                    chunk = remaining[:3800]
                    remaining = remaining[3800:]
                    await tg.send_message(chat_id, chunk)

    except Exception as e:
        logger.exception(f"Error executing agent task: {e}")
        await tg.edit_message(
            chat_id,
            status_msg_id,
            f"❌ <b>执行出错:</b>\n<code>{html_mod.escape(str(e))}</code>",
        )

# -----------------------------------------------------------------------------
# Main Polling Loop
# -----------------------------------------------------------------------------
async def main():
    global GEMINI_API_KEY, MODEL_TARGET
    if not BOT_TOKEN:
        logger.error("AGY_SDK_BOT_TOKEN is not configured! Please set it in .env.")
        sys.exit(1)

    load_state()

    logger.info("Starting Antigravity SDK Telegram Bridge...")
    logger.info(f"Allowed Chats: {ALLOWED_CHATS if ALLOWED_CHATS else 'ALL (Warning: public)'}")
    logger.info(f"Workspace: {WORKDIR}")
    logger.info(f"Model: {MODEL_TARGET or 'Default (gemini-2.5-flash)'}")

    async with aiohttp.ClientSession() as session:
        tg = TelegramClient(session)

        # Register bot commands
        commands = [
            {"command": "new", "description": "开启新会话 (清空当前上下文)"},
            {"command": "status", "description": "查看当前 SDK 桥状态与会话 ID"},
            {"command": "key", "description": "设置/更新 Gemini API Key (/key AIza...)"},
            {"command": "model", "description": "切换模型 (/model gemini-2.5-pro)"},
            {"command": "help", "description": "查看使用帮助"},
        ]
        await tg.api_call("setMyCommands", {"commands": commands})

        offset = 0
        while True:
            try:
                updates = await tg.api_call("getUpdates", {"offset": offset, "timeout": 20})
                if updates and updates.get("ok"):
                    for item in updates.get("result", []):
                        offset = item["update_id"] + 1
                        msg = item.get("message")
                        if not msg:
                            continue

                        chat_id = msg["chat"]["id"]
                        if ALLOWED_CHATS and chat_id not in ALLOWED_CHATS:
                            logger.warning(f"Blocked unauthorized message from chat {chat_id}")
                            continue

                        text = msg.get("text", "").strip()
                        msg_id = msg.get("message_id")

                        if not text:
                            continue

                        if text == "/start" or text == "/help":
                            key_status = "✅ 已配置" if GEMINI_API_KEY else "⚠️ 未配置 (请使用 <code>/key AIza...</code> 设置)"
                            help_text = (
                                "🤖 <b>Google Antigravity Python SDK 实验桥 (反重力头马)</b>\n\n"
                                "本机器人基于官方 <code>google-antigravity</code> Python SDK 构建，"
                                "采用内置原生 <code>localharness</code> 运行时驱动。\n\n"
                                f"• API 密钥状态: {key_status}\n"
                                f"• 当前模型: <code>{MODEL_TARGET or 'gemini-2.5-flash (默认)'}</code>\n"
                                f"• 会话 ID: <code>{chat_sessions.get(chat_id) or '无 (新会话)'}</code>\n\n"
                                "<b>可用指令:</b>\n"
                                "• <code>/key &lt;AIza...&gt;</code> - 配置或更新 Gemini API 密钥\n"
                                "• <code>/model &lt;name&gt;</code> - 切换模型 (如 gemini-2.5-pro, gemini-2.5-flash)\n"
                                "• <code>/new</code> - 开启全新会话\n"
                                "• <code>/status</code> - 查询当前会话与运行时状态\n"
                                "• <code>/help</code> - 显示帮助信息\n\n"
                                "直接发送文字即可发起多步骤智能体任务！"
                            )
                            await tg.send_message(chat_id, help_text, reply_to=msg_id)
                            continue

                        if text.startswith("/key"):
                            parts = text.split(maxsplit=1)
                            if len(parts) < 2 or not parts[1].strip():
                                await tg.send_message(
                                    chat_id,
                                    "用法: <code>/key AIzaSy...</code>\n从 https://aistudio.google.com/ 获取 API Key 后在此设置。",
                                    reply_to=msg_id,
                                )
                            else:
                                new_k = parts[1].strip()
                                GEMINI_API_KEY = new_k
                                os.environ["GEMINI_API_KEY"] = new_k
                                update_env_file("GEMINI_API_KEY", new_k)
                                masked = new_k[:6] + "..." + new_k[-4:] if len(new_k) > 10 else "***"
                                await tg.send_message(
                                    chat_id,
                                    f"✅ <b>Gemini API Key 已成功保存！</b>\n当前 Key: <code>{masked}</code>\n现在您可以直接发送任务给我了！",
                                    reply_to=msg_id,
                                )
                            continue

                        if text.startswith("/model"):
                            parts = text.split(maxsplit=1)
                            if len(parts) < 2 or not parts[1].strip():
                                await tg.send_message(
                                    chat_id,
                                    f"当前模型: <code>{MODEL_TARGET or 'gemini-2.5-flash (默认)'}</code>\n\n"
                                    "切换模型用法: <code>/model &lt;模型名称&gt;</code>\n"
                                    "例如:\n"
                                    "• <code>/model gemini-2.5-pro</code>\n"
                                    "• <code>/model gemini-2.5-flash</code>\n"
                                    "• <code>/model default</code> (恢复默认)",
                                    reply_to=msg_id,
                                )
                            else:
                                new_m = parts[1].strip()
                                if new_m.lower() in ("default", "none", "reset"):
                                    MODEL_TARGET = "gemini-2.5-flash"
                                    update_env_file("AGY_SDK_MODEL", "gemini-2.5-flash")
                                    await tg.send_message(chat_id, "✅ 已恢复默认模型: <code>gemini-2.5-flash</code>", reply_to=msg_id)
                                else:
                                    MODEL_TARGET = new_m
                                    update_env_file("AGY_SDK_MODEL", new_m)
                                    await tg.send_message(chat_id, f"✅ 模型已切换为: <code>{new_m}</code>", reply_to=msg_id)
                            continue

                        if text == "/new":
                            chat_sessions[chat_id] = None
                            save_state()
                            await tg.send_message(chat_id, "✨ 已为您开启全新会话上下文。", reply_to=msg_id)
                            continue

                        if text == "/status":
                            cid = chat_sessions.get(chat_id) or "无 (新对话)"
                            status_text = (
                                "📊 <b>Antigravity SDK 状态:</b>\n"
                                f"• 会话 ID: <code>{cid}</code>\n"
                                f"• 模型: <code>{MODEL_TARGET or '默认 (gemini-2.5-flash)'}</code>\n"
                                f"• 工作区: <code>{WORKDIR}</code>\n"
                                f"• 认证方式: <code>Gemini Developer API</code>"
                            )
                            await tg.send_message(chat_id, status_text, reply_to=msg_id)
                            continue

                        # Execute agent task in background asyncio task
                        asyncio.create_task(execute_agent_task(tg, chat_id, text, msg_id))

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Polling loop exception: {e}")
                await asyncio.sleep(3)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Antigravity SDK Bridge stopped.")
