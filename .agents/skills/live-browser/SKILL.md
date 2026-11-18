---
name: live-browser
description: Real-time Telegram Browser Mirroring & Human-in-the-Loop Takeover (`live-browser` CLI / `agy-live-browser.service`). Streams browser frames live into Telegram via an auto-updating in-chat `editMessageMedia` Live Card + a 10 FPS Telegram Mini App WebSocket panel with 1-click AI Pause / Human Takeover control arbitration. Use whenever operating a browser interactively, when the user wants to watch browser actions in real time on Telegram, or when human confirmation / manual input takeover is needed.
---

# Live Browser (`live-browser` — Telegram Real-Time View & Human Takeover)

`live-browser` (`~/.local/bin/live-browser` -> [scripts/live_browser_ctl.py](./scripts/live_browser_ctl.py)) connects to the persistent local `agy-live-browser.service` daemon ([scripts/live_browser_server.py](./scripts/live_browser_server.py), listening on `127.0.0.1:18795`).

## Key Capabilities

1. **Dual-Mode Telegram Real-Time Visibility**:
   - **In-Chat Live Photo Card (`editMessageMedia`)**: Automatically sends a single `🔴 LIVE 浏览器实况` photo message in the active Telegram chat (`@bot_one` or `@bot_two`) and updates it in place without spamming the chat.
   - **Telegram Mini App Real-Time Stream (8–12 FPS)**: Attaches a `[🖥 打开实时画面 / 人工接管]` `web_app` button to the live card. Inside Telegram's built-in Mini App panel, the user watches real-time binary JPEG frames, cursor ripples, tabs, and URL updates.
2. **3-State Human Takeover Arbitration (`👀 观看` -> `🖐 一键接管` -> `▶️ 交还给 AI`)**:
   - When the user clicks **`🖐 一键接管`** in the Mini App (or the agent runs `live-browser wait-human`), AI actions pause cleanly (`ai_allowed_event`) while the user taps, scrolls, zooms, switches tabs, or types/pastes text.
   - **Smart Mobile & Desktop Typing**: Clicking any editable `<input>` / `<textarea>` / `[contenteditable]` on the remote canvas automatically pops up a top-aligned Floating Input Sheet (`input_focused`, immune to iOS keyboard overlap via `visualViewport`), supporting full Chinese/Unicode (`insert_text`), password masking, and 1-tap `填入并回车 ↵` / `覆盖原内容`. Desktop physical keyboards also type directly into the active browser page.
   - **Cross-System Copy-Paste (Browser -> Phone/PC System Clipboard, Notes/Notepad, `.txt`, TG)**:
     - **Zero-Fingerprint X11 Clipboard Sync**: Polls Camoufox's underlying Xvfb `DISPLAY` `CLIPBOARD` externally via `xclip -o -selection clipboard -t UTF8_STRING` without injecting any persistent JS hooks into webpages. Clicking any `[Copy]` button on a remote site (or pressing `Ctrl+C` / `Cmd+C`) immediately pops up the top `#clip-sheet` in the Mini App.
     - **Freeform Drag-to-Select & Touch Text Extraction (`🖊 选字` / `🖊 拖选文字`)**: Works in both Watch (`👀`) and Takeover (`🖐`) modes. Dragging a finger across the canvas paints exact character ranges via `document.caretPositionFromPoint` (`mode="range"` / `mode="range_preview"`) with a live top preview pill (`#live-sel-pill`), while single-tapping extracts the exact element/paragraph (`mode="point"` with container-margin guard). Users can also expand `#clip-textarea` (`🔍 放大选词`) and sub-select arbitrary words with native mobile cursor handles (`✂️ 仅复制选中的 X 个字`, blur-safe via `selectionchange`).
     - **Multi-Target Export**: 1-tap `📋 复制框内全部 / ✂️ 仅复制选中的 X 个字` (writes to iOS/Android/Windows/macOS OS-wide clipboard for pasting into Apple Notes, Notepad, WeChat, password managers), `📤 备忘录/分享` (native OS `navigator.share` sheet directly into Notes/Files), `💾 .txt` file download, or `📨 发回TG`.
   - When the user clicks **`▶️ 交还给 AI`**, AI resumes immediately from the updated DOM/page state.
3. **100% Pinned Browser Profile Compliance**:
   - Uses `AsyncCamoufox` with `google_browser.py`'s exact invariants: `flock` on the profile lockfile, `headless="virtual"`, `os="windows"`, `humanize=True`, `network.proxy.type=0`, and direct egress (`_direct_env()`).
   - Legacy scripts using `with open_google_browser() as ctx:` ALSO automatically stream frames and support interactive human takeover via `SyncLiveBridge`!
4. **Zero-Trust Security**:
   - WebSocket `/ws` requires cryptographic Telegram `WebApp.initData` HMAC-SHA256 validation against the local bot tokens plus `ALLOWED_CHATS` whitelist (e.g. `123456789`). Unauthorized visitors always receive `403 Forbidden`.

## CLI Usage

```bash
# Check daemon health, current browser mode, takeover lock, and public Mini App URL
live-browser status

# Start persistent browser session & push live card + Mini App button to current TG chat
live-browser start --url "https://myaccount.google.com"

# Multi-step browser automation (persists across CLI invocations!)
live-browser open "https://mail.google.com/mail/u/0/#inbox"
live-browser click "button[aria-label='Search mail']"
live-browser fill "input[name='q']" "from:cloudflare" --submit
live-browser wait 2000
live-browser text "body"
live-browser screenshot ~/agy-workspace/inbox.png

# Explicitly pause AI and ask user to take over in Telegram Mini App (background if long!)
live-browser wait-human --reason "请在实时面板完成二次确认后点【▶️ 交还给 AI】" --timeout 600

# Force refresh / re-send the Live Card in the current Telegram bot chat
live-browser notify --new

# Configure public HTTPS URL (e.g. Cloudflare Tunnel) for Telegram Mini App button
live-browser set-public-url "https://live.yourdomain.com"

# Close hosted browser and release the profile lock
live-browser stop
```

## Long-Waiting Takeover Rule (Telegram Bridge)

When calling `live-browser wait-human`, remember `AGENTS.md` rule #2:
- Run `live-browser wait-human ...` as a **background** command (`WaitMsBeforeAsync <= 5000`), immediately inform the user in chat that they can tap **`[🖥 打开实时画面 / 人工接管]`** on the Live Card above, and let the background command notify you automatically once the user clicks **`[▶️ 交还给 AI]`**!
