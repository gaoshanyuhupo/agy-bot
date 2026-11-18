# agy-bot

Open-source companion stack for **Google Antigravity CLI (`agy`)**: a real-time multi-bot Telegram bridge (`sendMessageDraft` streaming + group rate-limit protection), an interactive Telegram Mini App browser takeover & clipboard hub, lossless post-compact transcript rehydration, a stateless local observer LLM shim, Continuous-Learning v2 instinct evolution, and a strict automated desensitization test suite.

- **License**: [MIT](./LICENSE)
- **Repository**: `https://github.com/gaoshanyuhupo/agy-bot`

---

## Architecture & Core Components

### 1. `bridge/` — Real-Time Multi-Bot Telegram Bridge v3 (`bridge.py`)
- **Native `sendMessageDraft` Streaming + Group Anti-429 Fallback**: Instant *"Thinking…"* bubble, native Telegram Stop button support, event-driven tool/thought updates, animated token streaming, and adaptive backoff + final coalesced fallback for group chats.
- **Warm Persistent `stream-json` Session Pool**: Maintains persistent `agy --input-format stream-json --output-format stream-json` processes with idle TTL reaping and instant cancellation.
- **Project & Workspace Switcher (`/project`)**: Switches cleanly between registered Antigravity CLI projects (`~/.gemini/config/projects/*.json`) with automatic session resume.
- **Usage & Cost Telemetry (`/usage`, `/cost`)**: Splits cloud quota monitoring (`/usage`) from local transcript token, prefix-cache hit rate, and API USD accounting (`/cost`).
- **Scheduled Tasks Engine (`/schedule` / `/cron`)**: Supports 5-field cron expressions and relative timers (`in 30m`) with shell/script/agent/keepalive job types and Telegram inline controls.
- **Smart Auto-Compact & Recovery**: Configurable auto-compaction (`/compact`, `/context`) plus automatic retry/recovery on transient errors.
- **Multi-Bot Concurrency & Coordinator Bus (`bot_bus.py`, `bot_bus_mcp.py`)**: Per-instance media outbox isolation, `fcntl.flock` atomic media claim locking across concurrent bots (`@bot_one`, `@bot_two`), and stdio MCP delegation tools (`acb-team`).
- **Zero-Downtime Hot Reload**: Sentinel-file triggered (`AGY_TG_RELOAD_FILE`, e.g. `/tmp/agy_bridge_reload`) graceful `os.execv` reload between turns.

### 2. `.agents/skills/live-browser/` — Telegram Live Browser & Human Takeover
- **Dual-Mode Live Mirroring**: In-chat `editMessageMedia` single-photo Live Card plus a low-latency binary JPEG WebSocket stream inside a Telegram Mini App (`https://live.your-domain.com` behind Cloudflare Tunnel).
- **3-State Control Arbitration**: Switch cleanly between AI observation, 1-click human takeover (pausing AI via `ai_allowed_event`), and handing control back to AI from the updated DOM state.
- **Mobile/Desktop Input & X11 Clipboard Sync**: Auto-popping `visualViewport`-safe CJK/IME input sheet for focused inputs, external `xclip` clipboard reading, and character-exact finger drag-to-select (`document.caretPositionFromPoint`).
- Full operator & mobile guide: [docs/TELEGRAM_LIVE_BROWSER_GUIDE.md](./docs/TELEGRAM_LIVE_BROWSER_GUIDE.md).

### 3. `hooks/` — Lossless Post-Compact Rehydration & Lifecycle Hooks
- **`rehydrate_after_compact.py` (`PreInvocation`)**: Detects `/compact` checkpoints in `transcript_full.jsonl` (including `/fork` ancestry) and restores a concise verbatim request timeline, recent dialogue, and a path+size `read_file` index.
- **`claude_mem_hook_gate.py` & `hooks.json`**: Unified lifecycle hook gate (`SessionStart`, `PreInvocation`, `Stop`) guarded by `AGY_INTERNAL_OBSERVER=1` to short-circuit observer recursion, slash commands, and trivial zero-tool steps.

### 4. `mem-hub/` — Local Observer LLM Shim & Continuous-Learning v2 Daemon
- **`agy_llm_shim.py`**: Local OpenAI/Anthropic-compatible HTTP shim backed by an isolated tool-free `pure-llm` agent (`mem-hub/observer-sandbox/`) with clean stateless session rotation.
- **`agy_instinct_daemon.py`**: Extracts session instincts with confidence scoring, updates `.agents/rules/ecc-active-instincts.md`, and evolves non-redundant instincts into capped reusable skills.

### 5. `scripts/` & `tests/` — Strict Desensitization Gate & Cost Accounting
- **`scripts/security_audit.py`**: Zero-leak structural scanner covering raw API keys/tokens, half-masked prefixes, credentialed URLs, unallowlisted external endpoints/domains, numeric/hex/UUID IDs, emails/`@handles`, hardcoded `/home/<user>` or `User=` paths, non-doc IPs, forbidden runtime files, and Git commit history (`--check-history`). Supports optional external blocklists (`--blocklist-file` / `~/.config/agy-audit-blocklist.txt`).
- **`tests/test_desensitization.py`**: Automated `unittest` regression suite verifying positive secret/PII detection, allowlist boundaries, Git history rewrite hygiene, runtime `$HOME` path resolution, and repository release gates.
- **`scripts/calc_cycle_cost.py`**: Standalone CLI calculator reading `~/.gemini/antigravity-cli/brain/*/logs/transcript.jsonl` to report token totals, cache hit rate, and estimated API USD savings.

---

## Repository Layout

```text
agy-bot/
├── .agents/                  # Shared skills (live-browser, continuous-learning-v2, altare, mem-search) & workflows
├── .github/workflows/        # CI desensitization audit & unittest verification
├── bridge/                   # Telegram Bridge v3 (bridge.py, scheduler.py, bot_bus*.py, .env.example)
├── config/                   # Sanitized MCP configuration template (mcp_config.example.json)
├── docs/                     # Live Browser & Mobile input architecture guide
├── hooks/                    # hooks.json + lossless rehydrate_after_compact.py + hook gate
├── legacy/sdk-bridge/        # Historical SDK bridge v1 reference
├── mem-hub/                  # agy_llm_shim.py, agy_instinct_daemon.py, and isolated observer-sandbox/
├── scripts/                  # security_audit.py and standalone calc_cycle_cost.py
├── systemd/examples/         # Generic systemd unit templates (using YOUR_USER placeholders)
├── tests/                    # Automated desensitization & runtime regression tests
└── workspace/                # Shared workspace agent delivery guidelines (AGENTS.md)
```

---

## Quickstart

### 1. Clone & Configure Environment

```bash
git clone https://github.com/gaoshanyuhupo/agy-bot.git
cd agy-bot

# Create bridge runtime directory & config outside the git working tree (chmod 600)
mkdir -p "$HOME/agy-tg-bridge"
cp bridge/bridge.py bridge/scheduler.py bridge/bot_bus.py bridge/bot_bus_mcp.py "$HOME/agy-tg-bridge/"
cp bridge/.env.example "$HOME/agy-tg-bridge/.env"
chmod 600 "$HOME/agy-tg-bridge/.env"
# Edit $HOME/agy-tg-bridge/.env with your BotFather token and Telegram user ID
```

Copy & adapt [config/mcp_config.example.json](./config/mcp_config.example.json) to `~/.gemini/antigravity-cli/mcp_config.json`, replacing `YOUR_USER` and placeholder tokens.

### 2. Install Bridge & Optional Live-Browser Dependencies

```bash
python3 -m venv "$HOME/agy-tg-bridge/venv"
"$HOME/agy-tg-bridge/venv/bin/pip" install -r bridge/requirements.txt

# Launch manually for foreground verification (or manage via systemd in Step 3):
# AGY_TG_ENV_FILE="$HOME/agy-tg-bridge/.env" "$HOME/agy-tg-bridge/venv/bin/python" "$HOME/agy-tg-bridge/bridge.py"
```

If using `.agents/skills/live-browser/`, set your tunnel token outside git (never commit secrets):

```bash
mkdir -p "$HOME/.config/agy-live-browser"
chmod 700 "$HOME/.config/agy-live-browser"
cat <<'EOF' > "$HOME/.config/agy-live-browser/tunnel.env"
CLOUDFLARE_TUNNEL_TOKEN=REPLACE_WITH_YOUR_TUNNEL_TOKEN
EOF
chmod 600 "$HOME/.config/agy-live-browser/tunnel.env"
```

### 3. Systemd Deployment (Optional)

Generic unit templates are in [`systemd/examples/`](./systemd/examples). Replace `YOUR_USER` with your Linux username before installing into `/etc/systemd/system/` or `~/.config/systemd/user/`.

### 4. Run Desensitization Audit & Tests

```bash
# Strict audit across working tree + full Git history
python3 scripts/security_audit.py --mode public-release --check-history

# Run full desensitization & runtime regression test suite
python3 -m unittest discover -s tests -v
```
