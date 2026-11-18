# agy-bot

[English](./README.md) | [简体中文](./README.zh-CN.md)

Open-source companion stack built natively on the **official Google Antigravity CLI (`agy`)**—connecting directly to local persistent `agy` `stream-json` sessions (avoiding third-party reverse-proxy ban risks):
- **Telegram Group Multi-Bot Team Collaboration**: `sendMessageDraft` real-time streaming, group anti-429 adaptive fallback, `acb-team` async delegation, and optional Git Worktree (`worktree: true`) concurrent isolation.
- **Multi-Fingerprint, Multi-Egress Camoufox Browser & Telegram Mini App Takeover**: Named profiles with per-profile OS, viewport, WebGL, WebRTC/GeoIP, and proxy egress switching to isolate tasks and handle strict anti-bot checks (such as Cloudflare challenges), while supporting locked persistent fingerprints + direct host egress for core accounts; 1-click Telegram Mini App human takeover lets you resolve interactive challenges and hand control back to AI.
- **Cross-Session Anti-Forgetting & Managed Ops**: Lossless `/compact` transcript rehydration, stateless local observer LLM shim, Continuous-Learning v2, `mem-search`, `/undo`/`/redo`, `/schedule`/`/cron`, `/project`, `/usage`/`/cost`, `agy-bot setup/doctor --fix` self-healing, and zero-downtime hot reload.
- **Zero-Trace OpenBao Secret Ops & Automated Desensitization Gate**: Sanitized [OpenBao Zero-Trace Secret Ops Guide](./docs/OPENBAO_SECRETOPS_GUIDE.md) paired with structural working-tree + Git history auditing and a Python 3.11–3.14 CI matrix.

- **License**: [MIT](./LICENSE)
- **Repository**: `https://github.com/gaoshanyuhupo/agy-bot`
- **Community**: [LINUX.DO](https://linux.do/)
- **Security Policy**: [SECURITY.md](./SECURITY.md) · **Contributing**: [CONTRIBUTING.md](./CONTRIBUTING.md)

![agy-bot System Architecture](./docs/images/architecture.svg)

---

## Architecture & Core Components

### 1. `bridge/` — Real-Time Multi-Bot Telegram Bridge v3 (`bridge.py`, `cli.py`)
- **Native `sendMessageDraft` Streaming + Group Anti-429 Fallback**: Instant *"Thinking…"* bubble, native Telegram Stop button support, event-driven tool/thought updates, animated token streaming, and adaptive backoff + final coalesced fallback for group chats.
- **Warm Persistent `stream-json` Session Pool**: Maintains persistent `agy --input-format stream-json --output-format stream-json` processes with idle TTL reaping and instant cancellation.
- **Project & Workspace Switcher (`/project`)**: Switches cleanly between registered Antigravity CLI projects (`~/.gemini/config/projects/*.json`) with automatic session resume.
- **Usage & Cost Telemetry (`/usage`, `/cost`)**: Splits cloud quota monitoring (`/usage`) from local transcript token, prefix-cache hit rate, and API USD accounting (`/cost`).
- **Scheduled Tasks Engine (`/schedule` / `/cron`)**: Supports 5-field cron expressions and relative timers (`in 30m` / `10分钟`) with shell/script/agent/keepalive job types and Telegram inline controls.
- **Content-Addressed Workspace Undo/Redo (`/undo`, `/redo`)**: Captures pre/post turn workspace snapshots with external-edit conflict protection and atomic rollback/replay.
- **Smart Auto-Compact & Recovery**: Configurable auto-compaction (`/compact`, `/context`) plus automatic retry/recovery on transient errors.
- **Multi-Bot Concurrency & Coordinator Bus (`bot_bus.py`, `bot_bus_mcp.py`)**: Per-instance media outbox isolation, `fcntl.flock` atomic media claim locking + per-bot poller `flock` (`FD_CLOEXEC`) across concurrent bots (`@bot_one`, `@bot_two`), stdio MCP delegation tools (`acb-team`), and optional `worktree: true` Git worktree isolation on `team_dispatch` (`<repo>/.worktrees/<job_id>` on branch `agy-team/<job_id>`, `.git/info/exclude` zero-pollution exclusion, auto-pruning clean no-op worktrees, and post-review cleanup via `team_job(action="cleanup_worktree")`).
- **Setup & Diagnostics CLI (`agy-bot setup` / `agy-bot doctor`)**: PEP 621 packaged CLI (`pyproject.toml`) for safe out-of-tree runtime bootstrapping and offline/online environment verification.
- **Zero-Downtime Hot Reload**: Sentinel-file triggered (`AGY_TG_RELOAD_FILE`, e.g. `/tmp/agy_bridge_reload`) graceful `os.execv` reload between turns.

### 2. `.agents/skills/live-browser/` — Multi-Fingerprint Live Browser & Telegram Takeover
- **Dual-Mode Live Mirroring**: In-chat `editMessageMedia` single-photo Live Card plus a low-latency binary JPEG WebSocket stream inside a Telegram Mini App (`https://live.your-domain.com` behind Cloudflare Tunnel).
- **Multi-Fingerprint & Multi-Egress Profiles (`--profile`, `--os`, `--proxy-bao`)**: Manage isolated named profiles in `~/.config/agy-live-browser/profiles.json` (`0600`) with independent `os` (`windows`/`macos`/`linux`), `locale`, `window`, `webgl_config`, `block_webrtc`, `geoip`, `--ephemeral` temp contexts, and per-profile `--proxy` or memory-only OpenBao `--proxy-bao` egress—masking credentials (`socks5://***@example.com:1080`) in all status/card outputs.
- **Pinned Persistent Profile Hard-Lock**: When a host-pinned profile module is installed, `default` stays fail-closed locked to its persistent fingerprint (`os="windows"`, `headless="virtual"`) and direct host egress (`network.proxy.type=0`), rejecting any proxy or fingerprint override.
- **3-State Control Arbitration**: Switch cleanly between AI observation, 1-click human takeover (pausing AI via `ai_allowed_event` to resolve interactive verifications or Cloudflare challenges), and handing control back to AI from the updated DOM state.
- **Mobile/Desktop Input & X11 Clipboard Sync**: Auto-popping `visualViewport`-safe CJK/IME input sheet for focused inputs, external `xclip` clipboard reading, and character-exact finger drag-to-select (`document.caretPositionFromPoint`).
- **Quick CLI**:
  ```bash
  live-browser profile create us-work --os macos --locale en-US --window 1440x900 --block-webrtc --geoip --proxy-bao kv/proxies/us-west
  live-browser start --profile us-work --restart --url "https://example.com"
  ```
- Full operator & mobile guide: [docs/TELEGRAM_LIVE_BROWSER_GUIDE.md](./docs/TELEGRAM_LIVE_BROWSER_GUIDE.md).

### 3. `hooks/` — Lossless Post-Compact Rehydration & Lifecycle Hooks
- **`rehydrate_after_compact.py` (`PreInvocation`)**: Detects `/compact` checkpoints in `transcript_full.jsonl` (including `/fork` ancestry) and restores a concise verbatim request timeline, recent dialogue, and a path+size `read_file` index.
- **`claude_mem_hook_gate.py` & `hooks.json`**: Unified lifecycle hook gate (`SessionStart`, `PreInvocation`, `Stop`) guarded by `AGY_INTERNAL_OBSERVER=1` to short-circuit observer recursion, slash commands, and trivial zero-tool steps.

### 4. `mem-hub/` — Local Observer LLM Shim & Continuous-Learning v2 Daemon
- **`agy_llm_shim.py`**: Local OpenAI/Anthropic-compatible HTTP shim backed by an isolated tool-free `pure-llm` agent (`mem-hub/observer-sandbox/`) with clean stateless session rotation.
- **`agy_instinct_daemon.py`**: Extracts session instincts with confidence scoring, updates `.agents/rules/ecc-active-instincts.md`, and evolves non-redundant instincts into capped reusable skills.

### 5. `scripts/`, `tests/` & `docs/OPENBAO_SECRETOPS_GUIDE.md` — Zero-Trace Secret Ops, Desensitization Gate & Cost Accounting
- **Self-Hosted OpenBao Zero-Trace Secret Guide**: Fully sanitized patterns for `0600` local Vault credentials, ephemeral CLI env injection, in-memory Python helpers, and disk-free `live-browser --proxy-bao` egress in [docs/OPENBAO_SECRETOPS_GUIDE.md](./docs/OPENBAO_SECRETOPS_GUIDE.md).
- **`scripts/security_audit.py`**: Zero-leak structural scanner covering raw API keys/tokens, half-masked prefixes, credentialed URLs, unallowlisted external endpoints/domains, numeric/hex/UUID IDs, emails/`@handles`, hardcoded `/home/<user>` or `User=` paths, non-doc IPs, forbidden runtime files, and Git commit history (`--check-history`). Supports optional external blocklists (`--blocklist-file` / `~/.config/agy-audit-blocklist.txt`).
- **`tests/`**: Automated `unittest` suite covering desensitization boundaries (`test_desensitization.py`), P0 hardening (`test_bridge_p0.py`), core bridge subsystems (`test_bridge_core.py`), cron scheduler (`test_scheduler.py`), CLI diagnostics (`test_cli_doctor.py`), live-browser multi-fingerprint/pinned-profile isolation (`test_live_browser_profiles.py`), and multi-bot team bus & worktree isolation (`test_bot_bus.py`, `test_bot_bus_worktree.py`, `test_group_chat_bus.py`).
- **`scripts/calc_cycle_cost.py`**: Standalone CLI calculator reading `~/.gemini/antigravity-cli/brain/*/logs/transcript.jsonl` to report token totals, cache hit rate, and estimated API USD savings.

---

## Repository Layout

```text
agy-bot/
├── .agents/                  # Shared skills (live-browser, continuous-learning-v2, altare, mem-search) & workflows
├── .github/                  # CI workflows, Issue forms, and PR desensitization checklist
├── bridge/                   # Telegram Bridge v3 (bridge.py, scheduler.py, bot_bus*.py, cli.py, .env.example)
├── config/                   # Sanitized MCP configuration template (mcp_config.example.json)
├── docs/                     # Architecture diagram, Live Browser guide & OpenBao zero-trace secret guide
├── hooks/                    # hooks.json + lossless rehydrate_after_compact.py + hook gate
├── legacy/sdk-bridge/        # Historical SDK bridge v1 reference
├── mem-hub/                  # agy_llm_shim.py, agy_instinct_daemon.py, and isolated observer-sandbox/
├── scripts/                  # security_audit.py and standalone calc_cycle_cost.py
├── systemd/examples/         # Generic systemd unit templates (KillMode=mixed, YOUR_USER placeholders)
├── tests/                    # Automated desensitization, bridge, scheduler, CLI, live-browser & team-bus tests
├── workspace/                # Shared workspace agent delivery guidelines (AGENTS.md)
├── pyproject.toml            # PEP 621 package metadata, `agy-bot` CLI script & Ruff lint config
├── README.md / README.zh-CN.md
├── SECURITY.md / CONTRIBUTING.md
└── LICENSE
```

---

## Quickstart

### 1. Clone, Install CLI & Bootstrap Runtime Directory

```bash
git clone https://github.com/gaoshanyuhupo/agy-bot.git
cd agy-bot

python3 -m venv "$HOME/agy-tg-bridge/venv"
"$HOME/agy-tg-bridge/venv/bin/pip" install -e .

# Bootstrap runtime files & .env (chmod 0600, never overwrites an existing .env without --force):
"$HOME/agy-tg-bridge/venv/bin/agy-bot" setup --target-dir "$HOME/agy-tg-bridge"
```

Or copy the runtime files manually outside the git working tree (`chmod 600` for `.env`):

```bash
mkdir -p "$HOME/agy-tg-bridge"
cp bridge/bridge.py bridge/scheduler.py bridge/bot_bus.py bridge/bot_bus_mcp.py "$HOME/agy-tg-bridge/"
cp bridge/.env.example "$HOME/agy-tg-bridge/.env"
chmod 600 "$HOME/agy-tg-bridge/.env"
# Edit $HOME/agy-tg-bridge/.env with your Telegram BotFather token and allowed chat ID(s)
```

Copy & adapt [config/mcp_config.example.json](./config/mcp_config.example.json) to `~/.gemini/antigravity-cli/mcp_config.json`, replacing `YOUR_USER` and placeholder tokens.

### 2. Run Environment Health Checks & Launch

```bash
# Offline read-only diagnostics (add --fix to tighten .env to 0600 & create missing dirs, or --online to verify Telegram getMe):
"$HOME/agy-tg-bridge/venv/bin/agy-bot" doctor --env-file "$HOME/agy-tg-bridge/.env"

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

Generic unit templates are in [`systemd/examples/`](./systemd/examples) with `KillMode=mixed` (preserving child processes gracefully while cleaning up cleanly). Replace `YOUR_USER` with your Linux username before installing into `/etc/systemd/system/` or `~/.config/systemd/user/`.

### 4. Run Desensitization Audit, Lint & Tests

```bash
# Strict audit across working tree + full Git history
python3 scripts/security_audit.py --mode public-release --check-history

# Lint check (optional dev dependency: pip install -e ".[dev]")
ruff check .

# Run full desensitization & runtime test suite
python3 -m unittest discover -s tests -v
```

---

## Acknowledgements & Design References

`agy-bot` builds upon and draws architectural inspiration from several outstanding open-source projects:

### Memory Management & Continuous Learning
- [`thedotmack/claude-mem`](https://github.com/thedotmack/claude-mem): Cross-session persistent memory and the 3-step `mem-search` retrieval workflow (`search → timeline → get_observations`); `hooks/claude_mem_hook_gate.py`, `hooks/hooks.json`, and `mem-hub/agy_llm_shim.py` implement recursion-free `agy` adaptation for its lifecycle and observer pipeline.
- [`affaan-m/ECC`](https://github.com/affaan-m/ECC) (Everything Claude Code, and the *Homunculus* architecture it references): `.agents/skills/continuous-learning-v2/` (`origin: ECC`) and `mem-hub/agy_instinct_daemon.py` draw on its atomic instinct observation, confidence scoring, project-scoped isolation, and skill evolution pipeline.
- [`NousResearch/hermes-agent`](https://github.com/NousResearch/hermes-agent) & [`HKUDS/nanobot`](https://github.com/HKUDS/nanobot): Inspired prefix-cache-friendly frozen ruleset boundaries (avoiding dynamic injection that busts prompt prefix caches), on-demand/background memory consolidation ideas, and multi-agent collaborative workspace isolation.

### Telegram Bridge, HITL & Ops
- [`banteg/takopi`](https://github.com/banteg/takopi): Single-instance `flock` anti-`409` conflict guard, `pyproject.toml` + `setup`/`doctor` CLI onboarding wizard, offline mock-Telegram unit testing pattern, and Python 3.11–3.14 + `ruff` CI matrix design.
- [`overwirehq/claude-code-telegram`](https://github.com/overwirehq/claude-code-telegram): Reference comparison for `sendMessageDraft` streaming boundaries, `SECURITY.md`, and community security governance practices.
- [`grinev/opencode-telegram-bot`](https://github.com/grinev/opencode-telegram-bot): Reference for Telegram HTML chunking with robust code-block fence re-closing and human-in-the-loop tool-approval UI planning.
- [`openclaw/openclaw`](https://github.com/openclaw/openclaw): Multimodal routing patterns for video/sticker/media-group messages and long-polling backoff self-healing discipline.
- [`chenhg5/cc-connect`](https://github.com/chenhg5/cc-connect): Lightweight quickstart documentation structure, multi-channel bridging ideas, and on-demand task scheduling references.
- [`emreturkmencom/antigravity-telegram-suite`](https://github.com/emreturkmencom/antigravity-telegram-suite) & [`pavel-molyanov/telegram-ai-agent`](https://github.com/pavel-molyanov/telegram-ai-agent): Pioneering Antigravity / AI CLI Telegram bridge projects in the same domain.

---

## Community & Friendly Links

- **[LINUX.DO](https://linux.do/)** — Friendly community link for engineering discussions, technical exchange, and open-source tool sharing.

