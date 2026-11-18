# AI-INSTALL: Zero-Guesswork Deployment & Verification Guide

This document is structured for both **AI coding agents** (Antigravity CLI, Claude Code, Codex, OpenClaw) and **human operators** to install, configure, run, and verify `agy-bot` deterministically in one pass.

---

## 1. Prerequisites & Pre-Flight Checks

Verify the host satisfies the minimum runtime contract before writing any configuration:

```bash
python3 --version          # Must be >= 3.11
which agy || ls -la "$HOME/.local/bin/agy"
git --version
```

- **Python**: `>= 3.11` (stdlib `fcntl`, `sqlite3`, `zoneinfo` + `requests >= 2.31.0`).
- **Antigravity CLI (`agy`)**: installed and authenticated on the host (`$HOME/.local/bin/agy` or in `$PATH`).
- **Telegram Bot Token(s)**: obtained from BotFather (`1234567890:REPLACE_WITH_TELEGRAM_BOT_TOKEN`).
- **Allowed Chat ID(s)**: your Telegram user ID (e.g. `123456789`) or supergroup chat ID (e.g. `-1001234567890`).

---

## 2. Install Package (`agy-bot` CLI)

```bash
python3 -m venv "$HOME/agy-tg-bridge/venv"
"$HOME/agy-tg-bridge/venv/bin/pip" install --upgrade pip
"$HOME/agy-tg-bridge/venv/bin/pip" install -e .
"$HOME/agy-tg-bridge/venv/bin/agy-bot" --help
```

---

## 3. Bootstrap Configuration (`agy-bot setup`)

### Option A: Single-Bot Quickstart

Preview first (`--check-only` writes zero files):

```bash
"$HOME/agy-tg-bridge/venv/bin/agy-bot" setup \
  --target-dir "$HOME/agy-tg-bridge" \
  --non-interactive \
  --check-only
```

Initialize runtime files, `.env` (`chmod 0600`), and an optional systemd unit:

```bash
"$HOME/agy-tg-bridge/venv/bin/agy-bot" setup \
  --target-dir "$HOME/agy-tg-bridge" \
  --non-interactive \
  --allowed-chats "123456789" \
  --workdir "$HOME/agy-workspace" \
  --fallback-models "gemini-3.8-flash-high,claude-sonnet-5-5" \
  --systemd-out "$HOME/agy-tg-bridge/systemd-units"
```

### Option B: Multi-Bot Team Setup (`--bots` + `--systemd-out`)

Generate a Coordinator + Workers team sharing a single `AGY_BOT_BUS_DIR` and `AGY_TG_ALLOWED_CHATS`, with isolated `STATE_FILE` / `RELOAD_FILE` and `chmod 0600` on every `.env*` file:

```bash
"$HOME/agy-tg-bridge/venv/bin/agy-bot" setup \
  --target-dir "$HOME/agy-tg-bridge" \
  --non-interactive \
  --bots main,dev,qa \
  --roles coordinator,worker,worker \
  --allowed-chats "-1001234567890,123456789" \
  --workdir "$HOME/agy-workspace" \
  --bus-dir "$HOME/.gemini/antigravity-cli/bot-bus" \
  --fallback-models "gemini-3.8-flash-high,claude-sonnet-5-5" \
  --systemd-out "$HOME/agy-tg-bridge/systemd-units"
```

Generated artifacts:
- `$HOME/agy-tg-bridge/.env` (`AGY_TG_BOT_ROLE=coordinator`, placeholder handle `@your_bot_1` / `main`)
- `$HOME/agy-tg-bridge/.env.dev` (`AGY_TG_BOT_ROLE=worker`, placeholder handle `@your_bot_2`)
- `$HOME/agy-tg-bridge/.env.qa` (`AGY_TG_BOT_ROLE=worker`)
- `$HOME/agy-tg-bridge/systemd-units/agy-tg-bridge*.service` (`Restart=on-failure`, `NoNewPrivileges=true`, `EnvironmentFile=`)

> **Important**: `setup` never overwrites an existing `.env*` unless `--force` is passed. Replace `REPLACE_WITH_*` tokens manually or inject via your secret manager.

---

## 4. Automated Verification Gate (`agy-bot doctor`)

Run offline diagnostics and auto-fix safe directory/permission issues:

```bash
"$HOME/agy-tg-bridge/venv/bin/agy-bot" doctor \
  --env-file "$HOME/agy-tg-bridge/.env" \
  --fix \
  --json
```

Expected JSON gate checks:
- `"status": "ok"` (or `"warn"` if optional items remain)
- `"summary.fail": 0`
- `env_file` mode verified as `0o600`

After populating a real `AGY_TG_BOT_TOKEN`, verify Telegram Bot API connectivity (`getMe`):

```bash
"$HOME/agy-tg-bridge/venv/bin/agy-bot" doctor \
  --env-file "$HOME/agy-tg-bridge/.env" \
  --online \
  --json
```

---

## 5. Docker & Docker Compose Deployment

Build the non-root container image (zero `.env` files baked into image):

```bash
docker build -t agy-bot:latest .
```

Prepare runtime env files (`chmod 0600`) from `bridge/.env.example`, then launch Coordinator + Worker via `docker-compose.example.yml`:

```bash
cp bridge/.env.example .env.coordinator && chmod 0600 .env.coordinator
cp bridge/.env.example .env.worker && chmod 0600 .env.worker
# Edit .env.coordinator and .env.worker with real BOT_TOKEN and ALLOWED_CHATS
docker compose -f docker-compose.example.yml up -d
docker compose -f docker-compose.example.yml ps
```

---

## 6. Optional Feature Enablement

### A. Group / User RBAC Isolation

In your `.env*` file:

```dotenv
AGY_TG_ADMIN_USERS=123456789
AGY_TG_READONLY_USERS=987654321
AGY_TG_ALLOW_GROUP_READONLY=0
```

- `admin` users have full command/callback access.
- `readonly` guests can query `/status`, `/usage`, `/cost`, `/context`, `/browser` (view-only), and ask read-only questions in sandboxed sessions, while mutating commands (`/undo`, `/model ...`, `/browser switch ...`, `/delegate`) are blocked.

### B. Model Auto-Failover

Configure globally in `.env*`:

```dotenv
AGY_TG_FALLBACK_MODELS=gemini-3.8-flash-high,claude-sonnet-5-5
```

Or per chat/topic live inside Telegram:

```text
/model fallback gemini-3.8-flash-high,claude-sonnet-5-5
/model fallback off
```

### C. Live-Browser Multi-Fingerprint Panel (`/browser`)

1. Start the local Live-Browser daemon (listens on `127.0.0.1:18795` by default and writes `local.token` under `$HOME/.config/agy-live-browser/` with mode `0600`).
2. Optionally set `AGY_LIVE_BROWSER_URL=http://127.0.0.1:18795` and `AGY_LIVE_BROWSER_CONFIG_DIR=$HOME/.config/agy-live-browser` in the bridge `.env`.
3. Use `/browser` in Telegram to view status, inspect masked egress profiles, switch fingerprints (`🔄 切到 ...`), stop the browser, or open the Mini App in private chat (`https://` `public_url` required).

### D. Upstream Benchmark Digest (`scripts/benchmark_digest.py`)

Monitor a configurable list of benchmark repositories (non-draft releases, merged PRs, and default-branch commits) with `0o600` incremental state and zero-noise `[SILENT]` output when unchanged:

```bash
python3 scripts/benchmark_digest.py \
  --repos-file "$HOME/.gemini/antigravity-cli/cache/benchmark_repos.json" \
  --first-run-silent
```

### E. Fail-Closed GitHub Webhook Receiver (`bridge/github_webhook.py`)

Receive HMAC-SHA256 verified GitHub events on `127.0.0.1:18798` and forward filtered alerts to Bot Bus (`--notify-bot` + `--chat-id`):

```bash
python3 bridge/github_webhook.py --print-systemd
python3 bridge/github_webhook.py --check-config --bao-ref REPLACE_WITH_BAO_SECRET_PATH
```

> **Fail-Closed**: The webhook server refuses to start if `AGY_GH_WEBHOOK_SECRET`, `AGY_GH_WEBHOOK_SECRET_FILE`, and `AGY_GH_WEBHOOK_SECRET_BAO_REF` all resolve empty.

---

## 7. Secret Hygiene & Pre-Commit Audit

- **Never** commit `.env`, `.env.*`, `*.token`, `*.pem`, or real IDs/domains.
- Keep all `.env*` files at `0600`.
- When using OpenBao or another vault, store only vault path references or inject secrets at runtime.
- Run the repository security gate before committing or publishing:

```bash
python3 scripts/security_audit.py --mode public-release --json
```
