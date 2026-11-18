---
name: evolved-telegram-bridge-ops
description: "When managing, configuring, or debugging multi-agent Telegram bridge daemons, hot-reloading prompt rules, or isolating media outputs across bots"
---

# Telegram Bridge Operations and Multi-Agent Isolation

## Overview
Operational standards for maintaining multi-agent Telegram bridge daemons sharing workspaces. Covers zero-downtime hot-reloading of agent skills/rules and strict media isolation across concurrent bots.

## Zero-Downtime Hot Reloading
When updating agent skills, system rules, or memory context files:
1. Update skill manifests in `.agents/skills/<name>/SKILL.md` or rules in `.agents/rules/`.
2. Do NOT restart running bridge systemd services or processes directly, as active polling and turn contexts will terminate.
3. Touch the sentinel reload flag files in `/tmp`:
   ```bash
   touch /tmp/agy_bridge_reload /tmp/agy_bridge_sg_reload
   ```
4. Bridge daemons monitor these sentinel files and reload skills, system prompts, and memory projections on the fly.

## Media Isolation & Asset Claim Locking
In multi-bot environments operating in the same workspace, media artifacts must be strictly partitioned:
1. **Turn Context Filtering**: Verify generated media paths against the current turn transcript or tool execution outputs before queuing to Telegram.
2. **Directory Exclusions**: Exclude noise directories from media scans (e.g., `node_modules/`, `.git/`, `dist/`, `.cache/`).
3. **Atomic Claims Locking**: Use `fcntl.flock` on a shared claim registry (e.g., `IMG_CLAIMS_FILE`) before reading or transmitting an image artifact to prevent duplicate broadcasts across concurrent bots.
4. **Session Outbox**: Stage media in scoped bot outbox directories rather than root workspace directories.

## Verification & Maintenance
- Confirm bridge processes are active: `pgrep -af "bridge.py"`
- Check bridge logs after touching `/tmp/agy_bridge_*reload` to confirm state reload without dropped messages.
- Ensure claim lock files release properly after media transmission.
