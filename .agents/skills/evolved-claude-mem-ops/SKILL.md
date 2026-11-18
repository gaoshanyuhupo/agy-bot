---
name: evolved-claude-mem-ops
description: "Diagnose, configure, and maintain the Claude-Mem worker stack, memory hook pipeline, and headless agent setup."
---

# Claude-Mem Operations and Diagnostics

Operational guide for managing, configuring, and auditing the Claude-Mem memory stack and background services in Antigravity CLI environments.

## Headless Setup & Nag Suppression

When provisioning automated agents or running in headless/daemon environments, suppress interactive onboarding banners on `SessionStart`:

- Configure `~/.claude-mem/setup-state.json` with:
```json
{
  "status": "complete",
  "choice": "local-worker",
  "tools": ["antigravity"]
}
```
- This avoids interactive `setup=1` nag prompts from polluting session initialization context.

## Stack Health Diagnostics

Audit the status of Claude-Mem and its dependent daemons across the system:

```bash
# Verify active service units
systemctl is-active agy-llm-shim.service claude-mem-worker.service agy-instinct-daemon.service
```

### Diagnostic Checks
1. **Service Verification**: Check that `claude-mem-worker.service` and `agy-instinct-daemon.service` are active.
2. **Database Integrity**: Inspect SQLite tables in `~/.claude-mem/claude-mem.db` and review local configuration state.
3. **Hook Simulation**: Validate the context injection hook by running:
   ```bash
   echo '{"event": "SessionStart"}' | bun worker-service.cjs hook antigravity-cli context
   ```
4. **Context Rules Sync**: Verify generated rule files in `.agents/rules/` (such as `claude-mem-recent.md`) stay within concise line limits (< 30 lines) without truncating active context.
