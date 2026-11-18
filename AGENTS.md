# Contributor & Agent Guidelines (`agy-bot`)

Guidelines for developing and extending `agy-bot`.

## 1. Zero-Secret & Portability Invariants

1. **Never commit credentials or personal identifiers**:
   - Store all Telegram bot tokens, API keys, Tunnel tokens, and personal chat IDs in `chmod 600` files outside the repository (e.g., `$HOME/agy-tg-bridge/.env` or `$HOME/.config/agy-live-browser/tunnel.env`) or environment variables.
   - Do not commit half-masked secret fragments (`••••` / `***`), real numeric Telegram chat/user IDs, private domain names, personal email addresses, or non-placeholder `@handles`.
2. **Dynamic Path Resolution**:
   - Derive runtime directories from `os.path.expanduser("~")`, `Path.home()`, `$HOME`, or environment variables (`AGY_REPO_DIR`, `AGY_TG_ENV_FILE`, `AGY_TG_STATE_FILE`, `AGY_SHIM_API_KEY`).
   - In examples and templates (`config/mcp_config.example.json`, `systemd/examples/*.service.example`), always use `$HOME`, `/home/YOUR_USER`, and `User=YOUR_USER`.
3. **Host-Specific Operational Skills Stay Out of Public Git**:
   - Keep account-specific credentials wrappers, private Vault helpers, and personal automation skills outside this public repository.

## 2. Verification Before Every Commit

```bash
# 1. Compile-check Python modules
python3 -m py_compile bridge/*.py hooks/*.py mem-hub/*.py scripts/*.py tests/*.py \
  .agents/skills/live-browser/scripts/*.py

# 2. Enforce strict desensitization across workspace + Git history
python3 scripts/security_audit.py --mode public-release --check-history

# 3. Run unit & runtime verification tests
python3 -m unittest discover -s tests -v
```

## 3. Telegram Media Delivery Rule

When an agent generates screenshots, charts, or QR images during a Telegram session, write them into the configured workspace outbox and share clickable `https://...` URLs directly in the chat reply rather than hiding them only inside local `file://` `.md` artifacts.
