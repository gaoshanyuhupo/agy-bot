# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, credential leak, or authorization bypass in `agy-bot`, please report it responsibly:

- **Do NOT post live tokens, chat IDs, private keys, or internal hostnames in public issues or pull requests.**
- Use GitHub **Private Vulnerability Reporting** (Security Advisories) on `https://github.com/gaoshanyuhupo/agy-bot` when available, or open a minimal sanitized issue requesting a private channel.

---

## Built-In Security Architecture

1. **Fail-Closed Authorization (`bridge/bridge.py`)**:
   - When `AGY_TG_ALLOWED_CHATS` (and `AGY_TG_ALLOWED_USERS` where applicable) is empty, all incoming Telegram updates and bus deliveries are rejected by default.
   - Never run the bridge with unauthenticated public chat allowlists.
2. **Out-of-Tree `chmod 600` Secret Storage**:
   - Store `AGY_TG_BOT_TOKEN`, STT keys, and Cloudflare Tunnel tokens outside the Git repository (e.g. `$HOME/agy-tg-bridge/.env` with `chmod 600` or `$HOME/.config/agy-live-browser/tunnel.env`).
   - `agy-bot setup` creates `.env` with `0600` permissions and never overwrites an existing `.env` unless `--force` is explicitly provided.
3. **Single-Instance `flock` & Child FD Isolation**:
   - Each bridge poller acquires an exclusive `fcntl.flock` lock on a SHA-256-hashed lock filename (never exposing the raw bot token in paths or lock contents) marked `FD_CLOEXEC` so spawned subprocesses cannot inherit the poller lock across `os.execv` or shell invocations.
4. **Process-Group & Systemd Hygiene**:
   - Example systemd units in `systemd/examples/` enforce `KillMode=mixed` and `YOUR_USER` placeholders instead of hardcoded usernames.
5. **Automated Desensitization Gate (`scripts/security_audit.py`)**:
   - CI and local pre-commit checks enforce `--mode public-release --check-history`, blocking raw tokens, masked prefixes, credentialed URLs, non-allowlisted domains/handles, numeric/hex/UUID IDs, and hardcoded `/home/<user>` paths across both working tree and full Git commit history.
   - Never execute or commit unverified third-party scripts or untrusted secrets.
