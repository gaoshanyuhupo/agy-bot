# Self-Hosted OpenBao Zero-Trace Secret Ops Guide / 自部署 OpenBao 无痕用密指南

> **Security Principle / 安全原则**：Never write plaintext API keys, Bot tokens, GitHub PATs, or proxy credentials into repository files, `.env` files inside Git, `.git/config`, or browser profile configs. Fetch short-lived or scoped secrets into process memory at runtime from a self-hosted [OpenBao](https://bao.example.com) instance (or compatible Vault KV v2 endpoint) stored under `chmod 0700`/`0600` directories outside the repository.

---

## 1. Self-Hosted OpenBao & `0600` Local Credential Bootstrap / 自部署与本地凭据初始化

Keep AppRole credentials and cached client tokens strictly outside any Git working tree (e.g. under `$HOME/.config/openbao/`):

```bash
mkdir -p "$HOME/.config/openbao"
chmod 700 "$HOME/.config/openbao"

cat <<'EOF' > "$HOME/.config/openbao/card.json"
{
  "base_url": "https://bao.example.com",
  "card_name": "example-worker-card",
  "role_id": "REPLACE_WITH_ROLE_ID",
  "secret_id": "REPLACE_WITH_SECRET_ID"
}
EOF
chmod 600 "$HOME/.config/openbao/card.json"
```

Verify connectivity and read a secret field without printing unnecessary metadata:

```bash
# Check AppRole auth & server health
bao status

# Read a single field from a KV secret path
bao get kv/services/example --field api_key

# Read full JSON payload (only when inspecting non-sensitive keys or piping in memory)
bao get kv/services/example
```

---

## 2. Ephemeral CLI Subprocess Env Injection / CLI 短暂子进程环境变量注入

Inject credentials only into the target child process environment (`VAR="$(bao get ...)" cmd`) instead of exporting globally or writing `.env` / `.git/config`:

### Git Push via `gh auth git-credential` (Zero PAT in `.git/config`)

```bash
# Ensure origin uses clean HTTPS without embedded credentials:
# git remote set-url origin https://github.com/YOUR_ORG/YOUR_REPO.git

GH_TOKEN="$(bao get kv/github/deploy --field token)" \
  git -c credential.helper='!gh auth git-credential' push origin main
```

### One-Off CLI / API Invocation

```bash
EXAMPLE_API_KEY="$(bao get kv/services/example --field api_key)" \
  your-cli-tool --endpoint https://api.example.com/v1
```

> **Tip / 提示**：Prefer command substitution directly inside the child command prefix (`VAR="$(...)" cmd`) so the secret is not retained in your parent shell environment or `~/.bashrc`.

---

## 3. In-Memory Python Secret Helper / Python 脚本内存动态提取

In automation scripts, read secrets into local variables with a timeout and never log raw stdout/stderr on failure:

```python
#!/usr/bin/env python3
"""Minimal in-memory OpenBao secret helper (zero disk writes)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any


def get_bao_secret(path: str, field: str | None = None, *, timeout: float = 15.0) -> Any:
    """Fetch a secret string (when `field` is set) or JSON dict in memory from `bao get`."""
    bao_bin = shutil.which("bao") or str(Path.home() / ".local/bin/bao")
    cmd = [bao_bin, "get", path]
    if field:
        cmd.extend(["--field", field])

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"bao get failed for {path!r} (exit={proc.returncode})")

    raw = (proc.stdout or "").strip()
    if not raw:
        raise RuntimeError(f"bao get returned empty payload for {path!r}")
    return raw if field else json.loads(raw)
```

---

## 4. `live-browser` Multi-Egress Proxy Integration / 浏览器代理凭据零落盘

Combine `live-browser` named profiles with `--proxy-bao` so proxy usernames and passwords stay exclusively in OpenBao and process memory—never saved to `~/.config/agy-live-browser/profiles.json`, Telegram Live Cards, or daemon logs.

### Step A: Store Proxy Egress Config in OpenBao

Store either a JSON object (`{"server": "socks5://proxy.example.com:1080", "username": "YOUR_PROXY_USER", "password": "YOUR_PROXY_PASS"}`) or a URL field (`url`) at e.g. `kv/proxies/us-west`:

```bash
bao set kv/proxies/us-west \
  url="socks5://YOUR_PROXY_USER:YOUR_PROXY_PASS@proxy.example.com:1080"
```

### Step B: Create & Launch a Named Profile Using `--proxy-bao`

```bash
# Create an isolated macOS fingerprint bound to an OpenBao proxy reference
live-browser profile create us-west \
  --os macos \
  --locale en-US \
  --window 1440x900 \
  --block-webrtc \
  --geoip \
  --proxy-bao kv/proxies/us-west#url

# Launch (resolves proxy credentials in memory; status & TG cards display masked egress)
live-browser start --profile us-west --url "https://example.com"
live-browser status
# -> "egress": "socks5://***@example.com:1080"
```

### Step C: Pinned Core Profile Remains Strictly Direct-Egress

When your host runs a pinned persistent account profile (via `google-profile`), omitting `--profile` or passing `--profile default` always enforces `os="windows"`, `persistent_context=True`, `network.proxy.type=0`, and direct host egress (`_direct_env()`). Any attempt to inject `--proxy` or `--proxy-bao` onto a `pinned=True` profile fails closed with `ValueError`.

---

## 5. Desensitization & CI Anti-Leak Gate / 脱敏门禁与 CI 防泄漏闭环

Pair OpenBao secret ops with `scripts/security_audit.py` so accidental plaintext tokens, credentialed URLs, real domains, or Vault-specific internal paths are blocked before commit or release:

```bash
# Audit working tree + full Git commit history in strict public-release mode
python3 scripts/security_audit.py --mode public-release --check-history

# Run full lint & offline unit tests (including OpenBao proxy-ref & masking tests)
ruff check --no-cache .
python3 -m unittest discover -s tests -v
```
