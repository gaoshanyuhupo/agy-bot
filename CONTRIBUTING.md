# Contributing to `agy-bot`

Thank you for contributing to `agy-bot`! Please follow these guidelines to keep the codebase clean, portable, and strictly free of secrets or personal identifiers.

## 1. Local Development Setup

```bash
git clone https://github.com/gaoshanyuhupo/agy-bot.git
cd agy-bot

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## 2. Coding Standards & Portability

- **Python 3.11+**: Target `requires-python = ">=3.11"` (see `pyproject.toml`).
- **Dynamic Paths Only**: Always derive paths from `$HOME`, `Path.home()`, `os.path.expanduser("~")`, or environment variables (`AGY_TG_ENV_FILE`, `AGY_TG_WORKDIR`, `AGY_TG_STATE_FILE`, `AGY_TG_LOCK_DIR`). Never hardcode `/home/<user>` or personal usernames.
- **Keep `bridge/bridge.py` Standalone-Compatible**: Ensure `python3 bridge/bridge.py` and standalone copies in `$HOME/agy-tg-bridge/bridge.py` continue to run directly without requiring package installation.
- **No Side Effects on Import**: Diagnostic/utility modules such as `bridge/cli.py` and `bridge/scheduler.py` must remain safe to import in offline tests.

## 3. Required Verification Before Opening a Pull Request

Run all four checks locally and confirm zero failures:

```bash
# 1. Syntax compile check
python3 -m py_compile bridge/*.py hooks/*.py mem-hub/*.py scripts/*.py tests/*.py \
  .agents/skills/live-browser/scripts/*.py

# 2. Ruff lint check (matches [tool.ruff] in pyproject.toml)
ruff check .

# 3. Offline unit test suite
python3 -m unittest discover -s tests -v

# 4. Strict public-release + Git history desensitization audit
python3 scripts/security_audit.py --mode public-release --check-history
```

## 4. Desensitization Checklist

Before committing or pushing:
- Use only `REPLACE_WITH_*`, `YOUR_*`, `EXAMPLE_*` placeholders and RFC 2606 / RFC 5737 safe example domains (`example.com`, `your-domain.com`) and documentation IPs.
- Use only generic example chat/user IDs (`123456789`, `-1001234567890`) and generic handles (`@bot_one`, `@bot_two`, `@example_bot`).
- Ensure no `.env`, `*.token`, `*.db`, `*.pem`, or `.ruff_cache` artifacts are staged.
