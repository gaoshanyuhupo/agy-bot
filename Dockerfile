# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/app \
    AGY_TG_WORKDIR=/app/workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 agy \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /app --shell /bin/bash agy

WORKDIR /app

# Install package dependencies from pyproject.toml without baking runtime secrets
COPY pyproject.toml README.md ./
COPY bridge ./bridge
COPY scripts/security_audit.py ./scripts/security_audit.py

RUN pip install --no-cache-dir . \
    && mkdir -p /app/workspace /app/.gemini/antigravity-cli /var/lib/agy/bot-bus \
    && chown -R agy:agy /app /var/lib/agy

USER agy

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-m", "bridge.cli", "--help"]

CMD ["python", "/app/bridge/bridge.py"]
