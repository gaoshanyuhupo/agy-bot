#!/usr/bin/env bash
set -euo pipefail
export PATH="${HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin"

# Strip ambient proxy variables so cloudflared connects directly to Cloudflare edge
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY FTP_PROXY SOCKS_PROXY http_proxy https_proxy all_proxy ftp_proxy socks_proxy
export NO_PROXY="*"
export no_proxy="*"

ENV_FILE="${LIVE_BROWSER_TUNNEL_ENV:-${HOME}/.config/agy-live-browser/tunnel.env}"
if [[ -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
fi

TUNNEL_TOKEN="${TUNNEL_TOKEN:-${CLOUDFLARE_TUNNEL_TOKEN:-}}"
if [[ -z "${TUNNEL_TOKEN}" && -n "${TUNNEL_SECRET_REF:-}" ]]; then
  SECRET_CLI="${TUNNEL_SECRET_CLI:-$(command -v bao || true)}"
  if [[ -n "${SECRET_CLI}" && -x "${SECRET_CLI}" ]]; then
    TUNNEL_TOKEN="$("${SECRET_CLI}" get "${TUNNEL_SECRET_REF}" --field "${TUNNEL_SECRET_FIELD:-api_key}")"
  fi
fi

if [[ -z "${TUNNEL_TOKEN}" ]]; then
  echo "ERROR: Missing TUNNEL_TOKEN (set CLOUDFLARE_TUNNEL_TOKEN or configure ${ENV_FILE})" >&2
  exit 1
fi
export TUNNEL_TOKEN

exec /usr/local/bin/cloudflared tunnel --no-autoupdate --protocol http2 run
