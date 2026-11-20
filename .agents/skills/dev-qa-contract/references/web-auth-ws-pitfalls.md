# Recurring Web / Auth / WebSocket / Canvas / Audit Pitfall Checklist

Load this reference before implementing or auditing HTTP servers, reverse proxies, auth/session cookies, WebSockets, remote canvas UIs, read-only telemetry endpoints, or secret-audit patterns.

## A. Zero-Log Credentials & Third-Party SDK Isolation

1. **No Secrets in Query Strings**: Pass one-time magic-link or bootstrap tokens ONLY in `#fragment` or `POST` JSON bodies — never `?token=` (which leaks into server logs, proxies, browser history, and `Referer`).
2. **Immediate Fragment Wipe Before 3p SDKs**: Extract `#fragment` synchronously on entry and clear it via `history.replaceState` BEFORE dynamically loading any third-party script or WebApp SDK.
3. **Hardened Access Logging**: Use a custom `SanitizedAccessLogger` locking minimal log fields (strip query strings on all routes; exclude `Referer` and `User-Agent` headers; never log raw `initData`, cookies, or bearer tokens).
4. **Response Cache & Referrer Headers**: Set `Referrer-Policy: no-referrer` and `Cache-Control: no-store` on all auth, session, and private API responses. Disable link previews when delivering one-time links in chat.

## B. Public Origin, Reverse Proxy & Cookie Hardening

1. **Strict Origin Parsing**: Validate origins with a strict parser/regex rejecting paths, userinfo, and empty trailing `?`, `#`, or `:` suffixes. Compare schemes case-insensitively (`https` / `HTTPS`).
2. **Public Mode Fail-Fast & Cookie Flags**: In public mode, fail fast at startup unless the configured public origin uses `https://`. Always emit host-only `HttpOnly; Secure; SameSite=Lax` (or `__Host-`) cookies unconditionally in public mode — do NOT derive `Secure` from spoofable proxy headers.
3. **CSRF / CSWSH Origin Guard**: Enforce strict `Origin == expected_origin` checks on WebSocket upgrades and all state-changing `POST`/`PUT`/`DELETE` routes. Set explicit `Content-Security-Policy` `frame-ancestors` boundaries.
4. **Internal Route Isolation**: Never expose `/internal/*` endpoints on public routers; enforce dual verification (`loopback peer IP` + internal shared token header).

## C. WebSocket Teardown, Live RBAC Revocation & Takeover Safety

1. **Bidirectional Live Auth Check**: Re-check live session validity and RBAC on BOTH client->upstream and upstream->client TEXT/BINARY frames — never rely solely on handshake-time auth.
2. **Ordered Teardown on Revocation / Logout**: Set `closing = True` atomically, **close the upstream WebSocket first**, then perform a bounded close on the downstream socket so in-flight frames cannot leak after logout.
3. **Scoped Revocation vs. Identity Eviction**: Support both single-session logout (revoking only that `session_hash`) and full identity eviction (revoking all sessions for `(bot_key, user_id)`). Enforce `(bot_key, user_id)` ownership — role alone does not grant ownership of another user's session.
4. **Ownerless Takeover Protection**: On upstream `finally:` teardown, atomically verify under lock that the disconnecting viewer owns the named takeover before releasing control; never falsely clear an ownerless `wait-human` pause state.
5. **Async Frame Generation Guard**: Guard frontend async decode/render (`createImageBitmap`, screenshot fetches) with monotonic `connGenRef` / `frameRenderGen` counters and clear the canvas immediately on disconnect or session switch.

## D. Canvas, Mobile Touch & DPR Coordinate Source of Truth

1. **Monotonic State Generations**: Bind async frame decodes, text extracts, and tab/session switches to monotonic `(wsConnGen, frameRenderGen, session_gen, takeover_gen)`.
2. **Atomic Gesture Cancellation**: Clear active pointer/touch state (`gestureStart`, `lastTapInfo`, minimap drag) immediately upon session switch, tab change, or AI/Human takeover toggle.
3. **True Backing Ratios Over Nominal DPR**: Compute pointer-to-viewport scaling from actual backing ratios (`canvas.width / stageCssWidth`, `canvas.height / stageCssHeight`) rather than nominal `window.devicePixelRatio` after integer rounding.
4. **Multi-Touch Pinch/Pan Hygiene**: Guarantee `1 -> 2 -> 1` finger transitions never emit phantom clicks or wheel events after pinch/pan ends.

## E. Read-Only Telemetry, Secret Audit & CI Portability

1. **Strict Telemetry Allowlists**: Expose only explicit allowlisted fields; never return raw tracebacks, raw file paths, or unbounded free text. Truncate URLs to `scheme://host[:port]`, normalize timestamps to ISO-8601 UTC or `null`, and validate display labels against an explicit character allowlist.
2. **No Broad Audit Exclusions**: In `scripts/security_audit.py`, never skip whole directories or add blanket allowlists; narrow false positives using syntactic JSON/JS/CSS span awareness and pair every rule change with positive + negative regression unit tests against `HEAD`.
3. **Deterministic Monotonic Timeouts in Tests**: Never construct expired monotonic timestamps using raw `time.monotonic() - TTL` (which goes negative on fresh CI runners whose uptime `< TTL` and triggers `<= 0` sentinel checks). Mock `time.monotonic` with a fixed positive baseline instead.
4. **Live Host & Protected File Isolation**:
   - Never run `systemctl restart agy-tg-bridge*` during an active bot turn — deploy via `python3 scripts/sync_live.py deploy` to queue graceful idle `execv` hot-reloads.
   - Keep protected browser files (`google_browser.py`, `static/index.html`) untouched unless explicitly approved (`--allow-protected`) and never spawn real `camoufox`/`playwright` processes inside unit tests (`NoRealBrowser` hook).
