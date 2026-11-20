---
name: dev-qa-contract
description: >-
  Structured Dev-QA fasttrack workflow for multi-agent feature delivery.
  Use before coding non-trivial features, authoring Shift-Left QA pre-flight contracts,
  classifying MVP-Preview vs Prod-Release blockers, or running scoped Re-QA and verify_gate.py.
---

# Dev↔QA Fasttrack Contract (`dev-qa-contract`)

Converges Coordinator → Dev → Independent QA cycles within **1–2 rounds** via upfront acceptance contracts, explicit two-tier release gates, diff-scoped re-verification, and a single verification CLI.

## 1. End-to-End Fasttrack Workflow

1. **Declare Gate Tier (Coordinator)**
   - Stamp every dispatch brief with **`Gate Tier: MVP-Preview`** (default for prototypes / direction checks) or **`Gate Tier: Prod-Release`** (mandatory before public exposure, hardening, or public repo sync).
2. **Shift-Left QA Pre-Flight Contract (QA, ≤ 2 min)**
   - For features touching auth, WebSocket/proxy, public HTTP endpoints, state concurrency, or >1 module, QA produces **5–8 concrete must-pass counterexamples** using [references/contract-template.md](./references/contract-template.md) before Dev writes code.
   - Coordinator embeds the contract verbatim into the Dev brief.
3. **Contract-Driven Build & Self-Proof (Dev)**
   - Read [references/web-auth-ws-pitfalls.md](./references/web-auth-ws-pitfalls.md) before implementing HTTP/Auth/WS/Proxy/Canvas/Telemetry/Audit code.
   - Implement the feature plus unit tests covering every contract item `C1..Cn`.
   - Run the scoped single-command gate (`scripts/verify_gate.py`) and attach the pass receipt + per-item test mapping to the handoff.
4. **Tiered QA & Scoped Incremental Re-QA (QA)**
   - **Round 1**: Block (`NO-GO`) strictly according to the declared `Gate Tier`. In `MVP-Preview`, log defense-in-depth edge cases under `## Follow-up (Prod-Release Backlog)` rather than blocking preview launch.
   - **Round ≥ 2 (Scoped Re-QA)**: Inspect **ONLY** `git diff <prev_qa_sha>..HEAD` (or working-tree diff) plus previously failed `Cx` items unless the diff modifies shared auth/session primitives. Never re-audit untouched modules or introduce brand-new P2 blockers mid-loop.

## 2. Two-Tier Gate Matrix

| Issue Class | `MVP-Preview` | `Prod-Release` |
|---|---|---|
| Auth/RBAC bypass, privilege escalation, CSWSH, cross-tenant data exposure | **BLOCK (P0)** | **BLOCK (P0)** |
| Real credential/secret leak, `audit-secrets` > 0, plaintext token in access logs/URLs | **BLOCK (P0)** | **BLOCK (P0)** |
| Live daemon regression, broken build/core flow, unauthorized edit to protected files (`google_browser.py`, `static/index.html`) | **BLOCK (P0)** | **BLOCK (P0)** |
| Defense-in-depth edge cases (sub-ms micro-races with 0 data leak, rare URL/header corner cases, synthetic audit corners, polish) | **Follow-up (non-blocking)** | **BLOCK (P1)** or explicit human risk sign-off |

## 3. Unified Verification Gate Command

Run before every Dev handoff and QA sign-off:

```bash
python3 scripts/verify_gate.py --scope studio [--tier mvp|prod] [--no-build] [--json]
python3 scripts/verify_gate.py --scope browser [--json]
python3 scripts/verify_gate.py --scope bridge [--json]
python3 scripts/verify_gate.py --scope security [--json]
python3 scripts/verify_gate.py --scope all [--tier prod] [--json]
```

What `verify_gate.py` checks atomically with zero repo pollution:
1. `py_compile` into a `TemporaryDirectory` (dual Python with camoufox venv when applicable).
2. `ruff check --select F401,F821` (auto-detected when installed).
3. Offline `webui` TypeScript + Vite build (`studio`/`all`, auto-skipped in `mvp` when `webui/` is clean or `--no-build`).
4. Scoped `unittest` runs with the `NoRealBrowser` import hook blocking real `camoufox`/`playwright` launches.
5. `python3 scripts/sync_live.py audit-secrets --json` (must exit `0` with `0` findings).
6. `git diff --check` + protected-file guard (`google_browser.py`, `static/index.html`).

## 4. Reference Manuals (Load On Demand)

- Pre-Flight Contract, Handoff Receipt & Scoped Re-QA Templates:
  [references/contract-template.md](./references/contract-template.md)
- Recurring Web / Auth / WebSocket / Canvas / Telemetry / Audit Pitfall Checklist:
  [references/web-auth-ws-pitfalls.md](./references/web-auth-ws-pitfalls.md)
