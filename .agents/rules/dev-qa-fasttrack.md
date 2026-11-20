---
trigger: always_on
description: Mandatory Dev-QA fasttrack contract (Shift-Left QA, two-tier MVP/Prod gate, scoped Re-QA, single-command verify gate)
---

# Dev↔QA Fasttrack Workflow Policy

For all multi-file feature development, security-sensitive changes, or multi-agent dispatches in this workspace, follow this contract to converge Dev↔QA loops within **1–2 rounds** without relaxing core security boundaries:

1. **Explicit Gate Tier on Every Dispatch**:
   - Every dispatch brief MUST declare **`Gate Tier: MVP-Preview`** (default for new features / prototypes / direction checks) or **`Gate Tier: Prod-Release`** (mandatory before public exposure, production hardening, or public repository release).
   - Under `MVP-Preview`, ONLY true P0 defects block (`NO-GO`): real auth/RBAC bypass or cross-tenant data leak, real credential/secret leak (`audit-secrets` > 0), live service breakage, or unauthorized edits to protected files (`google_browser.py`, `static/index.html`). Defense-in-depth edge cases are logged under `Follow-up (Prod-Release Backlog)` without blocking preview launch.
   - Under `Prod-Release`, enforce full zero-tolerance red-team, concurrency/revocation race, CI/lint, and public export gates in one pass.
2. **Shift-Left QA Pre-Flight Contract (≤ 2 min)**:
   - Before implementing non-trivial features (touching auth, WebSocket/proxy, public endpoints, or >1 module), QA produces **5–8 concrete must-pass counterexamples** up front; the coordinator embeds this contract into the Dev brief before coding starts, and Dev self-verifies each item with test evidence on handoff.
3. **Scoped Incremental Re-QA (Round ≥ 2)**:
   - After a `BLOCK`, Re-QA inspects **ONLY the new incremental `git diff` plus previously failed checklist items** (unless the diff alters shared auth/session primitives). Do not re-audit untouched modules or invent new P2 edge cases mid-loop.
4. **Load Skill & Run Single-Command Gate**:
   - Load the `dev-qa-contract` skill (`.agents/skills/dev-qa-contract/SKILL.md`) for templates and the recurring Web/Auth/WS/Canvas pitfall checklist.
   - Run `python3 scripts/verify_gate.py --scope <studio|browser|bridge|security|all> [--tier mvp|prod]` before Dev handoff and before QA sign-off.
