# Dev↔QA Contract & Scoped Re-QA Templates

Use these compact templates verbatim in Coordinator dispatches, QA pre-flight reviews, Dev handoffs, and Round 2+ Re-QA receipts.

## 1. Shift-Left QA Pre-Flight Contract (QA -> Coordinator -> Dev, ≤ 2 min)

Limit to **5–8 concrete, negative/boundary counterexamples** directly relevant to the task scope:

```markdown
### QA Pre-Flight Contract
- **Gate Tier**: `MVP-Preview` | `Prod-Release`
- **Scope**: `<studio | browser | bridge | security | all>` (`<target modules/endpoints>`)
- **Gate Command**: `python3 scripts/verify_gate.py --scope <scope> --tier <mvp|prod> --json`

| ID | Boundary | Counterexample / Abuse Input | Expected Safe Outcome | Tier |
|---|---|---|---|---|
| C1 | Auth / Tenant | `<exact negative input>` | `<exact HTTP/WS status/close code>` | MVP |
| C2 | Secret / Log | `<token/cookie/fragment handling>` | `<never in query, Referer, or logs>` | MVP |
| C3 | State / Race | `<tab/session/takeover/revocation race>` | `<atomic cancel / monotonic gen drop>` | MVP/Prod |
| C4 | Safety / Isolation | `<protected files / live services untouched>` | `<0 diff on protected files, NoRealBrowser>` | MVP |

**Explicitly Out of Scope for This Tier**:
- `<deferred hardening items tracked for Prod-Release>`
```

## 2. Dev Handoff Self-Proof Receipt (Dev -> Coordinator -> QA)

```markdown
### Dev Delivery Receipt
- **Gate Tier**: `MVP-Preview` | `Prod-Release`
- **Changed Files**: `<list of modified/added files>`
- **Contract Self-Proof**:
  - [x] `C1` -> `<test_file.py::TestClass::test_case>` (PASS)
  - [x] `C2` -> `<test_file.py::TestClass::test_case>` (PASS)
  - ...
- **Unified Gate Receipt**:
  - Command: `python3 scripts/verify_gate.py --scope <scope> --tier <mvp|prod> --json`
  - Result: `ok: true` (`pass=X, fail=0, skip=Y`, `<duration>s`)
- **Deferred Follow-ups** (if any): `<none or short list>`
```

## 3. Scoped Incremental Re-QA Protocol (Round ≥ 2)

When a Round 1 QA report returns `BLOCK` with failed items `Cx, Cy`:

1. **Lock the Audit Boundary**:
   - Inspect `git diff <prev_qa_sha>..HEAD` (or current working tree diff against pre-fix snapshot).
   - Re-verify ONLY:
     - Previously failed items (`Cx`, `Cy`) and their regression unit tests;
     - Code paths directly modified by the new diff.
   - Escalate outside the diff ONLY if the remediation itself altered shared auth/session/RBAC primitives.
2. **No Moving Goalposts**:
   - Do NOT invent new `Prod-Release` polish/hardening blockers during an `MVP-Preview` fix round unless the fix itself introduced a new P0 defect.
   - Record any newly noticed non-P0 hardening ideas under `## Follow-up (Prod-Release Backlog)`.

```markdown
### Scoped Re-QA Receipt (Round <N>)
- **Gate Tier**: `MVP-Preview` | `Prod-Release`
- **Diff Window**: `<base_sha>..<head_sha>` (`<N> files changed`)
- **Previously Failed Items Re-Verified**:
  - `Cx`: **PASS** (`<evidence / test>`)
  - `Cy`: **PASS** (`<evidence / test>`)
- **Untouched Modules Excluded**: `<explicit note that unchanged modules were not re-audited>`
- **Unified Gate Verification**: `verify_gate.py --scope <scope>` -> **PASS**
- **Verdict**: `GO` | `NO-GO`
- **Follow-up (Prod-Release Backlog)**: `<non-blocking items, if any>`
```
