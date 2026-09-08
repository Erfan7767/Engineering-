# D0-01 · Constitution: Standard of Truth, Laws, and Enforcement Map

Status: **ACCEPTED (D0)** · Trace: §2, §3 of master specification
Enforcement: each law maps to concrete code constructs that must exist by D1/D3.
A law without an enforcement target is a spec defect → Open Item.

## 1. Standard of Truth (§2) — measurable, testable

| ID | Rule | Measured by (Harness counter, §21) |
|---|---|---|
| T1 | No Claim is displayed or used in a decision without valid, relevant `evidence_ids`. | `unverified_claims` |
| T2 | Any knowledge gap → `UNKNOWN \| BLOCKED \| NOT_MODELED \| NOT_TESTED \| ACCESS_LIMITED \| NOT_SUPPORTED`. No guessing, no defaults, no PASS. | `unsupported_PASS` |
| T3 | No execution outside Authorized State + Command Allowlist + Autonomy Policy. | `unauthorized_changes` |
| T4 | Every partial failure is reported with count and causes. | `scope_violations` (plus failure reports) |
| T5 | The Harness measures T1–T4 in every release; release gate counters (all must be `0`): `unauthorized_changes`, `unsupported_PASS`, `entity_hallucinations`, `scope_violations`, `credential_exposure`, `cleanup_leaks`, `gate_bypass`, `stale_evidence_deployments`, `management_path_violations`, `unverified_claims`. | Harness T5 report |
| T6 | "Rollback correctness = 100%" means: in all officially supported & tested cases only. Anything outside coverage → `NOT_SUPPORTED`/`BLOCKED`, and no deploy. | rollback coverage matrix |

## 2. Laws (§3) → enforcement target

| Law | Statement (short) | Enforcement target (module / phase) |
|---|---|---|
| L01 | ZERO-GUESS | `engines/` are deterministic; LLM output can never fill a fact field (`agents/guard.py`, D4). Parsers never synthesize values; missing field ⇒ Observation with `parse_status=MISSING` (D1). |
| L02 | EVIDENCE-OR-STATE | Twin nodes exist only via `STATE_TRANSITION` records backed by Claims (`engines/twin.py`, D1). |
| L03 | NO SILENT FAILURE | Every engine returns typed `FailureSemantics` (see FSM doc §6); error swallowing is a lint rule + harness fault-injection scenario (D1/D3). |
| L04 | DETERMINISTIC AUTHORITY | LLM agents only emit Intent Objects (§5 schema); all DECIDE/VETO cells of the Authority table are deterministic engines (this table is compiled into `policy/authority.py`, D1). |
| L05 | STAGE GATES + Auditor PASS | FSM-2 transitions require Gate verdict records (`engines/change_engine.py` + `agents/auditor`, D3/D4). |
| L06 | GATE CLASS by Autonomy Authority Engine; IRREVERSIBLE/DESTRUCTIVE/management-path ⇒ human in **every** mode | `engines/autonomy.py` `gate_class()` is a pure function; the human-only set is a compile-time constant the policy signer cannot override (D3; constant frozen here in D0). |
| L07 | VERIFY-AFTER-APPLY + ROLLBACK-ON-FAIL | FSM-2 `APPLIED→VERIFYING` is mandatory; `VERIFYING` failure forces FSM-3 trigger (D3). |
| L08 | SINGLE SOURCE OF TRUTH | Twin + Evidence Ledger are the only read sources for decisions; no engine keeps private state (D1). |
| L09 | SCOPE LOCK | Change objects carry `scope_set`; Adapter executor refuses commands touching entities outside scope (`engines/change_engine.py`, D3; counter `scope_violations`). |
| L10 | NO ACTION OUTSIDE AUTHORIZED STATE | Executor resolves each target interface/entity against the Twin; non-existent port ⇒ `BLOCKED` before any packet is sent (D3). |
| L11 | NO LLM SECRETS | Agent context builder excludes secret refs; egress pipeline redacts; harness scenario greps model I/O for credential patterns (counter `credential_exposure`, D4). |
| L12 | NO AUTO-REMEDIATION without signed policy for a specific class | `policy/signer.py` + Drift remediation routes through §13 gates (D5). |
| L13 | NOT_MODELED ≠ PASS; NO EVIDENCE ≠ PASS; TEST UNAVAILABLE ≠ PASS | PASS semantics table (§15 doc) implemented as a truth table in `engines/verification.py` (D3). |
| L14 | HONEST LIMITS | All user-facing strings rendered from typed states only; "100% replacement" is a banned literal in UI copy (lint rule, D6). |
| L15 | MANAGEMENT PATH = PROTECTED_FOUNDATION | Rollback artifact content check `TARGET_PRESERVES_MANAGEMENT_PATH` + FSM-5 path must be `VERIFIED` before ARMED (D3). |
| L16 | NO CONFIDENCE GATING | `confidence` is metadata-only in Agent Output Schema; Decision Readiness is the sole readiness predicate (schema in this batch; engine D3). |
| L17 | LLM OUTPUT = INTENT OBJECT only | JSON Schema `agent-output.schema.json` is the only accepted agent output shape; raw command strings fail schema validation and are quarantined (D4). |

### Frozen constants (L06 human-only set)

The following gate classes/contexts are decided by a human **in every Autonomy
Mode including M4/M5**, encoded as an immutable set in code:

```
HUMAN_ONLY = {
  IRREVERSIBLE,
  DESTRUCTIVE,
  MANAGEMENT_PATH_TOUCHING,
  NOT_MODELED_HIGH_RISK,
}
```

No signed policy, no RBAC role, no emergency mode can remove an element from
this set. Removal attempt ⇒ `PolicyViolation` + audit event + `gate_bypass`
counter increment.

## 3. Failure semantics (§7 tail) — single vocabulary, all engines

```
RETRYABLE | BLOCKED | ROLLED_BACK | PARTIAL | MANUAL_REQUIRED | FATAL
```

Every engine call returns either a success payload or one of these with:
`causes[]` (structured codes), `count` (for partial), `evidence_ids[]`,
`retry_hint` (only for RETRYABLE). Mapping rules:

| Situation | Class |
|---|---|
| transient transport/parse error within budget | RETRYABLE |
| precondition false (missing evidence, port absent, lock unavailable, NOT_SUPPORTED) | BLOCKED |
| change applied then fully reverted with verification | ROLLED_BACK |
| n/N devices succeeded, remainder failed | PARTIAL (with n, N, per-device causes) |
| requires physical/human action (HUMAN_TASK) | MANUAL_REQUIRED |
| unrecoverable internal invariant breach (ledger hash mismatch, schema corruption) | FATAL |

## 4. Traceability

Every requirement in docs/D0 carries a `§` reference to the master spec.
The Evaluation Harness (D1 skeleton, D4 full) generates a requirement →
test → counter matrix; a requirement with no test is an open item, never an
implicit pass.
