# D0-03 · State Machines (FSM-1 … FSM-5) with Deterministic Guards

Status: **ACCEPTED (D0)** · Trace: §7
Every transition requires its Guard to evaluate TRUE on **evidence**, never
on inference alone. A transition without a satisfied guard is a
`gate_bypass` counter increment and is rejected by the FSM runtime.
The D1 runtime (`transitions`-based) is generated from the tables below;
docs and code share one source (`specs/data/fsm/*.json`, emitted in D1).

Common failure vocabulary (all FSMs): `RETRYABLE | BLOCKED | ROLLED_BACK |
PARTIAL | MANUAL_REQUIRED | FATAL` (see D0-01 §3).

---

## FSM-1 · Device Lifecycle

States:
`UNKNOWN, PHYSICAL_DETECTED, ACCESSIBLE, IDENTIFIED, BOOTSTRAP_REQUIRED,
BOOTSTRAPPED, DISCOVERED, MODELED, MANAGED` + branch states
`ACCESS_LIMITED, PASSWORD_LOCKED, RECOVERY_REQUIRED, UNSUPPORTED, STALE`.

| # | From → To | Guard (all must hold) | Evidence required |
|---|---|---|---|
| 1.1 | UNKNOWN → PHYSICAL_DETECTED | carrier seen on NIC **or** COM port enumerates **or** MAC seen via local segment probe | PROBE event |
| 1.2 | PHYSICAL_DETECTED → ACCESSIBLE | a session opens AND responds AND `day0_state_classifier` returns non-error | CLI/SERIAL event + parse OK |
| 1.3 | ACCESSIBLE → IDENTIFIED | vendor+model+OS+version Claims resolved from `show version`-class evidence (per-vendor identity commands) with `verification_scope=DEVICE_IDENTITY` | ≥1 Claim per field |
| 1.4 | IDENTIFIED → BOOTSTRAP_REQUIRED | day-0 classifier ⇒ FACTORY_DEFAULT/FACTORY_LIKE **and** management plane absent | classifier Observation |
| 1.5 | BOOTSTRAP_REQUIRED → BOOTSTRAPPED | bootstrap Change VERIFIED (FSM-2 VERIFIED) **and** Post-Bootstrap Baseline artifact hashed & stored | Change record + artifact sha256 |
| 1.6 | IDENTIFIED → DISCOVERED | discovery plan completed; every layer returned a terminal status (success or typed failure; no silent skip) | layer result set |
| 1.7 | DISCOVERED → MODELED | Twin accepted all Claims; zero unresolved `entity_hallucination` flags; Gaps List emitted | Twin ack + gaps list |
| 1.8 | MODELED → MANAGED | monitoring collectors bound **and** reconciliation baseline stored **and** recovery path (FSM-5) ≠ LOST | baseline id |
| 1.9 | ACCESSIBLE → ACCESS_LIMITED | session opens but command set denied/unsupported beyond budget | error Observations |
| 1.10 | any → PASSWORD_LOCKED | auth rejected with credential-validity unknown | auth failure event |
| 1.11 | any → RECOVERY_REQUIRED | device unreachable AND last-known state ≠ clean AND no session possible for `reachability_timeout` | reachability probe set |
| 1.12 | IDENTIFIED → UNSUPPORTED | Capability Matrix: model/version not in supported set | matrix lookup record |
| 1.13 | MANAGED → STALE | freshness policy violation beyond grace AND no fresh evidence | ledger freshness check |
| 1.14 | ACCESS_LIMITED/PASSWORD_LOCKED/RECOVERY_REQUIRED/STALE → (re-entry) | the blocking condition cleared **with new evidence** (re-run of the corresponding gate) | fresh events |

Invariants:
* `MANAGED` is only reachable through 1.8 (no shortcut after reboots; a
  reboot forces re-evaluation via 1.13 check).
* `UNSUPPORTED` is sticky for the version; leaving requires a version change
  Claim.

---

## FSM-2 · Change Lifecycle

States:
`DRAFT, VALIDATED, PLANNED, RISK_ASSESSED, AUTHORIZED, ARMED, APPLYING,
APPLIED, VERIFYING, VERIFIED, CLEANED, CLOSED` + branches
`REJECTED, PARTIAL, FAILED, ROLLED_BACK, RECOVERING, MANUAL_REQUIRED`.

| # | From → To | Guard |
|---|---|---|
| 2.1 | DRAFT → VALIDATED | Validation Fabric full pass: Schema→Vendor Lint→Semantic→Dependency→IPAM→Policy→Entity Guard→Capability→Pre-Deploy Modeling; NOT_MODELED features recorded (≠ PASS, L13) |
| 2.2 | VALIDATED → PLANNED | Dependency DAG built from Config IR `requires/provides/blocks`; topological sort total (no cycle); permanent constraints hold (mgmt plane first & protected, controller before adoption, underlay before overlay, AAA/NTP/PKI before dependents) |
| 2.3 | PLANNED → RISK_ASSESSED | Blast Radius Engine produced `risk_class` + affected set; worst-case recorded |
| 2.4 | RISK_ASSESSED → AUTHORIZED | Autonomy Authority verdict ∈ {AUTO_EXECUTE, APPROVAL_REQUIRED-satisfied}; Decision Readiness (§13) all conjuncts true; human approvals carry RBAC identity (+MFA ≥ HIGH_RISK); gate class ∉ HUMAN_ONLY unless human-decided |
| 2.5 | AUTHORIZED → ARMED | maintenance window valid; no conflicting change on intersecting scope (Scheduler); config lock acquired or acquirable; rollback FSM-3 state == READY (L15 checks included); scope lock recorded |
| 2.6 | ARMED → APPLYING | executor re-verifies Authorized State (L10) immediately before first command; allowlist re-check |
| 2.7 | APPLYING → APPLIED | all commands/stages acknowledged; per-stage verification passed where staged |
| 2.8 | APPLYING → FAILED / PARTIAL | stage failure ⇒ Failure Orchestrator decides CONTINUE/ISOLATE/PARTIAL_ROLLBACK/FULL_ROLLBACK/HALT with recorded causes & counts |
| 2.9 | APPLIED → VERIFYING | mandatory, automatic; test matrix derived from Network Intent (§15) |
| 2.10 | VERIFYING → VERIFIED | PASS semantics satisfied for all mandatory tests **or** each non-PASS has a human acceptance with identity (T4 counters intact) |
| 2.11 | VERIFYING → (rollback path) | any mandatory FAIL ⇒ FSM-3 ROLLBACK_TRIGGERED; change → ROLLED_BACK on FSM-3 success, RECOVERING otherwise |
| 2.12 | VERIFIED → CLEANED | Temporary Resource Manager: temporary_resources == 0 or EXPLICITLY_PRESERVED_BY_APPROVAL |
| 2.13 | CLEANED → CLOSED | Twin updated from post-deploy discovery; documentation set emitted; audit chain complete |
| 2.14 | any pre-APPLYING → REJECTED | VETO (Auditor/Policy) or human denial; reason + evidence recorded |
| 2.15 | any post-APPLYING → MANUAL_REQUIRED | failure class MANUAL_REQUIRED (e.g., physical intervention) with HUMAN_TASK instructions emitted |

Invariants:
* No transition may skip a state (linearity) except into branch states.
* `gate_bypass` increments if any guard was evaluated on evidence older than
  its Freshness-per-Decision bound (§8) at decision time.

---

## FSM-3 · Rollback

States: `NOT_SUPPORTED, NOT_CONFIGURED, NOT_READY, READY, ARMED, CONFIRMED,
ROLLBACK_TRIGGERED, ROLLBACK_SUCCEEDED, ROLLBACK_FAILED, UNKNOWN`.

| # | From → To | Guard |
|---|---|---|
| 3.1 | (init) → NOT_SUPPORTED | Recovery Capability Matrix: mechanism absent for model/version |
| 3.2 | (init) → NOT_CONFIGURED | mechanism supported but no artifact yet |
| 3.3 | NOT_CONFIGURED → NOT_READY | artifact exists but any of: hash missing, filesystem prereqs unverified, content check failed |
| 3.4 | NOT_READY → READY | ALL of: MECHANISM_SUPPORTED_ON_VERSION ∧ ARTIFACT_EXISTS ∧ HASH_RECORDED ∧ FILESYSTEM_PREREQS ∧ TARGET_PRESERVES_MANAGEMENT_PATH (content inspection; target == Post-Bootstrap Baseline) ∧ ALL_COMMANDS_REVERSIBLE_BY_METHOD ∧ RECOVERY_PATH_VERIFIED |
| 3.5 | READY → ARMED | Change FSM-2 reaches ARMED; rollback bound to that change id |
| 3.6 | ARMED → CONFIRMED | apply succeeded and verification window opened (e.g., `configure confirm` / `commit` / safe-mode release per adapter) |
| 3.7 | ARMED → ROLLBACK_TRIGGERED | verification FAIL, timeout, or explicit abort |
| 3.8 | ROLLBACK_TRIGGERED → ROLLBACK_SUCCEEDED | artifact re-applied AND post-rollback verification pass AND mgmt path reachable |
| 3.9 | ROLLBACK_TRIGGERED → ROLLBACK_FAILED | any of the above fails ⇒ FSM-5 escalation |
| 3.10 | any → UNKNOWN | evidence insufficient to classify (e.g., device vanished mid-rollback) |

Invariants:
* Deploy permission (FSM-2 guard 2.5) requires state READY — never inferred.
* `reload-in` style mechanisms are declared last-resort layers and cannot be
  the sole rollback method for HIGH_RISK+ changes.

---

## FSM-4 · Link / Physical Evidence

States: `UNKNOWN, INFERRED, ONE_SIDED, CONFLICTING,
INTERMEDIATE_SUSPECTED, DIRECT_NEIGHBOR_PROBABLE,
DIRECT_NEIGHBOR_CONFIRMED, PHYSICAL_PATH_VERIFIED, STALE`.

| # | From → To | Guard |
|---|---|---|
| 4.1 | UNKNOWN → INFERRED | endpoint(s) with no LLDP/CDP; only MAC/ARP co-occurrence |
| 4.2 | → ONE_SIDED | neighbor advertisement seen from exactly one endpoint |
| 4.3 | → CONFLICTING | two sources disagree (port, MAC, or existence) — never auto-resolved; raised to operator |
| 4.4 | → INTERMEDIATE_SUSPECTED | passive evidence consistent only with an unmanaged intermediary (e.g., MAC churn, TTL/hop hints) |
| 4.5 | → DIRECT_NEIGHBOR_PROBABLE | **ceiling of passive evidence**: bidirectional LLDP/CDP match **or** one-sided + clean MAC history + port name correlation + time correlation |
| 4.6 | PROBABLE → CONFIRMED | 4.5 evidence **and** absence-of-intermediary proven (no MAC churn across window, no third-party MAC on the segment) |
| 4.7 | CONFIRMED/PROBABLE → PHYSICAL_PATH_VERIFIED | gated active proof (link-toggle correlation / TDR / DOM per §10, Gate-controlled, pre-production only) **or** explicit human confirmation with identity |
| 4.8 | any → STALE | LLDP hold 120 s / CDP hold 180 s exceeded (values read from tables, not assumed) without refresh |
| 4.9 | STALE → UNKNOWN | re-evaluation initiated; the stale bundle is quarantined (never silently revived) |

Invariants:
* Topology documentation prints link state verbatim; a PHYSICAL_PATH claim
  displayed from PROBABLE evidence is an `unverified_claims` violation.

---

## FSM-5 · Recovery Hierarchy (independent of Rollback)

States: `NOT_NEEDED, ESCALATING(L0…L7), RECOVERED, HUMAN_REQUIRED, LOST`.

Levels: `L0 app rollback → L1 config rollback → L2 device-local → L3 OOB →
L4 console → L5 bootloader (DESTRUCTIVE tier) → L6 physical → L7 human`.

| # | From → To | Guard |
|---|---|---|
| 5.1 | NOT_NEEDED → ESCALATING(L0) | failure classified recoverable; change id bound |
| 5.2 | ESCALATING(Ln) → ESCALATING(Ln+1) | Ln attempted with evidence of failure, or Ln capability NOT_SUPPORTED on this model (matrix lookup) |
| 5.3 | ESCALATING(Ln) → RECOVERED | device reachable again AND identity re-confirmed AND state re-classified via FSM-1 |
| 5.4 | ESCALATING(L5) | requires DESTRUCTIVE gate + human decision in every mode (L06) |
| 5.5 | ESCALATING(L6/L7) → HUMAN_REQUIRED | physical/human task emitted with exact instructions; platform waits for evidence of completion |
| 5.6 | any ESCALATING → LOST | all modeled paths exhausted without reachability; device marked for on-site intervention |

Invariants:
* Every MANAGED device must have a **tested** recovery path on record before
  its changes may ARM (feeds FSM-2 guard 2.5 via FSM-3 3.4).
* With the v1 direct-connect constraint (ADR-0004), L3 is NOT_CONFIGURED on
  devices lacking OOB — recorded, not guessed.

---

## Runtime requirements (for D1)

1. All transitions emit `STATE_TRANSITION` records into the Evidence Ledger
   (see D0-04) with: fsm, entity, from, to, guard_id, evidence_ids[],
   actor (engine|human+identity), collected_at.
2. Guard evaluation is pure & logged; an exception inside a guard ⇒
   transition denied (fail-closed), never allowed.
3. Illegal transition attempts are audited and counted (`gate_bypass`).
4. Diagrams (mermaid) for all five FSMs are embedded in
   `docs/D0/03-state-machines.md.pics/` in the next D0 batch.
