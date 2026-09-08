# ADR-0007 · Autonomy ceiling M3; HUMAN_ONLY gate set is immutable

Status: **Accepted** · Trace: §3 (L06), §13 · Resolves OI-0006

## Context
Sponsor answer (f): v1 targets M3 Controlled Autonomous. M4/M5 demand
harness scale (≥1000 scenarios) and shadow-mode maturity that do not exist
yet; the HUMAN_ONLY set is a law-level constant (L06) independent of mode.

## Decision
1. v1 ships modes M0–M3. M4/M5 schemas exist but are refused at activation
   (`ModeNotReleased`) until the §21 scenario counts (≥1000 for M4) and
   shadow-mode evidence are recorded in the Open Items Register.
2. Mode activation requires: signed Autonomy Policy (RBAC identity + MFA),
   explicit site/scope binding, TTL where applicable. No global "all sites"
   activation is representable.
3. `HUMAN_ONLY = {IRREVERSIBLE, DESTRUCTIVE, MANAGEMENT_PATH_TOUCHING,
   NOT_MODELED_HIGH_RISK}` is compiled as a frozen constant. The policy
   schema **cannot express** removing these; attempts are validation errors
   and audit events.
4. M3 additionally requires (per §13): Decision Readiness all-true,
   rollback FSM-3 READY, recovery path tested, window valid, blast radius
   accepted — otherwise the verdict downgrades to APPROVAL_REQUIRED or
   BLOCKED (never up-escalated by heuristics).
5. Every autonomous action in M3 carries a human-readable justification
   bundle (gate verdict + evidence ids + freshness ages) in the Audit
   Ledger; M5-style retroactive review is available as a tool even in M3.

## Consequences
* Default posture is conservative: anything not explicitly allowed by the
  signed policy for the scope is APPROVAL_REQUIRED.
* Mode ceiling is enforced in code (`engines/autonomy.py`), not only docs.

## Alternatives considered
* Ship M4 behind a flag (rejected: no harness basis; violates T5/T6).
