# ADR-0010 · Freshness-per-Decision evaluated at decision time, recorded per decision

Status: **Accepted** · Trace: §8 (Freshness-per-Decision), T5 `stale_evidence_deployments`

## Context
Evidence ages differently per decision kind; evaluating freshness at
collection time (and reusing the verdict) is a classic staleness hole.

## Decision
1. Every decision record computes freshness **at decision time** from
   `collected_at` (collector clock, Time Authority) vs. the decision-class
   bound: Deploy/Rollback 60 s (link/interface/MAC), Design 24 h,
   Documentation unbounded-with-age-printed, running-config via Change
   Detection (no TTL).
2. If any required evidence exceeds its bound, the engine's only options are
   re-collect-then-decide or BLOCKED. There is no "stale but probably ok".
3. The evaluated ages are persisted on the decision record
   (`freshness_at_use`) so audits can replay the exact computation.
4. LLDP/CDP holdtimes are read from device tables; defaults (120 s / 180 s)
   are used only as labeled fallbacks when the table read is unavailable,
   and that fallback itself is recorded as an evidence-quality note.
5. UNSYNCED collector clocks make age a lower bound; decisions that need
   hard freshness with an UNSYNCED clock ⇒ BLOCKED.

## Consequences
* Deploy paths gain a re-collection round-trip just before apply (by design;
  this is the 60 s rule realized).
* `stale_evidence_deployments` counter is simply "decision records whose
  freshness computation violated their bound" — zero tolerance at release.

## Alternatives considered
* TTL stamps on Claims set at collection (rejected: decision-class dependent
  and clock-drift-fragile).
