# ADR-0009 · Rollback-first deployment: FSM-3 READY is a precondition of ARMED

Status: **Accepted** · Trace: §13, §14, L07, L15

## Context
"Deploy safely with proven rollback/recovery" (§1) must be structural, not
behavioral: a change must be physically unable to ARM without a READY
rollback bound to it.

## Decision
1. FSM-2 guard 2.5 hard-requires FSM-3 state READY for the bound rollback
   object; READY itself requires the full §14 conjunction including
   `TARGET_PRESERVES_MANAGEMENT_PATH` content inspection and
   `RECOVERY_PATH_VERIFIED`.
2. Rollback artifacts are captured **before** apply (Post-Bootstrap Baseline
   for day-0; running-config snapshot + mechanism-specific artifacts
   otherwise), hashed, and stored in the artifact store; artifact absence ⇒
   NOT_READY ⇒ no ARMED.
3. Per-vendor mechanisms (v1): IOS-XE archive + `configure replace`/confirm-
   revert flow; Junos `commit confirmed`+`commit`; RouterOS Safe Mode +
   export/import (+ version-bound binary backup, history explicitly NOT
   relied upon); FortiOS API backup/restore; ArubaOS checkpoint/rollback
   where available; UniFi controller-managed rollback via controller API.
   Anything else ⇒ NOT_SUPPORTED stub.
4. `reload-in`-class mechanisms may only be a declared **last layer**, never
   the sole method for HIGH_RISK+.
5. Post-trigger verification is mandatory (FSM-3 3.8); rollback without
   verification ⇒ ROLLBACK_FAILED semantics even if the device "looks fine".

## Consequences
* Some legitimate-seeming changes become un-ARMable on versions without a
  supported mechanism — this is the intended T6 honesty: BLOCKED, not
  "probably fine".
* The D3 CI gate "rollback/recovery proven in CI" is defined as: every
  supported (vendor, mechanism) pair has a recorded, replayable success
  evidence bundle on lab hardware.

## Alternatives considered
* Allow ARMED with NOT_CONFIGURED rollback + human waiver (rejected: waiver
  fatigue would erode T6; waivers exist only as explicit BLOCKED-override
  audit events owned by HUMAN_RBAC, and they downgrade the mode to M2 for
  that scope).
