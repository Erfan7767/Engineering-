# ADR-0003 · Deterministic engines decide; LLM emits Intent Objects only

Status: **Accepted** · Trace: §3 (L04, L16, L17), §4, §5

## Context
Autonomous network changes with LLMs in the loop require that no stochastic
component can authorize, configure, or verify anything.

## Decision
1. The Authority Table (D0-02) is the law: every DECIDE/VETO cell is a
   deterministic engine or a human with RBAC identity.
2. LLM agents A1–A5 may only emit objects conforming to
   `agent_output.schema.json` (Intent Objects). Raw commands in agent output
   fail validation and are quarantined (counted, audited).
3. `confidence` is metadata only (L16): never a gate condition, never shown
   as a justification; Decision Readiness (§13) is the single readiness
   predicate.
4. Entity Guard: any `target_entities[].entity_ref` not present in the
   Inventory rejects the whole Intent Object (`entity_hallucinations`
   counter).
5. Agents receive only Normalized Observations/Claims + local RAG over
   vendor documents — never raw device text, never credentials (§5, L11).

## Consequences
* Agent quality issues degrade into BLOCKED, never into wrong actions.
* Harness can replay identical Observations to agents and diff outputs
  safely (no execution side effects from agents themselves).

## Alternatives considered
* LLM-with-tool-calling executing commands (rejected: violates L04/L17).
* Confidence-threshold automation (rejected: violates L16).
