# Architecture Decision Records

Conventions (ADR-0000):

1. One file per decision: `ADR-NNNN-short-title.md`.
2. Sections: Context · Decision · Consequences · Alternatives considered · Trace.
3. Status lifecycle: `Proposed → Accepted → Superseded by ADR-XXXX`.
   An Accepted ADR is **immutable**; change requires a new superseding ADR.
4. Every ADR cites its spec trace (`§n` of the master specification) and,
   where applicable, the Open Items Register entry it resolves.
5. Decisions that constrain code are listed in the Constitution enforcement
   map (`docs/D0/01-…`); the D1 test suite asserts those mappings exist.

Index:

| ADR | Title | Status |
|---|---|---|
| 0001 | Adapter-first vendor isolation; Python 3.11+ core | Accepted |
| 0002 | Event-sourced, Ed25519-signed Evidence Ledger (SQLite first) | Accepted |
| 0003 | Deterministic engines decide; LLM emits Intent Objects only | Accepted |
| 0004 | v1 physical access: direct PC connection; OOB modeled, not assumed | Accepted |
| 0005 | Cloud LLM behind signed egress policy with secret redaction | Accepted |
| 0006 | Real-hardware lab as the test substrate for v1 | Accepted |
| 0007 | Autonomy ceiling M3; HUMAN_ONLY gate set is immutable | Accepted |
| 0008 | Windows (MSI) packaging first | Accepted |
| 0009 | Rollback-first deployment: FSM-3 READY is a precondition of ARMED | Accepted |
| 0010 | Freshness-per-Decision evaluated at decision time, recorded per decision | Accepted |
