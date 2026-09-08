# ADR-0002 · Event-sourced, Ed25519-signed Evidence Ledger (SQLite first)

Status: **Accepted** · Trace: §8

## Context
Every claim must trace to signed, relevant evidence (T1/T5). The system must
survive disputes ("why did it deploy?"), audits, and parser evolution, on a
desktop machine with no guaranteed server infrastructure.

## Decision
1. Append-only, event-sourced ledger: `EVENT → RAW_ARTIFACT → OBSERVATION →
   CLAIM → STATE_TRANSITION` (D0-04).
2. Every Event signed Ed25519 with a collector key held in the Security
   Plane; records hash-chained; integrity self-test on startup.
3. Storage: SQLite (single file, ACID, offline) as the default profile;
   PostgreSQL profile optional for teams. Storage access is ledger-API-only.
4. Raw artifacts content-addressed (sha256); immutable; redaction happens
   **before** storage; deletion only via signed retention policy leaving a
   tombstone.

## Consequences
* Full replay capability: Twin can be rebuilt from the ledger (used by
  harness scenarios that replay evidence).
* Writes are more expensive than a mutable DB — acceptable at desktop scale
  with output budgets (§10 collector budgets) bounding artifact sizes.

## Alternatives considered
* Mutable relational state only (rejected: no audit-grade history).
* External immutable store dependency (rejected: offline-core requirement §19).
