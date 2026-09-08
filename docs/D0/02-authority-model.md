# D0-02 · Authority Model: PROPOSE / DECIDE / VETO

Status: **ACCEPTED (D0)** · Trace: §4
This table is normative. D1 compiles it into `policy/authority.py` as a
lookup structure; D4 wires agents to it. **The LLM never holds a DECIDE or
VETO cell, and no authority can convert UNKNOWN into any value.**

| Decision | PROPOSE | DECIDE | VETO |
|---|---|---|---|
| Interface / Serial / Vendor / OS identity | — | Device/Inventory Evidence (Ledger Claims) | — |
| IP overlap / subnetting | — | IPAM Engine (E07) | — |
| Config syntax / semantics | — | Validation Fabric (E10) | — |
| Feature feasibility | — | Capability Matrix (E06) | — |
| Requirement interpretation | Requirements Agent (A2) | Human confirmation | Auditor (A4) |
| Business→Network Intent | Requirements Agent (A2) | Intent Compiler (E08) + Human | Auditor (A4) |
| Architecture / Design | Architect Agent (A3) | Validation Fabric + Policy Engine (E10/E24) | Auditor (A4) |
| Deployment order | — | Dependency DAG Engine (E12) | Policy Engine (E24) |
| Blast radius / risk class | — | Blast Radius Engine (E13) | — |
| Autonomy decision | — | Autonomy Authority Engine (E14) | Human (RBAC) |
| Deployment permission | Orchestrator (A1) | Gate per §13 | Policy Engine (E24) |
| Live state / test result | — | Live Evidence + TEST_ORIGIN tag | — |
| Failure continuation | — | Failure Orchestrator (E18) | Human |
| Drift remediation | Reconciliation Engine (E22) | Gate per §13 | Policy Engine (E24) |
| Final documentation | — | Post-Deploy Observed State (Twin) | — |

## Binding rules

1. **Exactly one DECIDE cell per decision.** Two engines claiming DECIDE is a
   build error (checked by a unit test over this table compiled as data).
2. **VETO is final.** A VETO record terminates the FSM-2 path into
   `REJECTED` with the veto reason and evidence ids; only a *new* change
   object (new DRAFT) can restart.
3. **PROPOSE cells are advisory.** A PROPOSE output without an accompanying
   Intent Object schema instance is discarded.
4. **UNKNOWN is terminal for automation.** If the DECIDE cell's engine cannot
   decide (missing evidence/model), the decision outcome is `UNKNOWN` ⇒ the
   change is `BLOCKED`, never defaulted.
5. **Human cells are identified by RBAC identity + MFA** for HIGH_RISK and
   above (§18); a human DECIDE without recorded identity ⇒ audit violation.

## Derived artifact (D1)

`policy/authority.py` exposes:

```python
def who_decides(decision: DecisionKind) -> AuthorityCell: ...
def assert_no_llm_decide() -> None: ...   # unit-tested invariant
def veto(change_id, actor, reason, evidence_ids) -> VetoRecord: ...
```

The table above is embedded as frozen data (`AUTHORITY_TABLE`) so docs and
code cannot diverge; the D1 test `test_authority_table_matches_spec` hashes
the embedded table against this document's canonical JSON export
(`specs/data/authority_table.json`, produced in the D1 batch).
