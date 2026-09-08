# D0-06 · Architecture Overview

Status: **ACCEPTED (D0)** · Trace: §1, §5, §6, §20
Companion docs: Authority (D0-02), FSMs (D0-03), Ledger (D0-04),
Threat Model (D0-05).

## 1. Planes

```
┌──────────────────────────── UI PLANE (D6: Tauri/React) ────────────────────────────┐
│ operator consoles, approval dialogs, topology/docs views — read via Gate APIs only │
└──────────────────────────────────────▲─────────────────────────────────────────────┘
                                       │ typed APIs (never raw stores)
┌──────────────────────────── AGENT PLANE (D4) ──────────────────────────────────────┐
│ A1 Orchestrator · A2 Requirements · A3 Architect · A4 Auditor(VETO) · A5 Diagnosis │
│ UNTRUSTED INPUT PRODUCERS — Intent Objects only (L17), no credentials (L11)        │
└──────────────────────────────────────▲─────────────────────────────────────────────┘
                                       │ Observations/Claims/Twin projections + local RAG
┌──────────────────── CONTROL PLANE (D1–D3, deterministic engines E01–E30) ──────────┐
│ Decision & execution engines; Authority Table is law; gates, DAG, blast radius     │
└─────────────▲──────────────────────────────────────────────▲───────────────────────┘
              │ read/write (API only)                        │ adapter interfaces only
┌─────────────┴─────────────┐                 ┌──────────────┴───────────────────────┐
│ EVIDENCE PLANE (D1)       │                 │ ACCESS PLANE (D1)                    │
│ Ledger, Twin, Artifact    │                 │ Access/Config/Discovery/Rollback/    │
│ store, Key registry       │                 │ Recovery/Verification/Monitoring/    │
│ append-only, signed       │                 │ Lifecycle/Wireless adapters          │
└───────────────────────────┘                 └──────────────┬───────────────────────┘
                                                             │ Serial/Ethernet/NETCONF/
┌──────────────────────────── SECURITY PLANE (D1+) ─────────────────────┼────────────┐
│ Vault, keys, RBAC+MFA, policy signer, allowlists, audit, redaction    ▼ devices    │
└────────────────────────────────────────────────────────────────────────────────────┘
```

Rules: downward arrows only for authority (Control → Access); Evidence is
written by Access through the Ledger API and read by everyone through typed
queries; **no engine bypasses the Ledger; no adapter bypasses the allowlist;
no agent bypasses schema validation.**

## 2. Engine registry (E01–E30) with phase and authority role

| ID | Engine | Phase | Authority role (D0-02) | Key interfaces |
|---|---|---|---|---|
| E01 | Day-0 Access | D1 | DECIDE device access method (with Access Profiles) | AccessAdapter |
| E02 | Collector | D1 | produces Events | AccessAdapter |
| E03 | Parsers/Normalizers | D1 | produces Observations | parser registry |
| E04 | Evidence Ledger | D1 | DECIDE device identity facts (via Claims) | ledger API |
| E05 | Digital Twin | D1 | current-state projection | twin API |
| E06 | Capability Matrix | D2 | DECIDE feature feasibility | matrix data |
| E07 | IPAM | D2 | DECIDE IP overlap/subnetting | ipam API |
| E08 | Intent Compiler | D2 | co-DECIDE business→network intent (with Human) | intent schema |
| E09 | Config IR/Generator | D2 | produces IR (validated, not decided) | IR schema |
| E10 | Validation Fabric | D2 | DECIDE config syntax/semantics | pipeline API |
| E11 | Pre-Deploy Modeling | D2 | modeling verdicts (NOT_MODELED ≠ PASS) | Batfish adapter |
| E12 | Dependency DAG | D3 | DECIDE deployment order | DAG API |
| E13 | Blast Radius | D3 | DECIDE risk class | graph queries |
| E14 | Autonomy Authority | D3 | DECIDE autonomy verdicts | policy API |
| E15 | Change/Deploy | D3 | executes FSM-2 | executor + locks |
| E16 | Rollback Adapters | D3 | FSM-3 mechanics | RollbackAdapter |
| E17 | Recovery Hierarchy | D3 | FSM-5 escalation | RecoveryAdapter |
| E18 | Failure Orchestrator | D3 | DECIDE failure continuation | failure API |
| E19 | Test/Verification | D3 | PASS semantics | VerificationAdapter |
| E20 | Probe Manager | D3 | gated active evidence | probes API |
| E21 | Cleanup/Temp Resources | D3 | MANDATORY cleanup | resource registry |
| E22 | Reconciliation | D5 co-located D2 defaults | proposes remediation | defaults DB |
| E23 | Drift | D5 | classification | drift API |
| E24 | Policy Engine | D1 (core)/D3 (gates) | VETO deployment order/remediation | policy API |
| E25 | Audit Ledger | D1 | immutable audit | audit API |
| E26 | Documentation | D5 | DECIDE final docs from observed state | doc API |
| E27 | Monitoring | D5 | collectors/baselines | MonitoringAdapter |
| E28 | Lifecycle (FW/Lic) | D5 | upgrade as full Change | LifecycleAdapter |
| E29 | Scheduler/Calendar | D5 | windows/conflicts | calendar API |
| E30 | Evaluation Harness | D1 skeleton / D4 full | measures T5 | harness runner |

## 3. Adapter layer (ADR-0001)

Interfaces (stable in v1): `AccessAdapter, DiscoveryAdapter, ConfigAdapter,
RollbackAdapter, RecoveryAdapter, VerificationAdapter, MonitoringAdapter,
LifecycleAdapter, WirelessControlPlaneAdapter`.

Vendor implementations v1 (all six in parallel):
`CiscoIOSXE, Junos, RouterOS, FortiOS, ArubaOS, UniFi` — each package
provides the subset it can support and ships **explicit NOT_SUPPORTED stubs**
for the rest, so capability questions always return a typed answer.

Binding resolution: `(vendor, platform, os, version)` → implementation, via
the Capability Matrices (§11) — **never** by vendor-name conditionals in
engines.

## 4. Source layout (finalized in D1; frozen here)

```
src/netops_autopilot/
├── core/           # failure semantics, ids, time authority, budgets
├── ledger/         # E04 ledger store, signing, hash chain
├── fsm/            # FSM-1..5 runtime + guard registry
├── twin/           # E05 projection + layers
├── engines/        # E06..E30 (one module per engine)
├── adapters/
│   ├── interfaces/ # abstract interfaces only
│   ├── cisco_iosxe/ junos/ routeros/ fortios/ arubaos/ unifi/
├── agents/         # A1..A5 + guard (Entity Guard, schema gate)
├── policy/         # authority table, autonomy, signer, allowlists
├── security/       # vault, keys, rbac, redaction
├── ui_bridge/      # typed APIs consumed by the Tauri frontend
└── cli/            # headless ops interface (same APIs)
```

## 5. Cross-cutting decisions

* **Offline core (§19):** every connector has state
  `AVAILABLE|UNAVAILABLE|NOT_CONFIGURED` and a REQUIRED/OPTIONAL
  classification per task; the LLM connector being UNAVAILABLE is a
  documented degraded mode, never a crash.
* **Concurrency:** device session locks are acquired before APPLYING; lock
  acquisition failure ⇒ BLOCKED (FSM-2 2.5). Parallel human sessions are
  detected and pause automation on that device (TH-13).
* **Budgets:** every command carries timeout + output budget + retry policy;
  circuit breakers per (device, command class) (TH-09).
* **Determinism:** engine outputs are pure functions of (ledger state,
  policy, matrices); harness replays verify byte-identical decisions.
* **Identities:** everything that acts has an identity: engines (key id),
  humans (RBAC + MFA), agents (agent id + model id + policy id).

## 6. What D0 deliberately does NOT decide (Open Items)

Database index layouts, CI runner vendors, UI component library, runbook
authoring format, Batfish version pin — each gets an Open Items entry and an
ADR when decided (see `open_items_register.md`).
