# NetOps Autopilot

Evidence-driven autonomous Network Engineering desktop platform.

> **Master specification:** `P1-ARCHITECTURE-REVIEWED` (supersedes P0-FINAL).
> The full binding specification is mirrored in `docs/D0/` and the
> `open_items_register.md` tracks every deviation, question, and closure.

## What this platform is (and is not)

The user racks, cables, powers and connects the device (Console / USB-Serial /
Ethernet), then states the customer requirement in natural language. The
platform then: discovers reality **with evidence** → understands intent →
designs → generates → validates **before** deploy → deploys safely with a
**proven** rollback & recovery path → verifies **after** deploy with real
tests → cleans up temporary resources → documents from **observed** reality →
monitors, detects drift, and diagnoses.

Every task is classified in exactly one Capability Domain (§1):

| Domain | Meaning |
|---|---|
| `AUTOMATED` | Platform executes fully, within the signed Autonomy Policy. |
| `ASSISTED` | Platform designs/generates/validates; a human step is mandatory. |
| `HUMAN_TASK` | Beyond software (cabling, racking, hardware replacement, ISP coordination, physical resets). The platform produces precise instructions and **verifies the result with evidence afterwards**. |

This system is **not** a "100% replacement" for engineers. It executes
everything `AUTOMATED`, leads `ASSISTED`, and directs `HUMAN_TASK` — and it
announces the classification of every task.

## Delivery phases (§23)

| Phase | Scope | Status |
|---|---|---|
| **D0** | Architecture, ADRs, Threat Model, JSON Schemas, FSM diagrams, Command Allowlists, Default Access Profiles, Capability Domain Matrix, Open Items Register | **COMPLETE** |
| **D1** | Core: Ledger + FSMs + Policy + Access Layer + Collector/Parsers + Twin + Adapter Interfaces (lab-verified) | **CODE-COMPLETE, lab verification pending** — Batches 1–5 delivered: core/ledger/fsm/policy, adapter layer + allowlist + E02 Collector + E03 Parsers (6 vendor golden fixtures), Digital Twin (E05), deterministic serial console transport, **all five FSMs as code (93 guarded transitions)**, canonicalization + Platform Defaults DB. 195 passing tests. Remaining for phase exit: first lab-hardware evidence run (needs sponsor device + console port). |
| **D2** | Capability Matrices + IPAM + Intent Compiler + Config IR + Validation Fabric + Preflight + Reconciliation + Service Dependency Graph | **COMPLETE (code-level)** — all eight components delivered in 4 batches: E06 Capability Engine, E07 IPAM Engine, E08 Intent Compiler (§12 guest-isolation golden: 4 mandated decisions, complete zone×zone matrix, blocking questions), E09 Config IR (reversibility tags, gate derivation), E10 Validation Fabric (nine-stage pipeline), E11 Preflight Engine (Twin×AdapterRegistry modeling assessment, wired as `PreflightFn`), E22 Reconciliation D2 scope (immutable baselines + typed drift classification), P1-34 Service Dependency Graph (deterministic ordering). 306 tests total. Lab-evidence gates remain as open items: OI-0140 (capability operational fields), OI-0141 (ArubaOS checkpoint/rollback), OI-0142 (DHCPv6/SLAAC NOT_MODELED). |
| **D3** | DAG + Blast Radius + Autonomy Authority + Change Engine + Rollback Adapters + Recovery Hierarchy/OOB + Failure Orchestrator + Test/Probe + Cleanup | **COMPLETE (code-level)** — all nine components delivered in 4 batches: E12 Dependency DAG, E13 Blast Radius, E14 Autonomy Authority (M3-locked), E15 Change Engine (FSM-2 spine 2.1→2.4 + veto), E16 Rollback Engine (FSM-3, artifact-hash honesty), E17 Recovery Engine (FSM-5, ADR-0004 OOB skip, L5 human gate), E18 Failure Orchestrator (guard 2.8 decisions with T4 n/N), E19 Verification Engine (intent-derived test matrix, guards 2.9/2.10), Temporary Resource Manager (guard 2.12). 409 tests total. Hardware-touching execution (adapters applying to real devices) awaits the physical lab per OI-0005. |
| **D4** | Agents A1–A5 + Boundaries + Claim/Relevance Verifier + Evaluation Harness (T5 report) | **IN PROGRESS** — Batches 1–2 delivered: Agent Boundary Guard (L01/L02/L11/L17), Agent Context Builder (secret redaction), Claim/Relevance Verifier (D0-04 §5 three rules, fail-closed, ledger read accessors added), Link Evidence Engine (FSM-4 per-link ladder, passive ceilings, terminal CONFLICTING). 452 tests total. Next batch: Evaluation Harness full (T5 report) + agent PROPOSE→DECIDE wiring over the authority table. |
| D5 | Monitoring + Drift + Lifecycle + Runbooks + Scheduler + Documentation | NOT STARTED |
| D6 | UI (Tauri) + Packaging (MSI first) + Manuals + Shadow Mode tooling | NOT STARTED |

No phase transition before the previous phase's tests are delivered and green.

## v1 scope decisions (locked by sponsor answers, see Register items OI-0001…OI-0006)

* Vendors, **all six in parallel at equal priority**: Cisco IOS/IOS-XE,
  RouterOS, Junos, FortiOS, Aruba/HP, UniFi.
* Access hardware: **direct PC connection** (Serial/Ethernet); no console
  server, no hub, no second NIC initially. OOB is *modeled* but DAY-0 cannot
  rely on it (see ADR-0004).
* Host OS: **Windows (MSI)** first; Linux/macOS packaging later.
* LLM runtime: **cloud API** behind a signed egress policy with secret
  redaction (L11); a local-Ollama provider is delivered as an alternate
  `LLMProvider` implementation.
* Lab: **real physical hardware** (hardware-in-the-loop) is the test
  substrate; no containerlab/GNS3.
* Target autonomy ceiling for v1: **M3 Controlled Autonomous** — only
  gate-classes explicitly allowed by a signed policy; IRREVERSIBLE /
  DESTRUCTIVE / management-path changes remain human-decided in **every**
  mode (L06).

## Repository layout

```
netops-autopilot/
├── README.md                      ← this file
├── adr/                           ← Architecture Decision Records (immutable once Accepted)
├── specs/
│   ├── schemas/                   ← JSON Schemas (draft-07), source of truth for pydantic models in D1
│   └── data/                      ← Access profiles, allowlists, defaults DB, capability matrices (JSON)
├── docs/D0/                       ← D0 deliverables (architecture, authority, FSMs, threat model…)
├── src/netops_autopilot/          ← code (populated from D1)
├── tests/                         ← evaluation harness (§21), mirrors src/
└── open_items_register.md         ← the ONLY place items open/close (with recorded decisions)
```

## Running the tests (D1 onward)

```powershell
pip install -r requirements.txt
python -m pytest tests/
```

Dependency policy: `requirements.txt` lists exactly what the current phase
imports; §20 libraries (Scrapli, Netmiko, pySerial, pyATS, pybatfish, …) are
added adapter-by-adapter as their phases land — no dependency enters the
repo before its engine does.

## Hard rules (always true, enforced in code from D1 onward)

1. No claim is displayed or used in a decision without valid, relevant
   `evidence_ids` (T1).
2. Missing knowledge is `UNKNOWN | BLOCKED | NOT_MODELED | NOT_TESTED |
   ACCESS_LIMITED | NOT_SUPPORTED` — never a guess, a default, or a PASS (T2).
3. Nothing executes outside Authorized State + Command Allowlist + Autonomy
   Policy (T3).
4. Every partial failure is reported with its count and causes (T4).
5. Release requires all T5 counters == 0 (see `docs/D0/10-evaluation-harness.md`).
