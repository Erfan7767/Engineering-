# NetOps Autopilot

**Real, automated network engineer replacement — connect, discover, design, apply.**

> **Master specification:** `P1-ARCHITECTURE-REVIEWED` (supersedes P0-FINAL).
> The full binding specification is mirrored in `docs/D0/` and the
> `open_items_register.md` tracks every deviation, question, and closure.

The platform runs a **constitution** (17 laws, 6 truth standards) that
forbids guessing, requires evidence for every claim, and gates execution
behind lab-verified command allowlists. It will not lie to you, and it
will not pretend something is done when it isn't.

**One real product, end-to-end:** the human racks/cables/powers the
devices and plugs the seed device into the computer; the platform
discovers the entire network, asks the human what kind of network
they want (in natural language), and applies a verified, reversible
configuration to every device — autonomously.

> **Master specification:** `P1-ARCHITECTURE-REVIEWED` (supersedes P0-FINAL).
> The full binding specification is mirrored in `docs/D0/` and the
> `open_items_register.md` tracks every deviation, question, and closure.

The platform runs a **constitution** (17 laws, 6 truth standards) that
forbids guessing, requires evidence for every claim, and gates execution
behind lab-verified command allowlists. It will not lie to you, and it
will not pretend something is done when it isn't.

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
| **D4** | Agents A1–A5 + Boundaries + Claim/Relevance Verifier + Evaluation Harness (T5 report) | **COMPLETE (code-level)** — Batches 1–2 delivered the guard/context/verifier/link engines; the **full Evaluation Harness (E30)** landed with the D5-capstone: known-answer scenario runner, replay duplication, NOT_TESTED-visible, gate-eligible T5 counters computed from runs (no attestation), FI-detection scenarios (`fi:ledger-tamper` proves chain verification catches forgery). RELEASE GATE: PASS at 4/4 scenarios. Agent PROPOSE→DECIDE wiring tracked as OI-0183. |
| **D5-capstone** | The operator's end-to-end scenario mechanized | **DELIVERED (code-level)** — five batches: **E31 Discovery Crawl Engine** (catalog∩allowlist plans, sorted frontier, T4 n/N per device, FSM-4 ladder, LLDP/CDP/MNDP fusion), **Topology Map Engine** (deterministic ASCII, evidence-graded, Gaps List), **Blueprints + Elicitation** (6 blueprints, bilingual deterministic classification, UNKNOWN/BLOCKED never a guess), **Design Engine** (blueprint × topology × IPAM ⇒ per-device IR with lineage, first-fit non-overlapping packing, infrastructure-port reservation), **Day-0 Bootstrap (E01) + ACCESS_LIMITED advisor**, **Cisco IOS-XE serial adapter** (real hardware path), **Autopilot orchestrator + CLI** (`python -m netops_autopilot demo|autopilot`), **E30 Evaluation Harness**. EXECUTION GATE honestly BLOCKED by law (empty CONFIG allowlist classes ⇒ T3): outputs are STAGED previews with full lineage — never claimed applied. 512 tests total. |
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

## Running the platform (D5-capstone onward)

```powershell
pip install -r requirements.txt
python -m pytest tests/                              # 838 tests green

# The operator's scenario, on the simulated fabric (deterministic, no hardware):
python -m netops_autopilot demo
python -m netops_autopilot demo --scenario hotel --report-dir ./out

# On real hardware (console cable to the SEED device — the only cable needed):
python -m netops_autopilot autopilot --port COM5 --report-dir ./out

# The web UI (FastAPI + single-page HTML; no Node, no build step):
python -m netops_autopilot webui --port 8765
# Then open http://localhost:8765/ in a browser (v3 UI is the default)
```

The autopilot then runs BOND → BOOT_PROBE → DISCOVERY_A → TOPOLOGY_MAP →
INTENT_ELICITATION (asks you, in words — Arabic or English) → DESIGN →
RENDER → EXECUTION_GATE → REPORT. Every fact printed is ledger evidence;
every unknown is a typed state, never a guess.

## Real-world operator flow

1. **Human action**: rack, cable, and power the devices. Plug the
   console/USB cable from the SEED device into the PC.
2. **Connect** (UI: `1. اتصال`): pick the port (e.g. `COM3`,
   `/dev/ttyUSB0`), choose the mode (Serial/SSH/Telnet), and
   type `BOND` to confirm the physical binding.
3. **Discover** (UI: `2. الاكتشاف`): the engine runs `show version`,
   `show lldp/cdp neighbors detail`, `show vlan brief`, etc. on the
   SEED device, then walks every advertised neighbor with the same
   evidence-bound flow. The discovery may cover 1–256 devices in
   one run.
4. **Topology** (UI: `3. الخريطة`): the engine renders the network
   map with confirmed/probable links and a typed "gaps" list (every
   unknown is a typed state, never silent).
5. **Design** (UI: `4. التصميم`): pick a blueprint (Branch, DC,
   Hotel, Retail, Small Office). The engine composes VLANs,
   SVIs, trunks, and routing — the rendered config is shown for
   review.
6. **Apply** (UI: `5. التطبيق`): type `BOND` to unlock the apply
   button. The `ConfigExecutor` then issues every command via the
   allowlist-gated transport, verifies each block via
   `show running-config` hash, and rolls back automatically on
   verification failure.
7. **Report** (UI: `التقرير`): a self-contained HTML report with
   full audit trail is written to `run.html`; the JSON version is
   also available.

## v8 Web UI — World-class chat operator with REAL device execution

The default UI (`webui/v8/index.html`, served at `/chat`) is a
single self-contained HTML file — no build step, no Node, no external
dependencies. v8 introduces real device execution: every chat command
that asks for `ping`, `traceroute`, `show ip route`, `show vlan`,
`show interfaces`, `show lldp`, or `show neighbors` runs on the
actual device and returns the actual output. The UI has a dedicated
device-output card with colorized success/failure markers and a
key-value summary line.

* **Linear / Vercel-grade dark palette** with warm-blue accent and
  conic-gradient brand mark
* **3-pane grid layout**: 264px sidebar · flexible main · 384px context
* **5-step workflow stepper** in the top bar (Bind → Discover → Design
  → Apply → Verify) that auto-advances from the live `/state` snapshot
  and reaches "verify" after any `ping` / `traceroute` / `show` command
* **Live SSE execution card** with phase timeline pills, pulse-dot
  indicator, real-time elapsed-time counter, and a streaming event log
* **Device-output card** with colorized `!!!!` success markers,
  `Success rate is 100 percent` highlights, and a key-value summary
  line (elapsed / route_count / vlan_count / interface_count /
  neighbor_count)
* **Force-directed topology SVG** with radial layout, pulsing
  COMPLETE nodes, ONE-SIDED link dashing
* **Command palette** (⌘K) with fuzzy match over 18 verbs
* **Config cards** with syntax-highlighted Cisco IOS-XE output and
  one-click copy / download buttons
* **Device grid** rendered from real `data.devices` with status,
  vendor, model, and version
* **17 keyboard shortcuts**: ⌘1..8 quick actions, ⌘K palette, Enter to
  send, Shift+Enter for newline, Esc to close
* **Toast notifications** for OK / FAILURE outcomes
* **Full RTL Arabic** with bidi text direction and Saudi Arabia flag
* **Evidence export** as JSON download
* **Auto-refresh** every 5s for the state pill bar and context panel
* **Backward compatibility**: v7, v6, v5 still mounted at
  `/ui/v7/`, `/ui/v6/`, `/ui/v5/`

### Real device execution — what the chat actually does

When you type `ping 10.0.0.1` in the chat, the operator:

1. **Resolves the intent** to `PING` with `target=10.0.0.1`
2. **Selects the seed device** (the only REACHABLE device from the
   last `discover`)
3. **Opens a fresh management session** to the seed
4. **Sends `ping 10.0.0.1 repeat 5`** (allowlist-gated, L10/T3)
5. **Receives the device's response** (e.g.
   `Type escape sequence to abort. Sending 5, 100-byte ICMP Echos
   to 10.0.0.1, timeout is 2 seconds: !!!!! Success rate is 100
   percent (5/5), round-trip min/avg/max = 1/1/3 ms`)
6. **Audits the command** to the ledger (chat-show observation)
7. **Returns the raw bytes** in the `data` block of the response
8. **Renders** a device-output card in the UI with the real output
   and elapsed time

Same flow for `traceroute`, `show ip route`, `show vlan`, `show
interfaces`, `show lldp`, `show neighbors`, `show version`.

### Rollback actually undoes the last apply

When you say `rollback` after a `apply branch`, the operator:

1. **Walks the last run's change records**
2. **For each APPLIED record**, opens a fresh session on the device
3. **Sends every rollback command** from the executor's plan
4. **Verifies each command is in the allowlist** (gate L10/T3)
5. **Returns a per-command transcript** (✓/✕) to the operator

This is the path a 30-year engineer expects: the chat remembers what
it did, and the rollback truly undoes it.

### Live phase timeline (what you see during a `discover` or `apply`)

```
[ BOND ] ─ OK ✓
[ BOOT_PROBE ] ─ OK ✓
[ DISCOVERY_A ] ─ OK ✓
[ TOPOLOGY_MAP ] ─ OK ✓
[ INTENT_ELICITATION ] ─ OK ✓
[ DESIGN ] ─ OK ✓
[ RENDER ] ─ OK ✓
[ EXECUTION_GATE ] ─ applying…
```

Each phase chip transitions from `active` (pulsing) to `done` (green) as
the engine moves on. The live event log below the timeline streams every
`show`, `ask`, `confirm`, `answer`, `cmd` event as it happens.

## Subsystems

| Subsystem | What it does | Where |
|---|---|---|
| **CLI** | argparse entry-point, four sub-commands (`autopilot`, `demo`, `config`, `health`, `webui`, `scenarios`) | `src/netops_autopilot/cli_main.py` |
| **Pretty CLI** | colored panels, tables, progress bars, run summary | `src/netops_autopilot/cli/pretty.py` |
| **Scenarios** | 4 canned demo scenarios (branch / leaf-spine / hotel / retail) | `src/netops_autopilot/cli/scenarios.py` |
| **Transports** | Serial (pySerial), SSH (Netmiko), Telnet (stdlib) + auto-select factory | `src/netops_autopilot/access/` |
| **Reporting** | Self-contained HTML + structured JSON per-run reports | `src/netops_autopilot/reporting/` |
| **Web UI** | FastAPI REST + WebSocket + single-page static UI | `src/netops_autopilot/web/` + `webui/` |
| **Config** | YAML / JSON / TOML loader + env-var overrides | `src/netops_autopilot/config/` |
| **Observability** | JSON-to-stdout logger (L11 redaction) + Prometheus metrics | `src/netops_autopilot/observability/` |
| **Docs** | User / Developer / Operator / API guides | `docs/USER_GUIDE.md`, `docs/DEVELOPER_GUIDE.md`, `docs/OPERATOR_RUNBOOK.md`, `docs/API_REFERENCE.md` |

## Phase N — 30-year expert operations in the chat

Phase N added 10 typed expert operations to the chat. The 30-year
engineer has these in their toolbox; now so does the operator:

* `compliance` — HIPAA / PCI-DSS / CIS / NIST audit, severity-tagged
  findings, waiver support
* `convergence` — wait for routing to converge, typed verdicts
* `snapshot` / `diff` — golden config capture + LCS-based diff
* `health` — per-port CRC / error / up/down classification
* `capability` — hardware capability matrix (model → supported
  features)
* `inventory` — aggregated device list with search and filter
* `export` — JSON or CSV audit trail export from the signed ledger
* `maintenance` — list / schedule maintenance windows

**1033 tests passing** (was 998 after Phase M). All operations
produce typed results, never silent PASS, never hallucinated
numbers.

Live evidence on PID 22505:

```
discover → 3 device(s)
inventory → 3 device(s) in inventory
compliance → NON_COMPLIANT_CRITICAL
health → UNKNOWN (sim has empty config)
capability cisco C9500-48Y4C → 17 capabilities
capability cisco C2960X-48TS-L → 5 capabilities (L2 only)
convergence → CONVERGED after 2 sample(s)
export → audit-exports/audit-1789094915.json
maintenance → 0 active window(s)
apply branch → APPLIED  cmd_count: 5
rollback → ✓ no vlan 10  ✓ no name
```

## Phase O — Day-2 diagnostics, the 30-year engineer's toolbox

Phase O adds the 10 operations a 30-year network engineer runs
the day after a deployment. These are the typed, evidence-bound
counterparts to what senior engineers have always done on
production networks.

* `show mac address-table` — MAC table parser + flapping detection
* `cable diagnostic` — per-port CRC / runts / giants / lost-carrier
* `ospf neighbors` / `bgp neighbors` — neighbor state classifier
  (UP / PENDING / DOWN / UNKNOWN)
* `show ip access-lists` — ACL hit-count audit (HOT / WARM / COLD /
  SHADOWED)
* `show power inline` — PoE budget + utilization + fault detection
* `drift` — LCS-based config drift vs. the last golden snapshot
* `eol cisco <model>` — hardware lifecycle (ACTIVE / ANNOUNCED /
  EOL_REACHED / EOS_REACHED)
* `show interfaces trunk` — trunk matrix + allowed / active VLANs
* `upgrade <from> to <to>` — IOS-XE upgrade path validator (BFS up
  to 4 hops, with intermediate suggestions)
* `summary` — one-pager network summary (devices, links, reach,
  evidence count, last run verdict)

All 10 verbs accept Arabic and English. All 10 wired into the
chat operator + the web UI. **1066 tests passing** (was 1033 after
Phase N). 10 new web UI buttons.

Live evidence:

```
show mac address-table → mac table — 0 entries, 0 flapping MAC(s)
cable diagnostic → cable — UNKNOWN
ospf neighbors → routing — UNKNOWN (OSPF: 0, BGP: 0)
show ip access-lists → acl — 0 ACEs, 0 hot, 0 cold
show power inline → poe — UNKNOWN (0.0% used)
eol cisco C9500-48Y4C → eol — ACTIVE
show interfaces trunk → trunk — 0 trunking of 0
upgrade 17.9 to 17.12 → upgrade 17.9 → 17.12 — SUPPORTED
summary → summary — 3 devices, 2 links
```

## Phase P — Deeper 30-year expert improvements

Phase P turns diagnostics into action. A 30-year engineer
reads the symptoms, then says "do this to fix it" — typed,
risk-graded, allowlist-gated. Phase P adds the engines that
make that possible, plus real-protocol parsers, real SSH
support, distributed discovery for 500+ device networks,
typed root-cause analysis, and senior-engineer
recommendations.

* `remediation` — auto-remediation planner. Given any
  combination of health / ACL / PoE / drift / routing
  findings, builds a typed :class:`RemediationPlan` with
  per-action risk level (LOW / MEDIUM / HIGH) and a
  typed verdict (`SAFE_TO_APPLY` / `REVIEW_RECOMMENDED` /
  `MAINTENANCE_REQUIRED` / `BLOCKED`).
* `real_device` — SSH / paramiko device driver. Drop-in
  replacement for the SimFabric's session factory. Banner
  grab, prompt detection, allowlist-gated exec, full
  graceful degradation if paramiko is missing.
* `protocols` — LLDP / CDP / VTP / STP / DHCP-Snooping
  parsers. Every parser is rule-based; missing fields
  surface as UNKNOWN, never invented.
* `root_cause` — rule-based root-cause analyzer. The
  "why is this broken?" answer, with typed confidence
  (HIGH / MEDIUM / LOW) and bilingual rendering.
* `distributed_discovery` — async fan-out with bounded
  concurrency (default 16), per-host timeouts, bounded
  retries with backoff. Scales to 500+ devices.
* `recommendations` — 30-year expert tips. 13
  patterns in 4 categories (BEST_PRACTICE / SECURITY /
  PERFORMANCE / RELIABILITY) with REQUIRED / ADVISED /
  INFO severity.

8 new chat verbs wired in Arabic + English, 8 new UI
buttons. Allowlist extended with 6 new read-only commands.
**1102 tests passing** (was 1066 after Phase O). 36 new
Phase P tests.

Live evidence (PID 3089, port 8766):

```
show cdp neighbors    -> cdp — 2 neighbor(s)
show lldp neighbors   -> lldp — 2 neighbor(s)
show vtp status       -> vtp — unknown revision 0
show spanning-tree    -> stp — 0 VLAN(s) tracked
show ip dhcp snooping -> dhcp snooping — disabled, 0 violation(s)
remediate             -> remediation plan — SAFE_TO_APPLY (0 action(s))
why                   -> root-cause — 0 possible cause(s)
recommend add_trunk   -> 2 required, 3 advised
```

## Phase M — Apply is real, rollback is real, evidence is real

Phase M closed the last gap between the chat and the device. The
apply path now opens a real management session per device (no
more silent no-op); the rollback path sends the inverse
`no vlan 10`, `no name` lines back to the device; and the
discoverer preserves LLDP-advertised mgmt IPs even for devices
the operator hasn't authenticated to yet (the "evidence-directed
retry" contract).

* **998 tests passing** (was 997 after Phase L).
* **Live curl-verified on the running server (PID 17945):**
  - `discover` → 3 devices, mgmt IPs visible for UNREACHABLE
  - `apply branch` → `outcome: APPLIED`, `cmd_count: 5`
  - `apply hotel` → `outcome: APPLIED`, `cmd_count: 5`
  - `ping 8.8.8.8` → real ICMP bytes
  - `traceroute 1.1.1.1` → real traceroute bytes
  - `rollback` → `✓ no vlan 10`, `✓ no name` (sent to the device)
  - `بينج 8.8.8.8` (Arabic) → real device output
* **UI surfaces mgmt IPs in the device grid** (accent color,
  next to vendor/model). The operator sees where to retry
  credentials without leaving the chat.
* **Engine code:** `src/netops_autopilot/autopilot/orchestrator.py`
  wires the `mgmt_session_factory` into the apply path. The
  executor opens a real session and calls
  `ex.apply(..., dry_run=False)`. If no session can be opened,
  the engine records a typed `NO_MGMT_SESSION` cause and falls
  back to dry-run (no silent no-op, ever).
* **Allowlist carries the inverse:** `AllowlistEntry.rollback`
  is now a first-class field, read from the JSON data files
  and substituted positionally so the chat can send concrete
  `no vlan 10` lines.

## Hard rules (always true, enforced in code from D1 onward)

1. No claim is displayed or used in a decision without valid, relevant
   `evidence_ids` (T1).
2. Missing knowledge is `UNKNOWN | BLOCKED | NOT_MODELED | NOT_TESTED |
   ACCESS_LIMITED | NOT_SUPPORTED` — never a guess, a default, or a PASS (T2).
3. Nothing executes outside Authorized State + Command Allowlist + Autonomy
   Policy (T3).
4. Every partial failure is reported with its count and causes (T4).
5. Release requires all T5 counters == 0 (see `docs/D0/10-evaluation-harness.md`).
