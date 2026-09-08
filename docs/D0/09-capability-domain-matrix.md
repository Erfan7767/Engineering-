# D0-09 · Capability Domain Matrix (AUTOMATED / ASSISTED / HUMAN_TASK)

Status: **ACCEPTED (D0)** · Trace: §1, P1-26
Every platform capability is classified in exactly one domain. The
classification is announced to the operator at task start and printed in
documentation. The machine-readable seed is
`specs/data/capability/capability_domain_matrix.json`.

Rules:
1. A capability may only be AUTOMATED if every engine/adapter/evidence path
   it needs exists, is capability-matrix-confirmed, and the Autonomy Policy
   for the scope allows its gate class.
2. ASSISTED = platform does design/generation/validation; one or more human
   steps are mandatory and enumerated.
3. HUMAN_TASK = physically beyond software; platform emits precise
   instructions and **verifies the outcome with evidence afterwards** (this
   verification itself is AUTOMATED).
4. Reclassification requires a register entry + harness evidence.

## Matrix (v1 seed)

| # | Capability | Domain | Rationale / human steps |
|---|---|---|---|
| C01 | Device discovery & evidence collection | AUTOMATED | Read-only collectors within budgets. |
| C02 | Physical installation (rack, power, cabling) | HUMAN_TASK | Instructions generated; verified via carrier/link/MAC evidence after. |
| C03 | Console/serial hookup | HUMAN_TASK | Verified via session-open evidence. |
| C04 | Day-0 bootstrap | AUTOMATED (policy-gated) | Reversible set; Post-Bootstrap Baseline captured. |
| C05 | Identity & hardware inventory | AUTOMATED | Multi-field cross-check claims. |
| C06 | VLAN/L2 design & apply | AUTOMATED (M2+ gates) | Rollback-backed; IR reversibility-tagged. |
| C07 | Routing (static/OSPF/BGP) design & apply | AUTOMATED (M2+ gates; HIGH_RISK core-plane parts M3-only per policy) | Modeled coverage gates apply. |
| C08 | Wireless design (SSID/security/RF) | ASSISTED | RF site realities require human site judgment; platform designs/validates; human confirms placement/power classes. |
| C09 | Wireless apply (controller-managed) | AUTOMATED | Via controller APIs; revision rollback. |
| C10 | Firewall policy design & apply | AUTOMATED with ASSISTED sign-off for production zones | Blast radius typically HIGH_RISK. |
| C11 | AAA/802.1X/RADIUS rollout | ASSISTED | Depends on external identity systems; human coordinates IdP/RADIUS endpoints. |
| C12 | ISP coordination (circuits, peering, PPPoE creds) | HUMAN_TASK | Platform prepares configs & verifies service reachability after. |
| C13 | Hardware replacement (failed units) | HUMAN_TASK | Platform detects (L0 evidence), emits replacement steps, re-verifies serials/identity after. |
| C14 | Firmware upgrade | AUTOMATED with gates | Full Change lifecycle incl. rollback image + window (D5 Lifecycle Engine). |
| C15 | License management | ASSISTED | Portal/vendor steps human; platform tracks state & expiry. |
| C16 | CVE assessment | AUTOMATED (offline DB; feed connector optional) | Findings are evidence; remediation = new Change. |
| C17 | Backup/restore of configs | AUTOMATED | Artifact store + hashes. |
| C18 | Destructive recovery (netinstall/rommon/factory) | HUMAN_TASK (gate DESTRUCTIVE) | Platform never executes; instructions + post-verification only. |
| C19 | Monitoring & alerting | AUTOMATED | Baselines + collector set. |
| C20 | Drift detection & classification | AUTOMATED | Remediation routes through gates (ASSISTED at HIGH_RISK+). |
| C21 | Documentation generation | AUTOMATED | From observed state only; ages printed. |
| C22 | Credential rotation | ASSISTED | Human approves scope/timing; platform executes where API exists, else instructions. |
| C23 | Certificate lifecycle (PKI) | ASSISTED | External CA interactions human unless local CA configured (connector). |
| C24 | Physical path verification | ASSISTED | Platform proposes gated active tests; human confirms or authorizes toggle tests (pre-production). |
| C25 | WAN failover testing | AUTOMATED (pre-production, gated) | Probe-managed with rollback-on-fail. |

## Enforcement

* The Autonomy Authority (E14) consults this matrix: a requested operation
  classified ASSISTED/HUMAN_TASK cannot resolve to AUTO_EXECUTE regardless
  of mode or policy.
* The UI prints the domain badge for every task; documentation includes the
  HUMAN_TASK completion list with its verification evidence (§16).
