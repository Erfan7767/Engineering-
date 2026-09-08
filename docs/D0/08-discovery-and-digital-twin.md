# D0-08 · Layered Discovery & Digital Twin

Status: **ACCEPTED (D0)** · Trace: §10 · ADR-0001, ADR-0002, ADR-0004

## 1. Collector constraints (E02)

Per (device, command): **timeout**, **output budget** (bytes; overflow ⇒
`truncated=true` artifact + typed status), **circuit breaker** (open after k
consecutive failures; half-open probe cadence). Session locking per vendor
+ detection of parallel human sessions ⇒ automation pauses on that device
(TH-13). All collection produces signed Events (D0-04).

## 2. Parsers (E03)

Deterministic only: TextFSM/ntc-templates, Genie parsers, YANG/NETCONF
structured data, vendor REST JSON. **The LLM never sees raw device text.**
Every parser: registered id+version, golden fixtures per vendor/version
(§21), output = Observations with `parse_status`. Parser changes are
versioned; re-parse never mutates history (D0-04 §1).

## 3. Discovery layers and their verification scopes

| Layer | Content | Primary scopes |
|---|---|---|
| L0 Physical | power, PSU, fans, cable/TDR, SFP identity, DOM optical power, PoE budget/draw, speed/duplex, CRC/errors | INTERFACE_EXISTENCE, HARDWARE_INVENTORY |
| L1 Interface | admin/oper, MTU, media, transceiver, counters | INTERFACE_EXISTENCE |
| L2 | VLAN, MAC table, STP (root/roles), LACP, MLAG/vPC, trunk/access, 802.1X, port-security | CONFIGURATION, DIRECT_NEIGHBOR (inputs) |
| L3 | ARP/ND, routing tables, VRF, OSPF/BGP/IS-IS neighbors, static, ECMP, PBR, NAT | IP_ADDRESS, ROUTING_STATE |
| L4–7 Services | DHCP, DNS, HTTP(S), RADIUS/TACACS+, NTP, syslog, SNMP, app reachability | SERVICE_REACHABILITY |
| Security | ACL, firewall/NAT policy, VPN/IPsec, AAA, PKI/certs (expiry) | POLICY_BEHAVIOR, CONFIGURATION |
| Lifecycle | firmware/bootloader/licenses/EoL-EoS/CVE (offline DB, optional update feed) | DEVICE_IDENTITY (extensions) |

Every layer run ends in a terminal status per device: success set, or typed
failures (RETRYABLE/BLOCKED/NOT_SUPPORTED/…). Silent skips are impossible
(FSM-1 guard 1.6). **Identity/hardware** = version + inventory + stack/
chassis + serials (claims with DEVICE_IDENTITY/HARDWARE_INVENTORY scopes).

## 4. Structural models

### Stack / Chassis
`Device ⊃ Chassis|Stack ⊃ Member{serial, slot}`; every `Interface` binds to
a `Member.serial`. Vendor equivalents mapped: Virtual Chassis (Juniper),
IRF (HPE), StackWise/StackWise-Virtual (Cisco). **MLAG/vPC ≠ stack** — they
are multi-device logical constructs modeled in the Logical Twin layer with
their own evidence (LACP/peer-link claims), never collapsed into a stack.

### Port-name normalization
A deterministic normalizer runs **before any matching** (e.g., `Gi1/0/1` ≡
`GigabitEthernet1/0/1`; RouterOS `ether1` as-is; Junos `ge-0/0/1` vs
`ge-0/0/1.0` unit handling). Normalization rules are per-vendor data files
(grown from lab evidence); unmapped names stay raw and are flagged.

### Link Evidence Fusion (FSM-4 inputs)
* Passive ceiling = `DIRECT_NEIGHBOR_PROBABLE`: bidirectional LLDP/CDP match,
  or one-sided advertisement + clean MAC history + port-name correlation +
  time correlation.
* `+ absence of intermediary` (no MAC churn across window, no third-party
  MACs) ⇒ `DIRECT_NEIGHBOR_CONFIRMED`.
* Active proof (link-toggle correlation, TDR, DOM deltas) is **gated**
  (pre-production only, Gate per §13) or replaced by explicit human
  confirmation ⇒ `PHYSICAL_PATH_VERIFIED`.
* Endpoints without LLDP ⇒ `INFERRED`; intermediaries suspected ⇒
  `INTERMEDIATE_SUSPECTED`; disagreements ⇒ `CONFLICTING` (operator-raised).

### Wireless domain model (P0-07)
`Controller ⊃ AP ⊃ Radio ⊃ {SSID/WLAN, VLAN binding, channel/width/power/
DFS, band steering, min RSSI, 802.11k/v/r, WPA2/WPA3/802.1X, RADIUS binding,
guest isolation, captive portal, mesh/backhaul}` + client health
(SNR/RSSI/noise/retry/utilization) + adoption mechanics per vendor
(UniFi L2/L3 inform, WLC adoption, Aruba controller/Instant).

### Site model
`Site ⊃ Rack ⊃ Device`; **multi-site is first-class**, WAN links modeled as
links with their own FSM-4 evidence.

### OOB model (ADR-0004)
OOB network, console server, mgmt VRF, secondary WAN, LTE. Per device:
`primary_path`, `secondary_path`, `recovery_path (tested)`. v1 default:
secondary/recovery = `NOT_CONFIGURED`, honestly.

### Service Dependency Graph (P1-34)
Services declare `depends_on[]` / `provides[]` (e.g., 802.1X → RADIUS →
DNS → NTP → PKI → cert chain). Consumed by the DAG (ordering), Blast Radius
(service impact), and failure orchestration.

## 5. Digital Twin layers (E05)

`Physical | Logical | Operational | Intent | Security | Dependency | Service
| Historical`. Every entity carries cross-layer references and the
`evidence_ids[]` that justify its existence (L02). The Twin is a projection:
it answers "what is the current believed state, and on what evidence";
history queries go to the Ledger. **Gaps List**: every model incompleteness
is explicit (entity present but field UNKNOWN, link INFERRED, layer
NOT_SUPPORTED…) and rendered wherever the model is displayed.

## 6. Outputs consumed downstream

* Blast Radius (E13): entity/service/path graphs.
* DAG (E12): requires/provides from Config IR + service dependencies.
* Reconciliation (E22): canonicalized intended vs observed (needs Platform
  Defaults DB, D2).
* Documentation (E26): prints states and ages verbatim.
