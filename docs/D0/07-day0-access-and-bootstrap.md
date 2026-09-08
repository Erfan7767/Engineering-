# D0-07 · Day-0 Access, Bootstrap & Destructive Recovery Gating

Status: **ACCEPTED (D0)** · Trace: §9 · ADR-0004, ADR-0007

## 1. Pre-flight (S0)

Ordered checklist, each step producing evidence (PROBE events):

1. Enumerate COM ports; auto-baud negotiation on the selected port.
2. Enumerate NICs; confirm link/carrier on the segment facing the device.
3. Detect USB adapters (serial & NIC) — warn on unpowered hubs (v1: direct
   connect per ADR-0004).
4. **User confirmation checkpoint**: operator confirms the mapping
   "this port/NIC ↔ this physical device" (identity binding moment;
   recorded as a USER event with operator identity).

## 2. Access methods — chosen from MODEL + HARDWARE INVENTORY

`SERIAL_CONSOLE | ETHERNET_DEFAULT_PROFILE | MAC_LAYER (MNDP/MAC-Telnet/
WinBox) | CONTROLLER_ADOPT | PNP_DHCP | OOB_CONSOLE_SERVER`

Selection rule: the method comes from the **Default Access Profile of the
identified model** (`specs/data/access_profiles/*.json`). Vendor-name
conditionals like "Cisco ⇒ 192.168.1.1" are forbidden; the profile states
the facts per model family (default IP, ports, transport, auth mode).
OOB_CONSOLE_SERVER is NOT_CONFIGURED in v1 deployments (ADR-0004).

## 3. Destructive recovery — separate class

`NETINSTALL | ROMMON_RESET | FACTORY_RESET_BUTTON | BOOTLOADER_RECOVERY`

* Gate class **DESTRUCTIVE** ⇒ human decides in every mode (HUMAN_ONLY).
* Never auto-selected by any engine, including the Failure Orchestrator
  (FSM-5 escalation may *propose* reaching L5, but entering L5 requires the
  human gate).
* Each destructive method's profile lists preconditions (e.g., Netinstall
  requires L2 reachability + specific boot sequence) and produces
  HUMAN_TASK instructions when preconditions need hands.

## 4. Day-0 state classifier

`FACTORY_DEFAULT | FACTORY_LIKE | CONFIGURED | ACCESS_LIMITED |
PASSWORD_LOCKED | RECOVERY_REQUIRED | UNKNOWN`

Criteria are **vendor/version-specific** (stored in
`specs/data/defaults_db/day0_classifiers.json`, grown per lab evidence):
e.g., default-credential acceptance + empty config markers ⇒ FACTORY_DEFAULT;
banner/config present ⇒ CONFIGURED; auth reject ⇒ PASSWORD_LOCKED; boot
interrupt/monitor mode ⇒ RECOVERY_REQUIRED. No criteria match ⇒ UNKNOWN
(feeds FSM-1 branches; never "assume factory").

## 5. Bootstrap (reversible, policy-gated)

Order (each step verified before the next):
1. hostname (from site model),
2. temporary management IP on an **isolated** management segment,
3. enable SSH (keys generated platform-side),
4. enable LLDP,
5. create temporary local account — secret stored **only** in the Vault,
   referenced by id, rotation scheduled,
6. enable the vendor's own rollback machinery where it exists
   (e.g., Cisco `archive config`),
7. NTP = LOCAL_ONLY, else `TIME_STATUS=DEFERRED` (never a failure).

**Post-Bootstrap Baseline** = the configuration snapshot taken immediately
after step verification; it is the rollback target for the bootstrap change
and for early-stage recovery (FSM-3 target).

## 6. Access Profiles JSON contract (per model family)

See `specs/data/access_profiles/README.md` for the field contract and the
six v1 starter profiles (one file per vendor family, model-keyed).

## 7. Outputs consumed downstream

* FSM-1 transitions 1.1–1.5 and branch entries.
* Device record initialization in the Inventory (identity claims pending
  DISCOVERED).
* Risk note for direct-connect lockout (ADR-0004 §4) surfaced at ARMED gates.
