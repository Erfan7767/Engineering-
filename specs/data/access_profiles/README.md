# Default Access Profiles — field contract (D0-07 §6)

One JSON file per vendor family: `cisco_iosxe.json`, `routeros.json`,
`junos.json`, `fortios.json`, `arubaos.json`, `unifi.json`.
Each file maps **model (or model family regex)** → profile.

Selection is model-driven, never vendor-name-driven (§9). Profiles with
unverified defaults must carry `"verified": false` and the Collector treats
them as hypotheses to confirm (FAILED confirmation ⇒ ACCESS_LIMITED branch,
not silent retry forever).

## Profile fields

```jsonc
{
  "match": { "vendor": "…", "models": ["exact-model", "^family-prefix.*"] },
  "os_hint": { "os": "ios-xe", "version_constraint": ">=16.9" },   // informational; identity still comes from evidence
  "console": { "present": true, "baud_candidates": [9600, 115200], "flow_control": "none" },
  "ethernet_defaults": [
    { "ip": "192.168.88.1/24", "interface_hint": "bridge1", "verified": true,
      "notes": "RouterOS default bridge address" }
  ],
  "mac_layer": { "protocols": ["MNDP", "MAC_TELNET", "WINBOX"], "enabled_default": "UNKNOWN" },
  "controller_adopt": { "applicable": false },
  "pnp_dhcp": { "applicable": false },
  "auth_defaults": { "mode": "none|password|keybased", "default_account": "admin",
                     "default_password_policy": "NONE_EXPECTED | FACTORY_RANDOM | UNKNOWN" },
  "rollback_mechanism": { "kind": "archive|commit-confirmed|safe-mode|api-backup|checkpoint|controller",
                          "min_version": "…", "status": "SUPPORTED | NOT_SUPPORTED | UNKNOWN" },
  "day0_classifier_ref": "defaults_db/day0_classifiers.json#/<vendor>/<model>",
  "destructive_recovery": [ { "method": "NETINSTALL", "preconditions": ["…"], "gate": "DESTRUCTIVE" } ]
}
```

Rules:
1. Any field whose truth is not documented by the vendor or verified in the
   lab ⇒ `UNKNOWN` (T2) — and the corresponding access path is attempted
   only as an explicitly-labeled hypothesis.
2. `default_password_policy: NONE_EXPECTED` means "device ships with no
   password"; attempting guessed credentials is forbidden (zero-guess, L01).
3. Profiles are versioned; a profile change requires a register entry.

## v1 starter files

Starter profiles (D0 seed, all fields above that are known from vendor
documentation; every uncertain field marked UNKNOWN) ship in this batch:

* `routeros.json` — default bridge IP, MAC-layer protocols, Safe Mode.
* `cisco_iosxe.json` — console-first, archive rollback, ROMMON destructive.
* `junos.json` — commit confirmed, amnesiac/factory note as UNKNOWN.
* `fortios.json` — default management, API backup/restore.
* `arubaos.json` — controller-centric adoption, checkpoint where available.
* `unifi.json` — controller adoption (L2/L3), inform URL mechanics.

Unknown-by-default fields will be filled from lab evidence in D1 (register
items OI-0101… track each gap).
