# Command Allowlists — contract (D0, populated from D1)

Per-vendor allowlist files live here: `cisco_iosxe.json`, `routeros.json`,
`junos.json`, `fortios.json`, `arubaos.json`, `unifi.json`.

## Classes (executed only through adapters; checked by E15 executor)

| Class | Meaning | Allowed modes |
|---|---|---|
| `READ_ONLY` | state queries producing evidence; budgets enforced | all modes incl. M0 |
| `CONFIG_REVERSIBLE` | changes classified REVERSIBLE_BY_REPLACE by the Config IR | ≥ M2 with gates per §13 |
| `CONFIG_HIGH_RISK` | touches mgmt plane / routing core / AAA | HIGH_RISK gate; human in M0–M2, policy-allowed in M3 |
| `DESTRUCTIVE` | destructive recovery (§9) | human only, every mode |
| `FORBIDDEN` | never executed (e.g., erase/format, credential dumps) | none |

## Rules

1. Allowlist entries are exact command templates with typed argument slots
   (no free-text tail). Template match failure ⇒ BLOCKED (L10).
2. The authoritative command→field registry (for the Relevance Guard,
   D0-04 §5) is generated from the same files in D1 — one source of truth.
3. Adding an entry requires: parser exists (golden fixture), capability
   matrix row exists, register entry recorded.
4. Per-device runtime narrowing: if the Capability Matrix says NO for
   (model, version, feature), matching entries are suppressed regardless of
   the static allowlist.

## D0 seed

Each v1 file seeds: (a) the class skeleton, (b) a starter READ_ONLY set
covering identity + discovery layers (§10 L0–L3), explicitly marked
`"status": "seed-verify-in-lab"`. Full matrices land in D1/D2 with golden
fixtures; nothing outside the allowlist can execute at any point.
