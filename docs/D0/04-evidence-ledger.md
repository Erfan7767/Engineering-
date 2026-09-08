# D0-04 · Evidence & Event Ledger (§8)

Status: **ACCEPTED (D0)** · Trace: §8
Append-only, event-sourced, signed. The Ledger is the single historical
source of truth (L08); the Digital Twin is its current-state projection.

## 1. Chain

```
EVENT → RAW_ARTIFACT → PARSER → OBSERVATION → CLAIM → STATE_TRANSITION
```

* No Claim without Observations; no Observation without a RawArtifact; no
  RawArtifact without an Event. Orphans are FATAL integrity errors.
* Re-parsing: new parser version ⇒ new Observations referencing the same
  RawArtifact; old Observations are never mutated (they gain
  `superseded_by`).

## 2. Records (JSON Schemas in `specs/schemas/`)

### Event (`event.schema.json`)
```
event_id, type ∈ {CLI, NETCONF, RESTCONF, SNMP, API, SERIAL, PROBE, USER,
  SYSLOG, TRAP, TELEMETRY},
device_id, session_id, command_or_op,
operator_identity (human RBAC id | engine id),
collector_identity (collector instance + key id),
collected_at          ← collector clock, ALWAYS (Time Authority rule),
collector_clock_status ∈ {SYNCED, UNSYNCED, DRIFT_SUSPECTED},
device_clock_at_collection, device_clock_status,
signature             ← Ed25519 over canonical Event bytes
```

### RawArtifact (`raw_artifact.schema.json`)
`raw_id, event_id, storage_uri, sha256, bytes, truncated`
Content-addressed store; `truncated=true` requires `budget_reason`.

### Observation (`observation.schema.json`)
`obs_id, raw_id, parser_id, parser_version, field, value, parse_status ∈
{OK, MISSING, PARSE_FAILED, UNSUPPORTED_FIELD}`

### Claim (`claim.schema.json`)
```
claim_id, subject_entity, predicate, value,
evidence_ids[]            ← obs/event ids; must be valid & RELEVANT
verification_scope ∈ {DEVICE_IDENTITY, INTERFACE_EXISTENCE,
  HARDWARE_INVENTORY, DIRECT_NEIGHBOR, PHYSICAL_PATH, IP_ADDRESS,
  ROUTING_STATE, CONFIGURATION, SERVICE_REACHABILITY, POLICY_BEHAVIOR,
  INTENT_COMPLIANCE}
status ∈ {CONFIRMED, CONFLICTING, STALE, WITHDRAWN},
freshness_at_use, relevance_check ∈ {PASS, FAIL}
```

### StateTransition (see FSM doc): links Claims → Twin mutations.

## 3. Signing & keys

* Every Event is signed with the collector's **Ed25519** key at creation.
  Key material lives only in the Security Plane (OS keychain + encrypted
  store, §18); engines see key *ids*, never bytes.
* Ledger integrity: hash-chained (each record carries the previous hash);
  the chain head is checkpointed to the Audit Ledger (E25) per session and
  daily.
* Key rotation: collector keys rotate per policy; old signatures remain
  verifiable (key id → public key registry, append-only).

## 4. Time Authority

* `collected_at` is always the collector's clock; device clock is a separate
  field, never trusted for ordering or freshness.
* Collector clock status recorded with every Event; UNSYNCED evidence is
  still stored but freshness decisions treat it conservatively (age is a
  lower bound).
* NTP on managed devices is configured LOCAL_ONLY at bootstrap unless an
  approved source exists; otherwise `TIME_STATUS=DEFERRED` (not a failure).

## 5. Relevance Guard (T1)

A Claim's `evidence_ids` must satisfy **all**:
1. Same device (or explicit cross-device scope declared).
2. Same command/operation that produces the field (command→field registry,
   per vendor/version, maintained with parsers).
3. The field actually parsed (`parse_status=OK`).
Existence of *some* evidence is not relevance. Failed relevance check ⇒
Claim rejected with `relevance_check=FAIL` and counted (`unverified_claims`
if anything downstream referenced it).

## 6. Freshness-per-Decision (T5: `stale_evidence_deployments`)

| Decision | Rule |
|---|---|
| Deploy / Rollback | link & interface & MAC-table evidence age < 60 s, else **re-collect** before proceeding |
| Design | age < 24 h |
| Documentation | any age, **age must be printed** |
| Running-config | **no TTL** — validity via Change Detection: config hash + syslog `CONFIG_I` class + vendor archive log |
| LLDP/CDP neighbor tables | holdtimes read **from the device tables** (defaults 120 s / 180 s only as fallbacks, marked as such) |

Freshness is evaluated **at decision time** and the evaluated age is stored
on the decision record (`freshness_at_use`).

## 7. Retention & privacy

* Raw artifacts immutable; deletion only via a signed retention policy and
  logged as a tombstone (hash remains).
* Credentials are never artifacts: anything matching the secret classifier
  is redacted before storage (counter `credential_exposure`).

## 8. Implementation notes (D1)

* Store: SQLite (single-file, desktop) with optional PostgreSQL profile.
* Hash chain + signatures verified on startup (integrity self-test = FATAL
  on mismatch, L03).
* Ledger API is the only write path; direct SQL writes are forbidden by
  architecture lint.
