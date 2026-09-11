# Phase V — Execution Closure

**Goal:** make the platform *actually change the network* instead of only
producing a correct preview of what it would change — without weakening a
single safety law.

Every defect below was **reproduced first**, then fixed, then locked by a test
in `tests/test_phase_v_safety.py`. Nothing here is speculative.

---

## 1. The rollback plan was built and then thrown away

`ConfigExecutor._rollback()` looped over the inverse commands and its body
only recorded the `!`-prefixed manual markers. It never called
`session.execute()`. Verified by AST inspection before the fix:

```
CALLS INSIDE _rollback():
    line.strip()
    stripped.startswith('!')
    stripped.startswith('#')
    record.failure_causes.append(f'MANUAL_ROLLBACK_REQUIRED:{stripped}')
=> session.execute present? False
```

Observed behaviour — the device kept `vlan 10` and `name users` while the
record reported a clean rollback:

```
outcome          : APPLIED_PARTIAL
rollback PLAN    : ['no vlan 10', 'no name', 'no vlan 20', 'no name']
ACTUALLY SENT    : show running-config, vlan 10, name users, vlan 20
=> rollback commands actually issued to device: 0
```

**Now:** inverses are issued in reverse order, at the CLI mode depth the
original command ran at, and the outcome is derived from what actually
happened. `ROLLED_BACK` requires every inverse accepted *and* the read-back
hash back at baseline; anything less is `ROLLBACK_FAILED` with
`DEVICE_MAY_BE_LEFT_IN_PARTIAL_STATE`.

```
outcome           : ROLLED_BACK
rollback issued   : 4 | succeeded: 4
device config left: []
before/rollback   : f4ef259f7c8f4d3f / f4ef259f7c8f4d3f
```

## 2. First-token matching defeated the whole allowlist

`_classify_command()` compared only the first word of a command against the
first word of each template, and never consulted `FORBIDDEN`. Twelve commands
that `CommandAllowlist.classify()` correctly rejected were accepted by the
executor:

```
'ip http server'          allowlist=None  executor=CONFIG_REVERSIBLE   <<< BYPASS
'ip nat inside source …'  allowlist=None  executor=CONFIG_REVERSIBLE   <<< BYPASS
'username attacker privilege 15 secret 0 cisco123'
                          allowlist=None  executor=CONFIG_HIGH_RISK    <<< BYPASS
'enable secret 5 $9$EVILHASH'
                          allowlist=None  executor=CONFIG_HIGH_RISK    <<< BYPASS
```

**Now:** `CommandAllowlist.gate()` matches structurally — every literal
segment and the arity must match, placeholders bind by name, `<args>` is an
explicit trailing catch-all, and `CLASS_PRIORITY` evaluates FORBIDDEN and
DESTRUCTIVE first. All twelve are refused; every legitimate rendered line
still passes.

Specificity ranks by **literal characters**, not literal tokens, so
`interface Vlan10` resolves to `interface Vlan<vlan_id>` rather than the
broader `interface <intf>`.

## 3. The rendered config was not valid IOS-XE

The renderer emitted `ip address 10.240.0.1/25`. IOS/IOS-XE requires a dotted
mask and rejects the CIDR form, so the preview shown to the operator would
have been refused by the device. With a correct gate, 6 of the 25 rendered
lines were blocked:

```
BLOCKED  'ip address 10.240.0.1/25'                gate=None
BLOCKED  'switchport trunk encapsulation dot1q'    gate=None
```

**Now:** the IR carries `address` (CIDR, for Junos/RouterOS), `address_ip` and
`address_mask` (for IOS-XE), and each vendor renderer emits the syntax its
platform accepts. `switchport trunk encapsulation dot1q` — which the trunk
renderer always emitted — is now a registered template with an inverse. An
IPv6 zone has no dotted mask, so the parameter stays unbound and the renderer
reports `NOT_MODELED` (T2) instead of inventing one.

```
interface Vlan10
 ip address 10.240.0.1 255.255.255.128
```

## 4. `configure terminal` never reached the device

Mode-transition wrappers were classified as comments and recorded but not
sent, so every config line was typed in **user EXEC mode** on real hardware:

```
sent: ['show running-config', 'enable', 'vlan 10', ...]   # no 'configure terminal'
```

**Now:** wrappers are issued, but only from the closed set
`SAFE_MODE_TRANSITIONS`. Anything else is refused with `UNSAFE_WRAPPER`, so
configuration cannot be smuggled in through the wrapper channel.

## 5. Indentation *is* the CLI mode — and was being ignored

The renderer encodes nesting as indentation. After `vlan 10` / `name users`
the session is in `config-vlan`, so `ip routing` must be preceded by `exit`.
The executor now derives the mode depth from the indentation, inserts the
`exit` commands, and refuses `INDENT_WITHOUT_MODE_ENTRY` when a line is
indented without the previous line having opened a sub-mode. Rollback uses the
same depth model, so `no name` lands inside `vlan 10` and `no vlan 10` in
global config.

## 6. The preview and the applied config were different things

The orchestrator applied `rendered.blocks[0].commands` while
`RenderedConfig.to_text()` — what the operator reads and approves — prints
every block. **Now** both use `_all_commands(rendered)`.

## 7. No change was ever written to the audit ledger

`_record_to_ledger()` called `store.append_event(dict, key_id=…)`. The real
signature is `append_event(event: Event)` and takes a **signed** `Event`, so
the call raised `TypeError` on every single change — and the surrounding
`except Exception: pass` hid it. L13 was violated silently for the whole life
of the module.

**Now:** a signed `Event` plus a content-addressed `RawArtifact` carrying the
full `ChangeRecord`. A failed write records `LEDGER_WRITE_FAILED`; a missing
signing key records `LEDGER_NOT_CONFIGURED`. Neither is ever swallowed.

```
config_change events: 2 | signed: True | chain verified: True
```

## 8. Running-config hashes counted platform noise as change

`show running-config` on IOS prints `Current configuration : N bytes`, so an
unchanged config could hash differently and a correctly restored device could
look unrestored. `normalize_running_config()` now strips header noise,
`!` comment lines and `Last configuration change at` before hashing.

## 9. Real hardware could discover a network and configure none of it

`cli_main._refused_mgmt_factory()` raised `MGMT_PATH_NOT_MODELED`
unconditionally, and `web/server.py` imported `_open_real_management` — a
function that **did not exist anywhere in the codebase**, so the web operator
always fell into `NO_REAL_ADAPTER`. The SSH and telnet transports it needed
were already written, tested, and unused.

**Now:** `access/mgmt_session.py` implements the real path.

- Devices are contacted at management addresses **discovery observed**
  (`DeviceResult.mgmt_addresses`). No observed address ⇒ typed
  `ACCESS_LIMITED`. No address is ever guessed, defaulted, or scanned.
- **Identity is confirmed before any configuration.** The serial is read and
  parsed by the same golden parsers the crawl used, then compared with the
  serial the crawl recorded. Mismatch ⇒ `IDENTITY_MISMATCH` and the session is
  closed. Unreadable ⇒ `IDENTITY_UNVERIFIED`, refused unless the operator
  passes `--allow-unverified-identity`.
- The seed device reuses the already-open console session rather than opening
  a second handle on the same serial port.
- Credentials come from a `getpass`-backed provider, are cached per run, and
  `MgmtCredential.__repr__` redacts both secrets.

## 10. Declared inverses that the allowlist itself forbade

`router ospf <pid>` declares `no router ospf <pid>` as its inverse, but
`no router <args>` sat in `FORBIDDEN` — so enabling OSPF had no automatic
rollback. `CommandAllowlist.inverse_conflicts()` now detects this at load
time; both Cisco conflicts are resolved and the detector reports `[]`.

Undo authorisation is by **provenance**: `is_registered_inverse()` accepts a
string only if it *is* a registered inverse of an applied template and is not
itself FORBIDDEN. The chat rollback path used a first-token shortcut
("it starts with `no` and the head matches, so it is fine") and now uses this.

## 11. `CONFIG_HIGH_RISK` had no stronger gate than `CONFIG_REVERSIBLE`

`enable secret`, `router bgp` and `username … privilege 15` were applied under
the same gate as `vlan 10`. They now require `arm_high_risk()`, which the
orchestrator calls only after the operator types `BOND`.

## 12. Demo scenarios printed nonsense Q&A

`answers[1]` held a site name (`"branch-01"`) where the orchestrator asks for
a **discovered device ref**, and the `blueprint_hint` matched two blueprints
at once, so `elicit()` returned `BLOCKED` and asked a disambiguation question
the script did not answer. Every subsequent answer landed one slot late —
while the run still reported success:

```
Q: On which discovered device does the WAN/ISP terminate? [core-sw2]:
A: ISP fiber DHCP handoff          ← wrong slot
Q: Describe the WAN handoff …
A: STANDARD                        ← wrong slot
```

**Now** the hint is unambiguous, `answers[1]` is `seed-01`, and both properties
are asserted for every scenario so the desynchronisation cannot return.

---

## What is newly runnable

| Command | What it does |
|---|---|
| `netops-autopilot demo --execute` | Full discover → design → render → **apply** → verify → rollback path against the deterministic fabric, BOND gate enforced. Verified: `COMPLETE-APPLIED`, 21/21 and 4/4 commands. |
| `netops-autopilot autopilot --port COM5 --execute` | Same, on real hardware, reaching neighbours over `--mgmt-method ssh\|telnet`. |
| `netops-autopilot chat` | Interactive operator REPL (Arabic/English) with state across turns; `--message` for a single scriptable turn, `--simulate` for the fabric. |

## Test count

`1269 passed, 2 skipped` (was `1232 passed, 2 skipped`). The 2 skips are
`pytest.skip()` calls written into `tests/test_web.py:212` and `:223` for a
known Starlette `TestClient` WebSocket race — pre-existing and documented in
the source, not environment failures.
