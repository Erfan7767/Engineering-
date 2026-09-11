# Phase W — A deployed network that actually works

**Status:** DELIVERED · `tests/test_phase_w_deployable.py` (28 cases) + `tests/test_answer_alignment.py` (4 cases)
**Suite:** 1269 → **1301 passed, 2 skipped**
**Preceded by:** [Phase V — Execution closure](phase-v-execution-closure.md)

Phase V made the platform *change* a device safely. That was necessary and not
sufficient. A run could report `COMPLETE-APPLIED` while the result was a network
that would not work: an unsaved configuration, no DHCP, zero end-user access
ports, and a switch the operator could never get into. Phase W closes the gap
between "the executor succeeded" and "the network works".

Every defect below was **reproduced before it was fixed**, and is locked by a
test. Where a fix is guarded by a mutation check, that is stated.

---

## W1 — The configuration was never persisted

**Defect.** No persist command existed anywhere in the repository: not in the
renderers, not in the allowlists, not in the executor. Cisco loses the running
configuration on reload; Junos' `commit confirmed 2` actively *reverts* it after
two minutes. The platform reported a permanent change that was not permanent.

**Fix.**

* Renderer `wrappers.persist`: cisco `write memory`, junos `commit`, routeros
  `[]` (RouterOS auto-persists; an empty list is a deliberate statement, not an
  omission).
* New allowlist class `CONFIG_PERSIST`, deliberately **kept out of
  `CONFIG_CLASSES`** via `PERSIST_CLASSES`. Persisting is not a reversible
  configuration statement, so it must not be reachable through the change gate
  or through the rollback planner.
* `RenderedConfig.persist` + a `! persist` section in `to_text()`.
* `ConfigExecutor._persist()` runs **only after verification passes** and
  **never during rollback** — saving a half-applied state would make the damage
  permanent. Every command must gate as `CONFIG_PERSIST`; anything else is
  refused rather than sent, so this channel cannot smuggle configuration past
  the gate.
* Failure is loud: `ChangeOutcome.PERSIST_FAILED`, surfaced as
  `verdict="PERSIST_FAILED"` / `final="BLOCKED-PERSIST-FAILED"`.

Every DHCP entry was added with its inverse, and `inverse_conflicts()` returns
`[]`.

## W2 — No DHCP pool was ever emitted

**Defect.** Clients got a link and no address. There was no DHCP feature in any
renderer and no DHCP line in any allowlist.

**Fix.** Cisco `dhcp` feature; `_dhcp_exclusion()` reserves the first
`DHCP_RESERVED_HOSTS = 10` usable addresses, always extends to cover the
gateway, never empties a pool (a `/30` yields `.1`–`.2`), and returns `None` for
IPv6 (SLAAC/RA, not an IPv4 pool). One pool per INTERNAL/GUEST/DMZ zone.

Two wire-level mistakes were found and fixed while proving this:

* **`dns-server` is space-separated on IOS.** The renderer produced
  `dns-server 1.1.1.1, 9.9.9.9`, which the device rejects. Operators naturally
  type commas, so the comma is normalised in the design engine, not at the wire.
* **The optional-line marker must not eat indentation.** A template line
  prefixed with exactly `"? "` is skipped when its placeholder is unbound.
  Indentation encodes CLI nesting, so only those two characters are stripped —
  `cmd[1:].lstrip()` silently moved `dns-server` out of `ip dhcp pool` mode.
  Unmarked lines still raise `KeyError` ⇒ typed `NOT_MODELED`; an optional line
  must never be able to mask a missing required one.

Verified rendered block (demo, `seed-01`):

```
ip dhcp excluded-address 10.240.0.1 10.240.0.10
ip dhcp pool users
 network 10.240.0.0 255.255.255.128
 default-router 10.240.0.1
 dns-server 1.1.1.1 9.9.9.9
```

## W3 — Access-port assignment was structurally guaranteed to be zero

**Defect.** Nothing in the repository collected the port inventory, so
`harvest_interfaces()` could only ever name *neighbour* ports — exactly the
ports reserved for infrastructure. The demo reported `0 access ports`. On top
of that, ports were ordered lexicographically, so `gi1/0/10` sorted before
`gi1/0/2` and the wrong VLAN landed on the wrong socket; and every zone got
exactly **one** port regardless of planned size.

**Fix.** `parsers/interface_inventory.py::CiscoIosXeInterfacesStatusParser`,
registered as the 14th catalog builder; `show interfaces status` added to the
crawl plan; `DeviceResult.interface_table`; `harvest_interfaces()` prefers the
inventory. Natural `port_sort_key()`; `_zone_weights` / `_weighted_cycle` spread
free ports in proportion to planned host counts (deterministic, replay-identical).
Demo: **0 → 10 access ports** (users 6 : voice 4).

Two column-splitting bugs were fixed in the parser. In a fixed-width CLI table a
column spans start-of-heading to start-of-next-heading, and the last column runs
to the end of the *data* line; and `str.split()` is wrong because the `Type`
column contains spaces (`10GBase-SR SFP+`). Both truncated every value. No
header ⇒ both fields MISSING, never an empty table.

## W4 — Verification proved the configuration *moved*, not that it was right

**Defect.** `_verify_change()` checked two things: no syntax-error marker, and
the running-config hash changed. Neither proves the intended state exists. A
line the device parsed and ignored, or a later line that overwrote an earlier
one, both leave a different hash and a wrong network — reported as verified.

**Fix.** The readback text is now compared against the plan:

* every applied line whose class is in `CONFIG_CLASSES` must be **present** in
  the normalized running-config, else `VERIFY_STATE_ABSENT:<line>` ⇒ rollback;
* a `no …` line is checked the other way round — the negated form must be
  **gone** (`VERIFY_STATE_STILL_PRESENT`);
* mode transitions (`enable`, `configure terminal`, `end`, `exit`) leave no
  configuration line and are classified outside `CONFIG_CLASSES`, so they are
  excluded and **counted as unchecked, never as verified**;
* coverage is reported on the record: `ChangeRecord.state_checked` /
  `state_absent`, carried into `to_dict()`. Zero coverage with a non-zero
  command count is visible, not assumed away.

Rollback needed no equivalent change: it is already verified by
`rollback_hash == before_hash`, i.e. exact equality with the pre-change
baseline, which is strictly stronger than a presence check.

**Mutation-checked.** Removing the state check fails 3 tests.

## W5 — A credential refusal was permanent

**Defect.** Discovery reported `ACCESS_LIMITED` and the design excluded the
device from the managed set — forever. Nothing ever offered a retry, so a
network with one differently-credentialed switch stayed permanently
half-configured while the run still reported success.

**Fix.** `orchestrator._phase_access_retry()`, bounded at `max_rounds=2`, runs
directly after discovery so a device that unlocks is re-crawled before the map
is built. Both directions are honest: a device that unlocks joins the managed
set with its identity confirmed; a device that still refuses stays excluded
**and is announced**.

Two decisions inside it are deliberate:

* **It is not `io.confirm`.** A confirmation whose default is "yes" is not a
  confirmation. Supplying credentials to a device and re-probing it is a
  security-relevant act, so it requires an explicit affirmative; silence
  declines. (`grants_access_retry()`.)
* **A declined retry writes no phase record.** Discovery did not run again, so a
  second `DISCOVERY_A` row would put a phase in the report that no work
  corresponds to. The exclusion is already announced where it belongs: the gaps
  list (`DEVICE_UNREACHABLE`), the design role reason (`UNMANAGED_NEIGHBOR`),
  and the console.

Effect on the demo: `access-sw1` goes `UNMANAGED_NEIGHBOR → L2_ACCESS`, and
`demo --execute` applies **3/3** devices instead of 2.

---

## Defects found while proving the above

These were not on the Phase W list. Each was found by reading output rather than
by reading code, which is the argument for running the thing.

### The design announced a trunk it never configured

`_uplinks()` assigned **one uplink per device** — "the best discovered link
only" — so a router fanning out to two switches announced both links in the plan
and configured only one. With three devices the core switch was cabled to
`seed-01:gi1/0/1` while that socket stayed in its default access state on
VLAN 1: the plan said trunk, the device said access, and no test failed.

Two defects in one loop:

* the `break` sat **inside** the link loop, so `candidates` never held a second
  entry and the `.sort()` by FSM-4 grade below it was **dead code** — while the
  emitted `reason` claimed grade-based selection with a `(peer, port)`
  tie-break. That is a false statement about what the engine did.
* every end of every link now gets an assignment, keyed by `(device, local
  port)`, best grade per port. A port with no interface evidence is skipped
  rather than guessed.

Now asserted for both retry paths: every uplink end is in trunk mode in the
render, and no port is both trunk and access. **Mutation-checked** — reinstating
the one-per-device rule fails 2 tests.

### The test substrate fabricated a device identity

`access-sw1` was backed by `core_sw2_session()`. Unlocking it made the device
answer with core-sw2's hostname, serial **and LLDP table**, and the design then
planned two different neighbours onto one seed socket — one physical port, two
links. Fabricated evidence in the substrate is as bad as fabricated evidence in
the product, because the product's tests are graded against it. `access-sw1` now
reports itself: `C9200-24T`, `FCW1832A0QQ`, its own LLDP reciprocal, so the link
is corroborated from both ends and the `ONE_SIDED` gap legitimately clears.

### A prompt the demo answered and then ignored

`cli_main` handed the engine `fabric.open` — a bound method, which does not
carry the `grant()` hook the retry loop uses to model the operator supplying
working credentials. The demo therefore printed the retry question, took the
`y`, printed nothing, and left `access-sw1` outside the managed set — while
still reporting `COMPLETE-STAGED`. A prompt whose answer is silently discarded
is worse than no prompt, because it reports a decision that was never acted on.
Now covered by driving the real command entry point rather than the engine,
since the wiring was what was broken. **Mutation-checked.**

### Four hand-written answer lists

The scripted answer sequence was duplicated in `cli/scenarios.py`,
`harness/runner.py`, `test_autopilot_e2e.py` and `test_executor_e2e.py`. Adding
one question shifted all four by a slot, and `ScriptedIO`'s "default to `y` when
the queue is empty" hid it — the demo printed nonsense Q&A while still reporting
success. `autopilot/answer_script.py` is now the single source of truth:
`ANSWER_SLOTS` names the questions in the order they are asked, `access_retry`
and `intent` are **required** arguments, and `make_scenario_io` splices nothing.
`tests/test_answer_alignment.py` asserts no scenario leaves an answer
unconsumed, every scenario resolves to its intended blueprint, and the DNS
answer reaches the DNS question.

---

## Reproduce

```bash
PYTHONPATH=src python3 -m netops_autopilot demo             # staged
PYTHONPATH=src python3 -m netops_autopilot demo --execute   # COMPLETE-APPLIED
python3 -m pytest -o addopts="" -q                          # 1301 passed, 2 skipped
```

## Still open

* `specs/data/renderers/` covers **cisco_iosxe, junos, routeros** only. arubaos,
  fortios and unifi have allowlists and access profiles but no renderer, so they
  cannot be configured — this is a coverage gap, not a correctness claim.
* The hardware lab gate (OI-0005) remains open by construction. Everything above
  is proven against the deterministic simulated fabric and the golden fixtures.
