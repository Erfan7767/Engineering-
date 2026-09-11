# NetOps Autopilot — User Guide

This guide walks you from a fresh checkout to your first completed
run, end-to-end.

## 1. Install

```bash
# Clone
git clone <repo> && cd <repo>

# Create a venv (Python 3.11+)
python3 -m venv .venv
source .venv/bin/activate

# Install (the bare-bones install — no optional drivers)
pip install -e .
```

The install never pulls in pySerial/FastAPI/Netmiko unless you opt in
to the hardware tier:

```bash
pip install -e '.[hardware]'   # adds pySerial for the console transport
pip install -e '.[web]'        # adds FastAPI for the dashboard
pip install -e '.[all]'        # everything
```

## 2. Verify the install

```bash
PYTHONPATH=src python -m netops_autopilot --help
```

You should see the top-level CLI help with these subcommands:

* `run` — drive a full autopilot pipeline against a probe port
* `report <run.json>` — re-render a saved run report
* `health` — print the engine health (good for shell healthchecks)

## 3. Run the test suite

```bash
PYTHONPATH=src python -m pytest tests/
```

On a clean checkout the suite is **807 passed, 3 skipped** in ~5
seconds. The skipped tests are platform-gated (Windows-only serial
behaviour, etc.) and skip silently on Linux/macOS.

## 4. First blueprint

```bash
PYTHONPATH=src python -m netops_autopilot run \
    --port SIM0 \
    --scenario branch \
    --report-out run.html
```

What this does:

1. **`BOND`** — the engine asks you to type `BOND` to confirm it owns
   the device. The confirm is enforced on every run; no cron, no
   unattended mode (L07 / human-in-the-loop).
2. **`BOOT_PROBE`** — a serial banner probe is sent to `--port`. The
   default SimFabric responds with a deterministic banner so you can
   test the pipeline without a physical device.
3. **`DISCOVERY_A`** — `show version`, `show vlan brief`, `show lldp
   neighbors detail`, etc. (Cisco IOS-XE allowlist). Output is recorded
   to the ledger.
4. **`TOPOLOGY_MAP`** — LLDP + CDP neighbors are merged into a
   topology graph.
5. **`INTENT_ELICITATION`** — the engine asks a small set of yes/no
   questions (use scripted I/O for non-interactive runs).
6. **`DESIGN`** — a typed `IntentObject` is built (vlans, interfaces,
   addressing). Every address is RFC1918-safe.
7. **`RENDER`** — the intent is rendered to vendor-specific config
   previews. The output is a string of Cisco IOS commands, never
   executed.
8. **`EXECUTION_GATE`** — the run is staged but execution is BLOCKED
   unless a lab-verified allowlist grants a vendor's CONFIG_REVERSIBLE
   or CONFIG_HIGH_RISK class. This is **T3** (the master spec's
   proof-of-lab gate).
9. **`REPORT`** — `run.html` is written. Open it in any browser.

## 5. Inspect the ledger

Every action the engine took is in the ledger:

```python
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.ledger.canon import canonicalize
import json, hashlib

store = LedgerStore.open("ledger.jsonl")
for event in store.iter_events():
    print(event["type"], event["actor"], event["at"])

# Chain integrity
print(store.verify_chain().ok)  # True
```

The ledger is append-only; tampering with any event breaks the chain
on the next `verify_chain()`.

## 6. Scripted (non-interactive) runs

The same `run` command, driven by a pre-canned script:

```python
from netops_autopilot.cli.scenarios import make_scenario_io
io = make_scenario_io("hotel")  # answers the elicitation questions
engine = AutopilotEngine(io=io, ...)
```

The four bundled scenarios are `branch`, `leaf-spine`, `hotel`, and
`retail`. They are exercised by the integration tests so a regression
in any of them fails CI.

## 7. Configuration allowlist (T3 / lab-verify)

Execution is **always** blocked until a CONFIG class has lab evidence.
The allowlist lives in
`src/netops_autopilot/config/allowlist.py` and is shipped empty by
default — a fresh install will never auto-execute on a real device.
Once your lab has syntax-verified a vendor's `vlan <id> / name <n>`
template, add it to the reversible class and the engine will allow
the gate to open.

## 8. LLM (L17 / ADR-0005)

The LLM layer is **off by default**. To enable it, set:

```bash
export NETOPS_LLM_PROVIDER=ollama
export NETOPS_LLM_MODEL=llama3
export NETOPS_LLM_HOST=http://localhost:11434
```

When the LLM is invoked, **all payloads are redacted** (L11) before
they leave the host — passwords, API keys, PEM blocks, bearer/basic
auth headers, and dict keys whose name is a known secret pattern.

`build_provider("")` returns a `NullProvider` that raises
`Failure(BLOCKED, "LLM_PROVIDER_DISABLED")` on every `complete()`.
This is intentional: the engine treats the LLM as opt-in, never as
required.

## 9. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `NO_BAUD_RESPONSE: port=...` | Nothing on the serial port, or wrong baud | Check the cable, lower the baud candidates, try a different COM port |
| `NOT_MODELED: discovery layer 'foo'` | The adapter for this vendor has no `show foo` mapping | Add the command to `LAYER_COMMANDS` (Cisco IOS-XE) under the allowlist |
| `CONFIG_ALLOWLIST_EMPTY` at `EXECUTION_GATE` | No lab-verified CONFIG class yet | Add lab evidence to the allowlist, or accept the staged output |
| `LLM_PROVIDER_DISABLED` | LLM is off (default) | Set `NETOPS_LLM_PROVIDER` |
| `BOND_NOT_CONFIRMED: human refused` | You typed `n` (or anything but `BOND`) at the BOND prompt | Re-run and type `BOND` |
| `T5 release gate FAILED` | One of the ten counters is non-zero | Read the counter reasons: `counters.reasons("credential_exposure")` etc. |

## 10. What next?

* Read `docs/API.md` for the full public surface.
* Read `docs/CONSTITUTION.md` (L01–L17, T1–T6) for the design
  contract.
* Open the dashboard (`webui/v2/index.html` in this repo) for a
  live, self-contained UI that drives the same engine.
