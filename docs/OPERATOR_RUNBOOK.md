# NetOps Autopilot — Operator Runbook

**Audience:** the operator on call when something goes wrong during a run.

This runbook is organized by symptom. Find the symptom, follow the recipe.
Every recipe ends with "if this didn't fix it" — escalation path.

---

## A. Discovery problems

### A.1 `NO_BAUD_RESPONSE` on the console

**Symptom:** the BOND phase succeeds, BOOT_PROBE then blocks with
`NO_BAUD_RESPONSE: port=COM5 candidates=(9600, 115200)`.

**Probable causes (in order of likelihood):**

1. **Wrong port.** On Windows, open Device Manager → Ports (COM & LPT) and
   confirm the COM number. On Linux, `ls /dev/ttyUSB* /dev/ttyACM*`.
2. **Wrong baud.** Add `--port COM5` and use the access profile's baud
   for that vendor (Cisco default 9600, Juniper 9600, etc.). If unsure,
   try 115200 second.
3. **Cable issue.** A USB-Serial cable that requires a specific driver
   (FTDI, CH340, CP210x) — check the cable's vendor and install the
   driver if needed.
4. **Device is unpowered or the console port is wrong.** Double-check
   the physical layer.

**If none of the above applies:** capture the bytes with another tool
(`miniterm.py`, `putty`) and confirm the device is actually emitting
characters. If it is, file an issue with the captured bytes — the
allowlist or vendor detection may need tuning.

---

### A.2 `FAMILY_UNKNOWN` after a clean banner

**Symptom:** the BOOT_PROBE phase asks for the vendor family
interactively and the platform doesn't recognize a value you typed.

**Resolution:** the supported families are exactly:

* `cisco/ios-xe`
* `junos`
* `routeros`
* `fortios`
* `arubaos`
* `unifi`

Type one of these **exactly** (lowercase, with the slash for Cisco). If
the device is none of those, the v1 catalog doesn't support it yet —
file an OI (open item) in the issue tracker.

---

### A.3 `INTENT_UNKNOWN` after the elicitation prompt

**Symptom:** the orchestrator asks "What kind of network do you want to
build?" and your free-form answer doesn't match any blueprint.

**Resolution:** the available blueprints are listed in
`engines/blueprints.py` (BRANCH_OFFICE, SMALL_OFFICE, GUEST_OFFICE,
CAMPUS, DATACENTER, SECURE_OFFICE). Try phrasing your request closer
to a blueprint name, or answer with the ID. The CLI prints the menu
every time the answer is unknown.

---

## B. Run-phase problems

### B.1 The run blocks at BOND

**Symptom:** the CLI prints `[BOND] HUMAN_DECISION` and never proceeds.

**Cause:** the operator hasn't typed `y` to confirm the physical binding.
The console is waiting for input.

**Resolution:** type `y` and press Enter. If you typed something else
(`n`, empty), the run aborts with `OPERATOR_DID_NOT_CONFIRM_BINDING`.

---

### B.2 The run is stuck at EXECUTION_GATE

**Symptom:** the report says `Final: COMPLETE-STAGED` and the
EXECUTION_GATE detail is `CONFIG_ALLOWLIST_EMPTY: ...`.

**This is by design, not a bug.** The constitution (T3) requires
lab-verified command syntax before any CONFIG class is allowed to
execute. The run still produced all the previews; the gate is doing
its job. Hand the previews to a human operator, or populate the
allowlist classes with lab evidence to unlock the gate.

---

### B.3 The run aborts with `BLOCKED-DAY0`

**Symptom:** the day-0 state is `PASSWORD_LOCKED` or `RECOVERY_REQUIRED`.

**Resolution:** this is a `HUMAN_TASK` — the device needs a human at
the console to set initial credentials. The orchestrator's output
lists the exact steps. Perform them, then re-run.

---

## C. Web UI problems

### C.1 "● offline" badge stays red

**Symptom:** the web UI's top bar shows `● offline` and never goes green.

**Causes:**

1. The server isn't running. Start it: `python -m netops_autopilot webui --port 8765`.
2. Wrong port. The UI defaults to `http://localhost:8765`; if the server
   listens elsewhere, pass `?api_base=http://host:port` in the URL.
3. CORS / cross-origin. The UI is designed for same-origin; if you open
   the HTML file directly from disk, set `api_base` explicitly.
4. The server is running but blocked on import errors. Check the
   server's stdout.

---

### C.2 `401 missing Bearer token` from the API

**Symptom:** the API returns 401 on every request.

**Cause:** the server was started with `NETOPS_API_KEY=...` and the UI
isn't passing the token.

**Resolution:** append `?api_key=<your-key>` to the UI's URL, or unset
`NETOPS_API_KEY` in the server's environment.

---

## D. Configuration problems

### D.1 `CONFIG_YAML_DRIVER_MISSING` on startup

**Symptom:** `python -m netops_autopilot config --path foo.yaml` errors.

**Resolution:** `pip install pyyaml`. The platform refuses to silently
fall back to a different format (L01 / T2).

---

### D.2 `CONFIG_AUTONOMY_MODE_INVALID`

**Symptom:** config validation rejects the `autonomy_mode` field.

**Resolution:** the valid values are `M1`, `M2`, `M3`, `M4`, `M5`. v1
defaults to `M3` (Controlled Autonomous). Higher modes are reserved
for v1+ until the safety case is signed.

---

## E. Escalation

When a runbook recipe doesn't fix the issue, capture and attach:

1. The full terminal transcript (with `--report-dir` output).
2. The HTML report under `report-dir/<run-id>.html`.
3. The JSON report under `report-dir/<run-id>.json`.
4. The ledger file (`netops-ledger-*.sqlite3`) — but **only if you can
   share it**: it may contain signed events with device identifiers.
5. The vendor-family + access profile in use.

Then file an issue with the captured bundle. Don't open a fresh run
without reviewing the previous report — repeat errors usually mean
the constitution is doing its job and a more invasive change is
required (always go through the Open Items Register).
