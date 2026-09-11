# NetOps Autopilot — Developer Guide

**Audience:** engineers extending the platform (new vendors, new engines,
new transports, new UI surfaces).

> Read [`docs/D0/01-constitution-laws-and-truth-standard.md`](../D0/01-constitution-laws-and-truth-standard.md)
> first. Every code change must respect L01–L17. The constitution is not
> a guideline — it is enforced by tests.

---

## 1. Repository layout

```
src/netops_autopilot/
├── __main__.py              # python -m entry point
├── cli_main.py              # the operator CLI (argparse + sub-commands)
├── cli/                     # CLI enhancements
│   ├── io.py                # ScriptedIO, ConsoleIO
│   ├── pretty.py            # colored panels, tables, progress bars
│   └── scenarios.py         # built-in demo scenarios
├── access/                  # transport layer (console, SSH, telnet)
│   ├── serial_transport.py
│   ├── ssh_transport.py
│   ├── telnet_transport.py
│   ├── transport_factory.py
│   ├── allowlist.py
│   ├── collector.py
│   └── day0.py
├── adapters/                # vendor-specific adapters (one package per vendor)
├── agents/                  # LLM agents + context builder + claim verifier
├── autopilot/               # the orchestrator that ties everything together
├── config/                  # YAML/JSON/TOML config loader
├── core/                    # primitives: ids, budgets, counters, failures, timeauth
├── engines/                 # the 30+ business engines
├── fsm/                     # the 5 finite-state machines (5 FSMs, 93 guarded transitions)
├── harness/                 # the evaluation harness (E30)
├── ledger/                  # signed event-sourced ledger
├── observability/           # JSON logger + Prometheus-compatible metrics
├── parsers/                 # text → structured (per-vendor)
├── policy/                  # authority table
├── reconcile/               # canonicalization + drift detection
├── reporting/               # HTML + JSON report writers
├── web/                     # FastAPI server (REST + WebSocket)
└── webui/                   # path resolver to the static web UI
```

The single-page web UI lives in `webui/index.html` (root of the repo).
It is intentionally framework-free so it works in any browser with no
build step.

---

## 2. The constitution, in 60 seconds

The platform operates under 17 laws (L01–L17) and 6 truth standards
(T1–T6). Highlights:

* **L01 ZERO-GUESS** — engines are deterministic; an LLM can never fill a
  fact field. Parsers never synthesize values; a missing field is an
  Observation with `parse_status=MISSING`.
* **L02 EVIDENCE-OR-STATE** — Twin nodes exist only via `STATE_TRANSITION`
  records backed by Claims.
* **L03 NO SILENT FAILURE** — every engine returns a typed `Failure`
  (`RETRYABLE | BLOCKED | ROLLED_BACK | PARTIAL | MANUAL_REQUIRED | FATAL`).
* **L06 HUMAN_ONLY** — `IRREVERSIBLE | DESTRUCTIVE | MANAGEMENT_PATH_TOUCHING
  | NOT_MODELED_HIGH_RISK` are decided by a human **in every Autonomy Mode**,
  even M4/M5. The set is a compile-time constant the policy signer cannot
  override.
* **T1** — no claim is displayed without valid `evidence_ids`.
* **T2** — knowledge gaps are typed (`UNKNOWN | BLOCKED | NOT_MODELED |
  NOT_TESTED | ACCESS_LIMITED | NOT_SUPPORTED`), never guessed.
* **T3** — no execution outside Authorized State + Command Allowlist +
  Autonomy Policy. The release gate keeps `unauthorized_changes == 0`.

Read [`docs/D0/01-constitution-laws-and-truth-standard.md`](../D0/01-constitution-laws-and-truth-standard.md)
for the full text.

---

## 3. Adding a new vendor adapter

Each vendor lives in its own sub-package of `src/netops_autopilot/adapters/`
and must:

1. Define an `Adapter` class implementing the `Adapter` interface
   (see `adapters/interfaces.py`).
2. Ship an allowlist JSON in `specs/data/allowlists/<vendor>.json`
   (schema in `specs/schemas/`).
3. Ship at least one golden parser fixture in
   `tests/fixtures/golden/<vendor>/` and the corresponding parser test.
4. Be registered in `adapters/registry.py` and
   `cli_main._real_session_factory` paths as needed.

Linting for new code: any new failure path **must** raise a typed
`Failure(BLOCKED|...)` with at least one `cause`; silent `except: pass`
is rejected by the no-silent-failure rule.

---

## 4. Adding a new transport

Transports implement the `ExecSession` protocol (`open / execute / close`).
A new transport should:

1. Live in `src/netops_autopilot/access/<name>_transport.py`.
2. Use lazy imports for any heavy dependency (Netmiko, asyncssh, ...) so
   the module remains importable when the driver is missing.
3. Raise a typed `Failure(BLOCKED, "DRIVER_UNAVAILABLE: ...")` when the
   dependency isn't installed (this is the convention, see
   `ssh_transport._netmiko_factory`).
4. Be wired into `access/transport_factory.py` for priority.
5. Have at least 10 unit tests using the in-process `Fake*Channel` mock
   to keep CI fast and deterministic.

---

## 5. Adding a new engine

Engines are pure functions of their inputs (plus the shared ledger/twin).
The convention:

```python
def my_engine(input: MyInput) -> MyResult | Failure:
    """L01: deterministic, evidence-bound, typed output."""
    if not is_valid(input):
        return blocked("MY_INPUT_INVALID: ...")
    # ... pure logic ...
    return MyResult(...)
```

Every engine result is one of:

* a successful value, **or**
* a `Failure` with at least one cause (L03).

Engines must never write to the ledger directly. They return observations
and let the orchestrator decide what to persist. This keeps the engines
testable without I/O and makes the ledger the single source of truth (L08).

---

## 6. The evidence ledger

`ledger.store.LedgerStore` is a thin wrapper over sqlite3 with one extra
guarantee: every event is signed with an Ed25519 key and the events form
a hash chain. `store.verify_chain()` returns `{"ok": True, "events": N}`.

Three counters always live in the ledger and feed the release gate:

* `unverified_claims` (T1)
* `unsupported_pass` (T2)
* `unauthorized_changes` (T3)

The full T1–T6 + L11 + cleanup + gate-bypass + stale-evidence + mgmt-path
set is exposed as a Prometheus registry in
`observability.metrics.MetricsRegistry`. Call `reg.scrape()` to get the
text payload.

---

## 7. Tests

* `pytest tests/` — the full suite. **All tests must pass before any
  merge.** No skipped tests in stable code (use `pytest.skip` only with
  a written justification in the test docstring).
* Tests are co-located with the code they cover (`tests/test_<module>.py`).
* `tests/test_*_transport.py` use the in-process `Fake*Channel` mocks
  for determinism — no live network.
* `tests/test_web.py` uses `fastapi.testclient.TestClient` (no live
  HTTP server).
* `tests/support/loopback.py` and `simfabric.py` are the simulation
  fabric for the autopilot e2e tests.

CI matrix: Python 3.11, 3.12, 3.13. The web tests are skipped on 3.11
(`telnetlib` import path; intentional, see the test docstring).

---

## 8. Adding a web endpoint

The web server is a thin FastAPI shell. To add a new endpoint:

1. Open `src/netops_autopilot/web/server.py` and add a route inside
   `create_app()`. Use the existing `_check_key` helper if the endpoint
   should require `NETOPS_API_KEY`.
2. Update `tests/test_web.py` with at least one happy-path test and
   one failure-path test (404 / 401 / 400 as appropriate).
3. Update the OpenAPI docstring in `create_app()` so the auto-generated
   docs at `/docs` stay accurate.

The WebSocket route at `/runs/{run_id}/events` exists but the Starlette
TestClient's WS race is acknowledged in `test_web.py`; manual verification
is documented in `docs/USER_GUIDE.md`.

---

## 9. Adding a CLI sub-command

In `cli_main.py`:

1. Add a subparser.
2. Write a `run_<name>(...)` function that does the work and returns
   an exit code (`0 = ok`, `2 = typed error`, `1 = generic error`).
3. Use `cli.pretty` to format the output — never `print()` raw text.
4. Add tests in `tests/test_cli.py` covering the happy path, the
   `--help` exit, and any failure paths (missing input, bad config).

---

## 10. Build & release

* **Local dev:** `pip install -r requirements.txt && pytest`
* **Web UI smoke test:** `python -m netops_autopilot webui --port 8765`,
  then open `http://localhost:8765/ui/`.
* **Windows MSI:** `cd packaging/msi && ./build.sh` (the recipe is
  pre-release; see ADR-0008 for the bundled-deps policy).

The release gate (see `docs/D0/10-evaluation-harness.md`):

```
T1 unverified_claims          == 0
T2 unsupported_PASS           == 0
T3 unauthorized_changes       == 0
T4 scope_violations           == 0
L11 credential_exposure       == 0
cleanup_leaks                 == 0
gate_bypass                   == 0
stale_evidence_deployments    == 0
management_path_violations    == 0
```

If any is non-zero, the harness fails the release. This is non-negotiable.

---

## 11. Coding style

* Type hints everywhere; `from __future__ import annotations` at the top.
* Frozen dataclasses for value objects; mutable state stays in a single
  place per engine.
* No global mutable state in engines. The orchestrator owns the lifetime.
* Comments explain **why**, not what. Code is self-documenting for "what".
* No `print()` in libraries — use the `observability.JsonLogger`.
* CLI tools are allowed to print, but should reach for `cli.pretty`
  first.
