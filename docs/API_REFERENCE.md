# NetOps Autopilot — API Reference

**Base URL:** `http://localhost:8765` (default; configurable).
**Auth:** `Authorization: Bearer <key>` when `NETOPS_API_KEY` is set.
**Content type:** `application/json` for requests; varies for responses.

This is the surface the Web UI talks to and the surface you can drive
from any HTTP client. Every endpoint honors the constitution: nothing
is a guess, every state is typed, every claim is evidence-bound.

---

## `GET /healthz`

Liveness probe.

**Response 200:**
```json
{
  "status": "ok",
  "service": "netops-autopilot",
  "version": "0.1.0",
  "api_key_required": false,
  "runs_in_memory": 0,
  "ts": "2026-09-10T18:18:50+00:00"
}
```

---

## `POST /runs`

Start a new run. The body is the run configuration; the run executes
in a background thread, so this endpoint returns immediately.

**Request body:**
```json
{
  "port": "COM5",
  "execute": false
}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `port` | string | yes | console port (`COM5`, `/dev/ttyUSB0`, ...) |
| `execute` | bool | no | request execution (still gated by T3) |

**Response 200:**
```json
{
  "run_id": "abc123def456",
  "status": "RUNNING"
}
```

**Errors:**

* `400` — `port` missing or not a string.
* `401` — missing `Authorization` header (when API key is set).
* `403` — invalid API key.

---

## `GET /runs/{run_id}`

Get a run's current state.

**Response 200:**
```json
{
  "run_id": "abc123def456",
  "status": "RUNNING",
  "final": "",
  "created_at": "2026-09-10T18:18:50+00:00",
  "finished_at": null,
  "error": null,
  "phases": [
    {"phase": "BOND", "status": "OK", "detail": "..."},
    {"phase": "BOOT_PROBE", "status": "OK", "detail": "..."}
  ]
}
```

`status` is one of `PENDING | RUNNING | COMPLETE | BLOCKED | ERROR`.
`final` is the empty string while the run is in progress; once
terminal, it carries values like `COMPLETE-STAGED`, `BLOCKED-DESIGN`,
`BLOCKED-BLOCKED`, etc.

**Errors:**

* `404` — unknown run id.
* `401` / `403` — auth.

---

## `GET /runs/{run_id}/topology`

Get the discovered topology as JSON.

**Response 200:**
```json
{
  "nodes": [
    {"device_ref": "seed-01", "vendor_family": "cisco/ios-xe", "status": "COMPLETE"}
  ],
  "edges": [
    {"a_device_ref": "seed-01", "b_device_ref": "sw-01", "evidence_refs": ["e1", "e2"]}
  ],
  "gaps": [
    "NEIGHBOR_MENTIONED_NO_EVIDENCE: 10.0.0.5"
  ],
  "ascii": "seed-01 (Cisco IOS XE)\n  └─ sw-01 (UNREACHABLE)\n"
}
```

**Errors:** `404` if the run hasn't reached TOPOLOGY_MAP yet, or the
phase was BLOCKED before discovery completed.

---

## `GET /runs/{run_id}/report`

Self-contained HTML report (rendered server-side, no external assets).

**Response 200:** `text/html` body with the full run summary, ASCII
topology, intent, design, rendered configs, execution gate, and
counters.

**Errors:** `404` if the report isn't ready (run not yet terminal).

---

## `GET /runs/{run_id}/report.json`

Same data as the HTML report, but in machine-readable form.

**Response 200:** `application/json`. Schema is
`netops-autopilot/run-report/v1` (see `src/netops_autopilot/reporting/json_report.py`).

---

## `WS /runs/{run_id}/events`

Live event stream. After accepting, the server sends one message per
status change (or every 500ms while the run is active), and closes the
socket when the run reaches a terminal state.

**Message format:**
```json
{
  "type": "status",
  "status": "RUNNING",
  "final": "",
  "phases": [...]
}
```

For an unknown run id:
```json
{"type": "error", "detail": "run not found"}
```

The Starlette `TestClient` has a known race when the server closes
immediately after sending — see `tests/test_web.py` for the
acknowledgement. Manual verification with `websocat`/`wscat` works
without issue.

---

## Error conventions

| HTTP | Meaning |
|---|---|
| 400 | Input validation failure (missing/invalid field) |
| 401 | Missing `Authorization: Bearer ...` |
| 403 | Invalid API key |
| 404 | Resource not found (run id, topology, report) |
| 422 | (reserved for future use) |
| 500 | Unhandled server error; check the server log |

Every error body is `{"detail": "<human-readable>"}` (FastAPI default).
The platform never returns a non-typed error to a client.

---

## Auth

Set the env var `NETOPS_API_KEY=<your-secret>` on the server. Then
every request must include:

```
Authorization: Bearer <your-secret>
```

The UI handles this transparently when `?api_key=...` is in the URL.
For production, terminate TLS upstream (nginx / caddy) and rotate the
key via your secret manager.
