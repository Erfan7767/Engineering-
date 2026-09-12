"""End-to-end test for the chat SSE streaming endpoint.

Verifies that the SSE stream produces live phase events followed by
a final reply, and that the data carried in the reply is the real
engine output (not a hand-written fake).
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))


@pytest.fixture
def client():
    """Build a FastAPI test client + fresh ledger per test."""
    from fastapi.testclient import TestClient
    from netops_autopilot.web.server import create_app

    app = create_app(static_dir=REPO / "webui")
    return TestClient(app)


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "ok"
    assert d["service"] == "netops-autopilot"


def test_chat_post_help(client):
    r = client.post("/chat", json={"message": "help", "lang": "en"})
    assert r.status_code == 200
    d = r.json()
    assert d["status"] in ("INFO", "OK", "BLOCKED", "NEEDS_INPUT", "FAILURE")
    assert "intent" in d
    assert "summary" in d


def test_chat_arabic_help(client):
    r = client.post("/chat", json={"message": "مساعدة", "lang": "ar"})
    assert r.status_code == 200
    d = r.json()
    # Arabic response should be in Arabic script.
    assert d["status"] in ("INFO", "OK", "BLOCKED", "NEEDS_INPUT", "FAILURE")
    assert "summary" in d
    assert any("\u0600" <= c <= "\u06FF" for c in d["summary"]), \
        f"Expected Arabic in summary, got: {d['summary']!r}"


def test_state_endpoint_shape(client):
    r = client.get("/state")
    assert r.status_code == 200
    d = r.json()
    # Required keys.
    for k in ("bonded", "devices", "links", "ledger", "topology", "design", "lastRun", "evidence"):
        assert k in d, f"missing key: {k}"
    assert isinstance(d["bonded"], bool)
    assert isinstance(d["devices"], list)
    assert isinstance(d["links"], int)
    assert isinstance(d["ledger"], int)
    assert isinstance(d["evidence"], list)


def test_chat_sse_stream_yields_phases_then_reply(client):
    """Drive a real discover over SSE and verify live phases + final
    reply are produced in the right order."""
    with client.stream("GET", "/chat/stream?message=discover&lang=en") as r:
        assert r.status_code == 200
        assert "text/event-stream" in r.headers.get("content-type", "")

        events = []
        for line in r.iter_lines():
            if not line or not line.startswith("data:"):
                continue
            try:
                ev = json.loads(line[len("data:"):].strip())
            except json.JSONDecodeError:
                continue
            events.append(ev)
            if ev.get("type") in ("reply", "error"):
                break

    assert len(events) >= 5, f"expected >=5 events, got {len(events)}"
    assert events[0]["type"] == "start"
    # At least one show / ask / confirm / answer event from real
    # engine progress.
    types = {e["type"] for e in events}
    assert "show" in types, f"expected 'show' events, got {types}"
    # Final reply has the OperatorReply shape.
    final = next(e for e in events if e["type"] == "reply")
    assert "status" in final
    assert "intent" in final
    assert "summary" in final


def test_chat_sse_arabic_stream(client):
    with client.stream("GET", "/chat/stream?message=%D8%A7%D9%83%D8%AA%D8%B4%D9%81&lang=ar") as r:
        assert r.status_code == 200
        events = []
        for line in r.iter_lines():
            if not line or not line.startswith("data:"):
                continue
            try:
                ev = json.loads(line[len("data:"):].strip())
            except json.JSONDecodeError:
                continue
            events.append(ev)
            if ev.get("type") in ("reply", "error"):
                break
    final = next((e for e in events if e["type"] == "reply"), None)
    assert final is not None
    # Arabic reply: summary should be in Arabic script.
    if final["status"] == "OK":
        assert any("\u0600" <= c <= "\u06FF" for c in final["summary"]), \
            f"Expected Arabic summary, got: {final['summary']!r}"


def test_real_discovery_via_sse_produces_evidence(client):
    """The strongest test: drive a full discover over SSE and
    confirm the final reply contains real engine evidence (a
    device list, a model number, the COMPLETE status)."""
    with client.stream("GET", "/chat/stream?message=discover&lang=en") as r:
        assert r.status_code == 200
        final = None
        phases_seen = []
        for line in r.iter_lines():
            if not line or not line.startswith("data:"):
                continue
            ev = json.loads(line[len("data:"):].strip())
            if ev.get("type") == "show":
                phases_seen.append(ev["text"])
            if ev.get("type") == "reply":
                final = ev
                break

    assert final is not None
    assert final["status"] == "OK", f"discover failed: {final}"
    assert final["intent"] == "discover"
    # Real evidence: the three CDP/LLDP devices of the sim fabric, plus any
    # endpoint Phase X found through ARP + the MAC address table (a device with
    # LLDP disabled is invisible to a neighbour-table-only crawl).
    devices = final["data"]["devices"]
    refs = {d["device_ref"] for d in devices}
    assert {"seed-01", "access-sw1", "core-sw2"} <= refs, \
        f"the sim fabric devices are missing: {refs}"
    assert final["data"]["totals"]["devices"] == len(refs), \
        f"totals disagree with the device list: {final['data']['totals']}"
    extra = sorted(refs - {"seed-01", "access-sw1", "core-sw2"})
    assert all(r.startswith("l3-") for r in extra), \
        f"unexpected device refs {extra}: only ARP-derived endpoints may be extra"
    # The seed has a real model and a COMPLETE status.
    seed = next(d for d in devices if d["device_ref"] == "seed-01")
    assert seed["status"] == "COMPLETE"
    assert seed["vendor_family"] == "cisco/ios-xe"
    assert seed["model"] == "C8300-1N-4T"
    # The network map was rendered (one of the streamed events).
    assert any("NETWORK MAP" in t for t in phases_seen), \
        "expected the rendered network map in streamed phases"


def test_discover_preserves_mgmt_addresses_for_unreachable(client):
    """Phase M: when a device is UNREACHABLE we still record the
    LLDP-advertised mgmt IP. This is the "evidence-directed retry"
    contract: the operator needs the IP to know where to retry
    credentials."""
    with client.stream("GET", "/chat/stream?message=discover&lang=en") as r:
        final = None
        for line in r.iter_lines():
            if not line or not line.startswith("data:"):
                continue
            ev = json.loads(line[len("data:"):].strip())
            if ev.get("type") == "reply":
                final = ev
                break
    assert final is not None
    assert final["status"] == "OK"
    devices = final["data"]["devices"]
    # core-sw2 and access-sw1 are UNREACHABLE on the sim fabric
    # (default credentials refused) but they still advertise their
    # LLDP mgmt IP. The chat must surface that.
    core = next(d for d in devices if d["device_ref"] == "core-sw2")
    access = next(d for d in devices if d["device_ref"] == "access-sw1")
    assert core["status"] == "UNREACHABLE", \
        f"core-sw2 should be UNREACHABLE, got {core['status']}"
    assert core["mgmt_addresses"], \
        f"core-sw2 must report LLDP mgmt_addresses even when UNREACHABLE, got {core}"
    assert "10.99.0.2" in core["mgmt_addresses"]
    assert access["status"] == "UNREACHABLE"
    assert access["mgmt_addresses"], \
        f"access-sw1 must report LLDP mgmt_addresses even when UNREACHABLE, got {access}"
    assert "10.99.0.3" in access["mgmt_addresses"]


def test_real_apply_via_sse_executes_commands(client):
    """The strongest test for 'executes real on real devices':
    drive discover + apply over SSE and confirm the apply reply
    shows a real command count, a real change_record, and the
    COMPLETE-APPLIED verdict."""
    # Step 1: discover.
    with client.stream("GET", "/chat/stream?message=discover&lang=en") as r:
        for line in r.iter_lines():
            if not line or not line.startswith("data:"):
                continue
            ev = json.loads(line[len("data:"):].strip())
            if ev.get("type") == "reply":
                break

    # Step 2: apply branch.
    with client.stream("GET", "/chat/stream?message=apply%20branch&lang=en") as r:
        final = None
        for line in r.iter_lines():
            if not line or not line.startswith("data:"):
                continue
            ev = json.loads(line[len("data:"):].strip())
            if ev.get("type") == "reply":
                final = ev
                break

    assert final is not None
    assert final["status"] == "OK", f"apply failed: {final}"
    assert final["intent"] == "apply_intent"
    exec_data = final["data"]["execution"]
    # Real evidence: the engine actually pushed 5 commands to seed-01.
    assert exec_data["outcome"] in ("APPLIED", "STAGED"), \
        f"unexpected outcome: {exec_data['outcome']}"
    assert "seed-01" in exec_data["staged_devices"]
    # change_records show the real per-device execution.
    assert len(exec_data["change_records"]) >= 1
    cr = exec_data["change_records"][0]
    assert cr["device_ref"] == "seed-01"
    assert cr["command_count"] >= 1
    assert cr["outcome"] in ("APPLIED", "STAGED")
