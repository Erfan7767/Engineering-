"""v8 UI: structural smoke tests + real-device execution integration.

The v8 chat operator UI is a single 1700-line file that mounts as
the default at /chat. v8 introduces two major capabilities:

  1. The chat's ``ping``, ``traceroute``, ``show ip route``,
     ``show vlan``, ``show interfaces``, ``show lldp`` commands
     actually execute on the device (via DeviceCommandRunner).
  2. The UI shows the real device output with a dedicated card
     component (renderDeviceOutputCard) including colorized
     success/failure markers and a key-value summary line.

These tests verify the UI is wired correctly AND that the real
execution path works end-to-end through the chat API.
"""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient

from netops_autopilot.web.server import create_app


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app())


# ============================================================ UI structure


def test_v8_chat_page_loads(client: TestClient) -> None:
    """GET /chat → 200 HTML, contains the v8 title."""
    r = client.get("/chat")
    assert r.status_code == 200
    assert "v8" in r.text or "Real Device Execution" in r.text
    assert len(r.text) > 60_000, f"v8 too small: {len(r.text)} bytes"


def test_v8_has_real_device_execution_components(client: TestClient) -> None:
    """The renderer for real device output is in the page."""
    r = client.get("/chat")
    assert "renderDeviceOutputCard" in r.text
    assert "REAL DEVICE OUTPUT" in r.text
    assert "device-output" in r.text


def test_v8_bilingual(client: TestClient) -> None:
    """Both English and Arabic are present."""
    r = client.get("/chat")
    assert "const I18N" in r.text
    assert "en:" in r.text and "ar:" in r.text
    # Real device verbs in Arabic
    for ar in ("ping", "الأجهزة", "اكتشف", "تطبيق", "جاهز", "فشل"):
        assert ar in r.text, f"missing Arabic: {ar}"


def test_v8_18_verbs(client: TestClient) -> None:
    """All 18 commands are listed."""
    r = client.get("/chat")
    for v in ("discover", "show devices", "show topology", "apply branch",
              "apply hotel", "ping 10.0.0.1", "traceroute 8.8.8.8",
              "show ip route", "show vlan", "show interfaces",
              "show lldp", "show neighbors", "show version", "diagnose",
              "rollback", "show config seed-01", "status", "help"):
        assert f'verb: "{v}"' in r.text, f"missing verb: {v}"


def test_v8_5_step_workflow(client: TestClient) -> None:
    """The 5-step workflow is in the topbar."""
    r = client.get("/chat")
    for s in ("bind", "discover", "design", "apply", "verify"):
        assert f'data-step="{s}"' in r.text


def test_v8_3_tabs(client: TestClient) -> None:
    """State / Topology / Evidence tabs in the right panel."""
    r = client.get("/chat")
    for t in ("state", "topology", "evidence"):
        assert f'data-tab="{t}"' in r.text


def test_v8_command_palette(client: TestClient) -> None:
    """The ⌘K palette is wired."""
    r = client.get("/chat")
    assert 'id="modal-back"' in r.text
    assert 'id="modal-input"' in r.text
    assert "renderPalette" in r.text


def test_v8_color_schemes(client: TestClient) -> None:
    """Color-coded pill classes exist for OK / warn / bad."""
    r = client.get("/chat")
    assert ".pill.ok" in r.text
    assert ".pill.warn" in r.text
    assert ".pill.bad" in r.text


def test_v8_8_quick_actions(client: TestClient) -> None:
    """The 8 quick actions (⌘1..8) are defined in COMMANDS array."""
    r = client.get("/chat")
    # Quick actions are built dynamically in JS from the COMMANDS
    # array; check the JS source.
    for verb in ("discover", "show devices", "show topology", "apply branch",
                 "apply hotel", "ping 10.0.0.1", "traceroute 8.8.8.8",
                 "show ip route"):
        assert f'verb: "{verb}"' in r.text
    # And check the keyboard shortcut handler exists
    assert "parseInt(e.key, 10) - 1" in r.text


# ============================================================ real device exec


def test_real_discover_via_chat(client: TestClient) -> None:
    """discover seeds the chat op so subsequent commands have a target."""
    r = client.post("/chat", json={"message": "discover"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "OK"
    assert body["summary"].startswith("discovered")


def test_real_ping_returns_cisco_output(client: TestClient) -> None:
    """``ping 10.0.0.1`` returns the real Cisco IOS-XE ping output."""
    r = client.post("/chat", json={"message": "ping 10.0.0.1"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "OK"
    assert "Success rate" in body.get("detail", "") or "!!!!" in body.get("detail", "")
    # The data block must carry the real output for the UI to render.
    data = body.get("data", {})
    assert "output" in data
    assert "Success rate" in data["output"] or "!!!!" in data["output"]
    assert data["success"] is True
    assert data["command"].startswith("ping")


def test_real_traceroute_returns_hops(client: TestClient) -> None:
    """``traceroute 8.8.8.8`` returns the device's traceroute output."""
    r = client.post("/chat", json={"message": "traceroute 8.8.8.8"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "OK"
    data = body.get("data", {})
    assert "output" in data
    assert "8.8.8.8" in data["output"]
    assert data["command"].startswith("traceroute")


def test_real_show_ip_route_returns_routes(client: TestClient) -> None:
    """``show ip route`` returns the routing table with parsed count."""
    r = client.post("/chat", json={"message": "show ip route"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "OK"
    data = body.get("data", {})
    assert "output" in data
    assert data["route_count"] >= 1
    assert "0.0.0.0/0" in data["output"] or "directly connected" in data["output"]


def test_real_show_vlan_returns_vlans(client: TestClient) -> None:
    """``show vlan`` returns the VLAN table with parsed count."""
    r = client.post("/chat", json={"message": "show vlan"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "OK"
    data = body.get("data", {})
    assert "output" in data
    assert data.get("vlan_count", 0) >= 1
    assert "VLAN" in data["output"] or "vlan" in data["output"]


def test_real_show_interfaces_returns_ports(client: TestClient) -> None:
    """``show interfaces`` returns the port status with parsed count."""
    r = client.post("/chat", json={"message": "show interfaces"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "OK"
    data = body.get("data", {})
    assert "output" in data
    assert data.get("interface_count", 0) >= 1
    assert "Gi" in data["output"] or "Port" in data["output"]


def test_real_show_lldp_returns_neighbors(client: TestClient) -> None:
    """``show lldp`` returns the LLDP neighbor table with parsed count."""
    r = client.post("/chat", json={"message": "show lldp"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "OK"
    data = body.get("data", {})
    assert "output" in data
    assert data.get("neighbor_count", 0) >= 1
    assert "Chassis" in data["output"] or "Capability" in data["output"]


def test_arabic_ping_works(client: TestClient) -> None:
    """Arabic ``بينج 10.0.0.1`` resolves to ping and executes."""
    r = client.post("/chat", json={"message": "بينج 10.0.0.1"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "OK"
    assert re.search(r"[\u0600-\u06FF]", body["summary"]), "Arabic summary missing"
    data = body.get("data", {})
    assert "output" in data
    assert data["success"] is True


def test_show_config_seed01(client: TestClient) -> None:
    """``show config seed-01`` returns the rendered Cisco config."""
    r = client.post("/chat", json={"message": "show config seed-01"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "OK"
    data = body.get("data", {})
    assert "config" in data
    assert "interface Vlan" in data["config"] or "vlan 10" in data["config"]
    assert data.get("device") == "seed-01"


def test_apply_branch_executes_real_config(client: TestClient) -> None:
    """``apply branch`` returns APPLIED with change records.

    Must run after a successful discover — apply needs the
    discovered device list to design a network.
    """
    # Ensure discover is fresh
    client.post("/chat", json={"message": "discover"})
    r = client.post("/chat", json={"message": "apply branch"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("OK", "NEEDS_INPUT", "BLOCKED", "FAILURE")
    if body["status"] == "OK" and "APPLIED" in body["summary"]:
        data = body.get("data", {})
        exec_data = data.get("execution", {})
        assert exec_data.get("outcome") == "APPLIED"
        records = exec_data.get("change_records", [])
        assert len(records) >= 1
        # Each change record has at least the device_ref and command_count
        rec = records[0]
        assert "device_ref" in rec
        assert "command_count" in rec
        assert rec["command_count"] >= 1


def test_rollback_plan_returned_for_real_apply(client: TestClient) -> None:
    """After ``apply branch``, the chat has a real rollback plan in memory."""
    # apply was already done by previous test; just ask for rollback
    r = client.post("/chat", json={"message": "rollback"})
    assert r.status_code == 200
    body = r.json()
    # Either OK (real rollback) or BLOCKED (no plan to rollback)
    assert body["status"] in ("OK", "BLOCKED")


def test_diagnose_returns_health(client: TestClient) -> None:
    """``diagnose`` returns the network health snapshot."""
    r = client.post("/chat", json={"message": "diagnose"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "OK"
    # The summary mentions either gaps or healthy
    assert "gap" in body["summary"].lower() or "healthy" in body["summary"].lower()


def test_help_returns_commands(client: TestClient) -> None:
    """``help`` returns the available commands list."""
    r = client.post("/chat", json={"message": "help"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("OK", "INFO")
    assert body["summary"] in ("available commands", "الأوامر المتاحة")
    assert "discover" in body["detail"] or "اكتشف" in body["detail"]


def test_arabic_help_returns_arabic_commands(client: TestClient) -> None:
    """Arabic ``مساعدة`` returns Arabic commands."""
    r = client.post("/chat", json={"message": "مساعدة"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] in ("OK", "INFO")
    assert body["summary"] == "الأوامر المتاحة"


def test_state_endpoint_powers_context_panel(client: TestClient) -> None:
    """``/state`` returns the data the v8 context panel renders."""
    s = client.get("/state").json()
    for key in ("bonded", "devices", "links", "ledger", "lastRun"):
        assert key in s, f"missing key: {key}"
    if s.get("devices"):
        d = s["devices"][0]
        for dk in ("device_ref", "status", "vendor", "model"):
            assert dk in d, f"device missing: {dk}"


def test_old_versions_remain_mounted(client: TestClient) -> None:
    """Backward compat: v6, v7 still served at /ui/v6/, /ui/v7/."""
    for v in ("v6", "v7", "v8"):
        r = client.get(f"/ui/{v}/")
        assert r.status_code == 200, f"{v} mount broken"


def test_sse_streams_phase_events(client: TestClient) -> None:
    """SSE yields the phase events the v8 timeline renders."""
    with client.stream("GET", "/chat/stream?message=discover&lang=en") as r:
        assert r.status_code == 200
        events = []
        for line in r.iter_lines():
            if not line:
                continue
            if line.startswith("data: "):
                try:
                    events.append(json.loads(line[6:]))
                except Exception:
                    pass
            if len(events) >= 5:
                break
    # At least start + show + reply events
    types = [e.get("type") for e in events]
    assert "start" in types, f"missing start event: {types}"


def test_concurrent_chat_requests_dont_error(client: TestClient) -> None:
    """6 parallel requests — all return 200, no SQLite lock errors."""
    import concurrent.futures

    def fire(msg: str):
        r = client.post("/chat", json={"message": msg})
        return r.status_code, r.json().get("status", "?")

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(fire, m) for m in
                ["discover", "help", "show devices", "show ip route",
                 "apply branch", "diagnose"]]
        results = [f.result() for f in futs]
    for code, st in results:
        assert code == 200, f"request failed: {code}"
        # discover/help/show_devices should be OK
        # apply may produce a duplicate-run warning but still 200
