"""The WAN handoff the operator describes is the WAN handoff that gets built.

``wan_handoff`` was a *required* blueprint parameter: the operator was asked to
describe it, the answer was validated as present, and then the design engine
never read it. The WAN was given a static gateway out of the allocated site
block regardless of what the operator said, and because a static gateway does
not install a default route, the site came up with no internet egress — while
the run reported COMPLETE-APPLIED.

Phase 7 caught it as `SERVICE_UP:internet_egress FAILED`. These tests pin the
fix, and pin the negative case too: an unrecognised handoff must not be silently
treated as DHCP, because that would put a provider-assumed address on the
interface (L01).
"""

from __future__ import annotations

import pytest

from netops_autopilot.engines.design_engine import handoff_is_dhcp


# ======================================================= the predicate itself
@pytest.mark.parametrize("handoff,expected", [
    ("ISP fiber DHCP handoff", True),
    ("isp dhcp", True),
    ("Cable modem, dynamic address", True),
    ("Static /30 from ISP, next hop 203.0.113.1", False),
    ("Metro Ethernet, handed a /29", False),
    ("", False),
    (None, False),
])
def test_only_an_explicit_statement_counts_as_dhcp(handoff, expected):
    assert handoff_is_dhcp(handoff) is expected


# ============================================ it reaches the rendered config
def _rendered_commands(wan_handoff: str) -> list[str]:
    from netops_autopilot.autopilot.orchestrator import AutopilotEngine
    from netops_autopilot.cli.scenarios import make_scenario_io
    from tests.support.simfabric import SimFabricFactory, make_ledger_stack

    store, key_id, _c, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = make_scenario_io("branch")
    # The scenario's own script answers the handoff question positionally;
    # overwrite it with the value under test.
    engine = AutopilotEngine(store=store, key_id=key_id, io=io, time_authority=ta)
    report = engine.run(
        probe_port_session_factory=lambda p: fabric.probe(p),
        mgmt_session_factory=fabric, port="SIM0", execute=False)
    engine._operator_answers["wan_handoff"] = wan_handoff
    engine._phase_render(report.design)
    return [c for c in report.renders["seed-01"].to_text().splitlines()]


def test_a_declared_dhcp_handoff_puts_no_static_gateway_on_the_wan():
    lines = _rendered_commands("ISP fiber DHCP handoff")
    wan_block = [l.strip() for l in _block_for(lines, "Vlan40")]
    assert "ip address dhcp" in wan_block, wan_block
    assert not any(l.startswith("ip address 10.240") for l in wan_block), (
        f"a static gateway was configured on a DHCP handoff: {wan_block}")


def test_a_static_handoff_keeps_the_static_gateway():
    """No silent behaviour change for the operator who did not say DHCP."""
    lines = _rendered_commands("Static /30 from the ISP")
    wan_block = [l.strip() for l in _block_for(lines, "Vlan40")]
    assert "ip address dhcp" not in wan_block, wan_block
    assert any(l.startswith("ip address 10.240") for l in wan_block), wan_block


def test_the_answer_is_not_ignored_between_the_prompt_and_the_design():
    """The regression this whole file exists for."""
    from netops_autopilot.autopilot.orchestrator import AutopilotEngine
    from netops_autopilot.cli.scenarios import make_scenario_io
    from tests.support.simfabric import SimFabricFactory, make_ledger_stack

    store, key_id, _c, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = make_scenario_io("branch")
    engine = AutopilotEngine(store=store, key_id=key_id, io=io, time_authority=ta)
    engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
               mgmt_session_factory=fabric, port="SIM0", execute=False)
    # Both the design and the IR read the same single source of answers; a
    # hand-picked subset in either one is how the answer went missing.
    assert engine._design_answers()["wan_handoff"] == "ISP fiber DHCP handoff"
    assert engine._design_answers()["dns_servers"] == "1.1.1.1, 9.9.9.9"


def _block_for(lines: list[str], interface: str) -> list[str]:
    out, inside = [], False
    for line in lines:
        if line.strip() == f"interface {interface}":
            inside = True
            out.append(line)
            continue
        if inside:
            if line.startswith(" ") and line.strip():
                out.append(line)
            else:
                break
    return out
