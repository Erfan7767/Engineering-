"""The isolation the policy requires is actually configured on a device.

Three of the six blueprints declare ``guest_isolation=True``. Until now nothing
implemented it: the router had every zone directly connected and no ACL, so
guest traffic reached the corporate VLAN while the run reported success. Phase 7
exposed that as six CONNECTIVITY_DENY failures naming each pair.

These tests pin the fix, and pin the two ways it could go wrong:

* an ACL with denies and no trailing permit black-holes its whole zone — a
  "security" change that takes the network down;
* an ACL that is created but never applied to an interface filters nothing, so
  the configuration would look right and the requirement would still be unmet.
"""

from __future__ import annotations

import pytest

from netops_autopilot.engines.design_engine import effective_denied_pairs
from netops_autopilot.engines.verification import VerificationPlanner


def _run():
    from netops_autopilot.autopilot.orchestrator import AutopilotEngine
    from netops_autopilot.cli.scenarios import make_scenario_io
    from tests.support.simfabric import SimFabricFactory, make_ledger_stack

    store, key_id, _c, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = make_scenario_io("branch")
    io.append_answers({"bond_confirm": "BOND"})
    engine = AutopilotEngine(store=store, key_id=key_id, io=io, time_authority=ta)
    report = engine.run(
        probe_port_session_factory=lambda p: fabric.probe(p),
        mgmt_session_factory=fabric, port="SIM0", execute=True)
    return fabric, report


def _acl_lines(fabric):
    session = fabric.open("seed-01", ())
    return [c for c in session.written_config
            if c.lower().startswith(("ip access-list", "deny ", "permit ",
                                     "ip access-group"))]


# ============================================ design and verification agree
def test_the_design_enforces_the_same_matrix_the_verifier_grades():
    """Two readings of one rule set is how a network enforces the wrong thing."""
    _fabric, report = _run()
    planned_deny = {tuple(t.test_id.split(":")[-1].split("->"))
                    for t in VerificationPlanner().derive(report.intent)
                    if "CONNECTIVITY_DENY" in t.test_id}
    assert set(report.design.denied_pairs) == planned_deny, (
        f"design enforces {sorted(report.design.denied_pairs)} but the matrix "
        f"requires {sorted(planned_deny)}")


def test_no_blueprint_can_declare_isolation_without_the_design_carrying_it():
    from netops_autopilot.engines.blueprints import BLUEPRINTS
    isolated = [b.blueprint_id for b in BLUEPRINTS if b.guest_isolation]
    assert isolated, "expected at least one blueprint to require isolation"


# ================================================== the ACL really gets built
def test_every_denied_pair_gets_a_real_deny_line_on_the_device():
    import ipaddress
    fabric, report = _run()
    lines = _acl_lines(fabric)
    subnet = {z.zone: z.subnet for z in report.design.zones}
    unenforceable = {(a, b) for a, b, _ in report.design.unenforceable_isolation}
    enforceable = [p for p in report.design.denied_pairs if p not in unenforceable]
    assert enforceable, "no pair was enforceable — the test would be vacuous"
    for src, dst in enforceable:
        s = ipaddress.ip_network(subnet[src], strict=False)
        d = ipaddress.ip_network(subnet[dst], strict=False)
        want = (f"deny ip {s.network_address} {s.hostmask} "
                f"{d.network_address} {d.hostmask}")
        assert want in lines, f"{src}->{dst} not enforced; missing {want!r}"


def test_the_acl_ends_with_a_permit_so_it_cannot_black_hole_its_zone():
    """Deny-only ACLs are the classic way a 'security' change kills a network."""
    fabric, report = _run()
    lines = _acl_lines(fabric)
    names = {l.split()[-1] for l in lines if l.startswith("ip access-list extended")}
    assert names, "no ACL was created"
    for name in sorted(names):
        entries = _entries_after(lines, name)
        assert entries, f"{name} has no entries"
        assert entries[-1] == "permit ip any any", (
            f"{name} does not end with a permit — everything after the denies "
            f"is dropped: {entries}")


def test_the_acl_is_applied_to_an_interface_not_just_created():
    """An unapplied ACL filters nothing and looks correct in the config."""
    fabric, report = _run()
    lines = _acl_lines(fabric)
    created = {l.split()[-1] for l in lines if l.startswith("ip access-list extended")}
    applied = {l.split()[2] for l in lines if l.startswith("ip access-group")}
    assert created == applied, (
        f"created but not applied: {sorted(created - applied)}")
    assert applied, "nothing was applied"


def test_an_enforceable_pair_passes_because_of_the_deny_not_for_lack_of_a_path():
    """Guards against the vacuous pass this file exists to prevent.

    Both subnets must be reachable in the routing table; otherwise a DENY test
    passes by concluding "no L3 path" and proves nothing about the ACL.
    """
    fabric, report = _run()
    unenforceable = {(a, b) for a, b, _ in report.design.unenforceable_isolation}
    subs = {z.zone: z.subnet.split("/")[0] for z in report.design.zones}
    routes = fabric.open("seed-01", ()).execute("show ip route", 5).decode()
    checked = 0
    for tid in report.verification["passed"]:
        if "CONNECTIVITY_DENY" not in tid:
            continue
        src, dst = tid.split(":")[-1].split("->")
        if (src, dst) in unenforceable:
            continue
        assert subs[src] in routes and subs[dst] in routes, (
            f"{src}->{dst} passed while unrouted — vacuous")
        checked += 1
    assert checked, "no enforceable DENY test passed — nothing was proven"


def test_a_pair_the_platform_cannot_enforce_is_reported_not_silently_skipped():
    """A deny naming a provider-chosen subnet matches nothing, so it is not
    written — and the operator is told, with the reason and the remedy."""
    _fabric, report = _run()
    un = report.design.unenforceable_isolation
    assert un, "expected the DHCP-handoff WAN pairs to be declared unenforceable"
    for src, dst, why in un:
        assert "wan" in (src, dst)
        assert "provider" in why and ("firewall" in why or "reflexive" in why), why
    # and it surfaces as unrun, never as a pass
    for src, dst, _why in un:
        want = f"CONNECTIVITY_DENY:{src}->{dst}"
        assert any(k.endswith(want) for k in report.verification["unrun"]), (
            f"{src}->{dst} is unenforceable but was not reported unrun: "
            f"{sorted(report.verification['unrun'])}")
    assert report.verification["verdict"] == "INCOMPLETE"


def _entries_after(lines: list[str], name: str) -> list[str]:
    """Entries belonging to the last `ip access-list extended <name>` block."""
    out: list[str] = []
    inside = False
    for line in lines:
        if line.startswith("ip access-list extended"):
            inside = line.split()[-1] == name
            continue
        if inside and line.startswith(("deny ", "permit ")):
            out.append(line)
        elif line.startswith("ip access-group"):
            inside = False
    return out
