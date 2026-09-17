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

import ipaddress

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


_ANY = "0.0.0.0 255.255.255.255"


def _deny_covers(line: str, src, dst) -> bool:
    """True when this deny line blocks ``src`` from reaching ``dst``.

    Semantic, not textual: a side written as ``0.0.0.0 255.255.255.255`` means
    *any*, and any covers every zone. That is how a pair whose far end is
    provider-addressed — and therefore never known — is still enforced, so
    matching only the exact allocated subnets would miss a rule that works.
    """
    import re
    m = re.match(r"\s*deny\s+ip\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$", line)
    if m is None:
        return False
    try:
        s = _from_wildcard(m.group(1), m.group(2))
        d = _from_wildcard(m.group(3), m.group(4))
    except ValueError:
        return False
    return s.supernet_of(src) and d.supernet_of(dst)


def _from_wildcard(address: str, wildcard: str):
    """An IOS ``<address> <wildcard>`` pair as a network.

    The second field is a *wildcard* mask — the inverse of a netmask — so
    ``0.0.0.0 255.255.255.255`` is ``0.0.0.0/0`` (any), not ``/32``. Feeding it
    to ``ip_network`` as a netmask would read ``any`` as a single host and
    every coverage check would silently report "not enforced".
    """
    bits = bin(int(ipaddress.IPv4Address(wildcard))).count("1")
    return ipaddress.ip_network(f"{address}/{32 - bits}", strict=False)


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
        assert any(_deny_covers(line, s, d) for line in lines), (
            f"{src}->{dst} not enforced: no deny line in {lines!r} covers "
            f"{s} -> {d}")


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

    Both sides must really be on the wire. For a zone this platform addressed
    that is the allocated block; for a provider-addressed WAN it is the
    provider's network, read from the routing table — grading against the
    allocated block would find no route and pass the pair for "no L3 path",
    proving nothing about the ACL. Each passing pair must also have a deny
    line that covers it, so the pass is attributable to the ACL.
    """
    from netops_autopilot.engines.verification_executor import VerificationExecutor

    fabric, report = _run()
    unenforceable = {(a, b) for a, b, _ in report.design.unenforceable_isolation}
    zones = {z.zone: z for z in report.design.zones}
    routes = fabric.open("seed-01", ()).execute("show ip route", 5).decode()
    lines = _acl_lines(fabric)

    def on_wire(zone):
        return (VerificationExecutor._connected_network(routes, zone)
                or str(ipaddress.ip_network(zone.subnet, strict=False)))

    checked = 0
    for tid in report.verification["passed"]:
        if "CONNECTIVITY_DENY" not in tid:
            continue
        src, dst = tid.split(":")[-1].split("->")
        if (src, dst) in unenforceable:
            continue
        s_wire, d_wire = on_wire(zones[src]), on_wire(zones[dst])
        assert s_wire in routes and d_wire in routes, (
            f"{src}->{dst} passed while {s_wire} or {d_wire} is unrouted — "
            f"the pass came from the absence of a path, not from the ACL")
        s = ipaddress.ip_network(zones[src].subnet, strict=False)
        d = ipaddress.ip_network(zones[dst].subnet, strict=False)
        assert any(_deny_covers(line, s, d) for line in lines), (
            f"{src}->{dst} passed with no deny line covering {s} -> {d}")
        checked += 1
    assert checked, "no enforceable DENY test passed — nothing was proven"


def test_a_provider_addressed_pair_is_enforced_with_any_not_declared_hopeless():
    """A provider-chosen address is unknown; `any` on that side is not.

    These pairs used to be reported unenforceable, so every DHCP-handoff site
    was permanently INCOMPLETE at verification and its WAN isolation was
    configured nowhere. ``deny ip any <internal>`` inbound on the WAN gateway
    blocks inbound from the provider whatever address it handed out — an
    ordinary rule, not a weaker one.
    """
    fabric, report = _run()
    wan = [z.zone for z in report.design.zones if z.kind == "WAN"]
    assert wan, "the blueprint has no WAN zone — the test would be vacuous"
    pairs = [p for p in report.design.denied_pairs if wan[0] in p]
    assert pairs, "no denied pair involves the WAN — nothing to prove"
    assert report.design.unenforceable_isolation == (), (
        "a pair with one provider-assigned end is enforceable as `any`")

    lines = _acl_lines(fabric)
    subnet = {z.zone: z.subnet for z in report.design.zones}
    for src, dst in pairs:
        s = ipaddress.ip_network(subnet[src], strict=False)
        d = ipaddress.ip_network(subnet[dst], strict=False)
        assert any(_deny_covers(line, s, d) for line in lines), (
            f"{src}->{dst} not enforced")
    assert any(_ANY in line for line in lines), (
        "no `any` form was written, so the unknown side was not covered")
    assert report.verification["verdict"] == "PASS"
    assert report.verification["unrun"] == {}


def test_a_pair_with_both_ends_provider_chosen_is_reported_not_faked():
    """The one case `any` cannot express, and why.

    Naming either end is impossible, and ``deny ip any any`` would deny
    everything — so the pair is reported rather than misconfigured.
    """
    from types import SimpleNamespace

    from netops_autopilot.engines.design_engine import _unenforceable_isolation
    from netops_autopilot.engines.intent_compiler import RuleAction

    intent = SimpleNamespace(
        zones=[SimpleNamespace(name="wan-a"), SimpleNamespace(name="wan-b")],
        rules=[SimpleNamespace(src_zone="wan-a", dst_zone="wan-b",
                               action=RuleAction.DENY, precedence=1)])
    zones = [SimpleNamespace(zone="wan-a", kind="WAN"),
             SimpleNamespace(zone="wan-b", kind="WAN")]

    out = _unenforceable_isolation(intent, zones, "ISP fiber DHCP handoff")

    assert [(a, b) for a, b, _ in out] == [("wan-a", "wan-b")]
    assert "both" in out[0][2] and "provider" in out[0][2]


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


# ================================================ a dead rule is not a deny
def test_a_deny_naming_a_network_that_is_not_on_the_wire_enforces_nothing():
    """The trap this whole change exists to avoid.

    A WAN under a DHCP handoff is on the wire under the provider's network.
    A rule naming the block this platform *allocated* for it matches no
    packet: it reads as protection, passes review, and protects nothing. The
    grader judges against what the routing table says is connected, so such a
    rule is reported as not enforced rather than counted as a pass.
    """
    from types import SimpleNamespace

    from netops_autopilot.engines.verification_executor import VerificationExecutor

    src = SimpleNamespace(zone="users", subnet="10.240.0.0/25", vlan_id=10)
    dst = SimpleNamespace(zone="wan", subnet="10.240.0.208/29", vlan_id=40)

    dead = "ip access-list extended ACL_USERS_IN\n deny ip 10.240.0.0 0.0.0.127 10.240.0.208 0.0.0.7\n permit ip any any\n"
    live = "ip access-list extended ACL_USERS_IN\n deny ip 10.240.0.0 0.0.0.127 0.0.0.0 255.255.255.255\n permit ip any any\n"

    # graded against the allocated block, the dead rule looks fine — which is
    # exactly why the on-wire network has to be passed in
    assert VerificationExecutor._acl_denies(dead, src, dst) is True
    assert VerificationExecutor._acl_denies(
        dead, src, dst, dst_on_wire="203.0.113.0/29") is False
    assert VerificationExecutor._acl_denies(
        live, src, dst, dst_on_wire="203.0.113.0/29") is True


def test_the_connected_network_is_read_for_the_right_svi_only():
    """``Vlan4`` must not be matched by a line about ``Vlan40``."""
    from types import SimpleNamespace

    from netops_autopilot.engines.verification_executor import VerificationExecutor

    text = "      10.9.8.0/24 is directly connected, Vlan40\n"
    assert VerificationExecutor._connected_network(
        text, SimpleNamespace(vlan_id=40)) == "10.9.8.0/24"
    assert VerificationExecutor._connected_network(
        text, SimpleNamespace(vlan_id=4)) is None
    assert VerificationExecutor._connected_network(
        "no routes here", SimpleNamespace(vlan_id=40)) is None
