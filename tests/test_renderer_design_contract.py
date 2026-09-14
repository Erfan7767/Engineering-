"""The design engine's REAL output, rendered by EVERY renderer we ship.

This exists because the two halves of the system drifted apart without anything
noticing. The design engine emits an SVI node whose parameters are
``{vlan_id, address, address_ip, address_mask, address_prefix, zone}``, while the
RouterOS, Junos and FortiOS templates all addressed that interface as ``{name}``
or ``{interface}`` — parameters nobody emits. The gateway address, the one node a
design cannot work without, silently rendered as NOT_MODELED on three of five
vendors:

    ios-xe    35/35      routeros  11/35      junos  15/35
    arubaos   18/35      fortios    4/35

Nothing caught it because the renderer/allowlist alignment test feeds the
renderers hand-written samples that share the same wrong assumption. A test that
renders the design engine's own output against every data file is the only thing
that pins the two sides together, so that is what this is.

Two distinct failure modes are kept apart on purpose:

* **unbound parameter** — the template asks for data the design engine does not
  provide. This is always a bug in one of the two files, never a legitimate
  capability gap, so it is asserted to be zero.
* **feature not modeled** — the vendor genuinely has no template for that
  feature. That is a real capability gap and is reported honestly by the
  renderer, so it is locked to a declared set here: it may only shrink, and
  shrinking it is a deliberate, visible act.
"""
from __future__ import annotations

import dataclasses

import pytest

from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli.scenarios import make_scenario_io
from netops_autopilot.engines.config_renderer import _RENDERER_FILES, render_ir

from .support.simfabric import SimFabricFactory, make_ledger_stack

#: Features each vendor's renderer data file does NOT model, measured against a
#: real branch design. Locked so a gap cannot open silently: adding a template
#: makes this fail until the entry is removed, which is the point — progress
#: across vendors should be a visible change, not a quiet one.
NOT_MODELED_FEATURES = {
    "ios-xe": frozenset(),
    "arubaos": frozenset({"dhcp", "wan_dhcp", "acl_deny", "acl_permit", "acl_apply"}),
    "junos": frozenset({"dhcp", "wan_dhcp", "acl_deny", "acl_permit", "acl_apply"}),
    "routeros": frozenset(),
    "fortios": frozenset({"trunk", "access", "dhcp", "wan_dhcp",
                          "acl_deny", "acl_permit", "acl_apply"}),
}


def _render_matrix():
    """{vendor_os: {feature: status}} from a real design, not a hand-built IR."""
    store, key_id, _collector, time_authority = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = make_scenario_io("branch")
    io.append_answers({"bond_confirm": "BOND"})
    engine = AutopilotEngine(store=store, key_id=key_id, io=io,
                             time_authority=time_authority)
    engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
               mgmt_session_factory=lambda r, h: fabric.open(r, h),
               port="SIM0", execute=True)

    matrix: dict[str, dict[str, str]] = {}
    for filename in sorted(set(_RENDERER_FILES.values())):
        os_name = next(k for k, v in _RENDERER_FILES.items() if v == filename)
        results: dict[str, str] = {}
        for _ref, ir in engine._irs.items():
            nodes = tuple(dataclasses.replace(n, vendor_os=os_name) for n in ir.nodes)
            rendered = render_ir(_ref, dataclasses.replace(ir, nodes=nodes))
            # render_ir emits exactly one block per node, in order, so the
            # feature name comes from the node itself rather than being parsed
            # back out of a node_id.
            assert len(rendered.blocks) == len(nodes)
            for node, block in zip(nodes, rendered.blocks):
                # A feature that renders anywhere is not "unmodeled" for the
                # vendor; only a total absence counts.
                if results.get(node.feature) == "RENDERED":
                    continue
                results[node.feature] = block.status if block.status == "RENDERED" \
                    else ("UNBOUND" if "unbound" in block.reason else "NOT_MODELED")
        matrix[os_name] = results
    return matrix


@pytest.fixture(scope="module")
def matrix():
    return _render_matrix()


def test_no_renderer_asks_for_a_parameter_the_design_never_emits(matrix):
    """An unbound parameter is always drift between the two files, never a gap."""
    broken = {os_name: sorted(f for f, st in feats.items() if st == "UNBOUND")
              for os_name, feats in matrix.items()}
    broken = {k: v for k, v in broken.items() if v}
    assert not broken, (
        "these templates reference parameters the design engine does not emit; "
        "either the template is wrong or the node is missing a value it already "
        f"knows: {broken}")


def test_the_unmodeled_feature_set_only_shrinks(matrix):
    """A capability gap is allowed, but it must be declared and may not grow."""
    actual = {os_name: frozenset(f for f, st in feats.items() if st != "RENDERED")
              for os_name, feats in matrix.items()}
    assert set(actual) == set(NOT_MODELED_FEATURES), (
        "a renderer data file appeared or disappeared; update the declared set")
    for os_name, declared in NOT_MODELED_FEATURES.items():
        assert actual[os_name] == declared, (
            f"{os_name}: modeled features changed.\n"
            f"  newly unmodeled (a regression): {sorted(actual[os_name] - declared)}\n"
            f"  newly modeled   (update NOT_MODELED_FEATURES): "
            f"{sorted(declared - actual[os_name])}")


def test_cisco_renders_the_whole_design(matrix):
    """The reference vendor must stay complete; everything else is measured
    against it."""
    feats = matrix["ios-xe"]
    assert feats and all(st == "RENDERED" for st in feats.values()), feats


def test_every_renderer_models_the_l3_gateway(matrix):
    """The SVI is the node a design cannot work without: without it a VLAN
    exists but has no address, so no client can ever use it. This is the exact
    regression that motivated the file, named on its own so it cannot hide
    inside a bigger set."""
    for os_name, feats in matrix.items():
        assert feats.get("svi") == "RENDERED", (
            f"{os_name} cannot render the gateway address for a zone")


def test_a_vendor_with_a_gap_says_so_instead_of_guessing(matrix):
    """Honesty check: the renderer's own reason must name the missing feature,
    not emit a plausible-looking command."""
    from netops_autopilot.engines.config_ir import (ConfigIR, IRNode, Operation,
                                                    Reversibility)

    for os_name, declared in NOT_MODELED_FEATURES.items():
        for feature in sorted(declared):
            rc = render_ir("probe", ConfigIR("t", (IRNode(
                f"{feature}-probe", "probe", Operation.CREATE, feature, os_name,
                {"probe": "no real parameters"}, Reversibility.REVERSIBLE_BY_REPLACE,
                (), ()),)))
            block = rc.blocks[0]
            assert block.status == "NOT_MODELED"
            assert feature in block.reason and os_name in block.reason, block.reason
            assert not block.commands


def test_resolver_lists_use_the_notation_each_vendor_demands():
    """IOS separates ``dns-server`` values with spaces; RouterOS separates list
    values with commas. The design engine normalises resolvers to the IOS form,
    so a comma vendor must not inherit it verbatim — a space there makes the
    device read the second resolver as an unrelated token.

    This was a live defect: the first RouterOS DHCP template used ``{dns}`` and
    rendered ``dns-server=1.1.1.1 9.9.9.9``, which RouterOS would not have
    accepted as two resolvers.
    """
    from netops_autopilot.engines.config_ir import (ConfigIR, IRNode, Operation,
                                                    Reversibility)

    params = {"pool": "users", "interface": "users", "network": "10.240.0.0",
              "netmask": "255.255.255.128", "prefix": "25",
              "gateway": "10.240.0.1", "exclude_first": "10.240.0.1",
              "exclude_last": "10.240.0.10", "pool_first": "10.240.0.11",
              "pool_last": "10.240.0.126", "dns": "1.1.1.1 9.9.9.9"}

    def dhcp_line(os_name):
        rc = render_ir("probe", ConfigIR("t", (IRNode(
            "dhcp-users", "probe", Operation.CREATE, "dhcp", os_name, dict(params),
            Reversibility.REVERSIBLE_BY_REPLACE, (), ()),)))
        assert rc.blocks[0].status == "RENDERED", rc.blocks[0].reason
        hits = [c.strip() for c in rc.blocks[0].commands if "dns" in c.lower()]
        assert len(hits) == 1, rc.blocks[0].commands
        return hits[0]

    ios = dhcp_line("ios-xe")
    assert "dns-server 1.1.1.1 9.9.9.9" in ios, ios      # space-separated
    ros = dhcp_line("routeros")
    assert "dns-server=1.1.1.1,9.9.9.9" in ros, ros      # comma-separated
    assert " " not in ros.split("dns-server=")[1], ros   # no stray second token
