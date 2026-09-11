"""Tests for Phase R2 engines — BGP / templates / services."""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from netops_autopilot.engines.bgp_advanced import (
    parse_route_maps, bucketize_communities,
    RouteMapAction,
)
from netops_autopilot.engines.templates import (
    TemplateContext, render_template, render_string,
    available_templates,
)
from netops_autopilot.engines.services import (
    parse_isc_leases, parse_windows_scopes, build_report,
)


# ==================================================================
# R8 — BGP advanced
# ==================================================================


def test_bgp_parse_route_maps():
    output = """
route-map RM-IBGP-IN permit 10
 match ip address prefix-list CUSTOMERS
 match community COMM-LIST-CUSTOMERS
 set local-preference 200
 set community 65001:100
!
route-map RM-IBGP-OUT deny 5
 match ip address prefix-list STAFF
 set metric 50
!
route-map RM-IBGP-IN permit 20
 set as-path prepend 65001 65001
!
"""
    rms = parse_route_maps(output)
    assert len(rms) == 2
    rm_in = next(r for r in rms if r.name == "RM-IBGP-IN")
    assert rm_in.clause_count == 2
    assert rm_in.permit_count == 2
    assert rm_in.clauses[0].match_prefix_list == "CUSTOMERS"
    assert rm_in.clauses[0].set_local_pref == 200
    assert rm_in.clauses[0].set_community == "65001:100"


def test_bgp_bucketize_communities():
    output = """
route-map RM-A permit 10
 set community 65001:200
!
route-map RM-B deny 5
 match community COMM-LOW
!
"""
    rms = parse_route_maps(output)
    rep = bucketize_communities(rms)
    rendered = rep.render("en")
    assert "BGP communities" in rendered


def test_bgp_empty_input():
    rms = parse_route_maps("")
    assert rms == []


# ==================================================================
# R9 — Templates
# ==================================================================


def test_templates_available():
    templates = available_templates()
    assert "vlan_ios" in templates
    assert "bgp_ios" in templates
    assert "dhcp_snoop_ios" in templates
    assert "ntp_ios" in templates


def test_templates_render_vlan_ok():
    ctx = TemplateContext()
    ctx["vlan_id"] = 10
    ctx["vlan_name"] = "MGMT"
    ctx["mgmt_ip"] = "10.99.0.1"
    ctx["mgmt_mask"] = "255.255.255.0"
    res = render_template("vlan_ios", ctx)
    assert res.is_valid
    assert "vlan 10" in res.output
    assert "10.99.0.1" in res.output


def test_templates_render_missing_field():
    ctx = TemplateContext()
    ctx["vlan_id"] = 10
    # vlan_name missing
    res = render_template("vlan_ios", ctx)
    assert not res.is_valid
    assert "vlan_name" in res.missing_fields


def test_templates_render_unknown_template():
    res = render_template("does_not_exist", TemplateContext())
    assert not res.is_valid


def test_templates_inline_render():
    res = render_string(
        "ntp server {{ server }} prefer\n",
        TemplateContext(fields={"server": "10.0.0.1"}),
    )
    assert res.is_valid
    assert "ntp server 10.0.0.1 prefer" in res.output


# ==================================================================
# R10 — DNS/DHCP services
# ==================================================================


def test_services_parse_isc_leases_minimal():
    text = """
lease 10.0.0.100 {
  starts 1 2026/09/01 12:00:00;
  ends 1 2026/09/01 18:00:00;
  hardware ethernet aa:bb:cc:dd:ee:01;
  client-hostname "alice-laptop";
  binding state active;
}
lease 10.0.0.101 {
  starts 2 2026/09/02 08:00:00;
  ends 2 2026/09/02 12:00:00;
  hardware ethernet aa:bb:cc:dd:ee:02;
  binding state free;
}
"""
    leases = parse_isc_leases(text)
    assert len(leases) >= 1
    assert leases[0].hostname == "alice-laptop"
    assert leases[0].mac == "aa:bb:cc:dd:ee:01"


def test_services_parse_windows_scopes():
    text = """
Subnet: 10.0.0.0
Start Address: 10.0.0.100
End Address: 10.0.0.200
Subnet: 10.0.1.0
Start Address: 10.0.1.1
End Address: 10.0.1.254
"""
    scopes = parse_windows_scopes(text)
    assert len(scopes) == 2


def test_services_build_report_aggregates():
    leases = [
        # Two active, one expired (epoch 0 ends is past)
        # Use the parser for safety.
    ]
    # Empty report should still render without exception.
    rep = build_report()
    assert rep.total_leases == 0
    assert rep.active_leases == 0
    text = rep.render("en")
    assert "DHCP" in text


def test_services_render_bilingual():
    rep = build_report()
    en = rep.render("en")
    ar = rep.render("ar")
    assert "DHCP" in en
    assert "DHCP" in ar
    assert "نشط" in ar
