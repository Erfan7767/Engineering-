"""E07 IPAM Engine: deterministic allocation, overlap detection, typed errors."""

import pytest

from netops_autopilot.core.failures import Failure
from netops_autopilot.engines import ipam


def cause(result_or_exc):
    return result_or_exc.value.causes[0] if hasattr(result_or_exc, "value") else ""


# ------------------------------------------------------------------ overlaps
def test_overlap_detection_pairs():
    assert ipam.find_overlaps(["10.0.0.0/24", "10.0.1.0/24"]) == []
    assert ipam.find_overlaps(["10.0.0.0/24", "10.0.0.128/25"]) == [("10.0.0.0/24", "10.0.0.128/25")]
    assert ipam.find_overlaps(["10.0.0.0/24", "10.0.0.0/24"]) == [("10.0.0.0/24", "10.0.0.0/24")]
    # partial overlap across boundary
    assert ipam.find_overlaps(["10.0.0.0/23", "10.0.1.0/24"]) == [("10.0.0.0/23", "10.0.1.0/24")]


def test_overlap_across_families_is_not_an_overlap():
    assert ipam.find_overlaps(["10.0.0.0/24", "fd00::/64"]) == []


def test_assert_no_overlap_raises_with_pairs():
    with pytest.raises(Failure) as exc:
        ipam.assert_no_overlap(["192.168.10.0/24", "192.168.10.0/25", "172.16.0.0/16"])
    assert "IPAM_OVERLAP" in exc.value.causes[0]
    assert "192.168.10.0/24 <-> 192.168.10.0/25" in exc.value.causes[0]


def test_invalid_cidr_is_typed():
    with pytest.raises(Failure) as exc:
        ipam.parse_network("10.0.0.1/24")  # host bits set, strict
    assert "INVALID_CIDR" in exc.value.causes[0]


# ---------------------------------------------------------------- subnetting
@pytest.mark.parametrize("hosts,prefix", [
    (1, 30), (2, 30), (30, 27), (254, 24), (255, 23), (4094, 20),
])
def test_subnet_for_hosts_exact_sizing(hosts, prefix):
    assert ipam.subnet_for_hosts(hosts) == prefix


def test_subnet_for_hosts_refuses_too_small_lans_and_huge_counts():
    with pytest.raises(Failure) as exc:
        ipam.subnet_for_hosts(0)
    assert "HOST_COUNT_EXCESS" in exc.value.causes[0]
    with pytest.raises(Failure):
        ipam.subnet_for_hosts(70000)


def test_subnet_for_hosts_ipv6_is_64():
    assert ipam.subnet_for_hosts(500, ipv6=True) == 64


def test_allocate_subnet_indexing_is_deterministic():
    assert ipam.allocate_subnet("10.10.0.0/16", 24, 0) == "10.10.0.0/24"
    assert ipam.allocate_subnet("10.10.0.0/16", 24, 1) == "10.10.1.0/24"
    assert ipam.allocate_subnet("10.10.0.0/16", 24, 255) == "10.10.255.0/24"
    with pytest.raises(Failure) as exc:
        ipam.allocate_subnet("10.10.0.0/16", 24, 256)
    assert "INDEX_OUT_OF_RANGE" in exc.value.causes[0]
    with pytest.raises(Failure) as exc:
        ipam.allocate_subnet("10.10.0.0/24", 24, 0)
    assert "PREFIX_TOO_COARSE" in exc.value.causes[0]


# ------------------------------------------------------------------ gateways
def test_gateway_first_usable_by_default():
    assert ipam.gateway_address("192.168.10.0/24") == "192.168.10.1"
    assert ipam.gateway_address("192.168.10.0/24", position=2) == "192.168.10.2"
    assert ipam.gateway_address("fd00:10::/64") == "fd00:10::1"


def test_gateway_refuses_p2p_sizes():
    with pytest.raises(Failure) as exc:
        ipam.gateway_address("10.0.0.0/31")
    assert "NOT_SUPPORTED" in exc.value.causes[0]


# ---------------------------------------------------------------------- DHCP
def test_dhcp_range_skips_gateway_and_reservations():
    r = ipam.dhcp_range("192.168.10.0/24", gateway="192.168.10.1", size=10, skip_first_n=8)
    assert (r.start, r.end, r.size) == ("192.168.10.10", "192.168.10.19", 10)


def test_dhcp_range_exhaustion_and_gateway_location():
    with pytest.raises(Failure) as exc:
        ipam.dhcp_range("192.168.10.0/28", gateway="192.168.10.1", size=100)
    assert "RANGE_EXHAUSTED" in exc.value.causes[0]
    with pytest.raises(Failure) as exc:
        ipam.dhcp_range("192.168.10.0/24", gateway="10.9.9.9", size=5)
    assert "ADDRESS_OUTSIDE_SUBNET" in exc.value.causes[0]


# ----------------------------------------------------------------- P2P links
def test_p2p_rfc3021_allocation():
    subnet, a, b = ipam.p2p_link("10.99.0.0/24", 0)
    assert subnet == "10.99.0.0/31" and a == "10.99.0.0" and b == "10.99.0.1"
    subnet, a, b = ipam.p2p_link("10.99.0.0/24", 3)
    assert subnet == "10.99.0.6/31" and a == "10.99.0.6" and b == "10.99.0.7"


def test_p2p_fallback_30():
    subnet, a, b = ipam.p2p_link("10.99.0.0/24", 0, rfc3021=False)
    assert subnet == "10.99.0.0/30" and a == "10.99.0.1" and b == "10.99.0.2"


# ------------------------------------------------------------- summarization
def test_summarization_truths():
    assert ipam.summarizes("10.10.0.0/16", ["10.10.1.0/24", "10.10.200.0/24"]) is True
    assert ipam.summarizes("10.10.0.0/16", ["10.10.1.0/24", "10.11.0.0/24"]) is False
    assert ipam.summarizes("10.10.0.0/16", ["fd00::/64"]) is False


# ----------------------------------------------------------------------- IPv6
def test_ula_validation():
    assert ipam.validate_ula("fd12:3456::/48") is True
    assert ipam.validate_ula("2001:db8::/48") is False
    assert ipam.validate_ula("10.0.0.0/8") is False


def test_site_lan_prefix_allocation():
    assert ipam.site_lan_prefix("fd12:3456::/48", 0) == "fd12:3456::/64"
    assert ipam.site_lan_prefix("fd12:3456::/48", 1) == "fd12:3456:0:1::/64"
    with pytest.raises(Failure):
        ipam.site_lan_prefix("fd12:3456::/48", 65536)


# --------------------------------------------------------------- determinism
def test_identical_inputs_identical_outputs():
    for _ in range(3):
        assert ipam.allocate_subnet("172.20.0.0/16", 22, 7) == "172.20.28.0/22"
        r = ipam.dhcp_range("172.20.28.0/22", gateway="172.20.28.1", size=50, skip_first_n=10)
        assert (r.start, r.end) == ("172.20.28.12", "172.20.28.61")
