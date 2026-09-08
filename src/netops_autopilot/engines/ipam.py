"""E07 IPAM Engine — deterministic IP planning (§4: DECIDE cell for
overlap/subnetting). Pure stdlib (``ipaddress``), pure functions, typed
failures. No randomness, no heuristics: identical inputs ⇒ identical plan.

Failure codes are stable strings consumed by engines/gates:
  INVALID_CIDR, IPAM_OVERLAP, PREFIX_TOO_COARSE, PREFIX_TOO_FINE,
  INDEX_OUT_OF_RANGE, HOST_COUNT_EXCESS, RANGE_EXHAUSTED,
  ADDRESS_OUTSIDE_SUBNET, NOT_SUPPORTED.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Union

from ..core.failures import Failure, FailureClass

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def _blocked(code: str, detail: str) -> Failure:
    return Failure(cls=FailureClass.BLOCKED, causes=(f"{code}: {detail}",))


def parse_network(text: str) -> Network:
    try:
        return ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise _blocked("INVALID_CIDR", f"{text!r}: {exc}") from None


# ------------------------------------------------------------------ overlaps
def find_overlaps(cidrs: list[str]) -> list[tuple[str, str]]:
    """All overlapping pairs (deterministic order: input order, i<j).
    Containment and equality both count as overlap."""
    nets = [(text, parse_network(text)) for text in cidrs]
    out: list[tuple[str, str]] = []
    for i in range(len(nets)):
        for j in range(i + 1, len(nets)):
            a_text, a = nets[i]
            b_text, b = nets[j]
            if a.version != b.version:
                continue
            if a.overlaps(b):
                out.append((a_text, b_text))
    return out


def assert_no_overlap(cidrs: list[str]) -> None:
    overlaps = find_overlaps(cidrs)
    if overlaps:
        pairs = "; ".join(f"{a} <-> {b}" for a, b in overlaps)
        raise _blocked("IPAM_OVERLAP", pairs)


# ----------------------------------------------------------------- subnetting
def subnet_for_hosts(host_count: int, *, ipv6: bool = False) -> int:
    """Smallest prefixlen with capacity >= host_count.

    IPv4 accounts for network + broadcast addresses; prefixes finer than
    /29 for LANs are refused (P2P links use p2p_link, not this function).
    IPv6 is /64 in v1 — anything larger is NOT_SUPPORTED (T2)."""
    if host_count < 1:
        raise _blocked("HOST_COUNT_EXCESS", f"host_count={host_count}")
    if ipv6:
        capacity = 2 ** 64 - 2
        if host_count > capacity:
            raise _blocked("HOST_COUNT_EXCESS", f"{host_count} exceeds /64 capacity")
        return 64
    needed = host_count + 2
    if needed > 2 ** 16:
        raise _blocked("HOST_COUNT_EXCESS", f"{host_count} hosts require a supernet beyond v1 scope")
    prefix = 32
    while (2 ** (32 - prefix)) < needed:
        prefix -= 1
    return prefix


def allocate_subnet(parent: str, prefix_len: int, index: int) -> str:
    """The index-th block of size prefix_len inside parent (0-based).

    O(1) arithmetic — never enumerates blocks, so v6 /48→/64 (65 536
    blocks) is instant and deterministic."""
    parent_net = parse_network(parent)
    if prefix_len <= parent_net.prefixlen:
        raise _blocked("PREFIX_TOO_COARSE",
                       f"/{prefix_len} is not finer than parent /{parent_net.prefixlen}")
    max_bits = parent_net.max_prefixlen
    if prefix_len > max_bits:
        raise _blocked("PREFIX_TOO_FINE", f"/{prefix_len} exceeds /{max_bits}")
    total = 1 << (prefix_len - parent_net.prefixlen)
    if index < 0 or index >= total:
        raise _blocked("INDEX_OUT_OF_RANGE", f"index={index} outside 0..{total - 1} of {parent}")
    block_addrs = 1 << (max_bits - prefix_len)
    new_net_int = int(parent_net.network_address) + index * block_addrs
    return str(ipaddress.ip_network((new_net_int, prefix_len)))


# ------------------------------------------------------------------ gateways
def gateway_address(subnet: str, position: int = 1) -> str:
    """Deterministic gateway: the position-th usable address (default: first).

    IPv4: usable = hosts() (network/broadcast excluded). IPv6: arithmetic
    offset from the network address (subnet-router anycast position 0 is
    excluded) — NEVER enumerated, so /48-/64 scales are instant.
    /31-/32 (v4) and /127-/128 (v6) have no gateway concept ⇒ error."""
    net = parse_network(subnet)
    if net.version == 4:
        if net.prefixlen >= 31:
            raise _blocked("NOT_SUPPORTED", f"{subnet} is point-to-point/host-sized; no gateway")
        hosts = list(net.hosts())
        if position < 1 or position > len(hosts):
            raise _blocked("INDEX_OUT_OF_RANGE", f"gateway position={position} outside usable range of {subnet}")
        return str(hosts[position - 1])
    if net.prefixlen >= 127:
        raise _blocked("NOT_SUPPORTED", f"{subnet} is point-to-point-sized; no gateway")
    max_position = net.num_addresses - 2  # exclude subnet-router anycast + last reserved
    if position < 1 or position > max_position:
        raise _blocked("INDEX_OUT_OF_RANGE", f"gateway position={position} outside usable range of {subnet}")
    return str(ipaddress.ip_address(int(net.network_address) + position))


# --------------------------------------------------------------------- DHCP
@dataclass(frozen=True)
class DhcpRange:
    start: str
    end: str
    size: int


def dhcp_range(subnet: str, *, gateway: str, size: int, skip_first_n: int = 0) -> DhcpRange:
    """First ``size`` consecutive usable addresses after skipping the gateway
    and ``skip_first_n`` low addresses (static reservations zone).

    IPv4-only in v1: DHCPv6/SLAAC pool planning is a separate, not-yet-
    modeled surface (T2 ⇒ NOT_SUPPORTED, never approximated).
    Deterministic by construction: ascending allocation only."""
    net = parse_network(subnet)
    if net.version != 4:
        raise _blocked("NOT_SUPPORTED", "DHCP range planning is IPv4-only in v1; DHCPv6/SLAAC NOT_MODELED")
    gw = ipaddress.ip_address(gateway)
    if gw not in net:
        raise _blocked("ADDRESS_OUTSIDE_SUBNET", f"gateway {gateway} not inside {subnet}")
    if size < 1:
        raise _blocked("RANGE_EXHAUSTED", f"size={size}")
    pool = [a for a in net.hosts() if a != gw][skip_first_n:]
    if len(pool) < size:
        raise _blocked("RANGE_EXHAUSTED", f"{len(pool)} usable < requested {size} in {subnet}")
    return DhcpRange(start=str(pool[0]), end=str(pool[size - 1]), size=size)


# ------------------------------------------------------------------ P2P links
def p2p_link(pool: str, index: int, *, rfc3021: bool = True) -> tuple[str, str, str]:
    """Allocate one point-to-point link from the pool: (/31, endpoint_a,
    endpoint_b) per RFC 3021, or /30 when rfc3021=False. Endpoints are the
    two addresses in ascending order — never randomly paired."""
    prefix_len = 31 if rfc3021 else 30
    subnet_text = allocate_subnet(pool, prefix_len, index)
    net = ipaddress.ip_network(subnet_text)
    addresses = [str(a) for a in net]
    if rfc3021:
        return subnet_text, addresses[0], addresses[1]
    usable = [str(a) for a in net.hosts()]
    return subnet_text, usable[0], usable[1]


# ------------------------------------------------------------- summarization
def summarizes(summary: str, members: list[str]) -> bool:
    """True iff every member subnet is fully contained in the summary."""
    summary_net = parse_network(summary)
    return all(parse_network(m).version == summary_net.version and parse_network(m).subnet_of(summary_net)
               for m in members)


# ----------------------------------------------------------------------- IPv6
def validate_ula(prefix: str) -> bool:
    """True iff the prefix sits inside fc00::/7 (RFC 4193 ULA space)."""
    net = parse_network(prefix)
    if net.version != 6:
        return False
    return ipaddress.ip_network("fc00::/7").supernet_of(net)


def site_lan_prefix(site_prefix: str, index: int) -> str:
    """The index-th /64 LAN prefix of a site's (typically /48) assignment."""
    return allocate_subnet(site_prefix, 64, index)
