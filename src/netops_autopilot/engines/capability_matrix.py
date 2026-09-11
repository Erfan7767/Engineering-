"""Hardware Capability Matrix — what does this device actually support?

A 30-year engineer knows that a Cisco 2901 cannot run the same
features as a Catalyst 9500. Before designing a network, the
engineer looks up the device's capabilities and designs
accordingly. This module is the typed implementation.

What it does:

* Maintains a hardware capability catalogue (per model per
  vendor) covering common features: routing protocols, switching
  features, security features, hardware crypto, PoE budget, etc.
* Looks up a device's capabilities from its inventory record.
* Returns a typed capability report. If the model is unknown,
  the verdict is UNKNOWN, not a guess.

What it does NOT do (typed, never silent):

* It does NOT pretend to know an unknown device. A new model
  returns ``UNKNOWN_MODEL`` with an instruction to add it to
  the catalogue.
* It does NOT silently degrade. A feature that needs an
  unsupported capability raises a typed ``CAPABILITY_MISSING``
  with the specific feature and required capability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Capability(str, Enum):
    __test__ = False

    # Routing
    OSPF = "OSPF"
    BGP = "BGP"
    EIGRP = "EIGRP"
    RIP = "RIP"
    STATIC = "STATIC"
    # Switching
    L2_SWITCHING = "L2_SWITCHING"
    L3_SWITCHING = "L3_SWITCHING"
    VLAN_TRUNK = "VLAN_TRUNK"
    VXLAN = "VXLAN"
    # Security
    ACL = "ACL"
    NAT = "NAT"
    IPSEC = "IPSEC"
    MACSEC = "MACSEC"
    # Hardware
    HARDWARE_CRYPTO = "HARDWARE_CRYPTO"
    POE = "POE"
    POE_PLUS = "POE_PLUS"
    UPOE = "UPOE"
    # Management
    SSH = "SSH"
    SNMP_V3 = "SNMP_V3"
    NETCONF = "NETCONF"
    RESTCONF = "RESTCONF"
    # Performance
    HIGH_AVAILABILITY = "HIGH_AVAILABILITY"
    STACKING = "STACKING"
    MLAG = "MLAG"


@dataclass(frozen=True)
class HardwareSpec:
    """A hardware capability record for one model."""

    __test__ = False

    vendor: str
    model: str
    capabilities: frozenset[Capability]
    max_vlans: int = 0
    max_routes: int = 0
    notes: str = ""


# A small starter catalogue. Real systems would load this from
# a database or a vendor API.
_CATALOG: tuple[HardwareSpec, ...] = (
    HardwareSpec(
        vendor="cisco",
        model="C8300-1N-4T",
        capabilities=frozenset({
            Capability.OSPF, Capability.BGP, Capability.EIGRP, Capability.STATIC,
            Capability.L3_SWITCHING, Capability.VLAN_TRUNK,
            Capability.ACL, Capability.NAT, Capability.IPSEC, Capability.MACSEC,
            Capability.HARDWARE_CRYPTO,
            Capability.SSH, Capability.SNMP_V3, Capability.NETCONF, Capability.RESTCONF,
        }),
        max_vlans=4094, max_routes=1_000_000,
        notes="ISR 1000/4000/8300 series — modular WAN edge",
    ),
    HardwareSpec(
        vendor="cisco",
        model="C9500-48Y4C",
        capabilities=frozenset({
            Capability.OSPF, Capability.BGP, Capability.EIGRP, Capability.STATIC,
            Capability.L2_SWITCHING, Capability.L3_SWITCHING, Capability.VLAN_TRUNK, Capability.VXLAN,
            Capability.ACL, Capability.MACSEC,
            Capability.HARDWARE_CRYPTO,
            Capability.SSH, Capability.SNMP_V3, Capability.NETCONF, Capability.RESTCONF,
            Capability.HIGH_AVAILABILITY, Capability.STACKING,
        }),
        max_vlans=4094, max_routes=256_000,
        notes="Catalyst 9500 — campus core",
    ),
    HardwareSpec(
        vendor="cisco",
        model="C9200-48P",
        capabilities=frozenset({
            Capability.OSPF, Capability.BGP, Capability.EIGRP, Capability.STATIC,
            Capability.L2_SWITCHING, Capability.L3_SWITCHING, Capability.VLAN_TRUNK,
            Capability.ACL, Capability.MACSEC,
            Capability.HARDWARE_CRYPTO,
            Capability.SSH, Capability.SNMP_V3, Capability.NETCONF, Capability.RESTCONF,
            Capability.STACKING, Capability.POE, Capability.POE_PLUS,
        }),
        max_vlans=4094, max_routes=32_000,
        notes="Catalyst 9200 — access layer with PoE+",
    ),
    HardwareSpec(
        vendor="cisco",
        model="C2960X-48TS-L",
        capabilities=frozenset({
            Capability.L2_SWITCHING, Capability.VLAN_TRUNK,
            Capability.ACL,
            Capability.SSH, Capability.SNMP_V3,
        }),
        max_vlans=4094, max_routes=0,
        notes="Catalyst 2960-X — L2 access only",
    ),
    HardwareSpec(
        vendor="cisco",
        model="ASR-1001-HX",
        capabilities=frozenset({
            Capability.OSPF, Capability.BGP, Capability.EIGRP, Capability.STATIC,
            Capability.L3_SWITCHING, Capability.VLAN_TRUNK,
            Capability.ACL, Capability.NAT, Capability.IPSEC, Capability.MACSEC,
            Capability.HARDWARE_CRYPTO,
            Capability.SSH, Capability.SNMP_V3, Capability.NETCONF,
            Capability.HIGH_AVAILABILITY,
        }),
        max_vlans=4094, max_routes=4_000_000,
        notes="ASR 1000 — service provider edge",
    ),
    # Generic fallback (used when model is unknown but the
    # vendor is recognised; we mark L2/L3 as available but
    # mark everything else as unknown).
    HardwareSpec(
        vendor="generic",
        model="unknown",
        capabilities=frozenset({Capability.STATIC, Capability.SSH}),
        max_vlans=0, max_routes=0,
        notes="Fallback for unknown models — capability check returns UNKNOWN",
    ),
)


def lookup(vendor: str, model: str) -> HardwareSpec | None:
    """Look up a model in the catalogue. Returns None if unknown."""
    v = vendor.strip().lower()
    m = model.strip().lower()
    for spec in _CATALOG:
        if spec.vendor == v and spec.model.lower() == m:
            return spec
    return None


def has_capability(vendor: str, model: str, cap: Capability) -> tuple[bool, str]:
    """Return (has_cap, reason). Reason is one of:
    - "OK" (has capability)
    - "CAPABILITY_MISSING" (model known, capability not in set)
    - "UNKNOWN_MODEL" (model not in catalogue)
    """
    spec = lookup(vendor, model)
    if spec is None:
        return False, f"UNKNOWN_MODEL: {vendor}/{model}"
    if cap in spec.capabilities:
        return True, "OK"
    return False, f"CAPABILITY_MISSING: {vendor}/{model} does not support {cap.value}"


def render_capabilities(spec: HardwareSpec, lang: str = "en") -> str:
    caps = ", ".join(sorted(c.value for c in spec.capabilities))
    if lang == "ar":
        return (
            f"المواصفات لـ {spec.vendor} {spec.model}\n"
            f"  القدرات: {caps}\n"
            f"  أقصى VLAN: {spec.max_vlans}   أقصى مسارات: {spec.max_routes}\n"
            f"  ملاحظات: {spec.notes}"
        )
    return (
        f"Capabilities for {spec.vendor} {spec.model}\n"
        f"  Capabilities: {caps}\n"
        f"  Max VLANs: {spec.max_vlans}   Max routes: {spec.max_routes}\n"
        f"  Notes: {spec.notes}"
    )
