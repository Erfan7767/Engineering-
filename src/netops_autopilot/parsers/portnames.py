"""Port-name normalization (D0-08 §4) — runs before ANY matching.

Deterministic, per-vendor data rules; grown from lab evidence. Unmapped
names stay RAW (never rewritten into another guess) and the caller can see
``mapped=False`` — normalization can never fabricate a correspondence
(T2). Only case and vendor-long→short shape are normalized; identity of
the port (numbers) is never altered.
"""

from __future__ import annotations

import re

# Cisco IOS-XE long→short prefixes, longest-first so a longer prefix always
# wins over a shorter overlapping one at the same position.
_CISCO_PREFIXES: tuple[tuple[str, str], ...] = tuple(sorted(
    {
        "twentyfivegige": "tw",
        "twohundredgigabitethernet": "twohu",
        "hundredgigabitethernet": "hu",
        "fortygigabitethernet": "fo",
        "twentyfivegigabitethernet": "tw",
        "tengigabitethernet": "te",
        "fivegigabitethernet": "fiv",
        "gigabitethernet": "gi",
        "fastethernet": "fa",
        "appgigabitethernet": "ap",
        "port-channel": "po",
        "loopback": "lo",
        "tunnel": "tu",
        "vlan": "vl",
        "management": "mg",
        "ethernet": "eth",
        "serial": "se",
        "bundle-ether": "be",
        "nve": "nve",
        "null": "nu",
    }.items(),
    key=lambda item: -len(item[0]),
))

_JUNOS_UNIT = re.compile(r"^(?P<phys>[a-z]+-\d+/\d+/\d+)(?:\.\d+)?$", re.I)


def normalize_port(vendor_family: str, name: str | None) -> tuple[str, bool]:
    """Return (canonical_name, mapped). ``mapped=False`` ⇒ raw passthrough.

    Cisco: 'GigabitEthernet1/0/1' ≡ 'Gi1/0/1' (§4's own example).
    Junos: 'ge-0/0/1.0' ≡ 'ge-0/0/1' (logical unit folded to the PHY).
    Others: case-fold only — their CLI/LLDP names are already canonical.
    """
    if not name:
        return ("", False)
    text = name.strip()
    if not text:
        return ("", False)
    family = (vendor_family or "").lower()

    if family.startswith("cisco"):
        low = text.lower()
        for long, short in _CISCO_PREFIXES:
            if low.startswith(long):
                rest = text[len(long):]
                # Do not fold a prefix that runs INTO the numbering
                # (e.g. 'Ethernet0' vs 'Ethernet0/0' are the same port;
                # 'EthernetMgmt' was listed separately already).
                return (short + rest.lower(), True)
        return (text.lower(), False)

    if family.startswith("junos"):
        m = _JUNOS_UNIT.match(text)
        if m:
            return (m.group("phys").lower(), True if "." in text else False)
        return (text.lower(), False)

    # routeros / arubaos / fortios / unifi / unknown family: case-fold only.
    return (text.lower(), False)
