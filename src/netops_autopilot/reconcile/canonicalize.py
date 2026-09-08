"""Canonicalization (D0-08 §4, §12) — deterministic, data-driven.

Port names are normalized BEFORE any matching. Unknown names pass through
unchanged and are flagged, never mangled by heuristics (L01).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------- port names
#: Cisco IOS/IOS-XE abbreviation → canonical base. Longest-first matching.
CISCO_ABBREVIATIONS: dict[str, str] = {
    "Hu": "HundredGigE",
    "Fo": "FortyGigE",
    "Te": "TenGigabitEthernet",
    "Gi": "GigabitEthernet",
    "Fa": "FastEthernet",
    "Et": "Ethernet",
    "Po": "Port-channel",
    "Lo": "Loopback",
    "Vl": "Vlan",
    "Tu": "Tunnel",
    "Se": "Serial",
}

#: Canonical bases recognized case-insensitively (already-expanded names).
CISCO_CANONICAL_BASES: frozenset[str] = frozenset({
    v.lower() for v in CISCO_ABBREVIATIONS.values()
} | {"nve", "bdi", "appnav", "ucse"})

_SPLIT_RE = re.compile(r"^(?P<prefix>[A-Za-z-]+)(?P<rest>.*)$")


@dataclass(frozen=True)
class NameNormalization:
    canonical: str
    changed: bool
    rule: str  # which rule produced the result ("cisco_expand", "cisco_case", "juniper_unit", "passthrough", …)


def normalize_cisco_port(name: str) -> NameNormalization:
    """Gi1/0/1 ≡ GigabitEthernet1/0/1; port-channel casing canonicalized."""
    m = _SPLIT_RE.match(name.strip())
    if not m:
        return NameNormalization(name, False, "passthrough")
    prefix, rest = m.group("prefix"), m.group("rest")

    # Longest abbreviation first (Hu before H, Te before T…).
    for abbrev in sorted(CISCO_ABBREVIATIONS, key=len, reverse=True):
        if prefix == abbrev or prefix.lower() == abbrev.lower():
            return NameNormalization(CISCO_ABBREVIATIONS[abbrev] + rest, prefix != CISCO_ABBREVIATIONS[abbrev], "cisco_expand")

    # Already-canonical base (any casing) ⇒ canonical casing.
    low = prefix.lower().rstrip("-")
    for base in CISCO_CANONICAL_BASES:
        if low == base:
            canonical = next(v for v in CISCO_ABBREVIATIONS.values() if v.lower() == base) if base in {v.lower() for v in CISCO_ABBREVIATIONS.values()} else prefix
            candidate = canonical + rest
            if candidate != name:
                return NameNormalization(candidate, True, "cisco_case")
            return NameNormalization(name, False, "cisco_case")
    return NameNormalization(name, False, "passthrough")


_JUNOS_UNIT_RE = re.compile(r"^(?P<base>[A-Za-z]+-[0-9]/[0-9]/[0-9]+)(?:\.(?P<unit>[0-9]+))?$")


def normalize_junos_port(name: str) -> tuple[str, int | None]:
    """ge-0/0/1.0 → ("ge-0/0/1", 0); names not in fpc/pic/port[.unit] form
    return unchanged with unit None (no guessing)."""
    m = _JUNOS_UNIT_RE.match(name.strip())
    if not m:
        return name, None
    unit = m.group("unit")
    return m.group("base"), int(unit) if unit is not None else None


def normalize_routeros_port(name: str) -> NameNormalization:
    """RouterOS names are already canonical; whitespace stripped only."""
    stripped = name.strip()
    return NameNormalization(stripped, stripped != name, "routeros_strip")


# --------------------------------------------------------------- vlan lists
def canonical_vlan_list(spec: str) -> str:
    """'1,3-5,2' → '1-5'; '7,7' → '7'. Invalid tokens ⇒ ValueError (typed,
    surfaced by engines as BLOCKED — never silently dropped)."""
    numbers: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            lo_s, hi_s = token.split("-", 1)
            lo, hi = int(lo_s), int(hi_s)
            if lo > hi or lo < 1:
                raise ValueError(f"invalid vlan range: {token!r}")
            numbers.update(range(lo, hi + 1))
        else:
            value = int(token)
            if value < 1:
                raise ValueError(f"invalid vlan id: {token!r}")
            numbers.add(value)
    if not numbers:
        return ""
    # Emit minimal range notation deterministically.
    parts: list[str] = []
    start = prev = min(numbers)
    for value in sorted(numbers)[1:] + [None]:  # type: ignore[list-item]
        if value is not None and value == prev + 1:
            prev = value
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        if value is not None:
            start = prev = value
    return ",".join(parts)


# ------------------------------------------------------------------ statuses
STATUS_SYNONYMS: dict[str, str] = {
    "up": "up",
    "connected": "up",
    "active": "up",
    "down": "down",
    "notconnect": "down",
    "inactive": "down",
    "administratively down": "admin_down",
    "admin down": "admin_down",
    "disabled": "admin_down",
}


def canonical_status(raw: str) -> tuple[str, bool]:
    """Return (canonical, known). Unknown statuses pass through lowercased
    with known=False — reconciliation treats them as NOT comparable."""
    key = raw.strip().lower()
    if key in STATUS_SYNONYMS:
        return STATUS_SYNONYMS[key], True
    return key, False
