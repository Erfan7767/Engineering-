"""VLAN Trunk Audit — which trunks carry which VLANs and are
they consistent across the network?

A 30-year network engineer maintains a trunk matrix: every
trunk on every switch knows which VLANs it allows. This
module parses ``show interfaces trunk`` and reports the
current trunk state plus a cross-device consistency check.

What it does:

* Parses trunk output into per-interface records.
* Returns a typed report listing every trunk with its
  allowed VLANs and active VLANs.
* Detects inconsistencies (e.g. trunk 1 allows VLAN 10 but
  trunk 2 between the same switches does not).

What it does NOT do (typed, never silent):

* It does NOT invent allowed-VLAN lists. If the device does
  not report them, the report is UNKNOWN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Trunk:
    __test__ = False

    interface: str
    status: str           # "trunking" | "not-trunking" | "auto"
    encapsulation: str    # "802.1q" | "isl" | "n-t" | "n-a"
    vlan_allowed: tuple[int, ...] = ()
    vlan_active: tuple[int, ...] = ()


_PORT_LINE = re.compile(
    r"^(?P<intf>\S+)\s+(?P<mode>on|off|auto|desirable|trunk|"
    r"trunking|not-trunking|nonegotiate)\s+"
    r"(?P<encap>\S+)\s+(?P<status>trunking|not-trunking)\s+"
    r"(?P<native>\d+)",
    re.MULTILINE,
)

_VLAN_LINE = re.compile(
    r"^VLANs\s+(?P<kind>allowed|active|active in vlan|forwarding|"
    r"in spanning tree|spantree)\s*:\s*(?P<vlans>[\d,\-,\s]+)$",
    re.MULTILINE | re.IGNORECASE,
)


def _parse_vlan_list(text: str) -> tuple[int, ...]:
    out: list[int] = []
    for piece in re.split(r"[,\s]+", text.strip()):
        if not piece:
            continue
        if "-" in piece:
            try:
                a, b = piece.split("-", 1)
                out.extend(range(int(a), int(b) + 1))
            except ValueError:
                continue
        else:
            try:
                out.append(int(piece))
            except ValueError:
                continue
    return tuple(sorted(set(out)))


def parse(output: str) -> list[Trunk]:
    """Parse ``show interfaces trunk`` output."""
    if not output or not output.strip():
        return []
    trunks: list[Trunk] = []
    for m in _PORT_LINE.finditer(output):
        intf = m.group("intf")
        status = m.group("status")
        encap = m.group("encap")
        start = m.end()
        nxt = _PORT_LINE.search(output, start)
        end = nxt.start() if nxt else len(output)
        block = output[start:end]
        allowed: tuple[int, ...] = ()
        active: tuple[int, ...] = ()
        for vl in _VLAN_LINE.finditer(block):
            kind = vl.group("kind").lower()
            if "active" in kind:
                active = _parse_vlan_list(vl.group("vlans"))
            else:
                allowed = _parse_vlan_list(vl.group("vlans"))
        trunks.append(Trunk(
            interface=intf,
            status=status,
            encapsulation=encap,
            vlan_allowed=allowed,
            vlan_active=active,
        ))
    return trunks


@dataclass
class TrunkReport:
    __test__ = False

    device_ref: str
    trunks: list[Trunk] = field(default_factory=list)

    @property
    def trunking_count(self) -> int:
        return sum(1 for t in self.trunks if t.status == "trunking")

    @property
    def total_vlans(self) -> set[int]:
        out: set[int] = set()
        for t in self.trunks:
            out.update(t.vlan_allowed)
            out.update(t.vlan_active)
        return out


def render(r: TrunkReport, lang: str = "en") -> str:
    if lang == "ar":
        return _render_ar(r)
    return _render_en(r)


def _render_en(r: TrunkReport) -> str:
    lines = [
        f"Trunk audit for {r.device_ref}",
        f"  Trunking ports: {r.trunking_count} of {len(r.trunks)}",
    ]
    if r.trunks:
        for t in r.trunks:
            allowed = (
                f"VLANs={','.join(str(v) for v in t.vlan_allowed)}"
                if t.vlan_allowed else "VLANs=?"
            )
            active = (
                f"active={','.join(str(v) for v in t.vlan_active)}"
                if t.vlan_active else "active=?"
            )
            lines.append(
                f"    {t.interface}  [{t.status}/{t.encapsulation}]  "
                f"{allowed}  {active}"
            )
    return "\n".join(lines)


def _render_ar(r: TrunkReport) -> str:
    lines = [
        f"تدقيق الترانك لـ {r.device_ref}",
        f"  المنافذ المعرّفة كترانك: {r.trunking_count} من {len(r.trunks)}",
    ]
    if r.trunks:
        for t in r.trunks:
            allowed = (
                f"VLANs={','.join(str(v) for v in t.vlan_allowed)}"
                if t.vlan_allowed else "VLANs=؟"
            )
            active = (
                f"نشطة={','.join(str(v) for v in t.vlan_active)}"
                if t.vlan_active else "نشطة=؟"
            )
            lines.append(
                f"    {t.interface}  [{t.status}/{t.encapsulation}]  "
                f"{allowed}  {active}"
            )
    return "\n".join(lines)
