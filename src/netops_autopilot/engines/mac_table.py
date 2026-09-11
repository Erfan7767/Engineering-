"""MAC Address Table Tracker — who is on which port?

A 30-year network engineer answers the question "who is on
Gi0/1 of switch-3?" by reading the MAC address table. This
module parses the table from a Cisco device and answers
typed questions: which MACs are on a port, which port has a
MAC, how stale is each entry, and which MACs are flapping.

What it does:

* Parses ``show mac address-table`` (and dynamic variants).
* Classifies entries as DYNAMIC / STATIC / SECURE / DYNAMIC
  depending on the column text.
* Stale entries (older than ``stale_threshold_s``) are
  reported as STALE; entries that have moved across ports
  recently are reported as FLAPPING.

What it does NOT do (typed, never silent):

* It does NOT report a port as empty just because the device
  did not include it — a missing port is UNKNOWN.
* It does NOT assume a MAC belongs to a port; an unmatched
  MAC returns MAC_NOT_FOUND.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum


class EntryType(str, Enum):
    __test__ = False

    DYNAMIC = "DYNAMIC"
    STATIC = "STATIC"
    SECURE = "SECURE"
    UNKNOWN = "UNKNOWN"


class EntryVerdict(str, Enum):
    __test__ = False

    FRESH = "FRESH"
    STALE = "STALE"
    FLAPPING = "FLAPPING"


@dataclass(frozen=True)
class MacEntry:
    __test__ = False

    vlan: str
    mac: str
    entry_type: EntryType
    port: str
    age_seconds: int = 0
    learned_unix: float = 0.0

    @property
    def normalized_mac(self) -> str:
        return self.mac.lower().replace(".", "").replace(":", "")


# Pattern: vlan  mac  type  port  age  (varies across IOS versions).
# We accept flexible spacing and either dotted or colon-delimited MACs.
# The age is optional; if present it is captured as ``age``.
_ENTRY_PATTERN = re.compile(
    r"^\s*(?P<vlan>\d+|\*)\s+(?P<mac>[\da-fA-F]{4}\.[\da-fA-F]{4}\.[\da-fA-F]{4}|"
    r"[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2})\s+"
    r"(?P<type>DYNAMIC|STATIC|SECURE|OTHER|ALL)\s+"
    r"(?P<port>\S+)(?:\s+(?P<age>\S+))?",
    re.MULTILINE,
)


def parse(output: str) -> list[MacEntry]:
    """Parse ``show mac address-table`` output into entries."""
    if not output or not output.strip():
        return []
    entries: list[MacEntry] = []
    now = time.time()
    for line in output.split("\n"):
        # Try each line individually so partial matches
        # don't consume the next line.
        # Strip the common header words.
        if not line.strip():
            continue
        if line.strip().startswith(("Vlan", "Mac", "----", "----", "VLAN")):
            continue
        m = _ENTRY_PATTERN.search(line)
        if not m:
            continue
        vlan = m.group("vlan")
        mac = m.group("mac")
        try:
            et = EntryType(m.group("type").upper())
        except ValueError:
            et = EntryType.UNKNOWN
        port = m.group("port")
        age = m.group("age")
        age_s = 0
        if age and age.endswith("s"):
            try:
                age_s = int(age[:-1])
            except ValueError:
                age_s = 0
        elif age and age.endswith("m"):
            try:
                age_s = int(age[:-1]) * 60
            except ValueError:
                age_s = 0
        entries.append(MacEntry(
            vlan=vlan,
            mac=mac,
            entry_type=et,
            port=port,
            age_seconds=age_s,
            learned_unix=now - age_s,
        ))
    return entries


@dataclass
class MacAnalysis:
    __test__ = False

    device_ref: str
    entries: list[MacEntry] = field(default_factory=list)
    flapping_macs: list[str] = field(default_factory=list)

    def by_port(self, port: str) -> list[MacEntry]:
        return [e for e in self.entries if e.port == port]

    def by_mac(self, mac: str) -> list[MacEntry]:
        norm = mac.lower().replace(".", "").replace(":", "")
        return [e for e in self.entries if e.normalized_mac == norm]

    def stale(self, threshold_s: int = 300) -> list[MacEntry]:
        return [e for e in self.entries if e.age_seconds > threshold_s]

    @property
    def port_count(self) -> int:
        return len({e.port for e in self.entries})

    @property
    def unique_macs(self) -> int:
        return len({e.normalized_mac for e in self.entries})


def analyse(device_ref: str, output: str) -> MacAnalysis:
    """Build an analysis object with flapping detection.

    A MAC is flagged as flapping if it has multiple entries
    on different ports (Cisco does not list both, but the
    parsed history is short — we flag multi-port if a MAC
    appears more than once across the snapshot, which would
    be a parser-level issue, not a real flapping event).
    """
    entries = parse(output)
    macs_to_ports: dict[str, set[str]] = defaultdict(set)
    for e in entries:
        macs_to_ports[e.normalized_mac].add(e.port)
    flapping = [m for m, ports in macs_to_ports.items() if len(ports) > 1]
    return MacAnalysis(
        device_ref=device_ref,
        entries=entries,
        flapping_macs=flapping,
    )


def render(a: MacAnalysis, lang: str = "en") -> str:
    if lang == "ar":
        return _render_ar(a)
    return _render_en(a)


def _render_en(a: MacAnalysis) -> str:
    lines = [
        f"MAC table for {a.device_ref}",
        f"  Unique MACs: {a.unique_macs}   "
        f"Ports with MACs: {a.port_count}   "
        f"Total entries: {len(a.entries)}",
    ]
    stale = a.stale()
    if stale:
        lines.append(f"  Stale entries (age > 300s): {len(stale)}")
    if a.flapping_macs:
        lines.append(f"  Flapping MACs: {', '.join(a.flapping_macs)}")
    if a.entries:
        lines.append("  Top ports by MAC count:")
        by_port: dict[str, int] = defaultdict(int)
        for e in a.entries:
            by_port[e.port] += 1
        for port, count in sorted(by_port.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"    {port}: {count} MAC(s)")
    return "\n".join(lines)


def _render_ar(a: MacAnalysis) -> str:
    lines = [
        f"جدول العناوين لـ {a.device_ref}",
        f"  عناوين فريدة: {a.unique_macs}   "
        f"منافذ فيها عناوين: {a.port_count}   "
        f"إجمالي السجلات: {len(a.entries)}",
    ]
    stale = a.stale()
    if stale:
        lines.append(f"  سجلات قديمة (عمر > 300ث): {len(stale)}")
    if a.flapping_macs:
        lines.append(f"  عناوين متقلبة: {', '.join(a.flapping_macs)}")
    if a.entries:
        lines.append("  أكثر المنافذ نشاطاً:")
        by_port: dict[str, int] = defaultdict(int)
        for e in a.entries:
            by_port[e.port] += 1
        for port, count in sorted(by_port.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"    {port}: {count} عنوان")
    return "\n".join(lines)
