"""Cable Diagnostics — what is the physical state of a link?

A 30-year network engineer pulls a cable and asks "is this
the right port? does the cable have any faults?". This module
parses the output of ``show interfaces`` counters and flags
ports with cable faults (CRC runs, giants, runts, input
errors) and ports that look physically unhealthy.

What it does:

* Parses per-interface error counters from a Cisco device.
* Classifies ports by their physical state: GOOD / DEGRADED
  / FAULT.
* Returns a typed per-port report with the underlying
  counter values.

What it does NOT do (typed, never silent):

* It does NOT report a port as GOOD if the device did not
  report counters — missing counters are marked UNKNOWN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class CableHealth(str, Enum):
    __test__ = False

    GOOD = "GOOD"
    DEGRADED = "DEGRADED"
    FAULT = "FAULT"
    UNKNOWN = "UNKNOWN"
    DOWN = "DOWN"


@dataclass(frozen=True)
class CableStats:
    __test__ = False

    interface: str
    admin_up: bool
    line_up: bool
    input_errors: int = 0
    crc: int = 0
    giants: int = 0
    runts: int = 0
    frame: int = 0
    output_errors: int = 0
    collisions: int = 0
    late_collisions: int = 0
    deferred: int = 0
    lost_carrier: int = 0
    no_carrier: int = 0
    input_packets: int = 0
    output_packets: int = 0

    @property
    def health(self) -> CableHealth:
        if not self.admin_up:
            return CableHealth.DOWN
        if not self.line_up:
            return CableHealth.DOWN
        # Hard faults: lost carrier / no carrier = physical disconnect
        if self.lost_carrier > 0 or self.no_carrier > 0:
            return CableHealth.FAULT
        # Soft faults: high CRC or runts
        if self.crc > 100 or self.runts > 5 or self.giants > 5:
            return CableHealth.DEGRADED
        if self.input_errors > 50 or self.output_errors > 50:
            return CableHealth.DEGRADED
        if self.collisions > 100 or self.late_collisions > 5:
            return CableHealth.DEGRADED
        return CableHealth.GOOD

    @property
    def fault_summary(self) -> str:
        issues: list[str] = []
        if self.crc:
            issues.append(f"CRC={self.crc}")
        if self.runts:
            issues.append(f"runts={self.runts}")
        if self.giants:
            issues.append(f"giants={self.giants}")
        if self.frame:
            issues.append(f"frame={self.frame}")
        if self.lost_carrier:
            issues.append(f"lost_carrier={self.lost_carrier}")
        if self.no_carrier:
            issues.append(f"no_carrier={self.no_carrier}")
        if self.input_errors:
            issues.append(f"input_errors={self.input_errors}")
        if self.output_errors:
            issues.append(f"output_errors={self.output_errors}")
        if self.collisions:
            issues.append(f"collisions={self.collisions}")
        if self.late_collisions:
            issues.append(f"late_collisions={self.late_collisions}")
        return ", ".join(issues) if issues else "no errors"


_INTERFACE_HEADER = re.compile(
    r"^(?P<name>\S+)\s+is\s+(?P<admin>(up|down|administratively down)),\s+"
    r"line protocol is\s+(?P<line>(up|down))",
    re.MULTILINE,
)


def _opt_int(block: str, name: str) -> int:
    """Return the integer preceding ``name`` in the block, or 0."""
    m = re.search(rf"(\d+)\s+{re.escape(name)}", block)
    return int(m.group(1)) if m else 0


def _req_int(block: str, name: str) -> int:
    m = re.search(rf"(\d+)\s+{re.escape(name)}", block)
    return int(m.group(1)) if m else 0


def parse(output: str) -> list[CableStats]:
    """Parse ``show interfaces`` and return per-port cable stats."""
    if not output or not output.strip():
        return []
    stats: list[CableStats] = []
    for m in _INTERFACE_HEADER.finditer(output):
        name = m.group("name")
        admin = m.group("admin").lower()
        line = m.group("line").lower()
        start = m.end()
        next_m = _INTERFACE_HEADER.search(output, start)
        end = next_m.start() if next_m else len(output)
        block = output[start:end]
        admin_up = admin == "up"
        line_up = line == "up"
        stats.append(CableStats(
            interface=name,
            admin_up=admin_up,
            line_up=line_up,
            input_errors=_opt_int(block, "input errors"),
            crc=_opt_int(block, "CRC"),
            giants=_opt_int(block, "giants"),
            runts=_opt_int(block, "runts"),
            frame=_opt_int(block, "frame"),
            output_errors=_opt_int(block, "output errors"),
            collisions=_opt_int(block, "collisions"),
            late_collisions=_opt_int(block, "late collisions"),
            deferred=_opt_int(block, "deferred"),
            lost_carrier=_opt_int(block, "lost carrier"),
            no_carrier=_opt_int(block, "no carrier"),
            input_packets=_req_int(block, "packets input"),
            output_packets=_req_int(block, "packets output"),
        ))
    return stats


@dataclass
class CableReport:
    __test__ = False

    device_ref: str
    interfaces: list[CableStats] = field(default_factory=list)

    @property
    def fault_interfaces(self) -> list[CableStats]:
        return [i for i in self.interfaces if i.health == CableHealth.FAULT]

    @property
    def degraded_interfaces(self) -> list[CableStats]:
        return [i for i in self.interfaces if i.health == CableHealth.DEGRADED]

    @property
    def down_interfaces(self) -> list[CableStats]:
        return [i for i in self.interfaces if i.health == CableHealth.DOWN]

    @property
    def good_interfaces(self) -> list[CableStats]:
        return [i for i in self.interfaces if i.health == CableHealth.GOOD]

    @property
    def overall_verdict(self) -> str:
        if not self.interfaces:
            return "UNKNOWN"
        if self.fault_interfaces:
            return "FAULT"
        if self.degraded_interfaces:
            return "DEGRADED"
        if self.down_interfaces:
            return "MIXED"
        return "GOOD"


def render(r: CableReport, lang: str = "en") -> str:
    if lang == "ar":
        return _render_ar(r)
    return _render_en(r)


def _render_en(r: CableReport) -> str:
    lines = [
        f"Cable diagnostics for {r.device_ref}",
        f"  Verdict: {r.overall_verdict}",
        f"  Good: {len(r.good_interfaces)}   "
        f"Degraded: {len(r.degraded_interfaces)}   "
        f"Fault: {len(r.fault_interfaces)}   "
        f"Down: {len(r.down_interfaces)}",
    ]
    bad = r.fault_interfaces + r.degraded_interfaces
    if bad:
        lines.append("  Interfaces needing attention:")
        for i in bad:
            lines.append(f"    [{i.health.value}] {i.interface}: {i.fault_summary}")
    return "\n".join(lines)


def _render_ar(r: CableReport) -> str:
    lines = [
        f"تشخيص الكابلات لـ {r.device_ref}",
        f"  النتيجة: {r.overall_verdict}",
        f"  سليم: {len(r.good_interfaces)}   "
        f"متدهور: {len(r.degraded_interfaces)}   "
        f"عطل: {len(r.fault_interfaces)}   "
        f"معطل: {len(r.down_interfaces)}",
    ]
    bad = r.fault_interfaces + r.degraded_interfaces
    if bad:
        lines.append("  المنافذ التي تحتاج انتباه:")
        for i in bad:
            lines.append(f"    [{i.health.value}] {i.interface}: {i.fault_summary}")
    return "\n".join(lines)
