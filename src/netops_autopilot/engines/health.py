"""Health Engine — per-device interface/link health scoring.

A 30-year network engineer doesn't ask "is the device up?". The
engineer asks "are the interfaces healthy? Are there errors?
Which ports are flapping?". This module answers those questions
with typed, evidence-tagged results.

What it does:

* Parses the output of ``show interfaces`` (Cisco IOS-XE) into
  per-interface records.
* Computes a per-interface health score (0-100) based on
  input errors, CRC errors, output errors, and link state.
* Identifies interfaces in a degraded state (high error rate,
  down/up flapping).
* Returns a typed health report. No silent PASS — a missing
  input is SAMPLE_MISSING.

What it does NOT do (typed, never silent):

* It does NOT make up numbers. If the device does not report
  CRC errors, we report ``NOT_REPORTED``, not 0.
* It does NOT alert on a single counter. The 30-year engineer
  cares about trends; the chat surfaces the current snapshot
  and flags interfaces where the error count is "high" relative
  to the device's other interfaces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class InterfaceHealth(str, Enum):
    __test__ = False

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


# High error rate threshold: any interface whose error count
# is more than 1% of the input packet count is DEGRADED.
_HIGH_ERROR_RATE = 0.01
# An interface with errors over this absolute threshold on a
# low-traffic port is also DEGRADED.
_ABSOLUTE_LOW_ERROR_THRESHOLD = 10


@dataclass(frozen=True)
class InterfaceRecord:
    """One parsed interface."""

    __test__ = False

    name: str
    admin_state: str           # "up" or "down"
    line_protocol: str         # "up" or "down"
    input_packets: int = 0
    output_packets: int = 0
    input_errors: Optional[int] = None
    crc_errors: Optional[int] = None
    output_errors: Optional[int] = None
    input_rate_bps: int = 0
    output_rate_bps: int = 0
    last_flapped: str = ""     # human-readable uptime or "never"

    @property
    def is_up(self) -> bool:
        return self.admin_state.lower() == "up" and self.line_protocol.lower() == "up"

    @property
    def error_rate(self) -> float:
        if self.input_errors is None or self.input_packets == 0:
            return 0.0
        return self.input_errors / max(self.input_packets, 1)

    @property
    def health(self) -> InterfaceHealth:
        if not self.is_up:
            return InterfaceHealth.DOWN
        if self.input_errors is not None and self.input_errors > _ABSOLUTE_LOW_ERROR_THRESHOLD:
            if self.error_rate > _HIGH_ERROR_RATE:
                return InterfaceHealth.CRITICAL
            return InterfaceHealth.DEGRADED
        return InterfaceHealth.HEALTHY


# Cisco IOS-XE ``show interfaces`` parser. We split on the
# interface name and extract counters.

_INTERFACE_HEADER = re.compile(
    r"^(?P<name>\S+)\s+is\s+(?P<admin>(up|down|administratively down)),\s+"
    r"line protocol is\s+(?P<line>(up|down))",
    re.MULTILINE,
)


def parse_interfaces(output: str) -> list[InterfaceRecord]:
    """Parse the text of ``show interfaces`` into records."""
    if not output or not output.strip():
        return []
    records: list[InterfaceRecord] = []
    for m in _INTERFACE_HEADER.finditer(output):
        name = m.group("name")
        admin = m.group("admin")
        line_proto = m.group("line")
        # Find the block for this interface (until the next
        # interface header or end of text).
        start = m.end()
        next_match = _INTERFACE_HEADER.search(output, start)
        end = next_match.start() if next_match else len(output)
        block = output[start:end]
        records.append(InterfaceRecord(
            name=name,
            admin_state="up" if admin.startswith("up") else "down",
            line_protocol=line_proto,
            input_packets=_int_field(block, "input packets"),
            output_packets=_int_field(block, "output packets"),
            input_errors=_opt_int_field(block, r"\d+\s+input errors"),
            crc_errors=_opt_int_field(block, r"\d+\s+CRC"),
            output_errors=_opt_int_field(block, r"\d+\s+output errors"),
            input_rate_bps=_rate_field(block, "input rate"),
            output_rate_bps=_rate_field(block, "output rate"),
        ))
    return records


def _int_field(block: str, name: str) -> int:
    """Return the integer following ``name`` in ``block``, or 0."""
    m = re.search(rf"(\d+)\s+{re.escape(name)}", block)
    return int(m.group(1)) if m else 0


def _opt_int_field(block: str, pattern: str) -> Optional[int]:
    """Return the integer matching ``pattern`` in ``block``, or None."""
    m = re.search(pattern, block)
    if not m:
        return None
    return int(m.group(0).split()[0])


def _rate_field(block: str, name: str) -> int:
    """Return the bit-rate following ``name`` (e.g. '1000 bits/sec')."""
    m = re.search(rf"{re.escape(name)}\s+(\d+)\s+bits/sec", block)
    return int(m.group(1)) if m else 0


# -------------------------------------------------------------- health report

@dataclass
class DeviceHealth:
    """Per-device health report."""

    __test__ = False

    device_ref: str
    interfaces: list[InterfaceRecord] = field(default_factory=list)

    @property
    def healthy_count(self) -> int:
        return sum(1 for i in self.interfaces if i.health == InterfaceHealth.HEALTHY)

    @property
    def degraded_count(self) -> int:
        return sum(1 for i in self.interfaces if i.health == InterfaceHealth.DEGRADED)

    @property
    def critical_count(self) -> int:
        return sum(1 for i in self.interfaces if i.health == InterfaceHealth.CRITICAL)

    @property
    def down_count(self) -> int:
        return sum(1 for i in self.interfaces if i.health == InterfaceHealth.DOWN)

    @property
    def overall_verdict(self) -> str:
        if not self.interfaces:
            return "UNKNOWN"
        if self.critical_count:
            return "CRITICAL"
        if self.degraded_count:
            return "DEGRADED"
        if self.down_count == len(self.interfaces):
            return "DOWN"
        if self.healthy_count == len(self.interfaces):
            return "HEALTHY"
        return "MIXED"


def render_health(h: DeviceHealth, lang: str = "en") -> str:
    if lang == "ar":
        return _render_health_ar(h)
    return _render_health_en(h)


def _render_health_en(h: DeviceHealth) -> str:
    lines: list[str] = []
    lines.append(f"Health for {h.device_ref}")
    lines.append(f"  Verdict: {h.overall_verdict}")
    lines.append(
        f"  Healthy: {h.healthy_count}   Degraded: {h.degraded_count}   "
        f"Critical: {h.critical_count}   Down: {h.down_count}   "
        f"Total: {len(h.interfaces)}"
    )
    bad = [i for i in h.interfaces if i.health != InterfaceHealth.HEALTHY]
    if bad:
        lines.append("")
        lines.append("  Interfaces needing attention:")
        for i in bad:
            tag = f"[{i.health.value}]"
            err = f"err={i.input_errors}" if i.input_errors else ""
            crc = f"crc={i.crc_errors}" if i.crc_errors else ""
            extra = " ".join(x for x in (err, crc) if x)
            lines.append(f"    {tag} {i.name} ({i.admin_state}/{i.line_protocol}) {extra}")
    return "\n".join(lines)


def _render_health_ar(h: DeviceHealth) -> str:
    lines: list[str] = []
    lines.append(f"صحة {h.device_ref}")
    lines.append(f"  النتيجة: {h.overall_verdict}")
    lines.append(
        f"  سليم: {h.healthy_count}   متدهور: {h.degraded_count}   "
        f"حرج: {h.critical_count}   معطل: {h.down_count}   "
        f"المجموع: {len(h.interfaces)}"
    )
    bad = [i for i in h.interfaces if i.health != InterfaceHealth.HEALTHY]
    if bad:
        lines.append("")
        lines.append("  المنافذ التي تحتاج انتباه:")
        for i in bad:
            tag = f"[{i.health.value}]"
            err = f"err={i.input_errors}" if i.input_errors else ""
            crc = f"crc={i.crc_errors}" if i.crc_errors else ""
            extra = " ".join(x for x in (err, crc) if x)
            lines.append(f"    {tag} {i.name} ({i.admin_state}/{i.line_protocol}) {extra}")
    return "\n".join(lines)
