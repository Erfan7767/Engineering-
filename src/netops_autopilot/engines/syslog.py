"""Syslog Parser — events from the device logs.

A 30-year engineer reads syslog every morning to spot
patterns: a flapping interface, repeated auth failures, an
NTP drift warning. This module is the typed implementation:
parse Cisco / Linux / Windows-style syslog, surface
:class:`SyslogEvent` records, and produce a
:class:`SyslogReport` with severity buckets and top
sources.

Design contract:

* **Typed** — :class:`SyslogEvent` carries the parsed
  severity, facility, hostname, and message.
* **Deterministic** — same log lines → same buckets.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum


class SyslogSeverity(str, Enum):
    __test__ = False

    EMERGENCY = "emergency"
    ALERT = "alert"
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    INFORMATIONAL = "informational"
    DEBUG = "debug"
    UNKNOWN = "unknown"


# PRI mapping: 0..23 -> severity
_PRI_TO_SEVERITY: dict[int, SyslogSeverity] = {
    0: SyslogSeverity.EMERGENCY,
    1: SyslogSeverity.ALERT,
    2: SyslogSeverity.CRITICAL,
    3: SyslogSeverity.ERROR,
    4: SyslogSeverity.WARNING,
    5: SyslogSeverity.NOTICE,
    6: SyslogSeverity.INFORMATIONAL,
    7: SyslogSeverity.DEBUG,
}


@dataclass(frozen=True)
class SyslogEvent:
    __test__ = False

    timestamp_unix: float
    hostname: str
    tag: str
    severity: SyslogSeverity
    facility: int
    message: str

    def render(self, lang: str = "en") -> str:
        sev = self.severity.value
        if lang == "ar":
            return (
                f"[{sev}] {self.hostname} {self.tag}: "
                f"{self.message}"
            )
        return (
            f"[{sev}] {self.hostname} {self.tag}: "
            f"{self.message}"
        )


@dataclass
class SyslogReport:
    __test__ = False

    events: list[SyslogEvent] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    top_tags: list[tuple[str, int]] = field(default_factory=list)
    errors: list[SyslogEvent] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return self.severity_counts.get(
            SyslogSeverity.ERROR.value, 0
        ) + self.severity_counts.get(
            SyslogSeverity.CRITICAL.value, 0
        )

    @property
    def overall_verdict(self) -> str:
        if self.severity_counts.get(
            SyslogSeverity.EMERGENCY.value, 0
        ) > 0:
            return "EMERGENCY"
        if self.error_count > 0:
            return "ERRORS_PRESENT"
        if self.severity_counts.get(
            SyslogSeverity.WARNING.value, 0
        ) > 0:
            return "WARNINGS_PRESENT"
        return "CLEAN"

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            head = (
                f"تحليل السجل: {self.overall_verdict}\n"
                f"  أحداث: {len(self.events)}\n"
                f"  أخطاء: {self.error_count}"
            )
        else:
            head = (
                f"Syslog scan: {self.overall_verdict}\n"
                f"  Events: {len(self.events)}\n"
                f"  Errors: {self.error_count}"
            )
        return head


# RFC 5424 syslog: <PRI>1 TIMESTAMP HOSTNAME APPNAME PROCID MSGID ...
_RFC5424 = re.compile(
    r"<(?P<pri>\d+)>(?P<ver>\d+)\s+(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<rest>.*)"
)

# BSD-style: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
_BSD = re.compile(
    r"<(?P<pri>\d+)>(?P<mon>\S+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)"
)

# Cisco-style: TIMESTAMP: %FACILITY-SEVERITY-MNEMONIC: MESSAGE
_CISCO = re.compile(
    r"^(\S+):\s+%(?P<fac>\w+)-(?P<sev>\d)-(?P<mnem>\w+):\s+(?P<msg>.*)$"
)


def _pri_to_severity(pri: int) -> tuple[SyslogSeverity, int]:
    sev = pri % 8
    facility = pri // 8
    return (
        _PRI_TO_SEVERITY.get(sev, SyslogSeverity.UNKNOWN),
        facility,
    )


def parse_line(
    line: str,
    *,
    timestamp_unix: float = 0.0,
) -> SyslogEvent | None:
    """Parse a single syslog line into a :class:`SyslogEvent`.

    Supports RFC 5424, BSD-style, and Cisco IOS style.
    """
    if not line or not line.strip():
        return None
    # RFC 5424
    m = _RFC5424.match(line)
    if m:
        try:
            pri = int(m.group("pri"))
        except ValueError:
            pri = 0
        sev, facility = _pri_to_severity(pri)
        return SyslogEvent(
            timestamp_unix=timestamp_unix,
            hostname=m.group("host"),
            tag=m.group("app"),
            severity=sev,
            facility=facility,
            message=m.group("rest"),
        )
    # Cisco IOS style
    m = _CISCO.match(line)
    if m:
        sev_map = {
            "0": SyslogSeverity.EMERGENCY,
            "1": SyslogSeverity.ALERT,
            "2": SyslogSeverity.CRITICAL,
            "3": SyslogSeverity.ERROR,
            "4": SyslogSeverity.WARNING,
            "5": SyslogSeverity.NOTICE,
            "6": SyslogSeverity.INFORMATIONAL,
            "7": SyslogSeverity.DEBUG,
        }
        sev = sev_map.get(m.group("sev"), SyslogSeverity.UNKNOWN)
        return SyslogEvent(
            timestamp_unix=timestamp_unix,
            hostname="",
            tag=f"{m.group('fac')}-{m.group('mnem')}",
            severity=sev,
            facility=0,
            message=m.group("msg"),
        )
    # BSD
    m = _BSD.match(line)
    if m:
        try:
            pri = int(m.group("pri"))
        except ValueError:
            pri = 0
        sev, facility = _pri_to_severity(pri)
        rest = m.group("rest")
        # BSD format: TAG[PID]: MESSAGE
        tag = ""
        if ":" in rest:
            tag, _, msg = rest.partition(":")
            msg = msg.strip()
        else:
            msg = rest
        return SyslogEvent(
            timestamp_unix=timestamp_unix,
            hostname=m.group("host"),
            tag=tag,
            severity=sev,
            facility=facility,
            message=msg,
        )
    return None


def parse_log(
    log: str,
    *,
    timestamp_unix: float = 0.0,
) -> SyslogReport:
    """Parse a multi-line syslog into a :class:`SyslogReport`."""
    rep = SyslogReport()
    if not log:
        return rep
    sev_counts: Counter[str] = Counter()
    tag_counts: Counter[str] = Counter()
    for line in log.splitlines():
        ev = parse_line(line, timestamp_unix=timestamp_unix)
        if ev is None:
            continue
        rep.events.append(ev)
        sev_counts[ev.severity.value] += 1
        tag_counts[ev.tag] += 1
        if ev.severity in (
            SyslogSeverity.ERROR,
            SyslogSeverity.CRITICAL,
        ):
            rep.errors.append(ev)
    rep.severity_counts = dict(sev_counts)
    rep.top_tags = tag_counts.most_common(10)
    return rep
