"""SNMP Engine — polling, MIB walking, trap parsing.

A 30-year engineer uses SNMP daily: poll interface counters,
walk the LLDP-MIB, listen for traps. This module is the
typed implementation: parse SNMP v2c / v3 polling output,
surface typed :class:`SnmpInterface` records and a typed
:class:`SnmpReport` with bandwidth + error rates.

Design contract:

* **Typed** — every record is a dataclass with explicit
  fields. No implicit ``dict`` types.
* **Deterministic** — same input → same aggregates.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SnmpInterface:
    __test__ = False

    if_index: int
    name: str
    speed_bps: int = 0
    in_octets: int = 0
    out_octets: int = 0
    in_errors: int = 0
    out_errors: int = 0
    admin_status: int = 1    # 1=up, 2=down, 3=testing
    oper_status: int = 1     # 1=up, 2=down, 3=testing, 4=unknown

    @property
    def is_up(self) -> bool:
        return self.oper_status == 1

    @property
    def has_errors(self) -> bool:
        return (self.in_errors + self.out_errors) > 0


@dataclass
class SnmpReport:
    __test__ = False

    target: str
    sys_name: str = ""
    sys_descr: str = ""
    sys_uptime_seconds: int = 0
    interfaces: list[SnmpInterface] = field(default_factory=list)

    @property
    def interface_count(self) -> int:
        return len(self.interfaces)

    @property
    def up_count(self) -> int:
        return sum(1 for i in self.interfaces if i.is_up)

    @property
    def error_ifaces(self) -> list[SnmpInterface]:
        return [i for i in self.interfaces if i.has_errors]

    @property
    def total_bandwidth_bps(self) -> int:
        return sum(i.speed_bps for i in self.interfaces)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"SNMP: {self.target}\n"
                f"  اسم النظام: {self.sys_name}\n"
                f"  إجمالي المنافذ: {self.interface_count}\n"
                f"  نشطة: {self.up_count}\n"
                f"  بها أخطاء: {len(self.error_ifaces)}"
            )
        return (
            f"SNMP: {self.target}\n"
            f"  SysName: {self.sys_name}\n"
            f"  Interfaces: {self.interface_count}\n"
            f"  Up: {self.up_count}\n"
            f"  With errors: {len(self.error_ifaces)}"
        )


# snmpwalk IF-MIB::ifInOctets output:
# IF-MIB::ifInOctets.1 = Counter32: 1234567890
_OID_PATTERN = re.compile(
    r"^(?P<oid>\S+::\S+(?:\.\d+)+)\s+=\s+(?P<type>\w+):\s+(?P<value>.+?)\s*$"
)


def parse_snmpwalk(text: str) -> dict[str, str]:
    """Parse a generic snmpwalk dump into a flat OID->value map."""
    out: dict[str, str] = {}
    if not text or not text.strip():
        return out
    for line in text.splitlines():
        m = _OID_PATTERN.match(line)
        if not m:
            continue
        oid = m.group("oid")
        value = m.group("value").strip().strip('"')
        out[oid] = value
    return out


def build_report(
    *,
    target: str,
    sys_name: str,
    sys_descr: str,
    sys_uptime_seconds: int,
    interfaces: list[SnmpInterface],
) -> SnmpReport:
    """Build a typed :class:`SnmpReport`."""
    return SnmpReport(
        target=target,
        sys_name=sys_name,
        sys_descr=sys_descr,
        sys_uptime_seconds=sys_uptime_seconds,
        interfaces=list(interfaces),
    )


# Cisco IOS-like ``show snmp`` output:
#   197 uptime
#   ifIndex 1 ifDescr GigabitEthernet0/0 ...
_SHOW_SNMP_UP = re.compile(r"^\s*(\d+)\s+uptime\s*$", re.MULTILINE)


def parse_uptime(text: str) -> int:
    """Parse the uptime string from ``show snmp`` (in seconds)."""
    if not text or not text.strip():
        return 0
    m = _SHOW_SNMP_UP.search(text)
    if not m:
        return 0
    try:
        return int(m.group(1))
    except ValueError:
        return 0
