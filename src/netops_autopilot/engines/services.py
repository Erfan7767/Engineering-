"""DNS/DHCP Service Engine — full resolver + lease analyzer."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class DhcpLease:
    __test__ = False

    ip: str
    mac: str
    hostname: str
    starts: datetime
    ends: datetime
    binding_state: str = "active"

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.ends

    @property
    def is_reservation(self) -> bool:
        return "reservation" in self.binding_state.lower()


@dataclass(frozen=True)
class DhcpScope:
    __test__ = False

    name: str
    subnet: str
    range_start: str
    range_end: str
    default_gateway: str = ""
    dns_servers: tuple[str, ...] = ()


@dataclass
class DhcpReport:
    __test__ = False

    scopes: list[DhcpScope] = field(default_factory=list)
    leases: list[DhcpLease] = field(default_factory=list)

    @property
    def total_leases(self) -> int:
        return len(self.leases)

    @property
    def active_leases(self) -> int:
        return sum(
            1 for l in self.leases if not l.is_expired
        )

    @property
    def expired_leases(self) -> int:
        return sum(
            1 for l in self.leases if l.is_expired
        )

    @property
    def utilization_pct(self) -> float:
        if not self.scopes:
            return 0.0
        sc = self.scopes[0]
        try:
            start_last = int(sc.range_start.split(".")[-1])
            end_last = int(sc.range_end.split(".")[-1])
            size = max(1, end_last - start_last + 1)
        except (ValueError, IndexError):
            return 0.0
        return min(100.0, (self.active_leases / size) * 100.0)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"DHCP: {self.total_leases} إيجار\n"
                f"  نشط: {self.active_leases}\n"
                f"  منتهي: {self.expired_leases}\n"
                f"  الاستخدام: {self.utilization_pct:.1f}%"
            )
        return (
            f"DHCP: {self.total_leases} lease(s)\n"
            f"  Active: {self.active_leases}\n"
            f"  Expired: {self.expired_leases}\n"
            f"  Utilization: {self.utilization_pct:.1f}%"
        )


_SCOPE_PATTERN = re.compile(
    r"Subnet:\s+(?P<subnet>\S+)\s+"
    r"Start Address:\s+(?P<start>\S+)\s+"
    r"End Address:\s+(?P<end>\S+)"
)

_LEASE_BLOCK = re.compile(
    r"lease\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s*\{(?P<body>[^}]*)\}",
    re.DOTALL,
)


def _parse_dt(date_str: str, time_str: str) -> datetime:
    for fmt in (
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(
                f"{date_str} {time_str}", fmt,
            )
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.fromtimestamp(0, tz=timezone.utc)


def parse_isc_leases(text: str) -> list[DhcpLease]:
    """Parse ISC DHCP ``dhcpd.leases``."""
    leases: list[DhcpLease] = []
    if not text or not text.strip():
        return leases
    for m in _LEASE_BLOCK.finditer(text):
        ip = m.group("ip")
        body = m.group("body")
        # Extract fields from the body using simple regex
        # matchers that look for the keyword + value.
        mac_match = re.search(
            r"hardware\s+ethernet\s+([0-9a-fA-F:]+)", body,
        )
        mac = mac_match.group(1).lower() if mac_match else ""
        host_match = re.search(
            r"client-hostname\s+\"([^\"]+)\"", body,
        )
        if not host_match:
            host_match = re.search(
                r"client-hostname\s+(\S+)", body,
            )
        hostname = host_match.group(1) if host_match else ""
        start_match = re.search(
            r"starts\s+\d+\s+(\d+/\d+/\d+)\s+(\d+:\d+:\d+)",
            body,
        )
        end_match = re.search(
            r"ends\s+\d+\s+(\d+/\d+/\d+)\s+(\d+:\d+:\d+)",
            body,
        )
        starts = (
            _parse_dt(
                start_match.group(1),
                start_match.group(2),
            ) if start_match else datetime.fromtimestamp(
                0, tz=timezone.utc,
            )
        )
        ends = (
            _parse_dt(
                end_match.group(1),
                end_match.group(2),
            ) if end_match else datetime.fromtimestamp(
                0, tz=timezone.utc,
            )
        )
        state_match = re.search(
            r"binding\s+state\s+(\w+)", body,
        )
        state = state_match.group(1).lower() if state_match else "active"
        leases.append(DhcpLease(
            ip=ip,
            mac=mac,
            hostname=hostname,
            starts=starts,
            ends=ends,
            binding_state=state,
        ))
    return leases


def parse_windows_scopes(text: str) -> list[DhcpScope]:
    """Parse Windows DHCP scope dump."""
    scopes: list[DhcpScope] = []
    if not text or not text.strip():
        return scopes
    for m in _SCOPE_PATTERN.finditer(text):
        scopes.append(DhcpScope(
            name=m.group("subnet"),
            subnet=m.group("subnet"),
            range_start=m.group("start"),
            range_end=m.group("end"),
        ))
    return scopes


def build_report(
    scopes: list[DhcpScope] | None = None,
    leases: list[DhcpLease] | None = None,
) -> DhcpReport:
    """Build a :class:`DhcpReport` from typed inputs."""
    return DhcpReport(
        scopes=list(scopes or []),
        leases=list(leases or []),
    )
