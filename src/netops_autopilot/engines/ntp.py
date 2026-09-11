"""NTP / Network Time Audit.

A 30-year engineer knows: an unsynchronized network is a
broken network. Logs without timestamps are useless. This
module is the typed implementation: parse ``show ntp``
output, surface typed :class:`NtpPeer` records and a
typed :class:`NtpReport` with skew / drift findings.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class NtpPeer:
    __test__ = False

    remote: str
    refid: str = ""
    stratum: int = 16
    when_seconds: int = 0
    poll_seconds: int = 0
    reach: int = 0
    delay_ms: float = 0.0
    offset_ms: float = 0.0
    jitter_ms: float = 0.0

    @property
    def is_reachable(self) -> bool:
        return self.reach > 0

    @property
    def is_synchronized(self) -> bool:
        return self.stratum < 16 and self.is_reachable

    @property
    def is_high_skew(self) -> bool:
        return abs(self.offset_ms) > 100.0


@dataclass
class NtpReport:
    __test__ = False

    device: str
    peers: list[NtpPeer] = field(default_factory=list)

    @property
    def peer_count(self) -> int:
        return len(self.peers)

    @property
    def reachable_count(self) -> int:
        return sum(1 for p in self.peers if p.is_reachable)

    @property
    def synced_count(self) -> int:
        return sum(1 for p in self.peers if p.is_synchronized)

    @property
    def high_skew(self) -> list[NtpPeer]:
        return [p for p in self.peers if p.is_high_skew]

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"NTP: {self.peer_count} نظير، "
                f"{self.synced_count} متزامن، "
                f"{len(self.high_skew)} انحراف عالي"
            )
        return (
            f"NTP: {self.peer_count} peer(s), "
            f"{self.synced_count} synchronized, "
            f"{len(self.high_skew)} high-skew"
        )


_NTP_LINE = re.compile(
    r"^(?P<remote>\S+)\s+(?P<refid>\S+)\s+"
    r"(?P<stratum>\d+)\s+(?P<when>\S+)\s+(?P<poll>\S+)\s+"
    r"(?P<reach>\d+)\s+(?P<delay>\S+)\s+(?P<offset>\S+)\s+"
    r"(?P<jitter>\S+)\s*$",
    re.MULTILINE,
)


def _parse_ms(s: str) -> float:
    """Parse ``12.345`` or ``12ms`` into ms."""
    try:
        return float(s.rstrip("ms"))
    except ValueError:
        return 0.0


def _parse_seconds(s: str) -> int:
    """Parse ``36`` or ``36s`` into seconds."""
    s = s.rstrip("s")
    try:
        return int(s)
    except ValueError:
        return 0


def parse_cisco_ntp(
    device: str,
    output: str,
) -> NtpReport:
    """Parse ``show ntp associations``."""
    rep = NtpReport(device=device)
    if not output or not output.strip():
        return rep
    for m in _NTP_LINE.finditer(output):
        try:
            stratum = int(m.group("stratum"))
        except ValueError:
            stratum = 16
        try:
            reach = int(m.group("reach"), 16)
        except ValueError:
            reach = 0
        rep.peers.append(NtpPeer(
            remote=m.group("remote"),
            refid=m.group("refid"),
            stratum=stratum,
            when_seconds=_parse_seconds(m.group("when")),
            poll_seconds=_parse_seconds(m.group("poll")),
            reach=reach,
            delay_ms=_parse_ms(m.group("delay")),
            offset_ms=_parse_ms(m.group("offset")),
            jitter_ms=_parse_ms(m.group("jitter")),
        ))
    return rep
