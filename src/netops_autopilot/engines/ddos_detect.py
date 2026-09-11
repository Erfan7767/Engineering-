"""NetFlow-based DDoS Detection.

A 30-year engineer watches for volumetric DDoS: a single
source blasting UDP/ICMP, a SYN flood, an amplification
(NTP/DNS). This module is the typed implementation: take
a list of NetFlow records, surface typed
:class:`DdosSignal` records and a typed
:class:`DdosReport`.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum

from netops_autopilot.engines.flow import FlowRecord, FlowProtocol


class DdosSignalKind(str, Enum):
    __test__ = False

    UDP_FLOOD = "udp-flood"
    SYN_FLOOD = "syn-flood"
    ICMP_FLOOD = "icmp-flood"
    AMPLIFICATION = "amplification"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DdosSignal:
    __test__ = False

    kind: DdosSignalKind
    src_ip: str
    target: str
    bytes: int
    packets: int
    confidence: float          # 0.0 .. 1.0

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"{self.src_ip} -> {self.target}: "
                f"{self.kind.value} "
                f"({self.bytes} بايت، "
                f"ثقة {self.confidence*100:.0f}%)"
            )
        return (
            f"{self.src_ip} -> {self.target}: "
            f"{self.kind.value} "
            f"({self.bytes} bytes, "
            f"confidence {self.confidence*100:.0f}%)"
        )


@dataclass
class DdosReport:
    __test__ = False

    signals: list[DdosSignal] = field(default_factory=list)

    @property
    def signal_count(self) -> int:
        return len(self.signals)

    @property
    def has_signal(self) -> bool:
        return self.signal_count > 0

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            head = (
                f"DDoS: {self.signal_count} إشارة"
            )
        else:
            head = (
                f"DDoS: {self.signal_count} signal(s)"
            )
        if self.signals:
            head += "\n" + "\n".join(
                s.render(lang=lang) for s in self.signals[:5]
            )
        return head


def detect(
    flows: list[FlowRecord],
    *,
    syn_threshold: int = 1000,
    bytes_threshold: int = 1_000_000,
) -> DdosReport:
    """Detect DDoS signals in a list of flows."""
    rep = DdosReport()
    if not flows:
        return rep
    # Aggregate by (src, dst, protocol).
    agg: dict[tuple[str, str, str], list[FlowRecord]] = (
        defaultdict(list)
    )
    for f in flows:
        agg[(f.src_ip, f.dst_ip, f.protocol.value)].append(f)

    for (src, dst, proto), group in agg.items():
        total_bytes = sum(f.bytes for f in group)
        total_pkts = sum(f.packets for f in group)
        if proto == FlowProtocol.UDP.value and total_pkts >= syn_threshold:
            rep.signals.append(DdosSignal(
                kind=DdosSignalKind.UDP_FLOOD,
                src_ip=src, target=dst,
                bytes=total_bytes,
                packets=total_pkts,
                confidence=min(1.0, total_pkts / 5000.0),
            ))
        elif proto == FlowProtocol.TCP.value and total_pkts >= syn_threshold:
            rep.signals.append(DdosSignal(
                kind=DdosSignalKind.SYN_FLOOD,
                src_ip=src, target=dst,
                bytes=total_bytes,
                packets=total_pkts,
                confidence=min(1.0, total_pkts / 5000.0),
            ))
        elif proto == FlowProtocol.ICMP.value and total_bytes >= bytes_threshold:
            rep.signals.append(DdosSignal(
                kind=DdosSignalKind.ICMP_FLOOD,
                src_ip=src, target=dst,
                bytes=total_bytes,
                packets=total_pkts,
                confidence=min(1.0, total_bytes / 10_000_000.0),
            ))
    return rep
