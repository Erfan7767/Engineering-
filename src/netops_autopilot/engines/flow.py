"""NetFlow / sFlow / IPFIX Traffic Analyzer.

A 30-year network engineer keeps a top-N of "who is
chatting with whom". This module is the typed
implementation: aggregate flow records into a TopN of
talkers / listeners, and surface top applications / ports.

Design contract:

* **Typed flows** — :class:`FlowRecord` carries the 5-tuple
  + bytes + packets + timestamp.
* **Deterministic aggregation** — same input list → same
  TopN every time.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum


class FlowProtocol(str, Enum):
    __test__ = False

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FlowRecord:
    __test__ = False

    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: FlowProtocol = FlowProtocol.UNKNOWN
    bytes: int = 0
    packets: int = 0
    timestamp_unix: float = 0.0
    application: str = ""


@dataclass(frozen=True)
class FlowAggregate:
    __test__ = False

    key: str
    bytes: int
    packets: int


@dataclass
class FlowReport:
    __test__ = False

    flows: list[FlowRecord] = field(default_factory=list)
    top_talkers: list[FlowAggregate] = field(default_factory=list)
    top_listeners: list[FlowAggregate] = field(default_factory=list)
    top_applications: list[FlowAggregate] = field(default_factory=list)
    total_bytes: int = 0
    total_packets: int = 0

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            head = (
                f"تحليل التدفق: {len(self.flows)} سجل\n"
                f"  إجمالي البايتات: {self.total_bytes}\n"
                f"  إجمالي الحزم: {self.total_packets}"
            )
        else:
            head = (
                f"Flow analysis: {len(self.flows)} record(s)\n"
                f"  Total bytes: {self.total_bytes}\n"
                f"  Total packets: {self.total_packets}"
            )
        return head


def _agg_by(
    key_fn,
    flows: list[FlowRecord],
    n: int = 10,
) -> list[FlowAggregate]:
    bytes_total: dict[str, int] = defaultdict(int)
    packets_total: dict[str, int] = defaultdict(int)
    for f in flows:
        k = key_fn(f)
        bytes_total[k] += f.bytes
        packets_total[k] += f.packets
    out = sorted(
        bytes_total.keys(),
        key=lambda k: -bytes_total[k],
    )[:n]
    return [
        FlowAggregate(
            key=k,
            bytes=bytes_total[k],
            packets=packets_total[k],
        )
        for k in out
    ]


def aggregate(
    flows: list[FlowRecord],
    *,
    top_n: int = 10,
) -> FlowReport:
    """Aggregate a list of flows into a TopN report."""
    rep = FlowReport(flows=list(flows))
    rep.total_bytes = sum(f.bytes for f in flows)
    rep.total_packets = sum(f.packets for f in flows)
    rep.top_talkers = _agg_by(
        lambda f: f.src_ip, flows, n=top_n,
    )
    rep.top_listeners = _agg_by(
        lambda f: f.dst_ip, flows, n=top_n,
    )
    rep.top_applications = _agg_by(
        lambda f: f.application or f"{f.dst_port}/{f.protocol.value}",
        flows, n=top_n,
    )
    return rep


def parse_cisco_netflow(output: str) -> list[FlowRecord]:
    """Parse a Cisco NetFlow cache dump.

    Lines look like:

    ::

        SrcIf  SrcIPaddress   DstIf  DstIPaddress   Pr SrcP DstP Pkts
        Gi0/1  10.0.0.1       Gi0/2  10.0.0.2       06 1234 80    100

    The protocol column uses the IANA number (06 = TCP,
    17 = UDP, 01 = ICMP).
    """
    if not output or not output.strip():
        return []
    proto_map = {
        "06": FlowProtocol.TCP,
        "17": FlowProtocol.UDP,
        "01": FlowProtocol.ICMP,
    }
    flows: list[FlowRecord] = []
    now = time.time()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        # Skip header lines (start with SrcIf / Source / etc.)
        first = parts[0]
        if not first.startswith(("Gi", "Fa", "Te", "Eth", "Lo", "Tu", "Po")):
            continue
        try:
            pkts = int(parts[-1])
            src_port = int(parts[-3])
            dst_port = int(parts[-2])
            proto_code = parts[-4]
        except (ValueError, IndexError):
            continue
        flows.append(FlowRecord(
            src_ip=parts[1] if len(parts) > 1 else "",
            dst_ip=parts[3] if len(parts) > 3 else "",
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto_map.get(proto_code, FlowProtocol.UNKNOWN),
            bytes=pkts * 64,  # we don't have byte counts in this view
            packets=pkts,
            timestamp_unix=now,
        ))
    return flows
