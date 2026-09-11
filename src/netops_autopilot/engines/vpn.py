"""IPSec VPN Engine — typed tunnel monitor.

A 30-year engineer monitors IPSec tunnels: Phase-1 up,
Phase-2 up, packets encrypted, last rekey time. This
module is the typed implementation: parse Cisco
``show crypto ipsec sa`` / ``show crypto isakmp sa`` /
Juniper ``show ipsec sa`` output, surface typed
:class:`IpsecTunnel` records.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class IpsecTunnel:
    __test__ = False

    name: str
    local: str
    remote: str
    phase1_up: bool = False
    phase2_up: bool = False
    encrypted_pkts: int = 0
    decrypted_pkts: int = 0
    last_rekey_seconds: int = 0

    @property
    def is_healthy(self) -> bool:
        return self.phase1_up and self.phase2_up

    @property
    def health_label(self) -> str:
        if not self.phase1_up:
            return "DOWN"
        if not self.phase2_up:
            return "PHASE1_ONLY"
        return "UP"


@dataclass
class VpnReport:
    __test__ = False

    device: str
    tunnels: list[IpsecTunnel] = field(default_factory=list)

    @property
    def tunnel_count(self) -> int:
        return len(self.tunnels)

    @property
    def up_count(self) -> int:
        return sum(1 for t in self.tunnels if t.is_healthy)

    @property
    def down_count(self) -> int:
        return sum(1 for t in self.tunnels if not t.is_healthy)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"VPN: {self.tunnel_count} نفق\n"
                f"  نشط: {self.up_count}\n"
                f"  معطل: {self.down_count}"
            )
        return (
            f"VPN: {self.tunnel_count} tunnel(s)\n"
            f"  Up: {self.up_count}\n"
            f"  Down: {self.down_count}"
        )


_TUNNEL_PEER = re.compile(
    r"peer\s+(?P<peer>\d+\.\d+\.\d+\.\d+)"
    r"(?:\s+port\s+(?P<port>\d+))?",
    re.MULTILINE,
)


def parse_crypto_isakmp(
    device: str,
    output: str,
) -> VpnReport:
    """Parse ``show crypto isakmp sa``."""
    rep = VpnReport(device=device)
    if not output or not output.strip():
        return rep
    peers: dict[str, IpsecTunnel] = {}
    for m in _TUNNEL_PEER.finditer(output):
        peer = m.group("peer")
        if peer not in peers:
            peers[peer] = IpsecTunnel(
                name=f"isakmp-{peer}",
                local="",
                remote=peer,
                phase1_up=True,
            )
    rep.tunnels = list(peers.values())
    return rep
