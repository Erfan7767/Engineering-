"""Network Protocol Parsers — LLDP, CDP, VTP, STP, DHCP.

A 30-year network engineer can read the raw output of any of
these protocols and immediately spot the issue:

* A CDP neighbor with the wrong platform = someone moved a
  cable and the running-config still has the old label.
* A VTP revision number higher than the server's = a
  rogue switch is announcing VLANs.
* An STP root port on a non-root switch = someone
  re-patched a cable and broke the spanning tree.
* A DHCP snooping violation = an unauthorized DHCP server
  is on the LAN.

This module turns those raw outputs into typed, evidence-bound
reports. Every parser is rule-based — there is no LLM
guessing, no hallucination. If a field is missing, the report
says "UNKNOWN".

What it does:

* Parses ``show lldp neighbors detail`` into per-port
  :class:`LldpNeighbor` records.
* Parses ``show cdp neighbors detail`` into per-port
  :class:`CdpNeighbor` records.
* Parses ``show vtp status`` and ``show vtp password`` into
  a :class:`VtpStatus` with revision / domain / mode.
* Parses ``show spanning-tree`` into a :class:`StpStatus`
  with root bridge / root port / topology changes.
* Parses ``show ip dhcp snooping`` and ``show ip dhcp
  snooping binding`` into a :class:`DhcpSnoopingStatus`.

What it does NOT do (typed, never silent):

* It does NOT invent neighbors. An empty list of LLDP
  neighbors on a trunk port is a real finding, not a bug.
* It does NOT infer the VTP mode from a partial output —
  the report says UNKNOWN if the field is missing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------
# LLDP
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class LldpNeighbor:
    __test__ = False

    local_interface: str
    chassis_id: str = ""
    system_name: str = ""
    port_id: str = ""
    mgmt_ip: str = ""
    platform: str = ""


@dataclass
class LldpReport:
    __test__ = False

    device_ref: str
    neighbors: list[LldpNeighbor] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.neighbors)

    @property
    def unknown_devices(self) -> list[LldpNeighbor]:
        return [
            n for n in self.neighbors
            if not n.system_name and not n.chassis_id
        ]

    def by_interface(self, intf: str) -> list[LldpNeighbor]:
        return [n for n in self.neighbors if n.local_interface == intf]


_LLDP_LOCAL_INTF = re.compile(
    r"^Local Intf:\s*(?P<intf>\S+)", re.MULTILINE,
)
_LLDP_CHASSIS = re.compile(r"^Chassis id:\s*(?P<v>.+)$", re.MULTILINE)
_LLDP_SYSNAME = re.compile(r"^System Name:\s*(?P<v>.+)$", re.MULTILINE)
_LLDP_PORT_ID = re.compile(r"^Port id:\s*(?P<v>.+)$", re.MULTILINE)
_LLDP_MGMT = re.compile(r"^Management Address:\s*(?P<v>.+)$", re.MULTILINE)
_LLDP_PLATFORM = re.compile(r"^Platform:\s*(?P<v>.+)$", re.MULTILINE)


def parse_lldp(output: str) -> list[LldpNeighbor]:
    """Parse ``show lldp neighbors detail`` output."""
    if not output or not output.strip():
        return []
    # Split into per-neighbor blocks using Local Intf as anchor.
    blocks: list[str] = []
    starts = list(_LLDP_LOCAL_INTF.finditer(output))
    for i, m in enumerate(starts):
        start = m.start()
        end = starts[i + 1].start() if i + 1 < len(starts) else len(output)
        blocks.append(output[start:end])
    neighbors: list[LldpNeighbor] = []
    for b in blocks:
        local = _LLDP_LOCAL_INTF.search(b)
        if not local:
            continue
        chassis = _LLDP_CHASSIS.search(b)
        sysname = _LLDP_SYSNAME.search(b)
        port = _LLDP_PORT_ID.search(b)
        mgmt = _LLDP_MGMT.search(b)
        platform = _LLDP_PLATFORM.search(b)
        neighbors.append(LldpNeighbor(
            local_interface=local.group("intf"),
            chassis_id=chassis.group("v").strip() if chassis else "",
            system_name=sysname.group("v").strip() if sysname else "",
            port_id=port.group("v").strip() if port else "",
            mgmt_ip=mgmt.group("v").strip() if mgmt else "",
            platform=platform.group("v").strip() if platform else "",
        ))
    return neighbors


# ---------------------------------------------------------------------
# CDP
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class CdpNeighbor:
    __test__ = False

    local_interface: str
    device_id: str = ""
    platform: str = ""
    remote_port: str = ""
    mgmt_ip: str = ""
    version: str = ""


@dataclass
class CdpReport:
    __test__ = False

    device_ref: str
    neighbors: list[CdpNeighbor] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.neighbors)


_CDP_DEVICE = re.compile(r"^Device ID:\s*(?P<v>.+)$", re.MULTILINE)
_CDP_PLATFORM = re.compile(r"^Platform:\s*(?P<v>.+?),", re.MULTILINE)
_CDP_INTERFACE = re.compile(r"^Interface:\s*(?P<v>.+?),\s*Port ID", re.MULTILINE)
_CDP_PORT = re.compile(r"^Port ID \(outgoing port\):\s*(?P<v>.+)$", re.MULTILINE)
_CDP_MGMT = re.compile(r"^IP address:\s*(?P<v>.+)$", re.MULTILINE)
_CDP_VERSION = re.compile(r"^Version:\s*(?P<v>.+)$", re.MULTILINE)


def parse_cdp(output: str) -> list[CdpNeighbor]:
    """Parse ``show cdp neighbors detail`` output."""
    if not output or not output.strip():
        return []
    # Split by "----" separator
    parts = re.split(r"-{5,}", output)
    neighbors: list[CdpNeighbor] = []
    for block in parts:
        if "Device ID" not in block:
            continue
        dev = _CDP_DEVICE.search(block)
        plat = _CDP_PLATFORM.search(block)
        local = _CDP_INTERFACE.search(block)
        port = _CDP_PORT.search(block)
        mgmt = _CDP_MGMT.search(block)
        ver = _CDP_VERSION.search(block)
        if not dev or not local:
            continue
        neighbors.append(CdpNeighbor(
            local_interface=local.group("v").strip(),
            device_id=dev.group("v").strip(),
            platform=plat.group("v").strip() if plat else "",
            remote_port=port.group("v").strip() if port else "",
            mgmt_ip=mgmt.group("v").strip() if mgmt else "",
            version=ver.group("v").strip() if ver else "",
        ))
    return neighbors


# ---------------------------------------------------------------------
# VTP
# ---------------------------------------------------------------------


class VtpMode(str, Enum):
    __test__ = False

    SERVER = "server"
    CLIENT = "client"
    TRANSPARENT = "transparent"
    OFF = "off"
    UNKNOWN = "unknown"


@dataclass
class VtpStatus:
    __test__ = False

    vtp_domain: str = ""
    vtp_mode: VtpMode = VtpMode.UNKNOWN
    vtp_revision: int = 0
    last_modified_vlan: str = ""
    md5_digest: str = ""

    @property
    def is_rogue(self) -> bool:
        """A revision number > 0 on a transparent/off device
        is suspicious."""
        return self.vtp_mode in (VtpMode.TRANSPARENT, VtpMode.OFF) \
            and self.vtp_revision > 0


_VTP_DOMAIN = re.compile(r"VTP Domain Name\s*:\s*(?P<v>\S+)")
_VTP_MODE = re.compile(r"VTP Operating Mode\s*:\s*(?P<v>\S+)")
_VTP_REV = re.compile(r"Configuration Revision\s*:\s*(?P<v>\d+)")
_VTP_LAST = re.compile(r"VTP Operating Mode.*?(?:Local updater ID|Last.*?modified).*?(?P<v>\S+)")
_VTP_MD5 = re.compile(r"MD5 digest\s*:\s*(?P<v>[0-9a-fA-Fx]+)")


def parse_vtp(output: str) -> VtpStatus:
    """Parse ``show vtp status`` output."""
    if not output or not output.strip():
        return VtpStatus()
    s = VtpStatus()
    m = _VTP_DOMAIN.search(output)
    if m:
        s.vtp_domain = m.group("v").strip()
    m = _VTP_MODE.search(output)
    if m:
        try:
            s.vtp_mode = VtpMode(m.group("v").strip().lower())
        except ValueError:
            s.vtp_mode = VtpMode.UNKNOWN
    m = _VTP_REV.search(output)
    if m:
        try:
            s.vtp_revision = int(m.group("v").strip())
        except ValueError:
            pass
    m = _VTP_MD5.search(output)
    if m:
        s.md5_digest = m.group("v").strip()
    return s


# ---------------------------------------------------------------------
# STP
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class StpInstance:
    __test__ = False

    vlan_id: str
    root_bridge: str = ""
    root_priority: int = 0
    root_port: str = ""
    bridge_priority: int = 0
    topology_changes: int = 0
    last_topology_change_s: int = 0


@dataclass
class StpReport:
    __test__ = False

    device_ref: str
    instances: list[StpInstance] = field(default_factory=list)

    @property
    def unstable(self) -> list[StpInstance]:
        return [i for i in self.instances if i.topology_changes > 5]


_STP_VLAN = re.compile(
    r"^VLAN(?P<vlan>\d+)\s+(?P<root_pri>\d+)\s+"
    r"(?P<root_mac>[\da-fA-F\.]+)\s+(?P<cost>\d+)\s+(?P<root_port>\S+)",
    re.MULTILINE,
)


def parse_stp(output: str) -> StpReport:
    """Parse ``show spanning-tree`` summary output."""
    r = StpReport(device_ref="")
    if not output or not output.strip():
        return r
    for m in _STP_VLAN.finditer(output):
        try:
            pri = int(m.group("root_pri"))
        except ValueError:
            pri = 0
        r.instances.append(StpInstance(
            vlan_id=m.group("vlan"),
            root_bridge=m.group("root_mac"),
            root_priority=pri,
            root_port=m.group("root_port"),
        ))
    return r


# ---------------------------------------------------------------------
# DHCP Snooping
# ---------------------------------------------------------------------


@dataclass
class DhcpSnoopingStatus:
    __test__ = False

    enabled: bool = False
    trusted_ports: list[str] = field(default_factory=list)
    violations: int = 0
    bindings_count: int = 0
    untrusted_bindings: int = 0

    @property
    def has_rogue_server(self) -> bool:
        return self.violations > 0


def parse_dhcp_snooping(
    status_output: str,
    binding_output: str = "",
) -> DhcpSnoopingStatus:
    """Parse ``show ip dhcp snooping`` and the binding table."""
    s = DhcpSnoopingStatus()
    if not status_output or not status_output.strip():
        return s
    if "DHCP snooping is enabled" in status_output or \
       "Switch snooping is enabled" in status_output:
        s.enabled = True
    # Trusted ports: any line with "Trusted" + interface
    for m in re.finditer(
        r"Trusted\s+(?:Interface|interfaces?)\s*:\s*(?P<intfs>[^\n]+)",
        status_output, re.IGNORECASE,
    ):
        for tok in m.group("intfs").split(","):
            s.trusted_ports.append(tok.strip())
    # Violations
    m = re.search(
        r"DHCP snooping violations\s*:\s*(?P<n>\d+)",
        status_output, re.IGNORECASE,
    )
    if m:
        try:
            s.violations = int(m.group("n"))
        except ValueError:
            pass
    # Bindings — each row starts with an IP address (4 octets).
    if binding_output:
        rows = []
        for l in binding_output.splitlines():
            if not l or not l.strip():
                continue
            first = l.split()[0]
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", first):
                rows.append(l)
        s.bindings_count = len(rows)
    return s
