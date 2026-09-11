"""Multi-Vendor Command Dispatcher — the same intent, different commands.

A 30-year engineer knows that "show arp" on a Cisco is
"show arp" on a Juniper too, but "show ip route" is "show
route" on Junos and "show ip route" on EOS. This module is
the typed implementation: given a logical intent (e.g.
"routing table"), return the canonical command for each
supported vendor.

Design contract:

* **Typed** — :class:`LogicalCommand` is a vendor-neutral
  verb (e.g. ROUTING_TABLE / INTERFACE_STATUS / MAC_TABLE).
* **Deterministic** — same logical command + same vendor =
  same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class LogicalCommand(str, Enum):
    __test__ = False

    ROUTING_TABLE = "routing_table"
    INTERFACE_STATUS = "interface_status"
    INTERFACE_DETAIL = "interface_detail"
    MAC_TABLE = "mac_table"
    ARP_TABLE = "arp_table"
    VLAN_TABLE = "vlan_table"
    NEIGHBORS = "neighbors"
    VERSION = "version"
    INVENTORY = "inventory"
    POE = "poe"
    STP = "stp"
    VTP = "vtp"
    BGP_SUMMARY = "bgp_summary"
    OSPF_NEIGHBOR = "ospf_neighbor"
    NTP_STATUS = "ntp_status"
    CONFIG = "config"
    TRUNK = "trunk"
    DHCP_SNOOP = "dhcp_snoop"


class Vendor(str, Enum):
    __test__ = False

    CISCO_IOSXE = "cisco/ios-xe"
    CISCO_NXOS = "cisco/nx-os"
    JUNIPER_JUNOS = "juniper/junos"
    ARISTA_EOS = "arista/eos"
    NOKIA_SRLINUX = "nokia/sr-linux"
    MIKROTIK_ROUTEROS = "mikrotik/routeros"
    UBIQUITI_UNIFI = "ubiquiti/unifi"
    HUAWEI_VRP = "huawei/vrp"
    FORTINET_FORTIOS = "fortinet/fortios"
    HPE_ARUBAOS = "hpe/arubaos"


@dataclass(frozen=True)
class CommandMapping:
    __test__ = False

    vendor: Vendor
    command: str
    notes: str = ""


# Catalog: each logical command -> dict[vendor, command].
_CATALOGUE: dict[LogicalCommand, dict[Vendor, CommandMapping]] = {
    LogicalCommand.ROUTING_TABLE: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show ip route",
            "Standard Cisco IOS-XE.",
        ),
        Vendor.CISCO_NXOS: CommandMapping(
            Vendor.CISCO_NXOS, "show ip route",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show route",
            "Junos does not use 'ip' prefix.",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show ip route",
        ),
        Vendor.NOKIA_SRLINUX: CommandMapping(
            Vendor.NOKIA_SRLINUX, "show network-instance default route-table",
        ),
        Vendor.HUAWEI_VRP: CommandMapping(
            Vendor.HUAWEI_VRP, "display ip routing-table",
        ),
        Vendor.MIKROTIK_ROUTEROS: CommandMapping(
            Vendor.MIKROTIK_ROUTEROS, "/ip route print",
        ),
    },
    LogicalCommand.INTERFACE_STATUS: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show ip interface brief",
        ),
        Vendor.CISCO_NXOS: CommandMapping(
            Vendor.CISCO_NXOS, "show interface status",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show interfaces terse",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show ip interface brief",
        ),
        Vendor.NOKIA_SRLINUX: CommandMapping(
            Vendor.NOKIA_SRLINUX, "show interface brief",
        ),
        Vendor.HUAWEI_VRP: CommandMapping(
            Vendor.HUAWEI_VRP, "display ip interface brief",
        ),
        Vendor.MIKROTIK_ROUTEROS: CommandMapping(
            Vendor.MIKROTIK_ROUTEROS, "/interface print brief",
        ),
    },
    LogicalCommand.MAC_TABLE: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show mac address-table",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show ethernet-switching table",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show mac address-table",
        ),
        Vendor.HUAWEI_VRP: CommandMapping(
            Vendor.HUAWEI_VRP, "display mac-address",
        ),
    },
    LogicalCommand.VLAN_TABLE: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show vlan brief",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show vlans",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show vlan",
        ),
        Vendor.HUAWEI_VRP: CommandMapping(
            Vendor.HUAWEI_VRP, "display vlan",
        ),
    },
    LogicalCommand.NEIGHBORS: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show cdp neighbors detail",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show lldp neighbors",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show lldp neighbors detail",
        ),
        Vendor.HUAWEI_VRP: CommandMapping(
            Vendor.HUAWEI_VRP, "display lldp neighbor",
        ),
    },
    LogicalCommand.VERSION: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show version",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show version",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show version",
        ),
        Vendor.HUAWEI_VRP: CommandMapping(
            Vendor.HUAWEI_VRP, "display version",
        ),
    },
    LogicalCommand.STP: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show spanning-tree",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show spanning-tree bridge",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show spanning-tree",
        ),
    },
    LogicalCommand.VTP: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show vtp status",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS,
            "Junos has no VTP; uses GVRP/MVRP.",
            notes="Junos uses MVRP, not VTP.",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show vtp status",
        ),
    },
    LogicalCommand.BGP_SUMMARY: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show ip bgp summary",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show bgp summary",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show ip bgp summary",
        ),
        Vendor.HUAWEI_VRP: CommandMapping(
            Vendor.HUAWEI_VRP, "display bgp peer",
        ),
    },
    LogicalCommand.OSPF_NEIGHBOR: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show ip ospf neighbor",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show ospf neighbor",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show ip ospf neighbor",
        ),
        Vendor.HUAWEI_VRP: CommandMapping(
            Vendor.HUAWEI_VRP, "display ospf peer brief",
        ),
    },
    LogicalCommand.POE: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show power inline",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show poe interface",
        ),
        Vendor.HPE_ARUBAOS: CommandMapping(
            Vendor.HPE_ARUBAOS, "show power-over-ethernet",
        ),
    },
    LogicalCommand.NTP_STATUS: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show ntp status",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show ntp status",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show ntp status",
        ),
    },
    LogicalCommand.CONFIG: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show running-config",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show configuration",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show running-config",
        ),
        Vendor.HUAWEI_VRP: CommandMapping(
            Vendor.HUAWEI_VRP, "display current-configuration",
        ),
    },
    LogicalCommand.TRUNK: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show interfaces trunk",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS,
            "show interfaces ... | match trunk",
            notes="Junos uses interface mode, not trunk.",
        ),
    },
    LogicalCommand.DHCP_SNOOP: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show ip dhcp snooping",
        ),
        Vendor.HUAWEI_VRP: CommandMapping(
            Vendor.HUAWEI_VRP, "display dhcp snooping",
        ),
    },
    LogicalCommand.ARP_TABLE: {
        Vendor.CISCO_IOSXE: CommandMapping(
            Vendor.CISCO_IOSXE, "show ip arp",
        ),
        Vendor.JUNIPER_JUNOS: CommandMapping(
            Vendor.JUNIPER_JUNOS, "show arp",
        ),
        Vendor.ARISTA_EOS: CommandMapping(
            Vendor.ARISTA_EOS, "show ip arp",
        ),
        Vendor.HUAWEI_VRP: CommandMapping(
            Vendor.HUAWEI_VRP, "display arp",
        ),
    },
}


def lookup(
    logical: LogicalCommand,
    vendor: Vendor,
) -> CommandMapping | None:
    """Return the canonical command for ``logical`` on
    ``vendor``, or None if unsupported."""
    return _CATALOGUE.get(logical, {}).get(vendor)


def supported_vendors(
    logical: LogicalCommand,
) -> list[Vendor]:
    """Return the vendors that support ``logical``."""
    return list(_CATALOGUE.get(logical, {}).keys())


def translate_command(
    *,
    logical: LogicalCommand,
    vendor: Vendor,
    lang: str = "en",
) -> str:
    """Return a human-readable translation (rendered)."""
    cmd = lookup(logical, vendor)
    if cmd is None:
        if lang == "ar":
            return (
                f"الأمر {logical.value} غير مدعوم على {vendor.value}"
            )
        return (
            f"Command {logical.value} not supported on {vendor.value}"
        )
    notes = (
        f" — {cmd.notes}" if cmd.notes else ""
    )
    if lang == "ar":
        return f"{vendor.value}: {cmd.command}{notes}"
    return f"{vendor.value}: {cmd.command}{notes}"


def translate_all(
    logical: LogicalCommand,
    lang: str = "en",
) -> str:
    """Return a multi-vendor mapping for ``logical``."""
    supported = supported_vendors(logical)
    if lang == "ar":
        head = (
            f"ترجمة الأمر '{logical.value}' عبر "
            f"{len(supported)} منصة:"
        )
    else:
        head = (
            f"Translation of '{logical.value}' across "
            f"{len(supported)} vendor(s):"
        )
    body = "\n".join(
        translate_command(logical=logical, vendor=v, lang=lang)
        for v in supported
    )
    return head + "\n" + body
