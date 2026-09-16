"""
BGP + VXLAN EVPN + SD-WAN — دقة CCIE Data Center + JNCIE-DC
V5 FINAL — للشبكات الضخمة 200+ جهاز
"""
from typing import List

class AdvancedProtocols:
    def cisco_bgp(self, asn: int, neighbors: List[str]) -> List[str]:
        cmds = [f"router bgp {asn}", f" bgp router-id 10.0.0.1", " bgp log-neighbor-changes"]
        for nb in neighbors:
            cmds += [f" neighbor {nb} remote-as {asn}", f" neighbor {nb} update-source Loopback0"]
        cmds += [" address-family l2vpn evpn", "  neighbor default send-community extended", " exit-address-family"]
        return cmds

    def juniper_evpn(self) -> List[str]:
        return [
            "set protocols bgp group EVPN type internal",
            "set protocols bgp group EVPN family evpn signaling",
            "set protocols evpn vni-options vni 10010 vrf-target target:65000:10010",
            "set routing-instances EVPN-100 instance-type virtual-switch",
        ]

    def sdwan_fortinet(self) -> List[str]:
        return [
            "config system sdwan",
            " set status enable",
            " config zone",
            "  edit virtual-wan-link",
            " next",
            " end",
            " config members",
            "  edit 1",
            "   set interface wan1",
            "  next",
            " end",
        ]

    def vxlan_cisco(self, vni: int, vlan: int) -> List[str]:
        return [
            f"interface nve1",
            f" member vni {vni}",
            f"  ingress-replication protocol bgp",
            f" vlan {vlan}",
            f"  vn-segment {vni}",
        ]

advanced = AdvancedProtocols()
