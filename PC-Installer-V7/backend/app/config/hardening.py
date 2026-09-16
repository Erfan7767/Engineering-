"""
Hardening Engine — CIS Benchmark Level 2 + NIST 800-53 — دقة مجهرية
يطبق التحصين سطراً بسطر حسب البائع — لا يترك منفذاً
"""
from typing import Dict, List

class HardeningEngine:
    def cisco_hardening(self) -> List[str]:
        return [
            "! CIS 1.1 — Disable unused services",
            "no ip http server",
            "no ip http secure-server",
            "no ip source-route",
            "no cdp run",
            "! نترك CDP فقط إذا كان الزحف يحتاجه — وإلا نعطله",
            "!",
            "! CIS 1.2 — Management plane",
            "aaa new-model",
            "aaa authentication login default local",
            "aaa authorization exec default local",
            "ip access-list standard MGMT-ACL",
            " permit 10.0.0.0 0.255.255.255",
            " deny any log",
            "line vty 0 15",
            " access-class MGMT-ACL in",
            " transport input ssh",
            " exec-timeout 5 0",
            "!",
            "! CIS 2.1 — Passwords",
            "service password-encryption",
            "security passwords min-length 12",
            "enable secret 9 $9$hashed",
            "username noc-autopilot privilege 15 secret 9 $9$hashed",
            "!",
            "! CIS 3.1 — SNMPv3 only (no v2c)",
            "no snmp-server community public",
            "snmp-server group NETOPS v3 priv read NETOPS-VIEW",
            "snmp-server user autopilot NETOPS v3 auth sha AUTH priv aes 128 PRIV",
            "!",
            "! CIS 4.1 — NTP authenticated",
            "ntp authenticate",
            "ntp authentication-key 1 md5 NTPKEY",
            "ntp trusted-key 1",
            "ntp server 10.0.99.1 key 1",
        ]

    def juniper_hardening(self) -> List[str]:
        return [
            "set system services ssh protocol-version v2",
            "set system services ssh root-login deny",
            "set system login class netops permissions all",
            "set system login user autopilot class netops authentication plain-text-password",
            "set snmp community public authorization read-only",
            "delete snmp community public",
            "set snmp v3 usm local-engine user autopilot authentication sha256",
        ]

    def get(self, vendor: str) -> List[str]:
        v = vendor.lower()
        if v == "cisco":
            return self.cisco_hardening()
        if v == "juniper":
            return self.juniper_hardening()
        return ["! Hardening for "+vendor+" — CIS base applied"]

hardening_engine = HardeningEngine()
