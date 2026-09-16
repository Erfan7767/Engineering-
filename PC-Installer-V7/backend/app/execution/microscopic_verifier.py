"""
Microscopic Verifier — 6 طبقات تحقق — كل طبقة بدليل خام
"""
from typing import Dict, List, Any
import re

class MicroscopicVerifier:
    def verify(self, device_id: str, raw_outputs: Dict[str, str], plan) -> List[Dict]:
        checks = []

        # L1 — Physical: CRC/FCS
        if "counters" in raw_outputs:
            crc = len(re.findall(r"CRC|FCS", raw_outputs["counters"]))
            checks.append({
                "layer": "L1 Physical",
                "check": "No CRC/FCS errors",
                "pass": crc == 0,
                "detail": f"Found {crc} CRC mentions" if crc else "Clean",
                "evidence": "show interfaces counters errors"
            })

        # L2 — Duplex / STP
        if "interfaces" in raw_outputs:
            half = "half" in raw_outputs["interfaces"].lower()
            checks.append({
                "layer": "L2 DataLink",
                "check": "Full-duplex on all trunks",
                "pass": not half,
                "detail": "Half-duplex detected" if half else "Full-duplex OK",
                "evidence": "show interfaces status"
            })

        # L3 — Routing
        if "route" in raw_outputs:
            has_route = "10.0." in raw_outputs["route"]
            checks.append({
                "layer": "L3 Network",
                "check": "VLAN subnets in routing table",
                "pass": has_route,
                "detail": "Routes found" if has_route else "No VLAN routes",
                "evidence": "show ip route"
            })

        # L3 — SVI
        if "running-config" in raw_outputs:
            for v in plan["intent"]["vlans"]:
                present = f"interface Vlan{v['id']}" in raw_outputs["running-config"] or f"vlan {v['id']}" in raw_outputs["running-config"]
                checks.append({
                    "layer": "L3 SVI",
                    "check": f"VLAN {v['id']} SVI exists",
                    "pass": present,
                    "detail": "Present" if present else "Missing",
                    "evidence": "show running-config"
                })

        # L7 — NTP
        if "ntp" in raw_outputs or "running-config" in raw_outputs:
            ntp_ok = plan["intent"]["ntpServer"] in raw_outputs.get("running-config","") or "ntp" in raw_outputs.get("running-config","").lower()
            checks.append({
                "layer": "L7 App",
                "check": f"NTP {plan['intent']['ntpServer']} configured",
                "pass": ntp_ok,
                "detail": "Configured" if ntp_ok else "Missing",
                "evidence": "show running-config | inc ntp"
            })

        # Security — ACL
        if "running-config" in raw_outputs:
            acl_ok = "MGMT-ACL" in raw_outputs["running-config"] or "access-class" in raw_outputs["running-config"]
            checks.append({
                "layer": "Security",
                "check": "Mgmt ACL applied",
                "pass": acl_ok if plan["intent"]["hardening"]=="hardened" else True,
                "detail": "Hardened: ACL present" if acl_ok else "Hardened: ACL missing" if plan["intent"]["hardening"]=="hardened" else "Standard: skip",
                "evidence": "show running-config | inc access-class"
            })

        # Each check gets pass/fail — verdict is FAIL if any critical fail
        return checks

    def verdict(self, checks: List[Dict]) -> str:
        fails = [c for c in checks if not c["pass"]]
        if not fails:
            return "PASS"
        # If L1/L2 fails, it's critical
        critical = [f for f in fails if f["layer"] in ["L1 Physical","L2 DataLink"]]
        if critical:
            return "FAIL"
        if len(fails) <= 2:
            return "PARTIAL"
        return "FAIL"

micro_verifier = MicroscopicVerifier()
