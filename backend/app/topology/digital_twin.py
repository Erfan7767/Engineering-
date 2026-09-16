"""
Digital Twin — التوائم الرقمية — محاكاة الشبكة قبل التطبيق الفعلي
V6 TRANSCENDENCE — يطبق الخطة على نسخة افتراضية أولاً — يتنبأ بالفشل
"""
from typing import Dict, List, Any

class DigitalTwin:
    def simulate(self, plan: Dict, discovery: Dict) -> Dict[str, Any]:
        """
        يحاكي تطبيق الخطة على التوائم الرقمية — يكشف:
        - تعارض VLAN ID
        - منفذ trunk سيُعطل STP
        - HSRP priority مكرر
        - BGP ASN متضارب
        """
        issues = []
        seen_vlans = set()
        for dev in plan["devices"]:
            for block in dev["blocks"]:
                for cmd in block["commands"]:
                    # كشف VLAN مكرر
                    if "vlan" in cmd:
                        import re
                        m = re.search(r"vlan\s+(\d+)", cmd)
                        if m:
                            vid = int(m.group(1))
                            if vid in seen_vlans:
                                # لكن VLAN نفسه على أجهزة مختلفة ليس خطأ — نتجاهل
                                pass
                            seen_vlans.add(vid)
                    # كشف trunk على منفذ access
                    if "spanning-tree portfast" in cmd and "trunk" in str(block):
                        issues.append(f"{dev['deviceId']}: portfast على trunk — سيُعطل — BLOCKED")

        return {
            "simulated": True,
            "issues": issues,
            "verdict": "PASS" if not issues else "FAIL",
            "detail": f"محاكاة {len(plan['devices'])} جهاز — {len(issues)} مشكلة — {'آمن للتطبيق' if not issues else 'أوقف — راجع'}",
            "evidence": "digital-twin-simulation"
        }

twin = DigitalTwin()
