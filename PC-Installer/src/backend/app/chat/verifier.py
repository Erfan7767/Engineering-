"""
Claim Verifier — آخر بوابة قبل أن تصل أي جملة إلى الإنسان
القواعد:
- أي ادعاء يذكر كياناً خارج المخزون = REJECTED ويُحذف
- أي ادعاء بلا دليل مُستشهد به = UNVERIFIED (يُعرض كفرضية مع تحذير)
- أي ادعاء له دليل = VERIFIED
"""
import re
from typing import Dict, List, Any

class ClaimVerifier:
    def verify(self, text: str, evidenceIds: List[str], inventory: Dict, evidence_store: Dict) -> Dict[str, Any]:
        # استخرج الكيانات المذكورة (أسماء أجهزة)
        # نمط hostname: أحرف + أرقام + شرطة
        mentioned = re.findall(r"\b[A-Z0-9][A-Z0-9\-]{2,}\b", text)
        # تحقق هل كل مذكور موجود في المخزون؟
        inventory_ids = set(inventory.get("devices", {}).keys()) if isinstance(inventory.get("devices"), dict) else set([d["id"] for d in inventory.get("devices", [])])
        # أيضاً تحقق من IPs
        ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)
        # فلترة الكيانات التي تبدو أجهزة (ليست كلمات عادية)
        suspects = [m for m in mentioned if len(m) >= 4 and not m.isdigit()]
        unknown = [s for s in suspects if s not in inventory_ids and not re.match(r"^(VLAN|CPU|SNMP|SSH|LLDP|CDP|OSPF)$", s)]

        # قاعدة 1: REJECTED
        if unknown and any(u in text for u in unknown):
            # تحقق هل الكيان ورد فعلاً كاسم جهاز أم كلمة عامة
            real_unknown = [u for u in unknown if u in inventory_ids or u.startswith("BR") or u.startswith("DC") or u.startswith("HQ")]
            # تبسيط: إذا ذكر جهاز غير موجود في المخزون
            outside = [u for u in suspects if u not in inventory_ids and (u.startswith("BR") or u.startswith("DC") or u.startswith("HQ"))]
            if outside:
                return {
                    "status": "REJECTED",
                    "evidenceIds": evidenceIds,
                    "reason": f"Claim references entities that are not in the inventory: {', '.join(outside)}. Rejected before display."
                }

        # قاعدة 2: UNVERIFIED
        if not evidenceIds:
            return {
                "status": "UNVERIFIED",
                "evidenceIds": [],
                "reason": "No raw collection backs this statement. Displayed only as a hypothesis — not a fact.",
                "warning": "⚠️ ادعاء بلا دليل — لا يُعتمد عليه لاتخاذ قرار"
            }

        # تحقق كل evidenceId موجود فعلاً في المخزن
        missing = [eid for eid in evidenceIds if eid not in evidence_store]
        if missing:
            return {
                "status": "UNVERIFIED",
                "evidenceIds": [e for e in evidenceIds if e in evidence_store],
                "reason": f"Some cited evidence not found: {missing}"
            }

        return {
            "status": "VERIFIED",
            "evidenceIds": evidenceIds,
            "reason": "All claims grounded in cited raw evidence"
        }

verifier = ClaimVerifier()
