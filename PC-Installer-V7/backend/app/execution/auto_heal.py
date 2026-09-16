"""
Auto-Heal — الشفاء التلقائي — يراقب الشبكة بعد التطبيق ويصلح تلقائياً
V6 TRANSCENDENCE — evidence-driven — لا يصلح بدون دليل
"""
from typing import Dict, List

class AutoHeal:
    def check_and_heal(self, health_evidence: List[Dict]) -> List[Dict]:
        """
        يقرأ health evidence (CPU, CRC, flaps) — إذا تجاوز عتبة → يقترح إصلاح حتمي
        لا ينفذ تلقائياً — يقترح وينتظر نافذ — إلا إذا كان READ-ONLY
        """
        actions = []
        for ev in health_evidence:
            # مثال: CRC storm
            if ev.get("crcErrors", 0) > 1000:
                actions.append({
                    "deviceId": ev["deviceId"],
                    "issue": f"CRC {ev['crcErrors']} — كابل أو SFP تالف",
                    "suggested": "افحص الكابل — استبدل SFP — لا تغير التكوين",
                    "auto": False,  # يحتاج تدخل مادي — لا يُصلح برمجياً
                    "evidenceId": ev.get("evidenceId")
                })
            # CPU high
            if ev.get("cpu", 0) > 85:
                actions.append({
                    "deviceId": ev["deviceId"],
                    "issue": f"CPU {ev['cpu']}% sustained",
                    "suggested": "تحقق من loop أو broadcast storm — راجع spanning-tree",
                    "auto": False,
                    "evidenceId": ev.get("evidenceId")
                })
        return actions

healer = AutoHeal()
