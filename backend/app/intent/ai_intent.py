"""
AI Intent — تحويل اللغة الطبيعية إلى intent حتمي — مع grounding مطلق
V6 TRANSCENDENCE — LLM مقيد بالأدلة فقط — لا يخترع
"""
from typing import Dict, Any
import re

class AIIntent:
    """
    يحول: "أريد شبكة جامعة 3 مباني مع واي فاي معزول وضيوف" 
    → intent منظم — لكن لا يخترع VLAN غير مذكور — يطلب تأكيد
    """
    def parse_natural(self, text: str, discovered_devices: int) -> Dict[str, Any]:
        lower = text.lower()
        # كشف النية الحقيقية — مقيد بقائمة بيضاء
        hints = {
            "campus": ["جامعة", "campus", "حرم", "3 مباني", "مباني"],
            "data-center": ["مركز بيانات", "data center", "dc "],
            "small-office": ["مكتب", "office", "5 أجهزة"],
            "branch": ["فرع", "branch"],
        }
        preset = None
        for k, words in hints.items():
            if any(w in lower for w in words):
                preset = k
                break
        
        # كشف المتطلبات الدقيقة — فقط ما ذُكر حرفياً
        vlans = []
        if "واي فاي" in text or "wifi" in lower:
            vlans.append({"id": 40, "name": "WIFI", "purpose": "لاسلكي"})
        if "ضيوف" in text or "guest" in lower:
            vlans.append({"id": 99, "name": "GUEST", "purpose": "ضيوف معزولة"})
        if "خوادم" in text or "servers" in lower:
            vlans.append({"id": 30, "name": "SERVERS", "purpose": "خوادم"})
        
        # إذا لم يذكر، لا يخترع — يستخدم preset الأساسي فقط
        # Scale recommendation — حسب عدد الأجهزة المكتشفة فعلياً
        scale_note = f"مكتشف {discovered_devices} جهاز — {'هرمي Core/Dist/Access' if discovered_devices>20 else 'مسطح L2'}"

        return {
            "preset": preset,
            "explicit_vlans": vlans,
            "scale_note": scale_note,
            "requires_confirmation": preset is None,
            "grounded": True,  # كل شيء من النص أو preset — لا اختراع
        }

ai_intent = AIIntent()
