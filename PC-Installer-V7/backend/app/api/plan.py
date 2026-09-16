from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Any
from app.intent.parser import parser
from app.intent.designer import designer
from app.config.generator import generator
from app.audit.log import audit_log

router = APIRouter()

class IntentRequest(BaseModel):
    text: str
    discovery: Dict[str, Any]  # نتيجة الاكتشاف

@router.post("/intent")
async def parse_intent(req: IntentRequest):
    result = parser.parse(req.text)
    if not result["ok"]:
        audit_log.append(actor="autopilot", action="intent.rejected", target=req.text[:60], risk="READ-ONLY", outcome="blocked", detail=result["error"])
        return result
    audit_log.append(actor="operator", action="intent.accepted", target=result["preset"], risk="READ-ONLY", outcome="ok", detail=f"Intent parsed: {result['preset']} confidence {result['confidence']}")
    return result

@router.post("/generate")
async def generate_plan(req: IntentRequest):
    parsed = parser.parse(req.text)
    if not parsed["ok"]:
        return parsed
    intent = parsed["intent"]
    plan = designer.design(req.discovery, intent)
    # generate configs preview
    configs = generator.generate(plan)
    
    audit_log.append(actor="autopilot", action="plan.generated", target=plan["networkName"], risk="READ-ONLY", outcome="ok", detail=f"Plan hash {plan['hash']} with {len(plan['devices'])} devices, {len(plan['requirements'])} requirements")
    
    return {
        "plan": plan,
        "configs": configs,
        "summary": {
            "devices": len(plan["devices"]),
            "requirements": len(plan["requirements"]),
            "hash": plan["hash"]
        }
    }
