from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Any, List
from app.chat.copilot import copilot
from app.discovery.evidence import evidence_store
from app.audit.log import audit_log

router = APIRouter()

class ChatRequest(BaseModel):
    question: str
    inventory: Dict[str, Any] = {}
    evidence: Dict[str, Any] = {}

@router.post("/")
async def chat(req: ChatRequest):
    # Use provided or fallback to stored evidence
    evidence = req.evidence or evidence_store.to_dict()
    inventory = req.inventory or {}
    # If no inventory provided, try to build from evidence
    result = copilot.handle(req.question, inventory, evidence)
    
    audit_log.append(
        actor="operator",
        action="assistant.question",
        target=req.question[:80],
        risk="READ-ONLY",
        outcome="ok" if result.get("grounded") else "blocked",
        detail=f"Answered grounded={result.get('grounded')} evidenceIds={len(result.get('evidenceIds',[]))}"
    )
    return result

@router.get("/history")
async def history():
    return {"audit": audit_log.to_list()[-10:]}
