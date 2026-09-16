from fastapi import APIRouter
from app.audit.log import audit_log

router = APIRouter()

@router.get("/")
async def get_audit():
    return {
        "entries": audit_log.to_list(),
        "chain_valid": audit_log.verify_chain(),
        "count": len(audit_log.entries)
    }

@router.get("/verify")
async def verify():
    return {"valid": audit_log.verify_chain(), "count": len(audit_log.entries)}
