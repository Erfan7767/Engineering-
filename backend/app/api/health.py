from fastapi import APIRouter
from typing import List, Dict, Any
from pydantic import BaseModel

router = APIRouter()

class HealthImport(BaseModel):
    records: List[Dict[str, Any]]
    declaredErrors: List[Dict] = []

@router.post("/import")
async def import_health(req: HealthImport):
    # Validate — كل سجل يجب أن يحمل evidenceId و deviceId
    errors = []
    for i, r in enumerate(req.records):
        if "deviceId" not in r or "evidenceId" not in r:
            errors.append(f"record[{i}] missing deviceId/evidenceId — rejected")
    if errors:
        return {"ok": False, "errorsAr": errors}
    
    return {
        "ok": True,
        "imported": len(req.records),
        "detail": f"READ-ONLY fleet health evidence imported: {len(req.records)} records"
    }

@router.get("/")
async def health():
    return {
        "status": "ok",
        "engine": "evidence-first",
        "message": "استورد health pack من الأجهزة الحقيقية ثم اسأل المحاور 'ما صحة الشبكة؟'"
    }
