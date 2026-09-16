from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, List, Any
from app.execution.engine import engine
from app.discovery.crawler import Target

router = APIRouter()

class BackupRequest(BaseModel):
    targets: List[Dict]  # [{device_id, mgmt_ip, vendor, username, password}]

class ApproveRequest(BaseModel):
    approved: bool
    operator: str = "human"

class ApplyRequest(BaseModel):
    plan: Dict[str, Any]
    targets: List[Dict]
    vault: Dict[str, str] = {}

@router.post("/backup")
async def backup(req: BackupRequest):
    targets = [Target(d["device_id"], d.get("hostname", d["device_id"]), d["mgmt_ip"], d.get("vendor","cisco"), d.get("username","admin"), d.get("password","admin")) for d in req.targets]
    result = engine.backup(targets)
    return {"backups": result, "stored_in": "backups/"}

@router.post("/dry-run")
async def dry_run(req: ApplyRequest):
    result = engine.dry_run(req.plan, [])
    return result

@router.post("/diff")
async def diff(req: ApplyRequest):
    # need backups first — use empty if not exists
    diffs = engine.diff(req.plan, engine.backups)
    return {"diffs": diffs}

@router.post("/approve")
async def approve(req: ApproveRequest):
    ok = engine.approve(req.approved, req.operator)
    return {"approved": ok, "gate": "نافذ", "detail": "Approved — apply now allowed" if ok else "Rejected — apply blocked"}

@router.post("/apply")
async def apply(req: ApplyRequest):
    targets = [Target(d["device_id"], d.get("hostname", d["device_id"]), d["mgmt_ip"], d.get("vendor","cisco"), d.get("username","admin"), d.get("password","admin")) for d in req.targets]
    result = engine.apply(req.plan, targets, req.vault)
    return result

@router.post("/verify")
async def verify(req: ApplyRequest):
    targets = [Target(d["device_id"], d.get("hostname", d["device_id"]), d["mgmt_ip"], d.get("vendor","cisco"), d.get("username","admin"), d.get("password","admin")) for d in req.targets]
    result = engine.verify(req.plan, targets)
    return result

@router.post("/rollback")
async def rollback(deviceId: str):
    return engine.rollback(deviceId)
