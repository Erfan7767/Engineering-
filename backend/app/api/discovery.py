from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, List
from app.discovery.crawler import crawler, Target
from app.topology.mapper import mapper
from app.audit.log import audit_log

router = APIRouter()

class DiscoverRequest(BaseModel):
    seedDeviceId: str
    mgmtIp: str
    username: str = "admin"
    password: str = "admin"
    vendor: str = "cisco"
    vault: Dict[str, str] = {}  # deviceId -> password for non-default

@router.post("/start")
async def start_discovery(req: DiscoverRequest):
    seed = Target(
        device_id=req.seedDeviceId,
        hostname=req.seedDeviceId,
        mgmt_ip=req.mgmtIp,
        vendor=req.vendor,
        username=req.username,
        password=req.password,
    )
    audit_log.append(actor="operator", action="discovery.start", target=req.seedDeviceId, risk="READ-ONLY", outcome="ok", detail=f"Crawl started from {req.seedDeviceId} ({req.mgmtIp}) via LLDP/CDP")
    
    result = crawler.discover(seed, req.vault)
    
    topology = mapper.build(result)
    
    audit_log.append(actor="autopilot", action="discovery.completed", target=f"{len(result.devices)} devices / {len(result.links)} links", risk="READ-ONLY", outcome="ok", detail=f"Discovery finished with {len(result.failures)} explicit failure(s). No failure suppressed." if result.failures else "Discovery completed — all reachable")
    
    return {
        "devices": result.devices,
        "links": [l.__dict__ for l in result.links],
        "topology": topology,
        "evidence": result.evidence,
        "failures": result.failures,
        "stats": {
            "deviceCount": len(result.devices),
            "linkCount": len(result.links),
            "failureCount": len(result.failures),
        }
    }

@router.get("/evidence")
async def get_evidence():
    from app.discovery.evidence import evidence_store
    return evidence_store.to_dict()
