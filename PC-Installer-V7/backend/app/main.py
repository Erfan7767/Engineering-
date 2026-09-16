"""
NetOps Autopilot — المهندس الآلي الحقيقي
FastAPI Backend — Evidence-First, Deterministic, No Hallucination
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import os

from app.api import discovery, plan, execution, topology, chat, audit, health
from app.audit.log import audit_log

app = FastAPI(
    title="NetOps Autopilot API",
    description="مهندس شبكات آلي حقيقي — اكتشاف، تصميم، تنفيذ، تحقق — مبني على الأدلة فقط",
    version="2.0.0-real",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(discovery.router, prefix="/api/discovery", tags=["discovery"])
app.include_router(topology.router, prefix="/api/topology", tags=["topology"])
app.include_router(plan.router, prefix="/api/plan", tags=["plan"])
app.include_router(execution.router, prefix="/api/execution", tags=["execution"])
app.include_router(chat.router, prefix="/api/chat", tags=["chat"])
app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
app.include_router(health.router, prefix="/api/health", tags=["health"])

@app.get("/api")
async def root():
    return {
        "name": "NetOps Autopilot REAL",
        "version": "2.0.0",
        "mode": "evidence-first",
        "principle": "لا تخمين، لا تجاهل، لا هلوسة — كل حقيقة لها دليل خام",
        "endpoints": ["/api/discovery", "/api/topology", "/api/plan", "/api/execution", "/api/chat", "/api/audit", "/api/health"]
    }

@app.get("/api/status")
async def status():
    return {
        "engine": "deterministic",
        "evidence_store": "hash-chained",
        "claim_verifier": "enforced",
        "allowlist": "read-only + staged-change",
        "gate": "نافذ — لا أمر تعديل قبل الموافقة الصريحة",
        "audit_entries": len(audit_log.entries)
    }

# Serve frontend build if exists
frontend_dist = os.path.join(os.path.dirname(__file__), "../../frontend/dist")
if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")
