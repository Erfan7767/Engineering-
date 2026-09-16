"""
Evidence Model — الحجر الأساس: لا حقيقة بدون دليل خام
Every fact must cite rawOutput + evidenceId + timestamp
"""
from pydantic import BaseModel, Field
from typing import Optional, Literal, List, Dict, Any
from datetime import datetime, timezone
import hashlib
import json

class EvidenceRecord(BaseModel):
    deviceId: str
    command: str
    method: Literal["ssh-cli", "snmp", "rest", "icmp"] = "ssh-cli"
    rawOutput: str  # غير معدل، كما طبعه الجهاز حرفياً
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    durationMs: int = 0
    exitStatus: Literal["ok", "error", "timeout", "auth-fail"] = "ok"
    parser: Optional[str] = None
    parsedFacts: Optional[Dict[str, Any]] = None
    evidenceId: str  # deviceId::command::hash
    sha256: Optional[str] = None

    def compute_hash(self):
        self.sha256 = hashlib.sha256(self.rawOutput.encode("utf-8")).hexdigest()
        return self.sha256

class EvidenceStore:
    """مخزن الأدلة — كل أدلة الخام + فهرسة + تتبع الفشل الصريح"""
    def __init__(self):
        self.records: Dict[str, EvidenceRecord] = {}
        self.failures: List[Dict] = []  # explicit failures — never suppressed

    def add(self, record: EvidenceRecord):
        record.compute_hash()
        self.records[record.evidenceId] = record
        return record

    def add_failure(self, deviceId: str, method: str, reason: str):
        self.failures.append({
            "deviceId": deviceId,
            "method": method,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "excluded_from_conclusions": True
        })

    def get(self, evidenceId: str) -> Optional[EvidenceRecord]:
        return self.records.get(evidenceId)

    def by_device(self, deviceId: str) -> List[EvidenceRecord]:
        return [r for r in self.records.values() if r.deviceId == deviceId]

    def all(self) -> List[EvidenceRecord]:
        return list(self.records.values())

    def to_dict(self):
        return {
            "records": {k: v.model_dump() for k,v in self.records.items()},
            "failures": self.failures
        }

evidence_store = EvidenceStore()
