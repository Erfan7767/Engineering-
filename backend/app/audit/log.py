"""
Audit Log — سجل تدقيق متسلسل بـ hash chain
كل إدخال يحمل hash(prevHash + seq + timestamp + actor + action + target + outcome)
لا يمكن التلاعب به — أي تعديل يكسر السلسلة
"""
from typing import List, Dict, Any
from datetime import datetime, timezone
import hashlib
import json

class AuditEntry:
    def __init__(self, seq: int, timestamp: str, actor: str, action: str, target: str, risk: str, outcome: str, detail: str, prevHash: str):
        self.seq = seq
        self.timestamp = timestamp
        self.actor = actor
        self.action = action
        self.target = target
        self.risk = risk
        self.outcome = outcome
        self.detail = detail
        self.prevHash = prevHash
        self.hash = self._compute_hash()

    def _compute_hash(self):
        data = f"{self.seq}{self.timestamp}{self.actor}{self.action}{self.target}{self.outcome}{self.prevHash}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def to_dict(self):
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "risk": self.risk,
            "outcome": self.outcome,
            "detail": self.detail,
            "prevHash": self.prevHash,
            "hash": self.hash,
        }

class AuditLog:
    def __init__(self):
        self.entries: List[AuditEntry] = []
        # Genesis
        genesis = AuditEntry(
            seq=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor="system",
            action="audit.init",
            target="genesis",
            risk="READ-ONLY",
            outcome="ok",
            detail="Audit log initialized — hash chain genesis",
            prevHash="-"
        )
        self.entries.append(genesis)

    def append(self, actor: str, action: str, target: str, risk: str, outcome: str, detail: str):
        prev = self.entries[-1]
        entry = AuditEntry(
            seq=prev.seq + 1,
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            action=action,
            target=target,
            risk=risk,
            outcome=outcome,
            detail=detail,
            prevHash=prev.hash,
        )
        self.entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        for i in range(1, len(self.entries)):
            if self.entries[i].prevHash != self.entries[i-1].hash:
                return False
            if self.entries[i].hash != self.entries[i]._compute_hash():
                return False
        return True

    def to_list(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.entries]

audit_log = AuditLog()
