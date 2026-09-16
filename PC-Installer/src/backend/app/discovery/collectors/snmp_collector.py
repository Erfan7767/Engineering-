"""
SNMP Collector — للتحقق من الأجهزة التي لا تسمح بـ SSH
"""
from app.discovery.evidence import EvidenceRecord, evidence_store
import hashlib
import time

class SNMPCollector:
    def collect(self, target, community: str = "public") -> EvidenceRecord:
        evidence_id = f"{target.device_id}::snmp::sysDescr"
        start = time.time()
        try:
            from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((target.mgmt_ip, 161), timeout=5, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
                ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysObjectID', 0)),
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            if errorIndication:
                raw = f"SNMP error: {errorIndication}"
                status = "error"
            elif errorStatus:
                raw = f"SNMP error: {errorStatus.prettyPrint()}"
                status = "error"
            else:
                raw = "\n".join([f"{x[0].prettyPrint()} = {x[1].prettyPrint()}" for x in varBinds])
                status = "ok"
            rec = EvidenceRecord(
                deviceId=target.device_id,
                command="snmp: sysDescr + sysObjectID",
                method="snmp",
                rawOutput=raw,
                durationMs=int((time.time()-start)*1000),
                exitStatus=status,
                evidenceId=evidence_id,
                parser="snmp"
            )
            evidence_store.add(rec)
            return rec
        except Exception as e:
            rec = EvidenceRecord(
                deviceId=target.device_id,
                command="snmp: sysDescr",
                method="snmp",
                rawOutput=f"SNMP failed: {e}",
                exitStatus="error",
                evidenceId=evidence_id,
            )
            evidence_store.add(rec)
            evidence_store.add_failure(target.device_id, "snmp", str(e))
            return rec
