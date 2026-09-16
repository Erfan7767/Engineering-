"""
SSH Collector — الجمع الحتمي عبر SSH/CLI
Supports: Cisco IOS/XE, Juniper Junos, MikroTik RouterOS, Fortinet FortiOS, Aruba CX
"""
import time
import hashlib
from typing import Dict, List, Optional
from datetime import datetime, timezone
from app.discovery.evidence import EvidenceRecord, evidence_store

# أوامر القراءة فقط — القائمة البيضاء الصارمة
ALLOWLIST_COMMANDS = {
    "cisco": [
        "show version",
        "show inventory",
        "show interfaces",
        "show interfaces status",
        "show ip interface brief",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
        "show running-config",
        "show vlan brief",
        "show ip route",
        "show processes cpu sorted | include CPU",
        "show interfaces counters errors",
    ],
    "juniper": [
        "show version",
        "show chassis hardware",
        "show interfaces terse",
        "show lldp neighbors",
        "show configuration | display set",
        "show vlans",
        "show route summary",
    ],
    "mikrotik": [
        "/system resource print",
        "/interface print detail",
        "/ip neighbor print detail",
        "/export terse",
        "/interface monitor-traffic once",
    ],
    "fortinet": [
        "get system status",
        "get hardware status",
        "diagnose netlink interface list",
        "get system interface",
        "show full-configuration",
    ],
    "aruba": [
        "show version",
        "show system",
        "show interface brief",
        "show lldp neighbors detail",
        "show running-config",
    ],
    "generic": [
        "show version",
        "show interfaces",
        "show lldp neighbors detail",
    ]
}

COMMAND_NOT_ALLOWED = "Command not in allowlist — rejected before execution"


class SSHCollector:
    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def collect(self, target, command: str, password: str = None) -> EvidenceRecord:
        """جمع دليل واحد — كل تنفيذ يسجل rawOutput + evidenceId"""
        import paramiko
        evidence_id = f"{target.device_id}::{self._sanitize(command)}::{hashlib.sha256(command.encode()).hexdigest()[:8]}"

        if not self._is_allowed(target.vendor, command):
            rec = EvidenceRecord(
                deviceId=target.device_id,
                command=command,
                method="ssh-cli",
                rawOutput=COMMAND_NOT_ALLOWED,
                exitStatus="error",
                evidenceId=evidence_id,
                parser=None,
            )
            evidence_store.add(rec)
            evidence_store.add_failure(target.device_id, "ssh-cli", COMMAND_NOT_ALLOWED)
            return rec

        start = time.time()
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=target.mgmt_ip,
                username=target.username,
                password=password or target.password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            stdin, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            raw = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            exit_status = "ok" if not err else "error"
            raw_output = raw if raw else err
            duration = int((time.time() - start) * 1000)
            client.close()

            rec = EvidenceRecord(
                deviceId=target.device_id,
                command=command,
                method="ssh-cli",
                rawOutput=raw_output,
                durationMs=duration,
                exitStatus=exit_status,
                evidenceId=evidence_id,
            )
            evidence_store.add(rec)
            return rec

        except Exception as e:
            rec = EvidenceRecord(
                deviceId=target.device_id,
                command=command,
                method="ssh-cli",
                rawOutput=f"SSH failed: {str(e)}",
                durationMs=int((time.time() - start) * 1000),
                exitStatus="timeout" if "timed out" in str(e).lower() else "error",
                evidenceId=evidence_id,
            )
            evidence_store.add(rec)
            evidence_store.add_failure(target.device_id, "ssh-cli", str(e))
            return rec

    def collect_all(self, target, password: str = None) -> List[EvidenceRecord]:
        vendor = (target.vendor or "generic").lower()
        commands = ALLOWLIST_COMMANDS.get(vendor, ALLOWLIST_COMMANDS["generic"])
        results = []
        for cmd in commands:
            results.append(self.collect(target, cmd, password))
        return results

    def _is_allowed(self, vendor: str, command: str) -> bool:
        vendor = (vendor or "generic").lower()
        allow = ALLOWLIST_COMMANDS.get(vendor, ALLOWLIST_COMMANDS["generic"])
        # تطابق دقيق أو بادئة
        return any(command.strip() == a or command.strip().startswith(a) for a in allow)

    def _sanitize(self, cmd: str) -> str:
        return cmd.replace(" ", "_").replace("/", "_")[:40]
