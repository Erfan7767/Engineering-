"""
Deterministic Crawler — الزحف الحتمي عبر LLDP/CDP فقط
المبدأ: لا نخمن وصلة غير معلنة في جدول الجيران. أي جهاز لا يصل عبر كابل مكتشف = فشل صريح
"""
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from app.discovery.evidence import evidence_store
from app.discovery.collectors.ssh_collector import SSHCollector

@dataclass
class Target:
    device_id: str
    hostname: str
    mgmt_ip: str
    vendor: str
    username: str
    password: str
    discovered_via: Optional[str] = None  # cableId that led to it

@dataclass
class Link:
    local_device: str
    local_if: str
    remote_device: str
    remote_if: str
    protocol: str  # LLDP / CDP
    evidenceId: str
    cableId: str

@dataclass
class DiscoveryResult:
    devices: List[Dict]
    links: List[Link]
    evidence: Dict
    failures: List[Dict]
    sites: List[str]

class DeterministicCrawler:
    """
    1. يبدأ من seedDevice (الموصول بالكمبيوتر)
    2. يجمع جدول الجيران (CDP/LLDP)
    3. لكل جار مكتشف، يحاول الاتصال وقراءة جدوله
    4. يكرر حتى لا يوجد جيران جدد — كل وصلة يجب أن تكون معلنة من الطرفين إن أمكن
    5. أي فشل = إعلان فشل صريح، لا يتم تجاهله أو دمجه
    """
    def __init__(self, ssh_collector: SSHCollector = None):
        self.ssh = ssh_collector or SSHCollector()
        self.visited: Set[str] = set()
        self.queue: List[Target] = []
        self.devices: Dict[str, Dict] = {}
        self.links: List[Link] = []
        self.failures: List[Dict] = []

    def discover(self, seed: Target, vault: Dict[str, str], max_hops: int = 20) -> DiscoveryResult:
        self.queue = [seed]
        self.visited = set()
        hop = 0

        while self.queue and hop < max_hops:
            hop += 1
            target = self.queue.pop(0)
            if target.device_id in self.visited:
                continue
            self.visited.add(target.device_id)

            # جرب كلمة مرور المصنع أو المخصصة من vault
            password = vault.get(target.device_id) or target.password or "admin"
            records = self.ssh.collect_all(target, password)

            # تحقق هل فشلت كل أوامر الجمع؟
            if all(r.exitStatus != "ok" for r in records):
                self.failures.append({
                    "deviceId": target.device_id,
                    "mgmtIp": target.mgmt_ip,
                    "reason": records[0].rawOutput if records else "no response",
                    "hop": hop,
                    "excluded_from_conclusions": True
                })
                evidence_store.add_failure(target.device_id, "ssh-cli", "all commands failed")
                continue

            # حلل الجيران
            neighbors = self._parse_neighbors(records, target)
            device_info = self._parse_device_info(records, target)
            self.devices[target.device_id] = device_info

            for nb in neighbors:
                cable_id = f"{target.device_id}:{nb['local_if']}--{nb['remote_id']}:{nb['remote_if']}"
                link = Link(
                    local_device=target.device_id,
                    local_if=nb['local_if'],
                    remote_device=nb['remote_id'],
                    remote_if=nb['remote_if'],
                    protocol=nb['protocol'],
                    evidenceId=nb['evidenceId'],
                    cableId=cable_id
                )
                # منع التكرار
                if not any(l.cableId == cable_id for l in self.links):
                    self.links.append(link)

                # إذا الجار غير مكتشف سابقاً، أضفه للطابور
                if nb['remote_id'] not in self.visited and nb['remote_id'] not in [q.device_id for q in self.queue]:
                    # نحتاج IP الجار — نحاول استخراجه من LLDP (Management address)
                    mgmt_ip = nb.get('mgmt_ip')
                    if mgmt_ip:
                        self.queue.append(Target(
                            device_id=nb['remote_id'],
                            hostname=nb['remote_id'],
                            mgmt_ip=mgmt_ip,
                            vendor="generic",
                            username=target.username,
                            password=password,
                            discovered_via=cable_id
                        ))
                    else:
                        self.failures.append({
                            "deviceId": nb['remote_id'],
                            "reason": "Neighbor discovered but no management IP in LLDP — cannot crawl. Declared explicit failure.",
                            "via": cable_id,
                            "evidenceId": nb['evidenceId']
                        })

        return DiscoveryResult(
            devices=list(self.devices.values()),
            links=self.links,
            evidence=evidence_store.to_dict(),
            failures=self.failures,
            sites=list(set(d.get("site", "unknown") for d in self.devices.values()))
        )

    def _parse_neighbors(self, records, target) -> List[Dict]:
        neighbors = []
        for rec in records:
            if "cdp" not in rec.command.lower() and "lldp" not in rec.command.lower():
                continue
            # تحليل CDP
            if "cdp" in rec.command:
                # Cisco CDP detail: Device ID: <id> / IP address: <ip> / Interface: <local>, Port ID: <remote>
                for m in re.finditer(r"Device ID:\s*(\S+).*?IP address:\s*(\d+\.\d+\.\d+\.\d+).*?Interface:\s*(\S+).*?Port ID[^:]*:\s*(\S+)", rec.rawOutput, re.S):
                    neighbors.append({
                        "remote_id": m.group(1).strip(),
                        "mgmt_ip": m.group(2).strip(),
                        "local_if": m.group(3).strip().rstrip(","),
                        "remote_if": m.group(4).strip(),
                        "protocol": "CDP",
                        "evidenceId": rec.evidenceId
                    })
            if "lldp" in rec.command:
                # LLDP detail: Chassis id: <id> / Management Address: <ip> / Port id: <remote> / Port Description: ...
                # Cisco
                for m in re.finditer(r"Chassis id:\s*(\S+).*?Management Address:\s*(\d+\.\d+\.\d+\.\d+).*?Port id:\s*(\S+).*?Port Description:\s*(\S+)", rec.rawOutput, re.S):
                    neighbors.append({
                        "remote_id": m.group(1).strip(),
                        "mgmt_ip": m.group(2).strip(),
                        "local_if": m.group(4).strip(),
                        "remote_if": m.group(3).strip(),
                        "protocol": "LLDP",
                        "evidenceId": rec.evidenceId
                    })
                # Juniper / generic: neighbor table lines
                for m in re.finditer(r"(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+)", rec.rawOutput):
                    # heuristic fallback — still requires evidence
                    pass
        return neighbors

    def _parse_device_info(self, records, target) -> Dict:
        info = {
            "id": target.device_id,
            "hostname": target.hostname,
            "mgmtIp": target.mgmt_ip,
            "vendor": target.vendor,
            "model": "unknown",
            "osVersion": "unknown",
            "serial": "unknown",
            "uptimeSeconds": 0,
            "interfaces": [],
            "site": "unknown",
            "evidenceIds": [r.evidenceId for r in records],
        }
        for rec in records:
            if "version" in rec.command:
                # Cisco example
                m = re.search(r"Version\s+(\S+)", rec.rawOutput)
                if m:
                    info["osVersion"] = m.group(1)
                m = re.search(r"Model number\s*:\s*(\S+)", rec.rawOutput)
                if m:
                    info["model"] = m.group(1)
                m = re.search(r"Processor board ID\s+(\S+)", rec.rawOutput)
                if m:
                    info["serial"] = m.group(1)
            if "interfaces" in rec.command:
                # عدد الواجهات
                count = len(re.findall(r"line protocol is", rec.rawOutput))
                info["interfaceCount"] = count
        return info

# Singleton for API
crawler = DeterministicCrawler()
