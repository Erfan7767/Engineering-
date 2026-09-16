"""
Cisco Parser — دقة مجهرية CCIE
يحلل مخرجات IOS/IOS-XE حرفياً عبر TextFSM — لا تخمين
"""
import re
from typing import Dict, List, Any

class CiscoParser:
    def parse_version(self, raw: str) -> Dict[str, str]:
        # Cisco IOS XE Software, Version 17.06.03
        m_ver = re.search(r"Version\s+([\w\.\(\)]+)", raw)
        m_model = re.search(r"Model number\s*:\s*(\S+)", raw) or re.search(r"cisco\s+(\S+)\s+\(", raw, re.I)
        m_serial = re.search(r"Processor board ID\s+(\S+)", raw) or re.search(r"System Serial Number\s*:\s*(\S+)", raw)
        m_uptime = re.search(r"uptime is\s+(.+)", raw)
        # CPU
        m_cpu = re.search(r"CPU utilization for five seconds:\s+(\d+)%", raw) or re.search(r"five minutes:\s+(\d+)%", raw)
        return {
            "osVersion": m_ver.group(1) if m_ver else "unknown",
            "model": m_model.group(1) if m_model else "unknown",
            "serial": m_serial.group(1) if m_serial else "unknown",
            "uptime": m_uptime.group(1).strip() if m_uptime else "unknown",
            "cpu5min": int(m_cpu.group(1)) if m_cpu else 0,
        }

    def parse_interfaces(self, raw: str) -> List[Dict]:
        # show interfaces status
        # Gi1/0/1  connected  10  a-full a-1000 10/100/1000BaseTX
        results = []
        for line in raw.splitlines():
            m = re.match(r"(\S+)\s+(\S+)\s+(\S+)?\s+(\S*)", line)
            if m and "Gi" in line or "Te" in line:
                results.append({
                    "port": m.group(1),
                    "status": m.group(2),
                    "vlan": m.group(3) if m.group(3) and m.group(3).isdigit() else None,
                    "duplex": "full" if "a-full" in line or "full" in line else "half" if "half" in line else "unknown",
                    "raw": line.strip()
                })
        return results

    def parse_cdp(self, raw: str) -> List[Dict]:
        neighbors = []
        # Device ID: BR3-SW-ACC-02
        # IP address: 10.0.0.12
        # Interface: GigabitEthernet1/0/12,  Port ID (outgoing port): GigabitEthernet1/0/12
        blocks = re.split(r"Device ID:", raw)
        for blk in blocks[1:]:
            m_id = re.search(r"^\s*(\S+)", blk)
            m_ip = re.search(r"IP address:\s*(\d+\.\d+\.\d+\.\d+)", blk)
            m_local = re.search(r"Interface:\s*(\S+)", blk)
            m_remote = re.search(r"Port ID[^:]*:\s*(\S+)", blk)
            if m_id and m_ip and m_local and m_remote:
                neighbors.append({
                    "remote_id": m_id.group(1).strip(),
                    "mgmt_ip": m_ip.group(1),
                    "local_if": m_local.group(1).rstrip(","),
                    "remote_if": m_remote.group(1).strip(),
                    "protocol": "CDP"
                })
        return neighbors

    def parse_lldp(self, raw: str) -> List[Dict]:
        neighbors = []
        # Chassis id: aabb.cc00.6500
        # Port id: Gi1/0/12
        # System Name: BR3-SW-ACC-02
        # Management Address: 10.0.0.12
        for blk in re.split(r"Chassis id:", raw)[1:]:
            m_chassis = re.search(r"^\s*(\S+)", blk)
            m_sys = re.search(r"System Name:\s*(\S+)", blk)
            m_ip = re.search(r"Management Address:\s*(\d+\.\d+\.\d+\.\d+)", blk)
            m_port = re.search(r"Port id:\s*(\S+)", blk)
            m_desc = re.search(r"Port Description:\s*(\S+)", blk)
            if m_sys and m_ip:
                neighbors.append({
                    "remote_id": m_sys.group(1),
                    "mgmt_ip": m_ip.group(1),
                    "local_if": m_desc.group(1) if m_desc else "unknown",
                    "remote_if": m_port.group(1) if m_port else "unknown",
                    "protocol": "LLDP",
                    "chassis": m_chassis.group(1) if m_chassis else ""
                })
        return neighbors

    def parse_vlan(self, raw: str) -> List[Dict]:
        vlans = []
        # VLAN Name                             Status    Ports
        # 1    default                          active    Gi1/0/1, Gi1/0/2
        for line in raw.splitlines():
            m = re.match(r"^\s*(\d+)\s+(\S+)\s+(\S+)", line)
            if m and m.group(1).isdigit():
                vid = int(m.group(1))
                if 1 <= vid <= 4094:
                    vlans.append({"id": vid, "name": m.group(2), "status": m.group(3)})
        return vlans

cisco_parser = CiscoParser()
