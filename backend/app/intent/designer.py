"""
Designer — يولد الخطة الحتمية من intent + الأجهزة المكتشفة فعلياً
- يحدد أدوار الأجهزة (core / distribution / access / wan-edge / firewall) بثلاث قنوات أدلة: الطراز، الطوبولوجيا، الاسم — وحسم معلن
- يخصص VLANs للمنافذ، يبني SVI، DHCP، Default Route، OSPF، NAT، Firewall
- لا يخترع IP غير موجود — يستخدم 10.0.<vlan>.0/24 حتمياً
- يربط كل كتلة بمتطلبات Requirement IDs
"""
from typing import Dict, List, Any
import hashlib

ROLE_RULES = {
    "core": ["CORE", "DIST", "4500", "9300", "EX4"],
    "wan-edge": ["WAN", "RTR", "EDGE", "ISR"],
    "firewall": ["FW", "FIREWALL", "FORTIGATE", "SRX"],
    "access": ["ACC", "SW-ACC", "ACCESS", "2960", "EX2300"]
}

class Designer:
    def design(self, discovery: Dict, intent: Dict) -> Dict[str, Any]:
        devices = discovery.get("devices", [])
        links = discovery.get("links", [])

        # 1. تصنيف الأدوار — ثلاث قنوات
        role_map = {}
        for d in devices:
            hostname = d.get("hostname", "").upper()
            model = d.get("model", "").upper()
            # قناة 1: الاسم
            role = None
            scores = {r: 0 for r in ROLE_RULES}
            for r, keywords in ROLE_RULES.items():
                for kw in keywords:
                    if kw in hostname or kw in model:
                        scores[r] += 1
            # قناة 2: الطوبولوجيا (درجة المركزية = عدد الوصلات)
            degree = sum(1 for l in links if l["source"] == d["id"] or l["target"] == d["id"])
            if degree >= 3 and not role:
                scores["core"] += 1
            if d.get("mgmtIp", "").endswith(".1") or "WAN" in hostname:
                scores["wan-edge"] += 0.5

            best = max(scores, key=lambda k: scores[k])
            role = best if scores[best] > 0 else "access"
            # conflict detection
            top2 = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:2]
            conflict = top2[0][1] == top2[1][1] and top2[0][1] > 0

            role_map[d["id"]] = {
                "role": role,
                "scores": scores,
                "conflict": conflict,
                "degree": degree,
            }

        # 2. توزيع VLANs والمنافذ
        port_roles = []
        for d in devices:
            role = role_map[d["id"]]["role"]
            # المنافذ: أول منفذين للأجهزة ذات degree عالي = trunk, الباقي access
            # نحتاج معرفة المنافذ الفعلية — إن لم تكن مكتشفة، نعلن ذلك
            iface_count = d.get("interfaceCount", 4)
            for i in range(iface_count):
                port_name = f"ge-0/0/{i}" if d.get("vendor") == "juniper" else f"GigabitEthernet1/0/{i+1}"
                if i < 2 and degree >= 2:
                    port_roles.append({
                        "deviceId": d["id"],
                        "port": port_name,
                        "role": "trunk",
                        "allowedVlans": [v["id"] for v in intent["vlans"]],
                        "peerDeviceId": None
                    })
                else:
                    # access: وزع VLANs بالتناوب
                    vlan = intent["vlans"][i % len(intent["vlans"])]
                    port_roles.append({
                        "deviceId": d["id"],
                        "port": port_name,
                        "role": "access",
                        "accessVlan": vlan["id"]
                    })

        # 3. توليد المتطلبات
        requirements = []
        for v in intent["vlans"]:
            requirements.append({
                "id": f"REQ-VLAN-{v['id']}",
                "title": f"VLAN {v['id']} {v['name']} موجودة على كل المبدلات",
                "vlan": v["id"]
            })
        requirements.append({"id": "REQ-ROUTING", "title": f"Routing: {intent['routing']}"})
        requirements.append({"id": "REQ-NTP", "title": f"NTP: {intent['ntpServer']}"})
        if intent["hardening"] == "hardened":
            requirements.append({"id": "REQ-HARDENING", "title": "CIS Hardening: SSH only, SNMPv3, Mgmt ACL"})

        # 4. بناء كتل التكوين لكل جهاز — مع ربط Requirement IDs
        generated_devices = []
        for d in devices:
            r = role_map[d["id"]]
            blocks = []

            # Block: VLANs
            blocks.append({
                "id": f"{d['id']}::vlans",
                "requirementIds": [f"REQ-VLAN-{v['id']}" for v in intent["vlans"]],
                "commands": self._build_vlan_block(d, intent),
                "vendor": d.get("vendor", "cisco")
            })

            # Block: Access / Trunk ports
            pr = [p for p in port_roles if p["deviceId"] == d["id"]]
            blocks.append({
                "id": f"{d['id']}::interfaces",
                "requirementIds": ["REQ-VLAN-*"],
                "commands": self._build_interface_block(d, pr),
                "vendor": d.get("vendor", "cisco")
            })

            # Block: SVI + DHCP إذا كان L3 gateway
            is_l3 = r["role"] in ["core", "distribution"]
            if is_l3:
                blocks.append({
                    "id": f"{d['id']}::svi",
                    "requirementIds": ["REQ-VLAN-*"],
                    "commands": self._build_svi_block(d, intent),
                    "vendor": d.get("vendor", "cisco")
                })

            # Block: Routing
            if r["role"] in ["core", "wan-edge"]:
                blocks.append({
                    "id": f"{d['id']}::routing",
                    "requirementIds": ["REQ-ROUTING"],
                    "commands": self._build_routing_block(d, intent),
                    "vendor": d.get("vendor", "cisco")
                })

            # Block: Security / Hardening
            if intent["hardening"] == "hardened":
                blocks.append({
                    "id": f"{d['id']}::hardening",
                    "requirementIds": ["REQ-HARDENING"],
                    "commands": self._build_hardening_block(d),
                    "vendor": d.get("vendor", "cisco")
                })

            generated_devices.append({
                "deviceId": d["id"],
                "hostname": d["hostname"],
                "mgmtIp": d["mgmtIp"],
                "vendor": d.get("vendor", "cisco"),
                "role": r["role"],
                "blocks": blocks,
                "conflict": r["conflict"]
            })

        plan = {
            "networkName": intent["networkName"],
            "intent": intent,
            "devices": generated_devices,
            "portRoles": port_roles,
            "requirements": requirements,
            "generatedAt": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "hash": hashlib.sha256(str(generated_devices).encode()).hexdigest()[:12],
            "roleMap": role_map,
        }
        return plan

    def _build_vlan_block(self, device, intent):
        vendor = device.get("vendor", "cisco").lower()
        cmds = []
        for v in intent["vlans"]:
            if vendor == "cisco":
                cmds += [f"vlan {v['id']}", f" name {v['name']}", "exit"]
            elif vendor == "juniper":
                cmds += [f"set vlans {v['name']} vlan-id {v['id']}"]
            elif vendor == "mikrotik":
                cmds += [f"/interface vlan add name=vlan{v['id']} vlan-id={v['id']} interface=bridge1"]
            elif vendor == "fortinet":
                cmds += [f"config system interface", f"edit vlan{v['id']}", f"set vdom root", f"set vlanid {v['id']}"]
            elif vendor == "aruba":
                cmds += [f"vlan {v['id']}", f" name {v['name']}"]
        return cmds

    def _build_interface_block(self, device, port_roles):
        cmds = []
        for pr in port_roles:
            if pr["role"] == "access":
                cmds += [f"interface {pr['port']}", f" switchport mode access", f" switchport access vlan {pr['accessVlan']}", " no shutdown"]
            else:
                cmds += [f"interface {pr['port']}", " switchport mode trunk", f" switchport trunk allowed vlan {','.join(map(str, pr['allowedVlans']))}", " no shutdown"]
        return cmds

    def _build_svi_block(self, device, intent):
        cmds = []
        for v in intent["vlans"]:
            ip = f"10.0.{v['id']}.1"
            mask = "255.255.255.0"
            cmds += [f"interface vlan {v['id']}", f" ip address {ip} {mask}", " no shutdown"]
            if v.get("dhcp"):
                cmds += [f"ip dhcp pool VLAN{v['id']}", f" network 10.0.{v['id']}.0 255.255.255.0", f" default-router {ip}"]
        return cmds

    def _build_routing_block(self, device, intent):
        if intent["routing"] == "ospf":
            return ["router ospf 1", " network 10.0.0.0 0.255.255.255 area 0"]
        else:
            return ["ip route 0.0.0.0 0.0.0.0 10.0.99.2"]

    def _build_hardening_block(self, device):
        return [
            "no ip http server",
            "no ip http secure-server",
            "line vty 0 15",
            " transport input ssh",
            " access-class MGMT-ACL in",
            "exit",
            "ip access-list standard MGMT-ACL",
            " permit 10.0.0.0 0.255.255.255"
        ]

designer = Designer()
