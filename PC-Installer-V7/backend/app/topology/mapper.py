"""
Topology Mapper — يبني الخريطة الشبكية الفعلية والمنطقية من الأدلة فقط
لا يخمن وصلة غير معلنة
"""
from typing import Dict, List, Any
from app.discovery.crawler import DiscoveryResult

class TopologyMapper:
    def build(self, result: DiscoveryResult) -> Dict[str, Any]:
        nodes = []
        for d in result.devices:
            nodes.append({
                "id": d["id"],
                "hostname": d["hostname"],
                "mgmtIp": d["mgmtIp"],
                "vendor": d["vendor"],
                "model": d.get("model", "unknown"),
                "status": "reachable" if d["id"] not in [f["deviceId"] for f in result.failures] else "unreachable",
                "evidenceIds": d.get("evidenceIds", []),
                "site": d.get("site", "unknown"),
                "interfaceCount": d.get("interfaceCount", 0),
            })

        edges = []
        for l in result.links:
            edges.append({
                "id": l.cableId,
                "source": l.local_device,
                "target": l.remote_device,
                "sourceIf": l.local_if,
                "targetIf": l.remote_if,
                "protocol": l.protocol,
                "evidenceId": l.evidenceId,
                "status": "up",
            })

        # حساب المواقع المنطقية: كل جهاز بدون site يُستدل عليه من LLDP site-id إن وجد، وإلا unknown — لا نخمن
        sites = {}
        for n in nodes:
            sites.setdefault(n["site"], []).append(n["id"])

        # اكتشاف الحلقات (loops) — تحذير فقط، لا يصحح تلقائياً
        loops = self._detect_loops(nodes, edges)

        return {
            "nodes": nodes,
            "edges": edges,
            "sites": sites,
            "metrics": {
                "deviceCount": len(nodes),
                "linkCount": len(edges),
                "failureCount": len(result.failures),
                "loops": loops,
            },
            "generatedAt": result.evidence.get("records", {}).get(next(iter(result.evidence.get("records", {})), ""), {}).get("timestamp") if result.evidence.get("records") else None,
            "evidenceBased": True,
            "failures": result.failures,
        }

    def _detect_loops(self, nodes, edges):
        # DFS بسيط لكشف الحلقة
        adj = {n["id"]: [] for n in nodes}
        for e in edges:
            adj[e["source"]].append(e["target"])
            adj[e["target"]].append(e["source"])
        visited = set()
        stack = set()
        loops = []

        def dfs(v, parent):
            visited.add(v)
            stack.add(v)
            for nb in adj.get(v, []):
                if nb not in visited:
                    if dfs(nb, v):
                        return True
                elif nb != parent and nb in stack:
                    loops.append(f"Loop: {v} -- {nb}")
            stack.remove(v)
            return False

        for n in nodes:
            if n["id"] not in visited:
                dfs(n["id"], None)
        return loops

mapper = TopologyMapper()
