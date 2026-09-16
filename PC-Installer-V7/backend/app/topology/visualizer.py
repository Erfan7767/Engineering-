"""
Visualizer — تصوير الشبكة — خريطة تفاعلية احترافية
V7 ULTRA MAX — يرسم أي شبكة صغيرة/متوسطة/كبيرة/معقدة — مع حالة كل وصلة
"""
from typing import Dict, List

class Visualizer:
    def build_vis_data(self, topology: Dict) -> Dict:
        nodes = []
        for n in topology.get("nodes", []):
            color = "#10b981" if n["status"]=="reachable" else "#ef4444" if n["status"]=="unreachable" else "#f59e0b"
            nodes.append({
                "id": n["id"],
                "label": f"{n['id']}\n{n['vendor']}",
                "title": f"{n['hostname']} — {n['mgmtIp']} — {n['model']}",
                "color": color,
                "shape": "box" if "CORE" in n["id"] else "ellipse",
                "evidence": n.get("evidenceIds", [])[:1]
            })
        edges = []
        for e in topology.get("edges", []):
            edges.append({
                "from": e["source"],
                "to": e["target"],
                "label": f"{e['sourceIf']} → {e['targetIf']}\n{e['protocol']}",
                "color": "#0ea5e9",
                "title": f"evidence: {e['evidenceId'][:30]}..."
            })
        return {"nodes": nodes, "edges": edges, "count": {"nodes": len(nodes), "edges": len(edges)}}

visualizer = Visualizer()
