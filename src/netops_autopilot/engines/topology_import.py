"""Topology Importer — EVE-NG / GNS3 / NetBox import.

A 30-year engineer uses lab tools (EVE-NG, GNS3, CML) and
inventory systems (NetBox) to manage topology. This module
is the typed implementation: parse an EVE-NG topology YAML
or a NetBox JSON export and surface a typed
:class:`ImportedTopology` with nodes + edges.

Design contract:

* **Typed** — :class:`ImportedNode` /
  :class:`ImportedEdge` are frozen dataclasses.
* **Deterministic** — same input → same topology.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ImportedNode:
    __test__ = False

    name: str
    kind: str        # router / switch / firewall / server
    image: str = ""  # EVE-NG image (e.g. "vios")
    mgmt_ip: str = ""
    platform: str = ""


@dataclass(frozen=True)
class ImportedEdge:
    __test__ = False

    a: str
    b: str
    label: str = ""


@dataclass
class ImportedTopology:
    __test__ = False

    name: str
    nodes: list[ImportedNode] = field(default_factory=list)
    edges: list[ImportedEdge] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"{self.name}: {self.node_count} عقدة، "
                f"{self.edge_count} رابط"
            )
        return (
            f"{self.name}: {self.node_count} node(s), "
            f"{self.edge_count} edge(s)"
        )


def parse_eve_ng_yaml(
    text: str,
) -> ImportedTopology:
    """Parse an EVE-NG topology YAML into typed records.

    We support the lightweight subset used in ``.unl`` /
    topology exports:
    ``name: <x>`` plus lines starting with ``- name:`` /
    ``- type:`` / ``- image:`` for nodes, and
    ``connections:`` / ``- <a>: <b>`` for edges.

    If real YAML isn't available, we fall back to a strict
    line-by-line parser to keep this engine dependency-free.
    """
    topo = ImportedTopology(name="imported")
    if not text or not text.strip():
        return topo
    lines = text.splitlines()
    name = "imported"
    nodes: list[ImportedNode] = []
    edges: list[ImportedEdge] = []
    cur: dict[str, str] = {}
    section: str = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.startswith("name:"):
            name = stripped.split(":", 1)[1].strip().strip('"')
            continue
        if stripped.startswith("nodes:"):
            section = "nodes"
            continue
        if stripped.startswith("connections:"):
            section = "connections"
            if cur:
                nodes.append(_node_from_dict(cur))
                cur = {}
            continue
        if section == "nodes":
            if stripped.startswith("- "):
                if cur:
                    nodes.append(_node_from_dict(cur))
                kv = stripped[2:]
                if ":" in kv:
                    k, v = kv.split(":", 1)
                    cur = {k.strip(): v.strip().strip('"')}
            elif ":" in stripped and cur:
                k, v = stripped.split(":", 1)
                cur[k.strip()] = v.strip().strip('"')
        elif section == "connections":
            if ":" in stripped:
                a, b = stripped.split(":", 1)
                edges.append(ImportedEdge(
                    a=a.strip(),
                    b=b.strip(),
                ))
    if cur:
        nodes.append(_node_from_dict(cur))
    topo = ImportedTopology(
        name=name,
        nodes=nodes,
        edges=edges,
    )
    return topo


def _node_from_dict(d: dict[str, str]) -> ImportedNode:
    return ImportedNode(
        name=d.get("name", "unknown"),
        kind=d.get("type", d.get("kind", "router")),
        image=d.get("image", ""),
        mgmt_ip=d.get("mgmt_ip", d.get("ip", "")),
        platform=d.get("platform", ""),
    )


def parse_netbox_json(text: str) -> ImportedTopology:
    """Parse a NetBox devices export into a typed topology."""
    topo = ImportedTopology(name="netbox")
    if not text or not text.strip():
        return topo
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return topo
    nodes: list[ImportedNode] = []
    edges: list[ImportedEdge] = []
    if not isinstance(data, dict):
        return topo
    name = (
        data.get("name")
        or data.get("site", {}).get("name", "netbox")
    )
    devices = data.get("devices", [])
    for d in devices:
        if not isinstance(d, dict):
            continue
        nodes.append(ImportedNode(
            name=str(d.get("name", "unknown")),
            kind=str(d.get("device_type", "router")),
            mgmt_ip=str(d.get("primary_ip", "")),
        ))
    interfaces = data.get("interfaces", [])
    # Pair interfaces on the same device with their
    # connected ones (NetBox stores ``cable`` peer).
    for i in interfaces:
        if not isinstance(i, dict):
            continue
        a = i.get("device")
        peer = i.get("cable", {}).get("peer_device")
        if a and peer:
            edges.append(ImportedEdge(
                a=str(a),
                b=str(peer),
                label=str(i.get("name", "")),
            ))
    return ImportedTopology(
        name=str(name),
        nodes=nodes,
        edges=edges,
    )
