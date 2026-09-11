"""Topology Anomaly Detector — the 30-year expert's "what's wrong with this map?".

A senior engineer takes one look at a topology and spots the
issues: a switch with only one uplink (single point of
failure), an asymmetric LACP bundle (3 ports on one side, 2
on the other), a triangle that creates a Layer-2 loop, a
broken link that nobody noticed.

This module turns that experience into a typed detector.
Every anomaly is a :class:`Anomaly` with a category,
severity, the affected devices, and the rationale.

Design contract:

* **Deterministic** — same topology always produces the same
  list of anomalies.
* **Typed** — every anomaly has an
  :class:`AnomalyCategory` and :class:`AnomalySeverity`.
* **Bilingual** — rendering in English or Arabic.
* **No hallucination** — every anomaly is backed by
  evidence in the topology. If we can't see it, we don't
  flag it.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum


class AnomalyCategory(str, Enum):
    __test__ = False

    SINGLE_POINT_OF_FAILURE = "SINGLE_POINT_OF_FAILURE"
    ASYMMETRIC_BUNDLE = "ASYMMETRIC_BUNDLE"
    L2_LOOP = "L2_LOOP"
    BROKEN_LINK = "BROKEN_LINK"
    ISLANDED_DEVICE = "ISLANDED_DEVICE"
    ASYMMETRIC_PATH = "ASYMMETRIC_PATH"
    FABRIC_OVERSUBSCRIPTION = "FABRIC_OVERSUBSCRIPTION"
    DUAL_HOMING_MISSING = "DUAL_HOMING_MISSING"


class AnomalySeverity(str, Enum):
    __test__ = False

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class Anomaly:
    __test__ = False

    category: AnomalyCategory
    severity: AnomalySeverity
    affected_devices: tuple[str, ...]
    title: str
    title_ar: str
    detail: str
    detail_ar: str

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"[{self.severity.value}] "
                f"{self.category.value} — {self.title_ar}\n"
                f"   {self.detail_ar}\n"
                f"   الأجهزة: {', '.join(self.affected_devices)}"
            )
        return (
            f"[{self.severity.value}] "
            f"{self.category.value} — {self.title}\n"
            f"   {self.detail}\n"
            f"   Affected: {', '.join(self.affected_devices)}"
        )


@dataclass
class AnomalyReport:
    __test__ = False

    anomalies: list[Anomaly] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(
            1 for a in self.anomalies
            if a.severity == AnomalySeverity.CRITICAL
        )

    @property
    def high_count(self) -> int:
        return sum(
            1 for a in self.anomalies
            if a.severity == AnomalySeverity.HIGH
        )

    @property
    def overall_verdict(self) -> str:
        if self.critical_count > 0:
            return "CRITICAL_FINDINGS"
        if self.high_count > 0:
            return "HIGH_RISK_FINDINGS"
        if self.anomalies:
            return "ADVISORY_FINDINGS"
        return "CLEAN"

    def render(self, lang: str = "en") -> str:
        if not self.anomalies:
            return (
                "Topology is clean — no anomalies."
                if lang == "en"
                else "الطوبولوجيا سليمة — لا توجد شذوذات."
            )
        order = [
            AnomalySeverity.CRITICAL,
            AnomalySeverity.HIGH,
            AnomalySeverity.MEDIUM,
            AnomalySeverity.LOW,
            AnomalySeverity.INFO,
        ]
        sorted_a = sorted(
            self.anomalies,
            key=lambda a: order.index(a.severity),
        )
        if lang == "ar":
            head = (
                f"نتائج فحص الطوبولوجيا: {self.overall_verdict}\n"
                f"  حرج: {self.critical_count}  عالي: {self.high_count}"
            )
        else:
            head = (
                f"Topology scan: {self.overall_verdict}\n"
                f"  Critical: {self.critical_count}  "
                f"High: {self.high_count}"
            )
        body = "\n".join(a.render(lang=lang) for a in sorted_a)
        return head + "\n\n" + body


def _build_adjacency(
    nodes: list,
    edges: list,
) -> tuple[dict[str, set[str]], dict[str, int]]:
    """Build an undirected adjacency map and per-node degree."""
    adj: dict[str, set[str]] = defaultdict(set)
    degree: dict[str, int] = {n.device_ref: 0 for n in nodes}
    for e in edges:
        if hasattr(e, "endpoint_a"):
            a = e.endpoint_a.device_ref
            b = e.endpoint_b.device_ref
        else:
            a = e.a_key
            b = e.b_key
        adj[a].add(b)
        adj[b].add(a)
        degree[a] = degree.get(a, 0) + 1
        degree[b] = degree.get(b, 0) + 1
    return adj, degree


def _find_loops(
    adj: dict[str, set[str]],
) -> list[tuple[str, str, str]]:
    """Find triangles (3-cycles). True loops in real networks
    usually show up as triangles when STP has placed a port
    in BLOCKING.
    """
    triangles: list[tuple[str, str, str]] = []
    nodes = sorted(adj.keys())
    for i, a in enumerate(nodes):
        for j, b in enumerate(nodes[i + 1:], start=i + 1):
            if b not in adj.get(a, set()):
                continue
            for c in nodes[j + 1:]:
                if c in adj.get(a, set()) and c in adj.get(b, set()):
                    triangles.append((a, b, c))
    return triangles


def _find_broken_links(
    edges: list,
    adjacency_grade: dict[tuple[str, str], str],
) -> list:
    """Find links whose FSM grade suggests they aren't really up."""
    broken: list = []
    for e in edges:
        if e.fsm4_state in ("STALE", "UNKNOWN", "ONE_SIDED"):
            broken.append(e)
    return broken


def _bundle_counts(
    edges: list,
) -> dict[tuple[str, str], int]:
    """Count parallel links between each pair of devices."""
    pairs: dict[tuple[str, str], int] = defaultdict(int)
    for e in edges:
        if hasattr(e, "endpoint_a"):
            a = e.endpoint_a.device_ref
            b = e.endpoint_b.device_ref
        else:
            a = e.a_key
            b = e.b_key
        key = tuple(sorted([a, b]))
        pairs[key] += 1
    return pairs


def detect_anomalies(
    topo,
) -> AnomalyReport:
    """Run every anomaly check against the topology.

    ``topo`` is duck-typed: it has ``.nodes`` (list of
    :class:`MapNode`) and ``.edges`` (list of :class:`MapEdge`).
    """
    rep = AnomalyReport()
    nodes = list(getattr(topo, "nodes", []) or [])
    edges = list(getattr(topo, "edges", []) or [])
    if not nodes:
        return rep

    adj, degree = _build_adjacency(nodes, edges)

    # 1. Single point of failure: device with only ONE link
    #    and no redundant path.
    for ref, d in degree.items():
        if d == 1:
            rep.anomalies.append(Anomaly(
                category=AnomalyCategory.SINGLE_POINT_OF_FAILURE,
                severity=AnomalySeverity.HIGH,
                affected_devices=(ref,),
                title=(
                    f"Single uplink — {ref} has only one link"
                ),
                title_ar=(
                    f"نقطة فشل وحيدة — {ref} له رابط واحد فقط"
                ),
                detail=(
                    f"{ref} has exactly one link in the topology. "
                    f"If that link fails, the device is islanded."
                ),
                detail_ar=(
                    f"{ref} له رابط واحد فقط. إن فشل، يصبح معزولاً."
                ),
            ))
    # 2. Islanded device: degree == 0
    for n in nodes:
        if degree.get(n.device_ref, 0) == 0:
            rep.anomalies.append(Anomaly(
                category=AnomalyCategory.ISLANDED_DEVICE,
                severity=AnomalySeverity.CRITICAL,
                affected_devices=(n.device_ref,),
                title=(
                    f"Islanded device — {n.device_ref}"
                ),
                title_ar=(
                    f"جهاز معزول — {n.device_ref}"
                ),
                detail=(
                    f"{n.device_ref} is discovered but has no "
                    f"links to any other device."
                ),
                detail_ar=(
                    f"{n.device_ref} مكتشف لكن لا يوجد روابط."
                ),
            ))
    # 3. L2 loops (triangles)
    for a, b, c in _find_loops(adj):
        rep.anomalies.append(Anomaly(
            category=AnomalyCategory.L2_LOOP,
            severity=AnomalySeverity.MEDIUM,
            affected_devices=(a, b, c),
            title=(
                f"L2 triangle between {a}, {b}, {c}"
            ),
            title_ar=(
                f"مثلث L2 بين {a}، {b}، {c}"
            ),
            detail=(
                "Three devices form a triangle. Spanning-tree "
                "should be blocking one of the legs — verify "
                "the blocked port matches the design."
            ),
            detail_ar=(
                "ثلاثة أجهزة تشكل مثلثاً. يجب أن يكون STP يحجب "
                "أحد الأضلاع. تحقق أن المنفذ المحظور يطابق التصميم."
            ),
        ))
    # 4. Asymmetric bundle — same pair, but a different number
    #    of links each direction (we only have undirected counts,
    #    so flag pairs with >2 links as advisory).
    pairs = _bundle_counts(edges)
    for (a, b), n in pairs.items():
        if n >= 3:
            rep.anomalies.append(Anomaly(
                category=AnomalyCategory.ASYMMETRIC_BUNDLE,
                severity=AnomalySeverity.LOW,
                affected_devices=(a, b),
                title=(
                    f"Dense bundle: {n} links between {a} and {b}"
                ),
                title_ar=(
                    f"حزمة كثيفة: {n} روابط بين {a} و {b}"
                ),
                detail=(
                    f"{n} parallel links between the same two "
                    f"devices — verify they form a single LACP "
                    f"bundle, not two separate ones."
                ),
                detail_ar=(
                    f"{n} روابط متوازية بين نفس الجهازين — "
                    f"تأكد أنها تشكل حزمة LACP واحدة."
                ),
            ))
    # 5. Broken / stale links
    for e in edges:
        state = (
            e.fsm4_state if hasattr(e, "fsm4_state")
            else (e.state if hasattr(e, "state") else "UNKNOWN")
        )
        if state in ("STALE", "UNKNOWN"):
            if hasattr(e, "endpoint_a"):
                a = e.endpoint_a.device_ref
                b = e.endpoint_b.device_ref
            else:
                a = e.a_key
                b = e.b_key
            rep.anomalies.append(Anomaly(
                category=AnomalyCategory.BROKEN_LINK,
                severity=AnomalySeverity.MEDIUM,
                affected_devices=(a, b),
                title=(f"Link evidence is {state}"),
                title_ar=(f"إثبات الرابط {state}"),
                detail=(
                    f"Link from {a} to {b} has "
                    f"{state} evidence."
                ),
                detail_ar=(
                    f"الرابط من {a} إلى {b} "
                    f"حالة {state}."
                ),
            ))
    return rep
