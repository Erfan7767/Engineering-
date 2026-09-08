"""E10 Validation Fabric — the nine-stage deterministic pipeline (§12).

Order is fixed: SCHEMA → VENDOR_LINT → SEMANTIC → DEPENDENCY → IPAM →
POLICY → ENTITY_GUARD → CAPABILITY → PREFLIGHT.

Verdict algebra:
* any stage FAIL  ⇒ overall FAIL
* any stage BLOCKED (and none FAIL) ⇒ overall BLOCKED
* otherwise ⇒ overall PASS — with preflight status recorded; NOT_MODELED is
  never rewritten into PASS (L13); it feeds gate escalation downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Mapping, Optional

from ..core.failures import Failure, FailureClass
from ..engines.capability import CapabilityEngine, CapabilityValue
from ..twin.twin import DigitalTwin
from . import ipam
from .config_ir import MGMT_FEATURES, ConfigIR, IRNode, Operation, Reversibility

STAGES = (
    "SCHEMA", "VENDOR_LINT", "SEMANTIC", "DEPENDENCY", "IPAM",
    "POLICY", "ENTITY_GUARD", "CAPABILITY", "PREFLIGHT",
)


class StageStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    NOT_MODELED = "NOT_MODELED"


class Severity(str, Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class FabricVerdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class Finding:
    stage: str
    code: str
    severity: Severity
    message: str


@dataclass(frozen=True)
class StageResult:
    stage: str
    status: StageStatus
    findings: tuple[Finding, ...] = ()


@dataclass(frozen=True)
class PolicyContext:
    """Autonomy policy facts relevant to validation (signed policy fields)."""

    allowed_gate_classes: frozenset[str]


@dataclass(frozen=True)
class PreflightStatus:
    state: str  # SUPPORTED_AND_MODELED | PARTIALLY_MODELED | NOT_MODELED | PARSE_FAILED | MODEL_INCOMPLETE
    notes: str = ""


#: Preflight adapter signature: ir → PreflightStatus. Absent ⇒ NOT_MODELED.
PreflightFn = Callable[[ConfigIR], PreflightStatus]


def _stage(stage: str, findings: list[Finding]) -> StageResult:
    """BLOCKED ('cannot judge') outranks FAIL ('judged and rejected'): a
    stage that cannot evaluate is never reported as having judged."""
    blocked = [f for f in findings if f.code.startswith("BLOCKED")]
    if blocked:
        return StageResult(stage, StageStatus.BLOCKED, tuple(findings))
    errors = [f for f in findings if f.severity is Severity.ERROR]
    if errors:
        return StageResult(stage, StageStatus.FAIL, tuple(findings))
    return StageResult(stage, StageStatus.PASS, tuple(findings))


class ValidationFabric:
    def __init__(self, capability: CapabilityEngine, twin: DigitalTwin,
                 preflight: Optional[PreflightFn] = None) -> None:
        self._capability = capability
        self._twin = twin
        self._preflight = preflight

    # ------------------------------------------------------------------ run
    def run(self, ir: ConfigIR, *, policy: Optional[PolicyContext],
            device_versions: Mapping[str, str],
            external_provides: frozenset[str] = frozenset()) -> "FabricResult":
        results: list[StageResult] = []
        results.append(self._schema(ir))
        results.append(self._vendor_lint(ir))
        results.append(self._semantic(ir))
        results.append(self._dependency(ir, external_provides))
        results.append(self._ipam(ir))
        results.append(self._policy(ir, policy))
        results.append(self._entity_guard(ir))
        results.append(self._capability_stage(ir, device_versions))
        results.append(self._preflight_stage(ir))

        statuses = [r.status for r in results]
        if StageStatus.FAIL in statuses:
            verdict = FabricVerdict.FAIL
        elif StageStatus.BLOCKED in statuses:
            verdict = FabricVerdict.BLOCKED
        else:
            verdict = FabricVerdict.PASS
        preflight = next(r for r in results if r.stage == "PREFLIGHT")
        return FabricResult(ir_id=ir.ir_id, verdict=verdict, stage_results=tuple(results),
                            gate_class=ir.gate_class(), preflight_status=preflight.status)

    # --------------------------------------------------------------- stages
    def _schema(self, ir: ConfigIR) -> StageResult:
        findings: list[Finding] = []
        for node in ir.nodes:
            for problem in node.is_well_formed():
                findings.append(Finding("SCHEMA", "SCHEMA_VIOLATION", Severity.ERROR,
                                        f"{node.node_id}: {problem}"))
        return _stage("SCHEMA", findings)

    def _vendor_lint(self, ir: ConfigIR) -> StageResult:
        findings: list[Finding] = []
        for node in ir.nodes:
            if self._capability.platform_entry(node.vendor_os) is None:
                findings.append(Finding("VENDOR_LINT", "UNKNOWN_VENDOR_OS", Severity.ERROR,
                                        f"{node.node_id}: vendor_os {node.vendor_os!r} not registered"))
                continue
            if node.feature not in self._capability.features_of(node.vendor_os):
                findings.append(Finding("VENDOR_LINT", "UNKNOWN_FEATURE_FOR_FAMILY", Severity.ERROR,
                                        f"{node.node_id}: feature {node.feature!r} not registered for {node.vendor_os}"))
        return _stage("VENDOR_LINT", findings)

    def _semantic(self, ir: ConfigIR) -> StageResult:
        findings: list[Finding] = []
        for node in ir.nodes:
            vlan_id = node.parameters.get("vlan_id")
            if vlan_id is not None and not (isinstance(vlan_id, int) and 1 <= vlan_id <= 4094):
                findings.append(Finding("SEMANTIC", "INVALID_VLAN_ID", Severity.ERROR,
                                        f"{node.node_id}: vlan_id={vlan_id!r} outside 1..4094"))
            if node.operation is Operation.DELETE and not (node.depends_on or node.requires):
                findings.append(Finding("SEMANTIC", "DELETE_WITHOUT_EXISTENCE_EVIDENCE", Severity.WARNING,
                                        f"{node.node_id}: DELETE without depends_on/requires — existence must be evidenced"))
            if node.feature in MGMT_FEATURES and not node.touches_management_plane:
                findings.append(Finding("SEMANTIC", "MGMT_FEATURE_NOT_FLAGGED", Severity.ERROR,
                                        f"{node.node_id}: feature {node.feature!r} is management-plane; flag required (L15)"))
        return _stage("SEMANTIC", findings)

    def _dependency(self, ir: ConfigIR, external_provides: frozenset[str]) -> StageResult:
        findings: list[Finding] = []
        providers: dict[str, list[str]] = {}
        for node in ir.nodes:
            for token in node.provides:
                providers.setdefault(token, []).append(node.node_id)
        for token, owners in sorted(providers.items()):
            if len(owners) > 1:
                findings.append(Finding("DEPENDENCY", "DUPLICATE_PROVIDES", Severity.ERROR,
                                        f"token {token!r} provided by {owners}"))
        node_ids = {n.node_id for n in ir.nodes}
        for node in ir.nodes:
            for token in node.requires:
                if token not in providers and token not in external_provides:
                    findings.append(Finding("DEPENDENCY", "UNSATISFIED_REQUIRES", Severity.ERROR,
                                            f"{node.node_id} requires {token!r} but nothing provides it"))
            for dep in node.depends_on:
                if dep not in node_ids:
                    findings.append(Finding("DEPENDENCY", "UNKNOWN_DEPENDS_ON", Severity.ERROR,
                                            f"{node.node_id} depends_on unknown node {dep!r}"))
        # Cycle detection over depends_on + requires→provider edges.
        edges: dict[str, set[str]] = {n.node_id: set(n.depends_on) for n in ir.nodes}
        token_owner = {token: owners[0] for token, owners in providers.items() if len(owners) == 1}
        for node in ir.nodes:
            for token in node.requires:
                owner = token_owner.get(token)
                if owner and owner != node.node_id:
                    edges[node.node_id].add(owner)
        if _has_cycle(edges):
            findings.append(Finding("DEPENDENCY", "DEPENDENCY_CYCLE", Severity.ERROR,
                                    "requires/provides/depends_on graph contains a cycle"))
        return _stage("DEPENDENCY", findings)

    def _ipam(self, ir: ConfigIR) -> StageResult:
        findings: list[Finding] = []
        cidrs: list[str] = []
        for node in ir.nodes:
            subnet = node.parameters.get("subnet") or node.parameters.get("network") or node.parameters.get("cidr")
            gateway = node.parameters.get("gateway")
            if subnet is None:
                continue
            cidrs.append(str(subnet))
            try:
                if gateway is not None:
                    ipam.gateway_address(str(subnet))  # validates subnet sanity
                    net = ipam.parse_network(str(subnet))
                    import ipaddress as _ip
                    if _ip.ip_address(str(gateway)) not in net:
                        findings.append(Finding("IPAM", "ADDRESS_OUTSIDE_SUBNET", Severity.ERROR,
                                                f"{node.node_id}: gateway {gateway} outside {subnet}"))
            except Failure as exc:
                findings.append(Finding("IPAM", exc.causes[0].split(":")[0], Severity.ERROR,
                                        f"{node.node_id}: {exc.causes[0]}"))
        try:
            overlaps = ipam.find_overlaps(cidrs)
            for a, b in overlaps:
                findings.append(Finding("IPAM", "IPAM_OVERLAP", Severity.ERROR, f"{a} overlaps {b}"))
        except Failure as exc:
            findings.append(Finding("IPAM", "INVALID_CIDR", Severity.ERROR, exc.causes[0]))
        return _stage("IPAM", findings)

    def _policy(self, ir: ConfigIR, policy: Optional[PolicyContext]) -> StageResult:
        if policy is None:
            return StageResult("POLICY", StageStatus.BLOCKED, (
                Finding("POLICY", "BLOCKED_POLICY_CONTEXT_REQUIRED", Severity.ERROR,
                        "no signed-policy context supplied; validation cannot judge authority (T3)"),
            ))
        findings: list[Finding] = []
        gate = ir.gate_class()
        if gate not in policy.allowed_gate_classes and gate in {"LOW_RISK", "HIGH_RISK"}:
            findings.append(Finding("POLICY", "POLICY_GATE_NOT_ALLOWED", Severity.ERROR,
                                    f"gate class {gate} not in policy allow-set {sorted(policy.allowed_gate_classes)}"))
        if gate in {"IRREVERSIBLE", "DESTRUCTIVE"}:
            findings.append(Finding("POLICY", "HUMAN_GATE_REQUIRED", Severity.WARNING,
                                    f"gate class {gate} is human-only in every mode (L06); Autonomy Authority will enforce"))
        return _stage("POLICY", findings)

    def _entity_guard(self, ir: ConfigIR) -> StageResult:
        findings: list[Finding] = []
        for node in ir.nodes:
            if not self._twin.exists(node.target.entity_type, node.target.entity_ref):
                findings.append(Finding("ENTITY_GUARD", "ENTITY_NOT_IN_INVENTORY", Severity.ERROR,
                                        f"{node.node_id}: {node.target.entity_type}:{node.target.entity_ref} not in Twin (§5/L02)"))
        return _stage("ENTITY_GUARD", findings)

    def _capability_stage(self, ir: ConfigIR, device_versions: Mapping[str, str]) -> StageResult:
        findings: list[Finding] = []
        for node in ir.nodes:
            version = device_versions.get(node.target.entity_ref)
            if version is None:
                findings.append(Finding("CAPABILITY", "BLOCKED_DEVICE_VERSION_UNKNOWN", Severity.ERROR,
                                        f"{node.node_id}: no version evidence for {node.target.entity_ref} (FSM-1 not IDENTIFIED)"))
                continue
            value = self._capability.lookup(node.vendor_os, version, node.feature, "configure")
            if value is CapabilityValue.YES:
                continue
            if value is CapabilityValue.PARTIAL:
                findings.append(Finding("CAPABILITY", "CAPABILITY_PARTIAL", Severity.WARNING,
                                        f"{node.node_id}: {node.feature} PARTIAL on {node.vendor_os} {version} — scope restriction required"))
                continue
            findings.append(Finding("CAPABILITY", "CAPABILITY_NOT_CONFIRMED", Severity.ERROR,
                                    f"{node.node_id}: configure capability for {node.feature} on {node.vendor_os} {version} is {value.value} (T2: not planned)"))
        return _stage("CAPABILITY", findings)

    def _preflight_stage(self, ir: ConfigIR) -> StageResult:
        if self._preflight is None:
            return StageResult("PREFLIGHT", StageStatus.NOT_MODELED, (
                Finding("PREFLIGHT", "PREFLIGHT_NOT_INTEGRATED", Severity.INFO,
                        "No PreflightFn wired (supply PreflightEngine.evaluate); NOT_MODELED recorded (L13: never PASS)"),
            ))
        status = self._preflight(ir)
        if status.state == "SUPPORTED_AND_MODELED":
            return StageResult("PREFLIGHT", StageStatus.PASS, (Finding("PREFLIGHT", "MODELED", Severity.INFO, status.notes),))
        if status.state in {"PARTIALLY_MODELED", "MODEL_INCOMPLETE"}:
            return StageResult("PREFLIGHT", StageStatus.PASS, (Finding("PREFLIGHT", status.state, Severity.WARNING, status.notes),))
        if status.state == "PARSE_FAILED":
            return StageResult("PREFLIGHT", StageStatus.FAIL, (Finding("PREFLIGHT", "PARSE_FAILED", Severity.ERROR, status.notes),))
        return StageResult("PREFLIGHT", StageStatus.NOT_MODELED, (Finding("PREFLIGHT", "NOT_MODELED", Severity.WARNING, status.notes),))


@dataclass(frozen=True)
class FabricResult:
    ir_id: str
    verdict: FabricVerdict
    stage_results: tuple[StageResult, ...]
    gate_class: str
    preflight_status: StageStatus

    def stage(self, name: str) -> StageResult:
        return next(r for r in self.stage_results if r.stage == name)

    def errors(self) -> list[Finding]:
        return [f for r in self.stage_results for f in r.findings if f.severity is Severity.ERROR]

    def not_modeled_high_risk(self) -> bool:
        """HUMAN_ONLY trigger (L06): NOT_MODELED preflight on HIGH_RISK+ work."""
        return (self.preflight_status is StageStatus.NOT_MODELED
                and self.gate_class in {"HIGH_RISK", "IRREVERSIBLE", "DESTRUCTIVE"})


def _has_cycle(edges: Mapping[str, set[str]]) -> bool:
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {node: WHITE for node in edges}

    def visit(node: str) -> bool:
        color[node] = GRAY
        for neighbor in sorted(edges.get(node, ())):
            if neighbor not in color:
                continue
            if color[neighbor] == GRAY:
                return True
            if color[neighbor] == WHITE and visit(neighbor):
                return True
        color[node] = BLACK
        return False

    return any(color[n] == WHITE and visit(n) for n in sorted(edges))
