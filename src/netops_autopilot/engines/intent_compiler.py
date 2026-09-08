"""E08 Intent Compiler — Business Intent → Network Intent (§12).

Scope of this engine: requirements intake (structured), blocking questions
for every gap (T2), and the deterministic zone×zone policy matrix. The
abstract network model / IR hand-off continues in the downstream pipeline
(E09+). No addressing or VLAN decisions exist in a Network Intent — the
policy matrix comes FIRST, exactly as §12 mandates ("before any VLAN/IP"
for the guest-isolation example).

Authority (D0-02): the compiler co-decides business→network intent WITH a
human; the output is a proposal that requires human confirmation, and the
Auditor may veto. The compiler itself never executes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ..core.failures import Failure, FailureClass
from ..core.ids import new_id
from .service_graph import ServiceGraph


class ZoneKind(str, Enum):
    INTERNAL = "INTERNAL"
    GUEST = "GUEST"
    DMZ = "DMZ"
    MGMT = "MGMT"
    WAN = "WAN"


#: Deterministic zone ordering used everywhere (matrix rows/columns, rule ids).
ZONE_KIND_ORDER = (ZoneKind.WAN, ZoneKind.MGMT, ZoneKind.DMZ, ZoneKind.INTERNAL, ZoneKind.GUEST)


class RuleAction(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True)
class Zone:
    name: str
    kind: ZoneKind

    def __post_init__(self) -> None:
        if not self.name:
            raise Failure(cls=FailureClass.BLOCKED, causes=("INTENT_ZONE_NAME_EMPTY",))


@dataclass(frozen=True)
class PolicyRule:
    """One zone×zone matrix entry. Lower ``precedence`` wins on the same
    (src, dst) pair — service carve-outs are lower than blanket denies."""

    precedence: int
    src_zone: str
    dst_zone: str
    action: RuleAction
    services: tuple[str, ...]  # empty tuple = ALL
    reason: str


@dataclass(frozen=True)
class BlockingQuestion:
    """A knowledge gap that BLOCKS compilation until a human answers (T2)."""

    code: str
    field: str
    question: str


@dataclass(frozen=True)
class BusinessIntentRequest:
    """Structured intake — A2 proposes, the compiler validates shape only."""

    requirement_text: str
    zones: tuple[Zone, ...]
    guest_isolation: bool = False
    internal_internet: bool = True
    dot1x_required: bool = False
    uses_certificates: bool = False
    availability_class: Optional[str] = None  # HIGH | STANDARD
    growth_plan: Optional[str] = None
    intent_id: str = field(default_factory=new_id)


@dataclass(frozen=True)
class NetworkIntent:
    intent_id: str
    requirement_text: str
    status: str  # COMPILED | BLOCKED
    zones: tuple[Zone, ...]
    rules: tuple[PolicyRule, ...]
    required_services: tuple[str, ...]  # bring-up order from ServiceGraph
    availability_class: Optional[str]
    growth_plan: Optional[str]
    blocking_questions: tuple[BlockingQuestion, ...] = ()


# ------------------------------------------------------------------ questions
def _blocking_questions(req: BusinessIntentRequest) -> list[BlockingQuestion]:
    out: list[BlockingQuestion] = []
    if not req.zones:
        out.append(BlockingQuestion("BQ-NO-ZONES", "zones",
                                    "No zones declared. What are the network zones (internal/guest/dmz/mgmt/wan)?"))
        # Zone-derived questions are suppressed while the root gap is open —
        # one root question, not derivative noise.
        return out + _non_zone_questions(req)
    kinds = {z.kind for z in req.zones}
    if req.guest_isolation and ZoneKind.GUEST not in kinds:
        out.append(BlockingQuestion("BQ-GUEST-FLAG-NO-ZONE", "zones",
                                    "Guest isolation requested but no GUEST zone exists. Which zone hosts guests?"))
    needs_internet = req.guest_isolation or req.internal_internet
    if needs_internet and ZoneKind.WAN not in kinds:
        out.append(BlockingQuestion("BQ-NO-EGRESS", "zones",
                                    "Internet egress required but no WAN zone exists. How does this site reach the Internet?"))
    return out + _non_zone_questions(req)


def _non_zone_questions(req: BusinessIntentRequest) -> list[BlockingQuestion]:
    out: list[BlockingQuestion] = []
    if req.availability_class is None:
        out.append(BlockingQuestion("BQ-AVAILABILITY-MISSING", "availability_class",
                                    "Availability class not stated. HIGH (redundant paths/protocols) or STANDARD?"))
    elif req.availability_class not in {"HIGH", "STANDARD"}:
        out.append(BlockingQuestion("BQ-AVAILABILITY-INVALID", "availability_class",
                                    f"Availability class {req.availability_class!r} is not HIGH|STANDARD."))
    if req.growth_plan is None:
        out.append(BlockingQuestion("BQ-GROWTH-MISSING", "growth_plan",
                                    "Growth plan not stated. Expected user/site growth horizon (e.g., +25% in 12 months)?"))
    return out


# ------------------------------------------------------------------ services
def _required_services(req: BusinessIntentRequest) -> list[str]:
    base = ["dns", "dhcp"]
    if req.dot1x_required:
        base += ["dot1x", "radius"]
    if req.uses_certificates:
        base.append("pki")
    if req.internal_internet or req.guest_isolation:
        base.append("internet_egress")
    # Deterministic de-duplication preserving first appearance.
    seen: list[str] = []
    for name in base:
        if name not in seen:
            seen.append(name)
    return seen


# ---------------------------------------------------------------------- rules
def _zone_order_key(zone: Zone) -> tuple[int, str]:
    return (ZONE_KIND_ORDER.index(zone.kind), zone.name)


def _policy_rules(req: BusinessIntentRequest) -> list[PolicyRule]:
    zones = sorted(req.zones, key=_zone_order_key)
    rules: list[PolicyRule] = []

    def zones_of_kind(kind: ZoneKind) -> list[Zone]:
        return [z for z in zones if z.kind is kind]

    # --- Guest isolation (the §12 mandatory example) --------------------
    if req.guest_isolation:
        for guest in zones_of_kind(ZoneKind.GUEST):
            for target in zones_of_kind(ZoneKind.INTERNAL):
                # Service carve-out FIRST (lower precedence): guests need
                # DNS/DHCP to function, and nothing else internal.
                rules.append(PolicyRule(90, guest.name, target.name, RuleAction.ALLOW,
                                        ("dns", "dhcp"), "GUEST_BOOTSTRAP_SERVICES"))
                rules.append(PolicyRule(110, guest.name, target.name, RuleAction.DENY,
                                        (), "GUEST_ISOLATION_INTERNAL"))
            for target in zones_of_kind(ZoneKind.MGMT):
                rules.append(PolicyRule(100, guest.name, target.name, RuleAction.DENY,
                                        (), "GUEST_ISOLATION_MGMT"))
            for target in zones_of_kind(ZoneKind.GUEST):
                if target.name != guest.name:
                    rules.append(PolicyRule(120, guest.name, target.name, RuleAction.DENY,
                                            (), "GUEST_INTER_ZONE_ISOLATION"))
            rules.append(PolicyRule(120, guest.name, guest.name, RuleAction.DENY,
                                    (), "GUEST_INTRA_ISOLATION"))
            for target in zones_of_kind(ZoneKind.WAN):
                rules.append(PolicyRule(130, guest.name, target.name, RuleAction.ALLOW,
                                        (), "GUEST_INTERNET_EGRESS"))

    # --- Internal internet egress ----------------------------------------
    if req.internal_internet:
        for source in zones_of_kind(ZoneKind.INTERNAL):
            for target in zones_of_kind(ZoneKind.WAN):
                rules.append(PolicyRule(200, source.name, target.name, RuleAction.ALLOW,
                                        (), "INTERNAL_INTERNET_EGRESS"))

    # --- Intra-zone default (except isolated guest zone) -------------------
    isolated_guest_names = {z.name for z in zones_of_kind(ZoneKind.GUEST)} if req.guest_isolation else set()
    for zone in zones:
        if zone.name in isolated_guest_names:
            continue
        rules.append(PolicyRule(500, zone.name, zone.name, RuleAction.ALLOW, (), "INTRA_ZONE_DEFAULT"))

    # --- Complete matrix: everything unstated is DEFAULT_DENY -------------
    covered: set[tuple[str, str]] = {(r.src_zone, r.dst_zone) for r in rules}
    for source in zones:
        for target in zones:
            if (source.name, target.name) not in covered:
                rules.append(PolicyRule(1000, source.name, target.name, RuleAction.DENY,
                                        (), "DEFAULT_DENY"))

    rules.sort(key=lambda r: (r.precedence, r.src_zone, r.dst_zone))
    return rules


# -------------------------------------------------------------------- compiler
class IntentCompiler:
    """Deterministic Business→Network Intent compilation (§12)."""

    def __init__(self, service_graph: ServiceGraph) -> None:
        self._services = service_graph

    def compile(self, req: BusinessIntentRequest) -> NetworkIntent:
        questions = _blocking_questions(req)
        if questions:
            return NetworkIntent(
                intent_id=req.intent_id, requirement_text=req.requirement_text,
                status="BLOCKED", zones=req.zones, rules=(), required_services=(),
                availability_class=req.availability_class, growth_plan=req.growth_plan,
                blocking_questions=tuple(questions),
            )
        required = self._services.order_for(_required_services(req))
        return NetworkIntent(
            intent_id=req.intent_id, requirement_text=req.requirement_text,
            status="COMPILED", zones=req.zones, rules=tuple(_policy_rules(req)),
            required_services=tuple(required),
            availability_class=req.availability_class, growth_plan=req.growth_plan,
        )

    # ------------------------------------------------------ query helpers
    @staticmethod
    def effective_rules_for_pair(intent: NetworkIntent, src: str, dst: str) -> tuple[PolicyRule, ...]:
        """All rules for one ordered pair, precedence-sorted (lowest wins)."""
        return tuple(r for r in intent.rules if r.src_zone == src and r.dst_zone == dst)

    @staticmethod
    def matrix_is_complete(intent: NetworkIntent) -> bool:
        names = {z.name for z in intent.zones}
        covered = {(r.src_zone, r.dst_zone) for r in intent.rules}
        return all((s, d) in covered for s in names for d in names)
