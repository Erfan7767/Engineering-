"""E14 Autonomy Authority Engine — DECIDE autonomy decisions (D0-02).

The single DECIDE cell for "Autonomy decision"; HUMAN_ONLY enforcement of
L06 lives here, deterministically:

* IRREVERSIBLE / DESTRUCTIVE gates are human-decided in EVERY mode (L06);
* HIGH_RISK gates require an RBAC identity + verified MFA (§18, FSM-2 2.4);
* NOT_MODELED is terminal for automation (L13 + D0-02 rule 4: UNKNOWN ⇒
  BLOCKED, never defaulted) — even a valid human approval does not convert
  an unmodeled change into an executable one;
* the v1 ceiling is locked at M3 Controlled Autonomous (sponsor decision
  OI-0006); constructing a higher ceiling is a typed failure, and lower
  ceilings conservatively require approval for everything.

The engine outputs a decision record; it never executes anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ..core.failures import Failure, FailureClass
from ..fsm.change_fsm import HUMAN_ONLY_GATES, MFA_GATES

KNOWN_GATE_CLASSES = frozenset({"LOW_RISK", "HIGH_RISK", "IRREVERSIBLE", "DESTRUCTIVE"})
KNOWN_RISK_CLASSES = KNOWN_GATE_CLASSES  # E13 reuses the gate vocabulary


class AutonomyLevel(str, Enum):
    M0_MANUAL = "M0_MANUAL"
    M1_ASSISTED = "M1_ASSISTED"
    M2_SUPERVISED = "M2_SUPERVISED"
    M3_CONTROLLED = "M3_CONTROLLED"
    M4_HIGH = "M4_HIGH"
    M5_FULL = "M5_FULL"


#: Locked v1 ceiling (OI-0006). Frozen at construction, enforced below.
LOCKED_CEILING = AutonomyLevel.M3_CONTROLLED


class Verdict(str, Enum):
    AUTO_EXECUTE = "AUTO_EXECUTE"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    HUMAN_ONLY = "HUMAN_ONLY"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class Approval:
    """Identity-bound human approval (§18): RBAC identity + MFA state."""

    rbac_identity: str
    mfa_verified: bool

    def __post_init__(self) -> None:
        if not self.rbac_identity:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("APPROVAL_IDENTITY_EMPTY: human decisions without recorded identity are audit violations (D0-02 rule 5)",))


@dataclass(frozen=True)
class DecisionReadiness:
    """§13 Decision Readiness conjuncts — all must be provably true.
    ``None`` means UNKNOWN and counts as FALSE (fail-closed, rule 4)."""

    intent_compiled: Optional[bool] = None
    fabric_pass: Optional[bool] = None
    dag_built: Optional[bool] = None
    blast_recorded: Optional[bool] = None
    rollback_ready: Optional[bool] = None
    twin_fresh: Optional[bool] = None
    capability_confirmed: Optional[bool] = None
    no_conflicting_change: Optional[bool] = None

    _CONJUNCTS = ("intent_compiled", "fabric_pass", "dag_built", "blast_recorded",
                  "rollback_ready", "twin_fresh", "capability_confirmed", "no_conflicting_change")

    def conjunct(self, name: str) -> bool:
        return getattr(self, name) is True

    def unknown_conjuncts(self) -> tuple[str, ...]:
        return tuple(n for n in self._CONJUNCTS if getattr(self, n) is None)

    def false_conjuncts(self) -> tuple[str, ...]:
        return tuple(n for n in self._CONJUNCTS if getattr(self, n) is not True)

    @property
    def all_true(self) -> bool:
        return all(getattr(self, n) is True for n in self._CONJUNCTS)


@dataclass(frozen=True)
class AutonomyDecision:
    verdict: Verdict
    gate_class: str
    risk_class: str
    level: AutonomyLevel
    human_decided: bool
    approval_satisfied: bool
    reasons: tuple[str, ...]


class AutonomyAuthority:
    def __init__(self, ceiling: AutonomyLevel = LOCKED_CEILING) -> None:
        order = list(AutonomyLevel)
        if order.index(ceiling) > order.index(LOCKED_CEILING):
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"AUTONOMY_CEILING_LOCKED: v1 ceiling is {LOCKED_CEILING.value} (OI-0006); "
                                  f"{ceiling.value} refuses construction",))
        self._ceiling = ceiling

    @property
    def ceiling(self) -> AutonomyLevel:
        return self._ceiling

    # ---------------------------------------------------------------- decide
    def decide(self, *, gate_class: str, risk_class: str,
               preflight_not_modeled: bool,
               approval: Optional[Approval] = None) -> AutonomyDecision:
        reasons: list[str] = []

        if gate_class not in KNOWN_GATE_CLASSES:
            return self._decision(Verdict.BLOCKED, gate_class, risk_class,
                                  False, False, [f"GATE_CLASS_UNKNOWN:{gate_class!r}"])
        if risk_class not in KNOWN_RISK_CLASSES:
            return self._decision(Verdict.BLOCKED, gate_class, risk_class,
                                  False, False, [f"RISK_CLASS_UNKNOWN:{risk_class!r} (rule 4: UNKNOWN is terminal)"])
        if preflight_not_modeled:
            return self._decision(Verdict.BLOCKED, gate_class, risk_class,
                                  False, False,
                                  ["NOT_MODELED_TERMINAL: automation cannot proceed without a model (L13); approval cannot substitute for modeling"])

        human_decided = approval is not None
        if gate_class in HUMAN_ONLY_GATES:
            reasons.append(f"HUMAN_ONLY_GATE:{gate_class} in every mode (L06)")
            # Human-only gates are MFA gates (§18): a decision without
            # verified MFA is not a complete decision (never emit it as one).
            decided = approval is not None and approval.mfa_verified
            if not decided:
                reasons.append("HUMAN_DECISION_MISSING" if approval is None else "HUMAN_DECISION_MFA_UNVERIFIED")
            return self._decision(Verdict.HUMAN_ONLY, gate_class, risk_class,
                                  decided, decided, reasons)

        if gate_class in MFA_GATES:
            satisfied = approval is not None and approval.mfa_verified
            reasons.append(f"MFA_GATE:{gate_class} requires RBAC identity + verified MFA (§18)")
            if not satisfied:
                reasons.append("APPROVAL_UNSATISFIED")
            return self._decision(Verdict.APPROVAL_REQUIRED, gate_class, risk_class,
                                  human_decided, satisfied, reasons)

        # LOW_RISK — autonomy depends on the locked ceiling.
        if self._ceiling is AutonomyLevel.M3_CONTROLLED:
            return self._decision(Verdict.AUTO_EXECUTE, gate_class, risk_class,
                                  False, True, ["M3_CONTROLLED: low-risk fully modeled work executes"])
        reasons.append(f"CEILING_BELOW_M3:{self._ceiling.value}: low-risk work still requires approval")
        return self._decision(Verdict.APPROVAL_REQUIRED, gate_class, risk_class,
                              human_decided, human_decided, reasons)

    # ------------------------------------------------------------- internal
    def _decision(self, verdict: Verdict, gate_class: str, risk_class: str,
                  human_decided: bool, approval_satisfied: bool,
                  reasons: list[str]) -> AutonomyDecision:
        return AutonomyDecision(verdict=verdict, gate_class=gate_class,
                                risk_class=risk_class, level=self._ceiling,
                                human_decided=human_decided,
                                approval_satisfied=approval_satisfied,
                                reasons=tuple(reasons))
