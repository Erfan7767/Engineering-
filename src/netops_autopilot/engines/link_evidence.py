"""Link Evidence Engine (D4) — drives FSM-4 per link (D0-03 §FSM-4, §10).

One guarded state machine per link entity: the epistemic ladder from
UNKNOWN through passive ceilings to gated proof. The engine's job is
discipline, not judgment — every method fires exactly one transition with
exactly the evidence kind its guard demands, and a refused transition
raises the guard's typed Failure (never swallowed, L03).

Epistemic rules preserved from the normative table:
* passive evidence ceiling = DIRECT_NEIGHBOR_PROBABLE (4.5);
* CONFIRMED requires PROVEN absence of an intermediary (4.6);
* PHYSICAL_PATH_VERIFIED only via GATED active proof or explicit human
  confirmation (4.7) — never inferred (L01);
* CONFLICTING is terminal for automation (no outgoing transitions);
* STALE quarantines; only a recorded re-evaluation returns to UNKNOWN (4.9).
"""

from __future__ import annotations

from typing import Callable, Optional

from ..core.failures import Failure, FailureClass
from ..fsm import link_fsm as lf
from ..ledger.models import OperatorIdentity

_LINK_ACTOR = OperatorIdentity(kind="ENGINE", id="E20")


class LinkEvidenceEngine:
    """Owns one FSM-4 instance per link id (each link has its own ladder)."""

    def __init__(self, factory: Callable[[], object]) -> None:
        """``factory`` must return a fresh ``build_link_fsm(...)`` instance."""
        self._factory = factory
        self._machines: dict[str, object] = {}

    # ------------------------------------------------------------------ state
    def state(self, link_id: str) -> str:
        machine = self._machines.get(link_id)
        return machine.state if machine is not None else lf.UNKNOWN

    def machine(self, link_id: str):
        if link_id not in self._machines:
            self._machines[link_id] = self._factory()
        return self._machines[link_id]

    # ------------------------------------------------------- passive ladder
    def inferred(self, link_id: str, evidence_id: str) -> None:
        """4.1: MAC/ARP co-occurrence ⇒ INFERRED."""
        self._fire(link_id, lf.INFERRED, lf.SCOPE_NEIGHBOR,
                   "passive:mac_arp_cooccurrence", evidence_id)

    def one_sided(self, link_id: str, evidence_id: str) -> None:
        """4.2: neighbor advertisement seen on one side only."""
        self._fire(link_id, lf.ONE_SIDED, lf.SCOPE_NEIGHBOR,
                   "passive:neighbor_advertisement_one_side", evidence_id)

    def conflict(self, link_id: str, evidence_id: str) -> None:
        """4.3: sources disagree ⇒ terminal for automation (operator-raised)."""
        self._fire(link_id, lf.CONFLICTING, lf.SCOPE_NEIGHBOR,
                   "passive:sources_disagree", evidence_id)

    def intermediary_suspected(self, link_id: str, evidence_id: str) -> None:
        """4.4: hints of an intermediate device on the path."""
        self._fire(link_id, lf.INTERMEDIATE_SUSPECTED, lf.SCOPE_NEIGHBOR,
                   "passive:intermediary_hints", evidence_id)

    def probable_bidirectional(self, link_id: str, evidence_id: str) -> None:
        """4.5 via bidirectional neighbor match (the strong passive path)."""
        self._fire(link_id, lf.DIRECT_NEIGHBOR_PROBABLE, lf.SCOPE_NEIGHBOR,
                   "passive:bidirectional_match", evidence_id)

    def probable_correlated(self, link_id: str, clean_mac_id: str,
                            port_name_id: str, time_id: str) -> None:
        """4.5 via the three-conjunct correlation path (all required)."""
        self._fire(link_id, lf.DIRECT_NEIGHBOR_PROBABLE, lf.SCOPE_NEIGHBOR,
                   ("passive:one_sided_plus_clean_mac",
                    "passive:port_name_correlation",
                    "passive:time_correlation"),
                   (clean_mac_id, port_name_id, time_id))

    # ------------------------------------------------------------ confirmations
    def confirmed(self, link_id: str, absence_of_intermediary_id: str) -> None:
        """4.6: CONFIRMED requires proven absence of an intermediary."""
        self._fire(link_id, lf.DIRECT_NEIGHBOR_CONFIRMED, lf.SCOPE_NEIGHBOR,
                   "passive:absence_of_intermediary_proven", absence_of_intermediary_id)

    def path_verified_active(self, link_id: str, gated_proof_id: str) -> None:
        """4.7 via gated active proof (link-toggle/TDR/DOM, §10)."""
        self._fire(link_id, lf.PHYSICAL_PATH_VERIFIED, lf.SCOPE_PATH,
                   "active:gated_proof", gated_proof_id)

    def path_verified_human(self, link_id: str, human_confirmation_id: str) -> None:
        """4.7 via explicit human confirmation with recorded identity."""
        self._fire(link_id, lf.PHYSICAL_PATH_VERIFIED, lf.SCOPE_PATH,
                   "human:explicit_confirmation", human_confirmation_id)

    # ------------------------------------------------------------- lifecycle
    def stale(self, link_id: str, holdtime_evidence_id: str) -> None:
        """4.8: freshness holdtime exceeded ⇒ quarantine the bundle."""
        self._fire(link_id, lf.STALE, lf.SCOPE_NEIGHBOR,
                   "freshness:holdtime_exceeded", holdtime_evidence_id)

    def reevaluate(self, link_id: str, reassessment_id: str) -> None:
        """4.9: recorded re-evaluation returns STALE → UNKNOWN."""
        self._fire(link_id, lf.UNKNOWN, lf.SCOPE_NEIGHBOR,
                   "reassessment:initiated", reassessment_id)

    # -------------------------------------------------------------- internal
    def _fire(self, link_id: str, target: str, scope: str, kind, evidence_id) -> None:
        if not link_id:
            raise Failure(cls=FailureClass.BLOCKED, causes=("LINK_ID_EMPTY",))
        kinds = (kind,) if isinstance(kind, str) else tuple(kind)
        ids = (evidence_id,) if isinstance(evidence_id, str) else tuple(evidence_id)
        if len(kinds) != len(ids):
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"LINK_EVIDENCE_ARITY:{len(kinds)} kinds vs {len(ids)} ids",))
        for eid in ids:
            if not eid:
                raise Failure(cls=FailureClass.BLOCKED,
                              causes=("LINK_EVIDENCE_ID_EMPTY: every rung needs recorded evidence (T1)",))
        evidence = [{"scope": scope, "kind": k, "evidence_id": eid, "status": "OK"}
                    for k, eid in zip(kinds, ids)]
        result = self.machine(link_id).fire(link_id, target, {"evidence": evidence}, _LINK_ACTOR)
        if not result.success:
            raise result.failure
