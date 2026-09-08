"""Link Evidence Engine: FSM-4 epistemic ladder, ceilings, terminal conflicts."""

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.core.failures import Failure
from netops_autopilot.engines.link_evidence import LinkEvidenceEngine
from netops_autopilot.fsm import link_fsm as lf
from netops_autopilot.ledger.store import LedgerStore


@pytest.fixture()
def engine():
    counters = CounterCollector()

    def factory():
        return lf.build_link_fsm(recorder=LedgerStore(":memory:"), counters=counters)

    return LinkEvidenceEngine(factory)


# ------------------------------------------------------------------- ladder
def test_unknown_is_the_default_state(engine):
    assert engine.state("link-1") == lf.UNKNOWN


def test_full_passive_to_verified_lifecycle(engine):
    engine.inferred("link-1", "ev-cooccur")
    assert engine.state("link-1") == lf.INFERRED
    engine.probable_bidirectional("link-1", "ev-bidir")
    assert engine.state("link-1") == lf.DIRECT_NEIGHBOR_PROBABLE
    engine.confirmed("link-1", "ev-no-intermediary")
    assert engine.state("link-1") == lf.DIRECT_NEIGHBOR_CONFIRMED
    engine.path_verified_active("link-1", "ev-gated-proof")
    assert engine.state("link-1") == lf.PHYSICAL_PATH_VERIFIED
    engine.stale("link-1", "ev-holdtime")
    assert engine.state("link-1") == lf.STALE
    engine.reevaluate("link-1", "ev-reassess")
    assert engine.state("link-1") == lf.UNKNOWN


def test_one_sided_correlation_path_requires_all_three_conjuncts(engine):
    engine.one_sided("link-2", "ev-advert")
    assert engine.state("link-2") == lf.ONE_SIDED
    engine.probable_correlated("link-2", "ev-clean-mac", "ev-port-name", "ev-time")
    assert engine.state("link-2") == lf.DIRECT_NEIGHBOR_PROBABLE


def test_human_confirmation_also_verifies_path(engine):
    engine.inferred("link-3", "ev-1")
    engine.probable_bidirectional("link-3", "ev-2")
    engine.confirmed("link-3", "ev-3")
    engine.path_verified_human("link-3", "ev-human-identity")
    assert engine.state("link-3") == lf.PHYSICAL_PATH_VERIFIED


# ----------------------------------------------------------------- ceilings
def test_passive_ceiling_cannot_skip_to_confirmed(engine):
    engine.inferred("link-4", "ev-1")
    with pytest.raises(Failure) as exc:
        engine.confirmed("link-4", "ev-2")  # must pass PROBABLE first
    assert "ILLEGAL_TRANSITION" in exc.value.causes[0]
    assert engine.state("link-4") == lf.INFERRED


def test_path_verification_never_from_passive_alone(engine):
    engine.inferred("link-5", "ev-1")
    with pytest.raises(Failure):
        engine.path_verified_active("link-5", "ev-2")  # needs PROBABLE+ first
    engine.probable_bidirectional("link-5", "ev-3")
    engine.path_verified_active("link-5", "ev-4")  # PROBABLE → verified is legal (4.7)
    assert engine.state("link-5") == lf.PHYSICAL_PATH_VERIFIED


def test_conflicting_is_terminal_for_automation(engine):
    engine.conflict("link-6", "ev-disagree")
    assert engine.state("link-6") == lf.CONFLICTING
    with pytest.raises(Failure):
        engine.inferred("link-6", "ev-late")  # no outgoing transitions (4.3)
    with pytest.raises(Failure):
        engine.stale("link-6", "ev-holdtime")
    assert engine.state("link-6") == lf.CONFLICTING  # operator-raised, never auto-resolved


def test_intermediary_suspension_is_its_own_rung(engine):
    engine.intermediary_suspected("link-7", "ev-hints")
    assert engine.state("link-7") == lf.INTERMEDIATE_SUSPECTED
    with pytest.raises(Failure):
        engine.probable_bidirectional("link-7", "ev-bidir")  # suspicion blocks promotion


# ------------------------------------------------------------- per-link state
def test_links_have_independent_machines(engine):
    engine.inferred("link-a", "ev-1")
    engine.conflict("link-b", "ev-2")
    assert engine.state("link-a") == lf.INFERRED
    assert engine.state("link-b") == lf.CONFLICTING
    assert engine.state("link-c") == lf.UNKNOWN


# -------------------------------------------------------------- evidence law
def test_empty_evidence_ids_are_refused(engine):
    with pytest.raises(Failure) as exc:
        engine.inferred("link-8", "")
    assert "LINK_EVIDENCE_ID_EMPTY" in exc.value.causes[0]
    with pytest.raises(Failure):
        engine.probable_correlated("link-8", "ev-1", "", "ev-3")


def test_conjunction_arity_is_checked(engine):
    with pytest.raises(Failure) as exc:
        engine._fire("link-9", lf.DIRECT_NEIGHBOR_PROBABLE, lf.SCOPE_NEIGHBOR,
                     ("passive:one_sided_plus_clean_mac", "passive:port_name_correlation"),
                     ("ev-1",))
    assert "LINK_EVIDENCE_ARITY" in exc.value.causes[0]


def test_transitions_are_recorded_in_the_ledger(engine):
    engine.inferred("link-r", "ev-1")
    engine.probable_bidirectional("link-r", "ev-2")
    machine = engine.machine("link-r")
    assert machine.state == lf.DIRECT_NEIGHBOR_PROBABLE
