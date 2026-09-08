"""FSM-4 Link Evidence: passive ceiling, gated physical proof, staleness."""

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.fsm import link_fsm as lf
from netops_autopilot.fsm.evidence import ctx, ev
from netops_autopilot.ledger.models import OperatorIdentity
from netops_autopilot.ledger.store import LedgerStore

ENGINE = OperatorIdentity(kind="ENGINE", id="E20")
NB = lf.SCOPE_NEIGHBOR
PATH = lf.SCOPE_PATH


@pytest.fixture()
def rig():
    store = LedgerStore(":memory:")
    counters = CounterCollector()
    return store, counters, lf.build_link_fsm(recorder=store, counters=counters)


def test_state_set_matches_spec():
    assert lf.ALL_STATES == frozenset({
        "UNKNOWN", "INFERRED", "ONE_SIDED", "CONFLICTING",
        "INTERMEDIATE_SUSPECTED", "DIRECT_NEIGHBOR_PROBABLE",
        "DIRECT_NEIGHBOR_CONFIRMED", "PHYSICAL_PATH_VERIFIED", "STALE",
    })


def test_passive_ceiling_via_bidirectional_match(rig):
    _, _, fsm = rig
    fsm.fire("link-1", lf.INFERRED, ctx(ev(NB, "passive:mac_arp_cooccurrence")), ENGINE)
    r = fsm.fire("link-1", lf.DIRECT_NEIGHBOR_PROBABLE, ctx(ev(NB, "passive:bidirectional_match")), ENGINE)
    assert r.success and fsm.state == lf.DIRECT_NEIGHBOR_PROBABLE


def test_one_sided_path_requires_all_three_correlations(rig):
    _, _, fsm = rig
    fsm.fire("link-1", lf.ONE_SIDED, ctx(ev(NB, "passive:neighbor_advertisement_one_side")), ENGINE)
    partial = ctx(ev(NB, "passive:one_sided_plus_clean_mac"), ev(NB, "passive:port_name_correlation"))
    r = fsm.fire("link-1", lf.DIRECT_NEIGHBOR_PROBABLE, partial, ENGINE)
    assert not r.success and "time_correlation" in r.failure.causes[0]
    full = ctx(*partial["evidence"], ev(NB, "passive:time_correlation"))
    assert fsm.fire("link-1", lf.DIRECT_NEIGHBOR_PROBABLE, full, ENGINE).success


def test_confirmed_requires_absence_of_intermediary(rig):
    _, _, fsm = rig
    fsm.state = lf.DIRECT_NEIGHBOR_PROBABLE
    r = fsm.fire("link-1", lf.DIRECT_NEIGHBOR_CONFIRMED, ctx(), ENGINE)
    assert not r.success and "absence_of_intermediary" in r.failure.causes[0]
    assert fsm.fire("link-1", lf.DIRECT_NEIGHBOR_CONFIRMED,
                    ctx(ev(NB, "passive:absence_of_intermediary_proven")), ENGINE).success


def test_physical_path_verified_only_via_gated_active_or_human(rig):
    _, _, fsm = rig
    fsm.state = lf.DIRECT_NEIGHBOR_CONFIRMED
    r = fsm.fire("link-1", lf.PHYSICAL_PATH_VERIFIED, ctx(ev(NB, "passive:bidirectional_match")), ENGINE)
    assert not r.success  # passive evidence can never produce this state
    assert fsm.fire("link-1", lf.PHYSICAL_PATH_VERIFIED,
                    ctx(ev(PATH, "active:gated_proof", "probe-7")), ENGINE).success

    fsm2_state = lf.build_link_fsm(recorder=fsm._recorder, counters=CounterCollector())
    fsm2_state.state = lf.DIRECT_NEIGHBOR_PROBABLE
    assert fsm2_state.fire("link-2", lf.PHYSICAL_PATH_VERIFIED,
                           ctx(ev(PATH, "human:explicit_confirmation", "human-3")), ENGINE).success


def test_conflicting_is_terminal_for_automation(rig):
    _, counters, fsm = rig
    fsm.fire("link-1", lf.CONFLICTING, ctx(ev(NB, "passive:sources_disagree")), ENGINE)
    assert fsm.allowed_targets() == []  # operator-raised, never auto-resolved
    r = fsm.fire("link-1", lf.DIRECT_NEIGHBOR_PROBABLE, ctx(ev(NB, "passive:bidirectional_match")), ENGINE)
    assert r.illegal and counters.value("gate_bypass") == 1


def test_intermediate_suspected_entry(rig):
    _, _, fsm = rig
    assert fsm.fire("link-1", lf.INTERMEDIATE_SUSPECTED,
                    ctx(ev(NB, "passive:intermediary_hints")), ENGINE).success


def test_staleness_and_quarantined_revival(rig):
    _, _, fsm = rig
    fsm.state = lf.DIRECT_NEIGHBOR_CONFIRMED
    assert fsm.fire("link-1", lf.STALE, ctx(ev(NB, "freshness:holdtime_exceeded")), ENGINE).success
    # A stale bundle cannot jump back to CONFIRMED; only 4.9 re-evaluation.
    r = fsm.fire("link-1", lf.DIRECT_NEIGHBOR_CONFIRMED,
                 ctx(ev(NB, "passive:absence_of_intermediary_proven")), ENGINE)
    assert r.illegal
    assert fsm.fire("link-1", lf.UNKNOWN, ctx(ev(NB, "reassessment:initiated")), ENGINE).success


def test_staleness_reachable_from_all_live_states(rig):
    _, _, fsm = rig
    for state in (lf.INFERRED, lf.ONE_SIDED, lf.DIRECT_NEIGHBOR_PROBABLE,
                  lf.DIRECT_NEIGHBOR_CONFIRMED, lf.PHYSICAL_PATH_VERIFIED):
        fsm.state = state
        assert fsm.fire("link-x", lf.STALE, ctx(ev(NB, "freshness:holdtime_exceeded")), ENGINE).success, state


def test_transitions_recorded_with_link_label(rig):
    store, _, fsm = rig
    fsm.fire("link-1", lf.INFERRED, ctx(ev(NB, "passive:mac_arp_cooccurrence")), ENGINE)
    trs = store.transitions()
    assert trs[-1].fsm == lf.FSM_LABEL and trs[-1].guard_id == "4.1"
