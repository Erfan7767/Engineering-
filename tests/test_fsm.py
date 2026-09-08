"""FSM runtime + FSM-1 guards (D0-03): evidence-only transitions, fail-closed,
illegal attempts counted as gate_bypass, denials are BLOCKED (not bypass)."""

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.core.failures import FailureClass
from netops_autopilot.fsm.device_fsm import (
    ACCESSIBLE,
    BOOTSTRAPPED,
    BOOTSTRAP_REQUIRED,
    DISCOVERED,
    IDENTIFIED,
    MANAGED,
    MODELED,
    PHYSICAL_DETECTED,
    build_device_fsm,
)
from netops_autopilot.ledger.models import OperatorIdentity
from netops_autopilot.ledger.store import LedgerStore

ENGINE = OperatorIdentity(kind="ENGINE", id="E01-DAY0")


@pytest.fixture()
def rig():
    store = LedgerStore(":memory:")
    counters = CounterCollector()
    fsm = build_device_fsm(recorder=store, counters=counters)
    return store, counters, fsm


def ev(scope, kind, eid="ev-1", status="OK"):
    return {"scope": scope, "kind": kind, "evidence_id": eid, "status": status}


def ctx(*items):
    return {"evidence": list(items)}


def test_happy_path_unknown_to_identified(rig):
    store, counters, fsm = rig
    r = fsm.fire("dev-1", PHYSICAL_DETECTED, ctx(ev("INTERFACE_EXISTENCE", "carrier_probe")), ENGINE)
    assert r.success and fsm.state == PHYSICAL_DETECTED
    r = fsm.fire("dev-1", ACCESSIBLE, ctx(
        ev("DEVICE_IDENTITY", "session_open", "ev-2"),
        ev("DEVICE_IDENTITY", "day0_classifier", "ev-3"),
    ), ENGINE)
    assert r.success
    identity = ctx(*[ev("DEVICE_IDENTITY", f"identity_field:{f}", f"ev-id-{f}") for f in ("vendor", "model", "os", "version")])
    assert fsm.fire("dev-1", IDENTIFIED, identity, ENGINE).success
    assert fsm.state == IDENTIFIED
    # every transition recorded with evidence ids (L02, L08)
    trs = store.transitions()
    assert [t.guard_id for t in trs] == ["1.1", "1.2", "1.3"]
    assert all(t.evidence_ids and t.evidence_ids[0] != "guard:no-evidence-declared" for t in trs)


def test_guard_denial_is_blocked_not_bypass(rig):
    _, counters, fsm = rig
    r = fsm.fire("dev-1", PHYSICAL_DETECTED, ctx(), ENGINE)  # no evidence at all
    assert not r.success and fsm.state == "UNKNOWN"
    assert r.failure.cls is FailureClass.BLOCKED
    assert "MISSING_EVIDENCE" in r.failure.causes[0]
    assert counters.value("gate_bypass") == 0  # denial ≠ bypass


def test_illegal_transition_counts_gate_bypass(rig):
    _, counters, fsm = rig
    r = fsm.fire("dev-1", MANAGED, ctx(), ENGINE)  # UNKNOWN→MANAGED has no table entry
    assert not r.success and r.illegal
    assert counters.value("gate_bypass") == 1
    assert "ILLEGAL_TRANSITION" in list(counters.reasons("gate_bypass"))[0]
    assert fsm.state == "UNKNOWN"


def test_partial_identity_evidence_denies_1_3(rig):
    _, _, fsm = rig
    fsm.fire("dev-1", PHYSICAL_DETECTED, ctx(ev("INTERFACE_EXISTENCE", "carrier_probe")), ENGINE)
    fsm.fire("dev-1", ACCESSIBLE, ctx(ev("DEVICE_IDENTITY", "session_open"), ev("DEVICE_IDENTITY", "day0_classifier")), ENGINE)
    partial = ctx(*[ev("DEVICE_IDENTITY", f"identity_field:{f}") for f in ("vendor", "model")])
    r = fsm.fire("dev-1", IDENTIFIED, partial, ENGINE)
    assert not r.success
    assert "os" in r.failure.causes[0] or "version" in r.failure.causes[0]


def test_failed_status_evidence_ignored(rig):
    _, _, fsm = rig
    r = fsm.fire(
        "dev-1", PHYSICAL_DETECTED,
        ctx(ev("INTERFACE_EXISTENCE", "carrier_probe", status="PARSE_FAILED")),
        ENGINE,
    )
    assert not r.success  # evidence with bad status never satisfies a guard


def test_bootstrap_branch_full(rig):
    _, _, fsm = rig
    fsm.fire("dev-1", PHYSICAL_DETECTED, ctx(ev("INTERFACE_EXISTENCE", "carrier_probe")), ENGINE)
    fsm.fire("dev-1", ACCESSIBLE, ctx(ev("DEVICE_IDENTITY", "session_open"), ev("DEVICE_IDENTITY", "day0_classifier")), ENGINE)
    fsm.fire("dev-1", IDENTIFIED, ctx(*[ev("DEVICE_IDENTITY", f"identity_field:{f}") for f in ("vendor", "model", "os", "version")]), ENGINE)
    r = fsm.fire("dev-1", BOOTSTRAP_REQUIRED, ctx(
        ev("DEVICE_IDENTITY", "day0_state:FACTORY_DEFAULT", "ev-f"),
        ev("DEVICE_IDENTITY", "mgmt_plane_absent", "ev-m"),
    ), ENGINE)
    assert r.success
    r = fsm.fire("dev-1", BOOTSTRAPPED, ctx(
        ev("CONFIGURATION", "bootstrap_change_verified", "ev-bv"),
        ev("CONFIGURATION", "post_bootstrap_baseline_hashed", "ev-bh"),
    ), ENGINE)
    assert r.success and fsm.state == BOOTSTRAPPED


def test_managed_requires_all_three_1_8(rig):
    _, _, fsm = rig
    fsm.state = MODELED  # test-level state injection for guard isolation
    r = fsm.fire("dev-1", MANAGED, ctx(
        ev("SERVICE_REACHABILITY", "monitoring_collectors_bound"),
        ev("CONFIGURATION", "reconciliation_baseline_stored"),
        # recovery path missing ⇒ deny
    ), ENGINE)
    assert not r.success
    assert "recovery" in r.failure.causes[0]


def test_guard_exception_fails_closed(rig):
    from netops_autopilot.fsm.runtime import GuardedFsm, Transition

    def broken_guard(c):
        raise RuntimeError("boom")

    store, counters, _ = rig
    fsm = GuardedFsm(
        fsm_label="FSM-1_DEVICE",
        initial_state="UNKNOWN",
        transitions=[Transition("UNKNOWN", "PHYSICAL_DETECTED", "1.1", broken_guard)],
        recorder=store,
        counters=counters,
    )
    r = fsm.fire("dev-1", "PHYSICAL_DETECTED", {}, ENGINE)
    assert not r.success
    assert "GUARD_EXCEPTION" in r.failure.causes[0]
    assert fsm.state == "UNKNOWN"
    assert counters.value("gate_bypass") == 0


def test_duplicate_transition_table_rejected(rig):
    from netops_autopilot.fsm.runtime import GuardedFsm, Transition, GuardOutcome

    g = lambda c: GuardOutcome.pass_with("x")
    store, counters, _ = rig
    with pytest.raises(ValueError):
        GuardedFsm(
            fsm_label="FSM-1_DEVICE", initial_state="A",
            transitions=[Transition("A", "B", "g", g), Transition("A", "B", "g2", g)],
            recorder=store, counters=counters,
        )
