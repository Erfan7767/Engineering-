"""E05 Digital Twin: evidence-only mutations, typed admissions, Gaps List."""

from datetime import datetime, timezone

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.ledger.models import Claim, ClaimStatus, SubjectEntity
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.twin.models import TwinLayer
from netops_autopilot.twin.twin import TWIN_FSM_LABEL, Admission, DigitalTwin

NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def rig():
    store = LedgerStore(":memory:")
    counters = CounterCollector()
    return store, counters, DigitalTwin(store, counters)


def claim(etype, ref, predicate, value, evidence=("obs-1",), status="CONFIRMED", relevance="PASS", scope="DEVICE_IDENTITY"):
    return Claim(
        subject_entity=SubjectEntity(entity_type=etype, entity_ref=ref),
        predicate=predicate, value=value, evidence_ids=list(evidence),
        verification_scope=scope, status=status, relevance_check=relevance,
    )


def test_confirmed_relevant_claim_creates_entity_with_provenance(rig):
    store, _, twin = rig
    result = twin.apply_claim(claim("DEVICE", "dev-1", "vendor", "cisco"), NOW)
    assert result.admission is Admission.APPLIED
    entity = twin.entity("DEVICE", "dev-1")
    assert entity is not None
    fr = entity.fields["vendor"]
    assert fr.value == "cisco"
    assert fr.evidence_ids == ("obs-1",)
    assert fr.layer is TwinLayer.PHYSICAL and fr.layer_origin == "registry"
    # Mutation is a ledger record (D0-04 chain tail).
    trs = [t for t in store.transitions() if t.fsm == TWIN_FSM_LABEL]
    assert len(trs) == 1 and trs[0].guard_id == "TWIN-ADMIT"
    assert trs[0].evidence_ids == ["obs-1"]


def test_field_update_replaces_value_keeps_latest_evidence(rig):
    _, _, twin = rig
    twin.apply_claim(claim("DEVICE", "dev-1", "os_version", "17.9.3", evidence=("obs-a",)), NOW)
    twin.apply_claim(claim("DEVICE", "dev-1", "os_version", "17.9.4", evidence=("obs-b",)), NOW)
    fr = twin.entity("DEVICE", "dev-1").fields["os_version"]
    assert fr.value == "17.9.4" and fr.evidence_ids == ("obs-b",)


def test_irrelevant_claim_rejected_and_counted(rig):
    _, counters, twin = rig
    result = twin.apply_claim(claim("DEVICE", "dev-1", "vendor", "evil", relevance="FAIL"), NOW)
    assert result.admission is Admission.REJECTED_NOT_RELEVANT
    assert twin.entity("DEVICE", "dev-1") is None
    assert counters.value("unverified_claims") == 1


def test_non_confirmed_claims_never_mutate(rig):
    _, _, twin = rig
    for status in ("CONFLICTING", "STALE", "WITHDRAWN"):
        result = twin.apply_claim(claim("DEVICE", "dev-2", "vendor", "x", status=status), NOW)
        assert result.admission is Admission.REJECTED_NOT_CONFIRMED
    assert twin.entity("DEVICE", "dev-2") is None


def test_entity_guard_lookup(rig):
    _, _, twin = rig
    assert not twin.exists("DEVICE", "ghost")
    twin.apply_claim(claim("DEVICE", "dev-1", "vendor", "cisco"), NOW)
    assert twin.exists("DEVICE", "dev-1")


def test_gaps_identity_incomplete_lists_missing_fields(rig):
    _, _, twin = rig
    twin.apply_claim(claim("DEVICE", "dev-1", "vendor", "cisco"), NOW)
    gaps = twin.gaps()
    g = [x for x in gaps if x.kind == "IDENTITY_INCOMPLETE"]
    assert len(g) == 1
    assert "model" in g[0].detail and "os" in g[0].detail and "os_version" in g[0].detail
    assert "vendor" not in g[0].detail.replace("missing fields:", "")


def test_gaps_interface_oper_status_unknown(rig):
    _, _, twin = rig
    twin.apply_claim(claim("INTERFACE", "dev-1:Gi1/0/1", "mtu", 1500, scope="INTERFACE_EXISTENCE"), NOW)
    gaps = twin.gaps()
    assert any(g.kind == "FIELD_UNKNOWN" and g.entity_ref == "dev-1:Gi1/0/1" for g in gaps)
    twin.apply_claim(claim("INTERFACE", "dev-1:Gi1/0/1", "oper_status", "up", scope="INTERFACE_EXISTENCE"), NOW)
    assert not any(g.kind == "FIELD_UNKNOWN" for g in twin.gaps())


def test_gaps_link_states_below_confirmed(rig):
    _, _, twin = rig
    twin.apply_claim(claim("LINK", "link-a", "link_state", "INFERRED", scope="DIRECT_NEIGHBOR"), NOW)
    twin.apply_claim(claim("LINK", "link-b", "link_state", "DIRECT_NEIGHBOR_CONFIRMED", scope="DIRECT_NEIGHBOR"), NOW)
    kinds = {(g.entity_ref, g.kind) for g in twin.gaps()}
    assert ("link-a", "LINK_EVIDENCE_BELOW_CONFIRMED") in kinds
    assert not any(ref == "link-b" for ref, _ in kinds)


def test_layers_projection(rig):
    _, _, twin = rig
    twin.apply_claim(claim("INTERFACE", "dev-1:Gi1/0/1", "mtu", 1500, scope="INTERFACE_EXISTENCE"), NOW)
    twin.apply_claim(claim("INTERFACE", "dev-1:Gi1/0/1", "oper_status", "up", scope="INTERFACE_EXISTENCE"), NOW)
    layers = twin.entity("INTERFACE", "dev-1:Gi1/0/1").layers_present()
    assert TwinLayer.LOGICAL in layers and TwinLayer.OPERATIONAL in layers


def test_entities_filter_sorted(rig):
    _, _, twin = rig
    twin.apply_claim(claim("DEVICE", "b-device", "vendor", "x"), NOW)
    twin.apply_claim(claim("DEVICE", "a-device", "vendor", "y"), NOW)
    twin.apply_claim(claim("INTERFACE", "a-device:e1", "mtu", 1500, scope="INTERFACE_EXISTENCE"), NOW)
    devices = twin.entities("DEVICE")
    assert [e.entity_ref for e in devices] == ["a-device", "b-device"]
    assert len(twin.entities()) == 3
