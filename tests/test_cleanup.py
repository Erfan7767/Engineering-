"""Cleanup (Temporary Resource Manager): register, verify, leak accounting."""

import pytest

from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.core.failures import Failure
from netops_autopilot.engines.cleanup import (
    CleanupManager, PreservedApproval, ResourceKind, TempResource,
)


def res(rid, kind=ResourceKind.ACCOUNT, node_id="n1"):
    return TempResource(resource_id=rid, kind=kind, description=f"temp {rid}", created_by_node=node_id)


@pytest.fixture()
def counters():
    return CounterCollector()


@pytest.fixture()
def manager(counters):
    m = CleanupManager(counters)
    m.register("chg-1", (res("tmp-admin", ResourceKind.ACCOUNT),
                         res("tmp-acl-99", ResourceKind.ACL),
                         res("tmp-vlan-999", ResourceKind.VLAN)))
    return m


# --------------------------------------------------------------- registration
def test_register_is_sorted_and_complete(manager):
    ids = [r.resource_id for r in manager.registered("chg-1")]
    assert ids == sorted(ids)
    assert len(ids) == 3


def test_duplicate_registration_refused(counters):
    m = CleanupManager(counters)
    with pytest.raises(Failure) as exc:
        m.register("chg-1", (res("x"), res("x")))
    assert "TEMP_RESOURCE_DUPLICATE" in exc.value.causes[0]


def test_incomplete_resource_refused():
    with pytest.raises(Failure):
        TempResource(resource_id="", kind=ResourceKind.ACL, description="d", created_by_node="n")


# ------------------------------------------------------------------- verify
def test_all_removed_is_clean_with_zero_evidence(manager, counters):
    report = manager.verify("chg-1", frozenset({"tmp-admin", "tmp-acl-99", "tmp-vlan-999"}))
    assert report.clean and report.leaked == ()
    ev = CleanupManager.evidence_for_fsm2(report)
    assert ev["kind"] == "temp_resources:zero"
    assert counters.value("cleanup_leaks") == 0


def test_leak_is_counted_and_refuses_cleaned_evidence(manager, counters):
    report = manager.verify("chg-1", frozenset({"tmp-admin"}))
    assert report.leaked == ("tmp-acl-99", "tmp-vlan-999")
    assert counters.value("cleanup_leaks") == 2  # one increment per leak (T5)
    assert "chg-1:tmp-acl-99:ACL" in list(counters.reasons("cleanup_leaks"))
    with pytest.raises(Failure) as exc:
        CleanupManager.evidence_for_fsm2(report)
    assert "CLEANUP_LEAK" in exc.value.causes[0]


def test_untracked_removal_gets_no_credit(manager):
    with pytest.raises(Failure) as exc:
        manager.verify("chg-1", frozenset({"tmp-admin", "ghost-resource"}))
    assert "CLEANUP_REMOVAL_UNTRACKED" in exc.value.causes[0]


def test_unknown_change_register_is_typed(manager):
    with pytest.raises(Failure) as exc:
        manager.verify("chg-999", frozenset())
    assert "CLEANUP_REGISTER_UNKNOWN" in exc.value.causes[0]


# --------------------------------------------------------------- preservation
def test_preservation_requires_approval_with_identity_and_reason(manager, counters):
    with pytest.raises(Failure):
        manager.verify("chg-1", frozenset({"tmp-admin", "tmp-acl-99"}),
                       preserve_ids=frozenset({"tmp-vlan-999"}))  # no approval
    with pytest.raises(Failure):
        PreservedApproval(rbac_identity="", reason="needed")
    report = manager.verify("chg-1", frozenset({"tmp-admin", "tmp-acl-99"}),
                            approval=PreservedApproval("netops-admin@corp", "shared lab VLAN retained by policy"),
                            preserve_ids=frozenset({"tmp-vlan-999"}))
    assert report.clean and report.preserved == ("tmp-vlan-999",)
    ev = CleanupManager.evidence_for_fsm2(report)
    assert ev["kind"] == "temp_resources:preserved_by_approval"
    assert counters.value("cleanup_leaks") == 0


def test_preserving_untracked_resource_refused(manager):
    with pytest.raises(Failure) as exc:
        manager.verify("chg-1", frozenset({"tmp-admin", "tmp-acl-99", "tmp-vlan-999"}),
                       approval=PreservedApproval("x@corp", "r"),
                       preserve_ids=frozenset({"ghost"}))
    assert "CLEANUP_PRESERVATION_UNTRACKED" in exc.value.causes[0]
