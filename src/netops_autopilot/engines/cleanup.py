"""Temporary Resource Manager — cleanup verification (FSM-2 guard 2.12).

Every temporary resource a change creates (temp accounts, ACLs, routes,
VLANs, sessions) is REGISTERED before apply and must be proven removed
before the change can reach CLEANED. Two honest outcomes:

* zero leaked resources ⇒ ``temp_resources:zero`` evidence;
* explicit preservation ⇒ ``temp_resources:preserved_by_approval`` with a
  recorded identity — an unreasoned or anonymous preservation is refused
  (D0-02 rule 5 spirit);
* anything else is a LEAK: typed failure AND one ``cleanup_leaks`` counter
  increment per leaked resource (T5) — cleanup failure is never silent (L03).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..core.counters import CounterCollector
from ..core.failures import Failure, FailureClass


class ResourceKind(str, Enum):
    ACCOUNT = "ACCOUNT"
    ACL = "ACL"
    ROUTE = "ROUTE"
    VLAN = "VLAN"
    SESSION = "SESSION"
    TUNNEL = "TUNNEL"


@dataclass(frozen=True)
class TempResource:
    resource_id: str
    kind: ResourceKind
    description: str
    created_by_node: str

    def __post_init__(self) -> None:
        if not self.resource_id or not self.created_by_node:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("TEMP_RESOURCE_INCOMPLETE: id and creating node are mandatory",))


@dataclass(frozen=True)
class PreservedApproval:
    rbac_identity: str
    reason: str

    def __post_init__(self) -> None:
        if not self.rbac_identity or not self.reason:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("PRESERVATION_APPROVAL_INCOMPLETE: identity + reason required (no anonymous keeps)",))


@dataclass(frozen=True)
class CleanupReport:
    change_id: str
    registered: tuple[str, ...]
    removed: tuple[str, ...]
    preserved: tuple[str, ...]
    leaked: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return not self.leaked


class CleanupManager:
    def __init__(self, counters: CounterCollector) -> None:
        self._counters = counters
        self._registered: dict[str, dict[str, TempResource]] = {}

    # ------------------------------------------------------------- register
    def register(self, change_id: str, resources) -> None:
        if not change_id:
            raise Failure(cls=FailureClass.BLOCKED, causes=("CLEANUP_CHANGE_ID_EMPTY",))
        bucket = self._registered.setdefault(change_id, {})
        for resource in resources:
            if resource.resource_id in bucket:
                raise Failure(cls=FailureClass.BLOCKED,
                              causes=(f"TEMP_RESOURCE_DUPLICATE:{resource.resource_id}",))
            bucket[resource.resource_id] = resource

    def registered(self, change_id: str) -> tuple[TempResource, ...]:
        return tuple(sorted(self._registered.get(change_id, {}).values(),
                            key=lambda r: r.resource_id))

    # --------------------------------------------------------------- verify
    def verify(self, change_id: str, observed_removed: frozenset[str],
               approval: PreservedApproval | None = None,
               preserve_ids: frozenset[str] = frozenset()) -> CleanupReport:
        """Compare the register against observed reality. ``preserve_ids``
        requires an approval; unknown removal ids are rejected (no credit
        for resources we never tracked)."""
        bucket = self._registered.get(change_id)
        if bucket is None:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"CLEANUP_REGISTER_UNKNOWN:{change_id}",))
        registered = set(bucket)
        unknown_removed = sorted(observed_removed - registered)
        if unknown_removed:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"CLEANUP_REMOVAL_UNTRACKED:{','.join(unknown_removed)}",))
        if preserve_ids and approval is None:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=("CLEANUP_PRESERVATION_WITHOUT_APPROVAL",))
        unregistered_preserve = sorted(preserve_ids - registered)
        if unregistered_preserve:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"CLEANUP_PRESERVATION_UNTRACKED:{','.join(unregistered_preserve)}",))

        preserved = tuple(sorted(preserve_ids))
        removed = tuple(sorted(observed_removed))
        leaked = tuple(sorted(registered - observed_removed - preserve_ids))
        for resource_id in leaked:
            self._counters.increment("cleanup_leaks",
                                     f"{change_id}:{resource_id}:{bucket[resource_id].kind.value}")
        return CleanupReport(change_id=change_id, registered=tuple(sorted(registered)),
                             removed=removed, preserved=preserved, leaked=leaked)

    # ------------------------------------------------- FSM-2 guard 2.12 feed
    @staticmethod
    def evidence_for_fsm2(report: CleanupReport, evidence_id: str = "cleanup-ev") -> dict:
        scope = "CONFIGURATION"
        if not report.clean:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"CLEANUP_LEAK:{','.join(report.leaked)} — cannot evidence CLEANED",))
        if report.preserved:
            return {"scope": scope, "kind": "temp_resources:preserved_by_approval",
                    "evidence_id": evidence_id, "status": "OK",
                    "detail": ",".join(report.preserved)}
        return {"scope": scope, "kind": "temp_resources:zero",
                "evidence_id": evidence_id, "status": "OK"}
