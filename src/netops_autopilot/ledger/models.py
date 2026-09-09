"""Ledger record models — pydantic mirrors of ``specs/schemas/*.schema.json``.

The JSON Schemas are the normative contract; these models exist so engines
get typed construction. ``tests/test_schemas.py`` round-trips instances
through the JSON Schemas to prove they cannot diverge silently.

Field names match the schemas exactly (snake_case).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..core.ids import new_id


class _LedgerModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


class EventType(str, Enum):
    CLI = "CLI"
    NETCONF = "NETCONF"
    RESTCONF = "RESTCONF"
    SNMP = "SNMP"
    API = "API"
    SERIAL = "SERIAL"
    PROBE = "PROBE"
    USER = "USER"
    SYSLOG = "SYSLOG"
    TRAP = "TRAP"
    TELEMETRY = "TELEMETRY"


class ClockStatusEnum(str, Enum):
    SYNCED = "SYNCED"
    UNSYNCED = "UNSYNCED"
    DRIFT_SUSPECTED = "DRIFT_SUSPECTED"


class OperatorIdentity(_LedgerModel):
    kind: str  # ENGINE | HUMAN | AGENT (validated below)
    id: str = Field(min_length=1)
    rbac_role: Optional[str] = None
    mfa_verified: Optional[bool] = None

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in {"ENGINE", "HUMAN", "AGENT"}:
            raise ValueError("kind must be ENGINE|HUMAN|AGENT")
        return v


class CollectorIdentity(_LedgerModel):
    collector_id: str = Field(min_length=1)
    key_id: str = Field(min_length=1)


class EventSignature(_LedgerModel):
    algorithm: str = "Ed25519"
    key_id: str = Field(min_length=1)
    value_b64: str


class Event(_LedgerModel):
    """Root record of the chain. Signature covers the event WITHOUT the
    signature field itself (canonical JSON, sorted keys)."""

    event_id: str = Field(default_factory=new_id)
    type: EventType
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    command_or_op: str = Field(min_length=1)
    operator_identity: OperatorIdentity
    collector_identity: CollectorIdentity
    collected_at: datetime
    collector_clock_status: ClockStatusEnum
    device_clock_at_collection: Optional[str] = None
    device_clock_status: Optional[str] = None
    signature: Optional[EventSignature] = None

    def signing_payload(self) -> dict:
        data = self.model_dump(mode="json")
        data.pop("signature", None)
        return data


class RawArtifact(_LedgerModel):
    raw_id: str = Field(default_factory=new_id)
    event_id: str
    storage_uri: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bytes: int = Field(ge=0)
    truncated: bool
    budget_reason: Optional[str] = None

    @model_validator(mode="after")
    def _truncated_requires_reason(self) -> "RawArtifact":
        # model_validator covers the default-value case too (field validators
        # skip unset defaults unless validate_default=True).
        if self.truncated and not self.budget_reason:
            raise ValueError("budget_reason required when truncated=true")
        return self


class ParseStatus(str, Enum):
    OK = "OK"
    MISSING = "MISSING"
    PARSE_FAILED = "PARSE_FAILED"
    UNSUPPORTED_FIELD = "UNSUPPORTED_FIELD"


class Observation(_LedgerModel):
    obs_id: str = Field(default_factory=new_id)
    raw_id: str
    parser_id: str = Field(min_length=1)
    parser_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    field: str = Field(min_length=1)
    value: Optional[Any] = None
    parse_status: ParseStatus
    superseded_by: Optional[str] = None

    @model_validator(mode="after")
    def _ok_requires_value(self) -> "Observation":
        if self.parse_status is ParseStatus.OK and self.value is None:
            raise ValueError("value required when parse_status=OK")
        return self


VERIFICATION_SCOPES = (
    "DEVICE_IDENTITY",
    "INTERFACE_EXISTENCE",
    "HARDWARE_INVENTORY",
    "DIRECT_NEIGHBOR",
    "PHYSICAL_PATH",
    "IP_ADDRESS",
    "ROUTING_STATE",
    "CONFIGURATION",
    "SERVICE_REACHABILITY",
    "POLICY_BEHAVIOR",
    "INTENT_COMPLIANCE",
)


class SubjectEntity(_LedgerModel):
    entity_type: str
    entity_ref: str = Field(min_length=1)

    @field_validator("entity_type")
    @classmethod
    def _etype(cls, v: str) -> str:
        allowed = {
            "DEVICE", "CHASSIS", "STACK_MEMBER", "INTERFACE", "VLAN",
            "LINK", "SERVICE", "POLICY", "SITE", "RACK",
        }
        if v not in allowed:
            raise ValueError(f"entity_type must be one of {sorted(allowed)}")
        return v


class FreshnessAtUse(_LedgerModel):
    decision_kind: str
    age_seconds_at_decision: float = Field(ge=0)
    bound_seconds: Optional[float] = None


class ClaimStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    CONFLICTING = "CONFLICTING"
    STALE = "STALE"
    WITHDRAWN = "WITHDRAWN"


class Claim(_LedgerModel):
    """A typed statement admissible only with valid, RELEVANT evidence (T1)."""

    claim_id: str = Field(default_factory=new_id)
    subject_entity: SubjectEntity
    predicate: str = Field(min_length=1)
    value: Any
    evidence_ids: list[str] = Field(min_length=1)
    verification_scope: str
    status: ClaimStatus
    freshness_at_use: Optional[FreshnessAtUse] = None
    relevance_check: str  # PASS | FAIL

    @field_validator("verification_scope")
    @classmethod
    def _scope(cls, v: str) -> str:
        if v not in VERIFICATION_SCOPES:
            raise ValueError(f"verification_scope must be one of {VERIFICATION_SCOPES}")
        return v

    @field_validator("relevance_check")
    @classmethod
    def _rel(cls, v: str) -> str:
        if v not in {"PASS", "FAIL"}:
            raise ValueError("relevance_check must be PASS|FAIL")
        return v


class StateTransition(_LedgerModel):
    """FSM transition record (D0-03 runtime rules)."""

    transition_id: str = Field(default_factory=new_id)
    fsm: str  # FSM-1..FSM-5 label
    entity_ref: str = Field(min_length=1)
    from_state: str = Field(min_length=1)
    to_state: str = Field(min_length=1)
    guard_id: str = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)
    actor: OperatorIdentity
    collected_at: datetime

    @field_validator("fsm")
    @classmethod
    def _fsm(cls, v: str) -> str:
        allowed = {
            "FSM-1_DEVICE", "FSM-2_CHANGE", "FSM-3_ROLLBACK", "FSM-4_LINK",
            "FSM-5_RECOVERY", "TWIN_PROJECTION",
            # AUTOPILOT: capstone run machine (register OI-0160/D5-capstone);
            # its guard table lives in autopilot/orchestrator.py transitions.
            "AUTOPILOT",
        }
        if v not in allowed:
            raise ValueError(f"fsm must be one of {sorted(allowed)}")
        return v
