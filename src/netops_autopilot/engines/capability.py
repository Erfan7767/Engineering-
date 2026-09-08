"""E06 Capability Matrices — the DECIDE cell for feature feasibility (§4).

Two matrices (§11):
* Protocol/Feature matrix: per (platform, feature) × operation with values
  YES | NO | PARTIAL | UNKNOWN.
* Recovery matrix: per (platform, recovery mechanism).

Rules:
* UNKNOWN ⇒ the feature is NOT plannable (T2/L13); planners consult
  :meth:`CapabilityEngine.is_plannable` and nothing else.
* Version constraints are evaluated conservatively: a version string we
  cannot parse against the constraint yields UNKNOWN, never a match.
* LLM output cannot raise a capability value; only lab-evidence updates to
  the data file may (register-tracked growth rule).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from importlib import resources
from typing import Optional


class CapabilityValue(str, Enum):
    YES = "YES"
    NO = "NO"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"

    @property
    def plannable(self) -> bool:
        """Only YES authorizes planning; PARTIAL requires the planner to
        restrict scope, and UNKNOWN/NO forbid it (T2)."""
        return self is CapabilityValue.YES


class RecoveryStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class FeatureCapability:
    vendor_os: str
    feature: str
    values: dict[str, CapabilityValue]
    basis: str
    note: str = ""

    def operation(self, name: str) -> CapabilityValue:
        return self.values.get(name, CapabilityValue.UNKNOWN)


@dataclass(frozen=True)
class RecoveryCapability:
    vendor_os: str
    mechanism: str
    status: RecoveryStatus
    note: str = ""


_NUM_RE = re.compile(r"^(\d+(?:\.\d+)*)")


def parse_version_tuple(version: str) -> Optional[tuple[int, ...]]:
    """Conservative numeric prefix parse: '17.09.04a' → (17,9,4);
    '21.4R3-S5' → (21,4); '7.14.3 (stable)' → (7,14,3).
    Returns None when no numeric core exists — callers must treat that as
    UNKNOWN, never as a match."""
    m = _NUM_RE.match(version.strip())
    if not m:
        return None
    return tuple(int(part) for part in m.group(1).split("."))


def version_satisfies(version: str, constraint: str) -> Optional[bool]:
    """Evaluate a simple constraint ('>=16.9', '>=7.0') against a version.
    Returns None when either side is not parseable or the constraint is
    UNKNOWN — None propagates to UNKNOWN capability (conservative)."""
    if not constraint or constraint.upper() == "UNKNOWN":
        return None
    if not constraint.startswith(">="):
        return None  # only >= constraints exist in v1 data; others ⇒ unknown
    bound_text = constraint[2:].strip()
    version_t = parse_version_tuple(version)
    bound_t = parse_version_tuple(bound_text)
    if version_t is None or bound_t is None:
        return None
    # Compare element-wise with zero padding.
    length = max(len(version_t), len(bound_t))
    v = version_t + (0,) * (length - len(version_t))
    b = bound_t + (0,) * (length - len(bound_t))
    return v >= b


class CapabilityEngine:
    def __init__(self, feature_data: dict, recovery_data: dict) -> None:
        self._feature = feature_data["matrix"]
        self._recovery = recovery_data["matrix"]

    @classmethod
    def load_builtin(cls) -> "CapabilityEngine":
        base = resources.files("netops_autopilot.engines").joinpath("data")
        feature = json.loads(base.joinpath("protocol_feature_matrix.json").read_text(encoding="utf-8"))
        recovery = json.loads(base.joinpath("recovery_matrix.json").read_text(encoding="utf-8"))
        return cls(feature, recovery)

    # ------------------------------------------------------------- features
    def platform_entry(self, vendor_os: str) -> Optional[dict]:
        return self._feature.get(vendor_os)

    def lookup(self, vendor_os: str, version: str, feature: str, operation: str) -> CapabilityValue:
        """Typed capability answer. UNKNOWN is returned (never raised) for
        anything not confirmed: unknown platform, failed version check,
        missing feature, or missing operation."""
        entry = self.platform_entry(vendor_os)
        if entry is None:
            return CapabilityValue.UNKNOWN
        constraint = entry.get("version_constraint", "UNKNOWN")
        if version_satisfies(version, constraint) is not True:
            return CapabilityValue.UNKNOWN
        feat = entry.get("features", {}).get(feature)
        if feat is None:
            return CapabilityValue.UNKNOWN
        return CapabilityValue(str(feat.get(operation, "UNKNOWN")))

    def feature_record(self, vendor_os: str, feature: str) -> Optional[FeatureCapability]:
        entry = self.platform_entry(vendor_os)
        if entry is None:
            return None
        feat = entry.get("features", {}).get(feature)
        if feat is None:
            return None
        values = {op: CapabilityValue(str(feat.get(op, "UNKNOWN"))) for op in feat if op in {
            "discover", "configure", "validate", "rollback", "operational_test", "model_coverage"}}
        return FeatureCapability(vendor_os=vendor_os, feature=feature, values=values,
                                 basis=feat.get("basis", "UNKNOWN"), note=feat.get("note", ""))

    def is_plannable(self, vendor_os: str, version: str, feature: str, operation: str = "configure") -> bool:
        """The single gate planners may use (L13)."""
        return self.lookup(vendor_os, version, feature, operation).plannable

    def features_of(self, vendor_os: str) -> list[str]:
        entry = self.platform_entry(vendor_os)
        return sorted(entry.get("features", {})) if entry else []

    # ------------------------------------------------------------- recovery
    def recovery_lookup(self, vendor_os: str, mechanism: str) -> RecoveryCapability:
        entry = self._recovery.get(vendor_os, {}).get(mechanism)
        if entry is None:
            return RecoveryCapability(vendor_os=vendor_os, mechanism=mechanism,
                                      status=RecoveryStatus.UNKNOWN, note="no matrix entry")
        return RecoveryCapability(vendor_os=vendor_os, mechanism=mechanism,
                                  status=RecoveryStatus(str(entry["status"])), note=entry.get("note", ""))

    def recovery_methods(self, vendor_os: str) -> list[str]:
        return sorted(self._recovery.get(vendor_os, {}))
