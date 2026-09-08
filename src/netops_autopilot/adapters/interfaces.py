"""Adapter interfaces (D0-06 §3) — the nine stable surfaces.

Design rules (spec §6, ADR-0001):
* Missing capability is a TYPED STATE, not an exception: every default
  method announces ``NOT_SUPPORTED`` via a structured Failure (T2).
* No interface method may accept or return raw credentials (L11); secrets
  are resolved by the Access Layer from the Vault at session-open time.
* All methods are evidence-producing or evidence-consuming: they return
  bytes/structured payloads for the Ledger, or typed operation results.
"""

from __future__ import annotations

from abc import ABC
from enum import Enum
from typing import Any, Protocol

from ..core.failures import Failure, FailureClass


class CapabilityState(str, Enum):
    """Typed capability answer — never a guess (T2)."""

    SUPPORTED = "SUPPORTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    UNKNOWN = "UNKNOWN"


def not_supported(op: str) -> Failure:
    """Structured announcement that an adapter capability does not exist."""
    return Failure(
        cls=FailureClass.BLOCKED,
        causes=(f"NOT_SUPPORTED: {op} — adapter announces no implementation (T2)",),
    )


class ExecSession(Protocol):
    """A live device session able to execute allowlisted operations.

    Implementations raise ``TimeoutError`` on budget-exceeding latency and
    ``ConnectionError`` on transport loss; the Collector maps both to typed
    failures (RETRYABLE), never swallowing them (L03).
    """

    def execute(self, command: str, timeout_s: float) -> bytes: ...

    def close(self) -> None: ...


class AdapterBase(ABC):
    """Common adapter root: identity + capability announcement."""

    vendor_family: str = "UNKNOWN"

    def capability(self, operation: str) -> CapabilityState:  # pragma: no cover - overridden
        """Capability Matrix is authoritative (§11); adapters report their
        own mechanical support only, and UNKNOWN is the honest default."""
        return CapabilityState.UNKNOWN


class AccessAdapter(AdapterBase):
    """Session lifecycle, locking, parallel-human-session detection (§10)."""

    def open_session(self, device_ref: str, method: str) -> ExecSession:
        raise not_supported(f"open_session:{method}")

    def close_session(self, device_ref: str) -> None:
        raise not_supported("close_session")

    def acquire_lock(self, device_ref: str) -> bool:
        """Config/session lock; failure ⇒ Collector/Change engine BLOCKs (FSM-2)."""
        raise not_supported("acquire_lock")

    def release_lock(self, device_ref: str) -> None:
        raise not_supported("release_lock")

    def human_session_active(self, device_ref: str) -> bool:
        """Detect concurrent human sessions (TH-13). Default: cannot tell ⇒
        True (fail-safe pause), unless the transport proves exclusivity."""
        return True


class DiscoveryAdapter(AdapterBase):
    """Layered discovery command execution (D0-08 §3)."""

    def run_layer(self, device_ref: str, layer: str) -> bytes:
        raise not_supported(f"discovery_layer:{layer}")


class ConfigAdapter(AdapterBase):
    """Configuration capture & IR application (E09/E15 boundary)."""

    def capture_running_config(self, device_ref: str) -> bytes:
        raise not_supported("capture_running_config")

    def apply_ir(self, device_ref: str, ir_ref: str, dry_run: bool = False) -> Any:
        raise not_supported("apply_ir")


class RollbackAdapter(AdapterBase):
    """FSM-3 mechanics per §14 / ADR-0009."""

    def prepare(self, device_ref: str, method: str) -> Any:
        raise not_supported(f"rollback_prepare:{method}")

    def arm(self, device_ref: str) -> Any:
        raise not_supported("rollback_arm")

    def confirm(self, device_ref: str) -> Any:
        raise not_supported("rollback_confirm")

    def trigger(self, device_ref: str) -> Any:
        raise not_supported("rollback_trigger")

    def verify_after(self, device_ref: str) -> Any:
        raise not_supported("rollback_verify_after")


class RecoveryAdapter(AdapterBase):
    """FSM-5 levels L0..L7. L5+ require a human gate token (HUMAN_ONLY)."""

    def level_supported(self, device_ref: str, level: int) -> CapabilityState:
        return CapabilityState.NOT_SUPPORTED

    def execute_level(self, device_ref: str, level: int, human_gate_token: str | None = None) -> Any:
        if level >= 5 and not human_gate_token:
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(f"DESTRUCTIVE_GATE_REQUIRED: recovery L{level} is human-only in every mode (L06)",),
            )
        raise not_supported(f"recovery_level:{level}")


class VerificationAdapter(AdapterBase):
    """Operational test execution (E19, §15)."""

    def run_test(self, device_ref: str, test_id: str) -> Any:
        raise not_supported(f"test:{test_id}")


class MonitoringAdapter(AdapterBase):
    """Syslog/SNMP/gNMI collectors binding (E27, D5)."""

    def bind_collectors(self, device_ref: str) -> Any:
        raise not_supported("bind_collectors")


class LifecycleAdapter(AdapterBase):
    """Firmware/license state & upgrade-as-Change (E28, D5)."""

    def firmware_state(self, device_ref: str) -> Any:
        raise not_supported("firmware_state")

    def license_state(self, device_ref: str) -> Any:
        raise not_supported("license_state")


class WirelessControlPlaneAdapter(AdapterBase):
    """Controller adoption/provisioning (UniFi/Aruba/FortiAP paths)."""

    def adoption_state(self, device_ref: str) -> Any:
        raise not_supported("adoption_state")

    def adopt(self, device_ref: str) -> Any:
        raise not_supported("adopt")

    def provision(self, device_ref: str, ir_ref: str) -> Any:
        raise not_supported("provision")


#: The nine interface types, in spec order (D0-06 §3).
ALL_ADAPTER_INTERFACES: tuple[type, ...] = (
    AccessAdapter,
    DiscoveryAdapter,
    ConfigAdapter,
    RollbackAdapter,
    RecoveryAdapter,
    VerificationAdapter,
    MonitoringAdapter,
    LifecycleAdapter,
    WirelessControlPlaneAdapter,
)
