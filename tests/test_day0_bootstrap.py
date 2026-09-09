"""E01 Day-0 Bootstrap: ordered, per-step verified, halts typed on failure."""

import pytest

from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.engines.day0_bootstrap import (
    Day0BootstrapEngine,
    StepStatus,
    load_bootstrap_steps,
)
from tests.support.loopback import LoopbackSession


class FakeConfigSession:
    def __init__(self, fail_at_command: str | None = None) -> None:
        self.sent: list[str] = []
        self.fail_at = fail_at_command
        self.closed = False

    def send(self, command: str, timeout_s: float) -> bytes:
        self.sent.append(command)
        if self.fail_at and command.startswith(self.fail_at):
            raise ConnectionError("link dropped mid-config")
        return b""

    def close(self) -> None:
        self.closed = True


def test_steps_loaded_from_profile_data():
    steps = load_bootstrap_steps("cisco_iosxe.json", hostname="edge-01")
    assert len(steps) == 2
    assert steps[0].step_id.startswith("1:hostname")
    assert "hostname edge-01" in steps[0].commands
    assert steps[0].verified_seed is False     # honest until lab evidence
    assert steps[0].verify_contains == "hostname edge-01"


def test_unsupported_family_is_typed_blocked():
    with pytest.raises(Failure) as exc_info:
        load_bootstrap_steps("unifi.json", hostname="ap-01")
    assert any("BOOTSTRAP_NOT_MODELED" in c for c in exc_info.value.causes)


def test_happy_path_orders_and_verifies_then_baselines():
    steps = load_bootstrap_steps("cisco_iosxe.json", hostname="edge-01")
    session = FakeConfigSession()
    captures = iter([
        b"hostname edge-01\nlldp run\n",
        b"hostname edge-01\nlldp run\n",
    ])
    report = Day0BootstrapEngine().execute(
        device_ref="edge-01", hostname="edge-01", steps=steps,
        config_session_factory=lambda: session,
        collect_capture_fn=lambda cmd: next(captures),
        ntp_local_reachable=False)
    assert report.completed
    assert [s.status for s in report.steps] == [StepStatus.VERIFIED, StepStatus.VERIFIED]
    # order preserved, substitution applied
    assert session.sent[2] == "hostname edge-01"
    # baseline hash lineage exists per step
    assert all(s.baseline_sha256 for s in report.steps)
    # NTP deferred is a STATE, not a failure (D0-07 §5)
    assert report.ntp_state == "DEFERRED"


def test_verify_mismatch_halts_typed_no_continuation():
    steps = load_bootstrap_steps("cisco_iosxe.json", hostname="edge-01")
    session = FakeConfigSession()
    report = Day0BootstrapEngine().execute(
        device_ref="edge-01", hostname="edge-01", steps=steps,
        config_session_factory=lambda: session,
        collect_capture_fn=lambda cmd: b"hostname something-else\n")
    assert not report.completed
    assert report.halted_at == "1:hostname"
    assert report.steps[0].status is StepStatus.FAILED
    assert "VERIFY_MISMATCH" in report.steps[0].failure_causes[0]
    # the second step was never touched (no blind continuation)
    assert len(report.steps) == 1


def test_transport_drop_halts_typed():
    steps = load_bootstrap_steps("cisco_iosxe.json", hostname="edge-01")
    session = FakeConfigSession(fail_at_command="hostname")
    report = Day0BootstrapEngine().execute(
        device_ref="edge-01", hostname="edge-01", steps=steps,
        config_session_factory=lambda: session,
        collect_capture_fn=lambda cmd: b"")
    assert not report.completed
    assert "TRANSPORT_ERROR" in report.steps[0].failure_causes[0]


def test_session_refusal_reports_planned_only():
    steps = load_bootstrap_steps("routeros.json", hostname="r1")

    def refuse():
        raise Failure(cls=FailureClass.BLOCKED, causes=("AUTH_REFUSED",))

    report = Day0BootstrapEngine().execute(
        device_ref="r1", hostname="r1", steps=steps,
        config_session_factory=refuse, collect_capture_fn=lambda cmd: b"")
    assert not report.completed
    assert all(s.status is StepStatus.PLANNED for s in report.steps)
