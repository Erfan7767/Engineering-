"""E02 Collector: allowlist gating, locks, breaker, budgets, evidence chain."""

from datetime import datetime, timezone

import pytest

from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
from netops_autopilot.access.collector import Collector, CircuitBreaker, CircuitState, SessionLockManager
from netops_autopilot.core.budgets import CommandBudget
from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.core.timeauth import TimeAuthority
from netops_autopilot.ledger.models import EventType
from netops_autopilot.ledger.store import LedgerStore
from tests.support.loopback import LoopbackSession

NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)

AL = CommandAllowlist((
    AllowlistEntry(template="show version", cls="READ_ONLY", purpose="identity"),
    AllowlistEntry(template="show inventory", cls="READ_ONLY", purpose="hardware"),
    AllowlistEntry(template="write erase", cls="FORBIDDEN"),
))


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


@pytest.fixture()
def rig():
    store = LedgerStore(":memory:")
    key = store.keys.create_key("collector")
    clock = FakeClock()
    collector = Collector(
        store=store,
        key_id=key,
        allowlist=AL,
        time_authority=TimeAuthority(clock=lambda: NOW),
        locks=SessionLockManager(),
        default_budget=CommandBudget(max_retries=1, breaker_threshold=3),
        breaker_cooldown_s=10.0,
        clock=clock,
    )
    session = LoopbackSession({"show version": b"Cisco IOS XE Software, Version 17.09.04a\n"})
    return store, collector, session, clock


def test_happy_path_records_signed_event_and_artifact(rig):
    store, collector, session, _ = rig
    result = collector.collect(device_ref="dev-1", command="show version", session=session)
    assert result.output.startswith(b"Cisco IOS XE")
    assert store.event_count() == 1
    events = store.events()
    assert events[0].device_id == "dev-1"
    assert events[0].type is EventType.CLI
    assert events[0].signature is not None
    assert result.artifact.sha256 and len(result.artifact.sha256) == 64
    assert not result.truncated
    store.integrity_self_test()


def test_unregistered_command_blocked_before_any_execution(rig):
    _, collector, session, _ = rig
    with pytest.raises(Failure) as exc:
        collector.collect(device_ref="dev-1", command="show spanning-tree", session=session)
    assert exc.value.cls is FailureClass.BLOCKED
    assert "COMMAND_NOT_ALLOWED" in exc.value.causes[0]
    assert "UNREGISTERED" in exc.value.causes[0]
    assert session.executed == []  # nothing reached the device


def test_forbidden_command_blocked_typed(rig):
    _, collector, session, _ = rig
    with pytest.raises(Failure) as exc:
        collector.collect(device_ref="dev-1", command="write erase", session=session)
    assert "FORBIDDEN" in exc.value.causes[0]
    assert session.executed == []


def test_human_session_pauses_automation(rig):
    _, collector, session, _ = rig
    collector._locks.declare_human_session("dev-1")
    with pytest.raises(Failure) as exc:
        collector.collect(device_ref="dev-1", command="show version", session=session)
    assert "HUMAN_SESSION_ACTIVE" in exc.value.causes[0]
    collector._locks.clear_human_session("dev-1")
    assert collector.collect(device_ref="dev-1", command="show version", session=session).output


def test_external_lock_blocks(rig):
    _, collector, session, _ = rig
    assert collector._locks.acquire("dev-1", "some-other-owner")
    with pytest.raises(Failure) as exc:
        collector.collect(device_ref="dev-1", command="show version", session=session)
    assert "SESSION_LOCK_HELD" in exc.value.causes[0]


def test_transport_failure_is_retryable_and_counts_breaker(rig):
    _, collector, session, _ = rig
    session.fail_times["show version"] = 99
    with pytest.raises(Failure) as exc:
        collector.collect(device_ref="dev-1", command="show version", session=session)
    assert exc.value.cls is FailureClass.RETRYABLE
    assert exc.value.retry_hint is not None


def test_breaker_opens_after_threshold_then_cooldown(rig):
    _, collector, session, clock = rig
    session.fail_times["show version"] = 99
    for _ in range(3):  # threshold = 3 (budget.breaker_threshold)
        with pytest.raises(Failure):
            collector.collect(device_ref="dev-1", command="show version", session=session)
    breaker = collector._breaker("dev-1", "show version")
    assert breaker.state is CircuitState.OPEN
    # While open: no execution attempt, RETRYABLE with cooldown hint.
    attempts_before = len(session.executed)
    with pytest.raises(Failure) as exc:
        collector.collect(device_ref="dev-1", command="show version", session=session)
    assert "CIRCUIT_OPEN" in exc.value.causes[0]
    assert len(session.executed) == attempts_before
    # After cooldown the breaker half-opens and allows a probe.
    clock.t += 11.0
    assert breaker.state is CircuitState.HALF_OPEN
    session.fail_times["show version"] = 0
    assert collector.collect(device_ref="dev-1", command="show version", session=session).output
    assert breaker.state is CircuitState.CLOSED


def test_output_budget_truncation_recorded(rig):
    _, collector, session, _ = rig
    session.outputs["show version"] = b"x" * 5000
    result = collector.collect(
        device_ref="dev-1", command="show version", session=session,
        budget=CommandBudget(max_output_bytes=1000, max_retries=0, breaker_threshold=2),
    )
    assert result.truncated and len(result.output) == 1000
    assert result.artifact.truncated and result.artifact.budget_reason


def test_circuit_breaker_unit():
    clock = FakeClock()
    cb = CircuitBreaker(threshold=2, cooldown_s=5.0, clock=clock)
    assert cb.allow_request()
    cb.record_failure()
    assert cb.state is CircuitState.CLOSED
    cb.record_failure()
    assert cb.state is CircuitState.OPEN and not cb.allow_request()
    clock.t = 6.0
    assert cb.state is CircuitState.HALF_OPEN and cb.allow_request()
    cb.record_success()
    assert cb.state is CircuitState.CLOSED


def test_session_lock_manager_unit():
    locks = SessionLockManager()
    assert locks.acquire("d", "owner-a")
    assert not locks.acquire("d", "owner-b")
    assert locks.acquire("d", "owner-a")  # reentrant for same owner
    locks.release("d", "owner-a")
    assert locks.acquire("d", "owner-b")
