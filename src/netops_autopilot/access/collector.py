"""E02 Collector — evidence production with budgets, breakers, locks.

Pipeline per collection (D0-04 chain head):
    allowlist check → lock/human-session check → breaker check →
    session.execute (timeout/output budget) → Event(signed) → RawArtifact.

Every step failure is a typed Failure (L03); nothing is silently retried
beyond budget, nothing executes outside the allowlist (L10/T3).
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from ..adapters.interfaces import ExecSession
from ..core.budgets import CommandBudget, enforce_output_budget
from ..core.failures import Failure, FailureClass
from ..core.ids import new_id
from ..core.timeauth import TimeAuthority, utc_now
from ..ledger.models import (
    ClockStatusEnum,
    CollectorIdentity,
    Event,
    EventType,
    OperatorIdentity,
    RawArtifact,
)
from ..ledger.store import LedgerStore
from .allowlist import CommandAllowlist


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    """Per (device, command) breaker (D0-08 §1, TH-09).

    CLOSED → OPEN after ``threshold`` consecutive failures; OPEN rejects
    until ``cooldown_s`` passes; then HALF_OPEN allows one probe —
    success closes, failure reopens.
    """

    def __init__(self, threshold: int, cooldown_s: float, clock: Callable[[], float] = time.monotonic) -> None:
        if threshold < 1 or cooldown_s <= 0:
            raise ValueError("threshold >= 1 and cooldown_s > 0 required")
        self._threshold = threshold
        self._cooldown_s = cooldown_s
        self._clock = clock
        self._state = CircuitState.CLOSED
        self._consecutive_failures = 0
        self._opened_at: Optional[float] = None

    @property
    def state(self) -> CircuitState:
        if self._state is CircuitState.OPEN and self._clock() - (self._opened_at or 0) >= self._cooldown_s:
            self._state = CircuitState.HALF_OPEN
        return self._state

    def allow_request(self) -> bool:
        return self.state is not CircuitState.OPEN

    def record_success(self) -> None:
        self._consecutive_failures = 0
        self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._threshold:
            self._state = CircuitState.OPEN
            self._opened_at = self._clock()


class SessionLockManager:
    """Device-level session locking + human-session pause (TH-13, §10)."""

    def __init__(self) -> None:
        self._locked_by: dict[str, str] = {}
        self._human_sessions: set[str] = set()

    def acquire(self, device_ref: str, owner: str) -> bool:
        if device_ref in self._human_sessions:
            return False
        holder = self._locked_by.get(device_ref)
        if holder is not None and holder != owner:
            return False
        self._locked_by[device_ref] = owner
        return True

    def release(self, device_ref: str, owner: str) -> None:
        if self._locked_by.get(device_ref) == owner:
            del self._locked_by[device_ref]

    def declare_human_session(self, device_ref: str) -> None:
        self._human_sessions.add(device_ref)

    def clear_human_session(self, device_ref: str) -> None:
        self._human_sessions.discard(device_ref)

    def human_session_active(self, device_ref: str) -> bool:
        return device_ref in self._human_sessions


@dataclass(frozen=True)
class CollectResult:
    event: Event
    artifact: RawArtifact
    output: bytes
    truncated: bool


class Collector:
    """E02: executes allowlisted read-only operations and records evidence.

    Only READ_ONLY commands are executable here (allowlist rule 2); config
    application belongs to E15 with gates (D3).
    """

    OWNER = "E02-collector"

    def __init__(
        self,
        store: LedgerStore,
        key_id: str,
        allowlist: CommandAllowlist,
        time_authority: TimeAuthority,
        locks: SessionLockManager,
        *,
        collector_id: str = "collector-0",
        default_budget: Optional[CommandBudget] = None,
        breaker_cooldown_s: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._key_id = key_id
        self._allowlist = allowlist
        self._time = time_authority
        self._locks = locks
        self._collector_id = collector_id
        self._budget = default_budget or CommandBudget()
        self._breakers: dict[tuple[str, str], CircuitBreaker] = {}
        self._breaker_threshold = self._budget.breaker_threshold
        self._cooldown_s = breaker_cooldown_s
        self._clock = clock

    # ------------------------------------------------------------- internals
    def _breaker(self, device_ref: str, command: str) -> CircuitBreaker:
        key = (device_ref, command)
        if key not in self._breakers:
            self._breakers[key] = CircuitBreaker(self._breaker_threshold, self._cooldown_s, self._clock)
        return self._breakers[key]

    def _event_type(self, session_kind: str) -> EventType:
        return EventType.SERIAL if session_kind == "serial" else EventType.CLI

    # ------------------------------------------------------------------ API
    def collect(
        self,
        *,
        device_ref: str,
        command: str,
        session: ExecSession,
        session_kind: str = "cli",
        budget: Optional[CommandBudget] = None,
    ) -> CollectResult:
        """Execute one allowlisted read-only command; record Event+Artifact.

        Raises Failure(BLOCKED) for preconditions, Failure(RETRYABLE) for
        transient transport errors within retry budget.
        """
        # 1. Allowlist (L10/T3) — explicit, typed, never defaulted.
        if not self._allowlist.is_readable(command):
            cls = self._allowlist.classify(command)
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(f"COMMAND_NOT_ALLOWED: {command!r} class={cls or 'UNREGISTERED'} (READ_ONLY only here)",),
            )

        # 2. Human session / locking (TH-13, FSM-2 concurrency).
        if self._locks.human_session_active(device_ref):
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(f"HUMAN_SESSION_ACTIVE: automation paused for {device_ref} (TH-13)",),
            )
        if not self._locks.acquire(device_ref, self.OWNER):
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(f"SESSION_LOCK_HELD: {device_ref} locked by another owner",),
            )

        breaker = self._breaker(device_ref, command)
        if not breaker.allow_request():
            raise Failure(
                cls=FailureClass.RETRYABLE,
                causes=(f"CIRCUIT_OPEN: {device_ref}/{command!r} breaker open after repeated failures",),
                retry_hint=f"retry after cooldown ({self._cooldown_s}s)",
            )

        # 3. Execute within budget; retries bounded by budget.max_retries.
        b = budget or self._budget
        payload: bytes = b""
        truncated = False
        last_error: Optional[Exception] = None
        for attempt in range(b.max_retries + 1):
            try:
                payload = session.execute(command, b.timeout_s)
                payload, truncated, _ = enforce_output_budget(payload, b)
                last_error = None
                break
            except (TimeoutError, ConnectionError) as exc:
                last_error = exc
        if last_error is not None:
            breaker.record_failure()
            raise Failure(
                cls=FailureClass.RETRYABLE,
                causes=(f"TRANSPORT_ERROR: {type(last_error).__name__}: {last_error}",),
                retry_hint="breaker counts failures; circuit opens at threshold",
            )

        breaker.record_success()

        # 4. Record evidence: signed Event + content-addressed RawArtifact.
        event = Event(
            type=self._event_type(session_kind),
            device_id=device_ref,
            session_id=None,
            command_or_op=command,
            operator_identity=OperatorIdentity(kind="ENGINE", id="E02"),
            collector_identity=CollectorIdentity(collector_id=self._collector_id, key_id=self._key_id),
            collected_at=self._time.now(),
            collector_clock_status=ClockStatusEnum(self._time.status.value),
        )
        event = self._store.sign_event(event, self._key_id)
        self._store.append_event(event)
        artifact = RawArtifact(
            raw_id=new_id(),
            event_id=event.event_id,
            storage_uri=f"ledger://artifacts/{event.event_id}",
            sha256=hashlib.sha256(payload).hexdigest(),
            bytes=len(payload),
            truncated=truncated,
            budget_reason=None if not truncated else f"OUTPUT_BUDGET_EXCEEDED at {b.max_output_bytes} bytes",
        )
        self._store.append_raw_artifact(artifact)

        self._locks.release(device_ref, self.OWNER)
        return CollectResult(event=event, artifact=artifact, output=payload, truncated=truncated)
