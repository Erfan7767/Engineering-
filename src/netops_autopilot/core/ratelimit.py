"""Rate limiter — token-bucket, deterministic, no wall-clock dependence.

A small rate limiter used to throttle outbound commands (e.g. to a
network device) so that a bug in the orchestrator cannot flood the
device. The implementation is:

* **Deterministic** — uses an injected clock; tests can advance time
  without sleeping.
* **Bounded** — the bucket has a finite capacity; bursts beyond it are
  refused with a typed :class:`Failure(RETRYABLE)`.
* **Composable** — multiple limiters can be nested (e.g. per-device
  and global).

Used by the collector, the harness, and (optionally) the orchestrator
when dispatching many parallel commands.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Optional

from .failures import Failure, FailureClass


Clock = Callable[[], float]


@dataclass(frozen=True)
class RateLimitPolicy:
    """The rate at which the bucket refills.

    Attributes:
        capacity: max tokens the bucket can hold.
        refill_per_s: tokens added per second.
    """
    capacity: float
    refill_per_s: float

    def __post_init__(self) -> None:
        if self.capacity <= 0:
            raise ValueError("capacity must be positive")
        if self.refill_per_s <= 0:
            raise ValueError("refill_per_s must be positive")


class RateLimiter:
    """A token-bucket rate limiter."""

    def __init__(self, policy: RateLimitPolicy, *, clock: Optional[Clock] = None) -> None:
        self._policy = policy
        self._clock = clock or _wall_clock
        self._tokens = policy.capacity
        self._last_refill = self._clock()
        self._lock = threading.Lock()

    @property
    def available_tokens(self) -> float:
        """The current number of tokens (rounded down for display)."""
        with self._lock:
            return self._refill_locked(self._clock())

    def try_acquire(self, n: float = 1.0) -> None:
        """Try to take ``n`` tokens. Raise a typed ``Failure(RETRYABLE)`` if
        the bucket is dry.

        The error message includes the time until enough tokens are
        available, so the caller can decide whether to back off or fail
        a different way.
        """
        if n <= 0:
            raise ValueError("n must be positive")
        with self._lock:
            now = self._clock()
            self._tokens = self._refill_locked(now)
            if self._tokens >= n:
                self._tokens -= n
                return
            needed = n - self._tokens
            wait_s = needed / self._policy.refill_per_s
            raise Failure(
                cls=FailureClass.RETRYABLE,
                causes=(
                    f"RATE_LIMITED: need {n:.1f} tokens, "
                    f"have {self._tokens:.1f}, retry in {wait_s:.3f}s",
                ),
                retry_hint=f"sleep {wait_s:.3f}s and retry",
            )

    def acquire(self, n: float = 1.0) -> None:
        """Alias for :meth:`try_acquire` (semantic clarity in callers)."""
        self.try_acquire(n)

    def _refill_locked(self, now: float) -> float:
        elapsed = max(0.0, now - self._last_refill)
        refill = elapsed * self._policy.refill_per_s
        new_tokens = min(self._policy.capacity, self._tokens + refill)
        self._last_refill = now
        self._tokens = new_tokens
        return new_tokens


def _wall_clock() -> float:
    import time
    return time.monotonic()
