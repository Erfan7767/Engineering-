"""Tests for the rate limiter and LRU cache."""

from __future__ import annotations

import threading

import pytest

from netops_autopilot.core.cache import LRUCache, CacheStats
from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.core.ratelimit import RateLimiter, RateLimitPolicy


# ----------------- RateLimiter -----------------


class _FakeClock:
    def __init__(self) -> None:
        self.t = 0.0
    def __call__(self) -> float:
        return self.t
    def advance(self, dt: float) -> None:
        self.t += dt


def test_policy_rejects_zero_capacity():
    with pytest.raises(ValueError):
        RateLimitPolicy(capacity=0, refill_per_s=1.0)


def test_policy_rejects_zero_refill():
    with pytest.raises(ValueError):
        RateLimitPolicy(capacity=10, refill_per_s=0)


def test_initial_tokens_equal_capacity():
    policy = RateLimitPolicy(capacity=5, refill_per_s=1.0)
    rl = RateLimiter(policy, clock=_FakeClock())
    assert rl.available_tokens == 5


def test_acquire_decrements_tokens():
    policy = RateLimitPolicy(capacity=5, refill_per_s=1.0)
    rl = RateLimiter(policy, clock=_FakeClock())
    rl.acquire(2)
    assert rl.available_tokens == 3


def test_acquire_too_many_raises_retryable():
    policy = RateLimitPolicy(capacity=2, refill_per_s=1.0)
    rl = RateLimiter(policy, clock=_FakeClock())
    rl.acquire(2)
    with pytest.raises(Failure) as exc:
        rl.acquire(1)
    assert exc.value.cls is FailureClass.RETRYABLE
    assert "RATE_LIMITED" in exc.value.causes[0]


def test_tokens_refill_over_time():
    clock = _FakeClock()
    policy = RateLimitPolicy(capacity=2, refill_per_s=2.0)  # 2 tokens / sec
    rl = RateLimiter(policy, clock=clock)
    rl.acquire(2)
    assert rl.available_tokens == 0
    clock.advance(0.5)
    assert rl.available_tokens == 1
    clock.advance(0.5)
    assert rl.available_tokens == 2
    # Cap at capacity.
    clock.advance(100.0)
    assert rl.available_tokens == 2


def test_acquire_rejects_zero_and_negative():
    rl = RateLimiter(RateLimitPolicy(capacity=1, refill_per_s=1.0), clock=_FakeClock())
    with pytest.raises(ValueError):
        rl.acquire(0)
    with pytest.raises(ValueError):
        rl.acquire(-1)


def test_concurrent_acquire_respects_capacity():
    """100 threads each try to take 1 token from capacity=10; only 10 succeed."""
    policy = RateLimitPolicy(capacity=10, refill_per_s=0.001)  # almost no refill
    rl = RateLimiter(policy, clock=_FakeClock())
    successes = []
    failures = []
    lock = threading.Lock()

    def worker():
        try:
            rl.acquire(1)
            with lock:
                successes.append(1)
        except Failure:
            with lock:
                failures.append(1)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Exactly 10 successes; the rest are rate-limited.
    assert len(successes) == 10
    assert len(failures) == 40


# ----------------- LRUCache -----------------


def test_cache_rejects_zero_capacity():
    with pytest.raises(ValueError):
        LRUCache(capacity=0)


def test_cache_miss_returns_default():
    c: LRUCache[str, int] = LRUCache(capacity=2)
    assert c.get("missing") is None
    assert c.get("missing", default=42) == 42


def test_cache_hit_returns_value():
    c: LRUCache[str, int] = LRUCache(capacity=2)
    c.set("a", 1)
    assert c.get("a") == 1
    s = c.stats
    assert s.hits == 1
    assert s.misses == 0


def test_cache_miss_increments_misses():
    c: LRUCache[str, int] = LRUCache(capacity=2)
    c.get("x")
    assert c.stats.misses == 1


def test_cache_evicts_least_recently_used():
    c: LRUCache[str, int] = LRUCache(capacity=2)
    c.set("a", 1)
    c.set("b", 2)
    # Touch "a" so "b" is now LRU.
    c.get("a")
    c.set("c", 3)  # should evict "b"
    assert c.get("b") is None
    assert c.get("a") == 1
    assert c.get("c") == 3
    s = c.stats
    assert s.evictions == 1


def test_cache_overwrite_does_not_evict():
    c: LRUCache[str, int] = LRUCache(capacity=2)
    c.set("a", 1)
    c.set("a", 99)
    assert c.get("a") == 99
    s = c.stats
    assert s.evictions == 0


def test_cache_delete():
    c: LRUCache[str, int] = LRUCache(capacity=2)
    c.set("a", 1)
    assert c.delete("a") is True
    assert c.delete("a") is False
    assert c.get("a") is None


def test_cache_clear_resets_state():
    c: LRUCache[str, int] = LRUCache(capacity=2)
    c.set("a", 1)
    c.get("a")
    c.get("missing")
    c.clear()
    s = c.stats
    assert s.hits == 0
    assert s.misses == 0
    assert s.size == 0


def test_cache_len_and_contains():
    c: LRUCache[str, int] = LRUCache(capacity=3)
    c.set("a", 1)
    c.set("b", 2)
    assert len(c) == 2
    assert "a" in c
    assert "missing" not in c


def test_cache_keys_returns_list():
    c: LRUCache[str, int] = LRUCache(capacity=3)
    c.set("a", 1)
    c.set("b", 2)
    keys = c.keys()
    assert set(keys) == {"a", "b"}


def test_cache_hit_rate():
    c: LRUCache[str, int] = LRUCache(capacity=2)
    c.set("a", 1)
    c.get("a")  # hit
    c.get("a")  # hit
    c.get("x")  # miss
    assert c.stats.hit_rate == pytest.approx(2 / 3)


def test_cache_thread_safety():
    c: LRUCache[int, int] = LRUCache(capacity=100)
    def worker(start: int):
        for i in range(start, start + 50):
            c.set(i, i * 2)
            c.get(i)
    threads = [threading.Thread(target=worker, args=(i * 50,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # The cache should never have more than 100 items.
    assert len(c) <= 100
    s = c.stats
    assert s.hits + s.misses >= 4 * 50


def test_cache_eviction_count_increments():
    c: LRUCache[int, int] = LRUCache(capacity=2)
    for i in range(10):
        c.set(i, i)
    # 8 evictions expected.
    assert c.stats.evictions == 8
