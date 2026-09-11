"""Bounded LRU cache — pure Python, thread-safe, no external deps.

Used for short-lived caches (parser results, banner detections) where
unbounded growth would be a memory hazard. The cache evicts the
least-recently-used entry when capacity is reached.

Honors the constitution:

* **L01** — keys are opaque (no semantic inference).
* **L03** — no silent failure; ``get`` returns ``None`` on miss, never
  raises.
* **L08** — no private state outside the cache; the cache is the single
  source of truth for the (k -> v) mapping at the cache boundary.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Generic, Optional, TypeVar

K = TypeVar("K")
V = TypeVar("V")


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0


class LRUCache(Generic[K, V]):
    """A thread-safe LRU cache with bounded capacity."""

    def __init__(self, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._data: "OrderedDict[K, V]" = OrderedDict()
        self._lock = threading.Lock()
        self._stats = CacheStats()

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def stats(self) -> CacheStats:
        with self._lock:
            self._stats.size = len(self._data)
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                size=self._stats.size,
            )

    def get(self, key: K, default: Optional[V] = None) -> Optional[V]:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                self._stats.hits += 1
                return self._data[key]
            self._stats.misses += 1
            return default

    def set(self, key: K, value: V) -> None:
        with self._lock:
            if key in self._data:
                self._data[key] = value
                self._data.move_to_end(key)
                return
            self._data[key] = value
            self._stats.size = len(self._data)
            while len(self._data) > self._capacity:
                self._data.popitem(last=False)
                self._stats.evictions += 1

    def delete(self, key: K) -> bool:
        with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self._stats = CacheStats()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def __contains__(self, key: K) -> bool:
        with self._lock:
            return key in self._data

    def keys(self) -> list[K]:
        with self._lock:
            return list(self._data.keys())
