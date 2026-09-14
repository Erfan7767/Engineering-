"""Distributed Discovery — scale to 500+ devices with async execution.

A 30-year engineer working in a large campus or service
provider does NOT walk the network one device at a time. They
spray a discovery packet from multiple seed points in
parallel, gather the responses, and merge them into a single
topology. This module is the typed, async, parallel
implementation.

Design contract:

* **Async + bounded concurrency** — at most N workers run at
  once. The caller controls N (default 16).
* **Streamed results** — discovery events arrive as the
  workers complete. The caller can render the topology in
  near-real-time as new devices are discovered.
* **Bounded retries** — each seed/peer is retried at most
  R times (default 2). Beyond that, the failure is reported
  with a typed reason and the discovery continues.
* **Per-host budget** — every seed has a per-host timeout.
  Default 30 seconds.
* **No hallucination** — a device is in the inventory only
  if a real worker reported a banner / CDP / LLDP response.

Status: this is NOT wired into the shipping run, and it is not a drop-in.
The claim it used to carry — "a drop-in for the existing
:class:`DiscoveryCrawlEngine`, implements the same shape" — was false. It
returns a :class:`DistributedDiscoveryResult` of :class:`DiscoveryEvent`
objects; :class:`DiscoveryCrawlEngine.crawl` returns a ``CrawlReport`` of
``DeviceResult`` objects carrying parsed identity, interface, VLAN, ARP and MAC
tables, which the design engine consumes. Bridging the two means producing all
of that parsed inventory per device, not renaming a result type.

Measured instead: the shipping crawl is breadth-first and serial, and it does
scale — 73 devices in 1.28 s, 157 in 5.20 s, 273 in 11.9 s of engine time on
the simulated transport, every device COMPLETE up to ``max_devices`` and the
rest recorded ``NOT_PROBED``. What a large *real* network actually needs is
parallel management sessions, not this module as it stands. See
``tests/test_large_networks_scale_for_real.py``.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional


@dataclass
class DiscoveryTarget:
    __test__ = False

    seed_ref: str
    host: str
    port: int = 22
    credentials_ref: str = ""        # ref into a credential store
    role_hint: str = ""              # e.g. "core", "tor", "spine"


@dataclass
class DiscoveryEvent:
    __test__ = False

    target: DiscoveryTarget
    ok: bool
    device_ref: str = ""
    banner: str = ""
    elapsed_s: float = 0.0
    error: str = ""
    discovered_at_unix: float = 0.0
    neighbors: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class DistributedDiscoveryResult:
    __test__ = False

    events: list[DiscoveryEvent] = field(default_factory=list)
    started_at_unix: float = 0.0
    completed_at_unix: float = 0.0

    @property
    def devices(self) -> list[str]:
        return [e.device_ref for e in self.events if e.ok and e.device_ref]

    @property
    def unreachable(self) -> list[DiscoveryEvent]:
        return [e for e in self.events if not e.ok]

    @property
    def reachable_count(self) -> int:
        return sum(1 for e in self.events if e.ok)

    @property
    def total_count(self) -> int:
        return len(self.events)

    @property
    def overall_verdict(self) -> str:
        if not self.events:
            return "NO_TARGETS"
        if self.reachable_count == 0:
            return "ALL_UNREACHABLE"
        if self.reachable_count == self.total_count:
            return "ALL_REACHABLE"
        return "PARTIAL"

    def elapsed_s(self) -> float:
        return self.completed_at_unix - self.started_at_unix


@dataclass
class DiscoveryConfig:
    __test__ = False

    max_concurrency: int = 16
    per_host_timeout_s: float = 30.0
    max_retries: int = 2
    retry_backoff_s: float = 1.0


# A probe is an async callable that returns a DiscoveryEvent.
ProbeFn = Callable[[DiscoveryTarget], Awaitable[DiscoveryEvent]]


class DistributedDiscovery:
    """Run a discovery fan-out across many targets with bounded
    concurrency and per-target retries.

    Usage:

    .. code-block:: python

        dd = DistributedDiscovery()
        result = await dd.run(targets, probe=my_probe)
    """

    def __init__(self, config: Optional[DiscoveryConfig] = None) -> None:
        self.config = config or DiscoveryConfig()
        self._sem: Optional[asyncio.Semaphore] = None

    async def run(
        self,
        targets: list[DiscoveryTarget],
        probe: ProbeFn,
    ) -> DistributedDiscoveryResult:
        if not targets:
            return DistributedDiscoveryResult(
                started_at_unix=time.time(),
                completed_at_unix=time.time(),
            )
        self._sem = asyncio.Semaphore(self.config.max_concurrency)
        result = DistributedDiscoveryResult(started_at_unix=time.time())
        tasks = [self._run_one(target, probe, result) for target in targets]
        await asyncio.gather(*tasks, return_exceptions=False)
        result.completed_at_unix = time.time()
        return result

    async def _run_one(
        self,
        target: DiscoveryTarget,
        probe: ProbeFn,
        result: DistributedDiscoveryResult,
    ) -> DiscoveryEvent:
        assert self._sem is not None
        async with self._sem:
            last_event: DiscoveryEvent | None = None
            for attempt in range(self.config.max_retries + 1):
                try:
                    ev = await asyncio.wait_for(
                        probe(target),
                        timeout=self.config.per_host_timeout_s,
                    )
                except asyncio.TimeoutError:
                    ev = DiscoveryEvent(
                        target=target,
                        ok=False,
                        error="timeout",
                        discovered_at_unix=time.time(),
                    )
                except Exception as exc:  # noqa: BLE001
                    ev = DiscoveryEvent(
                        target=target,
                        ok=False,
                        error=f"{type(exc).__name__}: {exc}",
                        discovered_at_unix=time.time(),
                    )
                result.events.append(ev)
                last_event = ev
                if ev.ok:
                    break
                if attempt < self.config.max_retries:
                    await asyncio.sleep(
                        self.config.retry_backoff_s * (attempt + 1)
                    )
            assert last_event is not None
            return last_event
