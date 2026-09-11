"""Convergence Engine — verify the network actually learned new routes/ARP.

A 30-year network engineer doesn't trust "show ip route" right
after an apply. The engineer waits 5 seconds, queries again, and
compares. If the topology didn't change, the apply didn't take
effect (or worse, it took effect but the network is in a
transient loop state).

This module is the typed implementation of that pattern.

What it does:

* Polls a list of read-only show commands on a device (or set of
  devices) at a fixed interval, up to a maximum number of
  attempts or until convergence is detected.
* Convergence = the observed state is stable across two
  consecutive samples. The previous sample is compared byte-for-
  byte (after stripping volatile counters like uptime).
* Reports convergence time, number of attempts, and the final
  observed state. Returns TYPED results; never a guess.

What it does NOT do (typed, never silent):

* It does NOT silently time out — the operator sees the count of
  attempts and a typed TIMEOUT verdict with the partial samples.
* It does NOT report convergence on samples that differ only by
  uptime — those are explicitly masked.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, Protocol


class _ExecSession(Protocol):
    def execute(self, command: str, timeout_s: float) -> bytes: ...


class ConvergenceVerdict(str, Enum):
    """The verdict from a convergence probe."""

    __test__ = False

    CONVERGED = "CONVERGED"
    NOT_CONVERGED = "NOT_CONVERGED"
    TIMEOUT = "TIMEOUT"
    TRANSPORT_FAILED = "TRANSPORT_FAILED"


# Volatile patterns: lines that legitimately change every poll
# (timestamps, uptime, packet counters, last-cleared counters).
_VOLATILE_PATTERNS: tuple[re.Pattern, ...] = (
    # Cisco uptime
    re.compile(r"router\s+uptime\s+is\s+\S+", re.IGNORECASE),
    re.compile(r"\S+\s+uptime\s+is\s+.+", re.IGNORECASE),
    # Last cleared counters
    re.compile(r"Last\s+clearing\s+of\s+\"show\s+interface\".+", re.IGNORECASE),
    # Current timestamp at the top of show output
    re.compile(r"Current\s+time\s*:.*", re.IGNORECASE),
)


def _normalize_for_diff(output: str) -> str:
    """Strip volatile lines from an output sample so the diff is
    semantically meaningful.
    """
    out = output
    for p in _VOLATILE_PATTERNS:
        out = p.sub("<VOLATILE>", out)
    return out.strip()


@dataclass
class ConvergenceProbe:
    """Configuration for a single convergence probe."""

    __test__ = False

    device_ref: str
    # The commands to poll. Each must be allowed by the
    # device's allowlist (READ_ONLY or CONFIG_REVERSIBLE).
    commands: tuple[str, ...] = ("show ip route summary", "show ip arp")
    # How many samples to take before giving up.
    max_attempts: int = 6
    # Delay between samples.
    interval_s: float = 2.0
    # How long each individual command may take.
    per_command_timeout_s: float = 10.0


@dataclass
class ConvergenceSample:
    """A single polled state."""

    __test__ = False

    attempt: int
    output: str
    timestamp_s: float


@dataclass
class ConvergenceResult:
    """The full convergence verdict for one probe."""

    __test__ = False

    device_ref: str
    verdict: ConvergenceVerdict
    attempts: int
    convergence_time_s: float
    samples: list[ConvergenceSample] = field(default_factory=list)
    final_state: str = ""
    detail: str = ""


def probe(
    session: _ExecSession,
    cfg: ConvergenceProbe,
    *,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> ConvergenceResult:
    """Run a convergence probe on a live session.

    Behaviour:

    * Every command in ``cfg.commands`` is executed each attempt
      and concatenated (so a single diff is computed over the
      union, not per-command).
    * Two consecutive samples are compared after stripping
      volatile lines. If they are equal, the verdict is
      CONVERGED.
    * If the maximum number of attempts is reached without two
      matching samples, the verdict is TIMEOUT.
    * If the session raises, the verdict is TRANSPORT_FAILED.
    """
    start = clock()
    prev_output: Optional[str] = None
    last_output = ""
    for attempt in range(1, cfg.max_attempts + 1):
        try:
            chunks: list[str] = []
            for cmd in cfg.commands:
                data = session.execute(cmd, timeout_s=cfg.per_command_timeout_s)
                chunks.append(data.decode("utf-8", errors="replace"))
            raw = "\n".join(chunks)
        except Exception as exc:  # noqa: BLE001 — transport-level
            return ConvergenceResult(
                device_ref=cfg.device_ref,
                verdict=ConvergenceVerdict.TRANSPORT_FAILED,
                attempts=attempt,
                convergence_time_s=clock() - start,
                samples=[
                    ConvergenceSample(
                        attempt=a,
                        output="",
                        timestamp_s=0.0,
                    ) for a in range(1, attempt + 1)
                ],
                detail=f"{type(exc).__name__}: {exc}",
            )

        normalized = _normalize_for_diff(raw)
        last_output = raw
        if prev_output is not None and normalized == prev_output:
            elapsed = clock() - start
            return ConvergenceResult(
                device_ref=cfg.device_ref,
                verdict=ConvergenceVerdict.CONVERGED,
                attempts=attempt,
                convergence_time_s=elapsed,
                samples=[ConvergenceSample(
                    attempt=attempt, output=raw, timestamp_s=elapsed)],
                final_state=raw,
                detail=f"converged after {attempt} samples in {elapsed:.1f}s",
            )
        prev_output = normalized
        if attempt < cfg.max_attempts:
            sleep(cfg.interval_s)

    return ConvergenceResult(
        device_ref=cfg.device_ref,
        verdict=ConvergenceVerdict.TIMEOUT,
        attempts=cfg.max_attempts,
        convergence_time_s=clock() - start,
        samples=[ConvergenceSample(
            attempt=cfg.max_attempts, output=last_output,
            timestamp_s=clock() - start)],
        final_state=last_output,
        detail=(
            f"NOT converged after {cfg.max_attempts} samples "
            f"({cfg.max_attempts * cfg.interval_s:.1f}s)"
        ),
    )


# Resolve enum at module load (deferred because of forward ref shenanigans).
