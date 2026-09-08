"""T5 release-gate counters (master spec §2 T5, docs/D0/10).

The harness computes these from ledger/decision records of scenario runs;
the collector here is the in-process accumulator used by engines and the
FSM runtime during a run. Release requires ALL counters == 0.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterator

#: The ten release-gate counters, exactly as named in §2 T5.
T5_COUNTERS: tuple[str, ...] = (
    "unauthorized_changes",
    "unsupported_PASS",
    "entity_hallucinations",
    "scope_violations",
    "credential_exposure",
    "cleanup_leaks",
    "gate_bypass",
    "stale_evidence_deployments",
    "management_path_violations",
    "unverified_claims",
)


class CounterCollector:
    """Accumulates T5 counter increments with reason codes.

    Increments are append-only per run; ``snapshot()`` is what the harness
    report prints. There is no decrement API: counters only ever grow.
    """

    def __init__(self) -> None:
        self._values: dict[str, list[str]] = {name: [] for name in T5_COUNTERS}

    def increment(self, name: str, reason: str) -> None:
        if name not in self._values:
            raise KeyError(f"unknown T5 counter: {name!r} (registry is fixed by spec)")
        self._values[name].append(reason)

    def value(self, name: str) -> int:
        return len(self._values[name])

    def snapshot(self) -> dict[str, int]:
        return {name: len(reasons) for name, reasons in self._values.items()}

    def reasons(self, name: str) -> Iterator[str]:
        return iter(self._values[name])

    def assert_release_gate(self) -> None:
        """Raise if any counter is non-zero (release gate per §2 T5)."""
        bad = {name: len(v) for name, v in self._values.items() if v}
        if bad:
            raise AssertionError(f"T5 release gate FAILED: {bad}")
