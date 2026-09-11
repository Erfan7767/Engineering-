"""Prometheus-compatible metrics registry (text format, no Prometheus client dep).

Exposes ``Counter`` and ``Gauge`` primitives; the ``MetricsRegistry.scrape()``
method returns a Prometheus 0.0.4 text-format payload. Suitable for
sidecar scrapers, ``/metrics`` endpoints, and direct log ingestion.

Counters T1–T6 from the constitution are first-class:
* ``unverified_claims`` (T1)
* ``unsupported_PASS`` (T2)
* ``unauthorized_changes`` (T3)
* ``scope_violations`` (T4)
* (T5 derived in the harness)
* ``rollback_coverage`` (T6 gauge)
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Iterable


@dataclass
class Counter:
    """A monotonically-increasing counter."""

    name: str
    help: str
    value: float = 0.0
    labels: dict[str, str] = field(default_factory=dict)

    def inc(self, n: float = 1.0) -> None:
        if n < 0:
            raise ValueError("Counter cannot decrease")
        self.value += n

    def render(self) -> str:
        labels = ""
        if self.labels:
            kv = ",".join(f'{k}="{v}"' for k, v in sorted(self.labels.items()))
            labels = "{" + kv + "}"
        return f"# HELP {self.name} {self.help}\n# TYPE {self.name} counter\n{self.name}{labels} {self.value}"


@dataclass
class Gauge:
    """A value that can go up and down."""

    name: str
    help: str
    value: float = 0.0
    labels: dict[str, str] = field(default_factory=dict)

    def set(self, v: float) -> None:
        self.value = v

    def inc(self, n: float = 1.0) -> None:
        self.value += n

    def dec(self, n: float = 1.0) -> None:
        self.value -= n

    def render(self) -> str:
        labels = ""
        if self.labels:
            kv = ",".join(f'{k}="{v}"' for k, v in sorted(self.labels.items()))
            labels = "{" + kv + "}"
        return f"# HELP {self.name} {self.help}\n# TYPE {self.name} gauge\n{self.name}{labels} {self.value}"


class MetricsRegistry:
    """A typed metrics registry with the T1–T6 counters pre-registered."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, Counter] = {}
        self._gauges: dict[str, Gauge] = {}
        self._register_constitution_counters()

    def _register_constitution_counters(self) -> None:
        for c in (
            Counter("netops_unverified_claims_total", "T1: claims without valid evidence (counter, 0 for release)"),
            Counter("netops_unsupported_pass_total", "T2: PASS without proper evidence (counter, 0 for release)"),
            Counter("netops_unauthorized_changes_total", "T3: changes outside Authorized State (counter, 0 for release)"),
            Counter("netops_scope_violations_total", "T4: scope violations (counter, 0 for release)"),
            Counter("netops_credential_exposure_total", "L11: credential patterns in user-facing output (counter, 0 for release)"),
            Counter("netops_cleanup_leaks_total", "Temp-resource leaks (counter, 0 for release)"),
            Counter("netops_gate_bypass_total", "Bypass of any gate (counter, 0 for release)"),
            Counter("netops_stale_evidence_deployments_total", "Deployments with stale evidence (counter, 0 for release)"),
            Counter("netops_management_path_violations_total", "Management-path preservation violations (counter, 0 for release)"),
        ):
            self._counters[c.name] = c
        for g in (
            Gauge("netops_ledger_events_total", "Total events in the evidence ledger"),
            Gauge("netops_chain_ok", "1 if the ledger hash chain verifies, else 0"),
            Gauge("netops_runs_total", "Number of completed runs since process start"),
            Gauge("netops_rollback_coverage", "T6: fraction of supported cases that have a verified rollback"),
        ):
            self._gauges[g.name] = g

    def counter(self, name: str) -> Counter:
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name, name.replace("_", " "))
            return self._counters[name]

    def gauge(self, name: str) -> Gauge:
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = Gauge(name, name.replace("_", " "))
            return self._gauges[name]

    def inc_constitution(self, code: str, n: float = 1.0) -> None:
        """Increment the constitutional counter matching ``code``.

        ``code`` is one of: T1, T2, T3, T4, L11, gate_bypass,
        stale_evidence, mgmt_path, cleanup.
        """
        mapping = {
            "T1": "netops_unverified_claims_total",
            "T2": "netops_unsupported_pass_total",
            "T3": "netops_unauthorized_changes_total",
            "T4": "netops_scope_violations_total",
            "L11": "netops_credential_exposure_total",
            "cleanup": "netops_cleanup_leaks_total",
            "gate_bypass": "netops_gate_bypass_total",
            "stale_evidence": "netops_stale_evidence_deployments_total",
            "mgmt_path": "netops_management_path_violations_total",
        }
        name = mapping.get(code.upper())
        if name is None:
            return
        self.counter(name).inc(n)

    def scrape(self) -> str:
        with self._lock:
            parts: list[str] = []
            for c in self._counters.values():
                parts.append(c.render())
            for g in self._gauges.values():
                parts.append(g.render())
            return "\n".join(parts) + "\n"

    def snapshot(self) -> dict[str, float]:
        """Return a JSON-serializable snapshot of all metrics."""
        with self._lock:
            return {
                **{c.name: c.value for c in self._counters.values()},
                **{g.name: g.value for g in self._gauges.values()},
            }
