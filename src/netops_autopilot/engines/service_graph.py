"""P1-34 Service Dependency Graph — services declare depends_on/provides.

Consumers:
* Dependency DAG (E12, D3): permanent constraint "AAA/NTP/PKI before
  dependents" is realized here as data, not prose.
* Blast Radius (E13): service impact fans out along dependents.
* Intent Compiler (E08): required-service resolution & ordering.

Determinism: topological order is Kahn's algorithm over a SORTED frontier —
identical inputs produce identical orderings on every run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Iterable

from ..core.failures import Failure, FailureClass


@dataclass(frozen=True)
class ServiceNode:
    name: str
    provides: tuple[str, ...]
    depends_on: tuple[str, ...]
    note: str = ""


class ServiceGraph:
    def __init__(self, services: dict[str, ServiceNode]) -> None:
        self._services = dict(services)
        # Referential integrity is checked once, at construction (fail-fast).
        for node in self._services.values():
            for dep in node.depends_on:
                if dep not in self._services:
                    raise Failure(
                        cls=FailureClass.FATAL,
                        causes=(f"SERVICE_GRAPH_DANGLING: {node.name} depends_on unknown {dep!r}",),
                    )
        self._check_cycles()

    # ------------------------------------------------------------ loading
    @classmethod
    def from_data(cls, data: dict) -> "ServiceGraph":
        nodes = {
            name: ServiceNode(name=name,
                              provides=tuple(spec.get("provides", ())),
                              depends_on=tuple(spec.get("depends_on", ())),
                              note=spec.get("note", ""))
            for name, spec in data.get("services", {}).items()
        }
        return cls(nodes)

    @classmethod
    def load_builtin(cls) -> "ServiceGraph":
        raw = resources.files("netops_autopilot.engines").joinpath(
            "data/service_dependencies.json").read_text(encoding="utf-8")
        return cls.from_data(json.loads(raw))

    # ------------------------------------------------------------ queries
    def service(self, name: str) -> ServiceNode:
        try:
            return self._services[name]
        except KeyError:
            raise Failure(cls=FailureClass.BLOCKED,
                          causes=(f"SERVICE_UNKNOWN: {name!r} not in dependency graph",)) from None

    def names(self) -> list[str]:
        return sorted(self._services)

    def provides_token(self, token: str) -> list[str]:
        return sorted(n for n, s in self._services.items() if token in s.provides)

    def dependencies_of(self, name: str, *, transitive: bool = True) -> list[str]:
        """Deterministic sorted dependency list (transitive closure by default)."""
        root = self.service(name)
        if not transitive:
            return sorted(root.depends_on)
        seen: set[str] = set()
        stack = list(root.depends_on)
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(self._services[current].depends_on)
        return sorted(seen)

    def dependents_of(self, name: str) -> list[str]:
        """Everything that (transitively) depends on this service."""
        self.service(name)
        seen: set[str] = set()
        frontier = [name]
        while frontier:
            current = frontier.pop()
            for candidate, node in self._services.items():
                if current in node.depends_on and candidate not in seen:
                    seen.add(candidate)
                    frontier.append(candidate)
        return sorted(seen)

    def order_for(self, services: Iterable[str]) -> list[str]:
        """Bring-up order for the requested services INCLUDING all their
        transitive dependencies, topologically sorted (deterministic)."""
        required: set[str] = set()
        for name in services:
            required.add(self.service(name).name)
            required.update(self.dependencies_of(name))
        indegree = {name: len([d for d in self._services[name].depends_on if d in required])
                    for name in required}
        frontier = sorted(n for n, d in indegree.items() if d == 0)
        order: list[str] = []
        while frontier:
            current = frontier.pop(0)
            order.append(current)
            for name in sorted(required):
                if current in self._services[name].depends_on:
                    indegree[name] -= 1
                    if indegree[name] == 0:
                        frontier.append(name)
            frontier.sort()
        if len(order) != len(required):
            raise Failure(cls=FailureClass.FATAL, causes=("SERVICE_GRAPH_CYCLE: ordering impossible",))
        return order

    # ------------------------------------------------------------ integrity
    def _check_cycles(self) -> None:
        for name in self._services:
            seen: set[str] = set()
            stack = [name]
            while stack:
                current = stack.pop()
                for dep in self._services[current].depends_on:
                    if dep == name:
                        raise Failure(cls=FailureClass.FATAL,
                                      causes=(f"SERVICE_GRAPH_CYCLE: {name} transitively depends on itself",))
                    if dep not in seen:
                        seen.add(dep)
                        stack.append(dep)
