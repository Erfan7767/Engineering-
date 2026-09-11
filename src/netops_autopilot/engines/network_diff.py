"""Network-wide Config Diff — compare configs across devices.

A 30-year engineer checks: is the running-config the same
on every edge switch? is the ACL identical on every
gateway? This module is the typed implementation: take
``{device: config_text}`` and surface a typed
:class:`NetworkDiffReport` with cross-device similarity.

Design contract:

* **Typed** — :class:`DeviceConfig` carries the device
  reference + the config text.
* **Deterministic** — same input → same report.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DeviceConfig:
    __test__ = False

    device_ref: str
    config: str


@dataclass(frozen=True)
class DeviceSimilarity:
    __test__ = False

    a: str
    b: str
    similarity: float

    @property
    def is_identical(self) -> bool:
        return self.similarity >= 0.999


@dataclass
class NetworkDiffReport:
    __test__ = False

    devices: list[DeviceConfig] = field(default_factory=list)
    pairs: list[DeviceSimilarity] = field(default_factory=list)

    @property
    def device_count(self) -> int:
        return len(self.devices)

    @property
    def identical_pairs(self) -> list[DeviceSimilarity]:
        return [p for p in self.pairs if p.is_identical]

    @property
    def divergent_pairs(self) -> list[DeviceSimilarity]:
        return [p for p in self.pairs if not p.is_identical]

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"فرق الشبكة: {self.device_count} جهاز، "
                f"{len(self.divergent_pairs)} متباين"
            )
        return (
            f"Network diff: {self.device_count} device(s), "
            f"{len(self.divergent_pairs)} divergent"
        )


def build_report(
    devices: list[DeviceConfig],
) -> NetworkDiffReport:
    """Build a :class:`NetworkDiffReport` from typed inputs."""
    rep = NetworkDiffReport(devices=list(devices))
    for i, a in enumerate(devices):
        for b in devices[i + 1:]:
            sim = difflib.SequenceMatcher(
                a=a.config.splitlines(),
                b=b.config.splitlines(),
                autojunk=False,
            ).ratio()
            rep.pairs.append(DeviceSimilarity(
                a=a.device_ref,
                b=b.device_ref,
                similarity=sim,
            ))
    return rep
