"""QoS Engine — DSCP marking, queues, shaping audit.

A 30-year engineer keeps QoS consistent across the network:
``dscp ef`` for voice, ``af41`` for video, ``default`` for
best-effort. This module is the typed implementation:
parse Cisco ``show policy-map interface`` output, surface
typed :class:`QosPolicy` / :class:`QosClass` records, and
report on policy-map consistency.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class DscpClass(str, Enum):
    __test__ = False

    EF = "ef"
    AF41 = "af41"
    AF31 = "af31"
    AF21 = "af21"
    BE = "be"
    CS1 = "cs1"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class QosClass:
    __test__ = False

    name: str
    dscp: DscpClass = DscpClass.UNKNOWN
    bandwidth_pct: int = 0
    priority: bool = False
    queue_limit: int = 0


@dataclass
class QosPolicy:
    __test__ = False

    name: str
    classes: list[QosClass] = field(default_factory=list)

    @property
    def class_count(self) -> int:
        return len(self.classes)

    @property
    def has_priority(self) -> bool:
        return any(c.priority for c in self.classes)

    @property
    def has_voice(self) -> bool:
        return any(c.dscp == DscpClass.EF for c in self.classes)


@dataclass
class QosReport:
    __test__ = False

    device: str
    policies: list[QosPolicy] = field(default_factory=list)

    @property
    def policy_count(self) -> int:
        return len(self.policies)

    @property
    def has_voice_policies(self) -> int:
        return sum(1 for p in self.policies if p.has_voice)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"QoS: {self.policy_count} سياسة\n"
                f"  بصوت: {self.has_voice_policies}"
            )
        return (
            f"QoS: {self.policy_count} policy(-map(s))\n"
            f"  With voice: {self.has_voice_policies}"
        )


_POLICY_HEADER = re.compile(
    r"^\s*Policy Map\s+(?P<name>\S+)\s*$",
    re.MULTILINE,
)
_CLASS_LINE = re.compile(
    r"^\s*Class\s+(?P<name>\S+)",
    re.MULTILINE,
)
_DSCP_LINE = re.compile(
    r"^\s*dscp\s+(?P<dscp>ef|af\d+|be|cs\d+)",
    re.MULTILINE,
)


def parse_policy_maps(
    device: str,
    output: str,
) -> QosReport:
    """Parse ``show policy-map`` output."""
    rep = QosReport(device=device)
    if not output or not output.strip():
        return rep
    headers = list(_POLICY_HEADER.finditer(output))
    for i, m in enumerate(headers):
        body_start = m.end()
        body_end = (
            headers[i + 1].start() if i + 1 < len(headers)
            else len(output)
        )
        body = output[body_start:body_end]
        policy = QosPolicy(name=m.group("name"))
        for cm in _CLASS_LINE.finditer(body):
            name = cm.group("name")
            dscp = DscpClass.UNKNOWN
            priority = "priority" in body
            for dm in _DSCP_LINE.finditer(body):
                dscp = DscpClass(dm.group("dscp").lower())
                break
            policy.classes.append(QosClass(
                name=name,
                dscp=dscp,
                priority=priority,
            ))
        rep.policies.append(policy)
    return rep
