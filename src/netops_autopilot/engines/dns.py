"""DNS Health Engine — recursive resolver sanity checks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class DnsStatus(str, Enum):
    __test__ = False

    NOERROR = "NOERROR"
    NXDOMAIN = "NXDOMAIN"
    SERVFAIL = "SERVFAIL"
    REFUSED = "REFUSED"
    FORMERR = "FORMERR"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DnsAnswer:
    __test__ = False

    name: str
    type: str
    value: str
    ttl: int = 0


@dataclass
class DnsReport:
    __test__ = False

    question: str = ""
    server: str = ""
    status: DnsStatus = DnsStatus.UNKNOWN
    answers: list[DnsAnswer] = field(default_factory=list)
    latency_ms: float = 0.0
    dnssec_validated: bool = False
    raw_output: str = ""

    @property
    def answer_count(self) -> int:
        return len(self.answers)

    @property
    def overall_verdict(self) -> str:
        if self.status == DnsStatus.NOERROR and self.answer_count > 0:
            return "OK"
        if self.status in (
            DnsStatus.SERVFAIL, DnsStatus.FORMERR,
        ):
            return "FAILURE"
        if self.status == DnsStatus.NXDOMAIN:
            return "NXDOMAIN"
        if self.status == DnsStatus.REFUSED:
            return "REFUSED"
        return "UNKNOWN"

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"DNS: {self.question}\n"
                f"  الخادم: {self.server}\n"
                f"  الحالة: {self.status.value}\n"
                f"  الإجابات: {self.answer_count}\n"
                f"  زمن الاستجابة: {self.latency_ms:.1f} مللي ثانية"
            )
        return (
            f"DNS: {self.question}\n"
            f"  Server: {self.server}\n"
            f"  Status: {self.status.value}\n"
            f"  Answers: {self.answer_count}\n"
            f"  Latency: {self.latency_ms:.1f} ms"
        )


_DIG_STATUS = re.compile(r"status:\s+(?P<status>\w+)")
_DIG_ANSWER = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)\s+(?P<ttl>\d+)\s+IN\s+"
    r"(?P<type>[A-Z]+)\s+(?P<value>\S+)\s*$",
    re.MULTILINE,
)
_DIG_SERVER = re.compile(
    r";; SERVER:\s+(?P<server>[\d.]+)#\d+\((?P<name>[^)]+)\)"
)
_DIG_QUERY = re.compile(
    r";; QUESTION SECTION:\s*;\s*(?P<name>[A-Za-z0-9._-]+)"
)
_DIG_TIME = re.compile(r";; Query time:\s+(?P<ms>\d+)\s+msec")


def parse_dig(output: str) -> DnsReport:
    """Parse ``dig +all`` output."""
    rep = DnsReport(raw_output=output or "")
    if not output or not output.strip():
        return rep
    m = _DIG_QUERY.search(output)
    if m:
        rep.question = m.group("name")
    m = _DIG_SERVER.search(output)
    if m:
        rep.server = m.group("server")
    m = _DIG_STATUS.search(output)
    if m:
        try:
            rep.status = DnsStatus(m.group("status"))
        except ValueError:
            rep.status = DnsStatus.UNKNOWN
    for m in _DIG_ANSWER.finditer(output):
        try:
            ttl = int(m.group("ttl"))
        except ValueError:
            ttl = 0
        rep.answers.append(DnsAnswer(
            name=m.group("name"),
            type=m.group("type"),
            value=m.group("value"),
            ttl=ttl,
        ))
    m = _DIG_TIME.search(output)
    if m:
        try:
            rep.latency_ms = float(m.group("ms"))
        except ValueError:
            pass
    return rep
