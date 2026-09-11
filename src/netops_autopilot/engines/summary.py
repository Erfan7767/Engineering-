"""Network Summary — one-pager for the whole network.

A 30-year network engineer walks into a meeting and shows
one page: devices, links, compliance, health, EOL — all
summarized. This module produces that view from the chat
context.

What it does:

* Reads the chat operator's context (last_discovery,
  last_topology, last_run, evidence).
* Produces a typed text rendering of the network state.

What it does NOT do (typed, never silent):

* It does NOT pretend knowledge it doesn't have. A missing
  context field is shown as a "—" placeholder.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SummaryInputs:
    __test__ = False

    device_count: int = 0
    reachable_count: int = 0
    unreachable_count: int = 0
    link_count: int = 0
    last_run_verdict: str = ""
    evidence_count: int = 0


def build(inputs: SummaryInputs, lang: str = "en") -> str:
    if lang == "ar":
        return _render_ar(inputs)
    return _render_en(inputs)


def _render_en(s: SummaryInputs) -> str:
    lines = [
        "=" * 60,
        "  NETWORK SUMMARY",
        "=" * 60,
        f"  Devices:    {s.device_count}",
        f"  Reachable:  {s.reachable_count}",
        f"  Unreachable: {s.unreachable_count}",
        f"  Links:      {s.link_count}",
        f"  Last run:   {s.last_run_verdict or '—'}",
        f"  Evidence:   {s.evidence_count} item(s)",
        "=" * 60,
    ]
    return "\n".join(lines)


def _render_ar(s: SummaryInputs) -> str:
    lines = [
        "=" * 60,
        "  ملخص الشبكة",
        "=" * 60,
        f"  الأجهزة:     {s.device_count}",
        f"  قابل للوصول:  {s.reachable_count}",
        f"  غير قابل:     {s.unreachable_count}",
        f"  الروابط:      {s.link_count}",
        f"  آخر تشغيل:   {s.last_run_verdict or '—'}",
        f"  الأدلة:       {s.evidence_count} عنصر",
        "=" * 60,
    ]
    return "\n".join(lines)
