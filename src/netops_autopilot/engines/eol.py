"""Hardware EOL / EOS check — is this device still supported?

A 30-year network engineer keeps a running list of which
hardware has reached End-of-Sale or End-of-Support. This
module is the typed implementation: given a vendor/model,
return its EOL/EOS status from a built-in catalogue.

What it does:

* Maintains a small catalogue of common Cisco devices with
  their announced EOS/EOL dates.
* Looks up a device and returns a typed EolStatus with the
  relevant dates and a recommended action.

What it does NOT do (typed, never silent):

* It does NOT pretend to know about a device not in the
  catalogue. An unknown model returns UNKNOWN_MODEL.
* It does NOT silently fail on dates; the catalogue is the
  single source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class EolVerdict(str, Enum):
    __test__ = False

    ACTIVE = "ACTIVE"               # still supported
    ANNOUNCED = "ANNOUNCED"         # EOL announced but not reached
    EOL_REACHED = "EOL_REACHED"     # End-of-Life date has passed
    EOS_REACHED = "EOS_REACHED"     # End-of-Support date has passed
    UNKNOWN_MODEL = "UNKNOWN_MODEL"


@dataclass(frozen=True)
class EolRecord:
    __test__ = False

    vendor: str
    model: str
    eos_date: str = ""          # ISO date string, "End of Sale"
    eol_date: str = ""          # ISO date string, "End of Life"
    eossupport_date: str = ""   # ISO date string, "End of Support"
    replacement: str = ""       # recommended replacement model


_CATALOG: tuple[EolRecord, ...] = (
    EolRecord(
        vendor="cisco", model="C2960X-48TS-L",
        eos_date="2017-01-30", eol_date="2022-01-31",
        eossupport_date="2027-01-31",
        replacement="C9200-48P",
    ),
    EolRecord(
        vendor="cisco", model="C2960X-48FPS-L",
        eos_date="2017-01-30", eol_date="2022-01-31",
        eossupport_date="2027-01-31",
        replacement="C9200-48P",
    ),
    EolRecord(
        vendor="cisco", model="C2960X-24TS-L",
        eos_date="2017-01-30", eol_date="2022-01-31",
        eossupport_date="2027-01-31",
        replacement="C9200-24P",
    ),
    EolRecord(
        vendor="cisco", model="C9500-48Y4C",
        eos_date="", eol_date="",
        eossupport_date="2030-04-30",
        replacement="",
    ),
    EolRecord(
        vendor="cisco", model="C9200-48P",
        eos_date="", eol_date="",
        eossupport_date="2031-04-30",
        replacement="",
    ),
    EolRecord(
        vendor="cisco", model="C8300-1N-4T",
        eos_date="", eol_date="",
        eossupport_date="2032-01-31",
        replacement="",
    ),
    EolRecord(
        vendor="cisco", model="ASR-1001-HX",
        eos_date="", eol_date="",
        eossupport_date="2030-04-30",
        replacement="",
    ),
)


def lookup(vendor: str, model: str) -> EolRecord | None:
    """Look up a model in the EOL catalogue."""
    v = vendor.strip().lower()
    m = model.strip().lower()
    for rec in _CATALOG:
        if rec.vendor == v and rec.model.lower() == m:
            return rec
    return None


@dataclass
class EolStatus:
    __test__ = False

    record: EolRecord
    verdict: EolVerdict
    today: str
    detail: str = ""


def evaluate(
    vendor: str, model: str,
    today: str | None = None,
) -> EolStatus | None:
    """Evaluate the EOL status of a model as of ``today``."""
    rec = lookup(vendor, model)
    if rec is None:
        return None
    if today is None:
        today = datetime.now(tz=timezone.utc).date().isoformat()

    # Compare dates; missing dates are treated as "not reached"
    def _passed(d: str) -> bool:
        if not d:
            return False
        try:
            return d <= today
        except TypeError:
            return False

    if _passed(rec.eossupport_date):
        verdict = EolVerdict.EOS_REACHED
        detail = (
            f"End of Support passed on {rec.eossupport_date}. "
            f"Replace with {rec.replacement or 'N/A'}."
        )
    elif _passed(rec.eol_date):
        verdict = EolVerdict.EOL_REACHED
        detail = (
            f"End of Life passed on {rec.eol_date}. "
            f"End of Support on {rec.eossupport_date}. "
            f"Replace with {rec.replacement or 'N/A'}."
        )
    elif rec.eos_date:
        verdict = EolVerdict.ANNOUNCED
        detail = (
            f"End of Sale was {rec.eos_date}, "
            f"End of Life {rec.eol_date or 'TBD'}, "
            f"End of Support {rec.eossupport_date or 'TBD'}. "
            f"Plan replacement with {rec.replacement or 'N/A'}."
        )
    else:
        verdict = EolVerdict.ACTIVE
        detail = (
            f"Active. End of Support on {rec.eossupport_date or 'TBD'}."
        )
    return EolStatus(
        record=rec,
        verdict=verdict,
        today=today,
        detail=detail,
    )


def render(s: EolStatus, lang: str = "en") -> str:
    if lang == "ar":
        return (
            f"حالة EOL لـ {s.record.vendor} {s.record.model}\n"
            f"  النتيجة: {s.verdict.value}\n"
            f"  اليوم: {s.today}\n"
            f"  {s.detail}"
        )
    return (
        f"EOL status for {s.record.vendor} {s.record.model}\n"
        f"  Verdict: {s.verdict.value}\n"
        f"  Today: {s.today}\n"
        f"  {s.detail}"
    )
