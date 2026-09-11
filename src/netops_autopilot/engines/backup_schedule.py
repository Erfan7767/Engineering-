"""Backup Scheduler — typed cron-style schedule + retention.

A 30-year engineer keeps daily / weekly / monthly backups
of every device config. This module is the typed
implementation: declare a :class:`BackupPolicy`, and the
engine returns the next N scheduled run-times as a typed
:class:`BackupScheduleReport`.

Design contract:

* **Typed** — :class:`BackupPolicy` is a frozen dataclass.
* **Deterministic** — same policy → same schedule.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass(frozen=True)
class BackupPolicy:
    __test__ = False

    name: str
    daily_at_hour: int = 2       # 02:00
    weekly_dow: int = 6          # Saturday
    monthly_day: int = 1         # First of month
    retention_daily: int = 7
    retention_weekly: int = 4
    retention_monthly: int = 12


@dataclass(frozen=True)
class BackupEvent:
    __test__ = False

    when: datetime
    kind: str     # daily / weekly / monthly


@dataclass
class BackupScheduleReport:
    __test__ = False

    policy: BackupPolicy
    events: list[BackupEvent] = field(default_factory=list)

    @property
    def event_count(self) -> int:
        return len(self.events)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            head = (
                f"النسخ الاحتياطي '{self.policy.name}': "
                f"{self.event_count} موعد"
            )
        else:
            head = (
                f"Backup '{self.policy.name}': "
                f"{self.event_count} scheduled run(s)"
            )
        return head


def build_schedule(
    policy: BackupPolicy,
    *,
    start: datetime | None = None,
    horizon_days: int = 30,
) -> BackupScheduleReport:
    """Build a :class:`BackupScheduleReport` for ``horizon_days``."""
    if start is None:
        start = datetime.now().replace(
            minute=0, second=0, microsecond=0,
        )
    rep = BackupScheduleReport(policy=policy)
    end = start + timedelta(days=horizon_days)
    cur = start
    while cur < end:
        # Daily backup at ``daily_at_hour``.
        if cur.hour == policy.daily_at_hour:
            rep.events.append(BackupEvent(
                when=cur, kind="daily",
            ))
        # Weekly on ``weekly_dow`` (Monday=0 .. Sunday=6).
        if (
            cur.weekday() == policy.weekly_dow
            and cur.hour == policy.daily_at_hour
        ):
            rep.events.append(BackupEvent(
                when=cur, kind="weekly",
            ))
        # Monthly on ``monthly_day``.
        if (
            cur.day == policy.monthly_day
            and cur.hour == policy.daily_at_hour
        ):
            rep.events.append(BackupEvent(
                when=cur, kind="monthly",
            ))
        cur += timedelta(hours=1)
    return rep
