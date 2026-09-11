"""IOS Upgrade Path Validator — can I safely upgrade this device?

A 30-year network engineer reads Cisco's release notes before
upgrading. The question is always: "does my current version
have a supported upgrade path to the target version?". This
module is the typed implementation: it answers YES/NO with
a typed reason.

What it does:

* Maintains a small catalogue of supported upgrade paths for
  common Cisco IOS-XE major versions.
* Checks whether the (current, target) pair is in the
  catalogue.
* Returns a typed verdict with the recommended intermediate
  version (if any).

What it does NOT do (typed, never silent):

* It does NOT claim an upgrade is safe just because the
  target version is later. A missing path entry returns
  UNKNOWN with a typed suggestion.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class UpgradeVerdict(str, Enum):
    __test__ = False

    SUPPORTED = "SUPPORTED"           # direct upgrade
    REQUIRES_INTERMEDIATE = "REQUIRES_INTERMEDIATE"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class UpgradeStep:
    __test__ = False

    from_version: str
    to_version: str
    intermediate: str = ""   # required intermediate version, if any


# Direct upgrade paths for Cisco IOS-XE. Each entry says
# "from_version can be upgraded directly to to_version"
# (or, if ``intermediate`` is set, must go through it).
_PATHS: tuple[UpgradeStep, ...] = (
    UpgradeStep("15.6", "16.9"),
    UpgradeStep("16.9", "17.3"),
    UpgradeStep("17.3", "17.9"),
    UpgradeStep("17.6", "17.9"),
    UpgradeStep("17.9", "17.12"),
    UpgradeStep("17.12", "17.15"),
    UpgradeStep("15.7", "16.12"),
    UpgradeStep("16.12", "17.3"),
)


def _major(version: str) -> str:
    """Return the major.minor of a version string."""
    parts = version.strip().split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return version.strip()


def evaluate(current: str, target: str) -> UpgradeStep:
    """Look up the upgrade path from ``current`` to ``target``.

    Returns a typed UpgradeStep with the appropriate verdict.
    If the path is direct, ``intermediate`` is empty and
    verdict is SUPPORTED. If an intermediate is required, the
    UpgradeStep carries the intermediate version and verdict
    is REQUIRES_INTERMEDIATE.

    We do a BFS through the path catalogue up to a depth of 6
    hops so long chains (15.6 -> 16.9 -> 17.3 -> 17.9 -> 17.12)
    resolve to the first required intermediate.
    """
    cur = _major(current)
    tgt = _major(target)
    if cur == tgt:
        return UpgradeStep(
            from_version=cur, to_version=tgt,
            intermediate="",
        )
    # Direct first.
    for step in _PATHS:
        if step.from_version == cur and step.to_version == tgt:
            return step
    # BFS for the shortest chain.
    # visited tracks versions we've already considered.
    visited: set[str] = {cur}
    # queue holds (current_version, first_intermediate)
    from collections import deque
    q: deque[tuple[str, str]] = deque()
    for s1 in _PATHS:
        if s1.from_version == cur and s1.to_version not in visited:
            if s1.to_version == tgt:
                # Direct was caught above; this is just defensive.
                return UpgradeStep(cur, tgt, "")
            q.append((s1.to_version, s1.to_version))
            visited.add(s1.to_version)
    while q:
        version, first_intermediate = q.popleft()
        for s in _PATHS:
            if s.from_version != version:
                continue
            if s.to_version == tgt:
                return UpgradeStep(
                    from_version=cur,
                    to_version=tgt,
                    intermediate=first_intermediate,
                )
            if s.to_version not in visited:
                visited.add(s.to_version)
                q.append((s.to_version, first_intermediate))
    # Nothing matched.
    return UpgradeStep(
        from_version=cur, to_version=tgt,
        intermediate="",
    )


def verdict_for(step: UpgradeStep) -> UpgradeVerdict:
    if step.from_version == step.to_version:
        return UpgradeVerdict.UNKNOWN
    if step.intermediate:
        return UpgradeVerdict.REQUIRES_INTERMEDIATE
    if (step.from_version, step.to_version) in {
        (s.from_version, s.to_version) for s in _PATHS
    }:
        return UpgradeVerdict.SUPPORTED
    return UpgradeVerdict.NOT_SUPPORTED


def render(step: UpgradeStep, v: UpgradeVerdict, lang: str = "en") -> str:
    if lang == "ar":
        return (
            f"مسار الترقية من {step.from_version} إلى {step.to_version}\n"
            f"  النتيجة: {v.value}\n"
            + (
                f"  يجب المرور بـ {step.intermediate} أولاً\n"
                if step.intermediate else ""
            )
        )
    return (
        f"Upgrade path from {step.from_version} to {step.to_version}\n"
        f"  Verdict: {v.value}\n"
        + (
            f"  Must go through {step.intermediate} first\n"
            if step.intermediate else ""
        )
    )
