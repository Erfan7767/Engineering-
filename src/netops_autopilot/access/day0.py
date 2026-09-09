"""Day-0 state classifier (D0-07 §4) + ACCESS_LIMITED access-path advisor.

The classifier NEVER assumes: criteria are per-vendor data
(``specs/data/defaults_db/day0_classifiers.json``) with explicit absence of
a match ⇒ ``UNKNOWN``. Priorities make shadowed classes deterministic
(e.g. ``rommon`` evidence outranks ``PASSWORD_LOCKED`` fragments).

The advisor solves the concrete operator problem of this capstone: the seed
device only answers with default credentials (``ACCESS_LIMITED``), but LLDP
evidence shows it managing/authenticating elsewhere. The suggested path is
a deterministic decision over OBSERVED facts — never a guess (T2):

1. advertised management addresses (bidirectional, identity-confirmed first);
2. adapter-availability is consulted mechanically (no adapter ⇒
   NOT_MODELED — never imply a path that cannot be driven);
3. nothing eligible ⇒ ``HUMAN_TASK_REQUIRED`` with the exact blocking fact.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Any, Optional

from ..core.failures import Failure, FailureClass


class Day0State(str, Enum):
    FACTORY_DEFAULT = "FACTORY_DEFAULT"
    FACTORY_LIKE = "FACTORY_LIKE"
    CONFIGURED = "CONFIGURED"
    ACCESS_LIMITED = "ACCESS_LIMITED"
    PASSWORD_LOCKED = "PASSWORD_LOCKED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    UNKNOWN = "UNKNOWN"


@lru_cache(maxsize=1)
def _classifier_data() -> dict[str, Any]:
    """Criteria data; env override first, then the repo/installed data pack
    (``specs_data_dir``). Missing everywhere ⇒ typed BLOCKED (T2)."""
    import pathlib
    from ..specs_data import specs_data_dir
    override = os.environ.get("DAY0_CLASSIFIERS_PATH")
    path_text = override or specs_data_dir("defaults_db", "day0_classifiers.json")
    path = pathlib.Path(path_text) if path_text else None
    if path is None or not path.exists():
        raise Failure(
            cls=FailureClass.BLOCKED,
            causes=("DAY0_CLASSIFIERS_ABSENT: specs/data/defaults_db/day0_classifiers.json missing "
                    "(set NETOPS_SPECS_DATA or DAY0_CLASSIFIERS_PATH)",))
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_banner(text: bytes | str) -> str:
    return text.decode("utf-8", errors="replace") if isinstance(text, bytes) else text


def classify_day0_state(vendor_family: str, probe_output: bytes | str) -> Day0State:
    """Classify one probe banner/login output for the vendor family.

    Deterministic: highest-priority class whose markers match wins; a class
    with ``markers_all`` requires every marker; with ``markers_any`` at least
    one. No family's criteria match ⇒ UNKNOWN (D0-07 §4: never assume)."""
    try:
        data = _classifier_data()
    except Failure:
        return Day0State.UNKNOWN
    family = data.get("families", {}).get(vendor_family, {})
    text_lower = _normalize_banner(probe_output).lower()
    candidates: list[tuple[int, Day0State]] = []
    for class_name, criteria in family.get("classes", {}).items():
        try:
            state = Day0State[class_name]
        except KeyError:
            continue  # data lies outside the spec vocabulary: ignore, never crash
        markers_all = [m.lower() for m in criteria.get("markers_all", [])]
        markers_any = [m.lower() for m in criteria.get("markers_any", [])]
        # markers may embed printf-style slots (e.g. 'switch: %s'); treat '%s'
        # as a wildcard segment.
        ok = True
        for marker in markers_all:
            pattern = re.escape(marker).replace(r"%s", r".*?")
            if not re.search(pattern, text_lower, re.S):
                ok = False
                break
        if ok and markers_any:
            ok = any(re.search(re.escape(m).replace(r"%s", r".*?"), text_lower, re.S)
                     for m in markers_any)
        if ok and (markers_all or markers_any):
            candidates.append((int(criteria.get("priority", 0)), state))
    if not candidates:
        return Day0State.UNKNOWN
    candidates.sort(key=lambda item: (-item[0], item[1].value))
    return candidates[0][1]


# --------------------------------------------------------- ACCESS_LIMITED path
@dataclass(frozen=True)
class AccessPathSuggestion:
    """Deterministic advice for ACCESS_LIMITED devices."""

    verdict: str                       # MANAGEMENT_PATH_CANDIDATE | HUMAN_TASK_REQUIRED | NOT_MODELED
    addresses: tuple[str, ...] = ()    # deduped, sorted, identity-eligible first
    reasons: tuple[str, ...] = ()


def _adapter_available(adapter_registry: Any, vendor_key: str) -> Optional[bool]:
    """Mechanical adapter-existence probe over a variety of registry shapes.

    Returns True/False when provable, None when the registry cannot answer
    (honest UNKNOWN — the caller degrades the verdict, never invents)."""
    if adapter_registry is None:
        return None
    probe = None
    for attr in ("has_for", "supports", "has", "get_adapter"):
        fn = getattr(adapter_registry, attr, None)
        if callable(fn):
            probe = fn
            break
    if probe is None:
        adapters = getattr(adapter_registry, "adapters", None)
        if isinstance(adapters, dict):
            keys = {str(k).lower() for k in adapters}
            return any(vendor_key in k for k in keys)
        return None
    try:
        if probe.__name__ in ("get_adapter", "get"):
            return probe(vendor_key) is not None
        return bool(probe(vendor_key))
    except Exception:
        return None


def suggest_access_path(
    *,
    vendor_family: str,
    identity_evidence: dict[str, set[str]],
    adapter_registry: Any = None,
) -> AccessPathSuggestion:
    """Suggest the next evidence-eligible access path for ACCESS_LIMITED devices.

    ``identity_evidence`` maps ``mgmt_address`` → set of identity ties
    (``confirmed_bidirectional``, ``chassis_match``, ``name_match``); the
    caller builds it strictly from ledger/Twin evidence.
    """
    vendor_key = vendor_family.split("/")[0].lower()

    scored: list[tuple[int, str]] = []
    for address, ties in identity_evidence.items():
        if not address:
            continue
        if "confirmed_bidirectional" in ties and (ties & {"chassis_match", "name_match"}):
            rank = 0
        elif ties & {"chassis_match", "name_match"}:
            rank = 1
        elif ties:
            rank = 2
        else:
            continue  # zero identity ties: not eligible, never suggested blindly
        scored.append((rank, address))
    scored.sort()
    addresses = tuple(dict.fromkeys(a for _, a in scored))
    reasons = [
        f"candidate-order rule: identity-confirmed bidirectional > identity-tied > partially "
        f"tied; zero-tied addresses excluded ({len(identity_evidence) - len(scored)} dropped)"
    ]

    if not addresses:
        return AccessPathSuggestion(
            verdict="HUMAN_TASK_REQUIRED",
            reasons=tuple(reasons) + (
                "no advertised management address carries identity evidence — "
                "provide out-of-band access or confirm credentials with evidence",
            ),
        )

    available = _adapter_available(adapter_registry, vendor_key)
    if available is False:
        return AccessPathSuggestion(
            verdict="NOT_MODELED",
            addresses=addresses,
            reasons=tuple(reasons) + (
                f"no registered adapter can drive management access for {vendor_family!r} (T2)",
            ),
        )
    reason_extra = ("adapter availability UNKNOWN (registry cannot answer); path listed as "
                    "candidate only" if available is None else
                    f"adapter for {vendor_family!r} registered")
    return AccessPathSuggestion(
        verdict="MANAGEMENT_PATH_CANDIDATE",
        addresses=addresses,
        reasons=tuple(reasons) + (reason_extra,),
    )
