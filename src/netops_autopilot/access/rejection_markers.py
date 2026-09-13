"""The vocabulary a device uses to say "no".

A CLI session does not raise when a device refuses a line. IOS prints
``% Invalid input detected at '^' marker.`` and hands the prompt back;
netmiko returns that text and the transport reports success. Treating
"the transport did not raise" as "the device accepted this" is how a
change gets recorded as applied when the device never took it.

The strings that mean refusal differ per vendor, and they are data, not
code: every other vendor-specific fact in this repository (allowlists,
renderers, access profiles, capability matrices) lives in
``specs/data/``. Refusal wording was the one vendor-specific vocabulary
still hardcoded in the executor, and it was hardcoded in a Cisco shape —
so a RouterOS ``bad command name`` or a FortiOS ``Command fail`` went
unrecognised and the change was failed for a generic "state not present"
reason instead of the device's own words.

The markers are loaded as a union across vendors rather than selected by
device: ``ExecSession`` exposes only ``execute`` and ``close``, so the
executor cannot know which OS is behind the session. That is safe in the
direction that matters — every entry is a phrase that only appears when a
command was refused — and the data is still keyed per vendor so a future
narrowing needs no code change.

Risk is asymmetric and the data says so: a marker that never matches
costs only diagnosis detail, because the post-apply state readback still
fails the change; a marker that over-matches costs a false rollback. The
lists are therefore narrow, and each file records where its wording came
from.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, Mapping, Optional, Tuple

from netops_autopilot.specs_data import specs_data_dir

#: Refusals that read the same on every CLI, applied in addition to the
#: per-vendor entries. Kept in code because they are not a vendor fact.
GENERIC_MARKERS: Tuple[str, ...] = ("syntax error", "unknown command")

_DATA_SUBDIR = "device_errors"


@dataclass(frozen=True)
class RejectionVocabulary:
    """Every phrase that means "this command was refused"."""

    markers: Tuple[str, ...]
    by_vendor_os: Mapping[str, Tuple[str, ...]]
    #: False when the specs data pack could not be found, in which case only
    #: :data:`GENERIC_MARKERS` are known. Degrading to the vendor-neutral
    #: baseline is a loss of detail, never a claim of success.
    data_available: bool

    def matches(self, response: bytes | str) -> Optional[str]:
        """Return the matched refusal marker, or ``None``.

        Comparison is case-insensitive substring, matching how these CLIs
        echo the marker back inside a longer banner.
        """
        if isinstance(response, bytes):
            body = response.decode("utf-8", "replace")
        else:
            body = response
        body = body.lower()
        if not body.strip():
            return None
        for marker in self.markers:
            if marker in body:
                return marker
        return None

    def rejected(self, response: bytes | str) -> bool:
        return self.matches(response) is not None


def _load() -> RejectionVocabulary:
    directory = specs_data_dir(_DATA_SUBDIR)
    by_vendor: Dict[str, Tuple[str, ...]] = {}
    if directory and os.path.isdir(directory):
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".json"):
                continue
            try:
                doc = json.loads(
                    open(os.path.join(directory, name), encoding="utf-8").read())
            except (OSError, json.JSONDecodeError):
                continue
            os_name = str(doc.get("vendor_os") or "").strip().lower()
            markers = tuple(
                sorted({str(m).strip().lower()
                        for m in doc.get("rejection_markers", ())
                        if str(m).strip()}))
            if not os_name or not markers:
                continue
            by_vendor[os_name] = markers
            # A renderer file can serve several vendor_os spellings
            # (cisco_iosxe.json answers for both "ios-xe" and "ios"); the
            # refusal wording is the same for all of them.
            for alias in doc.get("also_matches", ()):
                alias = str(alias).strip().lower()
                if alias:
                    by_vendor[alias] = markers
    merged = tuple(sorted({*GENERIC_MARKERS, *(m for v in by_vendor.values() for m in v)}))
    return RejectionVocabulary(
        markers=merged, by_vendor_os=by_vendor, data_available=bool(by_vendor))


_CACHED: Optional[RejectionVocabulary] = None


def load_vocabulary() -> RejectionVocabulary:
    """The refusal vocabulary, loaded once per process."""
    global _CACHED
    if _CACHED is None:
        _CACHED = _load()
    return _CACHED


def reset_cache() -> None:
    """Drop the cached vocabulary (tests that point at another data pack)."""
    global _CACHED
    _CACHED = None
