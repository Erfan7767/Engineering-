"""Repo-root data-pack locator (``specs/data/**``).

Installed wheels do not bundle the specs tree (a data pack — the user's
knowledge base); resolution order is deliberate and explicit:

``NETOPS_SPECS_DATA`` env var → repository checkout (anchor: this file's
parent chain) → pip ``sysconfig['data']/netops_autopilot_specs``.

Absence everywhere yields the empty string — every consumer treats that as
a typed NOT_CONFIGURED/BLOCKED state (T2), never an implicit guess path.
"""

from __future__ import annotations

import os
import pathlib
import sysconfig

_ENV = "NETOPS_SPECS_DATA"
_anchor_dir = pathlib.Path(__file__).resolve().parent


def specs_data_dir(*parts: str) -> str:
    """Absolute path inside the specs data pack, or '' when unavailable."""
    candidates: list[pathlib.Path] = []
    env = os.environ.get(_ENV)
    if env:
        candidates.append(pathlib.Path(env))
    candidates.append(_anchor_dir.parent.parent / "specs" / "data")
    try:
        candidates.append(pathlib.Path(sysconfig.get_paths()["data"]) / "netops_autopilot_specs")
    except (KeyError, OSError):
        pass
    for base in candidates:
        probe = base.joinpath(*parts)
        if probe.exists() or not parts:
            if probe.exists() or base.exists():
                return str(probe)
        # also honor 'exists' for the exact probe only; fall through otherwise
        if probe.exists():
            return str(probe)
    return ""
