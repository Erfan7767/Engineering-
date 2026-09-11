"""Identifier generation and typed ID helpers.

Every ledger entity gets a UUIDv4. Ids are opaque strings everywhere else;
no semantic parsing of ids is permitted (L01: nothing inferred from ids).

This module adds:

* A :class:`TypedId` factory that tags ids with their kind (``evt:``,
  ``obs:``, ``claim:``, ``txn:``, ``run:``) for human readability.
* :func:`short_id` for UI display.
* :func:`is_typed_id` to validate prefixes without parsing semantics.
* :func:`extract_kind` to read the kind without trusting the suffix.

The original :func:`new_id` API is preserved for backward compatibility.
"""

from __future__ import annotations

import re
import uuid
from typing import Final

_ID_PREFIX_RE: Final[re.Pattern[str]] = re.compile(r"^([a-z]{1,8}):([A-Za-z0-9_\-]+)$")


def new_id() -> str:
    """Return a fresh random UUID4 as canonical string."""
    return str(uuid.uuid4())


def typed_id(kind: str, raw: Optional[str] = None) -> str:
    """Return a kind-prefixed id (``"<kind>:<uuid>"``).

    Args:
        kind: short lowercase tag, e.g. ``"evt"``, ``"obs"``, ``"claim"``,
            ``"txn"``, ``"run"``.
        raw: optional explicit UUID; if absent, a fresh UUIDv4 is used.

    Raises:
        ValueError: if ``kind`` is empty, contains ``:``, or is not lowercase.
    """
    if not kind or not isinstance(kind, str):
        raise ValueError("kind must be a non-empty string")
    if ":" in kind:
        raise ValueError("kind must not contain ':'")
    if kind != kind.lower():
        raise ValueError("kind must be lowercase")
    if raw is None:
        raw = str(uuid.uuid4())
    return f"{kind}:{raw}"


def extract_kind(typed: str) -> Optional[str]:
    """Return the kind prefix of a typed id, or None if untyped."""
    if not isinstance(typed, str):
        return None
    m = _ID_PREFIX_RE.match(typed)
    return m.group(1) if m else None


def is_typed_id(typed: str, kind: Optional[str] = None) -> bool:
    """Return True if ``typed`` is a well-formed typed id.

    If ``kind`` is given, also check that the prefix matches.
    """
    extracted = extract_kind(typed)
    if extracted is None:
        return False
    if kind is not None and extracted != kind:
        return False
    return True


def short_id(typed: str, length: int = 8) -> str:
    """Return a short display form of an id, e.g. ``"evt:abcd1234"``.

    The full id is preserved in the ledger; this is purely a presentation
    helper. If the id is shorter than ``length``, it is returned as-is.
    """
    if not isinstance(typed, str):
        return ""
    if ":" in typed:
        kind, _, rest = typed.partition(":")
        return f"{kind}:{rest[:length]}"
    return typed[:length]


def strip_kind(typed: str) -> str:
    """Return the part after the kind prefix, or the id as-is if untyped."""
    if not isinstance(typed, str):
        return ""
    if ":" in typed:
        return typed.split(":", 1)[1]
    return typed
