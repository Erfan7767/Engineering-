"""Identifier generation.

Every ledger entity gets a UUIDv4. Ids are opaque strings everywhere else;
no semantic parsing of ids is permitted (L01: nothing inferred from ids).
"""

from __future__ import annotations

import uuid


def new_id() -> str:
    """Return a fresh random UUID4 as canonical string."""
    return str(uuid.uuid4())
