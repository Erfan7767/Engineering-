"""Tests for the typed-id subsystem."""

from __future__ import annotations

import pytest

from netops_autopilot.core.ids import (
    extract_kind,
    is_typed_id,
    new_id,
    short_id,
    strip_kind,
    typed_id,
)


def test_new_id_returns_uuid4_string():
    i = new_id()
    assert isinstance(i, str)
    assert len(i) == 36
    # UUID4 has '4' in the version position
    assert i[14] == "4"


def test_new_id_is_unique():
    ids = {new_id() for _ in range(1000)}
    assert len(ids) == 1000


def test_typed_id_basic():
    tid = typed_id("evt")
    assert tid.startswith("evt:")
    assert is_typed_id(tid, "evt")


def test_typed_id_explicit_raw():
    tid = typed_id("obs", raw="12345")
    assert tid == "obs:12345"


def test_typed_id_rejects_empty_kind():
    with pytest.raises(ValueError):
        typed_id("")


def test_typed_id_rejects_kind_with_colon():
    with pytest.raises(ValueError):
        typed_id("evt:weird")


def test_typed_id_rejects_uppercase_kind():
    with pytest.raises(ValueError):
        typed_id("EVT")


def test_extract_kind_returns_prefix():
    assert extract_kind("evt:abc") == "evt"
    assert extract_kind("obs:123") == "obs"
    assert extract_kind("claim:xyz") == "claim"


def test_extract_kind_returns_none_for_untyped():
    assert extract_kind("plain-id") is None
    assert extract_kind("") is None
    assert extract_kind("EVT:abc") is None  # uppercase kind is not recognized


def test_is_typed_id_without_kind():
    assert is_typed_id("evt:abc") is True
    assert is_typed_id("plain") is False


def test_is_typed_id_with_kind():
    assert is_typed_id("evt:abc", "evt") is True
    assert is_typed_id("obs:abc", "evt") is False


def test_is_typed_id_handles_non_string():
    assert is_typed_id(None) is False  # type: ignore[arg-type]
    assert is_typed_id(123) is False  # type: ignore[arg-type]


def test_short_id_preserves_kind():
    assert short_id("evt:abcdefghij") == "evt:abcdefgh"
    assert short_id("evt:abc") == "evt:abc"
    assert short_id("plain-id") == "plain-id"


def test_short_id_custom_length():
    assert short_id("evt:abcdefghij", length=4) == "evt:abcd"
    assert short_id("evt:abc", length=10) == "evt:abc"


def test_short_id_handles_non_string():
    assert short_id(None) == ""  # type: ignore[arg-type]


def test_strip_kind_removes_prefix():
    assert strip_kind("evt:abc") == "abc"
    assert strip_kind("plain") == "plain"
    assert strip_kind("evt:has:colons") == "has:colons"


def test_strip_kind_handles_non_string():
    assert strip_kind(None) == ""  # type: ignore[arg-type]


def test_typed_id_default_kind_values():
    """The kind values that are used in production code."""
    for kind in ("evt", "obs", "claim", "txn", "run", "device", "link"):
        tid = typed_id(kind)
        assert is_typed_id(tid, kind)
        assert extract_kind(tid) == kind


def test_round_trip_through_short_id():
    """short_id → extract_kind returns the original kind."""
    for kind in ("evt", "obs", "claim", "run"):
        tid = typed_id(kind)
        short = short_id(tid, length=4)
        assert extract_kind(short) == kind
