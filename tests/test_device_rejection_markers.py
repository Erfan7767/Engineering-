"""A device that says "no" must be heard, whatever brand it is.

A CLI session does not raise when a device refuses a line. IOS prints
``% Invalid input detected at '^' marker.`` and hands the prompt back;
RouterOS prints ``bad command name``; FortiOS prints ``Command fail``.
In every case the transport reports success, so the only evidence that
the device refused is the wording it printed.

The executor's refusal vocabulary used to be a hardcoded tuple in
Cisco's shape, which meant a RouterOS or FortiOS refusal was not
recognised as a refusal: the change still failed — the state readback
cannot find a line the device never accepted — but it failed for a
generic reason and the device's own diagnosis was thrown away. The
vocabulary is now data in ``specs/data/device_errors/``, one file per
config-capable vendor.

These tests cover both halves: the data (every vendor that can receive
configuration has refusal wording, and its own sample is recognised) and
the wiring (a refusal on the real executor is reported in the device's
own words and never becomes APPLIED).
"""
from __future__ import annotations

import json
import os
from typing import Dict, List

import pytest

from netops_autopilot.access import rejection_markers
from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
from netops_autopilot.access.executor import ChangeOutcome, ConfigExecutor
from netops_autopilot.access.rejection_markers import (
    GENERIC_MARKERS,
    load_vocabulary,
    reset_cache,
)
from netops_autopilot.engines.config_renderer import _RENDERER_FILES
from netops_autopilot.specs_data import specs_data_dir

#: The three Cisco markers that were hardcoded in the executor before the
#: vocabulary became data, plus the two vendor-neutral ones. Losing any of
#: these would be a silent regression in production behaviour.
_PREVIOUSLY_HARDCODED = (
    "% invalid input", "% incomplete command", "% ambiguous",
    "syntax error", "unknown command",
)


class _RefusingSession:
    """A session the device accepts, on which one line is refused.

    Models the real failure exactly: the transport never raises, the
    refusal arrives as ordinary response text, and ``show running-config``
    reflects only the lines the device actually took.
    """

    def __init__(self, refuse: Dict[str, str]) -> None:
        self._refuse = dict(refuse)
        self.state: List[str] = []
        self.sent: List[str] = []

    def execute(self, command: str, timeout_s: float | None = None) -> bytes:
        self.sent.append(command)
        if command == "show running-config":
            body = "\n".join(self.state)
            return f"!\n{body}\nend\n".encode("utf-8")
        if command in self._refuse:
            # The device answers with its refusal and takes nothing.
            return self._refuse[command].encode("utf-8")
        if command.startswith("no "):
            # A real device removes the configuration; a double that merely
            # records the inverse line leaves the device in a state no
            # rollback can ever match, and the test then measures the
            # double instead of the executor.
            positive = command[3:].strip()
            self.state = [line for line in self.state if line != positive]
        else:
            self.state.append(command)
        return f"{command}\nsw01(config)#".encode("utf-8")

    def close(self) -> None:
        return None


def _allowlist() -> CommandAllowlist:
    return CommandAllowlist((
        AllowlistEntry(template="vlan <vlan_id>", cls="CONFIG_REVERSIBLE",
                       purpose="create vlan", rollback="no vlan <vlan_id>"),
        AllowlistEntry(template="name <name>", cls="CONFIG_REVERSIBLE",
                       purpose="vlan name", rollback="no name"),
        AllowlistEntry(template="show running-config", cls="READ_ONLY",
                       purpose="state readback", notes=""),
    ))


def _data_files() -> Dict[str, dict]:
    directory = specs_data_dir("device_errors")
    assert directory and os.path.isdir(directory), "specs data pack unavailable"
    out: Dict[str, dict] = {}
    for name in sorted(os.listdir(directory)):
        if name.endswith(".json"):
            out[name] = json.loads(
                open(os.path.join(directory, name), encoding="utf-8").read())
    return out


# ---------------- the data ----------------


def test_every_config_capable_vendor_has_refusal_vocabulary():
    """No vendor may be able to receive configuration without it.

    The set is derived from the renderer map rather than listed by hand:
    a vendor with a renderer can have configuration pushed to it, so a
    vendor with a renderer must have refusal wording.
    """
    vocabulary = load_vocabulary()
    assert vocabulary.data_available is True
    # The *keys* are the vendor_os names; the values are filenames.
    renderable = set(_RENDERER_FILES)
    missing = sorted(renderable - set(vocabulary.by_vendor_os))
    assert missing == [], f"no refusal vocabulary for: {missing}"


def test_each_vendor_sample_rejection_is_recognised():
    """Each data file proves itself against its own sample.

    A marker list nobody has checked against a real refusal banner is
    decoration, so every file carries the text it claims to catch.
    """
    vocabulary = load_vocabulary()
    for name, doc in _data_files().items():
        sample = doc.get("sample_rejection")
        assert sample, f"{name} declares no sample_rejection"
        matched = vocabulary.matches(sample)
        assert matched is not None, f"{name}: sample not recognised: {sample!r}"


def test_markers_are_lowercase_so_matching_cannot_silently_miss():
    vocabulary = load_vocabulary()
    assert all(m == m.lower() and m.strip() for m in vocabulary.markers)
    assert all(
        m == m.lower()
        for by_os in vocabulary.by_vendor_os.values() for m in by_os
    )


def test_the_markers_already_in_production_survive():
    """Data-driven must not cost the detection that already worked."""
    vocabulary = load_vocabulary()
    for marker in _PREVIOUSLY_HARDCODED:
        assert marker in vocabulary.markers, marker
    for marker in GENERIC_MARKERS:
        assert marker in vocabulary.markers, marker


def test_vocabulary_is_a_union_across_vendors():
    """The executor cannot know the OS behind an ExecSession."""
    vocabulary = load_vocabulary()
    for by_os in vocabulary.by_vendor_os.values():
        for marker in by_os:
            assert marker in vocabulary.markers


# ---------------- the wiring, through the real executor ----------------


@pytest.mark.parametrize("vendor,refusal", [
    ("routeros", "/ip pool> add name=users\n             ^ bad command name"),
    ("fortios", "Command fail."),
    ("arubaos", "Invalid input: vlan 4o96"),
    ("junos", "syntax error, expecting <command>."),
    ("cisco", "                    ^\n% Invalid input detected at '^' marker."),
])
def test_a_refusal_is_reported_in_the_devices_own_words(vendor, refusal):
    """The device's diagnosis reaches the change record, not a generic one.

    Every one of these used to be invisible except the Cisco form: the
    transport returned normally, so the refusal only surfaced later as
    "state not present", with the reason the device gave us discarded.
    """
    sess = _RefusingSession({"vlan 10": refusal})
    record = ConfigExecutor(allowlist=_allowlist(), run_id=f"rej-{vendor}").apply(
        "dev1", sess, ["vlan 10"])
    assert record.outcome is not ChangeOutcome.APPLIED
    causes = [c for c in record.failure_causes if c.startswith("DEVICE_REJECTED_SYNTAX:")]
    assert causes, f"{vendor}: no DEVICE_REJECTED_SYNTAX cause in {record.failure_causes}"
    assert "vlan 10" in causes[0]
    # The marker the device actually printed is what we report.
    assert any(word in causes[0] for word in (
        "bad command name", "command fail", "invalid input", "syntax error")), causes[0]


def test_a_refused_line_is_rolled_back_and_not_counted_as_applied():
    """Refusal on line two must undo line one, not leave a half change."""
    sess = _RefusingSession({"name users": "Command fail."})
    record = ConfigExecutor(allowlist=_allowlist(), run_id="rej-rollback").apply(
        "dev1", sess, ["vlan 10", "name users"])
    assert record.outcome is ChangeOutcome.ROLLED_BACK
    assert "no vlan 10" in sess.sent, "the accepted line was not inverted"
    assert any(c.startswith("DEVICE_REJECTED_SYNTAX:name users") for c in
               record.failure_causes), record.failure_causes


def test_a_successful_response_is_not_mistaken_for_a_refusal():
    """The other failure mode: an over-eager marker rolls back good work."""
    sess = _RefusingSession({})
    record = ConfigExecutor(allowlist=_allowlist(), run_id="rej-clean").apply(
        "dev1", sess, ["vlan 10", "name users"])
    assert record.outcome is ChangeOutcome.APPLIED
    assert record.failure_causes == []
    assert ["vlan 10", "name users"] == [c for c in sess.state]


def test_an_empty_response_is_not_a_refusal():
    """A silent device is a different problem; do not invent a refusal."""
    assert load_vocabulary().matches(b"") is None
    assert load_vocabulary().matches("   \n") is None


# ---------------- degradation ----------------


def test_a_missing_data_pack_degrades_to_the_vendor_neutral_baseline(monkeypatch):
    """Losing the data pack loses detail, never the refusal to claim success.

    The generic markers stay in code precisely so that a machine without
    the specs pack still refuses a line that says "syntax error", rather
    than silently accepting everything.
    """
    real = rejection_markers.specs_data_dir
    monkeypatch.setattr(rejection_markers, "specs_data_dir", lambda *parts: "")
    reset_cache()
    try:
        vocabulary = load_vocabulary()
        assert vocabulary.data_available is False
        assert vocabulary.by_vendor_os == {}
        assert tuple(vocabulary.markers) == tuple(sorted(GENERIC_MARKERS))
        assert vocabulary.matches("% Invalid input detected") is None
        assert vocabulary.matches("syntax error") == "syntax error"
    finally:
        # monkeypatch is undone only at teardown, so the pack must be put
        # back by hand before the recovery is checked.
        rejection_markers.specs_data_dir = real
        reset_cache()
    assert load_vocabulary().data_available is True
    assert "% invalid input" in load_vocabulary().markers
