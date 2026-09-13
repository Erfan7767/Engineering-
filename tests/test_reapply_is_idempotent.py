"""Re-applying a design must be a no-op, not a rollback.

An unchanged running-config hash has two opposite meanings:

* the device took the session and ignored every line — a real failure; and
* the device was already in the requested state — applying an idempotent
  design twice, which is normal.

``_verify_change`` read the first meaning unconditionally and returned
``VERIFY_NO_CHANGE``, and ``apply`` rolls back whenever verification fails. So
re-applying an already-applied design sent the rollback plan at a correctly
configured device. Measured against a session that models a real IOS device
(``show running-config`` renders state, so an identical line changes nothing):

    apply #1: APPLIED
    apply #2: ROLLBACK_FAILED
              VERIFY_NO_CHANGE: before==after
              ROLLBACK_STATE_MISMATCH
              device left holding ['name users']   # vlan 10 was deleted

The device that was working is broken, and the rollback could not restore it.

Signal 3 — ``_verify_state_present`` — already knows which meaning applies, so
it is now computed before the hash verdict instead of after it. Unchanged hash
plus the requested state present is ``ALREADY_IN_DESIRED_STATE`` and succeeds;
unchanged hash plus the requested state absent is still ``VERIFY_NO_CHANGE``
and still rolls back.
"""
from __future__ import annotations

import pytest

from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
from netops_autopilot.access.executor import ChangeOutcome, ConfigExecutor


class StatefulDevice:
    """A device whose running-config renders state, not a transcript.

    Re-sending a line that is already configured changes nothing, which is what
    IOS/IOS-XE does. The loopback double replays a command log instead, so it
    cannot reproduce this defect; that gap is recorded in
    ``test_the_loopback_double_replays_a_transcript``.
    """

    def __init__(self, ignores: bool = False, pads: bool = False) -> None:
        self.state: list[str] = []
        self.ignores = ignores
        self.pads = pads

    def execute(self, command: str, timeout_s: float | None = None) -> bytes:
        if command == "show running-config":
            return ("!\n" + "\n".join(self.state) + "\nend\n").encode("utf-8")
        if self.ignores:
            return f"{command}\nsw01(config)#".encode("utf-8")
        if command.startswith("no "):
            positive = command[3:].strip()
            self.state = [line for line in self.state if line != positive]
        elif self.pads:
            # Records something, but not the line that was asked for.
            self.state.append("! ignored: " + command)
        elif command not in self.state:
            self.state.append(command)
        return f"{command}\nsw01(config)#".encode("utf-8")

    def close(self) -> None:
        return None


def _allowlist() -> CommandAllowlist:
    return CommandAllowlist((
        AllowlistEntry(template="vlan <id>", cls="CONFIG_REVERSIBLE",
                       purpose="create vlan", rollback="no vlan <id>"),
        AllowlistEntry(template="name <n>", cls="CONFIG_REVERSIBLE",
                       purpose="vlan name", rollback="no name"),
        AllowlistEntry(template="show running-config", cls="READ_ONLY",
                       purpose="readback", notes=""),
    ))


CHANGE = ["vlan 10", "name users"]


def test_reapplying_an_applied_design_changes_nothing_and_breaks_nothing():
    """The regression: the second apply used to delete the configuration."""
    device = StatefulDevice()
    executor = ConfigExecutor(allowlist=_allowlist(), run_id="idem")

    first = executor.apply("dev1", device, CHANGE)
    assert first.outcome is ChangeOutcome.APPLIED
    assert first.already_applied is False
    assert device.state == CHANGE

    second = executor.apply("dev1", device, CHANGE)
    assert second.outcome is ChangeOutcome.APPLIED
    assert second.rollback_issued == 0, "a working device was rolled back"
    assert second.already_applied is True
    assert device.state == CHANGE, f"the device lost configuration: {device.state}"


def test_the_no_op_is_repeatable():
    device = StatefulDevice()
    executor = ConfigExecutor(allowlist=_allowlist(), run_id="idem")
    executor.apply("dev1", device, CHANGE)
    for _ in range(3):
        record = executor.apply("dev1", device, CHANGE)
        assert record.outcome is ChangeOutcome.APPLIED
        assert record.rollback_issued == 0
    assert device.state == CHANGE


def test_the_no_op_says_what_it_was():
    """Silent success and honest success are not the same report."""
    device = StatefulDevice()
    executor = ConfigExecutor(allowlist=_allowlist(), run_id="idem")
    executor.apply("dev1", device, CHANGE)
    second = executor.apply("dev1", device, CHANGE)
    assert second.already_applied is True
    assert second.to_dict()["already_applied"] is True


# ============================================ the failure it must still catch


def test_a_device_that_ignores_the_change_still_fails_and_rolls_back():
    """The distinction exists for a reason; this is the reason."""
    device = StatefulDevice(ignores=True)
    record = ConfigExecutor(allowlist=_allowlist(), run_id="neg").apply(
        "dev1", device, CHANGE)
    assert record.already_applied is False
    assert record.outcome is not ChangeOutcome.APPLIED
    assert any(c.startswith("VERIFY_NO_CHANGE") for c in record.failure_causes)
    assert any(c.startswith("VERIFY_STATE_ABSENT") for c in record.failure_causes)


def test_a_device_that_configures_something_else_still_fails():
    """A moved hash with the requested state absent is not a no-op either."""
    device = StatefulDevice(pads=True)
    record = ConfigExecutor(allowlist=_allowlist(), run_id="neg2").apply(
        "dev1", device, CHANGE)
    assert record.already_applied is False
    assert record.outcome is not ChangeOutcome.APPLIED
    assert any(c.startswith("VERIFY_STATE_ABSENT") for c in record.failure_causes)


def test_a_real_modification_after_a_no_op_still_applies():
    """Idempotence must not turn into 'stop listening'."""
    device = StatefulDevice()
    executor = ConfigExecutor(allowlist=_allowlist(), run_id="mod")
    executor.apply("dev1", device, CHANGE)
    executor.apply("dev1", device, CHANGE)          # no-op
    third = executor.apply("dev1", device, ["vlan 20", "name guests"])
    assert third.outcome is ChangeOutcome.APPLIED
    assert third.already_applied is False
    assert "vlan 20" in device.state


def test_a_partial_overlap_is_a_change_not_a_no_op():
    """One new line means the device was not already in the requested state."""
    device = StatefulDevice()
    executor = ConfigExecutor(allowlist=_allowlist(), run_id="part")
    executor.apply("dev1", device, ["vlan 10"])
    record = executor.apply("dev1", device, CHANGE)
    assert record.outcome is ChangeOutcome.APPLIED
    assert record.already_applied is False
    assert device.state == CHANGE


# ============================================ the double's own limitation


def test_the_loopback_double_replays_a_transcript():
    """Recorded, not hidden: the shipped double cannot reproduce this defect.

    ``LoopbackSession.effective_config`` replays a command log, so applying the
    same design twice appends the block again and the hash moves — where a real
    device's would not. The tests above therefore use a stateful double. Making
    the loopback double stateful is a larger change: deduplicating a parent
    without its children leaves orphaned lines, because the replay has no
    nesting context to attach them to.
    """
    from netops_autopilot.simfabric import seed_session

    session = seed_session()
    for _ in range(2):
        for command in ("vlan 77", "name probe", "exit"):
            session.execute(command, timeout_s=5.0)
    occurrences = [line for line in session.effective_config()
                   if line[1].strip() == "vlan 77"]
    assert len(occurrences) == 2, (
        "the loopback double now models state; these tests can use it directly "
        "and this note is stale")


def test_the_chat_report_distinguishes_a_no_op_from_a_change():
    """The operator has to be able to tell the two apart in the reply."""
    from types import SimpleNamespace
    from netops_autopilot.chat.operator import ChatOperator
    from tests.support.simfabric import make_ledger_stack

    store, _kid, _collector, _ta = make_ledger_stack()
    operator = ChatOperator(store=store, runner=None)

    def _report(already: bool) -> SimpleNamespace:
        record = {
            "device_ref": "seed-01", "outcome": "APPLIED",
            "applied_count": 2, "command_count": 2,
            "already_applied": already,
        }
        return SimpleNamespace(execution={"outcome": "APPLIED",
                                          "change_records": [record]})

    changed = operator._render_apply_report("en", _report(False))
    noop = operator._render_apply_report("en", _report(True))
    assert "already in this state" not in changed
    assert "already in this state" in noop
    assert operator._render_apply_report("ar", _report(True)) != noop
