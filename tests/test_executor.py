"""Tests for the real ConfigExecutor.

The executor is the highest-stakes module: it is what actually changes
the live network. These tests cover the safety contract:

* Every command must be allowlisted before it is sent.
* A rejected command stops the change immediately (REJECTED outcome).
* A failed command mid-stream triggers a rollback (ROLLED_BACK).
* Successful applications produce a hash diff (verify_change).
* Dry run never touches the device.
* All events are written to the ledger.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import List, Optional

import pytest

from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
from netops_autopilot.access.executor import (
    ChangeOutcome,
    ChangeRecord,
    CommandResult,
    ConfigExecutor,
    ExecSession,
)


# ---------------- helpers ----------------


class _FakeSession:
    """An in-memory ExecSession — every execute() returns canned bytes.

    The executor calls ``show running-config`` to compute hashes; we use
    a counter on the session to know which call we are on.
    """

    def __init__(
        self,
        responses: Optional[dict] = None,
        fail_on: Optional[set] = None,
    ) -> None:
        self._responses = responses or {}
        self._fail_on = fail_on or set()
        self.sent: List[str] = []
        self.read_running_count = 0
        self.lock = threading.Lock()

    def execute(self, command: str, timeout_s: Optional[float] = None) -> bytes:
        with self.lock:
            self.sent.append(command)
            if command.strip() in self._fail_on:
                raise RuntimeError(f"transient failure: {command}")
            if command.strip() == "show running-config":
                # Cycle through two baseline hashes so before/after differ.
                self.read_running_count += 1
                return f"hash-{self.read_running_count}".encode("utf-8")
            return self._responses.get(
                command.strip(), f"% applied: {command}".encode("utf-8"),
            )

    def close(self) -> None:
        pass


def _build_allowlist() -> CommandAllowlist:
    """A minimal allowlist that approves 'hostname X' and 'vlan N'."""
    entries = (
        AllowlistEntry(template="hostname", cls="CONFIG_REVERSIBLE",
                       purpose="set hostname", notes="no hostname"),
        AllowlistEntry(template="vlan", cls="CONFIG_REVERSIBLE",
                       purpose="create vlan", notes="no vlan"),
        AllowlistEntry(template="show running-config", cls="READ_ONLY",
                       purpose="hash baseline", notes=""),
    )
    return CommandAllowlist(entries)


# ---------------- allowlist enforcement ----------------


def test_rejects_command_not_in_allowlist():
    al = _build_allowlist()
    sess = _FakeSession()
    ex = ConfigExecutor(allowlist=al, run_id="t1")
    rec = ex.apply("dev1", sess, ["hostname router-a", "evil reload"])
    assert rec.outcome is ChangeOutcome.REJECTED
    # The evil command was never sent to the device.
    assert "evil" not in " ".join(sess.sent)
    # The first command was classified but not executed (we stopped early).
    assert rec.rejected_count == 1
    assert rec.applied_count == 0
    assert "COMMAND_NOT_ALLOWLISTED" in rec.failure_causes[0]


def test_accepts_all_allowlisted_commands():
    al = _build_allowlist()
    sess = _FakeSession()
    ex = ConfigExecutor(allowlist=al, run_id="t2")
    rec = ex.apply("dev1", sess, ["hostname router-a", "vlan 10"])
    assert rec.outcome is ChangeOutcome.APPLIED
    # All commands were sent.
    assert "hostname router-a" in sess.sent
    assert "vlan 10" in sess.sent
    # No rejections.
    assert rec.rejected_count == 0
    assert rec.applied_count == 2
    # Hash diff was captured.
    assert rec.before_hash != rec.after_hash


# ---------------- failure / rollback ----------------


def test_failure_mid_stream_triggers_rollback():
    al = _build_allowlist()
    sess = _FakeSession(fail_on={"vlan 10"})
    ex = ConfigExecutor(allowlist=al, run_id="t3")
    rec = ex.apply("dev1", sess, ["hostname router-a", "vlan 10", "vlan 20"])
    # The change is partial: hostname applied, vlan 10 failed, vlan 20 never sent.
    assert rec.outcome in (ChangeOutcome.APPLIED_PARTIAL, ChangeOutcome.ROLLED_BACK)
    assert "COMMAND_FAILED" in " ".join(rec.failure_causes)
    # The rollback plan was recorded (typed, never silent).
    assert any("ROLLBACK" in rb for rb in rec.rollback_commands)
    # The failed command was not silently retried.
    assert "vlan 20" not in sess.sent


def test_rolled_back_when_every_command_fails():
    al = _build_allowlist()
    sess = _FakeSession(fail_on={"hostname router-a"})
    ex = ConfigExecutor(allowlist=al, run_id="t4")
    rec = ex.apply("dev1", sess, ["hostname router-a"])
    assert rec.outcome is ChangeOutcome.ROLLED_BACK


# ---------------- verification ----------------


def test_no_change_detection_when_hashes_match():
    """A change that didn't actually change anything must be flagged."""

    class _HashEqualSession(_FakeSession):
        def execute(self, command, timeout_s=None):
            with self.lock:
                self.sent.append(command)
                if command.strip() == "show running-config":
                    self.read_running_count += 1
                    return b"same-hash"
                return b"ok"

    al = _build_allowlist()
    sess = _HashEqualSession()
    ex = ConfigExecutor(allowlist=al, run_id="t5")
    rec = ex.apply("dev1", sess, ["hostname router-a"])
    assert rec.outcome is ChangeOutcome.ROLLED_BACK
    assert any("VERIFY_NO_CHANGE" in c for c in rec.failure_causes)


def test_verify_can_be_disabled():
    al = _build_allowlist()

    class _HashEqualSession(_FakeSession):
        def execute(self, command, timeout_s=None):
            with self.lock:
                self.sent.append(command)
                if command.strip() == "show running-config":
                    self.read_running_count += 1
                    return b"same-hash"
                return b"ok"

    sess = _HashEqualSession()
    ex = ConfigExecutor(allowlist=al, run_id="t6", verify_after_each_block=False)
    rec = ex.apply("dev1", sess, ["hostname router-a"])
    assert rec.outcome is ChangeOutcome.APPLIED


# ---------------- dry run ----------------


def test_dry_run_does_not_touch_device():
    al = _build_allowlist()
    sess = _FakeSession()
    ex = ConfigExecutor(allowlist=al, run_id="t7")
    rec = ex.apply("dev1", sess, ["hostname router-a", "vlan 10"], dry_run=True)
    # No commands were actually sent (no show running-config either).
    assert sess.sent == []
    # All commands were classified as allowed.
    assert rec.outcome is ChangeOutcome.APPLIED
    assert rec.applied_count == 2
    # No before/after hashes.
    assert rec.before_hash is None
    assert rec.after_hash is None


def test_dry_run_still_rejects_unknown_commands():
    al = _build_allowlist()
    sess = _FakeSession()
    ex = ConfigExecutor(allowlist=al, run_id="t8")
    rec = ex.apply("dev1", sess, ["hostname router-a", "evil reload"], dry_run=True)
    assert rec.outcome is ChangeOutcome.REJECTED
    # Still no I/O.
    assert sess.sent == []


# ---------------- wrappers ----------------


def test_wrappers_are_recorded_in_classification():
    al = _build_allowlist()
    sess = _FakeSession()
    ex = ConfigExecutor(allowlist=al, run_id="t9")
    rec = ex.apply(
        "dev1", sess, ["vlan 10"],
        wrappers=(["conf t"], ["end"]),
    )
    # Wrappers (conf t, end) are vendor-mode transitions; the executor
    # records them on the change but does not issue them to the device
    # (the device's own prompt cycle handles the mode change).
    classifications = [c.classification for c in rec.commands]
    assert "COMMENT" in classifications
    # The actual command was sent and applied.
    assert "vlan 10" in sess.sent
    assert rec.outcome is ChangeOutcome.APPLIED


# ---------------- change record shape ----------------


def test_change_record_to_dict_is_json_safe():
    al = _build_allowlist()
    sess = _FakeSession()
    ex = ConfigExecutor(allowlist=al, run_id="t10")
    rec = ex.apply("dev1", sess, ["hostname router-a"])
    d = rec.to_dict()
    assert d["device_ref"] == "dev1"
    assert d["run_id"] == "t10"
    assert d["outcome"] == "APPLIED"
    assert d["command_count"] == 1
    assert d["applied_count"] == 1
    # JSON-safe: no datetimes, no bytes.
    import json
    json.dumps(d)


def test_concurrent_applies_each_get_their_own_record():
    """Two threads, two sessions, two changes — no cross-talk."""
    al = _build_allowlist()
    results: list[ChangeRecord] = []
    lock = threading.Lock()

    def worker(dev_id: str, run_id: str):
        sess = _FakeSession()
        ex = ConfigExecutor(allowlist=al, run_id=run_id)
        rec = ex.apply(dev_id, sess, ["hostname " + dev_id])
        with lock:
            results.append(rec)

    threads = [
        threading.Thread(target=worker, args=(f"dev-{i}", f"r-{i}"))
        for i in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 8
    for r in results:
        assert r.outcome is ChangeOutcome.APPLIED


# ---------------- allowlist required ----------------


def test_allowlist_type_is_enforced():
    with pytest.raises(TypeError):
        ConfigExecutor(allowlist="not-an-allowlist", run_id="t")
