"""Integration of Batch 2 pieces: allowlist → Collector → Parser → Ledger.

Proves the chain EVENT → RAW_ARTIFACT → OBSERVATION with intact references
and a valid signature/hash chain — the §8 chain head realized in code.
"""

from datetime import datetime, timezone
from pathlib import Path

from netops_autopilot.simfabric import fixtures_dir as simfabric_fixtures_dir

import pytest

from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
from netops_autopilot.access.collector import Collector, SessionLockManager
from netops_autopilot.core.budgets import CommandBudget
from netops_autopilot.core.timeauth import TimeAuthority
from netops_autopilot.ledger.models import Observation
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.parsers.cisco_show_version import CiscoIosXeShowVersionParser
from tests.support.loopback import LoopbackSession

FIXTURE = simfabric_fixtures_dir() / "cisco_iosxe" / "show_version.txt"
NOW = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)


def test_collect_parse_store_chain():
    store = LedgerStore(":memory:")
    key = store.keys.create_key("collector")
    al = CommandAllowlist((AllowlistEntry(template="show version", cls="READ_ONLY"),))
    collector = Collector(
        store=store, key_id=key, allowlist=al,
        time_authority=TimeAuthority(clock=lambda: NOW),
        locks=SessionLockManager(),
        default_budget=CommandBudget(max_retries=0),
    )
    session = LoopbackSession({"show version": FIXTURE.read_bytes()})

    result = collector.collect(device_ref="edge-router-01", command="show version", session=session)

    parser = CiscoIosXeShowVersionParser()
    observations = parser.parse(result.output, raw_id=result.artifact.raw_id)
    for obs in observations:
        store.append_observation(obs)

    # Chain integrity: artifact references the event; observations the artifact.
    assert result.artifact.event_id == result.event.event_id
    assert all(obs.raw_id == result.artifact.raw_id for obs in observations)

    # Identity fields usable by FSM-1 guard 1.3.
    by_field = {o.field: o.value for o in observations}
    assert by_field["version"] == "17.09.04a"
    assert by_field["model"] == "C8300-1N-4T"
    assert by_field["serial"] == "DOG2734L0XX"

    # Ledger remains verifiable end-to-end.
    store.integrity_self_test()
    assert store.verify_chain().ok
