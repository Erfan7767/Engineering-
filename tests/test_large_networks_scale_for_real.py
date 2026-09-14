"""A large network is a real case, not a claim.

Until this file existed, every scaling statement the platform made rested on a
four-device fabric. Four devices cannot show a discovery budget binding, cannot
show a design placing thousands of access ports, and cannot show a per-device
cost that only becomes wall-clock time at three digits.

`simfabric.LargeFabric` generates a real three-tier fabric — one L3 core, ``k``
distribution switches, ``k * m`` access switches — with unique serials and
chassis ids and reciprocal LLDP, and the *real* crawler, design engine,
renderer, executor and verifier run against it.

What it measured, and what was wrong:

    fabric  COMPLETE  NOT_PROBED  applied   time
         7         7           0      7/7   0.09 s
        21        21           0    21/21   0.23 s
        73        73           0    73/73   1.28 s
       157       157           0  157/157   5.20 s
       273       256          17  256/273  11.91 s   <-- budget bound

The 273-device run was honest — the 17 devices a neighbour named were recorded
``NOT_PROBED`` with the budget named in the reason, never invented and never
silently dropped. But `max_devices` was a default buried in `crawl()` that
nothing above it could change: a campus larger than 256 stopped there and the
operator had no way to lift the ceiling short of editing source. It is now an
engine parameter and a `--max-devices` flag, and when the budget binds the run
says so and names the remedy.
"""

from __future__ import annotations

import pytest

from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from netops_autopilot.simfabric import LargeFabric, make_ledger_stack

# Every device in these fabrics is reachable, so the credential-retry question
# is never asked; the sequence starts at the BOND confirmation.
ANSWERS = ["y", "campus", "seed-01", "ISP fiber DHCP handoff", "STANDARD",
           "+25% in 12 months", "1.1.1.1, 9.9.9.9", "BOND"]


def _run(k, m, *, max_devices=256, max_l3_probes=32, execute=True):
    fabric = LargeFabric(k, m)
    store, key_id, _counters, time_auth = make_ledger_stack()
    engine = AutopilotEngine(
        store=store, key_id=key_id, io=ScriptedIO(list(ANSWERS)),
        time_authority=time_auth,
        max_devices=max_devices, max_l3_probes=max_l3_probes)
    report = engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                        mgmt_session_factory=fabric.open, port="SIM0",
                        execute=execute)
    return fabric, report


def _status_counts(report):
    out: dict[str, int] = {}
    for device in report.crawl.devices:
        out[device.status.value] = out.get(device.status.value, 0) + 1
    return out


# ============================================== the fabric itself is honest
def test_serials_and_chassis_ids_are_unique():
    """The two ways a synthetic fabric lies about being many devices.

    A repeated serial is an identity collision and the crawler rightly refuses
    to split it, collapsing the fabric to one device. A repeated chassis id
    does the same from the neighbour side.
    """
    fabric = LargeFabric(3, 3)
    serials, chassis = [], set()
    for session in fabric.sessions.values():
        text = session.execute("show version", 5).decode()
        serials.append([l for l in text.splitlines()
                        if l.startswith("System serial number")][0].split(":")[1].strip())
        lldp = session.execute("show lldp neighbors detail", 5).decode()
        chassis.update(l.split(":", 1)[1].strip() for l in lldp.splitlines()
                       if l.startswith("Chassis id:"))
    assert len(serials) == len(set(serials)), "duplicate serials collapse the fabric"
    assert len(chassis) == len(fabric.refs), (len(chassis), len(fabric.refs))


def test_every_lldp_entry_is_its_own_block():
    """One separator for the whole table parses to a single neighbour.

    The parser splits on `^-{5,}$`, so a table with n neighbours and one
    separator yields one row and the fabric silently becomes two devices deep.
    """
    fabric = LargeFabric(2, 3)
    text = fabric.sessions["dist-01"].execute("show lldp neighbors detail", 5).decode()
    separators = [l for l in text.splitlines() if set(l.strip()) == {"-"} and len(l.strip()) >= 5]
    neighbours = [l for l in text.splitlines() if l.startswith("System Name:")]
    assert len(neighbours) == 4, neighbours          # seed + 3 access
    assert len(separators) == len(neighbours), (len(separators), len(neighbours))


# ================================================== discovery scales for real
def test_a_three_tier_fabric_is_discovered_and_configured_completely():
    fabric, report = _run(4, 4)                      # 21 devices
    assert len(fabric.refs) == 21
    assert _status_counts(report) == {"COMPLETE": 21}, _status_counts(report)
    assert len(report.topology.nodes) == 21
    assert len(report.topology.edges) == 20          # a tree: n-1 links
    assert report.execution["outcome"] == "APPLIED"
    assert len(report.execution["managed_devices"]) == 21
    assert report.verification["failed"] == ()


def test_a_large_campus_runs_end_to_end():
    fabric, report = _run(8, 8)                      # 73 devices
    assert len(fabric.refs) == 73
    assert _status_counts(report) == {"COMPLETE": 73}, _status_counts(report)
    assert len(report.design.access) > 1000
    assert report.execution["outcome"] == "APPLIED"
    assert len(report.execution["managed_devices"]) == 73


# ============================================== the budget binds, loudly
def test_the_budget_records_what_it_refused_instead_of_dropping_it():
    """A device a neighbour named is a fact; refusing to crawl it is a decision."""
    fabric, report = _run(4, 4, max_devices=10)      # 21 devices, budget 10
    counts = _status_counts(report)
    assert counts["COMPLETE"] == 10, counts
    assert counts["NOT_PROBED"] == 11, counts
    for device in report.crawl.devices:
        if device.status.value != "NOT_PROBED":
            continue
        assert device.rejection_reasons, device.device_ref
        assert "device budget 10 reached" in device.rejection_reasons[0]
        assert "nothing about it is known" in device.rejection_reasons[0]
    # and the run never claims completeness
    assert not report.final.startswith("COMPLETE"), report.final
    assert len(report.execution["managed_devices"]) == 10


def test_raising_the_budget_crawls_the_devices_it_previously_refused():
    _, small = _run(4, 4, max_devices=10)
    _, large = _run(4, 4, max_devices=64)
    assert _status_counts(small)["NOT_PROBED"] == 11
    assert _status_counts(large) == {"COMPLETE": 21}, _status_counts(large)
    assert len(large.execution["managed_devices"]) == 21


def test_the_operator_is_told_the_budget_bound_and_how_to_lift_it(capsys):
    _run(4, 4, max_devices=10)
    out = capsys.readouterr().out
    assert "DISCOVERY BUDGET" in out, out[-800:]
    line = [l for l in out.splitlines() if "DISCOVERY BUDGET" in l][0]
    assert "11 device(s)" in line, line
    assert "--max-devices" in line, line             # names the actual remedy
    assert "receive NO configuration" in line, line  # and the consequence


def test_no_notice_when_the_budget_did_not_bind(capsys):
    _run(4, 4, max_devices=64)
    assert "DISCOVERY BUDGET" not in capsys.readouterr().out


# ============================================== a zero budget is refused
def test_a_zero_device_budget_is_refused_not_silently_empty():
    """A budget of zero would report an empty network that is not empty."""
    store, key_id, _counters, time_auth = make_ledger_stack()
    with pytest.raises(ValueError) as exc:
        AutopilotEngine(store=store, key_id=key_id, io=ScriptedIO(list(ANSWERS)),
                        time_authority=time_auth, max_devices=0)
    assert "max_devices=0" in str(exc.value)
    with pytest.raises(ValueError):
        AutopilotEngine(store=store, key_id=key_id, io=ScriptedIO(list(ANSWERS)),
                        time_authority=time_auth, max_l3_probes=0)


def test_the_cli_declares_the_budget_flags(capsys):
    """The flags must exist, be documented, and default to the old constant."""
    from netops_autopilot.cli_main import main
    with pytest.raises(SystemExit):
        main(["autopilot", "--help"])
    out = capsys.readouterr().out
    assert "--max-devices" in out and "--max-l3-probes" in out
    assert "default 256" in out
    assert "NOT_PROBED" in out          # the help says what the budget does


def test_the_cli_refuses_a_zero_budget_before_touching_hardware(capsys):
    from netops_autopilot.cli_main import run_autopilot
    assert run_autopilot("COM3", False, max_devices=0) == 2
    assert "Refusing" in capsys.readouterr().err
