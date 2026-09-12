"""Phase X — a managed device with no configuration is never a clean run.

The execution gate derived its device list from ``report.renders`` — the very
dictionary a failed render leaves a device out of. The check was therefore
self-confirming: a device that produced no configuration was not expected
either, so the run reported ``COMPLETE-STAGED`` / ``COMPLETE-APPLIED`` over a
network that was missing a device. Two bare ``continue`` statements in the apply
loop did the same for unknown vendor families and missing allowlists, and
``all(...)`` over an empty outcome list made an apply that sent nothing report
``COMPLETE-APPLIED``.
"""

from __future__ import annotations

import dataclasses

import pytest

from netops_autopilot.autopilot.answer_script import answer_script
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.cli import ScriptedIO
from tests.support.simfabric import SimFabricFactory, make_ledger_stack


def _run_and_regate(vendor_family: str | None, *, execute: bool = False):
    """Run the pipeline, optionally re-typing one device's vendor family.

    Re-running render and the gate on a fresh engine holding the report is what
    makes a managed-but-unrenderable device reachable in a test: the simulated
    fabric is all Cisco, and the defect is about what the *gate* does when a
    device drops out, not about the fabric.
    """
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(
        store=store, key_id=key_id,
        io=ScriptedIO(answer_script(access_retry="y",
                                    intent="branch office with VoIP")),
        time_authority=time_auth)
    report = engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                        mgmt_session_factory=fabric, port="SIM0", execute=False)
    design = report.design
    if vendor_family is None:
        return report, design

    devices = [
        dataclasses.replace(
            d, identity=dataclasses.replace(d.identity, vendor_family=vendor_family))
        if d.device_ref == "core-sw2" else d
        for d in report.crawl.devices
    ]
    report.crawl = dataclasses.replace(report.crawl, devices=tuple(devices))

    store2, key2, _c2, ta2 = make_ledger_stack()
    engine2 = AutopilotEngine(store=store2, key_id=key2, io=ScriptedIO(["BOND"]),
                              time_authority=ta2)
    engine2.report = report
    report.renders.clear()
    engine2.catalog_allowlists = engine.catalog_allowlists
    engine2._phase_render(design)
    engine2._phase_execution_gate(design, execute=execute,
                                  mgmt_session_factory=fabric)
    return report, design


def test_a_fully_configurable_fabric_is_still_complete():
    """The honest baseline: nothing dropped, so the verdict stays COMPLETE."""
    report, _design = _run_and_regate(None)
    assert report.final == "COMPLETE-STAGED"
    assert report.execution["unconfigured_devices"] == []
    assert sorted(report.execution["managed_devices"]) == \
        sorted(report.execution["staged_devices"])


def test_a_managed_device_with_no_configuration_blocks_a_clean_verdict():
    """`fortios` has no renderer data, so core-sw2 gets nothing at all."""
    report, design = _run_and_regate("fortinet/fortios")
    managed = sorted(r.device_ref for r in design.roles
                     if r.role != "UNMANAGED_NEIGHBOR")
    assert "core-sw2" in managed
    assert report.final == "INCOMPLETE-STAGED"
    assert report.execution["unconfigured_devices"] == ["core-sw2"]
    # the reason is carried, not just a bare name
    assert "RENDERER_NOT_MODELED" in report.execution["unconfigured_reasons"]["core-sw2"]
    # and it reaches the map's gap list, where every other unknown lives
    assert any(g.startswith("DEVICE_UNCONFIGURED core-sw2")
               for g in report.topology.gaps), report.topology.gaps


def test_the_phase_detail_states_the_real_coverage():
    """`staged 2/3` — the denominator is the managed set, not the render dict."""
    report, _design = _run_and_regate("fortinet/fortios")
    gate = [p for p in report.phases if p.phase.value == "EXECUTION_GATE"]
    assert gate and gate[-1].status == "INCOMPLETE"
    assert "2/3 managed device(s)" in gate[-1].detail


def test_the_apply_path_also_refuses_a_clean_verdict():
    """The same hole on the execute=True branch: applied 2 of 3, not success."""
    report, _design = _run_and_regate("fortinet/fortios", execute=True)
    assert report.final == "INCOMPLETE-APPLIED"
    assert report.execution["outcome"] == "INCOMPLETE"
    assert report.execution["unconfigured_devices"] == ["core-sw2"]


def test_an_apply_that_sent_nothing_is_never_reported_as_applied():
    """`all([])` is vacuously True; an empty apply used to look like success.

    Every managed device is unrendered here, so the accurate verdict is
    INCOMPLETE — the point of the test is that it can never be COMPLETE-APPLIED.
    """
    store, key_id, _c, ta = make_ledger_stack()
    engine = AutopilotEngine(store=store, key_id=key_id, io=ScriptedIO(["BOND"]),
                             time_authority=ta)
    report, design = _run_and_regate(None)
    engine.report = report
    report.renders.clear()          # nothing rendered, nothing to send
    engine.catalog_allowlists = {}
    engine._phase_execution_gate(design, execute=True, mgmt_session_factory=None)
    assert report.final == "INCOMPLETE-APPLIED"
    assert report.execution["outcome"] == "INCOMPLETE"
    assert report.execution["change_records"] == []
    assert sorted(report.execution["unconfigured_devices"]) == \
        sorted(report.execution["managed_devices"])


def test_a_rendered_device_that_cannot_be_gated_is_reported_not_sent():
    """The bare `continue` in the apply loop: rendered, then silently dropped.

    An unknown vendor family means no allowlist can be selected, so nothing may
    be sent — but the device must still be named in the outcome.
    """
    store, key_id, _c, ta = make_ledger_stack()
    engine = AutopilotEngine(store=store, key_id=key_id, io=ScriptedIO(["BOND"]),
                             time_authority=ta)
    report, design = _run_and_regate(None)
    engine.report = report
    engine.catalog_allowlists = {}      # nothing can be gated
    engine._phase_execution_gate(design, execute=True, mgmt_session_factory=None)
    assert report.final == "INCOMPLETE-APPLIED"
    assert sorted(report.execution["not_sent"]) == \
        sorted(report.execution["managed_devices"])
    assert all("NO_ALLOWLIST" in why
               for why in report.execution["not_sent"].values())


def test_coverage_is_derived_from_the_design_not_the_render_dict():
    """The regression guard on the mechanism itself, not just its symptoms."""
    store, key_id, _c, ta = make_ledger_stack()
    engine = AutopilotEngine(store=store, key_id=key_id, io=ScriptedIO([]),
                             time_authority=ta)
    report, design = _run_and_regate(None)
    engine.report = report
    managed, unconfigured = engine._config_coverage(design)
    assert unconfigured == []
    # drop one render: coverage must notice immediately
    del report.renders["access-sw1"]
    managed2, unconfigured2 = engine._config_coverage(design)
    assert managed == managed2
    assert [ref for ref, _ in unconfigured2] == ["access-sw1"]
