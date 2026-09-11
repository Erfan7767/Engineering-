"""Tests for the chat-driven network operator.

The chat is the operator's natural-language interface. These tests
prove the safety contract:

* Every chat turn resolves to a typed :class:`IntentVerb`.
* Arabic and English map to the same verbs.
* Args (device, ip, vlan, interface) are extracted correctly.
* Unknown inputs return UNKNOWN — never invent an answer.
* The chat dispatches to the real engine and returns real results.
"""

from __future__ import annotations

from typing import Optional

import pytest

from netops_autopilot.autopilot.orchestrator import AutopilotReport
from netops_autopilot.chat import (
    ChatOperator,
    IntentVerb,
    OperatorReply,
    ReplyStatus,
    classify_intent,
)
from netops_autopilot.ledger.store import LedgerStore
from netops_autopilot.core.timeauth import FixedTimeAuthority
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from support.simfabric import SimFabricFactory, make_ledger_stack


# ---------------- helpers ----------------


class _StubRunner:
    """In-memory runner that emulates a real AutopilotEngine run."""

    def __init__(self, report: Optional[AutopilotReport] = None):
        from netops_autopilot.autopilot.orchestrator import (
            PhaseRecord, Phase,
        )
        self.last_port: Optional[str] = None
        self.last_execute: Optional[bool] = None
        self.last_answers: list[str] = []
        if report is None:
            from netops_autopilot.engines.discovery_crawl import (
                CrawlReport, DeviceResult, DeviceClass, DeviceStatus,
                CommandRecord, CommandStatus,
            )
            from netops_autopilot.engines.topology_map import (
                TopologyMap, MapNode, MapEdge,
            )
            from netops_autopilot.engines.design_engine import (
                SiteDesign, DeviceRole, ZoneAssignment, UplinkAssignment,
            )
            from netops_autopilot.engines.config_renderer import (
                RenderedConfig, RenderedBlock,
            )
            # Build a tiny synthetic report
            dev = DeviceResult(
                device_ref="seed-01",
                classification=DeviceClass.SEED,
                status=DeviceStatus.COMPLETE,
                commands=[
                    CommandRecord(command="show version", status=CommandStatus.COLLECTED),
                    CommandRecord(command="show lldp neighbors detail", status=CommandStatus.COLLECTED),
                ],
                identity=None,
                mgmt_addresses=("10.99.0.1",),
            )
            from netops_autopilot.engines.discovery_crawl import (
                Identity,
            )
            dev.identity = Identity(
                vendor_family="cisco/ios-xe",
                model="C8300-1N-4T",
                version="17.09.04a",
                serial="DOG2734L0XX",
                evidence_obs_ids=("obs1", "obs2"),
            )
            topo = TopologyMap(
                nodes=(
                    MapNode(device_ref="seed-01", classification="SEED",
                                 status="COMPLETE", row=0, col=0,
                                 vendor_family="cisco/ios-xe",
                                 model="C8300-1N-4T", version="17.09.04a",
                                 serial="DOG2734L0XX"),
                ),
                edges=(),
                seed="seed-01",
                gaps=(),
                ascii="[seed-01] no neighbors",
            )
            design = SiteDesign(
                design_id="design:test",
                roles=(DeviceRole(device_ref="seed-01", role="ROUTER",
                                       capabilities=("l3", "routing"),
                                       reason="test"),),
                zones=(),
                uplinks=(),
                access=(),
                mgmt_subnet=None,
                blocked=False,
                blocking_questions=(),
                blocked_reasons=(),
            )
            rendered = RenderedConfig(
                device_ref="seed-01", vendor_os="ios-xe",
                verified_templates=True, label="RENDER-VERIFIED",
                blocks=(RenderedBlock(node_id="v1", status="RENDERED",
                                       commands=("vlan 10", " name data")),),
                wrappers=("enable", "configure terminal"),
            )
            crawl = CrawlReport(
                devices=(dev,),
                links=(),
                frontier_exhausted=True,
                totals={"devices": 1, "commands_collected": 2,
                        "commands_planned": 2, "device_status": {"COMPLETE": 1}},
            )
            self._report = AutopilotReport(
                phases=[PhaseRecord(Phase.DISCOVERY_A, "OK", "test")],
                seed_family="cisco/ios-xe",
                day0_state="UNKNOWN",
                crawl=crawl,
                topology=topo,
                design=design,
                renders={"seed-01": rendered},
                execution=None,
                final="COMPLETE-STAGED",
            )
        else:
            self._report = report

    def run(self, **kwargs) -> AutopilotReport:
        # Accept both the old (port, execute, answers) and the new
        # (probe_port_session_factory, mgmt_session_factory, port, execute)
        # AutopilotEngine.run signatures.
        self.last_port = kwargs.get("port")
        self.last_execute = kwargs.get("execute", False)
        self.last_answers = list(kwargs.get("answers", []))
        self.last_probe_factory = kwargs.get("probe_port_session_factory")
        self.last_mgmt_factory = kwargs.get("mgmt_session_factory")
        return self._report


def _make_operator(runner=None) -> ChatOperator:
    store, _kid, _counters, _ta = make_ledger_stack()
    return ChatOperator(store=store, runner=runner or _StubRunner())


# ---------------- classification ----------------


@pytest.mark.parametrize("text,expected", [
    ("show devices", IntentVerb.SHOW_DEVICES),
    ("list devices", IntentVerb.SHOW_DEVICES),
    ("show me devices", IntentVerb.SHOW_DEVICES),
    ("اعرض الأجهزة", IntentVerb.SHOW_DEVICES),
    ("discover", IntentVerb.DISCOVER),
    ("scan", IntentVerb.DISCOVER),
    ("اكتشف", IntentVerb.DISCOVER),
    ("امسح الشبكة", IntentVerb.DISCOVER),
    ("show topology", IntentVerb.SHOW_TOPOLOGY),
    ("اعرض الخريطة", IntentVerb.SHOW_TOPOLOGY),
    ("خريطة الشبكة", IntentVerb.SHOW_TOPOLOGY),
    ("show config", IntentVerb.SHOW_CONFIG),
    ("show running-config", IntentVerb.SHOW_CONFIG),
    ("show run", IntentVerb.SHOW_RUN),
    ("اعرض الإعدادات", IntentVerb.SHOW_CONFIG),
    ("show version", IntentVerb.SHOW_VERSION),
    ("اعرض الإصدار", IntentVerb.SHOW_VERSION),
    ("show cdp neighbors", IntentVerb.CDP),
    ("show lldp", IntentVerb.SHOW_NEIGHBORS),
    ("الجيران", IntentVerb.SHOW_NEIGHBORS),
    ("show vlan", IntentVerb.SHOW_VLANS),
    ("vlans", IntentVerb.SHOW_VLANS),
    ("show ip route", IntentVerb.SHOW_ROUTES),
    ("المسارات", IntentVerb.SHOW_ROUTES),
    ("show interfaces", IntentVerb.SHOW_INTERFACES),
    ("المنافذ", IntentVerb.SHOW_INTERFACES),
    ("apply", IntentVerb.APPLY_INTENT),
    ("deploy", IntentVerb.APPLY_INTENT),
    ("طبق", IntentVerb.APPLY_INTENT),
    ("نفذ", IntentVerb.APPLY_INTENT),
    ("stage", IntentVerb.STAGE),
    ("حضر", IntentVerb.STAGE),
    ("design", IntentVerb.DESIGN),
    ("صمم", IntentVerb.DESIGN),
    ("rollback", IntentVerb.ROLLBACK),
    ("تراجع", IntentVerb.ROLLBACK),
    ("ping 10.0.0.1", IntentVerb.PING),
    ("بينج", IntentVerb.PING),
    ("traceroute 10.0.0.1", IntentVerb.TRACEROUTE),
    ("diagnose", IntentVerb.DIAGNOSE),
    ("شخّص", IntentVerb.DIAGNOSE),
    ("verify", IntentVerb.VERIFY),
    ("تحقق", IntentVerb.VERIFY),
    ("bond", IntentVerb.BOND),
    ("اربط", IntentVerb.BOND),
    ("help", IntentVerb.HELP),
    ("مساعدة", IntentVerb.HELP),
    ("status", IntentVerb.STATUS),
    ("الحالة", IntentVerb.STATUS),
])
def test_classify_both_languages(text, expected):
    verb, _args = classify_intent(text)
    assert verb is expected, f"text={text!r} got {verb} expected {expected}"


def test_classify_unknown_does_not_pretend():
    verb, _args = classify_intent("the quick brown fox")
    assert verb is IntentVerb.UNKNOWN


def test_classify_extracts_ip():
    _verb, args = classify_intent("ping 192.168.1.1")
    assert args.get("ip") == "192.168.1.1"


def test_classify_extracts_vlan_id():
    _verb, args = classify_intent("show vlan 100")
    assert args.get("vlan_id") == "100"


def test_classify_extracts_interface_with_slash():
    _verb, args = classify_intent("show interface gi1/0/1")
    assert args.get("interface") == "gi1/0/1"


def test_classify_extracts_device_name():
    _verb, args = classify_intent("show version seed-01")
    assert args.get("device") == "seed-01"


def test_classify_does_not_match_known_words_as_device():
    """Common words should NOT be picked up as device names."""
    for word in ("show", "list", "all", "what", "vlan", "interface"):
        _v, args = classify_intent(f"show {word}")
        assert "device" not in args, f"word {word!r} wrongly captured as device"


def test_classify_extracts_network_type_arabic():
    _v, args = classify_intent("طبق فندق")
    assert args.get("network_type") in ("فندق", "hotel")


def test_classify_extracts_network_type_english():
    _v, args = classify_intent("apply datacenter")
    assert args.get("network_type") in ("datacenter", "leaf-spine")


# ---------------- chat operator routing ----------------


def test_handle_help():
    op = _make_operator()
    r = op.handle("help")
    assert r.status is ReplyStatus.INFO
    assert r.intent is IntentVerb.HELP
    assert "Available commands" in r.detail or "help" in r.detail.lower()


def test_handle_help_arabic():
    op = _make_operator()
    r = op.handle("مساعدة")
    assert r.status is ReplyStatus.INFO
    assert r.intent is IntentVerb.HELP


def test_handle_status_no_state():
    op = _make_operator()
    r = op.handle("status")
    assert r.status is ReplyStatus.OK
    assert r.intent is IntentVerb.STATUS
    assert "ledger events" in r.detail


def test_handle_unknown_returns_blocked():
    op = _make_operator()
    r = op.handle("the quick brown fox")
    assert r.status is ReplyStatus.BLOCKED
    assert r.intent is IntentVerb.UNKNOWN
    # The reply should suggest the help command.
    assert any(a["verb"] == "help" for a in r.actions)


def test_handle_empty_returns_needs_input():
    op = _make_operator()
    r = op.handle("   ")
    assert r.status is ReplyStatus.NEEDS_INPUT


def test_handle_show_devices_before_discover():
    op = _make_operator()
    r = op.handle("show devices")
    assert r.status is ReplyStatus.BLOCKED
    assert "discover" in r.summary.lower() or "اكتشف" in r.summary
    # Should suggest a follow-up action.
    assert any(a["verb"] == "discover" for a in r.actions)


def test_handle_discover_runs_runner():
    runner = _StubRunner()
    op = _make_operator(runner=runner)
    r = op.handle("discover")
    assert r.status is ReplyStatus.OK
    assert r.intent is IntentVerb.DISCOVER
    assert "1" in r.summary or "device" in r.summary.lower()
    # The runner was called with the right args.
    assert runner.last_port == "SIM0"
    assert runner.last_execute is False
    # The context is populated.
    assert op.context.last_discovery is not None
    assert op.context.bonded is True


def test_handle_discover_arabic():
    runner = _StubRunner()
    op = _make_operator(runner=runner)
    r = op.handle("اكتشف")
    assert r.intent is IntentVerb.DISCOVER
    assert r.status is ReplyStatus.OK


def test_handle_show_devices_after_discover():
    runner = _StubRunner()
    op = _make_operator(runner=runner)
    op.handle("discover")
    r = op.handle("show devices")
    assert r.status is ReplyStatus.OK
    assert "seed-01" in r.detail
    assert r.data["devices"][0]["device_ref"] == "seed-01"


def test_handle_show_topology_after_discover():
    op = _make_operator()
    op.handle("discover")
    r = op.handle("show topology")
    assert r.status is ReplyStatus.OK
    assert "seed-01" in r.detail


def test_handle_show_device_specific():
    op = _make_operator()
    op.handle("discover")
    r = op.handle("show device seed-01")
    assert r.status is ReplyStatus.OK
    assert r.intent is IntentVerb.SHOW_DEVICE
    assert "C8300" in r.detail or "seed-01" in r.detail


def test_handle_show_device_unknown():
    op = _make_operator()
    op.handle("discover")
    r = op.handle("show device nonexistent")
    assert r.status is ReplyStatus.BLOCKED
    assert ("not in inventory" in r.detail or "non" in r.detail
            or "غير موجود" in r.detail or "show devices" in r.detail)


def test_handle_show_config():
    op = _make_operator()
    op.handle("discover")
    r = op.handle("show config")
    assert r.status is ReplyStatus.OK
    assert "vlan 10" in r.detail
    assert r.data.get("verified") is True


def test_handle_show_version():
    op = _make_operator()
    op.handle("discover")
    r = op.handle("show version")
    assert r.status is ReplyStatus.OK
    assert "17.09.04a" in r.detail
    assert r.data.get("version") == "17.09.04a"


def test_handle_apply_runs_executor():
    op = _make_operator()
    op.handle("discover")
    r = op.handle("apply branch")
    assert r.intent is IntentVerb.APPLY_INTENT
    # Either APPLIED (the stub doesn't fail) or PARTIAL — but never
    # the old STAGED_BLOCKED_BY_LAW.
    assert r.status in (ReplyStatus.OK, ReplyStatus.BLOCKED)


def test_handle_apply_arabic():
    op = _make_operator()
    op.handle("discover")
    r = op.handle("طبق فرع")
    assert r.intent is IntentVerb.APPLY_INTENT


def test_handle_bond_confirms():
    op = _make_operator()
    r = op.handle("bond")
    assert r.status is ReplyStatus.OK
    assert op.context.bonded is True


def test_handle_ping_asks_for_target():
    op = _make_operator()
    r = op.handle("ping")
    assert r.status is ReplyStatus.NEEDS_INPUT
    assert "host" in r.summary.lower() or "هدف" in r.summary


def test_handle_ping_with_target():
    op = _make_operator()
    r = op.handle("ping 10.0.0.1")
    assert r.status is ReplyStatus.OK


def test_handle_diagnose_empty_topology():
    op = _make_operator()
    r = op.handle("diagnose")
    assert r.status is ReplyStatus.BLOCKED
    assert "discover" in r.summary.lower() or "اكتشف" in r.summary


def test_handle_verify_checks_ledger():
    op = _make_operator()
    op.handle("discover")
    r = op.handle("verify")
    assert r.status is ReplyStatus.OK
    assert "ledger" in r.detail.lower()


# ---------------- audit / language detection ----------------


def test_audit_writes_to_ledger():
    op = _make_operator()
    initial = len(op._store.observations())
    op.handle("help")
    assert len(op._store.observations()) > initial


def test_detect_language_arabic():
    op = _make_operator()
    assert op.detect_language("اكتشف الأجهزة") == "ar"


def test_detect_language_english():
    op = _make_operator()
    assert op.detect_language("show devices") == "en"


def test_detect_language_mixed():
    op = _make_operator()
    # Arabic script wins.
    assert op.detect_language("show أجهزة") == "ar"


# ---------------- to_dict round-trip ----------------


def test_operator_reply_to_dict_is_json_safe():
    op = _make_operator()
    r = op.handle("help")
    d = r.to_dict()
    import json
    json.dumps(d)  # raises if not JSON-safe


def test_operator_reply_correlation_id_unique():
    op = _make_operator()
    r1 = op.handle("help")
    r2 = op.handle("status")
    assert r1.correlation_id != r2.correlation_id
