"""Design Engine: deterministic blueprint × topology × IPAM ⇒ IR."""

from netops_autopilot.engines.blueprints import BLUEPRINTS, business_intent_from_blueprint
from netops_autopilot.engines.capability import CapabilityEngine, CapabilityValue
from netops_autopilot.engines.design_engine import DesignEngine, harvest_interfaces
from netops_autopilot.engines.intent_compiler import IntentCompiler
from netops_autopilot.engines.service_graph import ServiceGraph
from netops_autopilot.fsm import link_fsm as lf
from tests.test_discovery_crawl import (
    BACK_TABLE,
    BACK_VERSION,
    ScriptedFactory,
    _engine,
    _seed_session,
)
from tests.support.loopback import LoopbackSession


class _Matrix:
    """CapabilityMatrix-shaped stand-in over the real CapabilityEngine."""

    plannable = (CapabilityValue.YES, CapabilityValue.PARTIAL)

    def __init__(self, engine: CapabilityEngine) -> None:
        self._engine = engine

    def lookup(self, family: str, version: str | None, feature: str, operation: str):
        if version is None:
            return CapabilityValue.UNKNOWN
        return self._engine.lookup(family, version, feature, operation)


def _build():
    factory = ScriptedFactory(
        scripts={
            "core-sw1": _seed_session(),
            "core-sw2": LoopbackSession({
                "show version": BACK_VERSION,
                "show lldp neighbors detail": BACK_TABLE,
                "show cdp neighbors detail": b"",
            }),
        },
        refuse={"access-sw1": ("AUTH_REFUSED",)},
    )
    engine, store, twin, link_engine, allowlist = _engine(factory)
    report = engine.crawl(seed_ref="core-sw1", seed_family="cisco/ios-xe",
                          session_factory=factory, allowlist_of=lambda f: allowlist)
    return report


def _compiled_intent(bp_id: str, answers):
    bp = next(b for b in BLUEPRINTS if b.blueprint_id == bp_id)
    req, missing = business_intent_from_blueprint(bp, answers=answers, requirement_text=bp_id)
    assert not missing
    return bp, IntentCompiler(ServiceGraph.load_builtin()).compile(req)


def _engine_and_intent():
    blueprint, intent = _compiled_intent("branch", {"wan_handoff": "fiber handoff on edge",
                                                    "availability": "STANDARD", "growth": "flat"})
    capability = _Matrix(CapabilityEngine.load_builtin())
    return DesignEngine(capability), blueprint, intent


def test_harvest_interfaces_normalized_and_deduped():
    report = _build()
    harvest = harvest_interfaces(report)
    # discovery harvest includes the one-sided claim about access-sw1's port
    # (seed-advertised evidence; config never consumes it — unreachable
    # devices receive no IR, as the roles test proves).
    assert set(harvest) == {"core-sw1", "core-sw2", "access-sw1"}
    # LLDP 'Gi1/0/1' ≡ CDP 'GigabitEthernet1/0/1' must collapse (§4).
    assert harvest["core-sw1"] == ("gi1/0/1", "gi1/0/2")
    assert harvest["core-sw2"] == ("gi0/1",)


def test_design_deterministic_replay():
    engine, bp, intent = _engine_and_intent()
    design_a = engine.design(intent=intent, blueprint=bp, report=_build(),
                             answers={"router_device": "core-sw1"}, site_block_v4="10.50.0.0/16")
    design_b = engine.design(intent=intent, blueprint=bp, report=_build(),
                             answers={"router_device": "core-sw1"}, site_block_v4="10.50.0.0/16")
    assert design_a == design_b
    assert not design_a.blocked


def test_roles_and_unreachable_policy():
    engine, bp, intent = _engine_and_intent()
    design = engine.design(intent=intent, blueprint=bp, report=_build(),
                           answers={"router_device": "core-sw1"}, site_block_v4="10.50.0.0/16")
    roles = {r.device_ref: r.role for r in design.roles}
    assert roles["core-sw1"] == "ROUTER"
    # access-sw1 was never reached ⇒ outside the managed set, loudly.
    assert roles["access-sw1"] == "UNMANAGED_NEIGHBOR"
    # It receives no IR.
    ir = engine.render_ir(design, vendor_os_of={"core-sw1": "ios-xe", "core-sw2": "ios-xe"})
    assert "access-sw1" not in ir


def test_zone_plan_uses_ipam_deterministically():
    engine, bp, intent = _engine_and_intent()
    design = engine.design(intent=intent, blueprint=bp, report=_build(),
                           answers={"router_device": "core-sw1"}, site_block_v4="10.50.0.0/16")
    by_zone = {z.zone: z for z in design.zones}
    # first-fit cursor packing, coarsest-first: users /25, voice /26,
    # wan /27, mgmt /28 — zero overlap by construction.
    assert by_zone["users"].subnet == "10.50.0.0/25"
    assert by_zone["voice"].subnet == "10.50.0.128/26"
    assert by_zone["mgmt"].subnet == "10.50.0.192/28"        # /28 before /29 in the cursor
    assert by_zone["wan"].subnet == "10.50.0.208/29"         # handoff-sized /29
    assert by_zone["users"].gateway == "10.50.0.1"
    assert by_zone["mgmt"].gateway == "10.50.0.193"          # first usable of its block
    subnets = [z.subnet for z in design.zones]
    assert not __import__("netops_autopilot.engines.ipam", fromlist=["find_overlaps"]).find_overlaps(subnets)
    assert all("IPAM" in z.reason for z in design.zones)


def test_unreachable_devices_get_no_ir_and_managed_do():
    engine, bp, intent = _engine_and_intent()
    design = engine.design(intent=intent, blueprint=bp, report=_build(),
                           answers={"router_device": "core-sw1"}, site_block_v4="10.50.0.0/16")
    ir = engine.render_ir(design, vendor_os_of={"core-sw1": "ios-xe", "core-sw2": "ios-xe"})
    assert set(ir) <= {"core-sw1", "core-sw2"}
    # Router carries SVI nodes with the exact gateway addressing.
    svi_nodes = [n for n in ir["core-sw1"].nodes if n.feature == "svi"]
    assert svi_nodes and all(n.reversibility.value == "REVERSIBLE_BY_REPLACE" for n in svi_nodes)
    assert any(n.parameters["address"].startswith("10.50.0.1/") for n in svi_nodes)
    # Lineage present everywhere.
    assert all("reason" in n.parameters for ir_ in ir.values() for n in ir_.nodes if n.node_id != "noop")


def test_blocked_intent_blocks_design():
    import dataclasses
    engine, bp, intent = _engine_and_intent()
    bad = engine.design(intent=dataclasses.replace(intent, status="BLOCKED"), blueprint=bp,
                        report=_build(), answers={}, site_block_v4="10.50.0.0/16")
    assert bad.blocked and "INTENT_NOT_COMPILED" in bad.blocked_reasons
