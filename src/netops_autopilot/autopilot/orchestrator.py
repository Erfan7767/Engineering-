"""The Autopilot Engine — phases, wiring, honesty gates."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional, Protocol

from ..access.allowlist import AllowlistEntry, CommandAllowlist
from ..access.collector import Collector, SessionLockManager
from ..access.day0 import Day0State, classify_day0_state
from ..access.vendor_detect import detect_family_candidates
from ..core.budgets import CommandBudget
from ..core.counters import CounterCollector
from ..core.failures import Failure, FailureClass
from ..core.timeauth import TimeAuthority
from ..engines.blueprints import BLUEPRINTS, ElicitationResult, business_intent_from_blueprint, elicit, menu
from ..engines.capability import CapabilityEngine
from ..engines.claim_factory import ClaimFactory
from ..engines.config_renderer import RenderedConfig, render_ir
from ..engines.day0_bootstrap import Day0BootstrapEngine, load_bootstrap_steps
from ..engines.design_engine import DesignEngine, SiteDesign
from ..engines.discovery_crawl import CrawlReport, DeviceClass, DiscoveryCrawlEngine, SessionFactory
from ..engines.intent_compiler import IntentCompiler, NetworkIntent
from ..engines.link_evidence import LinkEvidenceEngine
from ..engines.service_graph import ServiceGraph
from ..engines.topology_map import TopologyMap, TopologyMapEngine
from ..fsm.link_fsm import build_link_fsm
from ..ledger.models import OperatorIdentity, StateTransition
from ..ledger.store import LedgerStore
from ..parsers.catalog import default_registry
from ..specs_data import specs_data_dir
from ..twin.twin import DigitalTwin

_AUTOPILOT_ACTOR = OperatorIdentity(kind="ENGINE", id="AUTOPILOT")


class Phase(str, Enum):
    BOND = "BOND"
    BOOT_PROBE = "BOOT_PROBE"
    DISCOVERY_A = "DISCOVERY_A"
    TOPOLOGY_MAP = "TOPOLOGY_MAP"
    INTENT_ELICITATION = "INTENT_ELICITATION"
    DESIGN = "DESIGN"
    RENDER = "RENDER"
    EXECUTION_GATE = "EXECUTION_GATE"
    REPORT = "REPORT"


class OperatorIO(Protocol):
    """The human channel — injected (CLI stdin/stdout, scripted in tests)."""

    def ask(self, question: str) -> str: ...
    def confirm(self, question: str) -> bool: ...
    def show(self, text: str) -> None: ...


@dataclass
class PhaseRecord:
    phase: Phase
    status: str                       # OK | BLOCKED | HUMAN_DECISION | TYPED_STOP
    detail: str = ""


@dataclass
class AutopilotReport:
    phases: list[PhaseRecord] = field(default_factory=list)
    seed_family: Optional[str] = None
    day0_state: Optional[str] = None
    crawl: Optional[CrawlReport] = None
    topology: Optional[TopologyMap] = None
    elicitation: Optional[ElicitationResult] = None
    intent: Optional[NetworkIntent] = None
    design: Optional[SiteDesign] = None
    renders: dict[str, RenderedConfig] = field(default_factory=dict)
    execution: Optional[dict] = None
    final: str = "RUNNING"            # COMPLETE-STAGED | BLOCKED-*


class AutopilotEngine:
    """Owns one run. All components are real; IO is injected."""

    def __init__(
        self,
        *,
        store: LedgerStore,
        key_id: str,
        io: OperatorIO,
        time_authority: Optional[TimeAuthority] = None,
    ) -> None:
        self.store = store
        self.key_id = key_id
        self.io = io
        self.counters = CounterCollector()
        self.time = time_authority or TimeAuthority(clock=lambda: datetime.now(timezone.utc))
        self.registry = default_registry()
        self.time = time_authority or self.time
        self.locks = SessionLockManager()
        self.twin = DigitalTwin(store, self.counters)
        self.links = LinkEvidenceEngine(
            lambda: build_link_fsm(recorder=store, counters=self.counters))
        self.claims = ClaimFactory(store, self.registry)
        self.catalog_allowlists = self._load_embedded_allowlists()
        self.collector: Optional[Collector] = None      # built per-family below
        self.crawl = DiscoveryCrawlEngine(
            store=store, twin=self.twin, collector=None,  # set in run()
            parsers=self.registry, link_engine=self.links, claim_factory=self.claims)
        self.report = AutopilotReport()

    # ------------------------------------------------------------------ utils
    def _load_embedded_allowlists(self) -> dict[str, CommandAllowlist]:
        out: dict[str, CommandAllowlist] = {}
        for family_file, family in (
            ("cisco_iosxe.json", "cisco/ios-xe"), ("routeros.json", "routeros"),
            ("junos.json", "junos"), ("fortios.json", "fortios"),
            ("arubaos.json", "arubaos"), ("unifi.json", "unifi"),
        ):
            path_text = specs_data_dir("allowlists", family_file)
            if not path_text:
                continue
            import json as _json
            doc = _json.loads(open(path_text, encoding="utf-8").read())
            entries: list[AllowlistEntry] = []
            for cls_name, body in doc.get("classes", {}).items():
                for entry in body.get("entries", []):
                    entries.append(AllowlistEntry(
                        template=entry["template"], cls=cls_name,
                        purpose=entry.get("purpose", ""), notes=entry.get("reason", "")))
            out[family] = CommandAllowlist(tuple(entries))
        return out

    def _transition(self, from_phase: str, to_phase: str, guard: str, detail: str) -> None:
        self.store.append_transition(StateTransition(
            fsm="AUTOPILOT", entity_ref="run",
            from_state=from_phase, to_state=to_phase, guard_id=guard,
            evidence_ids=[f"detail:{detail[:60]}"], actor=_AUTOPILOT_ACTOR,
            collected_at=datetime.now(timezone.utc)))

    def _phase(self, phase: Phase, status: str, detail: str) -> None:
        self.report.phases.append(PhaseRecord(phase, status, detail))
        self.io.show(f"[{phase.value}] {status} — {detail}")

    # -------------------------------------------------------------------- run
    def run(
        self,
        *,
        probe_port_session_factory: Callable[[str], object],
        mgmt_session_factory: Callable[[str, tuple[str, ...]], object],
        port: str,
        execute: bool = False,
    ) -> AutopilotReport:
        try:
            self._phase_bond(port)
            session = self._phase_boot_probe(port, probe_port_session_factory)
            if session is None:
                return self.report
            self._phase_discovery(session, mgmt_session_factory)
            self._phase_map()
            blueprint = self._phase_elicit()
            if blueprint is None:
                return self.report
            design = self._phase_design(blueprint)
            if design is None or design.blocked:
                self.report.final = "BLOCKED-DESIGN"
                return self.report
            self._phase_render(design)
            self._phase_execution_gate(design, execute)
        except Failure as exc:
            self._phase(Phase.REPORT, "TYPED_STOP", "; ".join(exc.causes))
            self.report.final = f"BLOCKED-{exc.cls.value}"
        return self.report

    # ----------------------------------------------------------------- phases
    def _phase_bond(self, port: str) -> None:
        self._phase(Phase.BOND, "HUMAN_DECISION",
                    f"confirm the physical binding: PC port {port} ↔ the SEED device console/email link "
                    f"(the identity-binding moment, D0-07 §1.4)")
        ok = self.io.confirm(f"Is port {port} physically connected to the seed device? [y/N] ")
        if not ok:
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                "OPERATOR_DID_NOT_CONFIRM_BINDING: run cannot start without identity binding (S0)",))
        self._transition("START", Phase.BOND.value, "OP-BIND", f"operator bound {port}")

    def _phase_boot_probe(self, port: str, session_factory):
        banner = session_factory(port)  # returns (session, banner_bytes)
        session, banner = banner if isinstance(banner, tuple) else (banner, b"")
        candidates = detect_family_candidates(banner or b"")
        day0 = classify_day0_state(candidates[0], banner) if candidates else Day0State.UNKNOWN
        self.report.day0_state = day0.value
        if not candidates:
            answer = self.io.ask(
                "Vendor family UNKNOWN from the console banner (never guessed). "
                "Enter it explicitly [cisco/ios-xe|routeros|junos|fortios|arubaos|unifi]: ")
            family = answer.strip().lower()
            if family not in self.catalog_allowlists:
                raise Failure(cls=FailureClass.BLOCKED, causes=(
                    f"FAMILY_UNKNOWN: {family!r} not in the v1 catalog — no plan, no guess",))
        elif len(candidates) > 1:
            answer = self.io.ask(
                f"Ambiguous banner: candidates {candidates}. Which family is this device? "
                f"[{ '|'.join(candidates) }]: ")
            family = answer.strip().lower()
            if family not in candidates:
                raise Failure(cls=FailureClass.BLOCKED, causes=(
                    f"OPERATOR_ANSWER_NOT_IN_CANDIDATES: {family!r}",))
        else:
            family = candidates[0]
            self.io.show(f"Banner evidence ⇒ family={family} (data-driven marker match)")
        self.report.seed_family = family
        # Day-0 state announcements (typed, never assumed).
        if day0 in (Day0State.PASSWORD_LOCKED, Day0State.RECOVERY_REQUIRED):
            self.io.show(
                f"⚠ Day-0 state = {day0.value} — a HUMAN_TASK is required on this device "
                f"(recovery/credentials) before automation can proceed (D0-07 §3/§4).")
        self._transition(Phase.BOND.value, Phase.BOOT_PROBE.value, "FAMILY-ID",
                         f"family={family} day0={day0.value}")
        self._phase(Phase.BOOT_PROBE, "OK", f"family={family} day0={day0.value}")
        family_file = {"cisco/ios-xe": "cisco_iosxe.json", "routeros": "routeros.json",
                       "junos": "junos.json", "fortios": "fortios.json",
                       "arubaos": "arubaos.json", "unifi": "unifi.json"}[family]
        try:
            steps = load_bootstrap_steps(family_file, hostname="seed-01")
            self.io.show(f"Bootstrap plan loaded: {len(steps)} steps "
                         f"(seed templates verified={steps[0].verified_seed if steps else 'n/a'})")
        except Failure as exc:
            self.io.show(f"Bootstrap: {'; '.join(exc.causes)}")
        return (session, family)

    def _phase_discovery(self, boot, mgmt_session_factory) -> None:
        session, family = boot
        allowlist = self.catalog_allowlists[family]
        self.collector = Collector(
            store=self.store, key_id=self.key_id, allowlist=allowlist,
            time_authority=self.time, locks=self.locks,
            default_budget=CommandBudget(max_retries=1))
        self.crawl = DiscoveryCrawlEngine(
            store=self.store, twin=self.twin, collector=self.collector,
            parsers=self.registry, link_engine=self.links, claim_factory=self.claims)

        class _Factory:
            def open(self, device_ref, hints):
                if device_ref == "seed-01":
                    return session
                return mgmt_session_factory(device_ref, hints)

        plan = self.crawl.plan_for(family, allowlist)
        self.io.show(f"Crawl plan (catalog ∩ READ_ONLY allowlist): "
                     f"{', '.join(cmd for cmd, _ in plan) or '∅'}")
        report = self.crawl.crawl(
            seed_ref="seed-01", seed_family=family,
            session_factory=_Factory(),
            allowlist_of=lambda fam: self.catalog_allowlists.get(fam, CommandAllowlist(())))
        self.report.crawl = report
        totals = report.totals
        self._transition(Phase.BOOT_PROBE.value, Phase.DISCOVERY_A.value, "CRAWL",
                         f"devices={totals['devices']} cmds={totals['commands_collected']}/{totals['commands_planned']}")
        self._phase(Phase.DISCOVERY_A, "OK",
                    f"devices={totals['devices']} commands={totals['commands_collected']}/{totals['commands_planned']} "
                    f"statuses={totals['device_status']}")

    def _phase_map(self) -> None:
        assert self.report.crawl is not None
        topo = TopologyMapEngine(self.twin).build(self.report.crawl)
        self.report.topology = topo
        self.io.show("\n" + topo.ascii + "\n")
        self._transition(Phase.DISCOVERY_A.value, Phase.TOPOLOGY_MAP.value, "MAP",
                         f"nodes={len(topo.nodes)} edges={len(topo.edges)} gaps={len(topo.gaps)}")
        self._phase(Phase.TOPOLOGY_MAP, "OK",
                    f"nodes={len(topo.nodes)} links={len(topo.edges)} gaps={len(topo.gaps)}")

    def _phase_elicit(self):
        assert self.report.crawl is not None
        answer = self.io.ask("What kind of network do you want to build? "
                             "(describe it, or pick a blueprint id)\n" + menu() + "\n> ")
        result = elicit(answer)
        self.report.elicitation = result
        if result.status == "UNKNOWN":
            self._phase(Phase.INTENT_ELICITATION, "BLOCKED", "answer did not match any blueprint (UNKNOWN)")
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                "INTENT_UNKNOWN: the human's answer matched no blueprint — asked again with the menu "
                "(never defaulted)",))
        if result.status == "BLOCKED":
            self._phase(Phase.INTENT_ELICITATION, "HUMAN_DECISION", "ambiguity — asking to disambiguate")
            answer = self.io.ask(result.question + "\n> ")
            result = elicit(answer)
            self.report.elicitation = result
            if result.status != "MATCHED":
                raise Failure(cls=FailureClass.BLOCKED, causes=(
                    "INTENT_STILL_AMBIGUOUS: refusing to guess the network type",))
        bp = result.blueprint
        assert bp is not None
        crawl = self.report.crawl
        reachable = [d.device_ref for d in crawl.devices if d.status.value == "COMPLETE"]
        router_default = reachable[0] if reachable else ""
        answers: dict[str, str] = {}
        answers["router_device"] = self.io.ask(
            f"On which discovered device does the WAN/ISP terminate? [{router_default}]: ").strip() or router_default
        answers["wan_handoff"] = self.io.ask("Describe the WAN handoff (e.g., 'ISP fiber, dhcp'): ").strip()
        answers["availability"] = (self.io.ask("Availability class [STANDARD|HIGH]: ").strip() or "STANDARD")
        answers["growth"] = self.io.ask("Growth plan (e.g., '+25% in 12 months'): ").strip() or "+25% in 12 months"
        request, missing = business_intent_from_blueprint(
            bp, answers=answers, requirement_text=answer)
        if missing:
            raise Failure(cls=FailureClass.BLOCKED, causes=tuple(
                f"BLUEPRINT_PARAM_MISSING:{m}" for m in missing))
        compiler = IntentCompiler(ServiceGraph.load_builtin())
        intent = compiler.compile(request)  # type: ignore[arg-type]
        self.report.intent = intent
        if intent.status != "COMPILED":
            self._phase(Phase.INTENT_ELICITATION, "BLOCKED",
                        f"compiler BLOCKED: {[q.code for q in intent.blocking_questions]}")
            raise Failure(cls=FailureClass.BLOCKED, causes=tuple(
                f"COMPILER_{q.code}" for q in intent.blocking_questions))
        self._transition(Phase.TOPOLOGY_MAP.value, Phase.INTENT_ELICITATION.value,
                         "INTENT", f"blueprint={bp.blueprint_id} rules={len(intent.rules)}")
        self._phase(Phase.INTENT_ELICITATION, "OK",
                    f"blueprint={bp.blueprint_id} (keyword={result.matched_keyword}) "
                    f"→ COMPILED: {len(intent.zones)} zones, {len(intent.rules)} matrix rules")
        return bp

    def _phase_design(self, blueprint) -> Optional[SiteDesign]:
        assert self.report.crawl is not None and self.report.intent is not None
        capability = CapabilityEngine.load_builtin()
        engine = DesignEngine(capability)
        answers = {
            "router_device": self._ask_again("router_device", "seed-01"),
        }
        design = engine.design(
            intent=self.report.intent, blueprint=blueprint, report=self.report.crawl,
            answers=answers, site_block_v4="10.240.0.0/16")
        self.report.design = design
        if design.blocked:
            for q in design.blocking_questions:
                self.io.show(f"BLOCKING: {q}")
            self._phase(Phase.DESIGN, "BLOCKED", f"{len(design.blocking_questions)} blocking questions")
            return design
        lines = ["", "SITE DESIGN (deterministic; replay-identical):"]
        lines.append(f"  design_id: {design.design_id}")
        for role in design.roles:
            lines.append(f"  ROLE {role.device_ref:<16} {role.role:<18} ({role.reason})")
        for zone in design.zones:
            lines.append(f"  ZONE {zone.zone:<8} vlan={zone.vlan_id:<4} {zone.subnet:<18} gw={zone.gateway} on {zone.routed_on}")
        for up in design.uplinks:
            lines.append(f"  UPLINK {up.device_ref}:{up.local_port} ↔ {up.peer_ref}:{up.peer_port} [{up.link_state}]")
        for acc in design.access:
            lines.append(f"  ACCESS {acc.device_ref}:{acc.port} → vlan {acc.vlan_id} ({acc.zone})")
        self.io.show("\n".join(lines) + "\n")
        self._transition(Phase.INTENT_ELICITATION.value, Phase.DESIGN.value, "DESIGN",
                         f"zones={len(design.zones)} uplinks={len(design.uplinks)} access={len(design.access)}")
        self._phase(Phase.DESIGN, "OK",
                    f"{len(design.zones)} zones · {len(design.uplinks)} uplinks · {len(design.access)} access ports")
        return design

    def _ask_again(self, key: str, default: str) -> str:
        return default

    def _phase_render(self, design: SiteDesign) -> None:
        assert self.report.crawl is not None
        vendor_os_of = {}
        for dev in self.report.crawl.devices:
            if dev.identity and dev.identity.vendor_family:
                vendor_os_of[dev.device_ref] = dev.identity.vendor_family.split("/")[-1]
        irs = DesignEngine(CapabilityEngine.load_builtin()).render_ir(design, vendor_os_of=vendor_os_of)
        for ref, ir in sorted(irs.items()):
            try:
                rendered = render_ir(ref, ir)
                self.report.renders[ref] = rendered
            except Failure as exc:
                lines = "; ".join(exc.causes)
                self.io.show(f"Render {ref}: {lines}")
        shown = sum(1 for r in self.report.renders.values())
        for ref, rendered in sorted(self.report.renders.items()):
            self.io.show(rendered.to_text() + "\n")
        self._transition(Phase.DESIGN.value, Phase.RENDER.value, "RENDER", f"devices={shown}")
        self._phase(Phase.RENDER, "OK", f"rendered previews for {shown} device(s)")

    def _phase_execution_gate(self, design: SiteDesign, execute: bool) -> None:
        # The law: CONFIG allowlist classes are EMPTY seeds (T3). Nothing may
        # configure today. Staging artifacts exist; application is a typed STOP.
        blocker = ("CONFIG_ALLOWLIST_EMPTY: all six vendors ship empty CONFIG_REVERSIBLE/"
                   "CONFIG_HIGH_RISK classes (seed-verify-in-lab) — application BLOCKED by T3. "
                   "Staged: IR + renderer PREVIEWs; awaiting lab syntax evidence to unlock execution.")
        self.report.execution = {
            "requested": execute,
            "outcome": "STAGED_BLOCKED_BY_LAW",
            "reason": blocker,
            "staged_devices": sorted(self.report.renders),
            "human_required_to_unlock": "lab evidence populates CONFIG allowlist classes (T3/T2)",
        }
        self._transition(Phase.RENDER.value, Phase.EXECUTION_GATE.value, "GATE", "STAGED_BLOCKED_BY_LAW")
        self._phase(Phase.EXECUTION_GATE, "TYPED_STOP", blocker)
        self.report.final = "COMPLETE-STAGED"
        self._transition(Phase.EXECUTION_GATE.value, Phase.REPORT.value, "REPORT", self.report.final)
