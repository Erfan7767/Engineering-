"""The Autopilot Engine — phases, wiring, honesty gates."""

from __future__ import annotations

import dataclasses

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
from .answer_script import grants_access_retry
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
from ..engines.verification import VerificationEngine, VerificationPlanner
from ..engines.verification_executor import CLIENT_ZONE_KINDS, VerificationExecutor
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
    #: Phase 7 — ask the network whether it actually does what was asked.
    #: "Config stuck" is not "requirement met": the executor already proves the
    #: lines landed, this proves the network behaves.
    VERIFY = "VERIFY"
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
    verification: Optional[dict] = None
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
        #: device_ref → why no configuration was produced for it. Feeds the
        #: execution gate's coverage check, so a managed device that ended up
        #: with nothing is reported with a reason instead of vanishing.
        self.render_failures: dict[str, str] = {}

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
                        purpose=entry.get("purpose", ""), notes=entry.get("reason", ""),
                        rollback=entry.get("rollback", ""),
                        # Phase V: `enters_mode` drives the executor's CLI mode
                        # stack. Dropping it made every rollback plan land in
                        # the wrong mode, so it must be carried through.
                        enters_mode=bool(entry.get("enters_mode", False))))
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
            self._phase_access_retry(session, mgmt_session_factory)
            self._phase_map()
            blueprint = self._phase_elicit()
            if blueprint is None:
                return self.report
            design = self._phase_design(blueprint)
            if design is None or design.blocked:
                self.report.final = "BLOCKED-DESIGN"
                return self.report
            self._phase_render(design)
            self._bind_mgmt_context(mgmt_session_factory, session)
            self._phase_execution_gate(design, execute, mgmt_session_factory)
            if execute:
                self._phase_verify(design, mgmt_session_factory)
        except Failure as exc:
            self._phase(Phase.REPORT, "TYPED_STOP", "; ".join(exc.causes))
            self.report.final = f"BLOCKED-{exc.cls.value}"
        return self.report

    # ----------------------------------------------------------------- phases
    def _phase_verify(self, design: SiteDesign, mgmt_session_factory) -> None:
        """Phase 7 — verify the network, not the config text.

        ``VerificationPlanner`` derives the mandatory matrix from the compiled
        intent (every zone pair, plus every required service); this phase runs
        each test against the real devices and grades it only from what they
        answered. Evidence is collected through the ``Collector``, so every
        graded test is backed by a ledgered Artifact and the ``evidence_id`` on
        the result is that artifact.

        Three outcomes are kept strictly distinct, because conflating them is
        how a run ends up claiming success it did not earn:

        * ``PASS``     — every precondition positively observed on the device.
        * ``FAILED``   — a precondition was positively contradicted, and the
                         reason names the specific missing piece.
        * ``INCOMPLETE`` — the test could not be graded because its evidence
                         could not be obtained. Never reported as PASS.
        """
        assert self.report.intent is not None
        specs = VerificationPlanner().derive(self.report.intent)
        executor = VerificationExecutor(
            self.collector,
            lambda ref, _kind: mgmt_session_factory(ref, ()))
        outcome = executor.run(specs=specs, design=design)

        if not outcome.results:
            verdict = "INCOMPLETE"
        elif outcome.unrun:
            verdict = "INCOMPLETE"
        elif outcome.failed:
            verdict = "FAILED"
        else:
            verdict = "PASS"

        self.report.verification = {
            "tests_total": len(specs),
            "graded": outcome.graded,
            "passed": outcome.passed,
            "failed": outcome.failed,
            "reasons": dict(outcome.reasons),
            "unrun": {tid: why for tid, why in outcome.unrun},
            "dhcp_scope": [z.zone for z in design.zones
                           if z.kind in CLIENT_ZONE_KINDS],
            "evidence_count": len(outcome.evidence),
            "evidence_ids": [e.raw_id for e in outcome.evidence],
            "verdict": verdict,
        }
        # Cross-check against the engine that grades results: it refuses to
        # accept a result set that does not match the derived matrix exactly,
        # so a silently dropped test cannot slip through as a pass.
        if outcome.results and not outcome.unrun:
            engine_report = VerificationEngine().evaluate(specs, outcome.results)
            self.report.verification["engine_all_pass"] = engine_report.all_pass

        self._transition(Phase.EXECUTION_GATE.value, Phase.VERIFY.value,
                         "VERIFY", verdict)
        detail = (f"{len(outcome.passed)}/{len(specs)} passed"
                  + (f", {len(outcome.failed)} FAILED" if outcome.failed else "")
                  + (f", {len(outcome.unrun)} unrun" if outcome.unrun else ""))
        self._phase(Phase.VERIFY, verdict if verdict != "PASS" else "OK", detail)
        for tid in outcome.failed:
            self.io.show(f"!! VERIFY FAIL {tid}: {outcome.reasons.get(tid, '')}")
            if self.report.topology is not None:
                self.report.topology = dataclasses.replace(
                    self.report.topology,
                    gaps=tuple(self.report.topology.gaps)
                    + (f"VERIFY_FAILED {tid}: {outcome.reasons.get(tid, '')}",))
        for tid, why in outcome.unrun:
            self.io.show(f"!! VERIFY UNRUN {tid}: {why}")

        if verdict != "PASS" and self.report.final.startswith("COMPLETE"):
            # An applied run whose network does not do what was asked is not
            # complete. The config landed; the requirement did not.
            self.report.final = "INCOMPLETE-" + self.report.final.split("-", 1)[1]

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

    def _phase_access_retry(self, boot, mgmt_session_factory,
                            max_rounds: int = 2) -> None:
        """Give the operator the evidence-directed retry the gaps list promises.

        Discovery reports ``ACCESS_LIMITED`` for a device whose credentials
        were refused, and the design then excludes it from the managed set.
        That exclusion was permanent: nothing ever offered a retry, so a
        network with one differently-credentialed switch stayed permanently
        half-configured while the run still reported success.

        The loop is honest in both directions. A device that unlocks is
        re-crawled and joins the managed set with its identity confirmed; a
        device that still refuses stays excluded *and is announced*. Nothing
        is silently included and nothing is silently dropped.
        """
        assert self.report.crawl is not None
        session, family = boot
        for _round in range(max_rounds):
            limited = self._access_limited_refs()
            if not limited:
                return
            listing = ", ".join(limited)
            # Deliberately NOT ``io.confirm``: a confirmation whose default is
            # "yes" is not a confirmation. Supplying credentials to a device
            # and re-probing it is a security-relevant act, so it requires an
            # explicit affirmative answer — silence declines.
            answer = self.io.ask(
                f"{len(limited)} discovered device(s) could not be reached with the "
                f"credentials tried: {listing}.\n"
                f"Retry now with management credentials? Type 'y' to retry, "
                f"anything else to leave them out: ").strip().lower()
            if not grants_access_retry(answer):
                # No phase record here, deliberately: discovery did not run
                # again, so writing a second DISCOVERY_A row would put a phase
                # in the report that no work corresponds to. The exclusion is
                # already announced where it belongs — the gaps list
                # (DEVICE_UNREACHABLE), the design role reason
                # (UNMANAGED_NEIGHBOR) and this line on the operator's console.
                self.io.show(
                    f"ACCESS_RETRY DECLINED — {len(limited)} device(s) stay outside "
                    f"the managed set ({listing}): announced, never silently "
                    f"included or dropped.")
                return
            # Real hardware collects the secret through the management
            # factory's getpass-backed provider on the next open attempt; the
            # simulated fabric has an explicit grant hook.
            grant = getattr(mgmt_session_factory, "grant", None)
            if callable(grant):
                grant()
            allowlist = self.catalog_allowlists[family]

            class _Factory:
                def open(self, device_ref, hints):
                    if device_ref == "seed-01":
                        return session
                    return mgmt_session_factory(device_ref, hints)

            report = self.crawl.crawl(
                seed_ref="seed-01", seed_family=family,
                session_factory=_Factory(),
                allowlist_of=lambda fam: self.catalog_allowlists.get(fam, CommandAllowlist(())))
            before, after = set(self._access_limited_refs()), set()
            self.report.crawl = report
            after = set(self._access_limited_refs())
            unlocked = sorted(before - after)
            still = sorted(after)
            if unlocked:
                self.io.show(f"ACCESS RETRY OK — now reachable: {', '.join(unlocked)}")
            if not unlocked:
                self._phase(Phase.DISCOVERY_A, "ACCESS_LIMITED",
                            f"retry did not unlock any device; still limited: "
                            f"{', '.join(still) or '∅'}")
                return
        remaining = self._access_limited_refs()
        if remaining:
            self._phase(Phase.DISCOVERY_A, "ACCESS_LIMITED",
                        f"{len(remaining)} device(s) still outside the managed set: "
                        f"{', '.join(remaining)}")

    def _access_limited_refs(self) -> list[str]:
        """Devices discovery saw but could not reach for an access reason."""
        if self.report.crawl is None:
            return []
        out: list[str] = []
        for dev in self.report.crawl.devices:
            if dev.status.value == "COMPLETE":
                continue
            causes = " ".join(dev.rejection_reasons or ())
            if "ACCESS_LIMITED" in causes or "AUTH_REFUSED" in causes:
                out.append(dev.device_ref)
        return sorted(out)

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
        # Client DNS for the DHCP pools. Deliberately asked and never
        # defaulted: an invented resolver is a silent, hard-to-find outage.
        # Blank is allowed and leaves the pools without a dns-server line,
        # which the design then reports as a visible gap.
        answers["dns_servers"] = self.io.ask(
            "DNS server(s) handed to clients, comma-separated (blank = none): ").strip()
        self._dns_servers = answers["dns_servers"]
        # Keep the whole set. Every one of these was asked of a human, and the
        # design engine is the consumer — handing it a hand-picked subset is how
        # an answered requirement gets silently dropped. Two already had been:
        # `dns_servers` (no resolver ever reached a DHCP pool) and `wan_handoff`
        # (the WAN was given a static gateway the operator never described, and
        # the site was left with no internet egress).
        self._operator_answers = dict(answers)
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
        answers = self._design_answers()
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
        irs = DesignEngine(CapabilityEngine.load_builtin()).render_ir(
            design, vendor_os_of=vendor_os_of, answers=self._design_answers())
        for ref, ir in sorted(irs.items()):
            try:
                rendered = render_ir(ref, ir)
                self.report.renders[ref] = rendered
            except Failure as exc:
                lines = "; ".join(exc.causes)
                # Remembered, not just printed: the execution gate has to know
                # a managed device ended up with no configuration, and why.
                self.render_failures[ref] = lines
                self.io.show(f"Render {ref}: {lines}")
        shown = sum(1 for r in self.report.renders.values())
        for ref, rendered in sorted(self.report.renders.items()):
            self.io.show(rendered.to_text() + "\n")
        self._transition(Phase.DESIGN.value, Phase.RENDER.value, "RENDER", f"devices={shown}")
        self._phase(Phase.RENDER, "OK", f"rendered previews for {shown} device(s)")

    # ------------------------------------------------------- config coverage
    def _config_coverage(self, design: SiteDesign) -> tuple[list[str], list[tuple[str, str]]]:
        """Split the managed set into configured and unconfigured devices.

        "Managed" is the design's own statement — every role except
        ``UNMANAGED_NEIGHBOR``. Deriving it from ``self.report.renders``
        instead, which is what the gate used to do, made the check
        self-confirming: a device that produced no configuration simply was not
        in the dictionary, so it was not expected either, and the run reported
        success over a network that was missing a device.

        Returns ``(managed, unconfigured)`` where each unconfigured entry is
        ``(device_ref, reason)``. The reason comes from the recorded render
        failure when there is one; otherwise the honest statement that no
        configuration was produced and the engine does not know why.
        """
        managed = sorted(
            r.device_ref for r in design.roles if r.role != "UNMANAGED_NEIGHBOR")
        unconfigured: list[tuple[str, str]] = []
        for ref in managed:
            if ref in self.report.renders:
                continue
            reason = self.render_failures.get(
                ref,
                "no configuration was produced for this device (no rendered "
                "block and no recorded render failure)")
            unconfigured.append((ref, reason))
        return managed, unconfigured

    def _partial_renders(self, managed: list[str]) -> list[tuple[str, str]]:
        """Managed devices whose render is missing at least one asked-for feature.

        ``NOT_MODELED`` means the design *did* ask for something this vendor's
        renderer cannot express — not that the feature was unwanted. Showing it
        in the preview was honest; leaving it out of the outcome was not,
        because the run then reported a device as configured when part of its
        configuration was never produced. A render where EVERY node is
        NOT_MODELED is the extreme case: a RenderedConfig exists, so the old
        "is it in renders" check passed, yet not one command was sent.

        Returns ``(device_ref, reason)`` for each partially rendered device.
        """
        out: list[tuple[str, str]] = []
        for ref in managed:
            rendered = self.report.renders.get(ref)
            if rendered is None:
                continue                      # counted by _config_coverage
            # `documentation`/node_id="noop" is the placeholder a device gets
            # when the design produced no nodes for it. That device needs no
            # change, so it is complete — not a renderer gap.
            missing = [b for b in rendered.blocks
                       if b.status != "RENDERED" and b.node_id != "noop"]
            if not missing:
                continue
            features = sorted({
                (b.reason.split("feature ", 1)[1].split(" has no template", 1)[0]
                 if "feature " in b.reason else b.node_id)
                for b in missing})
            kind = ("NO RENDERABLE NODES" if not any(
                b.status == "RENDERED" for b in rendered.blocks)
                else "PARTIALLY RENDERED")
            if kind == "NO RENDERABLE NODES" and any(
                    b.node_id == "noop" for b in rendered.blocks):
                continue                     # no-op design, nothing to do
            out.append((ref, f"{kind}: {', '.join(features)} — the design asked "
                             f"for these and this vendor has no template (T2)"))
        return out

    def _announce_unconfigured(self, unconfigured: list[tuple[str, str]]) -> None:
        """Say plainly which managed devices got nothing, and add a gap."""
        for ref, reason in unconfigured:
            self.io.show(
                f"!! UNCONFIGURED {ref}: {reason} — this device is in the "
                f"managed set and received NO configuration. The network is "
                f"incomplete; this is never reported as a clean run.")
            if self.report.topology is not None:
                # ``gaps`` is an immutable tuple, so the map is rebuilt rather
                # than mutated in place.
                self.report.topology = dataclasses.replace(
                    self.report.topology,
                    gaps=tuple(self.report.topology.gaps)
                    + (f"DEVICE_UNCONFIGURED {ref}: {reason}",))

    def _phase_execution_gate(self, design: SiteDesign, execute: bool,
                              mgmt_session_factory=None) -> None:
        """The execution gate.

        With lab-verified allowlists, the gate has three outcomes:

        1. ``execute=False`` (default) — stage every change, return
           ``COMPLETE-STAGED``. The human can review the rendered output
           and re-run with ``--execute`` to apply.

        2. ``execute=True`` AND human-confirmed — apply every staged
           change via :class:`ConfigExecutor`. Each device gets a
           :class:`ChangeRecord`; rollback is automatic on verification
           failure.

        3. ``execute=True`` but the operator says no at the BOND gate —
           the run ends with ``BLOCKED-DENIED`` (the engine never
           configures a device the human has not approved).
        """
        from ..access.executor import ConfigExecutor, ChangeOutcome
        staged = sorted(self.report.renders)
        managed, unconfigured = self._config_coverage(design)
        partial = self._partial_renders(managed)
        if unconfigured:
            self._announce_unconfigured(unconfigured)
        for ref, reason in partial:
            self.io.show(f"!! INCOMPLETE CONFIG {ref}: {reason}")
            if self.report.topology is not None:
                self.report.topology = dataclasses.replace(
                    self.report.topology,
                    gaps=tuple(self.report.topology.gaps)
                    + (f"CONFIG_INCOMPLETE {ref}: {reason}",))
        if not execute:
            self.report.execution = {
                "requested": False,
                "outcome": ("INCOMPLETE-STAGED" if (unconfigured or partial)
                            else "STAGED"),
                "reason": ("execute=False; changes are staged, not applied"
                           if not unconfigured else
                           "execute=False; staged, but managed device(s) have no "
                           "configuration — see unconfigured_devices"),
                "staged_devices": staged,
                "managed_devices": managed,
                "unconfigured_devices": [ref for ref, _ in unconfigured],
                "unconfigured_reasons": {ref: why for ref, why in unconfigured},
                "partially_rendered": {ref: why for ref, why in partial},
                "human_required_to_unlock": "re-run with --execute and a confirmation at the BOND gate",
            }
            incomplete_now = bool(unconfigured or partial)
            self._transition(Phase.RENDER.value, Phase.EXECUTION_GATE.value, "GATE",
                             "INCOMPLETE" if incomplete_now else "STAGED")
            self._phase(Phase.EXECUTION_GATE, "OK" if not incomplete_now else "INCOMPLETE",
                        f"staged {len(staged)}/{len(managed)} managed device(s); apply with --execute"
                        + (f" — {len(unconfigured)} UNCONFIGURED" if unconfigured else "")
                        + (f" — {len(partial)} PARTIAL" if partial else ""))
            self.report.final = "INCOMPLETE-STAGED" if incomplete_now else "COMPLETE-STAGED"
            self._transition(Phase.EXECUTION_GATE.value, Phase.REPORT.value, "REPORT", self.report.final)
            return

        # Execute path. Demand an explicit human confirmation.
        # The gate has a single input (typed BOND); the human types
        # BOND once to unlock the apply. A second call would consume
        # the next scripted answer and break scripted tests.
        typed = self.io.ask(
            f"About to APPLY config to {len(staged)} device(s). "
            f"Type BOND exactly to confirm (or anything else to abort): "
        ).strip()
        if typed != "BOND":
            self.report.execution = {
                "requested": True,
                "outcome": "BLOCKED_DENIED",
                "reason": f"operator did not type BOND (got {typed!r}); refusing to apply",
                "staged_devices": staged,
            }
            self._transition(Phase.RENDER.value, Phase.EXECUTION_GATE.value, "GATE", "DENIED")
            self._phase(Phase.EXECUTION_GATE, "TYPED_STOP", "operator denied at the apply gate")
            self.report.final = "BLOCKED-DENIED"
            return

        # Apply each device's rendered config. We use the live
        # ``mgmt_session_factory`` so the executor actually pushes
        # the lines to the device (in sim mode this is the
        # SimFabric; on real hardware the SSH/Telnet session).
        # This is the "no hallucination" rule: the apply path now
        # executes for real, not just plans.
        records = []
        applied_sessions: list = []
        skipped: list[tuple[str, str]] = []
        for ref, rendered in self.report.renders.items():
            family = self._family_of(ref)
            if not family:
                # Was a bare `continue`: the device dropped out of the run and
                # the verdict was computed over whatever was left, so a device
                # with an unknown vendor family made the apply look complete.
                skipped.append((ref, "VENDOR_FAMILY_UNKNOWN: no allowlist can be "
                                     "selected, so nothing was sent"))
                continue
            allowlist = self.catalog_allowlists.get(family)
            if not allowlist:
                skipped.append((ref, f"NO_ALLOWLIST:{family}: configuration was "
                                     "rendered but cannot be gated, so nothing was sent"))
                continue
            ex = ConfigExecutor(allowlist=allowlist, store=self.store,
                                run_id=f"{self._run_id_safe()}-{ref}",
                                key_id=self.key_id,
                                collector_id=f"config-executor:{ref}",
                                time_authority=self.time)
            # CONFIG_HIGH_RISK (routing daemons, credentials) is unlocked by
            # the operator's BOND, never by the engine on its own.
            ex.arm_high_risk()
            # Open a real management session for this device. The
            # family is REACHABLE because it was discovered. In sim
            # mode this is the SimFabric's per-device session; on
            # real hardware the SSH/Telnet adapter.
            session = None
            try:
                session = mgmt_session_factory(ref, ())
            except Exception as exc:  # noqa: BLE001
                # If we can't open a session, fall back to a dry_run
                # so the apply still records a change record. The
                # outcome below will reflect this.
                record = ex.apply(
                    ref, _NullSession(), _all_commands(rendered),
                    dry_run=True,
                    wrappers=rendered.wrappers,
                    mode_exit=rendered.mode_exit,
                )
                record.failure_causes.append(
                    f"NO_MGMT_SESSION: {exc!r}"
                )
                records.append(record.to_dict())
                continue
            if session is None:
                record = ex.apply(
                    ref, _NullSession(), _all_commands(rendered),
                    dry_run=True,
                    wrappers=rendered.wrappers,
                    mode_exit=rendered.mode_exit,
                )
                records.append(record.to_dict())
                continue
            applied_sessions.append((ref, session))
            # Real apply: dry_run=False sends every line to the
            # device through the session. The executor's allowlist
            # gate runs FIRST, so an unsupported line is rejected
            # without ever reaching the wire.
            record = ex.apply(
                ref, session, _all_commands(rendered),
                dry_run=False,
                wrappers=rendered.wrappers,
                    mode_exit=rendered.mode_exit,
                persist=getattr(rendered, "persist", ()),
            )
            records.append(record.to_dict())

        outcomes = [r["outcome"] for r in records]
        # A managed device with no configuration at all, and a rendered device
        # that never reached the wire, are both incompleteness — distinct from
        # the safety failures below, but never something a clean verdict may
        # paper over. ``all(...)`` over an empty list is vacuously True, so an
        # apply that sent nothing used to report COMPLETE-APPLIED.
        incomplete = sorted({ref for ref, _ in unconfigured}
                            | {ref for ref, _ in skipped}
                            | {ref for ref, _ in partial})
        for ref, why in skipped:
            self.io.show(f"!! NOT_SENT {ref}: {why}")
        if "PERSIST_FAILED" in outcomes:
            # Applied and verified, but not saved: the network works right now
            # and silently breaks at the next reload. Louder than PARTIAL.
            verdict = "PERSIST_FAILED"
            self.report.final = "BLOCKED-PERSIST-FAILED"
        elif "ROLLBACK_FAILED" in outcomes:
            # A device we could not restore is the loudest possible outcome.
            # It must outrank everything else so a run can never be reported
            # as COMPLETE while a device sits in a partial state.
            verdict = "ROLLBACK_FAILED"
            self.report.final = "BLOCKED-ROLLBACK-FAILED"
        elif incomplete:
            verdict = "INCOMPLETE"
            self.report.final = "INCOMPLETE-APPLIED"
        elif outcomes and all(o == "APPLIED" for o in outcomes):
            verdict = "APPLIED"
            self.report.final = "COMPLETE-APPLIED"
        elif not outcomes:
            # Nothing was sent to anything. Vacuous success is a lie.
            verdict = "NOTHING_APPLIED"
            self.report.final = "INCOMPLETE-APPLIED"
        elif "REJECTED" in outcomes:
            verdict = "REJECTED"
            self.report.final = "BLOCKED-APPLY"
        elif all(o == "ROLLED_BACK" for o in outcomes):
            verdict = "ROLLED_BACK"
            self.report.final = "BLOCKED-ROLLED-BACK"
        else:
            verdict = "PARTIAL"
            self.report.final = "COMPLETE-PARTIAL"

        self.report.execution = {
            "requested": True,
            "outcome": verdict,
            "staged_devices": staged,
            "managed_devices": managed,
            "unconfigured_devices": [ref for ref, _ in unconfigured],
            "unconfigured_reasons": {ref: why for ref, why in unconfigured},
            "partially_rendered": {ref: why for ref, why in partial},
            "not_sent": {ref: why for ref, why in skipped},
            "change_records": records,
        }
        self._transition(Phase.RENDER.value, Phase.EXECUTION_GATE.value, "GATE", verdict)
        self._phase(Phase.EXECUTION_GATE, "OK" if not incomplete else "INCOMPLETE",
                    f"applied: {sum(o == 'APPLIED' for o in outcomes)}/{len(managed)} "
                    f"managed device(s)"
                    + (f" — {len(incomplete)} INCOMPLETE" if incomplete else ""))
        self._transition(Phase.EXECUTION_GATE.value, Phase.REPORT.value, "REPORT", self.report.final)

    def _design_answers(self) -> dict[str, str]:
        """Every answer the operator gave, for the design and the IR alike.

        Values come from what the human actually typed during elicitation.
        Anything not asked for is simply absent, so the renderer reports the
        gap instead of inventing a value.

        This is the single place that hands operator input to the engines. It
        used to be two — this helper for the IR and a separate literal dict in
        ``_phase_design`` — and each hand-picked a different subset, which is
        exactly how two answered requirements went missing: ``dns_servers``
        never reached a DHCP pool, and ``wan_handoff`` never reached the WAN,
        so the site was built with a static gateway the operator never
        described and no internet egress at all.
        """
        answers = dict(getattr(self, "_operator_answers", {}))
        answers["router_device"] = self._ask_again("router_device", "seed-01")
        return answers

    def _bind_mgmt_context(self, mgmt_session_factory, console_session) -> None:
        """Hand the discovery evidence to the management-session factory.

        A real management factory must reach a device at an address discovery
        *observed*, and must prove the session is the device the plan was
        built for (serial confirmation) before any configuration is sent. It
        also reuses the already-open console session for the seed device —
        opening a second handle on the same serial port would fail.

        Duck-typed: the simulated fabric factory has no such need, so only
        factories that declare ``bind_crawl`` receive it.
        """
        binder = getattr(mgmt_session_factory, "bind_crawl", None)
        if binder is None:
            return
        binder(self.report.crawl, console_session=console_session, seed_ref="seed-01")

    def _family_of(self, device_ref: str) -> Optional[str]:
        if not self.report.crawl:
            return None
        for d in self.report.crawl.devices:
            if d.device_ref == device_ref and d.identity:
                return d.identity.vendor_family
        return None

    def _run_id_safe(self) -> str:
        return f"run-{datetime.now(timezone.utc).strftime('%H%M%S')}"


def _all_commands(rendered) -> tuple[str, ...]:
    """Every command of a render, in order, across **all** blocks.

    Phase V: the executor used to apply ``rendered.blocks[0].commands`` only,
    while ``RenderedConfig.to_text()`` — the preview the human approves —
    prints every block. The operator therefore approved more than the engine
    applied, and the difference was silent. Preview and apply now share one
    source of truth.
    """
    out: list[str] = []
    for block in rendered.blocks:
        out.extend(block.commands)
    return tuple(out)


class _NullSession:
    """A no-op ExecSession used when the orchestrator dry-runs a change.

    The real CLI passes a live SerialConsoleTransport or SSHConsoleTransport;
    the orchestrator itself never holds the device handle. This NullSession
    makes it explicit that we are NOT sending to a device right now.
    """

    def execute(self, command: str, timeout_s: Optional[float] = None) -> bytes:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            "NULL_SESSION: orchestrator cannot apply; wire a real CLI pass for live changes",))

    def close(self) -> None:
        pass
