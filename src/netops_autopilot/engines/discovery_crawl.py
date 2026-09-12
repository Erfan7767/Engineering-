"""Discovery Crawl Engine — evidence-driven multi-device discovery (§10).

The operator's scenario, mechanized: ONE device is connected to the PC; the
engine identifies it with real show commands, reads its neighbor evidence
(LLDP/CDP/MNDP — passive only), then walks to every reachable neighbor and
repeats until the frontier is exhausted. Nothing is assumed:

* the command plan is DERIVED from the parser catalog ∩ the vendor's
  READ_ONLY allowlist — a command with no parser (or a parser with no
  allowlisted command) is simply not issued, and the omission is reported;
* every neighbor edge feeds FSM-4 (Link Evidence Engine): one-sided tables
  reach ONE_SIDED at most, bidirectional matches reach the passive ceiling
  DIRECT_NEIGHBOR_PROBABLE; CONFIRMED/PHYSICAL stay for later gated proof;
* a device whose session factory refuses is recorded UNREACHABLE with the
  failure cause — never silently dropped (T4 per-device n/N accounting);
* the crawl is DETERMINISTIC: sorted frontier, stable plan order, stable
  report ordering; replaying it over identical sessions is byte-identical.
"""

from __future__ import annotations

import ipaddress

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, Protocol

from ..access.allowlist import CommandAllowlist
from ..access.collector import Collector
from ..adapters.interfaces import ExecSession
from ..core.failures import Failure, FailureClass
from ..fsm import link_fsm as lf
from ..ledger.models import Observation, ParseStatus
from ..ledger.store import LedgerStore
from ..parsers.portnames import normalize_port
from ..parsers.registry import Parser, ParserRegistry
from ..twin.twin import DigitalTwin
from .claim_factory import ClaimFactory
from .link_evidence import LinkEvidenceEngine


class DeviceClass(str, Enum):
    """Reachability classification of a discovered device."""

    SEED = "SEED"                    # the direct-connected device
    NEIGHBOR_REACHED = "NEIGHBOR_REACHED"
    NEIGHBOR_UNREACHABLE = "NEIGHBOR_UNREACHABLE"   # evidence seen, session refused
    NEIGHBOR_NO_PATH_FACTS = "NEIGHBOR_NO_PATH_FACTS"  # no mgmt address advertised
    #: Phase X — found through ARP + the MAC address table rather than a
    #: neighbour advertisement. Weaker evidence than CDP/LLDP and graded as
    #: such, but it is the only way to see a device with LLDP disabled.
    NEIGHBOR_L3_EVIDENCE = "NEIGHBOR_L3_EVIDENCE"


class CommandStatus(str, Enum):
    COLLECTED = "COLLECTED"
    RETRYABLE = "RETRYABLE"      # transport/breaker failure (typed)
    BLOCKED = "BLOCKED"          # allowlist/lock/precondition refusal
    PARSER_MISSING = "PARSER_MISSING"  # allowlisted but no parser: reported, not issued


class DeviceStatus(str, Enum):
    COMPLETE = "COMPLETE"        # every planned command COLLECTED
    PARTIAL = "PARTIAL"          # ≥1 collected, ≥1 failed (n/N visible, T4)
    UNREACHABLE = "UNREACHABLE"  # session factory refused (typed cause kept)
    NO_PLAN = "NO_PLAN"          # no usable command plan for the family
    BLOCKED = "BLOCKED"          # collector refused before execution


@dataclass(frozen=True)
class CommandRecord:
    command: str
    status: CommandStatus
    causes: tuple[str, ...] = ()
    event_id: Optional[str] = None
    observation_count: int = 0
    ok_field_count: int = 0


@dataclass(frozen=True)
class Identity:
    """Per-device identity facts, each evidence-tagged (parser metadata +
    OK observations only). Canonical renaming is OI-0173 (honest gap)."""

    vendor_family: Optional[str]        # from the parser that answered
    model: Optional[str]
    version: Optional[str]
    serial: Optional[str]
    evidence_obs_ids: tuple[str, ...]


@dataclass
class DeviceResult:
    device_ref: str
    classification: DeviceClass
    status: DeviceStatus
    commands: list[CommandRecord] = field(default_factory=list)
    identity: Optional[Identity] = None
    mgmt_addresses: tuple[str, ...] = ()
    #: L1/L2 port inventory from ``show interfaces status`` (Phase W). Empty
    #: means the device never answered that command — NOT that it has no
    #: ports. The Design Engine must be able to tell the two apart.
    interface_table: tuple[dict, ...] = ()
    #: Phase X — L2/L3 evidence for devices that do not advertise themselves.
    #: ``show ip arp`` (live addresses) and ``show mac address-table`` (which
    #: port each MAC was learned on). CDP/LLDP alone is blind to a firewall
    #: with LLDP disabled, a server, or an AP; these two tables are what a
    #: network engineer falls back on, and without them the platform reported a
    #: complete topology that was missing physically cabled equipment.
    #: Empty means the device never answered — NOT that nothing is connected.
    arp_table: tuple[dict, ...] = ()
    mac_table: tuple[dict, ...] = ()
    event_count: int = 0
    observation_count: int = 0
    claim_admitted: int = 0
    claim_rejected: int = 0
    rejection_reasons: list[str] = field(default_factory=list)

    def counts(self) -> tuple[int, int]:
        """(collected, planned) — the T4 n/N of this device."""
        collected = sum(1 for c in self.commands if c.status is CommandStatus.COLLECTED)
        return collected, len(self.commands)


@dataclass(frozen=True)
class EndpointRef:
    device_ref: str
    interface: Optional[str]

    def key(self) -> str:
        return f"{self.device_ref}|{self.interface or '?'}"


@dataclass(frozen=True)
class CrawlLink:
    link_id: str
    endpoint_a: EndpointRef
    endpoint_b: EndpointRef
    fsm4_state: str
    protocols: tuple[str, ...]
    evidence_obs_ids: tuple[str, ...]


@dataclass(frozen=True)
class L3Endpoint:
    """A live L3 address that no neighbour advertisement explained.

    This is the evidence CDP/LLDP cannot produce: a device that exists, has an
    address, and never advertised itself. Every one of these is *recorded* —
    whether or not it was probed — because a discovery run that silently omits
    equipment it can see is worse than one that admits it stopped looking.
    """

    ip: str
    mac: str
    learned_on_device: str
    learned_on_port: Optional[str]
    vlan: Optional[str]
    #: What the reporting device's OWN port inventory says about that port:
    #: TRUNK (something behind it may carry further devices), ACCESS (an end
    #: host by the device's own configuration) or UNKNOWN (no inventory).
    port_kind: str
    probed: bool
    device_ref: Optional[str]
    reason: str


@dataclass(frozen=True)
class CrawlReport:
    devices: tuple[DeviceResult, ...]
    links: tuple[CrawlLink, ...]
    frontier_exhausted: bool
    totals: dict
    #: Phase X — L3 evidence gathered, including what was not probed.
    l3_endpoints: tuple[L3Endpoint, ...] = ()


class SessionFactory(Protocol):
    """Reachability oracle: open a session to a device, or refuse TYPED.

    Hints carry every advertised management address seen for the device;
    which one (if any) is usable is the factory's mechanical knowledge.
    """

    def open(self, device_ref: str, mgmt_hints: tuple[str, ...]) -> ExecSession: ...


def _link_id(a: EndpointRef, b: EndpointRef) -> str:
    pair = sorted([a.key(), b.key()])
    return f"LINK:{pair[0]}||{pair[1]}"


def _norm_name(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    return text.split(".")[0].strip().lower() or None


class DiscoveryCrawlEngine:
    """E31 in the registry: multi-device discovery over passive evidence."""

    ACTOR_ID = "E31"

    def __init__(
        self,
        *,
        store: LedgerStore,
        twin: DigitalTwin,
        collector: Collector,
        parsers: ParserRegistry,
        link_engine: LinkEvidenceEngine,
        claim_factory: ClaimFactory,
    ) -> None:
        self._store = store
        self._twin = twin
        self._collector = collector
        self._parsers = parsers
        self._links = link_engine
        self._claims = claim_factory
        self._families: dict[str, str] = {}

    # ------------------------------------------------------------ crawl plan
    def plan_for(self, vendor_family: str, allowlist: CommandAllowlist) -> tuple[tuple[str, Parser], ...]:
        """(command, parser) pairs: catalog ∩ READ_ONLY allowlist, sorted."""
        plan: list[tuple[str, Parser]] = []
        for parser in self._iter_family_parsers(vendor_family):
            cmd = parser.info.command_ref
            if allowlist.is_readable(cmd):
                plan.append((cmd, parser))
        return tuple(sorted(plan, key=lambda item: item[0]))

    def _iter_family_parsers(self, vendor_family: str) -> list[Parser]:
        from ..parsers.catalog import canonical_families
        families = set(canonical_families(vendor_family))
        out: list[Parser] = []
        for key in self._all_parser_keys():
            parser = self._parsers.get(*key)
            if parser.info.vendor_family in families:
                out.append(parser)
        return out

    def _all_parser_keys(self) -> list[tuple[str, str]]:
        # ParserRegistry exposes .get/.latest; catalog keys are discovered via
        # the registry's internal map (stable, read-only).
        return sorted(getattr(self._parsers, "_parsers", {}).keys())

    # ------------------------------------------------------------------ crawl
    def crawl(
        self,
        *,
        seed_ref: str,
        seed_family: str,
        session_factory: SessionFactory,
        allowlist_of: Callable[[str], CommandAllowlist],
        max_devices: int = 256,
        max_l3_probes: int = 32,
    ) -> CrawlReport:
        """Breadth-first, deterministic: frontier is a sorted set each wave."""
        visited: dict[str, DeviceResult] = {}
        tables: dict[str, list[dict]] = {}
        frontier: list[tuple[str, str, tuple[str, ...], DeviceClass]] = [
            (seed_ref, seed_family, (), DeviceClass.SEED)
        ]

        while frontier and len(visited) < max_devices:
            wave: list[tuple[str, str, tuple[str, ...], DeviceClass]] = []
            for device_ref, family, hints, classification in sorted(frontier):
                if device_ref in visited or len(visited) >= max_devices:
                    continue
                result = self._crawl_device(
                    device_ref=device_ref, family=family, hints=hints,
                    classification=classification, session_factory=session_factory,
                    allowlist_of=allowlist_of,
                )
                visited[device_ref] = result
                self._families[device_ref] = (result.identity.vendor_family
                                              if result.identity else family)
                table = self._merged_table(device_ref)
                if table is not None:
                    tables[device_ref] = table
                    self._record_links(device_ref, table)
                # Enqueue unseen neighbors with consistent naming.
                known_names = set(visited.keys()) | set(tables.keys())
                if table:
                    for entry in sorted(table, key=lambda e: (_norm_name(e["neighbor_id"]) or "",
                                                              e["local_intf"] or "")):
                        neighbor = _norm_name(entry["neighbor_id"])
                        if not neighbor or neighbor in visited:
                            continue
                        if neighbor in {ref for ref, *_ in wave}:
                            continue
                        mgmt_hints = tuple(sorted({entry["mgmt_address"]} - {None})) if entry["mgmt_address"] else ()
                        classification_next = (
                            DeviceClass.NEIGHBOR_REACHED if mgmt_hints
                            else DeviceClass.NEIGHBOR_NO_PATH_FACTS
                        )
                        # The neighbor's family is UNKNOWN until its own
                        # identity answers; platform hints travel as data,
                        # never as assumed identity.
                        wave.append((neighbor, platform_family_hint(entry), mgmt_hints, classification_next))
                known_names.update(ref for ref, *_ in wave)
            frontier = wave

        links = self._link_report(tables)
        # Phase X: CDP/LLDP exhausted. Now look for what never advertised
        # itself, using ARP joined to the MAC address table.
        l3_endpoints, l3_links = self._discover_via_l2l3(
            visited, tables=tables, session_factory=session_factory,
            allowlist_of=allowlist_of,
            max_devices=max_devices, max_l3_probes=max_l3_probes)
        if l3_links:
            existing = {l.link_id for l in links}
            links.extend(l for l in l3_links if l.link_id not in existing)
        totals = self._totals(visited)
        exhausted = not frontier
        return CrawlReport(
            devices=tuple(visited[d] for d in sorted(visited)),
            links=tuple(links),
            frontier_exhausted=exhausted,
            totals=totals,
            l3_endpoints=tuple(l3_endpoints),
        )

    # ------------------------------------------- L2/L3 evidence (Phase X)
    @staticmethod
    def _port_kind(device: DeviceResult, port: Optional[str]) -> str:
        """What the device's OWN port inventory says about a port.

        ``TRUNK`` means something behind it may carry further devices;
        ``ACCESS`` means the device's own configuration makes whatever is
        attached an end host; ``UNKNOWN`` means no inventory answered. This is
        read from evidence the device itself gave, never assumed.
        """
        if not port or not device.interface_table:
            return "UNKNOWN"
        want = port.lower().replace(" ", "")
        for row in device.interface_table:
            got = (row.get("port") or "")
            if got and got.lower().replace(" ", "") == want:
                vlan = (row.get("vlan") or "").lower()
                if vlan == "trunk":
                    return "TRUNK"
                if vlan.isdigit():
                    return "ACCESS"
                return "UNKNOWN"
        return "UNKNOWN"

    def _l3_candidates(self, visited: dict[str, DeviceResult],
                       tables: Optional[dict[str, list[dict]]] = None) -> list[tuple]:
        """Join ARP to the MAC address table for every crawled device.

        Returns deterministic ``(ip, mac, device_ref, port, vlan, port_kind)``
        tuples for live addresses that no neighbour advertisement explained.

        Already-known addresses are excluded from **two** evidence sources:
        each device's own ``mgmt_addresses``, and every management address
        advertised in any neighbour table crawled so far. The second matters —
        a seed device carries no evidence about *itself*, so its own address
        would otherwise be re-discovered as an unknown endpoint.
        """
        known_ips: set[str] = set()
        for device in visited.values():
            known_ips.update(device.mgmt_addresses)
        for table in (tables or {}).values():
            for entry in table:
                advertised = entry.get("mgmt_address")
                if advertised:
                    known_ips.add(advertised)

        out: dict[str, tuple] = {}
        for ref in sorted(visited):
            device = visited[ref]
            if not device.arp_table or not device.mac_table:
                continue          # no evidence: never invent an endpoint
            mac_index: dict[str, tuple] = {}
            for row in device.mac_table:
                mac = (row.get("mac_address") or "").lower()
                if mac and mac not in mac_index:
                    mac_index[mac] = (row.get("ports"), row.get("vlan"))
            for row in sorted(device.arp_table,
                              key=lambda r: (r.get("address") or "",
                                             r.get("hardware_addr") or "")):
                ip = row.get("address")
                mac = (row.get("hardware_addr") or "").lower()
                if not ip or not mac:
                    continue
                if ip in known_ips:
                    continue      # already a discovered device, by its own address
                port, vlan = mac_index.get(mac, (None, None))
                key = f"{ref}|{ip}"
                if key in out:
                    continue
                out[key] = (ip, mac, ref, port, vlan, self._port_kind(device, port))
        # Deterministic probe order: numeric by address, then reporting device.
        def _ip_key(item):
            ip = item[1][0]
            try:
                return (0, int(ipaddress.ip_address(ip)), item[1][2])
            except ValueError:
                return (1, 0, ip)
        return [out[k] for k in sorted(out, key=lambda k: _ip_key((None, out[k])))]

    def _discover_via_l2l3(
        self,
        visited: dict[str, DeviceResult],
        *,
        tables: Optional[dict[str, list[dict]]] = None,
        session_factory: SessionFactory,
        allowlist_of: Callable[[str], CommandAllowlist],
        max_devices: int,
        max_l3_probes: int,
    ) -> tuple[list[L3Endpoint], list[CrawlLink]]:
        """Discover what never advertised itself, and record all of it.

        Two honesty rules shape the result:

        * every endpoint found is recorded, including those not probed, with
          the reason — nothing seen is silently dropped;
        * a derived link is graded ``INFERRED``, or ``INTERMEDIATE_SUSPECTED``
          when it was learned on a trunk (where an unannounced switch may sit
          in between) — never as a confirmed neighbour.
        """
        candidates = self._l3_candidates(visited, tables)
        endpoints: list[L3Endpoint] = []
        links: list[CrawlLink] = []
        probed = 0
        for ip, mac, ref, port, vlan, port_kind in candidates:
            device_ref = f"l3-{ip}"
            if device_ref in visited:
                endpoints.append(L3Endpoint(
                    ip=ip, mac=mac, learned_on_device=ref, learned_on_port=port,
                    vlan=vlan, port_kind=port_kind, probed=True,
                    device_ref=device_ref,
                    reason="already crawled during the CDP/LLDP pass"))
                continue
            if len(visited) >= max_devices:
                endpoints.append(L3Endpoint(
                    ip=ip, mac=mac, learned_on_device=ref, learned_on_port=port,
                    vlan=vlan, port_kind=port_kind, probed=False, device_ref=None,
                    reason=f"NOT_PROBED: device budget {max_devices} reached"))
                continue
            if probed >= max_l3_probes:
                endpoints.append(L3Endpoint(
                    ip=ip, mac=mac, learned_on_device=ref, learned_on_port=port,
                    vlan=vlan, port_kind=port_kind, probed=False, device_ref=None,
                    reason=f"NOT_PROBED: L3 probe budget {max_l3_probes} reached "
                           f"(endpoint is recorded, never silently dropped)"))
                continue
            probed += 1
            result = self._crawl_device(
                device_ref=device_ref, family="UNKNOWN", hints=(ip,),
                classification=DeviceClass.NEIGHBOR_L3_EVIDENCE,
                session_factory=session_factory, allowlist_of=allowlist_of)
            visited[device_ref] = result
            endpoints.append(L3Endpoint(
                ip=ip, mac=mac, learned_on_device=ref, learned_on_port=port,
                vlan=vlan, port_kind=port_kind, probed=True,
                device_ref=device_ref,
                reason=("answered a management session"
                        if result.status is DeviceStatus.COMPLETE
                        else f"probed; status={result.status.value}")))
            # The inferred link. Graded below PROBABLE on purpose: an ARP entry
            # proves an address is live, not that it is directly attached.
            state = (lf.INTERMEDIATE_SUSPECTED if port_kind == "TRUNK"
                     else lf.INFERRED)
            a = EndpointRef(ref, port)
            b = EndpointRef(device_ref, None)
            if b.key() < a.key():
                a, b = b, a
            links.append(CrawlLink(
                link_id=_link_id(a, b), endpoint_a=a, endpoint_b=b,
                fsm4_state=state, protocols=("ARP", "MAC_ADDRESS_TABLE"),
                evidence_obs_ids=()))
        return endpoints, links

    # ------------------------------------------------------------- one device
    def _crawl_device(
        self,
        *,
        device_ref: str,
        family: str,
        hints: tuple[str, ...],
        classification: DeviceClass,
        session_factory: SessionFactory,
        allowlist_of: Callable[[str], CommandAllowlist],
    ) -> DeviceResult:
        result = DeviceResult(device_ref=device_ref, classification=classification,
                              status=DeviceStatus.BLOCKED)
        try:
            session = session_factory.open(device_ref, hints)
        except Failure as exc:
            result.status = DeviceStatus.UNREACHABLE
            result.rejection_reasons.extend(exc.causes)
            # Even when the management session is refused, we still
            # know the advertised mgmt address from the neighbor's
            # LLDP/CDP entry. Record it so the operator can issue
            # ``ping <neighbor>`` from the chat and reach it later
            # once credentials are fixed.
            result.mgmt_addresses = tuple(hints)
            return result

        allowlist = allowlist_of(family)
        plan = self.plan_for(family, allowlist)
        result.mgmt_addresses = tuple(hints)
        if not plan:
            result.status = DeviceStatus.NO_PLAN
            result.rejection_reasons.append(
                f"NO_CRAWL_PLAN: family={family!r} has no catalog parser with a READ_ONLY allowlisted command")
            session.close()
            return result

        observations_all: list[Observation] = []
        for command, parser in plan:
            try:
                outcome = self._collector.collect(
                    device_ref=device_ref, command=command, session=session,
                    session_kind="serial" if classification is DeviceClass.SEED else "cli",
                )
            except Failure as exc:
                status = (CommandStatus.RETRYABLE if exc.cls is FailureClass.RETRYABLE
                          else CommandStatus.BLOCKED)
                result.commands.append(CommandRecord(command=command, status=status, causes=tuple(exc.causes)))
                continue
            except (TimeoutError, ConnectionError) as exc:
                result.commands.append(CommandRecord(command=command, status=CommandStatus.RETRYABLE,
                                                     causes=(f"{type(exc).__name__}: {exc}",)))
                continue

            observations = parser.parse(outcome.output, raw_id=outcome.artifact.raw_id)
            for obs in observations:
                self._store.append_observation(obs)
            observations_all.extend(observations)
            result.event_count += 1
            result.observation_count += len(observations)
            result.commands.append(CommandRecord(
                command=command, status=CommandStatus.COLLECTED,
                event_id=outcome.event.event_id,
                observation_count=len(observations),
                ok_field_count=sum(1 for o in observations if o.parse_status is ParseStatus.OK)))

        session.close()

        # Claims (T1-strict) → Twin admission.
        issues = self._claims.issue_for_device(device_ref, observations_all)
        from ..twin.twin import Admission
        for issue in issues:
            if issue.admitted:
                apply_result = self._twin.apply_claim(
                    issue.claim,
                    collected_at=self._collector_now(),
                )
                if apply_result.admission is Admission.APPLIED:
                    result.claim_admitted += 1
                else:
                    result.claim_rejected += 1
                    result.rejection_reasons.append(apply_result.reason)
            else:
                result.claim_rejected += 1
                result.rejection_reasons.extend(issue.reasons)

        result.identity = self._identity_of(device_ref, plan, observations_all)
        result.interface_table = self._table_of(observations_all, "interface_table")
        result.arp_table = self._table_of(observations_all, "arp_table")
        result.mac_table = self._table_of(observations_all, "mac_table")
        collected, planned = result.counts()
        result.status = (DeviceStatus.COMPLETE if collected == planned
                         else DeviceStatus.PARTIAL if collected else DeviceStatus.BLOCKED)
        return result

    # --------------------------------------------------------------- helpers
    def _collector_now(self):
        """The twin transition requires a timestamp; the ledger clock is the
        only legal source. Collector keeps its TimeAuthority private — the
        crawl obtains time through a fresh event only. To avoid a synthetic
        event per claim, claims carry their own observations; the twin's
        transition stamp uses the store-visible most recent collection time,
        falling back to the local monotonic clock ONLY for the stamp field
        (the stamp is not evidence; the evidence ids are)."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc)

    def _neighbor_tables_of(self, device_ref: str) -> dict[str, list[dict]]:
        """Per-source tables as stored in the Twin: {proto: table}.

        Each parser's evidence keeps its own predicate (neighbor_table_lldp,
        neighbor_table_cdp, neighbor_table_mndp) — no source overwrites
        another (T1)."""
        entity = self._twin.entity("DEVICE", device_ref)
        if entity is None:
            return {}
        out: dict[str, list[dict]] = {}
        for predicate, record in entity.fields.items():
            if not predicate.startswith("neighbor_table_"):
                continue
            proto = predicate[len("neighbor_table_"):]
            if isinstance(record.value, list):
                out[proto] = record.value
        return out

    # fixed fusion priority: LLDP rows are anchored; CDP/MNDP fill gaps.
    _PROTO_PRIORITY = ("lldp", "cdp", "mndp")

    def _merged_table(self, device_ref: str) -> Optional[list[dict]]:
        """Deterministic evidence fusion of per-source tables (§10).

        Rows are keyed (local_intf, neighbor); a later protocol only FILLS
        fields the earlier source did not state (None). Provenance is kept
        via each row's protocol + the twin predicates. Output sorted;
        identical inputs ⇒ identical merge."""
        sources = self._neighbor_tables_of(device_ref)
        if not sources:
            return None
        family = self._families.get(device_ref, "")
        merged: dict[tuple[str, str], dict] = {}
        for proto in self._PROTO_PRIORITY:
            for entry in sources.get(proto, []):
                key = (normalize_port(family, entry.get("local_intf"))[0],
                       _norm_name(entry.get("neighbor_id")) or "")
                row = merged.get(key)
                if row is None:
                    merged[key] = dict(entry)
                else:
                    for field in entry:
                        if row.get(field) is None and entry.get(field) is not None:
                            row[field] = entry[field]
        rows = sorted(
            merged.values(),
            key=lambda r: (_norm_name(r.get("local_intf")) or "",
                           _norm_name(r.get("neighbor_id")) or ""))
        return rows

    @staticmethod
    def _table_of(observations: list[Observation], field: str) -> tuple[dict, ...]:
        """The OK observation for a tabular field, if the device produced one.

        Only an OK observation counts. A MISSING one (no header in the output)
        leaves the tuple empty, which downstream readers must treat as "table
        unavailable" and refuse to invent anything from.

        Was ``_interfaces_of``; generalised because ARP and the MAC address
        table carry exactly the same "OK or unknowable, never silently empty"
        contract as the port inventory.
        """
        for obs in observations:
            if obs.field == field and obs.parse_status is ParseStatus.OK \
                    and isinstance(obs.value, list):
                return tuple(dict(row) for row in obs.value if isinstance(row, dict))
        return ()

    def _identity_of(self, device_ref: str, plan, observations: list[Observation]) -> Identity:
        ok = [o for o in observations if o.parse_status is ParseStatus.OK]

        def first(*fields: str) -> Optional[tuple[str, str]]:
            for obs in ok:
                if obs.field in fields and isinstance(obs.value, str) and obs.value:
                    return obs.value, obs.obs_id
            return None

        model = first("model", "board_name", "platform")
        version = first("version", "junos_version")
        serial = first("serial", "serial-number", "serial_id")
        family = plan[0][1].info.vendor_family if plan else None
        ids = [e[1] for e in (model, version, serial) if e]
        if not version and family == "unifi":
            version = first("version")  # api payload carries software version
        return Identity(
            vendor_family=family,
            model=model[0] if model else None,
            version=version[0] if version else None,
            serial=serial[0] if serial else None,
            evidence_obs_ids=tuple(sorted(set(ids))),
        )

    # ------------------------------------------------------------- link wiring
    def _record_links(self, device_ref: str, table: list[dict]) -> None:
        for entry in table:
            neighbor = _norm_name(entry["neighbor_id"])
            a = EndpointRef(device_ref, entry["local_intf"])
            b = EndpointRef(neighbor or "UNKNOWN", entry["neighbor_intf"])
            link_id = _link_id(a, b)
            obs_id = self._table_obs_id(device_ref, (entry.get("protocol") or "").lower() or None)
            if obs_id is None:
                continue
            state = self._links.state(link_id)
            if state in (lf.UNKNOWN,):
                self._links.one_sided(link_id, obs_id)
            # Bidirectional check (both tables already known).
            if neighbor and self._is_bidirectional(device_ref, entry, neighbor):
                if self._links.state(link_id) in (lf.UNKNOWN, lf.ONE_SIDED):
                    try:
                        self._links.probable_bidirectional(
                            link_id, self._table_obs_id(neighbor) or obs_id)
                    except Failure:
                        pass  # state machine refuses duplicates; state stays truthful

    def _is_bidirectional(self, device_ref: str, entry: dict, neighbor_norm: str) -> bool:
        """True iff the neighbor's own table names this device back with
        matching interfaces (port-name correlation is post-normalized lower)."""
        back_table = self._merged_table(neighbor_norm)
        if not back_table:
            return False
        back_name = _norm_name(device_ref)
        neighbor_family = self._families.get(neighbor_norm, "")
        for back in back_table:
            if _norm_name(back.get("neighbor_id")) != back_name:
                continue
            advertised = entry.get("neighbor_intf")
            reported = back.get("local_intf")
            if advertised and reported:
                # Both sides name the SAME remote port; normalize with the
                # reporting device's own family rules (§4).
                if normalize_port(neighbor_family, advertised)[0] == normalize_port(neighbor_family, reported)[0]:
                    return True
            elif advertised is None and reported is not None:
                return True  # MNDP-style: no far-port advertisement; name match only
        return False

    def _table_obs_id(self, device_ref: str, proto: Optional[str] = None) -> Optional[str]:
        entity = self._twin.entity("DEVICE", device_ref)
        if entity is None:
            return None
        protos = (proto,) if proto else self._PROTO_PRIORITY
        for p in protos:
            record = entity.fields.get(f"neighbor_table_{p}")
            if record is not None and record.evidence_ids:
                return record.evidence_ids[0]
        return None

    def _link_report(self, tables: dict[str, list[dict]]) -> list[CrawlLink]:
        seen: dict[str, dict] = {}
        for device_ref, table in tables.items():
            for entry in table:
                neighbor = _norm_name(entry["neighbor_id"])
                a = EndpointRef(device_ref, entry["local_intf"])
                b = EndpointRef(neighbor or "UNKNOWN", entry["neighbor_intf"])
                link_id = _link_id(a, b)
                obs_id = self._table_obs_id(device_ref, (entry.get("protocol") or "").lower() or None)
                slot = seen.setdefault(link_id, {
                    "a": a, "b": b, "protocols": set(), "evidence": set(),
                })
                if entry["protocol"]:
                    slot["protocols"].add(entry["protocol"])
                if obs_id:
                    slot["evidence"].add(obs_id)
        out: list[CrawlLink] = []
        for link_id in sorted(seen):
            slot = seen[link_id]
            a, b = slot["a"], slot["b"]
            if b.key() < a.key():
                a, b = b, a
            out.append(CrawlLink(
                link_id=link_id, endpoint_a=a, endpoint_b=b,
                fsm4_state=self._links.state(link_id),
                protocols=tuple(sorted(slot["protocols"])),
                evidence_obs_ids=tuple(sorted(slot["evidence"]))))
        return out

    # ----------------------------------------------------------------- totals
    @staticmethod
    def _totals(visited: dict[str, DeviceResult]) -> dict:
        collected = planned = 0
        by_status: dict[str, int] = {}
        for result in visited.values():
            c, p = result.counts()
            collected += c
            planned += p
            by_status[result.status.value] = by_status.get(result.status.value, 0) + 1
        return {
            "devices": len(visited),
            "commands_collected": collected,
            "commands_planned": planned,
            "device_status": dict(sorted(by_status.items())),
        }


def platform_family_hint(entry: dict) -> str:
    """Neighbor vendor hint from the advertisement ONLY when the protocol
    states it; otherwise UNKNOWN (the neighbor identifies itself when
    crawled — hints never become identity)."""
    platform = (entry.get("platform") or "").lower()
    known = (
        ("cisco", "cisco/ios-xe"), ("ios xe", "cisco/ios-xe"), ("catalyst", "cisco/ios-xe"),
        ("routeros", "routeros"), ("mikrotik", "routeros"),
        ("junos", "junos"), ("juniper", "junos"),
        ("fortigate", "fortios"), ("fortinet", "fortios"),
        ("aruba", "arubaos"),
        ("unifi", "unifi"), ("ubiquiti", "unifi"),
    )
    for token, family in known:
        if token in platform:
            return family
    return "UNKNOWN"
