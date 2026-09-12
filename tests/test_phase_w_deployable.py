"""Phase W regression suite — a deployed network that actually works.

Phase V made the platform *change* the device safely. Phase W makes the
result *be a working network that stays working*. Each test locks a defect
that was reproduced first:

* the port inventory was collected by nobody, so `harvest_interfaces` could
  only ever name neighbour ports — which are exactly the ports reserved for
  infrastructure. Access-port assignment was structurally guaranteed to be 0;
* ports were ordered lexicographically, so `gi1/0/10` came before `gi1/0/2`
  and the wrong VLAN landed on the wrong socket;
* every zone got exactly ONE access port regardless of planned size;
* the applied configuration was never persisted — Cisco lost it on reload and
  Junos' `commit confirmed 2` reverted it after two minutes;
* no DHCP pool was ever emitted, so clients got an address for nothing;
* `dns-server` was rendered comma-separated, which IOS rejects.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netops_autopilot.access.allowlist import CommandAllowlist
from netops_autopilot.autopilot.answer_script import answer_script
from netops_autopilot.access.executor import ChangeOutcome, ConfigExecutor
from netops_autopilot.engines.design_engine import (
    DHCP_RESERVED_HOSTS,
    _dhcp_exclusion,
    port_sort_key,
)
from netops_autopilot.parsers.interface_inventory import CiscoIosXeInterfacesStatusParser
from netops_autopilot.specs_data import specs_data_dir

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "golden"

# Declining the access retry keeps access-sw1 excluded, so these tests exercise
# the honest-gap path. ``answer_script`` is the single source of truth for the
# sequence — see its module docstring for why hand-written lists were the bug.
ANSWERS = answer_script(access_retry="n", intent="branch office with VoIP")


def cisco_allowlist() -> CommandAllowlist:
    return CommandAllowlist.load_vendor(specs_data_dir("allowlists"), "cisco/ios-xe")


class CountingDevice:
    """Records exactly what reached the device, and can fail a chosen line."""

    def __init__(self, fail_on=(), persist_fails: bool = False,
                 silently_drop=(), stuck=()):
        self.sent: list[str] = []
        self.state: set[str] = set()
        self._fail_on = set(fail_on)
        self._persist_fails = persist_fails
        # ``silently_drop``: the device accepts the line and returns success,
        # but never applies it. This is the real-world failure that a hash
        # comparison cannot see — the config changed (other lines), just not
        # the way we asked.
        self._silently_drop = set(silently_drop)
        # ``stuck``: a line that refuses to go away under ``no …``.
        self._stuck = set(stuck)

    def execute(self, command: str, timeout_s=None) -> bytes:
        self.sent.append(command)
        c = command.strip()
        if c in self._fail_on:
            raise RuntimeError(f"DEVICE_REJECTED: {c}")
        if c == "show running-config":
            body = "\n".join(sorted(self.state))
            return (f"Building configuration...\n\nCurrent configuration : {len(body)} "
                    f"bytes\n!\n{body}\nend\n").encode()
        if c == "write memory":
            if self._persist_fails:
                raise RuntimeError("FLASH_WRITE_ERROR")
            return b"[OK]"
        if c in ("enable", "configure terminal", "end", "exit"):
            return b""
        if c.startswith("no "):
            target = c[3:].strip()
            if target not in self._stuck:
                self.state.discard(target)
        elif c not in self._silently_drop and not c.startswith("default "):
            self.state.add(c)
        return b"% ok"

    def close(self) -> None:
        pass


# ==================================================== 1. interface inventory
def test_golden_show_interfaces_status():
    parser = CiscoIosXeInterfacesStatusParser()
    raw = (FIXTURES / "cisco_iosxe" / "show_interfaces_status.txt").read_bytes()
    expected = json.loads(
        (FIXTURES / "cisco_iosxe" / "show_interfaces_status.expected.json").read_text())
    assert parser.info.parser_id == expected["parser_id"]
    got = {o.field: (o.parse_status.value, o.value) for o in parser.parse(raw, "raw-w")}
    for exp in expected["expected"]:
        status, value = got[exp["field"]]
        assert status == exp["parse_status"], exp["field"]
        assert value == exp["value"], exp["field"]


def test_inventory_type_column_with_a_space_is_not_shattered():
    """`10GBase-SR SFP+` must survive; `str.split()` would cut it in half."""
    parser = CiscoIosXeInterfacesStatusParser()
    raw = (b"Port      Status         Vlan       Duplex  Speed Type\n"
           b"Te1/1/1   connected      routed     a-full  a-10G  10GBase-SR SFP+\n")
    table = [o.value for o in parser.parse(raw, "r") if o.field == "interface_table"][0]
    assert table[0]["type"] == "10GBase-SR SFP+"
    assert table[0]["port"] == "Te1/1/1"


def test_no_header_is_missing_not_an_empty_table():
    """An unreadable table and a switch with no ports are different facts."""
    parser = CiscoIosXeInterfacesStatusParser()
    statuses = {o.field: o.parse_status.value
                for o in parser.parse(b"% Invalid input detected\n", "r")}
    assert statuses == {"interface_table": "MISSING", "interface_count": "MISSING"}

    empty = {o.field: o.value for o in parser.parse(
        b"Port      Status         Vlan       Duplex  Speed Type\n", "r")
        if o.field == "interface_table"}
    assert empty["interface_table"] == []


# ============================================ 2. access ports are assignable
def _crawl(devices):
    from netops_autopilot.engines.discovery_crawl import (
        CrawlLink, CrawlReport, DeviceClass, DeviceResult, DeviceStatus, Identity)
    return CrawlReport


def test_harvest_uses_the_inventory_not_only_neighbour_links():
    """The structural defect: neighbour-only harvesting can never yield a
    user port, because every port a neighbour table names is infrastructure."""
    from dataclasses import dataclass, field as dc_field

    @dataclass
    class _Ep:
        device_ref: str
        interface: str

    @dataclass
    class _Link:
        endpoint_a: _Ep
        endpoint_b: _Ep

    @dataclass
    class _Id:
        vendor_family: str

    @dataclass
    class _Dev:
        device_ref: str
        identity: _Id
        interface_table: tuple = ()

    @dataclass
    class _Report:
        devices: list = dc_field(default_factory=list)
        links: list = dc_field(default_factory=list)

    from netops_autopilot.engines.design_engine import harvest_interfaces

    # only neighbour evidence: both ports are infrastructure
    link_only = _Report(
        devices=[_Dev("sw1", _Id("cisco/ios-xe"))],
        links=[_Link(_Ep("sw1", "Gi1/0/1"), _Ep("core", "Gi0/1"))])
    assert harvest_interfaces(link_only)["sw1"] == ("gi1/0/1",)

    # with the inventory: real user ports appear
    with_inventory = _Report(
        devices=[_Dev("sw1", _Id("cisco/ios-xe"), (
            {"port": "Gi1/0/1"}, {"port": "Gi1/0/2"},
            {"port": "Gi1/0/3"}, {"port": "Gi1/0/10"},
        ))],
        links=[_Link(_Ep("sw1", "Gi1/0/1"), _Ep("core", "Gi0/1"))])
    assert harvest_interfaces(with_inventory)["sw1"] == (
        "gi1/0/1", "gi1/0/2", "gi1/0/3", "gi1/0/10")


def test_port_ordering_is_natural_not_lexicographic():
    ports = ["gi1/0/1", "gi1/0/10", "gi1/0/11", "gi1/0/2", "gi1/0/3"]
    assert sorted(ports) == ["gi1/0/1", "gi1/0/10", "gi1/0/11", "gi1/0/2", "gi1/0/3"]
    assert sorted(ports, key=port_sort_key) == [
        "gi1/0/1", "gi1/0/2", "gi1/0/3", "gi1/0/10", "gi1/0/11"]


def test_the_demo_design_assigns_real_access_ports():
    """End-to-end: the shipped demo used to report `0 access ports`."""
    from netops_autopilot.autopilot.orchestrator import AutopilotEngine
    from netops_autopilot.cli import ScriptedIO
    from tests.support.simfabric import SimFabricFactory, make_ledger_stack

    answers = list(ANSWERS)
    store, key_id, _c, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(store=store, key_id=key_id, io=ScriptedIO(answers),
                             time_authority=ta)
    report = engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                        mgmt_session_factory=fabric.open, port="SIM0", execute=False)
    assert len(report.design.access) > 0, "no end-user access port was assigned"
    # the largest zone must get the largest share
    counts: dict[str, int] = {}
    for a in report.design.access:
        counts[a.zone] = counts.get(a.zone, 0) + 1
    assert counts.get("users", 0) > counts.get("voice", 0)


# ====================================================== 3. DHCP is emitted
def test_dhcp_exclusion_always_covers_the_gateway():
    first, last = _dhcp_exclusion("10.0.0.0/25", "10.0.0.1")
    assert first == "10.0.0.1"
    assert last == f"10.0.0.{DHCP_RESERVED_HOSTS}"

    # a gateway further up the subnet must still be inside the excluded block
    first, last = _dhcp_exclusion("10.0.0.0/25", "10.0.0.50")
    assert last == "10.0.0.50"


def test_dhcp_exclusion_refuses_to_empty_the_pool():
    # a /30 has 2 usable addresses; reserving 10 must not swallow them all
    first, last = _dhcp_exclusion("10.0.0.0/30", "10.0.0.1")
    assert first == "10.0.0.1" and last == "10.0.0.2"


def test_dhcp_exclusion_is_none_for_ipv6():
    """IPv6 uses SLAAC/RA; emitting an IPv4 pool would be an invention."""
    assert _dhcp_exclusion("2001:db8::/64", "2001:db8::1") is None


def test_dns_list_is_rendered_space_separated_as_ios_requires():
    from netops_autopilot.engines.config_renderer import _render_commands
    templates = tuple(json.loads(
        (Path(specs_data_dir("renderers")) / "cisco_iosxe.json").read_text()
    )["features"]["dhcp"]["commands"])
    base = {"pool": "users", "network": "10.0.0.0", "netmask": "255.255.255.0",
            "gateway": "10.0.0.1", "exclude_first": "10.0.0.1", "exclude_last": "10.0.0.10"}
    with_dns = _render_commands(templates, {**base, "dns": "1.1.1.1 9.9.9.9"})
    assert " dns-server 1.1.1.1 9.9.9.9" in with_dns
    assert not any("," in line for line in with_dns), "IOS rejects a comma-separated list"

    # an unbound OPTIONAL line is skipped, not fatal to the block
    without = _render_commands(templates, base)
    assert not any("dns-server" in line for line in without)
    assert any("ip dhcp pool users" == line for line in without)


def test_optional_marker_preserves_cli_indentation():
    from netops_autopilot.engines.config_renderer import _render_commands
    out = _render_commands(("ip dhcp pool {p}", "?  network {n} {m}"),
                           {"p": "users", "n": "10.0.0.0", "m": "255.255.255.0"})
    assert out == ("ip dhcp pool users", " network 10.0.0.0 255.255.255.0")


def test_required_placeholder_still_fails_the_block():
    from netops_autopilot.engines.config_renderer import _render_commands
    with pytest.raises(KeyError):
        _render_commands((" network {network} {netmask}",), {"network": "10.0.0.0"})


# ================================================== 4. config is persisted
def test_persist_runs_after_verification_and_reaches_the_device():
    dev = CountingDevice()
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="w-persist")
    rec = ex.apply("sw1", dev, ["vlan 10", " name users"],
                   wrappers=(["enable", "configure terminal"], ["end"]),
                   persist=["write memory"])
    assert rec.outcome is ChangeOutcome.APPLIED
    assert "write memory" in dev.sent
    # strictly after the config and after the read-back verification
    assert dev.sent.index("write memory") > dev.sent.index("name users")
    assert dev.sent.index("write memory") > max(
        i for i, c in enumerate(dev.sent) if c == "show running-config")
    assert [c.phase for c in rec.commands if c.command == "write memory"] == ["PERSIST"]


def test_persist_never_runs_when_the_change_was_rolled_back():
    """Saving a half-applied configuration would make the damage permanent."""
    dev = CountingDevice(fail_on={"vlan 20"})
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="w-nopersist")
    rec = ex.apply("sw1", dev, ["vlan 10", "vlan 20"],
                   wrappers=(["enable", "configure terminal"], ["end"]),
                   persist=["write memory"])
    assert rec.outcome is ChangeOutcome.ROLLED_BACK
    assert "write memory" not in dev.sent


def test_persist_failure_is_loud_not_silent():
    """Applied and verified but unsaved = breaks at the next reload."""
    dev = CountingDevice(persist_fails=True)
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="w-persistfail")
    rec = ex.apply("sw1", dev, ["vlan 10"],
                   wrappers=(["enable", "configure terminal"], ["end"]),
                   persist=["write memory"])
    assert rec.outcome is ChangeOutcome.PERSIST_FAILED
    assert any("LOST on the next reload" in c for c in rec.failure_causes)


def test_persist_channel_cannot_smuggle_configuration():
    dev = CountingDevice()
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="w-smuggle")
    rec = ex.apply("sw1", dev, ["vlan 10"],
                   wrappers=(["enable", "configure terminal"], ["end"]),
                   persist=["ip http server"])
    assert rec.outcome is ChangeOutcome.PERSIST_FAILED
    assert any("PERSIST_NOT_ALLOWLISTED" in c for c in rec.failure_causes)
    assert "ip http server" not in dev.sent


def test_preview_shows_the_persist_step():
    """The operator must approve the whole operation, saving included."""
    from netops_autopilot.autopilot.orchestrator import AutopilotEngine
    from netops_autopilot.cli import ScriptedIO
    from tests.support.simfabric import SimFabricFactory, make_ledger_stack

    answers = list(ANSWERS)
    store, key_id, _c, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(store=store, key_id=key_id, io=ScriptedIO(answers),
                             time_authority=ta)
    report = engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                        mgmt_session_factory=fabric.open, port="SIM0", execute=False)
    text = "\n".join(r.to_text() for r in report.renders.values())
    assert "write memory" in text
    assert "ip dhcp pool users" in text


# ============================================ 5. every rendered line is legal
def test_every_rendered_line_of_the_demo_design_passes_the_gate():
    from netops_autopilot.autopilot.orchestrator import AutopilotEngine, _all_commands
    from netops_autopilot.cli import ScriptedIO
    from tests.support.simfabric import SimFabricFactory, make_ledger_stack

    answers = list(ANSWERS)
    store, key_id, _c, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(store=store, key_id=key_id, io=ScriptedIO(answers),
                             time_authority=ta)
    report = engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                        mgmt_session_factory=fabric.open, port="SIM0", execute=False)
    al = cisco_allowlist()
    checked = 0
    for rendered in report.renders.values():
        for line in _all_commands(rendered):
            stripped = line.strip()
            if not stripped:
                continue
            assert al.gate(stripped) in ("CONFIG_REVERSIBLE", "CONFIG_HIGH_RISK"), (
                f"rendered line is not allowlisted: {stripped!r}")
            checked += 1
        for line in rendered.persist:
            assert al.gate(line.strip()) == "CONFIG_PERSIST", line
    assert checked > 40, f"only {checked} lines checked — the design shrank"


# ============================================== 6. The design is physically
# self-consistent: what the plan announces, the configuration actually does.
def _run_with_retry(decision: str):
    from netops_autopilot.autopilot.orchestrator import AutopilotEngine
    from netops_autopilot.cli import ScriptedIO
    from tests.support.simfabric import SimFabricFactory, make_ledger_stack

    store, key_id, _c, ta = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    engine = AutopilotEngine(store=store, key_id=key_id,
                             io=ScriptedIO(answer_script(access_retry=decision,
                                                         intent="branch office with VoIP")),
                             time_authority=ta)
    return engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                      mgmt_session_factory=fabric, port="SIM0", execute=False)


def _mode_of(report) -> dict[tuple[str, str], str]:
    """Map (device, port) → the switchport mode the render puts it in."""
    modes: dict[tuple[str, str], str] = {}
    for dev, rendered in report.renders.items():
        current = None
        for line in rendered.to_text().splitlines():
            if line.startswith("interface "):
                current = line.split(None, 1)[1].lower()
            elif current and line.strip().startswith("switchport mode "):
                modes[(dev, current)] = line.strip().split()[-1]
    return modes


@pytest.mark.parametrize("decision", ["n", "y"])
def test_both_ends_of_every_uplink_are_actually_trunked(decision):
    """A link whose far end is left in access mode carries no design VLANs.

    The design engine used to assign ONE uplink per device — "the best
    discovered link only" — so a router fanning out to two switches announced
    both links in the plan and configured only one of them. The core switch
    was cabled to seed-01:gi1/0/1 while that socket stayed in its default
    access state on VLAN 1: the plan said trunk, the device said access.
    """
    report = _run_with_retry(decision)
    modes = _mode_of(report)
    missing = []
    for up in report.design.uplinks:
        for dev, port in ((up.device_ref, up.local_port), (up.peer_ref, up.peer_port)):
            if modes.get((dev, port)) != "trunk":
                missing.append(f"{dev}:{port} (mode={modes.get((dev, port))})")
    assert not missing, f"uplink ends never put into trunk mode: {sorted(missing)}"


@pytest.mark.parametrize("decision", ["n", "y"])
def test_no_port_is_both_trunk_and_access(decision):
    """One socket cannot carry two roles; overlapping assignment is a defect."""
    report = _run_with_retry(decision)
    modes = _mode_of(report)
    access = {(a.device_ref, a.port.lower()) for a in report.design.access}
    trunks = {k for k, v in modes.items() if v == "trunk"}
    overlap = sorted(access & trunks)
    assert not overlap, f"port assigned both trunk and access: {overlap}"


def test_uplink_selection_is_grade_ranked_not_first_link_found():
    """The FSM-4 ranking must actually run, not be dead code after a `break`.

    The loop over discovered links used to `break` on the first match, so the
    `.sort()` by grade never saw a second candidate and the emitted `reason`
    described a selection the engine never performed.
    """
    report = _run_with_retry("y")
    ups = {(u.device_ref, u.local_port): u for u in report.design.uplinks}
    # seed-01 fans out to two neighbours; both sockets must be planned.
    assert ("seed-01", "gi1/0/1") in ups and ("seed-01", "gi1/0/2") in ups
    for u in ups.values():
        assert u.link_state is not None
        assert "best grade per local port" in u.reason, u.reason


def test_a_retried_device_reports_its_own_identity():
    """The substrate must not fabricate: access-sw1 answers as itself.

    It was previously backed by ``core_sw2_session()``, so unlocking it made
    the device report core-sw2's hostname, serial and LLDP table — and the
    design engine then planned two different neighbours onto one seed socket.
    """
    report = _run_with_retry("y")
    by_ref = {d.device_ref: d for d in report.crawl.devices}
    seed, access = by_ref["seed-01"], by_ref["access-sw1"]
    assert access.identity.serial != seed.identity.serial
    assert access.identity.model != seed.identity.model
    assert access.status.value == "COMPLETE"
    # Both ends of the access-sw1 link corroborate each other, so that specific
    # link has no weak-evidence gap. Other links legitimately do — Phase X adds
    # ARP-derived ones graded INFERRED, which must never be laundered into a
    # confirmed neighbour.
    about_access = [g for g in report.topology.gaps
                    if "access-sw1" in g and "l3-" not in g]
    assert not any("ONE_SIDED" in g or "LINK_EVIDENCE_BELOW_CONF" in g
                   for g in about_access), about_access


# ================================== 7. post-apply verification is factual, not
# a hash. A changed hash proves the configuration moved; only the readback
# proves it moved to the state we asked for.
def test_a_line_the_device_silently_ignored_fails_verification():
    """`vlan 20` is accepted, returns success — and never lands.

    The other line does change the configuration, so the before/after hashes
    differ and the old check would have reported this change verified.
    """
    dev = CountingDevice(silently_drop={"vlan 20"})
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="w-verify-absent")
    rec = ex.apply("sw1", dev, ["vlan 10", "vlan 20"],
                   wrappers=(["enable", "configure terminal"], ["end"]),
                   persist=["write memory"])
    assert rec.outcome is ChangeOutcome.ROLLED_BACK
    assert "VERIFY_STATE_ABSENT:vlan 20" in rec.failure_causes
    assert rec.state_absent == 1
    # the unverified state must not be made permanent
    assert "write memory" not in dev.sent


def test_a_negation_that_did_not_take_effect_is_caught():
    """A `no …` line is verified the other way round: the form must be *gone*.

    Driven directly because no cisco template currently yields a forward
    ``no …`` line — negations reach the device only through the rollback path,
    which is verified separately by baseline-hash equality. The branch is
    defensive, and defensive code that is never exercised is not tested code,
    so it is exercised here rather than left to be trusted.
    """
    from netops_autopilot.access.executor import _PlannedLine

    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="w-verify-negation")
    dev = CountingDevice(stuck={"vlan 10"})
    dev.state.add("vlan 10")                     # the device refuses to remove it
    applied = [_PlannedLine(raw="no vlan 10", stripped="no vlan 10", kind="CONFIG",
                            cls="CONFIG_REVERSIBLE", match=None, depth=0,
                            enters_mode=False)]
    ex.apply("sw1", dev, ["vlan 10"], wrappers=([], []))   # baseline record
    rec = ex.apply("sw1", dev, [], wrappers=([], []))
    causes = ex._verify_state_present(
        dev.execute("show running-config", timeout_s=1.0), applied, rec)
    assert causes == ["VERIFY_STATE_STILL_PRESENT:no vlan 10"]
    assert rec.state_absent == 1

    # and the mirror case: a negation that did take effect verifies clean
    dev2 = CountingDevice()
    dev2.state.add("vlan 10")
    dev2.state.discard("vlan 10")                # it really went away
    rec2 = ex.apply("sw1", dev2, [], wrappers=([], []))
    assert ex._verify_state_present(
        dev2.execute("show running-config", timeout_s=1.0), applied, rec2) == []


def test_verification_coverage_is_reported_on_the_record():
    """Coverage is stated, so `verified` can never mean `nothing was checked`."""
    dev = CountingDevice()
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="w-verify-coverage")
    lines = ["vlan 10", " name users", "ip routing"]
    rec = ex.apply("sw1", dev, lines,
                   wrappers=(["enable", "configure terminal"], ["end"]))
    assert rec.outcome is ChangeOutcome.APPLIED
    assert rec.state_checked == len(lines)
    assert rec.state_absent == 0
    # mode transitions are not configuration: they must not inflate coverage
    assert rec.state_checked == len(
        [c for c in rec.commands
         if c.phase == "APPLY" and c.classification in ("CONFIG_REVERSIBLE",
                                                        "CONFIG_HIGH_RISK")])
    payload = rec.to_dict()
    assert payload["state_checked"] == len(lines) and payload["state_absent"] == 0


def _config_body(rendered_text: str) -> list[str]:
    """The configuration lines only: no wrappers, no comments, no persist."""
    body: list[str] = []
    inside = False
    for line in rendered_text.splitlines():
        stripped = line.strip()
        if stripped == "configure terminal":
            inside = True
            continue
        if stripped == "end":
            inside = False
            continue
        if not inside or not stripped or stripped.startswith("!"):
            continue
        if stripped == "write memory":       # the persist section, not config
            continue
        body.append(line)
    return body


def test_state_verification_runs_before_persist_on_the_real_rendered_config():
    """End to end: the demo design's lines must all be found in the readback."""
    report = _run_with_retry("y")
    body = _config_body(report.renders["seed-01"].to_text())
    assert body, "the render produced no configuration body"
    dev = CountingDevice()
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="w-verify-rendered",
                        verify_after_each_block=True)
    rec = ex.apply("seed-01", dev, body,
                   wrappers=(["enable", "configure terminal"], ["end"]),
                   persist=["write memory"])
    assert rec.outcome is ChangeOutcome.APPLIED, rec.failure_causes
    assert rec.state_absent == 0
    assert rec.state_checked > 30, f"only {rec.state_checked} lines were checked"
    # the rendered text carries the persist marker as a comment, never as a line
    assert not any("! persist" in c for c in dev.sent)
    # every line we sent is now in the device's own running-config
    readback = dev.execute("show running-config", timeout_s=1.0).decode()
    for line in body:
        assert line.strip() in readback, line
