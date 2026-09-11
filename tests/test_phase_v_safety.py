"""Phase V regression suite — the defects that made the platform *claim*
safety it did not have.

Every test here locks a specific, previously-shipping defect:

* the executor's rollback plan was built and then thrown away (the device was
  left half-configured while the record said ``ROLLED_BACK``);
* first-token allowlist matching let ``ip http server`` through because
  ``ip routing`` was registered;
* ``configure terminal`` was swallowed as a comment, so config lines reached a
  real device in user EXEC mode;
* the renderer emitted ``ip address 10.0.0.1/25``, which IOS-XE rejects;
* only ``blocks[0]`` was applied while the preview showed every block;
* the ledger write raised ``TypeError`` every time and the surrounding
  ``except Exception: pass`` hid it, so no change was ever auditable;
* the real-hardware management path raised unconditionally, so a discovered
  network could never be configured;
* demo scenario answers were shifted one slot, printing nonsense Q&A.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import pytest

from netops_autopilot.access.allowlist import AllowlistEntry, CommandAllowlist
from netops_autopilot.access.executor import (
    ChangeOutcome,
    ConfigExecutor,
    normalize_running_config,
)
from netops_autopilot.specs_data import specs_data_dir


# ------------------------------------------------------------------ fixtures
def cisco_allowlist() -> CommandAllowlist:
    return CommandAllowlist.load_vendor(specs_data_dir("allowlists"), "cisco/ios-xe")


class StatefulDevice:
    """A device that models its own configuration and can be made to fail."""

    def __init__(self, fail_on: Optional[set] = None, reject_inverses: bool = False):
        self.sent: list[str] = []
        self.state: set[str] = set()
        self._fail_on = fail_on or set()
        self._reject_inverses = reject_inverses

    def _mutate(self, cmd: str) -> None:
        if cmd.startswith("no "):
            body = cmd[3:].strip()
            if body in self.state:
                self.state.discard(body)
                return
            head = body.split()[0]
            for existing in list(self.state):
                if existing.split()[0] == head:
                    self.state.discard(existing)
        elif cmd.startswith("default "):
            self.state.discard(cmd[len("default "):])
        else:
            self.state.add(cmd)

    def execute(self, command: str, timeout_s=None) -> bytes:
        self.sent.append(command)
        if command.strip() in self._fail_on:
            raise RuntimeError(f"DEVICE_REJECTED: {command}")
        if command.strip() == "show running-config":
            body = "\n".join(sorted(self.state))
            return (f"Building configuration...\n\n"
                    f"Current configuration : {len(body)} bytes\n!\n{body}\nend\n").encode()
        if self._reject_inverses and command.strip().startswith("no "):
            raise RuntimeError("INVERSE_REJECTED")
        if command.strip() in ("enable", "configure terminal", "end", "exit"):
            return b""
        self._mutate(command.strip())
        return b"% ok"

    def close(self) -> None:
        pass


# ======================================================= 1. allowlist bypass
BYPASS_ATTEMPTS = [
    "ip http server",
    "ip http secure-server",
    "ip nat inside source static 10.0.0.5 8.8.8.8",
    "ip access-list extended EVIL",
    "switchport port-security maximum 1",
    "switchport voice vlan 999",
    "username attacker privilege 15 secret 0 cisco123",
    "enable secret 5 $9$EVILHASH",
    "no ip routing",
    "write erase",
    "erase startup-config",
    "reload",
    "no router ospf 1",
]


@pytest.mark.parametrize("command", BYPASS_ATTEMPTS)
def test_dangerous_command_never_reaches_the_config_gate(command):
    """First-token matching accepted all of these; structural matching refuses."""
    al = cisco_allowlist()
    assert al.gate(command) not in ("CONFIG_REVERSIBLE", "CONFIG_HIGH_RISK")


def test_structural_match_binds_placeholders_and_respects_arity():
    al = cisco_allowlist()
    assert al.match("vlan 10").template == "vlan <vlan_id>"
    assert al.match("vlan 10").value("vlan_id") == "10"
    assert al.match("interface Vlan10").template == "interface Vlan<vlan_id>"
    # arity is a hard requirement, not a suggestion
    assert al.match("switchport mode") is None
    assert al.match("switchport mode trunk extra") is None


def test_forbidden_outranks_config_for_the_same_command():
    al = CommandAllowlist((
        AllowlistEntry(template="no router <args>", cls="FORBIDDEN"),
        AllowlistEntry(template="router ospf <pid>", cls="CONFIG_HIGH_RISK",
                       rollback="no router ospf <pid>"),
    ))
    assert al.gate("router ospf 1") == "CONFIG_HIGH_RISK"
    assert al.gate("no router ospf 1") == "FORBIDDEN"


# ================================================= 2. rollback is really done
def test_rollback_commands_are_actually_issued_to_the_device():
    """The headline defect: the plan was built, then never sent."""
    dev = StatefulDevice(fail_on={"vlan 20"})
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="v-rollback")
    rec = ex.apply("sw1", dev, ["vlan 10", "name users", "vlan 20", "name voice"],
                   wrappers=(["enable", "configure terminal"], ["end"]))

    assert rec.outcome is ChangeOutcome.ROLLED_BACK
    assert rec.rollback_issued >= 1, "no inverse command ever reached the device"
    assert "no vlan 10" in dev.sent
    assert "no name" in dev.sent
    # the device is provably back where it started
    assert dev.state == set()
    assert rec.rollback_hash == rec.before_hash


def test_rollback_failure_is_never_reported_as_rolled_back():
    """If an inverse is rejected the record must say so, loudly."""
    dev = StatefulDevice(fail_on={"vlan 20"}, reject_inverses=True)
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="v-rb-fail")
    rec = ex.apply("sw1", dev, ["vlan 10", "name users", "vlan 20"],
                   wrappers=(["enable", "configure terminal"], ["end"]))

    assert rec.outcome is ChangeOutcome.ROLLBACK_FAILED
    assert any("ROLLBACK_COMMAND_FAILED" in c for c in rec.failure_causes)
    assert any("DEVICE_MAY_BE_LEFT_IN_PARTIAL_STATE" in c for c in rec.failure_causes)


def test_inverse_is_issued_at_the_mode_depth_it_was_applied_at():
    """`no name` belongs inside `vlan 10`; `no vlan 10` belongs in global config."""
    dev = StatefulDevice(fail_on={"ip routing"})
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="v-depth")
    rec = ex.apply("sw1", dev, ["vlan 10", " name users", "ip routing"],
                   wrappers=(["enable", "configure terminal"], ["end"]))
    depths = {c.command: c.depth for c in rec.commands if c.phase == "APPLY"}
    assert depths["vlan 10"] == 0
    assert depths["name users"] == 1


# ============================================== 3. CLI mode handling
def test_config_mode_entry_actually_reaches_the_device():
    dev = StatefulDevice()
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="v-mode")
    ex.apply("sw1", dev, ["vlan 10"], wrappers=(["enable", "configure terminal"], ["end"]))
    assert dev.sent.index("configure terminal") < dev.sent.index("vlan 10")
    assert "end" in dev.sent


def test_dropping_indent_inserts_exit_before_the_next_command():
    """`ip routing` after `vlan 10`/`name users` must not be typed in config-vlan."""
    dev = StatefulDevice()
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="v-exit")
    ex.apply("sw1", dev, ["vlan 10", " name users", "ip routing"],
             wrappers=(["enable", "configure terminal"], ["end"]))
    assert dev.sent.index("name users") < dev.sent.index("exit") < dev.sent.index("ip routing")


def test_indent_without_a_mode_entry_is_refused():
    al = CommandAllowlist((
        AllowlistEntry(template="hostname <h>", cls="CONFIG_REVERSIBLE", rollback="no hostname"),
    ))
    dev = StatefulDevice()
    ex = ConfigExecutor(allowlist=al, run_id="v-bad-indent")
    rec = ex.apply("sw1", dev, ["hostname R1", " name x"])
    assert rec.outcome is ChangeOutcome.REJECTED
    assert any("INDENT_WITHOUT_MODE_ENTRY" in c for c in rec.failure_causes)
    assert dev.sent == []


def test_unsafe_wrapper_cannot_smuggle_configuration():
    dev = StatefulDevice()
    ex = ConfigExecutor(allowlist=cisco_allowlist(), run_id="v-wrapper")
    rec = ex.apply("sw1", dev, ["vlan 10"],
                   wrappers=(["configure terminal", "ip http server"], ["end"]))
    assert rec.outcome is ChangeOutcome.REJECTED
    assert any("UNSAFE_WRAPPER" in c for c in rec.failure_causes)
    assert dev.sent == []


# ============================================== 4. renderer/allowlist agreement
def test_running_config_normalization_ignores_platform_header_noise():
    a = normalize_running_config(b"Building configuration...\n\nCurrent configuration : 9 bytes\n!\nhostname R1\n")
    b = normalize_running_config(b"Building configuration...\n\nCurrent configuration : 9 bytes\n!\nhostname R1\n!\n")
    assert a == b


def test_rendered_preview_equals_what_the_executor_would_apply():
    """`blocks[0]` used to be the only block applied, while the preview printed all."""
    from netops_autopilot.autopilot.orchestrator import _all_commands

    @dataclass
    class _Block:
        commands: tuple

    @dataclass
    class _Render:
        blocks: tuple

    render = _Render(blocks=(_Block(("vlan 10", " name users")),
                             _Block(("vlan 20", " name voice"))))
    assert _all_commands(render) == ("vlan 10", " name users", "vlan 20", " name voice")


def test_every_rendered_line_of_a_real_design_passes_the_gate():
    """The demo's own output must be both valid IOS-XE and fully allowlisted."""
    from netops_autopilot.engines.blueprints import BLUEPRINTS, elicit
    from netops_autopilot.autopilot.orchestrator import _all_commands  # noqa: F401

    al = cisco_allowlist()
    lines = [
        "vlan 10", " name users", "ip routing",
        "interface Vlan10", " ip address 10.240.0.1 255.255.255.128",
        "interface gi1/0/1", " switchport trunk encapsulation dot1q",
        " switchport mode trunk", " switchport trunk allowed vlan 10,20,30,40",
    ]
    for line in lines:
        assert al.gate(line) in ("CONFIG_REVERSIBLE", "CONFIG_HIGH_RISK"), line
    # CIDR form is not valid IOS-XE and must not be produced
    assert al.gate("ip address 10.240.0.1/25") is None


# ============================================== 5. audit trail is real
def test_config_change_is_written_to_the_signed_ledger():
    from tests.support.simfabric import make_ledger_stack
    store, key_id, _c, ta = make_ledger_stack()
    dev = StatefulDevice()
    ex = ConfigExecutor(allowlist=cisco_allowlist(), store=store, key_id=key_id,
                        run_id="v-ledger", collector_id="unit-test", time_authority=ta)
    rec = ex.apply("sw1", dev, ["vlan 10", " name users"],
                   wrappers=(["enable", "configure terminal"], ["end"]))
    assert rec.outcome is ChangeOutcome.APPLIED
    events = [e for e in store.events() if (e.command_or_op or "").startswith("CONFIG_CHANGE")]
    assert len(events) == 1
    assert events[0].signature is not None          # actually signed
    assert store.verify_chain().ok
    assert not any("LEDGER_WRITE_FAILED" in c for c in rec.failure_causes)


def test_missing_signing_key_is_reported_not_swallowed():
    from tests.support.simfabric import make_ledger_stack
    store, _key_id, _c, _ta = make_ledger_stack()
    dev = StatefulDevice()
    ex = ConfigExecutor(allowlist=cisco_allowlist(), store=store, key_id=None,
                        run_id="v-noleadger")
    rec = ex.apply("sw1", dev, ["vlan 10"])
    assert any("LEDGER_NOT_CONFIGURED" in c for c in rec.failure_causes)


# ============================================== 6. high-risk gate
def test_high_risk_lines_require_explicit_arming():
    al = CommandAllowlist((
        AllowlistEntry(template="router ospf <pid>", cls="CONFIG_HIGH_RISK",
                       rollback="no router ospf <pid>", enters_mode=True),
    ))
    dev = StatefulDevice()
    unarmed = ConfigExecutor(allowlist=al, run_id="v-unarmed")
    rec = unarmed.apply("r1", dev, ["router ospf 1"])
    assert rec.outcome is ChangeOutcome.REJECTED
    assert any("HIGH_RISK_NOT_AUTHORIZED" in c for c in rec.failure_causes)
    assert "router ospf 1" not in dev.sent

    armed = ConfigExecutor(allowlist=al, run_id="v-armed").arm_high_risk()
    rec2 = armed.apply("r1", dev, ["router ospf 1"])
    assert rec2.outcome is ChangeOutcome.APPLIED


# ============================================== 7. real management path
@dataclass
class _FakeIdentity:
    vendor_family: Optional[str]
    model: Optional[str] = None
    version: Optional[str] = None
    serial: Optional[str] = None
    evidence_obs_ids: tuple = ()


@dataclass
class _FakeDevice:
    device_ref: str
    identity: Optional[_FakeIdentity] = None
    mgmt_addresses: tuple = ()


@dataclass
class _FakeCrawl:
    devices: list = field(default_factory=list)


class _RecordingConnect:
    """Stands in for select_transport; returns a session with a known serial."""

    def __init__(self, serial: str):
        self.serial = serial
        self.specs: list = []

    def __call__(self, spec):
        self.specs.append(spec)
        factory = self

        class _S:
            def open(self):
                pass

            def execute(self, command, timeout_s=None):
                return (f"Cisco IOS XE Software, Version 17.09.04a\n"
                        f"System serial number     : {factory.serial}\n").encode()

            def close(self):
                pass

        return _S()


def _factory(serial_on_wire: str, allow_unverified: bool = False):
    from netops_autopilot.access.mgmt_session import MgmtCredential, MgmtSessionFactory
    return MgmtSessionFactory(
        credential_provider=lambda ref, fam: MgmtCredential("admin", "pw"),
        allow_unverified_identity=allow_unverified,
        connect=_RecordingConnect(serial_on_wire),
    )


def test_device_with_no_observed_management_address_is_refused():
    from netops_autopilot.core.failures import Failure
    f = _factory("FOC1234X9YZ")
    f.bind_crawl(_FakeCrawl(devices=[
        _FakeDevice("core-sw2", _FakeIdentity("cisco/ios-xe", serial="FOC1234X9YZ"), ()),
    ]))
    with pytest.raises(Failure) as exc:
        f("core-sw2", ())
    assert any("ACCESS_LIMITED" in c for c in exc.value.causes)


def test_identity_mismatch_refuses_to_configure():
    from netops_autopilot.core.failures import Failure
    f = _factory("WRONG-SERIAL")          # the wire answers a different box
    f.bind_crawl(_FakeCrawl(devices=[
        _FakeDevice("core-sw2", _FakeIdentity("cisco/ios-xe", serial="FOC1234X9YZ"),
                    ("10.0.0.2",)),
    ]))
    with pytest.raises(Failure) as exc:
        f("core-sw2", ())
    assert any("IDENTITY_MISMATCH" in c for c in exc.value.causes)


def test_matching_identity_opens_the_session():
    f = _factory("FOC1234X9YZ")
    f.bind_crawl(_FakeCrawl(devices=[
        _FakeDevice("core-sw2", _FakeIdentity("cisco/ios-xe", serial="FOC1234X9YZ"),
                    ("10.0.0.2",)),
    ]))
    session = f("core-sw2", ())
    assert session is not None
    assert f.confirmed_identities[0].status == "CONFIRMED"


def test_unverified_identity_refuses_unless_the_operator_opts_in():
    from netops_autopilot.core.failures import Failure
    crawl = _FakeCrawl(devices=[
        _FakeDevice("core-sw2", _FakeIdentity("cisco/ios-xe", serial=None), ("10.0.0.2",)),
    ])
    strict = _factory("FOC1234X9YZ")
    strict.bind_crawl(crawl)
    with pytest.raises(Failure) as exc:
        strict("core-sw2", ())
    assert any("IDENTITY_UNVERIFIED" in c for c in exc.value.causes)

    permissive = _factory("FOC1234X9YZ", allow_unverified=True)
    permissive.bind_crawl(crawl)
    assert permissive("core-sw2", ()) is not None
    assert permissive.confirmed_identities[0].status == "UNVERIFIED"


def test_credentials_are_never_repr_able():
    from netops_autopilot.access.mgmt_session import MgmtCredential
    text = repr(MgmtCredential("admin", "Sup3rS3cret", enable_secret="en4ble"))
    assert "Sup3rS3cret" not in text
    assert "en4ble" not in text


def test_undiscovered_device_is_never_addressed():
    from netops_autopilot.core.failures import Failure
    f = _factory("FOC1234X9YZ")
    f.bind_crawl(_FakeCrawl(devices=[]))
    with pytest.raises(Failure) as exc:
        f("ghost-99", ())
    assert any("DEVICE_NOT_DISCOVERED" in c for c in exc.value.causes)
