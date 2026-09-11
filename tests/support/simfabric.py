"""Simulated device fabric — the DETERMINISTIC evaluation substrate.

A scripted three-switch fabric answering like real consoles:

    seed-01 (direct console) ──LLDP/CDP── core-sw2 (names back, reachable)
        └──one-sided──> access-sw1 (ACCESS_LIMITED: default credentials
                       rejected — the operator's duplicate-device problem,
                       mechanized and evidence-tagged)

Registered in open_items_register.md as the SIMULATED substrate; the real
hardware lab gate (OI-0005) stays open and untouched by construction.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from netops_autopilot.access.collector import Collector, SessionLockManager
from netops_autopilot.core.budgets import CommandBudget
from netops_autopilot.core.counters import CounterCollector
from netops_autopilot.core.failures import Failure, FailureClass
from netops_autopilot.core.timeauth import TimeAuthority
from netops_autopilot.fsm.link_fsm import build_link_fsm
from netops_autopilot.ledger.store import LedgerStore
from tests.support.loopback import LoopbackSession

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "golden"
NOW = datetime(2026, 9, 9, 12, 0, 0, tzinfo=timezone.utc)

BACK_TABLE = b"""Capability codes:
    (R) Router, (B) Bridge

------------------------------------------------
Local Intf: Gi0/1
Chassis id: 0011.2233.4455
Port id: Gi1/0/1
Port Description: GigabitEthernet1/0/1
System Name: SEED-01
System Description:
Cisco IOS Software
Time remaining: 100 seconds
Management Addresses:
    IP: 10.99.0.1

Total entries displayed: 1
"""

BACK_VERSION = b"""Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software
cisco C9300-48P (ARM) processor
CORE-SW2 uptime is 1 day, 2 hours
System serial number           : FOC1234X9YZ
Configuration register is 0x2102
"""

SEED_BANNER = b"\r\nCisco IOS Software, Catalyst L3 Switch\r\nseed-01 con0 is now available\r\nseed-01> "


def _fx(name: str) -> bytes:
    return (FIXTURES / "cisco_iosxe" / f"{name}.txt").read_bytes()


def seed_session() -> LoopbackSession:
    return LoopbackSession({
        "show version": _fx("show_version"),
        "show lldp neighbors detail": _fx("show_lldp_neighbors_detail"),
        "show cdp neighbors detail": _fx("show_cdp_neighbors_detail"),
        "show ip route": _fx("show_ip_route"),
        "show clock detail": _fx("show_clock"),
        "show vlan brief": _fx("show_vlan_brief"),
        "show interfaces status": _fx("show_interfaces_status"),
        "ping": _fx("ping"),
        "ping 10.0.0.1 repeat 5": _fx("ping"),
        "ping 10.99.0.2 repeat 5": _fx("ping"),
        "ping 10.99.0.3 repeat 5": _fx("ping"),
        "traceroute": _fx("traceroute"),
        "traceroute 8.8.8.8": _fx("traceroute"),
    })


def core_sw2_session() -> LoopbackSession:
    return LoopbackSession({
        "show version": BACK_VERSION,
        "show lldp neighbors detail": BACK_TABLE,
        "show cdp neighbors detail": b"",
        "show ip route": _fx("show_ip_route"),
        "show clock detail": _fx("show_clock"),
    })


class SimFabricFactory:
    """SessionFactory over the scripted fabric (typed refusals included)."""

    def __init__(self, *, include_access: bool = False, access_behavior: str = "refuse") -> None:
        self._seed = seed_session()
        self._core = core_sw2_session()
        self._include_access = include_access
        self._access_behavior = access_behavior
        self.opened: list[str] = []

    def open(self, device_ref: str, mgmt_hints: tuple[str, ...]):
        self.opened.append(device_ref)
        if device_ref == "seed-01":
            return self._seed
        if device_ref == "core-sw2" and self._include_access:
            if self._access_behavior == "refuse":
                raise Failure(cls=FailureClass.BLOCKED, causes=(
                    "AUTH_REFUSED: default credentials rejected on core-sw2 "
                    "(ACCESS_LIMITED — evidence-directed retry required)",))
            return self._core
        if device_ref == "access-sw1":
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                "AUTH_REFUSED: default credentials rejected on access-sw1 "
                "(ACCESS_LIMITED — evidence-directed retry required)",))
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"NO_ROUTE_KNOWN: {device_ref} has no mgmt-path facts",))

    def grant(self) -> None:
        """The operator fixed credentials: core-sw2 now answers."""
        self._access_behavior = "allow"

    def device_session(self, device_ref: str) -> LoopbackSession:
        """Return a LoopbackSession that answers show commands for the
        given device_ref. Used by the chat's DeviceCommandRunner so
        ``ping``, ``traceroute``, ``show ip route`` etc. actually
        execute against the sim-fabric and return real bytes.
        """
        if "core-sw2" in device_ref:
            return self._core
        if "access" in device_ref:
            return self._seed  # access-sw1 echoes seed for testing
        return self._seed

    # ---------------------------------------------------------- boot session
    def probe(self, port: str):
        """(session, banner) for the orchestrator's boot probe."""
        return (self._seed, SEED_BANNER)


def make_ledger_stack():
    """Fresh store + collector-ready helpers (CLI demo + E2E share this)."""
    store = LedgerStore(":memory:")
    key_id = store.keys.create_key("autopilot-collector")
    counters = CounterCollector()
    time_auth = TimeAuthority(clock=lambda: NOW)
    return store, key_id, counters, time_auth
