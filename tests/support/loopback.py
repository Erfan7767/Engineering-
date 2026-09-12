"""Test doubles implementing the adapter interfaces (D1 test infra).

LoopbackSession/LoopbackAccessAdapter are NOT vendor adapters; they exist so
the Collector and engines are exercised against the real interface contracts
before lab-hardware adapters land (ADR-0006 tiers run on hardware later).
"""

from __future__ import annotations

import re
from typing import Optional

from netops_autopilot.adapters.interfaces import AccessAdapter, CapabilityState, ExecSession


class LoopbackSession:
    """Canned responses keyed by command; supports fault injection.

    The session tracks every command it has received in ``self.executed``,
    so the executor's actual write commands show up in the audit trail.
    Write commands (anything not in ``outputs``) return a generic
    success response and are recorded in ``self.written_config``.
    """

    #: Documentation-only space (RFC 5737 TEST-NET-3) used to model a provider
    #: DHCP lease. These addresses are not routable anywhere, so a simulated
    #: lease can never be mistaken for real production addressing — and a test
    #: that depends on them cannot pass against real hardware by accident.
    DHCP_LEASE_GATEWAY = "203.0.113.1"
    DHCP_LEASE_FIRST = "203.0.113.2"

    TIMEOUT_SENTINEL = "__TIMEOUT__"
    CONNFAIL_SENTINEL = "__CONNFAIL__"

    def __init__(self, outputs: dict[str, bytes] | None = None, fail_times: dict[str, int] | None = None) -> None:
        self.outputs = dict(outputs or {})
        self.fail_times = dict(fail_times or {})
        self.executed: list[str] = []
        self.written_config: list[str] = []
        #: ``(display_depth, command)`` for everything written. A real device
        #: re-indents sub-mode commands in ``show running-config`` even though
        #: it accepts them unindented, so the double has to model that or a
        #: parser written against real output silently matches nothing here.
        self.written_indented: list[tuple[int, str]] = []
        self._mode_depth = 0
        #: VLAN ids whose SVI was configured `ip address dhcp`, in order. The
        #: provider's lease is modelled, not known — see DHCP_LEASE_GATEWAY.
        self.dhcp_interfaces: list[int] = []
        self.closed = False
        self.started_in_config_mode: bool = False

    def execute(self, command: str, timeout_s: float) -> bytes:
        self.executed.append(command)
        if self.fail_times.get(command, 0) > 0:
            self.fail_times[command] -= 1
            raise ConnectionError("loopback injected transport failure")
        if command.strip().lower() == "show ip route" and self.dhcp_interfaces:
            return self.ip_route().encode("utf-8")
        out = self.outputs.get(command, b"")
        if not out:
            # Try prefix match: ``ping 10.0.0.1 repeat 5`` → ``ping``
            head = command.strip().split(None, 1)[0] if command.strip() else ""
            if head and head in self.outputs:
                out = self.outputs[head]
        if not out:
            # Try "ping <ip>" / "traceroute <ip>" without repeat count.
            cmd_stripped = command.strip()
            parts = cmd_stripped.split()
            if len(parts) == 2 and parts[0].lower() in ("ping", "traceroute"):
                # If we have a canned response for that verb, return it.
                verb = parts[0].lower()
                if verb in self.outputs:
                    out = self.outputs[verb]
        if out == self.TIMEOUT_SENTINEL.encode():
            raise TimeoutError("loopback injected timeout")
        if out == self.CONNFAIL_SENTINEL.encode():
            raise ConnectionError("loopback injected connection failure")
        # If the command is a write (not in the read-only canned
        # outputs), record it as actually written and return a
        # generic success response. This is what a real device would
        # do for any well-formed config line.
        if not out:
            cmd_stripped = command.strip()
            head = cmd_stripped.split(None, 1)[0] if cmd_stripped else ""
            # ``show running-config`` returns the current
            # running-config (built from written_config). This is
            # the executor's post-apply verification hook.
            if cmd_stripped == "show running-config":
                return self.running_config().encode("utf-8")
            if cmd_stripped == "show ip interface brief":
                return self.ip_interface_brief().encode("utf-8")
            if cmd_stripped == "show ip access-lists":
                return self.ip_access_lists().encode("utf-8")
            READ_HEADS = {"show", "ping", "traceroute"}
            if head and head.lower() not in READ_HEADS and not cmd_stripped.startswith("!"):
                self.written_config.append(cmd_stripped)
                self.written_indented.append((self._mode_depth, cmd_stripped))
                # Transition tracking
                if head.lower() in ("configure", "conf"):
                    self.started_in_config_mode = True
                elif cmd_stripped.lower() in ("end", "exit"):
                    self.started_in_config_mode = cmd_stripped.lower() == "exit"
                    self._mode_depth = 0
                elif self._opens_mode(cmd_stripped):
                    # A real device indents everything entered from here.
                    self._mode_depth += 1
                if cmd_stripped.lower() == "ip address dhcp":
                    inside = self.current_interface()
                    if inside is not None and inside not in self.dhcp_interfaces:
                        self.dhcp_interfaces.append(inside)
                # Standard Cisco IOS-XE success response
                return b""
        return out

    def close(self) -> None:
        self.closed = True

    def vlan_members(self) -> dict[int, list[str]]:
        """L2 membership exactly as the device reports it in its VLAN table."""
        text = self.outputs.get("show vlan brief", b"").decode("utf-8", "replace")
        out: dict[int, list[str]] = {}
        for line in text.splitlines():
            m = re.match(r"^(\d+)\s+(\S+)\s+(\S+)\s*(.*)$", line)
            if not m:
                continue
            out[int(m.group(1))] = [p.strip() for p in m.group(4).split(",") if p.strip()]
        return out

    def ip_interface_brief(self) -> str:
        """`show ip interface brief` derived from what was actually applied.

        An SVI is reported `up/up` only when its VLAN has a member port, which
        is what a real device does: an SVI on an empty VLAN is admin-up but
        protocol-down. Reporting `up/up` unconditionally would let verification
        pass on a network that cannot actually forward, which is exactly the
        false success this double exists to avoid.
        """
        lines = ["Interface              IP-Address      OK? Method Status"
                 "                Protocol"]
        members = self.vlan_members()
        current: Optional[int] = None
        for cmd in self.written_config:
            head = re.match(r"^interface Vlan(\d+)$", cmd, re.IGNORECASE)
            if head:
                current = int(head.group(1))
                continue
            if cmd.lower() == "ip address dhcp" and current is not None:
                idx = (self.dhcp_interfaces.index(current)
                       if current in self.dhcp_interfaces else 0)
                protocol = "up" if members.get(current) else "down"
                lines.append(f"Vlan{current:<18} {self.dhcp_lease_for(idx):<15} YES DHCP  "
                             f"up                    {protocol}")
                current = None
                continue
            addr = re.match(r"^ip address (\S+) (\S+)$", cmd)
            if addr and current is not None:
                protocol = "up" if members.get(current) else "down"
                lines.append(f"Vlan{current:<18} {addr.group(1):<15} YES manual "
                             f"up                    {protocol}")
                current = None
        return "\n".join(lines) + "\n"

    def ip_access_lists(self) -> str:
        """ACLs derived from what was actually applied — empty means none exist.

        Never synthesises a deny that was not configured: post-apply
        verification of a DENY requirement must be able to fail.
        """
        body = [c for c in self.written_config
                if c.lower().startswith(("access-list", "ip access-list"))]
        if not body:
            return ""
        return "\n".join(body) + "\n"

    #: Commands that open a CLI sub-mode, so a real device indents the lines
    #: entered from them. First token only.
    _MODE_OPENERS = frozenset({
        "interface", "vlan", "router", "line", "ip", "access-list",
        "username", "crypto", "class-map", "policy-map",
    })

    def current_interface(self) -> Optional[int]:
        """The SVI the session is currently inside, if any."""
        for _depth, cmd in reversed(self.written_indented):
            head = re.match(r"^interface Vlan(\d+)$", cmd, re.IGNORECASE)
            if head:
                return int(head.group(1))
            if cmd.lower() in ("exit", "end"):
                return None
        return None

    def dhcp_lease_for(self, index: int) -> str:
        """Deterministic modelled lease: 203.0.113.2, .3, .4 …"""
        head, last = self.DHCP_LEASE_FIRST.rsplit(".", 1)
        return f"{head}.{int(last) + index}"

    def ip_route(self) -> str:
        """`show ip route` with the default route a DHCP WAN handoff installs.

        A real device learns the default route from the provider's lease, which
        is exactly why the design must not configure a static gateway on a
        DHCP-handoff WAN. Merged onto the canned table rather than replacing it,
        so the pre-existing connected routes stay visible.
        """
        base = self.outputs.get("show ip route", b"").decode("utf-8", "replace")
        vlan = self.dhcp_interfaces[0]
        gw_head = self.DHCP_LEASE_GATEWAY.rsplit(".", 1)[0]
        extra = [
            f"Gateway of last resort is {self.DHCP_LEASE_GATEWAY} to network 0.0.0.0",
            "",
            f"      {gw_head}.0/29 is directly connected, Vlan{vlan}",
            f"S*    0.0.0.0/0 [254/0] via {self.DHCP_LEASE_GATEWAY}",
        ]
        return base.rstrip("\n") + "\n" + "\n".join(extra) + "\n"

    @classmethod
    def _opens_mode(cls, command: str) -> bool:
        """True when a real device would indent the lines entered from here.

        ``ip`` is a container only for ``ip dhcp pool`` and ``ip access-list``;
        ``ip address`` and ``ip route`` are leaf statements that stay at the
        current level. Treating every ``ip`` line as a mode entry would indent
        address lines and make the blob unlike anything a device emits.
        """
        tokens = command.split()
        if not tokens:
            return False
        head = tokens[0].lower()
        if head == "ip":
            return len(tokens) >= 3 and (
                (tokens[1].lower() == "dhcp" and tokens[2].lower() == "pool")
                or tokens[1].lower() == "access-list")
        return head in cls._MODE_OPENERS - {"ip"}

    def running_config(self) -> str:
        """Return the running-config as a Cisco-style text blob.

        Built from the lines that were written, re-indented the way a real
        device formats them: sub-mode commands sit one space in per level.
        Without that indentation a parser written against real ``show
        running-config`` output — which is what production devices emit —
        matches nothing here, and verification would grade a correctly
        configured device as broken.
        """
        lines = [
            "! Last applied by NetOps Autopilot",
            f"! {len(self.written_config)} command(s) committed",
            "!",
        ]
        for depth, cmd in self.written_indented:
            # `ip` opens a mode only as a container prefix (`ip dhcp pool`,
            # `ip access-list`); a plain `ip address` / `ip route` is a leaf.
            if depth > 0:
                lines.append(" " * depth + cmd)
            else:
                lines.append(cmd)
        return "\n".join(lines) + "\n"


class LoopbackAccessAdapter(AccessAdapter):
    """Minimal AccessAdapter over LoopbackSession for pipeline tests."""

    vendor_family = "test/loopback"

    def __init__(self, session: LoopbackSession) -> None:
        self._session = session
        self._locks: set[str] = set()

    def capability(self, operation: str) -> CapabilityState:
        return CapabilityState.SUPPORTED if operation.startswith("open_session") else CapabilityState.NOT_SUPPORTED

    def open_session(self, device_ref: str, method: str) -> ExecSession:
        return self._session

    def close_session(self, device_ref: str) -> None:
        self._session.close()

    def acquire_lock(self, device_ref: str) -> bool:
        if device_ref in self._locks:
            return False
        self._locks.add(device_ref)
        return True

    def release_lock(self, device_ref: str) -> None:
        self._locks.discard(device_ref)

    def human_session_active(self, device_ref: str) -> bool:
        return False  # loopback transport proves exclusivity
