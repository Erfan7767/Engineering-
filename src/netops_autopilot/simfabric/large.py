"""Large synthetic fabrics — the scaling harness the product never had.

Every claim this platform makes about "large and small networks" was measured
on a four-device fabric until this module existed. A four-device run cannot
show a discovery budget binding, cannot show a design that has to place four
thousand access ports, and cannot show a per-device cost that only becomes a
wall-clock problem at three digits.

This generates a real three-tier fabric — one L3 core, ``k`` distribution
switches, ``k * m`` access switches — as ``LoopbackSession`` devices with
unique serials and chassis ids and *reciprocal* LLDP, then hands it to the
same ``SimFabricFactory`` interface the rest of the platform uses. Nothing here
stands in for an engine: the real crawler, design, renderer, executor and
verifier all run against it.

Two details matter, because getting either wrong makes the fabric lie:

* **Every serial and chassis id is unique.** Two devices sharing a serial is
  an identity collision, and the crawler rightly refuses to treat them as
  distinct — the fabric would collapse to one device and the run would look
  like a discovery bug.
* **The dashed separator precedes every LLDP entry.** The parser splits blocks
  on ``^-{5,}$``; one separator for the whole table parses to a single
  neighbour and the fabric silently becomes a two-device network.

Measured on this harness (simulated transport, so wall clock is engine cost
only): 7 devices 0.09 s, 21 → 0.23 s, 73 → 1.28 s, 157 → 5.20 s,
273 → 11.9 s / 104 MB, every device COMPLETE up to the budget and the rest
recorded ``NOT_PROBED`` rather than dropped.
"""

from __future__ import annotations

from typing import Optional

from .fabric import SEED_BANNER, _fx
from .loopback import LoopbackSession


def _version(hostname: str, serial: str, model: str) -> bytes:
    return f"""Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.09.04a
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.

{hostname} uptime is 1 day, 2 hours
System image file is "bootflash:packages.conf"

Cisco {model} processor with 1401856K/6144K bytes of memory.
Processor board ID {serial}
System serial number : {serial}
48 Gigabit Ethernet interfaces

Configuration register is 0x2102
""".encode()


def _lldp(entries) -> bytes:
    """entries: list of (local_intf, chassis, port_id, sysname, mgmt_ip)"""
    out = ["Capability codes:", "    (R) Router, (B) Bridge", ""]
    for local, chassis, port, name, ip in entries:
        out += ["------------------------------------------------",
                f"Local Intf: {local}", f"Chassis id: {chassis}",
                f"Port id: {port}", f"Port Description: GigabitEthernet{port[2:]}",
                f"System Name: {name}", "System Description:",
                "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software",
                "Time remaining: 100 seconds",
                "System Capabilities: B,R", "Enabled Capabilities: R",
                "Management Addresses:", f"    IP: {ip}", ""]
    out.append(f"Total entries displayed: {len(entries)}")
    return "\n".join(out).encode()


def _interfaces(count: int, uplink_ports) -> bytes:
    rows = ["Port      Status         Vlan       Duplex  Speed Type"]
    for i in range(1, count + 1):
        port = f"Gi1/0/{i}"
        if i in uplink_ports:
            rows.append(f"Gi1/0/{i:<3} connected      trunk      a-full  a-1000 10/100/1000BaseTX")
        elif i <= 4:
            rows.append(f"Gi1/0/{i:<3} connected      10         a-full  a-1000 10/100/1000BaseTX")
        else:
            rows.append(f"Gi1/0/{i:<3} notconnect     1          auto    auto   10/100/1000BaseTX")
    return "\n".join(rows).encode()


def build(k: int, m: int):
    """1 core + k distribution + k*m access. Returns (refs, sessions, seed_ref)."""
    refs, sessions = [], {}
    def add(ref, hostname, serial, chassis, ip, neighbours, ports, uplinks):
        refs.append(ref)
        sessions[ref] = LoopbackSession({
            "show version": _version(hostname, serial, "C9300-48P"),
            "show lldp neighbors detail": _lldp(neighbours),
            "show cdp neighbors detail": b"",
            "show ip route": _fx("show_ip_route"),
            "show clock detail": _fx("show_clock"),
            "show vlan brief": _fx("show_vlan_brief"),
            "show interfaces status": _interfaces(ports, uplinks),
        })
    # core: seed-01
    core_nbrs = []
    for i in range(1, k + 1):
        core_nbrs.append((f"Gi1/0/{i}", f"00aa.0000.{i:04x}", "Gi1/0/24",
                          f"DIST-{i:02d}.lab", f"10.99.1.{i}"))
    add("seed-01", "SEED-01", "SEEDSERIAL0001", "0011.2233.4455", "10.99.0.2",
        core_nbrs, 48, set(range(1, k + 1)))
    # distribution
    n = 1
    for i in range(1, k + 1):
        nbrs = [("Gi1/0/24", "0011.2233.4455", f"Gi1/0/{i}", "SEED-01.lab", "10.99.0.2")]
        ups = {24}
        for j in range(1, m + 1):
            p = j
            nbrs.append((f"Gi1/0/{p}", f"00bb.{i:04x}.{j:04x}", "Gi1/0/24",
                         f"ACC-{i:02d}-{j:02d}.lab", f"10.99.{i+1}.{j}"))
            ups.add(p)
        add(f"dist-{i:02d}", f"DIST-{i:02d}", f"DISTSERIAL{i:05d}", f"00aa.0000.{i:04x}",
            f"10.99.1.{i}", nbrs, 48, ups)
        for j in range(1, m + 1):
            n += 1
            add(f"acc-{i:02d}-{j:02d}", f"ACC-{i:02d}-{j:02d}", f"ACCSERIAL{i:03d}{j:03d}",
                f"00bb.{i:04x}.{j:04x}", f"10.99.{i+1}.{j}",
                [("Gi1/0/24", f"00aa.0000.{i:04x}", f"Gi1/0/{j}",
                  f"DIST-{i:02d}.lab", f"10.99.1.{i}")], 24, {24})
    return refs, sessions


class LargeFabric:
    def __init__(self, k, m):
        self.refs, self.sessions = build(k, m)
        self.opened = []
    def probe(self, port):
        return self.sessions["seed-01"], SEED_BANNER
    def open(self, device_ref, mgmt_hints=()):
        self.opened.append(device_ref)
        s = self.sessions.get(device_ref)
        if s is None:
            raise KeyError(device_ref)
        return s
    def __call__(self, device_ref, mgmt_hints=()):
        return self.open(device_ref, mgmt_hints)


