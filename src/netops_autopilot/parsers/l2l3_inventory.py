"""Deterministic parsers: Cisco IOS-XE ``show ip arp`` and ``show mac address-table``.

Why these two exist. Discovery previously read **only** CDP and LLDP neighbour
tables. A device with LLDP disabled — a firewall with it off by default, a
server, an access point, anything not configured to advertise — is completely
invisible to that method, so the platform reported a complete topology that was
missing equipment physically cabled into the network. That is exactly the
"ignoring things" failure the platform is not allowed to have.

ARP and the MAC address table are the evidence a network engineer actually falls
back on, and they answer a different question:

* ``show ip arp`` — which L3 addresses are live on this device, with the MAC and
  the interface each was learned on. A live address is a device, whether or not
  it advertises itself.
* ``show mac address-table`` — which physical port each MAC was learned on.

Joined on MAC, they place a non-advertising device at an IP **and** on a port.
That is strictly weaker evidence than a bidirectional LLDP session, so it is
graded as such downstream and never presented as a confirmed neighbour.

Field rules (L01 — never guess):

* The header anchors the parse. No header ⇒ unknown structure ⇒ both fields
  MISSING, never an empty table. "Nothing is connected" and "I could not read
  this" are different facts.
* Rows are split **positionally** using the header's column spans. ``str.split()``
  would shatter ``Age (min)`` and ``Mac Address``, which both contain spaces.
* A row whose key column is empty, or that has fewer columns than the header, is
  skipped rather than partially interpreted.
* Empty cells become ``None`` — explicit absence, never ``''``.
"""

from __future__ import annotations

import re
from typing import Optional

from ..ledger.models import Observation
from .registry import Parser, ParserInfo, obs_missing, obs_ok

ARP_ROW_KEYS: tuple[str, ...] = ("protocol", "address", "age_minutes",
                                 "hardware_addr", "type", "interface")
MAC_ROW_KEYS: tuple[str, ...] = ("vlan", "mac_address", "type", "ports")

_ARP_HEADER = re.compile(
    r"^(?P<protocol>Protocol)\s+(?P<address>Address)\s+"
    r"(?P<age_minutes>Age\s*\(min\))\s+(?P<hardware_addr>Hardware\s*Addr)\s+"
    r"(?P<type>Type)\s+(?P<interface>Interface)\s*$", re.I)

_MAC_HEADER = re.compile(
    r"^(?P<vlan>Vlan)\s+(?P<mac_address>Mac\s*Address)\s+"
    r"(?P<type>Type)\s+(?P<ports>Ports)\s*$", re.I)

#: Lines that are furniture, not data.
_MAC_NOISE = (
    re.compile(r"^[\s\-]*$"),
    re.compile(r"^\s*Mac Address Table\s*$", re.I),
    re.compile(r"^\s*Total Mac Addresses", re.I),
    re.compile(r"^\s*Number of permanent entries", re.I),
)

#: Shape of each table's key column. A row whose key does not have this shape is
#: not a row — it is trailing prose that happens to sit in the same columns, and
#: accepting it would invent a device. Validating the key is what makes the
#: positional split safe against footer text.
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAC_ADDR = re.compile(r"^[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}$|"
                       r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")


def _column_spans(match: "re.Match[str]", names: tuple[str, ...]) -> list[tuple[int, int]]:
    """Column boundaries from a header match.

    A column runs from the start of its heading to the start of the next one —
    not for the length of the heading. The last column runs to end of the *data*
    line, because the header is normally narrower than the rows it heads.
    """
    starts = [match.start(name) for name in names]
    spans: list[tuple[int, int]] = [(starts[i], starts[i + 1])
                                    for i in range(len(starts) - 1)]
    spans.append((starts[-1], -1))
    return spans


def _split_row(line: str, spans: list[tuple[int, int]]) -> list[str]:
    return [(line[start:] if end < 0 else line[start:end]).strip()
            for start, end in spans]


def _emit(parser: Parser, raw_id: str, table_field: str, count_field: str,
          table: Optional[list[dict]]) -> list[Observation]:
    if table is None:
        return [obs_missing(parser, raw_id, table_field),
                obs_missing(parser, raw_id, count_field)]
    return [obs_ok(parser, raw_id, table_field, table),
            obs_ok(parser, raw_id, count_field, len(table))]


def _parse_table(text: str, header: re.Pattern, keys: tuple[str, ...],
                 key_column: str, key_pattern: re.Pattern,
                 noise: tuple[re.Pattern, ...] = ()) -> Optional[list[dict]]:
    """Shared fixed-width table walk for both commands."""
    lines = text.splitlines()
    header_index: Optional[int] = None
    spans: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        match = header.match(line.rstrip())
        if match:
            header_index = index
            spans = _column_spans(match, keys)
            break
    if header_index is None:
        return None                            # unknown structure: MISSING

    table: list[dict] = []
    for line in lines[header_index + 1:]:
        if not line.strip():
            continue
        if any(rx.match(line) for rx in noise):
            continue
        rematch = header.match(line.rstrip())
        if rematch:                            # paginated output re-heads itself
            spans = _column_spans(rematch, keys)
            continue
        cells = _split_row(line, spans)
        if len(cells) < len(keys):
            continue                           # wrapped/truncated: never guess
        row = dict(zip(keys, cells))
        key = row[key_column]
        if not key or not key_pattern.match(key):
            continue                           # prose in the columns, not a row
        table.append({k: (v if v else None) for k, v in row.items()})
    return table


class CiscoIosXeArpParser(Parser):
    """``show ip arp`` → ``arp_table`` + ``arp_count``."""

    info = ParserInfo(
        parser_id="regex/cisco_iosxe_show_ip_arp",
        version="1.0.0",
        vendor_family="cisco/ios-xe",
        command_ref="show ip arp",
    )

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        table = _parse_table(raw.decode("utf-8", errors="replace"),
                             _ARP_HEADER, ARP_ROW_KEYS, "address", _IPV4)
        return _emit(self, raw_id, "arp_table", "arp_count", table)


class CiscoIosXeMacAddressTableParser(Parser):
    """``show mac address-table`` → ``mac_table`` + ``mac_count``."""

    info = ParserInfo(
        parser_id="regex/cisco_iosxe_show_mac_address_table",
        version="1.0.0",
        vendor_family="cisco/ios-xe",
        command_ref="show mac address-table",
    )

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        table = _parse_table(raw.decode("utf-8", errors="replace"),
                             _MAC_HEADER, MAC_ROW_KEYS, "mac_address", _MAC_ADDR,
                             noise=_MAC_NOISE)
        return _emit(self, raw_id, "mac_table", "mac_count", table)
