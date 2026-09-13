"""Deterministic neighbor-discovery parsers for all six v1 vendor families.

These feed the multi-device discovery crawl (D5-capstone) and, through the
Link Evidence Engine (FSM-4), the topology map. Contract (E03, D0-08 §2):

* never raise on malformed input — structure problems yield MISSING
  observations, never guesses (T2/L01);
* ``command_ref`` equals the allowlist READ_ONLY template EXACTLY, so the
  Claim Relevance Guard rule 2 (command↔field agreement) passes;
* every entry carries a FIXED key set with explicit ``None`` for facts the
  source does not state — absence is typed, not hidden.

Emission shape per parser: one ``neighbor_table`` observation (list of
entry dicts) plus one ``neighbor_count`` observation. A positively-detected
empty table is OK/[]/0; unrecognizable structure is MISSING, never [].
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from ..ledger.models import Observation
from .registry import Parser, ParserInfo, obs_missing, obs_ok

#: Fixed key set of every neighbor table entry (explicit absence = None).
ENTRY_KEYS: tuple[str, ...] = (
    "local_intf",       # normalized local interface name (raw from device)
    "neighbor_id",      # system name / device id as advertised
    "neighbor_intf",    # remote port id as advertised
    "chassis_id",       # MAC/serial-ish id, or None
    "mgmt_address",     # advertised management IP, or None
    "platform",         # advertised platform string, or None
    "protocol",         # LLDP | CDP | MNDP
)


def _entry(protocol: str, *, local_intf: Optional[str], neighbor_id: Optional[str],
           neighbor_intf: Optional[str], chassis_id: Optional[str] = None,
           mgmt_address: Optional[str] = None, platform: Optional[str] = None) -> dict:
    return {
        "local_intf": local_intf,
        "neighbor_id": neighbor_id,
        "neighbor_intf": neighbor_intf,
        "chassis_id": chassis_id,
        "mgmt_address": mgmt_address,
        "platform": platform,
        "protocol": protocol,
    }


def _emit(parser: Parser, raw_id: str, table: Optional[list[dict]], proto: str) -> list[Observation]:
    """Central emission with PROTOCOL-SUFFIXED fields: a device answering
    both LLDP and CDP must never have one evidence source overwrite the
    other in the Twin (T1: each source keeps its own predicate).
    ``table`` None ⇒ both fields MISSING (structure unknown, never '')."""
    field = f"neighbor_table_{proto.lower()}"
    count = f"neighbor_count_{proto.lower()}"
    if table is None:
        return [obs_missing(parser, raw_id, field),
                obs_missing(parser, raw_id, count)]
    return [obs_ok(parser, raw_id, field, table),
            obs_ok(parser, raw_id, count, len(table))]


_KV = re.compile(r"^\s*(?P<k>[A-Za-z][A-Za-z0-9 _\-.]*?)\s*:\s*(?P<v>.*?)\s*$")


_KEY_LINE = re.compile(r"^\S[^:]{0,40}:\s")


def _system_description(block: str) -> Optional[str]:
    """The platform string a neighbour advertised about itself.

    In ``show lldp neighbors detail`` the value of ``System Description:`` sits
    on the FOLLOWING line, which a line-based key/value scan drops. That string
    is the only vendor evidence LLDP carries: with CDP disabled — a routine
    hardening step, ``no cdp run`` — it is the difference between a neighbour
    the platform can crawl and one it silently gives up on.
    """
    m = re.search(r"(?im)^System Description:[ \t]*(.*)$", block)
    if not m:
        return None
    inline = m.group(1).strip()
    if inline:
        return inline
    for line in block[m.end():].splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # An empty description must not swallow the next record's key line.
        if _KEY_LINE.match(stripped):
            return None
        return stripped
    return None


def _kv_pairs(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        m = _KV.match(line)
        if m:
            out.append((m.group("k").strip().lower(), m.group("v").strip()))
    return out


# ---------------------------------------------------------------- cisco ios-xe
class CiscoIosXeLldpNeighborsDetailParser(Parser):
    """``show lldp neighbors detail`` — block records anchored by 'Local Intf:'.

    Block delimiters are the dashed separators; each block contributes one
    entry keyed on the mandatory anchor; partial blocks keep typed None
    fields rather than being dropped silently.
    """

    info = ParserInfo(
        parser_id="regex/cisco_iosxe_show_lldp_neighbors_detail",
        version="1.0.0",
        vendor_family="cisco/ios-xe",
        command_ref="show lldp neighbors detail",
    )

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        text = raw.decode("utf-8", errors="replace")
        if not re.search(r"(?im)^local intf\s*:", text):
            return _emit(self, raw_id, None, "LLDP")
        blocks = re.split(r"(?m)^-{5,}\s*$", text)
        table: list[dict] = []
        for block in blocks:
            pairs = _kv_pairs(block)
            if not pairs:
                continue
            kvs: dict[str, list[str]] = {}
            for k, v in pairs:
                kvs.setdefault(k, []).append(v)
            if not kvs.get("local intf"):
                continue
            mgmt: Optional[str] = None
            # 'Management Addresses' block lines look like 'IP: 10.0.0.2'.
            mgmt_block = re.search(r"Management Addresses:\s*\n\s*IP:\s*(\S+)", block)
            if mgmt_block:
                mgmt = mgmt_block.group(1)
            table.append(_entry(
                "LLDP",
                local_intf=kvs.get("local intf", [None])[0] or None,
                neighbor_id=kvs.get("system name", [None])[0] or None,
                neighbor_intf=kvs.get("port id", [None])[0] or None,
                chassis_id=kvs.get("chassis id", [None])[0] or None,
                mgmt_address=mgmt,
                platform=_system_description(block),
            ))
        return _emit(self, raw_id, table, "LLDP")


class CiscoIosXeCdpNeighborsDetailParser(Parser):
    """``show cdp neighbors detail`` — block records anchored by 'Device ID:'."""

    info = ParserInfo(
        parser_id="regex/cisco_iosxe_show_cdp_neighbors_detail",
        version="1.0.0",
        vendor_family="cisco/ios-xe",
        command_ref="show cdp neighbors detail",
    )

    _IFACE = re.compile(
        r"(?im)^Interface:\s*(?P<local>\S+),\s*Port ID \(outgoing port\):\s*(?P<remote>\S+)\s*$")
    _PLATFORM = re.compile(r"(?im)^Platform:\s*(?P<p>[^,]+),")

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        text = raw.decode("utf-8", errors="replace")
        if not re.search(r"(?im)^device id\s*:", text):
            return _emit(self, raw_id, None, "CDP")
        blocks = re.split(r"(?m)^-{5,}\s*$", text)
        table: list[dict] = []
        for block in blocks:
            device = re.search(r"(?im)^Device ID:\s*(\S+)\s*$", block)
            if not device:
                continue
            iface = self._IFACE.search(block)
            platform = self._PLATFORM.search(block)
            ip = re.search(r"(?im)^\s*IP(?:v4)? address:\s*(\S+)\s*$", block)
            table.append(_entry(
                "CDP",
                local_intf=iface.group("local") if iface else None,
                neighbor_id=device.group(1),
                neighbor_intf=iface.group("remote") if iface else None,
                mgmt_address=ip.group(1) if ip else None,
                platform=platform.group("p").strip() if platform else None,
            ))
        return _emit(self, raw_id, table, "CDP")


# ------------------------------------------------------------------------ junos
class JunosLldpNeighborsParser(Parser):
    """``show lldp neighbors`` — fixed table with header line, empty = header only."""

    info = ParserInfo(
        parser_id="regex/junos_show_lldp_neighbors",
        version="1.0.0",
        vendor_family="juniper/junos",
        command_ref="show lldp neighbors",
    )

    _ROW = re.compile(
        r"^(?P<local>\S+)\s+(?P<parent>\S+)\s+(?P<chassis>\S+)\s+(?P<port>.+?)\s{2,}(?P<name>\S+)\s*$")

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        text = raw.decode("utf-8", errors="replace")
        if "Local Interface" not in text or "Chassis Id" not in text or "System Name" not in text:
            return _emit(self, raw_id, None, "LLDP")
        table: list[dict] = []
        seen_header = False
        for line in text.splitlines():
            if not seen_header:
                if line.lstrip().startswith("Local Interface"):
                    seen_header = True
                continue
            if not line.strip():
                continue
            m = self._ROW.match(line.strip())
            if m:
                table.append(_entry(
                    "LLDP",
                    local_intf=m.group("local"),
                    neighbor_id=m.group("name"),
                    neighbor_intf=m.group("port").strip(),
                    chassis_id=None if m.group("chassis") == "-" else m.group("chassis"),
                ))
            else:  # row shape broke: structure is not what the header promised
                return _emit(self, raw_id, None, "LLDP")
        return _emit(self, raw_id, table, "LLDP")


# --------------------------------------------------------------------- routeros
class RouterOsIpNeighborPrintParser(Parser):
    """``/ip neighbor/print`` — MNDP table; columnar v7 rows and key=value rows.

    Columnar rows: ``# INTERFACE ADDRESS MAC-ADDRESS IDENTITY PLATFORM ...``.
    Detail rows: ``interface=ether1 address=.. mac-address=.. identity=..``.
    Row numbers may carry flag letters glued to them ('0 D'); handled.
    """

    info = ParserInfo(
        parser_id="regex/routeros_ip_neighbor_print",
        version="1.0.0",
        vendor_family="mikrotik/routeros",
        command_ref="/ip neighbor/print",
    )

    _MAC = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
    _ROW = re.compile(
        rf"^\s*\d+(?:\s+[A-Za-z]+)*\s+(?P<intf>\S+)\s+(?P<addr>\S+)\s+(?P<mac>{_MAC})\s+"
        rf"(?P<ident>\S+)\s+(?P<platform>\S+)")
    _KVROW = re.compile(
        rf"interface=(?P<intf>\S+).*?address=(?P<addr>\S+).*?mac-address=(?P<mac>{_MAC})"
        rf".*?identity=(?P<ident>\"[^\"]*\"|\S+)(?:.*?platform=(?P<platform>\"[^\"]*\"|\S+))?")

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        text = raw.decode("utf-8", errors="replace")
        has_columnar = "MAC-ADDRESS" in text.upper()
        has_kv = "mac-address=" in text
        if not has_columnar and not has_kv:
            return _emit(self, raw_id, None, "MNDP")
        table: list[dict] = []
        for line in text.splitlines():
            m = self._KVROW.search(line)
            if m:
                table.append(_entry(
                    "MNDP",
                    local_intf=m.group("intf"),
                    neighbor_id=m.group("ident").strip('"'),
                    neighbor_intf=None,  # MNDP does not advertise the remote port (typed absence)
                    chassis_id=m.group("mac"),
                    mgmt_address=m.group("addr"),
                    platform=(m.group("platform") or "").strip('"') or None,
                ))
                continue
            m = self._ROW.match(line.rstrip("\r\n"))
            if m:
                table.append(_entry(
                    "MNDP",
                    local_intf=m.group("intf"),
                    neighbor_id=m.group("ident"),
                    neighbor_intf=None,
                    chassis_id=m.group("mac"),
                    mgmt_address=m.group("addr"),
                    platform=m.group("platform"),
                ))
        return _emit(self, raw_id, table, "MNDP")


# ---------------------------------------------------------------------- arubaos
class ArubaOsLldpNeighborsParser(Parser):
    """``show lldp neighbors`` (AOS-CX / controller): 'Local Port' anchored blocks."""

    info = ParserInfo(
        parser_id="regex/arubaos_show_lldp_neighbors",
        version="1.0.0",
        vendor_family="aruba/arubaos",
        command_ref="show lldp neighbors",
    )

    _ANCHOR = re.compile(r"(?im)^Local Port\s*:\s*(?P<lp>\S+)\s*$")
    _KVMAP = (
        ("neighbor chassis-name", "neighbor_id"),
        ("neighbor chassis-id", "chassis_id"),
        ("neighbor management-address", "mgmt_address"),
        ("neighbor port-id", "neighbor_intf"),
    )

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        text = raw.decode("utf-8", errors="replace")
        if "Local Port" not in text and "Neighbor Entries" not in text:
            return _emit(self, raw_id, None, "LLDP")
        anchors = list(self._ANCHOR.finditer(text))
        table: list[dict] = []
        for i, anchor in enumerate(anchors):
            end = anchors[i + 1].start() if i + 1 < len(anchors) else len(text)
            block = text[anchor.start():end]
            fields: dict[str, Optional[str]] = {v: None for _, v in self._KVMAP}
            for key, value in _kv_pairs(block):
                for prefix, dest in self._KVMAP:
                    if key.startswith(prefix):
                        fields[dest] = fields.get(dest) or value or None
            table.append(_entry(
                "LLDP",
                local_intf=anchor.group("lp"),
                neighbor_id=fields["neighbor_id"],
                neighbor_intf=fields["neighbor_intf"],
                chassis_id=fields["chassis_id"],
                mgmt_address=fields["mgmt_address"],
            ))
        return _emit(self, raw_id, table, "LLDP")


# ----------------------------------------------------------------------- fortios
class FortiOsLldpNeighborsParser(Parser):
    """``get system lldp neighbors`` — blocks introduced by '== entry:' lines.

    Representation note: this fixture shape is synthetic-representative
    (register OI-0172) pending a lab capture; the parser is deliberately
    tolerant of key spelling (Chassis ID / chassis id, Port ID / port id).
    """

    info = ParserInfo(
        parser_id="regex/fortios_get_system_lldp_neighbors",
        version="1.0.0",
        vendor_family="fortinet/fortios",
        command_ref="get system lldp neighbors",
    )

    _HEAD = re.compile(r"(?im)^==\s*entry:\s*(?P<lp>\S+)")
    _KVMAP = (
        ("chassis id", "chassis_id"),
        ("system name", "neighbor_id"),
        ("port id", "neighbor_intf"),
        ("management address", "mgmt_address"),
        ("platform", "platform"),
    )

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        text = raw.decode("utf-8", errors="replace")
        if "chassis id" not in text.lower() and "== entry:" not in text.lower():
            return _emit(self, raw_id, None, "LLDP")
        heads = list(self._HEAD.finditer(text))
        if not heads:
            return _emit(self, raw_id, None, "LLDP")
        table: list[dict] = []
        for i, head in enumerate(heads):
            end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
            block = text[head.start():end]
            fields: dict[str, Optional[str]] = {v: None for _, v in self._KVMAP}
            for key, value in _kv_pairs(block):
                for prefix, dest in self._KVMAP:
                    if key == prefix:
                        fields[dest] = fields.get(dest) or value or None
            table.append(_entry(
                "LLDP",
                local_intf=head.group("lp"),
                neighbor_id=fields["neighbor_id"],
                neighbor_intf=fields["neighbor_intf"],
                chassis_id=fields["chassis_id"],
                mgmt_address=fields["mgmt_address"],
                platform=fields["platform"],
            ))
        return _emit(self, raw_id, table, "LLDP")


# ------------------------------------------------------------------------ unifi
class UnifiLldpTableParser(Parser):
    """UniFi ``api:/stat/device`` — LLDP table embedded in the controller JSON.

    The controller is the evidence origin; every wired lldp_table row across
    the answering devices becomes one entry (device scope is supplied by the
    caller via the collection event, exactly like the device JSON parser).
    """

    info = ParserInfo(
        parser_id="json/unifi_lldp_table",
        version="1.0.0",
        vendor_family="ubiquiti/unifi",
        command_ref="api:/stat/device",
    )

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        try:
            doc = json.loads(raw.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError):
            return _emit(self, raw_id, None, "LLDP")
        data = doc.get("data") if isinstance(doc, dict) else None
        if not isinstance(data, list):
            return _emit(self, raw_id, None, "LLDP")
        table: list[dict] = []
        for device in data:
            if not isinstance(device, dict):
                continue
            rows = device.get("lldp_table")
            if rows is None:
                continue  # device has no lldp table: typed absence (no rows ≠ unknown)
            if not isinstance(rows, list):
                return _emit(self, raw_id, None, "LLDP")
            for row in rows:
                if not isinstance(row, dict) or row.get("lldp_id") is None and row.get("chassis_id") is None:
                    continue
                local = row.get("local_port_name") or (
                    f"port{row.get('local_port_idx')}" if row.get("local_port_idx") is not None else None)
                table.append(_entry(
                    "LLDP",
                    local_intf=local,
                    neighbor_id=row.get("lldp_system_name") or row.get("lldp_hostname"),
                    neighbor_intf=row.get("lldp_port_desc") or row.get("port_id"),
                    chassis_id=row.get("chassis_id"),
                    mgmt_address=row.get("lldp_mgmt_address") or row.get("mgmt_address"),
                ))
        return _emit(self, raw_id, table, "LLDP")


#: Builders in fixed registry order (catalog determinism).
NEIGHBOR_CATALOG_BUILDERS = (
    CiscoIosXeLldpNeighborsDetailParser,
    CiscoIosXeCdpNeighborsDetailParser,
    JunosLldpNeighborsParser,
    RouterOsIpNeighborPrintParser,
    ArubaOsLldpNeighborsParser,
    FortiOsLldpNeighborsParser,
    UnifiLldpTableParser,
)
