"""Deterministic parser: Cisco IOS-XE ``show interfaces status``.

The L1/L2 port inventory of a switch. This is the evidence the Design Engine
needs to assign **end-user access ports** — without it the only ports the
platform can name are the ones that appear in a neighbour table, and those are
exactly the ports it must reserve for infrastructure. The result was a design
that created VLANs and gateways but never plugged a single user in.

Field rules (L01 — never guess):

* The header line anchors the parse. No header ⇒ the table structure is
  unknown ⇒ both fields are MISSING, never an empty table. An empty table and
  an unreadable one are different facts and must not be conflated.
* A row is only accepted when its port column is non-empty and the column
  count matches the header. A wrapped or truncated line is skipped rather
  than partially interpreted.
* ``vlan`` is the string the device printed: an id, ``trunk``, ``routed``,
  ``unassigned`` or ``*``. It is passed through verbatim; deciding what it
  means is the Design Engine's job, not the parser's.
"""

from __future__ import annotations

import re
from typing import Optional

from ..ledger.models import Observation
from .registry import Parser, ParserInfo, obs_missing, obs_ok

#: Fixed key set of every inventory row (explicit absence = None).
ROW_KEYS: tuple[str, ...] = (
    "port", "status", "vlan", "duplex", "speed", "type",
)

_HEADER = re.compile(
    r"^(?P<port>Port)\s+(?P<status>Status)\s+(?P<vlan>Vlan)\s+"
    r"(?P<duplex>Duplex)\s+(?P<speed>Speed)\s+(?P<type>Type)\s*$", re.I)


def _emit(parser: Parser, raw_id: str,
          table: Optional[list[dict]]) -> list[Observation]:
    if table is None:
        return [obs_missing(parser, raw_id, "interface_table"),
                obs_missing(parser, raw_id, "interface_count")]
    return [obs_ok(parser, raw_id, "interface_table", table),
            obs_ok(parser, raw_id, "interface_count", len(table))]


_COL_NAMES = ("port", "status", "vlan", "duplex", "speed", "type")


def _column_spans(match: "re.Match[str]") -> list[tuple[int, int]]:
    """Column boundaries from a header match.

    A column runs from the start of its header word to the start of the next
    one — NOT for the length of the header word. Data is wider than the
    headings (``Gi1/0/10`` under ``Port``, ``notconnect`` under ``Status``), so
    using the word length truncates every value. The last column runs to end
    of line because ``Type`` may itself contain spaces (``10/100/1000BaseTX``).
    """
    starts = [match.start(name) for name in _COL_NAMES]
    spans: list[tuple[int, int]] = [(starts[i], starts[i + 1])
                                    for i in range(len(starts) - 1)]
    # ``None`` = run to the end of whichever DATA line is being split. The
    # header is shorter than the rows (``Type`` holds ``10/100/1000BaseTX``),
    # so bounding the last column by the header truncates every value.
    spans.append((starts[-1], -1))
    return spans


def _split_row(line: str, spans: list[tuple[int, int]]) -> list[str]:
    """Split a data row using the header's column spans.

    Positional splitting is the only reliable method here: ``str.split()``
    would shatter the ``Type`` field, and the columns are not separated by a
    single delimiter.
    """
    return [(line[start:] if end < 0 else line[start:end]).strip()
            for start, end in spans]


class CiscoIosXeInterfacesStatusParser(Parser):
    """``show interfaces status`` → ``interface_table`` + ``interface_count``."""

    info = ParserInfo(
        parser_id="regex/cisco_iosxe_show_interfaces_status",
        version="1.0.0",
        vendor_family="cisco/ios-xe",
        command_ref="show interfaces status",
    )

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()

        header_index: Optional[int] = None
        spans: list[tuple[int, int]] = []
        for index, line in enumerate(lines):
            match = _HEADER.match(line.rstrip())
            if match:
                header_index = index
                spans = _column_spans(match)
                break
        if header_index is None:
            # No header ⇒ unknown structure. Never an empty table.
            return _emit(self, raw_id, None)

        table: list[dict] = []
        for line in lines[header_index + 1:]:
            if not line.strip():
                continue
            # A new header (paginated output) restarts the spans.
            rematch = _HEADER.match(line.rstrip())
            if rematch:
                spans = _column_spans(rematch)
                continue
            cells = _split_row(line, spans)
            if len(cells) < len(ROW_KEYS):
                continue                      # wrapped/truncated: skip, never guess
            row = dict(zip(ROW_KEYS, cells))
            if not row["port"]:
                continue
            # Explicit absence, never '': an unpopulated column is None.
            table.append({k: (v if v else None) for k, v in row.items()})
        return _emit(self, raw_id, table)
