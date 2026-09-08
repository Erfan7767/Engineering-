"""Deterministic key-value line parser.

Handles ``key: value`` output with arbitrary leading whitespace (RouterOS
``print detail`` style, and similar CLI surfaces). Keys may contain
letters, digits, dashes and dots. Lines that don't match are ignored but
counted, so structural surprises are observable, not silent.
"""

from __future__ import annotations

import re

from ..ledger.models import Observation, ParseStatus
from .registry import Parser, ParserInfo, obs_missing, obs_ok

_KV_RE = re.compile(r"^\s*(?P<key>[A-Za-z0-9._-]+)\s*:\s*(?P<value>.+?)\s*$")


class KeyValueParser(Parser):
    """Extract a declared field set from key-value text.

    Declared fields absent from the output become MISSING observations
    (T2); unknown lines are counted in a ``_unparsed_lines`` observation
    only when non-zero (auditability without noise).
    """

    def __init__(self, parser_id: str, version: str, vendor_family: str, command_ref: str, fields: tuple[str, ...]) -> None:
        self.info = ParserInfo(parser_id=parser_id, version=version, vendor_family=vendor_family, command_ref=command_ref)
        self._fields = tuple(fields)

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            # Binary/garbage payload: every declared field is PARSE_FAILED.
            return [
                Observation(
                    raw_id=raw_id, parser_id=self.info.parser_id,
                    parser_version=self.info.version, field=f,
                    parse_status=ParseStatus.PARSE_FAILED,
                )
                for f in self._fields
            ]

        found: dict[str, str] = {}
        unparsed = 0
        for line in text.splitlines():
            if not line.strip():
                continue
            m = _KV_RE.match(line)
            if m:
                found[m.group("key")] = m.group("value")
            else:
                unparsed += 1

        out: list[Observation] = []
        for field in self._fields:
            if field in found:
                out.append(obs_ok(self, raw_id, field, found[field]))
            else:
                out.append(obs_missing(self, raw_id, field))
        if unparsed:
            out.append(obs_ok(self, raw_id, "_unparsed_lines", unparsed))
        return out


def routeros_system_resource() -> KeyValueParser:
    """Golden parser for ``/system/resource/print`` (fixture-backed)."""
    return KeyValueParser(
        parser_id="keyvalue/routeros_system_resource_print",
        version="1.0.0",
        vendor_family="mikrotik/routeros",
        command_ref="/system/resource/print",
        fields=("uptime", "version", "build-time", "cpu", "board-name"),
    )
