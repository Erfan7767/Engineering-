"""Deterministic parser: Cisco IOS-XE ``show version``.

Field patterns are exact-line regexes; any field that does not match is a
MISSING observation (never guessed, L01). This parser backs the
DEVICE_IDENTITY claims of FSM-1 guard 1.3 together with ``show inventory``.
"""

from __future__ import annotations

import re

from ..ledger.models import Observation
from .registry import Parser, ParserInfo, obs_missing, obs_ok

_FIELDS: tuple[tuple[str, re.Pattern], ...] = (
    ("version", re.compile(r"^Cisco IOS XE Software, Version (?P<v>\S+)\s*$", re.M)),
    ("image_family", re.compile(r"^Cisco IOS Software \[(?P<f>[A-Za-z0-9_]+)\]", re.M)),
    ("model", re.compile(r"^cisco (?P<m>\S+) .*processor", re.M | re.I)),
    ("uptime", re.compile(r"^.* uptime is (?P<u>.+?)\s*$", re.M)),
    ("serial", re.compile(r"^System serial number\s*:\s*(?P<s>\S+)\s*$", re.M)),
    ("config_register", re.compile(r"^Configuration register is (?P<r>0x[0-9A-Fa-f]+)\s*$", re.M)),
)


class CiscoIosXeShowVersionParser(Parser):
    info = ParserInfo(
        parser_id="regex/cisco_iosxe_show_version",
        version="1.0.0",
        vendor_family="cisco/ios-xe",
        command_ref="show version",
    )

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        text = raw.decode("utf-8", errors="replace")
        out: list[Observation] = []
        for field, pattern in _FIELDS:
            m = pattern.search(text)
            if m:
                value = next(iter(m.groupdict().values()))
                out.append(obs_ok(self, raw_id, field, value))
            else:
                out.append(obs_missing(self, raw_id, field))
        return out
