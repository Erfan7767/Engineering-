"""Deterministic parsers for the remaining v1 vendor surfaces.

Golden fixtures back each parser (§21 parser tier). Fixture provenance is
declared in the corresponding ``*.expected.json`` (synthetic-representative
seeds until replaced by lab captures — register items OI-0131…OI-0134).

Rules everywhere: matched field ⇒ OK observation with the captured value;
unmatched field ⇒ MISSING (never guessed, L01); undecodable payload ⇒
PARSE_FAILED for every declared field (L03).
"""

from __future__ import annotations

import json
import re

from ..ledger.models import Observation
from .registry import Parser, ParserInfo, obs_missing, obs_ok


class RegexLineParser(Parser):
    """Shared engine: exact regex per declared field, multiline input."""

    def __init__(self, info: ParserInfo, fields: tuple[tuple[str, re.Pattern], ...]) -> None:
        self.info = info
        self._fields = fields

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        text = raw.decode("utf-8", errors="replace")
        out: list[Observation] = []
        for field, pattern in self._fields:
            m = pattern.search(text)
            if m:
                out.append(obs_ok(self, raw_id, field, next(iter(m.groupdict().values()))))
            else:
                out.append(obs_missing(self, raw_id, field))
        return out


def junos_show_version() -> Parser:
    return RegexLineParser(
        ParserInfo("regex/junos_show_version", "1.0.0", "juniper/junos", "show version"),
        (
            ("hostname", re.compile(r"^Hostname: (?P<v>\S+)\s*$", re.M)),
            ("model", re.compile(r"^Model: (?P<v>\S+)\s*$", re.M)),
            ("serial", re.compile(r"^Serial number: (?P<v>\S+)\s*$", re.M)),
            ("junos_version", re.compile(r"^Junos: (?P<v>\S+)\s*$", re.M)),
        ),
    )


def fortios_get_system_status() -> Parser:
    return RegexLineParser(
        ParserInfo("regex/fortios_get_system_status", "1.0.0", "fortinet/fortios", "get system status"),
        (
            ("version", re.compile(r"^Version: (?P<v>.+?)\s*$", re.M)),
            ("serial", re.compile(r"^Serial-Number: (?P<v>\S+)\s*$", re.M)),
            ("model", re.compile(r"^Model name: (?P<v>.+?)\s*$", re.M)),
            ("uptime", re.compile(r"^Uptime: (?P<v>.+?)\s*$", re.M)),
        ),
    )


def arubaos_show_version() -> Parser:
    return RegexLineParser(
        ParserInfo("regex/arubaos_show_version", "1.0.0", "aruba/arubaos", "show version"),
        (
            ("model", re.compile(r"^ArubaOS \(MODEL: (?P<v>[^),]+)\)", re.M)),
            ("version", re.compile(r"\), Version (?P<v>[0-9][0-9A-Za-z.\-]*)\s*$", re.M)),
            ("rom", re.compile(r"^ROM: (?P<v>\S+)\s*$", re.M)),
        ),
    )


class UnifiDeviceJsonParser(Parser):
    """UniFi controller ``api:/stat/device`` response (JSON).

    Per-device observations are indexed: ``device[i].<field>``. Any payload
    that is not a JSON object with ``meta.rc == "ok"`` and a ``data`` list
    yields PARSE_FAILED observations — controller error envelopes are never
    interpreted as device facts.
    """

    info = ParserInfo("json/unifi_stat_device", "1.0.0", "ubiquiti/unifi", "api:/stat/device")
    DEVICE_FIELDS: tuple[str, ...] = ("model", "serial", "version", "type", "state", "adopted", "mac", "ip")

    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        try:
            doc = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return [
                Observation(raw_id=raw_id, parser_id=self.info.parser_id,
                            parser_version=self.info.version, field="_payload",
                            parse_status="PARSE_FAILED")
            ]
        if not isinstance(doc, dict) or doc.get("meta", {}).get("rc") != "ok" or not isinstance(doc.get("data"), list):
            return [
                Observation(raw_id=raw_id, parser_id=self.info.parser_id,
                            parser_version=self.info.version, field="_envelope",
                            parse_status="PARSE_FAILED")
            ]
        out: list[Observation] = []
        for i, device in enumerate(doc["data"]):
            if not isinstance(device, dict):
                continue
            for field in self.DEVICE_FIELDS:
                name = f"device[{i}].{field}"
                if field in device:
                    out.append(obs_ok(self, raw_id, name, device[field]))
                else:
                    out.append(obs_missing(self, raw_id, name))
        return out
