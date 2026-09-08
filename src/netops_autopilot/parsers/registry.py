"""Parser registry + base contract.

Parsers are registered by ``(parser_id, version)``; re-parsing with a newer
version produces NEW observations referencing the same RawArtifact and
marks old ones superseded (D0-04 §1) — the store-level supersede link is
maintained by the caller (engine) via ``Observation.superseded_by``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..ledger.models import Observation, ParseStatus


@dataclass(frozen=True)
class ParserInfo:
    parser_id: str
    version: str
    vendor_family: str
    command_ref: str


class Parser(ABC):
    """Deterministic raw-bytes → Observations."""

    info: ParserInfo

    @abstractmethod
    def parse(self, raw: bytes, raw_id: str) -> list[Observation]:
        """Return observations. Must never raise on malformed input:
        field-level problems are PARSE_FAILED/MISSING observations (L03)."""


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers: dict[tuple[str, str], Parser] = {}

    def register(self, parser: Parser) -> None:
        key = (parser.info.parser_id, parser.info.version)
        if key in self._parsers:
            raise ValueError(f"parser already registered: {key}")
        self._parsers[key] = parser

    def get(self, parser_id: str, version: str) -> Parser:
        try:
            return self._parsers[(parser_id, version)]
        except KeyError:
            raise KeyError(f"parser not registered: {(parser_id, version)}") from None

    def latest(self, parser_id: str) -> Parser:
        versions = sorted((v for (pid, v) in self._parsers if pid == parser_id), key=_version_key)
        if not versions:
            raise KeyError(f"no parser registered for {parser_id!r}")
        return self._parsers[(parser_id, versions[-1])]


def _version_key(v: str) -> tuple[int, ...]:
    return tuple(int(part) for part in v.split("."))


def obs_ok(parser: Parser, raw_id: str, field: str, value) -> Observation:
    return Observation(
        raw_id=raw_id, parser_id=parser.info.parser_id,
        parser_version=parser.info.version, field=field, value=value,
        parse_status=ParseStatus.OK,
    )


def obs_missing(parser: Parser, raw_id: str, field: str) -> Observation:
    return Observation(
        raw_id=raw_id, parser_id=parser.info.parser_id,
        parser_version=parser.info.version, field=field,
        parse_status=ParseStatus.MISSING,
    )
