"""BGP RPKI / ROA Validation Engine.

A 30-year engineer runs RPKI to validate BGP prefixes
against ROAs (Route Origin Authorizations). A prefix
marked ``invalid`` should not be accepted. This module is
the typed implementation: take a list of (prefix, asn,
rpki_state) tuples, surface typed :class:`RpkiValidation`
records and a typed :class:`RpkiReport` with findings.

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RpkiState(str, Enum):
    __test__ = False

    VALID = "valid"
    INVALID = "invalid"
    NOT_FOUND = "not-found"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RpkiValidation:
    __test__ = False

    prefix: str
    origin_asn: int
    state: RpkiState = RpkiState.UNKNOWN

    @property
    def is_invalid(self) -> bool:
        return self.state == RpkiState.INVALID


@dataclass
class RpkiReport:
    __test__ = False

    validations: list[RpkiValidation] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.validations)

    @property
    def valid_count(self) -> int:
        return sum(
            1 for v in self.validations
            if v.state == RpkiState.VALID
        )

    @property
    def invalid_count(self) -> int:
        return sum(
            1 for v in self.validations
            if v.state == RpkiState.INVALID
        )

    @property
    def not_found_count(self) -> int:
        return sum(
            1 for v in self.validations
            if v.state == RpkiState.NOT_FOUND
        )

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"RPKI: {self.valid_count} صالح، "
                f"{self.invalid_count} غير صالح، "
                f"{self.not_found_count} غير موجود"
            )
        return (
            f"RPKI: {self.valid_count} valid, "
            f"{self.invalid_count} invalid, "
            f"{self.not_found_count} not-found"
        )


def evaluate(
    validations: list[RpkiValidation],
) -> RpkiReport:
    """Build a typed :class:`RpkiReport`."""
    return RpkiReport(validations=list(validations))
