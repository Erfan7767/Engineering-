"""Network Blueprints + deterministic intent elicitation.

The human answers "what kind of network do you want?" in free text (Arabic
or English). Elicitation is a DETERMINISTIC keyword table over curated
blueprints — there is NO scoring fuzz and NO guessing: zero hits ⇒
UNKNOWN (asking again with the menu), two+ hits ⇒ BLOCKED with a
disambiguation question (T2). Everything downstream is then compiled by
the existing Intent Compiler (E08) — blueprints emit its request shape,
never bypass it.

Six v1 blueprints, each data-only (zones, default sizes per zone class,
features). Sizes the blueprint cannot infer become blocking parameters —
the elicitation returns them as questions, exactly like the compiler does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .intent_compiler import BusinessIntentRequest, Zone, ZoneKind


@dataclass(frozen=True)
class Blueprint:
    blueprint_id: str
    title_en: str
    zones: tuple[Zone, ...]
    guest_isolation: bool
    dot1x_required: bool
    uses_certificates: bool
    default_host_sizes: dict[str, int]   # zone name → host count
    required_parameters: tuple[str, ...]  # blocking answers still needed


def _z(name: str, kind: ZoneKind) -> Zone:
    return Zone(name=name, kind=kind)


#: The v1 catalog. Order defines menu order (deterministic).
BLUEPRINTS: tuple[Blueprint, ...] = (
    Blueprint(
        blueprint_id="small_office",
        title_en="Small office (single site, few switches)",
        zones=(_z("users", ZoneKind.INTERNAL), _z("mgmt", ZoneKind.MGMT), _z("wan", ZoneKind.WAN)),
        guest_isolation=False, dot1x_required=False, uses_certificates=False,
        default_host_sizes={"users": 48, "mgmt": 8, "wan": 4},
        required_parameters=("wan_handoff",),
    ),
    Blueprint(
        blueprint_id="guest_office",
        title_en="Office with isolated guest Wi-Fi/zone",
        zones=(_z("users", ZoneKind.INTERNAL), _z("guest", ZoneKind.GUEST),
               _z("mgmt", ZoneKind.MGMT), _z("wan", ZoneKind.WAN)),
        guest_isolation=True, dot1x_required=False, uses_certificates=False,
        default_host_sizes={"users": 48, "guest": 32, "mgmt": 8, "wan": 4},
        required_parameters=("wan_handoff",),
    ),
    Blueprint(
        blueprint_id="branch",
        title_en="Branch site behind an upstream core (users + VoIP + mgmt)",
        zones=(_z("users", ZoneKind.INTERNAL), _z("voice", ZoneKind.INTERNAL),
               _z("mgmt", ZoneKind.MGMT), _z("wan", ZoneKind.WAN)),
        guest_isolation=False, dot1x_required=False, uses_certificates=False,
        default_host_sizes={"users": 96, "voice": 48, "mgmt": 12, "wan": 4},
        required_parameters=("wan_handoff",),
    ),
    Blueprint(
        blueprint_id="campus",
        title_en="Campus / HQ (users + servers in DMZ + optional 802.1X)",
        zones=(_z("users", ZoneKind.INTERNAL), _z("servers", ZoneKind.DMZ),
               _z("guest", ZoneKind.GUEST), _z("mgmt", ZoneKind.MGMT), _z("wan", ZoneKind.WAN)),
        guest_isolation=True, dot1x_required=False, uses_certificates=False,
        default_host_sizes={"users": 400, "servers": 32, "guest": 128, "mgmt": 32, "wan": 4},
        required_parameters=("wan_handoff",),
    ),
    Blueprint(
        blueprint_id="datacenter",
        title_en="Small data-center pod (server segments + mgmt, no guest)",
        zones=(_z("servers", ZoneKind.DMZ), _z("app", ZoneKind.INTERNAL),
               _z("mgmt", ZoneKind.MGMT), _z("wan", ZoneKind.WAN)),
        guest_isolation=False, dot1x_required=False, uses_certificates=False,
        default_host_sizes={"servers": 128, "app": 64, "mgmt": 24, "wan": 4},
        required_parameters=("wan_handoff",),
    ),
    Blueprint(
        blueprint_id="secure_office",
        title_en="Office with 802.1X port authentication (+certificates)",
        zones=(_z("users", ZoneKind.INTERNAL), _z("guest", ZoneKind.GUEST),
               _z("mgmt", ZoneKind.MGMT), _z("wan", ZoneKind.WAN)),
        guest_isolation=True, dot1x_required=True, uses_certificates=True,
        default_host_sizes={"users": 96, "guest": 32, "mgmt": 16, "wan": 4},
        required_parameters=("wan_handoff", "availability"),
    ),
)

_BY_ID = {b.blueprint_id: b for b in BLUEPRINTS}

# ---------------------------------------------------------------- elicitation
@dataclass(frozen=True)
class ElicitationResult:
    status: str                              # MATCHED | BLOCKED | UNKNOWN
    blueprint: Optional[Blueprint] = None
    matched_keyword: Optional[str] = None
    candidates: tuple[str, ...] = ()         # for BLOCKED
    question: Optional[str] = None           # what to ask the human next


#: keyword → blueprint id. Curated, bilingual; every keyword is unambiguous
#: BY CONSTRUCTION (a keyword may map to exactly one blueprint).
_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("small office", "small_office"), ("مكتب صغير", "small_office"),
    ("small business", "small_office"), ("شركة صغيرة", "small_office"),
    ("guest", "guest_office"), ("ضيوف", "guest_office"), ("ضيف", "guest_office"),
    ("guest wifi", "guest_office"), ("واي فاي ضيوف", "guest_office"),
    ("branch", "branch"), ("فرع", "branch"), ("مكتب فرعي", "branch"),
    ("campus", "campus"), ("حرم", "campus"), ("مقر رئيسي", "campus"),
    ("headquarters", "campus"), ("hq", "campus"), ("جامعة", "campus"),
    ("data center", "datacenter"), ("datacenter", "datacenter"),
    ("مركز بيانات", "datacenter"), ("سيرفرات", "datacenter"), ("خوادم", "datacenter"),
    ("server room", "datacenter"), ("غرفة خوادم", "datacenter"),
    ("802.1x", "secure_office"), ("dot1x", "secure_office"),
    ("مصادقة", "secure_office"), ("شهادات", "secure_office"),
)
#: Guard against catastrophic ambiguity: these bigrams flip nothing alone.
_GUEST_ISOLATION_HINTS = ("isolated", "isolation", "معزولة", "عزل")


def menu() -> str:
    lines = ["Available network blueprints (choose by id or describe in words):"]
    for i, bp in enumerate(BLUEPRINTS, 1):
        lines.append(f"  {i}. {bp.blueprint_id:<14} — {bp.title_en}")
    return "\n".join(lines)


def _text_hits(text: str) -> list[tuple[str, str]]:
    """All (keyword, blueprint_id) hits of the normalized text, keyword-desc."""
    folded = " ".join(text.lower().split())
    hits: list[tuple[str, str]] = []
    for keyword, bp_id in sorted(_KEYWORDS, key=lambda kv: -len(kv[0])):
        # phrase containment with word-ish boundaries (regex-escaped phrase).
        pattern = r"(?<![\w])" + re.escape(keyword) + r"(?![\w])"
        if re.search(pattern, folded):
            hits.append((keyword, bp_id))
    return hits


def elicit(answer_text: str) -> ElicitationResult:
    """Deterministic classification of the human's free-text answer.

    * exact blueprint id match (or menu number) wins immediately;
    * no keyword ⇒ UNKNOWN (never default to the first blueprint);
    * distinct blueprint hits >1 after precedence filtering ⇒ BLOCKED with
      a disambiguation question listing only the surviving candidates.
    """
    text = " ".join(answer_text.strip().split())
    folded = text.lower()
    if not folded:
        return ElicitationResult(status="UNKNOWN", question=menu())

    # 1. Direct id or menu index.
    for bp in BLUEPRINTS:
        if folded == bp.blueprint_id or folded == bp.blueprint_id.replace("_", " "):
            return ElicitationResult(status="MATCHED", blueprint=bp, matched_keyword=bp.blueprint_id)
    numbers = re.fullmatch(r"\d{1,2}", folded)
    if numbers and 1 <= int(folded) <= len(BLUEPRINTS):
        bp = BLUEPRINTS[int(folded) - 1]
        return ElicitationResult(status="MATCHED", blueprint=bp, matched_keyword=f"menu:{folded}")

    # 2. Keyword pass.
    hits = _text_hits(text)
    if not hits:
        return ElicitationResult(status="UNKNOWN", question=menu())
    unique_bps = sorted({bp for _, bp in hits})
    if len(unique_bps) == 1:
        bp = _BY_ID[unique_bps[0]]
        return ElicitationResult(status="MATCHED", blueprint=bp, matched_keyword=hits[0][0])

    # 2b. guest_isolation modifier: a generic base-family keyword + an
    # isolation hint prefers the blueprints carrying guest isolation
    # WITHIN the hit set — deterministic subsetting, not scoring.
    if any(h in folded for h in _GUEST_ISOLATION_HINTS):
        iso = [b for b in unique_bps if _BY_ID[b].guest_isolation and b != "secure_office"]
        if len(iso) == 1:
            return ElicitationResult(status="MATCHED", blueprint=_BY_ID[iso[0]],
                                     matched_keyword=f"{hits[0][0]}+isolation")

    # 3. Genuine ambiguity ⇒ BLOCKED with the surviving menu, never a pick.
    survivors = "\n".join(f"  - {b} ({_BY_ID[b].title_en})" for b in unique_bps)
    return ElicitationResult(
        status="BLOCKED", candidates=tuple(unique_bps),
        question=(f"Ambiguous network type; more than one blueprint matched ({', '.join(unique_bps)}). "
                  f"Which one do you mean?\n{survivors}"))


def business_intent_from_blueprint(
    bp: Blueprint,
    *,
    answers: dict[str, str],
    requirement_text: str,
) -> tuple[Optional[BusinessIntentRequest], list[str]]:
    """Assemble the compiler request; missing required parameters are
    returned as blocking question CODES (the human fills them — T2)."""
    missing: list[str] = []
    for param in bp.required_parameters:
        if param not in answers or not answers[param].strip():
            missing.append(param)
    if missing:
        return None, missing

    availability = answers.get("availability", "STANDARD").strip().upper()
    if availability not in {"HIGH", "STANDARD"}:
        availability = "STANDARD"
    growth = answers.get("growth", "+25% in 12 months").strip()

    request = BusinessIntentRequest(
        requirement_text=requirement_text,
        zones=bp.zones,
        guest_isolation=bp.guest_isolation,
        internal_internet=True,
        dot1x_required=bp.dot1x_required or answers.get("dot1x", "").strip().lower() in {"yes", "نعم", "y", "true", "1"},
        uses_certificates=bp.uses_certificates,
        availability_class=availability,
        growth_plan=growth,
    )
    return request, []
