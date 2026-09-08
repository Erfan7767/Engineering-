"""Agent Boundary Guard (D4) — L01/L02/L11/L17 enforcement.

The single gate through which any LLM agent output enters the platform:

1. SCHEMA: the payload must validate against ``agent_output.schema.json``
   — the Intent Object is the ONLY accepted shape (L17). Invalid payloads
   are QUARANTINED, never forwarded;
2. ENTITY GUARD: every ``target_entities`` entry must already exist in the
   Digital Twin (Entity Guard, §5 / L02). Fabricated references increment
   ``entity_hallucinations`` (T5) and quarantine the payload;
3. RAW COMMANDS: string values in ``proposed_change`` are matched against
   command prefixes DERIVED FROM the six vendor allowlists (data-driven —
   no hardcoded vendor knowledge). A match ⇒ quarantined, because only the
   Config IR Generator (E09) may produce executable artifacts (L17);
4. CREDENTIAL PATTERNS (L11): the serialized payload is scanned for
   credential shapes; a hit increments ``credential_exposure`` (T5) and
   quarantines — secrets never transit the agent plane.

All checks run to completion: the verdict lists EVERY reason, deterministically.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any, Mapping

from jsonschema import Draft7Validator

from ..core.counters import CounterCollector
from ..twin.twin import DigitalTwin

_VALID_ENTITY_TYPES = frozenset({
    "DEVICE", "CHASSIS", "STACK_MEMBER", "INTERFACE", "VLAN",
    "LINK", "SERVICE", "POLICY", "SITE", "RACK",
})

#: Credential shapes (L11). Conservative on purpose: a false quarantine is
#: recoverable, a leaked secret is not.
_CREDENTIAL_PATTERNS = tuple(
    re.compile(p, re.IGNORECASE) for p in (
        r"\bpassword\s*[:=]",
        r"\bpasswd\s*[:=]",
        r"\bsecret\s*[:=]",
        r"\bapi[_-]?key\s*[:=]",
        r"\baccess[_-]?token\s*[:=]",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"\bsnmp\s+server\s+community\b",
    ))


@dataclass(frozen=True)
class GuardVerdict:
    accepted: bool
    quarantine_reasons: tuple[str, ...]   # SCHEMA_INVALID / ENTITY_NOT_IN_INVENTORY:<ref> /
                                          # RAW_COMMAND_DETECTED:<key> / CREDENTIAL_PATTERN_DETECTED
    entity_violations: tuple[str, ...]

    @property
    def quarantined(self) -> bool:
        return not self.accepted


def _load_schema() -> dict:
    raw = resources.files("netops_autopilot.agents").joinpath(
        "data/agent_output.schema.json").read_text(encoding="utf-8")
    return json.loads(raw)


def _allowlist_command_prefixes() -> tuple[str, ...]:
    """Command prefixes derived from the six vendor allowlists — the same
    data the Collector executes from, so quarantine and execution stay in
    lockstep. Templates are cut at '<' (argument placeholder)."""
    prefixes: set[str] = set()
    root = resources.files("netops_autopilot.agents").joinpath("data/allowlists")
    for entry in root.iterdir():
        if not entry.name.endswith(".json"):
            continue
        data = json.loads(entry.read_text(encoding="utf-8"))
        for cls in data.get("classes", {}).values():
            for item in cls.get("entries", []):
                template = str(item.get("template", "")).split("<")[0].strip().lower()
                if len(template) >= 3:
                    prefixes.add(template)
    return tuple(sorted(prefixes))


class AgentGuard:
    def __init__(self, twin: DigitalTwin, counters: CounterCollector) -> None:
        self._twin = twin
        self._counters = counters
        self._validator = Draft7Validator(_load_schema())
        self._prefixes = _allowlist_command_prefixes()

    # ------------------------------------------------------------------ admit
    def admit(self, payload: Mapping[str, Any]) -> GuardVerdict:
        reasons: list[str] = []
        entity_violations: list[str] = []

        # 1. Schema (L17): the Intent Object is the only accepted shape.
        errors = sorted(self._validator.iter_errors(dict(payload)),
                        key=lambda e: "/" + "/".join(str(p) for p in e.path))
        for error in errors:
            reasons.append(f"SCHEMA_INVALID:{'/' + '/'.join(str(p) for p in error.path) if error.path else '/'}")

        # 2. Entity Guard (§5/L02): only pre-existing Twin entities may be targeted.
        for ref in payload.get("target_entities", ()) if isinstance(payload.get("target_entities"), list) else ():
            if not isinstance(ref, Mapping):
                continue
            entity_type, entity_ref = ref.get("entity_type"), ref.get("entity_ref")
            if entity_type not in _VALID_ENTITY_TYPES or not entity_ref:
                continue  # schema errors already reported above
            if not self._twin.exists(str(entity_type), str(entity_ref)):
                entity_violations.append(f"{entity_type}:{entity_ref}")
        if entity_violations:
            self._counters.increment("entity_hallucinations",
                                     f"agent payload referenced {len(entity_violations)} non-existent entit(y/ies): "
                                     + ",".join(sorted(entity_violations)))
            for violation in sorted(entity_violations):
                reasons.append(f"ENTITY_NOT_IN_INVENTORY:{violation}")

        # 3. Raw command strings (L17): executable artifacts are E09's only.
        proposed = payload.get("proposed_change")
        if isinstance(proposed, Mapping):
            for key in sorted(proposed):
                value = proposed[key]
                if isinstance(value, str) and self._looks_like_command(value):
                    reasons.append(f"RAW_COMMAND_DETECTED:{key}")

        # 4. Credential patterns (L11).
        serialized = json.dumps(payload, sort_keys=True, default=str)
        if any(p.search(serialized) for p in _CREDENTIAL_PATTERNS):
            self._counters.increment("credential_exposure",
                                     "agent payload matched a credential pattern; quarantined before transit")
            reasons.append("CREDENTIAL_PATTERN_DETECTED")

        accepted = not reasons
        return GuardVerdict(accepted=accepted, quarantine_reasons=tuple(sorted(reasons)),
                            entity_violations=tuple(sorted(entity_violations)))

    # -------------------------------------------------------------- internals
    def _looks_like_command(self, value: str) -> bool:
        candidate = value.strip().lower()
        if len(candidate) < 3:
            return False
        return any(candidate == p or candidate.startswith(p) for p in self._prefixes)
