"""The single source of truth for a scripted operator answer sequence.

The orchestrator asks its questions in a fixed order, and a scripted run must
supply one answer per question **in that order**. That sequence used to be hand
written in four places — ``cli/scenarios.py``, ``harness/runner.py`` and two
test modules — and every time a question was added, all four shifted one slot
and the answers silently landed on the wrong question. ``ScriptedIO`` made it
worse by defaulting to ``"y"`` when the queue ran dry, so a misaligned run
still reported success.

Building the sequence from one function, with the security-relevant decision
required rather than defaulted, removes the whole class of defect.
"""

from __future__ import annotations

from typing import Final

#: The orchestrator's questions, in the order it asks them.
ANSWER_SLOTS: Final[tuple[str, ...]] = (
    "bond_physical",      # Phase.BOND              confirm — is the cable in the seed?
    "access_retry",       # Phase.DISCOVERY_A       ask — Phase W
    "intent",             # Phase.INTENT_ELICITATION ask (free-form / menu no.)
    "router_device",      # Phase.INTENT_ELICITATION ask
    "wan_handoff",        # Phase.INTENT_ELICITATION ask
    "availability",       # Phase.INTENT_ELICITATION ask
    "growth",             # Phase.INTENT_ELICITATION ask
    "dns_servers",        # Phase.INTENT_ELICITATION ask — Phase W
    "bond_confirm",       # Phase.EXECUTION_GATE    ask — typed BOND
)

#: Every key the orchestrator can ask under. A run may ask a subset — it
#: depends on what discovery found — but it must never ask outside this set,
#: and ``answers_keyed`` must cover all of it.
QUESTION_KEYS: Final[tuple[str, ...]] = ANSWER_SLOTS + ("bond_physical",)

_YES: Final[frozenset[str]] = frozenset({"y", "yes", "نعم"})

#: The only string that unlocks the apply gate.
_BOND_WORD: Final[str] = "BOND"


def answer_script(
    *,
    access_retry: str,
    intent: str,
    bond_confirm: str = "no",
    apply: bool = False,
    router_device: str = "seed-01",
    wan_handoff: str = "ISP fiber DHCP handoff",
    availability: str = "STANDARD",
    growth: str = "+25% in 12 months",
    dns_servers: str = "1.1.1.1, 9.9.9.9",
) -> list[str]:
    """Build a complete answer list in the order the orchestrator asks.

    ``access_retry`` and ``intent`` are required. ``access_retry`` decides
    whether the platform will prompt for management credentials and re-probe a
    device discovery could not reach — a security-relevant act that must never
    be left implicit — so the caller has to state it.
    """
    if access_retry.strip().lower() not in _YES | {"n", "no", "لا"}:
        raise ValueError(
            f"access_retry={access_retry!r} is not an explicit yes/no; a "
            f"credential retry must be decided deliberately, never defaulted")
    return [answers_keyed(
        access_retry=access_retry, intent=intent,
        bond_confirm=_bond_decision(apply, bond_confirm),
        router_device=router_device, wan_handoff=wan_handoff,
        availability=availability, growth=growth, dns_servers=dns_servers,
    )[slot] for slot in ANSWER_SLOTS]


def answers_keyed(
    *,
    access_retry: str,
    intent: str,
    bond_confirm: str = "no",
    apply: bool = False,
    bond_physical: str = "y",
    router_device: str = "seed-01",
    wan_handoff: str = "ISP fiber DHCP handoff",
    availability: str = "STANDARD",
    growth: str = "+25% in 12 months",
    dns_servers: str = "1.1.1.1, 9.9.9.9",
) -> dict[str, str]:
    """The same answers, addressed by the question they belong to.

    This is the form to install. :func:`answer_script` flattens it into the
    order ``ANSWER_SLOTS`` happens to declare, and that order is a fact about
    today's orchestrator: ``access_retry`` is asked only when a device was
    unreachable, so a caller cannot know the order in advance, and one
    question added anywhere shifts every answer after it onto the wrong
    question. Keyed answers cannot shift. The orchestrator names every
    question it asks; see ``QUESTION_KEYS``.
    """
    if access_retry.strip().lower() not in _YES | {"n", "no", "لا"}:
        raise ValueError(
            f"access_retry={access_retry!r} is not an explicit yes/no; a "
            f"credential retry must be decided deliberately, never defaulted")
    return {
        "bond_physical": bond_physical,
        "bond_confirm": _bond_decision(apply, bond_confirm),
        "access_retry": access_retry,
        "intent": intent,
        "router_device": router_device,
        "wan_handoff": wan_handoff,
        "availability": availability,
        "growth": growth,
        "dns_servers": dns_servers,
    }


def _bond_decision(apply: bool, bond_confirm: str) -> str:
    """Resolve the apply-gate answer, refusing the trap in the middle.

    The gate unlocks only on the literal word ``BOND`` (see the execution gate
    in the orchestrator). ``"y"`` — the natural thing to write, and this
    function's own historical default — does not unlock it: the run stages
    everything and then ends ``BLOCKED-DENIED`` with "operator did not type
    BOND", pointing at a decision the caller never realised they had made.
    Every caller in the tree ran with ``execute=False`` and never reached the
    gate, so the unsatisfiable default was never exercised.

    So: ``apply=True`` means BOND, ``apply=False`` means decline, and a
    yes-ish ``bond_confirm`` that is not BOND is an error rather than a run
    that quietly refuses to apply.
    """
    if apply:
        return _BOND_WORD
    lowered = bond_confirm.strip().lower()
    if lowered in _YES:
        raise ValueError(
            f"bond_confirm={bond_confirm!r} looks like a yes, but the apply "
            f"gate unlocks only on the literal word {_BOND_WORD!r}. Pass "
            f"apply=True to authorise the apply, or bond_confirm="
            f"{_BOND_WORD!r} — an ambiguous yes is not a decision to change "
            f"a production device.")
    return bond_confirm


def grants_access_retry(answer: str) -> bool:
    """Whether an operator's answer authorises the credential retry."""
    return answer.strip().lower() in _YES
