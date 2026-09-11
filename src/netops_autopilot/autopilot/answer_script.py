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
    "bond_confirm",       # Phase.BOND              confirm
    "access_retry",       # Phase.DISCOVERY_A       ask — Phase W
    "intent",             # Phase.INTENT_ELICITATION ask (free-form / menu no.)
    "router_device",      # Phase.INTENT_ELICITATION ask
    "wan_handoff",        # Phase.INTENT_ELICITATION ask
    "availability",       # Phase.INTENT_ELICITATION ask
    "growth",             # Phase.INTENT_ELICITATION ask
    "dns_servers",        # Phase.INTENT_ELICITATION ask — Phase W
)

_YES: Final[frozenset[str]] = frozenset({"y", "yes", "نعم"})


def answer_script(
    *,
    access_retry: str,
    intent: str,
    bond_confirm: str = "y",
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
    script = {
        "bond_confirm": bond_confirm,
        "access_retry": access_retry,
        "intent": intent,
        "router_device": router_device,
        "wan_handoff": wan_handoff,
        "availability": availability,
        "growth": growth,
        "dns_servers": dns_servers,
    }
    return [script[slot] for slot in ANSWER_SLOTS]


def grants_access_retry(answer: str) -> bool:
    """Whether an operator's answer authorises the credential retry."""
    return answer.strip().lower() in _YES
