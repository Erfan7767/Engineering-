"""Targeted network changes from the chat — real execution, real evidence.

The chat could previously only change a network by re-running the whole
autopilot (``apply <type>``). A request as ordinary as "create a VLAN for
staff" had no path, so it was refused. This module is that path.

It deliberately contains **no command strings**. Every line it will send is
produced by :func:`netops_autopilot.engines.config_renderer.render_ir` from an
IR node built exactly the way :mod:`engines.design_engine` builds one for a
full site design, and it is applied by the same :class:`ConfigExecutor` the
orchestrator uses — the same allowlist gate, the same pre-built rollback plan,
the same ledger write, the same post-apply readback. One execution path, not a
second one bolted on for the chat; a parallel path is how the two end up
disagreeing about what is safe.

Two-step by design, mirroring the platform's existing ``design`` then ``apply``
flow:

1. :func:`plan_create_vlan` builds the plan and sends **nothing**. It returns
   the exact commands, the device, and how success will be checked.
2. :func:`execute_change` sends them — only when the operator confirms.

Nothing here reports success on its own say-so. The evidence is the device's
own readback, and :class:`ChangeReport` keeps ``applied``, ``verified`` and
``failure_causes`` as separate facts, so "planned", "sent" and "proven on the
wire" can never be collapsed into one word.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Sequence

from ..access.allowlist import CommandAllowlist
from ..access.executor import ConfigExecutor
from ..core.failures import Failure, FailureClass
from ..engines.config_ir import (
    ConfigIR,
    EntityRef,
    IRNode,
    Operation,
    Reversibility,
)
from ..engines.config_renderer import render_ir
from ..ledger.store import LedgerStore


# ---------------------------------------------------------------------------
# plan / outcome
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChangePlan:
    """A targeted change, fully rendered, not yet sent.

    Everything the operator needs in order to say yes or no: what was
    understood, which device, the exact lines, and how success will be
    checked afterwards.
    """

    change_id: str
    request: str                     # what the operator typed
    understood: str                  # the parsed intent, in words
    device_ref: str
    vendor_os: str
    commands: tuple[str, ...]        # what will actually be sent
    wrappers: tuple[tuple[str, ...], tuple[str, ...]]
    persist: tuple[str, ...]
    mode_exit: str
    verify_command: str              # read-only check run afterwards
    verify_expect: tuple[str, ...]   # substrings that must appear
    preview: str                     # the rendered config as text

    def to_dict(self) -> dict:
        return {
            "change_id": self.change_id,
            "request": self.request,
            "understood": self.understood,
            "device_ref": self.device_ref,
            "vendor_os": self.vendor_os,
            "commands": list(self.commands),
            "verify_command": self.verify_command,
            "verify_expect": list(self.verify_expect),
        }


@dataclass(frozen=True)
class ChangeReport:
    """What actually happened — kept separate from what was planned."""

    plan: ChangePlan
    outcome: str
    applied: tuple[str, ...]
    rejected: tuple[str, ...]
    failure_causes: tuple[str, ...]
    #: Evidence read back from the device, not from the plan.
    evidence: str
    #: The device's own readback contained what the change was supposed to
    #: leave behind. Distinct from ``outcome``: a command can be accepted by
    #: the CLI and still not be in the running config.
    verified: bool
    rolled_back: bool
    rollback_complete: bool
    #: Lines the executor looked for in the readback but did not find. A
    #: non-zero value with a clean outcome means the check proved nothing.
    state_absent: int

    @property
    def succeeded(self) -> bool:
        return self.outcome == "APPLIED" and self.verified and not self.rejected

    def to_dict(self) -> dict:
        return {
            "change_id": self.plan.change_id,
            "device_ref": self.plan.device_ref,
            "outcome": self.outcome,
            "applied": list(self.applied),
            "rejected": list(self.rejected),
            "failure_causes": list(self.failure_causes),
            "verified": self.verified,
            "state_absent": self.state_absent,
            "rolled_back": self.rolled_back,
            "rollback_complete": self.rollback_complete,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# parsing — what the operator actually asked for
# ---------------------------------------------------------------------------

#: A VLAN name is letters/digits/hyphen/underscore, 1..32 chars (IEEE 802.1Q
#: allows 32). Anything else is refused rather than passed to the device,
#: which is where a stray character becomes a syntax error at best.
_NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")

#: Words that name a purpose rather than a literal VLAN name. An operator who
#: says "a VLAN for staff" means the staff VLAN; the platform picks a name for
#: it instead of asking them to know the naming scheme.
_PURPOSES = {
    "موظفين": "STAFF", "الموظفين": "STAFF", "staff": "STAFF", "employees": "STAFF",
    "ضيوف": "GUESTS", "الضيوف": "GUESTS", "guests": "GUESTS", "guest": "GUESTS",
    "صوت": "VOICE", "الصوت": "VOICE", "voice": "VOICE", "هواتف": "VOICE",
    "إدارة": "MGMT", "ادارة": "MGMT", "mgmt": "MGMT", "management": "MGMT",
    "كاميرات": "CCTV", "كاميرا": "CCTV", "cctv": "CCTV", "cameras": "CCTV",
    "مختبر": "LAB", "lab": "LAB", "servers": "SERVERS", "خوادم": "SERVERS",
}


def _affix_forms(token: str) -> list[str]:
    """A token plus its bare forms, longest affix first.

    Arabic attaches the preposition and the definite article to the noun —
    "للموظفين" is "for the staff" — so a lookup on the raw token never
    matches, and the operator who asked for a staff VLAN is asked again for a
    purpose they already gave. Only leading affixes that actually occur are
    stripped, one at a time, and each intermediate form is kept.
    """
    forms = [token]
    cur = token
    while True:
        nxt = None
        for pre in ("بال", "وال", "لل", "ال", "ل", "ب", "و"):
            if cur.startswith(pre) and len(cur) - len(pre) >= 3:
                nxt = cur[len(pre):]
                break
        if nxt is None:
            return forms
        forms.append(nxt)
        cur = nxt


def parse_vlan_request(text: str) -> dict[str, object]:
    """Extract ``vlan_id`` / ``name`` from a free-text request.

    Returns a dict with whatever was actually found. Never invents an id:
    ``vlan_id`` is absent unless the operator gave one, and the caller decides
    what to do about that rather than silently picking one.
    """
    out: dict[str, object] = {}
    m = re.search(r"\bvlan\b\D{0,8}?(\d{1,4})\b", text.lower())
    if not m:
        # "أنشئ vlan 30" and "add vlan 30" both hit the pattern above; a bare
        # trailing number ("أنشئ شبكة 30") does not, and is not guessed at.
        m = re.search(r"(?:vlan|شبكة)\s+(\d{1,4})\b", text.lower())
    if m:
        vid = int(m.group(1))
        if 1 <= vid <= 4094:
            out["vlan_id"] = vid
        else:
            out["vlan_id_rejected"] = vid
    _REQUEST_WORDS = {"vlan", "vlans", "create", "add", "new", "make", "the",
                      "for", "an", "and", "with", "أنشئ", "انشئ", "أضف", "اضف",
                      "شبكة", "جديد", "جديدة", "على", "في", "من", "هذا", "هذه"}
    for token in re.split(r"[\s,،]+", text):
        key = token.strip(" .،,!?\"'").lower()
        for form in _affix_forms(key):
            if form in _PURPOSES:
                out["name"] = _PURPOSES[form]
                break
        if "name" in out:
            break
    for token in re.split(r"[\s,،]+", text):
        if "name" in out:
            break
        key = token.strip(" .،,!?\"'").lower()
        # A literal name the operator chose. Skip the words that are part of
        # the request rather than the name.
        if _NAME_OK.match(key) and len(key) >= 3 and not key.isdigit():
            if key not in _REQUEST_WORDS:
                out["name"] = key.upper()
    return out


def read_existing_vlans(text: str) -> dict[int, str]:
    """Parse ``show vlan brief`` into ``{vlan_id: name}``.

    The first column is validated as all-digits before a row is accepted, so
    the header, the ``----`` rule and any trailing prose are skipped rather
    than turned into invented VLANs. A parser that fabricates rows here would
    make the collision check below worse than no check at all.
    """
    out: dict[int, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        if not parts[0].isdigit():
            continue                      # header, rule, or prose
        vid = int(parts[0])
        if not 1 <= vid <= 4094:
            continue
        out.setdefault(vid, parts[1])
    return out


def next_free_vlan(existing: Sequence[int], reserved: Sequence[int] = ()) -> int:
    """Smallest unallocated VLAN id above the reserved floor.

    Reserved by default: 1 (default), 1002-1005 (legacy FDDI/Token Ring on
    Cisco). Allocating one of those is a real fault, not a style issue.
    """
    taken = set(existing) | set(reserved) | {1, 1002, 1003, 1004, 1005}
    for vid in range(10, 4095):
        if vid not in taken:
            return vid
    raise Failure(cls=FailureClass.BLOCKED,
                  causes=("VLAN_SPACE_EXHAUSTED: no free VLAN id in 10-4094",))


# ---------------------------------------------------------------------------
# planning — render, send nothing
# ---------------------------------------------------------------------------


def plan_create_vlan(
    *,
    change_id: str,
    request: str,
    device_ref: str,
    vendor_os: str,
    vlan_id: int,
    name: str,
    existing: Mapping[int, str],
) -> ChangePlan:
    """Render a single-VLAN change and return it without touching a device.

    ``existing`` is the device's **current** VLAN table, read from it. It is
    required, not optional: creating a VLAN without knowing which ids are
    taken is how a new VLAN silently lands on top of one already in service —
    the CLI accepts it, the id is now the other VLAN's, and the collision is
    discovered by an outage rather than by a check.

    Raises :class:`Failure` on a collision, or if the platform cannot express
    the change for this OS. A plan that would send nothing is not a plan;
    saying so is the honest answer, and the caller turns it into a refusal.
    """
    if not 1 <= vlan_id <= 4094:
        raise Failure(cls=FailureClass.BLOCKED,
                      causes=(f"VLAN_ID_OUT_OF_RANGE: {vlan_id} (must be 1-4094)",))
    if not _NAME_OK.match(name):
        raise Failure(cls=FailureClass.BLOCKED,
                      causes=(f"VLAN_NAME_INVALID: {name!r} — IEEE 802.1Q allows "
                              f"1-32 chars, letters/digits/._-",))
    # -- collisions, checked against the device's real state -----------------
    clash_id = existing.get(vlan_id)
    if clash_id is not None and clash_id.lower() == name.lower():
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"VLAN_ALREADY_EXISTS: VLAN {vlan_id} is already named "
            f"{clash_id!r} on {device_ref} — nothing to do",))
    if clash_id is not None:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"VLAN_ID_IN_USE: VLAN {vlan_id} on {device_ref} is already "
            f"{clash_id!r}; creating it would take that VLAN over. Choose "
            f"another id, or rename it explicitly if that is what you mean.",))
    for vid, nm in sorted(existing.items()):
        if nm.lower() == name.lower():
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                f"VLAN_NAME_IN_USE: {name!r} already exists on {device_ref} as "
                f"VLAN {vid}; a second VLAN under the same name cannot be told "
                f"apart by name.",))
    # Built the same way design_engine builds the same node for a site design,
    # so the renderer, the allowlist and the alignment tests all apply to it
    # exactly as they do to a full design.
    node = IRNode(
        node_id=f"vlan-{vlan_id}",
        target=EntityRef(entity_type="DEVICE", entity_ref=device_ref),
        operation=Operation.CREATE,
        feature="vlan",
        vendor_os=vendor_os,
        parameters={"vlan_id": vlan_id, "name": name,
                    "reason": f"chat targeted change: {request[:80]}"},
        reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
        provides=(f"vlan:{vlan_id}",),
    )
    rendered = render_ir(device_ref, ConfigIR(
        title=f"chat: create vlan {vlan_id} ({name})", nodes=(node,)))

    not_modeled = [b for b in rendered.blocks if b.status != "RENDERED"]
    if not_modeled:
        raise Failure(cls=FailureClass.BLOCKED, causes=tuple(
            f"NOT_MODELED node={b.node_id}: {b.reason}" for b in not_modeled))
    commands = tuple(c for b in rendered.blocks for c in b.commands)
    if not commands:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            "NO_COMMANDS_RENDERED: the change produced nothing to send",))

    return ChangePlan(
        change_id=change_id,
        request=request,
        understood=f"create VLAN {vlan_id} named {name} on {device_ref}",
        device_ref=device_ref,
        vendor_os=vendor_os,
        commands=commands,
        wrappers=rendered.wrappers,
        persist=rendered.persist,
        mode_exit=rendered.mode_exit,
        verify_command="show vlan brief",
        # The readback must show the id AND the name. Checking only the id
        # would pass on a VLAN that exists under a different name.
        verify_expect=(str(vlan_id), name),
        preview=rendered.to_text(),
    )


# ---------------------------------------------------------------------------
# execution — send, then prove it on the device
# ---------------------------------------------------------------------------


def execute_change(
    plan: ChangePlan,
    *,
    session,
    allowlist: CommandAllowlist,
    store: Optional[LedgerStore],
    read_back: Callable[[str, str], str],
    run_id: str = "chat-targeted",
    key_id: Optional[str] = None,
) -> ChangeReport:
    """Apply the plan through the platform's real executor, then verify.

    ``read_back(device_ref, command) -> text`` is supplied by the caller (the
    chat's read-only runner) so this module never opens a session of its own.

    ``verified`` comes from the device's readback, never from the outcome
    enum. A command the CLI accepted is not the same fact as a line present in
    the running config, and only the second one means the network changed.
    """
    executor = ConfigExecutor(
        allowlist=allowlist, store=store, run_id=run_id, key_id=key_id)
    record = executor.apply(
        plan.device_ref, session, plan.commands,
        dry_run=False,
        wrappers=plan.wrappers,
        persist=plan.persist,
        mode_exit=plan.mode_exit,
    )

    applied = tuple(c.command for c in record.commands
                    if c.phase == "APPLY" and c.ok)
    rejected = tuple(c.command for c in record.commands
                     if c.phase == "APPLY" and not c.ok)

    outcome = getattr(record.outcome, "value", str(record.outcome))
    rolled_back = outcome in ("ROLLED_BACK", "ROLLBACK_FAILED")

    # Verification is skipped, not faked, when the change did not land — after
    # a rollback the absence of the line is the expected state, and reporting
    # "verified: False" there would be a different kind of lie.
    evidence = ""
    verified = False
    if outcome == "APPLIED":
        try:
            evidence = read_back(plan.device_ref, plan.verify_command)
        except Exception as exc:  # noqa: BLE001 - honest failure, not a crash
            evidence = f"READBACK_FAILED: {exc!r}"
        else:
            verified = all(tok in evidence for tok in plan.verify_expect)

    return ChangeReport(
        plan=plan,
        outcome=outcome,
        applied=applied,
        rejected=rejected,
        failure_causes=tuple(record.failure_causes),
        evidence=evidence,
        verified=verified,
        rolled_back=rolled_back,
        rollback_complete=(outcome == "ROLLED_BACK"),
        state_absent=int(record.state_absent or 0),
    )
