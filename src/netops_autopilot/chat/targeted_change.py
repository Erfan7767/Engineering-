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

import ipaddress

#: The wildcard form of "any" in IOS ACL syntax, for a side of a deny rule
#: whose address the provider chooses and this platform therefore never knows.
_ANY_NETWORK = ipaddress.ip_network("0.0.0.0/0")
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
from ..engines.design_engine import (
    DHCP_RESERVED_HOSTS,
    _dhcp_exclusion,
    _dhcp_pool_range,
    _prefix_to_mask,
)
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
    "مستخدمين": "USERS", "المستخدمين": "USERS", "users": "USERS", "user": "USERS",
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


#: Purpose words an operator actually types, mapped to the zone names a design
#: really uses. Only explicit equivalences — a purpose with no entry is not
#: matched to the nearest-looking zone, because "the closest zone" is a guess
#: and a pool on the wrong subnet is worse than a refusal.
_PURPOSE_TO_ZONE = {
    "STAFF": ("users", "staff", "employees", "corporate"),
    "USERS": ("users",),
    "GUESTS": ("guest", "guests"),
    "MGMT": ("mgmt", "management", "admin"),
    "VOICE": ("voice", "voip", "phones"),
    "CCTV": ("cctv", "cameras"),
    "LAB": ("lab",),
    "SERVERS": ("servers", "datacenter"),
}


def resolve_zone(text: str, zone_names: Sequence[str]) -> tuple[Optional[str], tuple[str, ...]]:
    """Which of ``zone_names`` the request means, or ``(None, matched)``.

    Matching is against the zones the design actually contains, never against a
    vocabulary of zones that might exist. Returns every zone the text matched so
    the caller can refuse an ambiguous request instead of picking one — sending
    a DHCP pool to the wrong zone is a change nobody asked for.
    """
    norm = _normalize_for_zone(text)
    tokens: set[str] = set()
    for raw in re.split(r"[\s,،;]+", norm):
        key = raw.strip(" .،,!?\"'")
        if not key:
            continue
        forms = [key, *_affix_forms(key)]
        tokens.update(forms)
        # The purpose lookup has to run over the affix-stripped forms too:
        # Arabic attaches the preposition and the article to the noun, so the
        # operator writes "للضيوف" where the vocabulary holds "ضيوف". Looking
        # the raw token up was silently missing every prefixed form.
        for form in forms:
            purpose = _PURPOSES.get(form)
            if purpose:
                tokens.update(_PURPOSE_TO_ZONE.get(purpose, ()))

    matched = tuple(z for z in zone_names
                    if z.lower() in tokens or _normalize_for_zone(z) in tokens)
    return (matched[0] if len(matched) == 1 else None), matched


#: "اعزل X عن Y" / "isolate X from Y". X is the zone being denied and Y the zone
#: it may not reach — the order is the whole meaning of the request, so the
#: split is on the separator and each side is resolved separately rather than
#: taking the two matches in whatever order the text happened to name them.
_PAIR_SPLIT = (re.compile(r"\s+عن\s+"), re.compile(r"\s+from\s+"))


def resolve_zone_pair(text: str, zone_names: Sequence[str]):
    """``((src, dst), matched)`` for an isolation request.

    ``src`` is the zone that loses access. Returns ``(None, None)`` when either
    side is unresolved or both sides resolve to the same zone — a zone cannot be
    isolated from itself, and picking a side to make the request work would be
    guessing at which direction the operator meant.
    """
    norm = _normalize_for_zone(text)
    parts = None
    for rx in _PAIR_SPLIT:
        split = rx.split(norm)
        if len(split) == 2:
            parts = split
            break
    if parts is None:
        return (None, None), ()
    src, src_matched = resolve_zone(parts[0], zone_names)
    dst, dst_matched = resolve_zone(parts[1], zone_names)
    matched = tuple(dict.fromkeys((*src_matched, *dst_matched)))
    if not (src and dst) or src == dst:
        return (None, None), matched
    return (src, dst), matched


def _normalize_for_zone(text: str) -> str:
    """Lowercase, collapse whitespace, strip Arabic harakat.

    Mirrors the chat operator's normaliser. Alef/ya/taa-marbuta variants are
    NOT folded, because the operator does not fold them either — matching here
    against a fold that happens nowhere else would accept spellings the rest of
    the platform would not.
    """
    t = text.strip().lower()
    return re.sub(r"\s+", " ", re.sub(r"[\u064B-\u0652\u0670\u0640]", "", t))


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


def plan_add_dhcp(
    *,
    change_id: str,
    request: str,
    device_ref: str,
    vendor_os: str,
    zone: str,
    subnet: str,
    gateway: str,
    dns: str = "",
) -> ChangePlan:
    """Render a DHCP pool for one zone and return it without touching a device.

    ``subnet`` and ``gateway`` are **required**, and they come from the design
    that was actually applied — never from a guess. A pool built on an invented
    subnet would hand out addresses that are not on the wire, which is a worse
    failure than refusing: the client gets a lease, then cannot reach anything.
    The caller resolves them from ``context.last_design`` or refuses and says
    the subnet is unknown.

    The node is built exactly the way :mod:`engines.design_engine` builds the
    same node for a site design, and reuses that module's own exclusion and
    pool-window helpers, so a pool created from the chat and one created by a
    full run cannot disagree about which addresses are handed out.
    """
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"SUBNET_UNPARSEABLE: {subnet!r} ({exc})",)) from exc
    if net.version != 4:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"SUBNET_NOT_IPV4: {subnet!r} — IPv6 zones use SLAAC/RA, and this "
            f"path models an IPv4 pool only",))
    try:
        gw = ipaddress.ip_address(gateway)
    except ValueError as exc:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"GATEWAY_UNPARSEABLE: {gateway!r} ({exc})",)) from exc
    if gw not in net:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"GATEWAY_OUTSIDE_SUBNET: {gateway} is not inside {subnet}; a pool "
            f"whose default-router is off-subnet gives clients a lease they "
            f"cannot use",))

    exclusion = _dhcp_exclusion(subnet, gateway)
    mask = _prefix_to_mask(str(net.prefixlen))
    pool_range = _dhcp_pool_range(subnet, exclusion[1]) if exclusion else None
    if not (exclusion and mask and pool_range):
        # Not invented, not silently dropped: the same three-way check the
        # design engine applies, so an unusable subnet is refused here rather
        # than rendered into a pool with no assignable addresses.
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"NO_DHCP_POOL: subnet {subnet} has no computable IPv4 exclusion "
            f"block or assignable window (T2)",))

    params = {
        "pool": zone,
        "interface": zone,
        "network": str(net.network_address),
        "netmask": mask,
        "prefix": str(net.prefixlen),
        "gateway": gateway,
        "exclude_first": exclusion[0],
        "exclude_last": exclusion[1],
        "pool_first": pool_range[0],
        "pool_last": pool_range[1],
        "reason": (f"chat targeted change: pool for zone {zone}; first "
                   f"{DHCP_RESERVED_HOSTS} usable addresses reserved for "
                   f"gateway/infrastructure"),
    }
    if dns:
        # Same normalisation the design engine applies: IOS `dns-server` takes
        # a space-separated list even though people write commas.
        params["dns"] = " ".join(
            t for t in re.split(r"[,;\s]+", dns.strip()) if t)

    node = IRNode(
        node_id=f"dhcp-{zone}",
        target=EntityRef(entity_type="DEVICE", entity_ref=device_ref),
        operation=Operation.CREATE,
        feature="dhcp",
        vendor_os=vendor_os,
        parameters=params,
        reversibility=Reversibility.REVERSIBLE_BY_REPLACE,
        requires=(f"l3:{zone}",),
        provides=(f"dhcp:{zone}",),
    )
    rendered = render_ir(device_ref, ConfigIR(
        title=f"chat: dhcp pool for {zone}", nodes=(node,)))

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
        understood=(f"DHCP pool {zone} on {device_ref}: {subnet}, gateway "
                    f"{gateway}, assignable {pool_range[0]}-{pool_range[1]}"),
        device_ref=device_ref,
        vendor_os=vendor_os,
        commands=commands,
        wrappers=rendered.wrappers,
        persist=rendered.persist,
        mode_exit=rendered.mode_exit,
        # Read the config back rather than trusting the CLI's silence. The pool
        # name AND the network must both be present: a pool that exists with
        # the wrong network is a different failure and must not read as success.
        verify_command="show running-config",
        verify_expect=(f"pool {zone}", str(net.network_address)),
        preview=rendered.to_text(),
    )


_ACL_DENY_RE = re.compile(
    r"^\s*(?:\d+\s+)?deny\s+ip\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)")


def read_acl_denies(text: str) -> dict[str, set[tuple[str, str]]]:
    """``{acl_name: {(src_network, dst_network), ...}}`` from ``show ip access-lists``.

    Only lines that actually parse as a ``deny ip`` with four operands are
    recorded. A parser that guessed here would either miss an isolation that is
    already in force — and send a duplicate — or invent one and refuse a change
    the operator still needs.
    """
    out: dict[str, set[tuple[str, str]]] = {}
    current: Optional[str] = None
    for line in text.splitlines():
        head = line.strip()
        if head.startswith("ip access-list"):
            parts = head.split()
            # "ip access-list extended NAME" / "ip access-list standard NAME"
            current = parts[-1] if len(parts) >= 4 else None
            if current:
                out.setdefault(current, set())
            continue
        if current is None:
            continue
        m = _ACL_DENY_RE.match(line)
        if m:
            out[current].add((m.group(1), m.group(3)))
    return out


def plan_isolate_zones(
    *,
    change_id: str,
    request: str,
    device_ref: str,
    vendor_os: str,
    src_zone: str,
    dst_zone: str,
    src_subnet: str,
    dst_subnet: str,
    vlan_id: int,
    existing: Optional[Mapping[str, set]] = None,
    src_provider_assigned: bool = False,
    dst_provider_assigned: bool = False,
) -> ChangePlan:
    """Render a one-way isolation (``src`` may not reach ``dst``) and send nothing.

    Three nodes, in the order that makes them safe: the deny, then the
    ``permit ip any any`` that keeps everything else reachable, then the apply.
    Emitting the deny without the permit is how a zone gets black-holed — an
    extended ACL with no permit at the end denies everything it does not name.

    ``existing`` is the device's current ``show ip access-lists``. When the
    deny is already in force the change is refused as a no-op rather than sent
    again: on IOS re-entering a named ACL appends, so a second identical deny
    is harmless but a duplicate rule is a lie about what changed.
    
    A side flagged ``provider_assigned`` takes its address from the provider,
    so the subnet on record is a plan that never reaches the wire. Naming it
    would produce a rule that reads as protection and protects nothing, so
    that side is written as ``any`` — ``0.0.0.0 255.255.255.255`` — which
    covers the zone whatever address the provider handed out.
    """
    try:
        src_net = ipaddress.ip_network(src_subnet, strict=False)
        dst_net = ipaddress.ip_network(dst_subnet, strict=False)
    except ValueError as exc:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"SUBNET_UNPARSEABLE: {src_subnet!r}/{dst_subnet!r} ({exc})",)) from exc
    if src_provider_assigned:
        src_net = _ANY_NETWORK
    if dst_provider_assigned:
        dst_net = _ANY_NETWORK
    for net, label in ((src_net, "source"), (dst_net, "destination")):
        if net.version != 4:
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                f"SUBNET_NOT_IPV4: the {label} zone is {net}; this path models "
                f"an IPv4 filter only",))
    if src_net == dst_net:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"SAME_ZONE: {src_subnet} is both ends of the rule; a zone cannot "
            f"be isolated from itself",))

    acl_name = f"ACL_{src_zone.upper()}_IN"
    already = (existing or {}).get(acl_name, set())
    key = (str(src_net.network_address), str(dst_net.network_address))
    if key in already:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"ALREADY_ISOLATED: {acl_name} on {device_ref} already denies "
            f"{key[0]} -> {key[1]}; nothing to change",))

    def _ref(node_id: str) -> EntityRef:
        return EntityRef(entity_type="DEVICE", entity_ref=device_ref)

    common = dict(target=_ref(device_ref), vendor_os=vendor_os,
                  reversibility=Reversibility.REVERSIBLE_BY_REPLACE)
    deny = IRNode(
        node_id=f"acl-deny-{src_zone}-{dst_zone}", operation=Operation.CREATE,
        feature="acl_deny",
        parameters={
            "acl_name": acl_name,
            "src_net": str(src_net.network_address),
            "src_wc": str(src_net.hostmask),
            "dst_net": str(dst_net.network_address),
            "dst_wc": str(dst_net.hostmask),
            "src_prefix": src_net.prefixlen,
            "dst_prefix": dst_net.prefixlen,
            "reason": (f"chat targeted change: {src_zone} -> {dst_zone} DENIED, "
                       f"enforced inbound on the {src_zone} gateway"),
        },
        requires=(f"l3:{src_zone}",), provides=(), **common)
    permit = IRNode(
        node_id=f"acl-permit-{src_zone}", operation=Operation.CREATE,
        feature="acl_permit",
        parameters={"acl_name": acl_name,
                    "reason": ("everything not denied above stays reachable from "
                               f"{src_zone}; without it the ACL black-holes the zone")},
        requires=(f"l3:{src_zone}",), provides=(), **common)
    apply = IRNode(
        node_id=f"acl-apply-{src_zone}", operation=Operation.UPDATE,
        feature="acl_apply",
        parameters={"acl_name": acl_name, "vlan_id": vlan_id,
                    "reason": f"{acl_name} applied inbound on Vlan{vlan_id}"},
        requires=(f"l3:{src_zone}",), provides=(), **common)

    rendered = render_ir(device_ref, ConfigIR(
        title=f"chat: isolate {src_zone} from {dst_zone}",
        nodes=(deny, permit, apply)))

    not_modeled = [b for b in rendered.blocks if b.status != "RENDERED"]
    if not_modeled:
        raise Failure(cls=FailureClass.BLOCKED, causes=tuple(
            f"NOT_MODELED node={b.node_id}: {b.reason}" for b in not_modeled))
    commands = tuple(c for b in rendered.blocks for c in b.commands)
    if not commands:
        # Not an error: on RouterOS a filter rule is in force the moment it is
        # added and the default forward policy is accept, so acl_permit and
        # acl_apply legitimately render nothing. The deny is what must be there.
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            "NO_COMMANDS_RENDERED: the change produced nothing to send",))

    return ChangePlan(
        change_id=change_id,
        request=request,
        understood=(f"deny {src_zone} ({src_subnet}) -> {dst_zone} "
                    f"({dst_subnet}) via {acl_name} inbound on Vlan{vlan_id}"),
        device_ref=device_ref,
        vendor_os=vendor_os,
        commands=commands,
        wrappers=rendered.wrappers,
        persist=rendered.persist,
        mode_exit=rendered.mode_exit,
        # Read the ACL back from the device. The name alone is not enough: an
        # ACL can exist with the wrong statement in it and still "be there".
        verify_command="show ip access-lists",
        verify_expect=(acl_name, str(src_net.network_address),
                       str(dst_net.network_address)),
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
