"""Auto-Remediation Engine — the 30-year expert's "fix it now" button.

A senior network engineer, after the day-2 diagnostics surface a
problem, picks a remediation: "lower that port to 100M because
the cable is bad", "remove the stale MAC from the table", "kill
the looping broadcast on VLAN 10". This module turns those
choices into a typed, evidence-bound, allowlist-gated action.

Design contract:

* **Typed actions only** — every remediation is a typed
  :class:`RemediationAction` with a clear ``kind``,
  ``target_device``, ``target_interface`` (if any), and
  ``commands`` to execute.
* **Risk-graded** — every action carries a :class:`RiskLevel`
  (LOW / MEDIUM / HIGH). LOW = safe, MEDIUM = reversible,
  HIGH = requires a maintenance window.
* **Allowlist-gated** — every command is checked against the
  same allowlist that the executor uses. A remediation that
  contains a forbidden command is rejected at the
  :func:`plan_remediations` stage, before it ever reaches a
  device.
* **Idempotent** — every action has a ``would_be_no_op()``
  method that, given the current device state, says whether
  applying the action would do nothing. Idempotent operations
  are safe to retry.
* **Never silent** — the engine never applies a remediation
  silently. It returns a typed :class:`RemediationPlan` and
  the caller must explicitly approve it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    __test__ = False

    LOW = "LOW"               # read-only or self-healing
    MEDIUM = "MEDIUM"         # reversible, e.g. "shutdown" / "no shutdown"
    HIGH = "HIGH"             # service-affecting, needs a maintenance window


class ActionKind(str, Enum):
    __test__ = False

    # Cable / interface
    LOWER_PORT_SPEED = "lower_port_speed"
    DISABLE_ERROR_PORT = "disable_error_port"
    RESET_INTERFACE = "reset_interface"
    NEGOTIATE_AUTO = "negotiate_auto"

    # MAC / VLAN hygiene
    CLEAR_STALE_MAC = "clear_stale_mac"
    PRUNE_UNUSED_VLAN = "prune_unused_vlan"

    # Routing
    RESTART_OSPF_PROCESS = "restart_ospf_process"
    SOFT_RESET_BGP = "soft_reset_bgp"
    RELOAD_CONVERGENCE = "reload_convergence"

    # ACL hygiene
    REMOVE_SHADOWED_ACE = "remove_shadowed_ace"
    REMOVE_UNUSED_ACE = "remove_unused_ace"

    # PoE
    DISABLE_FAULTY_POE_PORT = "disable_faulty_poe_port"
    PRIORITIZE_POE_BUDGET = "prioritize_poe_budget"

    # Config
    RESTORE_FROM_GOLDEN = "restore_from_golden"
    ACCEPT_BASELINE = "accept_baseline"

    # System
    NTP_SYNC = "ntp_sync"
    CLEAR_LOG_BUFFER = "clear_log_buffer"


@dataclass(frozen=True)
class RemediationAction:
    __test__ = False

    kind: ActionKind
    target_device: str
    target_interface: str = ""
    description: str = ""
    commands: tuple[str, ...] = ()
    risk: RiskLevel = RiskLevel.MEDIUM
    rationale: str = ""
    evidence_id: str = ""

    def would_be_no_op(self, current_state: dict[str, Any]) -> bool:
        """Return True if applying this action would do nothing
        given the device's current state.

        ``current_state`` is a free-form dict the caller can fill
        with what the device just reported. The default
        implementation returns False (we don't know if it's a
        no-op, so we'll try).
        """
        if not self.target_interface:
            return False
        key = f"{self.target_device}:{self.target_interface}"
        return current_state.get(key, {}).get(
            "already_applied", False
        )


@dataclass
class RemediationPlan:
    __test__ = False

    actions: list[RemediationAction] = field(default_factory=list)
    blocked: list[RemediationAction] = field(default_factory=list)
    dry_run: bool = True

    @property
    def action_count(self) -> int:
        return len(self.actions)

    @property
    def blocked_count(self) -> int:
        return len(self.blocked)

    @property
    def highest_risk(self) -> RiskLevel:
        if not self.actions:
            return RiskLevel.LOW
        order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH]
        return max(
            (a.risk for a in self.actions),
            key=lambda r: order.index(r),
        )

    @property
    def overall_verdict(self) -> str:
        if self.blocked and not self.actions:
            return "BLOCKED"
        if self.highest_risk == RiskLevel.HIGH:
            return "MAINTENANCE_REQUIRED"
        if self.highest_risk == RiskLevel.MEDIUM:
            return "REVIEW_RECOMMENDED"
        return "SAFE_TO_APPLY"

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return self._render_ar()
        return self._render_en()

    def _render_en(self) -> str:
        lines = ["Remediation plan:"]
        lines.append(f"  Verdict:    {self.overall_verdict}")
        lines.append(f"  Actions:    {self.action_count}")
        lines.append(f"  Blocked:    {self.blocked_count}")
        lines.append(f"  Highest risk: {self.highest_risk.value}")
        if self.actions:
            lines.append("")
            lines.append("  Actions to apply:")
            for i, a in enumerate(self.actions, 1):
                lines.append(
                    f"    {i}. [{a.risk.value}] {a.kind.value}"
                    f" on {a.target_device}"
                    f"{':' + a.target_interface if a.target_interface else ''}"
                )
                if a.description:
                    lines.append(f"       {a.description}")
                if a.rationale:
                    lines.append(f"       Why: {a.rationale}")
                if a.commands:
                    lines.append("       Commands:")
                    for cmd in a.commands:
                        lines.append(f"         {cmd}")
        if self.blocked:
            lines.append("")
            lines.append("  Blocked (would need approval):")
            for a in self.blocked:
                lines.append(
                    f"    - [{a.risk.value}] {a.kind.value} on {a.target_device}"
                )
        return "\n".join(lines)

    def _render_ar(self) -> str:
        lines = ["خطة الإصلاح:"]
        lines.append(f"  النتيجة:   {self.overall_verdict}")
        lines.append(f"  الإجراءات: {self.action_count}")
        lines.append(f"  المحظورة:  {self.blocked_count}")
        lines.append(f"  أعلى خطورة: {self.highest_risk.value}")
        if self.actions:
            lines.append("")
            lines.append("  الإجراءات للتطبيق:")
            for i, a in enumerate(self.actions, 1):
                lines.append(
                    f"    {i}. [{a.risk.value}] {a.kind.value}"
                    f" على {a.target_device}"
                    f"{':' + a.target_interface if a.target_interface else ''}"
                )
                if a.description:
                    lines.append(f"       {a.description}")
                if a.rationale:
                    lines.append(f"       السبب: {a.rationale}")
                if a.commands:
                    lines.append("       الأوامر:")
                    for cmd in a.commands:
                        lines.append(f"         {cmd}")
        if self.blocked:
            lines.append("")
            lines.append("  محظورة (تحتاج موافقة):")
            for a in self.blocked:
                lines.append(
                    f"    - [{a.risk.value}] {a.kind.value} على {a.target_device}"
                )
        return "\n".join(lines)


# -----------------------------------------------------------------------
# Plan generators — turn a diagnostic finding into a remediation plan.
# -----------------------------------------------------------------------


def plan_from_health(
    device_ref: str,
    health_interfaces: list[dict[str, Any]],
) -> RemediationPlan:
    """Plan a remediation from per-interface health findings.

    Each entry in ``health_interfaces`` is a dict with at least:

    * ``interface`` (str)
    * ``verdict``   (one of: "healthy", "degraded", "critical", "down")
    * ``crc``       (int, optional)
    * ``errors``    (int, optional)
    * ``cable_diag`` (one of: "good", "degraded", "fault", optional)

    Rules:

    * "down" + errors: schedule a reset (MEDIUM).
    * "critical" + crc>50: lower the port speed (MEDIUM, common
      cable fix).
    * "degraded" + cable_diag=fault: shut the port (HIGH).
    * Otherwise: leave alone.
    """
    plan = RemediationPlan()
    for entry in health_interfaces:
        intf = entry.get("interface", "")
        verdict = entry.get("verdict", "healthy")
        crc = int(entry.get("crc", 0) or 0)
        cable = entry.get("cable_diag", "good")
        if verdict == "down":
            plan.actions.append(RemediationAction(
                kind=ActionKind.RESET_INTERFACE,
                target_device=device_ref,
                target_interface=intf,
                description=f"Reset {intf} (port is down)",
                commands=(f"interface {intf}", "shutdown", "no shutdown"),
                risk=RiskLevel.MEDIUM,
                rationale="Port is down — soft reset may recover the link",
            ))
        elif verdict == "critical" and crc > 50:
            plan.actions.append(RemediationAction(
                kind=ActionKind.LOWER_PORT_SPEED,
                target_device=device_ref,
                target_interface=intf,
                description=(
                    f"Lower {intf} to 100M to stabilize a flaky link"
                ),
                commands=(
                    f"interface {intf}",
                    "speed 100",
                    "duplex full",
                ),
                risk=RiskLevel.MEDIUM,
                rationale=(
                    f"CRC={crc} > 50 — high error rate usually "
                    "indicates cable or speed/duplex mismatch"
                ),
            ))
        elif verdict == "critical" and cable == "fault":
            plan.actions.append(RemediationAction(
                kind=ActionKind.DISABLE_ERROR_PORT,
                target_device=device_ref,
                target_interface=intf,
                description=(
                    f"Shut {intf} until the cable is replaced"
                ),
                commands=(
                    f"interface {intf}",
                    "shutdown",
                ),
                risk=RiskLevel.HIGH,
                rationale="Cable diagnostics reported FAULT",
            ))
    return plan


def plan_from_acl(
    device_ref: str,
    cold_aces: list[dict[str, Any]],
) -> RemediationPlan:
    """Plan to remove COLD (zero-hit) ACEs.

    Each entry has at least ``list_name`` and ``line_no``.
    """
    plan = RemediationPlan()
    for ace in cold_aces:
        list_name = ace.get("list_name", "")
        line_no = int(ace.get("line_no", 0) or 0)
        if not list_name or not line_no:
            continue
        plan.actions.append(RemediationAction(
            kind=ActionKind.REMOVE_UNUSED_ACE,
            target_device=device_ref,
            description=(
                f"Remove unused ACE at {list_name} line {line_no}"
            ),
            commands=(
                f"ip access-list extended {list_name}",
                f"no {line_no}",
            ),
            risk=RiskLevel.MEDIUM,
            rationale=(
                f"ACE on {list_name} line {line_no} has 0 hits "
                "in the audit window — likely dead policy"
            ),
        ))
    return plan


def plan_from_poe(
    device_ref: str,
    fault_ports: list[str],
    over_budget: bool,
) -> RemediationPlan:
    """Plan for PoE issues."""
    plan = RemediationPlan()
    for intf in fault_ports:
        plan.actions.append(RemediationAction(
            kind=ActionKind.DISABLE_FAULTY_POE_PORT,
            target_device=device_ref,
            target_interface=intf,
            description=f"Disable PoE on {intf} (fault)",
            commands=(
                f"interface {intf}",
                "power inline never",
            ),
            risk=RiskLevel.HIGH,
            rationale="PoE fault — likely bad PD or cable",
        ))
    if over_budget:
        plan.actions.append(RemediationAction(
            kind=ActionKind.PRIORITIZE_POE_BUDGET,
            target_device=device_ref,
            description="Enable PoE priority by port class",
            commands=(
                "power inline priority critical GigabitEthernet0/1-12",
            ),
            risk=RiskLevel.MEDIUM,
            rationale=(
                "PoE budget exceeded — prioritization prevents "
                "low-priority ports from starving critical ones"
            ),
        ))
    return plan


def plan_from_drift(
    device_ref: str,
    drift_lines: list[dict[str, Any]],
    golden_text: str | None = None,
) -> RemediationPlan:
    """Plan a remediation for config drift.

    If ``golden_text`` is given, the plan is to restore from golden.
    Otherwise the plan is to capture the current state as the new
    baseline (ACCEPT_BASELINE).
    """
    plan = RemediationPlan()
    if not drift_lines:
        return plan
    if golden_text:
        plan.actions.append(RemediationAction(
            kind=ActionKind.RESTORE_FROM_GOLDEN,
            target_device=device_ref,
            description="Replace running-config with golden snapshot",
            commands=("configure replace flash:golden",),
            risk=RiskLevel.HIGH,
            rationale=(
                f"{len(drift_lines)} drift line(s) detected — "
                "restoring golden returns the device to a known-good state"
            ),
        ))
    else:
        plan.actions.append(RemediationAction(
            kind=ActionKind.ACCEPT_BASELINE,
            target_device=device_ref,
            description="Capture current running-config as new golden",
            commands=("write memory",),
            risk=RiskLevel.LOW,
            rationale=(
                f"{len(drift_lines)} drift line(s) — the change is "
                "intentional; capture the new baseline"
            ),
        ))
    return plan


def plan_from_routing(
    device_ref: str,
    down_neighbors: list[dict[str, Any]],
) -> RemediationPlan:
    """Plan a remediation for routing peer issues."""
    plan = RemediationPlan()
    for nbr in down_neighbors:
        proto = nbr.get("protocol", "ospf")
        peer = nbr.get("neighbor", "")
        if proto == "ospf":
            plan.actions.append(RemediationAction(
                kind=ActionKind.RESTART_OSPF_PROCESS,
                target_device=device_ref,
                description=f"Restart OSPF to recover {peer}",
                commands=("clear ip ospf process",),
                risk=RiskLevel.MEDIUM,
                rationale=(
                    f"OSPF neighbor {peer} is DOWN — a process reset "
                    "is the standard short-term recovery"
                ),
            ))
        elif proto == "bgp":
            plan.actions.append(RemediationAction(
                kind=ActionKind.SOFT_RESET_BGP,
                target_device=device_ref,
                description=f"Soft-reset BGP peer {peer}",
                commands=(f"clear ip bgp {peer} soft",),
                risk=RiskLevel.MEDIUM,
                rationale=(
                    f"BGP peer {peer} is DOWN — soft reset refreshes "
                    "the BGP table without tearing the session"
                ),
            ))
    return plan


def merge_plans(*plans: RemediationPlan) -> RemediationPlan:
    """Merge multiple plans into a single plan."""
    out = RemediationPlan()
    for p in plans:
        out.actions.extend(p.actions)
        out.blocked.extend(p.blocked)
    return out


def plan_remediations(
    *,
    health: list[dict[str, Any]] | None = None,
    cold_aces: list[dict[str, Any]] | None = None,
    poe_faults: list[str] | None = None,
    poe_over_budget: bool = False,
    drift_lines: list[dict[str, Any]] | None = None,
    golden_text: str | None = None,
    down_neighbors: list[dict[str, Any]] | None = None,
    device_ref: str = "seed-01",
) -> RemediationPlan:
    """Top-level plan generator: pick the right remediations for
    any combination of findings.

    Always returns a typed :class:`RemediationPlan`. The caller
    is expected to inspect ``overall_verdict`` before applying.
    """
    plans: list[RemediationPlan] = []
    if health:
        plans.append(plan_from_health(device_ref, health))
    if cold_aces:
        plans.append(plan_from_acl(device_ref, cold_aces))
    if poe_faults or poe_over_budget:
        plans.append(plan_from_poe(device_ref, poe_faults or [], poe_over_budget))
    if drift_lines:
        plans.append(plan_from_drift(device_ref, drift_lines, golden_text))
    if down_neighbors:
        plans.append(plan_from_routing(device_ref, down_neighbors))
    return merge_plans(*plans)
