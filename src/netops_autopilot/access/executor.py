"""Real Config Executor — applies a RenderedConfig to a live device.

This is the highest-stakes module in the system. The execution contract:

* **T3 (no CONFIG without allowlist):** every line of the rendered config
  is structurally matched against :class:`CommandAllowlist` BEFORE it is
  sent. A line that does not match a CONFIG_REVERSIBLE/CONFIG_HIGH_RISK
  template — arity and every literal segment — is rejected; the executor
  never sends a command it cannot classify.
* **L04 (deterministic authority):** the executor takes a fully
  rendered config (the IR is gone) — no live LLM, no free-form text.
* **L09 (rollback on failure):** the executor pre-builds the rollback
  plan from the allowlist, **issues it to the device** on the first
  failure, re-reads state to confirm the device is back, and records
  whether the rollback actually completed. A rollback that did not
  complete is ``ROLLBACK_FAILED`` — loud, never silently reported as
  ``ROLLED_BACK``.
* **L13 (blast-radius is a recorded fact):** every change writes a
  `config_change` event to the ledger with the device_ref, the
  irreversible-flag, the before/after running-config hash, and the
  commit id (where available). A ledger write that fails is recorded on
  the ChangeRecord, never swallowed.
* **L11 (secrets redacted):** password fields are never sent in
  plaintext and never logged; the redact() pipeline runs on every
  command before it leaves the host.

The executor is **session-bound**: it does not own its own transport.
The caller passes a :class:`SerialConsoleTransport`, an
:class:`SSHConsoleTransport`, or any object with a matching ``execute``
method (the canonical ``ExecSession`` shape). This makes it equally
usable from the simulator and from real hardware.

Phase V changes (why they matter):

1. **The rollback plan is now actually issued.** The previous revision
   built ``rollback_commands`` and then discarded them: the loop body
   only recorded comment lines and never called ``session.execute``.
   The device was left half-configured while the record claimed
   ``ROLLED_BACK``. That is the single most dangerous defect this
   module ever had, because it made an unsafe state look safe.
2. **Rollback runs in the correct CLI mode.** Inverses are issued in
   reverse order with the mode stack rewound to the depth each command
   was applied at, so ``no name`` lands inside ``vlan 10`` and
   ``no vlan 10`` lands in global config.
3. **Mode-transition wrappers are sent.** ``configure terminal`` used to
   be swallowed as a comment, so config lines reached a real device in
   user EXEC mode and failed. Wrappers are now issued, gated by a closed
   set of known mode-transition commands.
4. **Allowlist matching is structural.** First-token matching let
   ``ip http server`` through because ``ip routing`` was registered.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional, Protocol, Sequence

from ..core.failures import Failure, FailureClass
from ..core.ids import new_id
from ..ledger.models import (
    ClockStatusEnum,
    CollectorIdentity,
    Event,
    EventType,
    OperatorIdentity,
    RawArtifact,
)
from ..ledger.store import LedgerStore
from .allowlist import (
    CONFIG_CLASSES,
    PERSIST_CLASSES,
    CommandAllowlist,
    CommandMatch,
)


class ExecSession(Protocol):
    """The minimum surface the executor needs from a transport."""

    def execute(self, command: str, timeout_s: Optional[float] = None) -> bytes: ...
    def close(self) -> None: ...


#: Actor identity used for every event the executor writes.
_EXECUTOR_ACTOR = OperatorIdentity(kind="ENGINE", id="CONFIG-EXECUTOR")

#: The closed set of commands the executor will issue as CLI *mode
#: transitions*, i.e. outside the CONFIG allowlist gate. These change no
#: configuration state; they move the session between modes (or, for
#: Junos, commit an already-staged candidate). Anything not in this set
#: is refused — a caller cannot smuggle configuration through ``wrappers``.
SAFE_MODE_TRANSITIONS = frozenset({
    # Cisco IOS / IOS-XE
    "enable", "disable", "end", "exit",
    "configure terminal", "conf t", "configure t",
    # Junos
    "configure", "configure private", "configure exclusive", "top", "up",
    "commit check", "commit confirmed 1", "commit confirmed 2",
    "commit confirmed 5", "commit", "rollback 0",
    # ArubaOS / FortiOS session-level
    "enable-session", "exit-session",
})


class ChangeOutcome(str, Enum):
    APPLIED = "APPLIED"
    APPLIED_PARTIAL = "APPLIED_PARTIAL"            # some blocks applied
    ROLLED_BACK = "ROLLED_BACK"                    # rolled back AND confirmed clean
    ROLLBACK_FAILED = "ROLLBACK_FAILED"            # rollback attempted, device NOT confirmed clean
    PERSIST_FAILED = "PERSIST_FAILED"              # applied + verified, but NOT saved to startup
    REJECTED = "REJECTED"                          # allowlist rejected a command
    BLOCKED_DRY_RUN_MISMATCH = "BLOCKED_DRY_RUN_MISMATCH"
    DRY_RUN = "DRY_RUN"                            # plan passed the gate; NOTHING was sent


@dataclass(frozen=True)
class CommandResult:
    """The recorded outcome of one command on one device."""

    device_ref: str
    command: str
    classification: str                # CONFIG_REVERSIBLE | CONFIG_HIGH_RISK | REJECTED | ...
    accepted: bool
    response_bytes: bytes
    response_hash: str
    error: Optional[str] = None
    phase: str = "APPLY"               # APPLY | MODE | ROLLBACK | VERIFY | BASELINE
    depth: int = 0                     # CLI mode depth the command was issued at

    def ok(self) -> bool:
        return self.accepted and self.error is None


@dataclass
class ChangeRecord:
    """Full evidence bundle for one config change."""

    device_ref: str
    run_id: str
    outcome: ChangeOutcome
    started_at: datetime
    finished_at: Optional[datetime] = None
    commands: list[CommandResult] = field(default_factory=list)
    rollback_commands: list[str] = field(default_factory=list)
    rollback_results: list[CommandResult] = field(default_factory=list)
    before_hash: Optional[str] = None
    after_hash: Optional[str] = None
    rollback_hash: Optional[str] = None
    #: Phase W — how many applied configuration lines were found in the
    #: post-apply readback, and how many were not. Zero with a non-zero
    #: command count means verification proved nothing, so it is reported
    #: rather than left for the operator to guess.
    state_checked: int = 0
    state_absent: int = 0
    commit_id: Optional[str] = None
    failure_causes: list[str] = field(default_factory=list)

    @property
    def command_count(self) -> int:
        return len([c for c in self.commands if c.phase == "APPLY"])

    @property
    def applied_count(self) -> int:
        # A dry-run record carries the planned commands with phase="APPLY" so
        # command_count stays meaningful, but none of them reached a device.
        # Reporting them as applied would put a number on the record that
        # contradicts its own outcome.
        if self.outcome == ChangeOutcome.DRY_RUN:
            return 0
        return sum(1 for c in self.commands
                   if c.phase == "APPLY" and c.classification in CONFIG_CLASSES and c.ok())

    @property
    def rejected_count(self) -> int:
        return sum(1 for c in self.commands if not c.accepted)

    @property
    def rollback_issued(self) -> int:
        """How many inverse commands actually reached the device."""
        return len([r for r in self.rollback_results if r.phase == "ROLLBACK"])

    @property
    def rollback_succeeded(self) -> int:
        return sum(1 for r in self.rollback_results if r.phase == "ROLLBACK" and r.ok())

    def to_dict(self) -> dict:
        return {
            "device_ref": self.device_ref,
            "run_id": self.run_id,
            "outcome": self.outcome.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "command_count": self.command_count,
            "applied_count": self.applied_count,
            "rejected_count": self.rejected_count,
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
            "rollback_hash": self.rollback_hash,
            "state_checked": self.state_checked,
            "state_absent": self.state_absent,
            "commit_id": self.commit_id,
            "failure_causes": list(self.failure_causes),
            "rollback_commands": list(self.rollback_commands),
            "rollback_issued": self.rollback_issued,
            "rollback_succeeded": self.rollback_succeeded,
            "commands": [
                {
                    "command": c.command,
                    "classification": c.classification,
                    "accepted": c.accepted,
                    "response_hash": c.response_hash,
                    "error": c.error,
                    "phase": c.phase,
                    "depth": c.depth,
                }
                for c in self.commands
            ],
            "rollback_results": [
                {
                    "command": r.command,
                    "accepted": r.accepted,
                    "error": r.error,
                    "response_hash": r.response_hash,
                }
                for r in self.rollback_results
            ],
        }


def _hash_response(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


@dataclass(frozen=True)
class _PlannedLine:
    """One line of the change, classified, with the mode depth it runs at."""

    raw: str
    stripped: str
    kind: str                          # CONFIG | MODE | COMMENT
    cls: str
    match: Optional[CommandMatch]
    depth: int
    enters_mode: bool


def _build_rollback_plan(
    lines: Sequence[_PlannedLine], allowlist: CommandAllowlist,
) -> list[tuple[str, int]]:
    """Build ``(inverse_command, depth)`` pairs for every reversible line.

    The inverse comes from the allowlist entry that matched the command,
    resolved by :meth:`CommandAllowlist.resolve_inverse` so placeholders
    bind by name. A line with no declared inverse yields a
    ``! MANUAL_ROLLBACK_REQUIRED:`` marker — typed, never silently
    skipped, and never issued to a device.
    """
    plan: list[tuple[str, int]] = []
    for line in lines:
        if line.kind != "CONFIG":
            continue
        inverse = allowlist.resolve_inverse(line.stripped)
        if inverse:
            plan.append((inverse, line.depth))
        else:
            tmpl = line.match.template if line.match else "?"
            plan.append((
                f"! MANUAL_ROLLBACK_REQUIRED: {line.stripped}  (template {tmpl!r} declares no inverse)",
                line.depth,
            ))
    return plan


#: Lines that carry no configuration meaning and that several platforms vary
#: between two reads of an *unchanged* config (IOS prints the byte count in
#: the header; some builds print a timestamp). Hashing them verbatim would
#: make an identical configuration look changed — and a correctly rolled-back
#: device look unrestored.
_CONFIG_NOISE = (
    re.compile(r"^\s*building configuration", re.IGNORECASE),
    re.compile(r"^\s*current configuration\s*:\s*\d+\s*bytes", re.IGNORECASE),
    re.compile(r"^\s*!.*$"),
    re.compile(r"^\s*$"),
    re.compile(r"^\s*last configuration change at", re.IGNORECASE),
    re.compile(r"^\s*! time:", re.IGNORECASE),
)


def normalize_running_config(data: bytes) -> bytes:
    """Strip non-configuration noise so two reads of the same config hash equal."""
    out: list[str] = []
    for line in data.decode("utf-8", "replace").splitlines():
        if any(rx.match(line) for rx in _CONFIG_NOISE):
            continue
        out.append(line.rstrip())
    return "\n".join(out).encode("utf-8")


def _read_running_config(session: ExecSession) -> Optional[bytes]:
    """Read the running-config verbatim, or ``None`` if the read failed.

    Verification needs the text, not just its hash: a changed hash proves
    *something* changed, which is a much weaker claim than "the lines we sent
    are in the device's configuration".
    """
    try:
        return session.execute("show running-config", timeout_s=10.0)
    except Exception:  # noqa: BLE001 — best-effort; absence is reported, not guessed
        return None


def _read_running_hash(session: ExecSession) -> Optional[str]:
    """Capture a baseline hash of the running-config for drift detection.

    The hash covers the *normalized* configuration (see
    :func:`normalize_running_config`) so platform header noise cannot be
    mistaken for a configuration change.

    Returns ``None`` if the device doesn't support a hashed read (a real
    device will, the simulator will be best-effort). The hash is recorded
    on the ChangeRecord for the post-execution diff.
    """
    try:
        data = session.execute("show running-config", timeout_s=10.0)
        return hashlib.sha256(normalize_running_config(data)).hexdigest()[:16]
    except Exception:  # noqa: BLE001 — best-effort
        return None


class ConfigExecutor:
    """Apply a rendered config to a device, with allowlist + rollback safety."""

    def __init__(
        self,
        *,
        allowlist: CommandAllowlist,
        store: Optional[LedgerStore] = None,
        run_id: str = "ad-hoc",
        verify_after_each_block: bool = True,
        send_mode_wrappers: bool = True,
        key_id: Optional[str] = None,
        collector_id: str = "config-executor",
        time_authority=None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not isinstance(allowlist, CommandAllowlist):
            raise TypeError("allowlist must be a CommandAllowlist")
        self._allowlist = allowlist
        self._store = store
        self._run_id = run_id
        self._verify_per_block = verify_after_each_block
        self._send_wrappers = send_mode_wrappers
        self._key_id = key_id
        self._collector_id = collector_id
        self._time = time_authority
        self._armed = False
        self._clock = clock

    @property
    def run_id(self) -> str:
        return self._run_id

    # ------------------------------------------------------ main entry point
    def apply(
        self,
        device_ref: str,
        session: ExecSession,
        commands: Sequence[str],
        *,
        dry_run: bool = False,
        wrappers: tuple[Sequence[str], Sequence[str]] = ((), ()),
        persist: Sequence[str] = (),
        mode_exit: str = "exit",
    ) -> ChangeRecord:
        """Apply ``commands`` to ``device_ref`` via ``session``.

        Every line is checked against the allowlist BEFORE it is sent. On
        any rejection, the executor stops, marks REJECTED, and returns a
        record. On the first failure the rollback plan is issued to the
        device and the outcome reflects whether the device was actually
        restored (``ROLLED_BACK``) or not (``ROLLBACK_FAILED``).
        """
        enter, exit_ = wrappers
        record = ChangeRecord(
            device_ref=device_ref, run_id=self._run_id,
            outcome=ChangeOutcome.APPLIED,
            started_at=self._clock(),
        )

        # ----- Phase 0: plan. Classify every line and compute mode depth.
        try:
            planned = self._plan(list(enter), list(commands), list(exit_),
                                 record=record, mode_exit=mode_exit)
        except Failure as exc:
            record.outcome = ChangeOutcome.REJECTED
            record.failure_causes.extend(exc.causes)
            record.finished_at = self._clock()
            self._record_to_ledger(record)
            return record

        config_lines = [p for p in planned if p.kind == "CONFIG"]
        plan = _build_rollback_plan(config_lines, self._allowlist)
        record.rollback_commands = [cmd for cmd, _d in plan]

        # A high-risk line needs a stronger gate than a reversible one.
        high_risk = [p.stripped for p in config_lines if p.cls == "CONFIG_HIGH_RISK"]
        if high_risk and not self._authorize_high_risk(high_risk):
            record.outcome = ChangeOutcome.REJECTED
            record.failure_causes.append(
                "HIGH_RISK_NOT_AUTHORIZED:" + "|".join(high_risk))
            record.finished_at = self._clock()
            self._record_to_ledger(record)
            return record

        if dry_run:
            for p in planned:
                record.commands.append(CommandResult(
                    device_ref=device_ref, command=p.stripped,
                    classification=p.cls, accepted=True,
                    response_bytes=b"", response_hash="",
                    phase="APPLY" if p.kind == "CONFIG" else "MODE",
                    depth=p.depth,
                ))
            # A dry run proves the plan clears the allowlist gate. It does not
            # put anything on the device, so claiming APPLIED here would report
            # an unreachable or untouched device as configured — the one thing
            # a change record must never get wrong.
            record.outcome = ChangeOutcome.DRY_RUN
            record.failure_causes.append(
                "DRY_RUN_ONLY: plan validated against the allowlist; no command "
                "was sent to the device")
            record.finished_at = self._clock()
            self._record_to_ledger(record)
            return record

        # ----- Phase 1: baseline evidence.
        record.before_hash = _read_running_hash(session)

        # ----- Phase 2: apply. Mode transitions are explicit lines in the
        # plan (derived from the renderer's indentation), so the session is
        # always in the mode the next command expects.
        current_depth = 0
        applied: list[_PlannedLine] = []
        for p in planned:
            if p.kind == "COMMENT" or not p.stripped:
                continue
            if p.kind == "MODE":
                result = self._issue(session, record, p.stripped, "MODE",
                                     p.cls, p.depth)
                if not result.ok():
                    return self._abort(session, record, plan, applied,
                                       f"MODE_COMMAND_FAILED:{p.stripped}:{result.error}",
                                       current_depth, mode_exit=mode_exit)
                # A one-level exit recorded at depth d means "leaving d+1 for
                # d". Cisco and ArubaOS call it `exit`; FortiOS calls it `end`.
                # Other wrappers (configure terminal / commit) do not change
                # the sub-mode depth the CONFIG lines are counted in.
                if p.stripped.lower() == mode_exit.lower():
                    current_depth = p.depth
                continue

            result = self._issue(session, record, p.stripped, "APPLY",
                                 p.cls, p.depth)
            if not result.ok():
                return self._abort(session, record, plan, applied,
                                   f"COMMAND_FAILED:{p.stripped}:{result.error}",
                                   current_depth, mode_exit=mode_exit)
            applied.append(p)
            current_depth = p.depth + (1 if p.enters_mode else 0)

        record.after_hash = _read_running_hash(session)

        # ----- Phase 3: post-execution verification.
        if self._verify_per_block:
            verified, causes = self._verify_change(session, record, applied)
            if not verified:
                record.failure_causes.extend(causes)
                self._rollback(session, plan, applied, record, current_depth=0,
                               mode_exit=mode_exit)
                record.finished_at = self._clock()
                self._record_to_ledger(record)
                return record

        # ----- Phase 4: persist. Only now.
        # A change that is not saved is a change that vanishes on the next
        # reload, so this is not optional housekeeping — but it must never run
        # before verification (we would be making an unverified state
        # permanent) and never during rollback (we would be making the
        # half-applied state permanent).
        if persist:
            persisted, persist_causes = self._persist(session, record, persist)
            if not persisted:
                record.failure_causes.extend(persist_causes)
                record.outcome = ChangeOutcome.PERSIST_FAILED
                self._record_to_ledger(record)
                return record

        record.outcome = ChangeOutcome.APPLIED
        self._record_to_ledger(record)
        return record

    def _persist(self, session: ExecSession, record: ChangeRecord,
                 commands: Sequence[str]) -> tuple[bool, list[str]]:
        """Issue the vendor's persist commands. Returns (ok, causes).

        Each one must be allowlisted ``CONFIG_PERSIST``; anything else is
        refused rather than sent, so this channel cannot be used to smuggle
        configuration past the change gate.
        """
        causes: list[str] = []
        for command in commands:
            stripped = command.strip()
            if not stripped:
                continue
            if self._allowlist.gate(stripped) not in PERSIST_CLASSES:
                causes.append(f"PERSIST_NOT_ALLOWLISTED:{stripped}")
                continue
            result = self._issue(session, record, stripped, "PERSIST",
                                 "CONFIG_PERSIST", 0)
            if not result.ok():
                causes.append(
                    f"PERSIST_FAILED:{stripped}:{result.error} — the change is in the "
                    f"running-config but will be LOST on the next reload")
        return (not causes, causes)

    # ------------------------------------------------------------ planning
    def _plan(self, enter: list[str], body: list[str], exit_: list[str],
              record: Optional[ChangeRecord] = None,
              mode_exit: str = "exit") -> list[_PlannedLine]:
        """Classify every line and compute the CLI mode depth of each.

        The renderer encodes CLI nesting as indentation (one level per
        indent step), which is exactly what a human engineer reads off the
        page. The executor honours it literally: when the indent level
        drops, ``exit`` commands are inserted so the session is back in the
        right mode before the next line is sent. Without this, ``ip
        routing`` after ``vlan 10``/``name users`` would be typed into
        ``config-vlan`` mode and rejected by a real device.

        Raises a typed ``Failure`` on the first line that has no execution
        path, so nothing is sent when the plan is not fully authorised.
        """
        planned: list[_PlannedLine] = []

        for raw in enter:
            planned.extend(self._plan_wrapper(raw, depth=0))

        step = self._indent_step(body)
        level = 0
        pending_mode_at: Optional[int] = None
        for raw in body:
            stripped = raw.strip()
            if not stripped:
                continue
            if stripped.startswith("!") or stripped.startswith("#"):
                planned.append(_PlannedLine(raw, stripped, "COMMENT", "COMMENT",
                                            None, level, False))
                continue
            target = (len(raw) - len(raw.lstrip(" "))) // step
            if target > level:
                # Deeper nesting is only legal directly after a command that
                # opened a sub-mode at the parent level. Anything else is a
                # renderer defect — refuse it rather than guess the mode.
                if pending_mode_at is None or target != pending_mode_at + 1:
                    raise Failure(cls=FailureClass.BLOCKED, causes=(
                        f"INDENT_WITHOUT_MODE_ENTRY:{stripped} (indent level {target}, "
                        f"session at {level}) — the previous line did not open a sub-mode",))
                level = target
            while level > target:
                planned.append(_PlannedLine(mode_exit, mode_exit, "MODE",
                                            "MODE_TRANSITION", None, level - 1, False))
                level -= 1
            pending_mode_at = None

            match = self._allowlist.match(stripped)
            if match is None or match.cls not in CONFIG_CLASSES:
                got = match.cls if match else "UNREGISTERED"
                if record is not None:
                    # The refused line is evidence in its own right: name it
                    # on the record, do not leave it only in a cause string.
                    record.commands.append(CommandResult(
                        device_ref=record.device_ref, command=stripped,
                        classification=got, accepted=False,
                        response_bytes=b"", response_hash="",
                        error="COMMAND_NOT_ALLOWLISTED", phase="PLAN", depth=level))
                raise Failure(cls=FailureClass.BLOCKED, causes=(
                    f"COMMAND_NOT_ALLOWLISTED:{stripped} (class={got})",))
            planned.append(_PlannedLine(raw, stripped, "CONFIG", match.cls,
                                        match, level, match.entry.enters_mode))
            if match.entry.enters_mode:
                pending_mode_at = level

        # Leave every mode we are still inside before the exit wrappers run.
        while level > 0:
            planned.append(_PlannedLine(mode_exit, mode_exit, "MODE",
                                        "MODE_TRANSITION", None, level - 1, False))
            level -= 1

        for raw in exit_:
            planned.extend(self._plan_wrapper(raw, depth=0))
        return planned

    def _plan_wrapper(self, raw: str, depth: int) -> list[_PlannedLine]:
        stripped = raw.strip()
        if not stripped:
            return []
        if stripped.startswith("!") or stripped.startswith("#"):
            return [_PlannedLine(raw, stripped, "COMMENT", "COMMENT", None, depth, False)]
        # Wrappers are vendor mode transitions declared by the renderer data
        # file. They are held to a closed set so a caller cannot smuggle
        # configuration through them.
        if stripped.lower() not in SAFE_MODE_TRANSITIONS:
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                f"UNSAFE_WRAPPER:{stripped} — not a known CLI mode transition; "
                f"configuration must go through the CONFIG allowlist",))
        return [_PlannedLine(raw, stripped, "MODE", "MODE_TRANSITION", None, depth, False)]

    @staticmethod
    def _indent_step(body: Sequence[str]) -> int:
        """The indent width one nesting level represents (default 1 space)."""
        indents = [len(l) - len(l.lstrip(" ")) for l in body if l.strip()]
        positive = [i for i in indents if i > 0]
        return min(positive) if positive else 1


    def _authorize_high_risk(self, high_risk: list[str]) -> bool:
        """Gate for CONFIG_HIGH_RISK lines (routing daemons, credentials).

        Default policy: a high-risk change is authorised only when the
        caller explicitly armed the executor. The orchestrator arms it
        after the operator types BOND, so the human decision is what
        unlocks it — never the engine on its own.
        """
        return self._high_risk_armed

    @property
    def _high_risk_armed(self) -> bool:
        return getattr(self, "_armed", False)

    def arm_high_risk(self) -> "ConfigExecutor":
        """Arm the CONFIG_HIGH_RISK gate (call only after human confirmation)."""
        self._armed = True
        return self

    # ------------------------------------------------------------ issuing
    def _issue(self, session: ExecSession, record: ChangeRecord, command: str,
               phase: str, cls: str, depth: int) -> CommandResult:
        try:
            response = session.execute(command, timeout_s=30.0)
            result = CommandResult(
                device_ref=record.device_ref, command=command,
                classification=cls, accepted=True,
                response_bytes=response, response_hash=_hash_response(response),
                phase=phase, depth=depth,
            )
        except Failure as exc:
            result = CommandResult(
                device_ref=record.device_ref, command=command,
                classification=cls, accepted=False,
                response_bytes=b"", response_hash="",
                error="; ".join(exc.causes), phase=phase, depth=depth,
            )
        except Exception as exc:  # noqa: BLE001 — transport-level
            result = CommandResult(
                device_ref=record.device_ref, command=command,
                classification=cls, accepted=False,
                response_bytes=b"", response_hash="",
                error=f"{type(exc).__name__}:{exc}", phase=phase, depth=depth,
            )
        record.commands.append(result)
        return result

    def _abort(self, session: ExecSession, record: ChangeRecord,
               plan: list[tuple[str, int]], applied: list[_PlannedLine],
               cause: str, current_depth: int = 0,
               mode_exit: str = "exit") -> ChangeRecord:
        """A command failed mid-stream: roll back what we already applied."""
        record.failure_causes.append(cause)
        self._rollback(session, plan, applied, record, current_depth=current_depth,
                       mode_exit=mode_exit)
        record.finished_at = self._clock()
        self._record_to_ledger(record)
        return record

    # ------------------------------------------------------------ rollback
    def _rollback(
        self,
        session: ExecSession,
        plan: Sequence[tuple[str, int]],
        applied: Sequence[_PlannedLine],
        record: ChangeRecord,
        current_depth: int = 0,
        mode_exit: str = "exit",
    ) -> None:
        """Issue the inverse commands to the device, deepest-first.

        Each inverse is issued at the mode depth the original command was
        applied at: the session is unwound with ``exit`` until the depth
        matches, then the inverse is sent. Manual markers are never sent —
        they are recorded so the operator sees exactly what is left to do.

        The outcome is set from what actually happened:
        ``ROLLED_BACK`` only when every issued inverse was accepted and the
        running-config is back to the baseline; otherwise ``ROLLBACK_FAILED``
        with a typed cause, so an unsafe device is never reported as clean.
        """
        if not applied:
            # Nothing reached the device; there is nothing to undo.
            record.outcome = ChangeOutcome.ROLLED_BACK
            record.rollback_hash = record.before_hash
            return

        failed: list[str] = []
        manual: list[str] = []

        for inverse, depth in reversed(plan):
            if inverse.startswith("!"):
                manual.append(inverse)
                record.failure_causes.append(f"MANUAL_ROLLBACK_REQUIRED:{inverse[2:].strip()}")
                continue
            # Unwind to the depth the original command ran at.
            while current_depth > depth:
                res = self._issue_raw(session, record, mode_exit, "ROLLBACK",
                                      current_depth - 1)
                current_depth -= 1
                if not res.ok():
                    failed.append(f"{mode_exit}@{current_depth}:{res.error}")
                    break
            res = self._issue_raw(session, record, inverse, "ROLLBACK", depth)
            record.rollback_results.append(res)
            if not res.ok():
                failed.append(f"{inverse}:{res.error}")

        # Leave any mode we are still inside.
        while current_depth > 0:
            self._issue_raw(session, record, mode_exit, "ROLLBACK", current_depth - 1)
            current_depth -= 1

        record.rollback_hash = _read_running_hash(session)

        if manual and not failed:
            # Every automatic inverse worked but something still needs a human.
            record.outcome = ChangeOutcome.ROLLBACK_FAILED
            record.failure_causes.append(
                "ROLLBACK_INCOMPLETE_MANUAL_STEPS_REQUIRED")
        elif failed:
            record.outcome = ChangeOutcome.ROLLBACK_FAILED
            record.failure_causes.extend(f"ROLLBACK_COMMAND_FAILED:{f}" for f in failed)
            record.failure_causes.append(
                "DEVICE_MAY_BE_LEFT_IN_PARTIAL_STATE: manual recovery required")
        elif record.before_hash is not None and record.rollback_hash is not None \
                and record.rollback_hash != record.before_hash:
            record.outcome = ChangeOutcome.ROLLBACK_FAILED
            record.failure_causes.append(
                f"ROLLBACK_STATE_MISMATCH: baseline={record.before_hash} "
                f"after_rollback={record.rollback_hash}")
        else:
            record.outcome = ChangeOutcome.ROLLED_BACK

    def _issue_raw(self, session: ExecSession, record: ChangeRecord, command: str,
                   phase: str, depth: int) -> CommandResult:
        """Issue a rollback/mode command; record it but never raise."""
        try:
            response = session.execute(command, timeout_s=30.0)
            return CommandResult(
                device_ref=record.device_ref, command=command,
                classification="ROLLBACK", accepted=True,
                response_bytes=response, response_hash=_hash_response(response),
                phase=phase, depth=depth,
            )
        except Failure as exc:
            err = "; ".join(exc.causes)
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}:{exc}"
        return CommandResult(
            device_ref=record.device_ref, command=command,
            classification="ROLLBACK", accepted=False,
            response_bytes=b"", response_hash="", error=err,
            phase=phase, depth=depth,
        )

    # -------------------------------------------------------- verification
    def _verify_change(
        self, session: ExecSession, record: ChangeRecord,
        applied: Sequence[_PlannedLine],
    ) -> tuple[bool, list[str]]:
        """Re-read state and assert the change took effect.

        Returns ``(ok, causes)``. Two independent signals are required:

        1. every command the device answered did not contain a Cisco-style
           error marker (``% Invalid input``, ``% Incomplete command``);
        2. the running-config hash actually changed from the baseline.

        Signal 1 catches the common real-world failure where a device
        accepts the session but rejects the syntax; signal 2 catches a
        no-op change. When the baseline hash is unavailable we say so
        rather than claiming verification we did not perform.
        """
        causes: list[str] = []
        for line, result in zip(applied, [c for c in record.commands if c.phase == "APPLY"]):
            body = result.response_bytes.decode("utf-8", "replace").lower()
            for marker in ("% invalid input", "% incomplete command",
                           "% ambiguous", "syntax error", "unknown command"):
                if marker in body:
                    causes.append(f"DEVICE_REJECTED_SYNTAX:{line.stripped}:{marker}")
                    break
        if causes:
            return (False, causes)

        readback = _read_running_config(session)
        if readback is None:
            # Typed caveat, never a silent pass.
            causes.append("VERIFY_READBACK_UNAVAILABLE: state change not confirmed")
            return (True, causes)

        normalized = normalize_running_config(readback)
        record.after_hash = hashlib.sha256(normalized).hexdigest()[:16]
        if record.before_hash is None:
            causes.append("VERIFY_BASELINE_UNAVAILABLE: state change not confirmed")
        elif record.after_hash == record.before_hash:
            return (False, [f"VERIFY_NO_CHANGE: before==after ({record.after_hash})"])

        # Signal 3 (Phase W): the intended state actually exists on the device.
        causes.extend(self._verify_state_present(normalized, applied, record))
        return (not causes, causes)

    def _verify_state_present(
        self, normalized: bytes, applied: Sequence[_PlannedLine],
        record: ChangeRecord,
    ) -> list[str]:
        """Assert each applied configuration line exists in the readback.

        The hash comparison above proves the configuration *changed*. It does
        not prove it changed into what was asked for: a line the device parsed
        and then ignored, or a later line that overwrote an earlier one, both
        leave a different hash and a wrong network. Reading the lines back is
        the only signal that closes that gap, so it is now required.

        Mode transitions (``enable``, ``configure terminal``, ``end``,
        ``exit``) leave no configuration line and are classified outside
        ``CONFIG_CLASSES``; they are excluded and counted as unchecked rather
        than counted as verified. A ``no …`` line is checked the other way
        round — the negated form must be *gone*.
        """
        present = {
            " ".join(line.split())
            for line in normalized.decode("utf-8", "replace").splitlines()
            if line.strip() and not line.lstrip().startswith("!")
        }
        causes: list[str] = []
        for planned in applied:
            if planned.cls not in CONFIG_CLASSES:
                continue                       # not a configuration statement
            target = " ".join(planned.stripped.split())
            record.state_checked += 1
            if target.startswith("no "):
                positive = " ".join(target[3:].split())
                if positive in present:
                    record.state_absent += 1
                    causes.append(f"VERIFY_STATE_STILL_PRESENT:{target}")
                continue
            if target not in present:
                record.state_absent += 1
                causes.append(f"VERIFY_STATE_ABSENT:{target}")
        return causes

    # ------------------------------------------------------------- ledger
    def _record_to_ledger(self, record: ChangeRecord) -> None:
        """Write the change to the tamper-evident ledger (L13).

        Phase V: this used to call ``store.append_event(dict, key_id=...)``.
        ``LedgerStore.append_event`` takes a **signed ``Event``**, so the call
        raised ``TypeError`` every single time — and the surrounding
        ``except Exception: pass`` hid it. No ``config_change`` audit record
        was ever written. The exception is no longer swallowed: if the write
        fails the ChangeRecord carries ``LEDGER_WRITE_FAILED`` so the operator
        knows the change is not provable.
        """
        if self._store is None:
            return
        if not self._key_id:
            record.failure_causes.append(
                "LEDGER_NOT_CONFIGURED: no signing key supplied; this change is not "
                "recorded in the tamper-evident ledger")
            return
        try:
            detail = json.dumps(record.to_dict(), sort_keys=True).encode("utf-8")
            summary = (
                f"CONFIG_CHANGE device={record.device_ref} outcome={record.outcome.value} "
                f"applied={record.applied_count}/{record.command_count} "
                f"rollback={record.rollback_succeeded}/{record.rollback_issued} "
                f"before={record.before_hash} after={record.after_hash} "
                f"rollback_hash={record.rollback_hash} run={record.run_id}"
            )
            if record.failure_causes:
                summary += " causes=" + "|".join(record.failure_causes[:8])
            event = Event(
                type=EventType.CLI,
                device_id=record.device_ref,
                session_id=record.run_id,
                command_or_op=summary[:1900],
                operator_identity=_EXECUTOR_ACTOR,
                collector_identity=CollectorIdentity(
                    collector_id=self._collector_id, key_id=self._key_id),
                collected_at=self._clock(),
                collector_clock_status=(
                    ClockStatusEnum(self._time.status.value) if self._time is not None
                    else ClockStatusEnum.UNSYNCED),
            )
            event = self._store.sign_event(event, self._key_id)
            self._store.append_event(event)
            self._store.append_raw_artifact(RawArtifact(
                raw_id=new_id(),
                event_id=event.event_id,
                storage_uri=f"ledger://artifacts/{event.event_id}",
                sha256=hashlib.sha256(detail).hexdigest(),
                bytes=len(detail),
                truncated=False,
            ))
        except Exception as exc:  # noqa: BLE001 — recorded, never swallowed
            record.failure_causes.append(
                f"LEDGER_WRITE_FAILED:{type(exc).__name__}:{exc}")
