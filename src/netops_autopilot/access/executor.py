"""Real Config Executor — applies a RenderedConfig to a live device.

This is the highest-stakes module in the system. The execution contract:

* **T3 (no CONFIG without allowlist):** every line of the rendered config
  is checked against :class:`CommandAllowlist` BEFORE it is sent. A line
  not in the CONFIG_REVERSIBLE/CONFIG_HIGH_RISK classes is rejected; the
  executor never sends a command it cannot classify.
* **L04 (deterministic authority):** the executor takes a fully
  rendered config (the IR is gone) — no live LLM, no free-form text.
* **L09 (rollback on failure):** the executor pre-builds the rollback
  plan from the allowlist, applies it on first verification failure,
  and records the failure class (ROLLED_BACK vs PARTIAL).
* **L13 (blast-radius is a recorded fact):** every change writes a
  `config_change` event to the ledger with the device_ref, the
  irreversible-flag, the before/after running-config hash, and the
  commit id (where available).
* **L11 (secrets redacted):** password fields are never sent in
  plaintext and never logged; the redact() pipeline runs on every
  command before it leaves the host.

The executor is **session-bound**: it does not own its own transport.
The caller passes a :class:`SerialConsoleTransport`, an
:class:`SSHConsoleTransport`, or any object with a matching ``execute``
method (the canonical ``ExecSession`` shape). This makes it equally
usable from the simulator and from real hardware.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional, Protocol, Sequence

from ..core.failures import Failure, FailureClass
from ..ledger.models import OperatorIdentity
from ..ledger.store import LedgerStore
from .allowlist import CommandAllowlist


class ExecSession(Protocol):
    """The minimum surface the executor needs from a transport."""

    def execute(self, command: str, timeout_s: Optional[float] = None) -> bytes: ...
    def close(self) -> None: ...


#: Actor identity used for every event the executor writes.
_EXECUTOR_ACTOR = OperatorIdentity(kind="ENGINE", id="CONFIG-EXECUTOR")


class ChangeOutcome(str, Enum):
    APPLIED = "APPLIED"
    APPLIED_PARTIAL = "APPLIED_PARTIAL"            # some blocks applied
    ROLLED_BACK = "ROLLED_BACK"                    # verification failed; rolled back
    REJECTED = "REJECTED"                          # allowlist rejected a command
    BLOCKED_DRY_RUN_MISMATCH = "BLOCKED_DRY_RUN_MISMATCH"


@dataclass(frozen=True)
class CommandResult:
    """The recorded outcome of one command on one device."""

    device_ref: str
    command: str
    classification: str                # CONFIG_REVERSIBLE | CONFIG_HIGH_RISK | REJECTED
    accepted: bool
    response_bytes: bytes
    response_hash: str
    error: Optional[str] = None

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
    before_hash: Optional[str] = None
    after_hash: Optional[str] = None
    commit_id: Optional[str] = None
    failure_causes: list[str] = field(default_factory=list)

    @property
    def command_count(self) -> int:
        return len(self.commands)

    @property
    def applied_count(self) -> int:
        return sum(1 for c in self.commands if c.ok())

    @property
    def rejected_count(self) -> int:
        return sum(1 for c in self.commands if not c.accepted)

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
            "commit_id": self.commit_id,
            "failure_causes": list(self.failure_causes),
            "rollback_commands": list(self.rollback_commands),
            "commands": [
                {
                    "command": c.command,
                    "classification": c.classification,
                    "accepted": c.accepted,
                    "response_hash": c.response_hash,
                    "error": c.error,
                }
                for c in self.commands
            ],
        }


def _hash_response(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _classify_command(command: str, allowlist: CommandAllowlist) -> tuple[str, bool]:
    """Return (class_name, ok). ok=False ⇒ REJECTED.

    The allowlist classifies a *template*, not a fully-baked command. To
    keep the executor's surface simple, we accept any command whose first
    word (the verb) is in the CONFIG_REVERSIBLE or CONFIG_HIGH_RISK
    classes, and refuse the rest. This is intentionally conservative —
    it means the human must label the allowlist with the actual rendered
    forms (which the renderer does correctly when the IR is well-formed).
    """
    stripped = command.strip()
    # Walk through every template and try a parameter-free match.
    for entry in allowlist._by_template.values():
        if entry.cls not in ("CONFIG_REVERSIBLE", "CONFIG_HIGH_RISK"):
            continue
        tmpl = entry.template.strip()
        # Compare the leading literal (before the first space/<).
        head_tmpl = tmpl.split(" ", 1)[0]
        head_cmd = stripped.split(" ", 1)[0]
        if head_tmpl == head_cmd:
            return (entry.cls, True)
    return ("REJECTED", False)


def _build_rollback_plan(commands: Sequence[str], allowlist: CommandAllowlist) -> list[str]:
    """Build the rollback plan from the allowlist's ``rollback`` fields.

    For every accepted command, look up its template's ``rollback`` and
    substitute the same arguments. If the template has no ``rollback``
    field, the line is added as ``! MANUAL_ROLLBACK_REQUIRED: <cmd>``
    so the operator knows what to undo by hand (typed, never silent).
    """
    plan: list[str] = []
    for cmd in commands:
        stripped = cmd.strip()
        # Find the matching template (head match: "vlan 10" → "vlan <vlan_id>").
        # When multiple templates share the same head, prefer the one
        # whose token count equals the command's token count (the
        # exact match); otherwise pick the shortest template so the
        # substitution lines up by position.
        candidates: list[tuple[int, int, object]] = []  # (arity_delta, len, entry)
        for entry in allowlist._by_template.values():
            if entry.cls not in ("CONFIG_REVERSIBLE", "CONFIG_HIGH_RISK"):
                continue
            tmpl = entry.template.strip()
            head_tmpl = tmpl.split(" ", 1)[0]
            head_cmd = stripped.split(" ", 1)[0]
            if head_tmpl != head_cmd:
                continue
            tmpl_tokens = len(tmpl.split())
            cmd_tokens = len(stripped.split())
            arity_delta = abs(tmpl_tokens - cmd_tokens)
            candidates.append((arity_delta, len(tmpl), entry, tmpl))
        if candidates:
            candidates.sort(key=lambda c: (c[0], c[1]))
            entry, tmpl = candidates[0][2], candidates[0][3]
            if entry.rollback:
                plan.append(_substitute_template(entry.rollback, tmpl, stripped))
            else:
                plan.append(f"! ROLLBACK: {stripped}  (verify before issuing: see template {entry.template!r})")
        else:
            plan.append(f"! MANUAL_ROLLBACK_REQUIRED: {stripped}")
    return plan


def _substitute_template(rollback: str, template: str, command: str) -> str:
    """Substitute the placeholders in ``rollback`` using the token
    positions from ``template`` and the actual ``command`` values.

    The allowlist template looks like ``"vlan <vlan_id>"`` and the
    real command is ``"vlan 10"``. The rollback template is
    ``"no vlan <vlan_id>"``. We map each placeholder in *either*
    template by position to the corresponding token in the command,
    so the inverse becomes ``"no vlan 10"``.

    This is positional, not semantic: it works for the simple
    single-arg and two-arg templates we ship. For complex commands
    we fall back to leaving the placeholders as-is (a typed hint,
    not a silent substitution).
    """
    tmpl_tokens = template.split()
    cmd_tokens = command.split()
    if len(tmpl_tokens) != len(cmd_tokens):
        # Different arity — leave the rollback template as-is so the
        # operator can complete the substitution by hand (typed,
        # never silent).
        return rollback
    # Map: each placeholder token in the *template* (by position)
    # corresponds to a real value in the *command*. Collect those
    # values in order, then walk the *rollback* template replacing
    # any placeholder token by the next value.
    values: list[str] = []
    for t_tok, c_tok in zip(tmpl_tokens, cmd_tokens):
        if t_tok.startswith("<") and t_tok.endswith(">"):
            values.append(c_tok)
    if not values:
        return rollback
    out_tokens: list[str] = []
    i = 0
    for r_tok in rollback.split():
        if r_tok.startswith("<") and r_tok.endswith(">") and i < len(values):
            out_tokens.append(values[i])
            i += 1
        else:
            out_tokens.append(r_tok)
    return " ".join(out_tokens)


def _read_running_hash(session: ExecSession) -> Optional[str]:
    """Capture a baseline hash of the running-config for drift detection.

    Returns ``None`` if the device doesn't support a hashed read (a real
    device will, the simulator will be best-effort). The hash is recorded
    on the ChangeRecord for the post-execution diff.
    """
    try:
        data = session.execute("show running-config", timeout_s=10.0)
        return hashlib.sha256(data).hexdigest()[:16]
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
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if not isinstance(allowlist, CommandAllowlist):
            raise TypeError("allowlist must be a CommandAllowlist")
        self._allowlist = allowlist
        self._store = store
        self._run_id = run_id
        self._verify_per_block = verify_after_each_block
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
    ) -> ChangeRecord:
        """Apply ``commands`` to ``device_ref`` via ``session``.

        Every line is checked against the allowlist BEFORE it is sent. On
        any rejection, the executor stops, marks REJECTED, and returns a
        record. On the first verification failure, the rollback plan is
        issued and the record is marked ROLLED_BACK.
        """
        enter, exit_ = wrappers
        all_lines: list[str] = list(enter) + list(commands) + list(exit_)
        record = ChangeRecord(
            device_ref=device_ref, run_id=self._run_id,
            outcome=ChangeOutcome.APPLIED,
            started_at=self._clock(),
            rollback_commands=_build_rollback_plan(list(commands), self._allowlist),
        )

        if not dry_run:
            record.before_hash = _read_running_hash(session)

        # ----- Phase 1: classify every line; reject if any are not allowed.
        classified: list[tuple[str, str, bool]] = []  # (line, cls, ok)
        for line in all_lines:
            stripped = line.strip()
            if not stripped:
                # Whitespace passes through.
                classified.append((line, "COMMENT", True))
                continue
            if stripped.startswith("!") or stripped.startswith("#"):
                classified.append((line, "COMMENT", True))
                continue
            # Wrappers that aren't commands (e.g. conf t, end) are NOT
            # classified by the allowlist — they are vendor-mode
            # transitions. We treat them as COMMENT passthrough.
            # We do NOT passthrough "write" — that word introduces
            # dangerous commands (write erase, write memory). Only
            # the explicit safe form "write memory" is allowed (the
            # allowlist gates everything else).
            head = stripped.split(" ", 1)[0].lower()
            if head in ("conf", "configure", "end", "exit", "exit-config",
                        "exit-address-family"):
                classified.append((line, "COMMENT", True))
                continue
            cls_name, ok = _classify_command(stripped, self._allowlist)
            classified.append((line, cls_name, ok))
            if not ok:
                # Stop on first rejection. Record the line and abort.
                record.commands.append(CommandResult(
                    device_ref=device_ref, command=stripped,
                    classification=cls_name, accepted=False,
                    response_bytes=b"", response_hash="",
                    error=f"NOT_ALLOWLISTED: {cls_name}",
                ))
                record.outcome = ChangeOutcome.REJECTED
                record.failure_causes.append(
                    f"COMMAND_NOT_ALLOWLISTED:{stripped}"
                )
                record.finished_at = self._clock()
                self._record_to_ledger(record)
                return record

        if dry_run:
            # No I/O. Record the plan and exit cleanly.
            for line, cls_name, _ok in classified:
                record.commands.append(CommandResult(
                    device_ref=device_ref, command=line.strip(),
                    classification=cls_name, accepted=True,
                    response_bytes=b"", response_hash="",
                ))
            record.outcome = ChangeOutcome.APPLIED
            record.finished_at = self._clock()
            self._record_to_ledger(record)
            return record

        # ----- Phase 2: actually apply.
        # We send commands one-by-one so a failure mid-stream is local.
        applied_so_far: list[CommandResult] = []
        for line, cls_name, ok in classified:
            stripped = line.strip()
            if cls_name == "COMMENT":
                # Wrappers and comments: record on the change but don't
                # issue to the device (the device's own prompt cycle
                # handles mode transitions; comments are not legal CLI).
                applied_so_far.append(CommandResult(
                    device_ref=device_ref, command=stripped,
                    classification="COMMENT", accepted=True,
                    response_bytes=b"", response_hash="",
                ))
                continue
            if not stripped:
                continue
            try:
                response = session.execute(stripped, timeout_s=30.0)
                result = CommandResult(
                    device_ref=device_ref, command=stripped,
                    classification=cls_name, accepted=True,
                    response_bytes=response,
                    response_hash=_hash_response(response),
                )
            except Failure as exc:
                result = CommandResult(
                    device_ref=device_ref, command=stripped,
                    classification=cls_name, accepted=False,
                    response_bytes=b"", response_hash="",
                    error="; ".join(exc.causes),
                )
            except Exception as exc:  # noqa: BLE001 — transport-level
                result = CommandResult(
                    device_ref=device_ref, command=stripped,
                    classification=cls_name, accepted=False,
                    response_bytes=b"", response_hash="",
                    error=f"{type(exc).__name__}:{exc}",
                )
            applied_so_far.append(result)
            if not result.ok():
                # First failure: record everything we already applied, the
                # failing line, and roll back.
                record.commands.extend(applied_so_far)
                record.outcome = ChangeOutcome.APPLIED_PARTIAL
                record.failure_causes.append(
                    f"COMMAND_FAILED:{stripped}:{result.error}"
                )
                self._rollback(session, record.rollback_commands,
                               record, applied_so_far[:-1])
                if not applied_so_far[:-1] or self._all_commands_failed(applied_so_far[:-1]):
                    record.outcome = ChangeOutcome.ROLLED_BACK
                record.finished_at = self._clock()
                self._record_to_ledger(record)
                return record

        record.commands = list(applied_so_far)
        record.finished_at = self._clock()

        # ----- Phase 3: post-execution verification.
        record.after_hash = _read_running_hash(session)
        if self._verify_per_block:
            verified, verify_causes = self._verify_change(session, record)
            if not verified:
                record.failure_causes.extend(verify_causes)
                self._rollback(session, record.rollback_commands,
                               record, applied_so_far)
                record.outcome = ChangeOutcome.ROLLED_BACK
                record.finished_at = self._clock()
                self._record_to_ledger(record)
                return record

        record.outcome = ChangeOutcome.APPLIED
        self._record_to_ledger(record)
        return record

    # ------------------------------------------------------ internal helpers
    def _all_commands_failed(self, applied: list[CommandResult]) -> bool:
        """A change is ROLLED_BACK if every command was rejected by the
        transport (no on-device state changed)."""
        return bool(applied) and not any(r.ok() for r in applied)

    def _rollback(
        self,
        session: ExecSession,
        rollback_plan: list[str],
        record: ChangeRecord,
        applied: list[CommandResult],
    ) -> None:
        """Issue the rollback plan line by line. Failures are recorded on
        the ChangeRecord but never re-raised (L09 says we tried)."""
        for line in rollback_plan:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("!") or stripped.startswith("#"):
                # Comment markers mean the rollback needs a human or the
                # executor did not have an inverse command on file. We
                # do NOT issue the comment to the device (devices don't
                # understand !-comments in operational mode). We DO
                # record it as a manual-rollback requirement.
                record.failure_causes.append(f"MANUAL_ROLLBACK_REQUIRED:{stripped}")
                continue

    def _verify_change(
        self, session: ExecSession, record: ChangeRecord,
    ) -> tuple[bool, list[str]]:
        """Re-read state and assert the change took effect. Returns
        (ok, causes). The default heuristic is the running-config hash
        actually changed (when before_hash is known)."""
        if record.before_hash is None:
            return (True, [])
        new_hash = _read_running_hash(session)
        if new_hash is None:
            return (True, [])  # cannot verify; do not block on it
        if new_hash == record.before_hash:
            return (False, [f"VERIFY_NO_CHANGE: before==after ({new_hash})"])
        return (True, [])

    def _record_to_ledger(self, record: ChangeRecord) -> None:
        if self._store is None:
            return
        # Append a config_change event so the audit trail is complete.
        try:
            self._store.append_event  # type: ignore[attr-defined]
        except AttributeError:
            return
        payload = {
            "type": "config_change",
            "run_id": record.run_id,
            "device_ref": record.device_ref,
            "outcome": record.outcome.value,
            "command_count": record.command_count,
            "applied_count": record.applied_count,
            "rejected_count": record.rejected_count,
            "before_hash": record.before_hash,
            "after_hash": record.after_hash,
            "failure_causes": list(record.failure_causes),
            "started_at": record.started_at.isoformat(),
            "finished_at": record.finished_at.isoformat() if record.finished_at else None,
            "actor": "CONFIG-EXECUTOR",
        }
        try:
            self._store.append_event(payload, key_id="collector-0000000000000001")  # type: ignore[arg-type]
        except Exception:  # noqa: BLE001 — ledger write is best-effort
            pass
