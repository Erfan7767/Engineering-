"""E01 Day-0 Bootstrap Engine (D0-07 §5) — ordered, verified, reversible.

The plan comes from the device family's Access Profile ``bootstrap`` data
(never from vendor-name conditionals in code). Execution rules:

* ordered steps; each step VERIFIED before the next executes — a failed
  verification halts the whole sequence with a typed reason (never blind
  continuation);
* per-step Post-Bootstrap Baseline = rising running-config capture hash
  (FSM-3 target lineage, §5);
* templates whose profile flag ``verified=false`` are labeled honest seeds
  (OI-0171 family) — the plan exposes the flag, the EXECUTION still happens
  through real sessions only, and verification always uses READ_ONLY
  commands through the Collector (allowlist law untouched);
* the engine never authenticates by itself: credential material arrives via
  the injected config-session factory (vault boundary), never as engine
  state (L11).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, Protocol

from ..core.failures import Failure, FailureClass
from ..specs_data import specs_data_dir


class StepStatus(str, Enum):
    PLANNED = "PLANNED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    SKIPPED_NOT_MODELED = "SKIPPED_NOT_MODELED"


@dataclass(frozen=True)
class BootstrapStep:
    step_id: str
    commands: tuple[str, ...]           # rendered (hostname etc. substituted)
    verify_command: str
    verify_contains: Optional[str]      # None ⇒ capture-only verification
    verified_seed: bool                 # profile flag, surfaced honestly


@dataclass
class StepResult:
    step: BootstrapStep
    status: StepStatus = StepStatus.PLANNED
    baseline_sha256: Optional[str] = None
    failure_causes: tuple[str, ...] = ()


@dataclass(frozen=True)
class BootstrapReport:
    device_ref: str
    hostname: str
    steps: tuple[StepResult, ...]
    completed: bool
    halted_at: Optional[str]            # step_id where the sequence stopped
    ntp_state: str                      # LOCAL_ONLY | DEFERRED (D0-07 §5: never a failure)
    verified_seed: bool


class ConfigSession(Protocol):
    """A write-path session (serial console / SSH exec channel)."""

    def send(self, command: str, timeout_s: float) -> bytes: ...
    def close(self) -> None: ...


def load_bootstrap_steps(vendor_family_file: str, *, hostname: str) -> tuple[BootstrapStep, ...]:
    """Render the family's bootstrap template from its Access Profile.

    Missing profile/steps ⇒ typed BLOCKED (T2), never a default plan."""
    path_text = specs_data_dir("access_profiles", vendor_family_file)
    if not path_text:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"ACCESS_PROFILE_ABSENT: {vendor_family_file} not found in specs data pack",))
    doc = json.loads(open(path_text, encoding="utf-8").read())
    steps_out: list[BootstrapStep] = []
    found_any = False
    for profile in doc.get("profiles", []):
        bootstrap = profile.get("bootstrap")
        if bootstrap is None:
            continue
        found_any = True
        verified = bool(bootstrap.get("verified", False))
        for i, step in enumerate(bootstrap.get("steps", [])):
            commands = tuple(c.format(hostname=hostname) for c in step.get("commands", ()))
            verify_command = step.get("verify_command", "").format(hostname=hostname)
            verify_contains = step.get("verify_contains")
            if verify_contains:
                verify_contains = verify_contains.format(hostname=hostname)
            steps_out.append(BootstrapStep(
                step_id=f"{i + 1}:{step.get('step', 'unnamed')}",
                commands=commands, verify_command=verify_command,
                verify_contains=verify_contains, verified_seed=verified))
    if not found_any or not steps_out:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"BOOTSTRAP_NOT_MODELED: access profile {vendor_family_file} carries no "
            f"bootstrap template for this model family (T2 — never improvised)",))
    return tuple(steps_out)


class Day0BootstrapEngine:
    """Executes the profile's ordered bootstrap on a live config session."""

    def execute(
        self,
        *,
        device_ref: str,
        hostname: str,
        steps: tuple[BootstrapStep, ...],
        config_session_factory: Callable[[], ConfigSession],
        collect_capture_fn: Callable[[str], bytes],
        ntp_local_reachable: bool = False,
        max_step_timeout_s: float = 30.0,
    ) -> BootstrapReport:
        """``collect_capture_fn`` returns a running-config capture for the
        baseline hash; it is the CALLER's duty to route it through the
        Collector (allowlisted READ_ONLY) so evidence lands in the ledger."""
        results: list[StepResult] = []
        halted: Optional[str] = None
        session: Optional[ConfigSession] = None
        try:
            session = config_session_factory()
        except Failure as exc:
            return BootstrapReport(
                device_ref=device_ref, hostname=hostname, steps=tuple(
                    StepResult(step=s, status=StepStatus.PLANNED) for s in steps),
                completed=False, halted_at=steps[0].step_id if steps else None,
                ntp_state="DEFERRED", verified_seed=all(s.verified_seed for s in steps))

        for step in steps:
            result = StepResult(step=step)
            try:
                for command in step.commands:
                    session.send(command, max_step_timeout_s)
                # verification: capture predicate over allowlisted read-back
                capture = collect_capture_fn(step.verify_command)
                if step.verify_contains is not None and step.verify_contains.encode() not in capture:
                    result.status = StepStatus.FAILED
                    result.failure_causes = (
                        f"VERIFY_MISMATCH: {step.verify_contains!r} not in capture of {step.verify_command!r}",)
                else:
                    result.status = StepStatus.VERIFIED
                    result.baseline_sha256 = hashlib.sha256(capture).hexdigest()
            except (TimeoutError, ConnectionError) as exc:
                result.status = StepStatus.FAILED
                result.failure_causes = (f"TRANSPORT_ERROR: {type(exc).__name__}: {exc}",)
            except Failure as exc:
                result.status = StepStatus.FAILED
                result.failure_causes = tuple(exc.causes)
            results.append(result)
            if result.status is StepStatus.FAILED:
                halted = step.step_id
                break
        try:
            session.close()
        except Exception:
            pass  # close must never mask the typed outcome (L03 is in the results)
        completed = halted is None and all(r.status is StepStatus.VERIFIED for r in results)
        ntp_state = "LOCAL_ONLY" if ntp_local_reachable else "DEFERRED"
        return BootstrapReport(
            device_ref=device_ref, hostname=hostname, steps=tuple(results),
            completed=completed, halted_at=halted, ntp_state=ntp_state,
            verified_seed=all(s.verified_seed for s in steps))
