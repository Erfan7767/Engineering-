"""Output/time budgets per (device, command) (D0-08 §1, TH-09).

Budgets bound every collector command. Overflow produces a *truncated*
artifact with a recorded reason — never a silent drop, never an unbounded
read (L03).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CommandBudget:
    """Per-command limits. Defaults are conservative desktop values."""

    timeout_s: float = 30.0
    max_output_bytes: int = 1_000_000
    max_retries: int = 2
    breaker_threshold: int = 5  # consecutive failures before circuit opens

    def __post_init__(self) -> None:
        if self.timeout_s <= 0 or self.max_output_bytes <= 0 or self.max_retries < 0 or self.breaker_threshold < 1:
            raise ValueError("budget fields must be positive (max_retries >= 0)")


def enforce_output_budget(payload: bytes, budget: CommandBudget) -> tuple[bytes, bool, str | None]:
    """Clamp collector output to the budget.

    Returns ``(payload, truncated, budget_reason)``. ``budget_reason`` is
    mandatory whenever ``truncated`` is true (RawArtifact schema allOf).
    """
    if len(payload) <= budget.max_output_bytes:
        return payload, False, None
    return (
        payload[: budget.max_output_bytes],
        True,
        f"OUTPUT_BUDGET_EXCEEDED: {len(payload)} > {budget.max_output_bytes} bytes",
    )
