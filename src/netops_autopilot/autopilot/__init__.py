"""Autopilot — the capstone orchestrator.

Drives the operator's scenario end-to-end, phase by phase, with every
transition recorded (AUTOPILOT ledger transitions) and every gate honest:

    BOND → BOOT_PROBE → DISCOVERY_A → TOPOLOGY_MAP → INTENT_ELICITATION
        → DESIGN → RENDER → EXECUTION_GATE → REPORT

The execution gate enforces the platform's own law: the CONFIG allowlist
classes are empty seeds (T3), so v1 execution stops at a STAGED state with
the exact blocking reason — staged artifacts (IR + vendor render previews)
are produced, never silently "applied". This is the truth of the system
today; claiming otherwise would be exactly the hallucination this platform
exists to prevent.
"""

from .orchestrator import (  # noqa: F401
    AutopilotEngine,
    AutopilotReport,
    OperatorIO,
    Phase,
)
