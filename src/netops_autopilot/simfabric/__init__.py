"""The deterministic simulated fabric, and the devices behind it.

This used to live in ``tests/support/``. That was a real defect rather than
tidiness: eight modules inside the shipped package imported
``tests.support.simfabric``, and ``pyproject.toml`` packages only ``src/``, so
every one of those imports was broken in an installed deployment —
``netops-autopilot chat --simulate`` died with
``ModuleNotFoundError: No module named 'tests'``, and ``web/server.py`` had
grown a ``sys.path.append`` of the repository root to paper over it.

The simulation is a first-class, opt-in part of the product: it is how the
discovery, design, apply and verify phases are exercised without hardware. It
belongs in the package, named for what it is, next to the device answers it
serves (``fixtures/golden/``). It is never a default — the production transport
is ``ssh_transport._netmiko_factory``, and nothing reaches this module unless
the operator asked for a simulated seed port.
"""
from __future__ import annotations

from pathlib import Path

from .fabric import (
    FIXTURES,
    SEED_BANNER,
    SimFabricFactory,
    access_sw1_session,
    core_sw2_session,
    make_ledger_stack,
    seed_session,
)
from .loopback import LoopbackSession

def fixtures_dir() -> Path:
    """Directory holding the golden device answers the fabric serves.

    Lives inside the package so the simulated fabric works from an installed
    distribution, not only from a source checkout.
    """
    return FIXTURES


__all__ = [
    "FIXTURES",
    "fixtures_dir",
    "LoopbackSession",
    "SEED_BANNER",
    "SimFabricFactory",
    "access_sw1_session",
    "core_sw2_session",
    "make_ledger_stack",
    "seed_session",
]
