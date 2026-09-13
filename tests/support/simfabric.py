"""Backwards-compatible path for the simulated fabric.

The implementation moved into the shipped package (``netops_autopilot.simfabric``)
because the package itself imported it and ``tests/`` is not part of the
distribution. This shim keeps existing imports working and guarantees there is
still exactly one implementation.
"""
from netops_autopilot.simfabric import *  # noqa: F401,F403
from netops_autopilot.simfabric import (  # noqa: F401
    FIXTURES,
    fixtures_dir,
    SEED_BANNER,
    SimFabricFactory,
    access_sw1_session,
    core_sw2_session,
    make_ledger_stack,
    seed_session,
)
