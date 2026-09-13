"""Backwards-compatible path for ``LoopbackSession``.

The implementation lives in the shipped package (``netops_autopilot.simfabric``).
"""
from netops_autopilot.simfabric.loopback import *  # noqa: F401,F403
from netops_autopilot.simfabric.loopback import LoopbackSession  # noqa: F401
