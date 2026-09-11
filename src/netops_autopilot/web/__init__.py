"""Web API subsystem — REST + WebSocket for NetOps Autopilot.

* FastAPI is an *optional* dependency; the server only imports when the
  user actually calls ``python -m netops_autopilot webui`` (L11 + ADR-0008).
* Missing FastAPI ⇒ typed ``Failure(BLOCKED)`` with install instructions
  (never a crash).
* All endpoints honor the constitution: every response is evidence-bound,
  every typed state is explicit, no implicit PASS.
"""
from .server import create_app, run_server

__all__ = ["create_app", "run_server"]
