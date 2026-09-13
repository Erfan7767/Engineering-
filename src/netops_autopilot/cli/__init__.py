"""CLI enhancements for NetOps Autopilot.

* :mod:`pretty` — colored terminal rendering, panels, tables, progress bars.
* :mod:`scenarios` — canned demo scenarios for the operator CLI.

This package also re-exports ``ScriptedIO`` and ``ConsoleIO`` for backward
compatibility with code that did ``from netops_autopilot.cli import ...``.
"""
from .pretty import (
    Panel,
    Table,
    ColorMode,
    banner,
    status_line,
    kv_line,
    progress,
    render_run_summary,
)
from .io import ScriptedIO, ConsoleIO, RefusingIO

__all__ = [
    "Panel",
    "Table",
    "ColorMode",
    "banner",
    "status_line",
    "kv_line",
    "progress",
    "render_run_summary",
    "ScriptedIO",
    "RefusingIO",
    "ConsoleIO",
]
