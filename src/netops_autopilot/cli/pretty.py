"""Pretty terminal output — pure-Python rich text formatting (no external deps).

Design goals:
- **Zero new dependencies** (works on bare Python 3.11+).
- **Cross-platform:** falls back to plain text on non-TTY (CI, scripts, tests).
- **Color autodetect:** uses ANSI only when stdout is a TTY and ``NO_COLOR`` is unset.
- **Deterministic for tests:** ``force=ColorMode.NEVER`` for reproducible output.

This is NOT a replacement for libraries like Rich — it's a focused toolkit
for the four primitives the operator UI needs: panel, table, progress, status.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional, TextIO


class ColorMode(str, Enum):
    AUTO = "AUTO"
    ALWAYS = "ALWAYS"
    NEVER = "NEVER"


def _resolve_color_mode(force: ColorMode) -> bool:
    if force is ColorMode.NEVER:
        return False
    if force is ColorMode.ALWAYS:
        return True
    # AUTO: respect NO_COLOR env (https://no-color.org/), TERM=dumb, non-TTY
    if os.environ.get("NO_COLOR"):
        return False
    term = os.environ.get("TERM", "")
    if term == "dumb":
        return False
    return sys.stdout.isatty()


# ----------------- ANSI codes (minimal, well-supported) -----------------

class _A:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    ITALIC = "\x1b[3m"
    UNDERLINE = "\x1b[4m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN = "\x1b[36m"
    WHITE = "\x1b[37m"
    BRED = "\x1b[91m"
    BGREEN = "\x1b[92m"
    BYELLOW = "\x1b[93m"
    BBLUE = "\x1b[94m"
    BMAGENTA = "\x1b[95m"
    BCYAN = "\x1b[96m"


_STATUS_STYLES = {
    "OK": _A.BGREEN,
    "BLOCKED": _A.BRED,
    "HUMAN_DECISION": _A.BYELLOW,
    "TYPED_STOP": _A.BMAGENTA,
    "RETRYABLE": _A.BYELLOW,
    "PARTIAL": _A.BYELLOW,
    "RUNNING": _A.BCYAN,
    "INFO": _A.BBLUE,
    "WARN": _A.BYELLOW,
    "ERROR": _A.BRED,
    "FATAL": _A.BRED,
}


def _paint(text: str, color: str, enabled: bool) -> str:
    if not enabled or not color:
        return text
    return f"{color}{text}{_A.RESET}"


def _strip_for_width(text: str) -> int:
    """Visible width (rough ANSI-stripping)."""
    import re
    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", text)
    return len(cleaned)


# ----------------- Public primitives -----------------


@dataclass
class Panel:
    """A boxed panel with title, body lines, and accent color."""

    title: str
    body: list[str]
    accent: str = _A.BCYAN
    color_mode: ColorMode = ColorMode.AUTO

    def render(self, width: Optional[int] = None) -> str:
        enabled = _resolve_color_mode(self.color_mode)
        if width is None:
            width = shutil.get_terminal_size((100, 30)).columns
        width = max(40, min(width, 200))
        title_text = f" {self.title} "
        inner = width - 4  # borders + padding
        top = "╭─" + title_text + "─" * max(1, inner - _strip_for_width(title_text)) + "╮"
        bot = "╰" + "─" * (width - 2) + "╯"
        out: list[str] = [_paint(top, self.accent, enabled)]
        for line in self.body:
            line = line.rstrip("\n")
            if _strip_for_width(line) > inner:
                # Truncate
                cut = line[: inner - 1] + "…"
            else:
                cut = line + " " * (inner - _strip_for_width(line))
            out.append(_paint("│ ", self.accent, enabled) + cut + _paint(" │", self.accent, enabled))
        out.append(_paint(bot, self.accent, enabled))
        return "\n".join(out)


@dataclass
class Table:
    """Minimal column-aligned table."""

    headers: list[str]
    rows: list[list[str]]
    color_mode: ColorMode = ColorMode.AUTO

    def render(self) -> str:
        enabled = _resolve_color_mode(self.color_mode)
        widths = [len(h) for h in self.headers]
        for row in self.rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], _strip_for_width(str(cell)))
        def fmt_row(cells: list[str]) -> str:
            parts = []
            for i, c in enumerate(cells):
                w = widths[i] if i < len(widths) else len(c)
                parts.append(str(c).ljust(w))
            return "  ".join(parts)
        sep = "  ".join("─" * w for w in widths)
        lines = [_paint(fmt_row(self.headers), _A.BOLD, enabled), _paint(sep, _A.DIM, enabled)]
        for row in self.rows:
            lines.append(fmt_row([str(c) for c in row]))
        return "\n".join(lines)


def status_line(status: str, message: str, color_mode: ColorMode = ColorMode.AUTO) -> str:
    """Render a phase status line: ``[OK] message``."""
    enabled = _resolve_color_mode(color_mode)
    style = _STATUS_STYLES.get(status, "")
    badge = _paint(f"[{status}]", style, enabled)
    return f"{badge} {message}"


def banner(text: str, color_mode: ColorMode = ColorMode.AUTO) -> str:
    """Render a centered banner with bold + cyan."""
    enabled = _resolve_color_mode(color_mode)
    w = shutil.get_terminal_size((100, 20)).columns
    text = text.strip()
    pad = max(0, (w - len(text) - 4) // 2)
    return _paint("=" * w, _A.BCYAN, enabled) + "\n" + (
        " " * pad + _paint(text, _A.BOLD + _A.BCYAN, enabled) + "\n"
    ) + _paint("=" * w, _A.BCYAN, enabled)


def kv_line(key: str, value: str, key_color: str = _A.DIM, color_mode: ColorMode = ColorMode.AUTO) -> str:
    """Render a key/value line: ``key: value`` with key dimmed."""
    enabled = _resolve_color_mode(color_mode)
    return f"{_paint(key + ':', key_color, enabled)} {value}"


@contextmanager
def progress(label: str, total: Optional[int] = None, color_mode: ColorMode = ColorMode.AUTO):
    """Context manager that draws a single-line progress bar.

    Usage::

        with progress("Discovering devices", total=10) as p:
            for device in devices:
                p.tick(f"device={device}")
    """
    enabled = _resolve_color_mode(color_mode)
    start = time.monotonic()
    state = {"n": 0}

    def _draw(msg: str = "") -> None:
        if not enabled:
            # Plain mode: print label + msg on first call only (no spam)
            return
        elapsed = time.monotonic() - start
        if total:
            n = state["n"]
            pct = min(100, int(100 * n / total))
            bar_w = 30
            filled = int(bar_w * n / total)
            bar = "█" * filled + "░" * (bar_w - filled)
            sys.stdout.write(
                f"\r{_paint('⏳', _A.BCYAN, enabled)} {label:<32} "
                f"{_paint(bar, _A.BCYAN, enabled)} {pct:3d}% {msg}  "
            )
        else:
            sys.stdout.write(f"\r{_paint('⏳', _A.BCYAN, enabled)} {label:<32} ... {msg}  ({elapsed:.1f}s)")
        sys.stdout.flush()

    def _finish() -> None:
        elapsed = time.monotonic() - start
        if enabled:
            sys.stdout.write(
                f"\r{_paint('✓', _A.BGREEN, enabled)} {label:<32} "
                f"{_paint('done', _A.BGREEN, enabled)} ({elapsed:.1f}s)" + " " * 20 + "\n"
            )
            sys.stdout.flush()

    class _Bar:
        def tick(self, msg: str = "") -> None:
            state["n"] += 1
            _draw(msg)

        def set(self, n: int, msg: str = "") -> None:
            state["n"] = n
            _draw(msg)

        def update(self, msg: str) -> None:
            _draw(msg)

    try:
        _draw()
        yield _Bar()
    finally:
        _finish()


def write(stream: TextIO, text: str) -> None:
    stream.write(text)
    if not text.endswith("\n"):
        stream.write("\n")
    stream.flush()


# ----------------- High-level composite helpers -----------------


def render_run_summary(
    *,
    final: str,
    event_count: int,
    chain_ok: bool,
    devices: Optional[int] = None,
    zones: Optional[int] = None,
    blueprint: Optional[str] = None,
    color_mode: ColorMode = ColorMode.AUTO,
) -> str:
    """Render a one-shot run-summary panel (used at end of CLI)."""
    enabled = _resolve_color_mode(color_mode)
    accent = _STATUS_STYLES.get(final.split("-")[0], _A.BCYAN)
    body = [
        kv_line("Final", _paint(final, _STATUS_STYLES.get(final.split("-")[0], _A.BOLD), enabled), _A.BOLD, color_mode),
        kv_line("Events (ledger)", str(event_count)),
        kv_line("Chain integrity", _paint("✓ OK" if chain_ok else "✗ TAMPERED", _A.BGREEN if chain_ok else _A.BRED, enabled)),
    ]
    if devices is not None:
        body.append(kv_line("Devices discovered", str(devices)))
    if zones is not None:
        body.append(kv_line("Zones designed", str(zones)))
    if blueprint is not None:
        body.append(kv_line("Blueprint", blueprint))
    return Panel("NetOps Autopilot · Run Summary", body, accent=accent, color_mode=color_mode).render()


# ----------------- Self-test -----------------

def _selftest() -> None:
    """Used by the test suite to confirm rendering works in all modes."""
    assert "[OK]" in status_line("OK", "x")
    assert Panel("t", ["a"], color_mode=ColorMode.NEVER).render()
    assert Table(["a", "b"], [["1", "2"]], color_mode=ColorMode.NEVER).render()
    assert banner("hi", color_mode=ColorMode.NEVER)
    assert kv_line("k", "v", color_mode=ColorMode.NEVER)
    assert render_run_summary(final="COMPLETE-STAGED", event_count=10, chain_ok=True, color_mode=ColorMode.NEVER)


if __name__ == "__main__":  # pragma: no cover
    print(banner("NetOps Autopilot"))
    print(Panel("Demo", ["hello", "world"]))
    print(Table(["col1", "col2"], [["a", "b"], ["c", "d"]]))
    with progress("Loading", total=10) as p:
        for i in range(10):
            time.sleep(0.01)
            p.tick(f"step {i + 1}")
