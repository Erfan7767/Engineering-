"""Tests for the CLI pretty-printing subsystem."""

from __future__ import annotations

import io
import os
import sys

import pytest

from netops_autopilot.cli.pretty import (
    Panel,
    Table,
    ColorMode,
    banner,
    status_line,
    kv_line,
    progress,
    render_run_summary,
    _resolve_color_mode,
)


# ----------------- Color mode -----------------


def test_color_mode_never_returns_false():
    assert _resolve_color_mode(ColorMode.NEVER) is False
    assert _resolve_color_mode(ColorMode.ALWAYS) is True


def test_color_mode_auto_no_color_env(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert _resolve_color_mode(ColorMode.AUTO) is False


def test_color_mode_auto_dumb_term(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    assert _resolve_color_mode(ColorMode.AUTO) is False


# ----------------- status_line -----------------


def test_status_line_contains_label():
    out = status_line("OK", "all good", color_mode=ColorMode.NEVER)
    assert "[OK]" in out
    assert "all good" in out


def test_status_line_all_states_have_styles():
    for s in ("OK", "BLOCKED", "HUMAN_DECISION", "TYPED_STOP", "PARTIAL", "RUNNING", "WARN", "ERROR"):
        out = status_line(s, "x", color_mode=ColorMode.NEVER)
        assert f"[{s}]" in out


# ----------------- Panel -----------------


def test_panel_renders_title_and_body():
    p = Panel("title", ["line1", "line2"], color_mode=ColorMode.NEVER)
    out = p.render()
    assert "title" in out
    assert "line1" in out
    assert "line2" in out


def test_panel_truncates_long_lines():
    p = Panel("t", ["x" * 500], color_mode=ColorMode.NEVER)
    out = p.render()
    # The "…" truncation mark should be present.
    assert "…" in out


def test_panel_minimum_width():
    p = Panel("t", ["x"], color_mode=ColorMode.NEVER)
    out = p.render(width=20)
    # Border chars present.
    assert "─" in out


# ----------------- Table -----------------


def test_table_renders_headers_and_rows():
    t = Table(["a", "b"], [["1", "2"], ["3", "4"]], color_mode=ColorMode.NEVER)
    out = t.render()
    assert "a" in out and "b" in out
    assert "1" in out and "2" in out
    assert "3" in out and "4" in out


def test_table_aligns_columns():
    t = Table(["short", "longer_column"], [["a", "bb"]], color_mode=ColorMode.NEVER)
    out = t.render()
    # Both cells should be on one line.
    lines = out.splitlines()
    assert len(lines) == 3  # header, separator, row
    # The data row should contain both cells separated by spaces.
    assert "a" in lines[2] and "bb" in lines[2]


def test_table_empty_rows():
    t = Table(["a", "b"], [], color_mode=ColorMode.NEVER)
    out = t.render()
    assert "a" in out and "b" in out


# ----------------- banner / kv_line -----------------


def test_banner_contains_text():
    out = banner("hello", color_mode=ColorMode.NEVER)
    assert "hello" in out
    assert "=" in out


def test_kv_line_contains_pair():
    out = kv_line("name", "value", color_mode=ColorMode.NEVER)
    assert "name:" in out
    assert "value" in out


# ----------------- progress -----------------


def test_progress_with_total_does_not_crash(capsys):
    with progress("test", total=5, color_mode=ColorMode.NEVER):
        for _ in range(5):
            pass


def test_progress_without_total_does_not_crash(capsys):
    with progress("test", color_mode=ColorMode.NEVER):
        for _ in range(3):
            pass


# ----------------- render_run_summary -----------------


def test_run_summary_complete():
    out = render_run_summary(
        final="COMPLETE-STAGED", event_count=42, chain_ok=True,
        devices=3, zones=4, blueprint="branch_office",
        color_mode=ColorMode.NEVER,
    )
    assert "COMPLETE-STAGED" in out
    assert "42" in out
    assert "OK" in out
    assert "3" in out
    assert "4" in out
    assert "branch_office" in out


def test_run_summary_chain_tampered():
    out = render_run_summary(
        final="BLOCKED", event_count=0, chain_ok=False,
        color_mode=ColorMode.NEVER,
    )
    assert "TAMPERED" in out


# ----------------- self-test -----------------


def test_module_selftest():
    # Re-run the module's own self-test
    from netops_autopilot.cli import pretty
    pretty._selftest()
