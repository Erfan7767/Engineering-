"""Tests for the CLI entry-point (cli_main.py)."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

import pytest

from netops_autopilot.cli_main import (
    main,
    run_health,
    run_scenarios,
    run_config,
)


# ----------------- main() arg parsing -----------------


def test_help_exits_clean(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0


def test_missing_subcommand_fails(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code != 0


def test_autopilot_requires_port(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["autopilot"])
    assert exc.value.code != 0


def test_health_command_runs(capsys):
    rc = main(["health"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "NetOps Autopilot" in out


def test_scenarios_command_runs(capsys):
    rc = main(["scenarios"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "branch" in out
    assert "hotel" in out


def test_config_show_defaults(capsys):
    rc = main(["config", "--show-defaults"])
    assert rc == 0
    out = capsys.readouterr().out
    j = json.loads(out)
    assert "console" in j
    assert "network" in j


def test_config_load_path(tmp_path: Path, capsys):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"console": {"port": "COM7"}}))
    rc = main(["config", "--path", str(p)])
    assert rc == 0
    j = json.loads(capsys.readouterr().out)
    assert j["console"]["port"] == "COM7"


def test_config_load_path_missing(tmp_path: Path, capsys):
    rc = main(["config", "--path", str(tmp_path / "missing.json")])
    assert rc == 2  # ConfigError returns 2


# ----------------- demo command writes reports -----------------


def test_demo_with_report_dir(tmp_path: Path, capsys):
    rc = main(["demo", "--scenario", "branch", "--report-dir", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Reports written" in out
    files = list(tmp_path.iterdir())
    names = {p.name for p in files}
    assert "demo-branch.html" in names
    assert "demo-branch.json" in names
    # The HTML must be a non-empty file.
    html = (tmp_path / "demo-branch.html").read_text(encoding="utf-8")
    assert "NetOps Autopilot" in html
    j = json.loads((tmp_path / "demo-branch.json").read_text(encoding="utf-8"))
    assert j["final"] in ("COMPLETE-STAGED", "BLOCKED-DESIGN", "BLOCKED-*")


def test_demo_all_four_scenarios(tmp_path: Path, capsys):
    for scenario in ("branch", "leaf-spine", "hotel", "retail"):
        rc = main(["demo", "--scenario", scenario, "--report-dir", str(tmp_path / scenario)])
        assert rc == 0, f"scenario {scenario} failed with rc={rc}"


# ----------------- run_health / run_scenarios directly -----------------


def test_run_health_returns_zero():
    assert run_health() == 0


def test_run_scenarios_returns_zero():
    assert run_scenarios() == 0


def test_run_config_defaults_returns_zero(capsys):
    rc = run_config(path=None, show_defaults=True)
    assert rc == 0
