"""The evidence record has one findable home, not one file per working directory.

``cli_main`` wrote ``netops-ledger.sqlite3`` into the current working
directory, so the record landed wherever the operator happened to be standing.
The web run worker wrote ``netops-ledger-<run_id>.sqlite3`` into the current
directory, one per run and never removed — this repository's own tree had 1063
of them. The same server module resolved its *chat* ledger through
``NETOPS_LEDGER_DB`` with a temp-dir fallback, so the two disagreed about where
state lives.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from netops_autopilot.ledger.paths import (
    LEDGER_NAME,
    data_dir,
    describe,
    ensure_parent,
    ledger_path,
    run_ledger_path,
)
from netops_autopilot.ledger.store import LedgerStore


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    monkeypatch.delenv("NETOPS_LEDGER_DB", raising=False)
    monkeypatch.delenv("NETOPS_DATA_DIR", raising=False)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def test_the_default_is_under_the_operators_home_not_the_cwd(isolated):
    path = pathlib.Path(ledger_path())
    assert path.is_absolute(), path
    assert str(path).startswith(str(isolated)), (
        f"the ledger went to {path}, not under the operator's home {isolated}")
    assert path.name == LEDGER_NAME


def test_it_does_not_depend_on_where_the_command_was_run_from(isolated, monkeypatch, tmp_path):
    elsewhere = tmp_path / "somewhere-else"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert ledger_path() == str(isolated / ".local" / "share"
                                / "netops-autopilot" / LEDGER_NAME)


def test_an_explicit_path_is_honoured_verbatim(monkeypatch, tmp_path):
    wanted = tmp_path / "custom" / "my-ledger.sqlite3"
    monkeypatch.setenv("NETOPS_LEDGER_DB", str(wanted))
    assert ledger_path() == str(wanted)
    # and per-run ledgers stay beside it, not back in the state directory
    assert run_ledger_path("r1") == str(tmp_path / "custom" / "runs"
                                        / "netops-ledger-r1.sqlite3")


def test_xdg_data_home_is_respected(monkeypatch, tmp_path):
    monkeypatch.delenv("NETOPS_LEDGER_DB", raising=False)
    monkeypatch.delenv("NETOPS_DATA_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert data_dir() == tmp_path / "xdg" / "netops-autopilot"


def test_per_run_ledgers_are_isolated_but_in_one_place(isolated):
    a, b = run_ledger_path("run-a"), run_ledger_path("run-b")
    assert a != b, "two runs would share one evidence chain"
    assert pathlib.Path(a).parent == pathlib.Path(b).parent
    assert "run-a" in a and "run-b" in b, "a run cannot be correlated to its ledger"


def test_the_store_creates_the_directory_it_needs(isolated):
    """sqlite3 reports a missing parent as "unable to open database file"."""
    target = isolated / "deep" / "nested" / "ledger.sqlite3"
    assert not target.parent.exists()
    store = LedgerStore(str(target))
    try:
        assert target.exists(), "the database was not created"
        assert store.head_hash() is not None
    finally:
        store.close() if hasattr(store, "close") else None


def test_ensure_parent_reports_what_it_created(tmp_path):
    made = ensure_parent(str(tmp_path / "a" / "b" / "x.sqlite3"))
    assert made == tmp_path / "a" / "b"
    assert ensure_parent(str(tmp_path / "a" / "b" / "y.sqlite3")) is None


def test_the_operator_is_told_where_the_record_went(isolated, monkeypatch):
    monkeypatch.setenv("NETOPS_LEDGER_DB", "/tmp/told/ledger.sqlite3")
    assert describe() == "ledger: /tmp/told/ledger.sqlite3 (NETOPS_LEDGER_DB)"
    monkeypatch.delenv("NETOPS_LEDGER_DB")
    assert "default state directory" in describe()


def test_nothing_in_the_package_writes_a_ledger_into_the_working_directory():
    """Repo-wide guard on the two expressions that caused the litter."""
    root = pathlib.Path(__file__).resolve().parent.parent / "src"
    offenders = []
    for path in sorted(root.rglob("*.py")):
        if path.name == "paths.py":
            continue
        text = path.read_text(encoding="utf-8")
        for pattern in (r'LedgerStore\(\s*f?"netops-ledger',
                        r'LedgerStore\(\s*f?["\']netops-ledger'):
            for match in re.finditer(pattern, text):
                line = text[: match.start()].count("\n") + 1
                offenders.append(f"{path.relative_to(root)}:{line}")
    assert not offenders, (
        "a ledger is being created at a hardcoded relative path, which lands "
        "in the operator's working directory: " + ", ".join(offenders))
