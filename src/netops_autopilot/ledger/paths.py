"""Where the platform keeps its state.

The ledger is the evidence record: every observation, every command sent to a
device, every decision and its justification. It is the only thing that can
answer "why did this network get configured this way?", so an operator has to
be able to find it, and it must not be scattered.

Two defects this removes:

* ``cli_main`` wrote ``netops-ledger.sqlite3`` into the **current working
  directory**, so the record landed wherever the operator happened to be
  standing when they ran the command — a different file per directory, none of
  them where anyone would look.
* The web run worker wrote ``netops-ledger-<run_id>.sqlite3`` into the current
  directory, **one file per run, never removed**. A long-running server
  accumulated them without bound: this repository's own working tree had 1063
  of them. The same file already resolved its *chat* ledger correctly, through
  ``NETOPS_LEDGER_DB`` with a temp-dir fallback, so the two disagreed.

Precedence, highest first:

1. ``NETOPS_LEDGER_DB`` — an explicit path. Honoured verbatim, including a
   relative one, because an operator who names a file means that file.
2. ``NETOPS_DATA_DIR`` — an explicit state directory.
3. ``$XDG_DATA_HOME/netops-autopilot`` when ``XDG_DATA_HOME`` is set.
4. ``~/.local/share/netops-autopilot`` (``~/.netops-autopilot`` if the home
   directory cannot be determined, e.g. a service account with no home).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

#: The ledger file name inside the state directory.
LEDGER_NAME = "netops-ledger.sqlite3"

#: Per-run ledgers live here, under the state directory — isolated from each
#: other, but in one place an operator can find, list and clean.
RUNS_SUBDIR = "runs"


def data_dir() -> Path:
    """The directory this platform keeps its state in."""
    override = os.environ.get("NETOPS_DATA_DIR")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg).expanduser() / "netops-autopilot"
    home = _home()
    if home is None:
        return Path(".netops-autopilot")
    return home / ".local" / "share" / "netops-autopilot"


def ledger_path(name: str = LEDGER_NAME) -> str:
    """The evidence ledger an operator should expect to find.

    ``NETOPS_LEDGER_DB`` wins outright: naming a file is an explicit act and
    the platform does not second-guess it.
    """
    override = os.environ.get("NETOPS_LEDGER_DB")
    if override:
        return override
    return str(data_dir() / name)


def run_ledger_path(run_id: str) -> str:
    """Where one web/API run keeps its own evidence chain.

    Each run gets its own ledger so its hash chain is closed and auditable on
    its own — but under the state directory, not in the caller's working
    directory, and named after the run so it can be correlated with the
    record the API returned.
    """
    override = os.environ.get("NETOPS_LEDGER_DB")
    base = Path(override).parent if override else data_dir()
    return str(base / RUNS_SUBDIR / f"netops-ledger-{run_id}.sqlite3")


def describe() -> str:
    """A one-line account of where state goes, for ``--help`` and startup logs.

    An operator who cannot find the ledger cannot audit the run, so the
    resolved path is reported rather than left to be guessed.
    """
    override = os.environ.get("NETOPS_LEDGER_DB")
    if override:
        return f"ledger: {override} (NETOPS_LEDGER_DB)"
    source = ("NETOPS_DATA_DIR" if os.environ.get("NETOPS_DATA_DIR")
              else "XDG_DATA_HOME" if os.environ.get("XDG_DATA_HOME")
              else "default state directory")
    return f"ledger: {ledger_path()} ({source})"


#: What a run whose ledger lives only in memory must say about itself.
#:
#: ``make_ledger_stack`` builds ``LedgerStore(":memory:")``, which the demo and
#: the test suite use. The run summary reports a ledger event count and a
#: verified hash chain, and both are true — for the lifetime of the process.
#: Saying nothing let an operator read "Events (ledger): 43 · Chain integrity
#: OK" as a record they could go and audit afterwards. There is no such
#: record, and a rehearsal must not quietly imply one exists.
IN_MEMORY_NOTICE = (
    "ledger: in memory only — this run is a rehearsal and its evidence is "
    "discarded when the process exits; nothing was written to disk")


def ensure_parent(path: str) -> Optional[Path]:
    """Create the directory a database path lives in, if it does not exist.

    ``sqlite3.connect`` fails with ``unable to open database file`` when the
    parent directory is missing, which is an opaque way to report "you have
    never run this before". Returns the directory created, or ``None``.
    """
    parent = Path(path).expanduser().parent
    if str(parent) in ("", "."):
        return None
    if parent.is_dir():
        return None
    parent.mkdir(parents=True, exist_ok=True)
    return parent


def _home() -> Optional[Path]:
    try:
        return Path.home()
    except (RuntimeError, KeyError):   # no HOME and no passwd entry
        return None
