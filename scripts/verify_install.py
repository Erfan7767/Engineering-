"""Verify the install is healthy.

Boots the CLI and prints the result of every subcommand. Exits 0 on
success, non-zero on any failure. Designed to be run in CI right after
``pip install -e .`` to catch the "it imports but doesn't actually
work" class of bugs.

Usage:
    python scripts/verify_install.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(cmd: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=timeout,
        env={"PYTHONPATH": "src", **__import__("os").environ},
    )


def main() -> int:
    py = sys.executable

    print("=" * 60)
    print("NetOps Autopilot — install verification")
    print("=" * 60)

    # 1. Top-level --help
    print("\n[1/6] CLI --help")
    r = _run([py, "-m", "netops_autopilot", "--help"])
    if r.returncode != 0:
        print("FAIL:", r.stderr)
        return 1
    print("ok")

    # 2. health subcommand
    print("\n[2/6] health subcommand")
    r = _run([py, "-m", "netops_autopilot", "health"])
    if r.returncode != 0:
        print("FAIL:", r.stderr)
        return 1
    print("ok:", r.stdout.strip()[:120])

    # 3. config subcommand (smoke)
    print("\n[3/6] config subcommand (smoke)")
    r = _run([py, "-m", "netops_autopilot", "config", "--help"])
    if r.returncode != 0:
        print("FAIL:", r.stderr)
        return 1
    print("ok")

    # 4. full test suite smoke
    print("\n[4/6] test suite (smoke: import-only)")
    r = _run([py, "-c", (
        "import sys; sys.path.insert(0, 'src');"
        "from netops_autopilot.autopilot import AutopilotEngine;"
        "from netops_autopilot.ledger.store import LedgerStore;"
        "from netops_autopilot.adapters.cisco_iosxe import CiscoIosXeSerialAdapter;"
        "from netops_autopilot.llm.providers import build_provider;"
        "from netops_autopilot.core.ratelimit import RateLimiter;"
        "from netops_autopilot.core.cache import LRUCache;"
        "print('imports ok')"
    )], timeout=30)
    if r.returncode != 0:
        print("FAIL:", r.stderr)
        return 1
    print(r.stdout.strip())

    # 5. version + key import
    print("\n[5/6] package version")
    r = _run([py, "-c", (
        "import sys; sys.path.insert(0, 'src');"
        "import netops_autopilot;"
        "print(getattr(netops_autopilot, '__version__', 'dev'))"
    )], timeout=10)
    if r.returncode != 0:
        print("FAIL:", r.stderr)
        return 1
    print("version:", r.stdout.strip())

    # 6. HTML report renders a non-empty string
    print("\n[6/7] HTML report renders")
    r = _run([py, "-c", (
        "import sys; sys.path.insert(0, 'src');"
        "from netops_autopilot.reporting.html_report import render_html_report, report_from_autopilot;"
        "data = report_from_autopilot("
        "  report={'final': 'COMPLETE-STAGED', 'phases': []},"
        "  run_id='verify', ledger_event_count=0, chain_ok=True);"
        "html = render_html_report(data);"
        "assert len(html) > 1000, 'html too small';"
        "print('html bytes:', len(html))"
    )], timeout=10)
    if r.returncode != 0:
        print("FAIL:", r.stderr)
        return 1
    print(r.stdout.strip())

    # 7. End-to-end engine run on the simulated fabric
    print("\n[7/7] end-to-end engine run")
    r = _run([py, "-c", (
        "import sys; sys.path.insert(0, 'src');"
        "from netops_autopilot.autopilot.orchestrator import AutopilotEngine;"
        "from netops_autopilot.cli import ScriptedIO;"
        "from netops_autopilot.ledger.store import LedgerStore;"
        "from netops_autopilot.core.timeauth import TimeAuthority;"
        "import datetime;"
        "tz = datetime.timezone.utc;"
        "ta = TimeAuthority(clock=lambda: datetime.datetime.now(tz));"
        "store = LedgerStore(':memory:');"
        "kid = store.keys.create_key('verify');"
        "engine = AutopilotEngine(store=store, key_id=kid, io=ScriptedIO(["
        "    'y', '2', 'seed-01', 'ISP fiber DHCP', 'STANDARD', '+25% in 12 months'"
        "]), time_authority=ta);"
        "from tests.support.simfabric import SimFabricFactory;"
        "fabric = SimFabricFactory(include_access=True, access_behavior='allow');"
        "report = engine.run("
        "  probe_port_session_factory=lambda p: fabric.probe(p),"
        "  mgmt_session_factory=fabric.open,"
        "  port='SIM0', execute=False);"
        "assert report.final == 'COMPLETE-STAGED', f'final={report.final}';"
        "assert store.verify_chain().ok, 'ledger chain broken';"
        "print('run ok, devices:', report.crawl.totals.get('devices', 0) if report.crawl else 0)"
    )], timeout=30)
    if r.returncode != 0:
        print("FAIL:", r.stderr)
        return 1
    print(r.stdout.strip())

    print("\n" + "=" * 60)
    print("ALL 7 CHECKS PASSED")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
