"""netops-autopilot CLI — the operator interface (headless, same APIs as UI).

Real-hardware path::

    netops-autopilot autopilot --port COM5            # interactive
    netops-autopilot autopilot --port COM5 --execute  # execution gate armed

Evaluation path (no hardware needed, deterministic)::

    netops-autopilot demo

Everything the CLI prints comes from the engines; the human answers only
where the law requires a human (binding, credentials, intent, HUMAN_ONLY).
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from .autopilot import AutopilotEngine, OperatorIO
from .core.failures import Failure
from .core.timeauth import TimeAuthority
from .ledger.store import LedgerStore
from datetime import datetime, timezone


class ConsoleIO:
    """stdin/stdout operator channel."""

    def ask(self, question: str) -> str:
        print(question)
        try:
            return input("> ").strip()
        except EOFError:
            return ""

    def confirm(self, question: str) -> bool:
        try:
            return input(question).strip().lower() in {"y", "yes", "نعم", "n/a-confirm"}
        except EOFError:
            return False

    def show(self, text: str) -> None:
        print(text)


class ScriptedIO:
    """Deterministic demo answers (visible in the transcript)."""

    def __init__(self, answers: list[str]) -> None:
        self._answers = list(answers)
        self.transcript: list[str] = []

    def ask(self, question: str) -> str:
        answer = self._answers.pop(0) if self._answers else ""
        self.transcript.append(f"Q: {question.splitlines()[-1]}\nA: {answer}")
        print(f"Q: {question.splitlines()[-1]}\nA: {answer}")
        return answer

    def confirm(self, question: str) -> bool:
        answer = self._answers.pop(0) if self._answers else "y"
        print(f"Q: {question}\nA: {answer}")
        return answer.strip().lower() in {"y", "yes", "نعم"}

    def show(self, text: str) -> None:
        print(text)


def _real_session_factory(port: str):
    """Open the console session and probe a banner (best-effort evidence)."""
    from .access.serial_transport import SerialConsoleTransport, SerialProfile

    profile = SerialProfile(port=port)
    transport = SerialConsoleTransport(profile)
    transport.open()
    try:
        banner = transport.execute("", 1.5)
    except (TimeoutError, Failure):
        banner = b""
    return (transport, banner)


def _refused_mgmt_factory(device_ref: str, hints: tuple[str, ...]):
    """v1 has no SSH infra yet (ADR-0004 direct-connect): typed refusal."""
    raise Failure(
        cls=__import__("netops_autopilot.core.failures", fromlist=["FailureClass"]).FailureClass.BLOCKED,
        causes=("MGMT_PATH_NOT_MODELED: SSH/telnet management sessions land with the transport "
                "batch — today only the direct console is real (ADR-0004). Neighbors stay "
                "discovered-but-unreached, never assumed managed.",))


def run_autopilot(port: str, execute: bool) -> int:
    store = LedgerStore("netops-ledger.sqlite3")
    key_id = store.keys.create_key("autopilot-collector")
    engine = AutopilotEngine(
        store=store, key_id=key_id, io=ConsoleIO(),
        time_authority=TimeAuthority(clock=lambda: datetime.now(timezone.utc)))
    report = engine.run(
        probe_port_session_factory=_real_session_factory,
        mgmt_session_factory=_refused_mgmt_factory,
        port=port, execute=execute)
    print(f"\n=== RUN {report.final} · events={store.event_count()} · "
          f"ledger-chain-ok={store.verify_chain().ok} ===")
    return 0 if report.final.startswith("COMPLETE") else 2


def run_demo() -> int:
    from tests.support.simfabric import SimFabricFactory, make_ledger_stack
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    answers = ["y",                                # 1 binding confirm
               "2",                                # 2 network type → branch
               "seed-01",                          # 3 router device
               "ISP fiber DHCP handoff",           # 4 wan handoff
               "STANDARD",                         # 5 availability
               "+25% in 12 months"]                # 6 growth
    engine = AutopilotEngine(store=store, key_id=key_id,
                             io=ScriptedIO(answers), time_authority=time_auth)
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=False)
    print(f"\n=== DEMO {report.final} · events={store.event_count()} · "
          f"ledger-chain-ok={store.verify_chain().ok} ===")
    if report.crawl:
        print(f"devices={report.crawl.totals}")
    if report.design:
        print(f"design={report.design.design_id} blocked={report.design.blocked}")
    return 0 if report.final.startswith("COMPLETE") else 2


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="netops-autopilot",
                                     description="Evidence-driven autonomous network engineering")
    sub = parser.add_subparsers(dest="command", required=True)

    ap = sub.add_parser("autopilot", help="run the end-to-end autopilot on a real console port")
    ap.add_argument("--port", required=True, help="console port (COMx / /dev/ttyUSB0)")
    ap.add_argument("--execute", action="store_true",
                    help="request execution (the EXECUTION_GATE still enforces the law)")

    sub.add_parser("demo", help="deterministic simulated fabric, full flow, no hardware")

    args = parser.parse_args(argv)
    if args.command == "autopilot":
        return run_autopilot(args.port, args.execute)
    if args.command == "demo":
        return run_demo()
    return 1


if __name__ == "__main__":
    sys.exit(main())
