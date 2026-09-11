"""netops-autopilot CLI — the operator interface (headless, same APIs as UI).

Real-hardware path::

    netops-autopilot autopilot --port COM5            # interactive
    netops-autopilot autopilot --port COM5 --execute  # execution gate armed

Evaluation path (no hardware needed, deterministic)::

    netops-autopilot demo
    netops-autopilot demo --scenario leaf-spine
    netops-autopilot demo --scenario hotel --report-dir ./out

Configuration::

    netops-autopilot config                          # effective config from env
    netops-autopilot config --path ./config.yaml     # load from file
    netops-autopilot config --show-defaults          # compiled defaults

Web UI::

    netops-autopilot webui --port 8765

Everything the CLI prints comes from the engines; the human answers only
where the law requires a human (binding, credentials, intent, HUMAN_ONLY).
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Optional

from .autopilot import AutopilotEngine, OperatorIO
from .cli import ConsoleIO, ScriptedIO
from .core.failures import Failure
from .core.timeauth import TimeAuthority
from .ledger.store import LedgerStore
from datetime import datetime, timezone


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
    from .core.failures import FailureClass
    raise Failure(
        cls=FailureClass.BLOCKED,
        causes=("MGMT_PATH_NOT_MODELED: SSH/telnet management sessions land with the transport "
                "batch — today only the direct console is real (ADR-0004). Neighbors stay "
                "discovered-but-unreached, never assumed managed.",))


def run_autopilot(port: str, execute: bool, report_dir: Optional[str] = None) -> int:
    store = LedgerStore("netops-ledger.sqlite3")
    key_id = store.keys.create_key("autopilot-collector")
    engine = AutopilotEngine(
        store=store, key_id=key_id, io=ConsoleIO(),
        time_authority=TimeAuthority(clock=lambda: datetime.now(timezone.utc)))
    report = engine.run(
        probe_port_session_factory=_real_session_factory,
        mgmt_session_factory=_refused_mgmt_factory,
        port=port, execute=execute)
    from .cli.pretty import render_run_summary, ColorMode
    chain_ok = store.verify_chain().ok
    print(render_run_summary(
        final=report.final,
        event_count=store.event_count(),
        chain_ok=chain_ok,
        devices=(report.crawl.totals.get("devices") if report.crawl else None),
        color_mode=ColorMode.AUTO,
    ))
    if report_dir:
        _write_reports(report, store, report_dir, run_id=f"run-{port}")
    return 0 if report.final.startswith("COMPLETE") else 2


def run_demo(scenario: str = "branch", report_dir: Optional[str] = None) -> int:
    from tests.support.simfabric import SimFabricFactory, make_ledger_stack
    from .cli.scenarios import make_scenario_io
    store, key_id, _counters, time_auth = make_ledger_stack()
    fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    io = make_scenario_io(scenario)
    engine = AutopilotEngine(store=store, key_id=key_id,
                             io=io, time_authority=time_auth)
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        mgmt_session_factory=fabric.open,
        port="SIM0", execute=False)
    from .cli.pretty import render_run_summary, ColorMode
    chain_ok = store.verify_chain().ok
    print(render_run_summary(
        final=report.final,
        event_count=store.event_count(),
        chain_ok=chain_ok,
        devices=(report.crawl.totals.get("devices") if report.crawl else None),
        zones=(len(report.design.zones) if report.design else None),
        blueprint=(getattr(report.elicitation, "blueprint_id", None) if report.elicitation else None),
        color_mode=ColorMode.AUTO,
    ))
    if report_dir:
        _write_reports(report, store, report_dir, run_id=f"demo-{scenario}")
    return 0 if report.final.startswith("COMPLETE") else 2


def _write_reports(report: Any, store: Any, report_dir: str, run_id: str) -> None:
    """Write HTML + JSON reports to ``report_dir`` (best-effort)."""
    from pathlib import Path
    from .reporting.html_report import render_html_report, report_from_autopilot
    from .reporting.json_report import render_json_report
    out = Path(report_dir)
    out.mkdir(parents=True, exist_ok=True)
    chain_ok = store.verify_chain().ok
    event_count = store.event_count()
    counters: dict[str, int] = {}
    data = report_from_autopilot(
        report, run_id=run_id,
        ledger_event_count=event_count, chain_ok=chain_ok,
        counters=counters,
    )
    html_path = out / f"{run_id}.html"
    json_path = out / f"{run_id}.json"
    html_path.write_text(render_html_report(data), encoding="utf-8")
    json_path.write_text(render_json_report(
        report=report, ledger_event_count=event_count, chain_ok=chain_ok,
        counters=counters,
    ), encoding="utf-8")
    print(f"Reports written: {html_path} · {json_path}")


def run_config(*, path: Optional[str], show_defaults: bool) -> int:
    from .cli.pretty import Panel, ColorMode
    from .config import load_config, load_config_from_env, DEFAULT_CONFIG, ConfigError
    from pathlib import Path
    if show_defaults:
        import json as _json
        print(_json.dumps(DEFAULT_CONFIG.to_dict(), indent=2, ensure_ascii=False))
        return 0
    try:
        cfg = load_config(Path(path)) if path else load_config_from_env()
    except ConfigError as exc:
        print(Panel("Config error", [str(exc)], accent="\x1b[31m", color_mode=ColorMode.AUTO).render())
        return 2
    import json as _json
    print(_json.dumps(cfg.to_dict(), indent=2, ensure_ascii=False))
    return 0


def run_health() -> int:
    """Print platform health: importable engines, ledger factory, etc."""
    from .cli.pretty import Panel, kv_line
    from .ledger.store import LedgerStore
    from .engines.discovery_crawl import DiscoveryCrawlEngine
    from .engines.topology_map import TopologyMapEngine
    from .engines.intent_compiler import IntentCompiler
    from .engines.design_engine import DesignEngine
    from .engines.blueprints import BLUEPRINTS
    lines = [
        kv_line("Platform", "netops-autopilot 0.1.0"),
        kv_line("Python", _python_version()),
        kv_line("Engines loaded",
                f"crawl={DiscoveryCrawlEngine.__name__}, "
                f"topo={TopologyMapEngine.__name__}, "
                f"intent={IntentCompiler.__name__}, "
                f"design={DesignEngine.__name__}"),
        kv_line("Blueprints", ", ".join(sorted(b.blueprint_id for b in BLUEPRINTS))),
        kv_line("Ledger store", f"{LedgerStore.__name__} (sqlite3 backend)"),
        kv_line("Optional deps",
                "netmiko (SSH), pyyaml (YAML), fastapi+uvicorn (web) — all optional"),
    ]
    print(Panel("NetOps Autopilot · Health", lines, accent="\x1b[36m").render())
    return 0


def _python_version() -> str:
    import sys
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def run_webui(*, host: str, port: int, static_dir: Optional[str]) -> int:
    from pathlib import Path
    from .web import run_server
    from .core.failures import Failure
    sd = Path(static_dir) if static_dir else None
    if sd is None:
        from .webui import webui_index_path
        # Use the parent directory so the FastAPI static mount works.
        sd = webui_index_path().parent if webui_index_path().exists() else None
    try:
        run_server(host=host, port=port, static_dir=sd)
        return 0
    except Failure as exc:
        print(f"Web UI failed to start: {exc}", file=sys.stderr)
        return 2


def run_scenarios() -> int:
    from .cli.pretty import Table, ColorMode
    from .cli.scenarios import list_scenarios
    rows = [[k, v] for k, v in list_scenarios()]
    print(Table(["id", "description"], rows, color_mode=ColorMode.AUTO).render())
    print()
    print("Run with: netops-autopilot demo --scenario <id>")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="netops-autopilot",
                                     description="Evidence-driven autonomous network engineering")
    sub = parser.add_subparsers(dest="command", required=True)

    ap = sub.add_parser("autopilot", help="run the end-to-end autopilot on a real console port")
    ap.add_argument("--port", required=True, help="console port (COMx / /dev/ttyUSB0)")
    ap.add_argument("--execute", action="store_true",
                    help="request execution (the EXECUTION_GATE still enforces the law)")
    ap.add_argument("--report-dir", default=None,
                    help="write HTML + JSON reports to this directory after the run")

    demo = sub.add_parser("demo", help="deterministic simulated fabric, full flow, no hardware")
    demo.add_argument("--scenario", default="branch",
                      choices=["branch", "leaf-spine", "hotel", "retail"],
                      help="which canned scenario to run (default: branch)")
    demo.add_argument("--report-dir", default=None,
                      help="write HTML + JSON reports to this directory after the run")

    cfg = sub.add_parser("config", help="print effective configuration")
    cfg.add_argument("--path", default=None, help="load config from this path (YAML/JSON/TOML)")
    cfg.add_argument("--show-defaults", action="store_true",
                     help="print the compiled defaults as JSON and exit")

    health = sub.add_parser("health", help="print platform health (no hardware required)")

    web = sub.add_parser("webui", help="launch the FastAPI web UI")
    web.add_argument("--host", default="0.0.0.0", help="bind host (default: 0.0.0.0)")
    web.add_argument("--port", type=int, default=8765, help="bind port (default: 8765)")
    web.add_argument("--static", default=None, help="path to static web UI directory")

    sub.add_parser("scenarios", help="list built-in demo scenarios")

    args = parser.parse_args(argv)
    if args.command == "autopilot":
        return run_autopilot(args.port, args.execute, report_dir=args.report_dir)
    if args.command == "demo":
        return run_demo(scenario=args.scenario, report_dir=args.report_dir)
    if args.command == "config":
        return run_config(path=args.path, show_defaults=args.show_defaults)
    if args.command == "health":
        return run_health()
    if args.command == "webui":
        return run_webui(host=args.host, port=args.port, static_dir=args.static)
    if args.command == "scenarios":
        return run_scenarios()
    return 1


if __name__ == "__main__":
    sys.exit(main())
