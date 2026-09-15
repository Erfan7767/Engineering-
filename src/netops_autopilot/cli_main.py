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
import os
import sys
from typing import Any, Optional

from .autopilot import AutopilotEngine, OperatorIO
from .cli import ConsoleIO, ScriptedIO
from .core.failures import Failure
from .core.timeauth import TimeAuthority
from .ledger.paths import IN_MEMORY_NOTICE, describe, ledger_path
from .ledger.store import LedgerStore
from datetime import datetime, timezone


def _real_session_factory(port: str):
    """Open the console session and probe a banner (best-effort evidence)."""
    from .access.serial_transport import SerialConsoleTransport, SerialProfile

    profile = SerialProfile(port=port)
    transport = SerialConsoleTransport(profile)
    transport.open()
    # The connect banner is the vendor evidence, and it exists only once: it
    # is whatever the device printed while the line was coming up, which the
    # transport captured during its baud probe. Reading an empty command
    # afterwards returns a prompt and identifies nothing, which used to send
    # every real console run to "FAMILY_UNKNOWN — ask the operator".
    banner = transport.banner
    if not banner.strip():
        try:
            banner = transport.execute("", 1.5)
        except (TimeoutError, Failure):
            banner = b""
    return (transport, banner)


def _make_credential_provider(method: str, username: Optional[str] = None):
    """Build the operator-credential callback used by the mgmt factory.

    Passwords are read with :func:`getpass.getpass` so they are never echoed,
    never stored in shell history, and never written to the ledger. They are
    collected once per run and reused for every device the operator's account
    can reach — the platform never invents or defaults a credential.
    """
    import getpass
    cache: dict[str, Any] = {}

    def provider(device_ref: str, vendor_family: str):
        from .access.mgmt_session import MgmtCredential
        if cache:
            base = next(iter(cache.values()))
            return MgmtCredential(username=base.username, password=base.password,
                                  enable_secret=base.enable_secret, method=method)
        user = username or getpass.getpass(
            f"Management username for {device_ref} ({vendor_family}): ")
        if not user:
            raise Failure(cls=FailureClass.BLOCKED, causes=(
                f"NO_CREDENTIALS: operator supplied no username for {device_ref}; "
                f"the platform does not fall back to a default account",))
        password = getpass.getpass(f"Management password for {user}@{device_ref}: ")
        secret = getpass.getpass(
            f"Enable secret for {device_ref} (blank if none): ").strip()
        cred = MgmtCredential(username=user, password=password,
                              enable_secret=secret, method=method)
        cache["base"] = cred
        return cred

    return provider


#: Lazily-built management-session factory shared by the web chat path.
#: ``web/server.py`` imports :func:`_open_real_management`; before Phase V that
#: name did not exist anywhere in the codebase, so the web operator could never
#: reach real hardware — every attempt fell into the ``NO_REAL_ADAPTER``
#: refusal. It is implemented now, on top of the same identity-confirming
#: factory the CLI uses.
_SHARED_MGMT_FACTORY: Any = None


def _open_real_management(device_ref: str, crawl: Any = None,
                          console_session: Any = None,
                          seed_ref: str = "seed-01") -> Any:
    """Open a confirmed management session for the web/chat device runner.

    ``crawl`` is the discovery evidence the operator already holds. Without it
    the factory refuses (typed) rather than guessing an address, because a
    device it never observed is a device it must not touch.
    """
    global _SHARED_MGMT_FACTORY
    if _SHARED_MGMT_FACTORY is None:
        _SHARED_MGMT_FACTORY = _real_mgmt_factory(
            method=os.environ.get("NETOPS_MGMT_METHOD", "ssh"),
            username=os.environ.get("NETOPS_MGMT_USER"),
            allow_unverified_identity=(
                os.environ.get("NETOPS_ALLOW_UNVERIFIED_IDENTITY", "") == "1"),
        )
    if crawl is not None:
        _SHARED_MGMT_FACTORY.bind_crawl(crawl, console_session=console_session,
                                        seed_ref=seed_ref)
    return _SHARED_MGMT_FACTORY(device_ref, ())


def _real_mgmt_factory(method: str = "ssh", username: Optional[str] = None,
                       allow_unverified_identity: bool = False):
    """The real out-of-band path to every discovered device.

    Phase V replaced the old unconditional ``MGMT_PATH_NOT_MODELED`` refusal.
    Devices are reached at management addresses discovery *observed*, and each
    session is identity-confirmed (serial match against the crawl evidence)
    before a single configuration line is sent.
    """
    from .access.mgmt_session import MgmtSessionFactory
    return MgmtSessionFactory(
        credential_provider=_make_credential_provider(method, username),
        allow_unverified_identity=allow_unverified_identity)


def run_autopilot(port: str, execute: bool, report_dir: Optional[str] = None,
                  mgmt_method: str = "ssh", mgmt_user: Optional[str] = None,
                  allow_unverified_identity: bool = False,
                  max_devices: int = 256, max_l3_probes: int = 32,
                  discovery_workers: int = 1) -> int:
    # A budget of zero would discover nothing and report an empty topology as
    # though the network were empty — the one answer discovery must never give.
    if max_devices < 1 or max_l3_probes < 1 or discovery_workers < 1:
        print(f"Refusing: --max-devices must be >= 1 (got {max_devices}), "
              f"--max-l3-probes must be >= 1 (got {max_l3_probes}) and "
              f"--discovery-workers must be >= 1 (got {discovery_workers}). A "
              f"budget of zero would report an empty network that is not empty.",
              file=sys.stderr)
        return 2
    store = LedgerStore(ledger_path())
    # The ledger is the evidence record for this run. An operator who cannot
    # find it cannot audit what was sent to their devices, so the resolved
    # path is announced rather than left to be guessed.
    print(describe())
    key_id = store.keys.create_key("autopilot-collector")
    engine = AutopilotEngine(
        store=store, key_id=key_id, io=ConsoleIO(),
        time_authority=TimeAuthority(clock=lambda: datetime.now(timezone.utc)),
        max_devices=max_devices, max_l3_probes=max_l3_probes,
        discovery_workers=discovery_workers)
    report = engine.run(
        probe_port_session_factory=_real_session_factory,
        mgmt_session_factory=_real_mgmt_factory(
            method=mgmt_method, username=mgmt_user,
            allow_unverified_identity=allow_unverified_identity),
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


def run_demo(scenario: str = "branch", report_dir: Optional[str] = None,
             execute: bool = False) -> int:
    from .simfabric import SimFabricFactory, make_ledger_stack
    from .cli.scenarios import make_scenario_io
    from .core.failures import Failure
    store, key_id, _counters, time_auth = make_ledger_stack()
    # make_ledger_stack builds an in-memory store. The summary at the end of
    # this run reports a ledger event count and a verified hash chain, which
    # would read as a record the operator can audit later. It is not one.
    print(IN_MEMORY_NOTICE)
    try:
        fabric = SimFabricFactory(include_access=True, access_behavior="allow")
    except Failure as exc:
        print(f"Demo cannot start: {exc}", file=sys.stderr)
        return 2
    io = make_scenario_io(scenario)
    if execute:
        # The apply gate demands a typed BOND; the demo answers it so the
        # whole discover → design → render → APPLY → verify → rollback path
        # can be exercised without hardware.
        io.append_answers({"bond_confirm": "BOND"})
    engine = AutopilotEngine(store=store, key_id=key_id,
                             io=io, time_authority=time_auth)
    report = engine.run(
        probe_port_session_factory=lambda port: fabric.probe(port),
        # The factory object, not its bound ``.open`` method: the access-retry
        # loop needs the ``grant()`` hook to model the operator supplying
        # working credentials, and a bound method does not carry it. Passing
        # ``.open`` made the demo answer "y" to the retry prompt and then do
        # nothing at all — a prompt whose answer is ignored is worse than no
        # prompt, because it reports a decision that was never acted on.
        mgmt_session_factory=fabric,
        port="SIM0", execute=execute)
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
        kv_line("Evidence ledger", describe()),
        kv_line("Device drivers", _driver_status()),
    ]
    print(Panel("NetOps Autopilot · Health", lines, accent="\x1b[36m").render())
    return 0


#: What each driver is for, and what is lost without it. The console driver is
#: first because it is the canonical hardware path: it is how the operator's
#: one cabled device is reached at all.
_DRIVERS: tuple[tuple[str, str, str], ...] = (
    ("serial", "console", "cannot open a serial console port — the cabled device is unreachable"),
    ("netmiko", "SSH", "cannot open SSH management sessions to discovered devices"),
    ("telnetlib", "telnet", "telnet management unavailable (stdlib telnetlib was removed in Python 3.13, PEP 594)"),
    ("yaml", "YAML config", "YAML configuration files cannot be read"),
    ("fastapi", "web UI", "the web control surface cannot start"),
)


def _driver_status() -> str:
    """Which device drivers this interpreter can actually import.

    This used to be a fixed string — "netmiko (SSH), pyyaml (YAML),
    fastapi+uvicorn (web) — all optional" — printed whether or not any of them
    was installed. A health check that reports availability without checking
    is worse than no health check: it tells an operator their machine is ready
    for hardware it cannot talk to. And it never mentioned ``serial``, which is
    the driver the whole console path depends on.

    Each entry is probed with a real import, so the answer is what this
    interpreter can do, not what the documentation says it should be able to.
    """
    import importlib.util

    parts: list[str] = []
    consequences: list[str] = []
    for module, role, consequence in _DRIVERS:
        if importlib.util.find_spec(module) is None:
            parts.append(f"{role}: MISSING")
            consequences.append(consequence)
        else:
            parts.append(f"{role}: OK")
    if consequences:
        parts.append("— " + "; ".join(consequences))
    return ", ".join(parts)


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


def run_chat(port: Optional[str] = None, message: Optional[str] = None,
             simulate: bool = False) -> int:
    """Headless chat REPL — the same operator the web UI exposes.

    ``--message`` runs a single turn and exits (scriptable); with no message
    the operator reads lines until EOF or ``exit``/``quit``.
    """
    from .access.allowlist import CommandAllowlist
    from .chat.device_runner import DeviceCommandRunner
    from .chat.operator import ChatOperator
    from .specs_data import specs_data_dir

    store = LedgerStore(ledger_path())
    print(describe())
    key_id = store.keys.create_key("chat-operator")
    time_auth = TimeAuthority(clock=lambda: datetime.now(timezone.utc))
    engine = AutopilotEngine(store=store, key_id=key_id, io=ConsoleIO(),
                             time_authority=time_auth)
    allowlist = CommandAllowlist.load_dir(specs_data_dir("allowlists"))

    seed_port = port or os.environ.get("NETOPS_SEED_PORT", "SIM0")
    if simulate or str(seed_port).upper().startswith("SIM"):
        from .simfabric import SimFabricFactory
        fabric = SimFabricFactory(include_access=True, access_behavior="allow")
        session_factory = fabric.device_session

        class _SimRunner:
            def run(self, *, port, execute, answers):
                from .cli import ScriptedIO
                # The chat supplies the answers the run needs (bond confirm,
                # intent, WAN, availability, growth); they must actually be
                # installed on the engine or it falls back to the interactive
                # console and blocks on a prompt nobody is answering.
                engine.io = ScriptedIO(dict(answers))
                return engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                                  mgmt_session_factory=fabric,
                                  port=port, execute=execute)
        runner: Any = _SimRunner()
    else:
        mgmt = _real_mgmt_factory()
        session_factory = lambda ref: _open_real_management(ref)  # noqa: E731

        class _RealRunner:
            def run(self, *, port, execute, answers):
                from .cli import ScriptedIO
                engine.io = ScriptedIO(dict(answers))
                return engine.run(probe_port_session_factory=_real_session_factory,
                                  mgmt_session_factory=mgmt,
                                  port=port, execute=execute)
        runner = _RealRunner()

    device_runner = DeviceCommandRunner(session_factory=session_factory,
                                        allowlist=allowlist, store=store)
    op = ChatOperator(store=store, runner=runner, device_runner=device_runner,
                      allowlist=allowlist)

    def _turn(text: str) -> None:
        reply = op.handle(text)
        # OperatorReply is a dataclass: print what an operator reads, not the
        # repr. ``summary`` is the one-line verdict, ``detail`` the evidence.
        summary = getattr(reply, "summary", "") or ""
        detail = getattr(reply, "detail", "") or ""
        status = getattr(getattr(reply, "status", None), "value", None) or ""
        head = f"[{status.upper()}] {summary}" if status else summary
        print(head)
        if detail:
            print(detail)
        for action in getattr(reply, "actions", None) or []:
            label = action.get("label") if isinstance(action, dict) else str(action)
            if label:
                print(f"  → {label}")

    if message:
        _turn(message)
        return 0
    print("NetOps Autopilot · chat operator  (type 'help', 'exit' to quit)")
    while True:
        try:
            line = input("netops> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        if line.lower() in {"exit", "quit", "خروج"}:
            return 0
        _turn(line)


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
    ap.add_argument("--mgmt-method", default="ssh", choices=["ssh", "telnet"],
                    help="management path used to reach discovered neighbours (default: ssh)")
    ap.add_argument("--mgmt-user", default=None,
                    help="management username (prompted securely if omitted)")
    ap.add_argument("--allow-unverified-identity", action="store_true",
                    help="configure a device whose serial could not be confirmed "
                         "(operator takes responsibility; refused by default)")
    ap.add_argument("--max-devices", type=int, default=256, metavar="N",
                    help="discovery device budget (default 256). Neighbours beyond "
                         "it are recorded NOT_PROBED and get no configuration; "
                         "raise it for a large campus")
    ap.add_argument("--max-l3-probes", type=int, default=32, metavar="N",
                    help="how many L3 endpoints discovery may probe for devices "
                         "that never advertised themselves (default 32)")
    ap.add_argument("--discovery-workers", type=int, default=1, metavar="N",
                    help="management sessions to hold open at once during "
                         "discovery (default 1 = serial). Overlaps only the "
                         "wait on devices; evidence is still recorded in sorted "
                         "device order, so the run is unchanged. A large campus "
                         "at ~3 s/device is ~14 min serially; 16 workers cuts "
                         "that to under a minute. Keep it within the VTY limit "
                         "of the gear.")

    demo = sub.add_parser("demo", help="deterministic simulated fabric, full flow, no hardware")
    demo.add_argument("--scenario", default="branch",
                      choices=["branch", "leaf-spine", "hotel", "retail"],
                      help="which canned scenario to run (default: branch)")
    demo.add_argument("--report-dir", default=None,
                      help="write HTML + JSON reports to this directory after the run")
    demo.add_argument("--execute", action="store_true",
                      help="run the full apply path against the simulated fabric "
                           "(the typed BOND gate is still enforced)")

    cfg = sub.add_parser("config", help="print effective configuration")
    cfg.add_argument("--path", default=None, help="load config from this path (YAML/JSON/TOML)")
    cfg.add_argument("--show-defaults", action="store_true",
                     help="print the compiled defaults as JSON and exit")

    health = sub.add_parser("health", help="print platform health (no hardware required)")

    web = sub.add_parser("webui", help="launch the FastAPI web UI")
    web.add_argument("--host", default="0.0.0.0", help="bind host (default: 0.0.0.0)")
    web.add_argument("--port", type=int, default=8765, help="bind port (default: 8765)")
    web.add_argument("--static", default=None, help="path to static web UI directory")

    chat = sub.add_parser("chat", help="interactive network operator (Arabic/English)")
    chat.add_argument("--port", default=None,
                      help="seed console port (SIM0 = deterministic simulated fabric)")
    chat.add_argument("--message", default=None,
                      help="run a single chat turn and exit (scriptable)")
    chat.add_argument("--simulate", action="store_true",
                      help="force the deterministic simulated fabric")

    sub.add_parser("scenarios", help="list built-in demo scenarios")

    args = parser.parse_args(argv)
    if args.command == "autopilot":
        return run_autopilot(args.port, args.execute, report_dir=args.report_dir,
                             mgmt_method=args.mgmt_method, mgmt_user=args.mgmt_user,
                             allow_unverified_identity=args.allow_unverified_identity,
                             max_devices=args.max_devices,
                             max_l3_probes=args.max_l3_probes,
                             discovery_workers=args.discovery_workers)
    if args.command == "demo":
        return run_demo(scenario=args.scenario, report_dir=args.report_dir,
                        execute=args.execute)
    if args.command == "config":
        return run_config(path=args.path, show_defaults=args.show_defaults)
    if args.command == "health":
        return run_health()
    if args.command == "webui":
        return run_webui(host=args.host, port=args.port, static_dir=args.static)
    if args.command == "chat":
        return run_chat(port=args.port, message=args.message, simulate=args.simulate)
    if args.command == "scenarios":
        return run_scenarios()
    return 1


if __name__ == "__main__":
    sys.exit(main())
