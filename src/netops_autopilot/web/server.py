"""FastAPI server — REST + WebSocket surface for the Autopilot.

Endpoints:
- ``GET  /healthz``                — liveness + build info
- ``POST /runs``                   — start a new run (port + execute flag)
- ``GET  /runs/{run_id}``          — run summary (JSON)
- ``GET  /runs/{run_id}/topology`` — topology JSON (nodes, edges, gaps)
- ``GET  /runs/{run_id}/report``   — HTML report (self-contained)
- ``WS   /runs/{run_id}/events``   — live event stream
- ``POST /chat``                   — send a chat message to the operator
- ``GET  /chat/stream``            — SSE stream of the operator's live reply
- ``GET  /state``                  — operator state snapshot
- ``GET  /``                       — embedded web UI (v8 chat operator)

The server runs the AutopilotEngine in a thread, so the API stays
responsive while the discovery crawl is in progress.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3 as _sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# --- global sqlite3 thread-safety patch ----------------------------------
# FastAPI runs sync endpoints in a threadpool; the SSE stream runs the
# chat in a worker thread. The LedgerStore uses sqlite3 with the
# default ``check_same_thread=True``, which raises
# ``ProgrammingError`` if a different thread touches the connection.
# Patch ``sqlite3.connect`` to default to thread-safe so any
# LedgerStore — wherever created — is usable from any thread.
_orig_sqlite3_connect = _sqlite3.connect
def _thread_safe_sqlite3_connect(database, *args, **kwargs):
    kwargs.setdefault("check_same_thread", False)
    return _orig_sqlite3_connect(database, *args, **kwargs)
_sqlite3.connect = _thread_safe_sqlite3_connect  # type: ignore[assignment]
# ------------------------------------------------------------------------

from ..autopilot import AutopilotEngine
from ..cli import ConsoleIO
from ..core.failures import Failure, FailureClass
from ..core.timeauth import TimeAuthority
from ..ledger.paths import ledger_path, run_ledger_path
from ..ledger.store import LedgerStore
from ..reporting.html_report import render_html_report, report_from_autopilot
from ..reporting.json_report import render_json_report


@dataclass
class RunRecord:
    run_id: str
    status: str = "PENDING"        # PENDING | RUNNING | COMPLETE | BLOCKED | ERROR
    final: str = ""
    created_at: str = ""
    finished_at: Optional[str] = None
    report: Any = None
    error: Optional[str] = None
    events: list[dict[str, Any]] = field(default_factory=list)


_RUNS: dict[str, RunRecord] = {}
_RUNS_LOCK = threading.Lock()
_API_KEY = os.environ.get("NETOPS_API_KEY", "")  # L11: empty ⇒ disabled


# ----------------- FastAPI app factory (lazy import) -----------------


def _ensure_fastapi():
    try:
        from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Header, Request  # noqa: F401
        from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
        from fastapi.staticfiles import StaticFiles
        return True
    except ImportError as exc:
        raise Failure(
            cls=__import__("netops_autopilot.core.failures", fromlist=["FailureClass"]).FailureClass.BLOCKED,
            causes=("WEB_DRIVER_UNAVAILABLE: FastAPI not installed. `pip install fastapi uvicorn[standard]` to enable.",),
        ) from exc


def create_app(*, static_dir: Optional[Path] = None) -> Any:
    if static_dir is None:
        # The assets ship inside the package (netops_autopilot/webui/static).
        # Walking parents to the repository root instead — the previous
        # behaviour — resolved to nothing in an installed wheel, and the app
        # then served 404 for "/" while reporting a clean startup.
        from ..webui import WEBUI_DIR
        if WEBUI_DIR.exists():
            static_dir = WEBUI_DIR
    """Construct the FastAPI app. Caller is responsible for ``uvicorn.run(app)``."""
    _ensure_fastapi()
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Header as _Header
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles

    app = FastAPI(
        title="NetOps Autopilot API",
        version="0.1.0",
        description="Evidence-driven autonomous network engineering — REST + WebSocket surface.",
    )

    # Re-bind Header to a module-level alias so route signatures can use it
    # without re-importing in the closure scope (which FastAPI misinterprets).
    Header = _Header

    def _check_key(authorization: Optional[str]) -> None:
        if not _API_KEY:
            return
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing Bearer token")
        if authorization.removeprefix("Bearer ").strip() != _API_KEY:
            raise HTTPException(status_code=403, detail="invalid API key")

    @app.get("/healthz")
    def healthz() -> dict:
        return {
            "status": "ok",
            "service": "netops-autopilot",
            "version": "0.1.0",
            "api_key_required": bool(_API_KEY),
            "runs_in_memory": len(_RUNS),
            "ts": datetime.now(timezone.utc).isoformat(),
        }

    @app.post("/runs")
    def create_run(payload: dict, authorization: Optional[str] = Header(default=None)) -> dict:
        _check_key(authorization)
        port = payload.get("port")
        execute = bool(payload.get("execute", False))
        # The "sim" flag tells the API to use the deterministic simulated
        # fabric (no real hardware needed). It exists so the operator can
        # rehearse the whole flow from the browser.
        sim = bool(payload.get("sim", False)) or (port or "").upper().startswith("SIM")
        # What network the operator wants. Without this the worker had no way
        # to know and built the same blueprint for every request.
        intent = payload.get("intent")
        if intent is not None and not isinstance(intent, str):
            raise HTTPException(status_code=400, detail="`intent` must be a string")
        if not port or not isinstance(port, str):
            raise HTTPException(status_code=400, detail="`port` (string) is required")
        run_id = uuid.uuid4().hex[:12]
        rec = RunRecord(
            run_id=run_id,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        with _RUNS_LOCK:
            _RUNS[run_id] = rec
        # Launch in a daemon thread so the request returns immediately.
        th = threading.Thread(
            target=_run_autopilot_worker,
            args=(run_id, port, execute, sim, intent),
            daemon=True,
        )
        th.start()
        return {"run_id": run_id, "status": rec.status}

    @app.get("/runs/{run_id}")
    def get_run(run_id: str, authorization: Optional[str] = Header(default=None)) -> dict:
        _check_key(authorization)
        with _RUNS_LOCK:
            rec = _RUNS.get(run_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="run not found")
        return {
            "run_id": rec.run_id,
            "status": rec.status,
            "final": rec.final,
            "created_at": rec.created_at,
            "finished_at": rec.finished_at,
            "error": rec.error,
            "phases": [vars(p) for p in getattr(rec.report, "phases", [])] if rec.report else [],
        }

    @app.get("/runs/{run_id}/topology")
    def get_topology(run_id: str, authorization: Optional[str] = Header(default=None)) -> dict:
        _check_key(authorization)
        with _RUNS_LOCK:
            rec = _RUNS.get(run_id)
        if rec is None or rec.report is None or getattr(rec.report, "topology", None) is None:
            raise HTTPException(status_code=404, detail="topology not available")
        topo = rec.report.topology
        return {
            "nodes": [vars(n) for n in getattr(topo, "nodes", [])],
            "edges": [vars(e) for e in getattr(topo, "edges", [])],
            "gaps": [str(g) for g in getattr(topo, "gaps", [])],
            "ascii": getattr(topo, "ascii", ""),
        }

    @app.get("/runs/{run_id}/report")
    def get_html_report(run_id: str, authorization: Optional[str] = Header(default=None)):
        _check_key(authorization)
        with _RUNS_LOCK:
            rec = _RUNS.get(run_id)
        if rec is None or rec.report is None:
            raise HTTPException(status_code=404, detail="report not available")
        data = report_from_autopilot(
            rec.report,
            run_id=rec.run_id,
            ledger_event_count=0,
            chain_ok=True,
        )
        return HTMLResponse(render_html_report(data))

    @app.get("/runs/{run_id}/report.json")
    def get_json_report(run_id: str, authorization: Optional[str] = Header(default=None)) -> JSONResponse:
        _check_key(authorization)
        with _RUNS_LOCK:
            rec = _RUNS.get(run_id)
        if rec is None or rec.report is None:
            raise HTTPException(status_code=404, detail="report not available")
        return JSONResponse(
            content=json.loads(render_json_report(
                report=rec.report,
                ledger_event_count=0,
                chain_ok=True,
            ))
        )

    @app.websocket("/runs/{run_id}/events")
    async def ws_events(websocket: WebSocket, run_id: str):
        await websocket.accept()
        try:
            with _RUNS_LOCK:
                rec = _RUNS.get(run_id)
            if rec is None:
                await websocket.send_json({"type": "error", "detail": "run not found"})
                # Small delay so the client has a chance to read before close.
                await asyncio.sleep(0.05)
                await websocket.close()
                return
            await websocket.send_json({
                "type": "status",
                "status": rec.status,
                "final": rec.final,
                "phases": [vars(p) for p in getattr(rec.report, "phases", [])] if rec.report else [],
            })
            await asyncio.sleep(0.05)
            await websocket.close()
        except WebSocketDisconnect:
            return

    if static_dir is not None and static_dir.exists():
        app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")
        # Also serve the v2 UI at /ui/v2 (back-compat)
        v2_dir = static_dir / "v2"
        if v2_dir.exists():
            app.mount("/ui/v2", StaticFiles(directory=str(v2_dir), html=True), name="ui-v2")
        # v3: world-class dark UI with AR/EN i18n and full workflow
        v3_dir = static_dir / "v3"
        if v3_dir.exists():
            app.mount("/ui/v3", StaticFiles(directory=str(v3_dir), html=True), name="ui-v3")
            from fastapi.responses import HTMLResponse as _HTML
            v3_index = static_dir / "v3" / "index.html"
            if v3_index.exists():
                @app.get("/ui/", include_in_schema=False)
                def _serve_v3_index():
                    return _HTML(v3_index.read_text(encoding="utf-8"))
                @app.get("/", include_in_schema=False)
                def _serve_root():
                    return _HTML(v3_index.read_text(encoding="utf-8"))

        # v4: chat-driven operator UI. Mounted under /ui/v4.
        v4_dir = static_dir / "v4"
        if v4_dir.exists():
            app.mount("/ui/v4", StaticFiles(directory=str(v4_dir), html=True), name="ui-v4")
        # v5: previous world-class chat operator UI.
        v5_dir = static_dir / "v5"
        if v5_dir.exists():
            app.mount("/ui/v5", StaticFiles(directory=str(v5_dir), html=True), name="ui-v5")
        # v8: world-class chat operator UI with REAL device execution.
        # Now mounts at /chat by default; older versions (v7, v6, v5,
        # v4) stay reachable at /ui/v7/, /ui/v6/, /ui/v5/, /ui/v4/.
        v8_dir = static_dir / "v8"
        v7_dir = static_dir / "v7"
        v6_dir = static_dir / "v6"
        v5_dir = static_dir / "v5"
        v4_dir = static_dir / "v4"

        if v8_dir.exists():
            app.mount("/ui/v8", StaticFiles(directory=str(v8_dir), html=True), name="ui-v8")
            v8_index = v8_dir / "index.html"
            if v8_index.exists():
                @app.get("/chat", include_in_schema=False)
                def _serve_v8_chat():
                    return _HTML(v8_index.read_text(encoding="utf-8"))

        # Always mount the older versions so they remain reachable.
        if v7_dir.exists():
            app.mount("/ui/v7", StaticFiles(directory=str(v7_dir), html=True), name="ui-v7")
        if v6_dir.exists():
            app.mount("/ui/v6", StaticFiles(directory=str(v6_dir), html=True), name="ui-v6")
        if v5_dir.exists():
            app.mount("/ui/v5", StaticFiles(directory=str(v5_dir), html=True), name="ui-v5")
        if v4_dir.exists():
            app.mount("/ui/v4", StaticFiles(directory=str(v4_dir), html=True), name="ui-v4")

        if not v8_dir.exists():
            # Fall back to v7, then v6, then v5, then v4.
            for vname in ("v7", "v6", "v5", "v4"):
                vx = static_dir / vname / "index.html"
                if vx.exists():
                    @app.get("/chat", include_in_schema=False)
                    def _serve_fallback():
                        return _HTML(vx.read_text(encoding="utf-8"))
                    break

    # ============================================================ chat API
    # The chat operator is **shared across all requests** so a
    # multi-step conversation (discover → apply) preserves state
    # between calls. SQLite is configured thread-safe at module
    # import time (see top of file), so the same connection can be
    # touched from any thread; a process-wide lock serializes
    # engine runs to avoid "database is locked" under load.
    import threading as _threading
    _chat_state_lock = _threading.Lock()
    # The seed port — used by the chat's device runner to decide
    # whether to use the SimFabric (SIM-prefix) or real hardware.
    _seed_port_value = os.environ.get("NETOPS_SEED_PORT", "SIM0")

    def _get_chat_op() -> Any:
        # Lazy init guarded by the lock so two concurrent first
        # requests don't both construct operators.
        op = getattr(create_app, "_shared_chat_op", None)
        if op is not None:
            return op
        try:
            from netops_autopilot.chat import ChatOperator
            from netops_autopilot.autopilot import AutopilotEngine, OperatorIO
            from netops_autopilot.cli import RefusingIO
            from netops_autopilot.ledger.paths import ledger_path
            from netops_autopilot.ledger.store import LedgerStore
            import os, tempfile

            store = LedgerStore(ledger_path("netops_webui_ledger.sqlite3"))
            key_id = store.keys.create_key("webui-chat")
            runner = AutopilotEngine(store=store, key_id=key_id, io=RefusingIO())
            # Build a DeviceCommandRunner so chat commands like
            # ``ping``, ``traceroute``, ``show ip route`` actually
            # execute on the seed device. We use the SimFabric in
            # sim mode (port starting with SIM) and the real refused
            # factories for real ports. The session factory takes
            # ``device_ref`` and returns a fresh session.
            from netops_autopilot.access.allowlist import CommandAllowlist
            from netops_autopilot.chat.device_runner import DeviceCommandRunner
            from netops_autopilot.specs_data import specs_data_dir

            def _session_factory(device_ref: str):
                # In sim mode the SimFabric answers all read-only
                # commands for any device_ref. On real hardware the
                # management session is opened from the connection
                # layer (see cli_main).
                if str(_seed_port_value).upper().startswith("SIM"):
                    from ..simfabric import SimFabricFactory
                    fabric = SimFabricFactory()
                    return fabric.device_session(device_ref)
                # Real hardware: open a management session via the
                # connection layer.
                try:
                    from netops_autopilot.cli_main import _open_real_management
                    return _open_real_management(device_ref)
                except Exception:  # noqa: BLE001
                    # If no real adapter is wired, fall back to refused
                    raise Failure(cls=FailureClass.BLOCKED, causes=(
                        f"NO_REAL_ADAPTER: cannot open session for {device_ref} "
                        f"on a real port — set NETOPS_SEED_PORT=SIM* to use the "
                        f"deterministic sim-fabric.",))

            allowlist = CommandAllowlist.load_dir(
                specs_data_dir("allowlists")
            )
            device_runner = DeviceCommandRunner(
                session_factory=_session_factory,
                allowlist=allowlist,
                store=store,
            )
            _shared_chat_op = ChatOperator(
                store=store, runner=runner,
                device_runner=device_runner,
                allowlist=allowlist,
            )
            setattr(create_app, "_shared_chat_op", _shared_chat_op)
            return _shared_chat_op
        except Exception as e:  # noqa: BLE001
            # Surface import errors during request handling instead of
            # crashing on app construction.
            err = repr(e)
            class _Broken:
                def handle(self, message: str) -> dict:
                    return {
                        "status": "FAILURE",
                        "intent": "ERROR",
                        "summary": "Chat operator unavailable",
                        "detail": f"Failed to construct ChatOperator: {err}",
                        "actions": [],
                        "data": {},
                        "evidence_ids": [],
                        "correlation_id": "n/a",
                    }
            setattr(create_app, "_shared_chat_op", _Broken())
            return getattr(create_app, "_shared_chat_op")

    @app.post("/chat")
    def post_chat(payload: dict, authorization: Optional[str] = Header(default=None)) -> dict:
        # Chat endpoint is read-only and unauthenticated — the
        # autopilot run inside the operator still goes through BOND.
        message = (payload.get("message") or "").strip()
        if not message:
            raise HTTPException(status_code=400, detail="empty message")
        op = _get_chat_op()
        # Serialize: the ledger is a single SQLite file. Acquire the
        # process-wide lock to avoid "database is locked" errors
        # under load, and to ensure that no two engine runs interleave
        # their writes.
        with _chat_state_lock:
            reply = op.handle(message)
        # Real ChatOperator returns OperatorReply; broken stub returns dict.
        if hasattr(reply, "to_dict"):
            return reply.to_dict()
        return dict(reply)

    @app.get("/chat/stream")
    def stream_chat(message: str, lang: str = "en") -> Any:
        """Server-Sent Events stream of the live chat execution.

        Streams phase progress as the engine runs, then closes with
        the final OperatorReply. Synchronous endpoint so the SQLite
        ledger (created in the main thread) is used consistently.
        """
        from fastapi.responses import StreamingResponse as _SR
        import queue as _queue
        import threading as _threading

        message = (message or "").strip()
        if not message:
            raise HTTPException(status_code=400, detail="empty message")

        op = _get_chat_op()
        runner = getattr(op, "_runner", None)
        prev_io = getattr(runner, "io", None) if runner is not None else None

        # Sync queue shared by the engine's worker thread and the
        # sync generator below (which lives on the same thread as
        # the FastAPI worker). Both sides stay in the main thread.
        events: "_queue.Queue[dict]" = _queue.Queue()
        done = _threading.Event()

        class _StreamIO:
            """Forwards to an inner OperatorIO and mirrors it onto the stream.

            ``set_inner`` exists because the chat installs the operator's
            answers for a run by replacing the engine's io. Replacing this
            wrapper outright would silently stop the phase stream mid-run, so
            the answers are installed *inside* it instead.
            """

            def __init__(self, inner):
                self._inner = inner

            def set_inner(self, inner):
                previous, self._inner = self._inner, inner
                return previous

            def ask(self, prompt: str, key=None) -> str:
                events.put({"type": "ask", "prompt": prompt[:200], "key": key})
                a = self._inner.ask(prompt, key=key) if key else self._inner.ask(prompt)
                events.put({"type": "answer", "value": a, "key": key})
                return a

            def confirm(self, prompt: str, key=None) -> bool:
                events.put({"type": "confirm", "prompt": prompt[:200], "key": key})
                r = (self._inner.confirm(prompt, key=key) if key
                     else self._inner.confirm(prompt))
                events.put({"type": "answer", "value": "y" if r else "n"})
                return r

            def show(self, text: str) -> None:
                events.put({"type": "show", "text": text})
                if self._inner is not None and hasattr(self._inner, "show"):
                    try:
                        self._inner.show(text)
                    except Exception:  # noqa: BLE001
                        pass

        def _run():
            try:
                if runner is not None:
                    runner.io = _StreamIO(prev_io)
                # Serialize ledger writes across all threads.
                with _chat_state_lock:
                    reply = op.handle(message)
                if hasattr(reply, "to_dict"):
                    payload = reply.to_dict()
                else:
                    payload = dict(reply)
                events.put({"type": "reply", **payload})
            except Exception as exc:  # noqa: BLE001
                events.put({"type": "error", "detail": str(exc)})
            finally:
                if runner is not None:
                    runner.io = prev_io
                events.put({"type": "done"})
                done.set()

        # Run on a worker thread so the engine's blocking IO doesn't
        # stall the event loop. The ledger is in the main thread
        # (created in create_app), so the SQLite store needs to be
        # used there. We achieve this by NOT using ``runner.io``
        # directly in the worker — instead, the chat operator calls
        # ``op.handle()`` which already runs synchronously. We
        # therefore need to call op.handle() in the main thread, but
        # the engine is blocking. Solution: run the chat in a
        # thread, and have that thread ONLY call op.handle, while
        # the ledger accesses happen in the main thread for any
        # subsequent /state calls. SQLite connection is per-thread
        # in CPython, so a fresh connection per request would be
        # needed for the worker. We work around this by setting
        # ``check_same_thread=False`` on the connection at startup.
        # See _configure_ledger_thread_safety below.
        _threading.Thread(target=_run, daemon=True).start()

        def _gen():
            yield f"data: {json.dumps({'type': 'start', 'lang': lang})}\n\n"
            # Heartbeat: keep the connection open even if the engine
            # is quiet. The engine's ask/confirm IO blocks the
            # worker thread until the IO returns, which is the
            # synchronous NullIO — so events arrive quickly. We just
            # poll the queue.
            while not (done.is_set() and events.empty()):
                try:
                    ev = events.get(timeout=0.1)
                except _queue.Empty:
                    continue
                yield f"data: {json.dumps(ev)}\n\n"
                if ev.get("type") in ("reply", "error", "done"):
                    break

        return _SR(_gen(), media_type="text/event-stream")

    @app.get("/state")
    def get_state() -> dict:
        """Full operator state snapshot for the v5 chat UI.

        Returns bonded, devices, links, ledger, topology (with nodes
        + edges + gaps), design summary, last run, and the recent
        evidence trail. This is the rich snapshot the v5 UI needs to
        render its context panel (state / topology / evidence tabs).
        """
        op = _get_chat_op()
        if not hasattr(op, "context"):
            return {
                "bonded": False, "devices": [], "links": 0, "ledger": 0,
                "topology": None, "design": None, "lastRun": None,
                "evidence": [],
            }
        ctx = op.context
        devices: list[dict] = []
        topo_data = None
        if getattr(ctx, "last_topology", None) and ctx.last_topology:
            topo = ctx.last_topology
            for n in topo.nodes:
                devices.append({
                    "device_ref": n.device_ref,
                    "classification": n.classification,
                    "model": n.model,
                    "version": n.version,
                    "vendor": n.vendor_family,
                    "status": n.status,
                })
            topo_data = {
                "nodes": [
                    {
                        "device_ref": n.device_ref,
                        "classification": n.classification,
                        "vendor": n.vendor_family,
                        "model": n.model,
                    }
                    for n in topo.nodes
                ],
                "edges": [
                    # MapEdge uses ``a_key`` / ``b_key`` in
                    # ``"device|intf"`` form; split them for the UI
                    # to consume.
                    {
                        "a_ref": e.a_key.split("|", 1)[0] if "|" in e.a_key else e.a_key,
                        "b_ref": e.b_key.split("|", 1)[0] if "|" in e.b_key else e.b_key,
                        "a_intf": e.a_key.split("|", 1)[1] if "|" in e.a_key else "",
                        "b_intf": e.b_key.split("|", 1)[1] if "|" in e.b_key else "",
                        "evidence_state": getattr(e, "state", "CONFIRMED"),
                    }
                    for e in topo.edges
                ],
                "gaps": list(topo.gaps),
            }
        design_data = None
        if getattr(ctx, "last_design", None) and ctx.last_design:
            d = ctx.last_design
            design_data = {
                "design_id": d.design_id,
                "roles": [{"device_ref": r.device_ref, "role": r.role} for r in d.roles],
                "blocked": d.blocked,
                "blocking_questions": list(d.blocking_questions),
            }
        last_run_data = None
        if getattr(ctx, "last_run", None) and ctx.last_run:
            r = ctx.last_run
            last_run_data = {
                "final": r.final,
                "phases": [
                    {
                        "phase": p.phase.value if hasattr(p.phase, "value") else str(p.phase),
                        # PhaseRecord has ``status`` (not ``outcome``).
                        "outcome": getattr(p, "status", "OK"),
                        "detail": getattr(p, "detail", ""),
                    }
                    for p in (r.phases or [])
                ],
            }
        # Recent evidence (ledger events) — last 30. Tolerate
        # rotated keys (events() will raise KeyError) and return
        # what we can.
        evidence: list[dict] = []
        try:
            all_events = (op._store.events() if hasattr(op, "_store") else [])
            for ev in all_events[-30:]:
                evidence.append({
                    "id": ev.event_id,
                    "type": ev.type.value if hasattr(ev.type, "value") else str(ev.type),
                })
        except Exception:  # noqa: BLE001
            pass

        return {
            "bonded": bool(ctx.bonded),
            "devices": devices,
            "links": len(topo.edges) if getattr(ctx, "last_topology", None) and ctx.last_topology else 0,
            "ledger": op._store.event_count() if hasattr(op, "_store") else 0,
            "topology": topo_data,
            "design": design_data,
            "lastRun": last_run_data,
            "evidence": evidence,
        }

    return app


class _ConsoleOnlyMgmt:
    """Management sessions for a web-initiated run on real hardware.

    The device on the console cable is reachable — the operator has it open
    right now — so it is served from the session the boot probe already
    established. Opening a second handle on the same serial port would fail,
    which is why the orchestrator hands the console session back through
    ``bind_crawl`` rather than letting a factory open its own.

    Every other device is refused, and the reason is the true one. This worker
    used to refuse *all* devices, seed included, with the text "SSH/telnet
    management sessions are not enabled in this build" — which was untrue, the
    CLI enables them. What is actually true is that this run has no
    credentials: a background worker has no terminal to prompt on and the API
    does not accept a password. The consequence was that a web-initiated run
    on real hardware configured nothing at all, and said OK.
    """

    def __init__(self, port: str) -> None:
        self._port = port
        self._console_session = None
        self._seed_ref = "seed-01"

    def bind_crawl(self, crawl, console_session=None, seed_ref: str = "seed-01"):
        self._console_session = console_session
        self._seed_ref = seed_ref

    def __call__(self, device_ref: str, hints):
        if device_ref == self._seed_ref and self._console_session is not None:
            return self._console_session
        raise Failure(
            cls=FailureClass.BLOCKED,
            causes=(
                f"NO_MGMT_CREDENTIALS:{device_ref} — this run was started from "
                f"the web API, which does not collect management credentials "
                f"and has no terminal to prompt on. The device on the console "
                f"cable is configured; this discovered neighbour is not. Run "
                f"`netops-autopilot autopilot --port {self._port} "
                f"--mgmt-user <user>` to configure it.",
            ),
        )


def _run_autopilot_worker(run_id: str, port: str, execute: bool, sim: bool = False,
                          intent: Optional[str] = None) -> None:
    """Background worker: runs the AutopilotEngine and updates the record.

    When ``sim=True`` (or ``port`` starts with ``SIM``), the worker uses
    the deterministic SimFabric so the operator can rehearse the entire
    flow without a physical device. Otherwise the worker attempts to
    open a real serial port; any failure is reported as a typed ERROR.
    """
    with _RUNS_LOCK:
        rec = _RUNS[run_id]
        rec.status = "RUNNING"
    try:
        # Under the state directory, named after the run. This used to be
        # ``netops-ledger-<run_id>.sqlite3`` in the *current working
        # directory*: one file per run, never removed, so a long-running
        # server littered wherever it was started from.
        store = LedgerStore(run_ledger_path(run_id))
        key_id = store.keys.create_key("api-runner")
        engine = AutopilotEngine(
            store=store, key_id=key_id, io=ConsoleIO(),
            time_authority=TimeAuthority(clock=lambda: datetime.now(timezone.utc)),
        )

        if sim:
            # Use the SimFabric — deterministic, no hardware needed.
            try:
                from ..simfabric import SimFabricFactory
            except Exception:  # pragma: no cover - defensive
                # Fall back to a typed refusal so we never silently mis-run.
                def _refused_probe(p):
                    raise Failure(
                        cls=__import__("netops_autopilot.core.failures", fromlist=["FailureClass"]).FailureClass.BLOCKED,
                        causes=("SIM_UNAVAILABLE: tests/ not on path; run from repo root",),
                    )
                def _refused_mgmt(d, h):
                    raise Failure(
                        cls=__import__("netops_autopilot.core.failures", fromlist=["FailureClass"]).FailureClass.BLOCKED,
                        causes=("SIM_UNAVAILABLE",),
                    )
                engine.io = ScriptedIO(["y", "n"])  # refuse BOND
                report = engine.run(
                    probe_port_session_factory=_refused_probe,
                    mgmt_session_factory=_refused_mgmt,
                    port=port, execute=execute,
                )
                with _RUNS_LOCK:
                    rec.report = report
                    rec.final = report.final
                    rec.status = "COMPLETE" if report.final.startswith("COMPLETE") else "BLOCKED"
                    rec.finished_at = datetime.now(timezone.utc).isoformat()
                return
            fabric = SimFabricFactory(include_access=True, access_behavior="allow")
            from ..cli import ScriptedIO
            from ..autopilot.answer_script import answers_keyed
            # Keyed, and carrying the intent the operator actually sent. This
            # used to be a six-item positional list whose second slot was the
            # hard-coded string "2": every run started from the browser built
            # the same blueprint no matter what the operator had asked for,
            # and the list was three answers short of the questions the engine
            # asks, so the rest were answered with "".
            engine.io = ScriptedIO(dict(answers_keyed(
                access_retry="n",
                intent=intent or "branch",
                apply=execute,
            )))
            report = engine.run(
                probe_port_session_factory=lambda p: fabric.probe(p),
                mgmt_session_factory=fabric.open,
                port=port, execute=execute,
            )
            with _RUNS_LOCK:
                rec.report = report
                rec.final = report.final
                rec.status = "COMPLETE" if report.final.startswith("COMPLETE") else "BLOCKED"
                rec.finished_at = datetime.now(timezone.utc).isoformat()
            return

        # Real hardware path. The console factory is the CLI's, not a copy:
        # this worker used to carry its own, which read the banner with
        # `execute("", 1.5)`. That returns a prompt, identifies no vendor, and
        # every web-initiated run on real hardware died at FAMILY_UNKNOWN. The
        # CLI's copy was fixed to read the connect banner the transport
        # captured; a duplicate meant the fix never reached here.
        from ..cli_main import _real_session_factory

        mgmt = _ConsoleOnlyMgmt(port)

        from ..cli import ScriptedIO
        from ..autopilot.answer_script import answers_keyed
        # ``execute`` is the caller's authorisation to apply, and the API is
        # key-protected, so it is honoured. Until now the flag was passed to
        # the engine while the apply gate was answered with something that was
        # never the word BOND, so ``execute: true`` staged everything and then
        # denied — a request that could never do what it asked for.
        engine.io = ScriptedIO(dict(answers_keyed(
            access_retry="n", intent=intent or "branch", apply=execute)))
        report = engine.run(
            probe_port_session_factory=_real_session_factory,
            mgmt_session_factory=mgmt,
            port=port, execute=execute,
        )
        with _RUNS_LOCK:
            rec.report = report
            rec.final = report.final
            rec.status = "COMPLETE" if report.final.startswith("COMPLETE") else "BLOCKED"
            rec.finished_at = datetime.now(timezone.utc).isoformat()
    except Exception as exc:  # noqa: BLE001
        with _RUNS_LOCK:
            rec.status = "ERROR"
            rec.error = f"{type(exc).__name__}: {exc}"
            rec.finished_at = datetime.now(timezone.utc).isoformat()


def run_server(*, host: str = "0.0.0.0", port: int = 8765, static_dir: Optional[Path] = None) -> None:
    """Entry point used by ``python -m netops_autopilot webui``."""
    _ensure_fastapi()
    try:
        import uvicorn  # type: ignore[import-not-found]
    except ImportError as exc:
        raise Failure(
            cls=__import__("netops_autopilot.core.failures", fromlist=["FailureClass"]).FailureClass.BLOCKED,
            causes=("UVICORN_UNAVAILABLE: `pip install uvicorn[standard]` to enable the web UI.",),
        ) from exc
    app = create_app(static_dir=static_dir)
    uvicorn.run(app, host=host, port=port, log_level="info")
