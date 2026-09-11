"""Structured JSON run-report renderer (machine-readable output for SIEM/downstream tools).

Conforms to the Constitution (L01-L17): every claim references evidence,
no implicit PASS, typed states only.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Optional


def _to_jsonable(obj: Any) -> Any:
    """Convert dataclasses, enums, datetimes to JSON-safe types."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    if hasattr(obj, "value") and hasattr(obj, "name"):  # Enum
        return obj.value
    if is_dataclass(obj):
        return _to_jsonable(asdict(obj))
    if hasattr(obj, "__dict__"):
        return _to_jsonable(vars(obj))
    return str(obj)


def render_json_report(
    *,
    report: Any,
    ledger_event_count: int,
    chain_ok: bool,
    counters: Optional[dict[str, int]] = None,
    extra: Optional[dict[str, Any]] = None,
    pretty: bool = True,
) -> str:
    """Render an Autopilot run report as a JSON document.

    Args:
        report: the ``AutopilotReport`` object.
        ledger_event_count: number of signed events in the ledger.
        chain_ok: ``True`` if the ledger hash chain verifies.
        counters: optional T1–T6 counter snapshot.
        extra: optional extra fields to include.
        pretty: when ``True``, indent the output (default; recommended for files).
    """
    payload: dict[str, Any] = {
        "schema": "netops-autopilot/run-report/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "final": getattr(report, "final", "UNKNOWN"),
        "phases": _to_jsonable(getattr(report, "phases", [])),
        "ledger": {
            "event_count": ledger_event_count,
            "chain_ok": chain_ok,
        },
    }
    if getattr(report, "seed_family", None) is not None:
        payload["seed_family"] = report.seed_family
    if getattr(report, "day0_state", None) is not None:
        payload["day0_state"] = report.day0_state
    if getattr(report, "crawl", None) is not None:
        payload["crawl"] = _to_jsonable(report.crawl)
    if getattr(report, "topology", None) is not None:
        topo = report.topology
        payload["topology"] = {
            "nodes": _to_jsonable(getattr(topo, "nodes", [])),
            "edges": _to_jsonable(getattr(topo, "edges", [])),
            "gaps": _to_jsonable(getattr(topo, "gaps", [])),
            "ascii": getattr(topo, "ascii", ""),
        }
    if getattr(report, "elicitation", None) is not None:
        payload["elicitation"] = _to_jsonable(report.elicitation)
    if getattr(report, "intent", None) is not None:
        payload["intent"] = _to_jsonable(report.intent)
    if getattr(report, "design", None) is not None:
        payload["design"] = _to_jsonable(report.design)
    if getattr(report, "renders", None):
        payload["renders"] = {k: _to_jsonable(v) for k, v in report.renders.items()}
    if getattr(report, "execution", None) is not None:
        payload["execution"] = _to_jsonable(report.execution)
    if counters is not None:
        payload["counters"] = dict(counters)
    if extra:
        payload["extra"] = _to_jsonable(extra)
    return json.dumps(payload, indent=2 if pretty else None, ensure_ascii=False, sort_keys=False)
