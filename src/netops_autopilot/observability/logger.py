"""Structured JSON logger for NetOps Autopilot.

Every event is a single line of JSON to stdout (or a file). Suitable for
ingestion by Elasticsearch/Loki/CloudWatch without any extra agent.

Honors the constitution:
* **L11 (NO_LLM_SECRETS):** :meth:`JsonLogger.log` redacts known secret
  patterns (``password``, ``secret``, ``token``, ``api_key``) at any depth
  before serialization. The redaction is *defense-in-depth* on top of the
  upstream LLM egress policy.
* **T3 (Authorized state):** events carry a ``phase`` and a typed
  ``state``; "PASS" never appears implicitly — only via an explicit
  ``{"outcome": "PASS", "evidence_ids": [...]}`` payload.
"""

from __future__ import annotations

import json
import re
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, IO, Optional


_SECRET_KEYS = re.compile(
    r"(?i)(password|passwd|secret|token|api_key|apikey|access_key|private_key)"
)
_SECRET_VALUE = re.compile(
    r"(?i)(?:password|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*([^\s,;}\"']+)"
)


def _redact(obj: Any) -> Any:
    """Recursively redact secret-shaped fields/values."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if _SECRET_KEYS.search(str(k)):
                out[k] = "[REDACTED]"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [_redact(x) for x in obj]
    if isinstance(obj, str):
        return _SECRET_VALUE.sub(lambda m: m.group(0).replace(m.group(1), "[REDACTED]"), obj)
    return obj


@dataclass
class LogEvent:
    """A typed log event (one JSON line on the wire)."""

    ts: str
    level: str
    phase: str
    message: str
    state: str = "INFO"
    evidence_ids: list[str] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        payload = asdict(self)
        payload = _redact(payload)
        return json.dumps(payload, ensure_ascii=False, sort_keys=False)


class JsonLogger:
    """Thread-safe JSON logger writing to a stream (default: stdout)."""

    def __init__(self, stream: Optional[IO[str]] = None, *, min_level: str = "INFO") -> None:
        self._stream = stream or sys.stdout
        self._min_level = min_level
        self._levels = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
        self._lock = threading.Lock()

    def _should_emit(self, level: str) -> bool:
        return self._levels.get(level.upper(), 20) >= self._levels.get(self._min_level, 20)

    def log(
        self,
        level: str,
        phase: str,
        message: str,
        *,
        state: str = "INFO",
        evidence_ids: Optional[list[str]] = None,
        counters: Optional[dict[str, int]] = None,
        **extra: Any,
    ) -> None:
        if not self._should_emit(level):
            return
        ts = datetime.now(timezone.utc).isoformat()
        # If the user passed `extra={"foo": "bar"}`, ``**extra`` would give us
        # ``{"extra": {"foo": "bar"}}`` which nests one level too deep.
        # Unwrap a single ``extra`` keyword to keep the JSON shape flat.
        if list(extra.keys()) == ["extra"] and isinstance(extra["extra"], dict):
            extra = extra["extra"]
        payload: dict[str, Any] = {
            "ts": ts,
            "level": level.upper(),
            "phase": phase,
            "state": state,
            "message": message,
            "evidence_ids": list(evidence_ids or []),
            "counters": dict(counters or {}),
            "extra": extra,
        }
        payload = _redact(payload)
        line = json.dumps(payload, ensure_ascii=False, sort_keys=False)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()

    # ---- convenience helpers ----

    def info(self, phase: str, message: str, **kw: Any) -> None:
        self.log("INFO", phase, message, **kw)

    def warn(self, phase: str, message: str, **kw: Any) -> None:
        self.log("WARN", phase, message, state="WARN", **kw)

    def error(self, phase: str, message: str, **kw: Any) -> None:
        self.log("ERROR", phase, message, state="ERROR", **kw)

    def debug(self, phase: str, message: str, **kw: Any) -> None:
        self.log("DEBUG", phase, message, state="DEBUG", **kw)


_DEFAULT: Optional[JsonLogger] = None
_DEFAULT_LOCK = threading.Lock()


def get_logger(stream: Optional[IO[str]] = None) -> JsonLogger:
    """Return a process-wide logger, creating one on first call."""
    global _DEFAULT
    with _DEFAULT_LOCK:
        if _DEFAULT is None:
            _DEFAULT = JsonLogger(stream=stream)
        return _DEFAULT
