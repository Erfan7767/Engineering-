"""LLM provider implementations and the contract they all implement.

The :class:`LLMProvider` protocol is intentionally minimal: take a
:class:`LLMRequest` (system + user messages, with optional structured
schema), return a :class:`LLMResponse` (text + parsed structured output
+ token usage). This keeps the surface small and easy to mock.

Providers MUST:

* redact secrets (L11) — even before they reach this layer (the agent
  context builder already does so, but providers re-redact at egress).
* never execute or interpret the response — that is the orchestrator's
  job, after schema validation (L17).
* report usage so the harness can attribute costs.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


# --------------------------------------------------------------------------- #
# Secret redaction (L11)
# --------------------------------------------------------------------------- #

# Patterns that look like secrets, credentials, or tokens. These are
# redacted at the egress boundary, regardless of where they came from.
REDACT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*([^\s,;}\"']+)"),
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]+"),
)


def redact(text: str) -> str:
    """Replace secret-shaped substrings with ``[REDACTED]``."""
    out = text
    for pat in REDACT_PATTERNS:
        # In Python 3.13+ ``re.Pattern.groups`` is an int (the count of
        # capture groups). Use the more portable ``pat.groups >= 1`` check.
        if pat.groups >= 1:
            out = pat.sub(lambda m: m.group(0).replace(m.group(pat.groups), "[REDACTED]"), out)
        else:
            out = pat.sub("[REDACTED]", out)
    return out


_SECRET_KEYS_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)"
)


def redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Recursively redact secrets in a dict.

    * A key whose name looks like a secret (e.g. ``password``,
      ``api_key``) ⇒ the value is replaced with ``[REDACTED]``
      regardless of its content (L11).
    * String values are also pattern-redacted in case the value is a
      ``key=value`` pair.
    * Nested dicts and lists are walked recursively.
    """
    out: dict[str, Any] = {}
    for k, v in d.items():
        if _SECRET_KEYS_RE.search(str(k)):
            out[k] = "[REDACTED]"
            continue
        if isinstance(v, str):
            out[k] = redact(v)
        elif isinstance(v, dict):
            out[k] = redact_dict(v)
        elif isinstance(v, list):
            out[k] = [redact_dict(x) if isinstance(x, dict)
                      else (redact(x) if isinstance(x, str) else x) for x in v]
        else:
            out[k] = v
    return out


# --------------------------------------------------------------------------- #
# Request / response
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class LLMUsage:
    """Token accounting for one call."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass(frozen=True)
class LLMRequest:
    """A single LLM call."""
    system: str
    user: str
    # Optional JSON-Schema that the response should conform to (L17).
    response_schema: Optional[dict[str, Any]] = None
    # Provider-specific knobs (kept loose for forward compatibility).
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LLMResponse:
    """The LLM's reply (text + optional structured payload + usage)."""
    text: str
    structured: Optional[dict[str, Any]] = None
    usage: LLMUsage = LLMUsage()
    duration_s: float = 0.0
    model: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class LLMProvider(Protocol):
    """The contract every LLM provider must implement."""

    name: str

    def is_available(self) -> bool:
        """Return True if the provider can serve a request right now."""
        ...

    def complete(self, request: LLMRequest) -> LLMResponse:
        """Issue a single completion. The provider is responsible for
        redaction, schema validation, and error reporting."""
        ...


# --------------------------------------------------------------------------- #
# Built-in providers
# --------------------------------------------------------------------------- #


class NullProvider:
    """A no-op provider that always raises BLOCKED.

    Use this when the deployment has no LLM (lab air-gapped) or as a
    sentinel during testing — the orchestrator must still pass through
    its evidence pipeline.
    """

    name = "null"

    def is_available(self) -> bool:
        return True  # always "available" so the policy can be expressed

    def complete(self, request: LLMRequest) -> LLMResponse:
        from ..core.failures import Failure, FailureClass
        raise Failure(
            cls=FailureClass.BLOCKED,
            causes=("LLM_PROVIDER_DISABLED: no provider configured (L17 / ADR-0005). "
                    "Set the LLM provider in config to enable LLM-assisted flows.",),
        )


class EchoProvider:
    """A deterministic test provider that echoes the user prompt.

    Useful for unit tests and CI: it never hits a network and never
    blocks. The orchestrator can wire it in to verify schema validation
    paths without spending tokens.
    """

    name = "echo"

    def is_available(self) -> bool:
        return True

    def complete(self, request: LLMRequest) -> LLMResponse:
        started = time.monotonic()
        # Deterministic, no randomness.
        text = f"[ECHO] system={len(request.system)}c user={len(request.user)}c"
        structured: Optional[dict[str, Any]] = None
        if request.response_schema:
            # Build a minimal compliant payload from the schema's
            # `properties` (best-effort, used only in tests).
            structured = _synthetic_payload(request.response_schema, request.user)
        prompt_tokens = (len(request.system) + len(request.user)) // 4
        completion_tokens = 10
        return LLMResponse(
            text=text,
            structured=structured,
            usage=LLMUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            duration_s=time.monotonic() - started,
            model="echo",
        )


def _synthetic_payload(schema: dict[str, Any], user: str) -> dict[str, Any]:
    """Build a minimal JSON object conforming to a JSON-Schema (best-effort)."""
    out: dict[str, Any] = {}
    properties = schema.get("properties", {})
    for key, spec in properties.items():
        kind = (spec or {}).get("type")
        if kind == "string":
            out[key] = ""
        elif kind == "integer":
            out[key] = 0
        elif kind == "boolean":
            out[key] = False
        elif kind == "array":
            out[key] = []
        elif kind == "object":
            out[key] = _synthetic_payload(spec, user)
        else:
            out[key] = None
    # Stash the user prompt for tests that want to inspect it.
    out.setdefault("_echo", user[:120])
    return out


class OllamaProvider:
    """A provider that talks to a local Ollama daemon (ADR-0005 alternative).

    Lazy import of ``urllib`` so the module loads without an internet
    connection. ``is_available()`` performs a cheap HTTP probe and
    returns False on any failure (the orchestrator then falls back to a
    :class:`NullProvider` per its policy).
    """

    name = "ollama"

    def __init__(
        self,
        *,
        host: str = "http://127.0.0.1:11434",
        model: str = "llama3.1",
        timeout_s: float = 30.0,
    ) -> None:
        if not host:
            raise ValueError("host is required")
        if not model:
            raise ValueError("model is required")
        self._host = host.rstrip("/")
        self._model = model
        self._timeout = timeout_s

    def is_available(self) -> bool:
        try:
            import urllib.request
            req = urllib.request.Request(f"{self._host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2.0) as r:  # noqa: S310
                return r.status == 200
        except Exception:  # noqa: BLE001
            return False

    def complete(self, request: LLMRequest) -> LLMResponse:
        from ..core.failures import Failure, FailureClass
        if not self.is_available():
            raise Failure(
                cls=FailureClass.BLOCKED,
                causes=(f"OLLAMA_UNREACHABLE: {self._host} did not respond to /api/tags",),
            )
        # Redact before egress (defense in depth on top of the upstream
        # agent context builder).
        system = redact(request.system)
        user = redact(request.user)
        payload = {
            "model": self._model,
            "system": system,
            "prompt": user,
            "stream": False,
        }
        if request.response_schema:
            payload["format"] = request.response_schema
        data = json.dumps(payload).encode("utf-8")
        import urllib.request
        req = urllib.request.Request(
            f"{self._host}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:  # noqa: S310
                body = json.loads(r.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise Failure(
                cls=FailureClass.RETRYABLE,
                causes=(f"OLLAMA_REQUEST_FAILED: {type(exc).__name__}: {exc}",),
                retry_hint="check the Ollama daemon and model availability",
            ) from exc
        text = body.get("response", "")
        structured: Optional[dict[str, Any]] = None
        if request.response_schema:
            try:
                structured = json.loads(text)
            except json.JSONDecodeError:
                # Provider didn't honor the schema; treat as BLOCKED so
                # the orchestrator does not pass it to a decision.
                raise Failure(
                    cls=FailureClass.BLOCKED,
                    causes=("OLLAMA_SCHEMA_VIOLATION: response was not valid JSON",),
                )
        # Ollama returns token counts under "eval_count"/"prompt_eval_count".
        usage = LLMUsage(
            prompt_tokens=body.get("prompt_eval_count", 0),
            completion_tokens=body.get("eval_count", 0),
            total_tokens=body.get("prompt_eval_count", 0) + body.get("eval_count", 0),
        )
        return LLMResponse(
            text=text,
            structured=structured,
            usage=usage,
            duration_s=time.monotonic() - started,
            model=self._model,
            raw=body,
        )


def build_provider(name: str, **kwargs: Any) -> LLMProvider:
    """Factory for the well-known providers."""
    name = (name or "").strip().lower()
    if name in ("", "null", "none"):
        return NullProvider()
    if name == "echo":
        return EchoProvider()
    if name == "ollama":
        return OllamaProvider(**kwargs)
    # Lazy import for cloud providers; the user opted in by setting the
    # name. We refuse by default (L11 — no implicit egress).
    raise ValueError(f"LLM_PROVIDER_UNKNOWN:{name!r} (allowed: null, echo, ollama)")
