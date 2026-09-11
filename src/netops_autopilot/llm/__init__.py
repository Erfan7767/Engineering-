"""LLM provider layer — safe, swappable, evidence-bound (L17 / ADR-0005).

Every provider implements the same :class:`LLMProvider` interface so the
caller doesn't care whether the model runs locally (Ollama) or in the
cloud (Anthropic, OpenAI, etc.). All providers honor:

* **L04 (DETERMINISTIC AUTHORITY)**: the LLM only emits Intent Objects
  (JSON); the actual decisions are made by deterministic engines.
* **L11 (NO LLM SECRETS)**: the egress pipeline redacts credentials
  before any payload leaves the host; this module exposes a
  :func:`redact` helper used by the agent context builder.
* **L17 (LLM OUTPUT = INTENT OBJECT)**: the only accepted output shape
  is the :class:`agent_output.schema.json` schema; raw command strings
  are quarantined and never executed.
* **ADR-0005**: cloud providers run behind a signed egress policy with
  secret redaction.
"""

from .providers import (
    LLMProvider,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    OllamaProvider,
    EchoProvider,
    NullProvider,
    build_provider,
    redact,
    redact_dict,
    REDACT_PATTERNS,
)

__all__ = [
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "LLMUsage",
    "OllamaProvider",
    "EchoProvider",
    "NullProvider",
    "build_provider",
    "redact",
    "redact_dict",
    "REDACT_PATTERNS",
]
