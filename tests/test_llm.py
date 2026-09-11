"""Tests for the LLM provider layer."""

from __future__ import annotations

import json

import pytest

from netops_autopilot.llm.providers import (
    EchoProvider,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    NullProvider,
    OllamaProvider,
    REDACT_PATTERNS,
    build_provider,
    redact,
    redact_dict,
)
from netops_autopilot.core.failures import Failure, FailureClass


# ----------------- redact() -----------------


def test_redact_password_value():
    out = redact("password=hunter2")
    assert "hunter2" not in out
    assert "[REDACTED]" in out


def test_redact_token_value():
    out = redact("token: abc.def-ghi")
    assert "abc.def-ghi" not in out


def test_redact_bearer():
    out = redact("Authorization: Bearer eyJabc")
    assert "eyJabc" not in out
    assert "[REDACTED]" in out


def test_redact_pem_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nABC\n-----END RSA PRIVATE KEY-----"
    out = redact(pem)
    assert "ABC" not in out
    assert "[REDACTED]" in out


def test_redact_no_secrets_passes_through():
    text = "the user wants a small branch office with guest WiFi"
    assert redact(text) == text


def test_redact_dict_recursively():
    d = {"user": "alice", "creds": {"password": "shh"}}
    out = redact_dict(d)
    assert out["user"] == "alice"
    assert out["creds"]["password"] == "[REDACTED]"


def test_redact_dict_in_list():
    d = {"items": [{"api_key": "abc"}, "plain"]}
    out = redact_dict(d)
    assert out["items"][0]["api_key"] == "[REDACTED]"
    assert out["items"][1] == "plain"


# ----------------- NullProvider -----------------


def test_null_provider_is_available():
    assert NullProvider().is_available() is True


def test_null_provider_blocks():
    with pytest.raises(Failure) as exc:
        NullProvider().complete(LLMRequest(system="s", user="u"))
    assert exc.value.cls is FailureClass.BLOCKED
    assert "LLM_PROVIDER_DISABLED" in exc.value.causes[0]


# ----------------- EchoProvider -----------------


def test_echo_provider_deterministic():
    p = EchoProvider()
    r1 = p.complete(LLMRequest(system="sys", user="hello"))
    r2 = p.complete(LLMRequest(system="sys", user="hello"))
    assert r1.text == r2.text
    assert "ECHO" in r1.text


def test_echo_provider_emits_structured_for_schema():
    p = EchoProvider()
    schema = {
        "type": "object",
        "properties": {
            "intent": {"type": "string"},
            "count": {"type": "integer"},
        },
    }
    r = p.complete(LLMRequest(system="s", user="u", response_schema=schema))
    assert r.structured is not None
    assert r.structured["intent"] == ""
    assert r.structured["count"] == 0


def test_echo_provider_usage_nonzero():
    r = EchoProvider().complete(LLMRequest(system="a long system prompt", user="a long user prompt"))
    assert r.usage.total_tokens > 0


# ----------------- OllamaProvider -----------------


def test_ollama_provider_requires_host_and_model():
    with pytest.raises(ValueError):
        OllamaProvider(host="", model="x")
    with pytest.raises(ValueError):
        OllamaProvider(host="h", model="")


def test_ollama_is_available_false_when_unreachable(monkeypatch):
    """Mock urllib so the probe times out / fails."""
    import urllib.error
    def boom(*a, **kw):
        raise urllib.error.URLError("nope")
    monkeypatch.setattr("urllib.request.urlopen", boom)
    p = OllamaProvider(host="http://127.0.0.1:1", model="x")
    assert p.is_available() is False


def test_ollama_is_available_true_when_server_up(monkeypatch):
    import io
    class _Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def read(self): return b"{}"
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **kw: _Resp())
    p = OllamaProvider(host="http://127.0.0.1:11434", model="llama3.1")
    assert p.is_available() is True


def test_ollama_complete_unreachable_blocks(monkeypatch):
    import urllib.error
    def boom(*a, **kw):
        raise urllib.error.URLError("nope")
    monkeypatch.setattr("urllib.request.urlopen", boom)
    p = OllamaProvider(host="http://127.0.0.1:1", model="x")
    with pytest.raises(Failure) as exc:
        p.complete(LLMRequest(system="s", user="u"))
    assert exc.value.cls is FailureClass.BLOCKED
    assert "OLLAMA_UNREACHABLE" in exc.value.causes[0]


def test_ollama_complete_success_redacts(monkeypatch):
    """Verify that secrets in the prompt are redacted before egress."""
    captured = {}
    def fake_urlopen(req, **kw):
        # First call: /api/tags (availability probe)
        # Second call: /api/generate (the actual call)
        url = req.full_url if hasattr(req, "full_url") else str(req)
        captured.setdefault("urls", []).append(url)
        if "tags" in url:
            class _Probe:
                status = 200
                def __enter__(self): return self
                def __exit__(self, *a): pass
                def read(self): return b"{}"
            return _Probe()
        # Capture the body for the actual call.
        if hasattr(req, "data") and req.data:
            captured["body"] = json.loads(req.data.decode("utf-8"))
        class _Resp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self):
                return json.dumps({
                    "response": "OK",
                    "prompt_eval_count": 10,
                    "eval_count": 5,
                }).encode("utf-8")
        return _Resp()
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    p = OllamaProvider(host="http://127.0.0.1:11434", model="x")
    r = p.complete(LLMRequest(
        system="",
        user="connect to host=1.2.3.4 password=hunter2",
    ))
    # The body that hit the wire must NOT contain "hunter2".
    assert "hunter2" not in json.dumps(captured["body"]), f"leaked: {captured['body']}"
    assert r.usage.total_tokens == 15
    assert r.text == "OK"


def test_ollama_schema_violation_blocks(monkeypatch):
    def fake_urlopen(req, **kw):
        class _Resp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def read(self):
                # Returns non-JSON text — schema violated.
                return json.dumps({"response": "this is not json"}).encode("utf-8")
        return _Resp()
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    p = OllamaProvider(host="http://127.0.0.1:11434", model="x")
    with pytest.raises(Failure) as exc:
        p.complete(LLMRequest(system="", user="x", response_schema={"type": "object"}))
    assert exc.value.cls is FailureClass.BLOCKED
    assert "SCHEMA_VIOLATION" in exc.value.causes[0]


# ----------------- build_provider -----------------


def test_build_provider_null():
    assert isinstance(build_provider("null"), NullProvider)


def test_build_provider_empty_is_null():
    assert isinstance(build_provider(""), NullProvider)


def test_build_provider_echo():
    assert isinstance(build_provider("echo"), EchoProvider)


def test_build_provider_ollama():
    assert isinstance(build_provider("ollama", host="http://x:1", model="m"), OllamaProvider)


def test_build_provider_unknown_rejected():
    with pytest.raises(ValueError):
        build_provider("claude-3.5-sonnet")


# ----------------- LLMRequest / LLMResponse -----------------


def test_request_default_options_empty():
    r = LLMRequest(system="s", user="u")
    assert r.options == {}
    assert r.response_schema is None


def test_response_default_values():
    r = LLMResponse(text="hi")
    assert r.structured is None
    assert r.usage.total_tokens == 0
    assert r.duration_s == 0.0
    assert r.model == ""
    assert r.raw == {}


def test_usage_to_dict():
    u = LLMUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
    d = u.to_dict()
    assert d == {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
