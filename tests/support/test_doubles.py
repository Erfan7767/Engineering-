"""Test doubles. Deterministic stand-ins for things a test cannot have.

These live here rather than in ``src/`` on purpose. A fake transport or a
provider that fabricates answers is a test tool, and shipping one inside the
product package means a deployment can reach it: ``build_provider("echo")`` used
to be a supported setting, and the provider it returned answered every request
with a synthetic schema-compliant payload and invented token counts — a result
that looked like a model's and flowed into the evidence pipeline as if it were
one. ``tests/test_no_fake_implementations.py`` asserts nothing of the kind is
importable from the package again.

What is here must never be reachable from production code. The real paths are
``netmiko.ConnectHandler`` for SSH, ``telnetlib3`` for Telnet, and a configured
provider for the LLM.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from netops_autopilot.access.ssh_transport import SSHChannelLike, SSHDriverFactory
from netops_autopilot.access.telnet_transport import (
    TelnetChannelLike,
    TelnetDriverFactory,
)
from netops_autopilot.llm import LLMRequest, LLMResponse, LLMUsage


@dataclass
class FakeSSHChannel:
    """A fully-deterministic in-memory Netmiko replacement for tests."""

    responses: dict[str, str] = field(default_factory=dict)
    default_response: str = "device# "
    opened: bool = False
    closed: bool = False
    sent: list[str] = field(default_factory=list)
    connect_fail: Optional[Exception] = None
    command_fail: Optional[Exception] = None
    prompt: str = "device# "

    def send_command(self, command: str, read_timeout: float = 30.0) -> str:
        self.sent.append(command)
        if self.command_fail is not None:
            raise self.command_fail
        return self.responses.get(command, self.default_response)

    def find_prompt(self) -> str:
        return self.prompt

    def disconnect(self) -> None:
        self.closed = True


def fake_ssh_factory(channel: FakeSSHChannel) -> SSHDriverFactory:
    """Return a driver factory that always yields the given channel."""

    def _factory(
        host: str, port: int, username: str, password: str,
        device_type: str, timeout: float,
    ) -> SSHChannelLike:
        if channel.connect_fail is not None:
            raise channel.connect_fail
        channel.opened = True
        return channel

    return _factory


@dataclass
class FakeTelnetChannel:
    """A fully-deterministic in-memory telnet replacement for tests."""

    responses: list[bytes] = None  # type: ignore[assignment]
    opened: bool = False
    closed: bool = False
    written: list[bytes] = None  # type: ignore[assignment]
    connect_fail: Optional[Exception] = None
    login_prompt_response: bytes = b"login: "
    password_prompt_response: bytes = b"Password: "

    def __post_init__(self) -> None:
        if self.responses is None:
            self.responses = []
        if self.written is None:
            self.written = []

    def read_until(self, match: bytes | str, timeout: float | None = None) -> bytes:
        if isinstance(match, bytes) and match == b"login:":
            return self.login_prompt_response
        if isinstance(match, bytes) and match == b"Password:":
            return self.password_prompt_response
        if self.responses:
            return self.responses.pop(0)
        return b""

    def write(self, data: bytes) -> None:
        self.written.append(data)

    def close(self) -> None:
        self.closed = True


def fake_telnet_factory(channel: FakeTelnetChannel) -> TelnetDriverFactory:
    def _factory(host: str, port: int, timeout: float) -> TelnetChannelLike:
        if channel.connect_fail is not None:
            raise channel.connect_fail
        channel.opened = True
        return channel
    return _factory


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
