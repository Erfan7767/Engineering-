"""Operator I/O channel implementations.

``ConsoleIO`` and ``ScriptedIO`` are the two canonical implementations of
``OperatorIO`` (defined in :mod:`autopilot.orchestrator`). They are kept
here so they can be imported from both the CLI entry-point and the test
suite, and re-exported by :mod:`cli` for backward compatibility.
"""

from __future__ import annotations

from typing import Optional

from ..core.failures import Failure, FailureClass


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

    def append_answers(self, answers: list[str]) -> None:
        """Queue further deterministic answers (e.g. the typed BOND at the
        apply gate) without rebuilding the whole script."""
        self._answers.extend(answers)

    def confirm(self, question: str) -> bool:
        answer = self._answers.pop(0) if self._answers else "y"
        print(f"Q: {question}\nA: {answer}")
        return answer.strip().lower() in {"y", "yes", "نعم"}

    def show(self, text: str) -> None:
        print(text)


class RefusingIO:
    """An operator channel with nobody behind it.

    The engine must never guess an operator's answer. A server constructs the
    engine before any request has supplied answers, so it installs this: a run
    that reaches a question without answers installed stops with a typed
    failure instead of inventing a network type, a WAN handoff or a BOND
    confirmation. ``show`` is still served — output is not a decision.
    """

    _CAUSE = ("NO_ANSWER_SOURCE: the engine asked a question and no operator "
              "channel was installed for this run; supply the operator's "
              "answers (ScriptedIO) rather than letting the engine guess")

    def ask(self, question: str) -> str:
        raise Failure(cls=FailureClass.BLOCKED, causes=(self._CAUSE,))

    def confirm(self, question: str) -> bool:
        raise Failure(cls=FailureClass.BLOCKED, causes=(self._CAUSE,))

    def show(self, text: str) -> None:
        return None
