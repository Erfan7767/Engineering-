"""Operator I/O channel implementations.

``ConsoleIO`` and ``ScriptedIO`` are the two canonical implementations of
``OperatorIO`` (defined in :mod:`autopilot.orchestrator`). They are kept
here so they can be imported from both the CLI entry-point and the test
suite, and re-exported by :mod:`cli` for backward compatibility.
"""

from __future__ import annotations

from typing import Optional


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

    def confirm(self, question: str) -> bool:
        answer = self._answers.pop(0) if self._answers else "y"
        print(f"Q: {question}\nA: {answer}")
        return answer.strip().lower() in {"y", "yes", "نعم"}

    def show(self, text: str) -> None:
        print(text)
