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
    """stdin/stdout operator channel.

    ``key`` identifies the question. A human reading a prompt does not need
    it, but every machine-fed channel does: it is what keeps an answer
    attached to the question it was asked.
    """

    def ask(self, question: str, key: Optional[str] = None) -> str:
        print(question)
        try:
            return input("> ").strip()
        except EOFError:
            return ""

    def confirm(self, question: str, key: Optional[str] = None) -> bool:
        try:
            return input(question).strip().lower() in {"y", "yes", "نعم", "n/a-confirm"}
        except EOFError:
            return False

    def show(self, text: str) -> None:
        print(text)


class ScriptedIO:
    """Deterministic operator answers, addressed by question identity.

    Two forms are accepted.

    A **mapping** ``{key: answer}`` is the correct form. The orchestrator
    names every question it asks, and the answer is looked up by that name,
    so the set of questions may grow, shrink or change order without a single
    answer moving. An unanswered question is a typed failure, never an empty
    string and never a default: the old positional queue returned ``""`` when
    it ran dry and ``"y"`` for a confirm, so a misaligned run still reported
    success having built the wrong network from the right answers.

    A **list** is positional and kept for the scenarios and tests that were
    written against it. It is inherently fragile — the question set is
    data-dependent (``access_retry`` is asked only when a device is
    unreachable), so a caller cannot know the order in advance — and every
    answer it serves is recorded in :attr:`consumed` with the key of the
    question that consumed it, which makes a misalignment visible instead of
    silent.
    """

    def __init__(self, answers) -> None:
        if isinstance(answers, dict):
            self._keyed: dict[str, str] = dict(answers)
            self._answers: list[str] = []
        else:
            self._keyed = {}
            self._answers = list(answers)
        self.transcript: list[str] = []
        #: ``(key, answer)`` for every answer served, in the order served.
        self.consumed: list[tuple[Optional[str], str]] = []

    # ------------------------------------------------------------- internals
    def _take(self, key: Optional[str], question: str, fallback: str) -> str:
        if self._keyed:
            if key is None:
                raise Failure(cls=FailureClass.BLOCKED, causes=(
                    "UNKEYED_QUESTION: the engine asked %r without a key while "
                    "keyed answers were installed; refusing to guess which "
                    "question this is" % question.splitlines()[-1][:60],))
            if key not in self._keyed:
                raise Failure(cls=FailureClass.BLOCKED, causes=(
                    f"ANSWER_NOT_SCRIPTED:{key} — the run reached a question the "
                    f"caller did not answer. Answers are addressed by name, so "
                    f"this is a missing answer, not an empty one; the platform "
                    f"will not invent it.",))
            return self._keyed[key]
        if self._answers:
            return self._answers.pop(0)
        return fallback

    def ask(self, question: str, key: Optional[str] = None) -> str:
        answer = self._take(key, question, "")
        self.consumed.append((key, answer))
        self.transcript.append(f"Q: {question.splitlines()[-1]}\nA: {answer}")
        print(f"Q: {question.splitlines()[-1]}\nA: {answer}")
        return answer

    def append_answers(self, answers) -> None:
        """Queue further answers without rebuilding the whole script."""
        if isinstance(answers, dict):
            self._keyed.update(answers)
        else:
            self._answers.extend(answers)

    def confirm(self, question: str, key: Optional[str] = None) -> bool:
        answer = self._take(key, question, "y")
        self.consumed.append((key, answer))
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

    def ask(self, question: str, key: Optional[str] = None) -> str:
        raise Failure(cls=FailureClass.BLOCKED, causes=(self._CAUSE,))

    def confirm(self, question: str, key: Optional[str] = None) -> bool:
        raise Failure(cls=FailureClass.BLOCKED, causes=(self._CAUSE,))

    def show(self, text: str) -> None:
        return None
