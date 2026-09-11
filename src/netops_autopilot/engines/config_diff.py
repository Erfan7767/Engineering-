"""Config Diff Engine — typed line-level config comparison.

A 30-year engineer diffs running-config vs golden-config
daily. This module is the typed implementation: take two
config strings, surface typed :class:`ConfigLineDiff`
records, and produce a typed :class:`ConfigDiffReport`.

Design contract:

* **Typed** — :class:`ConfigLineDiff` carries the action
  (``added`` / ``removed`` / ``unchanged``).
* **Deterministic** — same inputs → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from enum import Enum


class DiffAction(str, Enum):
    __test__ = False

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    UNCHANGED = "unchanged"


@dataclass(frozen=True)
class ConfigLineDiff:
    __test__ = False

    action: DiffAction
    line: str
    old_line: str = ""
    line_no: int = 0

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            tag = {
                DiffAction.ADDED: "+",
                DiffAction.REMOVED: "-",
                DiffAction.CHANGED: "~",
                DiffAction.UNCHANGED: " ",
            }[self.action]
        else:
            tag = {
                DiffAction.ADDED: "+",
                DiffAction.REMOVED: "-",
                DiffAction.CHANGED: "~",
                DiffAction.UNCHANGED: " ",
            }[self.action]
        return f"{tag} {self.line}"


@dataclass
class ConfigDiffReport:
    __test__ = False

    a_label: str
    b_label: str
    diffs: list[ConfigLineDiff] = field(default_factory=list)

    @property
    def added_count(self) -> int:
        return sum(
            1 for d in self.diffs
            if d.action == DiffAction.ADDED
        )

    @property
    def removed_count(self) -> int:
        return sum(
            1 for d in self.diffs
            if d.action == DiffAction.REMOVED
        )

    @property
    def unchanged_count(self) -> int:
        return sum(
            1 for d in self.diffs
            if d.action == DiffAction.UNCHANGED
        )

    @property
    def has_changes(self) -> bool:
        if self.added_count > 0 or self.removed_count > 0:
            return True
        return any(
            d.action == DiffAction.CHANGED for d in self.diffs
        )

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            head = (
                f"الفرق: {self.added_count} إضافة، "
                f"{self.removed_count} إزالة، "
                f"{self.unchanged_count} بدون تغيير"
            )
        else:
            head = (
                f"Diff: +{self.added_count} -{self.removed_count} "
                f"={self.unchanged_count}"
            )
        if not self.has_changes:
            head += "\n  (no changes)"
        return head


def diff(
    *,
    a: str,
    a_label: str,
    b: str,
    b_label: str,
) -> ConfigDiffReport:
    """Diff two config texts line by line.

    ``a`` is the "from" side, ``b`` is the "to" side.
    """
    rep = ConfigDiffReport(a_label=a_label, b_label=b_label)
    a_lines = (a or "").splitlines()
    b_lines = (b or "").splitlines()
    matcher = difflib.SequenceMatcher(
        a=a_lines, b=b_lines, autojunk=False,
    )
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                rep.diffs.append(ConfigLineDiff(
                    action=DiffAction.UNCHANGED,
                    line=a_lines[i1 + k],
                    line_no=i1 + k + 1,
                ))
        elif tag == "delete":
            for k in range(i2 - i1):
                rep.diffs.append(ConfigLineDiff(
                    action=DiffAction.REMOVED,
                    line=a_lines[i1 + k],
                    line_no=i1 + k + 1,
                ))
        elif tag == "insert":
            for k in range(j2 - j1):
                rep.diffs.append(ConfigLineDiff(
                    action=DiffAction.ADDED,
                    line=b_lines[j1 + k],
                    line_no=j1 + k + 1,
                ))
        elif tag == "replace":
            # Pair them line-by-line as CHANGED when possible.
            n = max(i2 - i1, j2 - j1)
            for k in range(n):
                old = (
                    a_lines[i1 + k]
                    if i1 + k < i2 else ""
                )
                new = (
                    b_lines[j1 + k]
                    if j1 + k < j2 else ""
                )
                if old and new:
                    rep.diffs.append(ConfigLineDiff(
                        action=DiffAction.CHANGED,
                        line=new,
                        old_line=old,
                        line_no=i1 + k + 1,
                    ))
                elif old:
                    rep.diffs.append(ConfigLineDiff(
                        action=DiffAction.REMOVED,
                        line=old,
                        line_no=i1 + k + 1,
                    ))
                else:
                    rep.diffs.append(ConfigLineDiff(
                        action=DiffAction.ADDED,
                        line=new,
                        line_no=j1 + k + 1,
                    ))
    return rep
