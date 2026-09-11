"""Command Allowlist enforcement (specs/data/allowlists/*, D0).

Rules (allowlists README):

1. Only registered templates execute; everything else ⇒ BLOCKED (L10/T3).
2. The Collector is READ_ONLY-only in this release line; higher classes are
   reserved for E15 (D3) with their gates.
3. ``classify`` returns the class name or None (unknown ⇒ never allowed).

Two distinct lookups live here, and the difference is a safety boundary:

``classify(command)``
    **Verbatim template lookup.** Returns the class of a *registered
    template string* — e.g. ``classify("show version")`` or
    ``classify("erase <args>")``. It is used by the parsers, the diff
    engine and the audit tooling, which work with template names rather
    than live commands. It never pattern-matches.

``gate(command)``
    **Live-command gate.** Structurally matches a *real, fully-baked*
    command against every template, with placeholders bound, and returns
    the class the executor is allowed to act on. FORBIDDEN and
    DESTRUCTIVE are evaluated first (``CLASS_PRIORITY``) so a dangerous
    command can never be smuggled through a broader class.

History (Phase V): an earlier revision of the executor matched on the
first token only. That let ``ip http server`` through because ``ip
routing`` was registered, and let ``username attacker privilege 15
secret 0 ...`` through because ``username <name> privilege 15 secret
<hash>`` was registered. ``gate()`` closes that: arity and every literal
segment must match.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

#: Execution order: first matching class wins; FORBIDDEN is checked first so
#: a forbidden template can never hide inside a broader class by accident.
CLASS_PRIORITY = ("FORBIDDEN", "DESTRUCTIVE", "CONFIG_HIGH_RISK", "CONFIG_REVERSIBLE", "READ_ONLY")

#: Classes an executor may push to a device.
CONFIG_CLASSES = ("CONFIG_REVERSIBLE", "CONFIG_HIGH_RISK")

#: A trailing placeholder with one of these names swallows the remainder of
#: the command (``erase <args>`` matches ``erase startup-config``).
_CATCHALL_NAMES = frozenset({"args", "rest", "remainder"})

#: Matches a ``<placeholder>`` inside a single template token.
_PLACEHOLDER = re.compile(r"<([A-Za-z_][A-Za-z0-9_]*)>")


@dataclass(frozen=True)
class AllowlistEntry:
    template: str
    cls: str
    purpose: str = ""
    notes: str = ""
    rollback: str = ""
    #: True when issuing this command enters a CLI sub-mode (``interface
    #: Gi0/1``, ``router ospf 1``, ``vlan 10`` on IOS). The executor uses it
    #: to track the mode stack so an inverse is issued at the depth the
    #: original command ran at. Absent from the data ⇒ the command does not
    #: change mode, which is correct for the flat CLIs (Junos ``set``,
    #: RouterOS one-liners).
    enters_mode: bool = False


@dataclass(frozen=True)
class CommandMatch:
    """The result of structurally matching a live command to a template.

    ``bindings`` maps each placeholder name to the literal value found in
    the command, so an inverse can be rebuilt without re-parsing.
    """

    entry: AllowlistEntry
    bindings: tuple = ()            # tuple[tuple[str, str], ...]

    @property
    def cls(self) -> str:
        return self.entry.cls

    @property
    def template(self) -> str:
        return self.entry.template

    def value(self, name: str) -> Optional[str]:
        for key, val in self.bindings:
            if key == name:
                return val
        return None

    @property
    def is_catchall(self) -> bool:
        return any(k in _CATCHALL_NAMES for k, _ in self.bindings)


def _compile_template(template: str):
    """Compile a template into a list of per-token matchers.

    Returns ``(matchers, catchall_name)``. Each matcher is either a
    compiled full-match regex (token may contain embedded placeholders)
    or ``None`` for a plain case-insensitive literal. ``catchall_name``
    is set when the template ends in ``<args>``-style catch-all.
    """
    tokens = template.split()
    matchers: list = []
    catchall_name: Optional[str] = None
    for index, tok in enumerate(tokens):
        is_last = index == len(tokens) - 1
        names = _PLACEHOLDER.findall(tok)
        if is_last and names and names[0] in _CATCHALL_NAMES and len(names) == 1 \
                and tok == f"<{names[0]}>":
            catchall_name = names[0]
            matchers.append(None)          # placeholder slot, handled separately
            continue
        if not names:
            matchers.append(("LIT", tok.lower()))
            continue
        # Build a regex: literal runs escaped, placeholders → (\S+).
        parts: list[str] = []
        pos = 0
        for m in _PLACEHOLDER.finditer(tok):
            parts.append(re.escape(tok[pos:m.start()]))
            parts.append(r"(\S+)")
            pos = m.end()
        parts.append(re.escape(tok[pos:]))
        matchers.append(("RE", re.compile("".join(parts), re.IGNORECASE), tuple(names)))
    return matchers, catchall_name


def _match_one(compiled, catchall_name: Optional[str], tokens: list[str]):
    """Try to match ``tokens`` against one compiled template.

    Returns the bindings tuple on success, ``None`` on failure.
    """
    matchers = compiled
    if catchall_name is None:
        if len(tokens) != len(matchers):
            return None                     # arity is a hard requirement
        bindings: list = []
        for tok, matcher in zip(tokens, matchers):
            kind = matcher[0]
            if kind == "LIT":
                if tok.lower() != matcher[1]:
                    return None
            else:
                m = matcher[1].fullmatch(tok)
                if m is None:
                    return None
                bindings.extend(zip(matcher[2], m.groups()))
        return tuple(bindings)

    # Catch-all: the last template slot absorbs the remainder.
    if len(tokens) < len(matchers) - 1:
        return None
    bindings = []
    for tok, matcher in zip(tokens[: len(matchers) - 1], matchers[:-1]):
        kind = matcher[0]
        if kind == "LIT":
            if tok.lower() != matcher[1]:
                return None
        else:
            m = matcher[1].fullmatch(tok)
            if m is None:
                return None
            bindings.extend(zip(matcher[2], m.groups()))
    rest = " ".join(tokens[len(matchers) - 1:])
    if not rest:
        return None                         # ``erase`` alone is not ``erase <args>``
    bindings.append((catchall_name, rest))
    return tuple(bindings)


class CommandAllowlist:
    """In-memory allowlist compiled from the JSON data files."""

    def __init__(self, entries: tuple[AllowlistEntry, ...] = ()) -> None:
        self._entries = tuple(entries)
        self._by_template: dict[str, AllowlistEntry] = {}
        self._compiled: dict[str, object] = {}
        self._catchall: dict[str, Optional[str]] = {}
        self._inverse_cache = None
        for entry in self._entries:
            # Duplicate template across classes is a data defect, not a runtime guess.
            if entry.template in self._by_template and self._by_template[entry.template].cls != entry.cls:
                raise ValueError(f"template registered in two classes: {entry.template!r}")
            self._by_template[entry.template] = entry
            if entry.template not in self._compiled:
                compiled, catch = _compile_template(entry.template)
                self._compiled[entry.template] = compiled
                self._catchall[entry.template] = catch
        #: Templates ordered by safety class, then by specificity (most
        #: specific first) so a narrow template always wins over a broad one.
        self._ordered: tuple[AllowlistEntry, ...] = tuple(self._sort_entries())

    # ------------------------------------------------------------ ordering
    def _specificity(self, entry: AllowlistEntry) -> tuple:
        """Lower sorts first. Prefer more literal *content*, then fewer
        placeholders.

        Counting literal characters (not literal tokens) is what makes
        ``interface Vlan<vlan_id>`` outrank ``interface <intf>``: both have one
        placeholder and two tokens, but the first pins the ``Vlan`` prefix and
        therefore describes a narrower set of commands.
        """
        literal_chars = len(_PLACEHOLDER.sub("", entry.template).replace(" ", ""))
        placeholders = len(_PLACEHOLDER.findall(entry.template))
        return (-literal_chars, placeholders, len(entry.template))

    def _sort_entries(self) -> list[AllowlistEntry]:
        rank = {cls: i for i, cls in enumerate(CLASS_PRIORITY)}
        seen: set[str] = set()
        out: list[AllowlistEntry] = []
        for entry in self._entries:
            if entry.template in seen:
                continue
            seen.add(entry.template)
            out.append(entry)
        out.sort(key=lambda e: (rank.get(e.cls, len(CLASS_PRIORITY)), self._specificity(e)))
        return out

    # ------------------------------------------------------------ loading
    @classmethod
    def load_dir(cls, directory: str | Path) -> "CommandAllowlist":
        """Load every ``*.json`` allowlist file in a directory."""
        entries: list[AllowlistEntry] = []
        for path in sorted(Path(directory).glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            for cls_name, body in data.get("classes", {}).items():
                for raw in body.get("entries", []):
                    entries.append(
                        AllowlistEntry(
                            template=raw["template"],
                            cls=cls_name,
                            purpose=raw.get("purpose", ""),
                            notes=raw.get("notes", "") if cls_name != "FORBIDDEN" else raw.get("reason", ""),
                            rollback=raw.get("rollback", ""),
                            enters_mode=bool(raw.get("enters_mode", False)),
                        )
                    )
        return cls(tuple(entries))

    @classmethod
    def load_vendor(cls, directory: str | Path, vendor_family: str) -> "CommandAllowlist":
        """Load a single vendor family's allowlist by ``vendor_family`` id.

        ``vendor_family`` is the value inside the file (e.g. ``cisco/ios-xe``),
        not the filename. Raises ``KeyError`` when the family is not present —
        an unknown vendor has no allowlist, therefore no execution path.
        """
        for path in sorted(Path(directory).glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            if data.get("vendor_family") != vendor_family:
                continue
            entries: list[AllowlistEntry] = []
            for cls_name, body in data.get("classes", {}).items():
                for raw in body.get("entries", []):
                    entries.append(
                        AllowlistEntry(
                            template=raw["template"],
                            cls=cls_name,
                            purpose=raw.get("purpose", ""),
                            notes=raw.get("notes", "") if cls_name != "FORBIDDEN" else raw.get("reason", ""),
                            rollback=raw.get("rollback", ""),
                            enters_mode=bool(raw.get("enters_mode", False)),
                        )
                    )
            return cls(tuple(entries))
        raise KeyError(f"no allowlist registered for vendor_family={vendor_family!r}")

    # ------------------------------------------------- verbatim template API
    def classify(self, command: str) -> str | None:
        """Verbatim registered-template lookup. Never pattern-matches."""
        entry = self._by_template.get(command.strip())
        return entry.cls if entry else None

    def entry(self, command: str) -> AllowlistEntry | None:
        return self._by_template.get(command.strip())

    def is_readable(self, command: str) -> bool:
        """True iff the command is an explicitly allowlisted READ_ONLY entry."""
        return self.classify(command) == "READ_ONLY"

    # ----------------------------------------------------- live-command API
    def match(self, command: str) -> CommandMatch | None:
        """Structurally match a live command. Dangerous classes win first.

        Returns ``None`` when no template matches — an unregistered command
        has no execution path (L10/T3).
        """
        tokens = command.strip().split()
        if not tokens:
            return None
        for entry in self._ordered:
            bindings = _match_one(self._compiled[entry.template],
                                  self._catchall[entry.template], tokens)
            if bindings is not None:
                return CommandMatch(entry=entry, bindings=bindings)
        return None

    def gate(self, command: str) -> str | None:
        """The class the executor may act on for this live command."""
        m = self.match(command)
        return m.cls if m else None

    def is_config(self, command: str) -> bool:
        """True iff the live command is allowlisted as a CONFIG class."""
        return self.gate(command) in CONFIG_CLASSES

    def is_forbidden(self, command: str) -> bool:
        return self.gate(command) in ("FORBIDDEN", "DESTRUCTIVE")

    def templates_in_class(self, cls: str) -> tuple[str, ...]:
        return tuple(e.template for e in self._entries if e.cls == cls)

    # ------------------------------------------------------- inverse surface
    def _inverse_templates(self) -> list:
        """Compiled templates for every declared CONFIG inverse."""
        if getattr(self, "_inverse_cache", None) is not None:
            return self._inverse_cache
        out = []
        for entry in self._entries:
            if entry.cls not in CONFIG_CLASSES or not entry.rollback:
                continue
            if entry.rollback.startswith("!"):
                continue          # manual marker, not an issuable command
            compiled, catchall = _compile_template(entry.rollback)
            out.append((entry, compiled, catchall))
        self._inverse_cache = out
        return out

    def is_registered_inverse(self, command: str) -> Optional[AllowlistEntry]:
        """The source template if ``command`` is a declared CONFIG inverse.

        This is the only sound way to authorise an undo line. A chat or engine
        path must not reason "it starts with ``no`` and the head matches an
        allowed template, so it is fine" — that is exactly the first-token
        shortcut that let arbitrary configuration through. Here the string has
        to *be* a registered inverse, and it must not itself be FORBIDDEN or
        DESTRUCTIVE.
        """
        stripped = command.strip()
        if not stripped:
            return None
        if self.is_forbidden(stripped):
            return None
        tokens = stripped.split()
        for source, compiled, catchall in self._inverse_templates():
            if _match_one(compiled, catchall, tokens) is not None:
                return source
        return None

    def inverse_conflicts(self) -> list:
        """Declared inverses that the allowlist itself forbids.

        A data defect, not a runtime condition: if ``router ospf <pid>``
        declares ``no router ospf <pid>`` as its inverse but ``no router
        <args>`` sits in FORBIDDEN, then that change has no automatic rollback
        and the operator must be told *before* the change, not during it.
        """
        conflicts = []
        for source, compiled, catchall in self._inverse_templates():
            sample = _PLACEHOLDER.sub("0", source.rollback)
            if self.is_forbidden(sample):
                conflicts.append((source.template, source.rollback, self.gate(sample)))
        return conflicts

    def resolve_inverse(self, command: str) -> Optional[str]:
        """Build the concrete inverse of a live command from its template.

        Returns ``None`` when the template declares no inverse — the caller
        must then treat the line as manual-rollback (typed, never silent).
        """
        m = self.match(command)
        if m is None or not m.entry.rollback:
            return None
        return self._render_inverse(m.entry.rollback, m.entry.template, command.strip())

    @staticmethod
    def _render_inverse(rollback: str, template: str, command: str) -> str:
        """Substitute placeholders in ``rollback`` from the live command.

        Mapping is by placeholder *name*, not position, so
        ``no neighbor <ip>`` for template ``neighbor <ip> remote-as <asn>``
        resolves correctly even though the rollback is shorter.

        A placeholder that the command did not bind is left verbatim so the
        operator sees an obviously-incomplete line instead of a plausible
        but wrong one.
        """
        bindings: dict[str, str] = {}
        # Bind per template token using the compiled matcher for accuracy.
        compiled, catchall = _compile_template(template)
        tokens = command.split()
        if catchall is None and len(tokens) == len(compiled):
            for tok, matcher in zip(tokens, compiled):
                if matcher[0] == "RE":
                    found = matcher[1].fullmatch(tok)
                    if found:
                        bindings.update(zip(matcher[2], found.groups()))
        elif catchall is not None and len(tokens) >= len(compiled) - 1:
            for tok, matcher in zip(tokens[: len(compiled) - 1], compiled[:-1]):
                if matcher[0] == "RE":
                    found = matcher[1].fullmatch(tok)
                    if found:
                        bindings.update(zip(matcher[2], found.groups()))
            bindings[catchall] = " ".join(tokens[len(compiled) - 1:])
        else:
            return rollback

        def sub(m: "re.Match[str]") -> str:
            name = m.group(1)
            return bindings.get(name, m.group(0))

        return _PLACEHOLDER.sub(sub, rollback)

    def size(self) -> int:
        return len(self._entries)
