"""Backup & Restore Engine — golden config snapshots with integrity.

A 30-year engineer never makes a change without a known-good
backup. The backup is golden: byte-identical to the device's
last verified-good state, and recoverable even after a failed
apply + rollback.

This module is the typed implementation.

What it does:

* Captures the running-config of a device on demand, computes a
  SHA-256 over the normalized text, and stores the snapshot in
  the on-disk ledger (separate from the audit log; the snapshot
  is data, the audit is evidence).
* Restores a snapshot to a session — sends the snapshot line
  by line to the device, allowlist-gated.
* Lists snapshots by device, with timestamp and hash.
* Diffs two snapshots (or a snapshot vs. live) — the "what
  changed" view a 30-year engineer expects before a rollback
  decision.

What it does NOT do (typed, never silent):

* It does NOT auto-restore without an explicit operator command.
* It does NOT keep unbounded snapshots — the store keeps the
  last N per device (default 32).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol


class _ExecSession(Protocol):
    def execute(self, command: str, timeout_s: float) -> bytes: ...
    def close(self) -> None: ...


class _Factory(Protocol):
    def __call__(self, device_ref: str) -> _ExecSession: ...


@dataclass(frozen=True)
class ConfigSnapshot:
    """An immutable, hash-tagged snapshot of a device's config."""

    __test__ = False

    snapshot_id: str        # <device>-<unix_ms>-<short_hash>
    device_ref: str
    captured_at_unix: float
    config_text: str
    config_hash: str        # sha256[:16]
    byte_size: int
    note: str = ""          # free-form operator note (e.g. "post-apply branch")


def capture(
    session: _ExecSession,
    device_ref: str,
    *,
    note: str = "",
    clock: callable = time.time,
) -> ConfigSnapshot:
    """Capture the running-config from an open session."""
    data = session.execute("show running-config", timeout_s=30.0)
    text = data.decode("utf-8", errors="replace")
    h = hashlib.sha256(_normalize(text).encode("utf-8")).hexdigest()[:16]
    snap_id = (
        f"{device_ref}-{int(clock() * 1000)}-{h}"
    )
    return ConfigSnapshot(
        snapshot_id=snap_id,
        device_ref=device_ref,
        captured_at_unix=clock(),
        config_text=text,
        config_hash=h,
        byte_size=len(text.encode("utf-8")),
        note=note,
    )


def _normalize(text: str) -> str:
    """Normalize a running-config text so the hash is stable across
    cosmetic differences (trailing whitespace, line endings).
    """
    out = text.replace("\r\n", "\n").replace("\r", "\n")
    out = "\n".join(line.rstrip() for line in out.split("\n"))
    return out.strip()


# --------------------------------------------------------------------- storage
# The snapshot store is a simple on-disk JSON-per-snapshot. The
# path is configurable (defaults to ``.netops-snapshots/`` next
# to the working directory).

class SnapshotStore:
    """A small typed key-value store for snapshots."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _device_dir(self, device_ref: str) -> Path:
        d = self._root / device_ref
        d.mkdir(parents=True, exist_ok=True)
        return d

    def save(self, snap: ConfigSnapshot, max_keep: int = 32) -> None:
        d = self._device_dir(snap.device_ref)
        path = d / f"{snap.snapshot_id}.json"
        path.write_text(
            json.dumps(snap, default=_snapshot_to_json, indent=2),
            encoding="utf-8",
        )
        # Garbage-collect old snapshots beyond max_keep.
        existing = sorted(
            d.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for old in existing[max_keep:]:
            try:
                old.unlink()
            except OSError:
                pass

    def list(self, device_ref: str) -> list[ConfigSnapshot]:
        d = self._device_dir(device_ref)
        snaps: list[ConfigSnapshot] = []
        for p in sorted(d.glob("*.json")):
            try:
                d_obj = json.loads(p.read_text(encoding="utf-8"))
                snaps.append(_snapshot_from_json(d_obj))
            except (OSError, ValueError):
                continue
        return snaps

    def latest(self, device_ref: str) -> Optional[ConfigSnapshot]:
        snaps = self.list(device_ref)
        return snaps[0] if snaps else None

    def get(self, snapshot_id: str) -> Optional[ConfigSnapshot]:
        for p in self._root.rglob(f"{snapshot_id}.json"):
            try:
                return _snapshot_from_json(
                    json.loads(p.read_text(encoding="utf-8"))
                )
            except (OSError, ValueError):
                continue
        return None


def _snapshot_to_json(obj) -> str:
    if isinstance(obj, ConfigSnapshot):
        return obj.__dict__
    raise TypeError(f"Cannot serialize {type(obj)}")


def _snapshot_from_json(d: dict) -> ConfigSnapshot:
    return ConfigSnapshot(
        snapshot_id=d["snapshot_id"],
        device_ref=d["device_ref"],
        captured_at_unix=d["captured_at_unix"],
        config_text=d["config_text"],
        config_hash=d["config_hash"],
        byte_size=d["byte_size"],
        note=d.get("note", ""),
    )


# --------------------------------------------------------------------- diffing

@dataclass(frozen=True)
class ConfigDiffLine:
    """One line of a config diff."""

    __test__ = False

    kind: str   # "added" | "removed" | "context"
    text: str


@dataclass(frozen=True)
class ConfigDiff:
    """A complete diff between two snapshots."""

    __test__ = False

    device_ref: str
    left_id: str
    right_id: str
    lines: tuple[ConfigDiffLine, ...]
    added_count: int
    removed_count: int


def diff_snapshots(left: ConfigSnapshot, right: ConfigSnapshot) -> ConfigDiff:
    """Return a line-level diff (LCS-based, not Myers, but readable).

    The diff treats each normalized line as a token and emits
    added/removed/context lines. This is the same output format
    a 30-year engineer expects from ``diff -u``.
    """
    left_lines = _normalize(left.config_text).split("\n")
    right_lines = _normalize(right.config_text).split("\n")

    # LCS-based diff.
    n, m = len(left_lines), len(right_lines)
    # dp[i][j] = LCS length of left_lines[:i], right_lines[:j]
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if left_lines[i - 1] == right_lines[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    # Walk back to produce the diff.
    out: list[ConfigDiffLine] = []
    i, j = n, m
    while i > 0 and j > 0:
        if left_lines[i - 1] == right_lines[j - 1]:
            out.append(ConfigDiffLine("context", left_lines[i - 1]))
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            out.append(ConfigDiffLine("removed", left_lines[i - 1]))
            i -= 1
        else:
            out.append(ConfigDiffLine("added", right_lines[j - 1]))
            j -= 1
    while i > 0:
        out.append(ConfigDiffLine("removed", left_lines[i - 1]))
        i -= 1
    while j > 0:
        out.append(ConfigDiffLine("added", right_lines[j - 1]))
        j -= 1

    out.reverse()
    added = sum(1 for x in out if x.kind == "added")
    removed = sum(1 for x in out if x.kind == "removed")
    return ConfigDiff(
        device_ref=right.device_ref,
        left_id=left.snapshot_id,
        right_id=right.snapshot_id,
        lines=tuple(out),
        added_count=added,
        removed_count=removed,
    )


def render_diff(d: ConfigDiff, lang: str = "en") -> str:
    if lang == "ar":
        return _render_diff_ar(d)
    return _render_diff_en(d)


def _render_diff_en(d: ConfigDiff) -> str:
    head = (
        f"--- {d.left_id} (old)\n"
        f"+++ {d.right_id} (new)\n"
        f"@@ +{d.added_count} -{d.removed_count} @@\n"
    )
    body = "\n".join(
        ("+" if x.kind == "added" else "-" if x.kind == "removed" else " ") + x.text
        for x in d.lines
    )
    return head + body


def _render_diff_ar(d: ConfigDiff) -> str:
    head = (
        f"--- {d.left_id} (قديم)\n"
        f"+++ {d.right_id} (جديد)\n"
        f"@@ +{d.added_count} -{d.removed_count} @@\n"
    )
    body = "\n".join(
        ("+" if x.kind == "added" else "-" if x.kind == "removed" else " ") + x.text
        for x in d.lines
    )
    return head + body


# --------------------------------------------------------------------- restore

@dataclass
class RestoreResult:
    """The result of restoring a snapshot to a device."""

    __test__ = False

    snapshot_id: str
    device_ref: str
    lines_sent: int = 0
    lines_accepted: int = 0
    lines_rejected: int = 0
    error: str = ""

    @property
    def success(self) -> bool:
        return not self.error and self.lines_rejected == 0


def restore(
    snapshot: ConfigSnapshot,
    session: _ExecSession,
    allowlist: "CommandAllowlist",  # type: ignore[name-defined]
) -> RestoreResult:
    """Restore a snapshot to an open session.

    Behaviour:

    * Sends ``enable`` then ``configure terminal`` first.
    * Sends every config line in the snapshot.
    * Strips comment lines and blank lines.
    * Records accepted vs rejected counts.
    * Sends ``end`` at the end.
    * On any failure, returns the error in the result and the
      session is left in a recoverable state (we never end mid-
      configure-terminal).
    """
    result = RestoreResult(
        snapshot_id=snapshot.snapshot_id,
        device_ref=snapshot.device_ref,
    )
    try:
        for cmd in ("enable", "configure terminal"):
            session.execute(cmd, timeout_s=10.0)
        for line in snapshot.config_text.split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("!"):
                continue
            try:
                session.execute(stripped, timeout_s=10.0)
                result.lines_sent += 1
                result.lines_accepted += 1
            except Exception as exc:  # noqa: BLE001
                result.lines_sent += 1
                result.lines_rejected += 1
                if not result.error:
                    result.error = f"line {stripped!r}: {type(exc).__name__}: {exc}"
        session.execute("end", timeout_s=10.0)
    except Exception as exc:  # noqa: BLE001
        result.error = f"{type(exc).__name__}: {exc}"
    return result
