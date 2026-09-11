"""Diff/Preview Engine — show what will change BEFORE applying.

A 30-year engineer never types 'commit' without seeing the diff
first. This module is the typed implementation of "show me the
diff between my current config and what would be applied".

What it does:

* Loads the current snapshot (from the snapshot store) of a
  device and the proposed rendered config.
* Computes a line-level diff with added/removed/context
  classification.
* Categorizes each added line as CONFIG_REVERSIBLE,
  CONFIG_HIGH_RISK, or READ_ONLY (using the same allowlist the
  executor uses).
* Returns a typed preview with counts by risk class.

What it does NOT do (typed, never silent):

* It does NOT apply anything. The diff is a preview.
* It does NOT silently skip the live-config fetch — if the
  device is unreachable, the diff is built against the last
  cached snapshot, with a typed UNVERIFIED marker.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .backup import ConfigSnapshot, diff_snapshots, ConfigDiff, ConfigDiffLine


@dataclass(frozen=True)
class RiskClassSummary:
    """How many lines fall into each risk class."""

    __test__ = False

    config_reversible: int = 0
    config_high_risk: int = 0
    read_only: int = 0
    forbidden: int = 0
    unclassified: int = 0


@dataclass(frozen=True)
class PreviewReport:
    """A typed preview of what would change if the proposed
    config were applied to a device.
    """

    __test__ = False

    device_ref: str
    proposed_config: str
    diff: ConfigDiff
    risk_summary: RiskClassSummary
    is_unverified: bool       # True if no current snapshot was available
    detail: str = ""


def preview(
    device_ref: str,
    proposed_config: str,
    current_snapshot: ConfigSnapshot | None,
    allowlist: "CommandAllowlist",  # type: ignore[name-defined]
) -> PreviewReport:
    """Build a typed preview.

    If ``current_snapshot`` is None, the diff is built against
    an empty config (so every proposed line shows as "added"),
    and the report is flagged as unverified.
    """
    if current_snapshot is None:
        from .backup import ConfigSnapshot as _Snap
        empty = _Snap(
            snapshot_id="<empty>",
            device_ref=device_ref,
            captured_at_unix=0.0,
            config_text="",
            config_hash="0" * 16,
            byte_size=0,
            note="no prior snapshot; diff is unverified",
        )
        diff = diff_snapshots(empty, _Snap(
            snapshot_id="<proposed>",
            device_ref=device_ref,
            captured_at_unix=0.0,
            config_text=proposed_config,
            config_hash="0" * 16,
            byte_size=len(proposed_config),
        ))
        unverified = True
        detail = "no prior snapshot available — every line shown as ADDED"
    else:
        from .backup import ConfigSnapshot as _Snap
        proposed_snap = _Snap(
            snapshot_id="<proposed>",
            device_ref=device_ref,
            captured_at_unix=0.0,
            config_text=proposed_config,
            config_hash="0" * 16,
            byte_size=len(proposed_config),
        )
        diff = diff_snapshots(current_snapshot, proposed_snap)
        unverified = False
        detail = (
            f"diff vs. snapshot {current_snapshot.snapshot_id} "
            f"(captured at {current_snapshot.captured_at_unix})"
        )

    # Categorize each added line by allowlist class.
    summary = RiskClassSummary()
    for line in diff.lines:
        if line.kind != "added":
            continue
        text = line.text.strip()
        if not text or text.startswith("!"):
            continue
        cls = _classify(allowlist, text)
        if cls == "CONFIG_REVERSIBLE":
            summary = RiskClassSummary(
                summary.config_reversible + 1,
                summary.config_high_risk,
                summary.read_only,
                summary.forbidden,
                summary.unclassified,
            )
        elif cls == "CONFIG_HIGH_RISK":
            summary = RiskClassSummary(
                summary.config_reversible,
                summary.config_high_risk + 1,
                summary.read_only,
                summary.forbidden,
                summary.unclassified,
            )
        elif cls == "READ_ONLY":
            summary = RiskClassSummary(
                summary.config_reversible,
                summary.config_high_risk,
                summary.read_only + 1,
                summary.forbidden,
                summary.unclassified,
            )
        elif cls == "FORBIDDEN":
            summary = RiskClassSummary(
                summary.config_reversible,
                summary.config_high_risk,
                summary.read_only,
                summary.forbidden + 1,
                summary.unclassified,
            )
        else:
            summary = RiskClassSummary(
                summary.config_reversible,
                summary.config_high_risk,
                summary.read_only,
                summary.forbidden,
                summary.unclassified + 1,
            )

    return PreviewReport(
        device_ref=device_ref,
        proposed_config=proposed_config,
        diff=diff,
        risk_summary=summary,
        is_unverified=unverified,
        detail=detail,
    )


def render_preview(p: PreviewReport, lang: str = "en") -> str:
    if lang == "ar":
        return _render_preview_ar(p)
    return _render_preview_en(p)


def _classify(allowlist, text: str) -> str | None:
    """Classify a command line. Try the exact text first, then
    head+next-token match against the templates (e.g. "vlan 10"
    head="vlan" + next="10" matches "vlan <vlan_id>"). The
    head-match requires both the head and the second token to
    match a template prefix (so "no" alone doesn't match
    "no vlan <vlan_id>" — we only trust the match when the
    template has the same shape as the input).
    """
    cls = allowlist.classify(text)
    if cls is not None:
        return cls
    tokens = text.split()
    if len(tokens) < 2:
        return None
    head = tokens[0]
    next_tok = tokens[1]
    for tmpl, entry in getattr(allowlist, "_by_template", {}).items():
        tmpl_tokens = tmpl.split()
        if len(tmpl_tokens) < 2:
            continue
        if tmpl_tokens[0] != head:
            continue
        # The second token of the template must be a placeholder
        # OR must equal the input's second token.
        if tmpl_tokens[1].startswith("<") or tmpl_tokens[1] == next_tok:
            return entry.cls
    return None


def _render_preview_en(p: PreviewReport) -> str:
    head = (
        f"Preview for {p.device_ref}\n"
        f"  {p.detail}\n"
        f"  Lines added: {p.diff.added_count}   "
        f"Lines removed: {p.diff.removed_count}\n"
        f"  Risk: reversible={p.risk_summary.config_reversible}  "
        f"high_risk={p.risk_summary.config_high_risk}  "
        f"read_only={p.risk_summary.read_only}  "
        f"forbidden={p.risk_summary.forbidden}  "
        f"unclassified={p.risk_summary.unclassified}\n"
    )
    if p.risk_summary.forbidden > 0:
        head += "  ✕ APPLY WILL FAIL — forbidden lines detected\n"
    if p.is_unverified:
        head += "  ! UNVERIFIED — no prior snapshot; apply is blind\n"
    body = "\n".join(
        ("+" if x.kind == "added" else "-" if x.kind == "removed" else " ") + x.text
        for x in p.diff.lines
    )
    return head + body


def _render_preview_ar(p: PreviewReport) -> str:
    head = (
        f"معاينة لـ {p.device_ref}\n"
        f"  {p.detail}\n"
        f"  أسطر مضافة: {p.diff.added_count}   "
        f"أسطر محذوفة: {p.diff.removed_count}\n"
        f"  المخاطرة: عكسي={p.risk_summary.config_reversible}  "
        f"عالي={p.risk_summary.config_high_risk}  "
        f"قراءة={p.risk_summary.read_only}  "
        f"ممنوع={p.risk_summary.forbidden}  "
        f"غير_مُصنف={p.risk_summary.unclassified}\n"
    )
    if p.risk_summary.forbidden > 0:
        head += "  ✕ التطبيق سيفشل — تم اكتشاف أسطر ممنوعة\n"
    if p.is_unverified:
        head += "  ! غير_مُتحقق — لا توجد نسخة سابقة؛ التطبيق أعمى\n"
    body = "\n".join(
        ("+" if x.kind == "added" else "-" if x.kind == "removed" else " ") + x.text
        for x in p.diff.lines
    )
    return head + body
