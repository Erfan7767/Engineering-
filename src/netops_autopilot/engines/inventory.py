"""Inventory Aggregator — typed, single-pane-of-glass inventory.

A 30-year engineer wants one screen that shows: device, model,
serial, vendor, OS version, uptime, IP, port, status, and last
seen. This module produces that view from the discovery crawl
result.

What it does:

* Accepts a list of device records (the same shape the
  DiscoveryCrawlEngine emits).
* Aggregates them into a single inventory structure.
* Filters by status, vendor, model, or search text.
* Renders a typed table for the chat.

What it does NOT do (typed, never silent):

* It does NOT make up fields. Missing serial is empty string,
  not "unknown" or "?".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class InventoryItem:
    """A single device in the inventory."""

    __test__ = False

    device_ref: str
    vendor: str = ""
    model: str = ""
    serial: str = ""
    os_version: str = ""
    mgmt_address: str = ""
    status: str = ""
    interface_count: int = 0
    last_seen_unix: float = 0.0


@dataclass
class Inventory:
    __test__ = False

    items: list[InventoryItem] = field(default_factory=list)

    @property
    def by_status(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for i in self.items:
            out[i.status] = out.get(i.status, 0) + 1
        return out

    @property
    def by_vendor(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for i in self.items:
            out[i.vendor] = out.get(i.vendor, 0) + 1
        return out

    def search(self, text: str) -> "Inventory":
        t = text.strip().lower()
        if not t:
            return self
        return Inventory(items=[
            i for i in self.items
            if t in i.device_ref.lower()
            or t in i.model.lower()
            or t in i.vendor.lower()
            or t in i.mgmt_address.lower()
        ])

    def filter(self, *, status: str = "", vendor: str = "", model: str = "") -> "Inventory":
        out = []
        for i in self.items:
            if status and i.status != status:
                continue
            if vendor and i.vendor != vendor:
                continue
            if model and i.model != model:
                continue
            out.append(i)
        return Inventory(items=out)


def render_inventory(inv: Inventory, lang: str = "en") -> str:
    if lang == "ar":
        return _render_ar(inv)
    return _render_en(inv)


def _render_en(inv: Inventory) -> str:
    if not inv.items:
        return "No devices in inventory."
    lines = [
        f"Inventory ({len(inv.items)} device(s))",
        f"  By status: {inv.by_status}",
        f"  By vendor: {inv.by_vendor}",
        "",
    ]
    lines.append(
        f"  {'REF':<20s} {'VENDOR':<14s} {'MODEL':<20s} "
        f"{'STATUS':<14s} {'IP':<18s} {'PORTS'}"
    )
    lines.append("  " + "-" * 96)
    for i in inv.items:
        lines.append(
            f"  {i.device_ref:<20s} {i.vendor:<14s} {i.model:<20s} "
            f"{i.status:<14s} {i.mgmt_address:<18s} {i.interface_count}"
        )
    return "\n".join(lines)


def _render_ar(inv: Inventory) -> str:
    if not inv.items:
        return "لا توجد أجهزة في المخزون."
    lines = [
        f"المخزون ({len(inv.items)} جهاز)",
        f"  بالحالة: {inv.by_status}",
        f"  بالمصنع: {inv.by_vendor}",
        "",
    ]
    lines.append(
        f"  {'المرجع':<20s} {'المصنع':<14s} {'الطراز':<20s} "
        f"{'الحالة':<14s} {'IP':<18s} {'منافذ'}"
    )
    lines.append("  " + "-" * 96)
    for i in inv.items:
        lines.append(
            f"  {i.device_ref:<20s} {i.vendor:<14s} {i.model:<20s} "
            f"{i.status:<14s} {i.mgmt_address:<18s} {i.interface_count}"
        )
    return "\n".join(lines)

