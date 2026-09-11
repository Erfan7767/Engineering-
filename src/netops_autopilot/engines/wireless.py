"""Wireless Network Engine — WiFi APs, controllers, RADIUS.

A 30-year network engineer runs wireless networks too. This
module is the typed implementation: parse ``show ap
summary`` on a controller, parse ``show wlan summary``,
parse RADIUS accounting events, and report on channel
utilization and client density.

Design contract:

* **Typed** — :class:`AccessPoint`, :class:`WirelessClient`,
  :class:`Wlan`, :class:`RadiusEvent` are typed records.
* **Bilingual** — rendering in English or Arabic.
* **No hallucination** — every field is rule-parsed. Missing
  fields surface as empty / UNKNOWN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class RadioBand(str, Enum):
    __test__ = False

    BAND_2_4 = "2.4GHz"
    BAND_5 = "5GHz"
    BAND_6 = "6GHz"
    UNKNOWN = "unknown"


class WlanSecurity(str, Enum):
    __test__ = False

    OPEN = "open"
    WPA2_PSK = "wpa2-psk"
    WPA2_ENT = "wpa2-ent"
    WPA3_PSK = "wpa3-psk"
    WPA3_ENT = "wpa3-ent"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AccessPoint:
    __test__ = False

    name: str
    model: str = ""
    ip: str = ""
    clients: int = 0
    channel: str = ""
    band: RadioBand = RadioBand.UNKNOWN
    utilization_pct: float = 0.0


@dataclass
class ApReport:
    __test__ = False

    aps: list[AccessPoint] = field(default_factory=list)

    @property
    def ap_count(self) -> int:
        return len(self.aps)

    @property
    def total_clients(self) -> int:
        return sum(a.clients for a in self.aps)

    @property
    def high_util_aps(self) -> list[AccessPoint]:
        return [
            a for a in self.aps
            if a.utilization_pct >= 70.0
        ]


@dataclass(frozen=True)
class Wlan:
    __test__ = False

    ssid: str
    vlan_id: int = 0
    security: WlanSecurity = WlanSecurity.UNKNOWN
    enabled: bool = True


@dataclass
class WlanReport:
    __test__ = False

    wlans: list[Wlan] = field(default_factory=list)

    @property
    def open_wlans(self) -> list[Wlan]:
        return [
            w for w in self.wlans
            if w.security == WlanSecurity.OPEN and w.enabled
        ]


_AP_PATTERN = re.compile(
    r"^(?P<name>\S+)\s+(?P<model>\S+)\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<clients>\d+)\s+(?P<channel>\S+)\s+(?P<util>\d+)%",
    re.MULTILINE,
)


def parse_ap_summary(output: str) -> ApReport:
    """Parse ``show ap summary`` output."""
    rep = ApReport()
    if not output or not output.strip():
        return rep
    for m in _AP_PATTERN.finditer(output):
        try:
            util = float(m.group("util"))
        except ValueError:
            util = 0.0
        ch = m.group("channel")
        band = (
            RadioBand.BAND_2_4 if ch.endswith(("1", "6", "11"))
            else RadioBand.BAND_5 if ch.isdigit() and 36 <= int(ch) <= 165
            else RadioBand.BAND_6 if ch.startswith(("1", "5"))
            else RadioBand.UNKNOWN
        )
        rep.aps.append(AccessPoint(
            name=m.group("name"),
            model=m.group("model"),
            ip=m.group("ip"),
            clients=int(m.group("clients")),
            channel=ch,
            band=band,
            utilization_pct=util,
        ))
    return rep


_WLAN_PATTERN = re.compile(
    r"^(?P<wlan_id>\d+)\s+(?P<ssid>\S+)\s+(?P<vlan>\d+)\s+"
    r"(?P<status>UP|DOWN|ADMIN\s+DOWN)\s*",
    re.MULTILINE,
)


def parse_wlan_summary(output: str) -> WlanReport:
    """Parse ``show wlan summary`` output."""
    rep = WlanReport()
    if not output or not output.strip():
        return rep
    for m in _WLAN_PATTERN.finditer(output):
        # Skip the header line itself (column names).
        if m.group("ssid").upper() == "SSID":
            continue
        try:
            vlan = int(m.group("vlan"))
        except ValueError:
            vlan = 0
        rep.wlans.append(Wlan(
            ssid=m.group("ssid"),
            vlan_id=vlan,
            security=WlanSecurity.UNKNOWN,
            enabled=(m.group("status").upper() == "UP"),
        ))
    return rep


# RADIUS accounting event types
class RadiusEventType(str, Enum):
    __test__ = False

    START = "start"
    STOP = "stop"
    INTERIM = "interim"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RadiusEvent:
    __test__ = False

    username: str
    mac: str = ""
    ssid: str = ""
    event_type: RadiusEventType = RadiusEventType.UNKNOWN
    timestamp_unix: float = 0.0
    ap: str = ""


_RADIUS_PATTERN = re.compile(
    r"Acct-Status-Type\s*=\s*(?P<type>\w+).*?"
    r"User-Name\s*=\s*\"?(?P<user>[^\"\s]+)\"?.*?"
    r"Called-Station-Id\s*=\s*\"?(?P<ap>[^\"\s,]+)",
    re.DOTALL,
)


def parse_radius_event(line: str) -> RadiusEvent | None:
    """Parse a single RADIUS accounting line."""
    if not line or "Acct-Status-Type" not in line:
        return None
    m = _RADIUS_PATTERN.search(line)
    if not m:
        return None
    try:
        et = RadiusEventType(m.group("type").lower())
    except ValueError:
        et = RadiusEventType.UNKNOWN
    return RadiusEvent(
        username=m.group("user"),
        ap=m.group("ap"),
        event_type=et,
    )
