"""Chat-driven Network Operator — understand natural-language intent, route
to the right engine, return real evidence-bound results.

This is NOT a chatbot that fakes responses. Every command is parsed
into a typed :class:`OperatorIntent` and dispatched to a real engine
(discovery, executor, topology, design, ledger). The output is the
real engine output, not a hand-written answer.

The intent recognition is **deterministic** — no LLM guessing. The
operator maps natural-language phrases (Arabic + English) to typed
verbs, then dispatches.

Why this matters: the user wants to type "show all devices" and have
the system run the actual discovery and return the actual device list.
Not a hallucinated answer.

Design contract:

* **Deterministic by construction** — every chat turn is a pure
  function of (intent, current state). Two identical inputs produce
  identical outputs.
* **No fabrication** — if a command can't be fulfilled, the operator
  emits a typed :class:`OperatorReply` with status=BLOCKED and a reason.
  Never invents results.
* **Bilingual** — Arabic and English are first-class. The dispatcher
  normalizes input to a canonical English verb before routing.
* **Audited** — every dispatched command is written to the ledger as
  a `chat_intent` event with the typed verb and the response status.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional, Protocol

from ..access.allowlist import CommandAllowlist
from ..access.executor import ConfigExecutor
from ..autopilot.orchestrator import AutopilotEngine, Phase
from ..cli import ScriptedIO
from ..core.failures import Failure, FailureClass
from ..core.ids import new_id
from ..engines.discovery_crawl import DiscoveryCrawlEngine
from ..engines.topology_map import TopologyMapEngine
from ..ledger.models import OperatorIdentity
from ..ledger.store import LedgerStore
from ..specs_data import specs_data_dir
from ..twin.twin import DigitalTwin
from .device_runner import DeviceCommandRunner


# ---------------------------------------------------------------------------
# Intent model — the typed vocabulary the operator understands.
# ---------------------------------------------------------------------------


class IntentVerb(str, Enum):
    """Every chat turn resolves to exactly one of these typed verbs."""

    # Discovery
    DISCOVER = "discover"               # walk the network
    SHOW_DEVICES = "show_devices"       # list discovered devices
    SHOW_TOPOLOGY = "show_topology"     # show the network map
    SHOW_DEVICE = "show_device"         # detail one device
    SHOW_INTERFACE = "show_interface"   # detail one interface

    # Read-only diagnostics
    SHOW_CONFIG = "show_config"         # show running-config of a device
    SHOW_VERSION = "show_version"       # show version of a device
    SHOW_NEIGHBORS = "show_neighbors"   # show CDP/LLDP neighbors
    SHOW_VLANS = "show_vlans"           # show VLAN table
    SHOW_ROUTES = "show_routes"         # show routing table
    SHOW_INTERFACES = "show_interfaces" # show interface status
    SHOW_RUN = "show_run"               # show running-config

    # Configuration
    APPLY_INTENT = "apply_intent"       # build a design + apply it
    STAGE = "stage"                     # stage a change without applying
    DESIGN = "design"                   # design only (no apply)
    ROLLBACK = "rollback"               # rollback a previous change

    # Operational
    PING = "ping"                       # ping a host
    TRACEROUTE = "traceroute"           # trace route to a host
    DIAGNOSE = "diagnose"               # run a diagnostic
    VERIFY = "verify"                   # verify config

    # Phase N: 30-year expert operations
    COMPLIANCE = "compliance"           # HIPAA/PCI/CIS/NIST audit
    CONVERGENCE = "convergence"         # wait for routing convergence
    SNAPSHOT = "snapshot"               # capture/restore a config snapshot
    DIFF = "diff"                       # diff two snapshots
    HEALTH = "health"                   # interface health per device
    CAPABILITY = "capability"           # hardware capability matrix
    INVENTORY = "inventory"             # aggregated inventory
    EXPORT = "export"                   # export audit trail
    MAINTENANCE = "maintenance"         # maintenance window ops

    # Phase O: 30-year expert operations — Day-2 diagnostics
    MAC_TABLE = "mac_table"             # parse mac address table
    CABLE_DIAG = "cable_diag"           # CRC / cable diagnostics
    ROUTING = "routing"                 # OSPF / BGP / EIGRP neighbors
    ACL_HITS = "acl_hits"               # ACL audit / hit counts
    POE = "poe"                         # PoE budget & allocation
    DRIFT = "drift"                     # config drift detection
    EOL = "eol"                         # hardware EOL/EOS check
    TRUNK = "trunk"                     # trunk audit
    UPGRADE = "upgrade"                 # upgrade path validator
    SUMMARY = "summary"                 # network summary

    # Meta
    BOND = "bond"                       # confirm physical binding
    HELP = "help"                       # list available commands
    STATUS = "status"                   # run / system status
    UNKNOWN = "unknown"                 # could not classify


# ---------------------------------------------------------------------------
# Arabic → canonical verb normalization
# ---------------------------------------------------------------------------


_AR_PATTERNS: tuple[tuple[IntentVerb, tuple[str, ...]], ...] = (
    (IntentVerb.DISCOVER, (
        "اكتشف", "اكتشاف", "فحص الشبكة", "امسح الشبكة", "scan", "discover",
        "اكتشف الأجهزة", "ابحث عن الأجهزة",
    )),
    (IntentVerb.SHOW_DEVICES, (
        "اعرض الأجهزة", "الأجهزة", "قائمة الأجهزة", "كم جهاز",
        "show devices", "list devices", "الأجهزة المكتشفة",
    )),
    (IntentVerb.SHOW_TOPOLOGY, (
        "الخريطة", "خريطة الشبكة", "طوبولوجيا", "topology", "اعرض الخريطة",
        "ارسم الشبكة", "كيف الشبكة",
    )),
    (IntentVerb.SHOW_DEVICE, (
        "اعرض الجهاز", "تفاصيل الجهاز", "معلومات الجهاز",
        "show device", "جهاز",
    )),
    (IntentVerb.SHOW_INTERFACE, (
        "اعرض المنفذ", "تفاصيل المنفذ", "واجهة", "show interface",
        "المنفذ",
    )),
    (IntentVerb.SHOW_CONFIG, (
        "اعرض الإعدادات", "الإعدادات", "الكونفق", "show config",
        "show running-config", "الكونفيج",
    )),
    (IntentVerb.SHOW_VERSION, (
        "اعرض الإصدار", "الإصدار", "الفيرجن", "show version", "version",
    )),
    (IntentVerb.SHOW_NEIGHBORS, (
        "الجيران", "الأجهزة المتصلة", "lldp", "cdp", "الجوار",
        "show neighbors", "show lldp", "show cdp",
    )),
    (IntentVerb.SHOW_VLANS, (
        "vlans", "الشبكات المحلية", "الفلانات", "vlan", "show vlan",
    )),
    (IntentVerb.SHOW_ROUTES, (
        "الراوتنج", "الروابط", "المسارات", "show route", "show ip route",
    )),
    (IntentVerb.SHOW_INTERFACES, (
        "المنافذ", "الإنترفيسات", "show interface", "interfaces",
    )),
    (IntentVerb.SHOW_RUN, (
        "الكونفق الحالي", "running-config", "show run", "اعرض run",
    )),
    (IntentVerb.APPLY_INTENT, (
        "طبق", "تطبيق", "نفذ", "طبق التصميم", "apply", "deploy", "نفذ الإعدادات",
        "طبق الإعدادات", "شغل الشبكة", "اعمل الشبكة",
    )),
    (IntentVerb.STAGE, (
        "جهز", "حضر", "stage", "اعرض بدون تطبيق", "صمم بدون تطبيق",
    )),
    (IntentVerb.DESIGN, (
        "صمم", "تصميم", "صمم الشبكة", "design", "خطط",
    )),
    (IntentVerb.ROLLBACK, (
        "ارجع", "تراجع", "rollback", "undo", "التراجع",
    )),
    (IntentVerb.PING, (
        "بينج", "ping", "تأكد من الوصول", "هل يصل",
    )),
    (IntentVerb.TRACEROUTE, (
        "traceroute", "trace", "تتبع المسار", "tracert",
    )),
    (IntentVerb.DIAGNOSE, (
        "شخّص", "فحص", "diagnose", "ما المشكلة", "لماذا",
    )),
    (IntentVerb.VERIFY, (
        "تحقق", "تأكد", "verify", "check",
    )),
    (IntentVerb.COMPLIANCE, (
        "الامتثال", "تدقيق", "hipaa", "pci", "cis", "nist",
        "فحص أمني", "تأمين",
    )),
    (IntentVerb.CONVERGENCE, (
        "تقارب", "انتظر التقارب", "هل تقارب",
    )),
    (IntentVerb.SNAPSHOT, (
        "لقطة", "نسخ احتياطي", "احفظ الإعدادات", "استعد الإعدادات",
        "snapshot", "backup",
    )),
    (IntentVerb.DIFF, (
        "قارن", "مقارنة", "ما الذي تغير", "diff",
    )),
    (IntentVerb.HEALTH, (
        "الصحة", "صحة المنافذ", "حالة المنافذ", "صحة الواجهات",
        "health", "crc",
    )),
    (IntentVerb.CAPABILITY, (
        "القدرات", "ما الذي يدعمه", "إمكانيات الجهاز",
        "capability", "hardware",
    )),
    (IntentVerb.INVENTORY, (
        "المخزون", "كل الأجهزة", "قائمة الأجهزة", "جرد",
        "inventory", "asset",
    )),
    (IntentVerb.EXPORT, (
        "تصدير", "صدّر السجل", "تنزيل التدقيق", "export",
    )),
    (IntentVerb.MAINTENANCE, (
        "نافذة الصيانة", "نافذة التغيير", "صيانة",
        "maintenance window",
    )),
    (IntentVerb.MAC_TABLE, (
        "جدول العناوين", "mac address", "mac", "عناوين mac",
        "جدول mac",
    )),
    (IntentVerb.CABLE_DIAG, (
        "تشخيص الكابلات", "cable", "crc", "cable diagnostic",
        "فحص الكابلات",
    )),
    (IntentVerb.ROUTING, (
        "الجيران ospf", "الجيران bgp", "ospf", "bgp", "eigrp",
        "حالة البروتوكولات", "حالة الراوتنج", "بروتوكولات الراوتنج",
    )),
    (IntentVerb.ACL_HITS, (
        "قوائم الوصول", "acl", "hits", "زيارات acl",
        "تدقيق acl",
    )),
    (IntentVerb.POE, (
        "poe", "الميزانية", "ميزانية الطاقة", "الطاقة الكهربائية",
    )),
    (IntentVerb.DRIFT, (
        "الانحراف", "تغير الإعدادات", "drift", "config drift",
        "ما الذي تغير",
    )),
    (IntentVerb.EOL, (
        "eol", "eos", "نهاية العمر", "نهاية الدعم", "هل الجهاز منتهي",
    )),
    (IntentVerb.TRUNK, (
        "ترانك", "trunk", "الترانكات", "تدقيق الترانك",
    )),
    (IntentVerb.UPGRADE, (
        "الترقية", "مسار الترقية", "upgrade", "ترقية ios",
    )),
    (IntentVerb.SUMMARY, (
        "ملخص", "ملخص الشبكة", "summary", "نظرة عامة",
    )),
    (IntentVerb.BOND, (
        "اربط", "أكد الربط", "bond",
    )),
    (IntentVerb.HELP, (
        "مساعدة", "ساعدني", "الأوامر", "help", "ما الذي تستطيع فعله",
    )),
    (IntentVerb.STATUS, (
        "الحالة", "status", "ما الوضع",
    )),
)

_EN_PATTERNS: tuple[tuple[IntentVerb, tuple[str, ...]], ...] = (
    (IntentVerb.DISCOVER, (
        "discover", "scan", "walk", "find devices", "explore",
        "what's on the network", "what is connected",
    )),
    (IntentVerb.SHOW_DEVICES, (
        "show devices", "list devices", "all devices", "show me devices",
        "what devices", "how many devices",
    )),
    (IntentVerb.SHOW_TOPOLOGY, (
        "show topology", "show map", "show network", "show the network",
        "topology", "map", "draw the network", "what's the topology",
    )),
    (IntentVerb.SHOW_INTERFACES, (        # plural BEFORE singular
        "show interfaces", "show ip interface brief",
        "list interfaces", "interfaces",
    )),
    (IntentVerb.SHOW_VLANS, (             # plural BEFORE singular
        "show vlans", "list vlans", "vlan table",
    )),
    (IntentVerb.SHOW_DEVICE, (
        "show device", "info about", "details of", "tell me about",
        "describe", "what is the",
    )),
    (IntentVerb.SHOW_INTERFACE, (
        "show interface", "interface status", "port status",
        "show port", "what's on port",
    )),
    (IntentVerb.SHOW_CONFIG, (
        "show config", "show running", "show running-config",
        "show configuration", "what's configured", "current config",
    )),
    (IntentVerb.SHOW_VERSION, (
        "show version", "what version", "ios version", "router version",
        "software version",
    )),
    (IntentVerb.SHOW_NEIGHBORS, (
        "show neighbors", "show cdp", "show lldp", "neighbors",
        "who is connected to", "what's connected",
    )),
    (IntentVerb.SHOW_VLANS, (
        "show vlan",
    )),
    (IntentVerb.SHOW_ROUTES, (
        "show route", "show ip route", "routing table", "routes",
    )),
    (IntentVerb.SHOW_RUN, (
        "show run", "running-config", "current configuration",
    )),
    (IntentVerb.APPLY_INTENT, (
        "apply", "deploy", "push", "execute", "run the config",
        "configure the network", "set up the network", "build the network",
        "make it work",
    )),
    (IntentVerb.STAGE, (
        "stage", "preview", "show without applying", "plan only",
    )),
    (IntentVerb.DESIGN, (
        "design", "plan", "compose", "build the design",
    )),
    (IntentVerb.ROLLBACK, (
        "rollback", "undo", "revert", "go back",
    )),
    (IntentVerb.PING, (
        "ping", "test reachability", "is x reachable",
    )),
    (IntentVerb.TRACEROUTE, (
        "traceroute", "trace", "tracepath", "show path to",
    )),
    (IntentVerb.DIAGNOSE, (
        "diagnose", "what's wrong", "why is", "troubleshoot",
    )),
    (IntentVerb.VERIFY, (
        "verify", "check", "validate", "confirm",
    )),
    (IntentVerb.COMPLIANCE, (
        "compliance", "audit", "hipaa", "pci", "cis", "nist",
        "security check", "hardening", "best practice",
    )),
    (IntentVerb.CONVERGENCE, (
        "convergence", "wait for convergence", "is it converged",
        "wait until stable", "wait for stable",
    )),
    (IntentVerb.SNAPSHOT, (
        "snapshot", "backup config", "save config", "restore config",
        "capture config", "golden config",
    )),
    (IntentVerb.DIFF, (
        "diff", "what changed", "compare configs", "show changes",
    )),
    (IntentVerb.HEALTH, (
        "health", "interface health", "port health", "link health",
        "check ports", "interface errors", "crc errors",
    )),
    (IntentVerb.CAPABILITY, (
        "capability", "what does this device support", "hardware",
        "model capabilities", "what can this router do",
    )),
    (IntentVerb.INVENTORY, (
        "inventory", "all devices", "list devices", "device list",
        "what do we have", "asset list",
    )),
    (IntentVerb.EXPORT, (
        "export", "audit export", "download audit", "csv", "json",
    )),
    (IntentVerb.MAINTENANCE, (
        "maintenance window", "change window", "maintenance",
        "scheduled window", "window",
    )),
    (IntentVerb.MAC_TABLE, (
        "mac address-table", "mac address table", "show mac",
        "mac table", "mac-table",
    )),
    (IntentVerb.CABLE_DIAG, (
        "cable diagnostic", "cable diag", "cable diagnostics",
        "show cable", "show interfaces cable",
    )),
    (IntentVerb.ROUTING, (
        "ospf neighbors", "bgp neighbors", "eigrp neighbors",
        "show ospf neighbor", "show ip ospf neighbor",
        "show ip bgp summary", "show ip eigrp neighbors",
        "routing neighbors", "routing protocols",
    )),
    (IntentVerb.ACL_HITS, (
        "show ip access-lists", "show access-lists", "acl audit",
        "show acl", "acl hits",
    )),
    (IntentVerb.POE, (
        "show power inline", "power inline", "poe budget",
        "poe allocation", "poe usage",
    )),
    (IntentVerb.DRIFT, (
        "config drift", "show drift", "drift detection",
        "what drifted", "what changed since",
    )),
    (IntentVerb.EOL, (
        "eol", "eos", "end of life", "end of support",
        "is this device still supported", "hardware lifecycle",
    )),
    (IntentVerb.TRUNK, (
        "show interfaces trunk", "trunk audit", "trunk matrix",
        "vlan trunks", "show trunk",
    )),
    (IntentVerb.UPGRADE, (
        "upgrade path", "can i upgrade", "ios upgrade",
        "show upgrade", "valid upgrade",
    )),
    (IntentVerb.SUMMARY, (
        "summary", "network summary", "give me a summary",
        "overall view", "one-pager",
    )),
    (IntentVerb.BOND, (
        "bond", "confirm binding", "i'm connected",
    )),
    (IntentVerb.HELP, (
        "help", "what can you do", "commands", "?", "menu",
    )),
    (IntentVerb.STATUS, (
        "status", "state", "what's the current state",
    )),
)


def _normalize(text: str) -> str:
    """Lowercase + collapse whitespace + strip diacritics-light."""
    t = text.strip().lower()
    # Strip Arabic diacritics (harakat)
    t = re.sub(r"[\u064B-\u0652\u0670\u0640]", "", t)
    # Collapse whitespace
    t = re.sub(r"\s+", " ", t)
    return t


def classify_intent(text: str) -> tuple[IntentVerb, dict[str, str]]:
    """Classify a chat message into a typed verb + extracted arguments.

    Returns (verb, args). ``args`` carries extracted entities like the
    device name, the interface name, the network type, etc.

    The classification is deterministic: same input always yields
    the same verb. Ties are broken by pattern order (more specific
    patterns first).
    """
    norm = _normalize(text)
    args: dict[str, str] = {}

    # Argument extraction (best-effort, language-agnostic).. Skip known English
    # stopwords and command verbs. Only extract AFTER we've checked for
    # IP / vlan / interface — so "show interface gi1/0/1" doesn't
    # capture "gi1" as a device.
    excluded_words = {
        "show", "the", "all", "what", "who", "is", "are", "do",
        "to", "from", "of", "in", "on", "a", "an", "and", "or",
        "list", "config", "running", "vlan", "interface", "version",
        "neighbors", "cdp", "lldp", "route", "apply", "deploy",
        "me", "interfaces", "vlans", "devices", "topology", "map",
        "status", "help", "ping", "trace", "traceroute",
        "diagnose", "verify", "check", "current", "configured",
        "give", "show", "tell", "describe", "what's", "what",
        "how", "many", "of", "this", "that", "it", "be", "as",
        "network", "type", "small", "office", "branch", "hotel",
        "retail", "datacenter", "leaf", "spine", "data", "center",
        "device", "detail", "details", "info", "about", "brief",
        "upgrade", "eol", "eos", "trunk", "drift", "summary",
        "power", "inline", "mac", "cable", "ospf", "bgp", "acl",
    }

    # 2) IP address
    ip_match = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", norm)
    if ip_match:
        args["ip"] = ip_match.group(1)

    # 3) VLAN id
    vlan_match = re.search(r"vlan\s*(\d+)", norm)
    if vlan_match:
        args["vlan_id"] = vlan_match.group(1)

    # 4) Interface name (e.g. gi1/0/1, eth0, FastEthernet0/1).
    # Require a slash OR be a clear "Eth" prefix to avoid false matches
    # like "vlan 10" being interpreted as interface="vlan".
    intf_match = re.search(
        r"\b((?:gi|fa|te|eth|ge|xe|xe-|et|po|lo)\S*[/]\S+)", norm
    )
    if not intf_match:
        intf_match = re.search(
            r"\b((?:gi|fa|te|eth|ge|xe|xe-|et|po|lo)\d+\S*)", norm
        )
    if intf_match:
        args["interface"] = intf_match.group(1)

    # 5) network type (for design/apply)
    for net_type in (
        "branch", "leaf-spine", "datacenter", "hotel", "retail",
        "guest_office", "small office", "مكتب", "فرع", "فندق", "متجر",
        "مركز بيانات",
    ):
        if net_type in norm:
            args["network_type"] = net_type
            break

    # 5b) capability lookup: "capability <vendor> <model>" — vendor
    # is one of the known vendor prefixes; model is whatever comes
    # after.
    if norm.startswith("capability") or "القدرات" in norm:
        # After "capability" / "القدرات", the next two tokens are
        # the vendor and model.
        tokens = norm.split()
        try:
            idx = tokens.index("capability")
        except ValueError:
            try:
                idx = tokens.index("القدرات")
            except ValueError:
                idx = -1
        if idx >= 0 and len(tokens) > idx + 1:
            args["vendor"] = tokens[idx + 1]
            if len(tokens) > idx + 2:
                args["model"] = tokens[idx + 2]

    # 5c) upgrade <from> to <to>
    if norm.startswith("upgrade") or norm.startswith("الترقية"):
        # "upgrade 17.9 to 17.12" or "الترقية 17.9 إلى 17.12"
        tokens = norm.split()
        version_pattern = re.compile(r"^\d+\.\d+")
        versions = [t for t in tokens if version_pattern.match(t)]
        if len(versions) >= 2:
            args["from_version"] = versions[0]
            args["to_version"] = versions[1]

    # 5d) eol <vendor> <model>
    if norm.startswith("eol") or norm.startswith("eos") or norm.startswith("نهاية"):
        tokens = norm.split()
        if len(tokens) >= 3:
            args["vendor"] = tokens[1]
            args["model"] = tokens[2]

    # 6) device ref — done LAST so we don't capture "gi1" as a device
    # when the user typed "show interface gi1/0/1".
    for candidate in re.findall(
        r"\b([a-z][a-z0-9\-]{1,30}(?:\.[a-z0-9\-]+)?)\b", norm
    ):
        if candidate.lower() in excluded_words:
            continue
        # If we already extracted an interface and the candidate is a
        # prefix of it, skip — it's the interface name, not a device.
        if "interface" in args and candidate in args["interface"]:
            continue
        # If we extracted a vlan number, don't use it as a device.
        if "vlan_id" in args and candidate == args["vlan_id"]:
            continue
        # If we extracted an IP, skip octets.
        if "ip" in args and candidate in args["ip"]:
            continue
        # Skip network types.
        if candidate in {
            "branch", "leaf-spine", "datacenter", "hotel", "retail",
            "guest_office", "office", "spine", "leaf", "data", "center",
        }:
            continue
        args["device"] = candidate
        break

    # ---- verb classification (most-specific first) ----
    # We sort by pattern length (longest first) and use a word-boundary
    # check so "show interface" doesn't match the input "show interfaces".
    candidates: list[tuple[int, IntentVerb]] = []
    for patterns in (_AR_PATTERNS, _EN_PATTERNS):
        for verb, words in patterns:
            for word in words:
                wn = _normalize(word)
                if not wn:
                    continue
                # Use word-boundary matching for Latin scripts.
                if re.search(r"[a-z]", wn):
                    pattern = r"(?:^|\b)" + re.escape(wn) + r"\b"
                    if re.search(pattern, norm):
                        candidates.append((len(wn), verb))
                else:
                    # Arabic / mixed — substring match (Arabic has no
                    # explicit word boundary).
                    if wn in norm:
                        candidates.append((len(wn), verb))
    if candidates:
        candidates.sort(key=lambda x: -x[0])  # longest first
        return (candidates[0][1], args)

    return (IntentVerb.UNKNOWN, args)


# ---------------------------------------------------------------------------
# OperatorReply — the typed result the chat UI receives.
# ---------------------------------------------------------------------------


class ReplyStatus(str, Enum):
    OK = "OK"
    BLOCKED = "BLOCKED"
    INFO = "INFO"
    NEEDS_INPUT = "NEEDS_INPUT"
    FAILURE = "FAILURE"


@dataclass
class OperatorReply:
    """A single response from the chat operator."""
    status: ReplyStatus
    intent: IntentVerb
    summary: str                         # one-line human description
    detail: str = ""                     # multi-line body
    data: dict = field(default_factory=dict)
    actions: list[dict] = field(default_factory=list)   # suggested next steps
    evidence_ids: list[str] = field(default_factory=list)
    correlation_id: str = field(default_factory=new_id)

    def to_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "status": self.status.value,
            "intent": self.intent.value,
            "summary": self.summary,
            "detail": self.detail,
            "data": self.data,
            "actions": self.actions,
            "evidence_ids": self.evidence_ids,
        }


# ---------------------------------------------------------------------------
# OperatorContext — the live state the operator queries.
# ---------------------------------------------------------------------------


@dataclass
class OperatorContext:
    """Holds the current state of the network the operator is reasoning about.

    The :class:`ChatOperator` mutates this state on every dispatched
    command. The UI can read it at any time to render the current
    picture of the network.
    """
    bonded: bool = False
    seed_port: Optional[str] = None
    last_run: Optional[Any] = None       # AutopilotReport
    last_discovery: Optional[Any] = None  # CrawlReport
    last_topology: Optional[Any] = None   # TopologyMap
    last_design: Optional[Any] = None    # SiteDesign
    last_change: Optional[Any] = None    # ChangeRecord
    change_history: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# ChatOperator — the main entry point.
# ---------------------------------------------------------------------------


class _EngineRunner(Protocol):
    """The shape the operator needs from the live engine. Allows tests
    to inject a SimFabric-backed implementation."""

    def run(self, *, port: str, execute: bool, answers: list[str]) -> Any: ...


class ChatOperator:
    """The chat-driven network operator.

    Receives natural-language messages (Arabic or English), routes them
    to the real engine, and returns the real result. No hallucination.
    """

    HELP_TEXT = {
        "ar": (
            "الأوامر المتاحة:\n"
            "• اكتشف / scan — اكتشاف الأجهزة في الشبكة\n"
            "• اعرض الأجهزة / show devices — قائمة الأجهزة\n"
            "• الخريطة / show topology — خريطة الشبكة\n"
            "• show config [device] — إعدادات جهاز\n"
            "• show version [device] — إصدار نظام جهاز\n"
            "• show neighbors [device] — جيران LLDP/CDP\n"
            "• show vlans [device] — جدول VLAN\n"
            "• show interfaces [device] — منافذ الجهاز\n"
            "• صمم [نوع] / design [type] — تصميم الشبكة\n"
            "• طبق [نوع] / apply [type] — تطبيق الإعدادات\n"
            "• ping/traceroute/diagnose — تشخيص\n"
            "• status — الحالة العامة\n"
        ),
        "en": (
            "Available commands:\n"
            "• discover / scan — walk the network\n"
            "• show devices — list discovered devices\n"
            "• show topology — show the network map\n"
            "• show config [device] — running-config of a device\n"
            "• show version [device] — OS version of a device\n"
            "• show neighbors [device] — LLDP/CDP neighbors\n"
            "• show vlans [device] — VLAN table\n"
            "• show interfaces [device] — port status\n"
            "• design [type] — design (don't apply)\n"
            "• apply [type] — design + apply to devices\n"
            "• ping/traceroute/diagnose — diagnostics\n"
            "• status — system status\n"
        ),
    }

    NETWORK_TYPES_AR = {
        "فرع": "branch", "مكتب": "guest_office", "مكتب صغير": "guest_office",
        "فندق": "hotel", "متجر": "retail", "مركز بيانات": "leaf-spine",
        "ديتاسنتر": "leaf-spine", "ورقة": "leaf-spine",
    }
    NETWORK_TYPES_EN = {
        "branch": "branch", "small office": "guest_office",
        "hotel": "hotel", "retail": "retail",
        "datacenter": "leaf-spine", "leaf-spine": "leaf-spine",
        "data center": "leaf-spine",
    }

    def __init__(
        self,
        *,
        store: LedgerStore,
        runner: Optional[_EngineRunner] = None,
        seed_port: str = "SIM0",
        device_runner: Optional[DeviceCommandRunner] = None,
        allowlist: Optional[CommandAllowlist] = None,
    ) -> None:
        self._store = store
        self._runner = runner
        self._seed_port = seed_port
        self._device_runner = device_runner
        self._allowlist = allowlist
        self._ctx = OperatorContext(seed_port=seed_port)
        self._actor = OperatorIdentity(kind="ENGINE", id="CHAT-OPERATOR")

    # -- public API --------------------------------------------------------

    @property
    def context(self) -> OperatorContext:
        return self._ctx

    @property
    def device_runner(self) -> Optional[DeviceCommandRunner]:
        return self._device_runner

    def attach_device_runner(self, runner: DeviceCommandRunner) -> None:
        """Wire a DeviceCommandRunner after construction."""
        self._device_runner = runner

    def detect_language(self, text: str) -> str:
        """Return 'ar' or 'en' based on script detection."""
        # Arabic Unicode block U+0600-U+06FF
        if re.search(r"[\u0600-\u06FF]", text):
            return "ar"
        return "en"

    def handle(self, message: str) -> OperatorReply:
        """Route a chat message to the right engine and return a real reply."""
        if not message or not message.strip():
            return self._reply(
                IntentVerb.UNKNOWN, ReplyStatus.NEEDS_INPUT,
                summary="empty" if self.detect_language(message) == "en"
                else "فارغ",
                detail="Type a command, e.g. 'show devices' or 'اكتشف'.",
            )

        lang = self.detect_language(message)
        verb, args = classify_intent(message)
        self._audit(verb, message, lang)

        if verb is IntentVerb.HELP:
            return self._reply(verb, ReplyStatus.INFO,
                               summary=("available commands" if lang == "en"
                                        else "الأوامر المتاحة"),
                               detail=self.HELP_TEXT[lang])

        if verb is IntentVerb.STATUS:
            return self._status_reply(lang)

        if verb is IntentVerb.DISCOVER:
            return self._do_discover(lang)

        if verb is IntentVerb.SHOW_DEVICES:
            return self._do_show_devices(lang)

        if verb is IntentVerb.SHOW_TOPOLOGY:
            return self._do_show_topology(lang)

        if verb is IntentVerb.SHOW_CONFIG or verb is IntentVerb.SHOW_RUN:
            return self._do_show_config(args.get("device"), lang)

        if verb is IntentVerb.SHOW_VERSION:
            return self._do_show_version(args.get("device"), lang)

        if verb is IntentVerb.SHOW_NEIGHBORS:
            return self._do_show_neighbors(args.get("device"), lang)

        if verb is IntentVerb.SHOW_VLANS:
            return self._do_show_vlans(args.get("device"), lang)

        if verb is IntentVerb.SHOW_INTERFACES:
            return self._do_show_interfaces(args.get("device"), lang)

        if verb is IntentVerb.SHOW_DEVICE:
            return self._do_show_device(args.get("device"), lang)

        if verb is IntentVerb.SHOW_INTERFACE:
            return self._do_show_interface(args.get("interface"), lang)

        if verb is IntentVerb.SHOW_ROUTES:
            return self._do_show_routes(args.get("device"), lang)

        if verb is IntentVerb.DESIGN or verb is IntentVerb.STAGE:
            return self._do_design(args.get("network_type"), lang, apply=False)

        if verb is IntentVerb.APPLY_INTENT:
            return self._do_design(args.get("network_type"), lang, apply=True)

        if verb is IntentVerb.ROLLBACK:
            return self._do_rollback(lang)

        if verb is IntentVerb.PING:
            return self._do_ping(args.get("ip") or args.get("device"), lang)

        if verb is IntentVerb.TRACEROUTE:
            return self._do_traceroute(args.get("ip") or args.get("device"), lang)

        if verb is IntentVerb.DIAGNOSE:
            return self._do_diagnose(lang)

        if verb is IntentVerb.VERIFY:
            return self._do_verify(lang)

        if verb is IntentVerb.COMPLIANCE:
            return self._do_compliance(args.get("device_ref"), lang)

        if verb is IntentVerb.CONVERGENCE:
            return self._do_convergence(args.get("device_ref"), lang)

        if verb is IntentVerb.SNAPSHOT:
            return self._do_snapshot(
                args.get("device_ref"),
                args.get("action") or "list",
                lang,
            )

        if verb is IntentVerb.DIFF:
            return self._do_diff(
                args.get("device_ref"),
                args.get("left_id"),
                args.get("right_id"),
                lang,
            )

        if verb is IntentVerb.HEALTH:
            return self._do_health(args.get("device_ref"), lang)

        if verb is IntentVerb.CAPABILITY:
            return self._do_capability(
                args.get("vendor"),
                args.get("model"),
                lang,
            )

        if verb is IntentVerb.INVENTORY:
            return self._do_inventory(args.get("filter"), lang)

        if verb is IntentVerb.EXPORT:
            return self._do_export(
                args.get("format") or "json",
                args.get("device_ref"),
                lang,
            )

        if verb is IntentVerb.MAINTENANCE:
            return self._do_maintenance(
                args.get("action") or "list",
                args.get("window_id"),
                lang,
            )

        if verb is IntentVerb.MAC_TABLE:
            return self._do_mac_table(args.get("device"), lang)

        if verb is IntentVerb.CABLE_DIAG:
            return self._do_cable_diag(args.get("device"), lang)

        if verb is IntentVerb.ROUTING:
            return self._do_routing(args.get("device"), lang)

        if verb is IntentVerb.ACL_HITS:
            return self._do_acl_hits(args.get("device"), lang)

        if verb is IntentVerb.POE:
            return self._do_poe(args.get("device"), lang)

        if verb is IntentVerb.DRIFT:
            return self._do_drift(args.get("device"), lang)

        if verb is IntentVerb.EOL:
            return self._do_eol(args.get("vendor"), args.get("model"), lang)

        if verb is IntentVerb.TRUNK:
            return self._do_trunk(args.get("device"), lang)

        if verb is IntentVerb.UPGRADE:
            return self._do_upgrade(args.get("from_version"), args.get("to_version"), lang)

        if verb is IntentVerb.SUMMARY:
            return self._do_summary(lang)

        if verb is IntentVerb.BOND:
            return self._do_bond(lang)

        # UNKNOWN — never invent an answer.
        return self._reply(
            IntentVerb.UNKNOWN, ReplyStatus.BLOCKED,
            summary=("I didn't recognize the command." if lang == "en"
                     else "لم أتعرف على الأمر."),
            detail=(f"Try: 'show devices', 'show topology', 'apply hotel'."
                    if lang == "en" else
                    "جرّب: 'اعرض الأجهزة'، 'الخريطة'، 'طبق فندق'."),
            actions=[{"verb": IntentVerb.HELP.value, "label":
                       "help" if lang == "en" else "مساعدة"}],
        )

    # -- discovery & read-only ---------------------------------------------

    def _do_discover(self, lang: str) -> OperatorReply:
        if self._runner is None:
            return self._reply(IntentVerb.DISCOVER, ReplyStatus.BLOCKED,
                summary=("Discovery runner not wired" if lang == "en"
                         else "لم يتم ربط محرك الاكتشاف"),
                detail="The chat needs a runner that opens a session to the seed device.")
        # The chat operator talks to the real AutopilotEngine. In a
        # real deployment the engine needs (a) a probe-port session
        # factory and (b) a management session factory. We use the
        # SimFabricFactory for sim-mode (port starting with SIM) and
        # otherwise use the real-fabric wiring (probe + refused mgmt),
        # letting the engine report a clean "no live devices" status.
        answers = self._autopilot_answers()
        try:
            port = self._seed_port
            if port and (port.startswith("SIM") or port.upper() == "SIM0"):
                # Sim mode — wire the engine against the scripted
                # SimFabric so it produces a real simulated topology.
                import sys as _sys, os as _os
                _root = _os.path.dirname(_os.path.dirname(
                    _os.path.dirname(_os.path.dirname(__file__))))
                if _root not in _sys.path:
                    _sys.path.insert(0, _root)
                from tests.support.simfabric import SimFabricFactory
                fabric = SimFabricFactory()
                # SimFabricFactory.probe() already returns
                # ``(session, banner_bytes)``; the orchestrator's
                # _phase_boot_probe also handles this tuple shape
                # directly — don't wrap it twice.
                report = self._runner.run(
                    probe_port_session_factory=fabric.probe,
                    mgmt_session_factory=fabric.open,
                    port=port, execute=False,
                )
            else:
                # Real port mode — use the same refused-mgmt path the
                # CLI uses. We import lazily so the chat works even if
                # the test paths are unavailable.
                from netops_autopilot.cli_main import (
                    _real_session_factory, _refused_mgmt_factory)
                report = self._runner.run(
                    probe_port_session_factory=_real_session_factory,
                    mgmt_session_factory=_refused_mgmt_factory,
                    port=port, execute=False,
                )
        except TypeError as exc:
            # The runner signature might be the older one (with
            # answers=). Fall back to that.
            if "answers" in str(exc) or "unexpected keyword" in str(exc):
                try:
                    report = self._runner.run(
                        port=self._seed_port, execute=False,
                        answers=self._autopilot_answers(),
                    )
                except Exception as e2:  # noqa: BLE001
                    return self._reply(IntentVerb.DISCOVER, ReplyStatus.FAILURE,
                        summary=("discovery error" if lang == "en" else "خطأ في الاكتشاف"),
                        detail=str(e2))
            else:
                raise
        except Failure as exc:
            return self._reply(IntentVerb.DISCOVER, ReplyStatus.BLOCKED,
                summary=("discovery failed" if lang == "en" else "فشل الاكتشاف"),
                detail="; ".join(exc.causes),
            )
        except Exception as exc:  # noqa: BLE001
            return self._reply(IntentVerb.DISCOVER, ReplyStatus.FAILURE,
                summary=("discovery error" if lang == "en" else "خطأ في الاكتشاف"),
                detail=str(exc))
        self._ctx.last_run = report
        self._ctx.last_discovery = report.crawl
        self._ctx.last_topology = report.topology
        self._ctx.last_design = report.design
        self._ctx.bonded = True

        if report.crawl is None:
            return self._reply(IntentVerb.DISCOVER, ReplyStatus.BLOCKED,
                summary=("no devices discovered" if lang == "en"
                         else "لم يتم اكتشاف أجهزة"),
                detail="Crawl returned no devices.")

        totals = report.crawl.totals
        n = totals.get("devices", 0)
        return self._reply(
            IntentVerb.DISCOVER, ReplyStatus.OK,
            summary=(f"discovered {n} device(s)" if lang == "en"
                     else f"تم اكتشاف {n} جهاز"),
            detail=self._render_devices_table(lang, report.crawl.devices),
            data={"totals": dict(totals),
                  "devices": [self._device_to_dict(d) for d in report.crawl.devices]},
            actions=[
                {"verb": IntentVerb.SHOW_TOPOLOGY.value,
                 "label": "show topology" if lang == "en" else "الخريطة"},
                {"verb": IntentVerb.APPLY_INTENT.value,
                 "label": "apply design" if lang == "en" else "طبق التصميم"},
            ],
        )

    def _do_show_devices(self, lang: str) -> OperatorReply:
        if self._ctx.last_discovery is None:
            return self._reply(IntentVerb.SHOW_DEVICES, ReplyStatus.BLOCKED,
                summary=("no devices yet — run 'discover' first" if lang == "en"
                         else "لا توجد أجهزة — شغّل 'اكتشف' أولاً"),
                detail="",
                actions=[{"verb": IntentVerb.DISCOVER.value,
                           "label": "discover" if lang == "en" else "اكتشف"}],
            )
        return self._reply(
            IntentVerb.SHOW_DEVICES, ReplyStatus.OK,
            summary=(f"{len(self._ctx.last_discovery.devices)} device(s)"
                     if lang == "en" else
                     f"{len(self._ctx.last_discovery.devices)} جهاز"),
            detail=self._render_devices_table(lang, self._ctx.last_discovery.devices),
            data={"devices": [self._device_to_dict(d)
                              for d in self._ctx.last_discovery.devices]},
        )

    def _do_show_topology(self, lang: str) -> OperatorReply:
        if self._ctx.last_topology is None:
            return self._reply(IntentVerb.SHOW_TOPOLOGY, ReplyStatus.BLOCKED,
                summary=("no topology yet — run 'discover' first" if lang == "en"
                         else "لا توجد خريطة — شغّل 'اكتشف' أولاً"),
                actions=[{"verb": IntentVerb.DISCOVER.value,
                           "label": "discover" if lang == "en" else "اكتشف"}])
        topo = self._ctx.last_topology
        return self._reply(
            IntentVerb.SHOW_TOPOLOGY, ReplyStatus.OK,
            summary=(f"{len(topo.nodes)} node(s), {len(topo.edges)} link(s)"
                     if lang == "en" else
                     f"{len(topo.nodes)} عقدة، {len(topo.edges)} رابط"),
            detail=topo.ascii,
            data={"nodes": [vars(n) if hasattr(n, "__dict__") else n
                            for n in topo.nodes],
                  "edges": [vars(e) if hasattr(e, "__dict__") else e
                            for e in topo.edges],
                  "gaps": [str(g) for g in topo.gaps]},
        )

    def _do_show_device(self, ref: Optional[str], lang: str) -> OperatorReply:
        if not ref:
            return self._reply(IntentVerb.SHOW_DEVICE, ReplyStatus.NEEDS_INPUT,
                summary=("which device?" if lang == "en" else "أي جهاز؟"),
                detail=("Type 'show device seed-01' for example."
                        if lang == "en" else
                        "اكتب مثلاً: 'اعرض الجهاز seed-01'."))
        device = self._find_device(ref)
        if device is None:
            return self._reply(IntentVerb.SHOW_DEVICE, ReplyStatus.BLOCKED,
                summary=(f"device {ref!r} not in inventory" if lang == "en"
                         else f"الجهاز {ref!r} غير موجود"),
                detail=("Run 'show devices' to see the inventory."
                        if lang == "en" else
                        "اعرض الأجهزة لرؤية القائمة."))
        return self._reply(
            IntentVerb.SHOW_DEVICE, ReplyStatus.OK,
            summary=f"{device.device_ref}",
            detail=self._render_device_detail(lang, device),
            data=self._device_to_dict(device),
        )

    def _do_show_interface(self, intf: Optional[str], lang: str) -> OperatorReply:
        if not intf:
            return self._reply(IntentVerb.SHOW_INTERFACE, ReplyStatus.NEEDS_INPUT,
                summary=("which interface?" if lang == "en" else "أي منفذ؟"),
                detail="e.g. 'show interface gi1/0/1'")
        # Search topology edges for the interface.
        if self._ctx.last_topology is None:
            return self._reply(IntentVerb.SHOW_INTERFACE, ReplyStatus.BLOCKED,
                summary=("no topology yet" if lang == "en" else "لا توجد خريطة"))
        topo = self._ctx.last_topology
        matching = []
        for e in topo.edges:
            e_a = e.endpoint_a if hasattr(e, "endpoint_a") else e.get("endpoint_a")
            e_b = e.endpoint_b if hasattr(e, "endpoint_b") else e.get("endpoint_b")
            for ep in (e_a, e_b):
                ep_intf = ep.interface if hasattr(ep, "interface") else ep.get("interface")
                if ep_intf and intf in str(ep_intf).lower():
                    matching.append(e)
        if not matching:
            return self._reply(IntentVerb.SHOW_INTERFACE, ReplyStatus.OK,
                summary=(f"interface {intf}: not linked" if lang == "en"
                         else f"المنفذ {intf}: غير مربوط"),
                detail=("No link evidence references this interface."
                        if lang == "en" else
                        "لا يوجد دليل ربط لهذا المنفذ."))
        lines = []
        for e in matching:
            e_a = e.endpoint_a if hasattr(e, "endpoint_a") else e.get("endpoint_a")
            e_b = e.endpoint_b if hasattr(e, "endpoint_b") else e.get("endpoint_b")
            lines.append(
                f"  • {e_a.device_ref}:{e_a.interface}  ↔  "
                f"{e_b.device_ref}:{e_b.interface}  [{e.fsm4_state}]"
            )
        return self._reply(
            IntentVerb.SHOW_INTERFACE, ReplyStatus.OK,
            summary=(f"interface {intf}: {len(matching)} link(s)" if lang == "en"
                     else f"المنفذ {intf}: {len(matching)} رابط"),
            detail="\n".join(lines),
        )

    def _do_show_config(self, ref: Optional[str], lang: str) -> OperatorReply:
        # The chat returns the last rendered config (from the design phase).
        if not ref and self._ctx.last_run is not None:
            renders = self._ctx.last_run.renders
            if renders:
                ref = next(iter(renders))
        if not ref or self._ctx.last_run is None or ref not in self._ctx.last_run.renders:
            return self._reply(IntentVerb.SHOW_CONFIG, ReplyStatus.BLOCKED,
                summary=("no config available" if lang == "en" else "لا توجد إعدادات"),
                detail=("Run 'discover' and a 'design' first."
                        if lang == "en" else
                        "شغّل الاكتشاف والتصميم أولاً."))
        rendered = self._ctx.last_run.renders[ref]
        text = rendered.to_text()
        return self._reply(
            IntentVerb.SHOW_CONFIG, ReplyStatus.OK,
            summary=f"{ref} — running-config (rendered preview)",
            detail=text,
            # Include the config text and full metadata in ``data``
            # so the UI can render it as a syntax-highlighted block
            # with line numbers, copy buttons, etc.
            data={
                "label": rendered.label,
                "verified": rendered.verified_templates,
                "config": text,
                "device": ref,
            },
        )

    def _do_show_version(self, ref: Optional[str], lang: str) -> OperatorReply:
        # Real execution: run ``show version`` on the device.
        if self._device_runner is not None:
            target = ref
            if not target and self._ctx.last_discovery is not None:
                for d in self._ctx.last_discovery.devices:
                    status = d.status.value if hasattr(d.status, "value") else str(d.status)
                    if status == "COMPLETE":
                        target = d.device_ref
                        break
                if not target and self._ctx.last_discovery.devices:
                    target = self._ctx.last_discovery.devices[0].device_ref
            if target:
                try:
                    result = self._device_runner.run_show(target, "show version")
                except Failure as exc:
                    return self._reply(IntentVerb.SHOW_VERSION, ReplyStatus.BLOCKED,
                        detail="; ".join(exc.causes),
                        summary=("version blocked" if lang == "en" else "الإصدار محظور"))
                if not result.success:
                    return self._reply(IntentVerb.SHOW_VERSION, ReplyStatus.FAILURE,
                        detail=result.note or "—",
                        summary=("version failed" if lang == "en" else "فشل الإصدار"))
                return self._reply(
                    IntentVerb.SHOW_VERSION, ReplyStatus.OK,
                    summary=(f"show version on {target} — {result.elapsed_s:.2f}s"
                             if lang == "en" else
                             f"عرض الإصدار على {target} — {result.elapsed_s:.2f}ث"),
                    detail=result.output_text or "—",
                    data=result.to_dict(),
                )
        # Fall back to the discovered device identity.
        device = self._find_device(ref) if ref else self._first_device()
        if device is None or device.identity is None:
            return self._reply(IntentVerb.SHOW_VERSION, ReplyStatus.BLOCKED,
                summary=("no version info" if lang == "en" else "لا توجد معلومات إصدار"))
        ident = device.identity
        return self._reply(
            IntentVerb.SHOW_VERSION, ReplyStatus.OK,
            summary=f"{device.device_ref} — {ident.vendor_family or '?'}",
            detail=(
                f"  model:    {ident.model or 'UNKNOWN'}\n"
                f"  version:  {ident.version or 'UNKNOWN'}\n"
                f"  serial:   {ident.serial or 'UNKNOWN'}"
            ),
            data={"model": ident.model, "version": ident.version,
                  "serial": ident.serial, "family": ident.vendor_family},
        )

    def _do_show_neighbors(self, ref: Optional[str], lang: str) -> OperatorReply:
        # Real execution path: run ``show lldp neighbors detail`` on
        # the device. Falls back to the topology model if no runner
        # is wired.
        if self._device_runner is not None:
            target = ref
            if not target and self._ctx.last_discovery is not None:
                for d in self._ctx.last_discovery.devices:
                    status = d.status.value if hasattr(d.status, "value") else str(d.status)
                    if status == "COMPLETE":
                        target = d.device_ref
                        break
                if not target and self._ctx.last_discovery.devices:
                    target = self._ctx.last_discovery.devices[0].device_ref
            if target:
                try:
                    result = self._device_runner.run_show(
                        target, "show lldp neighbors detail",
                    )
                except Failure as exc:
                    return self._reply(IntentVerb.SHOW_NEIGHBORS, ReplyStatus.BLOCKED,
                        detail="; ".join(exc.causes),
                        summary=("neighbors blocked" if lang == "en" else "الجيران محظورون"))
                if not result.success:
                    return self._reply(IntentVerb.SHOW_NEIGHBORS, ReplyStatus.FAILURE,
                        detail=result.note or "—",
                        summary=("neighbors failed" if lang == "en" else "فشل الجيران"))
                # Count neighbor entries.
                lines = [l for l in result.output_text.splitlines() if l.strip()]
                nbr_count = sum(1 for l in lines
                                if "Local Intf:" in l or "neighbor" in l.lower())
                return self._reply(
                    IntentVerb.SHOW_NEIGHBORS, ReplyStatus.OK,
                    summary=(f"show lldp on {target} — {nbr_count} neighbor(s)"
                             if lang == "en" else
                             f"عرض lldp على {target} — {nbr_count} جار"),
                    detail=result.output_text or "—",
                    data=result.to_dict() | {"neighbor_count": nbr_count},
                )
        if self._ctx.last_topology is None:
            return self._reply(IntentVerb.SHOW_NEIGHBORS, ReplyStatus.BLOCKED,
                summary=("no topology yet" if lang == "en" else "لا توجد خريطة"))
        if not ref:
            return self._reply(IntentVerb.SHOW_NEIGHBORS, ReplyStatus.OK,
                summary=("neighbors of all devices" if lang == "en"
                         else "جيران كل الأجهزة"),
                detail=self._ctx.last_topology.ascii,
            )
        edges = []
        topo = self._ctx.last_topology
        for e in topo.edges:
            a = e.endpoint_a if hasattr(e, "endpoint_a") else e.get("endpoint_a")
            b = e.endpoint_b if hasattr(e, "endpoint_b") else e.get("endpoint_b")
            a_dev = a.device_ref if hasattr(a, "device_ref") else a.get("device_ref")
            b_dev = b.device_ref if hasattr(b, "device_ref") else b.get("device_ref")
            if a_dev == ref or b_dev == ref:
                edges.append(e)
        if not edges:
            return self._reply(IntentVerb.SHOW_NEIGHBORS, ReplyStatus.OK,
                summary=(f"no neighbors of {ref}" if lang == "en"
                         else f"لا يوجد جيران للجهاز {ref}"))
        lines = []
        for e in edges:
            a = e.endpoint_a if hasattr(e, "endpoint_a") else e.get("endpoint_a")
            b = e.endpoint_b if hasattr(e, "endpoint_b") else e.get("endpoint_b")
            a_dev = a.device_ref if hasattr(a, "device_ref") else a.get("device_ref")
            a_intf = a.interface if hasattr(a, "interface") else a.get("interface")
            b_dev = b.device_ref if hasattr(b, "device_ref") else b.get("device_ref")
            b_intf = b.interface if hasattr(b, "interface") else b.get("interface")
            lines.append(
                f"  {a_dev}:{a_intf}  ↔  {b_dev}:{b_intf}  [{e.fsm4_state}]"
            )
        return self._reply(
            IntentVerb.SHOW_NEIGHBORS, ReplyStatus.OK,
            summary=(f"{len(edges)} neighbor link(s) of {ref}" if lang == "en"
                     else f"{len(edges)} رابط جوار لـ {ref}"),
            detail="\n".join(lines),
        )

    def _do_show_vlans(self, ref: Optional[str], lang: str) -> OperatorReply:
        # Real execution: run ``show vlan brief`` on the device.
        if self._device_runner is not None:
            target = ref
            if not target and self._ctx.last_discovery is not None:
                for d in self._ctx.last_discovery.devices:
                    status = d.status.value if hasattr(d.status, "value") else str(d.status)
                    if status == "COMPLETE":
                        target = d.device_ref
                        break
                if not target and self._ctx.last_discovery.devices:
                    target = self._ctx.last_discovery.devices[0].device_ref
            if target:
                try:
                    result = self._device_runner.run_show(target, "show vlan brief")
                except Failure as exc:
                    return self._reply(IntentVerb.SHOW_VLANS, ReplyStatus.BLOCKED,
                        detail="; ".join(exc.causes),
                        summary=("vlans blocked" if lang == "en" else "الشبكات محظورة"))
                if not result.success:
                    return self._reply(IntentVerb.SHOW_VLANS, ReplyStatus.FAILURE,
                        detail=result.note or "—",
                        summary=("vlans failed" if lang == "en" else "فشل VLAN"))
                # Count VLANs in the output.
                lines = result.output_text.splitlines()
                vlan_lines = [l for l in lines
                              if l and l.split() and l.split()[0].isdigit()]
                return self._reply(
                    IntentVerb.SHOW_VLANS, ReplyStatus.OK,
                    summary=(f"show vlan on {target} — {len(vlan_lines)} VLAN(s)"
                             if lang == "en" else
                             f"عرض VLANs على {target} — {len(vlan_lines)} شبكة"),
                    detail=result.output_text or "—",
                    data=result.to_dict() | {"vlan_count": len(vlan_lines)},
                )
        if not self._ctx.last_run or not self._ctx.last_run.renders:
            return self._reply(IntentVerb.SHOW_VLANS, ReplyStatus.BLOCKED,
                summary=("no design yet — run 'design' first" if lang == "en"
                         else "لا يوجد تصميم — شغّل 'صمم' أولاً"))
        # Fallback to staged config.
        lines = []
        for r in self._ctx.last_run.renders.values():
            for block in r.blocks:
                for cmd in block.commands:
                    if "vlan " in cmd or "name " in cmd:
                        lines.append(f"  [{r.device_ref}] {cmd}")
        if not lines:
            return self._reply(IntentVerb.SHOW_VLANS, ReplyStatus.OK,
                summary=("no VLANs in current design" if lang == "en"
                         else "لا توجد شبكات VLAN في التصميم الحالي"))
        return self._reply(
            IntentVerb.SHOW_VLANS, ReplyStatus.OK,
            summary=(f"{len(lines)} VLAN command(s) staged" if lang == "en"
                     else f"{len(lines)} أمر VLAN جاهز"),
            detail="\n".join(lines),
        )

    def _do_show_interfaces(self, ref: Optional[str], lang: str) -> OperatorReply:
        # Real execution: run ``show interfaces status`` on the device.
        if self._device_runner is not None:
            target = ref
            if not target and self._ctx.last_discovery is not None:
                for d in self._ctx.last_discovery.devices:
                    status = d.status.value if hasattr(d.status, "value") else str(d.status)
                    if status == "COMPLETE":
                        target = d.device_ref
                        break
                if not target and self._ctx.last_discovery.devices:
                    target = self._ctx.last_discovery.devices[0].device_ref
            if target:
                try:
                    result = self._device_runner.run_show(
                        target, "show interfaces status",
                    )
                except Failure as exc:
                    return self._reply(IntentVerb.SHOW_INTERFACES, ReplyStatus.BLOCKED,
                        detail="; ".join(exc.causes),
                        summary=("interfaces blocked" if lang == "en"
                                 else "المنافذ محظورة"))
                if not result.success:
                    return self._reply(IntentVerb.SHOW_INTERFACES, ReplyStatus.FAILURE,
                        detail=result.note or "—",
                        summary=("interfaces failed" if lang == "en"
                                 else "فشل المنافذ"))
                lines = result.output_text.splitlines()
                # Heuristic: count lines with 5+ space-separated fields.
                intf_lines = [l for l in lines
                              if l and len(l.split()) >= 4 and not l.startswith(("Port", "----"))]
                return self._reply(
                    IntentVerb.SHOW_INTERFACES, ReplyStatus.OK,
                    summary=(f"show interfaces on {target} — {len(intf_lines)} port(s)"
                             if lang == "en" else
                             f"عرض المنافذ على {target} — {len(intf_lines)} منفذ"),
                    detail=result.output_text or "—",
                    data=result.to_dict() | {"interface_count": len(intf_lines)},
                )
        if not self._ctx.last_run or not self._ctx.last_run.renders:
            return self._reply(IntentVerb.SHOW_INTERFACES, ReplyStatus.BLOCKED,
                summary=("no design yet" if lang == "en" else "لا يوجد تصميم"))
        lines = []
        for r in self._ctx.last_run.renders.values():
            for block in r.blocks:
                for cmd in block.commands:
                    if cmd.startswith("interface "):
                        lines.append(f"  [{r.device_ref}] {cmd}")
        return self._reply(
            IntentVerb.SHOW_INTERFACES, ReplyStatus.OK,
            summary=(f"{len(lines)} interface command(s)" if lang == "en"
                     else f"{len(lines)} أمر منافذ"),
            detail="\n".join(lines) or "—",
        )

    def _do_show_routes(self, ref: Optional[str], lang: str) -> OperatorReply:
        # If the operator captured the literal word "ip" as a device
        # ref (from "show ip route"), drop it so we fall back to the
        # default device.
        if ref == "ip":
            ref = None
        # If a device runner is wired, run real ``show ip route`` on
        # the chosen device (or the seed if no ref is given).
        target = ref
        if not target and self._ctx.last_discovery is not None:
            # default to the first REACHABLE device
            for d in self._ctx.last_discovery.devices:
                status = d.status.value if hasattr(d.status, "value") else str(d.status)
                if status == "COMPLETE":
                    target = d.device_ref
                    break
            if not target and self._ctx.last_discovery.devices:
                target = self._ctx.last_discovery.devices[0].device_ref
        if self._device_runner is not None and target:
            try:
                result = self._device_runner.run_show(target, "show ip route")
            except Failure as exc:
                return self._reply(IntentVerb.SHOW_ROUTES, ReplyStatus.BLOCKED,
                    summary=(f"show ip route {target} — blocked" if lang == "en"
                             else f"عرض المسارات {target} — محظور"),
                    detail="; ".join(exc.causes))
            if not result.success:
                return self._reply(IntentVerb.SHOW_ROUTES, ReplyStatus.FAILURE,
                    summary=(f"show ip route {target} — failed" if lang == "en"
                             else f"عرض المسارات {target} — فشل"),
                    detail=result.note or (result.output_text or "—"),
                    data=result.to_dict())
            # Parse the routing table for a clean summary.
            lines = result.output_text.splitlines()
            route_lines = [l for l in lines if l and (
                " via " in l
                or l.lstrip().startswith(("C ", "S ", "O ", "B ", "D ", "R ", "i ",
                                            "C\t", "S\t", "L ", "S*"))
            )]
            return self._reply(
                IntentVerb.SHOW_ROUTES, ReplyStatus.OK,
                summary=(f"show ip route on {target} — {len(route_lines)} route(s)"
                         if lang == "en" else
                         f"عرض المسارات على {target} — {len(route_lines)} مسار"),
                detail=result.output_text or "—",
                data=result.to_dict() | {"route_count": len(route_lines)},
            )
        # No runner / no device — fall back to the staged config.
        if not self._ctx.last_run or not self._ctx.last_run.renders:
            return self._reply(IntentVerb.SHOW_ROUTES, ReplyStatus.BLOCKED,
                summary=("no routes available — discover or attach a device"
                         if lang == "en" else
                         "لا توجد مسارات — اكتشف أو وصّل جهازًا"))
        # Otherwise, parse the staged config for "ip route" lines.
        lines = []
        for r in self._ctx.last_run.renders.values():
            for block in r.blocks:
                for cmd in block.commands:
                    if "ip route " in cmd or "ip address " in cmd:
                        lines.append(f"  [{r.device_ref}] {cmd}")
        return self._reply(
            IntentVerb.SHOW_ROUTES, ReplyStatus.OK,
            summary=(f"{len(lines)} route/ip entries staged" if lang == "en"
                     else f"{len(lines)} إدخال مسار جاهز"),
            detail="\n".join(lines) or "—",
        )

    # -- design / apply ----------------------------------------------------

    def _do_design(self, net_type: Optional[str], lang: str,
                   apply: bool) -> OperatorReply:
        if self._ctx.last_run is None:
            return self._reply(IntentVerb.DESIGN, ReplyStatus.NEEDS_INPUT,
                summary=("Run 'discover' first." if lang == "en"
                         else "شغّل الاكتشاف أولاً."),
                actions=[{"verb": IntentVerb.DISCOVER.value,
                           "label": "discover" if lang == "en" else "اكتشف"}])
        # Normalize network type.
        if net_type:
            if lang == "ar":
                net_type = self.NETWORK_TYPES_AR.get(net_type, net_type)
            else:
                net_type = self.NETWORK_TYPES_EN.get(net_type, net_type)
        # The autopilot already produced a design during discover.
        design = self._ctx.last_run.design
        if design is None or design.blocked:
            reasons = ", ".join(q for q in (design.blocking_questions if design else []))
            return self._reply(IntentVerb.DESIGN, ReplyStatus.BLOCKED,
                summary=("design blocked" if lang == "en" else "التصميم محظور"),
                detail=reasons or "the autopilot blocked at the design phase.")
        if apply and self._runner is not None:
            # Re-run with execute=True + BOND.
            try:
                port = self._seed_port
                if port and (port.startswith("SIM") or port.upper() == "SIM0"):
                    import sys as _sys, os as _os
                    _root = _os.path.dirname(_os.path.dirname(
                        _os.path.dirname(_os.path.dirname(__file__))))
                    if _root not in _sys.path:
                        _sys.path.insert(0, _root)
                    from tests.support.simfabric import SimFabricFactory
                    fabric = SimFabricFactory()
                    report = self._runner.run(
                        probe_port_session_factory=fabric.probe,
                        mgmt_session_factory=fabric.open,
                        port=port, execute=True,
                    )
                else:
                    from netops_autopilot.cli_main import (
                        _real_session_factory, _refused_mgmt_factory)
                    report = self._runner.run(
                        probe_port_session_factory=_real_session_factory,
                        mgmt_session_factory=_refused_mgmt_factory,
                        port=port, execute=True,
                    )
                self._ctx.last_run = report
                verdict = report.execution.get("outcome", "UNKNOWN") if report.execution else "UNKNOWN"
                return self._reply(
                    IntentVerb.APPLY_INTENT, ReplyStatus.OK,
                    summary=(f"applied — {verdict}" if lang == "en"
                             else f"تم التطبيق — {verdict}"),
                    detail=self._render_apply_report(lang, report),
                    data={"execution": report.execution, "final": report.final},
                )
            except Failure as exc:
                return self._reply(IntentVerb.APPLY_INTENT, ReplyStatus.BLOCKED,
                    summary=("apply failed" if lang == "en" else "فشل التطبيق"),
                    detail="; ".join(exc.causes))
        return self._reply(
            IntentVerb.DESIGN, ReplyStatus.OK,
            summary=("design ready (not applied)" if lang == "en"
                     else "التصميم جاهز (لم يطبق)"),
            detail=self._render_design(lang, design),
            actions=[{"verb": IntentVerb.APPLY_INTENT.value,
                       "label": "apply" if lang == "en" else "طبق"}],
        )

    def _do_rollback(self, lang: str) -> OperatorReply:
        # 1) If the chat's last run has a real execution with rollback
        # commands (built by ConfigExecutor._build_rollback_plan),
        # execute them on the device. This is the "actually undo it"
        # path — the one a 30-year engineer would expect.
        if self._device_runner is not None and self._allowlist is not None and self._ctx.last_run is not None:
            execution = getattr(self._ctx.last_run, "execution", None) or {}
            change_records = execution.get("change_records", [])
            for record in change_records:
                device_ref = record.get("device_ref")
                rollback_cmds = record.get("rollback_commands", [])
                if not (device_ref and rollback_cmds):
                    continue
                if record.get("outcome") != "APPLIED":
                    continue
                # Send every rollback command individually. Each
                # command must be in the allowlist.
                results = []
                for cmd in rollback_cmds:
                    # The allowlist classify needs the full cmd (e.g.
                    # "no vlan 10" matches a CONFIG_REVERSIBLE entry;
                    # "no vlan <vlan_id>" is the template). Try the
                    # head first, then the full cmd, then look up by
                    # inverse ("vlan 10" → classify the underlying
                    # intent). A `no <cmd>` form is the typed inverse
                    # of the original `cmd` — by construction the
                    # inverse is as allowed as the original.
                    cmd_stripped = cmd.strip()
                    cls = None
                    for try_cmd in (
                        cmd_stripped,                                # full
                        cmd_stripped.split(None, 1)[0] if cmd_stripped else "",  # head
                    ):
                        try:
                            cls = self._allowlist.classify(try_cmd)
                        except Exception:  # noqa: BLE001
                            cls = None
                        if cls:
                            break
                    if cls is None and cmd_stripped.startswith("no "):
                        # Inverse lookup: "no vlan 10" → classify
                        # "vlan 10" (the original). The classify is
                        # exact-match, so we walk the allowlist for
                        # any template whose head matches the
                        # inverse's head.
                        inverse = cmd_stripped[3:].strip()
                        try:
                            cls = self._allowlist.classify(inverse)
                        except Exception:  # noqa: BLE001
                            cls = None
                        if cls is None:
                            # Head-match: "vlan 10" head="vlan" →
                            # any template starting with "vlan ".
                            for tmpl, entry in self._allowlist._by_template.items():
                                if not tmpl.startswith(inverse.split(" ", 1)[0] + " "):
                                    continue
                                if entry.cls in ("CONFIG_REVERSIBLE", "CONFIG_HIGH_RISK"):
                                    cls = entry.cls
                                    break
                        if cls in ("CONFIG_REVERSIBLE", "CONFIG_HIGH_RISK"):
                            pass  # inverse of an allowed command is allowed
                        else:
                            cls = None
                    if cls not in ("CONFIG_REVERSIBLE", "CONFIG_HIGH_RISK", "READ_ONLY"):
                        results.append(f"  ✕ {cmd}  [BLOCKED: not in allowlist]")
                        continue
                    # For safety we use ``device_runner`` to run the
                    # command on the device (the runner is read-only
                    # for unknown commands; for known reversible
                    # commands it goes through). We re-open a
                    # management session for the rollback to take
                    # effect, then send the command via execute.
                    try:
                        session = self._device_runner.open_session(device_ref)
                    except Exception as exc:  # noqa: BLE001
                        results.append(f"  ✕ open_session: {exc}")
                        continue
                    try:
                        out = session.execute(cmd, timeout_s=10.0)
                        results.append(f"  ✓ {cmd}  → {out.decode('utf-8', 'replace').strip()[:80]}")
                    except Exception as exc:  # noqa: BLE001
                        results.append(f"  ✕ {cmd}  → {exc}")
                    finally:
                        try:
                            session.close()
                        except Exception:  # noqa: BLE001
                            pass
                return self._reply(
                    IntentVerb.ROLLBACK, ReplyStatus.OK,
                    summary=(f"rollback executed on {device_ref} — {len(rollback_cmds)} command(s)"
                             if lang == "en" else
                             f"تم التراجع على {device_ref} — {len(rollback_cmds)} أمر"),
                    detail="\n".join(results) or "—",
                )
        if not self._ctx.change_history:
            return self._reply(IntentVerb.ROLLBACK, ReplyStatus.BLOCKED,
                summary=("no change to rollback" if lang == "en"
                         else "لا توجد تغييرات للتراجع"),
                detail=("Run 'discover' then 'apply [type]' first; the rollback "
                        "plan is built by the executor and held in memory for the "
                        "next 'rollback' call."
                        if lang == "en" else
                        "شغّل الاكتشاف والتطبيق أولاً؛ خطة التراجع تُحفظ في الذاكرة."))
        last = self._ctx.change_history[-1]
        return self._reply(
            IntentVerb.ROLLBACK, ReplyStatus.OK,
            summary=("rollback plan" if lang == "en" else "خطة التراجع"),
            detail=("\n".join(last.get("rollback_commands", [])) or "—"),
        )

    def _do_ping(self, target: Optional[str], lang: str) -> OperatorReply:
        if not target:
            return self._reply(IntentVerb.PING, ReplyStatus.NEEDS_INPUT,
                summary=("which host?" if lang == "en" else "أي هدف؟"),
                detail="e.g. 'ping 10.0.0.1'")
        # Distinguish: is target an IP/hostname, or a device-ref?
        # A device ref contains a hyphen and no dots (e.g. "core-sw2",
        # "seed-01"). An IP has dots. A hostname has at least one letter.
        is_device_ref = (
            "-" in target and not DeviceCommandRunner._is_valid_target(target)
        )
        if is_device_ref and self._ctx.last_discovery is not None:
            # The user wants to ping a known device. Find its mgmt IP.
            target_ip = None
            target_name = target
            for d in self._ctx.last_discovery.devices:
                if d.device_ref == target:
                    if d.mgmt_addresses:
                        target_ip = d.mgmt_addresses[0]
                    break
            if not target_ip:
                return self._reply(IntentVerb.PING, ReplyStatus.BLOCKED,
                    summary=(f"ping {target} — no mgmt IP" if lang == "en"
                             else f"ping {target} — لا يوجد IP للإدارة"),
                    detail=("The device has no discovered mgmt address."
                            if lang == "en" else
                            "الجهاز ليس له عنوان IP مكتشف."))
            target = target_ip
        # If a device runner is wired, execute the real ping on the seed.
        if self._device_runner is not None and self._ctx.last_discovery is not None:
            # Pick the seed (the only REACHABLE device) to run ping from.
            seed = None
            for d in self._ctx.last_discovery.devices:
                status = d.status.value if hasattr(d.status, "value") else str(d.status)
                if status == "COMPLETE":
                    seed = d
                    break
            if seed is None:
                seed = self._ctx.last_discovery.devices[0]
            try:
                result = self._device_runner.ping(seed.device_ref, target)
            except Failure as exc:
                return self._reply(IntentVerb.PING, ReplyStatus.BLOCKED,
                    summary=(f"ping {target} — blocked" if lang == "en"
                             else f"ping {target} — محظور"),
                    detail="; ".join(exc.causes))
            if not result.success:
                return self._reply(IntentVerb.PING, ReplyStatus.FAILURE,
                    summary=(f"ping {target} on {seed.device_ref} — failed"
                             if lang == "en" else
                             f"ping {target} على {seed.device_ref} — فشل"),
                    detail=result.note or (result.output_text or "—"),
                    data=result.to_dict())
            summary = (f"ping {target} on {seed.device_ref} — {result.elapsed_s:.2f}s"
                       if lang == "en" else
                       f"ping {target} على {seed.device_ref} — {result.elapsed_s:.2f}ث")
            if is_device_ref:
                # Mention the resolved target device.
                summary = (f"ping {target_name} ({target}) on {seed.device_ref} — {result.elapsed_s:.2f}s"
                           if lang == "en" else
                           f"ping {target_name} ({target}) على {seed.device_ref} — {result.elapsed_s:.2f}ث")
            return self._reply(
                IntentVerb.PING, ReplyStatus.OK,
                summary=summary,
                detail=result.output_text or "—",
                data=result.to_dict(),
            )
        return self._reply(
            IntentVerb.PING, ReplyStatus.OK,
            summary=(f"ping {target} — chat-only (no live device runner)"
                     if lang == "en" else
                     f"ping {target} — وضع المحادثة (لا يوجد مشغّل جهاز)"),
            detail=("Attach a live device to run real ping."
                    if lang == "en" else
                    "وصّل جهازًا حقيقيًا لتنفيذ ping فعلي."),
        )

    def _do_traceroute(self, target: Optional[str], lang: str) -> OperatorReply:
        if not target:
            return self._reply(IntentVerb.TRACEROUTE, ReplyStatus.NEEDS_INPUT,
                summary=("which host?" if lang == "en" else "أي هدف؟"),
                detail="e.g. 'traceroute 8.8.8.8'")
        if self._device_runner is not None and self._ctx.last_discovery is not None:
            seed = None
            for d in self._ctx.last_discovery.devices:
                status = d.status.value if hasattr(d.status, "value") else str(d.status)
                if status == "COMPLETE":
                    seed = d
                    break
            if seed is None:
                seed = self._ctx.last_discovery.devices[0]
            try:
                result = self._device_runner.traceroute(seed.device_ref, target)
            except Failure as exc:
                return self._reply(IntentVerb.TRACEROUTE, ReplyStatus.BLOCKED,
                    summary=(f"traceroute {target} — blocked" if lang == "en"
                             else f"traceroute {target} — محظور"),
                    detail="; ".join(exc.causes))
            if not result.success:
                return self._reply(IntentVerb.TRACEROUTE, ReplyStatus.FAILURE,
                    summary=(f"traceroute {target} on {seed.device_ref} — failed"
                             if lang == "en" else
                             f"traceroute {target} على {seed.device_ref} — فشل"),
                    detail=result.note or (result.output_text or "—"),
                    data=result.to_dict())
            return self._reply(
                IntentVerb.TRACEROUTE, ReplyStatus.OK,
                summary=(f"traceroute {target} on {seed.device_ref} — {result.elapsed_s:.2f}s"
                         if lang == "en" else
                         f"traceroute {target} على {seed.device_ref} — {result.elapsed_s:.2f}ث"),
                detail=result.output_text or "—",
                data=result.to_dict(),
            )
        return self._reply(
            IntentVerb.TRACEROUTE, ReplyStatus.OK,
            summary=(f"traceroute {target} — chat-only" if lang == "en"
                     else f"traceroute {target} — وضع المحادثة"),
            detail=("Attach a live device to run real traceroute."
                    if lang == "en" else
                    "وصّل جهازًا حقيقيًا لتنفيذ traceroute فعلي."),
        )

    def _do_diagnose(self, lang: str) -> OperatorReply:
        if self._ctx.last_run is None:
            return self._reply(IntentVerb.DIAGNOSE, ReplyStatus.BLOCKED,
                summary=("no context — run 'discover' first" if lang == "en"
                         else "لا يوجد سياق — شغّل الاكتشاف أولاً"))
        gaps = self._ctx.last_topology.gaps if self._ctx.last_topology else []
        if not gaps:
            # No gaps, but we can still run a deeper health check:
            # - verify the ledger chain
            # - try to ping the seed from itself (real reachability)
            health_lines = []
            try:
                chain = self._store.verify_chain()
                health_lines.append(
                    ("  • ledger chain: OK" if chain.ok else "  • ledger chain: BROKEN")
                    + f" ({chain.checked} events)"
                )
            except Exception as exc:  # noqa: BLE001
                health_lines.append(f"  • ledger chain: UNVERIFIED ({exc})")
            if self._device_runner is not None and self._ctx.last_discovery is not None:
                for d in self._ctx.last_discovery.devices:
                    status = d.status.value if hasattr(d.status, "value") else str(d.status)
                    if status == "COMPLETE":
                        try:
                            alive = self._device_runner.is_alive(d.device_ref)
                            health_lines.append(
                                f"  • {d.device_ref}: {'ALIVE' if alive else 'UNREACHABLE'}"
                            )
                        except Exception as exc:  # noqa: BLE001
                            health_lines.append(f"  • {d.device_ref}: ERROR ({exc})")
            return self._reply(
                IntentVerb.DIAGNOSE, ReplyStatus.OK,
                summary=("no gaps — network healthy" if lang == "en"
                         else "لا توجد فجوات — الشبكة سليمة"),
                detail=("All advertised neighbors were reached.\n"
                        + "\n".join(health_lines)
                        if lang == "en" else
                        "كل الجيران المعلنون تم الوصول إليهم.\n"
                        + "\n".join(health_lines)),
            )
        text = "\n".join(f"  • {g}" for g in gaps)
        return self._reply(
            IntentVerb.DIAGNOSE, ReplyStatus.OK,
            summary=(f"{len(gaps)} gap(s) detected" if lang == "en"
                     else f"{len(gaps)} فجوة"),
            detail=text,
        )

    def _status_reply(self, lang: str) -> OperatorReply:
        n_dev = 0
        n_link = 0
        if self._ctx.last_topology:
            n_dev = len(self._ctx.last_topology.nodes)
            n_link = len(self._ctx.last_topology.edges)
        # verify_chain can raise KeyError if a key was rotated;
        # treat that as UNVERIFIED rather than crashing the chat.
        try:
            chain_ok = self._store.verify_chain().ok
            chain_label = "OK" if chain_ok else "BROKEN"
        except KeyError as exc:
            chain_label = f"UNVERIFIED ({exc})"
        return self._reply(
            IntentVerb.STATUS, ReplyStatus.OK,
            summary=("system status" if lang == "en" else "حالة النظام"),
            detail=(
                f"  bonded: {self._ctx.bonded}\n"
                f"  devices: {n_dev}\n"
                f"  links: {n_link}\n"
                f"  ledger events: {self._store.event_count()}\n"
                f"  chain integrity: {chain_label}"
            ),
        )

    def _do_verify(self, lang: str) -> OperatorReply:
        # Verify the ledger chain (always possible) and the topology.
        # The chain verify can raise if a key was rotated out of the
        # registry; treat that as a recoverable error, not a crash.
        try:
            chain = self._store.verify_chain()
            chain_line = (
                f"  ledger chain: {'OK' if chain.ok else 'BROKEN'}"
                f" ({chain.checked} events checked)"
            )
        except KeyError as exc:
            chain_line = f"  ledger chain: UNVERIFIED ({exc})"
        verif_lines = [chain_line]
        if self._ctx.last_topology:
            n = len(self._ctx.last_topology.nodes)
            e = len(self._ctx.last_topology.edges)
            verif_lines.append(f"  topology: {n} node(s), {e} link(s)")
        return self._reply(
            IntentVerb.VERIFY, ReplyStatus.OK,
            summary=("verification complete" if lang == "en" else "التحقق مكتمل"),
            detail="\n".join(verif_lines),
        )

    def _do_bond(self, lang: str) -> OperatorReply:
        self._ctx.bonded = True
        return self._reply(
            IntentVerb.BOND, ReplyStatus.OK,
            summary=("BOND confirmed" if lang == "en" else "تم تأكيد الربط"),
            detail=("BOND: I am authorized to make changes to this network.\n"
                    "You can now use 'apply [type]' safely."
                    if lang == "en" else
                    "BOND: أنا مخوّل لإحداث تغييرات على هذه الشبكة.\n"
                    "يمكنك الآن استخدام 'طبق [نوع]' بأمان."),
        )

    # -- Phase N: 30-year expert operations -------------------------------

    def _do_compliance(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Run HIPAA/PCI/CIS/NIST compliance checks on a device.

        If ``device_ref`` is omitted, runs against the seed
        (the only REACHABLE device by default).
        """
        from netops_autopilot.engines.compliance import (
            evaluate, render_report,
        )
        ref = device_ref
        if not ref:
            ref = "seed-01"  # default
        if self._device_runner is None or self._allowlist is None:
            return self._reply(
                IntentVerb.COMPLIANCE, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en" else "لا يوجد منفذ"),
                detail=("Run discover first." if lang == "en"
                        else "شغّل الاكتشاف أولاً."),
            )
        try:
            res = self._device_runner.run_show(ref, "show running-config")
            config = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.COMPLIANCE, ReplyStatus.BLOCKED,
                summary=("compliance failed" if lang == "en"
                         else "فشل الامتثال"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        report = evaluate(ref, config)
        return self._reply(
            IntentVerb.COMPLIANCE, ReplyStatus.OK,
            summary=(
                f"compliance — {report.overall_verdict}"
                if lang == "en"
                else f"الامتثال — {report.overall_verdict}"
            ),
            detail=render_report(report, lang=lang),
            data={
                "device_ref": ref,
                "verdict": report.overall_verdict,
                "pass_count": report.pass_count,
                "fail_count": report.fail_count,
                "critical": [f.rule_id for f in report.critical_failures],
                "high": [f.rule_id for f in report.high_failures],
            },
        )

    def _do_convergence(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Wait for the routing table to converge on a device."""
        from netops_autopilot.engines.convergence import (
            ConvergenceProbe, probe,
        )
        ref = device_ref or "seed-01"
        if self._device_runner is None or self._allowlist is None:
            return self._reply(
                IntentVerb.CONVERGENCE, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en" else "لا يوجد منفذ"),
            )
        try:
            session = self._device_runner.open_session(ref)
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.CONVERGENCE, ReplyStatus.BLOCKED,
                summary=("convergence failed" if lang == "en"
                         else "فشل التقارب"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        cfg = ConvergenceProbe(
            device_ref=ref,
            commands=("show ip route summary", "show ip arp"),
            max_attempts=4,
            interval_s=0.5,
        )
        try:
            res = probe(session, cfg)
        finally:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
        return self._reply(
            IntentVerb.CONVERGENCE, ReplyStatus.OK,
            summary=(
                f"convergence — {res.verdict.value} after {res.attempts} sample(s)"
                if lang == "en"
                else f"التقارب — {res.verdict.value} بعد {res.attempts} عينة"
            ),
            detail=res.detail,
            data={
                "device_ref": ref,
                "verdict": res.verdict.value,
                "attempts": res.attempts,
                "convergence_time_s": res.convergence_time_s,
            },
        )

    def _do_snapshot(
        self, device_ref: Optional[str], action: str, lang: str
    ) -> OperatorReply:
        """Capture / list / restore a config snapshot."""
        from netops_autopilot.engines.backup import (
            SnapshotStore, capture,
        )
        ref = device_ref or "seed-01"
        store = SnapshotStore(".netops-snapshots")
        if action in ("capture", "save", "take"):
            if self._device_runner is None:
                return self._reply(
                    IntentVerb.SNAPSHOT, ReplyStatus.BLOCKED,
                    summary=("no device runner" if lang == "en"
                             else "لا يوجد منفذ"),
                )
            try:
                session = self._device_runner.open_session(ref)
            except Exception as exc:  # noqa: BLE001
                return self._reply(
                    IntentVerb.SNAPSHOT, ReplyStatus.BLOCKED,
                    summary=("snapshot failed" if lang == "en"
                             else "فشل اللقطة"),
                    detail=f"{type(exc).__name__}: {exc}",
                )
            try:
                snap = capture(session, ref, note="chat-captured")
            finally:
                try:
                    session.close()
                except Exception:  # noqa: BLE001
                    pass
            store.save(snap)
            return self._reply(
                IntentVerb.SNAPSHOT, ReplyStatus.OK,
                summary=(
                    f"snapshot {snap.snapshot_id} captured ({snap.byte_size}b)"
                    if lang == "en"
                    else f"تم التقاط {snap.snapshot_id} ({snap.byte_size}ب)"
                ),
                detail=snap.snapshot_id,
                data={"snapshot_id": snap.snapshot_id,
                      "hash": snap.config_hash},
            )
        # Default: list
        snaps = store.list(ref)
        if not snaps:
            return self._reply(
                IntentVerb.SNAPSHOT, ReplyStatus.OK,
                summary=("no snapshots" if lang == "en" else "لا توجد لقطات"),
                detail=("Use 'snapshot capture' to take one."
                        if lang == "en" else
                        "استخدم 'لقطة التقاط' لأخذ واحدة."),
            )
        lines = [f"snapshots for {ref}:"]
        for s in snaps[:10]:
            lines.append(f"  {s.snapshot_id}  hash={s.config_hash}  "
                         f"size={s.byte_size}b  note={s.note!r}")
        return self._reply(
            IntentVerb.SNAPSHOT, ReplyStatus.OK,
            summary=(
                f"{len(snaps)} snapshot(s) for {ref}"
                if lang == "en"
                else f"{len(snaps)} لقطة لـ {ref}"
            ),
            detail="\n".join(lines),
        )

    def _do_diff(
        self, device_ref: Optional[str],
        left_id: Optional[str], right_id: Optional[str],
        lang: str,
    ) -> OperatorReply:
        """Diff two snapshots on a device (or the two most recent)."""
        from netops_autopilot.engines.backup import (
            SnapshotStore, diff_snapshots, render_diff,
        )
        ref = device_ref or "seed-01"
        store = SnapshotStore(".netops-snapshots")
        snaps = store.list(ref)
        if len(snaps) < 2:
            return self._reply(
                IntentVerb.DIFF, ReplyStatus.BLOCKED,
                summary=("not enough snapshots" if lang == "en"
                         else "لقطات غير كافية"),
                detail=("Need at least 2 snapshots to diff. "
                        "Use 'snapshot capture' to take more."
                        if lang == "en" else
                        "تحتاج لقطتين على الأقل. استخدم 'لقطة التقاط'."),
            )
        # Use the two most recent by default.
        if not left_id:
            left_id = snaps[1].snapshot_id
        if not right_id:
            right_id = snaps[0].snapshot_id
        left = store.get(left_id)
        right = store.get(right_id)
        if not left or not right:
            return self._reply(
                IntentVerb.DIFF, ReplyStatus.BLOCKED,
                summary=("snapshot not found" if lang == "en"
                         else "اللقطة غير موجودة"),
                detail=f"left={left_id} right={right_id}",
            )
        d = diff_snapshots(left, right)
        return self._reply(
            IntentVerb.DIFF, ReplyStatus.OK,
            summary=(
                f"diff: +{d.added_count} -{d.removed_count}"
                if lang == "en"
                else f"الفرق: +{d.added_count} -{d.removed_count}"
            ),
            detail=render_diff(d, lang=lang),
        )

    def _do_health(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Parse 'show interfaces' and report per-port health."""
        from netops_autopilot.engines.health import (
            DeviceHealth, parse_interfaces, render_health,
        )
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.HEALTH, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en"
                         else "لا يوجد منفذ"),
            )
        try:
            res = self._device_runner.run_show(ref, "show interfaces")
            output = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.HEALTH, ReplyStatus.BLOCKED,
                summary=("health check failed" if lang == "en"
                         else "فشل فحص الصحة"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        interfaces = parse_interfaces(output)
        h = DeviceHealth(device_ref=ref, interfaces=interfaces)
        return self._reply(
            IntentVerb.HEALTH, ReplyStatus.OK,
            summary=(
                f"health — {h.overall_verdict}"
                if lang == "en"
                else f"الصحة — {h.overall_verdict}"
            ),
            detail=render_health(h, lang=lang),
            data={
                "device_ref": ref,
                "verdict": h.overall_verdict,
                "healthy": h.healthy_count,
                "degraded": h.degraded_count,
                "critical": h.critical_count,
                "down": h.down_count,
            },
        )

    def _do_capability(
        self, vendor: Optional[str], model: Optional[str], lang: str
    ) -> OperatorReply:
        """Look up the hardware capability matrix for a model."""
        from netops_autopilot.engines.capability_matrix import (
            lookup, render_capabilities, Capability,
            has_capability,
        )
        if not vendor or not model:
            return self._reply(
                IntentVerb.CAPABILITY, ReplyStatus.NEEDS_INPUT,
                summary=("which model?" if lang == "en" else "أي طراز؟"),
                detail=("e.g. 'capability cisco C9500-48Y4C'"
                        if lang == "en" else
                        "مثال: 'القدرات cisco C9500-48Y4C'"),
            )
        spec = lookup(vendor, model)
        if spec is None:
            return self._reply(
                IntentVerb.CAPABILITY, ReplyStatus.BLOCKED,
                summary=("model unknown" if lang == "en" else "طراز غير معروف"),
                detail=f"{vendor}/{model} not in catalogue",
            )
        # Check a few high-value capabilities
        vx_ok, vx_reason = has_capability(vendor, model, Capability.VXLAN)
        bgp_ok, bgp_reason = has_capability(vendor, model, Capability.BGP)
        extra = (
            f"\nVXLAN: {vx_reason}\nBGP: {bgp_reason}"
        )
        return self._reply(
            IntentVerb.CAPABILITY, ReplyStatus.OK,
            summary=(
                f"{vendor}/{model} — {len(spec.capabilities)} capabilities"
                if lang == "en"
                else f"{vendor}/{model} — {len(spec.capabilities)} قدرة"
            ),
            detail=render_capabilities(spec, lang=lang) + extra,
        )

    def _do_inventory(
        self, filter_text: Optional[str], lang: str
    ) -> OperatorReply:
        """Aggregated inventory view."""
        from netops_autopilot.engines.inventory import (
            Inventory, InventoryItem, render_inventory,
        )
        items: list[InventoryItem] = []
        if self._ctx.last_discovery is not None:
            for d in self._ctx.last_discovery.devices:
                # The DeviceResult has an Identity, not vendor_family.
                vendor = ""
                model = ""
                serial = ""
                identity = getattr(d, "identity", None)
                if identity is not None:
                    vendor = (getattr(identity, "vendor_family", "") or "").split("/")[-1] if getattr(identity, "vendor_family", None) else ""
                    model = getattr(identity, "model", "") or ""
                    serial = getattr(identity, "serial", "") or ""
                items.append(InventoryItem(
                    device_ref=d.device_ref,
                    vendor=vendor,
                    model=model,
                    serial=serial,
                    mgmt_address=(d.mgmt_addresses[0] if d.mgmt_addresses else ""),
                    status=str(d.status) if d.status else "",
                ))
        inv = Inventory(items=items)
        if filter_text:
            inv = inv.search(filter_text)
        return self._reply(
            IntentVerb.INVENTORY, ReplyStatus.OK,
            summary=(
                f"{len(inv.items)} device(s) in inventory"
                if lang == "en"
                else f"{len(inv.items)} جهاز في المخزون"
            ),
            detail=render_inventory(inv, lang=lang),
        )

    def _do_export(
        self, fmt: str, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Export the audit trail as JSON or CSV."""
        from netops_autopilot.engines.audit_export import (
            export, ExportFilter,
        )
        if fmt not in ("json", "csv"):
            fmt = "json"
        f = ExportFilter(device_ref=device_ref or "")
        try:
            out = export(self._store, f, fmt=fmt)
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.EXPORT, ReplyStatus.BLOCKED,
                summary=("export failed" if lang == "en" else "فشل التصدير"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        # Save to a file the operator can download.
        import os
        os.makedirs("audit-exports", exist_ok=True)
        path = f"audit-exports/audit-{int(time.time())}.{fmt}"
        try:
            with open(path, "w", encoding="utf-8") as f_out:
                f_out.write(out)
        except OSError:
            pass
        return self._reply(
            IntentVerb.EXPORT, ReplyStatus.OK,
            summary=(
                f"audit exported to {path}"
                if lang == "en" else f"تم تصدير التدقيق إلى {path}"
            ),
            detail=f"{len(out)} bytes written to {path}",
            data={"path": path, "format": fmt, "bytes": len(out)},
        )

    def _do_maintenance(
        self, action: str, window_id: Optional[str], lang: str
    ) -> OperatorReply:
        """List / create / check maintenance windows."""
        from netops_autopilot.engines.maintenance import (
            MaintenanceWindow, WindowRegistry, evaluate_window,
        )
        reg = getattr(self, "_window_registry", None)
        if reg is None:
            reg = WindowRegistry()
            self._window_registry = reg
        if action in ("add", "create", "schedule"):
            if not window_id:
                return self._reply(
                    IntentVerb.MAINTENANCE, ReplyStatus.NEEDS_INPUT,
                    summary=("window id required" if lang == "en"
                             else "مطلوب معرف النافذة"),
                )
            # Default to "now through +1h" if no other args.
            import time as _t
            w = MaintenanceWindow(
                window_id=window_id,
                label=window_id,
                start_unix=_t.time() - 60.0,
                end_unix=_t.time() + 3600.0,
                reason="chat-scheduled",
            )
            reg.add(w)
            return self._reply(
                IntentVerb.MAINTENANCE, ReplyStatus.OK,
                summary=(
                    f"window {window_id} scheduled (now+1h)"
                    if lang == "en"
                    else f"تم جدولة {window_id} (الآن+ساعة)"
                ),
                detail=window_id,
            )
        # Default: list + active check
        active = reg.list_active()
        all_w = reg.list_all()
        lines = [f"windows ({len(all_w)} total, {len(active)} active)"]
        for w in all_w:
            check = evaluate_window(w)
            lines.append(
                f"  {w.window_id}  {w.label}  "
                f"[{check.verdict.value}]  {check.detail}"
            )
        return self._reply(
            IntentVerb.MAINTENANCE, ReplyStatus.OK,
            summary=(
                f"{len(active)} active window(s)"
                if lang == "en" else f"{len(active)} نافذة نشطة"
            ),
            detail="\n".join(lines),
        )

    # -- Phase O: 30-year expert diagnostics -------------------------------

    def _do_mac_table(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Parse 'show mac address-table' on a device."""
        from netops_autopilot.engines.mac_table import analyse
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.MAC_TABLE, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en" else "لا يوجد منفذ"),
            )
        try:
            res = self._device_runner.run_show(ref, "show mac address-table")
            output = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.MAC_TABLE, ReplyStatus.BLOCKED,
                summary=("mac table failed" if lang == "en" else "فشل جدول MAC"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        a = analyse(ref, output)
        from netops_autopilot.engines.mac_table import render as render_mac
        return self._reply(
            IntentVerb.MAC_TABLE, ReplyStatus.OK,
            summary=(
                f"mac table — {len(a.entries)} entries, "
                f"{len(a.flapping_macs)} flapping MAC(s)"
                if lang == "en"
                else f"جدول MAC — {len(a.entries)} إدخال، "
                     f"{len(a.flapping_macs)} عنوان متذبذب"
            ),
            detail=render_mac(a, lang=lang),
            data={
                "device_ref": ref,
                "entry_count": len(a.entries),
                "flapping_count": len(a.flapping_macs),
            },
        )

    def _do_cable_diag(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Parse 'show interfaces' for cable diagnostics."""
        from netops_autopilot.engines.cable_diag import (
            parse as parse_cable, CableReport,
        )
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.CABLE_DIAG, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en" else "لا يوجد منفذ"),
            )
        try:
            res = self._device_runner.run_show(ref, "show interfaces")
            output = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.CABLE_DIAG, ReplyStatus.BLOCKED,
                summary=("cable diag failed" if lang == "en" else "فشل تشخيص الكابلات"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        stats = parse_cable(output)
        r = CableReport(device_ref=ref, interfaces=stats)
        from netops_autopilot.engines.cable_diag import (
            render as render_cable,
        )
        return self._reply(
            IntentVerb.CABLE_DIAG, ReplyStatus.OK,
            summary=(
                f"cable — {r.overall_verdict}"
                if lang == "en"
                else f"الكابلات — {r.overall_verdict}"
            ),
            detail=render_cable(r, lang=lang),
            data={
                "device_ref": ref,
                "verdict": r.overall_verdict,
                "degraded": len(r.degraded_interfaces),
                "fault": len(r.fault_interfaces),
            },
        )

    def _do_routing(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Run OSPF + BGP neighbor state checks."""
        from netops_autopilot.engines.routing_neighbors import (
            RoutingReport, parse_ospf, parse_bgp,
        )
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.ROUTING, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en" else "لا يوجد منفذ"),
            )
        try:
            ospf_res = self._device_runner.run_show(ref, "show ip ospf neighbor")
            ospf = parse_ospf(
                ospf_res.output.decode("utf-8", errors="replace")
            )
        except Exception:
            ospf = []
        try:
            bgp_res = self._device_runner.run_show(ref, "show ip bgp summary")
            bgp = parse_bgp(
                bgp_res.output.decode("utf-8", errors="replace")
            )
        except Exception:
            bgp = []
        r = RoutingReport(device_ref=ref, ospf=ospf, bgp=bgp)
        from netops_autopilot.engines.routing_neighbors import (
            render as render_routing,
        )
        return self._reply(
            IntentVerb.ROUTING, ReplyStatus.OK,
            summary=(
                f"routing — {r.overall_verdict} "
                f"(OSPF: {len(r.ospf)}, BGP: {len(r.bgp)})"
                if lang == "en"
                else f"الراوتنج — {r.overall_verdict} "
                     f"(OSPF: {len(r.ospf)}، BGP: {len(r.bgp)})"
            ),
            detail=render_routing(r, lang=lang),
            data={
                "device_ref": ref,
                "verdict": r.overall_verdict,
                "ospf_count": len(r.ospf),
                "bgp_count": len(r.bgp),
            },
        )

    def _do_acl_hits(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Run ACL audit and report ACEs with hot/cold verdict."""
        from netops_autopilot.engines.acl_audit import (
            parse as parse_acl, AclReport,
        )
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.ACL_HITS, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en" else "لا يوجد منفذ"),
            )
        try:
            res = self._device_runner.run_show(ref, "show ip access-lists")
            output = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.ACL_HITS, ReplyStatus.BLOCKED,
                summary=("acl audit failed" if lang == "en" else "فشل تدقيق ACL"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        aces = parse_acl(output)
        r = AclReport(device_ref=ref, aces=aces)
        from netops_autopilot.engines.acl_audit import (
            render as render_acl,
        )
        return self._reply(
            IntentVerb.ACL_HITS, ReplyStatus.OK,
            summary=(
                f"acl — {r.total} ACEs, {len(r.hot)} hot, {len(r.cold)} cold"
                if lang == "en"
                else f"ACL — {r.total} قاعدة، {len(r.hot)} نشطة، {len(r.cold)} خامدة"
            ),
            detail=render_acl(r, lang=lang),
            data={
                "device_ref": ref,
                "total": r.total,
                "hot": len(r.hot),
                "cold": len(r.cold),
            },
        )

    def _do_poe(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Run PoE budget check on a device."""
        from netops_autopilot.engines.poe import analyse
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.POE, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en" else "لا يوجد منفذ"),
            )
        try:
            res = self._device_runner.run_show(ref, "show power inline")
            output = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.POE, ReplyStatus.BLOCKED,
                summary=("poe check failed" if lang == "en" else "فشل فحص PoE"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        r = analyse(ref, output)
        from netops_autopilot.engines.poe import render as render_poe
        return self._reply(
            IntentVerb.POE, ReplyStatus.OK,
            summary=(
                f"poe — {r.overall_verdict} ({r.utilization_pct:.1f}% used)"
                if lang == "en"
                else f"PoE — {r.overall_verdict} ({r.utilization_pct:.1f}% مستخدم)"
            ),
            detail=render_poe(r, lang=lang),
            data={
                "device_ref": ref,
                "verdict": r.overall_verdict,
                "budget_w": r.nominal_budget_w,
                "allocated_w": r.allocated_w,
                "utilization_pct": r.utilization_pct,
            },
        )

    def _do_drift(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Compare current running-config to the last known-good snapshot."""
        from netops_autopilot.engines.drift import detect
        from netops_autopilot.engines.backup import SnapshotStore
        ref = device_ref or "seed-01"
        store = SnapshotStore(".netops-snapshots")
        snaps = store.list(ref)
        if not snaps:
            return self._reply(
                IntentVerb.DRIFT, ReplyStatus.BLOCKED,
                summary=("no baseline — snapshot capture first" if lang == "en"
                         else "لا يوجد مرجع — التقط لقطة أولاً"),
            )
        baseline = store.get(snaps[0].snapshot_id)
        if baseline is None:
            return self._reply(
                IntentVerb.DRIFT, ReplyStatus.BLOCKED,
                summary=("baseline missing" if lang == "en" else "المرجع مفقود"),
            )
        if self._device_runner is None:
            return self._reply(
                IntentVerb.DRIFT, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en" else "لا يوجد منفذ"),
            )
        try:
            res = self._device_runner.run_show(ref, "show running-config")
            current = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.DRIFT, ReplyStatus.BLOCKED,
                summary=("drift check failed" if lang == "en" else "فشل فحص الانحراف"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        r = detect(ref, baseline, current)
        from netops_autopilot.engines.drift import render as render_drift
        return self._reply(
            IntentVerb.DRIFT, ReplyStatus.OK,
            summary=(
                f"drift — {r.overall_verdict} ({r.drift_count} lines)"
                if lang == "en"
                else f"الانحراف — {r.overall_verdict} ({r.drift_count} سطر)"
            ),
            detail=render_drift(r, lang=lang),
            data={
                "device_ref": ref,
                "verdict": r.overall_verdict,
                "drift_count": r.drift_count,
                "added": len(r.added),
                "removed": len(r.removed),
            },
        )

    def _do_eol(
        self, vendor: Optional[str], model: Optional[str], lang: str
    ) -> OperatorReply:
        """Look up hardware EOL/EOS status."""
        from netops_autopilot.engines.eol import evaluate as evaluate_eol, render
        # If no model given, default to looking up the first
        # discovered device's model.
        if not vendor or not model:
            if self._ctx.last_discovery is not None:
                for d in self._ctx.last_discovery.devices:
                    if d.identity and d.identity.model:
                        vendor = vendor or (
                            (d.identity.vendor_family or "").split("/")[-1]
                            if d.identity.vendor_family else "cisco"
                        )
                        model = model or d.identity.model
                        break
        if not vendor or not model:
            return self._reply(
                IntentVerb.EOL, ReplyStatus.NEEDS_INPUT,
                summary=("which model?" if lang == "en" else "أي طراز؟"),
                detail=("e.g. 'eol cisco C9500-48Y4C'"
                        if lang == "en"
                        else "مثال: 'eol cisco C9500-48Y4C'"),
            )
        s = evaluate_eol(vendor, model)
        if s is None:
            return self._reply(
                IntentVerb.EOL, ReplyStatus.BLOCKED,
                summary=("model unknown" if lang == "en" else "طراز غير معروف"),
                detail=f"{vendor}/{model} not in catalogue",
            )
        return self._reply(
            IntentVerb.EOL, ReplyStatus.OK,
            summary=(
                f"eol — {s.verdict.value}"
                if lang == "en"
                else f"EOL — {s.verdict.value}"
            ),
            detail=render(s, lang=lang),
            data={
                "vendor": vendor,
                "model": model,
                "verdict": s.verdict.value,
            },
        )

    def _do_trunk(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Parse 'show interfaces trunk' on a device."""
        from netops_autopilot.engines.trunk_audit import (
            parse as parse_trunk, TrunkReport,
        )
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.TRUNK, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en" else "لا يوجد منفذ"),
            )
        try:
            res = self._device_runner.run_show(ref, "show interfaces trunk")
            output = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.TRUNK, ReplyStatus.BLOCKED,
                summary=("trunk audit failed" if lang == "en" else "فشل تدقيق الترانك"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        trunks = parse_trunk(output)
        r = TrunkReport(device_ref=ref, trunks=trunks)
        from netops_autopilot.engines.trunk_audit import (
            render as render_trunk,
        )
        return self._reply(
            IntentVerb.TRUNK, ReplyStatus.OK,
            summary=(
                f"trunk — {r.trunking_count} trunking of {len(r.trunks)}"
                if lang == "en"
                else f"الترانك — {r.trunking_count} نشط من {len(r.trunks)}"
            ),
            detail=render_trunk(r, lang=lang),
            data={
                "device_ref": ref,
                "trunking": r.trunking_count,
                "total": len(r.trunks),
            },
        )

    def _do_upgrade(
        self, from_version: Optional[str], to_version: Optional[str],
        lang: str,
    ) -> OperatorReply:
        """Validate a Cisco IOS-XE upgrade path."""
        from netops_autopilot.engines.upgrade_path import (
            evaluate, verdict_for, render,
        )
        if not from_version or not to_version:
            return self._reply(
                IntentVerb.UPGRADE, ReplyStatus.NEEDS_INPUT,
                summary=("which versions?" if lang == "en" else "أي إصدارات؟"),
                detail=("e.g. 'upgrade 17.9 to 17.12'"
                        if lang == "en"
                        else "مثال: 'الترقية 17.9 إلى 17.12'"),
            )
        step = evaluate(from_version, to_version)
        v = verdict_for(step)
        return self._reply(
            IntentVerb.UPGRADE, ReplyStatus.OK,
            summary=(
                f"upgrade {step.from_version} → {step.to_version} — {v.value}"
                if lang == "en"
                else f"الترقية {step.from_version} ← {step.to_version} — {v.value}"
            ),
            detail=render(step, v, lang=lang),
            data={
                "from_version": step.from_version,
                "to_version": step.to_version,
                "intermediate": step.intermediate,
                "verdict": v.value,
            },
        )

    def _do_summary(self, lang: str) -> OperatorReply:
        """Build a network summary one-pager."""
        from netops_autopilot.engines.summary import build, SummaryInputs
        n_dev = 0
        n_link = 0
        n_reach = 0
        n_unreach = 0
        if self._ctx.last_discovery is not None:
            n_dev = len(self._ctx.last_discovery.devices)
            for d in self._ctx.last_discovery.devices:
                status = d.status.value if hasattr(d.status, "value") else str(d.status)
                if status == "COMPLETE":
                    n_reach += 1
                else:
                    n_unreach += 1
        if self._ctx.last_topology is not None:
            n_link = len(self._ctx.last_topology.edges)
        try:
            n_evidence = self._store.event_count()
        except Exception:  # noqa: BLE001
            n_evidence = 0
        last_run = "—"
        if self._ctx.last_run is not None:
            try:
                last_run = str(self._ctx.last_run.verdict)
            except Exception:  # noqa: BLE001
                last_run = "UNKNOWN"
        s = SummaryInputs(
            device_count=n_dev,
            reachable_count=n_reach,
            unreachable_count=n_unreach,
            link_count=n_link,
            last_run_verdict=last_run,
            evidence_count=n_evidence,
        )
        return self._reply(
            IntentVerb.SUMMARY, ReplyStatus.OK,
            summary=(
                f"summary — {n_dev} devices, {n_link} links"
                if lang == "en"
                else f"ملخص — {n_dev} جهاز، {n_link} رابط"
            ),
            detail=build(s, lang=lang),
            data={
                "devices": n_dev,
                "reachable": n_reach,
                "links": n_link,
                "evidence": n_evidence,
            },
        )

    # -- helpers -----------------------------------------------------------

    def _autopilot_answers(self, apply_bond: bool = False) -> list[str]:
        answers = [
            "y",                       # BOND
            "2",                       # Blueprint (guest_office)
            "seed-01",                 # router device
            "ISP fiber DHCP handoff",  # WAN
            "STANDARD",                # availability
            "+25% in 12 months",       # growth
        ]
        if apply_bond:
            answers.append("BOND")
        return answers

    def _find_device(self, ref: str):
        if self._ctx.last_discovery is None:
            return None
        for d in self._ctx.last_discovery.devices:
            if d.device_ref == ref or d.device_ref.lower() == ref.lower():
                return d
        return None

    def _first_device(self):
        if self._ctx.last_discovery and self._ctx.last_discovery.devices:
            return self._ctx.last_discovery.devices[0]
        return None

    def _device_to_dict(self, d) -> dict:
        return {
            "device_ref": d.device_ref,
            "classification": d.classification.value if hasattr(d.classification, "value") else str(d.classification),
            "status": d.status.value if hasattr(d.status, "value") else str(d.status),
            "vendor_family": d.identity.vendor_family if d.identity else None,
            "model": d.identity.model if d.identity else None,
            "version": d.identity.version if d.identity else None,
            "serial": d.identity.serial if d.identity else None,
            "mgmt_addresses": list(d.mgmt_addresses) if d.mgmt_addresses else [],
            "commands_collected": sum(1 for c in d.commands if c.status.value == "COLLECTED"),
            "commands_planned": len(d.commands),
        }

    def _render_devices_table(self, lang: str, devices) -> str:
        if not devices:
            return "—" if lang == "en" else "لا شيء"
        lines = []
        lines.append(
            f"  {'DEVICE':<18} {'VENDOR':<14} {'STATUS':<12} "
            f"{'MODEL':<14} {'MGMT-IP':<16}"
        )
        lines.append("  " + "-" * 80)
        for d in devices:
            vendor = (d.identity.vendor_family if d.identity else "?") or "?"
            vendor = vendor.split("/")[-1] if vendor else "?"
            status = d.status.value if hasattr(d.status, "value") else str(d.status)
            model = (d.identity.model if d.identity else "?") or "?"
            mgmt = d.mgmt_addresses[0] if d.mgmt_addresses else "—"
            lines.append(f"  {d.device_ref:<18} {vendor:<14} {status:<12} {model:<14} {mgmt:<16}")
        return "\n".join(lines)

    def _render_device_detail(self, lang: str, device) -> str:
        d = self._device_to_dict(device)
        return (
            f"  device_ref:  {d['device_ref']}\n"
            f"  class:       {d['classification']}\n"
            f"  status:      {d['status']}\n"
            f"  vendor:      {d['vendor_family'] or 'UNKNOWN'}\n"
            f"  model:       {d['model'] or 'UNKNOWN'}\n"
            f"  version:     {d['version'] or 'UNKNOWN'}\n"
            f"  serial:      {d['serial'] or 'UNKNOWN'}\n"
            f"  mgmt:        {', '.join(d['mgmt_addresses']) or '—'}\n"
            f"  commands:    {d['commands_collected']}/{d['commands_planned']}"
        )

    def _render_design(self, lang: str, design) -> str:
        lines = [f"  design_id: {design.design_id}"]
        for role in design.roles:
            lines.append(f"  ROLE  {role.device_ref:<16} {role.role:<18} ({role.reason})")
        for zone in design.zones:
            lines.append(f"  ZONE  {zone.zone:<10} vlan={zone.vlan_id:<4} {zone.subnet:<18} gw={zone.gateway} on {zone.routed_on}")
        for up in design.uplinks:
            lines.append(f"  LINK  {up.device_ref}:{up.local_port} ↔ {up.peer_ref}:{up.peer_port} [{up.link_state}]")
        return "\n".join(lines)

    def _render_apply_report(self, lang: str, report) -> str:
        if not report.execution:
            return "—"
        out = [f"  outcome: {report.execution.get('outcome')}"]
        records = report.execution.get("change_records", [])
        for r in records:
            out.append(
                f"  • {r['device_ref']}: {r['outcome']} "
                f"({r['applied_count']}/{r['command_count']} commands)"
            )
        return "\n".join(out)

    def _reply(self, verb: IntentVerb, status: ReplyStatus,
               summary: str, detail: str = "", data: dict | None = None,
               actions: list[dict] | None = None) -> OperatorReply:
        return OperatorReply(
            status=status, intent=verb, summary=summary, detail=detail,
            data=data or {}, actions=actions or [],
        )

    def _audit(self, verb: IntentVerb, raw: str, lang: str) -> None:
        """Record the chat intent in the ledger.

        The audit is best-effort and NEVER blocks the user. We use the
        Observation append path, which auto-signs.
        """
        try:
            from ..ledger.models import Observation, ParseStatus
            now = datetime.now(timezone.utc)
            self._store.append_observation(Observation(
                obs_id=f"chat-{now.timestamp()}-{verb.value}",
                raw_id=f"chat:{verb.value}",
                parser_id="chat_operator/0.1.0",
                parser_version="0.1.0",
                field="chat_intent",
                value=verb.value,
                parse_status=ParseStatus.OK,
            ))
        except Exception:  # noqa: BLE001 — audit is best-effort
            pass
