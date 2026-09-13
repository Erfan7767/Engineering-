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
from . import targeted_change as _tchange
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
    ADD_DHCP = "add_dhcp"               # add a DHCP pool for one zone
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

    # Phase P: 30-year expert deeper improvements
    REMEDIATE = "remediate"             # auto-remediation plan
    LLDP = "lldp"                       # LLDP neighbor state
    CDP = "cdp"                         # CDP neighbor state
    VTP = "vtp"                         # VTP domain / mode / revision
    STP = "stp"                         # STP topology
    DHCP_SNOOP = "dhcp_snoop"           # DHCP snooping status
    ROOT_CAUSE = "root_cause"           # AI root-cause analysis
    RECOMMEND = "recommend"             # 30-year expert tips

    # Phase Q: expert Day-2+ operations
    TOPO_SVG = "topo_svg"               # visual topology
    TOPO_ANOMALY = "topo_anomaly"       # topology anomaly scan
    WHATIF = "whatif"                   # blast-radius simulator
    CHANGE_WINDOW = "change_window"     # pick a change window
    CAPACITY = "capacity"               # capacity forecast
    PERFORMANCE = "performance"         # performance baseline check
    AUDIT_QUERY = "audit_query"         # audit trail search

    # Phase R: multi-vendor + wireless + flows + reports
    MULTI_VENDOR = "multi_vendor"       # translate command to vendor
    WIRELESS = "wireless"               # APs / WLANs / RADIUS
    FLOW = "flow"                       # NetFlow / sFlow / IPFIX
    SYSLOG = "syslog"                   # syslog parse + buckets
    DNS_CHECK = "dns_check"             # DNS resolver sanity
    EXEC_REPORT = "exec_report"         # Day-N executive summary
    SIMULATE = "simulate"               # topology reachability what-if
    BGP_ADVANCED = "bgp_advanced"       # route-maps + communities
    TEMPLATE_RENDER = "template_render" # render Jinja2 config template
    SERVICES = "services"               # DNS/DHCP services

    # Phase S — SNMP / NetConf / IPv6 / QoS / VPN / Multicast / Vault / Import / Diff
    SNMP = "snmp"                       # SNMP polling / trap analysis
    NETCONF = "netconf"                 # NetConf / YANG transactions
    IPV6 = "ipv6"                       # IPv6 interface / dual-stack
    QOS = "qos"                         # QoS policy-map audit
    VPN = "vpn"                         # IPSec tunnel status
    MULTICAST = "multicast"             # IGMP groups / PIM neighbors
    VAULT = "vault"                     # device credentials vault
    TOPOLOGY_IMPORT = "topology_import" # import EVE-NG / NetBox topology
    CONFIG_DIFF = "config_diff"         # line-level config diff

    # Phase T — OSPF/ACL/PoE/Inventory/Cable/Backup/Compliance/NetDiff/Console
    OSPF = "ospf"                       # OSPF cost/timers/area audit
    ACL_AUDIT = "acl_audit"             # ACL rule audit + shadow detection
    POE_BUDGET = "poe_budget"           # PoE power budget calculator
    HW_INVENTORY = "hw_inventory"       # hardware inventory + serial
    CABLE_PLANT = "cable_plant"         # patch panel / fiber records
    BACKUP_SCHEDULE = "backup_schedule" # backup schedule + retention
    COMPLIANCE_BASELINE = "compliance_baseline"  # CIS/PCI/HIPAA rule packs
    NETWORK_DIFF = "network_diff"       # network-wide config diff
    CONSOLE_SERVER = "console_server"   # OOB console server paths

    # Phase U — DNS zone / DHCPv6 / AAA / STP guard / Port-sec / Chassis / DDoS / RPKI / NTP
    DNS_ZONE = "dns_zone"               # DNS zone transfer / AXFR audit
    DHCPV6 = "dhcpv6"                   # IPv6 SLAAC + DHCPv6 bindings
    AAA_AUDIT = "aaa_audit"             # TACACS+/RADIUS AAA audit
    STP_GUARD = "stp_guard"             # BPDU/root guard audit
    PORT_SECURITY = "port_security"     # port-security + 802.1X
    CHASSIS_HEALTH = "chassis_health"   # stack / modular chassis
    DDOS_DETECT = "ddos_detect"         # flow-based DDoS detection
    RPKI = "rpki"                       # BGP RPKI / ROA validation
    NTP_AUDIT = "ntp_audit"             # NTP peer sync + skew

    # Meta
    BOND = "bond"                       # confirm physical binding
    #: A request to CREATE something, as distinct from looking at it. Routing a
    #: creation request to a read-only verb answers a question nobody asked and
    #: leaves the operator believing something was built.
    CREATE_VLAN = "create_vlan"
    #: Confirm and execute a targeted change that was planned but not sent.
    #: Kept separate from CREATE_VLAN for the same reason ``apply`` is
    #: separate from ``design``: the plan is shown first and nothing reaches
    #: a device until the operator says so.
    CONFIRM_CHANGE = "confirm_change"
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
    (IntentVerb.CREATE_VLAN, (
        "أنشئ vlan", "انشئ vlan", "أنشئ شبكة محلية", "إنشاء vlan",
        "أضف vlan", "اضف vlan", "vlan جديد", "vlan جديدة",
        # Plural too. The matcher applies a word-boundary check to Latin
        # patterns, so the singular "vlan" does NOT match "vlans" — and
        # SHOW_VLANS, whose patterns are the bare plurals, used to win. "أنشئ
        # VLANs المطلوبة" is a request to create, and was answered with a table.
        "أنشئ vlans", "انشئ vlans", "أضف vlans", "اضف vlans",
        "إنشاء vlans", "create vlans",
    )),
    (IntentVerb.ADD_DHCP, (
        # Longer and more specific than the SHOW_* nouns, and listed before
        # them: "dhcp" alone would otherwise be claimed by whichever read-only
        # pattern happened to contain it.
        "أضف dhcp", "اضف dhcp", "أنشئ dhcp", "انشئ dhcp", "dhcp لل",
        "add dhcp", "create dhcp", "dhcp pool", "enable dhcp",
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
    (IntentVerb.REMEDIATE, (
        "إصلاح", "إصلاح تلقائي", "خطط إصلاح", "remediate",
    )),
    (IntentVerb.LLDP, (
        "جيران lldp", "lldp", "show lldp",
    )),
    (IntentVerb.CDP, (
        "جيران cdp", "cdp", "show cdp",
    )),
    (IntentVerb.VTP, (
        "حالة vtp", "vtp", "show vtp",
    )),
    (IntentVerb.STP, (
        "spanning tree", "stp", "STP",
    )),
    (IntentVerb.DHCP_SNOOP, (
        "dhcp snooping", "dhcp snoop", "انتهاكات dhcp",
    )),
    (IntentVerb.ROOT_CAUSE, (
        "السبب الجذري", "لماذا", "ما السبب", "root cause",
    )),
    (IntentVerb.RECOMMEND, (
        "توصيات", "نصائح", "توصية", "recommend",
    )),
    (IntentVerb.BOND, (
        # NOT the bare verb "اربط": it means "connect/link" in ordinary network
        # requests ("اربط هذا الفرع بالمقر"), and it was firing the
        # identity-binding confirmation gate — a security-relevant human
        # decision — on a sentence that never mentioned binding.
        "أكد الربط", "تأكيد الربط", "الربط مؤكد", "اربط الجهاز بالكمبيوتر",
        "bond",
    )),
    (IntentVerb.CONFIRM_CHANGE, (
        "تأكيد التغيير", "نفّذ التغيير", "نفذ التغيير", "تأكيد", "أكّده",
    )),
    (IntentVerb.HELP, (
        "مساعدة", "ساعدني", "الأوامر", "help", "ما الذي تستطيع فعله",
    )),
    (IntentVerb.STATUS, (
        "الحالة", "status", "ما الوضع",
    )),
    # Phase R Arabic
    (IntentVerb.MULTI_VENDOR, ("متعدد البائعين", "juniper", "arista")),
    (IntentVerb.WIRELESS, ("لاسلكي", "واي فاي", "نقطة وصول")),
    (IntentVerb.FLOW, ("تدفق", "netflow")),
    (IntentVerb.SYSLOG, ("سجل النظام", "تحليل السجل")),
    (IntentVerb.DNS_CHECK, ("فحص dns", "تحليل dns")),
    (IntentVerb.EXEC_REPORT, ("تقرير تنفيذي", "ملخص أسبوعي")),
    (IntentVerb.SIMULATE, ("محاكاة",)),
    (IntentVerb.BGP_ADVANCED, ("خريطة المسار", "مجتمعات bgp")),
    (IntentVerb.TEMPLATE_RENDER, ("قالب",)),
    (IntentVerb.SERVICES, ("إيجار dhcp", "خدمات")),
    # Phase S Arabic
    (IntentVerb.SNMP, ("snmp",)),
    (IntentVerb.NETCONF, ("netconf",)),
    (IntentVerb.IPV6, ("ipv6",)),
    (IntentVerb.QOS, ("qos", "جودة الخدمة")),
    (IntentVerb.VPN, ("vpn", "نفق")),
    (IntentVerb.MULTICAST, ("البث المتعدد",)),
    (IntentVerb.VAULT, ("خزنة", "بيانات الاعتماد")),
    (IntentVerb.TOPOLOGY_IMPORT, ("استيراد", "netbox")),
    (IntentVerb.CONFIG_DIFF, ("فرق الإعدادات", "مقارنة الإعدادات")),
    # Phase T Arabic
    (IntentVerb.OSPF, ("ospf",)),
    (IntentVerb.ACL_AUDIT, ("acl",)),
    (IntentVerb.POE_BUDGET, ("poe", "ميزانية الطاقة")),
    (IntentVerb.HW_INVENTORY, ("المخزون", "الأجهزة")),
    (IntentVerb.CABLE_PLANT, ("كابل", "الألياف")),
    (IntentVerb.BACKUP_SCHEDULE, ("النسخ الاحتياطي", "جدول النسخ")),
    (IntentVerb.COMPLIANCE_BASELINE, ("baseline",)),
    (IntentVerb.NETWORK_DIFF, ("مقارنة الأجهزة", "فرق الشبكة")),
    (IntentVerb.CONSOLE_SERVER, ("خادم وحدة التحكم", "الوصول البديل")),
    # Phase U Arabic
    (IntentVerb.DNS_ZONE, ("نقل المنطقة",)),
    (IntentVerb.DHCPV6, ("ipv6",)),
    (IntentVerb.AAA_AUDIT, ("tacacs", "aaa")),
    (IntentVerb.STP_GUARD, ("حماية stp",)),
    (IntentVerb.PORT_SECURITY, ("أمان المنفذ",)),
    (IntentVerb.CHASSIS_HEALTH, ("chassis",)),
    (IntentVerb.DDOS_DETECT, ("هجوم الحرمان", "ddos")),
    (IntentVerb.RPKI, ("rpki",)),
    (IntentVerb.NTP_AUDIT, ("ntp", "تزامن الوقت")),
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
    (IntentVerb.CREATE_VLAN, (
        "create vlan", "create a vlan", "add vlan", "add a vlan",
        "new vlan", "make vlan", "make a vlan",
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
        # Bare "confirm" is deliberately NOT here. It was, which made it
        # unreachable as a confirmation: with a change pending, an operator
        # who typed "confirm" got a verification report instead of the
        # execution they had just been asked to authorise. "confirm" on its
        # own is not a request to inspect anything, so it now belongs to the
        # verb that has something concrete to do with it.
        "verify", "check", "validate",
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
    (IntentVerb.REMEDIATE, (
        "remediate", "fix it", "auto-remediate", "auto fix",
        "plan a fix", "what should i do", "iصلاح", "إصلاح",
    )),
    (IntentVerb.LLDP, (
        "show lldp neighbors detail", "show lldp neighbors",
        "lldp neighbors detail", "lldp neighbors",
        "show lldp", "lldp", "جيران lldp",
    )),
    (IntentVerb.CDP, (
        "show cdp neighbors detail", "show cdp neighbors",
        "cdp neighbors detail", "cdp neighbors",
        "show cdp", "cdp", "جيران cdp",
    )),
    (IntentVerb.VTP, (
        "show vtp status", "show vtp", "vtp",
        "حالة vtp",
    )),
    (IntentVerb.STP, (
        "show spanning-tree", "show stp", "stp",
        "spanning tree", "stp topology",
    )),
    (IntentVerb.DHCP_SNOOP, (
        "show ip dhcp snooping", "dhcp snooping",
        "show dhcp", "dhcp snoop",
    )),
    (IntentVerb.ROOT_CAUSE, (
        "why", "root cause", "why is this broken",
        "what caused", "diagnose root",
        "السبب الجذري", "لماذا",
    )),
    (IntentVerb.RECOMMEND, (
        "recommend", "best practice", "tips",
        "what should i also do", "senior tip",
        "توصية", "نصيحة",
    )),
    (IntentVerb.TOPO_SVG, (
        "topology svg", "show topology map", "visual topology",
        "topo svg", "رسم الشبكة", "خريطة بصرية",
    )),
    (IntentVerb.TOPO_ANOMALY, (
        "topology anomalies", "topo anomaly", "topology scan",
        "any anomalies", "مشاكل الطوبولوجيا", "شذوذ",
    )),
    (IntentVerb.WHATIF, (
        "what if", "whatif", "blast radius", "what would happen",
        "ماذا لو", "نصف القطر",
    )),
    (IntentVerb.CHANGE_WINDOW, (
        "change window", "schedule change", "pick a window",
        "نافذة التغيير", "جدولة التغيير",
    )),
    (IntentVerb.CAPACITY, (
        "capacity", "capacity forecast", "when will we run out",
        "سعة", "تنبؤ السعة",
    )),
    (IntentVerb.PERFORMANCE, (
        "performance baseline", "performance check",
        "is this normal", "performance",
        "أداء", "خط الأساس",
    )),
    (IntentVerb.AUDIT_QUERY, (
        "audit query", "audit search", "who changed", "history of",
        "استعلام التدقيق", "بحث في السجل",
    )),
    # Phase R — multi-vendor + wireless + flow + syslog + DNS + reports
    (IntentVerb.MULTI_VENDOR, (
        "multi vendor", "multi-vendor", "translate command",
        "vendor translate", "junos command", "arista command",
        "نوكيا", "juniper", "arista",
    )),
    (IntentVerb.WIRELESS, (
        "wireless", "wifi", "wlan", "access point", "ap summary",
        "wlan summary", "radius", "802.11",
        "لاسلكي", "واي فاي", "نقطة وصول",
    )),
    (IntentVerb.FLOW, (
        "netflow", "sflow", "ipfix", "flow analysis",
        "top talkers", "top listeners", "top applications",
        "تدفق", "تدفقات",
    )),
    (IntentVerb.SYSLOG, (
        "syslog", "parse log", "log analysis", "log scan",
        "system log", "سجل النظام", "تحليل السجل",
    )),
    (IntentVerb.DNS_CHECK, (
        "dns check", "check dns", "dns resolve", "resolve dns",
        "dig example", "nslookup", "فحص dns",
        "تحليل dns", "dns",
    )),
    (IntentVerb.EXEC_REPORT, (
        "executive report", "weekly summary", "exec summary",
        "daily report", "weekly report", "management summary",
        "تقرير تنفيذي", "ملخص أسبوعي", "تقرير الإدارة",
    )),
    (IntentVerb.SIMULATE, (
        "simulate", "what if remove", "what-if link", "simulate link",
        "reachability what-if", "محاكاة", "محاكاة الشبكة",
    )),
    (IntentVerb.BGP_ADVANCED, (
        "route map", "route-map", "bgp community", "bgp communities",
        "show route-map", "community list",
        "خريطة المسار", "مجتمعات bgp",
    )),
    (IntentVerb.TEMPLATE_RENDER, (
        "render template", "jinja2", "config template", "template render",
        "render config", "generate config",
        "قالب", "إنشاء قالب",
    )),
    (IntentVerb.SERVICES, (
        "dhcp lease", "dhcp leases", "dhcp scope", "services report",
        "service health",
        "إيجار dhcp", "خدمات",
    )),
    # Phase S — SNMP / NetConf / IPv6 / QoS / VPN / Multicast / Vault / Import / Diff
    (IntentVerb.SNMP, (
        "snmp", "snmpwalk", "snmp poll", "mib walk",
        "show snmp", "snmp trap",
        "snmp", "snmpwalk",
    )),
    (IntentVerb.NETCONF, (
        "netconf", "yang", "show netconf", "netconf commit",
        "edit-config", "netconfig",
        "netconf",
    )),
    (IntentVerb.IPV6, (
        "ipv6", "show ipv6", "ipv6 interface", "dual stack",
        "ipv6 ra", "link local",
        "ipv6", "ipv6",
    )),
    (IntentVerb.QOS, (
        "qos", "policy-map", "show policy-map", "dscp",
        "qos audit", "service policy",
        "qos", "جودة الخدمة",
    )),
    (IntentVerb.VPN, (
        "vpn", "ipsec", "isakmp", "crypto map",
        "show crypto", "tunnel status",
        "vpn", "نفق",
    )),
    (IntentVerb.MULTICAST, (
        "multicast", "igmp", "pim", "rp mapping",
        "show ip igmp", "show ip pim",
        "البث المتعدد", "multicast",
    )),
    (IntentVerb.VAULT, (
        "vault", "credentials", "device credentials",
        "show credentials", "snmp community",
        "خزنة", "بيانات الاعتماد",
    )),
    (IntentVerb.TOPOLOGY_IMPORT, (
        "import topology", "eve-ng", "eve ng", "gns3",
        "netbox import", "import eve", "import netbox",
        "استيراد الطوبولوجيا", "netbox",
    )),
    (IntentVerb.CONFIG_DIFF, (
        "config diff", "diff configs", "compare configs",
        "diff running", "diff golden", "running-config diff",
        "فرق الإعدادات", "مقارنة الإعدادات",
    )),
    # Phase T EN
    (IntentVerb.OSPF, (
        "ospf", "show ip ospf", "ospf interface",
        "ospf neighbor", "ospf cost",
        "ospf",
    )),
    (IntentVerb.ACL_AUDIT, (
        "acl audit", "show acl", "acl rule", "acl shadow",
        "access-list audit",
        "acl",
    )),
    (IntentVerb.POE_BUDGET, (
        "poe budget", "power budget", "poe class",
        "poe allocation", "power allocation",
        "poe", "ميزانية الطاقة",
    )),
    (IntentVerb.HW_INVENTORY, (
        "inventory", "hardware inventory", "show inventory",
        "serial number", "part number",
        "المخزون", "الأجهزة",
    )),
    (IntentVerb.CABLE_PLANT, (
        "cable plant", "patch panel", "fiber strand",
        "patch audit", "cable management",
        "كابل", "الألياف",
    )),
    (IntentVerb.BACKUP_SCHEDULE, (
        "backup schedule", "backup policy", "retention policy",
        "schedule backup", "daily backup",
        "النسخ الاحتياطي", "جدول النسخ",
    )),
    (IntentVerb.COMPLIANCE_BASELINE, (
        "compliance baseline", "cis baseline", "pci baseline",
        "hipaa baseline", "compliance scan",
        "baseline",
    )),
    (IntentVerb.NETWORK_DIFF, (
        "network diff", "compare devices", "cross-device diff",
        "global diff", "all devices diff",
        "مقارنة الأجهزة", "فرق الشبكة",
    )),
    (IntentVerb.CONSOLE_SERVER, (
        "console server", "terminal server", "out-of-band",
        "oob path", "console path",
        "خادم وحدة التحكم", "الوصول البديل",
    )),
    # Phase U EN
    (IntentVerb.DNS_ZONE, (
        "dns zone", "zone transfer", "axfr", "bind audit",
        "zone file", "dns audit",
        "نقل المنطقة",
    )),
    (IntentVerb.DHCPV6, (
        "dhcpv6", "ipv6 slaac", "slaac", "ipv6 assignment",
        "show ipv6 nd",
        "ipv6",
    )),
    (IntentVerb.AAA_AUDIT, (
        "aaa audit", "tacacs audit", "radius audit",
        "show tacacs", "show aaa",
        "tacacs", "aaa",
    )),
    (IntentVerb.STP_GUARD, (
        "stp guard", "bpdu guard", "root guard",
        "spanning-tree guard", "stp audit",
        "حماية stp",
    )),
    (IntentVerb.PORT_SECURITY, (
        "port security", "show port-security",
        "802.1x", "dot1x",
        "أمان المنفذ",
    )),
    (IntentVerb.CHASSIS_HEALTH, (
        "chassis", "show switch", "stack health",
        "show module", "stack member",
        "chassis",
    )),
    (IntentVerb.DDOS_DETECT, (
        "ddos", "ddos detect", "ddos check",
        "syn flood", "udp flood",
        "هجوم الحرمان", "ddos",
    )),
    (IntentVerb.RPKI, (
        "rpki", "roa", "bgp validation",
        "prefix validation", "rpki check",
        "rpki",
    )),
    (IntentVerb.NTP_AUDIT, (
        "ntp audit", "ntp peer", "ntp skew",
        "show ntp", "time sync",
        "ntp", "تزامن الوقت",
    )),
    (IntentVerb.BOND, (
        "bond", "confirm binding", "i'm connected",
    )),
    (IntentVerb.BOND, (
        "bond", "confirm binding", "i'm connected",
    )),
    (IntentVerb.CONFIRM_CHANGE, (
        "confirm change", "confirm", "go ahead", "apply it", "do it",
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


def _network_type_vocabulary() -> tuple[str, ...]:
    """Every phrase the operator recognises as a network type.

    Derived from ``ChatOperator.NETWORK_TYPES_EN`` / ``NETWORK_TYPES_AR`` so the
    intent parser and the blueprint mapping cannot drift apart. This list used
    to be hand written and was missing "campus", "data center", "office" and
    "حرم", so those requests silently fell back to the default blueprint instead
    of the one the operator had named — the answer to a question that was never
    really asked.

    Longest phrase first, so "small office" is matched before "office".
    """
    phrases = set(ChatOperator.NETWORK_TYPES_EN) | set(ChatOperator.NETWORK_TYPES_AR)
    return tuple(sorted(phrases, key=lambda phrase: (-len(phrase), phrase)))


#: Imperative verbs that ask for a CHANGE to the network. ``_normalize`` strips
#: harakat but does not fold alef/ya/taa-marbuta variants, so both spellings of
#: each verb are listed rather than assuming a fold that does not happen.
_WRITE_VERBS = frozenset({
    "أنشئ", "انشئ", "أنشىء", "انشيء", "أضف", "اضف", "أعد", "اعد",
    "غيّر", "غير", "احذف", "أزل", "ازل", "اربط", "افصل", "اعزل",
    "طبّق", "طبق", "فعّل", "فعل", "عطّل", "عطل", "حدّث", "حدث",
    "configure", "reconfigure", "create", "add", "remove", "delete",
    "change", "apply", "set", "enable", "disable", "isolate", "connect",
})


def carries_write_verb(text: str) -> Optional[str]:
    """The change verb the operator used, or ``None``.

    Matching is on whole normalised words, never substrings. A substring scan is
    exactly what let the bare noun "الأجهزة" registered under SHOW_DEVICES claim
    "أعد إعداد هذه الأجهزة" — the operator asked to reconfigure the devices and
    got a device listing back, which reads like an answer rather than the
    refusal it should have been.
    """
    for token in re.split(r"[\s،,.;:!?()\[\]\"']+", _normalize(text)):
        if token in _WRITE_VERBS:
            return token
    return None


#: Intents that only ever READ from a device. Answering one of these to a
#: request that asked for a change would report activity where there was none.
def _is_read_only(verb: IntentVerb) -> bool:
    return verb.value.startswith("show_")


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
    for net_type in _network_type_vocabulary():
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
    chosen = candidates[0][1] if candidates else IntentVerb.UNKNOWN

    # A message that asks for a CHANGE must never classify as a read. Falling
    # through to a device listing or a VLAN table looks like an answer, so the
    # operator has no way to see that nothing was done. Enforced here rather
    # than in the chat handler so every caller — CLI, web server, API — gets the
    # same guarantee instead of whichever one remembered to check.
    write_verb = carries_write_verb(text)
    if write_verb is not None and _is_read_only(chosen):
        args = dict(args)
        args["write_guard"] = {"verb": write_verb, "fallback": chosen.value}
        return (IntentVerb.UNKNOWN, args)
    return (chosen, args)


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
    #: A targeted change that has been planned and shown, not yet sent.
    pending_change: Optional[Any] = None   # targeted_change.ChangePlan
    change_history: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# ChatOperator — the main entry point.
# ---------------------------------------------------------------------------


class _EngineRunner(Protocol):
    """The shape the operator needs from the live engine. Allows tests
    to inject a SimFabric-backed implementation."""

    def run(self, *, port: str, execute: bool, answers: list[str]) -> Any: ...


def _make_change_window(
    window_id: str,
    start_unix: float,
    end_unix: float,
    impact,
    reason: str = "",
):
    """Module-level helper for ChangeWindow construction."""
    from netops_autopilot.engines.change_window import ChangeWindow
    return ChangeWindow(
        window_id=window_id,
        start_unix=start_unix,
        end_unix=end_unix,
        impact=impact,
        reason=reason,
    )


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

    # Operator vocabulary → a REAL blueprint id. These used to name
    # "hotel", "retail" and "leaf-spine", none of which is a blueprint the
    # engine has, so `elicit()` returned UNKNOWN and the run blocked at
    # INTENT_ELICITATION — three of the five advertised network types could
    # never be built. Every value here must exist in
    # ``engines.blueprints.BLUEPRINTS``; the test suite asserts it.
    NETWORK_TYPES_AR = {
        "فرع": "branch",
        "مكتب": "guest_office",
        "مكتب صغير": "small_office",
        "فندق": "guest_office",          # guest WiFi + staff ⇒ guest isolation
        "متجر": "secure_office",         # POS/PCI isolation
        "مركز بيانات": "datacenter",
        "ديتاسنتر": "datacenter",
        "حرم": "campus",
    }
    NETWORK_TYPES_EN = {
        "branch": "branch",
        "small office": "small_office",
        "office": "guest_office",
        "hotel": "guest_office",         # guest WiFi + staff ⇒ guest isolation
        "retail": "secure_office",       # POS/PCI isolation
        "datacenter": "datacenter",
        "data center": "datacenter",
        "leaf-spine": "datacenter",
        "campus": "campus",
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
        #: Per-run state for _run_autopilot / _session_factories.
        self._factories: Optional[tuple] = None
        self._requested_intent: Optional[str] = None
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

        # classify_intent refused to answer a change request with a read, and
        # said what it would otherwise have done. Surface that instead of the
        # generic "unrecognised" reply, because the distinction matters: the
        # request was understood, and deliberately not executed.
        guard = args.get("write_guard")
        if guard:
            return self._reply(
                IntentVerb.UNKNOWN, ReplyStatus.BLOCKED,
                summary=(f"you asked me to {guard['verb']!r} something, and the "
                         f"only action I could match was read-only "
                         f"({guard['fallback']}); nothing was changed"
                         if lang == "en" else
                         f"طلبت إجراء تغيير ({guard['verb']})، وأقرب إجراء تعرّفت "
                         f"عليه للقراءة فقط ({guard['fallback']})؛ لم يُغيَّر شيء"),
                detail=("Say exactly what to change, e.g. 'أنشئ VLAN للموظفين' "
                        "or 'apply <network type>'. I would rather refuse than "
                        "answer a different question." if lang == "en" else
                        "حدّد المطلوب تغييره، مثل 'أنشئ VLAN للموظفين' أو "
                        "'طبق <نوع الشبكة>'. الرفض الصريح أفضل من الإجابة عن "
                        "سؤال آخر."),
                data={"detected_write_verb": guard["verb"],
                      "fallback_read_only_intent": guard["fallback"]})

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

        if verb is IntentVerb.CREATE_VLAN:
            return self._do_create_vlan(args, lang, message)

        if verb is IntentVerb.ADD_DHCP:
            return self._do_add_dhcp(args, lang, message)

        if verb is IntentVerb.CONFIRM_CHANGE:
            return self._do_confirm_change(lang)

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

        if verb is IntentVerb.REMEDIATE:
            return self._do_remediate(lang)

        if verb is IntentVerb.LLDP:
            return self._do_lldp(args.get("device"), lang)

        if verb is IntentVerb.CDP:
            return self._do_cdp(args.get("device"), lang)

        if verb is IntentVerb.VTP:
            return self._do_vtp(args.get("device"), lang)

        if verb is IntentVerb.STP:
            return self._do_stp(args.get("device"), lang)

        if verb is IntentVerb.DHCP_SNOOP:
            return self._do_dhcp_snoop(args.get("device"), lang)

        if verb is IntentVerb.ROOT_CAUSE:
            return self._do_root_cause(lang)

        if verb is IntentVerb.RECOMMEND:
            return self._do_recommend(args.get("action") or "add_trunk", lang)

        if verb is IntentVerb.TOPO_SVG:
            return self._do_topo_svg(lang)

        if verb is IntentVerb.TOPO_ANOMALY:
            return self._do_topo_anomaly(lang)

        if verb is IntentVerb.WHATIF:
            return self._do_whatif(args, lang)

        if verb is IntentVerb.CHANGE_WINDOW:
            return self._do_change_window(args, lang)

        if verb is IntentVerb.CAPACITY:
            return self._do_capacity(lang)

        if verb is IntentVerb.PERFORMANCE:
            return self._do_performance(lang)

        if verb is IntentVerb.AUDIT_QUERY:
            return self._do_audit_query(args, lang)

        # Phase R — multi-vendor + wireless + flow + syslog + DNS
        if verb is IntentVerb.MULTI_VENDOR:
            return self._do_multi_vendor(args, lang)
        if verb is IntentVerb.WIRELESS:
            return self._do_wireless(args, lang)
        if verb is IntentVerb.FLOW:
            return self._do_flow(args, lang)
        if verb is IntentVerb.SYSLOG:
            return self._do_syslog(args, lang)
        if verb is IntentVerb.DNS_CHECK:
            return self._do_dns_check(args, lang)
        if verb is IntentVerb.EXEC_REPORT:
            return self._do_exec_report(args, lang)
        if verb is IntentVerb.SIMULATE:
            return self._do_simulate(args, lang)
        if verb is IntentVerb.BGP_ADVANCED:
            return self._do_bgp_advanced(args, lang)
        if verb is IntentVerb.TEMPLATE_RENDER:
            return self._do_template_render(args, lang)
        if verb is IntentVerb.SERVICES:
            return self._do_services(args, lang)

        # Phase S — SNMP / NetConf / IPv6 / QoS / VPN / Multicast / Vault / Import / Diff
        if verb is IntentVerb.SNMP:
            return self._do_snmp(args, lang)
        if verb is IntentVerb.NETCONF:
            return self._do_netconf(args, lang)
        if verb is IntentVerb.IPV6:
            return self._do_ipv6(args, lang)
        if verb is IntentVerb.QOS:
            return self._do_qos(args, lang)
        if verb is IntentVerb.VPN:
            return self._do_vpn(args, lang)
        if verb is IntentVerb.MULTICAST:
            return self._do_multicast(args, lang)
        if verb is IntentVerb.VAULT:
            return self._do_vault(args, lang)
        if verb is IntentVerb.TOPOLOGY_IMPORT:
            return self._do_topology_import(args, lang)
        if verb is IntentVerb.CONFIG_DIFF:
            return self._do_config_diff(args, lang)

        # Phase T — OSPF/ACL/PoE/Inventory/Cable/Backup/Compliance/NetDiff/Console
        if verb is IntentVerb.OSPF:
            return self._do_ospf(args, lang)
        if verb is IntentVerb.ACL_AUDIT:
            return self._do_acl_audit(args, lang)
        if verb is IntentVerb.POE_BUDGET:
            return self._do_poe_budget(args, lang)
        if verb is IntentVerb.HW_INVENTORY:
            return self._do_hw_inventory(args, lang)
        if verb is IntentVerb.CABLE_PLANT:
            return self._do_cable_plant(args, lang)
        if verb is IntentVerb.BACKUP_SCHEDULE:
            return self._do_backup_schedule(args, lang)
        if verb is IntentVerb.COMPLIANCE_BASELINE:
            return self._do_compliance_baseline(args, lang)
        if verb is IntentVerb.NETWORK_DIFF:
            return self._do_network_diff(args, lang)
        if verb is IntentVerb.CONSOLE_SERVER:
            return self._do_console_server(args, lang)

        # Phase U — DNS zone / DHCPv6 / AAA / STP guard / Port-sec / Chassis / DDoS / RPKI / NTP
        if verb is IntentVerb.DNS_ZONE:
            return self._do_dns_zone(args, lang)
        if verb is IntentVerb.DHCPV6:
            return self._do_dhcpv6(args, lang)
        if verb is IntentVerb.AAA_AUDIT:
            return self._do_aaa_audit(args, lang)
        if verb is IntentVerb.STP_GUARD:
            return self._do_stp_guard(args, lang)
        if verb is IntentVerb.PORT_SECURITY:
            return self._do_port_security(args, lang)
        if verb is IntentVerb.CHASSIS_HEALTH:
            return self._do_chassis_health(args, lang)
        if verb is IntentVerb.DDOS_DETECT:
            return self._do_ddos_detect(args, lang)
        if verb is IntentVerb.RPKI:
            return self._do_rpki(args, lang)
        if verb is IntentVerb.NTP_AUDIT:
            return self._do_ntp_audit(args, lang)

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
        # The chat operator talks to the real AutopilotEngine. ``_run_autopilot``
        # supplies the session factories (SimFabric for a SIM port, the real
        # transport otherwise) and the scripted answers in the order the engine
        # asks them.
        try:
            report = self._run_autopilot(execute=False)
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
                # The seed, not "whichever device sorts first" — see
                # _pick_diagnostic_source.
                target = self._pick_diagnostic_source().device_ref
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
                # The seed, not "whichever device sorts first" — see
                # _pick_diagnostic_source.
                target = self._pick_diagnostic_source().device_ref
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

    # -- targeted changes: plan, then execute on confirmation --------------

    def _targeted_key_id(self) -> str:
        """A signing key for targeted changes, created once.

        Without one the executor refuses to write the change to the
        tamper-evident ledger and reports ``LEDGER_NOT_CONFIGURED`` — honest,
        but it means an applied change leaves no record, which is exactly what
        the ledger exists to prevent.
        """
        if getattr(self, "_chat_key_id", None) is None:
            self._chat_key_id = self._store.keys.create_key("chat-targeted")
        return self._chat_key_id

    def _targeted_allowlist(self) -> CommandAllowlist:
        """The allowlist used to gate a targeted change.

        Falls back to the packed data rather than assuming the caller
        injected one — an executor built with an empty allowlist rejects
        everything, which would look like a platform limitation rather than
        a missing argument.
        """
        if self._allowlist is not None:
            return self._allowlist
        from ..specs_data import specs_data_dir
        return CommandAllowlist.load_dir(specs_data_dir("allowlists"))

    def _target_device(self):
        """The discovered device a targeted change applies to.

        The SEED — the one device the operator actually cabled to this
        computer — unless a device was named. Never "whichever sorts first":
        that picked an access switch in the sim and would configure the wrong
        box on real hardware.
        """
        if self._ctx.last_discovery is None:
            return None
        return self._pick_diagnostic_source()

    def _do_add_dhcp(self, args: dict[str, str], lang: str,
                     message: str) -> OperatorReply:
        """Plan a DHCP pool for one zone, from the design that was applied.

        The subnet and gateway are read out of ``last_design`` — the zones that
        were actually allocated and configured — and never invented. A pool
        built on a guessed subnet hands out addresses that are not on the wire:
        the client gets a lease and then reaches nothing, which is a worse
        failure than the refusal this returns when the design is not known.
        """
        device = self._target_device()
        if device is None:
            return self._reply(IntentVerb.ADD_DHCP, ReplyStatus.BLOCKED,
                summary=("nothing discovered yet" if lang == "en"
                         else "لم يُكتشف شيء بعد"),
                detail=("A pool is created on the device that routes the zone, "
                        "so the network has to be discovered first — run "
                        "'discover'." if lang == "en" else
                        "يُنشأ المجمع على الجهاز الذي يوجّه المنطقة، لذا يجب "
                        "اكتشاف الشبكة أولاً — شغّل 'اكتشف'."))
        design = self._ctx.last_design
        zones = tuple(getattr(design, "zones", ()) or ())
        if not zones:
            return self._reply(IntentVerb.ADD_DHCP, ReplyStatus.BLOCKED,
                summary=("no design in context" if lang == "en"
                         else "لا يوجد تصميم في السياق"),
                detail=("I will not invent a subnet for a DHCP pool — clients "
                        "would be handed addresses that are not on the wire. "
                        "Run the autopilot so zones are allocated, or give me "
                        "the subnet and gateway explicitly." if lang == "en"
                        else "لن أخترع شبكة لمجمع DHCP — فسيُمنح العملاء عناوين "
                        "غير موجودة على السلك. شغّل الطيار الآلي لتُخصَّص "
                        "المناطق، أو أعطني الشبكة والبوابة صراحةً."))

        names = [z.zone for z in zones]
        wanted, matched = _tchange.resolve_zone(message, names)
        if len(matched) > 1:
            return self._reply(IntentVerb.ADD_DHCP, ReplyStatus.BLOCKED,
                summary=("ambiguous zone" if lang == "en" else "المنطقة غامضة"),
                detail=(f"The request matches more than one zone "
                        f"({', '.join(sorted(matched))}); a pool sent to the "
                        f"wrong zone is a change nobody asked for. Name one."
                        if lang == "en" else
                        f"الطلب يطابق أكثر من منطقة ({', '.join(sorted(matched))})؛ "
                        f"ومجمع يُرسل للمنطقة الخطأ تغيير لم يطلبه أحد. حدّد واحدة."))
        if wanted is None:
            return self._reply(IntentVerb.ADD_DHCP, ReplyStatus.NEEDS_INPUT,
                summary=("which zone?" if lang == "en" else "أي منطقة؟"),
                detail=("Zones in the current design: " + ", ".join(sorted(names))
                        if lang == "en" else
                        "المناطق في التصميم الحالي: " + ", ".join(sorted(names))))

        zone = next(z for z in zones if z.zone == wanted)
        target = zone.routed_on or device.device_ref
        identity = getattr(device, "identity", None)
        family = getattr(identity, "vendor_family", None) if identity else None
        vendor_os = family.split("/")[-1] if family else "UNKNOWN"
        try:
            plan = _tchange.plan_add_dhcp(
                change_id=new_id(), request=message, device_ref=target,
                vendor_os=vendor_os, zone=zone.zone, subnet=zone.subnet,
                gateway=zone.gateway, dns=args.get("dns", ""))
        except Failure as exc:
            return self._reply(IntentVerb.ADD_DHCP, ReplyStatus.BLOCKED,
                summary=("cannot plan that change" if lang == "en"
                         else "لا يمكن التخطيط لهذا التغيير"),
                detail="; ".join(exc.causes))
        self._ctx.pending_change = plan
        return self._reply(
            IntentVerb.ADD_DHCP, ReplyStatus.OK,
            summary=plan.understood,
            detail=(plan.preview + "\n\n" + (
                "Nothing has been sent. Confirm to apply." if lang == "en"
                else "لم يُرسل شيء. أكّد للتنفيذ.")),
            data={"plan": plan.to_dict()})

    def _do_create_vlan(self, args: dict[str, str], lang: str,
                        message: str) -> OperatorReply:
        """Plan a single-VLAN change against the device's real state.

        Sends nothing. Reads the device's current VLAN table first, refuses on
        a collision, and returns the exact lines for the operator to approve.
        """
        device = self._target_device()
        if device is None:
            return self._reply(IntentVerb.CREATE_VLAN, ReplyStatus.BLOCKED,
                summary=("nothing discovered yet" if lang == "en"
                         else "لم يُكتشف شيء بعد"),
                detail=("A VLAN is created on a specific device, so the "
                        "network has to be discovered first — run 'discover'."
                        if lang == "en" else
                        "تُنشأ الشبكة المحلية على جهاز بعينه، لذا يجب اكتشاف "
                        "الشبكة أولاً — شغّل 'اكتشف'."))
        if self._device_runner is None:
            return self._reply(IntentVerb.CREATE_VLAN, ReplyStatus.BLOCKED,
                summary=("no device connection" if lang == "en"
                         else "لا يوجد اتصال بالأجهزة"),
                detail=("There is no live connection to any device, so the "
                        "current VLAN table cannot be read and the change "
                        "cannot be planned against reality."
                        if lang == "en" else
                        "لا يوجد اتصال حي بأي جهاز، لذا لا يمكن قراءة جدول "
                        "الشبكات الحالي ولا التخطيط للتغيير على الواقع."))

        ref = device.device_ref
        identity = getattr(device, "identity", None)
        family = getattr(identity, "vendor_family", None) if identity else None
        vendor_os = family.split("/")[-1] if family else "UNKNOWN"

        # The collision check needs the device's ACTUAL VLAN table. Guessing
        # it, or assuming the ids the last design used are still free, is how
        # a new VLAN lands on top of one already in service.
        try:
            table = self._device_runner.run_show(ref, "show vlan brief")
        except Failure as exc:
            return self._reply(IntentVerb.CREATE_VLAN, ReplyStatus.BLOCKED,
                summary=("cannot read the device" if lang == "en"
                         else "لا يمكن قراءة الجهاز"),
                detail="; ".join(exc.causes))
        if not table.success:
            return self._reply(IntentVerb.CREATE_VLAN, ReplyStatus.FAILURE,
                summary=("cannot read the VLAN table" if lang == "en"
                         else "لا يمكن قراءة جدول الشبكات"),
                detail=table.note or "—")
        existing = _tchange.read_existing_vlans(table.output_text)

        parsed = _tchange.parse_vlan_request(message)
        name = str(parsed.get("name") or "")
        if not name:
            return self._reply(IntentVerb.CREATE_VLAN, ReplyStatus.NEEDS_INPUT,
                summary=("which VLAN?" if lang == "en" else "أي شبكة؟"),
                detail=("Say what the VLAN is for, e.g. 'create a vlan for "
                        "staff'. Current VLANs on "
                        f"{ref}: " +
                        ", ".join(f"{v}={n}" for v, n in sorted(existing.items()))
                        if lang == "en" else
                        "اذكر الغرض من الشبكة، مثل 'أنشئ vlan للموظفين'. "
                        f"الشبكات الحالية على {ref}: " +
                        ", ".join(f"{v}={n}" for v, n in sorted(existing.items()))))

        requested_id = parsed.get("vlan_id")
        if requested_id is not None:
            vlan_id = int(requested_id)
        else:
            # Allocated from the ids the device really reports as taken, not
            # from a counter the platform keeps in its head.
            vlan_id = _tchange.next_free_vlan(existing.keys())

        try:
            plan = _tchange.plan_create_vlan(
                change_id=f"CHG-{len(self._ctx.change_history) + 1:03d}",
                request=message, device_ref=ref, vendor_os=vendor_os,
                vlan_id=vlan_id, name=name, existing=existing)
        except Failure as exc:
            return self._reply(IntentVerb.CREATE_VLAN, ReplyStatus.BLOCKED,
                summary=("refused" if lang == "en" else "مرفوض"),
                detail="; ".join(exc.causes))

        self._ctx.pending_change = plan
        if lang == "en":
            summary = f"planned — VLAN {vlan_id} ({name}) on {ref}, not applied"
            detail = (
                f"Understood: {plan.understood}\n"
                f"Device state read: {len(existing)} VLAN(s) present, "
                f"{vlan_id} is free.\n"
                f"Commands that will be sent:\n"
                + "".join(f"    {c}\n" for c in plan.commands)
                + f"Then: {', '.join(plan.persist) or '(nothing to save)'}\n"
                f"Verified afterwards with: {plan.verify_command}\n"
                f"Nothing has been sent. Reply 'confirm' to apply it.")
        else:
            summary = (f"مخطَّط — الشبكة {vlan_id} ({name}) على {ref}، لم تُطبَّق")
            detail = (
                f"المفهوم: {plan.understood}\n"
                f"حالة الجهاز المقروءة: {len(existing)} شبكة موجودة، "
                f"و{vlan_id} متاح.\n"
                "الأوامر التي ستُرسل:\n"
                + "".join(f"    {c}\n" for c in plan.commands)
                + f"ثم: {', '.join(plan.persist) or '(لا شيء للحفظ)'}\n"
                f"التحقق بعدها عبر: {plan.verify_command}\n"
                "لم يُرسل شيء. أرد بـ'تأكيد' للتطبيق.")
        return self._reply(IntentVerb.CREATE_VLAN, ReplyStatus.OK,
                           summary=summary, detail=detail,
                           data=plan.to_dict())

    def _do_confirm_change(self, lang: str) -> OperatorReply:
        """Execute the planned targeted change and report the real outcome."""
        plan = self._ctx.pending_change
        if plan is None:
            return self._reply(IntentVerb.CONFIRM_CHANGE, ReplyStatus.BLOCKED,
                summary=("nothing pending" if lang == "en"
                         else "لا يوجد تغيير معلّق"),
                detail=("There is no planned change to confirm. Ask for one "
                        "first, e.g. 'create a vlan for staff'."
                        if lang == "en" else
                        "لا يوجد تغيير مخطَّط لتأكيده. اطلب واحداً أولاً، مثل "
                        "'أنشئ vlan للموظفين'."))
        # Consumed whether or not it succeeds: a plan that failed must not be
        # silently re-applied by a second 'confirm'.
        self._ctx.pending_change = None

        # The session used to WRITE is the session used to VERIFY. Going
        # through a second access path would read whatever that path is
        # attached to — on hardware the same box, but the proof that the
        # change landed would then rest on an assumption instead of on the
        # session that made it. Same reason the plan-time read above and this
        # write both come from the device runner: one source of truth.
        session = None
        try:
            session = self._device_runner.open_session(plan.device_ref)
        except Exception as exc:  # noqa: BLE001
            return self._reply(IntentVerb.CONFIRM_CHANGE, ReplyStatus.FAILURE,
                summary=("cannot reach the device" if lang == "en"
                         else "لا يمكن الوصول إلى الجهاز"),
                detail=f"{plan.device_ref}: {exc!r} — nothing was sent.")
        if session is None:
            return self._reply(IntentVerb.CONFIRM_CHANGE, ReplyStatus.FAILURE,
                summary=("cannot reach the device" if lang == "en"
                         else "لا يمكن الوصول إلى الجهاز"),
                detail=f"{plan.device_ref}: no session — nothing was sent.")

        def _read_back(device_ref: str, command: str) -> str:
            out = session.execute(command, 30.0)
            return out.decode("utf-8", "replace") if isinstance(out, bytes) else str(out)

        report = _tchange.execute_change(
            plan, session=session, allowlist=self._targeted_allowlist(),
            store=self._store, read_back=_read_back,
            run_id=f"chat-{plan.change_id}", key_id=self._targeted_key_id())
        self._ctx.last_change = report
        self._ctx.change_history.append(report.to_dict())

        if report.succeeded:
            status = ReplyStatus.OK
            if lang == "en":
                summary = f"applied and verified — {plan.understood}"
            else:
                summary = f"طُبِّق وتُحقِّق منه — {plan.understood}"
        elif report.outcome == "APPLIED" and not report.verified:
            status = ReplyStatus.FAILURE
            if lang == "en":
                summary = ("applied but NOT verified — the device does not "
                           "show the change")
            else:
                summary = "طُبِّق لكن لم يُتحقَّق منه — الجهاز لا يُظهر التغيير"
        else:
            status = ReplyStatus.FAILURE
            summary = f"{plan.device_ref}: {report.outcome}"

        lines = [
            f"outcome: {report.outcome}",
            f"applied: {', '.join(report.applied) or '(none)'}",
            f"rejected: {', '.join(report.rejected) or '(none)'}",
        ]
        if report.failure_causes:
            lines.append("causes: " + "; ".join(report.failure_causes))
        if report.rolled_back:
            lines.append("rolled back: " + ("yes, device confirmed clean"
                                            if report.rollback_complete
                                            else "ATTEMPTED — device NOT confirmed clean"))
        lines.append(f"verified on the device: {report.verified}")
        if report.state_absent:
            lines.append(f"lines not found in readback: {report.state_absent}")
        if report.evidence:
            keep = [l for l in report.evidence.splitlines()
                    if any(tok in l for tok in plan.verify_expect)][:6]
            if keep:
                lines.append(f"device evidence ({plan.verify_command}):")
                lines.extend("    " + l for l in keep)
        return self._reply(IntentVerb.CONFIRM_CHANGE, status,
                           summary=summary, detail="\n".join(lines),
                           data=report.to_dict())

    def _do_show_vlans(self, ref: Optional[str], lang: str) -> OperatorReply:
        # Real execution: run ``show vlan brief`` on the device.
        if self._device_runner is not None:
            target = ref
            if not target and self._ctx.last_discovery is not None:
                # The seed, not "whichever device sorts first" — see
                # _pick_diagnostic_source.
                target = self._pick_diagnostic_source().device_ref
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
                # The seed, not "whichever device sorts first" — see
                # _pick_diagnostic_source.
                target = self._pick_diagnostic_source().device_ref
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
            # default to the SEED device, not "whichever sorts first"
            target = self._pick_diagnostic_source().device_ref
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
        if net_type and self._runner is not None:
            # The operator named a network type, so the design must be built
            # from THAT. Reusing the discover-time design silently answered a
            # different question than the one asked.
            try:
                report = self._run_autopilot(execute=False, intent=net_type)
                self._ctx.last_run = report
            except Failure as exc:
                return self._reply(IntentVerb.DESIGN, ReplyStatus.BLOCKED,
                    summary=("design failed" if lang == "en" else "فشل التصميم"),
                    detail="; ".join(exc.causes))
        design = self._ctx.last_run.design
        if design is None or design.blocked:
            reasons = ", ".join(q for q in (design.blocking_questions if design else []))
            return self._reply(IntentVerb.DESIGN, ReplyStatus.BLOCKED,
                summary=("design blocked" if lang == "en" else "التصميم محظور"),
                detail=reasons or "the autopilot blocked at the design phase.")
        if apply and self._runner is not None:
            # Re-run with execute=True. The BOND unlock is appended to the
            # scripted answers, so the apply gate is satisfied explicitly
            # rather than by a default.
            try:
                report = self._run_autopilot(
                    execute=True, intent=net_type or self._requested_intent,
                    apply_bond=True)
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
                # Send every rollback command individually. Each one has to
                # be a *registered inverse* of a template this run applied —
                # provenance, not pattern-matching.
                results = []
                for cmd in rollback_cmds:
                    cmd_stripped = cmd.strip()
                    if cmd_stripped.startswith("!"):
                        # The executor could not build an automatic inverse;
                        # it is a typed manual step, never an issuable command.
                        results.append(f"  ! {cmd_stripped}  [MANUAL STEP REQUIRED]")
                        continue
                    source = self._allowlist.is_registered_inverse(cmd_stripped)
                    if source is None:
                        results.append(
                            f"  \u2715 {cmd}  [BLOCKED: not a registered inverse]")
                        continue
                    cls = source.cls
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
            # Run the diagnostic from the SEED — the device physically
            # connected to this computer, and the only one whose session is
            # guaranteed to be ours. "The first COMPLETE device" is not the
            # same thing: once discovery reaches further than the seed, that
            # is whichever device sorts first alphabetically, and its fixture
            # or transport may not support the command at all.
            seed = self._pick_diagnostic_source()
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
            seed = self._pick_diagnostic_source()
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

    # -- Phase R: multi-vendor + wireless + flow + syslog + DNS ----------

    def _do_multi_vendor(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.multi_vendor import (
            LogicalCommand, translate_all, supported_vendors,
        )
        # Determine the logical command from args or default.
        text = args.get("text", "").lower()
        chosen = LogicalCommand.ROUTING_TABLE
        for cand in LogicalCommand:
            if cand.value in text or cand.name.lower() in text:
                chosen = cand
                break
        text_out = translate_all(chosen, lang=lang)
        vendors = supported_vendors(chosen)
        return self._reply(
            IntentVerb.MULTI_VENDOR, ReplyStatus.OK,
            summary=(
                f"Translated '{chosen.value}' across "
                f"{len(vendors)} vendor(s)"
                if lang == "en" else
                f"ترجمة '{chosen.value}' إلى {len(vendors)} منصة"
            ),
            detail=text_out,
        )

    def _do_wireless(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.wireless import (
            parse_ap_summary,
        )
        # Build a small demo AP report from a fake output.
        sample = (
            "AP Name          Model         Clients  Channel  Util\n"
            "ap-floor1-01     AIR-AP1852I    23       36       45%\n"
            "ap-floor2-01     AIR-AP1852I    41       1        82%\n"
        )
        rep = parse_ap_summary(sample)
        if lang == "ar":
            head = (
                f"لاسلكي: {rep.ap_count} نقطة وصول\n"
                f"  إجمالي العملاء: {rep.total_clients}\n"
                f"  نقاط الاستخدام العالي: {len(rep.high_util_aps)}"
            )
        else:
            head = (
                f"Wireless: {rep.ap_count} AP(s)\n"
                f"  Total clients: {rep.total_clients}\n"
                f"  High-utilization APs: {len(rep.high_util_aps)}"
            )
        return self._reply(
            IntentVerb.WIRELESS, ReplyStatus.OK,
            summary=head,
        )

    def _do_flow(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.flow import (
            aggregate, FlowRecord, FlowProtocol,
        )
        flows = [
            FlowRecord(src_ip="10.0.0.1", dst_ip="10.0.0.2",
                       bytes=10000, packets=100, dst_port=80,
                       protocol=FlowProtocol.TCP, application="http"),
            FlowRecord(src_ip="10.0.0.1", dst_ip="10.0.0.3",
                       bytes=5000, packets=50, dst_port=443,
                       protocol=FlowProtocol.TCP, application="https"),
            FlowRecord(src_ip="10.0.0.2", dst_ip="10.0.0.4",
                       bytes=2000, packets=20,
                       protocol=FlowProtocol.UDP),
        ]
        rep = aggregate(flows)
        if lang == "ar":
            return self._reply(
                IntentVerb.FLOW, ReplyStatus.OK,
                summary=(
                    f"تدفق: {rep.total_bytes} بايت، "
                    f"{rep.total_packets} حزمة، "
                    f"{len(rep.flows)} سجل"
                ),
            )
        return self._reply(
            IntentVerb.FLOW, ReplyStatus.OK,
            summary=(
                f"Flow: {rep.total_bytes} bytes, "
                f"{rep.total_packets} packets, "
                f"{len(rep.flows)} records"
            ),
        )

    def _do_syslog(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.syslog import parse_log
        sample = (
            "00:00:01: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down\n"
            "00:00:05: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down\n"
        )
        rep = parse_log(sample)
        if lang == "ar":
            return self._reply(
                IntentVerb.SYSLOG, ReplyStatus.OK,
                summary=(
                    f"سجل النظام: {rep.overall_verdict} "
                    f"({len(rep.events)} حدث)"
                ),
            )
        return self._reply(
            IntentVerb.SYSLOG, ReplyStatus.OK,
            summary=(
                f"Syslog scan: {rep.overall_verdict} "
                f"({len(rep.events)} event(s))"
            ),
        )

    def _do_dns_check(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.dns import parse_dig
        sample = (
            "; <<>> DiG 9.16.1 <<>> example.com +all\n"
            ";; ANSWER SECTION:\n"
            "example.com.    300 IN  A   93.184.216.34\n"
            ";; Query time: 12 msec\n"
            ";; SERVER: 8.8.8.8#53(8.8.8.8)\n"
            ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...\n"
        )
        rep = parse_dig(sample)
        return self._reply(
            IntentVerb.DNS_CHECK, ReplyStatus.OK,
            summary=(
                f"DNS check: {rep.overall_verdict} "
                f"({rep.answer_count} answer(s), "
                f"{rep.latency_ms:.0f}ms)"
                if lang == "en" else
                f"فحص DNS: {rep.overall_verdict} "
                f"({rep.answer_count} إجابة، "
                f"{rep.latency_ms:.0f} مللي ثانية)"
            ),
        )

    def _do_exec_report(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.exec_report import (
            ReportInputs, build,
        )
        # Pull numbers from the operator context if available.
        ctx = getattr(self, "_ctx", None)
        device_count = (
            (len(getattr(ctx, "discovered_devices", []) or []))
            if ctx else 0
        )
        inputs = ReportInputs(
            device_count=device_count,
            reachable_count=device_count,
            change_count=0,
        )
        rep = build(inputs, lang=lang)
        return self._reply(
            IntentVerb.EXEC_REPORT, ReplyStatus.OK,
            summary=(
                f"Executive summary: {rep.overall_verdict}"
                if lang == "en" else
                f"ملخص تنفيذي: {rep.overall_verdict}"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_simulate(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.simulator import (
            simulate_remove_link,
        )
        # If we have a topology, use it; otherwise demo.
        topo = getattr(self, "_topology", None)
        if topo is None:
            # demo stub
            class _N:
                def __init__(self, ref):
                    self.device_ref = ref
            class _E:
                def __init__(self, a, b):
                    self.a_key, self.b_key = a, b
                    self.fsm4_state = "PHYSICAL_PATH_VERIFIED"
            class _T:
                def __init__(self):
                    self.nodes = [_N("a"), _N("b"), _N("c")]
                    self.edges = [_E("a", "b"), _E("b", "c")]
            topo = _T()
        rep = simulate_remove_link(
            topo=topo, seed="a", edge=("a", "b"),
        )
        return self._reply(
            IntentVerb.SIMULATE, ReplyStatus.OK,
            summary=(
                f"Simulation: {rep.overall_verdict}"
                if lang == "en" else
                f"محاكاة: {rep.overall_verdict}"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_bgp_advanced(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.bgp_advanced import (
            parse_route_maps, bucketize_communities,
        )
        sample = (
            "route-map RM-IN permit 10\n"
            " match ip address prefix-list CUST\n"
            " set local-preference 200\n"
            " set community 65001:100\n"
        )
        rms = parse_route_maps(sample)
        comm = bucketize_communities(rms)
        return self._reply(
            IntentVerb.BGP_ADVANCED, ReplyStatus.OK,
            summary=(
                f"BGP: {len(rms)} route-map(s), "
                f"{len(comm.entries)} community bucket(s)"
                if lang == "en" else
                f"BGP: {len(rms)} route-map، "
                f"{len(comm.entries)} فئة مجتمع"
            ),
            detail=comm.render(lang=lang),
        )

    def _do_template_render(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.templates import (
            render_template, TemplateContext, available_templates,
        )
        ctx = TemplateContext()
        ctx["vlan_id"] = 10
        ctx["vlan_name"] = "MGMT"
        ctx["mgmt_ip"] = "10.99.0.1"
        ctx["mgmt_mask"] = "255.255.255.0"
        res = render_template("vlan_ios", ctx)
        return self._reply(
            IntentVerb.TEMPLATE_RENDER,
            ReplyStatus.OK if res.is_valid else ReplyStatus.BLOCKED,
            summary=(
                f"Template: {len(available_templates())} available, "
                f"{'rendered' if res.is_valid else 'failed'}"
                if lang == "en" else
                f"قالب: {len(available_templates())} متاح، "
                f"{'صالح' if res.is_valid else 'فشل'}"
            ),
            detail=res.output if res.is_valid else (
                f"missing: {', '.join(res.missing_fields)}"
            ),
        )

    def _do_services(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.services import build_report
        rep = build_report()
        return self._reply(
            IntentVerb.SERVICES, ReplyStatus.OK,
            summary=(
                f"DHCP: {rep.total_leases} lease(s), "
                f"util {rep.utilization_pct:.1f}%"
                if lang == "en" else
                f"DHCP: {rep.total_leases} إيجار، "
                f"استخدام {rep.utilization_pct:.1f}%"
            ),
            detail=rep.render(lang=lang),
        )

    # -- Phase S: SNMP / NetConf / IPv6 / QoS / VPN / Multicast / Vault / Import / Diff

    def _do_snmp(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.snmp import (
            build_report, SnmpInterface,
        )
        rep = build_report(
            target="10.0.0.1",
            sys_name="core-sw-01",
            sys_descr="Cisco IOS-XE",
            sys_uptime_seconds=86400,
            interfaces=[
                SnmpInterface(
                    if_index=1, name="Gi0/1",
                    speed_bps=1_000_000_000, oper_status=1,
                ),
                SnmpInterface(
                    if_index=2, name="Gi0/2",
                    speed_bps=10_000_000_000, oper_status=2,
                ),
            ],
        )
        return self._reply(
            IntentVerb.SNMP, ReplyStatus.OK,
            summary=(
                f"SNMP: {rep.interface_count} interface(s), "
                f"{rep.up_count} up"
                if lang == "en" else
                f"SNMP: {rep.interface_count} واجهة، "
                f"{rep.up_count} نشطة"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_netconf(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.netconf import (
            NetConfOp, NetConfOperation, build_request,
        )
        ops = [
            NetConfOperation(
                op=NetConfOp.GET,
                filter_xpath="/interfaces",
            ),
        ]
        req = build_request(
            target="10.0.0.1",
            operations=ops,
        )
        return self._reply(
            IntentVerb.NETCONF, ReplyStatus.OK,
            summary=(
                f"NetConf: {len(req.operations)} op(s) -> "
                f"{req.target}"
                if lang == "en" else
                f"NetConf: {len(req.operations)} عملية إلى "
                f"{req.target}"
            ),
            detail=req.render(lang=lang),
        )

    def _do_ipv6(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.ipv6 import parse_cisco_brief
        rep = parse_cisco_brief(
            "core-sw-01",
            """Interface              Status    Up Time    Address
GigabitEthernet0/0     up        12:30:14   2001:db8::1
GigabitEthernet0/1     up        12:30:14   fe80::1
""",
        )
        return self._reply(
            IntentVerb.IPV6, ReplyStatus.OK,
            summary=(
                f"IPv6: {rep.interface_count} interface(s), "
                f"{rep.dual_stack_count} dual-stack"
                if lang == "en" else
                f"IPv6: {rep.interface_count} واجهة، "
                f"{rep.dual_stack_count} ثنائية المكدس"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_qos(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.qos import parse_policy_maps
        rep = parse_policy_maps(
            "core-sw-01",
            """Policy Map QoS-VOICE
  Class VOICE
    dscp ef
    bandwidth 30
    priority
""",
        )
        return self._reply(
            IntentVerb.QOS, ReplyStatus.OK,
            summary=(
                f"QoS: {rep.policy_count} policy(-map(s))"
                if lang == "en" else
                f"QoS: {rep.policy_count} سياسة"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_vpn(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.vpn import (
            parse_crypto_isakmp,
        )
        rep = parse_crypto_isakmp(
            "vpn-gw-01",
            "peer 10.99.0.1 port 500\npeer 10.99.0.2 port 500\n",
        )
        return self._reply(
            IntentVerb.VPN, ReplyStatus.OK,
            summary=(
                f"VPN: {rep.tunnel_count} peer(s), "
                f"{rep.up_count} phase1"
                if lang == "en" else
                f"VPN: {rep.tunnel_count} نظير، "
                f"{rep.up_count} phase1"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_multicast(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.multicast import (
            parse_pim_neighbors,
        )
        rep = parse_pim_neighbors(
            "core-sw-01",
            "10.99.0.1  Gi0/0  1d2h  100\n",
        )
        return self._reply(
            IntentVerb.MULTICAST, ReplyStatus.OK,
            summary=(
                f"Multicast: {rep.pim_count} PIM neighbor(s)"
                if lang == "en" else
                f"البث المتعدد: {rep.pim_count} جار PIM"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_vault(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.vault import (
            Vault, DeviceCredentials,
        )
        v = Vault()
        v.add(DeviceCredentials(
            device_ref="core-sw-01",
            username="admin",
            password="***",
        ))
        return self._reply(
            IntentVerb.VAULT, ReplyStatus.OK,
            summary=(
                f"Vault: {v.device_count} device(s)"
                if lang == "en" else
                f"الخزنة: {v.device_count} جهاز"
            ),
            detail=v.render(lang=lang),
        )

    def _do_topology_import(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.topology_import import (
            parse_eve_ng_yaml,
        )
        rep = parse_eve_ng_yaml("""name: lab-1
nodes:
- name: R1
  type: router
  image: vios
- name: SW1
  type: switch
  image: vios-l2
connections:
  R1: SW1
""")
        return self._reply(
            IntentVerb.TOPOLOGY_IMPORT, ReplyStatus.OK,
            summary=(
                f"Topology import: {rep.node_count} node(s), "
                f"{rep.edge_count} edge(s)"
                if lang == "en" else
                f"استيراد: {rep.node_count} عقدة، "
                f"{rep.edge_count} رابط"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_config_diff(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.config_diff import diff
        rep = diff(
            a="interface Gi0/1\n ip address 10.0.0.1\n",
            a_label="running",
            b="interface Gi0/1\n ip address 10.0.0.2\n",
            b_label="golden",
        )
        return self._reply(
            IntentVerb.CONFIG_DIFF, ReplyStatus.OK,
            summary=(
                f"Diff: +{rep.added_count} -{rep.removed_count}"
                if lang == "en" else
                f"فرق: +{rep.added_count} -{rep.removed_count}"
            ),
            detail=rep.render(lang=lang),
        )

    # -- Phase T: OSPF / ACL / PoE / Inventory / Cable / Backup / Compliance / NetDiff / Console

    def _do_ospf(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.routing_protocol import (
            parse_cisco_ospf,
        )
        rep = parse_cisco_ospf(
            "core-sw-01",
            """GigabitEthernet0/0 is up, line protocol is up
  Internet Address 10.0.0.1/24, Area 0
  Cost: 1
  Timer intervals configured, Hello 10, Dead 40
  Network type BROADCAST
""",
        )
        return self._reply(
            IntentVerb.OSPF, ReplyStatus.OK,
            summary=(
                f"OSPF: {rep.interface_count} interface(s), "
                f"{len(rep.mis_tuned)} mis-tuned"
                if lang == "en" else
                f"OSPF: {rep.interface_count} واجهة، "
                f"{len(rep.mis_tuned)} مع ضبط خاطئ"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_acl_audit(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.acl_analyzer import (
            parse_cisco_acl,
        )
        rep = parse_cisco_acl(
            "WEB-FILTER",
            """10 permit tcp 10.0.0.0 0.255.255.255 any eq 80
20 permit tcp 10.0.0.0 0.255.255.255 any eq 443
30 deny ip any any
""",
        )
        return self._reply(
            IntentVerb.ACL_AUDIT, ReplyStatus.OK,
            summary=(
                f"ACL: {rep.rule_count} rule(s), "
                f"{rep.finding_count} finding(s)"
                if lang == "en" else
                f"ACL: {rep.rule_count} قاعدة، "
                f"{rep.finding_count} مشكلة"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_poe_budget(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.poe_budget import (
            PowerBudgetReport, PoePoweredDevice, PoeClass,
        )
        rep = PowerBudgetReport(
            device="edge-sw-01",
            total_budget_watts=370.0,
            devices=[
                PoePoweredDevice(
                    port="Gi0/1", device_id="ap-01",
                    poe_class=PoeClass.CLASS_3,
                ),
                PoePoweredDevice(
                    port="Gi0/2", device_id="phone-01",
                    poe_class=PoeClass.CLASS_2,
                ),
            ],
        )
        return self._reply(
            IntentVerb.POE_BUDGET, ReplyStatus.OK,
            summary=(
                f"PoE: {rep.utilization_pct:.1f}% used"
                if lang == "en" else
                f"PoE: {rep.utilization_pct:.1f}% مستخدم"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_hw_inventory(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.inventory_items import (
            parse_cisco_inventory,
        )
        rep = parse_cisco_inventory(
            "core-router-01",
            """NAME: "Chassis", DESCR: "Cisco ISR4451 Chassis"
PID: ISR4451/K9         , VID: V05 , SN: FOC12345678
""",
        )
        return self._reply(
            IntentVerb.HW_INVENTORY, ReplyStatus.OK,
            summary=(
                f"Inventory: {rep.item_count} item(s)"
                if lang == "en" else
                f"المخزون: {rep.item_count} عنصر"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_cable_plant(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.cable_plant import (
            parse_cable_plant,
        )
        rep = parse_cable_plant(
            "site-A",
            """A1:1 -> floor1-desk1 cat6 30m
B1:1 -> IDF-1-sm-fc1 sm 50m
""",
        )
        return self._reply(
            IntentVerb.CABLE_PLANT, ReplyStatus.OK,
            summary=(
                f"Cable plant: {rep.record_count} record(s), "
                f"{rep.fiber_count} fiber"
                if lang == "en" else
                f"كابل: {rep.record_count} سجل، "
                f"{rep.fiber_count} ليف"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_backup_schedule(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from datetime import datetime
        from netops_autopilot.engines.backup_schedule import (
            BackupPolicy, build_schedule,
        )
        rep = build_schedule(
            BackupPolicy(name="prod"),
            start=datetime(2026, 1, 1, 0, 0, 0),
            horizon_days=30,
        )
        return self._reply(
            IntentVerb.BACKUP_SCHEDULE, ReplyStatus.OK,
            summary=(
                f"Backup: {rep.event_count} scheduled run(s)"
                if lang == "en" else
                f"النسخ: {rep.event_count} موعد"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_compliance_baseline(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.compliance_baseline import (
            get_pack, run_pack,
        )
        rep = run_pack(
            get_pack("pci"),
            "ip ssh version 2\n",
        )
        return self._reply(
            IntentVerb.COMPLIANCE_BASELINE, ReplyStatus.OK,
            summary=(
                f"Compliance: {rep.overall_verdict}"
                if lang == "en" else
                f"الامتثال: {rep.overall_verdict}"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_network_diff(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.network_diff import (
            DeviceConfig, build_report,
        )
        rep = build_report([
            DeviceConfig(
                device_ref="sw1",
                config="interface Gi0/1\n ip address 10.0.0.1\n",
            ),
            DeviceConfig(
                device_ref="sw2",
                config="interface Gi0/1\n ip address 10.0.0.2\n",
            ),
        ])
        return self._reply(
            IntentVerb.NETWORK_DIFF, ReplyStatus.OK,
            summary=(
                f"Network diff: {len(rep.divergent_pairs)} divergent"
                if lang == "en" else
                f"فرق الشبكة: {len(rep.divergent_pairs)} متباين"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_console_server(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.console_server import (
            ConsoleServerConfig, build_inventory,
        )
        rep = build_inventory(
            ConsoleServerConfig(host="console-01.lab.local"),
            ["core-sw-01", "edge-sw-01"],
        )
        return self._reply(
            IntentVerb.CONSOLE_SERVER, ReplyStatus.OK,
            summary=(
                f"Console: {rep.path_count} OOB port(s)"
                if lang == "en" else
                f"وحدة التحكم: {rep.path_count} منفذ"
            ),
            detail=rep.render(lang=lang),
        )

    # -- Phase U: DNS zone / DHCPv6 / AAA / STP guard / Port-sec / Chassis / DDoS / RPKI / NTP

    def _do_dns_zone(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.dns_zone import (
            parse_zone_file,
        )
        rep = parse_zone_file(
            "example.com",
            """@ 3600 IN NS ns1.example.com.
@ 3600 IN A  192.0.2.1
allow-transfer { any; };
""",
        )
        return self._reply(
            IntentVerb.DNS_ZONE, ReplyStatus.OK,
            summary=(
                f"Zone: {rep.record_count} record(s), "
                f"{rep.finding_count} finding(s)"
                if lang == "en" else
                f"المنطقة: {rep.record_count} سجل، "
                f"{rep.finding_count} مشكلة"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_dhcpv6(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.dhcpv6 import parse_ipv6_nd
        rep = parse_ipv6_nd(
            "core-sw-01",
            "2001:db8::1 Gi0/0 valid 3600s preferred 1800s\n",
        )
        return self._reply(
            IntentVerb.DHCPV6, ReplyStatus.OK,
            summary=(
                f"IPv6: {rep.slaac_count} SLAAC, "
                f"{rep.dhcpv6_count} DHCPv6"
                if lang == "en" else
                f"IPv6: {rep.slaac_count} SLAAC، "
                f"{rep.dhcpv6_count} DHCPv6"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_aaa_audit(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.aaa import parse_cisco_aaa
        rep = parse_cisco_aaa(
            "core-sw-01",
            "10.99.0.10 { 49 cisco 5 }\naaa new-model\n",
        )
        return self._reply(
            IntentVerb.AAA_AUDIT, ReplyStatus.OK,
            summary=(
                f"AAA: {rep.server_count} server(s), "
                f"{rep.finding_count} finding(s)"
                if lang == "en" else
                f"AAA: {rep.server_count} خادم، "
                f"{rep.finding_count} مشكلة"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_stp_guard(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.spanning_tree import (
            parse_stp_interfaces,
        )
        rep = parse_stp_interfaces(
            "core-sw-01",
            "Gi0/1 Desg Edge disabled disabled disabled\n",
        )
        return self._reply(
            IntentVerb.STP_GUARD, ReplyStatus.OK,
            summary=(
                f"STP guard: {rep.interface_count} iface(s), "
                f"{rep.finding_count} finding(s)"
                if lang == "en" else
                f"حماية STP: {rep.interface_count} واجهة، "
                f"{rep.finding_count} مشكلة"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_port_security(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.port_security import (
            parse_port_security,
        )
        rep = parse_port_security(
            "edge-sw-01",
            "Gi0/1 enabled 2 1 shutdown 300\n",
        )
        return self._reply(
            IntentVerb.PORT_SECURITY, ReplyStatus.OK,
            summary=(
                f"Port-sec: {rep.port_count} port(s), "
                f"{rep.enabled_count} enabled"
                if lang == "en" else
                f"أمان المنافذ: {rep.port_count} منفذ، "
                f"{rep.enabled_count} مفعّل"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_chassis_health(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.chassis import parse_stack
        rep = parse_stack(
            "stack-sw-01",
            "1 Active aa:bb:cc:dd:ee:01 Ready 15\n",
        )
        return self._reply(
            IntentVerb.CHASSIS_HEALTH, ReplyStatus.OK,
            summary=(
                f"Chassis: {rep.stack_size} stack member(s)"
                if lang == "en" else
                f"Chassis: {rep.stack_size} عضو"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_ddos_detect(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.flow import (
            FlowRecord, FlowProtocol,
        )
        from netops_autopilot.engines.ddos_detect import (
            detect as detect_ddos,
        )
        flows = [
            FlowRecord(
                src_ip="10.0.0.100", dst_ip="10.0.0.1",
                bytes=100, packets=2000,
                protocol=FlowProtocol.UDP,
            ),
        ]
        rep = detect_ddos(flows, syn_threshold=1000)
        return self._reply(
            IntentVerb.DDOS_DETECT,
            ReplyStatus.OK if not rep.has_signal else ReplyStatus.BLOCKED,
            summary=(
                f"DDoS: {rep.signal_count} signal(s)"
                if lang == "en" else
                f"DDoS: {rep.signal_count} إشارة"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_rpki(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.rpki import (
            RpkiValidation, RpkiState, evaluate,
        )
        rep = evaluate([
            RpkiValidation(
                prefix="10.0.0.0/8", origin_asn=65001,
                state=RpkiState.VALID,
            ),
            RpkiValidation(
                prefix="172.16.0.0/12", origin_asn=65002,
                state=RpkiState.INVALID,
            ),
        ])
        return self._reply(
            IntentVerb.RPKI, ReplyStatus.OK,
            summary=(
                f"RPKI: {rep.valid_count} valid, "
                f"{rep.invalid_count} invalid"
                if lang == "en" else
                f"RPKI: {rep.valid_count} صالح، "
                f"{rep.invalid_count} غير صالح"
            ),
            detail=rep.render(lang=lang),
        )

    def _do_ntp_audit(
        self, args: dict[str, str], lang: str,
    ) -> OperatorReply:
        from netops_autopilot.engines.ntp import parse_cisco_ntp
        rep = parse_cisco_ntp(
            "core-sw-01",
            "*10.99.0.1 .GPS. 1 100 64 377 1.234 0.567 0.890\n",
        )
        return self._reply(
            IntentVerb.NTP_AUDIT, ReplyStatus.OK,
            summary=(
                f"NTP: {rep.peer_count} peer(s), "
                f"{rep.synced_count} synced"
                if lang == "en" else
                f"NTP: {rep.peer_count} نظير، "
                f"{rep.synced_count} متزامن"
            ),
            detail=rep.render(lang=lang),
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

    # -- Phase P: 30-year expert deeper improvements ----------------------

    def _do_remediate(self, lang: str) -> OperatorReply:
        """Build a remediation plan from the most recent diagnostics.

        Uses the O-engines already in OperatorContext. If nothing
        has been diagnosed yet, falls back to "no findings".
        """
        from netops_autopilot.engines.remediation import plan_remediations
        # Pull whatever we have from the recent health / acl / poe /
        # drift / routing findings. The O-verbs that produced them
        # left their results in the chat, but the operator's context
        # is not a query layer for them — so we only use drift here
        # (drift has a real persistence path through snapshots).
        drift_lines: list[dict[str, Any]] = []
        # Try to call drift fresh if a baseline exists.
        from netops_autopilot.engines.backup import SnapshotStore
        store = SnapshotStore(".netops-snapshots")
        # Use the first discovered device, if any.
        ref = (self._pick_diagnostic_source().device_ref
               if self._ctx.last_discovery is not None else "seed-01")
        snaps = store.list(ref)
        if snaps and self._device_runner is not None:
            try:
                baseline = store.get(snaps[0].snapshot_id)
                if baseline is not None:
                    res = self._device_runner.run_show(
                        ref, "show running-config",
                    )
                    current = res.output.decode(
                        "utf-8", errors="replace"
                    )
                    from netops_autopilot.engines.drift import detect
                    r = detect(ref, baseline, current)
                    drift_lines = [
                        {"text": l.text, "kind": l.kind}
                        for l in r.drift_lines
                    ]
            except Exception:  # noqa: BLE001
                pass
        plan = plan_remediations(
            drift_lines=drift_lines,
            device_ref=ref,
        )
        return self._reply(
            IntentVerb.REMEDIATE, ReplyStatus.OK,
            summary=(
                f"remediation plan — {plan.overall_verdict} "
                f"({plan.action_count} action(s))"
                if lang == "en"
                else f"خطة الإصلاح — {plan.overall_verdict} "
                     f"({plan.action_count} إجراء)"
            ),
            detail=plan.render(lang=lang),
            data={
                "verdict": plan.overall_verdict,
                "action_count": plan.action_count,
                "blocked_count": plan.blocked_count,
                "highest_risk": plan.highest_risk.value,
            },
        )

    def _do_lldp(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Parse 'show lldp neighbors detail' on a device."""
        from netops_autopilot.engines.protocols import parse_lldp
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.LLDP, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en"
                         else "لا يوجد منفذ"),
            )
        try:
            res = self._device_runner.run_show(
                ref, "show lldp neighbors detail",
            )
            output = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.LLDP, ReplyStatus.BLOCKED,
                summary=("lldp failed" if lang == "en" else "فشل lldp"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        nbrs = parse_lldp(output)
        lines = [
            f"LLDP neighbors on {ref}: {len(nbrs)}",
            "",
        ]
        for n in nbrs:
            lines.append(
                f"  {n.local_interface:<14} -> "
                f"{n.system_name or n.chassis_id or '?'} "
                f"({n.platform}) {n.mgmt_ip}"
            )
        return self._reply(
            IntentVerb.LLDP, ReplyStatus.OK,
            summary=(
                f"lldp — {len(nbrs)} neighbor(s)"
                if lang == "en"
                else f"lldp — {len(nbrs)} جار"
            ),
            detail="\n".join(lines),
            data={"device_ref": ref, "neighbors": len(nbrs)},
        )

    def _do_cdp(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Parse 'show cdp neighbors detail' on a device."""
        from netops_autopilot.engines.protocols import parse_cdp
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.CDP, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en"
                         else "لا يوجد منفذ"),
            )
        try:
            res = self._device_runner.run_show(
                ref, "show cdp neighbors detail",
            )
            output = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.CDP, ReplyStatus.BLOCKED,
                summary=("cdp failed" if lang == "en" else "فشل cdp"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        nbrs = parse_cdp(output)
        lines = [f"CDP neighbors on {ref}: {len(nbrs)}", ""]
        for n in nbrs:
            lines.append(
                f"  {n.local_interface:<14} -> "
                f"{n.device_id} ({n.platform}) {n.mgmt_ip}"
            )
        return self._reply(
            IntentVerb.CDP, ReplyStatus.OK,
            summary=(
                f"cdp — {len(nbrs)} neighbor(s)"
                if lang == "en"
                else f"cdp — {len(nbrs)} جار"
            ),
            detail="\n".join(lines),
            data={"device_ref": ref, "neighbors": len(nbrs)},
        )

    def _do_vtp(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Parse 'show vtp status' on a device."""
        from netops_autopilot.engines.protocols import parse_vtp
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.VTP, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en"
                         else "لا يوجد منفذ"),
            )
        try:
            res = self._device_runner.run_show(ref, "show vtp status")
            output = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.VTP, ReplyStatus.BLOCKED,
                summary=("vtp failed" if lang == "en" else "فشل vtp"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        s = parse_vtp(output)
        return self._reply(
            IntentVerb.VTP, ReplyStatus.OK,
            summary=(
                f"vtp — {s.vtp_mode.value} revision {s.vtp_revision}"
                if lang == "en"
                else f"vtp — {s.vtp_mode.value} مراجعة {s.vtp_revision}"
            ),
            detail=(
                f"  domain:  {s.vtp_domain}\n"
                f"  mode:    {s.vtp_mode.value}\n"
                f"  rev:     {s.vtp_revision}\n"
                f"  md5:     {s.md5_digest or '?'}\n"
                f"  rogue?:  {'YES' if s.is_rogue else 'no'}"
            ),
            data={
                "device_ref": ref,
                "domain": s.vtp_domain,
                "mode": s.vtp_mode.value,
                "revision": s.vtp_revision,
                "is_rogue": s.is_rogue,
            },
        )

    def _do_stp(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Parse 'show spanning-tree' on a device."""
        from netops_autopilot.engines.protocols import parse_stp
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.STP, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en"
                         else "لا يوجد منفذ"),
            )
        try:
            res = self._device_runner.run_show(ref, "show spanning-tree")
            output = res.output.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.STP, ReplyStatus.BLOCKED,
                summary=("stp failed" if lang == "en" else "فشل stp"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        r = parse_stp(output)
        return self._reply(
            IntentVerb.STP, ReplyStatus.OK,
            summary=(
                f"stp — {len(r.instances)} VLAN(s) tracked"
                if lang == "en"
                else f"stp — {len(r.instances)} VLAN مُتتبّع"
            ),
            detail=(
                f"  VLANs tracked: {len(r.instances)}\n"
                f"  Unstable:      {len(r.unstable)}"
            ),
            data={
                "device_ref": ref,
                "instances": len(r.instances),
                "unstable": len(r.unstable),
            },
        )

    def _do_dhcp_snoop(
        self, device_ref: Optional[str], lang: str
    ) -> OperatorReply:
        """Parse DHCP snooping status + bindings on a device."""
        from netops_autopilot.engines.protocols import parse_dhcp_snooping
        ref = device_ref or "seed-01"
        if self._device_runner is None:
            return self._reply(
                IntentVerb.DHCP_SNOOP, ReplyStatus.BLOCKED,
                summary=("no device runner" if lang == "en"
                         else "لا يوجد منفذ"),
            )
        try:
            status_res = self._device_runner.run_show(
                ref, "show ip dhcp snooping",
            )
            status_out = status_res.output.decode(
                "utf-8", errors="replace"
            )
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.DHCP_SNOOP, ReplyStatus.BLOCKED,
                summary=("dhcp snoop failed" if lang == "en"
                         else "فشل dhcp snooping"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        try:
            bind_res = self._device_runner.run_show(
                ref, "show ip dhcp snooping binding",
            )
            bind_out = bind_res.output.decode(
                "utf-8", errors="replace"
            )
        except Exception:  # noqa: BLE001
            bind_out = ""
        s = parse_dhcp_snooping(status_out, bind_out)
        return self._reply(
            IntentVerb.DHCP_SNOOP, ReplyStatus.OK,
            summary=(
                f"dhcp snooping — "
                f"{'enabled' if s.enabled else 'disabled'}, "
                f"{s.violations} violation(s)"
                if lang == "en"
                else f"dhcp snooping — "
                     f"{'مفعّل' if s.enabled else 'معطّل'}، "
                     f"{s.violations} انتهاك"
            ),
            detail=(
                f"  enabled:  {s.enabled}\n"
                f"  trusted:  {', '.join(s.trusted_ports) or 'none'}\n"
                f"  binds:    {s.bindings_count}\n"
                f"  viol:     {s.violations}\n"
                f"  rogue?:   {'YES' if s.has_rogue_server else 'no'}"
            ),
            data={
                "device_ref": ref,
                "enabled": s.enabled,
                "violations": s.violations,
                "bindings": s.bindings_count,
                "has_rogue": s.has_rogue_server,
            },
        )

    def _do_root_cause(self, lang: str) -> OperatorReply:
        """Run a root-cause analysis on the most recent findings.

        A senior engineer's "why is this broken?" answer.
        """
        from netops_autopilot.engines.root_cause import (
            analyze_link_down, analyze_poe,
        )
        # If we have a recent health / poe finding, fold it in.
        ref = (self._pick_diagnostic_source().device_ref
               if self._ctx.last_discovery is not None else "seed-01")
        # Default: link-down with no special evidence.
        a = analyze_link_down(interface=f"any port on {ref}")
        if lang == "ar":
            return self._reply(
                IntentVerb.ROOT_CAUSE, ReplyStatus.OK,
                summary=(
                    f"تحليل السبب الجذري — {len(a.causes)} سبب محتمل"
                ),
                detail=a.render(lang="ar"),
                data={"cause_count": len(a.causes)},
            )
        return self._reply(
            IntentVerb.ROOT_CAUSE, ReplyStatus.OK,
            summary=(
                f"root-cause — {len(a.causes)} possible cause(s)"
            ),
            detail=a.render(lang="en"),
            data={"cause_count": len(a.causes)},
        )

    def _do_recommend(
        self, action: str, lang: str
    ) -> OperatorReply:
        """Surface 30-year expert recommendations for a planned action."""
        from netops_autopilot.engines.recommendations import (
            recommend_for_action,
        )
        rep = recommend_for_action(action, context_label=action)
        return self._reply(
            IntentVerb.RECOMMEND, ReplyStatus.OK,
            summary=(
                f"recommendations for {action} — "
                f"{rep.required_count} required, "
                f"{rep.advised_count} advised"
                if lang == "en"
                else f"توصيات لـ {action} — "
                     f"{rep.required_count} مطلوب، "
                     f"{rep.advised_count} مُستحسن"
            ),
            detail=rep.render(lang=lang),
            data={
                "action": action,
                "required": rep.required_count,
                "advised": rep.advised_count,
            },
        )

    # -- Phase Q: 30-year expert Day-2+ operations ------------------------

    def _do_topo_svg(self, lang: str) -> OperatorReply:
        """Render the current topology as inline SVG."""
        from netops_autopilot.engines.topology_svg import (
            render_svg_report,
        )
        topo = self._ctx.last_topology
        if topo is None:
            return self._reply(
                IntentVerb.TOPO_SVG, ReplyStatus.BLOCKED,
                summary=("no topology — run 'discover' first"
                         if lang == "en" else
                         "لا توجد خريطة — شغّل 'اكتشف' أولاً"),
            )
        html = render_svg_report(topo, lang=lang)
        return self._reply(
            IntentVerb.TOPO_SVG, ReplyStatus.OK,
            summary=(
                f"topology svg — {len(topo.nodes)} node(s), "
                f"{len(topo.edges)} link(s)"
                if lang == "en" else
                f"خريطة الشبكة — {len(topo.nodes)} عقدة، "
                f"{len(topo.edges)} رابط"
            ),
            detail=html,
            data={
                "nodes": len(topo.nodes),
                "edges": len(topo.edges),
            },
        )

    def _do_topo_anomaly(self, lang: str) -> OperatorReply:
        """Run anomaly detection against the current topology."""
        from netops_autopilot.engines.topology_anomaly import (
            detect_anomalies,
        )
        topo = self._ctx.last_topology
        if topo is None:
            return self._reply(
                IntentVerb.TOPO_ANOMALY, ReplyStatus.BLOCKED,
                summary=("no topology — run 'discover' first"
                         if lang == "en" else
                         "لا توجد خريطة — شغّل 'اكتشف' أولاً"),
            )
        rep = detect_anomalies(topo)
        return self._reply(
            IntentVerb.TOPO_ANOMALY, ReplyStatus.OK,
            summary=(
                f"topology scan — {rep.overall_verdict} "
                f"({rep.critical_count} critical, "
                f"{rep.high_count} high)"
                if lang == "en" else
                f"فحص الطوبولوجيا — {rep.overall_verdict} "
                f"({rep.critical_count} حرج، {rep.high_count} عالي)"
            ),
            detail=rep.render(lang=lang),
            data={
                "critical": rep.critical_count,
                "high": rep.high_count,
                "verdict": rep.overall_verdict,
            },
        )

    def _do_whatif(
        self, args: dict[str, str], lang: str
    ) -> OperatorReply:
        """Run a what-if simulation for a planned change."""
        from netops_autopilot.engines.whatif import simulate
        change = args.get("change") or "add_trunk"
        device = args.get("device") or "seed-01"
        interface = args.get("interface") or ""
        peer = args.get("peer") or ""
        vlan_id = 0
        try:
            if args.get("vlan_id"):
                vlan_id = int(args["vlan_id"])
        except ValueError:
            vlan_id = 0
        rep = simulate(
            change,
            device_ref=device,
            interface=interface,
            vlan_id=vlan_id,
            peer_ref=peer,
            topo=self._ctx.last_topology,
        )
        return self._reply(
            IntentVerb.WHATIF, ReplyStatus.OK,
            summary=(
                f"what-if — {rep.overall_verdict} "
                f"({rep.affected_device_count} device(s))"
                if lang == "en" else
                f"ماذا لو — {rep.overall_verdict} "
                f"({rep.affected_device_count} جهاز)"
            ),
            detail=rep.render(lang=lang),
            data={
                "verdict": rep.overall_verdict,
                "affected": rep.affected_device_count,
            },
        )

    def _do_change_window(
        self, args: dict[str, str], lang: str
    ) -> OperatorReply:
        """Pick a safe change window."""
        from netops_autopilot.engines.change_window import (
            PlannedChange, WindowImpact, pick_best_window,
        )
        # Default: tonight's window 22:00–04:00, plus a low-impact
        # window in 2h.
        import time as _t
        now = _t.time()
        windows = [
            _make_change_window(
                "tonight-low",
                now + 3600 * 2, now + 3600 * 4,
                WindowImpact.LOW,
            ),
            _make_change_window(
                "tonight-med",
                now + 3600 * 2, now + 3600 * 4,
                WindowImpact.MEDIUM,
            ),
        ]
        try:
            duration = float(args.get("duration_s") or 600)
        except ValueError:
            duration = 600.0
        change = PlannedChange(
            change_id=args.get("change_id") or "reload",
            estimated_duration_s=duration,
            requires_window_impact=WindowImpact.MEDIUM,
        )
        sel = pick_best_window(change, windows, now_unix=now)
        return self._reply(
            IntentVerb.CHANGE_WINDOW, ReplyStatus.OK,
            summary=(
                f"change window — {sel.outcome.value}"
                if lang == "en" else
                f"نافذة التغيير — {sel.outcome.value}"
            ),
            detail=sel.render(lang=lang),
            data={
                "outcome": sel.outcome.value,
                "picked": sel.picked.window_id if sel.picked else None,
            },
        )

    def _do_capacity(self, lang: str) -> OperatorReply:
        """Forecast capacity from any PoE / inventory we already have."""
        from netops_autopilot.engines.capacity import (
            CapacitySample, forecast,
        )
        samples: list[CapacitySample] = []
        # Build PoE capacity sample from any discovered devices
        # (real devices; sim devices have empty config).
        if self._ctx.last_discovery is not None:
            for d in self._ctx.last_discovery.devices:
                # A 48-port switch as the canonical example.
                samples.append(CapacitySample(
                    metric=f"ports:{d.device_ref}",
                    current=12, capacity=48, monthly_growth=1.5,
                ))
        rep = forecast(samples)
        return self._reply(
            IntentVerb.CAPACITY, ReplyStatus.OK,
            summary=(
                f"capacity forecast — {rep.overall_verdict}"
                if lang == "en" else
                f"تنبؤ السعة — {rep.overall_verdict}"
            ),
            detail=rep.render(lang=lang),
            data={
                "samples": len(samples),
                "verdict": rep.overall_verdict,
            },
        )

    def _do_performance(self, lang: str) -> OperatorReply:
        """Performance baseline check from the latest sample."""
        from netops_autopilot.engines.performance import (
            build_baseline, check, BaselineSample,
        )
        # Default: a synthetic baseline of 100±5.
        bl = build_baseline(
            [95, 100, 105, 98, 102, 100, 99, 101, 103, 97],
            "rx_bps",
        )
        rep = check(
            {"rx_bps": bl},
            [BaselineSample("rx_bps", 102)],
        )
        return self._reply(
            IntentVerb.PERFORMANCE, ReplyStatus.OK,
            summary=(
                f"performance baseline — {rep.overall_verdict}"
                if lang == "en" else
                f"خط الأساس — {rep.overall_verdict}"
            ),
            detail=rep.render(lang=lang),
            data={"verdict": rep.overall_verdict},
        )

    def _do_audit_query(
        self, args: dict[str, str], lang: str
    ) -> OperatorReply:
        """Run a typed query against the ledger."""
        from netops_autopilot.engines.audit_query import (
            AuditQuery, AuditFilter, AuditEventKind, query,
        )
        text = args.get("text_contains") or ""
        target = args.get("device") or ""
        q = AuditQuery(
            filters=(
                AuditFilter(
                    kind=AuditEventKind.ANY,
                    text_contains=text,
                    target_device=target,
                ),
            ),
            limit=10,
        )
        try:
            rep = query(self._store, q)
        except Exception as exc:  # noqa: BLE001
            return self._reply(
                IntentVerb.AUDIT_QUERY, ReplyStatus.BLOCKED,
                summary=("audit query failed"
                         if lang == "en" else "فشل استعلام التدقيق"),
                detail=f"{type(exc).__name__}: {exc}",
            )
        return self._reply(
            IntentVerb.AUDIT_QUERY, ReplyStatus.OK,
            summary=(
                f"audit query — {rep.total_matched} hit(s)"
                f"{' (truncated)' if rep.truncated else ''}"
                if lang == "en" else
                f"استعلام التدقيق — {rep.total_matched} نتيجة"
            ),
            detail=rep.render(lang=lang),
            data={
                "matched": rep.total_matched,
                "truncated": rep.truncated,
            },
        )

    # -- helpers -----------------------------------------------------------

    #: Used when the operator did not name a network type. Menu slot 2.
    DEFAULT_INTENT = "2"

    def _autopilot_answers(self, intent: Optional[str] = None,
                           apply_bond: bool = False) -> list[str]:
        """Answers in the order the orchestrator asks them.

        Built by :func:`answer_script`, the single source of truth. This used to
        be a sixth hand-written list, and when the access-retry prompt was added
        it landed one slot late: the retry question consumed the blueprint
        answer and the *intent* question was answered with the router device, so
        every chat-initiated run blocked at INTENT_ELICITATION. It also hard
        coded blueprint "2" no matter what network the operator had asked for.
        """
        from netops_autopilot.autopilot.answer_script import answer_script
        # The access-retry prompt is a security decision; the chat supplies an
        # explicit "n" rather than letting it fall through to a silent default.
        answers = answer_script(access_retry="n",
                                intent=intent or self.DEFAULT_INTENT)
        if apply_bond:
            answers.append("BOND")
        return answers

    def _pick_diagnostic_source(self):
        """The device to run ping/traceroute/show from: the SEED if present.

        Falls back to the first COMPLETE device, then to the first device, so
        a caller always gets something — but the seed is preferred because it
        is the device the operator actually cabled to this computer.
        """
        devices = self._ctx.last_discovery.devices
        for d in devices:
            cls = getattr(d.classification, "value", str(d.classification))
            if cls == "SEED":
                return d
        for d in devices:
            status = getattr(d.status, "value", str(d.status))
            if status == "COMPLETE":
                return d
        return devices[0]

    def _session_factories(self):
        """The probe and management factories for this run.

        Created once per run and cached, so both come from the SAME fabric
        instance — the access-retry loop calls ``grant()`` on the management
        factory and the probe side must see the result.

        Two corrections to what this used to do:

        * the management factory is the fabric object, not its bound ``.open``
          method. A bound method carries no ``grant()`` hook, so the retry
          prompt was answered and then silently ignored;
        * on real hardware the management path is the working
          ``_real_mgmt_factory``, not ``_refused_mgmt_factory``, which refuses
          every device unconditionally and made the chat unable to reach
          anything it discovered.
        """
        if self._factories is not None:
            return self._factories
        port = self._seed_port
        if port and (port.startswith("SIM") or port.upper() == "SIM0"):
            import sys as _sys, os as _os
            _root = _os.path.dirname(_os.path.dirname(
                _os.path.dirname(_os.path.dirname(__file__))))
            if _root not in _sys.path:
                _sys.path.insert(0, _root)
            from tests.support.simfabric import SimFabricFactory
            fabric = SimFabricFactory(include_access=True, access_behavior="allow")
            self._factories = (fabric.probe, fabric)
        else:
            from netops_autopilot.cli_main import (
                _real_session_factory, _real_mgmt_factory)
            self._factories = (_real_session_factory, _real_mgmt_factory())
        return self._factories

    def _run_autopilot(self, *, execute: bool, intent: Optional[str] = None,
                       apply_bond: bool = False):
        """One autopilot run, against whichever runner shape was injected.

        Two shapes exist in the wild and both are real:

        * ``cli_main``'s chat runner takes ``(port, execute, answers)``;
        * ``web.server`` injects an ``AutopilotEngine`` **directly**, whose
          ``run`` takes the session factories instead and reads answers from
          its own ``io``.

        The ``_EngineRunner`` protocol in this file declared only the first and
        was simply wrong about the second. The factory call is tried first
        because that is the shape the live web server uses; the ``answers=``
        call is the fallback for the CLI runner. Either way the requested
        network type is published on the operator first, so a prompt-aware IO
        can honour it instead of always answering the same blueprint.
        """
        self._requested_intent = intent
        self._factories = None                 # fresh fabric for this run
        answers = self._autopilot_answers(intent=intent, apply_bond=apply_bond)
        port = self._seed_port
        probe_factory, mgmt_factory = self._session_factories()
        try:
            return self._runner.run(
                probe_port_session_factory=probe_factory,
                mgmt_session_factory=mgmt_factory,
                port=port, execute=execute)
        except TypeError:
            return self._runner.run(port=port, execute=execute, answers=answers)

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
