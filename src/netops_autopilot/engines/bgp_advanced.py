"""BGP Communities and Route-Map Engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class RouteMapAction(str, Enum):
    __test__ = False

    PERMIT = "permit"
    DENY = "deny"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RouteMapClause:
    __test__ = False

    sequence: int
    action: RouteMapAction
    match_acl: str = ""
    match_prefix_list: str = ""
    match_community: str = ""
    set_local_pref: int = 0
    set_metric: int = 0
    set_community: str = ""
    set_next_hop: str = ""
    set_as_path_prepend: str = ""


@dataclass
class BgpRouteMap:
    __test__ = False

    name: str
    clauses: list[RouteMapClause] = field(default_factory=list)

    @property
    def clause_count(self) -> int:
        return len(self.clauses)

    @property
    def permit_count(self) -> int:
        return sum(
            1 for c in self.clauses
            if c.action == RouteMapAction.PERMIT
        )

    @property
    def deny_count(self) -> int:
        return sum(
            1 for c in self.clauses
            if c.action == RouteMapAction.DENY
        )


@dataclass
class BgpCommunityReport:
    __test__ = False

    entries: dict[str, list[str]] = field(default_factory=dict)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            if not self.entries:
                return "لا توجد مجتمعات BGP مسجلة"
            head = f"مجتمعات BGP: {len(self.entries)} فئة"
        else:
            if not self.entries:
                return "No BGP communities registered"
            head = f"BGP communities: {len(self.entries)} bucket(s)"
        lines = [head]
        for bucket, communities in sorted(self.entries.items()):
            lines.append(f"  {bucket}: {', '.join(communities)}")
        return "\n".join(lines)


# Cisco IOS route-map format:
# route-map NAME permit N
#   match ip address PREFIX-LIST-NAME
#   match community COMMUNITY-LIST
#   set local-preference 200
_ROUTE_MAP_HEADER = re.compile(
    r"^route-map\s+(?P<name>\S+)\s+(?P<action>permit|deny)\s+"
    r"(?P<seq>\d+)\s*$",
    re.MULTILINE,
)
_MATCH_IP = re.compile(
    r"^\s*match\s+ip\s+address\s+(?:prefix-list\s+)?(?P<val>\S+)",
    re.MULTILINE,
)
_MATCH_COMMUNITY = re.compile(
    r"^\s*match\s+community\s+(?P<val>\S+)",
    re.MULTILINE,
)
_SET_LOCAL_PREF = re.compile(
    r"^\s*set\s+local-preference\s+(?P<val>\d+)",
    re.MULTILINE,
)
_SET_METRIC = re.compile(
    r"^\s*set\s+metric\s+(?P<val>\d+)",
    re.MULTILINE,
)
_SET_COMMUNITY = re.compile(
    r"^\s*set\s+community\s+(?P<val>[\d:,\s-]+)",
    re.MULTILINE,
)
_SET_NEXT_HOP = re.compile(
    r"^\s*set\s+ip\s+next-hop\s+(?P<val>\S+)",
    re.MULTILINE,
)
_SET_AS_PATH_PREPEND = re.compile(
    r"^\s*set\s+as-path\s+prepend\s+(?P<val>\S+)",
    re.MULTILINE,
)


def parse_route_maps(output: str) -> list[BgpRouteMap]:
    """Parse ``show route-map`` output into typed records."""
    if not output or not output.strip():
        return []
    matches = list(_ROUTE_MAP_HEADER.finditer(output))
    blocks: list[BgpRouteMap] = []
    for i, m in enumerate(matches):
        body_start = m.end()
        body_end = (
            matches[i + 1].start() if i + 1 < len(matches)
            else len(output)
        )
        body = output[body_start:body_end]
        try:
            action = RouteMapAction(m.group("action"))
        except ValueError:
            action = RouteMapAction.UNKNOWN
        try:
            seq = int(m.group("seq"))
        except ValueError:
            seq = 0
        kwargs: dict[str, object] = {}
        mm = _MATCH_IP.search(body)
        if mm:
            kwargs["match_prefix_list"] = mm.group("val")
        mm = _MATCH_COMMUNITY.search(body)
        if mm:
            kwargs["match_community"] = mm.group("val")
        mm = _SET_LOCAL_PREF.search(body)
        if mm:
            try:
                kwargs["set_local_pref"] = int(mm.group("val"))
            except ValueError:
                pass
        mm = _SET_METRIC.search(body)
        if mm:
            try:
                kwargs["set_metric"] = int(mm.group("val"))
            except ValueError:
                pass
        mm = _SET_COMMUNITY.search(body)
        if mm:
            kwargs["set_community"] = mm.group("val").strip()
        mm = _SET_NEXT_HOP.search(body)
        if mm:
            kwargs["set_next_hop"] = mm.group("val")
        mm = _SET_AS_PATH_PREPEND.search(body)
        if mm:
            kwargs["set_as_path_prepend"] = mm.group("val")
        clause = RouteMapClause(
            sequence=seq,
            action=action,
            **kwargs,  # type: ignore[arg-type]
        )
        existing = next(
            (b for b in blocks if b.name == m.group("name")),
            None,
        )
        if existing is None:
            blocks.append(BgpRouteMap(
                name=m.group("name"),
                clauses=[clause],
            ))
        else:
            existing.clauses.append(clause)
    return blocks


def bucketize_communities(
    route_maps: list[BgpRouteMap],
) -> BgpCommunityReport:
    """Group communities by the route-map that uses them."""
    rep = BgpCommunityReport()
    bucket: dict[str, list[str]] = {}
    for rm in route_maps:
        for c in rm.clauses:
            if c.set_community:
                bucket.setdefault(
                    f"{rm.name}:{c.sequence}", [],
                ).append(c.set_community)
            if c.match_community:
                bucket.setdefault(
                    f"{rm.name}:{c.sequence}", [],
                ).append(f"match:{c.match_community}")
    rep.entries = bucket
    return rep
