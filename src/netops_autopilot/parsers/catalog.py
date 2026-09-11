"""Parser catalog — the default registry for all v1 golden parsers.

One import point for engines/tests; registration order is fixed so the
catalog is deterministic across runs.
"""

from __future__ import annotations

from .cisco_show_version import CiscoIosXeShowVersionParser
from .interface_inventory import CiscoIosXeInterfacesStatusParser
from .keyvalue import routeros_system_resource
from .neighbor_parsers import NEIGHBOR_CATALOG_BUILDERS
from .registry import ParserRegistry
from .vendor_parsers import (
    UnifiDeviceJsonParser,
    arubaos_show_version,
    fortios_get_system_status,
    junos_show_version,
)

#: All golden parsers of the v1 catalog, in fixed order.
CATALOG_BUILDERS = (
    routeros_system_resource,
    CiscoIosXeShowVersionParser,
    CiscoIosXeInterfacesStatusParser,
    junos_show_version,
    fortios_get_system_status,
    arubaos_show_version,
    UnifiDeviceJsonParser,
    *NEIGHBOR_CATALOG_BUILDERS,
)


#: Family vocabulary aliases (outer data vocabulary → canonical parser
#: families). The platform's two namings (access-profile style vs parser
#: style) meet HERE, as data — never as conditionals scattered in engines.
FAMILY_ALIASES: dict[str, tuple[str, ...]] = {
    "cisco/ios-xe": ("cisco/ios-xe",),
    "routeros": ("mikrotik/routeros",),
    "junos": ("juniper/junos",),
    "fortios": ("fortinet/fortios",),
    "arubaos": ("aruba/arubaos",),
    "unifi": ("ubiquiti/unifi",),
}


def canonical_families(family: str) -> tuple[str, ...]:
    """Alias resolution; unknown family ⇒ its own name only (no guessing)."""
    return FAMILY_ALIASES.get(family, (family,))


def default_registry() -> ParserRegistry:
    registry = ParserRegistry()
    for builder in CATALOG_BUILDERS:
        registry.register(builder())
    return registry
