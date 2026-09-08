"""Parser catalog — the default registry for all v1 golden parsers.

One import point for engines/tests; registration order is fixed so the
catalog is deterministic across runs.
"""

from __future__ import annotations

from .cisco_show_version import CiscoIosXeShowVersionParser
from .keyvalue import routeros_system_resource
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
    junos_show_version,
    fortios_get_system_status,
    arubaos_show_version,
    UnifiDeviceJsonParser,
)


def default_registry() -> ParserRegistry:
    registry = ParserRegistry()
    for builder in CATALOG_BUILDERS:
        registry.register(builder())
    return registry
