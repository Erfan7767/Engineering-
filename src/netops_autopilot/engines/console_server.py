"""Out-of-band Console Server Integration.

A 30-year engineer keeps a terminal server (Cisco 2509,
Opengear, Raritan) for out-of-band access to every device.
When SSH fails, the console server is the fallback. This
module is the typed implementation: take a typed
:class:`ConsoleServerConfig` and a device reference,
return a typed :class:`ConsolePath` (TCP port to dial).

Design contract:

* **Typed** — :class:`ConsoleServerConfig` /
  :class:`ConsolePath` are dataclasses.
* **Deterministic** — same input → same path.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ConsoleServerConfig:
    __test__ = False

    host: str
    base_port: int = 2000    # Cisco 2509 convention
    port_stride: int = 1
    max_ports: int = 64
    label_format: str = "{device}"

    def path_for(
        self,
        device_ref: str,
        port_index: int,
    ) -> "ConsolePath":
        """Build a typed :class:`ConsolePath`."""
        return ConsolePath(
            host=self.host,
            port=self.base_port + (
                port_index * self.port_stride
            ),
            label=self.label_format.format(
                device=device_ref,
            ),
            device_ref=device_ref,
        )


@dataclass(frozen=True)
class ConsolePath:
    __test__ = False

    host: str
    port: int
    label: str
    device_ref: str

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"OOB: telnet {self.host} {self.port} "
                f"({self.label})"
            )
        return (
            f"OOB: telnet {self.host} {self.port} "
            f"({self.label})"
        )


@dataclass
class ConsoleServerInventory:
    __test__ = False

    config: ConsoleServerConfig
    paths: list[ConsolePath] = field(default_factory=list)

    @property
    def path_count(self) -> int:
        return len(self.paths)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"خادم وحدة التحكم: {self.path_count} منفذ "
                f"على {self.config.host}"
            )
        return (
            f"Console server: {self.path_count} port(s) "
            f"on {self.config.host}"
        )


def build_inventory(
    config: ConsoleServerConfig,
    devices: list[str],
) -> ConsoleServerInventory:
    """Build a typed inventory of OOB paths for ``devices``."""
    inv = ConsoleServerInventory(config=config)
    for i, device_ref in enumerate(devices):
        if i >= config.max_ports:
            break
        inv.paths.append(config.path_for(
            device_ref=device_ref,
            port_index=i,
        ))
    return inv
