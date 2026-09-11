"""Configuration loader for NetOps Autopilot.

* **Format auto-detection:** .yaml/.yml → YAML, .toml → TOML, .json → JSON.
* **Optional dependencies:** PyYAML and tomllib/tomli are loaded lazily;
  missing drivers yield a typed error with install instructions.
* **Schema-validated:** every loaded config is checked against
  :class:`Config` invariants.
* **Deterministic defaults:** :data:`DEFAULT_CONFIG` is the single source
  of truth for the platform's defaults.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Optional

from ..core.failures import Failure, FailureClass


class ConfigError(Failure):
    """A typed configuration error."""

    def __init__(self, causes: tuple[str, ...]) -> None:
        super().__init__(cls=FailureClass.BLOCKED, causes=causes)


@dataclass(frozen=True)
class ConsoleProfile:
    port: str = "COM5"
    baud: int = 9600
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 30.0

    def __post_init__(self) -> None:
        if not self.port:
            raise ConfigError(("CONFIG_CONSOLE_PORT_EMPTY",))
        if self.baud <= 0:
            raise ConfigError(("CONFIG_CONSOLE_BAUD_INVALID",))
        if self.connect_timeout_s <= 0 or self.read_timeout_s <= 0:
            raise ConfigError(("CONFIG_CONSOLE_TIMEOUT_INVALID",))


@dataclass(frozen=True)
class NetworkProfile:
    default_blueprint: str = "branch_office"
    site_block_v4: str = "10.240.0.0/16"
    availability: str = "STANDARD"
    growth: str = "+25% in 12 months"
    autonomy_mode: str = "M3"          # M1..M5

    def __post_init__(self) -> None:
        if self.autonomy_mode not in {"M1", "M2", "M3", "M4", "M5"}:
            raise ConfigError((f"CONFIG_AUTONOMY_MODE_INVALID:{self.autonomy_mode}",))


@dataclass(frozen=True)
class ReportingProfile:
    output_dir: str = "./reports"
    emit_html: bool = True
    emit_json: bool = True
    pretty_json: bool = True

    def __post_init__(self) -> None:
        if not self.output_dir:
            raise ConfigError(("CONFIG_OUTPUT_DIR_EMPTY",))


@dataclass(frozen=True)
class WebProfile:
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 8765
    static_dir: Optional[str] = None

    def __post_init__(self) -> None:
        if self.port <= 0 or self.port > 65535:
            raise ConfigError((f"CONFIG_WEB_PORT_INVALID:{self.port}",))


@dataclass(frozen=True)
class Config:
    console: ConsoleProfile = field(default_factory=ConsoleProfile)
    network: NetworkProfile = field(default_factory=NetworkProfile)
    reporting: ReportingProfile = field(default_factory=ReportingProfile)
    web: WebProfile = field(default_factory=WebProfile)
    vendor_priority: tuple[str, ...] = (
        "cisco/ios-xe", "junos", "routeros", "fortios", "arubaos", "unifi",
    )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "console": asdict(self.console),
            "network": asdict(self.network),
            "reporting": asdict(self.reporting),
            "web": asdict(self.web),
            "vendor_priority": list(self.vendor_priority),
        }
        return d


DEFAULT_CONFIG = Config()


# ----------------- Loaders -----------------


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ConfigError(("CONFIG_YAML_DRIVER_MISSING: `pip install pyyaml` to load YAML configs",)) from exc
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _load_toml(path: Path) -> dict[str, Any]:
    # Python 3.11+ has tomllib (read-only).
    try:
        import tomllib  # type: ignore[import-not-found]
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[import-not-found, no-redef]
        except ImportError as exc:
            raise ConfigError(
                ("CONFIG_TOML_DRIVER_MISSING: Python 3.11+ has tomllib built-in; older versions need `pip install tomli`",),
            ) from exc
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _load_json(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _build_config(d: dict[str, Any]) -> Config:
    """Construct a ``Config`` from a (possibly partial) dict, merging with defaults."""
    console_raw = d.get("console", {})
    network_raw = d.get("network", {})
    reporting_raw = d.get("reporting", {})
    web_raw = d.get("web", {})
    vendor_priority = tuple(d.get("vendor_priority", DEFAULT_CONFIG.vendor_priority))
    try:
        return Config(
            console=ConsoleProfile(**console_raw) if console_raw else ConsoleProfile(),
            network=NetworkProfile(**network_raw) if network_raw else NetworkProfile(),
            reporting=ReportingProfile(**reporting_raw) if reporting_raw else ReportingProfile(),
            web=WebProfile(**web_raw) if web_raw else WebProfile(),
            vendor_priority=vendor_priority,
        )
    except TypeError as exc:
        raise ConfigError((f"CONFIG_FIELD_UNKNOWN:{exc}",)) from exc


def load_config(path: str | Path) -> Config:
    """Load a config from disk. Format is auto-detected from the extension."""
    p = Path(path)
    if not p.exists():
        raise ConfigError((f"CONFIG_NOT_FOUND:{p}",))
    suffix = p.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        data = _load_yaml(p)
    elif suffix == ".toml":
        data = _load_toml(p)
    elif suffix == ".json":
        data = _load_json(p)
    else:
        raise ConfigError((f"CONFIG_FORMAT_UNSUPPORTED:{suffix}",))
    return _build_config(data)


def save_config(config: Config, path: str | Path) -> None:
    """Save a config to disk (YAML or JSON based on extension)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ConfigError(("CONFIG_YAML_DRIVER_MISSING: `pip install pyyaml`",)) from exc
        with open(p, "w", encoding="utf-8") as fh:
            yaml.safe_dump(config.to_dict(), fh, sort_keys=False)
    else:
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(config.to_dict(), fh, indent=2, ensure_ascii=False)


def load_config_from_env() -> Config:
    """Build a Config from environment variables (or defaults).

    Recognized variables:
    - ``NETOPS_CONSOLE_PORT``
    - ``NETOPS_CONSOLE_BAUD``
    - ``NETOPS_AUTONOMY_MODE``
    - ``NETOPS_WEB_PORT``
    - ``NETOPS_WEB_ENABLED`` ("1"/"0")
    - ``NETOPS_OUTPUT_DIR``
    - ``NETOPS_CONFIG_PATH`` — if set, delegates to :func:`load_config`.
    """
    cfg_path = os.environ.get("NETOPS_CONFIG_PATH")
    if cfg_path:
        return load_config(cfg_path)
    base = DEFAULT_CONFIG
    console = base.console
    port = os.environ.get("NETOPS_CONSOLE_PORT")
    if port:
        console = ConsoleProfile(
            port=port,
            baud=int(os.environ.get("NETOPS_CONSOLE_BAUD", console.baud)),
            connect_timeout_s=console.connect_timeout_s,
            read_timeout_s=console.read_timeout_s,
        )
    network = base.network
    mode = os.environ.get("NETOPS_AUTONOMY_MODE")
    if mode:
        network = NetworkProfile(
            default_blueprint=network.default_blueprint,
            site_block_v4=network.site_block_v4,
            availability=network.availability,
            growth=network.growth,
            autonomy_mode=mode,
        )
    reporting = base.reporting
    out = os.environ.get("NETOPS_OUTPUT_DIR")
    if out:
        reporting = ReportingProfile(
            output_dir=out,
            emit_html=reporting.emit_html,
            emit_json=reporting.emit_json,
            pretty_json=reporting.pretty_json,
        )
    web = base.web
    web_enabled = os.environ.get("NETOPS_WEB_ENABLED")
    if web_enabled is not None:
        web = WebProfile(
            enabled=web_enabled == "1",
            host=web.host,
            port=int(os.environ.get("NETOPS_WEB_PORT", web.port)),
            static_dir=web.static_dir,
        )
    return Config(console=console, network=network, reporting=reporting, web=web)
