"""Tests for the configuration subsystem."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from netops_autopilot.config import (
    Config,
    ConfigError,
    ConsoleProfile,
    DEFAULT_CONFIG,
    NetworkProfile,
    ReportingProfile,
    WebProfile,
    load_config,
    load_config_from_env,
    save_config,
)


# ----------------- Profile validation -----------------


def test_default_config_is_valid():
    assert isinstance(DEFAULT_CONFIG, Config)
    # Round-trip via to_dict
    d = DEFAULT_CONFIG.to_dict()
    assert "console" in d
    assert "network" in d
    assert "web" in d
    assert "reporting" in d


def test_console_profile_rejects_empty_port():
    with pytest.raises(ConfigError):
        ConsoleProfile(port="", baud=9600)


def test_console_profile_rejects_bad_baud():
    with pytest.raises(ConfigError):
        ConsoleProfile(port="COM5", baud=0)


def test_console_profile_rejects_bad_timeouts():
    with pytest.raises(ConfigError):
        ConsoleProfile(port="COM5", baud=9600, connect_timeout_s=0)


def test_network_profile_rejects_bad_autonomy():
    with pytest.raises(ConfigError):
        NetworkProfile(autonomy_mode="M99")


def test_reporting_profile_rejects_empty_output():
    with pytest.raises(ConfigError):
        ReportingProfile(output_dir="")


def test_web_profile_rejects_bad_port():
    with pytest.raises(ConfigError):
        WebProfile(port=0)
    with pytest.raises(ConfigError):
        WebProfile(port=70000)


# ----------------- JSON load/save -----------------


def test_json_round_trip(tmp_path: Path):
    p = tmp_path / "config.json"
    save_config(DEFAULT_CONFIG, p)
    assert p.exists()
    loaded = load_config(p)
    assert loaded == DEFAULT_CONFIG


def test_json_load_partial_overrides(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({
        "console": {"port": "COM7", "baud": 115200},
        "network": {"autonomy_mode": "M2"},
    }))
    cfg = load_config(p)
    assert cfg.console.port == "COM7"
    assert cfg.console.baud == 115200
    assert cfg.network.autonomy_mode == "M2"
    # Other fields use defaults
    assert cfg.web.port == DEFAULT_CONFIG.web.port


def test_json_load_unknown_field_raises(tmp_path: Path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"console": {"port": "x", "unknown_field": 1}}))
    with pytest.raises(ConfigError):
        load_config(p)


# ----------------- YAML load (optional dep) -----------------


def test_yaml_load(tmp_path: Path):
    pytest.importorskip("yaml")
    p = tmp_path / "config.yaml"
    p.write_text(
        "console:\n  port: COM8\n  baud: 115200\nnetwork:\n  autonomy_mode: M2\n"
    )
    cfg = load_config(p)
    assert cfg.console.port == "COM8"
    assert cfg.console.baud == 115200
    assert cfg.network.autonomy_mode == "M2"


def test_yaml_missing_driver_raises_blocked(tmp_path: Path):
    p = tmp_path / "config.yaml"
    p.write_text("console:\n  port: x\n")
    # Force the missing-driver path by ensuring pyyaml isn't installed
    import builtins
    real_import = builtins.__import__
    def _fake(name, *a, **kw):
        if name == "yaml":
            raise ImportError("simulated missing")
        return real_import(name, *a, **kw)
    import pytest as _pt
    monkey = _pt.MonkeyPatch()
    monkey.setattr(builtins, "__import__", _fake)
    try:
        with _pt.raises(ConfigError) as exc:
            load_config(p)
        assert "YAML" in str(exc.value)
    finally:
        monkey.undo()


# ----------------- TOML load -----------------


def test_toml_load(tmp_path: Path):
    p = tmp_path / "config.toml"
    p.write_text(
        '[console]\nport = "COM9"\nbaud = 115200\n'
        '[network]\nautonomy_mode = "M4"\n'
    )
    cfg = load_config(p)
    assert cfg.console.port == "COM9"
    assert cfg.console.baud == 115200
    assert cfg.network.autonomy_mode == "M4"


# ----------------- env var loader -----------------


def test_env_loader_uses_defaults_when_no_vars(monkeypatch):
    for k in list(os.environ):
        if k.startswith("NETOPS_"):
            monkeypatch.delenv(k, raising=False)
    cfg = load_config_from_env()
    assert cfg == DEFAULT_CONFIG


def test_env_loader_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("NETOPS_CONSOLE_PORT", "COM12")
    monkeypatch.setenv("NETOPS_CONSOLE_BAUD", "115200")
    monkeypatch.setenv("NETOPS_AUTONOMY_MODE", "M4")
    monkeypatch.setenv("NETOPS_WEB_PORT", "9000")
    monkeypatch.setenv("NETOPS_WEB_ENABLED", "1")
    monkeypatch.setenv("NETOPS_OUTPUT_DIR", str(tmp_path))
    cfg = load_config_from_env()
    assert cfg.console.port == "COM12"
    assert cfg.console.baud == 115200
    assert cfg.network.autonomy_mode == "M4"
    assert cfg.web.port == 9000
    assert cfg.web.enabled is True
    assert str(cfg.reporting.output_dir) == str(tmp_path)


def test_env_loader_delegates_to_path(monkeypatch, tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({"console": {"port": "COM50"}}))
    monkeypatch.setenv("NETOPS_CONFIG_PATH", str(p))
    cfg = load_config_from_env()
    assert cfg.console.port == "COM50"


# ----------------- Format detection -----------------


def test_unknown_extension_raises(tmp_path: Path):
    p = tmp_path / "config.xml"
    p.write_text("<x/>")
    with pytest.raises(ConfigError):
        load_config(p)


def test_missing_file_raises(tmp_path: Path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.json")
