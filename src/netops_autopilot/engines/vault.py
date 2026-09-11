"""Credential Vault — typed device credential storage.

A 30-year engineer keeps device credentials in a vault.
This module is the typed implementation: in-memory store of
:class:`DeviceCredentials`, with a typed lookup and a
typed :class:`VaultReport`. Designed to be backed by an
OS keyring in production; the in-memory path is used for
tests and stateless deployments.

Design contract:

* **Typed** — :class:`DeviceCredentials` is a frozen
  dataclass; no string-typed dicts.
* **Bilingual** — rendering in English or Arabic.
* **No leak** — credentials are never printed in clear
  text, only their redacted form.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DeviceCredentials:
    __test__ = False

    device_ref: str
    username: str
    password: str = ""
    enable_password: str = ""
    snmp_community: str = ""

    def redact(self) -> str:
        """Return a redacted representation safe for logs."""
        pw = (
            "***" if self.password else "(none)"
        )
        en = (
            "***" if self.enable_password else "(none)"
        )
        sn = (
            "***" if self.snmp_community else "(none)"
        )
        return (
            f"device={self.device_ref} user={self.username} "
            f"password={pw} enable={en} snmp={sn}"
        )


@dataclass
class Vault:
    __test__ = False

    _creds: dict[str, DeviceCredentials] = field(default_factory=dict)

    def add(self, creds: DeviceCredentials) -> None:
        """Add / replace credentials for a device."""
        self._creds[creds.device_ref] = creds

    def get(self, device_ref: str) -> DeviceCredentials | None:
        return self._creds.get(device_ref)

    def remove(self, device_ref: str) -> bool:
        return self._creds.pop(device_ref, None) is not None

    @property
    def device_count(self) -> int:
        return len(self._creds)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"الخزنة: {self.device_count} جهاز، "
                f"بيانات اعتماد مخزنة"
            )
        return (
            f"Vault: {self.device_count} device(s) with credentials"
        )


@dataclass
class VaultReport:
    __test__ = False

    vault: Vault
    missing_devices: tuple[str, ...] = ()

    @property
    def overall_verdict(self) -> str:
        if not self.missing_devices:
            return "COMPLETE"
        return f"MISSING:{len(self.missing_devices)}"

    def render(self, lang: str = "en") -> str:
        head = self.vault.render(lang=lang)
        if self.missing_devices:
            head += (
                f"\n  Missing: {', '.join(self.missing_devices)}"
            )
        return head
