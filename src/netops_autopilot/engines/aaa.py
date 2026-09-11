"""AAA / TACACS+ / RADIUS Audit.

A 30-year engineer runs AAA everywhere: SSH only via
TACACS+, console fallback to local, RADIUS for 802.1X.
This module is the typed implementation: parse Cisco
``show aaa`` / ``show tacacs`` output, surface typed
:class:`AaaServer` records and a typed :class:`AaaReport`
with findings (local fallback only, no TACACS, etc.).

Design contract:

* **Typed** — every record is a dataclass.
* **Deterministic** — same input → same output.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AaaServer:
    __test__ = False

    host: str
    server_type: str = "tacacs+"      # tacacs+ / radius / ldap
    port: int = 49
    is_reachable: bool = False
    timeout_seconds: int = 5
    encrypted: bool = True


@dataclass(frozen=True)
class AaaFinding:
    __test__ = False

    kind: str          # "no_tacacs" / "local_only" / "unencrypted"
    detail: str


@dataclass
class AaaReport:
    __test__ = False

    device: str
    servers: list[AaaServer] = field(default_factory=list)
    findings: list[AaaFinding] = field(default_factory=list)
    uses_local_fallback: bool = False
    aaa_new_model: bool = False

    @property
    def server_count(self) -> int:
        return len(self.servers)

    @property
    def reachable_count(self) -> int:
        return sum(1 for s in self.servers if s.is_reachable)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            return (
                f"AAA: {self.server_count} خادم، "
                f"{self.reachable_count} قابل للوصول، "
                f"{self.finding_count} مشكلة"
            )
        return (
            f"AAA: {self.server_count} server(s), "
            f"{self.reachable_count} reachable, "
            f"{self.finding_count} finding(s)"
        )


_TACACS = re.compile(
    r"(?P<host>\d+\.\d+\.\d+\.\d+)\s+"
    r"\{\s*(?P<port>\d+)\s+(?P<key>\S+)\s+(?P<timeout>\d+)\s*\}",
)
_LOCAL = re.compile(
    r"^\s*aaa\s+authentication\s+login\s+\S+\s+local",
    re.MULTILINE,
)
_AAA_NEW_MODEL = re.compile(
    r"^\s*aaa\s+new-model",
    re.MULTILINE,
)


def parse_cisco_aaa(
    device: str,
    output: str,
) -> AaaReport:
    """Parse Cisco ``show tacacs`` / ``show aaa servers`` output."""
    rep = AaaReport(device=device)
    if not output or not output.strip():
        return rep
    rep.aaa_new_model = bool(_AAA_NEW_MODEL.search(output))
    rep.uses_local_fallback = bool(_LOCAL.search(output))
    for m in _TACACS.finditer(output):
        try:
            port = int(m.group("port"))
            timeout = int(m.group("timeout"))
        except ValueError:
            port = 49
            timeout = 5
        rep.servers.append(AaaServer(
            host=m.group("host"),
            server_type="tacacs+",
            port=port,
            is_reachable=False,  # requires live probe
            timeout_seconds=timeout,
            encrypted=bool(m.group("key")),
        ))
    # Findings.
    if rep.server_count == 0:
        rep.findings.append(AaaFinding(
            kind="no_tacacs",
            detail="No TACACS+ server configured.",
        ))
    if rep.uses_local_fallback and not rep.aaa_new_model:
        rep.findings.append(AaaFinding(
            kind="local_only",
            detail="Local-only authentication (no AAA new-model).",
        ))
    if not rep.aaa_new_model:
        rep.findings.append(AaaFinding(
            kind="no_aaa_new_model",
            detail="aaa new-model not enabled.",
        ))
    return rep
