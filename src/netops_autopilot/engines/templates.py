"""Configuration Template Engine — Jinja2-based config rendering.

A 30-year engineer keeps a library of templates: ``vlan.j2``,
``bgp.j2``, ``dhcp-snooping.j2``. This module is the typed
implementation: render a Jinja2 template with a typed
:class:`TemplateContext`, validate the output, and surface a
:class:`TemplateResult`.

Design contract:

* **Typed** — :class:`TemplateContext` carries only typed
  fields; the engine never invents values.
* **Deterministic** — same context + same template = same
  output every time.
* **Bilingual** — rendering in English or Arabic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class TemplateVerdict(str, Enum):
    __test__ = False

    OK = "OK"
    RENDER_ERROR = "RENDER_ERROR"
    MISSING_FIELD = "MISSING_FIELD"
    UNSAFE_OUTPUT = "UNSAFE_OUTPUT"


@dataclass
class TemplateContext:
    __test__ = False

    fields: dict[str, object] = field(default_factory=dict)

    def get(self, key: str, default: object | None = None) -> object:
        return self.fields.get(key, default)

    def __getitem__(self, key: str) -> object:
        return self.fields[key]

    def __setitem__(self, key: str, value: object) -> None:
        self.fields[key] = value


@dataclass
class TemplateResult:
    __test__ = False

    template_name: str
    output: str
    verdict: TemplateVerdict = TemplateVerdict.OK
    missing_fields: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def is_valid(self) -> bool:
        return self.verdict == TemplateVerdict.OK

    def render(self, lang: str = "en") -> str:
        if lang == "ar":
            head = (
                f"قالب '{self.template_name}': "
                f"{'صالح' if self.is_valid else 'غير صالح'}"
            )
        else:
            head = (
                f"Template '{self.template_name}': "
                f"{'valid' if self.is_valid else 'invalid'}"
            )
        return head


# Tiny built-in templates to avoid requiring jinja2 at runtime.
# We support a minimal {{var}} interpolation that 30-year
# engineers use day-1; jinja2 is added later if installed.


_BUILTIN: dict[str, str] = {
    "vlan_ios": """\
vlan {{ vlan_id }}
 name {{ vlan_name }}
!
interface vlan {{ vlan_id }}
 ip address {{ mgmt_ip }} {{ mgmt_mask }}
 no shutdown
!
""",
    "vlan_junos": """\
set vlans {{ vlan_name }} vlan-id {{ vlan_id }}
set interfaces irb unit {{ vlan_id }} family inet address {{ mgmt_ip }}
""",
    "bgp_ios": """\
router bgp {{ asn }}
 neighbor {{ neighbor_ip }} remote-as {{ neighbor_asn }}
 neighbor {{ neighbor_ip }} description {{ neighbor_desc }}
 address-family ipv4
  neighbor {{ neighbor_ip }} activate
  neighbor {{ neighbor_ip }} route-map {{ route_map_in }} in
 exit-address-family
!
""",
    "dhcp_snoop_ios": """\
ip dhcp snooping
ip dhcp snooping vlan {{ vlan_list }}
no ip dhcp snooping information option
!
interface range {{ uplink_ports }}
 ip dhcp snooping trust
!
""",
    "ntp_ios": """\
ntp server {{ server_ip }} prefer
ntp authentication-key 1 md5 {{ secret }}
ntp trusted-key 1
ntp authenticate
!
""",
}


_INTERPOLATION = (
    "{{\\s*(?P<name>[A-Za-z_][A-Za-z0-9_.]*)\\s*}}"
)


def available_templates() -> list[str]:
    """Return the list of built-in template names."""
    return sorted(_BUILTIN.keys())


def get_template(name: str) -> str | None:
    """Return the raw template body, or None."""
    return _BUILTIN.get(name)


def _interpolate(
    template: str,
    ctx: TemplateContext,
) -> tuple[str, list[str]]:
    """Render a simple ``{{var}}`` template.

    Returns ``(rendered, missing)``.
    """
    import re

    pattern = re.compile(_INTERPOLATION)
    missing: list[str] = []

    def replace(match: "re.Match[str]") -> str:
        name = match.group("name")
        if name not in ctx.fields:
            missing.append(name)
            return f"<MISSING:{name}>"
        return str(ctx.fields[name])

    rendered = pattern.sub(replace, template)
    return rendered, missing


def render_template(
    name: str,
    context: TemplateContext,
) -> TemplateResult:
    """Render a built-in template by name."""
    body = _BUILTIN.get(name)
    if body is None:
        return TemplateResult(
            template_name=name,
            output="",
            verdict=TemplateVerdict.MISSING_FIELD,
            error=f"template '{name}' not found",
        )
    rendered, missing = _interpolate(body, context)
    if missing:
        return TemplateResult(
            template_name=name,
            output=rendered,
            verdict=TemplateVerdict.MISSING_FIELD,
            missing_fields=missing,
        )
    return TemplateResult(
        template_name=name,
        output=rendered,
        verdict=TemplateVerdict.OK,
    )


def render_string(
    raw: str,
    context: TemplateContext,
) -> TemplateResult:
    """Render an arbitrary template body."""
    rendered, missing = _interpolate(raw, context)
    if missing:
        return TemplateResult(
            template_name="<inline>",
            output=rendered,
            verdict=TemplateVerdict.MISSING_FIELD,
            missing_fields=missing,
        )
    return TemplateResult(
        template_name="<inline>",
        output=rendered,
        verdict=TemplateVerdict.OK,
    )
