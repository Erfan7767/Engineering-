"""Config Renderer — Config IR ⇒ per-vendor command PREVIEW (data-driven).

Renders the vendor-neutral IR to concrete CLI text using the renderer data
files (``specs/data/renderers/*.json``). Honesty contract:

* a feature with no template for the device's vendor_os is a typed
  ``NOT_MODELED`` entry, never skipped silently (T2);
* templates flagged ``verified: false`` produce output labeled PREVIEW —
  the law still blocks application (CONFIG allowlist classes are empty
  seeds, T3) and labels keep that truth attached to every document;
* unknown parameters raise ``BLOCKED`` at render input validation —
  the renderer never fabricates a command shape.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from ..core.failures import Failure, FailureClass
from ..specs_data import specs_data_dir
from .config_ir import ConfigIR

_RENDERER_FILES = {
    "ios-xe": "cisco_iosxe.json",
    "ios": "cisco_iosxe.json",
    "routeros": "routeros.json",
    "junos": "junos.json",
}


@dataclass(frozen=True)
class RenderedBlock:
    node_id: str
    status: str                    # RENDERED | NOT_MODELED
    commands: tuple[str, ...]
    reason: str = ""


@dataclass(frozen=True)
class RenderedConfig:
    device_ref: str
    vendor_os: str
    verified_templates: bool
    label: str                     # PREVIEW_SEED_UNVERIFIED
    blocks: tuple[RenderedBlock, ...]
    wrappers: tuple[str, ...]

    def to_text(self) -> str:
        lines = [f"! {self.label} — device={self.device_ref} vendor_os={self.vendor_os}"]
        enter, exit_ = self.wrappers
        rendered_any = any(b.status == "RENDERED" for b in self.blocks)
        if not rendered_any:
            lines.append("! NO RENDERABLE NODES: every feature NOT_MODELED for this vendor_os (T2)")
            return "\n".join(lines)
        lines.extend(enter)
        for block in self.blocks:
            if block.status != "RENDERED":
                lines.append(f"! NOT_MODELED node={block.node_id}: {block.reason}")
                continue
            lines.extend(block.commands)
        lines.extend(exit_)
        return "\n".join(lines)


def _load_renderer(vendor_os: str) -> dict:
    filename = _RENDERER_FILES.get(vendor_os)
    if filename is None:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"RENDERER_NOT_MODELED: no renderer data for vendor_os={vendor_os!r} (T2)",))
    path_text = specs_data_dir("renderers", filename)
    if not path_text:
        raise Failure(cls=FailureClass.BLOCKED, causes=(
            f"RENDERER_DATA_ABSENT: {filename} missing from specs data pack",))
    return json.loads(open(path_text, encoding="utf-8").read())


def render_ir(device_ref: str, ir: ConfigIR) -> RenderedConfig:
    if not ir.nodes:
        raise Failure(cls=FailureClass.BLOCKED, causes=("RENDER_EMPTY_IR",))
    os_name = ir.nodes[0].vendor_os
    data = _load_renderer(os_name)
    features = data.get("features", {})
    wrappers_data = data.get("wrappers", {})
    blocks: list[RenderedBlock] = []
    prelude_done: set[str] = set()
    for node in ir.nodes:
        template = features.get(node.feature)
        if template is None:
            blocks.append(RenderedBlock(node_id=node.node_id, status="NOT_MODELED",
                                        commands=(),
                                        reason=f"feature {node.feature!r} has no template for {os_name} (T2)"))
            continue
        params = {k: v for k, v in node.parameters.items() if k != "reason"}
        if "allowed_vlans" in params and params["allowed_vlans"] is not None:
            params["allowed_vlans_csv"] = ",".join(str(v) for v in params["allowed_vlans"])
        try:
            commands = tuple(cmd.format(**{k: _fmt(v) for k, v in params.items()})
                             for cmd in template.get("commands", ()))
            prelude: tuple[str, ...] = ()
            if node.feature not in prelude_done:
                prelude = tuple(cmd.format(**{k: _fmt(v) for k, v in params.items()})
                                for cmd in template.get("prelude", ()))
                prelude_done.add(node.feature)
        except (KeyError, AttributeError) as exc:
            blocks.append(RenderedBlock(node_id=node.node_id, status="NOT_MODELED",
                                        commands=(),
                                        reason=f"template parameter unbound: {exc} (T2)"))
            continue
        blocks.append(RenderedBlock(node_id=node.node_id, status="RENDERED",
                                    commands=prelude + commands))
    wrappers = (tuple(wrappers_data.get("enter_config", ())),
                tuple(wrappers_data.get("exit_config", ())))
    verified = bool(data.get("verified", False))
    label = "RENDER-VERIFIED" if verified else "PREVIEW_SEED_UNVERIFIED"
    return RenderedConfig(device_ref=device_ref, vendor_os=os_name,
                          verified_templates=verified, label=label,
                          blocks=tuple(blocks), wrappers=wrappers)


def _fmt(value) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value)
    return str(value)
