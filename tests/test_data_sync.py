"""Data integrity: package-embedded copies must stay byte-identical to their
sources of truth under specs/data (the D0-02 anti-drift pattern)."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

PAIRS = (
    ("specs/data/authority_table.json", "src/netops_autopilot/policy/data/authority_table.json"),
    ("specs/data/defaults_db/platform_defaults.json", "src/netops_autopilot/reconcile/data/platform_defaults.json"),
    ("specs/data/capability/protocol_feature_matrix.json", "src/netops_autopilot/engines/data/protocol_feature_matrix.json"),
    ("specs/data/capability/recovery_matrix.json", "src/netops_autopilot/engines/data/recovery_matrix.json"),
    ("specs/data/defaults_db/service_dependencies.json", "src/netops_autopilot/engines/data/service_dependencies.json"),
    ("specs/schemas/agent_output.schema.json", "src/netops_autopilot/agents/data/agent_output.schema.json"),
    ("specs/data/allowlists/cisco_iosxe.json", "src/netops_autopilot/agents/data/allowlists/cisco_iosxe.json"),
    ("specs/data/allowlists/routeros.json", "src/netops_autopilot/agents/data/allowlists/routeros.json"),
    ("specs/data/allowlists/junos.json", "src/netops_autopilot/agents/data/allowlists/junos.json"),
    ("specs/data/allowlists/fortios.json", "src/netops_autopilot/agents/data/allowlists/fortios.json"),
    ("specs/data/allowlists/arubaos.json", "src/netops_autopilot/agents/data/allowlists/arubaos.json"),
    ("specs/data/allowlists/unifi.json", "src/netops_autopilot/agents/data/allowlists/unifi.json"),
    # Renderers were NOT in this list, and the three embedded copies had drifted
    # far enough to assert verified=true for Junos and RouterOS while the source
    # of truth says, in so many words, that no configuration fixture exists in
    # this repository to verify against. A stale copy claiming lab-verification
    # is worse than a missing one, so every renderer is covered now.
    ("specs/data/renderers/cisco_iosxe.json", "src/netops_autopilot/agents/data/cisco_iosxe.json"),
    ("specs/data/renderers/routeros.json", "src/netops_autopilot/agents/data/routeros.json"),
    ("specs/data/renderers/junos.json", "src/netops_autopilot/agents/data/junos.json"),
    ("specs/data/renderers/arubaos.json", "src/netops_autopilot/agents/data/arubaos.json"),
    ("specs/data/renderers/fortios.json", "src/netops_autopilot/agents/data/fortios.json"),
)


@pytest.mark.parametrize("source,embedded", PAIRS)
def test_embedded_data_matches_source_of_truth(source, embedded):
    src = (ROOT / source).read_bytes()
    dst = (ROOT / embedded).read_bytes()
    assert src == dst, f"{embedded} drifted from {source} — re-sync and record a register entry"
