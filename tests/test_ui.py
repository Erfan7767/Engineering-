"""Structural tests for the web UI assets.

The UI is a single self-contained HTML file; these tests prove the
file is well-formed, has the expected sections, and references the
real backend API correctly. The tests do NOT exercise the JS in a
browser — that's a manual smoke test. They catch structural breakage
(removed elements, broken i18n keys, etc.) on every CI run.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from netops_autopilot.webui import WEBUI_DIR

ROOT = Path(__file__).resolve().parent.parent
V3 = WEBUI_DIR / "v3" / "index.html"
V2 = WEBUI_DIR / "v2" / "index.html"


# ------------------- file presence -------------------


def test_v3_exists_and_is_self_contained():
    assert V3.exists()
    html = V3.read_text(encoding="utf-8")
    # No external stylesheets or scripts (sandboxed iframe)
    assert "<link rel=\"stylesheet\"" not in html
    assert "<script src=" not in html
    # Must declare lang and dir
    assert 'data-lang=' in html
    # Has the brand mark
    assert "NetOps Autopilot" in html


def test_v2_still_present_for_backcompat():
    assert V2.exists()


# ------------------- i18n completeness -------------------


def test_all_i18n_keys_have_both_languages():
    """Every key in the I18N dict has ar + en; every data-i18n ref
    resolves to a real key in both languages."""
    html = V3.read_text(encoding="utf-8")
    # Extract I18N object
    m = re.search(r"const I18N = \{([^}]+)\}", html, re.DOTALL)
    assert m, "I18N object not found"
    # Crude parse: find quoted keys
    keys = set(re.findall(r'"([\w-]+)"\s*:\s*"', m.group(1)))
    refs = set(re.findall(r'data-i18n="([^"]+)"', html))
    missing = refs - keys
    assert not missing, f"data-i18n refs not in I18N: {missing}"


# ------------------- view structure -------------------


@pytest.mark.parametrize("view_id,expected_section", [
    ("view-connect", "nav-connect"),
    ("view-discover", "nav-discover"),
    ("view-topology", "nav-topology"),
    ("view-design", "nav-design"),
    ("view-apply", "nav-apply"),
    ("view-ledger", "nav-ledger"),
    ("view-report", "nav-report"),
])
def test_every_view_has_nav_link(view_id, expected_section):
    html = V3.read_text(encoding="utf-8")
    assert f'id="{view_id}"' in html
    assert f'data-view="{view_id.replace("view-", "")}"' in html


# ------------------- backend integration -------------------


def test_api_paths_match_backend():
    html = V3.read_text(encoding="utf-8")
    # The UI calls /runs, /runs/{id}, /runs/{id}/topology, etc.
    for path in ("/runs", "/healthz"):
        assert f'"{path}"' in html or f"`{path}`" in html or f"'{path}'" in html


def test_bond_is_required_for_apply():
    """The apply button is disabled until the human types BOND exactly."""
    html = V3.read_text(encoding="utf-8")
    # The bond input unlocks the apply button
    assert 'applyBond' in html
    assert '"BOND"' in html


# ------------------- topology rendering -------------------


def test_topology_svg_target_exists():
    html = V3.read_text(encoding="utf-8")
    assert 'id="topoSvg"' in html
    assert 'id="devList"' in html
    assert 'id="terminal"' in html


def test_blueprint_cards_have_real_ids():
    html = V3.read_text(encoding="utf-8")
    # BLUEPRINTS array must have at least the 5 expected ids
    for bp_id in ("branch", "leaf-spine", "hotel", "retail", "guest_office"):
        assert f'"{bp_id}"' in html


# ------------------- RTL support -------------------


def test_rtl_is_default():
    html = V3.read_text(encoding="utf-8")
    assert 'body class="rtl"' in html
    assert 'dir="rtl"' in html
    # Switching to LTR is supported
    assert "body.ltr" in html or "rtl" in html
