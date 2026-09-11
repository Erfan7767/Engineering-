"""Web UI package — the static single-page web interface.

The actual HTML/JS/CSS lives in ``webui/index.html`` (next to the
``src/netops_autopilot/`` tree) so it can be served by the FastAPI app
or opened directly from disk.
"""
from pathlib import Path

WEBUI_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent / "webui"


def webui_index_path() -> Path:
    """Return the absolute path to ``webui/index.html``."""
    return WEBUI_DIR / "index.html"
