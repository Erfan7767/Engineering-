"""Web UI package — the static single-page web interface.

The HTML/JS/CSS lives in ``webui/static/`` **inside this package**. It used to
live at the repository root, reached by walking four ``.parent`` levels out of
the source tree. That worked from a checkout and silently broke the moment the
package was installed: a wheel ships only what is inside a package, so the
served app started, answered every request with ``404 {"detail":"Not Found"}``
and looked healthy while the interface was gone. Keeping the assets next to
the code that serves them makes "installed" and "works" the same statement.
"""
from pathlib import Path

#: The packaged static tree. Always inside the importable package, so it
#: survives wheel, editable and zip installation alike.
WEBUI_DIR: Path = Path(__file__).resolve().parent / "static"


def webui_index_path() -> Path:
    """Return the absolute path to the shipped ``index.html``."""
    return WEBUI_DIR / "index.html"
