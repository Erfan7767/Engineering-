"""What `pip install netops-autopilot` must leave behind is a working program.

Four separate defects, all invisible from a repository checkout and all
verified against a real wheel built into a clean virtualenv:

1. **No command.** ``[project.scripts]`` was absent, so ``pip install`` left
   nothing on ``PATH``. The package installed cleanly and could only be reached
   as ``python -m netops_autopilot`` — a form its own ``--help`` text never
   mentioned, because every example in it says ``netops-autopilot``.

2. **No data.** ``packages.find`` collected Python modules and nothing else.
   The wheel held 195 ``.py`` files and zero data files, so:
   ``demo`` died with ``FileNotFoundError: .../fixtures/golden/cisco_iosxe/
   show_version.txt`` — a traceback naming a path inside ``site-packages`` that
   told the operator nothing — and ``engines/data/service_dependencies.json``
   was missing too.

3. **No interface.** ``webui/`` lived at the repository root, reached by walking
   four ``.parent`` levels out of the source tree. Installed, that resolved to
   nothing: uvicorn reported ``Application startup complete`` and then answered
   ``GET /`` with ``404 {"detail":"Not Found"}``. A control surface that starts
   cleanly and serves nothing is worse than one that refuses to start.

4. **No knowledge base.** The vendor allowlists, banner markers, capability
   matrix and renderer specs live in ``specs/data/``. ``specs_data_dir`` already
   probes ``sysconfig['data']/netops_autopilot_specs`` for exactly this case,
   but nothing ever put files there — so an installed package resolved every
   vendor fact to a typed BLOCKED and could not plan one crawl command.
   Shipping the pack into the directory the locator already looks in closes the
   gap with no second copy to drift.

These tests hold the invariants without building a wheel: every data file the
package reads must be matched by a declared glob, every module must be
reachable, and the command must be declared.
"""

from __future__ import annotations

import ast
import pathlib
import tomllib

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "src"
PKG = SRC / "netops_autopilot"


@pytest.fixture(scope="module")
def pyproject() -> dict:
    return tomllib.loads((REPO / "pyproject.toml").read_text())


# =================================================== 1. an installable command
def test_the_package_declares_a_console_command(pyproject):
    """`pip install` must leave something the operator can type."""
    scripts = pyproject.get("project", {}).get("scripts", {})
    assert "netops-autopilot" in scripts, (
        "no [project.scripts] entry: the package installs and leaves no command")
    target = scripts["netops-autopilot"]
    module, _, func = target.partition(":")
    path = SRC / (module.replace(".", "/") + ".py")
    assert path.exists(), (module, path)
    tree = ast.parse(path.read_text())
    names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert func in names, (func, sorted(names))


def test_the_command_target_is_the_cli_entry_point():
    from netops_autopilot.cli_main import main
    assert callable(main)


# ================================= 2. every data file is declared package data
def test_every_data_file_in_the_package_is_declared_package_data(pyproject):
    """A data file the code reads must ship. Nothing may rely on a checkout."""
    covered: set[pathlib.Path] = set()
    for pkg, pats in pyproject["tool"]["setuptools"]["package-data"].items():
        base = PKG / pkg.split(".", 1)[1]
        for pat in pats:
            covered.update(m for m in base.glob(pat) if m.is_file())
    on_disk = {p for p in PKG.rglob("*")
               if p.is_file() and p.suffix != ".py"
               and "__pycache__" not in p.parts and "egg-info" not in str(p)}
    assert on_disk, "no data files found — the scan itself is broken"
    orphans = sorted(str(p.relative_to(SRC)) for p in on_disk - covered)
    assert not orphans, (
        "these files ship in a checkout but not in a wheel; add them to "
        f"[tool.setuptools.package-data]: {orphans}")


def test_the_vendor_knowledge_base_is_declared_as_installed_data(pyproject):
    """Every JSON in specs/data must reach sysconfig['data']/netops_autopilot_specs."""
    data_files = pyproject["tool"]["setuptools"]["data-files"]
    sources = [s for pats in data_files.values() for s in pats]
    missing = []
    for path in sorted((REPO / "specs" / "data").rglob("*.json")):
        rel = path.relative_to(REPO)
        if not any(pathlib.Path(rel).match(pat) for pat in sources):
            missing.append(str(rel))
    assert not missing, (
        "these knowledge-base files never reach an installed package, so every "
        f"vendor fact resolves to BLOCKED: {missing}")


def test_the_installed_specs_location_is_the_one_the_locator_probes():
    """The pack must land where specs_data_dir already looks — no new path."""
    import sysconfig
    from netops_autopilot import specs_data as sd
    src = pathlib.Path(sd.__file__).read_text()
    assert "netops_autopilot_specs" in src, (
        "the locator no longer probes the directory the wheel ships into")
    assert sysconfig.get_paths()["data"] in src or "sysconfig" in src


# ================================================ 3. the interface is packaged
def test_the_web_interface_ships_inside_the_package():
    from netops_autopilot.webui import WEBUI_DIR, webui_index_path
    assert PKG in WEBUI_DIR.parents, (
        f"{WEBUI_DIR} is outside the package, so a wheel cannot carry it")
    assert webui_index_path().is_file()
    assert webui_index_path().read_bytes().lower().startswith(b"<!doctype html")


def test_the_server_finds_the_interface_without_a_repository():
    """create_app must not reconstruct a repo-root path by walking parents."""
    src = (PKG / "web" / "server.py").read_text()
    assert "parent.parent.parent.parent" not in src, (
        "the server is guessing the repository root again")
    assert "WEBUI_DIR" in src


# ==================================================== 4. no unreachable module
def _modules() -> dict[str, pathlib.Path]:
    out = {}
    for path in PKG.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        rel = path.relative_to(SRC).with_suffix("")
        parts = list(rel.parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        out[".".join(parts)] = path
    return out


def test_every_shipped_module_is_reachable():
    """Dead code in the shipped package is a claim the package does not keep.

    `engines/real_device.py` was 108 statements that nothing imported, whose
    docstring promised allowlist gating and ledger auditing it never performed,
    whose factory ignored the ``device_ref`` it was handed, and which could not
    even run because paramiko was never a declared dependency. It sat next to
    the real netmiko transport and read like the hardware path.
    """
    modules = _modules()
    referenced: set[str] = set()
    sources = [(None, p) for p in (REPO / "tests").rglob("*.py")]
    sources += list(modules.items())
    for name, path in sources:
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:                       # pragma: no cover
            continue
        # the package a relative import resolves against
        if name is None:
            pkg_parts: list[str] = []
        elif path.name == "__init__.py":
            pkg_parts = name.split(".")
        else:
            pkg_parts = name.split(".")[:-1]
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    referenced.add(a.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0:
                    base, tail = [], node.module.split(".") if node.module else []
                else:
                    base = pkg_parts[: len(pkg_parts) - (node.level - 1)]
                    tail = node.module.split(".") if node.module else []
                referenced.add(".".join(base + tail))
                # `from pkg import sub` may be importing the submodule itself
                for a in node.names:
                    referenced.add(".".join(base + tail + [a.name]))
    entry_points = {"netops_autopilot", "netops_autopilot.__main__",
                    "netops_autopilot.cli_main", "netops_autopilot.py.typed"}
    # importing any submodule imports its package, so a package __init__ is
    # reachable whenever something beneath it is
    for name in list(referenced):
        parts = name.split(".")
        for i in range(1, len(parts)):
            referenced.add(".".join(parts[:i]))
    unreachable = sorted(n for n in modules
                         if n not in referenced and n not in entry_points
                         and not n.endswith(".py.typed"))
    assert not unreachable, (
        "nothing imports these; they are dead weight in the shipped package: "
        f"{unreachable}")


# ============================================= 5. missing data fails loudly
def test_a_missing_fixture_is_a_typed_failure_not_a_traceback(monkeypatch, tmp_path):
    """An operator deserves a sentence, not a path inside site-packages."""
    import netops_autopilot.simfabric.fabric as fab
    from netops_autopilot.core.failures import Failure, FailureClass
    monkeypatch.setattr(fab, "FIXTURES", tmp_path / "absent")
    with pytest.raises(Failure) as exc:
        fab._fx("show_version")
    assert exc.value.cls is FailureClass.BLOCKED
    text = str(exc.value)
    assert "SIM_FABRIC_DATA_MISSING" in text
    # and the remedy it names must be real
    assert "NETOPS_SIM_FABRIC_FIXTURES" in text
    assert "NETOPS_SIM_FABRIC_FIXTURES" in pathlib.Path(fab.__file__).read_text()


def test_the_fixture_override_is_honoured(monkeypatch, tmp_path):
    (tmp_path / "cisco_iosxe").mkdir(parents=True)
    (tmp_path / "cisco_iosxe" / "show_version.txt").write_bytes(b"REAL OVERRIDE")
    import importlib
    import netops_autopilot.simfabric.fabric as fab
    monkeypatch.setenv("NETOPS_SIM_FABRIC_FIXTURES", str(tmp_path))
    mod = importlib.reload(fab)
    try:
        assert mod.FIXTURES == tmp_path
        assert mod._fx("show_version") == b"REAL OVERRIDE"
    finally:
        monkeypatch.delenv("NETOPS_SIM_FABRIC_FIXTURES")
        importlib.reload(fab)


# ============================================= 6. the drivers are declared
def test_the_hardware_and_web_drivers_are_declared_and_optional(pyproject):
    """A bare install must still degrade honestly; [all] must be a real program."""
    extras = pyproject["project"]["optional-dependencies"]
    assert "hardware" in extras and "web" in extras and "all" in extras
    joined = " ".join(extras["hardware"] + extras["web"])
    for driver in ("pyserial", "netmiko", "fastapi", "uvicorn"):
        assert driver in joined, (driver, extras)
    for extra in ("hardware", "web"):
        assert set(extras[extra]) <= set(extras["all"]), extra
