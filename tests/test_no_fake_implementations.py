"""Nothing in the shipped package may stand in for the real thing.

This is the constraint stated plainly: no placeholder, no mock, no fake
implementation, no invented result, under any circumstance. It is asserted here
rather than promised in a document, because the codebase had already grown three
violations and nothing noticed:

* ``FakeSSHChannel`` and ``FakeTelnetChannel`` lived in ``src/`` though only
  tests used them — a deployment importing the package could reach a transport
  that answers from a dict.
* ``EchoProvider`` was worse. It was a *supported* setting:
  ``build_provider("echo")`` returned a provider that answered every request
  with a synthetic schema-compliant payload and invented token counts. Those
  responses passed schema validation and flowed into the evidence pipeline
  indistinguishably from a real model's. That is not a test helper; it is a
  fabricated result reachable from configuration.

The doubles now live in ``tests/support/test_doubles.py``, which production code
does not import.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"

#: Class-name prefixes that mark a stand-in. Matched on the prefix so a rename
#: cannot slip one past, and narrow enough that no real class in this codebase
#: begins with any of them.
FAKE_PREFIXES = ("Fake", "Mock", "Stub", "Dummy")

MARKERS = ("TODO", "FIXME", "XXX", "HACK", "NotImplementedError")


def _modules():
    for path in sorted(SRC.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        yield path, path.read_text(encoding="utf-8")


def test_no_test_double_class_is_shipped():
    """A class whose name says it is not real has no business in the package."""
    offenders = []
    for path, source in _modules():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.startswith(FAKE_PREFIXES):
                offenders.append(f"{path.relative_to(SRC.parent)}:{node.lineno}: "
                                 f"{node.name}")
    assert not offenders, (
        "test doubles found in the shipped package — move them to "
        f"tests/support/test_doubles.py: {offenders}")


def test_no_provider_fabricates_an_answer():
    """The LLM factory may return a real provider or refuse. It may not return
    something that invents a completion."""
    from netops_autopilot.llm.providers import build_provider

    for name in ("echo", "fake", "mock", "test", "synthetic"):
        with pytest.raises(ValueError) as exc:
            build_provider(name)
        assert "LLM_PROVIDER_UNKNOWN" in str(exc.value), (name, str(exc.value))

    # The null object is allowed because it does the honest thing: it raises
    # BLOCKED and names the reason instead of returning a result.
    from netops_autopilot.core.failures import Failure
    from netops_autopilot.llm import LLMRequest, NullProvider

    provider = build_provider("null")
    assert isinstance(provider, NullProvider)
    with pytest.raises(Failure) as exc:
        provider.complete(LLMRequest(system="s", user="u"))
    assert "LLM_PROVIDER_DISABLED" in exc.value.causes[0]


def test_the_double_is_not_importable_from_the_package():
    """Moving the code is not enough if it stays exported."""
    import netops_autopilot.llm as llm

    assert not hasattr(llm, "EchoProvider")
    assert "EchoProvider" not in llm.__all__

    import netops_autopilot.access.ssh_transport as ssh
    import netops_autopilot.access.telnet_transport as tel

    assert not hasattr(ssh, "FakeSSHChannel")
    assert not hasattr(ssh, "fake_ssh_factory")
    assert not hasattr(tel, "FakeTelnetChannel")
    assert not hasattr(tel, "fake_telnet_factory")


def test_no_unfinished_work_is_shipped():
    """A marker that says the code is not done, or a body that raises
    NotImplementedError, is a placeholder — and this project ships none."""
    offenders = []
    for path, source in _modules():
        for lineno, line in enumerate(source.splitlines(), 1):
            stripped = line.split("#", 1)[-1] if "#" in line else line
            if any(marker in line for marker in MARKERS):
                # A word inside a longer identifier is not a marker.
                if any(marker in line and not marker.isalpha()
                       or f" {marker}" in line or f"{marker}:" in line
                       or f"{marker})" in line for marker in MARKERS):
                    offenders.append(f"{path.relative_to(SRC.parent)}:{lineno}: "
                                     f"{line.strip()[:70]}")
    assert not offenders, f"unfinished-work markers in the package: {offenders}"


def test_the_real_transport_is_the_one_wired_by_default():
    """The default driver factory must reach a real driver, not a dict."""
    from netops_autopilot.access import ssh_transport

    # Constructing a transport without an explicit factory uses netmiko, which
    # opens a real SSH session — not an in-memory stand-in.
    transport = ssh_transport.SSHConsoleTransport(
        ssh_transport.SSHProfile(host="203.0.113.1", username="u", password="p"))
    assert transport._factory is ssh_transport._netmiko_factory


def test_an_unusable_transport_refuses_rather_than_pretending():
    """``telnetlib`` was removed in Python 3.13 (PEP 594), so on a modern
    runtime the stdlib Telnet driver cannot exist. The transport must say so.

    Pinned because the tempting fix is a stub that returns a canned banner, and
    that would turn "console access unavailable" into "console access worked".
    """
    import sys

    from netops_autopilot.access import telnet_transport
    from netops_autopilot.core.failures import Failure

    try:
        import telnetlib  # noqa: F401
        available = True
    except ImportError:
        available = False

    if not available:
        assert sys.version_info >= (3, 13)
        with pytest.raises(Failure) as exc:
            telnet_transport._stdlib_telnet_factory("203.0.113.1", 23, 5.0)
        assert "TELNET_DRIVER_UNAVAILABLE" in exc.value.causes[0]
        assert "PEP 594" in exc.value.causes[0]


# ---------------------------------------------------------------------------
# The package must not depend on the test suite
# ---------------------------------------------------------------------------


def test_no_shipped_module_imports_the_test_suite():
    """``tests/`` is not part of the distribution, so importing it is a crash.

    ``pyproject.toml`` sets ``[tool.setuptools.packages.find] where = ["src"]``,
    which means an installed ``netops-autopilot`` has no ``tests`` package at
    all. Eight modules used to import ``tests.support.simfabric`` anyway, so
    ``chat --simulate`` died with ``ModuleNotFoundError`` and ``web/server.py``
    grew a ``sys.path.append`` of the repository root to hide it.
    """
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                if name == "tests" or name.startswith("tests."):
                    offenders.append(f"{path.relative_to(SRC)}:{node.lineno}: {name}")
    assert offenders == [], (
        "shipped modules importing the test suite: " + ", ".join(offenders))


def test_the_simulated_fabric_ships_inside_the_package():
    """The simulation is a product feature, so it must live where the product does.

    Both the code and the golden device answers it serves are checked: a module
    that ships without its data would import cleanly and then fail at the first
    ``show version``.
    """
    import netops_autopilot.simfabric as sim

    package_dir = pathlib.Path(sim.__file__).resolve().parent
    assert SRC / "netops_autopilot" / "simfabric" == package_dir, (
        "the simulated fabric must sit under src/netops_autopilot/ so that "
        "packages.find(where=['src']) includes it in the distribution")

    fixtures = sim.fixtures_dir()
    assert fixtures.is_dir(), fixtures
    samples = sorted(p.name for p in fixtures.rglob("*.txt"))
    assert samples, "the fabric has no device answers to serve"
    # The seed device's identity comes from this file; without it discovery
    # cannot even name the family.
    assert "show_version.txt" in samples


def test_the_shipped_package_needs_nothing_outside_itself_to_simulate():
    """The regression that hid this: a ``sys.path`` hack pointing at the repo root.

    Parsed rather than grepped — prose in a docstring explaining the hack is not
    the hack, and a guard that fires on prose teaches people to delete the
    explanation instead of the defect.
    """
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.Expr, ast.AugAssign)):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Attribute) and sub.attr == "path"
                        and isinstance(sub.value, ast.Name)
                        and sub.value.id in {"sys", "_sys"}):
                    offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
                    break
    assert offenders == [], (
        "shipped modules manipulating sys.path (the package must resolve its own "
        "modules and data): " + ", ".join(sorted(set(offenders))))
