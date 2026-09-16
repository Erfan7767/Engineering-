"""The API must be able to reach the devices it discovers.

A run started from the browser used to configure *only* the device on the
console cable. Every neighbour discovery found was refused with
``NO_MGMT_CREDENTIALS`` — truthfully, because the API collected no
credentials and a background worker has no terminal to prompt on. The
refusal was honest; the capability was missing.

These tests cover what the API does with operator-supplied credentials:
it validates them strictly, it hands them to the same identity-confirming
factory the CLI uses, and it never lets the password escape into a
response, a run record, or a log line.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from netops_autopilot.access.mgmt_session import MgmtCredential, MgmtSessionFactory
from netops_autopilot.web import create_app
from netops_autopilot.web.server import (
    _credential_mgmt_factory,
    _mgmt_credential_from,
)


@pytest.fixture()
def client(monkeypatch, tmp_path) -> TestClient:
    # Keep every ledger the worker creates inside the test's own directory.
    monkeypatch.setenv("NETOPS_DATA_DIR", str(tmp_path))
    return TestClient(create_app())


_GOOD = {"username": "netops", "password": "s3cr3t", "enable_secret": "en4ble",
         "method": "ssh", "port": 22}


# --------------------------------------------------------------------------
# Strict validation: a malformed request fails loudly, before a run exists
# --------------------------------------------------------------------------


def test_a_credential_object_that_is_not_an_object_is_rejected(client) -> None:
    r = client.post("/runs", json={"port": "/dev/nope", "mgmt": "netops"})
    assert r.status_code == 400
    assert "mgmt" in r.json()["detail"]


@pytest.mark.parametrize("mgmt,fragment", [
    ({"password": "s3cr3t"}, "username"),
    ({"username": "   ", "password": "s3cr3t"}, "username"),
    ({"username": "netops"}, "password"),
    ({"username": "netops", "password": ""}, "password"),
    ({"username": "netops", "password": "s3cr3t", "method": "carrier-pigeon"},
     "method"),
    ({"username": "netops", "password": "s3cr3t", "port": 0}, "port"),
    ({"username": "netops", "password": "s3cr3t", "port": 70000}, "port"),
    ({"username": "netops", "password": "s3cr3t", "port": "22"}, "port"),
    ({"username": "netops", "password": "s3cr3t", "port": True}, "port"),
    ({"username": "netops", "password": "s3cr3t", "enable_secret": 7},
     "enable_secret"),
])
def test_malformed_credentials_are_rejected(client, mgmt, fragment) -> None:
    r = client.post("/runs", json={"port": "/dev/nope", "mgmt": mgmt})
    assert r.status_code == 400
    assert fragment in r.json()["detail"]


def test_a_well_formed_credential_is_accepted(client) -> None:
    r = client.post("/runs", json={"port": "/dev/nope", "sim": True,
                                   "mgmt": _GOOD})
    assert r.status_code == 200
    assert r.json()["mgmt_credentials"] == "supplied"


def test_a_run_without_credentials_says_so(client) -> None:
    r = client.post("/runs", json={"port": "/dev/nope", "sim": True})
    assert r.status_code == 200
    assert r.json()["mgmt_credentials"] == "none"


# --------------------------------------------------------------------------
# The password must not escape
# --------------------------------------------------------------------------


def test_the_password_is_not_echoed_by_the_endpoint(client) -> None:
    r = client.post("/runs", json={"port": "/dev/nope", "sim": True,
                                   "mgmt": _GOOD})
    assert r.status_code == 200
    assert "s3cr3t" not in r.text
    assert "en4ble" not in r.text


def test_the_credential_masks_itself_in_every_rendering() -> None:
    cred = _mgmt_credential_from({"mgmt": _GOOD})
    assert cred is not None
    for rendering in (repr(cred), str(cred), f"{cred}"):
        assert "s3cr3t" not in rendering
        assert "en4ble" not in rendering


def test_the_credential_is_parsed_with_its_parts_intact() -> None:
    cred = _mgmt_credential_from({"mgmt": _GOOD})
    assert cred == MgmtCredential(username="netops", password="s3cr3t",
                                  enable_secret="en4ble", method="ssh", port=22)


def test_the_method_defaults_to_ssh_and_the_secret_to_blank() -> None:
    cred = _mgmt_credential_from(
        {"mgmt": {"username": " netops ", "password": "s3cr3t"}})
    assert cred.method == "ssh"
    assert cred.enable_secret == ""
    assert cred.port is None
    assert cred.username == "netops"          # trimmed, not passed through raw


def test_no_credential_key_means_no_credential() -> None:
    assert _mgmt_credential_from({}) is None


# --------------------------------------------------------------------------
# What the credential actually buys: the real, identity-confirming path
# --------------------------------------------------------------------------


def test_a_supplied_credential_builds_the_real_factory() -> None:
    cred = _mgmt_credential_from({"mgmt": _GOOD})
    factory = _credential_mgmt_factory(cred)

    assert isinstance(factory, MgmtSessionFactory)
    # The same credential serves every discovered device — one operator
    # account, collected once, never per-device prompts.
    assert factory.credential_provider("dev-02", "cisco/ios-xe") is cred
    assert factory.credential_provider("dev-07", "juniper/junos") is cred


def test_the_real_factory_refuses_to_act_without_discovery_evidence() -> None:
    """It must not dial an address it has no evidence for."""
    cred = _mgmt_credential_from({"mgmt": _GOOD})
    factory = _credential_mgmt_factory(cred)

    with pytest.raises(Exception) as exc:
        factory("dev-02", ())
    assert "CRAWL_NOT_BOUND" in str(exc.value)


def test_identity_verification_is_not_relaxed_by_supplying_a_password() -> None:
    """A credential is not a licence to skip the serial check."""
    cred = _mgmt_credential_from({"mgmt": _GOOD})
    factory = _credential_mgmt_factory(cred)
    assert factory.allow_unverified_identity is False


# --------------------------------------------------------------------------
# The refusal the credential removes, measured on a real crawl
# --------------------------------------------------------------------------


def _real_crawl_and_neighbour():
    """Discovery evidence produced by the real engine, and one neighbour."""
    from netops_autopilot.autopilot.answer_script import answers_keyed
    from netops_autopilot.autopilot.orchestrator import AutopilotEngine
    from netops_autopilot.cli import ScriptedIO
    from tests.support.simfabric import SimFabricFactory, make_ledger_stack

    fabric = SimFabricFactory(include_access=False)
    store, key_id, _counters, time_auth = make_ledger_stack()
    engine = AutopilotEngine(store=store, key_id=key_id, time_authority=time_auth,
                             io=ScriptedIO(dict(answers_keyed(
                                 access_retry="n", intent="branch", apply=False))))
    report = engine.run(probe_port_session_factory=lambda p: fabric.probe(p),
                        mgmt_session_factory=fabric.open,
                        port="SIM-SEED", execute=False)
    neighbours = [d for d in report.crawl.devices if d.device_ref != "seed-01"]
    assert neighbours, "discovery found no neighbour to reach"
    return report.crawl, neighbours[0]


def test_a_run_without_credentials_blames_the_credentials(client) -> None:
    """The old refusal, kept as the control for the test below."""
    from netops_autopilot.web.server import _ConsoleOnlyMgmt

    crawl, neighbour = _real_crawl_and_neighbour()
    mgmt = _ConsoleOnlyMgmt("SIM-SEED")
    mgmt.bind_crawl(crawl, console_session=None, seed_ref="seed-01")

    with pytest.raises(Exception) as exc:
        mgmt(neighbour.device_ref, ())
    assert f"NO_MGMT_CREDENTIALS:{neighbour.device_ref}" in str(exc.value)


def test_a_supplied_credential_moves_the_run_past_the_credential_refusal() -> None:
    """With credentials the platform stops blaming credentials.

    It then refuses for the true next reason — discovery did not observe this
    neighbour's vendor family, so no management dialect can be selected, and
    the platform never guesses one. The point is not that it succeeds; it is
    that the missing capability this change removes is no longer the reason.
    """
    crawl, neighbour = _real_crawl_and_neighbour()
    cred = _mgmt_credential_from({"mgmt": _GOOD})
    factory = _credential_mgmt_factory(cred)
    factory.bind_crawl(crawl, console_session=None, seed_ref="seed-01")

    with pytest.raises(Exception) as exc:
        factory(neighbour.device_ref, ())
    message = str(exc.value)
    assert "NO_MGMT_CREDENTIALS" not in message
    assert "IDENTITY_INCOMPLETE" in message


# --------------------------------------------------------------------------
# The wiring: the worker must actually use what the API collected
# --------------------------------------------------------------------------

_ptype = pytest.mark.skipif(
    not hasattr(__import__("os"), "openpty"), reason="this platform has no pty")


@_ptype
def test_the_worker_uses_the_credentials_the_api_collected() -> None:
    """A supplied credential changes what the run says about its neighbours.

    Measured over a real pty: without credentials the run's own report
    carries ``NO_MGMT_CREDENTIALS`` for every neighbour it could not reach;
    with them that reason is gone and the run gets as far as the next true
    one. Both runs still configure the device on the console cable, so this
    is a capability added, not a path broken.
    """
    import os

    from netops_autopilot.simfabric.fabric import SEED_BANNER, seed_session
    from netops_autopilot.simfabric.pty_device import PtyDevice
    from netops_autopilot.web import server

    def _run(cred):
        device = PtyDevice.over(seed_session(), prompt=b"seed-01> ")
        device._banner = SEED_BANNER
        device.start()
        try:
            server._RUNS.clear()
            server._RUNS["t"] = server.RunRecord(run_id="t", created_at="now")
            server._run_autopilot_worker("t", device.port_path, True, False,
                                         "branch", cred)
            return server._RUNS["t"].report
        finally:
            device.stop()

    bare = _run(None)
    assert "NO_MGMT_CREDENTIALS" in repr(bare), (
        "the control run was expected to name the missing credentials")

    cred = _mgmt_credential_from({"mgmt": _GOOD})
    with_creds = _run(cred)
    assert "NO_MGMT_CREDENTIALS" not in repr(with_creds)
    # And the credential must not have cost the seed its configuration.
    assert (with_creds.execution or {}).get("outcome") == "APPLIED"
    assert (bare.execution or {}).get("outcome") == "APPLIED"
    assert "s3cr3t" not in repr(with_creds)


# --------------------------------------------------------------------------
# The password must not cross the network in cleartext
# --------------------------------------------------------------------------


def _remote_client(monkeypatch, tmp_path) -> TestClient:
    """A client whose peer address is another host, as the server sees it."""
    monkeypatch.setenv("NETOPS_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("NETOPS_ALLOW_PLAINTEXT_MGMT", raising=False)
    return TestClient(create_app(), client=("10.1.2.3", 50000))


def test_a_remote_peer_cannot_post_a_password_in_cleartext(
        monkeypatch, tmp_path) -> None:
    client = _remote_client(monkeypatch, tmp_path)
    r = client.post("/runs", json={"port": "/dev/nope", "mgmt": _GOOD})
    assert r.status_code == 403
    assert "REFUSING_PLAINTEXT_CREDENTIAL" in r.json()["detail"]
    assert "10.1.2.3" in r.json()["detail"]
    assert "s3cr3t" not in r.text


def test_the_operator_can_accept_that_risk_explicitly(
        monkeypatch, tmp_path) -> None:
    client = _remote_client(monkeypatch, tmp_path)
    monkeypatch.setenv("NETOPS_ALLOW_PLAINTEXT_MGMT", "1")
    r = client.post("/runs", json={"port": "/dev/nope", "sim": True,
                                   "mgmt": _GOOD})
    assert r.status_code == 200
    assert r.json()["mgmt_credentials"] == "supplied"


def test_a_run_without_credentials_is_unaffected_by_the_peer(
        monkeypatch, tmp_path) -> None:
    """The guard is about secrets, not about who may start a run."""
    client = _remote_client(monkeypatch, tmp_path)
    r = client.post("/runs", json={"port": "/dev/nope", "sim": True})
    assert r.status_code == 200
    assert r.json()["mgmt_credentials"] == "none"


def test_ipv6_loopback_is_local() -> None:
    from netops_autopilot.web.server import _plaintext_credential_refusal
    assert _plaintext_credential_refusal("::1") is None
    assert _plaintext_credential_refusal("127.0.0.1") is None
    assert _plaintext_credential_refusal("10.1.2.3") is not None
    assert _plaintext_credential_refusal(None) is not None
