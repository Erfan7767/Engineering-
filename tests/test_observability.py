"""Tests for the observability subsystem (JSON logger + metrics)."""

from __future__ import annotations

import io
import json

import pytest

from netops_autopilot.observability import (
    Counter,
    Gauge,
    JsonLogger,
    LogEvent,
    MetricsRegistry,
    get_logger,
    _redact,
)


# ----------------- Redaction (L11) -----------------


def test_redact_dict_password():
    out = _redact({"username": "admin", "password": "p4ssw0rd"})
    assert out["username"] == "admin"
    assert out["password"] == "[REDACTED]"


def test_redact_nested_dict():
    out = _redact({"outer": {"api_key": "abc", "innocent": "x"}})
    assert out["outer"]["api_key"] == "[REDACTED]"
    assert out["outer"]["innocent"] == "x"


def test_redact_list():
    out = _redact([{"secret": "shh"}, "plain"])
    assert out[0]["secret"] == "[REDACTED]"
    assert out[1] == "plain"


def test_redact_value_pattern():
    out = _redact("password=hunter2 token=abc")
    assert "hunter2" not in out
    assert "abc" not in out


def test_redact_preserves_non_secret_keys():
    out = _redact({"vendor": "cisco", "family": "ios-xe"})
    assert out == {"vendor": "cisco", "family": "ios-xe"}


# ----------------- JsonLogger -----------------


def test_logger_writes_json_line():
    buf = io.StringIO()
    log = JsonLogger(stream=buf, min_level="INFO")
    log.info("BOND", "binding confirmed", evidence_ids=["e1"])
    line = buf.getvalue().strip()
    j = json.loads(line)
    assert j["phase"] == "BOND"
    assert j["message"] == "binding confirmed"
    assert j["evidence_ids"] == ["e1"]
    assert j["level"] == "INFO"


def test_logger_respects_min_level():
    buf = io.StringIO()
    log = JsonLogger(stream=buf, min_level="WARN")
    log.info("X", "ignored")
    log.warn("X", "kept")
    lines = buf.getvalue().strip().splitlines()
    assert len(lines) == 1
    assert "kept" in lines[0]


def test_logger_redacts_secrets():
    buf = io.StringIO()
    log = JsonLogger(stream=buf, min_level="INFO")
    log.info("AUTH", "login", extra={"password": "shh", "ok": True})
    line = buf.getvalue().strip()
    j = json.loads(line)
    assert j["extra"]["password"] == "[REDACTED]"
    assert j["extra"]["ok"] is True


def test_logger_thread_safety():
    import threading
    buf = io.StringIO()
    log = JsonLogger(stream=buf, min_level="INFO")
    def worker(n):
        for i in range(50):
            log.info("WORKER", f"msg {n}-{i}")
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lines = buf.getvalue().strip().splitlines()
    assert len(lines) == 4 * 50
    # Every line must be valid JSON.
    for line in lines:
        json.loads(line)


# ----------------- Metrics -----------------


def test_counter_inc_and_render():
    c = Counter("foo_total", "help")
    c.inc()
    c.inc(5)
    out = c.render()
    assert "foo_total 6" in out
    assert "# TYPE foo_total counter" in out


def test_counter_rejects_negative():
    c = Counter("foo_total", "help")
    with pytest.raises(ValueError):
        c.inc(-1)


def test_counter_with_labels():
    c = Counter("foo_total", "help", labels={"vendor": "cisco"})
    c.inc()
    out = c.render()
    assert 'vendor="cisco"' in out


def test_gauge_set_inc_dec():
    g = Gauge("foo", "help")
    g.set(10)
    g.inc(5)
    g.dec(3)
    assert g.value == 12


def test_gauge_render():
    g = Gauge("foo", "help")
    g.set(7)
    out = g.render()
    assert "foo 7" in out
    assert "# TYPE foo gauge" in out


# ----------------- MetricsRegistry -----------------


def test_registry_has_constitution_counters():
    r = MetricsRegistry()
    snap = r.scrape()
    # T1-T4 + L11 + cleanup + gate_bypass + stale_evidence + mgmt_path
    for name in (
        "netops_unverified_claims_total",
        "netops_unsupported_pass_total",
        "netops_unauthorized_changes_total",
        "netops_scope_violations_total",
        "netops_credential_exposure_total",
        "netops_cleanup_leaks_total",
        "netops_gate_bypass_total",
        "netops_stale_evidence_deployments_total",
        "netops_management_path_violations_total",
    ):
        assert name in snap
        assert "counter" in snap.split(name)[1].split("\n")[0]


def test_registry_inc_constitution_by_code():
    r = MetricsRegistry()
    r.inc_constitution("T1")
    r.inc_constitution("T1")
    r.inc_constitution("T3", n=3)
    r.inc_constitution("L11")
    snap = r.scrape()
    assert "netops_unverified_claims_total 2" in snap
    assert "netops_unauthorized_changes_total 3" in snap
    assert "netops_credential_exposure_total 1" in snap


def test_registry_unknown_code_is_noop():
    r = MetricsRegistry()
    r.inc_constitution("NOT_A_REAL_CODE")  # must not raise
    snap = r.scrape()
    assert "NOT_A_REAL_CODE" not in snap


def test_registry_custom_counter_and_gauge():
    r = MetricsRegistry()
    r.counter("my_counter").inc(5)
    r.gauge("my_gauge").set(42)
    snap = r.scrape()
    assert "my_counter 5" in snap
    assert "my_gauge 42" in snap


def test_registry_snapshot_returns_dict():
    r = MetricsRegistry()
    r.counter("x").inc(3)
    snap = r.snapshot()
    assert isinstance(snap, dict)
    assert snap.get("x") == 3
    assert "netops_chain_ok" in snap


# ----------------- Singleton -----------------


def test_get_logger_singleton():
    a = get_logger()
    b = get_logger()
    assert a is b
