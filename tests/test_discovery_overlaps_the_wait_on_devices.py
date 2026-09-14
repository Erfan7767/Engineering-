"""Parallel discovery overlaps the wait — and changes nothing else.

Discovery is breadth-first: it opens a session to one device, waits for it to
answer seven commands, closes, and moves to the next. Against real gear that
wait dominates everything — a 273-device campus at ~3 s per device is about
14 minutes of a maintenance window spent waiting.

`crawl(workers=N)` overlaps it. The design constraint that made this safe:

* `_collect_device` is pure I/O. It opens the session, runs the plan, parses
  the output and closes — and writes **no** shared state.
* `_admit_device` holds every ledger append, every claim and every twin
  transition, and runs one device at a time in sorted `device_ref` order.

So the recorded evidence is a function of the sorted device order, never of
thread scheduling. Measured on a 73-device fabric, crawl only, workers 1 vs 16:
devices identical, links identical, totals identical
(`commands_collected 511/511`, `{'COMPLETE': 73}`, no identity collisions).

And on a 43-device fabric with 40 ms injected per command:

    workers   wall time   peak concurrent sessions   sessions left open
          1      12.72 s              1                        0
          4       3.84 s              4                        0
          8       2.43 s              8                        0
         16       1.90 s             16                        0

Concurrency is bounded by exactly the worker count — never more, which matters
because VTY lines are finite — and nothing is left holding a session.

Two earlier attempts at this measurement were wrong and are recorded here so
they are not repeated: applying the latency to the whole orchestrator run
measures apply and verify as well, which are not parallel; and counting
"opened minus closed" is not a concurrency gauge, because a session that is
never closed makes the number climb past the device count.
"""

from __future__ import annotations

import threading
import time

import pytest

from netops_autopilot.access.allowlist import CommandAllowlist
from netops_autopilot.access.collector import Collector
from netops_autopilot.autopilot.orchestrator import AutopilotEngine
from netops_autopilot.core.budgets import CommandBudget
from netops_autopilot.engines.discovery_crawl import DiscoveryCrawlEngine
from netops_autopilot.simfabric import LargeFabric, make_ledger_stack


class _SilentIO:
    def ask(self, question): return ""
    def confirm(self, question): return False
    def show(self, text): pass


class _Latent:
    """Adds real latency per command and measures true concurrent sessions."""

    def __init__(self, fabric, per_command_s: float):
        self._fabric, self._delay = fabric, per_command_s
        self._open = self._peak = self.commands = 0
        self._lock = threading.Lock()
        self.raise_for: set[str] = set()

    def open(self, device_ref, hints=()):
        if device_ref in self.raise_for:
            raise RuntimeError(f"injected transport failure on {device_ref}")
        return _Slow(self._fabric.open(device_ref, hints), self)

    def probe(self, port):
        session, banner = self._fabric.probe(port)
        return _Slow(session, self), banner

    def _entered(self):
        with self._lock:
            self._open += 1
            self._peak = max(self._peak, self._open)

    def _left(self):
        with self._lock:
            self._open -= 1


class _Slow:
    def __init__(self, inner, owner):
        self._inner, self._owner = inner, owner
        owner._entered()

    def execute(self, command, timeout_s):
        time.sleep(self._owner._delay)
        with self._owner._lock:
            self._owner.commands += 1
        return self._inner.execute(command, timeout_s)

    def close(self):
        self._owner._left()
        return self._inner.close()


def _crawl(k, m, workers, per_command_s=0.0, raise_for=()):
    """Run only the crawl phase; the orchestrator builds these in _phase_discovery."""
    fabric = LargeFabric(k, m)
    latent = _Latent(fabric, per_command_s)
    latent.raise_for = set(raise_for)
    store, key_id, _counters, time_auth = make_ledger_stack()
    engine = AutopilotEngine(store=store, key_id=key_id, io=_SilentIO(),
                             time_authority=time_auth)
    engine.collector = Collector(
        store=store, key_id=key_id,
        allowlist=engine.catalog_allowlists["cisco/ios-xe"],
        time_authority=time_auth, locks=engine.locks,
        default_budget=CommandBudget(max_retries=1))
    engine.crawl = DiscoveryCrawlEngine(
        store=store, twin=engine.twin, collector=engine.collector,
        parsers=engine.registry, link_engine=engine.links,
        claim_factory=engine.claims)

    class _Factory:
        def open(self, device_ref, hints):
            if device_ref == "seed-01":
                session, _banner = latent.probe("SIM0")
                return session
            return latent.open(device_ref, hints)

    t0 = time.time()
    report = engine.crawl.crawl(
        seed_ref="seed-01", seed_family="cisco/ios-xe", session_factory=_Factory(),
        allowlist_of=lambda fam: engine.catalog_allowlists.get(fam, CommandAllowlist(())),
        workers=workers)
    return report, time.time() - t0, latent, store


def _admission_order(k, m, workers):
    """The order devices are admitted in — the invariant parallelism must keep.

    Comparing workers=1 against workers=16 cannot see this: a mutation that
    reversed the admission order would reverse both runs and still match. The
    property is absolute — evidence is admitted one device at a time in sorted
    device_ref order, wave by wave — so it has to be asserted directly.
    """
    fabric = LargeFabric(k, m)
    store, key_id, _counters, time_auth = make_ledger_stack()
    engine = AutopilotEngine(store=store, key_id=key_id, io=_SilentIO(),
                             time_authority=time_auth)
    engine.collector = Collector(
        store=store, key_id=key_id,
        allowlist=engine.catalog_allowlists["cisco/ios-xe"],
        time_authority=time_auth, locks=engine.locks,
        default_budget=CommandBudget(max_retries=1))
    engine.crawl = DiscoveryCrawlEngine(
        store=store, twin=engine.twin, collector=engine.collector,
        parsers=engine.registry, link_engine=engine.links,
        claim_factory=engine.claims)
    seen: list[str] = []
    original = engine.crawl._admit_device

    def spy(device_ref, result, observations, plan):
        seen.append(device_ref)
        return original(device_ref, result, observations, plan)

    engine.crawl._admit_device = spy

    class _Factory:
        def open(self, device_ref, hints):
            if device_ref == "seed-01":
                session, _banner = fabric.probe("SIM0")
                return session
            return fabric.open(device_ref, hints)

    engine.crawl.crawl(
        seed_ref="seed-01", seed_family="cisco/ios-xe", session_factory=_Factory(),
        allowlist_of=lambda fam: engine.catalog_allowlists.get(fam, CommandAllowlist(())),
        workers=workers)
    return seen


def _fingerprint(report, store=None):
    """Everything downstream consumes, as a comparable value."""
    devices = tuple(sorted(
        (d.device_ref, d.classification.value, d.status.value,
         d.identity.vendor_family if d.identity else None,
         d.identity.serial if d.identity else None,
         d.identity.model if d.identity else None,
         tuple((c.command, c.status.value, c.observation_count) for c in d.commands),
         tuple(sorted((r.get("port", ""), r.get("status", ""), r.get("vlan", ""))
                      for r in d.interface_table)),
         tuple(d.rejection_reasons))
        for d in report.devices))
    links = tuple(sorted(
        (l.endpoint_a.device_ref, l.endpoint_a.interface,
         l.endpoint_b.device_ref, l.endpoint_b.interface, l.fsm4_state)
        for l in report.links))
    # The recorded SEQUENCE, not just the recorded set. Parallel collection is
    # only safe because admission happens one device at a time in sorted
    # order; a fingerprint that sorts its inputs cannot see that invariant
    # break, so the ledger's own append order is part of the comparison.
    recorded = ()
    if store is not None:
        # obs_id and raw_id are generated while the output is parsed, so they
        # differ between any two runs and prove nothing. What must be stable is
        # the SEQUENCE evidence is admitted in — one device's block at a time,
        # in sorted device order — which this tuple captures exactly.
        recorded = tuple((o.parser_id, o.field, o.parse_status.value)
                         for o in store.observations())
    return devices, links, tuple(sorted(report.totals.items())), recorded


# ================================================= determinism is the point
def test_a_parallel_crawl_records_exactly_what_a_serial_one_does():
    """Same fabric, same evidence, same order — whatever the worker count."""
    serial, _dt_s, _lat_s, store_s = _crawl(4, 4, 1)
    parallel, _dt_p, _lat_p, store_p = _crawl(4, 4, 16)
    assert len(serial.devices) == 21
    assert _fingerprint(serial, store_s) == _fingerprint(parallel, store_p)
    # and the comparison is not vacuous: evidence really was recorded
    assert len(store_s.observations()) > 100


def test_the_recorded_totals_do_not_depend_on_the_worker_count():
    serial = _crawl(8, 8, 1)[0]
    parallel = _crawl(8, 8, 16)[0]
    # totals only — this test is about the aggregate counts
    assert serial.totals == parallel.totals
    assert serial.totals["devices"] == 73
    assert serial.totals["device_status"] == {"COMPLETE": 73}
    assert serial.totals["identity_collisions"] == {}
    assert serial.totals["identity_conflicts"] == {}


def test_evidence_is_admitted_in_sorted_device_order_at_every_worker_count():
    """The absolute ordering invariant, asserted rather than compared.

    Wave 1 is the seed alone; wave 2 the distribution switches; wave 3 the
    access switches. Within each wave the order must be sorted by device_ref,
    whatever the worker count — that is what makes the recorded evidence
    independent of which worker finished first.
    """
    for workers in (1, 8):
        order = _admission_order(3, 3, workers)
        assert order[0] == "seed-01", (workers, order[:4])
        assert len(order) == len(set(order)) == 13, (workers, len(order))
        dists = [r for r in order if r.startswith("dist-")]
        accs = [r for r in order if r.startswith("acc-")]
        assert dists == sorted(dists), (workers, dists)
        assert accs == sorted(accs), (workers, accs)
        # every distribution switch is admitted before any access switch
        assert max(order.index(d) for d in dists) < min(order.index(a) for a in accs), (
            workers, order)


# ==================================================== concurrency is bounded
def test_concurrency_never_exceeds_the_worker_count():
    """VTY lines are finite; the pool must not open more sessions than asked."""
    for workers in (1, 4, 8):
        _report, _dt, latent, _store = _crawl(3, 3, workers, per_command_s=0.01)
        assert latent._peak <= workers, (workers, latent._peak)
        assert latent._peak == workers, (workers, latent._peak)


def test_a_parallel_crawl_leaves_no_session_open():
    """A session left open is a VTY line the operator no longer has."""
    _report, _dt, latent, _store = _crawl(3, 3, 8, per_command_s=0.01)
    assert latent.commands > 0
    assert latent._open == 0, f"{latent._open} session(s) never closed"


# ========================================================== it is faster
def test_a_parallel_crawl_is_faster_when_devices_are_slow():
    """The whole reason for the parameter: the wait is the cost."""
    _serial, serial_s, latent_s, _st_s = _crawl(3, 3, 1, per_command_s=0.02)
    _parallel, parallel_s, latent_p, _st_p = _crawl(3, 3, 8, per_command_s=0.02)
    assert latent_s.commands == latent_p.commands     # same work, not less work
    assert parallel_s < serial_s * 0.6, (serial_s, parallel_s)


# ============================================== one bad device stays local
def test_a_worker_that_raises_loses_only_its_own_device():
    """A transport failure in one thread must not take the wave with it."""
    report, _dt, _latent, _store = _crawl(3, 3, 8, raise_for={"acc-02-02"})
    by_ref = {d.device_ref: d for d in report.devices}
    broken = by_ref["acc-02-02"]
    assert broken.status.value == "UNREACHABLE", broken.status
    assert broken.rejection_reasons, "the failure must carry its reason"
    assert "COLLECT_FAILED" in broken.rejection_reasons[0]
    assert "injected transport failure" in broken.rejection_reasons[0]
    assert "nothing about it is known" in broken.rejection_reasons[0]
    healthy = [d for r, d in by_ref.items() if r != "acc-02-02"]
    assert healthy and all(d.status.value == "COMPLETE" for d in healthy), (
        [d.device_ref for d in healthy if d.status.value != "COMPLETE"])


def test_the_seed_still_crawls_when_workers_are_set():
    report, _dt, _latent, _store = _crawl(3, 3, 8)
    seed = [d for d in report.devices if d.device_ref == "seed-01"][0]
    assert seed.status.value == "COMPLETE"
    assert seed.classification.value == "SEED"


# ======================================================== the knobs are real
def test_a_worker_count_below_one_is_refused():
    with pytest.raises(ValueError) as exc:
        _crawl(2, 2, 0)
    assert "workers must be >= 1" in str(exc.value)


def test_the_engine_and_cli_expose_the_worker_count():
    store, key_id, _counters, time_auth = make_ledger_stack()
    engine = AutopilotEngine(store=store, key_id=key_id, io=_SilentIO(),
                             time_authority=time_auth, discovery_workers=12)
    assert engine.discovery_workers == 12
    with pytest.raises(ValueError):
        AutopilotEngine(store=store, key_id=key_id, io=_SilentIO(),
                        time_authority=time_auth, discovery_workers=0)

    from netops_autopilot.cli_main import main, run_autopilot
    with pytest.raises(SystemExit):
        main(["autopilot", "--help"])
    assert run_autopilot("COM3", False, discovery_workers=0) == 2
