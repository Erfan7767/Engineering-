"""SerialConsoleTransport: deterministic framing, baud probe, budgets.

All time is fake (injected clock + sleep); zero wall-clock, zero randomness.
"""

import sys

import pytest

from netops_autopilot.access import serial_transport as st
from netops_autopilot.core.failures import Failure
from netops_autopilot.core.timeauth import ClockStatus  # noqa: F401  (import-surface guard)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class FakeSleep:
    def __init__(self, clock: FakeClock):
        self._clock = clock
        self.calls = 0

    def __call__(self, dt: float):
        self.calls += 1
        self._clock.t += dt


class FakePort:
    """Scripted serial port.

    Chunks are delivered when clock >= their absolute time. ``cr_response``
    models a device that answers the wakeup CR: the response is scheduled at
    ``clock + respond_after_s`` on the first ``write`` — i.e. relative to the
    probe moment, exactly like a real console (the input buffer is cleared by
    ``reset_input_buffer`` before the write, as on real hardware).
    """

    def __init__(self, clock: FakeClock, chunks: list[tuple[float, bytes]] | None = None,
                 cr_response: bytes | None = None, respond_after_s: float = 0.05):
        self._clock = clock
        self._chunks = sorted(list(chunks or []))
        self._cr_response = cr_response
        self._respond_after_s = respond_after_s
        self._cr_answered = False
        self.writes: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        if self._cr_response is not None and not self._cr_answered and data == b"\r":
            self._cr_answered = True
            self._chunks.append((self._clock.t + self._respond_after_s, self._cr_response))
            self._chunks.sort()
        return len(data)

    def read(self, size: int = 1) -> bytes:
        now = self._clock.t
        due = [d for (at, d) in self._chunks if at <= now]
        self._chunks = [(at, d) for (at, d) in self._chunks if at > now]
        return b"".join(due)

    def reset_input_buffer(self) -> None:
        now = self._clock.t
        self._chunks = [(at, d) for (at, d) in self._chunks if at > now]

    def close(self) -> None:
        self.closed = True


@pytest.fixture()
def clock_sleeper():
    clock = FakeClock()
    return clock, FakeSleep(clock)


def make_factory(clock, ports_by_baud):
    created = []

    def factory(port, baud, read_timeout_s):
        created.append(baud)
        return ports_by_baud.get(baud, FakePort(clock, []))

    return factory, created


PROFILE = st.SerialProfile(port="COM4", baud_candidates=(9600, 115200), quiet_period_s=0.35)


def test_open_selects_first_responding_baud(clock_sleeper):
    clock, sleeper = clock_sleeper
    quiet = FakePort(clock)                                              # 9600: silence
    loud = FakePort(clock, cr_response=b"\r\nUser Access Verification\r\n")  # 115200: decodable
    factory, created = make_factory(clock, {9600: quiet, 115200: loud})
    t = st.SerialConsoleTransport(PROFILE, port_factory=factory, clock=clock, sleep=sleeper)
    t.open()
    assert t.negotiated_baud == 115200
    assert created == [9600, 115200]
    assert quiet.closed and not loud.closed


def test_open_all_silent_is_blocked_typed(clock_sleeper):
    clock, sleeper = clock_sleeper
    factory, created = make_factory(clock, {})
    t = st.SerialConsoleTransport(PROFILE, port_factory=factory, clock=clock, sleep=sleeper)
    with pytest.raises(Failure) as exc:
        t.open()
    assert "NO_BAUD_RESPONSE" in exc.value.causes[0]
    assert created == [9600, 115200]  # every candidate probed, in order


def test_open_skips_undecodable_garbage(clock_sleeper):
    clock, sleeper = clock_sleeper
    garbage = FakePort(clock, cr_response=b"\xff\xfe\x80\x81")
    clean = FakePort(clock, cr_response=b"Router>")
    factory, _ = make_factory(clock, {9600: garbage, 115200: clean})
    t = st.SerialConsoleTransport(PROFILE, port_factory=factory, clock=clock, sleep=sleeper)
    t.open()
    assert t.negotiated_baud == 115200
    assert garbage.closed


def test_execute_framed_by_quiet_period(clock_sleeper):
    clock, sleeper = clock_sleeper
    port = FakePort(clock, cr_response=b"boot banner\r\n")
    factory, _ = make_factory(clock, {9600: port})
    t = st.SerialConsoleTransport(
        st.SerialProfile(port="COM4", baud_candidates=(9600,), quiet_period_s=0.35),
        port_factory=factory, clock=clock, sleep=sleeper,
    )
    t.open()
    clock.t = 10.0  # deterministic epoch for execute
    port._chunks = [(10.05, b"version 17.9\r\n")]
    out = t.execute("show version", timeout_s=5.0)
    assert out == b"version 17.9\r\n"
    assert port.writes[-1] == b"show version\r"


def test_execute_stops_on_prompt_match(clock_sleeper):
    clock, sleeper = clock_sleeper
    port = FakePort(clock, cr_response=b"boot\r\n")
    factory, _ = make_factory(clock, {9600: port})
    t = st.SerialConsoleTransport(
        st.SerialProfile(port="COM4", baud_candidates=(9600,), quiet_period_s=5.0),  # quiet period unreachable
        port_factory=factory, clock=clock, sleep=sleeper,
    )
    t.open()
    clock.t = 10.0
    port._chunks = [(10.02, b"ok\r\nRouter# ")]
    out = t.execute("show clock", timeout_s=30.0)
    # prompt match ended the read well before the 5s quiet period could
    assert sleeper.calls < 50
    # ...and the prompt itself is furniture, not evidence. This used to assert
    # out.endswith(b"Router# "), which locked in the defect: a real console's
    # trailing prompt reached the parsers, and `show interfaces status` gained
    # a port named after the prompt.
    assert b"Router#" not in out
    assert out.strip() == b"ok"


def test_execute_timeout_is_deterministic(clock_sleeper):
    clock, sleeper = clock_sleeper
    port = FakePort(clock, cr_response=b"login: ")
    factory, _ = make_factory(clock, {9600: port})
    t = st.SerialConsoleTransport(
        st.SerialProfile(port="COM4", baud_candidates=(9600,)),
        port_factory=factory, clock=clock, sleep=sleeper,
    )
    t.open()
    clock.t = 100.0  # fresh epoch; no chunks scheduled during execute
    port._chunks = []
    with pytest.raises(TimeoutError):
        t.execute("show version", timeout_s=1.0)
    assert clock.t >= 101.0  # fake time advanced exactly via injected sleeps


def test_execute_before_open_is_blocked(clock_sleeper):
    clock, sleeper = clock_sleeper
    t = st.SerialConsoleTransport(PROFILE, port_factory=lambda *a: FakePort(clock), clock=clock, sleep=sleeper)
    with pytest.raises(Failure) as exc:
        t.execute("show version", timeout_s=1.0)
    assert "SESSION_NOT_OPEN" in exc.value.causes[0]


def test_close_resets_session(clock_sleeper):
    clock, sleeper = clock_sleeper
    port = FakePort(clock, cr_response=b"ok>")
    factory, _ = make_factory(clock, {9600: port})
    t = st.SerialConsoleTransport(
        st.SerialProfile(port="COM4", baud_candidates=(9600,)),
        port_factory=factory, clock=clock, sleep=sleeper,
    )
    t.open()
    t.close()
    assert port.closed and t.negotiated_baud is None


def test_missing_pyserial_driver_is_blocked_typed(monkeypatch):
    """No driver installed ⇒ typed BLOCKED, never an ImportError crash (T2)."""
    monkeypatch.setitem(sys.modules, "serial", None)
    with pytest.raises(Failure) as exc:
        st._pyserial_factory("COM1", 9600, 0.05)
    assert "SERIAL_DRIVER_UNAVAILABLE" in exc.value.causes[0]


def test_profile_validation():
    with pytest.raises(ValueError):
        st.SerialProfile(port="COM1", baud_candidates=())
    with pytest.raises(ValueError):
        st.SerialProfile(port="COM1", quiet_period_s=0)
    with pytest.raises(ValueError):
        st.SerialProfile(port="COM1", prompt_pattern="([")


def test_pre_connect_drain_is_bounded_on_a_port_that_never_goes_quiet():
    """The banner read must not depend on the port ever returning b"".

    A real pty returns b"" when nothing is waiting, so an unbounded
    ``while port.read(4096)`` looked correct there. A port object that always
    has bytes — which is what a fixture double does — spun forever and grew
    memory until the interpreter was killed. The bound is the injected clock,
    so this test costs no wall time.
    """
    class ChattyPort:
        def __init__(self) -> None:
            self.closed = False
            self.reset_called = False
            self.reads = 0

        def write(self, data: bytes) -> int:
            return len(data)

        def read(self, size: int = 1) -> bytes:
            self.reads += 1
            if self.reads > 100_000:
                raise AssertionError("the pre-connect drain never stopped")
            return b"banner line\r\n"      # never quiet

        def reset_input_buffer(self) -> None:
            self.reset_called = True

        def close(self) -> None:
            self.closed = True

    port = ChattyPort()
    fake_t = [0.0]

    def clock() -> float:
        fake_t[0] += 0.05
        return fake_t[0]

    transport = st.SerialConsoleTransport(
        st.SerialProfile(port="/dev/null", baud_candidates=(9600,)),
        port_factory=lambda p, b, t: port,
        clock=clock,
        sleep=lambda _s: None,
    )
    transport.open()
    try:
        assert transport.banner.startswith(b"banner line")
        # 0.8 s window / 0.05 s per clock call, for the drain and the probe.
        assert port.reads < 100, f"the drain read {port.reads} times"
    finally:
        transport.close()
