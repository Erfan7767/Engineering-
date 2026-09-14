"""A simulated IOS console on a real OS pseudo-terminal.

`LoopbackSession` is a dictionary: `execute()` looks a command up and returns
bytes. It exercises the parsers, the design engine and the executor, but it
never touches a transport. Every byte-framing decision the platform makes —
baud probing, quiet-period framing, prompt detection, buffer caps — lives in
the serial and telnet transports, and until this module existed those were
tested only against in-process fakes.

This is the other end of a real file descriptor. `pty.openpty()` gives a
master/slave pair; the slave is a genuine device node (``/dev/pts/N``) that
pySerial opens exactly as it would open ``/dev/ttyUSB0``, and a thread plays
the device: it answers the initial carriage return with a banner and prompt,
then serves one canned answer per command line.

So the framing is real. The transport negotiates a baud rate against a channel
that answers, decides where a response ends by watching the line go quiet, and
closes a real descriptor — the same code path an operator's console cable
takes, with no hardware in the room.
"""

from __future__ import annotations

import os
import pty
import select
import threading
import tty
from typing import Optional


class PtyDevice:
    """A console device on a real pseudo-terminal.

    ``answers`` maps a command line to the bytes the device prints *before*
    its prompt. Anything not in the table is answered the way IOS answers an
    unknown command, so a typo in a plan is visible rather than silently
    swallowed.
    """

    def __init__(self, answers: dict[str, bytes], *, banner: bytes = b"",
                 prompt: bytes = b"seed-01> ", unknown: Optional[bytes] = None,
                 echo: bool = True) -> None:
        self._answers = dict(answers)
        self._banner = banner
        self._prompt = prompt
        self._unknown = (unknown if unknown is not None else
                         b"% Invalid input detected at '^' marker.\r\n")
        self._echo = echo
        self._master: Optional[int] = None
        self._slave: Optional[int] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.port_path: str = ""
        #: every command line the device was asked for, in arrival order
        self.received: list[str] = []
        self._greeted = False
        self._backend = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------- lifecycle
    def start(self) -> "PtyDevice":
        master, slave = pty.openpty()
        # Raw: the device owns the line. Without this the terminal discipline
        # echoes and canonicalises for us, and the transport would be framing
        # the kernel's output rather than the device's.
        tty.setraw(master)
        tty.setraw(slave)
        self._master, self._slave = master, slave
        self.port_path = os.ttyname(slave)
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                        name="pty-device")
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=2.0)
        for fd in (self._master, self._slave):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._master = self._slave = None

    @classmethod
    def over(cls, backend, *, prompt: bytes = b"seed-01> ") -> "PtyDevice":
        """Put a real channel in front of an existing simulated device.

        ``backend`` is anything with ``execute(command, timeout_s)`` — in
        practice a :class:`LoopbackSession`, which already models what applying
        a configuration does to the device's own answers (its VLAN table, its
        running-config, its interface membership). Wrapping it means the
        transport, the framing and the byte stream are all real while the
        device still behaves like one that remembers what it was told, so
        verification has something true to read back.
        """
        device = cls({}, prompt=prompt)
        device._backend = backend
        return device

    def __enter__(self) -> "PtyDevice":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # ---------------------------------------------------------------- device
    def _write(self, data: bytes) -> None:
        if self._master is None:
            return
        try:
            os.write(self._master, data)
        except OSError:
            pass

    def _serve(self) -> None:
        assert self._master is not None
        master = self._master
        # The banner is NOT written here. On a pty, a write to the master
        # before anything has the slave open is discarded, so it would simply
        # be lost. A real console prints its banner when the line comes up;
        # the closest faithful moment here is the first carriage return, which
        # is also where the transport is listening.
        line = bytearray()
        while not self._stop.is_set():
            try:
                ready, _w, _x = select.select([master], [], [], 0.05)
            except (OSError, ValueError):
                return
            if not ready:
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError:
                return
            if not chunk:
                return
            for byte in chunk:
                if byte in (10, 13):                     # CR or LF ends a line
                    text = line.decode("utf-8", errors="replace").strip()
                    line.clear()
                    self._write(b"\r\n")
                    self._respond(text)
                else:
                    line.append(byte)
                    if self._echo:
                        self._write(bytes([byte]))

    def _respond(self, command: str) -> None:
        with self._lock:
            self.received.append(command)
        if not self._greeted:
            self._greeted = True
            self._write(self._banner)
        if not command:
            self._write(self._prompt)
            return
        if self._backend is not None:
            try:
                body = self._backend.execute(command, 5.0)
            except Exception as exc:   # noqa: BLE001 - a device error is output
                body = f"% {type(exc).__name__}: {exc}\r\n".encode()
            self._write((body or b"") + self._prompt)
            return
        body = self._answers.get(command)
        if body is None:
            # Longest prefix wins, so `ping 10.0.0.1 repeat 5` can be answered
            # by a `ping` entry without the plan having to guess the arguments.
            candidates = [k for k in self._answers if command.startswith(k)]
            body = self._answers[max(candidates, key=len)] if candidates else None
        self._write((body if body is not None else self._unknown) + self._prompt)
