"""Serialize trusted access to the application's controlling terminal.

The dashboard is intentionally different from every other terminal user.  It may
wait for a complete canonical input line without owning the arbiter, but it must
acquire a low-priority lease and revalidate the handoff before consuming that
line.  Approval and authentication users invalidate such waits and discard any
pending input before displaying their prompt.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum
import heapq
import math
import os
import select
import stat
import termios
import threading
import time
from typing import BinaryIO, Callable, Iterator


CONTROLLING_TTY_PATH = "/dev/tty"
DEFAULT_DASHBOARD_POLL_SECONDS = 0.10
MAX_DASHBOARD_POLL_SECONDS = 1.0
DEFAULT_DASHBOARD_LINE_BYTES = 4096
MAX_DASHBOARD_LINE_BYTES = 64 * 1024


class TerminalError(RuntimeError):
    """Base class for trusted-terminal failures."""


class TerminalUnavailableError(TerminalError):
    """The controlling terminal cannot be opened or safely validated."""


class TerminalBusyError(TerminalError, TimeoutError):
    """A terminal lease could not be acquired before its deadline."""


class TerminalInputError(TerminalError):
    """Dashboard input was not a bounded canonical line."""


class TerminalPriority(IntEnum):
    """Priorities for trusted terminal users.

    An active user is never forcibly interrupted.  Priorities only choose the
    next owner, which is enough for the dashboard because it does not retain a
    lease while waiting for ordinary input.
    """

    DASHBOARD = 0
    ATTACHMENT = 10
    INTERACTIVE = 20
    APPROVAL = 30
    SECRET = 40


@dataclass(frozen=True, slots=True)
class TerminalState:
    """A race-free snapshot suitable for dashboard status rendering."""

    busy: bool
    purpose: str | None
    priority: TerminalPriority | None
    waiting: int
    highest_waiting_priority: TerminalPriority | None
    handoff_generation: int


@dataclass(slots=True)
class _Waiter:
    priority: TerminalPriority
    sequence: int
    thread_id: int
    cancelled: bool = False


def _validate_poll_seconds(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 <= value <= MAX_DASHBOARD_POLL_SECONDS
    ):
        raise ValueError(
            "dashboard poll timeout must be between 0 and "
            f"{MAX_DASHBOARD_POLL_SECONDS:g} seconds"
        )
    return float(value)


def _validate_wait_timeout(value: object | None) -> float | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError("terminal lease timeout must be a non-negative number")
    return float(value)


def _validate_line_limit(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_DASHBOARD_LINE_BYTES
    ):
        raise ValueError(
            "dashboard line limit must be between 1 and "
            f"{MAX_DASHBOARD_LINE_BYTES} bytes"
        )
    return value


def _validate_purpose(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError("terminal purpose must be 1-128 printable characters")
    return value


def _validate_terminal(stream: BinaryIO) -> None:
    """Require a character terminal that is currently in canonical mode."""

    try:
        descriptor = stream.fileno()
        metadata = os.fstat(descriptor)
        attributes = termios.tcgetattr(descriptor)
        valid = (
            os.isatty(descriptor)
            and stat.S_ISCHR(metadata.st_mode)
            and bool(attributes[3] & termios.ICANON)
        )
    except (AttributeError, OSError, termios.error, ValueError) as exc:
        raise TerminalUnavailableError(
            "controlling terminal could not be validated"
        ) from exc
    if not valid:
        raise TerminalUnavailableError(
            "controlling terminal is not a canonical character terminal"
        )


def _wait_until_readable(stream: BinaryIO, timeout: float) -> bool:
    try:
        readable, _writable, _exceptional = select.select(
            (stream.fileno(),), (), (), timeout
        )
    except (AttributeError, OSError, ValueError) as exc:
        raise TerminalUnavailableError(
            "controlling terminal could not be polled"
        ) from exc
    return bool(readable)


def _flush_input(stream: BinaryIO) -> None:
    try:
        termios.tcflush(stream.fileno(), termios.TCIFLUSH)
    except (AttributeError, OSError, termios.error, ValueError) as exc:
        raise TerminalUnavailableError(
            "controlling terminal input could not be discarded"
        ) from exc


class TerminalArbiter:
    """A priority-aware, reentrant lock for the one controlling terminal.

    Passing an instance anywhere an existing ``threading.RLock`` was accepted
    is supported.  The plain context-manager interface represents an
    ``INTERACTIVE`` claim and flushes input before first entry.  New callers
    should use :meth:`claim` to name their purpose and priority.

    The injectable terminal operations exist for deterministic tests.  The
    production opener is deliberately always called with ``/dev/tty``; process
    stdin is never consulted.
    """

    def __init__(
        self,
        *,
        terminal_opener: Callable[..., BinaryIO] = open,
        terminal_validator: Callable[[BinaryIO], None] = _validate_terminal,
        readiness_waiter: Callable[[BinaryIO, float], bool] = _wait_until_readable,
        input_flusher: Callable[[BinaryIO], None] = _flush_input,
        monotonic: Callable[[], float] = time.monotonic,
        dashboard_poll_slice_seconds: float = DEFAULT_DASHBOARD_POLL_SECONDS,
    ) -> None:
        poll_slice = _validate_poll_seconds(dashboard_poll_slice_seconds)
        if poll_slice == 0:
            raise ValueError("dashboard poll slice must be greater than zero")
        for operation, name in (
            (terminal_opener, "terminal opener"),
            (terminal_validator, "terminal validator"),
            (readiness_waiter, "readiness waiter"),
            (input_flusher, "input flusher"),
            (monotonic, "monotonic clock"),
        ):
            if not callable(operation):
                raise TypeError(f"{name} must be callable")

        self._terminal_opener = terminal_opener
        self._terminal_validator = terminal_validator
        self._readiness_waiter = readiness_waiter
        self._input_flusher = input_flusher
        self._monotonic = monotonic
        self._dashboard_poll_slice_seconds = poll_slice

        self._condition = threading.Condition(threading.Lock())
        self._owner_thread_id: int | None = None
        self._owner_depth = 0
        self._owner_priority: TerminalPriority | None = None
        self._owner_purpose: str | None = None
        self._waiters: list[tuple[int, int, _Waiter]] = []
        self._next_sequence = 0
        self._handoff_generation = 0

    @property
    def state(self) -> TerminalState:
        """Return one synchronized snapshot without exposing mutable internals."""

        with self._condition:
            self._discard_cancelled_waiters()
            highest = (
                self._waiters[0][2].priority if self._waiters else None
            )
            return TerminalState(
                busy=self._owner_thread_id is not None,
                purpose=self._owner_purpose,
                priority=self._owner_priority,
                waiting=sum(
                    1 for _priority, _sequence, waiter in self._waiters
                    if not waiter.cancelled
                ),
                highest_waiting_priority=highest,
                handoff_generation=self._handoff_generation,
            )

    @property
    def busy(self) -> bool:
        """Whether a terminal user currently owns a lease."""

        with self._condition:
            return self._owner_thread_id is not None

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        """Implement the ``threading.Lock`` interface at interactive priority."""

        if not isinstance(blocking, bool):
            raise TypeError("blocking must be a boolean")
        if not blocking and timeout != -1:
            raise ValueError("can't specify a timeout for a non-blocking acquire")
        if timeout == -1:
            wait_timeout = None if blocking else 0.0
        else:
            wait_timeout = _validate_wait_timeout(timeout)
        return self._acquire_claim(
            priority=TerminalPriority.INTERACTIVE,
            purpose="interactive terminal use",
            timeout=wait_timeout,
            flush_input=True,
        )

    def release(self) -> None:
        """Release one reentrant level of the current thread's lease."""

        thread_id = threading.get_ident()
        with self._condition:
            if self._owner_thread_id != thread_id:
                raise RuntimeError("cannot release an un-owned terminal arbiter")
            self._owner_depth -= 1
            if self._owner_depth:
                return
            self._owner_thread_id = None
            self._owner_priority = None
            self._owner_purpose = None
            self._condition.notify_all()

    def __enter__(self) -> "TerminalArbiter":
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()

    @contextmanager
    def claim(
        self,
        *,
        priority: TerminalPriority = TerminalPriority.INTERACTIVE,
        purpose: str = "interactive terminal use",
        timeout: float | None = None,
        flush_input: bool | None = None,
    ) -> Iterator["TerminalArbiter"]:
        """Acquire a named terminal lease and release it on context exit.

        Non-dashboard claims flush pending input by default.  A finite timeout
        raises :class:`TerminalBusyError` rather than yielding without a lease.
        """

        priority = self._checked_priority(priority)
        purpose = _validate_purpose(purpose)
        timeout = _validate_wait_timeout(timeout)
        if flush_input is None:
            flush_input = priority is not TerminalPriority.DASHBOARD
        if not isinstance(flush_input, bool):
            raise TypeError("flush_input must be a boolean or None")
        acquired = self._acquire_claim(
            priority=priority,
            purpose=purpose,
            timeout=timeout,
            flush_input=flush_input,
        )
        if not acquired:
            raise TerminalBusyError("controlling terminal remained busy")
        try:
            yield self
        finally:
            self.release()

    def poll_dashboard_line(
        self,
        timeout: float = DEFAULT_DASHBOARD_POLL_SECONDS,
        *,
        max_bytes: int = DEFAULT_DASHBOARD_LINE_BYTES,
    ) -> str | None:
        """Return one trusted dashboard line, or ``None`` when none is available.

        Readiness is polled in bounded slices without holding a terminal lease.
        Once a complete canonical line appears, a dashboard-priority lease is
        acquired before reading.  Any intervening higher-priority handoff makes
        the line stale and returns ``None`` without consuming it.
        """

        timeout = _validate_poll_seconds(timeout)
        max_bytes = _validate_line_limit(max_bytes)
        started = self._monotonic()
        deadline = started + timeout

        with self._condition:
            self._discard_cancelled_waiters()
            if self._owner_thread_id is not None or self._has_priority_waiter():
                return None
            generation = self._handoff_generation

        with self._open_terminal() as terminal:
            self._call_terminal_operation(
                self._terminal_validator,
                terminal,
                failure="controlling terminal could not be validated",
            )
            while True:
                with self._condition:
                    self._discard_cancelled_waiters()
                    if (
                        generation != self._handoff_generation
                        or self._owner_thread_id is not None
                        or self._has_priority_waiter()
                    ):
                        return None

                remaining = max(0.0, deadline - self._monotonic())
                wait_slice = min(self._dashboard_poll_slice_seconds, remaining)
                ready = self._call_terminal_operation(
                    self._readiness_waiter,
                    terminal,
                    wait_slice,
                    failure="controlling terminal could not be polled",
                )
                if not isinstance(ready, bool):
                    raise TypeError("terminal readiness waiter must return bool")
                if ready:
                    break
                if remaining == 0 or self._monotonic() >= deadline:
                    return None

            remaining = max(0.0, deadline - self._monotonic())
            acquired = self._acquire_claim(
                priority=TerminalPriority.DASHBOARD,
                purpose="dashboard input",
                timeout=remaining,
                flush_input=False,
            )
            if not acquired:
                return None
            try:
                with self._condition:
                    if generation != self._handoff_generation:
                        return None
                # A viewer can change terminal modes while the dashboard waits;
                # validate again under the lease immediately before consuming.
                self._call_terminal_operation(
                    self._terminal_validator,
                    terminal,
                    failure="controlling terminal could not be revalidated",
                )
                try:
                    data = terminal.readline(max_bytes + 1)
                except (AttributeError, OSError, ValueError) as exc:
                    raise TerminalUnavailableError(
                        "dashboard input could not be read"
                    ) from exc
                if not isinstance(data, bytes):
                    raise TerminalInputError(
                        "dashboard terminal returned non-byte input"
                    )
                if not data:
                    return None
                if len(data) > max_bytes:
                    self._call_terminal_operation(
                        self._input_flusher,
                        terminal,
                        failure="overlong dashboard input could not be discarded",
                    )
                    raise TerminalInputError("dashboard input line is too long")
                if data.endswith(b"\n"):
                    data = data[:-1]
                    if data.endswith(b"\r"):
                        data = data[:-1]
                return data.decode("utf-8", errors="surrogateescape")
            finally:
                self.release()

    def _acquire_claim(
        self,
        *,
        priority: TerminalPriority,
        purpose: str,
        timeout: float | None,
        flush_input: bool,
    ) -> bool:
        thread_id = threading.get_ident()
        deadline = None if timeout is None else self._monotonic() + timeout
        first_entry = False

        with self._condition:
            if self._owner_thread_id == thread_id:
                self._owner_depth += 1
                return True

            waiter = _Waiter(priority, self._next_sequence, thread_id)
            self._next_sequence += 1
            heapq.heappush(
                self._waiters,
                (-int(priority), waiter.sequence, waiter),
            )
            while True:
                self._discard_cancelled_waiters()
                if (
                    self._owner_thread_id is None
                    and self._waiters
                    and self._waiters[0][2] is waiter
                ):
                    heapq.heappop(self._waiters)
                    self._owner_thread_id = thread_id
                    self._owner_depth = 1
                    self._owner_priority = priority
                    self._owner_purpose = purpose
                    if priority is not TerminalPriority.DASHBOARD:
                        self._handoff_generation += 1
                    first_entry = True
                    self._condition.notify_all()
                    break

                if deadline is None:
                    self._condition.wait()
                    continue
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    waiter.cancelled = True
                    self._discard_cancelled_waiters()
                    self._condition.notify_all()
                    return False
                self._condition.wait(remaining)

        if first_entry and flush_input:
            try:
                self._discard_pending_input()
            except BaseException:
                self.release()
                raise
        return True

    def _discard_pending_input(self) -> None:
        with self._open_terminal() as terminal:
            self._call_terminal_operation(
                self._terminal_validator,
                terminal,
                failure="controlling terminal could not be validated",
            )
            self._call_terminal_operation(
                self._input_flusher,
                terminal,
                failure="controlling terminal input could not be discarded",
            )

    @contextmanager
    def _open_terminal(self) -> Iterator[BinaryIO]:
        try:
            terminal = self._terminal_opener(
                CONTROLLING_TTY_PATH, "rb", buffering=0
            )
        except (OSError, ValueError) as exc:
            raise TerminalUnavailableError(
                f"unable to open controlling terminal {CONTROLLING_TTY_PATH}"
            ) from exc
        try:
            yield terminal
        finally:
            try:
                terminal.close()
            except (AttributeError, OSError, ValueError):
                # Closing a read-only descriptor cannot make already-completed
                # terminal work unsafe, and should not mask the primary result.
                pass

    @staticmethod
    def _checked_priority(value: object) -> TerminalPriority:
        if not isinstance(value, TerminalPriority):
            raise TypeError("terminal priority must be a TerminalPriority")
        return value

    @staticmethod
    def _call_terminal_operation(
        operation: Callable[..., object],
        *arguments: object,
        failure: str,
    ) -> object:
        try:
            return operation(*arguments)
        except TerminalError:
            raise
        except (OSError, termios.error, ValueError) as exc:
            raise TerminalUnavailableError(failure) from exc

    def _has_priority_waiter(self) -> bool:
        return any(
            not waiter.cancelled
            and waiter.priority is not TerminalPriority.DASHBOARD
            for _priority, _sequence, waiter in self._waiters
        )

    def _discard_cancelled_waiters(self) -> None:
        while self._waiters and self._waiters[0][2].cancelled:
            heapq.heappop(self._waiters)
