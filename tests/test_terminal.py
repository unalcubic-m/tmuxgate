import io
import threading
import time
import unittest

from tmuxgate.terminal import (
    CONTROLLING_TTY_PATH,
    TerminalArbiter,
    TerminalBusyError,
    TerminalInputError,
    TerminalPriority,
    TerminalUnavailableError,
)


class RecordingTerminal(io.BytesIO):
    def __init__(self, content=b""):
        super().__init__(content)
        self.read_calls = 0
        self.was_closed = False

    def readline(self, size=-1):
        self.read_calls += 1
        return super().readline(size)

    def close(self):
        self.was_closed = True
        super().close()


class TerminalFactory:
    def __init__(self, *contents):
        self._contents = list(contents)
        self.calls = []
        self.streams = []

    def __call__(self, path, mode, *, buffering):
        self.calls.append((path, mode, buffering))
        content = self._contents.pop(0) if self._contents else b""
        stream = RecordingTerminal(content)
        self.streams.append(stream)
        return stream


def wait_for(predicate, timeout=1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


class TerminalArbiterTests(unittest.TestCase):
    def make_arbiter(self, factory=None, **overrides):
        factory = TerminalFactory() if factory is None else factory
        flushed = []
        validated = []
        arguments = {
            "terminal_opener": factory,
            "terminal_validator": lambda stream: validated.append(stream),
            "readiness_waiter": lambda stream, timeout: True,
            "input_flusher": lambda stream: flushed.append(stream),
            "dashboard_poll_slice_seconds": 0.01,
        }
        arguments.update(overrides)
        return TerminalArbiter(**arguments), factory, validated, flushed

    def test_plain_context_manager_is_reentrant_and_flushes_once(self):
        arbiter, factory, validated, flushed = self.make_arbiter()

        with arbiter:
            outer_state = arbiter.state
            with arbiter:
                self.assertTrue(arbiter.busy)
                self.assertEqual(arbiter.state, outer_state)

        self.assertFalse(arbiter.busy)
        self.assertEqual(
            factory.calls,
            [(CONTROLLING_TTY_PATH, "rb", 0)],
        )
        self.assertEqual(len(validated), 1)
        self.assertEqual(flushed, validated)
        self.assertEqual(outer_state.priority, TerminalPriority.INTERACTIVE)
        self.assertEqual(outer_state.handoff_generation, 1)

    def test_claim_exposes_named_busy_state(self):
        arbiter, _factory, _validated, _flushed = self.make_arbiter()

        with arbiter.claim(
            priority=TerminalPriority.APPROVAL,
            purpose="request approval",
            flush_input=False,
        ):
            state = arbiter.state
            self.assertTrue(state.busy)
            self.assertEqual(state.purpose, "request approval")
            self.assertEqual(state.priority, TerminalPriority.APPROVAL)
            self.assertEqual(state.waiting, 0)

        self.assertFalse(arbiter.state.busy)
        self.assertIsNone(arbiter.state.purpose)

    def test_terminal_users_are_serialized(self):
        arbiter, _factory, _validated, _flushed = self.make_arbiter()
        entered = threading.Event()
        finished = threading.Event()

        def worker():
            with arbiter.claim(
                priority=TerminalPriority.ATTACHMENT,
                purpose="attachment",
                flush_input=False,
            ):
                entered.set()
            finished.set()

        with arbiter.claim(
            priority=TerminalPriority.APPROVAL,
            purpose="approval",
            flush_input=False,
        ):
            thread = threading.Thread(target=worker)
            thread.start()
            self.assertTrue(wait_for(lambda: arbiter.state.waiting == 1))
            self.assertFalse(entered.is_set())

        self.assertTrue(finished.wait(1))
        thread.join(1)
        self.assertFalse(thread.is_alive())

    def test_highest_priority_waiter_is_selected_then_fifo(self):
        arbiter, _factory, _validated, _flushed = self.make_arbiter()
        order = []

        def worker(name, priority):
            with arbiter.claim(
                priority=priority,
                purpose=name,
                flush_input=False,
            ):
                order.append(name)
                time.sleep(0.01)

        with arbiter.claim(
            priority=TerminalPriority.DASHBOARD,
            purpose="dashboard transaction",
            flush_input=False,
        ):
            low = threading.Thread(
                target=worker, args=("low", TerminalPriority.ATTACHMENT)
            )
            low.start()
            self.assertTrue(wait_for(lambda: arbiter.state.waiting == 1))
            first_high = threading.Thread(
                target=worker, args=("high-1", TerminalPriority.SECRET)
            )
            second_high = threading.Thread(
                target=worker, args=("high-2", TerminalPriority.SECRET)
            )
            first_high.start()
            self.assertTrue(wait_for(lambda: arbiter.state.waiting == 2))
            second_high.start()
            self.assertTrue(wait_for(lambda: arbiter.state.waiting == 3))
            self.assertEqual(
                arbiter.state.highest_waiting_priority,
                TerminalPriority.SECRET,
            )

        for thread in (low, first_high, second_high):
            thread.join(1)
            self.assertFalse(thread.is_alive())
        self.assertEqual(order, ["high-1", "high-2", "low"])

    def test_timed_claim_fails_without_disturbing_owner(self):
        arbiter, _factory, _validated, _flushed = self.make_arbiter()
        result = []

        def worker():
            try:
                with arbiter.claim(
                    priority=TerminalPriority.APPROVAL,
                    purpose="timed approval",
                    timeout=0.02,
                    flush_input=False,
                ):
                    result.append("entered")
            except TerminalBusyError:
                result.append("timed-out")

        with arbiter.claim(
            priority=TerminalPriority.DASHBOARD,
            purpose="configuration",
            flush_input=False,
        ):
            thread = threading.Thread(target=worker)
            thread.start()
            thread.join(1)
            self.assertFalse(thread.is_alive())
            self.assertEqual(result, ["timed-out"])
            self.assertEqual(arbiter.state.purpose, "configuration")
            self.assertEqual(arbiter.state.waiting, 0)

    def test_non_owner_cannot_release(self):
        arbiter, _factory, _validated, _flushed = self.make_arbiter()
        errors = []

        with arbiter.claim(
            priority=TerminalPriority.DASHBOARD,
            purpose="dashboard",
            flush_input=False,
        ):
            def release_from_worker():
                try:
                    arbiter.release()
                except RuntimeError as exc:
                    errors.append(str(exc))

            thread = threading.Thread(target=release_from_worker)
            thread.start()
            thread.join(1)
            self.assertTrue(arbiter.busy)

        self.assertEqual(errors, ["cannot release an un-owned terminal arbiter"])

    def test_failed_flush_releases_lease_and_fails_closed(self):
        factory = TerminalFactory()

        def reject_terminal(stream):
            raise OSError("not a terminal")

        arbiter, _factory, _validated, _flushed = self.make_arbiter(
            factory,
            terminal_validator=reject_terminal,
        )

        with self.assertRaises(TerminalUnavailableError):
            with arbiter:
                self.fail("unsafe terminal lease was yielded")

        self.assertFalse(arbiter.busy)
        self.assertEqual(arbiter.state.waiting, 0)

    def test_dashboard_poll_reads_one_canonical_line_from_only_dev_tty(self):
        factory = TerminalFactory(b"jobs\r\n")
        arbiter, _factory, validated, flushed = self.make_arbiter(factory)

        line = arbiter.poll_dashboard_line(timeout=0)

        self.assertEqual(line, "jobs")
        self.assertEqual(
            factory.calls,
            [(CONTROLLING_TTY_PATH, "rb", 0)],
        )
        self.assertEqual(validated, [factory.streams[0], factory.streams[0]])
        self.assertEqual(flushed, [])
        self.assertEqual(factory.streams[0].read_calls, 1)
        self.assertTrue(factory.streams[0].was_closed)
        self.assertFalse(arbiter.busy)

    def test_dashboard_poll_preserves_non_utf8_bytes_with_surrogateescape(self):
        factory = TerminalFactory(b"show-\xff\n")
        arbiter, _factory, _validated, _flushed = self.make_arbiter(factory)

        self.assertEqual(
            arbiter.poll_dashboard_line(timeout=0),
            "show-\udcff",
        )

    def test_dashboard_poll_does_not_open_terminal_while_busy(self):
        arbiter, factory, _validated, _flushed = self.make_arbiter()

        with arbiter.claim(
            priority=TerminalPriority.APPROVAL,
            purpose="approval",
            flush_input=False,
        ):
            self.assertIsNone(arbiter.poll_dashboard_line(timeout=0.1))

        self.assertEqual(factory.calls, [])

    def test_dashboard_idle_wait_does_not_hold_terminal_lease(self):
        factory = TerminalFactory(b"stale\n", b"")
        waiter_started = threading.Event()
        finish_wait = threading.Event()
        result = []

        def wait_for_input(stream, timeout):
            waiter_started.set()
            finish_wait.wait(0.5)
            return True

        arbiter, _factory, _validated, flushed = self.make_arbiter(
            factory,
            readiness_waiter=wait_for_input,
            dashboard_poll_slice_seconds=0.5,
        )

        def dashboard():
            result.append(arbiter.poll_dashboard_line(timeout=1.0))

        thread = threading.Thread(target=dashboard)
        thread.start()
        self.assertTrue(waiter_started.wait(1))
        self.assertFalse(arbiter.busy)

        with arbiter.claim(
            priority=TerminalPriority.APPROVAL,
            purpose="approval",
        ):
            self.assertEqual(arbiter.state.purpose, "approval")

        finish_wait.set()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, [None])
        self.assertEqual(factory.streams[0].read_calls, 0)
        self.assertEqual(flushed, [factory.streams[1]])
        self.assertEqual(arbiter.state.handoff_generation, 1)

    def test_overlong_dashboard_line_is_flushed_and_rejected(self):
        factory = TerminalFactory(b"abcde\n")
        arbiter, _factory, _validated, flushed = self.make_arbiter(factory)

        with self.assertRaisesRegex(TerminalInputError, "too long"):
            arbiter.poll_dashboard_line(timeout=0, max_bytes=4)

        self.assertEqual(flushed, [factory.streams[0]])
        self.assertFalse(arbiter.busy)

    def test_poll_and_claim_arguments_are_strictly_bounded(self):
        arbiter, _factory, _validated, _flushed = self.make_arbiter()

        for timeout in (-1, 1.01, float("inf"), True):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    arbiter.poll_dashboard_line(timeout=timeout)
        for max_bytes in (0, 65537, True):
            with self.subTest(max_bytes=max_bytes):
                with self.assertRaises(ValueError):
                    arbiter.poll_dashboard_line(max_bytes=max_bytes)
        with self.assertRaises(TypeError):
            with arbiter.claim(priority=20):
                pass
        with self.assertRaises(ValueError):
            with arbiter.claim(purpose="approval\nspoof"):
                pass


if __name__ == "__main__":
    unittest.main()
