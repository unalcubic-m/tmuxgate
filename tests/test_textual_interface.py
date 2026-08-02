"""Headless and isolated-PTY tests for the read-only Textual foundation."""

from __future__ import annotations

import asyncio
from contextlib import nullcontext
import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import stat
import struct
import sys
import termios
import threading
import time
import tomllib
from types import SimpleNamespace
import unittest
from unittest import mock

from textual.widgets import Static, TabbedContent

from tmuxgate.approval import ApprovalDecision
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.operator_interface import (
    ActivityKind,
    ExecutionApprovalPrompt,
    OperationalActivity,
    OperatorInterfaceError,
)
from tmuxgate.textual_interface import (
    DashboardJob,
    DashboardMachine,
    DashboardRuntimeSnapshot,
    MAX_DASHBOARD_JOBS,
    MAX_DASHBOARD_MACHINES,
    MINIMUM_COLUMNS,
    MINIMUM_ROWS,
    TextualOperatorInterface,
    TmuxgateDashboardApp,
    validate_textual_terminal,
)


REQUEST_ID = "0123456789abcdef0123456789abcdef"
REPOSITORY = Path(__file__).resolve().parents[1]


class FakeTerminalArbiter:
    def claim(self, **_keywords):
        return nullcontext()

    def poll_dashboard_line(self, **_keywords):
        return None


def config() -> SimpleNamespace:
    return SimpleNamespace(
        broker=SimpleNamespace(approval_mode="always"),
        mcp=SimpleNamespace(host="127.0.0.1", port=8765),
        machines={},
    )


def prompt() -> ExecutionApprovalPrompt:
    request = RequestSpec(
        "app-server",
        ExecutionMode.ARGV,
        "/srv/app",
        argv=("printf", "%s", "hello"),
    )
    return ExecutionApprovalPrompt.create(
        REQUEST_ID,
        request,
        None,
        unbound_fake=True,
    )


class TextualDependencyTests(unittest.TestCase):
    def test_textual_runtime_dependency_is_exactly_pinned(self):
        project = tomllib.loads((REPOSITORY / "pyproject.toml").read_text("utf-8"))[
            "project"
        ]
        pins = [item for item in project["dependencies"] if item.startswith("textual")]
        self.assertEqual(pins, ["textual==8.2.8"])


class TextualOperatorInterfaceTests(unittest.TestCase):
    def test_terminal_ownership_validation_fails_closed(self):
        stdin = mock.Mock()
        stdout = mock.Mock()
        stdin.fileno.return_value = 10
        stdout.fileno.return_value = 11
        with (
            mock.patch("tmuxgate.textual_interface.os.isatty", return_value=False),
            self.assertRaisesRegex(OperatorInterfaceError, "requires terminal"),
        ):
            validate_textual_terminal(stdin, stdout)

        character = stat.S_IFCHR | 0o600
        with (
            mock.patch("tmuxgate.textual_interface.os.isatty", return_value=True),
            mock.patch(
                "tmuxgate.textual_interface.os.fstat",
                side_effect=(
                    SimpleNamespace(st_mode=character, st_rdev=1),
                    SimpleNamespace(st_mode=character, st_rdev=2),
                ),
            ),
            self.assertRaisesRegex(OperatorInterfaceError, "one terminal"),
        ):
            validate_textual_terminal(stdin, stdout)

        with (
            mock.patch("tmuxgate.textual_interface.os.isatty", return_value=True),
            mock.patch(
                "tmuxgate.textual_interface.os.fstat",
                side_effect=(
                    SimpleNamespace(st_mode=character, st_rdev=1),
                    SimpleNamespace(st_mode=character, st_rdev=1),
                ),
            ),
            mock.patch("tmuxgate.textual_interface.os.tcgetpgrp", return_value=7),
            mock.patch("tmuxgate.textual_interface.os.getpgrp", return_value=8),
            self.assertRaisesRegex(OperatorInterfaceError, "foreground"),
        ):
            validate_textual_terminal(stdin, stdout)

    def test_disabled_approval_mode_fails_closed_without_plain_fallback(self):
        with self.assertRaisesRegex(OperatorInterfaceError, "--plain"):
            TextualOperatorInterface(
                FakeTerminalArbiter(), approval_mode="disabled"
            )

    def test_prompt_and_activity_history_are_bounded_and_close_denies(self):
        interface = TextualOperatorInterface(
            FakeTerminalArbiter(),
            activity_capacity=2,
            prompt_capacity=2,
            validate_terminal=False,
        )
        decisions = []
        prompts = [
            ExecutionApprovalPrompt.create(
                f"{index:032x}",
                prompt().request,
                None,
                unbound_fake=True,
            )
            for index in range(1, 4)
        ]
        workers = [
            threading.Thread(
                target=lambda item=item: decisions.append(
                    interface.request_execution_approval(item)
                )
            )
            for item in prompts
        ]
        for worker in workers:
            worker.start()
        deadline = time.monotonic() + 2
        while interface.pending_prompt_count < 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(interface.queued_prompts), 2)
        self.assertEqual(interface.pending_prompt_count, 3)
        self.assertEqual(len(interface.activity_history), 2)
        self.assertTrue(interface.close())
        for worker in workers:
            worker.join(timeout=1)
            self.assertFalse(worker.is_alive())
        self.assertEqual(len(decisions), 3)
        self.assertTrue(
            all(item.decision is ApprovalDecision.DENIED for item in decisions)
        )

    def test_headless_dashboard_navigation_bounds_and_inert_rendering(self):
        interface = TextualOperatorInterface(
            FakeTerminalArbiter(), activity_capacity=3, validate_terminal=False
        )
        self.addCleanup(interface.close)
        malicious = "[bold]not markup[/bold]\x1b]8;;https://evil.invalid\x07link"
        for index in range(8):
            interface.publish_activity(
                OperationalActivity.create(
                    ActivityKind.BROKER_AUDIT,
                    f"activity-{index} {malicious}",
                )
            )
        machines = tuple(
            DashboardMachine(
                alias=f"machine-{index}",
                description=malicious,
                enabled=index % 2 == 0,
                ssh_state="idle",
            )
            for index in range(MAX_DASHBOARD_MACHINES + 20)
        )
        jobs = tuple(
            DashboardJob(
                request_id=f"{index:032x}",
                machine_alias="app-server",
                state=malicious,
                updated_at="2026-08-03T00:00:00Z",
                active=index % 2 == 0,
            )
            for index in range(MAX_DASHBOARD_JOBS + 20)
        )
        interface.bind_dashboard_provider(
            lambda: DashboardRuntimeSnapshot(
                ready=True,
                listener="http://127.0.0.1:8765/mcp",
                approval_mode="always",
                machines=machines,
                jobs=jobs,
                terminal_owner=malicious,
            )
        )
        app = TmuxgateDashboardApp(interface, threading.Event(), config())

        async def exercise() -> None:
            async with app.run_test(size=(100, 30)) as pilot:
                await pilot.pause()
                widget_count = len(list(app.query("*")))
                dashboard = app.query_one("#dashboard-content", Static).render().plain
                self.assertIn("Application readiness: ready", dashboard)
                self.assertIn("Configured machines: 276", dashboard)
                self.assertIn("Active durable jobs: 60", dashboard)
                self.assertNotIn("\x1b", dashboard)
                self.assertIn(r"\x1b", dashboard)

                for key, expected in (
                    ("j", "jobs"),
                    ("m", "machines"),
                    ("a", "activity"),
                    ("r", "requests"),
                    ("?", "help"),
                    ("d", "dashboard"),
                ):
                    await pilot.press(key)
                    await pilot.pause()
                    self.assertEqual(
                        app.query_one("#views", TabbedContent).active, expected
                    )

                jobs_text = app.query_one("#jobs-content", Static).render().plain
                machines_text = app.query_one(
                    "#machines-content", Static
                ).render().plain
                activity_text = app.query_one(
                    "#activity-content", Static
                ).render().plain
                self.assertLessEqual(len(jobs_text.splitlines()), MAX_DASHBOARD_JOBS + 1)
                self.assertLessEqual(
                    len(machines_text.splitlines()), MAX_DASHBOARD_MACHINES + 1
                )
                self.assertEqual(activity_text.count("activity-"), 3)
                self.assertIn("[bold]not markup[/bold]", activity_text)
                self.assertNotIn("\x1b", activity_text)
                self.assertIn(r"\x1b", activity_text)
                self.assertEqual(len(list(app.query("*"))), widget_count)

                await pilot.resize_terminal(MINIMUM_COLUMNS - 1, MINIMUM_ROWS - 1)
                await pilot.pause()
                self.assertTrue(app.minimum_size)
                self.assertTrue(app.query_one("#minimum-warning", Static).display)
                self.assertFalse(app.query_one("#views", TabbedContent).display)
                await pilot.press("j")
                self.assertEqual(
                    app.query_one("#views", TabbedContent).active, "dashboard"
                )

                await pilot.resize_terminal(MINIMUM_COLUMNS, MINIMUM_ROWS)
                await pilot.pause()
                self.assertFalse(app.minimum_size)
                self.assertTrue(app.query_one("#views", TabbedContent).display)

        asyncio.run(exercise())


PTY_HELPER = r"""
import asyncio
from contextlib import nullcontext
import os
import signal
import termios
import threading
from types import SimpleNamespace
from tmuxgate.textual_interface import TextualOperatorInterface, TmuxgateDashboardApp

mode = os.environ["TMUXGATE_TUI_TEST_MODE"]
terminal = os.open("/dev/tty", os.O_RDWR)
before = termios.tcgetattr(terminal)
stop = threading.Event()

class Terminal:
    def claim(self, **_keywords):
        return nullcontext()
    def poll_dashboard_line(self, **_keywords):
        return None

class Probe(TmuxgateDashboardApp):
    def on_mount(self):
        super().on_mount()
        if mode == "normal":
            self.set_timer(0.2, self.exit)
        elif mode == "exception":
            raise RuntimeError("synthetic TUI failure")

if mode == "cancel":
    interface = TextualOperatorInterface(Terminal())
    app = Probe(interface, stop, SimpleNamespace())
    async def cancel_app():
        task = asyncio.create_task(app.run_async())
        await asyncio.sleep(0.2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    asyncio.run(cancel_app())
    interface.close()
else:
    interface = TextualOperatorInterface(
        Terminal(),
        app_factory=lambda owner, event, config: Probe(owner, event, config),
    )
    config = SimpleNamespace(
        broker=SimpleNamespace(approval_mode="always"),
        mcp=SimpleNamespace(host="127.0.0.1", port=8765),
        machines={},
    )
    if mode == "signal":
        signal.signal(signal.SIGTERM, lambda *_arguments: stop.set())
    try:
        interface.run_dashboard(stop, config)
    except BaseException:
        pass
    finally:
        interface.close()

after = termios.tcgetattr(terminal)
os.write(terminal, b"TMUXGATE_RESTORED=" + (b"yes" if before == after else b"no") + b"\r\n")
os.close(terminal)
"""


@unittest.skipUnless(hasattr(pty, "fork"), "requires a Unix PTY")
class TextualPtyLifecycleTests(unittest.TestCase):
    def _run_mode(self, mode: str) -> bytes:
        child, master = pty.fork()
        if child == 0:
            environment = dict(os.environ)
            environment["TMUXGATE_TUI_TEST_MODE"] = mode
            environment.setdefault("TERM", "xterm-256color")
            os.execve(
                sys.executable,
                [sys.executable, "-c", PTY_HELPER],
                environment,
            )
        try:
            fcntl.ioctl(
                master,
                termios.TIOCSWINSZ,
                struct.pack("HHHH", 30, 100, 0, 0),
            )
            output = bytearray()
            sent_signal = False
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                readable, _, _ = select.select([master], [], [], 0.1)
                if readable:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
                if (
                    mode == "signal"
                    and not sent_signal
                    and b"\x1b[?1049h" in output
                ):
                    os.kill(child, signal.SIGTERM)
                    sent_signal = True
                waited, status = os.waitpid(child, os.WNOHANG)
                if waited:
                    self.assertTrue(os.WIFEXITED(status), output.decode(errors="replace"))
                    break
            else:
                os.kill(child, signal.SIGKILL)
                self.fail(f"Textual PTY helper timed out in {mode} mode")
            if mode == "signal":
                self.assertTrue(sent_signal)
            return bytes(output)
        finally:
            os.close(master)

    def test_normal_exception_signal_and_cancellation_restore_terminal(self):
        for mode in ("normal", "exception", "signal", "cancel"):
            with self.subTest(mode=mode):
                output = self._run_mode(mode)
                self.assertIn(b"\x1b[?1049h", output)
                self.assertIn(b"\x1b[?1049l", output)
                self.assertIn(b"TMUXGATE_RESTORED=yes", output)


if __name__ == "__main__":
    unittest.main()
