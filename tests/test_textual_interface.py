"""Headless and isolated-PTY tests for the Textual operator interface."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager, nullcontext
import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import socket
import stat
import struct
import sys
import tempfile
import termios
import threading
import time
import tomllib
from types import SimpleNamespace
import unittest
from unittest import mock

from textual.widgets import Button, Static, TabbedContent

from tmuxgate.approval import ApprovalDecision
from tmuxgate.config import parse_config
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.operator_interface import (
    ActivityKind,
    ConnectionPhase,
    ExecutionApprovalPrompt,
    MachineDisablePrompt,
    OperationalActivity,
    OperatorInterfaceError,
    PendingDecision,
    QueuedPrompt,
    RemoteMutationState,
    RouteFallbackPrompt,
    SecretInputRecipient,
    SshRetryPrompt,
)
from tmuxgate.textual_interface import (
    APPROVAL_ARM_SECONDS,
    DashboardJob,
    DashboardMachine,
    DashboardRuntimeSnapshot,
    ExecutionApprovalScreen,
    MAX_DASHBOARD_JOBS,
    MAX_DASHBOARD_MACHINES,
    MachineDisableScreen,
    MINIMUM_COLUMNS,
    MINIMUM_ROWS,
    REFRESH_SECONDS,
    RouteFallbackScreen,
    SecretInputAuthorizationScreen,
    SshRetryScreen,
    TextualOperatorInterface,
    TerminalOwnershipState,
    TmuxgateDashboardApp,
    flush_textual_input,
    validate_textual_terminal,
)
from tmuxgate.settings import serialize_config
from test_config import valid_config
from test_connection_plan import build_plan


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


def secret_prompt():
    execution = prompt()
    return SecretInputRecipient(
        REQUEST_ID,
        execution.request,
        build_plan(),
        "home-lan",
    ).create_prompt("tmuxgate-" + REQUEST_ID[:12])


class TextualDependencyTests(unittest.TestCase):
    def test_textual_runtime_dependency_is_exactly_pinned(self):
        project = tomllib.loads((REPOSITORY / "pyproject.toml").read_text("utf-8"))[
            "project"
        ]
        pins = [item for item in project["dependencies"] if item.startswith("textual")]
        self.assertEqual(pins, ["textual==8.2.8"])


class TextualOperatorInterfaceTests(unittest.TestCase):
    @staticmethod
    async def _wait_for_approval(
        app: TmuxgateDashboardApp,
        pilot,
        expected_prompt: ExecutionApprovalPrompt,
    ) -> ExecutionApprovalScreen:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if isinstance(app.screen, ExecutionApprovalScreen):
                screen = app.screen
                if (
                    screen.prompt.prompt_id == expected_prompt.prompt_id
                    and len(list(screen.query("#approval-views"))) == 1
                    and len(list(screen.query("#approval-deny:focus"))) == 1
                ):
                    return screen
            await pilot.pause(0.02)
        raise AssertionError("matching execution approval modal did not open")

    @staticmethod
    async def _wait_for_recovery(app, pilot, screen_type, expected_prompt):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if isinstance(app.screen, screen_type):
                screen = app.screen
                if (
                    screen.prompt.prompt_id == expected_prompt.prompt_id
                    and len(list(screen.query("#recovery-views"))) == 1
                    and len(list(screen.query("#recovery-cancel:focus"))) == 1
                ):
                    return screen
            await pilot.pause(0.02)
        raise AssertionError("matching recovery modal did not open")

    @staticmethod
    async def _wait_for_machine_disable(app, pilot, expected_prompt):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if isinstance(app.screen, MachineDisableScreen):
                screen = app.screen
                if (
                    screen.prompt.prompt_id == expected_prompt.prompt_id
                    and len(list(screen.query("#disable-views"))) == 1
                    and len(list(screen.query("#disable-cancel:focus"))) == 1
                ):
                    return screen
            await pilot.pause(0.02)
        raise AssertionError("matching machine-disable modal did not open")

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

    def test_modal_boundary_flushes_kernel_input_or_fails_closed(self):
        stream = mock.Mock()
        stream.fileno.return_value = 12
        with (
            mock.patch("tmuxgate.textual_interface.os.isatty", return_value=True),
            mock.patch("tmuxgate.textual_interface.termios.tcflush") as flushed,
        ):
            flush_textual_input(stream)
        flushed.assert_called_once_with(12, termios.TCIFLUSH)

        with (
            mock.patch("tmuxgate.textual_interface.os.isatty", return_value=True),
            mock.patch(
                "tmuxgate.textual_interface.termios.tcflush",
                side_effect=OSError("synthetic flush failure"),
            ),
            self.assertRaisesRegex(OperatorInterfaceError, "discard buffered"),
        ):
            flush_textual_input(stream)

    def test_runtime_terminal_loss_stops_tui_and_denies_pending_prompt(self):
        terminal_lost = threading.Event()

        def validator() -> None:
            if terminal_lost.is_set():
                raise OperatorInterfaceError("foreground terminal ownership lost")

        interface = TextualOperatorInterface(
            FakeTerminalArbiter(),
            terminal_validator=validator,
        )
        self.addCleanup(interface.close)
        pending_prompt = prompt()
        decisions = []
        worker = threading.Thread(
            target=lambda: decisions.append(
                interface.request_execution_approval(pending_prompt)
            )
        )
        worker.start()
        deadline = time.monotonic() + 1
        while interface.pending_prompt_count < 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        stop = threading.Event()
        app = TmuxgateDashboardApp(interface, stop, config())

        async def exercise() -> None:
            async with app.run_test(size=(100, 30)) as pilot:
                await self._wait_for_approval(app, pilot, pending_prompt)
                terminal_lost.set()
                await pilot.pause(REFRESH_SECONDS + 0.10)

        asyncio.run(exercise())
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertTrue(stop.is_set())
        self.assertIsInstance(app.snapshot_failure, OperatorInterfaceError)
        self.assertEqual(len(decisions), 1)
        self.assertIs(decisions[0].decision, ApprovalDecision.DENIED)

    def test_textual_exception_directs_explicit_plain_restart(self):
        class FailingApp(TmuxgateDashboardApp):
            def run(self, *args, **kwargs):
                raise RuntimeError("synthetic driver initialization failure")

        interface = TextualOperatorInterface(
            FakeTerminalArbiter(),
            validate_terminal=False,
            app_factory=FailingApp,
        )
        self.addCleanup(interface.close)
        with self.assertRaisesRegex(OperatorInterfaceError, "--plain"):
            interface.run_dashboard(threading.Event(), config())

    def test_disabled_execution_approval_never_bypasses_secret_authorization(self):
        interface = TextualOperatorInterface(
            FakeTerminalArbiter(),
            approval_mode="disabled",
            validate_terminal=False,
        )
        self.addCleanup(interface.close)
        execution = prompt()
        self.assertIs(
            interface.request_execution_approval(execution).decision,
            ApprovalDecision.APPROVED,
        )

        secret = secret_prompt()
        result = []
        worker = threading.Thread(
            target=lambda: result.append(
                interface.request_secret_input_authorization(secret)
            )
        )
        worker.start()
        deadline = time.monotonic() + 1
        while interface.pending_prompt_count != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(worker.is_alive())
        interface.close()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertIs(result[0].decision, ApprovalDecision.DENIED)

    def test_exact_secret_modal_reserves_suspends_and_restores_terminal(self):
        events = []

        class RecordingTerminal(FakeTerminalArbiter):
            @contextmanager
            def claim(self, **keywords):
                events.append(("claim", keywords["priority"]))
                yield
                events.append(("release", keywords["priority"]))

        class RecordingApp(TmuxgateDashboardApp):
            @contextmanager
            def suspend(self):
                events.append("suspend")
                yield
                events.append("resume")

        interface = TextualOperatorInterface(
            RecordingTerminal(), validate_terminal=False
        )
        self.addCleanup(interface.close)
        secret = secret_prompt()
        decisions = []
        authorizer = threading.Thread(
            target=lambda: decisions.append(
                interface.request_secret_input_authorization(secret)
            )
        )
        authorizer.start()
        app = RecordingApp(interface, threading.Event(), config())

        async def exercise() -> None:
            async with app.run_test(size=(100, 30)) as pilot:
                deadline = time.monotonic() + 2
                while not (
                    isinstance(app.screen, SecretInputAuthorizationScreen)
                    and len(list(app.screen.query("#secret-document"))) == 1
                    and len(list(app.screen.query("#secret-deny:focus"))) == 1
                ):
                    if time.monotonic() >= deadline:
                        raise AssertionError("secret authorization modal did not open")
                    await pilot.pause(0.02)
                screen = app.screen
                self.assertIs(
                    interface.terminal_ownership_state,
                    TerminalOwnershipState.MODAL,
                )
                document = screen.query_one("#secret-document", Static).render().plain
                self.assertIn(secret.request_id, document)
                self.assertIn(secret.endpoint_id, document)
                self.assertIn(secret.viewer_session_id, document)
                self.assertIn(secret.secret_input_binding_sha256, document)
                self.assertTrue(screen.query_one("#secret-deny", Button).has_focus)
                await pilot.pause(APPROVAL_ARM_SECONDS + 0.10)
                self.assertTrue(await pilot.click("#secret-approve"))
                deadline = time.monotonic() + 1
                while authorizer.is_alive() and time.monotonic() < deadline:
                    await pilot.pause(0.02)
                self.assertIs(
                    interface.terminal_ownership_state,
                    TerminalOwnershipState.EXTERNAL,
                )

                handoff = threading.Thread(
                    target=lambda: interface.run_external_terminal_session(
                        secret, lambda: events.append("trusted-session")
                    )
                )
                handoff.start()
                deadline = time.monotonic() + 2
                while handoff.is_alive() and time.monotonic() < deadline:
                    await pilot.pause(0.02)
                handoff.join(timeout=0)
                self.assertFalse(handoff.is_alive())
                self.assertIs(
                    interface.terminal_ownership_state,
                    TerminalOwnershipState.TUI,
                )

        asyncio.run(exercise())
        authorizer.join(timeout=1)
        self.assertIs(decisions[0].decision, ApprovalDecision.APPROVED)
        self.assertEqual(
            events,
            [
                ("claim", 40),
                "suspend",
                "trusted-session",
                "resume",
                ("release", 40),
            ],
        )

    def test_external_failure_restores_tui_and_rejects_stale_authority(self):
        class RecordingApp(TmuxgateDashboardApp):
            @contextmanager
            def suspend(self):
                yield

        interface = TextualOperatorInterface(
            FakeTerminalArbiter(), validate_terminal=False
        )
        self.addCleanup(interface.close)
        secret = secret_prompt()
        self.assertTrue(interface._begin_modal(secret))
        interface._complete_modal(secret, ApprovalDecision.APPROVED)
        stale = SecretInputRecipient(
            "1" * 32,
            secret.request,
            secret.connection_plan,
            secret.endpoint_id,
        ).create_prompt("tmuxgate-" + ("1" * 12))
        with self.assertRaisesRegex(OperatorInterfaceError, "exact authorization"):
            interface._validate_external_reservation(stale)
        app = RecordingApp(interface, threading.Event(), config())
        with self.assertRaisesRegex(RuntimeError, "synthetic handoff failure"):
            app.run_external_terminal_session(
                secret,
                lambda: (_ for _ in ()).throw(
                    RuntimeError("synthetic handoff failure")
                ),
            )
        self.assertIs(
            interface.terminal_ownership_state,
            TerminalOwnershipState.TUI,
        )

        abandoned = secret_prompt()
        pending = PendingDecision(abandoned)
        pending.abandon()
        self.assertTrue(interface._begin_modal(abandoned))
        self.assertFalse(
            interface._resolve_modal(
                QueuedPrompt(99, abandoned, pending),
                ApprovalDecision.APPROVED,
            )
        )
        self.assertIs(
            interface.terminal_ownership_state,
            TerminalOwnershipState.TUI,
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
                machines_text = (
                    app.query_one("#machines-content", Static).render().plain
                )
                activity_text = (
                    app.query_one("#activity-content", Static).render().plain
                )
                self.assertLessEqual(
                    len(jobs_text.splitlines()), MAX_DASHBOARD_JOBS + 1
                )
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

    def test_connection_progress_replaces_request_projection_in_place(self):
        interface = TextualOperatorInterface(
            FakeTerminalArbiter(), validate_terminal=False
        )
        self.addCleanup(interface.close)
        for phase in (
            ConnectionPhase.CONNECTING,
            ConnectionPhase.RUNNING,
            ConnectionPhase.COMPLETED,
        ):
            interface.publish_activity(
                OperationalActivity.create(
                    ActivityKind.CONNECTION,
                    f"phase {phase.value}",
                    request_id=REQUEST_ID,
                    machine_name="app-server",
                    endpoint_id="home-lan",
                    connection_phase=phase,
                    remote_mutation_state=(
                        RemoteMutationState.NOT_STARTED
                        if phase is ConnectionPhase.CONNECTING
                        else RemoteMutationState.STARTED
                    ),
                )
            )
        app = TmuxgateDashboardApp(interface, threading.Event(), config())

        async def exercise() -> None:
            async with app.run_test(size=(100, 30)) as pilot:
                await pilot.pause()
                dashboard = app.query_one("#dashboard-content", Static).render().plain
                progress = next(
                    line
                    for line in dashboard.splitlines()
                    if line.startswith("Request connection progress:")
                )
                self.assertIn("01234567=completed@home-lan", progress)
                self.assertNotIn("connecting", progress)
                self.assertNotIn("running", progress)
                self.assertEqual(progress.count("01234567="), 1)

        asyncio.run(exercise())

    def test_retry_and_fallback_modals_are_exact_safe_and_separate(self):
        interface = TextualOperatorInterface(
            FakeTerminalArbiter(), validate_terminal=False
        )
        self.addCleanup(interface.close)
        plan = build_plan()
        request = RequestSpec(
            "app-server",
            ExecutionMode.ARGV,
            "/srv/app",
            argv=("true",),
        )
        diagnostics = b"[bold]literal[/bold]\x1b]8;;https://evil.invalid\x07\n"
        retry = SshRetryPrompt.create(
            REQUEST_ID,
            request,
            plan,
            endpoint_id="home-lan",
            failure_detail="OpenSSH exited with status 255\ninjected label",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
            openssh_diagnostics=diagnostics,
        )
        fallback = RouteFallbackPrompt.create(
            REQUEST_ID,
            request,
            plan,
            failed_endpoint_id="home-lan",
            fallback_endpoint_id="wireguard",
            failure_detail="same endpoint retry was cancelled",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
            openssh_diagnostics=diagnostics,
        )
        decisions: dict[str, ApprovalDecision] = {}

        def decide(item):
            method = (
                interface.request_ssh_retry
                if isinstance(item, SshRetryPrompt)
                else interface.request_fallback
            )
            decisions[item.prompt_id] = method(item).decision

        first = threading.Thread(target=decide, args=(retry,))
        second = threading.Thread(target=decide, args=(fallback,))
        first.start()
        while interface.pending_prompt_count < 1:
            time.sleep(0.01)
        second.start()
        while interface.pending_prompt_count < 2:
            time.sleep(0.01)
        app = TmuxgateDashboardApp(interface, threading.Event(), config())

        async def exercise() -> None:
            async with app.run_test(size=(100, 30)) as pilot:
                retry_screen = await self._wait_for_recovery(
                    app, pilot, SshRetryScreen, retry
                )
                self.assertTrue(
                    retry_screen.query_one("#recovery-cancel", Button).has_focus
                )
                summary = (
                    retry_screen.query_one("#recovery-summary-document", Static)
                    .render()
                    .plain
                )
                self.assertIn("Permitted retry: 1 of 1", summary)
                self.assertIn("Remote command: not_started", summary)
                self.assertIn(r"\x0ainjected label", summary)
                diagnostics_text = (
                    retry_screen.query_one("#recovery-diagnostics-document", Static)
                    .render()
                    .plain
                )
                binding = (
                    retry_screen.query_one("#recovery-binding-document", Static)
                    .render()
                    .plain
                )
                self.assertNotIn("\x1b", diagnostics_text)
                self.assertIn(r"\x1b", diagnostics_text)
                self.assertIn(retry.retry_binding_sha256, binding)
                await pilot.press("x")
                await pilot.pause()
                self.assertTrue(first.is_alive())
                await pilot.press("enter")

                fallback_screen = await self._wait_for_recovery(
                    app, pilot, RouteFallbackScreen, fallback
                )
                fallback_summary = (
                    fallback_screen.query_one("#recovery-summary-document", Static)
                    .render()
                    .plain
                )
                self.assertIn("Failed route: home-lan", fallback_summary)
                self.assertIn(
                    "Failed identity: operator@192.0.2.20:22",
                    fallback_summary,
                )
                self.assertIn("Proposed route: wireguard", fallback_summary)
                self.assertIn("original RUN approval", fallback_summary)
                fallback_binding = (
                    fallback_screen.query_one("#recovery-binding-document", Static)
                    .render()
                    .plain
                )
                self.assertIn(fallback.fallback_binding_sha256, fallback_binding)
                await pilot.pause(APPROVAL_ARM_SECONDS + 0.10)
                self.assertTrue(await pilot.click("#recovery-approve"))

        asyncio.run(exercise())
        first.join(timeout=1)
        second.join(timeout=1)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertIs(decisions[retry.prompt_id], ApprovalDecision.DENIED)
        self.assertIs(decisions[fallback.prompt_id], ApprovalDecision.APPROVED)

    def test_machine_disable_modal_is_exact_bounded_and_safe_when_small(self):
        interface = TextualOperatorInterface(
            FakeTerminalArbiter(), validate_terminal=False
        )
        self.addCleanup(interface.close)
        plan = build_plan()
        first = MachineDisablePrompt.create(
            REQUEST_ID,
            prompt().request,
            plan,
            failure_detail="all routes failed [bold]\x1b[31m",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
        )
        second = MachineDisablePrompt.create(
            "2" * 32,
            prompt().request,
            plan,
            failure_detail="all routes failed",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
        )
        decisions: dict[str, ApprovalDecision] = {}

        def decide(item: MachineDisablePrompt) -> None:
            decisions[item.prompt_id] = interface.request_machine_disable(item).decision

        workers = [
            threading.Thread(target=decide, args=(item,))
            for item in (first, second)
        ]
        for index, worker in enumerate(workers, start=1):
            worker.start()
            deadline = time.monotonic() + 1
            while (
                interface.pending_prompt_count < index and time.monotonic() < deadline
            ):
                time.sleep(0.01)
        app = TmuxgateDashboardApp(interface, threading.Event(), config())

        async def exercise() -> None:
            async with app.run_test(size=(100, 30)) as pilot:
                screen = await self._wait_for_machine_disable(app, pilot, first)
                self.assertTrue(
                    screen.query_one("#disable-cancel", Button).has_focus
                )
                summary = (
                    screen.query_one("#disable-summary-document", Static)
                    .render()
                    .plain
                )
                request_evidence = (
                    screen.query_one("#disable-request-document", Static)
                    .render()
                    .plain
                )
                binding = (
                    screen.query_one("#disable-binding-document", Static)
                    .render()
                    .plain
                )
                self.assertNotIn("\x1b", summary)
                self.assertIn(r"\u001b", summary)
                self.assertIn(plan.plan_sha256, request_evidence)
                self.assertIn(first.binding_sha256, binding)
                await pilot.pause(APPROVAL_ARM_SECONDS + 0.10)
                self.assertFalse(
                    screen.query_one("#disable-approve", Button).disabled
                )
                await pilot.resize_terminal(MINIMUM_COLUMNS - 1, MINIMUM_ROWS - 1)
                await pilot.pause()
                self.assertTrue(
                    screen.query_one(".decision-size-warning", Static).display
                )
                self.assertTrue(
                    screen.query_one("#disable-approve", Button).disabled
                )
                self.assertTrue(
                    screen.query_one("#disable-cancel", Button).has_focus
                )
                await pilot.press("enter")

                await self._wait_for_machine_disable(app, pilot, second)
                await pilot.resize_terminal(100, 30)
                await pilot.pause(APPROVAL_ARM_SECONDS + 0.10)
                self.assertTrue(await pilot.click("#disable-approve"))

        asyncio.run(exercise())
        for worker in workers:
            worker.join(timeout=1)
            self.assertFalse(worker.is_alive())
        self.assertIs(decisions[first.prompt_id], ApprovalDecision.DENIED)
        self.assertIs(decisions[second.prompt_id], ApprovalDecision.APPROVED)

    def test_execution_approval_views_resize_and_explicit_decisions(self):
        interface = TextualOperatorInterface(
            FakeTerminalArbiter(), validate_terminal=False
        )
        self.addCleanup(interface.close)
        malicious = (
            b"echo '[bold]literal[/bold]'\n\x1b]8;;https://evil.invalid\x07link\n"
        )
        request = RequestSpec(
            "app-server",
            ExecutionMode.SCRIPT,
            "/srv/app",
            script=malicious + b"printf '%s\\n' complete\n" * 2000,
            purpose="Review [red]literal markup[/red]",
        )
        plan = build_plan()
        approval = ExecutionApprovalPrompt.create(REQUEST_ID, request, plan)
        denied = ExecutionApprovalPrompt.create(
            "1" * 32, prompt().request, None, unbound_fake=True
        )
        decisions: dict[str, ApprovalDecision] = {}

        def request_decision(item: ExecutionApprovalPrompt) -> None:
            result = interface.request_execution_approval(item)
            decisions[item.prompt_id] = result.decision

        first = threading.Thread(target=request_decision, args=(approval,))
        second = threading.Thread(target=request_decision, args=(denied,))
        first.start()
        while interface.pending_prompt_count < 1:
            time.sleep(0.01)
        second.start()
        while interface.pending_prompt_count < 2:
            time.sleep(0.01)
        app = TmuxgateDashboardApp(interface, threading.Event(), config())

        async def exercise() -> None:
            async with app.run_test(size=(100, 30)) as pilot:
                screen = await self._wait_for_approval(app, pilot, approval)
                widget_count = len(list(screen.query("*")))
                self.assertEqual(
                    screen.query_one("#approval-views", TabbedContent).active,
                    "approval-summary",
                )
                self.assertTrue(screen.query_one("#approval-deny", Button).has_focus)
                self.assertTrue(screen.query_one("#approval-approve", Button).disabled)

                await pilot.press("x")
                await pilot.pause()
                self.assertTrue(first.is_alive())
                for key, expected in (
                    ("c", "approval-code"),
                    ("t", "approval-technical"),
                    ("s", "approval-summary"),
                ):
                    await pilot.press(key)
                    await pilot.pause()
                    self.assertEqual(
                        screen.query_one("#approval-views", TabbedContent).active,
                        expected,
                    )
                code = (
                    screen.query_one("#approval-code-document", Static).render().plain
                )
                summary = (
                    screen.query_one("#approval-summary-document", Static)
                    .render()
                    .plain
                )
                technical = (
                    screen.query_one("#approval-technical-document", Static)
                    .render()
                    .plain
                )
                self.assertIn("home-lan", summary)
                self.assertIn("192.0.2.20", summary)
                self.assertIn(plan.plan_sha256, technical)
                self.assertNotIn("\x1b", code)
                self.assertIn(r"\x1b", code)
                self.assertIn("complete", code)
                self.assertIn("script_sha256:", technical)
                self.assertEqual(len(list(screen.query("*"))), widget_count)

                await pilot.resize_terminal(MINIMUM_COLUMNS, MINIMUM_ROWS)
                await pilot.pause()
                self.assertIs(app.screen, screen)
                self.assertTrue(screen.query_one("#approval-deny", Button).display)
                await pilot.pause(APPROVAL_ARM_SECONDS + 0.10)
                self.assertFalse(screen.query_one("#approval-approve", Button).disabled)
                self.assertTrue(await pilot.click("#approval-approve"))

                next_screen = await self._wait_for_approval(app, pilot, denied)
                self.assertTrue(
                    next_screen.query_one("#approval-deny", Button).has_focus
                )
                await pilot.press("escape")
                await pilot.pause()

        asyncio.run(exercise())
        first.join(timeout=1)
        second.join(timeout=1)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertIs(decisions[approval.prompt_id], ApprovalDecision.APPROVED)
        self.assertIs(decisions[denied.prompt_id], ApprovalDecision.DENIED)

    def test_stale_input_and_modal_identity_cannot_approve_next_prompt(self):
        interface = TextualOperatorInterface(
            FakeTerminalArbiter(), validate_terminal=False
        )
        self.addCleanup(interface.close)
        prompts = [
            ExecutionApprovalPrompt.create(
                f"{index:032x}", prompt().request, None, unbound_fake=True
            )
            for index in range(1, 4)
        ]
        decisions: dict[str, ApprovalDecision] = {}
        workers = []
        for index, item in enumerate(prompts, start=1):
            worker = threading.Thread(
                target=lambda value=item: decisions.__setitem__(
                    value.prompt_id,
                    interface.request_execution_approval(value).decision,
                )
            )
            worker.start()
            workers.append(worker)
            deadline = time.monotonic() + 1
            while (
                interface.pending_prompt_count < index and time.monotonic() < deadline
            ):
                time.sleep(0.01)
        app = TmuxgateDashboardApp(interface, threading.Event(), config())

        async def exercise() -> None:
            async with app.run_test(size=(100, 30)) as pilot:
                first_screen = await self._wait_for_approval(app, pilot, prompts[0])
                first_item = interface.queued_prompts[0]
                # An activation aimed at Approve before this exact prompt is
                # armed cannot resolve it. Enter then selects the focused safe
                # default, Deny.
                await pilot.click("#approval-approve")
                await pilot.pause()
                self.assertTrue(workers[0].is_alive())
                await pilot.press("enter")
                second_screen = await self._wait_for_approval(app, pilot, prompts[1])
                self.assertIsNot(first_screen, second_screen)
                second_item = interface.queued_prompts[1]
                app._complete_operator_decision(first_item, ApprovalDecision.APPROVED)
                await pilot.pause()
                self.assertTrue(workers[1].is_alive())
                self.assertEqual(
                    app._active_decision.prompt.prompt_id,
                    second_item.prompt.prompt_id,
                )
                self.assertIs(app._active_decision.pending, second_item.pending)

                await pilot.pause(APPROVAL_ARM_SECONDS + 0.10)
                self.assertTrue(await pilot.click("#approval-approve"))
                await self._wait_for_approval(app, pilot, prompts[2])
                await pilot.press("enter")
                await pilot.pause()

        asyncio.run(exercise())
        for worker in workers:
            worker.join(timeout=1)
            self.assertFalse(worker.is_alive())
        self.assertIs(decisions[prompts[0].prompt_id], ApprovalDecision.DENIED)
        self.assertIs(decisions[prompts[1].prompt_id], ApprovalDecision.APPROVED)
        self.assertIs(decisions[prompts[2].prompt_id], ApprovalDecision.DENIED)

    def test_dashboard_close_denies_active_and_queued_prompts(self):
        interface = TextualOperatorInterface(
            FakeTerminalArbiter(), validate_terminal=False
        )
        self.addCleanup(interface.close)
        prompts = [
            ExecutionApprovalPrompt.create(
                f"{index:032x}", prompt().request, None, unbound_fake=True
            )
            for index in range(10, 12)
        ]
        decisions = []
        workers = [
            threading.Thread(
                target=lambda item=item: decisions.append(
                    interface.request_execution_approval(item)
                )
            )
            for item in prompts
        ]
        for index, worker in enumerate(workers, start=1):
            worker.start()
            deadline = time.monotonic() + 1
            while (
                interface.pending_prompt_count < index and time.monotonic() < deadline
            ):
                time.sleep(0.01)
        stop = threading.Event()
        app = TmuxgateDashboardApp(interface, stop, config())

        async def exercise() -> None:
            async with app.run_test(size=(100, 30)) as pilot:
                await self._wait_for_approval(app, pilot, prompts[0])
                await pilot.press("q")
                await pilot.pause()

        asyncio.run(exercise())
        self.assertTrue(stop.is_set())
        for worker in workers:
            worker.join(timeout=1)
            self.assertFalse(worker.is_alive())
        self.assertEqual(len(decisions), 2)
        self.assertTrue(
            all(item.decision is ApprovalDecision.DENIED for item in decisions)
        )


PTY_HELPER = r"""
import asyncio
from contextlib import nullcontext
import os
import signal
import subprocess
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
    tui_keys = 0

    def on_mount(self):
        super().on_mount()
        if mode == "normal":
            self.set_timer(0.2, self.exit)
        elif mode == "exception":
            raise RuntimeError("synthetic TUI failure")
        elif mode in {"handoff", "handoff_failure"}:
            self.call_after_refresh(self.run_handoff)

    def on_key(self, event):
        self.tui_keys += 1

    def run_handoff(self):
        command = (
            "IFS= read -r secret; test \"$secret\" = external-secret"
            if mode == "handoff"
            else "exit 7"
        )
        failed = False
        try:
            with self.suspend():
                os.write(terminal, b"TMUXGATE_HANDOFF_ACTIVE=yes\r\n")
                subprocess.run(
                    ["/bin/sh", "-c", command],
                    stdin=terminal,
                    stdout=terminal,
                    stderr=terminal,
                    check=True,
                )
        except subprocess.CalledProcessError:
            failed = True
        os.write(
            terminal,
            b"TMUXGATE_HANDOFF_FAILED=" + (b"yes" if failed else b"no") + b"\r\n",
        )
        os.write(
            terminal,
            b"TMUXGATE_TUI_KEYS=" + str(self.tui_keys).encode("ascii") + b"\r\n",
        )
        self.exit()

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
    def _run_cli(self, *, plain: bool) -> bytes:
        with tempfile.TemporaryDirectory(prefix="tmuxgate-cli-pty-") as directory:
            root = Path(directory)
            home = root / "home"
            runtime = root / "runtime"
            state = root / "state"
            for path in (home, runtime, state):
                path.mkdir(mode=0o700)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            data = valid_config()
            data["version"] = 2
            data["mcp"] = {"host": "127.0.0.1", "port": port}
            config_path = root / "config.toml"
            config_path.write_bytes(serialize_config(parse_config(data)))
            config_path.chmod(0o600)
            arguments = [
                sys.executable,
                "-m",
                "tmuxgate",
                "--config",
                os.fspath(config_path),
                "--state-dir",
                os.fspath(state),
                "--socket",
                os.fspath(runtime / "broker.sock"),
                "--fake",
            ]
            if plain:
                arguments.append("--plain")
            child, master = pty.fork()
            if child == 0:
                environment = dict(os.environ)
                environment.update(
                    {
                        "HOME": os.fspath(home),
                        "PYTHONPATH": os.pathsep.join(("src", "tests")),
                        "TERM": "xterm-256color",
                        "XDG_CACHE_HOME": os.fspath(home / "cache"),
                        "XDG_CONFIG_HOME": os.fspath(home / "config"),
                        "XDG_RUNTIME_DIR": os.fspath(runtime),
                        "XDG_STATE_HOME": os.fspath(home / "state"),
                    }
                )
                os.execve(sys.executable, arguments, environment)
            output = bytearray()
            sent_quit = False
            status = None
            try:
                fcntl.ioctl(
                    master,
                    termios.TIOCSWINSZ,
                    struct.pack("HHHH", 30, 100, 0, 0),
                )
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    readable, _, _ = select.select([master], [], [], 0.1)
                    if readable:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError:
                            chunk = b""
                        if chunk:
                            output.extend(chunk)
                    ready = (
                        b"Choose: " in output if plain else b"\x1b[?1049h" in output
                    )
                    if ready and not sent_quit:
                        os.write(master, b"q\n" if plain else b"q")
                        sent_quit = True
                    waited, status = os.waitpid(child, os.WNOHANG)
                    if waited:
                        break
                else:
                    os.kill(child, signal.SIGKILL)
                    os.waitpid(child, 0)
                    self.fail(
                        "default CLI PTY timed out:\n"
                        + output.decode(errors="replace")
                    )
                self.assertTrue(sent_quit, output.decode(errors="replace"))
                self.assertIsNotNone(status)
                self.assertTrue(os.WIFEXITED(status), output.decode(errors="replace"))
                self.assertEqual(
                    os.WEXITSTATUS(status),
                    0,
                    output.decode(errors="replace"),
                )
                return bytes(output)
            finally:
                os.close(master)

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
                        mode == "handoff"
                        and b"TMUXGATE_HANDOFF_ACTIVE=yes" in output
                        and b"external-secret" not in output
                    ):
                        os.write(master, b"external-secret\n")
                if mode == "signal" and not sent_signal and b"\x1b[?1049h" in output:
                    os.kill(child, signal.SIGTERM)
                    sent_signal = True
                waited, status = os.waitpid(child, os.WNOHANG)
                if waited:
                    self.assertTrue(
                        os.WIFEXITED(status), output.decode(errors="replace")
                    )
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

    def test_default_cli_uses_tui_and_plain_remains_explicit(self):
        tui_output = self._run_cli(plain=False)
        self.assertIn(b"\x1b[?1049h", tui_output)
        self.assertIn(b"\x1b[?1049l", tui_output)
        self.assertNotIn(b"TMUXGATE RUNNING", tui_output)

        plain_output = self._run_cli(plain=True)
        self.assertIn(b"TMUXGATE RUNNING", plain_output)
        self.assertNotIn(b"\x1b[?1049h", plain_output)

    def test_external_process_owns_bytes_while_textual_is_suspended(self):
        output = self._run_mode("handoff")
        self.assertIn(b"TMUXGATE_HANDOFF_ACTIVE=yes", output)
        self.assertIn(b"TMUXGATE_HANDOFF_FAILED=no", output)
        self.assertIn(b"TMUXGATE_TUI_KEYS=0", output)
        self.assertIn(b"TMUXGATE_RESTORED=yes", output)
        self.assertGreaterEqual(output.count(b"\x1b[?1049h"), 2)
        self.assertGreaterEqual(output.count(b"\x1b[?1049l"), 2)

    def test_external_process_failure_resumes_and_restores_textual(self):
        output = self._run_mode("handoff_failure")
        self.assertIn(b"TMUXGATE_HANDOFF_FAILED=yes", output)
        self.assertIn(b"TMUXGATE_TUI_KEYS=0", output)
        self.assertIn(b"TMUXGATE_RESTORED=yes", output)


if __name__ == "__main__":
    unittest.main()
