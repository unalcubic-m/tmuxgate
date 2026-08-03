"""Lifecycle tests for the unified broker and MCP application."""

from __future__ import annotations

from contextlib import nullcontext, redirect_stderr, redirect_stdout
import io
from pathlib import Path
import signal
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from tmuxgate import application
from tmuxgate.application import RecoveryBlockedError, UnifiedApplication
from tmuxgate.mcp_server import McpServerError
from tmuxgate.runtime import RuntimeSecurityError, acquire_state_lock
from tmuxgate.textual_interface import TextualOperatorInterface


def _write_config(
    path: Path, *, mcp_port: int = 18765, approval_mode: str = "disabled"
) -> None:
    path.write_text(
        f"""\
version = 2

[broker]
approval_mode = "{approval_mode}"

[mcp]
host = "127.0.0.1"
port = {mcp_port}

[contexts.home]
gateway = "192.0.2.1"
source_cidr = "192.0.2.0/24"
fingerprints = []

[machines.local]
description = "Test machine"
ssh_profile = "local"
user = "operator"
host_key_alias = "tmuxgate-local"
connect_timeout_seconds = 6

[[machines.local.endpoints]]
id = "home-lan"
address = "192.0.2.20"
port = 22
priority = 10
requires = "home"
""",
        encoding="utf-8",
    )
    path.chmod(0o600)


class UnifiedApplicationLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "config.toml"
        self.socket_path = self.root / "broker.sock"
        self.state_dir = self.root / "state"
        _write_config(self.config_path)

    def _application(
        self, dashboard=None, operator_interface=None
    ) -> UnifiedApplication:
        terminal = mock.Mock()
        terminal.claim.return_value = nullcontext()
        return UnifiedApplication(
            config_path=self.config_path,
            socket_path=self.socket_path,
            state_dir=self.state_dir,
            fake=True,
            dashboard=dashboard,
            terminal=terminal,
            operator_interface=operator_interface,
        )

    def test_shutdown_closes_operator_after_admission_stop_before_broker_join(self):
        events = []
        broker = mock.Mock()
        broker.start.return_value = None
        broker.stop.side_effect = lambda: events.append("broker.stop") or True
        mcp_http = mock.Mock()
        mcp_http.start.return_value = None
        mcp_http.request_stop.side_effect = lambda: events.append("mcp.request_stop")
        mcp_http.stop.return_value = True
        operator = mock.Mock()
        operator.close.side_effect = lambda: events.append("operator.close") or True
        operator.run_dashboard.side_effect = lambda stop, config: None

        app = self._application(operator_interface=operator)
        with (
            mock.patch.object(application, "BrokerServer", return_value=broker),
            mock.patch.object(application, "create_mcp_server", return_value=object()),
            mock.patch.object(application, "EmbeddedMcpServer", return_value=mcp_http),
        ):
            self.assertEqual(app.run(), 0)

        self.assertLess(events.index("mcp.request_stop"), events.index("operator.close"))
        self.assertLess(events.index("operator.close"), events.index("broker.stop"))
        operator.close.assert_called_once_with()

    def test_textual_runtime_provider_exposes_ready_application_state(self):
        _write_config(self.config_path, approval_mode="always")
        terminal = mock.Mock()
        terminal.claim.return_value = nullcontext()
        terminal.state.return_value = SimpleNamespace(busy=False, purpose=None)

        class CapturingTextualInterface(TextualOperatorInterface):
            snapshot = None

            def run_dashboard(self, stop, config):
                del stop
                self.snapshot = self.dashboard_snapshot(config)

        operator = CapturingTextualInterface(terminal, validate_terminal=False)
        broker = mock.Mock()
        broker.stop.return_value = True
        mcp_http = mock.Mock()
        mcp_http.stop.return_value = True
        app = UnifiedApplication(
            config_path=self.config_path,
            socket_path=self.socket_path,
            state_dir=self.state_dir,
            fake=True,
            terminal=terminal,
            operator_interface=operator,
        )
        with (
            mock.patch.object(application, "BrokerServer", return_value=broker),
            mock.patch.object(application, "create_mcp_server", return_value=object()),
            mock.patch.object(
                application, "EmbeddedMcpServer", return_value=mcp_http
            ),
        ):
            self.assertEqual(app.run(), 0)

        snapshot = operator.snapshot
        self.assertIsNotNone(snapshot)
        self.assertTrue(snapshot.ready)
        self.assertEqual(snapshot.listener, "http://127.0.0.1:18765/mcp")
        self.assertEqual(snapshot.approval_mode, "always")
        self.assertEqual(snapshot.terminal_owner, "tui")
        self.assertEqual(len(snapshot.machines), 1)
        self.assertEqual(snapshot.machines[0].alias, "local")
        self.assertEqual(snapshot.machines[0].ssh_state, "not used (fake)")

    def test_textual_mode_accepts_disabled_execution_approval_policy(self):
        app = UnifiedApplication(
            config_path=self.config_path,
            socket_path=self.socket_path,
            state_dir=self.state_dir,
            fake=True,
            textual=True,
        )
        with (
            self.assertRaisesRegex(RuntimeError, "listener reached"),
            mock.patch(
                "tmuxgate.textual_interface.validate_textual_terminal"
            ),
            mock.patch.object(
                application,
                "open_broker_listener",
                side_effect=RuntimeError("listener reached"),
            ) as listener,
        ):
            app.run()
        listener.assert_called_once_with(self.socket_path)

    def test_textual_terminal_validation_precedes_listener_start(self):
        _write_config(self.config_path, approval_mode="always")
        app = UnifiedApplication(
            config_path=self.config_path,
            socket_path=self.socket_path,
            state_dir=self.state_dir,
            fake=True,
            textual=True,
        )
        with (
            self.assertRaisesRegex(RuntimeError, "synthetic terminal failure"),
            mock.patch(
                "tmuxgate.textual_interface.validate_textual_terminal",
                side_effect=RuntimeError("synthetic terminal failure"),
            ),
            mock.patch.object(application, "open_broker_listener") as listener,
        ):
            app.run()
        listener.assert_not_called()

    def test_fake_mode_starts_broker_then_mcp_and_stops_in_reverse_order(self):
        events: list[str] = []
        broker = mock.Mock()
        broker.start.side_effect = lambda: events.append("broker.start")
        broker.stop.side_effect = lambda: events.append("broker.stop") or True
        mcp_http = mock.Mock()
        mcp_http.start.side_effect = lambda: events.append("mcp.start")
        mcp_http.request_stop.side_effect = lambda: events.append("mcp.request_stop")
        mcp_http.stop.side_effect = lambda: events.append("mcp.stop") or True
        mcp_server = object()

        def make_broker(*args, **kwargs):
            del args
            self.assertEqual(
                kwargs["max_client_sessions"],
                kwargs["max_pending_requests"]
                + 2
                + application.DEFAULT_CONTROL_WORKERS,
            )
            events.append("broker.create")
            return broker

        def configure_mcp(socket_path, **kwargs):
            self.assertEqual(socket_path, self.socket_path)
            self.assertIsInstance(kwargs["call_pools"], application.BrokerCallPools)
            events.append("mcp.configure")
            return mcp_server

        def make_mcp(server, **kwargs):
            self.assertIs(server, mcp_server)
            self.assertEqual(kwargs["host"], "127.0.0.1")
            self.assertEqual(kwargs["port"], 18765)
            self.assertRegex(kwargs["bearer_token"], r"^[0-9a-f]{64}$")
            self.assertTrue(callable(kwargs["on_unexpected_exit"]))
            events.append("mcp.create")
            return mcp_http

        def dashboard(stop_event, terminal, config):
            del terminal
            self.assertFalse(stop_event.is_set())
            self.assertEqual(config.broker.approval_mode, "disabled")
            events.append("dashboard")

        app = self._application(dashboard)
        with (
            mock.patch.object(application, "BrokerServer", side_effect=make_broker),
            mock.patch.object(
                application, "create_mcp_server", side_effect=configure_mcp
            ),
            mock.patch.object(
                application, "EmbeddedMcpServer", side_effect=make_mcp
            ),
            redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(app.run(), 0)

        self.assertEqual(
            events,
            [
                "broker.create",
                "mcp.configure",
                "mcp.create",
                "broker.start",
                "mcp.start",
                "dashboard",
                "mcp.request_stop",
                "broker.stop",
                "mcp.stop",
            ],
        )
        broker.stop.assert_called_once_with()
        mcp_http.request_stop.assert_called_once_with()
        mcp_http.stop.assert_called_once_with()
        mcp_http.raise_if_failed.assert_called_once_with()
        self.assertTrue(app.stop_event.is_set())
        self.assertFalse(self.socket_path.exists())
        token_path = self.state_dir / "mcp-token"
        self.assertRegex(
            token_path.read_text(encoding="ascii").strip(),
            r"^[0-9a-f]{64}$",
        )
        self.assertEqual(token_path.stat().st_mode & 0o777, 0o600)

    def test_post_ready_mcp_exit_stops_and_fails_the_whole_application(self):
        broker = mock.Mock()
        broker.stop.return_value = True
        mcp_http = mock.Mock()
        mcp_http.stop.return_value = True
        callback = None

        def make_mcp(server, **kwargs):
            nonlocal callback
            del server
            callback = kwargs["on_unexpected_exit"]
            return mcp_http

        def start_mcp():
            assert callback is not None
            callback(RuntimeError("injected post-ready failure"))

        mcp_http.start.side_effect = start_mcp
        mcp_http.raise_if_failed.side_effect = McpServerError(
            "MCP HTTP server stopped unexpectedly"
        )
        app = self._application()

        with (
            mock.patch.object(application, "BrokerServer", return_value=broker),
            mock.patch.object(application, "create_mcp_server", return_value=object()),
            mock.patch.object(application, "EmbeddedMcpServer", side_effect=make_mcp),
            redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(McpServerError, "stopped unexpectedly"):
                app.run()

        self.assertTrue(app.stop_event.is_set())
        broker.stop.assert_called_once_with()
        mcp_http.request_stop.assert_called_once_with()
        mcp_http.stop.assert_called_once_with()

    def test_incomplete_shutdown_retains_resources_and_returns_software_error(self):
        broker = mock.Mock()
        broker.stop.return_value = False
        mcp_http = mock.Mock()
        mcp_http.stop.return_value = True
        retained_before = len(application._RETAINED_SHUTDOWN_RESOURCES)

        with (
            mock.patch.object(application, "BrokerServer", return_value=broker),
            mock.patch.object(application, "create_mcp_server", return_value=object()),
            mock.patch.object(
                application,
                "EmbeddedMcpServer",
                return_value=mcp_http,
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()) as errors,
        ):
            result = self._application(lambda *args: None).run()

        self.assertEqual(result, application.EXIT_SOFTWARE)
        self.assertEqual(
            len(application._RETAINED_SHUTDOWN_RESOURCES),
            retained_before + 1,
        )
        self.assertTrue(self.socket_path.exists())
        message = errors.getvalue()
        self.assertIn(
            "a broker worker or client session did not stop cleanly",
            message,
        )
        self.assertIn("New work is no longer accepted", message)
        self.assertIn("tmuxgate will return status 70", message)
        self.assertIn("run 'tmuxgate jobs' after exit", message)
        with self.assertRaisesRegex(RuntimeSecurityError, "another state lifecycle"):
            acquire_state_lock(self.state_dir)

        retained = application._RETAINED_SHUTDOWN_RESOURCES.pop()
        retained.close()
        self.assertFalse(self.socket_path.exists())

    def test_incomplete_shutdown_identifies_mcp_http_thread(self):
        broker = mock.Mock()
        broker.stop.return_value = True
        mcp_http = mock.Mock()
        mcp_http.stop.return_value = False
        retained_before = len(application._RETAINED_SHUTDOWN_RESOURCES)

        with (
            mock.patch.object(application, "BrokerServer", return_value=broker),
            mock.patch.object(application, "create_mcp_server", return_value=object()),
            mock.patch.object(
                application,
                "EmbeddedMcpServer",
                return_value=mcp_http,
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()) as errors,
        ):
            result = self._application(lambda *args: None).run()

        self.assertEqual(result, application.EXIT_SOFTWARE)
        self.assertEqual(
            len(application._RETAINED_SHUTDOWN_RESOURCES),
            retained_before + 1,
        )
        message = errors.getvalue()
        self.assertIn("the MCP HTTP server thread did not stop cleanly", message)
        self.assertNotIn("a broker worker or client session", message)

        application._RETAINED_SHUTDOWN_RESOURCES.pop().close()

    def test_cleanup_failure_does_not_skip_other_components_or_signal_restore(self):
        events: list[str] = []
        broker = mock.Mock()
        broker.stop.side_effect = lambda: events.append("broker.stop") or True
        mcp_http = mock.Mock()

        def fail_request_stop():
            events.append("mcp.request_stop")
            raise RuntimeError("signal MCP failed")

        mcp_http.request_stop.side_effect = fail_request_stop
        mcp_http.stop.side_effect = lambda: events.append("mcp.stop") or True
        retained_before = len(application._RETAINED_SHUTDOWN_RESOURCES)
        app = self._application(lambda *args: None)

        with (
            mock.patch.object(application, "BrokerServer", return_value=broker),
            mock.patch.object(application, "create_mcp_server", return_value=object()),
            mock.patch.object(
                application,
                "EmbeddedMcpServer",
                return_value=mcp_http,
            ),
            mock.patch.object(
                app,
                "_restore_signal_handlers",
                side_effect=lambda previous: events.append("signals.restore"),
            ),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(app.run(), application.EXIT_SOFTWARE)

        self.assertEqual(
            events,
            ["mcp.request_stop", "broker.stop", "mcp.stop", "signals.restore"],
        )
        self.assertEqual(
            len(application._RETAINED_SHUTDOWN_RESOURCES),
            retained_before + 1,
        )
        application._RETAINED_SHUTDOWN_RESOURCES.pop().close()

    def test_mcp_startup_failure_stops_mcp_before_rolling_back_broker(self):
        events: list[str] = []
        broker = mock.Mock()
        broker.start.side_effect = lambda: events.append("broker.start")
        broker.stop.side_effect = lambda: events.append("broker.stop") or True
        mcp_http = mock.Mock()

        def fail_mcp_start():
            events.append("mcp.start")
            raise RuntimeError("MCP bind failed")

        mcp_http.start.side_effect = fail_mcp_start
        mcp_http.request_stop.side_effect = lambda: events.append("mcp.request_stop")
        mcp_http.stop.side_effect = lambda: events.append("mcp.stop") or True

        with (
            mock.patch.object(application, "BrokerServer", return_value=broker),
            mock.patch.object(application, "create_mcp_server", return_value=object()),
            mock.patch.object(
                application, "EmbeddedMcpServer", return_value=mcp_http
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "MCP bind failed"):
                self._application(lambda *args: None).run()

        self.assertEqual(
            events,
            [
                "broker.start",
                "mcp.start",
                "mcp.request_stop",
                "broker.stop",
                "mcp.stop",
            ],
        )
        broker.stop.assert_called_once_with()
        mcp_http.request_stop.assert_called_once_with()
        mcp_http.stop.assert_called_once_with()
        self.assertFalse(self.socket_path.exists())

    def test_construction_failure_closes_prompt_presenter_then_transport_pool(self):
        events: list[str] = []
        pool = mock.Mock()
        pool.close_idle.side_effect = lambda: events.append("pool.close")
        presenter = mock.Mock()
        presenter.close.side_effect = lambda: events.append("presenter.close") or True
        lifecycle = SimpleNamespace(listener=object(), socket_path=self.socket_path)
        app = UnifiedApplication(
            config_path=self.config_path,
            socket_path=self.socket_path,
            state_dir=self.state_dir,
            fake=False,
            dashboard=lambda *args: None,
            terminal=mock.Mock(),
        )

        with (
            mock.patch.object(
                application, "open_broker_listener", return_value=nullcontext(lifecycle)
            ),
            mock.patch.object(application, "MasterTransportPool", return_value=pool),
            mock.patch.object(
                application, "SecretPromptPresenter", return_value=presenter
            ),
            mock.patch.object(
                application,
                "SshChannelRunner",
                side_effect=RuntimeError("channel construction failed"),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "channel construction failed"):
                app.run()

        self.assertEqual(events, ["presenter.close", "pool.close"])

    def test_blocking_recovery_prevents_listener_broker_and_mcp_creation(self):
        recovery = SimpleNamespace(
            safe_to_accept_new_approvals=False,
            blocking_request_ids=("request-a", "request-b"),
        )
        listener = mock.Mock()
        broker = mock.Mock()
        mcp_http = mock.Mock()

        with (
            mock.patch.object(application, "recover_startup", return_value=recovery),
            mock.patch.object(application, "open_broker_listener", listener),
            mock.patch.object(application, "BrokerServer", broker),
            mock.patch.object(application, "create_mcp_server") as create_mcp,
            mock.patch.object(application, "EmbeddedMcpServer", mcp_http),
        ):
            with self.assertRaisesRegex(
                RecoveryBlockedError,
                r"recovery blocks new approvals: request-a, request-b",
            ):
                self._application(lambda *args: None).run()

        listener.assert_not_called()
        broker.assert_not_called()
        create_mcp.assert_not_called()
        mcp_http.assert_not_called()
        self.assertFalse(self.socket_path.exists())

    def test_state_singleton_is_acquired_before_recovery_for_any_socket_path(self):
        app = self._application(lambda *args: None)
        self.state_dir.mkdir(mode=0o700)
        with acquire_state_lock(self.state_dir):
            with mock.patch.object(application, "recover_startup") as recover:
                with self.assertRaisesRegex(
                    RuntimeSecurityError,
                    "another state lifecycle",
                ):
                    app.run()

        recover.assert_not_called()
        self.assertFalse(self.socket_path.exists())

    def test_signal_handlers_request_stop_and_are_restored(self):
        app = self._application()
        installed: dict[int, object] = {}
        previous = {
            signal.SIGINT: object(),
            signal.SIGTERM: object(),
        }

        def replace_handler(number, handler):
            installed[number] = handler
            return previous[number]

        with mock.patch.object(signal, "signal", side_effect=replace_handler) as setter:
            saved = app._install_signal_handlers()
            self.assertEqual(saved, previous)
            self.assertFalse(app.stop_event.is_set())
            installed[signal.SIGTERM](signal.SIGTERM, None)
            self.assertTrue(app.stop_event.is_set())

            setter.reset_mock()
            app._restore_signal_handlers(saved)
            self.assertEqual(
                setter.call_args_list,
                [
                    mock.call(signal.SIGINT, previous[signal.SIGINT]),
                    mock.call(signal.SIGTERM, previous[signal.SIGTERM]),
                ],
            )

    def test_partial_signal_installation_is_rolled_back(self):
        app = self._application()
        old_interrupt = object()
        calls: list[tuple[int, object]] = []

        def replace_handler(number, handler):
            calls.append((number, handler))
            if len(calls) == 1:
                return old_interrupt
            if len(calls) == 2:
                raise RuntimeError("cannot install SIGTERM")
            return object()

        with mock.patch.object(signal, "signal", side_effect=replace_handler):
            with self.assertRaisesRegex(RuntimeError, "cannot install SIGTERM"):
                app._install_signal_handlers()

        self.assertEqual(calls[0][0], signal.SIGINT)
        self.assertEqual(calls[1][0], signal.SIGTERM)
        self.assertEqual(calls[2], (signal.SIGINT, old_interrupt))

    def test_worker_thread_does_not_install_process_signal_handlers(self):
        app = self._application()
        observed: list[dict[int, object]] = []

        with mock.patch.object(signal, "signal") as setter:
            worker = threading.Thread(
                target=lambda: observed.append(app._install_signal_handlers())
            )
            worker.start()
            worker.join(timeout=2.0)

        self.assertFalse(worker.is_alive())
        self.assertEqual(observed, [{}])
        setter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
