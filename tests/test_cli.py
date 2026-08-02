import json
from contextlib import nullcontext, redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tmuxgate import cli
from tmuxgate.models import ExecutionMode, RequestSpec, ResultFormat
from tmuxgate.result import ExecutionResult, TransportStatus
from tmuxgate.scheduler import ApprovalDecision, RequestState


REQUEST_ID = "0123456789abcdef0123456789abcdef"


class CommandLineParsingTests(unittest.TestCase):
    def test_exec_and_script_are_not_public_commands(self):
        parser = cli.build_parser()
        for command in ("exec", "script"):
            with self.subTest(command=command):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    parser.parse_args([command])
                self.assertEqual(raised.exception.code, 2)

    def test_help_omits_removed_execution_commands(self):
        help_text = cli.build_parser().format_help()
        self.assertNotIn("tmuxgate exec", help_text)
        self.assertNotIn("tmuxgate script", help_text)
        self.assertNotIn("{exec,", help_text)

    def test_unified_alias_help_renders_with_inherited_options(self):
        parser = cli.build_parser()
        for command in ("broker", "dashboard"):
            with self.subTest(command=command):
                with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    parser.parse_args([command, "--help"])
                self.assertEqual(raised.exception.code, 0)

    def test_global_config_path_applies_to_config_subcommand(self):
        commands = (
            ("_config_check", ("check",)),
            ("_config_list", ("list",)),
            ("_config_path", ("path",)),
            ("_config_edit", ("edit",)),
            ("_config_set_broker", ("set-broker",)),
            ("_config_add_machine", ("add-machine",)),
            ("_config_remove_machine", ("remove-machine", "app-server")),
            ("_config_disable_machine", ("disable-machine", "app-server")),
            ("_config_enable_machine", ("enable-machine", "app-server")),
            ("_config_enroll_home", ("enroll-home",)),
        )
        for handler_name, command in commands:
            with self.subTest(command=command[0]), mock.patch.object(
                cli, handler_name, return_value=0
            ) as handler:
                status = cli.main(
                    ["--config", "/global/config.toml", "config", *command]
                )

            self.assertEqual(status, 0)
            self.assertEqual(handler.call_args.args[0].path, "/global/config.toml")

    def test_config_subcommand_path_overrides_global_config(self):
        commands = (
            ("_config_check", ("check",)),
            ("_config_list", ("list",)),
            ("_config_path", ("path",)),
            ("_config_edit", ("edit",)),
            ("_config_set_broker", ("set-broker",)),
            ("_config_add_machine", ("add-machine",)),
            ("_config_remove_machine", ("remove-machine", "app-server")),
            ("_config_disable_machine", ("disable-machine", "app-server")),
            ("_config_enable_machine", ("enable-machine", "app-server")),
            ("_config_enroll_home", ("enroll-home",)),
        )
        for handler_name, command in commands:
            with self.subTest(command=command[0]), mock.patch.object(
                cli, handler_name, return_value=0
            ) as handler:
                status = cli.main(
                    [
                        "--config",
                        "/global/config.toml",
                        "config",
                        *command,
                        "--path",
                        "/override/config.toml",
                    ]
                )

            self.assertEqual(status, 0)
            self.assertEqual(handler.call_args.args[0].path, "/override/config.toml")

    def test_settings_prompt_uses_the_controlling_terminal(self):
        terminal = SimpleNamespace(
            reader=io.StringIO("\nlogical-machine\n"),
            writer=io.StringIO(),
        )
        with mock.patch(
            "tmuxgate.cli.open_approval_terminal",
            return_value=nullcontext(terminal),
        ) as opener:
            value = cli._prompt("Logical machine name")

        self.assertEqual(value, "logical-machine")
        self.assertEqual(
            terminal.writer.getvalue(),
            "Logical machine name: A value is required.\nLogical machine name: ",
        )
        opener.assert_called_once_with()

    def test_settings_editor_is_attached_to_the_controlling_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_bytes(b"version = 2\n")
            terminal = SimpleNamespace(
                reader=io.StringIO(),
                writer=io.StringIO(),
            )
            with (
                mock.patch(
                    "tmuxgate.cli.load_config_snapshot",
                    return_value=(object(), b"version = 2\n"),
                ),
                mock.patch(
                    "tmuxgate.cli.open_approval_terminal",
                    return_value=nullcontext(terminal),
                ),
                mock.patch(
                    "tmuxgate.cli.subprocess.run",
                    return_value=SimpleNamespace(returncode=1),
                ) as run,
                redirect_stderr(io.StringIO()),
            ):
                status = cli._config_edit(SimpleNamespace(path=str(path)))

        self.assertEqual(status, cli.EXIT_UNAVAILABLE)
        self.assertIs(run.call_args.kwargs["stdin"], terminal.reader)
        self.assertIs(run.call_args.kwargs["stdout"], terminal.writer)
        self.assertIs(run.call_args.kwargs["stderr"], terminal.writer)


class ResultPresentationTests(unittest.TestCase):
    def _request(self, result_format=ResultFormat.TRANSPARENT):
        return RequestSpec(
            machine_alias="app-server",
            mode=ExecutionMode.ARGV,
            cwd="/tmp",
            argv=("true",),
            result_format=result_format,
        )

    def test_transparent_result_keeps_streams_separate_and_returns_exit_7(self):
        result = ExecutionResult(
            request_id=REQUEST_ID,
            transport_status=TransportStatus.COMPLETE,
            stdout=b"stdout-line\n",
            stderr=b"stderr-line\n",
            remote_exit_status=7,
        )
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        calls = []

        def submitter(request, *, socket_path):
            calls.append((request, socket_path))
            return result

        status = cli.submit_and_present(
            self._request(),
            socket_path="/tmp/gate.sock",
            submitter=submitter,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(status, 7)
        self.assertEqual(stdout.getvalue(), b"stdout-line\n")
        self.assertEqual(stderr.getvalue(), b"stderr-line\n")
        self.assertEqual(calls[0][1], "/tmp/gate.sock")

    def test_json_result_is_unambiguous_and_returns_local_success(self):
        result = ExecutionResult(
            request_id=REQUEST_ID,
            transport_status=TransportStatus.COMPLETE,
            stdout=b"out",
            stderr=b"err",
            remote_exit_status=255,
        )
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        status = cli.submit_and_present(
            self._request(ResultFormat.JSON),
            socket_path=None,
            submitter=lambda request, socket_path: result,
            stdout=stdout,
            stderr=stderr,
        )
        document = json.loads(stdout.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(document["transport_status"], "complete")
        self.assertEqual(document["remote_exit_status"], 255)
        self.assertEqual(document["stdout_base64"], "b3V0")
        self.assertEqual(document["stderr_base64"], "ZXJy")
        self.assertEqual(stderr.getvalue(), b"")

    def test_denial_has_documented_local_exit_and_diagnostic(self):
        result = ExecutionResult(
            request_id=REQUEST_ID,
            transport_status=TransportStatus.DENIED,
            detail="request denied by operator",
        )
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        status = cli.present_result(
            result,
            ResultFormat.TRANSPARENT,
            stdout=stdout,
            stderr=stderr,
        )
        self.assertEqual(status, 77)
        self.assertEqual(stdout.getvalue(), b"")
        self.assertIn(b"request denied by operator", stderr.getvalue())


class FailClosedSurfaceTests(unittest.TestCase):
    def test_real_broker_requires_valid_config_before_opening_socket(self):
        errors = io.StringIO()
        with (
            mock.patch(
                "tmuxgate.application.load_config",
                side_effect=cli.ConfigError("missing protected config"),
            ) as load,
            mock.patch("tmuxgate.application.open_broker_listener") as listen,
            redirect_stderr(errors),
        ):
            status = cli.main(["broker"])
        self.assertEqual(status, cli.EXIT_CONFIG)
        self.assertIn("missing protected config", errors.getvalue())
        load.assert_called_once()
        listen.assert_not_called()

    def test_remote_control_commands_attempt_no_remote_action(self):
        for command in ("cleanup",):
            with self.subTest(command=command):
                errors = io.StringIO()
                with redirect_stderr(errors):
                    status = cli.main([command, REQUEST_ID])
                self.assertEqual(status, cli.EXIT_UNAVAILABLE)
                self.assertIn("no remote action was attempted", errors.getvalue())

    def test_attach_missing_durable_job_attempts_no_remote_action(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = io.StringIO()
            with redirect_stderr(errors):
                status = cli.main(
                    [
                        "attach", REQUEST_ID,
                        "--state-dir", str(Path(directory) / "state"),
                    ]
                )
        self.assertEqual(status, cli.EXIT_UNAVAILABLE)
        self.assertIn("operation failed", errors.getvalue())

    def test_collect_missing_local_spool_attempts_no_remote_action(self):
        with tempfile.TemporaryDirectory() as directory:
            errors = io.StringIO()
            with redirect_stderr(errors):
                status = cli.main(
                    ["collect", REQUEST_ID, "--state-dir", str(Path(directory) / "state")]
                )
        self.assertEqual(status, cli.EXIT_UNAVAILABLE)
        self.assertIn("operation failed", errors.getvalue())

    def test_jobs_lists_empty_local_state_without_remote_contact(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = Path(directory) / "state"
            output = io.StringIO()
            with redirect_stdout(output):
                status = cli.main(["jobs", "--state-dir", str(state_dir)])
        self.assertEqual(status, 0)
        self.assertEqual(output.getvalue(), "No durable tmuxgate jobs.\n")

    def test_job_json_document_exposes_every_recovery_gate(self):
        record = SimpleNamespace(
            completion_time="2026-07-19T12:02:00Z",
            decision=ApprovalDecision.APPROVED,
            endpoint_id="wireguard",
            exit_status=7,
            failure_detail=None,
            generation=8,
            local_spool_manifest_sha256="a" * 64,
            local_spool_verified=True,
            machine_alias="app-server",
            remote_mutation_started=True,
            remote_job_path=f"~/.cache/tmuxgate/jobs/{REQUEST_ID}",
            remote_tmux_session=f"tmuxgate-{REQUEST_ID[:12]}",
            request_id=REQUEST_ID,
            start_time="2026-07-19T12:01:00Z",
            state=RequestState.LEASE_RELEASED,
            terminal_restored=True,
            updated_at="2026-07-19T12:03:00Z",
            viewer_detached=True,
        )
        document = cli._job_document(record)
        self.assertEqual(document["decision"], "approved")
        self.assertEqual(document["local_spool_manifest_sha256"], "a" * 64)
        self.assertTrue(document["local_spool_verified"])
        self.assertTrue(document["viewer_detached"])
        self.assertTrue(document["terminal_restored"])
        self.assertEqual(document["state"], "lease-released")

    def test_after_reboot_recovery_requires_exact_tty_phrase_and_writes_once(self):
        record = SimpleNamespace(
            request_id=REQUEST_ID,
            machine_alias="app-server",
            endpoint_id="home-lan",
            start_time="2026-07-21T19:31:38.081797Z",
            generation=3,
            failure_detail="remote execution is incomplete",
            state=RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        )
        abandoned = SimpleNamespace(
            request_id=REQUEST_ID,
            generation=4,
        )
        terminal = SimpleNamespace(
            reader=io.StringIO(
                f"ABANDON {REQUEST_ID} app-server GENERATION 3 "
                "AFTER FULL REBOOT\n"
            ),
            writer=io.StringIO(),
        )
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.__exit__.return_value = False
        store.load.side_effect = (record, record)
        store.mark_abandoned_after_operator_confirmed_reboot.return_value = abandoned
        paths = SimpleNamespace(runtime_dir=Path("/runtime"), state_dir=Path("/state"))
        output = io.StringIO()

        with (
            mock.patch("tmuxgate.cli.prepare_runtime_layout", return_value=paths),
            mock.patch("tmuxgate.cli.acquire_state_lock", return_value=nullcontext()),
            mock.patch("tmuxgate.cli.DurableStateStore", return_value=store),
            mock.patch(
                "tmuxgate.cli.open_approval_terminal",
                return_value=nullcontext(terminal),
            ),
            redirect_stdout(output),
        ):
            status = cli.main(["recover", "after-reboot", REQUEST_ID])

        self.assertEqual(status, 0)
        store.mark_abandoned_after_operator_confirmed_reboot.assert_called_once_with(record)
        self.assertIn("No SSH action", output.getvalue())

    def test_after_reboot_recovery_wrong_phrase_leaves_state_unchanged(self):
        record = SimpleNamespace(
            request_id=REQUEST_ID,
            machine_alias="app-server",
            endpoint_id="home-lan",
            start_time="2026-07-21T19:31:38.081797Z",
            generation=3,
            failure_detail="remote execution is incomplete",
            state=RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        )
        terminal = SimpleNamespace(
            reader=io.StringIO("wrong phrase\n"),
            writer=io.StringIO(),
        )
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.__exit__.return_value = False
        store.load.return_value = record
        paths = SimpleNamespace(runtime_dir=Path("/runtime"), state_dir=Path("/state"))
        errors = io.StringIO()

        with (
            mock.patch("tmuxgate.cli.prepare_runtime_layout", return_value=paths),
            mock.patch("tmuxgate.cli.acquire_state_lock", return_value=nullcontext()),
            mock.patch("tmuxgate.cli.DurableStateStore", return_value=store),
            mock.patch(
                "tmuxgate.cli.open_approval_terminal",
                return_value=nullcontext(terminal),
            ),
            redirect_stderr(errors),
        ):
            status = cli.main(["recover", "after-reboot", REQUEST_ID])

        self.assertEqual(status, 77)
        store.mark_abandoned_after_operator_confirmed_reboot.assert_not_called()
        self.assertIn("no state changed", errors.getvalue())

    def test_after_reboot_reconciles_completion_proven_without_local_spool(self):
        record = SimpleNamespace(
            request_id=REQUEST_ID,
            machine_alias="vps",
            endpoint_id="wireguard",
            start_time="2026-08-02T20:55:49.412934Z",
            completion_time="2026-08-02T20:55:56.981336Z",
            exit_status=0,
            generation=5,
            failure_detail=None,
            state=RequestState.COMPLETION_PROVEN,
        )
        abandoned = SimpleNamespace(request_id=REQUEST_ID, generation=6)
        terminal = SimpleNamespace(
            reader=io.StringIO(
                f"ABANDON {REQUEST_ID} vps GENERATION 5 AFTER FULL REBOOT\n"
            ),
            writer=io.StringIO(),
        )
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.__exit__.return_value = False
        store.load.side_effect = (record, record)
        store.mark_abandoned_after_operator_confirmed_reboot.return_value = abandoned
        paths = SimpleNamespace(runtime_dir=Path("/runtime"), state_dir=Path("/state"))

        with (
            mock.patch("tmuxgate.cli.prepare_runtime_layout", return_value=paths),
            mock.patch("tmuxgate.cli.acquire_state_lock", return_value=nullcontext()),
            mock.patch("tmuxgate.cli.DurableStateStore", return_value=store),
            mock.patch(
                "tmuxgate.cli.open_approval_terminal",
                return_value=nullcontext(terminal),
            ),
            redirect_stdout(io.StringIO()),
        ):
            status = cli.main(["recover", "after-reboot", REQUEST_ID])

        self.assertEqual(status, 0)
        store.mark_abandoned_after_operator_confirmed_reboot.assert_called_once_with(
            record
        )
        prompt = terminal.writer.getvalue()
        self.assertIn("completed:  2026-08-02T20:55:56.981336Z", prompt)
        self.assertIn("exit:       0", prompt)

    def test_after_dead_pane_recovery_requires_exact_tty_phrase_and_writes_once(self):
        record = SimpleNamespace(
            request_id=REQUEST_ID,
            machine_alias="workstation",
            endpoint_id="wireguard",
            start_time="2026-07-28T22:33:00.568265Z",
            generation=3,
            failure_detail="observer channel timed out",
            state=RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        )
        abandoned = SimpleNamespace(request_id=REQUEST_ID, generation=4)
        terminal = SimpleNamespace(
            reader=io.StringIO(
                f"ABANDON {REQUEST_ID} workstation GENERATION 3 "
                "AFTER DEAD PANE\n"
            ),
            writer=io.StringIO(),
        )
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.__exit__.return_value = False
        store.load.side_effect = (record, record)
        store.mark_abandoned_after_operator_confirmed_dead_pane.return_value = abandoned
        paths = SimpleNamespace(runtime_dir=Path("/runtime"), state_dir=Path("/state"))
        output = io.StringIO()

        with (
            mock.patch("tmuxgate.cli.prepare_runtime_layout", return_value=paths),
            mock.patch("tmuxgate.cli.acquire_state_lock", return_value=nullcontext()),
            mock.patch("tmuxgate.cli.DurableStateStore", return_value=store),
            mock.patch(
                "tmuxgate.cli.open_approval_terminal",
                return_value=nullcontext(terminal),
            ),
            redirect_stdout(output),
        ):
            status = cli.main(["recover", "after-dead-pane", REQUEST_ID])

        self.assertEqual(status, 0)
        store.mark_abandoned_after_operator_confirmed_dead_pane.assert_called_once_with(
            record
        )
        self.assertIn("No SSH action", output.getvalue())

    def test_after_dead_pane_recovery_wrong_phrase_leaves_state_unchanged(self):
        record = SimpleNamespace(
            request_id=REQUEST_ID,
            machine_alias="workstation",
            endpoint_id="wireguard",
            start_time="2026-07-28T22:33:00.568265Z",
            generation=3,
            failure_detail="observer channel timed out",
            state=RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        )
        terminal = SimpleNamespace(
            reader=io.StringIO("wrong phrase\n"),
            writer=io.StringIO(),
        )
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.__exit__.return_value = False
        store.load.return_value = record
        paths = SimpleNamespace(runtime_dir=Path("/runtime"), state_dir=Path("/state"))
        errors = io.StringIO()

        with (
            mock.patch("tmuxgate.cli.prepare_runtime_layout", return_value=paths),
            mock.patch("tmuxgate.cli.acquire_state_lock", return_value=nullcontext()),
            mock.patch("tmuxgate.cli.DurableStateStore", return_value=store),
            mock.patch(
                "tmuxgate.cli.open_approval_terminal",
                return_value=nullcontext(terminal),
            ),
            redirect_stderr(errors),
        ):
            status = cli.main(["recover", "after-dead-pane", REQUEST_ID])

        self.assertEqual(status, 77)
        store.mark_abandoned_after_operator_confirmed_dead_pane.assert_not_called()
        self.assertIn("no state changed", errors.getvalue())

    def test_after_reboot_recovery_eof_leaves_state_unchanged(self):
        record = SimpleNamespace(
            request_id=REQUEST_ID,
            machine_alias="app-server",
            endpoint_id="home-lan",
            start_time="2026-07-21T19:31:38.081797Z",
            generation=3,
            failure_detail="remote execution is incomplete",
            state=RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        )
        terminal = SimpleNamespace(reader=io.StringIO(""), writer=io.StringIO())
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.__exit__.return_value = False
        store.load.return_value = record
        paths = SimpleNamespace(runtime_dir=Path("/runtime"), state_dir=Path("/state"))

        with (
            mock.patch("tmuxgate.cli.prepare_runtime_layout", return_value=paths),
            mock.patch("tmuxgate.cli.acquire_state_lock", return_value=nullcontext()),
            mock.patch("tmuxgate.cli.DurableStateStore", return_value=store),
            mock.patch(
                "tmuxgate.cli.open_approval_terminal",
                return_value=nullcontext(terminal),
            ),
            redirect_stderr(io.StringIO()),
        ):
            status = cli.main(["recover", "after-reboot", REQUEST_ID])

        self.assertEqual(status, 77)
        store.mark_abandoned_after_operator_confirmed_reboot.assert_not_called()

    def test_after_reboot_recovery_detects_confirmation_race(self):
        record = SimpleNamespace(
            request_id=REQUEST_ID,
            machine_alias="app-server",
            endpoint_id="home-lan",
            start_time="2026-07-21T19:31:38.081797Z",
            generation=3,
            failure_detail="remote execution is incomplete",
            state=RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        )
        changed = SimpleNamespace(**{**record.__dict__, "generation": 4})
        terminal = SimpleNamespace(
            reader=io.StringIO(
                f"ABANDON {REQUEST_ID} app-server GENERATION 3 "
                "AFTER FULL REBOOT\n"
            ),
            writer=io.StringIO(),
        )
        store = mock.MagicMock()
        store.__enter__.return_value = store
        store.__exit__.return_value = False
        store.load.side_effect = (record, changed)
        paths = SimpleNamespace(runtime_dir=Path("/runtime"), state_dir=Path("/state"))

        with (
            mock.patch("tmuxgate.cli.prepare_runtime_layout", return_value=paths),
            mock.patch("tmuxgate.cli.acquire_state_lock", return_value=nullcontext()),
            mock.patch("tmuxgate.cli.DurableStateStore", return_value=store),
            mock.patch(
                "tmuxgate.cli.open_approval_terminal",
                return_value=nullcontext(terminal),
            ),
            redirect_stderr(io.StringIO()),
        ):
            status = cli.main(["recover", "after-reboot", REQUEST_ID])

        self.assertEqual(status, cli.EXIT_UNAVAILABLE)
        store.mark_abandoned_after_operator_confirmed_reboot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
