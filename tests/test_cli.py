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
from tmuxgate.state import StateConflictError


REQUEST_ID = "0123456789abcdef0123456789abcdef"


class CommandLineParsingTests(unittest.TestCase):
    def test_exec_accepts_options_after_machine_and_preserves_exact_argv(self):
        argv = [
            "exec",
            "app-server",
            "--cwd",
            "/opt/a path",
            "--timeout",
            "19",
            "--env",
            "B=two words",
            "--env",
            "A=$value",
            "--socket",
            "/tmp/broker.sock",
            "--",
            "printf",
            "space value",
            "quote'\"",
            "$HOME; touch never",
            "line one\nline two",
            "Türkçe",
        ]
        captured = []

        def fake_submit(request, *, socket_path):
            captured.append((request, socket_path))
            return 23

        with mock.patch("tmuxgate.cli.submit_and_present", side_effect=fake_submit):
            status = cli.main(argv)

        self.assertEqual(status, 23)
        request, socket_path = captured[0]
        self.assertEqual(socket_path, "/tmp/broker.sock")
        self.assertEqual(request.machine_alias, "app-server")
        self.assertEqual(request.cwd, "/opt/a path")
        self.assertEqual(request.timeout_seconds, 19)
        self.assertEqual(request.environment, (("A", "$value"), ("B", "two words")))
        self.assertEqual(
            request.argv,
            (
                "printf",
                "space value",
                "quote'\"",
                "$HOME; touch never",
                "line one\nline two",
                "Türkçe",
            ),
        )

    def test_exec_requires_command_payload(self):
        parser = cli.build_parser()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            parser.parse_args(["exec", "app-server", "--cwd", "/tmp"])
        self.assertEqual(raised.exception.code, 2)

    def test_script_file_preserves_exact_bytes(self):
        content = b"#!/bin/bash\nprintf '\\xff'\n\xff\x00\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payload.sh"
            path.write_bytes(content)
            captured = []

            def fake_submit(request, *, socket_path):
                captured.append(request)
                return 0

            with mock.patch("tmuxgate.cli.submit_and_present", side_effect=fake_submit):
                status = cli.main(
                    [
                        "script",
                        "app-server",
                        "--cwd",
                        "/tmp",
                        "--file",
                        str(path),
                    ]
                )

        self.assertEqual(status, 0)
        self.assertEqual(captured[0].mode, ExecutionMode.SCRIPT)
        self.assertEqual(captured[0].script, content)

    def test_invalid_environment_is_usage_error_before_socket_contact(self):
        errors = io.StringIO()
        with (
            mock.patch("tmuxgate.cli.submit_request") as submit,
            redirect_stderr(errors),
        ):
            status = cli.main(
                ["exec", "app-server", "--cwd", "/tmp", "--env", "BROKEN", "--", "true"]
            )
        self.assertEqual(status, cli.EXIT_USAGE)
        self.assertIn("NAME=VALUE", errors.getvalue())
        submit.assert_not_called()

    def test_duplicate_environment_is_rejected_by_request_model(self):
        errors = io.StringIO()
        with (
            mock.patch("tmuxgate.cli.submit_request") as submit,
            redirect_stderr(errors),
        ):
            status = cli.main(
                [
                    "exec",
                    "app-server",
                    "--cwd",
                    "/tmp",
                    "--env",
                    "A=one",
                    "--env",
                    "A=two",
                    "--",
                    "true",
                ]
            )
        self.assertEqual(status, cli.EXIT_USAGE)
        self.assertIn("duplicate environment variable", errors.getvalue())
        submit.assert_not_called()


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
                "tmuxgate.cli.load_config",
                side_effect=cli.ConfigError("missing protected config"),
            ) as load,
            mock.patch("tmuxgate.cli.open_broker_listener") as listen,
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

    def test_broker_connection_failure_maps_to_unavailable(self):
        errors = io.StringIO()
        with (
            mock.patch(
                "tmuxgate.cli.submit_request",
                side_effect=cli.BrokerConnectionError("broker absent"),
            ),
            redirect_stderr(errors),
        ):
            status = cli.main(
                ["exec", "app-server", "--cwd", "/tmp", "--", "true"]
            )
        self.assertEqual(status, cli.EXIT_UNAVAILABLE)
        self.assertIn("broker absent", errors.getvalue())

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
            mock.patch("tmuxgate.cli.acquire_broker_lock", return_value=nullcontext()),
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
            mock.patch("tmuxgate.cli.acquire_broker_lock", return_value=nullcontext()),
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
            mock.patch("tmuxgate.cli.acquire_broker_lock", return_value=nullcontext()),
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
            mock.patch("tmuxgate.cli.acquire_broker_lock", return_value=nullcontext()),
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
            mock.patch("tmuxgate.cli.acquire_broker_lock", return_value=nullcontext()),
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
            mock.patch("tmuxgate.cli.acquire_broker_lock", return_value=nullcontext()),
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
