import io
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from tmuxgate.approval import (
    ApprovalDecision,
    ApprovalTerminal,
    request_approval,
)
from tmuxgate.broker import BrokerError, BrokerServer, _ClientSession
from tmuxgate.client import BrokerConnectionError, submit_request
from tmuxgate.fake import FakeExecution, ScriptedApprover, ScriptedFakeExecutor
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.operator_interface import ActivityKind, OperationalActivity
from tmuxgate.protocol import receive_frame, send_frame
from tmuxgate.result import ExecutionResult, TransportStatus
from tmuxgate.runtime import PeerCredentialError, create_broker_socket


def request(label: str, *, machine: str = "machine-a") -> RequestSpec:
    return RequestSpec(
        machine_alias=machine,
        mode=ExecutionMode.ARGV,
        cwd="/tmp",
        argv=("definitely-not-a-real-executor", label),
    )


class BlockingFakeExecutor:
    """A test barrier which, like every fake, never interprets the request."""

    def __init__(self, executions: list[FakeExecution]) -> None:
        self._executions = list(executions)
        self._lock = threading.Lock()
        self.calls: list[tuple[str, RequestSpec]] = []
        self.first_started = threading.Event()
        self.release_first = threading.Event()

    def __call__(self, request_id: str, spec: RequestSpec) -> FakeExecution:
        with self._lock:
            index = len(self.calls)
            self.calls.append((request_id, spec))
            execution = self._executions[index]
        if index == 0:
            self.first_started.set()
            if not self.release_first.wait(timeout=3):
                raise RuntimeError("test did not release first fake execution")
        return execution


class BlockingApprover:
    def __init__(self, decision=ApprovalDecision.APPROVED) -> None:
        self.decision = decision
        self.calls: list[tuple[str, RequestSpec]] = []
        self.started = threading.Event()
        self.release = threading.Event()

    def __call__(self, request_id: str, spec: RequestSpec) -> ApprovalDecision:
        self.calls.append((request_id, spec))
        self.started.set()
        if not self.release.wait(timeout=3):
            raise RuntimeError("test did not release approval prompt")
        return self.decision


class IndefinitelyBlockingExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, RequestSpec]] = []
        self.started = threading.Event()
        self.release = threading.Event()

    def __call__(self, request_id: str, spec: RequestSpec) -> FakeExecution:
        self.calls.append((request_id, spec))
        self.started.set()
        self.release.wait()
        return FakeExecution()


class FailingFakeExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, RequestSpec]] = []

    def __call__(self, request_id: str, spec: RequestSpec) -> FakeExecution:
        self.calls.append((request_id, spec))
        raise RuntimeError("injected post-running-boundary failure")


class RemoteSetupFailingExecutor:
    def __init__(self) -> None:
        self.calls = []

    def __call__(self, request_id: str, spec: RequestSpec) -> ExecutionResult:
        self.calls.append((request_id, spec))
        return ExecutionResult(
            request_id,
            TransportStatus.REMOTE_SETUP_FAILURE,
            detail="authorized_keys may have changed; command was not started",
        )


class BrokerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.socket_path = Path(self.temporary.name) / "broker.sock"
        self.servers: list[BrokerServer] = []

    def tearDown(self):
        for server in reversed(self.servers):
            server.stop()

    def start_server(
        self,
        approver,
        executor,
        *,
        allowed_machines=("machine-a",),
        max_pending_requests=16,
        max_client_sessions=None,
        send_timeout_seconds=0.5,
        peer_validator=None,
        **broker_options,
    ) -> BrokerServer:
        listener = create_broker_socket(self.socket_path)
        options = {}
        if peer_validator is not None:
            options["peer_validator"] = peer_validator
        server = BrokerServer(
            listener,
            allowed_machines=allowed_machines,
            approver=approver,
            executor=executor,
            max_pending_requests=max_pending_requests,
            max_client_sessions=max_client_sessions,
            request_timeout_seconds=0.5,
            send_timeout_seconds=send_timeout_seconds,
            **broker_options,
            **options,
        )
        server.start()
        self.servers.append(server)
        return server

    @staticmethod
    def wait_until(predicate, *, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.005)
        return predicate()

    def test_denial_returns_local_status_and_never_calls_executor(self):
        approver = ScriptedApprover([ApprovalDecision.DENIED])
        executor = ScriptedFakeExecutor([FakeExecution(stdout=b"must-not-run")])
        activity: list[OperationalActivity] = []
        server = self.start_server(
            approver,
            executor,
            activity_publisher=activity.append,
        )

        result = submit_request(request("deny-me"), socket_path=self.socket_path)

        self.assertEqual(result.transport_status, TransportStatus.DENIED)
        self.assertIsNone(result.remote_exit_status)
        self.assertEqual(executor.calls, [])
        events = [name for name, _ in server.audit_log]
        self.assertLess(
            events.index("preapproval-status-written"),
            events.index("approval-begun"),
        )
        self.assertEqual(
            [event.message for event in activity],
            events,
        )
        self.assertTrue(
            all(event.kind is ActivityKind.BROKER_AUDIT for event in activity)
        )
        self.assertTrue(
            all(
                event.request_id is None or len(event.request_id) == 32
                for event in activity
            )
        )

    def test_two_executions_progress_in_parallel_when_configured(self):
        approver = ScriptedApprover(
            [ApprovalDecision.APPROVED, ApprovalDecision.APPROVED]
        )
        executor = BlockingFakeExecutor(
            [FakeExecution(stdout=b"first"), FakeExecution(stdout=b"second")]
        )
        self.start_server(
            approver,
            executor,
            allowed_machines=("machine-a", "machine-b"),
            max_active_remote_commands=2,
        )
        results = []
        first = threading.Thread(
            target=lambda: results.append(
                submit_request(request("first"), socket_path=self.socket_path)
            )
        )
        second = threading.Thread(
            target=lambda: results.append(
                submit_request(
                    request("second", machine="machine-b"),
                    socket_path=self.socket_path,
                )
            )
        )
        first.start()
        self.assertTrue(executor.first_started.wait(timeout=1))
        second.start()
        self.assertTrue(self.wait_until(lambda: len(executor.calls) == 2))
        executor.release_first.set()
        first.join(timeout=2)
        second.join(timeout=2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(
            {result.stdout for result in results}, {b"first", b"second"}
        )

    def test_writer_does_not_own_socket_timeout_until_reader_handoff(self):
        broker_end, client_end = socket.socketpair()
        self.addCleanup(client_end.close)
        closed = threading.Event()
        session = _ClientSession(
            broker_end,
            send_timeout_seconds=0.1,
            on_closed=lambda _session: closed.set(),
        )

        time.sleep(0.03)
        self.assertIsNone(broker_end.gettimeout())
        session.finish_reading()
        self.assertTrue(
            self.wait_until(lambda: broker_end.gettimeout() == 0.1)
        )
        session.close()
        self.assertTrue(closed.wait(timeout=1))

    def test_non_utf8_filesystem_bytes_survive_end_to_end_framing(self):
        original = RequestSpec(
            machine_alias="machine-a",
            mode=ExecutionMode.ARGV,
            cwd=os.fsdecode(b"/tmp/raw-\xff-dir"),
            argv=(
                "definitely-not-a-real-executor",
                os.fsdecode(b"raw-\xfe-argument"),
            ),
            environment=(("RAW_VALUE", os.fsdecode(b"value-\xfd")),),
        )
        approver = ScriptedApprover([ApprovalDecision.APPROVED])
        executor = ScriptedFakeExecutor([FakeExecution(stdout=b"preserved\n")])
        self.start_server(approver, executor)

        result = submit_request(original, socket_path=self.socket_path)

        self.assertEqual(result.stdout, b"preserved\n")
        self.assertEqual(approver.calls[0][1], original)
        self.assertEqual(executor.calls[0][1], original)
        received = executor.calls[0][1]
        self.assertEqual(os.fsencode(received.cwd), b"/tmp/raw-\xff-dir")
        self.assertEqual(os.fsencode(received.argv[1]), b"raw-\xfe-argument")
        self.assertEqual(
            os.fsencode(dict(received.environment)["RAW_VALUE"]), b"value-\xfd"
        )

    def test_disconnected_awaiting_client_makes_later_run_stale(self):
        approver = BlockingApprover(ApprovalDecision.APPROVED)
        executor = ScriptedFakeExecutor([])
        server = self.start_server(
            approver,
            executor,
            approval_heartbeat_seconds=0.03,
        )
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(os.fspath(self.socket_path))
        spec = request("disconnect-during-prompt")
        send_frame(client, spec.to_wire_header(), spec.script)
        client.shutdown(socket.SHUT_WR)
        self.assertTrue(approver.started.wait(timeout=1))
        client.close()

        self.assertTrue(server.wait_for_audit("approval-client-disconnected"))
        approver.release.set()
        self.assertTrue(server.wait_for_audit("stale-approval-ignored"))
        self.assertEqual(executor.calls, [])
        self.assertTrue(
            self.wait_until(lambda: server._scheduler.record_count == 0)
        )

    def test_stop_during_blocked_approval_never_starts_executor(self):
        approver = BlockingApprover(ApprovalDecision.APPROVED)
        executor = ScriptedFakeExecutor([])
        server = self.start_server(approver, executor)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        client.connect(os.fspath(self.socket_path))
        spec = request("stop-before-run")
        send_frame(client, spec.to_wire_header(), spec.script)
        client.shutdown(socket.SHUT_WR)
        self.assertTrue(approver.started.wait(timeout=1))

        outcome: list[bool] = []
        stopper = threading.Thread(target=lambda: outcome.append(server.stop()))
        stopper.start()
        self.assertTrue(self.wait_until(server._stopping.is_set))
        approver.release.set()
        stopper.join(timeout=2)

        self.assertFalse(stopper.is_alive())
        self.assertEqual(outcome, [True])
        self.assertEqual(executor.calls, [])

    def test_blocked_executor_makes_stop_report_incomplete(self):
        approver = ScriptedApprover([ApprovalDecision.APPROVED])
        executor = IndefinitelyBlockingExecutor()
        server = self.start_server(
            approver,
            executor,
            shutdown_timeout_seconds=0.05,
        )
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        client.connect(os.fspath(self.socket_path))
        spec = request("blocked-executor")
        send_frame(client, spec.to_wire_header(), spec.script)
        client.shutdown(socket.SHUT_WR)
        self.assertTrue(executor.started.wait(timeout=1))

        self.assertFalse(server.stop())
        self.assertTrue(server.wait_for_audit("stop-incomplete"))
        executor.release.set()

        def workers_stopped():
            with server._execution_threads_lock:
                executions_done = not any(
                    thread.is_alive() for thread in server._execution_threads
                )
            with server._sessions_lock:
                sessions_done = not server._sessions
            return executions_done and sessions_done

        self.assertTrue(self.wait_until(workers_stopped))
        self.assertTrue(server.stop())

    def test_partial_thread_start_failure_can_be_rolled_back(self):
        listener = create_broker_socket(self.socket_path)
        server = BrokerServer(
            listener,
            allowed_machines=("machine-a",),
            approver=ScriptedApprover([]),
            executor=ScriptedFakeExecutor([]),
            shutdown_timeout_seconds=0.5,
        )
        self.servers.append(server)

        with mock.patch.object(
            server._terminal_thread,
            "start",
            side_effect=RuntimeError("injected terminal thread start failure"),
        ):
            with self.assertRaisesRegex(BrokerError, "start all broker workers"):
                server.start()

        self.assertTrue(server.stop())

    def test_executor_failure_is_incomplete_and_retains_the_command_lease(self):
        approver = ScriptedApprover([ApprovalDecision.APPROVED])
        executor = FailingFakeExecutor()
        server = self.start_server(approver, executor)

        result = submit_request(
            request("uncertain-after-start"),
            socket_path=self.socket_path,
        )

        self.assertEqual(result.transport_status, TransportStatus.INCOMPLETE)
        self.assertIsNone(result.remote_exit_status)
        self.assertIn("lease retained", result.detail)
        self.assertEqual(len(executor.calls), 1)
        self.assertTrue(server.wait_for_audit("recovery-required"))
        request_id = executor.calls[0][0]
        self.assertEqual(server._scheduler.lease_owner, request_id)
        self.assertIn(request_id, server._jobs)
        self.assertIn(request_id, server._active_request_ids)

    def test_remote_setup_failure_releases_slot_without_claiming_command_start(self):
        approver = ScriptedApprover([ApprovalDecision.APPROVED])
        executor = RemoteSetupFailingExecutor()
        server = self.start_server(approver, executor)

        result = submit_request(
            request("uncertain-enrollment"),
            socket_path=self.socket_path,
        )

        self.assertEqual(
            result.transport_status,
            TransportStatus.REMOTE_SETUP_FAILURE,
        )
        self.assertIn("command was not started", result.detail)
        self.assertTrue(server.wait_for_audit("remote-setup-failure"))
        self.assertIsNone(server._scheduler.lease_owner)
        self.assertFalse(any(name == "recovery-required" for name, _ in server.audit_log))

    def test_approved_malicious_argv_is_not_executed_and_exit_seven_is_exact(self):
        marker = Path(self.temporary.name) / "client-command-was-run"
        malicious = RequestSpec(
            machine_alias="machine-a",
            mode=ExecutionMode.ARGV,
            cwd="/tmp",
            argv=("sh", "-c", f"printf compromised > {marker}"),
        )
        approver = ScriptedApprover([ApprovalDecision.APPROVED])
        executor = ScriptedFakeExecutor(
            [
                FakeExecution(
                    stdout=b"stdout-line\n\x00",
                    stderr=b"stderr-line\n\xff",
                    exit_status=7,
                )
            ]
        )
        self.start_server(approver, executor)

        result = submit_request(malicious, socket_path=self.socket_path)

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        self.assertEqual(result.stdout, b"stdout-line\n\x00")
        self.assertEqual(result.stderr, b"stderr-line\n\xff")
        self.assertEqual(result.remote_exit_status, 7)
        self.assertEqual(result.transparent_exit_code(), 7)
        self.assertFalse(marker.exists())
        self.assertEqual(len(executor.calls), 1)

    def test_three_clients_are_fifo_and_only_one_fake_command_runs_at_a_time(self):
        approver = ScriptedApprover(
            [
                ApprovalDecision.APPROVED,
                ApprovalDecision.APPROVED,
                ApprovalDecision.APPROVED,
            ]
        )
        executor = BlockingFakeExecutor(
            [
                FakeExecution(stdout=b"A\n", exit_status=0),
                FakeExecution(stdout=b"B\n", exit_status=3),
                FakeExecution(stdout=b"C\n", exit_status=5),
            ]
        )
        server = self.start_server(approver, executor)
        results: dict[str, object] = {}

        def run(label: str):
            results[label] = submit_request(
                request(label),
                socket_path=self.socket_path,
            )

        first = threading.Thread(target=run, args=("A",))
        second = threading.Thread(target=run, args=("B",))
        third = threading.Thread(target=run, args=("C",))
        first.start()
        self.assertTrue(executor.first_started.wait(timeout=2))
        second.start()
        self.assertTrue(
            self.wait_until(
                lambda: sum(name == "queued" for name, _ in server.audit_log) == 2
            )
        )
        third.start()
        self.assertTrue(
            self.wait_until(
                lambda: sum(name == "queued" for name, _ in server.audit_log) == 3
            )
        )
        self.assertEqual(len(approver.calls), 1)
        self.assertEqual(len(executor.calls), 1)

        executor.release_first.set()
        first.join(timeout=3)
        second.join(timeout=3)
        third.join(timeout=3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertFalse(third.is_alive())
        self.assertEqual(
            [call[1].argv[-1] for call in approver.calls],
            ["A", "B", "C"],
        )
        self.assertEqual(
            [call[1].argv[-1] for call in executor.calls],
            ["A", "B", "C"],
        )
        self.assertEqual(results["A"].stdout, b"A\n")
        self.assertEqual(results["B"].stdout, b"B\n")
        self.assertEqual(results["B"].remote_exit_status, 3)
        self.assertEqual(results["C"].stdout, b"C\n")
        self.assertEqual(results["C"].remote_exit_status, 5)

    def test_client_payload_cannot_answer_the_broker_terminal_prompt(self):
        terminal_output = io.StringIO()
        terminal = ApprovalTerminal(
            reader=io.StringIO("DENY\n"),
            writer=terminal_output,
        )

        def terminal_approver(request_id, spec):
            return request_approval(
                request_id,
                spec,
                terminal=terminal,
                pager=None,
            )

        executor = ScriptedFakeExecutor([FakeExecution(stdout=b"must-not-run")])
        self.start_server(terminal_approver, executor)
        payload = b"RUN 00000000\nDENY\nRUN anything-the-client-wants\n"
        spec = RequestSpec(
            machine_alias="machine-a",
            mode=ExecutionMode.SCRIPT,
            cwd="/tmp",
            script=payload,
        )

        result = submit_request(spec, socket_path=self.socket_path)

        self.assertEqual(result.transport_status, TransportStatus.DENIED)
        self.assertEqual(executor.calls, [])
        self.assertIn("RUN 00000000", terminal_output.getvalue())
        self.assertIn("Approve? [y/N]", terminal_output.getvalue())

    def test_full_pending_queue_rejects_third_request_without_approval(self):
        approver = ScriptedApprover(
            [ApprovalDecision.APPROVED, ApprovalDecision.APPROVED]
        )
        executor = BlockingFakeExecutor([FakeExecution(), FakeExecution()])
        server = self.start_server(
            approver,
            executor,
            max_pending_requests=1,
        )
        results: dict[str, object] = {}

        first = threading.Thread(
            target=lambda: results.setdefault(
                "A",
                submit_request(request("A"), socket_path=self.socket_path),
            )
        )
        second = threading.Thread(
            target=lambda: results.setdefault(
                "B",
                submit_request(request("B"), socket_path=self.socket_path),
            )
        )
        first.start()
        self.assertTrue(executor.first_started.wait(timeout=2))
        second.start()
        self.assertTrue(
            self.wait_until(
                lambda: sum(name == "queued" for name, _ in server.audit_log) == 2
            )
        )

        rejected = submit_request(request("C"), socket_path=self.socket_path)

        self.assertEqual(rejected.transport_status, TransportStatus.BROKER_BUSY)
        self.assertEqual(len(approver.calls), 1)
        self.assertEqual(len(executor.calls), 1)
        executor.release_first.set()
        first.join(timeout=3)
        second.join(timeout=3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual([call[1].argv[-1] for call in executor.calls], ["A", "B"])

    def test_unknown_machine_is_rejected_without_approval_or_execution(self):
        approver = ScriptedApprover([ApprovalDecision.APPROVED])
        executor = ScriptedFakeExecutor([FakeExecution()])
        self.start_server(approver, executor)

        result = submit_request(
            request("unknown", machine="unknown-machine"),
            socket_path=self.socket_path,
        )

        self.assertEqual(result.transport_status, TransportStatus.INVALID_REQUEST)
        self.assertIn("unknown configured machine", result.detail)
        self.assertEqual(approver.calls, [])
        self.assertEqual(executor.calls, [])

    def test_runtime_disabled_machine_is_rejected_before_queue_or_approval(self):
        approver = ScriptedApprover([ApprovalDecision.APPROVED])
        executor = ScriptedFakeExecutor([FakeExecution()])
        enabled = {"machine-a": False}
        server = self.start_server(
            approver,
            executor,
            machine_enabled=enabled.__getitem__,
        )

        result = submit_request(request("disabled"), socket_path=self.socket_path)

        self.assertEqual(result.transport_status, TransportStatus.INVALID_REQUEST)
        self.assertIn("configured machine is disabled", result.detail)
        self.assertEqual(approver.calls, [])
        self.assertEqual(executor.calls, [])
        self.assertIn(("disabled-machine", result.request_id), server.audit_log)

    def test_pending_queue_is_bounded_while_one_command_runs(self):
        approver = ScriptedApprover(
            [ApprovalDecision.APPROVED, ApprovalDecision.APPROVED]
        )
        executor = BlockingFakeExecutor([FakeExecution(), FakeExecution(stdout=b"second")])
        server = self.start_server(
            approver,
            executor,
            max_pending_requests=1,
        )
        results: list[object] = []

        first = threading.Thread(
            target=lambda: results.append(
                submit_request(request("active"), socket_path=self.socket_path)
            )
        )
        queued = threading.Thread(
            target=lambda: results.append(
                submit_request(request("queued"), socket_path=self.socket_path)
            )
        )
        first.start()
        self.assertTrue(executor.first_started.wait(timeout=2))
        queued.start()
        self.assertTrue(
            self.wait_until(
                lambda: sum(name == "queued" for name, _ in server.audit_log) == 2
            )
        )

        rejected = submit_request(request("overflow"), socket_path=self.socket_path)
        self.assertEqual(rejected.transport_status, TransportStatus.BROKER_BUSY)
        self.assertEqual(len(approver.calls), 1)
        self.assertEqual(len(executor.calls), 1)

        executor.release_first.set()
        first.join(timeout=3)
        queued.join(timeout=3)
        self.assertFalse(first.is_alive())
        self.assertFalse(queued.is_alive())
        self.assertEqual(len(executor.calls), 2)

    def test_peer_is_validated_before_any_request_bytes_are_read(self):
        validator_called = threading.Event()

        def reject_peer(_connection):
            validator_called.set()
            raise PeerCredentialError("injected wrong UID")

        approver = ScriptedApprover([ApprovalDecision.APPROVED])
        executor = ScriptedFakeExecutor([FakeExecution()])
        server = self.start_server(
            approver,
            executor,
            peer_validator=reject_peer,
        )
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        client.connect(os.fspath(self.socket_path))

        self.assertTrue(validator_called.wait(timeout=1))
        self.assertTrue(server.wait_for_audit("peer-rejected"))
        client.settimeout(1)
        self.assertEqual(client.recv(1), b"")
        self.assertEqual(approver.calls, [])
        self.assertEqual(executor.calls, [])

    def test_client_disconnect_after_approval_does_not_cancel_fake_job(self):
        approver = ScriptedApprover(
            [ApprovalDecision.APPROVED, ApprovalDecision.APPROVED]
        )
        executor = BlockingFakeExecutor([FakeExecution(), FakeExecution(stdout=b"second")])
        server = self.start_server(approver, executor)

        abandoned = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        abandoned.connect(os.fspath(self.socket_path))
        first_request = request("abandoned-after-approval")
        send_frame(abandoned, first_request.to_wire_header(), first_request.script)
        abandoned.shutdown(socket.SHUT_WR)
        while True:
            frame = receive_frame(abandoned, timeout_seconds=2)
            if frame.header.get("type") == "status" and frame.header.get("state") == "execution-starting":
                break
        self.assertTrue(executor.first_started.wait(timeout=2))
        abandoned.close()

        second_result: list[object] = []
        second = threading.Thread(
            target=lambda: second_result.append(
                submit_request(request("second"), socket_path=self.socket_path)
            )
        )
        second.start()
        self.assertTrue(
            self.wait_until(
                lambda: sum(name == "queued" for name, _ in server.audit_log) == 2
            )
        )
        self.assertEqual(len(approver.calls), 1)
        executor.release_first.set()
        second.join(timeout=3)

        self.assertFalse(second.is_alive())
        self.assertEqual(len(executor.calls), 2)
        self.assertEqual(second_result[0].stdout, b"second")
        completed_ids = [request_id for name, request_id in server.audit_log if name == "completed"]
        self.assertEqual(len(completed_ids), 2)

    def test_nonreading_result_client_cannot_block_the_next_command(self):
        approver = ScriptedApprover(
            [ApprovalDecision.APPROVED, ApprovalDecision.APPROVED]
        )
        executor = ScriptedFakeExecutor(
            [
                FakeExecution(stdout=b"x" * (8 * 1024 * 1024)),
                FakeExecution(stdout=b"B-complete\n", exit_status=4),
            ]
        )
        server = self.start_server(
            approver,
            executor,
            send_timeout_seconds=0.15,
        )

        nonreader = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(nonreader.close)
        nonreader.connect(os.fspath(self.socket_path))
        first_request = request("large-result-nonreader")
        send_frame(nonreader, first_request.to_wire_header(), first_request.script)
        nonreader.shutdown(socket.SHUT_WR)
        while True:
            frame = receive_frame(nonreader, timeout_seconds=2)
            if frame.header.get("type") == "status" and frame.header.get("state") == "execution-starting":
                break
        # Stop reading before the large result.  Its per-session writer will
        # time out, but the coordinator and another session must remain live.
        second = submit_request(request("B"), socket_path=self.socket_path)

        self.assertEqual(second.stdout, b"B-complete\n")
        self.assertEqual(second.remote_exit_status, 4)
        self.assertEqual([call[1].argv[-1] for call in executor.calls], ["large-result-nonreader", "B"])
        self.assertTrue(server.wait_for_audit("result-client-disconnected"))

    def test_client_validates_broker_peer_before_sending_request(self):
        approver = ScriptedApprover([ApprovalDecision.APPROVED])
        executor = ScriptedFakeExecutor([FakeExecution()])
        self.start_server(approver, executor)
        checked = threading.Event()

        def reject_broker(_connection):
            checked.set()
            raise PeerCredentialError("injected broker UID mismatch")

        with self.assertRaises(BrokerConnectionError):
            submit_request(
                request("not-sent"),
                socket_path=self.socket_path,
                broker_peer_validator=reject_broker,
            )
        self.assertTrue(checked.is_set())
        time.sleep(0.05)
        self.assertEqual(approver.calls, [])
        self.assertEqual(executor.calls, [])

    def test_broker_retries_a_request_id_collision(self):
        approver = ScriptedApprover([ApprovalDecision.APPROVED])
        executor = ScriptedFakeExecutor([FakeExecution()])
        self.start_server(approver, executor)
        first_id = "1" * 32
        second_id = "2" * 32

        with mock.patch(
            "tmuxgate.broker.new_request_id",
            side_effect=[first_id, first_id, second_id],
        ):
            first = submit_request(
                request("unknown-1", machine="unknown-one"),
                socket_path=self.socket_path,
            )
            second = submit_request(
                request("unknown-2", machine="unknown-two"),
                socket_path=self.socket_path,
            )

        self.assertEqual(first.request_id, first_id)
        self.assertEqual(second.request_id, second_id)
        self.assertNotEqual(first.request_id, second.request_id)

    def test_completed_requests_are_pruned_and_histories_are_bounded(self):
        count = 12
        approver = ScriptedApprover([ApprovalDecision.DENIED] * count)
        executor = ScriptedFakeExecutor([])
        server = self.start_server(
            approver,
            executor,
            audit_capacity=8,
            recent_request_id_capacity=4,
        )

        for index in range(count):
            result = submit_request(
                request(f"denied-{index}"), socket_path=self.socket_path
            )
            self.assertEqual(result.transport_status, TransportStatus.DENIED)

        self.assertTrue(
            self.wait_until(
                lambda: server._scheduler.record_count == 0
                and not server._jobs
                and not server._active_request_ids
            )
        )
        with server._reader_threads_lock:
            self.assertEqual(server._reader_threads, set())
        self.assertLessEqual(len(server._recent_request_ids), 4)
        self.assertLessEqual(len(server._recent_request_id_set), 4)
        self.assertLessEqual(len(server.audit_log), 8)

    def test_broker_rejects_nonfinite_and_boolean_timeouts(self):
        fields = (
            "request_timeout_seconds",
            "send_timeout_seconds",
            "approval_heartbeat_seconds",
            "shutdown_timeout_seconds",
        )
        values = (True, float("nan"), float("inf"), float("-inf"))
        index = 0
        for field in fields:
            for value in values:
                with self.subTest(field=field, value=value):
                    listener = create_broker_socket(
                        Path(self.temporary.name) / f"invalid-{index}.sock"
                    )
                    index += 1
                    self.addCleanup(listener.close)
                    with self.assertRaises(ValueError):
                        BrokerServer(
                            listener,
                            allowed_machines=("machine-a",),
                            approver=ScriptedApprover([]),
                            executor=ScriptedFakeExecutor([]),
                            **{field: value},
                        )


if __name__ == "__main__":
    unittest.main()
