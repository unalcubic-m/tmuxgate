from dataclasses import replace
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from tmuxgate.approval import ApprovalDecision
from tmuxgate.broker import BrokerServer
from tmuxgate.broker_api import (
    BrokerControlError,
    BrokerControlService,
    JobPage,
    ListJobsRequest,
    ListMachinesRequest,
    MachineList,
    ReadVerifiedResultRequest,
    ResultStream,
    decode_control_request,
    decode_control_response,
)
from tmuxgate.client import list_jobs, list_machines, read_verified_result
from tmuxgate.models import PROTOCOL_VERSION
from tmuxgate.protocol import Frame, ProtocolError
from tmuxgate.runtime import create_broker_socket
from tmuxgate.scheduler import RequestState
from tmuxgate.spool import ResultSpool, STDOUT_NAME
from tmuxgate.state import DurableJobRecord, DurableStateStore


REQUEST_ID = "0123456789abcdef0123456789abcdef"
DENIED_ID = "89abcdef0123456789abcdef01234567"
CREATED = "2026-07-19T12:00:00.000000Z"
LATER = "2026-07-19T12:01:00.000000Z"


def completed_record(manifest_sha256: str) -> DurableJobRecord:
    return DurableJobRecord(
        request_id=REQUEST_ID,
        generation=1,
        machine_alias="machine-a",
        client_request_sha256="a" * 64,
        connection_plan_sha256="b" * 64,
        endpoint_id="home-lan",
        resolved_user="operator",
        resolved_hostname="192.0.2.20",
        resolved_port=22,
        host_key_alias="tmuxgate-machine-a",
        remote_job_path=f"~/.cache/tmuxgate/jobs/{REQUEST_ID}",
        remote_tmux_session=f"tmuxgate-{REQUEST_ID[:12]}",
        decision=ApprovalDecision.APPROVED,
        state=RequestState.LOCAL_SPOOL_VERIFIED,
        created_at=CREATED,
        updated_at=CREATED,
        start_time=CREATED,
        completion_time=CREATED,
        exit_status=7,
        remote_mutation_started=True,
        local_spool_verified=True,
        local_spool_manifest_sha256=manifest_sha256,
    )


def denied_record() -> DurableJobRecord:
    return DurableJobRecord(
        request_id=DENIED_ID,
        generation=1,
        machine_alias="machine-a",
        client_request_sha256="c" * 64,
        connection_plan_sha256=None,
        endpoint_id=None,
        resolved_user=None,
        resolved_hostname=None,
        resolved_port=None,
        host_key_alias=None,
        remote_job_path=None,
        remote_tmux_session=None,
        decision=ApprovalDecision.DENIED,
        state=RequestState.DENIED,
        created_at=LATER,
        updated_at=LATER,
    )


class ControlCodecTests(unittest.TestCase):
    def test_requests_require_exact_fields_and_empty_payload(self):
        request = decode_control_request(
            Frame({"protocol": PROTOCOL_VERSION, "type": "list_machines"}, b"")
        )
        self.assertIsInstance(request, ListMachinesRequest)

        with self.assertRaisesRegex(ProtocolError, "unknown"):
            decode_control_request(
                Frame(
                    {"protocol": PROTOCOL_VERSION, "type": "list_machines", "host": "leak"},
                    b"",
                )
            )
        with self.assertRaisesRegex(ProtocolError, "payload"):
            decode_control_request(
                Frame(
                    {"protocol": PROTOCOL_VERSION, "type": "list_machines"},
                    b"prompt answer",
                )
            )
        with self.assertRaisesRegex(ProtocolError, "between"):
            decode_control_request(
                Frame(
                    {
                        "cursor": None,
                        "limit": True,
                        "protocol": PROTOCOL_VERSION,
                        "states": [],
                        "type": "list_jobs",
                    },
                    b"",
                )
            )

    def test_response_type_is_bound_to_request(self):
        header, payload = MachineList(()).to_wire()
        response = decode_control_response(ListMachinesRequest(), Frame(header, payload))
        self.assertEqual(response, MachineList(()))
        with self.assertRaises(ProtocolError):
            decode_control_response(ListJobsRequest(), Frame(header, payload))


class BrokerControlServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        os.chmod(self.temporary.name, 0o700)
        self.state_dir = Path(self.temporary.name) / "state"
        self.store = DurableStateStore(self.state_dir)
        self.addCleanup(self.store.close)
        self.spool = ResultSpool(self.state_dir)
        self.addCleanup(self.spool.close)
        self.stdout = b"out\x00\xfftail"
        self.stderr = b"err\x00\xfe"
        stored = self.spool.store(REQUEST_ID, self.stdout, self.stderr, 7)
        self.completed = completed_record(stored.manifest_payload_sha256)
        self.store.write(self.completed)
        self.store.write(denied_record())
        self.service = BrokerControlService(
            {"machine-a": SimpleNamespace(description="Application server")},
            self.store,
            self.spool,
        )

    def test_machine_list_exposes_only_alias_and_description(self):
        response = self.service.handle(ListMachinesRequest())
        self.assertIsInstance(response, MachineList)
        self.assertEqual(response.machines[0].alias, "machine-a")
        self.assertEqual(response.machines[0].description, "Application server")
        self.assertEqual(set(response.machines[0].to_wire()), {"alias", "description"})

    def test_jobs_filter_and_paginate_newest_first(self):
        first = self.service.handle(ListJobsRequest(limit=1))
        self.assertIsInstance(first, JobPage)
        self.assertEqual([job.request_id for job in first.jobs], [DENIED_ID])
        self.assertIsNotNone(first.next_cursor)

        second = self.service.handle(ListJobsRequest(limit=1, cursor=first.next_cursor))
        self.assertEqual([job.request_id for job in second.jobs], [REQUEST_ID])
        self.assertIsNone(second.next_cursor)
        completed = self.service.handle(
            ListJobsRequest(states=(RequestState.LOCAL_SPOOL_VERIFIED,))
        )
        self.assertEqual([job.request_id for job in completed.jobs], [REQUEST_ID])
        self.assertTrue(completed.jobs[0].verified_result_available)

    def test_verified_result_read_rechecks_manifest_and_returns_bounded_bytes(self):
        with mock.patch.object(
            self.spool,
            "load",
            side_effect=AssertionError("full spool load must not be used"),
        ):
            chunk = self.service.handle(
                ReadVerifiedResultRequest(
                    REQUEST_ID,
                    ResultStream.STDOUT,
                    offset=1,
                    limit=4,
                )
            )
        self.assertEqual(chunk.data, self.stdout[1:5])
        self.assertEqual(chunk.next_offset, 5)
        self.assertFalse(chunk.eof)
        self.assertEqual(chunk.total_size, len(self.stdout))
        self.assertEqual(chunk.sha256, hashlib.sha256(self.stdout).hexdigest())
        self.assertEqual(chunk.manifest_sha256, self.completed.local_spool_manifest_sha256)

    def test_unverified_mismatch_and_corrupt_spools_fail_closed(self):
        with self.assertRaises(BrokerControlError) as denied:
            self.service.handle(ReadVerifiedResultRequest(DENIED_ID, "stdout"))
        self.assertEqual(denied.exception.code, "result_unverified")

        self.store.write(
            replace(
                self.completed,
                generation=2,
                local_spool_manifest_sha256="0" * 64,
            )
        )
        with self.assertRaises(BrokerControlError) as mismatch:
            self.service.handle(ReadVerifiedResultRequest(REQUEST_ID, "stdout"))
        self.assertEqual(mismatch.exception.code, "result_mismatch")

        self.store.write(replace(self.completed, generation=3))
        stream_path = self.spool.path / REQUEST_ID / STDOUT_NAME
        stream_path.write_bytes(b"X" + self.stdout[1:])
        os.chmod(stream_path, 0o600)
        with self.assertRaises(BrokerControlError) as corrupt:
            self.service.handle(ReadVerifiedResultRequest(REQUEST_ID, "stdout"))
        self.assertEqual(corrupt.exception.code, "result_corrupt")


class BrokerControlIntegrationTests(BrokerControlServiceTests):
    def setUp(self):
        super().setUp()
        self.socket_path = Path(self.temporary.name) / "broker.sock"
        listener = create_broker_socket(self.socket_path)
        self.approval_calls = []
        self.execution_calls = []

        def approver(request_id, request):
            self.approval_calls.append((request_id, request))
            return ApprovalDecision.DENIED

        def executor(request_id, request):
            self.execution_calls.append((request_id, request))
            raise AssertionError("control request entered execution")

        self.server = BrokerServer(
            listener,
            allowed_machines=("machine-a",),
            approver=approver,
            executor=executor,
            request_timeout_seconds=0.5,
            send_timeout_seconds=0.5,
            control_service=self.service,
        )
        self.server.start()
        self.addCleanup(self.server.stop)

    def test_typed_clients_round_trip_through_broker_without_approval(self):
        machines = list_machines(self.socket_path)
        self.assertEqual([machine.alias for machine in machines], ["machine-a"])

        page = list_jobs(
            self.socket_path,
            states=(RequestState.LOCAL_SPOOL_VERIFIED,),
        )
        self.assertEqual([job.request_id for job in page.jobs], [REQUEST_ID])

        chunk = read_verified_result(
            self.socket_path,
            request_id=REQUEST_ID,
            stream="stderr",
            limit=3,
        )
        self.assertEqual(chunk.data, self.stderr[:3])
        self.assertEqual(self.approval_calls, [])
        self.assertEqual(self.execution_calls, [])


if __name__ == "__main__":
    unittest.main()
