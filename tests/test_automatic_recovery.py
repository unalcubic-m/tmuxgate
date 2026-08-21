from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from tmuxgate.approval import ApprovalDecision
from tmuxgate.automatic_recovery import AutomaticRecoveryCoordinator
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.remote_job import RemoteJobBusyError
from tmuxgate.scheduler import RequestState
from tmuxgate.spool import ResultSpool
from tmuxgate.state import (
    DurableJobRecord,
    DurableStateStore,
    RemotePhase,
    new_approved_job_record,
    recover_startup,
)
from test_connection_plan import build_plan
from test_remote_job import FakeRemoteBackend


REQUEST_ID = "1234567890abcdef1234567890abcdef"
LEGACY_INCIDENT_ID = "9bb20b44e6d4c263befeb6ff4cfee87d"


class RecoveryViewer:
    def __init__(self, backend, viewer):
        self.backend = backend
        self.viewer = viewer

    @property
    def attached(self):
        return self.viewer.attached

    def send_input(self, data):
        self.viewer.send_input(data)

    def send_ctrl_c(self):
        self.viewer.send_ctrl_c()

    def detach(self):
        self.viewer.detach()

    def terminate(self):
        self.viewer.detach()


class RecoveryBackend(FakeRemoteBackend):
    def attach(self, identity):
        return RecoveryViewer(self, super().attach(identity))

    def discard_unstarted(self, identity):
        if self.gate or self.running or self.result is not None or self.session:
            raise RemoteJobBusyError("not proven unstarted")
        self.staged = False
        self.events.append("discard-unstarted")


class FakeLease:
    def __init__(self):
        self.transport = SimpleNamespace(machine_name="app-server")
        self.released = False

    def release(self):
        self.released = True


class FakePool:
    def __init__(self):
        self.leases = []
        self.authorizations = []

    def acquire(self, authorization, endpoint):
        self.authorizations.append((authorization, endpoint))
        lease = FakeLease()
        self.leases.append(lease)
        return lease


class AutomaticRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.state = DurableStateStore(root / "state")
        self.spool = ResultSpool(root / "state")
        self.pool = FakePool()
        self.backend = RecoveryBackend()
        self.coordinator = AutomaticRecoveryCoordinator(
            state=self.state,
            spool=self.spool,
            transports=self.pool,
            backend_factory=lambda _transport: self.backend,
        )
        self.request = RequestSpec(
            "app-server", ExecutionMode.ARGV, "/", argv=("true",)
        )
        self.plan = build_plan()
        self.endpoint = self.plan.selected.resolved

    def tearDown(self):
        self.coordinator.close()
        self.spool.close()
        self.state.close()
        self.temporary.cleanup()

    def approved(self):
        return self.state.write(
            new_approved_job_record(REQUEST_ID, self.request, self.plan)
        )

    def legacy_record(self):
        return DurableJobRecord(
            request_id=LEGACY_INCIDENT_ID,
            generation=1,
            machine_alias="app-server",
            client_request_sha256="a" * 64,
            connection_plan_sha256="b" * 64,
            endpoint_id="home-lan",
            resolved_user="operator",
            resolved_hostname="example.invalid",
            resolved_port=22,
            host_key_alias="tmuxgate-app-server",
            remote_job_path=f"~/.cache/tmuxgate/jobs/{LEGACY_INCIDENT_ID}",
            remote_tmux_session=f"tmuxgate-{LEGACY_INCIDENT_ID[:12]}",
            decision=ApprovalDecision.APPROVED,
            state=RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            created_at="2026-08-21T00:00:00Z",
            updated_at="2026-08-21T00:01:00Z",
            start_time="2026-08-21T00:00:30Z",
            remote_mutation_started=True,
            failure_detail="remote staging failed with status 255",
            resolved_identity_sha256="c" * 64,
            remote_phase=RemotePhase.LEGACY_UNCERTAIN,
            record_version=3,
        )

    def at_phase(self, phase):
        record = self.approved()
        if phase is RemotePhase.NOT_ATTEMPTED:
            return record
        record = self.state.mark_remote_connection_attempted(record)
        if phase is RemotePhase.CONNECTION_ATTEMPTED:
            return record
        record, _ = self.state.request_remote_staging(record)
        if phase is RemotePhase.STAGING_REQUESTED:
            return record
        record = self.state.mark_remote_staging_verified(record)
        if phase is RemotePhase.STAGING_VERIFIED:
            return record
        record = self.state.request_remote_wrapper(record)
        if phase is RemotePhase.REMOTE_WRAPPER_REQUESTED:
            return record
        record = self.state.mark_remote_wrapper_created(record)
        if phase is RemotePhase.REMOTE_WRAPPER_CREATED:
            return record
        record = self.state.mark_user_command_started(record)
        return record

    def test_crash_before_and_after_each_pre_wrapper_marker_is_safe(self):
        for phase in (
            RemotePhase.NOT_ATTEMPTED,
            RemotePhase.CONNECTION_ATTEMPTED,
            RemotePhase.STAGING_REQUESTED,
            RemotePhase.STAGING_VERIFIED,
        ):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                store = DurableStateStore(Path(directory) / "state")
                try:
                    record = store.write(
                        new_approved_job_record(REQUEST_ID, self.request, self.plan)
                    )
                    if phase is not RemotePhase.NOT_ATTEMPTED:
                        record = store.mark_remote_connection_attempted(record)
                    if phase in {
                        RemotePhase.STAGING_REQUESTED,
                        RemotePhase.STAGING_VERIFIED,
                    }:
                        record, _ = store.request_remote_staging(record)
                    if phase is RemotePhase.STAGING_VERIFIED:
                        record = store.mark_remote_staging_verified(record)
                    report = recover_startup(store)
                    recovered = store.load(REQUEST_ID)
                    self.assertEqual(recovered.state, RequestState.FAILED_PRE_REMOTE)
                    self.assertFalse(recovered.remote_mutation_started)
                    self.assertFalse(report.blocking_request_ids)
                finally:
                    store.close()

    def test_crash_around_wrapper_markers_is_reconciled_not_guessed(self):
        for phase in (
            RemotePhase.REMOTE_WRAPPER_REQUESTED,
            RemotePhase.REMOTE_WRAPPER_CREATED,
        ):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                store = DurableStateStore(Path(directory) / "state")
                try:
                    record = store.write(
                        new_approved_job_record(REQUEST_ID, self.request, self.plan)
                    )
                    record = store.mark_remote_connection_attempted(record)
                    record, _ = store.request_remote_staging(record)
                    record = store.mark_remote_staging_verified(record)
                    record = store.request_remote_wrapper(record)
                    if phase is RemotePhase.REMOTE_WRAPPER_CREATED:
                        record = store.mark_remote_wrapper_created(record)
                    report = recover_startup(store)
                    recovered = store.load(REQUEST_ID)
                    self.assertEqual(
                        recovered.state,
                        RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
                    )
                    self.assertIn(REQUEST_ID, report.automatic_recovery_request_ids)
                    self.assertFalse(recovered.remote_mutation_started)
                finally:
                    store.close()

    def test_proven_unstarted_wrapper_is_discarded_and_terminalized(self):
        record = self.at_phase(RemotePhase.REMOTE_WRAPPER_REQUESTED)
        record = self.state.mark_recovery_required(record, detail="broker crash")

        outcome = self.coordinator.reconcile(record, self.endpoint)

        self.assertEqual(outcome.status, "failed-pre-remote")
        final = self.state.load(REQUEST_ID)
        self.assertEqual(final.state, RequestState.FAILED_PRE_REMOTE)
        self.assertFalse(final.remote_mutation_started)
        self.assertEqual(self.backend.events, ["discard-unstarted"])

    def test_previously_verified_wrapper_that_never_started_is_safe(self):
        record = self.at_phase(RemotePhase.REMOTE_WRAPPER_CREATED)
        record = self.state.mark_recovery_required(record, detail="broker crash")
        self.backend.staged = True

        outcome = self.coordinator.reconcile(record, self.endpoint)

        self.assertEqual(outcome.status, "failed-pre-remote")
        self.assertEqual(
            self.state.load(REQUEST_ID).state, RequestState.FAILED_PRE_REMOTE
        )
        self.assertEqual(self.backend.events, ["discard-unstarted"])

    def test_gate_release_observation_closes_both_missing_marker_windows(self):
        record = self.at_phase(RemotePhase.REMOTE_WRAPPER_REQUESTED)
        record = self.state.mark_recovery_required(
            record, detail="crash immediately after gate release"
        )
        self.backend.staged = True
        self.backend.session = True
        self.backend.gate = True
        self.backend.running = True

        outcome = self.coordinator.reconcile(record, self.endpoint)

        self.assertEqual(outcome.status, "running")
        current = self.state.load(REQUEST_ID)
        self.assertEqual(current.remote_phase, RemotePhase.USER_COMMAND_STARTED)
        self.assertTrue(current.remote_mutation_started)
        self.assertEqual(self.backend.events, ["attach"])

    def test_gated_wrapper_is_adopted_started_and_repeated_recovery_is_idempotent(self):
        record = self.at_phase(RemotePhase.REMOTE_WRAPPER_CREATED)
        record = self.state.mark_recovery_required(record, detail="dashboard restarted")
        self.backend.staged = True
        self.backend.session = True

        first = self.coordinator.reconcile(record, self.endpoint)
        second = self.coordinator.reconcile(
            self.state.load(REQUEST_ID), self.endpoint
        )

        self.assertEqual(first.status, "running")
        self.assertEqual(second.status, "running")
        current = self.state.load(REQUEST_ID)
        self.assertEqual(current.remote_phase, RemotePhase.USER_COMMAND_STARTED)
        self.assertTrue(current.remote_mutation_started)
        self.assertEqual(self.backend.events.count("release-gate"), 1)

    def test_running_detached_session_is_reattached_automatically(self):
        record = self.at_phase(RemotePhase.USER_COMMAND_STARTED)
        self.backend.staged = True
        self.backend.session = True
        self.backend.gate = True
        self.backend.running = True

        outcome = self.coordinator.reconcile(record, self.endpoint)

        self.assertEqual(outcome.status, "running")
        self.assertEqual(self.backend.attached, 1)
        self.assertEqual(self.backend.events, ["attach"])

    def test_complete_spool_with_detached_viewer_is_collected_and_cleaned(self):
        record = self.at_phase(RemotePhase.USER_COMMAND_STARTED)
        self.backend.staged = True
        self.backend.session = True
        self.backend.gate = True
        self.backend.complete(b"stdout\n", b"stderr\n", 23)

        outcome = self.coordinator.reconcile(record, self.endpoint)

        self.assertEqual(outcome.status, "recovered")
        final = self.state.load(REQUEST_ID)
        self.assertEqual(final.state, RequestState.RESULT_DELIVERING)
        self.assertEqual(final.remote_phase, RemotePhase.CLEANUP_COMPLETED)
        self.assertEqual(final.exit_status, 23)
        spooled = self.spool.load(REQUEST_ID)
        self.assertEqual((spooled.stdout, spooled.stderr), (b"stdout\n", b"stderr\n"))
        self.assertEqual(self.backend.events, ["collect", "cleanup"])

    def test_missing_spool_after_start_remains_fail_closed_with_one_action(self):
        record = self.at_phase(RemotePhase.USER_COMMAND_STARTED)
        self.backend.gate = True

        first = self.coordinator.reconcile(record, self.endpoint)
        generation = self.state.load(REQUEST_ID).generation
        second = self.coordinator.reconcile(
            self.state.load(REQUEST_ID), self.endpoint
        )

        self.assertTrue(first.manual_action_required)
        self.assertTrue(second.manual_action_required)
        current = self.state.load(REQUEST_ID)
        self.assertEqual(current.state, RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING)
        self.assertEqual(current.generation, generation)
        self.assertIsNone(current.exit_status)
        self.assertFalse(current.local_spool_verified)
        self.assertNotIn("cleanup", self.backend.events)

    def test_local_spool_survives_reboot_and_cleanup_retries_idempotently(self):
        record = self.at_phase(RemotePhase.USER_COMMAND_STARTED)
        record = self.state.mark_completion_proven(record, exit_status=7)
        record = self.state.mark_viewer_detached(record)
        record = self.state.mark_terminal_restored(record)
        spooled = self.spool.store(REQUEST_ID, b"out", b"err", 7)
        record = self.state.mark_local_spool_verified(
            record, manifest_sha256=spooled.manifest_payload_sha256
        )

        outcome = self.coordinator.reconcile(record, self.endpoint)
        repeated = self.coordinator.reconcile(
            self.state.load(REQUEST_ID), self.endpoint
        )

        self.assertEqual(outcome.status, "recovered")
        self.assertEqual(repeated.status, "recovered")
        self.assertEqual(
            self.state.load(REQUEST_ID).remote_phase,
            RemotePhase.CLEANUP_COMPLETED,
        )

    def test_cleanup_completed_marker_restarts_without_remote_contact(self):
        record = self.at_phase(RemotePhase.USER_COMMAND_STARTED)
        record = self.state.mark_completion_proven(record, exit_status=0)
        record = self.state.mark_viewer_detached(record)
        record = self.state.mark_terminal_restored(record)
        spooled = self.spool.store(REQUEST_ID, b"", b"", 0)
        record = self.state.mark_local_spool_verified(
            record, manifest_sha256=spooled.manifest_payload_sha256
        )
        record = self.state.mark_remote_cleanup_completed(record)

        first = self.coordinator.reconcile(record, self.endpoint)
        second = self.coordinator.reconcile(
            self.state.load(REQUEST_ID), self.endpoint
        )

        self.assertEqual((first.status, second.status), ("recovered", "recovered"))
        self.assertFalse(self.pool.authorizations)
        self.assertEqual(
            self.state.load(REQUEST_ID).state, RequestState.RESULT_DELIVERING
        )

    def test_legacy_incident_never_infers_command_absence(self):
        legacy = self.legacy_record()
        self.state.write(legacy)

        outcome = self.coordinator.reconcile(legacy, self.endpoint)

        self.assertTrue(outcome.manual_action_required)
        unchanged = self.state.load(LEGACY_INCIDENT_ID)
        self.assertEqual(unchanged.generation, 2)
        self.assertIn("missing artifacts do not prove", unchanged.failure_detail)
        self.assertIsNone(unchanged.exit_status)
        self.assertEqual(len(self.pool.authorizations), 1)
        self.assertNotIn("cleanup", self.backend.events)

    def test_legacy_positive_running_evidence_is_upgraded_and_reattached(self):
        legacy = self.legacy_record()
        self.state.write(legacy)
        self.backend.staged = True
        self.backend.session = True
        self.backend.gate = True
        self.backend.running = True

        outcome = self.coordinator.reconcile(legacy, self.endpoint)

        self.assertEqual(outcome.status, "running")
        upgraded = self.state.load(LEGACY_INCIDENT_ID)
        self.assertEqual(upgraded.record_version, 4)
        self.assertEqual(upgraded.remote_phase, RemotePhase.USER_COMMAND_STARTED)
        self.assertTrue(upgraded.remote_mutation_started)
        self.assertEqual(self.backend.events, ["attach"])

    def test_single_uncertainty_acknowledgement_claims_nothing_remote(self):
        record = self.at_phase(RemotePhase.USER_COMMAND_STARTED)
        record = self.state.mark_recovery_required(
            record,
            detail=(
                "command-start evidence exists, but the exact remote job has "
                "neither a complete authenticated result nor authoritative "
                "termination evidence"
            ),
        )

        abandoned = self.state.mark_abandoned_after_operator_acknowledged_uncertainty(
            record
        )

        self.assertEqual(
            abandoned.state,
            RequestState.ABANDONED_AFTER_OPERATOR_ACKNOWLEDGED_UNCERTAINTY,
        )
        self.assertIsNone(abandoned.exit_status)
        self.assertFalse(abandoned.local_spool_verified)
        self.assertEqual(self.backend.events, [])


if __name__ == "__main__":
    unittest.main()
