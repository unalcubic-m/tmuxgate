from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from tmuxgate.scheduler import ApprovalDecision, RequestState
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.state import (
    DurableJobRecord,
    DurableStateStore,
    StateConflictError,
    StateCorruptionError,
    new_approved_job_record,
    recover_startup,
)
from test_connection_plan import build_plan


REQUEST_ID = "89abcdef0123456789abcdef01234567"
SECOND_ID = "0123456789abcdef0123456789abcdef"
CREATED = "2026-07-19T12:00:00.000000Z"


def record(
    request_id=REQUEST_ID,
    *,
    generation=1,
    state=RequestState.APPROVED_PRE_REMOTE,
    remote_mutation_started=False,
    start_time=None,
    decision=ApprovalDecision.APPROVED,
    resolved=True,
    job_identity=True,
    completion_time=None,
    exit_status=None,
    local_spool_verified=False,
    local_spool_manifest_sha256=None,
    viewer_detached=False,
    terminal_restored=False,
    failure_detail=None,
):
    return DurableJobRecord(
        request_id=request_id,
        generation=generation,
        machine_alias="app-server",
        client_request_sha256="a" * 64,
        connection_plan_sha256="b" * 64 if resolved else None,
        endpoint_id="home-lan" if resolved else None,
        resolved_user="operator" if resolved else None,
        resolved_hostname="192.0.2.20" if resolved else None,
        resolved_port=22 if resolved else None,
        host_key_alias="tmuxgate-app-server" if resolved else None,
        remote_job_path=(
            f"~/.cache/tmuxgate/jobs/{request_id}" if job_identity else None
        ),
        remote_tmux_session=(f"tmuxgate-{request_id[:12]}" if job_identity else None),
        decision=decision,
        state=state,
        created_at=CREATED,
        updated_at=CREATED,
        start_time=start_time,
        completion_time=completion_time,
        exit_status=exit_status,
        remote_mutation_started=remote_mutation_started,
        local_spool_verified=local_spool_verified,
        local_spool_manifest_sha256=local_spool_manifest_sha256,
        viewer_detached=viewer_detached,
        terminal_restored=terminal_restored,
        failure_detail=failure_detail,
    )


class DurableStateTests(unittest.TestCase):
    def make_store(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name) / "state"
        store = DurableStateStore(root)
        self.addCleanup(store.close)
        self.addCleanup(temporary.cleanup)
        return store

    def test_atomic_record_is_owner_only_checksummed_and_round_trips(self):
        store = self.make_store()
        original = record()
        store.write(original)

        path = store.jobs_dir / f"{REQUEST_ID}.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        envelope = json.loads(path.read_text(encoding="ascii"))
        self.assertEqual(set(envelope), {"payload", "sha256"})
        self.assertEqual(store.load(REQUEST_ID), original)

    def test_generation_must_be_created_at_one_and_increment_exactly(self):
        store = self.make_store()
        with self.assertRaises(StateConflictError):
            store.write(record(generation=2))
        first = store.write(record())
        with self.assertRaises(StateConflictError):
            store.write(replace(first, generation=3))
        second = store.write(replace(first, generation=2, updated_at="2026-07-19T12:01:00Z"))
        self.assertEqual(store.load(REQUEST_ID), second)

    def test_failed_atomic_replace_preserves_previous_record(self):
        store = self.make_store()
        first = store.write(record())
        second = replace(first, generation=2, updated_at="2026-07-19T12:01:00Z")
        with patch("tmuxgate.state.os.replace", side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                store.write(second)
        self.assertEqual(store.load(REQUEST_ID), first)
        self.assertEqual(
            sorted(item.name for item in store.jobs_dir.iterdir()),
            [f"{REQUEST_ID}.json"],
        )

    def test_checksum_unknown_fields_duplicate_keys_and_bad_json_fail_closed(self):
        store = self.make_store()
        store.write(record())
        path = store.jobs_dir / f"{REQUEST_ID}.json"
        original = path.read_bytes()

        envelope = json.loads(original)
        envelope["sha256"] = "0" * 64
        path.write_text(json.dumps(envelope), encoding="ascii")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(StateCorruptionError, "checksum"):
            store.load(REQUEST_ID)

        path.write_bytes(b'{"payload":{},"payload":{},"sha256":"x"}')
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(StateCorruptionError, "duplicate"):
            store.load(REQUEST_ID)

        path.write_bytes(b"not json")
        os.chmod(path, 0o600)
        with self.assertRaises(StateCorruptionError):
            store.load(REQUEST_ID)

    def test_symlink_or_permissive_state_file_is_rejected(self):
        store = self.make_store()
        outside = store.jobs_dir.parent / "outside"
        outside.write_text("do not read", encoding="ascii")
        path = store.jobs_dir / f"{REQUEST_ID}.json"
        path.symlink_to(outside)
        with self.assertRaises(StateCorruptionError):
            store.load(REQUEST_ID)
        path.unlink()
        store.write(record())
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(StateCorruptionError, "metadata"):
            store.load(REQUEST_ID)

    def test_load_all_removes_only_valid_stale_atomic_temporaries(self):
        store = self.make_store()
        store.write(record())
        stale = store.jobs_dir / f".{REQUEST_ID}.{'c' * 32}.tmp"
        stale.write_bytes(b"partial")
        os.chmod(stale, 0o600)
        self.assertEqual(store.load_all(), (record(),))
        self.assertFalse(stale.exists())

        unexpected = store.jobs_dir / "notes.txt"
        unexpected.write_text("unexpected", encoding="ascii")
        os.chmod(unexpected, 0o600)
        with self.assertRaisesRegex(StateCorruptionError, "unexpected"):
            store.load_all()

    def test_read_only_store_ignores_but_never_unlinks_atomic_temporaries(self):
        writer = self.make_store()
        writer.write(record())
        in_progress = writer.jobs_dir / f".{REQUEST_ID}.{'d' * 32}.tmp"
        in_progress.write_bytes(b"write still in progress")
        os.chmod(in_progress, 0o600)
        reader = DurableStateStore(
            writer.jobs_dir.parent,
            cleanup_stale_temporaries=False,
        )
        self.addCleanup(reader.close)

        self.assertEqual(reader.load_all(), (record(),))
        self.assertTrue(in_progress.exists())

    def test_remote_start_permit_is_returned_only_after_durable_boundary(self):
        store = self.make_store()
        approved = store.write(record())
        armed, permit = store.arm_remote_start(
            approved, now=lambda: "2026-07-19T12:02:00.000000Z"
        )
        self.assertEqual(armed.state, RequestState.REMOTE_MAY_BE_RUNNING)
        self.assertTrue(armed.remote_mutation_started)
        self.assertEqual(store.load(REQUEST_ID), armed)
        self.assertEqual(permit.request_id, REQUEST_ID)
        self.assertEqual(permit.durable_generation, 2)
        self.assertEqual(len(permit.durable_payload_sha256), 64)

    def test_bound_approval_plan_creates_predictable_pre_mutation_record(self):
        store = self.make_store()
        request = RequestSpec(
            "app-server", ExecutionMode.ARGV, "/", argv=("true",)
        )
        plan = build_plan()
        approved = new_approved_job_record(
            REQUEST_ID,
            request,
            plan,
            now=lambda: CREATED,
        )
        store.write(approved)
        self.assertEqual(approved.connection_plan_sha256, plan.plan_sha256)
        self.assertEqual(approved.endpoint_id, "home-lan")
        self.assertEqual(
            approved.remote_job_path, f"~/.cache/tmuxgate/jobs/{REQUEST_ID}"
        )
        self.assertFalse(approved.remote_mutation_started)

        armed, _permit = store.arm_remote_start(
            approved, now=lambda: "2026-07-19T12:02:00Z"
        )
        self.assertTrue(armed.remote_mutation_started)

    def test_remote_start_cannot_be_armed_without_approval_plan_and_job_identity(self):
        store = self.make_store()
        queued = record(
            state=RequestState.QUEUED,
            decision=None,
            resolved=False,
            job_identity=False,
        )
        store.write(queued)
        with self.assertRaises(StateConflictError):
            store.arm_remote_start(queued)

    def test_record_invariants_reject_unsafe_job_path_and_invented_completion(self):
        with self.assertRaisesRegex(StateCorruptionError, "guarded job parent"):
            replace(record(), remote_job_path="/tmp/attacker")
        with self.assertRaisesRegex(StateCorruptionError, "completion_time"):
            record(exit_status=7)
        with self.assertRaisesRegex(StateCorruptionError, "approved decision"):
            record(decision=None)
        with self.assertRaisesRegex(StateCorruptionError, "mutation boundary"):
            record(state=RequestState.REMOTE_MAY_BE_RUNNING)


class StartupRecoveryTests(unittest.TestCase):
    def make_store(self):
        temporary = tempfile.TemporaryDirectory()
        store = DurableStateStore(Path(temporary.name) / "state")
        self.addCleanup(store.close)
        self.addCleanup(temporary.cleanup)
        return store

    def test_pre_remote_restart_is_atomically_terminalized_and_does_not_block(self):
        store = self.make_store()
        queued = record(
            state=RequestState.QUEUED,
            decision=None,
            resolved=False,
            job_identity=False,
        )
        store.write(queued)
        report = recover_startup(
            store, now=lambda: "2026-07-19T12:03:00.000000Z"
        )
        recovered = store.load(REQUEST_ID)
        self.assertEqual(recovered.state, RequestState.CANCELLED_BEFORE_APPROVAL)
        self.assertEqual(recovered.generation, 2)
        self.assertEqual(report.interrupted_pre_remote_ids, (REQUEST_ID,))
        self.assertTrue(report.safe_to_accept_new_approvals)

    def test_approved_but_proven_pre_remote_restart_becomes_failed_pre_remote(self):
        store = self.make_store()
        store.write(record())
        report = recover_startup(store, now=lambda: "2026-07-19T12:03:00Z")
        recovered = store.load(REQUEST_ID)
        self.assertEqual(recovered.state, RequestState.FAILED_PRE_REMOTE)
        self.assertEqual(recovered.decision, ApprovalDecision.APPROVED)
        self.assertFalse(report.blocking_request_ids)

    def test_possibly_running_job_blocks_all_new_approvals(self):
        store = self.make_store()
        store.write(
            record(
                state=RequestState.REMOTE_MAY_BE_RUNNING,
                remote_mutation_started=True,
                start_time="2026-07-19T12:02:00Z",
            )
        )
        report = recover_startup(store)
        self.assertEqual(report.blocking_request_ids, (REQUEST_ID,))
        self.assertFalse(report.safe_to_accept_new_approvals)


class DurableLifecycleTransitionTests(unittest.TestCase):
    def make_store(self):
        temporary = tempfile.TemporaryDirectory()
        store = DurableStateStore(Path(temporary.name) / "state")
        self.addCleanup(store.close)
        self.addCleanup(temporary.cleanup)
        return store

    def armed(self, store):
        approved = store.write(record())
        armed, _ = store.arm_remote_start(
            approved,
            now=lambda: "2026-07-19T12:01:00.000000Z",
        )
        return armed

    def test_every_completion_gate_is_fsynced_before_done(self):
        store = self.make_store()
        current = self.armed(store)
        current = store.mark_completion_proven(
            current,
            exit_status=7,
            now=lambda: "2026-07-19T12:02:00.000000Z",
        )
        self.assertEqual(current.state, RequestState.COMPLETION_PROVEN)
        self.assertEqual(current.exit_status, 7)
        self.assertEqual(store.load(REQUEST_ID), current)

        current = store.mark_viewer_detached(
            current,
            now=lambda: "2026-07-19T12:03:00.000000Z",
        )
        current = store.mark_terminal_restored(
            current,
            now=lambda: "2026-07-19T12:04:00.000000Z",
        )
        current = store.mark_local_spool_verified(
            current,
            manifest_sha256="c" * 64,
            now=lambda: "2026-07-19T12:05:00.000000Z",
        )
        self.assertTrue(current.local_spool_verified)
        self.assertEqual(current.local_spool_manifest_sha256, "c" * 64)

        current = store.release_lease(
            current,
            now=lambda: "2026-07-19T12:06:00.000000Z",
        )
        self.assertEqual(current.state, RequestState.LEASE_RELEASED)
        current = store.begin_result_delivery(
            current,
            now=lambda: "2026-07-19T12:07:00.000000Z",
        )
        self.assertEqual(current.state, RequestState.RESULT_DELIVERING)
        current = store.mark_done(
            current,
            now=lambda: "2026-07-19T12:08:00.000000Z",
        )
        self.assertEqual(current.state, RequestState.DONE)
        self.assertEqual(current.generation, 9)
        self.assertEqual(store.load(REQUEST_ID), current)
        self.assertTrue(recover_startup(store).safe_to_accept_new_approvals)

    def test_lease_release_refuses_each_missing_gate(self):
        store = self.make_store()
        current = self.armed(store)
        current = store.mark_completion_proven(current, exit_status=0)
        with self.assertRaises(StateConflictError):
            store.release_lease(current)
        current = store.mark_viewer_detached(current)
        with self.assertRaises(StateConflictError):
            store.release_lease(current)
        current = store.mark_local_spool_verified(
            current,
            manifest_sha256="d" * 64,
        )
        with self.assertRaises(StateConflictError):
            store.release_lease(current)
        current = store.mark_terminal_restored(current)
        released = store.release_lease(current)
        self.assertEqual(released.state, RequestState.LEASE_RELEASED)

    def test_recovery_is_durable_and_can_be_reconciled_to_real_completion(self):
        store = self.make_store()
        current = self.armed(store)
        current = store.mark_recovery_required(
            current,
            detail="viewer transport disappeared",
        )
        self.assertEqual(
            current.state,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        )
        self.assertIn("viewer transport", current.failure_detail)
        self.assertFalse(recover_startup(store).safe_to_accept_new_approvals)
        current = store.mark_completion_proven(current, exit_status=130)
        self.assertEqual(current.exit_status, 130)
        self.assertIsNone(current.failure_detail)

    def test_operator_confirmed_reboot_abandons_without_inventing_completion(self):
        store = self.make_store()
        current = self.armed(store)
        current = store.mark_recovery_required(
            current,
            detail="viewer transport disappeared",
        )
        abandoned = store.mark_abandoned_after_operator_confirmed_reboot(
            current,
            now=lambda: "2026-07-19T12:09:00.000000Z",
        )

        self.assertEqual(
            abandoned.state,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
        )
        self.assertEqual(abandoned.generation, 4)
        self.assertEqual(abandoned.updated_at, "2026-07-19T12:09:00.000000Z")
        self.assertIn("viewer transport disappeared", abandoned.failure_detail)
        self.assertIn("full reboot", abandoned.failure_detail)
        self.assertIsNone(abandoned.completion_time)
        self.assertIsNone(abandoned.exit_status)
        self.assertFalse(abandoned.local_spool_verified)
        self.assertIsNone(abandoned.local_spool_manifest_sha256)
        self.assertFalse(abandoned.viewer_detached)
        self.assertFalse(abandoned.terminal_restored)
        self.assertEqual(store.load(REQUEST_ID), abandoned)
        self.assertTrue(recover_startup(store).safe_to_accept_new_approvals)

    def test_operator_confirmed_reboot_abandonment_refuses_wrong_or_stale_state(self):
        store = self.make_store()
        armed = self.armed(store)
        with self.assertRaises(StateConflictError):
            store.mark_abandoned_after_operator_confirmed_reboot(armed)

        recovery = store.mark_recovery_required(armed, detail="uncertain")
        store.mark_abandoned_after_operator_confirmed_reboot(recovery)
        with self.assertRaises(StateConflictError):
            store.mark_abandoned_after_operator_confirmed_reboot(recovery)

    def test_operator_confirmed_dead_pane_abandons_without_inventing_completion(self):
        store = self.make_store()
        current = self.armed(store)
        current = store.mark_recovery_required(
            current,
            detail="observer channel timed out",
        )
        abandoned = store.mark_abandoned_after_operator_confirmed_dead_pane(
            current,
            now=lambda: "2026-07-29T00:10:00.000000Z",
        )

        self.assertEqual(
            abandoned.state,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
        )
        self.assertEqual(abandoned.generation, 4)
        self.assertIn("observer channel timed out", abandoned.failure_detail)
        self.assertIn("visibly dead", abandoned.failure_detail)
        self.assertIsNone(abandoned.completion_time)
        self.assertIsNone(abandoned.exit_status)
        self.assertFalse(abandoned.local_spool_verified)
        self.assertIsNone(abandoned.local_spool_manifest_sha256)
        self.assertFalse(abandoned.viewer_detached)
        self.assertFalse(abandoned.terminal_restored)
        self.assertEqual(store.load(REQUEST_ID), abandoned)
        self.assertTrue(recover_startup(store).safe_to_accept_new_approvals)

    def test_operator_confirmed_dead_pane_refuses_wrong_or_stale_state(self):
        store = self.make_store()
        armed = self.armed(store)
        with self.assertRaises(StateConflictError):
            store.mark_abandoned_after_operator_confirmed_dead_pane(armed)

        recovery = store.mark_recovery_required(armed, detail="uncertain")
        store.mark_abandoned_after_operator_confirmed_dead_pane(recovery)
        with self.assertRaises(StateConflictError):
            store.mark_abandoned_after_operator_confirmed_dead_pane(recovery)

    def test_canonical_proven_unstarted_evidence_releases_without_completion(self):
        store = self.make_store()
        current = self.armed(store)
        current = store.mark_recovery_required(
            current,
            detail="remote create timed out",
        )
        abandoned = store.mark_abandoned_after_proven_unstarted(
            current,
            evidence_request_id=SECOND_ID,
            evidence_manifest_sha256="e" * 64,
            now=lambda: "2026-07-29T08:30:00.000000Z",
        )

        self.assertEqual(
            abandoned.state,
            RequestState.ABANDONED_AFTER_PROVEN_UNSTARTED,
        )
        self.assertIn(SECOND_ID, abandoned.failure_detail)
        self.assertIn("e" * 64, abandoned.failure_detail)
        self.assertIn("gate_released=0", abandoned.failure_detail)
        self.assertIn("requested command never started", abandoned.failure_detail)
        self.assertIsNone(abandoned.completion_time)
        self.assertIsNone(abandoned.exit_status)
        self.assertFalse(abandoned.local_spool_verified)
        self.assertFalse(abandoned.viewer_detached)
        self.assertFalse(abandoned.terminal_restored)
        self.assertTrue(recover_startup(store).safe_to_accept_new_approvals)

        with self.assertRaises(StateConflictError):
            store.mark_abandoned_after_proven_unstarted(
                current,
                evidence_request_id=current.request_id,
                evidence_manifest_sha256="e" * 64,
            )

    def test_reboot_abandonment_record_rejects_completion_claims(self):
        valid = record(
            state=RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
            remote_mutation_started=True,
            start_time="2026-07-19T12:01:00Z",
            failure_detail="operator confirmed full reboot",
        )
        with self.assertRaisesRegex(StateCorruptionError, "completion gates"):
            replace(
                valid,
                completion_time="2026-07-19T12:02:00Z",
                exit_status=255,
            )
        with self.assertRaisesRegex(StateCorruptionError, "completion gates"):
            replace(valid, viewer_detached=True)
        with self.assertRaisesRegex(StateCorruptionError, "audit detail"):
            replace(valid, failure_detail=None)

        dead_pane = replace(
            valid,
            state=RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
            failure_detail="operator confirmed dedicated pane visibly dead",
        )
        with self.assertRaisesRegex(StateCorruptionError, "completion gates"):
            replace(dead_pane, viewer_detached=True)

    def test_proven_pre_remote_failure_never_claims_mutation(self):
        store = self.make_store()
        approved = store.write(record())
        failed = store.fail_pre_remote(
            approved,
            detail="SSH authentication was not established",
        )
        self.assertEqual(failed.state, RequestState.FAILED_PRE_REMOTE)
        self.assertFalse(failed.remote_mutation_started)
        self.assertIsNone(failed.start_time)
        self.assertTrue(recover_startup(store).safe_to_accept_new_approvals)

    def test_spool_boolean_and_digest_cannot_diverge(self):
        completed = record(
            state=RequestState.COMPLETION_PROVEN,
            remote_mutation_started=True,
            start_time="2026-07-19T12:01:00Z",
            completion_time="2026-07-19T12:02:00Z",
            exit_status=0,
            viewer_detached=True,
        )
        with self.assertRaisesRegex(StateCorruptionError, "must be paired"):
            replace(completed, local_spool_verified=True)
        with self.assertRaisesRegex(StateCorruptionError, "must be paired"):
            replace(completed, local_spool_manifest_sha256="e" * 64)

    def test_stale_record_cannot_advance_a_second_branch(self):
        store = self.make_store()
        armed = self.armed(store)
        recovery = store.mark_recovery_required(armed, detail="uncertain")
        with self.assertRaises(StateConflictError):
            store.mark_completion_proven(armed, exit_status=0)
        self.assertEqual(store.load(REQUEST_ID), recovery)

    def test_proven_completion_still_blocks_until_spool_viewer_and_terminal_gates(self):
        store = self.make_store()
        store.write(
            record(
                state=RequestState.COMPLETION_PROVEN,
                remote_mutation_started=True,
                start_time="2026-07-19T12:02:00Z",
                completion_time="2026-07-19T12:04:00Z",
                exit_status=7,
            )
        )
        report = recover_startup(store)
        self.assertFalse(report.safe_to_accept_new_approvals)

    def test_multiple_uncertain_records_are_all_reported_and_never_collapsed(self):
        store = self.make_store()
        for request_id in (REQUEST_ID, SECOND_ID):
            store.write(
                record(
                    request_id,
                    state=RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
                    remote_mutation_started=True,
                    start_time="2026-07-19T12:02:00Z",
                )
            )
        report = recover_startup(store)
        self.assertEqual(set(report.blocking_request_ids), {REQUEST_ID, SECOND_ID})
        self.assertFalse(report.safe_to_accept_new_approvals)


if __name__ == "__main__":
    unittest.main()
