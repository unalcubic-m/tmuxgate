from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from tmuxgate.models import DisconnectPolicy, ExecutionMode, RequestSpec
from tmuxgate.reboot_recovery import BootIdProbeError
from tmuxgate.recovery_coordinator import (
    ExpectedRebootRecoveryCoordinator,
    RecoveryCoordinatorError,
)
from tmuxgate.result import ExecutionResult, ResultCode, TransportStatus
from tmuxgate.scheduler import RequestState
from tmuxgate.state import (
    DurableStateStore,
    StateCorruptionError,
    new_approved_job_record,
    recover_startup,
)
from tmuxgate.transport import TransportBusyError, TransportError
from test_connection_plan import build_plan


REQUEST_ID = "1" * 32
OTHER_REQUEST_ID = "2" * 32
PRE_BOOT_ID = "11111111-2222-3333-4444-555555555555"
POST_BOOT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class FakeClock:
    def __init__(self):
        self.value = datetime(2026, 8, 20, tzinfo=timezone.utc)

    def now(self):
        return self.value.isoformat(timespec="microseconds").replace("+00:00", "Z")

    def sleep(self, seconds):
        self.value += timedelta(seconds=seconds)


class FakeProbe:
    def __init__(self, post_results=()):
        self.post_results = list(post_results)
        self.pre_calls = []
        self.post_calls = []

    def capture_pre_reboot(self, transport):
        self.pre_calls.append(transport)
        return PRE_BOOT_ID

    def probe_after_disconnect(self, endpoint):
        self.post_calls.append(endpoint)
        if not self.post_results:
            raise BootIdProbeError("reboot_probe_unavailable", "host unreachable")
        result = self.post_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


class FakePool:
    def __init__(self):
        self.pins = (REQUEST_ID,)
        self.reconcile_calls = []
        self.reconcile_error = None

    def pinned_request_ids_for_machine(self, machine_name):
        return self.pins

    def reconcile_verified_reboot(self, **kwargs):
        self.reconcile_calls.append(kwargs)
        if self.reconcile_error is not None:
            raise self.reconcile_error
        if self.pins:
            raise TransportBusyError("verified reboot transport still has command pins")
        return "unowned_control_reconciled"


class FakeLease:
    def __init__(self, pool, record, endpoint):
        self.pool = pool
        self.request_id = record.request_id
        self.release_count = 0
        self.transport = type(
            "Transport",
            (),
            {
                "machine_name": record.machine_alias,
                "connection_plan_sha256": record.connection_plan_sha256,
                "identity_sha256": record.resolved_identity_sha256,
                "endpoint": endpoint,
                "control_path": Path("/tmp/tmuxgate-test-control.sock"),
            },
        )()

    def release(self):
        self.release_count += 1
        self.pool.pins = ()


class ExpectedRebootRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = DurableStateStore(Path(self.temporary.name) / "state")
        self.addCleanup(self.store.close)
        self.plan = build_plan()
        self.endpoint = self.plan.selected.resolved
        self.request = RequestSpec(
            "app-server",
            ExecutionMode.ARGV,
            "/tmp",
            argv=("/usr/bin/systemctl", "reboot"),
            purpose="reboot for maintenance",
            disconnect_policy=DisconnectPolicy.EXPECT_FULL_REBOOT,
        )

    def armed(self):
        record = new_approved_job_record(
            REQUEST_ID,
            self.request,
            self.plan,
            now=lambda: "2026-08-19T23:59:57.000000Z",
        )
        self.store.write(record)
        record = self.store.record_pre_reboot_boot_id(
            record,
            boot_id=PRE_BOOT_ID,
            now=lambda: "2026-08-19T23:59:58.000000Z",
        )
        record, _permit = self.store.arm_remote_start(
            record,
            now=lambda: "2026-08-19T23:59:59.000000Z",
        )
        return record

    def coordinator(self, probe, pool=None, clock=None, timeout=4):
        pool = FakePool() if pool is None else pool
        clock = FakeClock() if clock is None else clock
        return (
            ExpectedRebootRecoveryCoordinator(
                state=self.store,
                transports=pool,
                boot_id_probe=probe,
                identity_revalidator=lambda endpoint: endpoint,
                timeout_seconds=timeout,
                probe_interval_seconds=1,
                now=clock.now,
                sleep=clock.sleep,
            ),
            pool,
            clock,
        )

    def test_changed_boot_commits_exact_evidence_before_pin_cleanup(self):
        record = self.armed()
        coordinator, pool, _clock = self.coordinator(FakeProbe((POST_BOOT_ID,)))
        lease = FakeLease(pool, record, self.endpoint)

        result = coordinator.recover(record, self.endpoint, lease=lease)

        self.assertEqual(
            result.transport_status,
            TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT,
        )
        self.assertEqual(
            result.result_code, ResultCode.ABANDONED_AFTER_VERIFIED_REBOOT
        )
        self.assertEqual((result.stdout, result.stderr), (b"", b""))
        self.assertIsNone(result.remote_exit_status)
        terminal = self.store.load(REQUEST_ID)
        self.assertEqual(terminal.state, RequestState.ABANDONED_AFTER_VERIFIED_REBOOT)
        evidence = terminal.reboot_recovery
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.pre_boot_id, PRE_BOOT_ID)
        self.assertEqual(evidence.post_boot_id, POST_BOOT_ID)
        self.assertEqual(evidence.request_id, REQUEST_ID)
        self.assertEqual(evidence.endpoint_id, self.endpoint.endpoint_id)
        self.assertEqual(evidence.evidence_sha256, evidence.computed_evidence_sha256())
        self.assertEqual(lease.release_count, 1)
        self.assertEqual(pool.pins, ())
        self.assertEqual(len(pool.reconcile_calls), 1)
        self.assertIsNone(terminal.completion_time)
        self.assertIsNone(terminal.exit_status)
        self.assertFalse(terminal.local_spool_verified)

    def test_same_boot_is_not_reboot_and_can_resume_original_job(self):
        record = self.armed()
        coordinator, _pool, _clock = self.coordinator(FakeProbe((PRE_BOOT_ID,)))
        resumed_records = []

        def resume(same_boot_record, endpoint):
            resumed_records.append((same_boot_record, endpoint))
            completed = self.store.mark_completion_proven(
                same_boot_record,
                exit_status=7,
            )
            return ExecutionResult(
                completed.request_id,
                TransportStatus.COMPLETE,
                remote_exit_status=7,
            )

        result = coordinator.recover(
            record,
            self.endpoint,
            same_boot_resumer=resume,
        )

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        self.assertEqual(len(resumed_records), 1)
        self.assertEqual(
            self.store.load(REQUEST_ID).state,
            RequestState.COMPLETION_PROVEN,
        )
        self.assertEqual(coordinator.active_request_ids, ())

    def test_same_boot_until_deadline_fails_closed_with_stable_code(self):
        record = self.armed()
        coordinator, pool, _clock = self.coordinator(
            FakeProbe((PRE_BOOT_ID,) * 8),
            timeout=2,
        )

        result = coordinator.recover(record, self.endpoint)

        self.assertEqual(result.result_code, ResultCode.SAME_BOOT_OBSERVED)
        failed = self.store.load(REQUEST_ID)
        self.assertEqual(failed.state, RequestState.EXPECTED_REBOOT_RECOVERY_FAILED)
        self.assertGreaterEqual(failed.reboot_recovery.probe_attempts, 1)
        self.assertEqual(pool.pins, (REQUEST_ID,))

    def test_unreachable_host_times_out_without_releasing_the_pin(self):
        record = self.armed()
        coordinator, pool, _clock = self.coordinator(FakeProbe(), timeout=2)

        result = coordinator.recover(record, self.endpoint)

        self.assertEqual(result.result_code, ResultCode.REBOOT_RECOVERY_TIMEOUT)
        self.assertEqual(
            self.store.load(REQUEST_ID).state,
            RequestState.EXPECTED_REBOOT_RECOVERY_FAILED,
        )
        self.assertEqual(pool.pins, (REQUEST_ID,))
        self.assertEqual(coordinator.active_count, 1)

    def test_changed_boot_after_deadline_cannot_authorize_abandonment(self):
        clock = FakeClock()

        class SlowProbe(FakeProbe):
            def probe_after_disconnect(self, endpoint):
                clock.sleep(5)
                return super().probe_after_disconnect(endpoint)

        record = self.armed()
        coordinator, pool, _clock = self.coordinator(
            SlowProbe((POST_BOOT_ID,)),
            clock=clock,
            timeout=4,
        )

        result = coordinator.recover(
            record,
            self.endpoint,
            lease=FakeLease(pool, record, self.endpoint),
        )

        self.assertEqual(result.result_code, ResultCode.REBOOT_RECOVERY_TIMEOUT)
        self.assertEqual(pool.reconcile_calls, [])
        failed = self.store.load(REQUEST_ID)
        self.assertEqual(failed.state, RequestState.EXPECTED_REBOOT_RECOVERY_FAILED)
        self.assertEqual(failed.reboot_recovery.probe_attempts, 1)

    def test_changed_boot_observation_must_follow_remote_start_boundary(self):
        record = self.armed()
        pending = self.store.begin_expected_reboot_verification(
            record,
            deadline_at="2026-08-20T00:00:04.000000Z",
            detail="expected reboot verification began",
            now=lambda: "2026-08-20T00:00:00.000000Z",
        )

        with self.assertRaisesRegex(StateCorruptionError, "start/deadline bounds"):
            self.store.mark_expected_reboot_verified(
                pending,
                post_boot_id=POST_BOOT_ID,
                reason="injected observation before the remote start boundary",
                now=lambda: "2026-08-19T23:59:59.000000Z",
            )

        self.assertEqual(self.store.load(REQUEST_ID), pending)

    def test_endpoint_identity_change_fails_immediately(self):
        record = self.armed()
        changed = replace(self.endpoint, resolved_hostname="192.0.2.99")
        coordinator, _pool, _clock = self.coordinator(FakeProbe((POST_BOOT_ID,)))

        result = coordinator.recover(record, changed)

        self.assertEqual(result.result_code, ResultCode.ENDPOINT_IDENTITY_MISMATCH)
        self.assertEqual(
            self.store.load(REQUEST_ID).state,
            RequestState.EXPECTED_REBOOT_RECOVERY_FAILED,
        )

    def test_host_key_mismatch_fails_immediately(self):
        record = self.armed()
        mismatch = BootIdProbeError("host_key_mismatch", "host key mismatch")
        coordinator, _pool, _clock = self.coordinator(FakeProbe((mismatch,)))

        result = coordinator.recover(record, self.endpoint)

        self.assertEqual(result.result_code, ResultCode.HOST_KEY_MISMATCH)

    def test_malformed_boot_id_fails_immediately_with_stable_code(self):
        record = self.armed()
        malformed = BootIdProbeError(
            "boot_id_invalid",
            "boot ID probe returned non-canonical output",
        )
        probe = FakeProbe((malformed, POST_BOOT_ID))
        coordinator, pool, _clock = self.coordinator(probe)

        result = coordinator.recover(record, self.endpoint)

        self.assertEqual(result.result_code, ResultCode.BOOT_ID_INVALID)
        self.assertEqual(len(probe.post_calls), 1)
        self.assertEqual(pool.reconcile_calls, [])
        failed = self.store.load(REQUEST_ID)
        self.assertEqual(failed.state, RequestState.EXPECTED_REBOOT_RECOVERY_FAILED)
        self.assertEqual(
            failed.reboot_recovery.failure_code,
            ResultCode.BOOT_ID_INVALID.value,
        )

    def test_credential_failure_is_immediate_and_never_starts_a_probe(self):
        record = self.armed()
        probe = FakeProbe((POST_BOOT_ID,))
        coordinator, pool, _clock = self.coordinator(probe)

        result = coordinator.fail_closed_after_remote_start(
            record,
            code=ResultCode.CREDENTIAL_PROMPT_MISMATCH,
            detail="stored prompt binding did not match",
        )

        self.assertEqual(result.result_code, ResultCode.CREDENTIAL_PROMPT_MISMATCH)
        self.assertEqual(probe.post_calls, [])
        self.assertEqual(pool.pins, (REQUEST_ID,))
        failed = self.store.load(REQUEST_ID)
        self.assertEqual(failed.state, RequestState.EXPECTED_REBOOT_RECOVERY_FAILED)
        self.assertEqual(
            failed.reboot_recovery.failure_code,
            ResultCode.CREDENTIAL_PROMPT_MISMATCH.value,
        )

    def test_stale_request_generation_fails_without_probing_or_cleanup(self):
        stale = self.armed()
        current = self.store.begin_expected_reboot_verification(
            stale,
            deadline_at="2026-08-20T00:05:00.000000Z",
            detail="another recovery worker began verification",
            now=lambda: "2026-08-20T00:00:00.000000Z",
        )
        probe = FakeProbe((POST_BOOT_ID,))
        coordinator, pool, _clock = self.coordinator(probe)

        result = coordinator.recover(stale, self.endpoint)

        self.assertEqual(result.result_code, ResultCode.REQUEST_BINDING_MISMATCH)
        self.assertEqual(self.store.load(REQUEST_ID), current)
        self.assertEqual(probe.post_calls, [])
        self.assertEqual(pool.reconcile_calls, [])

    def test_connection_plan_mismatch_is_rejected_before_recovery(self):
        record = self.armed()
        self.assertIsNotNone(record.reboot_recovery)
        assert record.reboot_recovery is not None
        mismatched_evidence = replace(
            record.reboot_recovery,
            connection_plan_sha256="f" * 64,
        )

        with self.assertRaisesRegex(StateCorruptionError, "evidence identity"):
            replace(record, reboot_recovery=mismatched_evidence)

    def test_verified_evidence_digest_binds_policy_deadline_and_attempts(self):
        record = self.armed()
        coordinator, pool, _clock = self.coordinator(FakeProbe((POST_BOOT_ID,)))

        coordinator.recover(
            record,
            self.endpoint,
            lease=FakeLease(pool, record, self.endpoint),
        )

        evidence = self.store.load(REQUEST_ID).reboot_recovery
        self.assertIsNotNone(evidence)
        assert evidence is not None
        document = evidence.evidence_document()
        self.assertEqual(document["disconnect_policy"], "expect_full_reboot")
        self.assertEqual(document["probe_attempts"], 1)
        self.assertIsNotNone(document["recovery_deadline_at"])
        self.assertIsNotNone(document["last_probe_at"])
        assert evidence.verified_at is not None
        assert evidence.remote_start_time is not None
        self.assertGreater(evidence.verified_at, evidence.remote_start_time)
        with self.assertRaisesRegex(StateCorruptionError, "digest does not match"):
            replace(evidence, probe_attempts=evidence.probe_attempts + 1)

    def test_cleanup_failure_keeps_evidence_complete_record_for_restart(self):
        record = self.armed()
        pool = FakePool()
        pool.reconcile_error = TransportError("unsafe control path mode")
        coordinator, _pool, _clock = self.coordinator(
            FakeProbe((POST_BOOT_ID,)), pool=pool
        )
        lease = FakeLease(pool, record, self.endpoint)

        result = coordinator.recover(record, self.endpoint, lease=lease)

        self.assertEqual(result.result_code, ResultCode.UNSAFE_CONTROL_PATH)
        pending = self.store.load(REQUEST_ID)
        self.assertEqual(
            pending.state,
            RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING,
        )
        self.assertIsNotNone(pending.reboot_recovery.evidence_sha256)

        pool.reconcile_error = None
        restarted, _pool, _clock = self.coordinator(FakeProbe(), pool=pool)
        restarted.register_startup((pending,))
        result = restarted.recover(pending, self.endpoint)
        self.assertEqual(
            result.transport_status,
            TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT,
        )
        self.assertEqual(pool.reconcile_calls.__len__(), 2)

    def test_ambiguous_live_master_keeps_cleanup_pending(self):
        record = self.armed()
        pool = FakePool()
        pool.reconcile_error = TransportBusyError(
            "live master shutdown could not be confirmed"
        )
        coordinator, _pool, _clock = self.coordinator(
            FakeProbe((POST_BOOT_ID,)), pool=pool
        )
        lease = FakeLease(pool, record, self.endpoint)

        result = coordinator.recover(record, self.endpoint, lease=lease)

        self.assertEqual(result.result_code, ResultCode.AMBIGUOUS_MASTER_STATE)
        self.assertEqual(
            self.store.load(REQUEST_ID).state,
            RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING,
        )

    def test_incomplete_recovery_survives_restart_and_blocks_only_its_machine(self):
        record = self.armed()
        report = recover_startup(self.store)
        coordinator, pool, _clock = self.coordinator(FakeProbe((POST_BOOT_ID,)))
        # A restarted pool has no in-memory pin; the exact old socket remains
        # protected and is reconciled only after evidence is committed.
        pool.pins = ()
        coordinator.register_startup(report.records)

        self.assertEqual(coordinator.active_count, 1)
        with self.assertRaises(RecoveryCoordinatorError):
            coordinator.require_machine_available("app-server", OTHER_REQUEST_ID)
        coordinator.require_machine_available("other-server", OTHER_REQUEST_ID)

        result = coordinator.recover(record, self.endpoint)
        self.assertEqual(
            result.transport_status,
            TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT,
        )
        self.assertEqual(coordinator.active_count, 0)

    def test_repeated_cleanup_never_releases_another_request_pin(self):
        record = self.armed()
        coordinator, pool, _clock = self.coordinator(FakeProbe((POST_BOOT_ID,)))
        lease = FakeLease(pool, record, self.endpoint)
        result = coordinator.recover(record, self.endpoint, lease=lease)
        self.assertEqual(
            result.transport_status,
            TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT,
        )
        pool.pins = (OTHER_REQUEST_ID,)

        repeated = coordinator.recover(self.store.load(REQUEST_ID), self.endpoint)
        self.assertEqual(
            repeated.transport_status,
            TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT,
        )
        self.assertEqual(pool.pins, (OTHER_REQUEST_ID,))
