from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from tmuxgate.executor import RealExecutor
from tmuxgate.result import TransportStatus
from tmuxgate.scheduler import RequestState
from tmuxgate.spool import ResultSpool
from tmuxgate.state import DurableStateStore
from tmuxgate.approval import ApprovalDecision
from tmuxgate.transport import MasterTransportPool, SshMasterStartError
from test_planning import PlannerHarness, request
from test_remote_job import FakeRemoteBackend
from test_transport import FakeMasterBackend


REQUEST_ID = "0123456789abcdef0123456789abcdef"


class AutoCompletingBackend(FakeRemoteBackend):
    def attach(self, identity):
        viewer = super().attach(identity)
        self.viewer = viewer
        return viewer

    def release_gate(self, identity):
        super().release_gate(identity)
        self.complete(b"stdout-line\n", b"stderr-line\n", 7)
        self.viewer.detach()


class RetryMasterBackend(FakeMasterBackend):
    def __init__(self, failures):
        super().__init__()
        self.failures = failures

    def start_master(self, invocation, control_path):
        if self.failures:
            self.starts.append(invocation)
            self.failures -= 1
            raise SshMasterStartError(255)
        super().start_master(invocation, control_path)


class RealExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        (root / "control").mkdir(mode=0o700)
        (root / "state").mkdir(mode=0o700)
        self.master_backend = FakeMasterBackend()
        self.harness = PlannerHarness()
        self.planner = self.harness.planner()
        self.pool = MasterTransportPool(
            root / "control",
            backend=self.master_backend,
            identity_revalidator=lambda endpoint: endpoint,
        )
        self.state = DurableStateStore(root / "state")
        self.spool = ResultSpool(root / "state")

    def tearDown(self):
        self.pool.close_idle()
        self.spool.close()
        self.state.close()
        self.master_backend.close()
        self.temporary.cleanup()

    def approve(self, spec):
        self.planner(REQUEST_ID, spec)

    def executor(self, backend, **kwargs):
        return RealExecutor(
            planner=self.planner,
            transports=self.pool,
            state=self.state,
            spool=self.spool,
            backend_factory=lambda transport: backend,
            poll_interval_seconds=0.001,
            detached_wait_seconds=0.001,
            **kwargs,
        )

    def test_full_fake_transport_and_remote_job_returns_exact_result_and_done(self):
        spec = request(("printf", "hello"))
        self.approve(spec)
        backend = AutoCompletingBackend()
        executor = self.executor(backend)

        result = executor(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        self.assertEqual(result.stdout, b"stdout-line\n")
        self.assertEqual(result.stderr, b"stderr-line\n")
        self.assertEqual(result.remote_exit_status, 7)
        self.assertEqual(
            backend.events,
            ["stage", "create-gated", "attach", "release-gate", "collect", "cleanup"],
        )
        self.assertEqual(self.state.load(REQUEST_ID).state, RequestState.RESULT_DELIVERING)
        executor.result_delivery_finished(REQUEST_ID, True)
        self.assertEqual(self.state.load(REQUEST_ID).state, RequestState.DONE)
        spooled = self.spool.load(REQUEST_ID)
        self.assertEqual((spooled.stdout, spooled.stderr, spooled.exit_status), (b"stdout-line\n", b"stderr-line\n", 7))
        self.assertIsNone(self.pool.pinned_request_id)

    def test_transport_failure_is_proven_pre_remote_and_creates_no_job_state(self):
        spec = request(("true",))
        self.approve(spec)
        self.master_backend.fail_next_start = True
        result = self.executor(AutoCompletingBackend())(REQUEST_ID, spec)
        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertEqual(self.state.load_all(), ())
        self.assertIsNone(self.pool.pinned_request_id)

    def test_disabled_after_approval_is_proven_pre_remote_without_recovery_state(self):
        spec = request(("true",))
        self.approve(spec)
        self.planner.machine_enabled = lambda _machine_name: False

        result = self.executor(AutoCompletingBackend())(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertIn("configured machine is disabled", result.detail)
        self.assertEqual(self.master_backend.starts, [])
        self.assertEqual(self.state.load_all(), ())
        self.assertIsNone(self.pool.pinned_request_id)
        self.assertEqual(self.planner.pending_request_ids, ())

    def test_failed_ssh_master_can_be_retried_once_from_broker_terminal(self):
        self.master_backend.close()
        self.master_backend = RetryMasterBackend(1)
        self.pool.backend = self.master_backend
        spec = request(("true",))
        self.approve(spec)
        retry_calls = []

        def retry(*args, **kwargs):
            retry_calls.append((args, kwargs))
            return ApprovalDecision.APPROVED

        result = self.executor(
            AutoCompletingBackend(), ssh_retry_approver=retry
        )(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        self.assertEqual(len(self.master_backend.starts), 2)
        self.assertEqual(len(retry_calls), 1)
        self.assertEqual(retry_calls[0][1]["endpoint_id"], "home-lan")
        self.assertFalse(retry_calls[0][1]["remote_mutation_started"])

    def test_broker_confirmed_ssh_retry_is_bounded_to_one_attempt(self):
        self.master_backend.close()
        self.master_backend = RetryMasterBackend(2)
        self.pool.backend = self.master_backend
        spec = request(("true",))
        self.approve(spec)
        retry_calls = []

        def retry(*args, **kwargs):
            retry_calls.append((args, kwargs))
            return ApprovalDecision.APPROVED

        fallback_calls = []

        def deny_fallback(*args, **kwargs):
            fallback_calls.append((args, kwargs))
            return ApprovalDecision.DENIED

        result = self.executor(
            AutoCompletingBackend(),
            ssh_retry_approver=retry,
            fallback_approver=deny_fallback,
        )(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertEqual(len(self.master_backend.starts), 2)
        self.assertEqual(len(retry_calls), 1)
        self.assertEqual(len(fallback_calls), 1)
        self.assertIn("retry also failed", fallback_calls[0][1]["failure_detail"])
        self.assertEqual(self.state.load_all(), ())

    def test_cancelled_ssh_retry_requires_fallback_approval_without_state(self):
        self.master_backend.close()
        self.master_backend = RetryMasterBackend(1)
        self.pool.backend = self.master_backend
        spec = request(("true",))
        self.approve(spec)
        retry_calls = []
        fallback_calls = []

        def cancel_retry(*args, **kwargs):
            retry_calls.append((args, kwargs))
            return ApprovalDecision.DENIED

        def deny_fallback(*args, **kwargs):
            fallback_calls.append((args, kwargs))
            return ApprovalDecision.DENIED

        def unexpected_disable(*args, **kwargs):
            raise AssertionError("untried fallback must not offer machine disable")

        result = self.executor(
            AutoCompletingBackend(),
            ssh_retry_approver=cancel_retry,
            fallback_approver=deny_fallback,
            machine_disable_approver=unexpected_disable,
        )(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertEqual(len(self.master_backend.starts), 1)
        self.assertEqual(len(retry_calls), 1)
        self.assertEqual(len(fallback_calls), 1)
        self.assertIn(
            "cancelled the same-endpoint retry",
            fallback_calls[0][1]["failure_detail"],
        )
        self.assertEqual(self.state.load_all(), ())

    def test_fallback_endpoint_has_its_own_single_confirmed_retry(self):
        self.master_backend.close()
        self.master_backend = RetryMasterBackend(3)
        self.pool.backend = self.master_backend
        spec = request(("true",))
        self.approve(spec)
        retry_endpoint_ids = []
        fallback_calls = []

        def approve_retry(*args, **kwargs):
            retry_endpoint_ids.append(kwargs["endpoint_id"])
            return ApprovalDecision.APPROVED

        def approve_fallback(*args, **kwargs):
            fallback_calls.append((args, kwargs))
            return ApprovalDecision.APPROVED

        result = self.executor(
            AutoCompletingBackend(),
            ssh_retry_approver=approve_retry,
            fallback_approver=approve_fallback,
        )(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        self.assertEqual(len(self.master_backend.starts), 4)
        self.assertEqual(retry_endpoint_ids, ["home-lan", "wireguard"])
        self.assertEqual(len(fallback_calls), 1)
        self.assertEqual(
            fallback_calls[0][1]["fallback_endpoint_id"],
            "wireguard",
        )

    def test_exhausted_ssh_endpoints_can_disable_machine_once(self):
        self.master_backend.close()
        self.master_backend = RetryMasterBackend(4)
        self.pool.backend = self.master_backend
        spec = request(("true",))
        self.approve(spec)
        disable_calls = []
        disabled = []

        def approve_disable(*args, **kwargs):
            disable_calls.append((args, kwargs))
            return ApprovalDecision.APPROVED

        result = self.executor(
            AutoCompletingBackend(),
            ssh_retry_approver=(
                lambda *args, **kwargs: ApprovalDecision.APPROVED
            ),
            fallback_approver=(
                lambda *args, **kwargs: ApprovalDecision.APPROVED
            ),
            machine_disable_approver=approve_disable,
            machine_disabler=disabled.append,
        )(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertEqual(len(self.master_backend.starts), 4)
        self.assertEqual(len(disable_calls), 1)
        self.assertEqual(disable_calls[0][0], (REQUEST_ID, "app-server"))
        self.assertFalse(disable_calls[0][1]["remote_mutation_started"])
        self.assertEqual(disabled, ["app-server"])
        self.assertIn("machine disabled by operator", result.detail)
        self.assertEqual(self.state.load_all(), ())

    def test_disable_write_failure_preserves_original_pre_remote_failure(self):
        self.master_backend.close()
        self.master_backend = RetryMasterBackend(4)
        self.pool.backend = self.master_backend
        spec = request(("true",))
        self.approve(spec)

        def fail_disable(machine_name):
            raise OSError(f"cannot persist {machine_name}")

        result = self.executor(
            AutoCompletingBackend(),
            ssh_retry_approver=(
                lambda *args, **kwargs: ApprovalDecision.APPROVED
            ),
            fallback_approver=(
                lambda *args, **kwargs: ApprovalDecision.APPROVED
            ),
            machine_disable_approver=(
                lambda *args, **kwargs: ApprovalDecision.APPROVED
            ),
            machine_disabler=fail_disable,
        )(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertIn("SSH transport was not established", result.detail)
        self.assertIn("machine remains enabled because disabling failed", result.detail)
        self.assertEqual(self.state.load_all(), ())

    def test_already_disabled_machine_skips_duplicate_disable_prompt(self):
        self.master_backend.close()
        self.master_backend = RetryMasterBackend(4)
        self.pool.backend = self.master_backend
        spec = request(("true",))
        self.approve(spec)

        def unexpected_disable_prompt(*args, **kwargs):
            raise AssertionError("an already-disabled machine must not prompt again")

        result = self.executor(
            AutoCompletingBackend(),
            ssh_retry_approver=(
                lambda *args, **kwargs: ApprovalDecision.APPROVED
            ),
            fallback_approver=(
                lambda *args, **kwargs: ApprovalDecision.APPROVED
            ),
            machine_disable_approver=unexpected_disable_prompt,
            machine_enabled=lambda _machine_name: False,
        )(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertIn("machine was already disabled", result.detail)
        self.assertEqual(self.state.load_all(), ())

    def test_ssh_retry_refuses_changed_ssh_identity_plan(self):
        self.master_backend.close()
        self.master_backend = RetryMasterBackend(1)
        self.pool.backend = self.master_backend
        spec = request(("true",))
        self.approve(spec)
        approved_plan = self.harness.approval_calls[0][2]
        changed_selected = replace(
            approved_plan.selected,
            resolved=replace(
                approved_plan.selected.resolved,
                resolved_user="different-user",
            ),
        )
        changed_plan = replace(
            approved_plan,
            endpoints=(changed_selected, *approved_plan.fallbacks),
            plan_sha256="e" * 64,
        )
        self.planner.connection_builder = (
            lambda route_plan, snapshot, *, resolver: changed_plan
        )

        result = self.executor(
            AutoCompletingBackend(),
            ssh_retry_approver=lambda *args, **kwargs: ApprovalDecision.APPROVED,
        )(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertIn("plan changed", result.detail)
        self.assertEqual(len(self.master_backend.starts), 1)
        self.assertEqual(self.state.load_all(), ())

    def test_non_ssh_setup_failure_never_offers_authentication_retry(self):
        spec = request(("true",))
        self.approve(spec)
        self.master_backend.fail_next_start = True

        def unexpected_retry(*args, **kwargs):
            raise AssertionError("ordinary transport failures must not be retried")

        def unexpected_disable(*args, **kwargs):
            raise AssertionError("ordinary transport failures must not offer disable")

        result = self.executor(
            AutoCompletingBackend(),
            ssh_retry_approver=unexpected_retry,
            machine_disable_approver=unexpected_disable,
        )(REQUEST_ID, spec)
        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)

    def test_post_arm_failure_is_incomplete_and_retains_transport_lease(self):
        spec = request(("true",))
        self.approve(spec)
        backend = FakeRemoteBackend()

        def fail_stage(identity, submitted):
            raise RuntimeError("synthetic stage failure")

        backend.stage = fail_stage
        executor = self.executor(backend)
        result = executor(REQUEST_ID, spec)
        self.assertEqual(result.transport_status, TransportStatus.INCOMPLETE)
        self.assertEqual(self.pool.pinned_request_id, REQUEST_ID)
        self.assertEqual(
            self.state.load(REQUEST_ID).state,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        )
        # The retained lease is deliberately not released by the test subject.
        executor._recovery_leases[REQUEST_ID].release()


if __name__ == "__main__":
    unittest.main()
