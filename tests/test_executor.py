import asyncio
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from mcp import Client

from tmuxgate.broker import BrokerServer
from tmuxgate.broker_api import BrokerControlService
from tmuxgate.executor import RealExecutor
from tmuxgate.mcp_server import create_mcp_server
from tmuxgate.models import DisconnectPolicy
from tmuxgate.reboot_recovery import BootIdProbeError
from tmuxgate.recovery_coordinator import ExpectedRebootRecoveryCoordinator
from tmuxgate.result import ResultCode, TransportStatus
from tmuxgate.runtime import create_broker_socket
from tmuxgate.scheduler import RequestState
from tmuxgate.spool import ResultSpool
from tmuxgate.state import DurableStateStore, recover_startup
from tmuxgate.approval import ApprovalDecision
from tmuxgate.operator_interface import (
    ActivityKind,
    ConnectionPhase,
    OperatorDecision,
    PlainTerminalInterface,
    RemoteMutationState,
    RouteFallbackPrompt,
    SshRetryPrompt,
)
from tmuxgate.transport import MasterTransportPool, SshMasterStartError
from test_planning import PlannerHarness, request
from test_remote_job import FakeRemoteBackend
from test_connection_plan import build_plan
from test_transport import (
    FakeKeyManager,
    FakeMasterBackend,
    authorization,
    machine_endpoint,
)


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
            attempt = len(self.starts)
            self.failures -= 1
            raise SshMasterStartError(
                255,
                f"attempt {attempt}: malicious \x1b]8;;link\x07\n".encode(),
            )
        super().start_master(invocation, control_path)


class CallbackOperatorInterface:
    """Translate structured prompts to the focused legacy-style test callbacks."""

    def __init__(
        self,
        *,
        fallback_approver=lambda *args, **kwargs: ApprovalDecision.DENIED,
        ssh_retry_approver=lambda *args, **kwargs: ApprovalDecision.DENIED,
        machine_disable_approver=lambda *args, **kwargs: ApprovalDecision.DENIED,
    ):
        self.fallback_approver = fallback_approver
        self.ssh_retry_approver = ssh_retry_approver
        self.machine_disable_approver = machine_disable_approver
        self.prompts = []
        self.activity = []

    def request_fallback(self, prompt):
        self.prompts.append(prompt)
        decision = self.fallback_approver(
            prompt.request_id,
            prompt.request,
            prompt.connection_plan,
            failed_endpoint_id=prompt.failed_endpoint_id,
            fallback_endpoint_id=prompt.fallback_endpoint_id,
            failure_detail=prompt.failure_detail,
            remote_mutation_started=False,
        )
        return OperatorDecision.for_prompt(prompt, decision)

    def request_ssh_retry(self, prompt):
        self.prompts.append(prompt)
        decision = self.ssh_retry_approver(
            prompt.request_id,
            prompt.request,
            prompt.connection_plan,
            endpoint_id=prompt.endpoint_id,
            failure_detail=prompt.failure_detail,
            remote_mutation_started=False,
        )
        return OperatorDecision.for_prompt(prompt, decision)

    def request_machine_disable(self, prompt):
        self.prompts.append(prompt)
        decision = self.machine_disable_approver(
            prompt.request_id,
            prompt.request.machine_alias,
            failure_detail=prompt.failure_detail,
            remote_mutation_started=False,
        )
        return OperatorDecision.for_prompt(prompt, decision)

    def publish_activity(self, event):
        self.activity.append(event)


class NonPresentingTerminal:
    def claim(self, **_keywords):
        return nullcontext()

    def poll_dashboard_line(self, **_keywords):
        return None


class ExecutorBootProbe:
    def __init__(self, *, pre_boot_id, post_boot_id=None, pre_error=None):
        self.pre_boot_id = pre_boot_id
        self.post_boot_id = post_boot_id
        self.pre_error = pre_error
        self.pre_calls = []
        self.post_calls = []

    def capture_pre_reboot(self, transport):
        self.pre_calls.append(transport)
        if self.pre_error is not None:
            raise self.pre_error
        return self.pre_boot_id

    def probe_after_disconnect(self, endpoint):
        self.post_calls.append(endpoint)
        if self.post_boot_id is None:
            raise BootIdProbeError("reboot_probe_unavailable", "host unreachable")
        return self.post_boot_id


class SequencedExecutorBootProbe(ExecutorBootProbe):
    def __init__(self, *, pre_boot_id, post_outcomes):
        super().__init__(pre_boot_id=pre_boot_id)
        self.post_outcomes = list(post_outcomes)

    def probe_after_disconnect(self, endpoint):
        self.post_calls.append(endpoint)
        if not self.post_outcomes:
            raise AssertionError("boot probe sequence was exhausted")
        outcome = self.post_outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class PromptForbiddenAutomationInterface:
    """Automation boundary that proves the incident never asks an operator."""

    approval_mode = "disabled"

    def __init__(self):
        self.prompt_calls = []
        self.activity = []

    def _forbid(self, prompt):
        self.prompt_calls.append(prompt)
        raise AssertionError("the reboot incident must not call an operator prompt")

    request_execution_approval = _forbid
    request_ssh_retry = _forbid
    request_fallback = _forbid
    request_secret_input_authorization = _forbid
    request_machine_disable = _forbid

    def run_external_terminal_session(self, prompt, session):
        self._forbid(prompt)

    def run_terminal_session(self, purpose, session):
        self._forbid(purpose)

    def publish_activity(self, event):
        self.activity.append(event)


class InvalidRetryAutomationInterface(PlainTerminalInterface):
    def resolve_automation_prompt(self, prompt):
        if isinstance(prompt, SshRetryPrompt):
            object.__setattr__(prompt, "endpoint_id", "not-in-the-approved-plan")
        return super().resolve_automation_prompt(prompt)


class PostMutationFallbackAutomationInterface(PlainTerminalInterface):
    def resolve_automation_prompt(self, prompt):
        if isinstance(prompt, RouteFallbackPrompt):
            object.__setattr__(
                prompt,
                "remote_mutation_state",
                RemoteMutationState.MAY_HAVE_STARTED,
            )
        return super().resolve_automation_prompt(prompt)


class RealExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = self.root = Path(self.temporary.name)
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

    def assert_durable_pre_remote_failure(self, *, endpoint_id, detail_fragment):
        """An approved request that never reached a host is still listable."""

        records = self.state.load_all()
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.request_id, REQUEST_ID)
        self.assertEqual(record.state, RequestState.FAILED_PRE_REMOTE)
        self.assertEqual(record.decision, ApprovalDecision.APPROVED)
        self.assertFalse(record.remote_mutation_started)
        self.assertIsNone(record.start_time)
        self.assertIsNone(record.completion_time)
        self.assertIsNone(record.exit_status)
        self.assertFalse(record.local_spool_verified)
        self.assertEqual(record.endpoint_id, endpoint_id)
        self.assertIn(detail_fragment, record.failure_detail)
        return record

    def executor(self, backend, **kwargs):
        operator = kwargs.pop("operator_interface", None)
        if operator is None:
            operator = CallbackOperatorInterface(
                fallback_approver=kwargs.pop(
                    "fallback_approver",
                    lambda *args, **keywords: ApprovalDecision.DENIED,
                ),
                ssh_retry_approver=kwargs.pop(
                    "ssh_retry_approver",
                    lambda *args, **keywords: ApprovalDecision.DENIED,
                ),
                machine_disable_approver=kwargs.pop(
                    "machine_disable_approver",
                    lambda *args, **keywords: ApprovalDecision.DENIED,
                ),
            )
        self.operator = operator
        return RealExecutor(
            planner=self.planner,
            transports=self.pool,
            state=self.state,
            spool=self.spool,
            backend_factory=lambda transport, recipient: backend,
            operator_interface=operator,
            poll_interval_seconds=0.001,
            detached_wait_seconds=0.001,
            **kwargs,
        )

    def reboot_coordinator(self, probe):
        return ExpectedRebootRecoveryCoordinator(
            state=self.state,
            transports=self.pool,
            boot_id_probe=probe,
            identity_revalidator=lambda endpoint: endpoint,
            timeout_seconds=2,
            probe_interval_seconds=0.001,
        )

    def fill_pool_with_other_idle_masters(self):
        base = build_plan().selected.resolved
        paths = []
        for index in range(1, 4):
            endpoint = machine_endpoint(base, index)
            lease = self.pool.acquire(
                authorization(
                    endpoint.machine_name,
                    endpoint,
                    request_id=f"{index + 1:032x}",
                ),
                endpoint,
            )
            paths.append(lease.transport.control_path)
            lease.release()
        return tuple(paths)

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

    def test_transport_failure_is_proven_pre_remote_and_stays_durably_listed(self):
        spec = request(("true",))
        self.approve(spec)
        self.master_backend.fail_next_start = True
        result = self.executor(AutoCompletingBackend())(REQUEST_ID, spec)
        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        record = self.assert_durable_pre_remote_failure(
            endpoint_id="home-lan",
            detail_fragment="synthetic authentication failure",
        )
        self.assertIn("SSH transport was not established", record.failure_detail)
        self.assertIsNone(self.pool.pinned_request_id)

    def test_noninteractive_request_recovers_a_proven_dead_idle_master(self):
        stale_paths = self.fill_pool_with_other_idle_masters()
        self.master_backend.die_during_next_stop = True
        spec = request(("true",))
        self.approve(spec)
        backend = AutoCompletingBackend()

        result = self.executor(backend)(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        self.assertFalse(stale_paths[0].exists())
        self.assertIn("release-gate", backend.events)

    def test_interactive_request_recovers_a_proven_dead_idle_master(self):
        stale_paths = self.fill_pool_with_other_idle_masters()
        self.master_backend.die_during_next_stop = True
        spec = replace(request(("true",)), interactive=True)
        self.approve(spec)
        backend = AutoCompletingBackend()

        result = self.executor(backend)(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        self.assertFalse(stale_paths[0].exists())
        self.assertIn("release-gate", backend.events)

    def test_live_unconfirmed_eviction_is_durably_proven_pre_remote(self):
        stale_paths = self.fill_pool_with_other_idle_masters()
        self.master_backend.fail_next_stop = True
        spec = request(("true",))
        self.approve(spec)
        backend = AutoCompletingBackend()

        result = self.executor(backend)(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertEqual(backend.events, [])
        self.assertTrue(stale_paths[0].exists())
        record = self.assert_durable_pre_remote_failure(
            endpoint_id="home-lan",
            detail_fragment="master is still live",
        )
        self.assertFalse(record.remote_mutation_started)

    def test_durable_pre_remote_failure_never_blocks_startup_recovery(self):
        spec = request(("true",))
        self.approve(spec)
        self.master_backend.fail_next_start = True
        self.executor(AutoCompletingBackend())(REQUEST_ID, spec)

        report = recover_startup(self.state)

        self.assertTrue(report.safe_to_accept_new_approvals)
        self.assertEqual(report.blocking_request_ids, ())
        self.assertEqual(report.interrupted_pre_remote_ids, ())
        self.assertEqual(len(report.records), 1)
        self.assertEqual(report.records[0].state, RequestState.FAILED_PRE_REMOTE)

    def test_pre_remote_failure_stands_when_its_own_durable_failure_fails(self):
        spec = request(("true",))
        self.approve(spec)
        self.master_backend.fail_next_start = True
        written = []
        real_fail_pre_remote = self.state.fail_pre_remote

        def refuse_fail_pre_remote(record, **kwargs):
            written.append(record)
            raise OSError("synthetic durable failure-of-the-failure")

        self.state.fail_pre_remote = refuse_fail_pre_remote
        try:
            result = self.executor(AutoCompletingBackend())(REQUEST_ID, spec)
        finally:
            self.state.fail_pre_remote = real_fail_pre_remote

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertIn("synthetic authentication failure", result.detail)
        self.assertEqual(len(written), 1)
        # The record is left in its last fsynced state, not mid-transition, so
        # startup recovery can terminalize it conservatively.
        stranded = self.state.load(REQUEST_ID)
        self.assertEqual(stranded.state, RequestState.APPROVED_PRE_REMOTE)
        self.assertFalse(stranded.remote_mutation_started)
        report = recover_startup(self.state)
        self.assertTrue(report.safe_to_accept_new_approvals)
        self.assertEqual(report.interrupted_pre_remote_ids, (REQUEST_ID,))
        self.assertEqual(
            self.state.load(REQUEST_ID).state, RequestState.FAILED_PRE_REMOTE
        )

    def test_unrecordable_approval_fails_pre_remote_without_opening_ssh(self):
        spec = request(("true",))
        self.approve(spec)
        real_write = self.state.write

        def refuse_write(record):
            raise OSError("synthetic durable write failure")

        self.state.write = refuse_write
        try:
            result = self.executor(AutoCompletingBackend())(REQUEST_ID, spec)
        finally:
            self.state.write = real_write

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertIn("could not be recorded durably", result.detail)
        self.assertEqual(self.master_backend.starts, [])
        self.assertEqual(self.state.load_all(), ())
        self.assertIsNone(self.pool.pinned_request_id)

    def test_uncertain_key_enrollment_blocks_retry_and_route_fallback(self):
        self.pool.key_manager = FakeKeyManager("post-failure")
        spec = request(("true",))
        self.approve(spec)
        fallback_calls = []

        def unexpected_fallback(*args, **kwargs):
            fallback_calls.append((args, kwargs))
            return ApprovalDecision.APPROVED

        result = self.executor(
            AutoCompletingBackend(),
            fallback_approver=unexpected_fallback,
            ssh_retry_approver=lambda *args, **kwargs: ApprovalDecision.APPROVED,
        )(REQUEST_ID, spec)

        self.assertEqual(
            result.transport_status,
            TransportStatus.REMOTE_SETUP_FAILURE,
        )
        self.assertEqual(fallback_calls, [])
        self.assertEqual(len(self.master_backend.starts), 1)
        durable = self.state.load(REQUEST_ID)
        self.assertEqual(durable.state, RequestState.FAILED_REMOTE_SETUP)
        self.assertTrue(durable.remote_mutation_started)
        self.assertEqual(durable.endpoint_id, "home-lan")
        self.assertIn("fallback were not attempted", durable.failure_detail)
        self.assertIsNone(self.pool.pinned_request_id)
        failed = self.operator.activity[-1]
        self.assertIs(failed.connection_phase, ConnectionPhase.FAILED)
        self.assertIs(
            failed.remote_mutation_state, RemoteMutationState.MAY_HAVE_STARTED
        )

    def test_read_only_enrollment_failure_keeps_normal_approved_fallback(self):
        self.pool.key_manager = FakeKeyManager(["pre-failure", "present"])
        spec = request(("true",))
        self.approve(spec)
        fallback_calls = []

        def approve_fallback(*args, **kwargs):
            fallback_calls.append((args, kwargs))
            return ApprovalDecision.APPROVED

        result = self.executor(
            AutoCompletingBackend(),
            fallback_approver=approve_fallback,
        )(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        self.assertEqual(len(fallback_calls), 1)
        self.assertFalse(fallback_calls[0][1]["remote_mutation_started"])
        self.assertEqual(
            [item.kind for item in self.master_backend.starts],
            ["start-enrollment-master", "start-enrollment-master", "start-master"],
        )
        durable = self.state.load(REQUEST_ID)
        self.assertEqual(durable.endpoint_id, "wireguard")

    def test_verified_key_enrollment_continues_into_normal_command_boundary(self):
        self.pool.key_manager = FakeKeyManager("enrolled")
        spec = request(("true",))
        self.approve(spec)

        result = self.executor(AutoCompletingBackend())(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        durable = self.state.load(REQUEST_ID)
        self.assertEqual(durable.state, RequestState.RESULT_DELIVERING)
        self.assertTrue(durable.remote_mutation_started)
        self.assertEqual(durable.endpoint_id, "home-lan")
        self.assertEqual(
            self.pool.key_manager.events,
            [
                ("local-key-prepared", "home-lan"),
                ("remote-key-inspected", "home-lan"),
                ("remote-enrollment-started", "home-lan"),
            ],
        )

    def test_disabled_after_approval_is_proven_pre_remote_without_recovery_state(self):
        spec = request(("true",))
        self.approve(spec)
        self.planner.machine_enabled = lambda _machine_name: False

        result = self.executor(AutoCompletingBackend())(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertIn("configured machine is disabled", result.detail)
        self.assertEqual(self.master_backend.starts, [])
        # The approval was invalidated while being consumed, so no approved
        # record may exist: an unusable plan is not an authorized request.
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
        retry_prompt = next(
            item for item in self.operator.prompts if isinstance(item, SshRetryPrompt)
        )
        self.assertEqual(retry_prompt.retry_number, 1)
        self.assertEqual(retry_prompt.retry_limit, 1)
        self.assertEqual(
            retry_prompt.openssh_diagnostics,
            b"attempt 1: malicious \x1b]8;;link\x07\n",
        )
        phases = [event.connection_phase for event in self.operator.activity]
        self.assertIn(ConnectionPhase.CONNECTING, phases)
        self.assertIn(ConnectionPhase.RETRY_DECISION, phases)
        self.assertIn(ConnectionPhase.RETRYING, phases)
        self.assertIn(ConnectionPhase.RUNNING, phases)
        self.assertEqual(phases[-1], ConnectionPhase.COMPLETED)

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
        fallback_prompt = next(
            item
            for item in self.operator.prompts
            if isinstance(item, RouteFallbackPrompt)
        )
        self.assertEqual(
            fallback_prompt.openssh_diagnostics,
            b"attempt 2: malicious \x1b]8;;link\x07\n",
        )
        self.assert_durable_pre_remote_failure(
            endpoint_id="home-lan",
            detail_fragment="human denied the next approved fallback",
        )

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
        self.assert_durable_pre_remote_failure(
            endpoint_id="home-lan",
            detail_fragment="human denied the next approved fallback",
        )

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
        # The record follows the plan to the last endpoint actually attempted.
        record = self.assert_durable_pre_remote_failure(
            endpoint_id="wireguard",
            detail_fragment="machine disabled by operator",
        )
        self.assertEqual(record.failure_detail, result.detail)

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
        self.assert_durable_pre_remote_failure(
            endpoint_id="wireguard",
            detail_fragment="machine remains enabled because disabling failed",
        )

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
        self.assert_durable_pre_remote_failure(
            endpoint_id="wireguard",
            detail_fragment="machine was already disabled",
        )

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
        self.assert_durable_pre_remote_failure(
            endpoint_id="home-lan",
            detail_fragment="plan changed",
        )

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

    def test_automation_retry_and_fallback_are_audited_before_next_start(self):
        spec = request(("true",))
        self.approve(spec)
        interface = PlainTerminalInterface(
            NonPresentingTerminal(),
            approval_mode="disabled",
        )
        self.addCleanup(interface.close)
        backend = RetryMasterBackend(failures=2)
        original_start = backend.start_master

        def audited_start(invocation, control_path):
            audits = tuple(
                event
                for event in interface.activity_history
                if event.kind is ActivityKind.BROKER_AUDIT
            )
            if len(backend.starts) == 1:
                self.assertTrue(
                    any("same-endpoint" in event.message for event in audits)
                )
            elif len(backend.starts) == 2:
                self.assertTrue(
                    any("route fallback" in event.message for event in audits)
                )
            return original_start(invocation, control_path)

        backend.start_master = audited_start
        self.pool.backend = backend
        executor = self.executor(
            AutoCompletingBackend(),
            operator_interface=interface,
        )

        result = executor(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        self.assertEqual(len(backend.starts), 3)
        self.assertIsNone(interface._prompts.next_prompt(timeout=0))

    def test_invalid_automation_retry_binding_fails_structured_without_prompt(self):
        spec = request(("true",))
        self.approve(spec)
        interface = InvalidRetryAutomationInterface(
            NonPresentingTerminal(),
            approval_mode="disabled",
        )
        self.addCleanup(interface.close)
        backend = RetryMasterBackend(failures=1)
        self.pool.backend = backend

        result = self.executor(
            FakeRemoteBackend(),
            operator_interface=interface,
        )(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertEqual(result.result_code, ResultCode.AUTOMATION_POLICY_DENIED)
        self.assertIn("invalid structured prompt binding", result.detail)
        self.assertEqual(len(backend.starts), 1)
        self.assertIsNone(interface._prompts.next_prompt(timeout=0))

    def test_post_mutation_automation_fallback_fails_without_prompt(self):
        spec = request(("true",))
        self.approve(spec)
        interface = PostMutationFallbackAutomationInterface(
            NonPresentingTerminal(),
            approval_mode="disabled",
        )
        self.addCleanup(interface.close)
        backend = RetryMasterBackend(failures=2)
        self.pool.backend = backend

        result = self.executor(
            FakeRemoteBackend(),
            operator_interface=interface,
        )(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertEqual(result.result_code, ResultCode.AUTOMATION_POLICY_DENIED)
        self.assertIn("invalid structured prompt binding", result.detail)
        self.assertEqual(len(backend.starts), 2)
        self.assertIsNone(interface._prompts.next_prompt(timeout=0))

    def test_automation_denies_machine_disable_without_mutating_configuration(self):
        spec = request(("true",))
        self.approve(spec)
        interface = PlainTerminalInterface(
            NonPresentingTerminal(),
            approval_mode="disabled",
        )
        self.addCleanup(interface.close)
        backend = RetryMasterBackend(failures=4)
        self.pool.backend = backend
        disabled = []
        executor = self.executor(
            FakeRemoteBackend(),
            operator_interface=interface,
            machine_disabler=disabled.append,
            machine_enabled=lambda machine: True,
        )

        result = executor(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertEqual(result.result_code, ResultCode.AUTOMATION_POLICY_DENIED)
        self.assertEqual(disabled, [])
        self.assertIsNone(interface._prompts.next_prompt(timeout=0))

    def test_expected_reboot_persists_pre_boot_identity_before_remote_stage(self):
        spec = replace(
            request(("systemctl", "reboot")),
            disconnect_policy=DisconnectPolicy.EXPECT_FULL_REBOOT,
        )
        self.approve(spec)
        backend = AutoCompletingBackend()
        probe = ExecutorBootProbe(
            pre_boot_id="11111111-2222-3333-4444-555555555555"
        )
        executor = self.executor(
            backend,
            reboot_recovery=self.reboot_coordinator(probe),
        )

        result = executor(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        self.assertEqual(len(probe.pre_calls), 1)
        record = self.state.load(REQUEST_ID)
        self.assertEqual(
            record.reboot_recovery.pre_boot_id,
            "11111111-2222-3333-4444-555555555555",
        )
        self.assertLess(
            record.reboot_recovery.pre_boot_id_generation,
            record.reboot_recovery.remote_start_generation,
        )

    def test_pre_boot_identity_failure_never_starts_requested_command(self):
        spec = replace(
            request(("systemctl", "reboot")),
            disconnect_policy=DisconnectPolicy.EXPECT_FULL_REBOOT,
        )
        self.approve(spec)
        backend = FakeRemoteBackend()
        probe = ExecutorBootProbe(
            pre_boot_id="11111111-2222-3333-4444-555555555555",
            pre_error=BootIdProbeError(
                "pre_reboot_boot_id_unavailable",
                "pre-reboot boot ID is unavailable",
            ),
        )
        executor = self.executor(
            backend,
            reboot_recovery=self.reboot_coordinator(probe),
        )

        result = executor(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertEqual(result.result_code, ResultCode.PRE_REBOOT_BOOT_ID_UNAVAILABLE)
        self.assertEqual(backend.events, [])
        self.assertEqual(
            self.state.load(REQUEST_ID).state,
            RequestState.FAILED_PRE_REMOTE,
        )
        self.assertIsNone(self.pool.pinned_request_id)

    def test_changed_boot_after_disconnect_terminalizes_without_output_claim(self):
        spec = replace(
            request(("systemctl", "reboot")),
            disconnect_policy=DisconnectPolicy.EXPECT_FULL_REBOOT,
        )
        self.approve(spec)
        backend = FakeRemoteBackend()

        def fail_stage(identity, submitted):
            raise RuntimeError("simulated SSH reset")

        backend.stage = fail_stage
        probe = ExecutorBootProbe(
            pre_boot_id="11111111-2222-3333-4444-555555555555",
            post_boot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        executor = self.executor(
            backend,
            reboot_recovery=self.reboot_coordinator(probe),
        )

        result = executor(REQUEST_ID, spec)

        self.assertEqual(
            result.transport_status,
            TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT,
        )
        self.assertEqual(result.result_code, ResultCode.ABANDONED_AFTER_VERIFIED_REBOOT)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))
        self.assertIsNone(result.remote_exit_status)
        self.assertEqual(
            self.state.load(REQUEST_ID).state,
            RequestState.ABANDONED_AFTER_VERIFIED_REBOOT,
        )

    def test_complete_automation_mcp_reboot_incident_recovers_fresh_master(self):
        interface = PromptForbiddenAutomationInterface()
        probe = SequencedExecutorBootProbe(
            pre_boot_id="11111111-2222-3333-4444-555555555555",
            post_outcomes=(
                BootIdProbeError("reboot_probe_unavailable", "host is restarting"),
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            ),
        )
        coordinator = self.reboot_coordinator(probe)
        backends = []

        def backend_factory(_transport, _recipient):
            index = len(backends)
            backend = AutoCompletingBackend()
            if index == 1:
                def reset_during_stage(_identity, _submitted):
                    raise RuntimeError("simulated SSH reset during full-host reboot")

                backend.stage = reset_during_stage
            backends.append(backend)
            return backend

        executor = RealExecutor(
            planner=self.planner,
            transports=self.pool,
            state=self.state,
            spool=self.spool,
            backend_factory=backend_factory,
            operator_interface=interface,
            reboot_recovery=coordinator,
            poll_interval_seconds=0.001,
            detached_wait_seconds=0.001,
        )
        socket_path = self.root / "incident-broker.sock"
        listener = create_broker_socket(socket_path)
        control = BrokerControlService(
            {
                "app-server": SimpleNamespace(
                    description="Application server",
                    enabled=True,
                )
            },
            self.state,
            self.spool,
        )
        broker = BrokerServer(
            listener,
            allowed_machines=("app-server",),
            approver=self.planner,
            executor=executor,
            request_timeout_seconds=2.0,
            send_timeout_seconds=2.0,
            delivery_observer=executor.result_delivery_finished,
            control_service=control,
            activity_publisher=interface.publish_activity,
            external_active_count=lambda: coordinator.active_count,
        )
        broker.start()
        self.addCleanup(broker.stop)

        async def incident():
            async with Client(create_mcp_server(socket_path)) as client:
                warmup = await client.call_tool(
                    "run_argv",
                    {
                        "machine": "app-server",
                        "cwd": "/tmp",
                        "argv": ["true"],
                        "purpose": "establish a retained master",
                    },
                )
                old_path = next(self.pool.control_dir.iterdir())
                old_inode = old_path.stat().st_ino
                reboot = await client.call_tool(
                    "run_argv",
                    {
                        "machine": "app-server",
                        "cwd": "/tmp",
                        "argv": ["systemctl", "reboot"],
                        "purpose": "reboot the complete host",
                        "expect_full_reboot": True,
                    },
                )
                post_reboot = await client.call_tool(
                    "run_argv",
                    {
                        "machine": "app-server",
                        "cwd": "/tmp",
                        "argv": ["true"],
                        "purpose": "verify the fresh post-reboot transport",
                    },
                )
                return warmup, reboot, post_reboot, old_path, old_inode

        try:
            warmup, reboot, post_reboot, old_path, old_inode = asyncio.run(incident())
        finally:
            broker.stop()

        self.assertFalse(warmup.is_error)
        self.assertEqual(warmup.structured_content["transport_status"], "complete")
        self.assertFalse(reboot.is_error)
        self.assertEqual(
            reboot.structured_content["transport_status"],
            "abandoned_after_verified_reboot",
        )
        self.assertEqual(
            reboot.structured_content["result_code"],
            "abandoned_after_verified_reboot",
        )
        self.assertEqual(reboot.structured_content["stdout_length"], 0)
        self.assertEqual(reboot.structured_content["stderr_length"], 0)
        self.assertIsNone(reboot.structured_content["remote_exit_status"])
        self.assertFalse(post_reboot.is_error)
        self.assertEqual(
            post_reboot.structured_content["transport_status"], "complete"
        )
        self.assertEqual(len(probe.post_calls), 2)
        self.assertEqual(len(self.master_backend.starts), 2)
        self.assertEqual(len(self.master_backend.stops), 1)
        self.assertTrue(old_path.exists())
        self.assertNotEqual(old_path.stat().st_ino, old_inode)
        self.assertEqual(self.pool.pinned_request_ids, ())
        self.assertEqual(interface.prompt_calls, [])
        self.assertIsNone(self.pool.pinned_request_id)

    def test_verified_reboot_allows_next_request_through_a_fresh_master(self):
        reboot_spec = replace(
            request(("systemctl", "reboot")),
            disconnect_policy=DisconnectPolicy.EXPECT_FULL_REBOOT,
        )
        self.approve(reboot_spec)
        backend = AutoCompletingBackend()
        original_stage = backend.stage
        stage_calls = []

        def reset_first_stage(identity, submitted):
            stage_calls.append(identity.request_id)
            if len(stage_calls) == 1:
                raise RuntimeError("simulated SSH reset")
            return original_stage(identity, submitted)

        backend.stage = reset_first_stage
        probe = ExecutorBootProbe(
            pre_boot_id="11111111-2222-3333-4444-555555555555",
            post_boot_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        )
        interface = PlainTerminalInterface(
            NonPresentingTerminal(),
            approval_mode="disabled",
        )
        self.addCleanup(interface.close)
        executor = self.executor(
            backend,
            operator_interface=interface,
            reboot_recovery=self.reboot_coordinator(probe),
        )

        reboot_result = executor(REQUEST_ID, reboot_spec)
        starts_after_reboot = len(self.master_backend.starts)
        next_request_id = "f" * 32
        verification = request(("uname", "-a"))
        self.planner(next_request_id, verification)
        verification_result = executor(next_request_id, verification)

        self.assertEqual(
            reboot_result.transport_status,
            TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT,
        )
        self.assertEqual(verification_result.transport_status, TransportStatus.COMPLETE)
        self.assertEqual(starts_after_reboot, 1)
        self.assertEqual(len(self.master_backend.starts), 2)
        self.assertEqual(self.pool.pinned_request_ids, ())
        self.assertIsNone(interface._prompts.next_prompt(timeout=0))

    def test_recovering_machine_is_rejected_before_planning(self):
        probe = ExecutorBootProbe(
            pre_boot_id="11111111-2222-3333-4444-555555555555"
        )
        coordinator = self.reboot_coordinator(probe)
        coordinator.claim_expected_reboot("app-server", "f" * 32)
        spec = request(("true",))
        executor = self.executor(
            AutoCompletingBackend(),
            reboot_recovery=coordinator,
        )

        result = executor(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.RECOVERY_IN_PROGRESS)
        self.assertEqual(result.result_code, ResultCode.RECOVERY_IN_PROGRESS)
        with self.assertRaises(FileNotFoundError):
            self.state.load(REQUEST_ID)

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
