"""Composition of approved planning, SSH transport, remote jobs, and spool."""

from __future__ import annotations

from collections.abc import Callable
import threading
import time

from tmuxgate.approval import ApprovalDecision
from tmuxgate.connection_plan import ConnectionPlan, PlannedEndpoint
from tmuxgate.models import RequestSpec
from tmuxgate.operator_interface import (
    MachineDisablePrompt,
    OperatorInterface,
    RemoteMutationState,
    RouteFallbackPrompt,
    SshRetryPrompt,
    require_operator_decision,
)
from tmuxgate.planning import BoundRequestPlanner
from tmuxgate.remote_job import (
    RemoteJob,
    RemoteJobCoordinator,
    RemoteJobError,
    RemoteJobState,
)
from tmuxgate.result import ExecutionResult, TransportStatus
from tmuxgate.scheduler import RequestState
from tmuxgate.ssh import ResolvedSshEndpoint
from tmuxgate.spool import ResultSpool
from tmuxgate.state import DurableJobRecord, DurableStateStore, new_approved_job_record
from tmuxgate.transport import (
    KeyEnrollmentMutationError,
    MasterTransport,
    MasterTransportPool,
    SshMasterStartError,
    TransportError,
    TransportLease,
    issue_fallback_transport_authorization,
    issue_selected_transport_authorization,
)


class ExecutorError(RuntimeError):
    """The composed executor violated a lifecycle invariant."""


class SshEndpointsExhaustedError(TransportError):
    """Every approved endpoint exhausted its bounded SSH master retry."""


class KeyEnrollmentBoundaryError(TransportError):
    """The durable enrollment boundary could not be established safely."""


class RemoteSetupFailure(TransportError):
    """A remote setup mutation occurred, so retry and fallback are forbidden."""

    def __init__(self, detail: str, record: DurableJobRecord) -> None:
        super().__init__(detail)
        self.record = record


class _DurableKeyEnrollmentLifecycle:
    """Bind a possible key append to the approved request before it starts."""

    def __init__(
        self,
        state: DurableStateStore,
        request_id: str,
        request: RequestSpec,
        plan: ConnectionPlan,
        endpoint: PlannedEndpoint,
    ) -> None:
        self.state = state
        self.request_id = request_id
        self.request = request
        self.plan = plan
        self.endpoint = endpoint
        self.record: DurableJobRecord | None = None

    def before_remote_mutation(self, resolved: ResolvedSshEndpoint) -> None:
        if resolved != self.endpoint.resolved:
            raise KeyEnrollmentBoundaryError(
                "key enrollment endpoint differs from the approved route"
            )
        if self.record is not None:
            raise KeyEnrollmentBoundaryError(
                "key enrollment mutation boundary was requested more than once"
            )
        try:
            approved = new_approved_job_record(
                self.request_id,
                self.request,
                self.plan,
                planned_endpoint=self.endpoint,
            )
            self.record = self.state.write(approved)
            self.record = self.state.arm_key_enrollment(self.record)
        except BaseException as exc:
            if (
                self.record is not None
                and self.record.state is RequestState.APPROVED_PRE_REMOTE
            ):
                try:
                    self.record = self.state.fail_pre_remote(
                        self.record,
                        detail="durable SSH key-enrollment boundary failed",
                    )
                except BaseException:
                    pass
            raise KeyEnrollmentBoundaryError(
                "durable SSH key-enrollment boundary failed before remote mutation"
            ) from exc

    def remote_mutation_verified(self, resolved: ResolvedSshEndpoint) -> None:
        if resolved != self.endpoint.resolved or self.record is None:
            raise KeyEnrollmentMutationError(
                "key enrollment verification is not bound to the armed endpoint"
            )
        self.record = self.state.mark_key_enrollment_verified(self.record)

    def fail_after_remote_mutation(self, detail: str) -> DurableJobRecord:
        if self.record is None or not self.record.remote_mutation_started:
            raise ExecutorError("key enrollment failure lacks a durable mutation record")
        try:
            if self.record.state in {
                RequestState.KEY_ENROLLMENT_MAY_HAVE_STARTED,
                RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
            }:
                self.record = self.state.fail_remote_setup(
                    self.record,
                    detail=detail[:1000],
                )
        except BaseException:
            # The already-fsynced may-have-started record remains truthful and
            # startup recovery will terminalize it conservatively.
            pass
        return self.record


RemoteBackendFactory = Callable[[MasterTransport], object]
DetachedHandler = Callable[[str], str]


def _ignore_machine_disable(_machine_name: str) -> None:
    return None


def _machine_enabled(_machine_name: str) -> bool:
    return True


def reattach_detached_job(request_id: str) -> str:
    """Automatically restore an unexpectedly lost isolated viewer."""

    return "reattach"


class RealExecutor:
    """Synchronous single-command executor called by the broker terminal worker."""

    def __init__(
        self,
        *,
        planner: BoundRequestPlanner,
        transports: MasterTransportPool,
        state: DurableStateStore,
        spool: ResultSpool,
        backend_factory: RemoteBackendFactory,
        operator_interface: OperatorInterface,
        machine_disabler: Callable[[str], object] = _ignore_machine_disable,
        machine_enabled: Callable[[str], bool] = _machine_enabled,
        detached_handler: DetachedHandler = reattach_detached_job,
        poll_interval_seconds: float = 0.25,
        detached_wait_seconds: float = 5.0,
    ) -> None:
        for name, callback in (
            ("backend_factory", backend_factory),
            ("machine_disabler", machine_disabler),
            ("machine_enabled", machine_enabled),
            ("detached_handler", detached_handler),
        ):
            if not callable(callback):
                raise TypeError(f"{name} must be callable")
        for method_name in (
            "request_ssh_retry",
            "request_fallback",
            "request_machine_disable",
            "publish_activity",
        ):
            if not callable(getattr(operator_interface, method_name, None)):
                raise TypeError(
                    f"operator_interface must provide callable {method_name}"
                )
        self.planner = planner
        self.transports = transports
        self.state = state
        self.spool = spool
        self.backend_factory = backend_factory
        self.operator_interface = operator_interface
        self.machine_disabler = machine_disabler
        self.machine_enabled = machine_enabled
        self.detached_handler = detached_handler
        self.poll_interval_seconds = float(poll_interval_seconds)
        self.detached_wait_seconds = float(detached_wait_seconds)
        self._delivery_records: dict[str, DurableJobRecord] = {}
        self._recovery_leases: dict[str, TransportLease] = {}
        self._recovery_jobs: dict[str, tuple[RemoteJobCoordinator, RemoteJob]] = {}
        self._records_lock = threading.Lock()

    @property
    def recovery_request_ids(self) -> tuple[str, ...]:
        with self._records_lock:
            return tuple(sorted(self._recovery_jobs))

    def _acquire_transport(
        self,
        request_id: str,
        request: RequestSpec,
        plan: ConnectionPlan,
    ) -> tuple[TransportLease, PlannedEndpoint, DurableJobRecord | None]:
        failure: BaseException | None = None
        all_endpoints_exhausted = True
        for index, endpoint in enumerate(plan.endpoints):
            if index == 0:
                authorization = issue_selected_transport_authorization(
                    request_id,
                    request,
                    plan,
                    ApprovalDecision.APPROVED,
                )
            else:
                previous = plan.endpoints[index - 1]
                prompt = RouteFallbackPrompt.create(
                        request_id,
                        request,
                        plan,
                        failed_endpoint_id=previous.resolved.endpoint_id,
                        fallback_endpoint_id=endpoint.resolved.endpoint_id,
                        failure_detail=str(failure)[:500],
                        remote_mutation_state=RemoteMutationState.NOT_STARTED,
                    )
                decision = require_operator_decision(
                    prompt,
                    self.operator_interface.request_fallback(prompt),
                )
                if decision is not ApprovalDecision.APPROVED:
                    raise TransportError("human denied the next approved fallback")
                authorization = issue_fallback_transport_authorization(
                    request_id,
                    request,
                    plan,
                    failed_endpoint_id=previous.resolved.endpoint_id,
                    fallback_endpoint_id=endpoint.resolved.endpoint_id,
                    fallback_decision=decision,
                )
            ssh_attempt = 0
            while True:
                enrollment = _DurableKeyEnrollmentLifecycle(
                    self.state,
                    request_id,
                    request,
                    plan,
                    endpoint,
                )
                try:
                    lease = self.transports.acquire(
                        authorization,
                        endpoint.resolved,
                        key_enrollment_lifecycle=enrollment,
                    )
                except KeyEnrollmentBoundaryError:
                    raise
                except KeyEnrollmentMutationError as exc:
                    detail = (
                        f"SSH key enrollment on {endpoint.resolved.endpoint_id} "
                        f"failed after remote mutation may have started: {exc}; "
                        "retry and route fallback were not attempted"
                    )
                    record = enrollment.fail_after_remote_mutation(detail)
                    raise RemoteSetupFailure(detail, record) from exc
                except SshMasterStartError as exc:
                    failure = exc
                    if ssh_attempt == 0:
                        prompt = SshRetryPrompt.create(
                                request_id,
                                request,
                                plan,
                                endpoint_id=endpoint.resolved.endpoint_id,
                                failure_detail=str(exc)[:500],
                                remote_mutation_state=(
                                    RemoteMutationState.NOT_STARTED
                                ),
                            )
                        decision = require_operator_decision(
                            prompt,
                            self.operator_interface.request_ssh_retry(prompt),
                        )
                        if decision is ApprovalDecision.APPROVED:
                            self.planner.revalidate_connection_plan(
                                request_id,
                                request,
                                plan,
                                retried_endpoint_id=endpoint.resolved.endpoint_id,
                            )
                            ssh_attempt += 1
                            continue
                        all_endpoints_exhausted = False
                        failure = TransportError(
                            f"{exc}; operator cancelled the same-endpoint retry"
                        )
                    else:
                        failure = TransportError(
                            f"{exc}; the broker-terminal-confirmed retry also failed"
                        )
                    break
                except TransportError as exc:
                    if (
                        enrollment.record is not None
                        and enrollment.record.remote_mutation_started
                    ):
                        detail = (
                            f"SSH setup on {endpoint.resolved.endpoint_id} failed "
                            f"after verified key enrollment: {exc}; retry and route "
                            "fallback were not attempted"
                        )
                        record = enrollment.fail_after_remote_mutation(detail)
                        raise RemoteSetupFailure(detail, record) from exc
                    all_endpoints_exhausted = False
                    failure = exc
                    break
                return lease, endpoint, enrollment.record
            if index + 1 == len(plan.endpoints):
                assert failure is not None
                if all_endpoints_exhausted:
                    raise SshEndpointsExhaustedError(str(failure)) from failure
                raise failure
        raise TransportError("no approved endpoint transport could be established")

    def _retain_recovery(
        self,
        request_id: str,
        record: DurableJobRecord,
        lease: TransportLease,
        detail: str,
        coordinator: RemoteJobCoordinator | None = None,
        job: RemoteJob | None = None,
    ) -> ExecutionResult:
        try:
            record = self.state.mark_recovery_required(record, detail=detail[:1000])
        except BaseException:
            pass
        with self._records_lock:
            self._recovery_leases[request_id] = lease
            if coordinator is not None and job is not None:
                self._recovery_jobs[request_id] = (coordinator, job)
        return ExecutionResult(
            request_id,
            TransportStatus.INCOMPLETE,
            detail=detail + "; command lease retained for recovery",
        )

    def _monitor(self, request_id: str, coordinator: RemoteJobCoordinator, job: RemoteJob) -> None:
        while True:
            state = coordinator.refresh(job)
            if state is RemoteJobState.COMPLETE_DETACHED:
                return
            if state is RemoteJobState.RECOVERY_REQUIRED:
                raise RemoteJobError("remote job entered recovery-required state")
            if state is RemoteJobState.RUNNING_DETACHED:
                action = self.detached_handler(request_id)
                if action == "reattach":
                    coordinator.reattach(job)
                elif action == "wait":
                    time.sleep(self.detached_wait_seconds)
                else:
                    raise ExecutorError("detached handler returned an invalid action")
                continue
            time.sleep(self.poll_interval_seconds)

    def __call__(self, request_id: str, request: RequestSpec) -> ExecutionResult:
        try:
            # Consuming the approved plan is still entirely local.  In
            # particular, a runtime machine disable can invalidate a queued
            # approval here before any SSH transport or durable remote-start
            # boundary exists.
            context = self.planner.take(request_id, request)
        except BaseException as exc:
            return ExecutionResult(
                request_id,
                TransportStatus.PRE_REMOTE_FAILURE,
                detail=f"approved connection plan was not usable: {exc}",
            )
        try:
            lease, endpoint, approved = self._acquire_transport(
                request_id,
                request,
                context.connection_plan,
            )
        except RemoteSetupFailure as exc:
            return ExecutionResult(
                request_id,
                TransportStatus.REMOTE_SETUP_FAILURE,
                detail=str(exc),
            )
        except SshEndpointsExhaustedError as exc:
            disable_detail = "; machine remains enabled"
            try:
                enabled = self.machine_enabled(request.machine_alias)
                if type(enabled) is not bool:
                    raise ExecutorError(
                        "machine availability callback returned invalid state"
                    )
                if not enabled:
                    disable_detail = "; machine was already disabled"
                else:
                    prompt = MachineDisablePrompt.create(
                            request_id,
                            request,
                            context.connection_plan,
                            failure_detail=str(exc)[:500],
                            remote_mutation_state=RemoteMutationState.NOT_STARTED,
                        )
                    decision = require_operator_decision(
                        prompt,
                        self.operator_interface.request_machine_disable(prompt),
                    )
                    if decision is ApprovalDecision.APPROVED:
                        self.machine_disabler(request.machine_alias)
                        disable_detail = "; machine disabled by operator"
                    elif not self.machine_enabled(request.machine_alias):
                        # Another failed request may have disabled the machine
                        # while this request waited for the terminal arbiter.
                        disable_detail = "; machine was already disabled"
            except BaseException as disable_exc:
                disable_detail = (
                    "; machine remains enabled because disabling failed: "
                    f"{str(disable_exc)[:500]}"
                )
            return ExecutionResult(
                request_id,
                TransportStatus.PRE_REMOTE_FAILURE,
                detail=f"SSH transport was not established: {exc}{disable_detail}",
            )
        except BaseException as exc:
            return ExecutionResult(
                request_id,
                TransportStatus.PRE_REMOTE_FAILURE,
                detail=f"SSH transport was not established: {exc}",
            )

        try:
            if approved is None:
                approved = new_approved_job_record(
                    request_id,
                    request,
                    context.connection_plan,
                    planned_endpoint=endpoint,
                )
                approved = self.state.write(approved)
            armed, permit = self.state.arm_remote_start(approved)
        except BaseException as exc:
            try:
                if (
                    approved is not None
                    and approved.state
                    is RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE
                ):
                    self.state.fail_remote_setup(
                        approved,
                        detail=(
                            "durable command-start boundary failed after verified "
                            f"SSH key enrollment: {str(exc)[:800]}"
                        ),
                    )
                elif approved is not None:
                    self.state.fail_pre_remote(approved, detail=str(exc)[:1000])
            finally:
                lease.release()
            if (
                approved is not None
                and approved.remote_mutation_started
            ):
                return ExecutionResult(
                    request_id,
                    TransportStatus.REMOTE_SETUP_FAILURE,
                    detail=(
                        "SSH key enrollment was verified, but the durable command-start "
                        f"boundary failed: {exc}; no route fallback was attempted"
                    ),
                )
            return ExecutionResult(
                request_id,
                TransportStatus.PRE_REMOTE_FAILURE,
                detail=f"durable remote-start boundary failed: {exc}",
            )

        coordinator: RemoteJobCoordinator | None = None
        job: RemoteJob | None = None
        try:
            backend = self.backend_factory(lease.transport)
            coordinator = RemoteJobCoordinator(backend)
            job = coordinator.prepare(request_id, request, permit)
            coordinator.attach_and_start(job)
            self._monitor(request_id, coordinator, job)

            observation = backend.observe(job.identity)
            if not observation.completion_proven or observation.attached_clients != 0:
                raise RemoteJobError("completion/detach could not be proven")
            armed = self.state.mark_completion_proven(
                armed,
                exit_status=observation.exit_status,
            )
            armed = self.state.mark_viewer_detached(armed)
            if job.viewer is not None and not job.viewer.attached:
                try:
                    job.viewer.wait(timeout=0)
                except (AttributeError, TimeoutError):
                    pass
            armed = self.state.mark_terminal_restored(armed)
            collected = coordinator.collect(job)
            spooled = self.spool.store(
                request_id,
                collected.stdout,
                collected.stderr,
                collected.exit_status,
            )
            armed = self.state.mark_local_spool_verified(
                armed,
                manifest_sha256=spooled.manifest_payload_sha256,
            )
            armed = self.state.release_lease(armed)
            try:
                coordinator.cleanup(job)
            except BaseException:
                # Cleanup is safe to retry later and is not a command-lease gate.
                pass
            lease.release()
            armed = self.state.begin_result_delivery(armed)
            with self._records_lock:
                self._delivery_records[request_id] = armed
            return ExecutionResult(
                request_id,
                TransportStatus.COMPLETE,
                stdout=spooled.stdout,
                stderr=spooled.stderr,
                remote_exit_status=spooled.exit_status,
            )
        except BaseException as exc:
            return self._retain_recovery(
                request_id,
                armed,
                lease,
                f"remote execution is incomplete: {exc}",
                coordinator,
                job,
            )

    def result_delivery_finished(self, request_id: str, delivered: bool) -> None:
        with self._records_lock:
            record = self._delivery_records.pop(request_id, None)
        if record is None or not delivered:
            return
        self.state.mark_done(record)

    def discard_approval(self, request_id: str) -> None:
        self.planner.discard(request_id)
