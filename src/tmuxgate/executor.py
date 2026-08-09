"""Composition of approved planning, SSH transport, remote jobs, and spool."""

from __future__ import annotations

from collections.abc import Callable
import threading
import time

from tmuxgate.approval import ApprovalDecision
from tmuxgate.connection_plan import ConnectionPlan, PlannedEndpoint
from tmuxgate.models import RequestSpec
from tmuxgate.operator_interface import (
    ActivityKind,
    ConnectionPhase,
    MachineDisablePrompt,
    OperationalActivity,
    OperatorInterface,
    RemoteMutationState,
    RouteFallbackPrompt,
    SecretInputRecipient,
    SshRetryPrompt,
    require_operator_decision,
)
from tmuxgate.planning import BoundRequestPlanner
from tmuxgate.remote_job import (
    CollectedRemoteFiles,
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


def _bounded_detail(detail: str, fallback: str) -> str:
    """Keep a durable failure detail non-empty, NUL-free, and bounded."""

    text = detail.replace("\x00", "\ufffd")[:1000].strip()
    return text or fallback


class _DurablePreRemoteBoundary:
    """Own the approved request's durable record before any remote mutation.

    The record exists from the moment the bound approval is consumed, so a
    request that fails before SSH transport is established still leaves a
    truthful terminal record instead of nothing at all.
    """

    def __init__(
        self,
        state: DurableStateStore,
        request_id: str,
        request: RequestSpec,
        plan: ConnectionPlan,
    ) -> None:
        self.state = state
        self.request_id = request_id
        self.request = request
        self.plan = plan
        self.record: DurableJobRecord | None = None

    def approve(self, endpoint: PlannedEndpoint | None = None) -> DurableJobRecord:
        if self.record is not None:
            raise ExecutorError("the approved durable record was already written")
        approved = new_approved_job_record(
            self.request_id,
            self.request,
            self.plan,
            planned_endpoint=endpoint,
        )
        self.record = self.state.write(approved)
        return self.record

    def require_record(self) -> DurableJobRecord:
        if self.record is None:
            raise ExecutorError("the approved durable record was never written")
        return self.record

    def retarget(self, endpoint: PlannedEndpoint) -> DurableJobRecord:
        self.record = self.state.retarget_pre_remote_endpoint(
            self.require_record(),
            self.plan,
            endpoint,
        )
        return self.record

    def arm_key_enrollment(self) -> DurableJobRecord:
        self.record = self.state.arm_key_enrollment(self.require_record())
        return self.record

    def mark_key_enrollment_verified(self) -> DurableJobRecord:
        self.record = self.state.mark_key_enrollment_verified(self.require_record())
        return self.record

    def fail_pre_remote(self, detail: str) -> None:
        """Terminalize an approved record that never reached a remote host."""

        record = self.record
        if record is None or record.state is not RequestState.APPROVED_PRE_REMOTE:
            return
        try:
            self.record = self.state.fail_pre_remote(
                record,
                detail=_bounded_detail(
                    detail, "the request failed before SSH transport was established"
                ),
            )
        except BaseException:
            # The already-fsynced approved record stays truthful and startup
            # recovery terminalizes it; the caller's failure result still holds.
            pass

    def fail_remote_setup(self, detail: str) -> DurableJobRecord:
        record = self.require_record()
        try:
            if record.state in {
                RequestState.KEY_ENROLLMENT_MAY_HAVE_STARTED,
                RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
            }:
                self.record = self.state.fail_remote_setup(
                    record,
                    detail=_bounded_detail(
                        detail, "remote setup failed after a possible key enrollment"
                    ),
                )
        except BaseException:
            # The already-fsynced may-have-started record remains truthful and
            # startup recovery will terminalize it conservatively.
            pass
        return self.require_record()


class _DurableKeyEnrollmentLifecycle:
    """Bind a possible key append to the approved request before it starts."""

    def __init__(
        self,
        boundary: _DurablePreRemoteBoundary,
        endpoint: PlannedEndpoint,
    ) -> None:
        self.boundary = boundary
        self.endpoint = endpoint
        self.armed = False

    @property
    def record(self) -> DurableJobRecord:
        return self.boundary.require_record()

    def before_remote_mutation(self, resolved: ResolvedSshEndpoint) -> None:
        if resolved != self.endpoint.resolved:
            raise KeyEnrollmentBoundaryError(
                "key enrollment endpoint differs from the approved route"
            )
        if self.armed:
            raise KeyEnrollmentBoundaryError(
                "key enrollment mutation boundary was requested more than once"
            )
        self.armed = True
        try:
            self.boundary.arm_key_enrollment()
        except BaseException as exc:
            self.boundary.fail_pre_remote("durable SSH key-enrollment boundary failed")
            raise KeyEnrollmentBoundaryError(
                "durable SSH key-enrollment boundary failed before remote mutation"
            ) from exc

    def remote_mutation_verified(self, resolved: ResolvedSshEndpoint) -> None:
        if resolved != self.endpoint.resolved or not self.armed:
            raise KeyEnrollmentMutationError(
                "key enrollment verification is not bound to the armed endpoint"
            )
        self.boundary.mark_key_enrollment_verified()

    def fail_after_remote_mutation(self, detail: str) -> DurableJobRecord:
        if not self.record.remote_mutation_started:
            raise ExecutorError("key enrollment failure lacks a durable mutation record")
        return self.boundary.fail_remote_setup(detail)


RemoteBackendFactory = Callable[[MasterTransport, SecretInputRecipient], object]
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

    def _publish_connection(
        self,
        request_id: str,
        request: RequestSpec,
        phase: ConnectionPhase,
        message: str,
        *,
        endpoint_id: str | None = None,
        remote_mutation_state: RemoteMutationState = RemoteMutationState.NOT_STARTED,
        details: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.operator_interface.publish_activity(
            OperationalActivity.create(
                ActivityKind.CONNECTION,
                message,
                request_id=request_id,
                machine_name=request.machine_alias,
                endpoint_id=endpoint_id,
                details=details,
                connection_phase=phase,
                remote_mutation_state=remote_mutation_state,
            )
        )

    def _acquire_transport(
        self,
        request_id: str,
        request: RequestSpec,
        plan: ConnectionPlan,
        boundary: _DurablePreRemoteBoundary,
    ) -> tuple[TransportLease, PlannedEndpoint, DurableJobRecord]:
        failure: BaseException | None = None
        failure_diagnostics = b""
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
                self._publish_connection(
                    request_id,
                    request,
                    ConnectionPhase.FALLBACK_DECISION,
                    "SSH setup failed before remote mutation; a separate route "
                    "fallback decision is required.",
                    endpoint_id=previous.resolved.endpoint_id,
                )
                prompt = RouteFallbackPrompt.create(
                        request_id,
                        request,
                        plan,
                        failed_endpoint_id=previous.resolved.endpoint_id,
                        fallback_endpoint_id=endpoint.resolved.endpoint_id,
                        failure_detail=str(failure)[:500],
                        remote_mutation_state=RemoteMutationState.NOT_STARTED,
                        openssh_diagnostics=failure_diagnostics,
                    )
                decision = require_operator_decision(
                    prompt,
                    self.operator_interface.request_fallback(prompt),
                )
                if decision is not ApprovalDecision.APPROVED:
                    raise TransportError("human denied the next approved fallback")
                self._publish_connection(
                    request_id,
                    request,
                    ConnectionPhase.CONNECTING,
                    "Connecting through the separately approved fallback route; "
                    "the remote command has not started.",
                    endpoint_id=endpoint.resolved.endpoint_id,
                )
                authorization = issue_fallback_transport_authorization(
                    request_id,
                    request,
                    plan,
                    failed_endpoint_id=previous.resolved.endpoint_id,
                    fallback_endpoint_id=endpoint.resolved.endpoint_id,
                    fallback_decision=decision,
                )
            # Route fallback happens only before remote mutation, so the
            # approved record can truthfully follow the plan to this endpoint.
            boundary.retarget(endpoint)
            ssh_attempt = 0
            failure_diagnostics = b""
            while True:
                if ssh_attempt == 0:
                    self._publish_connection(
                        request_id,
                        request,
                        ConnectionPhase.CONNECTING,
                        "Establishing the approved SSH connection; remote setup "
                        "is occurring and the requested command has not started.",
                        endpoint_id=endpoint.resolved.endpoint_id,
                    )
                enrollment = _DurableKeyEnrollmentLifecycle(boundary, endpoint)
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
                    self._publish_connection(
                        request_id,
                        request,
                        ConnectionPhase.FAILED,
                        detail,
                        endpoint_id=endpoint.resolved.endpoint_id,
                        remote_mutation_state=RemoteMutationState.MAY_HAVE_STARTED,
                    )
                    raise RemoteSetupFailure(detail, record) from exc
                except SshMasterStartError as exc:
                    failure = exc
                    failure_diagnostics = exc.diagnostics
                    if ssh_attempt == 0:
                        self._publish_connection(
                            request_id,
                            request,
                            ConnectionPhase.RETRY_DECISION,
                            "OpenSSH setup failed before remote mutation; one "
                            "same-endpoint retry is available.",
                            endpoint_id=endpoint.resolved.endpoint_id,
                            details=(("retry_limit", "1"),),
                        )
                        prompt = SshRetryPrompt.create(
                                request_id,
                                request,
                                plan,
                                endpoint_id=endpoint.resolved.endpoint_id,
                                failure_detail=str(exc)[:500],
                                remote_mutation_state=(
                                    RemoteMutationState.NOT_STARTED
                                ),
                                openssh_diagnostics=failure_diagnostics,
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
                            self._publish_connection(
                                request_id,
                                request,
                                ConnectionPhase.RETRYING,
                                "Retrying approved SSH setup once; the remote "
                                "command has not started.",
                                endpoint_id=endpoint.resolved.endpoint_id,
                                details=(("retry", "1 of 1"),),
                            )
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
                    if enrollment.record.remote_mutation_started:
                        detail = (
                            f"SSH setup on {endpoint.resolved.endpoint_id} failed "
                            f"after verified key enrollment: {exc}; retry and route "
                            "fallback were not attempted"
                        )
                        record = enrollment.fail_after_remote_mutation(detail)
                        self._publish_connection(
                            request_id,
                            request,
                            ConnectionPhase.FAILED,
                            detail,
                            endpoint_id=endpoint.resolved.endpoint_id,
                            remote_mutation_state=RemoteMutationState.STARTED,
                        )
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
            self._publish_connection(
                request_id,
                request,
                ConnectionPhase.FAILED,
                "The approved connection plan was unusable; no remote command "
                "or mutation started.",
            )
            return ExecutionResult(
                request_id,
                TransportStatus.PRE_REMOTE_FAILURE,
                detail=f"approved connection plan was not usable: {exc}",
            )
        # Approval is final once the one-shot plan has been consumed, so the
        # approved record is written here.  Everything after this point leaves
        # a durable trace even when no remote host is ever contacted.
        boundary = _DurablePreRemoteBoundary(
            self.state,
            request_id,
            request,
            context.connection_plan,
        )
        try:
            boundary.approve()
        except BaseException as exc:
            self._publish_connection(
                request_id,
                request,
                ConnectionPhase.FAILED,
                "The approved request could not be recorded durably; no remote "
                "command or mutation started.",
            )
            return ExecutionResult(
                request_id,
                TransportStatus.PRE_REMOTE_FAILURE,
                detail=f"approved request could not be recorded durably: {exc}",
            )
        try:
            lease, endpoint, approved = self._acquire_transport(
                request_id,
                request,
                context.connection_plan,
                boundary,
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
            detail = f"SSH transport was not established: {exc}{disable_detail}"
            boundary.fail_pre_remote(detail)
            self._publish_connection(
                request_id,
                request,
                ConnectionPhase.FAILED,
                "All approved SSH setup attempts ended before remote execution.",
            )
            return ExecutionResult(
                request_id,
                TransportStatus.PRE_REMOTE_FAILURE,
                detail=detail,
            )
        except BaseException as exc:
            detail = f"SSH transport was not established: {exc}"
            boundary.fail_pre_remote(detail)
            self._publish_connection(
                request_id,
                request,
                ConnectionPhase.FAILED,
                "SSH transport was not established; no requested command started.",
            )
            return ExecutionResult(
                request_id,
                TransportStatus.PRE_REMOTE_FAILURE,
                detail=detail,
            )

        try:
            armed, permit = self.state.arm_remote_start(approved)
            self._publish_connection(
                request_id,
                request,
                ConnectionPhase.REMOTE_STARTING,
                "SSH setup is complete; the durable remote-execution boundary "
                "is armed and the requested command is starting.",
                endpoint_id=endpoint.resolved.endpoint_id,
                remote_mutation_state=(
                    RemoteMutationState.STARTED
                    if approved.remote_mutation_started
                    else RemoteMutationState.NOT_STARTED
                ),
            )
        except BaseException as exc:
            try:
                if approved.state is RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE:
                    boundary.fail_remote_setup(
                        "durable command-start boundary failed after verified "
                        f"SSH key enrollment: {str(exc)[:800]}"
                    )
                else:
                    boundary.fail_pre_remote(
                        f"durable remote-start boundary failed: {exc}"
                    )
            finally:
                lease.release()
            if approved.remote_mutation_started:
                self._publish_connection(
                    request_id,
                    request,
                    ConnectionPhase.FAILED,
                    "Remote setup mutation is durable, but the requested command "
                    "did not cross its start boundary.",
                    endpoint_id=endpoint.resolved.endpoint_id,
                    remote_mutation_state=RemoteMutationState.STARTED,
                )
                return ExecutionResult(
                    request_id,
                    TransportStatus.REMOTE_SETUP_FAILURE,
                    detail=(
                        "SSH key enrollment was verified, but the durable command-start "
                        f"boundary failed: {exc}; no route fallback was attempted"
                    ),
                )
            self._publish_connection(
                request_id,
                request,
                ConnectionPhase.FAILED,
                "The durable remote-start boundary failed before remote execution.",
                endpoint_id=endpoint.resolved.endpoint_id,
            )
            return ExecutionResult(
                request_id,
                TransportStatus.PRE_REMOTE_FAILURE,
                detail=f"durable remote-start boundary failed: {exc}",
            )

        coordinator: RemoteJobCoordinator | None = None
        job: RemoteJob | None = None
        try:
            recipient = SecretInputRecipient(
                request_id,
                request,
                context.connection_plan,
                endpoint.resolved.endpoint_id,
            )
            backend = self.backend_factory(lease.transport, recipient)
            coordinator = RemoteJobCoordinator(backend)
            job = coordinator.prepare(request_id, request, permit)
            coordinator.attach_and_start(job)
            self._publish_connection(
                request_id,
                request,
                ConnectionPhase.RUNNING,
                "Remote execution is running; SSH setup has completed.",
                endpoint_id=endpoint.resolved.endpoint_id,
                remote_mutation_state=RemoteMutationState.STARTED,
            )
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
            if isinstance(collected, CollectedRemoteFiles):
                try:
                    spooled = self.spool.store_files(
                        request_id,
                        collected.stdout_path,
                        collected.stderr_path,
                        stdout_size=collected.stdout_size,
                        stdout_sha256=collected.stdout_sha256,
                        stderr_size=collected.stderr_size,
                        stderr_sha256=collected.stderr_sha256,
                        exit_status=collected.exit_status,
                    )
                finally:
                    collected.close()
            else:
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
            self._publish_connection(
                request_id,
                request,
                ConnectionPhase.COMPLETED,
                "Remote execution completed and its result was verified locally.",
                endpoint_id=endpoint.resolved.endpoint_id,
                remote_mutation_state=RemoteMutationState.STARTED,
            )
            return ExecutionResult(
                request_id,
                TransportStatus.COMPLETE,
                stdout=spooled.stdout,
                stderr=spooled.stderr,
                remote_exit_status=spooled.exit_status,
            )
        except BaseException as exc:
            self._publish_connection(
                request_id,
                request,
                ConnectionPhase.FAILED,
                "Remote execution is incomplete; recovery evidence was retained.",
                endpoint_id=endpoint.resolved.endpoint_id,
                remote_mutation_state=RemoteMutationState.STARTED,
            )
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
