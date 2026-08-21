"""Evidence-driven automatic recovery for ordinary durable remote jobs."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import threading

from tmuxgate.remote_job import (
    CollectedRemoteFiles,
    RemoteJobCoordinator,
    RemoteJobError,
    RemoteJobIdentity,
    RemoteJobState,
)
from tmuxgate.scheduler import RequestState
from tmuxgate.ssh import ResolvedSshEndpoint
from tmuxgate.spool import ResultSpool
from tmuxgate.state import (
    DurableJobRecord,
    DurableStateStore,
    RemotePhase,
    STATE_FORMAT_VERSION,
)
from tmuxgate.transport import (
    MasterTransport,
    MasterTransportPool,
    TransportAuthorization,
    TransportLease,
)


class AutomaticRecoveryError(RuntimeError):
    """A recovery attempt failed without weakening durable uncertainty."""


@dataclass(frozen=True, slots=True)
class AutomaticRecoveryOutcome:
    request_id: str
    status: str
    detail: str
    manual_action_required: bool = False


RecoveryBackendFactory = Callable[[MasterTransport], object]


class _RecoveryLifecycle:
    def __init__(self, store: DurableStateStore, record: DurableJobRecord) -> None:
        self.store = store
        self.record = record

    def staging_verified(self) -> None:
        raise AutomaticRecoveryError("recovery never repeats staging")

    def before_remote_wrapper(self) -> None:
        raise AutomaticRecoveryError("recovery never creates an unrecorded wrapper")

    def remote_wrapper_created(self) -> None:
        if self.record.remote_phase is RemotePhase.REMOTE_WRAPPER_REQUESTED:
            self.record = self.store.mark_remote_wrapper_created(self.record)

    def user_command_started(self) -> None:
        self.record = self.store.mark_user_command_started(self.record)


class AutomaticRecoveryCoordinator:
    """Repeatedly reconcile exact durable identities using authenticated evidence."""

    def __init__(
        self,
        *,
        state: DurableStateStore,
        spool: ResultSpool,
        transports: MasterTransportPool,
        backend_factory: RecoveryBackendFactory,
    ) -> None:
        self.state = state
        self.spool = spool
        self.transports = transports
        self.backend_factory = backend_factory
        self._lock = threading.Lock()
        self._leases: dict[str, TransportLease] = {}

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._leases)

    def close(self) -> None:
        with self._lock:
            leases = tuple(self._leases.values())
            self._leases.clear()
        for lease in leases:
            lease.release()

    @staticmethod
    def _authorization(record: DurableJobRecord) -> TransportAuthorization:
        if any(
            value is None
            for value in (
                record.connection_plan_sha256,
                record.endpoint_id,
                record.resolved_identity_sha256,
            )
        ):
            raise AutomaticRecoveryError("durable recovery identity is incomplete")
        binding = hashlib.sha256(
            (
                "tmuxgate-recovery-v1\0"
                + record.request_id
                + "\0"
                + str(record.generation)
                + "\0"
                + record.client_request_sha256
            ).encode("ascii")
        ).hexdigest()
        return TransportAuthorization(
            request_id=record.request_id,
            machine_name=record.machine_alias,
            endpoint_id=record.endpoint_id,
            connection_plan_sha256=record.connection_plan_sha256,
            approval_binding_sha256=binding,
            resolved_identity_sha256=record.resolved_identity_sha256,
            allow_key_enrollment=False,
        )

    def _lease(
        self,
        record: DurableJobRecord,
        endpoint: ResolvedSshEndpoint,
    ) -> TransportLease:
        with self._lock:
            existing = self._leases.get(record.request_id)
        if existing is not None:
            return existing
        lease = self.transports.acquire(self._authorization(record), endpoint)
        with self._lock:
            winner = self._leases.setdefault(record.request_id, lease)
        if winner is not lease:
            lease.release()
        return winner

    def _release(self, request_id: str) -> None:
        with self._lock:
            lease = self._leases.pop(request_id, None)
        if lease is not None:
            lease.release()

    def _terminalize_safe_pre_wrapper(
        self, record: DurableJobRecord
    ) -> AutomaticRecoveryOutcome:
        detail = (
            "automatic reconciliation proved the broker stopped at durable phase "
            f"{record.remote_phase.value}, before any remote-wrapper request or "
            "user-command start marker"
        )
        if record.state is RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE:
            record = self.state.fail_remote_setup(record, detail=detail)
            status = "failed-remote-setup"
        else:
            record = self.state.fail_pre_remote(record, detail=detail)
            status = "failed-pre-remote"
        self._release(record.request_id)
        return AutomaticRecoveryOutcome(record.request_id, status, detail)

    def _advance_from_observation(self, lifecycle, observation) -> None:
        if (
            lifecycle.record.remote_phase is RemotePhase.REMOTE_WRAPPER_REQUESTED
            and (
                observation.session_exists
                or observation.gate_released
                or observation.command_running
                or observation.completion_proven
            )
        ):
            lifecycle.remote_wrapper_created()
        if (
            lifecycle.record.remote_phase is RemotePhase.REMOTE_WRAPPER_CREATED
            and observation.gate_released
        ):
            lifecycle.user_command_started()

    def _store_collected(self, request_id: str, collected):
        if isinstance(collected, CollectedRemoteFiles):
            try:
                return self.spool.store_files(
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
        return self.spool.store(
            request_id,
            collected.stdout,
            collected.stderr,
            collected.exit_status,
        )

    def _publish_recovered_result(self, record: DurableJobRecord) -> DurableJobRecord:
        if record.state is RequestState.LOCAL_SPOOL_VERIFIED:
            record = self.state.release_lease(record)
        if record.state is RequestState.LEASE_RELEASED:
            record = self.state.begin_result_delivery(record)
        return record

    def reconcile(
        self,
        record: DurableJobRecord,
        endpoint: ResolvedSshEndpoint,
    ) -> AutomaticRecoveryOutcome:
        """Perform one idempotent pass; callers may retry after any exception."""

        record = self.state.load(record.request_id)
        terminal = record.state in {
            RequestState.CANCELLED_BEFORE_APPROVAL,
            RequestState.DENIED,
            RequestState.FAILED_PRE_REMOTE,
            RequestState.FAILED_REMOTE_SETUP,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
            RequestState.ABANDONED_AFTER_OPERATOR_ACKNOWLEDGED_UNCERTAINTY,
            RequestState.ABANDONED_AFTER_PROVEN_UNSTARTED,
            RequestState.ABANDONED_AFTER_VERIFIED_REBOOT,
            RequestState.DONE,
        }
        if record.record_version == STATE_FORMAT_VERSION and record.remote_phase in {
            RemotePhase.CONNECTION_ATTEMPTED,
            RemotePhase.STAGING_REQUESTED,
            RemotePhase.STAGING_VERIFIED,
        } and record.state in {
            RequestState.APPROVED_PRE_REMOTE,
            RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
        }:
            return self._terminalize_safe_pre_wrapper(record)

        if record.remote_phase is RemotePhase.NOT_ATTEMPTED:
            return AutomaticRecoveryOutcome(
                record.request_id, "no-action", "no remote phase requires recovery"
            )

        if record.remote_phase is RemotePhase.CLEANUP_COMPLETED:
            record = self._publish_recovered_result(record)
            self._release(record.request_id)
            return AutomaticRecoveryOutcome(
                record.request_id, "recovered", "verified result and cleanup are durable"
            )

        # A locally authenticated spool is sufficient to unblock result access;
        # remote cleanup is retried independently and may never erase uncertainty.
        if record.remote_phase is RemotePhase.RESULT_SPOOL_LOCALLY_VERIFIED:
            record = self._publish_recovered_result(record)
            try:
                lease = self._lease(record, endpoint)
                backend = self.backend_factory(lease.transport)
                backend.cleanup(RemoteJobIdentity.for_request(record.request_id))
                record = self.state.mark_remote_cleanup_completed(record)
                self._release(record.request_id)
                return AutomaticRecoveryOutcome(
                    record.request_id, "recovered", "local result verified; cleanup proven"
                )
            except BaseException as exc:
                return AutomaticRecoveryOutcome(
                    record.request_id,
                    "result-recovered-cleanup-pending",
                    f"local result is verified; exact cleanup will retry: {exc}",
                )

        if terminal:
            self._release(record.request_id)
            return AutomaticRecoveryOutcome(
                record.request_id, "no-action", "durable job is already terminal"
            )

        legacy_uncertain = record.remote_phase is RemotePhase.LEGACY_UNCERTAIN
        if legacy_uncertain and record.resolved_identity_sha256 is None:
            return AutomaticRecoveryOutcome(
                record.request_id,
                "manual-action-required",
                "legacy record lacks an exact resolved endpoint identity and has only "
                "the old broad mutation marker; safe remote observation is unavailable",
                manual_action_required=True,
            )

        lease = self._lease(record, endpoint)
        backend = self.backend_factory(lease.transport)
        identity = RemoteJobIdentity.for_request(record.request_id)
        observation = backend.observe(identity)
        if legacy_uncertain:
            if (
                observation.gate_released
                or observation.command_running
                or observation.completion_proven
            ):
                observed_phase = RemotePhase.USER_COMMAND_STARTED
                detail = (
                    "authenticated exact-job observation upgraded the legacy broad "
                    "marker to user-command-started"
                )
            elif observation.session_exists:
                observed_phase = RemotePhase.REMOTE_WRAPPER_CREATED
                detail = (
                    "authenticated exact-job observation proved a gated legacy "
                    "wrapper exists and no command-start marker exists"
                )
            else:
                detail = (
                    "legacy broad mutation marker remains irreducible after exact "
                    "observation: session_exists=0, gate_released=0, "
                    "command_running=0, completion_proven=0; missing artifacts do "
                    "not prove that the old command never started"
                )
                if record.failure_detail != detail:
                    record = self.state.mark_recovery_required(record, detail=detail)
                self._release(record.request_id)
                return AutomaticRecoveryOutcome(
                    record.request_id,
                    "manual-action-required",
                    detail,
                    manual_action_required=True,
                )
            record = self.state.upgrade_legacy_remote_observation(
                record,
                observed_phase=observed_phase,
                detail=detail,
            )
        lifecycle = _RecoveryLifecycle(self.state, record)
        self._advance_from_observation(lifecycle, observation)
        record = lifecycle.record

        if (
            record.remote_phase in {
                RemotePhase.REMOTE_WRAPPER_REQUESTED,
                RemotePhase.REMOTE_WRAPPER_CREATED,
            }
            and not observation.session_exists
            and not observation.gate_released
            and not observation.command_running
            and not observation.completion_proven
        ):
            discard = getattr(backend, "discard_unstarted", None)
            if not callable(discard):
                raise AutomaticRecoveryError("backend cannot discard proven unstarted job")
            discard(identity)
            detail = (
                "authenticated exact-job observation proved session_exists=0, "
                "gate_released=0, command_running=0, completion_proven=0; guarded "
                "unstarted staging was removed"
            )
            self.state.fail_before_command_after_verified_observation(
                record, detail=detail
            )
            self._release(record.request_id)
            return AutomaticRecoveryOutcome(
                record.request_id, "failed-pre-remote", detail
            )

        coordinator = RemoteJobCoordinator(backend, lifecycle=lifecycle)
        job = coordinator.adopt(
            record.request_id,
            record.client_request_sha256,
            record.generation,
            observation,
        )
        if job.state is RemoteJobState.GATED_WAITING_FOR_VIEWER:
            coordinator.attach_and_start(job)
            return AutomaticRecoveryOutcome(
                record.request_id, "running", "gated wrapper was reattached and started"
            )
        if job.state is RemoteJobState.RUNNING_DETACHED:
            coordinator.reattach(job)
            return AutomaticRecoveryOutcome(
                record.request_id, "running", "detached running job was reattached"
            )
        if job.state is RemoteJobState.RUNNING_ATTACHED:
            return AutomaticRecoveryOutcome(
                record.request_id, "running", "exact remote session remains attached"
            )
        if job.state is RemoteJobState.COMPLETE_WAITING_FOR_DETACH:
            viewer = backend.attach(identity)
            terminate = getattr(viewer, "terminate", None)
            if not callable(terminate):
                raise RemoteJobError("completed stale viewer cannot be terminated safely")
            terminate()
            observation = backend.observe(identity)
            if observation.attached_clients != 0 or not observation.completion_proven:
                raise RemoteJobError("completed viewer detach was not proven")
            coordinator.refresh(job)
        if job.state is RemoteJobState.COMPLETE_DETACHED:
            record = lifecycle.record
            if record.remote_phase is RemotePhase.USER_COMMAND_STARTED:
                record = self.state.mark_completion_proven(
                    record, exit_status=observation.exit_status
                )
            if not record.viewer_detached:
                record = self.state.mark_viewer_detached(record)
            if not record.terminal_restored:
                record = self.state.mark_terminal_restored(record)
            collected = coordinator.collect(job)
            spooled = self._store_collected(record.request_id, collected)
            record = self.state.mark_local_spool_verified(
                record, manifest_sha256=spooled.manifest_payload_sha256
            )
            try:
                coordinator.cleanup(job)
                record = self.state.mark_remote_cleanup_completed(record)
            finally:
                record = self._publish_recovered_result(record)
                self._release(record.request_id)
            return AutomaticRecoveryOutcome(
                record.request_id,
                "recovered",
                "authenticated remote result was collected and verified locally",
            )

        detail = (
            "command-start evidence exists, but the exact remote job has neither "
            "a complete authenticated result nor authoritative termination evidence; "
            f"phase={record.remote_phase.value}, session_exists="
            f"{int(observation.session_exists)}, gate_released="
            f"{int(observation.gate_released)}, command_running="
            f"{int(observation.command_running)}, completion_proven="
            f"{int(observation.completion_proven)}"
        )
        if (
            record.state is not RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING
            or record.failure_detail != detail
        ):
            record = self.state.mark_recovery_required(record, detail=detail)
        return AutomaticRecoveryOutcome(
            record.request_id,
            "manual-action-required",
            detail,
            manual_action_required=True,
        )
