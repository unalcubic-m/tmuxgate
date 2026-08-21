"""Deterministic scheduling for bounded independent remote-command leases.

This module deliberately contains no I/O, clocks, threads, SSH, or tmux logic.
The broker feeds it facts that have already been established by the relevant
subsystem.  In particular, ``mark_local_spool_verified`` means the caller has
verified the canonical completion manifest and both local output streams.

An authenticated SSH ControlMaster is a transport, not a command lease.  This
scheduler models only the latter and permits a configured bounded number of
approved or possibly-running commands at a time.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import StrEnum

from tmuxgate.models import ValidationError, validate_alias, validate_request_id


class SchedulerError(RuntimeError):
    """Base class for invalid scheduler operations."""


class QueueFullError(SchedulerError):
    """The bounded, unapproved request queue is full."""


class DuplicateRequestError(SchedulerError):
    """A request ID has already been submitted."""


class UnknownRequestError(SchedulerError):
    """A request ID is not known to this scheduler."""


class LeaseBusyError(SchedulerError):
    """Another request owns the remote-command lease."""


class InvalidTransitionError(SchedulerError):
    """An event is not valid in the request's current state."""


class RequestState(StrEnum):
    QUEUED = "queued"
    CANCELLED_BEFORE_APPROVAL = "cancelled-before-approval"
    AWAITING_APPROVAL = "awaiting-approval"
    DENIED = "denied"
    APPROVED_PRE_REMOTE = "approved-pre-remote"
    KEY_ENROLLMENT_MAY_HAVE_STARTED = "key-enrollment-may-have-started"
    KEY_ENROLLMENT_VERIFIED_PRE_REMOTE = "key-enrollment-verified-pre-remote"
    REMOTE_MAY_BE_RUNNING = "remote-may-be-running"
    RECOVERY_REQUIRED_POSSIBLY_RUNNING = "recovery-required-possibly-running"
    EXPECTED_REBOOT_VERIFICATION_PENDING = "expected-reboot-verification-pending"
    EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING = (
        "expected-reboot-verified-cleanup-pending"
    )
    EXPECTED_REBOOT_RECOVERY_FAILED = "expected-reboot-recovery-failed"
    ABANDONED_AFTER_VERIFIED_REBOOT = "abandoned-after-verified-reboot"
    ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT = (
        "abandoned-after-operator-confirmed-reboot"
    )
    ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE = (
        "abandoned-after-operator-confirmed-dead-pane"
    )
    ABANDONED_AFTER_OPERATOR_ACKNOWLEDGED_UNCERTAINTY = (
        "abandoned-after-operator-acknowledged-uncertainty"
    )
    ABANDONED_AFTER_PROVEN_UNSTARTED = "abandoned-after-proven-unstarted"
    COMPLETION_PROVEN = "completion-proven"
    LOCAL_SPOOL_VERIFIED = "local-spool-verified"
    LEASE_RELEASED = "lease-released"
    FAILED_PRE_REMOTE = "failed-pre-remote"
    FAILED_REMOTE_SETUP = "failed-remote-setup"
    RESULT_DELIVERING = "result-delivering"
    DONE = "done"


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"


class LeaseReleaseReason(StrEnum):
    CANCELLED_BEFORE_APPROVAL = "cancelled-before-approval"
    DENIED = "denied"
    PRE_REMOTE_FAILURE = "pre-remote-failure"
    REMOTE_SETUP_FAILURE = "remote-setup-failure"
    VERIFIED_COMPLETION = "verified-completion"
    VERIFIED_REBOOT_ABANDONMENT = "verified-reboot-abandonment"
    RECOVERY_TRANSFERRED = "recovery-transferred"


_LEASE_HELD_STATES = frozenset(
    {
        RequestState.AWAITING_APPROVAL,
        RequestState.APPROVED_PRE_REMOTE,
        RequestState.REMOTE_MAY_BE_RUNNING,
        RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING,
        RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING,
        RequestState.COMPLETION_PROVEN,
        RequestState.LOCAL_SPOOL_VERIFIED,
    }
)

_REMOTE_LIFECYCLE_STATES = frozenset(
    {
        RequestState.REMOTE_MAY_BE_RUNNING,
        RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING,
        RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING,
        RequestState.COMPLETION_PROVEN,
        RequestState.LOCAL_SPOOL_VERIFIED,
    }
)

_RESULT_READY_STATES = frozenset(
    {
        RequestState.DENIED,
        RequestState.FAILED_PRE_REMOTE,
        RequestState.FAILED_REMOTE_SETUP,
        RequestState.LEASE_RELEASED,
        RequestState.ABANDONED_AFTER_VERIFIED_REBOOT,
        RequestState.EXPECTED_REBOOT_RECOVERY_FAILED,
    }
)

_FORGETTABLE_TERMINAL_STATES = frozenset(
    {
        RequestState.CANCELLED_BEFORE_APPROVAL,
        RequestState.DONE,
    }
)


@dataclass(frozen=True, slots=True)
class ScheduledRequest:
    """Immutable scheduling record for one broker request."""

    request_id: str
    sequence: int
    machine_alias: str = "default"
    state: RequestState = RequestState.QUEUED
    client_connected: bool = True
    decision: ApprovalDecision | None = None
    remote_may_be_running: bool = False
    completion_proven: bool = False
    remote_exit_status: int | None = None
    local_spool_verified: bool = False
    viewer_detached: bool = False
    terminal_restored: bool = False
    lease_release_reason: LeaseReleaseReason | None = None
    failure_detail: str | None = None


class SequentialScheduler:
    """FIFO scheduler for a bounded number of isolated remote commands.

    ``max_pending_requests`` bounds only the unapproved FIFO.  The current
    lease owner is not part of that count.  Submitting a request never reserves
    the lease; :meth:`begin_next_approval` does so immediately before the
    broker displays the approval UI.
    """

    def __init__(
        self,
        max_pending_requests: int = 16,
        max_active_remote_commands: int = 1,
        external_active_count: Callable[[], int] = lambda: 0,
    ) -> None:
        if (
            isinstance(max_pending_requests, bool)
            or not isinstance(max_pending_requests, int)
            or max_pending_requests < 1
        ):
            raise ValueError("max_pending_requests must be a positive integer")
        if (
            isinstance(max_active_remote_commands, bool)
            or not isinstance(max_active_remote_commands, int)
            or not 1 <= max_active_remote_commands <= 3
        ):
            raise ValueError("max_active_remote_commands must be from 1 to 3")
        self.max_pending_requests = max_pending_requests
        self.max_active_remote_commands = max_active_remote_commands
        if not callable(external_active_count):
            raise TypeError("external_active_count must be callable")
        self._external_active_count = external_active_count
        self._requests: dict[str, ScheduledRequest] = {}
        self._pending: deque[str] = deque()
        self._lease_owners: set[str] = set()
        self._next_sequence = 1

    @property
    def lease_owner(self) -> str | None:
        if len(self._lease_owners) > 1:
            raise LeaseBusyError("more than one remote-command lease is active")
        return next(iter(self._lease_owners), None)

    @property
    def lease_owners(self) -> tuple[str, ...]:
        return tuple(sorted(self._lease_owners))

    @property
    def active_count(self) -> int:
        return len(self._lease_owners) + self._validated_external_active_count()

    def _validated_external_active_count(self) -> int:
        value = self._external_active_count()
        if type(value) is not int or value < 0:
            raise SchedulerError("external active recovery count is invalid")
        return value

    @property
    def can_begin_approval(self) -> bool:
        return bool(self._pending) and (
            self.active_count < self.max_active_remote_commands
        )

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def pending_request_ids(self) -> tuple[str, ...]:
        return tuple(self._pending)

    @property
    def record_count(self) -> int:
        """Number of live/non-pruned scheduler records."""

        return len(self._requests)

    def request(self, request_id: str) -> ScheduledRequest:
        try:
            return self._requests[request_id]
        except KeyError as exc:
            raise UnknownRequestError(f"unknown request ID: {request_id}") from exc

    def submit(
        self, request_id: str, machine_alias: str = "default"
    ) -> ScheduledRequest:
        """Append a validated request ID to the bounded FIFO."""

        try:
            validated_id = validate_request_id(request_id)
        except ValidationError as exc:
            raise SchedulerError(str(exc)) from exc
        if validated_id in self._requests:
            raise DuplicateRequestError(f"duplicate request ID: {validated_id}")
        if len(self._pending) >= self.max_pending_requests:
            raise QueueFullError("pending request queue is full")

        try:
            validated_machine = validate_alias(
                machine_alias, field_name="machine alias"
            )
        except ValidationError as exc:
            raise SchedulerError(str(exc)) from exc
        record = ScheduledRequest(
            validated_id, self._next_sequence, validated_machine
        )
        self._next_sequence += 1
        self._requests[validated_id] = record
        self._pending.append(validated_id)
        self._assert_invariants()
        return record

    def begin_next_approval(self) -> ScheduledRequest | None:
        """Reserve the lease for the FIFO head immediately before approval."""

        if self.active_count >= self.max_active_remote_commands:
            raise LeaseBusyError("all remote-command lease slots are active")
        if not self._pending:
            return None

        request_id = self._pending.popleft()
        record = self._replace(
            request_id,
            state=RequestState.AWAITING_APPROVAL,
        )
        self._lease_owners.add(request_id)
        self._assert_invariants()
        return record

    def client_disconnected(self, request_id: str) -> ScheduledRequest:
        """Cancel unapproved work, but never cancel an approved remote job."""

        record = self.request(request_id)
        if not record.client_connected:
            return record

        if record.state is RequestState.QUEUED:
            self._pending.remove(request_id)
            record = self._replace(
                request_id,
                state=RequestState.CANCELLED_BEFORE_APPROVAL,
                client_connected=False,
            )
        elif record.state is RequestState.AWAITING_APPROVAL:
            record = self._replace(
                request_id,
                state=RequestState.CANCELLED_BEFORE_APPROVAL,
                client_connected=False,
                lease_release_reason=LeaseReleaseReason.CANCELLED_BEFORE_APPROVAL,
            )
            self._release_owner(request_id)
        else:
            # Once approved, disconnecting the waiting client must not stop,
            # kill, release, or rerun the remote job.
            record = self._replace(request_id, client_connected=False)

        self._assert_invariants()
        return record

    def approve(self, request_id: str) -> ScheduledRequest:
        record = self._require_state(request_id, RequestState.AWAITING_APPROVAL)
        self._require_lease_owner(request_id)
        record = self._replace(
            record.request_id,
            state=RequestState.APPROVED_PRE_REMOTE,
            decision=ApprovalDecision.APPROVED,
        )
        self._assert_invariants()
        return record

    def deny(self, request_id: str) -> ScheduledRequest:
        record = self._require_state(request_id, RequestState.AWAITING_APPROVAL)
        self._require_lease_owner(request_id)
        record = self._replace(
            record.request_id,
            state=RequestState.DENIED,
            decision=ApprovalDecision.DENIED,
            lease_release_reason=LeaseReleaseReason.DENIED,
        )
        self._release_owner(request_id)
        self._assert_invariants()
        return record

    def mark_pre_remote_failure(
        self, request_id: str, *, detail: str
    ) -> ScheduledRequest:
        """Record a proven pre-remote failure and safely release the lease."""

        record = self._require_state(request_id, RequestState.APPROVED_PRE_REMOTE)
        self._require_lease_owner(request_id)
        if not isinstance(detail, str) or not detail or "\x00" in detail:
            raise ValueError("failure detail must be a non-empty string without NUL")
        record = self._replace(
            record.request_id,
            state=RequestState.FAILED_PRE_REMOTE,
            lease_release_reason=LeaseReleaseReason.PRE_REMOTE_FAILURE,
            failure_detail=detail,
        )
        self._release_owner(request_id)
        self._assert_invariants()
        return record

    def mark_remote_setup_failure(
        self, request_id: str, *, detail: str
    ) -> ScheduledRequest:
        """Release a request whose setup mutated remote state but ran no job."""

        record = self._require_state(request_id, RequestState.APPROVED_PRE_REMOTE)
        self._require_lease_owner(request_id)
        if not isinstance(detail, str) or not detail or "\x00" in detail:
            raise ValueError("failure detail must be a non-empty string without NUL")
        record = self._replace(
            record.request_id,
            state=RequestState.FAILED_REMOTE_SETUP,
            lease_release_reason=LeaseReleaseReason.REMOTE_SETUP_FAILURE,
            failure_detail=detail,
        )
        self._release_owner(request_id)
        self._assert_invariants()
        return record

    def mark_remote_may_be_running(self, request_id: str) -> ScheduledRequest:
        """Cross the point after which failure must retain the lease."""

        record = self._require_state(request_id, RequestState.APPROVED_PRE_REMOTE)
        self._require_lease_owner(request_id)
        record = self._replace(
            record.request_id,
            state=RequestState.REMOTE_MAY_BE_RUNNING,
            remote_may_be_running=True,
        )
        self._assert_invariants()
        return record

    def mark_recovery_required(
        self, request_id: str, *, detail: str
    ) -> ScheduledRequest:
        """Retain the lease when the remote command might still be running."""

        record = self.request(request_id)
        if record.state not in {
            RequestState.REMOTE_MAY_BE_RUNNING,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        }:
            self._invalid_state(record, "mark recovery required")
        self._require_lease_owner(request_id)
        if not isinstance(detail, str) or not detail or "\x00" in detail:
            raise ValueError("recovery detail must be a non-empty string without NUL")
        record = self._replace(
            record.request_id,
            state=RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            failure_detail=detail,
        )
        self._assert_invariants()
        return record

    def mark_abandoned_after_verified_reboot(
        self, request_id: str, *, detail: str
    ) -> ScheduledRequest:
        """Release only after the executor committed changed-boot evidence."""

        record = self._require_state(request_id, RequestState.REMOTE_MAY_BE_RUNNING)
        self._require_lease_owner(request_id)
        if not isinstance(detail, str) or not detail or "\x00" in detail:
            raise ValueError("verified reboot detail must be non-empty text without NUL")
        record = self._replace(
            request_id,
            state=RequestState.ABANDONED_AFTER_VERIFIED_REBOOT,
            remote_may_be_running=False,
            lease_release_reason=LeaseReleaseReason.VERIFIED_REBOOT_ABANDONMENT,
            failure_detail=detail,
        )
        self._release_owner(request_id)
        self._assert_invariants()
        return record

    def mark_recovery_transferred(
        self, request_id: str, *, detail: str
    ) -> ScheduledRequest:
        """Move an unresolved reboot lease to the restart-survivable coordinator."""

        record = self._require_state(request_id, RequestState.REMOTE_MAY_BE_RUNNING)
        self._require_lease_owner(request_id)
        if not isinstance(detail, str) or not detail or "\x00" in detail:
            raise ValueError("transferred recovery detail must be non-empty text without NUL")
        record = self._replace(
            request_id,
            state=RequestState.EXPECTED_REBOOT_RECOVERY_FAILED,
            lease_release_reason=LeaseReleaseReason.RECOVERY_TRANSFERRED,
            failure_detail=detail,
        )
        self._release_owner(request_id)
        self._assert_invariants()
        return record

    def mark_remote_completion_proven(
        self, request_id: str, *, exit_status: int
    ) -> ScheduledRequest:
        """Record proven remote completion and its real 8-bit exit status."""

        record = self.request(request_id)
        if record.state not in {
            RequestState.REMOTE_MAY_BE_RUNNING,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        }:
            self._invalid_state(record, "mark remote completion proven")
        self._require_lease_owner(request_id)
        if (
            isinstance(exit_status, bool)
            or not isinstance(exit_status, int)
            or not 0 <= exit_status <= 255
        ):
            raise ValueError("remote exit status must be an integer from 0 to 255")
        record = self._replace(
            record.request_id,
            state=RequestState.COMPLETION_PROVEN,
            remote_may_be_running=False,
            completion_proven=True,
            remote_exit_status=exit_status,
        )
        self._maybe_release_verified(request_id)
        self._assert_invariants()
        return self.request(request_id)

    def mark_local_spool_verified(self, request_id: str) -> ScheduledRequest:
        """Record verified local manifest, stdout, and stderr persistence."""

        record = self._require_state(request_id, RequestState.COMPLETION_PROVEN)
        self._require_lease_owner(request_id)
        record = self._replace(
            record.request_id,
            state=RequestState.LOCAL_SPOOL_VERIFIED,
            local_spool_verified=True,
        )
        self._maybe_release_verified(request_id)
        self._assert_invariants()
        return self.request(request_id)

    def mark_viewer_detached(self, request_id: str) -> ScheduledRequest:
        """Record that the interactive viewer no longer owns the terminal."""

        record = self.request(request_id)
        if record.state not in _REMOTE_LIFECYCLE_STATES:
            self._invalid_state(record, "mark viewer detached")
        self._require_lease_owner(request_id)
        if not record.viewer_detached:
            self._replace(request_id, viewer_detached=True)
        self._maybe_release_verified(request_id)
        self._assert_invariants()
        return self.request(request_id)

    def mark_terminal_restored(self, request_id: str) -> ScheduledRequest:
        """Record that the broker has restored its own terminal state."""

        record = self.request(request_id)
        if record.state not in _REMOTE_LIFECYCLE_STATES:
            self._invalid_state(record, "mark terminal restored")
        self._require_lease_owner(request_id)
        if not record.viewer_detached:
            raise InvalidTransitionError(
                "terminal restoration cannot precede viewer detachment"
            )
        if not record.terminal_restored:
            self._replace(request_id, terminal_restored=True)
        self._maybe_release_verified(request_id)
        self._assert_invariants()
        return self.request(request_id)

    def begin_result_delivery(self, request_id: str) -> ScheduledRequest:
        """Begin potentially slow client delivery only after lease release."""

        record = self.request(request_id)
        if record.state not in _RESULT_READY_STATES:
            self._invalid_state(record, "begin result delivery")
        if record.lease_release_reason is None or request_id in self._lease_owners:
            raise InvalidTransitionError("result delivery requires prior lease release")
        record = self._replace(
            request_id,
            state=RequestState.RESULT_DELIVERING,
        )
        self._assert_invariants()
        return record

    def finish_result_delivery(self, request_id: str) -> ScheduledRequest:
        record = self._require_state(request_id, RequestState.RESULT_DELIVERING)
        record = self._replace(record.request_id, state=RequestState.DONE)
        self._assert_invariants()
        return record

    def forget_terminal(self, request_id: str) -> ScheduledRequest:
        """Remove a safely terminal record from the in-memory scheduler.

        The broker calls this after result delivery finishes, or after a client
        disconnect cancels work before approval.  Lease owners, queued work,
        and possibly-running jobs can never be forgotten.
        """

        record = self.request(request_id)
        if record.state not in _FORGETTABLE_TERMINAL_STATES:
            self._invalid_state(record, "forget nonterminal request")
        if request_id in self._pending or request_id in self._lease_owners:
            raise InvalidTransitionError(
                f"cannot forget active request {request_id}"
            )
        del self._requests[request_id]
        self._assert_invariants()
        return record

    def _maybe_release_verified(self, request_id: str) -> None:
        record = self.request(request_id)
        gates = (
            record.completion_proven,
            record.remote_exit_status is not None,
            record.local_spool_verified,
            record.viewer_detached,
            record.terminal_restored,
        )
        if all(gates):
            self._require_lease_owner(request_id)
            self._replace(
                request_id,
                state=RequestState.LEASE_RELEASED,
                lease_release_reason=LeaseReleaseReason.VERIFIED_COMPLETION,
            )
            self._release_owner(request_id)

    def _replace(self, request_id: str, **changes: object) -> ScheduledRequest:
        record = replace(self.request(request_id), **changes)
        self._requests[request_id] = record
        return record

    def _release_owner(self, request_id: str) -> None:
        self._require_lease_owner(request_id)
        self._lease_owners.remove(request_id)

    def _require_lease_owner(self, request_id: str) -> None:
        if request_id not in self._lease_owners:
            raise InvalidTransitionError(
                f"request {request_id} does not own the remote-command lease"
            )

    def _require_state(
        self, request_id: str, expected: RequestState
    ) -> ScheduledRequest:
        record = self.request(request_id)
        if record.state is not expected:
            self._invalid_state(record, f"transition requiring {expected.value}")
        return record

    @staticmethod
    def _invalid_state(record: ScheduledRequest, action: str) -> None:
        raise InvalidTransitionError(
            f"cannot {action} for {record.request_id} in state {record.state.value}"
        )

    def _assert_invariants(self) -> None:
        queued = tuple(
            record.request_id
            for record in sorted(self._requests.values(), key=lambda item: item.sequence)
            if record.state is RequestState.QUEUED
        )
        if queued != tuple(self._pending):
            raise AssertionError("pending deque is not the FIFO sequence of queued requests")
        if len(self._pending) > self.max_pending_requests:
            raise AssertionError("pending queue exceeds configured bound")

        lease_holders = tuple(
            record.request_id
            for record in self._requests.values()
            if record.state in _LEASE_HELD_STATES
        )
        if set(lease_holders) != self._lease_owners:
            raise AssertionError("lease-held states and active lease owners differ")
        if len(self._lease_owners) > self.max_active_remote_commands:
            raise AssertionError("active command leases exceed configured maximum")

        for record in self._requests.values():
            if record.state in {
                RequestState.LEASE_RELEASED,
                RequestState.RESULT_DELIVERING,
                RequestState.DONE,
            } and record.lease_release_reason is LeaseReleaseReason.VERIFIED_COMPLETION:
                if not (
                    record.completion_proven
                    and record.remote_exit_status is not None
                    and record.local_spool_verified
                    and record.viewer_detached
                    and record.terminal_restored
                ):
                    raise AssertionError(
                        "verified completion released before all safety gates"
                    )
