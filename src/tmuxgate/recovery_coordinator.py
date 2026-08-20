"""Broker-owned, machine-scoped expected-reboot recovery coordination."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timedelta
import threading
import time

from tmuxgate.models import DisconnectPolicy, validate_alias, validate_request_id
from tmuxgate.reboot_recovery import BootIdProbe, BootIdProbeError
from tmuxgate.result import ExecutionResult, ResultCode, TransportStatus
from tmuxgate.scheduler import RequestState
from tmuxgate.ssh import ResolvedSshEndpoint
from tmuxgate.state import DurableJobRecord, DurableStateStore, utc_now
from tmuxgate.transport import (
    MasterTransportPool,
    TransportBusyError,
    TransportError,
    TransportIdentityError,
    TransportLease,
    resolved_identity_sha256,
)


MAX_REBOOT_RECOVERY_TIMEOUT_SECONDS = 3600
_IMMEDIATE_FAILURE_CODES = frozenset(
    {
        ResultCode.ENDPOINT_IDENTITY_MISMATCH.value,
        ResultCode.HOST_KEY_MISMATCH.value,
        ResultCode.CREDENTIAL_UNAVAILABLE.value,
        ResultCode.BOOT_ID_INVALID.value,
    }
)


class RecoveryCoordinatorError(RuntimeError):
    """Recovery ownership or evidence binding was invalid."""


SameBootResumer = Callable[
    [DurableJobRecord, ResolvedSshEndpoint], ExecutionResult | None
]


def _parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RecoveryCoordinatorError("durable recovery time is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RecoveryCoordinatorError("durable recovery time is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise RecoveryCoordinatorError("durable recovery time is not UTC")
    return parsed


class ExpectedRebootRecoveryCoordinator:
    """Own expected reboot evidence, bounded probes, and exact cleanup."""

    def __init__(
        self,
        *,
        state: DurableStateStore,
        transports: MasterTransportPool,
        boot_id_probe: BootIdProbe,
        identity_revalidator: Callable[[ResolvedSshEndpoint], ResolvedSshEndpoint],
        timeout_seconds: int = 300,
        probe_interval_seconds: float = 2.0,
        now: Callable[[], str] = utc_now,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= MAX_REBOOT_RECOVERY_TIMEOUT_SECONDS
        ):
            raise ValueError("reboot recovery timeout must be from 1 to 3600 seconds")
        if (
            isinstance(probe_interval_seconds, bool)
            or not isinstance(probe_interval_seconds, (int, float))
            or not 0 < float(probe_interval_seconds) <= 60
        ):
            raise ValueError("reboot probe interval must be from 0 to 60 seconds")
        for name, callback in (
            ("identity_revalidator", identity_revalidator),
            ("now", now),
            ("sleep", sleep),
        ):
            if not callable(callback):
                raise TypeError(f"{name} must be callable")
        if not callable(getattr(boot_id_probe, "capture_pre_reboot", None)) or not callable(
            getattr(boot_id_probe, "probe_after_disconnect", None)
        ):
            raise TypeError("boot_id_probe must implement both fixed probes")
        self.state = state
        self.transports = transports
        self.boot_id_probe = boot_id_probe
        self.identity_revalidator = identity_revalidator
        self.timeout_seconds = timeout_seconds
        self.probe_interval_seconds = float(probe_interval_seconds)
        self.now = now
        self.sleep = sleep
        self._lock = threading.RLock()
        self._active_by_machine: dict[str, set[str]] = {}
        self._startup_request_ids: set[str] = set()
        self._stopping = threading.Event()

    def close(self) -> None:
        self._stopping.set()

    def _pause(self) -> None:
        if not self._stopping.is_set():
            self.sleep(self.probe_interval_seconds)

    @property
    def active_request_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(
                    request_id
                    for request_ids in self._active_by_machine.values()
                    for request_id in request_ids
                )
            )

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._startup_request_ids)

    def recovery_request_for_machine(self, machine_alias: str) -> str | None:
        machine_alias = validate_alias(machine_alias)
        with self._lock:
            request_ids = self._active_by_machine.get(machine_alias, set())
            return min(request_ids) if request_ids else None

    def register_startup(self, records: Iterable[DurableJobRecord]) -> None:
        with self._lock:
            for record in records:
                if record.state not in {
                    RequestState.REMOTE_MAY_BE_RUNNING,
                    RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
                    RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING,
                    RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING,
                    RequestState.EXPECTED_REBOOT_RECOVERY_FAILED,
                }:
                    continue
                self._active_by_machine.setdefault(record.machine_alias, set()).add(
                    record.request_id
                )
                self._startup_request_ids.add(record.request_id)

    def claim_expected_reboot(self, machine_alias: str, request_id: str) -> None:
        machine_alias = validate_alias(machine_alias)
        request_id = validate_request_id(request_id)
        with self._lock:
            existing = self._active_by_machine.get(machine_alias, set()) - {request_id}
            if existing:
                raise RecoveryCoordinatorError(
                    f"machine recovery is already owned by request {min(existing)}"
                )
            self._active_by_machine.setdefault(machine_alias, set()).add(request_id)

    def require_machine_available(self, machine_alias: str, request_id: str) -> None:
        machine_alias = validate_alias(machine_alias)
        request_id = validate_request_id(request_id)
        with self._lock:
            existing = self._active_by_machine.get(machine_alias, set()) - {request_id}
        if existing:
            raise RecoveryCoordinatorError(
                f"machine recovery is in progress for request {min(existing)}"
            )

    def release_claim(self, machine_alias: str, request_id: str) -> None:
        machine_alias = validate_alias(machine_alias)
        request_id = validate_request_id(request_id)
        with self._lock:
            request_ids = self._active_by_machine.get(machine_alias)
            if request_ids is not None:
                request_ids.discard(request_id)
                self._startup_request_ids.discard(request_id)
                if not request_ids:
                    self._active_by_machine.pop(machine_alias, None)

    def capture_pre_reboot(
        self,
        record: DurableJobRecord,
        lease: TransportLease,
    ) -> DurableJobRecord:
        self.require_machine_available(record.machine_alias, record.request_id)
        if record.disconnect_policy is not DisconnectPolicy.EXPECT_FULL_REBOOT:
            raise RecoveryCoordinatorError("pre-reboot capture lacks expected policy")
        if (
            lease.request_id != record.request_id
            or lease.transport.machine_name != record.machine_alias
            or lease.transport.connection_plan_sha256 != record.connection_plan_sha256
            or lease.transport.identity_sha256 != record.resolved_identity_sha256
            or lease.transport.endpoint.endpoint_id != record.endpoint_id
            or lease.transport.endpoint.host_key_alias != record.host_key_alias
        ):
            raise RecoveryCoordinatorError("pre-reboot probe transport binding differs")
        pins = self.transports.pinned_request_ids_for_machine(record.machine_alias)
        if pins != (record.request_id,):
            raise RecoveryCoordinatorError(
                "whole-host reboot requires exclusive same-machine command ownership"
            )
        boot_id = self.boot_id_probe.capture_pre_reboot(lease.transport)
        return self.state.record_pre_reboot_boot_id(record, boot_id=boot_id)

    def _revalidated_endpoint(
        self,
        record: DurableJobRecord,
        endpoint: ResolvedSshEndpoint,
    ) -> ResolvedSshEndpoint:
        if (
            endpoint.machine_name != record.machine_alias
            or endpoint.endpoint_id != record.endpoint_id
            or endpoint.host_key_alias != record.host_key_alias
        ):
            raise BootIdProbeError(
                ResultCode.ENDPOINT_IDENTITY_MISMATCH.value,
                "configured recovery endpoint differs from durable evidence",
            )
        try:
            current = self.identity_revalidator(endpoint)
        except BaseException as exc:
            raise BootIdProbeError(
                ResultCode.ENDPOINT_IDENTITY_MISMATCH.value,
                "recovery endpoint identity could not be revalidated",
            ) from exc
        if (
            not isinstance(current, ResolvedSshEndpoint)
            or current.machine_name != record.machine_alias
            or current.endpoint_id != record.endpoint_id
            or current.host_key_alias != record.host_key_alias
            or resolved_identity_sha256(current) != record.resolved_identity_sha256
        ):
            raise BootIdProbeError(
                ResultCode.ENDPOINT_IDENTITY_MISMATCH.value,
                "recovery endpoint identity changed after remote start",
            )
        return current

    def _deadline(self, record: DurableJobRecord) -> tuple[DurableJobRecord, datetime]:
        reboot = record.reboot_recovery
        if reboot is None:
            raise RecoveryCoordinatorError("expected reboot recovery lacks evidence")
        if record.state in {
            RequestState.REMOTE_MAY_BE_RUNNING,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            RequestState.COMPLETION_PROVEN,
        }:
            started = _parse_utc(self.now())
            deadline = started + timedelta(seconds=self.timeout_seconds)
            record = self.state.begin_expected_reboot_verification(
                record,
                deadline_at=deadline.isoformat(timespec="microseconds").replace(
                    "+00:00", "Z"
                ),
                detail="expected full-host reboot disconnected the command transport",
                now=self.now,
            )
            return record, deadline
        if reboot.recovery_deadline_at is None:
            raise RecoveryCoordinatorError("pending reboot recovery lacks its deadline")
        return record, _parse_utc(reboot.recovery_deadline_at)

    def _failure_result(
        self,
        record: DurableJobRecord,
        code: ResultCode,
        detail: str,
    ) -> ExecutionResult:
        with self._lock:
            self._startup_request_ids.add(record.request_id)
        return ExecutionResult(
            record.request_id,
            TransportStatus.INCOMPLETE,
            detail=detail,
            result_code=code,
        )

    def _finish_changed_boot(
        self,
        record: DurableJobRecord,
        endpoint: ResolvedSshEndpoint,
        lease: TransportLease | None,
    ) -> ExecutionResult:
        try:
            if lease is not None:
                lease.release()
            assert record.resolved_identity_sha256 is not None
            outcome = self.transports.reconcile_verified_reboot(
                machine_name=record.machine_alias,
                request_id=record.request_id,
                endpoint=endpoint,
                expected_identity_sha256=record.resolved_identity_sha256,
            )
            record = self.state.complete_expected_reboot_cleanup(
                record,
                cleanup_outcome=(
                    "exact_request_pin_released_and_" + outcome
                    if lease is not None
                    else outcome
                ),
            )
        except TransportIdentityError as exc:
            return self._failure_result(
                record, ResultCode.ENDPOINT_IDENTITY_MISMATCH, str(exc)
            )
        except TransportBusyError as exc:
            return self._failure_result(
                record, ResultCode.AMBIGUOUS_MASTER_STATE, str(exc)
            )
        except TransportError as exc:
            detail = str(exc)
            code = (
                ResultCode.UNSAFE_CONTROL_PATH
                if "unsafe" in detail.casefold() or "outside" in detail.casefold()
                else ResultCode.AMBIGUOUS_MASTER_STATE
            )
            return self._failure_result(record, code, detail)
        self.release_claim(record.machine_alias, record.request_id)
        return ExecutionResult(
            record.request_id,
            TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT,
            detail=record.failure_detail,
            result_code=ResultCode.ABANDONED_AFTER_VERIFIED_REBOOT,
        )

    def fail_closed_after_remote_start(
        self,
        record: DurableJobRecord,
        *,
        code: ResultCode,
        detail: str,
    ) -> ExecutionResult:
        """Terminalize a non-probe Automation failure while retaining ownership."""

        if code not in {
            ResultCode.CREDENTIAL_UNAVAILABLE,
            ResultCode.CREDENTIAL_PROMPT_MISMATCH,
            ResultCode.AUTOMATION_POLICY_DENIED,
        }:
            raise ValueError("unsupported expected-reboot fail-closed code")
        self.claim_expected_reboot(record.machine_alias, record.request_id)
        current = self.state.load(record.request_id)
        if current != record:
            return self._failure_result(
                current,
                ResultCode.REQUEST_BINDING_MISMATCH,
                "durable request generation changed before fail-closed recovery",
            )
        if current.state is RequestState.REMOTE_MAY_BE_RUNNING:
            current, _deadline = self._deadline(current)
        if current.state is not RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING:
            raise RecoveryCoordinatorError(
                "expected-reboot failure lacks a pending remote-start record"
            )
        current = self.state.fail_expected_reboot_recovery(
            current,
            failure_code=code.value,
            detail=detail,
        )
        return self._failure_result(current, code, detail)

    def recover(
        self,
        record: DurableJobRecord,
        endpoint: ResolvedSshEndpoint,
        *,
        lease: TransportLease | None = None,
        same_boot_resumer: SameBootResumer | None = None,
    ) -> ExecutionResult:
        """Run or resume bounded expected-reboot recovery without prompting."""

        self.claim_expected_reboot(record.machine_alias, record.request_id)
        current_record = self.state.load(record.request_id)
        if current_record != record:
            if current_record.state is RequestState.ABANDONED_AFTER_VERIFIED_REBOOT:
                record = current_record
            else:
                return self._failure_result(
                    current_record,
                    ResultCode.REQUEST_BINDING_MISMATCH,
                    "durable request generation or recovery binding changed before recovery",
                )
        if record.state is RequestState.ABANDONED_AFTER_VERIFIED_REBOOT:
            # A repeated worker or restart after the terminal durable commit
            # must never touch a transport now owned by a later request.
            self.release_claim(record.machine_alias, record.request_id)
            return ExecutionResult(
                record.request_id,
                TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT,
                detail=record.failure_detail,
                result_code=ResultCode.ABANDONED_AFTER_VERIFIED_REBOOT,
            )
        if record.state is RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING:
            current = self._revalidated_endpoint(record, endpoint)
            return self._finish_changed_boot(record, current, lease)
        if record.state is RequestState.EXPECTED_REBOOT_RECOVERY_FAILED:
            reboot = record.reboot_recovery
            assert reboot is not None and reboot.failure_code is not None
            try:
                code = ResultCode(reboot.failure_code)
            except ValueError:
                code = ResultCode.REBOOT_RECOVERY_TIMEOUT
            return self._failure_result(
                record,
                code,
                record.failure_detail or "expected reboot recovery previously failed",
            )
        record, deadline = self._deadline(record)
        same_boot_seen = False
        while not self._stopping.is_set() and _parse_utc(self.now()) < deadline:
            try:
                current = self._revalidated_endpoint(record, endpoint)
            except BootIdProbeError as exc:
                detail = str(exc)
                record = self.state.fail_expected_reboot_recovery(
                    record,
                    failure_code=exc.code,
                    detail=detail,
                )
                return self._failure_result(record, ResultCode(exc.code), detail)
            try:
                post_boot_id = self.boot_id_probe.probe_after_disconnect(current)
            except BootIdProbeError as exc:
                detail = str(exc)
                record = self.state.record_expected_reboot_probe_failure(
                    record,
                    failure_code=exc.code,
                    detail=detail,
                )
                if exc.code in _IMMEDIATE_FAILURE_CODES:
                    record = self.state.fail_expected_reboot_recovery(
                        record,
                        failure_code=exc.code,
                        detail=detail,
                    )
                    return self._failure_result(record, ResultCode(exc.code), detail)
                self._pause()
                continue
            observed_at = self.now()
            if _parse_utc(observed_at) >= deadline:
                detail = (
                    "independent boot-ID probe completed after the bounded recovery "
                    "deadline; its observation cannot authorize abandonment"
                )
                record = self.state.record_expected_reboot_probe_failure(
                    record,
                    failure_code=ResultCode.REBOOT_RECOVERY_TIMEOUT.value,
                    detail=detail,
                    now=lambda: observed_at,
                )
                record = self.state.fail_expected_reboot_recovery(
                    record,
                    failure_code=ResultCode.REBOOT_RECOVERY_TIMEOUT.value,
                    detail=detail,
                    now=lambda: observed_at,
                )
                return self._failure_result(
                    record, ResultCode.REBOOT_RECOVERY_TIMEOUT, detail
                )
            assert record.reboot_recovery is not None
            if post_boot_id != record.reboot_recovery.pre_boot_id:
                reason = (
                    "independent one-shot SSH probe revalidated the original endpoint "
                    "and observed a changed Linux boot ID"
                )
                record = self.state.mark_expected_reboot_verified(
                    record,
                    post_boot_id=post_boot_id,
                    reason=reason,
                    now=lambda: observed_at,
                )
                return self._finish_changed_boot(record, current, lease)
            same_boot_seen = True
            record = self.state.record_same_boot_observed(
                record,
                boot_id=post_boot_id,
                detail=(
                    "independent probe reached the original endpoint but observed "
                    "the pre-command boot ID; reboot abandonment is forbidden"
                ),
                now=lambda: observed_at,
            )
            if same_boot_resumer is not None:
                try:
                    resumed = same_boot_resumer(record, current)
                except BaseException:
                    resumed = None
                if resumed is not None:
                    if resumed.transport_status is TransportStatus.COMPLETE:
                        self.release_claim(record.machine_alias, record.request_id)
                    return resumed
            self._pause()

        if self._stopping.is_set():
            return self._failure_result(
                record,
                ResultCode.REBOOT_RECOVERY_TIMEOUT,
                "broker shutdown interrupted expected reboot recovery; durable retry remains pending",
            )

        failure_code = (
            ResultCode.SAME_BOOT_OBSERVED
            if same_boot_seen
            else ResultCode.REBOOT_RECOVERY_TIMEOUT
        )
        detail = (
            "recovery deadline expired after the original boot ID remained active"
            if same_boot_seen
            else "recovery deadline expired before a changed boot ID was verified"
        )
        record = self.state.fail_expected_reboot_recovery(
            record,
            failure_code=failure_code.value,
            detail=detail,
        )
        return self._failure_result(record, failure_code, detail)
