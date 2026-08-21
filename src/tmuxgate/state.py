"""Crash-safe owner-only job state and conservative startup recovery."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
import os
import re
import secrets
import stat
import threading

from tmuxgate.connection_plan import ConnectionPlan, PlannedEndpoint
from tmuxgate.models import (
    DisconnectPolicy,
    RequestSpec,
    validate_alias,
    validate_request_id,
)
from tmuxgate.runtime import PRIVATE_DIRECTORY_MODE, ensure_private_directory
from tmuxgate.scheduler import ApprovalDecision, RequestState


STATE_FORMAT_VERSION = 4
PREVIOUS_STATE_FORMAT_VERSION = 3
LEGACY_STATE_FORMAT_VERSIONS = frozenset({2, 3})
STATE_FILE_MODE = 0o600
STATE_JOBS_DIRECTORY_NAME = "jobs"
MAX_STATE_FILE_BYTES = 1024 * 1024

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ENDPOINT_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,62}\Z", re.ASCII)
_SESSION_RE = re.compile(r"tmuxgate-[0-9a-f]{8,32}\Z", re.ASCII)
_BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z",
    re.ASCII,
)
_TEMP_RE = re.compile(r"\.([0-9a-f]{32})\.([0-9a-f]{32})\.tmp\Z", re.ASCII)
_FINAL_RE = re.compile(r"([0-9a-f]{32})\.json\Z", re.ASCII)
_REMOTE_ACTIVE_STATES = frozenset(
    {
        RequestState.REMOTE_MAY_BE_RUNNING,
        RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING,
        RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING,
        RequestState.EXPECTED_REBOOT_RECOVERY_FAILED,
        RequestState.COMPLETION_PROVEN,
        RequestState.LOCAL_SPOOL_VERIFIED,
    }
)
_OPERATOR_ABANDONED_STATES = frozenset(
    {
        RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
        RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
        RequestState.ABANDONED_AFTER_OPERATOR_ACKNOWLEDGED_UNCERTAINTY,
    }
)
_AUTOMATIC_ABANDONED_STATES = frozenset(
    {RequestState.ABANDONED_AFTER_VERIFIED_REBOOT}
)
_PROVEN_UNSTARTED_STATES = frozenset(
    {RequestState.ABANDONED_AFTER_PROVEN_UNSTARTED}
)
_ABANDONED_STATES = (
    _OPERATOR_ABANDONED_STATES
    | _PROVEN_UNSTARTED_STATES
    | _AUTOMATIC_ABANDONED_STATES
)
_REMOTE_STARTED_STATES = _REMOTE_ACTIVE_STATES | _ABANDONED_STATES
_REMOTE_MUTATION_STATES = _REMOTE_STARTED_STATES | frozenset(
    {
        RequestState.KEY_ENROLLMENT_MAY_HAVE_STARTED,
        RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
        RequestState.FAILED_REMOTE_SETUP,
    }
)
_SAFE_PRE_REMOTE_RESTART_STATES = frozenset(
    {
        RequestState.QUEUED,
        RequestState.AWAITING_APPROVAL,
        RequestState.APPROVED_PRE_REMOTE,
    }
)


class StateError(RuntimeError):
    """Durable state could not be safely read or updated."""


class StateCorruptionError(StateError):
    """A state path or record violated a fail-closed invariant."""


class StateConflictError(StateError):
    """A caller attempted a stale or invalid generation update."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _validate_text(value: object, name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or "\x00" in value:
        raise StateCorruptionError(f"{name} must be non-empty text without NUL")
    return value


def _validate_digest(value: object, name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StateCorruptionError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _validate_timestamp(value: object, name: str, *, optional: bool = False) -> str | None:
    text = _validate_text(value, name, optional=optional)
    if text is None:
        return None
    if not text.endswith("Z"):
        raise StateCorruptionError(f"{name} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise StateCorruptionError(f"{name} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise StateCorruptionError(f"{name} must be UTC")
    return text


def _parsed_timestamp(value: str) -> datetime:
    """Parse a timestamp already accepted by `_validate_timestamp`."""

    return datetime.fromisoformat(value[:-1] + "+00:00")


def _canonical_json(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha256_document(document: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical_json(document)).hexdigest()


class RebootRecoveryPhase(StrEnum):
    PRE_BOOT_ID_CAPTURED = "pre_boot_id_captured"
    VERIFICATION_PENDING = "verification_pending"
    SAME_BOOT_OBSERVED = "same_boot_observed"
    VERIFIED_CHANGED_BOOT = "verified_changed_boot"
    CLEANUP_COMPLETE = "cleanup_complete"
    FAILED = "failed"


class RemotePhase(StrEnum):
    """Last fsynced fact in the ordinary remote-command lifecycle.

    ``REMOTE_WRAPPER_REQUESTED`` is deliberately additional to the public
    milestone list. It closes the crash window between asking the host to
    create the gated wrapper and recording that the wrapper was observed.
    """

    NOT_ATTEMPTED = "not_attempted"
    CONNECTION_ATTEMPTED = "connection_attempted"
    STAGING_REQUESTED = "staging_requested"
    STAGING_VERIFIED = "staging_verified"
    REMOTE_WRAPPER_REQUESTED = "remote_wrapper_requested"
    REMOTE_WRAPPER_CREATED = "remote_wrapper_created"
    USER_COMMAND_STARTED = "user_command_started"
    RESULT_SPOOL_FINALIZED = "result_spool_finalized"
    RESULT_SPOOL_LOCALLY_VERIFIED = "result_spool_locally_verified"
    CLEANUP_COMPLETED = "cleanup_completed"
    LEGACY_UNCERTAIN = "legacy_uncertain"


_REMOTE_PHASE_RANK = {
    RemotePhase.NOT_ATTEMPTED: 0,
    RemotePhase.CONNECTION_ATTEMPTED: 1,
    RemotePhase.STAGING_REQUESTED: 2,
    RemotePhase.STAGING_VERIFIED: 3,
    RemotePhase.REMOTE_WRAPPER_REQUESTED: 4,
    RemotePhase.REMOTE_WRAPPER_CREATED: 5,
    RemotePhase.USER_COMMAND_STARTED: 6,
    RemotePhase.RESULT_SPOOL_FINALIZED: 7,
    RemotePhase.RESULT_SPOOL_LOCALLY_VERIFIED: 8,
    RemotePhase.CLEANUP_COMPLETED: 9,
}


def remote_phase_at_least(phase: RemotePhase, expected: RemotePhase) -> bool:
    """Compare current-format phases while keeping legacy uncertainty opaque."""

    if phase is RemotePhase.LEGACY_UNCERTAIN:
        return False
    return _REMOTE_PHASE_RANK[phase] >= _REMOTE_PHASE_RANK[expected]


@dataclass(frozen=True, slots=True)
class RebootRecoveryEvidence:
    """Durable, exact evidence for one expected full-host reboot."""

    request_id: str
    machine_alias: str
    connection_plan_sha256: str
    endpoint_id: str
    resolved_identity_sha256: str
    host_key_alias: str
    pre_boot_id: str
    pre_boot_id_captured_at: str
    pre_boot_id_generation: int
    phase: RebootRecoveryPhase = RebootRecoveryPhase.PRE_BOOT_ID_CAPTURED
    remote_start_time: str | None = None
    remote_start_generation: int | None = None
    post_boot_id: str | None = None
    probe_attempts: int = 0
    recovery_started_at: str | None = None
    recovery_deadline_at: str | None = None
    last_probe_at: str | None = None
    verified_at: str | None = None
    evidence_sha256: str | None = None
    automatic_decision: str | None = None
    automatic_reason: str | None = None
    failure_code: str | None = None
    cleanup_outcome: str | None = None

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "request_id", validate_request_id(self.request_id))
            object.__setattr__(self, "machine_alias", validate_alias(self.machine_alias))
        except ValueError as exc:
            raise StateCorruptionError(str(exc)) from exc
        for name, value in (
            ("connection_plan_sha256", self.connection_plan_sha256),
            ("resolved_identity_sha256", self.resolved_identity_sha256),
        ):
            _validate_digest(value, name)
        if (
            not isinstance(self.endpoint_id, str)
            or _ENDPOINT_ID_RE.fullmatch(self.endpoint_id) is None
        ):
            raise StateCorruptionError("reboot recovery endpoint_id is invalid")
        _validate_text(self.host_key_alias, "reboot recovery host_key_alias")
        for name, value, optional in (
            ("pre_boot_id", self.pre_boot_id, False),
            ("post_boot_id", self.post_boot_id, True),
        ):
            if value is None and optional:
                continue
            if not isinstance(value, str) or _BOOT_ID_RE.fullmatch(value) is None:
                raise StateCorruptionError(f"{name} is not a canonical Linux boot ID")
        for name, value, optional in (
            ("pre_boot_id_captured_at", self.pre_boot_id_captured_at, False),
            ("remote_start_time", self.remote_start_time, True),
            ("recovery_started_at", self.recovery_started_at, True),
            ("recovery_deadline_at", self.recovery_deadline_at, True),
            ("last_probe_at", self.last_probe_at, True),
            ("verified_at", self.verified_at, True),
        ):
            _validate_timestamp(value, name, optional=optional)
        for name, value, optional in (
            ("pre_boot_id_generation", self.pre_boot_id_generation, False),
            ("remote_start_generation", self.remote_start_generation, True),
        ):
            if value is None and optional:
                continue
            if type(value) is not int or value < 1:
                raise StateCorruptionError(f"{name} must be a positive integer")
        if type(self.probe_attempts) is not int or self.probe_attempts < 0:
            raise StateCorruptionError("probe_attempts must be a non-negative integer")
        try:
            phase = RebootRecoveryPhase(self.phase)
        except (TypeError, ValueError) as exc:
            raise StateCorruptionError("reboot recovery phase is invalid") from exc
        object.__setattr__(self, "phase", phase)
        for name, value in (
            ("automatic_decision", self.automatic_decision),
            ("automatic_reason", self.automatic_reason),
            ("failure_code", self.failure_code),
            ("cleanup_outcome", self.cleanup_outcome),
        ):
            _validate_text(value, name, optional=True)
        _validate_digest(self.evidence_sha256, "evidence_sha256", optional=True)
        if (self.remote_start_time is None) != (self.remote_start_generation is None):
            raise StateCorruptionError("reboot recovery start time and generation must pair")
        if (self.recovery_started_at is None) != (self.recovery_deadline_at is None):
            raise StateCorruptionError("reboot recovery start and deadline must pair")
        if (self.automatic_decision is None) != (self.automatic_reason is None):
            raise StateCorruptionError("automatic reboot decision and reason must pair")
        pre_capture = _parsed_timestamp(self.pre_boot_id_captured_at)
        remote_start = (
            None
            if self.remote_start_time is None
            else _parsed_timestamp(self.remote_start_time)
        )
        recovery_start = (
            None
            if self.recovery_started_at is None
            else _parsed_timestamp(self.recovery_started_at)
        )
        recovery_deadline = (
            None
            if self.recovery_deadline_at is None
            else _parsed_timestamp(self.recovery_deadline_at)
        )
        verified_at = (
            None if self.verified_at is None else _parsed_timestamp(self.verified_at)
        )
        if remote_start is not None and pre_capture > remote_start:
            raise StateCorruptionError("pre-reboot evidence follows remote start")
        if recovery_start is not None:
            assert recovery_deadline is not None
            if remote_start is None or recovery_start < remote_start:
                raise StateCorruptionError("reboot recovery precedes remote start")
            if recovery_deadline <= recovery_start:
                raise StateCorruptionError("reboot recovery deadline is not future")
        if verified_at is not None:
            if (
                remote_start is None
                or recovery_start is None
                or recovery_deadline is None
                or verified_at <= remote_start
                or verified_at < recovery_start
                or verified_at >= recovery_deadline
            ):
                raise StateCorruptionError(
                    "verified reboot observation is outside its start/deadline bounds"
                )
        if phase in {
            RebootRecoveryPhase.VERIFIED_CHANGED_BOOT,
            RebootRecoveryPhase.CLEANUP_COMPLETE,
        }:
            if (
                self.post_boot_id is None
                or self.post_boot_id == self.pre_boot_id
                or self.verified_at is None
                or self.evidence_sha256 is None
                or self.automatic_decision != "abandon_after_verified_reboot"
            ):
                raise StateCorruptionError("verified reboot evidence is incomplete")
            if self.evidence_sha256 != self.computed_evidence_sha256():
                raise StateCorruptionError("verified reboot evidence digest does not match")
        if phase is RebootRecoveryPhase.SAME_BOOT_OBSERVED and (
            self.post_boot_id is None or self.post_boot_id != self.pre_boot_id
        ):
            raise StateCorruptionError("same-boot phase lacks matching boot IDs")
        if phase is RebootRecoveryPhase.CLEANUP_COMPLETE and self.cleanup_outcome is None:
            raise StateCorruptionError("completed reboot cleanup lacks an outcome")
        if phase is RebootRecoveryPhase.FAILED and self.failure_code is None:
            raise StateCorruptionError("failed reboot recovery lacks a failure code")

    def evidence_document(self) -> dict[str, object]:
        return {
            "automatic_decision": self.automatic_decision,
            "automatic_reason": self.automatic_reason,
            "connection_plan_sha256": self.connection_plan_sha256,
            "disconnect_policy": DisconnectPolicy.EXPECT_FULL_REBOOT.value,
            "endpoint_id": self.endpoint_id,
            "host_key_alias": self.host_key_alias,
            "last_probe_at": self.last_probe_at,
            "machine_alias": self.machine_alias,
            "post_boot_id": self.post_boot_id,
            "pre_boot_id": self.pre_boot_id,
            "pre_boot_id_captured_at": self.pre_boot_id_captured_at,
            "pre_boot_id_generation": self.pre_boot_id_generation,
            "probe_attempts": self.probe_attempts,
            "recovery_deadline_at": self.recovery_deadline_at,
            "recovery_started_at": self.recovery_started_at,
            "remote_start_generation": self.remote_start_generation,
            "remote_start_time": self.remote_start_time,
            "request_id": self.request_id,
            "resolved_identity_sha256": self.resolved_identity_sha256,
            "verified_at": self.verified_at,
        }

    def computed_evidence_sha256(self) -> str:
        return _sha256_document(self.evidence_document())

    def payload_document(self) -> dict[str, object]:
        return {
            "automatic_decision": self.automatic_decision,
            "automatic_reason": self.automatic_reason,
            "cleanup_outcome": self.cleanup_outcome,
            "connection_plan_sha256": self.connection_plan_sha256,
            "endpoint_id": self.endpoint_id,
            "evidence_sha256": self.evidence_sha256,
            "failure_code": self.failure_code,
            "host_key_alias": self.host_key_alias,
            "last_probe_at": self.last_probe_at,
            "machine_alias": self.machine_alias,
            "phase": self.phase.value,
            "post_boot_id": self.post_boot_id,
            "pre_boot_id": self.pre_boot_id,
            "pre_boot_id_captured_at": self.pre_boot_id_captured_at,
            "pre_boot_id_generation": self.pre_boot_id_generation,
            "probe_attempts": self.probe_attempts,
            "recovery_deadline_at": self.recovery_deadline_at,
            "recovery_started_at": self.recovery_started_at,
            "remote_start_generation": self.remote_start_generation,
            "remote_start_time": self.remote_start_time,
            "request_id": self.request_id,
            "resolved_identity_sha256": self.resolved_identity_sha256,
            "verified_at": self.verified_at,
        }

    @classmethod
    def from_payload(cls, payload: object) -> "RebootRecoveryEvidence":
        if not isinstance(payload, Mapping):
            raise StateCorruptionError("reboot recovery evidence must be an object")
        expected = set(cls.__dataclass_fields__)
        if set(payload) != expected:
            raise StateCorruptionError("reboot recovery fields are not exactly recognized")
        return cls(**payload)


@dataclass(frozen=True, slots=True)
class DurableJobRecord:
    request_id: str
    generation: int
    machine_alias: str
    client_request_sha256: str
    connection_plan_sha256: str | None
    endpoint_id: str | None
    resolved_user: str | None
    resolved_hostname: str | None
    resolved_port: int | None
    host_key_alias: str | None
    remote_job_path: str | None
    remote_tmux_session: str | None
    decision: ApprovalDecision | None
    state: RequestState
    created_at: str
    updated_at: str
    start_time: str | None = None
    completion_time: str | None = None
    exit_status: int | None = None
    remote_mutation_started: bool = False
    local_spool_verified: bool = False
    viewer_detached: bool = False
    terminal_restored: bool = False
    failure_detail: str | None = None
    local_spool_manifest_sha256: str | None = None
    resolved_identity_sha256: str | None = None
    disconnect_policy: DisconnectPolicy = DisconnectPolicy.NORMAL
    reboot_recovery: RebootRecoveryEvidence | None = None
    remote_phase: RemotePhase = RemotePhase.NOT_ATTEMPTED
    record_version: int = STATE_FORMAT_VERSION

    def __post_init__(self) -> None:
        try:
            request_id = validate_request_id(self.request_id)
            machine_alias = validate_alias(self.machine_alias)
        except ValueError as exc:
            raise StateCorruptionError(str(exc)) from exc
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "machine_alias", machine_alias)
        if type(self.generation) is not int or self.generation < 1:
            raise StateCorruptionError("generation must be a positive integer")
        if self.record_version not in LEGACY_STATE_FORMAT_VERSIONS | {
            STATE_FORMAT_VERSION
        }:
            raise StateCorruptionError("unsupported state record version")
        _validate_digest(self.client_request_sha256, "client_request_sha256")
        _validate_digest(
            self.connection_plan_sha256, "connection_plan_sha256", optional=True
        )
        _validate_digest(
            self.resolved_identity_sha256,
            "resolved_identity_sha256",
            optional=True,
        )
        try:
            disconnect_policy = DisconnectPolicy(self.disconnect_policy)
        except (TypeError, ValueError) as exc:
            raise StateCorruptionError("disconnect policy is invalid") from exc
        object.__setattr__(self, "disconnect_policy", disconnect_policy)
        if self.record_version == 2 and (
            disconnect_policy is not DisconnectPolicy.NORMAL
            or self.resolved_identity_sha256 is not None
            or self.reboot_recovery is not None
        ):
            raise StateCorruptionError("legacy state cannot claim reboot recovery evidence")
        try:
            remote_phase = RemotePhase(self.remote_phase)
        except (TypeError, ValueError) as exc:
            raise StateCorruptionError("remote phase is invalid") from exc
        object.__setattr__(self, "remote_phase", remote_phase)
        if self.record_version in LEGACY_STATE_FORMAT_VERSIONS:
            expected_legacy_phase = (
                RemotePhase.LEGACY_UNCERTAIN
                if self.remote_mutation_started
                else RemotePhase.NOT_ATTEMPTED
            )
            if remote_phase is not expected_legacy_phase:
                raise StateCorruptionError("legacy state claims a current remote phase")
        elif remote_phase is RemotePhase.LEGACY_UNCERTAIN:
            raise StateCorruptionError("current state cannot claim a legacy remote phase")
        if self.endpoint_id is not None and (
            not isinstance(self.endpoint_id, str)
            or _ENDPOINT_ID_RE.fullmatch(self.endpoint_id) is None
        ):
            raise StateCorruptionError("endpoint_id is invalid")
        for name, value in (
            ("resolved_user", self.resolved_user),
            ("resolved_hostname", self.resolved_hostname),
            ("host_key_alias", self.host_key_alias),
        ):
            _validate_text(value, name, optional=True)
        if self.resolved_port is not None and (
            type(self.resolved_port) is not int or not 1 <= self.resolved_port <= 65535
        ):
            raise StateCorruptionError("resolved_port must be from 1 to 65535")
        resolved_fields = (
            self.connection_plan_sha256,
            self.endpoint_id,
            self.resolved_user,
            self.resolved_hostname,
            self.resolved_port,
            self.host_key_alias,
        )
        if any(value is not None for value in resolved_fields) and not all(
            value is not None for value in resolved_fields
        ):
            raise StateCorruptionError("resolved connection identity must be all-or-none")
        if (self.remote_job_path is None) != (self.remote_tmux_session is None):
            raise StateCorruptionError("remote job path and tmux session must be paired")
        if self.remote_job_path is not None:
            expected_path = f"~/.cache/tmuxgate/jobs/{self.request_id}"
            if self.remote_job_path != expected_path:
                raise StateCorruptionError("remote job path is outside the guarded job parent")
            if (
                not isinstance(self.remote_tmux_session, str)
                or _SESSION_RE.fullmatch(self.remote_tmux_session) is None
            ):
                raise StateCorruptionError("remote tmux session name is invalid")

        try:
            state = RequestState(self.state)
        except (TypeError, ValueError) as exc:
            raise StateCorruptionError("state is invalid") from exc
        object.__setattr__(self, "state", state)
        if self.decision is not None:
            try:
                object.__setattr__(self, "decision", ApprovalDecision(self.decision))
            except (TypeError, ValueError) as exc:
                raise StateCorruptionError("decision is invalid") from exc
        _validate_timestamp(self.created_at, "created_at")
        _validate_timestamp(self.updated_at, "updated_at")
        _validate_timestamp(self.start_time, "start_time", optional=True)
        _validate_timestamp(self.completion_time, "completion_time", optional=True)
        if self.exit_status is not None and (
            type(self.exit_status) is not int or not 0 <= self.exit_status <= 255
        ):
            raise StateCorruptionError("exit_status must be from 0 to 255")
        for name, value in (
            ("remote_mutation_started", self.remote_mutation_started),
            ("local_spool_verified", self.local_spool_verified),
            ("viewer_detached", self.viewer_detached),
            ("terminal_restored", self.terminal_restored),
        ):
            if type(value) is not bool:
                raise StateCorruptionError(f"{name} must be boolean")
        _validate_text(self.failure_detail, "failure_detail", optional=True)
        _validate_digest(
            self.local_spool_manifest_sha256,
            "local_spool_manifest_sha256",
            optional=True,
        )

        if (
            self.record_version in LEGACY_STATE_FORMAT_VERSIONS
            and state in _REMOTE_MUTATION_STATES
            and not self.remote_mutation_started
        ):
            raise StateCorruptionError("remote lifecycle state lacks mutation boundary")
        if (
            self.record_version == STATE_FORMAT_VERSION
            and remote_phase_at_least(remote_phase, RemotePhase.USER_COMMAND_STARTED)
            and not self.remote_mutation_started
        ):
            raise StateCorruptionError("command-start phase lacks mutation boundary")
        if (
            self.record_version == STATE_FORMAT_VERSION
            and self.remote_mutation_started
            and state not in {
                RequestState.KEY_ENROLLMENT_MAY_HAVE_STARTED,
                RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
                RequestState.FAILED_REMOTE_SETUP,
            }
            and not remote_phase_at_least(
                remote_phase, RemotePhase.USER_COMMAND_STARTED
            )
        ):
            raise StateCorruptionError("mutation boundary precedes command-start phase")
        if (
            self.record_version == STATE_FORMAT_VERSION
            and state is RequestState.REMOTE_MAY_BE_RUNNING
            and not remote_phase_at_least(
                remote_phase, RemotePhase.USER_COMMAND_STARTED
            )
        ):
            raise StateCorruptionError("remote state lacks mutation boundary")
        if (
            self.record_version == STATE_FORMAT_VERSION
            and state is RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING
            and remote_phase not in {
                RemotePhase.REMOTE_WRAPPER_REQUESTED,
                RemotePhase.REMOTE_WRAPPER_CREATED,
                RemotePhase.USER_COMMAND_STARTED,
                RemotePhase.RESULT_SPOOL_FINALIZED,
                RemotePhase.RESULT_SPOOL_LOCALLY_VERIFIED,
                RemotePhase.CLEANUP_COMPLETED,
            }
        ):
            raise StateCorruptionError("recovery state lacks a remote uncertainty phase")
        if state in {
            RequestState.APPROVED_PRE_REMOTE,
            RequestState.KEY_ENROLLMENT_MAY_HAVE_STARTED,
            RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
            RequestState.REMOTE_MAY_BE_RUNNING,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING,
            RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING,
            RequestState.EXPECTED_REBOOT_RECOVERY_FAILED,
            RequestState.ABANDONED_AFTER_VERIFIED_REBOOT,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
            RequestState.ABANDONED_AFTER_OPERATOR_ACKNOWLEDGED_UNCERTAINTY,
            RequestState.ABANDONED_AFTER_PROVEN_UNSTARTED,
            RequestState.COMPLETION_PROVEN,
            RequestState.LOCAL_SPOOL_VERIFIED,
            RequestState.LEASE_RELEASED,
            RequestState.FAILED_REMOTE_SETUP,
        } and self.decision is not ApprovalDecision.APPROVED:
            raise StateCorruptionError("approved lifecycle state lacks approved decision")
        if state is RequestState.DENIED and self.decision is not ApprovalDecision.DENIED:
            raise StateCorruptionError("denied state lacks denied decision")
        if state in {RequestState.QUEUED, RequestState.AWAITING_APPROVAL} and self.decision is not None:
            raise StateCorruptionError("unapproved state unexpectedly has a decision")
        if state in {
            RequestState.APPROVED_PRE_REMOTE,
            RequestState.KEY_ENROLLMENT_MAY_HAVE_STARTED,
            RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
            RequestState.REMOTE_MAY_BE_RUNNING,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING,
            RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING,
            RequestState.EXPECTED_REBOOT_RECOVERY_FAILED,
            RequestState.ABANDONED_AFTER_VERIFIED_REBOOT,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
            RequestState.ABANDONED_AFTER_OPERATOR_ACKNOWLEDGED_UNCERTAINTY,
            RequestState.ABANDONED_AFTER_PROVEN_UNSTARTED,
            RequestState.COMPLETION_PROVEN,
            RequestState.LOCAL_SPOOL_VERIFIED,
            RequestState.LEASE_RELEASED,
            RequestState.FAILED_REMOTE_SETUP,
        } and any(value is None for value in resolved_fields):
            raise StateCorruptionError("approved lifecycle state lacks resolved identity")
        if state in _REMOTE_STARTED_STATES and self.remote_job_path is None:
            raise StateCorruptionError("remote lifecycle state lacks guarded job identity")
        if self.remote_mutation_started and self.start_time is None:
            raise StateCorruptionError("remote mutation boundary lacks start_time")
        if self.completion_time is not None and self.exit_status is None:
            raise StateCorruptionError("completion_time lacks exit_status")
        if self.exit_status is not None and self.completion_time is None:
            raise StateCorruptionError("exit_status lacks completion_time")
        if state in {RequestState.COMPLETION_PROVEN, RequestState.LOCAL_SPOOL_VERIFIED}:
            if self.exit_status is None or self.completion_time is None:
                raise StateCorruptionError("proven completion lacks time or exit status")
        if self.record_version == STATE_FORMAT_VERSION:
            if (
                state is RequestState.COMPLETION_PROVEN
                and remote_phase is not RemotePhase.RESULT_SPOOL_FINALIZED
            ):
                raise StateCorruptionError("completion state lacks finalized spool phase")
            if (
                state is RequestState.LOCAL_SPOOL_VERIFIED
                and remote_phase not in {
                    RemotePhase.RESULT_SPOOL_LOCALLY_VERIFIED,
                    RemotePhase.CLEANUP_COMPLETED,
                }
            ):
                raise StateCorruptionError(
                    "local spool state lacks local verification phase"
                )
        if state in _ABANDONED_STATES:
            if self.failure_detail is None:
                raise StateCorruptionError(
                    "abandonment lacks audit detail"
                )
            if any(
                (
                    self.completion_time is not None,
                    self.exit_status is not None,
                    self.local_spool_verified,
                    self.local_spool_manifest_sha256 is not None,
                    self.viewer_detached,
                    self.terminal_restored,
                )
            ):
                raise StateCorruptionError(
                    "abandonment cannot claim completion gates"
                )
        if self.local_spool_verified and self.exit_status is None:
            raise StateCorruptionError("verified local spool lacks proven completion")
        if self.local_spool_verified != (self.local_spool_manifest_sha256 is not None):
            raise StateCorruptionError(
                "local spool verification and manifest digest must be paired"
            )
        if self.terminal_restored and not self.viewer_detached:
            raise StateCorruptionError("terminal restoration precedes viewer detach")
        if state in {
            RequestState.CANCELLED_BEFORE_APPROVAL,
            RequestState.DENIED,
            RequestState.FAILED_PRE_REMOTE,
        } and self.remote_mutation_started:
            raise StateCorruptionError("pre-remote terminal state claims remote mutation")
        if state is RequestState.FAILED_REMOTE_SETUP and self.failure_detail is None:
            raise StateCorruptionError("remote setup failure lacks audit detail")
        if self.remote_mutation_started and state in {
            RequestState.LEASE_RELEASED,
            RequestState.RESULT_DELIVERING,
            RequestState.DONE,
        } and not (
            self.exit_status is not None
            and self.completion_time is not None
            and self.local_spool_verified
            and self.viewer_detached
            and self.terminal_restored
        ):
            raise StateCorruptionError("released remote job lacks every completion gate")
        if (
            self.record_version == STATE_FORMAT_VERSION
            and remote_phase_at_least(
                remote_phase, RemotePhase.RESULT_SPOOL_LOCALLY_VERIFIED
            )
            and not self.local_spool_verified
        ):
            raise StateCorruptionError("local verification phase lacks verified spool")

        reboot = self.reboot_recovery
        if reboot is not None and not isinstance(reboot, RebootRecoveryEvidence):
            raise StateCorruptionError("reboot_recovery must be structured evidence")
        if disconnect_policy is DisconnectPolicy.NORMAL:
            if reboot is not None or state in {
                RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING,
                RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING,
                RequestState.EXPECTED_REBOOT_RECOVERY_FAILED,
                RequestState.ABANDONED_AFTER_VERIFIED_REBOOT,
            }:
                raise StateCorruptionError("normal disconnect policy claims reboot recovery")
        else:
            if self.record_version == 2:
                raise StateCorruptionError("expected reboot requires current durable state")
            if state in _REMOTE_STARTED_STATES and reboot is None:
                raise StateCorruptionError("expected reboot remote state lacks pre-boot evidence")
        if reboot is not None:
            bindings = (
                reboot.request_id == self.request_id,
                reboot.machine_alias == self.machine_alias,
                reboot.connection_plan_sha256 == self.connection_plan_sha256,
                reboot.endpoint_id == self.endpoint_id,
                reboot.resolved_identity_sha256 == self.resolved_identity_sha256,
                reboot.host_key_alias == self.host_key_alias,
            )
            if not all(bindings):
                raise StateCorruptionError("reboot evidence identity differs from its request")
            if reboot.remote_start_time is not None and (
                reboot.remote_start_time != self.start_time
                or reboot.remote_start_generation is None
                or reboot.remote_start_generation > self.generation
            ):
                raise StateCorruptionError("reboot evidence remote start binding is invalid")
        phase_for_state = {
            RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING: {
                RebootRecoveryPhase.VERIFICATION_PENDING,
                RebootRecoveryPhase.SAME_BOOT_OBSERVED,
            },
            RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING: {
                RebootRecoveryPhase.VERIFIED_CHANGED_BOOT
            },
            RequestState.EXPECTED_REBOOT_RECOVERY_FAILED: {
                RebootRecoveryPhase.FAILED
            },
            RequestState.ABANDONED_AFTER_VERIFIED_REBOOT: {
                RebootRecoveryPhase.CLEANUP_COMPLETE
            },
        }
        if state in phase_for_state and (
            reboot is None or reboot.phase not in phase_for_state[state]
        ):
            raise StateCorruptionError("reboot recovery state and evidence phase differ")

    def payload_document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "client_request_sha256": self.client_request_sha256,
            "completion_time": self.completion_time,
            "connection_plan_sha256": self.connection_plan_sha256,
            "created_at": self.created_at,
            "decision": None if self.decision is None else self.decision.value,
            "endpoint_id": self.endpoint_id,
            "exit_status": self.exit_status,
            "failure_detail": self.failure_detail,
            "generation": self.generation,
            "host_key_alias": self.host_key_alias,
            "local_spool_verified": self.local_spool_verified,
            "local_spool_manifest_sha256": self.local_spool_manifest_sha256,
            "machine_alias": self.machine_alias,
            "record_version": self.record_version,
            "remote_job_path": self.remote_job_path,
            "remote_mutation_started": self.remote_mutation_started,
            "remote_tmux_session": self.remote_tmux_session,
            "request_id": self.request_id,
            "resolved_hostname": self.resolved_hostname,
            "resolved_port": self.resolved_port,
            "resolved_user": self.resolved_user,
            "start_time": self.start_time,
            "state": self.state.value,
            "terminal_restored": self.terminal_restored,
            "updated_at": self.updated_at,
            "viewer_detached": self.viewer_detached,
        }
        if self.record_version == STATE_FORMAT_VERSION:
            document.update(
                {
                    "disconnect_policy": self.disconnect_policy.value,
                    "reboot_recovery": (
                        None
                        if self.reboot_recovery is None
                        else self.reboot_recovery.payload_document()
                    ),
                    "resolved_identity_sha256": self.resolved_identity_sha256,
                    "remote_phase": self.remote_phase.value,
                }
            )
        elif self.record_version == 3:
            document.update(
                {
                    "disconnect_policy": self.disconnect_policy.value,
                    "reboot_recovery": (
                        None
                        if self.reboot_recovery is None
                        else self.reboot_recovery.payload_document()
                    ),
                    "resolved_identity_sha256": self.resolved_identity_sha256,
                }
            )
        return document

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> "DurableJobRecord":
        version = payload.get("record_version")
        expected = {
            "client_request_sha256", "completion_time", "connection_plan_sha256",
            "created_at", "decision", "endpoint_id", "exit_status", "failure_detail",
            "generation", "host_key_alias", "local_spool_manifest_sha256",
            "local_spool_verified", "machine_alias",
            "record_version", "remote_job_path", "remote_mutation_started",
            "remote_tmux_session", "request_id", "resolved_hostname", "resolved_port",
            "resolved_user", "start_time", "state", "terminal_restored", "updated_at",
            "viewer_detached",
        }
        if version == STATE_FORMAT_VERSION:
            expected.update(
                {
                    "disconnect_policy",
                    "reboot_recovery",
                    "resolved_identity_sha256",
                    "remote_phase",
                }
            )
        elif version == 3:
            expected.update(
                {
                    "disconnect_policy",
                    "reboot_recovery",
                    "resolved_identity_sha256",
                }
            )
        elif version != 2:
            raise StateCorruptionError("unsupported state record version")
        if set(payload) != expected:
            raise StateCorruptionError("state payload fields are not exactly recognized")
        return cls(
            request_id=payload["request_id"],
            generation=payload["generation"],
            machine_alias=payload["machine_alias"],
            client_request_sha256=payload["client_request_sha256"],
            connection_plan_sha256=payload["connection_plan_sha256"],
            endpoint_id=payload["endpoint_id"],
            resolved_user=payload["resolved_user"],
            resolved_hostname=payload["resolved_hostname"],
            resolved_port=payload["resolved_port"],
            host_key_alias=payload["host_key_alias"],
            remote_job_path=payload["remote_job_path"],
            remote_tmux_session=payload["remote_tmux_session"],
            decision=payload["decision"],
            state=payload["state"],
            created_at=payload["created_at"],
            updated_at=payload["updated_at"],
            start_time=payload["start_time"],
            completion_time=payload["completion_time"],
            exit_status=payload["exit_status"],
            remote_mutation_started=payload["remote_mutation_started"],
            local_spool_verified=payload["local_spool_verified"],
            local_spool_manifest_sha256=payload["local_spool_manifest_sha256"],
            viewer_detached=payload["viewer_detached"],
            terminal_restored=payload["terminal_restored"],
            failure_detail=payload["failure_detail"],
            resolved_identity_sha256=(
                payload["resolved_identity_sha256"]
                if version in {3, STATE_FORMAT_VERSION}
                else None
            ),
            disconnect_policy=(
                payload["disconnect_policy"]
                if version in {3, STATE_FORMAT_VERSION}
                else DisconnectPolicy.NORMAL
            ),
            reboot_recovery=(
                None
                if version not in {3, STATE_FORMAT_VERSION}
                or payload["reboot_recovery"] is None
                else RebootRecoveryEvidence.from_payload(payload["reboot_recovery"])
            ),
            remote_phase=(
                payload["remote_phase"]
                if version == STATE_FORMAT_VERSION
                else RemotePhase.LEGACY_UNCERTAIN
                if payload["remote_mutation_started"]
                else RemotePhase.NOT_ATTEMPTED
            ),
            record_version=version,
        )


@dataclass(frozen=True, slots=True)
class RemoteStartPermit:
    request_id: str
    durable_generation: int
    durable_payload_sha256: str


@dataclass(frozen=True, slots=True)
class StartupRecoveryReport:
    records: tuple[DurableJobRecord, ...]
    interrupted_pre_remote_ids: tuple[str, ...]
    blocking_request_ids: tuple[str, ...]
    safe_to_accept_new_approvals: bool
    blocking_machine_aliases: tuple[str, ...] = ()
    expected_reboot_request_ids: tuple[str, ...] = ()
    automatic_recovery_request_ids: tuple[str, ...] = ()


class DurableStateStore:
    """Atomic per-request JSON records under one validated private directory."""

    def __init__(
        self,
        state_dir: os.PathLike[str] | str,
        *,
        expected_uid: int | None = None,
        cleanup_stale_temporaries: bool = True,
    ):
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        if type(self.expected_uid) is not int or self.expected_uid < 0:
            raise StateError("expected UID must be a non-negative integer")
        if not isinstance(cleanup_stale_temporaries, bool):
            raise TypeError("cleanup_stale_temporaries must be boolean")
        self._cleanup_stale_temporaries = cleanup_stale_temporaries
        root = ensure_private_directory(state_dir, expected_uid=self.expected_uid)
        self.jobs_dir = ensure_private_directory(
            root / STATE_JOBS_DIRECTORY_NAME, expected_uid=self.expected_uid
        )
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            self._directory_fd = os.open(self.jobs_dir, flags)
        except OSError as exc:
            raise StateError("cannot open durable jobs directory") from exc
        metadata = os.fstat(self._directory_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self.expected_uid
            or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
        ):
            os.close(self._directory_fd)
            raise StateCorruptionError("durable jobs directory is not private and owned")
        self._lock = threading.Lock()

    def close(self) -> None:
        descriptor = getattr(self, "_directory_fd", -1)
        if descriptor >= 0:
            os.close(descriptor)
            self._directory_fd = -1

    def __enter__(self) -> "DurableStateStore":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @staticmethod
    def _filename(request_id: str) -> str:
        return f"{validate_request_id(request_id)}.json"

    def _read_bytes(self, filename: str) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(filename, flags, dir_fd=self._directory_fd)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise StateCorruptionError(f"cannot safely open state file {filename}") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.expected_uid
                or stat.S_IMODE(metadata.st_mode) != STATE_FILE_MODE
                or metadata.st_size > MAX_STATE_FILE_BYTES
            ):
                raise StateCorruptionError(f"state file metadata is unsafe: {filename}")
            chunks: list[bytes] = []
            remaining = MAX_STATE_FILE_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) > MAX_STATE_FILE_BYTES:
                raise StateCorruptionError(f"state file is too large: {filename}")
            return content
        finally:
            os.close(descriptor)

    @staticmethod
    def _decode(content: bytes) -> DurableJobRecord:
        def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise StateCorruptionError(f"duplicate state JSON key: {key}")
                result[key] = value
            return result

        def reject_constant(value: str) -> object:
            raise StateCorruptionError(f"nonstandard JSON constant: {value}")

        try:
            envelope = json.loads(
                content.decode("ascii"),
                object_pairs_hook=no_duplicates,
                parse_constant=reject_constant,
            )
        except StateCorruptionError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StateCorruptionError("state file is not canonical ASCII JSON") from exc
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "sha256"}:
            raise StateCorruptionError("state envelope fields are invalid")
        payload = envelope["payload"]
        digest = envelope["sha256"]
        if not isinstance(payload, dict) or not isinstance(digest, str):
            raise StateCorruptionError("state envelope values are invalid")
        if _sha256_document(payload) != digest:
            raise StateCorruptionError("state payload checksum does not match")
        return DurableJobRecord.from_payload(payload)

    def load(self, request_id: str) -> DurableJobRecord:
        filename = self._filename(request_id)
        with self._lock:
            record = self._decode(self._read_bytes(filename))
        if record.request_id != request_id:
            raise StateCorruptionError("state filename and request ID do not match")
        return record

    def _existing_generation(self, filename: str) -> int | None:
        try:
            return self._decode(self._read_bytes(filename)).generation
        except FileNotFoundError:
            return None

    def write(self, record: DurableJobRecord) -> DurableJobRecord:
        if not isinstance(record, DurableJobRecord):
            raise TypeError("record must be a DurableJobRecord")
        filename = self._filename(record.request_id)
        payload = record.payload_document()
        envelope = {"payload": payload, "sha256": _sha256_document(payload)}
        content = _canonical_json(envelope) + b"\n"
        if len(content) > MAX_STATE_FILE_BYTES:
            raise StateError("state record exceeds the configured limit")

        with self._lock:
            existing_generation = self._existing_generation(filename)
            expected_generation = 1 if existing_generation is None else existing_generation + 1
            if record.generation != expected_generation:
                raise StateConflictError(
                    f"state generation must be {expected_generation}, got {record.generation}"
                )
            temp_name = f".{record.request_id}.{secrets.token_hex(16)}.tmp"
            flags = (
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = -1
            try:
                descriptor = os.open(
                    temp_name, flags, STATE_FILE_MODE, dir_fd=self._directory_fd
                )
                offset = 0
                while offset < len(content):
                    written = os.write(descriptor, content[offset:])
                    if written <= 0:
                        raise StateError("state file write made no progress")
                    offset += written
                os.fsync(descriptor)
                os.close(descriptor)
                descriptor = -1
                os.replace(
                    temp_name,
                    filename,
                    src_dir_fd=self._directory_fd,
                    dst_dir_fd=self._directory_fd,
                )
                os.fsync(self._directory_fd)
            except BaseException:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    os.unlink(temp_name, dir_fd=self._directory_fd)
                except FileNotFoundError:
                    pass
                raise
        return record

    def _remove_stale_temp(self, name: str) -> None:
        metadata = os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != self.expected_uid
            or stat.S_IMODE(metadata.st_mode) != STATE_FILE_MODE
        ):
            raise StateCorruptionError(f"unsafe stale state temporary file: {name}")
        os.unlink(name, dir_fd=self._directory_fd)

    def load_all(self) -> tuple[DurableJobRecord, ...]:
        with self._lock:
            records: list[DurableJobRecord] = []
            removed_temp = False
            for name in sorted(os.listdir(self._directory_fd)):
                temp = _TEMP_RE.fullmatch(name)
                if temp is not None:
                    if self._cleanup_stale_temporaries:
                        self._remove_stale_temp(name)
                        removed_temp = True
                    continue
                final = _FINAL_RE.fullmatch(name)
                if final is None:
                    raise StateCorruptionError(f"unexpected durable state entry: {name}")
                record = self._decode(self._read_bytes(name))
                if record.request_id != final.group(1):
                    raise StateCorruptionError("state filename and request ID do not match")
                records.append(record)
            if removed_temp:
                os.fsync(self._directory_fd)
        records.sort(key=lambda item: (item.created_at, item.request_id))
        return tuple(records)

    def retarget_pre_remote_endpoint(
        self,
        record: DurableJobRecord,
        connection_plan: ConnectionPlan,
        planned_endpoint: PlannedEndpoint,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Re-point an approved, unmutated record at another approved endpoint.

        Route fallback is offered only before any remote mutation, so the
        durable record may still follow the plan without claiming that the
        previously named host was contacted.
        """

        if record.state is not RequestState.APPROVED_PRE_REMOTE:
            raise StateConflictError(
                "endpoint retargeting requires approved-pre-remote state"
            )
        if record.remote_mutation_started:
            raise StateConflictError(
                "endpoint retargeting cannot follow a remote mutation"
            )
        if not isinstance(connection_plan, ConnectionPlan):
            raise TypeError("connection_plan must be a ConnectionPlan")
        if record.connection_plan_sha256 != connection_plan.plan_sha256:
            raise StateConflictError(
                "endpoint retargeting requires the record's approved connection plan"
            )
        if (
            not isinstance(planned_endpoint, PlannedEndpoint)
            or planned_endpoint not in connection_plan.endpoints
        ):
            raise StateConflictError("planned endpoint is not in the connection plan")
        selected = planned_endpoint.resolved
        if selected.endpoint_id == record.endpoint_id:
            return record
        timestamp = now()
        retargeted = replace(
            record,
            generation=record.generation + 1,
            endpoint_id=selected.endpoint_id,
            resolved_user=selected.resolved_user,
            resolved_hostname=selected.resolved_hostname,
            resolved_port=selected.resolved_port,
            host_key_alias=selected.host_key_alias,
            resolved_identity_sha256=_sha256_document(
                selected.canonical_document()
            ),
            updated_at=timestamp,
        )
        self.write(retargeted)
        return retargeted

    def mark_remote_connection_attempted(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Fsync that the approved endpoint may have received an SSH attempt."""

        if record.record_version != STATE_FORMAT_VERSION:
            raise StateConflictError("atomic remote phases require current durable state")
        if record.state not in {
            RequestState.APPROVED_PRE_REMOTE,
            RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
        }:
            raise StateConflictError("connection attempt requires approved setup")
        if record.remote_phase is RemotePhase.CONNECTION_ATTEMPTED:
            return record
        if record.remote_phase is not RemotePhase.NOT_ATTEMPTED:
            raise StateConflictError("connection attempt is out of order")
        attempted = replace(
            record,
            generation=record.generation + 1,
            updated_at=now(),
            remote_phase=RemotePhase.CONNECTION_ATTEMPTED,
        )
        self.write(attempted)
        return attempted

    def upgrade_legacy_remote_observation(
        self,
        record: DurableJobRecord,
        *,
        observed_phase: RemotePhase,
        detail: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Upgrade only positive authenticated legacy remote evidence.

        A legacy broad mutation bit cannot prove a narrower phase on its own.
        An exact gated session does prove wrapper creation, while a released
        gate, running command, or authenticated complete spool proves command
        start. Missing remote artifacts are intentionally not accepted here.
        """

        if (
            record.record_version not in LEGACY_STATE_FORMAT_VERSIONS
            or record.remote_phase is not RemotePhase.LEGACY_UNCERTAIN
            or record.state is not RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING
            or observed_phase not in {
                RemotePhase.REMOTE_WRAPPER_CREATED,
                RemotePhase.USER_COMMAND_STARTED,
            }
        ):
            raise StateConflictError(
                "legacy phase upgrade requires positive exact-job recovery evidence"
            )
        _validate_text(detail, "legacy phase upgrade detail")
        upgraded = replace(
            record,
            generation=record.generation + 1,
            record_version=STATE_FORMAT_VERSION,
            updated_at=now(),
            remote_mutation_started=(
                observed_phase is RemotePhase.USER_COMMAND_STARTED
            ),
            remote_phase=observed_phase,
            failure_detail=detail,
        )
        self.write(upgraded)
        return upgraded

    def request_remote_staging(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> tuple[DurableJobRecord, RemoteStartPermit]:
        """Fsync immediately before the first remote staging request."""

        if record.state not in {
            RequestState.APPROVED_PRE_REMOTE,
            RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
        } or record.remote_phase is not RemotePhase.CONNECTION_ATTEMPTED:
            raise StateConflictError("staging requires an attempted approved connection")
        staged = replace(
            record,
            generation=record.generation + 1,
            updated_at=now(),
            remote_phase=RemotePhase.STAGING_REQUESTED,
        )
        self.write(staged)
        digest = _sha256_document(staged.payload_document())
        return staged, RemoteStartPermit(staged.request_id, staged.generation, digest)

    def mark_remote_staging_verified(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.remote_phase is not RemotePhase.STAGING_REQUESTED:
            raise StateConflictError("staging verification lacks a staging request")
        verified = replace(
            record,
            generation=record.generation + 1,
            updated_at=now(),
            remote_phase=RemotePhase.STAGING_VERIFIED,
        )
        self.write(verified)
        return verified

    def request_remote_wrapper(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.remote_phase is not RemotePhase.STAGING_VERIFIED:
            raise StateConflictError("wrapper creation requires verified staging")
        requested = replace(
            record,
            generation=record.generation + 1,
            updated_at=now(),
            remote_phase=RemotePhase.REMOTE_WRAPPER_REQUESTED,
        )
        self.write(requested)
        return requested

    def mark_remote_wrapper_created(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.remote_phase is not RemotePhase.REMOTE_WRAPPER_REQUESTED:
            raise StateConflictError("wrapper verification lacks a creation request")
        created = replace(
            record,
            generation=record.generation + 1,
            updated_at=now(),
            remote_phase=RemotePhase.REMOTE_WRAPPER_CREATED,
        )
        self.write(created)
        return created

    def mark_user_command_started(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Record only an observed release of the remote command-start gate."""

        if record.remote_phase is not RemotePhase.REMOTE_WRAPPER_CREATED:
            raise StateConflictError("command start requires a verified remote wrapper")
        timestamp = now()
        reboot = record.reboot_recovery
        if record.disconnect_policy is DisconnectPolicy.EXPECT_FULL_REBOOT:
            if reboot is None:
                raise StateConflictError(
                    "expected reboot start requires durable pre-boot evidence"
                )
            reboot = replace(
                reboot,
                remote_start_time=record.start_time or timestamp,
                remote_start_generation=record.generation + 1,
            )
        started = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.REMOTE_MAY_BE_RUNNING,
            remote_mutation_started=True,
            start_time=record.start_time or timestamp,
            updated_at=timestamp,
            reboot_recovery=reboot,
            remote_phase=RemotePhase.USER_COMMAND_STARTED,
        )
        self.write(started)
        return started

    def arm_remote_start(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> tuple[DurableJobRecord, RemoteStartPermit]:
        """Fsync `REMOTE_MAY_BE_RUNNING` before returning a start permit."""

        if record.state not in {
            RequestState.APPROVED_PRE_REMOTE,
            RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
        }:
            raise StateConflictError(
                "remote start can be armed only after approval and verified setup"
            )
        if record.remote_job_path is None or record.connection_plan_sha256 is None:
            raise StateConflictError(
                "remote start requires a planned guarded job identity and connection plan"
            )
        timestamp = now()
        reboot = record.reboot_recovery
        if record.disconnect_policy is DisconnectPolicy.EXPECT_FULL_REBOOT:
            if reboot is None:
                raise StateConflictError(
                    "expected reboot start requires durable pre-boot evidence"
                )
            reboot = replace(
                reboot,
                remote_start_time=record.start_time or timestamp,
                remote_start_generation=record.generation + 1,
            )
        armed = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.REMOTE_MAY_BE_RUNNING,
            remote_mutation_started=True,
            start_time=record.start_time or timestamp,
            updated_at=timestamp,
            reboot_recovery=reboot,
            remote_phase=RemotePhase.USER_COMMAND_STARTED,
        )
        self.write(armed)
        payload_digest = _sha256_document(armed.payload_document())
        return armed, RemoteStartPermit(armed.request_id, armed.generation, payload_digest)

    def record_pre_reboot_boot_id(
        self,
        record: DurableJobRecord,
        *,
        boot_id: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Fsync exact pre-reboot evidence before the command start boundary."""

        if record.disconnect_policy is not DisconnectPolicy.EXPECT_FULL_REBOOT:
            raise StateConflictError("pre-reboot evidence requires expected reboot policy")
        if record.state not in {
            RequestState.APPROVED_PRE_REMOTE,
            RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
        }:
            raise StateConflictError("pre-reboot evidence must precede remote command start")
        if record.reboot_recovery is not None:
            raise StateConflictError("pre-reboot evidence is already recorded")
        if not isinstance(boot_id, str) or _BOOT_ID_RE.fullmatch(boot_id) is None:
            raise ValueError("boot_id must be one canonical lowercase Linux boot ID")
        if any(
            value is None
            for value in (
                record.connection_plan_sha256,
                record.endpoint_id,
                record.resolved_identity_sha256,
                record.host_key_alias,
            )
        ):
            raise StateConflictError("pre-reboot evidence lacks an exact resolved identity")
        timestamp = now()
        next_generation = record.generation + 1
        evidence = RebootRecoveryEvidence(
            request_id=record.request_id,
            machine_alias=record.machine_alias,
            connection_plan_sha256=record.connection_plan_sha256,
            endpoint_id=record.endpoint_id,
            resolved_identity_sha256=record.resolved_identity_sha256,
            host_key_alias=record.host_key_alias,
            pre_boot_id=boot_id,
            pre_boot_id_captured_at=timestamp,
            pre_boot_id_generation=next_generation,
        )
        captured = replace(
            record,
            generation=next_generation,
            updated_at=timestamp,
            reboot_recovery=evidence,
        )
        self.write(captured)
        return captured

    def begin_expected_reboot_verification(
        self,
        record: DurableJobRecord,
        *,
        deadline_at: str,
        detail: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Persist the bounded recovery window after the expected disconnect."""

        if record.state not in {
            RequestState.REMOTE_MAY_BE_RUNNING,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            RequestState.COMPLETION_PROVEN,
            RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING,
        } or record.reboot_recovery is None:
            raise StateConflictError("expected reboot verification lacks an armed request")
        _validate_timestamp(deadline_at, "recovery_deadline_at")
        if not isinstance(detail, str) or not detail or "\x00" in detail:
            raise ValueError("recovery detail must be non-empty text without NUL")
        timestamp = now()
        reboot = replace(
            record.reboot_recovery,
            phase=RebootRecoveryPhase.VERIFICATION_PENDING,
            recovery_started_at=record.reboot_recovery.recovery_started_at or timestamp,
            recovery_deadline_at=record.reboot_recovery.recovery_deadline_at or deadline_at,
            failure_code=None,
        )
        pending = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING,
            updated_at=timestamp,
            failure_detail=detail,
            reboot_recovery=reboot,
        )
        self.write(pending)
        return pending

    def record_expected_reboot_probe_failure(
        self,
        record: DurableJobRecord,
        *,
        failure_code: str,
        detail: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if (
            record.state is not RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING
            or record.reboot_recovery is None
        ):
            raise StateConflictError("reboot probe attempt requires pending verification")
        _validate_text(failure_code, "failure_code")
        _validate_text(detail, "recovery detail")
        timestamp = now()
        reboot = replace(
            record.reboot_recovery,
            phase=RebootRecoveryPhase.VERIFICATION_PENDING,
            probe_attempts=record.reboot_recovery.probe_attempts + 1,
            last_probe_at=timestamp,
            failure_code=failure_code,
        )
        attempted = replace(
            record,
            generation=record.generation + 1,
            updated_at=timestamp,
            failure_detail=detail,
            reboot_recovery=reboot,
        )
        self.write(attempted)
        return attempted

    def record_same_boot_observed(
        self,
        record: DurableJobRecord,
        *,
        boot_id: str,
        detail: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if (
            record.state is not RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING
            or record.reboot_recovery is None
        ):
            raise StateConflictError("same-boot evidence requires pending verification")
        if boot_id != record.reboot_recovery.pre_boot_id:
            raise StateConflictError("same-boot evidence does not match the pre-boot ID")
        _validate_text(detail, "recovery detail")
        timestamp = now()
        reboot = replace(
            record.reboot_recovery,
            phase=RebootRecoveryPhase.SAME_BOOT_OBSERVED,
            post_boot_id=boot_id,
            probe_attempts=record.reboot_recovery.probe_attempts + 1,
            last_probe_at=timestamp,
            failure_code="same_boot_observed",
        )
        observed = replace(
            record,
            generation=record.generation + 1,
            updated_at=timestamp,
            failure_detail=detail,
            reboot_recovery=reboot,
        )
        self.write(observed)
        return observed

    def mark_expected_reboot_verified(
        self,
        record: DurableJobRecord,
        *,
        post_boot_id: str,
        reason: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Commit changed-boot evidence before any lease or pin release."""

        if (
            record.state is not RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING
            or record.reboot_recovery is None
        ):
            raise StateConflictError("verified reboot requires pending verification")
        if (
            not isinstance(post_boot_id, str)
            or _BOOT_ID_RE.fullmatch(post_boot_id) is None
            or post_boot_id == record.reboot_recovery.pre_boot_id
        ):
            raise StateConflictError("verified reboot requires a changed canonical boot ID")
        _validate_text(reason, "automatic_reason")
        timestamp = now()
        evidence_without_digest = replace(
            record.reboot_recovery,
            phase=RebootRecoveryPhase.VERIFICATION_PENDING,
            post_boot_id=post_boot_id,
            probe_attempts=record.reboot_recovery.probe_attempts + 1,
            last_probe_at=timestamp,
            verified_at=timestamp,
            automatic_decision="abandon_after_verified_reboot",
            automatic_reason=reason,
            failure_code=None,
            cleanup_outcome="pending",
        )
        evidence = replace(
            evidence_without_digest,
            phase=RebootRecoveryPhase.VERIFIED_CHANGED_BOOT,
            evidence_sha256=evidence_without_digest.computed_evidence_sha256(),
        )
        verified = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING,
            updated_at=timestamp,
            completion_time=None,
            exit_status=None,
            local_spool_verified=False,
            local_spool_manifest_sha256=None,
            viewer_detached=False,
            terminal_restored=False,
            failure_detail=reason,
            reboot_recovery=evidence,
        )
        self.write(verified)
        return verified

    def fail_expected_reboot_recovery(
        self,
        record: DurableJobRecord,
        *,
        failure_code: str,
        detail: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if (
            record.state is not RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING
            or record.reboot_recovery is None
        ):
            raise StateConflictError("failed reboot recovery requires pending verification")
        _validate_text(failure_code, "failure_code")
        _validate_text(detail, "recovery detail")
        timestamp = now()
        reboot = replace(
            record.reboot_recovery,
            phase=RebootRecoveryPhase.FAILED,
            failure_code=failure_code,
            automatic_decision="fail_closed",
            automatic_reason=detail,
        )
        failed = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.EXPECTED_REBOOT_RECOVERY_FAILED,
            updated_at=timestamp,
            failure_detail=detail,
            reboot_recovery=reboot,
        )
        self.write(failed)
        return failed

    def complete_expected_reboot_cleanup(
        self,
        record: DurableJobRecord,
        *,
        cleanup_outcome: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Record exact transport cleanup after changed-boot evidence is durable."""

        if (
            record.state is not RequestState.EXPECTED_REBOOT_VERIFIED_CLEANUP_PENDING
            or record.reboot_recovery is None
        ):
            raise StateConflictError("reboot cleanup requires committed changed-boot evidence")
        _validate_text(cleanup_outcome, "cleanup_outcome")
        timestamp = now()
        reboot = replace(
            record.reboot_recovery,
            phase=RebootRecoveryPhase.CLEANUP_COMPLETE,
            cleanup_outcome=cleanup_outcome,
        )
        abandoned = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.ABANDONED_AFTER_VERIFIED_REBOOT,
            updated_at=timestamp,
            failure_detail=(
                f"{record.failure_detail}; transport cleanup: {cleanup_outcome}"
            ),
            reboot_recovery=reboot,
        )
        self.write(abandoned)
        return abandoned

    def arm_key_enrollment(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Fsync the enrollment boundary before ``authorized_keys`` may change."""

        if record.state is not RequestState.APPROVED_PRE_REMOTE:
            raise StateConflictError("key enrollment can be armed only after approval")
        timestamp = now()
        armed = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.KEY_ENROLLMENT_MAY_HAVE_STARTED,
            remote_mutation_started=True,
            start_time=timestamp,
            updated_at=timestamp,
        )
        self.write(armed)
        return armed

    def mark_key_enrollment_verified(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Record that enrollment completed and the exact key is present."""

        if record.state is not RequestState.KEY_ENROLLMENT_MAY_HAVE_STARTED:
            raise StateConflictError("key enrollment verification lacks its boundary")
        timestamp = now()
        verified = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
            updated_at=timestamp,
        )
        self.write(verified)
        return verified

    def fail_remote_setup(
        self,
        record: DurableJobRecord,
        *,
        detail: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Terminalize setup after a remote mutation, without claiming a job ran."""

        if record.state not in {
            RequestState.KEY_ENROLLMENT_MAY_HAVE_STARTED,
            RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
        }:
            raise StateConflictError(
                "remote setup failure requires a key-enrollment mutation state"
            )
        if not isinstance(detail, str) or not detail or "\x00" in detail:
            raise ValueError("failure detail must be non-empty text without NUL")
        timestamp = now()
        failed = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.FAILED_REMOTE_SETUP,
            updated_at=timestamp,
            failure_detail=detail,
        )
        self.write(failed)
        return failed

    def fail_pre_remote(
        self,
        record: DurableJobRecord,
        *,
        detail: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.state is not RequestState.APPROVED_PRE_REMOTE:
            raise StateConflictError("pre-remote failure requires approved-pre-remote state")
        if record.record_version == STATE_FORMAT_VERSION and record.remote_phase in {
            RemotePhase.REMOTE_WRAPPER_REQUESTED,
            RemotePhase.REMOTE_WRAPPER_CREATED,
            RemotePhase.USER_COMMAND_STARTED,
            RemotePhase.RESULT_SPOOL_FINALIZED,
            RemotePhase.RESULT_SPOOL_LOCALLY_VERIFIED,
            RemotePhase.CLEANUP_COMPLETED,
        }:
            raise StateConflictError("pre-remote failure cannot discard wrapper uncertainty")
        if not isinstance(detail, str) or not detail or "\x00" in detail:
            raise ValueError("failure detail must be non-empty text without NUL")
        timestamp = now()
        failed = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.FAILED_PRE_REMOTE,
            updated_at=timestamp,
            failure_detail=detail,
        )
        self.write(failed)
        return failed

    def fail_before_command_after_verified_observation(
        self,
        record: DurableJobRecord,
        *,
        detail: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Terminalize only after an authenticated exact-job unstarted proof."""

        if (
            record.record_version != STATE_FORMAT_VERSION
            or record.state not in {
                RequestState.APPROVED_PRE_REMOTE,
                RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            }
            or record.remote_phase not in {
                RemotePhase.REMOTE_WRAPPER_REQUESTED,
                RemotePhase.REMOTE_WRAPPER_CREATED,
            }
            or record.remote_mutation_started
        ):
            raise StateConflictError(
                "verified pre-command failure requires current wrapper uncertainty"
            )
        _validate_text(detail, "verified pre-command failure detail")
        failed = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.FAILED_PRE_REMOTE,
            updated_at=now(),
            failure_detail=detail,
        )
        self.write(failed)
        return failed

    def mark_recovery_required(
        self,
        record: DurableJobRecord,
        *,
        detail: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.state not in {
            RequestState.APPROVED_PRE_REMOTE,
            RequestState.REMOTE_MAY_BE_RUNNING,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        }:
            raise StateConflictError("recovery requires a possibly-running state")
        if (
            record.state is RequestState.APPROVED_PRE_REMOTE
            and record.remote_phase not in {
                RemotePhase.REMOTE_WRAPPER_REQUESTED,
                RemotePhase.REMOTE_WRAPPER_CREATED,
            }
        ):
            raise StateConflictError("pre-start recovery requires wrapper uncertainty")
        if not isinstance(detail, str) or not detail or "\x00" in detail:
            raise ValueError("recovery detail must be non-empty text without NUL")
        timestamp = now()
        recovery = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            updated_at=timestamp,
            failure_detail=detail,
        )
        self.write(recovery)
        return recovery

    def mark_abandoned_after_operator_confirmed_reboot(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Release a stranded job only after a full reboot is operator-attested.

        A possibly-running job has no completion evidence to preserve. A
        completion-proven job can still be stranded when the reboot destroys
        its SSH master before canonical output is collected. In that case the
        prior structured completion evidence is copied into the audit detail
        before the unverified completion gates are cleared. The durable record
        remains readable by older releases and is never relabeled as a verified
        result.
        """

        if record.disconnect_policy is not DisconnectPolicy.NORMAL:
            raise StateConflictError(
                "expected-reboot requests require automatic changed-boot evidence"
            )
        if record.state not in {
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            RequestState.COMPLETION_PROVEN,
        }:
            raise StateConflictError(
                "operator-confirmed reboot abandonment requires recovery or "
                "uncollected completion state"
            )
        if (
            record.local_spool_verified
            or record.local_spool_manifest_sha256 is not None
        ):
            raise StateConflictError(
                "operator-confirmed reboot abandonment refuses verified local results"
            )
        if (
            record.state is RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING
            and any(
                (
                    record.completion_time is not None,
                    record.exit_status is not None,
                    record.viewer_detached,
                    record.terminal_restored,
                )
            )
        ):
            raise StateConflictError(
                "operator-confirmed reboot recovery has inconsistent completion gates"
            )
        timestamp = now()
        if record.state is RequestState.COMPLETION_PROVEN:
            prior_detail = (
                "remote completion was previously proven at "
                f"{record.completion_time} with exit status {record.exit_status}, "
                f"viewer_detached={str(record.viewer_detached).lower()}, and "
                f"terminal_restored={str(record.terminal_restored).lower()}, but "
                "canonical output and the local result spool were not verified"
            )
        else:
            prior_detail = record.failure_detail or "remote execution became uncertain"
        audit_detail = (
            f"{prior_detail}; controlling-terminal operator confirmed a full reboot "
            f"of logical machine {record.machine_alias} after remote start; remote "
            "result publication was abandoned and no SSH action or remote cleanup "
            "was attempted"
        )
        abandoned = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
            updated_at=timestamp,
            completion_time=None,
            exit_status=None,
            local_spool_verified=False,
            local_spool_manifest_sha256=None,
            viewer_detached=False,
            terminal_restored=False,
            failure_detail=audit_detail,
        )
        self.write(abandoned)
        return abandoned

    def mark_abandoned_after_operator_confirmed_dead_pane(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Release an uncertain job after the operator observed its pane dead.

        This transition is an auditable abandonment, never a completion claim.
        It records no exit status, canonical output, result spool, viewer-detach
        proof, or terminal-restoration proof and performs no remote operation.
        """

        if record.disconnect_policy is not DisconnectPolicy.NORMAL:
            raise StateConflictError(
                "dead-pane observation cannot replace expected-reboot evidence"
            )
        if record.state is not RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING:
            raise StateConflictError(
                "operator-confirmed dead-pane abandonment requires recovery state"
            )
        if any(
            (
                record.completion_time is not None,
                record.exit_status is not None,
                record.local_spool_verified,
                record.local_spool_manifest_sha256 is not None,
                record.viewer_detached,
                record.terminal_restored,
            )
        ):
            raise StateConflictError(
                "operator-confirmed dead-pane abandonment requires every completion "
                "gate to remain unproven"
            )
        timestamp = now()
        prior_detail = record.failure_detail or "remote execution became uncertain"
        audit_detail = (
            f"{prior_detail}; controlling-terminal operator confirmed the dedicated "
            f"tmux pane for logical machine {record.machine_alias} was visibly dead "
            "after the foreground command finished; remote completion, exit status, "
            "canonical output, and local spool remain unproven"
        )
        abandoned = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
            updated_at=timestamp,
            failure_detail=audit_detail,
        )
        self.write(abandoned)
        return abandoned

    def mark_abandoned_after_operator_acknowledged_uncertainty(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """One-action local abandonment for irreducible remote uncertainty.

        This never contacts or deletes the remote identity and never records an
        exit status, output, result spool, or assertion that the command ended.
        """

        if (
            record.disconnect_policy is not DisconnectPolicy.NORMAL
            or record.state is not RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING
            or any(
                (
                    record.completion_time is not None,
                    record.exit_status is not None,
                    record.local_spool_verified,
                    record.local_spool_manifest_sha256 is not None,
                    record.viewer_detached,
                    record.terminal_restored,
                )
            )
        ):
            raise StateConflictError(
                "uncertainty acknowledgement requires an unproven normal remote job"
            )
        timestamp = now()
        evidence = record.failure_detail or (
            "remote execution has no authoritative completion or termination evidence"
        )
        abandoned = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.ABANDONED_AFTER_OPERATOR_ACKNOWLEDGED_UNCERTAINTY,
            updated_at=timestamp,
            failure_detail=(
                f"{evidence}; controlling-terminal operator used the single TUI "
                "uncertainty action to unblock local scheduling; no remote cleanup "
                "was attempted and no completion, exit status, output, result spool, "
                "or remote absence is claimed"
            ),
        )
        self.write(abandoned)
        return abandoned

    def mark_abandoned_after_proven_unstarted(
        self,
        record: DurableJobRecord,
        *,
        evidence_request_id: str,
        evidence_manifest_sha256: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Release a job after canonical evidence proves it never started.

        The caller must separately verify the canonical evidence request and
        exact remote cleanup. This transition records those immutable local
        evidence identities and never claims command completion or output.
        """

        if record.state is not RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING:
            raise StateConflictError(
                "proven-unstarted abandonment requires recovery state"
            )
        evidence_request_id = validate_request_id(evidence_request_id)
        evidence_manifest_sha256 = _validate_digest(
            evidence_manifest_sha256,
            "evidence_manifest_sha256",
        )
        if evidence_request_id == record.request_id:
            raise StateConflictError("recovery evidence must be a separate request")
        if any(
            (
                record.completion_time is not None,
                record.exit_status is not None,
                record.local_spool_verified,
                record.local_spool_manifest_sha256 is not None,
                record.viewer_detached,
                record.terminal_restored,
            )
        ):
            raise StateConflictError(
                "proven-unstarted abandonment requires every completion gate "
                "to remain unproven"
            )
        timestamp = now()
        prior_detail = record.failure_detail or "remote execution became uncertain"
        audit_detail = (
            f"{prior_detail}; canonical evidence request {evidence_request_id} "
            f"manifest {evidence_manifest_sha256} proved gate_released=0, "
            "command_running=0, completion_proven=0, session_after=0, and "
            "directory_after=0; the requested command never started and no "
            "command completion, exit status, canonical output, or result spool "
            "is claimed"
        )
        abandoned = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.ABANDONED_AFTER_PROVEN_UNSTARTED,
            updated_at=timestamp,
            failure_detail=audit_detail,
        )
        self.write(abandoned)
        return abandoned

    def mark_completion_proven(
        self,
        record: DurableJobRecord,
        *,
        exit_status: int,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.state not in {
            RequestState.REMOTE_MAY_BE_RUNNING,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            RequestState.EXPECTED_REBOOT_VERIFICATION_PENDING,
        }:
            raise StateConflictError("completion requires a possibly-running state")
        if (
            isinstance(exit_status, bool)
            or not isinstance(exit_status, int)
            or not 0 <= exit_status <= 255
        ):
            raise ValueError("remote exit status must be from 0 to 255")
        timestamp = now()
        completed = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.COMPLETION_PROVEN,
            updated_at=timestamp,
            completion_time=timestamp,
            exit_status=exit_status,
            failure_detail=None,
            remote_phase=(
                RemotePhase.RESULT_SPOOL_FINALIZED
                if record.record_version == STATE_FORMAT_VERSION
                else record.remote_phase
            ),
        )
        self.write(completed)
        return completed

    def mark_viewer_detached(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.state not in {
            RequestState.COMPLETION_PROVEN,
            RequestState.LOCAL_SPOOL_VERIFIED,
        }:
            raise StateConflictError("viewer detach requires proven completion")
        timestamp = now()
        detached = replace(
            record,
            generation=record.generation + 1,
            updated_at=timestamp,
            viewer_detached=True,
        )
        self.write(detached)
        return detached

    def mark_terminal_restored(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.state not in {
            RequestState.COMPLETION_PROVEN,
            RequestState.LOCAL_SPOOL_VERIFIED,
        } or not record.viewer_detached:
            raise StateConflictError(
                "terminal restoration requires proven completion and viewer detach"
            )
        timestamp = now()
        restored = replace(
            record,
            generation=record.generation + 1,
            updated_at=timestamp,
            terminal_restored=True,
        )
        self.write(restored)
        return restored

    def mark_local_spool_verified(
        self,
        record: DurableJobRecord,
        *,
        manifest_sha256: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.state is not RequestState.COMPLETION_PROVEN:
            raise StateConflictError("local spool verification requires proven completion")
        if not record.viewer_detached:
            raise StateConflictError("local spool verification requires viewer detach")
        if not isinstance(manifest_sha256, str) or _SHA256_RE.fullmatch(manifest_sha256) is None:
            raise ValueError("spool manifest digest must be a lowercase SHA-256 digest")
        timestamp = now()
        verified = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.LOCAL_SPOOL_VERIFIED,
            updated_at=timestamp,
            local_spool_verified=True,
            local_spool_manifest_sha256=manifest_sha256,
            remote_phase=(
                RemotePhase.RESULT_SPOOL_LOCALLY_VERIFIED
                if record.record_version == STATE_FORMAT_VERSION
                else record.remote_phase
            ),
        )
        self.write(verified)
        return verified

    def mark_remote_cleanup_completed(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        """Record exact, idempotent cleanup only after local spool verification."""

        if record.record_version != STATE_FORMAT_VERSION:
            raise StateConflictError("legacy cleanup evidence cannot be upgraded in place")
        if record.remote_phase is RemotePhase.CLEANUP_COMPLETED:
            return record
        if record.remote_phase is not RemotePhase.RESULT_SPOOL_LOCALLY_VERIFIED:
            raise StateConflictError("cleanup requires a locally verified result spool")
        cleaned = replace(
            record,
            generation=record.generation + 1,
            updated_at=now(),
            remote_phase=RemotePhase.CLEANUP_COMPLETED,
        )
        self.write(cleaned)
        return cleaned

    def release_lease(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if (
            record.state is not RequestState.LOCAL_SPOOL_VERIFIED
            or not record.viewer_detached
            or not record.terminal_restored
        ):
            raise StateConflictError("lease release requires every durable completion gate")
        timestamp = now()
        released = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.LEASE_RELEASED,
            updated_at=timestamp,
        )
        self.write(released)
        return released

    def begin_result_delivery(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.state is not RequestState.LEASE_RELEASED:
            raise StateConflictError("result delivery requires a released lease")
        timestamp = now()
        delivering = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.RESULT_DELIVERING,
            updated_at=timestamp,
        )
        self.write(delivering)
        return delivering

    def mark_done(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.state is not RequestState.RESULT_DELIVERING:
            raise StateConflictError("done requires result-delivering state")
        timestamp = now()
        done = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.DONE,
            updated_at=timestamp,
        )
        self.write(done)
        return done


def new_approved_job_record(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan,
    *,
    planned_endpoint: PlannedEndpoint | None = None,
    now: Callable[[], str] = utc_now,
) -> DurableJobRecord:
    """Create the first durable record after bound approval, before mutation.

    The remote path and session are predictable local plans at this point;
    neither is evidence that a remote object has been created.
    """

    request_id = validate_request_id(request_id)
    if not isinstance(request, RequestSpec):
        raise TypeError("request must be a RequestSpec")
    if not isinstance(connection_plan, ConnectionPlan):
        raise TypeError("connection_plan must be a ConnectionPlan")
    if request.machine_alias != connection_plan.machine_name:
        raise StateConflictError("request machine does not match the connection plan")
    if planned_endpoint is None:
        planned_endpoint = connection_plan.selected
    if (
        not isinstance(planned_endpoint, PlannedEndpoint)
        or planned_endpoint not in connection_plan.endpoints
    ):
        raise StateConflictError("planned endpoint is not in the connection plan")
    selected = planned_endpoint.resolved
    timestamp = now()
    return DurableJobRecord(
        request_id=request_id,
        generation=1,
        machine_alias=request.machine_alias,
        client_request_sha256=request.client_request_sha256(),
        connection_plan_sha256=connection_plan.plan_sha256,
        endpoint_id=selected.endpoint_id,
        resolved_user=selected.resolved_user,
        resolved_hostname=selected.resolved_hostname,
        resolved_port=selected.resolved_port,
        host_key_alias=selected.host_key_alias,
        resolved_identity_sha256=_sha256_document(selected.canonical_document()),
        remote_job_path=f"~/.cache/tmuxgate/jobs/{request_id}",
        remote_tmux_session=f"tmuxgate-{request_id[:12]}",
        decision=ApprovalDecision.APPROVED,
        state=RequestState.APPROVED_PRE_REMOTE,
        created_at=timestamp,
        updated_at=timestamp,
        disconnect_policy=request.disconnect_policy,
    )


def recover_startup(
    store: DurableStateStore,
    *,
    now: Callable[[], str] = utc_now,
) -> StartupRecoveryReport:
    """Reconcile proven pre-remote interruptions and block uncertain jobs."""

    records = list(store.load_all())
    interrupted: list[str] = []
    for index, record in enumerate(records):
        if (
            record.record_version == STATE_FORMAT_VERSION
            and record.state in {
                RequestState.APPROVED_PRE_REMOTE,
                RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
            }
            and record.remote_phase in {
                RemotePhase.REMOTE_WRAPPER_REQUESTED,
                RemotePhase.REMOTE_WRAPPER_CREATED,
            }
        ):
            records[index] = store.mark_recovery_required(
                record,
                detail=(
                    "broker restarted after durable phase "
                    f"{record.remote_phase.value}; exact remote evidence must be "
                    "reconciled automatically"
                ),
                now=now,
            )
            continue
        if record.state in {
            RequestState.KEY_ENROLLMENT_MAY_HAVE_STARTED,
            RequestState.KEY_ENROLLMENT_VERIFIED_PRE_REMOTE,
        }:
            detail = (
                "broker restarted after SSH key enrollment may have mutated "
                "authorized_keys; the requested command was not started"
                if record.state is RequestState.KEY_ENROLLMENT_MAY_HAVE_STARTED
                else
                "broker restarted after SSH key enrollment was verified but before "
                "the requested command start was armed"
            )
            records[index] = store.fail_remote_setup(record, detail=detail, now=now)
            interrupted.append(record.request_id)
            continue
        if record.state not in _SAFE_PRE_REMOTE_RESTART_STATES:
            continue
        if record.remote_mutation_started:
            raise StateCorruptionError("pre-remote recovery record claims remote mutation")
        timestamp = now()
        replacement_state = (
            RequestState.CANCELLED_BEFORE_APPROVAL
            if record.state is RequestState.QUEUED
            else RequestState.FAILED_PRE_REMOTE
        )
        recovered = replace(
            record,
            generation=record.generation + 1,
            state=replacement_state,
            updated_at=timestamp,
            failure_detail="broker restarted before the remote-mutation boundary",
        )
        store.write(recovered)
        records[index] = recovered
        interrupted.append(record.request_id)

    blocking_records = tuple(
        record for record in records if record.state in _REMOTE_ACTIVE_STATES
    )
    blocking = tuple(record.request_id for record in blocking_records)
    expected_reboot = tuple(
        record.request_id
        for record in blocking_records
        if record.disconnect_policy is DisconnectPolicy.EXPECT_FULL_REBOOT
    )
    return StartupRecoveryReport(
        records=tuple(records),
        interrupted_pre_remote_ids=tuple(interrupted),
        blocking_request_ids=blocking,
        # Recovery now blocks only the affected machine.  The application must
        # attach a broker-owned coordinator before it accepts work for those
        # aliases, but unrelated machines remain safe.
        safe_to_accept_new_approvals=True,
        blocking_machine_aliases=tuple(
            sorted({record.machine_alias for record in blocking_records})
        ),
        expected_reboot_request_ids=expected_reboot,
        automatic_recovery_request_ids=tuple(
            record.request_id
            for record in records
            if (
                record.state in _REMOTE_ACTIVE_STATES
                and record.disconnect_policy is DisconnectPolicy.NORMAL
            )
            or (
                record.record_version == STATE_FORMAT_VERSION
                and record.remote_phase
                is RemotePhase.RESULT_SPOOL_LOCALLY_VERIFIED
            )
        ),
    )
