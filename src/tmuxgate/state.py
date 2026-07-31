"""Crash-safe owner-only job state and conservative startup recovery."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading

from tmuxgate.connection_plan import ConnectionPlan, PlannedEndpoint
from tmuxgate.models import RequestSpec, validate_alias, validate_request_id
from tmuxgate.runtime import PRIVATE_DIRECTORY_MODE, ensure_private_directory
from tmuxgate.scheduler import ApprovalDecision, RequestState


STATE_FORMAT_VERSION = 2
STATE_FILE_MODE = 0o600
STATE_JOBS_DIRECTORY_NAME = "jobs"
MAX_STATE_FILE_BYTES = 1024 * 1024

_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ENDPOINT_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,62}\Z", re.ASCII)
_SESSION_RE = re.compile(r"tmuxgate-[0-9a-f]{8,32}\Z", re.ASCII)
_TEMP_RE = re.compile(r"\.([0-9a-f]{32})\.([0-9a-f]{32})\.tmp\Z", re.ASCII)
_FINAL_RE = re.compile(r"([0-9a-f]{32})\.json\Z", re.ASCII)
_REMOTE_ACTIVE_STATES = frozenset(
    {
        RequestState.REMOTE_MAY_BE_RUNNING,
        RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        RequestState.COMPLETION_PROVEN,
        RequestState.LOCAL_SPOOL_VERIFIED,
    }
)
_OPERATOR_ABANDONED_STATES = frozenset(
    {
        RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
        RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
    }
)
_PROVEN_UNSTARTED_STATES = frozenset(
    {RequestState.ABANDONED_AFTER_PROVEN_UNSTARTED}
)
_ABANDONED_STATES = _OPERATOR_ABANDONED_STATES | _PROVEN_UNSTARTED_STATES
_REMOTE_STARTED_STATES = _REMOTE_ACTIVE_STATES | _ABANDONED_STATES
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
        _validate_digest(self.client_request_sha256, "client_request_sha256")
        _validate_digest(
            self.connection_plan_sha256, "connection_plan_sha256", optional=True
        )
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

        if state in _REMOTE_STARTED_STATES and not self.remote_mutation_started:
            raise StateCorruptionError("remote lifecycle state lacks mutation boundary")
        if state in {
            RequestState.APPROVED_PRE_REMOTE,
            RequestState.REMOTE_MAY_BE_RUNNING,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
            RequestState.ABANDONED_AFTER_PROVEN_UNSTARTED,
            RequestState.COMPLETION_PROVEN,
            RequestState.LOCAL_SPOOL_VERIFIED,
            RequestState.LEASE_RELEASED,
        } and self.decision is not ApprovalDecision.APPROVED:
            raise StateCorruptionError("approved lifecycle state lacks approved decision")
        if state is RequestState.DENIED and self.decision is not ApprovalDecision.DENIED:
            raise StateCorruptionError("denied state lacks denied decision")
        if state in {RequestState.QUEUED, RequestState.AWAITING_APPROVAL} and self.decision is not None:
            raise StateCorruptionError("unapproved state unexpectedly has a decision")
        if state in {
            RequestState.APPROVED_PRE_REMOTE,
            RequestState.REMOTE_MAY_BE_RUNNING,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
            RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
            RequestState.ABANDONED_AFTER_PROVEN_UNSTARTED,
            RequestState.COMPLETION_PROVEN,
            RequestState.LOCAL_SPOOL_VERIFIED,
            RequestState.LEASE_RELEASED,
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

    def payload_document(self) -> dict[str, object]:
        return {
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
            "record_version": STATE_FORMAT_VERSION,
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

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> "DurableJobRecord":
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
        if set(payload) != expected:
            raise StateCorruptionError("state payload fields are not exactly recognized")
        if payload["record_version"] != STATE_FORMAT_VERSION:
            raise StateCorruptionError("unsupported state record version")
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


class DurableStateStore:
    """Atomic per-request JSON records under one validated private directory."""

    def __init__(self, state_dir: os.PathLike[str] | str, *, expected_uid: int | None = None):
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        if type(self.expected_uid) is not int or self.expected_uid < 0:
            raise StateError("expected UID must be a non-negative integer")
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

    def arm_remote_start(
        self,
        record: DurableJobRecord,
        *,
        now: Callable[[], str] = utc_now,
    ) -> tuple[DurableJobRecord, RemoteStartPermit]:
        """Fsync `REMOTE_MAY_BE_RUNNING` before returning a start permit."""

        if record.state is not RequestState.APPROVED_PRE_REMOTE:
            raise StateConflictError("remote start can be armed only after approval")
        if record.remote_job_path is None or record.connection_plan_sha256 is None:
            raise StateConflictError(
                "remote start requires a planned guarded job identity and connection plan"
            )
        timestamp = now()
        armed = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.REMOTE_MAY_BE_RUNNING,
            remote_mutation_started=True,
            start_time=timestamp,
            updated_at=timestamp,
        )
        self.write(armed)
        payload_digest = _sha256_document(armed.payload_document())
        return armed, RemoteStartPermit(armed.request_id, armed.generation, payload_digest)

    def fail_pre_remote(
        self,
        record: DurableJobRecord,
        *,
        detail: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.state is not RequestState.APPROVED_PRE_REMOTE:
            raise StateConflictError("pre-remote failure requires approved-pre-remote state")
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

    def mark_recovery_required(
        self,
        record: DurableJobRecord,
        *,
        detail: str,
        now: Callable[[], str] = utc_now,
    ) -> DurableJobRecord:
        if record.state not in {
            RequestState.REMOTE_MAY_BE_RUNNING,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        }:
            raise StateConflictError("recovery requires a possibly-running state")
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
        """Release an uncertain job only after a full reboot is operator-attested.

        This transition deliberately records no remote exit status, completion
        time, canonical output, or verified result spool. The durable record is
        retained as an auditable terminal failure instead of being relabeled as
        successful or forgotten.
        """

        if record.state is not RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING:
            raise StateConflictError(
                "operator-confirmed reboot abandonment requires recovery state"
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
                "operator-confirmed reboot abandonment requires every completion "
                "gate to remain unproven"
            )
        timestamp = now()
        prior_detail = record.failure_detail or "remote execution became uncertain"
        audit_detail = (
            f"{prior_detail}; controlling-terminal operator confirmed a full reboot "
            f"of logical machine {record.machine_alias} after remote start; remote "
            "completion, exit status, canonical output, and local spool remain "
            "unproven"
        )
        abandoned = replace(
            record,
            generation=record.generation + 1,
            state=RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
            updated_at=timestamp,
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
        )
        self.write(verified)
        return verified

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
        remote_job_path=f"~/.cache/tmuxgate/jobs/{request_id}",
        remote_tmux_session=f"tmuxgate-{request_id[:12]}",
        decision=ApprovalDecision.APPROVED,
        state=RequestState.APPROVED_PRE_REMOTE,
        created_at=timestamp,
        updated_at=timestamp,
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

    blocking = tuple(
        record.request_id for record in records if record.state in _REMOTE_ACTIVE_STATES
    )
    return StartupRecoveryReport(
        records=tuple(records),
        interrupted_pre_remote_ids=tuple(interrupted),
        blocking_request_ids=blocking,
        safe_to_accept_new_approvals=not blocking,
    )
