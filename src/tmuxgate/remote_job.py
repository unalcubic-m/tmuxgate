"""Dedicated remote tmux job lifecycle over an injected backend."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
import hashlib
from pathlib import Path
import re
from typing import Protocol

from tmuxgate.models import RequestSpec, validate_request_id
from tmuxgate.state import RemoteStartPermit


REMOTE_JOBS_PARENT = "~/.cache/tmuxgate/jobs"
_SESSION_RE = re.compile(r"tmuxgate-[0-9a-f]{12}\Z", re.ASCII)
_WAIT_RE = re.compile(r"tmuxgate-start-[0-9a-f]{32}\Z", re.ASCII)


class RemoteJobError(RuntimeError):
    """Remote job evidence or a lifecycle transition failed closed."""


class RemoteJobBusyError(RemoteJobError):
    """An active or uncertain job cannot be cleaned or replaced."""


class RemoteJobState(StrEnum):
    PLANNED = "planned"
    STAGED = "staged"
    GATED_WAITING_FOR_VIEWER = "gated-waiting-for-viewer"
    RUNNING_ATTACHED = "running-attached"
    RUNNING_DETACHED = "running-detached"
    COMPLETE_WAITING_FOR_DETACH = "complete-waiting-for-detach"
    COMPLETE_DETACHED = "complete-detached"
    COLLECTED = "collected"
    RECOVERY_REQUIRED = "recovery-required"
    CLEANED = "cleaned"


@dataclass(frozen=True, slots=True)
class RemoteJobIdentity:
    request_id: str
    job_path: str
    tmux_session: str
    wait_channel: str

    @classmethod
    def for_request(cls, request_id: str) -> "RemoteJobIdentity":
        request_id = validate_request_id(request_id)
        return cls(
            request_id=request_id,
            job_path=f"{REMOTE_JOBS_PARENT}/{request_id}",
            tmux_session=f"tmuxgate-{request_id[:12]}",
            wait_channel=f"tmuxgate-start-{request_id}",
        )

    def __post_init__(self) -> None:
        request_id = validate_request_id(self.request_id)
        if self.job_path != f"{REMOTE_JOBS_PARENT}/{request_id}":
            raise RemoteJobError("remote job path is outside the exact guarded parent")
        if _SESSION_RE.fullmatch(self.tmux_session) is None:
            raise RemoteJobError("remote tmux session name is invalid")
        if _WAIT_RE.fullmatch(self.wait_channel) is None:
            raise RemoteJobError("remote wait channel is invalid")


@dataclass(frozen=True, slots=True)
class RemoteObservation:
    session_exists: bool
    attached_clients: int
    gate_released: bool
    command_running: bool
    completion_proven: bool
    exit_status: int | None
    stdout_size: int | None
    stderr_size: int | None
    stdout_sha256: str | None
    stderr_sha256: str | None

    def __post_init__(self) -> None:
        if type(self.attached_clients) is not int or self.attached_clients < 0:
            raise RemoteJobError("attached client count is invalid")
        if self.exit_status is not None and (
            type(self.exit_status) is not int or not 0 <= self.exit_status <= 255
        ):
            raise RemoteJobError("remote exit status is invalid")
        for name, value in (("stdout_size", self.stdout_size), ("stderr_size", self.stderr_size)):
            if value is not None and (type(value) is not int or value < 0):
                raise RemoteJobError(f"{name} is invalid")
        if self.completion_proven and (
            self.exit_status is None
            or self.stdout_size is None
            or self.stderr_size is None
            or self.stdout_sha256 is None
            or self.stderr_sha256 is None
        ):
            raise RemoteJobError("completion lacks exit status or stream evidence")
        for name, value in (
            ("stdout_sha256", self.stdout_sha256),
            ("stderr_sha256", self.stderr_sha256),
        ):
            if value is not None and re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise RemoteJobError(f"{name} is invalid")
        if self.command_running and self.completion_proven:
            raise RemoteJobError("job cannot be running and complete")


@dataclass(frozen=True, slots=True)
class CollectedRemoteResult:
    stdout: bytes
    stderr: bytes
    exit_status: int

    def __post_init__(self) -> None:
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise RemoteJobError("collected streams must be bytes")
        if type(self.exit_status) is not int or not 0 <= self.exit_status <= 255:
            raise RemoteJobError("collected exit status is invalid")

    @property
    def stdout_size(self) -> int:
        return len(self.stdout)

    @property
    def stderr_size(self) -> int:
        return len(self.stderr)

    @property
    def stdout_sha256(self) -> str:
        return hashlib.sha256(self.stdout).hexdigest()

    @property
    def stderr_sha256(self) -> str:
        return hashlib.sha256(self.stderr).hexdigest()


@dataclass(slots=True)
class CollectedRemoteFiles:
    """Private streamed result files plus their receive-time evidence."""

    stdout_path: Path
    stderr_path: Path
    stdout_size: int
    stderr_size: int
    stdout_sha256: str
    stderr_sha256: str
    exit_status: int
    _cleanup: Callable[[], None]
    _closed: bool = False

    def __post_init__(self) -> None:
        for name, path in (
            ("stdout", self.stdout_path),
            ("stderr", self.stderr_path),
        ):
            if not isinstance(path, Path) or not path.is_absolute():
                raise RemoteJobError(f"collected {name} path is invalid")
        for name, value in (
            ("stdout_size", self.stdout_size),
            ("stderr_size", self.stderr_size),
        ):
            if type(value) is not int or value < 0:
                raise RemoteJobError(f"collected {name} is invalid")
        for name, value in (
            ("stdout_sha256", self.stdout_sha256),
            ("stderr_sha256", self.stderr_sha256),
        ):
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise RemoteJobError(f"collected {name} is invalid")
        if type(self.exit_status) is not int or not 0 <= self.exit_status <= 255:
            raise RemoteJobError("collected exit status is invalid")
        if not callable(self._cleanup):
            raise RemoteJobError("collected result cleanup is invalid")

    def close(self) -> None:
        if not self._closed:
            self._cleanup()
            self._closed = True


RemoteCollection = CollectedRemoteResult | CollectedRemoteFiles


class ViewerHandle(Protocol):
    @property
    def attached(self) -> bool: ...
    def send_input(self, data: bytes) -> None: ...
    def send_ctrl_c(self) -> None: ...
    def detach(self) -> None: ...


class RemoteJobBackend(Protocol):
    def stage(self, identity: RemoteJobIdentity, request: RequestSpec) -> None: ...
    def create_gated_session(self, identity: RemoteJobIdentity) -> None: ...
    def attach(self, identity: RemoteJobIdentity) -> ViewerHandle: ...
    def observe(self, identity: RemoteJobIdentity) -> RemoteObservation: ...
    def release_gate(self, identity: RemoteJobIdentity) -> None: ...
    def collect(self, identity: RemoteJobIdentity) -> RemoteCollection: ...
    def cleanup(self, identity: RemoteJobIdentity) -> None: ...


@dataclass(slots=True)
class RemoteJob:
    identity: RemoteJobIdentity
    request_sha256: str
    durable_generation: int
    state: RemoteJobState = RemoteJobState.PLANNED
    viewer: ViewerHandle | None = None
    result: RemoteCollection | None = None


class RemoteJobCoordinator:
    """Enforce viewer-before-gate and fail-closed collection/cleanup ordering."""

    def __init__(self, backend: RemoteJobBackend):
        self.backend = backend
        self.active: RemoteJob | None = None

    def prepare(
        self,
        request_id: str,
        request: RequestSpec,
        permit: RemoteStartPermit,
    ) -> RemoteJob:
        if self.active is not None and self.active.state is not RemoteJobState.CLEANED:
            raise RemoteJobBusyError("another remote job remains active or retained")
        identity = RemoteJobIdentity.for_request(request_id)
        if permit.request_id != identity.request_id:
            raise RemoteJobError("durable start permit belongs to another request")
        if type(permit.durable_generation) is not int or permit.durable_generation < 2:
            raise RemoteJobError("durable start permit generation is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", permit.durable_payload_sha256):
            raise RemoteJobError("durable start permit digest is invalid")
        job = RemoteJob(
            identity=identity,
            request_sha256=request.client_request_sha256(),
            durable_generation=permit.durable_generation,
        )
        try:
            self.backend.stage(identity, request)
            job.state = RemoteJobState.STAGED
            self.backend.create_gated_session(identity)
            observation = self.backend.observe(identity)
            if (
                not observation.session_exists
                or observation.gate_released
                or observation.command_running
                or observation.completion_proven
            ):
                raise RemoteJobError("new remote session is not safely gated")
            job.state = RemoteJobState.GATED_WAITING_FOR_VIEWER
        except BaseException:
            job.state = RemoteJobState.RECOVERY_REQUIRED
            self.active = job
            raise
        self.active = job
        return job

    def attach_and_start(self, job: RemoteJob) -> ViewerHandle:
        self._require_active(job, RemoteJobState.GATED_WAITING_FOR_VIEWER)
        viewer = self.backend.attach(job.identity)
        observation = self.backend.observe(job.identity)
        if not viewer.attached or observation.attached_clients < 1:
            job.state = RemoteJobState.RECOVERY_REQUIRED
            raise RemoteJobError("viewer attachment could not be proven")
        if observation.gate_released or observation.command_running:
            job.state = RemoteJobState.RECOVERY_REQUIRED
            raise RemoteJobError("command crossed the gate before broker release")
        self.backend.release_gate(job.identity)
        observation = self.backend.observe(job.identity)
        if not observation.gate_released:
            job.state = RemoteJobState.RECOVERY_REQUIRED
            raise RemoteJobError("remote start gate release was not proven")
        job.viewer = viewer
        job.state = RemoteJobState.RUNNING_ATTACHED
        return viewer

    def refresh(self, job: RemoteJob) -> RemoteJobState:
        if self.active is not job or job.state in {
            RemoteJobState.PLANNED,
            RemoteJobState.STAGED,
            RemoteJobState.COLLECTED,
            RemoteJobState.CLEANED,
        }:
            raise RemoteJobError("job cannot be refreshed in its current state")
        observation = self.backend.observe(job.identity)
        if not observation.session_exists and not observation.completion_proven:
            job.state = RemoteJobState.RECOVERY_REQUIRED
            return job.state
        attached = observation.attached_clients > 0
        if observation.completion_proven:
            job.state = (
                RemoteJobState.COMPLETE_WAITING_FOR_DETACH
                if attached
                else RemoteJobState.COMPLETE_DETACHED
            )
        elif observation.command_running:
            job.state = (
                RemoteJobState.RUNNING_ATTACHED
                if attached
                else RemoteJobState.RUNNING_DETACHED
            )
        else:
            job.state = RemoteJobState.RECOVERY_REQUIRED
        return job.state

    def reattach(self, job: RemoteJob) -> ViewerHandle:
        self._require_active(job, RemoteJobState.RUNNING_DETACHED)
        viewer = self.backend.attach(job.identity)
        observation = self.backend.observe(job.identity)
        if not viewer.attached or observation.attached_clients < 1:
            job.state = RemoteJobState.RECOVERY_REQUIRED
            raise RemoteJobError("reattachment could not be proven")
        job.viewer = viewer
        job.state = RemoteJobState.RUNNING_ATTACHED
        return viewer

    def collect(self, job: RemoteJob) -> RemoteCollection:
        self._require_active(job, RemoteJobState.COMPLETE_DETACHED)
        observation = self.backend.observe(job.identity)
        if not observation.completion_proven or observation.attached_clients != 0:
            raise RemoteJobError("collection requires proven completion and viewer detach")
        result = self.backend.collect(job.identity)
        if (
            result.exit_status != observation.exit_status
            or result.stdout_size != observation.stdout_size
            or result.stderr_size != observation.stderr_size
            or result.stdout_sha256 != observation.stdout_sha256
            or result.stderr_sha256 != observation.stderr_sha256
        ):
            if isinstance(result, CollectedRemoteFiles):
                result.close()
            job.state = RemoteJobState.RECOVERY_REQUIRED
            raise RemoteJobError("collected result does not match remote completion evidence")
        job.result = result
        job.state = RemoteJobState.COLLECTED
        return result

    def cleanup(self, job: RemoteJob) -> None:
        self._require_active(job, RemoteJobState.COLLECTED)
        self.backend.cleanup(job.identity)
        job.state = RemoteJobState.CLEANED
        self.active = None

    def _require_active(self, job: RemoteJob, expected: RemoteJobState) -> None:
        if self.active is not job or job.state is not expected:
            raise RemoteJobError(
                f"job must be the active {expected.value} job for this operation"
            )
