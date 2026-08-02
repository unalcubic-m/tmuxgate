"""Approval-bound OpenSSH master command plans and a three-transport pool.

No backend is enabled by the public CLI yet.  Tests inject a fake backend; a
future real backend must execute these broker-owned invocations in the broker
terminal and never in the noninteractive client.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Protocol

from tmuxgate.approval import ApprovalDecision, approval_binding_sha256
from tmuxgate.connection_plan import ConnectionPlan, PlannedEndpoint
from tmuxgate.models import RequestSpec, validate_alias, validate_request_id
from tmuxgate.runtime import ensure_private_directory
from tmuxgate.ssh import (
    DEFAULT_SSH_PATH,
    ResolvedSshEndpoint,
    default_tmuxgate_identity_file,
)


MAX_RETAINED_MASTERS = 3
CONTROL_SOCKET_MODE = 0o600
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class TransportError(RuntimeError):
    """A master transport could not be safely created or reused."""


class TransportBusyError(TransportError):
    """A machine transport or all retention slots are unavailable."""


class TransportIdentityError(TransportError):
    """The current SSH identity differs from the approved plan."""


class KeyEnrollmentMutationError(TransportError):
    """Remote key enrollment may have mutated ``authorized_keys``."""


class KeyEnrollmentOutcome(StrEnum):
    """Proven outcome of the idempotent remote-key enrollment protocol."""

    ALREADY_PRESENT = "already-present"
    ENROLLED_AND_VERIFIED = "enrolled-and-verified"


class SshMasterStartError(TransportError):
    """Interactive OpenSSH exited before an authenticated master was ready."""

    def __init__(self, returncode: int) -> None:
        if type(returncode) is not int:
            raise TypeError("SSH master return code must be an integer")
        self.returncode = returncode
        super().__init__(
            "approved SSH master setup exited with status "
            f"{returncode} before remote execution; review the OpenSSH "
            "diagnostic printed in the broker terminal"
        )


def _canonical_sha256(document: Mapping[str, object]) -> str:
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def resolved_identity_sha256(resolved: ResolvedSshEndpoint) -> str:
    if not isinstance(resolved, ResolvedSshEndpoint):
        raise TypeError("resolved must be a ResolvedSshEndpoint")
    return _canonical_sha256(resolved.canonical_document())


@dataclass(frozen=True, slots=True)
class TransportAuthorization:
    request_id: str
    machine_name: str
    endpoint_id: str
    connection_plan_sha256: str
    approval_binding_sha256: str
    resolved_identity_sha256: str

    def __post_init__(self) -> None:
        validate_request_id(self.request_id)
        validate_alias(self.machine_name, field_name="machine name")
        validate_alias(self.endpoint_id, field_name="endpoint ID")
        for name, value in (
            ("connection_plan_sha256", self.connection_plan_sha256),
            ("approval_binding_sha256", self.approval_binding_sha256),
            ("resolved_identity_sha256", self.resolved_identity_sha256),
        ):
            if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _authorization_for_endpoint(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan,
    endpoint: PlannedEndpoint,
    decision: ApprovalDecision,
) -> TransportAuthorization:
    if decision is not ApprovalDecision.APPROVED:
        raise TransportIdentityError("transport authorization requires human approval")
    binding = approval_binding_sha256(request_id, request, connection_plan)
    return TransportAuthorization(
        request_id=request_id,
        machine_name=connection_plan.machine_name,
        endpoint_id=endpoint.resolved.endpoint_id,
        connection_plan_sha256=connection_plan.plan_sha256,
        approval_binding_sha256=binding,
        resolved_identity_sha256=resolved_identity_sha256(endpoint.resolved),
    )


def issue_selected_transport_authorization(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan,
    decision: ApprovalDecision,
) -> TransportAuthorization:
    """Issue a token only for the initially selected approved endpoint."""

    return _authorization_for_endpoint(
        request_id, request, connection_plan, connection_plan.selected, decision
    )


def issue_fallback_transport_authorization(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan,
    *,
    failed_endpoint_id: str,
    fallback_endpoint_id: str,
    fallback_decision: ApprovalDecision,
) -> TransportAuthorization:
    """Issue a token only for the next endpoint after separate fallback approval."""

    endpoints = {item.resolved.endpoint_id: item for item in connection_plan.endpoints}
    failed = endpoints.get(failed_endpoint_id)
    fallback = endpoints.get(fallback_endpoint_id)
    if failed is None or fallback is None or fallback.route_index != failed.route_index + 1:
        raise TransportIdentityError("fallback is not the next endpoint in the approved plan")
    return _authorization_for_endpoint(
        request_id, request, connection_plan, fallback, fallback_decision
    )


@dataclass(frozen=True, slots=True)
class SshInvocation:
    kind: str
    argv: tuple[str, ...]
    interactive_terminal: bool


def _ssh_executable(path: os.PathLike[str] | str) -> str:
    executable = Path(path)
    if not executable.is_absolute():
        raise TransportError("SSH executable path must be absolute")
    return os.fspath(executable)


def _identity_options(
    resolved: ResolvedSshEndpoint,
    *,
    enrollment: bool,
) -> tuple[str, ...]:
    user_known_hosts = " ".join(resolved.user_known_hosts_files)
    global_known_hosts = (
        " ".join(resolved.global_known_hosts_files)
        if resolved.global_known_hosts_files
        else "none"
    )
    authentication_options = (
        (
            "-o", "BatchMode=no",
            "-o", "KbdInteractiveAuthentication=yes",
            "-o", "PasswordAuthentication=yes",
            "-o",
            "PreferredAuthentications=publickey,keyboard-interactive,password",
        )
        if enrollment
        else (
            "-o", "BatchMode=yes",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "PasswordAuthentication=no",
            "-o", "PreferredAuthentications=publickey",
        )
    )
    return (
        *authentication_options,
        "-o", "CanonicalizeHostname=no",
        "-o", f"ConnectTimeout={resolved.connect_timeout_seconds}",
        "-o", "GSSAPIAuthentication=no",
        "-o", f"GlobalKnownHostsFile={global_known_hosts}",
        "-o", "HostbasedAuthentication=no",
        "-o", f"HostKeyAlias={resolved.host_key_alias}",
        "-o", f"HostName={resolved.resolved_hostname}",
        "-o", "IdentityAgent=none",
        "-o", f"IdentityFile={default_tmuxgate_identity_file(resolved.machine_name)}",
        "-o", "IdentitiesOnly=yes",
        "-o", "PermitLocalCommand=no",
        "-o", f"Port={resolved.resolved_port}",
        "-o", "PubkeyAuthentication=yes",
        "-o", "RemoteCommand=none",
        "-o", "RequestTTY=no",
        "-o", f"StrictHostKeyChecking={resolved.strict_host_key_checking}",
        "-o", f"User={resolved.resolved_user}",
        "-o", f"UserKnownHostsFile={user_known_hosts}",
    )


def build_master_start_invocation(
    resolved: ResolvedSshEndpoint,
    control_path: os.PathLike[str] | str,
    *,
    control_persist_seconds: int,
    ssh_path: os.PathLike[str] | str = DEFAULT_SSH_PATH,
) -> SshInvocation:
    if (
        type(control_persist_seconds) is not int
        or not 1 <= control_persist_seconds <= 86400
    ):
        raise ValueError("ControlPersist must be from 1 to 86400 seconds")
    path = Path(control_path)
    if not path.is_absolute():
        raise TransportError("control path must be absolute")
    argv = (
        _ssh_executable(ssh_path),
        "-M", "-N", "-f",
        *_identity_options(resolved, enrollment=False),
        "-o", "ClearAllForwardings=yes",
        "-o", "ControlMaster=yes",
        "-o", f"ControlPath={path}",
        "-o", f"ControlPersist={control_persist_seconds}",
        "-T", "--", resolved.ssh_profile,
    )
    return SshInvocation("start-master", argv, False)


def build_enrollment_master_start_invocation(
    resolved: ResolvedSshEndpoint,
    control_path: os.PathLike[str] | str,
    *,
    control_persist_seconds: int,
    ssh_path: os.PathLike[str] | str = DEFAULT_SSH_PATH,
) -> SshInvocation:
    """Build the prompt-capable master used only to verify or enroll the key."""

    if type(control_persist_seconds) is not int or not 1 <= control_persist_seconds <= 86400:
        raise ValueError("ControlPersist must be from 1 to 86400 seconds")
    path = Path(control_path)
    if not path.is_absolute():
        raise TransportError("control path must be absolute")
    argv = (
        _ssh_executable(ssh_path),
        "-M", "-N", "-f",
        *_identity_options(resolved, enrollment=True),
        "-o", "ClearAllForwardings=yes",
        "-o", "ControlMaster=yes",
        "-o", f"ControlPath={path}",
        "-o", f"ControlPersist={control_persist_seconds}",
        "-T", "--", resolved.ssh_profile,
    )
    return SshInvocation("start-enrollment-master", argv, True)


def build_master_control_invocation(
    resolved: ResolvedSshEndpoint,
    control_path: os.PathLike[str] | str,
    operation: str,
    *,
    ssh_path: os.PathLike[str] | str = DEFAULT_SSH_PATH,
) -> SshInvocation:
    if operation not in {"check", "exit"}:
        raise ValueError("master control operation must be check or exit")
    path = Path(control_path)
    if not path.is_absolute():
        raise TransportError("control path must be absolute")
    argv = (
        _ssh_executable(ssh_path),
        "-S", os.fspath(path),
        "-O", operation,
        *_identity_options(resolved, enrollment=False),
        "-T", "--", resolved.ssh_profile,
    )
    return SshInvocation(f"master-{operation}", argv, False)


def build_batch_channel_prefix(
    resolved: ResolvedSshEndpoint,
    control_path: os.PathLike[str] | str,
    *,
    ssh_path: os.PathLike[str] | str = DEFAULT_SSH_PATH,
) -> SshInvocation:
    """Build the fixed prefix for future noninteractive machine-control channels."""

    path = Path(control_path)
    if not path.is_absolute():
        raise TransportError("control path must be absolute")
    argv = (
        _ssh_executable(ssh_path),
        "-S", os.fspath(path),
        *_identity_options(resolved, enrollment=False),
        "-o", "ControlMaster=no",
        "-T", "--", resolved.ssh_profile,
    )
    return SshInvocation("batch-channel-prefix", argv, False)


def build_viewer_channel_prefix(
    resolved: ResolvedSshEndpoint,
    control_path: os.PathLike[str] | str,
    *,
    ssh_path: os.PathLike[str] | str = DEFAULT_SSH_PATH,
) -> SshInvocation:
    """Build the fixed interactive viewer prefix over an authenticated master."""

    path = Path(control_path)
    if not path.is_absolute():
        raise TransportError("control path must be absolute")
    argv = (
        _ssh_executable(ssh_path),
        "-S", os.fspath(path),
        *_identity_options(resolved, enrollment=False),
        "-o", "ControlMaster=no",
        "-o", "RemoteCommand=none",
        "-tt", "--", resolved.ssh_profile,
    )
    return SshInvocation("viewer-channel-prefix", argv, True)


class MasterBackend(Protocol):
    """Injected backend; fake tests implement this without executing SSH."""

    def start_master(self, invocation: SshInvocation, control_path: Path) -> None: ...
    def check_master(self, invocation: SshInvocation, control_path: Path) -> bool: ...
    def stop_master(self, invocation: SshInvocation, control_path: Path) -> None: ...


class SshKeyManager(Protocol):
    def prepare_local_key(self, resolved: ResolvedSshEndpoint) -> None: ...
    def enroll_remote_key(
        self,
        resolved: ResolvedSshEndpoint,
        control_path: Path,
        *,
        before_remote_mutation: Callable[[], None],
    ) -> KeyEnrollmentOutcome: ...


class KeyEnrollmentLifecycle(Protocol):
    """Durable callbacks around the remote enrollment mutation boundary."""

    def before_remote_mutation(self, resolved: ResolvedSshEndpoint) -> None: ...
    def remote_mutation_verified(self, resolved: ResolvedSshEndpoint) -> None: ...


IdentityRevalidator = Callable[[ResolvedSshEndpoint], ResolvedSshEndpoint]


@dataclass(slots=True)
class MasterTransport:
    machine_name: str
    endpoint: ResolvedSshEndpoint
    control_path: Path
    connection_plan_sha256: str
    identity_sha256: str
    last_used: float
    pinned_request_ids: set[str] = field(default_factory=set)
    cleanup_pending: bool = False


class TransportLease:
    def __init__(
        self,
        pool: "MasterTransportPool",
        transport: MasterTransport,
        request_id: str,
    ):
        self._pool = pool
        self.transport = transport
        self.request_id = validate_request_id(request_id)
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._pool.release(self)
            self._released = True

    def __enter__(self) -> MasterTransport:
        return self.transport

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


class MasterTransportPool:
    """Retain three authenticated masters and multiplex isolated job leases."""

    def __init__(
        self,
        control_dir: os.PathLike[str] | str,
        *,
        backend: MasterBackend,
        identity_revalidator: IdentityRevalidator,
        max_masters: int = MAX_RETAINED_MASTERS,
        idle_timeout_seconds: int = 600,
        clock: Callable[[], float] = time.monotonic,
        expected_uid: int | None = None,
        key_manager: SshKeyManager | None = None,
    ) -> None:
        if not callable(identity_revalidator):
            raise TypeError("identity_revalidator must be callable")
        if type(max_masters) is not int or not 1 <= max_masters <= MAX_RETAINED_MASTERS:
            raise ValueError("max_masters must be from 1 to 3")
        if type(idle_timeout_seconds) is not int or not 1 <= idle_timeout_seconds <= 86400:
            raise ValueError("idle timeout must be from 1 to 86400 seconds")
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self.control_dir = ensure_private_directory(
            control_dir, expected_uid=self.expected_uid
        )
        self.backend = backend
        self.identity_revalidator = identity_revalidator
        self.max_masters = max_masters
        self.idle_timeout_seconds = idle_timeout_seconds
        self.clock = clock
        self._transports: dict[str, MasterTransport] = {}
        self._lock = threading.RLock()
        self.key_manager = key_manager

    @property
    def retained_machine_names(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                item.machine_name
                for item in sorted(
                    self._transports.values(), key=lambda value: value.last_used
                )
            )

    @property
    def pinned_request_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(
                    request_id
                    for item in self._transports.values()
                    for request_id in item.pinned_request_ids
                )
            )

    @property
    def pinned_request_id(self) -> str | None:
        pinned = self.pinned_request_ids
        if len(pinned) > 1:
            raise TransportBusyError("more than one remote command is active")
        return pinned[0] if pinned else None

    def _control_path(self, machine_name: str, identity_sha256: str) -> Path:
        digest = hashlib.sha256(
            f"{machine_name}\0{identity_sha256}".encode("ascii")
        ).hexdigest()[:24]
        return self.control_dir / f"master-{digest}.sock"

    def _control_socket_present(self, path: Path) -> bool:
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            return False
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != self.expected_uid
            or stat.S_IMODE(metadata.st_mode) != CONTROL_SOCKET_MODE
        ):
            raise TransportError("SSH control socket is not an owned mode-0600 socket")
        return True

    def _remove_socket_if_safe(self, path: Path) -> None:
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != self.expected_uid
            or stat.S_IMODE(metadata.st_mode) != CONTROL_SOCKET_MODE
        ):
            raise TransportError("refusing to remove an unsafe control path")
        path.unlink()

    def _stop(self, transport: MasterTransport) -> None:
        if transport.pinned_request_ids:
            raise TransportBusyError("cannot close a pinned SSH master")
        invocation = build_master_control_invocation(
            transport.endpoint, transport.control_path, "exit"
        )
        self.backend.stop_master(invocation, transport.control_path)
        self._remove_socket_if_safe(transport.control_path)
        self._transports.pop(transport.machine_name, None)

    def _evict_one_idle(self) -> None:
        idle = [item for item in self._transports.values() if not item.pinned_request_ids]
        if not idle:
            raise TransportBusyError("all retained SSH masters are pinned")
        self._stop(min(idle, key=lambda item: (item.last_used, item.machine_name)))

    def _validated_current_identity(
        self, authorization: TransportAuthorization, resolved: ResolvedSshEndpoint
    ) -> tuple[ResolvedSshEndpoint, str]:
        if authorization.machine_name != resolved.machine_name:
            raise TransportIdentityError("authorized machine and resolved machine differ")
        if authorization.endpoint_id != resolved.endpoint_id:
            raise TransportIdentityError("authorized endpoint and resolved endpoint differ")
        try:
            current = self.identity_revalidator(resolved)
        except Exception as exc:
            raise TransportIdentityError("SSH identity revalidation failed") from exc
        if not isinstance(current, ResolvedSshEndpoint):
            raise TransportIdentityError("SSH identity revalidator returned an invalid result")
        if current.machine_name != authorization.machine_name:
            raise TransportIdentityError("SSH machine changed after human approval")
        current_digest = resolved_identity_sha256(current)
        if current_digest != authorization.resolved_identity_sha256:
            raise TransportIdentityError("SSH identity changed after authorization")
        return current, current_digest

    def acquire(
        self,
        authorization: TransportAuthorization,
        resolved: ResolvedSshEndpoint,
        *,
        key_enrollment_lifecycle: KeyEnrollmentLifecycle | None = None,
    ) -> TransportLease:
        """Reuse or authenticate a master, then pin it to this one request."""

        with self._lock:
            current, identity_digest = self._validated_current_identity(
                authorization, resolved
            )
            existing = self._transports.get(authorization.machine_name)
            if existing is not None and existing.cleanup_pending:
                self._stop(existing)
                existing = None
            if existing is not None and existing.identity_sha256 != identity_digest:
                self._stop(existing)
                existing = None
            if existing is not None:
                if not self._control_socket_present(existing.control_path):
                    if existing.pinned_request_ids:
                        raise TransportBusyError(
                            "active machine transport lost its control socket"
                        )
                    self._transports.pop(existing.machine_name, None)
                    existing = None
                else:
                    check = build_master_control_invocation(
                        current, existing.control_path, "check"
                    )
                    if not self.backend.check_master(check, existing.control_path):
                        if existing.pinned_request_ids:
                            raise TransportBusyError(
                                "active machine transport failed its control check"
                            )
                        self._remove_socket_if_safe(existing.control_path)
                        self._transports.pop(existing.machine_name, None)
                        existing = None
            if existing is None:
                if len(self._transports) >= self.max_masters:
                    self._evict_one_idle()
                if self.key_manager is not None:
                    self.key_manager.prepare_local_key(current)
                path = self._control_path(authorization.machine_name, identity_digest)
                if path.exists() or path.is_symlink():
                    raise TransportError("refusing a pre-existing master control path")
                start_builder = (
                    build_enrollment_master_start_invocation
                    if self.key_manager is not None
                    else build_master_start_invocation
                )
                start = start_builder(
                    current, path,
                    control_persist_seconds=self.idle_timeout_seconds,
                )
                master_started = False
                key_enrollment_started = False
                try:
                    self.backend.start_master(start, path)
                    master_started = True
                    if not self._control_socket_present(path):
                        raise TransportError(
                            "authenticated master did not create its control socket"
                        )
                    check = build_master_control_invocation(
                        current, path, "check"
                    )
                    if not self.backend.check_master(check, path):
                        raise TransportError(
                            "new authenticated SSH master failed its control check"
                        )
                    if self.key_manager is not None:
                        def before_remote_mutation() -> None:
                            nonlocal key_enrollment_started
                            if key_enrollment_lifecycle is None:
                                raise TransportError(
                                    "remote key enrollment lacks a durable lifecycle"
                                )
                            key_enrollment_lifecycle.before_remote_mutation(current)
                            key_enrollment_started = True

                        outcome = self.key_manager.enroll_remote_key(
                            current,
                            path,
                            before_remote_mutation=before_remote_mutation,
                        )
                        if outcome is KeyEnrollmentOutcome.ENROLLED_AND_VERIFIED:
                            if not key_enrollment_started:
                                raise TransportError(
                                    "key manager reported enrollment without crossing "
                                    "the durable mutation boundary"
                                )
                            assert key_enrollment_lifecycle is not None
                            key_enrollment_lifecycle.remote_mutation_verified(current)
                        elif outcome is not KeyEnrollmentOutcome.ALREADY_PRESENT:
                            raise TransportError(
                                "key manager returned an invalid enrollment outcome"
                            )
                        stop = build_master_control_invocation(
                            current, path, "exit"
                        )
                        self.backend.stop_master(stop, path)
                        master_started = False
                        self._remove_socket_if_safe(path)

                        strict_start = build_master_start_invocation(
                            current,
                            path,
                            control_persist_seconds=self.idle_timeout_seconds,
                        )
                        self.backend.start_master(strict_start, path)
                        master_started = True
                        if not self._control_socket_present(path):
                            raise TransportError(
                                "post-enrollment master did not create its control socket"
                            )
                        strict_check = build_master_control_invocation(
                            current, path, "check"
                        )
                        if not self.backend.check_master(strict_check, path):
                            raise TransportError(
                                "post-enrollment SSH master failed its control check"
                            )
                except BaseException as exc:
                    should_stop = master_started
                    if not should_stop:
                        try:
                            should_stop = self._control_socket_present(path)
                        except BaseException:
                            should_stop = False
                    try:
                        if should_stop:
                            stop = build_master_control_invocation(
                                current, path, "exit"
                            )
                            self.backend.stop_master(stop, path)
                    except BaseException as stop_exc:
                        try:
                            socket_retained = self._control_socket_present(path)
                        except BaseException as path_exc:
                            cleanup_error = TransportError(
                                "partial SSH master shutdown was not confirmed "
                                "and its control path is unsafe; the path was not removed"
                            )
                            if key_enrollment_started:
                                raise KeyEnrollmentMutationError(
                                    "remote key enrollment may have mutated authorized_keys; "
                                    "SSH master cleanup also could not be confirmed"
                                ) from path_exc
                            raise cleanup_error from path_exc
                        if socket_retained:
                            self._transports[authorization.machine_name] = (
                                MasterTransport(
                                    machine_name=authorization.machine_name,
                                    endpoint=current,
                                    control_path=path,
                                    connection_plan_sha256=(
                                        authorization.connection_plan_sha256
                                    ),
                                    identity_sha256=identity_digest,
                                    last_used=self.clock(),
                                    cleanup_pending=True,
                                )
                            )
                            cleanup_error = TransportError(
                                "partial SSH master shutdown was not confirmed; "
                                "its owned control socket was retained for "
                                "broker lifecycle cleanup"
                            )
                        else:
                            cleanup_error = TransportError(
                                "partial SSH master shutdown was not confirmed"
                            )
                        if key_enrollment_started:
                            raise KeyEnrollmentMutationError(
                                "remote key enrollment may have mutated authorized_keys; "
                                "SSH master cleanup also could not be confirmed"
                            ) from stop_exc
                        raise cleanup_error from stop_exc
                    try:
                        self._remove_socket_if_safe(path)
                    except BaseException as cleanup_exc:
                        if key_enrollment_started:
                            raise KeyEnrollmentMutationError(
                                "remote key enrollment may have mutated authorized_keys; "
                                "its SSH control path also could not be cleaned safely"
                            ) from cleanup_exc
                        raise
                    if key_enrollment_started:
                        if isinstance(exc, KeyEnrollmentMutationError):
                            raise
                        raise KeyEnrollmentMutationError(
                            "remote key enrollment may have mutated authorized_keys; "
                            "the requested command was not started"
                        ) from exc
                    raise
                existing = MasterTransport(
                    machine_name=authorization.machine_name,
                    endpoint=current,
                    control_path=path,
                    connection_plan_sha256=authorization.connection_plan_sha256,
                    identity_sha256=identity_digest,
                    last_used=self.clock(),
                )
                self._transports[existing.machine_name] = existing
            if authorization.request_id in existing.pinned_request_ids:
                raise TransportBusyError("request already pins this SSH master")
            existing.connection_plan_sha256 = authorization.connection_plan_sha256
            existing.last_used = self.clock()
            existing.pinned_request_ids.add(authorization.request_id)
            return TransportLease(self, existing, authorization.request_id)

    def release(self, lease: TransportLease) -> None:
        with self._lock:
            transport = lease.transport
            current = self._transports.get(transport.machine_name)
            if current is not transport:
                raise TransportError("transport lease is stale")
            request_id = next(
                (
                    item
                    for item in current.pinned_request_ids
                    if item == lease.request_id
                ),
                None,
            )
            if request_id is None:
                raise TransportError("transport lease was already released")
            current.pinned_request_ids.remove(request_id)
            current.last_used = self.clock()

    def reap_expired(self) -> tuple[str, ...]:
        with self._lock:
            now = self.clock()
            expired = tuple(
                item.machine_name
                for item in sorted(
                    self._transports.values(), key=lambda value: value.last_used
                )
                if not item.pinned_request_ids
                and now - item.last_used >= self.idle_timeout_seconds
            )
            for machine_name in expired:
                self._stop(self._transports[machine_name])
            return expired

    def close_idle(self) -> tuple[str, ...]:
        with self._lock:
            closed = tuple(
                item.machine_name
                for item in sorted(
                    self._transports.values(), key=lambda value: value.last_used
                )
                if not item.pinned_request_ids
            )
            for machine_name in closed:
                self._stop(self._transports[machine_name])
            return closed
