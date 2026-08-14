"""Presentation-independent operator prompts, decisions, and activity events.

Workers submit immutable prompts to an :class:`OperatorInterface`; they never
render a decision document or parse terminal input themselves.  Every prompt
has a fresh internal ID and a canonical binding hash.  The one-shot decision
slot checks both values, so a late or stale presenter cannot resolve another
prompt even when the human-readable labels happen to match.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import queue
import re
import secrets
import sys
import threading
from typing import Protocol, TypeAlias

from .approval import (
    ApprovalDecision,
    ApprovalPager,
    ApprovalTerminal,
    MAX_OPENSSH_DIAGNOSTIC_BYTES,
    request_approval,
    request_fallback_approval,
    request_machine_disable,
    request_secret_input_authorization,
    request_ssh_retry,
)
from .connection_plan import ConnectionPlan
from .models import ExecutionMode, RequestSpec, validate_alias, validate_request_id
from .terminal import TerminalArbiter, TerminalPriority


MAX_FAILURE_DETAIL_CHARACTERS = 4096
MAX_ACTIVITY_MESSAGE_CHARACTERS = 4096
SSH_RETRY_LIMIT = 1
_HEX_DIGEST_LENGTH = 64
_PROMPT_ID_LENGTH = 32
_DEFAULT_PAGER = object()
_VIEWER_SESSION_ID_RE = re.compile(r"tmuxgate-[0-9a-f]{12}\Z", re.ASCII)


class OperatorInterfaceError(RuntimeError):
    """The operator boundary rejected invalid state or failed closed."""


class RemoteMutationState(StrEnum):
    """Truthful state of remote mutation at a recovery decision boundary."""

    NOT_STARTED = "not_started"
    MAY_HAVE_STARTED = "may_have_started"
    STARTED = "started"


class RemoteCommandState(StrEnum):
    """Truthful requested-command state shown at recovery boundaries."""

    NOT_STARTED = "not_started"
    MAY_HAVE_STARTED = "may_have_started"
    STARTED = "started"


class ConnectionPhase(StrEnum):
    """Structured request lifecycle projected in place by operator UIs."""

    CONNECTING = "connecting"
    RETRY_DECISION = "retry_decision"
    RETRYING = "retrying"
    FALLBACK_DECISION = "fallback_decision"
    REMOTE_STARTING = "remote_starting"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ActivityKind(StrEnum):
    """Presentation-independent categories for bounded operator activity."""

    STARTUP = "startup"
    STATUS = "status"
    WARNING = "warning"
    ERROR = "error"
    BROKER_AUDIT = "broker_audit"
    SSH_PROMPT = "ssh_prompt"
    CONNECTION = "connection"


def _canonical_sha256(domain: str, document: dict[str, object]) -> str:
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(b"\x00")
    digest.update(encoded)
    return digest.hexdigest()


def _require_digest(value: str, *, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _HEX_DIGEST_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _require_prompt_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _PROMPT_ID_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("prompt_id must be 32 lowercase hexadecimal characters")
    return value


def _new_prompt_id() -> str:
    return secrets.token_hex(16)


def _require_viewer_session_id(value: str) -> str:
    if not isinstance(value, str) or _VIEWER_SESSION_ID_RE.fullmatch(value) is None:
        raise ValueError(
            "viewer_session_id must be tmuxgate- followed by 12 lowercase "
            "hexadecimal characters"
        )
    return value


def _require_request(request_id: str, request: RequestSpec) -> tuple[str, str, str]:
    request_id = validate_request_id(request_id)
    if not isinstance(request, RequestSpec):
        raise TypeError("request must be a RequestSpec")
    request_sha256 = request.client_request_sha256()
    if request.mode is ExecutionMode.SCRIPT:
        command_sha256 = hashlib.sha256(request.script).hexdigest()
    else:
        command_sha256 = _canonical_sha256(
            "tmuxgate-argv-identity-v1",
            {"argv": list(request.argv)},
        )
    return request_id, request_sha256, command_sha256


def _require_plan(request: RequestSpec, plan: ConnectionPlan) -> str:
    if not isinstance(plan, ConnectionPlan):
        raise TypeError("connection_plan must be a ConnectionPlan")
    if plan.machine_name != request.machine_alias:
        raise ValueError("connection plan belongs to a different request machine")
    # Connection-plan digests predate domain separation and hash only the
    # canonical JSON bytes.  Recalculate that exact established format here.
    encoded = json.dumps(
        plan.canonical_document(include_digest=False),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    calculated = hashlib.sha256(encoded).hexdigest()
    _require_digest(plan.plan_sha256, field_name="connection_plan.plan_sha256")
    if calculated != plan.plan_sha256:
        raise ValueError("connection plan digest does not match its canonical data")
    endpoint_ids = tuple(item.resolved.endpoint_id for item in plan.endpoints)
    if len(set(endpoint_ids)) != len(endpoint_ids):
        raise ValueError("connection plan endpoint identities must be unique")
    return calculated


def _require_failure_detail(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("failure_detail must be non-empty text")
    if len(value) > MAX_FAILURE_DETAIL_CHARACTERS:
        raise ValueError(
            f"failure_detail exceeds {MAX_FAILURE_DETAIL_CHARACTERS} characters"
        )
    return value


def _require_mutation_state(value: RemoteMutationState) -> RemoteMutationState:
    try:
        return RemoteMutationState(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid remote mutation state") from exc


def _require_command_state(value: RemoteCommandState) -> RemoteCommandState:
    try:
        return RemoteCommandState(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid remote command state") from exc


def _require_diagnostics(value: bytes) -> tuple[bytes, str]:
    if not isinstance(value, bytes):
        raise TypeError("OpenSSH diagnostics must be bytes")
    if len(value) > MAX_OPENSSH_DIAGNOSTIC_BYTES:
        raise ValueError(
            f"OpenSSH diagnostics exceed {MAX_OPENSSH_DIAGNOSTIC_BYTES} bytes"
        )
    return value, hashlib.sha256(value).hexdigest()


def _endpoint_index(plan: ConnectionPlan, endpoint_id: str) -> int:
    if not isinstance(endpoint_id, str) or not endpoint_id:
        raise ValueError("endpoint ID must be non-empty text")
    for index, endpoint in enumerate(plan.endpoints):
        if endpoint.resolved.endpoint_id == endpoint_id:
            return index
    raise ValueError("endpoint is not present in the approved connection plan")


@dataclass(frozen=True, slots=True)
class ExecutionApprovalPrompt:
    prompt_id: str
    request_id: str
    request: RequestSpec
    connection_plan: ConnectionPlan | None
    unbound_fake: bool
    client_request_sha256: str
    command_identity_sha256: str
    connection_plan_sha256: str | None
    binding_sha256: str

    def __post_init__(self) -> None:
        _require_prompt_id(self.prompt_id)
        request_id, request_digest, command_digest = _require_request(
            self.request_id, self.request
        )
        if request_id != self.request_id:
            raise ValueError("request_id is not canonical")
        _require_digest(self.client_request_sha256, field_name="client_request_sha256")
        _require_digest(
            self.command_identity_sha256, field_name="command_identity_sha256"
        )
        if self.client_request_sha256 != request_digest:
            raise ValueError("client request digest does not match request bytes")
        if self.command_identity_sha256 != command_digest:
            raise ValueError("command identity digest does not match request command")
        if not isinstance(self.unbound_fake, bool):
            raise TypeError("unbound_fake must be a bool")
        if self.connection_plan is None:
            if not self.unbound_fake:
                raise ValueError("connection_plan is required outside the fake backend")
            if self.connection_plan_sha256 is not None:
                raise ValueError("unbound fake prompt must not claim a plan digest")
            plan_digest = None
        else:
            if self.unbound_fake:
                raise ValueError("unbound_fake prompts must not include a connection plan")
            plan_digest = _require_plan(self.request, self.connection_plan)
            if self.connection_plan_sha256 != plan_digest:
                raise ValueError("connection plan digest does not match the approved plan")
        expected = _canonical_sha256(
            "tmuxgate-execution-prompt-v1",
            {
                "client_request_sha256": request_digest,
                "command_identity_sha256": command_digest,
                "connection_plan_sha256": plan_digest,
                "prompt_id": self.prompt_id,
                "request_id": request_id,
                "unbound_fake": self.unbound_fake,
            },
        )
        _require_digest(self.binding_sha256, field_name="binding_sha256")
        if self.binding_sha256 != expected:
            raise ValueError("execution prompt binding does not match its identity")

    @classmethod
    def create(
        cls,
        request_id: str,
        request: RequestSpec,
        connection_plan: ConnectionPlan | None,
        *,
        prompt_id: str | None = None,
        unbound_fake: bool = False,
    ) -> "ExecutionApprovalPrompt":
        request_id, request_digest, command_digest = _require_request(
            request_id, request
        )
        prompt_id = _new_prompt_id() if prompt_id is None else prompt_id
        _require_prompt_id(prompt_id)
        if not isinstance(unbound_fake, bool):
            raise TypeError("unbound_fake must be a bool")
        if connection_plan is None and not unbound_fake:
            raise ValueError("connection_plan is required outside the fake backend")
        if connection_plan is not None and unbound_fake:
            raise ValueError("unbound_fake prompts must not include a connection plan")
        plan_digest = (
            None if connection_plan is None else _require_plan(request, connection_plan)
        )
        binding = _canonical_sha256(
            "tmuxgate-execution-prompt-v1",
            {
                "client_request_sha256": request_digest,
                "command_identity_sha256": command_digest,
                "connection_plan_sha256": plan_digest,
                "prompt_id": prompt_id,
                "request_id": request_id,
                "unbound_fake": unbound_fake,
            },
        )
        return cls(
            prompt_id,
            request_id,
            request,
            connection_plan,
            unbound_fake,
            request_digest,
            command_digest,
            plan_digest,
            binding,
        )


@dataclass(frozen=True, slots=True)
class SshRetryPrompt:
    prompt_id: str
    request_id: str
    request: RequestSpec
    connection_plan: ConnectionPlan
    endpoint_id: str
    failure_detail: str
    openssh_diagnostics: bytes
    openssh_diagnostics_sha256: str
    retry_number: int
    retry_limit: int
    remote_command_state: RemoteCommandState
    remote_mutation_state: RemoteMutationState
    client_request_sha256: str
    command_identity_sha256: str
    connection_plan_sha256: str
    retry_binding_sha256: str

    def __post_init__(self) -> None:
        _require_prompt_id(self.prompt_id)
        request_id, request_digest, command_digest = _require_request(
            self.request_id, self.request
        )
        plan_digest = _require_plan(self.request, self.connection_plan)
        _endpoint_index(self.connection_plan, self.endpoint_id)
        failure = _require_failure_detail(self.failure_detail)
        diagnostics, diagnostic_digest = _require_diagnostics(
            self.openssh_diagnostics
        )
        _require_digest(
            self.openssh_diagnostics_sha256,
            field_name="openssh_diagnostics_sha256",
        )
        if self.openssh_diagnostics_sha256 != diagnostic_digest:
            raise ValueError("OpenSSH diagnostic digest does not match exact bytes")
        if self.retry_number != 1 or self.retry_limit != SSH_RETRY_LIMIT:
            raise ValueError("SSH retry prompt must expose the one-retry policy")
        command_state = _require_command_state(self.remote_command_state)
        if command_state is not RemoteCommandState.NOT_STARTED:
            raise ValueError("SSH retry is forbidden after the remote command may start")
        mutation = _require_mutation_state(self.remote_mutation_state)
        if mutation is not RemoteMutationState.NOT_STARTED:
            raise ValueError("SSH retry is forbidden after remote mutation may have started")
        for value, expected, name in (
            (self.client_request_sha256, request_digest, "client request"),
            (self.command_identity_sha256, command_digest, "command identity"),
            (self.connection_plan_sha256, plan_digest, "connection plan"),
        ):
            _require_digest(value, field_name=f"{name.replace(' ', '_')}_sha256")
            if value != expected:
                raise ValueError(f"{name} digest does not match canonical data")
        expected_binding = _canonical_sha256(
            "tmuxgate-ssh-retry-prompt-v1",
            {
                "client_request_sha256": request_digest,
                "command_identity_sha256": command_digest,
                "connection_plan_sha256": plan_digest,
                "endpoint_id": self.endpoint_id,
                "failure_detail": failure,
                "openssh_diagnostics_sha256": diagnostic_digest,
                "prompt_id": self.prompt_id,
                "remote_command_state": command_state.value,
                "remote_mutation_state": mutation.value,
                "request_id": request_id,
                "retry_limit": self.retry_limit,
                "retry_number": self.retry_number,
            },
        )
        _require_digest(self.retry_binding_sha256, field_name="retry_binding_sha256")
        if self.retry_binding_sha256 != expected_binding:
            raise ValueError("SSH retry binding does not match its canonical evidence")

    @property
    def binding_sha256(self) -> str:
        return self.retry_binding_sha256

    @classmethod
    def create(
        cls,
        request_id: str,
        request: RequestSpec,
        connection_plan: ConnectionPlan,
        *,
        endpoint_id: str,
        failure_detail: str,
        remote_mutation_state: RemoteMutationState,
        openssh_diagnostics: bytes = b"",
        retry_number: int = 1,
        retry_limit: int = SSH_RETRY_LIMIT,
        remote_command_state: RemoteCommandState = RemoteCommandState.NOT_STARTED,
        prompt_id: str | None = None,
    ) -> "SshRetryPrompt":
        request_id, request_digest, command_digest = _require_request(
            request_id, request
        )
        plan_digest = _require_plan(request, connection_plan)
        _endpoint_index(connection_plan, endpoint_id)
        failure_detail = _require_failure_detail(failure_detail)
        diagnostics, diagnostic_digest = _require_diagnostics(openssh_diagnostics)
        if retry_number != 1 or retry_limit != SSH_RETRY_LIMIT:
            raise ValueError("SSH retry prompt must expose the one-retry policy")
        command_state = _require_command_state(remote_command_state)
        if command_state is not RemoteCommandState.NOT_STARTED:
            raise ValueError("SSH retry is forbidden after the remote command may start")
        mutation = _require_mutation_state(remote_mutation_state)
        if mutation is not RemoteMutationState.NOT_STARTED:
            raise ValueError("SSH retry is forbidden after remote mutation may have started")
        prompt_id = _new_prompt_id() if prompt_id is None else prompt_id
        binding = _canonical_sha256(
            "tmuxgate-ssh-retry-prompt-v1",
            {
                "client_request_sha256": request_digest,
                "command_identity_sha256": command_digest,
                "connection_plan_sha256": plan_digest,
                "endpoint_id": endpoint_id,
                "failure_detail": failure_detail,
                "openssh_diagnostics_sha256": diagnostic_digest,
                "prompt_id": prompt_id,
                "remote_command_state": command_state.value,
                "remote_mutation_state": mutation.value,
                "request_id": request_id,
                "retry_limit": retry_limit,
                "retry_number": retry_number,
            },
        )
        return cls(
            prompt_id,
            request_id,
            request,
            connection_plan,
            endpoint_id,
            failure_detail,
            diagnostics,
            diagnostic_digest,
            retry_number,
            retry_limit,
            command_state,
            mutation,
            request_digest,
            command_digest,
            plan_digest,
            binding,
        )


@dataclass(frozen=True, slots=True)
class RouteFallbackPrompt:
    prompt_id: str
    request_id: str
    request: RequestSpec
    connection_plan: ConnectionPlan
    failed_endpoint_id: str
    fallback_endpoint_id: str
    failure_detail: str
    openssh_diagnostics: bytes
    openssh_diagnostics_sha256: str
    remote_command_state: RemoteCommandState
    remote_mutation_state: RemoteMutationState
    client_request_sha256: str
    command_identity_sha256: str
    connection_plan_sha256: str
    fallback_binding_sha256: str

    def __post_init__(self) -> None:
        _require_prompt_id(self.prompt_id)
        request_id, request_digest, command_digest = _require_request(
            self.request_id, self.request
        )
        plan_digest = _require_plan(self.request, self.connection_plan)
        failed_index = _endpoint_index(self.connection_plan, self.failed_endpoint_id)
        fallback_index = _endpoint_index(
            self.connection_plan, self.fallback_endpoint_id
        )
        if fallback_index != failed_index + 1:
            raise ValueError("fallback endpoint is not the next approved route")
        failure = _require_failure_detail(self.failure_detail)
        diagnostics, diagnostic_digest = _require_diagnostics(
            self.openssh_diagnostics
        )
        _require_digest(
            self.openssh_diagnostics_sha256,
            field_name="openssh_diagnostics_sha256",
        )
        if self.openssh_diagnostics_sha256 != diagnostic_digest:
            raise ValueError("OpenSSH diagnostic digest does not match exact bytes")
        command_state = _require_command_state(self.remote_command_state)
        if command_state is not RemoteCommandState.NOT_STARTED:
            raise ValueError("fallback is forbidden after the remote command may start")
        mutation = _require_mutation_state(self.remote_mutation_state)
        if mutation is not RemoteMutationState.NOT_STARTED:
            raise ValueError("fallback is forbidden after remote mutation may have started")
        for value, expected, name in (
            (self.client_request_sha256, request_digest, "client request"),
            (self.command_identity_sha256, command_digest, "command identity"),
            (self.connection_plan_sha256, plan_digest, "connection plan"),
        ):
            _require_digest(value, field_name=f"{name.replace(' ', '_')}_sha256")
            if value != expected:
                raise ValueError(f"{name} digest does not match canonical data")
        expected_binding = _canonical_sha256(
            "tmuxgate-route-fallback-prompt-v1",
            {
                "client_request_sha256": request_digest,
                "command_identity_sha256": command_digest,
                "connection_plan_sha256": plan_digest,
                "failed_endpoint_id": self.failed_endpoint_id,
                "failure_detail": failure,
                "fallback_endpoint_id": self.fallback_endpoint_id,
                "openssh_diagnostics_sha256": diagnostic_digest,
                "prompt_id": self.prompt_id,
                "remote_command_state": command_state.value,
                "remote_mutation_state": mutation.value,
                "request_id": request_id,
            },
        )
        _require_digest(
            self.fallback_binding_sha256, field_name="fallback_binding_sha256"
        )
        if self.fallback_binding_sha256 != expected_binding:
            raise ValueError("fallback binding does not match its canonical evidence")

    @property
    def binding_sha256(self) -> str:
        return self.fallback_binding_sha256

    @classmethod
    def create(
        cls,
        request_id: str,
        request: RequestSpec,
        connection_plan: ConnectionPlan,
        *,
        failed_endpoint_id: str,
        fallback_endpoint_id: str,
        failure_detail: str,
        remote_mutation_state: RemoteMutationState,
        openssh_diagnostics: bytes = b"",
        remote_command_state: RemoteCommandState = RemoteCommandState.NOT_STARTED,
        prompt_id: str | None = None,
    ) -> "RouteFallbackPrompt":
        request_id, request_digest, command_digest = _require_request(
            request_id, request
        )
        plan_digest = _require_plan(request, connection_plan)
        failed_index = _endpoint_index(connection_plan, failed_endpoint_id)
        if _endpoint_index(connection_plan, fallback_endpoint_id) != failed_index + 1:
            raise ValueError("fallback endpoint is not the next approved route")
        failure_detail = _require_failure_detail(failure_detail)
        diagnostics, diagnostic_digest = _require_diagnostics(openssh_diagnostics)
        command_state = _require_command_state(remote_command_state)
        if command_state is not RemoteCommandState.NOT_STARTED:
            raise ValueError("fallback is forbidden after the remote command may start")
        mutation = _require_mutation_state(remote_mutation_state)
        if mutation is not RemoteMutationState.NOT_STARTED:
            raise ValueError("fallback is forbidden after remote mutation may have started")
        prompt_id = _new_prompt_id() if prompt_id is None else prompt_id
        binding = _canonical_sha256(
            "tmuxgate-route-fallback-prompt-v1",
            {
                "client_request_sha256": request_digest,
                "command_identity_sha256": command_digest,
                "connection_plan_sha256": plan_digest,
                "failed_endpoint_id": failed_endpoint_id,
                "failure_detail": failure_detail,
                "fallback_endpoint_id": fallback_endpoint_id,
                "openssh_diagnostics_sha256": diagnostic_digest,
                "prompt_id": prompt_id,
                "remote_command_state": command_state.value,
                "remote_mutation_state": mutation.value,
                "request_id": request_id,
            },
        )
        return cls(
            prompt_id,
            request_id,
            request,
            connection_plan,
            failed_endpoint_id,
            fallback_endpoint_id,
            failure_detail,
            diagnostics,
            diagnostic_digest,
            command_state,
            mutation,
            request_digest,
            command_digest,
            plan_digest,
            binding,
        )


@dataclass(frozen=True, slots=True)
class SecretInputAuthorizationPrompt:
    """Exact, one-shot authority for one broker-terminal handoff."""

    prompt_id: str
    request_id: str
    request: RequestSpec
    connection_plan: ConnectionPlan
    endpoint_id: str
    viewer_session_id: str
    client_request_sha256: str
    command_identity_sha256: str
    connection_plan_sha256: str
    secret_input_binding_sha256: str

    def __post_init__(self) -> None:
        _require_prompt_id(self.prompt_id)
        request_id, request_digest, command_digest = _require_request(
            self.request_id, self.request
        )
        plan_digest = _require_plan(self.request, self.connection_plan)
        _endpoint_index(self.connection_plan, self.endpoint_id)
        _require_viewer_session_id(self.viewer_session_id)
        for value, expected, name in (
            (self.client_request_sha256, request_digest, "client request"),
            (self.command_identity_sha256, command_digest, "command identity"),
            (self.connection_plan_sha256, plan_digest, "connection plan"),
        ):
            _require_digest(value, field_name=f"{name.replace(' ', '_')}_sha256")
            if value != expected:
                raise ValueError(f"{name} digest does not match canonical data")
        expected_binding = _canonical_sha256(
            "tmuxgate-secret-input-prompt-v1",
            {
                "client_request_sha256": request_digest,
                "command_identity_sha256": command_digest,
                "connection_plan_sha256": plan_digest,
                "endpoint_id": self.endpoint_id,
                "prompt_id": self.prompt_id,
                "request_id": request_id,
                "viewer_session_id": self.viewer_session_id,
            },
        )
        _require_digest(
            self.secret_input_binding_sha256,
            field_name="secret_input_binding_sha256",
        )
        if self.secret_input_binding_sha256 != expected_binding:
            raise ValueError("secret-input binding does not match its exact recipient")

    @property
    def binding_sha256(self) -> str:
        return self.secret_input_binding_sha256

    @classmethod
    def create(
        cls,
        request_id: str,
        request: RequestSpec,
        connection_plan: ConnectionPlan,
        *,
        endpoint_id: str,
        viewer_session_id: str,
        prompt_id: str | None = None,
    ) -> "SecretInputAuthorizationPrompt":
        request_id, request_digest, command_digest = _require_request(
            request_id, request
        )
        plan_digest = _require_plan(request, connection_plan)
        _endpoint_index(connection_plan, endpoint_id)
        _require_viewer_session_id(viewer_session_id)
        prompt_id = _new_prompt_id() if prompt_id is None else prompt_id
        binding = _canonical_sha256(
            "tmuxgate-secret-input-prompt-v1",
            {
                "client_request_sha256": request_digest,
                "command_identity_sha256": command_digest,
                "connection_plan_sha256": plan_digest,
                "endpoint_id": endpoint_id,
                "prompt_id": prompt_id,
                "request_id": request_id,
                "viewer_session_id": viewer_session_id,
            },
        )
        return cls(
            prompt_id,
            request_id,
            request,
            connection_plan,
            endpoint_id,
            viewer_session_id,
            request_digest,
            command_digest,
            plan_digest,
            binding,
        )


@dataclass(frozen=True, slots=True)
class SecretInputRecipient:
    """Request and route identity retained while its isolated viewer is live."""

    request_id: str
    request: RequestSpec
    connection_plan: ConnectionPlan
    endpoint_id: str

    def __post_init__(self) -> None:
        _require_request(self.request_id, self.request)
        _require_plan(self.request, self.connection_plan)
        _endpoint_index(self.connection_plan, self.endpoint_id)

    def create_prompt(self, viewer_session_id: str) -> SecretInputAuthorizationPrompt:
        return SecretInputAuthorizationPrompt.create(
            self.request_id,
            self.request,
            self.connection_plan,
            endpoint_id=self.endpoint_id,
            viewer_session_id=viewer_session_id,
        )


@dataclass(frozen=True, slots=True)
class MachineDisablePrompt:
    prompt_id: str
    request_id: str
    request: RequestSpec
    connection_plan: ConnectionPlan
    failure_detail: str
    remote_mutation_state: RemoteMutationState
    binding_sha256: str

    def __post_init__(self) -> None:
        _require_prompt_id(self.prompt_id)
        request_id, request_digest, _command_digest = _require_request(
            self.request_id, self.request
        )
        plan_digest = _require_plan(self.request, self.connection_plan)
        failure = _require_failure_detail(self.failure_detail)
        mutation = _require_mutation_state(self.remote_mutation_state)
        if mutation is not RemoteMutationState.NOT_STARTED:
            raise ValueError("machine disable decision is forbidden after remote mutation")
        expected = _canonical_sha256(
            "tmuxgate-machine-disable-prompt-v1",
            {
                "client_request_sha256": request_digest,
                "connection_plan_sha256": plan_digest,
                "failure_detail": failure,
                "machine_name": self.request.machine_alias,
                "prompt_id": self.prompt_id,
                "remote_mutation_state": mutation.value,
                "request_id": request_id,
            },
        )
        _require_digest(self.binding_sha256, field_name="binding_sha256")
        if self.binding_sha256 != expected:
            raise ValueError("machine-disable binding does not match its evidence")

    @classmethod
    def create(
        cls,
        request_id: str,
        request: RequestSpec,
        connection_plan: ConnectionPlan,
        *,
        failure_detail: str,
        remote_mutation_state: RemoteMutationState,
        prompt_id: str | None = None,
    ) -> "MachineDisablePrompt":
        request_id, request_digest, _command_digest = _require_request(
            request_id, request
        )
        plan_digest = _require_plan(request, connection_plan)
        failure_detail = _require_failure_detail(failure_detail)
        mutation = _require_mutation_state(remote_mutation_state)
        if mutation is not RemoteMutationState.NOT_STARTED:
            raise ValueError("machine disable decision is forbidden after remote mutation")
        prompt_id = _new_prompt_id() if prompt_id is None else prompt_id
        binding = _canonical_sha256(
            "tmuxgate-machine-disable-prompt-v1",
            {
                "client_request_sha256": request_digest,
                "connection_plan_sha256": plan_digest,
                "failure_detail": failure_detail,
                "machine_name": request.machine_alias,
                "prompt_id": prompt_id,
                "remote_mutation_state": mutation.value,
                "request_id": request_id,
            },
        )
        return cls(
            prompt_id,
            request_id,
            request,
            connection_plan,
            failure_detail,
            mutation,
            binding,
        )


OperatorPrompt: TypeAlias = (
    ExecutionApprovalPrompt
    | SshRetryPrompt
    | RouteFallbackPrompt
    | SecretInputAuthorizationPrompt
    | MachineDisablePrompt
)


@dataclass(frozen=True, slots=True)
class OperatorDecision:
    """One decision bound to one exact prompt identity and canonical evidence."""

    prompt_id: str
    binding_sha256: str
    decision: ApprovalDecision

    def __post_init__(self) -> None:
        _require_prompt_id(self.prompt_id)
        _require_digest(self.binding_sha256, field_name="binding_sha256")
        try:
            decision = ApprovalDecision(self.decision)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid operator decision") from exc
        object.__setattr__(self, "decision", decision)

    @classmethod
    def for_prompt(
        cls, prompt: OperatorPrompt, decision: ApprovalDecision
    ) -> "OperatorDecision":
        return cls(prompt.prompt_id, prompt.binding_sha256, decision)


def require_operator_decision(
    prompt: OperatorPrompt,
    decision: OperatorDecision,
) -> ApprovalDecision:
    """Validate an interface result against the exact prompt before policy use."""

    if not isinstance(decision, OperatorDecision):
        raise OperatorInterfaceError("operator interface returned an invalid decision")
    if (
        decision.prompt_id != prompt.prompt_id
        or decision.binding_sha256 != prompt.binding_sha256
    ):
        raise OperatorInterfaceError("operator decision belongs to a different prompt")
    return decision.decision


@dataclass(frozen=True, slots=True)
class OperationalActivity:
    event_id: str
    kind: ActivityKind
    message: str
    request_id: str | None = None
    machine_name: str | None = None
    endpoint_id: str | None = None
    details: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    connection_phase: ConnectionPhase | None = None
    remote_mutation_state: RemoteMutationState | None = None

    def __post_init__(self) -> None:
        _require_prompt_id(self.event_id)
        try:
            kind = ActivityKind(self.kind)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid activity kind") from exc
        object.__setattr__(self, "kind", kind)
        if not isinstance(self.message, str) or not self.message:
            raise ValueError("activity message must be non-empty text")
        if len(self.message) > MAX_ACTIVITY_MESSAGE_CHARACTERS:
            raise ValueError("activity message is too long")
        if self.request_id is not None:
            validate_request_id(self.request_id)
        if self.machine_name is not None:
            validate_alias(self.machine_name)
        if self.endpoint_id is not None and (
            not isinstance(self.endpoint_id, str) or not self.endpoint_id
        ):
            raise ValueError("activity endpoint_id must be non-empty text")
        details = tuple(self.details)
        if any(
            not isinstance(name, str)
            or not name
            or not isinstance(value, str)
            for name, value in details
        ):
            raise ValueError("activity details must contain non-empty string keys")
        object.__setattr__(self, "details", details)
        if self.connection_phase is None:
            if kind is ActivityKind.CONNECTION:
                raise ValueError("connection activity requires a connection phase")
        else:
            try:
                phase = ConnectionPhase(self.connection_phase)
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid connection phase") from exc
            if kind is not ActivityKind.CONNECTION:
                raise ValueError("connection phase requires connection activity")
            if self.request_id is None or self.machine_name is None:
                raise ValueError("connection activity requires request and machine")
            object.__setattr__(self, "connection_phase", phase)
        if self.remote_mutation_state is not None:
            mutation = _require_mutation_state(self.remote_mutation_state)
            if kind is not ActivityKind.CONNECTION:
                raise ValueError("remote mutation state requires connection activity")
            object.__setattr__(self, "remote_mutation_state", mutation)
        elif kind is ActivityKind.CONNECTION:
            raise ValueError("connection activity requires remote mutation state")

    @classmethod
    def create(
        cls,
        kind: ActivityKind,
        message: str,
        *,
        request_id: str | None = None,
        machine_name: str | None = None,
        endpoint_id: str | None = None,
        details: tuple[tuple[str, str], ...] = (),
        connection_phase: ConnectionPhase | None = None,
        remote_mutation_state: RemoteMutationState | None = None,
    ) -> "OperationalActivity":
        return cls(
            _new_prompt_id(),
            kind,
            message,
            request_id,
            machine_name,
            endpoint_id,
            details,
            connection_phase,
            remote_mutation_state,
        )


class PendingDecision:
    """Thread-safe one-shot slot; cancellation and abandonment mean denial."""

    def __init__(
        self,
        prompt: OperatorPrompt,
        on_resolved: Callable[[str], None] | None = None,
    ) -> None:
        self.prompt = prompt
        self._condition = threading.Condition()
        self._result: OperatorDecision | None = None
        self._on_resolved = on_resolved

    @property
    def resolved(self) -> bool:
        with self._condition:
            return self._result is not None

    def resolve(self, decision: OperatorDecision) -> bool:
        if not isinstance(decision, OperatorDecision):
            raise TypeError("decision must be an OperatorDecision")
        if (
            decision.prompt_id != self.prompt.prompt_id
            or decision.binding_sha256 != self.prompt.binding_sha256
        ):
            return False
        callback: Callable[[str], None] | None
        with self._condition:
            if self._result is not None:
                return False
            self._result = decision
            callback = self._on_resolved
            self._condition.notify_all()
        if callback is not None:
            callback(self.prompt.prompt_id)
        return True

    def deny(self) -> bool:
        return self.resolve(
            OperatorDecision.for_prompt(self.prompt, ApprovalDecision.DENIED)
        )

    cancel = deny
    abandon = deny

    def wait(self, timeout: float | None = None) -> OperatorDecision:
        with self._condition:
            if self._result is None:
                self._condition.wait_for(lambda: self._result is not None, timeout)
            if self._result is None:
                raise TimeoutError("operator decision was not resolved")
            return self._result


@dataclass(frozen=True, slots=True)
class QueuedPrompt:
    sequence: int
    prompt: OperatorPrompt
    pending: PendingDecision


_CLOSE_QUEUE = object()


class PromptQueue:
    """FIFO prompt queue with atomic close and fail-closed pending ownership."""

    def __init__(self) -> None:
        self._queue: queue.Queue[QueuedPrompt | object] = queue.Queue()
        self._lock = threading.Lock()
        self._pending: dict[str, PendingDecision] = {}
        self._seen_prompt_ids: set[str] = set()
        self._next_sequence = 0
        self._closed = False

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def submit(self, prompt: OperatorPrompt) -> PendingDecision:
        self._require_prompt(prompt)
        with self._lock:
            if prompt.prompt_id in self._seen_prompt_ids:
                raise OperatorInterfaceError("prompt identity was already submitted")
            self._seen_prompt_ids.add(prompt.prompt_id)
            pending = PendingDecision(prompt, self._forget)
            if self._closed:
                closed = True
            else:
                closed = False
                sequence = self._next_sequence
                self._next_sequence += 1
                self._pending[prompt.prompt_id] = pending
                self._queue.put(QueuedPrompt(sequence, prompt, pending))
        if closed:
            pending.deny()
        return pending

    def decide_without_presentation(
        self,
        prompt: OperatorPrompt,
        decision: ApprovalDecision,
    ) -> OperatorDecision:
        """Record one automatic policy decision without exposing it to the UI."""

        self._require_prompt(prompt)
        decision = ApprovalDecision(decision)
        with self._lock:
            if prompt.prompt_id in self._seen_prompt_ids:
                raise OperatorInterfaceError("prompt identity was already submitted")
            self._seen_prompt_ids.add(prompt.prompt_id)
            if self._closed:
                decision = ApprovalDecision.DENIED
        return OperatorDecision.for_prompt(prompt, decision)

    @staticmethod
    def _require_prompt(prompt: OperatorPrompt) -> None:
        if not isinstance(
            prompt,
            (
                ExecutionApprovalPrompt,
                SshRetryPrompt,
                RouteFallbackPrompt,
                SecretInputAuthorizationPrompt,
                MachineDisablePrompt,
            ),
        ):
            raise TypeError("prompt must be a structured operator prompt")

    def next_prompt(self, timeout: float | None = None) -> QueuedPrompt | None:
        try:
            item = self._queue.get(timeout=timeout)
        except queue.Empty:
            return None
        if item is _CLOSE_QUEUE:
            return None
        assert isinstance(item, QueuedPrompt)
        return item

    def _forget(self, prompt_id: str) -> None:
        with self._lock:
            self._pending.pop(prompt_id, None)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            pending = tuple(self._pending.values())
            self._queue.put(_CLOSE_QUEUE)
        for item in pending:
            item.deny()


class OperatorInterface(Protocol):
    """Thread-safe presentation boundary owned by the foreground application."""

    def request_execution_approval(
        self, prompt: ExecutionApprovalPrompt
    ) -> OperatorDecision: ...

    def request_ssh_retry(self, prompt: SshRetryPrompt) -> OperatorDecision: ...

    def request_fallback(self, prompt: RouteFallbackPrompt) -> OperatorDecision: ...

    def request_secret_input_authorization(
        self, prompt: SecretInputAuthorizationPrompt
    ) -> OperatorDecision: ...

    def run_external_terminal_session(
        self,
        prompt: SecretInputAuthorizationPrompt,
        session: Callable[[], None],
    ) -> None: ...

    def run_terminal_session(
        self, purpose: str, session: Callable[[], None]
    ) -> None: ...

    def request_machine_disable(
        self, prompt: MachineDisablePrompt
    ) -> OperatorDecision: ...

    def publish_activity(self, event: OperationalActivity) -> None: ...

    def run_dashboard(self, stop: threading.Event, config: object) -> None: ...

    def close(self) -> bool: ...


Dashboard = Callable[[threading.Event, TerminalArbiter, object], None]
PromptPresenter = Callable[[OperatorPrompt], ApprovalDecision]


def _terminal_safe_text(value: str) -> str:
    return "".join(
        character
        if 0x20 <= ord(character) <= 0x7E
        else f"\\x{ord(character):02x}"
        if ord(character) <= 0xFF
        else f"\\u{ord(character):04x}"
        for character in value
    )


class PlainTerminalInterface:
    """FIFO line-oriented implementation using only the trusted ``/dev/tty``.

    A dedicated presenter thread is the sole consumer of the prompt queue.
    Worker threads block on their own :class:`PendingDecision`.  ``close()``
    atomically denies every pending slot before attempting to join the
    presenter, so shutdown cannot turn a missing interface into approval.
    """

    def __init__(
        self,
        terminal: TerminalArbiter,
        *,
        dashboard: Dashboard | None = None,
        approval_terminal: ApprovalTerminal | None = None,
        pager: ApprovalPager | None | object = _DEFAULT_PAGER,
        presenter: PromptPresenter | None = None,
        approval_mode: str = "always",
        activity_capacity: int = 256,
        close_timeout_seconds: float = 1.0,
    ) -> None:
        if not all(
            callable(getattr(terminal, method_name, None))
            for method_name in ("claim", "poll_dashboard_line")
        ):
            raise TypeError("terminal must provide the TerminalArbiter contract")
        if dashboard is not None and not callable(dashboard):
            raise TypeError("dashboard must be callable")
        if presenter is not None and not callable(presenter):
            raise TypeError("presenter must be callable")
        if approval_mode not in {"always", "disabled"}:
            raise ValueError("approval_mode must be 'always' or 'disabled'")
        if (
            isinstance(activity_capacity, bool)
            or not isinstance(activity_capacity, int)
            or not 1 <= activity_capacity <= 65536
        ):
            raise ValueError("activity_capacity must be between 1 and 65536")
        if close_timeout_seconds < 0:
            raise ValueError("close_timeout_seconds must be non-negative")
        self.terminal = terminal
        self._dashboard = dashboard
        self._approval_terminal = approval_terminal
        self._pager = pager
        self._presenter = self._present_prompt if presenter is None else presenter
        self._approval_mode = approval_mode
        self._approval_mode_lock = threading.Lock()
        self._prompts = PromptQueue()
        self._activity: deque[OperationalActivity] = deque(maxlen=activity_capacity)
        self._activity_lock = threading.Lock()
        self._close_timeout_seconds = float(close_timeout_seconds)
        self._failure: BaseException | None = None
        self._thread = threading.Thread(
            target=self._presentation_loop,
            name="tmuxgate-plain-operator",
            daemon=True,
        )
        self._thread.start()

    @property
    def activity_history(self) -> tuple[OperationalActivity, ...]:
        with self._activity_lock:
            return tuple(self._activity)

    @property
    def approval_mode(self) -> str:
        with self._approval_mode_lock:
            return self._approval_mode

    def set_approval_mode(self, approval_mode: str) -> None:
        if approval_mode not in {"always", "disabled"}:
            raise ValueError("approval_mode must be 'always' or 'disabled'")
        with self._approval_mode_lock:
            self._approval_mode = approval_mode

    def _request(self, prompt: OperatorPrompt) -> OperatorDecision:
        pending = self._prompts.submit(prompt)
        try:
            return pending.wait()
        except BaseException:
            pending.abandon()
            raise

    def request_execution_approval(
        self, prompt: ExecutionApprovalPrompt
    ) -> OperatorDecision:
        if not isinstance(prompt, ExecutionApprovalPrompt):
            raise TypeError("prompt must be an ExecutionApprovalPrompt")
        if self.approval_mode == "disabled":
            return self._prompts.decide_without_presentation(
                prompt, ApprovalDecision.APPROVED
            )
        return self._request(prompt)

    def request_ssh_retry(self, prompt: SshRetryPrompt) -> OperatorDecision:
        if not isinstance(prompt, SshRetryPrompt):
            raise TypeError("prompt must be an SshRetryPrompt")
        return self._request(prompt)

    def request_fallback(self, prompt: RouteFallbackPrompt) -> OperatorDecision:
        if not isinstance(prompt, RouteFallbackPrompt):
            raise TypeError("prompt must be a RouteFallbackPrompt")
        if self.approval_mode == "disabled":
            return self._prompts.decide_without_presentation(
                prompt, ApprovalDecision.APPROVED
            )
        return self._request(prompt)

    def request_secret_input_authorization(
        self, prompt: SecretInputAuthorizationPrompt
    ) -> OperatorDecision:
        if not isinstance(prompt, SecretInputAuthorizationPrompt):
            raise TypeError("prompt must be a SecretInputAuthorizationPrompt")
        if self.approval_mode == "disabled":
            return self._prompts.decide_without_presentation(
                prompt, ApprovalDecision.DENIED
            )
        # Manual approval mode retains an exact independent terminal decision.
        return self._request(prompt)

    def run_external_terminal_session(
        self,
        prompt: SecretInputAuthorizationPrompt,
        session: Callable[[], None],
    ) -> None:
        """Give a trusted process exclusive use of the controlling terminal."""

        if not isinstance(prompt, SecretInputAuthorizationPrompt):
            raise TypeError("prompt must be a SecretInputAuthorizationPrompt")
        if not callable(session):
            raise TypeError("external terminal session must be callable")
        with self.terminal.claim(
            priority=TerminalPriority.SECRET,
            purpose=f"secret input for request {prompt.request_id}",
        ):
            session()

    def run_terminal_session(
        self, purpose: str, session: Callable[[], None]
    ) -> None:
        """Give a trusted process the terminal outside any request binding.

        SSH authentication has to reach the operator before a request-bound
        secret recipient can exist, so this handoff is named by purpose rather
        than by prompt.  A line-oriented owner leaves the terminal canonical,
        so the ordinary validating claim is already correct here.
        """

        if not isinstance(purpose, str):
            raise TypeError("terminal session purpose must be a string")
        if not callable(session):
            raise TypeError("external terminal session must be callable")
        with self.terminal.claim(
            priority=TerminalPriority.INTERACTIVE, purpose=purpose
        ):
            session()

    def request_machine_disable(
        self, prompt: MachineDisablePrompt
    ) -> OperatorDecision:
        if not isinstance(prompt, MachineDisablePrompt):
            raise TypeError("prompt must be a MachineDisablePrompt")
        return self._request(prompt)

    def _presentation_loop(self) -> None:
        while not self._prompts.closed:
            queued = self._prompts.next_prompt()
            if queued is None:
                return
            if queued.pending.resolved:
                continue
            try:
                decision = ApprovalDecision(self._presenter(queued.prompt))
            except BaseException as exc:
                self._failure = exc
                self._prompts.close()
                return
            queued.pending.resolve(
                OperatorDecision.for_prompt(queued.prompt, decision)
            )

    def _present_prompt(self, prompt: OperatorPrompt) -> ApprovalDecision:
        priority = (
            TerminalPriority.SECRET
            if isinstance(prompt, (SshRetryPrompt, SecretInputAuthorizationPrompt))
            else TerminalPriority.APPROVAL
        )
        with self.terminal.claim(priority=priority, purpose=type(prompt).__name__):
            if isinstance(prompt, ExecutionApprovalPrompt):
                keywords: dict[str, object] = {
                    "terminal": self._approval_terminal,
                    "connection_plan": prompt.connection_plan,
                }
                if self._pager is not _DEFAULT_PAGER:
                    keywords["pager"] = self._pager
                return request_approval(prompt.request_id, prompt.request, **keywords)
            if isinstance(prompt, SshRetryPrompt):
                return request_ssh_retry(
                    prompt.request_id,
                    prompt.request,
                    prompt.connection_plan,
                    endpoint_id=prompt.endpoint_id,
                    failure_detail=prompt.failure_detail,
                    remote_mutation_started=False,
                    openssh_diagnostics=prompt.openssh_diagnostics,
                    openssh_diagnostics_sha256=(
                        prompt.openssh_diagnostics_sha256
                    ),
                    remote_command_state=prompt.remote_command_state.value,
                    retry_number=prompt.retry_number,
                    retry_limit=prompt.retry_limit,
                    retry_binding_sha256=prompt.retry_binding_sha256,
                    prompt_id=prompt.prompt_id,
                    terminal=self._approval_terminal,
                )
            if isinstance(prompt, RouteFallbackPrompt):
                keywords = {
                    "failed_endpoint_id": prompt.failed_endpoint_id,
                    "fallback_endpoint_id": prompt.fallback_endpoint_id,
                    "failure_detail": prompt.failure_detail,
                    "remote_mutation_started": False,
                    "openssh_diagnostics": prompt.openssh_diagnostics,
                    "openssh_diagnostics_sha256": (
                        prompt.openssh_diagnostics_sha256
                    ),
                    "remote_command_state": prompt.remote_command_state.value,
                    "fallback_binding_sha256": prompt.fallback_binding_sha256,
                    "prompt_id": prompt.prompt_id,
                    "terminal": self._approval_terminal,
                }
                if self._pager is not _DEFAULT_PAGER:
                    keywords["pager"] = self._pager
                return request_fallback_approval(
                    prompt.request_id,
                    prompt.request,
                    prompt.connection_plan,
                    **keywords,
                )
            if isinstance(prompt, SecretInputAuthorizationPrompt):
                return request_secret_input_authorization(
                    prompt.request_id,
                    prompt.request,
                    prompt.connection_plan,
                    prompt_id=prompt.prompt_id,
                    endpoint_id=prompt.endpoint_id,
                    viewer_session_id=prompt.viewer_session_id,
                    command_identity_sha256=prompt.command_identity_sha256,
                    secret_input_binding_sha256=prompt.secret_input_binding_sha256,
                    terminal=self._approval_terminal,
                )
            if isinstance(prompt, MachineDisablePrompt):
                return request_machine_disable(
                    prompt.request_id,
                    prompt.request.machine_alias,
                    failure_detail=prompt.failure_detail,
                    remote_mutation_started=False,
                    terminal=self._approval_terminal,
                )
            return ApprovalDecision.DENIED

    def publish_activity(self, event: OperationalActivity) -> None:
        if not isinstance(event, OperationalActivity):
            raise TypeError("event must be an OperationalActivity")
        with self._activity_lock:
            self._activity.append(event)
        if event.kind is ActivityKind.BROKER_AUDIT:
            return
        stream = sys.stderr if event.kind is ActivityKind.ERROR else sys.stdout
        try:
            with self.terminal.claim(
                priority=TerminalPriority.DASHBOARD,
                purpose="operator activity",
                flush_input=False,
            ):
                print(_terminal_safe_text(event.message), file=stream, flush=True)
        except BaseException as exc:
            self._failure = exc
            self._prompts.close()
            raise

    def run_dashboard(self, stop: threading.Event, config: object) -> None:
        if self._dashboard is None:
            while not stop.wait(0.25):
                pass
            return
        self._dashboard(stop, self.terminal, config)

    def close(self) -> bool:
        self._prompts.close()
        if self._thread.ident is not None:
            self._thread.join(timeout=self._close_timeout_seconds)
        return not self._thread.is_alive() and self._failure is None


__all__ = [
    "ActivityKind",
    "ConnectionPhase",
    "ExecutionApprovalPrompt",
    "MachineDisablePrompt",
    "OperationalActivity",
    "OperatorDecision",
    "OperatorInterface",
    "OperatorInterfaceError",
    "PendingDecision",
    "PlainTerminalInterface",
    "PromptQueue",
    "QueuedPrompt",
    "require_operator_decision",
    "RemoteMutationState",
    "RemoteCommandState",
    "RouteFallbackPrompt",
    "SecretInputAuthorizationPrompt",
    "SecretInputRecipient",
    "SshRetryPrompt",
]
