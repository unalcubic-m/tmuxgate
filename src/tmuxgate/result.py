"""Structured, binary-safe broker result messages and transparent relaying."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import json
import math
import socket
import time
from typing import Any, BinaryIO

from tmuxgate.models import (
    PREVIOUS_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
    ValidationError,
    validate_request_id,
)
from tmuxgate.protocol import ProtocolError, receive_frame, send_frame


RESULT_CHUNK_BYTES = 1024 * 1024
MAX_RESULT_STREAM_BYTES = 256 * 1024 * 1024


class TransportStatus(StrEnum):
    COMPLETE = "complete"
    DENIED = "denied"
    BROKER_BUSY = "broker_busy"
    INVALID_REQUEST = "invalid_request"
    PRE_REMOTE_FAILURE = "pre_remote_failure"
    REMOTE_SETUP_FAILURE = "remote_setup_failure"
    INCOMPLETE = "incomplete"
    COMMAND_TIMEOUT = "command_timeout"
    RESULT_COLLECTION_FAILURE = "result_collection_failure"
    INTERNAL_ERROR = "internal_error"
    RECOVERY_IN_PROGRESS = "recovery_in_progress"
    ABANDONED_AFTER_VERIFIED_REBOOT = "abandoned_after_verified_reboot"


class ResultCode(StrEnum):
    """Stable machine-readable outcomes that refine transport status."""

    RECOVERY_IN_PROGRESS = "recovery_in_progress"
    REBOOT_RECOVERY_TIMEOUT = "reboot_recovery_timeout"
    PRE_REBOOT_BOOT_ID_UNAVAILABLE = "pre_reboot_boot_id_unavailable"
    BOOT_ID_INVALID = "boot_id_invalid"
    SAME_BOOT_OBSERVED = "same_boot_observed"
    ENDPOINT_IDENTITY_MISMATCH = "endpoint_identity_mismatch"
    HOST_KEY_MISMATCH = "host_key_mismatch"
    UNSAFE_CONTROL_PATH = "unsafe_control_path"
    AMBIGUOUS_MASTER_STATE = "ambiguous_master_state"
    AUTOMATION_POLICY_DENIED = "automation_policy_denied"
    CREDENTIAL_UNAVAILABLE = "credential_unavailable"
    CREDENTIAL_PROMPT_MISMATCH = "credential_prompt_mismatch"
    UNEXPECTED_DISCONNECT = "unexpected_disconnect"
    REBOOT_PROBE_UNAVAILABLE = "reboot_probe_unavailable"
    REQUEST_BINDING_MISMATCH = "request_binding_mismatch"
    ABANDONED_AFTER_VERIFIED_REBOOT = "abandoned_after_verified_reboot"


LOCAL_EXIT_CODES: dict[TransportStatus, int] = {
    TransportStatus.DENIED: 77,
    TransportStatus.BROKER_BUSY: 75,
    TransportStatus.INVALID_REQUEST: 64,
    TransportStatus.PRE_REMOTE_FAILURE: 69,
    TransportStatus.REMOTE_SETUP_FAILURE: 70,
    TransportStatus.INCOMPLETE: 70,
    TransportStatus.COMMAND_TIMEOUT: 124,
    TransportStatus.RESULT_COLLECTION_FAILURE: 74,
    TransportStatus.INTERNAL_ERROR: 70,
    TransportStatus.RECOVERY_IN_PROGRESS: 75,
    TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT: 70,
}


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    request_id: str
    transport_status: TransportStatus
    stdout: bytes = b""
    stderr: bytes = b""
    remote_exit_status: int | None = None
    detail: str | None = None
    result_code: ResultCode | None = None

    def __post_init__(self) -> None:
        try:
            validate_request_id(self.request_id)
        except ValidationError as exc:
            raise ValueError(str(exc)) from exc
        try:
            status = TransportStatus(self.transport_status)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unsupported transport status: {self.transport_status!r}") from exc
        object.__setattr__(self, "transport_status", status)
        if not isinstance(self.stdout, (bytes, bytearray)) or not isinstance(
            self.stderr, (bytes, bytearray)
        ):
            raise ValueError("stdout and stderr must be bytes")
        object.__setattr__(self, "stdout", bytes(self.stdout))
        object.__setattr__(self, "stderr", bytes(self.stderr))
        if len(self.stdout) > MAX_RESULT_STREAM_BYTES or len(self.stderr) > MAX_RESULT_STREAM_BYTES:
            raise ValueError("result stream exceeds the configured in-memory version 1 limit")
        exit_status = self.remote_exit_status
        if status is TransportStatus.COMPLETE:
            if (
                isinstance(exit_status, bool)
                or not isinstance(exit_status, int)
                or not 0 <= exit_status <= 255
            ):
                raise ValueError("complete result requires an 8-bit remote exit status")
        elif exit_status is not None:
            raise ValueError("non-complete transport result must not invent a remote exit status")
        if self.detail is not None and (
            not isinstance(self.detail, str) or "\x00" in self.detail
        ):
            raise ValueError("result detail must be text without NUL")
        if self.result_code is not None:
            try:
                code = ResultCode(self.result_code)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"unsupported result code: {self.result_code!r}") from exc
            object.__setattr__(self, "result_code", code)
        if status is TransportStatus.COMPLETE and self.result_code is not None:
            raise ValueError("complete command result must not carry a recovery result code")
        if status is TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT:
            if self.result_code is not ResultCode.ABANDONED_AFTER_VERIFIED_REBOOT:
                raise ValueError("verified reboot abandonment requires its exact result code")
            if self.stdout or self.stderr or self.remote_exit_status is not None:
                raise ValueError("verified reboot abandonment cannot claim command output or exit")

    def transparent_exit_code(self) -> int:
        if self.transport_status is TransportStatus.COMPLETE:
            assert self.remote_exit_status is not None
            return self.remote_exit_status
        return LOCAL_EXIT_CODES[self.transport_status]

    def structured_json(self) -> bytes:
        document = {
            "detail": self.detail,
            "remote_exit_status": self.remote_exit_status,
            "request_id": self.request_id,
            "result_code": None if self.result_code is None else self.result_code.value,
            "stderr_base64": base64.b64encode(self.stderr).decode("ascii"),
            "stderr_length": len(self.stderr),
            "stderr_sha256": hashlib.sha256(self.stderr).hexdigest(),
            "stdout_base64": base64.b64encode(self.stdout).decode("ascii"),
            "stdout_length": len(self.stdout),
            "stdout_sha256": hashlib.sha256(self.stdout).hexdigest(),
            "transport_status": self.transport_status.value,
        }
        return (
            json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("utf-8")


def _result_header(result: ExecutionResult) -> dict[str, Any]:
    return {
        "detail": result.detail,
        "protocol": PROTOCOL_VERSION,
        "remote_exit_status": result.remote_exit_status,
        "request_id": result.request_id,
        "result_code": None if result.result_code is None else result.result_code.value,
        "stderr_length": len(result.stderr),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stdout_length": len(result.stdout),
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "transport_status": result.transport_status.value,
        "type": "result-start",
    }


def send_status(sock: socket.socket, request_id: str, state: str) -> None:
    validate_request_id(request_id)
    if not isinstance(state, str) or not state or "\x00" in state:
        raise ValueError("status state must be non-empty text without NUL")
    send_frame(
        sock,
        {
            "protocol": PROTOCOL_VERSION,
            "request_id": request_id,
            "state": state,
            "type": "status",
        },
    )


def _send_with_deadline(
    sock: socket.socket,
    header: dict[str, Any],
    payload: bytes = b"",
    *,
    deadline: float | None,
) -> None:
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("result write timed out")
        sock.settimeout(remaining)
    send_frame(sock, header, payload)


def _send_stream(
    sock: socket.socket,
    request_id: str,
    name: str,
    data: bytes,
    *,
    deadline: float | None,
) -> None:
    if not data:
        _send_with_deadline(
            sock,
            {
                "final": True,
                "offset": 0,
                "protocol": PROTOCOL_VERSION,
                "request_id": request_id,
                "stream": name,
                "type": "result-stream",
            },
            deadline=deadline,
        )
        return
    for offset in range(0, len(data), RESULT_CHUNK_BYTES):
        chunk = data[offset : offset + RESULT_CHUNK_BYTES]
        _send_with_deadline(
            sock,
            {
                "final": offset + len(chunk) == len(data),
                "offset": offset,
                "protocol": PROTOCOL_VERSION,
                "request_id": request_id,
                "stream": name,
                "type": "result-stream",
            },
            chunk,
            deadline=deadline,
        )


def send_result(
    sock: socket.socket,
    result: ExecutionResult,
    *,
    timeout_seconds: float | None = None,
) -> None:
    """Send a complete result under one optional absolute write deadline."""

    if timeout_seconds is not None and (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
    ):
        raise ValueError("result write timeout must be a positive finite number or None")
    deadline = (
        None if timeout_seconds is None else time.monotonic() + float(timeout_seconds)
    )
    previous_timeout = sock.gettimeout()
    try:
        _send_with_deadline(sock, _result_header(result), deadline=deadline)
        _send_stream(
            sock,
            result.request_id,
            "stdout",
            result.stdout,
            deadline=deadline,
        )
        _send_stream(
            sock,
            result.request_id,
            "stderr",
            result.stderr,
            deadline=deadline,
        )
        _send_with_deadline(
            sock,
            {
                "protocol": PROTOCOL_VERSION,
                "request_id": result.request_id,
                "type": "result-end",
            },
            deadline=deadline,
        )
    finally:
        sock.settimeout(previous_timeout)


def _require_exact_header(header: dict[str, Any], expected: set[str], name: str) -> None:
    if set(header) != expected:
        raise ProtocolError(f"{name} header fields are not exact")


def _require_protocol(value: object) -> None:
    if type(value) is not int or value not in {
        PREVIOUS_PROTOCOL_VERSION,
        PROTOCOL_VERSION,
    }:
        raise ProtocolError("result uses an unsupported protocol version")


def _receive_stream(
    sock: socket.socket,
    request_id: str,
    name: str,
    expected_length: int,
    expected_sha256: str,
) -> bytes:
    data = bytearray()
    while True:
        frame = receive_frame(sock, timeout_seconds=None)
        expected_fields = {
            "final",
            "offset",
            "protocol",
            "request_id",
            "stream",
            "type",
        }
        _require_exact_header(frame.header, expected_fields, "result stream")
        _require_protocol(frame.header["protocol"])
        if frame.header["type"] != "result-stream":
            raise ProtocolError("expected a result stream frame")
        if frame.header["request_id"] != request_id or frame.header["stream"] != name:
            raise ProtocolError("result stream identity or order mismatch")
        if type(frame.header["offset"]) is not int or frame.header["offset"] != len(data):
            raise ProtocolError("result stream offset mismatch")
        if type(frame.header["final"]) is not bool:
            raise ProtocolError("result stream final marker must be boolean")
        if len(data) + len(frame.payload) > expected_length:
            raise ProtocolError("result stream exceeds declared length")
        if not frame.payload and expected_length != 0:
            raise ProtocolError("nonempty result stream contains an empty chunk")
        data.extend(frame.payload)
        if frame.header["final"]:
            break
    if len(data) != expected_length:
        raise ProtocolError("result stream length does not match manifest")
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ProtocolError("result stream SHA-256 does not match manifest")
    return bytes(data)


def receive_result(
    sock: socket.socket,
    *,
    expected_request_id: str | None = None,
) -> ExecutionResult:
    while True:
        frame = receive_frame(sock, timeout_seconds=None)
        if frame.header.get("type") != "status":
            break
        _require_exact_header(
            frame.header,
            {"protocol", "request_id", "state", "type"},
            "status",
        )
        _require_protocol(frame.header["protocol"])
        if frame.payload:
            raise ProtocolError("status frame must not have a payload")
        if expected_request_id is not None and frame.header["request_id"] != expected_request_id:
            raise ProtocolError("status request ID mismatch")
        state = frame.header["state"]
        if not isinstance(state, str) or not state or "\x00" in state:
            raise ProtocolError("status state is invalid")

    _require_protocol(frame.header.get("protocol"))
    fields = {
        "detail",
        "protocol",
        "remote_exit_status",
        "request_id",
        "stderr_length",
        "stderr_sha256",
        "stdout_length",
        "stdout_sha256",
        "transport_status",
        "type",
    }
    if frame.header["protocol"] == PROTOCOL_VERSION:
        fields.add("result_code")
    _require_exact_header(frame.header, fields, "result start")
    if frame.header["type"] != "result-start" or frame.payload:
        raise ProtocolError("invalid result-start frame")
    request_id = frame.header["request_id"]
    try:
        validate_request_id(request_id)
    except ValidationError as exc:
        raise ProtocolError(str(exc)) from exc
    if expected_request_id is not None and request_id != expected_request_id:
        raise ProtocolError("result request ID mismatch")
    lengths: dict[str, int] = {}
    for name in ("stdout", "stderr"):
        value = frame.header[f"{name}_length"]
        if type(value) is not int or not 0 <= value <= MAX_RESULT_STREAM_BYTES:
            raise ProtocolError(f"invalid {name} length")
        digest = frame.header[f"{name}_sha256"]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ProtocolError(f"invalid {name} SHA-256")
        lengths[name] = value
    stdout = _receive_stream(
        sock,
        request_id,
        "stdout",
        lengths["stdout"],
        frame.header["stdout_sha256"],
    )
    stderr = _receive_stream(
        sock,
        request_id,
        "stderr",
        lengths["stderr"],
        frame.header["stderr_sha256"],
    )
    end = receive_frame(sock, timeout_seconds=None)
    _require_exact_header(end.header, {"protocol", "request_id", "type"}, "result end")
    _require_protocol(end.header["protocol"])
    if end.header["type"] != "result-end" or end.header["request_id"] != request_id or end.payload:
        raise ProtocolError("invalid result-end frame")
    try:
        return ExecutionResult(
            request_id=request_id,
            transport_status=frame.header["transport_status"],
            stdout=stdout,
            stderr=stderr,
            remote_exit_status=frame.header["remote_exit_status"],
            detail=frame.header["detail"],
            result_code=frame.header.get("result_code"),
        )
    except ValueError as exc:
        raise ProtocolError(f"invalid result manifest: {exc}") from exc


def relay_transparent(result: ExecutionResult, stdout: BinaryIO, stderr: BinaryIO) -> int:
    if result.stdout:
        stdout.write(result.stdout)
    if result.stderr:
        stderr.write(result.stderr)
    if result.transport_status is not TransportStatus.COMPLETE and result.detail:
        stderr.write(f"tmuxgate: {result.detail}\n".encode("utf-8", "backslashreplace"))
    stdout.flush()
    stderr.flush()
    return result.transparent_exit_code()
