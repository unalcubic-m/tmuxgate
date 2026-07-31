"""Noninteractive Unix-socket client for broker execution requests."""

from __future__ import annotations

import math
import os
from pathlib import Path
import socket

from tmuxgate.models import PROTOCOL_VERSION, RequestSpec, ValidationError, validate_request_id
from tmuxgate.protocol import ProtocolError, receive_frame, send_frame
from tmuxgate.result import ExecutionResult, receive_result
from tmuxgate.runtime import default_socket_path, require_same_uid


DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0
DEFAULT_REQUEST_SEND_TIMEOUT_SECONDS = 5.0


class BrokerConnectionError(ConnectionError):
    """The local broker could not be reached or its result was not received."""


def _positive_finite_timeout(value: object, *, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value <= 0
    ):
        raise ValueError(f"{label} must be a positive finite number")
    return float(value)


def exchange_request(
    sock: socket.socket,
    request: RequestSpec,
    *,
    send_timeout_seconds: float = DEFAULT_REQUEST_SEND_TIMEOUT_SECONDS,
) -> ExecutionResult:
    """Send exactly one request frame and wait for its structured result.

    The write side is closed immediately after the frame.  This gives the
    broker an unambiguous end-of-request marker while retaining the read side
    for status and result frames.
    """

    if not isinstance(request, RequestSpec):
        raise TypeError("request must be a RequestSpec")
    send_timeout = _positive_finite_timeout(
        send_timeout_seconds,
        label="request send timeout",
    )

    # A same-UID but wedged broker must not be able to block the client forever
    # before the request has even been accepted.  Once the complete request is
    # sent, the client deliberately returns to blocking mode: approval and an
    # approved job may legitimately take an unbounded amount of human time.
    sock.settimeout(send_timeout)
    try:
        send_frame(sock, request.to_wire_header(), request.script)
        sock.shutdown(socket.SHUT_WR)
    finally:
        sock.settimeout(None)
    # The first broker frame is a receipt that assigns the broker-generated
    # request ID.  Bind every later status and the result manifest to it.
    receipt = receive_frame(sock, timeout_seconds=None)
    expected_fields = {"protocol", "request_id", "state", "type"}
    if (
        set(receipt.header) != expected_fields
        or receipt.header.get("type") != "status"
        or type(receipt.header.get("protocol")) is not int
        or receipt.header.get("protocol") != PROTOCOL_VERSION
        or receipt.payload
    ):
        raise ProtocolError("broker did not send a valid first status receipt")
    try:
        request_id = validate_request_id(receipt.header["request_id"])
    except ValidationError as exc:
        raise ProtocolError(str(exc)) from exc
    state = receipt.header["state"]
    if not isinstance(state, str) or not state or "\x00" in state:
        raise ProtocolError("broker first status state is invalid")
    return receive_result(sock, expected_request_id=request_id)


def submit_request(
    request: RequestSpec,
    *,
    socket_path: os.PathLike[str] | str | None = None,
    connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
    request_send_timeout_seconds: float = DEFAULT_REQUEST_SEND_TIMEOUT_SECONDS,
    broker_peer_validator=require_same_uid,
) -> ExecutionResult:
    """Connect to the local broker, submit one request, and block for result."""

    if not isinstance(request, RequestSpec):
        raise TypeError("request must be a RequestSpec")
    if not callable(broker_peer_validator):
        raise TypeError("broker peer validator must be callable")
    connect_timeout = _positive_finite_timeout(
        connect_timeout_seconds,
        label="connect timeout",
    )
    request_send_timeout = _positive_finite_timeout(
        request_send_timeout_seconds,
        label="request send timeout",
    )
    path = default_socket_path() if socket_path is None else Path(socket_path)
    if not path.is_absolute():
        raise ValueError("broker socket path must be absolute")

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(connect_timeout)
        try:
            client.connect(os.fspath(path))
        except OSError as exc:
            raise BrokerConnectionError(f"cannot connect to broker socket {path}: {exc}") from exc
        try:
            # Validate the process at the other end before sending request data.
            broker_peer_validator(client)
        except Exception as exc:
            raise BrokerConnectionError("broker socket peer UID validation failed") from exc
        try:
            return exchange_request(
                client,
                request,
                send_timeout_seconds=request_send_timeout,
            )
        except OSError as exc:
            raise BrokerConnectionError(f"broker connection failed: {exc}") from exc
    finally:
        client.close()
