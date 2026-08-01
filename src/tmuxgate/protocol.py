"""Length-prefixed JSON-header plus raw-payload Unix-socket protocol."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import socket
import struct
import time
from typing import Any, Mapping


MAGIC = b"TMXGATE1"
PREFIX = struct.Struct("!8sIQ")
MAX_HEADER_BYTES = 256 * 1024
MAX_FRAME_PAYLOAD_BYTES = 16 * 1024 * 1024
DEFAULT_FRAME_TIMEOUT_SECONDS = 10.0


class ProtocolError(ValueError):
    """A peer sent a malformed or disallowed frame."""


@dataclass(frozen=True, slots=True)
class Frame:
    header: dict[str, Any]
    payload: bytes


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _encode_header(header: Mapping[str, Any]) -> bytes:
    if not isinstance(header, Mapping):
        raise ProtocolError("frame header must be a mapping")
    try:
        encoded = json.dumps(
            dict(header),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError(f"frame header is not valid JSON data: {exc}") from exc
    if not encoded or len(encoded) > MAX_HEADER_BYTES:
        raise ProtocolError("frame header length is outside the allowed range")
    return encoded


def encoded_header_size(header: Mapping[str, Any]) -> int:
    """Validate a frame header and return its exact encoded byte length."""

    return len(_encode_header(header))


def encode_frame(header: Mapping[str, Any], payload: bytes = b"") -> bytes:
    if not isinstance(payload, (bytes, bytearray)):
        raise ProtocolError("frame payload must be bytes")
    raw_payload = bytes(payload)
    if len(raw_payload) > MAX_FRAME_PAYLOAD_BYTES:
        raise ProtocolError("frame payload exceeds the allowed size")
    raw_header = _encode_header(header)
    return PREFIX.pack(MAGIC, len(raw_header), len(raw_payload)) + raw_header + raw_payload


def _decode_parts(raw_header: bytes, payload: bytes) -> Frame:
    def reject_constant(value: str) -> None:
        raise ProtocolError(f"nonstandard JSON constant is not allowed: {value}")

    try:
        header = json.loads(
            raw_header.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except ProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ProtocolError(f"invalid JSON header: {exc}") from exc
    if not isinstance(header, dict):
        raise ProtocolError("frame JSON header must be an object")
    return Frame(header=header, payload=payload)


def decode_frame(data: bytes) -> Frame:
    if len(data) < PREFIX.size:
        raise ProtocolError("truncated frame prefix")
    magic, header_length, payload_length = PREFIX.unpack_from(data)
    if magic != MAGIC:
        raise ProtocolError("invalid frame magic")
    _validate_lengths(header_length, payload_length)
    total_length = PREFIX.size + header_length + payload_length
    if len(data) != total_length:
        raise ProtocolError("frame has truncated or trailing bytes")
    header_start = PREFIX.size
    payload_start = header_start + header_length
    return _decode_parts(data[header_start:payload_start], data[payload_start:])


def _validate_lengths(header_length: int, payload_length: int) -> None:
    if not 1 <= header_length <= MAX_HEADER_BYTES:
        raise ProtocolError("frame header length is outside the allowed range")
    if payload_length > MAX_FRAME_PAYLOAD_BYTES:
        raise ProtocolError("frame payload length exceeds the allowed range")


def _remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProtocolError("frame read timed out")
    return remaining


def _validated_timeout(
    value: object,
    *,
    allow_none: bool,
) -> float | None:
    if value is None and allow_none:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value <= 0
    ):
        raise ProtocolError("frame timeout must be a positive finite number")
    return float(value)


def _recv_exact(
    sock: socket.socket,
    length: int,
    *,
    deadline: float | None,
) -> bytes:
    data = bytearray(length)
    view = memoryview(data)
    offset = 0
    while offset < length:
        if deadline is not None:
            sock.settimeout(_remaining(deadline))
        received = sock.recv_into(view[offset:])
        if received == 0:
            raise ProtocolError("peer closed connection during frame")
        offset += received
    return bytes(data)


def _receive_frame_with_deadline(
    sock: socket.socket,
    deadline: float | None,
) -> Frame:
    prefix = _recv_exact(sock, PREFIX.size, deadline=deadline)
    magic, header_length, payload_length = PREFIX.unpack(prefix)
    if magic != MAGIC:
        raise ProtocolError("invalid frame magic")
    _validate_lengths(header_length, payload_length)
    raw_header = _recv_exact(sock, header_length, deadline=deadline)
    payload = _recv_exact(sock, payload_length, deadline=deadline)
    return _decode_parts(raw_header, payload)


def receive_frame(
    sock: socket.socket,
    *,
    timeout_seconds: float | None = DEFAULT_FRAME_TIMEOUT_SECONDS,
) -> Frame:
    timeout = _validated_timeout(timeout_seconds, allow_none=True)
    previous_timeout = sock.gettimeout()
    deadline = (
        None
        if timeout is None
        else time.monotonic() + timeout
    )
    if deadline is None:
        sock.settimeout(None)
    try:
        return _receive_frame_with_deadline(sock, deadline)
    except TimeoutError as exc:
        raise ProtocolError("frame read timed out") from exc
    finally:
        sock.settimeout(previous_timeout)


def receive_single_request(
    sock: socket.socket,
    *,
    timeout_seconds: float = DEFAULT_FRAME_TIMEOUT_SECONDS,
) -> Frame:
    """Receive the sole client-to-broker frame and require write-side EOF.

    Clients must call ``shutdown(SHUT_WR)`` after their request. The broker may
    then send multiple response frames in the opposite direction.
    """

    timeout = _validated_timeout(timeout_seconds, allow_none=False)
    assert timeout is not None
    previous_timeout = sock.gettimeout()
    deadline = time.monotonic() + timeout
    try:
        frame = _receive_frame_with_deadline(sock, deadline)
        sock.settimeout(_remaining(deadline))
        trailing = sock.recv(1)
    except TimeoutError as exc:
        raise ProtocolError("client did not finish its single request") from exc
    finally:
        sock.settimeout(previous_timeout)
    if trailing:
        raise ProtocolError("client sent more than one request frame")
    return frame


def send_frame(sock: socket.socket, header: Mapping[str, Any], payload: bytes = b"") -> None:
    sock.sendall(encode_frame(header, payload))
