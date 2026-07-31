"""Validated client request models.

The client never supplies request IDs, endpoint addresses, or SSH options.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import base64
import binascii
from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import json
import os
import re
import secrets
from typing import Any


PROTOCOL_VERSION = 2
MAX_SCRIPT_BYTES = 16 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 7 * 24 * 60 * 60
MAX_PURPOSE_CHARACTERS = 500

_ALIAS_RE = re.compile(r"[a-z][a-z0-9-]{0,62}\Z", re.ASCII)
_ENVIRONMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z", re.ASCII)
_REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)


class ValidationError(ValueError):
    """Untrusted request data failed validation."""


class ExecutionMode(StrEnum):
    ARGV = "exec"
    SCRIPT = "script"


class ResultFormat(StrEnum):
    TRANSPARENT = "transparent"
    JSON = "json"


def validate_alias(value: object, *, field_name: str = "machine alias") -> str:
    if not isinstance(value, str) or _ALIAS_RE.fullmatch(value) is None:
        raise ValidationError(
            f"{field_name} must match {_ALIAS_RE.pattern!r}; got {value!r}"
        )
    return value


def validate_request_id(value: object) -> str:
    if not isinstance(value, str) or _REQUEST_ID_RE.fullmatch(value) is None:
        raise ValidationError("request ID must be exactly 32 lowercase hex characters")
    return value


def new_request_id() -> str:
    return secrets.token_hex(16)


def _validate_string(value: object, *, field_name: str, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string")
    if not allow_empty and not value:
        raise ValidationError(f"{field_name} must not be empty")
    if "\x00" in value:
        raise ValidationError(f"{field_name} must not contain NUL")
    try:
        encoded = os.fsencode(value)
    except UnicodeEncodeError as exc:
        raise ValidationError(
            f"{field_name} cannot be represented as local filesystem bytes"
        ) from exc
    if b"\x00" in encoded:
        raise ValidationError(f"{field_name} must not contain NUL")
    return value


def _encode_filesystem_text(value: str) -> str:
    return base64.b64encode(os.fsencode(value)).decode("ascii")


def _decode_filesystem_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be base64 text")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValidationError(f"{field_name} is not valid base64") from exc
    return _validate_string(os.fsdecode(raw), field_name=field_name)


def _normalize_environment(
    value: Mapping[str, str] | Sequence[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    items = tuple(value.items()) if isinstance(value, Mapping) else tuple(value)
    normalized: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise ValidationError("environment entries must be key/value pairs")
        raw_key, raw_value = item
        if not isinstance(raw_key, str) or _ENVIRONMENT_RE.fullmatch(raw_key) is None:
            raise ValidationError(f"invalid environment variable name: {raw_key!r}")
        if raw_key in seen:
            raise ValidationError(f"duplicate environment variable: {raw_key}")
        seen.add(raw_key)
        normalized.append(
            (raw_key, _validate_string(raw_value, field_name=f"environment {raw_key}"))
        )
    normalized.sort(key=lambda pair: pair[0])
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class RequestSpec:
    """Exact execution request as accepted from a noninteractive client."""

    machine_alias: str
    mode: ExecutionMode
    cwd: str
    argv: tuple[str, ...] = ()
    script: bytes = b""
    environment: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    timeout_seconds: int | None = None
    result_format: ResultFormat = ResultFormat.TRANSPARENT
    purpose: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "machine_alias", validate_alias(self.machine_alias))
        try:
            mode = ExecutionMode(self.mode)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"unsupported execution mode: {self.mode!r}") from exc
        object.__setattr__(self, "mode", mode)

        cwd = _validate_string(self.cwd, field_name="cwd", allow_empty=False)
        if not cwd.startswith("/"):
            raise ValidationError("remote cwd must be an absolute POSIX path")
        object.__setattr__(self, "cwd", cwd)

        if isinstance(self.argv, (str, bytes)):
            raise ValidationError("argv must be a sequence of strings")
        argv = tuple(
            _validate_string(argument, field_name=f"argv[{index}]")
            for index, argument in enumerate(self.argv)
        )
        object.__setattr__(self, "argv", argv)

        if not isinstance(self.script, (bytes, bytearray)):
            raise ValidationError("script payload must be bytes")
        script = bytes(self.script)
        if len(script) > MAX_SCRIPT_BYTES:
            raise ValidationError(f"script exceeds {MAX_SCRIPT_BYTES} bytes")
        object.__setattr__(self, "script", script)

        environment = _normalize_environment(self.environment)
        object.__setattr__(self, "environment", environment)

        timeout = self.timeout_seconds
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, int):
                raise ValidationError("timeout must be an integer number of seconds")
            if not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
                raise ValidationError(
                    f"timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds"
                )

        try:
            result_format = ResultFormat(self.result_format)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"unsupported result format: {self.result_format!r}") from exc
        object.__setattr__(self, "result_format", result_format)

        purpose = self.purpose
        if purpose is not None:
            if not isinstance(purpose, str) or not purpose:
                raise ValidationError("purpose must be non-empty text or omitted")
            if len(purpose) > MAX_PURPOSE_CHARACTERS:
                raise ValidationError(
                    f"purpose exceeds {MAX_PURPOSE_CHARACTERS} characters"
                )
            if any(ord(character) < 0x20 or ord(character) == 0x7F for character in purpose):
                raise ValidationError("purpose must be one line without control characters")

        if mode is ExecutionMode.ARGV:
            if not argv:
                raise ValidationError("exec mode requires at least one argv element")
            if script:
                raise ValidationError("exec mode must not include a script payload")
        elif argv:
            raise ValidationError("script mode must not include argv")

    def to_wire_header(self) -> dict[str, Any]:
        return {
            "argv_b64": [_encode_filesystem_text(item) for item in self.argv],
            "cwd_b64": _encode_filesystem_text(self.cwd),
            "environment_b64": [
                {"name": name, "value_b64": _encode_filesystem_text(value)}
                for name, value in self.environment
            ],
            "machine": self.machine_alias,
            "mode": self.mode.value,
            "protocol": PROTOCOL_VERSION,
            "purpose": self.purpose,
            "result_format": self.result_format.value,
            "timeout_seconds": self.timeout_seconds,
            "type": "execute",
        }

    @classmethod
    def from_wire(cls, header: Mapping[str, Any], payload: bytes) -> "RequestSpec":
        expected = {
            "argv_b64",
            "cwd_b64",
            "environment_b64",
            "machine",
            "mode",
            "protocol",
            "purpose",
            "result_format",
            "timeout_seconds",
            "type",
        }
        unknown = set(header) - expected
        missing = expected - set(header)
        if unknown:
            raise ValidationError(f"unknown request fields: {', '.join(sorted(unknown))}")
        if missing:
            raise ValidationError(f"missing request fields: {', '.join(sorted(missing))}")
        if type(header["protocol"]) is not int or header["protocol"] != PROTOCOL_VERSION:
            raise ValidationError("unsupported request protocol version")
        if header["type"] != "execute":
            raise ValidationError("unsupported request type")
        if not isinstance(header["argv_b64"], list):
            raise ValidationError("argv_b64 must be a JSON array")
        if not isinstance(header["environment_b64"], list):
            raise ValidationError("environment_b64 must be a JSON array")
        environment: list[tuple[str, str]] = []
        for index, entry in enumerate(header["environment_b64"]):
            if not isinstance(entry, dict) or set(entry) != {"name", "value_b64"}:
                raise ValidationError(
                    f"environment_b64[{index}] must contain only name and value_b64"
                )
            environment.append(
                (
                    entry["name"],
                    _decode_filesystem_text(
                        entry["value_b64"],
                        field_name=f"environment_b64[{index}].value_b64",
                    ),
                )
            )
        return cls(
            machine_alias=header["machine"],
            mode=header["mode"],
            cwd=_decode_filesystem_text(header["cwd_b64"], field_name="cwd_b64"),
            argv=tuple(
                _decode_filesystem_text(value, field_name=f"argv_b64[{index}]")
                for index, value in enumerate(header["argv_b64"])
            ),
            script=payload,
            environment=environment,
            timeout_seconds=header["timeout_seconds"],
            result_format=header["result_format"],
            purpose=header["purpose"],
        )

    @property
    def script_byte_length(self) -> int:
        return len(self.script)

    def client_request_sha256(self) -> str:
        header = json.dumps(
            self.to_wire_header(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256()
        digest.update(b"tmuxgate-client-request-v1\x00")
        digest.update(len(header).to_bytes(8, "big"))
        digest.update(header)
        digest.update(len(self.script).to_bytes(8, "big"))
        digest.update(self.script)
        return digest.hexdigest()
