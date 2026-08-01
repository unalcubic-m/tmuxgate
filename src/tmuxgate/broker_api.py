"""Typed, read-only broker control requests and verified-result queries."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
import base64
import json
import re
from typing import Any, Protocol, TypeAlias

from tmuxgate.models import PROTOCOL_VERSION, ValidationError, validate_alias, validate_request_id
from tmuxgate.protocol import Frame, ProtocolError
from tmuxgate.scheduler import ApprovalDecision, RequestState
from tmuxgate.spool import (
    MAX_VERIFIED_RANGE_BYTES,
    ResultSpool,
    SpoolError,
    SpoolRangeError,
    SpoolStateMismatchError,
)
from tmuxgate.state import DurableJobRecord, DurableStateStore, StateError


DEFAULT_JOB_PAGE_SIZE = 50
MAX_JOB_PAGE_SIZE = 100
DEFAULT_RESULT_CHUNK_BYTES = 64 * 1024
MAX_RESULT_CHUNK_BYTES = MAX_VERIFIED_RANGE_BYTES
MAX_CURSOR_BYTES = 1024

CONTROL_REQUEST_TYPES = frozenset(
    {"list_machines", "list_jobs", "read_verified_result"}
)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ERROR_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)


class ResultStream(StrEnum):
    STDOUT = "stdout"
    STDERR = "stderr"


class BrokerControlError(RuntimeError):
    """A control request was invalid or could not be answered safely."""

    def __init__(self, code: str, detail: str) -> None:
        if not isinstance(code, str) or _ERROR_CODE_RE.fullmatch(code) is None:
            raise ValueError("control error code is invalid")
        if (
            not isinstance(detail, str)
            or not detail
            or "\x00" in detail
            or len(detail) > 4096
        ):
            raise ValueError("control error detail is invalid")
        self.code = code
        self.detail = detail
        super().__init__(detail)


def _exact_header(
    header: Mapping[str, Any],
    expected: set[str],
    *,
    label: str,
) -> None:
    unknown = set(header) - expected
    missing = expected - set(header)
    if unknown:
        raise ProtocolError(f"unknown {label} fields: {', '.join(sorted(unknown))}")
    if missing:
        raise ProtocolError(f"missing {label} fields: {', '.join(sorted(missing))}")
    if type(header["protocol"]) is not int or header["protocol"] != PROTOCOL_VERSION:
        raise ProtocolError("unsupported control protocol version")


def _empty_payload(payload: bytes) -> None:
    if payload:
        raise ProtocolError("control request payload must be empty")


def _text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or "\x00" in value
    ):
        suffix = "text without NUL" if allow_empty else "non-empty text without NUL"
        raise ProtocolError(f"{label} must be {suffix}")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProtocolError(f"{label} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True, slots=True)
class MachineSummary:
    alias: str
    description: str

    def __post_init__(self) -> None:
        try:
            alias = validate_alias(self.alias, field_name="machine alias")
        except ValidationError as exc:
            raise ValueError(str(exc)) from exc
        if not isinstance(self.description, str) or "\x00" in self.description:
            raise ValueError("machine description must be text without NUL")
        object.__setattr__(self, "alias", alias)

    def to_wire(self) -> dict[str, object]:
        return {"alias": self.alias, "description": self.description}

    @classmethod
    def from_wire(cls, value: object) -> "MachineSummary":
        if not isinstance(value, dict) or set(value) != {"alias", "description"}:
            raise ProtocolError("machine summary fields are not exactly recognized")
        try:
            return cls(value["alias"], value["description"])
        except (TypeError, ValueError) as exc:
            raise ProtocolError(str(exc)) from exc


@dataclass(frozen=True, slots=True)
class ListMachinesRequest:
    def to_wire_header(self) -> dict[str, object]:
        return {"protocol": PROTOCOL_VERSION, "type": "list_machines"}


@dataclass(frozen=True, slots=True)
class ListJobsRequest:
    states: tuple[RequestState, ...] = ()
    limit: int = DEFAULT_JOB_PAGE_SIZE
    cursor: str | None = None

    def __post_init__(self) -> None:
        try:
            states = tuple(RequestState(item) for item in self.states)
        except (TypeError, ValueError) as exc:
            raise ValueError("job states contain an unsupported state") from exc
        if len(states) != len(set(states)):
            raise ValueError("job states must not contain duplicates")
        if type(self.limit) is not int or not 1 <= self.limit <= MAX_JOB_PAGE_SIZE:
            raise ValueError(f"job limit must be between 1 and {MAX_JOB_PAGE_SIZE}")
        if self.cursor is not None and (
            not isinstance(self.cursor, str)
            or not self.cursor
            or len(self.cursor.encode("utf-8")) > MAX_CURSOR_BYTES
            or "\x00" in self.cursor
        ):
            raise ValueError("job cursor is invalid")
        object.__setattr__(self, "states", states)

    def to_wire_header(self) -> dict[str, object]:
        return {
            "cursor": self.cursor,
            "limit": self.limit,
            "protocol": PROTOCOL_VERSION,
            "states": [state.value for state in self.states],
            "type": "list_jobs",
        }


@dataclass(frozen=True, slots=True)
class ReadVerifiedResultRequest:
    request_id: str
    stream: ResultStream
    offset: int = 0
    limit: int = DEFAULT_RESULT_CHUNK_BYTES

    def __post_init__(self) -> None:
        try:
            request_id = validate_request_id(self.request_id)
            stream = ResultStream(self.stream)
        except (TypeError, ValueError) as exc:
            raise ValueError(str(exc)) from exc
        if type(self.offset) is not int or self.offset < 0:
            raise ValueError("result offset must be a non-negative integer")
        if type(self.limit) is not int or not 1 <= self.limit <= MAX_RESULT_CHUNK_BYTES:
            raise ValueError(
                f"result chunk limit must be between 1 and {MAX_RESULT_CHUNK_BYTES}"
            )
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "stream", stream)

    def to_wire_header(self) -> dict[str, object]:
        return {
            "limit": self.limit,
            "offset": self.offset,
            "protocol": PROTOCOL_VERSION,
            "request_id": self.request_id,
            "stream": self.stream.value,
            "type": "read_verified_result",
        }


ControlRequest: TypeAlias = (
    ListMachinesRequest | ListJobsRequest | ReadVerifiedResultRequest
)


@dataclass(frozen=True, slots=True)
class MachineList:
    machines: tuple[MachineSummary, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.machines, tuple) or not all(
            isinstance(machine, MachineSummary) for machine in self.machines
        ):
            raise ValueError("machines must be a tuple of machine summaries")

    def to_wire(self) -> tuple[dict[str, object], bytes]:
        return (
            {
                "machines": [machine.to_wire() for machine in self.machines],
                "protocol": PROTOCOL_VERSION,
                "type": "list_machines_result",
            },
            b"",
        )


@dataclass(frozen=True, slots=True)
class JobSummary:
    request_id: str
    machine_alias: str
    state: RequestState
    created_at: str
    updated_at: str
    decision: ApprovalDecision | None
    exit_status: int | None
    start_time: str | None
    completion_time: str | None
    verified_result_available: bool
    recovery_required: bool

    def __post_init__(self) -> None:
        try:
            request_id = validate_request_id(self.request_id)
            machine_alias = validate_alias(self.machine_alias)
            state = RequestState(self.state)
            decision = None if self.decision is None else ApprovalDecision(self.decision)
        except (TypeError, ValueError) as exc:
            raise ValueError(str(exc)) from exc
        for label, value, optional in (
            ("created_at", self.created_at, False),
            ("updated_at", self.updated_at, False),
            ("start_time", self.start_time, True),
            ("completion_time", self.completion_time, True),
        ):
            if value is None and optional:
                continue
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError(f"{label} is invalid")
        if self.exit_status is not None and (
            type(self.exit_status) is not int or not 0 <= self.exit_status <= 255
        ):
            raise ValueError("exit status must be from 0 to 255")
        if type(self.verified_result_available) is not bool:
            raise ValueError("verified result availability must be boolean")
        if type(self.recovery_required) is not bool:
            raise ValueError("recovery requirement must be boolean")
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "machine_alias", machine_alias)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "decision", decision)

    @classmethod
    def from_record(cls, record: DurableJobRecord) -> "JobSummary":
        return cls(
            request_id=record.request_id,
            machine_alias=record.machine_alias,
            state=record.state,
            created_at=record.created_at,
            updated_at=record.updated_at,
            decision=record.decision,
            exit_status=record.exit_status,
            start_time=record.start_time,
            completion_time=record.completion_time,
            verified_result_available=record.local_spool_verified,
            recovery_required=(
                record.state is RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING
            ),
        )

    def to_wire(self) -> dict[str, object]:
        return {
            "completion_time": self.completion_time,
            "created_at": self.created_at,
            "decision": None if self.decision is None else self.decision.value,
            "exit_status": self.exit_status,
            "machine_alias": self.machine_alias,
            "recovery_required": self.recovery_required,
            "request_id": self.request_id,
            "start_time": self.start_time,
            "state": self.state.value,
            "updated_at": self.updated_at,
            "verified_result_available": self.verified_result_available,
        }

    @classmethod
    def from_wire(cls, value: object) -> "JobSummary":
        expected = {
            "completion_time", "created_at", "decision", "exit_status",
            "machine_alias", "recovery_required", "request_id", "start_time",
            "state", "updated_at", "verified_result_available",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ProtocolError("job summary fields are not exactly recognized")
        try:
            return cls(**value)
        except (TypeError, ValueError) as exc:
            raise ProtocolError(str(exc)) from exc


@dataclass(frozen=True, slots=True)
class JobPage:
    jobs: tuple[JobSummary, ...]
    next_cursor: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.jobs, tuple) or not all(
            isinstance(job, JobSummary) for job in self.jobs
        ):
            raise ValueError("jobs must be a tuple of job summaries")
        if self.next_cursor is not None and (
            not isinstance(self.next_cursor, str)
            or not self.next_cursor
            or len(self.next_cursor.encode("utf-8")) > MAX_CURSOR_BYTES
        ):
            raise ValueError("next cursor is invalid")

    def to_wire(self) -> tuple[dict[str, object], bytes]:
        return (
            {
                "jobs": [job.to_wire() for job in self.jobs],
                "next_cursor": self.next_cursor,
                "protocol": PROTOCOL_VERSION,
                "type": "list_jobs_result",
            },
            b"",
        )


@dataclass(frozen=True, slots=True)
class VerifiedResultChunk:
    request_id: str
    stream: ResultStream
    offset: int
    next_offset: int
    eof: bool
    total_size: int
    sha256: str
    exit_status: int
    manifest_sha256: str
    data: bytes

    def __post_init__(self) -> None:
        try:
            request_id = validate_request_id(self.request_id)
            stream = ResultStream(self.stream)
        except (TypeError, ValueError) as exc:
            raise ValueError(str(exc)) from exc
        if type(self.offset) is not int or self.offset < 0:
            raise ValueError("result offset is invalid")
        if type(self.next_offset) is not int or self.next_offset < self.offset:
            raise ValueError("result next offset is invalid")
        if type(self.total_size) is not int or self.total_size < self.next_offset:
            raise ValueError("result total size is invalid")
        if type(self.eof) is not bool or self.eof != (self.next_offset == self.total_size):
            raise ValueError("result EOF marker is invalid")
        if not isinstance(self.data, bytes) or len(self.data) != self.next_offset - self.offset:
            raise ValueError("result chunk bytes do not match its offsets")
        if len(self.data) > MAX_RESULT_CHUNK_BYTES:
            raise ValueError("result chunk exceeds the allowed size")
        if not isinstance(self.sha256, str) or _DIGEST_RE.fullmatch(self.sha256) is None:
            raise ValueError("result stream digest is invalid")
        if (
            not isinstance(self.manifest_sha256, str)
            or _DIGEST_RE.fullmatch(self.manifest_sha256) is None
        ):
            raise ValueError("result manifest digest is invalid")
        if type(self.exit_status) is not int or not 0 <= self.exit_status <= 255:
            raise ValueError("result exit status is invalid")
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "stream", stream)

    def to_wire(self) -> tuple[dict[str, object], bytes]:
        return (
            {
                "eof": self.eof,
                "exit_status": self.exit_status,
                "manifest_sha256": self.manifest_sha256,
                "next_offset": self.next_offset,
                "offset": self.offset,
                "protocol": PROTOCOL_VERSION,
                "request_id": self.request_id,
                "sha256": self.sha256,
                "stream": self.stream.value,
                "total_size": self.total_size,
                "type": "read_verified_result_result",
            },
            self.data,
        )


ControlResponse: TypeAlias = MachineList | JobPage | VerifiedResultChunk


class ControlService(Protocol):
    def handle(self, request: ControlRequest) -> ControlResponse: ...


def is_control_request_header(header: Mapping[str, Any]) -> bool:
    request_type = header.get("type")
    return isinstance(request_type, str) and request_type in CONTROL_REQUEST_TYPES


def decode_control_request(frame: Frame) -> ControlRequest:
    request_type = frame.header.get("type")
    if not isinstance(request_type, str) or request_type not in CONTROL_REQUEST_TYPES:
        raise ProtocolError("unsupported control request type")
    _empty_payload(frame.payload)
    if request_type == "list_machines":
        _exact_header(frame.header, {"protocol", "type"}, label="list_machines request")
        return ListMachinesRequest()
    if request_type == "list_jobs":
        _exact_header(
            frame.header,
            {"cursor", "limit", "protocol", "states", "type"},
            label="list_jobs request",
        )
        if not isinstance(frame.header["states"], list):
            raise ProtocolError("states must be a JSON array")
        try:
            return ListJobsRequest(
                states=tuple(frame.header["states"]),
                limit=frame.header["limit"],
                cursor=frame.header["cursor"],
            )
        except (TypeError, ValueError) as exc:
            raise ProtocolError(str(exc)) from exc
    _exact_header(
        frame.header,
        {"limit", "offset", "protocol", "request_id", "stream", "type"},
        label="read_verified_result request",
    )
    try:
        return ReadVerifiedResultRequest(
            request_id=frame.header["request_id"],
            stream=frame.header["stream"],
            offset=frame.header["offset"],
            limit=frame.header["limit"],
        )
    except (TypeError, ValueError) as exc:
        raise ProtocolError(str(exc)) from exc


def control_error_wire(error: BrokerControlError) -> tuple[dict[str, object], bytes]:
    return (
        {
            "code": error.code,
            "detail": error.detail,
            "protocol": PROTOCOL_VERSION,
            "type": "control_error",
        },
        b"",
    )


def decode_control_response(request: ControlRequest, frame: Frame) -> ControlResponse:
    response_type = frame.header.get("type")
    if response_type == "control_error":
        _exact_header(
            frame.header,
            {"code", "detail", "protocol", "type"},
            label="control error response",
        )
        _empty_payload(frame.payload)
        try:
            raise BrokerControlError(frame.header["code"], frame.header["detail"])
        except ValueError as exc:
            raise ProtocolError(str(exc)) from exc

    if isinstance(request, ListMachinesRequest):
        _exact_header(
            frame.header,
            {"machines", "protocol", "type"},
            label="list_machines response",
        )
        if response_type != "list_machines_result" or frame.payload:
            raise ProtocolError("broker sent an invalid list_machines response")
        values = frame.header["machines"]
        if not isinstance(values, list):
            raise ProtocolError("machines must be a JSON array")
        return MachineList(tuple(MachineSummary.from_wire(value) for value in values))

    if isinstance(request, ListJobsRequest):
        _exact_header(
            frame.header,
            {"jobs", "next_cursor", "protocol", "type"},
            label="list_jobs response",
        )
        if response_type != "list_jobs_result" or frame.payload:
            raise ProtocolError("broker sent an invalid list_jobs response")
        values = frame.header["jobs"]
        if not isinstance(values, list):
            raise ProtocolError("jobs must be a JSON array")
        try:
            return JobPage(
                tuple(JobSummary.from_wire(value) for value in values),
                frame.header["next_cursor"],
            )
        except ValueError as exc:
            raise ProtocolError(str(exc)) from exc

    assert isinstance(request, ReadVerifiedResultRequest)
    expected = {
        "eof", "exit_status", "manifest_sha256", "next_offset", "offset",
        "protocol", "request_id", "sha256", "stream", "total_size", "type",
    }
    _exact_header(frame.header, expected, label="read_verified_result response")
    if response_type != "read_verified_result_result":
        raise ProtocolError("broker sent an invalid read_verified_result response")
    try:
        response = VerifiedResultChunk(
            request_id=frame.header["request_id"],
            stream=frame.header["stream"],
            offset=frame.header["offset"],
            next_offset=frame.header["next_offset"],
            eof=frame.header["eof"],
            total_size=frame.header["total_size"],
            sha256=frame.header["sha256"],
            exit_status=frame.header["exit_status"],
            manifest_sha256=frame.header["manifest_sha256"],
            data=frame.payload,
        )
    except (TypeError, ValueError) as exc:
        raise ProtocolError(str(exc)) from exc
    if (
        response.request_id != request.request_id
        or response.stream is not request.stream
        or response.offset != request.offset
        or len(response.data) > request.limit
    ):
        raise ProtocolError("verified result response does not match its request")
    return response


def _cursor_for(record: DurableJobRecord) -> str:
    raw = json.dumps(
        {"created_at": record.created_at, "request_id": record.request_id, "version": 1},
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str) -> tuple[str, str]:
    try:
        raw_cursor = cursor.encode("ascii")
        padded = raw_cursor + b"=" * (-len(raw_cursor) % 4)
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
        document = json.loads(raw.decode("ascii"))
    except (UnicodeEncodeError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise BrokerControlError("invalid_cursor", "job cursor is invalid") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"created_at", "request_id", "version"}
        or type(document["version"]) is not int
        or document["version"] != 1
    ):
        raise BrokerControlError("invalid_cursor", "job cursor is invalid")
    created_at = document["created_at"]
    request_id = document["request_id"]
    if not isinstance(created_at, str) or not created_at or "\x00" in created_at:
        raise BrokerControlError("invalid_cursor", "job cursor is invalid")
    try:
        request_id = validate_request_id(request_id)
    except (TypeError, ValueError) as exc:
        raise BrokerControlError("invalid_cursor", "job cursor is invalid") from exc
    return created_at, request_id


class BrokerControlService:
    """Broker-owned, immutable machine metadata and durable read services."""

    def __init__(
        self,
        machines: Mapping[str, object] | Iterable[MachineSummary],
        state_store: DurableStateStore,
        result_spool: ResultSpool,
    ) -> None:
        summaries: list[MachineSummary] = []
        if isinstance(machines, Mapping):
            for alias, machine in machines.items():
                description = getattr(machine, "description", None)
                summaries.append(MachineSummary(alias, description))
        else:
            for machine in machines:
                if not isinstance(machine, MachineSummary):
                    raise TypeError("machines must contain MachineSummary values")
                summaries.append(machine)
        if len({machine.alias for machine in summaries}) != len(summaries):
            raise ValueError("machine summaries contain duplicate aliases")
        if not callable(getattr(state_store, "load", None)) or not callable(
            getattr(state_store, "load_all", None)
        ):
            raise TypeError("state store must support load and load_all")
        if not callable(getattr(result_spool, "read_verified_range", None)):
            raise TypeError("result spool must support verified range reads")
        self._machines = tuple(sorted(summaries, key=lambda item: item.alias))
        self._state_store = state_store
        self._result_spool = result_spool

    def handle(self, request: ControlRequest) -> ControlResponse:
        if isinstance(request, ListMachinesRequest):
            return MachineList(self._machines)
        if isinstance(request, ListJobsRequest):
            return self._list_jobs(request)
        if isinstance(request, ReadVerifiedResultRequest):
            return self._read_verified_result(request)
        raise BrokerControlError("invalid_request", "unsupported broker control request")

    def _list_jobs(self, request: ListJobsRequest) -> JobPage:
        try:
            records = self._state_store.load_all()
        except StateError as exc:
            raise BrokerControlError(
                "state_unavailable", "durable job state could not be verified"
            ) from exc
        allowed_states = frozenset(request.states)
        filtered = [
            record
            for record in records
            if not allowed_states or record.state in allowed_states
        ]
        filtered.sort(key=lambda item: (item.created_at, item.request_id), reverse=True)
        start = 0
        if request.cursor is not None:
            cursor_key = _decode_cursor(request.cursor)
            for index, record in enumerate(filtered):
                if (record.created_at, record.request_id) == cursor_key:
                    start = index + 1
                    break
            else:
                raise BrokerControlError(
                    "invalid_cursor", "job cursor does not identify a matching job"
                )
        selected = filtered[start : start + request.limit]
        has_more = start + len(selected) < len(filtered)
        next_cursor = _cursor_for(selected[-1]) if has_more and selected else None
        return JobPage(tuple(JobSummary.from_record(record) for record in selected), next_cursor)

    def _read_verified_result(
        self,
        request: ReadVerifiedResultRequest,
    ) -> VerifiedResultChunk:
        try:
            record = self._state_store.load(request.request_id)
        except FileNotFoundError as exc:
            raise BrokerControlError("not_found", "durable job was not found") from exc
        except StateError as exc:
            raise BrokerControlError(
                "state_unavailable", "durable job state could not be verified"
            ) from exc
        if (
            not record.local_spool_verified
            or record.local_spool_manifest_sha256 is None
        ):
            raise BrokerControlError(
                "result_unverified", "durable state does not verify a local result"
            )
        try:
            spooled = self._result_spool.read_verified_range(
                request.request_id,
                request.stream.value,
                offset=request.offset,
                limit=request.limit,
                expected_manifest_payload_sha256=(
                    record.local_spool_manifest_sha256
                ),
                expected_exit_status=record.exit_status,
            )
        except FileNotFoundError as exc:
            raise BrokerControlError("result_missing", "verified result spool is missing") from exc
        except SpoolRangeError as exc:
            raise BrokerControlError(
                "invalid_offset", "result offset is beyond the verified stream"
            ) from exc
        except SpoolStateMismatchError as exc:
            raise BrokerControlError(
                "result_mismatch", "durable state and result spool do not match"
            ) from exc
        except SpoolError as exc:
            raise BrokerControlError(
                "result_corrupt", "verified result spool failed integrity checks"
            ) from exc
        next_offset = request.offset + len(spooled.data)
        return VerifiedResultChunk(
            request_id=request.request_id,
            stream=request.stream,
            offset=request.offset,
            next_offset=next_offset,
            eof=next_offset == spooled.total_size,
            total_size=spooled.total_size,
            sha256=spooled.sha256,
            exit_status=spooled.exit_status,
            manifest_sha256=spooled.manifest_payload_sha256,
            data=spooled.data,
        )
