"""Local Unix-socket broker coordinator for fake and real executors."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
import math
import queue
import socket
import threading
import time
from typing import Protocol

from tmuxgate.approval import ApprovalDecision
from tmuxgate.broker_api import (
    BrokerControlError,
    ControlRequest,
    ControlService,
    control_error_wire,
    decode_control_request,
    is_control_request_header,
)
from tmuxgate.fake import FakeExecution
from tmuxgate.models import (
    DisconnectPolicy,
    RequestSpec,
    ValidationError,
    new_request_id,
    validate_alias,
)
from tmuxgate.operator_interface import ActivityKind, OperationalActivity
from tmuxgate.protocol import ProtocolError, receive_single_request, send_frame
from tmuxgate.result import ExecutionResult, TransportStatus, send_result, send_status
from tmuxgate.runtime import require_same_uid
from tmuxgate.scheduler import QueueFullError, RequestState, SequentialScheduler


DEFAULT_REQUEST_TIMEOUT_SECONDS = 10.0
DEFAULT_SEND_TIMEOUT_SECONDS = 2.0
DEFAULT_APPROVAL_HEARTBEAT_SECONDS = 0.25
DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 2.0
DEFAULT_AUDIT_CAPACITY = 4096
DEFAULT_RECENT_REQUEST_ID_CAPACITY = 4096


def _is_positive_finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return value > 0 and math.isfinite(value)
    except OverflowError:
        return False


class Approver(Protocol):
    def __call__(self, request_id: str, request: RequestSpec) -> ApprovalDecision: ...


class Executor(Protocol):
    def __call__(
        self, request_id: str, request: RequestSpec
    ) -> FakeExecution | ExecutionResult: ...


PeerValidator = Callable[[socket.socket], object]


class BrokerError(RuntimeError):
    """The local fake broker could not maintain an internal invariant."""


class ClientWriteError(BrokerError):
    """A broker response could not be delivered to its waiting client."""


@dataclass(slots=True)
class _WriteOperation:
    kind: str
    request_id: str | None = None
    state: str | None = None
    result: ExecutionResult | None = None
    control_header: dict[str, object] | None = None
    control_payload: bytes = b""
    callback: Callable[[BaseException | None], None] | None = None
    finished: threading.Event = field(default_factory=threading.Event)
    error: BaseException | None = None


class _ClientSession:
    """One request connection with exactly one socket-writing thread."""

    def __init__(
        self,
        connection: socket.socket,
        *,
        send_timeout_seconds: float,
        on_closed: Callable[["_ClientSession"], None],
    ) -> None:
        self.connection = connection
        self.connection.set_inheritable(False)
        self._send_timeout_seconds = send_timeout_seconds
        self._receipt_timeout_seconds = send_timeout_seconds + 0.5
        self._on_closed = on_closed
        self._outbound: queue.Queue[_WriteOperation | None] = queue.Queue()
        self._reader_complete = threading.Event()
        self._closing = threading.Event()
        self._closed = threading.Event()
        self._writer = threading.Thread(
            target=self._writer_loop,
            name="tmuxgate-client-writer",
            daemon=True,
        )
        self._writer.start()

    def send_status(self, request_id: str, state: str) -> None:
        self._write(_WriteOperation("status", request_id=request_id, state=state))

    def send_result(self, result: ExecutionResult) -> None:
        self._write(_WriteOperation("result", result=result))

    def send_control(self, header: dict[str, object], payload: bytes = b"") -> None:
        self._write(
            _WriteOperation(
                "control",
                control_header=header,
                control_payload=payload,
            )
        )

    def send_result_async(
        self,
        result: ExecutionResult,
        callback: Callable[[BaseException | None], None],
    ) -> None:
        if self._closing.is_set() or self._closed.is_set():
            raise ClientWriteError("client session is closed")
        self._outbound.put(_WriteOperation("result", result=result, callback=callback))

    def finish_reading(self) -> None:
        """Hand exclusive socket-timeout ownership from reader to writer."""

        self._reader_complete.set()

    def _write(self, operation: _WriteOperation) -> None:
        if self._closing.is_set() or self._closed.is_set():
            raise ClientWriteError("client session is closed")
        self._outbound.put(operation)
        if not operation.finished.wait(timeout=self._receipt_timeout_seconds):
            self.abort()
            raise ClientWriteError("timed out waiting for client write receipt")
        if operation.error is not None:
            raise ClientWriteError("client disconnected while broker was replying") from operation.error

    def _writer_loop(self) -> None:
        fatal_error: BaseException | None = None
        try:
            # socket.settimeout() is socket-wide.  The request reader must have
            # completely restored its timeout before this sole writer changes
            # it, otherwise the two threads can race and silently remove the
            # write deadline.
            self._reader_complete.wait()
            self.connection.settimeout(self._send_timeout_seconds)
            while True:
                operation = self._outbound.get()
                if operation is None:
                    return
                try:
                    if fatal_error is not None:
                        raise fatal_error
                    if operation.kind == "status":
                        assert operation.request_id is not None
                        assert operation.state is not None
                        send_status(self.connection, operation.request_id, operation.state)
                    elif operation.kind == "result":
                        assert operation.result is not None
                        send_result(
                            self.connection,
                            operation.result,
                            timeout_seconds=self._send_timeout_seconds,
                        )
                    elif operation.kind == "control":
                        assert operation.control_header is not None
                        send_frame(
                            self.connection,
                            operation.control_header,
                            operation.control_payload,
                        )
                    else:
                        raise BrokerError(f"unknown socket write operation: {operation.kind}")
                except BaseException as exc:
                    fatal_error = exc
                    operation.error = exc
                finally:
                    operation.finished.set()
                    if operation.callback is not None:
                        try:
                            operation.callback(operation.error)
                        except BaseException:
                            # The writer must never execute broker state logic.
                            # A callback may only enqueue a coordinator event.
                            pass
        finally:
            self._closed.set()
            try:
                self.connection.close()
            except OSError:
                pass
            self._on_closed(self)

    def close(self) -> None:
        if self._closing.is_set() or self._closed.is_set():
            return
        self._closing.set()
        self._reader_complete.set()
        self._outbound.put(None)

    def abort(self) -> None:
        if self._closing.is_set() or self._closed.is_set():
            return
        self._closing.set()
        self._reader_complete.set()
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._outbound.put(None)


@dataclass(frozen=True, slots=True)
class _IncomingRequest:
    session: _ClientSession
    request: RequestSpec


@dataclass(frozen=True, slots=True)
class _InvalidIncomingRequest:
    session: _ClientSession
    detail: str


@dataclass(slots=True)
class _WorkItem:
    request_id: str
    request: RequestSpec
    session: _ClientSession
    authorization: queue.Queue[bool] = field(default_factory=lambda: queue.Queue(maxsize=1))


@dataclass(frozen=True, slots=True)
class _ApprovalFinished:
    work: _WorkItem
    decision: ApprovalDecision | None
    error: BaseException | None = None


@dataclass(frozen=True, slots=True)
class _ExecutionFinished:
    work: _WorkItem
    execution: FakeExecution | ExecutionResult | None
    error: BaseException | None = None


@dataclass(frozen=True, slots=True)
class _ResultWriteFinished:
    request_id: str
    session: _ClientSession
    scheduled: bool
    retire_request_id: bool
    status_name: str
    error: BaseException | None = None


@dataclass(frozen=True, slots=True)
class _StopCoordinator:
    pass


@dataclass(slots=True)
class _Job:
    request_id: str
    request: RequestSpec
    session: _ClientSession


class BrokerServer:
    """Threaded local broker with serialized prompts and bounded executions.

    Reader threads validate and decode one request each.  A single coordinator
    owns every scheduler call.  A single terminal worker obtains decisions and
    invokes the executor.  Each client session has one writer thread; the
    coordinator waits for its write receipt before changing scheduler state.
    """

    def __init__(
        self,
        listener: socket.socket,
        *,
        allowed_machines: Iterable[str],
        machine_enabled: Callable[[str], bool] | None = None,
        approver: Approver,
        executor: Executor,
        max_pending_requests: int = 16,
        max_active_remote_commands: int = 1,
        max_client_sessions: int | None = None,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
        send_timeout_seconds: float = DEFAULT_SEND_TIMEOUT_SECONDS,
        approval_heartbeat_seconds: float = DEFAULT_APPROVAL_HEARTBEAT_SECONDS,
        shutdown_timeout_seconds: float = DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
        audit_capacity: int = DEFAULT_AUDIT_CAPACITY,
        recent_request_id_capacity: int = DEFAULT_RECENT_REQUEST_ID_CAPACITY,
        peer_validator: PeerValidator = require_same_uid,
        approval_discarder: Callable[[str], object] = lambda request_id: None,
        delivery_observer: Callable[[str, bool], object] = (
            lambda request_id, delivered: None
        ),
        control_service: ControlService | None = None,
        activity_publisher: Callable[[OperationalActivity], object] = (
            lambda event: None
        ),
        external_active_count: Callable[[], int] = lambda: 0,
    ) -> None:
        if listener.family != socket.AF_UNIX:
            raise ValueError("broker listener must be an AF_UNIX socket")
        if not all(
            callable(item)
            for item in (
                approver,
                executor,
                peer_validator,
                approval_discarder,
                delivery_observer,
                activity_publisher,
                external_active_count,
            )
        ):
            raise TypeError("broker callbacks must be callable")
        if control_service is not None and not callable(
            getattr(control_service, "handle", None)
        ):
            raise TypeError("control service must provide a callable handle method")
        if not _is_positive_finite_number(request_timeout_seconds):
            raise ValueError("request timeout must be a positive number")
        if not _is_positive_finite_number(send_timeout_seconds):
            raise ValueError("send timeout must be a positive number")
        for value, name in (
            (approval_heartbeat_seconds, "approval heartbeat"),
            (shutdown_timeout_seconds, "shutdown timeout"),
        ):
            if not _is_positive_finite_number(value):
                raise ValueError(f"{name} must be a positive number")
        for value, name in (
            (audit_capacity, "audit capacity"),
            (recent_request_id_capacity, "recent request ID capacity"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= 65536
            ):
                raise ValueError(f"{name} must be between 1 and 65536")
        if max_client_sessions is None:
            max_client_sessions = max_pending_requests + 2
        if (
            isinstance(max_client_sessions, bool)
            or not isinstance(max_client_sessions, int)
            or not 1 <= max_client_sessions <= 128
        ):
            raise ValueError("max client sessions must be between 1 and 128")
        machines = frozenset(validate_alias(item) for item in allowed_machines)
        if not machines:
            raise ValueError("at least one allowed machine is required")

        self._listener = listener
        self._allowed_machines = machines
        self._machine_enabled = (
            (lambda _machine_name: True)
            if machine_enabled is None
            else machine_enabled
        )
        if not callable(self._machine_enabled):
            raise TypeError("machine_enabled must be callable")
        self._approver = approver
        self._executor = executor
        self._peer_validator = peer_validator
        self._approval_discarder = approval_discarder
        self._delivery_observer = delivery_observer
        self._control_service = control_service
        self._activity_publisher = activity_publisher
        self._request_timeout_seconds = float(request_timeout_seconds)
        self._send_timeout_seconds = float(send_timeout_seconds)
        self._approval_heartbeat_seconds = float(approval_heartbeat_seconds)
        self._shutdown_timeout_seconds = float(shutdown_timeout_seconds)
        self._scheduler = SequentialScheduler(
            max_pending_requests,
            max_active_remote_commands=max_active_remote_commands,
            external_active_count=external_active_count,
        )
        self._events: queue.Queue[
            _IncomingRequest
            | _InvalidIncomingRequest
            | _ApprovalFinished
            | _ExecutionFinished
            | _ResultWriteFinished
            | _StopCoordinator
        ] = queue.Queue()
        self._terminal_queue: queue.Queue[_WorkItem | None] = queue.Queue()
        self._jobs: dict[str, _Job] = {}
        self._active_request_ids: set[str] = set()
        self._recent_request_ids: deque[str] = deque()
        self._recent_request_id_set: set[str] = set()
        self._recent_request_id_capacity = recent_request_id_capacity
        self._terminal_busy = False
        self._approval_work: _WorkItem | None = None
        self._started = False
        self._stopping = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._sessions: set[_ClientSession] = set()
        self._sessions_lock = threading.Lock()
        self._session_slots = threading.BoundedSemaphore(max_client_sessions)
        self._reader_threads: set[threading.Thread] = set()
        self._reader_threads_lock = threading.Lock()
        self._execution_threads: set[threading.Thread] = set()
        self._execution_threads_lock = threading.Lock()
        self._audit: deque[tuple[str, str | None]] = deque(maxlen=audit_capacity)
        self._audit_condition = threading.Condition()
        self._coordinator_thread = threading.Thread(
            target=self._coordinator_loop,
            name="tmuxgate-coordinator",
            daemon=True,
        )
        self._terminal_thread = threading.Thread(
            target=self._terminal_loop,
            name="tmuxgate-terminal-worker",
            daemon=True,
        )
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name="tmuxgate-accept",
            daemon=True,
        )

    @property
    def audit_log(self) -> tuple[tuple[str, str | None], ...]:
        with self._audit_condition:
            return tuple(self._audit)

    def wait_for_audit(self, event: str, *, timeout: float = 2.0) -> bool:
        """Wait until a named local test event has been recorded."""

        with self._audit_condition:
            return self._audit_condition.wait_for(
                lambda: any(name == event for name, _ in self._audit),
                timeout=timeout,
            )

    def start(self) -> None:
        if self._started:
            raise BrokerError("broker server has already been started")
        self._started = True
        self._listener.settimeout(0.1)
        try:
            self._coordinator_thread.start()
            self._terminal_thread.start()
            self._accept_thread.start()
        except Exception as exc:
            raise BrokerError("could not start all broker workers") from exc

    def stop(self) -> bool:
        """Request shutdown and report whether all broker workers stopped.

        Python cannot forcibly terminate an injected approver or executor.  A
        blocked callable therefore makes this method return ``False`` and adds
        ``stop-incomplete`` to the bounded audit log; it is never reported as a
        clean shutdown.  Calling ``stop`` again later retries the joins.
        """

        if not self._started:
            return True
        with self._lifecycle_lock:
            first_stop = not self._stopping.is_set()
            self._stopping.set()
        if first_stop:
            try:
                self._listener.close()
            except OSError:
                pass
            self._events.put(_StopCoordinator())
            self._terminal_queue.put(None)
        with self._sessions_lock:
            sessions = tuple(self._sessions)
        for session in sessions:
            session.abort()

        deadline = time.monotonic() + self._shutdown_timeout_seconds
        core_threads = (
            self._accept_thread,
            self._coordinator_thread,
            self._terminal_thread,
        )
        for thread in core_threads:
            # Thread.start() can fail after an earlier broker thread started.
            # An unstarted Thread cannot be joined during rollback.
            if thread.ident is not None:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        with self._reader_threads_lock:
            readers = tuple(self._reader_threads)
        for thread in readers:
            if thread.ident is not None:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
        with self._execution_threads_lock:
            executions = tuple(self._execution_threads)
        for thread in executions:
            if thread.ident is not None:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))

        with self._sessions_lock:
            sessions_remain = bool(self._sessions)
        incomplete = (
            any(thread.is_alive() for thread in core_threads)
            or any(thread.is_alive() for thread in readers)
            or any(thread.is_alive() for thread in executions)
            or sessions_remain
        )
        if incomplete:
            self._record("stop-incomplete")
        return not incomplete

    def _record(self, name: str, request_id: str | None = None) -> None:
        with self._audit_condition:
            self._audit.append((name, request_id))
            self._audit_condition.notify_all()
        try:
            self._activity_publisher(
                OperationalActivity.create(
                    ActivityKind.BROKER_AUDIT,
                    name,
                    request_id=request_id,
                )
            )
        except BaseException:
            # Reporting cannot alter the authoritative broker transition that
            # was already appended to the bounded audit above.
            pass

    def _accept_loop(self) -> None:
        while not self._stopping.is_set():
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stopping.is_set():
                    return
                continue

            # This must be the first operation on client-controlled data.  No
            # frame byte is read and no response writer is started beforehand.
            try:
                self._peer_validator(connection)
            except BaseException:
                self._record("peer-rejected")
                connection.close()
                continue

            if not self._session_slots.acquire(blocking=False):
                self._record("session-limit-rejected")
                connection.close()
                continue
            session = _ClientSession(
                connection,
                send_timeout_seconds=self._send_timeout_seconds,
                on_closed=self._session_closed,
            )
            with self._sessions_lock:
                self._sessions.add(session)
            reader = threading.Thread(
                target=self._read_one_request,
                args=(session,),
                name="tmuxgate-client-reader",
                daemon=True,
            )
            with self._reader_threads_lock:
                self._reader_threads.add(reader)
            reader.start()

    def _session_closed(self, session: _ClientSession) -> None:
        with self._sessions_lock:
            removed = session in self._sessions
            self._sessions.discard(session)
        if removed:
            self._session_slots.release()

    def _read_one_request(self, session: _ClientSession) -> None:
        event: _IncomingRequest | _InvalidIncomingRequest | None = None
        control_request: ControlRequest | None = None
        control_error: BrokerControlError | None = None
        try:
            frame = receive_single_request(
                session.connection,
                timeout_seconds=self._request_timeout_seconds,
            )
            if is_control_request_header(frame.header):
                try:
                    control_request = decode_control_request(frame)
                except (ProtocolError, ValidationError, ValueError) as exc:
                    detail = f"invalid control request: {exc}"
                    control_error = BrokerControlError(
                        "invalid_request",
                        detail[:4096],
                    )
            else:
                request = RequestSpec.from_wire(frame.header, frame.payload)
                event = _IncomingRequest(session, request)
        except (ProtocolError, ValidationError, OSError, ValueError) as exc:
            event = _InvalidIncomingRequest(session, str(exc))
        except BaseException:
            # Unexpected reader faults still fail closed without disclosing
            # process internals to the untrusted client.
            event = _InvalidIncomingRequest(session, "internal request reader failure")
        finally:
            # The event must not become visible to the coordinator until the
            # reader has restored the socket timeout and handed ownership to
            # the sole writer.
            session.finish_reading()
        try:
            if control_request is not None or control_error is not None:
                self._handle_control_request(
                    session,
                    control_request,
                    error=control_error,
                )
            else:
                assert event is not None
                self._events.put(event)
        finally:
            current = threading.current_thread()
            with self._reader_threads_lock:
                self._reader_threads.discard(current)

    def _handle_control_request(
        self,
        session: _ClientSession,
        request: ControlRequest | None,
        *,
        error: BrokerControlError | None,
    ) -> None:
        response_error = error
        response_wire: tuple[dict[str, object], bytes] | None = None
        if response_error is None:
            if self._control_service is None:
                response_error = BrokerControlError(
                    "unavailable",
                    "broker control service is unavailable",
                )
            else:
                assert request is not None
                try:
                    response = self._control_service.handle(request)
                    response_wire = response.to_wire()
                except BrokerControlError as exc:
                    response_error = exc
                except BaseException:
                    self._record("control-error")
                    response_error = BrokerControlError(
                        "internal_error",
                        "broker control request failed closed",
                    )
        if response_error is not None:
            response_wire = control_error_wire(response_error)
        assert response_wire is not None
        try:
            session.send_control(*response_wire)
        except ClientWriteError:
            self._record("control-client-disconnected")
            session.abort()
            return
        self._record("control-result")
        session.close()

    def _terminal_loop(self) -> None:
        while True:
            work = self._terminal_queue.get()
            if work is None:
                return
            try:
                decision = ApprovalDecision(self._approver(work.request_id, work.request))
            except BaseException as exc:
                approval_event = _ApprovalFinished(work, None, exc)
            else:
                approval_event = _ApprovalFinished(work, decision)
            if self._stopping.is_set():
                return
            self._events.put(approval_event)

            while not self._stopping.is_set():
                try:
                    authorized = work.authorization.get(timeout=0.1)
                    break
                except queue.Empty:
                    continue
            else:
                return
            if not authorized:
                continue

            self._start_execution(work)

    def _start_execution(self, work: _WorkItem) -> None:
        def execute() -> None:
            try:
                execution = self._executor(work.request_id, work.request)
                if not isinstance(execution, (FakeExecution, ExecutionResult)):
                    raise TypeError("executor returned an invalid result")
                if (
                    isinstance(execution, ExecutionResult)
                    and execution.request_id != work.request_id
                ):
                    raise TypeError("executor result belongs to another request")
            except BaseException as exc:
                event = _ExecutionFinished(work, None, exc)
            else:
                event = _ExecutionFinished(work, execution)
            finally:
                current = threading.current_thread()
                with self._execution_threads_lock:
                    self._execution_threads.discard(current)
            if not self._stopping.is_set():
                self._events.put(event)

        # This lock provides a linearization point with stop(): execution is
        # either committed before shutdown begins, or it cannot start.
        with self._lifecycle_lock:
            if self._stopping.is_set():
                return
            thread = threading.Thread(
                target=execute,
                name=f"tmuxgate-execution-{work.request_id[:8]}",
                daemon=True,
            )
            with self._execution_threads_lock:
                self._execution_threads.add(thread)
            thread.start()

    def _coordinator_loop(self) -> None:
        while True:
            try:
                if self._approval_work is None:
                    event = self._events.get()
                else:
                    event = self._events.get(
                        timeout=self._approval_heartbeat_seconds
                    )
            except queue.Empty:
                try:
                    self._probe_active_approval()
                except BaseException:
                    self._record("coordinator-error")
                    self._terminal_busy = True
                continue
            if isinstance(event, _StopCoordinator):
                return
            try:
                if isinstance(event, _IncomingRequest):
                    self._handle_incoming(event)
                elif isinstance(event, _InvalidIncomingRequest):
                    self._handle_invalid(event)
                elif isinstance(event, _ApprovalFinished):
                    self._handle_approval(event)
                elif isinstance(event, _ExecutionFinished):
                    self._handle_execution(event)
                elif isinstance(event, _ResultWriteFinished):
                    self._handle_result_write_finished(event)
                else:
                    raise BrokerError("unknown coordinator event")
                self._start_next_if_possible()
            except BaseException:
                # A coordinator failure is visible in tests and fails closed:
                # no second approval can begin after an uncertain transition.
                self._record("coordinator-error")
                self._terminal_busy = True

    def _allocate_request_id(self) -> str:
        # Random collisions are already extraordinarily unlikely, but request
        # identity is a protocol binding and therefore must be deterministic.
        for _ in range(128):
            request_id = new_request_id()
            if (
                request_id not in self._active_request_ids
                and request_id not in self._recent_request_id_set
            ):
                self._active_request_ids.add(request_id)
                return request_id
        raise BrokerError("unable to allocate a unique request ID")

    def _retire_request_id(self, request_id: str) -> None:
        """Move a completed active ID into bounded collision history."""

        self._active_request_ids.discard(request_id)
        if request_id in self._recent_request_id_set:
            return
        self._recent_request_ids.append(request_id)
        self._recent_request_id_set.add(request_id)
        while len(self._recent_request_ids) > self._recent_request_id_capacity:
            expired = self._recent_request_ids.popleft()
            self._recent_request_id_set.remove(expired)

    def _forget_cancelled(self, request_id: str) -> None:
        self._jobs.pop(request_id, None)
        self._scheduler.forget_terminal(request_id)
        self._retire_request_id(request_id)

    def _finish_scheduled_result(self, request_id: str) -> None:
        self._scheduler.finish_result_delivery(request_id)
        self._scheduler.forget_terminal(request_id)
        self._jobs.pop(request_id, None)
        self._retire_request_id(request_id)

    def _handle_incoming(self, event: _IncomingRequest) -> None:
        request_id = self._allocate_request_id()
        if event.request.machine_alias not in self._allowed_machines:
            self._deliver_unscheduled(
                event.session,
                ExecutionResult(
                    request_id,
                    TransportStatus.INVALID_REQUEST,
                    detail=f"unknown configured machine: {event.request.machine_alias}",
                ),
                "unknown-machine",
            )
            return
        try:
            enabled = self._machine_enabled(event.request.machine_alias)
        except BaseException:
            enabled = None
        if type(enabled) is not bool or not enabled:
            detail = (
                f"configured machine is disabled: {event.request.machine_alias}"
                if enabled is False
                else "machine availability could not be verified"
            )
            self._deliver_unscheduled(
                event.session,
                ExecutionResult(
                    request_id,
                    TransportStatus.INVALID_REQUEST,
                    detail=detail,
                ),
                "disabled-machine",
            )
            return

        try:
            self._scheduler.submit(request_id, event.request.machine_alias)
        except QueueFullError:
            self._deliver_unscheduled(
                event.session,
                ExecutionResult(
                    request_id,
                    TransportStatus.BROKER_BUSY,
                    detail="pending request queue is full",
                ),
                "queue-full",
            )
            return

        job = _Job(request_id, event.request, event.session)
        self._jobs[request_id] = job
        try:
            event.session.send_status(request_id, "queued")
        except ClientWriteError:
            self._scheduler.client_disconnected(request_id)
            event.session.close()
            self._record("queued-client-disconnected", request_id)
            self._forget_cancelled(request_id)
            return
        self._record("queued", request_id)

    def _handle_invalid(self, event: _InvalidIncomingRequest) -> None:
        request_id = self._allocate_request_id()
        self._deliver_unscheduled(
            event.session,
            ExecutionResult(
                request_id,
                TransportStatus.INVALID_REQUEST,
                detail=f"invalid request: {event.detail}",
            ),
            "invalid-request",
        )

    def _deliver_unscheduled(
        self,
        session: _ClientSession,
        result: ExecutionResult,
        status: str,
    ) -> None:
        try:
            session.send_status(result.request_id, status)
        except ClientWriteError:
            self._record(f"{status}-client-disconnected", result.request_id)
            session.abort()
            self._retire_request_id(result.request_id)
            return
        self._record(status, result.request_id)
        self._queue_result_write(
            session,
            result,
            scheduled=False,
            retire_request_id=True,
            status_name=status,
        )

    def _start_next_if_possible(self) -> None:
        while (
            not self._stopping.is_set()
            and not self._terminal_busy
            and self._scheduler.can_begin_approval
        ):
            request_id = self._scheduler.pending_request_ids[0]
            job = self._jobs[request_id]
            try:
                # A receipt from the sole session writer proves this frame was
                # written before begin_next_approval acquires the lease.
                job.session.send_status(request_id, "next-for-approval")
            except ClientWriteError:
                self._scheduler.client_disconnected(request_id)
                job.session.close()
                self._record("preapproval-client-disconnected", request_id)
                self._forget_cancelled(request_id)
                continue
            self._record("preapproval-status-written", request_id)
            selected = self._scheduler.begin_next_approval()
            if selected is None or selected.request_id != request_id:
                raise BrokerError("scheduler selected a non-FIFO request")
            self._record("approval-begun", request_id)
            self._terminal_busy = True
            work = _WorkItem(request_id, job.request, job.session)
            self._approval_work = work
            self._terminal_queue.put(work)

    @staticmethod
    def _authorize_without_blocking(work: _WorkItem, authorized: bool) -> None:
        try:
            work.authorization.put_nowait(authorized)
        except queue.Full:
            # A cancellation heartbeat may already have supplied False.
            pass

    def _probe_active_approval(self) -> None:
        """Detect a dead waiting client while the human prompt is open."""

        work = self._approval_work
        if work is None:
            return
        record = self._scheduler.request(work.request_id)
        if record.state is not RequestState.AWAITING_APPROVAL:
            return
        try:
            work.session.send_status(work.request_id, "awaiting-human-approval")
        except ClientWriteError:
            self._scheduler.client_disconnected(work.request_id)
            self._authorize_without_blocking(work, False)
            work.session.abort()
            self._record("approval-client-disconnected", work.request_id)
        else:
            self._record("approval-heartbeat", work.request_id)

    def _handle_approval(self, event: _ApprovalFinished) -> None:
        request_id = event.work.request_id
        record = self._scheduler.request(request_id)
        if record.state is RequestState.CANCELLED_BEFORE_APPROVAL:
            # The waiting client disappeared while the operator was deciding.
            # Its eventual RUN is stale and must never authorize execution.
            self._authorize_without_blocking(event.work, False)
            self._approval_work = None
            self._terminal_busy = False
            self._record("stale-approval-ignored", request_id)
            self._approval_discarder(request_id)
            self._forget_cancelled(request_id)
            return

        if event.error is not None:
            self._scheduler.deny(request_id)
            self._authorize_without_blocking(event.work, False)
            result = ExecutionResult(
                request_id,
                TransportStatus.INTERNAL_ERROR,
                detail=(
                    "approval subsystem failed closed: "
                    f"{type(event.error).__name__}: {event.error}"
                ),
            )
            self._record("approval-error", request_id)
            self._deliver_scheduled(event.work.session, result)
            self._approval_work = None
            self._terminal_busy = False
            return

        if event.decision is ApprovalDecision.DENIED:
            self._scheduler.deny(request_id)
            self._authorize_without_blocking(event.work, False)
            result = ExecutionResult(
                request_id,
                TransportStatus.DENIED,
                detail="request denied by human",
            )
            self._record("denied", request_id)
            self._deliver_scheduled(event.work.session, result)
            self._approval_work = None
            self._terminal_busy = False
            return

        if event.decision is not ApprovalDecision.APPROVED:
            raise BrokerError("approval worker returned an unknown decision")

        # A final write while the request is still unapproved is the
        # linearization point for disconnect-versus-RUN.  If it fails, RUN is
        # stale, the lease is released, and the executor is never authorized.
        try:
            event.work.session.send_status(request_id, "approval-confirmed")
        except ClientWriteError:
            self._scheduler.client_disconnected(request_id)
            self._authorize_without_blocking(event.work, False)
            event.work.session.abort()
            self._approval_work = None
            self._terminal_busy = False
            self._record("stale-approval-ignored", request_id)
            self._approval_discarder(request_id)
            self._forget_cancelled(request_id)
            return

        self._scheduler.approve(request_id)
        try:
            event.work.session.send_status(request_id, "execution-starting")
        except ClientWriteError:
            self._scheduler.client_disconnected(request_id)
            event.work.session.abort()
            self._record("approved-client-disconnected", request_id)
        self._record("approved", request_id)
        self._approval_work = None
        self._terminal_busy = False
        self._authorize_without_blocking(event.work, True)

    def _handle_execution(self, event: _ExecutionFinished) -> None:
        request_id = event.work.request_id
        if event.error is not None:
            self._scheduler.mark_remote_may_be_running(request_id)
            self._scheduler.mark_recovery_required(
                request_id,
                detail="executor failed after authorization; remote state is uncertain",
            )
            result = ExecutionResult(
                request_id,
                TransportStatus.INCOMPLETE,
                detail="execution result is incomplete; command lease retained",
            )
            self._queue_result_write(
                event.work.session,
                result,
                scheduled=False,
                retire_request_id=False,
                status_name="recovery-required",
            )
            self._record("recovery-required", request_id)
            # Retain only this request's scheduler lease; other slots continue.
            return

        assert event.execution is not None
        execution = event.execution
        if isinstance(execution, ExecutionResult):
            if execution.transport_status is TransportStatus.PRE_REMOTE_FAILURE:
                self._scheduler.mark_pre_remote_failure(
                    request_id,
                    detail=execution.detail or "pre-remote execution failure",
                )
                self._record("pre-remote-failure", request_id)
                self._deliver_scheduled(event.work.session, execution)
                return
            if execution.transport_status is TransportStatus.RECOVERY_IN_PROGRESS:
                self._scheduler.mark_pre_remote_failure(
                    request_id,
                    detail=execution.detail or "machine recovery is in progress",
                )
                self._record("recovery-in-progress", request_id)
                self._deliver_scheduled(event.work.session, execution)
                return
            if execution.transport_status is TransportStatus.REMOTE_SETUP_FAILURE:
                self._scheduler.mark_remote_setup_failure(
                    request_id,
                    detail=execution.detail or "remote setup failed after mutation",
                )
                self._record("remote-setup-failure", request_id)
                self._deliver_scheduled(event.work.session, execution)
                return
            if (
                execution.transport_status
                is TransportStatus.ABANDONED_AFTER_VERIFIED_REBOOT
            ):
                self._scheduler.mark_remote_may_be_running(request_id)
                self._scheduler.mark_abandoned_after_verified_reboot(
                    request_id,
                    detail=execution.detail or "full-host reboot was cryptographically verified",
                )
                self._record("abandoned-after-verified-reboot", request_id)
                self._deliver_scheduled(event.work.session, execution)
                return
            if (
                execution.transport_status is TransportStatus.INCOMPLETE
                and event.work.request.disconnect_policy
                is DisconnectPolicy.EXPECT_FULL_REBOOT
                and execution.result_code is not None
                and execution.result_code.value
                in {
                    "reboot_recovery_timeout",
                    "same_boot_observed",
                    "endpoint_identity_mismatch",
                    "host_key_mismatch",
                    "unsafe_control_path",
                    "ambiguous_master_state",
                    "credential_unavailable",
                    "credential_prompt_mismatch",
                    "reboot_probe_unavailable",
                    "request_binding_mismatch",
                }
            ):
                self._scheduler.mark_remote_may_be_running(request_id)
                self._scheduler.mark_recovery_transferred(
                    request_id,
                    detail=execution.detail or "expected reboot recovery failed closed",
                )
                self._record("expected-reboot-recovery-failed", request_id)
                self._deliver_scheduled(event.work.session, execution)
                return
            if execution.transport_status is not TransportStatus.COMPLETE:
                self._scheduler.mark_remote_may_be_running(request_id)
                self._scheduler.mark_recovery_required(
                    request_id,
                    detail=execution.detail or "remote result is incomplete",
                )
                self._queue_result_write(
                    event.work.session,
                    execution,
                    scheduled=False,
                    retire_request_id=False,
                    status_name="recovery-required",
                )
                self._record("recovery-required", request_id)
                return
            self._scheduler.mark_remote_may_be_running(request_id)
            self._scheduler.mark_remote_completion_proven(
                request_id,
                exit_status=execution.remote_exit_status,
            )
            self._scheduler.mark_local_spool_verified(request_id)
            self._scheduler.mark_viewer_detached(request_id)
            self._scheduler.mark_terminal_restored(request_id)
            self._record("completed", request_id)
            self._deliver_scheduled(event.work.session, execution)
            return

        self._scheduler.mark_remote_may_be_running(request_id)
        self._scheduler.mark_remote_completion_proven(
            request_id,
            exit_status=execution.exit_status,
        )
        self._scheduler.mark_local_spool_verified(request_id)
        self._scheduler.mark_viewer_detached(request_id)
        self._scheduler.mark_terminal_restored(request_id)
        result = ExecutionResult(
            request_id,
            TransportStatus.COMPLETE,
            stdout=execution.stdout,
            stderr=execution.stderr,
            remote_exit_status=execution.exit_status,
        )
        self._record("completed", request_id)
        self._deliver_scheduled(event.work.session, result)

    def _deliver_scheduled(
        self,
        session: _ClientSession,
        result: ExecutionResult,
    ) -> None:
        self._scheduler.begin_result_delivery(result.request_id)
        # Once all command-lease release gates have passed, result delivery no
        # longer needs the potentially large RequestSpec.  The scheduler record
        # remains until the per-client writer finishes or fails.
        self._jobs.pop(result.request_id, None)
        self._queue_result_write(
            session,
            result,
            scheduled=True,
            retire_request_id=True,
            status_name="result",
        )

    def _queue_result_write(
        self,
        session: _ClientSession,
        result: ExecutionResult,
        *,
        scheduled: bool,
        retire_request_id: bool,
        status_name: str,
    ) -> None:
        def completed(error: BaseException | None) -> None:
            self._events.put(
                _ResultWriteFinished(
                    result.request_id,
                    session,
                    scheduled,
                    retire_request_id,
                    status_name,
                    error,
                )
            )

        try:
            session.send_result_async(result, completed)
        except ClientWriteError:
            self._delivery_observer(result.request_id, False)
            if scheduled:
                self._scheduler.client_disconnected(result.request_id)
                self._finish_scheduled_result(result.request_id)
            elif retire_request_id:
                self._retire_request_id(result.request_id)
            self._record(f"{status_name}-client-disconnected", result.request_id)
            session.abort()

    def _handle_result_write_finished(self, event: _ResultWriteFinished) -> None:
        if event.scheduled:
            self._delivery_observer(event.request_id, event.error is None)
            if event.error is not None:
                self._scheduler.client_disconnected(event.request_id)
                self._record("result-client-disconnected", event.request_id)
            else:
                self._record("result-delivered", event.request_id)
            self._finish_scheduled_result(event.request_id)
        elif event.error is not None:
            self._record(f"{event.status_name}-client-disconnected", event.request_id)
        else:
            self._record(f"{event.status_name}-result-delivered", event.request_id)
        if not event.scheduled and event.retire_request_id:
            self._retire_request_id(event.request_id)
        event.session.close()
