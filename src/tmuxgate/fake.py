"""Deterministic fake execution components for local broker tests.

These helpers never interpret or execute a :class:`~tmuxgate.models.RequestSpec`.
They only return test data supplied by the caller.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
import threading

from tmuxgate.approval import ApprovalDecision
from tmuxgate.models import RequestSpec


@dataclass(frozen=True, slots=True)
class FakeExecution:
    """Pre-arranged output from a fake remote execution."""

    stdout: bytes = b""
    stderr: bytes = b""
    exit_status: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.stdout, (bytes, bytearray)):
            raise ValueError("fake stdout must be bytes")
        if not isinstance(self.stderr, (bytes, bytearray)):
            raise ValueError("fake stderr must be bytes")
        if (
            isinstance(self.exit_status, bool)
            or not isinstance(self.exit_status, int)
            or not 0 <= self.exit_status <= 255
        ):
            raise ValueError("fake exit status must be an integer from 0 to 255")
        object.__setattr__(self, "stdout", bytes(self.stdout))
        object.__setattr__(self, "stderr", bytes(self.stderr))


class ScriptedApprover:
    """Return explicit approval decisions in FIFO order."""

    def __init__(self, decisions: Iterable[ApprovalDecision | str]) -> None:
        self._decisions = deque(ApprovalDecision(item) for item in decisions)
        self._lock = threading.Lock()
        self.calls: list[tuple[str, RequestSpec]] = []

    def __call__(self, request_id: str, request: RequestSpec) -> ApprovalDecision:
        with self._lock:
            self.calls.append((request_id, request))
            if not self._decisions:
                raise RuntimeError("no scripted approval decision remains")
            return self._decisions.popleft()


class ScriptedFakeExecutor:
    """Return pre-arranged results without interpreting request contents."""

    def __init__(self, executions: Iterable[FakeExecution]) -> None:
        self._executions = deque(executions)
        self._lock = threading.Lock()
        self.calls: list[tuple[str, RequestSpec]] = []

    def __call__(self, request_id: str, request: RequestSpec) -> FakeExecution:
        with self._lock:
            self.calls.append((request_id, request))
            if not self._executions:
                raise RuntimeError("no scripted fake execution remains")
            # Deliberately do not inspect argv, scripts, environment, or cwd.
            return self._executions.popleft()
