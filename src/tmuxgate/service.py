"""Execution service with one fixed three-job semaphore."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Coroutine
from dataclasses import asdict
import logging
from pathlib import Path
import secrets
from typing import Any, Mapping, Sequence

from tmuxgate.config import Config
from tmuxgate import pane_input, panes
from tmuxgate.executor import RemoteExecutor, _validate_request
from tmuxgate.jobs import Job, JobStore
from tmuxgate.storage import read_private


LOGGER = logging.getLogger(__name__)
CONCURRENCY = 3


class ExecutionService:
    def __init__(
        self,
        config: Config,
        store: JobStore,
        executor: RemoteExecutor,
    ) -> None:
        self.config = config
        self.store = store
        self.executor = executor
        self._semaphore = asyncio.Semaphore(CONCURRENCY)
        self._tasks: set[asyncio.Task[Job]] = set()
        self._closing = False
        self._pane_writers: set[tuple[str, str, str]] = set()

    async def start(self) -> None:
        for job in self.store.recoverable():
            if job.machine not in self.config.machines:
                detail = (
                    f"machine={job.machine} job_id={job.job_id}: configured alias no longer exists"
                )
                self.store.update(
                    job,
                    state="unknown",
                    error_code="unknown_machine",
                    error_detail=detail,
                )
                continue
            self._track(job.job_id, self._recover(job))

    def _track(
        self, job_id: str, coroutine: Coroutine[Any, Any, Job]
    ) -> asyncio.Task[Job]:
        if self._closing:
            raise RuntimeError("execution service is shutting down")
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)

        def finished(completed: asyncio.Task[Job]) -> None:
            self._tasks.discard(completed)
            if not completed.cancelled():
                exception = completed.exception()
                if exception is not None:
                    LOGGER.error(
                        "job task crashed job_id=%s",
                        job_id,
                        exc_info=(
                            type(exception),
                            exception,
                            exception.__traceback__,
                        ),
                    )

        task.add_done_callback(finished)
        return task

    async def _execute(
        self,
        job: Job,
        destination: str,
        *,
        cwd: str,
        argv: Sequence[str] | None,
        script: str | None,
        environment: Mapping[str, str],
    ) -> Job:
        async with self._semaphore:
            return await self.executor.execute(
                job,
                destination,
                cwd=cwd,
                argv=argv,
                script=script,
                environment=environment,
            )

    async def _recover(self, job: Job) -> Job:
        async with self._semaphore:
            return await self.executor.recover(
                job, self.config.destination(job.machine)
            )

    async def _run(
        self,
        machine: str,
        cwd: str,
        *,
        argv: Sequence[str] | None,
        script: str | None,
        environment: Mapping[str, str] | None,
        timeout: float | None,
        sudo: bool,
    ) -> Job:
        values = {} if environment is None else dict(environment)
        _validate_request(cwd, argv, script, values)
        destination = self.config.destination(machine)
        if type(sudo) is not bool:
            raise ValueError("sudo must be a bool")
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
                raise ValueError("timeout must be a positive number")
            timeout = float(timeout)
        job = self.store.create(secrets.token_hex(16), machine, sudo)
        task = self._track(
            job.job_id,
            self._execute(
                job,
                destination,
                cwd=cwd,
                argv=None if argv is None else tuple(argv),
                script=script,
                environment=values,
            ),
        )
        if timeout is not None:
            try:
                return await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
            except asyncio.TimeoutError:
                return self.store.load(job.job_id)
        return await asyncio.shield(task)

    async def run_argv(
        self,
        machine: str,
        cwd: str,
        argv: Sequence[str],
        environment: Mapping[str, str] | None = None,
        timeout: float | None = None,
        sudo: bool = False,
    ) -> Job:
        return await self._run(
            machine,
            cwd,
            argv=argv,
            script=None,
            environment=environment,
            timeout=timeout,
            sudo=sudo,
        )

    async def run_script(
        self,
        machine: str,
        cwd: str,
        script: str,
        environment: Mapping[str, str] | None = None,
        timeout: float | None = None,
        sudo: bool = False,
    ) -> Job:
        return await self._run(
            machine,
            cwd,
            argv=None,
            script=script,
            environment=environment,
            timeout=timeout,
            sudo=sudo,
        )

    async def list_tmux_panes(self, machine: str, timeout: float = panes.DEFAULT_TIMEOUT) -> dict[str, object]:
        destination = self.config.destination(machine)
        panes.validate_timeout(timeout)
        if self._closing:
            raise RuntimeError("execution service is shutting down")
        try:
            async with asyncio.timeout(timeout):
                async with self._semaphore:
                    inventory = await panes.list_panes(destination)
            return {"machine": machine, "panes": [pane.view() for pane in inventory]}
        except TimeoutError as exc:
            raise panes.PaneError("inspection_timeout", "tmux inspection timed out") from exc

    async def capture_tmux_pane(
        self, machine: str, server_id: str, session_id: str, window_id: str,
        pane_id: str, lines: int = 200, timeout: float = panes.DEFAULT_TIMEOUT,
    ) -> dict[str, object]:
        destination = self.config.destination(machine)
        panes.validate_target(server_id, session_id, window_id, pane_id, lines)
        panes.validate_timeout(timeout)
        if self._closing:
            raise RuntimeError("execution service is shutting down")
        try:
            async with asyncio.timeout(timeout):
                async with self._semaphore:
                    view = await panes.capture_pane(destination, server_id, session_id, window_id, pane_id, lines)
            return {"machine": machine, **view}
        except TimeoutError as exc:
            raise panes.PaneError("inspection_timeout", "tmux inspection timed out") from exc

    async def _send_tmux_input(
        self, machine: str, server_id: str, session_id: str, window_id: str,
        pane_id: str, pane_pid: int, keys: str, *, literal: bool, submit: bool,
        timeout: float,
    ) -> dict[str, object]:
        destination = self.config.destination(machine)
        panes.validate_target(server_id, session_id, window_id, pane_id, 1)
        pane_input.validate_pid(pane_pid)
        panes.validate_timeout(timeout)
        if self._closing:
            raise RuntimeError("execution service is shutting down")
        # Linked session memberships and duplicate logical aliases for the same
        # configured destination must share one local writer scope.
        scope = (destination, server_id, pane_id)
        identity = {"machine": machine, "server_id": server_id, "session_id": session_id,
                    "window_id": window_id, "pane_id": pane_id, "pane_pid": pane_pid}
        if scope in self._pane_writers:
            return {**identity, **pane_input.outcome("not_sent", "pane_busy")}
        self._pane_writers.add(scope)
        dispatch = pane_input.Dispatch()
        try:
            async with asyncio.timeout(timeout):
                async with self._semaphore:
                    answer = await pane_input.send(destination, server_id, session_id, window_id, pane_id, pane_pid, keys,
                                                   literal=literal, submit=submit, dispatch=dispatch)
            return {**identity, **answer}
        except TimeoutError:
            answer = pane_input.outcome("unknown", "dispatch_unknown") if dispatch.started else pane_input.outcome("not_sent", "input_timeout")
            return {**identity, **answer}
        except panes.PaneError as exc:
            return {**identity, **pane_input.outcome("not_sent", exc.code), "error_detail": exc.detail}
        finally:
            self._pane_writers.discard(scope)

    async def send_tmux_text(
        self, machine: str, server_id: str, session_id: str, window_id: str,
        pane_id: str, pane_pid: int, text: str, multiline: bool = False,
        submit: bool = False, timeout: float = panes.DEFAULT_TIMEOUT,
    ) -> dict[str, object]:
        keys = pane_input.text_keys(text, multiline, submit)
        return await self._send_tmux_input(machine, server_id, session_id, window_id, pane_id, pane_pid, keys,
                                           literal=True, submit=submit, timeout=timeout)

    async def send_tmux_key(
        self, machine: str, server_id: str, session_id: str, window_id: str,
        pane_id: str, pane_pid: int, key: str, timeout: float = panes.DEFAULT_TIMEOUT,
    ) -> dict[str, object]:
        pane_input.validate_key(key)
        return await self._send_tmux_input(machine, server_id, session_id, window_id, pane_id, pane_pid, key,
                                           literal=False, submit=False, timeout=timeout)

    def get_job(self, job_id: str) -> Job:
        return self.store.load(job_id)

    def list_jobs(self, limit: int = 50) -> list[Job]:
        return self.store.list(limit)

    async def close(self) -> None:
        self._closing = True
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()


def job_view(job: Job, *, include_result: bool = True) -> dict[str, object]:
    view: dict[str, object] = asdict(job)
    if include_result and job.state == "complete":
        stdout, stdout_encoding = _output(Path(job.stdout_path))
        stderr, stderr_encoding = _output(Path(job.stderr_path))
        view.update(
            stdout=stdout,
            stdout_encoding=stdout_encoding,
            stderr=stderr,
            stderr_encoding=stderr_encoding,
        )
    return view


def _output(path: Path) -> tuple[str, str]:
    payload = read_private(path)
    try:
        return payload.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return base64.b64encode(payload).decode("ascii"), "base64"
