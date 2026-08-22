"""Execution service with one fixed three-job semaphore."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Coroutine
import logging
from pathlib import Path
import secrets
from typing import Any, Mapping, Sequence

from tmuxgate.config import Config
from tmuxgate.executor import RemoteExecutor, _validate_request
from tmuxgate.jobs import Job, JobStore, JobStoreError


LOGGER = logging.getLogger(__name__)
CONCURRENCY = 3


class UnknownMachineError(ValueError):
    def __init__(self, machine: str, aliases: Sequence[str]) -> None:
        self.machine = machine
        self.aliases = tuple(aliases)
        available = ", ".join(self.aliases) or "(none)"
        super().__init__(
            f"unknown_machine: {machine!r}; configured aliases: {available}"
        )


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
        self._tasks: dict[str, asyncio.Task[Job]] = {}
        self._closing = False

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

    def destination(self, machine: str) -> str:
        try:
            return self.config.machines[machine]
        except KeyError as exc:
            raise UnknownMachineError(machine, sorted(self.config.machines)) from exc

    def _new_job(self, machine: str, sudo: bool) -> Job:
        self.destination(machine)
        if type(sudo) is not bool:
            raise ValueError("sudo must be a bool")
        for _ in range(100):
            job_id = secrets.token_hex(16)
            try:
                return self.store.create(job_id, machine, sudo)
            except JobStoreError as exc:
                if "already exists" not in str(exc):
                    raise
        raise RuntimeError("could not allocate a unique job ID")

    def _track(
        self, job_id: str, coroutine: Coroutine[Any, Any, Job]
    ) -> asyncio.Task[Job]:
        if self._closing:
            raise RuntimeError("execution service is shutting down")
        if job_id in self._tasks:
            raise RuntimeError(f"job is already being monitored: {job_id}")
        task = asyncio.create_task(coroutine)
        self._tasks[job_id] = task

        def finished(completed: asyncio.Task[Job]) -> None:
            if self._tasks.get(job_id) is completed:
                self._tasks.pop(job_id, None)
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
        *,
        cwd: str,
        argv: Sequence[str] | None,
        script: str | None,
        environment: Mapping[str, str],
    ) -> Job:
        async with self._semaphore:
            return await self.executor.execute(
                job,
                self.destination(job.machine),
                cwd=cwd,
                argv=argv,
                script=script,
                environment=environment,
            )

    async def _recover(self, job: Job) -> Job:
        async with self._semaphore:
            return await self.executor.recover(
                job, self.destination(job.machine)
            )

    async def _wait(self, job: Job, task: asyncio.Task[Job], timeout: float | None) -> Job:
        if timeout is not None:
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
                raise ValueError("timeout must be a positive number")
            try:
                return await asyncio.wait_for(asyncio.shield(task), timeout=float(timeout))
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
        values = {} if environment is None else dict(environment)
        _validate_request(cwd, argv, None, values)
        job = self._new_job(machine, sudo)
        task = self._track(
            job.job_id,
            self._execute(
                job, cwd=cwd, argv=tuple(argv), script=None, environment=values
            ),
        )
        return await self._wait(job, task, timeout)

    async def run_script(
        self,
        machine: str,
        cwd: str,
        script: str,
        environment: Mapping[str, str] | None = None,
        timeout: float | None = None,
        sudo: bool = False,
    ) -> Job:
        values = {} if environment is None else dict(environment)
        _validate_request(cwd, None, script, values)
        job = self._new_job(machine, sudo)
        task = self._track(
            job.job_id,
            self._execute(
                job, cwd=cwd, argv=None, script=script, environment=values
            ),
        )
        return await self._wait(job, task, timeout)

    def get_job(self, job_id: str) -> Job:
        return self.store.load(job_id)

    def list_jobs(self, limit: int = 50) -> list[Job]:
        return self.store.list(limit)

    async def close(self) -> None:
        self._closing = True
        tasks = tuple(self._tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()


def job_view(job: Job, *, include_result: bool = True) -> dict[str, object]:
    view: dict[str, object] = {
        "job_id": job.job_id,
        "machine": job.machine,
        "sudo": job.sudo,
        "state": job.state,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "remote_directory": job.remote_directory,
        "remote_session": job.remote_session,
        "exit_code": job.exit_code,
        "error_code": job.error_code,
        "error_detail": job.error_detail,
        "stdout_path": job.stdout_path,
        "stderr_path": job.stderr_path,
    }
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
    payload = path.read_bytes()
    try:
        return payload.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return base64.b64encode(payload).decode("ascii"), "base64"
