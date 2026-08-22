"""Atomic, deliberately small local job records."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from typing import Literal, cast


JobState = Literal["starting", "running", "complete", "failed", "unknown"]
JOB_STATES = frozenset({"starting", "running", "complete", "failed", "unknown"})
JOB_FIELDS = frozenset(
    {
        "job_id",
        "machine",
        "sudo",
        "state",
        "created_at",
        "updated_at",
        "remote_directory",
        "remote_session",
        "exit_code",
        "error_code",
        "error_detail",
        "stdout_path",
        "stderr_path",
    }
)


class JobStoreError(RuntimeError):
    """A local job record is invalid or could not be persisted."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass(frozen=True, slots=True)
class Job:
    job_id: str
    machine: str
    sudo: bool
    state: JobState
    created_at: str
    updated_at: str
    remote_directory: str
    remote_session: str
    exit_code: int | None
    error_code: str | None
    error_detail: str | None
    stdout_path: str
    stderr_path: str


def _validate_job_id(job_id: str) -> None:
    if len(job_id) != 32 or any(character not in "0123456789abcdef" for character in job_id):
        raise JobStoreError("job_id must be 32 lowercase hexadecimal characters")


def _from_dict(value: object) -> Job:
    if not isinstance(value, dict) or set(value) != JOB_FIELDS:
        raise JobStoreError("job record does not use the current minimal format")
    job_id = value["job_id"]
    if not isinstance(job_id, str):
        raise JobStoreError("job_id must be a string")
    _validate_job_id(job_id)
    state = value["state"]
    if not isinstance(state, str) or state not in JOB_STATES:
        raise JobStoreError("job state is invalid")
    for field in (
        "machine",
        "created_at",
        "updated_at",
        "remote_directory",
        "remote_session",
        "stdout_path",
        "stderr_path",
    ):
        if not isinstance(value[field], str):
            raise JobStoreError(f"{field} must be a string")
    if type(value["sudo"]) is not bool:
        raise JobStoreError("sudo must be a bool")
    if value["exit_code"] is not None and type(value["exit_code"]) is not int:
        raise JobStoreError("exit_code must be an int or null")
    for field in ("error_code", "error_detail"):
        if value[field] is not None and not isinstance(value[field], str):
            raise JobStoreError(f"{field} must be a string or null")
    return Job(
        job_id=job_id,
        machine=cast(str, value["machine"]),
        sudo=cast(bool, value["sudo"]),
        state=cast(JobState, state),
        created_at=cast(str, value["created_at"]),
        updated_at=cast(str, value["updated_at"]),
        remote_directory=cast(str, value["remote_directory"]),
        remote_session=cast(str, value["remote_session"]),
        exit_code=cast(int | None, value["exit_code"]),
        error_code=cast(str | None, value["error_code"]),
        error_detail=cast(str | None, value["error_detail"]),
        stdout_path=cast(str, value["stdout_path"]),
        stderr_path=cast(str, value["stderr_path"]),
    )


class JobStore:
    """One JSON record per job, updated by fsync plus atomic rename."""

    def __init__(self, state_dir: Path | str) -> None:
        self.state_dir = Path(state_dir)
        self.jobs_dir = self.state_dir / "jobs"
        self.results_dir = self.state_dir / "results"
        self._ensure_directory(self.state_dir)
        self._ensure_directory(self.jobs_dir)
        self._ensure_directory(self.results_dir)

    @staticmethod
    def _ensure_directory(path: Path) -> None:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)

    def create(self, job_id: str, machine: str, sudo: bool) -> Job:
        _validate_job_id(job_id)
        timestamp = now()
        result_dir = self.results_dir / job_id
        self._ensure_directory(result_dir)
        job = Job(
            job_id=job_id,
            machine=machine,
            sudo=sudo,
            state="starting",
            created_at=timestamp,
            updated_at=timestamp,
            remote_directory=f"~/.cache/tmuxgate/jobs/{job_id}",
            remote_session=f"tmuxgate-{job_id}",
            exit_code=None,
            error_code=None,
            error_detail=None,
            stdout_path=str(result_dir / "stdout"),
            stderr_path=str(result_dir / "stderr"),
        )
        if self._path(job_id).exists():
            raise JobStoreError(f"job already exists: {job_id}")
        self.save(job)
        return job

    def _path(self, job_id: str) -> Path:
        _validate_job_id(job_id)
        return self.jobs_dir / f"{job_id}.json"

    def save(self, job: Job) -> Job:
        _validate_job_id(job.job_id)
        if job.state not in JOB_STATES:
            raise JobStoreError("job state is invalid")
        payload = json.dumps(
            asdict(job), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{job.job_id}.", suffix=".tmp", dir=self.jobs_dir
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self._path(job.job_id))
            directory_descriptor = os.open(self.jobs_dir, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise
        return job

    def update(self, job: Job, **changes: object) -> Job:
        if "updated_at" in changes:
            raise JobStoreError("updated_at is managed by JobStore")
        updated = replace(job, updated_at=now(), **changes)
        return self.save(updated)

    def load(self, job_id: str) -> Job:
        path = self._path(job_id)
        try:
            return _from_dict(json.loads(path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, JobStoreError) as exc:
            raise JobStoreError(f"invalid job record {path}: {exc}") from exc

    def list(self, limit: int = 50) -> list[Job]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        records: list[Job] = []
        for path in self.jobs_dir.glob("*.json"):
            try:
                records.append(self.load(path.stem))
            except JobStoreError:
                continue
        records.sort(key=lambda job: (job.created_at, job.job_id), reverse=True)
        return records[:limit]

    def recoverable(self) -> list[Job]:
        return [job for job in self.list(limit=1000) if job.state in {"starting", "running"}]
