"""Direct staging, remote tmux execution, monitoring, and result collection."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import importlib.resources
import io
import logging
import os
from pathlib import Path
import re
import shlex
import tarfile
import tempfile
from typing import Literal, Mapping, Sequence

from tmuxgate.credentials import CredentialStore, _erase
from tmuxgate.jobs import Job, JobStore
from tmuxgate import ssh


LOGGER = logging.getLogger(__name__)
ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
REMOTE_PARENT = ".cache/tmuxgate/jobs"


class ExecutionError(RuntimeError):
    def __init__(
        self, code: str, detail: str, *, possibly_started: bool = False
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.possibly_started = possibly_started


@dataclass(frozen=True, slots=True)
class CollectedResult:
    stdout: bytes
    stderr: bytes
    exit_code: int


def _context(machine: str, job_id: str, detail: str) -> str:
    return f"machine={machine} job_id={job_id}: {detail}"


def _validate_request(
    cwd: str,
    argv: Sequence[str] | None,
    script: str | None,
    environment: Mapping[str, str],
) -> None:
    if not isinstance(cwd, str) or not cwd or "\x00" in cwd:
        raise ValueError("cwd must be a non-empty NUL-free string")
    if (argv is None) == (script is None):
        raise ValueError("provide exactly one of argv or script")
    if argv is not None:
        if not argv or any(not isinstance(item, str) or "\x00" in item for item in argv):
            raise ValueError("argv must contain non-empty NUL-free string arguments")
    if script is not None:
        if not isinstance(script, str) or "\x00" in script:
            raise ValueError("script must be NUL-free UTF-8 text")
        script.encode("utf-8")
    for name, value in environment.items():
        if not isinstance(name, str) or not ENVIRONMENT_NAME.fullmatch(name):
            raise ValueError(f"invalid environment name: {name!r}")
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError(f"environment value for {name} must be a NUL-free string")


def _render_run_script(
    *,
    cwd: str,
    argv: Sequence[str] | None,
    script: str | None,
    environment: Mapping[str, str],
) -> bytes:
    _validate_request(cwd, argv, script, environment)
    template = (
        importlib.resources.files("tmuxgate")
        .joinpath("assets/remote_job.sh")
        .read_text(encoding="utf-8")
    )
    setup = [f"cd -- {shlex.quote(cwd)} || exit 125"]
    for name in sorted(environment):
        setup.append(f"export {name}={shlex.quote(environment[name])}")
    if argv is not None:
        command = f"exec {shlex.join(list(argv))}"
    else:
        command = 'exec /bin/bash <(tail -n +__TMUXGATE_PAYLOAD_LINE__ -- "$0")'
    rendered = template.replace("__TMUXGATE_SETUP__", "\n".join(setup))
    rendered = rendered.replace("__TMUXGATE_COMMAND__", command)
    prefix, marker, suffix = rendered.partition("# __TMUXGATE_PAYLOAD__")
    if not marker or suffix.strip():
        raise RuntimeError("remote job asset has an invalid payload marker")
    payload_line = prefix.count("\n") + 1
    prefix = prefix.replace("__TMUXGATE_PAYLOAD_LINE__", str(payload_line))
    if script is None:
        return prefix.encode("utf-8")
    payload = script if script.endswith("\n") else script + "\n"
    return (prefix + payload).encode("utf-8")


def _tar_run_script(content: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        member = tarfile.TarInfo("run.sh")
        member.size = len(content)
        member.mode = 0o700
        member.mtime = 0
        member.uid = 0
        member.gid = 0
        archive.addfile(member, io.BytesIO(content))
    return buffer.getvalue()


def _classify_failure(result: ssh.SSHResult, phase_code: str) -> ExecutionError:
    code = "ssh_failed" if result.returncode == 255 else phase_code
    detail = result.stderr_text or f"remote command exited {result.returncode}"
    return ExecutionError(code, detail)


def _requires_tty(stderr: str) -> bool:
    value = stderr.lower()
    return "tty" in value and any(
        phrase in value
        for phrase in ("require", "must have", "no tty", "terminal is required")
    )


class RemoteExecutor:
    def __init__(
        self,
        store: JobStore,
        credentials: CredentialStore,
        *,
        poll_interval: float = 1.0,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        self.store = store
        self.credentials = credentials
        self.poll_interval = poll_interval

    async def stage(
        self,
        job: Job,
        destination: str,
        *,
        cwd: str,
        argv: Sequence[str] | None,
        script: str | None,
        environment: Mapping[str, str],
    ) -> None:
        run_script = _render_run_script(
            cwd=cwd, argv=argv, script=script, environment=environment
        )
        archive = _tar_run_script(run_script)
        remote = """set -eu
umask 077
parent=$HOME/.cache/tmuxgate/jobs
mkdir -p -- "$parent"
job=$parent/$1
mkdir -- "$job"
tar -xf - -C "$job"
"""
        result = await ssh.run(
            destination,
            ["/bin/sh", "-c", remote, "tmuxgate-stage", job.job_id],
            input_data=archive,
        )
        if result.returncode != 0:
            raise _classify_failure(result, "remote_stage_failed")
        LOGGER.info(
            "job staged job_id=%s machine=%s state=starting remote_directory=%s",
            job.job_id,
            job.machine,
            job.remote_directory,
        )

    async def _passwordless_sudo(
        self, machine: str, job_id: str, destination: str
    ) -> bool:
        result = await ssh.run(destination, ["sudo", "-n", "--", "true"])
        if result.returncode == 0:
            return True
        if result.returncode == 255:
            failure = _classify_failure(result, "sudo_unavailable")
            raise ExecutionError(failure.code, _context(machine, job_id, failure.detail))
        detail = result.stderr_text
        if _requires_tty(detail):
            raise ExecutionError(
                "sudo_unavailable",
                _context(
                    machine,
                    job_id,
                    "sudo requires a TTY; configure noninteractive sudo for this host",
                ),
            )
        if "not found" in detail.lower() or "may not run sudo" in detail.lower():
            raise ExecutionError(
                "sudo_unavailable", _context(machine, job_id, detail or "sudo unavailable")
            )
        return False

    async def test_sudo_password(
        self,
        machine: str,
        destination: str,
        password: bytes | bytearray,
        *,
        job_id: str = "credential-test",
    ) -> None:
        attempt = bytearray(password)
        attempt.append(10)
        try:
            result = await ssh.run(
                destination,
                ["sudo", "-S", "-k", "-p", "", "--", "true"],
                input_data=attempt,
            )
        finally:
            _erase(attempt)
        if result.returncode == 0:
            return
        detail = result.stderr_text
        if result.returncode == 255:
            failure = _classify_failure(result, "sudo_unavailable")
            raise ExecutionError(failure.code, _context(machine, job_id, failure.detail))
        if _requires_tty(detail):
            raise ExecutionError(
                "sudo_unavailable",
                _context(
                    machine,
                    job_id,
                    "sudo requires a TTY; configure noninteractive sudo for this host",
                ),
            )
        if "not found" in detail.lower() or "may not run sudo" in detail.lower():
            raise ExecutionError(
                "sudo_unavailable", _context(machine, job_id, detail or "sudo unavailable")
            )
        raise ExecutionError(
            "sudo_auth_failed",
            _context(machine, job_id, "stored sudo credential was rejected"),
        )

    async def check_sudo(
        self, job: Job, destination: str
    ) -> Literal["passwordless", "password"]:
        if await self._passwordless_sudo(job.machine, job.job_id, destination):
            return "passwordless"
        password = self.credentials.read(job.machine)
        if password is None:
            raise ExecutionError(
                "sudo_password_missing",
                _context(job.machine, job.job_id, "no stored sudo credential"),
            )
        try:
            await self.test_sudo_password(
                job.machine, destination, password, job_id=job.job_id
            )
        finally:
            _erase(password)
        return "password"

    async def test_stored_sudo(
        self, machine: str, destination: str
    ) -> Literal["passwordless", "password"]:
        """Validate current sudo access for the credential CLI."""

        job_id = "credential-test"
        if await self._passwordless_sudo(machine, job_id, destination):
            return "passwordless"
        password = self.credentials.read(machine)
        if password is None:
            raise ExecutionError(
                "sudo_password_missing",
                _context(machine, job_id, "no stored sudo credential"),
            )
        try:
            await self.test_sudo_password(
                machine, destination, password, job_id=job_id
            )
        finally:
            _erase(password)
        return "password"

    async def start(self, job: Job, destination: str) -> None:
        if not job.sudo:
            remote = """job=$HOME/.cache/tmuxgate/jobs/$2
exec tmux new-session -d -s "$1" /bin/bash "$job/run.sh" 0 '' ''
"""
            result = await ssh.run(
                destination,
                [
                    "/bin/sh",
                    "-c",
                    remote,
                    "tmuxgate-start",
                    job.remote_session,
                    job.job_id,
                ],
            )
            if result.returncode != 0:
                failure = _classify_failure(result, "remote_start_failed")
                raise ExecutionError(
                    failure.code,
                    failure.detail,
                    possibly_started=failure.code == "ssh_failed",
                )
        else:
            mode = await self.check_sudo(job, destination)
            sudo_arguments = (
                "sudo -n --" if mode == "passwordless" else "sudo -S -k -p '' --"
            )
            remote = f"""job=$HOME/.cache/tmuxgate/jobs/$2
owner_uid=$(id -u) || exit 125
owner_gid=$(id -g) || exit 125
exec {sudo_arguments} tmux new-session -d -s "$1" /bin/bash "$job/run.sh" 1 "$owner_uid" "$owner_gid"
"""
            password: bytearray | None = None
            if mode == "password":
                password = self.credentials.read(job.machine)
                if password is None:
                    raise ExecutionError(
                        "sudo_password_missing",
                        _context(job.machine, job.job_id, "sudo credential disappeared"),
                    )
                password.append(10)
            try:
                result = await ssh.run(
                    destination,
                    [
                        "/bin/sh",
                        "-c",
                        remote,
                        "tmuxgate-sudo-start",
                        job.remote_session,
                        job.job_id,
                    ],
                    input_data=password,
                )
            finally:
                _erase(password)
            if result.returncode != 0:
                failure = _classify_failure(result, "sudo_job_start_failed")
                code = "sudo_job_start_failed" if failure.code != "ssh_failed" else failure.code
                raise ExecutionError(
                    code,
                    _context(job.machine, job.job_id, failure.detail),
                    possibly_started=failure.code == "ssh_failed",
                )
        LOGGER.info(
            "job started job_id=%s machine=%s state=running remote_directory=%s",
            job.job_id,
            job.machine,
            job.remote_directory,
        )

    async def completion_exists(self, job: Job, destination: str) -> bool:
        remote = 'test -f "$HOME/.cache/tmuxgate/jobs/$1/done"'
        result = await ssh.run(
            destination,
            ["/bin/sh", "-c", remote, "tmuxgate-done", job.job_id],
        )
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        raise _classify_failure(result, "ssh_failed")

    async def monitor(self, job: Job, destination: str) -> None:
        while not await self.completion_exists(job, destination):
            await asyncio.sleep(self.poll_interval)

    async def _sudo_session_result(self, job: Job, destination: str) -> ssh.SSHResult:
        mode = await self.check_sudo(job, destination)
        arguments = ["sudo", "-n", "--", "tmux", "has-session", "-t", job.remote_session]
        password: bytearray | None = None
        if mode == "password":
            arguments = [
                "sudo",
                "-S",
                "-k",
                "-p",
                "",
                "--",
                "tmux",
                "has-session",
                "-t",
                job.remote_session,
            ]
            password = self.credentials.read(job.machine)
            if password is None:
                raise ExecutionError(
                    "sudo_password_missing",
                    _context(job.machine, job.job_id, "no stored sudo credential"),
                )
            password.append(10)
        try:
            return await ssh.run(destination, arguments, input_data=password)
        finally:
            _erase(password)

    async def session_running(self, job: Job, destination: str) -> bool:
        if job.sudo:
            result = await self._sudo_session_result(job, destination)
        else:
            result = await ssh.run(
                destination, ["tmux", "has-session", "-t", job.remote_session]
            )
        if result.returncode == 0:
            return True
        if result.returncode in {1, 127}:
            return False
        if result.returncode == 255:
            raise _classify_failure(result, "ssh_failed")
        return False

    async def collect(self, job: Job, destination: str) -> Job:
        remote = """directory=$HOME/.cache/tmuxgate/jobs/$1
exec tar -cf - -C "$directory" stdout stderr exit-code
"""
        result = await ssh.run(
            destination,
            ["/bin/sh", "-c", remote, "tmuxgate-collect", job.job_id],
        )
        if result.returncode != 0:
            failure = _classify_failure(result, "result_collection_failed")
            raise ExecutionError("result_collection_failed", failure.detail)
        try:
            collected = _read_result_archive(result.stdout)
            _atomic_output(Path(job.stdout_path), collected.stdout)
            _atomic_output(Path(job.stderr_path), collected.stderr)
        except (OSError, ValueError, tarfile.TarError) as exc:
            raise ExecutionError("result_collection_failed", str(exc)) from exc
        complete = self.store.update(
            job,
            state="complete",
            exit_code=collected.exit_code,
            error_code=None,
            error_detail=None,
        )
        LOGGER.info(
            "job collected job_id=%s machine=%s state=complete remote_directory=%s",
            job.job_id,
            job.machine,
            job.remote_directory,
        )
        await self.cleanup(complete, destination)
        return complete

    async def cleanup(self, job: Job, destination: str) -> None:
        remote = 'rm -rf -- "$HOME/.cache/tmuxgate/jobs/$1"'
        result = await ssh.run(
            destination,
            ["/bin/sh", "-c", remote, "tmuxgate-cleanup", job.job_id],
        )
        if result.returncode != 0:
            LOGGER.warning(
                "remote cleanup retained job_id=%s machine=%s state=%s "
                "remote_directory=%s error_code=result_collection_failed ssh_stderr=%s",
                job.job_id,
                job.machine,
                job.state,
                job.remote_directory,
                result.stderr_text,
            )

    async def execute(
        self,
        job: Job,
        destination: str,
        *,
        cwd: str,
        argv: Sequence[str] | None,
        script: str | None,
        environment: Mapping[str, str],
    ) -> Job:
        current = job
        try:
            await self.stage(
                current,
                destination,
                cwd=cwd,
                argv=argv,
                script=script,
                environment=environment,
            )
            await self.start(current, destination)
            current = self.store.update(current, state="running")
            await self.monitor(current, destination)
            return await self.collect(current, destination)
        except asyncio.CancelledError:
            raise
        except ExecutionError as exc:
            state = (
                "unknown"
                if exc.possibly_started
                or (current.state == "running" and exc.code == "ssh_failed")
                else "failed"
            )
            prefix = f"machine={current.machine} job_id={current.job_id}:"
            detail = exc.detail if exc.detail.startswith(prefix) else _context(
                current.machine, current.job_id, exc.detail
            )
            LOGGER.error(
                "job failed job_id=%s machine=%s state=%s remote_directory=%s "
                "error_code=%s detail=%s",
                current.job_id,
                current.machine,
                state,
                current.remote_directory,
                exc.code,
                detail,
            )
            return self.store.update(
                current,
                state=state,
                error_code=exc.code,
                error_detail=detail,
            )

    async def recover(self, job: Job, destination: str) -> Job:
        try:
            if await self.completion_exists(job, destination):
                return await self.collect(job, destination)
            if await self.session_running(job, destination):
                running = job if job.state == "running" else self.store.update(job, state="running")
                await self.monitor(running, destination)
                return await self.collect(running, destination)
            detail = _context(
                job.machine,
                job.job_id,
                "no completion marker or convincing remote tmux session",
            )
            return self.store.update(
                job,
                state="unknown",
                error_code="remote_job_unknown",
                error_detail=detail,
            )
        except asyncio.CancelledError:
            raise
        except ExecutionError as exc:
            prefix = f"machine={job.machine} job_id={job.job_id}:"
            detail = exc.detail if exc.detail.startswith(prefix) else _context(
                job.machine, job.job_id, exc.detail
            )
            return self.store.update(
                job,
                state="unknown",
                error_code=exc.code,
                error_detail=detail,
            )


def _read_result_archive(payload: bytes) -> CollectedResult:
    values: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for member in archive.getmembers():
            if member.name not in {"stdout", "stderr", "exit-code"} or not member.isfile():
                raise ValueError("unexpected member in result archive")
            if member.name in values:
                raise ValueError("duplicate member in result archive")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError("missing result member data")
            values[member.name] = extracted.read()
    if set(values) != {"stdout", "stderr", "exit-code"}:
        raise ValueError("incomplete result archive")
    try:
        exit_text = values["exit-code"].decode("ascii").strip()
        if not exit_text.isdecimal():
            raise ValueError
        exit_code = int(exit_text)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid remote exit code") from exc
    if not 0 <= exit_code <= 255:
        raise ValueError("remote exit code is outside 0..255")
    return CollectedResult(values["stdout"], values["stderr"], exit_code)


def _atomic_output(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
