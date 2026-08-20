"""Real remote tmux job backend over one authenticated SSH master."""

from __future__ import annotations

from io import BytesIO
from importlib import resources
import os
from pathlib import Path
import re
import shlex
import stat
import tarfile
import tempfile
import threading
import time

from tmuxgate.config import ResultLimits
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.operator_interface import SecretInputRecipient
from tmuxgate.real_ssh import SshChannelRunner, ViewerProcess
from tmuxgate.remote_job import (
    CollectedRemoteFiles,
    RemoteJobBackend,
    RemoteJobError,
    RemoteJobIdentity,
    RemoteObservation,
)
from tmuxgate.runtime import ensure_private_directory
from tmuxgate.transport import (
    MasterTransport,
    build_batch_channel_prefix,
    build_viewer_channel_prefix,
)


MAX_STAGE_ARCHIVE_BYTES = 20 * 1024 * 1024
_COLLECTION_TEMP_RE = re.compile(r"\.[0-9a-f]{32}\.[A-Za-z0-9_-]{6,32}\Z", re.ASCII)

_STAGE_SCRIPT = r"""
set -eu
umask 077
job_id=$1
case "$job_id" in (*[!0-9a-f]*|'') exit 125;; esac
[ "${#job_id}" -eq 32 ] || exit 125
owner=$(id -u)
cache=$HOME/.cache
if [ -e "$cache" ]; then
    [ -d "$cache" ] && [ ! -L "$cache" ] || exit 125
    [ "$(stat -c '%u' "$cache")" = "$owner" ] || exit 125
else
    mkdir -m 700 "$cache" || exit 125
fi
root=$cache/tmuxgate
parent=$root/jobs
for directory in "$root" "$parent"; do
    if [ -e "$directory" ]; then
        [ -d "$directory" ] && [ ! -L "$directory" ] || exit 125
        [ "$(stat -c '%a:%u' "$directory")" = "700:$owner" ] || exit 125
    else
        mkdir -m 700 "$directory" || exit 125
    fi
done
job=$parent/$job_id
[ ! -e "$job" ] && [ ! -L "$job" ] || exit 125
mkdir -m 700 "$job"
tar -xf - -C "$job" --no-same-owner --no-same-permissions
chmod 600 "$job"/*
/bin/bash "$job/remote_control.sh" validate "$job_id"
"""


def _asset(name: str) -> bytes:
    return resources.files("tmuxgate").joinpath("assets", name).read_bytes()


def _tar_add(archive: tarfile.TarFile, name: str, content: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.mtime = 0
    archive.addfile(info, BytesIO(content))


def build_stage_archive(
    request: RequestSpec,
    limits: ResultLimits = ResultLimits(),
) -> bytes:
    if not isinstance(limits, ResultLimits):
        raise RemoteJobError("result limits are invalid")
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        _tar_add(archive, "mode", request.mode.value.encode("ascii") + b"\n")
        _tar_add(archive, "cwd.bin", os.fsencode(request.cwd) + b"\0")
        environment = b"".join(
            os.fsencode(name) + b"\0" + os.fsencode(value) + b"\0"
            for name, value in request.environment
        )
        _tar_add(archive, "environment.bin", environment)
        timeout = (
            b""
            if request.timeout_seconds is None
            else f"{request.timeout_seconds}\n".encode("ascii")
        )
        _tar_add(archive, "timeout", timeout)
        _tar_add(
            archive,
            "interactive",
            b"1\n" if request.interactive else b"0\n",
        )
        _tar_add(
            archive,
            "result-limits",
            (
                f"{limits.max_stdout_bytes}\n"
                f"{limits.max_stderr_bytes}\n"
                f"{limits.max_remote_capture_bytes}\n"
            ).encode("ascii"),
        )
        if request.mode is ExecutionMode.ARGV:
            _tar_add(
                archive,
                "argv.bin",
                b"".join(os.fsencode(argument) + b"\0" for argument in request.argv),
            )
        else:
            _tar_add(archive, "payload.sh", request.script)
        _tar_add(archive, "remote_runner.sh", _asset("remote_runner.sh"))
        _tar_add(archive, "remote_control.sh", _asset("remote_control.sh"))
    content = stream.getvalue()
    if len(content) > MAX_STAGE_ARCHIVE_BYTES:
        raise RemoteJobError("staging archive exceeds the configured limit")
    return content


class LocalCollectionBudget:
    """Reserve aggregate local temporary bytes across concurrent jobs."""

    def __init__(self, max_bytes: int) -> None:
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError("aggregate collection limit must be positive")
        self.max_bytes = max_bytes
        self._used = 0
        self._lock = threading.Lock()

    def reserve(self, size: int) -> "_CollectionReservation":
        if type(size) is not int or size < 0:
            raise RemoteJobError("local collection reservation is invalid")
        with self._lock:
            if size > self.max_bytes - self._used:
                raise RemoteJobError(
                    "aggregate local collection space limit would be exceeded"
                )
            self._used += size
        return _CollectionReservation(self, size)

    def _release(self, size: int) -> None:
        with self._lock:
            if not 0 <= size <= self._used:
                raise RuntimeError("local collection reservation accounting failed")
            self._used -= size


def prepare_collection_directory(path: Path) -> Path:
    """Create the private root and remove only proven stale collection temps."""

    root = ensure_private_directory(path)
    root_fd = os.open(
        root,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        for name in os.listdir(root_fd):
            if _COLLECTION_TEMP_RE.fullmatch(name) is None:
                raise RemoteJobError(
                    f"unexpected entry in local collection directory: {name}"
                )
            directory_fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            try:
                metadata = os.fstat(directory_fd)
                entries = set(os.listdir(directory_fd))
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                    or not entries.issubset({"stdout.raw", "stderr.raw"})
                ):
                    raise RemoteJobError("stale local collection directory is unsafe")
                for entry in entries:
                    file_metadata = os.stat(
                        entry, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if (
                        not stat.S_ISREG(file_metadata.st_mode)
                        or file_metadata.st_uid != os.getuid()
                        or stat.S_IMODE(file_metadata.st_mode) != 0o600
                    ):
                        raise RemoteJobError("stale local collection file is unsafe")
                for entry in entries:
                    os.unlink(entry, dir_fd=directory_fd)
            finally:
                os.close(directory_fd)
            os.rmdir(name, dir_fd=root_fd)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    return root


class _CollectionReservation:
    def __init__(self, budget: LocalCollectionBudget, size: int) -> None:
        self._budget = budget
        self._size = size
        self._released = False

    def release(self) -> None:
        if not self._released:
            self._budget._release(self._size)
            self._released = True


class RealRemoteJobBackend(RemoteJobBackend):
    def __init__(
        self,
        transport: MasterTransport,
        *,
        channels: SshChannelRunner | None = None,
        secret_input_recipient: SecretInputRecipient | None = None,
        attach_timeout_seconds: float = 10,
        viewer_dir: Path | None = None,
        collection_dir: Path | None = None,
        limits: ResultLimits = ResultLimits(),
        collection_budget: LocalCollectionBudget | None = None,
    ) -> None:
        self.transport = transport
        self.channels = SshChannelRunner() if channels is None else channels
        if secret_input_recipient is not None:
            if not isinstance(secret_input_recipient, SecretInputRecipient):
                raise TypeError(
                    "secret_input_recipient must be a SecretInputRecipient"
                )
            if (
                not isinstance(transport, MasterTransport)
                or transport.machine_name
                != secret_input_recipient.request.machine_alias
                or transport.endpoint.endpoint_id
                != secret_input_recipient.endpoint_id
                or transport.connection_plan_sha256
                != secret_input_recipient.connection_plan.plan_sha256
            ):
                raise RemoteJobError(
                    "secret-input recipient does not match the acquired transport"
                )
        self.secret_input_recipient = secret_input_recipient
        self.attach_timeout_seconds = float(attach_timeout_seconds)
        self.viewer_dir = viewer_dir
        self.collection_dir = collection_dir
        self.limits = limits
        self.collection_budget = (
            LocalCollectionBudget(limits.max_aggregate_collection_bytes)
            if collection_budget is None
            else collection_budget
        )

    def _batch_prefix(self) -> tuple[str, ...]:
        return build_batch_channel_prefix(
            self.transport.endpoint,
            self.transport.control_path,
        ).argv

    def _viewer_prefix(self) -> tuple[str, ...]:
        return build_viewer_channel_prefix(
            self.transport.endpoint,
            self.transport.control_path,
        ).argv

    @staticmethod
    def _control_command(identity: RemoteJobIdentity, operation: str) -> str:
        if operation not in {
            "validate", "create", "observe", "release",
            "attach", "collect-stdout", "collect-stderr", "cleanup",
        }:
            raise RemoteJobError("unsupported remote control operation")
        request_id = identity.request_id
        path = f"$HOME/.cache/tmuxgate/jobs/{request_id}/remote_control.sh"
        return f'/bin/bash "{path}" {operation} {request_id}'

    def _batch(
        self,
        identity: RemoteJobIdentity,
        operation: str,
        *,
        input_bytes: bytes = b"",
        timeout_seconds: float = 30,
    ) -> bytes:
        result = self.channels.batch(
            (*self._batch_prefix(), self._control_command(identity, operation)),
            input_bytes=input_bytes,
            timeout_seconds=timeout_seconds,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "backslashreplace").strip()
            if len(detail) > 500:
                detail = detail[:500] + "..."
            raise RemoteJobError(
                f"remote {operation} failed with status {result.returncode}"
                + (f": {detail}" if detail else "")
            )
        return result.stdout

    def stage(self, identity: RemoteJobIdentity, request: RequestSpec) -> None:
        archive = build_stage_archive(request, self.limits)
        command = (
            "/bin/bash -c "
            + shlex.quote(_STAGE_SCRIPT)
            + " tmuxgate-stage "
            + identity.request_id
        )
        result = self.channels.batch(
            (*self._batch_prefix(), command),
            input_bytes=archive,
            timeout_seconds=60,
        )
        if result.returncode != 0:
            raise RemoteJobError(
                f"remote staging failed with status {result.returncode}"
            )

    def create_gated_session(self, identity: RemoteJobIdentity) -> None:
        self._batch(identity, "create", timeout_seconds=15)

    def attach(self, identity: RemoteJobIdentity) -> ViewerProcess:
        argv = (*self._viewer_prefix(), self._control_command(identity, "attach"))
        if self.viewer_dir is None:
            viewer = self.channels.viewer(argv)
        else:
            viewer = self.channels.detached_viewer(
                argv,
                socket_path=self.viewer_dir / f"{identity.request_id}.sock",
                session_name=f"tmuxgate-{identity.request_id[:12]}",
                secret_input_recipient=self.secret_input_recipient,
            )
        deadline = time.monotonic() + self.attach_timeout_seconds
        while time.monotonic() < deadline:
            if not viewer.attached:
                viewer.close()
                raise RemoteJobError("interactive viewer exited before attachment")
            observation = self.observe(identity)
            if observation.attached_clients >= 1:
                return viewer
            time.sleep(0.05)
        if viewer.attached:
            viewer.terminate()
            viewer.wait(timeout=2)
        raise RemoteJobError("interactive viewer attachment timed out")

    @staticmethod
    def _parse_observation(content: bytes) -> RemoteObservation:
        try:
            text = content.decode("ascii")
        except UnicodeDecodeError as exc:
            raise RemoteJobError("remote observation is not ASCII") from exc
        values: dict[str, str] = {}
        for line in text.splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in values:
                raise RemoteJobError("remote observation is malformed")
            values[key] = value
        expected = {
            "session_exists", "attached_clients", "gate_released",
            "command_running", "completion_proven", "exit_status",
            "stdout_size", "stderr_size", "stdout_sha256", "stderr_sha256",
        }
        if set(values) != expected:
            raise RemoteJobError("remote observation fields are incomplete")

        def boolean(name: str) -> bool:
            if values[name] not in {"0", "1"}:
                raise RemoteJobError(f"remote observation {name} is invalid")
            return values[name] == "1"

        def optional_integer(name: str) -> int | None:
            value = values[name]
            if value == "":
                return None
            if not value.isascii() or not value.isdigit():
                raise RemoteJobError(f"remote observation {name} is invalid")
            return int(value)

        return RemoteObservation(
            session_exists=boolean("session_exists"),
            attached_clients=optional_integer("attached_clients") or 0,
            gate_released=boolean("gate_released"),
            command_running=boolean("command_running"),
            completion_proven=boolean("completion_proven"),
            exit_status=optional_integer("exit_status"),
            stdout_size=optional_integer("stdout_size"),
            stderr_size=optional_integer("stderr_size"),
            stdout_sha256=values["stdout_sha256"] or None,
            stderr_sha256=values["stderr_sha256"] or None,
        )

    def observe(self, identity: RemoteJobIdentity) -> RemoteObservation:
        self.channels.raise_automatic_secret_failure(identity.request_id)
        return self._parse_observation(self._batch(identity, "observe"))

    def release_gate(self, identity: RemoteJobIdentity) -> None:
        self._batch(identity, "release")

    def collect(self, identity: RemoteJobIdentity) -> CollectedRemoteFiles:
        observation = self.observe(identity)
        if (
            not observation.completion_proven
            or observation.attached_clients != 0
            or observation.stdout_size is None
            or observation.stderr_size is None
            or observation.stdout_sha256 is None
            or observation.stderr_sha256 is None
            or observation.exit_status is None
        ):
            raise RemoteJobError("remote collection lacks complete detached evidence")
        total = observation.stdout_size + observation.stderr_size
        if observation.stdout_size > self.limits.max_stdout_bytes:
            raise RemoteJobError("remote stdout exceeds the configured limit")
        if observation.stderr_size > self.limits.max_stderr_bytes:
            raise RemoteJobError("remote stderr exceeds the configured limit")
        if total > self.limits.max_total_result_bytes:
            raise RemoteJobError("remote result exceeds the configured total limit")
        if total > self.limits.max_local_collection_bytes:
            raise RemoteJobError("remote result exceeds local collection space limit")
        if self.collection_dir is None:
            raise RemoteJobError("local collection directory is unavailable")

        reservation = self.collection_budget.reserve(total)
        temporary: Path | None = None

        def cleanup() -> None:
            try:
                if temporary is not None:
                    for name in ("stdout.raw", "stderr.raw"):
                        try:
                            os.unlink(temporary / name)
                        except FileNotFoundError:
                            pass
                    try:
                        os.rmdir(temporary)
                    except FileNotFoundError:
                        pass
            finally:
                reservation.release()

        try:
            temporary = Path(tempfile.mkdtemp(
                prefix=f".{identity.request_id}.",
                dir=self.collection_dir,
            ))
            os.chmod(temporary, 0o700)
            metadata = temporary.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise RemoteJobError("local collection directory is unsafe")

            received = {}
            for stream, expected_size, expected_sha256 in (
                ("stdout", observation.stdout_size, observation.stdout_sha256),
                ("stderr", observation.stderr_size, observation.stderr_sha256),
            ):
                path = temporary / f"{stream}.raw"
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                descriptor = os.open(path, flags, 0o600)
                with os.fdopen(descriptor, "wb", buffering=0) as destination:
                    file_metadata = os.fstat(destination.fileno())
                    if (
                        not stat.S_ISREG(file_metadata.st_mode)
                        or file_metadata.st_uid != os.getuid()
                        or stat.S_IMODE(file_metadata.st_mode) != 0o600
                    ):
                        raise RemoteJobError("local collection file is unsafe")
                    streamed = self.channels.batch_to_file(
                        (*self._batch_prefix(), self._control_command(
                            identity, f"collect-{stream}"
                        )),
                        destination,
                        max_output_bytes=expected_size,
                        timeout_seconds=60,
                    )
                    if streamed.returncode != 0:
                        detail = streamed.stderr.decode(
                            "utf-8", "backslashreplace"
                        ).strip()[:500]
                        raise RemoteJobError(
                            f"remote {stream} collection failed with status "
                            f"{streamed.returncode}"
                            + (f": {detail}" if detail else "")
                        )
                    os.fsync(destination.fileno())
                if (
                    streamed.size != expected_size
                    or streamed.sha256 != expected_sha256
                ):
                    raise RemoteJobError(
                        f"streamed remote {stream} does not match completion evidence"
                    )
                received[stream] = streamed
            directory_fd = os.open(
                temporary,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return CollectedRemoteFiles(
                stdout_path=temporary / "stdout.raw",
                stderr_path=temporary / "stderr.raw",
                stdout_size=received["stdout"].size,
                stderr_size=received["stderr"].size,
                stdout_sha256=received["stdout"].sha256,
                stderr_sha256=received["stderr"].sha256,
                exit_status=observation.exit_status,
                _cleanup=cleanup,
            )
        except BaseException:
            cleanup()
            raise

    def cleanup(self, identity: RemoteJobIdentity) -> None:
        self._batch(identity, "cleanup")
