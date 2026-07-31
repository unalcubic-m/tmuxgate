"""Real remote tmux job backend over one authenticated SSH master."""

from __future__ import annotations

from io import BytesIO
from importlib import resources
import os
from pathlib import Path
import shlex
import tarfile
import time

from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.real_ssh import SshChannelRunner, ViewerProcess
from tmuxgate.remote_job import (
    CollectedRemoteResult,
    RemoteJobBackend,
    RemoteJobError,
    RemoteJobIdentity,
    RemoteObservation,
)
from tmuxgate.transport import (
    MasterTransport,
    build_batch_channel_prefix,
    build_viewer_channel_prefix,
)


MAX_STAGE_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_COLLECT_ARCHIVE_BYTES = 300 * 1024 * 1024

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


def build_stage_archive(request: RequestSpec) -> bytes:
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


class RealRemoteJobBackend(RemoteJobBackend):
    def __init__(
        self,
        transport: MasterTransport,
        *,
        channels: SshChannelRunner | None = None,
        attach_timeout_seconds: float = 10,
        viewer_dir: Path | None = None,
    ) -> None:
        self.transport = transport
        self.channels = SshChannelRunner() if channels is None else channels
        self.attach_timeout_seconds = float(attach_timeout_seconds)
        self.viewer_dir = viewer_dir

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
            "attach", "collect", "cleanup",
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
        archive = build_stage_archive(request)
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
        return self._parse_observation(self._batch(identity, "observe"))

    def release_gate(self, identity: RemoteJobIdentity) -> None:
        self._batch(identity, "release")

    @staticmethod
    def _parse_collection(content: bytes) -> CollectedRemoteResult:
        if len(content) > MAX_COLLECT_ARCHIVE_BYTES:
            raise RemoteJobError("remote collection archive exceeds the configured limit")
        expected = {"stdout.raw", "stderr.raw", "exit-code", "state"}
        extracted: dict[str, bytes] = {}
        try:
            with tarfile.open(fileobj=BytesIO(content), mode="r:") as archive:
                for member in archive.getmembers():
                    if (
                        member.name not in expected
                        or not member.isfile()
                        or member.name in extracted
                        or member.size < 0
                    ):
                        raise RemoteJobError("remote collection archive is unsafe")
                    source = archive.extractfile(member)
                    if source is None:
                        raise RemoteJobError("remote collection member is unreadable")
                    extracted[member.name] = source.read()
        except tarfile.TarError as exc:
            raise RemoteJobError("remote collection is not a valid tar archive") from exc
        if set(extracted) != expected or extracted["state"] != b"complete\n":
            raise RemoteJobError("remote collection is incomplete")
        try:
            exit_status = int(extracted["exit-code"].decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as exc:
            raise RemoteJobError("remote exit status is invalid") from exc
        return CollectedRemoteResult(
            extracted["stdout.raw"],
            extracted["stderr.raw"],
            exit_status,
        )

    def collect(self, identity: RemoteJobIdentity) -> CollectedRemoteResult:
        return self._parse_collection(
            self._batch(identity, "collect", timeout_seconds=60)
        )

    def cleanup(self, identity: RemoteJobIdentity) -> None:
        self._batch(identity, "cleanup")
