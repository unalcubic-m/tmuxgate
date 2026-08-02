import hashlib
from io import BytesIO
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import threading
import unittest

from tmuxgate.config import ResultLimits
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.real_remote import (
    LocalCollectionBudget,
    RealRemoteJobBackend,
    _STAGE_SCRIPT,
    build_stage_archive,
    prepare_collection_directory,
)
from tmuxgate.real_ssh import StreamBatchResult
from tmuxgate.remote_job import RemoteJobError, RemoteJobIdentity, RemoteObservation
from tmuxgate.transport import TransportError


REQUEST_ID = "0123456789abcdef0123456789abcdef"


class StageArchiveTests(unittest.TestCase):
    def _members(self, content):
        with tarfile.open(fileobj=BytesIO(content), mode="r:") as archive:
            return {
                member.name: archive.extractfile(member).read()
                for member in archive.getmembers()
            }

    def test_argv_environment_cwd_and_timeout_are_exact_structured_bytes(self):
        request = RequestSpec(
            machine_alias="app-server",
            mode=ExecutionMode.ARGV,
            cwd="/tmp/space dir",
            argv=("printf", "a b", "'\"$;\nünicode"),
            environment=(("NAME", "value $;\nö"),),
            timeout_seconds=17,
        )
        members = self._members(build_stage_archive(request))
        self.assertEqual(members["cwd.bin"], os.fsencode(request.cwd) + b"\0")
        self.assertEqual(
            members["argv.bin"],
            b"".join(os.fsencode(value) + b"\0" for value in request.argv),
        )
        self.assertEqual(members["environment.bin"], b"NAME\0value $;\n\xc3\xb6\0")
        self.assertEqual(members["timeout"], b"17\n")
        self.assertEqual(members["mode"], b"exec\n")
        self.assertIn(b"wait-for", members["remote_runner.sh"])

    def test_script_bytes_are_not_decoded_or_requoted(self):
        script = b"#!/bin/bash\nprintf '\xff\\n'\nexit 7\n"
        request = RequestSpec(
            machine_alias="app-server",
            mode=ExecutionMode.SCRIPT,
            cwd="/tmp",
            script=script,
        )
        members = self._members(build_stage_archive(request))
        self.assertEqual(members["payload.sh"], script)
        self.assertNotIn("argv.bin", members)

    def test_fixed_staging_shell_creates_only_private_validated_job(self):
        request = RequestSpec(
            machine_alias="app-server",
            mode=ExecutionMode.ARGV,
            cwd="/tmp",
            argv=("/bin/true",),
        )
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            home.mkdir(mode=0o700)
            completed = subprocess.run(
                ["/bin/bash", "-c", _STAGE_SCRIPT, "tmuxgate-stage", REQUEST_ID],
                input=build_stage_archive(request),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"HOME": os.fspath(home), "PATH": "/usr/bin:/bin"},
                timeout=5,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            job = home / ".cache/tmuxgate/jobs" / REQUEST_ID
            self.assertEqual(job.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all((item.stat().st_mode & 0o777) == 0o600 for item in job.iterdir()))


class RemoteParsingTests(unittest.TestCase):
    def test_control_command_contains_only_validated_identity(self):
        identity = RemoteJobIdentity.for_request(REQUEST_ID)
        command = RealRemoteJobBackend._control_command(identity, "observe")
        self.assertEqual(
            command,
            f'/bin/bash "$HOME/.cache/tmuxgate/jobs/{REQUEST_ID}/remote_control.sh" '
            f"observe {REQUEST_ID}",
        )
        with self.assertRaises(RemoteJobError):
            RealRemoteJobBackend._control_command(identity, "observe; id")

    def test_observation_is_strict_and_preserves_exit_status(self):
        stdout = b"out"
        stderr = b"err"
        content = (
            b"session_exists=1\nattached_clients=0\ngate_released=1\n"
            b"command_running=0\ncompletion_proven=1\nexit_status=7\n"
            b"stdout_size=3\nstderr_size=3\nstdout_sha256="
            + hashlib.sha256(stdout).hexdigest().encode("ascii")
            + b"\nstderr_sha256="
            + hashlib.sha256(stderr).hexdigest().encode("ascii")
            + b"\n"
        )
        observed = RealRemoteJobBackend._parse_observation(content)
        self.assertTrue(observed.completion_proven)
        self.assertEqual(observed.exit_status, 7)
        with self.assertRaises(RemoteJobError):
            RealRemoteJobBackend._parse_observation(content + b"extra=1\n")

    def test_collection_uses_separate_fixed_stream_operations(self):
        identity = RemoteJobIdentity.for_request(REQUEST_ID)
        stdout = RealRemoteJobBackend._control_command(identity, "collect-stdout")
        stderr = RealRemoteJobBackend._control_command(identity, "collect-stderr")
        self.assertIn(" collect-stdout ", stdout)
        self.assertIn(" collect-stderr ", stderr)
        with self.assertRaises(RemoteJobError):
            RealRemoteJobBackend._control_command(identity, "collect")


class StreamingCollectionTests(unittest.TestCase):
    def test_collection_startup_removes_only_safe_stale_temporaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "collections"
            root.mkdir(mode=0o700)
            stale = root / f".{REQUEST_ID}.abcdef12"
            stale.mkdir(mode=0o700)
            stream = stale / "stdout.raw"
            stream.write_bytes(b"partial")
            stream.chmod(0o600)
            self.assertEqual(prepare_collection_directory(root), root)
            self.assertEqual(list(root.iterdir()), [])

            unsafe = root / "unexpected"
            unsafe.write_bytes(b"do not delete")
            with self.assertRaisesRegex(RemoteJobError, "unexpected entry"):
                prepare_collection_directory(root)
            self.assertEqual(unsafe.read_bytes(), b"do not delete")

    class Channels:
        def __init__(self, stdout=b"out", stderr=b"err", *, truncate=False, fail=False):
            self.streams = {"stdout": stdout, "stderr": stderr}
            self.truncate = truncate
            self.fail = fail
            self.operations = []

        def batch_to_file(self, argv, destination, *, max_output_bytes, timeout_seconds):
            del timeout_seconds
            operation = "stdout" if "collect-stdout" in argv[-1] else "stderr"
            self.operations.append(operation)
            if self.fail:
                raise TransportError("injected local stream failure")
            content = self.streams[operation]
            if self.truncate:
                content = content[:-1]
            if len(content) > max_output_bytes:
                raise TransportError("stream exceeds configured limit")
            destination.write(content)
            return StreamBatchResult(
                b"",
                0,
                len(content),
                hashlib.sha256(content).hexdigest(),
            )

    class Backend(RealRemoteJobBackend):
        def __init__(self, observation, **kwargs):
            super().__init__(object(), **kwargs)
            self._observation = observation

        def _batch_prefix(self):
            return ("ssh",)

        def observe(self, identity):
            del identity
            return self._observation

    @staticmethod
    def _observation(stdout, stderr):
        return RemoteObservation(
            session_exists=False,
            attached_clients=0,
            gate_released=True,
            command_running=False,
            completion_proven=True,
            exit_status=7,
            stdout_size=len(stdout),
            stderr_size=len(stderr),
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        )

    def test_collection_streams_to_private_files_and_releases_reservation(self):
        stdout = b"stdout\x00\xff"
        stderr = b"stderr\x00\xfe"
        channels = self.Channels(stdout, stderr)
        with tempfile.TemporaryDirectory() as directory:
            collection_dir = Path(directory) / "collections"
            collection_dir.mkdir(mode=0o700)
            budget = LocalCollectionBudget(len(stdout) + len(stderr))
            backend = self.Backend(
                self._observation(stdout, stderr),
                channels=channels,
                collection_dir=collection_dir,
                collection_budget=budget,
            )
            result = backend.collect(RemoteJobIdentity.for_request(REQUEST_ID))
            self.assertEqual(channels.operations, ["stdout", "stderr"])
            self.assertEqual(result.stdout_path.read_bytes(), stdout)
            self.assertEqual(result.stderr_path.read_bytes(), stderr)
            self.assertEqual(result.stdout_path.stat().st_mode & 0o777, 0o600)
            temporary = result.stdout_path.parent
            self.assertEqual(temporary.stat().st_mode & 0o777, 0o700)
            result.close()
            self.assertFalse(temporary.exists())
            reservation = budget.reserve(len(stdout) + len(stderr))
            reservation.release()

    def test_collection_limits_accept_boundary_and_reject_one_over(self):
        with tempfile.TemporaryDirectory() as directory:
            collection_dir = Path(directory)
            limits = ResultLimits(
                max_stdout_bytes=3,
                max_stderr_bytes=3,
                max_total_result_bytes=6,
                max_local_collection_bytes=6,
                max_remote_capture_bytes=6,
                max_aggregate_collection_bytes=6,
            )
            exact = self.Backend(
                self._observation(b"out", b"err"),
                channels=self.Channels(),
                collection_dir=collection_dir,
                limits=limits,
            ).collect(RemoteJobIdentity.for_request(REQUEST_ID))
            exact.close()
            below = self.Backend(
                self._observation(b"ou", b"er"),
                channels=self.Channels(b"ou", b"er"),
                collection_dir=collection_dir,
                limits=limits,
            ).collect(RemoteJobIdentity.for_request(REQUEST_ID))
            below.close()
            oversized = self.Backend(
                self._observation(b"four", b""),
                channels=self.Channels(b"four", b""),
                collection_dir=collection_dir,
                limits=limits,
            )
            with self.assertRaisesRegex(RemoteJobError, "stdout exceeds"):
                oversized.collect(RemoteJobIdentity.for_request(REQUEST_ID))

            cases = (
                (
                    "stderr",
                    self._observation(b"", b"four"),
                    limits,
                    "stderr exceeds",
                ),
                (
                    "total",
                    self._observation(b"out", b"err"),
                    ResultLimits(
                        max_stdout_bytes=3,
                        max_stderr_bytes=3,
                        max_total_result_bytes=5,
                        max_local_collection_bytes=6,
                        max_remote_capture_bytes=6,
                        max_aggregate_collection_bytes=6,
                    ),
                    "total limit",
                ),
                (
                    "local",
                    self._observation(b"out", b"err"),
                    ResultLimits(
                        max_stdout_bytes=3,
                        max_stderr_bytes=3,
                        max_total_result_bytes=6,
                        max_local_collection_bytes=5,
                        max_remote_capture_bytes=6,
                        max_aggregate_collection_bytes=6,
                    ),
                    "local collection",
                ),
            )
            for name, observation, case_limits, message in cases:
                with self.subTest(name=name):
                    backend = self.Backend(
                        observation,
                        channels=self.Channels(b"out", b"four"),
                        collection_dir=collection_dir,
                        limits=case_limits,
                    )
                    with self.assertRaisesRegex(RemoteJobError, message):
                        backend.collect(RemoteJobIdentity.for_request(REQUEST_ID))

    def test_truncated_or_interrupted_collection_never_returns_files(self):
        stdout = b"out"
        stderr = b"err"
        for channels in (
            self.Channels(stdout, stderr, truncate=True),
            self.Channels(stdout, stderr, fail=True),
        ):
            with self.subTest(channels=channels.__dict__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                backend = self.Backend(
                    self._observation(stdout, stderr),
                    channels=channels,
                    collection_dir=root,
                )
                with self.assertRaises((RemoteJobError, TransportError)):
                    backend.collect(RemoteJobIdentity.for_request(REQUEST_ID))
                self.assertEqual(list(root.iterdir()), [])

    def test_parallel_reservations_cannot_exceed_aggregate_limit(self):
        budget = LocalCollectionBudget(5)
        start = threading.Barrier(4)
        release = threading.Event()
        outcomes = []

        def reserve():
            start.wait()
            try:
                reservation = budget.reserve(3)
            except RemoteJobError:
                outcomes.append("rejected")
            else:
                outcomes.append("reserved")
                release.wait(2)
                reservation.release()

        threads = [threading.Thread(target=reserve) for _ in range(3)]
        for thread in threads:
            thread.start()
        start.wait()
        poll = threading.Event()
        while len(outcomes) < 3:
            poll.wait(0.001)
        release.set()
        for thread in threads:
            thread.join(2)
        self.assertEqual(
            sorted(outcomes),
            ["rejected", "rejected", "reserved"],
        )


if __name__ == "__main__":
    unittest.main()
