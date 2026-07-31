import hashlib
from io import BytesIO
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.real_remote import RealRemoteJobBackend, _STAGE_SCRIPT, build_stage_archive
from tmuxgate.remote_job import RemoteJobError, RemoteJobIdentity


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

    def test_collection_rejects_links_and_accepts_exact_regular_members(self):
        stream = BytesIO()
        values = {
            "stdout.raw": b"out\n",
            "stderr.raw": b"err\n",
            "exit-code": b"7\n",
            "state": b"complete\n",
        }
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, value in values.items():
                info = tarfile.TarInfo(name)
                info.size = len(value)
                archive.addfile(info, BytesIO(value))
        result = RealRemoteJobBackend._parse_collection(stream.getvalue())
        self.assertEqual((result.stdout, result.stderr, result.exit_status), (b"out\n", b"err\n", 7))

        stream = BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            link = tarfile.TarInfo("stdout.raw")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            archive.addfile(link)
        with self.assertRaises(RemoteJobError):
            RealRemoteJobBackend._parse_collection(stream.getvalue())


if __name__ == "__main__":
    unittest.main()
