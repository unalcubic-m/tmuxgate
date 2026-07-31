import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest

from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.real_remote import RealRemoteJobBackend, build_stage_archive


REQUEST_ID = "0123456789abcdef0123456789abcdef"


@unittest.skipUnless(shutil.which("tmux") and shutil.which("script"), "tmux and script required")
class LocalRealTmuxIntegrationTests(unittest.TestCase):
    def test_real_scripts_gate_capture_collect_cleanup_and_leave_base_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            job = home / ".cache/tmuxgate/jobs" / REQUEST_ID
            job.mkdir(parents=True, mode=0o700)
            job.parent.chmod(0o700)
            job.parent.parent.chmod(0o700)
            request = RequestSpec(
                "app-server",
                ExecutionMode.ARGV,
                os.fspath(job),
                argv=(
                    "/bin/bash",
                    "-c",
                    "printf 'stdout-line\\n'; printf 'stderr-line\\n' >&2; exit 7",
                ),
            )
            archive_path = root / "stage.tar"
            archive_path.write_bytes(build_stage_archive(request))
            with tarfile.open(archive_path, mode="r:") as archive:
                archive.extractall(job, filter="data")
            for entry in job.iterdir():
                entry.chmod(0o600)

            socket_name = f"tmuxgate-test-{os.getpid()}-{time.monotonic_ns()}"
            wrapper = root / "tmux-wrapper"
            wrapper.write_text(
                f"#!/bin/sh\nexec /usr/bin/tmux -L {socket_name} \"$@\"\n",
                encoding="ascii",
            )
            wrapper.chmod(0o700)
            environment = {
                "HOME": os.fspath(home),
                "PATH": "/usr/bin:/bin",
                "TERM": "xterm-256color",
                "TMUXGATE_TMUX_BIN": os.fspath(wrapper),
            }
            control = job / "remote_control.sh"

            def run(operation, *, timeout=10):
                return subprocess.run(
                    ["/bin/bash", os.fspath(control), operation, REQUEST_ID],
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    check=False,
                )

            viewer = None
            try:
                subprocess.run(
                    [os.fspath(wrapper), "new-session", "-d", "-s", "base", "/bin/sleep", "30"],
                    env=environment,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assertEqual(run("validate").returncode, 0)
                created = run("create")
                self.assertEqual(created.returncode, 0, created.stderr)
                session = f"tmuxgate-{REQUEST_ID[:12]}"
                viewer_command = (
                    f"{shlex.quote(os.fspath(wrapper))} attach-session -t {session}"
                )
                viewer = subprocess.Popen(
                    ["/usr/bin/script", "-qefc", viewer_command, "/dev/null"],
                    env=environment,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    observed = run("observe")
                    if b"attached_clients=1\n" in observed.stdout:
                        break
                    time.sleep(0.05)
                else:
                    self.fail("viewer did not attach")
                self.assertEqual(run("release").returncode, 0)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    observed = run("observe")
                    if b"completion_proven=1\n" in observed.stdout:
                        break
                    time.sleep(0.05)
                else:
                    self.fail("job did not complete")
                viewer.wait(timeout=5)
                if viewer.stdin is not None:
                    viewer.stdin.close()
                ended = subprocess.run(
                    [os.fspath(wrapper), "has-session", "-t", session],
                    env=environment,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assertNotEqual(ended.returncode, 0)
                collected = run("collect")
                self.assertEqual(collected.returncode, 0, collected.stderr)
                result = RealRemoteJobBackend._parse_collection(collected.stdout)
                self.assertEqual(
                    (result.stdout, result.stderr, result.exit_status),
                    (b"stdout-line\n", b"stderr-line\n", 7),
                )
                self.assertEqual(run("cleanup").returncode, 0)
                base = subprocess.run(
                    [os.fspath(wrapper), "has-session", "-t", "base"],
                    env=environment,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self.assertEqual(base.returncode, 0)
            finally:
                if viewer is not None and viewer.poll() is None:
                    viewer.terminate()
                    viewer.wait(timeout=5)
                if viewer is not None and viewer.stdin is not None and not viewer.stdin.closed:
                    viewer.stdin.close()
                subprocess.run(
                    [os.fspath(wrapper), "kill-server"],
                    env=environment,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )


if __name__ == "__main__":
    unittest.main()
