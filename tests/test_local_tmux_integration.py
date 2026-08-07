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
from tmuxgate.real_remote import build_stage_archive
from tmuxgate.real_ssh import secret_prompt_signature


REQUEST_ID = "0123456789abcdef0123456789abcdef"
INTERACTIVE_REQUEST_ID = "fedcba9876543210fedcba9876543210"

# A distinctive value that must never reach a captured stream, the viewer pane,
# or a durable job file.
SENTINEL_SECRET = "tmuxgate-sentinel-secret-8f21c4"

# Read the reply exactly the way sudo does: prompt and reply both travel over
# the controlling terminal with echo disabled, so neither can enter the
# separately captured stdout/stderr streams.
_TTY_SECRET_READER = (
    "exec 9<>/dev/tty || exit 90; "
    "/usr/bin/stty -echo <&9; "
    "printf '[sudo] password for tester: ' >&9; "
    "IFS= read -r reply <&9; "
    "/usr/bin/stty echo <&9; "
    "printf '\\n' >&9; "
)


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
                    "(trap 'exit 0' TERM; sleep 30) 2>/dev/null & "
                    "printf 'stdout-path=%s\\n' \"$PATH\"; "
                    "printf 'stderr-line\\n' >&2; exit 7",
                ),
                environment={"PATH": "/request-controlled-path"},
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
                collected_stdout = run("collect-stdout")
                collected_stderr = run("collect-stderr")
                self.assertEqual(
                    collected_stdout.returncode, 0, collected_stdout.stderr
                )
                self.assertEqual(
                    collected_stderr.returncode, 0, collected_stderr.stderr
                )
                self.assertEqual(
                    (
                        collected_stdout.stdout,
                        collected_stderr.stdout,
                        b"exit_status=7\n" in observed.stdout,
                    ),
                    (
                        b"stdout-path=/request-controlled-path\n",
                        b"stderr-line\n",
                        True,
                    ),
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
    def test_interactive_job_takes_its_secret_from_the_real_viewer_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            job = home / ".cache/tmuxgate/jobs" / INTERACTIVE_REQUEST_ID
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
                    _TTY_SECRET_READER
                    + "printf 'secret_length=%s\\n' \"${#reply}\"; "
                    "printf 'stderr-line\\n' >&2; exit 7",
                ),
                interactive=True,
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
            session = f"tmuxgate-{INTERACTIVE_REQUEST_ID[:12]}"

            def run(operation, *, timeout=10):
                return subprocess.run(
                    ["/bin/bash", os.fspath(control), operation, INTERACTIVE_REQUEST_ID],
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    check=False,
                )

            def tmux(*arguments):
                return subprocess.run(
                    [os.fspath(wrapper), *arguments],
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                )

            panes = []

            def prompt_signature():
                """Detect the prompt the way the broker's presenter does."""

                cursor = tmux("display-message", "-p", "-t", session, "#{cursor_y}")
                pane = tmux("capture-pane", "-p", "-t", session)
                if cursor.returncode != 0 or pane.returncode != 0:
                    return None
                panes.append(pane.stdout)
                return secret_prompt_signature(
                    pane.stdout, cursor_y=int(cursor.stdout.strip())
                )

            viewer = None
            try:
                self.assertEqual(run("validate").returncode, 0)
                created = run("create")
                self.assertEqual(created.returncode, 0, created.stderr)
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
                    if b"attached_clients=1\n" in run("observe").stdout:
                        break
                    time.sleep(0.05)
                else:
                    self.fail("viewer did not attach")
                self.assertEqual(run("release").returncode, 0)

                signature = None
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    signature = prompt_signature()
                    if signature is not None:
                        break
                    time.sleep(0.05)
                else:
                    self.fail(f"prompt was not detected; last pane: {panes[-1:]!r}")
                self.assertIn(b"password for tester:", signature)

                self.assertIsNotNone(viewer.stdin)
                assert viewer.stdin is not None
                viewer.stdin.write(SENTINEL_SECRET.encode("ascii") + b"\n")
                viewer.stdin.flush()

                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    observed = run("observe")
                    if b"completion_proven=1\n" in observed.stdout:
                        break
                    prompt_signature()
                    time.sleep(0.05)
                else:
                    self.fail("interactive job did not complete")
                viewer.wait(timeout=5)
                viewer.stdin.close()

                collected_stdout = run("collect-stdout")
                collected_stderr = run("collect-stderr")
                self.assertEqual(collected_stdout.returncode, 0, collected_stdout.stderr)
                self.assertEqual(collected_stderr.returncode, 0, collected_stderr.stderr)
                self.assertEqual(
                    (
                        collected_stdout.stdout,
                        collected_stderr.stdout,
                        b"exit_status=7\n" in observed.stdout,
                    ),
                    (
                        b"secret_length=%d\n" % len(SENTINEL_SECRET),
                        b"stderr-line\n",
                        True,
                    ),
                )
                # The command received the exact reply, yet the reply itself
                # stayed on the terminal: it is absent from both captured
                # streams, from every pane capture an observer could have taken,
                # and from every file the broker later collects.
                secret = SENTINEL_SECRET.encode("ascii")
                self.assertNotIn(secret, collected_stdout.stdout)
                self.assertNotIn(secret, collected_stderr.stdout)
                self.assertTrue(panes)
                for index, pane in enumerate(panes):
                    self.assertNotIn(secret, pane, index)
                for entry in sorted(job.iterdir()):
                    self.assertNotIn(secret, entry.read_bytes(), entry.name)
                self.assertEqual(run("cleanup").returncode, 0)
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
