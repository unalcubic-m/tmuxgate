import os
import hashlib
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.remote_job import (
    CollectedRemoteResult,
    RemoteJobBusyError,
    RemoteJobCoordinator,
    RemoteJobError,
    RemoteJobIdentity,
    RemoteJobState,
    RemoteObservation,
)
from tmuxgate.state import RemoteStartPermit


REQUEST_ID = "89abcdef0123456789abcdef01234567"


class FakeViewer:
    def __init__(self, backend, identity):
        self.backend = backend
        self.identity = identity
        self._attached = True

    @property
    def attached(self):
        return self._attached

    def send_input(self, data):
        if not self._attached:
            raise RuntimeError("detached")
        self.backend.inputs.append(bytes(data))

    def send_ctrl_c(self):
        if not self._attached:
            raise RuntimeError("detached")
        self.backend.ctrl_c_count += 1

    def detach(self):
        if self._attached:
            self._attached = False
            self.backend.attached -= 1


class FakeRemoteBackend:
    def __init__(self):
        self.staged = False
        self.session = False
        self.gate = False
        self.running = False
        self.attached = 0
        self.result = None
        self.inputs = []
        self.ctrl_c_count = 0
        self.events = []
        self.attach_proven = True
        self.collected_override = None

    def stage(self, identity, request):
        self.staged = True
        self.events.append("stage")

    def create_gated_session(self, identity):
        if not self.staged:
            raise RuntimeError("not staged")
        self.session = True
        self.events.append("create-gated")

    def attach(self, identity):
        self.events.append("attach")
        viewer = FakeViewer(self, identity)
        if self.attach_proven:
            self.attached += 1
        else:
            viewer._attached = False
        return viewer

    def observe(self, identity):
        complete = self.result is not None
        return RemoteObservation(
            session_exists=self.session,
            attached_clients=self.attached,
            gate_released=self.gate,
            command_running=self.running,
            completion_proven=complete,
            exit_status=None if not complete else self.result.exit_status,
            stdout_size=None if not complete else len(self.result.stdout),
            stderr_size=None if not complete else len(self.result.stderr),
            stdout_sha256=None if not complete else hashlib.sha256(self.result.stdout).hexdigest(),
            stderr_sha256=None if not complete else hashlib.sha256(self.result.stderr).hexdigest(),
        )

    def release_gate(self, identity):
        if self.attached < 1:
            raise RuntimeError("no viewer")
        self.gate = True
        self.running = True
        self.events.append("release-gate")

    def complete(self, stdout=b"out", stderr=b"err", exit_status=7):
        self.running = False
        self.result = CollectedRemoteResult(stdout, stderr, exit_status)

    def collect(self, identity):
        self.events.append("collect")
        return self.collected_override or self.result

    def cleanup(self, identity):
        if self.running or self.attached:
            raise RemoteJobBusyError("active")
        self.session = False
        self.events.append("cleanup")


def request():
    return RequestSpec("app-server", ExecutionMode.ARGV, "/", argv=("true",))


def permit(request_id=REQUEST_ID):
    return RemoteStartPermit(request_id, 2, "a" * 64)


class RemoteJobCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.backend = FakeRemoteBackend()
        self.coordinator = RemoteJobCoordinator(self.backend)

    def prepare(self):
        return self.coordinator.prepare(REQUEST_ID, request(), permit())

    def test_job_identity_is_exact_and_cannot_escape_parent(self):
        identity = RemoteJobIdentity.for_request(REQUEST_ID)
        self.assertEqual(identity.job_path, f"~/.cache/tmuxgate/jobs/{REQUEST_ID}")
        self.assertEqual(identity.tmux_session, f"tmuxgate-{REQUEST_ID[:12]}")
        with self.assertRaises(RemoteJobError):
            RemoteJobIdentity(REQUEST_ID, "~/.cache/tmuxgate/jobs/../base", "tmuxgate-89abcdef0123", f"tmuxgate-start-{REQUEST_ID}")

    def test_session_stays_gated_until_viewer_attachment_is_proven(self):
        job = self.prepare()
        self.assertEqual(job.state, RemoteJobState.GATED_WAITING_FOR_VIEWER)
        self.assertFalse(self.backend.gate)
        viewer = self.coordinator.attach_and_start(job)
        self.assertTrue(viewer.attached)
        self.assertEqual(self.backend.events, ["stage", "create-gated", "attach", "release-gate"])
        self.assertEqual(job.state, RemoteJobState.RUNNING_ATTACHED)

    def test_unproven_attachment_never_releases_gate(self):
        job = self.prepare()
        self.backend.attach_proven = False
        with self.assertRaisesRegex(RemoteJobError, "attachment"):
            self.coordinator.attach_and_start(job)
        self.assertFalse(self.backend.gate)
        self.assertEqual(job.state, RemoteJobState.RECOVERY_REQUIRED)

    def test_stuck_job_remains_interactive_and_can_detach_and_reattach(self):
        job = self.prepare()
        viewer = self.coordinator.attach_and_start(job)
        viewer.send_input(b"CONTINUE\n")
        viewer.send_ctrl_c()
        self.assertEqual(self.backend.inputs, [b"CONTINUE\n"])
        self.assertEqual(self.backend.ctrl_c_count, 1)
        viewer.detach()
        self.assertEqual(self.coordinator.refresh(job), RemoteJobState.RUNNING_DETACHED)
        replacement = self.coordinator.reattach(job)
        self.assertTrue(replacement.attached)
        self.assertEqual(job.state, RemoteJobState.RUNNING_ATTACHED)

    def test_completion_waits_for_detach_then_collects_separate_streams_and_exit_seven(self):
        job = self.prepare()
        viewer = self.coordinator.attach_and_start(job)
        self.backend.complete(b"stdout-line\n", b"stderr-line\n", 7)
        self.assertEqual(
            self.coordinator.refresh(job), RemoteJobState.COMPLETE_WAITING_FOR_DETACH
        )
        with self.assertRaises(RemoteJobError):
            self.coordinator.collect(job)
        viewer.detach()
        self.assertEqual(self.coordinator.refresh(job), RemoteJobState.COMPLETE_DETACHED)
        result = self.coordinator.collect(job)
        self.assertEqual(result.stdout, b"stdout-line\n")
        self.assertEqual(result.stderr, b"stderr-line\n")
        self.assertEqual(result.exit_status, 7)
        self.coordinator.cleanup(job)
        self.assertEqual(job.state, RemoteJobState.CLEANED)
        self.assertIsNone(self.coordinator.active)

    def test_collection_mismatch_is_incomplete_and_cleanup_is_refused(self):
        job = self.prepare()
        viewer = self.coordinator.attach_and_start(job)
        self.backend.complete(b"out", b"err", 7)
        viewer.detach()
        self.coordinator.refresh(job)
        self.backend.collected_override = CollectedRemoteResult(b"OUT", b"err", 7)
        with self.assertRaisesRegex(RemoteJobError, "does not match"):
            self.coordinator.collect(job)
        self.assertEqual(job.state, RemoteJobState.RECOVERY_REQUIRED)
        with self.assertRaises(RemoteJobError):
            self.coordinator.cleanup(job)

    def test_missing_session_without_completion_requires_recovery(self):
        job = self.prepare()
        self.coordinator.attach_and_start(job)
        self.backend.session = False
        self.backend.running = False
        self.assertEqual(self.coordinator.refresh(job), RemoteJobState.RECOVERY_REQUIRED)

    def test_wrong_durable_permit_cannot_stage_and_second_job_cannot_overlap(self):
        with self.assertRaisesRegex(RemoteJobError, "another request"):
            self.coordinator.prepare(REQUEST_ID, request(), permit("0" * 32))
        job = self.prepare()
        with self.assertRaises(RemoteJobBusyError):
            self.coordinator.prepare("1" * 32, request(), permit("1" * 32))
        self.assertEqual(job.state, RemoteJobState.GATED_WAITING_FOR_VIEWER)


class RemoteRunnerTests(unittest.TestCase):
    def _run_descendant_case(
        self,
        directory,
        *,
        mode,
        command,
        timeout=b"",
        run_timeout=8,
    ):
        root = Path(directory)
        home = root / "home"
        job = home / ".cache/tmuxgate/jobs" / REQUEST_ID
        job.mkdir(parents=True, mode=0o700)
        marker = root / "descendant-terminated"
        files = {
            "mode": f"{mode}\n".encode("ascii"),
            "cwd.bin": os.fsencode(str(job)) + b"\0",
            "environment.bin": b"MARKER\0" + os.fsencode(marker) + b"\0",
            "timeout": timeout,
            "result-limits": b"1048576\n1048576\n2097152\n",
        }
        if mode == "exec":
            files["argv.bin"] = (
                b"/bin/bash\0--noprofile\0--norc\0-c\0" + command + b"\0"
            )
        else:
            files["payload.sh"] = command + b"\n"
        for name, content in files.items():
            path = job / name
            path.write_bytes(content)
            path.chmod(0o600)
        fake_tmux = root / "fake-tmux"
        fake_tmux.write_text(
            "#!/bin/sh\n[ \"$1\" = wait-for ] || exit 99\nexit 0\n",
            encoding="ascii",
        )
        fake_tmux.chmod(0o700)
        runner = Path(__file__).parents[1] / "src/tmuxgate/assets/remote_runner.sh"
        started = time.monotonic()
        completed = subprocess.run(
            [
                "/bin/bash",
                str(runner),
                str(job),
                f"tmuxgate-start-{REQUEST_ID}",
                str(fake_tmux),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
            timeout=run_timeout,
            check=False,
        )
        return completed, job, marker, time.monotonic() - started

    def test_background_child_retaining_each_stream_is_terminated_for_both_modes(self):
        cases = (
            (
                "stdout",
                b"(trap 'printf terminated > \"$MARKER\"; exit 0' TERM; "
                b"sleep 4) 2>/dev/null & printf primary",
                b"primary",
                b"",
            ),
            (
                "stderr",
                b"(trap 'printf terminated > \"$MARKER\"; exit 0' TERM; "
                b"sleep 4) >/dev/null & printf primary >&2",
                b"",
                b"primary",
            ),
        )
        for mode in ("exec", "script"):
            for stream, command, stdout, stderr in cases:
                with self.subTest(mode=mode, stream=stream), tempfile.TemporaryDirectory() as directory:
                    completed, job, marker, elapsed = self._run_descendant_case(
                        directory,
                        mode=mode,
                        command=command,
                    )
                    self.assertLess(elapsed, 3)
                    self.assertEqual(completed.returncode, 0)
                    self.assertEqual(completed.stdout, stdout)
                    if stream == "stdout":
                        self.assertEqual(completed.stderr, stderr)
                    else:
                        # Bash may report termination of its background job on
                        # the retained stderr before that descriptor closes.
                        self.assertTrue(completed.stderr.startswith(stderr))
                    self.assertEqual((job / "state").read_bytes(), b"complete\n")
                    self.assertEqual((job / "exit-code").read_bytes(), b"0\n")
                    self.assertEqual((job / "stdout.raw").read_bytes(), stdout)
                    self.assertEqual(
                        (job / "stderr.raw").read_bytes(), completed.stderr
                    )
                    self.assertTrue(marker.exists())

    def test_background_child_that_closes_both_streams_preserves_success(self):
        for mode in ("exec", "script"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                completed, job, _marker, elapsed = self._run_descendant_case(
                    directory,
                    mode=mode,
                    command=(
                        b"(exec >/dev/null 2>&1; sleep 4) & printf primary"
                    ),
                )
                self.assertLess(elapsed, 3)
                self.assertEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, b"primary")
                self.assertEqual(completed.stderr, b"")
                self.assertEqual((job / "state").read_bytes(), b"complete\n")
                self.assertEqual((job / "exit-code").read_bytes(), b"0\n")

    def test_detached_descriptor_holder_is_bounded_and_cannot_publish_or_append(self):
        command = (
            b"/usr/bin/setsid --fork /bin/bash --noprofile --norc -c "
            b"'trap \"\" PIPE; sleep 4; printf late || :' 2>/dev/null & "
            b"printf primary"
        )
        with tempfile.TemporaryDirectory() as directory:
            completed, job, _marker, elapsed = self._run_descendant_case(
                directory,
                mode="exec",
                command=command,
            )
            self.assertLess(elapsed, 3.5)
            self.assertEqual(completed.returncode, 125)
            self.assertEqual(completed.stderr, b"")
            self.assertEqual((job / "state").read_bytes(), b"capture-incomplete\n")
            self.assertFalse((job / "exit-code").exists())
            self.assertFalse((job / "stdout.fifo").exists())
            self.assertFalse((job / "stderr.fifo").exists())
            sealed_stdout = (job / "stdout.raw").read_bytes()
            self.assertEqual(completed.stdout, sealed_stdout)
            time.sleep(max(0, 4.5 - elapsed))
            self.assertEqual((job / "stdout.raw").read_bytes(), sealed_stdout)

    def test_timeout_terminates_descendants_that_outlive_the_primary_shell(self):
        command = b"sleep 30 & wait"
        with tempfile.TemporaryDirectory() as directory:
            completed, job, _marker, elapsed = self._run_descendant_case(
                directory,
                mode="script",
                command=command,
                timeout=b"1\n",
            )
            self.assertLess(elapsed, 4)
            self.assertEqual(completed.returncode, 124)
            self.assertEqual((job / "state").read_bytes(), b"complete\n")
            self.assertEqual((job / "exit-code").read_bytes(), b"124\n")
            self.assertFalse((job / "stdout.fifo").exists())
            self.assertFalse((job / "stderr.fifo").exists())

    def test_runner_enforces_stream_and_total_capture_limits(self):
        runner = Path(__file__).parents[1] / "src/tmuxgate/assets/remote_runner.sh"
        cases = (
            ("below", 2, 2, 3, 3, 5, True),
            ("exact", 3, 3, 3, 3, 6, True),
            ("stdout-over", 4, 0, 3, 3, 6, False),
            ("stderr-over", 0, 4, 3, 3, 6, False),
            ("total-over", 3, 4, 4, 4, 6, False),
        )
        for name, stdout_size, stderr_size, stdout_limit, stderr_limit, total, succeeds in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                home = Path(directory) / "home"
                job = home / ".cache/tmuxgate/jobs" / REQUEST_ID
                job.mkdir(parents=True, mode=0o700)
                command = (
                    f"head -c {stdout_size} /dev/zero; "
                    f"head -c {stderr_size} /dev/zero >&2"
                ).encode("ascii")
                files = {
                    "mode": b"exec\n",
                    "cwd.bin": os.fsencode(str(job)) + b"\0",
                    "environment.bin": b"",
                    "timeout": b"5\n",
                    "result-limits": (
                        f"{stdout_limit}\n{stderr_limit}\n{total}\n"
                    ).encode("ascii"),
                    "argv.bin": b"/bin/bash\0-c\0" + command + b"\0",
                }
                for filename, content in files.items():
                    path = job / filename
                    path.write_bytes(content)
                    path.chmod(0o600)
                fake_tmux = Path(directory) / "fake-tmux"
                fake_tmux.write_text(
                    "#!/bin/sh\n[ \"$1\" = wait-for ] || exit 99\nexit 0\n",
                    encoding="ascii",
                )
                fake_tmux.chmod(0o700)
                completed = subprocess.run(
                    [
                        "/bin/bash",
                        str(runner),
                        str(job),
                        f"tmuxgate-start-{REQUEST_ID}",
                        str(fake_tmux),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                    timeout=5,
                    check=False,
                )
                if succeeds:
                    self.assertEqual(completed.returncode, 0)
                    self.assertEqual((job / "state").read_bytes(), b"complete\n")
                    self.assertTrue((job / "exit-code").exists())
                else:
                    self.assertEqual(completed.returncode, 125)
                    self.assertEqual(
                        (job / "state").read_bytes(),
                        b"capture-limit-exceeded\n",
                    )
                    self.assertFalse((job / "exit-code").exists())

    def test_runner_captures_streams_separately_and_preserves_exit_status(self):
        runner = Path(__file__).parents[1] / "src/tmuxgate/assets/remote_runner.sh"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            job = home / ".cache/tmuxgate/jobs" / REQUEST_ID
            job.mkdir(parents=True, mode=0o700)
            (job / "mode").write_text("exec\n", encoding="ascii")
            (job / "cwd.bin").write_bytes(os.fsencode(str(job)) + b"\0")
            (job / "environment.bin").write_bytes(b"TMUXGATE_TEST\0value\0")
            (job / "timeout").write_bytes(b"")
            (job / "result-limits").write_bytes(b"1048576\n1048576\n2097152\n")
            argv = (
                b"/bin/bash",
                b"-c",
                b"printf 'stdout=%s\\n' \"$TMUXGATE_TEST\"; printf 'stderr-line\\n' >&2; exit 7",
            )
            (job / "argv.bin").write_bytes(b"\0".join(argv) + b"\0")
            for path in (
                job / "mode",
                job / "cwd.bin",
                job / "environment.bin",
                job / "timeout",
                job / "result-limits",
                job / "argv.bin",
            ):
                path.chmod(0o600)
            fake_tmux = Path(directory) / "fake-tmux"
            fake_tmux.write_text("#!/bin/sh\n[ \"$1\" = wait-for ] || exit 99\nexit 0\n", encoding="ascii")
            fake_tmux.chmod(0o700)
            environment = {
                "HOME": str(home),
                "PATH": "/usr/bin:/bin",
            }
            completed = subprocess.run(
                [
                    "/bin/bash",
                    str(runner),
                    str(job),
                    f"tmuxgate-start-{REQUEST_ID}",
                    str(fake_tmux),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                timeout=5,
                check=False,
            )
            self.assertEqual(completed.returncode, 7)
            self.assertEqual(completed.stdout, b"stdout=value\n")
            self.assertEqual(completed.stderr, b"stderr-line\n")
            self.assertEqual((job / "stdout.raw").read_bytes(), completed.stdout)
            self.assertEqual((job / "stderr.raw").read_bytes(), completed.stderr)
            self.assertEqual((job / "exit-code").read_text(encoding="ascii"), "7\n")
            self.assertEqual((job / "state").read_text(encoding="ascii"), "complete\n")
            self.assertFalse((job / "stdout.fifo").exists())
            self.assertFalse((job / "stderr.fifo").exists())

    def test_script_payload_is_resolved_from_job_dir_after_changing_to_requested_cwd(self):
        runner = Path(__file__).parents[1] / "src/tmuxgate/assets/remote_runner.sh"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            job = home / ".cache/tmuxgate/jobs" / REQUEST_ID
            job.mkdir(parents=True, mode=0o700)
            requested_cwd = Path(directory) / "requested-cwd"
            requested_cwd.mkdir()
            files = {
                "mode": b"script\n",
                "cwd.bin": os.fsencode(str(requested_cwd)) + b"\0",
                "environment.bin": b"",
                "timeout": b"5\n",
                "result-limits": b"1048576\n1048576\n2097152\n",
                "payload.sh": b"printf 'cwd=%s\\n' \"$PWD\"\nexit 7\n",
            }
            for name, content in files.items():
                path = job / name
                path.write_bytes(content)
                path.chmod(0o600)
            fake_tmux = Path(directory) / "fake-tmux"
            fake_tmux.write_text("#!/bin/sh\n[ \"$1\" = wait-for ] || exit 99\nexit 0\n", encoding="ascii")
            fake_tmux.chmod(0o700)
            completed = subprocess.run(
                [
                    "/bin/bash",
                    str(runner),
                    str(job),
                    f"tmuxgate-start-{REQUEST_ID}",
                    str(fake_tmux),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin",
                },
                timeout=5,
                check=False,
            )
            self.assertEqual(completed.returncode, 7)
            self.assertEqual(completed.stdout, f"cwd={requested_cwd}\n".encode())
            self.assertEqual(completed.stderr, b"")
            self.assertEqual((job / "exit-code").read_text(encoding="ascii"), "7\n")
            self.assertEqual((job / "state").read_text(encoding="ascii"), "complete\n")

    def test_failed_start_gate_cleans_fifos_and_reports_incomplete(self):
        runner = Path(__file__).parents[1] / "src/tmuxgate/assets/remote_runner.sh"
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            job = home / ".cache/tmuxgate/jobs" / REQUEST_ID
            job.mkdir(parents=True, mode=0o700)
            files = {
                "mode": b"exec\n",
                "cwd.bin": os.fsencode(str(job)) + b"\0",
                "environment.bin": b"",
                "timeout": b"",
                "result-limits": b"1048576\n1048576\n2097152\n",
                "argv.bin": b"/bin/true\0",
            }
            for name, content in files.items():
                path = job / name
                path.write_bytes(content)
                path.chmod(0o600)
            fake_tmux = Path(directory) / "fake-tmux"
            fake_tmux.write_text("#!/bin/sh\nexit 99\n", encoding="ascii")
            fake_tmux.chmod(0o700)
            completed = subprocess.run(
                [
                    "/bin/bash",
                    str(runner),
                    str(job),
                    f"tmuxgate-start-{REQUEST_ID}",
                    str(fake_tmux),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin",
                },
                timeout=5,
                check=False,
            )
            self.assertEqual(completed.returncode, 125)
            self.assertEqual((job / "state").read_text(encoding="ascii"), "capture-incomplete\n")
            self.assertFalse((job / "stdout.fifo").exists())
            self.assertFalse((job / "stderr.fifo").exists())
            self.assertFalse((job / "exit-code").exists())

    def test_hostile_request_environment_is_confined_to_exec_process(self):
        runner = Path(__file__).parents[1] / "src/tmuxgate/assets/remote_runner.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            job = home / ".cache/tmuxgate/jobs" / REQUEST_ID
            job.mkdir(parents=True, mode=0o700)
            marker = root / "environment-sourced"
            bash_env = root / "bash-env"
            shell_env = root / "shell-env"
            for path in (bash_env, shell_env):
                path.write_text(
                    f"printf sourced >> {marker}\n",
                    encoding="ascii",
                )
            hostile = {
                b"PATH": os.fsencode(root / "untrusted-bin"),
                b"LD_PRELOAD": os.fsencode(root / "untrusted-preload.so"),
                b"IFS": b":",
                b"BASH_ENV": os.fsencode(bash_env),
                b"ENV": os.fsencode(shell_env),
            }
            environment_bytes = b"".join(
                name + b"\0" + value + b"\0"
                for name, value in hostile.items()
            )
            files = {
                "mode": b"exec\n",
                "cwd.bin": os.fsencode(str(job)) + b"\0",
                "environment.bin": environment_bytes,
                "timeout": b"5\n",
                "result-limits": b"1048576\n1048576\n2097152\n",
                "argv.bin": b"/usr/bin/env\0-0\0",
            }
            for name, content in files.items():
                path = job / name
                path.write_bytes(content)
                path.chmod(0o600)
            control_environment = home / "control-environment.bin"
            fake_tmux = root / "fake-tmux"
            fake_tmux.write_text(
                "#!/bin/sh\n"
                f"/usr/bin/env -0 > {control_environment}\n"
                "[ \"$1\" = wait-for ] || exit 99\n"
                "exit 0\n",
                encoding="ascii",
            )
            fake_tmux.chmod(0o700)

            completed = subprocess.run(
                [
                    "/bin/bash",
                    str(runner),
                    str(job),
                    f"tmuxgate-start-{REQUEST_ID}",
                    str(fake_tmux),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                timeout=5,
                check=False,
            )

            self.assertEqual(completed.returncode, 0)
            target = self._parse_environment(completed.stdout)
            control = self._parse_environment(control_environment.read_bytes())
            for name, value in hostile.items():
                self.assertEqual(target[name], value)
                if name == b"PATH":
                    self.assertEqual(control[name], b"/usr/bin:/bin")
                else:
                    self.assertNotIn(name, control)
            self.assertFalse(marker.exists())
            self.assertIn(hostile[b"LD_PRELOAD"], completed.stderr)
            self.assertEqual((job / "state").read_bytes(), b"complete\n")

    def test_argv_and_script_preserve_exact_environment_bytes_at_boundary(self):
        runner = Path(__file__).parents[1] / "src/tmuxgate/assets/remote_runner.sh"
        exact = {
            b"EMPTY": b"",
            b"MULTILINE": b"first line\nsecond line",
            b"NON_UTF8": b"prefix-\xff-suffix",
            b"PUNCTUATION": b" $'\";=\\tail",
        }
        environment_bytes = b"".join(
            name + b"\0" + value + b"\0"
            for name, value in exact.items()
        )
        for mode in ("exec", "script"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                home = root / "home"
                job = home / ".cache/tmuxgate/jobs" / REQUEST_ID
                job.mkdir(parents=True, mode=0o700)
                files = {
                    "mode": f"{mode}\n".encode("ascii"),
                    "cwd.bin": os.fsencode(str(job)) + b"\0",
                    "environment.bin": environment_bytes,
                    "timeout": b"5\n",
                    "result-limits": b"1048576\n1048576\n2097152\n",
                }
                if mode == "exec":
                    files["argv.bin"] = b"/usr/bin/env\0-0\0"
                else:
                    files["payload.sh"] = b"/usr/bin/env -0\n"
                for name, content in files.items():
                    path = job / name
                    path.write_bytes(content)
                    path.chmod(0o600)
                fake_tmux = root / "fake-tmux"
                fake_tmux.write_text(
                    "#!/bin/sh\n[ \"$1\" = wait-for ] || exit 99\nexit 0\n",
                    encoding="ascii",
                )
                fake_tmux.chmod(0o700)

                completed = subprocess.run(
                    [
                        "/bin/bash",
                        str(runner),
                        str(job),
                        f"tmuxgate-start-{REQUEST_ID}",
                        str(fake_tmux),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                    timeout=5,
                    check=False,
                )

                self.assertEqual(completed.returncode, 0)
                self.assertEqual(completed.stderr, b"")
                target = self._parse_environment(completed.stdout)
                for name, value in exact.items():
                    self.assertEqual(target[name], value)
                self.assertEqual((job / "stdout.raw").read_bytes(), completed.stdout)
                self.assertEqual((job / "state").read_bytes(), b"complete\n")

    @staticmethod
    def _parse_environment(content):
        return {
            entry.split(b"=", 1)[0]: entry.split(b"=", 1)[1]
            for entry in content.split(b"\0")
            if entry
        }


if __name__ == "__main__":
    unittest.main()
