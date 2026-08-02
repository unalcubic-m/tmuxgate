from io import BytesIO
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import tempfile
import threading
import time
import tty
import unittest

from tmuxgate.approval import ApprovalDecision
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.operator_interface import (
    OperatorDecision,
    SecretInputRecipient,
)
from tmuxgate.real_ssh import (
    DetachedTmuxViewerProcess,
    SecretPromptPresenter,
    SshChannelRunner,
    SubprocessMasterBackend,
    _discard_pending_terminal_input,
    secret_prompt_signature,
)
from tmuxgate.transport import SshInvocation, SshMasterStartError, TransportError
from test_connection_plan import build_plan


class FakeTerminal(BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def fileno(self):
        return 99


class FlagLock:
    def __init__(self):
        self.held = False

    def __enter__(self):
        if self.held:
            raise AssertionError("terminal lock was entered recursively")
        self.held = True
        return self

    def __exit__(self, *args):
        self.held = False


class FakeAttachProcess:
    def __init__(self):
        self.returncode = None
        self.terminate_count = 0
        self.kill_count = 0
        self.wait_count = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.wait_count += 1
        if self.returncode is None:
            raise TimeoutError("fake viewer was not detached")
        return self.returncode

    def terminate(self):
        self.terminate_count += 1
        self.returncode = -15

    def kill(self):
        self.kill_count += 1
        self.returncode = -9


class ScriptedDetachedViewer(DetachedTmuxViewerProcess):
    def __init__(self, request_suffix):
        super().__init__(
            lambda *args, **kwargs: None,
            Path(f"/tmp/{request_suffix}.sock"),
            f"tmuxgate-{request_suffix}",
        )
        self.prompt = b"[sudo] password for operator:\n"
        self.process = None
        self.detached = threading.Event()
        self.detach_count = 0

    @property
    def attached(self):
        return True

    def capture_pane(self):
        return self.prompt

    def capture_history(self):
        return self.prompt

    def prompt_signature(self):
        return secret_prompt_signature(self.prompt)

    def detach_client(self, client_tty):
        if client_tty != "/dev/pts/test":
            raise AssertionError("presenter detached the wrong terminal")
        self.detach_count += 1
        self.process.returncode = 0
        self.detached.set()


_SECRET_REQUEST = RequestSpec(
    "app-server",
    ExecutionMode.ARGV,
    "/opt/docker",
    argv=("sudo", "--", "/bin/true"),
)
_SECRET_PLAN = build_plan()


def secret_input_recipient(viewer):
    suffix = viewer.session_name.removeprefix("tmuxgate-")
    return SecretInputRecipient(
        suffix + ("0" * 20),
        _SECRET_REQUEST,
        _SECRET_PLAN,
        "home-lan",
    )


def approve_secret_input(prompt):
    return OperatorDecision.for_prompt(prompt, ApprovalDecision.APPROVED)


def approved_presenter(**kwargs):
    return SecretPromptPresenter(authorizer=approve_secret_input, **kwargs)


class RealSshProcessTests(unittest.TestCase):
    def test_streaming_batch_enforces_limit_while_receiving(self):
        runner = SshChannelRunner()
        with tempfile.TemporaryFile("w+b") as destination:
            result = runner.batch_to_file(
                ("/bin/bash", "-c", "printf abc; printf diagnostic >&2; exit 7"),
                destination,
                max_output_bytes=3,
                timeout_seconds=5,
            )
            destination.seek(0)
            self.assertEqual(destination.read(), b"abc")
            self.assertEqual(result.size, 3)
            self.assertEqual(result.stderr, b"diagnostic")
            self.assertEqual(result.returncode, 7)

        with tempfile.TemporaryFile("w+b") as destination:
            with self.assertRaisesRegex(TransportError, "exceeds"):
                runner.batch_to_file(
                    ("/bin/bash", "-c", "printf abcd"),
                    destination,
                    max_output_bytes=3,
                    timeout_seconds=5,
                )

    def test_streaming_batch_fails_closed_on_local_write_error(self):
        class FailingDestination:
            def write(self, content):
                del content
                raise OSError("injected disk failure")

            def flush(self):
                raise AssertionError("failed output must not be flushed")

        with self.assertRaisesRegex(TransportError, "could not be stored"):
            SshChannelRunner().batch_to_file(
                ("/bin/bash", "-c", "printf data"),
                FailingDestination(),
                max_output_bytes=4,
                timeout_seconds=5,
            )

    def test_prompt_handoff_discards_only_preexisting_terminal_input(self):
        child = os.fork()
        if child == 0:
            status = 1
            master = slave = None
            try:
                os.setsid()
                signal.signal(signal.SIGHUP, signal.SIG_IGN)
                master, slave = pty.openpty()
                tty.setraw(slave)
                terminal_path = os.ttyname(slave)
                with open(terminal_path, "r+b", buffering=0) as terminal:
                    os.write(master, b"stale-enter\n")
                    if not select.select([slave], [], [], 1)[0]:
                        status = 2
                    else:
                        _discard_pending_terminal_input(terminal, terminal_path)
                        if select.select([slave], [], [], 0.05)[0]:
                            status = 3
                        else:
                            os.write(master, b"fresh-password")
                            if not select.select([slave], [], [], 1)[0]:
                                status = 4
                            elif os.read(slave, 14) != b"fresh-password":
                                status = 5
                            else:
                                status = 0
            except BaseException:
                status = 6
            finally:
                if slave is not None:
                    os.close(slave)
                if master is not None:
                    os.close(master)
                os._exit(status)

        waited, status = os.waitpid(child, 0)
        self.assertEqual(waited, child)
        self.assertTrue(os.WIFEXITED(status), status)
        self.assertEqual(os.WEXITSTATUS(status), 0)

    def test_prompt_handoff_flush_failure_stops_before_attach(self):
        viewer = ScriptedDetachedViewer("cccccccccccc")
        attach_calls = []

        def fail_flush(terminal, path):
            raise TransportError("injected flush failure")

        presenter = approved_presenter(
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            popen=lambda *args, **kwargs: attach_calls.append((args, kwargs)),
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=fail_flush,
        )
        try:
            with self.assertRaisesRegex(TransportError, "injected flush failure"):
                presenter._present(viewer, secret_input_recipient(viewer))
            self.assertEqual(attach_calls, [])
        finally:
            self.assertTrue(presenter.close())

    def test_remote_prompt_notifies_but_denial_never_attaches_terminal(self):
        viewer = ScriptedDetachedViewer("dededededede")
        notifications = []
        authorization_prompts = []
        attach_calls = []

        def deny(prompt):
            authorization_prompts.append(prompt)
            return OperatorDecision.for_prompt(prompt, ApprovalDecision.DENIED)

        presenter = SecretPromptPresenter(
            authorizer=deny,
            reporter=notifications.append,
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            popen=lambda *args, **kwargs: attach_calls.append((args, kwargs)),
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: None,
            poll_seconds=0.005,
        )
        try:
            presenter.watch(viewer, secret_input_recipient(viewer))
            deadline = time.monotonic() + 1
            while len(authorization_prompts) < 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(len(authorization_prompts), 1)
            self.assertEqual(attach_calls, [])
            self.assertTrue(viewer.attached)
            self.assertTrue(any("awaiting independent" in item for item in notifications))
            self.assertTrue(any("denied" in item for item in notifications))
            self.assertEqual(
                authorization_prompts[0].request_id,
                "dededededede" + ("0" * 20),
            )
            time.sleep(0.08)
            self.assertEqual(len(authorization_prompts), 1)
        finally:
            self.assertTrue(presenter.close())

    def test_stale_secret_authorization_cannot_attach_terminal(self):
        viewer = ScriptedDetachedViewer("efefefefefef")
        recipient = secret_input_recipient(viewer)
        attach_calls = []

        def stale_authorization(prompt):
            replacement = recipient.create_prompt(viewer.session_name)
            self.assertNotEqual(replacement.prompt_id, prompt.prompt_id)
            return OperatorDecision.for_prompt(
                replacement, ApprovalDecision.APPROVED
            )

        presenter = SecretPromptPresenter(
            authorizer=stale_authorization,
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            popen=lambda *args, **kwargs: attach_calls.append((args, kwargs)),
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: None,
        )
        try:
            with self.assertRaisesRegex(
                TransportError, "authorization failed closed"
            ):
                presenter._present(viewer, recipient)
            self.assertEqual(attach_calls, [])
            self.assertTrue(viewer.attached)
        finally:
            self.assertTrue(presenter.close())

    def test_stale_input_is_flushed_before_the_operator_notice(self):
        events = []
        viewer = ScriptedDetachedViewer("cdcdcdcdcdcd")

        class OrderedTerminal(FakeTerminal):
            def write(self, data):
                events.append("notice")
                return super().write(data)

        def popen(argv, **kwargs):
            events.append("attach")
            process = FakeAttachProcess()
            viewer.process = process
            viewer.prompt = (
                f"TMUXGATE_AUTH_COMPLETE={viewer.session_name}\n"
            ).encode("ascii")
            return process

        presenter = approved_presenter(
            terminal_opener=lambda *args, **kwargs: OrderedTerminal(),
            popen=popen,
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: events.append("flush"),
            poll_seconds=0.005,
        )
        try:
            presenter._present(viewer, secret_input_recipient(viewer))
            self.assertEqual(events, ["flush", "notice", "attach"])
            self.assertEqual(viewer.detach_count, 1)
        finally:
            self.assertTrue(presenter.close())

    def test_secret_prompt_detection_uses_cursor_not_nested_tmux_status(self):
        pane = (
            b"remote_before=1785312103.646452555\n"
            b"[sudo] password for operator:\n"
            b"\n\n\n"
            b"[DevWorkstation] tmu0:bash*  2026-07-29 11:01\n"
        )
        self.assertEqual(
            secret_prompt_signature(pane, cursor_y=1),
            b"[sudo] password for operator:",
        )
        self.assertIsNone(secret_prompt_signature(pane, cursor_y=2))

    def test_secret_prompt_detection_uses_only_the_visible_tail(self):
        self.assertEqual(
            secret_prompt_signature(b"output\n[sudo] password for operator:   \n"),
            b"[sudo] password for operator:",
        )
        self.assertEqual(
            secret_prompt_signature(b"Enter passphrase for key '/tmp/id':"),
            b"Enter passphrase for key '/tmp/id':",
        )
        self.assertIsNone(
            secret_prompt_signature(b"password: historical\ncommand still running\n")
        )

    def test_secret_prompt_detection_accepts_only_bounded_pwfeedback(self):
        prefix = b"[sudo] Password for operator: "
        for feedback in (b"", b"*", b"***", b"**", b"*", b""):
            with self.subTest(feedback=feedback):
                self.assertEqual(
                    secret_prompt_signature(prefix + feedback + b"   \n"),
                    (prefix + feedback).rstrip(),
                )
        self.assertIsNotNone(
            secret_prompt_signature(prefix + (b"*" * 256))
        )
        for rejected in (
            b"*" * 257,
            b"***x",
            "\u2022\u2022\u2022".encode("utf-8"),
            b"actual-password-text",
        ):
            with self.subTest(rejected=rejected):
                self.assertIsNone(
                    secret_prompt_signature(prefix + rejected)
                )

    def test_authentication_marker_uses_history_and_exact_session_line(self):
        session_name = "tmuxgate-787878787878"
        controls = []
        visible = b"[sudo] password for operator:\n"
        history = (
            b"TMUXGATE_AUTH_COMPLETE=tmuxgate-999999999999\n"
            b"prefix TMUXGATE_AUTH_COMPLETE=" + session_name.encode("ascii") + b"\n"
            b"TMUXGATE_AUTH_COMPLETE=" + session_name.encode("ascii") + b" suffix\n"
            b"TMUXGATE_AUTH_COMPLETE=" + session_name.encode("ascii") + b" \n"
            b"TMUXGATE_AUTH_COMPLETE=" + session_name.encode("ascii") + b"\r\n"
            + (b"later output\n" * 40)
        )

        def run(argv, **kwargs):
            controls.append(argv)
            output = history if argv[3:7] == ("capture-pane", "-p", "-S", "-") else visible
            return subprocess.CompletedProcess(argv, 0, output, b"")

        viewer = DetachedTmuxViewerProcess(
            run, Path("/tmp/787878787878.sock"), session_name
        )
        self.assertEqual(viewer.capture_pane(), visible)
        self.assertEqual(viewer.authentication_complete_count(), 1)
        self.assertEqual(
            controls,
            [
                (
                    "/usr/bin/tmux", "-S", "/tmp/787878787878.sock",
                    "capture-pane", "-p", "-t", session_name,
                ),
                (
                    "/usr/bin/tmux", "-S", "/tmp/787878787878.sock",
                    "capture-pane", "-p", "-S", "-", "-t", session_name,
                ),
            ],
        )

    def test_enrollment_authentication_inherits_only_broker_terminal(self):
        calls = []
        terminal = FakeTerminal()
        terminal_lock = FlagLock()

        def run(argv, **kwargs):
            self.assertTrue(terminal_lock.held)
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        backend = SubprocessMasterBackend(
            runner=run,
            terminal_opener=lambda *args, **kwargs: terminal,
            terminal_lock=terminal_lock,
        )
        invocation = SshInvocation(
            "start-enrollment-master", ("/usr/bin/ssh",), True
        )
        backend.start_master(invocation, Path("/tmp/master.sock"))
        kwargs = calls[0][1]
        self.assertIs(kwargs["stdin"], terminal)
        self.assertIs(kwargs["stdout"], terminal)
        self.assertIs(kwargs["stderr"], terminal)
        self.assertNotIn("SSH_AUTH_SOCK", kwargs["env"])
        self.assertIn(b"no requested command has started", terminal.getvalue())

    def test_post_enrollment_master_cannot_be_prompt_capable(self):
        terminal = FakeTerminal()
        backend = SubprocessMasterBackend(
            runner=lambda argv, **kwargs: subprocess.CompletedProcess(
                argv, 0, b"", b""
            ),
            terminal_opener=lambda *args, **kwargs: terminal,
        )
        backend.start_master(
            SshInvocation("start-master", ("/usr/bin/ssh",), False),
            Path("/tmp/master.sock"),
        )
        self.assertIn(b"public-key-only", terminal.getvalue())

        with self.assertRaisesRegex(TransportError, "terminal policy"):
            backend.start_master(
                SshInvocation("start-master", ("/usr/bin/ssh",), True),
                Path("/tmp/master.sock"),
            )

    def test_master_failure_reports_status_without_copying_terminal_output(self):
        terminal = FakeTerminal()

        def run(argv, **kwargs):
            return subprocess.CompletedProcess(
                argv,
                255,
                b"secret-like stdout that must remain terminal-only",
                b"secret-like stderr that must remain terminal-only",
            )

        backend = SubprocessMasterBackend(
            runner=run,
            terminal_opener=lambda *args, **kwargs: terminal,
        )
        invocation = SshInvocation(
            "start-enrollment-master", ("/usr/bin/ssh",), True
        )

        with self.assertRaises(SshMasterStartError) as raised:
            backend.start_master(invocation, Path("/tmp/master.sock"))

        self.assertEqual(raised.exception.returncode, 255)
        detail = str(raised.exception)
        self.assertIn("status 255", detail)
        self.assertIn("before remote execution", detail)
        self.assertIn("broker terminal", detail)
        self.assertNotIn("secret-like", detail)
        self.assertIn(b"Complete any OpenSSH prompt", terminal.getvalue())

    def test_master_stop_failure_is_observable(self):
        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 255, b"", b"failed")

        backend = SubprocessMasterBackend(runner=run)
        invocation = SshInvocation("master-exit", ("/usr/bin/ssh",), False)

        with self.assertRaisesRegex(TransportError, "shutdown was not confirmed"):
            backend.stop_master(invocation, Path("/tmp/master.sock"))

    def test_post_auth_batch_channel_cannot_prompt(self):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 7, b"out", b"err")

        result = SshChannelRunner(runner=run).batch(
            ("/usr/bin/ssh", "-o", "BatchMode=yes", "host", "true")
        )
        self.assertEqual((result.stdout, result.stderr, result.returncode), (b"out", b"err", 7))
        self.assertNotIn("stdin", calls[0][1])
        self.assertIs(calls[0][1]["stdout"], subprocess.PIPE)
        self.assertIs(calls[0][1]["stderr"], subprocess.PIPE)

    def test_parallel_secret_prompts_are_presented_one_at_a_time(self):
        terminal = FakeTerminal()
        viewers = {
            "aaaaaaaaaaaa": ScriptedDetachedViewer("aaaaaaaaaaaa"),
            "bbbbbbbbbbbb": ScriptedDetachedViewer("bbbbbbbbbbbb"),
        }
        started = []
        handoffs = []
        started_event = threading.Event()

        def popen(argv, **kwargs):
            suffix = argv[-1].removeprefix("tmuxgate-")
            handoffs.append(("attach", suffix))
            process = FakeAttachProcess()
            viewers[suffix].process = process
            started.append(suffix)
            started_event.set()
            return process

        presenter = approved_presenter(
            terminal_opener=lambda *args, **kwargs: terminal,
            popen=popen,
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: handoffs.append(
                ("flush", path)
            ),
            poll_seconds=0.01,
        )
        try:
            presenter.watch(
                viewers["aaaaaaaaaaaa"],
                secret_input_recipient(viewers["aaaaaaaaaaaa"]),
            )
            presenter.watch(
                viewers["bbbbbbbbbbbb"],
                secret_input_recipient(viewers["bbbbbbbbbbbb"]),
            )
            self.assertTrue(started_event.wait(timeout=1))
            time.sleep(0.05)
            self.assertEqual(len(started), 1)

            first = started[0]
            viewers[first].prompt = (
                f"TMUXGATE_AUTH_COMPLETE={viewers[first].session_name}\n"
            ).encode("ascii")
            self.assertTrue(viewers[first].detached.wait(timeout=1))
            deadline = time.monotonic() + 1
            while len(started) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(set(started), set(viewers))

            second = next(name for name in viewers if name != first)
            viewers[second].prompt = (
                f"TMUXGATE_AUTH_COMPLETE={viewers[second].session_name}\n"
            ).encode("ascii")
            self.assertTrue(viewers[second].detached.wait(timeout=1))
            self.assertEqual(
                handoffs,
                [
                    ("flush", "/dev/pts/test"),
                    ("attach", first),
                    ("flush", "/dev/pts/test"),
                    ("attach", second),
                ],
            )
        finally:
            self.assertTrue(presenter.close())

    def test_pwfeedback_typing_and_backspace_keep_viewer_attached(self):
        viewer = ScriptedDetachedViewer("dddddddddddd")
        attached = threading.Event()

        def popen(argv, **kwargs):
            process = FakeAttachProcess()
            viewer.process = process
            attached.set()
            return process

        presenter = approved_presenter(
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            popen=popen,
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: None,
            poll_seconds=0.005,
        )
        try:
            presenter.watch(viewer, secret_input_recipient(viewer))
            self.assertTrue(attached.wait(timeout=1))
            for prompt in (
                b"[sudo] password for operator: *\n",
                b"[sudo] password for operator: ***\n",
                b"[sudo] password for operator: **\n",
                b"[sudo] password for operator: *\n",
                b"[sudo] password for operator:\n",
            ):
                viewer.prompt = prompt
                time.sleep(0.08)
                self.assertFalse(viewer.detached.is_set(), prompt)

            viewer.prompt = (
                f"TMUXGATE_AUTH_COMPLETE={viewer.session_name}\n"
            ).encode("ascii")
            self.assertTrue(viewer.detached.wait(timeout=1))
            self.assertEqual(viewer.detach_count, 1)
        finally:
            self.assertTrue(presenter.close())

    def test_wrong_password_retry_reuses_the_same_attachment(self):
        cases = (
            (
                "sudo",
                b"[sudo] password for operator: **\n",
                b"Sorry, try again.\n",
                b"[sudo] password for operator:\n",
            ),
            (
                "openssh",
                b"operator@example's password:\n",
                b"Permission denied, please try again.\n",
                b"operator@example's password:\n",
            ),
        )
        for label, initial, rejection, retry in cases:
            with self.subTest(label=label):
                viewer = ScriptedDetachedViewer(
                    "eeeeeeeeeeee" if label == "sudo" else "ffffffffffff"
                )
                viewer.prompt = initial
                attach_count = 0
                attached = threading.Event()

                def popen(argv, **kwargs):
                    nonlocal attach_count
                    attach_count += 1
                    process = FakeAttachProcess()
                    viewer.process = process
                    attached.set()
                    return process

                presenter = approved_presenter(
                    terminal_opener=lambda *args, **kwargs: FakeTerminal(),
                    popen=popen,
                    terminal_path_resolver=lambda: "/dev/pts/test",
                    terminal_input_flusher=lambda terminal, path: None,
                    poll_seconds=0.005,
                )
                try:
                    presenter.watch(viewer, secret_input_recipient(viewer))
                    self.assertTrue(attached.wait(timeout=1))
                    viewer.prompt = rejection
                    time.sleep(0.12)
                    self.assertFalse(viewer.detached.is_set())
                    viewer.prompt = retry
                    time.sleep(0.12)
                    self.assertFalse(viewer.detached.is_set())
                    self.assertEqual(attach_count, 1)

                    viewer.prompt = (
                        f"TMUXGATE_AUTH_COMPLETE={viewer.session_name}\n"
                    ).encode("ascii")
                    self.assertTrue(viewer.detached.wait(timeout=1))
                    self.assertEqual(viewer.detach_count, 1)
                    self.assertEqual(attach_count, 1)
                finally:
                    self.assertTrue(presenter.close())

    def test_non_prompt_output_waits_for_an_exact_completion_marker(self):
        viewer = ScriptedDetachedViewer("121212121212")
        attached = threading.Event()

        def popen(argv, **kwargs):
            process = FakeAttachProcess()
            viewer.process = process
            attached.set()
            return process

        presenter = approved_presenter(
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            popen=popen,
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: None,
            poll_seconds=0.005,
        )
        try:
            presenter.watch(viewer, secret_input_recipient(viewer))
            self.assertTrue(attached.wait(timeout=1))
            for sequence in range(6):
                viewer.prompt = f"ordinary output {sequence}\n".encode("ascii")
                time.sleep(0.04)
                self.assertFalse(viewer.detached.is_set())

            viewer.prompt = (
                f"TMUXGATE_AUTH_COMPLETE={viewer.session_name}\n"
            ).encode("ascii")
            self.assertTrue(viewer.detached.wait(timeout=1))
            self.assertEqual(viewer.detach_count, 1)
        finally:
            self.assertTrue(presenter.close())

    def test_old_completion_marker_cannot_satisfy_a_later_prompt(self):
        viewer = ScriptedDetachedViewer("565656565656")
        marker = (
            f"TMUXGATE_AUTH_COMPLETE={viewer.session_name}\n"
        ).encode("ascii")
        viewer.prompt = marker + b"[sudo] password for operator:\n"
        attached = threading.Event()

        def popen(argv, **kwargs):
            process = FakeAttachProcess()
            viewer.process = process
            attached.set()
            return process

        presenter = approved_presenter(
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            popen=popen,
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: None,
            poll_seconds=0.005,
        )
        try:
            presenter.watch(viewer, secret_input_recipient(viewer))
            self.assertTrue(attached.wait(timeout=1))
            viewer.prompt = marker + b"ordinary output\n"
            time.sleep(0.12)
            self.assertFalse(viewer.detached.is_set())

            viewer.prompt += marker
            self.assertTrue(viewer.detached.wait(timeout=1))
            self.assertEqual(viewer.detach_count, 1)
        finally:
            self.assertTrue(presenter.close())

    def test_manual_detach_does_not_reattach_until_a_new_prompt_episode(self):
        viewer = ScriptedDetachedViewer("909090909090")
        processes = []

        def popen(argv, **kwargs):
            process = FakeAttachProcess()
            viewer.process = process
            processes.append(process)
            return process

        presenter = approved_presenter(
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            popen=popen,
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: None,
            poll_seconds=0.005,
        )
        try:
            presenter.watch(viewer, secret_input_recipient(viewer))
            deadline = time.monotonic() + 1
            while len(processes) < 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(len(processes), 1)

            processes[0].returncode = 0
            time.sleep(0.12)
            self.assertEqual(len(processes), 1)

            viewer.prompt = b"authentication check in progress\n"
            time.sleep(0.08)
            viewer.prompt = b"[sudo] password for operator:\n"
            deadline = time.monotonic() + 1
            while len(processes) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(len(processes), 2)

            viewer.prompt = (
                f"TMUXGATE_AUTH_COMPLETE={viewer.session_name}\n"
            ).encode("ascii")
            self.assertTrue(viewer.detached.wait(timeout=1))
            self.assertEqual(viewer.detach_count, 1)
        finally:
            self.assertTrue(presenter.close())

    def test_detach_failure_terminates_local_attachment_process(self):
        class DetachFailureViewer(ScriptedDetachedViewer):
            def detach_client(self, client_tty):
                self.detach_count += 1
                raise TransportError("injected detach failure")

        viewer = DetachFailureViewer("abababababab")
        process = FakeAttachProcess()

        def popen(argv, **kwargs):
            viewer.process = process
            viewer.prompt = (
                f"TMUXGATE_AUTH_COMPLETE={viewer.session_name}\n"
            ).encode("ascii")
            return process

        presenter = approved_presenter(
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            popen=popen,
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: None,
            poll_seconds=0.005,
        )
        try:
            with self.assertRaisesRegex(TransportError, "injected detach failure"):
                presenter._present(viewer, secret_input_recipient(viewer))
            self.assertEqual(viewer.detach_count, 1)
            self.assertEqual(process.terminate_count, 1)
            self.assertEqual(process.kill_count, 0)
            self.assertEqual(process.wait_count, 1)
            self.assertEqual(process.returncode, -15)
            with presenter._active_lock:
                self.assertIsNone(presenter._active)
        finally:
            self.assertTrue(presenter.close())

    def test_prompt_probe_failure_detaches_before_reporting_failure(self):
        class ProbeFailureViewer(ScriptedDetachedViewer):
            def __init__(self):
                super().__init__("343434343434")
                self.prompt_calls = 0

            def prompt_signature(self):
                self.prompt_calls += 1
                if self.prompt_calls > 2:
                    raise TransportError("injected prompt probe failure")
                return super().prompt_signature()

        viewer = ProbeFailureViewer()

        def popen(argv, **kwargs):
            process = FakeAttachProcess()
            viewer.process = process
            return process

        presenter = approved_presenter(
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            popen=popen,
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: None,
            poll_seconds=0.005,
        )
        try:
            with self.assertRaisesRegex(
                TransportError, "prompt inspection failed"
            ):
                presenter._present(viewer, secret_input_recipient(viewer))
            self.assertTrue(viewer.detached.is_set())
            self.assertEqual(viewer.detach_count, 1)
        finally:
            self.assertTrue(presenter.close())


if __name__ == "__main__":
    unittest.main()
