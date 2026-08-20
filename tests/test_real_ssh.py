from io import BytesIO
import os
import socket
from pathlib import Path
import pty
import select
import signal
import subprocess
import tempfile
import termios
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
    SSH_ENROLLMENT_TERMINAL_PURPOSE,
    DetachedTmuxViewerProcess,
    SecretPromptPresenter,
    SshChannelRunner,
    SubprocessMasterBackend,
    _discard_pending_terminal_input,
    _sudo_prompt_matches,
    secret_prompt_signature,
)
from tmuxgate.terminal import TerminalArbiter, TerminalUnavailableError
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
    interactive=True,
)
_NON_INTERACTIVE_SECRET_REQUEST = RequestSpec(
    "app-server",
    ExecutionMode.ARGV,
    "/opt/docker",
    argv=("sudo", "--", "/bin/true"),
)
_SECRET_PLAN = build_plan()


def secret_input_recipient(viewer, request=_SECRET_REQUEST):
    suffix = viewer.session_name.removeprefix("tmuxgate-")
    return SecretInputRecipient(
        suffix + ("0" * 20),
        request,
        _SECRET_PLAN,
        "home-lan",
    )


def approve_secret_input(prompt):
    return OperatorDecision.for_prompt(prompt, ApprovalDecision.APPROVED)


def approved_presenter(**kwargs):
    return SecretPromptPresenter(authorizer=approve_secret_input, **kwargs)


class InteractiveHandoffScopeTests(unittest.TestCase):
    """Terminal handoff exists only for explicitly interactive requests."""

    def _presenter(self, watched):
        presenter = SecretPromptPresenter(authorizer=approve_secret_input)
        presenter.watch = lambda viewer, recipient: watched.append(
            (viewer, recipient)
        )
        return presenter

    def test_watching_a_non_interactive_request_is_refused(self):
        viewer = ScriptedDetachedViewer("aaaaaaaaaaaa")
        presenter = approved_presenter(poll_seconds=0.005)
        try:
            with self.assertRaises(TransportError) as raised:
                presenter.watch(
                    viewer,
                    secret_input_recipient(
                        viewer, _NON_INTERACTIVE_SECRET_REQUEST
                    ),
                )
            self.assertIn("explicitly interactive", str(raised.exception))
        finally:
            self.assertTrue(presenter.close())

    def test_detached_viewer_watches_only_an_interactive_request(self):
        for interactive, request in (
            (True, _SECRET_REQUEST),
            (False, _NON_INTERACTIVE_SECRET_REQUEST),
        ):
            with self.subTest(interactive=interactive), tempfile.TemporaryDirectory() as directory:
                watched = []
                presenter = self._presenter(watched)
                listener = socket.socket(socket.AF_UNIX)
                try:
                    socket_path = Path(directory) / "viewer.sock"

                    def start_viewer(argv, **kwargs):
                        # Stand in for the private local tmux server: it is the
                        # start command that creates the owner-only socket.
                        listener.bind(os.fspath(socket_path))
                        return subprocess.CompletedProcess(argv, 0, b"", b"")

                    channels = SshChannelRunner(
                        runner=start_viewer, prompt_presenter=presenter
                    )
                    request_id = "b" * 12 + "0" * 20
                    channels.detached_viewer(
                        ("ssh", "host"),
                        socket_path=socket_path,
                        session_name=f"tmuxgate-{request_id[:12]}",
                        secret_input_recipient=SecretInputRecipient(
                            request_id, request, _SECRET_PLAN, "home-lan"
                        ),
                    )
                    self.assertEqual(len(watched), 1 if interactive else 0)
                finally:
                    listener.close()
                    self.assertTrue(presenter.close())


class RealSshProcessTests(unittest.TestCase):
    def test_automatic_sudo_matching_accepts_only_exact_supported_prompts(self):
        accepted = (
            (b"[sudo] password for operator:", None),
            (b"[sudo] PASSWORD for operator: ***", None),
            (
                b"[sudo: authenticate] Password:",
                b"[sudo: authenticate] Password:",
            ),
            (
                b"[sudo: authenticate] Password: ***",
                b"[sudo: authenticate] Password:",
            ),
        )
        rejected = (
            (b"operator@example's password:", None),
            (b"Password:", None),
            (b"[sudo: authenticate] Password:", None),
            (b"[sudo: authenticate] Password:", b"Password:"),
            (
                b"prefix [sudo: authenticate] Password:",
                b"[sudo: authenticate] Password:",
            ),
            (
                b"[sudo: authenticate] Password: " + (b"*" * 257),
                b"[sudo: authenticate] Password:",
            ),
        )

        for prompt, learned in accepted:
            with self.subTest(prompt=prompt, learned=learned):
                self.assertTrue(_sudo_prompt_matches(prompt, "operator", learned))
        for prompt, learned in rejected:
            with self.subTest(prompt=prompt, learned=learned):
                self.assertFalse(_sudo_prompt_matches(prompt, "operator", learned))

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
            recipient = secret_input_recipient(viewer)
            presenter.watch(viewer, recipient)
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

    def test_stored_sudo_password_is_submitted_without_operator_prompt(self):
        viewer = ScriptedDetachedViewer("dadadadadada")
        submitted = []
        authorization_prompts = []
        notifications = []
        viewer.submit_secret_line = submitted.append

        def unexpected_authorization(prompt):
            authorization_prompts.append(prompt)
            return OperatorDecision.for_prompt(prompt, ApprovalDecision.DENIED)

        presenter = SecretPromptPresenter(
            authorizer=unexpected_authorization,
            secret_provider=lambda machine: (
                b"stored-sudo-password" if machine == "app-server" else None
            ),
            automatic_secret_input=lambda: True,
            reporter=notifications.append,
            poll_seconds=0.005,
        )
        try:
            presenter.watch(viewer, secret_input_recipient(viewer))
            deadline = time.monotonic() + 1
            while not submitted and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(submitted, [b"stored-sudo-password"])
            self.assertEqual(authorization_prompts, [])
            self.assertTrue(any("submitted automatically" in item for item in notifications))
            time.sleep(0.05)
            self.assertEqual(len(submitted), 1)
        finally:
            self.assertTrue(presenter.close())

    def test_learned_sudo_password_is_submitted_without_operator_prompt(self):
        viewer = ScriptedDetachedViewer("dadbdadbdadb")
        viewer.prompt = b"[sudo: authenticate] Password:\n"
        submitted = []
        authorization_prompts = []
        viewer.submit_secret_line = submitted.append

        def unexpected_authorization(prompt):
            authorization_prompts.append(prompt)
            return OperatorDecision.for_prompt(prompt, ApprovalDecision.DENIED)

        presenter = SecretPromptPresenter(
            authorizer=unexpected_authorization,
            secret_provider=lambda machine: b"stored-sudo-password",
            prompt_provider=lambda machine: b"[sudo: authenticate] Password:",
            automatic_secret_input=lambda: True,
            poll_seconds=0.005,
        )
        try:
            presenter.watch(viewer, secret_input_recipient(viewer))
            deadline = time.monotonic() + 1
            while not submitted and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(submitted, [b"stored-sudo-password"])
            self.assertEqual(authorization_prompts, [])
        finally:
            self.assertTrue(presenter.close())

    def test_unknown_prompt_fails_without_enrollment_or_forward_input(self):
        viewer = ScriptedDetachedViewer("dadcdadcdadc")
        viewer.prompt = b"Custom privileged password:\n"
        submitted = []
        enrollment_calls = []
        authorization_prompts = []
        viewer.submit_secret_line = submitted.append

        def enroll(machine, prompt):
            enrollment_calls.append((machine, prompt))
            return b"newly-enrolled-password"

        def unexpected_authorization(prompt):
            authorization_prompts.append(prompt)
            return OperatorDecision.for_prompt(prompt, ApprovalDecision.DENIED)

        presenter = SecretPromptPresenter(
            authorizer=unexpected_authorization,
            credential_enroller=enroll,
            automatic_secret_input=lambda: True,
            poll_seconds=0.005,
        )
        try:
            recipient = secret_input_recipient(viewer)
            presenter.watch(viewer, recipient)
            deadline = time.monotonic() + 1
            failure = None
            while failure is None and time.monotonic() < deadline:
                try:
                    presenter.raise_automatic_failure(recipient.request_id)
                except TransportError as exc:
                    failure = exc
                else:
                    time.sleep(0.01)
            self.assertIsNotNone(failure)
            self.assertIn("does not match", str(failure))
            self.assertEqual(submitted, [])
            self.assertEqual(enrollment_calls, [])
            self.assertEqual(authorization_prompts, [])
        finally:
            self.assertTrue(presenter.close())

    def test_missing_stored_sudo_password_fails_without_enrollment_or_tty(self):
        viewer = ScriptedDetachedViewer("dadcdadcdadd")
        submitted = []
        enrollment_calls = []
        authorization_prompts = []
        terminal_handoffs = []
        viewer.submit_secret_line = submitted.append

        presenter = SecretPromptPresenter(
            authorizer=lambda prompt: authorization_prompts.append(prompt),
            secret_provider=lambda machine: None,
            credential_enroller=lambda machine, prompt: enrollment_calls.append(
                (machine, prompt)
            ),
            automatic_secret_input=lambda: True,
            terminal_handoff=lambda prompt, session: terminal_handoffs.append(prompt),
            poll_seconds=0.005,
        )
        try:
            recipient = secret_input_recipient(viewer)
            presenter.watch(viewer, recipient)
            deadline = time.monotonic() + 1
            failure = None
            while failure is None and time.monotonic() < deadline:
                try:
                    presenter.raise_automatic_failure(recipient.request_id)
                except TransportError as exc:
                    failure = exc
                else:
                    time.sleep(0.01)
            self.assertIsNotNone(failure)
            self.assertIn("no stored sudo credential", str(failure))
            self.assertEqual(submitted, [])
            self.assertEqual(enrollment_calls, [])
            self.assertEqual(authorization_prompts, [])
            self.assertEqual(terminal_handoffs, [])
        finally:
            self.assertTrue(presenter.close())

    def test_non_sudo_password_prompt_never_receives_stored_secret(self):
        viewer = ScriptedDetachedViewer("dbdbdbdbdbdb")
        viewer.prompt = b"operator@example's password:\n"
        submitted = []
        authorization_prompts = []
        notifications = []
        viewer.submit_secret_line = submitted.append

        def deny(prompt):
            authorization_prompts.append(prompt)
            return OperatorDecision.for_prompt(prompt, ApprovalDecision.DENIED)

        presenter = SecretPromptPresenter(
            authorizer=deny,
            secret_provider=lambda machine: b"must-not-be-sent",
            automatic_secret_input=lambda: True,
            reporter=notifications.append,
            poll_seconds=0.005,
        )
        try:
            presenter.watch(viewer, secret_input_recipient(viewer))
            deadline = time.monotonic() + 1
            while not notifications and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(authorization_prompts, [])
            self.assertEqual(submitted, [])
            self.assertTrue(any("suppressed" in item for item in notifications))
        finally:
            self.assertTrue(presenter.close())

    def test_failed_automatic_submission_suppresses_operator_prompt(self):
        viewer = ScriptedDetachedViewer("dcdcdcdcdcdc")
        authorization_prompts = []
        notifications = []

        def fail_submission(secret):
            self.assertEqual(secret, b"stored-sudo-password")
            raise TransportError("injected paste failure")

        def deny(prompt):
            authorization_prompts.append(prompt)
            return OperatorDecision.for_prompt(prompt, ApprovalDecision.DENIED)

        viewer.submit_secret_line = fail_submission
        presenter = SecretPromptPresenter(
            authorizer=deny,
            secret_provider=lambda machine: b"stored-sudo-password",
            automatic_secret_input=lambda: True,
            reporter=notifications.append,
            poll_seconds=0.005,
        )
        try:
            presenter.watch(viewer, secret_input_recipient(viewer))
            deadline = time.monotonic() + 1
            while not notifications and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(authorization_prompts, [])
            self.assertTrue(any("suppressed" in item for item in notifications))
            self.assertFalse(any("injected paste failure" in item for item in notifications))
        finally:
            self.assertTrue(presenter.close())

    def test_repeated_sudo_prompts_get_three_automatic_attempts_without_modal(self):
        class RetryingViewer(ScriptedDetachedViewer):
            def __init__(self):
                super().__init__("dcdedcdedcde")
                self.signatures = iter(
                    (
                        self.prompt,
                        None,
                        self.prompt,
                        None,
                        self.prompt,
                        None,
                        self.prompt,
                    )
                )

            def prompt_signature(self):
                try:
                    prompt = next(self.signatures)
                except StopIteration:
                    prompt = self.prompt
                return None if prompt is None else secret_prompt_signature(prompt)

        viewer = RetryingViewer()
        submitted = []
        enrollment_calls = []
        authorization_prompts = []
        notifications = []
        viewer.submit_secret_line = submitted.append

        def unexpected_authorization(prompt):
            authorization_prompts.append(prompt)
            return OperatorDecision.for_prompt(prompt, ApprovalDecision.DENIED)

        presenter = SecretPromptPresenter(
            authorizer=unexpected_authorization,
            secret_provider=lambda machine: b"old-stored-password",
            credential_enroller=lambda machine, prompt: enrollment_calls.append(
                (machine, prompt)
            ),
            automatic_secret_input=lambda: True,
            reporter=notifications.append,
            poll_seconds=0.005,
        )
        try:
            presenter.watch(viewer, secret_input_recipient(viewer))
            deadline = time.monotonic() + 1
            while len(submitted) < 3 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(submitted, [b"old-stored-password"] * 3)
            self.assertEqual(authorization_prompts, [])
            deadline = time.monotonic() + 1
            while (
                not any("rejected repeatedly" in item for item in notifications)
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertTrue(
                any("rejected repeatedly" in item for item in notifications)
            )
            self.assertEqual(enrollment_calls, [])
        finally:
            self.assertTrue(presenter.close())

    def test_secret_submission_uses_stdin_not_process_arguments(self):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        viewer = DetachedTmuxViewerProcess(
            run,
            Path("/tmp/dfdfdfdfdfdf.sock"),
            "tmuxgate-dfdfdfdfdfdf",
        )
        viewer.submit_secret_line(b"private value with spaces")

        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1]["input"], b"private value with spaces\n")
        self.assertNotIn("private value with spaces", repr(calls[0][0]))
        self.assertIn("load-buffer", calls[0][0])
        self.assertIn("paste-buffer", calls[1][0])

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

    def test_authorized_attachment_runs_only_inside_exact_terminal_handoff(self):
        events = []
        authorized = []
        viewer = ScriptedDetachedViewer("abababababab")

        def popen(argv, **kwargs):
            events.append("attach")
            process = FakeAttachProcess()
            viewer.process = process
            viewer.prompt = (
                f"TMUXGATE_AUTH_COMPLETE={viewer.session_name}\n"
            ).encode("ascii")
            return process

        def handoff(prompt, session):
            events.append(("handoff", prompt.secret_input_binding_sha256))
            session()
            events.append("handoff-complete")

        def authorize(prompt):
            authorized.append(prompt)
            return OperatorDecision.for_prompt(prompt, ApprovalDecision.APPROVED)

        presenter = SecretPromptPresenter(
            authorizer=authorize,
            terminal_handoff=handoff,
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            popen=popen,
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: events.append("flush"),
            poll_seconds=0.005,
        )
        try:
            recipient = secret_input_recipient(viewer)
            presenter._present(viewer, recipient)
            self.assertEqual(
                events,
                [
                    ("handoff", authorized[0].secret_input_binding_sha256),
                    "flush",
                    "attach",
                    "handoff-complete",
                ],
            )
        finally:
            self.assertTrue(presenter.close())

    def test_rejected_terminal_handoff_never_opens_or_attaches(self):
        viewer = ScriptedDetachedViewer("acacacacacac")
        opened = []

        def reject_handoff(prompt, session):
            del prompt, session
            raise TransportError("terminal already has an external owner")

        presenter = approved_presenter(
            terminal_handoff=reject_handoff,
            terminal_opener=lambda *args, **kwargs: opened.append("opened"),
            popen=lambda *args, **kwargs: opened.append("attached"),
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: None,
        )
        try:
            with self.assertRaisesRegex(TransportError, "external owner"):
                presenter._present(viewer, secret_input_recipient(viewer))
            self.assertEqual(opened, [])
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
        self.assertIs(kwargs["stderr"], subprocess.PIPE)
        self.assertNotIn("SSH_AUTH_SOCK", kwargs["env"])
        self.assertEqual(terminal.getvalue(), b"")

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
        self.assertEqual(terminal.getvalue(), b"")

        with self.assertRaisesRegex(TransportError, "terminal policy"):
            backend.start_master(
                SshInvocation("start-master", ("/usr/bin/ssh",), True),
                Path("/tmp/master.sock"),
            )

    def test_master_failure_captures_exact_structured_diagnostics(self):
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
        self.assertEqual(
            raised.exception.diagnostics,
            b"secret-like stderr that must remain terminal-only",
        )
        detail = str(raised.exception)
        self.assertIn("status 255", detail)
        self.assertIn("before remote execution", detail)
        self.assertNotIn("secret-like", detail)
        self.assertEqual(terminal.getvalue(), b"")

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


class EndingSessionViewer(ScriptedDetachedViewer):
    """A viewer whose session can be destroyed while a client is attached."""

    def __init__(self, request_suffix):
        super().__init__(request_suffix)
        self.session_alive = True
        self.probe_fails = False

    @property
    def attached(self):
        if self.probe_fails:
            raise TransportError("detached viewer cursor is unavailable")
        return self.session_alive

    def detach_client(self, client_tty):
        if not self.session_alive:
            raise AssertionError("a destroyed session must not be detached")
        super().detach_client(client_tty)


class ViewerSessionEndingTests(unittest.TestCase):
    """A destroyed viewer session is an ordinary ending, not a failure."""

    def _presenter(self, popen):
        return approved_presenter(
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            popen=popen,
            terminal_path_resolver=lambda: "/dev/pts/test",
            terminal_input_flusher=lambda terminal, path: None,
            poll_seconds=0.005,
        )

    @staticmethod
    def _exited_client(viewer, **changes):
        def popen(argv, **kwargs):
            process = FakeAttachProcess()
            # tmux prints "[exited]" and exits non-zero when the session it is
            # attached to is destroyed underneath the client.
            process.returncode = 1
            viewer.process = process
            for name, value in changes.items():
                setattr(viewer, name, value)
            return process

        return popen

    def test_client_exit_after_session_destruction_is_not_a_failure(self):
        # Regression: a command that finishes right after authentication tears
        # down its tmux session while the client is still attached, so the
        # client exits non-zero on its own.  That used to be reported as a
        # transport failure, and the resulting exception escaped Textual's
        # suspend block and permanently wedged the dashboard.
        viewer = EndingSessionViewer("aaaaaaaaaaaa")
        presenter = self._presenter(
            self._exited_client(viewer, session_alive=False)
        )
        try:
            presenter._attach_authorized_viewer(
                viewer, secret_input_recipient(viewer)
            )
            self.assertEqual(viewer.detach_count, 0)
        finally:
            self.assertTrue(presenter.close())

    def test_client_exit_with_a_live_session_remains_a_failure(self):
        viewer = EndingSessionViewer("bbbbbbbbbbbb")
        presenter = self._presenter(self._exited_client(viewer))
        try:
            with self.assertRaisesRegex(TransportError, "exited with status 1"):
                presenter._attach_authorized_viewer(
                    viewer, secret_input_recipient(viewer)
                )
        finally:
            self.assertTrue(presenter.close())

    def test_unreadable_session_probe_remains_a_failure(self):
        # An inconclusive probe is not proof of an ordinary ending.
        viewer = EndingSessionViewer("cccccccccccc")
        presenter = self._presenter(
            self._exited_client(viewer, probe_fails=True)
        )
        try:
            with self.assertRaisesRegex(TransportError, "exited with status 1"):
                presenter._attach_authorized_viewer(
                    viewer, secret_input_recipient(viewer)
                )
        finally:
            self.assertTrue(presenter.close())


class MasterStartTerminalBoundaryTests(unittest.TestCase):
    """Only a master that can actually prompt may reach the terminal."""

    @staticmethod
    def _invocation(interactive):
        kind = "start-enrollment-master" if interactive else "start-master"
        return SshInvocation(kind, ("/usr/bin/ssh",), interactive)

    def test_post_enrollment_master_never_reaches_the_terminal(self):
        calls = []
        terminal_lock = FlagLock()
        opened = []
        handoffs = []

        def run(argv, **kwargs):
            self.assertFalse(terminal_lock.held)
            calls.append(kwargs)
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        def opener(*args, **kwargs):
            opened.append(args)
            raise AssertionError("post-enrollment master opened the terminal")

        backend = SubprocessMasterBackend(
            runner=run,
            terminal_opener=opener,
            terminal_lock=terminal_lock,
            terminal_handoff=lambda purpose, session: handoffs.append(purpose),
        )

        backend.start_master(self._invocation(False), Path("/tmp/master.sock"))

        # BatchMode=yes with public-key-only authentication and a
        # passphrase-less key cannot prompt, so the operator's terminal is
        # neither opened, claimed, nor handed off.
        self.assertEqual(
            (opened, handoffs, terminal_lock.held),
            ([], [], False),
        )
        self.assertEqual(
            (calls[0]["stdin"], calls[0]["stdout"], calls[0]["stderr"]),
            (subprocess.DEVNULL, subprocess.DEVNULL, subprocess.PIPE),
        )

    def test_enrollment_master_runs_inside_the_configured_handoff(self):
        terminal = FakeTerminal()
        terminal_lock = FlagLock()
        observed = []

        def run(argv, **kwargs):
            observed.append(("run", kwargs["stdin"], kwargs["stdout"]))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        def handoff(purpose, session):
            observed.append(("handoff", purpose))
            session()

        backend = SubprocessMasterBackend(
            runner=run,
            terminal_opener=lambda *args, **kwargs: terminal,
            terminal_lock=terminal_lock,
            terminal_handoff=handoff,
        )

        backend.start_master(self._invocation(True), Path("/tmp/master.sock"))

        # The prompt-capable master still gets the terminal, but only from
        # inside the handoff, and never through the direct claim that a
        # full-screen interface cannot satisfy.
        self.assertEqual(
            observed,
            [
                ("handoff", SSH_ENROLLMENT_TERMINAL_PURPOSE),
                ("run", terminal, terminal),
            ],
        )
        self.assertFalse(terminal_lock.held)

    def test_enrollment_master_without_a_handoff_keeps_the_direct_claim(self):
        terminal = FakeTerminal()
        terminal_lock = FlagLock()
        held = []

        def run(argv, **kwargs):
            held.append(terminal_lock.held)
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        backend = SubprocessMasterBackend(
            runner=run,
            terminal_opener=lambda *args, **kwargs: terminal,
            terminal_lock=terminal_lock,
        )

        backend.start_master(self._invocation(True), Path("/tmp/master.sock"))

        self.assertEqual((held, terminal_lock.held), ([True], False))

    def test_handoff_that_skips_the_session_fails_closed(self):
        backend = SubprocessMasterBackend(
            runner=lambda argv, **kwargs: subprocess.CompletedProcess(
                argv, 0, b"", b""
            ),
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            terminal_handoff=lambda purpose, session: None,
        )

        with self.assertRaisesRegex(TransportError, "operator terminal"):
            backend.start_master(self._invocation(True), Path("/tmp/master.sock"))

    def test_handoff_must_be_callable(self):
        with self.assertRaisesRegex(TypeError, "terminal handoff must be callable"):
            SubprocessMasterBackend(terminal_handoff="not-callable")

    def test_noncanonical_terminal_no_longer_blocks_every_connection(self):
        """Regression for the default interface holding the terminal raw.

        A real arbiter over a real PTY in noncanonical mode rejects the
        validating interactive claim.  The post-enrollment master must not
        depend on that claim, and the enrollment master must reach the terminal
        through a handoff that restores canonical mode first.
        """

        primary, secondary = pty.openpty()
        self.addCleanup(os.close, primary)
        self.addCleanup(os.close, secondary)
        canonical = termios.tcgetattr(secondary)
        tty.setraw(secondary)
        arbiter = TerminalArbiter(
            terminal_opener=lambda *args, **kwargs: os.fdopen(
                os.dup(secondary), "rb", buffering=0
            )
        )

        # The exact failure from the report: a validating claim cannot be
        # taken while the interface holds the terminal noncanonical.
        with self.assertRaisesRegex(
            TerminalUnavailableError, "canonical character terminal"
        ):
            with arbiter:
                pass

        started = []
        backend = SubprocessMasterBackend(
            runner=lambda argv, **kwargs: started.append(kwargs["stdin"])
            or subprocess.CompletedProcess(argv, 0, b"", b""),
            terminal_opener=lambda *args, **kwargs: FakeTerminal(),
            terminal_lock=arbiter,
        )
        backend.start_master(self._invocation(False), Path("/tmp/master.sock"))
        self.assertEqual(started, [subprocess.DEVNULL])

        def suspending_handoff(purpose, session):
            # What the real full-screen interface does before yielding: leave
            # application mode, restoring the pre-TUI canonical settings.
            termios.tcsetattr(secondary, termios.TCSADRAIN, canonical)
            with arbiter.claim(purpose=purpose, flush_input=False):
                session()

        backend.terminal_handoff = suspending_handoff
        backend.start_master(self._invocation(True), Path("/tmp/master.sock"))
        self.assertEqual(len(started), 2)


if __name__ == "__main__":
    unittest.main()
