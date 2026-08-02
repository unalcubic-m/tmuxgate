import ast
import fcntl
import gc
import io
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
import weakref
from unittest.mock import call, patch

from tmuxgate.approval import (
    ApprovalDecision,
    ApprovalDisplayError,
    ApprovalError,
    ApprovalInputError,
    ApprovalTerminal,
    CONTROLLING_TTY_PATH,
    open_approval_terminal,
    render_approval_summary,
    render_approval_document,
    render_code_document,
    render_secret_input_authorization_document,
    request_approval,
    request_machine_disable,
    request_secret_input_authorization,
    secure_less_pager,
)
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.operator_interface import SecretInputAuthorizationPrompt
from test_connection_plan import build_plan


REQUEST_ID = "89abcdef0123456789abcdef01234567"
SHORT_ID = REQUEST_ID[:8]


def terminal_with_input(content: str) -> tuple[ApprovalTerminal, io.StringIO]:
    output = io.StringIO()
    return ApprovalTerminal(reader=io.StringIO(content), writer=output), output


def rendered_script_bytes(document: str) -> bytes:
    chunks = []
    for line in document.splitlines():
        if line.startswith("  @"):
            _offset, _line_number, literal = line.strip().split(" ", 2)
            chunks.append(ast.literal_eval(literal))
    return b"".join(chunks)


class ConsumingReader:
    def __init__(self, lines):
        self._lines = list(lines)

    def readline(self):
        if not self._lines:
            return ""
        return self._lines.pop(0)


class SecretLine(str):
    __slots__ = ("__weakref__",)


class ShortWriteBuffer:
    """A text writer that accepts at most seven characters per call."""

    def __init__(self):
        self.parts = []

    def write(self, content):
        accepted = min(7, len(content))
        self.parts.append(content[:accepted])
        return accepted

    def flush(self):
        return None

    def getvalue(self):
        return "".join(self.parts)


class ApprovalTests(unittest.TestCase):
    def test_secret_input_authorization_displays_exact_recipient_and_command(self):
        request = RequestSpec(
            "app-server",
            ExecutionMode.ARGV,
            "/opt/docker",
            argv=("sudo", "--", "/bin/true"),
        )
        plan = build_plan()
        prompt = SecretInputAuthorizationPrompt.create(
            REQUEST_ID,
            request,
            plan,
            endpoint_id="home-lan",
            viewer_session_id=f"tmuxgate-{REQUEST_ID[:12]}",
        )
        document = render_secret_input_authorization_document(
            REQUEST_ID,
            request,
            plan,
            prompt_id=prompt.prompt_id,
            endpoint_id=prompt.endpoint_id,
            viewer_session_id=prompt.viewer_session_id,
            command_identity_sha256=prompt.command_identity_sha256,
            secret_input_binding_sha256=prompt.secret_input_binding_sha256,
        )
        self.assertIn(f"request_id: {REQUEST_ID}", document)
        self.assertIn('machine: "app-server"', document)
        self.assertIn('  [0] "sudo"', document)
        self.assertIn("every byte typed", document)
        self.assertIn(prompt.secret_input_binding_sha256, document)

    def test_secret_input_authorization_accepts_only_full_bound_phrase(self):
        request = RequestSpec(
            "app-server",
            ExecutionMode.SCRIPT,
            "/opt/docker",
            script=b"sudo /bin/true\n",
        )
        plan = build_plan()
        prompt = SecretInputAuthorizationPrompt.create(
            REQUEST_ID,
            request,
            plan,
            endpoint_id="home-lan",
            viewer_session_id=f"tmuxgate-{REQUEST_ID[:12]}",
        )

        denied_terminal, denied_output = terminal_with_input(
            f"forward {REQUEST_ID[:-1]}0\n\n"
        )
        self.assertIs(
            request_secret_input_authorization(
                REQUEST_ID,
                request,
                plan,
                prompt_id=prompt.prompt_id,
                endpoint_id=prompt.endpoint_id,
                viewer_session_id=prompt.viewer_session_id,
                command_identity_sha256=prompt.command_identity_sha256,
                secret_input_binding_sha256=prompt.secret_input_binding_sha256,
                terminal=denied_terminal,
            ),
            ApprovalDecision.DENIED,
        )
        self.assertIn("not authorized", denied_output.getvalue())

        approved_terminal, _output = terminal_with_input(
            f"forward {REQUEST_ID}\n"
        )
        self.assertIs(
            request_secret_input_authorization(
                REQUEST_ID,
                request,
                plan,
                prompt_id=prompt.prompt_id,
                endpoint_id=prompt.endpoint_id,
                viewer_session_id=prompt.viewer_session_id,
                command_identity_sha256=prompt.command_identity_sha256,
                secret_input_binding_sha256=prompt.secret_input_binding_sha256,
                terminal=approved_terminal,
            ),
            ApprovalDecision.APPROVED,
        )

    def test_machine_disable_prompt_defaults_to_no_and_accepts_yes(self):
        for response in ("\n", "n\n", "N\n", "no\n", "NO\n"):
            with self.subTest(response=response):
                terminal, _output = terminal_with_input(response)
                self.assertEqual(
                    request_machine_disable(
                        REQUEST_ID,
                        "host",
                        failure_detail="SSH setup failed",
                        remote_mutation_started=False,
                        terminal=terminal,
                    ),
                    ApprovalDecision.DENIED,
                )
        for response in ("y\n", "Y\n", "yes\n", "YES\n"):
            with self.subTest(response=response):
                terminal, _output = terminal_with_input(response)
                self.assertEqual(
                    request_machine_disable(
                        REQUEST_ID,
                        "host",
                        failure_detail="SSH setup failed",
                        remote_mutation_started=False,
                        terminal=terminal,
                    ),
                    ApprovalDecision.APPROVED,
                )

    def test_machine_disable_prompt_does_not_echo_invalid_input(self):
        terminal, output = terminal_with_input("do-not-record-me\nn\n")

        decision = request_machine_disable(
            REQUEST_ID,
            "host",
            failure_detail="SSH setup failed",
            remote_mutation_started=False,
            terminal=terminal,
        )

        self.assertEqual(decision, ApprovalDecision.DENIED)
        self.assertNotIn("do-not-record-me", output.getvalue())
        self.assertIn("Please answer y or n.", output.getvalue())

    def test_machine_disable_prompt_is_forbidden_after_remote_mutation(self):
        terminal, _output = terminal_with_input("y\n")
        with self.assertRaises(ApprovalError):
            request_machine_disable(
                REQUEST_ID,
                "host",
                failure_detail="failure",
                remote_mutation_started=True,
                terminal=terminal,
            )

    def test_script_containing_run_text_cannot_approve_itself(self):
        script = (
            b"#!/bin/sh\n"
            b"echo RUN 89abcdef\n"
            b"RUN 89abcdef\n"
            b"echo DENY\n"
        )
        request = RequestSpec("host", ExecutionMode.SCRIPT, "/tmp", script=script)
        terminal, output = terminal_with_input("")

        with self.assertRaises(ApprovalInputError):
            request_approval(REQUEST_ID, request, terminal=terminal)

        self.assertIn("RUN 89abcdef", output.getvalue())

    def test_pager_return_value_cannot_approve_and_terminal_deny_wins(self):
        request = RequestSpec(
            "host",
            ExecutionMode.SCRIPT,
            "/",
            script=b"RUN 89abcdef\n" * 10,
        )
        terminal, _output = terminal_with_input("DENY\n")
        paged = []

        def pager(document):
            paged.append(document)
            return f"RUN {SHORT_ID}"

        decision = request_approval(
            REQUEST_ID,
            request,
            terminal=terminal,
            pager=pager,
            pager_threshold_bytes=0,
        )

        self.assertEqual(decision, ApprovalDecision.DENIED)
        self.assertEqual(len(paged), 1)

    def test_invalid_input_loops_until_an_exact_run_line(self):
        request = RequestSpec("host", ExecutionMode.ARGV, "/", argv=("true",))
        invalid = [
            f"RUN {SHORT_ID} extra\n",
            f" RUN {SHORT_ID}\n",
            f"RUN {SHORT_ID} \n",
            f"run {SHORT_ID}\n",
            f"RUN {REQUEST_ID}\n",
            "DENY \n",
        ]
        terminal, output = terminal_with_input("".join(invalid) + "yes\r\n")

        decision = request_approval(REQUEST_ID, request, terminal=terminal)

        self.assertEqual(decision, ApprovalDecision.APPROVED)
        self.assertEqual(
            output.getvalue().count("Please press Enter/y to approve"),
            len(invalid),
        )

    def test_default_terminal_opener_uses_only_dev_tty_for_read_and_write(self):
        reader = io.StringIO("DENY\n")
        writer = io.StringIO()
        with (
            patch("builtins.open", side_effect=[reader, writer]) as opened,
            patch("tmuxgate.approval._validate_controlling_terminal") as validate,
        ):
            with open_approval_terminal() as terminal:
                self.assertIs(terminal.reader, reader)
                self.assertIs(terminal.writer, writer)

        self.assertEqual(
            opened.call_args_list,
            [
                call(
                    CONTROLLING_TTY_PATH,
                    "r",
                    encoding="utf-8",
                    errors="surrogateescape",
                    buffering=1,
                    newline="",
                ),
                call(
                    CONTROLLING_TTY_PATH,
                    "w",
                    encoding="utf-8",
                    errors="strict",
                    buffering=1,
                    newline="",
                ),
            ],
        )
        validate.assert_called_once_with(reader, writer)

    def test_no_controlling_terminal_fails_closed(self):
        source_root = Path(__file__).resolve().parents[1] / "src"
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(source_root)
        program = """
from tmuxgate.approval import ApprovalTerminalError, request_approval
from tmuxgate.models import ExecutionMode, RequestSpec
try:
    request_approval(
        '89abcdef0123456789abcdef01234567',
        RequestSpec('host', ExecutionMode.ARGV, '/', argv=('true',)),
        pager=None,
    )
except ApprovalTerminalError:
    raise SystemExit(0)
raise SystemExit(9)
"""
        completed = subprocess.run(
            [sys.executable, "-c", program],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
            timeout=3,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))

    @unittest.skipUnless(hasattr(pty, "fork"), "requires a Unix controlling PTY")
    def test_run_on_process_stdin_cannot_approve_real_controlling_tty(self):
        stdin_reader, stdin_writer = os.pipe()
        result_reader, result_writer = os.pipe()
        pid, master = pty.fork()
        if pid == 0:  # pragma: no cover - assertions occur in the parent
            try:
                os.close(stdin_writer)
                os.close(result_reader)
                os.dup2(stdin_reader, 0)
                os.close(stdin_reader)
                decision = request_approval(
                    REQUEST_ID,
                    RequestSpec("host", ExecutionMode.ARGV, "/", argv=("true",)),
                    pager=None,
                )
                os.write(result_writer, decision.value.encode("ascii"))
                os._exit(0)
            except BaseException as exc:
                os.write(result_writer, f"error:{type(exc).__name__}".encode("ascii"))
                os._exit(1)

        os.close(stdin_reader)
        os.close(result_writer)
        waited = False
        try:
            # This is the untrusted client/process stdin.  The child must never
            # consume it as an approval response.
            # Enter alone now approves, so place that strongest possible value
            # on untrusted process stdin. It still must not reach /dev/tty.
            os.write(stdin_writer, b"\n")
            os.close(stdin_writer)
            stdin_writer = -1

            transcript = bytearray()
            deadline = time.monotonic() + 3
            while b"Approve? [Y/n]" not in transcript:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, bytes(transcript))
                readable, _, _ = select.select([master], [], [], remaining)
                self.assertTrue(readable, bytes(transcript))
                transcript.extend(os.read(master, 65536))

            readable, _, _ = select.select([result_reader], [], [], 0.15)
            self.assertFalse(readable, "stdin text unexpectedly made an approval decision")

            os.write(master, b"DENY\n")
            readable, _, _ = select.select([result_reader], [], [], 3)
            self.assertTrue(readable, bytes(transcript))
            self.assertEqual(os.read(result_reader, 128), b"denied")
            waited_pid, status = os.waitpid(pid, 0)
            waited = True
            self.assertEqual(waited_pid, pid)
            self.assertTrue(os.WIFEXITED(status))
            self.assertEqual(os.WEXITSTATUS(status), 0)
        finally:
            if stdin_writer >= 0:
                os.close(stdin_writer)
            os.close(result_reader)
            os.close(master)
            if not waited:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)

    def test_eof_raises_without_manufacturing_a_decision(self):
        request = RequestSpec("host", ExecutionMode.ARGV, "/", argv=("id",))
        terminal, output = terminal_with_input("")

        with self.assertRaisesRegex(ApprovalInputError, "EOF") as caught:
            request_approval(REQUEST_ID, request, terminal=terminal)

        self.assertNotIn("DENY", str(caught.exception))
        self.assertIn("Approve? [Y/n]", output.getvalue())

    def test_exact_argv_cwd_environment_and_all_script_bytes_are_rendered_safely(self):
        script = bytes(range(256)) * 3 + b"final-byte:\xff"
        request = RequestSpec(
            "host",
            ExecutionMode.SCRIPT,
            "/tmp/line\nwith\x1b-control",
            environment={
                "ALPHA": "space and\nnewline",
                "UNICODE": "T\u00fcrk\u00e7e/\u65e5\u672c\u8a9e",
            },
            script=script,
        )

        document = render_approval_document(REQUEST_ID, request)

        self.assertIn(f"cwd: {json.dumps(request.cwd, ensure_ascii=True)}", document)
        for name, value in request.environment:
            self.assertIn(
                f"env[{json.dumps(name, ensure_ascii=True)}]: "
                f"{json.dumps(value, ensure_ascii=True)}",
                document,
            )
        self.assertEqual(rendered_script_bytes(document), script)
        self.assertIn("L000001", document)
        self.assertNotIn("\x1b", document)
        self.assertNotIn("...", document)

        argv_request = RequestSpec(
            "host",
            ExecutionMode.ARGV,
            "/",
            argv=("printf", "space value", "line\none", "", "\x1b[31m"),
        )
        argv_document = render_approval_document(REQUEST_ID, argv_request)
        for index, argument in enumerate(argv_request.argv):
            self.assertIn(
                f"argv[{index}]: {json.dumps(argument, ensure_ascii=True)}",
                argv_document,
            )
        self.assertNotIn("\x1b", argv_document)

    def test_long_script_reaches_injected_pager_in_full(self):
        script = b"begin\n" + (b"0123456789abcdef" * 8192) + b"\nend\xff"
        request = RequestSpec("host", ExecutionMode.SCRIPT, "/", script=script)
        expected = render_code_document(REQUEST_ID, request)
        terminal, output = terminal_with_input("DENY\n")
        paged = []

        decision = request_approval(
            REQUEST_ID,
            request,
            terminal=terminal,
            pager=paged.append,
            pager_threshold_bytes=1024,
        )

        self.assertEqual(decision, ApprovalDecision.DENIED)
        self.assertEqual(paged, [expected])
        self.assertIn("000001 | begin\\n", paged[0])
        self.assertIn("end\\xff", paged[0])
        self.assertIn("complete approval document", output.getvalue())

    def test_newline_only_script_has_byte_bounded_render_rows(self):
        script = b"\n" * (1024 * 1024)
        request = RequestSpec("host", ExecutionMode.SCRIPT, "/", script=script)

        document = render_approval_document(REQUEST_ID, request)
        render_rows = sum(line.startswith("  @") for line in document.splitlines())

        self.assertEqual(render_rows, len(script) // 256)
        self.assertEqual(rendered_script_bytes(document), script)

    def test_secure_pager_uses_a_complete_sealed_file_and_allowlisted_environment(self):
        document = "header\ncomplete script bytes: \\x00 \\xff\n"
        observed = {}

        def fake_run(argv, **kwargs):
            descriptor = kwargs["pass_fds"][0]
            observed["argv"] = argv
            observed["document"] = os.pread(descriptor, 65536, 0)
            observed["seals"] = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
            observed["environment"] = kwargs["env"]
            return SimpleNamespace(returncode=0)

        with (
            patch.dict(
                os.environ,
                {
                    "LESSOPEN": "malicious-filter",
                    "LESSCLOSE": "malicious-close",
                    "LESS_TERMCAP_so": "malicious-terminal-sequence",
                    "PAGER": "malicious-pager",
                },
                clear=False,
            ),
            patch("builtins.open", side_effect=[io.BytesIO(), io.BytesIO()]),
            patch("tmuxgate.approval.subprocess.run", side_effect=fake_run),
        ):
            secure_less_pager(document)

        self.assertEqual(observed["document"], document.encode("ascii"))
        required = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        self.assertEqual(observed["seals"] & required, required)
        self.assertEqual(observed["argv"][-2], "--")
        self.assertTrue(observed["argv"][-1].startswith("/proc/self/fd/"))
        self.assertEqual(observed["environment"]["LESSSECURE"], "1")
        for unsafe_name in ("LESSOPEN", "LESSCLOSE", "LESS_TERMCAP_so", "PAGER"):
            self.assertNotIn(unsafe_name, observed["environment"])

    def test_no_pager_still_writes_the_complete_document_including_short_writes(self):
        script = b"x" * 4097 + b"last"
        request = RequestSpec("host", ExecutionMode.SCRIPT, "/", script=script)
        expected_code = render_code_document(REQUEST_ID, request)
        expected_summary = render_approval_summary(REQUEST_ID, request)
        writer = ShortWriteBuffer()
        terminal = ApprovalTerminal(reader=io.StringIO("DENY\n"), writer=writer)

        decision = request_approval(REQUEST_ID, request, terminal=terminal)

        self.assertEqual(decision, ApprovalDecision.DENIED)
        self.assertTrue(writer.getvalue().startswith(expected_code))
        self.assertIn(expected_summary, writer.getvalue())
        self.assertIn("last", expected_code)

    def test_view_code_and_details_are_paged_then_return_to_same_prompt(self):
        request = RequestSpec(
            "host", ExecutionMode.ARGV, "/tmp", argv=("printf", "space value")
        )
        terminal, output = terminal_with_input("c\nd\ny\n")
        paged = []

        decision = request_approval(
            REQUEST_ID,
            request,
            terminal=terminal,
            pager=paged.append,
        )

        self.assertIs(decision, ApprovalDecision.APPROVED)
        self.assertEqual(paged[0], render_code_document(REQUEST_ID, request))
        self.assertEqual(paged[1], render_approval_document(REQUEST_ID, request))
        self.assertGreaterEqual(output.getvalue().count("Approve? [Y/n]"), 3)

    def test_compact_summary_labels_advisory_purpose_and_exact_command(self):
        request = RequestSpec(
            "host",
            ExecutionMode.ARGV,
            "/tmp",
            argv=("printf", "space value"),
            purpose="Show one harmless formatted value",
        )
        summary = render_approval_summary(REQUEST_ID, request)
        self.assertIn(
            f"WHY        {json.dumps(request.purpose, ensure_ascii=True)}",
            summary,
        )
        expected_command = json.dumps("printf 'space value'", ensure_ascii=True)
        self.assertIn(
            f"RUN\n---\n{expected_command}",
            summary,
        )
        self.assertNotIn("ssh_g_argv", summary)

    def test_compact_and_paged_documents_escape_terminal_control_and_bidi(self):
        request = RequestSpec(
            "host",
            ExecutionMode.ARGV,
            "/tmp/\x1b[2J",
            argv=(
                "printf",
                "\x1b[2JFAKE SAFE COMMAND",
                "reverse-\u202e-txt",
                "bell-\x07",
            ),
            environment={"DISPLAY_TEXT": "\x9b31mspoof\x7f"},
            purpose="reverse-\u202e-status",
        )

        documents = (
            render_code_document(REQUEST_ID, request),
            render_approval_summary(REQUEST_ID, request),
            render_approval_document(REQUEST_ID, request),
        )

        for document in documents:
            with self.subTest(document=document[:40]):
                document.encode("ascii")
                self.assertTrue(
                    all(
                        character == "\n" or 0x20 <= ord(character) <= 0x7E
                        for character in document
                    )
                )
                self.assertNotIn("\x1b", document)
                self.assertNotIn("\u202e", document)

    def test_pager_failure_stops_before_terminal_input(self):
        request = RequestSpec("host", ExecutionMode.SCRIPT, "/", script=b"echo safe\n")
        reader = ConsumingReader([f"RUN {SHORT_ID}\n"])
        output = io.StringIO()

        def broken_pager(_document):
            raise OSError("pager unavailable")

        with self.assertRaises(ApprovalDisplayError):
            request_approval(
                REQUEST_ID,
                request,
                terminal=ApprovalTerminal(reader=reader, writer=output),
                pager=broken_pager,
                pager_threshold_bytes=0,
            )

        self.assertEqual(len(reader._lines), 1)

    def test_password_like_invalid_input_is_not_returned_echoed_or_retained(self):
        password = SecretLine("Correct-Horse-Battery-Staple!\n")
        password_reference = weakref.ref(password)
        reader = ConsumingReader([password, "DENY\n"])
        del password
        output = io.StringIO()
        request = RequestSpec("host", ExecutionMode.ARGV, "/", argv=("true",))

        decision = request_approval(
            REQUEST_ID,
            request,
            terminal=ApprovalTerminal(reader=reader, writer=output),
        )
        gc.collect()

        self.assertIs(decision, ApprovalDecision.DENIED)
        self.assertNotIn("Correct-Horse-Battery-Staple", output.getvalue())
        self.assertNotIn("Correct-Horse-Battery-Staple", repr(decision))
        self.assertIsNone(password_reference())


if __name__ == "__main__":
    unittest.main()
