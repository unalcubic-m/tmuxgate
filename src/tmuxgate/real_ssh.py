"""Real broker-owned OpenSSH subprocess backends."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import queue
import re
import selectors
import stat
import subprocess
import termios
import threading
import time
from typing import BinaryIO

from tmuxgate.approval import ApprovalDecision
from tmuxgate.operator_interface import (
    OperatorDecision,
    SecretInputAuthorizationPrompt,
    SecretInputRecipient,
    require_operator_decision,
)
from tmuxgate.transport import (
    MAX_OPENSSH_DIAGNOSTIC_BYTES,
    SshInvocation,
    SshMasterStartError,
    TransportError,
)


MAX_BATCH_OUTPUT_BYTES = 300 * 1024 * 1024
MAX_BATCH_DIAGNOSTIC_BYTES = 64 * 1024
STREAM_CHUNK_BYTES = 64 * 1024
_VIEWER_SESSION_RE = re.compile(r"tmuxgate-[0-9a-f]{12}\Z", re.ASCII)
_SECRET_PROMPT_RE = re.compile(
    rb"(?:password(?:\s+for\s+[^:\r\n]{1,160})?|passphrase(?:\s+for\s+[^:\r\n]{1,160})?)"
    rb"\s*:[ \t]*\*{0,256}[ \t]*\Z",
    re.IGNORECASE,
)


def secret_prompt_signature(
    content: bytes,
    *,
    cursor_y: int | None = None,
) -> bytes | None:
    """Return a password/passphrase prompt at the visible cursor row."""

    if not isinstance(content, bytes):
        raise TypeError("viewer pane content must be bytes")
    lines = content.splitlines()
    if cursor_y is None:
        stripped = content.rstrip(b" \t\r\n")
        if not stripped:
            return None
        line = stripped.splitlines()[-1]
    else:
        if type(cursor_y) is not int or not 0 <= cursor_y < len(lines):
            return None
        line = lines[cursor_y].rstrip(b" \t\r")
    line = line[-512:]
    return line if _SECRET_PROMPT_RE.search(line) is not None else None


def broker_terminal_path() -> str:
    """Resolve the broker's real owned PTY instead of the /dev/tty alias."""

    for file_descriptor in (0, 1, 2):
        try:
            if not os.isatty(file_descriptor):
                continue
            candidate = os.path.realpath(os.ttyname(file_descriptor))
            metadata = os.lstat(candidate)
        except (OSError, ValueError):
            continue
        if (
            candidate == "/dev/tty"
            or not candidate.startswith("/dev/")
            or not stat.S_ISCHR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
        ):
            continue
        return candidate
    raise TransportError("broker process has no safe owned terminal PTY")


def _discard_pending_terminal_input(terminal: BinaryIO, expected_tty: str) -> None:
    """Discard bytes queued before a private viewer owns the broker terminal."""

    try:
        descriptor = terminal.fileno()
        if (
            type(descriptor) is not int
            or descriptor < 0
            or not os.isatty(descriptor)
            or os.path.realpath(os.ttyname(descriptor))
            != os.path.realpath(expected_tty)
        ):
            raise TransportError("broker prompt presenter opened an unsafe terminal")
        termios.tcflush(descriptor, termios.TCIFLUSH)
    except TransportError:
        raise
    except (OSError, ValueError) as exc:
        raise TransportError(
            "broker terminal input queue could not be discarded"
        ) from exc


def _safe_environment() -> dict[str, str]:
    allowed = (
        "HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOGNAME",
        "TERM", "USER",
    )
    environment = {"PATH": "/usr/bin:/bin"}
    for name in allowed:
        value = os.environ.get(name)
        if value and "\x00" not in value:
            environment[name] = value
    return environment


def _run_completed(result: object, label: str) -> subprocess.CompletedProcess[bytes]:
    if not isinstance(result, subprocess.CompletedProcess):
        raise TransportError(f"{label} runner returned an invalid result")
    if not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes):
        raise TransportError(f"{label} runner did not return byte streams")
    if len(result.stdout) > MAX_BATCH_OUTPUT_BYTES or len(result.stderr) > MAX_BATCH_OUTPUT_BYTES:
        raise TransportError(f"{label} output exceeds the configured limit")
    return result


class SubprocessMasterBackend:
    """Start authentication on the broker terminal, then control in batch mode."""

    def __init__(
        self,
        *,
        runner: Callable[..., object] = subprocess.run,
        terminal_opener: Callable[..., BinaryIO] = open,
        terminal_lock: object | None = None,
    ) -> None:
        self.runner = runner
        self.terminal_opener = terminal_opener
        self.terminal_lock = threading.RLock() if terminal_lock is None else terminal_lock

    def start_master(self, invocation: SshInvocation, control_path: Path) -> None:
        expected_interactive = invocation.kind == "start-enrollment-master"
        if invocation.kind not in {"start-enrollment-master", "start-master"}:
            raise TransportError("master start requires a start invocation")
        if invocation.interactive_terminal != expected_interactive:
            raise TransportError("master start has an invalid terminal policy")
        with self.terminal_lock:
            with self.terminal_opener("/dev/tty", "r+b", buffering=0) as terminal:
                completed = self.runner(
                    invocation.argv,
                    stdin=terminal,
                    stdout=terminal,
                    stderr=subprocess.PIPE,
                    check=False,
                    env=_safe_environment(),
                )
        returncode = getattr(completed, "returncode", None)
        if type(returncode) is not int:
            raise TransportError("interactive SSH master runner returned no exit status")
        diagnostics = getattr(completed, "stderr", None)
        if not isinstance(diagnostics, bytes):
            raise TransportError("interactive SSH master returned invalid diagnostics")
        if len(diagnostics) > MAX_OPENSSH_DIAGNOSTIC_BYTES:
            raise TransportError(
                "OpenSSH diagnostics exceeded the structured interface limit"
            )
        if returncode != 0:
            raise SshMasterStartError(returncode, diagnostics)

    def _control(self, invocation: SshInvocation, label: str) -> bool:
        completed = _run_completed(
            self.runner(
                invocation.argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
                env=_safe_environment(),
            ),
            label,
        )
        return completed.returncode == 0

    def check_master(self, invocation: SshInvocation, control_path: Path) -> bool:
        if invocation.kind != "master-check" or invocation.interactive_terminal:
            raise TransportError("master check requires a batch control invocation")
        return self._control(invocation, "master check")

    def stop_master(self, invocation: SshInvocation, control_path: Path) -> None:
        if invocation.kind != "master-exit" or invocation.interactive_terminal:
            raise TransportError("master stop requires a batch control invocation")
        if not self._control(invocation, "master stop"):
            raise TransportError(
                "SSH master stop command failed; shutdown was not confirmed"
            )


@dataclass(frozen=True, slots=True)
class BatchResult:
    stdout: bytes
    stderr: bytes
    returncode: int


@dataclass(frozen=True, slots=True)
class StreamBatchResult:
    stderr: bytes
    returncode: int
    size: int
    sha256: str


class SshChannelRunner:
    """Execute fixed remote controls over one private authenticated master."""

    def __init__(
        self,
        *,
        runner: Callable[..., object] = subprocess.run,
        popen: Callable[..., object] = subprocess.Popen,
        terminal_opener: Callable[..., BinaryIO] = open,
        prompt_presenter: "SecretPromptPresenter | None" = None,
    ) -> None:
        self.runner = runner
        self.popen = popen
        self.terminal_opener = terminal_opener
        self.prompt_presenter = prompt_presenter

    def batch(
        self,
        argv: tuple[str, ...],
        *,
        input_bytes: bytes = b"",
        timeout_seconds: float = 30,
    ) -> BatchResult:
        if not argv or not isinstance(input_bytes, bytes):
            raise TransportError("batch SSH invocation is invalid")
        completed = _run_completed(
            self.runner(
                argv,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout_seconds,
                env=_safe_environment(),
            ),
            "batch SSH channel",
        )
        return BatchResult(completed.stdout, completed.stderr, completed.returncode)

    def batch_to_file(
        self,
        argv: tuple[str, ...],
        destination: BinaryIO,
        *,
        max_output_bytes: int,
        timeout_seconds: float = 30,
    ) -> StreamBatchResult:
        """Drain a batch channel incrementally into an already-private file."""

        if (
            not argv
            or type(max_output_bytes) is not int
            or max_output_bytes < 0
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise TransportError("streaming batch SSH invocation is invalid")
        try:
            process = self.popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_safe_environment(),
                close_fds=True,
            )
        except BaseException as exc:
            raise TransportError("streaming batch SSH channel could not start") from exc
        stdout = getattr(process, "stdout", None)
        stderr = getattr(process, "stderr", None)
        if stdout is None or stderr is None:
            try:
                process.kill()
                process.wait(timeout=5)
            except BaseException:
                pass
            raise TransportError("streaming batch SSH channel has no byte pipes")

        selector = selectors.DefaultSelector()
        digest = hashlib.sha256()
        size = 0
        diagnostic = bytearray()
        failure: TransportError | None = None
        deadline = time.monotonic() + float(timeout_seconds)
        try:
            selector.register(stdout, selectors.EVENT_READ, "stdout")
            selector.register(stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = TransportError("streaming batch SSH channel timed out")
                    break
                events = selector.select(min(remaining, 0.25))
                if not events:
                    continue
                for key, _mask in events:
                    try:
                        chunk = os.read(key.fileobj.fileno(), STREAM_CHUNK_BYTES)
                    except OSError as exc:
                        failure = TransportError(
                            "streaming batch SSH channel could not be read"
                        )
                        failure.__cause__ = exc
                        break
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    if key.data == "stdout":
                        if size + len(chunk) > max_output_bytes:
                            failure = TransportError(
                                "streaming batch SSH output exceeds the configured limit"
                            )
                            break
                        try:
                            written = destination.write(chunk)
                        except OSError as exc:
                            failure = TransportError(
                                "streaming batch SSH output could not be stored"
                            )
                            failure.__cause__ = exc
                            break
                        if written != len(chunk):
                            failure = TransportError(
                                "streaming batch SSH output write was incomplete"
                            )
                            break
                        digest.update(chunk)
                        size += len(chunk)
                    else:
                        if len(diagnostic) + len(chunk) > MAX_BATCH_DIAGNOSTIC_BYTES:
                            failure = TransportError(
                                "streaming batch SSH diagnostics exceed the configured limit"
                            )
                            break
                        diagnostic.extend(chunk)
                if failure is not None:
                    break
            if failure is not None:
                try:
                    process.kill()
                except BaseException:
                    pass
            try:
                returncode = process.wait(timeout=5 if failure is not None else max(
                    0.1, deadline - time.monotonic()
                ))
            except BaseException as exc:
                try:
                    process.kill()
                    process.wait(timeout=5)
                except BaseException:
                    pass
                if failure is None:
                    failure = TransportError(
                        "streaming batch SSH channel did not terminate"
                    )
                    failure.__cause__ = exc
            if failure is not None:
                raise failure
            try:
                destination.flush()
            except OSError as exc:
                raise TransportError(
                    "streaming batch SSH output could not be flushed"
                ) from exc
            if type(returncode) is not int:
                raise TransportError(
                    "streaming batch SSH channel returned no exit status"
                )
            return StreamBatchResult(
                bytes(diagnostic), returncode, size, digest.hexdigest()
            )
        finally:
            selector.close()
            for pipe in (stdout, stderr):
                try:
                    pipe.close()
                except BaseException:
                    pass

    def viewer(self, argv: tuple[str, ...]) -> "ViewerProcess":
        terminal = self.terminal_opener("/dev/tty", "r+b", buffering=0)
        try:
            process = self.popen(
                argv,
                stdin=terminal,
                stdout=terminal,
                stderr=terminal,
                env=_safe_environment(),
                close_fds=True,
            )
        except BaseException:
            terminal.close()
            raise
        return ViewerProcess(process, terminal)

    def detached_viewer(
        self,
        argv: tuple[str, ...],
        *,
        socket_path: Path,
        session_name: str,
        secret_input_recipient: SecretInputRecipient | None = None,
    ) -> "DetachedTmuxViewerProcess":
        """Launch one SSH viewer in its own private local tmux server."""

        if not argv or not socket_path.is_absolute():
            raise TransportError("detached viewer invocation is invalid")
        if _VIEWER_SESSION_RE.fullmatch(session_name) is None:
            raise TransportError("detached viewer session name is invalid")
        if self.prompt_presenter is not None:
            if not isinstance(secret_input_recipient, SecretInputRecipient):
                raise TransportError(
                    "automatic prompt detection requires an exact secret-input recipient"
                )
            if session_name != f"tmuxgate-{secret_input_recipient.request_id[:12]}":
                raise TransportError(
                    "detached viewer session does not match its exact request"
                )
        elif secret_input_recipient is not None:
            raise TransportError(
                "secret-input recipient requires an automatic prompt presenter"
            )
        if socket_path.exists() or socket_path.is_symlink():
            raise TransportError("refusing a pre-existing detached viewer socket")
        completed = _run_completed(
            self.runner(
                (
                    "/usr/bin/tmux", "-S", os.fspath(socket_path),
                    "new-session", "-d", "-s", session_name,
                    "--", *argv,
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
                env=_safe_environment(),
            ),
            "detached tmux viewer",
        )
        if completed.returncode != 0:
            raise TransportError("detached tmux viewer could not be started")
        try:
            metadata = os.lstat(socket_path)
        except FileNotFoundError as exc:
            raise TransportError("detached viewer exited during startup") from exc
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise TransportError("detached viewer socket is unsafe")
        os.chmod(socket_path, 0o600, follow_symlinks=False)
        viewer = DetachedTmuxViewerProcess(
            self.runner, socket_path, session_name
        )
        if self.prompt_presenter is not None:
            assert secret_input_recipient is not None
            self.prompt_presenter.watch(viewer, secret_input_recipient)
        return viewer


class ViewerProcess:
    def __init__(self, process: object, terminal: BinaryIO) -> None:
        self.process = process
        self.terminal = terminal
        self._closed = False

    @property
    def attached(self) -> bool:
        return self.process.poll() is None

    @property
    def returncode(self) -> int | None:
        return self.process.poll()

    def send_input(self, data: bytes) -> None:
        if not self.attached or not isinstance(data, bytes):
            raise TransportError("viewer is not attached")
        self.terminal.write(data)
        self.terminal.flush()

    def send_ctrl_c(self) -> None:
        self.send_input(b"\x03")

    def detach(self) -> None:
        if self.attached:
            raise TransportError("detach is performed interactively with tmux prefix+d")
        self.close()

    def wait(self, timeout: float | None = None) -> int:
        try:
            return self.process.wait(timeout=timeout)
        finally:
            if self.process.poll() is not None:
                self.close()

    def close(self) -> None:
        if not self._closed:
            self.terminal.close()
            self._closed = True

    def terminate(self) -> None:
        if self.attached:
            self.process.terminate()


class DetachedTmuxViewerProcess:
    """Handle for an SSH viewer hosted in a private detached local tmux."""

    def __init__(self, runner: Callable[..., object], socket_path: Path, session_name: str):
        self.runner = runner
        self.socket_path = socket_path
        self.session_name = session_name

    def _control(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return _run_completed(
            self.runner(
                (
                    "/usr/bin/tmux", "-S", os.fspath(self.socket_path),
                    *arguments,
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=5,
                env=_safe_environment(),
            ),
            "detached viewer control",
        )

    def capture_pane(self) -> bytes:
        completed = self._control(
            "capture-pane", "-p", "-t", self.session_name
        )
        if completed.returncode != 0:
            raise TransportError("detached viewer pane is unavailable")
        return completed.stdout

    def capture_history(self) -> bytes:
        completed = self._control(
            "capture-pane", "-p", "-S", "-", "-t", self.session_name
        )
        if completed.returncode != 0:
            raise TransportError("detached viewer history is unavailable")
        return completed.stdout

    def prompt_signature(self) -> bytes | None:
        cursor = self._control(
            "display-message", "-p", "-t", self.session_name, "#{cursor_y}"
        )
        if cursor.returncode != 0:
            raise TransportError("detached viewer cursor is unavailable")
        try:
            cursor_y = int(cursor.stdout.strip().decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise TransportError("detached viewer cursor is invalid") from exc
        return secret_prompt_signature(self.capture_pane(), cursor_y=cursor_y)

    def authentication_complete_count(self) -> int:
        """Count exact, session-bound authentication completion markers."""

        marker = f"TMUXGATE_AUTH_COMPLETE={self.session_name}".encode("ascii")
        return sum(
            line.rstrip(b"\r") == marker
            for line in self.capture_history().splitlines()
        )

    def detach_client(self, client_tty: str) -> None:
        if not isinstance(client_tty, str) or not client_tty.startswith("/dev/"):
            raise TransportError("detached viewer client tty is invalid")
        completed = self._control("detach-client", "-t", client_tty)
        if completed.returncode != 0:
            raise TransportError("detached viewer client could not be detached")

    @property
    def attached(self) -> bool:
        return self._control("has-session", "-t", self.session_name).returncode == 0

    @property
    def returncode(self) -> int | None:
        return None if self.attached else 0

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.attached:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("detached viewer did not exit before its deadline")
            time.sleep(0.05)
        self.terminate()
        return 0

    def terminate(self) -> None:
        if self.socket_path.exists():
            self._control("kill-server")
        try:
            metadata = os.lstat(self.socket_path)
        except FileNotFoundError:
            return
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise TransportError("refusing to remove an unsafe viewer socket")
        self.socket_path.unlink()

    def close(self) -> None:
        # Normal completion removes the local tmux server automatically.
        return None


class SecretPromptPresenter:
    """Notify on prompt detection and attach only after exact authorization."""

    def __init__(
        self,
        *,
        terminal_lock: object | None = None,
        terminal_opener: Callable[..., BinaryIO] = open,
        popen: Callable[..., object] = subprocess.Popen,
        terminal_path_resolver: Callable[[], str] = broker_terminal_path,
        terminal_input_flusher: Callable[[BinaryIO, str], None] = (
            _discard_pending_terminal_input
        ),
        authorizer: Callable[
            [SecretInputAuthorizationPrompt], OperatorDecision
        ],
        terminal_handoff: Callable[
            [SecretInputAuthorizationPrompt, Callable[[], None]], None
        ] | None = None,
        reporter: Callable[[str], object] = lambda message: None,
        poll_seconds: float = 0.10,
    ) -> None:
        if poll_seconds <= 0:
            raise ValueError("prompt presenter timing is invalid")
        if not callable(authorizer):
            raise TypeError("prompt presenter authorizer must be callable")
        self.terminal_lock = threading.RLock() if terminal_lock is None else terminal_lock
        self.terminal_opener = terminal_opener
        self.popen = popen
        self.terminal_path_resolver = terminal_path_resolver
        self.terminal_input_flusher = terminal_input_flusher
        self.authorizer = authorizer
        self.terminal_handoff = (
            self._locked_terminal_handoff
            if terminal_handoff is None
            else terminal_handoff
        )
        if not callable(self.terminal_handoff):
            raise TypeError("prompt presenter terminal handoff must be callable")
        self.reporter = reporter
        self.poll_seconds = float(poll_seconds)
        self._queue: queue.Queue[
            tuple[DetachedTmuxViewerProcess, SecretInputRecipient] | None
        ] = queue.Queue()
        self._stop = threading.Event()
        self._watched: set[tuple[str, str]] = set()
        self._watched_lock = threading.Lock()
        self._active: tuple[DetachedTmuxViewerProcess, str] | None = None
        self._active_lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._present_loop,
            name="tmuxgate-secret-prompt-presenter",
            daemon=True,
        )
        self._thread.start()

    def watch(
        self,
        viewer: DetachedTmuxViewerProcess,
        recipient: SecretInputRecipient,
    ) -> None:
        if not isinstance(viewer, DetachedTmuxViewerProcess):
            raise TypeError("prompt presenter requires a detached tmux viewer")
        if not isinstance(recipient, SecretInputRecipient):
            raise TypeError("prompt presenter requires an exact secret-input recipient")
        if viewer.session_name != f"tmuxgate-{recipient.request_id[:12]}":
            raise TransportError("viewer session does not match its exact request")
        key = (os.fspath(viewer.socket_path), viewer.session_name)
        with self._watched_lock:
            if key in self._watched:
                return
            self._watched.add(key)
        threading.Thread(
            target=self._monitor,
            args=(viewer, recipient, key),
            name=f"tmuxgate-prompt-watch-{viewer.session_name[-12:]}",
            daemon=True,
        ).start()

    def _monitor(
        self,
        viewer: DetachedTmuxViewerProcess,
        recipient: SecretInputRecipient,
        key: tuple[str, str],
    ) -> None:
        prompt_episode = False
        try:
            while not self._stop.is_set():
                try:
                    if not viewer.attached:
                        return
                    signature = viewer.prompt_signature()
                except (OSError, TransportError):
                    return
                if signature is not None and not prompt_episode:
                    prompt_episode = True
                    with self._active_lock:
                        active_viewer = (
                            None if self._active is None else self._active[0]
                        )
                    if active_viewer is not viewer:
                        self.reporter(
                            "secret input requested by remote pane for request "
                            f"{recipient.request_id} on {recipient.request.machine_alias}; "
                            "awaiting independent operator authorization"
                        )
                        self._queue.put((viewer, recipient))
                elif signature is None:
                    prompt_episode = False
                self._stop.wait(self.poll_seconds)
        finally:
            with self._watched_lock:
                self._watched.discard(key)

    def _present_loop(self) -> None:
        while not self._stop.is_set():
            queued = self._queue.get()
            if queued is None:
                return
            viewer, recipient = queued
            try:
                self._present(viewer, recipient)
            except (OSError, subprocess.SubprocessError, TransportError) as exc:
                # The viewer may have completed or been manually attached.
                self.reporter(
                    "automatic input viewer failed for "
                    f"{viewer.session_name}: {type(exc).__name__}: {exc}"
                )
                continue

    def _present(
        self,
        viewer: DetachedTmuxViewerProcess,
        recipient: SecretInputRecipient,
    ) -> None:
        if not viewer.attached:
            return
        if viewer.prompt_signature() is None:
            return
        prompt = recipient.create_prompt(viewer.session_name)
        try:
            decision = require_operator_decision(prompt, self.authorizer(prompt))
        except BaseException as exc:
            raise TransportError("secret-input authorization failed closed") from exc
        if decision is not ApprovalDecision.APPROVED:
            self.reporter(
                f"secret input denied for request {recipient.request_id}; "
                "remote command remains detached"
            )
            return
        try:
            self.terminal_handoff(
                prompt,
                lambda: self._attach_authorized_viewer(viewer, recipient),
            )
        except (OSError, subprocess.SubprocessError, TransportError):
            raise
        except BaseException as exc:
            raise TransportError("external terminal handoff failed closed") from exc

    def _locked_terminal_handoff(
        self,
        prompt: SecretInputAuthorizationPrompt,
        session: Callable[[], None],
    ) -> None:
        del prompt
        with self.terminal_lock:
            session()

    def _attach_authorized_viewer(
        self,
        viewer: DetachedTmuxViewerProcess,
        recipient: SecretInputRecipient,
    ) -> None:
        """Run the trusted tmux client while the presentation layer is absent."""

        if self._stop.is_set() or not viewer.attached:
            return
        if viewer.prompt_signature() is None:
            return
        client_tty = self.terminal_path_resolver()
        if (
            not isinstance(client_tty, str)
            or client_tty == "/dev/tty"
            or not client_tty.startswith("/dev/")
        ):
            raise TransportError("broker terminal resolver returned an unsafe PTY")
        with self.terminal_opener(client_tty, "r+b", buffering=0) as terminal:
            self.terminal_input_flusher(terminal, client_tty)
            terminal.write(
                (
                    "\r\n[tmuxgate] Password/passphrase input required for "
                    f"{viewer.session_name}. It stays attached through "
                    "typing and retries; use Ctrl-b d if the command does "
                    "not emit its authentication-complete marker.\r\n"
                ).encode("utf-8")
            )
            terminal.flush()
            completion_count = viewer.authentication_complete_count()
            process = self.popen(
                (
                    "/usr/bin/tmux", "-S", os.fspath(viewer.socket_path),
                    "attach-session", "-t", viewer.session_name,
                ),
                stdin=terminal,
                stdout=terminal,
                stderr=terminal,
                env=_safe_environment(),
                close_fds=True,
            )
            with self._active_lock:
                self._active = (viewer, client_tty)
            prompt_probe_error: OSError | TransportError | None = None
            try:
                while process.poll() is None and not self._stop.is_set():
                    try:
                        if not viewer.attached:
                            break
                        current_completion_count = (
                            viewer.authentication_complete_count()
                        )
                        viewer.prompt_signature()
                    except (OSError, TransportError) as exc:
                        prompt_probe_error = exc
                        viewer.detach_client(client_tty)
                        break
                    if current_completion_count > completion_count:
                        viewer.detach_client(client_tty)
                        break
                    self._stop.wait(self.poll_seconds)
                if self._stop.is_set() and process.poll() is None:
                    viewer.detach_client(client_tty)
                if process.poll() is None:
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        process.wait(timeout=2)
                returncode = process.poll()
                if type(returncode) is not int or returncode != 0:
                    raise TransportError(
                        "automatic viewer attachment exited with status "
                        f"{returncode}"
                    )
                if prompt_probe_error is not None:
                    raise TransportError(
                        "automatic viewer prompt inspection failed"
                    ) from prompt_probe_error
            finally:
                try:
                    if process.poll() is None:
                        try:
                            process.terminate()
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            if process.poll() is None:
                                try:
                                    process.kill()
                                except ProcessLookupError:
                                    pass
                                try:
                                    process.wait(timeout=2)
                                except subprocess.TimeoutExpired as exc:
                                    raise TransportError(
                                        "automatic viewer attachment "
                                        "could not be stopped"
                                    ) from exc
                    if process.poll() is None:
                        raise TransportError(
                            "automatic viewer attachment remains active"
                        )
                finally:
                    with self._active_lock:
                        self._active = None

    def close(self, *, timeout: float = 2.0) -> bool:
        self._stop.set()
        self._queue.put(None)
        with self._active_lock:
            active = self._active
        if active is not None:
            viewer, client_tty = active
            try:
                viewer.detach_client(client_tty)
            except (OSError, TransportError):
                pass
        self._thread.join(timeout=timeout)
        return not self._thread.is_alive()
