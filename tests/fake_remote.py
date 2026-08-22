"""Process-level fake SSH, sudo, and tmux command boundaries."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
from typing import cast, TypedDict


SSH_PROGRAM = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys

arguments = sys.argv[1:]
destination = arguments[-2]
command = arguments[-1]
with open(os.environ["TMUXGATE_TEST_LOG"], "a", encoding="utf-8") as handle:
    handle.write(json.dumps({
        "destination": destination,
        "command": command,
        "has_bearer_token": "TMUXGATE_MCP_TOKEN" in os.environ,
    }) + "\n")
if destination == "hostkey-fail":
    sys.stderr.write("Host key verification failed.\n")
    raise SystemExit(255)
if os.environ.get("TMUXGATE_TEST_FAIL_COLLECTION") == "1" and "tmuxgate-collect" in command:
    sys.stderr.write("controlled collection failure\n")
    raise SystemExit(1)
environment = os.environ.copy()
environment["HOME"] = os.environ["TMUXGATE_TEST_REMOTE_HOME"]
payload = sys.stdin.buffer.read()
completed = subprocess.run(
    ["/bin/sh", "-c", command],
    input=payload,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=environment,
    check=False,
)
sys.stdout.buffer.write(completed.stdout)
sys.stderr.buffer.write(completed.stderr)
if os.environ.get("TMUXGATE_TEST_DROP_AFTER_START") == "1" and "tmux new-session" in command:
    sys.stderr.write("controlled disconnect after possible start\n")
    raise SystemExit(255)
raise SystemExit(completed.returncode)
'''


SUDO_PROGRAM = r'''#!/usr/bin/env python3
import os
from pathlib import Path
import sys

arguments = sys.argv[1:]
mode = os.environ.get("TMUXGATE_TEST_SUDO_MODE", "passwordless")
if mode == "requiretty":
    sys.stderr.write("sudo: sorry, you must have a tty to run sudo\n")
    raise SystemExit(1)
if mode == "unavailable":
    sys.stderr.write("sudo: command not found\n")
    raise SystemExit(127)
separator = arguments.index("--")
options = arguments[:separator]
command = arguments[separator + 1:]
if "-n" in options and mode != "passwordless":
    sys.stderr.write("sudo: a password is required\n")
    raise SystemExit(1)
if "-S" in options:
    supplied = sys.stdin.buffer.readline().rstrip(b"\r\n")
    expected = Path(os.environ["TMUXGATE_TEST_SUDO_EXPECTED_FILE"]).read_bytes()
    if supplied != expected:
        sys.stderr.write("Sorry, try again.\n")
        raise SystemExit(1)
if os.environ.get("TMUXGATE_TEST_SUDO_START_FAIL") == "1" and command[:1] == ["tmux"]:
    sys.stderr.write("controlled sudo launch failure\n")
    raise SystemExit(1)
os.execvp(command[0], command)
'''


TMUX_PROGRAM = r"""#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import subprocess
import sys

root = Path(os.environ["TMUXGATE_TEST_REMOTE_HOME"]) / ".fake-tmux"
root.mkdir(mode=0o700, exist_ok=True)
arguments = sys.argv[1:]
if arguments[:1] == ["new-session"]:
    session = arguments[arguments.index("-s") + 1]
    command = arguments[arguments.index(session) + 1:]
    marker = root / session
    pid_file = root / f"{session}.pid"
    marker.touch()
    environment = os.environ.copy()
    environment["TMUXGATE_FAKE_MARKER"] = str(marker)
    environment["TMUXGATE_FAKE_PID"] = str(pid_file)
    supervisor = '''
"$@"
status=$?
rm -f -- "$TMUXGATE_FAKE_MARKER" "$TMUXGATE_FAKE_PID"
exit "$status"
'''
    process = subprocess.Popen(
        ["/bin/sh", "-c", supervisor, "tmuxgate-session", *command],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=environment,
        start_new_session=True,
    )
    if marker.exists():
        pid_file.write_text(str(process.pid), encoding="ascii")
    raise SystemExit(0)
if arguments[:1] == ["has-session"]:
    session = arguments[arguments.index("-t") + 1]
    raise SystemExit(0 if (root / session).exists() else 1)
if arguments[:1] == ["kill-server"]:
    for path in root.glob("*.pid"):
        try:
            os.killpg(int(path.read_text(encoding="ascii")), signal.SIGTERM)
        except (FileNotFoundError, ProcessLookupError, ValueError):
            pass
    raise SystemExit(0)
raise SystemExit(1)
"""


class CommandRecord(TypedDict):
    destination: str
    command: str
    has_bearer_token: bool


class FakeRemote:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.remote_home = root / "remote-home"
        self.bin_dir = root / "bin"
        self.tmux_dir = root / "tmux"
        self.log_path = root / "ssh.jsonl"
        self.password_path = root / "expected-password"
        self.socket_name = f"tmuxgate-test-{os.getpid()}-{id(self):x}"
        self.remote_home.mkdir(mode=0o700)
        self.bin_dir.mkdir(mode=0o700)
        self.tmux_dir.mkdir(mode=0o700)
        self.password_path.write_bytes(b"correct horse")
        self.password_path.chmod(0o600)
        self._program("ssh", SSH_PROGRAM)
        self._program("sudo", SUDO_PROGRAM)
        self._program("tmux", TMUX_PROGRAM)

    def _program(self, name: str, content: str) -> None:
        path = self.bin_dir / name
        path.write_text(content, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def environment(self, *, sudo_mode: str = "passwordless") -> dict[str, str]:
        return {
            "PATH": f"{self.bin_dir}:/usr/bin:/bin",
            "TMUXGATE_TEST_REMOTE_HOME": str(self.remote_home),
            "TMUXGATE_TEST_LOG": str(self.log_path),
            "TMUXGATE_TEST_TMUX_SOCKET": self.socket_name,
            "TMUX_TMPDIR": str(self.tmux_dir),
            "TMUXGATE_TEST_SUDO_MODE": sudo_mode,
            "TMUXGATE_TEST_SUDO_EXPECTED_FILE": str(self.password_path),
        }

    def commands(self) -> list[CommandRecord]:
        try:
            lines = self.log_path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        return [cast(CommandRecord, json.loads(line)) for line in lines]

    def remote_job(self, job_id: str) -> Path:
        return self.remote_home / ".cache" / "tmuxgate" / "jobs" / job_id

    def stop(self) -> None:
        subprocess.run(
            [str(self.bin_dir / "tmux"), "kill-server"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
