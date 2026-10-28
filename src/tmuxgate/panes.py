"""Bounded inspection and explicit input for existing tmux panes over SSH."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
import re
import unicodedata

from tmuxgate import ssh


MAX_RESPONSE_BYTES = 65536
MAX_PANES = 1000
DEFAULT_TIMEOUT = 10.0
PANE_FORMAT = "\t".join((
    "#{pid}:#{start_time}", "#{session_id}", "#{window_id}", "#{pane_id}",
    "#{pane_height}", "#{pane_width}",
    "#{pane_pid}",
))
FRAME_FORMAT = "TMUXGATE_PANE_V1\t#{pid}:#{start_time}\t#{window_id}\t#{pane_id}"
# No tmux startup, arbitrary sockets, shell interpolation, or names.
LIST_SCRIPT = 'command -v tmux >/dev/null 2>&1 || exit 127; export LC_ALL=C; exec tmux -u list-panes -a -F "$1"'


class PaneError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class Pane:
    server_id: str
    session_id: str
    window_id: str
    pane_id: str
    height: int
    width: int
    pane_pid: int

    def view(self) -> dict[str, object]:
        return asdict(self)


def validate_timeout(timeout: float) -> None:
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError("timeout must be finite and greater than 0, at most 30 seconds")


def _identity(value: str, pattern: str, label: str) -> None:
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError(f"{label} must be an exact ID returned by list_tmux_panes")


def validate_target(server_id: str, session_id: str, window_id: str, pane_id: str, lines: int) -> None:
    _identity(server_id, r"[0-9]{1,20}:[0-9]{1,20}", "server_id")
    for value, prefix, label in ((session_id, "$", "session_id"), (window_id, "@", "window_id"), (pane_id, "%", "pane_id")):
        _identity(value, re.escape(prefix) + r"(?:0|[1-9][0-9]{0,19})", label)
    if type(lines) is not int or not 1 <= lines <= 1000:
        raise ValueError("lines must be an integer from 1 to 1000")


def parse_panes(payload: bytes) -> list[Pane]:
    try:
        text = payload.decode("ascii")
        rows = text.splitlines()
        if len(rows) > MAX_PANES:
            raise ValueError("too many panes")
        panes = []
        identities = set()
        servers = set()
        for row in rows:
            server, session, window, pane, height, width, pane_pid = row.split("\t")
            validate_target(server, session, window, pane, 1)
            if re.fullmatch(r"[1-9][0-9]{0,5}", height) is None or re.fullmatch(r"[1-9][0-9]{0,5}", width) is None:
                raise ValueError("invalid pane dimensions")
            if re.fullmatch(r"[1-9][0-9]{0,19}", pane_pid) is None:
                raise ValueError("invalid pane process identity")
            identity = (session, window, pane)
            if identity in identities:
                raise ValueError("ambiguous pane identity")
            identities.add(identity)
            servers.add(server)
            panes.append(Pane(server, session, window, pane, int(height), int(width), int(pane_pid)))
        if len(servers) > 1:
            raise ValueError("inconsistent server identity")
        return panes
    except (UnicodeError, ValueError) as exc:
        raise PaneError("invalid_tmux_output", "tmux returned invalid or ambiguous pane metadata") from exc


async def _read(destination: str, arguments: list[str]) -> ssh.SSHResult:
    try:
        result = await ssh.run(destination, arguments, output_limit=MAX_RESPONSE_BYTES)
    except ssh.OutputLimitError as exc:
        raise PaneError("output_limit", "inspection exceeded 65536 bytes; reduce lines or pane count") from exc
    except OSError as exc:
        raise PaneError("ssh_failed", "unable to launch the SSH inspection") from exc
    if result.returncode == 255:
        raise PaneError("ssh_failed", "SSH inspection failed; verify connectivity, authentication, and host key")
    if result.returncode == 127:
        raise PaneError("tmux_unavailable", "tmux is unavailable on the configured target")
    return result


async def list_panes(destination: str) -> list[Pane]:
    result = await _read(destination, ["/bin/sh", "-c", LIST_SCRIPT, "tmuxgate-list-panes", PANE_FORMAT])
    if result.returncode:
        # Only tmux's known no-server diagnostics mean an empty inventory.
        error = result.stderr.decode("ascii", errors="replace").strip()
        if result.returncode == 1 and (error.startswith("no server running on ") or (
            error.startswith("error connecting to ") and error.endswith("(No such file or directory)")
        )):
            return []
        raise PaneError("tmux_failed", "unable to list existing tmux panes")
    return parse_panes(result.stdout)


def _select(panes: list[Pane], server: str, session: str, window: str, pane: str) -> Pane:
    matches = [item for item in panes if (item.server_id, item.session_id, item.window_id, item.pane_id) == (server, session, window, pane)]
    if len(matches) != 1:
        raise PaneError("stale_target", "exact pane target no longer exists; list panes again and select explicitly")
    return matches[0]


def terminal_text(payload: bytes) -> str:
    # tmux capture omits attributes; also neutralize embedded terminal controls,
    # bidi controls and OSC introducers. Never treat pane text as instructions.
    return "".join(
        f"\\u{ord(character):04x}" if character not in "\n\t" and unicodedata.category(character) in {"Cc", "Cf", "Cs"} else character
        for character in payload.decode("utf-8", errors="replace")
    )


async def capture_pane(destination: str, server: str, session: str, window: str, pane: str, lines: int) -> dict[str, object]:
    selected = _select(await list_panes(destination), server, session, window, pane)
    # One tmux command queue binds the metadata/capture to one server connection.
    # -p writes stdout only: it never creates or replaces a tmux paste buffer.
    result = await _read(destination, [
        "tmux", "-u", "display-message", "-p", "-t", pane, FRAME_FORMAT,
        ";", "capture-pane", "-p", "-t", pane, "-S", str(selected.height - lines), "-E", str(selected.height - 1),
        ";", "display-message", "-p", "-t", pane, FRAME_FORMAT,
    ])
    if result.returncode:
        raise PaneError("stale_target", "pane capture failed; list panes again and select explicitly")
    frame = f"TMUXGATE_PANE_V1\t{server}\t{window}\t{pane}\n".encode("ascii")
    if not result.stdout.startswith(frame) or not result.stdout.endswith(frame) or len(result.stdout) < 2 * len(frame):
        raise PaneError("stale_target", "pane identity changed during capture; discard output and list again")
    _select(await list_panes(destination), server, session, window, pane)
    payload = result.stdout[len(frame):-len(frame)]
    # A concurrent resize can change the captured line count; bound it locally too.
    physical_lines = payload.split(b"\n")
    if physical_lines[-1] == b"":
        physical_lines.pop()
    payload = b"\n".join(physical_lines[-lines:]) + (b"\n" if payload.endswith(b"\n") else b"")
    return {
        "server_id": server, "session_id": session, "window_id": window, "pane_id": pane,
        "text": terminal_text(payload), "encoding": "utf-8", "untrusted": True,
        "lines": payload.count(b"\n"), "controls_escaped": True,
    }
