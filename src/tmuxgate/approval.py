"""Broker-terminal-only request display and approval.

The public entry point in this module deliberately accepts no response supplied
by a client request.  In normal use it opens the process's controlling terminal
at ``/dev/tty``; tests may inject an :class:`ApprovalTerminal`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from enum import StrEnum
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
from typing import TextIO

from .connection_plan import ConnectionPlan, PlannedEndpoint
from .models import RequestSpec, validate_alias, validate_request_id


CONTROLLING_TTY_PATH = "/dev/tty"
DEFAULT_PAGER_THRESHOLD_BYTES = 64 * 1024
SCRIPT_RENDER_CHUNK_BYTES = 256
INLINE_SCRIPT_BYTES = 2048
_DEFAULT_PAGER = object()
_LESS_PATHS = (Path("/usr/bin/less"), Path("/bin/less"))
_PAGER_LOCALE_KEYS = ("COLORTERM", "LANG", "LC_ALL", "LC_CTYPE", "TERM")


class ApprovalError(RuntimeError):
    """The broker could not obtain a trustworthy approval decision."""


class ApprovalTerminalError(ApprovalError):
    """The broker's controlling terminal could not be opened."""


class ApprovalDisplayError(ApprovalError):
    """The complete approval document could not be displayed."""


class ApprovalInputError(ApprovalError):
    """The broker terminal stopped producing valid approval input."""


class ApprovalDecision(StrEnum):
    """The only information retained from the approval input line."""

    APPROVED = "approved"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class ApprovalTerminal:
    """Separate text streams for one trusted controlling terminal.

    Separate streams avoid update-mode buffering ambiguities on ``/dev/tty``.
    Production callers should let :func:`request_approval` open these streams;
    injection exists for deterministic local tests and broker integration.
    """

    reader: TextIO
    writer: TextIO


# A pager receives the complete, safely escaped approval document.  Its return
# value has no meaning and is intentionally ignored.
ApprovalPager = Callable[[str], object]


def _validate_controlling_terminal(reader: TextIO, writer: TextIO) -> None:
    """Prove both production streams are the same character terminal."""

    try:
        reader_fd = reader.fileno()
        writer_fd = writer.fileno()
        reader_stat = os.fstat(reader_fd)
        writer_stat = os.fstat(writer_fd)
        valid = (
            os.isatty(reader_fd)
            and os.isatty(writer_fd)
            and stat.S_ISCHR(reader_stat.st_mode)
            and stat.S_ISCHR(writer_stat.st_mode)
            and reader_stat.st_rdev == writer_stat.st_rdev
        )
    except (AttributeError, OSError, ValueError) as exc:
        raise ApprovalTerminalError(
            "broker /dev/tty streams could not be validated"
        ) from exc
    if not valid:
        raise ApprovalTerminalError("broker /dev/tty is not one controlling terminal")


@contextmanager
def open_approval_terminal() -> Iterator[ApprovalTerminal]:
    """Open independent input/output streams on the controlling ``/dev/tty``."""

    with ExitStack() as stack:
        try:
            reader = stack.enter_context(
                open(
                    CONTROLLING_TTY_PATH,
                    "r",
                    encoding="utf-8",
                    errors="surrogateescape",
                    buffering=1,
                    newline="",
                )
            )
            writer = stack.enter_context(
                open(
                    CONTROLLING_TTY_PATH,
                    "w",
                    encoding="utf-8",
                    errors="strict",
                    buffering=1,
                    newline="",
                )
            )
        except (OSError, ValueError) as exc:
            raise ApprovalTerminalError(
                f"unable to open broker controlling terminal {CONTROLLING_TTY_PATH}"
            ) from exc
        _validate_controlling_terminal(reader, writer)
        yield ApprovalTerminal(reader=reader, writer=writer)


def _quoted_text(value: str) -> str:
    """Return an ASCII, control-character-safe, reversible string spelling."""

    return json.dumps(value, ensure_ascii=True, allow_nan=False)


def _terminal_safe_document(lines: list[str]) -> str:
    """Join display lines only when every non-newline byte is printable ASCII."""

    document = "\n".join(lines) + "\n"
    if any(
        character != "\n" and not 0x20 <= ord(character) <= 0x7E
        for character in document
    ):
        raise ApprovalDisplayError(
            "approval renderer produced a non-printable terminal character"
        )
    return document


def _canonical_sha256(document: dict[str, object]) -> str:
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def approval_binding_sha256(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan,
) -> str:
    """Bind the exact request to the exact locally proven connection plan."""

    request_id = validate_request_id(request_id)
    if request.machine_alias != connection_plan.machine_name:
        raise ApprovalError("request machine alias does not match the connection plan")
    return _canonical_sha256(
        {
            "binding_version": 1,
            "connection_plan_sha256": connection_plan.plan_sha256,
            "client_request_sha256": request.client_request_sha256(),
            "request_id": request_id,
        }
    )


def _connection_plan_lines(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan,
) -> list[str]:
    binding = approval_binding_sha256(request_id, request, connection_plan)
    lines = [
        "connection_plan_bound: true",
        f"approval_binding_sha256: {binding}",
        f"connection_plan_sha256: {connection_plan.plan_sha256}",
        f"network_snapshot_sha256: {connection_plan.network_snapshot_sha256}",
        f"network_collection_error_count: {len(connection_plan.network_collection_errors)}",
    ]
    lines.extend(
        f"  network_collection_error: {_quoted_text(item)}"
        for item in connection_plan.network_collection_errors
    )
    lines.append(f"route_candidate_count: {len(connection_plan.candidates)}")
    for index, candidate in enumerate(connection_plan.candidates):
        lines.extend(
            [
                f"  candidate[{index}].endpoint_id: {_quoted_text(candidate.endpoint_id)}",
                f"  candidate[{index}].target: {candidate.address}:{candidate.port}",
                f"  candidate[{index}].context: {candidate.required_context}",
                f"  candidate[{index}].priority: {candidate.priority}",
                f"  candidate[{index}].result: {candidate.result}",
            ]
        )
        lines.extend(
            f"    reason: {_quoted_text(reason)}" for reason in candidate.reasons
        )
    lines.extend(
        [
            f"approved_route_count: {len(connection_plan.endpoints)}",
            f"fallback_policy: {connection_plan.fallback_policy}",
            "fallback_requires_new_terminal_confirmation: true",
            "fallback_forbidden_after_remote_mutation: true",
        ]
    )
    for endpoint in connection_plan.endpoints:
        resolved = endpoint.resolved
        prefix = f"  route[{endpoint.route_index}]"
        lines.extend(
            [
                f"{prefix}.role: {endpoint.role}",
                f"{prefix}.endpoint_id: {_quoted_text(resolved.endpoint_id)}",
                f"{prefix}.required_context: {resolved.required_context}",
                f"{prefix}.configured_target: {resolved.configured_address}:{resolved.configured_port}",
                f"{prefix}.ssh_profile: {_quoted_text(resolved.ssh_profile)}",
                f"{prefix}.resolved_identity: {_quoted_text(resolved.resolved_user)}@{_quoted_text(resolved.resolved_hostname)}:{resolved.resolved_port}",
                f"{prefix}.host_key_alias: {_quoted_text(resolved.host_key_alias)}",
                f"{prefix}.host_key_status: {resolved.host_key_evidence.status}",
                f"{prefix}.strict_host_key_checking: {resolved.strict_host_key_checking}",
                f"{prefix}.proxy_jump: {_quoted_text(resolved.proxy_jump or 'none')}",
                f"{prefix}.proxy_command: {_quoted_text(resolved.proxy_command or 'none')}",
                f"{prefix}.identity_agent: {_quoted_text(resolved.identity_agent or 'default')}",
                f"{prefix}.ssh_g_output_sha256: {resolved.ssh_g_output_sha256}",
                f"{prefix}.ssh_policy_sha256: {resolved.ssh_policy_sha256}",
            ]
        )
        for record in resolved.host_key_evidence.records:
            lines.append(
                f"{prefix}.host_key: {record.algorithm} {record.fingerprint_sha256} "
                f"marker={_quoted_text(record.marker or 'none')} "
                f"source={_quoted_text(record.source_path)}"
            )
        for index, argument in enumerate(resolved.ssh_g_argv):
            lines.append(f"{prefix}.ssh_g_argv[{index}]: {_quoted_text(argument)}")
    return lines


def _script_lines(script: bytes) -> list[str]:
    """Render every byte in fixed-size rows with line and offset metadata.

    Rows are bounded by script bytes, not by the number of newline characters.
    A newline-only maximum-size payload therefore cannot manufacture millions
    of Python objects before the human sees the approval document.
    """

    if not script:
        return ["  @00000000 L000001 b''"]
    rendered: list[str] = []
    line_number = 1
    for absolute_offset in range(0, len(script), SCRIPT_RENDER_CHUNK_BYTES):
        chunk = script[absolute_offset : absolute_offset + SCRIPT_RENDER_CHUNK_BYTES]
        newline_count = chunk.count(b"\n")
        last_line = line_number + newline_count
        if chunk.endswith(b"\n"):
            last_line -= 1
        if last_line > line_number:
            label = f"L{line_number:06d}-L{last_line:06d}"
        else:
            continuation = "+" if absolute_offset and script[absolute_offset - 1] != 0x0A else ""
            label = f"L{line_number:06d}{continuation}"
        rendered.append(f"  @{absolute_offset:08x} {label} {chunk!r}")
        line_number += newline_count
    return rendered


def _risk_indicators(request: RequestSpec) -> tuple[str, ...]:
    indicators: list[str] = []
    if request.mode.value == "script":
        indicators.append("SCRIPT_MODE")
    if request.timeout_seconds is None:
        indicators.append("NO_TIMEOUT_REQUESTED")
    if request.environment:
        indicators.append("ADDED_ENVIRONMENT")
    if request.argv:
        command = request.argv[0].rsplit("/", 1)[-1].lower()
        if command in {"rm", "dd", "mkfs", "wipefs", "shred", "zpool", "zfs"}:
            indicators.append("DESTRUCTIVE_TOOL_NAME")
        if command == "sudo":
            indicators.append("PRIVILEGE_TOOL")
        if command in {"sh", "bash", "dash", "zsh", "fish"}:
            indicators.append("SHELL_INTERPRETER")
    lowered_script = request.script.lower()
    if b"sudo" in lowered_script:
        indicators.append("SCRIPT_MENTIONS_SUDO")
    if any(token in lowered_script for token in (b"rm -", b"mkfs", b"wipefs", b"zpool destroy")):
        indicators.append("SCRIPT_DESTRUCTIVE_TEXT")
    return tuple(dict.fromkeys(indicators))


_RISK_EXPLANATIONS = {
    "SCRIPT_MODE": "Runs a script rather than one structured program argv",
    "NO_TIMEOUT_REQUESTED": "No timeout; interrupt a stuck command manually",
    "ADDED_ENVIRONMENT": "Adds environment variables to the remote command",
    "DESTRUCTIVE_TOOL_NAME": "Command name is commonly destructive",
    "PRIVILEGE_TOOL": "Command may request elevated privileges",
    "SHELL_INTERPRETER": "Command starts a shell interpreter",
    "SCRIPT_MENTIONS_SUDO": "Script mentions sudo",
    "SCRIPT_DESTRUCTIVE_TEXT": "Script contains potentially destructive text",
}


def _readable_script_lines(script: bytes) -> list[str]:
    """Render exact bytes as readable numbered source without terminal controls."""

    if not script:
        return ["000001 | (empty script)"]
    lines: list[str] = []
    line_number = 1
    for raw_line in script.splitlines(keepends=True):
        content = raw_line
        ending = ""
        if content.endswith(b"\n"):
            content = content[:-1]
            ending = "\\n"
            if content.endswith(b"\r"):
                content = content[:-1]
                ending = "\\r\\n"
        for offset in range(0, max(1, len(content)), SCRIPT_RENDER_CHUNK_BYTES):
            chunk = content[offset : offset + SCRIPT_RENDER_CHUNK_BYTES]
            rendered = "".join(
                chr(value)
                if 0x20 <= value <= 0x7E and value != 0x5C
                else "\\\\"
                if value == 0x5C
                else "\\t"
                if value == 0x09
                else f"\\x{value:02x}"
                for value in chunk
            )
            marker = f"{line_number:06d}" if offset == 0 else "      +"
            suffix = ending if offset + len(chunk) >= len(content) else ""
            lines.append(f"{marker} | {rendered}{suffix}")
        line_number += 1
    if script and not script.endswith((b"\n", b"\r")):
        pass
    return lines


def render_code_document(request_id: str, request: RequestSpec) -> str:
    """Render the exact command/script in a compact pager-friendly form."""

    request_id = validate_request_id(request_id)
    if not isinstance(request, RequestSpec):
        raise TypeError("request must be a RequestSpec")
    lines = [
        f"=== tmuxgate code {request_id[:8]} ===",
        f"mode: {request.mode.value}",
        f"cwd: {_quoted_text(request.cwd)}",
    ]
    if request.argv:
        lines.append(
            f"shell_escaped_view: {_quoted_text(shlex.join(request.argv))}"
        )
        lines.append("exact_structured_argv:")
        lines.extend(
            f"  [{index}] {_quoted_text(argument)}"
            for index, argument in enumerate(request.argv)
        )
    else:
        lines.extend(
            [
                f"script_bytes: {len(request.script)}",
                f"script_sha256: {hashlib.sha256(request.script).hexdigest()}",
                "exact_script_source (\\xNN escapes are literal byte values):",
                *_readable_script_lines(request.script),
            ]
        )
    lines.append("=== end code ===")
    return _terminal_safe_document(lines)


def render_approval_summary(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan | None = None,
) -> str:
    """Render the decision-relevant approval card; details remain pageable."""

    request_id = validate_request_id(request_id)
    risks = _risk_indicators(request)
    lines = [
        "",
        "TMUXGATE APPROVAL",
        "=================",
        (
            f"WHY        {_quoted_text(request.purpose)}"
            if request.purpose is not None
            else "WHY        No explanation supplied; review the exact command"
        ),
    ]
    if connection_plan is None:
        lines.append(
            f"CONNECT    {_quoted_text(request.machine_alias)} "
            "(route details unavailable)"
        )
    else:
        selected = connection_plan.selected.resolved
        lines.extend(
            [
                (
                    f"CONNECT    {_quoted_text(request.machine_alias)} -> "
                    f"{_quoted_text(selected.resolved_user)}@"
                    f"{_quoted_text(selected.resolved_hostname)}:"
                    f"{selected.resolved_port} via "
                    f"{_quoted_text(selected.required_context)}"
                ),
                (
                    f"IDENTITY   Host key {selected.host_key_evidence.status}; "
                    f"strict checking {selected.strict_host_key_checking}"
                ),
            ]
        )
    lines.append(f"DIRECTORY  {_quoted_text(request.cwd)}")
    if request.argv:
        lines.extend(
            ["", "RUN", "---", _quoted_text(shlex.join(request.argv))]
        )
    else:
        lines.extend(["", f"RUN SCRIPT ({len(request.script)} bytes)", "----------"])
        if len(request.script) <= INLINE_SCRIPT_BYTES:
            lines.extend(_readable_script_lines(request.script))
        else:
            lines.append("Complete script opened in the code pager before this prompt.")
    if request.environment:
        lines.extend(["", "ADDED ENVIRONMENT"])
        lines.extend(
            f"  {_quoted_text(name)}={_quoted_text(value)}"
            for name, value in request.environment
        )
    timeout = "none" if request.timeout_seconds is None else f"{request.timeout_seconds}s"
    lines.extend(["", f"TIMEOUT    {timeout}"])
    if risks:
        lines.append("SAFETY")
        lines.extend(f"  - {_RISK_EXPLANATIONS[item]}" for item in risks)
    else:
        lines.append("SAFETY     No obvious advisory flags")
    lines.extend(["", "Press d for technical identities, evidence, and binding hashes."])
    return _terminal_safe_document(lines)


def render_approval_document(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan | None = None,
) -> str:
    """Render the complete request without emitting terminal control bytes.

    Text values use JSON string notation and scripts use complete Python bytes
    literals.  Both forms are reversible.  Script bytes are split only for
    readability; no preview, ellipsis, or truncation is used.
    """

    request_id = validate_request_id(request_id)
    if not isinstance(request, RequestSpec):
        raise TypeError("request must be a RequestSpec")

    short_id = request_id[:8]
    lines = [
        "=== tmuxgate broker approval ===",
        f"request_id: {request_id}",
        f"approval_short_id: {short_id}",
        f"machine_alias: {_quoted_text(request.machine_alias)}",
        f"mode: {request.mode.value}",
        f"cwd: {_quoted_text(request.cwd)}",
        f"purpose: {_quoted_text(request.purpose) if request.purpose is not None else 'none'}",
        f"argv_count: {len(request.argv)}",
    ]
    if connection_plan is None:
        lines.append("connection_plan_bound: false")
    else:
        lines.extend(_connection_plan_lines(request_id, request, connection_plan))
    if request.argv:
        lines.extend(
            f"  argv[{index}]: {_quoted_text(argument)}"
            for index, argument in enumerate(request.argv)
        )
    else:
        lines.append("  (no argv elements)")

    lines.append(f"environment_count: {len(request.environment)}")
    if request.environment:
        lines.extend(
            f"  env[{_quoted_text(name)}]: {_quoted_text(value)}"
            for name, value in request.environment
        )
    else:
        lines.append("  (no environment entries)")

    timeout = "none" if request.timeout_seconds is None else str(request.timeout_seconds)
    lines.extend(
        [
            f"timeout_seconds: {timeout}",
            f"result_format: {request.result_format.value}",
            f"client_request_sha256: {request.client_request_sha256()}",
            f"script_bytes: {len(request.script)}",
            f"script_sha256: {hashlib.sha256(request.script).hexdigest()}",
            (
                "script_complete_bytes_literals: "
                f"ordered chunks of at most {SCRIPT_RENDER_CHUNK_BYTES} bytes"
            ),
        ]
    )
    risks = _risk_indicators(request)
    lines.append(f"risk_indicator_count: {len(risks)}")
    lines.extend(f"  risk: {risk}" for risk in risks)
    lines.extend(_script_lines(request.script))
    lines.append("=== end complete request ===")
    return _terminal_safe_document(lines)


def _write_all(writer: TextIO, content: str) -> None:
    """Write and flush all characters, failing closed on a short write."""

    offset = 0
    try:
        while offset < len(content):
            written = writer.write(content[offset:])
            if (
                isinstance(written, bool)
                or not isinstance(written, int)
                or written <= 0
                or written > len(content) - offset
            ):
                raise ApprovalDisplayError("approval terminal returned a short write")
            offset += written
        writer.flush()
    except ApprovalDisplayError:
        raise
    except Exception as exc:
        raise ApprovalDisplayError("unable to display the complete approval request") from exc


def _display_document(
    terminal: ApprovalTerminal,
    document: str,
    *,
    pager: ApprovalPager | None,
    pager_threshold_bytes: int,
) -> None:
    document_size = len(document.encode("ascii"))
    if pager is not None and document_size >= pager_threshold_bytes:
        try:
            # Do not assign or inspect the return value: pager output is display
            # data, never an approval-input channel.
            pager(document)
        except Exception as exc:
            raise ApprovalDisplayError(
                "configured pager failed before approval input was requested"
            ) from exc
        _write_all(
            terminal.writer,
            "The complete approval document was made available in the configured pager.\n",
        )
        return
    _write_all(terminal.writer, document)


def secure_less_pager(document: str) -> None:
    """Expose the complete safe document through a fixed local `less` binary.

    The document is first written to a sealed, seekable anonymous file.  The
    pager therefore receives an immutable complete file even if the operator
    quits before scrolling to the end; approval never depends on pipe
    consumption or on any value returned by the pager.
    """

    executable = next(
        (
            path
            for path in _LESS_PATHS
            if path.is_file() and os.access(path, os.X_OK)
        ),
        None,
    )
    if executable is None:
        raise ApprovalDisplayError("the required local less pager is unavailable")

    environment = {
        "HOME": "/nonexistent",
        "LESSHISTFILE": "-",
        "LESSSECURE": "1",
        "PATH": "/usr/bin:/bin",
    }
    for name in _PAGER_LOCALE_KEYS:
        value = os.environ.get(name)
        if value and "\x00" not in value:
            environment[name] = value

    raw_document = document.encode("ascii")
    descriptor = -1
    try:
        memfd_create = getattr(os, "memfd_create", None)
        allow_sealing = getattr(os, "MFD_ALLOW_SEALING", None)
        close_on_exec = getattr(os, "MFD_CLOEXEC", 0)
        if memfd_create is None or allow_sealing is None:
            raise ApprovalDisplayError("sealed Linux memfd support is required for paging")
        descriptor = memfd_create(
            "tmuxgate-approval",
            flags=close_on_exec | allow_sealing,
        )
        offset = 0
        while offset < len(raw_document):
            written = os.write(descriptor, raw_document[offset:])
            if written <= 0:
                raise ApprovalDisplayError("approval memfd returned a short write")
            offset += written
        if os.fstat(descriptor).st_size != len(raw_document):
            raise ApprovalDisplayError("approval memfd size does not match the document")
        os.lseek(descriptor, 0, os.SEEK_SET)
        required_seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, required_seals)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) & required_seals != required_seals:
            raise ApprovalDisplayError("approval memfd could not be sealed")

        with (
            open(CONTROLLING_TTY_PATH, "rb", buffering=0) as tty_reader,
            open(CONTROLLING_TTY_PATH, "wb", buffering=0) as tty_writer,
        ):
            completed = subprocess.run(
                [
                    str(executable),
                    "-N",
                    "-F",
                    "-X",
                    "--",
                    f"/proc/self/fd/{descriptor}",
                ],
                stdin=tty_reader,
                stdout=tty_writer,
                stderr=tty_writer,
                env=environment,
                check=False,
                close_fds=True,
                pass_fds=(descriptor,),
            )
    except ApprovalDisplayError:
        raise
    except OSError as exc:
        raise ApprovalDisplayError("unable to start the secure approval pager") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if completed.returncode != 0:
        raise ApprovalDisplayError(
            f"approval pager exited unsuccessfully with status {completed.returncode}"
        )


def _line_without_terminal_ending(raw_line: str) -> str:
    """Remove one LF (and its optional CR), but no other whitespace."""

    if raw_line.endswith("\n"):
        raw_line = raw_line[:-1]
        if raw_line.endswith("\r"):
            raw_line = raw_line[:-1]
    return raw_line


def _read_decision(
    terminal: ApprovalTerminal,
    short_id: str,
    *,
    code_document: str,
    details_document: str,
    pager: ApprovalPager | None,
) -> ApprovalDecision:
    instruction = (
        "Approve? [Y/n]  Enter=yes, c=view code, d=technical details: "
    )

    while True:
        _write_all(terminal.writer, instruction)
        try:
            raw_line = terminal.reader.readline()
        except Exception as exc:
            raise ApprovalInputError("unable to read from the broker terminal") from exc
        if raw_line == "":
            raise ApprovalInputError(
                "broker terminal reached EOF before an approval decision"
            )
        if not isinstance(raw_line, str):
            raise ApprovalInputError("broker terminal returned non-text approval input")

        response = _line_without_terminal_ending(raw_line).casefold()
        # Release the original terminal-input object before making a decision.
        # Invalid response content is neither repeated nor included in errors.
        raw_line = ""
        if response in {"", "y", "yes", "approve"}:
            response = ""
            return ApprovalDecision.APPROVED
        if response in {"n", "no", "deny"}:
            response = ""
            return ApprovalDecision.DENIED
        if response in {"c", "code", "view code", "d", "details", "view details"}:
            selected = (
                code_document
                if response in {"c", "code", "view code"}
                else details_document
            )
            response = ""
            _display_document(
                terminal,
                selected,
                pager=pager,
                pager_threshold_bytes=0,
            )
            continue
        response = ""
        _write_all(
            terminal.writer,
            "Please press Enter/y to approve, n to deny, c for code, or d for details.\n",
        )


def request_approval(
    request_id: str,
    request: RequestSpec,
    *,
    terminal: ApprovalTerminal | None = None,
    pager: ApprovalPager | None | object = _DEFAULT_PAGER,
    pager_threshold_bytes: int = DEFAULT_PAGER_THRESHOLD_BYTES,
    connection_plan: ConnectionPlan | None = None,
) -> ApprovalDecision:
    """Display a request and obtain one exact broker-terminal decision.

    The function returns only :class:`ApprovalDecision`.  It does not return,
    retain, log, or attach invalid terminal input to an exception.
    """

    request_id = validate_request_id(request_id)
    if not isinstance(request, RequestSpec):
        raise TypeError("request must be a RequestSpec")
    if (
        isinstance(pager_threshold_bytes, bool)
        or not isinstance(pager_threshold_bytes, int)
        or pager_threshold_bytes < 0
    ):
        raise ValueError("pager_threshold_bytes must be a non-negative integer")

    details_document = render_approval_document(request_id, request, connection_plan)
    summary_document = render_approval_summary(request_id, request, connection_plan)
    code_document = render_code_document(request_id, request)
    short_id = request_id[:8]
    selected_pager = secure_less_pager if pager is _DEFAULT_PAGER else pager

    if terminal is None:
        with open_approval_terminal() as opened_terminal:
            auto_page_code = request.mode.value == "script" and (
                len(request.script) > INLINE_SCRIPT_BYTES
                or len(code_document.encode("ascii")) >= pager_threshold_bytes
            )
            if auto_page_code:
                _display_document(
                    opened_terminal,
                    code_document,
                    pager=selected_pager,
                    pager_threshold_bytes=pager_threshold_bytes,
                )
            _write_all(opened_terminal.writer, summary_document)
            return _read_decision(
                opened_terminal,
                short_id,
                code_document=code_document,
                details_document=details_document,
                pager=selected_pager,
            )

    auto_page_code = request.mode.value == "script" and (
        len(request.script) > INLINE_SCRIPT_BYTES
        or len(code_document.encode("ascii")) >= pager_threshold_bytes
    )
    if auto_page_code:
        _display_document(
            terminal,
            code_document,
            pager=selected_pager,
            pager_threshold_bytes=pager_threshold_bytes,
        )
    _write_all(terminal.writer, summary_document)
    return _read_decision(
        terminal,
        short_id,
        code_document=code_document,
        details_document=details_document,
        pager=selected_pager,
    )


def request_bound_approval(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan,
    **kwargs: object,
) -> ApprovalDecision:
    """Require an approval document that contains a complete connection plan."""

    if not isinstance(connection_plan, ConnectionPlan):
        raise TypeError("connection_plan must be a ConnectionPlan")
    return request_approval(
        request_id,
        request,
        connection_plan=connection_plan,
        **kwargs,
    )


def _find_adjacent_fallback(
    connection_plan: ConnectionPlan,
    failed_endpoint_id: str,
    fallback_endpoint_id: str,
) -> tuple[PlannedEndpoint, PlannedEndpoint]:
    by_id = {item.resolved.endpoint_id: item for item in connection_plan.endpoints}
    failed = by_id.get(failed_endpoint_id)
    fallback = by_id.get(fallback_endpoint_id)
    if failed is None or fallback is None:
        raise ApprovalError("fallback endpoint is not in the approved connection plan")
    if fallback.route_index != failed.route_index + 1:
        raise ApprovalError("fallback must be the next route in the approved plan")
    return failed, fallback


def render_fallback_approval_document(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan,
    *,
    failed_endpoint_id: str,
    fallback_endpoint_id: str,
    failure_detail: str,
    remote_mutation_started: bool,
) -> str:
    """Render a new, exact fallback decision; never reuse the RUN approval."""

    request_id = validate_request_id(request_id)
    if remote_mutation_started:
        raise ApprovalError("fallback is forbidden after remote mutation has started")
    if not isinstance(failure_detail, str) or "\x00" in failure_detail:
        raise ApprovalError("fallback failure detail must be valid text")
    approval_binding_sha256(request_id, request, connection_plan)
    failed, fallback = _find_adjacent_fallback(
        connection_plan, failed_endpoint_id, fallback_endpoint_id
    )
    fallback_binding = _canonical_sha256(
        {
            "client_request_sha256": request.client_request_sha256(),
            "connection_plan_sha256": connection_plan.plan_sha256,
            "failed_endpoint_id": failed_endpoint_id,
            "failure_detail": failure_detail,
            "fallback_binding_version": 1,
            "fallback_endpoint_id": fallback_endpoint_id,
            "request_id": request_id,
        }
    )
    old = failed.resolved
    new = fallback.resolved
    return _terminal_safe_document(
        [
            "=== tmuxgate broker fallback approval ===",
            f"request_id: {request_id}",
            f"approval_short_id: {request_id[:8]}",
            f"connection_plan_sha256: {connection_plan.plan_sha256}",
            f"fallback_binding_sha256: {fallback_binding}",
            f"failed_endpoint_id: {_quoted_text(old.endpoint_id)}",
            f"failed_target: {_quoted_text(old.configured_address)}:{old.configured_port}",
            f"failure_detail: {_quoted_text(failure_detail)}",
            "remote_mutation_started: false",
            f"fallback_endpoint_id: {_quoted_text(new.endpoint_id)}",
            f"fallback_target: {_quoted_text(new.configured_address)}:{new.configured_port}",
            f"fallback_resolved_identity: {_quoted_text(new.resolved_user)}@{_quoted_text(new.resolved_hostname)}:{new.resolved_port}",
            f"fallback_host_key_alias: {_quoted_text(new.host_key_alias)}",
            f"fallback_host_key_status: {new.host_key_evidence.status}",
            "A new terminal confirmation is required; the original RUN approval is insufficient.",
            "=== end fallback request ===",
            "",
        ]
    )


def _read_fallback_decision(
    terminal: ApprovalTerminal,
    short_id: str,
    fallback_endpoint_id: str,
) -> ApprovalDecision:
    approve_line = f"FALLBACK {short_id} {fallback_endpoint_id}"
    instruction = f"Type exactly {approve_line} to use this fallback, or DENY to deny it.\n"
    _write_all(terminal.writer, instruction)
    while True:
        _write_all(terminal.writer, "tmuxgate fallback> ")
        try:
            raw_line = terminal.reader.readline()
        except Exception as exc:
            raise ApprovalInputError("unable to read from the broker terminal") from exc
        if raw_line == "":
            raise ApprovalInputError(
                "broker terminal reached EOF before a fallback decision"
            )
        if not isinstance(raw_line, str):
            raise ApprovalInputError("broker terminal returned non-text approval input")
        response = _line_without_terminal_ending(raw_line)
        raw_line = ""
        if response == approve_line:
            response = ""
            return ApprovalDecision.APPROVED
        if response == "DENY":
            response = ""
            return ApprovalDecision.DENIED
        response = ""
        _write_all(terminal.writer, "Invalid response; no decision was recorded.\n" + instruction)


def request_fallback_approval(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan,
    *,
    failed_endpoint_id: str,
    fallback_endpoint_id: str,
    failure_detail: str,
    remote_mutation_started: bool,
    terminal: ApprovalTerminal | None = None,
    pager: ApprovalPager | None | object = _DEFAULT_PAGER,
    pager_threshold_bytes: int = DEFAULT_PAGER_THRESHOLD_BYTES,
) -> ApprovalDecision:
    """Obtain a distinct broker-terminal approval for one adjacent fallback."""

    document = render_fallback_approval_document(
        request_id,
        request,
        connection_plan,
        failed_endpoint_id=failed_endpoint_id,
        fallback_endpoint_id=fallback_endpoint_id,
        failure_detail=failure_detail,
        remote_mutation_started=remote_mutation_started,
    )
    selected_pager = secure_less_pager if pager is _DEFAULT_PAGER else pager
    if terminal is None:
        with open_approval_terminal() as opened_terminal:
            _display_document(
                opened_terminal,
                document,
                pager=selected_pager,
                pager_threshold_bytes=pager_threshold_bytes,
            )
            return _read_fallback_decision(
                opened_terminal, request_id[:8], fallback_endpoint_id
            )
    _display_document(
        terminal,
        document,
        pager=selected_pager,
        pager_threshold_bytes=pager_threshold_bytes,
    )
    return _read_fallback_decision(terminal, request_id[:8], fallback_endpoint_id)


def render_ssh_retry_document(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan,
    *,
    endpoint_id: str,
    failure_detail: str,
    remote_mutation_started: bool,
) -> str:
    """Render one bounded retry decision for the same approved SSH endpoint."""

    request_id = validate_request_id(request_id)
    if remote_mutation_started:
        raise ApprovalError("SSH setup retry is forbidden after remote mutation")
    if not isinstance(failure_detail, str) or "\x00" in failure_detail:
        raise ApprovalError("SSH setup failure detail must be valid text")
    approval_binding_sha256(request_id, request, connection_plan)
    endpoint = next(
        (
            item
            for item in connection_plan.endpoints
            if item.resolved.endpoint_id == endpoint_id
        ),
        None,
    )
    if endpoint is None:
        raise ApprovalError("SSH retry endpoint is not in the approved plan")
    resolved = endpoint.resolved
    retry_binding = _canonical_sha256(
        {
            "client_request_sha256": request.client_request_sha256(),
            "connection_plan_sha256": connection_plan.plan_sha256,
            "endpoint_id": endpoint_id,
            "failure_detail": failure_detail,
            "request_id": request_id,
            "ssh_retry_binding_version": 1,
        }
    )
    return _terminal_safe_document(
        [
            "=== tmuxgate SSH setup retry ===",
            f"request_id: {request_id}",
            f"approval_short_id: {request_id[:8]}",
            f"machine: {_quoted_text(connection_plan.machine_name)}",
            f"endpoint_id: {_quoted_text(endpoint_id)}",
            "target: "
            f"{_quoted_text(resolved.configured_address)}:"
            f"{resolved.configured_port}",
            "resolved_identity: "
            f"{_quoted_text(resolved.resolved_user)}@"
            f"{_quoted_text(resolved.resolved_hostname)}:"
            f"{resolved.resolved_port}",
            f"failure_detail: {_quoted_text(failure_detail)}",
            f"ssh_retry_binding_sha256: {retry_binding}",
            "remote_mutation_started: false",
            "No remote command started. OpenSSH printed its diagnostic "
            "immediately above.",
            "One broker-terminal-confirmed retry is allowed for this endpoint.",
            "=== end SSH setup retry ===",
            "",
        ]
    )


def _read_ssh_retry_decision(
    terminal: ApprovalTerminal,
    short_id: str,
    endpoint_id: str,
) -> ApprovalDecision:
    prompt = (
        "Retry SSH setup once for request "
        f"{short_id} on endpoint {endpoint_id}? [Y/n] "
    )
    while True:
        _write_all(terminal.writer, prompt)
        try:
            raw_line = terminal.reader.readline()
        except Exception as exc:
            raise ApprovalInputError("unable to read from the broker terminal") from exc
        if raw_line == "":
            raise ApprovalInputError(
                "broker terminal reached EOF before an SSH retry decision"
            )
        if not isinstance(raw_line, str):
            raise ApprovalInputError("broker terminal returned non-text retry input")
        response = _line_without_terminal_ending(raw_line).casefold()
        raw_line = ""
        if response in {"", "y", "yes"}:
            response = ""
            return ApprovalDecision.APPROVED
        if response in {"n", "no"}:
            response = ""
            return ApprovalDecision.DENIED
        response = ""
        _write_all(
            terminal.writer,
            "Please answer y or n.\n",
        )


def request_ssh_retry(
    request_id: str,
    request: RequestSpec,
    connection_plan: ConnectionPlan,
    *,
    endpoint_id: str,
    failure_detail: str,
    remote_mutation_started: bool,
    terminal: ApprovalTerminal | None = None,
) -> ApprovalDecision:
    """Ask only the broker terminal for one same-endpoint SSH setup retry."""

    document = render_ssh_retry_document(
        request_id,
        request,
        connection_plan,
        endpoint_id=endpoint_id,
        failure_detail=failure_detail,
        remote_mutation_started=remote_mutation_started,
    )
    if terminal is None:
        with open_approval_terminal() as opened_terminal:
            _display_document(
                opened_terminal,
                document,
                pager=None,
                pager_threshold_bytes=DEFAULT_PAGER_THRESHOLD_BYTES,
            )
            return _read_ssh_retry_decision(
                opened_terminal, request_id[:8], endpoint_id
            )
    _display_document(
        terminal,
        document,
        pager=None,
        pager_threshold_bytes=DEFAULT_PAGER_THRESHOLD_BYTES,
    )
    return _read_ssh_retry_decision(terminal, request_id[:8], endpoint_id)


def render_machine_disable_document(
    request_id: str,
    machine_name: str,
    *,
    failure_detail: str,
    remote_mutation_started: bool,
) -> str:
    """Render the local-only choice offered after SSH setup is exhausted."""

    request_id = validate_request_id(request_id)
    machine_name = validate_alias(machine_name)
    if remote_mutation_started:
        raise ApprovalError("machine disable prompt is forbidden after remote mutation")
    if not isinstance(failure_detail, str) or "\x00" in failure_detail:
        raise ApprovalError("SSH setup failure detail must be valid text")
    return _terminal_safe_document(
        [
            "=== tmuxgate machine unavailable ===",
            f"request_id: {request_id}",
            f"machine: {_quoted_text(machine_name)}",
            f"failure_detail: {_quoted_text(failure_detail)}",
            "remote_mutation_started: false",
            "All permitted SSH setup attempts are finished. No remote command started.",
            "Disabling changes only local tmuxgate configuration and blocks future runs.",
            "=== end tmuxgate machine unavailable ===",
            "",
        ]
    )


def _read_machine_disable_decision(
    terminal: ApprovalTerminal,
    machine_name: str,
) -> ApprovalDecision:
    prompt = f"Disable machine {machine_name}? [y/N] "
    while True:
        _write_all(terminal.writer, prompt)
        try:
            raw_line = terminal.reader.readline()
        except Exception as exc:
            raise ApprovalInputError("unable to read from the broker terminal") from exc
        if raw_line == "":
            raise ApprovalInputError(
                "broker terminal reached EOF before a machine disable decision"
            )
        if not isinstance(raw_line, str):
            raise ApprovalInputError(
                "broker terminal returned non-text machine disable input"
            )
        response = _line_without_terminal_ending(raw_line).casefold()
        raw_line = ""
        if response in {"y", "yes"}:
            response = ""
            return ApprovalDecision.APPROVED
        if response in {"", "n", "no"}:
            response = ""
            return ApprovalDecision.DENIED
        response = ""
        _write_all(terminal.writer, "Please answer y or n.\n")


def request_machine_disable(
    request_id: str,
    machine_name: str,
    *,
    failure_detail: str,
    remote_mutation_started: bool,
    terminal: ApprovalTerminal | None = None,
) -> ApprovalDecision:
    """Ask only the broker terminal whether an unavailable machine is disabled."""

    document = render_machine_disable_document(
        request_id,
        machine_name,
        failure_detail=failure_detail,
        remote_mutation_started=remote_mutation_started,
    )
    if terminal is None:
        with open_approval_terminal() as opened_terminal:
            _display_document(
                opened_terminal,
                document,
                pager=None,
                pager_threshold_bytes=DEFAULT_PAGER_THRESHOLD_BYTES,
            )
            return _read_machine_disable_decision(opened_terminal, machine_name)
    _display_document(
        terminal,
        document,
        pager=None,
        pager_threshold_bytes=DEFAULT_PAGER_THRESHOLD_BYTES,
    )
    return _read_machine_disable_decision(terminal, machine_name)
