"""One ordinary OpenSSH subprocess helper."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
import shlex
from typing import Sequence


@dataclass(frozen=True, slots=True)
class SSHResult:
    returncode: int
    stdout: bytes
    stderr: bytes

    @property
    def stderr_text(self) -> str:
        return sanitize_stderr(self.stderr)


class OutputLimitError(ValueError):
    """A bounded inspection exceeded its SSH response budget."""


def remote_command(arguments: Sequence[str]) -> str:
    if not arguments or any(not isinstance(value, str) or "\x00" in value for value in arguments):
        raise ValueError("remote command arguments must be non-empty NUL-free strings")
    return shlex.join(arguments)


async def run(
    destination: str,
    arguments: Sequence[str],
    *,
    input_data: bytes | bytearray | None = None,
    output_limit: int | None = None,
) -> SSHResult:
    """Run one noninteractive SSH command with normal OpenSSH policy."""

    if output_limit is not None:
        if type(output_limit) is not int or output_limit <= 0 or input_data is not None:
            raise ValueError("bounded SSH requires a positive byte limit and no stdin")
    environment = os.environ.copy()
    environment.pop("TMUXGATE_MCP_TOKEN", None)
    environment.pop("TMUXGATE_BEARER_TOKEN", None)
    launch = asyncio.create_task(asyncio.create_subprocess_exec(
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "--",
        destination,
        remote_command(arguments),
        stdin=(
            asyncio.subprocess.PIPE
            if input_data is not None
            else asyncio.subprocess.DEVNULL
        ),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=environment,
    ))
    try:
        process = await asyncio.shield(launch)
    except asyncio.CancelledError:
        # Cancellation can arrive while the native subprocess is still being
        # created. Retain ownership until it can be reaped, including on Windows.
        try:
            process = await launch
        except Exception:
            raise asyncio.CancelledError from None
        await _stop(process)
        raise
    try:
        if output_limit is None:
            stdout, stderr = await process.communicate(input_data)
        else:
            stdout, stderr = await _bounded_output(process, output_limit)
    except asyncio.CancelledError:
        await _stop(process)
        raise
    except Exception:
        await _stop(process)
        raise
    returncode = process.returncode
    if returncode is None:
        raise RuntimeError("SSH subprocess ended without a return code")
    return SSHResult(returncode, stdout, stderr)


async def _bounded_output(process: asyncio.subprocess.Process, limit: int) -> tuple[bytes, bytes]:
    used = 0

    async def read(stream: asyncio.StreamReader | None) -> bytes:
        nonlocal used
        assert stream is not None
        chunks = []
        while chunk := await stream.read(min(limit + 1, 8192)):
            used += len(chunk)
            if used > limit:
                raise OutputLimitError("SSH inspection output exceeded its byte limit")
            chunks.append(chunk)
        return b"".join(chunks)

    readers = [asyncio.create_task(read(process.stdout)), asyncio.create_task(read(process.stderr))]
    try:
        stdout, stderr = await asyncio.gather(*readers)
        await process.wait()
        return stdout, stderr
    finally:
        for reader in readers:
            reader.cancel()
        await asyncio.gather(*readers, return_exceptions=True)


async def _stop(process: asyncio.subprocess.Process) -> None:
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(process.communicate(), timeout=2)
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.communicate()


def sanitize_stderr(stderr: bytes, limit: int = 2000) -> str:
    text = stderr.decode("utf-8", errors="replace")
    cleaned = "".join(
        character if character in "\n\t" or ord(character) >= 32 else "?"
        for character in text
    )
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "…"
    return cleaned.strip()
