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


def remote_command(arguments: Sequence[str]) -> str:
    if not arguments or any(not isinstance(value, str) or "\x00" in value for value in arguments):
        raise ValueError("remote command arguments must be non-empty NUL-free strings")
    return shlex.join(arguments)


async def run(
    destination: str,
    arguments: Sequence[str],
    *,
    input_data: bytes | bytearray | None = None,
) -> SSHResult:
    """Run one noninteractive SSH command with normal OpenSSH policy."""

    environment = os.environ.copy()
    environment.pop("TMUXGATE_MCP_TOKEN", None)
    environment.pop("TMUXGATE_BEARER_TOKEN", None)
    process = await asyncio.create_subprocess_exec(
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "--",
        destination,
        remote_command(arguments),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=environment,
    )
    try:
        stdout, stderr = await process.communicate(input_data)
    except asyncio.CancelledError:
        if process.returncode is None:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()
        raise
    returncode = process.returncode
    if returncode is None:
        raise RuntimeError("SSH subprocess ended without a return code")
    return SSHResult(returncode, stdout, stderr)


def sanitize_stderr(stderr: bytes, limit: int = 2000) -> str:
    text = stderr.decode("utf-8", errors="replace")
    cleaned = "".join(
        character if character in "\n\t" or ord(character) >= 32 else "?"
        for character in text
    )
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "…"
    return cleaned.strip()
