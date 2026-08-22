from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from tmuxgate import ssh


class _Process:
    def __init__(self) -> None:
        self.returncode: int | None = 0
        self.input_data: bytes | bytearray | None = None

    async def communicate(
        self, input_data: bytes | bytearray | None = None
    ) -> tuple[bytes, bytes]:
        self.input_data = input_data
        return b"stdout", b"stderr"


class SshProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_input_uses_devnull(self) -> None:
        process = _Process()
        create = AsyncMock(return_value=process)
        with patch("asyncio.create_subprocess_exec", create):
            result = await ssh.run("machine", ["true"])

        self.assertEqual(result.returncode, 0)
        self.assertEqual(create.call_args.kwargs["stdin"], asyncio.subprocess.DEVNULL)
        self.assertIsNone(process.input_data)

    async def test_password_buffer_uses_a_pipe_without_an_immutable_copy(self) -> None:
        process = _Process()
        create = AsyncMock(return_value=process)
        password = bytearray(b"secret\n")
        with patch("asyncio.create_subprocess_exec", create):
            await ssh.run("machine", ["sudo", "true"], input_data=password)

        self.assertEqual(create.call_args.kwargs["stdin"], asyncio.subprocess.PIPE)
        self.assertIs(process.input_data, password)


if __name__ == "__main__":
    unittest.main()
