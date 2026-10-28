"""Installed foreground broker and process-lock smoke tests on both platforms."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import build_opener, ProxyHandler

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from tmuxgate.storage import atomic_write, broker_lock, ensure_directory


class ForegroundTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="tmuxgate foreground ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "private state"
        ensure_directory(self.state)

    def stop(self, process: subprocess.Popen) -> None:
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=10)

    def test_broker_lock_excludes_second_process_and_is_released_after_crash(self) -> None:
        code = (
            "from pathlib import Path; import sys; "
            "from tmuxgate.storage import broker_lock; "
            "lock=broker_lock(Path(sys.argv[1])); lock.__enter__(); "
            "print('locked', flush=True); sys.stdin.buffer.read()"
        )
        process = subprocess.Popen([sys.executable, "-c", code, str(self.state)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop, process)
        assert process.stdout is not None
        self.assertEqual(process.stdout.readline().strip(), b"locked")
        with self.assertRaises(OSError):
            with broker_lock(self.state):
                self.fail("second broker acquired an active lock")
        process.kill()
        process.communicate(timeout=10)
        with broker_lock(self.state):
            pass

    def test_foreground_serve_authenticates_and_keeps_job_and_inspection_api(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config = self.root / "config.toml"
        # No test submits execution; the destination is a deliberately invalid name.
        config.write_text(f'[machines]\nsynthetic = "never-contact.invalid"\n[mcp]\nport = {port}\n', encoding="utf-8")
        atomic_write(self.state / "mcp-token", b"synthetic-test-token\n", exclusive=True)
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        # There is no SSH executable in this task's child search path.
        environment["PATH"] = str(self.root)
        process = subprocess.Popen([sys.executable, "-m", "tmuxgate", "--config", str(config),
            "--state-dir", str(self.state), "serve"], cwd=self.root, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop, process)
        endpoint = f"http://127.0.0.1:{port}/mcp"
        opener = build_opener(ProxyHandler({}))
        deadline = time.monotonic() + 15
        while True:
            try:
                opener.open(endpoint, timeout=0.5)
            except HTTPError as exc:
                self.assertEqual(exc.code, 401)
                exc.close()
                break
            except URLError:
                if process.poll() is not None or time.monotonic() >= deadline:
                    self.fail(f"foreground broker failed to listen (exit={process.poll()})")
                time.sleep(0.05)

        async def inspect() -> None:
            async with httpx2.AsyncClient(headers={"Authorization": "Bearer synthetic-test-token"}, trust_env=False) as client, streamable_http_client(endpoint, http_client=client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    self.assertEqual({tool.name for tool in tools.tools}, {"run_argv", "run_script", "get_job", "list_jobs", "list_tmux_panes", "capture_tmux_pane", "send_tmux_text", "send_tmux_key"})
                    jobs = await session.call_tool("list_jobs", {})
                    self.assertEqual(jobs.structured_content, {"jobs": []})

        asyncio.run(inspect())
        self.assertIsNone(process.poll())
        self.stop(process)
        with broker_lock(self.state):
            pass
