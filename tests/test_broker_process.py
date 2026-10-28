"""Portable broker tests with real native subprocess pipes and fake SSH."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tmuxgate import ssh
from tmuxgate.config import Config
from tmuxgate.credentials import CredentialStore
from tmuxgate.executor import RemoteExecutor
from tmuxgate.jobs import JobStore
from tmuxgate.service import ExecutionService, job_view
from tmuxgate.storage import read_private


class BrokerProcessTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="tmuxgate unicode \u00e7 space ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        environment = patch.dict(os.environ, {
            "TMUXGATE_PROTOCOL_ROOT": str(self.root),
            "TMUXGATE_MCP_TOKEN": "synthetic-client-token",
            "TMUXGATE_BEARER_TOKEN": "synthetic-client-token",
        })
        environment.start()
        self.addCleanup(environment.stop)
        create = asyncio.create_subprocess_exec
        self.processes: list[asyncio.subprocess.Process] = []

        async def fake_ssh(program: str, *arguments: str, **kwargs):
            self.assertEqual(program, "ssh")
            process = await create(
                sys.executable, str(Path(__file__).with_name("fake_ssh_protocol.py")),
                *arguments, **kwargs,
            )
            self.processes.append(process)
            return process

        boundary = patch("asyncio.create_subprocess_exec", fake_ssh)
        boundary.start()
        self.addCleanup(boundary.stop)
        self.store = JobStore(self.root / "private state")
        self.executor = RemoteExecutor(self.store, CredentialStore(self.store.state_dir), poll_interval=0.01)
        self.service = self.new_service()
        self.addAsyncCleanup(self.service.close)

    def new_service(self) -> ExecutionService:
        return ExecutionService(Config({"machine": "configured-alias", "hostkey": "hostkey-fail"}), self.store, self.executor)

    def calls(self) -> list[dict]:
        path = self.root / "calls.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []

    async def settle(self, service: ExecutionService) -> None:
        async with asyncio.timeout(10):
            while service._tasks:
                await asyncio.sleep(0.02)

    async def test_native_pipes_preserve_bytes_and_remote_quoting(self) -> None:
        arguments = ["echo", "a b", "'quoted'", "$HOME; & |", "\u00e7", "line\nbreak"]
        payload = b"stdin\r\n\x00\xff"
        result = await ssh.run("configured-alias", arguments, input_data=payload)
        self.assertEqual(result.stdout, payload)
        self.assertEqual(result.stderr, b"error\r\n\x00\xff")
        call = self.calls()[0]
        self.assertEqual(call["arguments"], arguments)
        self.assertEqual(call["destination"], "configured-alias")
        self.assertEqual(call["options"], ["-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "--"])
        self.assertFalse(call["bearer"])

    async def test_completed_job_preserves_binary_results_and_cleans_after_save(self) -> None:
        (self.root / "done").touch()
        job = await self.service.run_script("machine", "/tmp/a b", "printf '\u00e7\\r\\n'\n")
        self.assertEqual(job.state, "complete")
        self.assertEqual(job.exit_code, 17)
        self.assertEqual(read_private(Path(job.stdout_path)), b"out\r\n\x00\xff")
        self.assertEqual(read_private(Path(job.stderr_path)), b"err\r\n\xfe")
        self.assertEqual(job_view(job)["stdout_encoding"], "base64")
        self.assertEqual(self.store.load(job.job_id), job)
        self.assertTrue((self.root / "cleaned").exists())
        staged = (self.root / "staged").read_bytes()
        self.assertIn("\u00e7".encode(), staged)
        self.assertNotIn(b"\r\n", staged)

    async def test_host_key_failure_is_fatal_before_start(self) -> None:
        job = await self.service.run_argv("hostkey", "/tmp", ["true"])
        self.assertEqual((job.state, job.error_code), ("failed", "ssh_failed"))
        self.assertFalse((self.root / "starts").exists())

    async def test_initial_publication_failure_never_launches_ssh(self) -> None:
        with patch("tmuxgate.jobs.atomic_write", side_effect=OSError("synthetic durable write failure")):
            with self.assertRaises(OSError):
                await self.service.run_argv("machine", "/tmp", ["true"])
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.root / "starts").exists())

    async def test_ambiguous_start_is_unknown_and_never_restarted(self) -> None:
        (self.root / "disconnect").touch()
        job = await self.service.run_argv("machine", "/tmp", ["true"])
        self.assertEqual(job.state, "unknown")
        replacement = self.new_service()
        self.addAsyncCleanup(replacement.close)
        await replacement.start()
        await self.settle(replacement)
        self.assertEqual((self.root / "starts").read_text(), "start\n")

    async def test_recovery_of_starting_and_running_records_never_stages_or_starts(self) -> None:
        for number, state in (("1", "starting"), ("2", "running")):
            job = self.store.create(number * 32, "machine", False)
            self.store.update(job, state=state)
        await self.service.start()
        await self.settle(self.service)
        self.assertTrue(all(job.state == "unknown" for job in self.store.list()))
        self.assertFalse((self.root / "starts").exists())
        self.assertFalse((self.root / "staged").exists())

    async def test_restart_collects_existing_completion_without_reexecution(self) -> None:
        job = self.store.create("3" * 32, "machine", False)
        (self.root / "done").touch()
        await self.service.start()
        await self.settle(self.service)
        self.assertEqual(self.store.load(job.job_id).state, "complete")
        self.assertFalse((self.root / "starts").exists())

    async def test_shutdown_preserves_running_job_for_monitor_recovery(self) -> None:
        (self.root / "running").touch()
        job = await self.service.run_argv("machine", "/tmp", ["true"], timeout=0.05)
        async with asyncio.timeout(10):
            while self.store.load(job.job_id).state != "running":
                await asyncio.sleep(0.02)
        await self.service.close()
        self.assertEqual(self.store.load(job.job_id).state, "running")
        (self.root / "done").touch()
        replacement = self.new_service()
        self.addAsyncCleanup(replacement.close)
        await replacement.start()
        await self.settle(replacement)
        self.assertEqual(self.store.load(job.job_id).state, "complete")
        self.assertEqual((self.root / "starts").read_text(), "start\n")

    async def test_collection_failure_retains_remote_results(self) -> None:
        (self.root / "done").touch()
        (self.root / "fail-collection").touch()
        job = await self.service.run_argv("machine", "/tmp", ["true"])
        self.assertEqual((job.state, job.error_code), ("failed", "result_collection_failed"))
        self.assertFalse((self.root / "cleaned").exists())

    async def test_local_result_publication_failure_retains_remote_results(self) -> None:
        (self.root / "done").touch()
        with patch("tmuxgate.executor._atomic_output", side_effect=OSError("synthetic durable write failure")):
            job = await self.service.run_argv("machine", "/tmp", ["true"])
        self.assertEqual((job.state, job.error_code), ("failed", "result_collection_failed"))
        self.assertFalse((self.root / "cleaned").exists())

    async def test_sudo_password_uses_native_stdin_and_never_command_or_environment(self) -> None:
        self.executor.credentials.save("machine", b"synthetic-password")
        (self.root / "done").touch()
        job = await self.service.run_argv("machine", "/tmp", ["true"], sudo=True)
        self.assertEqual(job.state, "complete")
        self.assertNotIn("synthetic-password", json.dumps(self.calls()))
        self.assertNotIn("synthetic-password", read_private(self.store.jobs_dir / f"{job.job_id}.json").decode())

    async def test_cancellation_during_native_spawn_reaps_the_child(self) -> None:
        spawned = asyncio.Event()
        release = asyncio.Event()
        create = asyncio.create_subprocess_exec

        async def delayed(*arguments, **kwargs):
            process = await create(*arguments, **kwargs)
            spawned.set()
            await release.wait()
            return process

        with patch("asyncio.create_subprocess_exec", delayed):
            task = asyncio.create_task(ssh.run("configured-alias", ["sleep"]))
            await asyncio.wait_for(spawned.wait(), 10)
            task.cancel()
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 5)
        self.assertIsNotNone(self.processes[-1].returncode)

    async def test_cancellation_drains_flooded_native_pipes(self) -> None:
        task = asyncio.create_task(ssh.run("configured-alias", ["flood"]))
        async with asyncio.timeout(10):
            while not (self.root / "sleeping").exists():
                await asyncio.sleep(0.02)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        self.assertIsNotNone(self.processes[-1].returncode)

    async def test_cancellation_reaps_native_ssh_process(self) -> None:
        task = asyncio.create_task(ssh.run("configured-alias", ["sleep"]))
        async with asyncio.timeout(10):
            while not (self.root / "sleeping").exists():
                await asyncio.sleep(0.02)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        self.assertIsNotNone(self.processes[-1].returncode)
