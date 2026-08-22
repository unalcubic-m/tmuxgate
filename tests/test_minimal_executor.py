from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from fake_remote import FakeRemote
from tmuxgate.config import Config, UnknownMachineError
from tmuxgate.credentials import CredentialStore
from tmuxgate.executor import RemoteExecutor
from tmuxgate.jobs import Job, JobStore
from tmuxgate.service import ExecutionService, job_view


class MinimalExecutorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.remote = FakeRemote(self.root)
        self.environment = patch.dict(os.environ, self.remote.environment(), clear=False)
        self.environment.start()
        self.state_dir = self.root / "state"
        self.store = JobStore(self.state_dir)
        self.credentials = CredentialStore(self.state_dir)
        self.config = Config({"machine": "machine", "hostkey": "hostkey-fail"})
        self.executor = RemoteExecutor(
            self.store, self.credentials, poll_interval=0.02
        )
        self.service = ExecutionService(self.config, self.store, self.executor)
        await self.service.start()

    async def asyncTearDown(self) -> None:
        await self.service.close()
        self.remote.stop()
        self.environment.stop()
        self.temporary.cleanup()

    async def wait_for_state(
        self,
        job_id: str,
        states: set[str],
        timeout: float = 5,
        service: ExecutionService | None = None,
    ) -> Job:
        selected = self.service if service is None else service
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            job = selected.get_job(job_id)
            if job.state in states:
                return job
            if asyncio.get_running_loop().time() >= deadline:
                self.fail(f"job {job_id} remained {job.state}")
            await asyncio.sleep(0.02)

    async def test_argv_preserves_arguments_and_separates_output(self) -> None:
        job = await self.service.run_argv(
            "machine",
            "/tmp",
            [
                "/bin/sh",
                "-c",
                'printf "%s" "$1"; printf "%s" "$2" >&2; exit 7',
                "argument zero",
                "hello world",
                "error text",
            ],
            {"EXAMPLE": "value with spaces"},
        )
        self.assertEqual(job.state, "complete")
        self.assertEqual(job.exit_code, 7)
        result = job_view(job)
        self.assertEqual(result["stdout"], "hello world")
        self.assertEqual(result["stderr"], "error text")
        self.assertEqual(result["stdout_encoding"], "utf-8")
        self.assertFalse(self.remote.remote_job(job.job_id).exists())
        starts = [
            item for item in self.remote.commands() if "tmux new-session" in item["command"]
        ]
        self.assertEqual(len(starts), 1)

    async def test_utf8_script_executes_with_closed_stdin(self) -> None:
        job = await self.service.run_script(
            "machine",
            "/tmp",
            "printf 'İstanbul ✓\\n'\nif read value; then exit 99; fi\nprintf 'closed\\n'",
        )
        self.assertEqual(job.state, "complete")
        self.assertEqual(job.exit_code, 0)
        self.assertEqual(Path(job.stdout_path).read_text(encoding="utf-8"), "İstanbul ✓\nclosed\n")

    async def test_non_utf8_output_is_returned_as_base64(self) -> None:
        job = await self.service.run_script("machine", "/tmp", "printf '\\377'")
        result = job_view(job)
        self.assertEqual(result["stdout"], "/w==")
        self.assertEqual(result["stdout_encoding"], "base64")

    async def test_invalid_request_does_not_create_a_durable_job(self) -> None:
        with self.assertRaisesRegex(ValueError, "cwd"):
            await self.service.run_argv("machine", "", ["true"])
        with self.assertRaisesRegex(ValueError, "timeout"):
            await self.service.run_argv("machine", "/tmp", ["true"], timeout=0)
        self.assertEqual(self.service.list_jobs(), [])

    async def test_unknown_machine_is_exact_and_returns_aliases(self) -> None:
        with self.assertRaises(UnknownMachineError) as caught:
            await self.service.run_argv("Machine", "/tmp", ["true"])
        self.assertEqual(caught.exception.aliases, ("hostkey", "machine"))
        self.assertEqual(self.service.list_jobs(), [])

    async def test_host_key_verification_failure_is_fatal(self) -> None:
        job = await self.service.run_argv("hostkey", "/tmp", ["true"])
        self.assertEqual(job.state, "failed")
        self.assertEqual(job.error_code, "ssh_failed")
        self.assertIn("Host key verification failed", job.error_detail or "")
        self.assertFalse(
            any("tmux new-session" in item["command"] for item in self.remote.commands())
        )

    async def test_sudo_password_job_succeeds_without_secret_leakage(self) -> None:
        self.environment.stop()
        self.environment = patch.dict(
            os.environ, self.remote.environment(sudo_mode="password"), clear=False
        )
        self.environment.start()
        password = self.remote.password_path.read_bytes()
        self.credentials.save("machine", password)
        os.environ["TMUXGATE_MCP_TOKEN"] = "bearer-secret"
        try:
            with self.assertLogs("tmuxgate", level=logging.INFO) as captured:
                job = await self.service.run_argv(
                    "machine", "/tmp", ["/usr/bin/id", "-u"], sudo=True
                )
        finally:
            os.environ.pop("TMUXGATE_MCP_TOKEN", None)
        self.assertEqual(job.state, "complete")
        self.assertEqual(job.exit_code, 0)
        command_log = json.dumps(self.remote.commands())
        job_state = (self.state_dir / "jobs" / f"{job.job_id}.json").read_bytes()
        logs = "\n".join(captured.output).encode()
        self.assertNotIn(password, command_log.encode())
        self.assertNotIn(password, job_state)
        self.assertNotIn(password, logs)
        self.assertNotIn(b"bearer-secret", command_log.encode())
        self.assertFalse(any(item["has_bearer_token"] for item in self.remote.commands()))
        self.assertFalse(self.remote.remote_job(job.job_id).exists())

    async def test_passwordless_sudo_job_succeeds(self) -> None:
        job = await self.service.run_argv(
            "machine", "/tmp", ["/usr/bin/id", "-u"], sudo=True
        )
        self.assertEqual(job.state, "complete")
        self.assertEqual(job.exit_code, 0)

    async def test_sudo_errors_are_structured(self) -> None:
        self.environment.stop()
        self.environment = patch.dict(
            os.environ, self.remote.environment(sudo_mode="password"), clear=False
        )
        self.environment.start()
        missing = await self.service.run_argv(
            "machine", "/tmp", ["true"], sudo=True
        )
        self.assertEqual(missing.error_code, "sudo_password_missing")
        self.assertIn(missing.job_id, missing.error_detail or "")
        self.credentials.save("machine", b"wrong password")
        rejected = await self.service.run_argv(
            "machine", "/tmp", ["true"], sudo=True
        )
        self.assertEqual(rejected.error_code, "sudo_auth_failed")
        self.assertIn(rejected.job_id, rejected.error_detail or "")

        self.environment.stop()
        self.environment = patch.dict(
            os.environ, self.remote.environment(sudo_mode="requiretty"), clear=False
        )
        self.environment.start()
        requiretty = await self.service.run_argv(
            "machine", "/tmp", ["true"], sudo=True
        )
        self.assertEqual(requiretty.error_code, "sudo_unavailable")
        self.assertIn("configure noninteractive sudo", requiretty.error_detail or "")

        self.environment.stop()
        self.environment = patch.dict(
            os.environ, self.remote.environment(sudo_mode="unavailable"), clear=False
        )
        self.environment.start()
        unavailable = await self.service.run_argv(
            "machine", "/tmp", ["true"], sudo=True
        )
        self.assertEqual(unavailable.error_code, "sudo_unavailable")

        self.environment.stop()
        values = self.remote.environment(sudo_mode="passwordless")
        values["TMUXGATE_TEST_SUDO_START_FAIL"] = "1"
        self.environment = patch.dict(os.environ, values, clear=False)
        self.environment.start()
        launch = await self.service.run_argv(
            "machine", "/tmp", ["true"], sudo=True
        )
        self.assertEqual(launch.error_code, "sudo_job_start_failed")
        run_script = self.remote.remote_job(launch.job_id) / "run.sh"
        self.assertEqual(stat.S_IMODE(run_script.stat().st_mode), 0o700)
        self.assertFalse(
            any(
                "tar -xf" in item["command"]
                for item in self.remote.commands()
                if "tmuxgate-stage" in item["command"]
            )
        )
        for failed in (missing, rejected, requiretty, unavailable, launch):
            prefix = f"machine={failed.machine} job_id={failed.job_id}:"
            self.assertEqual((failed.error_detail or "").count(prefix), 1)

    async def test_client_cancellation_does_not_stop_remote_job(self) -> None:
        call = asyncio.create_task(
            self.service.run_script(
                "machine", "/tmp", "sleep 0.25\nprintf 'survived\\n'"
            )
        )
        job_id = ""
        deadline = asyncio.get_running_loop().time() + 3
        while not job_id:
            records = self.service.list_jobs()
            if records and records[0].state == "running":
                job_id = records[0].job_id
                break
            if asyncio.get_running_loop().time() > deadline:
                self.fail("job did not start")
            await asyncio.sleep(0.01)
        call.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await call
        completed = await self.wait_for_state(job_id, {"complete"})
        self.assertEqual(Path(completed.stdout_path).read_text(), "survived\n")

    async def test_restart_collects_job_without_rerunning_it(self) -> None:
        client = asyncio.create_task(
            self.service.run_script(
                "machine",
                "/tmp",
                "sleep 0.5\nprintf 'after restart\\n'",
            )
        )
        deadline = asyncio.get_running_loop().time() + 3
        while True:
            records = self.service.list_jobs()
            if records and records[0].state == "running":
                running = records[0]
                break
            if asyncio.get_running_loop().time() >= deadline:
                self.fail("job did not reach running before restart")
            await asyncio.sleep(0.01)
        await self.service.close()
        with self.assertRaises(asyncio.CancelledError):
            await client
        await asyncio.sleep(0.55)
        starts_before = sum(
            "tmux new-session" in item["command"] for item in self.remote.commands()
        )
        executor = RemoteExecutor(
            self.store, self.credentials, poll_interval=0.02
        )
        restarted = ExecutionService(self.config, self.store, executor)
        self.service = restarted
        await restarted.start()
        completed = await self.wait_for_state(
            running.job_id, {"complete"}, service=restarted
        )
        self.assertEqual(Path(completed.stdout_path).read_text(), "after restart\n")
        starts_after = sum(
            "tmux new-session" in item["command"] for item in self.remote.commands()
        )
        self.assertEqual(starts_after, starts_before)

    async def test_restart_resumes_monitoring_a_running_job(self) -> None:
        client = asyncio.create_task(
            self.service.run_script(
                "machine", "/tmp", "sleep 0.5\nprintf 'resumed\\n'"
            )
        )
        deadline = asyncio.get_running_loop().time() + 3
        while True:
            records = self.service.list_jobs()
            if records and records[0].state == "running":
                running = records[0]
                break
            if asyncio.get_running_loop().time() >= deadline:
                self.fail("job did not reach running before restart")
            await asyncio.sleep(0.01)
        await self.service.close()
        with self.assertRaises(asyncio.CancelledError):
            await client
        starts_before = sum(
            "tmux new-session" in item["command"] for item in self.remote.commands()
        )
        restarted = ExecutionService(
            self.config,
            self.store,
            RemoteExecutor(self.store, self.credentials, poll_interval=0.02),
        )
        self.service = restarted
        await restarted.start()
        completed = await self.wait_for_state(
            running.job_id, {"complete"}, service=restarted
        )
        self.assertEqual(Path(completed.stdout_path).read_text(), "resumed\n")
        self.assertEqual(
            sum(
                "tmux new-session" in item["command"]
                for item in self.remote.commands()
            ),
            starts_before,
        )

    async def test_ambiguous_starting_job_becomes_unknown_and_is_not_run(self) -> None:
        job = self.store.create("a" * 32, "machine", False)
        executor = RemoteExecutor(
            self.store, self.credentials, poll_interval=0.02
        )
        other = ExecutionService(self.config, self.store, executor)
        await other.start()
        try:
            unknown = await self.wait_for_state(
                job.job_id, {"unknown"}, service=other
            )
            self.assertEqual(unknown.error_code, "remote_job_unknown")
            self.assertEqual(
                (unknown.error_detail or "").count(
                    f"machine={job.machine} job_id={job.job_id}:"
                ),
                1,
            )
            self.assertFalse(
                any("tmux new-session" in item["command"] for item in self.remote.commands())
            )
        finally:
            await other.close()

    async def test_disconnect_during_start_is_unknown_and_never_rerun(self) -> None:
        os.environ["TMUXGATE_TEST_DROP_AFTER_START"] = "1"
        try:
            job = await self.service.run_script(
                "machine", "/tmp", "sleep 0.1\nprintf possibly-started"
            )
        finally:
            os.environ.pop("TMUXGATE_TEST_DROP_AFTER_START", None)
        self.assertEqual(job.state, "unknown")
        self.assertEqual(job.error_code, "ssh_failed")
        await asyncio.sleep(0.15)
        self.assertTrue((self.remote.remote_job(job.job_id) / "done").exists())
        starts = sum(
            "tmux new-session" in item["command"] for item in self.remote.commands()
        )
        restarted = ExecutionService(
            self.config,
            self.store,
            RemoteExecutor(self.store, self.credentials, poll_interval=0.02),
        )
        await restarted.start()
        try:
            self.assertEqual(restarted.get_job(job.job_id).state, "unknown")
            self.assertEqual(
                sum(
                    "tmux new-session" in item["command"]
                    for item in self.remote.commands()
                ),
                starts,
            )
        finally:
            await restarted.close()

    async def test_collection_failure_never_marks_complete_or_cleans_remote(self) -> None:
        os.environ["TMUXGATE_TEST_FAIL_COLLECTION"] = "1"
        try:
            job = await self.service.run_argv("machine", "/tmp", ["true"])
        finally:
            os.environ.pop("TMUXGATE_TEST_FAIL_COLLECTION", None)
        self.assertEqual(job.state, "failed")
        self.assertEqual(job.error_code, "result_collection_failed")
        self.assertTrue(self.remote.remote_job(job.job_id).exists())
        self.assertFalse(
            any("tmuxgate-cleanup" in item["command"] for item in self.remote.commands())
        )

    async def test_only_three_jobs_start_concurrently(self) -> None:
        script = 'while [ ! -f "$HOME/release" ]; do sleep 0.02; done\nprintf done'
        calls = [
            asyncio.create_task(
                self.service.run_script(
                    "machine", "/tmp", script, timeout=0.15
                )
            )
            for _ in range(4)
        ]
        initial = await asyncio.gather(*calls)
        deadline = asyncio.get_running_loop().time() + 3
        while True:
            starts = sum(
                "tmux new-session" in item["command"]
                for item in self.remote.commands()
            )
            if starts == 3:
                break
            if starts > 3 or asyncio.get_running_loop().time() >= deadline:
                self.fail(f"expected exactly three starts, observed {starts}")
            await asyncio.sleep(0.02)
        self.assertEqual(starts, 3)
        deadline = asyncio.get_running_loop().time() + 3
        while True:
            current = [self.service.get_job(job.job_id) for job in initial]
            if sum(job.state == "running" for job in current) == 3:
                break
            if asyncio.get_running_loop().time() >= deadline:
                self.fail("three jobs did not settle in running state")
            await asyncio.sleep(0.02)
        self.assertEqual(sum(job.state == "starting" for job in current), 1)
        self.assertEqual(
            sum(
                "tmux new-session" in item["command"]
                for item in self.remote.commands()
            ),
            3,
        )
        (self.remote.remote_home / "release").touch()
        for job in initial:
            await self.wait_for_state(job.job_id, {"complete"})


if __name__ == "__main__":
    unittest.main()
