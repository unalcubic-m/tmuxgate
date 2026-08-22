from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import stat
import tempfile
import unittest

from tmuxgate.jobs import JOB_FIELDS, JobStore, JobStoreError


class JobStoreTests(unittest.TestCase):
    def test_record_has_only_required_fields_and_atomic_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = JobStore(Path(directory) / "state")
            job = store.create("1" * 32, "machine", False)
            path = store.jobs_dir / f"{job.job_id}.json"
            raw = json.loads(path.read_text())
            self.assertEqual(set(raw), JOB_FIELDS)
            self.assertEqual(raw, asdict(job))
            self.assertEqual(stat.S_IMODE(store.jobs_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            complete = store.update(job, state="complete", exit_code=19)
            self.assertEqual(store.load(job.job_id), complete)
            self.assertNotEqual(job.updated_at, complete.updated_at)

    def test_create_is_exclusive_and_does_not_overwrite_a_collision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = JobStore(Path(directory) / "state")
            first = store.create("3" * 32, "first", False)
            with self.assertRaisesRegex(JobStoreError, "already exists"):
                store.create(first.job_id, "second", True)
            self.assertEqual(store.load(first.job_id), first)

    def test_current_format_record_remains_readable_and_paths_are_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = JobStore(Path(directory) / "state")
            job_id = "4" * 32
            result_dir = store.results_dir / job_id
            raw = {
                "job_id": job_id,
                "machine": "machine",
                "sudo": False,
                "state": "running",
                "created_at": "2026-08-22T00:00:00.000+00:00",
                "updated_at": "2026-08-22T00:00:01.000+00:00",
                "remote_directory": f"~/.cache/tmuxgate/jobs/{job_id}",
                "remote_session": f"tmuxgate-{job_id}",
                "exit_code": None,
                "error_code": None,
                "error_detail": None,
                "stdout_path": str(result_dir / "stdout"),
                "stderr_path": str(result_dir / "stderr"),
            }
            path = store.jobs_dir / f"{job_id}.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            self.assertEqual(asdict(store.load(job_id)), raw)
            raw["stdout_path"] = "/tmp/injected-output"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(JobStoreError, "unsafe derived paths"):
                store.load(job_id)

    def test_legacy_or_extra_fields_are_not_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = JobStore(Path(directory) / "state")
            job = store.create("2" * 32, "machine", False)
            path = store.jobs_dir / f"{job.job_id}.json"
            raw = json.loads(path.read_text())
            raw["legacy_phase"] = "approved"
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(JobStoreError, "minimal format"):
                store.load(job.job_id)


if __name__ == "__main__":
    unittest.main()
