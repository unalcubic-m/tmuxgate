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

    def test_unsafe_derived_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = JobStore(Path(directory) / "state")
            job = store.create("4" * 32, "machine", False)
            path = store.jobs_dir / f"{job.job_id}.json"
            raw = asdict(job)
            raw["stdout_path"] = "/tmp/injected-output"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(JobStoreError, "unsafe derived paths"):
                store.load(job.job_id)

    def test_extra_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = JobStore(Path(directory) / "state")
            job = store.create("2" * 32, "machine", False)
            path = store.jobs_dir / f"{job.job_id}.json"
            raw = json.loads(path.read_text())
            raw["unexpected"] = True
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(JobStoreError, "fields are invalid"):
                store.load(job.job_id)


if __name__ == "__main__":
    unittest.main()
