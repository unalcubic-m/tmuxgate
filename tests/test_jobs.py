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
