import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from tmuxgate.spool import (
    MANIFEST_NAME,
    MAX_MANIFEST_BYTES,
    MAX_VERIFIED_RANGE_BYTES,
    SPOOL_STREAM_READ_BYTES,
    STDERR_NAME,
    STDOUT_NAME,
    ResultSpool,
    SpoolConflictError,
    SpoolCorruptionError,
)


REQUEST_ID = "0123456789abcdef0123456789abcdef"


class ResultSpoolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        os.chmod(self.temporary.name, 0o700)
        self.state_dir = Path(self.temporary.name) / "state"
        self.spool = ResultSpool(self.state_dir)
        self.addCleanup(self.spool.close)

    def result_path(self):
        return self.spool.path / REQUEST_ID

    def test_store_and_load_preserve_separate_binary_streams_and_exit_seven(self):
        stdout = b"stdout\x00\xff\n"
        stderr = b"stderr\x00\xfe\n"
        stored = self.spool.store(REQUEST_ID, stdout, stderr, 7)
        loaded = self.spool.load(REQUEST_ID)

        self.assertEqual(loaded, stored)
        self.assertEqual(loaded.stdout, stdout)
        self.assertEqual(loaded.stderr, stderr)
        self.assertEqual(loaded.exit_status, 7)
        self.assertEqual(len(loaded.manifest_payload_sha256), 64)

    def test_directories_and_files_are_owner_only(self):
        self.spool.store(REQUEST_ID, b"out", b"err", 0)
        self.assertEqual(stat.S_IMODE(self.spool.path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.result_path().stat().st_mode), 0o700)
        for name in (STDOUT_NAME, STDERR_NAME, MANIFEST_NAME):
            self.assertEqual(
                stat.S_IMODE((self.result_path() / name).stat().st_mode),
                0o600,
            )

    def test_failure_before_publish_leaves_no_visible_or_partial_result(self):
        original = self.spool._write_file

        def interrupted(directory_fd, name, content):
            if name == STDERR_NAME:
                raise OSError("synthetic interruption")
            return original(directory_fd, name, content)

        with mock.patch.object(self.spool, "_write_file", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "synthetic"):
                self.spool.store(REQUEST_ID, b"out", b"err", 7)

        self.assertFalse(self.result_path().exists())
        self.assertEqual(list(self.spool.path.iterdir()), [])
        with self.assertRaises(FileNotFoundError):
            self.spool.load(REQUEST_ID)

    def test_identical_retry_is_idempotent_but_different_result_conflicts(self):
        first = self.spool.store(REQUEST_ID, b"out", b"err", 7)
        second = self.spool.store(REQUEST_ID, b"out", b"err", 7)
        self.assertEqual(first, second)
        with self.assertRaises(SpoolConflictError):
            self.spool.store(REQUEST_ID, b"different", b"err", 7)
        with self.assertRaises(SpoolConflictError):
            self.spool.store(REQUEST_ID, b"out", b"err", 8)

    def test_stream_corruption_is_detected(self):
        self.spool.store(REQUEST_ID, b"out", b"err", 7)
        (self.result_path() / STDOUT_NAME).write_bytes(b"tampered")
        os.chmod(self.result_path() / STDOUT_NAME, 0o600)
        with self.assertRaisesRegex(SpoolCorruptionError, "do not match"):
            self.spool.load(REQUEST_ID)

    def test_verified_range_hashes_only_selected_stream_with_bounded_reads(self):
        stdout = (b"0123456789abcdef" * (SPOOL_STREAM_READ_BYTES // 8)) + b"tail"
        stderr = b"unselected" * (SPOOL_STREAM_READ_BYTES // 2)
        stored = self.spool.store(REQUEST_ID, stdout, stderr, 7)
        manifest_size = (self.result_path() / MANIFEST_NAME).stat().st_size
        read_requests: list[int] = []
        read_lengths: list[int] = []
        original_read = os.read

        def observe_read(descriptor, amount):
            read_requests.append(amount)
            content = original_read(descriptor, amount)
            read_lengths.append(len(content))
            return content

        offset = SPOOL_STREAM_READ_BYTES - 7
        limit = 100_000
        with mock.patch("tmuxgate.spool.os.read", side_effect=observe_read):
            selected = self.spool.read_verified_range(
                REQUEST_ID,
                "stdout",
                offset=offset,
                limit=limit,
                expected_manifest_payload_sha256=(
                    stored.manifest_payload_sha256
                ),
                expected_exit_status=7,
            )

        self.assertEqual(selected.data, stdout[offset : offset + limit])
        self.assertEqual(selected.total_size, len(stdout))
        self.assertEqual(selected.sha256, hashlib.sha256(stdout).hexdigest())
        self.assertLessEqual(len(selected.data), MAX_VERIFIED_RANGE_BYTES)
        self.assertLessEqual(
            max(read_requests),
            max(MAX_MANIFEST_BYTES + 1, SPOOL_STREAM_READ_BYTES),
        )
        # The manifest and selected stdout are the only file bytes read.  The
        # unselected stderr is opened for exact metadata validation only.
        self.assertEqual(sum(read_lengths), manifest_size + len(stdout))

    def test_verified_range_rejects_same_size_selected_stream_corruption(self):
        stdout = b"selected-stream-bytes"
        stored = self.spool.store(REQUEST_ID, stdout, b"other-stream", 7)
        stream_path = self.result_path() / STDOUT_NAME
        stream_path.write_bytes(b"X" + stdout[1:])
        os.chmod(stream_path, 0o600)

        with self.assertRaisesRegex(SpoolCorruptionError, "does not match"):
            self.spool.read_verified_range(
                REQUEST_ID,
                "stdout",
                offset=0,
                limit=4,
                expected_manifest_payload_sha256=(
                    stored.manifest_payload_sha256
                ),
                expected_exit_status=7,
            )

    def test_verified_range_validates_unselected_stream_metadata_without_reading(self):
        stored = self.spool.store(REQUEST_ID, b"selected", b"other", 7)
        os.chmod(self.result_path() / STDERR_NAME, 0o644)

        with self.assertRaisesRegex(SpoolCorruptionError, "metadata"):
            self.spool.read_verified_range(
                REQUEST_ID,
                "stdout",
                offset=0,
                limit=4,
                expected_manifest_payload_sha256=(
                    stored.manifest_payload_sha256
                ),
                expected_exit_status=7,
            )

    def test_manifest_corruption_and_noncanonical_json_are_detected(self):
        self.spool.store(REQUEST_ID, b"out", b"err", 7)
        manifest = self.result_path() / MANIFEST_NAME
        document = json.loads(manifest.read_bytes())
        document["sha256"] = "0" * 64
        manifest.write_text(json.dumps(document), encoding="ascii")
        os.chmod(manifest, 0o600)
        with self.assertRaisesRegex(SpoolCorruptionError, "checksum"):
            self.spool.load(REQUEST_ID)

    def test_unexpected_entry_or_unsafe_file_mode_fails_closed(self):
        self.spool.store(REQUEST_ID, b"out", b"err", 7)
        extra = self.result_path() / "extra"
        extra.write_bytes(b"x")
        os.chmod(extra, 0o600)
        with self.assertRaisesRegex(SpoolCorruptionError, "entries"):
            self.spool.load(REQUEST_ID)
        extra.unlink()
        os.chmod(self.result_path() / STDERR_NAME, 0o644)
        with self.assertRaisesRegex(SpoolCorruptionError, "metadata"):
            self.spool.load(REQUEST_ID)

    def test_symlinked_result_directory_is_rejected(self):
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir(mode=0o700)
        self.result_path().symlink_to(outside, target_is_directory=True)
        with self.assertRaises(SpoolCorruptionError):
            self.spool.load(REQUEST_ID)

    def test_request_id_and_result_limits_are_validated_before_writes(self):
        for invalid in ("../escape", "-oProxyCommand=x", "g" * 32, REQUEST_ID.upper()):
            with self.subTest(request_id=invalid):
                with self.assertRaises(ValueError):
                    self.spool.store(invalid, b"", b"", 0)
        for invalid_status in (True, -1, 256, "7"):
            with self.subTest(exit_status=invalid_status):
                with self.assertRaises(ValueError):
                    self.spool.store(REQUEST_ID, b"", b"", invalid_status)
        with mock.patch("tmuxgate.spool.MAX_RESULT_STREAM_BYTES", 3):
            with self.assertRaisesRegex(ValueError, "exceeds"):
                self.spool.store(REQUEST_ID, b"four", b"", 0)
        self.assertEqual(list(self.spool.path.iterdir()), [])

    def test_existing_incomplete_directory_is_not_accepted_or_overwritten(self):
        self.result_path().mkdir(mode=0o700)
        (self.result_path() / STDOUT_NAME).write_bytes(b"partial")
        os.chmod(self.result_path() / STDOUT_NAME, 0o600)
        with self.assertRaises(SpoolCorruptionError):
            self.spool.store(REQUEST_ID, b"out", b"err", 7)
        self.assertEqual(
            {path.name for path in self.result_path().iterdir()},
            {STDOUT_NAME},
        )


if __name__ == "__main__":
    unittest.main()
