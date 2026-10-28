"""Real Windows ACL and filesystem failure tests, with synthetic data only."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
from typing import TYPE_CHECKING
import unittest
from unittest.mock import patch

from tmuxgate.credentials import CredentialError, CredentialStore
from tmuxgate.jobs import JobStore, JobStoreError
from tmuxgate.mcp import load_bearer_token
from tmuxgate.service import job_view
from tmuxgate.storage import atomic_write, ensure_directory, read_private

if TYPE_CHECKING or os.name == "nt":
    import pywintypes
    import win32con
    import win32file
    import win32security
    from tmuxgate import windows_storage as windows


@unittest.skipUnless(os.name == "nt", "native Windows filesystem security")
class WindowsStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.store = JobStore(self.root / "private state")

    def grant_everyone(self, path: Path) -> None:
        descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION)
        dacl = descriptor.GetSecurityDescriptorDacl()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32con.GENERIC_READ, win32security.CreateWellKnownSid(win32security.WinWorldSid))
        win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, dacl, None)

    def test_new_records_results_and_secrets_have_real_protected_owner_acl(self) -> None:
        job = self.store.create("1" * 32, "machine", False)
        credentials = CredentialStore(self.store.state_dir)
        credentials.save("machine", b"synthetic-password")
        atomic_write(Path(job.stdout_path), b"\x00\xff\r\n")
        for path in (self.store.state_dir, self.store.jobs_dir, self.store.results_dir,
                     Path(job.stdout_path).parent, credentials.directory,
                     self.store.jobs_dir / f"{job.job_id}.json", credentials.path_for("machine"), Path(job.stdout_path)):
            with self.subTest(path=path):
                descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                    win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
                self.assertEqual(descriptor.GetSecurityDescriptorOwner(), windows._sid())
                self.assertTrue(descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED)
                dacl = descriptor.GetSecurityDescriptorDacl()
                self.assertEqual(dacl.GetAceCount(), 1)
                self.assertEqual(dacl.GetAce(0)[2], windows._sid())
                self.assertEqual(dacl.GetAce(0)[1], win32file.FILE_ALL_ACCESS)

    def test_broad_acl_is_rejected_for_token_password_records_and_results(self) -> None:
        state = self.store.state_dir
        atomic_write(state / "mcp-token", b"synthetic-token\n")
        self.assertEqual(load_bearer_token(state), "synthetic-token")
        self.grant_everyone(state / "mcp-token")
        with self.assertRaisesRegex(ValueError, "owner-only"):
            load_bearer_token(state)
        credentials = CredentialStore(state)
        credentials.save("machine", b"synthetic-password")
        self.grant_everyone(credentials.path_for("machine"))
        with self.assertRaisesRegex(CredentialError, "owner-only"):
            credentials.read("machine")
        with self.assertRaises(CredentialError):
            credentials.save("machine", b"replacement")
        job = self.store.create("2" * 32, "machine", False)
        record = self.store.jobs_dir / f"{job.job_id}.json"
        self.grant_everyone(record)
        with self.assertRaises(JobStoreError):
            self.store.load(job.job_id)
        atomic_write(Path(job.stdout_path), b"sensitive-result")
        atomic_write(Path(job.stderr_path), b"")
        complete = self.store.create("3" * 32, "machine", False)
        atomic_write(Path(complete.stdout_path), b"sensitive-result")
        atomic_write(Path(complete.stderr_path), b"")
        complete = self.store.update(complete, state="complete", exit_code=0)
        self.grant_everyone(Path(complete.stdout_path))
        with self.assertRaises(PermissionError):
            job_view(complete)

    def test_existing_broad_directory_is_rejected_without_repair(self) -> None:
        self.grant_everyone(self.store.jobs_dir)
        with self.assertRaises(PermissionError):
            JobStore(self.store.state_dir)

    def test_unprotected_and_null_dacls_are_rejected(self) -> None:
        path = self.store.state_dir / "secret"
        atomic_write(path, b"synthetic")
        descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION)
        win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.UNPROTECTED_DACL_SECURITY_INFORMATION,
            None, None, descriptor.GetSecurityDescriptorDacl(), None)
        with self.assertRaises(PermissionError):
            read_private(path)
        win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, None, None)
        with self.assertRaises(PermissionError):
            read_private(path)

    def test_hardlinked_file_is_rejected(self) -> None:
        path = self.store.state_dir / "secret"
        atomic_write(path, b"synthetic")
        os.link(path, self.store.state_dir / "second-name")
        with self.assertRaisesRegex(PermissionError, "hard links"):
            read_private(path)

    def test_directory_junction_and_reparse_ancestor_are_rejected(self) -> None:
        target = self.store.state_dir / "target"
        ensure_directory(target)
        junction = self.root / "junction"
        # mklink /J creates an actual reparse point without symlink privileges.
        result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(target)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.addCleanup(junction.rmdir)
        with self.assertRaisesRegex(PermissionError, "reparse"):
            ensure_directory(junction)
        with self.assertRaisesRegex(PermissionError, "reparse"):
            ensure_directory(junction / "child")

    def test_atomic_collision_and_failed_replace_preserve_previous_bytes(self) -> None:
        path = self.store.state_dir / "secret"
        atomic_write(path, b"old", exclusive=True)
        with self.assertRaises(FileExistsError):
            atomic_write(path, b"collision", exclusive=True)
        self.assertEqual(read_private(path), b"old")
        with patch.object(win32file, "MoveFileEx", side_effect=pywintypes.error(5, "MoveFileEx", "synthetic failure")):
            with self.assertRaises(OSError):
                atomic_write(path, b"new")
        self.assertEqual(read_private(path), b"old")
        self.assertFalse(list(path.parent.glob("*.tmp")))
        with patch.object(win32file, "FlushFileBuffers", side_effect=pywintypes.error(5, "FlushFileBuffers", "synthetic failure")):
            with self.assertRaises(OSError):
                atomic_write(path, b"new")
        self.assertEqual(read_private(path), b"old")
        atomic_write(path, b"new\r\n\x00\xff")
        self.assertEqual(read_private(path), b"new\r\n\x00\xff")

    def test_missing_acl_capability_and_network_state_are_rejected(self) -> None:
        with patch.object(windows.win32api, "GetVolumeInformation", return_value=("", 0, 255, 0, "FAT32")):
            with self.assertRaisesRegex(PermissionError, "persistent"):
                ensure_directory(self.root / "no-acls")
        with self.assertRaisesRegex(PermissionError, "local fixed"):
            ensure_directory(Path(r"\\synthetic.invalid\share\state"))

    def test_foreign_owner_is_rejected(self) -> None:
        path = self.store.state_dir / "secret"
        atomic_write(path, b"synthetic")
        # Setting a real foreign owner requires privileges the broker must not
        # need. Substitute TokenUser to exercise the comparison against the real
        # on-disk owner/DACL without elevating the process.
        other = win32security.CreateWellKnownSid(win32security.WinWorldSid)
        with patch.object(windows, "_sid", return_value=other):
            with self.assertRaises(PermissionError):
                read_private(path)
