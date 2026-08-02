from pathlib import Path
from types import SimpleNamespace
import os
import subprocess
import tempfile
import unittest
from unittest import mock

from tmuxgate.real_ssh import BatchResult
from tmuxgate.ssh_key import (
    AutoSshKeyManager,
    _REMOTE_ENROLL_SCRIPT,
    _REMOTE_KEY_STATUS_SCRIPT,
)
from tmuxgate.transport import KeyEnrollmentOutcome, TransportError
from test_connection_plan import build_plan


class FakeChannels:
    def __init__(self, returncodes=(3, 0)):
        self.calls = []
        self.returncodes = list(returncodes)

    def batch(self, argv, *, input_bytes=b"", timeout_seconds=30):
        self.calls.append((argv, input_bytes, timeout_seconds))
        return BatchResult(b"", b"", self.returncodes.pop(0))


class AutoSshKeyManagerTests(unittest.TestCase):
    public_key = b"ssh-ed25519 AAAAC3NzaSynthetic tmuxgate-test\n"

    def test_first_connection_creates_and_enrolls_private_machine_key(self):
        resolved = build_plan().endpoints[0].resolved
        channels = FakeChannels()
        with tempfile.TemporaryDirectory() as directory:
            ssh_dir = Path(directory) / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            private = ssh_dir / "tmuxgate" / "app-server.ed25519"

            def keygen(argv, **kwargs):
                generated = Path(argv[argv.index("-f") + 1])
                generated.write_bytes(b"synthetic-private-key\n")
                generated.chmod(0o600)
                public = Path(os.fspath(generated) + ".pub")
                public.write_bytes(self.public_key)
                public.chmod(0o644)
                return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

            manager = AutoSshKeyManager(channels=channels, runner=keygen)
            with mock.patch(
                "tmuxgate.ssh_key.default_tmuxgate_identity_file",
                return_value=private,
            ):
                manager.prepare_local_key(resolved)
                boundary_calls = []
                outcome = manager.enroll_remote_key(
                    resolved,
                    Path("/tmp/master.sock"),
                    before_remote_mutation=lambda: boundary_calls.append("armed"),
                )

            self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                Path(os.fspath(private) + ".pub").stat().st_mode & 0o777,
                0o600,
            )
            self.assertEqual(outcome, KeyEnrollmentOutcome.ENROLLED_AND_VERIFIED)
            self.assertEqual(boundary_calls, ["armed"])
            self.assertEqual(len(channels.calls), 2)
            argv, public_input, timeout = channels.calls[-1]
            self.assertIn("BatchMode=yes", argv)
            self.assertTrue(public_input.startswith(b"ssh-ed25519 "))
            self.assertEqual(timeout, 30)

    def test_preinstalled_key_is_read_only_and_never_arms_mutation(self):
        resolved = build_plan().endpoints[0].resolved
        channels = FakeChannels((0,))
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "key"
            private.write_bytes(b"private\n")
            private.chmod(0o600)
            public = Path(os.fspath(private) + ".pub")
            public.write_bytes(self.public_key)
            public.chmod(0o600)
            manager = AutoSshKeyManager(channels=channels)
            with mock.patch(
                "tmuxgate.ssh_key.default_tmuxgate_identity_file",
                return_value=private,
            ):
                outcome = manager.enroll_remote_key(
                    resolved,
                    Path("/tmp/master.sock"),
                    before_remote_mutation=lambda: self.fail(
                        "read-only verification must not arm mutation"
                    ),
                )
        self.assertEqual(outcome, KeyEnrollmentOutcome.ALREADY_PRESENT)
        self.assertEqual(len(channels.calls), 1)

    def test_failed_append_or_verification_occurs_after_boundary(self):
        resolved = build_plan().endpoints[0].resolved
        channels = FakeChannels((3, 125))
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "key"
            private.write_bytes(b"private\n")
            private.chmod(0o600)
            public = Path(os.fspath(private) + ".pub")
            public.write_bytes(self.public_key)
            public.chmod(0o600)
            manager = AutoSshKeyManager(channels=channels)
            boundary_calls = []
            with mock.patch(
                "tmuxgate.ssh_key.default_tmuxgate_identity_file",
                return_value=private,
            ):
                with self.assertRaisesRegex(TransportError, "could not enroll"):
                    manager.enroll_remote_key(
                        resolved,
                        Path("/tmp/master.sock"),
                        before_remote_mutation=lambda: boundary_calls.append("armed"),
                    )
        self.assertEqual(boundary_calls, ["armed"])

    def run_enroll_script(self, home: Path, public_key: bytes) -> subprocess.CompletedProcess:
        return subprocess.run(
            ("/bin/sh", "-c", _REMOTE_ENROLL_SCRIPT),
            input=public_key,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={
                "HOME": os.fspath(home),
                "PATH": "/usr/bin:/bin",
            },
        )

    def test_symlinked_authorized_keys_accepts_exact_preinstalled_key_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            managed = home / "managed-authorized-keys"
            managed.write_bytes(self.public_key)
            managed.chmod(0o600)
            (ssh_dir / "authorized_keys").symlink_to(managed)
            before = managed.read_bytes()

            result = self.run_enroll_script(home, self.public_key)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(managed.read_bytes(), before)

    def test_missing_key_is_appended_verified_and_then_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)

            first = self.run_enroll_script(home, self.public_key)
            self.assertEqual(first.returncode, 0, first.stderr)
            authorized = home / ".ssh" / "authorized_keys"
            self.assertEqual(authorized.read_bytes(), self.public_key)
            self.assertEqual(authorized.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                self.run_status_script(home, self.public_key).returncode,
                0,
            )

            second = self.run_enroll_script(home, self.public_key)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(authorized.read_bytes(), self.public_key)

    def test_symlinked_authorized_keys_rejects_missing_key_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            managed = home / "managed-authorized-keys"
            managed.write_bytes(b"ssh-ed25519 AAAAC3NzaOther existing\n")
            managed.chmod(0o600)
            (ssh_dir / "authorized_keys").symlink_to(managed)
            before = managed.read_bytes()

            result = self.run_enroll_script(home, self.public_key)

            self.assertEqual(result.returncode, 125)
            self.assertEqual(managed.read_bytes(), before)

    def test_read_only_status_distinguishes_present_missing_and_unsafe(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            missing = self.run_status_script(home, self.public_key)
            self.assertEqual(missing.returncode, 3)

            ssh_dir = home / ".ssh"
            ssh_dir.mkdir(mode=0o700)
            authorized = ssh_dir / "authorized_keys"
            authorized.write_bytes(self.public_key)
            authorized.chmod(0o600)
            present = self.run_status_script(home, self.public_key)
            self.assertEqual(present.returncode, 0)

            authorized.chmod(0o644)
            unsafe = self.run_status_script(home, self.public_key)
            self.assertEqual(unsafe.returncode, 125)

    def run_status_script(
        self, home: Path, public_key: bytes
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            ("/bin/sh", "-c", _REMOTE_KEY_STATUS_SCRIPT),
            input=public_key,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"HOME": os.fspath(home), "PATH": "/usr/bin:/bin"},
        )


if __name__ == "__main__":
    unittest.main()
