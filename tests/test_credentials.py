"""Reusable sudo credential storage tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from tmuxgate.credentials import CredentialError, SudoCredentialStore


class SudoCredentialStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.state_dir = Path(self.temporary.name) / "state"
        self.state_dir.mkdir(mode=0o700)

    def test_passwords_round_trip_per_machine_in_owner_only_file(self):
        store = SudoCredentialStore(self.state_dir)
        self.assertIsNone(store.password_for("app-server"))

        store.set_password("app-server", "correct horse battery staple")
        store.set_credential(
            "db-server",
            "different-secret",
            b"[sudo: authenticate] Password:",
        )

        reloaded = SudoCredentialStore(self.state_dir)
        self.assertEqual(
            reloaded.password_for("app-server"), b"correct horse battery staple"
        )
        self.assertEqual(reloaded.password_for("db-server"), b"different-secret")
        self.assertIsNone(reloaded.prompt_for("app-server"))
        self.assertEqual(
            reloaded.prompt_for("db-server"),
            b"[sudo: authenticate] Password:",
        )
        reloaded.set_password("db-server", "replacement-secret")
        self.assertEqual(
            reloaded.prompt_for("db-server"),
            b"[sudo: authenticate] Password:",
        )
        self.assertEqual(
            reloaded.set_prompt("db-server", b"Custom sudo Password:"),
            b"replacement-secret",
        )
        self.assertEqual(
            reloaded.prompt_for("db-server"),
            b"Custom sudo Password:",
        )
        self.assertIsNone(reloaded.set_prompt("missing-server", b"sudo Password:"))
        self.assertEqual(stat.S_IMODE(reloaded.path.stat().st_mode), 0o600)
        self.assertTrue(reloaded.remove_password("app-server"))
        self.assertFalse(reloaded.remove_password("app-server"))
        self.assertIsNone(reloaded.password_for("app-server"))
        self.assertEqual(reloaded.password_for("db-server"), b"replacement-secret")

    def test_version_one_passwords_load_and_migrate_on_next_write(self):
        path = self.state_dir / "sudo-credentials.json"
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "passwords": {"app-server": "legacy-secret"},
                }
            ),
            encoding="utf-8",
        )
        path.chmod(0o600)

        store = SudoCredentialStore(self.state_dir)
        self.assertEqual(store.password_for("app-server"), b"legacy-secret")
        self.assertIsNone(store.prompt_for("app-server"))
        store.set_credential("db-server", "new-secret", b"Password:")

        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["version"], 2)
        reloaded = SudoCredentialStore(self.state_dir)
        self.assertEqual(reloaded.password_for("app-server"), b"legacy-secret")
        self.assertEqual(reloaded.prompt_for("db-server"), b"Password:")

    def test_store_rejects_unsafe_parent_file_and_password(self):
        self.state_dir.chmod(0o755)
        with self.assertRaisesRegex(CredentialError, "0700"):
            SudoCredentialStore(self.state_dir)
        self.state_dir.chmod(0o700)
        store = SudoCredentialStore(self.state_dir)
        for password in ("", "line one\nline two", "nul\x00byte"):
            with self.subTest(password=password):
                with self.assertRaises(CredentialError):
                    store.set_password("app-server", password)
        for prompt in (b"", b"line one\nPassword:", b"nul\x00Password:"):
            with self.subTest(prompt=prompt):
                with self.assertRaises(CredentialError):
                    store.set_credential("app-server", "secret", prompt)

        target = self.state_dir / "outside"
        target.write_text("not credentials", encoding="utf-8")
        store.path.symlink_to(target)
        with self.assertRaises(CredentialError):
            SudoCredentialStore(self.state_dir)
        self.assertEqual(stat.S_IFMT(os.lstat(store.path).st_mode), stat.S_IFLNK)


if __name__ == "__main__":
    unittest.main()
