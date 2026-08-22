from __future__ import annotations

from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fake_remote import FakeRemote
from tmuxgate.cli import build_parser, main
from tmuxgate.credentials import CredentialStore


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "config.toml"
        self.config.write_text('[machines]\nmachine = "machine"\n', encoding="utf-8")
        self.state = self.root / "state"
        self.remote = FakeRemote(self.root / "fake")

    def tearDown(self) -> None:
        self.remote.stop()
        self.temporary.cleanup()

    def arguments(self, *values: str) -> list[str]:
        return [
            "--config",
            str(self.config),
            "--state-dir",
            str(self.state),
            *values,
        ]

    def test_surface_contains_only_serve_sudo_and_jobs(self) -> None:
        help_text = build_parser().format_help()
        self.assertIn("{serve,sudo,jobs}", help_text)
        for obsolete in ("broker", "dashboard", "install", "approve", "attach"):
            self.assertNotIn(obsolete, help_text)

    def test_sudo_set_test_and_clear(self) -> None:
        environment = self.remote.environment(sudo_mode="password")
        with patch.dict(os.environ, environment, clear=False), patch(
            "getpass.getpass", return_value="correct horse"
        ), redirect_stdout(io.StringIO()):
            self.assertEqual(main(self.arguments("sudo", "set", "machine")), 0)
            store = CredentialStore(self.state)
            self.assertEqual(store.read("machine"), bytearray(b"correct horse"))
            self.assertEqual(main(self.arguments("sudo", "test", "machine")), 0)
            self.assertEqual(main(self.arguments("sudo", "clear", "machine")), 0)
            self.assertIsNone(store.read("machine"))

    def test_jobs_lists_empty_durable_state(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(self.arguments("jobs")), 0)
        self.assertEqual(output.getvalue().strip(), '{\n  "jobs": []\n}')


if __name__ == "__main__":
    unittest.main()
