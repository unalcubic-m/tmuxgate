from __future__ import annotations

from pathlib import Path
import stat
import tempfile
import unittest

from tmuxgate.credentials import CredentialStore


class CredentialStoreTests(unittest.TestCase):
    def test_one_owner_only_file_per_machine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = CredentialStore(Path(directory) / "state")
            store.save("machine/with/slashes", "secret value")
            path = store.path_for("machine/with/slashes")
            self.assertEqual(store.read("machine/with/slashes"), bytearray(b"secret value"))
            self.assertEqual(stat.S_IMODE(store.directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(len(list(store.directory.iterdir())), 1)
            self.assertTrue(store.clear("machine/with/slashes"))
            self.assertIsNone(store.read("machine/with/slashes"))


if __name__ == "__main__":
    unittest.main()
