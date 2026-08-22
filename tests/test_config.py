from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tmuxgate.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def test_minimal_mapping_and_port_load(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(
                '[machines]\nproxmox = "proxmox"\nhome = "operator@home"\n\n[mcp]\nport = 9000\n',
                encoding="utf-8",
            )
            config = load_config(path)
        self.assertEqual(
            config.machines, {"proxmox": "proxmox", "home": "operator@home"}
        )
        self.assertEqual(config.mcp_port, 9000)

    def test_old_architecture_sections_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(
                '[machines]\nhome = "home"\n[broker]\nmax_active_remote_commands = 3\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ConfigError, "unsupported"):
                load_config(path)

    def test_destination_cannot_be_an_ssh_option(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text('[machines]\nbad = "-oProxyCommand=evil"\n')
            with self.assertRaisesRegex(ConfigError, "unsafe"):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
