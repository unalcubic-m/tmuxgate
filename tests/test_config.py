from __future__ import annotations

from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from tmuxgate.config import ConfigError, default_config_path, default_state_dir, load_config


class ConfigTests(unittest.TestCase):
    def test_platform_defaults_and_explicit_environment(self) -> None:
        with patch("pathlib.Path.home", return_value=Path("profile")):
            if os.name == "nt":
                self.assertEqual(default_config_path({"APPDATA": "roaming", "XDG_CONFIG_HOME": "ignored"}), Path("roaming/tmuxgate/config.toml"))
                self.assertEqual(default_state_dir({"LOCALAPPDATA": "local", "XDG_STATE_HOME": "ignored"}), Path("local/tmuxgate"))
                self.assertEqual(default_config_path({}), Path("profile/AppData/Roaming/tmuxgate/config.toml"))
                self.assertEqual(default_state_dir({}), Path("profile/AppData/Local/tmuxgate"))
            else:
                self.assertEqual(default_config_path({"XDG_CONFIG_HOME": "config"}), Path("config/tmuxgate/config.toml"))
                self.assertEqual(default_state_dir({"XDG_STATE_HOME": "state"}), Path("state/tmuxgate"))
                self.assertEqual(default_config_path({}), Path("profile/.config/tmuxgate/config.toml"))
                self.assertEqual(default_state_dir({}), Path("profile/.local/state/tmuxgate"))

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

    def test_unexpected_sections_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(
                '[machines]\nhome = "home"\n[unexpected]\nenabled = true\n',
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
