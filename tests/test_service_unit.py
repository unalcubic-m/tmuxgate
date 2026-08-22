from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ServiceUnitTests(unittest.TestCase):
    def unit_lines(self) -> list[str]:
        unit = (
            ROOT / "src" / "tmuxgate" / "assets" / "tmuxgate.service"
        ).read_text(encoding="utf-8")
        return unit.splitlines()

    def test_server_does_not_inherit_client_bearer_variables(self) -> None:
        self.assertIn(
            "UnsetEnvironment=TMUXGATE_MCP_TOKEN TMUXGATE_BEARER_TOKEN",
            self.unit_lines(),
        )

    def test_graceful_restart_signals_server_before_ssh_monitors(self) -> None:
        self.assertIn("KillMode=mixed", self.unit_lines())


if __name__ == "__main__":
    unittest.main()
