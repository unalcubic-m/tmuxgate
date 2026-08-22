from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ServiceUnitTests(unittest.TestCase):
    def test_server_does_not_inherit_client_bearer_variables(self) -> None:
        unit = (
            ROOT / "src" / "tmuxgate" / "assets" / "tmuxgate.service"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "UnsetEnvironment=TMUXGATE_MCP_TOKEN TMUXGATE_BEARER_TOKEN",
            unit.splitlines(),
        )


if __name__ == "__main__":
    unittest.main()
