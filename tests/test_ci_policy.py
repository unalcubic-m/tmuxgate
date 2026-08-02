"""Regression checks for immutable third-party GitHub Action references."""

from pathlib import Path
import re
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
USES_PATTERN = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
IMMUTABLE_ACTION_PATTERN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def mutable_action_references(workflow: Path) -> tuple[str, ...]:
    references = USES_PATTERN.findall(workflow.read_text(encoding="utf-8"))
    return tuple(
        reference
        for reference in references
        if not reference.startswith("./")
        and IMMUTABLE_ACTION_PATTERN.fullmatch(reference) is None
    )


class CiSupplyChainPolicyTests(unittest.TestCase):
    def test_every_third_party_action_is_pinned_to_a_full_commit_sha(self):
        workflow_dir = ROOT / ".github" / "workflows"
        workflows = sorted(
            set(workflow_dir.glob("*.yml")) | set(workflow_dir.glob("*.yaml"))
        )
        self.assertTrue(workflows)
        violations = {
            workflow.name: mutable_action_references(workflow)
            for workflow in workflows
            if mutable_action_references(workflow)
        }
        self.assertEqual(violations, {})

    def test_controlled_mutable_action_fixture_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            workflow = Path(directory) / "mutable.yml"
            workflow.write_text(
                "steps:\n  - uses: actions/checkout@v7\n",
                encoding="utf-8",
            )
            self.assertEqual(
                mutable_action_references(workflow),
                ("actions/checkout@v7",),
            )


if __name__ == "__main__":
    unittest.main()
