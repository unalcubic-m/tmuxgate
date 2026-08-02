"""State-machine and injected-crash tests for durable record publication."""

from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from tmuxgate.state import DurableStateStore, StateConflictError
from test_state import record


class DurableWriteStateMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.temporary = tempfile.TemporaryDirectory()
        self.store = DurableStateStore(Path(self.temporary.name) / "state")
        self.current = self.store.write(record())

    @rule()
    def advance_generation(self):
        next_generation = self.current.generation + 1
        self.current = self.store.write(
            replace(
                self.current,
                generation=next_generation,
                updated_at=f"2026-08-03T00:{next_generation % 60:02d}:00.000000Z",
            )
        )

    @rule()
    def reject_stale_generation(self):
        try:
            self.store.write(self.current)
        except StateConflictError:
            return
        raise AssertionError("a stale durable generation was accepted")

    @invariant()
    def disk_matches_the_latest_successful_transition(self):
        assert self.store.load(self.current.request_id) == self.current
        assert sorted(item.name for item in self.store.jobs_dir.iterdir()) == [
            f"{self.current.request_id}.json"
        ]

    def teardown(self):
        self.store.close()
        self.temporary.cleanup()


TestDurableWriteStateMachine = DurableWriteStateMachine.TestCase
TestDurableWriteStateMachine.settings = settings(
    max_examples=30,
    stateful_step_count=20,
    deadline=None,
)


class DurableWriteFailureInjectionTests(unittest.TestCase):
    def _store_with_transition(self):
        temporary = tempfile.TemporaryDirectory()
        store = DurableStateStore(Path(temporary.name) / "state")
        current = store.write(record())
        transition = replace(
            current,
            generation=2,
            updated_at="2026-08-03T00:01:00.000000Z",
        )
        self.addCleanup(store.close)
        self.addCleanup(temporary.cleanup)
        return store, current, transition

    def test_failures_before_atomic_publication_preserve_the_previous_record(self):
        failure_points = ("open", "write", "file-fsync", "replace")
        for failure_point in failure_points:
            with self.subTest(failure_point=failure_point):
                store, current, transition = self._store_with_transition()
                real_open = os.open

                def injected_open(path, *args, **kwargs):
                    if isinstance(path, str) and path.startswith("."):
                        raise OSError("injected temporary-open failure")
                    return real_open(path, *args, **kwargs)

                if failure_point == "open":
                    patcher = mock.patch("tmuxgate.state.os.open", side_effect=injected_open)
                elif failure_point == "write":
                    patcher = mock.patch(
                        "tmuxgate.state.os.write",
                        side_effect=OSError("injected write failure"),
                    )
                elif failure_point == "file-fsync":
                    patcher = mock.patch(
                        "tmuxgate.state.os.fsync",
                        side_effect=OSError("injected file-fsync failure"),
                    )
                else:
                    patcher = mock.patch(
                        "tmuxgate.state.os.replace",
                        side_effect=OSError("injected replace failure"),
                    )

                with patcher, self.assertRaises(OSError):
                    store.write(transition)

                self.assertEqual(store.load(current.request_id), current)
                self.assertEqual(
                    sorted(item.name for item in store.jobs_dir.iterdir()),
                    [f"{current.request_id}.json"],
                )

    def test_directory_fsync_failure_leaves_a_valid_new_or_old_record(self):
        store, current, transition = self._store_with_transition()
        real_fsync = os.fsync
        calls = 0

        def fail_directory_fsync(descriptor):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected directory-fsync failure")
            return real_fsync(descriptor)

        with mock.patch("tmuxgate.state.os.fsync", side_effect=fail_directory_fsync):
            with self.assertRaises(OSError):
                store.write(transition)

        self.assertIn(store.load(current.request_id), (current, transition))
        self.assertEqual(
            sorted(item.name for item in store.jobs_dir.iterdir()),
            [f"{current.request_id}.json"],
        )


if __name__ == "__main__":
    unittest.main()
