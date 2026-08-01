import unittest

from tmuxgate.availability import (
    MachineAvailabilityError,
    MachineAvailabilityRegistry,
)
from tmuxgate.config import Endpoint, Machine


def machine(*, enabled=True):
    return Machine(
        "host",
        "Host",
        "host",
        "operator",
        "tmuxgate-host",
        6,
        (Endpoint("home-lan", "192.0.2.2", 22, 10, "home"),),
        enabled,
    )


class MachineAvailabilityRegistryTests(unittest.TestCase):
    def test_startup_disabled_machine_is_visible_but_not_enabled(self):
        registry = MachineAvailabilityRegistry({"host": machine(enabled=False)})

        self.assertFalse(registry.is_enabled("host"))
        self.assertFalse(registry.is_enabled("unknown"))

    def test_persistence_precedes_runtime_disable_and_transition_is_idempotent(self):
        registry = MachineAvailabilityRegistry({"host": machine()})
        observations = []

        def persist(alias, expected):
            observations.append((alias, expected, registry.is_enabled(alias)))

        self.assertTrue(registry.disable_persistently("host", persist))
        self.assertFalse(registry.is_enabled("host"))
        self.assertFalse(registry.disable_persistently("host", persist))
        self.assertEqual(len(observations), 1)
        self.assertTrue(observations[0][2])

    def test_persistence_failure_keeps_runtime_state_enabled(self):
        registry = MachineAvailabilityRegistry({"host": machine()})

        def fail(_alias, _expected):
            raise OSError("write failed")

        with self.assertRaises(OSError):
            registry.disable_persistently("host", fail)
        self.assertTrue(registry.is_enabled("host"))

    def test_unknown_machine_cannot_be_created_by_runtime_transition(self):
        registry = MachineAvailabilityRegistry({"host": machine()})
        with self.assertRaises(MachineAvailabilityError):
            registry.disable_persistently("other", lambda *_args: None)


if __name__ == "__main__":
    unittest.main()
