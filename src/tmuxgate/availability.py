"""Thread-safe runtime view of configured machine availability."""

from __future__ import annotations

from collections.abc import Callable, Mapping
import threading

from tmuxgate.config import Machine
from tmuxgate.models import ValidationError, validate_alias


class MachineAvailabilityError(RuntimeError):
    """A runtime machine state transition was invalid."""


class MachineAvailabilityRegistry:
    """Share startup flags and broker-confirmed disables across components."""

    def __init__(self, machines: Mapping[str, Machine]) -> None:
        if not isinstance(machines, Mapping) or not machines:
            raise ValueError("machines must be a non-empty mapping")
        startup: dict[str, Machine] = {}
        enabled: dict[str, bool] = {}
        for alias, machine in machines.items():
            try:
                machine_name = validate_alias(alias)
            except ValidationError as exc:
                raise ValueError(str(exc)) from exc
            if not isinstance(machine, Machine) or machine.name != machine_name:
                raise TypeError("machine registry entries must match their aliases")
            startup[machine_name] = machine
            enabled[machine_name] = machine.enabled
        self._startup = startup
        self._enabled = enabled
        self._lock = threading.RLock()

    def is_enabled(self, machine_name: str) -> bool:
        """Return false for unknown or currently disabled logical machines."""

        try:
            machine_name = validate_alias(machine_name)
        except (TypeError, ValidationError):
            return False
        with self._lock:
            return self._enabled.get(machine_name, False)

    def disable_persistently(
        self,
        machine_name: str,
        persist: Callable[[str, Machine], object],
    ) -> bool:
        """Persist then publish one disable as a single runtime transition."""

        try:
            machine_name = validate_alias(machine_name)
        except ValidationError as exc:
            raise MachineAvailabilityError(str(exc)) from exc
        if not callable(persist):
            raise TypeError("persist must be callable")
        with self._lock:
            try:
                startup_machine = self._startup[machine_name]
            except KeyError as exc:
                raise MachineAvailabilityError(
                    f"unknown configured machine: {machine_name}"
                ) from exc
            if not self._enabled[machine_name]:
                return False
            persist(machine_name, startup_machine)
            self._enabled[machine_name] = False
            return True
