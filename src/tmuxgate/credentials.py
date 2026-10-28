"""Owner-only per-machine sudo password files."""

from __future__ import annotations

import hashlib
from pathlib import Path

from tmuxgate.storage import atomic_write, ensure_directory, read_private, remove_private


class CredentialError(RuntimeError):
    """A sudo credential could not be read or stored safely."""


class CredentialStore:
    def __init__(self, state_dir: Path | str) -> None:
        state = Path(state_dir)
        ensure_directory(state)
        self.directory = state / "sudo"
        ensure_directory(self.directory)

    def path_for(self, machine: str) -> Path:
        digest = hashlib.sha256(machine.encode("utf-8")).hexdigest()
        return self.directory / digest

    def read(self, machine: str) -> bytearray | None:
        path = self.path_for(machine)
        try:
            value = bytearray(read_private(path))
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CredentialError(f"cannot read sudo credential for {machine}: {exc}") from exc
        if not value or b"\x00" in value or b"\n" in value or b"\r" in value:
            _erase(value)
            raise CredentialError(f"invalid sudo credential for {machine}")
        return value

    def save(self, machine: str, password: str | bytes | bytearray) -> None:
        if isinstance(password, str):
            value = password.encode("utf-8")
        else:
            value = bytes(password)
        if not value or b"\x00" in value or b"\n" in value or b"\r" in value:
            raise CredentialError("sudo password must be non-empty and single-line")
        try:
            atomic_write(self.path_for(machine), value)
        except OSError as exc:
            raise CredentialError(f"cannot store sudo credential for {machine}: {exc}") from exc

    def clear(self, machine: str) -> bool:
        try:
            return remove_private(self.path_for(machine))
        except OSError as exc:
            raise CredentialError(f"cannot clear sudo credential for {machine}: {exc}") from exc


def _erase(value: bytearray | None) -> None:
    if value is None:
        return
    for index in range(len(value)):
        value[index] = 0
    value.clear()
