"""Owner-only per-machine sudo password files."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile


class CredentialError(RuntimeError):
    """A sudo credential could not be read or stored safely."""


class CredentialStore:
    def __init__(self, state_dir: Path | str) -> None:
        self.directory = Path(state_dir) / "sudo"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)

    def path_for(self, machine: str) -> Path:
        digest = hashlib.sha256(machine.encode("utf-8")).hexdigest()
        return self.directory / digest

    def read(self, machine: str) -> bytearray | None:
        path = self.path_for(machine)
        try:
            status = path.stat(follow_symlinks=False)
            if not path.is_file() or status.st_uid != os.getuid():
                raise CredentialError(f"unsafe sudo credential file for {machine}")
            if status.st_mode & 0o077:
                raise CredentialError(f"sudo credential file for {machine} is not mode 0600")
            value = bytearray(path.read_bytes())
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
        descriptor, name = tempfile.mkstemp(prefix=".credential.", dir=self.directory)
        temporary = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path_for(machine))
            self.path_for(machine).chmod(0o600)
        except BaseException:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise

    def clear(self, machine: str) -> bool:
        try:
            self.path_for(machine).unlink()
            return True
        except FileNotFoundError:
            return False


def _erase(value: bytearray | None) -> None:
    if value is None:
        return
    for index in range(len(value)):
        value[index] = 0
    value.clear()
