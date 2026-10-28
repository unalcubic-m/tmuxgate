"""Protected local files and durable publication on the broker platform."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import stat
import tempfile
from typing import Iterator

if os.name == "nt":
    from tmuxgate import windows_storage as _windows


def ensure_directory(path: Path) -> None:
    if os.name == "nt":
        _windows.ensure_directory(path)
        return
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    status = path.lstat()
    if not stat.S_ISDIR(status.st_mode) or status.st_uid != os.getuid():
        raise PermissionError(f"expected an owner-only directory: {path}")
    path.chmod(0o700)


def read_private(path: Path) -> bytes:
    """Validate and read one owner-only regular file with exactly one link."""
    if os.name == "nt":
        return _windows.read_private(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        status = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or status.st_mode & 0o077
            or status.st_nlink != 1
        ):
            raise PermissionError(f"expected an owner-only regular file: {path}")
        return handle.read()


def atomic_write(path: Path, payload: bytes, *, exclusive: bool = False) -> None:
    ensure_directory(path.parent)
    if os.name == "nt":
        _windows.atomic_write(path, payload, exclusive=exclusive)
        return
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive:
            os.link(temporary, path)
            temporary.unlink()
        else:
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def remove_private(path: Path) -> bool:
    try:
        if os.name == "nt":
            return _windows.remove_private(path)
        read_private(path)
        path.unlink()
        return True
    except FileNotFoundError:
        return False


@contextmanager
def broker_lock(state: Path) -> Iterator[None]:
    """One broker may recover and update a state directory at a time."""
    ensure_directory(state)
    if os.name == "nt":
        with _windows.broker_lock(state):
            yield
        return
    import fcntl

    path = state / "broker.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_uid != os.getuid() or status.st_mode & 0o077 or status.st_nlink != 1:
            raise PermissionError(f"expected an owner-only broker lock: {path}")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)
