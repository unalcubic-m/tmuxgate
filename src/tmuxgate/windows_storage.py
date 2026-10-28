"""Native Windows ACLs, handle validation, and write-through publication.

This module is imported only on Windows. No chmod or POSIX emulation is used.
"""

from __future__ import annotations

from contextlib import contextmanager, ExitStack
from functools import lru_cache
from pathlib import Path
import secrets
from typing import Any, Iterator

import pywintypes
import win32api
import win32con
import win32file
import win32security
import winerror


@contextmanager
def _errors(path: Path) -> Iterator[None]:
    try:
        yield
    except pywintypes.error as exc:
        raise OSError(None, exc.strerror, str(path), exc.winerror) from exc


@lru_cache(maxsize=1)
def _sid() -> Any:
    with _handle(win32security.OpenProcessToken(
        win32api.GetCurrentProcess(), win32con.TOKEN_QUERY
    )) as token:
        return win32security.GetTokenInformation(token, win32security.TokenUser)[0]


def _attributes(directory: bool = False) -> Any:
    sid = win32security.ConvertSidToStringSid(_sid())
    flags = "OICI" if directory else ""
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"O:{sid}D:P(A;{flags};FA;;;{sid})", win32security.SDDL_REVISION_1
    )
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    attributes.bInheritHandle = False
    return attributes


def _local_path(path: Path) -> Path:
    path = path.absolute()
    # Network filesystems and filesystems without persistent ACLs cannot provide
    # the local security/durability contract of this broker.
    if path.drive.startswith("\\\\") or win32file.GetDriveType(path.anchor) != win32con.DRIVE_FIXED:
        raise PermissionError("Windows broker state requires a local fixed drive")
    if not win32api.GetVolumeInformation(path.anchor)[3] & win32con.FILE_PERSISTENT_ACLS:
        raise PermissionError("Windows broker state requires persistent filesystem ACLs")
    return path


@contextmanager
def _handle(handle: Any) -> Iterator[Any]:
    try:
        yield handle
    finally:
        handle.Close()


@contextmanager
def _open(path: Path, *, directory: bool, access: int = win32con.GENERIC_READ) -> Iterator[Any]:
    sharing = win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE
    if not directory:
        sharing |= win32con.FILE_SHARE_DELETE
    with _handle(win32file.CreateFile(
        str(path),
        access | win32con.READ_CONTROL,
        sharing,
        None,
        win32con.OPEN_EXISTING,
        win32file.FILE_FLAG_OPEN_REPARSE_POINT | win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )) as handle:
        yield handle


def _validate(handle: Any, path: Path, *, directory: bool, private: bool = True) -> None:
    information = win32file.GetFileInformationByHandle(handle)
    attributes = information[0]
    if attributes & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
        raise PermissionError(f"reparse points are forbidden in broker storage: {path}")
    if bool(attributes & win32con.FILE_ATTRIBUTE_DIRECTORY) != directory:
        raise PermissionError(f"unexpected broker storage object type: {path}")
    if not directory and information[7] != 1:
        raise PermissionError(f"hard links are forbidden in broker storage: {path}")
    if not private:
        return
    descriptor = win32security.GetSecurityInfo(
        handle, win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
    )
    dacl = descriptor.GetSecurityDescriptorDacl()
    control = descriptor.GetSecurityDescriptorControl()[0]
    if (
        descriptor.GetSecurityDescriptorOwner() != _sid()
        or not control & win32security.SE_DACL_PROTECTED
        or dacl is None
        or dacl.GetAceCount() != 1
    ):
        raise PermissionError(f"expected an owner-only protected ACL: {path}")
    (kind, flags), mask, sid = dacl.GetAce(0)
    permitted_flags = win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE if directory else 0
    if (
        kind != win32security.ACCESS_ALLOWED_ACE_TYPE
        or flags & ~permitted_flags
        or mask != win32file.FILE_ALL_ACCESS
        or sid != _sid()
    ):
        raise PermissionError(f"expected an owner-only protected ACL: {path}")


@contextmanager
def _parents(path: Path, *, create: bool = False) -> Iterator[None]:
    # Pin each ancestor without FILE_SHARE_DELETE until the operation finishes.
    # OPEN_REPARSE_POINT prevents following junctions, symlinks, and other tags.
    with ExitStack() as stack:
        for parent in reversed(path.parents):
            if create and not parent.exists():
                win32file.CreateDirectory(str(parent), _attributes(directory=True))
            handle = stack.enter_context(_open(parent, directory=True, access=0))
            _validate(handle, parent, directory=True, private=False)
        yield


def ensure_directory(path: Path) -> None:
    with _errors(path):
        path = _local_path(path)
        with _parents(path, create=True):
            try:
                win32file.CreateDirectory(str(path), _attributes(directory=True))
            except pywintypes.error as exc:
                if exc.winerror != winerror.ERROR_ALREADY_EXISTS:
                    raise
            with _open(path, directory=True, access=0) as handle:
                _validate(handle, path, directory=True)


def read_private(path: Path) -> bytes:
    with _errors(path):
        path = _local_path(path)
        with _parents(path), _open(path, directory=False) as handle:
            _validate(handle, path, directory=False)
            chunks = []
            while True:
                _status, chunk = win32file.ReadFile(handle, 1024 * 1024)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)


def atomic_write(path: Path, payload: bytes, *, exclusive: bool = False) -> None:
    with _errors(path):
        path = _local_path(path)
        with _parents(path):
            with _open(path.parent, directory=True, access=0) as parent:
                _validate(parent, path.parent, directory=True)
            temporary = path.with_name(f".{path.name}.{secrets.token_hex(16)}.tmp")
            try:
                with _handle(win32file.CreateFile(
                    str(temporary), win32con.GENERIC_WRITE | win32con.READ_CONTROL,
                    0, _attributes(), win32con.CREATE_NEW,
                    win32con.FILE_ATTRIBUTE_NORMAL | win32con.FILE_FLAG_WRITE_THROUGH, None,
                )) as handle:
                    _validate(handle, temporary, directory=False)
                    # WriteFile may return a short count; never publish partial data.
                    remaining = payload
                    while remaining:
                        _status, written = win32file.WriteFile(handle, remaining)
                        if written <= 0:
                            raise OSError("incomplete Windows storage write")
                        remaining = remaining[written:]
                    win32file.FlushFileBuffers(handle)
                if not exclusive:
                    try:
                        with _open(path, directory=False) as existing:
                            _validate(existing, path, directory=False)
                    except pywintypes.error as exc:
                        if exc.winerror != winerror.ERROR_FILE_NOT_FOUND:
                            raise
                flags = win32file.MOVEFILE_WRITE_THROUGH
                if not exclusive:
                    flags |= win32file.MOVEFILE_REPLACE_EXISTING
                win32file.MoveFileEx(str(temporary), str(path), flags)
            finally:
                temporary.unlink(missing_ok=True)


def remove_private(path: Path) -> bool:
    with _errors(path):
        path = _local_path(path)
        with _parents(path):
            with _open(path, directory=False) as handle:
                _validate(handle, path, directory=False)
            win32file.DeleteFile(str(path))
            return True


@contextmanager
def broker_lock(state: Path) -> Iterator[None]:
    path = state / "broker.lock"
    with _errors(path):
        path = _local_path(path)
        with _parents(path):
            with _handle(win32file.CreateFile(
                str(path), win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                0, _attributes(), win32con.OPEN_ALWAYS,
                win32file.FILE_FLAG_OPEN_REPARSE_POINT, None,
            )) as handle:
                _validate(handle, path, directory=False)
                yield
