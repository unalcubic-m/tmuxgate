"""Linux Unix-socket runtime security primitives for the local broker."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import errno
import fcntl
import os
from pathlib import Path
import socket
import stat
import struct


SOCKET_DIRECTORY_NAME = "tmuxgate"
SOCKET_FILE_NAME = "broker.sock"
STATE_DIRECTORY_NAME = "tmuxgate"
SPOOL_DIRECTORY_NAME = "spool"
CONTROL_DIRECTORY_NAME = "control"
VIEWER_DIRECTORY_NAME = "viewers"
BROKER_LOCK_FILE_NAME = "broker.lock"
SOCKET_MODE = 0o600
LOCK_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
DEFAULT_LISTEN_BACKLOG = 16


class RuntimeSecurityError(RuntimeError):
    """A runtime path or local peer failed a security invariant."""


class PeerCredentialError(RuntimeSecurityError):
    """Peer credentials were unavailable, malformed, or unauthorized."""


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    runtime_dir: Path
    socket_path: Path
    state_dir: Path
    control_dir: Path
    viewer_dir: Path
    spool_dir: Path
    lock_path: Path


_UCRED = struct.Struct("=iII")
_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_LOCK_OPEN_FLAGS = (
    os.O_RDWR
    | os.O_CREAT
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


def _expected_uid(value: int | None) -> int:
    uid = os.geteuid() if value is None else value
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise RuntimeSecurityError("expected UID must be a non-negative integer")
    return uid


def _absolute_path(value: os.PathLike[str] | str, *, label: str) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise RuntimeSecurityError(f"{label} must be a filesystem path") from exc
    if not isinstance(raw, str):
        raise RuntimeSecurityError(f"{label} must be text, not bytes")
    if "\x00" in raw:
        raise RuntimeSecurityError(f"{label} contains a NUL byte")
    if any(component in {".", ".."} for component in raw.split("/")):
        raise RuntimeSecurityError(f"{label} must not contain dot components")
    path = Path(raw)
    if not path.is_absolute():
        raise RuntimeSecurityError(f"{label} must be an absolute path")
    return path


def default_runtime_dir(
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Return the trusted per-user runtime directory from XDG_RUNTIME_DIR.

    There is intentionally no shared-/tmp fallback for the broker socket.
    """

    source = os.environ if environ is None else environ
    value = source.get("XDG_RUNTIME_DIR")
    if not isinstance(value, str) or not value:
        raise RuntimeSecurityError("XDG_RUNTIME_DIR is required for the broker socket")
    return _absolute_path(value, label="XDG_RUNTIME_DIR")


def default_socket_path(
    environ: Mapping[str, str] | None = None,
) -> Path:
    return default_runtime_dir(environ) / SOCKET_DIRECTORY_NAME / SOCKET_FILE_NAME


def default_state_home(
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Return XDG_STATE_HOME, falling back to ``~/.local/state``."""

    source = os.environ if environ is None else environ
    configured = source.get("XDG_STATE_HOME")
    if isinstance(configured, str) and configured:
        return _absolute_path(configured, label="XDG_STATE_HOME")
    home = source.get("HOME")
    if not isinstance(home, str) or not home:
        home = os.path.expanduser("~")
    return _absolute_path(home, label="HOME") / ".local" / "state"


def default_state_dir(
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Return the durable application state directory."""

    return default_state_home(environ) / STATE_DIRECTORY_NAME


def _validate_directory_stat(
    path: Path,
    metadata: os.stat_result,
    *,
    expected_uid: int,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeSecurityError(f"runtime directory is not a directory: {path}")
    if metadata.st_uid != expected_uid:
        raise RuntimeSecurityError(
            f"runtime directory is not owned by UID {expected_uid}: {path}"
        )
    mode = stat.S_IMODE(metadata.st_mode)
    if mode != PRIVATE_DIRECTORY_MODE:
        raise RuntimeSecurityError(
            f"runtime directory must have mode 0700, found {mode:04o}: {path}"
        )


def _same_object(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _path_components(path: Path) -> tuple[str, ...]:
    components = path.parts
    if not components or components[0] not in {"/", "//"}:
        raise RuntimeSecurityError(f"path is not absolute: {path}")
    if components[0] == "//":
        raise RuntimeSecurityError(f"double-slash root is not supported: {path}")
    return tuple(components[1:])


def _open_parent_directory_nofollow(path: Path) -> tuple[int, str]:
    """Open ``path``'s parent component by component without symlinks."""

    components = _path_components(path)
    if not components:
        raise RuntimeSecurityError("the filesystem root cannot be used here")
    try:
        descriptor = os.open("/", _DIRECTORY_OPEN_FLAGS)
    except OSError as exc:  # pragma: no cover - a functional Linux root is assumed
        raise RuntimeSecurityError(f"cannot open filesystem root: {exc}") from exc
    try:
        for component in components[:-1]:
            try:
                next_descriptor = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise RuntimeSecurityError(
                    f"path contains a symlink, missing, or non-directory component: "
                    f"{path}: {exc}"
                ) from exc
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, components[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _ensure_directory_chain_nofollow(
    path: Path,
    *,
    expected_uid: int,
) -> None:
    """Create missing directory components without following existing symlinks."""

    components = _path_components(path)
    descriptor = os.open("/", _DIRECTORY_OPEN_FLAGS)
    try:
        for component in components:
            try:
                next_descriptor = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                try:
                    os.mkdir(component, PRIVATE_DIRECTORY_MODE, dir_fd=descriptor)
                    next_descriptor = os.open(
                        component,
                        _DIRECTORY_OPEN_FLAGS,
                        dir_fd=descriptor,
                    )
                except OSError as exc:
                    raise RuntimeSecurityError(
                        f"cannot securely create state directory component "
                        f"{component!r} in {path}: {exc}"
                    ) from exc
            except OSError as exc:
                raise RuntimeSecurityError(
                    f"state path contains a symlink or non-directory component: "
                    f"{path}: {exc}"
                ) from exc
            os.close(descriptor)
            descriptor = next_descriptor

        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != expected_uid:
            raise RuntimeSecurityError(
                f"state home is not an owned directory for UID {expected_uid}: {path}"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise RuntimeSecurityError(
                f"state home must not be group/world writable: {path}"
            )
    finally:
        os.close(descriptor)


def _open_private_directory(path: Path, *, expected_uid: int) -> int:
    parent_descriptor, name = _open_parent_directory_nofollow(path)
    try:
        try:
            descriptor = os.open(
                name,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise RuntimeSecurityError(
                f"cannot open runtime directory without following symlinks: "
                f"{path}: {exc}"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            _validate_directory_stat(path, opened, expected_uid=expected_uid)
            named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if not _same_object(opened, named):
                raise RuntimeSecurityError(
                    f"runtime directory changed while opening: {path}"
                )
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor
    finally:
        os.close(parent_descriptor)


def ensure_private_directory(
    path: os.PathLike[str] | str,
    *,
    expected_uid: int | None = None,
) -> Path:
    """Create or validate an owner-only directory without following it.

    Unsafe pre-existing permissions are rejected instead of silently repaired.
    """

    directory = _absolute_path(path, label="private directory")
    uid = _expected_uid(expected_uid)
    parent_descriptor, name = _open_parent_directory_nofollow(directory)
    try:
        try:
            os.mkdir(name, PRIVATE_DIRECTORY_MODE, dir_fd=parent_descriptor)
        except FileExistsError:
            pass
        except OSError as exc:
            raise RuntimeSecurityError(
                f"cannot create private directory {directory}: {exc}"
            ) from exc
    finally:
        os.close(parent_descriptor)
    descriptor = _open_private_directory(directory, expected_uid=uid)
    os.close(descriptor)
    return directory


def _ensure_private_child(
    parent: os.PathLike[str] | str,
    name: str,
    *,
    expected_uid: int,
) -> Path:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise RuntimeSecurityError("private directory child name is invalid")
    parent_path = _absolute_path(parent, label="runtime parent")
    parent_descriptor = _open_private_directory(parent_path, expected_uid=expected_uid)
    try:
        try:
            os.mkdir(name, PRIVATE_DIRECTORY_MODE, dir_fd=parent_descriptor)
        except FileExistsError:
            pass
        except OSError as exc:
            raise RuntimeSecurityError(
                f"cannot create private runtime directory {parent_path / name}: {exc}"
            ) from exc

        try:
            child_descriptor = os.open(
                name,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise RuntimeSecurityError(
                f"cannot open private runtime directory without following symlinks: "
                f"{parent_path / name}: {exc}"
            ) from exc
        try:
            child_metadata = os.fstat(child_descriptor)
            _validate_directory_stat(
                parent_path / name,
                child_metadata,
                expected_uid=expected_uid,
            )
            named_metadata = os.stat(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if not _same_object(child_metadata, named_metadata):
                raise RuntimeSecurityError(
                    f"private runtime directory changed while opening: {parent_path / name}"
                )
        finally:
            os.close(child_descriptor)
    finally:
        os.close(parent_descriptor)
    return parent_path / name


def _prepare_socket_parent(
    socket_path: os.PathLike[str] | str | None,
    *,
    expected_uid: int,
    environ: Mapping[str, str] | None,
) -> tuple[Path, Path]:
    if socket_path is None:
        xdg_runtime = default_runtime_dir(environ)
        # XDG_RUNTIME_DIR is provided by the login/session manager and must
        # already exist with its specification-mandated ownership and mode.
        xdg_descriptor = _open_private_directory(
            xdg_runtime,
            expected_uid=expected_uid,
        )
        os.close(xdg_descriptor)
        runtime_dir = _ensure_private_child(
            xdg_runtime,
            SOCKET_DIRECTORY_NAME,
            expected_uid=expected_uid,
        )
        return runtime_dir / SOCKET_FILE_NAME, runtime_dir

    selected = _absolute_path(socket_path, label="broker socket path")
    if selected.name in {"", ".", ".."}:
        raise RuntimeSecurityError("broker socket path must name a file")
    runtime_dir = ensure_private_directory(selected.parent, expected_uid=expected_uid)
    return selected, runtime_dir


def ensure_socket_parent(
    socket_path: os.PathLike[str] | str | None = None,
    *,
    expected_uid: int | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    uid = _expected_uid(expected_uid)
    _, runtime_dir = _prepare_socket_parent(
        socket_path,
        expected_uid=uid,
        environ=environ,
    )
    return runtime_dir


def ensure_state_directory(
    state_dir: os.PathLike[str] | str | None = None,
    *,
    expected_uid: int | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Create or validate the durable owner-only application state directory.

    ``state_dir`` names the application directory itself.  When omitted it is
    ``$XDG_STATE_HOME/tmuxgate``, with the XDG default of
    ``~/.local/state/tmuxgate``.
    """

    uid = _expected_uid(expected_uid)
    selected = (
        default_state_dir(environ)
        if state_dir is None
        else _absolute_path(state_dir, label="state directory")
    )
    _ensure_directory_chain_nofollow(selected.parent, expected_uid=uid)
    return ensure_private_directory(selected, expected_uid=uid)


def ensure_spool_directory(
    state_dir: os.PathLike[str] | str,
    *,
    expected_uid: int | None = None,
) -> Path:
    """Create or validate the durable owner-only result spool directory."""

    uid = _expected_uid(expected_uid)
    return _ensure_private_child(
        state_dir,
        SPOOL_DIRECTORY_NAME,
        expected_uid=uid,
    )


def ensure_control_directory(
    runtime_dir: os.PathLike[str] | str,
    *,
    expected_uid: int | None = None,
) -> Path:
    uid = _expected_uid(expected_uid)
    return _ensure_private_child(
        runtime_dir,
        CONTROL_DIRECTORY_NAME,
        expected_uid=uid,
    )


def ensure_viewer_directory(
    runtime_dir: os.PathLike[str] | str,
    *,
    expected_uid: int | None = None,
) -> Path:
    uid = _expected_uid(expected_uid)
    return _ensure_private_child(
        runtime_dir,
        VIEWER_DIRECTORY_NAME,
        expected_uid=uid,
    )


def prepare_runtime_layout(
    socket_path: os.PathLike[str] | str | None = None,
    *,
    state_dir: os.PathLike[str] | str | None = None,
    expected_uid: int | None = None,
    environ: Mapping[str, str] | None = None,
) -> RuntimePaths:
    """Prepare separate ephemeral runtime and durable state boundaries."""

    uid = _expected_uid(expected_uid)
    selected_socket, runtime_dir = _prepare_socket_parent(
        socket_path,
        expected_uid=uid,
        environ=environ,
    )
    control_dir = ensure_control_directory(runtime_dir, expected_uid=uid)
    viewer_dir = ensure_viewer_directory(runtime_dir, expected_uid=uid)
    durable_state_dir = ensure_state_directory(
        state_dir,
        expected_uid=uid,
        environ=environ,
    )
    spool_dir = ensure_spool_directory(durable_state_dir, expected_uid=uid)
    return RuntimePaths(
        runtime_dir=runtime_dir,
        socket_path=selected_socket,
        state_dir=durable_state_dir,
        control_dir=control_dir,
        viewer_dir=viewer_dir,
        spool_dir=spool_dir,
        lock_path=runtime_dir / BROKER_LOCK_FILE_NAME,
    )


def _validate_socket_stat(
    path: Path,
    metadata: os.stat_result,
    *,
    expected_uid: int,
) -> None:
    if not stat.S_ISSOCK(metadata.st_mode):
        raise RuntimeSecurityError(f"refusing to replace non-socket path: {path}")
    if metadata.st_uid != expected_uid:
        raise RuntimeSecurityError(
            f"refusing to replace socket not owned by UID {expected_uid}: {path}"
        )
    mode = stat.S_IMODE(metadata.st_mode)
    if mode != SOCKET_MODE:
        raise RuntimeSecurityError(
            f"existing socket must have mode 0600, found {mode:04o}: {path}"
        )


def _validate_lock_stat(
    path: Path,
    metadata: os.stat_result,
    *,
    expected_uid: int,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeSecurityError(f"broker lock is not a regular file: {path}")
    if metadata.st_uid != expected_uid:
        raise RuntimeSecurityError(
            f"broker lock is not owned by UID {expected_uid}: {path}"
        )
    mode = stat.S_IMODE(metadata.st_mode)
    if mode != LOCK_MODE:
        raise RuntimeSecurityError(
            f"broker lock must have mode 0600, found {mode:04o}: {path}"
        )


class BrokerSingletonLock:
    """An owner-only advisory lock held by a broker lifecycle owner."""

    __slots__ = ("path", "_descriptor", "_closed")

    def __init__(self, path: Path, descriptor: int) -> None:
        self.path = path
        self._descriptor = descriptor
        self._closed = False

    @classmethod
    def acquire(
        cls,
        runtime_dir: os.PathLike[str] | str,
        *,
        expected_uid: int | None = None,
    ) -> BrokerSingletonLock:
        uid = _expected_uid(expected_uid)
        parent = _absolute_path(runtime_dir, label="broker runtime directory")
        parent_descriptor = _open_private_directory(parent, expected_uid=uid)
        lock_path = parent / BROKER_LOCK_FILE_NAME
        descriptor: int | None = None
        try:
            try:
                descriptor = os.open(
                    BROKER_LOCK_FILE_NAME,
                    _LOCK_OPEN_FLAGS,
                    LOCK_MODE,
                    dir_fd=parent_descriptor,
                )
            except OSError as exc:
                raise RuntimeSecurityError(
                    f"cannot securely open broker lock {lock_path}: {exc}"
                ) from exc
            opened = os.fstat(descriptor)
            named = os.stat(
                BROKER_LOCK_FILE_NAME,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            _validate_lock_stat(lock_path, opened, expected_uid=uid)
            if not _same_object(opened, named):
                raise RuntimeSecurityError(
                    f"broker lock changed while opening: {lock_path}"
                )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeSecurityError(
                    f"another broker lifecycle already holds {lock_path}"
                ) from exc
            except OSError as exc:
                raise RuntimeSecurityError(
                    f"cannot acquire broker singleton lock {lock_path}: {exc}"
                ) from exc
            return cls(lock_path, descriptor)
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            raise
        finally:
            os.close(parent_descriptor)

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
        finally:
            os.close(self._descriptor)

    def __enter__(self) -> BrokerSingletonLock:
        if self._closed:
            raise RuntimeSecurityError("broker singleton lock is already closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


def acquire_broker_lock(
    runtime_dir: os.PathLike[str] | str,
    *,
    expected_uid: int | None = None,
) -> BrokerSingletonLock:
    """Acquire the explicit broker singleton lifecycle lock."""

    return BrokerSingletonLock.acquire(runtime_dir, expected_uid=expected_uid)


def _nonblocking_listener_probe(path: Path) -> int:
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.setblocking(False)
        return probe.connect_ex(os.fspath(path))
    finally:
        probe.close()


def cleanup_socket_path(
    socket_path: os.PathLike[str] | str,
    *,
    expected_uid: int | None = None,
) -> bool:
    """Remove only a securely-owned, mode-0600, provably stale socket.

    ``ECONNREFUSED`` from a nonblocking connection is the sole stale-listener
    proof. A successful connection, an indeterminate result, or any unexpected
    filesystem object is preserved and rejected.
    """

    path = _absolute_path(socket_path, label="broker socket path")
    uid = _expected_uid(expected_uid)
    try:
        os.lstat(path.parent)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RuntimeSecurityError(
            f"cannot inspect broker socket parent {path.parent}: {exc}"
        ) from exc
    parent_descriptor = _open_private_directory(path.parent, expected_uid=uid)
    try:
        try:
            initial = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise RuntimeSecurityError(f"cannot inspect broker socket {path}: {exc}") from exc
        _validate_socket_stat(path, initial, expected_uid=uid)

        result = _nonblocking_listener_probe(path)
        if result == 0:
            raise RuntimeSecurityError(f"broker socket already has a live listener: {path}")
        if result == errno.ENOENT:
            return False
        if result != errno.ECONNREFUSED:
            message = os.strerror(result) if result else "unknown error"
            raise RuntimeSecurityError(
                f"cannot prove existing broker socket is stale ({message}): {path}"
            )

        try:
            current = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            named = os.lstat(path)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise RuntimeSecurityError(
                f"cannot revalidate stale broker socket {path}: {exc}"
            ) from exc
        _validate_socket_stat(path, current, expected_uid=uid)
        if not _same_object(initial, current) or not _same_object(initial, named):
            raise RuntimeSecurityError(f"broker socket changed during stale check: {path}")
        try:
            os.unlink(path.name, dir_fd=parent_descriptor)
        except OSError as exc:
            raise RuntimeSecurityError(f"cannot remove stale broker socket {path}: {exc}") from exc
        return True
    finally:
        os.close(parent_descriptor)


def create_broker_socket(
    socket_path: os.PathLike[str] | str | None = None,
    *,
    expected_uid: int | None = None,
    environ: Mapping[str, str] | None = None,
    backlog: int = DEFAULT_LISTEN_BACKLOG,
) -> socket.socket:
    """Create, bind, permission, and listen on the broker's Unix socket.

    This compatibility helper serializes stale cleanup through broker startup.
    New long-running broker entry points should use :func:`open_broker_listener`
    so the singleton lock remains held until the listener is closed.
    """

    if isinstance(backlog, bool) or not isinstance(backlog, int) or backlog < 1:
        raise RuntimeSecurityError("socket listen backlog must be a positive integer")
    uid = _expected_uid(expected_uid)
    path, runtime_dir = _prepare_socket_parent(
        socket_path,
        expected_uid=uid,
        environ=environ,
    )
    with acquire_broker_lock(runtime_dir, expected_uid=uid):
        return _create_broker_socket_at(
            path,
            runtime_dir,
            expected_uid=uid,
            backlog=backlog,
        )


def _create_broker_socket_at(
    path: Path,
    runtime_dir: Path,
    *,
    expected_uid: int,
    backlog: int,
) -> socket.socket:
    cleanup_socket_path(path, expected_uid=expected_uid)

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.set_inheritable(False)
    bound_metadata: os.stat_result | None = None
    try:
        listener.bind(os.fspath(path))
        bound_metadata = os.lstat(path)
        _validate_socket_stat_after_bind(
            path,
            bound_metadata,
            expected_uid=expected_uid,
        )
        os.chmod(path, SOCKET_MODE, follow_symlinks=False)
        final_metadata = os.lstat(path)
        _validate_socket_stat(path, final_metadata, expected_uid=expected_uid)
        if not _same_object(bound_metadata, final_metadata):
            raise RuntimeSecurityError(f"broker socket changed while securing it: {path}")

        # Revalidate the path's parent after binding so an unexpected rename is
        # detected before requests can be accepted.
        parent_descriptor = _open_private_directory(
            runtime_dir,
            expected_uid=expected_uid,
        )
        os.close(parent_descriptor)
        listener.listen(backlog)
        return listener
    except BaseException:
        listener.close()
        if bound_metadata is not None:
            _unlink_created_socket(
                path,
                bound_metadata,
                expected_uid=expected_uid,
            )
        raise


def _validate_socket_stat_after_bind(
    path: Path,
    metadata: os.stat_result,
    *,
    expected_uid: int,
) -> None:
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != expected_uid:
        raise RuntimeSecurityError(f"new broker socket has unsafe identity: {path}")


def _unlink_created_socket(
    path: Path,
    expected: os.stat_result,
    *,
    expected_uid: int,
) -> None:
    """Best-effort rollback, restricted to the exact socket just bound."""

    try:
        current = os.lstat(path)
    except OSError:
        return
    if (
        _same_object(current, expected)
        and stat.S_ISSOCK(current.st_mode)
        and current.st_uid == expected_uid
    ):
        try:
            os.unlink(path)
        except OSError:
            pass


class BrokerListenerLifecycle:
    """Own a raw listener and its singleton lock as one explicit lifecycle.

    ``listener`` remains an ordinary :class:`socket.socket`, so it can be
    passed directly to ``BrokerServer``.  The lifecycle object, rather than the
    server, must be closed after the server has stopped.
    """

    __slots__ = (
        "listener",
        "socket_path",
        "_lock",
        "_bound_metadata",
        "_expected_uid",
        "_closed",
    )

    def __init__(
        self,
        listener: socket.socket,
        socket_path: Path,
        lock: BrokerSingletonLock,
        bound_metadata: os.stat_result,
        *,
        expected_uid: int,
    ) -> None:
        self.listener = listener
        self.socket_path = socket_path
        self._lock = lock
        self._bound_metadata = bound_metadata
        self._expected_uid = expected_uid
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def lock_path(self) -> Path:
        return self._lock.path

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.listener.close()
            _unlink_created_socket(
                self.socket_path,
                self._bound_metadata,
                expected_uid=self._expected_uid,
            )
        finally:
            self._lock.close()

    def __enter__(self) -> BrokerListenerLifecycle:
        if self._closed:
            raise RuntimeSecurityError("broker listener lifecycle is already closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


def open_broker_listener(
    socket_path: os.PathLike[str] | str | None = None,
    *,
    expected_uid: int | None = None,
    environ: Mapping[str, str] | None = None,
    backlog: int = DEFAULT_LISTEN_BACKLOG,
) -> BrokerListenerLifecycle:
    """Open a broker listener with a singleton lock held for its lifetime."""

    if isinstance(backlog, bool) or not isinstance(backlog, int) or backlog < 1:
        raise RuntimeSecurityError("socket listen backlog must be a positive integer")
    uid = _expected_uid(expected_uid)
    path, runtime_dir = _prepare_socket_parent(
        socket_path,
        expected_uid=uid,
        environ=environ,
    )
    lock = acquire_broker_lock(runtime_dir, expected_uid=uid)
    listener: socket.socket | None = None
    metadata: os.stat_result | None = None
    try:
        listener = _create_broker_socket_at(
            path,
            runtime_dir,
            expected_uid=uid,
            backlog=backlog,
        )
        metadata = os.lstat(path)
        _validate_socket_stat(path, metadata, expected_uid=uid)
        return BrokerListenerLifecycle(
            listener,
            path,
            lock,
            metadata,
            expected_uid=uid,
        )
    except BaseException:
        if listener is not None:
            listener.close()
        if metadata is not None:
            _unlink_created_socket(path, metadata, expected_uid=uid)
        lock.close()
        raise


def peer_credentials(connection: socket.socket) -> PeerCredentials:
    """Read Linux ``SO_PEERCRED`` from a connected Unix-domain socket."""

    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        raise PeerCredentialError("SO_PEERCRED is unavailable on this platform")
    if connection.family != socket.AF_UNIX:
        raise PeerCredentialError("peer credentials require an AF_UNIX socket")
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, option, _UCRED.size)
    except OSError as exc:
        raise PeerCredentialError(f"cannot read peer credentials: {exc}") from exc
    if len(raw) != _UCRED.size:
        raise PeerCredentialError("kernel returned malformed peer credentials")
    pid, uid, gid = _UCRED.unpack(raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise PeerCredentialError("kernel returned invalid peer credentials")
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def require_same_uid(
    connection: socket.socket,
    *,
    expected_uid: int | None = None,
) -> PeerCredentials:
    """Return peer credentials only when the peer has the expected effective UID."""

    uid = _expected_uid(expected_uid)
    credentials = peer_credentials(connection)
    if credentials.uid != uid:
        raise PeerCredentialError(
            f"Unix-socket peer UID {credentials.uid} does not match broker UID {uid}"
        )
    return credentials
