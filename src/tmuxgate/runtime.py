"""Linux Unix-socket runtime security primitives for the local broker."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import errno
import fcntl
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import struct
import time


SOCKET_DIRECTORY_NAME = "tmuxgate"
SOCKET_FILE_NAME = "broker.sock"
STATE_DIRECTORY_NAME = "tmuxgate"
SPOOL_DIRECTORY_NAME = "spool"
CONTROL_DIRECTORY_NAME = "control"
VIEWER_DIRECTORY_NAME = "viewers"
BROKER_LOCK_FILE_NAME = "broker.lock"
STATE_LOCK_FILE_NAME = "state.lock"
MCP_TOKEN_FILE_NAME = "mcp-token"
SOCKET_MODE = 0o600
LOCK_MODE = 0o600
TOKEN_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
DEFAULT_LISTEN_BACKLOG = 16
OWNER_METADATA_SCHEMA = 1
MAX_OWNER_METADATA_BYTES = 4096


class RuntimeSecurityError(RuntimeError):
    """A runtime path or local peer failed a security invariant."""


class PeerCredentialError(RuntimeSecurityError):
    """Peer credentials were unavailable, malformed, or unauthorized."""


class BrokerAlreadyRunningError(RuntimeSecurityError):
    """A verified live tmuxgate process holds a lifecycle lock."""

    def __init__(
        self,
        path: Path,
        owner: RuntimeOwnerRecord,
        lifecycle_name: str = "broker",
    ) -> None:
        self.path = path
        self.owner = owner
        super().__init__(
            "Another tmuxgate broker is already running and owns this runtime.\n"
            f"Verified owner PID {owner.pid} already holds the "
            f"{lifecycle_name} lifecycle lock {path}.\n"
            "No existing broker or SSH master was modified.\n"
            "Use the existing broker, run 'tmuxgate runtime status', or "
            "explicitly stop/replace it with 'tmuxgate runtime takeover --yes' "
            "before retrying."
        )


class RuntimeOwnershipAmbiguousError(RuntimeSecurityError):
    """Runtime ownership could not be proven safe in either direction."""


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
    mcp_token_path: Path


@dataclass(frozen=True, slots=True)
class RuntimeOwnerRecord:
    """Exact Linux process incarnation recorded beside an advisory lock."""

    instance_id: str
    pid: int
    uid: int
    boot_id: str
    process_start_ticks: int
    executable_device: int
    executable_inode: int
    started_at_ns: int

    def to_bytes(self) -> bytes:
        document = {
            "boot_id": self.boot_id,
            "executable_device": self.executable_device,
            "executable_inode": self.executable_inode,
            "instance_id": self.instance_id,
            "pid": self.pid,
            "process_start_ticks": self.process_start_ticks,
            "schema": OWNER_METADATA_SCHEMA,
            "started_at_ns": self.started_at_ns,
            "state": "active",
            "uid": self.uid,
        }
        return (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )


@dataclass(frozen=True, slots=True)
class RuntimeOwnershipStatus:
    """One race-bounded observation of a lifecycle lock."""

    state: str
    path: Path
    owner: RuntimeOwnerRecord | None
    detail: str


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
_MCP_TOKEN_PATTERN = re.compile(rb"[0-9a-f]{64}\n\Z", re.ASCII)
_INSTANCE_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)
_BOOT_ID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z",
    re.ASCII,
)
_RELEASED_OWNER_METADATA = b'{"schema":1,"state":"released"}\n'


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


def resolve_runtime_paths(
    socket_path: os.PathLike[str] | str | None = None,
    *,
    state_dir: os.PathLike[str] | str | None = None,
    environ: Mapping[str, str] | None = None,
) -> RuntimePaths:
    """Derive runtime paths without creating or changing filesystem state."""

    selected_socket = (
        default_socket_path(environ)
        if socket_path is None
        else _absolute_path(socket_path, label="broker socket path")
    )
    if selected_socket.name in {"", ".", ".."}:
        raise RuntimeSecurityError("broker socket path must name a file")
    durable_state_dir = (
        default_state_dir(environ)
        if state_dir is None
        else _absolute_path(state_dir, label="state directory")
    )
    runtime_dir = selected_socket.parent
    return RuntimePaths(
        runtime_dir=runtime_dir,
        socket_path=selected_socket,
        state_dir=durable_state_dir,
        control_dir=runtime_dir / CONTROL_DIRECTORY_NAME,
        viewer_dir=runtime_dir / VIEWER_DIRECTORY_NAME,
        spool_dir=durable_state_dir / SPOOL_DIRECTORY_NAME,
        lock_path=runtime_dir / BROKER_LOCK_FILE_NAME,
        mcp_token_path=durable_state_dir / MCP_TOKEN_FILE_NAME,
    )


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


def _validate_mcp_token_stat(
    path: Path,
    metadata: os.stat_result,
    *,
    expected_uid: int,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeSecurityError(f"MCP token is not a regular file: {path}")
    if metadata.st_uid != expected_uid:
        raise RuntimeSecurityError(
            f"MCP token is not owned by UID {expected_uid}: {path}"
        )
    mode = stat.S_IMODE(metadata.st_mode)
    if mode != TOKEN_MODE:
        raise RuntimeSecurityError(
            f"MCP token must have mode 0600, found {mode:04o}: {path}"
        )


def _read_mcp_token(
    directory_descriptor: int,
    token_path: Path,
    *,
    expected_uid: int,
) -> str | None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(
            MCP_TOKEN_FILE_NAME,
            flags,
            dir_fd=directory_descriptor,
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise RuntimeSecurityError(
            f"cannot securely open MCP token {token_path}: {exc}"
        ) from exc

    try:
        opened = os.fstat(descriptor)
        _validate_mcp_token_stat(token_path, opened, expected_uid=expected_uid)
        chunks: list[bytes] = []
        total = 0
        # Read at most one byte beyond the canonical representation so an
        # oversized or newline-appended secret is rejected without allocation.
        while total < 66:
            chunk = os.read(descriptor, 66 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        payload = b"".join(chunks)
        if _MCP_TOKEN_PATTERN.fullmatch(payload) is None:
            raise RuntimeSecurityError(
                f"MCP token must contain one canonical 64-character lowercase "
                f"hex token: {token_path}"
            )
        try:
            named = os.stat(
                MCP_TOKEN_FILE_NAME,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise RuntimeSecurityError(
                f"cannot revalidate MCP token {token_path}: {exc}"
            ) from exc
        if not _same_object(opened, named):
            raise RuntimeSecurityError(
                f"MCP token changed while opening: {token_path}"
            )
        return payload[:-1].decode("ascii")
    finally:
        os.close(descriptor)


def load_or_create_mcp_token(
    state_dir: os.PathLike[str] | str,
    *,
    expected_uid: int | None = None,
) -> str:
    """Load or atomically create the owner-only MCP bearer token.

    A complete token is fsynced under a private temporary name before an
    atomic, no-overwrite hard link publishes ``mcp-token``.  Concurrent
    starters therefore either publish the token or load the fully-written
    winner; no caller can observe a partially-written credential.
    """

    uid = _expected_uid(expected_uid)
    directory = _absolute_path(state_dir, label="state directory")
    directory_descriptor = _open_private_directory(directory, expected_uid=uid)
    token_path = directory / MCP_TOKEN_FILE_NAME
    try:
        existing = _read_mcp_token(
            directory_descriptor,
            token_path,
            expected_uid=uid,
        )
        if existing is not None:
            return existing

        token = secrets.token_hex(32)
        payload = token.encode("ascii") + b"\n"
        temporary_name = f".{MCP_TOKEN_FILE_NAME}.{secrets.token_hex(16)}.tmp"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        temporary_metadata: os.stat_result | None = None
        temporary_removed = False
        try:
            descriptor = os.open(
                temporary_name,
                flags,
                TOKEN_MODE,
                dir_fd=directory_descriptor,
            )
            os.fchmod(descriptor, TOKEN_MODE)
            temporary_metadata = os.fstat(descriptor)
            _validate_mcp_token_stat(
                directory / temporary_name,
                temporary_metadata,
                expected_uid=uid,
            )
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise RuntimeSecurityError("MCP token write made no progress")
                offset += written
            os.fsync(descriptor)

            named_temporary = os.stat(
                temporary_name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if not _same_object(temporary_metadata, named_temporary):
                raise RuntimeSecurityError(
                    f"temporary MCP token changed while writing: "
                    f"{directory / temporary_name}"
                )
            try:
                os.link(
                    temporary_name,
                    MCP_TOKEN_FILE_NAME,
                    src_dir_fd=directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                published = True
            except FileExistsError:
                published = False
            except OSError as exc:
                raise RuntimeSecurityError(
                    f"cannot atomically publish MCP token {token_path}: {exc}"
                ) from exc

            named_token = os.stat(
                MCP_TOKEN_FILE_NAME,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            if published and not _same_object(temporary_metadata, named_token):
                raise RuntimeSecurityError(
                    f"MCP token changed while publishing: {token_path}"
                )

            os.unlink(temporary_name, dir_fd=directory_descriptor)
            temporary_removed = True
            os.fsync(directory_descriptor)
            if published:
                loaded = _read_mcp_token(
                    directory_descriptor,
                    token_path,
                    expected_uid=uid,
                )
                if loaded != token:
                    raise RuntimeSecurityError(
                        f"MCP token changed after publishing: {token_path}"
                    )
                return token

            winner = _read_mcp_token(
                directory_descriptor,
                token_path,
                expected_uid=uid,
            )
            if winner is None:  # pragma: no cover - requires a hostile same-UID race
                raise RuntimeSecurityError(
                    f"MCP token disappeared during concurrent creation: {token_path}"
                )
            return winner
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if not temporary_removed and temporary_metadata is not None:
                try:
                    named = os.stat(
                        temporary_name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                    if _same_object(temporary_metadata, named):
                        os.unlink(temporary_name, dir_fd=directory_descriptor)
                except FileNotFoundError:
                    pass
    finally:
        os.close(directory_descriptor)


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
        mcp_token_path=durable_state_dir / MCP_TOKEN_FILE_NAME,
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


def _read_boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
    except (OSError, UnicodeError) as exc:
        raise RuntimeOwnershipAmbiguousError(
            f"cannot read the Linux boot identity: {exc}"
        ) from exc
    if _BOOT_ID_PATTERN.fullmatch(value) is None:
        raise RuntimeOwnershipAmbiguousError("Linux boot identity is malformed")
    return value


def _read_process_start_ticks(pid: int) -> int:
    try:
        raw = Path(f"/proc/{pid}/stat").read_bytes()
    except FileNotFoundError:
        raise ProcessLookupError(pid) from None
    except OSError as exc:
        raise RuntimeOwnershipAmbiguousError(
            f"cannot inspect process {pid} start identity: {exc}"
        ) from exc
    closing = raw.rfind(b")")
    if closing < 0:
        raise RuntimeOwnershipAmbiguousError(
            f"process {pid} start identity is malformed"
        )
    fields = raw[closing + 1 :].split()
    # The suffix starts at proc(5) field 3 (state); starttime is field 22.
    if len(fields) <= 19 or not fields[19].isdigit():
        raise RuntimeOwnershipAmbiguousError(
            f"process {pid} start identity is malformed"
        )
    return int(fields[19])


def _read_process_executable(pid: int) -> tuple[int, int]:
    try:
        metadata = os.stat(f"/proc/{pid}/exe")
    except FileNotFoundError:
        raise ProcessLookupError(pid) from None
    except OSError as exc:
        raise RuntimeOwnershipAmbiguousError(
            f"cannot inspect process {pid} executable identity: {exc}"
        ) from exc
    return metadata.st_dev, metadata.st_ino


def _current_owner_record() -> RuntimeOwnerRecord:
    pid = os.getpid()
    executable_device, executable_inode = _read_process_executable(pid)
    return RuntimeOwnerRecord(
        instance_id=secrets.token_hex(16),
        pid=pid,
        uid=os.geteuid(),
        boot_id=_read_boot_id(),
        process_start_ticks=_read_process_start_ticks(pid),
        executable_device=executable_device,
        executable_inode=executable_inode,
        started_at_ns=time.time_ns(),
    )


def _require_metadata_integer(
    document: Mapping[str, object],
    name: str,
) -> int:
    value = document.get(name)
    if type(value) is not int or value < 0:
        raise RuntimeOwnershipAmbiguousError(
            f"runtime owner metadata has an invalid {name}"
        )
    return value


def _decode_owner_metadata(
    raw: bytes,
) -> tuple[str, RuntimeOwnerRecord | None]:
    if raw == _RELEASED_OWNER_METADATA:
        return "released", None
    if not raw:
        return "legacy-empty", None
    try:
        document = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeOwnershipAmbiguousError(
            "runtime owner metadata is malformed"
        ) from exc
    expected_keys = {
        "boot_id",
        "executable_device",
        "executable_inode",
        "instance_id",
        "pid",
        "process_start_ticks",
        "schema",
        "started_at_ns",
        "state",
        "uid",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise RuntimeOwnershipAmbiguousError(
            "runtime owner metadata has an unexpected shape"
        )
    if document.get("schema") != OWNER_METADATA_SCHEMA:
        raise RuntimeOwnershipAmbiguousError(
            "runtime owner metadata has an unsupported schema"
        )
    if document.get("state") != "active":
        raise RuntimeOwnershipAmbiguousError(
            "runtime owner metadata has an invalid state"
        )
    instance_id = document.get("instance_id")
    boot_id = document.get("boot_id")
    if (
        not isinstance(instance_id, str)
        or _INSTANCE_ID_PATTERN.fullmatch(instance_id) is None
    ):
        raise RuntimeOwnershipAmbiguousError(
            "runtime owner metadata has an invalid instance ID"
        )
    if not isinstance(boot_id, str) or _BOOT_ID_PATTERN.fullmatch(boot_id) is None:
        raise RuntimeOwnershipAmbiguousError(
            "runtime owner metadata has an invalid boot ID"
        )
    return (
        "active",
        RuntimeOwnerRecord(
            instance_id=instance_id,
            pid=_require_metadata_integer(document, "pid"),
            uid=_require_metadata_integer(document, "uid"),
            boot_id=boot_id,
            process_start_ticks=_require_metadata_integer(
                document, "process_start_ticks"
            ),
            executable_device=_require_metadata_integer(
                document, "executable_device"
            ),
            executable_inode=_require_metadata_integer(
                document, "executable_inode"
            ),
            started_at_ns=_require_metadata_integer(document, "started_at_ns"),
        ),
    )


def _read_lock_metadata(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, MAX_OWNER_METADATA_BYTES + 1)
    if len(raw) > MAX_OWNER_METADATA_BYTES:
        raise RuntimeOwnershipAmbiguousError("runtime owner metadata is too large")
    return raw


def _write_lock_metadata(descriptor: int, raw: bytes) -> None:
    if not raw or len(raw) > MAX_OWNER_METADATA_BYTES:
        raise RuntimeOwnershipAmbiguousError("refusing invalid runtime owner metadata")
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise RuntimeOwnershipAmbiguousError(
                "could not completely write runtime owner metadata"
            )
        view = view[written:]
    os.fsync(descriptor)


def _owner_process_state(owner: RuntimeOwnerRecord) -> str:
    if owner.boot_id != _read_boot_id():
        return "different"
    try:
        start_ticks = _read_process_start_ticks(owner.pid)
        executable_device, executable_inode = _read_process_executable(owner.pid)
    except ProcessLookupError:
        return "absent"
    try:
        process_uid = os.stat(f"/proc/{owner.pid}").st_uid
    except FileNotFoundError:
        return "absent"
    except OSError as exc:
        raise RuntimeOwnershipAmbiguousError(
            f"cannot inspect process {owner.pid} ownership: {exc}"
        ) from exc
    if (
        process_uid != owner.uid
        or start_ticks != owner.process_start_ticks
        or executable_device != owner.executable_device
        or executable_inode != owner.executable_inode
    ):
        return "different"
    return "matching"


def _same_process_incarnation(
    left: RuntimeOwnerRecord,
    right: RuntimeOwnerRecord,
) -> bool:
    return (
        left.instance_id,
        left.pid,
        left.uid,
        left.boot_id,
        left.process_start_ticks,
        left.executable_device,
        left.executable_inode,
        left.started_at_ns,
    ) == (
        right.instance_id,
        right.pid,
        right.uid,
        right.boot_id,
        right.process_start_ticks,
        right.executable_device,
        right.executable_inode,
        right.started_at_ns,
    )


class BrokerSingletonLock:
    """An owner-only advisory lock held by a broker lifecycle owner."""

    __slots__ = (
        "path",
        "owner",
        "reconciled_owner",
        "reconciled_legacy_metadata",
        "_descriptor",
        "_closed",
    )

    def __init__(
        self,
        path: Path,
        descriptor: int,
        owner: RuntimeOwnerRecord,
        *,
        reconciled_owner: RuntimeOwnerRecord | None,
        reconciled_legacy_metadata: bool,
    ) -> None:
        self.path = path
        self.owner = owner
        self.reconciled_owner = reconciled_owner
        self.reconciled_legacy_metadata = reconciled_legacy_metadata
        self._descriptor = descriptor
        self._closed = False

    @classmethod
    def acquire(
        cls,
        directory: os.PathLike[str] | str,
        *,
        expected_uid: int | None = None,
        lock_file_name: str = BROKER_LOCK_FILE_NAME,
        owner: RuntimeOwnerRecord | None = None,
    ) -> BrokerSingletonLock:
        if lock_file_name == BROKER_LOCK_FILE_NAME:
            lifecycle_name = "broker"
        elif lock_file_name == STATE_LOCK_FILE_NAME:
            lifecycle_name = "state"
        else:
            raise ValueError("unsupported tmuxgate lifecycle lock name")
        uid = _expected_uid(expected_uid)
        parent = _absolute_path(
            directory,
            label=f"{lifecycle_name} lifecycle directory",
        )
        parent_descriptor = _open_private_directory(parent, expected_uid=uid)
        lock_path = parent / lock_file_name
        descriptor: int | None = None
        created = False
        try:
            try:
                try:
                    descriptor = os.open(
                        lock_file_name,
                        _LOCK_OPEN_FLAGS | os.O_EXCL,
                        LOCK_MODE,
                        dir_fd=parent_descriptor,
                    )
                    created = True
                except FileExistsError:
                    descriptor = os.open(
                        lock_file_name,
                        _LOCK_OPEN_FLAGS,
                        LOCK_MODE,
                        dir_fd=parent_descriptor,
                    )
            except OSError as exc:
                raise RuntimeSecurityError(
                    f"cannot securely open {lifecycle_name} lock {lock_path}: {exc}"
                ) from exc
            opened = os.fstat(descriptor)
            named = os.stat(
                lock_file_name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            _validate_lock_stat(lock_path, opened, expected_uid=uid)
            if not _same_object(opened, named):
                raise RuntimeSecurityError(
                    f"{lifecycle_name} lock changed while opening: {lock_path}"
                )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                try:
                    metadata_state, existing_owner = _decode_owner_metadata(
                        _read_lock_metadata(descriptor)
                    )
                    if metadata_state != "active" or existing_owner is None:
                        raise RuntimeOwnershipAmbiguousError(
                            f"{lifecycle_name} lock is held but its owner metadata "
                            f"is not active: {lock_path}. No runtime artifact was modified."
                        )
                    if _owner_process_state(existing_owner) == "matching":
                        raise BrokerAlreadyRunningError(
                            lock_path, existing_owner, lifecycle_name
                        ) from exc
                    raise RuntimeOwnershipAmbiguousError(
                        f"{lifecycle_name} lock is held but its process identity "
                        f"does not match the recorded owner: {lock_path}. "
                        "PID reuse or an unrelated process is possible; no runtime "
                        "artifact was modified. Run 'tmuxgate runtime status'."
                    )
                except BrokerAlreadyRunningError:
                    raise
                except RuntimeOwnershipAmbiguousError:
                    raise
            except OSError as exc:
                raise RuntimeSecurityError(
                    f"cannot acquire {lifecycle_name} singleton lock {lock_path}: {exc}"
                ) from exc
            metadata_state, existing_owner = _decode_owner_metadata(
                _read_lock_metadata(descriptor)
            )
            reconciled_owner: RuntimeOwnerRecord | None = None
            reconciled_legacy = False
            if metadata_state == "active":
                assert existing_owner is not None
                if _owner_process_state(existing_owner) == "matching":
                    raise RuntimeOwnershipAmbiguousError(
                        f"{lifecycle_name} lock is free but the recorded process is "
                        f"still live: {lock_path}. No runtime artifact was modified."
                    )
                reconciled_owner = existing_owner
            elif metadata_state == "legacy-empty" and not created:
                reconciled_legacy = True
            selected_owner = _current_owner_record() if owner is None else owner
            if selected_owner.uid != uid:
                raise RuntimeOwnershipAmbiguousError(
                    "runtime owner UID does not match the lifecycle directory owner"
                )
            _write_lock_metadata(descriptor, selected_owner.to_bytes())
            return cls(
                lock_path,
                descriptor,
                selected_owner,
                reconciled_owner=reconciled_owner,
                reconciled_legacy_metadata=reconciled_legacy,
            )
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
            _write_lock_metadata(self._descriptor, _RELEASED_OWNER_METADATA)
        finally:
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
    owner: RuntimeOwnerRecord | None = None,
) -> BrokerSingletonLock:
    """Acquire the explicit broker singleton lifecycle lock."""

    return BrokerSingletonLock.acquire(
        runtime_dir,
        expected_uid=expected_uid,
        owner=owner,
    )


def acquire_state_lock(
    state_dir: os.PathLike[str] | str,
    *,
    expected_uid: int | None = None,
    owner: RuntimeOwnerRecord | None = None,
) -> BrokerSingletonLock:
    """Acquire the durable-state lifecycle lock independently of the listener."""

    return BrokerSingletonLock.acquire(
        state_dir,
        expected_uid=expected_uid,
        lock_file_name=STATE_LOCK_FILE_NAME,
        owner=owner,
    )


class RuntimeOwnership:
    """Own the durable state and ephemeral runtime as one broker lifecycle."""

    __slots__ = ("state_lock", "runtime_lock", "_closed")

    def __init__(
        self,
        state_lock: BrokerSingletonLock,
        runtime_lock: BrokerSingletonLock,
    ) -> None:
        self.state_lock = state_lock
        self.runtime_lock = runtime_lock
        self._closed = False

    @property
    def reconciled(self) -> tuple[str, ...]:
        messages: list[str] = []
        for lock in (self.state_lock, self.runtime_lock):
            if lock.reconciled_owner is not None:
                messages.append(
                    f"reconciled stale owner metadata at {lock.path} "
                    f"from PID {lock.reconciled_owner.pid}"
                )
            elif lock.reconciled_legacy_metadata:
                messages.append(
                    f"reconciled legacy empty lifecycle metadata at {lock.path}"
                )
        return tuple(messages)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        runtime_error: BaseException | None = None
        try:
            self.runtime_lock.close()
        except BaseException as exc:
            runtime_error = exc
        try:
            self.state_lock.close()
        except BaseException:
            if runtime_error is None:
                raise
        if runtime_error is not None:
            raise runtime_error

    def __enter__(self) -> RuntimeOwnership:
        if self._closed:
            raise RuntimeSecurityError("runtime ownership is already closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


def acquire_runtime_ownership(
    paths: RuntimePaths,
    *,
    expected_uid: int | None = None,
) -> RuntimeOwnership:
    """Acquire both broker-owned trees before any component can accept work."""

    if not isinstance(paths, RuntimePaths):
        raise TypeError("paths must be RuntimePaths")
    owner = _current_owner_record()
    state_lock = acquire_state_lock(
        paths.state_dir,
        expected_uid=expected_uid,
        owner=owner,
    )
    try:
        runtime_lock = acquire_broker_lock(
            paths.runtime_dir,
            expected_uid=expected_uid,
            owner=owner,
        )
    except BaseException:
        state_lock.close()
        raise
    return RuntimeOwnership(state_lock, runtime_lock)


def inspect_lifecycle_lock(
    directory: os.PathLike[str] | str,
    *,
    lock_file_name: str,
    expected_uid: int | None = None,
) -> RuntimeOwnershipStatus:
    """Observe one lifecycle lock without changing its metadata or owner."""

    if lock_file_name not in {BROKER_LOCK_FILE_NAME, STATE_LOCK_FILE_NAME}:
        raise ValueError("unsupported tmuxgate lifecycle lock name")
    uid = _expected_uid(expected_uid)
    parent = _absolute_path(directory, label="lifecycle directory")
    try:
        parent_descriptor = _open_private_directory(parent, expected_uid=uid)
    except RuntimeSecurityError as exc:
        cause: BaseException | None = exc
        while cause is not None and not isinstance(cause, FileNotFoundError):
            cause = cause.__cause__
        if cause is None:
            raise
        return RuntimeOwnershipStatus(
            "inactive", parent / lock_file_name, None, "directory does not exist"
        )
    descriptor: int | None = None
    path = parent / lock_file_name
    try:
        try:
            descriptor = os.open(
                lock_file_name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            return RuntimeOwnershipStatus(
                "inactive", path, None, "lock file does not exist"
            )
        opened = os.fstat(descriptor)
        named = os.stat(
            lock_file_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _validate_lock_stat(path, opened, expected_uid=uid)
        if not _same_object(opened, named):
            raise RuntimeOwnershipAmbiguousError(
                f"lifecycle lock changed while inspecting it: {path}"
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            metadata_state, owner = _decode_owner_metadata(
                _read_lock_metadata(descriptor)
            )
            if metadata_state != "active" or owner is None:
                return RuntimeOwnershipStatus(
                    "ambiguous",
                    path,
                    None,
                    "lock is held but active owner metadata is unavailable",
                )
            process_state = _owner_process_state(owner)
            if process_state == "matching":
                return RuntimeOwnershipStatus(
                    "active",
                    path,
                    owner,
                    "verified live tmuxgate owner holds the lock",
                )
            return RuntimeOwnershipStatus(
                "ambiguous",
                path,
                owner,
                "lock is held but PID reuse or unrelated-process identity is possible",
            )
        metadata_state, owner = _decode_owner_metadata(_read_lock_metadata(descriptor))
        if metadata_state == "active" and owner is not None:
            return RuntimeOwnershipStatus(
                "stale",
                path,
                owner,
                "lock is free and stale owner metadata remains",
            )
        return RuntimeOwnershipStatus(
            "inactive", path, None, "lock is free and no active owner is recorded"
        )
    finally:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)
        os.close(parent_descriptor)


def inspect_runtime_ownership(paths: RuntimePaths) -> tuple[RuntimeOwnershipStatus, ...]:
    """Inspect both durable-state and ephemeral-runtime owners."""

    statuses = (
        inspect_lifecycle_lock(
            paths.state_dir,
            lock_file_name=STATE_LOCK_FILE_NAME,
        ),
        inspect_lifecycle_lock(
            paths.runtime_dir,
            lock_file_name=BROKER_LOCK_FILE_NAME,
        ),
    )
    owners = tuple(status.owner for status in statuses)
    if (
        all(status.state in {"active", "ambiguous"} for status in statuses)
        and all(owner is not None for owner in owners)
        and _same_process_incarnation(owners[0], owners[1])
        and any(status.state == "ambiguous" for status in statuses)
    ):
        # /proc may intentionally hide the broker across PID namespaces. In
        # that case, require a fresh challenge response from the same-UID Unix
        # listener and bind every lock field, including the instance nonce.
        try:
            from tmuxgate.client import get_runtime_owner

            challenge = secrets.token_hex(16)
            proof = get_runtime_owner(
                paths.socket_path,
                challenge,
                connect_timeout_seconds=1.0,
                request_send_timeout_seconds=1.0,
                response_timeout_seconds=1.0,
            )
            owner = owners[0]
            assert owner is not None
            if (
                proof.challenge == challenge
                and (
                    proof.instance_id,
                    proof.pid,
                    proof.uid,
                    proof.boot_id,
                    proof.process_start_ticks,
                    proof.executable_device,
                    proof.executable_inode,
                    proof.started_at_ns,
                ) == (
                    owner.instance_id,
                    owner.pid,
                    owner.uid,
                    owner.boot_id,
                    owner.process_start_ticks,
                    owner.executable_device,
                    owner.executable_inode,
                    owner.started_at_ns,
                )
            ):
                return tuple(
                    RuntimeOwnershipStatus(
                        "active",
                        status.path,
                        status.owner,
                        "live same-UID broker proved the exact lock lease nonce",
                    )
                    for status in statuses
                )
        except BaseException:
            pass
    return statuses


def request_runtime_owner_shutdown(
    paths: RuntimePaths,
    *,
    timeout_seconds: float = 10.0,
    poll_interval_seconds: float = 0.05,
) -> RuntimeOwnerRecord:
    """Explicitly request SIGTERM from one exactly verified broker owner.

    This never sends SIGKILL and never removes a lock, socket, or metadata
    file.  The caller must start a replacement only after both kernel locks
    have been observed free.
    """

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or isinstance(poll_interval_seconds, bool)
        or not isinstance(poll_interval_seconds, (int, float))
        or not math.isfinite(poll_interval_seconds)
        or poll_interval_seconds <= 0
    ):
        raise ValueError("takeover timeouts must be positive finite numbers")
    statuses = inspect_runtime_ownership(paths)
    if any(item.state == "ambiguous" for item in statuses):
        raise RuntimeOwnershipAmbiguousError(
            "runtime ownership is ambiguous; no process was signalled"
        )
    active = [item.owner for item in statuses if item.state == "active"]
    if len(active) != len(statuses) or any(item is None for item in active):
        raise RuntimeOwnershipAmbiguousError(
            "a takeover requires the same verified live owner on both lifecycle locks; "
            "no process was signalled"
        )
    owner = active[0]
    assert owner is not None
    if not all(
        item is not None and _same_process_incarnation(owner, item)
        for item in active[1:]
    ):
        raise RuntimeOwnershipAmbiguousError(
            "lifecycle locks name different process incarnations; no process was signalled"
        )
    if _owner_process_state(owner) != "matching":
        raise RuntimeOwnershipAmbiguousError(
            "runtime owner changed before takeover; no process was signalled"
        )
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if pidfd_open is None or pidfd_send_signal is None:
        raise RuntimeOwnershipAmbiguousError(
            "safe pidfd takeover is unavailable; no process was signalled"
        )
    try:
        pidfd = pidfd_open(owner.pid, 0)
    except OSError as exc:
        raise RuntimeOwnershipAmbiguousError(
            f"could not pin the verified owner process: {exc}; no signal was sent"
        ) from exc
    try:
        if _owner_process_state(owner) != "matching":
            raise RuntimeOwnershipAmbiguousError(
                "runtime owner changed while pinning it; no signal was sent"
            )
        pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
    finally:
        os.close(pidfd)

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        current = inspect_runtime_ownership(paths)
        if all(item.state in {"inactive", "stale"} for item in current):
            return owner
        if any(item.state == "ambiguous" for item in current):
            raise RuntimeOwnershipAmbiguousError(
                "runtime ownership became ambiguous after SIGTERM; no artifact was removed"
            )
        time.sleep(min(poll_interval_seconds, max(0.0, deadline - time.monotonic())))
    raise RuntimeOwnershipAmbiguousError(
        "verified broker did not release runtime ownership after SIGTERM; "
        "it was not killed and no runtime artifact was removed"
    )


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
        "_owns_lock",
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
        owns_lock: bool = True,
    ) -> None:
        self.listener = listener
        self.socket_path = socket_path
        self._lock = lock
        self._bound_metadata = bound_metadata
        self._expected_uid = expected_uid
        self._owns_lock = owns_lock
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
            if self._owns_lock:
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
    existing_lock: BrokerSingletonLock | None = None,
) -> BrokerListenerLifecycle:
    """Open a broker listener with a runtime-path lock held for its lifetime."""

    if isinstance(backlog, bool) or not isinstance(backlog, int) or backlog < 1:
        raise RuntimeSecurityError("socket listen backlog must be a positive integer")
    uid = _expected_uid(expected_uid)
    path, runtime_dir = _prepare_socket_parent(
        socket_path,
        expected_uid=uid,
        environ=environ,
    )
    if existing_lock is None:
        lock = acquire_broker_lock(runtime_dir, expected_uid=uid)
        owns_lock = True
    else:
        lock = existing_lock
        owns_lock = False
        if lock.closed or lock.path != runtime_dir / BROKER_LOCK_FILE_NAME:
            raise RuntimeSecurityError(
                "existing broker lock does not own the selected runtime directory"
            )
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
            owns_lock=owns_lock,
        )
    except BaseException:
        if listener is not None:
            listener.close()
        if metadata is not None:
            _unlink_created_socket(path, metadata, expected_uid=uid)
        if owns_lock:
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
