"""Atomic owner-only canonical result spool.

A result becomes visible only after both raw streams and a checksummed manifest
have been fsynced inside a private temporary directory and that directory is
renamed to the validated request ID.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from typing import Mapping

from tmuxgate.models import validate_request_id
from tmuxgate.result import MAX_RESULT_STREAM_BYTES
from tmuxgate.runtime import PRIVATE_DIRECTORY_MODE, ensure_private_directory


SPOOL_DIRECTORY_NAME = "results"
SPOOL_FORMAT_VERSION = 1
SPOOL_FILE_MODE = 0o600
MAX_MANIFEST_BYTES = 64 * 1024

STDOUT_NAME = "stdout.raw"
STDERR_NAME = "stderr.raw"
MANIFEST_NAME = "manifest.json"
_EXPECTED_ENTRIES = frozenset({STDOUT_NAME, STDERR_NAME, MANIFEST_NAME})
_TEMP_RE = re.compile(r"\.([0-9a-f]{32})\.([0-9a-f]{32})\.tmp\Z", re.ASCII)


class SpoolError(RuntimeError):
    """A result could not be stored or proven exact."""


class SpoolCorruptionError(SpoolError):
    """Published spool evidence is missing, unsafe, or inconsistent."""


class SpoolConflictError(SpoolError):
    """A different result already exists for this request."""


def _canonical_json(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _payload_sha256(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class SpoolResult:
    request_id: str
    stdout: bytes
    stderr: bytes
    exit_status: int
    manifest_payload_sha256: str

    def __post_init__(self) -> None:
        validate_request_id(self.request_id)
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise ValueError("spooled streams must be bytes")
        if len(self.stdout) > MAX_RESULT_STREAM_BYTES or len(self.stderr) > MAX_RESULT_STREAM_BYTES:
            raise ValueError("spooled stream exceeds the configured limit")
        if type(self.exit_status) is not int or not 0 <= self.exit_status <= 255:
            raise ValueError("spooled exit status must be from 0 to 255")
        if re.fullmatch(r"[0-9a-f]{64}", self.manifest_payload_sha256) is None:
            raise ValueError("manifest payload digest is invalid")


class ResultSpool:
    """Store and load immutable per-request result directories."""

    def __init__(
        self,
        state_dir: os.PathLike[str] | str,
        *,
        expected_uid: int | None = None,
    ) -> None:
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        if type(self.expected_uid) is not int or self.expected_uid < 0:
            raise SpoolError("expected UID must be a non-negative integer")
        root = ensure_private_directory(state_dir, expected_uid=self.expected_uid)
        self.path = ensure_private_directory(
            root / SPOOL_DIRECTORY_NAME,
            expected_uid=self.expected_uid,
        )
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            self._root_fd = os.open(self.path, flags)
        except OSError as exc:
            raise SpoolError("cannot open result spool directory") from exc
        self._validate_directory_fd(self._root_fd, "result spool")
        self._lock = threading.Lock()

    def close(self) -> None:
        descriptor = getattr(self, "_root_fd", -1)
        if descriptor >= 0:
            os.close(descriptor)
            self._root_fd = -1

    def __enter__(self) -> "ResultSpool":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def _validate_directory_fd(self, descriptor: int, label: str) -> None:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self.expected_uid
            or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
        ):
            raise SpoolCorruptionError(f"{label} is not private and owner-only")

    def _open_result_directory(self, request_id: str) -> int:
        request_id = validate_request_id(request_id)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(request_id, flags, dir_fd=self._root_fd)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise SpoolCorruptionError("cannot safely open result directory") from exc
        try:
            self._validate_directory_fd(descriptor, "result directory")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _write_file(self, directory_fd: int, name: str, content: bytes) -> None:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(name, flags, SPOOL_FILE_MODE, dir_fd=directory_fd)
        try:
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise SpoolError("result spool write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _read_file(self, directory_fd: int, name: str, maximum: int) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=directory_fd)
        except OSError as exc:
            raise SpoolCorruptionError(f"cannot safely open {name}") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.expected_uid
                or stat.S_IMODE(metadata.st_mode) != SPOOL_FILE_MODE
                or metadata.st_size > maximum
            ):
                raise SpoolCorruptionError(f"unsafe result file metadata: {name}")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) > maximum:
                raise SpoolCorruptionError(f"result file exceeds limit: {name}")
            return content
        finally:
            os.close(descriptor)

    @staticmethod
    def _manifest_payload(
        request_id: str,
        stdout: bytes,
        stderr: bytes,
        exit_status: int,
    ) -> dict[str, object]:
        return {
            "exit_status": exit_status,
            "request_id": request_id,
            "spool_version": SPOOL_FORMAT_VERSION,
            "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "stderr_size": len(stderr),
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            "stdout_size": len(stdout),
        }

    @classmethod
    def _manifest_bytes(
        cls,
        request_id: str,
        stdout: bytes,
        stderr: bytes,
        exit_status: int,
    ) -> tuple[bytes, str]:
        payload = cls._manifest_payload(request_id, stdout, stderr, exit_status)
        digest = _payload_sha256(payload)
        envelope = {"payload": payload, "sha256": digest}
        return _canonical_json(envelope) + b"\n", digest

    def _cleanup_private_temp(self, name: str) -> None:
        if _TEMP_RE.fullmatch(name) is None:
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(name, flags, dir_fd=self._root_fd)
        except OSError:
            return
        try:
            try:
                self._validate_directory_fd(descriptor, "temporary result directory")
            except SpoolError:
                return
            entries = set(os.listdir(descriptor))
            if not entries.issubset(_EXPECTED_ENTRIES):
                return
            for entry in entries:
                try:
                    metadata = os.stat(entry, dir_fd=descriptor, follow_symlinks=False)
                except OSError:
                    return
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != self.expected_uid
                    or stat.S_IMODE(metadata.st_mode) != SPOOL_FILE_MODE
                ):
                    return
            for entry in entries:
                os.unlink(entry, dir_fd=descriptor)
        finally:
            os.close(descriptor)
        try:
            os.rmdir(name, dir_fd=self._root_fd)
            os.fsync(self._root_fd)
        except OSError:
            pass

    def store(
        self,
        request_id: str,
        stdout: bytes,
        stderr: bytes,
        exit_status: int,
    ) -> SpoolResult:
        request_id = validate_request_id(request_id)
        if not isinstance(stdout, bytes) or not isinstance(stderr, bytes):
            raise ValueError("result streams must be bytes")
        if len(stdout) > MAX_RESULT_STREAM_BYTES or len(stderr) > MAX_RESULT_STREAM_BYTES:
            raise ValueError("result stream exceeds the configured limit")
        if type(exit_status) is not int or not 0 <= exit_status <= 255:
            raise ValueError("exit status must be from 0 to 255")
        manifest, digest = self._manifest_bytes(request_id, stdout, stderr, exit_status)
        result = SpoolResult(request_id, stdout, stderr, exit_status, digest)

        with self._lock:
            try:
                existing = self.load(request_id)
            except FileNotFoundError:
                pass
            else:
                if existing == result:
                    return existing
                raise SpoolConflictError("a different canonical result already exists")

            temporary = f".{request_id}.{secrets.token_hex(16)}.tmp"
            os.mkdir(temporary, PRIVATE_DIRECTORY_MODE, dir_fd=self._root_fd)
            directory_fd = -1
            published = False
            try:
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                directory_fd = os.open(temporary, flags, dir_fd=self._root_fd)
                self._validate_directory_fd(directory_fd, "temporary result directory")
                self._write_file(directory_fd, STDOUT_NAME, stdout)
                self._write_file(directory_fd, STDERR_NAME, stderr)
                self._write_file(directory_fd, MANIFEST_NAME, manifest)
                os.fsync(directory_fd)
                os.rename(
                    temporary,
                    request_id,
                    src_dir_fd=self._root_fd,
                    dst_dir_fd=self._root_fd,
                )
                published = True
                os.fsync(self._root_fd)
            finally:
                if directory_fd >= 0:
                    os.close(directory_fd)
                if not published:
                    self._cleanup_private_temp(temporary)
        return result

    def load(self, request_id: str) -> SpoolResult:
        request_id = validate_request_id(request_id)
        directory_fd = self._open_result_directory(request_id)
        try:
            entries = set(os.listdir(directory_fd))
            if entries != _EXPECTED_ENTRIES:
                raise SpoolCorruptionError("result directory entries are not exact")
            manifest_content = self._read_file(
                directory_fd,
                MANIFEST_NAME,
                MAX_MANIFEST_BYTES,
            )
            stdout = self._read_file(
                directory_fd,
                STDOUT_NAME,
                MAX_RESULT_STREAM_BYTES,
            )
            stderr = self._read_file(
                directory_fd,
                STDERR_NAME,
                MAX_RESULT_STREAM_BYTES,
            )
        finally:
            os.close(directory_fd)

        def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
            document: dict[str, object] = {}
            for key, value in pairs:
                if key in document:
                    raise SpoolCorruptionError(f"duplicate manifest key: {key}")
                document[key] = value
            return document

        try:
            envelope = json.loads(
                manifest_content.decode("ascii"),
                object_pairs_hook=no_duplicates,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    SpoolCorruptionError(f"nonstandard manifest constant: {value}")
                ),
            )
        except SpoolCorruptionError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SpoolCorruptionError("result manifest is not valid ASCII JSON") from exc
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "sha256"}:
            raise SpoolCorruptionError("result manifest envelope is invalid")
        payload = envelope["payload"]
        digest = envelope["sha256"]
        expected_fields = {
            "exit_status",
            "request_id",
            "spool_version",
            "stderr_sha256",
            "stderr_size",
            "stdout_sha256",
            "stdout_size",
        }
        if not isinstance(payload, dict) or set(payload) != expected_fields:
            raise SpoolCorruptionError("result manifest payload is invalid")
        if not isinstance(digest, str) or _payload_sha256(payload) != digest:
            raise SpoolCorruptionError("result manifest checksum does not match")
        if manifest_content != _canonical_json(envelope) + b"\n":
            raise SpoolCorruptionError("result manifest is not canonical")
        if payload["spool_version"] != SPOOL_FORMAT_VERSION:
            raise SpoolCorruptionError("result spool version is unsupported")
        if payload["request_id"] != request_id:
            raise SpoolCorruptionError("manifest request ID does not match its directory")
        exit_status = payload["exit_status"]
        if type(exit_status) is not int or not 0 <= exit_status <= 255:
            raise SpoolCorruptionError("manifest exit status is invalid")
        expected = self._manifest_payload(request_id, stdout, stderr, exit_status)
        if payload != expected:
            raise SpoolCorruptionError("raw result streams do not match the manifest")
        return SpoolResult(request_id, stdout, stderr, exit_status, digest)
