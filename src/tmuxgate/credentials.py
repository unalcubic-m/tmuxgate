"""Owner-only reusable sudo credentials for automatic interactive requests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import stat
import threading

from tmuxgate.models import ValidationError, validate_alias


CREDENTIAL_FILE_NAME = "sudo-credentials.json"
CREDENTIAL_FILE_MODE = 0o600
MAX_PASSWORD_CHARACTERS = 4096
MAX_CREDENTIAL_FILE_BYTES = 1024 * 1024


class CredentialError(RuntimeError):
    """A reusable credential could not be stored or loaded safely."""


def _validated_password(password: object) -> str:
    if not isinstance(password, str) or not password:
        raise CredentialError("sudo password must not be empty")
    if len(password) > MAX_PASSWORD_CHARACTERS:
        raise CredentialError(
            f"sudo password exceeds {MAX_PASSWORD_CHARACTERS} characters"
        )
    if any(character in password for character in ("\x00", "\r", "\n")):
        raise CredentialError("sudo password must be one line without NUL bytes")
    return password


def _validated_machine(machine_name: object) -> str:
    try:
        return validate_alias(machine_name, field_name="machine name")
    except (TypeError, ValidationError) as exc:
        raise CredentialError(str(exc)) from exc


class SudoCredentialStore:
    """Persist one UTF-8 sudo password per logical machine in a 0600 file."""

    def __init__(self, state_dir: Path | str) -> None:
        self.state_dir = Path(state_dir)
        if not self.state_dir.is_absolute():
            raise CredentialError("credential state directory must be absolute")
        self.path = self.state_dir / CREDENTIAL_FILE_NAME
        self._lock = threading.RLock()
        self._validate_parent()
        self._load()

    def _validate_parent(self) -> None:
        try:
            metadata = os.stat(self.state_dir, follow_symlinks=False)
        except OSError as exc:
            raise CredentialError(
                f"credential state directory is unavailable: {self.state_dir}"
            ) from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise CredentialError(
                "credential state directory must be owner-only mode 0700"
            )

    def _load(self) -> dict[str, str]:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise CredentialError(
                f"cannot securely open sudo credential store: {self.path}"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != CREDENTIAL_FILE_MODE
                or metadata.st_size > MAX_CREDENTIAL_FILE_BYTES
            ):
                raise CredentialError(
                    "sudo credential store must be an owner-only 0600 regular file"
                )
            payload = bytearray()
            while len(payload) <= MAX_CREDENTIAL_FILE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, MAX_CREDENTIAL_FILE_BYTES + 1 - len(payload)),
                )
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > MAX_CREDENTIAL_FILE_BYTES:
                raise CredentialError("sudo credential store is too large")
        finally:
            os.close(descriptor)
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CredentialError("sudo credential store is malformed") from exc
        if not isinstance(document, dict) or set(document) != {"version", "passwords"}:
            raise CredentialError("sudo credential store has an unsupported schema")
        if document["version"] != 1 or not isinstance(document["passwords"], dict):
            raise CredentialError("sudo credential store has an unsupported schema")
        passwords: dict[str, str] = {}
        for raw_name, raw_password in document["passwords"].items():
            name = _validated_machine(raw_name)
            passwords[name] = _validated_password(raw_password)
        return passwords

    def _publish(self, passwords: dict[str, str]) -> None:
        self._validate_parent()
        document = {"version": 1, "passwords": passwords}
        content = (
            json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        temporary = self.state_dir / f".{CREDENTIAL_FILE_NAME}.{secrets.token_hex(16)}.tmp"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary, flags, CREDENTIAL_FILE_MODE)
        published = False
        try:
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise CredentialError("sudo credential write made no progress")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, self.path)
            directory = os.open(
                self.state_dir,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            published = True
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not published:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass

    def has_password(self, machine_name: str) -> bool:
        name = _validated_machine(machine_name)
        with self._lock:
            return name in self._load()

    def password_for(self, machine_name: str) -> bytes | None:
        name = _validated_machine(machine_name)
        with self._lock:
            password = self._load().get(name)
        return None if password is None else password.encode("utf-8")

    def set_password(self, machine_name: str, password: str) -> None:
        name = _validated_machine(machine_name)
        secret = _validated_password(password)
        with self._lock:
            passwords = self._load()
            passwords[name] = secret
            self._publish(passwords)

    def remove_password(self, machine_name: str) -> bool:
        name = _validated_machine(machine_name)
        with self._lock:
            passwords = self._load()
            if name not in passwords:
                return False
            del passwords[name]
            self._publish(passwords)
            return True


__all__ = [
    "CREDENTIAL_FILE_NAME",
    "CredentialError",
    "SudoCredentialStore",
]
