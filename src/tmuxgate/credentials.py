"""Owner-only reusable sudo credentials for automatic interactive requests."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
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
MAX_SUDO_PROMPT_BYTES = 1024
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


def _validated_prompt(prompt: object) -> bytes | None:
    if prompt is None:
        return None
    if not isinstance(prompt, bytes) or not prompt:
        raise CredentialError("sudo prompt must be non-empty bytes")
    if len(prompt) > MAX_SUDO_PROMPT_BYTES:
        raise CredentialError(
            f"sudo prompt exceeds {MAX_SUDO_PROMPT_BYTES} bytes"
        )
    if any(character in prompt for character in (b"\x00", b"\r", b"\n")):
        raise CredentialError("sudo prompt must be one line without NUL bytes")
    return prompt


@dataclass(frozen=True, slots=True)
class _StoredCredential:
    password: str
    prompt: bytes | None = None


class SudoCredentialStore:
    """Persist one password and learned exact prompt per logical machine."""

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

    def _load(self) -> dict[str, _StoredCredential]:
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
        if not isinstance(document, dict):
            raise CredentialError("sudo credential store has an unsupported schema")
        if set(document) == {"version", "passwords"} and document["version"] == 1:
            if not isinstance(document["passwords"], dict):
                raise CredentialError("sudo credential store has an unsupported schema")
            credentials: dict[str, _StoredCredential] = {}
            for raw_name, raw_password in document["passwords"].items():
                name = _validated_machine(raw_name)
                credentials[name] = _StoredCredential(
                    _validated_password(raw_password)
                )
            return credentials
        if set(document) != {"version", "credentials"} or document["version"] != 2:
            raise CredentialError("sudo credential store has an unsupported schema")
        if not isinstance(document["credentials"], dict):
            raise CredentialError("sudo credential store has an unsupported schema")
        credentials = {}
        for raw_name, raw_credential in document["credentials"].items():
            name = _validated_machine(raw_name)
            if not isinstance(raw_credential, dict) or set(raw_credential) != {
                "password",
                "prompt_base64",
            }:
                raise CredentialError("sudo credential store has an unsupported schema")
            raw_prompt = raw_credential["prompt_base64"]
            if raw_prompt is None:
                prompt = None
            elif isinstance(raw_prompt, str):
                try:
                    prompt = base64.b64decode(raw_prompt, validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise CredentialError("stored sudo prompt is malformed") from exc
            else:
                raise CredentialError("stored sudo prompt is malformed")
            credentials[name] = _StoredCredential(
                _validated_password(raw_credential["password"]),
                _validated_prompt(prompt),
            )
        return credentials

    def _publish(self, credentials: dict[str, _StoredCredential]) -> None:
        self._validate_parent()
        document = {
            "version": 2,
            "credentials": {
                name: {
                    "password": credential.password,
                    "prompt_base64": (
                        None
                        if credential.prompt is None
                        else base64.b64encode(credential.prompt).decode("ascii")
                    ),
                }
                for name, credential in credentials.items()
            },
        }
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
            credential = self._load().get(name)
        return None if credential is None else credential.password.encode("utf-8")

    def prompt_for(self, machine_name: str) -> bytes | None:
        name = _validated_machine(machine_name)
        with self._lock:
            credential = self._load().get(name)
        return None if credential is None else credential.prompt

    def set_password(self, machine_name: str, password: str) -> None:
        name = _validated_machine(machine_name)
        secret = _validated_password(password)
        with self._lock:
            credentials = self._load()
            previous = credentials.get(name)
            credentials[name] = _StoredCredential(
                secret,
                None if previous is None else previous.prompt,
            )
            self._publish(credentials)

    def set_credential(
        self,
        machine_name: str,
        password: str,
        prompt: bytes,
    ) -> None:
        name = _validated_machine(machine_name)
        secret = _validated_password(password)
        exact_prompt = _validated_prompt(prompt)
        assert exact_prompt is not None
        with self._lock:
            credentials = self._load()
            credentials[name] = _StoredCredential(secret, exact_prompt)
            self._publish(credentials)

    def set_prompt(self, machine_name: str, prompt: bytes) -> bytes | None:
        """Bind an exact learned prompt to an existing password atomically."""

        name = _validated_machine(machine_name)
        exact_prompt = _validated_prompt(prompt)
        assert exact_prompt is not None
        with self._lock:
            credentials = self._load()
            previous = credentials.get(name)
            if previous is None:
                return None
            credentials[name] = _StoredCredential(previous.password, exact_prompt)
            self._publish(credentials)
            return previous.password.encode("utf-8")

    def remove_password(self, machine_name: str) -> bool:
        name = _validated_machine(machine_name)
        with self._lock:
            credentials = self._load()
            if name not in credentials:
                return False
            del credentials[name]
            self._publish(credentials)
            return True


__all__ = [
    "CREDENTIAL_FILE_NAME",
    "CredentialError",
    "SudoCredentialStore",
]
