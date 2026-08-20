"""Owner-only configuration serialization and atomic publication helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
import errno
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import time
from types import MappingProxyType

from tmuxgate.config import (
    AppConfig,
    ConfigError,
    Machine,
    load_config,
    load_config_snapshot,
)
from tmuxgate.models import ValidationError, validate_alias


def _quote(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def _array(values: object) -> str:
    return "[" + ", ".join(_quote(value) for value in values) + "]"


def serialize_config(config: AppConfig) -> bytes:
    """Serialize the complete supported v2 settings schema as canonical TOML."""

    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    broker = config.broker
    mcp = config.mcp
    limits = config.limits
    lines = [
        "# Managed by tmuxgate configuration commands.",
        "version = 2",
        "",
        "[broker]",
        f"max_active_remote_commands = {broker.max_active_remote_commands}",
        f"max_open_ssh_masters = {broker.max_open_ssh_masters}",
        f"max_pending_requests = {broker.max_pending_requests}",
        f"queue_policy = {_quote(broker.queue_policy)}",
        f"ssh_master_idle_timeout_seconds = {broker.ssh_master_idle_timeout_seconds}",
        f"reboot_recovery_timeout_seconds = {broker.reboot_recovery_timeout_seconds}",
        f"approval_mode = {_quote(broker.approval_mode)}",
        "",
        "[mcp]",
        f"host = {_quote(mcp.host)}",
        f"port = {mcp.port}",
        "",
        "[limits]",
        f"max_stdout_bytes = {limits.max_stdout_bytes}",
        f"max_stderr_bytes = {limits.max_stderr_bytes}",
        f"max_total_result_bytes = {limits.max_total_result_bytes}",
        f"max_local_collection_bytes = {limits.max_local_collection_bytes}",
        f"max_remote_capture_bytes = {limits.max_remote_capture_bytes}",
        (
            "max_aggregate_collection_bytes = "
            f"{limits.max_aggregate_collection_bytes}"
        ),
    ]
    if config.home is not None:
        home = config.home
        lines.extend(
            [
                "",
                "[contexts.home]",
                f"gateway = {_quote(home.gateway)}",
                f"source_cidr = {_quote(home.source_cidr)}",
                "fingerprints = [",
            ]
        )
        for fingerprint in home.fingerprints:
            fields = (
                f"id = {_quote(fingerprint.id)}",
                f"link_type = {_quote(fingerprint.link_type)}",
                f"gateway_macs = {_array(sorted(fingerprint.gateway_macs))}",
                "connection_uuids = "
                f"{_array(sorted(fingerprint.connection_uuids, key=str))}",
                f"bssids = {_array(sorted(fingerprint.bssids))}",
            )
            # TOML inline tables must remain on one physical line.
            lines.append("  { " + ", ".join(fields) + " },")
        lines.append("]")
    if config.wireguard is not None:
        wireguard = config.wireguard
        lines.extend(
            [
                "",
                "[contexts.wireguard]",
                f"local_addresses = {_array(wireguard.local_addresses)}",
                f"remote_cidrs = {_array(wireguard.remote_cidrs)}",
            ]
        )
    for machine in config.machines.values():
        lines.extend(
            [
                "",
                f"[machines.{machine.name}]",
                f"description = {_quote(machine.description)}",
                f"enabled = {'true' if machine.enabled else 'false'}",
                f"ssh_profile = {_quote(machine.ssh_profile)}",
                f"user = {_quote(machine.user)}",
                f"host_key_alias = {_quote(machine.host_key_alias)}",
                f"connect_timeout_seconds = {machine.connect_timeout_seconds}",
            ]
        )
        for endpoint in machine.endpoints:
            lines.extend(
                [
                    "",
                    f"[[machines.{machine.name}.endpoints]]",
                    f"id = {_quote(endpoint.id)}",
                    f"address = {_quote(endpoint.address)}",
                    f"port = {endpoint.port}",
                    f"priority = {endpoint.priority}",
                    f"requires = {_quote(endpoint.required_context)}",
                ]
            )
    return ("\n".join(lines) + "\n").encode("ascii")


class ConfigWriteConflictError(ConfigError):
    """Configuration changed after a caller captured its update preimage."""


@contextmanager
def _config_write_lock(path: Path, *, timeout_seconds: float = 5.0) -> Iterator[None]:
    """Serialize tmuxgate writers through a validated owner-only lock file."""

    lock_path = path.parent / f".{path.name}.lock"
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ConfigError("configuration write lock is not a private regular file")
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    raise ConfigError("configuration is busy; try again") from exc
                time.sleep(0.01)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _publish_bytes_unlocked(path: Path, content: bytes) -> None:
    """Fsync and publish exact validated bytes while the caller holds the lock."""

    if not isinstance(content, bytes):
        raise TypeError("configuration content must be bytes")
    temporary = path.parent / f".config.{secrets.token_hex(16)}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(temporary, flags, 0o600)
    published = False
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("configuration write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        load_config(temporary)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
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


def _publish_config_unlocked(path: Path, config: AppConfig) -> None:
    """Publish after the caller has validated the path and acquired its lock."""

    _publish_bytes_unlocked(path, serialize_config(config))


def publish_config(
    path: Path,
    config: AppConfig,
    *,
    expected_config: AppConfig | None = None,
) -> None:
    """Validate, compare if requested, and atomically publish private config."""

    path = path.expanduser()
    if not path.is_absolute():
        raise ConfigError("configuration path must be absolute")
    # Prove the existing path and private parent before creating the sibling lock.
    load_config(path)
    with _config_write_lock(path):
        current = load_config(path)
        if expected_config is not None and current != expected_config:
            raise ConfigWriteConflictError(
                "configuration changed while the update was being prepared"
            )
        _publish_config_unlocked(path, config)


def publish_edited_config(
    path: Path,
    temporary: Path,
    *,
    expected_content: bytes,
) -> AppConfig:
    """CAS-publish a validated private edit while preserving its exact bytes."""

    path = path.expanduser()
    temporary = temporary.expanduser()
    if not path.is_absolute() or not temporary.is_absolute():
        raise ConfigError("configuration paths must be absolute")
    if temporary.parent != path.parent or temporary == path:
        raise ConfigError("edited configuration must be a sibling temporary")
    if not isinstance(expected_content, bytes):
        raise TypeError("expected_content must be bytes")
    load_config_snapshot(path)
    with _config_write_lock(path):
        _current, current_content = load_config_snapshot(path)
        if current_content != expected_content:
            raise ConfigWriteConflictError(
                "configuration changed while the editor was open"
            )
        # Reopen the editor output securely while holding the writer lock, then
        # copy those exact validated bytes into our own O_EXCL temporary.  The
        # owned copy is fsynced before replacement, so Nano's write durability
        # and a path swap after validation cannot affect the published file.
        edited, edited_content = load_config_snapshot(temporary)
        _publish_bytes_unlocked(path, edited_content)
    return edited


def set_machine_enabled(
    path: Path,
    name: str,
    *,
    enabled: bool,
    expected_machine: Machine | None = None,
) -> tuple[AppConfig, bool]:
    """Lock, reload, and set one machine flag while preserving current settings."""

    if type(enabled) is not bool:
        raise TypeError("enabled must be a boolean")
    if expected_machine is not None and not isinstance(expected_machine, Machine):
        raise TypeError("expected_machine must be a Machine")
    try:
        machine_name = validate_alias(name, field_name="machine name")
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
    config_path = Path(path).expanduser()
    if not config_path.is_absolute():
        raise ConfigError("configuration path must be absolute")
    load_config(config_path)
    with _config_write_lock(config_path):
        config = load_config(config_path)
        try:
            machine = config.machines[machine_name]
        except KeyError as exc:
            raise ConfigError(f"unknown configured machine: {machine_name}") from exc
        if machine.enabled is enabled:
            return config, False
        if expected_machine is not None and machine != expected_machine:
            raise ConfigWriteConflictError(
                f"machine settings changed before {machine_name} could be updated"
            )
        machines = dict(config.machines)
        machines[machine_name] = replace(machine, enabled=enabled)
        updated = replace(config, machines=MappingProxyType(machines))
        _publish_config_unlocked(config_path, updated)
        return updated, True


def set_approval_mode(
    path: Path,
    approval_mode: str,
) -> tuple[AppConfig, bool]:
    """Persist the dashboard's automatic/manual approval switch atomically."""

    if approval_mode not in {"always", "disabled"}:
        raise ConfigError("broker.approval_mode must be 'always' or 'disabled'")
    config_path = Path(path).expanduser()
    if not config_path.is_absolute():
        raise ConfigError("configuration path must be absolute")
    load_config(config_path)
    with _config_write_lock(config_path):
        config = load_config(config_path)
        if config.broker.approval_mode == approval_mode:
            return config, False
        updated = replace(
            config,
            broker=replace(config.broker, approval_mode=approval_mode),
        )
        _publish_config_unlocked(config_path, updated)
        return updated, True
