"""Owner-only configuration serialization and atomic publication helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets

from tmuxgate.config import AppConfig, ConfigError, load_config


def _quote(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)


def _array(values: object) -> str:
    return "[" + ", ".join(_quote(value) for value in values) + "]"


def serialize_config(config: AppConfig) -> bytes:
    """Serialize the complete supported v1 settings schema as canonical TOML."""

    if not isinstance(config, AppConfig):
        raise TypeError("config must be an AppConfig")
    broker = config.broker
    lines = [
        "# Managed by tmuxgate configuration commands.",
        "version = 1",
        "",
        "[broker]",
        f"max_active_remote_commands = {broker.max_active_remote_commands}",
        f"max_open_ssh_masters = {broker.max_open_ssh_masters}",
        f"max_pending_requests = {broker.max_pending_requests}",
        f"queue_policy = {_quote(broker.queue_policy)}",
        f"ssh_master_idle_timeout_seconds = {broker.ssh_master_idle_timeout_seconds}",
        f"approval_mode = {_quote(broker.approval_mode)}",
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


def publish_config(path: Path, config: AppConfig) -> None:
    """Validate and atomically publish an owner-only complete config."""

    path = path.expanduser()
    if not path.is_absolute():
        raise ConfigError("configuration path must be absolute")
    # Prove the existing path and private parent before replacing anything.
    load_config(path)
    content = serialize_config(config)
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
