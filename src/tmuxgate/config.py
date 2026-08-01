"""Strict, owner-controlled TOML configuration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import stat
import tomllib
from types import MappingProxyType
import uuid
from typing import Any

from tmuxgate.models import ValidationError, validate_alias


_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z", re.ASCII)
_USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}\Z", re.ASCII)
MCP_LOOPBACK_HOST = "127.0.0.1"
MCP_DEFAULT_PORT = 8765


class ConfigError(ValueError):
    """Configuration is unsafe, malformed, or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class BrokerConfig:
    max_active_remote_commands: int = 3
    max_open_ssh_masters: int = 3
    max_pending_requests: int = 16
    queue_policy: str = "fifo"
    ssh_master_idle_timeout_seconds: int = 600
    approval_mode: str = "disabled"

    def __post_init__(self) -> None:
        values = (
            ("max_active_remote_commands", self.max_active_remote_commands, 1, 3),
            ("max_open_ssh_masters", self.max_open_ssh_masters, 1, 3),
            ("max_pending_requests", self.max_pending_requests, 1, 64),
            (
                "ssh_master_idle_timeout_seconds",
                self.ssh_master_idle_timeout_seconds,
                1,
                86400,
            ),
        )
        for name, value, minimum, maximum in values:
            if type(value) is not int or not minimum <= value <= maximum:
                raise ConfigError(f"broker.{name} must be between {minimum} and {maximum}")
        if self.queue_policy != "fifo":
            raise ConfigError("broker.queue_policy must be 'fifo'")
        if self.approval_mode not in {"always", "disabled"}:
            raise ConfigError("broker.approval_mode must be 'always' or 'disabled'")


@dataclass(frozen=True, slots=True)
class McpConfig:
    host: str = MCP_LOOPBACK_HOST
    port: int = MCP_DEFAULT_PORT

    def __post_init__(self) -> None:
        if self.host != MCP_LOOPBACK_HOST:
            raise ConfigError(
                f"mcp.host must be the literal loopback address {MCP_LOOPBACK_HOST!r}"
            )
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ConfigError("mcp.port must be between 1 and 65535")


@dataclass(frozen=True, slots=True)
class HomeFingerprint:
    id: str
    link_type: str
    gateway_macs: frozenset[str]
    connection_uuids: frozenset[uuid.UUID]
    bssids: frozenset[str]


@dataclass(frozen=True, slots=True)
class HomeContext:
    gateway: ipaddress.IPv4Address
    source_cidr: ipaddress.IPv4Network
    fingerprints: tuple[HomeFingerprint, ...]


@dataclass(frozen=True, slots=True)
class WireGuardContext:
    local_addresses: tuple[ipaddress.IPv4Interface, ...]
    remote_cidrs: tuple[ipaddress.IPv4Network, ...]


@dataclass(frozen=True, slots=True)
class Endpoint:
    id: str
    address: ipaddress.IPv4Address
    port: int
    priority: int
    required_context: str


@dataclass(frozen=True, slots=True)
class Machine:
    name: str
    description: str
    ssh_profile: str
    user: str
    host_key_alias: str
    connect_timeout_seconds: int
    endpoints: tuple[Endpoint, ...]


@dataclass(frozen=True, slots=True)
class AppConfig:
    version: int
    broker: BrokerConfig
    home: HomeContext | None
    wireguard: WireGuardContext | None
    machines: Mapping[str, Machine]
    mcp: McpConfig = McpConfig()


def default_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        return Path(base) / "tmuxgate" / "config.toml"
    return Path.home() / ".config" / "tmuxgate" / "config.toml"


def _table(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigError(f"{name} must be a TOML table")
    return value


def _only(table: Mapping[str, Any], allowed: set[str], name: str) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise ConfigError(f"unknown fields in {name}: {', '.join(sorted(unknown))}")


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _string(value: object, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value) or "\x00" in value:
        raise ConfigError(f"{name} must be a valid string")
    return value


def _string_list(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{name} must be an array of strings")
    return tuple(value)


def _mac(value: str, name: str) -> str:
    if _MAC_RE.fullmatch(value) is None:
        raise ConfigError(f"{name} contains invalid MAC address {value!r}")
    return value.lower()


def _ipv4_address(value: object, name: str) -> ipaddress.IPv4Address:
    try:
        parsed = ipaddress.ip_address(_string(value, name))
    except ValueError as exc:
        raise ConfigError(f"{name} is not a valid IP address") from exc
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise ConfigError(f"{name} must be an IPv4 address")
    return parsed


def _ipv4_network(value: object, name: str) -> ipaddress.IPv4Network:
    try:
        parsed = ipaddress.ip_network(_string(value, name), strict=True)
    except ValueError as exc:
        raise ConfigError(f"{name} is not a valid canonical IPv4 network") from exc
    if not isinstance(parsed, ipaddress.IPv4Network):
        raise ConfigError(f"{name} must be an IPv4 network")
    return parsed


def _parse_broker(raw: object) -> BrokerConfig:
    table = _table(raw, "broker")
    allowed = {
        "max_active_remote_commands",
        "max_open_ssh_masters",
        "max_pending_requests",
        "queue_policy",
        "ssh_master_idle_timeout_seconds",
        "approval_mode",
    }
    _only(table, allowed, "broker")
    active = _integer(
        table.get("max_active_remote_commands", 3),
        "broker.max_active_remote_commands",
        1,
        3,
    )
    masters = _integer(table.get("max_open_ssh_masters", 3), "broker.max_open_ssh_masters", 1, 3)
    pending = _integer(table.get("max_pending_requests", 16), "broker.max_pending_requests", 1, 64)
    policy = _string(table.get("queue_policy", "fifo"), "broker.queue_policy")
    if policy != "fifo":
        raise ConfigError("broker.queue_policy must be 'fifo'")
    idle = _integer(
        table.get("ssh_master_idle_timeout_seconds", 600),
        "broker.ssh_master_idle_timeout_seconds",
        1,
        86400,
    )
    approval_mode = _string(
        table.get("approval_mode", "disabled"), "broker.approval_mode"
    )
    return BrokerConfig(
        max_active_remote_commands=active,
        max_open_ssh_masters=masters,
        max_pending_requests=pending,
        queue_policy=policy,
        ssh_master_idle_timeout_seconds=idle,
        approval_mode=approval_mode,
    )


def _parse_mcp(raw: object) -> McpConfig:
    table = _table(raw, "mcp")
    _only(table, {"host", "port"}, "mcp")
    host = _string(table.get("host", MCP_LOOPBACK_HOST), "mcp.host")
    if host != MCP_LOOPBACK_HOST:
        raise ConfigError(
            f"mcp.host must be the literal loopback address {MCP_LOOPBACK_HOST!r}"
        )
    port = _integer(table.get("port", MCP_DEFAULT_PORT), "mcp.port", 1, 65535)
    return McpConfig(host=host, port=port)


def _parse_home(raw: object) -> HomeContext:
    table = _table(raw, "contexts.home")
    _only(table, {"gateway", "source_cidr", "fingerprints"}, "contexts.home")
    gateway = _ipv4_address(table.get("gateway"), "contexts.home.gateway")
    source_cidr = _ipv4_network(table.get("source_cidr"), "contexts.home.source_cidr")
    if gateway not in source_cidr:
        raise ConfigError("contexts.home.gateway must belong to source_cidr")
    raw_fingerprints = table.get("fingerprints", [])
    if not isinstance(raw_fingerprints, list):
        raise ConfigError("contexts.home.fingerprints must be an array of tables")
    fingerprints: list[HomeFingerprint] = []
    ids: set[str] = set()
    for index, raw_fingerprint in enumerate(raw_fingerprints):
        name = f"contexts.home.fingerprints[{index}]"
        item = _table(raw_fingerprint, name)
        _only(item, {"id", "link_type", "gateway_macs", "connection_uuids", "bssids"}, name)
        try:
            fingerprint_id = validate_alias(item.get("id"), field_name=f"{name}.id")
        except ValidationError as exc:
            raise ConfigError(str(exc)) from exc
        if fingerprint_id in ids:
            raise ConfigError(f"duplicate home fingerprint ID: {fingerprint_id}")
        ids.add(fingerprint_id)
        link_type = _string(item.get("link_type"), f"{name}.link_type")
        if link_type not in {"ethernet", "wifi"}:
            raise ConfigError(f"{name}.link_type must be 'ethernet' or 'wifi'")
        gateway_macs = frozenset(
            _mac(value, f"{name}.gateway_macs")
            for value in _string_list(item.get("gateway_macs"), f"{name}.gateway_macs")
        )
        if not gateway_macs:
            raise ConfigError(f"{name}.gateway_macs must not be empty")
        try:
            connection_uuids = frozenset(
                uuid.UUID(value)
                for value in _string_list(item.get("connection_uuids"), f"{name}.connection_uuids")
            )
        except ValueError as exc:
            raise ConfigError(f"{name}.connection_uuids contains an invalid UUID") from exc
        if not connection_uuids:
            raise ConfigError(f"{name}.connection_uuids must not be empty")
        bssids = frozenset(
            _mac(value, f"{name}.bssids")
            for value in _string_list(item.get("bssids", []), f"{name}.bssids")
        )
        if link_type == "wifi" and not bssids:
            raise ConfigError(f"{name}.bssids must not be empty for Wi-Fi")
        if link_type == "ethernet" and bssids:
            raise ConfigError(f"{name}.bssids must be empty for Ethernet")
        fingerprints.append(
            HomeFingerprint(fingerprint_id, link_type, gateway_macs, connection_uuids, bssids)
        )
    return HomeContext(gateway, source_cidr, tuple(fingerprints))


def _parse_wireguard(raw: object) -> WireGuardContext:
    table = _table(raw, "contexts.wireguard")
    _only(table, {"local_addresses", "remote_cidrs"}, "contexts.wireguard")
    try:
        local_addresses = tuple(
            ipaddress.ip_interface(value)
            for value in _string_list(table.get("local_addresses"), "contexts.wireguard.local_addresses")
        )
    except ValueError as exc:
        raise ConfigError("contexts.wireguard.local_addresses contains an invalid address") from exc
    if not local_addresses or any(not isinstance(value, ipaddress.IPv4Interface) for value in local_addresses):
        raise ConfigError("contexts.wireguard.local_addresses must contain IPv4 interfaces")
    remote_cidrs = tuple(
        _ipv4_network(value, "contexts.wireguard.remote_cidrs")
        for value in _string_list(table.get("remote_cidrs"), "contexts.wireguard.remote_cidrs")
    )
    if not remote_cidrs:
        raise ConfigError("contexts.wireguard.remote_cidrs must not be empty")
    return WireGuardContext(local_addresses, remote_cidrs)


def _parse_endpoint(raw: object, name: str) -> Endpoint:
    table = _table(raw, name)
    _only(table, {"id", "address", "port", "priority", "requires"}, name)
    try:
        endpoint_id = validate_alias(table.get("id"), field_name=f"{name}.id")
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
    address = _ipv4_address(table.get("address"), f"{name}.address")
    port = _integer(table.get("port", 22), f"{name}.port", 1, 65535)
    priority = _integer(table.get("priority", 100), f"{name}.priority", 0, 10000)
    required = _string(table.get("requires"), f"{name}.requires")
    if required not in {"home", "wireguard"}:
        raise ConfigError(f"{name}.requires must be home or wireguard")
    return Endpoint(endpoint_id, address, port, priority, required)


def _parse_machine(name: str, raw: object, home: HomeContext | None, wireguard: WireGuardContext | None) -> Machine:
    try:
        machine_name = validate_alias(name, field_name="machine name")
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
    table = _table(raw, f"machines.{name}")
    _only(
        table,
        {"description", "ssh_profile", "user", "host_key_alias", "connect_timeout_seconds", "endpoints"},
        f"machines.{name}",
    )
    description = _string(table.get("description", name), f"machines.{name}.description", allow_empty=True)
    try:
        ssh_profile = validate_alias(table.get("ssh_profile", name), field_name=f"machines.{name}.ssh_profile")
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
    user = _string(table.get("user"), f"machines.{name}.user")
    if _USER_RE.fullmatch(user) is None:
        raise ConfigError(f"machines.{name}.user is invalid")
    host_key_alias = _string(table.get("host_key_alias"), f"machines.{name}.host_key_alias")
    if host_key_alias != f"tmuxgate-{machine_name}":
        raise ConfigError(
            f"machines.{name}.host_key_alias must equal 'tmuxgate-{machine_name}'"
        )
    timeout = _integer(
        table.get("connect_timeout_seconds", 6),
        f"machines.{name}.connect_timeout_seconds",
        1,
        60,
    )
    raw_endpoints = table.get("endpoints")
    if not isinstance(raw_endpoints, list) or not raw_endpoints:
        raise ConfigError(f"machines.{name}.endpoints must be a nonempty array")
    endpoints = tuple(
        _parse_endpoint(raw_endpoint, f"machines.{name}.endpoints[{index}]")
        for index, raw_endpoint in enumerate(raw_endpoints)
    )
    endpoint_ids = [endpoint.id for endpoint in endpoints]
    if len(endpoint_ids) != len(set(endpoint_ids)):
        raise ConfigError(f"machines.{name} contains duplicate endpoint IDs")
    for endpoint in endpoints:
        if endpoint.required_context == "home":
            if home is None:
                raise ConfigError(f"machines.{name} has a home endpoint but no home context")
            if not isinstance(endpoint.address, ipaddress.IPv4Address) or endpoint.address not in home.source_cidr:
                raise ConfigError(f"machines.{name} home endpoint is outside the home source CIDR")
        if endpoint.required_context == "wireguard":
            if wireguard is None:
                raise ConfigError(f"machines.{name} has a WireGuard endpoint but no WireGuard context")
            if not isinstance(endpoint.address, ipaddress.IPv4Address) or not any(
                endpoint.address in network for network in wireguard.remote_cidrs
            ):
                raise ConfigError(f"machines.{name} WireGuard endpoint is outside configured remote CIDRs")
    return Machine(machine_name, description, ssh_profile, user, host_key_alias, timeout, endpoints)


def parse_config(data: Mapping[str, Any]) -> AppConfig:
    table = _table(data, "configuration")
    version = table.get("version")
    if type(version) is not int or version not in {1, 2}:
        raise ConfigError("configuration version must equal 1 or 2")
    allowed = {"version", "broker", "contexts", "machines"}
    if version == 2:
        allowed.add("mcp")
    _only(table, allowed, "configuration")
    broker = _parse_broker(table.get("broker", {}))
    mcp = _parse_mcp(table.get("mcp", {}))
    contexts = _table(table.get("contexts", {}), "contexts")
    _only(contexts, {"home", "wireguard"}, "contexts")
    home = _parse_home(contexts["home"]) if "home" in contexts else None
    wireguard = _parse_wireguard(contexts["wireguard"]) if "wireguard" in contexts else None
    raw_machines = _table(table.get("machines"), "machines")
    if not raw_machines:
        raise ConfigError("machines must contain at least one configured alias")
    machines = MappingProxyType({
        name: _parse_machine(name, raw, home, wireguard)
        for name, raw in raw_machines.items()
    })
    # Version 1 is accepted as an input compatibility format.  The in-memory
    # model is normalized to the current schema so subsequent managed writes
    # publish version 2 rather than preserving the legacy format.
    return AppConfig(2, broker, home, wireguard, machines, mcp)


def _open_secure_config(path: Path):
    path = path.expanduser()
    if not path.is_absolute():
        raise ConfigError("configuration path must be absolute")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        directory_descriptor = os.open("/", directory_flags)
        for component in path.parent.parts[1:]:
            if component in {"", ".", ".."}:
                raise ConfigError("configuration path contains an unsafe component")
            next_descriptor = os.open(component, directory_flags, dir_fd=directory_descriptor)
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
    except ConfigError:
        try:
            os.close(directory_descriptor)
        except UnboundLocalError:
            pass
        raise
    except OSError as exc:
        try:
            os.close(directory_descriptor)
        except UnboundLocalError:
            pass
        raise ConfigError(
            f"cannot securely open configuration directory {path.parent}: {exc.strerror}"
        ) from exc
    parent_stat = os.fstat(directory_descriptor)
    if parent_stat.st_uid != os.getuid():
        os.close(directory_descriptor)
        raise ConfigError("configuration directory must be owned by the current user")
    if stat.S_IMODE(parent_stat.st_mode) & 0o077:
        os.close(directory_descriptor)
        raise ConfigError("configuration directory must not be accessible by group or others")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path.name, flags, dir_fd=directory_descriptor)
    except OSError as exc:
        os.close(directory_descriptor)
        raise ConfigError(f"cannot securely open {path}: {exc.strerror}") from exc
    os.close(directory_descriptor)
    file_stat = os.fstat(descriptor)
    if not stat.S_ISREG(file_stat.st_mode):
        os.close(descriptor)
        raise ConfigError("configuration must be a regular file")
    if file_stat.st_uid != os.getuid():
        os.close(descriptor)
        raise ConfigError("configuration file must be owned by the current user")
    if stat.S_IMODE(file_stat.st_mode) & 0o077:
        os.close(descriptor)
        raise ConfigError("configuration file mode must deny all group/other access")
    return os.fdopen(descriptor, "rb")


def load_config(path: str | os.PathLike[str] | None = None) -> AppConfig:
    config_path = Path(path) if path is not None else default_config_path()
    with _open_secure_config(config_path) as config_file:
        try:
            data = tomllib.load(config_file)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"invalid TOML: {exc}") from exc
    return parse_config(data)
