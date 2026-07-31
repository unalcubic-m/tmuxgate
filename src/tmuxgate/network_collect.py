"""Read-only collection of local route evidence for endpoint selection.

The collector never pings, resolves DNS, probes a port, or starts SSH.  It
reads kernel and NetworkManager state and turns any missing evidence into a
recorded collection error so the pure route policy can fail closed.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
import ipaddress
import json
import os
from pathlib import Path
import subprocess
from typing import Any
import uuid

from tmuxgate.network import (
    NeighborObservation,
    NetworkSnapshot,
    RouteObservation,
)


DEFAULT_IP_PATH = Path("/usr/sbin/ip")
DEFAULT_NMCLI_PATH = Path("/usr/bin/nmcli")
DEFAULT_COMMAND_TIMEOUT_SECONDS = 3.0
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024

CommandRunner = Callable[..., object]


class SnapshotCollectionError(RuntimeError):
    """One local evidence source could not be interpreted safely."""


def _safe_environment() -> dict[str, str]:
    return {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }


def _absolute_executable(value: os.PathLike[str] | str, label: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{label} executable path must be absolute")
    return os.fspath(path)


def _run(
    argv: tuple[str, ...],
    *,
    runner: CommandRunner,
    timeout_seconds: float,
) -> bytes:
    try:
        completed = runner(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
            env=_safe_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SnapshotCollectionError(f"command could not run: {type(exc).__name__}") from exc
    returncode = getattr(completed, "returncode", None)
    stdout = getattr(completed, "stdout", None)
    stderr = getattr(completed, "stderr", None)
    if type(returncode) is not int or not isinstance(stdout, bytes) or not isinstance(
        stderr, bytes
    ):
        raise SnapshotCollectionError("command runner returned an invalid result")
    if len(stdout) > MAX_COMMAND_OUTPUT_BYTES or len(stderr) > MAX_COMMAND_OUTPUT_BYTES:
        raise SnapshotCollectionError("command output exceeds the configured limit")
    if returncode != 0:
        raise SnapshotCollectionError(f"command exited with status {returncode}")
    return stdout


def _json_array(content: bytes, label: str) -> list[Any]:
    if b"\x00" in content:
        raise SnapshotCollectionError(f"{label} output contains NUL")
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotCollectionError(f"{label} output is not valid JSON") from exc
    if not isinstance(value, list):
        raise SnapshotCollectionError(f"{label} output is not a JSON array")
    return value


def _split_nmcli(line: str, expected_fields: int) -> tuple[str, ...]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        raise SnapshotCollectionError("nmcli output ends with an incomplete escape")
    fields.append("".join(current))
    if len(fields) != expected_fields:
        raise SnapshotCollectionError("nmcli output has an unexpected field count")
    return tuple(fields)


def _collect_addresses(document: list[Any]) -> dict[str, tuple[ipaddress.IPv4Interface, ...]]:
    result: dict[str, tuple[ipaddress.IPv4Interface, ...]] = {}
    for entry in document:
        if not isinstance(entry, dict):
            raise SnapshotCollectionError("ip address entry is not an object")
        interface = entry.get("ifname")
        addresses = entry.get("addr_info", [])
        if not isinstance(interface, str) or not interface or not isinstance(addresses, list):
            raise SnapshotCollectionError("ip address entry is malformed")
        parsed: list[ipaddress.IPv4Interface] = []
        for address in addresses:
            if not isinstance(address, dict):
                raise SnapshotCollectionError("ip address info is not an object")
            if address.get("family") != "inet":
                continue
            local = address.get("local")
            prefixlen = address.get("prefixlen")
            if not isinstance(local, str) or type(prefixlen) is not int:
                raise SnapshotCollectionError("IPv4 address evidence is malformed")
            try:
                parsed.append(ipaddress.IPv4Interface(f"{local}/{prefixlen}"))
            except ValueError as exc:
                raise SnapshotCollectionError("IPv4 address evidence is invalid") from exc
        result[interface] = tuple(
            sorted(parsed, key=lambda item: (int(item.ip), item.network.prefixlen))
        )
    return result


def _collect_links(
    document: list[Any],
) -> tuple[dict[str, frozenset[str]], dict[str, str]]:
    flags_by_interface: dict[str, frozenset[str]] = {}
    types_by_interface: dict[str, str] = {}
    for entry in document:
        if not isinstance(entry, dict):
            raise SnapshotCollectionError("ip link entry is not an object")
        interface = entry.get("ifname")
        flags = entry.get("flags")
        if not isinstance(interface, str) or not interface or not isinstance(flags, list):
            raise SnapshotCollectionError("ip link entry is malformed")
        if not all(isinstance(flag, str) and flag for flag in flags):
            raise SnapshotCollectionError("ip link flags are malformed")
        flags_by_interface[interface] = frozenset(flag.upper() for flag in flags)
        linkinfo = entry.get("linkinfo")
        kind = linkinfo.get("info_kind") if isinstance(linkinfo, dict) else None
        if kind == "wireguard":
            types_by_interface[interface] = "wireguard"
        elif entry.get("link_type") == "loopback":
            types_by_interface[interface] = "loopback"
    return flags_by_interface, types_by_interface


def _collect_active_connections(
    content: bytes,
) -> tuple[dict[str, uuid.UUID], dict[str, str]]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnapshotCollectionError("nmcli active connection output is not UTF-8") from exc
    uuids: dict[str, uuid.UUID] = {}
    types: dict[str, str] = {}
    type_names = {
        "802-3-ethernet": "ethernet",
        "ethernet": "ethernet",
        "802-11-wireless": "wifi",
        "wifi": "wifi",
        "wireguard": "wireguard",
    }
    for line in text.splitlines():
        if not line:
            continue
        interface, raw_uuid, raw_type = _split_nmcli(line, 3)
        if not interface or interface == "--":
            continue
        try:
            connection_uuid = uuid.UUID(raw_uuid)
        except ValueError as exc:
            raise SnapshotCollectionError("nmcli reported an invalid connection UUID") from exc
        if interface in uuids:
            raise SnapshotCollectionError("nmcli reported duplicate active interface")
        uuids[interface] = connection_uuid
        normalized_type = type_names.get(raw_type)
        if normalized_type is not None:
            types[interface] = normalized_type
    return uuids, types


def _collect_bssids(content: bytes) -> dict[str, str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnapshotCollectionError("nmcli Wi-Fi output is not UTF-8") from exc
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line:
            continue
        interface, active, bssid = _split_nmcli(line, 3)
        if active.lower() not in {"yes", "true"}:
            continue
        if not interface or not bssid:
            raise SnapshotCollectionError("active Wi-Fi evidence is incomplete")
        normalized = bssid.lower()
        if interface in result and result[interface] != normalized:
            raise SnapshotCollectionError("nmcli reported multiple active BSSIDs")
        result[interface] = normalized
    return result


def _collect_route(document: list[Any], destination: ipaddress.IPv4Address) -> RouteObservation:
    if len(document) != 1 or not isinstance(document[0], dict):
        raise SnapshotCollectionError("route lookup did not return exactly one object")
    entry = document[0]
    interface = entry.get("dev")
    source = entry.get("prefsrc", entry.get("src"))
    gateway = entry.get("gateway")
    if not isinstance(interface, str) or not interface:
        raise SnapshotCollectionError("route lookup lacks an interface")
    try:
        parsed_source = None if source is None else ipaddress.IPv4Address(source)
        parsed_gateway = None if gateway is None else ipaddress.IPv4Address(gateway)
    except (ValueError, TypeError) as exc:
        raise SnapshotCollectionError("route lookup has invalid IPv4 evidence") from exc
    return RouteObservation(destination, interface, parsed_source, parsed_gateway)


def _collect_neighbor(
    document: list[Any],
    gateway: ipaddress.IPv4Address,
    interface: str,
) -> NeighborObservation | None:
    matches: list[dict[str, Any]] = []
    for entry in document:
        if not isinstance(entry, dict):
            raise SnapshotCollectionError("neighbor entry is not an object")
        if entry.get("dst") != str(gateway):
            continue
        # The command itself is constrained with ``dev <interface>``. Some
        # iproute2 releases omit that now-redundant field from filtered JSON;
        # accept omission but never accept an explicitly different device.
        reported_interface = entry.get("dev")
        if reported_interface is not None and reported_interface != interface:
            continue
        matches.append(entry)
    if not matches:
        return None
    if len(matches) != 1:
        raise SnapshotCollectionError("neighbor lookup returned duplicate gateway entries")
    entry = matches[0]
    mac = entry.get("lladdr")
    raw_state = entry.get("state")
    if isinstance(raw_state, list) and len(raw_state) == 1:
        raw_state = raw_state[0]
    if not isinstance(mac, str) or not mac or not isinstance(raw_state, str) or not raw_state:
        raise SnapshotCollectionError("gateway neighbor evidence is incomplete")
    return NeighborObservation(mac.lower(), raw_state.upper())


def collect_network_snapshot(
    destinations: Iterable[ipaddress.IPv4Address],
    *,
    home_gateway: ipaddress.IPv4Address | None,
    runner: CommandRunner = subprocess.run,
    ip_path: os.PathLike[str] | str = DEFAULT_IP_PATH,
    nmcli_path: os.PathLike[str] | str = DEFAULT_NMCLI_PATH,
    timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> NetworkSnapshot:
    """Collect a complete read-only snapshot, retaining bounded source errors."""

    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise ValueError("snapshot command timeout must be a positive number")
    if not 0 < float(timeout_seconds) <= 30:
        raise ValueError("snapshot command timeout must be from 0 to 30 seconds")
    ip = _absolute_executable(ip_path, "ip")
    nmcli = _absolute_executable(nmcli_path, "nmcli")
    requested: set[ipaddress.IPv4Address] = set()
    for destination in destinations:
        if not isinstance(destination, ipaddress.IPv4Address):
            raise TypeError("snapshot destinations must be IPv4Address values")
        requested.add(destination)
    if home_gateway is not None:
        if not isinstance(home_gateway, ipaddress.IPv4Address):
            raise TypeError("home gateway must be an IPv4Address or None")
        requested.add(home_gateway)

    errors: list[str] = []
    addresses: dict[str, tuple[ipaddress.IPv4Interface, ...]] = {}
    flags: dict[str, frozenset[str]] = {}
    link_types: dict[str, str] = {}
    connection_uuids: dict[str, uuid.UUID] = {}
    bssids: dict[str, str] = {}
    routes: dict[ipaddress.IPv4Address, RouteObservation] = {}
    neighbors: dict[tuple[str, ipaddress.IPv4Address], NeighborObservation] = {}

    try:
        addresses = _collect_addresses(
            _json_array(
                _run((ip, "-j", "address", "show"), runner=runner, timeout_seconds=float(timeout_seconds)),
                "ip address",
            )
        )
    except SnapshotCollectionError as exc:
        errors.append(f"ip-address: {exc}")
    try:
        flags, link_types = _collect_links(
            _json_array(
                _run((ip, "-j", "-details", "link", "show"), runner=runner, timeout_seconds=float(timeout_seconds)),
                "ip link",
            )
        )
    except SnapshotCollectionError as exc:
        errors.append(f"ip-link: {exc}")
    try:
        connection_uuids, nm_types = _collect_active_connections(
            _run(
                (
                    nmcli,
                    "--terse",
                    "--escape",
                    "yes",
                    "--fields",
                    "DEVICE,UUID,TYPE",
                    "connection",
                    "show",
                    "--active",
                ),
                runner=runner,
                timeout_seconds=float(timeout_seconds),
            )
        )
        link_types.update(nm_types)
    except SnapshotCollectionError as exc:
        errors.append(f"nmcli-active: {exc}")
    try:
        bssids = _collect_bssids(
            _run(
                (
                    nmcli,
                    "--terse",
                    "--escape",
                    "yes",
                    "--fields",
                    "DEVICE,ACTIVE,BSSID",
                    "device",
                    "wifi",
                    "list",
                    "--rescan",
                    "no",
                ),
                runner=runner,
                timeout_seconds=float(timeout_seconds),
            )
        )
    except SnapshotCollectionError as exc:
        errors.append(f"nmcli-wifi: {exc}")

    for destination in sorted(requested, key=int):
        try:
            routes[destination] = _collect_route(
                _json_array(
                    _run(
                        (ip, "-j", "route", "get", str(destination)),
                        runner=runner,
                        timeout_seconds=float(timeout_seconds),
                    ),
                    f"route {destination}",
                ),
                destination,
            )
        except SnapshotCollectionError as exc:
            errors.append(f"route-{destination}: {exc}")

    if home_gateway is not None and home_gateway in routes:
        interface = routes[home_gateway].interface
        try:
            observation = _collect_neighbor(
                _json_array(
                    _run(
                        (ip, "-j", "neighbor", "show", "to", str(home_gateway), "dev", interface),
                        runner=runner,
                        timeout_seconds=float(timeout_seconds),
                    ),
                    f"neighbor {home_gateway}",
                ),
                home_gateway,
                interface,
            )
            if observation is not None:
                neighbors[(interface, home_gateway)] = observation
        except SnapshotCollectionError as exc:
            errors.append(f"neighbor-{home_gateway}: {exc}")

    return NetworkSnapshot(
        addresses_by_interface=addresses,
        link_flags=flags,
        link_types=link_types,
        routes=routes,
        neighbors=neighbors,
        connection_uuid_by_interface=connection_uuids,
        bssid_by_interface=bssids,
        collection_errors=tuple(errors),
    )
