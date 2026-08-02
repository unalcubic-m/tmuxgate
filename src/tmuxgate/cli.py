"""Public command-line surface for the unified local tmuxgate application."""

from __future__ import annotations

import argparse
from dataclasses import replace
import ipaddress
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import threading
from types import MappingProxyType
from typing import BinaryIO, Callable

from tmuxgate import __version__
from tmuxgate.application import RecoveryBlockedError, UnifiedApplication
from tmuxgate.approval import ApprovalError, open_approval_terminal
from tmuxgate.broker import BrokerError
from tmuxgate.client import BrokerConnectionError, submit_request
from tmuxgate.config import (
    ConfigError,
    Endpoint,
    HomeFingerprint,
    Machine,
    default_config_path,
    load_config,
    load_config_snapshot,
)
from tmuxgate.models import (
    RequestSpec,
    ResultFormat,
    ValidationError,
    validate_alias,
)
from tmuxgate.mcp_server import McpServerError
from tmuxgate.network_collect import collect_network_snapshot
from tmuxgate.protocol import ProtocolError
from tmuxgate.result import ExecutionResult, relay_transparent
from tmuxgate.runtime import (
    RuntimeSecurityError,
    acquire_state_lock,
    default_socket_path,
    default_state_dir,
    prepare_runtime_layout,
)
from tmuxgate.scheduler import RequestState
from tmuxgate.state import (
    DurableStateStore,
    StateConflictError,
    StateError,
)
from tmuxgate.spool import ResultSpool, SpoolError
from tmuxgate.settings import (
    publish_config,
    publish_edited_config,
    set_machine_enabled,
)
from tmuxgate.terminal import TerminalArbiter, TerminalError, TerminalPriority


EXIT_USAGE = 64
EXIT_UNAVAILABLE = 69
EXIT_SOFTWARE = 70
EXIT_CONFIG = 78


def _add_local_paths(
    parser: argparse.ArgumentParser,
    *,
    config: bool = False,
    inherit: bool = False,
) -> None:
    default: object = argparse.SUPPRESS if inherit else None
    parser.add_argument(
        "--socket",
        default=default,
        help=f"broker Unix socket (default: {default_socket_path() if os.environ.get('XDG_RUNTIME_DIR') else '$XDG_RUNTIME_DIR/tmuxgate/broker.sock'})",
    )
    if config:
        parser.add_argument(
            "--config",
            default=(argparse.SUPPRESS if inherit else str(default_config_path())),
            help=(
                "protected host configuration"
                if inherit
                else "protected host configuration (default: %(default)s)"
            ),
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tmuxgate",
        description="Owner-controlled broker for isolated remote tmux jobs",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    _add_local_paths(parser, config=True)
    parser.add_argument("--state-dir", default=None)
    parser.add_argument(
        "--fake",
        action="store_true",
        help="run local canned fake execution; never opens SSH",
    )
    subparsers = parser.add_subparsers(dest="command")

    config_parser = subparsers.add_parser("config", help="configuration tools")
    config_subparsers = config_parser.add_subparsers(dest="config_command", required=True)
    check_parser = config_subparsers.add_parser("check", help="validate protected config")
    check_parser.add_argument("--path", default=argparse.SUPPRESS)
    check_parser.set_defaults(handler=_config_check)
    list_parser = config_subparsers.add_parser(
        "list", help="show configured remote machine names and endpoints"
    )
    list_parser.add_argument("--path", default=argparse.SUPPRESS)
    list_parser.set_defaults(handler=_config_list)
    path_parser = config_subparsers.add_parser(
        "path", help="show the active configuration file path"
    )
    path_parser.add_argument("--path", default=argparse.SUPPRESS)
    path_parser.set_defaults(handler=_config_path)
    edit_parser = config_subparsers.add_parser(
        "edit", help="edit and validate settings in the terminal"
    )
    edit_parser.add_argument("--path", default=argparse.SUPPRESS)
    edit_parser.set_defaults(handler=_config_edit)
    broker_settings_parser = config_subparsers.add_parser(
        "set-broker", help="atomically update supported broker behavior"
    )
    broker_settings_parser.add_argument(
        "--approval-mode", choices=("always", "disabled"), default=None
    )
    broker_settings_parser.add_argument(
        "--max-active-remote-commands", type=int, default=None
    )
    broker_settings_parser.add_argument("--path", default=argparse.SUPPRESS)
    broker_settings_parser.set_defaults(handler=_config_set_broker)
    add_parser = config_subparsers.add_parser(
        "add-machine", help="guided addition of one logical remote machine"
    )
    add_parser.add_argument("name", nargs="?")
    add_parser.add_argument("--user", default=None)
    add_parser.add_argument("--description", default=None)
    add_parser.add_argument("--lan-ip", default=None)
    add_parser.add_argument("--wireguard-ip", default=None)
    add_parser.add_argument("--port", type=int, default=22)
    add_parser.add_argument("--path", default=argparse.SUPPRESS)
    add_parser.set_defaults(handler=_config_add_machine)
    remove_parser = config_subparsers.add_parser(
        "remove-machine", help="remove one logical machine from local settings"
    )
    remove_parser.add_argument("name")
    remove_parser.add_argument("--yes", action="store_true")
    remove_parser.add_argument("--path", default=argparse.SUPPRESS)
    remove_parser.set_defaults(handler=_config_remove_machine)
    for action, handler in (
        ("disable", _config_disable_machine),
        ("enable", _config_enable_machine),
    ):
        state_parser = config_subparsers.add_parser(
            f"{action}-machine",
            help=f"{action} one logical machine without removing its settings",
        )
        state_parser.add_argument("name")
        state_parser.add_argument("--path", default=argparse.SUPPRESS)
        state_parser.set_defaults(handler=handler)
    enroll_parser = config_subparsers.add_parser(
        "enroll-home", help="learn the directly connected physical home network"
    )
    enroll_parser.add_argument("--id", default=None)
    enroll_parser.add_argument("--yes", action="store_true")
    enroll_parser.add_argument("--path", default=argparse.SUPPRESS)
    enroll_parser.set_defaults(handler=_config_enroll_home)

    broker_parser = subparsers.add_parser(
        "broker",
        help="deprecated alias for the unified foreground application",
    )
    _add_local_paths(broker_parser, config=True, inherit=True)
    broker_parser.add_argument("--state-dir", default=argparse.SUPPRESS)
    broker_parser.add_argument(
        "--fake",
        action="store_true",
        default=argparse.SUPPRESS,
        help="run local canned fake execution; never opens SSH",
    )
    broker_parser.set_defaults(handler=_broker_alias_command)

    dashboard_parser = subparsers.add_parser(
        "dashboard",
        help="run the unified foreground application and terminal dashboard",
    )
    _add_local_paths(dashboard_parser, config=True, inherit=True)
    dashboard_parser.add_argument("--state-dir", default=argparse.SUPPRESS)
    dashboard_parser.add_argument(
        "--fake", action="store_true", default=argparse.SUPPRESS
    )
    dashboard_parser.set_defaults(handler=_unified_command)

    jobs_parser = subparsers.add_parser("jobs", help="list durable local job records")
    jobs_parser.add_argument("--state-dir", default=argparse.SUPPRESS)
    jobs_parser.add_argument("--json", action="store_true")
    jobs_parser.set_defaults(handler=_jobs_command)

    recover_parser = subparsers.add_parser(
        "recover", help="reconcile one exact recovery-blocked request"
    )
    recover_subparsers = recover_parser.add_subparsers(
        dest="recover_command", required=True
    )
    after_reboot_parser = recover_subparsers.add_parser(
        "after-reboot",
        help=(
            "record that a full machine reboot abandoned an uncertain or "
            "uncollectable completed request"
        ),
    )
    after_reboot_parser.add_argument("request_id")
    after_reboot_parser.add_argument("--state-dir", default=argparse.SUPPRESS)
    _add_local_paths(after_reboot_parser, inherit=True)
    after_reboot_parser.set_defaults(handler=_recover_after_reboot)
    after_dead_pane_parser = recover_subparsers.add_parser(
        "after-dead-pane",
        help="record that the operator visibly observed the dedicated pane dead",
    )
    after_dead_pane_parser.add_argument("request_id")
    after_dead_pane_parser.add_argument("--state-dir", default=argparse.SUPPRESS)
    _add_local_paths(after_dead_pane_parser, inherit=True)
    after_dead_pane_parser.set_defaults(handler=_recover_after_dead_pane)

    for name, help_text in (
        ("attach", "attach to an existing dedicated job"),
        ("collect", "collect a proven-complete job"),
        ("cleanup", "clean a verified inactive job"),
    ):
        control = subparsers.add_parser(name, help=help_text)
        control.add_argument("request_id")
        _add_local_paths(control, inherit=True)
        if name in {"attach", "collect"}:
            control.add_argument("--state-dir", default=argparse.SUPPRESS)
        if name == "collect":
            control.add_argument(
                "--result", choices=("transparent", "json"), default="transparent"
            )
            control.set_defaults(handler=_collect_local_result)
        elif name == "attach":
            control.set_defaults(handler=_attach_local_viewer)
        else:
            control.set_defaults(handler=_remote_control_unavailable)

    return parser


def _config_check(args: argparse.Namespace) -> int:
    config = load_config(args.path)
    enabled_count = sum(machine.enabled for machine in config.machines.values())
    print(
        "configuration valid: "
        f"{len(config.machines)} machines ({enabled_count} enabled), "
        f"{config.broker.max_open_ssh_masters} retained masters, "
        f"{config.broker.max_active_remote_commands} active remote commands, "
        f"approval={config.broker.approval_mode}"
    )
    return 0


def _config_list(args: argparse.Namespace) -> int:
    config = load_config(args.path)
    print("Configured remote machines")
    print("==========================")
    for machine in config.machines.values():
        status = "enabled" if machine.enabled else "disabled"
        print(
            f"{machine.name}  status={status}  user={machine.user}  "
            f"{machine.description}"
        )
        for endpoint in machine.endpoints:
            print(
                f"  - {endpoint.id:<12} {endpoint.address}:{endpoint.port} "
                f"when={endpoint.required_context}"
            )
    print("\nEdit: tmuxgate config edit")
    print("Restart tmuxgate after changing settings.")
    return 0


def _config_path(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser()
    load_config(path)
    print(path)
    return 0


def _config_set_broker(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser()
    config = load_config(path)
    changes: dict[str, object] = {}
    if args.approval_mode is not None:
        changes["approval_mode"] = args.approval_mode
    if args.max_active_remote_commands is not None:
        changes["max_active_remote_commands"] = args.max_active_remote_commands
    if not changes:
        raise ConfigError("set-broker requires at least one setting")
    updated = replace(config, broker=replace(config.broker, **changes))
    publish_config(path, updated, expected_config=config)
    print(
        "Broker settings updated: "
        f"approval_mode={updated.broker.approval_mode}, "
        f"max_active_remote_commands={updated.broker.max_active_remote_commands}."
    )
    print("Restart tmuxgate to load them.")
    return 0


def _config_edit(args: argparse.Namespace) -> int:
    """Edit a private temporary copy and publish only valid configuration."""

    path = Path(args.path).expanduser()
    if not path.is_absolute():
        raise ConfigError("configuration path must be absolute")
    _original_config, content = load_config_snapshot(path)
    temporary = path.parent / f".config.{secrets.token_hex(16)}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(temporary, flags, 0o600)
    try:
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise OSError("configuration temporary write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    try:
        while True:
            with open_approval_terminal() as terminal:
                completed = subprocess.run(
                    ("/usr/bin/nano", "--", os.fspath(temporary)),
                    stdin=terminal.reader,
                    stdout=terminal.writer,
                    stderr=terminal.writer,
                    check=False,
                )
            if completed.returncode != 0:
                print("tmuxgate: editor exited without publishing settings", file=sys.stderr)
                return EXIT_UNAVAILABLE
            try:
                config = load_config(temporary)
            except ConfigError as exc:
                print(f"tmuxgate: settings are not valid: {exc}", file=sys.stderr)
                print("Reopening the editor; fix the error or exit without saving.")
                continue
            config = publish_edited_config(
                path,
                temporary,
                expected_content=content,
            )
            print(
                f"Settings valid: {len(config.machines)} machines. "
                "Restart tmuxgate to load them."
            )
            return 0
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _prompt(label: str, *, default: str | None = None, allow_empty: bool = False) -> str:
    suffix = f" [{default}]" if default is not None else ""
    with open_approval_terminal() as terminal:
        while True:
            terminal.writer.write(f"{label}{suffix}: ")
            terminal.writer.flush()
            try:
                value = terminal.reader.readline()
            except EOFError as exc:
                raise ConfigError("settings input ended before completion") from exc
            if value == "":
                raise ConfigError("settings input ended before completion")
            value = value.rstrip("\r\n")
            if not value and default is not None:
                return default
            if value or allow_empty:
                return value
            terminal.writer.write("A value is required.\n")
            terminal.writer.flush()


def _ipv4_or_none(value: str, label: str) -> ipaddress.IPv4Address | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ConfigError(f"{label} is not a valid IP address") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise ConfigError(f"{label} must be IPv4")
    return address


def _config_add_machine(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser()
    config = load_config(path)
    name = args.name or _prompt("Logical machine name")
    name = validate_alias(name, field_name="machine name")
    if name in config.machines:
        raise ConfigError(f"machine already exists: {name}")
    user = args.user or _prompt(
        "SSH username", default=os.environ.get("USER") or "operator"
    )
    description = (
        args.description
        if args.description is not None
        else _prompt("Description", default=name)
    )
    lan_text = args.lan_ip
    wireguard_text = args.wireguard_ip
    if lan_text is None:
        lan_text = _prompt(
            "Home LAN IPv4 (leave empty if unavailable)", allow_empty=True
        )
    if wireguard_text is None:
        wireguard_text = _prompt(
            "WireGuard IPv4 (leave empty if unavailable)", allow_empty=True
        )
    lan = _ipv4_or_none(lan_text, "LAN address")
    wireguard = _ipv4_or_none(wireguard_text, "WireGuard address")
    if lan is None and wireguard is None:
        raise ConfigError("at least one LAN or WireGuard endpoint is required")
    if isinstance(args.port, bool) or not 1 <= args.port <= 65535:
        raise ConfigError("SSH port must be from 1 to 65535")
    endpoints: list[Endpoint] = []
    if lan is not None:
        endpoints.append(Endpoint("home-lan", lan, args.port, 10, "home"))
    if wireguard is not None:
        endpoints.append(Endpoint("wireguard", wireguard, args.port, 20, "wireguard"))
    machine = Machine(
        name,
        description,
        name,
        user,
        f"tmuxgate-{name}",
        6,
        tuple(endpoints),
    )
    machines = dict(config.machines)
    machines[name] = machine
    publish_config(
        path,
        replace(config, machines=MappingProxyType(machines)),
        expected_config=config,
    )
    print(f"Added {name}. Restart tmuxgate to load the new machine.")
    return 0


def _config_remove_machine(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser()
    config = load_config(path)
    name = validate_alias(args.name, field_name="machine name")
    if name not in config.machines:
        raise ConfigError(f"unknown configured machine: {name}")
    if len(config.machines) == 1:
        raise ConfigError("cannot remove the last configured machine")
    if not args.yes:
        answer = _prompt(
            f"Remove local settings for {name}? Type yes to confirm",
            allow_empty=True,
        )
        if answer.casefold() != "yes":
            print("No settings changed.")
            return 0
    machines = dict(config.machines)
    del machines[name]
    publish_config(
        path,
        replace(config, machines=MappingProxyType(machines)),
        expected_config=config,
    )
    print(f"Removed {name} from local settings. No remote machine was contacted.")
    return 0


def _config_set_machine_enabled(
    args: argparse.Namespace,
    *,
    enabled: bool,
) -> int:
    path = Path(args.path).expanduser()
    name = validate_alias(args.name, field_name="machine name")
    state = "enabled" if enabled else "disabled"
    _updated, changed = set_machine_enabled(path, name, enabled=enabled)
    if not changed:
        print(f"{name} is already {state}. No settings changed.")
        return 0
    print(
        f"{name} is now {state}. No remote machine was contacted. "
        "Restart tmuxgate to load the change."
    )
    return 0


def _config_disable_machine(args: argparse.Namespace) -> int:
    return _config_set_machine_enabled(args, enabled=False)


def _config_enable_machine(args: argparse.Namespace) -> int:
    return _config_set_machine_enabled(args, enabled=True)


def _direct_home_route(config: object, snapshot: object) -> object:
    """Return the proven direct home route or fail before active discovery."""

    home = config.home
    route = snapshot.routes.get(home.gateway)
    if (
        route is None
        or route.gateway is not None
        or route.source is None
        or route.source not in home.source_cidr
        or not any(
            address.ip == route.source
            for address in snapshot.addresses_by_interface.get(route.interface, ())
        )
    ):
        raise ConfigError(
            "not directly connected to the configured home LAN; refusing to enroll "
            "a routed or WireGuard view"
        )
    return route


def _refresh_home_neighbor(interface: str, gateway: ipaddress.IPv4Address) -> None:
    """Prompt one local ARP resolution through a bounded gateway-only ping."""

    try:
        subprocess.run(
            (
                "/usr/bin/ping",
                "-4",
                "-n",
                "-c",
                "1",
                "-W",
                "1",
                "-I",
                interface,
                "--",
                str(gateway),
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            },
        )
    except (OSError, subprocess.SubprocessError):
        # The following complete snapshot remains the authority. A blocked
        # ICMP reply may still have populated ARP; otherwise enrollment fails.
        pass


def _config_enroll_home(args: argparse.Namespace) -> int:
    path = Path(args.path).expanduser()
    config = load_config(path)
    home = config.home
    if home is None:
        raise ConfigError("home context is not configured")
    destinations = {
        home.gateway,
        *(
            endpoint.address
            for machine in config.machines.values()
            for endpoint in machine.endpoints
            if endpoint.required_context == "home"
        ),
    }
    snapshot = collect_network_snapshot(destinations, home_gateway=home.gateway)
    route = _direct_home_route(config, snapshot)
    interface = route.interface
    if snapshot.neighbors.get((interface, home.gateway)) is None:
        print("Refreshing local router identity...")
        _refresh_home_neighbor(interface, home.gateway)
        snapshot = collect_network_snapshot(destinations, home_gateway=home.gateway)
        # Re-prove the complete direct route after the active neighbor refresh;
        # never publish evidence gathered across a route or interface change.
        route = _direct_home_route(config, snapshot)
        interface = route.interface
    flags = snapshot.link_flags.get(interface, frozenset())
    link_type = snapshot.link_types.get(interface)
    neighbor = snapshot.neighbors.get((interface, home.gateway))
    connection_uuid = snapshot.connection_uuid_by_interface.get(interface)
    bssid = snapshot.bssid_by_interface.get(interface)
    if link_type not in {"ethernet", "wifi"}:
        raise ConfigError("home link type could not be proven as Ethernet or Wi-Fi")
    if "UP" not in flags or (link_type == "ethernet" and "LOWER_UP" not in flags):
        raise ConfigError("home interface is not currently connected")
    if neighbor is None or neighbor.state.upper() not in {
        "REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT",
    }:
        raise ConfigError("home router MAC is unavailable from the local neighbor cache")
    if connection_uuid is None:
        raise ConfigError("NetworkManager connection identity is unavailable")
    if link_type == "wifi" and bssid is None:
        raise ConfigError("current Wi-Fi BSSID is unavailable")
    default_id = "home-" + link_type + "-" + "".join(
        character if character.isalnum() or character == "-" else "-"
        for character in interface.lower()
    )
    fingerprint_id = validate_alias(
        args.id or default_id[:63], field_name="home fingerprint ID"
    )
    if any(item.id == fingerprint_id for item in home.fingerprints):
        raise ConfigError(f"home fingerprint already exists: {fingerprint_id}")
    print("Detected direct home network")
    print(f"  interface: {interface} ({link_type})")
    print(f"  source: {route.source}")
    print(f"  router: {home.gateway} / {neighbor.mac.lower()}")
    print(f"  connection UUID: {connection_uuid}")
    if bssid is not None:
        print(f"  Wi-Fi BSSID: {bssid.lower()}")
    if not args.yes:
        answer = _prompt("Enroll this as home? [y/N]", allow_empty=True)
        if answer.casefold() not in {"y", "yes"}:
            print("No settings changed.")
            return 0
    fingerprint = HomeFingerprint(
        fingerprint_id,
        link_type,
        frozenset({neighbor.mac.lower()}),
        frozenset({connection_uuid}),
        frozenset() if bssid is None else frozenset({bssid.lower()}),
    )
    updated_home = replace(home, fingerprints=(*home.fingerprints, fingerprint))
    publish_config(
        path,
        replace(config, home=updated_home),
        expected_config=config,
    )
    print(f"Enrolled {fingerprint_id}. Restart tmuxgate to use home-LAN routing.")
    return 0


def present_result(
    result: ExecutionResult,
    result_format: ResultFormat,
    *,
    stdout: BinaryIO,
    stderr: BinaryIO,
) -> int:
    if result_format is ResultFormat.JSON:
        stdout.write(result.structured_json())
        stdout.flush()
        return 0
    return relay_transparent(result, stdout, stderr)


def submit_and_present(
    request: RequestSpec,
    *,
    socket_path: str | None,
    submitter: Callable[..., ExecutionResult] | None = None,
    stdout: BinaryIO | None = None,
    stderr: BinaryIO | None = None,
) -> int:
    if submitter is None:
        submitter = submit_request
    result = submitter(request, socket_path=socket_path)
    output = sys.stdout.buffer if stdout is None else stdout
    errors = sys.stderr.buffer if stderr is None else stderr
    return present_result(result, request.result_format, stdout=output, stderr=errors)


def _job_document(record: object) -> dict[str, object]:
    return {
        "completion_time": record.completion_time,
        "decision": None if record.decision is None else record.decision.value,
        "endpoint_id": record.endpoint_id,
        "exit_status": record.exit_status,
        "failure_detail": record.failure_detail,
        "generation": record.generation,
        "local_spool_manifest_sha256": record.local_spool_manifest_sha256,
        "local_spool_verified": record.local_spool_verified,
        "machine": record.machine_alias,
        "remote_mutation_started": record.remote_mutation_started,
        "remote_job_path": record.remote_job_path,
        "remote_tmux_session": record.remote_tmux_session,
        "request_id": record.request_id,
        "start_time": record.start_time,
        "state": record.state.value,
        "terminal_restored": record.terminal_restored,
        "updated_at": record.updated_at,
        "viewer_detached": record.viewer_detached,
    }


def _jobs_command(args: argparse.Namespace) -> int:
    state_dir = default_state_dir() if args.state_dir is None else Path(args.state_dir)
    # A live broker may be between creating and atomically publishing a state
    # temporary.  This read-only administrative view must ignore, never unlink,
    # such entries; singleton-owned startup recovery performs stale cleanup.
    with DurableStateStore(
        state_dir,
        cleanup_stale_temporaries=False,
    ) as store:
        records = store.load_all()
    if args.json:
        print(json.dumps([_job_document(record) for record in records], sort_keys=True))
        return 0
    if not records:
        print("No durable tmuxgate jobs.")
        return 0
    print("REQUEST_ID                       MACHINE         STATE")
    for record in records:
        print(f"{record.request_id}  {record.machine_alias:<14} {record.state.value}")
    return 0


def _reboot_recovery_phrase(record: object) -> str:
    return (
        f"ABANDON {record.request_id} {record.machine_alias} "
        f"GENERATION {record.generation} AFTER FULL REBOOT"
    )


def _confirm_reboot_recovery(record: object) -> bool:
    phrase = _reboot_recovery_phrase(record)
    with open_approval_terminal() as terminal:
        terminal.writer.write(
            "\nTMUXGATE REBOOT RECOVERY\n"
            "========================\n"
            f"request:    {record.request_id}\n"
            f"machine:    {record.machine_alias}\n"
            f"endpoint:   {record.endpoint_id}\n"
            f"started:    {record.start_time}\n"
            f"completed:  {getattr(record, 'completion_time', None)}\n"
            f"exit:       {getattr(record, 'exit_status', None)}\n"
            f"generation: {record.generation}\n"
            f"failure:    {json.dumps(record.failure_detail, ensure_ascii=True)}\n\n"
            "Use this only after the entire named machine was rebooted after the "
            "start time above. This records an abandoned execution. Any prior "
            "completion evidence shown above is retained in the audit detail, "
            "but no output or verified result spool is claimed. It does not "
            "contact or clean the remote machine.\n\n"
            f"Type exactly:\n{phrase}\n> "
        )
        terminal.writer.flush()
        try:
            response = terminal.reader.readline()
        except KeyboardInterrupt:
            terminal.writer.write("\n")
            terminal.writer.flush()
            return False
    if response == "":
        return False
    return response.rstrip("\r\n") == phrase


def _recover_after_reboot(args: argparse.Namespace) -> int:
    paths = prepare_runtime_layout(
        socket_path=args.socket,
        state_dir=args.state_dir,
    )
    with acquire_state_lock(paths.state_dir):
        with DurableStateStore(paths.state_dir) as store:
            record = store.load(args.request_id)
            if record.state not in {
                RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
                RequestState.COMPLETION_PROVEN,
            }:
                raise StateConflictError(
                    "after-reboot recovery requires an exact recovery-blocked or "
                    "uncollected completion-proven request"
                )
            if not _confirm_reboot_recovery(record):
                print(
                    "tmuxgate: reboot recovery was not confirmed; no state changed",
                    file=sys.stderr,
                )
                return 77
            current = store.load(args.request_id)
            if current != record:
                raise StateConflictError(
                    "recovery record changed while operator confirmation was pending"
                )
            abandoned = store.mark_abandoned_after_operator_confirmed_reboot(current)
    print(
        "tmuxgate recorded an operator-confirmed reboot abandonment: "
        f"request={abandoned.request_id} generation={abandoned.generation}"
    )
    print(
        "No SSH action, remote cleanup, exit-status fabrication, or result-spool "
        "publication occurred."
    )
    return 0


def _dead_pane_recovery_phrase(record: object) -> str:
    return (
        f"ABANDON {record.request_id} {record.machine_alias} "
        f"GENERATION {record.generation} AFTER DEAD PANE"
    )


def _confirm_dead_pane_recovery(record: object) -> bool:
    phrase = _dead_pane_recovery_phrase(record)
    with open_approval_terminal() as terminal:
        terminal.writer.write(
            "\nTMUXGATE DEAD-PANE RECOVERY\n"
            "=============================\n"
            f"request:    {record.request_id}\n"
            f"machine:    {record.machine_alias}\n"
            f"endpoint:   {record.endpoint_id}\n"
            f"started:    {record.start_time}\n"
            f"generation: {record.generation}\n"
            f"failure:    {json.dumps(record.failure_detail, ensure_ascii=True)}\n\n"
            "Use this only after directly observing that this exact dedicated "
            "tmux pane is dead and its foreground command has finished. This "
            "records an abandoned execution. It does NOT claim a remote exit "
            "status, completed output, or a verified result spool, and it does "
            "not contact or clean the remote machine.\n\n"
            f"Type exactly:\n{phrase}\n> "
        )
        terminal.writer.flush()
        try:
            response = terminal.reader.readline()
        except KeyboardInterrupt:
            terminal.writer.write("\n")
            terminal.writer.flush()
            return False
    if response == "":
        return False
    return response.rstrip("\r\n") == phrase


def _recover_after_dead_pane(args: argparse.Namespace) -> int:
    paths = prepare_runtime_layout(
        socket_path=args.socket,
        state_dir=args.state_dir,
    )
    with acquire_state_lock(paths.state_dir):
        with DurableStateStore(paths.state_dir) as store:
            record = store.load(args.request_id)
            if record.state is not RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING:
                raise StateConflictError(
                    "after-dead-pane recovery requires an exact recovery-blocked request"
                )
            if not _confirm_dead_pane_recovery(record):
                print(
                    "tmuxgate: dead-pane recovery was not confirmed; no state changed",
                    file=sys.stderr,
                )
                return 77
            current = store.load(args.request_id)
            if current != record:
                raise StateConflictError(
                    "recovery record changed while operator confirmation was pending"
                )
            abandoned = store.mark_abandoned_after_operator_confirmed_dead_pane(
                current
            )
    print(
        "tmuxgate recorded an operator-confirmed dead-pane abandonment: "
        f"request={abandoned.request_id} generation={abandoned.generation}"
    )
    print(
        "No SSH action, remote cleanup, exit-status fabrication, or result-spool "
        "publication occurred."
    )
    return 0


def _remote_control_unavailable(args: argparse.Namespace) -> int:
    print(
        f"tmuxgate: {args.command} is fail-closed until the real broker control "
        "backend is enabled; no remote action was attempted",
        file=sys.stderr,
    )
    return EXIT_UNAVAILABLE


def _attach_local_viewer(args: argparse.Namespace) -> int:
    """Attach to one exact broker-created private local viewer session."""

    paths = prepare_runtime_layout(
        socket_path=args.socket,
        state_dir=args.state_dir,
    )
    with DurableStateStore(paths.state_dir) as store:
        record = store.load(args.request_id)
    if not record.remote_mutation_started or record.state in {
        RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
        RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
        RequestState.DONE,
    }:
        raise StateConflictError("request has no attachable active viewer")
    socket_path = paths.viewer_dir / f"{record.request_id}.sock"
    try:
        metadata = os.lstat(socket_path)
    except FileNotFoundError as exc:
        raise StateConflictError("the request's local viewer is not active") from exc
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise RuntimeSecurityError("the request's local viewer socket is unsafe")
    environment = dict(os.environ)
    environment.pop("TMUX", None)
    completed = subprocess.run(
        (
            "/usr/bin/tmux", "-S", os.fspath(socket_path),
            "attach-session", "-t", f"tmuxgate-{record.request_id[:12]}",
        ),
        stdin=None,
        stdout=None,
        stderr=None,
        check=False,
        env=environment,
    )
    return 0 if completed.returncode == 0 else EXIT_UNAVAILABLE


def _collect_local_result(args: argparse.Namespace) -> int:
    """Replay an already checksummed local result without contacting SSH."""

    state_dir = default_state_dir() if args.state_dir is None else Path(args.state_dir)
    with ResultSpool(state_dir) as spool:
        result = spool.load(args.request_id)
    execution = ExecutionResult(
        args.request_id,
        transport_status="complete",
        stdout=result.stdout,
        stderr=result.stderr,
        remote_exit_status=result.exit_status,
    )
    return present_result(
        execution,
        ResultFormat(args.result),
        stdout=sys.stdout.buffer,
        stderr=sys.stderr.buffer,
    )


def _running_dashboard(
    stop: threading.Event,
    terminal: TerminalArbiter,
    config_path: str,
    state_dir: str | None,
) -> None:
    """Integrated dashboard that yields idle terminal ownership to broker work."""

    menu = (
        "\nTMUXGATE RUNNING\n"
        "================\n"
        "1  List durable jobs\n"
        "2  List remote machines\n"
        "3  Add remote machine\n"
        "4  Remove remote machine\n"
        "5  Enroll this physical home network\n"
        "6  Advanced settings editor\n"
        "q  Stop tmuxgate\n"
        "Choose: "
    )
    redraw = True
    while not stop.is_set():
        if redraw:
            with terminal.claim(
                priority=TerminalPriority.DASHBOARD,
                purpose="dashboard rendering",
                flush_input=False,
            ):
                print(menu, end="", flush=True)
            redraw = False
        try:
            line = terminal.poll_dashboard_line(timeout=0.25)
        except (EOFError, KeyboardInterrupt):
            print()
            stop.set()
            return
        if line is None:
            continue
        choice = line.strip().casefold()
        if choice in {"q", "quit", "exit"}:
            stop.set()
            return
        status = 0
        with terminal.claim(
            priority=TerminalPriority.INTERACTIVE,
            purpose="dashboard operation",
        ):
            if choice == "1":
                arguments = ["jobs"]
                if state_dir is not None:
                    arguments.extend(("--state-dir", state_dir))
                status = main(arguments)
            elif choice == "2":
                status = main(["config", "list", "--path", config_path])
            elif choice == "3":
                status = main(["config", "add-machine", "--path", config_path])
            elif choice == "4":
                name = _prompt("Logical machine name to remove")
                status = main(
                    ["config", "remove-machine", name, "--path", config_path]
                )
            elif choice == "5":
                status = main(["config", "enroll-home", "--path", config_path])
            elif choice == "6":
                status = main(["config", "edit", "--path", config_path])
            else:
                print("Unknown choice.")
                redraw = True
                continue
            if status != 0:
                print(f"Operation ended with local status {status}.")
            elif choice != "1":
                print("Configuration changes take effect after tmuxgate restarts.")
        redraw = True


def _unified_command(args: argparse.Namespace) -> int:
    config_path = str(args.config)
    state_dir = None if args.state_dir is None else str(args.state_dir)
    application = UnifiedApplication(
        config_path=config_path,
        socket_path=args.socket,
        state_dir=args.state_dir,
        fake=args.fake,
        dashboard=lambda stop, terminal, config: _running_dashboard(
            stop,
            terminal,
            config_path,
            state_dir,
        ),
    )
    return application.run()


def _broker_alias_command(args: argparse.Namespace) -> int:
    print(
        "tmuxgate: 'broker' is deprecated; run 'tmuxgate' directly.",
        file=sys.stderr,
    )
    return _unified_command(args)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "config" and not hasattr(args, "path"):
        # A global --config supplied before the subcommand selects the same
        # protected file unless the legacy per-command --path overrides it.
        args.path = args.config
    try:
        handler = _unified_command if args.command is None else args.handler
        return int(handler(args))
    except RecoveryBlockedError as exc:
        print(f"tmuxgate: {exc}", file=sys.stderr)
        return EXIT_SOFTWARE
    except (ConfigError, RuntimeSecurityError) as exc:
        print(f"tmuxgate: configuration/security error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except (ValidationError, ValueError) as exc:
        print(f"tmuxgate: invalid request: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (
        ApprovalError,
        BrokerError,
        BrokerConnectionError,
        McpServerError,
        ProtocolError,
        StateError,
        SpoolError,
        TerminalError,
        OSError,
    ) as exc:
        print(f"tmuxgate: operation failed: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
