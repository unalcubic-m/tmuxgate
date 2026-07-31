"""Public command-line surface for the local approval broker and clients."""

from __future__ import annotations

import argparse
from dataclasses import replace
import ipaddress
import json
import os
from pathlib import Path
import signal
import secrets
import stat
import subprocess
import sys
import threading
from types import MappingProxyType
from typing import BinaryIO, Callable

from tmuxgate import __version__
from tmuxgate.approval import (
    ApprovalDecision,
    ApprovalError,
    open_approval_terminal,
    request_approval,
    request_fallback_approval,
)
from tmuxgate.broker import BrokerServer
from tmuxgate.client import BrokerConnectionError, submit_request
from tmuxgate.config import (
    ConfigError,
    Endpoint,
    HomeFingerprint,
    Machine,
    default_config_path,
    load_config,
)
from tmuxgate.fake import FakeExecution
from tmuxgate.executor import RealExecutor
from tmuxgate.models import (
    MAX_SCRIPT_BYTES,
    ExecutionMode,
    RequestSpec,
    ResultFormat,
    ValidationError,
    validate_alias,
)
from tmuxgate.network_collect import collect_network_snapshot
from tmuxgate.protocol import ProtocolError
from tmuxgate.planning import BoundRequestPlanner
from tmuxgate.real_remote import RealRemoteJobBackend
from tmuxgate.real_ssh import (
    SecretPromptPresenter,
    SshChannelRunner,
    SubprocessMasterBackend,
)
from tmuxgate.result import ExecutionResult, relay_transparent
from tmuxgate.runtime import (
    RuntimeSecurityError,
    acquire_broker_lock,
    default_socket_path,
    default_state_dir,
    open_broker_listener,
    prepare_runtime_layout,
)
from tmuxgate.scheduler import RequestState
from tmuxgate.state import (
    DurableStateStore,
    StateConflictError,
    StateError,
    recover_startup,
)
from tmuxgate.spool import ResultSpool, SpoolError
from tmuxgate.ssh import ResolvedSshEndpoint, resolve_ssh_endpoint
from tmuxgate.ssh_key import AutoSshKeyManager
from tmuxgate.settings import publish_config
from tmuxgate.transport import MasterTransportPool


EXIT_USAGE = 64
EXIT_UNAVAILABLE = 69
EXIT_SOFTWARE = 70
EXIT_CONFIG = 78


def _add_local_paths(parser: argparse.ArgumentParser, *, config: bool = False) -> None:
    parser.add_argument(
        "--socket",
        default=None,
        help=f"broker Unix socket (default: {default_socket_path() if os.environ.get('XDG_RUNTIME_DIR') else '$XDG_RUNTIME_DIR/tmuxgate/broker.sock'})",
    )
    if config:
        parser.add_argument(
            "--config",
            default=str(default_config_path()),
            help="protected host configuration (default: %(default)s)",
        )


def _add_request_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("host", help="configured logical machine name")
    parser.add_argument("--cwd", required=True, help="absolute remote working directory")
    parser.add_argument(
        "--purpose",
        default=None,
        help="short advisory explanation shown beside the exact command",
    )
    parser.add_argument("--timeout", type=int, default=None, help="requested command timeout")
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="environment variable to add; repeat as needed",
    )
    parser.add_argument(
        "--result",
        choices=("transparent", "json"),
        default="transparent",
        help="result presentation (default: %(default)s)",
    )
    _add_local_paths(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tmuxgate",
        description="Owner-controlled broker for isolated remote tmux jobs",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    config_parser = subparsers.add_parser("config", help="configuration tools")
    config_subparsers = config_parser.add_subparsers(dest="config_command", required=True)
    check_parser = config_subparsers.add_parser("check", help="validate protected config")
    check_parser.add_argument("--path", default=str(default_config_path()))
    check_parser.set_defaults(handler=_config_check)
    list_parser = config_subparsers.add_parser(
        "list", help="show configured remote machine names and endpoints"
    )
    list_parser.add_argument("--path", default=str(default_config_path()))
    list_parser.set_defaults(handler=_config_list)
    path_parser = config_subparsers.add_parser(
        "path", help="show the active configuration file path"
    )
    path_parser.add_argument("--path", default=str(default_config_path()))
    path_parser.set_defaults(handler=_config_path)
    edit_parser = config_subparsers.add_parser(
        "edit", help="edit and validate settings in the terminal"
    )
    edit_parser.add_argument("--path", default=str(default_config_path()))
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
    broker_settings_parser.add_argument("--path", default=str(default_config_path()))
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
    add_parser.add_argument("--path", default=str(default_config_path()))
    add_parser.set_defaults(handler=_config_add_machine)
    remove_parser = config_subparsers.add_parser(
        "remove-machine", help="remove one logical machine from local settings"
    )
    remove_parser.add_argument("name")
    remove_parser.add_argument("--yes", action="store_true")
    remove_parser.add_argument("--path", default=str(default_config_path()))
    remove_parser.set_defaults(handler=_config_remove_machine)
    enroll_parser = config_subparsers.add_parser(
        "enroll-home", help="learn the directly connected physical home network"
    )
    enroll_parser.add_argument("--id", default=None)
    enroll_parser.add_argument("--yes", action="store_true")
    enroll_parser.add_argument("--path", default=str(default_config_path()))
    enroll_parser.set_defaults(handler=_config_enroll_home)

    exec_parser = subparsers.add_parser("exec", help="submit structured argv")
    _add_request_options(exec_parser)
    exec_parser.add_argument(
        "argv",
        nargs="+",
        metavar="COMMAND",
        help="command and arguments following --",
    )
    exec_parser.set_defaults(handler=_exec_command)

    script_parser = subparsers.add_parser("script", help="submit exact script bytes")
    _add_request_options(script_parser)
    source = script_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="read exact script bytes from a local file")
    source.add_argument("--stdin", action="store_true", help="read exact script bytes from stdin")
    script_parser.set_defaults(handler=_script_command)

    broker_parser = subparsers.add_parser("broker", help="run the interactive broker")
    _add_local_paths(broker_parser, config=True)
    broker_parser.add_argument("--state-dir", default=None)
    broker_parser.add_argument(
        "--fake",
        action="store_true",
        help="run local canned fake execution; never opens SSH",
    )
    broker_parser.set_defaults(handler=_broker_command)

    jobs_parser = subparsers.add_parser("jobs", help="list durable local job records")
    jobs_parser.add_argument("--state-dir", default=None)
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
        help="record that a full machine reboot abandoned an uncertain request",
    )
    after_reboot_parser.add_argument("request_id")
    after_reboot_parser.add_argument("--state-dir", default=None)
    _add_local_paths(after_reboot_parser)
    after_reboot_parser.set_defaults(handler=_recover_after_reboot)
    after_dead_pane_parser = recover_subparsers.add_parser(
        "after-dead-pane",
        help="record that the operator visibly observed the dedicated pane dead",
    )
    after_dead_pane_parser.add_argument("request_id")
    after_dead_pane_parser.add_argument("--state-dir", default=None)
    _add_local_paths(after_dead_pane_parser)
    after_dead_pane_parser.set_defaults(handler=_recover_after_dead_pane)

    for name, help_text in (
        ("attach", "attach to an existing dedicated job"),
        ("collect", "collect a proven-complete job"),
        ("cleanup", "clean a verified inactive job"),
    ):
        control = subparsers.add_parser(name, help=help_text)
        control.add_argument("request_id")
        _add_local_paths(control)
        if name in {"attach", "collect"}:
            control.add_argument("--state-dir", default=None)
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
    print(
        "configuration valid: "
        f"{len(config.machines)} machines, "
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
        print(f"{machine.name}  user={machine.user}  {machine.description}")
        for endpoint in machine.endpoints:
            print(
                f"  - {endpoint.id:<12} {endpoint.address}:{endpoint.port} "
                f"when={endpoint.required_context}"
            )
    print("\nEdit: tmuxgate config edit")
    print("Restart a running broker after changing settings.")
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
    publish_config(path, updated)
    print(
        "Broker settings updated: "
        f"approval_mode={updated.broker.approval_mode}, "
        f"max_active_remote_commands={updated.broker.max_active_remote_commands}."
    )
    print("Restart a running broker to load them.")
    return 0


def _config_edit(args: argparse.Namespace) -> int:
    """Edit a private temporary copy and publish only valid configuration."""

    path = Path(args.path).expanduser()
    if not path.is_absolute():
        raise ConfigError("configuration path must be absolute")
    load_config(path)
    content = path.read_bytes()
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

    published = False
    try:
        while True:
            completed = subprocess.run(
                ("/usr/bin/nano", "--", os.fspath(temporary)),
                stdin=None,
                stdout=None,
                stderr=None,
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
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            published = True
            print(
                f"Settings valid: {len(config.machines)} machines. "
                "Restart the broker to load them."
            )
            return 0
    finally:
        if not published:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _prompt(label: str, *, default: str | None = None, allow_empty: bool = False) -> str:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        try:
            value = input(f"{label}{suffix}: ")
        except EOFError as exc:
            raise ConfigError("settings input ended before completion") from exc
        if not value and default is not None:
            return default
        if value or allow_empty:
            return value
        print("A value is required.")


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
    publish_config(path, replace(config, machines=MappingProxyType(machines)))
    print(f"Added {name}. Restart the broker to load the new machine.")
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
    publish_config(path, replace(config, machines=MappingProxyType(machines)))
    print(f"Removed {name} from local settings. No remote machine was contacted.")
    return 0


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
    publish_config(path, replace(config, home=updated_home))
    print(f"Enrolled {fingerprint_id}. Restart the broker to use home-LAN routing.")
    return 0


def _environment(values: list[str]) -> tuple[tuple[str, str], ...]:
    entries: list[tuple[str, str]] = []
    for value in values:
        name, separator, content = value.partition("=")
        if not separator:
            raise ValidationError("--env values must use NAME=VALUE")
        entries.append((name, content))
    return tuple(entries)


def _request_common(args: argparse.Namespace) -> dict[str, object]:
    return {
        "machine_alias": args.host,
        "cwd": args.cwd,
        "environment": _environment(args.env),
        "timeout_seconds": args.timeout,
        "result_format": ResultFormat(args.result),
        "purpose": args.purpose,
    }


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


def _exec_command(args: argparse.Namespace) -> int:
    argv = tuple(args.argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        raise ValidationError("exec requires a command after --")
    request = RequestSpec(mode=ExecutionMode.ARGV, argv=argv, **_request_common(args))
    return submit_and_present(request, socket_path=args.socket)


def _read_bounded(stream: BinaryIO) -> bytes:
    content = stream.read(MAX_SCRIPT_BYTES + 1)
    if len(content) > MAX_SCRIPT_BYTES:
        raise ValidationError(f"script exceeds {MAX_SCRIPT_BYTES} bytes")
    return content


def _script_command(args: argparse.Namespace) -> int:
    if args.stdin:
        script = _read_bounded(sys.stdin.buffer)
    else:
        with open(args.file, "rb") as source:
            script = _read_bounded(source)
    request = RequestSpec(
        mode=ExecutionMode.SCRIPT,
        script=script,
        **_request_common(args),
    )
    return submit_and_present(request, socket_path=args.socket)


class _ZeroFakeExecutor:
    def __call__(self, request_id: str, request: RequestSpec) -> FakeExecution:
        # Never inspect or execute request contents.
        return FakeExecution()


def _approve_without_prompt(*args: object) -> ApprovalDecision:
    """Honor the owner-controlled disabled approval mode."""

    return ApprovalDecision.APPROVED


def _broker_command(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    paths = prepare_runtime_layout(socket_path=args.socket, state_dir=args.state_dir)
    with DurableStateStore(paths.state_dir) as store, ResultSpool(paths.state_dir) as spool:
        recovery = recover_startup(store)
        if not recovery.safe_to_accept_new_approvals:
            blocked = ", ".join(recovery.blocking_request_ids)
            print(f"tmuxgate: recovery blocks new approvals: {blocked}", file=sys.stderr)
            return EXIT_SOFTWARE
        with open_broker_listener(paths.socket_path) as lifecycle:
            pool = None
            executor = None
            prompt_presenter = None
            if args.fake:
                approver = (
                    request_approval
                    if config.broker.approval_mode == "always"
                    else _approve_without_prompt
                )
                selected_executor = _ZeroFakeExecutor()
                approval_discarder = lambda request_id: None
                delivery_observer = lambda request_id, delivered: None
            else:
                terminal_lock = threading.RLock()
                if config.broker.approval_mode == "always":
                    planner = BoundRequestPlanner(config)

                    def serialized_planner(
                        request_id: str,
                        request: RequestSpec,
                    ) -> ApprovalDecision:
                        with terminal_lock:
                            return planner(request_id, request)

                    approver = serialized_planner
                else:
                    planner = BoundRequestPlanner(
                        config, approver=_approve_without_prompt
                    )
                    approver = planner

                def revalidate(resolved: ResolvedSshEndpoint) -> ResolvedSshEndpoint:
                    machine = config.machines[resolved.machine_name]
                    endpoint = next(
                        item for item in machine.endpoints
                        if item.id == resolved.endpoint_id
                    )
                    return resolve_ssh_endpoint(machine, endpoint)

                pool = MasterTransportPool(
                    paths.control_dir,
                    backend=SubprocessMasterBackend(
                        terminal_lock=terminal_lock
                    ),
                    identity_revalidator=revalidate,
                    max_masters=config.broker.max_open_ssh_masters,
                    idle_timeout_seconds=(
                        config.broker.ssh_master_idle_timeout_seconds
                    ),
                    key_manager=AutoSshKeyManager(),
                )
                prompt_presenter = SecretPromptPresenter(
                    terminal_lock=terminal_lock,
                    reporter=lambda message: print(
                        f"tmuxgate: {message}", file=sys.stderr, flush=True
                    ),
                )
                channels = SshChannelRunner(
                    prompt_presenter=prompt_presenter
                )

                def serialized_fallback_approval(
                    *arguments: object,
                    **keywords: object,
                ) -> ApprovalDecision:
                    with terminal_lock:
                        return request_fallback_approval(
                            *arguments, **keywords
                        )

                executor = RealExecutor(
                    planner=planner,
                    transports=pool,
                    state=store,
                    spool=spool,
                    backend_factory=lambda transport: RealRemoteJobBackend(
                        transport,
                        channels=channels,
                        viewer_dir=paths.viewer_dir,
                    ),
                    fallback_approver=(
                        serialized_fallback_approval
                        if config.broker.approval_mode == "always"
                        else _approve_without_prompt
                    ),
                )
                selected_executor = executor
                approval_discarder = executor.discard_approval
                delivery_observer = executor.result_delivery_finished
            server = BrokerServer(
                lifecycle.listener,
                allowed_machines=config.machines,
                approver=approver,
                executor=selected_executor,
                max_pending_requests=config.broker.max_pending_requests,
                max_active_remote_commands=(
                    config.broker.max_active_remote_commands
                ),
                approval_discarder=approval_discarder,
                delivery_observer=delivery_observer,
            )
            stop = threading.Event()

            def request_stop(signum: int, frame: object) -> None:
                stop.set()

            previous = {
                number: signal.signal(number, request_stop)
                for number in (signal.SIGINT, signal.SIGTERM)
            }
            try:
                server.start()
                kind = "fake" if args.fake else "real"
                print(f"tmuxgate {kind} broker listening on {lifecycle.socket_path}")
                print("Configured machines: " + ", ".join(config.machines))
                print(f"Approval mode: {config.broker.approval_mode}")
                if config.broker.approval_mode == "disabled":
                    print(
                        "WARNING: owner-authorized same-UID requests run without "
                        "per-command approval."
                    )
                print("Settings: tmuxgate config list | tmuxgate config edit")
                while not stop.wait(0.25):
                    pass
            finally:
                clean = server.stop()
                if prompt_presenter is not None:
                    clean = prompt_presenter.close() and clean
                if pool is not None:
                    try:
                        pool.close_idle()
                    except BaseException as exc:
                        clean = False
                        print(
                            f"tmuxgate: could not close all idle SSH masters: {exc}",
                            file=sys.stderr,
                        )
                for number, handler in previous.items():
                    signal.signal(number, handler)
            return 0 if clean else EXIT_SOFTWARE


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
    with DurableStateStore(state_dir) as store:
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
            f"generation: {record.generation}\n"
            f"failure:    {json.dumps(record.failure_detail, ensure_ascii=True)}\n\n"
            "Use this only after the entire named machine was rebooted after the "
            "start time above. This records an abandoned execution. It does NOT "
            "claim a remote exit status, completed output, or a verified result "
            "spool, and it does not contact or clean the remote machine.\n\n"
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
    with acquire_broker_lock(paths.runtime_dir):
        with DurableStateStore(paths.state_dir) as store:
            record = store.load(args.request_id)
            if record.state is not RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING:
                raise StateConflictError(
                    "after-reboot recovery requires an exact recovery-blocked request"
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
    with acquire_broker_lock(paths.runtime_dir):
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


def _interactive_menu() -> int:
    """Small terminal dashboard for ordinary personal operation."""

    while True:
        print(
            "\nTMUXGATE\n"
            "========\n"
            "1  Start execution broker\n"
            "2  List remote machines\n"
            "3  Add remote machine\n"
            "4  Remove remote machine\n"
            "5  Enroll this physical home network\n"
            "6  Advanced settings editor\n"
            "q  Quit\n"
        )
        try:
            choice = input("Choose [1]: ").strip().casefold() or "1"
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice in {"q", "quit", "exit"}:
            return 0
        if choice == "1":
            print("Starting broker. Press Ctrl-C to return to this menu.\n")
            status = main(["broker"])
        elif choice == "2":
            status = main(["config", "list"])
        elif choice == "3":
            status = main(["config", "add-machine"])
        elif choice == "4":
            name = _prompt("Logical machine name to remove")
            status = main(["config", "remove-machine", name])
        elif choice == "5":
            status = main(["config", "enroll-home"])
        elif choice == "6":
            status = main(["config", "edit"])
        else:
            print("Unknown choice.")
            continue
        if status != 0:
            print(f"Operation ended with local status {status}.")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        return _interactive_menu()
    try:
        return int(args.handler(args))
    except (ConfigError, RuntimeSecurityError) as exc:
        print(f"tmuxgate: configuration/security error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except (ValidationError, ValueError) as exc:
        print(f"tmuxgate: invalid request: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (
        ApprovalError,
        BrokerConnectionError,
        ProtocolError,
        StateError,
        SpoolError,
        OSError,
    ) as exc:
        print(f"tmuxgate: operation failed: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
