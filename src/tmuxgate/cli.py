"""Command-line entry point for the minimal automatic executor."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
from pathlib import Path
import sys

import uvicorn

from tmuxgate import __version__
from tmuxgate.config import (
    ConfigError,
    UnknownMachineError,
    default_state_dir,
    load_config,
)
from tmuxgate.credentials import CredentialError, CredentialStore, _erase
from tmuxgate.executor import ExecutionError, RemoteExecutor, sudo_access
from tmuxgate.jobs import JobStore, JobStoreError
from tmuxgate.mcp import authenticated_app, load_bearer_token
from tmuxgate.service import ExecutionService, job_view


LOGGER = logging.getLogger(__name__)
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 69
EXIT_CONFIG = 78


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tmuxgate",
        description="Automatic noninteractive SSH/tmux executor",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path, help="configuration file")
    parser.add_argument("--state-dir", type=Path, help="local state directory")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="run the loopback MCP service")
    serve.set_defaults(handler=_serve_command)

    sudo = subparsers.add_parser("sudo", help="manage whole-job sudo credentials")
    sudo_subparsers = sudo.add_subparsers(dest="sudo_command", required=True)
    for name, help_text, handler in (
        ("set", "test and save a machine password", _sudo_set_command),
        ("test", "test current sudo access", _sudo_test_command),
        ("clear", "delete a stored machine password", _sudo_clear_command),
    ):
        command = sudo_subparsers.add_parser(name, help=help_text)
        command.add_argument("machine")
        command.set_defaults(handler=handler)

    jobs = subparsers.add_parser("jobs", help="read durable local jobs")
    jobs.add_argument("job_id", nargs="?")
    jobs.add_argument("--limit", type=int, default=50)
    jobs.set_defaults(handler=_jobs_command)

    machines = subparsers.add_parser(
        "machines", help="list configured machines and destinations"
    )
    machines.set_defaults(handler=_machines_command)
    return parser


def _paths(args: argparse.Namespace) -> tuple[Path | None, Path]:
    state_dir = default_state_dir() if args.state_dir is None else args.state_dir
    return args.config, state_dir


async def _serve(args: argparse.Namespace) -> int:
    config_path, state_dir = _paths(args)
    config = load_config(config_path)
    store = JobStore(state_dir)
    credentials = CredentialStore(state_dir)
    executor = RemoteExecutor(store, credentials)
    service = ExecutionService(config, store, executor)
    token = load_bearer_token(state_dir)
    app = authenticated_app(service, token)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=config.mcp_port,
            access_log=False,
            log_level="warning",
            lifespan="on",
            ws="none",
        )
    )
    await service.start()
    LOGGER.info("tmuxgate MCP listening on 127.0.0.1:%s", config.mcp_port)
    try:
        await server.serve()
    finally:
        await service.close()
    return 0


def _serve_command(args: argparse.Namespace) -> int:
    return asyncio.run(_serve(args))


async def _sudo_set(args: argparse.Namespace) -> int:
    config_path, state_dir = _paths(args)
    destination = load_config(config_path).destination(args.machine)
    credentials = CredentialStore(state_dir)
    entered = getpass.getpass(f"Sudo password for {args.machine}: ")
    password = bytearray(entered.encode("utf-8"))
    entered = ""
    try:
        await sudo_access(credentials, args.machine, destination, password)
        credentials.save(args.machine, password)
    finally:
        _erase(password)
    print(f"Stored tested sudo credential for {args.machine}")
    return 0


def _sudo_set_command(args: argparse.Namespace) -> int:
    return asyncio.run(_sudo_set(args))


async def _sudo_test(args: argparse.Namespace) -> int:
    config_path, state_dir = _paths(args)
    destination = load_config(config_path).destination(args.machine)
    credentials = CredentialStore(state_dir)
    mode = await sudo_access(credentials, args.machine, destination)
    print(f"Sudo access for {args.machine}: {mode}")
    return 0


def _sudo_test_command(args: argparse.Namespace) -> int:
    return asyncio.run(_sudo_test(args))


def _sudo_clear_command(args: argparse.Namespace) -> int:
    config_path, state_dir = _paths(args)
    load_config(config_path).destination(args.machine)
    removed = CredentialStore(state_dir).clear(args.machine)
    status = "Cleared" if removed else "No stored"
    print(f"{status} sudo credential for {args.machine}")
    return 0


def _jobs_command(args: argparse.Namespace) -> int:
    _config_path, state_dir = _paths(args)
    store = JobStore(state_dir)
    if args.job_id is None:
        value: object = {
            "jobs": [
                job_view(job, include_result=False)
                for job in store.list(args.limit)
            ]
        }
    else:
        value = job_view(store.load(args.job_id))
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return 0


def _machines_command(args: argparse.Namespace) -> int:
    config_path, _state_dir = _paths(args)
    config = load_config(config_path)
    value = {
        "machines": [
            {"alias": alias, "destination": config.machines[alias]}
            for alias in sorted(config.machines)
        ]
    }
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "serve":
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        logging.getLogger("asyncio").setLevel(logging.WARNING)
    try:
        return int(args.handler(args))
    except UnknownMachineError as exc:
        print(f"tmuxgate: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (ConfigError, CredentialError, JobStoreError, ValueError) as exc:
        print(f"tmuxgate: configuration error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except ExecutionError as exc:
        print(f"tmuxgate: {exc.code}: {exc.detail}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    except (OSError, RuntimeError) as exc:
        print(f"tmuxgate: operation failed: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
