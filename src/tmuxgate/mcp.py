"""The four authenticated, loopback-only MCP tools."""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from tmuxgate import __version__
from tmuxgate.config import UnknownMachineError
from tmuxgate.service import ExecutionService, job_view


MAX_MCP_REQUEST_BYTES = 24 * 1024 * 1024


class BearerAuthMiddleware:
    """Reject unauthenticated HTTP before MCP parses the request."""

    def __init__(self, app: Any, token: str) -> None:
        if not isinstance(token, str) or not token or not token.isascii():
            raise ValueError("MCP bearer token must be non-empty ASCII")
        self._app = app
        self._expected = f"Bearer {token}".encode("ascii")

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return
        values = [
            value
            for name, value in scope.get("headers", ())
            if name.lower() == b"authorization"
        ]
        supplied = values[0] if len(values) == 1 else b""
        if hmac.compare_digest(supplied, self._expected):
            await self._app(scope, receive, send)
            return
        body = b'{"error":"unauthorized"}'
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"www-authenticate", b"Bearer"),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def load_bearer_token(state_dir: Path | str) -> str:
    path = Path(state_dir) / "mcp-token"
    try:
        status = path.stat(follow_symlinks=False)
        if not path.is_file() or status.st_uid != os.getuid() or status.st_mode & 0o077:
            raise ValueError(f"MCP token must be an owner-only regular file: {path}")
        token = path.read_text(encoding="ascii").strip()
    except FileNotFoundError as exc:
        raise ValueError(
            f"MCP token not found: {path}; create it with mode 0600"
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"cannot read MCP token {path}: {exc}") from exc
    if not token or not token.isascii() or any(character.isspace() for character in token):
        raise ValueError("MCP token must be non-empty ASCII without whitespace")
    return token


def _unknown_machine(exc: UnknownMachineError) -> dict[str, object]:
    return {
        "error_code": "unknown_machine",
        "error_detail": str(exc),
        "configured_aliases": list(exc.aliases),
    }


def create_mcp_server(service: ExecutionService) -> MCPServer:
    server = MCPServer(
        "tmuxgate",
        version=__version__,
        instructions=(
            "Run noninteractive commands on exact configured machine aliases. "
            "A disconnected or timed-out run may continue remotely; use get_job "
            "or list_jobs to recover it. Use sudo=true for whole-job sudo."
        ),
        log_level="WARNING",
    )

    @server.tool(
        name="run_argv",
        description="Run exact argv in one persistent remote tmux job.",
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=False,
            open_world_hint=True,
        ),
        structured_output=True,
    )
    async def run_argv(
        machine: str,
        cwd: str,
        argv: list[str],
        environment: dict[str, str] | None = None,
        timeout: float | None = None,
        sudo: bool = False,
    ) -> dict[str, object]:
        try:
            return job_view(
                await service.run_argv(
                    machine, cwd, argv, environment, timeout, sudo
                )
            )
        except UnknownMachineError as exc:
            return _unknown_machine(exc)
        except (TypeError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        name="run_script",
        description="Run one UTF-8 shell script in a persistent remote tmux job.",
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=True,
            idempotent_hint=False,
            open_world_hint=True,
        ),
        structured_output=True,
    )
    async def run_script(
        machine: str,
        cwd: str,
        script: str,
        environment: dict[str, str] | None = None,
        timeout: float | None = None,
        sudo: bool = False,
    ) -> dict[str, object]:
        try:
            return job_view(
                await service.run_script(
                    machine, cwd, script, environment, timeout, sudo
                )
            )
        except UnknownMachineError as exc:
            return _unknown_machine(exc)
        except (TypeError, ValueError) as exc:
            raise ToolError(str(exc)) from exc

    @server.tool(
        name="get_job",
        description="Read one durable job and its collected result when complete.",
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
        structured_output=True,
    )
    async def get_job(job_id: str) -> dict[str, object]:
        try:
            return job_view(service.get_job(job_id))
        except (FileNotFoundError, ValueError) as exc:
            raise ToolError(f"job not found: {job_id}") from exc

    @server.tool(
        name="list_jobs",
        description="List recent durable jobs so interrupted callers can rediscover IDs.",
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
        structured_output=True,
    )
    async def list_jobs(limit: int = 50) -> dict[str, object]:
        try:
            return {
                "jobs": [
                    job_view(job, include_result=False)
                    for job in service.list_jobs(limit)
                ]
            }
        except ValueError as exc:
            raise ToolError(str(exc)) from exc

    return server


def authenticated_app(service: ExecutionService, token: str) -> BearerAuthMiddleware:
    mcp = create_mcp_server(service)
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        max_request_body_size=MAX_MCP_REQUEST_BYTES,
        host="127.0.0.1",
    )
    return BearerAuthMiddleware(app, token)
