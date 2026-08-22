from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Any, cast
import unittest

from mcp.types import CallToolResult

from tmuxgate.config import Config
from tmuxgate.credentials import CredentialStore
from tmuxgate.executor import RemoteExecutor
from tmuxgate.jobs import JobStore
from tmuxgate.mcp import BearerAuthMiddleware, create_mcp_server, load_bearer_token
from tmuxgate.service import ExecutionService


class McpSurfaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_four_tools_exist_and_unknown_aliases_are_returned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = JobStore(Path(directory) / "state")
            credentials = CredentialStore(Path(directory) / "state")
            service = ExecutionService(
                Config({"exact": "exact"}),
                store,
                RemoteExecutor(store, credentials),
            )
            server = create_mcp_server(service)
            tools = await server.list_tools()
            self.assertEqual(
                {tool.name for tool in tools},
                {"run_argv", "run_script", "get_job", "list_jobs"},
            )
            by_name = {tool.name: tool for tool in tools}
            run_annotations = by_name["run_argv"].annotations
            get_annotations = by_name["get_job"].annotations
            self.assertIsNotNone(run_annotations)
            self.assertIsNotNone(get_annotations)
            assert run_annotations is not None
            assert get_annotations is not None
            self.assertFalse(run_annotations.read_only_hint)
            self.assertTrue(run_annotations.destructive_hint)
            self.assertFalse(get_annotations.destructive_hint)
            self.assertTrue(get_annotations.read_only_hint)
            result = await server.call_tool(
                "run_argv",
                {
                    "machine": "Exact",
                    "cwd": "/tmp",
                    "argv": ["true"],
                },
            )
            self.assertIsInstance(result, CallToolResult)
            result = cast(CallToolResult, result)
            self.assertIsNotNone(result.structured_content)
            assert result.structured_content is not None
            self.assertEqual(result.structured_content["error_code"], "unknown_machine")
            self.assertEqual(result.structured_content["configured_aliases"], ["exact"])
            script_result = await server.call_tool(
                "run_script",
                {"machine": "missing", "cwd": "/tmp", "script": "true"},
            )
            self.assertIsInstance(script_result, CallToolResult)
            script_result = cast(CallToolResult, script_result)
            self.assertIsNotNone(script_result.structured_content)
            assert script_result.structured_content is not None
            self.assertEqual(
                script_result.structured_content["error_code"], "unknown_machine"
            )
            listed = await server.call_tool("list_jobs", {})
            self.assertIsInstance(listed, CallToolResult)
            listed = cast(CallToolResult, listed)
            self.assertEqual(listed.structured_content, {"jobs": []})

    async def test_bearer_guard_rejects_missing_wrong_and_duplicate_headers(self) -> None:
        reached: list[bool] = []

        async def downstream(scope: Any, receive: Any, send: Any) -> None:
            reached.append(True)
            await send({"type": "http.response.start", "status": 204, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        app = BearerAuthMiddleware(downstream, "secret-token")

        async def status(headers: list[tuple[bytes, bytes]]) -> int:
            messages: list[dict[str, Any]] = []

            async def receive() -> dict[str, Any]:
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message: dict[str, Any]) -> None:
                messages.append(message)

            await app({"type": "http", "headers": headers}, receive, send)
            return int(messages[0]["status"])

        self.assertEqual(await status([]), 401)
        self.assertEqual(await status([(b"authorization", b"Bearer wrong")]), 401)
        self.assertEqual(
            await status(
                [
                    (b"authorization", b"Bearer secret-token"),
                    (b"authorization", b"Bearer secret-token"),
                ]
            ),
            401,
        )
        self.assertEqual(
            await status([(b"authorization", b"Bearer secret-token")]), 204
        )
        self.assertEqual(reached, [True])


class TokenTests(unittest.TestCase):
    def test_token_file_must_be_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            path = state / "mcp-token"
            path.write_text("token-value\n", encoding="ascii")
            path.chmod(0o600)
            self.assertEqual(load_bearer_token(state), "token-value")
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                load_bearer_token(state)


if __name__ == "__main__":
    unittest.main()
