"""Authorized pane input with synthetic SSH; never target a real terminal."""

from __future__ import annotations

import asyncio
from pathlib import Path
import shlex
import tempfile
from typing import Any, cast
import unittest
from unittest.mock import AsyncMock, patch

from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult

from tmuxgate import pane_input, ssh
from tmuxgate.config import Config
from tmuxgate.credentials import CredentialStore
from tmuxgate.executor import RemoteExecutor
from tmuxgate.jobs import JobStore
from tmuxgate.mcp import create_mcp_server
from tmuxgate.service import ExecutionService


ROW = b"12:1700000000\t$0\t@3\t%3\t24\t80\t999\n"
TARGET = ("12:1700000000", "$0", "@3", "%3", 999)


def response(stdout: bytes = ROW, code: int = 0, stderr: bytes = b"") -> ssh.SSHResult:
    return ssh.SSHResult(code, stdout, stderr)


class PaneInputTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        store = JobStore(Path(self.temporary.name) / "private state")
        self.service = ExecutionService(Config({"exact": "ssh-alias", "duplicate": "ssh-alias"}), store, RemoteExecutor(store, CredentialStore(store.state_dir)))
        self.addAsyncCleanup(self.service.close)

    async def test_literal_unicode_and_hostile_text_are_only_hex_bytes(self) -> None:
        text = "\u00e7\u0131kt\u0131 'quoted' \"double\" $HOME $(touch nope); #{pane_id} Enter"
        boundary = AsyncMock(side_effect=[response(), response(pane_input.SENT)])
        with patch("tmuxgate.ssh.run", boundary):
            result = await self.service.send_tmux_text("exact", *TARGET, text)
        self.assertEqual(result["status"], "sent")
        self.assertFalse(result["retryable"])
        self.assertEqual(self.service.list_jobs(), [])
        arguments = boundary.call_args_list[1].args[1]
        self.assertEqual(arguments[:5], ["tmux", "-u", "if-shell", "-F", "-t"])
        self.assertEqual(arguments[5], "$0:@3.%3")
        self.assertNotIn(text, ssh.remote_command(arguments))
        self.assertEqual(shlex.split(ssh.remote_command(arguments)), arguments)
        command = arguments[7]
        literal = command.split(" ; ")[0]
        tokens = shlex.split(literal)
        self.assertEqual(tokens[:4], ["send-keys", "-H", "-t", "%3"])
        self.assertEqual(bytes.fromhex(" ".join(tokens[4:])), text.encode())
        self.assertNotIn("send-keys -t %3 Enter", command)
        for variable in ("pid", "start_time", "session_id", "window_id", "pane_id", "pane_pid", "pane_dead", "pane_in_mode"):
            self.assertIn("#{" + variable + "}", arguments[6])
        self.assertEqual(boundary.await_count, 2)

    async def test_multiline_and_submit_are_explicit(self) -> None:
        with patch("tmuxgate.ssh.run", AsyncMock()) as boundary:
            with self.assertRaises(ValueError):
                await self.service.send_tmux_text("exact", *TARGET, "one\ntwo")
            boundary.assert_not_awaited()
        boundary = AsyncMock(side_effect=[response(), response(pane_input.SENT)])
        with patch("tmuxgate.ssh.run", boundary):
            await self.service.send_tmux_text("exact", *TARGET, "one\ntwo", multiline=True, submit=True)
        command = boundary.call_args_list[1].args[1][7]
        self.assertIn("6f 6e 65 0a 74 77 6f", command)
        self.assertIn(" ; send-keys -t %3 Enter ; ", command)

    async def test_explicit_key_is_one_allowlisted_event(self) -> None:
        for key in pane_input.KEYS:
            boundary = AsyncMock(side_effect=[response(), response(pane_input.SENT)])
            with self.subTest(key=key), patch("tmuxgate.ssh.run", boundary):
                result = await self.service.send_tmux_key("exact", *TARGET, key)
                self.assertEqual(result["status"], "sent")
                self.assertEqual(boundary.call_args_list[1].args[1][7], f"send-keys -t %3 {key} ; display-message -p TMUXGATE_INPUT_SENT_V1")

    async def test_invalid_ids_keys_text_controls_and_bounds_never_start_ssh(self) -> None:
        with patch("tmuxgate.ssh.run", AsyncMock()) as boundary:
            for text in ("", "\x00", "\r", "\x1b", "\t", "\x7f", "\u009b", "\ud800", "x" * 4097, "\u00e7" * 2049):
                with self.subTest(text=repr(text[:5])), self.assertRaises(ValueError):
                    await self.service.send_tmux_text("exact", *TARGET, text, multiline=True)
            for key in ("Enter C-c", "Enter;kill-server", "enter", "-X", "prefix", "\n", ""):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    await self.service.send_tmux_key("exact", *TARGET, key)
            for target in ((TARGET[0], "name;send-keys", "@3", "%3", 999), (TARGET[0], "$0", "@3", "%3", True), ("12:1700000000;bad", "$0", "@3", "%3", 999)):
                with self.assertRaises(ValueError):
                    await self.service.send_tmux_key("exact", *target, "Enter")
            for options in ({"multiline": 1}, {"submit": "yes"}, {"timeout": float("nan")}):
                with self.assertRaises(ValueError):
                    await self.service.send_tmux_text("exact", *TARGET, "hello", **cast(Any, options))
            boundary.assert_not_awaited()
        # Bound uses UTF-8 bytes, not characters, and accepts its exact edge.
        self.assertEqual(len(pane_input.text_keys("\u00e7" * 2048, False, False).split()), 4096)

    async def test_missing_restarted_respawned_or_relocated_pane_is_not_sent(self) -> None:
        for row in (b"", ROW.replace(b"12:", b"13:"), ROW.replace(b"$0", b"$1"), ROW.replace(b"@3", b"@4"), ROW.replace(b"%3", b"%4"), ROW.replace(b"999", b"1000")):
            boundary = AsyncMock(return_value=response(row))
            with self.subTest(row=row), patch("tmuxgate.ssh.run", boundary):
                result = await self.service.send_tmux_key("exact", *TARGET, "Enter")
                self.assertEqual((result["status"], result["error_code"]), ("not_sent", "stale_target"))
                self.assertEqual(boundary.await_count, 1)

    async def test_guard_can_reject_a_target_changed_after_discovery(self) -> None:
        boundary = AsyncMock(side_effect=[response(), response(pane_input.REJECTED)])
        with patch("tmuxgate.ssh.run", boundary):
            result = await self.service.send_tmux_text("exact", *TARGET, "hello")
        self.assertEqual((result["status"], result["error_code"]), ("not_sent", "stale_target"))
        self.assertFalse(result["retryable"])
        self.assertEqual(boundary.await_count, 2)

    async def test_preflight_ssh_error_is_not_sent(self) -> None:
        boundary = AsyncMock(return_value=response(b"", 255, b"private SSH diagnostic"))
        with patch("tmuxgate.ssh.run", boundary):
            result = await self.service.send_tmux_key("exact", *TARGET, "Enter")
        self.assertEqual((result["status"], result["error_code"]), ("not_sent", "ssh_failed"))
        self.assertNotIn("private SSH diagnostic", str(result))
        self.assertEqual(boundary.await_count, 1)

    async def test_disconnect_partial_ack_errors_and_overflow_are_unknown_never_retried(self) -> None:
        cases = [response(b"", 255), response(pane_input.SENT, 1), response(pane_input.SENT[:-1]),
                 response(pane_input.SENT, 0, b"unexpected"), OSError("private detail"),
                 ssh.OutputLimitError("overflow"), RuntimeError("unexpected local failure")]
        for reply in cases:
            boundary = AsyncMock(side_effect=[response(), reply])
            with self.subTest(reply=reply), patch("tmuxgate.ssh.run", boundary):
                result = await self.service.send_tmux_text("exact", *TARGET, "secret prompt", submit=True)
                self.assertEqual((result["status"], result["error_code"]), ("unknown", "dispatch_unknown"))
                self.assertFalse(result["retryable"])
                self.assertNotIn("private detail", str(result))
                self.assertNotIn("secret prompt", str(result))
                self.assertEqual(boundary.await_count, 2)
        self.assertEqual(self.service._pane_writers, set())

    async def test_timeout_before_dispatch_differs_from_timeout_after_dispatch(self) -> None:
        calls = []

        async def boundary(*args, **kwargs):
            calls.append(args)
            if len(calls) == 1:
                return response()
            await asyncio.Event().wait()

        with patch("tmuxgate.ssh.run", boundary):
            result = await self.service.send_tmux_key("exact", *TARGET, "Enter", timeout=0.02)
        self.assertEqual((result["status"], result["error_code"]), ("unknown", "dispatch_unknown"))
        self.assertEqual(len(calls), 2)
        with patch("tmuxgate.ssh.run", AsyncMock()) as ssh_boundary:
            async with self.service._semaphore:
                async with self.service._semaphore:
                    async with self.service._semaphore:
                        result = await self.service.send_tmux_key("exact", *TARGET, "Enter", timeout=0.02)
            self.assertEqual((result["status"], result["error_code"]), ("not_sent", "input_timeout"))
            ssh_boundary.assert_not_awaited()
        self.assertEqual(self.service._pane_writers, set())

    async def test_concurrent_writers_to_linked_pane_or_duplicate_alias_are_rejected(self) -> None:
        entered = asyncio.Event()
        release = asyncio.Event()

        async def boundary(destination, arguments, **kwargs):
            if arguments[0] == "/bin/sh":
                return response()
            entered.set()
            await release.wait()
            return response(pane_input.SENT)

        with patch("tmuxgate.ssh.run", boundary):
            first = asyncio.create_task(self.service.send_tmux_text("exact", *TARGET, "first", submit=True))
            try:
                await asyncio.wait_for(entered.wait(), 1)
                for alias, session in (("exact", "$0"), ("duplicate", "$1")):
                    second = await self.service.send_tmux_key(alias, TARGET[0], session, "@3", "%3", 999, "Enter")
                    self.assertEqual((second["status"], second["error_code"]), ("not_sent", "pane_busy"))
            finally:
                release.set()
                self.assertEqual((await first)["status"], "sent")
        self.assertEqual(self.service._pane_writers, set())

    async def test_cancelled_request_does_not_resend_and_releases_writer(self) -> None:
        entered = asyncio.Event()
        calls = 0

        async def boundary(destination, arguments, **kwargs):
            nonlocal calls
            calls += 1
            if arguments[0] == "/bin/sh":
                return response()
            entered.set()
            await asyncio.Event().wait()

        with patch("tmuxgate.ssh.run", boundary):
            task = asyncio.create_task(self.service.send_tmux_key("exact", *TARGET, "Enter"))
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(calls, 2)
        self.assertEqual(self.service._pane_writers, set())

    async def test_closed_service_does_not_dispatch(self) -> None:
        await self.service.close()
        with patch("tmuxgate.ssh.run", AsyncMock()) as boundary:
            with self.assertRaises(RuntimeError):
                await self.service.send_tmux_key("exact", *TARGET, "Enter")
            boundary.assert_not_awaited()

    async def test_mcp_write_metadata_errors_and_structured_outcomes(self) -> None:
        server = create_mcp_server(self.service)
        target = dict(zip(("server_id", "session_id", "window_id", "pane_id", "pane_pid"), TARGET))
        arguments = {"machine": "exact", **target, "text": "hello", "submit": True}
        boundary = AsyncMock(side_effect=[response(), response(pane_input.SENT)])
        with patch("tmuxgate.ssh.run", boundary):
            result = cast(CallToolResult, await server.call_tool("send_tmux_text", arguments))
            assert result.structured_content is not None
            self.assertEqual(result.structured_content["status"], "sent")
        with patch("tmuxgate.ssh.run", AsyncMock()) as ssh_boundary:
            missing = cast(CallToolResult, await server.call_tool("send_tmux_key", {"machine": "missing", **target, "key": "Enter"}))
            assert missing.structured_content is not None
            self.assertEqual(missing.structured_content["status"], "not_sent")
            self.assertEqual(missing.structured_content["error_code"], "unknown_machine")
            with self.assertRaises(ToolError):
                await server.call_tool("send_tmux_text", {**arguments, "text": "one\ntwo"})
            with self.assertRaises(ToolError):
                await server.call_tool("send_tmux_key", {"machine": "exact", **target, "key": "not-a-key"})
            ssh_boundary.assert_not_awaited()
