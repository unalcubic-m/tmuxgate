from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import os
from pathlib import Path
import stat
import tempfile
from types import MappingProxyType
import unittest
from unittest import mock

from tmuxgate import cli
from tmuxgate.config import (
    default_config_path,
    load_config,
    load_config_snapshot,
    parse_config,
)
from tmuxgate.network import NetworkSnapshot
from tmuxgate.settings import (
    ConfigWriteConflictError,
    publish_edited_config,
    serialize_config,
    set_approval_mode,
    set_machine_enabled,
)
from test_config import valid_config
from test_connection_plan import complete_snapshot


class SettingsCommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "config"
        self.root.mkdir(mode=0o700)
        self.path = self.root / "config.toml"
        self.path.write_bytes(serialize_config(parse_config(valid_config())))
        self.path.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def test_serializer_round_trips_all_machine_and_context_settings(self):
        config = load_config(self.path)
        self.assertEqual(config.version, 2)
        self.assertEqual(config.mcp.host, "127.0.0.1")
        self.assertEqual(config.mcp.port, 8765)
        self.assertEqual(config.broker.approval_mode, "disabled")
        self.assertEqual(tuple(config.machines), ("app-server",))
        self.assertEqual(config.home.gateway.exploded, "192.0.2.1")
        self.assertEqual(
            tuple(map(str, config.wireguard.local_addresses)),
            ("198.51.100.3/32",),
        )
        self.assertEqual(
            [item.id for item in config.machines["app-server"].endpoints],
            ["home-lan", "wireguard"],
        )
        self.assertTrue(config.machines["app-server"].enabled)
        self.assertIn(b"enabled = true\n", self.path.read_bytes())

    def test_serializer_upgrades_v1_input_to_explicit_v2_mcp_schema(self):
        content = serialize_config(parse_config(valid_config()))
        self.assertIn(b"version = 2\n", content)
        self.assertIn(
            b'[mcp]\nhost = "127.0.0.1"\nport = 8765\n',
            content,
        )

    def test_dashboard_approval_switch_persists_immediately(self):
        updated, changed = set_approval_mode(self.path, "always")
        self.assertTrue(changed)
        self.assertEqual(updated.broker.approval_mode, "always")
        self.assertEqual(load_config(self.path).broker.approval_mode, "always")
        _same, changed = set_approval_mode(self.path, "always")
        self.assertFalse(changed)
        updated, changed = set_approval_mode(self.path, "disabled")
        self.assertTrue(changed)
        self.assertEqual(updated.broker.approval_mode, "disabled")

    def test_list_and_structured_add_remove_are_atomic_and_need_no_remote(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(
                cli.main(["config", "list", "--path", str(self.path)]), 0
            )
        self.assertIn("app-server", output.getvalue())

        self.assertEqual(
            cli.main(
                [
                    "config", "add-machine", "new-server",
                    "--user", "operator",
                    "--description", "New server",
                    "--lan-ip", "192.0.2.44",
                    "--wireguard-ip", "198.51.100.204",
                    "--path", str(self.path),
                ]
            ),
            0,
        )
        added = load_config(self.path)
        self.assertIn("new-server", added.machines)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

        self.assertEqual(
            cli.main(
                ["config", "remove-machine", "new-server", "--yes", "--path", str(self.path)]
            ),
            0,
        )
        self.assertNotIn("new-server", load_config(self.path).machines)

    def test_set_broker_changes_approval_mode_atomically(self):
        self.assertEqual(
            cli.main(
                [
                    "config", "set-broker",
                    "--approval-mode", "always",
                    "--path", str(self.path),
                ]
            ),
            0,
        )
        self.assertEqual(load_config(self.path).broker.approval_mode, "always")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_enable_disable_commands_are_atomic_idempotent_and_list_status(self):
        self.assertEqual(
            cli.main(
                [
                    "config",
                    "disable-machine",
                    "app-server",
                    "--path",
                    str(self.path),
                ]
            ),
            0,
        )
        self.assertFalse(load_config(self.path).machines["app-server"].enabled)
        self.assertIn(b"enabled = false\n", self.path.read_bytes())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

        unchanged = self.path.read_bytes()
        self.assertEqual(
            cli.main(
                [
                    "config",
                    "disable-machine",
                    "app-server",
                    "--path",
                    str(self.path),
                ]
            ),
            0,
        )
        self.assertEqual(self.path.read_bytes(), unchanged)

        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(
                cli.main(["config", "list", "--path", str(self.path)]),
                0,
            )
        self.assertIn("app-server  status=disabled", output.getvalue())

        self.assertEqual(
            cli.main(
                [
                    "config",
                    "enable-machine",
                    "app-server",
                    "--path",
                    str(self.path),
                ]
            ),
            0,
        )
        self.assertTrue(load_config(self.path).machines["app-server"].enabled)

    def test_set_machine_enabled_reloads_and_preserves_unrelated_current_settings(self):
        first = load_config(self.path)
        current = parse_config(valid_config())
        current = replace(
            current,
            broker=replace(current.broker, max_active_remote_commands=2),
        )
        self.path.write_bytes(serialize_config(current))
        self.path.chmod(0o600)

        updated, changed = set_machine_enabled(
            self.path,
            "app-server",
            enabled=False,
        )

        self.assertTrue(first.machines["app-server"].enabled)
        self.assertTrue(changed)
        self.assertFalse(updated.machines["app-server"].enabled)
        self.assertEqual(updated.broker.max_active_remote_commands, 2)
        self.assertEqual(load_config(self.path), updated)
        lock_path = self.path.parent / f".{self.path.name}.lock"
        self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)

    def test_machine_disable_refuses_a_repointed_machine_preimage(self):
        startup = load_config(self.path)
        machines = dict(startup.machines)
        machines["app-server"] = replace(
            machines["app-server"],
            description="Repointed while broker was running",
        )
        current = replace(startup, machines=MappingProxyType(machines))
        self.path.write_bytes(serialize_config(current))
        self.path.chmod(0o600)

        with self.assertRaises(ConfigWriteConflictError):
            set_machine_enabled(
                self.path,
                "app-server",
                enabled=False,
                expected_machine=startup.machines["app-server"],
            )

        after = load_config(self.path)
        self.assertEqual(after, current)
        self.assertTrue(after.machines["app-server"].enabled)

    def test_editor_cas_rejects_comment_only_concurrent_change(self):
        _original, expected_content = load_config_snapshot(self.path)
        edited_content = b"# editor output\n" + expected_content
        temporary = self.root / ".config.editor.tmp"
        temporary.write_bytes(edited_content)
        temporary.chmod(0o600)

        concurrent_content = b"# concurrent comment-only update\n" + expected_content
        self.path.write_bytes(concurrent_content)
        self.path.chmod(0o600)

        with self.assertRaises(ConfigWriteConflictError):
            publish_edited_config(
                self.path,
                temporary,
                expected_content=expected_content,
            )

        self.assertEqual(self.path.read_bytes(), concurrent_content)
        self.assertEqual(temporary.read_bytes(), edited_content)

    def test_editor_publish_fsyncs_owned_exact_copy_before_replace(self):
        _original, expected_content = load_config_snapshot(self.path)
        edited_content = b"# exact editor output\n" + expected_content
        temporary = self.root / ".config.editor.tmp"
        temporary.write_bytes(edited_content)
        temporary.chmod(0o600)
        events = []
        real_fsync = os.fsync
        real_replace = os.replace

        def recording_fsync(descriptor):
            kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
            events.append(("fsync", kind))
            return real_fsync(descriptor)

        def recording_replace(source, destination):
            events.append(("replace", Path(source), Path(destination)))
            return real_replace(source, destination)

        with (
            mock.patch("tmuxgate.settings.os.fsync", side_effect=recording_fsync),
            mock.patch("tmuxgate.settings.os.replace", side_effect=recording_replace),
        ):
            edited = publish_edited_config(
                self.path,
                temporary,
                expected_content=expected_content,
            )

        self.assertEqual(edited, load_config(self.path))
        self.assertEqual(self.path.read_bytes(), edited_content)
        file_fsync_index = events.index(("fsync", "file"))
        replace_index = next(
            index for index, event in enumerate(events) if event[0] == "replace"
        )
        directory_fsync_index = events.index(("fsync", "directory"))
        self.assertLess(file_fsync_index, replace_index)
        self.assertLess(replace_index, directory_fsync_index)

    def test_home_enrollment_refuses_missing_direct_lan_evidence(self):
        before = self.path.read_bytes()
        empty = NetworkSnapshot({}, {}, {}, {}, {}, {}, {})
        errors = io.StringIO()
        with (
            mock.patch("tmuxgate.cli.collect_network_snapshot", return_value=empty),
            redirect_stderr(errors),
        ):
            status = cli.main(
                ["config", "enroll-home", "--yes", "--path", str(self.path)]
            )
        self.assertEqual(status, cli.EXIT_CONFIG)
        self.assertIn("not directly connected", errors.getvalue())
        self.assertEqual(self.path.read_bytes(), before)

    def test_home_enrollment_publishes_complete_current_identity(self):
        with mock.patch(
            "tmuxgate.cli.collect_network_snapshot", return_value=complete_snapshot()
        ):
            status = cli.main(
                [
                    "config", "enroll-home", "--id", "home-current", "--yes",
                    "--path", str(self.path),
                ]
            )
        self.assertEqual(status, 0)
        fingerprint = load_config(self.path).home.fingerprints[0]
        self.assertEqual(fingerprint.id, "home-current")
        self.assertEqual(fingerprint.gateway_macs, frozenset({"aa:bb:cc:dd:ee:ff"}))

    def test_home_enrollment_refreshes_missing_neighbor_then_revalidates(self):
        complete = complete_snapshot()
        missing_neighbor = NetworkSnapshot(
            complete.addresses_by_interface,
            complete.link_flags,
            complete.link_types,
            complete.routes,
            {},
            complete.connection_uuid_by_interface,
            complete.bssid_by_interface,
            complete.collection_errors,
        )
        with (
            mock.patch(
                "tmuxgate.cli.collect_network_snapshot",
                side_effect=(missing_neighbor, complete),
            ) as collect,
            mock.patch("tmuxgate.cli.subprocess.run") as refresh,
        ):
            status = cli.main(
                [
                    "config", "enroll-home", "--id", "home-refreshed", "--yes",
                    "--path", str(self.path),
                ]
            )
        self.assertEqual(status, 0)
        self.assertEqual(collect.call_count, 2)
        refresh.assert_called_once()
        refresh_argv = refresh.call_args.args[0]
        self.assertEqual(refresh_argv[0], "/usr/bin/ping")
        self.assertEqual(refresh_argv[-1], "192.0.2.1")
        self.assertEqual(refresh_argv[-3], "eth0")
        fingerprint = load_config(self.path).home.fingerprints[0]
        self.assertEqual(fingerprint.id, "home-refreshed")

    def test_home_enrollment_never_refreshes_without_direct_route(self):
        before = self.path.read_bytes()
        empty = NetworkSnapshot({}, {}, {}, {}, {}, {}, {})
        with (
            mock.patch("tmuxgate.cli.collect_network_snapshot", return_value=empty),
            mock.patch("tmuxgate.cli.subprocess.run") as refresh,
        ):
            status = cli.main(
                ["config", "enroll-home", "--yes", "--path", str(self.path)]
            )
        self.assertEqual(status, cli.EXIT_CONFIG)
        refresh.assert_not_called()
        self.assertEqual(self.path.read_bytes(), before)

    def test_no_argument_cli_starts_the_unified_application(self):
        with mock.patch("tmuxgate.cli.UnifiedApplication") as application:
            application.return_value.run.return_value = 0
            self.assertEqual(cli.main([]), 0)
        application.assert_called_once()
        arguments = application.call_args.kwargs
        self.assertEqual(arguments["config_path"], str(default_config_path()))
        self.assertIsNone(arguments["socket_path"])
        self.assertIsNone(arguments["state_dir"])
        self.assertFalse(arguments["fake"])
        self.assertIsNone(arguments["dashboard"])
        self.assertTrue(arguments["textual"])
        application.return_value.run.assert_called_once_with()

    def test_plain_is_explicit_and_preview_flag_is_removed(self):
        with mock.patch("tmuxgate.cli.UnifiedApplication") as application:
            application.return_value.run.return_value = 0
            self.assertEqual(cli.main(["--plain"]), 0)
        plain = application.call_args.kwargs
        self.assertFalse(plain["textual"])
        self.assertTrue(callable(plain["dashboard"]))

        with mock.patch("tmuxgate.cli.UnifiedApplication") as application:
            application.return_value.run.return_value = 0
            self.assertEqual(cli.main(["dashboard", "--plain"]), 0)
        dashboard_plain = application.call_args.kwargs
        self.assertFalse(dashboard_plain["textual"])
        self.assertTrue(callable(dashboard_plain["dashboard"]))

        with mock.patch("tmuxgate.cli.UnifiedApplication") as application:
            application.return_value.run.return_value = 0
            self.assertEqual(cli.main(["dashboard"]), 0)
        dashboard_tui = application.call_args.kwargs
        self.assertTrue(dashboard_tui["textual"])
        self.assertIsNone(dashboard_tui["dashboard"])

        with (
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            cli.build_parser().parse_args(["--tui"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
