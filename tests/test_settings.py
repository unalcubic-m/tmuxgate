from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tmuxgate import cli
from tmuxgate.config import load_config, parse_config
from tmuxgate.network import NetworkSnapshot
from tmuxgate.settings import serialize_config
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

    def test_no_argument_cli_opens_dashboard_and_can_quit(self):
        output = io.StringIO()
        with mock.patch("builtins.input", return_value="q"), redirect_stdout(output):
            self.assertEqual(cli.main([]), 0)
        self.assertIn("Start execution broker", output.getvalue())
        self.assertIn("Add remote machine", output.getvalue())


if __name__ == "__main__":
    unittest.main()
