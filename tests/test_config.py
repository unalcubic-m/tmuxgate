from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest

from tmuxgate.config import (
    BrokerConfig,
    ConfigError,
    McpConfig,
    load_config,
    parse_config,
)


def valid_config():
    return {
        "version": 1,
        "broker": {
            "max_active_remote_commands": 3,
            "max_open_ssh_masters": 3,
            "max_pending_requests": 16,
            "queue_policy": "fifo",
            "ssh_master_idle_timeout_seconds": 600,
            "approval_mode": "disabled",
        },
        "contexts": {
            "home": {
                "gateway": "192.0.2.1",
                "source_cidr": "192.0.2.0/24",
                "fingerprints": [],
            },
            "wireguard": {
                "local_addresses": ["198.51.100.3/32"],
                "remote_cidrs": ["198.51.100.0/25", "198.51.100.128/25"],
            },
        },
        "machines": {
            "app-server": {
                "description": "Example application server",
                "ssh_profile": "app-server",
                "user": "operator",
                "host_key_alias": "tmuxgate-app-server",
                "connect_timeout_seconds": 6,
                "endpoints": [
                    {
                        "id": "home-lan",
                        "address": "192.0.2.20",
                        "port": 22,
                        "priority": 10,
                        "requires": "home",
                    },
                    {
                        "id": "wireguard",
                        "address": "198.51.100.200",
                        "port": 22,
                        "priority": 20,
                        "requires": "wireguard",
                    },
                ],
            }
        },
    }


class ConfigTests(unittest.TestCase):
    def test_version_one_loads_with_loopback_mcp_defaults_and_upgrades_in_memory(self):
        config = parse_config(valid_config())
        self.assertEqual(config.version, 2)
        self.assertEqual(config.mcp, McpConfig(host="127.0.0.1", port=8765))

    def test_version_two_accepts_an_explicit_mcp_port(self):
        data = valid_config()
        data["version"] = 2
        data["mcp"] = {"host": "127.0.0.1", "port": 9876}
        config = parse_config(data)
        self.assertEqual(config.version, 2)
        self.assertEqual(config.mcp.port, 9876)

    def test_mcp_listener_is_restricted_to_literal_ipv4_loopback(self):
        for host in ("localhost", "::1", "0.0.0.0", "127.0.0.2"):
            with self.subTest(host=host):
                data = valid_config()
                data["version"] = 2
                data["mcp"] = {"host": host, "port": 8765}
                with self.assertRaisesRegex(ConfigError, "literal loopback"):
                    parse_config(data)
                with self.assertRaisesRegex(ConfigError, "literal loopback"):
                    McpConfig(host=host)

    def test_mcp_port_and_fields_are_strictly_validated(self):
        for port in (True, 0, 65536, "8765"):
            with self.subTest(port=port):
                data = valid_config()
                data["version"] = 2
                data["mcp"] = {"host": "127.0.0.1", "port": port}
                with self.assertRaisesRegex(ConfigError, "mcp.port"):
                    parse_config(data)
        data = valid_config()
        data["version"] = 2
        data["mcp"] = {"host": "127.0.0.1", "port": 8765, "path": "/mcp"}
        with self.assertRaisesRegex(ConfigError, "path"):
            parse_config(data)

    def test_version_one_rejects_new_schema_fields(self):
        data = valid_config()
        data["mcp"] = {"host": "127.0.0.1", "port": 8765}
        with self.assertRaisesRegex(ConfigError, "mcp"):
            parse_config(data)

    def test_valid_config_supports_three_commands_and_three_masters(self):
        config = parse_config(valid_config())
        self.assertEqual(config.broker.max_active_remote_commands, 3)
        self.assertEqual(config.broker.max_open_ssh_masters, 3)
        self.assertEqual(config.machines["app-server"].endpoints[0].address.exploded, "192.0.2.20")
        self.assertEqual(
            tuple(map(str, config.wireguard.local_addresses)),
            ("198.51.100.3/32",),
        )
        self.assertTrue(config.machines["app-server"].enabled)

    def test_machine_enabled_defaults_true_and_requires_a_boolean(self):
        data = valid_config()
        data["machines"]["app-server"]["enabled"] = False
        self.assertFalse(parse_config(data).machines["app-server"].enabled)

        for invalid in (0, 1, "false", None):
            with self.subTest(invalid=invalid):
                data = valid_config()
                data["machines"]["app-server"]["enabled"] = invalid
                with self.assertRaisesRegex(ConfigError, "enabled.*boolean"):
                    parse_config(data)

        machine = parse_config(valid_config()).machines["app-server"]
        with self.assertRaisesRegex(ConfigError, "enabled status.*boolean"):
            replace(machine, enabled=1)

    def test_wireguard_interface_names_are_not_configuration(self):
        for field, value in (("interface", "wg0"), ("interfaces", ["wg0"])):
            data = valid_config()
            data["contexts"]["wireguard"][field] = value
            with self.assertRaisesRegex(ConfigError, field):
                parse_config(data)

    def test_rejects_more_than_three_commands_or_masters(self):
        data = valid_config()
        data["broker"]["max_active_remote_commands"] = 4
        with self.assertRaises(ConfigError):
            parse_config(data)

    def test_broker_model_itself_enforces_execution_and_master_limits(self):
        with self.assertRaises(ConfigError):
            BrokerConfig(max_active_remote_commands=4)
        with self.assertRaises(ConfigError):
            BrokerConfig(max_open_ssh_masters=4)
        with self.assertRaises(ConfigError):
            BrokerConfig(ssh_master_idle_timeout_seconds=0)
        data = valid_config()
        data["broker"]["max_open_ssh_masters"] = 4
        with self.assertRaises(ConfigError):
            parse_config(data)

    def test_rejects_unknown_fields_and_host_key_alias_sharing(self):
        data = valid_config()
        data["broker"]["auto_approve"] = True
        with self.assertRaisesRegex(ConfigError, "auto_approve"):
            parse_config(data)

    def test_approval_can_be_reenabled_or_left_disabled(self):
        config = parse_config(valid_config())
        self.assertEqual(config.broker.approval_mode, "disabled")
        data = valid_config()
        data["broker"]["approval_mode"] = "always"
        self.assertEqual(parse_config(data).broker.approval_mode, "always")
        data["broker"]["approval_mode"] = "sometimes"
        with self.assertRaisesRegex(ConfigError, "approval_mode"):
            parse_config(data)

    def test_version_must_be_an_integer_and_machine_allowlist_is_immutable(self):
        data = valid_config()
        data["version"] = 1.0
        with self.assertRaises(ConfigError):
            parse_config(data)
        data = valid_config()
        data["version"] = 3
        with self.assertRaises(ConfigError):
            parse_config(data)
        config = parse_config(valid_config())
        with self.assertRaises(TypeError):
            config.machines["attacker"] = config.machines["app-server"]
        data = valid_config()
        data["machines"]["app-server"]["host_key_alias"] = "shared-key"
        with self.assertRaisesRegex(ConfigError, "must equal"):
            parse_config(data)

    def test_rejects_endpoint_outside_configured_context(self):
        data = valid_config()
        data["machines"]["app-server"]["endpoints"][1]["address"] = "203.0.113.9"
        with self.assertRaisesRegex(ConfigError, "outside configured remote CIDRs"):
            parse_config(data)

    def test_complete_wifi_fingerprint_is_accepted(self):
        data = valid_config()
        data["contexts"]["home"]["fingerprints"] = [
            {
                "id": "home-wifi",
                "link_type": "wifi",
                "gateway_macs": ["AA:BB:CC:DD:EE:FF"],
                "connection_uuids": ["11111111-2222-3333-4444-555555555555"],
                "bssids": ["11:22:33:44:55:66"],
            }
        ]
        config = parse_config(data)
        fingerprint = config.home.fingerprints[0]
        self.assertEqual(fingerprint.gateway_macs, frozenset({"aa:bb:cc:dd:ee:ff"}))

    def test_secure_loader_rejects_world_readable_file_and_symlink(self):
        toml = b'''version = 1\n[contexts]\n[machines.host]\nuser = "operator"\nhost_key_alias = "tmuxgate-host"\nendpoints = [{id="public",address="example.com",requires="always"}]\n'''
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            path = Path(directory) / "config.toml"
            path.write_bytes(toml)
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(ConfigError, "group/other"):
                load_config(path)
            os.chmod(path, 0o600)
            link = Path(directory) / "link.toml"
            link.symlink_to(path)
            with self.assertRaises(ConfigError):
                load_config(link)

    def test_secure_loader_rejects_symlinked_config_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir(mode=0o700)
            path = real / "config.toml"
            path.write_text("version = 1\n", encoding="utf-8")
            os.chmod(path, 0o600)
            linked = root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ConfigError):
                load_config(linked / "config.toml")

    def test_rejects_unconditional_endpoint_policy_bypass(self):
        data = valid_config()
        data["machines"]["app-server"]["endpoints"][0]["requires"] = "always"
        with self.assertRaisesRegex(ConfigError, "home or wireguard"):
            parse_config(data)


if __name__ == "__main__":
    unittest.main()
