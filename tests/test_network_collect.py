import ipaddress
import json
import subprocess
import unittest

from tmuxgate.config import parse_config
from tmuxgate.network import build_route_plan
from tmuxgate.network_collect import (
    MAX_COMMAND_OUTPUT_BYTES,
    collect_network_snapshot,
)


IP = "/usr/sbin/ip"
NMCLI = "/usr/bin/nmcli"
HOME_GATEWAY = ipaddress.IPv4Address("192.0.2.1")
LAN_TARGET = ipaddress.IPv4Address("192.0.2.20")
WG_TARGET = ipaddress.IPv4Address("198.51.100.200")
ETHERNET_UUID = "11111111-2222-3333-4444-555555555555"
WIREGUARD_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


class FakeRunner:
    def __init__(self, responses):
        self.responses = responses
        self.commands = []

    def __call__(self, argv, **kwargs):
        argv = tuple(argv)
        self.commands.append((argv, kwargs))
        response = self.responses.get(argv, (0, b"[]", b""))
        if isinstance(response, BaseException):
            raise response
        returncode, stdout, stderr = response
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def complete_responses():
    return {
        (IP, "-j", "address", "show"): (
            0,
            encoded(
                [
                    {
                        "ifname": "eth0",
                        "addr_info": [
                            {"family": "inet", "local": "192.0.2.42", "prefixlen": 24}
                        ],
                    },
                    {
                        "ifname": "wg0",
                        "addr_info": [
                            {"family": "inet", "local": "198.51.100.3", "prefixlen": 32}
                        ],
                    },
                ]
            ),
            b"",
        ),
        (IP, "-j", "-details", "link", "show"): (
            0,
            encoded(
                [
                    {
                        "ifname": "eth0",
                        "flags": ["BROADCAST", "UP", "LOWER_UP"],
                        "link_type": "ether",
                    },
                    {
                        "ifname": "wg0",
                        "flags": ["POINTOPOINT", "UP", "LOWER_UP"],
                        "link_type": "none",
                        "linkinfo": {"info_kind": "wireguard"},
                    },
                ]
            ),
            b"",
        ),
        (
            NMCLI,
            "--terse",
            "--escape",
            "yes",
            "--fields",
            "DEVICE,UUID,TYPE",
            "connection",
            "show",
            "--active",
        ): (
            0,
            (
                f"eth0:{ETHERNET_UUID}:802-3-ethernet\n"
                f"wg0:{WIREGUARD_UUID}:wireguard\n"
            ).encode(),
            b"",
        ),
        (
            NMCLI,
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
        ): (0, b"", b""),
        (IP, "-j", "route", "get", str(HOME_GATEWAY)): (
            0,
            encoded([{"dst": str(HOME_GATEWAY), "dev": "eth0", "prefsrc": "192.0.2.42"}]),
            b"",
        ),
        (IP, "-j", "route", "get", str(LAN_TARGET)): (
            0,
            encoded([{"dst": str(LAN_TARGET), "dev": "eth0", "prefsrc": "192.0.2.42"}]),
            b"",
        ),
        (IP, "-j", "route", "get", str(WG_TARGET)): (
            0,
            encoded([{"dst": str(WG_TARGET), "dev": "wg0", "prefsrc": "198.51.100.3"}]),
            b"",
        ),
        (
            IP,
            "-j",
            "neighbor",
            "show",
            "to",
            str(HOME_GATEWAY),
            "dev",
            "eth0",
        ): (
            0,
            encoded(
                [
                    {
                        "dst": str(HOME_GATEWAY),
                        "lladdr": "AA:BB:CC:DD:EE:FF",
                        "state": ["STALE"],
                    }
                ]
            ),
            b"",
        ),
    }


def route_config():
    return parse_config(
        {
            "version": 1,
            "broker": {},
            "contexts": {
                "home": {
                    "gateway": str(HOME_GATEWAY),
                    "source_cidr": "192.0.2.0/24",
                    "fingerprints": [
                        {
                            "id": "home-ethernet",
                            "link_type": "ethernet",
                            "gateway_macs": ["aa:bb:cc:dd:ee:ff"],
                            "connection_uuids": [ETHERNET_UUID],
                            "bssids": [],
                        }
                    ],
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
                    "endpoints": [
                        {
                            "id": "home-lan",
                            "address": str(LAN_TARGET),
                            "requires": "home",
                            "priority": 10,
                        },
                        {
                            "id": "wireguard",
                            "address": str(WG_TARGET),
                            "requires": "wireguard",
                            "priority": 20,
                        },
                    ],
                }
            },
        }
    )


class NetworkSnapshotCollectorTests(unittest.TestCase):
    def test_complete_read_only_snapshot_selects_home_then_wireguard_fallback(self):
        runner = FakeRunner(complete_responses())
        snapshot = collect_network_snapshot(
            [LAN_TARGET, WG_TARGET],
            home_gateway=HOME_GATEWAY,
            runner=runner,
        )
        config = route_config()
        plan = build_route_plan(
            config.machines["app-server"],
            snapshot,
            config.home,
            config.wireguard,
        )

        self.assertEqual(snapshot.collection_errors, ())
        self.assertEqual(snapshot.link_types["eth0"], "ethernet")
        self.assertEqual(snapshot.link_types["wg0"], "wireguard")
        self.assertEqual(
            snapshot.neighbors[("eth0", HOME_GATEWAY)].mac,
            "aa:bb:cc:dd:ee:ff",
        )
        self.assertEqual(
            [endpoint.id for endpoint in plan.eligible],
            ["home-lan", "wireguard"],
        )

        executables = {argv[0] for argv, _ in runner.commands}
        self.assertEqual(executables, {IP, NMCLI})
        flattened = [item for argv, _ in runner.commands for item in argv]
        self.assertNotIn("ping", flattened)
        self.assertNotIn("ssh", flattened)
        self.assertNotIn("arping", flattened)
        self.assertIn("--rescan", flattened)
        self.assertIn("no", flattened)
        for _, kwargs in runner.commands:
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["env"]["LC_ALL"], "C")

    def test_wifi_escaped_bssid_is_preserved_as_current_association(self):
        responses = complete_responses()
        responses[(IP, "-j", "address", "show")] = (
            0,
            encoded(
                [
                    {
                        "ifname": "wlan0",
                        "addr_info": [
                            {"family": "inet", "local": "192.0.2.42", "prefixlen": 24}
                        ],
                    }
                ]
            ),
            b"",
        )
        responses[(IP, "-j", "-details", "link", "show")] = (
            0,
            encoded(
                [
                    {
                        "ifname": "wlan0",
                        "flags": ["BROADCAST", "UP", "LOWER_UP"],
                        "link_type": "ether",
                    }
                ]
            ),
            b"",
        )
        active_key = next(key for key in responses if "DEVICE,UUID,TYPE" in key)
        wifi_key = next(key for key in responses if "DEVICE,ACTIVE,BSSID" in key)
        responses[active_key] = (
            0,
            f"wlan0:{ETHERNET_UUID}:802-11-wireless\n".encode(),
            b"",
        )
        responses[wifi_key] = (0, b"wlan0:yes:11\\:22\\:33\\:44\\:55\\:66\n", b"")
        for destination in (HOME_GATEWAY, LAN_TARGET):
            responses[(IP, "-j", "route", "get", str(destination))] = (
                0,
                encoded(
                    [{"dst": str(destination), "dev": "wlan0", "prefsrc": "192.0.2.42"}]
                ),
                b"",
            )
        old_neighbor = next(key for key in responses if "neighbor" in key)
        del responses[old_neighbor]
        responses[
            (
                IP,
                "-j",
                "neighbor",
                "show",
                "to",
                str(HOME_GATEWAY),
                "dev",
                "wlan0",
            )
        ] = (
            0,
            encoded(
                [
                    {
                        "dst": str(HOME_GATEWAY),
                        "dev": "wlan0",
                        "lladdr": "aa:bb:cc:dd:ee:ff",
                        "state": "REACHABLE",
                    }
                ]
            ),
            b"",
        )

        snapshot = collect_network_snapshot(
            [LAN_TARGET],
            home_gateway=HOME_GATEWAY,
            runner=FakeRunner(responses),
        )
        self.assertEqual(snapshot.link_types["wlan0"], "wifi")
        self.assertEqual(snapshot.bssid_by_interface["wlan0"], "11:22:33:44:55:66")

    def test_source_failure_is_recorded_and_does_not_discard_other_evidence(self):
        responses = complete_responses()
        wifi_key = next(key for key in responses if "DEVICE,ACTIVE,BSSID" in key)
        responses[wifi_key] = (10, b"", b"no wifi")
        snapshot = collect_network_snapshot(
            [LAN_TARGET, WG_TARGET],
            home_gateway=HOME_GATEWAY,
            runner=FakeRunner(responses),
        )
        self.assertTrue(any(error.startswith("nmcli-wifi:") for error in snapshot.collection_errors))
        self.assertIn(LAN_TARGET, snapshot.routes)
        self.assertIn(WG_TARGET, snapshot.routes)
        self.assertEqual(snapshot.addresses_by_interface["wg0"][0].ip.exploded, "198.51.100.3")

    def test_malformed_route_is_omitted_and_identified(self):
        responses = complete_responses()
        responses[(IP, "-j", "route", "get", str(LAN_TARGET))] = (
            0,
            encoded([{"dst": str(LAN_TARGET), "prefsrc": "192.0.2.42"}]),
            b"",
        )
        snapshot = collect_network_snapshot(
            [LAN_TARGET, WG_TARGET],
            home_gateway=HOME_GATEWAY,
            runner=FakeRunner(responses),
        )
        self.assertNotIn(LAN_TARGET, snapshot.routes)
        self.assertTrue(
            any(
                error.startswith(f"route-{LAN_TARGET}:") and "lacks an interface" in error
                for error in snapshot.collection_errors
            )
        )

    def test_empty_cached_neighbor_does_not_invent_router_identity(self):
        responses = complete_responses()
        neighbor_key = next(key for key in responses if "neighbor" in key)
        responses[neighbor_key] = (0, b"[]", b"")
        snapshot = collect_network_snapshot(
            [LAN_TARGET],
            home_gateway=HOME_GATEWAY,
            runner=FakeRunner(responses),
        )
        self.assertEqual(snapshot.neighbors, {})
        config = route_config()
        plan = build_route_plan(
            config.machines["app-server"],
            snapshot,
            config.home,
            config.wireguard,
        )
        self.assertNotIn("home-lan", [endpoint.id for endpoint in plan.eligible])

    def test_oversized_output_is_rejected_without_parsing(self):
        responses = complete_responses()
        responses[(IP, "-j", "address", "show")] = (
            0,
            b"x" * (MAX_COMMAND_OUTPUT_BYTES + 1),
            b"",
        )
        snapshot = collect_network_snapshot(
            [LAN_TARGET],
            home_gateway=HOME_GATEWAY,
            runner=FakeRunner(responses),
        )
        self.assertEqual(snapshot.addresses_by_interface, {})
        self.assertTrue(any("exceeds" in error for error in snapshot.collection_errors))

    def test_bad_runner_result_fails_one_source_closed(self):
        class BadRunner(FakeRunner):
            def __call__(self, argv, **kwargs):
                if tuple(argv) == (IP, "-j", "address", "show"):
                    return object()
                return super().__call__(argv, **kwargs)

        snapshot = collect_network_snapshot(
            [LAN_TARGET],
            home_gateway=HOME_GATEWAY,
            runner=BadRunner(complete_responses()),
        )
        self.assertEqual(snapshot.addresses_by_interface, {})
        self.assertTrue(any("invalid result" in error for error in snapshot.collection_errors))

    def test_invalid_inputs_are_rejected_before_any_command(self):
        runner = FakeRunner({})
        for timeout in (True, 0, -1, 31, float("nan"), float("inf"), "3"):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    collect_network_snapshot(
                        [LAN_TARGET],
                        home_gateway=HOME_GATEWAY,
                        runner=runner,
                        timeout_seconds=timeout,
                    )
        with self.assertRaises(TypeError):
            collect_network_snapshot(
                ["192.0.2.20"],
                home_gateway=HOME_GATEWAY,
                runner=runner,
            )
        with self.assertRaises(ValueError):
            collect_network_snapshot(
                [LAN_TARGET],
                home_gateway=HOME_GATEWAY,
                runner=runner,
                ip_path="ip",
            )
        self.assertEqual(runner.commands, [])


if __name__ == "__main__":
    unittest.main()
