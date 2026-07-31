import ipaddress
import uuid
import unittest

from tmuxgate.config import parse_config
from tmuxgate.network import (
    EvidenceResult,
    NeighborObservation,
    NetworkSnapshot,
    RouteObservation,
    build_route_plan,
)
from test_config import valid_config


def address(value):
    return ipaddress.ip_address(value)


def interface(value):
    return ipaddress.ip_interface(value)


class RouteSelectionTests(unittest.TestCase):
    def setUp(self):
        data = valid_config()
        data["contexts"]["home"]["fingerprints"] = [
            {
                "id": "home-ethernet",
                "link_type": "ethernet",
                "gateway_macs": ["aa:bb:cc:dd:ee:ff"],
                "connection_uuids": ["11111111-2222-3333-4444-555555555555"],
                "bssids": [],
            }
        ]
        self.config = parse_config(data)
        self.machine = self.config.machines["app-server"]

    def home_snapshot(
        self,
        *,
        flags=frozenset({"UP", "LOWER_UP"}),
        link_type="ethernet",
        neighbor_state="REACHABLE",
        neighbor_mac="aa:bb:cc:dd:ee:ff",
        connection_id=uuid.UUID("11111111-2222-3333-4444-555555555555"),
        bssid=None,
    ):
        home_gateway = address("192.0.2.1")
        home_target = address("192.0.2.20")
        return NetworkSnapshot(
            addresses_by_interface={"eth0": (interface("192.0.2.50/24"),)},
            link_flags={} if flags is None else {"eth0": flags},
            link_types={"eth0": link_type},
            routes={
                home_gateway: RouteObservation(home_gateway, "eth0", address("192.0.2.50"), None),
                home_target: RouteObservation(home_target, "eth0", address("192.0.2.50"), None),
            },
            neighbors={
                ("eth0", home_gateway): NeighborObservation(neighbor_mac, neighbor_state)
            },
            connection_uuid_by_interface={"eth0": connection_id},
            bssid_by_interface={} if bssid is None else {"eth0": bssid},
        )

    def test_current_away_network_selects_wireguard(self):
        home_gateway = address("192.0.2.1")
        home_target = address("192.0.2.20")
        wg_target = address("198.51.100.200")
        snapshot = NetworkSnapshot(
            addresses_by_interface={
                "enx000000000001": (interface("198.18.0.131/24"),),
                "wg0": (interface("198.51.100.3/32"),),
            },
            link_flags={"enx000000000001": frozenset({"UP"}), "wg0": frozenset({"UP"})},
            link_types={"enx000000000001": "ethernet", "wg0": "wireguard"},
            routes={
                home_gateway: RouteObservation(home_gateway, "enx000000000001", address("198.18.0.131"), address("198.18.0.115")),
                home_target: RouteObservation(home_target, "enx000000000001", address("198.18.0.131"), address("198.18.0.115")),
                wg_target: RouteObservation(wg_target, "wg0", address("198.51.100.3"), None),
            },
            neighbors={},
            connection_uuid_by_interface={},
            bssid_by_interface={},
        )
        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)
        self.assertEqual(plan.selected.id, "wireguard")
        home = next(item for item in plan.candidates if item.endpoint.id == "home-lan")
        self.assertEqual(home.result, EvidenceResult.NO_MATCH)

    def test_complete_home_fingerprint_beats_available_wireguard(self):
        home_gateway = address("192.0.2.1")
        home_target = address("192.0.2.20")
        wg_target = address("198.51.100.200")
        connection_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
        snapshot = NetworkSnapshot(
            addresses_by_interface={
                "eth0": (interface("192.0.2.50/24"),),
                "wg0": (interface("198.51.100.3/32"),),
            },
            link_flags={"eth0": frozenset({"UP", "LOWER_UP"}), "wg0": frozenset({"UP"})},
            link_types={"eth0": "ethernet", "wg0": "wireguard"},
            routes={
                home_gateway: RouteObservation(home_gateway, "eth0", address("192.0.2.50"), None),
                home_target: RouteObservation(home_target, "eth0", address("192.0.2.50"), None),
                wg_target: RouteObservation(wg_target, "wg0", address("198.51.100.3"), None),
            },
            neighbors={
                ("eth0", home_gateway): NeighborObservation("aa:bb:cc:dd:ee:ff", "REACHABLE")
            },
            connection_uuid_by_interface={"eth0": connection_id},
            bssid_by_interface={},
        )
        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)
        self.assertEqual([endpoint.id for endpoint in plan.eligible], ["home-lan", "wireguard"])

    def test_missing_cached_gateway_identity_fails_home_closed(self):
        home_gateway = address("192.0.2.1")
        home_target = address("192.0.2.20")
        snapshot = NetworkSnapshot(
            addresses_by_interface={"eth0": (interface("192.0.2.50/24"),)},
            link_flags={"eth0": frozenset({"UP", "LOWER_UP"})},
            link_types={"eth0": "ethernet"},
            routes={
                home_gateway: RouteObservation(home_gateway, "eth0", address("192.0.2.50"), None),
                home_target: RouteObservation(home_target, "eth0", address("192.0.2.50"), None),
            },
            neighbors={},
            connection_uuid_by_interface={
                "eth0": uuid.UUID("11111111-2222-3333-4444-555555555555")
            },
            bssid_by_interface={},
        )
        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)
        self.assertIsNone(plan.selected)
        home = next(item for item in plan.candidates if item.endpoint.id == "home-lan")
        self.assertEqual(home.result, EvidenceResult.UNKNOWN)

    def test_admin_up_and_stale_neighbor_without_ethernet_carrier_fails_closed(self):
        snapshot = self.home_snapshot(
            flags=frozenset({"UP"}),
            neighbor_state="STALE",
        )

        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)

        self.assertIsNone(plan.selected)
        home = next(item for item in plan.candidates if item.endpoint.id == "home-lan")
        self.assertEqual(home.result, EvidenceResult.NO_MATCH)
        self.assertTrue(any("mismatched Ethernet carrier" in reason for reason in home.reasons))

    def test_current_ethernet_carrier_can_corroborate_stale_neighbor_cache(self):
        snapshot = self.home_snapshot(
            flags=frozenset({"UP", "LOWER_UP"}),
            neighbor_state="STALE",
        )

        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)

        self.assertEqual(plan.selected.id, "home-lan")

    def test_missing_home_link_flags_is_unknown_not_eligible(self):
        snapshot = self.home_snapshot(flags=None, neighbor_state="STALE")

        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)

        self.assertIsNone(plan.selected)
        home = next(item for item in plan.candidates if item.endpoint.id == "home-lan")
        self.assertEqual(home.result, EvidenceResult.UNKNOWN)
        self.assertEqual(home.reasons, ("home interface flags are missing",))

    def test_carrier_without_administrative_up_is_not_eligible(self):
        snapshot = self.home_snapshot(flags=frozenset({"LOWER_UP"}))

        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)

        self.assertIsNone(plan.selected)
        home = next(item for item in plan.candidates if item.endpoint.id == "home-lan")
        self.assertEqual(home.result, EvidenceResult.NO_MATCH)
        self.assertEqual(home.reasons, ("home interface is not UP",))

    def test_current_wifi_bssid_is_association_evidence_without_lower_up_flag(self):
        data = valid_config()
        data["contexts"]["home"]["fingerprints"] = [
            {
                "id": "home-wifi",
                "link_type": "wifi",
                "gateway_macs": ["aa:bb:cc:dd:ee:ff"],
                "connection_uuids": ["11111111-2222-3333-4444-555555555555"],
                "bssids": ["11:22:33:44:55:66"],
            }
        ]
        config = parse_config(data)
        snapshot = self.home_snapshot(
            flags=frozenset({"UP"}),
            link_type="wifi",
            neighbor_state="STALE",
            bssid="11:22:33:44:55:66",
        )

        plan = build_route_plan(
            config.machines["app-server"],
            snapshot,
            config.home,
            config.wireguard,
        )

        self.assertEqual(plan.selected.id, "home-lan")

    def test_missing_current_wifi_association_is_unknown_not_eligible(self):
        data = valid_config()
        data["contexts"]["home"]["fingerprints"] = [
            {
                "id": "home-wifi",
                "link_type": "wifi",
                "gateway_macs": ["aa:bb:cc:dd:ee:ff"],
                "connection_uuids": ["11111111-2222-3333-4444-555555555555"],
                "bssids": ["11:22:33:44:55:66"],
            }
        ]
        config = parse_config(data)
        snapshot = self.home_snapshot(
            flags=frozenset({"UP"}),
            link_type="wifi",
            neighbor_state="STALE",
            bssid=None,
        )

        plan = build_route_plan(
            config.machines["app-server"],
            snapshot,
            config.home,
            config.wireguard,
        )

        self.assertIsNone(plan.selected)
        home = next(item for item in plan.candidates if item.endpoint.id == "home-lan")
        self.assertEqual(home.result, EvidenceResult.UNKNOWN)
        self.assertTrue(
            any("missing current Wi-Fi association BSSID" in reason for reason in home.reasons)
        )

    def test_wrong_current_wifi_association_is_not_eligible(self):
        data = valid_config()
        data["contexts"]["home"]["fingerprints"] = [
            {
                "id": "home-wifi",
                "link_type": "wifi",
                "gateway_macs": ["aa:bb:cc:dd:ee:ff"],
                "connection_uuids": ["11111111-2222-3333-4444-555555555555"],
                "bssids": ["11:22:33:44:55:66"],
            }
        ]
        config = parse_config(data)
        snapshot = self.home_snapshot(
            flags=frozenset({"UP"}),
            link_type="wifi",
            bssid="66:55:44:33:22:11",
        )

        plan = build_route_plan(
            config.machines["app-server"],
            snapshot,
            config.home,
            config.wireguard,
        )

        self.assertIsNone(plan.selected)
        home = next(item for item in plan.candidates if item.endpoint.id == "home-lan")
        self.assertEqual(home.result, EvidenceResult.NO_MATCH)
        self.assertTrue(
            any("mismatched current Wi-Fi association BSSID" in reason for reason in home.reasons)
        )

    def test_wireguard_operstate_unknown_does_not_matter_when_flag_is_up(self):
        wg_target = address("198.51.100.200")
        snapshot = NetworkSnapshot(
            addresses_by_interface={"wg0": (interface("198.51.100.3/32"),)},
            link_flags={"wg0": frozenset({"UP"})},
            link_types={"wg0": "wireguard"},
            routes={wg_target: RouteObservation(wg_target, "wg0", address("198.51.100.3"), None)},
            neighbors={},
            connection_uuid_by_interface={},
            bssid_by_interface={},
            collection_errors=("wg show: permission denied",),
        )
        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)
        self.assertEqual(plan.selected.id, "wireguard")

    def test_wireguard_route_selects_current_kernel_interface(self):
        data = valid_config()
        config = parse_config(data)
        target = address("198.51.100.200")
        snapshot = NetworkSnapshot(
            addresses_by_interface={
                "wg0-wstunnel": (interface("198.51.100.3/32"),),
            },
            link_flags={"wg0-wstunnel": frozenset({"UP"})},
            link_types={"wg0-wstunnel": "wireguard"},
            routes={
                target: RouteObservation(
                    target, "wg0-wstunnel", address("198.51.100.3"), None
                )
            },
            neighbors={},
            connection_uuid_by_interface={},
            bssid_by_interface={},
        )

        plan = build_route_plan(
            config.machines["app-server"],
            snapshot,
            config.home,
            config.wireguard,
        )

        self.assertEqual(plan.selected.id, "wireguard")

    def test_wireguard_route_accepts_renamed_verified_wireguard_link(self):
        target = address("198.51.100.200")
        snapshot = NetworkSnapshot(
            addresses_by_interface={"wg-renamed": (interface("198.51.100.3/32"),)},
            link_flags={"wg-renamed": frozenset({"UP"})},
            link_types={"wg-renamed": "wireguard"},
            routes={
                target: RouteObservation(
                    target, "wg-renamed", address("198.51.100.3"), None
                )
            },
            neighbors={},
            connection_uuid_by_interface={},
            bssid_by_interface={},
        )

        plan = build_route_plan(
            self.machine, snapshot, self.config.home, self.config.wireguard
        )

        self.assertEqual(plan.selected.id, "wireguard")

    def test_missing_wireguard_link_type_is_unknown_not_eligible(self):
        wg_target = address("198.51.100.200")
        snapshot = NetworkSnapshot(
            addresses_by_interface={"wg0": (interface("198.51.100.3/32"),)},
            link_flags={"wg0": frozenset({"UP"})},
            link_types={},
            routes={wg_target: RouteObservation(wg_target, "wg0", address("198.51.100.3"), None)},
            neighbors={},
            connection_uuid_by_interface={},
            bssid_by_interface={},
        )

        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)

        self.assertIsNone(plan.selected)
        wireguard = next(item for item in plan.candidates if item.endpoint.id == "wireguard")
        self.assertEqual(wireguard.result, EvidenceResult.UNKNOWN)
        self.assertEqual(wireguard.reasons, ("WireGuard interface link type is missing",))

    def test_non_wireguard_link_type_is_not_eligible(self):
        wg_target = address("198.51.100.200")
        snapshot = NetworkSnapshot(
            addresses_by_interface={"wg0": (interface("198.51.100.3/32"),)},
            link_flags={"wg0": frozenset({"UP"})},
            link_types={"wg0": "ethernet"},
            routes={wg_target: RouteObservation(wg_target, "wg0", address("198.51.100.3"), None)},
            neighbors={},
            connection_uuid_by_interface={},
            bssid_by_interface={},
        )

        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)

        self.assertIsNone(plan.selected)
        wireguard = next(item for item in plan.candidates if item.endpoint.id == "wireguard")
        self.assertEqual(wireguard.result, EvidenceResult.NO_MATCH)
        self.assertEqual(
            wireguard.reasons,
            ("configured WireGuard interface has a non-WireGuard link type",),
        )

    def test_wireguard_route_source_must_be_the_exact_assigned_interface(self):
        data = valid_config()
        data["contexts"]["wireguard"]["local_addresses"] = [
            "198.51.100.3/32",
            "198.51.100.4/32",
        ]
        config = parse_config(data)
        machine = config.machines["app-server"]
        target = address("198.51.100.200")
        snapshot = NetworkSnapshot(
            addresses_by_interface={"wg0": (interface("198.51.100.3/32"),)},
            link_flags={"wg0": frozenset({"UP"})},
            link_types={"wg0": "wireguard"},
            routes={target: RouteObservation(target, "wg0", address("198.51.100.4"), None)},
            neighbors={},
            connection_uuid_by_interface={},
            bssid_by_interface={},
        )
        plan = build_route_plan(machine, snapshot, config.home, config.wireguard)
        self.assertIsNone(plan.selected)

    def test_wireguard_assignment_must_match_configured_prefix_exactly(self):
        target = address("198.51.100.200")
        snapshot = NetworkSnapshot(
            addresses_by_interface={"wg0": (interface("198.51.100.3/24"),)},
            link_flags={"wg0": frozenset({"UP"})},
            link_types={"wg0": "wireguard"},
            routes={target: RouteObservation(target, "wg0", address("198.51.100.3"), None)},
            neighbors={},
            connection_uuid_by_interface={},
            bssid_by_interface={},
        )
        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)
        self.assertIsNone(plan.selected)

    def test_down_home_interface_is_rejected(self):
        home_gateway = address("192.0.2.1")
        home_target = address("192.0.2.20")
        snapshot = NetworkSnapshot(
            addresses_by_interface={"eth0": (interface("192.0.2.50/24"),)},
            link_flags={"eth0": frozenset()},
            link_types={"eth0": "ethernet"},
            routes={
                home_gateway: RouteObservation(home_gateway, "eth0", address("192.0.2.50"), None),
                home_target: RouteObservation(home_target, "eth0", address("192.0.2.50"), None),
            },
            neighbors={
                ("eth0", home_gateway): NeighborObservation("aa:bb:cc:dd:ee:ff", "STALE")
            },
            connection_uuid_by_interface={
                "eth0": uuid.UUID("11111111-2222-3333-4444-555555555555")
            },
            bssid_by_interface={},
        )
        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)
        self.assertIsNone(plan.selected)

    def test_failed_neighbor_state_is_rejected(self):
        home_gateway = address("192.0.2.1")
        home_target = address("192.0.2.20")
        snapshot = NetworkSnapshot(
            addresses_by_interface={"eth0": (interface("192.0.2.50/24"),)},
            link_flags={"eth0": frozenset({"UP", "LOWER_UP"})},
            link_types={"eth0": "ethernet"},
            routes={
                home_gateway: RouteObservation(home_gateway, "eth0", address("192.0.2.50"), None),
                home_target: RouteObservation(home_target, "eth0", address("192.0.2.50"), None),
            },
            neighbors={
                ("eth0", home_gateway): NeighborObservation("aa:bb:cc:dd:ee:ff", "FAILED")
            },
            connection_uuid_by_interface={
                "eth0": uuid.UUID("11111111-2222-3333-4444-555555555555")
            },
            bssid_by_interface={},
        )
        plan = build_route_plan(self.machine, snapshot, self.config.home, self.config.wireguard)
        self.assertIsNone(plan.selected)

    def test_home_context_precedes_wireguard_even_if_priority_is_misordered(self):
        data = valid_config()
        data["contexts"]["home"]["fingerprints"] = [
            {
                "id": "home-ethernet",
                "link_type": "ethernet",
                "gateway_macs": ["aa:bb:cc:dd:ee:ff"],
                "connection_uuids": ["11111111-2222-3333-4444-555555555555"],
                "bssids": [],
            }
        ]
        data["machines"]["app-server"]["endpoints"][0]["priority"] = 999
        data["machines"]["app-server"]["endpoints"][1]["priority"] = 1
        config = parse_config(data)
        machine = config.machines["app-server"]
        home_gateway = address("192.0.2.1")
        home_target = address("192.0.2.20")
        wg_target = address("198.51.100.200")
        snapshot = NetworkSnapshot(
            addresses_by_interface={
                "eth0": (interface("192.0.2.50/24"),),
                "wg0": (interface("198.51.100.3/32"),),
            },
            link_flags={"eth0": frozenset({"UP", "LOWER_UP"}), "wg0": frozenset({"UP"})},
            link_types={"eth0": "ethernet", "wg0": "wireguard"},
            routes={
                home_gateway: RouteObservation(home_gateway, "eth0", address("192.0.2.50"), None),
                home_target: RouteObservation(home_target, "eth0", address("192.0.2.50"), None),
                wg_target: RouteObservation(wg_target, "wg0", address("198.51.100.3"), None),
            },
            neighbors={
                ("eth0", home_gateway): NeighborObservation("aa:bb:cc:dd:ee:ff", "REACHABLE")
            },
            connection_uuid_by_interface={
                "eth0": uuid.UUID("11111111-2222-3333-4444-555555555555")
            },
            bssid_by_interface={},
        )
        plan = build_route_plan(machine, snapshot, config.home, config.wireguard)
        self.assertEqual([endpoint.id for endpoint in plan.eligible], ["home-lan", "wireguard"])


if __name__ == "__main__":
    unittest.main()
