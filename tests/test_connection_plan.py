from dataclasses import replace
import io
import ipaddress
import unittest
import uuid

from tmuxgate.approval import (
    ApprovalDecision,
    ApprovalError,
    ApprovalInputError,
    ApprovalTerminal,
    approval_binding_sha256,
    render_approval_document,
    render_fallback_approval_document,
    request_bound_approval,
    request_fallback_approval,
)
from tmuxgate.config import parse_config
from tmuxgate.connection_plan import (
    ConnectionPlanError,
    build_connection_plan,
    canonical_network_snapshot,
)
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.network import (
    NeighborObservation,
    NetworkSnapshot,
    RouteObservation,
    build_route_plan,
)
from tmuxgate.ssh import HostKeyEvidence, HostKeyRecord, ResolvedSshEndpoint
from test_config import valid_config


REQUEST_ID = "89abcdef0123456789abcdef01234567"


def address(value):
    return ipaddress.ip_address(value)


def interface(value):
    return ipaddress.ip_interface(value)


def complete_snapshot(*, collection_errors=()):
    gateway = address("192.0.2.1")
    home = address("192.0.2.20")
    wireguard = address("198.51.100.200")
    return NetworkSnapshot(
        addresses_by_interface={
            "eth0": (interface("192.0.2.50/24"),),
            "wg0": (interface("198.51.100.3/32"),),
        },
        link_flags={
            "eth0": frozenset({"UP", "LOWER_UP"}),
            "wg0": frozenset({"UP"}),
        },
        link_types={"eth0": "ethernet", "wg0": "wireguard"},
        routes={
            gateway: RouteObservation(gateway, "eth0", address("192.0.2.50"), None),
            home: RouteObservation(home, "eth0", address("192.0.2.50"), None),
            wireguard: RouteObservation(wireguard, "wg0", address("198.51.100.3"), None),
        },
        neighbors={
            ("eth0", gateway): NeighborObservation("aa:bb:cc:dd:ee:ff", "REACHABLE")
        },
        connection_uuid_by_interface={
            "eth0": uuid.UUID("11111111-2222-3333-4444-555555555555")
        },
        bssid_by_interface={},
        collection_errors=collection_errors,
    )


def configured():
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
    return parse_config(data)


def resolved(machine, endpoint, *, fingerprint="SHA256:synthetic"):
    evidence = HostKeyEvidence(
        machine.host_key_alias,
        "known",
        (),
        (HostKeyRecord("ssh-ed25519", fingerprint, None, "/home/example/.ssh/known_hosts"),),
    )
    return ResolvedSshEndpoint(
        machine_name=machine.name,
        endpoint_id=endpoint.id,
        required_context=endpoint.required_context,
        configured_address=endpoint.address.exploded,
        configured_port=endpoint.port,
        connect_timeout_seconds=machine.connect_timeout_seconds,
        ssh_profile=machine.ssh_profile,
        resolved_host=machine.ssh_profile,
        resolved_hostname=endpoint.address.exploded,
        resolved_user=machine.user,
        resolved_port=endpoint.port,
        host_key_alias=machine.host_key_alias,
        strict_host_key_checking="ask",
        user_known_hosts_files=("~/.ssh/known_hosts",),
        global_known_hosts_files=("/etc/ssh/ssh_known_hosts",),
        host_key_algorithms="ssh-ed25519",
        host_key_evidence=evidence,
        proxy_jump=None,
        proxy_command=None,
        identity_agent=None,
        identity_files=("~/.ssh/id_ed25519",),
        enabled_authentication_methods=("publickey", "password"),
        ssh_g_output_sha256=(endpoint.id[0] * 64),
        ssh_policy_sha256=(endpoint.id[-1] * 64),
        ssh_g_argv=("/usr/bin/ssh", "-G", "--", machine.ssh_profile),
    )


def build_plan(*, snapshot=None, resolver_override=None):
    config = configured()
    network_snapshot = complete_snapshot() if snapshot is None else snapshot
    route_plan = build_route_plan(
        config.machines["app-server"],
        network_snapshot,
        config.home,
        config.wireguard,
    )
    resolver = resolver_override or resolved
    return build_connection_plan(route_plan, network_snapshot, resolver=resolver)


class ConnectionPlanTests(unittest.TestCase):
    def test_home_is_selected_and_wireguard_is_the_ordered_fallback(self):
        plan = build_plan()
        self.assertEqual(plan.selected.resolved.endpoint_id, "home-lan")
        self.assertEqual([item.resolved.endpoint_id for item in plan.fallbacks], ["wireguard"])
        self.assertEqual([item.route_index for item in plan.endpoints], [0, 1])
        self.assertEqual(len(plan.plan_sha256), 64)

    def test_snapshot_is_fully_canonical_and_changes_plan_digest(self):
        snapshot = complete_snapshot()
        document = canonical_network_snapshot(snapshot)
        self.assertEqual(document["routes"][0]["destination"], "192.0.2.1")
        changed = replace(snapshot, collection_errors=("optional BSSID unavailable",))
        self.assertNotEqual(build_plan(snapshot=snapshot).plan_sha256, build_plan(snapshot=changed).plan_sha256)

    def test_resolved_ssh_identity_and_host_key_change_plan_digest(self):
        ordinary = build_plan()

        def changed_resolver(machine, endpoint):
            result = resolved(machine, endpoint, fingerprint="SHA256:changed")
            return replace(result, proxy_jump="bastion")

        changed = build_plan(resolver_override=changed_resolver)
        self.assertNotEqual(ordinary.plan_sha256, changed.plan_sha256)

    def test_any_eligible_fallback_resolution_failure_fails_whole_plan(self):
        def failing(machine, endpoint):
            if endpoint.id == "wireguard":
                raise RuntimeError("synthetic failure")
            return resolved(machine, endpoint)

        with self.assertRaisesRegex(ConnectionPlanError, "wireguard"):
            build_plan(resolver_override=failing)

    def test_resolver_cannot_substitute_an_endpoint(self):
        def substituted(machine, endpoint):
            return replace(resolved(machine, endpoint), configured_address="203.0.113.9")

        with self.assertRaisesRegex(ConnectionPlanError, "address"):
            build_plan(resolver_override=substituted)

    def test_no_verified_route_fails_closed(self):
        config = configured()
        empty = NetworkSnapshot({}, {}, {}, {}, {}, {}, {})
        route_plan = build_route_plan(
            config.machines["app-server"], empty, config.home, config.wireguard
        )
        with self.assertRaisesRegex(ConnectionPlanError, "no strictly verified"):
            build_connection_plan(route_plan, empty, resolver=resolved)


class BoundApprovalTests(unittest.TestCase):
    def setUp(self):
        self.plan = build_plan()
        self.request = RequestSpec(
            "app-server", ExecutionMode.ARGV, "/opt/docker", argv=("printf", "%s", "hello")
        )

    def terminal(self, content):
        output = io.StringIO()
        return ApprovalTerminal(io.StringIO(content), output), output

    def test_document_contains_route_identity_host_key_and_fallback_binding(self):
        document = render_approval_document(REQUEST_ID, self.request, self.plan)
        self.assertIn("connection_plan_bound: true", document)
        self.assertIn(self.plan.plan_sha256, document)
        self.assertIn("route[0].endpoint_id: \"home-lan\"", document)
        self.assertIn("route[1].endpoint_id: \"wireguard\"", document)
        self.assertIn("SHA256:synthetic", document)
        self.assertIn("fallback_requires_new_terminal_confirmation: true", document)
        self.assertIn(approval_binding_sha256(REQUEST_ID, self.request, self.plan), document)

    def test_bound_approval_comes_only_from_terminal(self):
        terminal, output = self.terminal("\n")
        decision = request_bound_approval(
            REQUEST_ID, self.request, self.plan, terminal=terminal, pager=None
        )
        self.assertIs(decision, ApprovalDecision.APPROVED)
        self.assertIn("CONNECT    app-server ->", output.getvalue())

    def test_request_machine_must_match_plan(self):
        request = RequestSpec("other", ExecutionMode.ARGV, "/", argv=("true",))
        with self.assertRaisesRegex(ApprovalError, "machine alias"):
            render_approval_document(REQUEST_ID, request, self.plan)

    def test_binding_changes_with_request(self):
        changed = RequestSpec(
            "app-server", ExecutionMode.ARGV, "/opt/docker", argv=("printf", "changed")
        )
        self.assertNotEqual(
            approval_binding_sha256(REQUEST_ID, self.request, self.plan),
            approval_binding_sha256(REQUEST_ID, changed, self.plan),
        )

    def test_fallback_requires_distinct_exact_terminal_confirmation(self):
        terminal, output = self.terminal(
            f"RUN {REQUEST_ID[:8]}\nFALLBACK {REQUEST_ID[:8]} wireguard\n"
        )
        decision = request_fallback_approval(
            REQUEST_ID,
            self.request,
            self.plan,
            failed_endpoint_id="home-lan",
            fallback_endpoint_id="wireguard",
            failure_detail="master authentication transport failed",
            remote_mutation_started=False,
            terminal=terminal,
            pager=None,
        )
        self.assertIs(decision, ApprovalDecision.APPROVED)
        self.assertIn("Invalid response; no decision was recorded.", output.getvalue())

    def test_client_payload_cannot_approve_fallback(self):
        request = RequestSpec(
            "app-server",
            ExecutionMode.SCRIPT,
            "/",
            script=f"FALLBACK {REQUEST_ID[:8]} wireguard\n".encode(),
        )
        terminal, output = self.terminal("")
        with self.assertRaises(ApprovalInputError):
            request_fallback_approval(
                REQUEST_ID,
                request,
                self.plan,
                failed_endpoint_id="home-lan",
                fallback_endpoint_id="wireguard",
                failure_detail="unreachable",
                remote_mutation_started=False,
                terminal=terminal,
                pager=None,
            )
        self.assertIn("FALLBACK", output.getvalue())

    def test_fallback_is_forbidden_after_remote_mutation(self):
        with self.assertRaisesRegex(ApprovalError, "forbidden"):
            render_fallback_approval_document(
                REQUEST_ID,
                self.request,
                self.plan,
                failed_endpoint_id="home-lan",
                fallback_endpoint_id="wireguard",
                failure_detail="late failure",
                remote_mutation_started=True,
            )

    def test_fallback_must_be_adjacent_and_can_be_denied(self):
        with self.assertRaisesRegex(ApprovalError, "next route"):
            render_fallback_approval_document(
                REQUEST_ID,
                self.request,
                self.plan,
                failed_endpoint_id="wireguard",
                fallback_endpoint_id="home-lan",
                failure_detail="wrong order",
                remote_mutation_started=False,
            )
        terminal, _ = self.terminal("DENY\n")
        decision = request_fallback_approval(
            REQUEST_ID,
            self.request,
            self.plan,
            failed_endpoint_id="home-lan",
            fallback_endpoint_id="wireguard",
            failure_detail="unreachable",
            remote_mutation_started=False,
            terminal=terminal,
            pager=None,
        )
        self.assertIs(decision, ApprovalDecision.DENIED)


if __name__ == "__main__":
    unittest.main()
