from dataclasses import replace
import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest

from tmuxgate.approval import ApprovalDecision
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.transport import (
    MasterTransportPool,
    SshInvocation,
    TransportAuthorization,
    TransportBusyError,
    TransportError,
    TransportIdentityError,
    build_batch_channel_prefix,
    build_master_control_invocation,
    build_master_start_invocation,
    issue_fallback_transport_authorization,
    issue_selected_transport_authorization,
    resolved_identity_sha256,
)
from test_connection_plan import REQUEST_ID, build_plan


SECOND_ID = "0123456789abcdef0123456789abcdef"


class FakeMasterBackend:
    """Creates only local Unix sockets; it never invokes OpenSSH."""

    def __init__(self):
        self.sockets = {}
        self.starts = []
        self.checks = []
        self.stops = []
        self.fail_next_start = False
        self.fail_next_check = False

    def start_master(self, invocation, control_path):
        self.starts.append(invocation)
        if self.fail_next_start:
            self.fail_next_start = False
            raise RuntimeError("synthetic authentication failure")
        master = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        master.bind(str(control_path))
        os.chmod(control_path, 0o600)
        master.listen(1)
        self.sockets[control_path] = master

    def check_master(self, invocation, control_path):
        self.checks.append(invocation)
        if self.fail_next_check:
            self.fail_next_check = False
            master = self.sockets.pop(control_path, None)
            if master is not None:
                master.close()
            return False
        return control_path in self.sockets

    def stop_master(self, invocation, control_path):
        self.stops.append(invocation)
        master = self.sockets.pop(control_path, None)
        if master is not None:
            master.close()
        try:
            control_path.unlink()
        except FileNotFoundError:
            pass

    def expire(self, control_path, *, leave_path=True):
        master = self.sockets.pop(control_path)
        master.close()
        if not leave_path:
            control_path.unlink()

    def close(self):
        for path, master in list(self.sockets.items()):
            master.close()
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        self.sockets.clear()


def authorization(machine_name, endpoint, request_id=REQUEST_ID, plan_digest="b" * 64):
    return TransportAuthorization(
        request_id=request_id,
        machine_name=machine_name,
        endpoint_id=endpoint.endpoint_id,
        connection_plan_sha256=plan_digest,
        approval_binding_sha256="c" * 64,
        resolved_identity_sha256=resolved_identity_sha256(endpoint),
    )


def machine_endpoint(base, index):
    names = ("app-server", "hypervisor", "utility-server", "edge-server")
    suffix = index + 20
    name = names[index]
    return replace(
        base,
        machine_name=name,
        endpoint_id="home-lan",
        configured_address=f"192.0.2.{suffix}",
        ssh_profile=name,
        resolved_host=name,
        resolved_hostname=f"192.0.2.{suffix}",
        host_key_alias=f"tmuxgate-{name}",
        ssh_g_output_sha256=f"{index + 1}" * 64,
        ssh_policy_sha256=f"{index + 5}" * 64,
        host_key_evidence=replace(
            base.host_key_evidence,
            host_key_alias=f"tmuxgate-{name}",
        ),
    )


class InvocationTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = build_plan().selected.resolved
        self.control = Path("/run/user/1000/tmuxgate/control/master-test.sock")

    def test_initial_master_is_interactive_but_overrides_global_remote_session(self):
        invocation = build_master_start_invocation(
            self.endpoint, self.control, control_persist_seconds=600
        )
        self.assertTrue(invocation.interactive_terminal)
        self.assertEqual(invocation.kind, "start-master")
        self.assertEqual(invocation.argv[0], "/usr/bin/ssh")
        for required in (
            "-M", "-N", "-f", "BatchMode=no", "RemoteCommand=none",
            "RequestTTY=no", "ClearAllForwardings=yes", "ControlMaster=yes",
            "StrictHostKeyChecking=ask", "HostName=192.0.2.20", "-T",
        ):
            self.assertIn(required, invocation.argv)
        self.assertEqual(invocation.argv[-2:], ("--", "app-server"))

    def test_control_and_batch_channels_can_never_prompt(self):
        check = build_master_control_invocation(self.endpoint, self.control, "check")
        batch = build_batch_channel_prefix(self.endpoint, self.control)
        for invocation in (check, batch):
            self.assertFalse(invocation.interactive_terminal)
            self.assertIn("BatchMode=yes", invocation.argv)
            self.assertIn("RemoteCommand=none", invocation.argv)
            self.assertIn("RequestTTY=no", invocation.argv)
            self.assertIn("-T", invocation.argv)
        self.assertEqual(check.argv[check.argv.index("-O") + 1], "check")
        self.assertIn("ControlMaster=no", batch.argv)

    def test_unsupported_paths_operations_and_timeouts_fail_closed(self):
        with self.assertRaises(TransportError):
            build_master_start_invocation(self.endpoint, "relative.sock", control_persist_seconds=10)
        with self.assertRaises(ValueError):
            build_master_start_invocation(self.endpoint, self.control, control_persist_seconds=0)
        with self.assertRaises(ValueError):
            build_master_control_invocation(self.endpoint, self.control, "forward")


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.plan = build_plan()
        self.request = RequestSpec(
            "app-server", ExecutionMode.ARGV, "/", argv=("true",)
        )

    def test_selected_authorization_requires_positive_human_decision(self):
        with self.assertRaisesRegex(TransportIdentityError, "human approval"):
            issue_selected_transport_authorization(
                REQUEST_ID, self.request, self.plan, ApprovalDecision.DENIED
            )
        token = issue_selected_transport_authorization(
            REQUEST_ID, self.request, self.plan, ApprovalDecision.APPROVED
        )
        self.assertEqual(token.endpoint_id, "home-lan")
        self.assertEqual(token.connection_plan_sha256, self.plan.plan_sha256)

    def test_fallback_requires_its_own_approval_and_adjacent_route(self):
        with self.assertRaises(TransportIdentityError):
            issue_fallback_transport_authorization(
                REQUEST_ID,
                self.request,
                self.plan,
                failed_endpoint_id="home-lan",
                fallback_endpoint_id="wireguard",
                fallback_decision=ApprovalDecision.DENIED,
            )
        token = issue_fallback_transport_authorization(
            REQUEST_ID,
            self.request,
            self.plan,
            failed_endpoint_id="home-lan",
            fallback_endpoint_id="wireguard",
            fallback_decision=ApprovalDecision.APPROVED,
        )
        self.assertEqual(token.endpoint_id, "wireguard")
        with self.assertRaisesRegex(TransportIdentityError, "next endpoint"):
            issue_fallback_transport_authorization(
                REQUEST_ID,
                self.request,
                self.plan,
                failed_endpoint_id="wireguard",
                fallback_endpoint_id="home-lan",
                fallback_decision=ApprovalDecision.APPROVED,
            )


class MasterPoolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.backend = FakeMasterBackend()
        self.addCleanup(self.backend.close)
        self.now = 0.0
        self.current = {}
        self.pool = MasterTransportPool(
            Path(self.temporary.name) / "control",
            backend=self.backend,
            identity_revalidator=lambda endpoint: self.current.get(
                endpoint.ssh_profile, endpoint
            ),
            clock=lambda: self.now,
            max_masters=3,
            idle_timeout_seconds=600,
        )
        base = build_plan().selected.resolved
        self.endpoints = tuple(machine_endpoint(base, index) for index in range(4))

    def acquire(self, index, request_id=REQUEST_ID, plan_digest="b" * 64):
        endpoint = self.endpoints[index]
        return self.pool.acquire(
            authorization(
                endpoint.ssh_profile, endpoint, request_id=request_id, plan_digest=plan_digest
            ),
            endpoint,
        )

    def test_private_socket_is_created_reused_and_left_idle_after_release(self):
        lease = self.acquire(0)
        path = lease.transport.control_path
        self.assertEqual(stat.S_IMODE(self.pool.control_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertTrue(stat.S_ISSOCK(path.stat().st_mode))
        lease.release()
        self.now = 10.0
        second = self.acquire(0, request_id=SECOND_ID, plan_digest="d" * 64)
        self.assertEqual(second.transport.control_path, path)
        self.assertEqual(second.transport.connection_plan_sha256, "d" * 64)
        self.assertEqual(len(self.backend.starts), 1)
        second.release()

    def test_three_machines_are_retained_and_fourth_evicts_oldest_idle(self):
        paths = []
        for index in range(3):
            self.now = float(index)
            lease = self.acquire(index, request_id=f"{index + 1:032x}")
            paths.append(lease.transport.control_path)
            lease.release()
        self.assertEqual(
            set(self.pool.retained_machine_names),
            {"app-server", "hypervisor", "utility-server"},
        )

        self.now = 10.0
        fourth = self.acquire(3, request_id="4" * 32)
        fourth.release()
        self.assertEqual(len(self.backend.starts), 4)
        self.assertEqual(len(self.backend.stops), 1)
        self.assertFalse(paths[0].exists())
        self.assertEqual(
            set(self.pool.retained_machine_names),
            {"hypervisor", "utility-server", "edge-server"},
        )

    def test_three_jobs_can_pin_same_or_different_masters(self):
        first = self.acquire(0)
        same_machine = self.acquire(0, request_id=SECOND_ID)
        other_machine = self.acquire(1, request_id="3" * 32)
        self.assertEqual(
            self.pool.pinned_request_ids,
            tuple(sorted((REQUEST_ID, SECOND_ID, "3" * 32))),
        )
        with self.assertRaisesRegex(TransportBusyError, "more than one"):
            _ = self.pool.pinned_request_id
        same_machine.release()
        other_machine.release()
        self.assertEqual(self.pool.pinned_request_id, REQUEST_ID)
        first.release()

    def test_expired_or_missing_master_reauthenticates_interactively(self):
        lease = self.acquire(0)
        path = lease.transport.control_path
        lease.release()
        self.backend.expire(path, leave_path=True)
        replacement = self.acquire(0, request_id=SECOND_ID)
        self.assertEqual(len(self.backend.starts), 2)
        self.assertTrue(self.backend.starts[-1].interactive_terminal)
        replacement.release()

        self.backend.expire(path, leave_path=False)
        third = self.acquire(0, request_id="3" * 32)
        self.assertEqual(len(self.backend.starts), 3)
        third.release()

    def test_identity_change_after_approval_prevents_reuse_or_authentication(self):
        endpoint = self.endpoints[0]
        self.current[endpoint.ssh_profile] = replace(
            endpoint, proxy_command="ssh -W %h:%p changed-bastion"
        )
        with self.assertRaisesRegex(TransportIdentityError, "changed after"):
            self.acquire(0)
        self.assertEqual(self.backend.starts, [])

    def test_authorization_for_another_machine_cannot_use_this_endpoint(self):
        endpoint = self.endpoints[0]
        token = authorization("hypervisor", endpoint)
        with self.assertRaisesRegex(TransportIdentityError, "machine"):
            self.pool.acquire(token, endpoint)
        self.assertEqual(self.backend.starts, [])

    def test_new_approved_endpoint_for_same_machine_closes_old_master(self):
        first = self.acquire(0)
        first_path = first.transport.control_path
        first.release()
        alternate = replace(
            self.endpoints[0],
            endpoint_id="wireguard",
            configured_address="198.51.100.200",
            resolved_hostname="198.51.100.200",
            ssh_g_output_sha256="e" * 64,
        )
        self.current[alternate.ssh_profile] = alternate
        token = authorization("app-server", alternate, request_id=SECOND_ID)
        second = self.pool.acquire(token, alternate)
        self.assertFalse(first_path.exists())
        self.assertEqual(len(self.backend.stops), 1)
        self.assertEqual(len(self.backend.starts), 2)
        second.release()

    def test_reaper_closes_only_expired_idle_masters(self):
        first = self.acquire(0)
        first.release()
        self.now = 300.0
        second = self.acquire(1, request_id=SECOND_ID)
        self.now = 601.0
        self.assertEqual(self.pool.reap_expired(), ("app-server",))
        self.assertEqual(self.pool.pinned_request_id, SECOND_ID)
        second.release()

    def test_authentication_or_poststart_check_failure_leaves_no_retained_socket(self):
        self.backend.fail_next_start = True
        with self.assertRaisesRegex(RuntimeError, "authentication"):
            self.acquire(0)
        self.assertEqual(self.pool.retained_machine_names, ())
        self.assertEqual(list(self.pool.control_dir.iterdir()), [])

        self.backend.fail_next_check = True
        with self.assertRaisesRegex(TransportError, "control check"):
            self.acquire(0)
        self.assertEqual(self.pool.retained_machine_names, ())
        self.assertEqual(list(self.pool.control_dir.iterdir()), [])

    def test_preexisting_or_unsafe_control_path_is_never_replaced(self):
        endpoint = self.endpoints[0]
        token = authorization(endpoint.ssh_profile, endpoint)
        expected = self.pool._control_path(
            endpoint.ssh_profile, resolved_identity_sha256(endpoint)
        )
        expected.write_text("do not replace", encoding="ascii")
        with self.assertRaisesRegex(TransportError, "pre-existing"):
            self.pool.acquire(token, endpoint)
        self.assertEqual(expected.read_text(encoding="ascii"), "do not replace")


if __name__ == "__main__":
    unittest.main()
