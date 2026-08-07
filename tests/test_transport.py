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
    KeyEnrollmentMutationError,
    KeyEnrollmentOutcome,
    MasterTransportPool,
    SshMasterStartError,
    TransportAuthorization,
    TransportBusyError,
    TransportError,
    TransportIdentityError,
    build_batch_channel_prefix,
    build_enrollment_master_start_invocation,
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
        self.fail_next_stop = False

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
        if self.fail_next_stop:
            self.fail_next_stop = False
            raise RuntimeError("synthetic master stop failure")
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


class PartialStartMasterBackend(FakeMasterBackend):
    def start_master(self, invocation, control_path):
        super().start_master(invocation, control_path)
        raise SshMasterStartError(255)


class FakeKeyManager:
    def __init__(self, outcome="enrolled"):
        self.outcome = outcome
        self.events = []

    def prepare_local_key(self, resolved):
        self.events.append(("local-key-prepared", resolved.endpoint_id))

    def enroll_remote_key(
        self, resolved, control_path, *, before_remote_mutation
    ):
        outcome = (
            self.outcome.pop(0)
            if isinstance(self.outcome, list)
            else self.outcome
        )
        self.events.append(("remote-key-inspected", resolved.endpoint_id))
        if outcome == "present":
            return KeyEnrollmentOutcome.ALREADY_PRESENT
        if outcome == "pre-failure":
            raise TransportError("read-only enrollment inspection failed")
        before_remote_mutation()
        self.events.append(("remote-enrollment-started", resolved.endpoint_id))
        if outcome == "post-failure":
            raise TransportError("append succeeded before verification failed")
        return KeyEnrollmentOutcome.ENROLLED_AND_VERIFIED


class FakeKeyEnrollmentLifecycle:
    def __init__(self):
        self.events = []

    def before_remote_mutation(self, resolved):
        self.events.append(("durable-boundary", resolved.endpoint_id))

    def remote_mutation_verified(self, resolved):
        self.events.append(("enrollment-verified", resolved.endpoint_id))


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

    def test_post_enrollment_master_is_public_key_only_and_agent_free(self):
        invocation = build_master_start_invocation(
            self.endpoint, self.control, control_persist_seconds=600
        )
        self.assertFalse(invocation.interactive_terminal)
        self.assertEqual(invocation.kind, "start-master")
        self.assertEqual(invocation.argv[0], "/usr/bin/ssh")
        for required in (
            "-M", "-N", "-f", "BatchMode=yes", "RemoteCommand=none",
            "RequestTTY=no", "IdentityAgent=none", "IdentitiesOnly=yes",
            "GSSAPIAuthentication=no", "HostbasedAuthentication=no",
            "KbdInteractiveAuthentication=no", "PasswordAuthentication=no",
            "PreferredAuthentications=publickey", "PubkeyAuthentication=yes",
            "ClearAllForwardings=yes", "ControlMaster=yes",
            "StrictHostKeyChecking=ask", "HostName=192.0.2.20", "-T",
        ):
            self.assertIn(required, invocation.argv)
        self.assertEqual(invocation.argv[-2:], ("--", "app-server"))

    def test_enrollment_master_is_the_only_prompt_capable_exception(self):
        invocation = build_enrollment_master_start_invocation(
            self.endpoint, self.control, control_persist_seconds=600
        )
        self.assertTrue(invocation.interactive_terminal)
        self.assertEqual(invocation.kind, "start-enrollment-master")
        for required in (
            "BatchMode=no", "IdentityAgent=none", "IdentitiesOnly=yes",
            "GSSAPIAuthentication=no", "HostbasedAuthentication=no",
            "KbdInteractiveAuthentication=yes", "PasswordAuthentication=yes",
            "PreferredAuthentications=publickey,keyboard-interactive,password",
            "PubkeyAuthentication=yes", "StrictHostKeyChecking=ask",
        ):
            self.assertIn(required, invocation.argv)

    def test_control_and_batch_channels_can_never_prompt(self):
        check = build_master_control_invocation(self.endpoint, self.control, "check")
        batch = build_batch_channel_prefix(self.endpoint, self.control)
        for invocation in (check, batch):
            self.assertFalse(invocation.interactive_terminal)
            self.assertIn("BatchMode=yes", invocation.argv)
            self.assertIn("IdentityAgent=none", invocation.argv)
            self.assertIn("IdentitiesOnly=yes", invocation.argv)
            self.assertIn("PasswordAuthentication=no", invocation.argv)
            self.assertIn("KbdInteractiveAuthentication=no", invocation.argv)
            self.assertIn("PreferredAuthentications=publickey", invocation.argv)
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

    def _successor_pool(self):
        """A pool standing in for the next broker process over the same dir."""

        return MasterTransportPool(
            self.pool.control_dir,
            backend=self.backend,
            identity_revalidator=lambda endpoint: self.current.get(
                endpoint.ssh_profile, endpoint
            ),
            clock=lambda: self.now,
            max_masters=3,
            idle_timeout_seconds=600,
        )

    def _acquire_from(self, pool, index, request_id=SECOND_ID):
        endpoint = self.endpoints[index]
        return pool.acquire(
            authorization(
                endpoint.ssh_profile,
                endpoint,
                request_id=request_id,
                plan_digest="d" * 64,
            ),
            endpoint,
        )

    def test_master_surviving_a_previous_process_is_stopped_and_replaced(self):
        # Regression: masters are detached with ControlPersist, so one outlives
        # the process that started it. The next process derives the same path,
        # has no record of the survivor, and could never recover on its own.
        lease = self.acquire(0)
        path = lease.transport.control_path
        lease.release()
        successor = self._successor_pool()
        starts_before = len(self.backend.starts)

        replacement = self._acquire_from(successor, 0)

        self.assertEqual(replacement.transport.control_path, path)
        self.assertEqual([item.kind for item in self.backend.stops], ["master-exit"])
        self.assertEqual(len(self.backend.starts), starts_before + 1)
        self.assertTrue(stat.S_ISSOCK(path.stat().st_mode))
        replacement.release()

    def test_socket_left_by_a_dead_master_is_removed_without_a_stop(self):
        lease = self.acquire(0)
        path = lease.transport.control_path
        lease.release()
        # The master died without cleaning up; the path outlives it.
        self.backend.expire(path, leave_path=True)
        successor = self._successor_pool()

        replacement = self._acquire_from(successor, 0)

        self.assertEqual(replacement.transport.control_path, path)
        self.assertEqual(self.backend.stops, [])
        replacement.release()

    def test_a_pre_existing_non_socket_is_refused_and_never_removed(self):
        lease = self.acquire(0)
        path = lease.transport.control_path
        lease.release()
        self.backend.expire(path, leave_path=False)
        path.write_bytes(b"not a control socket")
        path.chmod(0o600)
        successor = self._successor_pool()

        with self.assertRaisesRegex(
            TransportError, "refusing a pre-existing master control path"
        ):
            self._acquire_from(successor, 0)

        self.assertTrue(path.exists())
        self.assertEqual(path.read_bytes(), b"not a control socket")
        self.assertEqual(self.backend.stops, [])

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

    def test_expired_or_missing_master_reauthenticates_without_password_fallback(self):
        lease = self.acquire(0)
        path = lease.transport.control_path
        lease.release()
        self.backend.expire(path, leave_path=True)
        replacement = self.acquire(0, request_id=SECOND_ID)
        self.assertEqual(len(self.backend.starts), 2)
        self.assertFalse(self.backend.starts[-1].interactive_terminal)
        self.assertIn("PasswordAuthentication=no", self.backend.starts[-1].argv)
        replacement.release()

        self.backend.expire(path, leave_path=False)
        third = self.acquire(0, request_id="3" * 32)
        self.assertEqual(len(self.backend.starts), 3)
        third.release()

    def test_reboot_recovery_restart_retires_pin_and_reauthenticates(self):
        approved_reboot = self.acquire(0)
        lost_path = approved_reboot.transport.control_path
        self.backend.expire(lost_path, leave_path=False)

        for request_id in (SECOND_ID, "3" * 32):
            with self.subTest(request_id=request_id):
                with self.assertRaisesRegex(
                    TransportBusyError,
                    "active machine transport lost its control socket",
                ):
                    self.acquire(0, request_id=request_id)

        restarted_pool = MasterTransportPool(
            self.pool.control_dir,
            backend=self.backend,
            identity_revalidator=lambda endpoint: self.current.get(
                endpoint.ssh_profile, endpoint
            ),
            clock=lambda: self.now,
            max_masters=3,
            idle_timeout_seconds=600,
        )
        replacement = restarted_pool.acquire(
            authorization(
                self.endpoints[0].ssh_profile,
                self.endpoints[0],
                request_id=SECOND_ID,
            ),
            self.endpoints[0],
        )
        replacement.release()
        repeated = restarted_pool.acquire(
            authorization(
                self.endpoints[0].ssh_profile,
                self.endpoints[0],
                request_id="3" * 32,
            ),
            self.endpoints[0],
        )
        repeated.release()

        self.assertEqual(len(self.backend.starts), 2)
        self.assertEqual(restarted_pool.pinned_request_ids, ())

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

    def test_key_enrollment_crosses_durable_boundary_before_remote_write(self):
        manager = FakeKeyManager()
        lifecycle = FakeKeyEnrollmentLifecycle()
        self.pool.key_manager = manager
        endpoint = self.endpoints[0]

        lease = self.pool.acquire(
            authorization(endpoint.ssh_profile, endpoint),
            endpoint,
            key_enrollment_lifecycle=lifecycle,
        )

        self.assertEqual(
            manager.events,
            [
                ("local-key-prepared", "home-lan"),
                ("remote-key-inspected", "home-lan"),
                ("remote-enrollment-started", "home-lan"),
            ],
        )
        self.assertEqual(
            lifecycle.events,
            [
                ("durable-boundary", "home-lan"),
                ("enrollment-verified", "home-lan"),
            ],
        )
        self.assertEqual(
            [item.kind for item in self.backend.starts],
            ["start-enrollment-master", "start-master"],
        )
        self.assertTrue(self.backend.starts[0].interactive_terminal)
        self.assertFalse(self.backend.starts[1].interactive_terminal)
        self.assertIn("PasswordAuthentication=no", self.backend.starts[1].argv)
        self.assertEqual(len(self.backend.stops), 1)
        lease.release()

    def test_preinstalled_key_needs_no_mutation_boundary(self):
        manager = FakeKeyManager("present")
        lifecycle = FakeKeyEnrollmentLifecycle()
        self.pool.key_manager = manager
        endpoint = self.endpoints[0]

        lease = self.pool.acquire(
            authorization(endpoint.ssh_profile, endpoint),
            endpoint,
            key_enrollment_lifecycle=lifecycle,
        )

        self.assertEqual(lifecycle.events, [])
        self.assertEqual(
            [item.kind for item in self.backend.starts],
            ["start-enrollment-master", "start-master"],
        )
        lease.release()

    def test_post_boundary_enrollment_failure_is_never_downgraded(self):
        manager = FakeKeyManager("post-failure")
        lifecycle = FakeKeyEnrollmentLifecycle()
        self.pool.key_manager = manager
        endpoint = self.endpoints[0]

        with self.assertRaisesRegex(
            KeyEnrollmentMutationError,
            "may have mutated authorized_keys",
        ):
            self.pool.acquire(
                authorization(endpoint.ssh_profile, endpoint),
                endpoint,
                key_enrollment_lifecycle=lifecycle,
            )

        self.assertEqual(
            lifecycle.events,
            [("durable-boundary", "home-lan")],
        )
        self.assertEqual(self.pool.retained_machine_names, ())
        self.assertEqual(list(self.pool.control_dir.iterdir()), [])

    def test_missing_lifecycle_refuses_enrollment_before_remote_write(self):
        manager = FakeKeyManager()
        self.pool.key_manager = manager
        endpoint = self.endpoints[0]

        with self.assertRaisesRegex(TransportError, "durable lifecycle"):
            self.pool.acquire(
                authorization(endpoint.ssh_profile, endpoint),
                endpoint,
            )

        self.assertNotIn(
            ("remote-enrollment-started", "home-lan"),
            manager.events,
        )

        self.backend.fail_next_check = True
        with self.assertRaisesRegex(TransportError, "control check"):
            self.acquire(0)
        self.assertEqual(self.pool.retained_machine_names, ())
        self.assertEqual(list(self.pool.control_dir.iterdir()), [])

    def test_partial_failed_start_stops_owned_master_before_unlink(self):
        self.backend.close()
        self.backend = PartialStartMasterBackend()
        self.addCleanup(self.backend.close)
        self.pool.backend = self.backend

        with self.assertRaisesRegex(SshMasterStartError, "status 255"):
            self.acquire(0)

        self.assertEqual(len(self.backend.starts), 1)
        self.assertEqual(len(self.backend.stops), 1)
        self.assertEqual(self.pool.retained_machine_names, ())
        self.assertEqual(list(self.pool.control_dir.iterdir()), [])

    def test_partial_start_stop_failure_retains_owned_control_socket(self):
        self.backend.close()
        self.backend = PartialStartMasterBackend()
        self.addCleanup(self.backend.close)
        self.backend.fail_next_stop = True
        self.pool.backend = self.backend

        with self.assertRaisesRegex(
            TransportError, "retained for broker lifecycle cleanup"
        ):
            self.acquire(0)

        self.assertEqual(len(self.backend.starts), 1)
        self.assertEqual(len(self.backend.stops), 1)
        self.assertEqual(self.pool.retained_machine_names, ("app-server",))
        retained_path = next(iter(self.backend.sockets))
        self.assertTrue(retained_path.exists())
        self.assertEqual(list(self.pool.control_dir.iterdir()), [retained_path])

    def test_shutdown_retries_cleanup_of_retained_partial_master(self):
        self.backend.close()
        self.backend = PartialStartMasterBackend()
        self.addCleanup(self.backend.close)
        self.backend.fail_next_stop = True
        self.pool.backend = self.backend

        with self.assertRaises(TransportError):
            self.acquire(0)
        retained_path = next(iter(self.backend.sockets))

        self.assertEqual(self.pool.close_idle(), ("app-server",))
        self.assertEqual(len(self.backend.stops), 2)
        self.assertEqual(self.pool.retained_machine_names, ())
        self.assertFalse(retained_path.exists())
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
