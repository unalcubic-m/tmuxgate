from pathlib import Path
import subprocess
import unittest

from tmuxgate.real_ssh import SshChannelRunner
from tmuxgate.reboot_recovery import (
    BOOT_ID_COMMAND,
    BootIdProbeError,
    RealBootIdProbe,
)
from tmuxgate.transport import (
    build_independent_boot_id_probe_invocation,
)
from test_connection_plan import build_plan


BOOT_ID = "11111111-2222-3333-4444-555555555555"


class RecordingRunner:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((tuple(argv), kwargs))
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class BootIdProbeTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = build_plan().selected.resolved

    def probe(self, result):
        runner = RecordingRunner(result)
        return RealBootIdProbe(SshChannelRunner(runner=runner)), runner

    def test_pre_reboot_probe_uses_the_bound_master_and_exact_fixed_command(self):
        probe, runner = self.probe(
            subprocess.CompletedProcess((), 0, f"{BOOT_ID}\n".encode(), b"")
        )
        transport = type(
            "Transport",
            (),
            {
                "endpoint": self.endpoint,
                "control_path": Path("/tmp/tmuxgate-test-control.sock"),
            },
        )()

        self.assertEqual(probe.capture_pre_reboot(transport), BOOT_ID)
        argv = runner.calls[0][0]
        self.assertIn("-S", argv)
        self.assertEqual(argv[-1], BOOT_ID_COMMAND)

    def test_independent_probe_explicitly_disables_every_master_option(self):
        invocation = build_independent_boot_id_probe_invocation(self.endpoint)

        self.assertEqual(invocation.kind, "independent-boot-id-probe")
        self.assertNotIn("-S", invocation.argv)
        self.assertIn("ControlMaster=no", invocation.argv)
        self.assertIn("ControlPath=none", invocation.argv)
        self.assertIn("ControlPersist=no", invocation.argv)
        self.assertIn("StrictHostKeyChecking=yes", invocation.argv)
        self.assertIn(f"HostKeyAlias={self.endpoint.host_key_alias}", invocation.argv)
        self.assertEqual(invocation.argv[-1], BOOT_ID_COMMAND)

    def test_post_disconnect_probe_accepts_only_one_canonical_boot_id(self):
        invalid = (
            b"11111111-2222-3333-4444-555555555555\nextra\n",
            b"x" * 65,
            b"11111111-2222-3333-4444-55555555555X\n",
        )
        for stdout in invalid:
            with self.subTest(stdout=stdout[:16]):
                probe, _runner = self.probe(
                    subprocess.CompletedProcess((), 0, stdout, b"")
                )
                with self.assertRaisesRegex(BootIdProbeError, "boot ID probe"):
                    probe.probe_after_disconnect(self.endpoint)

    def test_host_key_mismatch_has_a_stable_classification(self):
        probe, _runner = self.probe(
            subprocess.CompletedProcess(
                (),
                255,
                b"",
                b"Host key verification failed.\n",
            )
        )

        with self.assertRaises(BootIdProbeError) as raised:
            probe.probe_after_disconnect(self.endpoint)
        self.assertEqual(raised.exception.code, "host_key_mismatch")

    def test_pre_reboot_timeout_is_classified_before_command_start(self):
        probe, _runner = self.probe(subprocess.TimeoutExpired(("ssh",), 10))
        transport = type(
            "Transport",
            (),
            {
                "endpoint": self.endpoint,
                "control_path": Path("/tmp/tmuxgate-test-control.sock"),
            },
        )()

        with self.assertRaises(BootIdProbeError) as raised:
            probe.capture_pre_reboot(transport)
        self.assertEqual(raised.exception.code, "pre_reboot_boot_id_unavailable")
