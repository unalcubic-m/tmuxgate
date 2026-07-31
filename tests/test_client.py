import socket
import time
import unittest

from tmuxgate.client import exchange_request
from tmuxgate.models import ExecutionMode, RequestSpec


class ClientTransmissionTests(unittest.TestCase):
    def test_request_send_has_an_absolute_deadline(self):
        sender, nonreading_broker = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sender.close)
        self.addCleanup(nonreading_broker.close)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        request = RequestSpec(
            machine_alias="machine-a",
            mode=ExecutionMode.SCRIPT,
            cwd="/tmp",
            script=b"x" * (2 * 1024 * 1024),
        )

        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            exchange_request(sender, request, send_timeout_seconds=0.02)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_invalid_send_timeout_is_rejected_before_transmission(self):
        sender, broker = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sender.close)
        self.addCleanup(broker.close)
        request = RequestSpec(
            machine_alias="machine-a",
            mode=ExecutionMode.ARGV,
            cwd="/tmp",
            argv=("true",),
        )

        for invalid in (True, 0, -1, float("nan"), float("inf"), "5"):
            with self.subTest(value=invalid):
                with self.assertRaises(ValueError):
                    exchange_request(sender, request, send_timeout_seconds=invalid)


if __name__ == "__main__":
    unittest.main()
