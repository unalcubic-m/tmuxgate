import io
import socket
import time
import unittest

from tmuxgate.models import PROTOCOL_VERSION
from tmuxgate.protocol import ProtocolError, send_frame
from tmuxgate.result import (
    ExecutionResult,
    TransportStatus,
    receive_result,
    relay_transparent,
    send_result,
    send_status,
)


REQUEST_ID = "0123456789abcdef0123456789abcdef"


class ResultProtocolTests(unittest.TestCase):
    def test_exit_seven_and_streams_remain_separate(self):
        expected = ExecutionResult(
            REQUEST_ID,
            TransportStatus.COMPLETE,
            stdout=b"stdout-line\n\x00",
            stderr=b"stderr-line\n\xff",
            remote_exit_status=7,
        )
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        send_status(left, REQUEST_ID, "queued")
        send_result(left, expected)
        actual = receive_result(right, expected_request_id=REQUEST_ID)
        self.assertEqual(actual, expected)
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        self.assertEqual(relay_transparent(actual, stdout, stderr), 7)
        self.assertEqual(stdout.getvalue(), expected.stdout)
        self.assertEqual(stderr.getvalue(), expected.stderr)

    def test_denial_has_no_remote_exit_and_uses_local_status(self):
        result = ExecutionResult(
            REQUEST_ID,
            TransportStatus.DENIED,
            detail="request denied by human",
        )
        self.assertEqual(result.transparent_exit_code(), 77)
        self.assertIsNone(result.remote_exit_status)
        stdout = io.BytesIO()
        stderr = io.BytesIO()
        self.assertEqual(relay_transparent(result, stdout, stderr), 77)
        self.assertEqual(stdout.getvalue(), b"")
        self.assertIn(b"denied", stderr.getvalue())

    def test_json_mode_is_binary_safe_and_unambiguous(self):
        result = ExecutionResult(
            REQUEST_ID,
            TransportStatus.COMPLETE,
            stdout=b"\xff",
            stderr=b"\x00",
            remote_exit_status=255,
        )
        document = result.structured_json()
        self.assertIn(b'"transport_status":"complete"', document)
        self.assertIn(b'"remote_exit_status":255', document)
        self.assertIn(b'"stdout_base64":"/w=="', document)

    def test_noncomplete_result_cannot_invent_remote_status(self):
        with self.assertRaises(ValueError):
            ExecutionResult(
                REQUEST_ID,
                TransportStatus.INCOMPLETE,
                remote_exit_status=0,
            )

    def test_transparent_incomplete_result_keeps_partial_streams(self):
        result = ExecutionResult(
            REQUEST_ID,
            TransportStatus.INCOMPLETE,
            stdout=b"partial-out\n",
            stderr=b"partial-err\n",
            detail="completion could not be proven",
        )
        stdout = io.BytesIO()
        stderr = io.BytesIO()

        self.assertEqual(relay_transparent(result, stdout, stderr), 70)
        self.assertEqual(stdout.getvalue(), b"partial-out\n")
        self.assertEqual(
            stderr.getvalue(),
            b"partial-err\ntmuxgate: completion could not be proven\n",
        )

    def test_remote_setup_failure_is_distinct_from_pre_remote_and_incomplete(self):
        result = ExecutionResult(
            REQUEST_ID,
            TransportStatus.REMOTE_SETUP_FAILURE,
            detail="authorized_keys may have changed; command was not started",
        )
        self.assertEqual(result.transparent_exit_code(), 70)
        self.assertIsNone(result.remote_exit_status)
        self.assertIn(b'"transport_status":"remote_setup_failure"', result.structured_json())

    def test_result_write_timeout_rejects_nonfinite_values(self):
        result = ExecutionResult(
            REQUEST_ID,
            TransportStatus.COMPLETE,
            remote_exit_status=0,
        )
        for invalid in (True, 0, -1, float("nan"), float("inf"), "1"):
            with self.subTest(value=invalid):
                with self.assertRaisesRegex(ValueError, "positive finite"):
                    send_result(None, result, timeout_seconds=invalid)

    def test_multiframe_result_write_uses_one_absolute_deadline(self):
        sender, nonreading_client = socket.socketpair()
        self.addCleanup(sender.close)
        self.addCleanup(nonreading_client.close)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        result = ExecutionResult(
            REQUEST_ID,
            TransportStatus.COMPLETE,
            stdout=b"x" * (2 * 1024 * 1024),
            remote_exit_status=0,
        )

        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            send_result(sender, result, timeout_seconds=0.02)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_later_status_state_must_be_nonempty_text_without_nul(self):
        for invalid_state in (None, 7, "", "bad\x00state"):
            with self.subTest(state=invalid_state):
                left, right = socket.socketpair()
                try:
                    send_frame(
                        left,
                        {
                            "protocol": PROTOCOL_VERSION,
                            "request_id": REQUEST_ID,
                            "state": invalid_state,
                            "type": "status",
                        },
                    )
                    with self.assertRaisesRegex(ProtocolError, "status state"):
                        receive_result(right, expected_request_id=REQUEST_ID)
                finally:
                    left.close()
                    right.close()


if __name__ == "__main__":
    unittest.main()
