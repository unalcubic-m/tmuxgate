import socket
import struct
import threading
import time
import unittest

from tmuxgate.protocol import (
    MAGIC,
    MAX_FRAME_PAYLOAD_BYTES,
    PREFIX,
    ProtocolError,
    decode_frame,
    encode_frame,
    receive_frame,
    receive_single_request,
    send_frame,
)


class ProtocolTests(unittest.TestCase):
    def test_binary_payload_and_unicode_header_round_trip(self):
        payload = bytes(range(256)) + b"\x00\xff"
        encoded = encode_frame({"type": "request", "text": "Türkçe"}, payload)
        decoded = decode_frame(encoded)
        self.assertEqual(decoded.header, {"text": "Türkçe", "type": "request"})
        self.assertEqual(decoded.payload, payload)

    def test_socket_round_trip(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        send_frame(left, {"type": "test"}, b"payload")
        frame = receive_frame(right)
        self.assertEqual(frame.header, {"type": "test"})
        self.assertEqual(frame.payload, b"payload")

    def test_rejects_bad_magic_truncation_and_trailing_bytes(self):
        good = encode_frame({"type": "test"})
        with self.assertRaises(ProtocolError):
            decode_frame(b"BADMAGIC" + good[8:])
        with self.assertRaises(ProtocolError):
            decode_frame(good[:-1])
        with self.assertRaises(ProtocolError):
            decode_frame(good + b"extra")

    def test_rejects_untrusted_oversized_length_before_reading_body(self):
        malicious = PREFIX.pack(MAGIC, 2, MAX_FRAME_PAYLOAD_BYTES + 1) + b"{}"
        with self.assertRaisesRegex(ProtocolError, "payload length"):
            decode_frame(malicious)

    def test_rejects_duplicate_json_keys(self):
        header = b'{"type":"one","type":"two"}'
        frame = PREFIX.pack(MAGIC, len(header), 0) + header
        with self.assertRaisesRegex(ProtocolError, "duplicate JSON key"):
            decode_frame(frame)

    def test_peer_close_mid_frame_is_an_error(self):
        left, right = socket.socketpair()
        self.addCleanup(right.close)
        left.sendall(struct.pack("!8sIQ", MAGIC, 20, 0) + b"{}")
        left.close()
        with self.assertRaisesRegex(ProtocolError, "closed connection"):
            receive_frame(right)

    def test_partial_peer_is_bounded_by_read_timeout(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.sendall(struct.pack("!8sIQ", MAGIC, 20, 0) + b"{}")
        with self.assertRaisesRegex(ProtocolError, "timed out"):
            receive_frame(right, timeout_seconds=0.01)

    def test_slow_trickle_cannot_extend_the_absolute_frame_deadline(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        encoded = encode_frame({"type": "slow"}, b"payload")

        def trickle():
            for byte in encoded:
                try:
                    left.send(bytes([byte]))
                except OSError:
                    return
                time.sleep(0.005)

        sender = threading.Thread(target=trickle)
        sender.start()
        started = time.monotonic()
        with self.assertRaisesRegex(ProtocolError, "timed out"):
            receive_frame(right, timeout_seconds=0.03)
        self.assertLess(time.monotonic() - started, 0.15)
        left.close()
        sender.join(timeout=1)

    def test_single_request_requires_shutdown_and_rejects_second_frame(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        left.sendall(encode_frame({"type": "one"}) + encode_frame({"type": "two"}))
        left.shutdown(socket.SHUT_WR)
        with self.assertRaisesRegex(ProtocolError, "more than one"):
            receive_single_request(right)

    def test_rejects_nonstandard_json_constants(self):
        header = b'{"value":NaN}'
        frame = PREFIX.pack(MAGIC, len(header), 0) + header
        with self.assertRaisesRegex(ProtocolError, "nonstandard JSON constant"):
            decode_frame(frame)

    def test_timeout_validation_rejects_bool_nonfinite_and_wrong_types(self):
        invalid_values = (True, 0, -1, float("nan"), float("inf"), "1")
        for value in invalid_values:
            with self.subTest(api="frame", value=value):
                with self.assertRaisesRegex(ProtocolError, "positive finite"):
                    receive_frame(None, timeout_seconds=value)
            with self.subTest(api="single-request", value=value):
                with self.assertRaisesRegex(ProtocolError, "positive finite"):
                    receive_single_request(None, timeout_seconds=value)


if __name__ == "__main__":
    unittest.main()
