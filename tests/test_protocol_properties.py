"""Property and fuzz tests for the untrusted broker frame boundary."""

import unittest

from hypothesis import given, settings, strategies as st

from tmuxgate.protocol import ProtocolError, decode_frame, encode_frame


_TEXT = st.text(
    alphabet=st.characters(exclude_categories=("Cs",)),
    max_size=64,
)
_JSON_SCALARS = st.none() | st.booleans() | st.integers() | _TEXT
_JSON_VALUES = st.recursive(
    _JSON_SCALARS,
    lambda children: st.lists(children, max_size=8)
    | st.dictionaries(_TEXT, children, max_size=8),
    max_leaves=24,
)
_HEADERS = st.dictionaries(_TEXT, _JSON_VALUES, max_size=12)


class ProtocolPropertyTests(unittest.TestCase):
    @settings(max_examples=200, deadline=None)
    @given(header=_HEADERS, payload=st.binary(max_size=4096))
    def test_generated_json_headers_and_binary_payloads_round_trip(self, header, payload):
        frame = decode_frame(encode_frame(header, payload))
        self.assertEqual(frame.header, header)
        self.assertEqual(frame.payload, payload)

    @settings(max_examples=300, deadline=None)
    @given(data=st.binary(max_size=4096))
    def test_arbitrary_input_never_escapes_the_protocol_error_boundary(self, data):
        try:
            frame = decode_frame(data)
        except ProtocolError:
            return
        self.assertIsInstance(frame.header, dict)
        self.assertIsInstance(frame.payload, bytes)

    @settings(max_examples=200, deadline=None)
    @given(
        header=_HEADERS,
        payload=st.binary(max_size=1024),
        cut_seed=st.integers(min_value=0),
        trailing=st.binary(min_size=1, max_size=32),
    )
    def test_generated_truncation_and_trailing_bytes_fail_closed(
        self,
        header,
        payload,
        cut_seed,
        trailing,
    ):
        encoded = encode_frame(header, payload)
        cut = cut_seed % len(encoded)
        with self.assertRaises(ProtocolError):
            decode_frame(encoded[:cut])
        with self.assertRaises(ProtocolError):
            decode_frame(encoded + trailing)


if __name__ == "__main__":
    unittest.main()
