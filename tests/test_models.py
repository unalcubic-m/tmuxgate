import unittest
import os

from tmuxgate.models import ExecutionMode, RequestSpec, ValidationError


class RequestSpecTests(unittest.TestCase):
    def test_purpose_is_bounded_bound_to_digest_and_round_trips(self):
        request = RequestSpec(
            "host",
            ExecutionMode.ARGV,
            "/",
            argv=("true",),
            purpose="Verify that the remote shell can run a harmless command",
        )
        rebuilt = RequestSpec.from_wire(request.to_wire_header(), b"")
        self.assertEqual(rebuilt.purpose, request.purpose)
        without = RequestSpec("host", ExecutionMode.ARGV, "/", argv=("true",))
        self.assertNotEqual(request.client_request_sha256(), without.client_request_sha256())
        with self.assertRaises(ValidationError):
            RequestSpec("host", ExecutionMode.ARGV, "/", argv=("true",), purpose="bad\nline")

    def test_argv_is_preserved_as_structured_unicode_data(self):
        argv = (
            "printf",
            "space value",
            "single'quote",
            'double"quote',
            "$HOME; rm -rf nope",
            "line one\nline two",
            "Türkçe/日本語",
            "",
        )
        request = RequestSpec("app-server", ExecutionMode.ARGV, "/tmp/a b", argv=argv)
        rebuilt = RequestSpec.from_wire(request.to_wire_header(), b"")
        self.assertEqual(rebuilt.argv, argv)
        self.assertEqual(rebuilt.cwd, "/tmp/a b")

    def test_script_bytes_are_preserved_exactly(self):
        script = b"#!/bin/bash\ncat <<'EOF'\n\xff\x00-not-allowed-in-argv-but-valid-here\nEOF\n"
        request = RequestSpec("hypervisor", ExecutionMode.SCRIPT, "/root", script=script)
        rebuilt = RequestSpec.from_wire(request.to_wire_header(), script)
        self.assertEqual(rebuilt.script, script)
        self.assertEqual(rebuilt.script_byte_length, len(script))
        self.assertEqual(rebuilt.client_request_sha256(), request.client_request_sha256())

    def test_client_cannot_supply_endpoint_or_ssh_options(self):
        request = RequestSpec("app-server", ExecutionMode.ARGV, "/", argv=("true",))
        header = request.to_wire_header()
        header["endpoint"] = "192.0.2.20"
        with self.assertRaisesRegex(ValidationError, "unknown request fields: endpoint"):
            RequestSpec.from_wire(header, b"")

    def test_non_utf8_filesystem_bytes_round_trip_exactly(self):
        raw_argument = b"non-utf8-\xff"
        argument = os.fsdecode(raw_argument)
        request = RequestSpec("host", ExecutionMode.ARGV, "/", argv=(argument,))
        rebuilt = RequestSpec.from_wire(request.to_wire_header(), b"")
        self.assertEqual(os.fsencode(rebuilt.argv[0]), raw_argument)
        self.assertEqual(rebuilt.client_request_sha256(), request.client_request_sha256())

    def test_protocol_version_must_be_an_integer(self):
        request = RequestSpec("host", ExecutionMode.ARGV, "/", argv=("true",))
        for invalid in (True, 1.0):
            header = request.to_wire_header()
            header["protocol"] = invalid
            with self.assertRaises(ValidationError):
                RequestSpec.from_wire(header, b"")

    def test_alias_cannot_become_an_ssh_option(self):
        with self.assertRaises(ValidationError):
            RequestSpec("-o-proxycommand-bad", ExecutionMode.ARGV, "/", argv=("true",))

    def test_exec_rejects_payload_and_script_rejects_argv(self):
        with self.assertRaises(ValidationError):
            RequestSpec("host", ExecutionMode.ARGV, "/", argv=("true",), script=b"bad")
        with self.assertRaises(ValidationError):
            RequestSpec("host", ExecutionMode.SCRIPT, "/", argv=("true",), script=b"echo")

    def test_environment_is_sorted_and_rejects_nul(self):
        request = RequestSpec(
            "host",
            ExecutionMode.ARGV,
            "/",
            argv=("env",),
            environment={"ZED": "last", "ALPHA": "first"},
        )
        self.assertEqual(request.environment, (("ALPHA", "first"), ("ZED", "last")))
        with self.assertRaises(ValidationError):
            RequestSpec(
                "host",
                ExecutionMode.ARGV,
                "/",
                argv=("env",),
                environment={"BAD": "secret\x00suffix"},
            )


if __name__ == "__main__":
    unittest.main()
