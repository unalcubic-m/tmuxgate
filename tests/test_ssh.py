import base64
import hashlib
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from tmuxgate.config import parse_config
from tmuxgate.ssh import (
    HostKeyEvidence,
    SshResolutionError,
    build_ssh_g_argv,
    collect_host_key_evidence,
    default_tmuxgate_identity_file,
    resolve_ssh_endpoint,
)
from test_config import valid_config


def unknown_host_key(
    alias="tmuxgate-app-server",
    user_known_hosts_files=(),
    global_known_hosts_files=(),
):
    return HostKeyEvidence(alias, "unknown", (), ())


def ssh_g_output(**changes):
    values = {
        "host": "app-server",
        "user": "operator",
        "hostname": "192.0.2.20",
        "port": "22",
        "batchmode": "no",
        "identityagent": "none",
        "identitiesonly": "yes",
        "canonicalizehostname": "false",
        "requesttty": "false",
        "stricthostkeychecking": "ask",
        "hostkeyalias": "tmuxgate-app-server",
        "permitlocalcommand": "no",
        "userknownhostsfile": "~/.ssh/known_hosts ~/.ssh/known_hosts2",
        "globalknownhostsfile": "/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2",
        "pubkeyauthentication": "true",
        "passwordauthentication": "true",
        "kbdinteractiveauthentication": "true",
        "gssapiauthentication": "false",
        "hostbasedauthentication": "false",
        "preferredauthentications": "publickey,keyboard-interactive,password",
        "identityfile": str(default_tmuxgate_identity_file("app-server")),
        "hostkeyalgorithms": "ssh-ed25519,rsa-sha2-512",
        "canonicalizePermittedcnames": "none",
    }
    values.update(changes)
    return "".join(f"{key} {value}\n" for key, value in values.items()).encode()


class SshResolutionTests(unittest.TestCase):
    def test_dedicated_identity_path_is_machine_specific(self):
        path = default_tmuxgate_identity_file(
            "app-server", {"HOME": "/home/example"}
        )
        self.assertEqual(
            path,
            Path("/home/example/.ssh/tmuxgate/app-server.ed25519"),
        )

    def setUp(self):
        config = parse_config(valid_config())
        self.machine = config.machines["app-server"]
        self.endpoint = self.machine.endpoints[0]

    def resolve(self, raw=None, *, host_key_collector=unknown_host_key):
        output = ssh_g_output() if raw is None else raw

        def runner(argv, **kwargs):
            self.last_argv = argv
            self.last_runner_kwargs = kwargs
            return SimpleNamespace(returncode=0, stdout=output, stderr=b"")

        return resolve_ssh_endpoint(
            self.machine,
            self.endpoint,
            runner=runner,
            host_key_collector=host_key_collector,
        )

    def test_broker_owns_exact_ssh_g_arguments_and_disables_global_session_policy(self):
        argv = build_ssh_g_argv(self.machine, self.endpoint)
        self.assertEqual(argv[0:2], ("/usr/bin/ssh", "-G"))
        self.assertEqual(argv[-3:], ("-T", "--", "app-server"))
        self.assertIn("RemoteCommand=none", argv)
        self.assertIn("RequestTTY=no", argv)
        self.assertIn("HostName=192.0.2.20", argv)
        self.assertIn("HostKeyAlias=tmuxgate-app-server", argv)
        self.assertIn("IdentityAgent=none", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertIn("GSSAPIAuthentication=no", argv)
        self.assertIn("HostbasedAuthentication=no", argv)
        self.assertIn(
            "PreferredAuthentications=publickey,keyboard-interactive,password",
            argv,
        )
        self.assertNotIn("ProxyCommand", " ".join(argv))

        resolved = self.resolve()
        self.assertEqual(resolved.resolved_user, "operator")
        self.assertEqual(resolved.resolved_hostname, "192.0.2.20")
        self.assertEqual(resolved.host_key_evidence.status, "unknown")
        self.assertEqual(resolved.identity_agent, "none")
        self.assertEqual(
            resolved.identity_files,
            (str(default_tmuxgate_identity_file("app-server")),),
        )
        self.assertEqual(resolved.enabled_authentication_methods, (
            "publickey", "password", "keyboard-interactive"
        ))

    def test_resolution_is_noninteractive_and_bounded(self):
        with mock.patch.dict(
            "os.environ", {"SSH_AUTH_SOCK": "/tmp/unrelated-agent.sock"}
        ):
            self.resolve()
        self.assertEqual(self.last_runner_kwargs["timeout"], 5.0)
        self.assertFalse(self.last_runner_kwargs["check"])
        self.assertEqual(self.last_runner_kwargs["env"]["PATH"], "/usr/bin:/bin")
        self.assertNotIn("SSH_AUTH_SOCK", self.last_runner_kwargs["env"])

    def test_exact_identity_fields_cannot_be_changed_by_ssh_config(self):
        changes = (
            ("host", "attacker"),
            ("hostname", "203.0.113.8"),
            ("user", "root"),
            ("port", "2222"),
            ("hostkeyalias", "shared"),
        )
        for key, value in changes:
            with self.subTest(key=key):
                with self.assertRaises(SshResolutionError):
                    self.resolve(ssh_g_output(**{key: value}))

    def test_unsafe_effective_policy_fails_closed(self):
        changes = (
            ("requesttty", "true"),
            ("batchmode", "yes"),
            ("identityagent", "/tmp/unrelated-agent.sock"),
            ("identitiesonly", "no"),
            ("gssapiauthentication", "yes"),
            ("hostbasedauthentication", "yes"),
            ("passwordauthentication", "no"),
            ("kbdinteractiveauthentication", "no"),
            ("preferredauthentications", "publickey,password"),
            ("canonicalizehostname", "true"),
            ("permitlocalcommand", "yes"),
            ("remotecommand", "tmux new-session -A -s base"),
            ("stricthostkeychecking", "no"),
            ("stricthostkeychecking", "accept-new"),
            ("userknownhostsfile", "/dev/null"),
            ("userknownhostsfile", "none"),
        )
        for key, value in changes:
            with self.subTest(key=key, value=value):
                with self.assertRaises(SshResolutionError):
                    self.resolve(ssh_g_output(**{key: value}))

    def test_profile_cannot_add_identity_or_certificate_files(self):
        unsafe_outputs = (
            ssh_g_output(identityfile="/tmp/profile-replacement"),
            ssh_g_output() + b"identityfile /tmp/profile-extra\n",
            ssh_g_output() + b"certificatefile /tmp/profile-cert.pub\n",
        )
        for output in unsafe_outputs:
            with self.subTest(output=output[-48:]):
                with self.assertRaises(SshResolutionError):
                    self.resolve(output)

    def test_owner_config_proxy_and_identity_are_recorded_in_plan_evidence(self):
        first = self.resolve(ssh_g_output(proxyjump="bastion"))
        second = self.resolve(ssh_g_output(proxycommand="ssh -W %h:%p bastion"))
        self.assertEqual(first.proxy_jump, "bastion")
        self.assertEqual(second.proxy_command, "ssh -W %h:%p bastion")
        self.assertNotEqual(first.ssh_g_output_sha256, second.ssh_g_output_sha256)

    def test_malformed_duplicate_nul_and_nonbyte_output_fail_closed(self):
        bad_outputs = (
            b"hostname\n",
            ssh_g_output() + b"hostname 192.0.2.20\n",
            ssh_g_output() + b"bad\x00value x\n",
        )
        for output in bad_outputs:
            with self.subTest(output=output[-40:]):
                with self.assertRaises(SshResolutionError):
                    self.resolve(output)

        def runner(argv, **kwargs):
            return SimpleNamespace(returncode=0, stdout="not bytes", stderr=b"")

        with self.assertRaises(SshResolutionError):
            resolve_ssh_endpoint(
                self.machine,
                self.endpoint,
                runner=runner,
                host_key_collector=unknown_host_key,
            )

    def test_timeout_must_be_positive_finite_and_not_bool(self):
        for value in (True, 0, -1, float("nan"), float("inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    resolve_ssh_endpoint(
                        self.machine,
                        self.endpoint,
                        timeout_seconds=value,
                    )

    def test_host_key_evidence_known_and_unknown_without_network(self):
        key_bytes = b"synthetic-ed25519-host-key"
        encoded = base64.b64encode(key_bytes).decode("ascii")
        expected = base64.b64encode(hashlib.sha256(key_bytes).digest()).decode().rstrip("=")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "known_hosts"
            path.write_text("synthetic local test\n", encoding="ascii")

            def known_runner(argv, **kwargs):
                self.assertEqual(argv[1:3], ("-F", "tmuxgate-app-server"))
                return SimpleNamespace(
                    returncode=0,
                    stdout=(
                        f"tmuxgate-app-server ssh-ed25519 {encoded}\n"
                    ).encode(),
                    stderr=b"",
                )

            evidence = collect_host_key_evidence(
                "tmuxgate-app-server",
                (str(path),),
                (),
                runner=known_runner,
            )
            self.assertEqual(evidence.status, "known")
            self.assertEqual(evidence.records[0].fingerprint_sha256, f"SHA256:{expected}")
            self.assertEqual(
                evidence.sources[0].sha256,
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )

            def unknown_runner(argv, **kwargs):
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"")

            unknown = collect_host_key_evidence(
                "tmuxgate-app-server", (str(path),), (), runner=unknown_runner
            )
            self.assertEqual(unknown.status, "unknown")
            self.assertEqual(unknown.records, ())


if __name__ == "__main__":
    unittest.main()
