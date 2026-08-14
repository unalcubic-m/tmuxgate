import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[1]
INSTALLER_PATH = REPOSITORY / "scripts" / "install.py"
SPEC = importlib.util.spec_from_file_location("tmuxgate_test_installer", INSTALLER_PATH)
assert SPEC is not None and SPEC.loader is not None
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


class InstallerTransformTests(unittest.TestCase):
    def test_codex_registration_append_preserves_every_existing_byte(self):
        original = (
            b'# formatting and comments are user-owned\r\n'
            b'[model]\r\nname = "example" # keep this spacing\r\n'
            b'details = { modes = ["one", "two"], enabled = true }\r\n'
            b'description = """multiline\r\nconfiguration [is preserved]\r\n"""\r\n'
            b'\r\n[mcp_servers.other]\r\n'
            b'args = [\r\n    "one",\r\n    "two",\r\n]\r\n'
            b'command="other"'
        )
        updated = installer.update_codex_registration(
            original,
            url="http://127.0.0.1:8765/mcp",
            replace_conflict=False,
        )

        self.assertTrue(updated.startswith(original))
        self.assertEqual(updated[: len(original)], original)
        self.assertEqual(
            tomllib.loads(updated.decode("utf-8"))["mcp_servers"]["other"]["command"],
            "other",
        )

    def test_codex_registration_replaces_only_a_simple_target_table(self):
        prefix = b'# byte-for-byte prefix\n[model]\nname = "kept"\n\n'
        target = b'[mcp_servers.tmuxgate] # old\ncommand = "tmuxgate-mcp"\n\n'
        suffix = b'[mcp_servers.other]\ncommand = "other" # byte-for-byte suffix\n'
        updated = installer.update_codex_registration(
            prefix + target + suffix,
            url="http://127.0.0.1:8765/mcp",
            replace_conflict=True,
        )

        self.assertTrue(updated.startswith(prefix))
        self.assertTrue(updated.endswith(suffix))
        parsed = tomllib.loads(updated.decode("utf-8"))
        self.assertEqual(
            parsed["mcp_servers"]["tmuxgate"],
            {
                "url": "http://127.0.0.1:8765/mcp",
                "bearer_token_env_var": installer.MCP_TOKEN_ENV,
                "tool_timeout_sec": installer.MCP_TOOL_TIMEOUT_SECONDS,
            },
        )

    def test_codex_registration_rejects_ambiguous_layout_even_with_replace(self):
        layouts = (
            b'[mcp_servers."tmuxgate"]\ncommand = "old"\n',
            (
                b'[mcp_servers.tmuxgate]\ncommand = "old"\n'
                b'[mcp_servers.tmuxgate.env]\nSECRET = "not-owned"\n'
            ),
            b'mcp_servers.tmuxgate = { command = "old" }\n',
        )
        for original in layouts:
            with self.subTest(original=original):
                with self.assertRaisesRegex(installer.InstallError, "simple|ambiguous"):
                    installer.update_codex_registration(
                        original,
                        url="http://127.0.0.1:8765/mcp",
                        replace_conflict=True,
                    )

    def _own_registration(self):
        return installer._codex_registration_payload(
            url="http://127.0.0.1:8765/mcp"
        ).decode("utf-8")

    def test_codex_registration_accepts_its_own_table_after_codex_rewrites_it(self):
        # Regression for issue #59. Codex rewrites this file: it renders our
        # integer timeout as a float and appends a per-tool approval sub-table
        # the first time an operator approves a tool. Both are our own
        # registration coming back in Codex's shape, so a later install must
        # recognize it as already present and leave the bytes alone rather than
        # demanding --replace-codex or manual editing.
        own = self._own_registration()
        floated = own.replace(
            f"tool_timeout_sec = {installer.MCP_TOOL_TIMEOUT_SECONDS}",
            f"tool_timeout_sec = {installer.MCP_TOOL_TIMEOUT_SECONDS}.0",
        )
        approvals = (
            '\n[mcp_servers.tmuxgate.tools.run_argv]\napproval_mode = "approve"\n'
            '[mcp_servers.tmuxgate.tools.run_script]\napproval_mode = "approve"\n'
        )
        for label, original in (
            ("unchanged", own),
            ("floated timeout", floated),
            ("tool approvals", own + approvals),
            ("both rewrites", floated + approvals),
        ):
            for replace_conflict in (False, True):
                with self.subTest(layout=label, replace_conflict=replace_conflict):
                    raw = original.encode("utf-8")
                    updated = installer.update_codex_registration(
                        raw,
                        url="http://127.0.0.1:8765/mcp",
                        replace_conflict=replace_conflict,
                    )
                    self.assertEqual(updated, raw)

    def test_codex_tool_approvals_survive_a_conflicting_rewrite(self):
        # The operator's approval policy is not ours to discard, so even the
        # byte-span replacement of a genuinely conflicting table must leave the
        # sub-tables below it intact.
        original = (
            b"[mcp_servers.tmuxgate]\n"
            b'url = "http://127.0.0.1:9999/stale"\n'
            b'[mcp_servers.tmuxgate.tools.run_argv]\napproval_mode = "approve"\n'
        )

        updated = installer.update_codex_registration(
            original, url="http://127.0.0.1:8765/mcp", replace_conflict=True
        )

        target = tomllib.loads(updated.decode("utf-8"))["mcp_servers"]["tmuxgate"]
        self.assertEqual(target["url"], "http://127.0.0.1:8765/mcp")
        self.assertEqual(
            target["tool_timeout_sec"], installer.MCP_TOOL_TIMEOUT_SECONDS
        )
        self.assertEqual(
            target["tools"], {"run_argv": {"approval_mode": "approve"}}
        )

    def test_codex_registration_still_refuses_foreign_values(self):
        # Tolerating Codex's own rewrite must not tolerate anything else. A
        # scalar named 'tools' was not written by Codex, so it stays visible as
        # a conflict rather than being mistaken for an approval sub-table.
        own = self._own_registration()
        conflicts = {
            "scalar tools key": own + 'tools = "not-a-table"\n',
            "foreign token variable": own.replace(
                installer.MCP_TOKEN_ENV, "SOMEONE_ELSES_TOKEN"
            ),
            "foreign url": own.replace(
                "http://127.0.0.1:8765/mcp", "http://evil.invalid/mcp"
            ),
        }
        for label, original in conflicts.items():
            with self.subTest(conflict=label):
                with self.assertRaisesRegex(
                    installer.InstallError, "different|ambiguous"
                ):
                    installer.update_codex_registration(
                        original.encode("utf-8"),
                        url="http://127.0.0.1:8765/mcp",
                        replace_conflict=False,
                    )

    def test_codex_stale_timeout_is_updated_in_either_numeric_form(self):
        # A timeout key in our own table is ours to bring up to date whatever
        # its current value, which is what lets MCP_TOOL_TIMEOUT_SECONDS change
        # without every existing install needing --replace-codex. Accepting the
        # float form must not turn that into a conflict.
        own = self._own_registration()
        for label, stale in (
            ("integer", "tool_timeout_sec = 60"),
            ("float", "tool_timeout_sec = 60.0"),
        ):
            with self.subTest(form=label):
                original = own.replace(
                    f"tool_timeout_sec = {installer.MCP_TOOL_TIMEOUT_SECONDS}", stale
                )

                updated = installer.update_codex_registration(
                    original.encode("utf-8"),
                    url="http://127.0.0.1:8765/mcp",
                    replace_conflict=False,
                )

                target = tomllib.loads(updated.decode("utf-8"))
                self.assertEqual(
                    target["mcp_servers"]["tmuxgate"]["tool_timeout_sec"],
                    installer.MCP_TOOL_TIMEOUT_SECONDS,
                )

    def test_codex_timeout_patch_preserves_other_tables_and_is_idempotent(self):
        original = (
            b'[model]\nname = "example"\n\n'
            b"[mcp_servers.tmuxgate]\n"
            b'url = "http://127.0.0.1:9876/mcp"\n'
            b'bearer_token_env_var = "TMUXGATE_MCP_TOKEN"\n\n'
            b"[mcp_servers.other]\ncommand = \"other\"\n"
        )
        updated = installer.patch_codex_timeout(original)
        parsed = tomllib.loads(updated.decode("utf-8"))

        self.assertEqual(
            parsed["mcp_servers"]["tmuxgate"]["tool_timeout_sec"],
            installer.MCP_TOOL_TIMEOUT_SECONDS,
        )
        self.assertEqual(parsed["mcp_servers"]["other"]["command"], "other")
        self.assertEqual(installer.patch_codex_timeout(updated), updated)

    def test_codex_timeout_patch_rejects_missing_or_duplicate_table(self):
        with self.assertRaisesRegex(installer.InstallError, "exactly one"):
            installer.patch_codex_timeout(b"[mcp_servers.other]\ncommand='x'\n")
        duplicate = b"[mcp_servers.tmuxgate]\nurl='a'\n[mcp_servers.tmuxgate]\nurl='b'\n"
        with self.assertRaises(installer.InstallError):
            installer.patch_codex_timeout(duplicate)

    def test_profile_block_is_idempotent_and_contains_no_token(self):
        token = "a" * 64
        env_path = Path("/tmp/tmuxgate config/codex-env.sh")
        first = installer.update_profile(b"export EXISTING=1\n", env_path)
        second = installer.update_profile(first, env_path)

        self.assertEqual(first, second)
        self.assertEqual(first.count(installer.PROFILE_START.encode()), 1)
        self.assertNotIn(token.encode(), first)
        self.assertIn(b"export EXISTING=1", first)

    def test_profile_rejects_incomplete_managed_block(self):
        with self.assertRaisesRegex(installer.InstallError, "incomplete"):
            installer.update_profile(
                installer.PROFILE_START.encode(), Path("/tmp/codex-env.sh")
            )

    def test_environment_file_reads_only_a_canonical_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            token_path = base / "mcp-token"
            env_path = base / "codex-env.sh"
            token = "0123456789abcdef" * 4
            token_path.write_text(token + "\n", encoding="ascii")
            token_path.chmod(0o600)
            env_payload = installer.build_env_file(token_path)
            env_path.write_bytes(env_payload)
            env_path.chmod(0o600)

            self.assertNotIn(token.encode("ascii"), env_payload)
            result = subprocess.run(
                (
                    "/bin/sh",
                    "-c",
                    '. "$1"; printf "%s" "$TMUXGATE_MCP_TOKEN"',
                    "sh",
                    str(env_path),
                ),
                check=True,
                capture_output=True,
                text=True,
                env={"PATH": os.environ.get("PATH", "")},
            )
            self.assertEqual(result.stdout, token)

            token_path.write_text("not-a-token\n", encoding="ascii")
            malformed = subprocess.run(
                (
                    "/bin/sh",
                    "-c",
                    '. "$1"; test -z "${TMUXGATE_MCP_TOKEN+x}"',
                    "sh",
                    str(env_path),
                ),
                check=False,
                capture_output=True,
                text=True,
                env={"PATH": os.environ.get("PATH", "")},
            )
            self.assertEqual(malformed.returncode, 0)
            self.assertEqual(malformed.stdout, "")

            token_path.write_text(token + "\nEXTRA\n", encoding="ascii")
            extra = subprocess.run(
                (
                    "/bin/sh",
                    "-c",
                    '. "$1"; test -z "${TMUXGATE_MCP_TOKEN+x}"',
                    "sh",
                    str(env_path),
                ),
                check=False,
                capture_output=True,
                text=True,
                env={"PATH": os.environ.get("PATH", "")},
            )
            self.assertEqual(extra.returncode, 0)

    def test_known_launchers_are_replaceable_but_unrelated_one_is_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "source"
            install_root = base / "data" / "tmuxgate"
            bin_dir = base / "bin"
            (source / "bin").mkdir(parents=True)
            bin_dir.mkdir()
            launcher = bin_dir / "tmuxgate"
            launcher.symlink_to(source / "bin" / "tmuxgate")
            self.assertTrue(
                installer.launcher_is_replaceable(
                    launcher,
                    source=source,
                    install_root=install_root,
                    replace_existing=False,
                )
            )
            launcher.unlink()
            launcher.symlink_to(base / "unrelated")
            self.assertFalse(
                installer.launcher_is_replaceable(
                    launcher,
                    source=source,
                    install_root=install_root,
                    replace_existing=False,
                )
            )
            self.assertTrue(
                installer.launcher_is_replaceable(
                    launcher,
                    source=source,
                    install_root=install_root,
                    replace_existing=True,
                )
            )

    def test_file_snapshot_restores_regular_symlink_and_missing_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            regular = base / "regular"
            regular.write_bytes(b"before")
            regular.chmod(0o640)
            snapshot = installer.FileSnapshot.capture(regular)
            regular.write_bytes(b"after")
            snapshot.restore(regular)
            self.assertEqual(regular.read_bytes(), b"before")
            self.assertEqual(stat.S_IMODE(regular.stat().st_mode), 0o640)

            linked = base / "linked"
            linked.symlink_to("first")
            link_snapshot = installer.FileSnapshot.capture(linked)
            linked.unlink()
            linked.symlink_to("second")
            link_snapshot.restore(linked)
            self.assertEqual(os.readlink(linked), "first")

            absent = base / "absent"
            absent_snapshot = installer.FileSnapshot.capture(absent)
            absent.write_bytes(b"created")
            absent_snapshot.restore(absent)
            self.assertFalse(absent.exists())

    def test_owned_write_refuses_a_changed_supplied_preimage(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            path.write_bytes(b"before")
            path.chmod(0o600)
            snapshot = installer.FileSnapshot.capture(path)
            path.write_bytes(b"concurrent edit")

            with self.assertRaisesRegex(installer.InstallError, "concurrent change"):
                installer._write_owned(
                    path,
                    b"installer edit",
                    0o600,
                    before=snapshot,
                )

            self.assertEqual(path.read_bytes(), b"concurrent edit")

    def test_owned_symlink_refuses_a_changed_supplied_preimage(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "current"
            path.symlink_to("first")
            snapshot = installer.FileSnapshot.capture(path)
            path.unlink()
            path.symlink_to("concurrent")

            with self.assertRaisesRegex(installer.InstallError, "concurrent change"):
                installer._symlink_owned(
                    path,
                    "installer",
                    before=snapshot,
                )

            self.assertEqual(os.readlink(path), "concurrent")

    def test_codex_entry_match_requires_http_url_and_token_variable(self):
        url = "http://127.0.0.1:8765/mcp"
        entry = {
            "name": "tmuxgate",
            "enabled": True,
            "disabled_reason": None,
            "transport": {
                "type": "streamable_http",
                "url": url,
                "bearer_token_env_var": "TMUXGATE_MCP_TOKEN",
                "http_headers": None,
                "env_http_headers": None,
            },
        }
        self.assertTrue(installer.codex_entry_matches(entry, url=url))
        entry["transport"]["bearer_token_env_var"] = None
        self.assertFalse(installer.codex_entry_matches(entry, url=url))

    def test_disabled_or_header_augmented_codex_entry_is_not_exact(self):
        url = "http://127.0.0.1:8765/mcp"
        entry = {
            "name": "tmuxgate",
            "enabled": False,
            "disabled_reason": "disabled by user",
            "transport": {
                "type": "streamable_http",
                "url": url,
                "bearer_token_env_var": "TMUXGATE_MCP_TOKEN",
                "http_headers": None,
                "env_http_headers": None,
            },
        }
        self.assertFalse(installer.codex_entry_matches(entry, url=url))
        entry["enabled"] = True
        entry["disabled_reason"] = None
        entry["transport"]["http_headers"] = {"x-extra": "value"}
        self.assertFalse(installer.codex_entry_matches(entry, url=url))

    def test_child_environment_scrubs_credentials_and_python_overrides(self):
        environment = {
            "PATH": "/usr/bin",
            "TMUXGATE_MCP_TOKEN": "c" * 64,
            "PYTHONPATH": "/untrusted",
            "PYTHONHOME": "/untrusted-home",
            "VIRTUAL_ENV": "/untrusted-venv",
            "KEEP_ME": "yes",
        }
        scrubbed = installer._child_environment(environment)
        self.assertEqual(scrubbed["KEEP_ME"], "yes")
        for name in ("TMUXGATE_MCP_TOKEN", "PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
            self.assertNotIn(name, scrubbed)


class InstallerProbeTests(unittest.TestCase):
    def test_installed_probe_preserves_config_and_existing_token(self):
        config_payload = (REPOSITORY / "examples" / "config.toml").read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            config = base / "config.toml"
            state_dir = base / "state"
            config.write_bytes(config_payload)
            config.chmod(0o600)
            state_dir.mkdir(mode=0o700)
            token = "b" * 64
            token_path = state_dir / "mcp-token"
            token_path.write_text(token + "\n", encoding="ascii")
            token_path.chmod(0o600)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = installer._installed_probe(
                    ("--config", str(config), "--state-dir", str(state_dir))
                )
            payload = json.loads(output.getvalue())

            self.assertEqual(result, 0)
            self.assertEqual(payload["mcp_url"], "http://127.0.0.1:8765/mcp")
            self.assertEqual(payload["approval_mode"], "disabled")
            self.assertNotIn(token, output.getvalue())
            self.assertEqual(config.read_bytes(), config_payload)
            self.assertEqual(token_path.read_text(encoding="ascii"), token + "\n")
            self.assertEqual(stat.S_IMODE(token_path.stat().st_mode), 0o600)


class FakeCodexRegistrationTests(unittest.TestCase):
    FAKE_CODEX = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import tomllib

config = Path(os.environ["CODEX_HOME"]) / "config.toml"
args = sys.argv[1:]
if args == ["mcp", "list", "--json"]:
    entry = None
    if config.exists():
        parsed = tomllib.loads(config.read_text())
        if set(parsed) != {"mcp_servers"} or set(parsed["mcp_servers"]) != {"tmuxgate"}:
            print("Codex verifier received unrelated live configuration", file=sys.stderr)
            raise SystemExit(92)
        if Path.cwd() != Path(os.environ["CODEX_HOME"]):
            print("Codex verifier cwd was not isolated", file=sys.stderr)
            raise SystemExit(93)
        isolated_home = Path(os.environ["CODEX_HOME"])
        if Path(os.environ["HOME"]) != isolated_home or Path(os.environ["PWD"]) != isolated_home:
            print("Codex verifier HOME/PWD was not isolated", file=sys.stderr)
            raise SystemExit(95)
        isolated_variables = (
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
            "TMPDIR",
        )
        if any(Path(os.environ[name]).parent != isolated_home for name in isolated_variables):
            print("Codex verifier XDG/temp environment was not isolated", file=sys.stderr)
            raise SystemExit(96)
        forbidden = ("TMUXGATE_MCP_TOKEN", "PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV")
        if any(name in os.environ for name in forbidden):
            print("Codex verifier inherited a forbidden variable", file=sys.stderr)
            raise SystemExit(94)
        target = parsed.get("mcp_servers", {}).get("tmuxgate")
        if isinstance(target, dict) and "url" in target:
            entry = {
                "name": "tmuxgate",
                "enabled": target.get("enabled", True),
                "disabled_reason": None,
                "transport": {
                    "type": "streamable_http",
                    "url": target["url"],
                    "bearer_token_env_var": target.get("bearer_token_env_var"),
                    "http_headers": target.get("http_headers"),
                    "env_http_headers": target.get("env_http_headers"),
                },
                "startup_timeout_sec": target.get("startup_timeout_sec"),
                "tool_timeout_sec": target.get("tool_timeout_sec"),
            }
        elif isinstance(target, dict) and "command" in target:
            entry = {
                "name": "tmuxgate",
                "enabled": True,
                "disabled_reason": None,
                "transport": {
                    "type": "stdio",
                    "command": target["command"],
                    "args": target.get("args", []),
                    "env": None,
                    "env_vars": [],
                    "cwd": None,
                },
                "startup_timeout_sec": None,
                "tool_timeout_sec": target.get("tool_timeout_sec"),
            }
    # Deliberately emulate a Codex build that serializes even for a nominally
    # read-only listing. The installer must expose only its disposable clone.
    config.write_text('[clobbered-by-fake-codex]\nvalue = true\n')
    fallback = Path(os.environ["HOME"]) / ".codex" / "config.toml"
    fallback.parent.mkdir(mode=0o700)
    fallback.write_text('[clobbered-home-fallback]\nvalue = true\n')
    print(json.dumps([] if entry is None else [entry]))
elif len(args) >= 2 and args[:2] in (["mcp", "add"], ["mcp", "remove"]):
    config.write_text('[clobbered]\nvalue = true\n')
    print("mutating Codex MCP command must not be called", file=sys.stderr)
    raise SystemExit(91)
else:
    print(f"unexpected fake Codex arguments: {args!r}", file=sys.stderr)
    raise SystemExit(2)
'''

    def test_registration_uses_only_cli_list_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            codex = base / "codex"
            codex.write_text(self.FAKE_CODEX, encoding="utf-8")
            codex.chmod(0o700)
            config = base / "config.toml"
            original = b'[unrelated]\nvalue = "kept"\n'
            config.write_bytes(original)
            config.chmod(0o600)
            backups = base / "backups"
            backups.mkdir(mode=0o700)
            url = "http://127.0.0.1:8765/mcp"
            environment = {"CODEX_HOME": str(base)}

            with mock.patch.dict(os.environ, environment, clear=False):
                mutation = installer._register_codex(
                    codex,
                    config,
                    url=url,
                    replace_conflict=False,
                    backup_dir=backups,
                )
                first_install = config.read_bytes()
                installer._register_codex(
                    codex,
                    config,
                    url=url,
                    replace_conflict=False,
                    backup_dir=backups,
                )

            self.assertEqual(config.read_bytes(), first_install)
            parsed = tomllib.loads(config.read_text(encoding="utf-8"))
            self.assertIsNotNone(mutation)
            self.assertEqual(mutation.before.data, original)
            self.assertEqual(parsed["unrelated"]["value"], "kept")
            self.assertEqual(
                parsed["mcp_servers"]["tmuxgate"]["tool_timeout_sec"],
                installer.MCP_TOOL_TIMEOUT_SECONDS,
            )
            self.assertNotIn("b" * 64, config.read_text(encoding="utf-8"))

    def test_registration_creates_absent_codex_config_without_mutating_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            codex = base / "codex"
            codex.write_text(self.FAKE_CODEX, encoding="utf-8")
            codex.chmod(0o700)
            config = base / "config.toml"
            backups = base / "backups"
            backups.mkdir(mode=0o700)

            with mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(base)},
                clear=False,
            ):
                mutation = installer._register_codex(
                    codex,
                    config,
                    url="http://127.0.0.1:8765/mcp",
                    replace_conflict=False,
                    backup_dir=backups,
                )

            self.assertIsNotNone(mutation)
            self.assertFalse(mutation.before.exists)
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
            self.assertEqual(list(backups.iterdir()), [])
            self.assertEqual(
                tomllib.loads(config.read_text())["mcp_servers"]["tmuxgate"]["url"],
                "http://127.0.0.1:8765/mcp",
            )

    def test_conflicting_registration_is_refused_without_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            codex = base / "codex"
            codex.write_text(self.FAKE_CODEX, encoding="utf-8")
            codex.chmod(0o700)
            config = base / "config.toml"
            original = b'[mcp_servers.tmuxgate]\ncommand = "old"\n'
            config.write_bytes(original)
            config.chmod(0o600)
            backups = base / "backups"
            backups.mkdir(mode=0o700)
            with mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(base)},
                clear=False,
            ):
                with self.assertRaisesRegex(installer.InstallError, "--replace-codex"):
                    installer._register_codex(
                        codex,
                        config,
                        url="http://127.0.0.1:8765/mcp",
                        replace_conflict=False,
                        backup_dir=backups,
                    )
            self.assertEqual(config.read_bytes(), original)

    def test_replace_codex_rewrites_only_the_simple_conflicting_table(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            codex = base / "codex"
            codex.write_text(self.FAKE_CODEX, encoding="utf-8")
            codex.chmod(0o700)
            config = base / "config.toml"
            prefix = b'[unrelated]\nvalue = "kept"\n\n'
            old = b'[mcp_servers.tmuxgate]\ncommand = "tmuxgate-mcp"\n\n'
            suffix = b'[mcp_servers.other]\ncommand = "other" # exact suffix\n'
            config.write_bytes(prefix + old + suffix)
            config.chmod(0o640)
            backups = base / "backups"
            backups.mkdir(mode=0o700)

            with mock.patch.dict(
                os.environ,
                {"CODEX_HOME": str(base)},
                clear=False,
            ):
                installer._register_codex(
                    codex,
                    config,
                    url="http://127.0.0.1:8765/mcp",
                    replace_conflict=True,
                    backup_dir=backups,
                )

            updated = config.read_bytes()
            self.assertTrue(updated.startswith(prefix))
            self.assertTrue(updated.endswith(suffix))
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o640)
            self.assertEqual(len(list(backups.iterdir())), 1)


class InstallerRetentionTests(unittest.TestCase):
    """Regression coverage for issue #53."""

    def _releases(self, base, *names):
        releases = base / "releases"
        releases.mkdir()
        for name in names:
            (releases / name).mkdir()
        return releases

    def test_only_the_newest_releases_survive(self):
        with tempfile.TemporaryDirectory() as temporary:
            names = [f"2026080{index}T120000Z-aaaaaaa{index}" for index in range(1, 6)]
            releases = self._releases(Path(temporary), *names)

            # keep is the total retained, and the newest release is normally
            # protected as the one just published, so it counts toward it.
            removed = installer._prune_releases(
                releases, keep=2, protected={names[-1]}
            )

            self.assertEqual(sorted(removed), sorted(names[:3]))
            self.assertEqual(
                sorted(path.name for path in releases.iterdir()), sorted(names[3:])
            )

    def test_protected_releases_survive_regardless_of_the_limit(self):
        # The rollback path is a `current` symlink flip, so the release it
        # would flip back to must outlive retention however small keep is.
        with tempfile.TemporaryDirectory() as temporary:
            names = [f"2026080{index}T120000Z-bbbbbbb{index}" for index in range(1, 6)]
            releases = self._releases(Path(temporary), *names)
            active, previous, in_use = names[4], names[0], names[1]

            removed = installer._prune_releases(
                releases, keep=1, protected={active, previous, in_use}
            )

            survivors = sorted(path.name for path in releases.iterdir())
            self.assertIn(active, survivors)
            self.assertIn(previous, survivors)
            self.assertIn(in_use, survivors)
            self.assertNotIn(previous, removed)

    def test_zero_keeps_everything(self):
        with tempfile.TemporaryDirectory() as temporary:
            names = [f"2026080{index}T120000Z-ccccccc{index}" for index in range(1, 5)]
            releases = self._releases(Path(temporary), *names)

            self.assertEqual(installer._prune_releases(releases, keep=0, protected=set()), [])
            self.assertEqual(len(list(releases.iterdir())), len(names))

    def test_a_release_a_live_process_runs_from_is_in_use(self):
        # A release is a virtual environment, and its bin/python is a symlink
        # to the system interpreter, so /proc/<pid>/exe resolves *outside* the
        # release. Detection that trusts exe alone finds nothing for exactly the
        # processes this must protect, so the check runs against a real live
        # process started from a real virtual environment.
        with tempfile.TemporaryDirectory() as temporary:
            releases = Path(temporary) / "releases"
            release = releases / "20260101T000000Z-aaaaaaaa"
            release.mkdir(parents=True)
            subprocess.run(
                (sys.executable, "-m", "venv", "--without-pip", str(release)),
                check=True,
                capture_output=True,
            )
            child = subprocess.Popen(
                (str(release / "bin" / "python"), "-c", "import time; time.sleep(30)"),
            )
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if release.name in installer._releases_in_use(releases):
                        break
                    time.sleep(0.05)
                in_use = installer._releases_in_use(releases)
                self.assertIn(release.name, in_use)
                # And retention must refuse to remove it even at keep=1.
                removed = installer._prune_releases(
                    releases, keep=1, protected=in_use
                )
                self.assertEqual(removed, [])
                self.assertTrue(release.is_dir())
            finally:
                child.terminate()
                child.wait(timeout=10)

    def test_a_release_no_process_uses_is_not_reported_in_use(self):
        with tempfile.TemporaryDirectory() as temporary:
            releases = Path(temporary) / "releases"
            (releases / "20260101T000000Z-bbbbbbbb").mkdir(parents=True)

            self.assertEqual(installer._releases_in_use(releases), set())

    def test_backups_keep_the_oldest_pre_image_of_each_kind(self):
        # The oldest pre-image is the file as it was before tmuxgate ever
        # managed it, and is the only one that can undo the integration.
        with tempfile.TemporaryDirectory() as temporary:
            backups = Path(temporary)
            profiles = [f"profile-0-2026080{index}T120000Z-dddddddd" for index in range(1, 6)]
            codex = [f"codex-config-2026080{index}T120000Z-eeeeeeee.toml" for index in (1, 2)]
            unmanaged = "not-written-by-this-installer"
            for name in (*profiles, *codex, unmanaged):
                (backups / name).write_text("x", encoding="ascii")

            removed = installer._prune_backups(backups, keep=2)

            survivors = sorted(path.name for path in backups.iterdir())
            self.assertIn(profiles[0], survivors)
            self.assertIn(profiles[-1], survivors)
            self.assertIn(profiles[-2], survivors)
            self.assertEqual(sorted(removed), sorted(profiles[1:3]))
            # A kind with no surplus, and anything this installer did not
            # write, are both left alone.
            for name in (*codex, unmanaged):
                self.assertIn(name, survivors)


class InstallerFlowTests(unittest.TestCase):
    def _fixture(self, base: Path):
        home = base / "home"
        data = base / "data"
        config_home = base / "config"
        state_home = base / "state"
        codex_home = base / "codex"
        bin_dir = base / "bin"
        for directory, mode in (
            (home, 0o700),
            (data, 0o700),
            (config_home, 0o700),
            (state_home, 0o700),
            (codex_home, 0o775),
            (bin_dir, 0o755),
        ):
            directory.mkdir(mode=mode)
        tmuxgate_config_dir = config_home / "tmuxgate"
        tmuxgate_config_dir.mkdir(mode=0o700)
        config = tmuxgate_config_dir / "config.toml"
        config_payload = (REPOSITORY / "examples" / "config.toml").read_bytes()
        config.write_bytes(config_payload)
        config.chmod(0o600)
        state_dir = state_home / "tmuxgate"
        state_dir.mkdir(mode=0o700)
        token = "d" * 64
        token_path = state_dir / "mcp-token"
        token_path.write_text(token + "\n", encoding="ascii")
        token_path.chmod(0o600)
        (home / ".bashrc").write_text("export BASH_SENTINEL=1\n", encoding="utf-8")
        (home / ".profile").write_text("export PROFILE_SENTINEL=1\n", encoding="utf-8")
        codex_config = codex_home / "config.toml"
        codex_config.write_text('[unrelated]\nvalue = "kept"\n', encoding="utf-8")
        codex_config.chmod(0o600)
        codex = base / "fake-codex"
        codex.write_text(FakeCodexRegistrationTests.FAKE_CODEX, encoding="utf-8")
        codex.chmod(0o700)
        environment = {
            "HOME": str(home),
            "XDG_DATA_HOME": str(data),
            "XDG_CONFIG_HOME": str(config_home),
            "XDG_STATE_HOME": str(state_home),
            "CODEX_HOME": str(codex_home),
            "SHELL": "/bin/bash",
            "PATH": os.environ.get("PATH", ""),
            "TMUXGATE_MCP_TOKEN": "e" * 64,
            "PYTHONPATH": "/must/be/scrubbed",
            "PYTHONHOME": "/must/be/scrubbed",
        }
        return {
            "home": home,
            "data": data,
            "config": config,
            "config_payload": config_payload,
            "state_dir": state_dir,
            "token": token,
            "token_path": token_path,
            "codex_home": codex_home,
            "codex_config": codex_config,
            "codex": codex,
            "bin_dir": bin_dir,
            "environment": environment,
        }

    def _fake_installer_runner(self, real_run):
        def run(command, *, env=None, cwd=None, capture=False, label):
            selected = list(command)
            if len(selected) >= 4 and selected[1:3] == ["-m", "venv"]:
                release = Path(selected[-1])
                binary = release / "bin"
                binary.mkdir(parents=True, exist_ok=True)
                for name in ("python", "tmuxgate"):
                    executable = binary / name
                    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                    executable.chmod(0o700)
                return subprocess.CompletedProcess(selected, 0, "", "")
            if "pip" in selected and "install" in selected:
                return subprocess.CompletedProcess(selected, 0, "", "")
            if selected and "/releases/" in selected[0]:
                if "--installed-probe" in selected:
                    probe_args = selected[selected.index("--installed-probe") + 1 :]
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        installer._installed_probe(probe_args)
                    return subprocess.CompletedProcess(selected, 0, output.getvalue(), "")
                return subprocess.CompletedProcess(selected, 0, "", "")
            return real_run(command, env=env, cwd=cwd, capture=capture, label=label)

        return run

    def _arguments(self, fixture):
        return installer._public_parser().parse_args(
            (
                "--source",
                str(REPOSITORY),
                "--bin-dir",
                str(fixture["bin_dir"]),
                "--codex-bin",
                str(fixture["codex"]),
            )
        )

    def test_full_install_and_repeat_are_atomic_idempotent_and_secret_free(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            real_run = installer._run
            fake_run = self._fake_installer_runner(real_run)
            output = io.StringIO()
            errors = io.StringIO()
            with mock.patch.dict(os.environ, fixture["environment"], clear=True):
                with mock.patch.object(
                    installer, "_run", side_effect=fake_run
                ) as run:
                    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                        self.assertEqual(installer.install(self._arguments(fixture)), 0)
                        self.assertEqual(installer.install(self._arguments(fixture)), 0)

            install_root = fixture["data"] / "tmuxgate"
            launcher = fixture["bin_dir"] / "tmuxgate"
            self.assertTrue(launcher.is_symlink())
            self.assertTrue(launcher.resolve().is_file())
            self.assertEqual(len(list((install_root / "releases").iterdir())), 2)
            self.assertEqual(fixture["config"].read_bytes(), fixture["config_payload"])
            self.assertEqual(
                fixture["token_path"].read_text(encoding="ascii"),
                fixture["token"] + "\n",
            )
            self.assertEqual(stat.S_IMODE(fixture["codex_home"].stat().st_mode), 0o700)
            parsed = tomllib.loads(fixture["codex_config"].read_text(encoding="utf-8"))
            self.assertEqual(parsed["unrelated"]["value"], "kept")
            self.assertEqual(
                parsed["mcp_servers"]["tmuxgate"]["tool_timeout_sec"],
                installer.MCP_TOOL_TIMEOUT_SECONDS,
            )
            for profile_name in (".bashrc", ".profile"):
                profile = (fixture["home"] / profile_name).read_text(encoding="utf-8")
                self.assertEqual(profile.count(installer.PROFILE_START), 1)
            env_file = fixture["config"].parent / "codex-env.sh"
            self.assertNotIn(fixture["token"], env_file.read_text(encoding="utf-8"))
            combined_output = output.getvalue() + errors.getvalue()
            self.assertNotIn(fixture["token"], combined_output)
            self.assertNotIn("e" * 64, combined_output)
            import_checks = [
                call.args[0]
                for call in run.call_args_list
                if call.kwargs["label"] == "verifying installed Python imports"
            ]
            self.assertTrue(import_checks)
            self.assertTrue(all("textual" in command[2] for command in import_checks))

    def test_manifest_failure_restores_links_and_retains_published_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            real_run = installer._run
            fake_run = self._fake_installer_runner(real_run)
            with mock.patch.dict(os.environ, fixture["environment"], clear=True):
                with mock.patch.object(installer, "_run", side_effect=fake_run):
                    installer.install(self._arguments(fixture))
                    install_root = fixture["data"] / "tmuxgate"
                    current = install_root / "current"
                    old_current = os.readlink(current)
                    old_manifest = (install_root / "install.json").read_bytes()
                    real_write_owned = installer._write_owned

                    def fail_manifest(path, payload, mode, *, before=None):
                        if path.name == "install.json":
                            raise installer.InstallError("injected manifest failure")
                        return real_write_owned(path, payload, mode, before=before)

                    with mock.patch.object(installer, "_write_owned", side_effect=fail_manifest):
                        with self.assertRaisesRegex(installer.InstallError, "manifest failure"):
                            installer.install(self._arguments(fixture))

            self.assertEqual(os.readlink(current), old_current)
            self.assertEqual((install_root / "install.json").read_bytes(), old_manifest)
            self.assertEqual(len(list((install_root / "releases").iterdir())), 2)
            self.assertTrue((fixture["bin_dir"] / "tmuxgate").resolve().is_file())

    def test_launcher_created_during_build_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            launcher = fixture["bin_dir"] / "tmuxgate"
            real_run = installer._run
            fake_run = self._fake_installer_runner(real_run)
            injected = False

            def racing_run(command, *, env=None, cwd=None, capture=False, label):
                nonlocal injected
                result = fake_run(
                    command,
                    env=env,
                    cwd=cwd,
                    capture=capture,
                    label=label,
                )
                if label == "preparing tmuxgate MCP credential" and not injected:
                    launcher.write_bytes(b"user launcher created during build\n")
                    launcher.chmod(0o700)
                    injected = True
                return result

            with mock.patch.dict(os.environ, fixture["environment"], clear=True):
                with mock.patch.object(installer, "_run", side_effect=racing_run):
                    with self.assertRaisesRegex(
                        installer.InstallError, "launcher changed during installation"
                    ):
                        installer.install(self._arguments(fixture))

            self.assertTrue(injected)
            self.assertFalse(launcher.is_symlink())
            self.assertEqual(launcher.read_bytes(), b"user launcher created during build\n")

    def test_missing_config_fails_before_creating_a_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            fixture["config"].unlink()
            with mock.patch.dict(os.environ, fixture["environment"], clear=True):
                with self.assertRaisesRegex(installer.InstallError, "configuration not found"):
                    installer.install(self._arguments(fixture))
            releases = fixture["data"] / "tmuxgate" / "releases"
            self.assertEqual(list(releases.iterdir()), [])

    def test_automatic_approvals_install_without_extra_acknowledgement(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            real_run = installer._run
            fake_run = self._fake_installer_runner(real_run)
            with mock.patch.dict(os.environ, fixture["environment"], clear=True):
                with mock.patch.object(installer, "_run", side_effect=fake_run):
                    self.assertEqual(installer.install(self._arguments(fixture)), 0)
            self.assertTrue((fixture["bin_dir"] / "tmuxgate").is_symlink())

    def _main_stderr(self, fixture, *extra):
        """Run the public entrypoint and return (exit status, stdout, stderr)."""

        out = io.StringIO()
        err = io.StringIO()
        argv = [
            "--source",
            str(REPOSITORY),
            "--bin-dir",
            str(fixture["bin_dir"]),
            "--codex-bin",
            str(fixture["codex"]),
            *extra,
        ]
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = installer.main(argv)
        return status, out.getvalue(), err.getvalue()

    @staticmethod
    def _rows(text):
        """Report lines with column padding collapsed, so layout is not asserted."""

        return re.sub(r"[ \t]+", " ", text)

    def _disable_approvals(self, fixture):
        fixture["config"].write_bytes(
            fixture["config_payload"].replace(
                b'approval_mode = "always"', b'approval_mode = "disabled"'
            )
        )

    def test_automatic_approval_mode_publishes_and_registers_codex(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            fake_run = self._fake_installer_runner(installer._run)
            with mock.patch.dict(os.environ, fixture["environment"], clear=True):
                with mock.patch.object(installer, "_run", side_effect=fake_run):
                    status, out, err = self._main_stderr(fixture)

            self.assertEqual(status, 0)
            self.assertTrue((fixture["bin_dir"] / "tmuxgate").is_symlink())
            self.assertIn("WARNING: approval_mode is disabled", err)
            self.assertNotIn("Overall result", err)
            self.assertNotIn(fixture["token"], out + err)

    def test_acknowledged_disabled_approvals_publish_and_report_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            fake_run = self._fake_installer_runner(installer._run)
            with mock.patch.dict(os.environ, fixture["environment"], clear=True):
                with mock.patch.object(installer, "_run", side_effect=fake_run):
                    self._disable_approvals(fixture)
                    status, out, err = self._main_stderr(
                        fixture, "--allow-disabled-approvals"
                    )

            self.assertEqual(status, 0)
            current = fixture["data"] / "tmuxgate" / "current"
            release_id = Path(os.readlink(current)).name
            # A published run names the release that actually became active.
            self.assertIn(f"Active release: {release_id}", out)
            self.assertIn("WARNING: approval_mode is disabled", err)
            self.assertNotIn("Overall result", err)
            self.assertNotIn(fixture["token"], out + err)

    def test_a_token_created_by_the_run_is_retained_after_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            fixture["token_path"].unlink()
            fake_run = self._fake_installer_runner(installer._run)
            with mock.patch.dict(os.environ, fixture["environment"], clear=True):
                with mock.patch.object(installer, "_run", side_effect=fake_run):
                    self._disable_approvals(fixture)
                    status, out, err = self._main_stderr(fixture)

            self.assertEqual(status, 0)
            self.assertTrue(fixture["token_path"].is_file())
            self.assertNotIn(
                fixture["token_path"].read_text(encoding="ascii").strip(), out + err
            )

    def test_failure_after_publication_reports_retained_candidate_and_rollback(self):
        # A release that was published before the failure may already have been
        # observed, so it is kept on purpose. The report must say it is retained
        # but not active, and must not describe the rolled-back integrations as
        # still updated.
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            fake_run = self._fake_installer_runner(installer._run)
            real_write = installer._write_owned

            def failing_write(path, payload, mode, **kwargs):
                if path.name == "install.json":
                    raise installer.InstallError("synthetic manifest failure")
                return real_write(path, payload, mode, **kwargs)

            report = installer.InstallReport()
            with mock.patch.dict(os.environ, fixture["environment"], clear=True):
                with mock.patch.object(installer, "_run", side_effect=fake_run):
                    with mock.patch.object(
                        installer, "_write_owned", side_effect=failing_write
                    ):
                        with contextlib.redirect_stdout(io.StringIO()):
                            with contextlib.redirect_stderr(io.StringIO()):
                                with self.assertRaises(installer.InstallError):
                                    installer.install(
                                        self._arguments(fixture), report
                                    )

            rendered = self._rows(report.render())
            self.assertIn("Candidate release : RETAINED, NOT ACTIVE", rendered)
            self.assertIn("Current/launcher publication : ROLLED BACK", rendered)
            self.assertIn("Codex registration : RESTORED", rendered)
            self.assertIn("Shell integration : RESTORED", rendered)
            self.assertIn("Rollback : COMPLETE", rendered)
            self.assertIn("Overall result : INCOMPLETE", rendered)
            self.assertIsNotNone(report.candidate_identity)
            retained = sorted(
                path.name
                for path in (fixture["data"] / "tmuxgate" / "releases").iterdir()
            )
            self.assertEqual(retained, [report.candidate_identity])

    def test_repeated_installs_stop_growing_the_data_directory(self):
        # Regression for issue #53: every run published a release and left the
        # one it replaced behind, so the data directory grew without bound.
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            fake_run = self._fake_installer_runner(installer._run)
            install_root = fixture["data"] / "tmuxgate"
            arguments = self._arguments(fixture)
            arguments.keep_releases = 2
            announced = []
            with mock.patch.dict(os.environ, fixture["environment"], clear=True):
                with mock.patch.object(installer, "_run", side_effect=fake_run):
                    for _ in range(5):
                        out = io.StringIO()
                        with contextlib.redirect_stdout(out):
                            with contextlib.redirect_stderr(io.StringIO()):
                                self.assertEqual(installer.install(arguments), 0)
                        announced.extend(
                            line
                            for line in out.getvalue().splitlines()
                            if line.startswith("Removed superseded release")
                        )

            releases = list((install_root / "releases").iterdir())
            # Bounded, and never fewer than what rollback needs.
            self.assertLessEqual(len(releases), 3)
            self.assertGreaterEqual(len(releases), 2)
            self.assertTrue(announced, "pruning must never be silent")
            # The invariants that matter more than the count: the launcher
            # still resolves, through current, to a release that exists.
            current = install_root / "current"
            self.assertTrue(current.resolve().is_dir())
            launcher = fixture["bin_dir"] / "tmuxgate"
            self.assertTrue(launcher.resolve().is_file())
            self.assertIn(
                Path(os.readlink(current)).name,
                [path.name for path in releases],
            )

    def test_retention_failure_never_fails_a_successful_install(self):
        # Reclaiming space is housekeeping. An install that published its
        # release has succeeded, whatever happens to the old directories.
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._fixture(Path(temporary))
            fake_run = self._fake_installer_runner(installer._run)
            with mock.patch.dict(os.environ, fixture["environment"], clear=True):
                with mock.patch.object(installer, "_run", side_effect=fake_run):
                    with mock.patch.object(
                        installer,
                        "_prune_releases",
                        side_effect=OSError("synthetic retention failure"),
                    ):
                        report = installer.InstallReport()
                        out = io.StringIO()
                        errors = io.StringIO()
                        with contextlib.redirect_stdout(out):
                            with contextlib.redirect_stderr(errors):
                                status = installer.install(
                                    self._arguments(fixture), report
                                )

            self.assertEqual(status, 0)
            self.assertIn("retention warning", errors.getvalue())
            self.assertEqual(report.overall, "COMPLETE")
            self.assertIn("FAILED", report.retention)
            self.assertTrue((fixture["bin_dir"] / "tmuxgate").resolve().is_file())

    def test_codex_home_is_hardened_to_owner_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "codex"
            path.mkdir(mode=0o775)
            installer._ensure_codex_directory(path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)


class InstallerSurfaceTests(unittest.TestCase):
    def test_installer_never_starts_or_kills_runtime_processes(self):
        source = INSTALLER_PATH.read_text(encoding="utf-8")
        forbidden = ("pkill", "killall", "tmux kill-server")
        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(value, source)


if __name__ == "__main__":
    unittest.main()
