import os
from pathlib import Path
import socket
import stat
import tempfile
import unittest
from unittest import mock

from tmuxgate.runtime import (
    PeerCredentialError,
    RuntimeSecurityError,
    acquire_broker_lock,
    cleanup_socket_path,
    create_broker_socket,
    default_socket_path,
    default_state_dir,
    default_state_home,
    ensure_control_directory,
    ensure_private_directory,
    ensure_socket_parent,
    ensure_spool_directory,
    ensure_state_directory,
    open_broker_listener,
    peer_credentials,
    prepare_runtime_layout,
    require_same_uid,
)


class RuntimePathTests(unittest.TestCase):
    def test_default_socket_is_under_xdg_runtime_directory(self):
        path = default_socket_path({"XDG_RUNTIME_DIR": "/run/user/1234"})
        self.assertEqual(path, Path("/run/user/1234/tmuxgate/broker.sock"))

        with self.assertRaisesRegex(RuntimeSecurityError, "XDG_RUNTIME_DIR"):
            default_socket_path({})
        with self.assertRaisesRegex(RuntimeSecurityError, "absolute"):
            default_socket_path({"XDG_RUNTIME_DIR": "relative"})

    def test_default_state_uses_xdg_or_home_fallback(self):
        self.assertEqual(
            default_state_home({"XDG_STATE_HOME": "/var/lib/private-user"}),
            Path("/var/lib/private-user"),
        )
        self.assertEqual(
            default_state_dir({"XDG_STATE_HOME": "/var/lib/private-user"}),
            Path("/var/lib/private-user/tmuxgate"),
        )
        self.assertEqual(
            default_state_home({"HOME": "/home/example"}),
            Path("/home/example/.local/state"),
        )
        with self.assertRaisesRegex(RuntimeSecurityError, "absolute"):
            default_state_home({"XDG_STATE_HOME": "relative"})

    def test_layout_separates_ephemeral_runtime_from_durable_state_and_spool(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            runtime_home = base / "run"
            state_home = base / "state"
            runtime_home.mkdir(mode=0o700)
            paths = prepare_runtime_layout(
                environ={
                    "XDG_RUNTIME_DIR": str(runtime_home),
                    "XDG_STATE_HOME": str(state_home),
                }
            )

            self.assertEqual(paths.runtime_dir, runtime_home / "tmuxgate")
            self.assertEqual(paths.socket_path, paths.runtime_dir / "broker.sock")
            self.assertEqual(paths.control_dir, paths.runtime_dir / "control")
            self.assertEqual(paths.lock_path, paths.runtime_dir / "broker.lock")
            self.assertEqual(paths.state_dir, state_home / "tmuxgate")
            self.assertEqual(paths.spool_dir, paths.state_dir / "spool")
            self.assertFalse((paths.runtime_dir / "state").exists())
            for directory in (
                paths.runtime_dir,
                paths.control_dir,
                paths.state_dir,
                paths.spool_dir,
            ):
                self.assertTrue(directory.is_dir())
                self.assertEqual(stat.S_IMODE(os.lstat(directory).st_mode), 0o700)
                self.assertEqual(os.lstat(directory).st_uid, os.geteuid())

    def test_layout_creates_home_fallback_state_tree_without_runtime_overlap(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            runtime_home = base / "run"
            home = base / "home"
            runtime_home.mkdir(mode=0o700)
            home.mkdir(mode=0o700)
            paths = prepare_runtime_layout(
                environ={
                    "XDG_RUNTIME_DIR": str(runtime_home),
                    "HOME": str(home),
                }
            )

            self.assertEqual(paths.state_dir, home / ".local/state/tmuxgate")
            self.assertEqual(paths.spool_dir, paths.state_dir / "spool")
            self.assertTrue(paths.state_dir.is_dir())
            self.assertTrue(paths.spool_dir.is_dir())
            self.assertNotEqual(paths.state_dir.parent, paths.runtime_dir)

    def test_custom_state_spool_and_control_helpers_are_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            runtime_dir = base / "runtime"
            state_dir = base / "durable-state"
            ensure_private_directory(runtime_dir)
            self.assertEqual(ensure_state_directory(state_dir), state_dir)
            spool_dir = ensure_spool_directory(state_dir)
            control_dir = ensure_control_directory(runtime_dir)
            self.assertEqual(ensure_state_directory(state_dir), state_dir)
            self.assertEqual(ensure_spool_directory(state_dir), spool_dir)
            self.assertEqual(ensure_control_directory(runtime_dir), control_dir)
            self.assertEqual(stat.S_IMODE(state_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(spool_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(control_dir.stat().st_mode), 0o700)

    def test_symlink_and_permissive_private_directories_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "target"
            target.mkdir(mode=0o700)
            linked = base / "linked"
            linked.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeSecurityError, "symlink"):
                ensure_private_directory(linked)

            permissive = base / "permissive"
            permissive.mkdir(mode=0o700)
            permissive.chmod(0o750)
            with self.assertRaisesRegex(RuntimeSecurityError, "0700"):
                ensure_private_directory(permissive)

    def test_symlinked_state_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "target"
            target.mkdir(mode=0o700)
            linked = base / "state"
            linked.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeSecurityError, "symlink"):
                ensure_state_directory(linked)

    def test_dot_components_are_rejected_for_custom_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            with self.assertRaisesRegex(RuntimeSecurityError, "dot components"):
                ensure_private_directory(f"{base}/./private")
            with self.assertRaisesRegex(RuntimeSecurityError, "dot components"):
                ensure_state_directory(f"{base}/branch/../state")
            with self.assertRaisesRegex(RuntimeSecurityError, "dot components"):
                ensure_socket_parent(f"{base}/runtime/../broker.sock")

    def test_intermediate_symlinks_are_rejected_for_custom_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            real = base / "real"
            real.mkdir(mode=0o700)
            linked = base / "linked"
            linked.symlink_to(real, target_is_directory=True)

            with self.assertRaisesRegex(RuntimeSecurityError, "symlink"):
                ensure_private_directory(linked / "private")
            with self.assertRaisesRegex(RuntimeSecurityError, "symlink"):
                ensure_state_directory(linked / "state")
            with self.assertRaisesRegex(RuntimeSecurityError, "symlink"):
                ensure_socket_parent(linked / "runtime" / "broker.sock")


class BrokerSocketTests(unittest.TestCase):
    def _new_path(self, base: Path) -> Path:
        runtime_dir = base / "runtime"
        ensure_private_directory(runtime_dir)
        return runtime_dir / "broker.sock"

    def test_create_binds_listens_and_enforces_mode_0600(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._new_path(Path(temporary))
            listener = create_broker_socket(path)
            try:
                metadata = os.lstat(path)
                self.assertTrue(stat.S_ISSOCK(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
                self.assertEqual(metadata.st_uid, os.geteuid())
                self.assertFalse(listener.get_inheritable())

                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.addCleanup(client.close)
                client.connect(os.fspath(path))
                accepted, _ = listener.accept()
                accepted.close()
            finally:
                listener.close()
            self.assertTrue(cleanup_socket_path(path))
            self.assertFalse(path.exists())

    def test_live_listener_is_refused_and_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._new_path(Path(temporary))
            live = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            live.bind(os.fspath(path))
            os.chmod(path, 0o600)
            live.listen(1)
            before = os.lstat(path)
            try:
                with self.assertRaisesRegex(RuntimeSecurityError, "live listener"):
                    create_broker_socket(path)
                after = os.lstat(path)
                self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            finally:
                live.close()
            self.assertTrue(cleanup_socket_path(path))

    def test_regular_file_is_refused_and_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._new_path(Path(temporary))
            path.touch(mode=0o600)
            before = os.lstat(path)
            with self.assertRaisesRegex(RuntimeSecurityError, "non-socket"):
                create_broker_socket(path)
            after = os.lstat(path)
            self.assertTrue(stat.S_ISREG(after.st_mode))
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))

    def test_only_mode_0600_stale_owned_socket_is_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._new_path(Path(temporary))
            stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stale.bind(os.fspath(path))
            os.chmod(path, 0o600)
            stale.close()

            listener = create_broker_socket(path)
            try:
                # A successful second bind proves the stale pathname was
                # removed; filesystems may immediately reuse its inode number.
                self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
            finally:
                listener.close()
            self.assertTrue(cleanup_socket_path(path))

    def test_stale_socket_with_unsafe_mode_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._new_path(Path(temporary))
            stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stale.bind(os.fspath(path))
            stale.close()
            os.chmod(path, 0o660)
            before = os.lstat(path)
            with self.assertRaisesRegex(RuntimeSecurityError, "0600"):
                create_broker_socket(path)
            self.assertEqual(before.st_ino, os.lstat(path).st_ino)

    def test_cleanup_of_missing_socket_is_a_noop(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._new_path(Path(temporary))
            self.assertFalse(cleanup_socket_path(path))


class BrokerLifecycleTests(unittest.TestCase):
    def _new_path(self, base: Path) -> Path:
        runtime_dir = base / "runtime"
        ensure_private_directory(runtime_dir)
        return runtime_dir / "broker.sock"

    def test_singleton_lock_is_mode_0600_exclusive_and_reacquirable(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime_dir = Path(temporary) / "runtime"
            ensure_private_directory(runtime_dir)

            first = acquire_broker_lock(runtime_dir)
            try:
                metadata = os.lstat(first.path)
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
                self.assertEqual(metadata.st_uid, os.geteuid())
                with self.assertRaisesRegex(RuntimeSecurityError, "already holds"):
                    acquire_broker_lock(runtime_dir)
            finally:
                first.close()

            second = acquire_broker_lock(runtime_dir)
            second.close()

    def test_singleton_lock_rejects_symlink_and_unsafe_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            runtime_dir = base / "runtime"
            ensure_private_directory(runtime_dir)
            target = base / "target.lock"
            target.touch(mode=0o600)
            (runtime_dir / "broker.lock").symlink_to(target)
            with self.assertRaises(RuntimeSecurityError):
                acquire_broker_lock(runtime_dir)

        with tempfile.TemporaryDirectory() as temporary:
            runtime_dir = Path(temporary) / "runtime"
            ensure_private_directory(runtime_dir)
            lock_path = runtime_dir / "broker.lock"
            lock_path.touch(mode=0o600)
            lock_path.chmod(0o640)
            with self.assertRaisesRegex(RuntimeSecurityError, "0600"):
                acquire_broker_lock(runtime_dir)

    def test_listener_lifecycle_holds_lock_and_removes_only_its_socket(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._new_path(Path(temporary))
            lifecycle = open_broker_listener(path)
            try:
                self.assertEqual(lifecycle.socket_path, path)
                self.assertEqual(lifecycle.lock_path, path.parent / "broker.lock")
                self.assertIs(type(lifecycle.listener), socket.socket)
                self.assertFalse(lifecycle.listener.get_inheritable())
                self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
                with self.assertRaisesRegex(RuntimeSecurityError, "already holds"):
                    open_broker_listener(path)
            finally:
                lifecycle.close()

            self.assertFalse(path.exists())
            reopened = open_broker_listener(path)
            reopened.close()

    def test_lock_prevents_bound_not_listening_socket_from_being_cleaned(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._new_path(Path(temporary))
            lock = acquire_broker_lock(path.parent)
            bound = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                bound.bind(os.fspath(path))
                os.chmod(path, 0o600)
                before = os.lstat(path)
                with self.assertRaisesRegex(RuntimeSecurityError, "already holds"):
                    open_broker_listener(path)
                after = os.lstat(path)
                self.assertEqual(
                    (before.st_dev, before.st_ino),
                    (after.st_dev, after.st_ino),
                )
            finally:
                bound.close()
                lock.close()
            self.assertTrue(cleanup_socket_path(path))

    def test_listener_setup_failure_closes_socket_and_releases_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = self._new_path(Path(temporary))
            with mock.patch(
                "tmuxgate.runtime._validate_socket_stat",
                side_effect=[None, RuntimeSecurityError("forced revalidation failure")],
            ):
                with self.assertRaisesRegex(
                    RuntimeSecurityError,
                    "forced revalidation failure",
                ):
                    open_broker_listener(path)

            self.assertFalse(path.exists())
            lock = acquire_broker_lock(path.parent)
            lock.close()


class PeerCredentialTests(unittest.TestCase):
    def test_linux_peer_credentials_and_same_uid_validation(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(left.close)
        self.addCleanup(right.close)

        credentials = peer_credentials(right)
        self.assertEqual(credentials.pid, os.getpid())
        self.assertEqual(credentials.uid, os.geteuid())
        self.assertEqual(credentials.gid, os.getegid())
        self.assertEqual(require_same_uid(right), credentials)

    def test_wrong_peer_uid_is_rejected(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with self.assertRaisesRegex(PeerCredentialError, "does not match"):
            require_same_uid(right, expected_uid=os.geteuid() + 1)

    def test_non_unix_socket_is_rejected(self):
        internet_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(internet_socket.close)
        with self.assertRaisesRegex(PeerCredentialError, "AF_UNIX"):
            peer_credentials(internet_socket)


if __name__ == "__main__":
    unittest.main()
