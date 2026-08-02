"""Automatic per-machine Ed25519 key creation and idempotent enrollment."""

from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path
import shlex
import stat
import subprocess

from tmuxgate.real_ssh import SshChannelRunner
from tmuxgate.runtime import ensure_private_directory
from tmuxgate.ssh import ResolvedSshEndpoint, default_tmuxgate_identity_file
from tmuxgate.transport import (
    KeyEnrollmentOutcome,
    TransportError,
    build_batch_channel_prefix,
)


_REMOTE_KEY_STATUS_SCRIPT = r"""
set -eu
key=$(cat)
case "$key" in
  'ssh-ed25519 '*) ;;
  *) exit 125 ;;
esac
case "$key" in
  *'\r'*|*'\n'*) exit 125 ;;
esac
owner=$(id -u)
ssh_dir=$HOME/.ssh
[ -e "$ssh_dir" ] || [ -L "$ssh_dir" ] || exit 3
[ -d "$ssh_dir" ] && [ ! -L "$ssh_dir" ] || exit 125
[ "$(stat -c '%a:%u' "$ssh_dir")" = "700:$owner" ] || exit 125
authorized=$ssh_dir/authorized_keys
[ -e "$authorized" ] || [ -L "$authorized" ] || exit 3
if [ -L "$authorized" ]; then
  grep -Fqx -- "$key" "$authorized" && exit 0
  exit 3
fi
[ -f "$authorized" ] || exit 125
[ "$(stat -c '%a:%u' "$authorized")" = "600:$owner" ] || exit 125
grep -Fqx -- "$key" "$authorized" && exit 0
exit 3
"""


_REMOTE_ENROLL_SCRIPT = r"""
set -eu
umask 077
key=$(cat)
case "$key" in
  'ssh-ed25519 '*) ;;
  *) echo 'tmuxgate refused invalid public key' >&2; exit 125 ;;
esac
case "$key" in
  *'\r'*|*'\n'*) echo 'tmuxgate refused multiline public key' >&2; exit 125 ;;
esac
owner=$(id -u)
ssh_dir=$HOME/.ssh
if [ -e "$ssh_dir" ] || [ -L "$ssh_dir" ]; then
  [ -d "$ssh_dir" ] && [ ! -L "$ssh_dir" ] || exit 125
  [ "$(stat -c '%a:%u' "$ssh_dir")" = "700:$owner" ] || exit 125
else
  mkdir -m 700 "$ssh_dir"
fi
authorized=$ssh_dir/authorized_keys
if [ -e "$authorized" ] || [ -L "$authorized" ]; then
  if [ -L "$authorized" ]; then
    # Some systems, including Proxmox, deliberately manage authorized_keys
    # through a symlink. Never write through it; accept only an exact key that
    # an operator has already installed through a trusted administrative path.
    grep -Fqx -- "$key" "$authorized" || exit 125
    exit 0
  fi
  [ -f "$authorized" ] || exit 125
  [ "$(stat -c '%a:%u' "$authorized")" = "600:$owner" ] || exit 125
else
  : > "$authorized"
  chmod 600 "$authorized"
fi
if ! grep -Fqx -- "$key" "$authorized"; then
  printf '%s\n' "$key" >> "$authorized"
fi
grep -Fqx -- "$key" "$authorized" || exit 125
"""


class AutoSshKeyManager:
    """Create one local key per logical machine and enroll it over a live master."""

    def __init__(
        self,
        *,
        channels: SshChannelRunner | None = None,
        runner=subprocess.run,
        expected_uid: int | None = None,
    ) -> None:
        self.channels = SshChannelRunner() if channels is None else channels
        self.runner = runner
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid

    def _paths(self, resolved: ResolvedSshEndpoint) -> tuple[Path, Path]:
        private = default_tmuxgate_identity_file(resolved.machine_name)
        return private, Path(os.fspath(private) + ".pub")

    def _validate_pair(self, private: Path, public: Path) -> bytes:
        for path, expected_mode in ((private, 0o600), (public, 0o600)):
            try:
                metadata = os.lstat(path)
            except FileNotFoundError as exc:
                raise TransportError("tmuxgate SSH key pair is incomplete") from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != self.expected_uid
                or stat.S_IMODE(metadata.st_mode) != expected_mode
            ):
                raise TransportError("tmuxgate SSH key file is unsafe")
        content = public.read_bytes()
        if (
            not content.startswith(b"ssh-ed25519 ")
            or b"\x00" in content
            or b"\r" in content
            or len(content) > 4096
            or len(content.rstrip(b"\n").splitlines()) != 1
        ):
            raise TransportError("tmuxgate public key is invalid")
        return content.rstrip(b"\n") + b"\n"

    def prepare_local_key(self, resolved: ResolvedSshEndpoint) -> None:
        private, public = self._paths(resolved)
        ssh_dir = ensure_private_directory(
            private.parent.parent, expected_uid=self.expected_uid
        )
        ensure_private_directory(private.parent, expected_uid=self.expected_uid)
        private_exists = private.exists() or private.is_symlink()
        public_exists = public.exists() or public.is_symlink()
        if private_exists != public_exists:
            raise TransportError("tmuxgate SSH key pair is incomplete")
        if not private_exists:
            completed = self.runner(
                (
                    "/usr/bin/ssh-keygen", "-q", "-t", "ed25519",
                    "-N", "", "-C", f"tmuxgate-{resolved.machine_name}",
                    "-f", os.fspath(private),
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=15,
            )
            if getattr(completed, "returncode", None) != 0:
                raise TransportError("tmuxgate could not create its SSH key")
            os.chmod(public, 0o600, follow_symlinks=False)
        self._validate_pair(private, public)

    def enroll_remote_key(
        self,
        resolved: ResolvedSshEndpoint,
        control_path: Path,
        *,
        before_remote_mutation: Callable[[], None],
    ) -> KeyEnrollmentOutcome:
        if not callable(before_remote_mutation):
            raise TypeError("before_remote_mutation must be callable")
        private, public = self._paths(resolved)
        content = self._validate_pair(private, public)
        prefix = build_batch_channel_prefix(resolved, control_path).argv
        status_command = "/bin/sh -c " + shlex.quote(_REMOTE_KEY_STATUS_SCRIPT)
        status = self.channels.batch(
            (*prefix, status_command),
            input_bytes=content,
            timeout_seconds=30,
        )
        if status.returncode == 0:
            return KeyEnrollmentOutcome.ALREADY_PRESENT
        if status.returncode != 3:
            raise TransportError(
                "tmuxgate could not safely inspect its SSH public key before enrollment"
            )

        before_remote_mutation()
        command = "/bin/sh -c " + shlex.quote(_REMOTE_ENROLL_SCRIPT)
        result = self.channels.batch(
            (*prefix, command),
            input_bytes=content,
            timeout_seconds=30,
        )
        if result.returncode != 0:
            raise TransportError(
                "tmuxgate could not enroll its SSH public key on the remote machine"
            )
        return KeyEnrollmentOutcome.ENROLLED_AND_VERIFIED
