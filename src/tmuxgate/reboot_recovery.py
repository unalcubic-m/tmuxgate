"""Fixed boot-identity probes used by expected-reboot recovery."""

from __future__ import annotations

from dataclasses import dataclass
import re
import subprocess
from typing import Protocol

from tmuxgate.real_ssh import SshChannelRunner
from tmuxgate.ssh import ResolvedSshEndpoint
from tmuxgate.transport import (
    MasterTransport,
    build_batch_channel_prefix,
    build_independent_boot_id_probe_invocation,
)


BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id"
BOOT_ID_COMMAND = f"/bin/cat {BOOT_ID_PATH}"
MAX_BOOT_ID_OUTPUT_BYTES = 64
_BOOT_ID_OUTPUT_RE = re.compile(
    rb"(?P<boot_id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\n\Z",
    re.ASCII,
)


class BootIdProbeError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        if not isinstance(code, str) or not code or "\x00" in code:
            raise ValueError("boot probe error code is invalid")
        if not isinstance(detail, str) or not detail or "\x00" in detail:
            raise ValueError("boot probe error detail is invalid")
        self.code = code
        super().__init__(detail)


class BootIdProbe(Protocol):
    def capture_pre_reboot(self, transport: MasterTransport) -> str: ...
    def probe_after_disconnect(self, endpoint: ResolvedSshEndpoint) -> str: ...


@dataclass(slots=True)
class RealBootIdProbe:
    channels: SshChannelRunner
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        if not isinstance(self.channels, SshChannelRunner):
            raise TypeError("channels must be an SshChannelRunner")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 0 < float(self.timeout_seconds) <= 60
        ):
            raise ValueError("boot probe timeout must be from 0 to 60 seconds")
        self.timeout_seconds = float(self.timeout_seconds)

    @staticmethod
    def _validated_output(stdout: bytes, stderr: bytes) -> str:
        if (
            len(stdout) > MAX_BOOT_ID_OUTPUT_BYTES
            or len(stderr) > MAX_BOOT_ID_OUTPUT_BYTES
        ):
            raise BootIdProbeError(
                "boot_id_invalid",
                "boot ID probe output exceeded the fixed validation bound",
            )
        match = _BOOT_ID_OUTPUT_RE.fullmatch(stdout)
        if match is None or stderr:
            raise BootIdProbeError(
                "boot_id_invalid",
                "boot ID probe returned non-canonical or diagnostically ambiguous output",
            )
        return match.group("boot_id").decode("ascii")

    def _run(self, argv: tuple[str, ...], *, pre_reboot: bool) -> str:
        try:
            result = self.channels.batch(
                argv,
                timeout_seconds=self.timeout_seconds,
            )
        except (TimeoutError, subprocess.TimeoutExpired) as exc:
            raise BootIdProbeError(
                "pre_reboot_boot_id_unavailable" if pre_reboot else "reboot_probe_unavailable",
                "boot ID probe timed out",
            ) from exc
        except BaseException as exc:
            raise BootIdProbeError(
                "pre_reboot_boot_id_unavailable" if pre_reboot else "reboot_probe_unavailable",
                "boot ID probe could not be executed",
            ) from exc
        if result.returncode != 0:
            diagnostic = result.stderr.decode("utf-8", "backslashreplace").casefold()
            if "host identification has changed" in diagnostic or "host key verification failed" in diagnostic:
                code = "host_key_mismatch"
            elif "permission denied" in diagnostic:
                code = "credential_unavailable"
            else:
                code = (
                    "pre_reboot_boot_id_unavailable"
                    if pre_reboot
                    else "reboot_probe_unavailable"
                )
            raise BootIdProbeError(code, f"boot ID probe exited with status {result.returncode}")
        return self._validated_output(result.stdout, result.stderr)

    def capture_pre_reboot(self, transport: MasterTransport) -> str:
        invocation = build_batch_channel_prefix(
            transport.endpoint,
            transport.control_path,
        )
        return self._run((*invocation.argv, BOOT_ID_COMMAND), pre_reboot=True)

    def probe_after_disconnect(self, endpoint: ResolvedSshEndpoint) -> str:
        invocation = build_independent_boot_id_probe_invocation(endpoint)
        return self._run(invocation.argv, pre_reboot=False)
