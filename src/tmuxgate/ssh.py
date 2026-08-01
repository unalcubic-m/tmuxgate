"""Broker-owned OpenSSH configuration resolution without making a connection."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import base64
import binascii
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
from typing import Any

from tmuxgate.config import Endpoint, Machine
from tmuxgate.models import validate_alias


DEFAULT_SSH_PATH = Path("/usr/bin/ssh")
DEFAULT_SSH_KEYGEN_PATH = Path("/usr/bin/ssh-keygen")
DEFAULT_RESOLUTION_TIMEOUT_SECONDS = 5.0
MAX_SSH_G_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_KNOWN_HOSTS_BYTES = 16 * 1024 * 1024
SSH_POLICY_VERSION = 2

_KEY_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*\Z", re.ASCII)
_SAFE_STRICT_HOST_KEY_CHECKING = frozenset({"ask", "yes"})
_FALSE_VALUES = frozenset({"false", "no"})
_NONE_VALUES = frozenset({"", "none"})


def default_tmuxgate_identity_file(
    machine_name: str,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Return the deterministic private identity path for one logical machine."""

    machine_name = validate_alias(machine_name, field_name="machine name")
    source = os.environ if environ is None else environ
    home = Path(source.get("HOME") or os.path.expanduser("~"))
    if not home.is_absolute():
        raise SshResolutionError("tmuxgate identity root must be absolute")
    return home / ".ssh" / "tmuxgate" / f"{machine_name}.ed25519"


class SshResolutionError(RuntimeError):
    """The broker could not prove a safe, exact OpenSSH execution identity."""


@dataclass(frozen=True, slots=True)
class KnownHostsSourceEvidence:
    configured_path: str
    resolved_path: str | None
    status: str
    sha256: str | None

    def canonical_document(self) -> dict[str, object]:
        return {
            "configured_path": self.configured_path,
            "resolved_path": self.resolved_path,
            "sha256": self.sha256,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class HostKeyRecord:
    algorithm: str
    fingerprint_sha256: str
    marker: str | None
    source_path: str

    def canonical_document(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "fingerprint_sha256": self.fingerprint_sha256,
            "marker": self.marker,
            "source_path": self.source_path,
        }


@dataclass(frozen=True, slots=True)
class HostKeyEvidence:
    host_key_alias: str
    status: str
    sources: tuple[KnownHostsSourceEvidence, ...]
    records: tuple[HostKeyRecord, ...]

    def __post_init__(self) -> None:
        if self.status not in {"known", "unknown"}:
            raise ValueError("host-key evidence status must be known or unknown")
        if (self.status == "known") != bool(self.records):
            raise ValueError("known host-key status must agree with records")

    def canonical_document(self) -> dict[str, object]:
        return {
            "host_key_alias": self.host_key_alias,
            "records": [item.canonical_document() for item in self.records],
            "sources": [item.canonical_document() for item in self.sources],
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class ResolvedSshEndpoint:
    machine_name: str
    endpoint_id: str
    required_context: str
    configured_address: str
    configured_port: int
    connect_timeout_seconds: int
    ssh_profile: str
    resolved_host: str
    resolved_hostname: str
    resolved_user: str
    resolved_port: int
    host_key_alias: str
    strict_host_key_checking: str
    user_known_hosts_files: tuple[str, ...]
    global_known_hosts_files: tuple[str, ...]
    host_key_algorithms: str | None
    host_key_evidence: HostKeyEvidence
    proxy_jump: str | None
    proxy_command: str | None
    identity_agent: str | None
    identity_files: tuple[str, ...]
    enabled_authentication_methods: tuple[str, ...]
    ssh_g_output_sha256: str
    ssh_policy_sha256: str
    ssh_g_argv: tuple[str, ...]

    def canonical_document(self) -> dict[str, object]:
        return {
            "machine_name": self.machine_name,
            "configured_address": self.configured_address,
            "configured_port": self.configured_port,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "enabled_authentication_methods": list(self.enabled_authentication_methods),
            "endpoint_id": self.endpoint_id,
            "global_known_hosts_files": list(self.global_known_hosts_files),
            "host_key_algorithms": self.host_key_algorithms,
            "host_key_alias": self.host_key_alias,
            "host_key_evidence": self.host_key_evidence.canonical_document(),
            "identity_agent": self.identity_agent,
            "identity_files": list(self.identity_files),
            "proxy_command": self.proxy_command,
            "proxy_jump": self.proxy_jump,
            "required_context": self.required_context,
            "resolved_host": self.resolved_host,
            "resolved_hostname": self.resolved_hostname,
            "resolved_port": self.resolved_port,
            "resolved_user": self.resolved_user,
            "ssh_g_argv": list(self.ssh_g_argv),
            "ssh_g_output_sha256": self.ssh_g_output_sha256,
            "ssh_policy_sha256": self.ssh_policy_sha256,
            "ssh_profile": self.ssh_profile,
            "strict_host_key_checking": self.strict_host_key_checking,
            "user_known_hosts_files": list(self.user_known_hosts_files),
        }


HostKeyCollector = Callable[
    [str, tuple[str, ...], tuple[str, ...]], HostKeyEvidence
]
CommandRunner = Callable[..., object]


def _canonical_sha256(document: Mapping[str, object]) -> str:
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _safe_environment() -> dict[str, str]:
    allowed = ("HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOGNAME", "SSH_AUTH_SOCK", "USER")
    environment: dict[str, str] = {"PATH": "/usr/bin:/bin"}
    for name in allowed:
        value = os.environ.get(name)
        if value and "\x00" not in value:
            environment[name] = value
    return environment


def build_ssh_g_argv(
    machine: Machine,
    endpoint: Endpoint,
    *,
    ssh_path: os.PathLike[str] | str = DEFAULT_SSH_PATH,
) -> tuple[str, ...]:
    """Build the sole broker-owned `ssh -G` invocation for one endpoint."""

    executable = Path(ssh_path)
    if not executable.is_absolute():
        raise SshResolutionError("ssh executable path must be absolute")
    return (
        os.fspath(executable),
        "-G",
        "-o",
        "BatchMode=no",
        "-o",
        "CanonicalizeHostname=no",
        "-o",
        f"ConnectTimeout={machine.connect_timeout_seconds}",
        "-o",
        f"HostKeyAlias={machine.host_key_alias}",
        "-o",
        f"HostName={endpoint.address.exploded}",
        "-o",
        f"IdentityFile={default_tmuxgate_identity_file(machine.name)}",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        f"Port={endpoint.port}",
        "-o",
        "RemoteCommand=none",
        "-o",
        "RequestTTY=no",
        "-o",
        f"User={machine.user}",
        "-T",
        "--",
        machine.ssh_profile,
    )


def _parse_output(raw_output: bytes) -> dict[str, list[str]]:
    if not isinstance(raw_output, bytes):
        raise SshResolutionError("ssh -G output must be bytes")
    if len(raw_output) > MAX_SSH_G_OUTPUT_BYTES:
        raise SshResolutionError("ssh -G output exceeds the configured limit")
    if b"\x00" in raw_output:
        raise SshResolutionError("ssh -G output contains NUL")
    text = raw_output.decode(errors="surrogateescape")
    parsed: dict[str, list[str]] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line:
            continue
        key, separator, value = raw_line.partition(" ")
        if not separator or _KEY_RE.fullmatch(key) is None or not value:
            raise SshResolutionError(f"ssh -G line {line_number} is malformed")
        parsed.setdefault(key.lower(), []).append(value)
    return parsed


def _single(parsed: Mapping[str, list[str]], key: str, *, required: bool = True) -> str | None:
    values = parsed.get(key, [])
    if not values:
        if required:
            raise SshResolutionError(f"ssh -G did not report {key}")
        return None
    if len(values) != 1:
        raise SshResolutionError(f"ssh -G reported {key} more than once")
    return values[0]


def _tokenized_option(parsed: Mapping[str, list[str]], key: str) -> tuple[str, ...]:
    value = _single(parsed, key, required=False)
    if value is None or value.lower() in _NONE_VALUES:
        return ()
    try:
        tokens = tuple(shlex.split(value, posix=True))
    except ValueError as exc:
        raise SshResolutionError(f"ssh -G {key} could not be tokenized") from exc
    if not tokens:
        raise SshResolutionError(f"ssh -G {key} is empty")
    return tokens


def _optional_value(parsed: Mapping[str, list[str]], key: str) -> str | None:
    value = _single(parsed, key, required=False)
    if value is None or value.lower() in _NONE_VALUES:
        return None
    return value


def _fingerprint_key_blob(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SshResolutionError("ssh-keygen returned a malformed host key") from exc
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _resolved_known_hosts_path(configured_path: str) -> Path:
    if "%" in configured_path:
        raise SshResolutionError(
            f"known-hosts path contains unsupported OpenSSH tokens: {configured_path!r}"
        )
    path = Path(configured_path).expanduser()
    if not path.is_absolute():
        raise SshResolutionError("known-hosts path must resolve to an absolute path")
    return path


def collect_host_key_evidence(
    host_key_alias: str,
    user_known_hosts_files: tuple[str, ...],
    global_known_hosts_files: tuple[str, ...],
    *,
    runner: CommandRunner = subprocess.run,
    ssh_keygen_path: os.PathLike[str] | str = DEFAULT_SSH_KEYGEN_PATH,
) -> HostKeyEvidence:
    """Inspect local known-hosts data for an alias without contacting a host."""

    executable = Path(ssh_keygen_path)
    if not executable.is_absolute():
        raise SshResolutionError("ssh-keygen executable path must be absolute")
    sources: list[KnownHostsSourceEvidence] = []
    records: list[HostKeyRecord] = []
    seen_records: set[tuple[str, str, str | None, str]] = set()

    for configured_path in (*user_known_hosts_files, *global_known_hosts_files):
        path = _resolved_known_hosts_path(configured_path)
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            sources.append(
                KnownHostsSourceEvidence(configured_path, os.fspath(path), "missing", None)
            )
            continue
        except OSError as exc:
            raise SshResolutionError(f"cannot inspect known-hosts file {path}: {exc}") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise SshResolutionError(f"known-hosts path is not a regular file: {path}")
        if metadata.st_size > MAX_KNOWN_HOSTS_BYTES:
            raise SshResolutionError(f"known-hosts file exceeds the configured limit: {path}")
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise SshResolutionError(f"cannot read known-hosts file {path}: {exc}") from exc
        source_digest = hashlib.sha256(content).hexdigest()
        sources.append(
            KnownHostsSourceEvidence(configured_path, os.fspath(path), "present", source_digest)
        )
        command = (
            os.fspath(executable),
            "-F",
            host_key_alias,
            "-f",
            os.fspath(path),
        )
        try:
            completed = runner(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_safe_environment(),
                timeout=DEFAULT_RESOLUTION_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SshResolutionError(f"local host-key lookup failed for {path}") from exc
        returncode = getattr(completed, "returncode", None)
        stdout = getattr(completed, "stdout", None)
        if returncode not in {0, 1} or not isinstance(stdout, bytes):
            raise SshResolutionError(f"local host-key lookup returned an invalid result for {path}")
        if len(stdout) > MAX_SSH_G_OUTPUT_BYTES:
            raise SshResolutionError("local host-key lookup output is too large")
        for raw_line in stdout.splitlines():
            if not raw_line or raw_line.startswith(b"#"):
                continue
            try:
                fields = raw_line.decode("ascii").split()
            except UnicodeDecodeError as exc:
                raise SshResolutionError("ssh-keygen host-key output is not ASCII") from exc
            marker: str | None = None
            if fields and fields[0].startswith("@"):
                if len(fields) < 4:
                    raise SshResolutionError("ssh-keygen returned a malformed marked key")
                marker, _hosts, algorithm, encoded_key = fields[:4]
            else:
                if len(fields) < 3:
                    raise SshResolutionError("ssh-keygen returned a malformed key")
                _hosts, algorithm, encoded_key = fields[:3]
            fingerprint = _fingerprint_key_blob(encoded_key)
            identity = (algorithm, fingerprint, marker, os.fspath(path))
            if identity in seen_records:
                continue
            seen_records.add(identity)
            records.append(
                HostKeyRecord(algorithm, fingerprint, marker, os.fspath(path))
            )

    records.sort(
        key=lambda item: (
            item.source_path,
            item.algorithm,
            item.fingerprint_sha256,
            item.marker or "",
        )
    )
    return HostKeyEvidence(
        host_key_alias=host_key_alias,
        status="known" if records else "unknown",
        sources=tuple(sources),
        records=tuple(records),
    )


def _policy_document(machine: Machine, endpoint: Endpoint) -> dict[str, object]:
    return {
        "batch_mode_for_initial_master": False,
        "batch_mode_for_post_auth_channels": True,
        "certificate_files": [],
        "canonicalize_hostname": False,
        "connect_timeout_seconds": machine.connect_timeout_seconds,
        "endpoint_address": endpoint.address.exploded,
        "endpoint_port": endpoint.port,
        "host_key_alias": machine.host_key_alias,
        "identity_files": [
            os.fspath(default_tmuxgate_identity_file(machine.name))
        ],
        "identities_only": True,
        "machine_control": {
            "remote_command": "none",
            "request_tty": False,
            "ssh_flag": "-T",
        },
        "permit_local_command": False,
        "policy_version": SSH_POLICY_VERSION,
        "remote_user": machine.user,
        "viewer": {
            "remote_command": "none",
            "request_tty": "force",
            "ssh_flag": "-tt",
        },
    }


def resolve_ssh_endpoint(
    machine: Machine,
    endpoint: Endpoint,
    *,
    runner: CommandRunner = subprocess.run,
    host_key_collector: HostKeyCollector = collect_host_key_evidence,
    ssh_path: os.PathLike[str] | str = DEFAULT_SSH_PATH,
    timeout_seconds: float = DEFAULT_RESOLUTION_TIMEOUT_SECONDS,
) -> ResolvedSshEndpoint:
    """Resolve and validate one configured endpoint using local `ssh -G` only."""

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
    ):
        raise ValueError("ssh -G timeout must be a positive finite number")
    argv = build_ssh_g_argv(machine, endpoint, ssh_path=ssh_path)
    try:
        completed = runner(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_safe_environment(),
            timeout=float(timeout_seconds),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SshResolutionError("local ssh -G resolution failed") from exc
    returncode = getattr(completed, "returncode", None)
    raw_output = getattr(completed, "stdout", None)
    raw_stderr = getattr(completed, "stderr", None)
    if returncode != 0 or not isinstance(raw_output, bytes):
        detail = raw_stderr[:160] if isinstance(raw_stderr, bytes) else b""
        raise SshResolutionError(f"ssh -G failed with status {returncode}: {detail!r}")
    parsed = _parse_output(raw_output)

    resolved_host = _single(parsed, "host")
    resolved_user = _single(parsed, "user")
    resolved_hostname = _single(parsed, "hostname")
    raw_port = _single(parsed, "port")
    host_key_alias = _single(parsed, "hostkeyalias")
    strict = _single(parsed, "stricthostkeychecking")
    request_tty = _single(parsed, "requesttty")
    batch_mode = _single(parsed, "batchmode")
    identities_only = _single(parsed, "identitiesonly")
    canonicalize = _single(parsed, "canonicalizehostname")
    permit_local = _single(parsed, "permitlocalcommand")
    remote_command = _optional_value(parsed, "remotecommand")

    try:
        resolved_port = int(raw_port, 10) if raw_port is not None else -1
    except ValueError as exc:
        raise SshResolutionError("ssh -G port is not an integer") from exc
    expected_hostname = endpoint.address.exploded
    required_matches = {
        "host": (resolved_host, machine.ssh_profile),
        "hostname": (resolved_hostname, expected_hostname),
        "hostkeyalias": (host_key_alias, machine.host_key_alias),
        "user": (resolved_user, machine.user),
    }
    for name, (observed, expected) in required_matches.items():
        if observed != expected:
            raise SshResolutionError(
                f"ssh -G resolved unexpected {name}: {observed!r}, expected {expected!r}"
            )
    if resolved_port != endpoint.port:
        raise SshResolutionError("ssh -G resolved an unexpected port")
    if request_tty not in _FALSE_VALUES:
        raise SshResolutionError("machine-control SSH did not disable RequestTTY")
    if batch_mode not in _FALSE_VALUES:
        raise SshResolutionError("initial SSH master must remain interactive")
    if identities_only not in {"true", "yes"}:
        raise SshResolutionError(
            "SSH must use only explicitly configured identities"
        )
    expected_identity_file = os.fspath(
        default_tmuxgate_identity_file(machine.name)
    )
    identity_files = tuple(parsed.get("identityfile", ()))
    if identity_files != (expected_identity_file,):
        raise SshResolutionError(
            "SSH must use exactly the dedicated tmuxgate identity file"
        )
    if parsed.get("certificatefile"):
        raise SshResolutionError(
            "SSH profile must not add certificate files"
        )
    if canonicalize not in _FALSE_VALUES:
        raise SshResolutionError("SSH hostname canonicalization was not disabled")
    if permit_local not in _FALSE_VALUES:
        raise SshResolutionError("SSH PermitLocalCommand was not disabled")
    if remote_command is not None:
        raise SshResolutionError("SSH RemoteCommand was not disabled")
    if strict not in _SAFE_STRICT_HOST_KEY_CHECKING:
        raise SshResolutionError("SSH host-key checking is not ask/yes")

    user_known_hosts = _tokenized_option(parsed, "userknownhostsfile")
    global_known_hosts = _tokenized_option(parsed, "globalknownhostsfile")
    if not user_known_hosts or all(
        item.lower() == "none" or item == "/dev/null" for item in user_known_hosts
    ):
        raise SshResolutionError("SSH has no persistent user known-hosts file")
    host_key_evidence = host_key_collector(
        machine.host_key_alias,
        user_known_hosts,
        global_known_hosts,
    )
    if not isinstance(host_key_evidence, HostKeyEvidence):
        raise SshResolutionError("host-key collector returned an invalid result")
    if host_key_evidence.host_key_alias != machine.host_key_alias:
        raise SshResolutionError("host-key evidence alias does not match the machine")

    authentication_options = (
        ("publickey", "pubkeyauthentication"),
        ("password", "passwordauthentication"),
        ("keyboard-interactive", "kbdinteractiveauthentication"),
    )
    enabled_authentication = tuple(
        label
        for label, key in authentication_options
        if (_single(parsed, key, required=False) or "no").lower() not in _FALSE_VALUES
    )
    policy_sha256 = _canonical_sha256(_policy_document(machine, endpoint))
    return ResolvedSshEndpoint(
        machine_name=machine.name,
        endpoint_id=endpoint.id,
        required_context=endpoint.required_context,
        configured_address=expected_hostname,
        configured_port=endpoint.port,
        connect_timeout_seconds=machine.connect_timeout_seconds,
        ssh_profile=machine.ssh_profile,
        resolved_host=resolved_host,
        resolved_hostname=resolved_hostname,
        resolved_user=resolved_user,
        resolved_port=resolved_port,
        host_key_alias=host_key_alias,
        strict_host_key_checking=strict,
        user_known_hosts_files=user_known_hosts,
        global_known_hosts_files=global_known_hosts,
        host_key_algorithms=_single(parsed, "hostkeyalgorithms", required=False),
        host_key_evidence=host_key_evidence,
        proxy_jump=_optional_value(parsed, "proxyjump"),
        proxy_command=_optional_value(parsed, "proxycommand"),
        identity_agent=_optional_value(parsed, "identityagent"),
        identity_files=identity_files,
        enabled_authentication_methods=enabled_authentication,
        ssh_g_output_sha256=hashlib.sha256(raw_output).hexdigest(),
        ssh_policy_sha256=policy_sha256,
        ssh_g_argv=argv,
    )
