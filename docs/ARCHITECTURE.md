# Architecture

tmuxgate implements one job execution path:

```text
load config
start authenticated loopback MCP
receive request
acquire one of three slots
stage run.sh directly over SSH stdin
start one remote tmux session
optionally start it through whole-job sudo
poll done
collect stdout, stderr, and exit code
save the durable local result
clean the remote directory
```

## Modules

- `config.py` accepts only `[machines]` and optional `[mcp].port` TOML data.
  Machine values are passed to ordinary OpenSSH as exact destinations.
- `jobs.py` stores one atomic JSON record per job and local result paths.
- `credentials.py` stores one mode-`0600` sudo password file per machine under
  a mode-`0700` directory.
- `ssh.py` is the sole OpenSSH subprocess helper. It disables terminal
  allocation and interactive SSH authentication while leaving OpenSSH host,
  key, ProxyJump, and known-host policy intact.
- `executor.py` generates and stages `run.sh`, starts remote tmux, handles
  whole-job sudo, polls, collects, and cleans.
- `service.py` owns startup recovery, background task lifetime, and the single
  `asyncio.Semaphore(3)`.
- `mcp.py` defines `run_argv`, `run_script`, `get_job`, `list_jobs`,
  `list_tmux_panes`, `capture_tmux_pane`, `send_tmux_text`, and `send_tmux_key`
  plus the bearer guard.
- `panes.py` inspects existing panes directly over SSH without creating jobs,
  scripts, remote directories, sessions, or local durable records.
- `pane_input.py` validates bounded literal text or one allowlisted key and
  dispatches it behind an immediate tmux-side identity guard, without retries.
- `cli.py` defines only `serve`, `sudo set/test/clear`, and local `jobs`
  inspection.
- `assets/remote_job.sh` is the complete remote result wrapper.
- `storage.py` supplies protected files, durable atomic writes, and a broker
  process lock. `windows_storage.py` implements its native Windows boundary
  using pywin32; Linux retains POSIX ownership, modes, and directory fsync.

## Trust boundaries

The MCP listener binds only `127.0.0.1`. An ASGI middleware compares exactly
one Authorization header with the owner-only local bearer token before MCP
parsing. Tokens and scripts are never logged.

Callers select a configured logical alias, never an endpoint or SSH option.
The configured value is an argv element after OpenSSH's `--`. Every remote
shell command is built with fixed shell text and separately shell-quoted
positional arguments. Request cwd, environment values, and argv are quoted
into `run.sh`; passwords are not.

OpenSSH is authoritative for hostnames, usernames, ports, identity files,
ProxyJump, and known-host verification. A host-key verification error is fatal.
The subprocess explicitly sets `StrictHostKeyChecking=yes`, `BatchMode=yes`,
and no TTY. The local broker can run on Windows; remote command construction,
paths, Bash wrapper, tmux, tar, UID/GID handling, and sudo remain Linux-only.

Remote command output is untrusted data. Local result paths are derived only
from a random hexadecimal job ID. Non-UTF-8 MCP output is base64 encoded.

### Existing-pane read boundary

Read-only inspection shares the configured alias lookup, bearer guard, sole
OpenSSH helper, and three-slot semaphore with jobs. Its total timeout includes
waiting for a slot; no background durable task or retry is created. SSH streams
are read concurrently under a combined 64 KiB budget, with overflow terminating
and reaping only the local SSH child. Existing job output collection is unchanged.

Discovery runs `tmux -u list-panes -a` with a fixed numeric-only format. It
never interpolates a session name, window name, title, or application output.
IDs are strictly validated before use. `server_id` combines tmux server PID and
start time to detect ordinary server restarts; IDs are not eternal capabilities
or a cryptographic generation identity (PID/time reuse remains an OS limitation).
Linked windows retain every session membership. Duplicate rows, inconsistent
server identities, malformed metadata, and excessive inventories fail closed.

Capture requires all four IDs, re-lists to check exact membership, then uses one
tmux command queue with server/window/pane metadata before and after
`capture-pane -p`. A final inventory check verifies membership again before any
text is returned. Any mismatch discards the captured output; it never selects
the first or active pane as a fallback. Concurrent application output and
topology changes are not locked; this is an observation, not an atomic snapshot.
tmux's `-p` writes stdout rather than creating a paste buffer. No input, attach,
selection, interrupt, resize, kill, cleanup, or sudo operation is involved.
Only the remote user's default socket is supported.

Pane text is not logged or persisted. UTF-8 is decoded with replacement and
terminal/bidi controls are escaped before returning explicitly untrusted text.
It must never be interpreted as instructions or permission. The same bearer
token grants both existing command execution and inspection; this release does
not introduce per-tool authorization or a restricted read-only principal.
See the [tmux manual](https://man.openbsd.org/tmux) for format IDs and capture
semantics, and the README for the bounded inspection API.

### Existing-pane write boundary

Input requires the same explicit IDs plus discovery's `pane_pid` to detect
ordinary pane respawns. The service validates all values before SSH, reserves
an in-memory writer scope keyed by configured destination/server/pane (not
session membership), and rejects a concurrent caller instead of queueing it.
The existing three-slot semaphore and positive, at most 30-second deadline apply. Identical
destination strings share the scope; different aliases that resolve to the
same host do not. No distributed lock or lock against a human terminal exists.
Text plus optional final Enter occupy one dispatch; separate tool calls have
no transaction/lease across them.

A fresh inventory validates exact membership and process ID. A single tmux
`if-shell -F` then compares server PID/start time, exact session/window/pane IDs,
pane process ID, liveness and absence of a tmux mode immediately before the
send in the same server command queue. `-F` evaluates a fixed format, not a
shell command. Any false guard takes only the rejection branch. Input is never
redirected to an active, first, named or replacement pane. OS PID/start-time
reuse is not a cryptographic generation identity; externally changing tmux
topology or custom hooks remains outside the broker's exclusive control.

Literal text is UTF-8 encoded under a 4096-byte limit and converted to numeric
hex arguments for `send-keys -H`. No user text is parsed as shell or tmux code.
Controls are rejected except LF with explicit `multiline=true`; raw LF may
execute shell lines, independently of the explicit optional final Enter.
Key events come from a fixed allowlist and cannot inject options or sequences.
No clipboard/paste buffer, remote script/file, attach, select, resize, or
session-kill operation is involved in the input API.

Once mutation SSH starts, any lost/invalid acknowledgement, nonzero exit,
output overflow, exception or timeout is `unknown`, never safe-to-retry.
A guard rejection or preflight failure is `not_sent`; a clean fixed receipt
is `sent`, confirming tmux command acceptance only. Local cancellation reaps
SSH but cannot retract already sent bytes. No automatic replay, rollback,
durable input queue or exactly-once claim is provided. A cancelled MCP caller
or broker crash must treat an absent receipt as unknown too. Input and pane
text are not persisted or logged; numeric encoding remains visible to trusted
processes that can inspect argv. The bearer guard is unchanged and confers no
per-tool roles: caller authorization for the precise target/action is still
required, and terminal output never grants it or proves Codex readiness.

## Job identity and storage

`secrets.token_hex(16)` produces the 32-character job ID. It exclusively
derives:

```text
~/.cache/tmuxgate/jobs/<job-id>/
tmuxgate-<job-id>
~/.local/state/tmuxgate/jobs/<job-id>.json
~/.local/state/tmuxgate/results/<job-id>/stdout
~/.local/state/tmuxgate/results/<job-id>/stderr
```

The JSON record contains only:

```text
job_id machine sudo state created_at updated_at
remote_directory remote_session exit_code
error_code error_detail stdout_path stderr_path
```

The only states are `starting`, `running`, `complete`, `failed`, and `unknown`.
The `Job` dataclass is the field authority. Initial publication is atomic and
exclusive; every update writes a mode-`0600` temporary file, fsyncs it,
atomically renames it, and fsyncs the jobs directory. Records with extra fields
or non-derived paths are rejected.

On Windows, configuration defaults to `%APPDATA%\tmuxgate\config.toml` and
state to `%LOCALAPPDATA%\tmuxgate`; explicit CLI paths override both platforms'
defaults. Windows requires a local fixed filesystem with persistent ACLs.
Files and directories are created with a protected DACL granting the current
token user SID full control, and that SID must own them. Existing broad,
inherited, null, or unfamiliar ACLs are rejected rather than repaired. Secrets,
job records, and result reads validate the same open handle's owner, DACL,
type, reparse attributes, and single-link count. All reparse points, including
ancestor junctions, are rejected. Ancestor handles deny delete sharing during
operations so they cannot be replaced while paths are in use. File readers
allow delete sharing so atomic replacement can proceed while an old handle is
being read. Same-user processes and privileged OS administrators are trusted.

Windows writes a private same-directory temporary file, flushes its contents
with `FlushFileBuffers`, closes it, and publishes with
`MoveFileEx(MOVEFILE_WRITE_THROUGH)`; initial publication omits
`MOVEFILE_REPLACE_EXISTING`. Errors propagate; no cross-volume copy or ignored
directory flush substitutes for durability. Linux continues to fsync contents,
publish exclusively with a hard link or replace by rename, and fsync the
containing directory. Result and credential publication now share these
durability rules with job records. As with POSIX fsync, storage hardware and
filesystem behavior bound crash guarantees.

## Remote lifecycle

The service writes `starting` before any SSH action and acquires one semaphore
slot before staging. SSH stdin writes `run.sh` directly into a new remote
directory under umask `077`, then changes it to mode `0700`. The directory is
created exclusively, and tmux is not started until the complete staging SSH
command succeeds, so an interrupted write cannot execute. This direct path is
permission-correct and easier to inspect than wrapping one file in tar.

The start operation invokes exactly one detached session:

```text
tmux new-session -d -s tmuxgate-<job-id> /bin/bash <job-dir>/run.sh ...
```

`run.sh` applies cwd and environment, executes exact argv or an appended UTF-8
script with stdin redirected from `/dev/null`, and redirects stdout and stderr
to separate files. It publishes `exit-code` by rename. It creates and renames
`done` only after every result file is final.

Normal monitoring tests only for `done`. Once present, a single tar stream
collects stdout, stderr, and exit-code. tmuxgate atomically writes both local
streams and only then changes JSON state to `complete`. Remote cleanup happens
after that local collection. A collection failure changes state to `failed`
with `result_collection_failed` and deliberately retains the remote directory.

MCP cancellation does not cancel the background execution task. A tool timeout
ends only that wait; it does not kill, retry, or detach the remote job because
remote tmux already owns persistence.

## Recovery and no-rerun invariant

Startup loads only `starting` and `running` records. For each record, while
holding one of the same three semaphore slots, it:

1. checks `done` and collects if present;
2. otherwise checks the exact derived tmux session;
3. resumes polling if the session convincingly exists;
4. otherwise stores `unknown`.

It never restages or restarts an existing record. This intentionally sacrifices
automatic recovery of a job that provably never started in order to prevent a
duplicate execution when evidence is ambiguous.

Service shutdown cancels only local SSH polling processes. It does not contact,
kill, or clean the remote job; the durable `starting` or `running` record is
left for conservative startup recovery.
Subprocess creation is shielded so shutdown owns and reaps even a child whose
native creation is still in flight. Cancellation terminates and drains the
local SSH process, escalating to kill after a bounded wait; it never sends a
remote job cancellation command.

## Whole-job sudo

Sudo is an explicit Boolean request property. tmuxgate never scans command text
for sudo and never detects or answers prompts.

One sudo-access function tests an explicitly entered CLI password, or first runs
`sudo -n -- true` and then loads and validates the machine's owner-only stored
credential with `sudo -S -k -p '' -- true`. The same failure classifier handles
SSH disconnects, unavailable sudo, and unsupported `requiretty` policies. A
password-based start reads the credential again. Password bytes are passed only
as SSH stdin and the bytearray is overwritten and cleared immediately after
each subprocess completes.
On Windows these stored bytes are protected by native owner-only ACLs instead
of POSIX modes; they are not stored in environment variables or encrypted with
a different credential backend.

The remote normal user's UID and GID are obtained before sudo and passed as
numeric wrapper arguments. The root `run.sh` changes stdout, stderr, exit-code,
and the temporary completion marker back to that UID/GID. Only then does it
rename the completion marker to `done`. This lets the ordinary SSH user collect
and clean the result.

`requiretty` policies are unsupported because tmuxgate never requests a TTY.
Lower executor operations return a stable code and plain detail. Execution and
recovery add machine and job ID exactly once; credential CLI errors have no fake
job context. All error details omit the password.

## Service lifecycle and logging

`tmuxgate serve` constructs the store, credentials, executor, service, MCP
surface, and uvicorn listener directly. The packaged non-root systemd user unit
uses `Restart=on-failure`; systemd owns restart and journald owns logs. The unit
also removes client-side bearer variables inherited from the user manager; the
server reads its credential only from the owner-only token file. `KillMode=mixed`
signals the server before its SSH monitor children, so graceful shutdown can
leave running remote tmux jobs recoverable instead of misclassifying a killed
local monitor as a remote failure.

Before recovery, `serve` holds an exclusive `broker.lock` in its private state
directory for the process lifetime. POSIX uses a nonblocking flock; Windows
uses a validated native file handle with sharing disabled. A second broker
fails before recovery even if configured for a different port. Exit or crash
releases the lock without unlinking its name or changing job state. Native
Windows initially supports foreground `serve` only; no service installation,
SCM integration, or restart policy is provided. Ctrl+C follows the same local
shutdown/recovery boundary. Standard asyncio's Windows Proactor loop supports
the subprocess pipes; the broker does not select a Selector loop.

Win32 design references: [CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew),
[GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[persistent ACLs](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw),
and [MoveFileEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).

Logging uses only the standard library. Records may contain job ID, machine,
state, derived remote directory, error code, and bounded control-character-
sanitized SSH stderr. Bearer tokens, passwords, credential input, complete
scripts, and raw process environments are prohibited.
