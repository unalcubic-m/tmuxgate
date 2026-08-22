# Architecture

tmuxgate implements one execution path:

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
- `mcp.py` defines exactly `run_argv`, `run_script`, `get_job`, and `list_jobs`
  plus the bearer guard.
- `cli.py` defines only `serve`, `sudo set/test/clear`, and local `jobs`
  inspection.
- `assets/remote_job.sh` is the complete remote result wrapper.

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

Remote command output is untrusted data. Local result paths are derived only
from a random hexadecimal job ID. Non-UTF-8 MCP output is base64 encoded.

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

Logging uses only the standard library. Records may contain job ID, machine,
state, derived remote directory, error code, and bounded control-character-
sanitized SSH stderr. Bearer tokens, passwords, credential input, complete
scripts, and raw process environments are prohibited.
