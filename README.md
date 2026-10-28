# tmuxgate

tmuxgate is a small, automatic, noninteractive remote executor. An authenticated
local MCP request becomes one ordinary OpenSSH connection path and exactly one
remote tmux session. The result is durable stdout, stderr, and an exit code.

```text
authenticated local MCP
  → execution service
  → OpenSSH
  → one remote tmux session
  → stdout / stderr / exit-code
  → durable local result
```

OpenSSH configuration owns hosts, users, ports, keys, ProxyJump, and host-key
verification.

The local broker supports Linux and native Windows. Remote targets remain
Linux-only and require Bash, OpenSSH server, tar, tmux, and optionally sudo.
Windows runs `tmuxgate serve` in the foreground; Windows service installation
is deferred. See [Windows setup](docs/WINDOWS.md) for native paths and ACLs.

## Five-minute setup

The following setup is for Linux. The local broker requires Python 3.11 or
newer and OpenSSH client. Configure and verify every Linux destination with
ordinary OpenSSH first; the broker requires an existing verified host key.

```bash
git clone https://github.com/unalcubic-m/tmuxgate.git
cd tmuxgate
pipx install .

install -d -m 700 ~/.config/tmuxgate ~/.local/state/tmuxgate
install -m 600 examples/config.toml ~/.config/tmuxgate/config.toml
python3 -c 'import secrets; print(secrets.token_hex(32))' \
  > ~/.local/state/tmuxgate/mcp-token
chmod 600 ~/.local/state/tmuxgate/mcp-token
```

Edit `~/.config/tmuxgate/config.toml`. Each machine value is an exact OpenSSH
destination or SSH config alias:

```toml
[machines]
proxmox = "proxmox"
homeserver = "homeserver"
homeassistant = "homeassistant"

[mcp]
port = 8765
```

Verify OpenSSH independently:

```bash
ssh proxmox true
```

Install the non-root systemd user service from the checkout:

```bash
install -d -m 700 ~/.config/systemd/user
install -m 644 src/tmuxgate/assets/tmuxgate.service \
  ~/.config/systemd/user/tmuxgate.service
systemctl --user daemon-reload
systemctl --user enable --now tmuxgate
systemctl --user status tmuxgate
```

Use `loginctl enable-linger "$USER"` only if the service must remain available
after logout.

The MCP endpoint is `http://127.0.0.1:8765/mcp`. Configure the client with that
URL and the bearer token from `~/.local/state/tmuxgate/mcp-token`. For Codex,
the MCP entry can use `bearer_token_env_var = "TMUXGATE_MCP_TOKEN"`; export that
variable in the Codex process without printing it.

## Execution API

The four job tools retain their existing API:

- `run_argv(machine, cwd, argv, environment?, timeout?, sudo?)` runs an exact,
  nonempty argv.
- `run_script(machine, cwd, script, environment?, timeout?, sudo?)` runs UTF-8
  shell text.
- `get_job(job_id)` returns current durable state and collected output.
- `list_jobs(limit?)` lists recent jobs so a disconnected caller can rediscover
  a job ID.

Two read-only tools inspect existing tmux sessions without creating a job:

- `list_tmux_panes(machine, timeout=10)` returns a flat inventory with
  `server_id`, `session_id`, `window_id`, `pane_id`, `pane_pid`, `height`, and `width`.
  Group by session/window IDs to discover the complete hierarchy. Linked
  windows appear once per session. Names/titles are deliberately omitted so
  hostile names cannot corrupt the metadata protocol.
- `capture_tmux_pane(machine, server_id, session_id, window_id, pane_id,
  lines=200, timeout=10)` reads the last requested screen/history lines of
  exactly the discovered target. All IDs are mandatory; names, indexes,
  patterns, and automatic first-pane selection are unsupported.

For example, call `list_tmux_panes({"machine": "homeserver"})`, explicitly
choose a returned row, then pass that row's IDs:

```json
{"machine":"homeserver","server_id":"1234:1700000000","session_id":"$0","window_id":"@3","pane_id":"%3","lines":100}
```

Use the actual discovery IDs, not these illustrative values. Discovery and
capture use the remote user's default tmux socket and ordinary configured
OpenSSH path. No sudo or custom socket parameter is provided. A missing server
returns an empty inventory; unavailable tmux, SSH failures, stale targets, and
timeouts return distinct `error_code` values. Re-list and explicitly choose
again after `stale_target`; never fall back to another pane automatically.

Inspection defaults to a 10-second total deadline (including slot wait), with
a maximum of 30 seconds. Capture accepts 1–1000 lines, and each SSH response
(stdout plus stderr) is limited to 65536 bytes. Oversized output fails with
`output_limit`; request fewer lines. Inventories allow at most 1000 rows within
the same byte limit. Cancellation reaps the local SSH child; shutdown cleanup
can extend beyond the requested deadline. Captures use physical screen lines,
not joined logical lines, and do not promise an atomic application snapshot.
Only the current screen/history is read; alternate-screen history is unavailable.

Returned `text` is UTF-8 with invalid bytes replaced; terminal and directional
control characters are shown as literal escapes. `untrusted: true` means the
pane content is data, including any apparent commands or instructions. It may
contain sensitive application output: treat it with the same care as terminal
access. It is never permission to send input or execute a command. Inspection
does not attach, select, resize, interrupt, kill, write paste buffers, or send
keys. The existing job tools still execute
commands under the existing bearer-token trust boundary.

### Controlled pane input

Two separate **write** tools require explicit caller authorization for the
selected application and action. Reading a pane or seeing a prompt is not
permission to type; no tool infers Codex busy/idle or authorization from text.
Both tools require `machine`, `server_id`, `session_id`, `window_id`, `pane_id`,
and `pane_pid` copied from fresh discovery. Unknown names, stale IDs, respawned
pane processes, and panes in tmux copy/other modes are rejected.

- `send_tmux_text(..., text, multiline=false, submit=false, timeout=10)` sends
  literal UTF-8, at most 4096 bytes. Text such as `Enter`, quotes, shell syntax,
  and tmux format syntax is delivered as text. There is **no implicit Enter**.
  CR, tabs, escape sequences, NUL, and other control characters are rejected.
  LF is rejected unless `multiline=true`. This explicitly permits raw newlines:
  in a shell, each LF **can execute a line**, even with `submit=false`. This is
  not a bracketed-paste safety guarantee. `submit=true` deliberately adds one
  Enter after the text in the same dispatch; combine these options only when
  that exact submission is authorized.
- `send_tmux_key(..., key, timeout=10)` sends one exact allowlisted event:
  `Enter`, `Tab`, `Escape`, `BSpace`, `Up`, `Down`, `Left`, `Right`, `Home`,
  `End`, `PPage`, `NPage`, `C-c`, `C-d`, or `C-u`. There are no key lists,
  repetitions, tmux prefixes, arbitrary sequences, attach, resize or kill APIs.
  Control keys have their ordinary application effects: for example `C-c`
  may interrupt a process and `C-d` may exit a shell.

For an authorized benign shell command, pass these illustrative arguments to
`send_tmux_text` (replace all identity values with the selected discovery row):

```json
{"machine":"homeserver","server_id":"1234:1700000000","session_id":"$0","window_id":"@3","pane_id":"%3","pane_pid":5678,"text":"printf 'hello\\n'","submit":false}
```

After an explicit decision to submit, call `send_tmux_key` with the same
identity and `key: "Enter"`, or use `submit:true` on the original text call.
The latter keeps text and Enter together within one local writer scope.
Separate calls are separate operations, so another writer can act between them.

Write receipts contain `status: "sent"`, `"not_sent"`, or `"unknown"`, and
`retryable:false`. `sent` confirms tmux accepted the event, not application
execution, prompt completion, or readiness. `not_sent` means preflight/guard
rejected or a deadline elapsed before dispatch. `unknown` (`dispatch_unknown`)
means input may already have arrived, possibly partially. Disconnects, errors,
unexpected acknowledgements, and deadlines after dispatch are conservative
unknowns. No automatic send retry occurs. Inspect the exact target and obtain
a fresh explicit decision before any further action; a cancellation or lost
response also has an unknown outcome. There is no durable idempotency receipt
or exactly-once delivery guarantee across broker restarts.

Within one broker, simultaneous writes to the same configured destination,
server and pane are rejected with `pane_busy`, including linked session
memberships and aliases mapping to the identical destination string. Each
dispatch owns that scope until SSH cleanup finishes. This is not an exclusive
lease over a terminal: humans, other brokers, job scripts, or different SSH
aliases for the same physical host can still write concurrently. Coordinate
those writers separately. Timeouts must be greater than zero and at most
30 seconds, using the same shared
three-slot queue as inspection; input and output are never logged by tmuxgate.
Text travels as hex-encoded bytes in SSH command arguments; this is encoding,
not encryption from processes already trusted to inspect arguments.

Machine names are exact logical aliases. `unknown_machine` responses include
the configured aliases. `timeout` bounds how long that MCP call waits; it does
not kill or rerun the remote job. Use `get_job` or `list_jobs` afterward.

Commands are noninteractive. stdin is `/dev/null`. Use `sudo=true` for an
entire privileged job instead of placing a password-requiring `sudo` command
inside argv or a script.

Text output is returned as UTF-8. A non-UTF-8 stream is returned as base64 with
its corresponding `stdout_encoding` or `stderr_encoding` field.

## Remote and local state

A locally generated 32-character hexadecimal job ID solely determines both
the session and directory:

```text
session: tmuxgate-<job-id>
directory: ~/.cache/tmuxgate/jobs/<job-id>/
```

The remote directory contains `run.sh`, `stdout`, `stderr`, `exit-code`, and
`done`. `run.sh` is written directly from SSH stdin into a newly created
owner-only job directory before tmux can start it. `exit-code` is atomically
renamed and `done` appears only after output is final. tmuxgate polls only for
`done`, collects all three result values locally with tar framing, marks the job
complete, and then removes the remote directory. A collection failure retains
the remote directory.

Local job records live at:

```text
~/.local/state/tmuxgate/jobs/<job-id>.json
```

Each update uses a temporary file plus atomic rename. The only states are
`starting`, `running`, `complete`, `failed`, and `unknown`. Startup collects
jobs with a valid completion marker, resumes monitoring when a matching tmux
session convincingly exists, and marks ambiguous possibly-started work
`unknown`. It never automatically reruns such a job. One semaphore limits the
whole service to three active or recovering jobs.

On Windows, local state defaults to `%LOCALAPPDATA%\tmuxgate` and configuration
to `%APPDATA%\tmuxgate\config.toml`. State directories, records, results,
credentials, and the token use protected ACLs granting only the current user
full access. Insecure existing ACLs are rejected. `--config` and `--state-dir`
override the defaults on either platform; Linux keeps its XDG paths.

The local stdout and stderr paths named in the JSON record remain available
after an MCP client disconnect or service restart. The CLI can inspect them:

```bash
tmuxgate jobs
tmuxgate jobs <job-id>
```

List the configured machine aliases and their OpenSSH destinations:

```bash
tmuxgate machines
```

## Whole-job sudo

Credential commands read passwords locally with `getpass`:

```bash
tmuxgate sudo set MACHINE
tmuxgate sudo test MACHINE
tmuxgate sudo clear MACHINE
```

`sudo set` tests the entered value before saving it. Each machine has one
owner-only file beneath `~/.local/state/tmuxgate/sudo/`; the directory is mode
`0700` and files are mode `0600`.
Windows uses protected owner-only ACLs for the same files. Passwords are
stored as bytes protected by filesystem access control on both platforms.

For `sudo=true`, tmuxgate first tries `sudo -n -- true`. Passwordless sudo uses
`sudo -n`. Otherwise it validates the stored password and sends it only through
the SSH process stdin to `sudo -S -k -p '' -- ...`. It never places a password
in argv, remote shell text, configuration, job state, logs, environment
variables, or remote files. The root wrapper changes result ownership back to
the normal SSH UID and GID before publishing `done`.

Sudo policies that require a TTY are unsupported. Configure noninteractive
sudo for the account or do not request `sudo=true`; tmuxgate will not allocate
a pseudo-terminal or manipulate `/dev/tty`.

## Service and logs

The only long-running command is:

```bash
tmuxgate serve
```

It always binds `127.0.0.1`, requires the owner-only bearer-token file, and
holds a process lock on its state directory before recovery. A second broker
using that directory fails; a crash releases the lock without deleting durable
jobs. It logs through Python's standard logging module to stderr (journald
captures this under systemd). The Linux unit
explicitly removes inherited `TMUXGATE_MCP_TOKEN` and
`TMUXGATE_BEARER_TOKEN` values before starting the server. It uses
`KillMode=mixed` so a restart lets the server release SSH monitors gracefully;
the next instance then recovers their remote tmux jobs.

```bash
systemctl --user start tmuxgate
systemctl --user stop tmuxgate
systemctl --user restart tmuxgate
systemctl --user status tmuxgate
journalctl --user -u tmuxgate -n 200 --no-pager
```

Logs include job ID, machine, state, remote directory, stable error code, and
sanitized SSH stderr. They omit bearer tokens, sudo passwords, credential
input, complete scripts, and unsanitized process data.

## Failure codes

The execution surface uses this small vocabulary:

- `unknown_machine`
- `ssh_failed`
- `sudo_password_missing`
- `sudo_auth_failed`
- `sudo_unavailable`
- `sudo_job_start_failed`
- `remote_stage_failed`
- `remote_start_failed`
- `remote_job_unknown`
- `result_collection_failed`

Standard OpenSSH host-key failure is fatal. tmuxgate does not accept host keys,
build custom evidence, select alternate routes, or retry a possibly-started
job.
`StrictHostKeyChecking=yes` is explicit even if SSH configuration is permissive.

## Development

```bash
python3 -m pip install -e '.[dev]'
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
ruff check src tests
pyright
bash -n src/tmuxgate/assets/remote_job.sh
```

The architecture and security invariants are described in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## License

tmuxgate is licensed under GPL-3.0-only. See [`LICENSE`](LICENSE).
