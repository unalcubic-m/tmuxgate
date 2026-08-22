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

## Five-minute setup

Requirements are Python 3.11 or newer, `ssh`, `tar`, and `tmux` on each remote
machine. Configure and verify every destination with ordinary OpenSSH first.

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

Only four MCP tools exist:

- `run_argv(machine, cwd, argv, environment?, timeout?, sudo?)` runs an exact,
  nonempty argv.
- `run_script(machine, cwd, script, environment?, timeout?, sudo?)` runs UTF-8
  shell text.
- `get_job(job_id)` returns current durable state and collected output.
- `list_jobs(limit?)` lists recent jobs so a disconnected caller can rediscover
  a job ID.

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
logs through Python's standard logging module for journald capture. The unit
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
