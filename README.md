# tmuxgate

[![CI](https://github.com/unalcubic-m/tmuxgate/actions/workflows/ci.yml/badge.svg)](https://github.com/unalcubic-m/tmuxgate/actions/workflows/ci.yml)

`tmuxgate` is one owner-controlled foreground application for running reviewed
commands in isolated tmux sessions on configured remote Linux machines. It
starts the Unix-socket execution broker, an authenticated Codex-compatible MCP
server, and a terminal dashboard together. The application that owns the
controlling terminal also owns route selection, SSH policy and authentication,
approvals, interactive recovery, result collection, and cleanup.

Codex connects to the already-running application over authenticated
Streamable HTTP on loopback. There is no `tmuxgate-mcp` command, helper, or
second server process, and MCP never uses standard input or `/dev/tty` as its
transport.

> [!WARNING]
> tmuxgate is pre-1.0 security-sensitive software. Review the threat model,
> configuration, bearer-token handling, and approval mode before using it on
> important systems. The default `approval_mode = "disabled"` does not ask for
> confirmation after an authenticated request passes broker validation. Set it
> to `"always"` when every request should require an explicit decision in the
> tmuxgate terminal.

## Why tmuxgate

Automation tools often need to run a bounded command on a remote host without
being given a reusable interactive SSH shell. tmuxgate narrows that workflow:

- MCP callers name a configured machine; they cannot supply an address, SSH
  option, identity file, proxy, or host-key policy.
- The broker builds and binds the complete route, `ssh -G`, host-key, fallback,
  working-directory, environment, argv, and script plan before execution.
- Every request gets a dedicated remote tmux session and a private local
  viewer. Existing remote sessions are not reused or modified.
- stdout, stderr, exit status, job state, and checksums are collected through a
  durable, fail-closed lifecycle.
- Password and passphrase prompts can be presented in the application's
  controlling terminal without tmuxgate reading or storing the entered bytes.

```text
Codex -> bearer-authenticated loopback HTTP -> embedded MCP server
                                                    |
                                         protected Unix socket
                                                    |
                                             local broker
                                           /              \
                              approval/auth terminal   broker-owned SSH
                                           \              /
                                            verified spool
```

The MCP layer deliberately uses the existing Unix-socket client protocol. It
does not bypass broker validation, approval, durable state, route planning,
SSH/tmux isolation, result verification, or cleanup rules.

## Requirements

- Linux with Unix-domain sockets and peer credentials
- Python 3.11+
- OpenSSH client tools (`ssh`, `ssh-keygen`)
- tmux on the local and remote machines
- Bash and standard archive/core utilities on the remote machines
- `ip`; NetworkManager's `nmcli` is also used when collecting configured
  home-network identity evidence

The package pins the tested official Python MCP SDK (`mcp==2.0.0`) and Uvicorn
(`uvicorn==0.52.0`), which provide the embedded Streamable HTTP stack.

## Install

The recommended user install is the repository's root installer:

```bash
git clone https://github.com/unalcubic-m/tmuxgate.git
cd tmuxgate
./install.sh
```

Run it as your normal user, without `sudo`. It creates an isolated, versioned
virtual environment below
`$XDG_DATA_HOME/tmuxgate/releases` (normally
`~/.local/share/tmuxgate/releases`), verifies the package and its MCP/Uvicorn
dependencies, then atomically points `current` and
`~/.local/bin/tmuxgate` at the verified release. It recognizes and replaces
the earlier checkout-backed `bin/tmuxgate` symlink as well as a launcher from a
previous managed install. It refuses to overwrite an unrelated launcher
unless `--replace-existing` is given.

The installer leaves the existing tmuxgate configuration, durable job state,
spool, and MCP token unchanged. If no token exists yet, it creates one using
the same owner-only runtime code as the application; that newly created
credential remains valid even if a later installation step fails. A protected
configuration file must already exist. The installer also registers the
configured Streamable HTTP endpoint with Codex, hardens an owner-controlled
Codex home directory to mode `0700`, sets
`tool_timeout_sec = 604900`, and installs a managed Bash token loader. The
loader contains the token-file path and validation logic, not the token. Open
a new Bash shell and restart Codex after installation so Codex inherits
`TMUXGATE_MCP_TOKEN` and reloads its MCP configuration.

No Node.js installation is required. tmuxgate and its installer use Python;
the official Python MCP SDK and Uvicorn are installed inside the isolated
environment.

The installer never starts tmuxgate in the background. After it completes,
run `tmuxgate` in the trusted terminal that should own the dashboard,
approvals, and interactive authentication. If the existing configuration has
`approval_mode = "disabled"`, installation stops before Codex or launcher
changes. Either change the file-based policy to `"always"`, or review the risk
and explicitly rerun with `--allow-disabled-approvals`; possession of the
bearer token then permits execution without a per-request terminal decision.

Existing Codex or shell-profile files are backed up with owner-only
permissions below `$XDG_DATA_HOME/tmuxgate/backups` before managed changes.
An incomplete install restores an installer-owned previous launcher, current
release, Codex configuration, and shell profiles without overwriting a
concurrent edit. A release that may already have been observed by a process is
retained instead of being deleted. A conflicting Codex registration named
`tmuxgate` is refused unless `--replace-codex` is explicitly given. Other
useful options are `--no-codex`, `--no-shell-integration`, and
`--allow-disabled-approvals`; run `./install.sh --help` for the complete
interface.

For a development-only environment, install directly into a checkout-local
virtual environment instead:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
tmuxgate --version
```

For development, the CLI can run directly from the checkout:

```bash
PYTHONPATH=src python3 -m tmuxgate --help
```

## Configure

tmuxgate reads an owner-only TOML file from
`$XDG_CONFIG_HOME/tmuxgate/config.toml`, falling back to
`~/.config/tmuxgate/config.toml`. Configuration remains file-based: the
dashboard and `tmuxgate config` commands may validate and atomically replace
that file, but the UI is not required to configure or run the service. Changes
take effect after tmuxgate restarts.

Start from the documented example, then replace every example alias, address,
user, and SSH profile with your own values:

```bash
install -d -m 700 ~/.config/tmuxgate
install -m 600 examples/config.toml ~/.config/tmuxgate/config.toml
tmuxgate config edit
tmuxgate config check
```

The addresses in [examples/config.toml](examples/config.toml) are reserved for
documentation and are intentionally not deployable values. Do not commit your
real configuration, host keys, fingerprints, machine inventory, or MCP token.

Configuration version 2 adds the MCP listener:

```toml
version = 2

[mcp]
host = "127.0.0.1"
port = 8765
```

Only the literal IPv4 loopback address is accepted. Existing version-1 files
remain readable and receive these MCP defaults. The next structured
configuration write (such as `set-broker`, `add-machine`, `remove-machine`,
`enable-machine`, `disable-machine`, or `enroll-home`) publishes the complete
file as version 2. `config edit` captures the parsed configuration and exact
source bytes from one secure open, rejects any concurrent byte-level change,
and fsyncs an owned private copy of the validated editor output before atomic
publication. It does not itself upgrade the schema version.

Structured configuration commands remain available:

```bash
tmuxgate config list
tmuxgate config add-machine
tmuxgate config remove-machine MACHINE
tmuxgate config disable-machine MACHINE
tmuxgate config enable-machine MACHINE
tmuxgate config enroll-home
tmuxgate config set-broker --approval-mode always
```

## Start tmuxgate and connect Codex

Start the unified application in a trusted interactive terminal:

```bash
tmuxgate
```

This command stays in the foreground and starts the broker, MCP listener, and
dashboard as one lifecycle. `tmuxgate dashboard` is an equivalent explicit
form. `tmuxgate broker` is a deprecated compatibility alias for the same
unified application. Stop it from the dashboard or with `Ctrl-C`; do not start
a separate MCP process.

The recommended `./install.sh` workflow has already registered this endpoint
with Codex and installed the token loader. Start tmuxgate in one terminal,
then open a new Bash shell and restart Codex. The application must remain in
its controlling terminal; the installer does not create a background service.

On first startup, or during the recommended installation, tmuxgate creates a
64-character bearer token in the selected owner-only state directory, normally
`~/.local/state/tmuxgate/mcp-token`, with mode `0600`. Startup prints the exact
token-file path after all listeners are ready, but never its contents. Leave
tmuxgate running. If the installer was run with `--no-codex`, export the token
in the environment that will launch Codex and register the Streamable HTTP
endpoint manually:

```bash
TMUXGATE_STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/tmuxgate"
export TMUXGATE_MCP_TOKEN="$(<"$TMUXGATE_STATE_DIR/mcp-token")"

codex mcp add tmuxgate \
  --url http://127.0.0.1:8765/mcp \
  --bearer-token-env-var TMUXGATE_MCP_TOKEN
```

With only `--no-shell-integration`, Codex is already registered; perform just
the token export before launching it.

If you chose another MCP port or state directory, use the values and token path
reported by tmuxgate. Codex must inherit `TMUXGATE_MCP_TOKEN` on every launch.
The installer adds the long tool timeout automatically. For a manual
registration, add it to the generated `~/.codex/config.toml` entry; the
complete entry is:

```toml
[mcp_servers.tmuxgate]
url = "http://127.0.0.1:8765/mcp"
bearer_token_env_var = "TMUXGATE_MCP_TOKEN"
tool_timeout_sec = 604900
```

The long tool timeout allows a request at tmuxgate's seven-day maximum plus
protocol overhead. You may set a shorter policy, but an MCP timeout or Codex
disconnect does not cancel an already approved job. Use `list_jobs` and
`read_verified_result` to find its durable outcome. Restart Codex after adding
or changing the server registration, and restart both programs after rotating
the token.

## MCP tools

The embedded server exposes five typed tools:

- `list_machines()` returns logical aliases, descriptions, and enabled status
  only.
- `run_argv(machine, cwd, argv, purpose, environment?, timeout_seconds?)`
  submits exact structured argv and waits for the broker result.
- `run_script(machine, cwd, purpose, script?, script_base64?, environment?,
  timeout_seconds?)` requires exactly one UTF-8 script or canonical base64 byte
  payload and waits for the broker result.
- `list_jobs(states?, limit?, cursor?)` returns sanitized durable records with
  bounded, opaque-cursor pagination.
- `read_verified_result(request_id, stream, offset?, limit?)` reads `stdout` or
  `stderr` only from a checksummed local spool that durable state marks as
  verified.

Execution results include the request ID, transport status, remote exit status,
byte lengths, and SHA-256 digests. Streams of at most 64 KiB are returned inline
as base64. Larger streams are marked truncated and must be read in chunks; the
default chunk is 64 KiB and the maximum is 1 MiB. Result reads also return byte
offsets, EOF, the complete stream digest, and the bound manifest digest. The
broker hashes only the selected stream with a fixed-size buffer, so a small
range request does not load both complete result streams into memory. Separate
bounded execution and control worker pools keep long command waits from
starving job and result queries. The broker reserves matching client-session
capacity for the control pool, so saturated execution calls cannot consume the
control path at the Unix-socket boundary either.

The former public `tmuxgate exec` and `tmuxgate script` commands have been
removed. Their structured request and exact-byte client functionality remains
internal to the MCP adapter and tests. `tmuxgate jobs`, `attach`, `collect`,
`recover`, configuration commands, and fail-closed administrative surfaces
remain available.

### Migrating from the earlier CLI workflow

1. Upgrade/install the package so the MCP dependency is present.
2. Keep an existing version-1 configuration as-is, or change it to version 2
   and add `[mcp]` when a nondefault port is required.
3. Start `tmuxgate` instead of a broker-only process; the deprecated
   `tmuxgate broker` spelling is temporary compatibility only.
4. Remove any stdio or `tmuxgate-mcp` Codex registration and add the
   authenticated loopback URL shown above.
5. Replace uses of public `tmuxgate exec`/`script` with `run_argv`/`run_script`.
   Existing administrative command invocations do not need to change.

When approval is set to `always`, tmuxgate shows a compact decision card in its
controlling terminal. Enter `y`/`yes`/`approve` (or press Enter) to approve,
`n`/`no`/`deny` to deny, `c` to inspect the exact code, or `d` to inspect the
complete technical evidence. Dashboard input, MCP data, Unix-socket data, and
process stdin cannot answer the prompt. The dashboard does not hold the
terminal while idle, allowing approvals, SSH authentication, and automatic
secret-prompt attachments to use the same terminal safely.

The plain screen is implemented behind a presentation-independent operator
interface. Execution, SSH-retry, fallback, and machine-disable prompts carry
their complete internal request/connection bindings through an exactly-once
FIFO decision queue; broker and executor workers do not parse terminal text.
Closing or failing the interface denies all unresolved prompts. This is an
internal architecture migration only: the visible line-oriented interface and
`/dev/tty` trust boundary remain the defaults, and no Textual/full-screen TUI
is included yet.

If initial OpenSSH master setup exits, tmuxgate leaves OpenSSH's diagnostic in
that controlling terminal, reports its exit status without copying terminal
output into MCP or durable state, and offers at most one exact broker-terminal
retry for each attempted approved endpoint before any remote command starts.
The retry recollects local network evidence,
re-resolves SSH policy, and proceeds only if the approved machine, ordered
candidate eligibility, eligible endpoint order, and complete resolved SSH
identities are unchanged. Volatile observation bytes may produce a new
snapshot digest without invalidating those semantics. The retry is never
automatic; a semantic change requires a fresh request and approval.
The dedicated per-machine key is the only effective identity file permitted,
and it is used with `IdentitiesOnly=yes`, so unrelated agent/default keys
cannot consume the server's authentication-attempt limit. Profile-added
`IdentityFile` or `CertificateFile` entries make SSH planning fail closed.

## Security model

tmuxgate is designed to fail closed around route evidence, effective SSH
configuration, host-key validation, request binding, remote-start state,
result collection, and cleanup. It never stores SSH or sudo passwords. Normal
successful jobs are collected and remotely cleaned automatically; the
standalone remote-cleanup surface remains disabled until it can provide the
same durable guarantees.

Loopback TCP does not provide the peer-UID authentication of the broker's Unix
socket. The MCP endpoint therefore requires the owner-only bearer token before
MCP request parsing and accepts only the configured loopback listener. Anyone
who obtains that token can submit requests. In particular, with
`approval_mode = "disabled"`, token possession is sufficient to cause remote
execution without a per-command decision. Never log, share, commit, or place
the token in `config.toml`.

tmuxgate is not a privilege boundary when a client and broker run as the same
Unix account. That account can normally access the same configuration, SSH
credentials, process state, token, and broker socket. For a stronger boundary,
run automation under a separate account or container and design access around
the bearer-token and SSH-credential threat model.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the lifecycle, MCP and
terminal boundaries, route selection rules, approval binding, transport
retention, and recovery model. See the official
[Codex MCP documentation](https://developers.openai.com/codex/mcp/) for Codex
server configuration. Report suspected vulnerabilities according to
[SECURITY.md](SECURITY.md).

## Development

Run the complete test suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Some tests exercise Linux Unix sockets, PTYs, OpenSSH behavior, authenticated
Streamable HTTP, and an isolated local tmux server. They do not contact
configured remote machines.

Contributions are welcome; read [CONTRIBUTING.md](CONTRIBUTING.md) before
changing approval, MCP authentication, route, SSH, durable-state, or cleanup
behavior.

## Project status

The unified broker/MCP/dashboard lifecycle, automatic collection and cleanup,
durable recovery gates, interactive viewer, guided configuration, bounded
parallel jobs, and retained SSH transports are implemented. The MCP tools,
command protocol, and configuration format may still change before 1.0.
Releases and the `main` branch should be treated as experimental until a stable
compatibility policy is published.

## License

tmuxgate is free software licensed under the
[GNU General Public License v3.0 only](LICENSE) (`GPL-3.0-only`).
