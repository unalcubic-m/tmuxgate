# tmuxgate

[![CI](https://github.com/unalcubic-m/tmuxgate/actions/workflows/ci.yml/badge.svg)](https://github.com/unalcubic-m/tmuxgate/actions/workflows/ci.yml)

`tmuxgate` is an owner-controlled broker for running reviewed commands in
isolated tmux sessions on configured remote Linux machines. A noninteractive
client submits a logical machine name and exact command; the local broker owns
route selection, SSH policy, authentication, optional terminal approval,
interactive recovery, result collection, and cleanup.

The project is dependency-free at runtime and targets Python 3.11 or newer on
Linux.

> [!WARNING]
> tmuxgate is pre-1.0 security-sensitive software. Review the threat model,
> configuration, and approval mode before using it on important systems. The
> default `approval_mode = "disabled"` does not ask for confirmation after a
> same-UID client request passes validation. Set it to `"always"` when every
> request should require an explicit decision in the broker terminal.

## Why tmuxgate

Automation tools often need to run a bounded command on a remote host without
being given a reusable interactive SSH shell. tmuxgate narrows that workflow:

- Clients name a configured machine; they cannot supply an address, SSH
  option, identity file, proxy, or host-key policy.
- The broker builds and binds the complete route, `ssh -G`, host-key, fallback,
  working-directory, environment, argv, and script plan before execution.
- Every request gets a dedicated remote tmux session and a private local
  viewer. Existing remote sessions are not reused or modified.
- stdout, stderr, exit status, job state, and checksums are collected through a
  durable, fail-closed lifecycle.
- Password and passphrase prompts can be presented in the broker terminal
  without tmuxgate reading or storing the entered bytes.

```text
client -> protected Unix socket -> local broker -> broker-owned SSH transport
                                           |                |
                                    approval/viewer    isolated remote job
                                           |                |
                                           +--- verified result spool <---+
```

## Requirements

- Linux with Unix-domain sockets and peer credentials
- Python 3.11+
- OpenSSH client tools (`ssh`, `ssh-keygen`)
- tmux on the local and remote machines
- Bash and standard archive/core utilities on the remote machines
- `ip`; NetworkManager's `nmcli` is also used when collecting configured
  home-network identity evidence

tmuxgate does not declare third-party Python runtime dependencies.

## Install from source

```bash
git clone https://github.com/unalcubic-m/tmuxgate.git
cd tmuxgate
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

The broker reads an owner-only TOML file from
`$XDG_CONFIG_HOME/tmuxgate/config.toml`, falling back to
`~/.config/tmuxgate/config.toml`.

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
real configuration, host keys, fingerprints, or machine inventory.

Running `tmuxgate` with no subcommand opens the terminal dashboard. It can
start the broker, manage logical machines, validate settings, and enroll a
directly connected home network. Structured configuration commands are also
available:

```bash
tmuxgate config list
tmuxgate config add-machine
tmuxgate config remove-machine MACHINE
tmuxgate config enroll-home
tmuxgate config set-broker --approval-mode always
```

Restart the broker after changing its configuration.

## Run a command

Start the broker in a trusted interactive terminal:

```bash
tmuxgate broker
```

From another process running as the same Unix user, submit structured argv or
an exact script:

```bash
tmuxgate exec app-server --cwd /tmp \
  --purpose "Show kernel and operating-system identity" -- \
  /usr/bin/uname -a

tmuxgate script app-server --cwd /tmp \
  --purpose "Run the reviewed maintenance script" --file script.sh
```

The client blocks until it receives the result. Use `tmuxgate jobs` to inspect
durable state and `tmuxgate attach REQUEST_ID` to enter an active request's
private viewer for arbitrary interaction, Ctrl-C, or tmux detach.

When approval is set to `always`, the broker shows a compact decision card.
Enter `y`/`yes`/`approve` (or press Enter) to approve, `n`/`no`/`deny` to deny,
`c` to inspect the exact code, or `d` to inspect the complete technical
evidence. Approval input is read only from the broker's controlling terminal;
socket data and command input cannot answer the prompt.

## Security model

tmuxgate is designed to fail closed around route evidence, effective SSH
configuration, host-key validation, request binding, remote-start state,
result collection, and cleanup. It never stores SSH or sudo passwords. Normal
successful jobs are collected and remotely cleaned automatically; the
standalone remote-cleanup surface remains disabled until it can provide the
same durable guarantees.

tmuxgate is not a privilege boundary when the client and broker run as the same
Unix account. That account can normally access the same configuration, SSH
credentials, process state, and broker socket. For a stronger boundary, run
automation under a separate account or container with access only to the
tmuxgate request socket and no direct SSH route or credentials.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the lifecycle, route
selection rules, approval binding, transport retention, and recovery model.
Report suspected vulnerabilities according to [SECURITY.md](SECURITY.md).

## Development

Run the full dependency-free test suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Some tests exercise Linux Unix sockets, PTYs, OpenSSH behavior, and an isolated
local tmux server. They do not contact configured remote machines.

Contributions are welcome; read [CONTRIBUTING.md](CONTRIBUTING.md) before
changing approval, route, SSH, durable-state, or cleanup behavior.

## Project status

The main execution path, automatic collection/cleanup, durable recovery gates,
interactive viewer, guided configuration, bounded parallel jobs, and retained
SSH transports are implemented. The command protocol and configuration format
may still change before 1.0. Releases and the `main` branch should be treated
as experimental until a stable compatibility policy is published.

## License

tmuxgate is free software licensed under the
[GNU General Public License v3.0 only](LICENSE) (`GPL-3.0-only`).
