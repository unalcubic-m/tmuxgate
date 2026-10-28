# Native Windows broker

Windows supports the local foreground broker, CLI inspection, and sudo
credential management. The MCP endpoint and its eight tools are identical to
Linux. Every remote target must be Linux with Bash, OpenSSH server, tar, tmux,
and optionally sudo. Windows remote shells are unsupported. There is no Windows
service installer in this release.

Existing remote sessions can be inspected using `list_tmux_panes` and
`capture_tmux_pane` with the IDs returned by discovery; see the README for
examples and limits. These tools use native OpenSSH directly, create no job
session, and never send input to an existing pane. No additional Windows
credentials, tmux installation, or persistent setup are introduced.

Explicitly authorized input uses `send_tmux_text` or `send_tmux_key` with the
same discovered IDs plus `pane_pid`. Literal text is bounded to 4096 UTF-8 bytes;
Enter and multiline execution are explicit. See the README for unknown-outcome
and concurrent-writer rules. No Windows or remote credential setup is changed.

## Requirements and paths

Use Python 3.11 or newer and the native Windows OpenSSH client (`ssh.exe` on
PATH). WSL, Git Bash, local tmux, and local sudo are unnecessary. SSH keys,
agent setup, SSH configuration, and verified known-host entries belong to the
Windows account running the broker. Provision these separately before use.
The broker always passes `BatchMode=yes`, `StrictHostKeyChecking=yes`, and
`-T`; unknown or changed host keys fail without prompting or fallback.

| Item | Windows default | Linux default |
| --- | --- | --- |
| Configuration | `%APPDATA%\tmuxgate\config.toml` | `$XDG_CONFIG_HOME/tmuxgate/config.toml` or `~/.config/tmuxgate/config.toml` |
| Durable state | `%LOCALAPPDATA%\tmuxgate` | `$XDG_STATE_HOME/tmuxgate` or `~/.local/state/tmuxgate` |
| Bearer token | `<state>\mcp-token` | `<state>/mcp-token` |

When Windows AppData variables are absent, the defaults are
`~/AppData/Roaming` and `~/AppData/Local`. Windows ignores XDG variables.
`--config` and `--state-dir` accept explicit paths, including spaces and
Unicode. Use a local fixed drive with persistent ACL support, normally NTFS.
Network shares, FAT/exFAT, reparse points (including directory junctions), and
hardlinked state files are rejected. Keep the state directory outside synced
folders and protect the account's profile and SSH installation.

## Foreground setup in PowerShell

From a checkout, install into a virtual environment:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
```

The Windows-only `pywin32` dependency supplies native security and filesystem
APIs. No administrator rights are needed. Create a new protected state
directory and token without printing the token or temporarily exposing it
through inherited ACLs:

```powershell
@'
import secrets
from tmuxgate.config import default_config_path, default_state_dir
from tmuxgate.storage import atomic_write, ensure_directory

config = default_config_path()
ensure_directory(config.parent)
state = default_state_dir()
ensure_directory(state)
atomic_write(state / "mcp-token", (secrets.token_hex(32) + "\n").encode("ascii"), exclusive=True)
'@ | .\.venv\Scripts\python.exe -
Copy-Item examples\config.toml "$env:APPDATA\tmuxgate\config.toml"
```

Edit that non-secret config file with the logical aliases and OpenSSH
destinations you have independently provisioned. Treat any process able to
read the bearer token as authorized to execute on every configured target.
Configure the MCP client privately with `http://127.0.0.1:8765/mcp` and the
token, then run:

```powershell
.\.venv\Scripts\tmuxgate.exe serve
```

For explicit paths, put options before the command:

```powershell
.\.venv\Scripts\tmuxgate.exe --config 'C:\Broker Config\config.toml' --state-dir 'C:\Broker State' serve
```

Stop the foreground broker with Ctrl+C. Restart the same command to recover
durable work. Closing or terminating the broker never authorizes a job rerun.
Startup collects completed work, resumes convincing remote sessions, and marks
ambiguous work `unknown`. A state-directory process lock prevents two brokers
from recovering the same jobs concurrently and releases automatically on exit.

`jobs`, `machines`, and `sudo set/test/clear` use the same syntax as Linux.
`sudo set/test` contact the configured target and belong to separately
authorized operational setup, not source development or CI. Password input
uses `getpass`; stored passwords are ACL-protected bytes, passed only over SSH
stdin, and cleared from the mutable in-memory transport buffer.

## Filesystem security and durability

New directories and files receive protected DACLs at creation granting only
the current Windows token's user SID full control. Existing objects must have
that owner and a protected owner-only DACL; broad, inherited, null, or unfamiliar
ACLs fail closed. The broker never silently repairs existing insecure state.
Create a fresh private directory or review and migrate existing data
separately. `chmod` and Windows read-only attributes are insufficient.

Reads validate ownership, DACL, file type, reparse attributes, and link count
on the same handle used to read. Ancestor directory handles are pinned against
replacement during each operation. Atomic updates flush a private temporary
file in the destination directory, close it, and publish with native
`MoveFileEx` using `MOVEFILE_WRITE_THROUGH`; initial publication omits
replacement. There is no copy fallback or Windows directory-fsync emulation.
This requests the filesystem's durability guarantees; hardware and filesystem
failures can still prevent persistence, as on Linux. Publication errors
propagate and remote cleanup follows successful local result publication.

These controls isolate ordinary accounts. Processes running as the same user,
administrators able to take ownership, and a compromised OS remain trusted.

## Development and validation

```powershell
.\.venv\Scripts\python.exe -m pip install -e '.[dev]'
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\pyright.exe
```

Native tests use temporary state and synthetic credentials. They exercise real
Windows ACLs, junctions, native subprocess pipes, foreground loopback MCP,
locking, binary output, cancellation, and conservative recovery. The Linux
remote-shell integration tests run on Ubuntu CI. No test contacts a real SSH
host or reads user SSH credentials. Windows service installation and live-host
validation remain separate work.
