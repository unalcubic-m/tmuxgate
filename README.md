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
> important systems. The default `approval_mode = "disabled"` treats the Codex
> tool approval as the operator decision and does not ask again in tmuxgate.
> A reusable password configured in the dashboard can then be submitted
> automatically at an exact sudo prompt. Turn Automation off in the dashboard
> (or set `approval_mode = "always"`) to restore tmuxgate-owned decisions.

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
- The default or an already-enrolled exact per-machine sudo prompt can receive
  an owner-only stored password automatically. Missing credentials and unknown
  prompts fail immediately; Automation never opens enrollment or Forward Input.
- A request may explicitly ask for `interactive` execution when the command
  genuinely needs a remote controlling terminal, such as `sudo` reading a
  password. Prompt detection and terminal handoff are offered only for those
  requests.

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
Protocol version 4 binds the explicit disconnect policy into the request hash;
the broker accepts exact version-3 frames only as the conservative `normal`
policy for rolling local upgrades.

## Requirements

- Linux with Unix-domain sockets and peer credentials
- Python 3.11+
- OpenSSH client tools (`ssh`, `ssh-keygen`)
- tmux on the local and remote machines
- Bash and standard archive/core utilities on the remote machines
- `ip`; NetworkManager's `nmcli` is also used when collecting configured
  home-network identity evidence

The package pins the tested official Python MCP SDK (`mcp==2.0.0`), Textual
(`textual==8.2.8`), and Uvicorn (`uvicorn==0.52.0`). Textual supports the
default full-screen operator interface; the MCP SDK and Uvicorn provide the
embedded Streamable HTTP stack. The TUI requires one foreground character
terminal shared by input and output. A terminal of at least 72 columns by 20
rows is recommended; smaller terminals retain a visible safe action and require
resizing before any positive security decision can be enabled.

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
run `tmuxgate` in the trusted terminal that should own the dashboard and
interactive authentication. The packaged example uses
`approval_mode = "disabled"`, so Codex approval is sufficient without a second
tmuxgate prompt. The dashboard Automation button changes this immediately and
persists it for the next launch.

Existing Codex or shell-profile files are backed up with owner-only
permissions below `$XDG_DATA_HOME/tmuxgate/backups` before managed changes.
An incomplete install restores an installer-owned previous launcher, current
release, Codex configuration, and shell profiles without overwriting a
concurrent edit. A release that may already have been observed by a process is
retained instead of being deleted. A conflicting Codex registration named
`tmuxgate` is refused unless `--replace-codex` is explicitly given. Other
useful options are `--no-codex` and `--no-shell-integration`; run
`./install.sh --help` for the complete interface.

After a successful install, the installer keeps the three most recent releases
and removes older ones, naming each directory it removes. Each release is a
complete virtual environment of roughly 80 MB, so keeping every one grew the
data directory without bound. Three keeps the cheap rollback available: reverting
a bad install is a `current` symlink flip while the release it points back to
still exists. `--keep-releases N` changes the number and `--keep-releases 0`
disables removal entirely. The release currently active, the one `current`
pointed at before this run, and any release a running process was started from
are never removed, whatever the limit says. Shell-profile and Codex backups are
trimmed the same way, except that the oldest pre-image of each file always
survives, because it is the only copy from before tmuxgate managed it.

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

Version 2 also accepts optional exact byte ceilings for result capture and
collection. The defaults preserve the existing 256 MiB per-stream protocol
ceiling while adding explicit total, local-temporary, remote-capture, and
aggregate-concurrency bounds:

```toml
[limits]
max_stdout_bytes = 268435456
max_stderr_bytes = 268435456
max_total_result_bytes = 536870912
max_local_collection_bytes = 536870912
max_remote_capture_bytes = 536870912
max_aggregate_collection_bytes = 1610612736
```

A stream or total exactly at its limit is accepted. One byte over fails closed:
the remote runner does not publish completion, the local collector does not
publish a verified spool, and the durable request remains recovery-required.
Lower limits are useful on constrained hosts. Managed configuration writes
preserve the configured values and materialize defaults when the table was
previously omitted.

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

Only one broker/runtime owner may be active for a configured state and runtime
directory. A duplicate default-TUI invocation opens a standalone conflict
dialog with safe "Use existing / Exit", read-only status, and separately
confirmed "Stop & start here" choices. The dialog itself owns no broker
resource and appears before tmuxgate reads secrets, recovers durable state,
reconciles SSH sockets, or opens a listener. Explicit `--plain` and
noninteractive launches retain the full terminal diagnostic. Inspect ownership
without changing it, or explicitly perform the same bounded safe recovery,
with:

```bash
tmuxgate runtime status
tmuxgate runtime reconcile
tmuxgate runtime takeover --yes
```

`runtime takeover` signals only an owner whose two lifecycle locks contain the
same verified process-incarnation identity. It sends `SIGTERM` through a Linux
PID descriptor, never sends `SIGKILL`, and never deletes a held lock or an
unverified SSH socket. If status reports ambiguous evidence, inspect it instead
of manually deleting lock or control files.

The stable dashboard keeps readiness and bounded operational state in place:

```text
tmuxgate · operator interface
Application readiness: ready       Approval mode: always
MCP listener: http://127.0.0.1:8765/mcp
Configured machines: 4             Active durable jobs: 0
Pending prompts: 0                  Terminal ownership: tui

[D] Dashboard  [J] Jobs  [M] Machines  [A] Activity  [R] Requests  [?] Help
```

When a decision is pending, one exact modal replaces dashboard interaction.
Summary, complete code or diagnostics, and binding evidence remain scrollable;
Escape always selects the safe action. Positive actions are disabled and
unfocused until the modal's stale-input fence has elapsed, so Enter inside that
window selects the safe action. Once the fence elapses, execution approval and
secret-input authorization focus their positive action and Enter commits the
decision; bounded SSH retry, adjacent-route fallback, and machine-disable keep
the safe action focused and require a deliberate button activation.

The Textual interface is the default in a supported interactive terminal.
`tmuxgate --plain` explicitly selects the supported line-oriented fail-safe;
the former `--tui` preview flag has been removed. The full-screen interface
provides keyboard-accessible Dashboard, Jobs, Machines,
Activity, queued-request, and Help views plus request-bound execution-approval
modals, bounded SSH-retry modals, and separately authorized route-fallback
modals, an exact secret-input authorization modal, and a separately bound local
machine-disable modal after all eligible SSH setup attempts are exhausted.
Recovery modals expose Summary, complete inert OpenSSH Diagnostics, and exact
Binding Evidence views. Deny, Cancel, or Keep enabled has default focus; positive
actions are briefly fenced when a modal opens and then require a deliberate
button action. Escape, quitting, UI failure, or shutdown denies unresolved
prompts. An approved secret-input decision suspends the TUI, restores the normal
terminal, and gives a trusted external tmux viewer direct ownership; the TUI
resumes with a full redraw on every return or failure path and never receives
the typed secret bytes. The TUI continually revalidates foreground ownership
and refuses redirected/mismatched terminal input and output, terminal loss, or
a background process group. Initialization or runtime failure stops the unified
application without changing approval policy or starting a plain replacement;
after inspecting the error, restart explicitly with `tmuxgate --plain`.

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

- `list_machines()` returns logical aliases, stored descriptions, and enabled
  status only. Run tools accept the exact alias or an unambiguous normalized
  stored name, so `DockerCore`, `DockerCoreVM`, and `docker-core` can all select
  a uniquely configured `dockercorevm` machine. Resolution can only produce an
  alias returned by the broker; endpoints and SSH options are never accepted.
- `run_argv(machine, cwd, argv, purpose, environment?, timeout_seconds?,
  interactive?, expect_full_reboot?)` submits exact structured argv and waits
  for the broker result.
- `run_script(machine, cwd, purpose, script?, script_base64?, environment?,
  timeout_seconds?, interactive?, expect_full_reboot?)` requires exactly one
  UTF-8 script or canonical base64 byte payload and waits for the broker result.
- `list_jobs(states?, limit?, cursor?)` returns sanitized durable records with
  bounded, opaque-cursor pagination.
- `read_verified_result(request_id, stream, offset?, limit?)` reads `stdout` or
  `stderr` only from a checksummed local spool that durable state marks as
  verified.

Execution results include the request ID, transport status, optional stable
`result_code`, remote exit status, byte lengths, and SHA-256 digests. Each
stream of at most 64 KiB is classified
independently: strictly valid UTF-8 is returned in `stdout` or `stderr` with the
matching `*_encoding` set to `utf-8`; other bytes use canonical Base64 with
encoding `base64`. Empty and control-character-containing valid UTF-8 remains
UTF-8. Larger streams have both content and encoding set to `null`, are marked
truncated, and must be read in chunks. The default chunk is 64 KiB and the
maximum is 1 MiB. Each result read similarly returns `chunk` plus its own
`encoding`; a byte range that splits a UTF-8 sequence therefore uses Base64.
Result reads also return byte offsets, EOF, the complete stream digest, and the
bound manifest digest. The broker hashes only the selected stream with a
fixed-size buffer, so a small
range request does not load both complete result streams into memory. Separate
bounded execution and control worker pools keep long command waits from
starving job and result queries. The broker reserves matching client-session
capacity for the control pool, so saturated execution calls cannot consume the
control path at the Unix-socket boundary either.

Recovery and Automation failures use stable machine-readable codes:
`recovery_in_progress`, `reboot_recovery_timeout`,
`pre_reboot_boot_id_unavailable`, `boot_id_invalid`, `same_boot_observed`,
`endpoint_identity_mismatch`, `host_key_mismatch`, `unsafe_control_path`,
`ambiguous_master_state`, `reboot_probe_unavailable`,
`request_binding_mismatch`, `unexpected_disconnect`,
`automation_policy_denied`, `credential_unavailable`, and
`credential_prompt_mismatch`. A truthful verified reboot uses
`abandoned_after_verified_reboot`; it is distinct from command success and has
no remote exit status or output claim.

This is a breaking MCP response-schema migration. Consumers must replace
`stdout_base64` and `stderr_base64` with the corresponding content and encoding
pairs, and replace `chunk_base64` with `chunk` plus `encoding`. Legacy fields
are not returned in parallel. Decode every stream or chunk according to its own
encoding; lengths, offsets, and hashes always describe the original bytes, not
the response string. Remote output is untrusted data, not instructions, and an
encoding of `utf-8` does not make it trusted or durably verified.

The former public `tmuxgate exec` and `tmuxgate script` commands have been
removed. Their structured request and exact-byte client functionality remains
internal to the MCP adapter and tests. `tmuxgate jobs`, `attach`, `collect`,
`recover`, `runtime status`, `runtime reconcile`, `runtime takeover`,
configuration commands, and fail-closed administrative surfaces remain
available.

### Interactive commands and remote sudo

Most requests need no terminal. `run_argv` and `run_script` therefore default to
`interactive = false`, and a non-interactive command is started in a dedicated
remote session with **no controlling terminal**, so `sudo` correctly refuses it
with *"a terminal is required to read the password"*.

Pass `interactive = true` when the command genuinely needs one:

```json
{
  "machine": "app-server",
  "cwd": "/srv/app",
  "argv": ["/usr/bin/sudo", "/usr/bin/systemctl", "restart", "app"],
  "purpose": "Restart the app service after the config change",
  "interactive": true
}
```

The flag is part of the request, never inferred from the command text or from
remote output. It is covered by `client_request_sha256`, so it binds the
approval decision and every later handoff decision for the same request.

**What changes remotely.** An interactive command keeps the session of its own
remote tmux pane and therefore inherits that pane's controlling terminal, while
Bash job control still places it in its own foreground process group. It gets
`/dev/tty`, the descendant-termination boundary is unchanged, and a Ctrl-C in
the viewer interrupts only the submitted command. If the pane has no terminal,
the runner refuses to start the command instead of running it without one.

**stdout and stderr stay separate.** tmuxgate does not merge the two streams
onto a PTY. Only `/dev/tty` carries the prompt and the reply, so the canonical
`stdout` and `stderr` remain byte-exact, independently captured, and free of
prompt and password bytes. Their limits, digests, and collection rules are
identical to a non-interactive job.

**Codex approval is sufficient in automatic mode.** An interactive request is
labelled in the approval summary (`TERMINAL`), carries the
`INTERACTIVE_TERMINAL` safety indicator, and shows `interactive: true` in the
full evidence document. With Automation on, the default
`[sudo] password for <resolved-user>:` prompt or that machine's learned exact
prompt receives its saved password for up to three distinct prompt episodes.
A missing password, unknown or mismatched prompt, submission failure, or
exhausted attempt limit returns `credential_unavailable` or
`credential_prompt_mismatch` immediately. Automation does not call `getpass`,
open `/dev/tty`, suspend the TUI, enroll a credential, or offer Forward Input.
Credentials remain an explicit dashboard/configuration ceremony performed
outside a running command.

With Automation off (`approval_mode = "always"`), stored passwords are not
submitted. A request-bound authorization names the full request ID, machine,
endpoint, approved command identity, and viewer session:

- in plain mode, type `forward <full-request-id>` on the trusted terminal;
- in the Textual interface, use the Deny-default modal's deliberately armed
  Forward Input action.

Denying it leaves the command detached and still running. Prompt handling is
offered only for requests that asked for `interactive` execution.

**What is and is not recorded.** Reusable passwords and machine-bound exact
prompt profiles are stored separately in the owner-only mode-`0600` state file
`sudo-credentials.json`; passwords never enter
ordinary configuration, activity text, process arguments, captured
`stdout`/`stderr`, the verified result spool, or durable job records. Automatic
submission loads a private named tmux buffer through stdin, pastes it, and
deletes it. Manual input still flows directly to the remote terminal. `sudo`
disables terminal echo while reading.

**Remote `sudo` prerequisites.** The remote account needs its own working sudo
rule; tmuxgate never becomes root itself but can supply the dashboard-stored
password. The
command runs under `env -i` with the fixed `/usr/bin:/bin` path, so invoke
`/usr/bin/sudo` by absolute path. Every request gets a fresh remote tmux session
and terminal, so with sudo's usual per-terminal timestamp policy a credential
cached by another session does not apply and the prompt appears again.

tmuxgate still does not use `sudo -S`, command-line passwords, environment
passwords, root SSH login, or broad `NOPASSWD` rules. Automatic input goes only
to the already-bound interactive viewer's exact default or learned machine
prompt.

> [!WARNING]
> A terminal handoff gives the remote program your keystrokes. Suppressing echo
> is the program's responsibility — `sudo` does it, and tmuxgate cannot
> guarantee it for an arbitrary command. Anything a program does echo becomes
> visible pane text. Authorize a handoff only for a command you have reviewed
> and trust with whatever you are about to type.

### Recovering after an intentional whole-host reboot

Set `expect_full_reboot = true` only when the submitted request is intended to
reboot the whole host and destroy its current SSH session. This explicit policy
is part of the canonical request hash; tmuxgate never infers it from argv or
script text. Before the requested command starts, tmuxgate reads and strictly
validates Linux `/proc/sys/kernel/random/boot_id` over the approved master and
fsyncs that baseline with the exact request, generation, connection plan,
endpoint, resolved SSH identity, and host-key alias.

After a disconnect, the broker uses bounded independent one-shot SSH probes
with `ControlMaster=no`, `ControlPath=none`, strict known-host checking, and the
original revalidated identity. Only a different canonical boot ID permits
automatic abandonment. A reset that returns the same boot ID is not a reboot;
tmuxgate attempts to resume observation/collection of the original guarded job
and otherwise fails closed. Unreachable hosts are retried only until
`broker.reboot_recovery_timeout_seconds` (default 300 seconds). While unresolved,
the exact machine returns `recovery_in_progress`; unrelated machines can use
remaining scheduler capacity.

Changed-boot evidence is durably committed before the old request pin is
released. The old control path is then reconciled through the normal owner,
mode, inode/device, file-type, and OpenSSH liveness checks. An unsafe or
ambiguous path is left untouched and the machine stays blocked. Startup resumes
incomplete evidence probes or evidence-complete cleanup without a terminal
prompt, so the broker does not need to be stopped or restarted for a correctly
marked Automation request.

`abandoned_after_verified_reboot` is an audited terminal abandonment, not a
successful command result. It has no fabricated exit status, completion time,
stdout, stderr, local-spool claim, viewer-detach claim, or terminal-restoration
claim. A verified reboot proves neither the rebooting command's exit status nor
its earlier side effects. `tmuxgate recover after-reboot REQUEST_ID` remains for
legacy records and normal interactive recovery when machine evidence is absent.

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

When approval is set to `always`, plain mode shows a compact decision card in
its controlling terminal. Enter `y`/`yes`/`approve` to approve; press Enter or
enter `n`/`no`/`deny` to deny; use `c` to inspect the exact code or `d` to
inspect the complete technical evidence. Dashboard input, MCP data, Unix-socket
data, and process stdin cannot answer the prompt. The dashboard does not hold
the terminal while idle, allowing approvals, SSH authentication, and separately
authorized secret-input attachments to use the same terminal safely.

Both screens are implemented behind a presentation-independent operator
interface. Execution, SSH-retry, fallback, and machine-disable prompts carry
their complete internal request/connection bindings through an exactly-once
FIFO decision queue; broker and executor workers do not parse terminal text.
Closing or failing either interface denies all unresolved prompts. The
line-oriented interface retains the same `/dev/tty` trust boundary when chosen
with `--plain`. The default Textual interface renders bounded structured activity and
runtime snapshots with markup disabled and control characters escaped, uses a
fixed dashboard widget tree, and marshals every structured prompt to its own
exact modal on the UI thread. Modal documents use three fixed scrollable
widgets regardless
of content length. Textual enters the alternate screen only after
foreground-terminal validation and relies on its driver cleanup to restore
terminal contents and modes on every exit path. Its explicit TUI, modal, and
external ownership states prevent another reader or modal from competing with
an authorized external viewer. Foreground ownership is re-proved on each
dashboard refresh, and a terminal below 72×20 hides evidence and disables the
positive action while leaving the safe action visible.

Remote password-like pane text is inspected only at the visible cursor row. In
automatic mode, the exact default or previously enrolled machine prompt can receive the
stored password for up to three fresh prompt episodes. Automatic mode never
queues credential enrollment or a Forward Input decision; a missing stored
password, unknown prompt, failed submission, or exhausted limit returns an
immediate structured failure. With Automation off, a separate card identifies
the full request ID, logical machine, endpoint, approved argv or script digest,
and remote-input action. Plain mode requires `forward <full-request-id>`; the
TUI shows the same binding in a Deny-default Forward Input modal.

If initial OpenSSH master setup exits, tmuxgate captures bounded complete stderr
diagnostics as exact bytes for the structured operator decision without copying
them into MCP or durable state. The plain and Textual views render those bytes
inertly and expose their SHA-256 and exact hexadecimal evidence. At most one
exact retry is available for each attempted approved endpoint before any remote
command starts. Automation approves it synchronously only when its immutable
request, plan, endpoint, host identity, mutation state, retry number, and
binding are exact, and audits that decision before retrying. Normal mode retains
the Cancel-default operator modal.
The retry recollects local network evidence,
re-resolves SSH policy, and proceeds only if the approved machine, ordered
candidate eligibility, eligible endpoint order, and complete resolved SSH
identities are unchanged. Volatile observation bytes may produce a new
snapshot digest without invalidating those semantics. A semantic change always
requires a fresh request and approval. Automation similarly authorizes only the
exact adjacent pre-mutation route fallback; it denies persistent machine
disable without changing configuration.
Before installing a missing dedicated public key, tmuxgate durably records the
exact request, approved endpoint, and possible `authorized_keys` mutation. If
enrollment or its verification then fails, the request ends with
`remote_setup_failure`; it is never retried or offered a fallback route. An
already-present exact key is detected with a read-only check and does not cross
that mutation boundary.
The dedicated per-machine key is the only effective identity file permitted.
The narrowly scoped enrollment master explicitly allows public-key, keyboard-
interactive, and password authentication so first use can install that key,
but it sets `IdentityAgent=none`, uses `IdentitiesOnly=yes`, disables GSSAPI and
host-based authentication, and is used only for the enrollment protocol. Once
the exact key is verified, tmuxgate closes that master and creates the command
master with public-key authentication only: password and keyboard-interactive
fallback are disabled before any requested command can start. Only the
enrollment master is given the controlling terminal, through the same
suspend-aware handoff the default interface uses for secret input; the command
master cannot prompt and is started with no terminal at all. SSH subprocesses
also receive no `SSH_AUTH_SOCK`. Profile-added `IdentityFile` or
`CertificateFile` entries make SSH planning fail closed. The complete
enrollment and post-enrollment authentication policy is included in the SSH
policy and resolved-identity digests shown in approval evidence.

## Security model

tmuxgate is designed to fail closed around route evidence, effective SSH
configuration, host-key validation, request binding, remote-start state,
result collection, and cleanup. It can store one reusable sudo password per
logical machine in an owner-only state file and submit it to an exact bound
sudo prompt. SSH enrollment passwords and all non-sudo prompts remain
terminal-owned. Normal
successful jobs are collected and remotely cleaned automatically; the
standalone remote-cleanup surface remains disabled until it can provide the
same durable guarantees.

Loopback TCP does not provide the peer-UID authentication of the broker's Unix
socket. The MCP endpoint therefore requires the owner-only bearer token before
MCP request parsing and accepts only the configured loopback listener. Anyone
who obtains that token can submit requests. With Automation on, token possession
is sufficient to cause remote execution and a matching interactive sudo request
may consume the stored password. Never log, share, or commit the token or
`sudo-credentials.json`, and never place either secret in `config.toml`.

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
