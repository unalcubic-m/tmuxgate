# tmuxgate architecture

## Unified process boundary

Running `tmuxgate` with no subcommand starts one foreground application with
three coordinated components:

1. The existing same-UID Unix-socket broker and execution workers.
2. An authenticated MCP Streamable HTTP endpoint at `/mcp` on the configured
   literal loopback address.
3. The local dashboard in the application's controlling terminal.

`tmuxgate dashboard` starts the same application explicitly. `tmuxgate broker`
is a deprecated compatibility alias and no longer starts a broker-only mode.
There is no `tmuxgate-mcp` executable or Codex-launched helper process. The
former public `tmuxgate exec` and `tmuxgate script` commands are removed; the
underlying `RequestSpec` and Unix-socket client remain internal interfaces for
MCP and tests. Administrative `jobs`, `attach`, `collect`, `recover`, and
configuration commands remain public. Standalone remote `cleanup` remains
deliberately disabled and fails closed until its broker-control protocol is
implemented.

The MCP server is embedded in the same OS process but runs its ASGI event loop
in a dedicated thread. Its transport is authenticated Streamable HTTP on
`127.0.0.1`, not stdio. Consequently, MCP protocol bytes cannot consume
process stdin or the application's `/dev/tty`, and Codex connects to an
already-running service instead of spawning it.

```text
Codex
  -> Authorization: Bearer ...
  -> http://127.0.0.1:<port>/mcp
  -> embedded typed MCP handlers
  -> internal one-shot Unix-socket client
  -> same-UID broker
  -> approval/planning/execution or broker-owned durable read
```

The internal MCP-to-broker hop is intentional even though both endpoints share
a process. MCP handlers retain only the broker socket path and a bounded local
worker dispatcher. They do not receive the planner, SSH pool, state store,
spool, machine endpoints, credentials, or cleanup capability. This preserves
the existing validation and execution trust boundary and ensures that new MCP
inputs cannot become an alternate execution path.

### Startup and shutdown

The unified lifecycle starts resources in fail-closed order:

1. Load and validate the owner-only configuration as one immutable snapshot.
2. Prepare private runtime/state directories and securely load or create the
   MCP bearer-token file.
3. Acquire the `state.lock` singleton in the state directory before opening or
   recovering any durable state.
4. Open durable state and the result spool, then perform startup recovery.
5. After recovery succeeds, acquire a separate `broker.lock` singleton in the
   socket's runtime directory, then inspect stale socket state and open the
   Unix listener while retaining both locks. Distinct lock names preserve both
   protections when the configured state and runtime directories are the same.
6. Construct the shared terminal arbiter, planner, transport pool, prompt
   presenter, executor, broker, and broker control service.
7. Start the broker, then start and await readiness of the MCP HTTP listener.
8. Report only sanitized listener/token-path information and enter the
   selected dashboard loop. Plain mode is the default; the Textual operator
   preview is selected only by explicit `--tui`.

Startup refuses to accept new approvals when durable recovery reports a
possibly running or incompletely collected request. An MCP bind or startup
failure stops the already-started broker and unwinds owned resources; there is
no silent broker-only mode. The explicit singleton lock prevents a deprecated
`broker` invocation or a second no-argument invocation that shares state from
creating a parallel owner; the separate runtime lock serializes every stale
socket check and bind even when competing invocations select different state
directories.

`SIGINT`, `SIGTERM`, or dashboard quit sets the shared stop event. Shutdown is
two-phase around MCP: it first tells the HTTP listener to stop accepting work,
then performs the broker's bounded worker shutdown so in-flight MCP handlers
blocked in the internal Unix client can finish, and only then joins the MCP
server. A clean shutdown subsequently closes the secret-prompt presenter,
idle SSH masters, and dedicated MCP broker-call pools, followed by the broker
listener, spool/state, and both singleton locks. If a bounded network component
does not stop cleanly, tmuxgate reports a software failure and retains its
owned resources until process exit rather than closing them underneath live
workers. That diagnostic names the component that did not stop, states that
new work is no longer accepted and that the process returns software-error
status 70, and directs the operator to inspect durable jobs because an already
approved remote job can continue independently. Disconnecting or timing out an
MCP call is not a cancellation
boundary: its internal blocking Unix-socket client may remain connected until
the broker produces a result. Its bounded execution-worker slot remains
charged until that synchronous client really returns. The existing
pre-approval cancellation rule applies only when that Unix client actually
disconnects. An approved request is never killed, retried, or made nondurable
because Codex disappeared.

### Configuration and migration

Configuration is still exclusively backed by the owner-only TOML file at
`$XDG_CONFIG_HOME/tmuxgate/config.toml` or
`~/.config/tmuxgate/config.toml`. Dashboard configuration actions invoke the
same `tmuxgate config` handlers. Structured actions use the same parser,
validation, serializer, and atomic publisher; the advanced `config edit`
action captures parsed settings and exact bytes from one secure descriptor,
then compares the current exact bytes under the owner-only writer lock. It
reopens the editor output securely under that lock and copies its exact
validated bytes into a broker-owned `0600` temporary that is fsynced before
atomic replacement. Comment-only concurrent changes therefore conflict rather
than being silently overwritten. The running application does not depend on
dashboard state. It retains its startup snapshot until restart so a
configuration edit cannot change an already approved route or execution
identity.

Schema version 2 adds:

```toml
[mcp]
host = "127.0.0.1"
port = 8765
```

The host must be the literal IPv4 loopback address and the port must be from 1
through 65535. Version-1 files remain valid without an `[mcp]` table and are
normalized in memory to these defaults. Structured managed writes always
publish version 2, so they require no separate migration command. The raw
`config edit` workflow preserves version 1 unless the operator changes it.
Version 1 deliberately does not accept an `[mcp]` table; change the top-level
version to 2 when configuring a nondefault port.

Operational migration replaces a broker-only launch with the no-argument
unified application, removes any Codex stdio/`tmuxgate-mcp` registration, and
registers the authenticated loopback URL. Callers move from the removed public
`exec`/`script` commands to the typed `run_argv`/`run_script` tools. Existing
administrative CLI workflows and durable records are retained.

### User installation and Codex registration

The root `./install.sh` is a user-scoped deployment transaction, not a service
manager. It refuses root, takes a private installer lock, and builds each
release in a new timestamped virtual environment below
`$XDG_DATA_HOME/tmuxgate/releases`. Python packages, including the official MCP
SDK and Uvicorn, are installed only into that environment; Node.js is not part
of the runtime or installation path. Imports, the installed CLI, and any
existing tmuxgate configuration are validated before the managed `current` and
user launcher symlinks are atomically switched.

The legacy checkout-backed `~/.local/bin/tmuxgate` symlink and a launcher from
an earlier managed install are recognized replacement targets. An unrelated
file or symlink fails closed unless the operator supplies
`--replace-existing`. The installer does not rewrite
`config.toml`, durable job records, verified result spools, or an existing
`mcp-token`; it invokes the installed token loader only to validate and reuse
that token, or to create the normal owner-only token when none exists. The
default protected configuration must exist before installation. A newly
created token is durable application state and is intentionally retained if a
later deployment step fails.

Codex registration is written directly to the single
`[mcp_servers.tmuxgate]` table using the configured
`http://127.0.0.1:<port>/mcp` Streamable HTTP URL,
`TMUXGATE_MCP_TOKEN` as `bearer_token_env_var`, and
`tool_timeout_sec = 604900`. The full candidate is validated with Python's TOML
parser. For compatibility verification, `codex mcp list --json` receives only
the canonical tmuxgate table in a private disposable `CODEX_HOME` and runs from
that isolated directory; neither the live config nor unrelated hooks and
settings are exposed to CLI serialization. The installer refuses a different
registration named `tmuxgate` unless `--replace-codex` is explicit, and even
then replaces only an unambiguous simple table; nested, quoted, or complex
layouts fail closed for manual review. An owner-controlled Codex home is
hardened to mode `0700` before its configuration is changed. Installer
children receive neither the MCP bearer token nor `PYTHONPATH`, `PYTHONHOME`,
or `VIRTUAL_ENV`, preventing credentials or checkout imports from leaking into
pip build isolation, smoke tests, or Codex commands.

For Bash launches, the installer writes an owner-only
`$XDG_CONFIG_HOME/tmuxgate/codex-env.sh` and a delimited managed source block
in `.bashrc` and `.profile`. The environment file contains a fixed token-file
path and canonical-token validation, never the credential bytes; each new
shell reads the credential directly from the owner-only durable state file.
The installer cannot alter an already-running process environment or MCP
registry snapshot, so a new Bash shell and a Codex restart are required.

Before changing a pre-existing Codex config or Bash profile, the installer
writes an owner-only backup below `$XDG_DATA_HOME/tmuxgate/backups`. It retains
snapshots of every managed mutation until the launcher switch and install
manifest complete. Immediately before a managed replacement, the installer
refuses to proceed if the captured preimage has changed. Failure restores a
file or link only while its exact installer-written post-image is still
present. The public launcher is also rechecked against replacement policy at
publication time so a launcher introduced during the build is not claimed.
These checks narrow but cannot eliminate the filesystem race between the last
comparison and an atomic replacement; retained owner-only backups are the
recovery path if another process writes in that interval. An unpublished
incomplete release is removed; a release that may already have been observed
through `current` is retained even after rollback so a running process cannot
lose packaged assets. Successful installations retain older versioned
releases and backups for operator recovery. The application itself is never
started, stopped, or killed by the installer: `tmuxgate` must still run in the
foreground in the terminal that owns approvals and authentication.

If the preserved configuration has `approval_mode = "disabled"`, installation
stops before Codex and launcher mutation unless the operator supplies
`--allow-disabled-approvals`. Registration does not weaken or override that
policy: the bearer token alone authorizes execution requests in this mode,
whereas `approval_mode = "always"` retains the independent broker-terminal
decision.

Configuration edits are validated and atomically published but require a
restart. Direct-home enrollment still requires complete local link,
source-address, route, router-neighbor, and NetworkManager identity evidence
and refuses a routed WireGuard view. When the otherwise-proven direct gateway
lacks a cached neighbor entry, enrollment alone may send one bounded ICMP
request to that configured gateway, then recollect and re-prove the full
snapshot before publication. Ordinary planning remains passive. These settings
actions do not open SSH or mutate a remote machine.

### MCP authentication and transport security

Loopback TCP has no Unix peer-credential equivalent, so every HTTP request must
present `Authorization: Bearer <token>`. A small ASGI middleware compares the
complete header in constant time and rejects failures before MCP parsing. The
MCP application also receives its fixed host for Host/Origin and DNS-rebinding
validation, disables access logging, and caps a request body at 24 MiB. The
listener cannot be configured on a wildcard, hostname, IPv6 address, or
non-loopback interface.

Before an execution request opens the Unix socket, the MCP handler serializes
its broker header and enforces the broker protocol's 256 KiB metadata limit.
Oversized argv/environment requests therefore produce an input error instead
of being misclassified as a malformed broker response.

The first unified startup creates `mcp-token` below the selected durable state
directory, normally `~/.local/state/tmuxgate/mcp-token`. The token is 32 random
bytes represented as 64 lowercase hexadecimal characters plus one newline.
Creation uses an exclusive private temporary file, mode `0600`, file `fsync`,
atomic no-overwrite publication, and directory `fsync`. Every load rejects
symlinks, non-regular files, the wrong owner or mode, malformed contents, and
replacement races. The application prints the token path, never the token.

For the credential, Codex configuration stores only the name of the environment
variable that supplies it:

```toml
[mcp_servers.tmuxgate]
url = "http://127.0.0.1:8765/mcp"
bearer_token_env_var = "TMUXGATE_MCP_TOKEN"
tool_timeout_sec = 604900
```

The environment variable must be populated from the token file before Codex
starts. The recommended timeout covers `RequestSpec`'s seven-day maximum plus
protocol overhead; shorter local policy is valid but may cause Codex to stop
waiting while an approved durable job continues. Token rotation requires
restarting tmuxgate and every Codex process that uses the old credential.

Possession of the bearer token grants request-submission authority. With
`approval_mode = "disabled"`, that authority can cause remote execution without
a per-request terminal decision. Authorization headers, request scripts,
environment values, stdout/stderr, and secret-terminal events must never be
logged. The token is state, not configuration, and must not be copied into the
main TOML file.

### Typed MCP tools

The MCP surface contains exactly five tools:

- `list_machines()` returns only logical aliases, descriptions, and the boolean
  enabled state; endpoints, addresses, SSH identities/options, routes, keys,
  and host-key evidence remain private to the broker.
- `run_argv(machine, cwd, argv, purpose, environment?, timeout_seconds?)`
  validates and creates `RequestSpec(mode=ARGV)` without shell-joining argv.
- `run_script(machine, cwd, purpose, script?, script_base64?, environment?,
  timeout_seconds?)` requires exactly one UTF-8 text script or canonical base64
  exact-byte script and creates `RequestSpec(mode=SCRIPT)`.
- `list_jobs(states?, limit=50, cursor?)` exposes sanitized durable metadata in
  newest-first pages. Page size is from 1 through 100 and cursors are opaque.
- `read_verified_result(request_id, stream, offset=0, limit=65536)` reads only
  `stdout` or `stderr`, with a maximum 1 MiB chunk.

Execution tools are annotated mutating, destructive, non-idempotent, and
open-world. List/result tools are annotated read-only, non-destructive,
idempotent, and closed-world. Codex-side approval based on those annotations is
only additive; broker-terminal approval remains authoritative.

`run_argv` and `run_script` block for the broker result and return the request
ID, transport status, optional remote exit status/detail, and length plus
SHA-256 for each stream. A stream of at most 64 KiB is strictly UTF-8 decoded
and returned as ordinary text with encoding `utf-8`; decoding failure selects
canonical Base64 and encoding `base64`. Each stream is classified independently.
Empty output, NUL, and terminal controls remain UTF-8 whenever strict decoding
succeeds. Larger content and its encoding are both omitted and marked
truncated. `read_verified_result` applies the same classifier independently to
every chunk and returns `chunk`, `encoding`, current/next byte offsets, EOF,
complete stream size/digest, exit status, and manifest digest. A byte range that
starts or ends inside a multibyte character therefore uses Base64, and
successive chunks may use different encodings. It never contacts SSH and never
reads tmux pane history.

This intentionally breaks the MCP response schema: `stdout_base64` and
`stderr_base64` are replaced by `stdout`/`stdout_encoding` and
`stderr`/`stderr_encoding`; `chunk_base64` is replaced by `chunk`/`encoding`.
There are no duplicate legacy fields. Consumers must decode every content value
according to its adjacent encoding. Lengths, offsets, next offsets, and hashes
remain byte-based and are computed from the original bytes. Readable remote
output remains untrusted data, not instructions; its encoding neither verifies
the result nor changes the transport-status trust rules.

Before a result byte is exposed, the broker requires durable state to mark the
local spool verified with a manifest digest and binds the current manifest and
exit status back to that record. It exact-validates both stream files, then
hashes only the selected stream in fixed 64 KiB reads while retaining at most
the requested 1 MiB range. Missing, corrupt, mismatched, unverified, abandoned,
or recovery-required results fail closed. `list_jobs` exposes only the request
ID, logical machine, state, decision, timestamps, exit status, verified-result
availability, and recovery requirement.

### Unix broker protocol and implementation boundary

Each client sends exactly one request frame, then shuts down its socket's write
side. The broker requires EOF before considering the request complete. Frame
reads have a bounded deadline, and argv/cwd/environment filesystem bytes are
base64 fields inside the JSON header so non-UTF-8 bytes survive exactly.
Execution responses may contain multiple status/result frames. The three MCP
control requests (`list_machines`, `list_jobs`, and `read_verified_result`) use
the same one-frame, EOF-terminated, same-UID-validated socket boundary and one
strictly decoded response.

The broker composes that local socket boundary, one-shot bound planner, real
broker-owned OpenSSH master/channels, durable state, dedicated remote tmux jobs,
canonical result spool, and client delivery. `--fake` remains available for
local tests. Successful jobs auto-collect and auto-clean. Local `collect`
replays a checksummed spool. `attach` enters an active request's private local
viewer without issuing a new remote command.

The embedded MCP layer uses separate bounded thread pools for execution waits
and read-only control requests. Long `run_argv`/`run_script` calls therefore
cannot consume the workers used by `list_machines`, `list_jobs`, or
`read_verified_result`. The broker client-session limit includes a matching
control-session reserve, so execution saturation cannot move the starvation
point down to the Unix listener. A disconnected coroutine does not free its
execution slot while its synchronous Unix client remains live, preventing
unbounded queued work after repeated HTTP cancellations.

Ephemeral socket, control, viewer, and `broker.lock` socket-lifecycle files live below
`$XDG_RUNTIME_DIR/tmuxgate`. The durable boundary is
`$XDG_STATE_HOME/tmuxgate` (default `~/.local/state/tmuxgate`) with the
`state.lock` lifecycle singleton, token, job records, and owner-only spool. The
durable job store uses checksummed,
generation-checked JSON records, mode `0600`, same-directory atomic replacement,
file `fsync`, and directory `fsync`. Startup recovery atomically terminalizes
records proven to be pre-remote and blocks all new approvals for possibly
running or incompletely collected records. A remote-start permit is returned
only after `REMOTE_MAY_BE_RUNNING` and the predictable guarded job identity are
durable. Completion, viewer detach, terminal restoration, local-spool
verification, lease release, delivery, and done are also generation-checked
and fsynced; the verified spool flag is inseparable from its exact manifest
digest. The real executor uses this store directly; there is no second state
path.

SSH public-key setup has its own durable sub-lifecycle in the same record. A
read-only remote check first proves whether the exact dedicated key is already
present. If it is missing, tmuxgate fsyncs
`KEY_ENROLLMENT_MAY_HAVE_STARTED`, bound to the request, approved plan, and
exact endpoint, before it may create `.ssh`, create `authorized_keys`, or
append the key. Successful append plus a final exact-key check is fsynced as
`KEY_ENROLLMENT_VERIFIED_PRE_REMOTE` before command setup continues. A channel,
script, verification, or later setup failure after that first boundary becomes
`FAILED_REMOTE_SETUP`: it truthfully retains `remote_mutation_started = true`
without claiming the requested command ran or inventing command output. Startup
conservatively terminalizes an interrupted enrollment in the same state.

The complete approval document binds the exact client request to the ordered
route plan, canonical network-snapshot digest, strict `ssh -G` identity, SSH
policy digest, host-key alias/evidence, proxy configuration, and fallback order.
The connection-plan component resolves every eligible fallback up front and
fails the entire plan if any resolved identity is inconsistent. The one-shot
planner composes collection, route policy, `ssh -G` resolution, and optional
bound terminal approval without opening SSH. An authorized context contains
only the request digest and immutable plan, is consumed once, and multiple
request-bound contexts may await parallel executor workers.

## Operator-interface boundary

`OperatorInterface` is the presentation-independent boundary between broker or
executor work and operator interaction. `PlainTerminalInterface` preserves the
line-oriented dashboard and the existing exact approval, SSH-retry, fallback,
machine-disable, and secret-input renderers. It remains the production default
and may be selected explicitly with `--plain`. It obtains decision bytes only
from the controlling `/dev/tty` under `TerminalArbiter`; stdin,
MCP/Unix-socket frames, request content, remote output, viewer pane content,
rendered diagnostics, and pager return values are never input sources.

`TextualOperatorInterface`, selected only with `--tui`, is the Textual operator
interface built on exactly pinned `textual==8.2.8`. Before entering
application mode it verifies that Textual's real stdin and stdout are the same
character terminal and that tmuxgate's process group owns that terminal in the
foreground. Validation, driver initialization, snapshot refresh, or terminal
ownership failure aborts the unified application; there is no automatic plain
fallback and no approval-policy change. Textual's driver owns alternate-screen
entry, resize/full redraw, signal/cancellation unwinding, and restoration of
the prior terminal modes and contents.

The Textual dashboard has one fixed widget tree with keyboard-accessible
Dashboard, Jobs, Machines, Activity, queued-request, and Help views. Its
runtime snapshot reports application/broker readiness, MCP listener and
approval mode, configured/enabled machines, bounded recent durable jobs,
retained SSH state, pending prompts, bounded activity, and terminal ownership.
Every externally derived string is passed as literal non-markup content after
C0/C1, DEL, format, bidi, and surrogate controls are escaped. Job, machine,
activity, and prompt rows are bounded without creating per-record widgets. A
terminal below 72 columns by 20 rows shows only a resize/quit guard when no
security decision is active.

The TUI supports execution approval, bounded SSH retry, separately authorized
adjacent-route fallback, and exact secret-input authorization decisions. It may
run with either approval mode: disabled execution approval is still automatic,
but never disables secret-input authorization. Its presenter thread remains the sole FIFO consumer,
but it schedules each supported prompt through Textual's thread-safe
`call_from_thread` boundary. The UI thread creates one modal for that exact
immutable queued item and returns its result through a callback which retains
the original object identity; no displayed label is parsed or used to select a
slot. Machine-disable prompts remain denied.

The interface tracks three synchronized foreground ownership states: `tui`,
`modal`, and `external`. A positive secret-input modal result atomically reserves
`external` ownership for that exact prompt ID before its waiting worker is
released. No later modal can open during that reservation, and a stale or
different prompt cannot consume it. The trusted presenter then asks the
interface to run the already-bound viewer session. On the UI thread, the
interface acquires the highest-priority `TerminalArbiter` lease and enters
Textual's `App.suspend()` context. Textual stops its input reader and output,
leaves alternate-screen/raw application mode, and restores the pre-TUI terminal
settings before the trusted tmux process is started with all three standard
streams connected directly to the resolved broker-owned `/dev/pts/...` device.
The TUI therefore never reads, buffers, renders, or logs secret bytes. Normal
return, cancellation, process failure, and exceptions all unwind the suspend
and arbiter contexts, restore `tui` ownership, and force a full layout repaint.
Concurrent terminal ownership or a missing/exited dashboard fails closed before
the terminal or viewer is opened.

An execution modal exposes separate Summary, Code, and Technical Details tabs.
The existing pure ASCII-safe renderers supply complete request, script,
connection-plan, identity, evidence, diagnostic, and binding content to three
fixed scrollable non-markup widgets; content size does not create additional
widgets. The full request ID is independently visible in the modal heading.
Deny receives initial focus and Enter therefore denies. Escape and modal close
also deny. Approve has no single-key binding and remains disabled during a
short opening fence, which consumes already-buffered activation input before a
later deliberate button action can approve. Dashboard, remote, pane, protocol,
ANSI, and rendered content remain data and cannot synthesize Textual events.

SSH retry and fallback each have a distinct focused modal with Summary,
Diagnostics, and Binding Evidence tabs. Cancel receives initial focus and is
the Enter/Escape/default action. The positive action is fenced like execution
approval. Retry shows the exact request, endpoint and resolved identity,
failure summary, requested-command and mutation states, and the enforced
`1 of 1` retry count. Fallback shows the failed and proposed routes and
identities and explains why the original RUN decision is insufficient. Both
retain the complete bounded OpenSSH stderr bytes, render a reversible inert
spelling, and expose the exact byte length, SHA-256, and hexadecimal evidence.

Workers submit immutable structured objects rather than presentation
arguments:

- `ExecutionApprovalPrompt` binds a fresh prompt ID, canonical request ID,
  complete `RequestSpec`, command/script identity digest, client-request
  digest, and the complete approved `ConnectionPlan` plus its digest. The
  plan-less form is restricted to the nonremote `--fake` test backend.
- `SshRetryPrompt` additionally binds the exact endpoint, failure detail,
  complete OpenSSH diagnostic digest, `1 of 1` retry policy, requested-command
  state, truthful remote-mutation state, and retry digest.
- `RouteFallbackPrompt` binds the failed endpoint, the immediately adjacent
  approved fallback, failure detail, diagnostic digest, requested-command and
  mutation states, and separate fallback digest. Construction rejects a
  nonadjacent route or any state in which the command or remote mutation may
  have started.
- `MachineDisablePrompt` binds the local mutation decision to the originating
  request, approved plan, failure, machine, and proven pre-remote state.
- `SecretInputAuthorizationPrompt` binds the exact request, machine/endpoint,
  command or script, approved plan, and isolated viewer-session recipient.
  `SecretInputRecipient` retains that request and route identity while the
  viewer is live and creates a fresh one-shot prompt for each new prompt
  episode.
- `OperationalActivity` carries a typed activity kind and optional canonical
  request, machine, endpoint, and detail identities. Connection events also
  carry a typed phase and truthful mutation state. The Textual dashboard
  replaces each request's connection projection with its latest phase, so
  approval progresses through connecting, retry/fallback decision, remote
  execution, completion, or failure in place. Plain mode consumes the same
  structured transitions linearly. Broker audit transitions enter the
  interface's bounded history; startup and error events use the same boundary.

Every prompt constructor recalculates the established connection-plan digest
and the exact client request/command identity. Missing, malformed, mismatched,
or internally inconsistent fields are rejected before queuing. A prompt gets a
cryptographically random process-local ID which may be submitted only once for
the interface lifetime. Human-readable labels and rendered terminal text are
never parsed to reconstruct these identities.

### Queue and decision ownership

`PromptQueue` is a mutex-protected FIFO. Submission receives a monotonically
increasing sequence number while holding that mutex, so concurrent worker
requests have one deterministic presentation order. Each queued item owns its
own `PendingDecision` condition variable. Each interface has one daemon
presenter thread and is the sole queue consumer; workers wait only on the slot
created for their exact prompt. The Textual interface also records a bounded
projection of every submission, schedules only the active execution item onto
the UI thread, waits for that item's resolution, and then advances to the next
FIFO item. Multiple worker requests therefore remain independent and only one
security modal can be active.

An immutable `OperatorDecision` repeats the prompt ID and canonical binding
digest in addition to Approved or Denied. `PendingDecision.resolve()` checks
both values atomically and accepts only its first matching result. A second
resolution, a decision for another request, a late decision for an earlier
prompt, or reuse of any prior prompt ID is rejected without affecting the
current prompt. Thus screen labels, queue position, short request IDs, or
stale terminal actions cannot select a decision target.

The foreground application owns the interface for the same lifetime as the
broker and MCP listener. Shutdown first stops new MCP admissions, then closes
the interface before joining broker workers. Queue close atomically resolves
every active and queued slot as Denied and makes later submissions immediately
Denied. Cancellation and worker abandonment use the same one-shot denial;
presenter/render/input exceptions close the queue and deny all unresolved
slots. Closing cannot interrupt a kernel-blocked `/dev/tty` read, so
`PlainTerminalInterface.close()` may report an unjoined presenter thread, but
the decision slots are already denied and application shutdown is reported
unclean rather than approving or closing dependencies underneath it.

OpenSSH first-master authentication still uses direct, arbiter-serialized
external terminal ownership. `SecretPromptPresenter` may detect and report
prompt-like remote output, but detection is not authority: before it can
attach a viewer, it submits a fresh `SecretInputAuthorizationPrompt` through
the same one-shot operator interface.

## Bounded command leases and retained transports

`max_active_remote_commands` defaults to three and may be configured from one
to three. The broker assigns one isolated lease per request. Each lease remains
held until:

- remote completion is proven;
- the canonical completion manifest and separate streams are stored locally;
- the viewer has exited or detached; and
- the broker has restored control and settings of its terminal.

Detaching while a command runs does not release that request's lease. An
uncertain job holds its own lease in recovery-required state; other configured
slots continue independently.

`approval_mode = "disabled"` is the default and performs no execution
confirmation prompt after authentication and broker validation. It does not
disable secret-input authorization. `approval_mode = "always"` enables the
execution approval UI. Its compact decision card contains advisory
purpose, logical machine, selected route and resolved identity, host-key status,
working directory, a JSON-quoted shell-escaped argv view or script identity/source,
environment, timeout, and human-readable advisories. Enter/`y` approves, `n`
denies, `c` opens the exact structured argv or complete escaped script, and `d`
opens the exhaustive network/SSH-policy/evidence/binding record. Both views use
the sealed secure pager and return to the same prompt. Client-controlled text
is rendered with reversible ASCII escapes, and a final renderer invariant
rejects every non-newline character outside printable ASCII, preventing ANSI,
C0/C1, DEL, Unicode bidi, or similar terminal-display injection. Approval is read only
from the application's `/dev/tty`; pager output, HTTP or Unix-socket data,
process stdin, and client-supplied purpose text cannot answer it.

Each SSH viewer runs in a separate owner-only local tmux server below the
runtime directory. A broker-owned monitor checks only the visible cursor row of
each viewer for a password or passphrase prompt; this deliberately ignores the
nested remote tmux status row below it. A match publishes a notification and
enters one shared FIFO, but never attaches the broker terminal by itself. The
presenter first asks the operator to authorize the exact request, logical
machine, approved argv or script identity, connection plan, endpoint, and
isolated viewer session. The trusted display states that typed bytes will be
sent to the remote process. Authorization requires typing the full
`forward <32-character request ID>` phrase on the broker's `/dev/tty`; Enter or
an explicit denial denies. Socket/MCP data, request bytes, remote pane content,
and process stdin are not input sources for this prompt. A stale prompt ID,
binding, request, command, endpoint, or viewer cannot resolve a replacement
prompt. Only after an Approved decision does the presenter request an exclusive
presentation-layer handoff, then revalidate the still-live viewer and
still-visible prompt and attach to the resolved broker-owned terminal device.
In Textual mode this happens only while the application is suspended. The prompt
matcher accepts at most 256 literal ASCII sudo `pwfeedback` stars after an
otherwise valid cursor-row prompt, including fewer stars after backspacing; it
does not accept arbitrary suffix text or alternate mask characters.

The presenter has no typing-speed, authentication-check, or retry timeout.
While the underlying approved job remains active, an attachment remains open
across a disappearing prompt, PAM delay, rejection output, and a newly visible
prompt. It detaches automatically only after observing a new exact
session-bound line
`TMUXGATE_AUTH_COMPLETE=tmuxgate-<12 hex>`. A reviewed script emits that
non-secret marker only after its authentication command has returned success,
for example by obtaining `#S` from its current remote tmux session. The
presenter counts exact markers already retained in the isolated local viewer's
bounded scrollback before attachment so an older marker cannot satisfy a later
prompt episode. Prompt matching continues to use only the visible cursor row;
history is scanned only for the cooperative marker. The marker is viewer-UX
signaling, not authentication security or durable completion evidence;
canonical job state and captured results remain authoritative. Job completion
and operator `Ctrl-b d` remain the fallback for commands without the marker.
A denial leaves the remote command running and detached. The same continuously
visible prompt is not offered again; clearing it and later displaying a new
prompt creates a fresh independently bound decision. A deliberate detach is
not automatically reversed while the same prompt
remains continuously visible; a cleared prompt followed by a new prompt begins
a new episode. This avoids both premature time-based detachment and
interception of password bytes. Prompt or marker probe failure attempts a
targeted detach fail-closed. If targeted tmux detach fails, the presenter
terminates and reaps the exact local attach process before releasing the
terminal lock, then reports the presenter error.

After authorization and before displaying its attachment notice, the presenter
revalidates the opened PTY and discards only input bytes that were already
queued on the broker terminal. It then writes the notice and starts attachment
without a second input flush. This prevents the authorization line or an
earlier dashboard keystroke from becoming a password submission while
preserving input typed in response to the notice.
Output is not flushed, and input continues directly to the viewer. Detection
does not inspect canonical stdout/stderr or store input.
`tmuxgate attach REQUEST_ID` remains available for arbitrary interaction,
inspection, Ctrl-C, or manual detach. Lost viewers are recreated automatically.
Normal completion closes the remote pane and local viewer automatically;
canonical capture does not depend on pane history.

In plain mode, one process-local `TerminalArbiter` serializes dashboard
transactions, the optional execution approval UI, mandatory secret-input
authorization,
fallback approval, interactive first-master SSH authentication, and approved
viewer attachments. The dashboard polls for a
complete canonical `/dev/tty` line in bounded slices without retaining a lease
while idle. It acquires the lowest-priority lease only immediately before
reading. Any intervening non-dashboard handoff increments a generation and
makes that pending dashboard line stale.

Non-dashboard plain-mode claims reopen and revalidate `/dev/tty` and discard
queued input before displaying their trusted interaction. Therefore pretyped
dashboard text cannot become an approval, fallback acknowledgement, SSH
password, or sudo secret. In Textual mode each positive modal action is fenced
while buffered UI input is drained and every other close or activation path
defaults to Deny. Secret-input approval additionally suspends the whole Textual
driver before any viewer can receive input. An active terminal transaction is not forcibly
interrupted; priorities
choose the next owner. Reentrant ownership allows existing approval and SSH
components to use the arbiter through their lock-compatible interface. Parallel
execution never places two password prompts or an approval and password prompt
on `/dev/tty` concurrently. This serialization applies only to human terminal
interaction; the remote command leases continue independently. The Textual
interface handles execution approval, SSH retry, fallback, and secret-input
authorization inside the full-screen driver; secret bytes flow only through
the separately owned external viewer while that driver is suspended.

Separately, up to three authenticated `ssh -N` ControlMaster transports may
remain idle. Reusing a transport never reuses request identity. Queued requests
do not cause connection attempts, health probes, or reconnections.

Before a machine's enrollment master is authenticated, the broker creates a
dedicated per-machine Ed25519 key below the owner-only `~/.ssh/tmuxgate`
directory. This enrollment-only master may fall back to interactive password
or keyboard-interactive authentication. It cannot run a requested command;
over that verified master, the broker idempotently installs only the public key
into the remote account's mode-`0600` `authorized_keys`.
If the remote account deliberately exposes `authorized_keys` as a symlink,
tmuxgate never writes through it. Enrollment succeeds only when the exact
dedicated public key was already installed through a separately trusted
administrative path; otherwise it fails closed.
Enrollment remains part of request execution instead of a separate key-setup
command. This keeps first use bound to the already approved machine, route, and
resolved SSH identity without adding a second administrative surface. The
lifecycle distinguishes local key preparation, authenticated-master readiness,
read-only enrollment inspection, durable enrollment start, verified enrollment,
and transport readiness. A key already present is proven read-only and
introduces no mutation uncertainty. When the key is absent, no remote write is
attempted unless the durable enrollment boundary succeeds. After that boundary,
any nonzero command, lost channel, failed final check, or failed durable
verification prevents same-endpoint retry and route fallback. The result uses
`remote_setup_failure`, not `pre_remote_failure` or `incomplete`, and releases
the in-memory command slot because no requested job was started; the durable
audit record remains available.
After the exact key is verified, the enrollment master is closed and its
control socket is removed. A separate post-enrollment master must then
authenticate with the dedicated public key alone before the request receives a
transport lease. A missing or rejected key therefore fails closed instead of
falling back to another workstation identity or password. Passwords and sudo
credentials are never stored. Automatic viewer presentation forwards terminal
input directly through tmux and SSH; tmuxgate does not read or retain those
bytes.

The transport implementation enforces the retention policy and
exact broker-owned OpenSSH invocation plans. Enrollment authentication is
broker-terminal interactive with `BatchMode=no` and an explicit preference for
public-key, keyboard-interactive, then password authentication. The
post-enrollment master, health checks, control operations, and machine-control
channel prefixes force `BatchMode=yes`, `PreferredAuthentications=publickey`,
and disable password and keyboard-interactive authentication. Every path sets
`IdentityAgent=none`, `IdentitiesOnly=yes`, `PubkeyAuthentication=yes`, and
disables GSSAPI and host-based authentication with the dedicated per-machine
key. SSH resolution and execution environments omit `SSH_AUTH_SOCK`.
Resolution requires the dedicated key to be the sole effective `IdentityFile`
and rejects profile-added `CertificateFile` entries, preventing unrelated
agent, default, or profile keys from broadening authentication. The versioned
policy document binds both enrollment and post-enrollment method sets into
`ssh_policy_sha256`; the resolved agent, identity file, enabled enrollment
methods, policy digest, and exact `ssh -G` arguments are also part of the
approval-bound resolved-identity digest. All invocation categories explicitly
override `RemoteCommand=none`, `RequestTTY=no`, `-T`, configured
hostname/user/port, host-key alias, strict host-key policy, and known-host files. The pool
revalidates the complete resolved identity digest immediately before use. It
retains at most three
mode-`0600` sockets in the private control directory, multiplexes separately
identified job leases on a machine transport, evicts only the least-recent
idle transport, and reconnects expired command masters through the same
enrollment verification followed by public-key-only replacement. The
subprocess backend is enabled only inside
the broker process.

OpenSSH owns its normal password/passphrase attempts through the broker
terminal. Its stderr is captured up to the structured-interface bound; an
oversized or malformed result fails closed without retry. A nonzero
initial-master exit becomes a typed pre-remote failure carrying the numeric
exit status and exact diagnostic bytes. Those bytes remain operator evidence,
are never copied to MCP or durable state, and render inertly with byte length,
SHA-256, and hexadecimal access. The status alone is not classified as an
authentication failure because it may also represent host-key, configuration,
or reachability failure.
Before considering an approved fallback, the executor may offer exactly one
same-endpoint retry. It requires an exact operator decision with Cancel as the
displayed and technical default, keeps the original request and connection-plan
binding, recollects local network evidence, re-resolves SSH policy and host-key
evidence, and requires the approved machine, ordered candidate eligibility,
eligible endpoint order, and
complete resolved SSH identities to remain equal. The retried endpoint must
remain eligible. Volatile observation bytes and their snapshot digest may
change when those security semantics do not. A semantic change fails closed
and requires a fresh request and approval. A subsequently approved fallback
endpoint has its own single-retry bound. Failed-start cleanup removes an owned
control socket only after master shutdown is confirmed; if shutdown fails, the
socket is retained in cleanup-only pool state and shutdown is retried during
the broker lifecycle. Declining or failing the bounded retry starts no remote
command and cannot create durable remote-job state. No local transport,
identity-validation, or control-path error is retried; a typed nonzero OpenSSH
start exit remains opaque except for the terminal diagnostic and numeric
status.

Fallback is offered only while enrollment is proven not to have started.
Local key preparation, master authentication, and the read-only key inspection
can fail before that boundary and retain the normal separately approved
fallback flow. Once `authorized_keys` may have changed, tmuxgate does not
render a fallback prompt claiming `remote_mutation_started = false`, does not
try another endpoint, and does not conceal the first endpoint's mutation.

Only when every eligible endpoint's initial OpenSSH master start and its
broker-terminal-approved retry have failed does the broker offer to disable the
logical machine. The local-only prompt is `Disable machine <alias>? [y/N]` and
defaults to no. Retry denial, fallback denial, plan revalidation failure,
generic local transport failure, and every post-remote failure do not offer
this mutation. A confirmed disable performs a locked, compare-and-swap update
of only that machine's `enabled` flag, preserves unrelated current settings,
and immediately updates the shared runtime availability registry. New and
still-queued requests then fail before network collection, approval, or SSH.
The non-revoking boundary is `BoundRequestPlanner.take()`: an execution that
already consumed its approved plan before the disable was committed may
continue, including if it has not reached remote mutation yet. This avoids
retroactively changing an active execution's approved transport semantics;
already remote-mutating jobs are likewise not cancelled. The machine remains
visible through `list_machines()` with `enabled = false` and can be restored
with `tmuxgate config enable-machine <alias>`.

Canonical local collection is part of the lease gate. Once completion, local
spool verification, viewer detachment, and terminal restoration all pass, a
slow or disconnected Codex-side client may receive A's already-collected bytes
while other isolated jobs progress. Parallelism cannot discard A's canonical
result.

```text
A: authorize -> connect/reuse -> private viewer -> run -> complete -> collect
B: authorize -> connect/reuse -> private viewer -> run -> complete -> collect
C: authorize -> connect/reuse -> private viewer -> run -> complete -> collect
```

## Request state machine

```text
RECEIVED
 -> VALIDATED
 -> QUEUED
 -> LEASE_RESERVED
 -> AWAITING_APPROVAL
    -> DENIED
    -> APPROVED
       -> MASTER_REUSE_CHECK
       -> MASTER_AUTHENTICATING or MASTER_READY
       -> STAGING
       -> GATED_WAITING_FOR_VIEWER
       -> ATTACHING
       -> RUNNING_ATTACHED <-> RUNNING_DETACHED
       -> REMOTE_COMPLETE
       -> WAITING_FOR_VIEWER_DETACH
       -> COLLECTING
       -> COMPLETE_VERIFIED_LOCAL
       -> LEASE_RELEASED
       -> RESULT_DELIVERING
       -> DONE
```

`RECOVERY_REQUIRED_POSSIBLY_RUNNING` is deliberately nonterminal and retains
the lease. A whole-host reboot can also strand `COMPLETION_PROVEN` after the
wrapper status was observed but before canonical output reached the local
spool; destroying the pinned SSH control socket makes collection impossible.
For either state, the broker must be stopped and
`tmuxgate recover after-reboot REQUEST_ID` may record
`ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT` after an exact controlling-terminal
confirmation that the entire logical machine rebooted after the recorded start
time. Stopping the broker retires its process-owned command lease and transport
pin. On restart, a new transport pool can authenticate a fresh SSH master.

This terminal audit state preserves the original start, identity, and job path.
For an uncertain request it retains null completion evidence. For a stranded
completion it copies the prior completion timestamp, exit status, and local
viewer/terminal gates into the failure detail before clearing the structured
unverified-result gates. The resulting record remains compatible with existing
state readers without fabricating canonical output or a verified spool.
Recovery performs no SSH or remote cleanup and is never presented as a command
result. The attestation proves that the old process cannot overlap later work;
it does not prove rollback or exclude partial effects before the reboot, so the
interrupted workflow must be independently verified before it is repeated. A
queued client disconnect cancels its unapproved request. A client disconnect
after approval never kills or reruns the remote job.

`ABANDONED_AFTER_PROVEN_UNSTARTED` is a distinct terminal audit state for a
remote-mutation-boundary failure whose later canonical evidence proves the
start gate remained closed, no command ran or completed, and the exact remote
session/directory were removed. It binds the separate evidence request ID and
verified spool-manifest digest in the failure detail. It never claims a remote
exit status, command output, viewer restoration, or completion.

## Route selection

The client supplies only a validated logical machine alias. Before approval,
the broker takes a local, read-only network snapshot. The implemented
collector uses bounded, broker-owned `ip -j` and NetworkManager commands to
read addresses, link flags/types, routes, the cached gateway neighbor,
connection UUIDs, and the currently associated Wi-Fi BSSID. Wi-Fi scanning is
explicitly disabled. It does not ping, ARP-probe, resolve DNS, probe a port, or
start SSH. Individual collection failures are included in the canonical
snapshot and leave the affected evidence missing so route policy fails closed.

Home LAN eligibility requires all of the following:

- a direct route to the configured home gateway, with no intermediate gateway;
- a selected source address in the configured home subnet;
- the source assigned to the selected interface;
- a direct route to the machine's LAN address on the same interface/source;
- a complete configured fingerprint match: link type, cached gateway MAC,
  NetworkManager connection UUID, and Wi-Fi BSSID when applicable.

For Ethernet, administrative `UP` is insufficient: the snapshot must also show
current `LOWER_UP` carrier. For Wi-Fi, a current matching BSSID is the
association evidence. A stale neighbor entry cannot establish home presence
without one of those current link signals.

Missing evidence fails LAN closed. WireGuard remains eligible when its link is
up, its expected local address is assigned, and the kernel route to the target
uses that kernel-reported WireGuard link and the configured source. No
transient interface name is trusted. The exact private endpoint, local tunnel
address/prefix, link type, route source, and separate SSH host-key evidence all
remain bound into the approved plan.

The approval digest binds the complete ordered endpoint plan and canonical
network snapshot. A material route, host-key evidence, or SSH-configuration
change produces a different plan digest and requires fresh approval. Fallback
is offered only to the next already-approved endpoint, only before remote
mutation, and requires an exact new broker-terminal
`FALLBACK <short-id> <endpoint-id>` acknowledgement. Commands are never
retried.

## SSH identity

All endpoints for one machine use one broker-controlled `HostKeyAlias`, for
example `tmuxgate-app-server`. Strict host-key checking remains enabled. A
first-seen key is handled by OpenSSH in the broker terminal; a mismatch stops.

Every machine-control SSH invocation overrides the workstation's global
interactive settings with `RemoteCommand=none`, `RequestTTY=no`, and `-T`.
Viewer channels use `RemoteCommand=none` and `-tt`.

## Remote isolation and recovery target

Every authorized command receives a validated job ID, a private directory
under `~/.cache/tmuxgate/jobs`, and a dedicated tmux server/session. Its runner
waits on a unique `tmux wait-for` channel until the viewer is attached and that
attachment is verified. The normal `base` session is never touched.

The remote control script starts the packaged runner with a fixed minimal
environment containing only the remote account's `HOME` and the fixed
`/usr/bin:/bin` tool path. The runner does not export submitted environment
entries into its own shell. It retains them as exact `name=value` arguments
until the final command boundary, where `/usr/bin/env -i` applies them only to
the approved argv process or the non-profile script shell, inside any requested
`/usr/bin/timeout` supervision. Consequently values such as `PATH`,
`LD_PRELOAD`, `IFS`, `BASH_ENV`, and `ENV` may intentionally affect the
submitted process but cannot replace or configure tmuxgate's gate, FIFO,
capture, state-publication, hashing, or cleanup tools. Runner control-plane
utilities use fixed absolute paths where practical.

The primary argv process or script shell starts as the leader of a dedicated
session and process group; configured `/usr/bin/timeout` supervision runs
inside that same boundary. After the primary process exits, the runner sends
`TERM` to every remaining member, allows one second for orderly shutdown, and
then sends `KILL` to the group. Timeout, capture-quota termination, viewer
Ctrl-C, and unexpected runner exit use the same descendant boundary. This is a
command lifecycle, not a service supervisor: a descendant can deliberately
escape by creating another session, but it cannot make retained output
descriptors look like successful completion.

stdout and stderr are drained through separate bounded FIFO pipelines to raw
result files while remaining visible in the pane. Each pipeline admits at most
its configured stream limit plus one sentinel byte, and a concurrent monitor
checks the combined per-job remote-capture ceiling while the submitted command
runs. Any independent or combined overrun publishes
`capture-limit-exceeded`, omits the exit-status file, and cannot become proven
completion. This bounds each raw file and actively monitors combined remote
disk growth. `capture-pane` is not a canonical result source.

The two capture pipelines also run in dedicated process groups. Once the
submitted process group has been terminated, the runner allows at most two
seconds for buffered stdout and stderr to reach their canonical files. If both
collectors do not finish, including when a detached or double-forked process
retains a FIFO writer, the runner terminates the complete collector groups,
unlinks both FIFOs, atomically publishes `capture-incomplete`, and omits the
exit-status file. The coordinator therefore enters recovery-required state and
cannot collect, verify, spool, or clean the job as a successful result. A
descendant that escapes only after closing both streams may continue outside
tmuxgate's command boundary, but it has no descriptor that can append to the
canonical streams. `complete` and its exit status are published only after the
submitted group is gone and both collectors have finished, so no descendant
can append canonical output after result publication. The policy and ordering
are identical for argv and script modes.

The real backend implements this lifecycle; fake and real-local-tmux tests
exercise the same scripts. A durable start permit is required before staging. The coordinator
proves the dedicated session is gated, proves at least one viewer is attached,
and only then releases the unique wait channel. A running viewer accepts input
and Ctrl-C and can detach/reattach without affecting another job. Completion
closes its pane/viewer automatically; collection requires the remote exit status,
both byte counts, and both SHA-256 digests to match the separately collected
raw streams. Collection no longer transports a complete tar archive. Fixed
`collect-stdout` and `collect-stderr` controls stream the two canonical files
over separate batch channels into newly created owner-only local temporary
files. Each SSH pipe is drained incrementally with receive-time byte and
diagnostic ceilings; hashes and sizes are accumulated as bytes arrive. The
collector rejects a stream, total, per-job local-space, or shared aggregate
reservation before publication. The shared reservation object serializes all
active jobs, so three parallel commands cannot each consume the full aggregate
allowance.

The canonical local spool copies those private files with no-follow opens and
bounded blocks into a private temporary result directory. It verifies owner,
mode, size, and receive-time SHA-256 evidence while copying, fsyncs both raw
streams and the manifest, and publishes only by atomic directory rename. Local
write failure, transport truncation, limit failure, changed source evidence,
or interruption removes the unpublished collection/spool temporary files and
never marks durable state spool-verified. Missing sessions, mismatched output,
quota failures, or ambiguous completion enter recovery-required state; remote
cleanup remains disallowed until verified collection so evidence is retained
for inspection and recovery.

The `[limits]` configuration table defines independent stdout and stderr
ceilings, total-result bytes, per-job local temporary bytes, remote per-job
captured bytes, and aggregate local collection bytes. Limits are inclusive:
exactly at the boundary succeeds and one byte over fails closed. The packaged
Bash runner retains pane stdin, uses separate mode-`0600` FIFOs and bounded
capture pipelines, writes the exit status only after both collectors finish,
terminates inherited-descriptor holders at the process-group boundary, seals an
ambiguous drain as incomplete, and cleans up failed-gate FIFOs without
manufacturing completion. Tests also execute the exact staging shell and
lifecycle in a private real local tmux server, including a background child
that retains stdout. The first approved remote job completed successfully on
July 19, 2026.

Broker/SSH failure does not rerun the command. State is reported as incomplete
unless completion and exit status can be proven. Cleanup validates the exact
parent and job ID and refuses active or uncertain jobs. A full machine reboot
can instead be recorded as operator-confirmed abandonment, without an invented
exit status or canonical result; stale remote job residue remains untouched
until a later independently approved cleanup can prove it inactive.
Because older tmuxgate builds do not recognize this terminal state, the
installed source must not be downgraded after recording one.

Every irreversible transition must be atomically written and fsynced under the
durable state boundary. The implemented state API requires the local record to
say `REMOTE_MAY_BE_RUNNING` before it returns a remote-start permit, so the
boundary precedes remote directory staging as well as command start. Startup
loads and reconciles durable state and refuses new approvals while any job is
corrupt, missing required evidence, possibly running, or not through every
completion/spool/viewer/terminal gate. The real coordinator consumes that
permit and recovery report; bypassing them is not an allowed executor design.
