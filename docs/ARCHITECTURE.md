# tmuxgate architecture

## Process boundary

The public architecture has two roles:

1. `tmuxgate broker` owns SSH authentication, private per-job local viewers,
   private SSH control sockets, job state, optional approval UI, and result
   collection.
2. `tmuxgate exec` and `tmuxgate script` are noninteractive Unix-socket clients.
   They submit structured requests and block for their own result.

`approval_mode = "disabled"` is the default and performs no confirmation
prompt. `approval_mode = "always"` enables the approval UI; in that mode,
approval is read only from the broker's `/dev/tty` and socket data is never
used as terminal input.

When enabled, the approval display is a compact decision card: advisory purpose,
logical machine, selected route and resolved identity, host-key status,
working directory, exact shell-escaped argv or script identity/source,
environment, timeout, and human-readable advisories. Enter/`y` approves, `n`
denies, `c` opens the exact structured argv or complete escaped script, and `d`
opens the exhaustive network/SSH-policy/evidence/binding record. Both views use
the sealed secure pager and return to the same prompt. Approval is still read
only from the broker's `/dev/tty`; pager output, socket/client data, process
stdin, and client-supplied purpose text can never answer the prompt.

Running `tmuxgate` without a subcommand opens the local terminal dashboard.
Its guided settings actions read, validate, and atomically replace the
owner-only TOML configuration; machine aliases and endpoints are configuration,
not source-code constants. Direct-home enrollment requires complete local
link, source-address, route, router-neighbor, and NetworkManager identity
evidence and refuses a routed WireGuard view. When the otherwise-proven direct
gateway lacks a cached neighbor entry, enrollment alone may send one bounded
ICMP request to that configured gateway, then recollect and re-prove the full
snapshot before publication. Ordinary planning remains passive. These settings
actions do not open SSH or mutate a remote machine.

Each client sends exactly one request frame, then shuts down its socket's write
side. The broker requires that EOF before considering the request complete;
multiple result frames may flow in the opposite direction. Frame reads have a
bounded deadline, and argv/cwd/environment filesystem bytes are base64 fields
inside the JSON header so non-UTF-8 bytes survive exactly.

### Current implementation boundary

The public broker composes the local socket boundary, one-shot bound planner,
real broker-owned OpenSSH master/channels, durable state, dedicated remote tmux
jobs, canonical result spool, and client delivery. `--fake` remains available
for local tests. Successful jobs auto-collect and auto-clean. Local `collect`
replays a checksummed spool. `attach` enters an active request's private local
viewer without issuing a new remote command. Standalone remote `cleanup`
remains deliberately disabled and fail closed until its broker-control
protocol is implemented.

Ephemeral socket, control, and singleton-lock files live below
`$XDG_RUNTIME_DIR/tmuxgate`. The durable boundary is
`$XDG_STATE_HOME/tmuxgate` (default `~/.local/state/tmuxgate`) with an
owner-only spool. The owner-only durable job store now uses checksummed,
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

The complete approval document can now bind the exact client request to the
ordered route plan, canonical network-snapshot digest, strict `ssh -G`
identity, SSH policy digest, host-key alias/evidence, proxy configuration, and
fallback order. The connection-plan component resolves every eligible fallback
up front and fails the entire plan if any resolved identity is inconsistent.
The one-shot planner now composes collection, route policy, `ssh -G`
resolution, and optional bound terminal approval without opening SSH. An
authorized context contains only the request digest and immutable plan, is
consumed once, and multiple request-bound contexts may await parallel executor
workers.

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

Each SSH viewer runs in a separate owner-only local tmux server below the
runtime directory. A broker-owned monitor checks only the visible cursor row of
each viewer for a password or passphrase prompt; this deliberately ignores the
nested remote tmux status row below it. Matching viewers enter one shared
FIFO presenter and attach to the broker's `/dev/tty` one at a time. The prompt
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
A deliberate detach is not automatically reversed while the same prompt
remains continuously visible; a cleared prompt followed by a new prompt begins
a new episode. This avoids both premature time-based detachment and
interception of password bytes. Prompt or marker probe failure attempts a
targeted detach fail-closed. If targeted tmux detach fails, the presenter
terminates and reaps the exact local attach process before releasing the
terminal lock, then reports the presenter error.

Before displaying its operator notice, the presenter revalidates the opened
PTY and discards only input bytes that were already queued on the broker
terminal. It then writes the notice and starts attachment without a second
input flush. This prevents an earlier dashboard keystroke from becoming a
password submission while preserving input typed in response to the notice.
Output is not flushed, and input continues directly to the viewer. Detection
does not inspect canonical stdout/stderr or store input.
`tmuxgate attach REQUEST_ID` remains available for arbitrary interaction,
inspection, Ctrl-C, or manual detach. Lost viewers are recreated automatically.
Normal completion closes the remote pane and local viewer automatically;
canonical capture does not depend on pane history.

One process-local terminal lock serializes the optional approval UI, fallback
approval, interactive first-master SSH authentication, and automatic prompt
presenter. Thus parallel execution never places two password prompts or an
approval and a password prompt on `/dev/tty` concurrently. This serialization
applies only to human terminal interaction; the three remote command leases
continue independently.

Separately, up to three authenticated `ssh -N` ControlMaster transports may
remain idle. Reusing a transport never reuses request identity. Queued requests
do not cause connection attempts, health probes, or reconnections.

Before a machine's first master is authenticated, the broker creates a
dedicated per-machine Ed25519 key below the owner-only `~/.ssh/tmuxgate`
directory. The first master may fall back to interactive password
authentication. Over that verified master, the broker idempotently installs
only the public key into the remote account's mode-`0600` `authorized_keys`.
If the remote account deliberately exposes `authorized_keys` as a symlink,
tmuxgate never writes through it. Enrollment succeeds only when the exact
dedicated public key was already installed through a separately trusted
administrative path; otherwise it fails closed.
Subsequent masters explicitly select that key. Passwords and sudo credentials
are never stored. Automatic viewer presentation forwards terminal input
directly through tmux and SSH; tmuxgate does not read or retain those bytes.

The transport implementation enforces the retention policy and
exact broker-owned OpenSSH invocation plans. Initial master authentication is
marked as broker-terminal interactive with `BatchMode=no`; health checks,
control operations, and future machine-control channel prefixes force
`BatchMode=yes`. All of them explicitly override `RemoteCommand=none`,
`RequestTTY=no`, `-T`, configured hostname/user/port, host-key alias, strict
host-key policy, and known-host files. The pool revalidates the complete
resolved identity digest immediately before use. It retains at most three
mode-`0600` sockets in the private control directory, multiplexes separately
identified job leases on a machine transport, evicts only the least-recent
idle transport, and reconnects expired masters
through the interactive path. The subprocess backend is enabled only inside
the broker process.

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
the lease. If the operator later performs a full reboot of the exact logical
machine, the broker must be stopped and `tmuxgate recover after-reboot` may
record `ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT` after an exact controlling-
terminal confirmation. This terminal audit state preserves the original start,
identity, job path, and failure detail while explicitly retaining null exit,
completion, and spool evidence. It performs no SSH or remote cleanup and is
never presented as a command result. The attestation proves that the old
process cannot overlap later work; it does not prove rollback or exclude
partial effects before the reboot, so the interrupted workflow must be
independently verified before it is repeated. A queued client disconnect cancels its
unapproved request. A client disconnect after approval never kills or reruns
the remote job.

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

stdout and stderr will be drained through separate FIFOs and tee processes to
raw result files while remaining visible in the pane. `capture-pane` is not a
canonical result source.

The real backend implements this lifecycle; fake and real-local-tmux tests
exercise the same scripts. A durable start permit is required before staging. The coordinator
proves the dedicated session is gated, proves at least one viewer is attached,
and only then releases the unique wait channel. A running viewer accepts input
and Ctrl-C and can detach/reattach without affecting another job. Completion
closes its pane/viewer automatically; collection requires the remote exit status,
both byte counts, and both SHA-256 digests to match the separately collected
raw streams. Missing sessions, mismatched output, or ambiguous completion enter
recovery-required state, and cleanup is allowed only after verified collection.
The canonical local spool publishes a result only by atomically renaming an
owner-only directory after both raw streams and a checksummed manifest have
been written and fsynced. It detects stream/manifest corruption, rejects unsafe
modes, symlinks, unexpected entries, and conflicts, and treats a pre-publish
interruption as incomplete rather than visible.
The packaged Bash runner retains pane stdin, uses separate mode-`0600` FIFOs and
tee processes, writes the exit status only after both tees finish, and cleans up
failed-gate FIFOs without manufacturing completion. Tests also execute the
exact staging shell and lifecycle in a private real local tmux server. The first
approved remote job completed successfully on July 19, 2026.

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
