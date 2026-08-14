# Security policy

tmuxgate handles MCP bearer authentication, command authorization, SSH
identity, interactive credential forwarding, remote process state, and
captured output. Please treat suspected vulnerabilities as sensitive.

## Supported versions

Until the first stable release, only the latest commit on `main` is supported.
Older development snapshots do not receive security backports.

## Reporting a vulnerability

Do not open a public issue, discussion, or pull request containing exploit
details.

Use GitHub's private vulnerability reporting for this repository when it is
available. If GitHub does not offer that option, contact the repository owner
through the [maintainer's GitHub profile](https://github.com/unalcubic-m)
without including vulnerability details and request a private reporting
channel.

Include, when possible:

- the affected commit or version;
- the violated security invariant;
- minimal reproduction steps;
- whether remote execution or credential exposure occurred; and
- suggested mitigations or tests.

Reports involving MCP authentication bypass, non-loopback exposure, token
disclosure, approval bypass, same-UID peer validation, request or route binding,
terminal-control injection, SSH option injection, host-key verification, credential capture, durable-state
corruption, recovery overlap, result-spool integrity, or unsafe remote cleanup
are especially important.

The maintainer will acknowledge a report as availability permits, investigate
it privately, and coordinate disclosure after a fix or mitigation is ready.
No response-time guarantee is currently offered.

## Threat-model boundary

tmuxgate is an accident-prevention and approval workflow, not a privilege
boundary, when the client and broker run as the same Unix user. Reports that
assume a same-user client cannot read that user's files (including the MCP
token), inspect processes, access the Unix socket, or access SSH credentials
are outside the documented boundary unless they also demonstrate a violation
of a stated tmuxgate invariant.

## Terminal presentation and input boundary

The default Textual dashboard is presentation, not authority. Structured
operator prompts retain their immutable request and route bindings outside the
rendered widget tree. MCP and Unix-socket frames, remote stdout/stderr, OpenSSH
diagnostics, tmux pane text, ANSI controls, terminal links, and Textual markup
are untrusted data: they are escaped and cannot create widgets, key events, or
decisions. Only deliberate input from the one validated foreground controlling
terminal may resolve a prompt. Deny, Cancel, or Keep enabled is the focused
default until the stale-input fence elapses; after it, execution approval and
secret-input authorization focus their positive action so one Return commits
the routine decision, while SSH retry, adjacent-route fallback, and
machine-disable keep the safe action focused. Escape always takes the safe
action, and a terminal below the documented minimum keeps the safe action
focused regardless of the fence.

The TUI revalidates terminal identity and foreground process-group ownership
throughout its lifetime. Startup or runtime loss fails the unified application
closed and never changes approval policy or starts a plain replacement;
`tmuxgate --plain` must be chosen explicitly on restart. A terminal below the
documented 72×20 minimum keeps the safe action visible and disables positive
actions until complete evidence is visible again.

Terminal access follows the connection's own declared policy. Only the
prompt-capable enrollment master is given the controlling terminal; the
post-enrollment command master runs with `BatchMode=yes`, public-key-only
authentication, and a passphrase-less dedicated key, so it cannot prompt and is
started with no terminal at all. Both handoffs — SSH authentication and secret
input — reserve the same single exclusive ownership slot and suspend the
full-screen interface before a trusted process reads.

Manual secret input is a separate ownership boundary. After an exact request-,
command-, route-, endpoint-, and viewer-bound authorization, Textual leaves
application mode and stops reading the terminal before the trusted external
viewer receives `/dev/tty`. In automatic mode, an exact default sudo prompt for
the resolved SSH user may instead receive the owner-only stored per-machine
password once. Manual bytes are not retained; stored bytes are kept only in the
mode-`0600` credential file and a short-lived private tmux buffer.

## Interactive remote execution

A remote command has a controlling terminal only when the approved request set
`interactive = true`. That flag is stated by the client, never inferred from the
command text or from remote output, and it is inside the client-request digest,
so it binds the execution approval and each later handoff authorization. A
non-interactive command runs in a session with no controlling terminal and
cannot open `/dev/tty` at all; prompt detection and terminal handoff are not
offered for it.

With Automation on, approving an interactive Codex request also authorizes one
stored-password submission if its viewer emits the exact resolved-user sudo
prompt. Prompt text cannot prove that the remote program really is sudo, so an
accepted interactive command can deliberately imitate that prompt and consume
the stored password; Codex approval is therefore the security decision for
both command execution and this credential use. Automation off restores the
second single-request handoff decision. Passwords never enter captured
stdout/stderr, the verified result spool, durable job records, activity text,
child arguments, or environment. tmuxgate still does not support `sudo -S`,
piped passwords, or environment-supplied passwords.

The residual risk is inherent to a handoff: while attached, the remote program
receives the operator's keystrokes, and suppressing echo is that program's
responsibility. `sudo` does it; tmuxgate cannot guarantee it for an arbitrary
command, and anything a program echoes becomes pane text. Reports that show
prompt detection authorizing input on its own, a handoff reaching a request that
did not ask for interactive execution, typed bytes appearing in any recorded
stream or durable record, or an interactive job escaping its process-group
termination boundary are security-boundary reports.

## Installer security boundary

Run `./install.sh` only from source you have reviewed and as the target user,
never with `sudo`. It downloads the declared Python dependencies into a
private, versioned virtual environment and does not require Node.js. It verifies
the staged installation before atomically replacing a recognized legacy or
managed launcher. An unrelated launcher and a conflicting Codex MCP entry are
refused unless the operator supplies the corresponding explicit replacement
flag.

The installer preserves the existing owner-only configuration, durable state,
result spool, and MCP token. It registers only the token environment-variable
name with Codex. Its Bash loader contains no credential: it reads and validates
the token from the owner-only state file whenever a new shell starts. A new
Bash shell and Codex restart are therefore required, and the token remains as
sensitive as the SSH authority reachable through tmuxgate. Installer child
processes do not inherit that token or Python path/virtual-environment
overrides. The owner-controlled Codex home is hardened to mode `0700` before
registration.

Backups of modified Codex configuration and shell profiles are stored with
owner-only permissions below `$XDG_DATA_HOME/tmuxgate/backups`; those backups
may contain other user configuration secrets and should be protected
accordingly. Managed files and symlinks are rolled back only while their exact
installer post-images remain, so rollback does not overwrite concurrent edits.
A newly created MCP token remains durable state after a later failure, and a
possibly observed versioned release is retained rather than deleted underneath
a running process.
The installer does not start, stop, or kill tmuxgate: all approval,
authentication, recovery, attachment, and cleanup interaction remains owned by
the foreground application and its controlling terminal.

Normal command transports never inherit an SSH agent or permit password,
keyboard-interactive, GSSAPI, or host-based fallback. The prompt-capable
connection is limited to the dedicated-key enrollment protocol and is replaced
by a public-key-only master before any requested command starts. Reports that
show another identity or authentication method can influence a post-enrollment
connection are security-boundary reports.

Installation does not change `approval_mode` and accepts the default automatic
mode. Anyone who obtains the MCP token can submit commands without a
per-request terminal approval and can consume a stored sudo password through a
matching interactive prompt. Use the dashboard Automation switch or the
file-based policy `always` when tmuxgate-terminal confirmation is required.
