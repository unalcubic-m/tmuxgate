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

Installation does not change `approval_mode`. When it is `disabled`, anyone
who obtains the MCP token can submit commands without a per-request terminal
approval. The installer refuses Codex integration in this condition unless the
operator explicitly supplies `--allow-disabled-approvals`; use the file-based
policy `always` when terminal confirmation is required.
