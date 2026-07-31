# Security policy

tmuxgate handles command authorization, SSH identity, interactive credential
forwarding, remote process state, and captured output. Please treat suspected
vulnerabilities as sensitive.

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

Reports involving approval bypass, same-UID peer validation, request or route
binding, SSH option injection, host-key verification, credential capture,
durable-state corruption, recovery overlap, result-spool integrity, or unsafe
remote cleanup are especially important.

The maintainer will acknowledge a report as availability permits, investigate
it privately, and coordinate disclosure after a fix or mitigation is ready.
No response-time guarantee is currently offered.

## Threat-model boundary

tmuxgate is an accident-prevention and approval workflow, not a privilege
boundary, when the client and broker run as the same Unix user. Reports that
assume a same-user client cannot read that user's files, inspect processes, or
access SSH credentials are outside the documented boundary unless they also
demonstrate a violation of a stated tmuxgate invariant.
