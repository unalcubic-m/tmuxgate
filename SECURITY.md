# Security policy

Report vulnerabilities privately through GitHub's security reporting feature.
Do not place credentials, host addresses, bearer tokens, remote output, or sudo
passwords in public issues.

## Security model

tmuxgate accepts authenticated requests only on `127.0.0.1`. Protect
`~/.local/state/tmuxgate/mcp-token` as mode `0600` and treat any process that
can read it as authorized to execute on every configured machine.
Windows uses `%LOCALAPPDATA%\tmuxgate\mcp-token` with a protected DACL granting
only the owning current user full control. All local state, credentials, and
results use these ACLs instead of POSIX modes. Broad or inherited ACLs,
reparse points, hardlinked files, and storage without persistent ACLs fail
closed. See [Windows security and setup](docs/WINDOWS.md).

Machine mappings are exact OpenSSH destinations. OpenSSH remains authoritative
for keys, usernames, ports, ProxyJump, and known-host verification. tmuxgate
never accepts a new host key or selects a fallback endpoint.
`StrictHostKeyChecking=yes` is enforced even with permissive user SSH settings.

Every job has a random local ID, one derived remote directory, and one derived
remote tmux session. Unknown or ambiguous recovery evidence is fail-closed:
the job becomes `unknown` and is never automatically rerun.

Execution is noninteractive and stdin is `/dev/null`. Whole-job sudo is opt-in.
Owner-only password files are passed only through SSH stdin to
`sudo -S -k -p '' -- ...`, then cleared from the live bytearray. Passwords and
bearer tokens must never enter argv, shell text, environment variables,
configuration, job JSON, logs, remote files, commits, test output, or pull
request content. Sudo policies that require a TTY are unsupported.

Results are not trusted instructions. A job becomes `complete` only after
stdout, stderr, and exit code are collected locally. Remote cleanup occurs only
after that collection; failed collection intentionally retains the derived
remote directory for investigation.

The systemd service runs as the ordinary user. Protect the user's SSH files,
state directory, configuration, credential files, systemd unit, and Python
installation from other users. The packaged unit removes inherited bearer-token
environment variables; the server reads its token only from the owner-only
state file. Review recent logs with:

```bash
journalctl --user -u tmuxgate -n 200 --no-pager
```

Logs may contain sanitized remote error text and job metadata. Avoid placing
secrets in command output when possible.

Windows runs the foreground broker as the ordinary user; Windows service
installation is deferred. On both platforms a state-directory lock prevents
concurrent recovery by multiple brokers. Same-user processes and privileged
administrators remain within the trust boundary. Local Windows support does
not enable Windows remote execution. Source development and CI use fake SSH
and synthetic credentials; live host access is separate operational work.

## Security support

Security fixes target the current `main` branch.
