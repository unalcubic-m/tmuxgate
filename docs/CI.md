# Continuous integration

CI runs isolated unittest discovery on Python 3.11, 3.12, and 3.13 on both
Ubuntu and native Windows. Ubuntu executes the Linux remote shell wrapper
through fake SSH, tmux, and sudo programs. Those shell-dependent cases are
explicitly skipped on Windows. Portable protocol tests launch a Python fake
SSH process, preserving native subprocess creation, binary stdin/stdout/stderr,
POSIX remote argument quoting, cancellation, and conservative recovery.

Windows-specific tests use actual DACLs, owner SIDs, hardlinks, and directory
junctions. They reject broad, inherited, null, and wrong-owner security, and
exercise flush/rename failures and exclusive publication. Both platforms run
an installed foreground broker on loopback, verify authentication and the same
eight MCP tools, and test interprocess locking and crash release. Windows CI
isolates USERPROFILE, APPDATA, and LOCALAPPDATA; Linux isolates HOME and XDG
paths. Every state directory is temporary and all credentials are synthetic.

The quality job runs:

```bash
ruff check src tests
pyright --pythonplatform Linux
pyright --pythonplatform Windows
shellcheck src/tmuxgate/assets/remote_job.sh
coverage combine
coverage report
PYTHONPATH=src:tests python -m unittest test_ci_policy -v
```

Third-party GitHub Actions must be pinned to full commit hashes.
Coverage counters from all matrix jobs are combined with relative source
paths before enforcing the existing 75% gate; Windows code is measured on
Windows rather than excluded from coverage. The quality job retains Linux
shellcheck and shell syntax validation.

The package job installs the project without development dependencies, runs the
CLI outside the checkout on Ubuntu and Windows, and reads an empty durable job
list from isolated platform-default directories.

Real SSH and sudo validation is deliberately separate from CI. CI credentials
must never contact configured machines or contain a real bearer token or sudo
password.
