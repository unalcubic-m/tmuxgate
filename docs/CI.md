# Continuous integration

CI runs the complete isolated unittest suite on Python 3.11, 3.12, and 3.13.
The process-level remote double replaces only the external SSH, tmux, and sudo
programs; production code still launches normal subprocesses.

The quality job runs:

```bash
ruff check src tests
pyright
shellcheck src/tmuxgate/assets/remote_job.sh
coverage run -m unittest discover -s tests
coverage report
PYTHONPATH=src:tests python -m unittest test_ci_policy -v
```

It also asserts that removed source and custom installation paths have not
returned. Third-party GitHub Actions must be pinned to full commit hashes.

The package job installs the project without development dependencies, runs the
CLI outside the checkout, and reads an empty durable job list from isolated XDG
directories.

Real SSH and sudo validation is deliberately separate from CI. CI credentials
must never contact configured machines or contain a real bearer token or sudo
password.
