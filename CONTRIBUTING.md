# Contributing to tmuxgate

Thank you for helping improve tmuxgate. This project sits on a sensitive trust
boundary, so changes should be small, explicit, and backed by failure-path
tests.

## Development setup

tmuxgate requires Linux and Python 3.11 or newer. Its declared runtime
dependencies include the official Python MCP SDK and Uvicorn; the editable
install below installs them with the package.

```bash
git clone https://github.com/unalcubic-m/tmuxgate.git
cd tmuxgate
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
```

Some tests require local Unix sockets, PTYs, OpenSSH tools, and tmux. The test
suite must not contact real remote machines or depend on a developer's SSH
configuration, credentials, network, or tmux sessions.

See [docs/CI.md](docs/CI.md) for the exact required pull-request checks,
coverage threshold, pinned tooling, isolation contract, intentional platform
prerequisites, and commands for reproducing each gate.

## Making a change

1. Open an issue first for a large feature, protocol change, or security-model
   change.
2. Keep the change focused and preserve fail-closed behavior.
3. Add regression tests for successful and rejected paths, including exact
   byte handling where relevant.
4. Update `docs/ARCHITECTURE.md` when changing approval binding, route
   evidence, SSH policy, durable state, remote execution, collection, cleanup,
   or recovery.
5. Run the complete test suite and applicable quality gates before opening a
   pull request.

Follow the existing Python style: four-space indentation, type annotations,
standard-library solutions, explicit validation at trust boundaries, and
immutable value objects where appropriate. Use short imperative commit
subjects.

## Pull requests

Pull requests should explain:

- what changed and why;
- security and failure-mode implications;
- compatibility or migration impact; and
- the exact checks that passed.

Never include real host addresses, usernames, network fingerprints, host keys,
credentials, runtime state, result spools, or private configuration in a pull
request, issue, test fixture, screenshot, or log.

## Security reports

Do not open a public issue for a suspected vulnerability. Follow
[SECURITY.md](SECURITY.md) instead.

By contributing, you agree that your contribution is licensed under the
project's [GNU General Public License v3.0 only](LICENSE).
