# Contributing

Use Python 3.11 or newer and keep the implementation focused on automatic,
noninteractive remote execution.

```bash
python3 -m pip install -e '.[dev]'
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
ruff check src tests
pyright
shellcheck src/tmuxgate/assets/remote_job.sh
```

Tests use `unittest.TestCase` and should describe observable behavior at the
SSH/tmux boundary. Use temporary local resources and never contact a real host
from a unit test. Every bug fix needs a regression test, including failure and
secret-handling paths.

Preserve the core invariants:

- exact configured machine aliases;
- ordinary OpenSSH policy and fatal host-key verification;
- exactly one remote tmux session per job;
- stdin closed from `/dev/null`;
- local collection before `complete` and cleanup only afterward;
- no automatic rerun of possibly-started work;
- sudo passwords only through SSH stdin;
- exactly four MCP tools and one concurrency semaphore of three.

Keep commits narrow with imperative subjects. Pull requests should explain
behavior, security effects, deletion impact, tests, and any real-machine checks.
Update `docs/ARCHITECTURE.md` whenever execution lifecycle, job recovery,
credential handling, or authentication changes.
