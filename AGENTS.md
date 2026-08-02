# Repository Guidelines

## Project Structure & Module Organization

`tmuxgate` is a Python 3.11+ package using a `src/` layout. Production code lives in `src/tmuxgate/`; `cli.py` and `__main__.py` expose the command-line interface, while broker, transport, approval, planning, state, and remote-execution concerns are separated into focused modules. Packaged shell helpers are under `src/tmuxgate/assets/`. Tests mirror these modules in `tests/test_*.py`. See `docs/ARCHITECTURE.md` before changing lifecycle or security behavior, and use `examples/config.toml` only as a non-secret configuration example.

## Build, Test, and Development Commands

- `PYTHONPATH=src python3 -m tmuxgate --help` runs the CLI directly from the checkout.
- `PYTHONPATH=src python3 -m unittest discover -s tests -v` runs the complete test suite.
- `PYTHONPATH=src python3 -m unittest tests.test_models -v` runs one test module during focused development.
- `python3 -m build` creates package artifacts when the optional `build` frontend is installed.

Runtime dependencies, including the official Python MCP SDK and Uvicorn, are declared in `pyproject.toml`; install the package before running tests directly from the checkout. Some integration tests require local Linux facilities such as Unix sockets, PTYs, OpenSSH, or tmux; keep unit tests deterministic and isolated from real remote hosts.

## Coding Style & Naming Conventions

Follow the existing Python style: four-space indentation, type annotations, concise module docstrings, and immutable `@dataclass(frozen=True, slots=True)` value objects where appropriate. Use `snake_case` for modules, functions, and variables; `PascalCase` for classes; and `UPPER_SNAKE_CASE` for constants. Prefer standard-library solutions and explicit validation at trust boundaries. There is no configured formatter or linter, so keep imports grouped consistently and review diffs for readability.

## Testing Guidelines

Tests use `unittest.TestCase`. Name files `test_<module>.py`, classes `<Subject>Tests`, and methods `test_<expected_behavior>`. Add regression tests for every bug fix, including failure paths and exact byte-preservation behavior where relevant. Run the full suite before submitting changes.

## Commit & Pull Request Guidelines

Use short, imperative commit subjects such as `Reject stale route evidence`. Keep commits narrowly scoped. Pull requests should explain the behavior change, security implications, and tests run; link relevant issues and include sanitized terminal output or screenshots when CLI/approval UI behavior changes.

## Concurrent Codex Sessions & Worktrees

Never let two active Codex sessions edit the same Git worktree. Every concurrent
session must have its own sibling worktree and dedicated branch before it edits
files. The original checkout may be assigned to one session; create sibling
worktrees for all others with `git worktree add`, outside the repository
directory.

At the beginning of a session and before any write or Git operation:

- Run `pwd`, `git branch --show-current`, `git status --short`, and
  `git worktree list`.
- Treat all pre-existing changes as owned by the session assigned to that
  worktree. Do not modify, stage, restore, stash, or commit them unless that
  ownership is explicitly transferred.
- If another active session is using the same path, stop before editing and
  move this session to a separate worktree.
- Record which worktree and branch this session owns, and perform every command
  from that path. Never edit another session's worktree.
- Stage only explicit paths owned by this session. Do not use `git add .`,
  `git add -A`, broad restore/reset/clean operations, or shared stashes.
- Do not switch branches in a worktree assigned to an active session. Do not
  remove or prune an active session's worktree.
- If two branches need the same file, coordinate ownership first and integrate
  through commits, rebasing, or cherry-picking after one side is complete;
  never resolve it through simultaneous filesystem edits.

Tests may run concurrently when they use repository-provided isolated temporary
resources. Any operation that affects shared state outside a worktree must be
performed by one designated session at a time.

## Security & Configuration

Preserve fail-closed behavior: clients provide logical machine names, never SSH options or endpoints, and approval remains broker-terminal-owned. Never commit real host addresses, credentials, known-host data, runtime state, or user configuration. Document any change to approval binding, route evidence, durable state, or remote cleanup in `docs/ARCHITECTURE.md`.
