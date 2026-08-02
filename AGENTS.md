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

## Security & Configuration

Preserve fail-closed behavior: clients provide logical machine names, never SSH options or endpoints, and approval remains broker-terminal-owned. Never commit real host addresses, credentials, known-host data, runtime state, or user configuration. Document any change to approval binding, route evidence, durable state, or remote cleanup in `docs/ARCHITECTURE.md`.

### DevWorkstation installation policy

The operator has explicitly chosen `approval_mode = "disabled"` for this development workstation. When running the user-scoped installer on DevWorkstation, preserve that setting and pass `--allow-disabled-approvals`; do not change it to `always`. Treat this as a workstation-specific development decision that must not weaken repository defaults, examples, tests, or behavior on other machines.
