# CI security gates

Every pull request must pass these GitHub Actions job names before merge:

- `Python 3.11`, `Python 3.12`, and `Python 3.13`
- `Quality and supply chain`
- `Adversarial coverage`
- `Package smoke test`

Repository rules should require those names. The jobs are deliberately split so
a compatibility failure, a source-quality failure, an adversarial-test failure,
and a packaging failure are distinguishable.

## Enforced checks

`Quality and supply chain` runs Ruff over `src`, `tests`, and `scripts` with the
explicit `E4`, `E7`, `E9`, and `F` rule families. It runs Pyright in basic mode
over the currently clean request-model, protocol, route-evidence,
connection-plan, scheduler, and result boundaries. That module list is a
visible staged baseline in `pyproject.toml`; expanding it must not be traded for
blanket ignores. Remaining production modules are not represented as type-clean
until their existing findings are resolved.

The same job runs ShellCheck over the installer, launcher, and both packaged
remote shell assets. The one suppression in `remote_runner.sh` is limited to
SC2317 on the function invoked indirectly by an `EXIT` trap. It also runs a
regression that rejects every third-party `uses:` reference not pinned to a
full 40-character commit SHA. Human-readable version comments are advisory;
the SHA is the supply-chain identity. Dependabot remains responsible for
proposing reviewed Action updates.

`Adversarial coverage` runs the complete unittest suite with statement and
branch measurement. The enforced project threshold is 75.0 percent. The
threshold is below the initial measured result to tolerate small changes while
still preventing a large unreviewed coverage loss; it should rise as uncovered
failure branches receive tests and must not be lowered without PR rationale.
Hypothesis generates valid frames, arbitrary malformed bytes, truncations, and
trailing data at the protocol boundary. A rule-based durable-store model checks
generation and on-disk invariants, while injected open, write, file-fsync,
replace, and directory-fsync failures check publication behavior.

Each external checker is first run against a controlled violation and the job
fails if that violation is accepted. The Action-pin regression likewise has a
mutable-tag fixture, coverage is challenged with an impossible controlled
threshold, and injected durable-write failures must be observed before their
postconditions are checked. These are checker regressions, not exceptions to
the real gates.

`Package smoke test` installs only the normal project, without the `dev` extra,
changes out of the source checkout, and exercises the installed `tmuxgate`
entry point. This prevents `PYTHONPATH=src` from masking a broken wheel or
console-script installation. Development-only tools therefore never become
runtime dependencies.

## Isolation and prerequisites

CI is Linux-only because integration tests use Unix sockets, PTYs, OpenSSH,
tmux, and the util-linux `script` command. The Python matrix verifies those
tools explicitly. ShellCheck is an intentional Ubuntu runner prerequisite.
There are no silent platform skips in the required Linux jobs.

Each matrix run receives a new private `HOME`, XDG configuration/state/cache
directories, a nonexistent SSH agent socket, and `/dev/null` as global Git
configuration. Its SSH config contains a poisoned `Host *` `ProxyCommand` that
creates a unique marker. The suite asserts the marker is absent, proving no
test tried to contact a developer-configured or real host. Real integration
tests may use only repository-created loopback OpenSSH/tmux resources and
session-specific temporary paths.

## Local reproduction

Use an isolated virtual environment; the optional extra contains only pinned
development tools:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ".[dev]"
ruff check src tests scripts
pyright
shellcheck install.sh bin/tmuxgate src/tmuxgate/assets/*.sh
PYTHONPATH=src:tests coverage run -m unittest discover -s tests -v
coverage report
python -m build
```

Do not point integration tests at configured machines or reuse a running
tmuxgate instance. A contributor without the documented Linux tools can run
the pure unit modules during development, but the required GitHub jobs are the
merge authority and do not waive missing local prerequisites.

## Staged hardening

The next stages are to make the remaining production modules Pyright-clean,
raise branch coverage while prioritizing state, transport, approval, spool,
and remote lifecycle failures, and add new properties when a protocol or state
transition is introduced. Future stages may add sanitizers or longer-running
fuzz campaigns as separate scheduled jobs; pull-request checks must remain
bounded, deterministic, isolated from configured hosts, and fail closed.
